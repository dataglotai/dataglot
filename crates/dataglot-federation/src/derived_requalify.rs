//!  /  — dialect-independent requalification of the dangling
//! derived-table column references the DataFusion unparser leaves on a
//! pushed-down `DISTINCT` / `GROUP BY`. Shared by every SQL connector's
//! [`SQLExecutor::ast_analyzer`](datafusion_federation::sql::SQLExecutor), chained
//! ahead of each connector's own dialect rewrites.

use std::collections::HashSet;

use datafusion::sql::sqlparser::ast;
use datafusion::sql::sqlparser::ast::VisitMut;

/// Repair the outer column qualifiers the DataFusion unparser leaves dangling
/// when a pushed-down plan wraps its projection in a **derived table**.
///
/// For a federated `SELECT DISTINCT region FROM users ORDER BY 1`, the unparser
/// emits:
///
/// ```sql
/// SELECT "users"."region"
/// FROM (SELECT "users"."region" FROM "public"."users") AS "derived_projection"
/// GROUP BY "users"."region" ORDER BY "users"."region"
/// ```
///
/// The outer scope's only relation is the derived table `derived_projection`,
/// so the outer `"users"."region"` references have no matching FROM entry and
/// Postgres rejects the query with *missing FROM-clause entry for table "users"*
///
/// **The rule.** When a `SELECT`'s FROM is a *single* derived table, that
/// derived alias is the only relation in scope — so *every* table-qualified
/// reference at that scope must be qualified by the derived alias. We requalify
/// each stale qualifier (a leaked source-relation name) to the derived alias,
/// regardless of how many distinct stale qualifiers leak (a same-source join
/// wrapped in `DISTINCT` leaves e.g. `u.region`, `o.status` — both are
/// rewritten).
///
/// **Soundness by construction.** We only ever descend through the FROM clause
/// (derived tables and nested joins) — never into a subquery embedded in an
/// *expression* (WHERE / projection / HAVING). A non-LATERAL derived table
/// cannot be correlated to an enclosing scope, so at every scope we reach every
/// non-alias qualifier is unambiguously a leaked name and is safe to requalify.
/// Expression subqueries, by contrast, *can* be correlated, and a leaked
/// qualifier there is textually indistinguishable from a genuine correlated
/// reference to an enclosing relation of the same name — so we deliberately
/// leave those unrepaired (they fail loudly on the remote, exactly as before
/// this fix) rather than risk silently rewriting a correlated reference. Two
/// further guards keep it sound: a scope whose derived subquery exposes
/// duplicate output column names is left unchanged (requalifying would make the
/// reference ambiguous), and a LATERAL derived table is never descended into.
///
/// For a set operation (or a parenthesized query body) the query-level ORDER BY
/// resolves against the output columns — branch/relation aliases are not in
/// scope — so a qualified sort key there is stripped to a bare column instead.
pub(crate) fn requalify_derived_refs(mut stmt: ast::Statement) -> ast::Statement {
    if let ast::Statement::Query(query) = &mut stmt {
        requalify_query(query);
    }
    stmt
}

fn requalify_query(query: &mut ast::Query) {
    // Split the borrow so the ORDER BY (on the `Query`) and the body are
    // available together — the fix needs to see both to decide safely.
    let ast::Query {
        body,
        order_by,
        with,
        ..
    } = &mut *query;
    // CTE definitions are their own uncorrelated scopes (a WITH query cannot
    // reference the outer query's FROM), so descend into each and requalify it
    // the same way — the unparser can wrap a CTE body in the derived-table shape.
    if let Some(with) = with {
        for cte in &mut with.cte_tables {
            requalify_query(&mut cte.query);
        }
    }
    match body.as_mut() {
        ast::SetExpr::Select(select) => fix_select_scope(select, order_by.as_mut()),
        ast::SetExpr::Query(inner) => {
            requalify_query(inner);
            // A parenthesized query body has no relation in scope at the wrapper
            // level — its trailing ORDER BY resolves against the inner query's
            // output columns, so strip any qualifier to a bare column.
            if let Some(order_by) = order_by.as_mut() {
                strip_order_by_qualifiers(order_by);
            }
        }
        other => {
            // UNION / INTERSECT / EXCEPT: fix each branch as its own scope, then
            // handle the query-level ORDER BY. At a set operation the sort keys
            // resolve against the *output columns* (branch relation aliases are
            // not in scope), so a qualified sort key must be stripped to a bare
            // column for Postgres to accept it.
            fix_set_expr_scope(other);
            if let Some(order_by) = order_by.as_mut() {
                strip_order_by_qualifiers(order_by);
            }
        }
    }
}

fn fix_set_expr_scope(body: &mut ast::SetExpr) {
    match body {
        ast::SetExpr::Select(select) => fix_select_scope(select, None),
        ast::SetExpr::Query(inner) => requalify_query(inner),
        ast::SetExpr::SetOperation { left, right, .. } => {
            fix_set_expr_scope(left);
            fix_set_expr_scope(right);
        }
        _ => {}
    }
}

/// Requalify stale qualifiers at a single `SELECT` scope, then descend through
/// its FROM clause only (see `requalify_derived_refs` for why not expressions).
fn fix_select_scope(select: &mut ast::Select, order_by: Option<&mut ast::OrderBy>) {
    // A single, non-LATERAL derived table ⇒ its alias is the only relation in
    // scope, so every OTHER table qualifier at this level is a leaked name that
    // must resolve to it — UNLESS the derived table exposes duplicate output
    // column names, in which case requalifying would make a reference ambiguous
    // (e.g. a DISTINCT over a same-source join projecting `u.id` and `o.id`, or a
    // duplicated projection `u.id, u.id`). We can't recover the per-column
    // correspondence from the unparsed SQL, so we leave such a scope unchanged
    // (no worse than the unrepaired SQL). Colliding-name join DISTINCT is a
    // tracked follow-up.
    let alias = if select.from.len() == 1 && select.from[0].joins.is_empty() {
        if let ast::TableFactor::Derived {
            lateral: false,
            alias: Some(a),
            subquery,
            ..
        } = &select.from[0].relation
        {
            if derived_outputs_collide(subquery) {
                None
            } else {
                Some(a.name.clone())
            }
        } else {
            None
        }
    } else {
        None
    };

    if let Some(alias) = alias {
        let mut fixer = ScopeFixer { alias, depth: 0 };
        let _ = select.visit(&mut fixer);
        if let Some(order_by) = order_by {
            // ORDER BY lives on the `Query`, not the `Select`; visit it under the
            // same scope (depth 0) so its qualifiers requalify to the derived
            // alias too.
            let _ = order_by.visit(&mut fixer);
        }
    }

    // Descend through the FROM clause (derived tables, nested joins) — a
    // non-LATERAL derived table is an uncorrelated scope, so requalifying it is
    // sound. Expression subqueries are intentionally NOT descended into.
    for twj in &mut select.from {
        requalify_table_with_joins(twj);
    }
}

fn requalify_from_factor(tf: &mut ast::TableFactor) {
    match tf {
        ast::TableFactor::Derived {
            lateral: false,
            subquery,
            ..
        } => requalify_query(subquery),
        ast::TableFactor::NestedJoin {
            table_with_joins, ..
        } => requalify_table_with_joins(table_with_joins),
        _ => {}
    }
}

/// Descend into the base relation and every joined relation of a FROM item.
fn requalify_table_with_joins(twj: &mut ast::TableWithJoins) {
    requalify_from_factor(&mut twj.relation);
    for join in &mut twj.joins {
        requalify_from_factor(&mut join.relation);
    }
}

/// Whether the derived subquery's projection could expose two columns with the
/// same output name — the case where requalifying an outer reference to the
/// derived alias would be ambiguous. Any projection item whose output name(s)
/// can't be read off the AST — a `*`/`table.*` wildcard (which can itself expand
/// to several duplicate-named columns) or a complex unaliased expression — is
/// treated as a *possible* collision and makes us bail, rather than assumed
/// collision-free.
fn derived_outputs_collide(subquery: &ast::Query) -> bool {
    // Resolve the body to the SELECT whose projection names the derived output
    // columns — for a set operation that is the leftmost branch, for a
    // parenthesized body the inner query. If it can't be resolved to a SELECT
    // (e.g. a VALUES list), bail conservatively (treat as a collision) so we
    // never requalify against output names we couldn't verify.
    let Some(select) = leftmost_select(&subquery.body) else {
        return true;
    };
    let mut seen = HashSet::new();
    for item in &select.projection {
        let ident = match item {
            ast::SelectItem::ExprWithAlias { alias, .. } => alias,
            ast::SelectItem::UnnamedExpr(ast::Expr::Identifier(id)) => id,
            ast::SelectItem::UnnamedExpr(ast::Expr::CompoundIdentifier(parts)) => {
                match parts.last() {
                    Some(p) => p,
                    None => return true,
                }
            }
            // Wildcard, qualified wildcard, or a complex unaliased expression:
            // the output name(s) can't be determined here, so bail.
            _ => return true,
        };
        // Collision key: lowercase every name, quoted or not. Whether a quoted
        // identifier is case-sensitive is dialect-specific — Postgres/Oracle
        // treat `"a"`/`"A"` as distinct, MySQL/SQLite fold them — and this shared
        // code has no dialect. Folding everything is the conservative choice:
        // it can only OVER-detect a collision, which makes us bail (leave the SQL
        // unrepaired — a hard "missing FROM-clause" failure the operator sees),
        // never UNDER-detect one, which would emit silently-ambiguous requalified
        // SQL. A DISTINCT/GROUP BY derived table with case-distinct quoted output
        // columns is vanishingly rare regardless.
        if !seen.insert(ident.value.to_lowercase()) {
            return true;
        }
    }
    false
}

/// The SELECT whose projection determines a query's output column names: the
/// query itself, the leftmost branch of a set operation, or the inner query of a
/// parenthesized body. `None` if it can't be resolved to a SELECT.
fn leftmost_select(body: &ast::SetExpr) -> Option<&ast::Select> {
    match body {
        ast::SetExpr::Select(select) => Some(select),
        ast::SetExpr::Query(inner) => leftmost_select(&inner.body),
        ast::SetExpr::SetOperation { left, .. } => leftmost_select(left),
        _ => None,
    }
}

/// Strip the table qualifier from a query-level ORDER BY whose scope has no
/// relation in it — a set operation, or a parenthesized query body. There the
/// ordering resolves against the (unqualified) output columns, so `ORDER BY
/// users.region` (or `ORDER BY upper(users.region)`) must drop the qualifier.
/// Depth-guarded so a subquery embedded in a sort key — its own scope — is not
/// touched.
fn strip_order_by_qualifiers(order_by: &mut ast::OrderBy) {
    let mut stripper = OrderByStripper { depth: 0 };
    let _ = order_by.visit(&mut stripper);
}

/// Drop the leading (table) part of a compound identifier, keeping the rest:
/// `users.region` → `region`, `users.col.field` → `col.field`.
fn drop_qualifier(parts: &[ast::Ident]) -> ast::Expr {
    if parts.len() == 2 {
        ast::Expr::Identifier(parts[1].clone())
    } else {
        ast::Expr::CompoundIdentifier(parts[1..].to_vec())
    }
}

struct OrderByStripper {
    depth: usize,
}

impl ast::VisitorMut for OrderByStripper {
    type Break = ();

    fn pre_visit_query(&mut self, _query: &mut ast::Query) -> core::ops::ControlFlow<()> {
        self.depth += 1;
        core::ops::ControlFlow::Continue(())
    }

    fn post_visit_query(&mut self, _query: &mut ast::Query) -> core::ops::ControlFlow<()> {
        self.depth = self.depth.saturating_sub(1);
        core::ops::ControlFlow::Continue(())
    }

    fn pre_visit_expr(&mut self, expr: &mut ast::Expr) -> core::ops::ControlFlow<()> {
        if self.depth == 0 {
            if let ast::Expr::CompoundIdentifier(parts) = expr {
                if parts.len() >= 2 {
                    *expr = drop_qualifier(parts);
                }
            }
        }
        core::ops::ControlFlow::Continue(())
    }
}

/// Mutating visitor that requalifies a scope's leaked table qualifiers to its
/// derived alias. It rewrites only at query depth 0 (this scope's own
/// expressions); `pre/post_visit_query` bump the depth as the walk enters/leaves
/// a subquery so nested scopes — which have their own FROM and are handled by
/// their own pass — are never touched here. The leading part of a compound
/// identifier (the table qualifier) is replaced unless it is already the alias.
struct ScopeFixer {
    alias: ast::Ident,
    depth: usize,
}

impl ast::VisitorMut for ScopeFixer {
    type Break = ();

    fn pre_visit_query(&mut self, _query: &mut ast::Query) -> core::ops::ControlFlow<()> {
        self.depth += 1;
        core::ops::ControlFlow::Continue(())
    }

    fn post_visit_query(&mut self, _query: &mut ast::Query) -> core::ops::ControlFlow<()> {
        self.depth = self.depth.saturating_sub(1);
        core::ops::ControlFlow::Continue(())
    }

    fn pre_visit_expr(&mut self, expr: &mut ast::Expr) -> core::ops::ControlFlow<()> {
        if self.depth == 0 {
            if let ast::Expr::CompoundIdentifier(parts) = expr {
                if parts.len() >= 2 {
                    // At a single-derived scope the derived alias is the ONLY
                    // relation, so every table qualifier must be it — set it
                    // unconditionally to the alias's exact value AND quote style.
                    // (Skipping on a bare value match would leave a stale
                    // `"Users"` unchanged next to an unquoted `users` alias,
                    // which Snowflake/Oracle resolve as different identifiers.)
                    parts[0] = self.alias.clone();
                }
            }
        }
        core::ops::ControlFlow::Continue(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use datafusion::sql::sqlparser::dialect::PostgreSqlDialect as PgParseDialect;
    use datafusion::sql::sqlparser::parser::Parser;

    fn analyze(sql: &str) -> String {
        let stmt = Parser::parse_sql(&PgParseDialect {}, sql)
            .expect("parse")
            .pop()
            .expect("one statement");
        requalify_derived_refs(stmt).to_string()
    }

    /// Smoke: the classic DISTINCT-wrapped-derived-table dangling qualifier is
    /// requalified to the derived alias (full coverage lives in the postgres
    /// connector tests, which exercise this via the same entry point).
    #[test]
    fn requalifies_dangling_derived_projection() {
        let bad = r#"SELECT "users"."region" FROM (SELECT "users"."region" FROM "public"."users") AS "derived_projection" GROUP BY "users"."region""#;
        let fixed = analyze(bad);
        assert!(
            fixed.starts_with(r#"SELECT "derived_projection"."region" FROM"#)
                && fixed.contains(r#"GROUP BY "derived_projection"."region""#),
            "outer refs requalified to the derived alias: {fixed}"
        );
    }

    /// A plain scan (no derived table) is left untouched.
    #[test]
    fn leaves_plain_scan_untouched() {
        let ok = r#"SELECT "users"."region" FROM "public"."users" GROUP BY "users"."region""#;
        assert_eq!(analyze(ok), ok);
    }

    /// A stale qualifier that matches the derived alias by VALUE but differs in
    /// quote style (`"users"` vs the bare alias `users`) is still requalified —
    /// they resolve as different identifiers on case/quote-sensitive dialects
    /// (Snowflake/Oracle), so leaving `"users"` would dangle (Gemini/CodeRabbit).
    #[test]
    fn requalifies_across_quote_style_mismatch() {
        let bad = r#"SELECT "users"."region" FROM (SELECT "users"."region" FROM "public"."users") AS users GROUP BY "users"."region""#;
        let fixed = analyze(bad);
        // The OUTER qualifier `"users"` is requalified to the bare alias `users`
        // (column keeps its own quote style). The inner subquery keeps
        // `"users"."region"` — the real table is in scope there.
        assert!(
            fixed.starts_with(r#"SELECT users."region" FROM"#)
                && fixed.contains(r#"GROUP BY users."region""#),
            "outer quoted stale qualifier must be requalified to the bare alias: {fixed}"
        );
    }
}

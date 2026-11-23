//! Dialect-independent requalification of the dangling
//! derived-table column references the DataFusion unparser leaves on a
//! pushed-down `DISTINCT` / `GROUP BY`. Shared by every SQL connector's
//! [`SQLExecutor::ast_analyzer`](datafusion_federation::sql::SQLExecutor), chained
//! ahead of each connector's own dialect rewrites.
//!
//! Two dangling shapes are repaired here (both otherwise fail on the remote with
//! *missing FROM-clause entry* / *referenced table not found*):
//!
//! 1. An ALIASED derived table `… AS derived_projection` whose outer references
//!    still carry the leaked source qualifier (the `SELECT DISTINCT` / `GROUP BY`
//!    wrapping) — requalified to the alias.
//! 2. An UNNAMED derived table `FROM (SELECT …)` the unparser emits for a
//!    federated `EXCEPT` / `INTERSECT` or a correlated scalar subquery in `WHERE`
//!    — repaired by [`repair_unnamed_derived`] (unwrap a trivial
//!    wrapper, else give it a fresh alias).
//!
//! **Known limitation.** A branch-filtered set operation
//! (`… EXCEPT SELECT … WHERE p`) unparses to a nested unnamed derived table
//! *inside* an `EXISTS` — an expression subquery this pass deliberately does not
//! descend into (see the soundness note below) — so it is not yet repaired. The
//! unfiltered set-op and correlated-scalar shapes are.

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
    // The unparser sometimes wraps a scope in an UNNAMED derived table
    // `FROM (SELECT …)` — seen on federated EXCEPT / INTERSECT and on a
    // correlated scalar subquery in WHERE. With no alias, every outer `Q.col`
    // reference (and any correlated reference to it from an EXISTS/NOT EXISTS)
    // dangles, and the source rejects the query with *missing FROM-clause entry*
    //. Repair it before the alias-based requalification below.
    repair_unnamed_derived(select);

    // A single, non-LATERAL derived table ⇒ its alias is the only relation in
    // scope, so every OTHER table qualifier at this level is a leaked name that
    // must resolve to it — UNLESS the derived table exposes duplicate output
    // column names, in which case requalifying would make a reference ambiguous
    // (e.g. a DISTINCT over a same-source join projecting `u.id` and `o.id`, or a
    // duplicated projection `u.id, u.id`). We can't recover the per-column
    // correspondence from the unparsed SQL, so we leave such a scope unchanged
    // (no worse than the unrepaired SQL). Colliding-name join DISTINCT is a
    // tracked follow-up.
    // The sole-FROM derived table's alias and whether its outputs collide, as
    // two independent facts: the alias exists whenever the FROM is one aliased,
    // non-LATERAL derived table; the collision only gates *column-level*
    // requalification (which would be ambiguous over duplicate output names).
    let (derived_alias, collide) = if select.from.len() == 1 && select.from[0].joins.is_empty() {
        if let ast::TableFactor::Derived {
            lateral: false,
            alias: Some(a),
            subquery,
            ..
        } = &select.from[0].relation
        {
            (Some(a.name.clone()), derived_outputs_collide(subquery))
        } else {
            (None, false)
        }
    } else {
        (None, false)
    };

    if let Some(alias) = &derived_alias {
        // A qualified wildcard `t.*` is a `SelectItem`, not an `Expr`, so the
        // visitor below never reaches it — requalify its qualifier to the derived
        // alias directly (else `t.*` dangles, the source rejects it — codex).
        // This is safe even when the outputs collide: `alias.*` selects the
        // derived table's columns regardless of duplicate names, so it runs
        // independently of the collision bailout on the column visitor below.
        for item in &mut select.projection {
            if let ast::SelectItem::QualifiedWildcard(
                ast::SelectItemQualifiedWildcardKind::ObjectName(name),
                _,
            ) = item
            {
                *name = ast::ObjectName(vec![ast::ObjectNamePart::Identifier(alias.clone())]);
            }
        }
    }

    // Column-level requalification (specific `t.col` references) IS ambiguous
    // over colliding outputs, so it runs only when the outputs don't collide.
    if let Some(alias) = derived_alias.filter(|_| !collide) {
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

/// The fresh alias given to an otherwise-unnamed derived table whose outer
/// references must then be requalified to it. Matches the name the DataFusion
/// unparser uses for its own derived tables.
const SYNTHETIC_DERIVED_ALIAS: &str = "derived_projection";

/// Repair a `SELECT` whose sole FROM item is an UNNAMED, non-LATERAL derived
/// table, which the unparser leaves with dangling `Q.col` outer references.
///
/// Two safe repairs, by the wrapper's shape:
///
/// * **Unwrap** a *trivial* wrapper — `(SELECT <plain cols> FROM <one base
///   table>)` with no WHERE/GROUP BY/DISTINCT/…: splice the base relation up
///   into the outer FROM. Every `Q.col` reference (including correlated ones in
///   an EXISTS) then resolves to the real base table. This is the EXCEPT /
///   INTERSECT shape, and unwrapping — rather than aliasing — is what keeps the
///   correlated references valid without any rewrite.
/// * Otherwise **name** the derived table with a fresh synthetic alias and let
///   the alias-based requalification below rewrite the outer references to it.
///   This is the correlated-scalar-subquery-in-WHERE shape (the wrapper holds a
///   decorrelated join and has no *external* correlated references). Skipped if
///   the derived outputs collide (an ambiguous requalification would be worse
///   than the current hard failure).
///
/// A fresh alias is used, never the leaked source name: reusing e.g.
/// `customers` for a wrapper over `customers` makes the source resolve the
/// derived alias and the inner base table ambiguously (empty/incorrect result),
/// so the alias must be a name that appears nowhere else.
fn repair_unnamed_derived(select: &mut ast::Select) {
    if select.from.len() != 1 || !select.from[0].joins.is_empty() {
        return;
    }
    // Unwrapping splices the base relation up, exposing ALL of its columns. That
    // is invisible when the outer scope names specific columns, but a wildcard
    // (`SELECT *`) observes the wrapper's column set, so unwrapping would leak
    // the base table's extra columns (`SELECT * FROM (SELECT t.id FROM t)` →
    // `SELECT * FROM t`, codex). When the outer projection has a wildcard, keep
    // the boundary: fresh-alias instead of unwrapping.
    let outer_has_wildcard = select.projection.iter().any(|item| {
        matches!(
            item,
            ast::SelectItem::Wildcard(_) | ast::SelectItem::QualifiedWildcard(..)
        )
    });
    // Decide the repair while borrowing the subquery, then apply it once the
    // borrow has ended (a clone for the unwrap, a bool for the fresh alias).
    let mut unwrap_to: Option<ast::TableWithJoins> = None;
    let mut needs_fresh_alias = false;
    if let ast::TableFactor::Derived {
        lateral: false,
        alias: None,
        subquery,
        ..
    } = &select.from[0].relation
    {
        match trivial_wrapper_base(subquery) {
            Some(base) if !outer_has_wildcard => unwrap_to = Some(base.clone()),
            // Always NAME the derived table — Postgres/DuckDB reject an unaliased
            // FROM-subquery outright (gemini). The collision case only skips the
            // outer-reference *requalification* (gated in `fix_select_scope`), not
            // the alias itself: naming it fixes a colliding wrapper with no
            // qualified outer references, and never worsens one that has them.
            _ => needs_fresh_alias = true,
        }
    }
    if let Some(base) = unwrap_to {
        select.from[0] = base;
    } else if needs_fresh_alias {
        if let ast::TableFactor::Derived { alias, .. } = &mut select.from[0].relation {
            *alias = Some(ast::TableAlias {
                explicit: true,
                name: ast::Ident::new(SYNTHETIC_DERIVED_ALIAS),
                columns: vec![],
                at: None,
            });
        }
    }
}

/// If `query` is a *trivial* projection wrapper — `SELECT <plain column refs or
/// wildcards> FROM <single base table, no joins>` with no WHERE / GROUP BY /
/// HAVING / DISTINCT / sort / LIMIT / OFFSET / WITH — return its single base
/// FROM item, which can be spliced up to replace the wrapper. Any other shape
/// (a filter, a join, a computed/renamed projection column, …) returns `None`,
/// because unwrapping it could change which rows or columns the outer scope
/// sees.
fn trivial_wrapper_base(query: &ast::Query) -> Option<&ast::TableWithJoins> {
    // The unparser can attach an EMPTY-but-`Some` ORDER BY / LIMIT to a plain
    // scan (`LimitOffset { limit: None, offset: None, limit_by: [] }`), so test
    // for an *effective* clause, not merely `Some`.
    let order_by_empty = match &query.order_by {
        None => true,
        Some(o) => matches!(&o.kind, ast::OrderByKind::Expressions(v) if v.is_empty()),
    };
    let limit_empty = match &query.limit_clause {
        None => true,
        Some(ast::LimitClause::LimitOffset {
            limit,
            offset,
            limit_by,
        }) => limit.is_none() && offset.is_none() && limit_by.is_empty(),
        Some(ast::LimitClause::OffsetCommaLimit { .. }) => false,
    };
    if query.with.is_some()
        || !order_by_empty
        || !limit_empty
        || query.fetch.is_some()
        || !query.locks.is_empty()
        || query.for_clause.is_some()
        || query.settings.is_some()
        || query.format_clause.is_some()
        || !query.pipe_operators.is_empty()
    {
        return None;
    }
    let ast::SetExpr::Select(select) = query.body.as_ref() else {
        return None;
    };
    if select.from.len() != 1 || !select.from[0].joins.is_empty() {
        return None;
    }
    // The base table must be UNALIASED. Lifting an aliased base (`… FROM t AS x`)
    // into the outer FROM would rename the relation to `x`, but the outer scope's
    // leaked references use the source name `t` — so `t.col` would no longer
    // resolve. An aliased base falls through to the fresh-alias repair instead,
    // which is sound regardless of the inner alias (gemini).
    if !matches!(
        select.from[0].relation,
        ast::TableFactor::Table { alias: None, .. }
    ) {
        return None;
    }
    // Bail on ANY clause unwrapping would silently discard — not just the common
    // ones, but every dialect/future field on `Select` that changes the rows or
    // columns the outer scope sees. An empty projection can't be a pass-through
    // wrapper either.
    if select.projection.is_empty()
        || select.selection.is_some()
        || select.having.is_some()
        || select.distinct.is_some()
        || select.top.is_some()
        || select.into.is_some()
        || select.exclude.is_some()
        || select.prewhere.is_some()
        || select.qualify.is_some()
        || select.value_table_mode.is_some()
        || !select.sort_by.is_empty()
        || !select.cluster_by.is_empty()
        || !select.distribute_by.is_empty()
        || !select.lateral_views.is_empty()
        || !select.connect_by.is_empty()
        || !select.named_window.is_empty()
        || !matches!(&select.group_by, ast::GroupByExpr::Expressions(e, m) if e.is_empty() && m.is_empty())
    {
        return None;
    }
    // The base table's bare name, against which projection qualifiers must
    // match — a projection column qualified by a *different* relation (only
    // possible via an illegal correlated reference in a non-LATERAL derived
    // table, but checked defensively) would resolve elsewhere once unwrapped.
    let ast::TableFactor::Table { name, .. } = &select.from[0].relation else {
        return None;
    };
    let Some(ast::ObjectNamePart::Identifier(base)) = name.0.last() else {
        return None;
    };
    // Every projection item must be a pass-through column (or wildcard) whose
    // qualifier, if any, is the base table itself: the outer references then
    // resolve against the base table's own column names.
    let pass_through = select.projection.iter().all(|item| match item {
        ast::SelectItem::UnnamedExpr(ast::Expr::Identifier(_)) => true,
        // A wildcard is a pass-through ONLY without column-transforming modifiers
        // (EXCLUDE / EXCEPT / REPLACE / RENAME / ILIKE / alias) — unwrapping would
        // drop them and read the untransformed base columns instead (codex).
        ast::SelectItem::Wildcard(opts) => is_plain_wildcard(opts),
        ast::SelectItem::UnnamedExpr(ast::Expr::CompoundIdentifier(parts)) => {
            // The relation qualifier sits just before the column (`t.col`,
            // `schema.t.col`). It must name the base table.
            parts.len() < 2 || parts[parts.len() - 2].value == base.value
        }
        ast::SelectItem::QualifiedWildcard(
            ast::SelectItemQualifiedWildcardKind::ObjectName(qualifier),
            opts,
        ) => {
            is_plain_wildcard(opts)
                && matches!(
                    qualifier.0.last(),
                    Some(ast::ObjectNamePart::Identifier(id)) if id.value == base.value
                )
        }
        _ => false,
    });
    pass_through.then(|| &select.from[0])
}

/// A wildcard with no column-transforming modifiers — safe to treat as a
/// pass-through of every base column. Any `EXCLUDE`/`EXCEPT`/`REPLACE`/`RENAME`/
/// `ILIKE`/alias option changes the projected columns, so it is not.
fn is_plain_wildcard(opts: &ast::WildcardAdditionalOptions) -> bool {
    opts.opt_ilike.is_none()
        && opts.opt_exclude.is_none()
        && opts.opt_except.is_none()
        && opts.opt_replace.is_none()
        && opts.opt_rename.is_none()
        && opts.opt_alias.is_none()
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

    /// A trivial UNNAMED derived wrapper — `(SELECT cols FROM one_table)` with no
    /// other clauses — is UNWRAPPED so the outer (and correlated) references
    /// resolve to the real base table (the EXCEPT / INTERSECT shape, ).
    #[test]
    fn unwraps_trivial_unnamed_derived() {
        let bad = r#"SELECT "customers"."id" FROM (SELECT "customers"."id" FROM "main"."customers") WHERE NOT EXISTS (SELECT 1 FROM "main"."orders" WHERE ("customers"."id" = "orders"."customer_id")) GROUP BY "customers"."id""#;
        let fixed = analyze(bad);
        assert!(
            fixed.contains(r#"FROM "main"."customers" WHERE NOT EXISTS"#)
                && !fixed.contains("FROM (SELECT"),
            "the trivial wrapper must be unwrapped to the base table: {fixed}"
        );
        // The correlated reference inside the NOT EXISTS now resolves too.
        assert!(
            fixed.contains(r#"("customers"."id" = "orders"."customer_id")"#),
            "correlated reference preserved: {fixed}"
        );
    }

    /// A NON-trivial UNNAMED derived wrapper (holds a join) can't be unwrapped,
    /// so it gets a fresh synthetic alias and its outer references requalify to
    /// it (the correlated-scalar-subquery-in-WHERE shape). A fresh alias — never
    /// the leaked source name — avoids the source resolving the derived table and
    /// its inner base table ambiguously.
    #[test]
    fn names_nontrivial_unnamed_derived() {
        let bad = r#"SELECT "c"."name" FROM (SELECT "c"."id", "c"."name" FROM "main"."customers" AS "c" LEFT OUTER JOIN (SELECT "o"."customer_id" FROM "main"."orders" AS "o") AS "sq" ON ("sq"."customer_id" = "c"."id")) WHERE ("c"."name" IS NOT NULL)"#;
        let fixed = analyze(bad);
        assert!(
            fixed.contains("AS derived_projection")
                && fixed.starts_with(r#"SELECT derived_projection."name" FROM"#),
            "non-trivial wrapper gets a fresh alias with requalified outer refs: {fixed}"
        );
    }

    /// A wrapper carrying a query-level clause unwrapping would discard (here
    /// `FOR UPDATE`) is NOT unwrapped — the lock must survive (coderabbit).
    #[test]
    fn does_not_unwrap_wrapper_with_lock() {
        let bad =
            r#"SELECT "orders"."id" FROM (SELECT "orders"."id" FROM "main"."orders" FOR UPDATE)"#;
        let fixed = analyze(bad);
        assert!(
            fixed.contains("FOR UPDATE") && fixed.contains("FROM (SELECT"),
            "the FOR UPDATE lock and its wrapper must survive (not unwrapped): {fixed}"
        );
        // The wrapper is instead fresh-aliased and the outer ref requalified to it.
        assert!(
            fixed.contains("AS derived_projection")
                && fixed.starts_with(r#"SELECT derived_projection."id" FROM"#),
            "the wrapper must be fresh-aliased with the outer ref requalified: {fixed}"
        );
    }

    /// A wrapper carrying a `WINDOW` clause (parsed into `named_window`) is NOT
    /// unwrapped — the window definitions must survive (gemini).
    #[test]
    fn does_not_unwrap_wrapper_with_window() {
        let bad = r#"SELECT "orders"."id" FROM (SELECT "orders"."id" FROM "main"."orders" WINDOW w AS (PARTITION BY "orders"."id"))"#;
        let fixed = analyze(bad);
        assert!(
            fixed.contains("WINDOW w AS") && fixed.contains("FROM (SELECT"),
            "the WINDOW clause and its wrapper must survive (not unwrapped): {fixed}"
        );
        assert!(
            fixed.contains("AS derived_projection")
                && fixed.starts_with(r#"SELECT derived_projection."id" FROM"#),
            "the wrapper must be fresh-aliased with the outer ref requalified: {fixed}"
        );
    }

    /// A `SELECT *` over a trivial wrapper must NOT be unwrapped — the wildcard
    /// observes the wrapper's column set, so unwrapping `(SELECT id FROM t)` to
    /// `t` would leak the base table's other columns (codex). The wrapper is
    /// fresh-aliased instead, preserving the projected column set.
    #[test]
    fn does_not_unwrap_wildcard_over_partial_projection() {
        let bad = r#"SELECT * FROM (SELECT "orders"."id" FROM "main"."orders")"#;
        let fixed = analyze(bad);
        assert!(
            fixed.contains("AS derived_projection") && fixed.contains("FROM (SELECT"),
            "the wrapper must be kept (fresh-aliased), preserving the * column set: {fixed}"
        );
        assert!(
            !fixed.contains(r#"FROM "main"."orders" "#)
                && !fixed.ends_with(r#"FROM "main"."orders""#),
            "must NOT unwrap to the bare base table (would leak extra columns): {fixed}"
        );
    }

    /// A wrapper whose base table is ALIASED is NOT unwrapped — lifting `… FROM
    /// customers AS c` would rename the relation to `c`, breaking the outer
    /// `customers.id` reference. Fresh-alias instead (gemini).
    #[test]
    fn does_not_unwrap_aliased_base() {
        let bad =
            r#"SELECT "customers"."id" FROM (SELECT "c"."id" FROM "main"."customers" AS "c")"#;
        let fixed = analyze(bad);
        assert!(
            fixed.contains("AS derived_projection")
                && fixed.contains(r#""main"."customers" AS "c""#)
                && fixed.starts_with(r#"SELECT derived_projection."id" FROM"#),
            "an aliased base must be fresh-aliased, not unwrapped: {fixed}"
        );
    }

    /// A qualified wildcard `t.*` in the outer projection must be requalified to
    /// the fresh alias — it's a `SelectItem`, not an `Expr`, so the expr visitor
    /// misses it and it would otherwise dangle (codex).
    #[test]
    fn requalifies_qualified_wildcard_to_fresh_alias() {
        let bad = r#"SELECT "orders".* FROM (SELECT "orders"."id" FROM "main"."orders")"#;
        let fixed = analyze(bad);
        assert!(
            fixed.starts_with("SELECT derived_projection.* FROM")
                && fixed.contains("AS derived_projection")
                && fixed.contains("FROM (SELECT"),
            "the qualified wildcard must requalify to the derived alias: {fixed}"
        );
    }

    /// A wrapper whose projection is qualified by a relation OTHER than its base
    /// table is NOT unwrapped — unwrapping would resolve the reference against
    /// the wrong relation. Fresh-alias instead (gemini).
    #[test]
    fn does_not_unwrap_foreign_qualified_projection() {
        let bad = r#"SELECT "z"."id" FROM (SELECT "orders"."id" FROM "main"."customers")"#;
        let fixed = analyze(bad);
        assert!(
            fixed.contains("AS derived_projection") && fixed.contains("FROM (SELECT"),
            "a projection qualified by a non-base relation must not be unwrapped: {fixed}"
        );
    }

    /// Even when the derived outputs collide (so outer references can't be
    /// safely requalified), the unnamed subquery must still receive the alias —
    /// Postgres/DuckDB reject an unaliased FROM-subquery outright (gemini).
    #[test]
    fn names_colliding_unnamed_derived() {
        let bad = r#"SELECT count(*) FROM (SELECT "u"."id", "o"."id" FROM "main"."a" AS "u", "main"."b" AS "o")"#;
        let fixed = analyze(bad);
        assert!(
            fixed.contains("AS derived_projection"),
            "a colliding unnamed subquery must still be aliased (valid FROM): {fixed}"
        );
    }

    /// An INNER wildcard trips the collision bailout (unknown output names), but
    /// the OUTER qualified wildcard must still requalify to the derived alias —
    /// `derived_projection.*` is valid regardless of colliding names (codex).
    #[test]
    fn requalifies_outer_wildcard_despite_inner_wildcard_collision() {
        let bad = r#"SELECT "t".* FROM (SELECT "t".* FROM "main"."t")"#;
        let fixed = analyze(bad);
        assert!(
            fixed.starts_with("SELECT derived_projection.* FROM")
                && fixed.contains("AS derived_projection"),
            "the outer wildcard must requalify even when the inner outputs collide: {fixed}"
        );
    }

    /// A wrapper whose inner projection is a MODIFIED wildcard (`* EXCLUDE (…)`)
    /// is NOT unwrapped — unwrapping would drop the modifier and read the
    /// untransformed base columns. Fresh-alias instead (codex).
    #[test]
    fn does_not_unwrap_modified_wildcard() {
        use datafusion::sql::sqlparser::dialect::DuckDbDialect;
        let bad = r#"SELECT id FROM (SELECT * EXCLUDE (x) FROM "main"."t")"#;
        let stmt = Parser::parse_sql(&DuckDbDialect {}, bad)
            .expect("parse")
            .pop()
            .expect("one statement");
        let fixed = requalify_derived_refs(stmt).to_string();
        assert!(
            fixed.contains("EXCLUDE")
                && fixed.contains("FROM (SELECT")
                && fixed.contains("AS derived_projection"),
            "a modified wildcard must be preserved (fresh-aliased, not unwrapped): {fixed}"
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

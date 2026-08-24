//! Identity-register alias shim — pgwire compatibility workaround.
//!
//! # What this is
//!
//! A pre-parse rewrite hook applied at the pg wire boundary, the same
//! mechanism as [`crate::show_schemas`] and [`crate::pg_compat`].
//!
//! `datafusion-pg-catalog` rewrites the parenthesis-less identity
//! registers `current_user` / `session_user` / `user` via a sqlparser
//! `VisitorMut` (`current_user` -> `session_user()`), but that visitor
//! **drops the SELECT-item alias**, so both projected columns collapse to
//! the same unnamed `session_user()` expression. `DataFusion` then rejects
//! the plan with `Projections require unique expression names`. Bare
//! `user` fails differently — it is not in the upstream rename table, so
//! it surfaces as `No field named user`. Real `PostgreSQL` accepts all of
//! these.
//!
//! An **explicit** alias survives the upstream rename (`SELECT current_user
//! AS a, session_user AS b` already works), so the fix is to add the
//! canonical `PostgreSQL` column name as an alias to each bare register
//! **before** the upstream rewrite runs:
//!
//! - `current_user` -> `current_user AS current_user`
//! - `session_user` -> `session_user AS session_user`
//! - `user`         -> `current_user AS current_user`
//!   (`PostgreSQL` reports `SELECT user`'s column as `current_user`, and
//!   rewriting the expression to `current_user` lets the upstream rename
//!   still apply)
//!
//! # Scope
//!
//! Only the **top-level** projection list of a simple `SELECT` is handled.
//! Registers inside subqueries / CTEs are out of scope (rarer; this is a
//! Low-priority correctness fix). Anything we do not confidently transform
//! is passed through unchanged — a parse failure, a non-`SELECT`
//! statement, or a multi-statement input all return `None`.
//!
//! # Known limitation
//!
//! `SELECT current_user, current_user` still errors downstream: we alias
//! both faithfully to `current_user`, but `DataFusion` requires unique
//! projection names while `PostgreSQL` allows duplicate column names. The
//! two goals are mutually exclusive without renaming one column (which
//! would violate `PostgreSQL` semantics), so the remaining
//! `Projections require unique expression names` error is a `DataFusion`
//! limitation, not one we can resolve here.

use sqlparser::ast::{
    Expr, FunctionArguments, Ident, ObjectNamePart, SelectItem, SetExpr, Statement,
};
use sqlparser::dialect::GenericDialect;
use sqlparser::parser::Parser;

/// If `expr` is a bare (parenthesis-less) identity register in a SELECT
/// projection, returns its canonical lowercase name (`current_user`,
/// `session_user`, or `user`); otherwise `None`.
///
/// In sqlparser 0.62 all three parse to an [`Expr::Function`] with a
/// single-identifier name and [`FunctionArguments::None`] (no parentheses,
/// so no argument list). A quoted identifier is not a register.
fn bare_identity_register(expr: &Expr) -> Option<&'static str> {
    let Expr::Function(func) = expr else {
        return None;
    };
    // Parenthesis-less form only: `current_user()` (with args) is a
    // different surface and left untouched.
    if !matches!(func.args, FunctionArguments::None) {
        return None;
    }
    let [ObjectNamePart::Identifier(ident)] = func.name.0.as_slice() else {
        return None;
    };
    if ident.quote_style.is_some() {
        return None;
    }
    match ident.value.to_ascii_lowercase().as_str() {
        "current_user" => Some("current_user"),
        "session_user" => Some("session_user"),
        "user" => Some("user"),
        _ => None,
    }
}

/// Alias bare identity registers with their canonical Postgres column names
/// so the upstream `current_user` -> `session_user` rename doesn't collapse
/// them to duplicate unnamed columns. Returns the rewritten SQL only if it
/// changed.
///
/// See the module docs for the exact mapping, scope, and known limitation.
#[must_use]
pub fn rewrite_identity_registers(query: &str) -> Option<String> {
    // Cheap gate: every identity register contains the substring `user`,
    // so a query without it can never need rewriting. Keep the hot path
    // (the ~all queries that don't reference a register) parse-free.
    if !query.to_ascii_lowercase().contains("user") {
        return None;
    }

    // Only confidently-simple statements are transformed; anything else
    // passes through untouched.
    let mut statements = Parser::parse_sql(&GenericDialect {}, query).ok()?;
    if statements.len() != 1 {
        return None;
    }
    let stmt = &mut statements[0];
    let Statement::Query(query_ast) = stmt else {
        return None;
    };
    let SetExpr::Select(select) = query_ast.body.as_mut() else {
        return None;
    };

    let mut changed = false;
    for item in &mut select.projection {
        // Only bare (unaliased) projection items are candidates; an
        // existing `ExprWithAlias` already survives the upstream rename.
        let new_item = match item {
            SelectItem::UnnamedExpr(expr) => match bare_identity_register(expr) {
                Some("current_user") => SelectItem::ExprWithAlias {
                    expr: expr.clone(),
                    alias: Ident::new("current_user"),
                },
                Some("session_user") => SelectItem::ExprWithAlias {
                    expr: expr.clone(),
                    alias: Ident::new("session_user"),
                },
                Some("user") => {
                    // Rewrite the expression to `current_user` so the
                    // upstream rename still applies, and alias it to
                    // `current_user` (Postgres reports that column name).
                    let mut rewritten = expr.clone();
                    if let Expr::Function(func) = &mut rewritten {
                        if let Some(ObjectNamePart::Identifier(ident)) = func.name.0.first_mut() {
                            *ident = Ident::new("current_user");
                        }
                    }
                    SelectItem::ExprWithAlias {
                        expr: rewritten,
                        alias: Ident::new("current_user"),
                    }
                }
                _ => continue,
            },
            _ => continue,
        };
        *item = new_item;
        changed = true;
    }

    if !changed {
        return None;
    }
    Some(stmt.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aliases_distinct_registers() {
        // `current_user` and `session_user` get distinct canonical aliases
        // so the upstream rename can't collapse them into one column.
        let out = rewrite_identity_registers("SELECT current_user, session_user")
            .expect("should rewrite");
        assert!(out.contains("AS current_user"), "{out}");
        assert!(out.contains("AS session_user"), "{out}");
    }

    #[test]
    fn bare_user_becomes_current_user() {
        // `user` is rewritten to `current_user` (so the upstream rename
        // applies) and aliased to `current_user` (Postgres column name).
        let out = rewrite_identity_registers("SELECT user").expect("should rewrite");
        assert!(out.contains("current_user AS current_user"), "{out}");
        assert!(!out.to_ascii_lowercase().contains(" user"), "{out}");
    }

    #[test]
    fn single_current_user_is_aliased() {
        // A lone register is still aliased to its canonical column name;
        // the result parses and names the column `current_user`.
        let out = rewrite_identity_registers("SELECT current_user").expect("should rewrite");
        assert!(out.contains("current_user AS current_user"), "{out}");
    }

    #[test]
    fn already_aliased_is_untouched() {
        // An explicit alias already survives the upstream rename — nothing
        // to do, so we pass through unchanged.
        assert!(rewrite_identity_registers("SELECT current_user AS a").is_none());
    }

    #[test]
    fn non_register_query_is_passthrough() {
        // Contains the substring `user` (via `users`) so it parses, but has
        // no bare register in the projection — must return `None` rather
        // than reserialize an unrelated query.
        assert!(rewrite_identity_registers("SELECT id FROM users").is_none());
    }

    #[test]
    fn cheap_gate_skips_userless_queries() {
        // No `user` substring: returns without parsing.
        assert!(rewrite_identity_registers("SELECT 1").is_none());
    }

    #[test]
    fn unparseable_input_is_passthrough() {
        // Junk / non-SELECT input never panics — it just passes through.
        assert!(rewrite_identity_registers("NOT SQL user ;;;").is_none());
        assert!(rewrite_identity_registers("UPDATE users SET x = 1").is_none());
    }

    #[test]
    fn duplicate_current_user_is_aliased_faithfully() {
        // Known limitation: we alias both to `current_user` (faithful to
        // Postgres, which allows duplicate column names). The downstream
        // `Projections require unique expression names` error is a
        // DataFusion constraint, not something this shim can satisfy
        // without violating Postgres semantics.
        let out = rewrite_identity_registers("SELECT current_user, current_user")
            .expect("should rewrite");
        assert_eq!(out.matches("AS current_user").count(), 2, "{out}");
    }
}

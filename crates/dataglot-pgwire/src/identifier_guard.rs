//! Pre-plan guard for pathological compound identifiers.
//!
//! DataFusion's SQL planner `.unwrap()`s instead of returning an error
//! when a compound identifier has more parts than it handles — e.g.
//! `SELECT a.b.c.d.e.f` panics with
//! `Internal("Incorrect number of identifiers: 6")` in
//! `datafusion-sql/src/expr/identifier.rs`. Reachable straight through
//! pg-wire, so an untrusted client can drop its own connection with a
//! panic instead of getting a clean error.
//!
//! We reject such statements *before* they reach the planner, on both
//! protocol paths (simple query + the extended-query parser), returning
//! a normal `42601 syntax_error`. Detection walks the parsed AST, so it
//! is whitespace- and quote-insensitive (unlike a text scan). Remove
//! once fixed upstream.

use pgwire::error::{ErrorInfo, PgWireError};
use sqlparser::ast::{visit_expressions, Expr};
use sqlparser::dialect::GenericDialect;
use sqlparser::parser::Parser;
use std::ops::ControlFlow;

/// Max compound-identifier parts DataFusion's planner handles
/// (`catalog.schema.table.column.field`). More triggers the panic.
const MAX_IDENTIFIER_PARTS: usize = 5;

/// Returns a clean pg-wire error if `sql` contains a compound identifier
/// with more than [`MAX_IDENTIFIER_PARTS`] parts; otherwise `None`.
///
/// A parse failure yields `None` — an unparseable statement can't reach
/// the compound-identifier planner path, and the planner will reject it
/// through the normal error channel anyway.
pub(crate) fn reject_deep_compound_identifier(sql: &str) -> Option<PgWireError> {
    let statements = Parser::parse_sql(&GenericDialect {}, sql).ok()?;

    let mut offending_parts: Option<usize> = None;
    for stmt in &statements {
        let flow = visit_expressions(stmt, |expr| {
            if let Expr::CompoundIdentifier(parts) = expr {
                if parts.len() > MAX_IDENTIFIER_PARTS {
                    offending_parts = Some(parts.len());
                    return ControlFlow::Break(());
                }
            }
            ControlFlow::Continue(())
        });
        if flow.is_break() {
            break;
        }
    }

    let n = offending_parts?;
    Some(PgWireError::UserError(Box::new(ErrorInfo::new(
        "ERROR".to_owned(),
        // 42601 — syntax_error.
        "42601".to_owned(),
        format!("compound identifier has too many parts ({n}; maximum is {MAX_IDENTIFIER_PARTS})"),
    ))))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_six_part_identifier() {
        // The canonical fuzzer-found crash.
        assert!(reject_deep_compound_identifier("SELECT a.b.c.d.e.f").is_some());
    }

    #[test]
    fn rejects_whitespace_and_quoted_variants() {
        // Same AST as the canonical case — a text scan would miss these.
        assert!(reject_deep_compound_identifier("SELECT a . b . c . d . e . f").is_some());
        assert!(reject_deep_compound_identifier(r#"SELECT "a"."b"."c"."d"."e"."f""#).is_some());
    }

    #[test]
    fn rejects_deep_identifier_nested_in_expression() {
        assert!(
            reject_deep_compound_identifier("SELECT 1 WHERE a.b.c.d.e.f > 0 OR x = 1").is_some()
        );
    }

    #[test]
    fn allows_normal_identifiers() {
        // Up to catalog.schema.table.column (4 parts) is common and fine.
        assert!(reject_deep_compound_identifier("SELECT a, t.b, s.t.c FROM t").is_none());
        assert!(
            reject_deep_compound_identifier("SELECT cat.sch.tbl.col FROM cat.sch.tbl").is_none()
        );
    }

    #[test]
    fn allows_five_part_identifier() {
        // Five parts is the documented maximum the planner handles.
        assert!(reject_deep_compound_identifier("SELECT a.b.c.d.e").is_none());
    }

    #[test]
    fn unparseable_input_is_not_rejected_here() {
        // Parse failure → None; the planner rejects it via the normal path.
        assert!(reject_deep_compound_identifier("NOT SQL AT ALL ;;;").is_none());
    }

    #[test]
    fn rejection_is_a_clean_user_error() {
        let err = reject_deep_compound_identifier("SELECT a.b.c.d.e.f").expect("should reject");
        assert!(matches!(err, PgWireError::UserError(_)));
    }
}

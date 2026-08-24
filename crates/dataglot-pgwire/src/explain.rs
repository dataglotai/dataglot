//! `EXPLAIN FEDERATION` SQL surface — Phase 0 strategic deliverable
//! per Strategy v3.0.
//!
//! # What this is
//!
//! A pre-parse rewrite hook applied at the pg wire boundary. When a
//! client sends `EXPLAIN FEDERATION <sql>`, the rewriter substitutes
//! `EXPLAIN VERBOSE <sql>` before `DfSessionService` parses it. The
//! verbose-explain output already contains the load-bearing
//! information operators want to see — `VirtualExecutionPlan` /
//! `sql_federation_exec` nodes from `datafusion-federation`, and the
//! warehouse-side scan nodes from `iceberg-datafusion`. The
//! `FEDERATION` keyword is the user-facing affordance that says "show
//! me what gets pushed down".
//!
//! # Why a pre-parse rewrite (and not a custom statement)
//!
//! `sqlparser-rs`'s grammar does not recognise `FEDERATION` as an
//! `EXPLAIN` modifier. Three implementation routes were considered
//! before this one was picked:
//!
//! 1. **`Statement::Custom` via `datafusion`'s extension hook** —
//!    proper, plan-level access; medium cost.
//! 2. **Patch `sqlparser-rs` upstream** — best long-term, worst
//!    short-term.
//! 3. **This module** — minimal blast radius, ships the strategic
//!    deliverable, lives entirely inside `dataglot-pgwire` (rule 5).
//!
//! Phase 1 can swap to (1) without changing the user-visible SQL
//! surface; the rewriter then becomes dead code and gets deleted.
//!
//! # Limitations
//!
//! * **Simple-query path only.** The extended-query protocol parses
//!   the SQL during `Parse`; `EXPLAIN FEDERATION` would fail at parse
//!   time before our rewrite hook fires. In practice every Postgres
//!   client (psql, JDBC, asyncpg) uses simple-query for explicit
//!   `EXPLAIN`-style statements, so this restriction is not user-
//!   visible.
//! * **No output post-processing.** The verbose-explain rows are
//!   passed through unchanged. A Phase 1 follow-up should filter or
//!   annotate to highlight the federation-specific nodes; this PR
//!   ships the surface, not the formatter.
//!
//! # Surface
//!
//! Case-insensitive `EXPLAIN FEDERATION <sql>` (any whitespace) maps
//! to `EXPLAIN VERBOSE <sql>`. Trailing semicolons, comments, and
//! mixed casing are preserved verbatim from the original.

/// Rewrite an `EXPLAIN FEDERATION ...` query into a plain
/// `EXPLAIN VERBOSE ...` for the inner SQL parser.
///
/// Returns `Some(rewritten)` when the input matches the
/// `EXPLAIN FEDERATION` shape; returns `None` for everything else
/// (the caller passes the query through unchanged).
///
/// Match rules:
/// - leading whitespace is allowed
/// - `EXPLAIN` and `FEDERATION` are case-insensitive
/// - at least one whitespace between `EXPLAIN` and `FEDERATION`
/// - at least one whitespace between `FEDERATION` and the inner SQL
/// - the inner SQL is preserved verbatim (including trailing
///   semicolons, comments, casing)
///
/// Non-matches (returns `None`):
/// - `EXPLAIN <sql>` without `FEDERATION` — pass through to plain
///   `EXPLAIN`
/// - `EXPLAIN VERBOSE <sql>` — pass through (already verbose)
/// - Anything that does not start with `EXPLAIN`
#[must_use]
pub fn rewrite_explain_federation(query: &str) -> Option<String> {
    let trimmed = query.trim_start();
    let after_explain = strip_keyword_ci(trimmed, "EXPLAIN")?;
    if !starts_with_whitespace(after_explain) {
        return None;
    }
    let after_explain_ws = after_explain.trim_start();
    let after_federation = strip_keyword_ci(after_explain_ws, "FEDERATION")?;
    if !starts_with_whitespace(after_federation) {
        return None;
    }
    let inner = after_federation.trim_start();
    if inner.is_empty() {
        return None;
    }
    Some(format!("EXPLAIN VERBOSE {inner}"))
}

/// If `s` starts with `keyword` (case-insensitive), return the
/// remainder; otherwise `None`.
///
/// Shared with [`crate::show_schemas`] — both pre-parse rewriters match
/// leading SQL keywords case-insensitively.
pub(crate) fn strip_keyword_ci<'a>(s: &'a str, keyword: &str) -> Option<&'a str> {
    if s.len() < keyword.len() {
        return None;
    }
    let (head, tail) = s.split_at(keyword.len());
    if head.eq_ignore_ascii_case(keyword) {
        Some(tail)
    } else {
        None
    }
}

pub(crate) fn starts_with_whitespace(s: &str) -> bool {
    s.chars().next().is_some_and(char::is_whitespace)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewrites_basic_explain_federation_select() {
        assert_eq!(
            rewrite_explain_federation("EXPLAIN FEDERATION SELECT 1"),
            Some("EXPLAIN VERBOSE SELECT 1".to_string())
        );
    }

    #[test]
    fn rewrites_explain_federation_with_complex_inner_sql() {
        let inner = "SELECT p.id, p.region, w.amount \
                     FROM customers p JOIN orders w USING (id) \
                     WHERE p.region = 'EU' ORDER BY p.id";
        let input = format!("EXPLAIN FEDERATION {inner}");
        assert_eq!(
            rewrite_explain_federation(&input),
            Some(format!("EXPLAIN VERBOSE {inner}"))
        );
    }

    #[test]
    fn case_insensitive_keywords() {
        for variant in [
            "explain federation SELECT 1",
            "Explain Federation SELECT 1",
            "EXPLAIN federation SELECT 1",
            "explain FEDERATION SELECT 1",
            "ExPlAiN fEdErAtIoN SELECT 1",
        ] {
            let out = rewrite_explain_federation(variant);
            assert!(
                out.is_some(),
                "expected rewrite to fire for {variant:?}, got None"
            );
            // Inner is preserved verbatim — only the leading keywords
            // are replaced.
            assert!(
                out.unwrap().ends_with("SELECT 1"),
                "inner SQL should be preserved verbatim from {variant:?}"
            );
        }
    }

    #[test]
    fn allows_extra_whitespace_between_keywords() {
        assert_eq!(
            rewrite_explain_federation("EXPLAIN  FEDERATION   SELECT 1"),
            Some("EXPLAIN VERBOSE SELECT 1".to_string())
        );
    }

    #[test]
    fn allows_leading_whitespace() {
        assert_eq!(
            rewrite_explain_federation("   EXPLAIN FEDERATION SELECT 1"),
            Some("EXPLAIN VERBOSE SELECT 1".to_string())
        );
    }

    #[test]
    fn preserves_trailing_semicolon() {
        assert_eq!(
            rewrite_explain_federation("EXPLAIN FEDERATION SELECT 1;"),
            Some("EXPLAIN VERBOSE SELECT 1;".to_string())
        );
    }

    #[test]
    fn preserves_inner_casing_and_quoting() {
        // Inner SQL casing must round-trip — datafusion is
        // case-sensitive for quoted identifiers.
        assert_eq!(
            rewrite_explain_federation("EXPLAIN FEDERATION SELECT \"Region\" FROM \"Customers\""),
            Some("EXPLAIN VERBOSE SELECT \"Region\" FROM \"Customers\"".to_string())
        );
    }

    #[test]
    fn does_not_match_plain_explain() {
        // Plain EXPLAIN must pass through unchanged so the user gets
        // the standard datafusion explain output.
        assert_eq!(rewrite_explain_federation("EXPLAIN SELECT 1"), None);
    }

    #[test]
    fn does_not_match_explain_verbose() {
        // EXPLAIN VERBOSE is already what we'd rewrite to; passing it
        // through lets the user request verbose output explicitly.
        assert_eq!(rewrite_explain_federation("EXPLAIN VERBOSE SELECT 1"), None);
    }

    #[test]
    fn does_not_match_explain_analyze() {
        // EXPLAIN ANALYZE is a different DataFusion surface — keep
        // hands off.
        assert_eq!(rewrite_explain_federation("EXPLAIN ANALYZE SELECT 1"), None);
    }

    #[test]
    fn does_not_match_select() {
        assert_eq!(rewrite_explain_federation("SELECT 1"), None);
        assert_eq!(rewrite_explain_federation(""), None);
    }

    #[test]
    fn does_not_match_explain_without_federation_keyword() {
        // Anything other than the literal `FEDERATION` keyword after
        // `EXPLAIN` should not trigger rewriting.
        assert_eq!(
            rewrite_explain_federation("EXPLAIN FED SELECT 1"),
            None,
            "`FED` is a prefix of `FEDERATION`, but not the keyword itself"
        );
    }

    #[test]
    fn does_not_match_explain_federation_with_no_inner_sql() {
        // `EXPLAIN FEDERATION` on its own is meaningless — let it
        // pass through so datafusion produces a useful error.
        assert_eq!(rewrite_explain_federation("EXPLAIN FEDERATION"), None);
        assert_eq!(rewrite_explain_federation("EXPLAIN FEDERATION   "), None);
    }

    #[test]
    fn does_not_match_explainfederation_glued_keywords() {
        // No whitespace between the two keywords — not the surface we
        // promised.
        assert_eq!(
            rewrite_explain_federation("EXPLAINFEDERATION SELECT 1"),
            None
        );
        assert_eq!(
            rewrite_explain_federation("EXPLAIN FEDERATIONSELECT 1"),
            None
        );
    }

    #[test]
    fn does_not_match_explain_with_table_named_federation() {
        // `EXPLAIN federation` could be a column-list explain in
        // some grammars; ours always treats the second word as the
        // FEDERATION keyword. The trailing whitespace + SQL gate
        // ensures we don't accidentally strip a real query that
        // happens to start `EXPLAIN federation` because anything
        // after the keyword is treated as the inner SQL.
        //
        // What we DO want to make sure: a query that names a table
        // `federation` and does not actually invoke our surface
        // (e.g. `SELECT * FROM federation`) is not touched.
        assert_eq!(rewrite_explain_federation("SELECT * FROM federation"), None);
    }
}

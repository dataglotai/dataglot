//! `SHOW SCHEMAS` SQL surface — pgwire compatibility shim.
//!
//! # What this is
//!
//! A pre-parse rewrite hook applied at the pg wire boundary, the same
//! mechanism as [`crate::explain`]. DataFusion's SQL planner supports
//! `SHOW TABLES` / `SHOW COLUMNS` / `SHOW CATALOGS` but **not**
//! `SHOW SCHEMAS` — it returns `This feature is not implemented:
//! Unsupported SQL statement: SHOW SCHEMAS`. Some BI / JDBC tools emit
//! it for schema discovery, so we rewrite it into an
//! `information_schema.schemata` query before the inner parser sees it:
//!
//! - `SHOW SCHEMAS`
//!   -> `SELECT DISTINCT schema_name FROM information_schema.schemata ORDER BY schema_name`
//! - `SHOW SCHEMAS {FROM|IN} <catalog>`
//!   -> `SELECT schema_name ... WHERE catalog_name = '<catalog>' ...`
//!
//! `information_schema.schemata` is already populated (the session is
//! built `with_information_schema(true)`), exposing `catalog_name` /
//! `schema_name`.
//!
//! # Why a pre-parse rewrite (and not a custom statement)
//!
//! Identical rationale to [`crate::explain`]: minimal blast radius,
//! lives entirely inside `dataglot-pgwire` (rule 5), and can be retired
//! the moment DataFusion's planner grows native `SHOW SCHEMAS` support.
//!
//! # Limitations
//!
//! * **Cross-catalog `SHOW SCHEMAS`.** Bare `SHOW SCHEMAS` (no `FROM`)
//!   lists schemas across *all* federated catalogs, not just the
//!   session's current catalog. Trino scopes the bare form to the
//!   current catalog, but our session's `current_database()` is not yet
//!   reliable, and cross-catalog visibility is arguably more
//!   useful in a federation engine. Use the explicit
//!   `SHOW SCHEMAS FROM <catalog>` form to scope.
//! * **No `LIKE` pattern.** `SHOW SCHEMAS [FROM c] LIKE '...'` is not
//!   rewritten — anything after the catalog identifier makes the
//!   matcher decline (returns `None`) so the original passes through to
//!   DataFusion unchanged rather than being mis-rewritten.
//! * **Simple-query path only**, same as [`crate::explain`].

use crate::explain::{starts_with_whitespace, strip_keyword_ci};

/// Rewrite a `SHOW SCHEMAS [ {FROM|IN} <catalog> ]` query into an
/// `information_schema.schemata` `SELECT`.
///
/// Returns `Some(rewritten)` when the input matches the shape; returns
/// `None` for everything else (the caller passes the query through
/// unchanged).
///
/// Match rules:
/// - leading/trailing whitespace and a single trailing `;` are allowed
/// - `SHOW`, `SCHEMAS`, `FROM`, `IN` are case-insensitive
/// - the catalog must be a single identifier (optionally double-quoted);
///   any trailing tokens (e.g. a `LIKE` clause) make the matcher decline
#[must_use]
pub fn rewrite_show_schemas(query: &str) -> Option<String> {
    let mut s = query.trim();
    // Tolerate a single trailing semicolon (simple-query statements).
    if let Some(stripped) = s.strip_suffix(';') {
        s = stripped.trim_end();
    }

    let after_show = strip_keyword_ci(s, "SHOW")?;
    if !starts_with_whitespace(after_show) {
        return None;
    }
    let after_schemas = strip_keyword_ci(after_show.trim_start(), "SCHEMAS")?;

    // Bare `SHOW SCHEMAS` — list every schema across all catalogs.
    if after_schemas.trim().is_empty() {
        return Some(BARE.to_string());
    }
    // `SCHEMAS` must be followed by whitespace before any `FROM`/`IN`,
    // otherwise this is some other token (e.g. `SCHEMASX`) — decline.
    if !starts_with_whitespace(after_schemas) {
        return None;
    }

    let rest = after_schemas.trim_start();
    let after_kw = strip_keyword_ci(rest, "FROM").or_else(|| strip_keyword_ci(rest, "IN"))?;
    if !starts_with_whitespace(after_kw) {
        return None;
    }

    // Exactly one token must remain: the catalog identifier. A trailing
    // `LIKE`/pattern (or anything else) means we don't understand the
    // statement — decline so it passes through unchanged.
    let catalog_tok = after_kw.trim();
    if catalog_tok.split_whitespace().count() != 1 {
        return None;
    }
    let catalog = catalog_tok.trim_matches('"');
    if catalog.is_empty() {
        return None;
    }
    // Escape single quotes for safe interpolation into the string literal.
    let escaped = catalog.replace('\'', "''");
    Some(format!(
        "SELECT schema_name FROM information_schema.schemata \
         WHERE catalog_name = '{escaped}' ORDER BY schema_name"
    ))
}

// Bare form spans every catalog, so DISTINCT collapses the schema names
// that recur across catalogs (e.g. `public`, `pg_catalog`) into one row
// each — a clean discovery list rather than one row per catalog.
const BARE: &str =
    "SELECT DISTINCT schema_name FROM information_schema.schemata ORDER BY schema_name";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewrites_bare_show_schemas() {
        assert_eq!(rewrite_show_schemas("SHOW SCHEMAS"), Some(BARE.to_string()));
    }

    #[test]
    fn rewrites_with_trailing_semicolon_and_whitespace() {
        assert_eq!(
            rewrite_show_schemas("  SHOW SCHEMAS ;  "),
            Some(BARE.to_string())
        );
    }

    #[test]
    fn rewrites_show_schemas_from_catalog() {
        assert_eq!(
            rewrite_show_schemas("SHOW SCHEMAS FROM tpch"),
            Some(
                "SELECT schema_name FROM information_schema.schemata \
                 WHERE catalog_name = 'tpch' ORDER BY schema_name"
                    .to_string()
            )
        );
    }

    #[test]
    fn rewrites_show_schemas_in_catalog() {
        // `IN` is the Trino-equivalent synonym for `FROM` here.
        assert_eq!(
            rewrite_show_schemas("show schemas in pg_orders"),
            Some(
                "SELECT schema_name FROM information_schema.schemata \
                 WHERE catalog_name = 'pg_orders' ORDER BY schema_name"
                    .to_string()
            )
        );
    }

    #[test]
    fn strips_double_quotes_around_catalog() {
        assert_eq!(
            rewrite_show_schemas("SHOW SCHEMAS FROM \"pg\""),
            Some(
                "SELECT schema_name FROM information_schema.schemata \
                 WHERE catalog_name = 'pg' ORDER BY schema_name"
                    .to_string()
            )
        );
    }

    #[test]
    fn case_insensitive_keywords() {
        for v in [
            "SHOW SCHEMAS",
            "show schemas",
            "Show Schemas",
            "ShOw ScHeMaS",
        ] {
            assert_eq!(rewrite_show_schemas(v), Some(BARE.to_string()), "{v:?}");
        }
    }

    #[test]
    fn escapes_single_quote_in_catalog_name() {
        // Defensive: a quote in the identifier must not break out of the
        // string literal.
        let out = rewrite_show_schemas("SHOW SCHEMAS FROM \"o'brien\"").unwrap();
        assert!(out.contains("catalog_name = 'o''brien'"), "{out}");
    }

    #[test]
    fn declines_show_tables() {
        // `SHOW TABLES` is handled natively by DataFusion — don't touch.
        assert_eq!(rewrite_show_schemas("SHOW TABLES"), None);
    }

    #[test]
    fn declines_show_schemas_like_pattern() {
        // We don't rewrite the LIKE form; pass through unchanged rather
        // than produce wrong SQL.
        assert_eq!(rewrite_show_schemas("SHOW SCHEMAS LIKE 'p%'"), None);
        assert_eq!(rewrite_show_schemas("SHOW SCHEMAS FROM pg LIKE 'p%'"), None);
    }

    #[test]
    fn declines_glued_or_partial_keywords() {
        assert_eq!(rewrite_show_schemas("SHOWSCHEMAS"), None);
        assert_eq!(rewrite_show_schemas("SHOW SCHEMASX"), None);
        assert_eq!(rewrite_show_schemas("SHOW SCHEMA"), None);
    }

    #[test]
    fn declines_from_without_catalog() {
        assert_eq!(rewrite_show_schemas("SHOW SCHEMAS FROM"), None);
        assert_eq!(rewrite_show_schemas("SHOW SCHEMAS FROM   "), None);
    }

    #[test]
    fn declines_unrelated_statements() {
        assert_eq!(rewrite_show_schemas("SELECT 1"), None);
        assert_eq!(rewrite_show_schemas(""), None);
        assert_eq!(rewrite_show_schemas("SHOW CATALOGS"), None);
    }
}

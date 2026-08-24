//! PostgreSQL-dialect compatibility shims at the pg wire boundary
//!, companions to [`crate::explain`] and [`crate::show_schemas`].
//!
//! A full Postgres-dialect coverage audit found that Dataglot rejects a
//! handful of **session- and transaction-control** statements that real
//! Postgres clients and middleware emit — most importantly the reset
//! statements connection poolers (pgbouncer) run on every connection
//! reset. They error with `Unsupported SQL statement`, which breaks any
//! deployment that puts a pooler in front of Dataglot.
//!
//! Dataglot's pgwire surface is a **read-only** federation/governance
//! engine: each connection is effectively stateless and transactions are
//! no-ops, so there is nothing to discard, reset, or save. These
//! statements are therefore safe to **accept as successful no-ops**
//! rather than error.
//!
//! # Two shims
//!
//! - [`noop_command_tag`] — whole-statement matcher for the no-op
//!   session/txn statements. The caller short-circuits and returns a
//!   `Response::Execution(Tag::new(tag))` without touching DataFusion.
//! - [`rewrite_table`] — rewrites the Postgres `TABLE <name>` shorthand
//!   into `SELECT * FROM <name>` (DataFusion's parser rejects `TABLE` as
//!   a statement), in the same pre-parse style as the other rewriters.
//!
//! # What is intentionally NOT here
//!
//! Writes / DDL / admin (`INSERT`, `CREATE`, `GRANT`, `VACUUM`,
//! `LISTEN`, …) correctly continue to error — they are out of scope for a
//! read-only federation surface. See  for the deferred long tail
//! (`FETCH FIRST` → use `LIMIT`; `current_catalog` → `current_database()`;
//! `format()`, `pg_typeof()`).

use crate::explain::{starts_with_whitespace, strip_keyword_ci};

/// If `s` begins with `keyword` (case-insensitive) followed by a word
/// boundary (whitespace or end of string), return the remainder.
///
/// Distinct from [`strip_keyword_ci`], which matches a bare prefix and
/// would accept `RESETX` as `RESET`; this enforces the boundary so only
/// genuine leading keywords match.
fn after_command<'a>(s: &'a str, keyword: &str) -> Option<&'a str> {
    let rest = strip_keyword_ci(s, keyword)?;
    if rest.is_empty() || starts_with_whitespace(rest) {
        Some(rest)
    } else {
        None
    }
}

/// Match a session/transaction-control statement that a read-only engine
/// can safely treat as a successful no-op, returning the Postgres command
/// tag to report (e.g. `"DISCARD"`).
///
/// Matches (case-insensitive, single statement, optional trailing `;`):
/// - `DISCARD ...` (ALL / PLANS / SEQUENCES / TEMP / TEMPORARY)
/// - `RESET ...` (a name, or `ALL`)
/// - `SAVEPOINT ...`
/// - `RELEASE ...` (`RELEASE [SAVEPOINT] <name>`)
/// - `ROLLBACK TO ...` — **only** the savepoint form; plain `ROLLBACK`
///   returns `None` so DataFusion handles it as a real transaction end.
///
/// Returns `None` for anything else (including multi-statement strings),
/// so the caller passes the query through unchanged.
#[must_use]
pub fn noop_command_tag(query: &str) -> Option<&'static str> {
    let mut s = query.trim();
    if let Some(stripped) = s.strip_suffix(';') {
        s = stripped.trim_end();
    }
    // Only handle a single statement; a remaining `;` means several.
    if s.contains(';') {
        return None;
    }

    if after_command(s, "DISCARD").is_some() {
        return Some("DISCARD");
    }
    if after_command(s, "RESET").is_some() {
        return Some("RESET");
    }
    if after_command(s, "SAVEPOINT").is_some() {
        return Some("SAVEPOINT");
    }
    if after_command(s, "RELEASE").is_some() {
        return Some("RELEASE");
    }
    // `ROLLBACK TO [SAVEPOINT] <name>` only — never plain `ROLLBACK`,
    // which DataFusion handles natively as a transaction end.
    if let Some(rest) = after_command(s, "ROLLBACK") {
        if after_command(rest.trim_start(), "TO").is_some() {
            return Some("ROLLBACK");
        }
    }
    None
}

/// Rewrite the Postgres `TABLE <name>` shorthand into
/// `SELECT * FROM <name>` (DataFusion's parser does not accept `TABLE`
/// as a statement). Returns `None` for anything else.
///
/// Only the bare single-reference form is handled (`TABLE foo`,
/// `TABLE a.b.c`); a trailing `ORDER BY`/`LIMIT`/etc. makes the matcher
/// decline so it passes through unchanged rather than be mis-rewritten.
/// Statements that merely *contain* `TABLE` (`CREATE TABLE`, `DROP
/// TABLE`, `LOCK TABLE`, …) never match — they don't start with it.
#[must_use]
pub fn rewrite_table(query: &str) -> Option<String> {
    let mut s = query.trim();
    if let Some(stripped) = s.strip_suffix(';') {
        s = stripped.trim_end();
    }
    let rest = strip_keyword_ci(s, "TABLE")?;
    if !starts_with_whitespace(rest) {
        return None;
    }
    let name = rest.trim();
    // Exactly one token — a bare table reference. Anything else (a
    // trailing clause) we don't understand; decline.
    if name.is_empty() || name.split_whitespace().count() != 1 {
        return None;
    }
    Some(format!("SELECT * FROM {name}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discard_all_is_noop() {
        assert_eq!(noop_command_tag("DISCARD ALL"), Some("DISCARD"));
        assert_eq!(noop_command_tag("discard all;"), Some("DISCARD"));
        assert_eq!(noop_command_tag("  DISCARD ALL  "), Some("DISCARD"));
    }

    #[test]
    fn reset_is_noop() {
        assert_eq!(noop_command_tag("RESET search_path"), Some("RESET"));
        assert_eq!(noop_command_tag("RESET ALL"), Some("RESET"));
        assert_eq!(noop_command_tag("reset statement_timeout;"), Some("RESET"));
    }

    #[test]
    fn savepoint_family_is_noop() {
        assert_eq!(noop_command_tag("SAVEPOINT s1"), Some("SAVEPOINT"));
        assert_eq!(noop_command_tag("RELEASE s1"), Some("RELEASE"));
        assert_eq!(noop_command_tag("RELEASE SAVEPOINT s1"), Some("RELEASE"));
        assert_eq!(noop_command_tag("ROLLBACK TO s1"), Some("ROLLBACK"));
        assert_eq!(
            noop_command_tag("ROLLBACK TO SAVEPOINT s1"),
            Some("ROLLBACK")
        );
    }

    #[test]
    fn plain_rollback_is_not_intercepted() {
        // Plain ROLLBACK / COMMIT / BEGIN are real transaction control —
        // DataFusion handles them, so we must NOT swallow them.
        assert_eq!(noop_command_tag("ROLLBACK"), None);
        assert_eq!(noop_command_tag("ROLLBACK;"), None);
        assert_eq!(noop_command_tag("COMMIT"), None);
        assert_eq!(noop_command_tag("BEGIN"), None);
    }

    #[test]
    fn word_boundary_enforced() {
        // Don't match keywords glued to more text.
        assert_eq!(noop_command_tag("RESETX foo"), None);
        assert_eq!(noop_command_tag("DISCARDED"), None);
        assert_eq!(noop_command_tag("SAVEPOINTER"), None);
    }

    #[test]
    fn multi_statement_not_intercepted() {
        // A reset bundled with other statements must go through the real
        // planner, not be swallowed wholesale.
        assert_eq!(noop_command_tag("RESET ALL; SELECT 1"), None);
        assert_eq!(noop_command_tag("DISCARD ALL; SELECT 1"), None);
    }

    #[test]
    fn unrelated_statements_not_intercepted() {
        assert_eq!(noop_command_tag("SELECT 1"), None);
        assert_eq!(noop_command_tag("SET search_path TO public"), None);
        assert_eq!(noop_command_tag(""), None);
    }

    #[test]
    fn rewrites_table_shorthand() {
        assert_eq!(
            rewrite_table("TABLE region"),
            Some("SELECT * FROM region".to_string())
        );
        assert_eq!(
            rewrite_table("table tpch.public.region;"),
            Some("SELECT * FROM tpch.public.region".to_string())
        );
        assert_eq!(
            rewrite_table("  TABLE \"My Tbl\"  "),
            None,
            "quoted name with a space is multi-token; decline rather than mangle"
        );
    }

    #[test]
    fn table_does_not_match_ddl_or_clauses() {
        // Statements containing TABLE but not starting with it.
        assert_eq!(rewrite_table("CREATE TABLE t (id int)"), None);
        assert_eq!(rewrite_table("DROP TABLE t"), None);
        assert_eq!(rewrite_table("LOCK TABLE t"), None);
        // Trailing clause after the table name — decline.
        assert_eq!(rewrite_table("TABLE region ORDER BY r_name"), None);
        assert_eq!(rewrite_table("TABLE"), None);
    }
}

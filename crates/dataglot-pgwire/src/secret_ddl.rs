//! `CREATE / DROP SECRET` DDL — first-class secrets for the SQL-native control
//! plane.
//!
//! A secret is a named, encrypted-at-rest credential in the meta store that a
//! catalog can reference (`dsn = secret <name>`) instead of inlining a password
//! or DSN in `CREATE CATALOG … WITH (…)`. Like [`crate::catalog_ddl`], the
//! statement has no DataFusion planner equivalent, so the pgwire handler detects
//! it at the wire boundary *before* planning and routes it to the control-plane
//! admin seam. This module is the parser half: statement text → typed
//! [`SecretDdl`]; the server-side admin encrypts + persists (later slices).
//!
//! # Grammar
//!
//! ```text
//! CREATE [OR REPLACE] SECRET [IF NOT EXISTS] <name> AS '<value>'
//! DROP   SECRET [IF EXISTS] <name>
//!
//! <name>  ::= bare identifier | "<double-quoted>"
//! <value> ::= '<single-quoted>' | "<double-quoted>" | <bare-token>
//! ```
//!
//! The lexing (keywords, identifiers, quoted values) reuses
//! [`crate::catalog_ddl`]'s helpers, so the two DDL surfaces stay consistent:
//! keywords are case-insensitive, a single trailing `;` is tolerated, and a
//! doubled quote inside a quoted value is one literal quote (so a DSN value
//! survives its `=` and spaces intact).
//!
//! # Rule 12 (credential isolation)
//!
//! The secret *value* is the whole point of a secret, so [`SecretDdl`]'s
//! [`std::fmt::Debug`] is **hand-written to redact it** — a stray
//! `tracing::debug!(?ddl)` or a test-failure dump can never leak the plaintext.
//! `PartialEq` still compares the value (tests assert on it deliberately).

use std::fmt;

use crate::catalog_ddl::{keyword, parse_identifier, parse_value};

/// A parsed secret-DDL statement.
///
/// `Debug` redacts the secret value (rule 12); `PartialEq` does not.
#[derive(Clone, PartialEq, Eq)]
pub enum SecretDdl {
    /// `CREATE [OR REPLACE] SECRET [IF NOT EXISTS] <name> AS '<value>'`.
    Create {
        /// Secret name (unquoted content).
        name: String,
        /// The secret plaintext — encrypted before it ever reaches the store.
        value: String,
        /// `OR REPLACE` was present.
        or_replace: bool,
        /// `IF NOT EXISTS` was present.
        if_not_exists: bool,
    },
    /// `DROP SECRET [IF EXISTS] <name>`.
    Drop {
        /// Secret name.
        name: String,
        /// `IF EXISTS` was present.
        if_exists: bool,
    },
}

impl fmt::Debug for SecretDdl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Create {
                name,
                or_replace,
                if_not_exists,
                // Never format the plaintext — rule 12.
                value: _,
            } => f
                .debug_struct("Create")
                .field("name", name)
                .field("value", &"<redacted>")
                .field("or_replace", or_replace)
                .field("if_not_exists", if_not_exists)
                .finish(),
            Self::Drop { name, if_exists } => f
                .debug_struct("Drop")
                .field("name", name)
                .field("if_exists", if_exists)
                .finish(),
        }
    }
}

/// Parse a `CREATE | DROP SECRET` statement, or `None` for anything else (and
/// for malformed secret DDL — the caller passes those through so the planner
/// surfaces a clear error rather than this module half-interpreting them).
#[must_use]
pub fn parse_secret_ddl(query: &str) -> Option<SecretDdl> {
    let mut s = query.trim();
    if let Some(stripped) = s.strip_suffix(';') {
        s = stripped.trim_end();
    }
    if let Some(rest) = keyword(s, "CREATE") {
        return parse_create(rest);
    }
    if let Some(rest) = keyword(s, "DROP") {
        return parse_drop(rest);
    }
    None
}

/// `CREATE …` remainder (after `CREATE`).
fn parse_create(s: &str) -> Option<SecretDdl> {
    // Optional `OR REPLACE`.
    let (or_replace, s) = if let Some(after_or) = keyword(s, "OR") {
        (true, keyword(after_or, "REPLACE")?)
    } else {
        (false, s)
    };
    let s = keyword(s, "SECRET")?;
    // Optional `IF NOT EXISTS`.
    let (if_not_exists, s) = if let Some(after_if) = keyword(s, "IF") {
        let after_not = keyword(after_if, "NOT")?;
        (true, keyword(after_not, "EXISTS")?)
    } else {
        (false, s)
    };
    let (name, s) = parse_identifier(s)?;
    let s = keyword(s.trim_start(), "AS")?;
    let (value, rest) = parse_value(s.trim_start())?;
    // Nothing may follow the value (a trailing `;` was already stripped).
    if !rest.trim().is_empty() {
        return None;
    }
    Some(SecretDdl::Create {
        name,
        value,
        or_replace,
        if_not_exists,
    })
}

/// `DROP …` remainder (after `DROP`).
fn parse_drop(s: &str) -> Option<SecretDdl> {
    let s = keyword(s, "SECRET")?;
    let (if_exists, s) = if let Some(after_if) = keyword(s, "IF") {
        (true, keyword(after_if, "EXISTS")?)
    } else {
        (false, s)
    };
    let (name, rest) = parse_identifier(s)?;
    if !rest.trim().is_empty() {
        return None;
    }
    Some(SecretDdl::Drop { name, if_exists })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_basic() {
        let ddl = parse_secret_ddl("CREATE SECRET pg_pw AS 'hunter2'").unwrap();
        assert_eq!(
            ddl,
            SecretDdl::Create {
                name: "pg_pw".to_string(),
                value: "hunter2".to_string(),
                or_replace: false,
                if_not_exists: false,
            }
        );
    }

    #[test]
    fn create_value_with_equals_and_spaces_preserved() {
        // A whole DSN as a secret value keeps its `=` and spaces.
        let ddl = parse_secret_ddl("CREATE SECRET dsn AS 'host=db port=5432 dbname=x'").unwrap();
        let SecretDdl::Create { name, value, .. } = ddl else {
            panic!("expected Create, got {ddl:?}");
        };
        assert_eq!(name, "dsn");
        assert_eq!(value, "host=db port=5432 dbname=x");
    }

    #[test]
    fn create_or_replace_if_not_exists_case_insensitive() {
        let ddl = parse_secret_ddl("create or replace secret IF NOT EXISTS s As 'v'").unwrap();
        assert_eq!(
            ddl,
            SecretDdl::Create {
                name: "s".to_string(),
                value: "v".to_string(),
                or_replace: true,
                if_not_exists: true,
            }
        );
    }

    #[test]
    fn create_escaped_quote_in_value() {
        // A doubled single-quote is one literal quote.
        let ddl = parse_secret_ddl("CREATE SECRET s AS 'a''b'").unwrap();
        let SecretDdl::Create { value, .. } = ddl else {
            panic!("expected Create, got {ddl:?}");
        };
        assert_eq!(value, "a'b");
    }

    #[test]
    fn create_quoted_name_and_trailing_semicolon() {
        let ddl = parse_secret_ddl("CREATE SECRET \"My Secret\" AS 'v';").unwrap();
        let SecretDdl::Create { name, value, .. } = ddl else {
            panic!("expected Create, got {ddl:?}");
        };
        assert_eq!(name, "My Secret");
        assert_eq!(value, "v");
    }

    #[test]
    fn drop_and_drop_if_exists() {
        assert_eq!(
            parse_secret_ddl("DROP SECRET s").unwrap(),
            SecretDdl::Drop {
                name: "s".to_string(),
                if_exists: false,
            }
        );
        assert_eq!(
            parse_secret_ddl("drop secret if exists s;").unwrap(),
            SecretDdl::Drop {
                name: "s".to_string(),
                if_exists: true,
            }
        );
    }

    #[test]
    fn non_secret_ddl_passes_through() {
        assert!(parse_secret_ddl("CREATE CATALOG c WITH (kind='postgres')").is_none());
        assert!(parse_secret_ddl("SELECT 1").is_none());
        assert!(parse_secret_ddl("CREATE TABLE t (a int)").is_none());
    }

    #[test]
    fn malformed_secret_ddl_declines() {
        // Missing `AS`.
        assert!(parse_secret_ddl("CREATE SECRET s 'v'").is_none());
        // Missing value.
        assert!(parse_secret_ddl("CREATE SECRET s AS").is_none());
        // Trailing junk after DROP name.
        assert!(parse_secret_ddl("DROP SECRET s extra").is_none());
        // Trailing junk after value.
        assert!(parse_secret_ddl("CREATE SECRET s AS 'v' extra").is_none());
    }

    #[test]
    fn debug_redacts_value() {
        let ddl = parse_secret_ddl("CREATE SECRET s AS 'super-secret'").unwrap();
        let shown = format!("{ddl:?}");
        assert!(shown.contains("<redacted>"), "{shown}");
        assert!(
            !shown.contains("super-secret"),
            "Debug must not leak the value: {shown}"
        );
    }
}

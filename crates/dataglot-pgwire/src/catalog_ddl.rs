//! `CREATE / ALTER / DROP CATALOG` DDL — the SQL-native control-plane surface
//!
//! DataFusion's planner has no `CREATE CATALOG` statement, so — exactly like
//! [`crate::show_schemas`] and [`crate::explain`] — the pgwire handler detects
//! these at the wire boundary *before* planning and routes them to the
//! control-plane admin seam (which builds the source, persists it to the meta
//! store, and registers it into the live session). This module is the parser
//! half: it turns the statement text into a typed [`CatalogDdl`]; the handler
//! + the server-side `CatalogAdmin` impl (later slices) do the effecting.
//!
//! # Grammar (a RisingWave-style option-bag DDL, not pg `CREATE SERVER`)
//!
//! ```text
//! CREATE [OR REPLACE] CATALOG [IF NOT EXISTS] <name> WITH ( <opt> [, <opt>]* )
//! ALTER  CATALOG <name> WITH ( <opt> [, <opt>]* )
//! DROP   CATALOG [IF EXISTS] <name>
//!
//! <opt>  ::= <key> = <value>
//! <key>  ::= bare identifier                       (lower-cased)
//! <value>::= '<single-quoted>' | "<double-quoted>" | <bare-token>
//! <name> ::= bare identifier | "<double-quoted>"
//! ```
//!
//! Single-/double-quoted values keep their content verbatim (a doubled quote
//! `''` / `""` is an escaped literal quote) — so a DSN like
//! `dsn = 'host=db port=5432 dbname=x'` survives its `=` and spaces intact.
//! Keywords are case-insensitive and a single trailing `;` is tolerated.
//!
//! Anything that isn't catalog DDL — including `CREATE TABLE`, which stays a
//! DataFusion concern — parses to `None` and passes through unchanged; so does
//! *malformed* catalog DDL, so the planner surfaces a clear error rather than
//! this module half-interpreting it.

use std::collections::HashMap;

use crate::explain::{starts_with_whitespace, strip_keyword_ci};

/// A parsed catalog-DDL statement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CatalogDdl {
    /// `CREATE [OR REPLACE] CATALOG [IF NOT EXISTS] <name> WITH (<options>)`.
    Create {
        /// Catalog name (unquoted content).
        name: String,
        /// `WITH (...)` options, keys lower-cased.
        options: HashMap<String, String>,
        /// `OR REPLACE` was present.
        or_replace: bool,
        /// `IF NOT EXISTS` was present.
        if_not_exists: bool,
    },
    /// `ALTER CATALOG <name> WITH (<options>)` — replaces the option set.
    Alter {
        /// Catalog name.
        name: String,
        /// New `WITH (...)` options, keys lower-cased.
        options: HashMap<String, String>,
    },
    /// `DROP CATALOG [IF EXISTS] <name>`.
    Drop {
        /// Catalog name.
        name: String,
        /// `IF EXISTS` was present.
        if_exists: bool,
    },
}

/// Parse a `CREATE | ALTER | DROP CATALOG` statement, or `None` for anything
/// else (and for malformed catalog DDL — the caller passes those through).
#[must_use]
pub fn parse_catalog_ddl(query: &str) -> Option<CatalogDdl> {
    let mut s = query.trim();
    if let Some(stripped) = s.strip_suffix(';') {
        s = stripped.trim_end();
    }
    if let Some(rest) = keyword(s, "CREATE") {
        return parse_create(rest);
    }
    if let Some(rest) = keyword(s, "ALTER") {
        return parse_alter(rest);
    }
    if let Some(rest) = keyword(s, "DROP") {
        return parse_drop(rest);
    }
    None
}

/// Strip a leading keyword that is followed by whitespace (a real word
/// boundary), returning the trimmed remainder. `None` if the keyword isn't a
/// whole-word prefix.
pub(crate) fn keyword<'a>(s: &'a str, kw: &str) -> Option<&'a str> {
    let rest = strip_keyword_ci(s, kw)?;
    if starts_with_whitespace(rest) {
        Some(rest.trim_start())
    } else {
        None
    }
}

/// `CREATE …` remainder (after `CREATE`).
fn parse_create(s: &str) -> Option<CatalogDdl> {
    // Optional `OR REPLACE`.
    let (or_replace, s) = if let Some(after_or) = keyword(s, "OR") {
        (true, keyword(after_or, "REPLACE")?)
    } else {
        (false, s)
    };
    let s = keyword(s, "CATALOG")?;
    // Optional `IF NOT EXISTS`.
    let (if_not_exists, s) = if let Some(after_if) = keyword(s, "IF") {
        let after_not = keyword(after_if, "NOT")?;
        (true, keyword(after_not, "EXISTS")?)
    } else {
        (false, s)
    };
    let (name, s) = parse_identifier(s)?;
    let s = keyword(s.trim_start(), "WITH")?;
    let options = parse_option_bag(s)?;
    Some(CatalogDdl::Create {
        name,
        options,
        or_replace,
        if_not_exists,
    })
}

/// `ALTER …` remainder (after `ALTER`).
fn parse_alter(s: &str) -> Option<CatalogDdl> {
    let s = keyword(s, "CATALOG")?;
    let (name, s) = parse_identifier(s)?;
    let s = keyword(s.trim_start(), "WITH")?;
    let options = parse_option_bag(s)?;
    Some(CatalogDdl::Alter { name, options })
}

/// `DROP …` remainder (after `DROP`).
fn parse_drop(s: &str) -> Option<CatalogDdl> {
    let s = keyword(s, "CATALOG")?;
    let (if_exists, s) = if let Some(after_if) = keyword(s, "IF") {
        (true, keyword(after_if, "EXISTS")?)
    } else {
        (false, s)
    };
    let (name, rest) = parse_identifier(s)?;
    // Nothing may follow the name (a trailing `;` was already stripped).
    if !rest.trim().is_empty() {
        return None;
    }
    Some(CatalogDdl::Drop { name, if_exists })
}

/// Parse a catalog name: a double-quoted identifier or a bare identifier.
pub(crate) fn parse_identifier(s: &str) -> Option<(String, &str)> {
    let s = s.trim_start();
    if let Some(rest) = s.strip_prefix('"') {
        parse_quoted(rest, '"')
    } else {
        let (id, rest) = parse_bare_ident(s)?;
        Some((id.to_string(), rest))
    }
}

/// Read a bare identifier `[A-Za-z_][A-Za-z0-9_]*`, returning `(ident, rest)`.
fn parse_bare_ident(s: &str) -> Option<(&str, &str)> {
    let first = s.chars().next()?;
    if !(first.is_alphabetic() || first == '_') {
        return None;
    }
    let end = s
        .find(|c: char| !(c.is_alphanumeric() || c == '_'))
        .unwrap_or(s.len());
    Some((&s[..end], &s[end..]))
}

/// Parse `( key = value , ... )` into a `key -> value` map (keys lower-cased,
/// values verbatim). `None` on any malformed shape.
///
/// Shared with [`crate::policy_ddl`]'s `WITH ( type = '…' )` mask option bag so
/// every control-plane DDL surface reads options identically.
pub(crate) fn parse_option_bag(s: &str) -> Option<HashMap<String, String>> {
    let mut rest = s.trim_start().strip_prefix('(')?;
    let mut opts = HashMap::new();
    loop {
        rest = rest.trim_start();
        if let Some(after) = rest.strip_prefix(')') {
            return after.trim().is_empty().then_some(opts);
        }
        if !opts.is_empty() {
            // Entries after the first are comma-separated; no trailing comma.
            rest = rest.strip_prefix(',')?.trim_start();
        }
        let (key, r) = parse_bare_ident(rest)?;
        rest = r.trim_start().strip_prefix('=')?.trim_start();
        let (value, r) = parse_value(rest)?;
        opts.insert(key.to_ascii_lowercase(), value);
        rest = r;
    }
}

/// Parse an option value: single-quoted, double-quoted, or a bare token
/// (terminated by whitespace, `,`, or `)`).
pub(crate) fn parse_value(s: &str) -> Option<(String, &str)> {
    if let Some(rest) = s.strip_prefix('\'') {
        parse_quoted(rest, '\'')
    } else if let Some(rest) = s.strip_prefix('"') {
        parse_quoted(rest, '"')
    } else {
        let end = s
            .find(|c: char| c == ',' || c == ')' || c.is_whitespace())
            .unwrap_or(s.len());
        if end == 0 {
            return None;
        }
        Some((s[..end].to_string(), &s[end..]))
    }
}

/// Read a quoted string body (the opening quote already consumed) up to the
/// closing `quote`, treating a doubled quote as one literal quote. Returns
/// `(content, rest_after_closing_quote)`; `None` if unterminated.
fn parse_quoted(s: &str, quote: char) -> Option<(String, &str)> {
    let qb = quote as u8; // quotes are ASCII
    let bytes = s.as_bytes();
    let mut out = String::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == qb {
            if bytes.get(i + 1) == Some(&qb) {
                out.push(quote); // escaped literal quote
                i += 2;
            } else {
                return Some((out, &s[i + 1..]));
            }
        } else {
            let ch = s[i..].chars().next()?;
            out.push(ch);
            i += ch.len_utf8();
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create(q: &str) -> CatalogDdl {
        parse_catalog_ddl(q).unwrap_or_else(|| panic!("should parse: {q}"))
    }

    #[test]
    fn create_with_options() {
        let d = create("CREATE CATALOG pg WITH (kind = 'postgres', dsn_env = 'PG_DSN')");
        let CatalogDdl::Create {
            name,
            options,
            or_replace,
            if_not_exists,
        } = d
        else {
            panic!("expected Create");
        };
        assert_eq!(name, "pg");
        assert!(!or_replace && !if_not_exists);
        assert_eq!(options["kind"], "postgres");
        assert_eq!(options["dsn_env"], "PG_DSN");
    }

    #[test]
    fn quoted_dsn_keeps_equals_and_spaces() {
        // The whole point of quoting: a DSN with `=` and spaces stays intact.
        let d = create("CREATE CATALOG pg WITH (dsn = 'host=db port=5432 dbname=x')");
        let CatalogDdl::Create { options, .. } = d else {
            panic!()
        };
        assert_eq!(options["dsn"], "host=db port=5432 dbname=x");
    }

    #[test]
    fn or_replace_if_not_exists_and_case_insensitivity() {
        let d = create("create or replace catalog if not exists \"My Cat\" with (kind='mysql')");
        let CatalogDdl::Create {
            name,
            or_replace,
            if_not_exists,
            options,
        } = d
        else {
            panic!()
        };
        assert_eq!(name, "My Cat"); // quoted identifier keeps its spaces/case
        assert!(or_replace && if_not_exists);
        assert_eq!(options["kind"], "mysql");
    }

    #[test]
    fn escaped_quote_in_value() {
        let d = create("CREATE CATALOG c WITH (note = 'a''b')");
        let CatalogDdl::Create { options, .. } = d else {
            panic!()
        };
        assert_eq!(options["note"], "a'b");
    }

    #[test]
    fn bare_value_and_trailing_semicolon() {
        let d = create("CREATE CATALOG c WITH (concurrency = 4);");
        let CatalogDdl::Create { options, .. } = d else {
            panic!()
        };
        assert_eq!(options["concurrency"], "4");
    }

    #[test]
    fn alter_replaces_options() {
        let d = create("ALTER CATALOG pg WITH (dsn_env = 'NEW')");
        let CatalogDdl::Alter { name, options } = d else {
            panic!("expected Alter");
        };
        assert_eq!(name, "pg");
        assert_eq!(options["dsn_env"], "NEW");
    }

    #[test]
    fn drop_and_drop_if_exists() {
        assert_eq!(
            create("DROP CATALOG pg"),
            CatalogDdl::Drop {
                name: "pg".into(),
                if_exists: false
            }
        );
        assert_eq!(
            create("drop catalog if exists pg;"),
            CatalogDdl::Drop {
                name: "pg".into(),
                if_exists: true
            }
        );
    }

    #[test]
    fn empty_option_bag_ok() {
        let d = create("CREATE CATALOG c WITH ()");
        let CatalogDdl::Create { options, .. } = d else {
            panic!()
        };
        assert!(options.is_empty());
    }

    #[test]
    fn non_catalog_ddl_passes_through() {
        // CREATE TABLE stays a DataFusion concern; SELECT/other never match.
        assert!(parse_catalog_ddl("CREATE TABLE t (a int)").is_none());
        assert!(parse_catalog_ddl("SELECT 1").is_none());
        assert!(parse_catalog_ddl("CREATE CATALOGX foo WITH (a=1)").is_none());
        assert!(parse_catalog_ddl("").is_none());
    }

    #[test]
    fn malformed_catalog_ddl_declines() {
        // Missing WITH, unterminated quote, trailing junk after DROP name,
        // trailing comma — all decline so the planner reports a clear error.
        assert!(parse_catalog_ddl("CREATE CATALOG pg").is_none());
        assert!(parse_catalog_ddl("CREATE CATALOG pg WITH (dsn = 'unterminated)").is_none());
        assert!(parse_catalog_ddl("DROP CATALOG pg EXTRA").is_none());
        assert!(parse_catalog_ddl("CREATE CATALOG c WITH (a=1,)").is_none());
        assert!(parse_catalog_ddl("CREATE OR CATALOG c WITH (a=1)").is_none());
    }
}

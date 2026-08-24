//! `CREATE / DROP VIEW` DDL — the SQL-native derived-product surface (
//! slice F9).
//!
//! A `CREATE VIEW` maps internally to a Dataglot **derived product** (the same
//! concept the config `[[derived_products]]` block declares). DataFusion's
//! planner *does* have a `CREATE VIEW` statement, but its view is session-local
//! and ephemeral; Dataglot's derived products are org-scoped and store-backed,
//! exactly like `CREATE CATALOG`. So — like [`crate::catalog_ddl`] — the pgwire
//! handler detects `CREATE / DROP VIEW` at the wire boundary *before* planning
//! and routes it to the control-plane admin seam (which validates the query,
//! persists the definition, and registers it live so subsequent connections can
//! query it). This module is the parser half: it turns the statement text into
//! a typed [`ViewDdl`]; the handler + the server-side [`crate::view_admin::ViewAdmin`]
//! impl do the effecting.
//!
//! # Grammar
//!
//! ```text
//! CREATE [OR REPLACE] VIEW [<catalog>.<schema>.]<name> AS <query>
//! DROP   VIEW [IF EXISTS] [<catalog>.<schema>.]<name>
//!
//! <name>  ::= bare identifier | "<double-quoted>" (optionally dotted, ≤3 parts)
//! <query> ::= arbitrary SQL, captured VERBATIM (everything after `AS`)
//! ```
//!
//! Plain (non-materialized) views only in v1: `CREATE MATERIALIZED VIEW …`
//! begins `CREATE … MATERIALIZED`, which is not `VIEW`, so it declines here and
//! passes through unchanged (materialization DDL is a future follow-up).
//!
//! The `AS <query>` body is captured **verbatim** — byte-for-byte the remainder
//! of the statement after the `AS` keyword — just as the catalog DSN is captured
//! verbatim, because it is arbitrary SQL the planner (not this module) must
//! interpret. Keywords are case-insensitive and a single trailing `;` is
//! tolerated.
//!
//! Anything that isn't view DDL — or is *malformed* view DDL (no `AS`, an empty
//! body, trailing junk after a `DROP` name) — parses to `None` and passes
//! through, so the planner surfaces a clear error rather than this module
//! half-interpreting it.

use crate::catalog_ddl::{keyword, parse_identifier};

/// A parsed view-DDL statement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ViewDdl {
    /// `CREATE [OR REPLACE] VIEW [cat.sch.]name AS <query>`.
    Create {
        /// Optional catalog qualifier (`None` ⇒ server default).
        catalog: Option<String>,
        /// Optional schema qualifier (`None` ⇒ server default).
        schema: Option<String>,
        /// View / derived-product name.
        name: String,
        /// The verbatim `AS <query>` body — arbitrary SQL.
        query: String,
        /// `OR REPLACE` was present.
        or_replace: bool,
    },
    /// `DROP VIEW [IF EXISTS] [cat.sch.]name`.
    Drop {
        /// Optional catalog qualifier.
        catalog: Option<String>,
        /// Optional schema qualifier.
        schema: Option<String>,
        /// View / derived-product name.
        name: String,
        /// `IF EXISTS` was present.
        if_exists: bool,
    },
}

/// Parse a `CREATE | DROP VIEW` statement, or `None` for anything else (and for
/// malformed view DDL — the caller passes those through to the planner).
#[must_use]
pub fn parse_view_ddl(query: &str) -> Option<ViewDdl> {
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
fn parse_create(s: &str) -> Option<ViewDdl> {
    // Optional `OR REPLACE`.
    let (or_replace, s) = if let Some(after_or) = keyword(s, "OR") {
        (true, keyword(after_or, "REPLACE")?)
    } else {
        (false, s)
    };
    // Must be `VIEW` (a bare word). `CREATE MATERIALIZED VIEW` fails here and
    // passes through — materialized views are out of scope for v1.
    let s = keyword(s, "VIEW")?;
    let (catalog, schema, name, rest) = parse_dotted_name(s)?;
    // The next whole word must be `AS`; everything after it is the verbatim body.
    let after_as = keyword(rest.trim_start(), "AS")?;
    let body = after_as.trim();
    if body.is_empty() {
        // `CREATE VIEW x AS` with no query is malformed — decline.
        return None;
    }
    Some(ViewDdl::Create {
        catalog,
        schema,
        name,
        query: body.to_string(),
        or_replace,
    })
}

/// `DROP …` remainder (after `DROP`).
fn parse_drop(s: &str) -> Option<ViewDdl> {
    let s = keyword(s, "VIEW")?;
    let (if_exists, s) = if let Some(after_if) = keyword(s, "IF") {
        (true, keyword(after_if, "EXISTS")?)
    } else {
        (false, s)
    };
    let (catalog, schema, name, rest) = parse_dotted_name(s)?;
    // Nothing may follow the name (a trailing `;` was already stripped).
    if !rest.trim().is_empty() {
        return None;
    }
    Some(ViewDdl::Drop {
        catalog,
        schema,
        name,
        if_exists,
    })
}

/// Parse a (possibly dotted, ≤3-part) object name into
/// `(catalog, schema, name, rest)`. One part ⇒ `name`; two ⇒ `schema.name`;
/// three ⇒ `catalog.schema.name`. Each part is a bare or double-quoted
/// identifier. `None` on an empty or >3-part name.
fn parse_dotted_name(s: &str) -> Option<(Option<String>, Option<String>, String, &str)> {
    let (first, mut rest) = parse_identifier(s)?;
    let mut parts = vec![first];
    loop {
        let r = rest.trim_start();
        let Some(after_dot) = r.strip_prefix('.') else {
            break;
        };
        let (part, r2) = parse_identifier(after_dot)?;
        parts.push(part);
        rest = r2;
        if parts.len() > 3 {
            return None;
        }
    }
    let (catalog, schema, name) = match parts.len() {
        1 => (None, None, parts.remove(0)),
        2 => {
            let name = parts.remove(1);
            (None, Some(parts.remove(0)), name)
        }
        3 => {
            let name = parts.remove(2);
            let schema = parts.remove(1);
            (Some(parts.remove(0)), Some(schema), name)
        }
        // 0 is impossible (first is always pushed); >3 returned early above.
        _ => return None,
    };
    Some((catalog, schema, name, rest))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(q: &str) -> ViewDdl {
        parse_view_ddl(q).unwrap_or_else(|| panic!("should parse: {q}"))
    }

    #[test]
    fn create_bare_name_captures_verbatim_body() {
        let d = parse("CREATE VIEW active AS SELECT id, email FROM users WHERE active = true");
        let ViewDdl::Create {
            catalog,
            schema,
            name,
            query,
            or_replace,
        } = d
        else {
            panic!("expected Create");
        };
        assert_eq!(catalog, None);
        assert_eq!(schema, None);
        assert_eq!(name, "active");
        assert!(!or_replace);
        // Body captured verbatim, byte-for-byte after `AS`.
        assert_eq!(query, "SELECT id, email FROM users WHERE active = true");
    }

    #[test]
    fn create_or_replace_and_case_insensitivity() {
        let d = parse("create or replace view v as select 1");
        let ViewDdl::Create {
            name,
            query,
            or_replace,
            ..
        } = d
        else {
            panic!("expected Create");
        };
        assert_eq!(name, "v");
        assert!(or_replace);
        assert_eq!(query, "select 1");
    }

    #[test]
    fn create_qualified_three_part_name() {
        let d = parse("CREATE VIEW pg.public.v AS SELECT * FROM t");
        let ViewDdl::Create {
            catalog,
            schema,
            name,
            query,
            ..
        } = d
        else {
            panic!("expected Create");
        };
        assert_eq!(catalog.as_deref(), Some("pg"));
        assert_eq!(schema.as_deref(), Some("public"));
        assert_eq!(name, "v");
        assert_eq!(query, "SELECT * FROM t");
    }

    #[test]
    fn create_two_part_name_is_schema_qualified() {
        let d = parse("CREATE VIEW public.v AS SELECT 1");
        let ViewDdl::Create {
            catalog,
            schema,
            name,
            ..
        } = d
        else {
            panic!("expected Create");
        };
        assert_eq!(catalog, None);
        assert_eq!(schema.as_deref(), Some("public"));
        assert_eq!(name, "v");
    }

    #[test]
    fn create_quoted_name_keeps_case_and_spaces() {
        let d = parse("CREATE VIEW \"My View\" AS SELECT 1");
        let ViewDdl::Create { name, .. } = d else {
            panic!("expected Create");
        };
        assert_eq!(name, "My View");
    }

    #[test]
    fn body_with_semicolon_stripped_and_joins_preserved() {
        // Trailing `;` stripped; the join body is preserved verbatim.
        let d =
            parse("CREATE VIEW j AS SELECT a.x, b.y FROM a JOIN b ON a.id = b.id WHERE a.x > 1;");
        let ViewDdl::Create { query, .. } = d else {
            panic!("expected Create");
        };
        assert_eq!(
            query,
            "SELECT a.x, b.y FROM a JOIN b ON a.id = b.id WHERE a.x > 1"
        );
    }

    #[test]
    fn drop_and_drop_if_exists() {
        assert_eq!(
            parse("DROP VIEW v"),
            ViewDdl::Drop {
                catalog: None,
                schema: None,
                name: "v".into(),
                if_exists: false,
            }
        );
        assert_eq!(
            parse("drop view if exists pg.public.v;"),
            ViewDdl::Drop {
                catalog: Some("pg".into()),
                schema: Some("public".into()),
                name: "v".into(),
                if_exists: true,
            }
        );
    }

    #[test]
    fn non_view_ddl_passes_through() {
        // CREATE TABLE / CATALOG stay other concerns; SELECT never matches.
        assert!(parse_view_ddl("CREATE TABLE t (a int)").is_none());
        assert!(parse_view_ddl("CREATE CATALOG c WITH (kind='postgres')").is_none());
        assert!(parse_view_ddl("SELECT 1").is_none());
        assert!(parse_view_ddl("").is_none());
        // Materialized views are out of scope for v1 — they pass through.
        assert!(parse_view_ddl("CREATE MATERIALIZED VIEW v AS SELECT 1").is_none());
    }

    #[test]
    fn malformed_view_ddl_declines() {
        // No `AS`, empty body, trailing junk after DROP name, >3-part name.
        assert!(parse_view_ddl("CREATE VIEW x").is_none());
        assert!(parse_view_ddl("CREATE VIEW x SELECT 1").is_none());
        assert!(parse_view_ddl("CREATE VIEW x AS").is_none());
        assert!(parse_view_ddl("CREATE VIEW x AS   ").is_none());
        assert!(parse_view_ddl("DROP VIEW v EXTRA").is_none());
        assert!(parse_view_ddl("CREATE VIEW a.b.c.d AS SELECT 1").is_none());
    }
}

//! `CREATE / DROP MASK` and `CREATE / DROP ROW FILTER` DDL — the SQL-native
//! governance surface for the control plane.
//!
//! Column masks and row filters are the two plan-time enforcement objects the
//! policy engine already applies (`dataglot-policy`; they map onto
//! `dataglot-server`'s `MaskConfig` / `RowFilterConfig`). Like
//! [`crate::catalog_ddl`], [`crate::secret_ddl`], and [`crate::user_ddl`], these
//! statements have no DataFusion planner equivalent, so the pgwire handler
//! detects them at the wire boundary *before* planning and routes them to the
//! control-plane admin seam (M4b). This module is the parser half: statement
//! text → typed [`PolicyDdl`]; M4b persists the rule and wires it into the
//! runtime enforcer.
//!
//! # Grammar (Snowflake-flavoured, grounded on the enforcer's shapes)
//!
//! ```text
//! CREATE MASK [IF NOT EXISTS] <name> ON <table> ( <column> ) AS '<literal>'
//! CREATE MASK [IF NOT EXISTS] <name> ON <table> ( <column> ) WITH ( type = '<kind>' [, <k>=<v>]* )
//! CREATE ROW FILTER [IF NOT EXISTS] <name> ON <table> USING ( <predicate-expr> )
//! DROP   MASK       [IF EXISTS] <name>
//! DROP   ROW FILTER [IF EXISTS] <name>
//!
//! <name>      ::= bare identifier | "<double-quoted>"
//! <table>     ::= <ident> [ '.' <ident> ]*        (bare | schema.table | catalog.schema.table)
//! <column>    ::= bare identifier | "<double-quoted>"
//! <literal>   ::= '<single-quoted>' | "<double-quoted>" | <bare-token>
//! <predicate> ::= arbitrary balanced-paren SQL boolean expression
//! ```
//!
//! ## How the grammar maps onto the enforcer
//!
//! - `<table>` is stored verbatim as the dotted string written, matching
//!   `MaskConfig.table` / `RowFilterConfig.table`, which are a single `String`
//!   the enforcer keys on as a `DataFusion` `TableReference` (bare / partial /
//!   full). The DDL doesn't reinterpret it — `pg.public.users` stays
//!   `pg.public.users`.
//! - The mask literal-vs-type split mirrors `MaskConfig`: `AS '<literal>'` maps
//!   to `MaskConfig.mask_literal`; `WITH ( type = '<kind>' … )` maps to
//!   `MaskConfig.mask_type` (a `MaskTypeConfig`), with any remaining options
//!   (e.g. `keep = 4` for `show_last`) carried alongside for M4b to assemble.
//! - The row-filter `USING ( <predicate> )` maps to `RowFilterConfig.predicate`
//!   as the `RowPredicateConfig::Sql { sql }` escape hatch — the full boolean
//!   SQL surface (`AND` / `OR` / `LIKE` / `IS NULL` / …).
//!
//! The lexing (keywords, identifiers, quoted values, the `WITH ( … )` option
//! bag) reuses [`crate::catalog_ddl`]'s helpers, so every control-plane DDL
//! surface stays consistent: keywords are case-insensitive, a single trailing
//! `;` is tolerated, and a doubled quote inside a quoted value is one literal
//! quote.
//!
//! Anything that isn't policy DDL — including `CREATE CATALOG` / `SECRET` /
//! `USER` and ordinary SQL — parses to `None` and passes through unchanged; so
//! does *malformed* policy DDL, so the planner surfaces a clear error rather
//! than this module half-interpreting it.
//!
//! Governance rules aren't credentials (unlike secrets/passwords), so
//! [`PolicyDdl`] derives a plain `Debug` — the predicate/literal are
//! config-level, not secrets.

use std::collections::HashMap;

use crate::catalog_ddl::{keyword, parse_identifier, parse_option_bag, parse_value};

/// How a [`PolicyDdl::CreateMask`] replaces its column — mirrors the
/// literal-vs-type split of `MaskConfig` (`mask_literal` vs `mask_type`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyMask {
    /// `AS '<literal>'` — a constant Utf8 replacement. Maps to
    /// `MaskConfig.mask_literal`.
    Literal(String),
    /// `WITH ( type = '<kind>' [, <k>=<v>]* )` — a named mask type. Maps to
    /// `MaskConfig.mask_type` (a `MaskTypeConfig`); `mask_type` is the `type`
    /// value (e.g. `redact` / `hash` / `show_last`) and `options` carries any
    /// remaining keys (e.g. `keep = 4`), lower-cased, for M4b to assemble.
    Typed {
        /// The `type = '<kind>'` value, verbatim (lower-cased by the caller if
        /// desired — kept as written here).
        mask_type: String,
        /// Remaining `WITH ( … )` options, keys lower-cased, `type` removed.
        options: HashMap<String, String>,
    },
}

/// A parsed policy-DDL statement (column mask or row filter).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyDdl {
    /// `CREATE MASK [IF NOT EXISTS] <name> ON <table> ( <column> ) …`.
    CreateMask {
        /// Policy name (unquoted content).
        name: String,
        /// Target table — the dotted string as written (`MaskConfig.table`).
        table: String,
        /// Target column within `table` (`MaskConfig.column`).
        column: String,
        /// How the column is masked (`MaskConfig` literal-vs-type split).
        mask: PolicyMask,
        /// `IF NOT EXISTS` was present.
        if_not_exists: bool,
    },
    /// `CREATE ROW FILTER [IF NOT EXISTS] <name> ON <table> USING ( <expr> )`.
    CreateRowFilter {
        /// Policy name.
        name: String,
        /// Target table — the dotted string as written (`RowFilterConfig.table`).
        table: String,
        /// Boolean SQL predicate the row must satisfy — maps to
        /// `RowPredicateConfig::Sql { sql }`. Captured verbatim (inner text
        /// between the `USING ( … )` parens, trimmed).
        predicate: String,
        /// `IF NOT EXISTS` was present.
        if_not_exists: bool,
    },
    /// `DROP MASK [IF EXISTS] <name>`.
    DropMask {
        /// Policy name.
        name: String,
        /// `IF EXISTS` was present.
        if_exists: bool,
    },
    /// `DROP ROW FILTER [IF EXISTS] <name>`.
    DropRowFilter {
        /// Policy name.
        name: String,
        /// `IF EXISTS` was present.
        if_exists: bool,
    },
}

/// Parse a `CREATE | DROP MASK` or `CREATE | DROP ROW FILTER` statement, or
/// `None` for anything else (and for malformed policy DDL — the caller passes
/// those through so the planner surfaces a clear error rather than this module
/// half-interpreting them).
#[must_use]
pub fn parse_policy_ddl(query: &str) -> Option<PolicyDdl> {
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

/// `CREATE …` remainder — dispatches to MASK or ROW FILTER.
fn parse_create(s: &str) -> Option<PolicyDdl> {
    if let Some(rest) = keyword(s, "MASK") {
        return parse_create_mask(rest);
    }
    if let Some(rest) = parse_row_filter_kw(s) {
        return parse_create_row_filter(rest);
    }
    None
}

/// `DROP …` remainder — dispatches to MASK or ROW FILTER.
fn parse_drop(s: &str) -> Option<PolicyDdl> {
    if let Some(rest) = keyword(s, "MASK") {
        let (if_exists, rest) = parse_if_exists(rest)?;
        let (name, tail) = parse_identifier(rest)?;
        if !tail.trim().is_empty() {
            return None;
        }
        return Some(PolicyDdl::DropMask { name, if_exists });
    }
    if let Some(rest) = parse_row_filter_kw(s) {
        let (if_exists, rest) = parse_if_exists(rest)?;
        let (name, tail) = parse_identifier(rest)?;
        if !tail.trim().is_empty() {
            return None;
        }
        return Some(PolicyDdl::DropRowFilter { name, if_exists });
    }
    None
}

/// `CREATE MASK …` remainder (after `MASK`).
fn parse_create_mask(s: &str) -> Option<PolicyDdl> {
    let (if_not_exists, s) = parse_if_not_exists(s)?;
    let (name, s) = parse_identifier(s)?;
    let s = keyword(s.trim_start(), "ON")?;
    let (table, s) = parse_table_ref(s)?;
    let (column, s) = parse_parenthesized_ident(s)?;
    let s = s.trim_start();
    // `AS '<literal>'` or `WITH ( type = '<kind>' … )`.
    if let Some(after_as) = keyword(s, "AS") {
        let (literal, rest) = parse_value(after_as.trim_start())?;
        if !rest.trim().is_empty() {
            return None;
        }
        return Some(PolicyDdl::CreateMask {
            name,
            table,
            column,
            mask: PolicyMask::Literal(literal),
            if_not_exists,
        });
    }
    if let Some(after_with) = keyword(s, "WITH") {
        let mut options = parse_option_bag(after_with)?;
        // The `type` key is mandatory in the typed form — it names the
        // MaskTypeConfig variant. Everything else is variant params (e.g.
        // `keep`) M4b assembles.
        let mask_type = options.remove("type")?;
        return Some(PolicyDdl::CreateMask {
            name,
            table,
            column,
            mask: PolicyMask::Typed { mask_type, options },
            if_not_exists,
        });
    }
    None
}

/// `CREATE ROW FILTER …` remainder (after `ROW FILTER`).
fn parse_create_row_filter(s: &str) -> Option<PolicyDdl> {
    let (if_not_exists, s) = parse_if_not_exists(s)?;
    let (name, s) = parse_identifier(s)?;
    let s = keyword(s.trim_start(), "ON")?;
    let (table, s) = parse_table_ref(s)?;
    let s = keyword(s.trim_start(), "USING")?;
    let (predicate, rest) = parse_balanced_parens(s.trim_start())?;
    if !rest.trim().is_empty() {
        return None;
    }
    let predicate = predicate.trim().to_string();
    if predicate.is_empty() {
        return None;
    }
    Some(PolicyDdl::CreateRowFilter {
        name,
        table,
        predicate,
        if_not_exists,
    })
}

/// Match the two-word `ROW FILTER` keyword, returning the remainder after it.
fn parse_row_filter_kw(s: &str) -> Option<&str> {
    let after_row = keyword(s, "ROW")?;
    keyword(after_row, "FILTER")
}

/// Parse a possibly-dotted table reference (`a` / `a.b` / `a.b.c`), each part a
/// bare or double-quoted identifier, joined with `.` verbatim. Returns
/// `(dotted, remainder)`.
fn parse_table_ref(s: &str) -> Option<(String, &str)> {
    let (first, mut rest) = parse_identifier(s)?;
    let mut parts = first;
    // A `.` (no intervening whitespace) continues the reference.
    while let Some(after_dot) = rest.strip_prefix('.') {
        let (part, r) = parse_identifier(after_dot)?;
        parts.push('.');
        parts.push_str(&part);
        rest = r;
    }
    Some((parts, rest))
}

/// Parse `( <ident> )` — a single identifier in parentheses. Returns
/// `(ident, remainder_after_close_paren)`.
fn parse_parenthesized_ident(s: &str) -> Option<(String, &str)> {
    let inner = s.trim_start().strip_prefix('(')?;
    let (ident, rest) = parse_identifier(inner)?;
    let rest = rest.trim_start().strip_prefix(')')?;
    Some((ident, rest))
}

/// Capture the text inside a balanced-parens group `( … )` (the group text
/// only, parens stripped), respecting single-quoted string literals (a doubled
/// `''` is an escaped quote and doesn't close the string). The opening `(` must
/// be the first non-whitespace char. Returns `(inner, remainder_after_close)`;
/// `None` if unbalanced/unterminated.
fn parse_balanced_parens(s: &str) -> Option<(String, &str)> {
    let bytes = s.as_bytes();
    if bytes.first() != Some(&b'(') {
        return None;
    }
    let mut depth = 0usize;
    let mut in_str = false;
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if in_str {
            if c == b'\'' {
                if bytes.get(i + 1) == Some(&b'\'') {
                    i += 2; // escaped quote
                    continue;
                }
                in_str = false;
            }
        } else {
            match c {
                b'\'' => in_str = true,
                b'(' => depth += 1,
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        // Inner text is between the outer parens.
                        return Some((s[1..i].to_string(), &s[i + 1..]));
                    }
                }
                _ => {}
            }
        }
        i += 1;
    }
    None
}

/// Parse an optional leading `IF NOT EXISTS`. Returns `(present, remainder)`;
/// `None` if `IF` is present but not followed by `NOT EXISTS` (malformed).
fn parse_if_not_exists(s: &str) -> Option<(bool, &str)> {
    if let Some(after_if) = keyword(s, "IF") {
        let after_not = keyword(after_if, "NOT")?;
        let after_exists = keyword(after_not, "EXISTS")?;
        Some((true, after_exists))
    } else {
        Some((false, s))
    }
}

/// Parse an optional leading `IF EXISTS`. Returns `(present, remainder)`;
/// `None` if `IF` is present but not followed by `EXISTS` (malformed).
fn parse_if_exists(s: &str) -> Option<(bool, &str)> {
    if let Some(after_if) = keyword(s, "IF") {
        let after_exists = keyword(after_if, "EXISTS")?;
        Some((true, after_exists))
    } else {
        Some((false, s))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(q: &str) -> PolicyDdl {
        parse_policy_ddl(q).unwrap_or_else(|| panic!("should parse: {q}"))
    }

    #[test]
    fn create_mask_literal() {
        assert_eq!(
            parse("CREATE MASK email_mask ON users ( email ) AS '***@example.com'"),
            PolicyDdl::CreateMask {
                name: "email_mask".to_string(),
                table: "users".to_string(),
                column: "email".to_string(),
                mask: PolicyMask::Literal("***@example.com".to_string()),
                if_not_exists: false,
            }
        );
    }

    #[test]
    fn create_mask_typed_redact() {
        let PolicyDdl::CreateMask { mask, .. } =
            parse("CREATE MASK m ON t ( c ) WITH ( type = 'redact' )")
        else {
            panic!("expected CreateMask");
        };
        assert_eq!(
            mask,
            PolicyMask::Typed {
                mask_type: "redact".to_string(),
                options: HashMap::new(),
            }
        );
    }

    #[test]
    fn create_mask_typed_with_extra_options() {
        // `type` is extracted; remaining option (`keep`) is carried for M4b.
        let PolicyDdl::CreateMask { mask, .. } =
            parse("CREATE MASK m ON t ( c ) WITH ( type = 'show_last', keep = 4 )")
        else {
            panic!("expected CreateMask");
        };
        let PolicyMask::Typed { mask_type, options } = mask else {
            panic!("expected Typed");
        };
        assert_eq!(mask_type, "show_last");
        assert_eq!(options.get("keep"), Some(&"4".to_string()));
        assert!(!options.contains_key("type"));
    }

    #[test]
    fn create_mask_typed_requires_type_key() {
        // A WITH bag without `type` is malformed → decline.
        assert!(parse_policy_ddl("CREATE MASK m ON t ( c ) WITH ( keep = 4 )").is_none());
    }

    #[test]
    fn create_mask_qualified_table_names() {
        // Two-part and three-part references stay verbatim.
        let PolicyDdl::CreateMask { table, .. } =
            parse("CREATE MASK m ON public.users ( email ) AS 'x'")
        else {
            panic!();
        };
        assert_eq!(table, "public.users");

        let PolicyDdl::CreateMask { table, column, .. } =
            parse("CREATE MASK m ON pg.public.users ( email ) AS 'x'")
        else {
            panic!();
        };
        assert_eq!(table, "pg.public.users");
        assert_eq!(column, "email");
    }

    #[test]
    fn create_mask_if_not_exists_and_quoted_name() {
        let PolicyDdl::CreateMask {
            name,
            if_not_exists,
            ..
        } = parse("CREATE MASK IF NOT EXISTS \"My Mask\" ON t ( c ) AS 'x'")
        else {
            panic!();
        };
        assert_eq!(name, "My Mask");
        assert!(if_not_exists);
    }

    #[test]
    fn create_row_filter_sql_predicate() {
        assert_eq!(
            parse("CREATE ROW FILTER tenant ON orders USING ( tenant_id = 'acme' )"),
            PolicyDdl::CreateRowFilter {
                name: "tenant".to_string(),
                table: "orders".to_string(),
                predicate: "tenant_id = 'acme'".to_string(),
                if_not_exists: false,
            }
        );
    }

    #[test]
    fn create_row_filter_predicate_with_nested_parens_and_quotes() {
        // Balanced-paren capture keeps inner parens; quoted `)` doesn't close.
        let PolicyDdl::CreateRowFilter { predicate, .. } =
            parse("CREATE ROW FILTER f ON t USING ( (a = 1 OR b = 2) AND note = 'has ) paren' )")
        else {
            panic!("expected CreateRowFilter");
        };
        assert_eq!(predicate, "(a = 1 OR b = 2) AND note = 'has ) paren'");
    }

    #[test]
    fn create_row_filter_if_not_exists_qualified_table() {
        let PolicyDdl::CreateRowFilter {
            table,
            if_not_exists,
            ..
        } = parse("CREATE ROW FILTER f ON pg.public.orders USING ( active )")
        else {
            panic!();
        };
        assert_eq!(table, "pg.public.orders");
        assert!(if_not_exists.eq(&false));

        let PolicyDdl::CreateRowFilter { if_not_exists, .. } =
            parse("CREATE ROW FILTER IF NOT EXISTS f ON t USING ( active )")
        else {
            panic!();
        };
        assert!(if_not_exists);
    }

    #[test]
    fn drop_mask_and_row_filter_with_if_exists() {
        assert_eq!(
            parse("DROP MASK m"),
            PolicyDdl::DropMask {
                name: "m".to_string(),
                if_exists: false,
            }
        );
        assert_eq!(
            parse("DROP MASK IF EXISTS m;"),
            PolicyDdl::DropMask {
                name: "m".to_string(),
                if_exists: true,
            }
        );
        assert_eq!(
            parse("DROP ROW FILTER f"),
            PolicyDdl::DropRowFilter {
                name: "f".to_string(),
                if_exists: false,
            }
        );
        assert_eq!(
            parse("drop row filter if exists f"),
            PolicyDdl::DropRowFilter {
                name: "f".to_string(),
                if_exists: true,
            }
        );
    }

    #[test]
    fn case_insensitivity_and_trailing_semicolon() {
        assert_eq!(
            parse("create mask m on t ( c ) as 'x';"),
            PolicyDdl::CreateMask {
                name: "m".to_string(),
                table: "t".to_string(),
                column: "c".to_string(),
                mask: PolicyMask::Literal("x".to_string()),
                if_not_exists: false,
            }
        );
        let PolicyDdl::CreateRowFilter { name, table, .. } =
            parse("CrEaTe RoW FiLtEr f On t UsInG ( active )")
        else {
            panic!("expected CreateRowFilter");
        };
        assert_eq!(name, "f");
        assert_eq!(table, "t");
    }

    #[test]
    fn non_policy_ddl_passes_through() {
        // Other control-plane DDL and ordinary SQL never match.
        assert!(parse_policy_ddl("CREATE CATALOG c WITH (kind='postgres')").is_none());
        assert!(parse_policy_ddl("CREATE SECRET s AS 'v'").is_none());
        assert!(parse_policy_ddl("CREATE USER alice").is_none());
        assert!(parse_policy_ddl("CREATE TABLE t (a int)").is_none());
        assert!(parse_policy_ddl("SELECT 1").is_none());
        assert!(parse_policy_ddl("").is_none());
        // `MASK`-prefixed word that isn't the keyword.
        assert!(parse_policy_ddl("CREATE MASKX m ON t ( c ) AS 'x'").is_none());
    }

    #[test]
    fn malformed_policy_ddl_declines() {
        // Missing ON.
        assert!(parse_policy_ddl("CREATE MASK m t ( c ) AS 'x'").is_none());
        // Missing column parens.
        assert!(parse_policy_ddl("CREATE MASK m ON t AS 'x'").is_none());
        // Neither AS nor WITH.
        assert!(parse_policy_ddl("CREATE MASK m ON t ( c )").is_none());
        // Unterminated predicate parens.
        assert!(parse_policy_ddl("CREATE ROW FILTER f ON t USING ( active").is_none());
        // Empty predicate.
        assert!(parse_policy_ddl("CREATE ROW FILTER f ON t USING (  )").is_none());
        // Trailing junk after the mask literal.
        assert!(parse_policy_ddl("CREATE MASK m ON t ( c ) AS 'x' extra").is_none());
        // Trailing junk after a DROP name.
        assert!(parse_policy_ddl("DROP MASK m extra").is_none());
        // ROW without FILTER.
        assert!(parse_policy_ddl("CREATE ROW f ON t USING ( active )").is_none());
        // Malformed IF clause.
        assert!(parse_policy_ddl("CREATE MASK IF EXISTS m ON t ( c ) AS 'x'").is_none());
        assert!(parse_policy_ddl("DROP MASK IF NOT EXISTS m").is_none());
    }

    #[test]
    fn debug_is_plain_and_shows_config_level_values() {
        // Governance rules aren't secrets — Debug may show the literal/predicate.
        let ddl = parse("CREATE MASK m ON t ( c ) AS 'plain-value'");
        assert!(format!("{ddl:?}").contains("plain-value"));
        let ddl = parse("CREATE ROW FILTER f ON t USING ( x = 1 )");
        assert!(format!("{ddl:?}").contains("x = 1"));
    }
}

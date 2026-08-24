//! `GRANT / REVOKE` DDL — the SQL-native privilege + role-membership surface for
//! the control plane.
//!
//! Like [`crate::catalog_ddl`], [`crate::secret_ddl`], [`crate::user_ddl`], and
//! [`crate::policy_ddl`], these statements have no DataFusion planner
//! equivalent, so the pgwire handler detects them at the wire boundary *before*
//! planning and routes them to the control-plane admin seam
//! ([`crate::grant_admin`]). This module is the parser half: statement text →
//! typed [`GrantDdl`]; the server-side admin persists the grant / membership to
//! the org-scoped meta store.
//!
//! **Scope (F5a): store only, no enforcement.** A parsed `GRANT` records a
//! privilege; it does **not** change how any query is planned or which rows a
//! reader sees. Enforcement (denying un-granted reads) is a separate follow-up
//! (F5b).
//!
//! # Grammar
//!
//! ```text
//! GRANT  SELECT ON <catalog>.<schema>.<table> TO   <grantee>
//! GRANT  USAGE  ON CATALOG <catalog>          TO   <grantee>
//! GRANT  <role>                               TO   <user>      -- role membership
//! REVOKE SELECT ON <catalog>.<schema>.<table> FROM <grantee>
//! REVOKE USAGE  ON CATALOG <catalog>          FROM <grantee>
//! REVOKE <role>                               FROM <user>      -- role membership
//!
//! <catalog>/<schema>/<table>/<grantee>/<role>/<user>
//!     ::= bare identifier | "<double-quoted>"
//! ```
//!
//! ## Disambiguation (privilege grant vs role membership)
//!
//! After `GRANT` / `REVOKE`, if the next token is a known **privilege keyword**
//! (`SELECT` or `USAGE`) the statement is a *privilege* grant/revoke; otherwise
//! it is role *membership* (`GRANT <role> TO <user>` — no privilege keyword, no
//! `ON`). A consequence is that a role literally named `select` / `usage` cannot
//! be used in the membership form; those two words are reserved here, matching
//! how every other control-plane DDL treats its leading keywords.
//!
//! ## Grantee kind is deferred (F5b)
//!
//! A `<grantee>` in a privilege grant is *just a name* — the grammar carries no
//! `USER` / `ROLE` qualifier, so this parser does not decide whether it is a
//! user or a role, and (like `CREATE MASK` not pre-checking columns) does **not**
//! require it to pre-exist. Resolving the principal is F5b's job. The membership
//! form is the one place the two sides are named distinctly: the left is a role,
//! the right a user.
//!
//! The lexing (keywords, identifiers, quoted values) reuses
//! [`crate::catalog_ddl`]'s helpers, so keywords are case-insensitive and a
//! single trailing `;` is tolerated. Grants are not credentials, so [`GrantDdl`]
//! derives a plain `Debug`.
//!
//! Anything that isn't grant DDL — including the other control-plane DDL and
//! ordinary SQL — parses to `None` and passes through unchanged; so does
//! *malformed* grant DDL, so the planner surfaces a clear error rather than this
//! module half-interpreting it.

use crate::catalog_ddl::{keyword, parse_identifier};

/// A parsed `GRANT` / `REVOKE` statement (privilege or role membership).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrantDdl {
    /// `GRANT SELECT ON <catalog>.<schema>.<table> TO <grantee>`.
    GrantSelect {
        /// Catalog part of the fully-qualified table.
        catalog: String,
        /// Schema part.
        schema: String,
        /// Table part.
        table: String,
        /// Grantee name (user or role — resolved in F5b).
        grantee: String,
    },
    /// `GRANT USAGE ON CATALOG <catalog> TO <grantee>`.
    GrantUsage {
        /// Catalog the usage is granted on.
        catalog: String,
        /// Grantee name (user or role — resolved in F5b).
        grantee: String,
    },
    /// `REVOKE SELECT ON <catalog>.<schema>.<table> FROM <grantee>`.
    RevokeSelect {
        /// Catalog part of the fully-qualified table.
        catalog: String,
        /// Schema part.
        schema: String,
        /// Table part.
        table: String,
        /// Grantee name.
        grantee: String,
    },
    /// `REVOKE USAGE ON CATALOG <catalog> FROM <grantee>`.
    RevokeUsage {
        /// Catalog the usage is revoked on.
        catalog: String,
        /// Grantee name.
        grantee: String,
    },
    /// `GRANT <role> TO <user>` — add a role membership.
    GrantRole {
        /// Role being granted.
        role: String,
        /// User the role is granted to.
        user: String,
    },
    /// `REVOKE <role> FROM <user>` — remove a role membership.
    RevokeRole {
        /// Role being revoked.
        role: String,
        /// User the role is revoked from.
        user: String,
    },
}

/// Parse a `GRANT` / `REVOKE` statement, or `None` for anything else (and for
/// malformed grant DDL — the caller passes those through so the planner surfaces
/// a clear error rather than this module half-interpreting them).
#[must_use]
pub fn parse_grant_ddl(query: &str) -> Option<GrantDdl> {
    let mut s = query.trim();
    if let Some(stripped) = s.strip_suffix(';') {
        s = stripped.trim_end();
    }
    if let Some(rest) = keyword(s, "GRANT") {
        return parse_grant(rest);
    }
    if let Some(rest) = keyword(s, "REVOKE") {
        return parse_revoke(rest);
    }
    None
}

/// `GRANT …` remainder — a privilege grant (`SELECT` / `USAGE`) or role
/// membership (anything else). See the module docs on disambiguation.
fn parse_grant(s: &str) -> Option<GrantDdl> {
    if let Some(rest) = keyword(s, "SELECT") {
        let (catalog, schema, table, grantee) = parse_select_target(rest, "TO")?;
        return Some(GrantDdl::GrantSelect {
            catalog,
            schema,
            table,
            grantee,
        });
    }
    if let Some(rest) = keyword(s, "USAGE") {
        let (catalog, grantee) = parse_usage_target(rest, "TO")?;
        return Some(GrantDdl::GrantUsage { catalog, grantee });
    }
    // Role membership: `GRANT <role> TO <user>`.
    let (role, user) = parse_membership(s, "TO")?;
    Some(GrantDdl::GrantRole { role, user })
}

/// `REVOKE …` remainder — mirror of [`parse_grant`] with `FROM` instead of `TO`.
fn parse_revoke(s: &str) -> Option<GrantDdl> {
    if let Some(rest) = keyword(s, "SELECT") {
        let (catalog, schema, table, grantee) = parse_select_target(rest, "FROM")?;
        return Some(GrantDdl::RevokeSelect {
            catalog,
            schema,
            table,
            grantee,
        });
    }
    if let Some(rest) = keyword(s, "USAGE") {
        let (catalog, grantee) = parse_usage_target(rest, "FROM")?;
        return Some(GrantDdl::RevokeUsage { catalog, grantee });
    }
    let (role, user) = parse_membership(s, "FROM")?;
    Some(GrantDdl::RevokeRole { role, user })
}

/// `ON <catalog>.<schema>.<table> <TO|FROM> <grantee>` (the tail of a `SELECT`
/// privilege statement). The table must be **exactly** three dotted parts.
fn parse_select_target(s: &str, to_kw: &str) -> Option<(String, String, String, String)> {
    let s = keyword(s.trim_start(), "ON")?;
    let (catalog, schema, table, rest) = parse_three_part_table(s.trim_start())?;
    let rest = keyword(rest.trim_start(), to_kw)?;
    let (grantee, tail) = parse_identifier(rest)?;
    if !tail.trim().is_empty() {
        return None;
    }
    Some((catalog, schema, table, grantee))
}

/// `ON CATALOG <catalog> <TO|FROM> <grantee>` (the tail of a `USAGE` statement).
fn parse_usage_target(s: &str, to_kw: &str) -> Option<(String, String)> {
    let s = keyword(s.trim_start(), "ON")?;
    let s = keyword(s.trim_start(), "CATALOG")?;
    let (catalog, rest) = parse_identifier(s.trim_start())?;
    let rest = keyword(rest.trim_start(), to_kw)?;
    let (grantee, tail) = parse_identifier(rest)?;
    if !tail.trim().is_empty() {
        return None;
    }
    Some((catalog, grantee))
}

/// `<role> <TO|FROM> <user>` (role membership). Both sides are bare/quoted
/// identifiers; nothing may follow the user.
fn parse_membership(s: &str, to_kw: &str) -> Option<(String, String)> {
    let (role, rest) = parse_identifier(s)?;
    let rest = keyword(rest.trim_start(), to_kw)?;
    let (user, tail) = parse_identifier(rest)?;
    if !tail.trim().is_empty() {
        return None;
    }
    Some((role, user))
}

/// Parse an **exactly** three-part `catalog.schema.table` reference (each part a
/// bare or double-quoted identifier). Returns `(catalog, schema, table,
/// remainder)`; declines a reference with fewer or more than three parts.
fn parse_three_part_table(s: &str) -> Option<(String, String, String, &str)> {
    let (catalog, rest) = parse_identifier(s)?;
    let rest = rest.strip_prefix('.')?;
    let (schema, rest) = parse_identifier(rest)?;
    let rest = rest.strip_prefix('.')?;
    let (table, rest) = parse_identifier(rest)?;
    // A further `.` would be a fourth part — SELECT requires exactly three.
    if rest.starts_with('.') {
        return None;
    }
    Some((catalog, schema, table, rest))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(q: &str) -> GrantDdl {
        parse_grant_ddl(q).unwrap_or_else(|| panic!("should parse: {q}"))
    }

    #[test]
    fn grant_select_on_qualified_table() {
        assert_eq!(
            parse("GRANT SELECT ON pg.public.orders TO alice"),
            GrantDdl::GrantSelect {
                catalog: "pg".into(),
                schema: "public".into(),
                table: "orders".into(),
                grantee: "alice".into(),
            }
        );
    }

    #[test]
    fn grant_usage_on_catalog() {
        assert_eq!(
            parse("GRANT USAGE ON CATALOG pg TO analyst"),
            GrantDdl::GrantUsage {
                catalog: "pg".into(),
                grantee: "analyst".into(),
            }
        );
    }

    #[test]
    fn grant_role_membership() {
        // No privilege keyword, no ON → membership.
        assert_eq!(
            parse("GRANT analyst TO alice"),
            GrantDdl::GrantRole {
                role: "analyst".into(),
                user: "alice".into(),
            }
        );
    }

    #[test]
    fn revoke_forms_mirror_grant() {
        assert_eq!(
            parse("REVOKE SELECT ON pg.public.orders FROM alice"),
            GrantDdl::RevokeSelect {
                catalog: "pg".into(),
                schema: "public".into(),
                table: "orders".into(),
                grantee: "alice".into(),
            }
        );
        assert_eq!(
            parse("REVOKE USAGE ON CATALOG pg FROM analyst"),
            GrantDdl::RevokeUsage {
                catalog: "pg".into(),
                grantee: "analyst".into(),
            }
        );
        assert_eq!(
            parse("REVOKE analyst FROM alice"),
            GrantDdl::RevokeRole {
                role: "analyst".into(),
                user: "alice".into(),
            }
        );
    }

    #[test]
    fn case_insensitivity_trailing_semicolon_and_quoted_identifiers() {
        assert_eq!(
            parse("grant select on \"My Cat\".\"S\".\"T\" to \"Big Role\";"),
            GrantDdl::GrantSelect {
                catalog: "My Cat".into(),
                schema: "S".into(),
                table: "T".into(),
                grantee: "Big Role".into(),
            }
        );
        let GrantDdl::GrantUsage { catalog, grantee } = parse("GrAnT uSaGe On CaTaLoG pg To alice")
        else {
            panic!("expected GrantUsage");
        };
        assert_eq!(catalog, "pg");
        assert_eq!(grantee, "alice");
    }

    #[test]
    fn non_grant_ddl_passes_through() {
        // Other control-plane DDL and ordinary SQL never match.
        assert!(parse_grant_ddl("CREATE CATALOG c WITH (kind='postgres')").is_none());
        assert!(parse_grant_ddl("CREATE USER alice").is_none());
        assert!(parse_grant_ddl("CREATE MASK m ON t ( c ) AS 'x'").is_none());
        assert!(parse_grant_ddl("SELECT 1").is_none());
        assert!(parse_grant_ddl("").is_none());
        // `GRANT`-prefixed word that isn't the keyword.
        assert!(parse_grant_ddl("GRANTED analyst TO alice").is_none());
    }

    #[test]
    fn malformed_grant_ddl_declines() {
        // SELECT requires a three-part table.
        assert!(parse_grant_ddl("GRANT SELECT ON orders TO alice").is_none());
        assert!(parse_grant_ddl("GRANT SELECT ON public.orders TO alice").is_none());
        // Four-part table is too many parts.
        assert!(parse_grant_ddl("GRANT SELECT ON a.b.c.d TO alice").is_none());
        // SELECT must be ON a table, not ON CATALOG.
        assert!(parse_grant_ddl("GRANT SELECT ON CATALOG pg TO alice").is_none());
        // USAGE must be ON CATALOG, not a bare/table object.
        assert!(parse_grant_ddl("GRANT USAGE ON pg.public.orders TO alice").is_none());
        assert!(parse_grant_ddl("GRANT USAGE ON pg TO alice").is_none());
        // Missing TO / FROM.
        assert!(parse_grant_ddl("GRANT SELECT ON pg.public.orders alice").is_none());
        assert!(parse_grant_ddl("REVOKE analyst alice").is_none());
        // Wrong direction keyword (GRANT wants TO, REVOKE wants FROM).
        assert!(parse_grant_ddl("GRANT analyst FROM alice").is_none());
        assert!(parse_grant_ddl("REVOKE analyst TO alice").is_none());
        // Trailing junk.
        assert!(parse_grant_ddl("GRANT USAGE ON CATALOG pg TO alice extra").is_none());
        assert!(parse_grant_ddl("GRANT analyst TO alice extra").is_none());
        // Missing grantee.
        assert!(parse_grant_ddl("GRANT USAGE ON CATALOG pg TO").is_none());
    }

    #[test]
    fn privilege_keywords_are_reserved_in_membership_position() {
        // `GRANT select TO alice` is read as a (malformed) privilege grant — it
        // needs `ON …`, which is absent — so it declines rather than becoming a
        // membership grant of a role named `select`.
        assert!(parse_grant_ddl("GRANT select TO alice").is_none());
    }

    #[test]
    fn debug_is_plain() {
        // Grants are config-level, not secrets — Debug may show the names.
        let ddl = parse("GRANT SELECT ON pg.public.orders TO alice");
        assert!(format!("{ddl:?}").contains("orders"));
    }
}

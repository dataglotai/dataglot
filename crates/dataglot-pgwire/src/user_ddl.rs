//! `CREATE / ALTER / DROP USER` and `CREATE / DROP ROLE` DDL — the
//! RisingWave-style user/role surface for the SQL-native control plane
//!
//! Like [`crate::catalog_ddl`] and [`crate::secret_ddl`], these statements have
//! no DataFusion planner equivalent, so the pgwire handler detects them at the
//! wire boundary *before* planning and routes them to the control-plane admin
//! seam (M3b). This module is the parser half: statement text → typed
//! [`UserDdl`]; the handler + server-side admin (M3b) hash the password, persist
//! the user/role, and wire it into auth.
//!
//! # Grammar
//!
//! ```text
//! CREATE USER [IF NOT EXISTS] <name> [WITH] [PASSWORD '<pw>'] [SUPERUSER | NOSUPERUSER]
//! ALTER  USER <name> [WITH] PASSWORD '<pw>'
//! DROP   USER [IF EXISTS] <name>
//! CREATE ROLE [IF NOT EXISTS] <name>
//! DROP   ROLE [IF EXISTS] <name>
//!
//! <name> ::= bare identifier | "<double-quoted>"
//! <pw>   ::= '<single-quoted>' | "<double-quoted>" | <bare-token>
//! ```
//!
//! The lexing (keywords, identifiers, quoted values) reuses
//! [`crate::catalog_ddl`]'s helpers, so every control-plane DDL surface stays
//! consistent: keywords are case-insensitive, a single trailing `;` is
//! tolerated, and a doubled quote inside a quoted value is one literal quote (so
//! a password with spaces or an embedded quote survives intact).
//!
//! Anything that isn't user/role DDL — including `CREATE CATALOG` and
//! `CREATE SECRET` — parses to `None` and passes through unchanged; so does
//! *malformed* user DDL, so the planner surfaces a clear error rather than this
//! module half-interpreting it.
//!
//! # Rule 12 (credential isolation)
//!
//! A `PASSWORD` clause is a credential, so [`UserDdl`]'s [`std::fmt::Debug`] is
//! **hand-written to redact it** — a stray `tracing::debug!(?ddl)` or a
//! test-failure dump can never leak the plaintext. `PartialEq` still compares
//! the password (tests assert on it deliberately).

use std::fmt;

use crate::catalog_ddl::{keyword, parse_identifier, parse_value};
use crate::explain::{starts_with_whitespace, strip_keyword_ci};

/// A parsed user/role-DDL statement.
///
/// `Debug` redacts any password (rule 12); `PartialEq` does not.
#[derive(Clone, PartialEq, Eq)]
pub enum UserDdl {
    /// `CREATE USER [IF NOT EXISTS] <name> [WITH] [PASSWORD '<pw>'] [SUPERUSER | NOSUPERUSER]`.
    CreateUser {
        /// User name (unquoted content).
        name: String,
        /// Plaintext password, if a `PASSWORD` clause was present. Hashed by
        /// M3b before it ever reaches the store; `None` = no password (the user
        /// cannot log in with a password).
        password: Option<String>,
        /// `SUPERUSER` was present (`NOSUPERUSER` or omitted ⇒ `false`).
        superuser: bool,
        /// `IF NOT EXISTS` was present.
        if_not_exists: bool,
    },
    /// `ALTER USER <name> [WITH] PASSWORD '<pw>'` — sets a new password.
    AlterUserPassword {
        /// User name.
        name: String,
        /// New plaintext password — hashed by M3b before it reaches the store.
        password: String,
    },
    /// `DROP USER [IF EXISTS] <name>`.
    DropUser {
        /// User name.
        name: String,
        /// `IF EXISTS` was present.
        if_exists: bool,
    },
    /// `CREATE ROLE [IF NOT EXISTS] <name>`.
    CreateRole {
        /// Role name.
        name: String,
        /// `IF NOT EXISTS` was present.
        if_not_exists: bool,
    },
    /// `DROP ROLE [IF EXISTS] <name>`.
    DropRole {
        /// Role name.
        name: String,
        /// `IF EXISTS` was present.
        if_exists: bool,
    },
}

impl fmt::Debug for UserDdl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CreateUser {
                name,
                password,
                superuser,
                if_not_exists,
            } => f
                .debug_struct("CreateUser")
                .field("name", name)
                // Never format the plaintext — rule 12. Preserve whether a
                // password was set without revealing it.
                .field("password", &password.as_ref().map(|_| "<redacted>"))
                .field("superuser", superuser)
                .field("if_not_exists", if_not_exists)
                .finish(),
            Self::AlterUserPassword { name, password: _ } => f
                .debug_struct("AlterUserPassword")
                .field("name", name)
                .field("password", &"<redacted>")
                .finish(),
            Self::DropUser { name, if_exists } => f
                .debug_struct("DropUser")
                .field("name", name)
                .field("if_exists", if_exists)
                .finish(),
            Self::CreateRole {
                name,
                if_not_exists,
            } => f
                .debug_struct("CreateRole")
                .field("name", name)
                .field("if_not_exists", if_not_exists)
                .finish(),
            Self::DropRole { name, if_exists } => f
                .debug_struct("DropRole")
                .field("name", name)
                .field("if_exists", if_exists)
                .finish(),
        }
    }
}

/// Parse a `CREATE | ALTER | DROP USER` or `CREATE | DROP ROLE` statement, or
/// `None` for anything else (and for malformed user DDL — the caller passes
/// those through so the planner surfaces a clear error rather than this module
/// half-interpreting them).
#[must_use]
pub fn parse_user_ddl(query: &str) -> Option<UserDdl> {
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

/// `CREATE …` remainder — dispatches to USER or ROLE.
fn parse_create(s: &str) -> Option<UserDdl> {
    if let Some(rest) = keyword(s, "USER") {
        return parse_create_user(rest);
    }
    if let Some(rest) = keyword(s, "ROLE") {
        return parse_create_role(rest);
    }
    None
}

/// `CREATE USER …` remainder (after `USER`).
fn parse_create_user(s: &str) -> Option<UserDdl> {
    let (if_not_exists, s) = parse_if_not_exists(s)?;
    let (name, s) = parse_identifier(s)?;
    let mut s = s.trim_start();
    // Optional `WITH` noise word.
    if let Some(after_with) = keyword(s, "WITH") {
        s = after_with;
    }
    // Optional `PASSWORD '<pw>'`.
    let mut password = None;
    if let Some(after_pw) = keyword(s, "PASSWORD") {
        let (pw, rest) = parse_value(after_pw.trim_start())?;
        password = Some(pw);
        s = rest.trim_start();
    }
    // Optional `SUPERUSER | NOSUPERUSER` (check the longer word first).
    let mut superuser = false;
    if !s.is_empty() {
        if let Some(rest) = word(s, "NOSUPERUSER") {
            superuser = false;
            s = rest;
        } else {
            // Must be `SUPERUSER`; anything else is trailing junk — decline.
            let rest = word(s, "SUPERUSER")?;
            superuser = true;
            s = rest;
        }
    }
    if !s.trim().is_empty() {
        return None;
    }
    Some(UserDdl::CreateUser {
        name,
        password,
        superuser,
        if_not_exists,
    })
}

/// `CREATE ROLE …` remainder (after `ROLE`).
fn parse_create_role(s: &str) -> Option<UserDdl> {
    let (if_not_exists, s) = parse_if_not_exists(s)?;
    let (name, rest) = parse_identifier(s)?;
    if !rest.trim().is_empty() {
        return None;
    }
    Some(UserDdl::CreateRole {
        name,
        if_not_exists,
    })
}

/// `ALTER …` remainder (after `ALTER`) — only `ALTER USER … PASSWORD` is valid.
fn parse_alter(s: &str) -> Option<UserDdl> {
    let s = keyword(s, "USER")?;
    let (name, s) = parse_identifier(s)?;
    let mut s = s.trim_start();
    // Optional `WITH` noise word.
    if let Some(after_with) = keyword(s, "WITH") {
        s = after_with;
    }
    let s = keyword(s, "PASSWORD")?;
    let (password, rest) = parse_value(s.trim_start())?;
    if !rest.trim().is_empty() {
        return None;
    }
    Some(UserDdl::AlterUserPassword { name, password })
}

/// `DROP …` remainder — dispatches to USER or ROLE.
fn parse_drop(s: &str) -> Option<UserDdl> {
    if let Some(rest) = keyword(s, "USER") {
        let (if_exists, rest) = parse_if_exists(rest)?;
        let (name, tail) = parse_identifier(rest)?;
        if !tail.trim().is_empty() {
            return None;
        }
        return Some(UserDdl::DropUser { name, if_exists });
    }
    if let Some(rest) = keyword(s, "ROLE") {
        let (if_exists, rest) = parse_if_exists(rest)?;
        let (name, tail) = parse_identifier(rest)?;
        if !tail.trim().is_empty() {
            return None;
        }
        return Some(UserDdl::DropRole { name, if_exists });
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

/// Strip a whole-word keyword whose boundary may be whitespace **or
/// end-of-input** (unlike [`keyword`], which requires trailing whitespace).
/// Used for trailing tokens like `SUPERUSER` that can sit at the very end of
/// the statement. Returns the trimmed remainder, or `None` if `kw` isn't a
/// whole-word prefix.
fn word<'a>(s: &'a str, kw: &str) -> Option<&'a str> {
    let rest = strip_keyword_ci(s, kw)?;
    if rest.is_empty() || starts_with_whitespace(rest) {
        Some(rest.trim_start())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(q: &str) -> UserDdl {
        parse_user_ddl(q).unwrap_or_else(|| panic!("should parse: {q}"))
    }

    #[test]
    fn create_user_minimal() {
        assert_eq!(
            parse("CREATE USER alice"),
            UserDdl::CreateUser {
                name: "alice".to_string(),
                password: None,
                superuser: false,
                if_not_exists: false,
            }
        );
    }

    #[test]
    fn create_user_with_password() {
        assert_eq!(
            parse("CREATE USER alice WITH PASSWORD 'hunter2'"),
            UserDdl::CreateUser {
                name: "alice".to_string(),
                password: Some("hunter2".to_string()),
                superuser: false,
                if_not_exists: false,
            }
        );
        // `WITH` is optional.
        assert_eq!(
            parse("CREATE USER alice PASSWORD 'hunter2'"),
            UserDdl::CreateUser {
                name: "alice".to_string(),
                password: Some("hunter2".to_string()),
                superuser: false,
                if_not_exists: false,
            }
        );
    }

    #[test]
    fn create_user_superuser_and_nosuperuser() {
        let UserDdl::CreateUser { superuser, .. } =
            parse("CREATE USER root WITH PASSWORD 'p' SUPERUSER")
        else {
            panic!("expected CreateUser");
        };
        assert!(superuser);

        let UserDdl::CreateUser { superuser, .. } = parse("CREATE USER svc NOSUPERUSER") else {
            panic!("expected CreateUser");
        };
        assert!(!superuser);

        // SUPERUSER without a PASSWORD clause is fine too.
        let UserDdl::CreateUser {
            superuser,
            password,
            ..
        } = parse("CREATE USER root SUPERUSER")
        else {
            panic!("expected CreateUser");
        };
        assert!(superuser);
        assert!(password.is_none());
    }

    #[test]
    fn create_user_if_not_exists() {
        assert_eq!(
            parse("CREATE USER IF NOT EXISTS alice"),
            UserDdl::CreateUser {
                name: "alice".to_string(),
                password: None,
                superuser: false,
                if_not_exists: true,
            }
        );
    }

    #[test]
    fn password_with_spaces_and_escaped_quote() {
        // Quoting keeps spaces intact; a doubled single-quote is one literal.
        let UserDdl::CreateUser { password, .. } =
            parse("CREATE USER a WITH PASSWORD 'p a ss''w0rd'")
        else {
            panic!("expected CreateUser");
        };
        assert_eq!(password, Some("p a ss'w0rd".to_string()));
    }

    #[test]
    fn quoted_identifier_name() {
        let UserDdl::CreateUser { name, .. } = parse("CREATE USER \"Alice Smith\"") else {
            panic!("expected CreateUser");
        };
        assert_eq!(name, "Alice Smith");
    }

    #[test]
    fn alter_user_password() {
        assert_eq!(
            parse("ALTER USER alice WITH PASSWORD 'new'"),
            UserDdl::AlterUserPassword {
                name: "alice".to_string(),
                password: "new".to_string(),
            }
        );
        // `WITH` optional here too.
        assert_eq!(
            parse("ALTER USER alice PASSWORD 'new'"),
            UserDdl::AlterUserPassword {
                name: "alice".to_string(),
                password: "new".to_string(),
            }
        );
    }

    #[test]
    fn drop_user_and_if_exists() {
        assert_eq!(
            parse("DROP USER alice"),
            UserDdl::DropUser {
                name: "alice".to_string(),
                if_exists: false,
            }
        );
        assert_eq!(
            parse("DROP USER IF EXISTS alice;"),
            UserDdl::DropUser {
                name: "alice".to_string(),
                if_exists: true,
            }
        );
    }

    #[test]
    fn create_and_drop_role() {
        assert_eq!(
            parse("CREATE ROLE analyst"),
            UserDdl::CreateRole {
                name: "analyst".to_string(),
                if_not_exists: false,
            }
        );
        assert_eq!(
            parse("CREATE ROLE IF NOT EXISTS analyst"),
            UserDdl::CreateRole {
                name: "analyst".to_string(),
                if_not_exists: true,
            }
        );
        assert_eq!(
            parse("DROP ROLE analyst"),
            UserDdl::DropRole {
                name: "analyst".to_string(),
                if_exists: false,
            }
        );
        assert_eq!(
            parse("DROP ROLE IF EXISTS analyst"),
            UserDdl::DropRole {
                name: "analyst".to_string(),
                if_exists: true,
            }
        );
    }

    #[test]
    fn case_insensitivity_and_trailing_semicolon() {
        assert_eq!(
            parse("create user alice with password 'p' nosuperuser;"),
            UserDdl::CreateUser {
                name: "alice".to_string(),
                password: Some("p".to_string()),
                superuser: false,
                if_not_exists: false,
            }
        );
        let UserDdl::CreateUser { superuser, .. } = parse("CrEaTe UsEr root sUpErUsEr") else {
            panic!("expected CreateUser");
        };
        assert!(superuser);
    }

    #[test]
    fn non_user_ddl_passes_through() {
        // Other control-plane DDL and ordinary SQL never match.
        assert!(parse_user_ddl("CREATE CATALOG c WITH (kind='postgres')").is_none());
        assert!(parse_user_ddl("CREATE SECRET s AS 'v'").is_none());
        assert!(parse_user_ddl("CREATE TABLE t (a int)").is_none());
        assert!(parse_user_ddl("SELECT 1").is_none());
        assert!(parse_user_ddl("").is_none());
        // A `USER`-prefixed word that isn't the keyword.
        assert!(parse_user_ddl("CREATE USERX alice").is_none());
    }

    #[test]
    fn malformed_user_ddl_declines() {
        // Missing name.
        assert!(parse_user_ddl("CREATE USER").is_none());
        // Unterminated quoted password.
        assert!(parse_user_ddl("CREATE USER a PASSWORD 'unterminated").is_none());
        // PASSWORD keyword with no value.
        assert!(parse_user_ddl("CREATE USER a PASSWORD").is_none());
        // Trailing junk after the SUPERUSER flag.
        assert!(parse_user_ddl("CREATE USER a SUPERUSER extra").is_none());
        // Trailing junk after a DROP name.
        assert!(parse_user_ddl("DROP USER a extra").is_none());
        // Malformed IF clause.
        assert!(parse_user_ddl("CREATE USER IF EXISTS a").is_none());
        assert!(parse_user_ddl("DROP USER IF NOT EXISTS a").is_none());
        // ALTER requires a PASSWORD clause.
        assert!(parse_user_ddl("ALTER USER a SUPERUSER").is_none());
        assert!(parse_user_ddl("ALTER USER a").is_none());
        // Unknown SUPERUSER-like flag.
        assert!(parse_user_ddl("CREATE USER a MAYBESUPERUSER").is_none());
    }

    #[test]
    fn debug_redacts_password() {
        // CreateUser with a password.
        let ddl = parse("CREATE USER a WITH PASSWORD 'super-secret'");
        let shown = format!("{ddl:?}");
        assert!(shown.contains("<redacted>"), "{shown}");
        assert!(
            !shown.contains("super-secret"),
            "Debug must not leak the password: {shown}"
        );

        // AlterUserPassword.
        let ddl = parse("ALTER USER a PASSWORD 'another-secret'");
        let shown = format!("{ddl:?}");
        assert!(shown.contains("<redacted>"), "{shown}");
        assert!(
            !shown.contains("another-secret"),
            "Debug must not leak the password: {shown}"
        );

        // No password ⇒ shows None, no redaction marker needed.
        let ddl = parse("CREATE USER a");
        let shown = format!("{ddl:?}");
        assert!(shown.contains("None"), "{shown}");
    }
}

//! `SHOW <variable>` compatibility shims, covering two cases:
//! `datafusion-postgres`'s `set_show` hook doesn't handle `server_version_num`,
//! `ssl`, or `is_superuser` at all (they fall through to DataFusion and error /
//! return nothing); and it reports `SHOW server_version` as an unparseable
//! `"datafusion … on …"` string that disagrees with the PG-compatible startup
//! `server_version` `ParameterStatus` (the pgwire crate's `16.6-…`). Some drivers
//! and BI tools trip on both.
//!
//! Same mechanism as [`crate::show_schemas`]: rewrite the statement into a
//! plain `SELECT '<value>' AS <name>` before it reaches DataFusion, on the
//! simple-query path. `SHOW` is issued over the simple protocol by psql/JDBC,
//! so (like `SHOW SCHEMAS`) this doesn't need an extended-protocol hook.
//!
//! These are session-level *reads* only — Dataglot doesn't model these as
//! writable GUCs. The values mirror what the rest of the stack reports:
//! `is_superuser` reflects the session's admin capability (`can_admin`) so it
//! agrees with the control-plane DDL gate rather than always
//! reporting `on`, and `server_version_num` advertises a modern PostgreSQL
//! major so version-gating clients enable their PG-16 code paths. `ssl = off`
//! is the plaintext default; reflecting real per-connection TLS state is a
//! follow-up.

/// PostgreSQL version advertised to version-gating clients, kept consistent
/// with the startup `server_version` `ParameterStatus` (the pgwire crate sends
/// `16.6-pgwire-<ver>` by default). Reporting the same PG major.minor for the
/// `SHOW` path means a client sees one coherent version whether it reads the
/// startup value or runs `SHOW server_version`. `SELECT version()` still
/// returns the real DataFusion engine version.
const SERVER_VERSION: &str = "16.6 (Dataglot)";
/// `server_version` as the integer drivers compare against (`16.6` → `160006`).
const SERVER_VERSION_NUM: &str = "160006";

/// Rewrite `SHOW <var>` into `SELECT '<value>' AS <var>` for the GUCs
/// `datafusion-postgres` leaves unhandled. Returns `Some(rewritten)` on a
/// match; `None` otherwise (the caller passes the query through unchanged).
///
/// Match rules: leading/trailing whitespace and a single trailing `;` are
/// tolerated; `SHOW` is case-insensitive and must be followed by whitespace;
/// the variable must be a single bare identifier (no extra tokens).
#[must_use]
pub fn rewrite_show_variable(query: &str) -> Option<String> {
    let mut s = query.trim();
    if let Some(stripped) = s.strip_suffix(';') {
        s = stripped.trim_end();
    }

    // `SHOW` (case-insensitive) followed by whitespace. `get`/`as_bytes().get`
    // keep this panic-free on non-ASCII input.
    if !s
        .get(..4)
        .is_some_and(|head| head.eq_ignore_ascii_case("show"))
    {
        return None;
    }
    if !s.as_bytes().get(4).is_some_and(u8::is_ascii_whitespace) {
        return None;
    }

    let var = s[4..].trim();
    // A single bare identifier only — decline `SHOW a b`, `SHOW "x"`, etc.
    if var.is_empty()
        || var
            .chars()
            .any(|c| c.is_whitespace() || c == '"' || c == ';')
    {
        return None;
    }

    let (name, value) = match var.to_ascii_lowercase().as_str() {
        // Override datafusion-postgres's `SHOW server_version` (it reports
        // "datafusion … on datafusion-postgres …", unparseable as a PG
        // version) so the SHOW path agrees with the PG-compatible startup
        // ParameterStatus. `SELECT version()` still exposes the real engine.
        "server_version" => ("server_version", SERVER_VERSION),
        "server_version_num" => ("server_version_num", SERVER_VERSION_NUM),
        "ssl" => ("ssl", "off"),
        // Dynamic: report the session's actual admin capability
        // rather than a hardcoded "on", so a non-admin session can't appear
        // privileged. `can_admin` is the operative admin flag (trust mode /
        // config identity / store superuser) — the same one the control-plane
        // DDL gate enforces, so `SHOW is_superuser` agrees with what DDL the
        // session may actually run. No principal bound (pgwire-library /
        // unit-test context) → "on", matching that gate's lenient default.
        "is_superuser" => (
            "is_superuser",
            if crate::current_auth_principal().is_none_or(|p| p.can_admin) {
                "on"
            } else {
                "off"
            },
        ),
        _ => return None,
    };
    Some(format!("SELECT '{value}' AS {name}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewrites_known_variables() {
        assert_eq!(
            rewrite_show_variable("SHOW server_version"),
            Some("SELECT '16.6 (Dataglot)' AS server_version".to_string())
        );
        assert_eq!(
            rewrite_show_variable("SHOW server_version_num"),
            Some("SELECT '160006' AS server_version_num".to_string())
        );
        assert_eq!(
            rewrite_show_variable("show ssl"),
            Some("SELECT 'off' AS ssl".to_string())
        );
        // No principal bound (this context) → the lenient default, "on".
        assert_eq!(
            rewrite_show_variable("SHOW is_superuser"),
            Some("SELECT 'on' AS is_superuser".to_string())
        );
    }

    #[tokio::test]
    async fn is_superuser_reflects_admin_capability() {
        use crate::auth_principal::{with_auth_principal, AuthPrincipal};

        // A non-admin session reports `off` — it must not look
        // privileged when it can't actually run control-plane DDL.
        let off = with_auth_principal(
            AuthPrincipal {
                can_admin: false,
                ..Default::default()
            },
            async { rewrite_show_variable("SHOW is_superuser") },
        )
        .await;
        assert_eq!(off.as_deref(), Some("SELECT 'off' AS is_superuser"));

        // An admin session (trust / config identity / store superuser) → `on`.
        let on = with_auth_principal(
            AuthPrincipal {
                can_admin: true,
                ..Default::default()
            },
            async { rewrite_show_variable("SHOW is_superuser") },
        )
        .await;
        assert_eq!(on.as_deref(), Some("SELECT 'on' AS is_superuser"));
    }

    #[test]
    fn tolerates_whitespace_case_and_semicolon() {
        assert_eq!(
            rewrite_show_variable("  ShOw   Server_Version_Num ;  "),
            Some("SELECT '160006' AS server_version_num".to_string())
        );
    }

    #[test]
    fn declines_unknown_and_malformed() {
        // Unknown variable — leave for datafusion-postgres / DataFusion.
        assert_eq!(rewrite_show_variable("SHOW search_path"), None);
        // Not a bare SHOW <ident>.
        assert_eq!(
            rewrite_show_variable("SHOW transaction isolation level"),
            None
        );
        assert_eq!(rewrite_show_variable("SELECT 1"), None);
        assert_eq!(rewrite_show_variable("SHOWserver_version_num"), None);
        assert_eq!(rewrite_show_variable("SHOW"), None);
        // A qualified/quoted name isn't our simple-identifier case.
        assert_eq!(rewrite_show_variable("SHOW \"ssl\""), None);
    }
}

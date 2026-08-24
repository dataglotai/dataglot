//! Connection authentication for the pgwire startup path.
//!
//! Phase 3 closes the security-audit gap that the engine *authorizes*
//! (policy enforcement keyed on [`StartupInfo::user`](crate::StartupInfo))
//! but never *authenticated* — the prior
//! [`NoopStartupHandler`](pgwire::api::auth::noop::NoopStartupHandler)
//! trusted whatever username a client asserted. This module adds password
//! authentication while preserving the trust mode as the dev default.
//!
//! # Model (mirrors `RisingWave`)
//!
//! `RisingWave` keeps a per-user auth record + a method (trust / md5 /
//! oauth / ldap) and builds an authenticator per connection. We adopt
//! the same shape but lean on the `pgwire` crate's built-in handlers
//! instead of hand-rolling the wire exchange:
//!
//! - [`AuthMode::Trust`] — no password check (dev default, identical to
//!   the prior behavior).
//! - [`AuthMode::Md5`] — Postgres MD5 password auth, validated against a
//!   [`PasswordSource`] the server builds from config.
//! - [`AuthMode::ScramSha256`] — Postgres SCRAM-SHA-256 (SASL) auth, a
//!   salted challenge–response that never puts a replayable
//!   password-equivalent on the wire. Backed by the *same*
//!   [`PasswordSource`] the md5 path uses (F7).
//!
//! The credential lookup ([`PasswordSource`]) is a trait so the server
//! crate owns *where* passwords come from (config + env indirection,
//! CLAUDE.md rule 12) without `dataglot-pgwire` taking a dependency on
//! `dataglot-server` (rule 4).
//!
//! The authenticated username flows into the exact same
//! [`StartupObserver`](crate::StartupObserver) seam the trust path uses,
//! so identity → policy resolution is unchanged downstream.

use std::fmt::Debug;
use std::sync::Arc;

use async_trait::async_trait;
use pgwire::api::auth::md5pass::hash_md5_password;
use pgwire::api::auth::sasl::scram;
use pgwire::api::auth::{AuthSource, LoginInfo, Password};
use pgwire::error::PgWireResult;

/// Source of cleartext passwords for authentication, keyed by username.
///
/// Implementors live in `dataglot-server` (config + environment
/// indirection). Returning `None` means "unknown user" — the auth
/// handler still runs the password exchange against a non-matching
/// hash so timing/responses don't trivially distinguish unknown users
/// from wrong passwords.
///
/// # Credential isolation (CLAUDE.md rule 12)
///
/// Implementations **must not** leak the cleartext password through
/// their [`Debug`] impl — redact it. The bound exists because
/// [`AuthSource`] requires `Debug`, not because the secret should be
/// printable.
#[async_trait]
pub trait PasswordSource: Debug + Send + Sync + 'static {
    /// Cleartext password for `user`, or `None` when `user` is unknown.
    ///
    /// Async (CLAUDE.md rule 10): the in-memory config source resolves
    /// synchronously, but the seam exists so a future directory backend
    /// (`LDAP` / `IdP`) can do IO here without a breaking change.
    async fn password(&self, user: &str) -> Option<String>;
}

/// How the pgwire startup path authenticates each connection.
///
/// Cheap to clone — [`AuthMode::Md5`] holds an `Arc`. The server holds
/// one value and clones it into every connection.
#[derive(Clone, Default)]
pub enum AuthMode {
    /// No password check; the asserted username is trusted. Dev default,
    /// preserves pre-Phase-3 behavior.
    #[default]
    Trust,
    /// Postgres MD5 password authentication backed by a [`PasswordSource`].
    Md5(Arc<dyn PasswordSource>),
    /// Postgres SCRAM-SHA-256 (SASL) authentication backed by a
    /// [`PasswordSource`]. The same cleartext-returning source as
    /// [`AuthMode::Md5`]; the wire exchange is a salted challenge–response
    /// (RFC 5802) that never transmits a replayable password-equivalent (F7).
    ScramSha256(Arc<dyn PasswordSource>),
    /// JWT authentication: the client presents a **signed JWT as
    /// its password**. The wire exchange is a Postgres cleartext-password
    /// request; the token is then verified by the [`crate::jwt::JwtVerifier`]
    /// (signature + `exp`/`nbf` + `iss`/`aud`) before the connection is
    /// allowed, and its `groups` claim populates the session identity. Any
    /// verification failure rejects the connection (fail-closed).
    Jwt(Arc<crate::jwt::JwtVerifier>),
    /// LDAP / Active Directory authentication: the connection is
    /// authenticated by **binding** to the directory as the user with the
    /// presented password; a failed bind rejects the connection
    /// (fail-closed). A successful bind then triggers a group search whose
    /// results populate the session identity.
    Ldap(Arc<crate::ldap::LdapAuthenticator>),
}

impl Debug for AuthMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render the inner PasswordSource / verifier / directory
        // credentials (rule 12 belt-and-braces).
        match self {
            Self::Trust => f.write_str("Trust"),
            Self::Md5(_) => f.write_str("Md5(..)"),
            Self::ScramSha256(_) => f.write_str("ScramSha256(..)"),
            Self::Jwt(_) => f.write_str("Jwt(..)"),
            Self::Ldap(_) => f.write_str("Ldap(..)"),
        }
    }
}

/// [`AuthSource`] adapter bridging a [`PasswordSource`] into the
/// `pgwire` crate's [`Md5PasswordAuthStartupHandler`].
///
/// For MD5 the handler expects the `AuthSource` to return the *expected*
/// `md5(...)` response string plus the challenge salt; it then compares
/// that to what the client sends. We mint a fresh random 4-byte salt per
/// challenge and pre-compute the expected hash from the cleartext
/// password the [`PasswordSource`] provides.
///
/// [`Md5PasswordAuthStartupHandler`]: pgwire::api::auth::md5pass::Md5PasswordAuthStartupHandler
pub(crate) struct DataglotAuthSource {
    source: Arc<dyn PasswordSource>,
}

impl Debug for DataglotAuthSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render the inner PasswordSource (rule 12 belt-and-braces) —
        // `AuthSource` only requires that `Self: Debug`, not that the
        // credential source be printable.
        f.debug_struct("DataglotAuthSource").finish_non_exhaustive()
    }
}

impl DataglotAuthSource {
    pub(crate) fn new(source: Arc<dyn PasswordSource>) -> Self {
        Self { source }
    }
}

#[async_trait]
impl AuthSource for DataglotAuthSource {
    async fn get_password(&self, login: &LoginInfo) -> PgWireResult<Password> {
        let user = login.user().unwrap_or_default();
        // Unknown users hash an empty password — the exchange still runs
        // and fails to match a real attempt, avoiding a cheap user-probe.
        let cleartext = self.source.password(user).await.unwrap_or_default();
        let salt: [u8; 4] = rand::random();
        let hashed = hash_md5_password(user, &cleartext, &salt);
        Ok(Password::new(Some(salt.to_vec()), hashed.into_bytes()))
    }
}

/// [`AuthSource`] adapter bridging a [`PasswordSource`] into the
/// `pgwire` crate's SCRAM-SHA-256 SASL handler (F7).
///
/// SCRAM verifies the client without the server ever seeing the
/// cleartext on the wire: the handler builds its challenge from the
/// `salt` + *salted* password this source returns, and checks the
/// client's proof against it. So [`get_password`](AuthSource::get_password)
/// fetches the cleartext from the [`PasswordSource`], mints a fresh
/// random per-connection salt, and returns
/// `gen_salted_password(cleartext, salt, SCRAM_ITERATIONS)`.
///
/// The iteration count baked in here **must** equal the one the SASL
/// handler advertises to the client — both use [`scram::SCRAM_ITERATIONS`],
/// wired together in `handler.rs`.
///
/// Fail-closed, no user-probe: an unknown user (or one with no password)
/// yields the salted *empty* password, exactly as the md5 source hashes
/// the empty password — the exchange still runs and the client's proof
/// cannot match, and nothing distinguishes "no such user" from "wrong
/// password" (rule 12; no reason is logged).
pub(crate) struct ScramAuthSource {
    source: Arc<dyn PasswordSource>,
}

impl Debug for ScramAuthSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render the inner PasswordSource (rule 12 belt-and-braces).
        f.debug_struct("ScramAuthSource").finish_non_exhaustive()
    }
}

impl ScramAuthSource {
    pub(crate) fn new(source: Arc<dyn PasswordSource>) -> Self {
        Self { source }
    }
}

#[async_trait]
impl AuthSource for ScramAuthSource {
    async fn get_password(&self, login: &LoginInfo) -> PgWireResult<Password> {
        let user = login.user().unwrap_or_default();
        // Unknown users salt an empty password — the SCRAM exchange still
        // runs and the client's proof fails to match, avoiding a cheap
        // user-probe (same fail-closed posture as the md5 source).
        let cleartext = self.source.password(user).await.unwrap_or_default();
        // Fresh per-connection random salt. `rand` is already a direct
        // dependency of this crate (used by the md5 source above); no new
        // Cargo dependency is introduced for F7.
        let salt: [u8; 16] = rand::random();
        let salted = scram::gen_salted_password(&cleartext, &salt, scram::SCRAM_ITERATIONS);
        Ok(Password::new(Some(salt.to_vec()), salted))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct MapSource(std::collections::HashMap<String, String>);
    #[async_trait]
    impl PasswordSource for MapSource {
        async fn password(&self, user: &str) -> Option<String> {
            self.0.get(user).cloned()
        }
    }

    #[tokio::test]
    async fn md5_source_hashes_known_user_with_salt() {
        let mut m = std::collections::HashMap::new();
        m.insert("alice".to_string(), "s3cret".to_string());
        let src = DataglotAuthSource::new(Arc::new(MapSource(m)));

        let login = LoginInfo::new(Some("alice"), None, "127.0.0.1".to_string());
        let pw = src.get_password(&login).await.unwrap();

        let salt = pw.salt().expect("md5 requires a salt");
        assert_eq!(salt.len(), 4, "postgres md5 salt is 4 bytes");
        // The stored hash must equal the canonical md5 of the same inputs.
        let expected = hash_md5_password("alice", "s3cret", salt);
        assert_eq!(pw.password(), expected.as_bytes());
    }

    #[tokio::test]
    async fn unknown_user_still_returns_a_password() {
        let src = DataglotAuthSource::new(Arc::new(MapSource(std::collections::HashMap::new())));
        let login = LoginInfo::new(Some("ghost"), None, "127.0.0.1".to_string());
        let pw = src.get_password(&login).await.unwrap();
        // Hashes the empty password — won't match any real attempt.
        let salt = pw.salt().unwrap();
        assert_eq!(
            pw.password(),
            hash_md5_password("ghost", "", salt).as_bytes()
        );
    }

    #[test]
    fn authmode_debug_redacts_source() {
        let src: Arc<dyn PasswordSource> = Arc::new(MapSource(std::collections::HashMap::new()));
        assert_eq!(format!("{:?}", AuthMode::Md5(Arc::clone(&src))), "Md5(..)");
        assert_eq!(
            format!("{:?}", AuthMode::ScramSha256(src)),
            "ScramSha256(..)"
        );
        assert_eq!(format!("{:?}", AuthMode::Trust), "Trust");
    }

    #[test]
    fn authmode_debug_redacts_jwt_and_ldap() {
        use crate::jwt::{JwtAlgorithm, JwtVerifier};
        use crate::ldap::{Ldap3Connection, LdapAuthenticator, LdapConfig};

        let verifier =
            JwtVerifier::new(JwtAlgorithm::Hs256, b"secret", "groups", None, None, 60).unwrap();
        assert_eq!(
            format!("{:?}", AuthMode::Jwt(Arc::new(verifier))),
            "Jwt(..)"
        );

        let ldap = LdapAuthenticator::new(
            LdapConfig {
                url: "ldap://d".into(),
                bind_dn_template: "uid={user}".into(),
                group_search_base: "ou=g".into(),
                group_filter_template: "(member={userdn})".into(),
                group_name_attr: "cn".into(),
            },
            Arc::new(Ldap3Connection::new("ldap://d")),
        );
        assert_eq!(format!("{:?}", AuthMode::Ldap(Arc::new(ldap))), "Ldap(..)");
    }

    #[tokio::test]
    async fn scram_source_salts_known_user_with_matching_iterations() {
        let mut m = std::collections::HashMap::new();
        m.insert("alice".to_string(), "s3cret".to_string());
        let src = ScramAuthSource::new(Arc::new(MapSource(m)));

        let login = LoginInfo::new(Some("alice"), None, "127.0.0.1".to_string());
        let pw = src.get_password(&login).await.unwrap();

        // SCRAM requires the server to return the salt it derived the
        // salted password with, so the handler can echo it in server-first.
        let salt = pw.salt().expect("scram requires a salt");
        assert!(!salt.is_empty(), "salt must be non-empty");
        // The stored bytes must equal the canonical salted password for the
        // same cleartext + salt + the SAME iteration count the handler uses.
        let expected = scram::gen_salted_password("s3cret", salt, scram::SCRAM_ITERATIONS);
        assert_eq!(pw.password(), expected.as_slice());
    }

    #[tokio::test]
    async fn scram_source_unknown_user_fails_closed() {
        let src = ScramAuthSource::new(Arc::new(MapSource(std::collections::HashMap::new())));
        let login = LoginInfo::new(Some("ghost"), None, "127.0.0.1".to_string());
        let pw = src.get_password(&login).await.unwrap();
        // Salts the empty password — the client's proof can never match, and
        // this is indistinguishable from a wrong-password attempt.
        let salt = pw.salt().expect("scram requires a salt");
        let expected = scram::gen_salted_password("", salt, scram::SCRAM_ITERATIONS);
        assert_eq!(pw.password(), expected.as_slice());
    }

    #[test]
    fn scram_source_debug_is_value_free() {
        let mut m = std::collections::HashMap::new();
        m.insert("alice".to_string(), "s3cret".to_string());
        let src = ScramAuthSource::new(Arc::new(MapSource(m)));
        let shown = format!("{src:?}");
        assert!(shown.contains("ScramAuthSource"));
        assert!(!shown.contains("alice"), "must not render usernames");
        assert!(!shown.contains("s3cret"), "must not render secrets");
    }
}

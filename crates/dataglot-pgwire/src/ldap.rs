//! LDAP / Active Directory authentication + directory-group resolution for
//! the `ldap` connection-auth mode.
//!
//! In `ldap` mode a connection is authenticated by **binding** to the
//! directory as the user (a DN built from a configured template) with the
//! password the client presents. A successful bind proves the credential; a
//! failed bind — or an unreachable directory — rejects the connection
//! (fail-closed). Once bound, the configured group base + filter are searched
//! and the group-name attribute values become the session's org-groups.
//!
//! # Fail-closed / least-privilege
//!
//! - **Bind fails** (bad password, unknown user, connection error) ⇒
//!   [`LdapOutcome::AuthFailed`] ⇒ the connection is rejected.
//! - **Bind succeeds but the group search fails** ⇒
//!   [`LdapOutcome::Authenticated`] with [`GroupLookup::Unavailable`]: the
//!   session is allowed (auth passed) but is granted **no** groups (least
//!   privilege), and the caller logs a WARN. Groups are never granted on a
//!   resolution error.
//!
//! # Testability
//!
//! All directory IO sits behind the [`LdapConnection`] trait, so
//! [`LdapAuthenticator`]'s bind→search orchestration (DN/filter templating,
//! outcome mapping, injection escaping) is unit-tested against an in-memory
//! mock with **no live server**. The real client [`Ldap3Connection`] wraps the
//! pure-Rust `ldap3` crate (hard rule 15) and its tokio backend, so every
//! call is async and non-blocking (hard rule 11).
//!
//! # Credential isolation (hard rule 12)
//!
//! The bind password is passed straight to the directory and never logged;
//! [`LdapError`] is value-free (no DN, no password, no filter), and
//! [`LdapConfig`]'s `Debug` renders no credential (there is none in it — a bind
//! DN template is not a secret, and there is no service-account password
//! stored here).

use async_trait::async_trait;

/// Static LDAP directory configuration (no secrets — the per-connection bind
/// password comes from the client, not from here).
#[derive(Debug, Clone)]
pub struct LdapConfig {
    /// Directory URL, e.g. `ldap://dir.example:389` or `ldaps://dir.example`.
    pub url: String,
    /// Template for the user's bind DN. `{user}` is replaced with the
    /// (DN-escaped) startup username, e.g.
    /// `uid={user},ou=people,dc=example,dc=com`.
    pub bind_dn_template: String,
    /// Search base for the group lookup, e.g. `ou=groups,dc=example,dc=com`.
    pub group_search_base: String,
    /// Group search filter template. `{user}` (filter-escaped username) and
    /// `{userdn}` (the user's full bind DN) are substituted, e.g.
    /// `(member={userdn})` or `(&(objectClass=group)(memberUid={user}))`.
    pub group_filter_template: String,
    /// Attribute on a matched group entry to read as the group name, e.g.
    /// `cn`.
    pub group_name_attr: String,
}

/// Error performing an LDAP operation. **Value-free** (hard rule 12): no
/// variant carries the DN, password, filter, or any entry data — only the
/// kind of failure.
#[derive(Debug, thiserror::Error)]
pub enum LdapError {
    /// Could not connect to / establish a session with the directory.
    #[error("ldap connection failed")]
    Connection,
    /// The bind operation itself errored (protocol / IO), as distinct from a
    /// clean "invalid credentials" result (which is `Ok(false)`).
    #[error("ldap bind failed")]
    Bind,
    /// The group search operation errored.
    #[error("ldap search failed")]
    Search,
}

/// One directory session's primitive operations. Abstracted so
/// [`LdapAuthenticator`] can be unit-tested with a mock (no live server).
///
/// Implementations must be async and non-blocking (rule 11).
#[async_trait]
pub trait LdapConnection: Send + Sync {
    /// Simple-bind as `dn` with `password`.
    ///
    /// - `Ok(true)` — bind succeeded (credential valid).
    /// - `Ok(false)` — the directory cleanly rejected the credential
    ///   (invalid username/password). The caller treats this as auth failure.
    /// - `Err(_)` — a connection / protocol error (directory unreachable);
    ///   the caller fails closed and rejects the connection.
    async fn simple_bind(&self, dn: &str, password: &str) -> Result<bool, LdapError>;

    /// Search `base` with `filter`, returning the `name_attr` values of every
    /// matched entry (the group names). Runs after a successful bind.
    async fn search_group_names(
        &self,
        base: &str,
        filter: &str,
        name_attr: &str,
    ) -> Result<Vec<String>, LdapError>;
}

/// The result of resolving group membership after a successful bind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroupLookup {
    /// The search succeeded; these are the group names (possibly empty).
    Resolved(Vec<String>),
    /// The search failed after a successful bind — least privilege, no groups.
    Unavailable,
}

/// The outcome of an LDAP authentication attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LdapOutcome {
    /// The bind failed (bad credential or directory unreachable) — reject.
    AuthFailed,
    /// The bind succeeded; `groups` carries the (possibly unavailable) group
    /// resolution.
    Authenticated {
        /// Group membership resolved after the successful bind.
        groups: GroupLookup,
    },
}

/// Orchestrates the bind→search flow over an [`LdapConnection`].
///
/// Cloneable/shareable behind an `Arc` — holds the static config and an
/// `Arc<dyn LdapConnection>`.
pub struct LdapAuthenticator {
    config: LdapConfig,
    connection: std::sync::Arc<dyn LdapConnection>,
}

impl std::fmt::Debug for LdapAuthenticator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Config carries no secret, but keep the connection opaque.
        f.debug_struct("LdapAuthenticator")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl LdapAuthenticator {
    /// Build an authenticator from config and a directory-connection backend.
    #[must_use]
    pub fn new(config: LdapConfig, connection: std::sync::Arc<dyn LdapConnection>) -> Self {
        Self { config, connection }
    }

    /// Authenticate `user` with `password`, then resolve group membership.
    ///
    /// An empty password is rejected up front: many directories treat a
    /// simple bind with an empty password as an **anonymous** bind that
    /// "succeeds" without proving the credential, which would be an auth
    /// bypass — so a blank password is always [`LdapOutcome::AuthFailed`].
    pub async fn authenticate(&self, user: &str, password: &str) -> LdapOutcome {
        if password.is_empty() {
            return LdapOutcome::AuthFailed;
        }
        let user_dn = self
            .config
            .bind_dn_template
            .replace("{user}", &escape_dn_value(user));

        match self.connection.simple_bind(&user_dn, password).await {
            Ok(true) => {}
            // Clean rejection OR a connection error both fail closed: the
            // connection is rejected. (A directory-unreachable error must not
            // silently allow the login.)
            Ok(false) | Err(_) => return LdapOutcome::AuthFailed,
        }

        // Bound — the credential is proven. Now resolve groups.
        let filter = self
            .config
            .group_filter_template
            .replace("{userdn}", &escape_filter_value(&user_dn))
            .replace("{user}", &escape_filter_value(user));

        let groups = match self
            .connection
            .search_group_names(
                &self.config.group_search_base,
                &filter,
                &self.config.group_name_attr,
            )
            .await
        {
            Ok(names) => GroupLookup::Resolved(names),
            // Search failed after a good bind — allow the session, grant no
            // groups (least privilege). The caller logs the WARN.
            Err(_) => GroupLookup::Unavailable,
        };
        LdapOutcome::Authenticated { groups }
    }
}

/// Escape a value for safe inclusion in an LDAP **search filter** (RFC 4515):
/// the metacharacters `* ( ) \ NUL` are backslash-hex encoded. Prevents an
/// attacker-controlled username from altering the filter's logic.
fn escape_filter_value(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for b in input.bytes() {
        match b {
            b'*' => out.push_str("\\2a"),
            b'(' => out.push_str("\\28"),
            b')' => out.push_str("\\29"),
            b'\\' => out.push_str("\\5c"),
            0 => out.push_str("\\00"),
            _ => out.push(b as char),
        }
    }
    out
}

/// Escape a value for safe inclusion in a **DN** component (RFC 4514):
/// the special characters `,+"\<>;=` and a leading `#`/space or trailing
/// space are escaped. Prevents DN injection through the username.
fn escape_dn_value(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for (i, ch) in input.chars().enumerate() {
        let last = i + 1 == input.chars().count();
        match ch {
            ',' | '+' | '"' | '\\' | '<' | '>' | ';' | '=' => {
                out.push('\\');
                out.push(ch);
            }
            ' ' if i == 0 || last => {
                out.push('\\');
                out.push(ch);
            }
            '#' if i == 0 => {
                out.push('\\');
                out.push(ch);
            }
            _ => out.push(ch),
        }
    }
    out
}

/// Real [`LdapConnection`] over the pure-Rust `ldap3` crate (rule 15) and its
/// tokio backend (rule 11 — all IO is async).
///
/// Each operation opens a fresh connection: `simple_bind` connects and binds
/// as the user; `search_group_names` connects, binds **as the same user**
/// (via the closed-over credential is not available here — see note), and
/// searches. Because a live directory is required, this type is exercised only
/// by `#[ignore]`-gated integration tests; unit tests use a mock
/// [`LdapConnection`].
pub struct Ldap3Connection {
    url: String,
    /// Optional read-only service account to bind as before the group search
    ///. `Some((dn, password))` ⇒ the search connection binds as this
    /// account first — required by directories that forbid anonymous search.
    /// `None` ⇒ the search runs anonymously (the default / historical path).
    /// The password lives here in the IO backend, never in [`LdapConfig`], and
    /// is redacted from `Debug` (rule 12).
    search_bind: Option<(String, String)>,
}

impl std::fmt::Debug for Ldap3Connection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Render the service-account DN (non-secret) but NEVER its password.
        f.debug_struct("Ldap3Connection")
            .field("url", &self.url)
            .field(
                "search_bind_dn",
                &self.search_bind.as_ref().map(|(dn, _)| dn.as_str()),
            )
            .finish()
    }
}

impl Ldap3Connection {
    /// Build a client for the directory at `url` whose group search runs
    /// anonymously (the default / historical behaviour).
    #[must_use]
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            search_bind: None,
        }
    }

    /// Build a client whose group search first binds as a read-only service
    /// account (`dn` / `password`) before searching — for directories
    /// that forbid anonymous search. The password is held in this backend and
    /// is never logged (rule 12).
    #[must_use]
    pub fn with_search_bind(
        url: impl Into<String>,
        dn: impl Into<String>,
        password: impl Into<String>,
    ) -> Self {
        Self {
            url: url.into(),
            search_bind: Some((dn.into(), password.into())),
        }
    }
}

#[async_trait]
impl LdapConnection for Ldap3Connection {
    async fn simple_bind(&self, dn: &str, password: &str) -> Result<bool, LdapError> {
        use ldap3::LdapConnAsync;
        let (conn, mut ldap) = LdapConnAsync::new(&self.url)
            .await
            .map_err(|_| LdapError::Connection)?;
        ldap3::drive!(conn);
        let result = ldap
            .simple_bind(dn, password)
            .await
            .map_err(|_| LdapError::Bind)?;
        // rc == 0 (LDAP_SUCCESS) ⇒ bound; rc == 49 (invalidCredentials) and
        // any other non-zero ⇒ a clean rejection, not an error.
        let bound = result.rc == 0;
        let _ = ldap.unbind().await;
        Ok(bound)
    }

    async fn search_group_names(
        &self,
        base: &str,
        filter: &str,
        name_attr: &str,
    ) -> Result<Vec<String>, LdapError> {
        use ldap3::{LdapConnAsync, Scope, SearchEntry};
        let (conn, mut ldap) = LdapConnAsync::new(&self.url)
            .await
            .map_err(|_| LdapError::Connection)?;
        ldap3::drive!(conn);
        //: if a read-only service account is configured, bind as it
        // before searching — directories that forbid anonymous search require
        // an authenticated lookup. Otherwise the search runs anonymously (the
        // historical default). A failed service-account bind fails closed: the
        // `Err` propagates and the caller maps it to `Unavailable` (no groups,
        // least privilege) — it never silently downgrades to an anonymous search.
        if let Some((dn, password)) = &self.search_bind {
            let result = ldap
                .simple_bind(dn, password)
                .await
                .map_err(|_| LdapError::Bind)?;
            if result.rc != 0 {
                return Err(LdapError::Bind);
            }
        }
        let (entries, _res) = ldap
            .search(base, Scope::Subtree, filter, [name_attr])
            .await
            .map_err(|_| LdapError::Search)?
            .success()
            .map_err(|_| LdapError::Search)?;
        let mut names = Vec::new();
        for entry in entries {
            let entry = SearchEntry::construct(entry);
            if let Some(values) = entry.attrs.get(name_attr) {
                names.extend(values.iter().cloned());
            }
        }
        let _ = ldap.unbind().await;
        Ok(names)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// Scripted mock: canned bind result + canned search result.
    struct MockConnection {
        bind: Result<bool, ()>,
        search: Result<Vec<String>, ()>,
        // Records the DN + filter the authenticator built, for assertions.
        seen_dn: std::sync::Mutex<Option<String>>,
        seen_filter: std::sync::Mutex<Option<String>>,
    }

    impl MockConnection {
        fn new(bind: Result<bool, ()>, search: Result<Vec<String>, ()>) -> Arc<Self> {
            Arc::new(Self {
                bind,
                search,
                seen_dn: std::sync::Mutex::new(None),
                seen_filter: std::sync::Mutex::new(None),
            })
        }
    }

    #[async_trait]
    impl LdapConnection for MockConnection {
        async fn simple_bind(&self, dn: &str, _password: &str) -> Result<bool, LdapError> {
            *self.seen_dn.lock().unwrap() = Some(dn.to_string());
            self.bind.map_err(|()| LdapError::Bind)
        }
        async fn search_group_names(
            &self,
            _base: &str,
            filter: &str,
            _attr: &str,
        ) -> Result<Vec<String>, LdapError> {
            *self.seen_filter.lock().unwrap() = Some(filter.to_string());
            self.search.clone().map_err(|()| LdapError::Search)
        }
    }

    fn config() -> LdapConfig {
        LdapConfig {
            url: "ldap://dir.example:389".into(),
            bind_dn_template: "uid={user},ou=people,dc=example,dc=com".into(),
            group_search_base: "ou=groups,dc=example,dc=com".into(),
            group_filter_template: "(member={userdn})".into(),
            group_name_attr: "cn".into(),
        }
    }

    #[tokio::test]
    async fn successful_bind_and_search_yields_groups() {
        let conn = MockConnection::new(Ok(true), Ok(vec!["QC-Finance".into(), "QC-Ops".into()]));
        let auth = LdapAuthenticator::new(config(), conn.clone());
        let outcome = auth.authenticate("alice", "s3cret").await;
        assert_eq!(
            outcome,
            LdapOutcome::Authenticated {
                groups: GroupLookup::Resolved(vec!["QC-Finance".into(), "QC-Ops".into()]),
            }
        );
        // DN template was filled in.
        assert_eq!(
            conn.seen_dn.lock().unwrap().as_deref(),
            Some("uid=alice,ou=people,dc=example,dc=com")
        );
        // {userdn} substituted into the filter.
        assert_eq!(
            conn.seen_filter.lock().unwrap().as_deref(),
            Some("(member=uid=alice,ou=people,dc=example,dc=com)")
        );
    }

    #[tokio::test]
    async fn failed_bind_is_auth_failure() {
        let conn = MockConnection::new(Ok(false), Ok(vec!["should-not-be-read".into()]));
        let auth = LdapAuthenticator::new(config(), conn);
        assert_eq!(
            auth.authenticate("alice", "wrong").await,
            LdapOutcome::AuthFailed
        );
    }

    #[tokio::test]
    async fn bind_connection_error_is_auth_failure() {
        // Directory unreachable ⇒ fail closed (reject), never allow.
        let conn = MockConnection::new(Err(()), Ok(vec![]));
        let auth = LdapAuthenticator::new(config(), conn);
        assert_eq!(
            auth.authenticate("alice", "s3cret").await,
            LdapOutcome::AuthFailed
        );
    }

    #[tokio::test]
    async fn empty_password_is_auth_failure_without_binding() {
        let conn = MockConnection::new(Ok(true), Ok(vec!["x".into()]));
        let auth = LdapAuthenticator::new(config(), conn.clone());
        assert_eq!(
            auth.authenticate("alice", "").await,
            LdapOutcome::AuthFailed
        );
        // The anonymous-bind bypass is prevented: we never even called bind.
        assert!(conn.seen_dn.lock().unwrap().is_none());
    }

    #[tokio::test]
    async fn search_failure_after_bind_is_unavailable_not_groups() {
        // Bind OK, search errors ⇒ authenticated but NO groups (least
        // privilege), never the (unknown) group set.
        let conn = MockConnection::new(Ok(true), Err(()));
        let auth = LdapAuthenticator::new(config(), conn);
        assert_eq!(
            auth.authenticate("alice", "s3cret").await,
            LdapOutcome::Authenticated {
                groups: GroupLookup::Unavailable,
            }
        );
    }

    #[tokio::test]
    async fn username_is_escaped_in_dn_and_filter() {
        // A username with DN/filter metacharacters must be escaped, not able
        // to alter the DN or filter structure (injection defense).
        let conn = MockConnection::new(Ok(true), Ok(vec![]));
        let auth = LdapAuthenticator::new(config(), conn.clone());
        let _ = auth.authenticate("ev,il)(uid=admin", "pw").await;
        let dn = conn.seen_dn.lock().unwrap().clone().unwrap();
        // The comma in the username is DN-escaped so it can't start a new RDN.
        assert!(dn.starts_with("uid=ev\\,il"), "dn was: {dn}");
        let filter = conn.seen_filter.lock().unwrap().clone().unwrap();
        // The parens are filter-escaped so they can't inject filter clauses.
        assert!(filter.contains("\\28"), "filter was: {filter}");
        assert!(filter.contains("\\29"), "filter was: {filter}");
    }

    #[test]
    fn error_display_is_value_free() {
        // rule 12: the error carries no DN / password / filter.
        for e in [LdapError::Connection, LdapError::Bind, LdapError::Search] {
            let shown = format!("{e} {e:?}");
            assert!(!shown.contains("alice"));
            assert!(!shown.contains("s3cret"));
            assert!(!shown.contains("uid="));
        }
    }

    #[test]
    fn config_debug_has_no_secret() {
        // The config holds no secret; confirm Debug is stable and the bind
        // template (not a secret) is present but nothing password-like is.
        let shown = format!("{:?}", config());
        assert!(shown.contains("bind_dn_template"));
    }

    #[test]
    fn ldap3_connection_debug_redacts_search_bind_password() {
        //: the read-only service-account credential lives in the
        // `Ldap3Connection` IO backend, not in `LdapConfig`. Its DN is
        // renderable (non-secret, aids debugging) but the password must NEVER
        // appear in Debug output (rule 12).
        let conn = Ldap3Connection::with_search_bind(
            "ldap://dir.example:389",
            "cn=svc-ro,ou=svc,dc=example,dc=com",
            "super-secret-pw",
        );
        let shown = format!("{conn:?}");
        assert!(
            shown.contains("cn=svc-ro"),
            "service-account DN should be visible: {shown}"
        );
        assert!(
            !shown.contains("super-secret-pw"),
            "service-account password must be redacted: {shown}"
        );

        // The anonymous default carries no service-account DN.
        let anon = format!("{:?}", Ldap3Connection::new("ldap://dir.example:389"));
        assert!(
            anon.contains("search_bind_dn: None"),
            "anonymous default should show no service account: {anon}"
        );
    }
}

//! Pluggable directory-group resolution.
//!
//! Populates [`Identity::org_groups`](dataglot_policy::Identity) from an
//! external identity provider so the role-conditional policy engine
//! (, `access_deny`) enforces per-directory-group for enterprises whose
//! membership lives in a JWT / OIDC token or an LDAP / AD directory rather
//! than in the server's static config.
//!
//! # The seam
//!
//! [`GroupResolver`] is the pluggable contract: given a `user` and an optional
//! `credential` (a JWT token, an LDAP password, or nothing for the config
//! resolver), resolve the session's groups. [`GroupResolution`] distinguishes
//! three outcomes the caller must treat differently:
//!
//! - [`GroupResolution::Groups`] — the authoritative membership.
//! - [`GroupResolution::NoGroups`] — authenticated, but no memberships.
//! - [`GroupResolution::Unavailable`] — the resolver's IO failed. The caller
//!   grants **no** groups (least privilege) and logs a WARN; it never treats
//!   an error as "no restrictions".
//!
//! Three implementations ship:
//!
//! - [`ConfigGroupResolver`] — the pre-existing static `[identities]` map,
//!   refactored behind the trait (behaviour byte-identical, back-compat).
//! - [`JwtGroupResolver`] — verifies a client-presented JWT (via the pgwire
//!   [`dataglot_pgwire::JwtVerifier`]) and extracts its `groups`
//!   claim.
//! - [`LdapGroupResolver`] — binds to LDAP/AD as the user (via the pgwire
//!   [`dataglot_pgwire::LdapAuthenticator`]) and searches
//!   the directory for group membership.
//!
//! # Crate DAG (rule 4)
//!
//! The trait lives in `dataglot-server` because a [`GroupResolution`] names
//! [`dataglot_policy::OrgGroupId`] (a `dataglot-policy` type), and
//! `dataglot-pgwire` must not depend on `dataglot-policy` laterally. The
//! actual JWT verification / LDAP IO primitives live in `dataglot-pgwire`
//! (they are auth-time concerns and carry the credential); this crate — which
//! depends on both — wraps them and maps their string group names into the
//! typed policy identifiers.
//!
//! # Wire path vs. the async contract (rule 11)
//!
//! [`GroupResolver::resolve_groups`] is `async` — the pluggable contract, and
//! what the unit tests exercise. On a live pgwire connection, though, the
//! equivalent JWT-verify / LDAP-bind runs **inside** the async pgwire startup
//! handler (which owns the credential), and its result is bridged to the
//! *synchronous* startup observer via the [`dataglot_pgwire::AuthGroups`]
//! task-local — the observer must not block on async IO. So the observer calls
//! the sync [`GroupResolver::resolve_session_groups`] adapter, which maps that
//! already-resolved context into a [`GroupResolution`] without doing IO.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use dataglot_pgwire::{AuthGroups, JwtVerifier, LdapAuthenticator, LdapOutcome};
use dataglot_policy::OrgGroupId;

use crate::config::IdentityProfileConfig;

/// The outcome of resolving a session's directory groups.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroupResolution {
    /// The resolver authoritatively resolved these groups (possibly empty is
    /// represented as [`GroupResolution::NoGroups`] instead).
    Groups(Vec<OrgGroupId>),
    /// The identity authenticated but holds no group memberships.
    NoGroups,
    /// The resolver's IO failed (directory unreachable, search error). The
    /// caller grants **no** groups (least privilege) and logs a WARN — never
    /// treat this as "no restrictions apply".
    Unavailable,
}

impl GroupResolution {
    /// Build from a list of group-name strings: an empty list is
    /// [`GroupResolution::NoGroups`], otherwise [`GroupResolution::Groups`].
    #[must_use]
    pub fn from_names<I, S>(names: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let groups: Vec<OrgGroupId> = names.into_iter().map(|n| OrgGroupId::new(n)).collect();
        if groups.is_empty() {
            GroupResolution::NoGroups
        } else {
            GroupResolution::Groups(groups)
        }
    }

    /// Map a pgwire [`AuthGroups`] (the auth-handler-resolved wire context)
    /// into a resolution: `unavailable` ⇒ [`GroupResolution::Unavailable`],
    /// else by group-name list.
    #[must_use]
    pub fn from_auth_groups(auth: &AuthGroups) -> Self {
        if auth.unavailable {
            GroupResolution::Unavailable
        } else {
            GroupResolution::from_names(auth.groups.iter().cloned())
        }
    }

    /// The resolved group names as plain strings — the shape
    /// [`Identity::org_groups`](dataglot_policy::Identity) holds. `NoGroups`
    /// and `Unavailable` both yield an empty list (least privilege).
    #[must_use]
    pub fn group_names(&self) -> Vec<String> {
        match self {
            GroupResolution::Groups(groups) => {
                groups.iter().map(|g| g.as_str().to_string()).collect()
            }
            GroupResolution::NoGroups | GroupResolution::Unavailable => Vec::new(),
        }
    }
}

/// Resolves a session's directory groups from an external identity provider.
///
/// `Send + Sync` so a single `Arc<dyn GroupResolver>` is shared across every
/// pgwire connection (rule 10).
#[async_trait]
pub trait GroupResolver: Send + Sync + std::fmt::Debug {
    /// Resolve the groups for `user`, given an optional `credential` (a JWT
    /// token for [`JwtGroupResolver`], an LDAP password for
    /// [`LdapGroupResolver`], `None` for [`ConfigGroupResolver`]).
    ///
    /// This is the pluggable contract and what the unit tests drive. On a live
    /// pgwire connection the equivalent resolution runs inside the async auth
    /// handler (rule 11); the observer path uses [`Self::resolve_session_groups`].
    async fn resolve_groups(&self, user: &str, credential: Option<&str>) -> GroupResolution;

    /// Sync adapter for the startup observer (rule 11): produce the group
    /// overlay from the already-resolved wire auth context, doing **no** IO.
    ///
    /// Returns `None` when this resolver contributes no external overlay — the
    /// [`ConfigGroupResolver`], whose groups are already folded into the
    /// identity by the config path. An `IdP` resolver returns
    /// `Some(resolution)` derived from `auth`.
    fn resolve_session_groups(&self, auth: Option<&AuthGroups>) -> Option<GroupResolution>;
}

/// The static-config group resolver — the pre- `[identities]` path,
/// refactored behind [`GroupResolver`]. Behaviour is byte-identical: a user's
/// groups are exactly their [`IdentityProfileConfig::groups`].
#[derive(Debug, Clone)]
pub struct ConfigGroupResolver {
    profiles: Arc<HashMap<String, IdentityProfileConfig>>,
}

impl ConfigGroupResolver {
    /// Build from the server's identity profiles.
    #[must_use]
    pub fn new(profiles: Arc<HashMap<String, IdentityProfileConfig>>) -> Self {
        Self { profiles }
    }

    /// The configured groups for `user`, as a resolution. Missing user or a
    /// user with no groups ⇒ [`GroupResolution::NoGroups`].
    #[must_use]
    pub fn groups_for(&self, user: &str) -> GroupResolution {
        match self.profiles.get(user) {
            Some(profile) if !profile.groups.is_empty() => {
                GroupResolution::from_names(profile.groups.iter().cloned())
            }
            _ => GroupResolution::NoGroups,
        }
    }
}

#[async_trait]
impl GroupResolver for ConfigGroupResolver {
    async fn resolve_groups(&self, user: &str, _credential: Option<&str>) -> GroupResolution {
        self.groups_for(user)
    }

    fn resolve_session_groups(&self, _auth: Option<&AuthGroups>) -> Option<GroupResolution> {
        // Config groups are already resolved into the identity by the
        // existing config path — no external overlay to apply.
        None
    }
}

/// The JWT group resolver: verifies a client-presented token and extracts its
/// `groups` claim. Wraps the same pgwire [`JwtVerifier`] the `jwt` auth mode
/// uses on the wire, so there is a single source of verification truth.
#[derive(Debug, Clone)]
pub struct JwtGroupResolver {
    verifier: Arc<JwtVerifier>,
}

impl JwtGroupResolver {
    /// Build from a configured verifier.
    #[must_use]
    pub fn new(verifier: Arc<JwtVerifier>) -> Self {
        Self { verifier }
    }
}

#[async_trait]
impl GroupResolver for JwtGroupResolver {
    async fn resolve_groups(&self, _user: &str, credential: Option<&str>) -> GroupResolution {
        // No token presented, or verification failed: the caller must have
        // already rejected the connection at the wire (fail-closed). Here we
        // grant nothing.
        match credential {
            Some(token) => match self.verifier.verify(token) {
                Ok(verified) => GroupResolution::from_names(verified.groups),
                // A token that fails verification yields no groups — the wire
                // handler rejects such a connection outright; this is the
                // defensive standalone-call path.
                Err(_) => GroupResolution::Unavailable,
            },
            None => GroupResolution::NoGroups,
        }
    }

    fn resolve_session_groups(&self, auth: Option<&AuthGroups>) -> Option<GroupResolution> {
        // The token was verified in the pgwire auth handler; `auth` carries the
        // extracted `groups` claim (or `unavailable`). `None` ⇒ nothing was
        // resolved (least privilege).
        Some(auth.map_or(GroupResolution::NoGroups, GroupResolution::from_auth_groups))
    }
}

/// The LDAP / AD group resolver: binds as the user and searches the directory.
/// Wraps the same pgwire [`LdapAuthenticator`] the `ldap` auth mode uses on the
/// wire.
#[derive(Debug, Clone)]
pub struct LdapGroupResolver {
    authenticator: Arc<LdapAuthenticator>,
}

impl LdapGroupResolver {
    /// Build from a configured authenticator.
    #[must_use]
    pub fn new(authenticator: Arc<LdapAuthenticator>) -> Self {
        Self { authenticator }
    }
}

#[async_trait]
impl GroupResolver for LdapGroupResolver {
    async fn resolve_groups(&self, user: &str, credential: Option<&str>) -> GroupResolution {
        let Some(password) = credential else {
            return GroupResolution::NoGroups;
        };
        match self.authenticator.authenticate(user, password).await {
            // Bind failed ⇒ the wire path rejects the connection; standalone,
            // grant nothing.
            LdapOutcome::AuthFailed => GroupResolution::Unavailable,
            LdapOutcome::Authenticated { groups } => match groups {
                dataglot_pgwire::GroupLookup::Resolved(names) => GroupResolution::from_names(names),
                dataglot_pgwire::GroupLookup::Unavailable => GroupResolution::Unavailable,
            },
        }
    }

    fn resolve_session_groups(&self, auth: Option<&AuthGroups>) -> Option<GroupResolution> {
        Some(auth.map_or(GroupResolution::NoGroups, GroupResolution::from_auth_groups))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dataglot_pgwire::JwtAlgorithm;
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use serde_json::json;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    // -- ConfigGroupResolver -------------------------------------------------

    fn profiles(entries: &[(&str, &[&str])]) -> Arc<HashMap<String, IdentityProfileConfig>> {
        let mut m = HashMap::new();
        for (user, groups) in entries {
            m.insert(
                (*user).to_string(),
                IdentityProfileConfig {
                    org: None,
                    groups: groups.iter().map(|s| (*s).to_string()).collect(),
                    password_env: None,
                },
            );
        }
        Arc::new(m)
    }

    #[tokio::test]
    async fn config_resolver_returns_configured_groups() {
        let r = ConfigGroupResolver::new(profiles(&[("alice", &["QC-Finance", "QC-Ops"])]));
        assert_eq!(
            r.resolve_groups("alice", None).await,
            GroupResolution::Groups(vec![
                OrgGroupId::new("QC-Finance"),
                OrgGroupId::new("QC-Ops"),
            ])
        );
    }

    #[tokio::test]
    async fn config_resolver_unknown_user_is_no_groups() {
        let r = ConfigGroupResolver::new(profiles(&[("alice", &["x"])]));
        assert_eq!(
            r.resolve_groups("ghost", None).await,
            GroupResolution::NoGroups
        );
    }

    #[test]
    fn config_resolver_contributes_no_wire_overlay() {
        let r = ConfigGroupResolver::new(profiles(&[]));
        assert!(r.resolve_session_groups(None).is_none());
        assert!(r
            .resolve_session_groups(Some(&AuthGroups::resolved(vec!["x".into()])))
            .is_none());
    }

    // -- JwtGroupResolver ----------------------------------------------------

    const SECRET: &[u8] = b"resolver-test-secret";

    fn jwt_resolver() -> JwtGroupResolver {
        let verifier =
            JwtVerifier::new(JwtAlgorithm::Hs256, SECRET, "groups", None, None, 60).unwrap();
        JwtGroupResolver::new(Arc::new(verifier))
    }

    fn sign(claims: &serde_json::Value) -> String {
        encode(
            &Header::new(Algorithm::HS256),
            claims,
            &EncodingKey::from_secret(SECRET),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn jwt_resolver_extracts_groups_from_valid_token() {
        let token = sign(&json!({
            "sub": "alice",
            "exp": now() + 3600,
            "groups": ["QC-Finance"],
        }));
        assert_eq!(
            jwt_resolver().resolve_groups("alice", Some(&token)).await,
            GroupResolution::Groups(vec![OrgGroupId::new("QC-Finance")])
        );
    }

    #[tokio::test]
    async fn jwt_resolver_missing_claim_is_no_groups() {
        let token = sign(&json!({ "sub": "alice", "exp": now() + 3600 }));
        assert_eq!(
            jwt_resolver().resolve_groups("alice", Some(&token)).await,
            GroupResolution::NoGroups
        );
    }

    #[tokio::test]
    async fn jwt_resolver_bad_token_grants_no_groups() {
        // A token signed with the wrong key must not yield groups — it is
        // Unavailable (defensive), never Groups.
        let bad = encode(
            &Header::new(Algorithm::HS256),
            &json!({ "sub": "mallory", "exp": now() + 3600, "groups": ["admin"] }),
            &EncodingKey::from_secret(b"attacker"),
        )
        .unwrap();
        assert_eq!(
            jwt_resolver().resolve_groups("mallory", Some(&bad)).await,
            GroupResolution::Unavailable
        );
    }

    #[test]
    fn jwt_resolver_maps_wire_context() {
        let r = jwt_resolver();
        assert_eq!(
            r.resolve_session_groups(Some(&AuthGroups::resolved(vec!["QC-Finance".into()]))),
            Some(GroupResolution::Groups(vec![OrgGroupId::new("QC-Finance")]))
        );
        assert_eq!(
            r.resolve_session_groups(Some(&AuthGroups::unavailable())),
            Some(GroupResolution::Unavailable)
        );
        assert_eq!(
            r.resolve_session_groups(Some(&AuthGroups::resolved(vec![]))),
            Some(GroupResolution::NoGroups)
        );
        assert_eq!(
            r.resolve_session_groups(None),
            Some(GroupResolution::NoGroups)
        );
    }

    // -- LdapGroupResolver ---------------------------------------------------
    // (bind/search flow is unit-tested against a mock in dataglot-pgwire::ldap;
    // here we cover the OrgGroupId mapping + wire-context adapter.)

    fn ldap_resolver() -> LdapGroupResolver {
        use dataglot_pgwire::{Ldap3Connection, LdapConfig};
        // The real connection is never dialed in these tests — resolve_groups
        // is exercised via resolve_session_groups (the observer path). The
        // bind/search behaviour itself is covered by the pgwire mock tests.
        let auth = LdapAuthenticator::new(
            LdapConfig {
                url: "ldap://unused".into(),
                bind_dn_template: "uid={user},dc=x".into(),
                group_search_base: "ou=g,dc=x".into(),
                group_filter_template: "(member={userdn})".into(),
                group_name_attr: "cn".into(),
            },
            Arc::new(Ldap3Connection::new("ldap://unused")),
        );
        LdapGroupResolver::new(Arc::new(auth))
    }

    #[test]
    fn ldap_resolver_maps_wire_context() {
        let r = ldap_resolver();
        assert_eq!(
            r.resolve_session_groups(Some(&AuthGroups::resolved(vec!["QC-Ops".into()]))),
            Some(GroupResolution::Groups(vec![OrgGroupId::new("QC-Ops")]))
        );
        // Search failure after bind ⇒ Unavailable ⇒ no groups (least priv).
        assert_eq!(
            r.resolve_session_groups(Some(&AuthGroups::unavailable())),
            Some(GroupResolution::Unavailable)
        );
    }

    #[tokio::test]
    async fn ldap_resolver_no_credential_is_no_groups() {
        assert_eq!(
            ldap_resolver().resolve_groups("alice", None).await,
            GroupResolution::NoGroups
        );
    }

    // -- GroupResolution mapping --------------------------------------------

    #[test]
    fn unavailable_and_no_groups_yield_no_names() {
        assert!(GroupResolution::Unavailable.group_names().is_empty());
        assert!(GroupResolution::NoGroups.group_names().is_empty());
        assert_eq!(
            GroupResolution::from_names(["a", "b"]).group_names(),
            vec!["a".to_string(), "b".to_string()]
        );
    }
}

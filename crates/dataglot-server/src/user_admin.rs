//! Server-side implementation of the pgwire [`UserAdmin`] seam plus the
//! store-backed [`PasswordSource`] that closes the loop — the effecting +
//! authenticating halves of SQL-native users.
//!
//! [`dataglot_pgwire::user_ddl`] parses `CREATE / ALTER / DROP USER` and
//! `CREATE / DROP ROLE`; [`StoreUserAdmin`] here persists the change to the
//! [`MetaStore`], and [`StoreUserPasswordSource`] reads it back on the next
//! connection's md5 auth exchange — so a user created at runtime authenticates
//! with **no** config-file entry.
//!
//! # Password storage: encrypted-cleartext, not a one-way verifier
//!
//! We investigated whether pgwire's md5 machinery can be fed a pre-computed
//! Postgres `md5(password‖username)` verifier (a one-way store, no key). The
//! contract that decides this is our own [`PasswordSource`] seam plus pgwire's
//! `md5pass::hash_md5_password` helper: that helper takes
//! **cleartext** and computes `md5(pw‖user)` itself, and our existing
//! `PasswordSource::password` returns cleartext (consumed by
//! `DataglotAuthSource` via that helper). So under the established contract the
//! source must yield **cleartext** — the "no" branch of the investigation.
//!
//! Therefore we reuse the slice-D envelope [`SecretCipher`]: the password is
//! encrypted and its base64 ciphertext stored in `password_hash`; the
//! store-backed source decrypts it to cleartext for pgwire. Consequently
//! `CREATE USER … PASSWORD` / `ALTER USER … PASSWORD` **require** a
//! `DATAGLOT_SECRET_KEY` (rejected clearly without one, exactly like
//! `CREATE SECRET`). `password_hash` is opaque and never logged or listed
//! (rule 12) — [`Debug`] on every type here is value-free.

use std::sync::Arc;

use async_trait::async_trait;
use base64::Engine as _;
use dataglot_catalog::MetaStore;
use dataglot_pgwire::user_admin::{UserAdmin, UserAdminError, UserOutcome};
use dataglot_pgwire::user_ddl::UserDdl;
use dataglot_pgwire::PasswordSource;

use crate::secret_crypto::SecretCipher;

/// [`UserAdmin`] backed by the [`MetaStore`], protecting passwords with the
/// envelope [`SecretCipher`].
///
///  M2: one admin serves every org — the target org arrives per
/// [`UserAdmin::apply`] call (threaded from the connection's session identity by
/// the pgwire handler) rather than being fixed at construction.
///
/// The cipher is optional: roles and passwordless users need no key, so the
/// admin is available whenever a store is; only a statement that *sets a
/// password* requires the cipher and errors [`UserAdminError::NotConfigured`]
/// without it (mirroring `CREATE SECRET`).
#[derive(Clone)]
pub struct StoreUserAdmin {
    store: Arc<dyn MetaStore>,
    cipher: Option<Arc<SecretCipher>>,
}

impl StoreUserAdmin {
    /// Wrap a store + optional envelope cipher. The target org is supplied per
    /// [`UserAdmin::apply`] call.
    #[must_use]
    pub fn new(store: Arc<dyn MetaStore>, cipher: Option<Arc<SecretCipher>>) -> Self {
        Self { store, cipher }
    }

    /// Encrypt a password into the opaque `password_hash` string (base64 of the
    /// envelope ciphertext). Requires the cipher — `CREATE/ALTER … PASSWORD`
    /// without a `DATAGLOT_SECRET_KEY` is refused, exactly like `CREATE SECRET`.
    fn protect(&self, password: &str) -> Result<String, UserAdminError> {
        let cipher = self.cipher.as_ref().ok_or(UserAdminError::NotConfigured)?;
        let ciphertext = cipher
            .encrypt(password.as_bytes())
            // The crypto error is already value-free (rule 12).
            .map_err(|e| UserAdminError::Backend(format!("user password: {e}")))?;
        Ok(base64::engine::general_purpose::STANDARD.encode(ciphertext))
    }

    /// Effect `CREATE USER` under `org`, enforcing global-unique usernames
    ///. Extracted from [`UserAdmin::apply`] so that method stays
    /// under the line budget.
    async fn create_user(
        &self,
        org: &str,
        name: String,
        password: Option<String>,
        superuser: bool,
        if_not_exists: bool,
    ) -> Result<UserOutcome, UserAdminError> {
        if self
            .store
            .get_user(org, &name)
            .await
            .map_err(|e| backend(&e))?
            .is_some()
        {
            if if_not_exists {
                return Ok(UserOutcome::NoOp);
            }
            return Err(UserAdminError::AlreadyExists(name));
        }
        // Global-unique usernames: a name already taken in ANY
        // other org is rejected, so login can route a username to exactly one
        // org. The same-org case is handled above (an idempotent `IF NOT EXISTS`
        // NoOp or an `AlreadyExists`), so a `find_user` match here is
        // necessarily a *different* org and a genuine conflict — even under
        // `IF NOT EXISTS`, since the name is unavailable rather than "already
        // this same user". The error names only the user, never the other org,
        // so it leaks no other tenant's layout (rule 12).
        if self
            .store
            .find_user(&name)
            .await
            .map_err(|e| backend(&e))?
            .is_some()
        {
            return Err(UserAdminError::AlreadyExists(name));
        }
        // Protect the password *before* the store write so a missing key fails
        // the statement without a half-created user.
        let hash = match &password {
            Some(pw) => Some(self.protect(pw)?),
            None => None,
        };
        self.store
            .put_user(org, &name, hash.as_deref(), superuser)
            .await
            .map_err(|e| backend(&e))?;
        Ok(UserOutcome::Created { name })
    }
}

/// Map a store error into a client-safe [`UserAdminError::Backend`]. Store
/// errors are backend IO / serialization failures and never carry credentials.
fn backend(e: &dataglot_catalog::CatalogServiceError) -> UserAdminError {
    UserAdminError::Backend(format!("user store: {e}"))
}

#[async_trait]
impl UserAdmin for StoreUserAdmin {
    async fn apply(&self, org: &str, ddl: UserDdl) -> Result<UserOutcome, UserAdminError> {
        match ddl {
            UserDdl::CreateUser {
                name,
                password,
                superuser,
                if_not_exists,
            } => {
                self.create_user(org, name, password, superuser, if_not_exists)
                    .await
            }
            UserDdl::AlterUserPassword { name, password } => {
                let Some((record, _)) = self
                    .store
                    .get_user(org, &name)
                    .await
                    .map_err(|e| backend(&e))?
                else {
                    return Err(UserAdminError::NotFound(name));
                };
                let hash = self.protect(&password)?;
                // Preserve the existing superuser flag — ALTER only sets the
                // password.
                self.store
                    .put_user(org, &name, Some(&hash), record.is_superuser)
                    .await
                    .map_err(|e| backend(&e))?;
                Ok(UserOutcome::Altered { name })
            }
            UserDdl::DropUser { name, if_exists } => {
                let removed = self
                    .store
                    .delete_user(org, &name)
                    .await
                    .map_err(|e| backend(&e))?;
                if removed {
                    Ok(UserOutcome::Dropped { name })
                } else if if_exists {
                    Ok(UserOutcome::NoOp)
                } else {
                    Err(UserAdminError::NotFound(name))
                }
            }
            UserDdl::CreateRole {
                name,
                if_not_exists,
            } => {
                let exists = self
                    .store
                    .list_roles(org)
                    .await
                    .map_err(|e| backend(&e))?
                    .iter()
                    .any(|r| r == &name);
                if exists {
                    if if_not_exists {
                        return Ok(UserOutcome::NoOp);
                    }
                    return Err(UserAdminError::AlreadyExists(name));
                }
                self.store
                    .put_role(org, &name)
                    .await
                    .map_err(|e| backend(&e))?;
                Ok(UserOutcome::Created { name })
            }
            UserDdl::DropRole { name, if_exists } => {
                let removed = self
                    .store
                    .delete_role(org, &name)
                    .await
                    .map_err(|e| backend(&e))?;
                if removed {
                    Ok(UserOutcome::Dropped { name })
                } else if if_exists {
                    Ok(UserOutcome::NoOp)
                } else {
                    Err(UserAdminError::NotFound(name))
                }
            }
        }
    }
}

/// A [`PasswordSource`] that resolves md5 credentials from the control-plane
/// [`MetaStore`], decrypting the stored password with the envelope
/// [`SecretCipher`] (see the module docs for why cleartext, not a verifier).
///
/// **Freshness:** the store is read on *every* auth (no cache), so a user just
/// created via `CREATE USER` authenticates immediately on the next connection.
/// The [`PasswordSource::password`] seam is already async (designed for exactly
/// a future IO backend), so the async store read drops straight in — there is
/// no sync/async bridge to cross.
///
/// **Multi-org auth routing:** usernames are globally unique
/// across orgs (`CREATE USER` rejects a cross-org duplicate), so auth scans the
/// store for the name with [`MetaStore::find_user`] and learns the user's org —
/// no longer pinned to `"default"`. The resolved org is mirrored into the
/// pgwire-owned auth-org task-local ([`dataglot_pgwire::try_set_auth_org`]) so
/// the sync `StartupObserver` (which cannot block on async, rule 11) can scope
/// the session to that tenant without re-querying the store. The server bridges
/// the value pgwire ⇄ policy (rule 4); the org is a tenant name, not a
/// credential (rule 12).
///
/// `Debug` is value-free (rule 12): it renders neither the store contents nor
/// the cipher.
#[derive(Clone)]
pub struct StoreUserPasswordSource {
    store: Arc<dyn MetaStore>,
    cipher: Arc<SecretCipher>,
}

impl std::fmt::Debug for StoreUserPasswordSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render the store or cipher (rule 12): `PasswordSource` only
        // requires `Debug`, not that the credential source be printable.
        f.debug_struct("StoreUserPasswordSource")
            .finish_non_exhaustive()
    }
}

impl StoreUserPasswordSource {
    /// Wrap a store + envelope cipher (the cipher is required to decrypt stored
    /// passwords).
    #[must_use]
    pub fn new(store: Arc<dyn MetaStore>, cipher: Arc<SecretCipher>) -> Self {
        Self { store, cipher }
    }
}

#[async_trait]
impl PasswordSource for StoreUserPasswordSource {
    async fn password(&self, user: &str) -> Option<String> {
        // Any failure (store error, unknown user, passwordless user, bad
        // base64, wrong key, non-UTF-8) resolves to "no credential" — the auth
        // handler then hashes an empty password and the login fails, exactly as
        // for an unknown user (no probe distinction, rule 12). We deliberately
        // do not log the reason.
        //
        // Global-unique usernames: scan every org for the name;
        // the match carries the org that owns it. We mirror that org into the
        // pgwire auth-org task-local so the startup observer scopes the session
        // to the user's tenant (rule 11: this is the async auth path, no
        // blocking; rule 4: the server carries the value across to pgwire). The
        // org is a tenant name, not a credential (rule 12). `try_set_*` is a
        // no-op outside a connection scope (e.g. unit tests), so it's safe here.
        let (org, record, hash) = self.store.find_user(user).await.ok()??;

        //  F5b: resolve the principal's superuser flag (from the user
        // record) and RBAC role memberships (a second store read, in this same
        // async auth path — rule 11), and bridge both to the sync startup
        // observer via the pgwire auth-principal task-local, exactly as the org
        // is bridged above. Fail-closed: a roles read error yields no roles
        // (never a spurious grant). Role names / a superuser bool are plain
        // data, not credentials (rule 12).
        let roles = self
            .store
            .list_roles_for_user(&org, user)
            .await
            .unwrap_or_default();
        dataglot_pgwire::try_set_auth_principal(dataglot_pgwire::AuthPrincipal {
            roles,
            is_superuser: record.is_superuser,
            // A store superuser may run control-plane DDL. The startup
            // observer recomputes `can_admin` (also granting it in trust mode /
            // for config identities), so this is the store-user baseline.
            can_admin: record.is_superuser,
        });
        dataglot_pgwire::try_set_auth_org(Some(org));
        let hash = hash?;
        let ciphertext = base64::engine::general_purpose::STANDARD
            .decode(hash.as_bytes())
            .ok()?;
        let plaintext = self.cipher.decrypt(&ciphertext).ok()?;
        String::from_utf8(plaintext).ok()
    }
}

/// A [`PasswordSource`] that consults a `primary` source first and falls back to
/// a `secondary` one — the store wins, config is the pre-seed/fallback so
/// existing `identities` configs keep working.
///
/// `Debug` is value-free (rule 12).
#[derive(Clone)]
pub struct MergedPasswordSource {
    primary: Arc<dyn PasswordSource>,
    secondary: Arc<dyn PasswordSource>,
}

impl std::fmt::Debug for MergedPasswordSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MergedPasswordSource")
            .finish_non_exhaustive()
    }
}

impl MergedPasswordSource {
    /// `primary` is tried first; `secondary` only when `primary` yields nothing.
    #[must_use]
    pub fn new(primary: Arc<dyn PasswordSource>, secondary: Arc<dyn PasswordSource>) -> Self {
        Self { primary, secondary }
    }
}

#[async_trait]
impl PasswordSource for MergedPasswordSource {
    async fn password(&self, user: &str) -> Option<String> {
        if let Some(pw) = self.primary.password(user).await {
            return Some(pw);
        }
        self.secondary.password(user).await
    }
}

#[cfg(test)]
mod tests {
    use dataglot_catalog::embedded::EmbeddedMetaStore;

    use super::*;

    async fn setup() -> (Arc<dyn MetaStore>, Arc<SecretCipher>, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store: Arc<dyn MetaStore> = Arc::new(
            EmbeddedMetaStore::open(dir.path().join("m.json"), "default")
                .await
                .expect("store"),
        );
        let cipher = Arc::new(SecretCipher::from_key_bytes(&[7u8; 32]));
        (store, cipher, dir)
    }

    fn create_user(name: &str, password: Option<&str>) -> UserDdl {
        UserDdl::CreateUser {
            name: name.to_string(),
            password: password.map(str::to_string),
            superuser: false,
            if_not_exists: false,
        }
    }

    #[tokio::test]
    async fn create_persists_under_call_org_with_protected_password() {
        // Persists under the passed org (not "default"), and the stored hash is
        // NOT the plaintext (rule 12).
        let (store, cipher, _d) = setup().await;
        let admin = StoreUserAdmin::new(Arc::clone(&store), Some(Arc::clone(&cipher)));

        admin
            .apply("acme", create_user("alice", Some("sekret")))
            .await
            .expect("create");

        // Under "acme", invisible to "default".
        assert!(store.get_user("acme", "alice").await.unwrap().is_some());
        assert!(store.get_user("default", "alice").await.unwrap().is_none());

        // The stored hash is opaque (encrypted), never the plaintext.
        let (_rec, hash) = store.get_user("acme", "alice").await.unwrap().unwrap();
        let hash = hash.expect("password set");
        assert!(
            !hash.contains("sekret"),
            "stored hash must not be plaintext"
        );
        // And it decrypts back to the original.
        let ct = base64::engine::general_purpose::STANDARD
            .decode(hash.as_bytes())
            .unwrap();
        assert_eq!(cipher.decrypt(&ct).unwrap(), b"sekret");
    }

    #[tokio::test]
    async fn password_op_without_cipher_is_not_configured() {
        let (store, _cipher, _d) = setup().await;
        let admin = StoreUserAdmin::new(Arc::clone(&store), None);
        let err = admin
            .apply("default", create_user("alice", Some("sekret")))
            .await
            .expect_err("password without key must fail");
        assert!(matches!(err, UserAdminError::NotConfigured), "{err}");
        // A passwordless user, however, needs no key.
        admin
            .apply("default", create_user("svc", None))
            .await
            .expect("passwordless create ok without a key");
    }

    #[tokio::test]
    async fn create_duplicate_and_if_not_exists() {
        let (store, cipher, _d) = setup().await;
        let admin = StoreUserAdmin::new(store, Some(cipher));
        admin
            .apply("default", create_user("alice", Some("p")))
            .await
            .expect("first");
        let err = admin
            .apply("default", create_user("alice", Some("p2")))
            .await
            .expect_err("dup");
        assert!(matches!(err, UserAdminError::AlreadyExists(ref n) if n == "alice"));
        let out = admin
            .apply("default", create_user("alice", Some("p3")))
            .await;
        // IF NOT EXISTS on existing → NoOp.
        let ine = UserDdl::CreateUser {
            name: "alice".into(),
            password: Some("p3".into()),
            superuser: false,
            if_not_exists: true,
        };
        drop(out);
        assert!(matches!(
            admin.apply("default", ine).await.unwrap(),
            UserOutcome::NoOp
        ));
    }

    #[tokio::test]
    async fn alter_missing_then_alter_updates_password() {
        let (store, cipher, _d) = setup().await;
        let admin = StoreUserAdmin::new(Arc::clone(&store), Some(Arc::clone(&cipher)));
        // ALTER on a missing user → NotFound.
        let err = admin
            .apply(
                "default",
                UserDdl::AlterUserPassword {
                    name: "ghost".into(),
                    password: "x".into(),
                },
            )
            .await
            .expect_err("alter missing");
        assert!(matches!(err, UserAdminError::NotFound(ref n) if n == "ghost"));

        admin
            .apply("default", create_user("alice", Some("old")))
            .await
            .expect("create");
        admin
            .apply(
                "default",
                UserDdl::AlterUserPassword {
                    name: "alice".into(),
                    password: "new".into(),
                },
            )
            .await
            .expect("alter");
        let (_rec, hash) = store.get_user("default", "alice").await.unwrap().unwrap();
        let ct = base64::engine::general_purpose::STANDARD
            .decode(hash.unwrap().as_bytes())
            .unwrap();
        assert_eq!(cipher.decrypt(&ct).unwrap(), b"new");
    }

    #[tokio::test]
    async fn drop_user_reports_existence() {
        let (store, cipher, _d) = setup().await;
        let admin = StoreUserAdmin::new(store, Some(cipher));
        admin
            .apply("default", create_user("alice", Some("p")))
            .await
            .expect("create");
        assert!(matches!(
            admin
                .apply(
                    "default",
                    UserDdl::DropUser {
                        name: "alice".into(),
                        if_exists: false
                    }
                )
                .await
                .unwrap(),
            UserOutcome::Dropped { .. }
        ));
        // Again without IF EXISTS → NotFound; with IF EXISTS → NoOp.
        assert!(matches!(
            admin
                .apply(
                    "default",
                    UserDdl::DropUser {
                        name: "alice".into(),
                        if_exists: false
                    }
                )
                .await,
            Err(UserAdminError::NotFound(_))
        ));
        assert!(matches!(
            admin
                .apply(
                    "default",
                    UserDdl::DropUser {
                        name: "alice".into(),
                        if_exists: true
                    }
                )
                .await
                .unwrap(),
            UserOutcome::NoOp
        ));
    }

    #[tokio::test]
    async fn role_lifecycle() {
        let (store, cipher, _d) = setup().await;
        let admin = StoreUserAdmin::new(Arc::clone(&store), Some(cipher));
        admin
            .apply(
                "default",
                UserDdl::CreateRole {
                    name: "analyst".into(),
                    if_not_exists: false,
                },
            )
            .await
            .expect("create role");
        assert!(store
            .list_roles("default")
            .await
            .unwrap()
            .contains(&"analyst".to_string()));
        // Duplicate without IF NOT EXISTS → AlreadyExists.
        assert!(matches!(
            admin
                .apply(
                    "default",
                    UserDdl::CreateRole {
                        name: "analyst".into(),
                        if_not_exists: false
                    }
                )
                .await,
            Err(UserAdminError::AlreadyExists(_))
        ));
        assert!(matches!(
            admin
                .apply(
                    "default",
                    UserDdl::DropRole {
                        name: "analyst".into(),
                        if_exists: false
                    }
                )
                .await
                .unwrap(),
            UserOutcome::Dropped { .. }
        ));
    }

    #[tokio::test]
    async fn store_source_returns_cleartext_for_stored_user_and_nothing_for_unknown() {
        let (store, cipher, _d) = setup().await;
        let admin = StoreUserAdmin::new(Arc::clone(&store), Some(Arc::clone(&cipher)));
        //  F3: the user lives in a NON-default org, yet auth still finds
        // it (global-unique usernames → cross-org `find_user`).
        admin
            .apply("acme", create_user("alice", Some("s3cret")))
            .await
            .expect("create");

        let source = StoreUserPasswordSource::new(Arc::clone(&store), cipher);
        // Known user → the exact cleartext, so pgwire's md5 verifier (which
        // recomputes md5(pw‖user) from this) matches the client's response —
        // proving the loop closes exactly as a config password would.
        assert_eq!(source.password("alice").await.as_deref(), Some("s3cret"));
        // Unknown user → nothing.
        assert!(source.password("ghost").await.is_none());

        // A passwordless user also yields nothing (cannot log in with a password).
        admin
            .apply("acme", create_user("svc", None))
            .await
            .expect("create passwordless");
        assert!(source.password("svc").await.is_none());
    }

    #[tokio::test]
    async fn create_user_rejects_cross_org_duplicate_but_stays_same_org_idempotent() {
        //  F3 global-unique usernames: `alice` in `acme` blocks `alice`
        // in `default`, while re-creating `alice` in `acme` still behaves as
        // before (same-org AlreadyExists / IF NOT EXISTS NoOp).
        let (store, cipher, _d) = setup().await;
        let admin = StoreUserAdmin::new(Arc::clone(&store), Some(cipher));

        admin
            .apply("acme", create_user("alice", Some("p")))
            .await
            .expect("create in acme");

        // Cross-org duplicate is rejected (message names only the user).
        let err = admin
            .apply("default", create_user("alice", Some("p2")))
            .await
            .expect_err("cross-org dup");
        assert!(matches!(err, UserAdminError::AlreadyExists(ref n) if n == "alice"));

        // Even IF NOT EXISTS is rejected across orgs — the name is unavailable,
        // not "already this same user".
        let ine = UserDdl::CreateUser {
            name: "alice".into(),
            password: Some("p3".into()),
            superuser: false,
            if_not_exists: true,
        };
        let err = admin
            .apply("default", ine)
            .await
            .expect_err("cross-org dup even with IF NOT EXISTS");
        assert!(matches!(err, UserAdminError::AlreadyExists(ref n) if n == "alice"));

        // Re-creating in the SAME org is still a plain same-org AlreadyExists.
        let err = admin
            .apply("acme", create_user("alice", Some("p4")))
            .await
            .expect_err("same-org dup");
        assert!(matches!(err, UserAdminError::AlreadyExists(ref n) if n == "alice"));

        // And IF NOT EXISTS in the same org is still an idempotent NoOp.
        let ine_same = UserDdl::CreateUser {
            name: "alice".into(),
            password: Some("p5".into()),
            superuser: false,
            if_not_exists: true,
        };
        assert!(matches!(
            admin.apply("acme", ine_same).await.unwrap(),
            UserOutcome::NoOp
        ));

        // The name still resolves to acme only.
        let (org, _rec, _hash) = store.find_user("alice").await.unwrap().unwrap();
        assert_eq!(org, "acme");
        assert!(store.get_user("default", "alice").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn store_source_debug_is_redacted() {
        let (store, cipher, _d) = setup().await;
        let source = StoreUserPasswordSource::new(store, cipher);
        let shown = format!("{source:?}");
        assert!(shown.contains("StoreUserPasswordSource"));
        assert!(
            !shown.contains("cipher"),
            "must not render the cipher: {shown}"
        );
    }

    #[derive(Debug)]
    struct MapSource(std::collections::HashMap<String, String>);
    #[async_trait]
    impl PasswordSource for MapSource {
        async fn password(&self, user: &str) -> Option<String> {
            self.0.get(user).cloned()
        }
    }

    #[tokio::test]
    async fn merged_source_prefers_primary_then_falls_back() {
        let primary = Arc::new(MapSource(std::collections::HashMap::from([(
            "alice".to_string(),
            "from-store".to_string(),
        )])));
        let secondary = Arc::new(MapSource(std::collections::HashMap::from([
            ("alice".to_string(), "from-config".to_string()),
            ("bob".to_string(), "config-only".to_string()),
        ])));
        let merged = MergedPasswordSource::new(primary, secondary);
        // Store (primary) wins.
        assert_eq!(
            merged.password("alice").await.as_deref(),
            Some("from-store")
        );
        // Config (secondary) fallback for a store-absent user.
        assert_eq!(merged.password("bob").await.as_deref(), Some("config-only"));
        // Unknown everywhere → nothing.
        assert!(merged.password("ghost").await.is_none());
    }
}

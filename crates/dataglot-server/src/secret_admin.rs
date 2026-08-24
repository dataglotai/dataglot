//! Server-side implementation of the pgwire [`SecretAdmin`] seam — the
//! effecting half of `CREATE / DROP SECRET` ( slice D.3).
//!
//! [`StoreSecretAdmin`] encrypts a secret's value with the envelope
//! [`SecretCipher`] and persists the ciphertext to the [`MetaStore`]; the store
//! never sees plaintext (rule 12). It also exposes [`resolve_secret`], which
//! catalog DDL uses to turn a `*_secret` option into the real value at
//! connect-build time.

use std::sync::Arc;

use async_trait::async_trait;
use dataglot_catalog::MetaStore;
use dataglot_pgwire::secret_admin::{SecretAdmin, SecretAdminError, SecretOutcome};
use dataglot_pgwire::secret_ddl::SecretDdl;

use crate::config::SecretResolver;
use crate::secret_crypto::SecretCipher;

/// A [`SecretResolver`] over the meta store + envelope cipher — the bridge that
/// lets catalog DDL resolve a `*_secret` reference at connect-build time
///. Kept separate from [`StoreSecretAdmin`] so the config
/// layer depends only on the trait, not the admin.
pub struct StoreSecretResolver {
    store: Arc<dyn MetaStore>,
    cipher: Arc<SecretCipher>,
}

impl StoreSecretResolver {
    /// Wrap a store + cipher. The target org is supplied per
    /// [`SecretResolver::resolve`] call so one resolver serves
    /// every tenant.
    #[must_use]
    pub fn new(store: Arc<dyn MetaStore>, cipher: Arc<SecretCipher>) -> Self {
        Self { store, cipher }
    }
}

#[async_trait]
impl SecretResolver for StoreSecretResolver {
    async fn resolve(&self, org: &str, name: &str) -> anyhow::Result<String> {
        resolve_secret(self.store.as_ref(), org, &self.cipher, name)
            .await
            // The `SecretAdminError` is already value-free (rule 12).
            .map_err(|e| anyhow::anyhow!("{e}"))
    }
}

/// [`SecretAdmin`] backed by the [`MetaStore`] + envelope [`SecretCipher`].
///
///  M2: one admin serves every org — the target org arrives per
/// [`SecretAdmin::apply`] call (threaded from the connection's session identity
/// by the pgwire handler) rather than being fixed at construction.
#[derive(Clone)]
pub struct StoreSecretAdmin {
    store: Arc<dyn MetaStore>,
    cipher: Arc<SecretCipher>,
}

impl StoreSecretAdmin {
    /// Wrap a store + cipher. The target org is supplied per
    /// [`SecretAdmin::apply`] call.
    #[must_use]
    pub fn new(store: Arc<dyn MetaStore>, cipher: Arc<SecretCipher>) -> Self {
        Self { store, cipher }
    }
}

/// Fetch + decrypt a secret by name. Used by catalog DDL to resolve a
/// `*_secret` option. Returns the plaintext (the caller must treat it as a
/// credential — never log it, rule 12).
///
/// # Errors
/// [`SecretAdminError::NotFound`] if there's no such secret, or
/// [`SecretAdminError::Backend`] on a store read / decryption failure.
pub async fn resolve_secret(
    store: &dyn MetaStore,
    org: &str,
    cipher: &SecretCipher,
    name: &str,
) -> Result<String, SecretAdminError> {
    let ciphertext = store
        .get_secret(org, name)
        .await
        .map_err(|e| SecretAdminError::Backend(format!("secret store: {e}")))?
        .ok_or_else(|| SecretAdminError::NotFound(name.to_string()))?;
    let plaintext = cipher
        .decrypt(&ciphertext)
        // The crypto error is already value-free (rule 12).
        .map_err(|e| SecretAdminError::Backend(format!("secret {name:?}: {e}")))?;
    String::from_utf8(plaintext).map_err(|_| {
        SecretAdminError::Backend(format!("secret {name:?}: value is not valid UTF-8"))
    })
}

#[async_trait]
impl SecretAdmin for StoreSecretAdmin {
    async fn apply(&self, org: &str, ddl: SecretDdl) -> Result<SecretOutcome, SecretAdminError> {
        match ddl {
            SecretDdl::Create {
                name,
                value,
                or_replace,
                if_not_exists,
            } => {
                let exists = self
                    .store
                    .list_secret_names(org)
                    .await
                    .map_err(|e| SecretAdminError::Backend(format!("secret store: {e}")))?
                    .iter()
                    .any(|n| n == &name);
                if exists {
                    if if_not_exists {
                        return Ok(SecretOutcome::NoOp);
                    }
                    if !or_replace {
                        return Err(SecretAdminError::AlreadyExists(name));
                    }
                }
                let ciphertext = self
                    .cipher
                    .encrypt(value.as_bytes())
                    .map_err(|e| SecretAdminError::Backend(format!("secret {name:?}: {e}")))?;
                self.store
                    .put_secret(org, &name, &ciphertext)
                    .await
                    .map_err(|e| SecretAdminError::Backend(format!("secret store: {e}")))?;
                Ok(SecretOutcome::Created { name })
            }
            SecretDdl::Drop { name, if_exists } => {
                let removed = self
                    .store
                    .delete_secret(org, &name)
                    .await
                    .map_err(|e| SecretAdminError::Backend(format!("secret store: {e}")))?;
                if removed {
                    Ok(SecretOutcome::Dropped { name })
                } else if if_exists {
                    Ok(SecretOutcome::NoOp)
                } else {
                    Err(SecretAdminError::NotFound(name))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use dataglot_catalog::embedded::EmbeddedMetaStore;

    use super::*;

    async fn setup() -> (Arc<dyn MetaStore>, Arc<SecretCipher>, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store: Arc<dyn MetaStore> = Arc::new(
            EmbeddedMetaStore::open(dir.path().join("m.json"), "default")
                .await
                .expect("store"),
        );
        let key = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
        let cipher = Arc::new(SecretCipher::from_base64_key("TEST", &key).expect("cipher"));
        (store, cipher, dir)
    }

    fn create(name: &str, value: &str, or_replace: bool, if_not_exists: bool) -> SecretDdl {
        SecretDdl::Create {
            name: name.to_string(),
            value: value.to_string(),
            or_replace,
            if_not_exists,
        }
    }

    #[tokio::test]
    async fn create_encrypts_and_resolve_round_trips() {
        let (store, cipher, _d) = setup().await;
        let admin = StoreSecretAdmin::new(Arc::clone(&store), Arc::clone(&cipher));

        admin
            .apply(
                "default",
                create("pw", "host=db password=hunter2", false, false),
            )
            .await
            .expect("create");

        // Stored bytes are ciphertext — the plaintext must not appear.
        let stored = store
            .get_secret("default", "pw")
            .await
            .unwrap()
            .expect("present");
        assert!(
            !stored.windows(6).any(|w| w == b"hunter"),
            "stored is ciphertext"
        );

        // Resolve decrypts back to the plaintext.
        let resolved = resolve_secret(store.as_ref(), "default", &cipher, "pw")
            .await
            .expect("resolve");
        assert_eq!(resolved, "host=db password=hunter2");
    }

    #[tokio::test]
    async fn create_persists_under_the_call_org_only() {
        //  M2: the org is a per-call argument, so a secret created for
        // org "acme" lands under "acme" and is invisible to "default".
        let (store, cipher, _d) = setup().await;
        let admin = StoreSecretAdmin::new(Arc::clone(&store), Arc::clone(&cipher));

        admin
            .apply("acme", create("pw", "s3cr3t", false, false))
            .await
            .expect("create under acme");

        assert!(store.get_secret("acme", "pw").await.unwrap().is_some());
        assert!(store.get_secret("default", "pw").await.unwrap().is_none());
        // The resolver reads it back only under the same org.
        assert!(resolve_secret(store.as_ref(), "acme", &cipher, "pw")
            .await
            .is_ok());
        assert!(matches!(
            resolve_secret(store.as_ref(), "default", &cipher, "pw").await,
            Err(SecretAdminError::NotFound(_))
        ));
    }

    #[tokio::test]
    async fn create_duplicate_and_if_not_exists_and_or_replace() {
        let (store, cipher, _d) = setup().await;
        let admin = StoreSecretAdmin::new(Arc::clone(&store), cipher);
        admin
            .apply("default", create("s", "v1", false, false))
            .await
            .expect("first");

        // Duplicate without flags → error.
        let err = admin
            .apply("default", create("s", "v2", false, false))
            .await
            .expect_err("dup");
        assert!(
            matches!(err, SecretAdminError::AlreadyExists(ref n) if n == "s"),
            "{err}"
        );

        // IF NOT EXISTS → no-op, value unchanged.
        let out = admin
            .apply("default", create("s", "v3", false, true))
            .await
            .expect("ine");
        assert!(matches!(out, SecretOutcome::NoOp));

        // OR REPLACE → value updated.
        admin
            .apply("default", create("s", "v4", true, false))
            .await
            .expect("replace");
        let v = resolve_secret(store.as_ref(), "default", &admin.cipher, "s")
            .await
            .unwrap();
        assert_eq!(v, "v4");
    }

    #[tokio::test]
    async fn drop_and_resolve_missing() {
        let (store, cipher, _d) = setup().await;
        let admin = StoreSecretAdmin::new(Arc::clone(&store), Arc::clone(&cipher));
        admin
            .apply("default", create("s", "v", false, false))
            .await
            .expect("create");

        // Drop reports existence.
        assert!(matches!(
            admin
                .apply(
                    "default",
                    SecretDdl::Drop {
                        name: "s".into(),
                        if_exists: false
                    }
                )
                .await
                .unwrap(),
            SecretOutcome::Dropped { .. }
        ));
        // Drop again without IF EXISTS → NotFound.
        let err = admin
            .apply(
                "default",
                SecretDdl::Drop {
                    name: "s".into(),
                    if_exists: false,
                },
            )
            .await
            .expect_err("gone");
        assert!(
            matches!(err, SecretAdminError::NotFound(ref n) if n == "s"),
            "{err}"
        );
        // IF EXISTS → no-op.
        assert!(matches!(
            admin
                .apply(
                    "default",
                    SecretDdl::Drop {
                        name: "s".into(),
                        if_exists: true
                    }
                )
                .await
                .unwrap(),
            SecretOutcome::NoOp
        ));
        // Resolving a missing secret errors.
        assert!(matches!(
            resolve_secret(store.as_ref(), "default", &cipher, "s").await,
            Err(SecretAdminError::NotFound(_))
        ));
    }
}

//! The control-plane admin seam for secret DDL.
//!
//! [`crate::secret_ddl`] parses `CREATE / DROP SECRET`; this trait effects it.
//! As with [`crate::catalog_admin`], the implementation lives in
//! `dataglot-server` (which owns the envelope key + the meta store), so the
//! *seam* lives here and the server depends on this crate — never the reverse
//! (rule 4).
//!
//! Unlike catalog DDL, a secret change touches **no** `SessionContext` — a
//! secret is only ever read later, when a catalog resolves a `*_secret`
//! reference. So the handler just applies the change and returns a command tag.

use async_trait::async_trait;

use crate::secret_ddl::SecretDdl;

/// Outcome of a secret-DDL statement (no session-visible effect).
#[derive(Debug)]
pub enum SecretOutcome {
    /// A secret was created or replaced.
    Created {
        /// Secret name.
        name: String,
    },
    /// A secret was dropped.
    Dropped {
        /// Secret name.
        name: String,
    },
    /// Nothing changed (`IF NOT EXISTS` on existing, `IF EXISTS` on missing).
    NoOp,
}

/// Why a secret-DDL statement could not be applied. `Display` is client-safe
/// and **never** echoes the secret value (rule 12).
#[derive(Debug)]
pub enum SecretAdminError {
    /// `CREATE SECRET <name>` without `OR REPLACE` / `IF NOT EXISTS`, but the
    /// name already exists.
    AlreadyExists(String),
    /// `DROP SECRET <name>` (without `IF EXISTS`) on a name that doesn't exist.
    NotFound(String),
    /// Secrets aren't available on this server — no control-plane store, or no
    /// envelope key configured.
    NotConfigured,
    /// Encryption or a meta-store write failed. The reason is value-free.
    Backend(String),
}

impl std::fmt::Display for SecretAdminError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AlreadyExists(name) => write!(f, "secret {name:?} already exists"),
            Self::NotFound(name) => write!(f, "secret {name:?} does not exist"),
            Self::NotConfigured => write!(
                f,
                "secrets are unavailable: this server needs a configured \
                 catalog_service and a DATAGLOT_SECRET_KEY envelope key"
            ),
            Self::Backend(reason) => write!(f, "{reason}"),
        }
    }
}

impl std::error::Error for SecretAdminError {}

/// Server-side seam that effects secret DDL: encrypt + persist to the store.
///
/// Implemented in `dataglot-server`. The pgwire handler holds one behind an
/// `Arc<dyn SecretAdmin>` and calls [`Self::apply`] on a parsed statement.
#[async_trait]
pub trait SecretAdmin: Send + Sync {
    /// Apply a parsed secret-DDL statement **scoped to `org`**. `org` is the
    /// connection's resolved org, threaded from the session
    /// identity by the handler so a secret persists under the issuing
    /// connection's tenant.
    ///
    /// # Errors
    /// [`SecretAdminError`] on a name precondition, missing configuration, or a
    /// crypto / store failure.
    async fn apply(&self, org: &str, ddl: SecretDdl) -> Result<SecretOutcome, SecretAdminError>;
}

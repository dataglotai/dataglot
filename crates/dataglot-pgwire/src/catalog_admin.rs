//! The control-plane admin seam for catalog DDL.
//!
//! [`crate::catalog_ddl`] parses `CREATE / ALTER / DROP CATALOG` into a typed
//! [`CatalogDdl`]; *this* module defines the trait that effects it. The split
//! exists because effecting a catalog change needs `CatalogConfig`, the
//! per-source connector builders, and the meta-store handle — all of which
//! live in `dataglot-server`, which may not be a dependency of `dataglot-pgwire`
//! (rule 4: `server → pgwire`, never the reverse). So the *seam* lives here and
//! the *implementation* lives in the server, which already depends on this
//! crate.
//!
//! The handler (a later slice) detects catalog DDL at the wire boundary,
//! calls [`CatalogAdmin::apply`], and applies the returned [`CatalogAdminOutcome`]
//! to the current [`datafusion::prelude::SessionContext`] so a
//! `CREATE CATALOG …; SELECT …` in one session sees its own change immediately.
//! The persistence side-effect inside the impl fires the meta-store's change
//! feed, so *other* sessions pick the catalog up on their next connection (the
//! live-registry refresh, slice B).

use std::sync::Arc;

use async_trait::async_trait;
use datafusion::catalog::CatalogProvider;

use crate::catalog_ddl::CatalogDdl;

/// What the session should do after a catalog-DDL statement is applied.
///
/// The impl has already persisted the change to the control plane; this tells
/// the *calling session* how to reflect it locally so the same connection sees
/// its own DDL without reconnecting.
#[derive(Debug)]
pub enum CatalogAdminOutcome {
    /// A catalog was created or replaced. Register `provider` under `name` in
    /// the session (replacing any existing registration of that name).
    Registered {
        /// Catalog name — the key under which to register.
        name: String,
        /// The freshly-built provider for the source.
        provider: Arc<dyn CatalogProvider>,
    },
    /// A catalog was dropped. Deregister `name` from the session.
    Dropped {
        /// Catalog name to remove from the session.
        name: String,
    },
    /// Nothing changed — `CREATE … IF NOT EXISTS` on an existing catalog, or
    /// `DROP … IF EXISTS` on a missing one. The statement still succeeds.
    NoOp,
}

/// Why a catalog-DDL statement could not be applied.
///
/// Every variant's `Display` is **client-safe**: it names the catalog and the
/// problem but never carries credentials (hard rule 12) — the connector
/// builders are responsible for redacting their own error chains, and the
/// [`Self::Backend`] message is built from those already-redacted strings.
#[derive(Debug)]
pub enum CatalogAdminError {
    /// `CREATE CATALOG <name>` without `OR REPLACE` / `IF NOT EXISTS`, but the
    /// name already exists.
    AlreadyExists(String),
    /// `ALTER` / `DROP CATALOG <name>` (without `IF EXISTS`) on a name that
    /// does not exist.
    NotFound(String),
    /// The `WITH (...)` options don't describe a valid catalog (unknown `kind`,
    /// missing a required field, an option the source doesn't accept, or a
    /// non-string-valued field the option-bag form can't express). Carries a
    /// human-readable reason.
    InvalidOptions(String),
    /// The source config parsed but the connector could not be built (e.g. the
    /// database is unreachable), or the meta-store write failed. Carries an
    /// already-redacted reason.
    Backend(String),
}

impl std::fmt::Display for CatalogAdminError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AlreadyExists(name) => write!(f, "catalog {name:?} already exists"),
            Self::NotFound(name) => write!(f, "catalog {name:?} does not exist"),
            Self::InvalidOptions(reason) => write!(f, "invalid catalog options: {reason}"),
            Self::Backend(reason) => write!(f, "{reason}"),
        }
    }
}

impl std::error::Error for CatalogAdminError {}

/// Server-side seam that effects catalog DDL against the control-plane store.
///
/// Implemented in `dataglot-server` (see its `catalog_admin` module). The
/// pgwire handler holds one behind an `Arc<dyn CatalogAdmin>` and calls
/// [`Self::apply`] whenever [`crate::catalog_ddl::parse_catalog_ddl`] returns
/// `Some`.
#[async_trait]
pub trait CatalogAdmin: Send + Sync {
    /// Apply a parsed catalog-DDL statement **scoped to `org`**: validate +
    /// build the source, persist the change to the control plane under that org
    /// (which fires the change feed for other sessions), and return how the
    /// calling session should reflect it. `org` is the connection's resolved
    /// org — the handler threads it from the session identity so a
    /// `CREATE CATALOG` persists under the issuing connection's tenant.
    ///
    /// # Errors
    /// Returns a [`CatalogAdminError`] when the name precondition fails
    /// (`AlreadyExists` / `NotFound`), the options are invalid, or the source
    /// build / store write fails.
    async fn apply(
        &self,
        org: &str,
        ddl: CatalogDdl,
    ) -> Result<CatalogAdminOutcome, CatalogAdminError>;
}

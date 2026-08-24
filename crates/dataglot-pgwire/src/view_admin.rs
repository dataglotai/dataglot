//! The control-plane admin seam for view DDL — derived products.
//!
//! [`crate::view_ddl`] parses `CREATE / DROP VIEW` into a typed [`ViewDdl`];
//! *this* module defines the trait that effects it. The split mirrors
//! [`crate::catalog_admin`]: persisting a derived product needs the meta-store
//! handle and the live per-org view registry, both of which live in
//! `dataglot-server` (rule 4: `server → pgwire`, never the reverse). So the
//! *seam* lives here and the *implementation* lives in the server.
//!
//! # Who plans the query
//!
//! Unlike catalog DDL, the **handler** validates + builds the view's provider
//! (a DataFusion [`ViewTable`](datafusion::datasource::ViewTable)) by planning
//! the `AS <query>` against the *calling session's* `SessionContext` — the only
//! context that can see a catalog the same session just created
//! (`CREATE CATALOG …; CREATE VIEW … AS SELECT … FROM that`). A query that can't
//! plan fails the statement there, before any persist (the "no half-created
//! view" invariant). The handler then hands the built provider to
//! [`ViewAdmin::apply`], which **persists** the definition and **registers the
//! provider into the live per-org registry** so subsequent connections can
//! query it — the same visibility model as `CREATE CATALOG`.
//!
//! # Governance (rule 6)
//!
//! A `ViewTable` inlines its plan at query time, so the underlying source
//! `TableScan` appears in the querying session's plan and the existing plan-time
//! `PolicyOptimizerRule` masks a masked source column *through* the view — the
//! mask can't be bypassed by querying the view instead of the source.

use std::sync::Arc;

use async_trait::async_trait;
use datafusion::catalog::TableProvider;

use crate::view_ddl::ViewDdl;

/// The result of applying a view-DDL statement, telling the *calling session*
/// how to reflect it locally (the persistence + live-registry side-effects have
/// already happened inside [`ViewAdmin::apply`]).
#[derive(Debug)]
pub enum ViewAdminOutcome {
    /// A view was created (new) — register the handler-built provider in-session.
    Created,
    /// An existing view was replaced (`OR REPLACE`) — register in-session.
    Replaced,
    /// A view was dropped. Deregister it from the session under these (stored)
    /// qualifiers.
    Dropped {
        /// Optional catalog qualifier the view was stored under.
        catalog: Option<String>,
        /// Optional schema qualifier the view was stored under.
        schema: Option<String>,
        /// View name to remove from the session.
        name: String,
    },
    /// Nothing changed — `DROP VIEW IF EXISTS` on a missing view. Still succeeds.
    NoOp,
}

/// Why a view-DDL statement could not be applied.
///
/// Every variant's `Display` is **client-safe**: it names the view and the
/// problem but never carries credentials (rule 12).
#[derive(Debug)]
pub enum ViewAdminError {
    /// `CREATE VIEW <name>` without `OR REPLACE`, but the name already exists.
    AlreadyExists(String),
    /// `DROP VIEW <name>` (without `IF EXISTS`) on a name that does not exist.
    NotFound(String),
    /// The `AS <query>` could not be planned — a broken/unresolvable query is
    /// rejected at `CREATE` time (like `CREATE CATALOG` validates its source).
    /// Carries a human-readable, credential-free reason.
    InvalidQuery(String),
    /// The query validated but the meta-store write failed. Carries an
    /// already-redacted reason.
    Backend(String),
}

impl std::fmt::Display for ViewAdminError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AlreadyExists(name) => write!(f, "view {name:?} already exists"),
            Self::NotFound(name) => write!(f, "view {name:?} does not exist"),
            Self::InvalidQuery(reason) => write!(f, "invalid view query: {reason}"),
            Self::Backend(reason) => write!(f, "{reason}"),
        }
    }
}

impl std::error::Error for ViewAdminError {}

/// Server-side seam that effects view DDL against the control-plane store.
///
/// Implemented in `dataglot-server` (see its `view_admin` module). The pgwire
/// handler holds one behind an `Arc<dyn ViewAdmin>` and calls [`Self::apply`]
/// whenever [`crate::view_ddl::parse_view_ddl`] returns `Some`.
#[async_trait]
pub trait ViewAdmin: Send + Sync {
    /// Apply a parsed view-DDL statement **scoped to `org`**.
    ///
    /// For `CREATE`, `provider` is the [`ViewTable`](datafusion::datasource::ViewTable)
    /// the handler already built + validated against the calling session;
    /// `apply` persists the derived-product definition under `org` and registers
    /// `provider` into the live per-org registry so subsequent connections see
    /// it. For `DROP`, `provider` is `None`; `apply` removes the definition from
    /// the store and the registry.
    ///
    /// # Errors
    /// Returns a [`ViewAdminError`] when the name precondition fails
    /// (`AlreadyExists` / `NotFound`) or the store write fails (`Backend`). The
    /// query-validity check (`InvalidQuery`) is the handler's, before `apply`.
    async fn apply(
        &self,
        org: &str,
        ddl: ViewDdl,
        provider: Option<Arc<dyn TableProvider>>,
    ) -> Result<ViewAdminOutcome, ViewAdminError>;
}

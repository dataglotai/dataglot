//! Error type for the catalog service.
//!
//! Library crate per hard rule 8 — typed errors via
//! `thiserror`, no `anyhow` here.

use thiserror::Error;

/// Catalog-service operation result type.
pub type Result<T> = std::result::Result<T, CatalogServiceError>;

/// Errors surfaced by [`crate::CatalogService`].
#[derive(Debug, Error)]
pub enum CatalogServiceError {
    /// Connect / TLS / startup-message failures from the
    /// underlying Postgres driver.
    #[error("postgres connection failed: {0}")]
    Connect(#[source] tokio_postgres::Error),

    /// Pool initialisation or borrow failure.
    #[error("postgres pool error: {0}")]
    Pool(String),

    /// A SQL statement returned an error (DDL, DML, or query).
    #[error("postgres query failed: {0}")]
    Query(#[source] tokio_postgres::Error),

    /// The schema version in the database doesn't match this
    /// crate's expected version. Indicates either a stale
    /// dataglot binary against a newer DB, or a fresh
    /// dataglot against a database that wasn't initialised
    /// by this crate.
    #[error("schema version mismatch: expected {expected}, found {found}")]
    SchemaVersionMismatch {
        /// Version this build of `dataglot-catalog` understands.
        expected: String,
        /// Version actually present in the database.
        found: String,
    },

    /// A row's `binding_json` column couldn't be decoded into
    /// a `CatalogBinding`. Indicates either a serde-shape
    /// regression in `dataglot-core::catalog` or an external
    /// write that injected malformed JSON.
    #[error("malformed binding for catalog {name:?}: {source}")]
    MalformedBinding {
        /// Catalog name the malformed binding was keyed under.
        name: String,
        /// Underlying serde error.
        #[source]
        source: serde_json::Error,
    },

    /// `serde_json::to_value` failed on a binding. Practically
    /// impossible for the current shape (all fields serialize
    /// cleanly) but kept as a typed error so future variants
    /// don't unwrap into a panic.
    #[error("failed to serialize binding for catalog {name:?}: {source}")]
    BindingSerialization {
        /// Catalog name the failing binding was keyed under.
        name: String,
        /// Underlying serde error.
        #[source]
        source: serde_json::Error,
    },

    /// Filesystem IO failed against the embedded meta store's backing
    /// file (read, atomic write, or rename). Postgres-backed stores
    /// never produce this.
    #[error("embedded meta store IO failed at {path:?}: {source}")]
    Io {
        /// Backing-file path the operation targeted.
        path: String,
        /// Underlying IO error.
        #[source]
        source: std::io::Error,
    },

    /// The embedded meta store's backing file exists but couldn't be
    /// parsed as its JSON document — a corrupt or hand-edited file, or
    /// a forward-incompatible on-disk shape.
    #[error("embedded meta store file {path:?} is corrupt: {source}")]
    CorruptStore {
        /// Backing-file path that failed to parse.
        path: String,
        /// Underlying serde error.
        #[source]
        source: serde_json::Error,
    },

    /// Serializing the embedded meta store's in-memory document to JSON
    /// failed. Practically impossible for the current shape (bindings +
    /// `*_env` source configs all serialize cleanly) but kept typed so a
    /// future variant can't turn into a panic.
    #[error("failed to serialize embedded meta store document: {0}")]
    StoreSerialization(#[source] serde_json::Error),

    /// A `db_grant` row carried a token this build doesn't
    /// understand — an unknown `grantee_kind` or `privilege`. Indicates an
    /// external write or a forward-incompatible row; the Postgres backend
    /// surfaces it typed rather than silently defaulting corrupt data.
    #[error("malformed grant row: {0}")]
    MalformedGrant(String),

    /// A `redb` transaction / table / commit operation failed in the embedded
    /// [`RedbMetaStore`](crate::RedbMetaStore). The message is redb's
    /// own — structural / IO detail only, never a stored value (rule 12).
    #[error("embedded meta store (redb) error: {0}")]
    Redb(String),

    /// A `spawn_blocking` task running a redb operation was cancelled or
    /// panicked. Distinct from [`Self::Redb`] so a runtime-shutdown
    /// cancellation is not mistaken for a storage fault.
    #[error("embedded meta store task failed: {0}")]
    Join(String),
}

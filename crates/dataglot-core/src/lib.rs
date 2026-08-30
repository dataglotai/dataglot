//! Shared types and `DataFusion` `SessionContext` setup for Dataglot.
//!
//! Public surface:
//! - [`SessionContextFactory`] / [`SessionConfig`]: factories for
//!   building configured `DataFusion` `SessionContext` instances. Use
//!   [`SessionContextFactory::create_federated_context`] when you want
//!   `datafusion-federation` installed (the cross-source pushdown
//!   workaround for upstream bug #N is wrapped here).
//! - [`DataglotError`] / [`Result`]: workspace error type.
//!
//! Connectors implement `DataFusion`'s own `TableProvider` /
//! `CatalogProvider` traits directly via `datafusion-federation`'s
//! `SQLExecutor` and `iceberg-datafusion`'s providers, so this crate
//! does NOT redefine those abstractions.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used))]
// bare .unwrap() panics without context on a live server; use .expect("why") or return an error. Tests exempt.
#![warn(missing_docs)]
#![cfg_attr(not(test), deny(clippy::print_stdout, clippy::print_stderr))]

pub mod catalog;
pub mod credentials;
pub mod error;
pub mod federation_dedup_guard;
pub mod federation_mark_join_guard;
pub mod federation_pushdown;
pub mod functions;
pub mod governance;
pub mod lineage;
pub mod pg_catalog_overlay;
pub mod pushdown_stats;
pub mod session;

pub use catalog::{
    CatalogBinding, IcebergCacheBinding, LiveConnectorBinding, LiveConnectorKind,
    SemanticCatalogBinding, SemanticCatalogError,
};
pub use credentials::{
    CredentialConfigEntry, CredentialConfigError, CredentialError, CredentialHandle,
    CredentialResolver, CredentialResolverConfig, Credentials, StaticCredentialResolver,
};
pub use error::{DataglotError, Result};
pub use governance::{
    placeholder_column, ColumnDefinitionSource, ColumnMetadata, DataProduct, DataProductPublisher,
    DynDataProductPublisher, NoopDataProductPublisher, ProductPlatform, TableName,
    PLACEHOLDER_DEFINITION,
};
pub use lineage::{
    extract_inputs, DatasetRef, DynLineageEmitter, Identity as LineageIdentity, LineageEmitter,
    NoopLineageEmitter, QueryFinishContext, QueryOutcome, QueryStartContext, RunId,
};
pub use pg_catalog_overlay::{
    build_scoped_pg_catalog_schema, build_scoped_pg_catalog_schema_with_roles,
    extract_pg_catalog_schema, prewarm_pg_catalog_static_tables, PgCatalogOverlayProvider,
    PgRoleSpec,
};
pub use pushdown_stats::{
    capture_pushdown_context, clear_pushdown_run_id, current_pushdown_run_id, record_pushdown,
    set_pushdown_run_id, with_pushdown_sink, CapturedPushdownContext, PushdownOutcome,
    PushdownSink, PushdownStat,
};
pub use session::{
    ensure_runtime_catalog, PlanRewriteFn, SessionConfig, SessionContextFactory,
    SessionPlanRewriter, RUNTIME_CATALOG, RUNTIME_SCHEMA,
};

/// Returns the `DataFusion` version as a string.
///
/// Useful for health checks and diagnostics.
#[must_use]
pub fn datafusion_version() -> &'static str {
    datafusion::DATAFUSION_VERSION
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_datafusion_version_returns_valid_string() {
        let version = datafusion_version();
        assert!(
            !version.is_empty(),
            "DataFusion version should not be empty"
        );
        // Version should start with a number (e.g., "53.0.0")
        assert!(
            version.chars().next().unwrap().is_ascii_digit(),
            "DataFusion version should start with a digit"
        );
    }
}

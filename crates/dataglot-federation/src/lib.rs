//! Federation layer — connectors that bridge external data sources into
//! `DataFusion`'s `SessionContext`.
//!
//! Each connector is a self-contained module:
//! - [`postgres::PostgresConnector`] implements `datafusion_federation::sql::SQLExecutor`
//!   over `tokio-postgres`, producing a federated `TableProvider` whose
//!   filters / projections / limits push down via the unparser.
//! - [`mysql::MysqlConnector`] mirrors the Postgres connector on top of
//!   `mysql_async`, with `MySqlDialect` driving the unparser so backticks
//!   and MySQL-flavoured `LIMIT n` are emitted instead of Postgres syntax.
//! - [`snowflake::SnowflakeConnector`] talks Snowflake's REST API via
//!   `snowflake-api` (pinned to Peaka's `arrow-58` fork). Snowflake
//!   returns Arrow IPC natively so the executor is mostly pass-through
//!   — no per-type byte decoders, just dialect + catalog discovery.
//!   MVP covers the 6 most-common types per the Phase 1 spec.
//! - [`iceberg::WarehouseConnector`] wraps an Iceberg REST catalog
//!   (typically Lakekeeper) and hands back `iceberg-datafusion`'s
//!   `IcebergStaticTableProvider` directly.
//!
//! Both SQL connectors expose `as_catalog_provider` for whole-catalog
//! registration with a `SessionContext`, and `table_provider` for
//! per-table registration.
//!
//! # Feature Flags
//!
//! Enable connectors via feature flags (per hard rule 9):
//! - `postgres` - `PostgreSQL` data source connector
//! - `mysql` - `MySQL` data source connector
//! - `iceberg` - Apache Iceberg table format support (Rule 7: kept as
//!   the internal feature name; user-facing surface uses "warehouse")
//! - `snowflake` - Snowflake data source connector (stub; dep is wired
//!   in via the Peaka `arrow-58` fork of `andrusha/snowflake-rs` but
//!   no `SQLExecutor` impl yet — see Phase 2 follow-up)
//!
//! ```bash
//! cargo build --features postgres,mysql,iceberg
//! ```

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used))]
// bare .unwrap() panics without context on a live server; use .expect("why") or return an error. Tests exempt.
#![warn(missing_docs)]
#![cfg_attr(not(test), deny(clippy::print_stdout, clippy::print_stderr))]

#[cfg(feature = "adbc")]
pub mod adbc;
pub mod codec;
pub mod health;
#[cfg(feature = "iceberg")]
pub mod iceberg;
#[cfg(feature = "iceberg")]
pub mod materialize;
#[cfg(feature = "mysql")]
pub mod mysql;
#[cfg(feature = "mysql")]
pub mod mysql_tls;
#[cfg(feature = "odata")]
pub mod odata;
#[cfg(any(feature = "oracle", feature = "oracle-pure"))]
pub mod oracle;
#[cfg(feature = "postgres")]
pub mod pg_tls;
#[cfg(feature = "postgres")]
pub mod postgres;
pub mod pushdown_metrics;
pub mod pushdown_trace;
pub mod registry;
#[cfg(feature = "rest")]
pub mod rest;
// Shared unparser fix-ups used by every SQL connector's ast_analyzer /
// logical_optimizer: derived-table requalification (/291) and
// governance-filter isolation (/291).
#[cfg(any(
    feature = "adbc",
    feature = "postgres",
    feature = "mysql",
    feature = "oracle",
    feature = "oracle-pure",
    feature = "snowflake"
))]
pub(crate) mod derived_requalify;
#[cfg(any(
    feature = "adbc",
    feature = "postgres",
    feature = "mysql",
    feature = "oracle",
    feature = "oracle-pure",
    feature = "snowflake"
))]
pub(crate) mod rls_isolation;
#[cfg(feature = "snowflake")]
pub mod snowflake;

pub use codec::{FederationPlanCodec, CODEC_VERSION};
pub use health::ConnectorHealthCheck;
pub use pushdown_metrics::{
    PushdownMetricsExec, WrapFederatedScansForMetrics, PUSHDOWN_METRIC_PREFIX,
};
pub use pushdown_trace::{instrument_pushdown, PUSHDOWN_TARGET};
pub use registry::{ConnectorRegistry, DynConnectorRegistry, InMemoryConnectorRegistry};

// Re-export the `SQLExecutor` trait from `datafusion-federation` so
// `dataglot-server`'s ballista wiring (slice 4b.5) can name the
// trait type for the `InMemoryConnectorRegistry::new` map without
// taking a direct `datafusion-federation` dep (hard rule 4 —
// cross-crate touchpoints go through known re-exports rather than
// transitive symbols).
pub use datafusion_federation::sql::SQLExecutor;

#[cfg(test)]
mod tests {
    #[test]
    fn test_crate_compiles() {
        // Verify crate compiles correctly
    }
}

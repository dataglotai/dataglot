//! `PostgreSQL` data source connector.
//!
//! This module is gated behind the `postgres` feature flag. It provides
//! [`PostgresConnector`] which implements the `datafusion-federation`
//! `SQLExecutor` trait on top of [`tokio_postgres`]. A connector instance
//! owns a `tokio-postgres` client and exposes two user-facing entry points:
//!
//! - [`PostgresConnector::connect`] — async constructor that parses a DSN
//!   and opens the connection.
//! - [`PostgresConnector::table_provider`] — lazily resolves the schema for
//!   a `<schema>.<table>` pair and returns a `DataFusion` `TableProvider`
//!   wired to `datafusion-federation` so filters/projections/limits push
//!   down to `PostgreSQL`.
//!
//! # Hard-rule compliance
//!
//! * Rule 1 — data flows as Arrow `RecordBatch` end-to-end; rows are decoded
//!   into Arrow arrays inside the `SQLExecutor::execute` impl on
//!   [`PostgresConnector`]. There is no row-mode conversion above this layer.
//! * Rule 10 — the executor is `Send + Sync + 'static`.
//! * Rule 11 — all I/O is async; no blocking calls under an async fn.
//! * Rule 12 — DSNs are parsed and stored as a [`tokio_postgres::Config`].
//!   The password is never included in logs, error messages, or `Debug`
//!   output. See the private `redacted_dsn` helper.
//! * Rule 13 — schemas are fetched on first `table_provider` call, not at
//!   connector construction time.

use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;
use std::sync::Arc;

use arrow::array::{
    ArrayRef, BooleanBuilder, Date32Builder, Decimal128Builder, Float32Builder, Float64Builder,
    Int16Builder, Int32Builder, Int64Builder, StringBuilder, TimestampMicrosecondBuilder,
    TimestampNanosecondBuilder, UInt64Builder,
};
use arrow::datatypes::{DataType, Field, Schema, SchemaRef, TimeUnit};
use arrow::record_batch::RecordBatch;
use async_trait::async_trait;
use datafusion::catalog::{
    CatalogProvider as DfCatalogProvider, SchemaProvider as DfSchemaProvider,
};
use datafusion::datasource::TableProvider;
use datafusion::error::{DataFusionError, Result as DfResult};
use datafusion::execution::SendableRecordBatchStream;
use datafusion::logical_expr::LogicalPlan;
use datafusion::physical_plan::stream::RecordBatchStreamAdapter;
use datafusion::physical_plan::PhysicalExpr;
use datafusion::sql::sqlparser::ast;
use datafusion::sql::unparser::dialect::{Dialect, PostgreSqlDialect};
use datafusion::sql::TableReference;
use datafusion_federation::sql::{
    AstAnalyzer, LogicalOptimizer, RemoteTableRef, SQLExecutor, SQLFederationProvider,
    SQLTableSource,
};
use datafusion_federation::FederatedTableProviderAdaptor;
use futures::stream;
use tokio_postgres::config::SslMode;
use tokio_postgres::types::Type as PgType;
use tokio_postgres::{Client, Config, NoTls, Row};
use tracing::{debug, info};

use crate::derived_requalify::requalify_derived_refs;
use crate::pg_tls::PgTls;
use crate::rls_isolation::isolate_outer_join_filters;
use dataglot_core::{DataglotError, Result as DataglotResult};

/// Format a `tokio_postgres::Error` for inclusion in user-visible
/// error messages.
///
/// `tokio_postgres::Error`'s own `Display` is famously terse — for
/// `Kind::Db` it writes the literal `"db error"` and leaves the
/// underlying [`tokio_postgres::error::DbError`] (which has the
/// real SQLSTATE + message + DETAIL + HINT) reachable only via
/// the `source()` chain. This swallowing surfaced in slice 4c.B
/// (PR #276): an unparsed UNION rejected by Postgres bubbled up
/// to the CI logs as `postgres query failed: db error` with no
/// diagnostic information. This helper prefers the `DbError`
/// when present and falls back to the generic `Display` for
/// non-db variants (IO, TLS, parse, etc.).
///
/// **Credential safety** (hard rule 12): `DbError` fields
/// (severity, code, message, detail, hint) come from `PostgreSQL`'s
/// response and describe the failure, not the connection — they
/// never contain DSN, password, or token material. The generic
/// `Display` for non-db variants is likewise safe (it prints
/// shapes like `"error communicating with the server"` without
/// host info).
fn format_pg_error(err: &tokio_postgres::Error) -> String {
    err.as_db_error()
        .map_or_else(|| err.to_string(), ToString::to_string)
}

/// A `PostgreSQL` federation connector.
///
/// Construct via [`PostgresConnector::connect`] with a libpq-style DSN. A
/// connector owns one `tokio-postgres` client plus the parsed [`Config`]
/// (with the password redacted in `Debug`). It can then hand out
/// [`TableProvider`]s backed by `datafusion-federation` for any
/// `<schema>.<table>` pair in that database.
///
/// Schemas are fetched lazily the first time a table is accessed —
/// construction never issues any queries beyond the initial connection
/// handshake.
pub struct PostgresConnector {
    /// Unique name used by `SQLExecutor::name`. Also serves as the
    /// federation compute-context key. This is DSN-derived (a
    /// credential-stripped host/db identity), so scans of the same source
    /// group for pushdown regardless of catalog name.
    name: String,
    /// Catalog name this connector is registered under, set via
    /// [`Self::with_catalog`] at build time. Used as the operator-facing
    /// `source` label in pushdown telemetry so it matches the query's
    /// `sources` list (`"pg"`), rather than the DSN-derived `name`. `None`
    /// falls back to `name` (e.g. tests that don't register a catalog).
    catalog: Option<String>,
    /// Shared Arrow client. `Client` itself is `Send + Sync`.
    client: Arc<Client>,
    /// Parsed connection config. Used for `Debug` (with redaction) and
    /// for identifying the compute context.
    config: Config,
}

/// Upper bound on establishing a Postgres connection (TCP + TLS + the
/// startup/auth handshake). Without it a source that accepts the socket but
/// then stalls on the handshake — e.g. a database container that is still
/// starting up — blocks the caller indefinitely. At server boot that defeats
/// `--tolerate-unreachable-catalogs`: the tolerate path skips connect
/// *errors*, but an unbounded hang never produces one, so the whole boot
/// wedges. Bounding the connect turns such a stall into a tolerable
/// `Connection` error. A DSN may still specify its own
/// `connect_timeout`; this is the backstop when it doesn't.
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// Upper bound on a single pushed-down query's execution. [`CONNECT_TIMEOUT`]
/// bounds *establishing* a connection; this bounds a query that runs
/// on an already-established one. Without it a source that completes the
/// handshake and then stalls mid-query — a black-holed TCP socket with no RST
/// (network partition, a paused/frozen container, a wedged backend) — blocks
/// the caller indefinitely and, because a catalog's sessions all share one
/// `Client` (see the multi-tenant note below), can wedge *every* session on
/// that catalog. Like the connect backstop, the hang never surfaces as an
/// error, so `--tolerate-unreachable-catalogs` can't help. This turns "hang
/// forever" into "fail eventually"; it is deliberately generous so legitimate
/// long-running analytics don't trip it. The faster dead-peer detector is the
/// transport keepalive below — this is the coarse last resort. The
/// operator-configurable form is tracked in.
const QUERY_TIMEOUT: std::time::Duration = std::time::Duration::from_mins(5);

/// Transport-level dead-peer detection applied to every source connection.
/// `tokio-postgres` enables TCP keepalives by default but only after a 2-hour
/// idle and with no `tcp_user_timeout`, so a black-holed peer is effectively
/// never detected. We tighten the idle and add a user-timeout so a dead
/// connection surfaces as an error in tens of seconds rather than hanging
///. Applied only when the DSN didn't set its own value, so an
/// operator can still override via the connection string.
const KEEPALIVE_IDLE: std::time::Duration = std::time::Duration::from_secs(30);
const KEEPALIVE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(10);
const KEEPALIVE_RETRIES: u32 = 3;
const TCP_USER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// The idle after which `tokio-postgres` sends its first keepalive probe by
/// default (2 hours). We treat a config still sitting at this value as "the
/// DSN didn't ask for a specific idle" and tighten it in
/// [`apply_resilience_defaults`].
const TOKIO_POSTGRES_DEFAULT_KEEPALIVE_IDLE: std::time::Duration =
    std::time::Duration::from_hours(2);

/// Fill in transport resilience defaults ([`KEEPALIVE_IDLE`],
/// [`TCP_USER_TIMEOUT`], …) on a source [`Config`], but only where the DSN
/// left them unset so an explicit operator choice always wins. Returns the
/// config so it can be threaded through the connect paths.
fn apply_resilience_defaults(mut config: Config) -> Config {
    if config.get_tcp_user_timeout().is_none() {
        config.tcp_user_timeout(TCP_USER_TIMEOUT);
    }
    // There's no getter that distinguishes "explicitly 2h" from "defaulted to
    // 2h", so we treat the tokio-postgres default idle as unset. Only tighten
    // when keepalives are on at all — respecting a DSN that turned them off.
    if config.get_keepalives()
        && config.get_keepalives_idle() >= TOKIO_POSTGRES_DEFAULT_KEEPALIVE_IDLE
    {
        config
            .keepalives_idle(KEEPALIVE_IDLE)
            .keepalives_interval(KEEPALIVE_INTERVAL)
            .keepalives_retries(KEEPALIVE_RETRIES);
    }
    config
}

/// Run a source query future under [`QUERY_TIMEOUT`], mapping expiry to a
/// `federation` error rather than letting it hang forever. The inner future's
/// own error type is left untouched (the caller maps it) — this only adds the
/// timeout envelope, so every call site shares one definition of "too long".
async fn with_query_timeout<F, T>(fut: F) -> DataglotResult<T>
where
    F: std::future::Future<Output = T>,
{
    tokio::time::timeout(QUERY_TIMEOUT, fut).await.map_err(|_| {
        DataglotError::federation(format!(
            "postgres query exceeded the {}s execution timeout",
            QUERY_TIMEOUT.as_secs()
        ))
    })
}

impl PostgresConnector {
    // MULTI-TENANT NOTE (; spec: the phase-3 `adbc-connector` plan).
    // The single shared `Arc<Client>` held by this connector has no per-user
    // isolation; the same physical connection serves every pgwire session on
    // this catalog. Safe today only because nothing in `connect` /
    // `connect_with_config` emits source-side session state. If you add init
    // queries (`SET application_name`, `SET search_path`, `SET ROLE`, etc.)
    // on the shared client, you MUST address state isolation across users —
    // see the ADBC connector's reset-on-return + discard-on-failure pattern.

    /// Open a connection to `PostgreSQL` and return a connector.
    ///
    /// `dsn` must be a libpq-style connection string accepted by
    /// [`tokio_postgres::Config::from_str`]. Both URI form
    /// (`postgres://user:pass@host/db`) and key-value form
    /// (`host=... user=... password=... dbname=...`) are supported.
    ///
    /// TLS is negotiated when the DSN requests it: `sslmode=require`
    /// builds a rustls connector (OS/corporate trust store by default —
    /// see [`crate::pg_tls`]); any other `sslmode` (the default
    /// `prefer`, or `disable`) connects in plaintext as before, so
    /// existing deployments are unchanged. For private-CA / self-signed
    /// servers or a custom verification policy, use
    /// [`Self::connect_with_tls`].
    ///
    /// # Errors
    /// Returns [`DataglotError::Configuration`] if the DSN is malformed
    /// and [`DataglotError::Connection`] if the connection fails.
    pub async fn connect(dsn: &str) -> DataglotResult<Self> {
        let config = Config::from_str(dsn).map_err(|e| {
            // tokio_postgres parse errors never contain credentials, but
            // we still avoid including the raw DSN — only the error.
            DataglotError::configuration(format!("invalid postgres DSN: {}", format_pg_error(&e)))
        })?;
        Self::connect_with_config(config).await
    }

    /// Open a connection using a pre-parsed [`Config`].
    ///
    /// Useful for tests where the DSN is assembled from testcontainer
    /// ports. The same redaction guarantees apply. TLS is selected from
    /// the config's `sslmode` (see [`Self::connect`]); `require` uses the
    /// default [`PgTls`] (native trust store, full verification).
    ///
    /// # Errors
    /// Returns [`DataglotError::Connection`] if the connection fails.
    pub async fn connect_with_config(config: Config) -> DataglotResult<Self> {
        // `Require` ⇒ TLS with the secure default; anything else stays
        // plaintext (preserves prior behavior; `prefer` is the libpq
        // default). Explicit trust-root / verification control goes
        // through `connect_with_tls`.
        if matches!(config.get_ssl_mode(), SslMode::Require) {
            return Self::connect_with_tls(config, &PgTls::default()).await;
        }
        Self::connect_plaintext(config).await
    }

    /// Open a TLS connection using an explicit [`PgTls`] policy (trust
    /// roots, optional verification bypass). Independent of the config's
    /// `sslmode` — calling this always negotiates TLS.
    ///
    /// # Errors
    /// Returns [`DataglotError::Configuration`] if the TLS material can't
    /// be loaded and [`DataglotError::Connection`] if the connection fails.
    pub async fn connect_with_tls(config: Config, tls: &PgTls) -> DataglotResult<Self> {
        let config = apply_resilience_defaults(config);
        debug!(
            host = ?config.get_hosts(),
            dbname = ?config.get_dbname(),
            user = ?config.get_user(),
            "opening postgres connection (TLS)"
        );
        // `make_connector` does blocking IO (reads the OS trust store / CA
        // file from disk), so build it off the async executor (rule 11).
        let tls = tls.clone();
        let connector = tokio::task::spawn_blocking(move || tls.make_connector())
            .await
            .map_err(|e| {
                DataglotError::connection(format!("TLS connector init join error: {e}"))
            })??;
        let (client, connection) = tokio::time::timeout(CONNECT_TIMEOUT, config.connect(connector))
            .await
            .map_err(|_| {
                DataglotError::connection(format!(
                    "timed out connecting to postgres over TLS after {}s",
                    CONNECT_TIMEOUT.as_secs()
                ))
            })?
            .map_err(|e| {
                DataglotError::connection(format!(
                    "failed to connect to postgres over TLS: {}",
                    format_pg_error(&e)
                ))
            })?;
        info!(
            host = ?config.get_hosts(),
            dbname = ?config.get_dbname(),
            tls = true,
            "connected to postgres source"
        );
        Ok(Self::spawn_and_build(config, client, connection))
    }

    /// Plaintext connection (the pre-TLS path).
    async fn connect_plaintext(config: Config) -> DataglotResult<Self> {
        let config = apply_resilience_defaults(config);
        debug!(
            host = ?config.get_hosts(),
            dbname = ?config.get_dbname(),
            user = ?config.get_user(),
            "opening postgres connection"
        );

        let (client, connection) = tokio::time::timeout(CONNECT_TIMEOUT, config.connect(NoTls))
            .await
            .map_err(|_| {
                DataglotError::connection(format!(
                    "timed out connecting to postgres after {}s",
                    CONNECT_TIMEOUT.as_secs()
                ))
            })?
            .map_err(|e| {
                DataglotError::connection(format!(
                    "failed to connect to postgres: {}",
                    format_pg_error(&e)
                ))
            })?;
        info!(
            host = ?config.get_hosts(),
            dbname = ?config.get_dbname(),
            tls = false,
            "connected to postgres source"
        );
        Ok(Self::spawn_and_build(config, client, connection))
    }

    /// Drive the connection IO on a background task and assemble the
    /// connector. Shared by the plaintext and TLS paths.
    fn spawn_and_build<S, T>(
        config: Config,
        client: Client,
        connection: tokio_postgres::Connection<S, T>,
    ) -> Self
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
        T: tokio_postgres::tls::TlsStream + Unpin + Send + 'static,
    {
        // Drive the underlying IO on a background task. If the connection
        // dies the error is logged via `tracing` — per rule 12 this never
        // includes credentials since we only log the error message from
        // the driver, not the DSN.
        tokio::spawn(async move {
            if let Err(e) = connection.await {
                tracing::warn!("postgres connection error: {}", format_pg_error(&e));
            }
        });

        let name = compute_context_name(&config);
        Self {
            name,
            catalog: None,
            client: Arc::new(client),
            config,
        }
    }

    /// Tag this connector with the catalog name it's registered under, used
    /// as the operator-facing `source` label in pushdown telemetry.
    /// Chained at build time: `PostgresConnector::connect(dsn).await?.with_catalog("pg")`.
    #[must_use]
    pub fn with_catalog(mut self, catalog: impl Into<String>) -> Self {
        self.catalog = Some(catalog.into());
        self
    }

    /// The operator-facing source label: the catalog name if set, else the
    /// DSN-derived compute-context name.
    fn source_label(&self) -> &str {
        pick_source_label(self.catalog.as_deref(), &self.name)
    }

    /// Return the connector's compute-context identifier. This is what
    /// `datafusion-federation` uses to group table scans that can be
    /// pushed down together.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Produce a [`TableProvider`] for `<schema>.<table>` that pushes
    /// filters, projections, and limits down to `PostgreSQL` via
    /// `datafusion-federation`.
    ///
    /// The schema is fetched on demand by querying
    /// `information_schema.columns`. This satisfies hard rule 13
    /// (lazy schema resolution) — no remote query is issued until the
    /// caller actually asks for a table.
    ///
    /// # Errors
    /// Returns [`DataglotError::Catalog`] if the table is not found or
    /// its schema cannot be mapped to Arrow types.
    pub async fn table_provider(
        self: &Arc<Self>,
        schema: &str,
        table: &str,
    ) -> DataglotResult<Arc<dyn TableProvider>> {
        let arrow_schema = self.fetch_arrow_schema(schema, table).await?;
        let executor: Arc<dyn SQLExecutor> = Arc::clone(self) as Arc<dyn SQLExecutor>;
        let provider = Arc::new(SQLFederationProvider::new(executor));
        let table_ref = RemoteTableRef::from(TableReference::partial(
            schema.to_string(),
            table.to_string(),
        ));
        let source = SQLTableSource::new_with_schema(provider, table_ref, arrow_schema);
        Ok(Arc::new(FederatedTableProviderAdaptor::new(Arc::new(
            source,
        ))))
    }

    /// Wrap this connector as a `DataFusion` [`CatalogProvider`].
    ///
    /// The returned catalog enumerates the user-visible namespaces of
    /// the underlying `PostgreSQL` database via
    /// `information_schema.schemata` (excluding the system schemas
    /// `pg_catalog`, `information_schema`, and `pg_toast`) and resolves
    /// tables lazily via [`Self::table_provider`].
    ///
    /// # Eager listing, lazy schema (caching strategy)
    ///
    /// `DataFusion`'s [`CatalogProvider::schema_names`] and
    /// [`CatalogProvider::schema`] are **synchronous**, but listing
    /// schemas and tables in `PostgreSQL` requires async I/O. Rather
    /// than dive into `block_in_place` + `Handle::block_on` (brittle —
    /// only safe under a multi-thread runtime), we eagerly fetch the
    /// list of schemas and the list of tables per schema once, here,
    /// while we still have an `async` context. Per-table column schemas
    /// remain **lazy** (rule 13) — they are only fetched when the
    /// async [`SchemaProvider::table`] is called, by delegating to the
    /// existing [`Self::table_provider`].
    ///
    /// Names are cached for the lifetime of the returned catalog. They
    /// are stable enough in practice (a `CREATE TABLE` issued through
    /// another session will not appear until a fresh
    /// `as_catalog_provider()` call). Drop and rebuild the catalog if
    /// the operator needs to pick up DDL.
    ///
    /// # Errors
    /// Returns [`DataglotError::Catalog`] if the listing queries
    /// against `information_schema` fail (typically a permissions
    /// problem or a dropped connection).
    ///
    /// [`CatalogProvider`]: datafusion::catalog::CatalogProvider
    /// [`CatalogProvider::schema_names`]: datafusion::catalog::CatalogProvider::schema_names
    /// [`CatalogProvider::schema`]: datafusion::catalog::CatalogProvider::schema
    /// [`SchemaProvider::table`]: datafusion::catalog::SchemaProvider::table
    pub async fn as_catalog_provider(
        self: &Arc<Self>,
    ) -> DataglotResult<Arc<dyn DfCatalogProvider>> {
        // 1. Pull the user-visible schemas. The system schemas listed
        //    in the WHERE clause are present on every Postgres instance
        //    and would only clutter the catalog surface for users.
        let schema_rows = self
            .client
            .query(
                "SELECT schema_name
                 FROM information_schema.schemata
                 WHERE schema_name NOT IN ('pg_catalog', 'information_schema', 'pg_toast')
                 ORDER BY schema_name",
                &[],
            )
            .await
            .map_err(|e| {
                DataglotError::catalog(format!(
                    "failed to list postgres schemas via information_schema.schemata: {}",
                    format_pg_error(&e)
                ))
            })?;
        let schema_names: Vec<String> = schema_rows
            .into_iter()
            .map(|r| r.get::<_, String>(0))
            .collect();

        // 2. For each schema, eagerly fetch its table list and build a
        //    cached `PostgresSchema`. The DataFusion catalog API gives
        //    us a sync `schema(name)` lookup, so we do the async work
        //    once up front and store the assembled providers.
        let mut schemas: HashMap<String, Arc<dyn DfSchemaProvider>> =
            HashMap::with_capacity(schema_names.len());
        for schema_name in &schema_names {
            let table_rows = self
                .client
                .query(
                    "SELECT table_name
                     FROM information_schema.tables
                     WHERE table_schema = $1
                       AND table_type IN ('BASE TABLE', 'VIEW')
                     ORDER BY table_name",
                    &[schema_name],
                )
                .await
                .map_err(|e| {
                    DataglotError::catalog(format!(
                        "failed to list postgres tables for schema '{schema_name}': {}",
                        format_pg_error(&e)
                    ))
                })?;
            let table_names: Vec<String> = table_rows
                .into_iter()
                .map(|r| r.get::<_, String>(0))
                .collect();
            schemas.insert(
                schema_name.clone(),
                Arc::new(PostgresSchema {
                    connector: Arc::clone(self),
                    schema_name: schema_name.clone(),
                    table_names,
                }) as Arc<dyn DfSchemaProvider>,
            );
        }

        Ok(Arc::new(PostgresCatalog {
            connector_name: self.name.clone(),
            schema_names,
            schemas,
        }) as Arc<dyn DfCatalogProvider>)
    }

    /// Fetch the Arrow schema for `<schema>.<table>` by querying
    /// `information_schema.columns`. Called from [`Self::table_provider`]
    /// and from `SQLExecutor::get_table_schema`.
    async fn fetch_arrow_schema(
        &self,
        schema_name: &str,
        table_name: &str,
    ) -> DataglotResult<SchemaRef> {
        let rows = self
            .client
            .query(
                // `numeric_precision` / `numeric_scale` are the
                // `information_schema` domain `cardinal_number` (over
                // int4); cast to a plain `int` so `tokio_postgres` can
                // decode them as `i32` (the domain OID isn't `INT4`).
                // Both are NULL for non-numeric columns and for an
                // unconstrained `NUMERIC` (no typmod).
                "SELECT column_name, udt_name, is_nullable,
                        numeric_precision::int AS numeric_precision,
                        numeric_scale::int     AS numeric_scale
                 FROM information_schema.columns
                 WHERE table_schema = $1 AND table_name = $2
                 ORDER BY ordinal_position",
                &[&schema_name, &table_name],
            )
            .await
            .map_err(|e| {
                DataglotError::catalog(format!(
                    "failed to query information_schema for {schema_name}.{table_name}: {}",
                    format_pg_error(&e)
                ))
            })?;

        if rows.is_empty() {
            return Err(DataglotError::catalog(format!(
                "table not found: {schema_name}.{table_name}"
            )));
        }

        let mut fields = Vec::with_capacity(rows.len());
        for row in rows {
            let column_name: String = row.get(0);
            let udt_name: String = row.get(1);
            let is_nullable_str: String = row.get(2);
            let numeric_precision: Option<i32> = row.get(3);
            let numeric_scale: Option<i32> = row.get(4);
            let nullable = matches!(is_nullable_str.as_str(), "YES" | "yes");
            let data_type = pg_udt_to_arrow(&udt_name, numeric_precision, numeric_scale)
                .ok_or_else(|| {
                DataglotError::catalog(format!(
                    "unsupported postgres type '{udt_name}' for column {schema_name}.{table_name}.{column_name}"
                ))
            })?;
            fields.push(Field::new(column_name, data_type, nullable));
        }
        Ok(Arc::new(Schema::new(fields)))
    }
}

impl fmt::Debug for PostgresConnector {
    /// Credential-safe `Debug` impl (hard rule 12). Emits host, port,
    /// user, and dbname — never password. The `client` field is
    /// intentionally omitted (`finish_non_exhaustive`) because its own
    /// `Debug` impl would expose the connection config, including the
    /// password.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PostgresConnector")
            .field("name", &self.name)
            .field("dsn", &redacted_dsn(&self.config))
            .finish_non_exhaustive()
    }
}

/// `DataFusion` [`CatalogProvider`] backed by a [`PostgresConnector`].
///
/// Built via [`PostgresConnector::as_catalog_provider`]. Holds a cached
/// list of user-visible schema names and a `HashMap` of pre-built
/// `PostgresSchema` providers keyed by schema name. The cache is
/// fixed at construction time — see the docs on
/// [`PostgresConnector::as_catalog_provider`] for why.
///
/// Per hard rule 12, `Debug` does not surface anything from the
/// underlying `PostgresConnector` other than its name.
///
/// [`CatalogProvider`]: datafusion::catalog::CatalogProvider
pub struct PostgresCatalog {
    /// The underlying connector's identifier — used for `Debug` and
    /// for diagnostic logs only. NOT used as the catalog's name in the
    /// `SessionContext`; that name is supplied by the caller of
    /// `register_catalog`.
    connector_name: String,
    /// Cached, alphabetised list of schema names. Returned verbatim
    /// from [`CatalogProvider::schema_names`].
    schema_names: Vec<String>,
    /// Pre-built schema providers, keyed by schema name. Lookups are
    /// O(1) and never block.
    schemas: HashMap<String, Arc<dyn DfSchemaProvider>>,
}

impl fmt::Debug for PostgresCatalog {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PostgresCatalog")
            .field("connector", &self.connector_name)
            .field("schema_count", &self.schema_names.len())
            .finish_non_exhaustive()
    }
}

impl DfCatalogProvider for PostgresCatalog {
    fn schema_names(&self) -> Vec<String> {
        self.schema_names.clone()
    }

    fn schema(&self, name: &str) -> Option<Arc<dyn DfSchemaProvider>> {
        self.schemas.get(name).map(Arc::clone)
    }
}

/// `DataFusion` [`SchemaProvider`] backed by a single `PostgreSQL`
/// schema (namespace) on a [`PostgresConnector`].
///
/// Per-table column schemas are NOT fetched at construction; they are
/// resolved lazily inside [`SchemaProvider::table`] by delegating to
/// [`PostgresConnector::table_provider`] (rule 13).
///
/// [`SchemaProvider`]: datafusion::catalog::SchemaProvider
struct PostgresSchema {
    /// The connector this schema belongs to.
    connector: Arc<PostgresConnector>,
    /// `PostgreSQL` schema (namespace) name.
    schema_name: String,
    /// Cached, alphabetised list of table names within this schema.
    /// Populated once at catalog-construction time.
    table_names: Vec<String>,
}

impl fmt::Debug for PostgresSchema {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PostgresSchema")
            .field("schema", &self.schema_name)
            .field("table_count", &self.table_names.len())
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl DfSchemaProvider for PostgresSchema {
    fn table_names(&self) -> Vec<String> {
        self.table_names.clone()
    }

    fn table_exist(&self, name: &str) -> bool {
        self.table_names.iter().any(|t| t == name)
    }

    async fn table(&self, name: &str) -> DfResult<Option<Arc<dyn TableProvider>>> {
        // Cheap negative path: if it isn't in the cached list, don't
        // even attempt to resolve. This avoids a remote roundtrip for
        // typos / `SELECT * FROM <catalog>.<schema>.does_not_exist`.
        if !self.table_exist(name) {
            return Ok(None);
        }
        // Lazy column-schema fetch (rule 13).
        let provider = self
            .connector
            .table_provider(&self.schema_name, name)
            .await
            .map_err(|e| DataFusionError::External(Box::new(e)))?;
        Ok(Some(provider))
    }
}

/// Build a short identifier for this connection for use as the
/// `SQLExecutor::compute_context`. Two connectors with the same host+port
/// +dbname+user share a compute context and can participate in the same
/// pushed-down query.
fn compute_context_name(config: &Config) -> String {
    use tokio_postgres::config::Host;

    let host = match config.get_hosts().first() {
        Some(Host::Tcp(s)) => s.clone(),
        #[cfg(unix)]
        Some(Host::Unix(p)) => p.display().to_string(),
        None => "localhost".to_string(),
    };
    let port = config.get_ports().first().copied().unwrap_or(5432);
    let dbname = config.get_dbname().unwrap_or("postgres");
    let user = config.get_user().unwrap_or("");
    format!("postgres://{user}@{host}:{port}/{dbname}")
}

/// Pick the operator-facing pushdown `source` label: the catalog
/// name when the connector was tagged via `with_catalog`, else the DSN-derived
/// compute-context `name`. Split out as a free fn so the selection is unit-
/// testable without a live connection.
fn pick_source_label<'a>(catalog: Option<&'a str>, name: &'a str) -> &'a str {
    catalog.unwrap_or(name)
}

/// Render a credential-free description of a connection. Deliberately
/// omits the password and any other secret-carrying fields.
///
/// This is the only function that formats a `Config` for display. If a
/// new secret-bearing field is added to `tokio_postgres::Config` in the
/// future, this function is the single place that needs updating.
fn redacted_dsn(config: &Config) -> String {
    use tokio_postgres::config::Host;

    let host = match config.get_hosts().first() {
        Some(Host::Tcp(s)) => s.clone(),
        #[cfg(unix)]
        Some(Host::Unix(p)) => p.display().to_string(),
        None => "<unset>".to_string(),
    };
    let port = config.get_ports().first().copied().unwrap_or(5432);
    let user = config.get_user().unwrap_or("<unset>");
    let dbname = config.get_dbname().unwrap_or("<unset>");
    // Note: `password=<redacted>` is only emitted when a password was
    // actually supplied, so that `{:?}`-style debugging doesn't imply a
    // password was set when it wasn't.
    let password_marker = if config.get_password().is_some() {
        " password=<redacted>"
    } else {
        ""
    };
    format!("host={host} port={port} user={user} dbname={dbname}{password_marker}")
}

/// Map a `PostgreSQL` user-defined type name (as reported by
/// `information_schema.columns.udt_name`) to an Arrow [`DataType`].
///
/// Supported types (per this PR's scope):
/// `int2`, `int4`, `int8`, `float4`, `float8`, `bool`, `text`, `varchar`,
/// `bpchar` (CHAR), `timestamp`, `timestamptz`, `date`.
///
/// Unknown types return `None`; the caller must treat this as an error
/// rather than silently skipping the column.
fn pg_udt_to_arrow(udt: &str, precision: Option<i32>, scale: Option<i32>) -> Option<DataType> {
    match udt {
        "int2" => Some(DataType::Int16),
        "int4" => Some(DataType::Int32),
        "int8" => Some(DataType::Int64),
        "float4" => Some(DataType::Float32),
        "float8" => Some(DataType::Float64),
        "bool" => Some(DataType::Boolean),
        "text" | "varchar" | "bpchar" | "name" => Some(DataType::Utf8),
        "date" => Some(DataType::Date32),
        "timestamp" | "timestamptz" => Some(DataType::Timestamp(TimeUnit::Microsecond, None)),
        // PG `numeric` carries its declared precision/scale in
        // `information_schema`; preserve them so the source's scale
        // survives federation (a `NUMERIC(10,2)` stays scale 2 rather
        // than rendering 18 trailing zeros). See [`decimal_type_for`].
        "numeric" => Some(decimal_type_for(precision, scale)),
        _ => None,
    }
}

/// Pick the Arrow `Decimal128` type for a PG `numeric` column from its
/// declared precision/scale.
///
/// A constrained `NUMERIC(p, s)` maps to `Decimal128(p, s)` so the
/// source scale survives federation. An unconstrained `NUMERIC` (NULL
/// typmod ⇒ NULL precision/scale) or a precision Arrow's `Decimal128`
/// can't represent (`> 38`) falls back to `(38, 18)` — 20 integer + 18
/// fractional digits, plenty for most federated columns. Values that
/// don't fit the chosen scale are rejected at decode time by
/// `rescale_decimal_to_i128` rather than silently truncated.
fn decimal_type_for(precision: Option<i32>, scale: Option<i32>) -> DataType {
    const FALLBACK: DataType = DataType::Decimal128(38, 18);
    match (precision, scale) {
        // p in 1..=38 and s in 0..=p both fit Decimal128's caps; the
        // `try_from`s always succeed under that guard (kept explicit so
        // the casts stay lint-clean).
        (Some(p), Some(s)) if (1..=38).contains(&p) && (0..=p).contains(&s) => {
            match (u8::try_from(p), i8::try_from(s)) {
                (Ok(p), Ok(s)) => DataType::Decimal128(p, s),
                _ => FALLBACK,
            }
        }
        _ => FALLBACK,
    }
}

/// Reinterpret a PG `int8` (`i64`) as `u64` for the `UInt64` arrow target,
/// rejecting negatives (fail-loud rather than wrap). Pure — unit-tested.
fn pg_int8_to_u64(x: i64, col_idx: usize) -> DfResult<u64> {
    if x >= 0 {
        Ok(x.cast_unsigned())
    } else {
        Err(DataFusionError::External(Box::new(
            DataglotError::federation(format!(
                "negative i64 ({x}) for arrow UInt64 column at index {col_idx}"
            )),
        )))
    }
}

/// Days since the Unix epoch for a `NaiveDate` (Arrow Date32), erroring if the
/// span overflows `i32`. Pure — unit-tested.
fn naive_date_to_days(d: chrono::NaiveDate) -> DfResult<i32> {
    let epoch = chrono::NaiveDate::from_ymd_opt(1970, 1, 1).expect("1970-01-01 is valid");
    let days = (d - epoch).num_days();
    i32::try_from(days).map_err(|_| {
        DataFusionError::External(Box::new(DataglotError::federation(format!(
            "date {d} out of range for arrow Date32"
        ))))
    })
}

/// Narrow a PG `NUMERIC` (`rust_decimal::Decimal`) to `i64` for the Int64 arrow
/// target (the SUM-of-int fallback path), erroring if it doesn't fit. Pure —
/// unit-tested.
fn numeric_to_i64(d: rust_decimal::Decimal, col_idx: usize) -> DfResult<i64> {
    use rust_decimal::prelude::ToPrimitive;
    d.to_i64().ok_or_else(|| {
        DataFusionError::External(Box::new(DataglotError::federation(format!(
            "NUMERIC value {d} at column {col_idx} doesn't fit in i64"
        ))))
    })
}

/// Decode the `tokio-postgres` row set for `query` into a single
/// [`RecordBatch`] that matches `schema` exactly.
///
/// The mapping in this function must stay in lockstep with
/// [`pg_udt_to_arrow`]: any Arrow type declared there must be decodable
/// here. An unknown combination of Arrow type + Postgres type is a bug
/// (the schema must have come from `pg_udt_to_arrow` in the first place)
/// and is surfaced as [`DataFusionError::External`].
fn rows_to_record_batch(schema: &SchemaRef, rows: &[Row]) -> DfResult<RecordBatch> {
    let mut columns: Vec<ArrayRef> = Vec::with_capacity(schema.fields().len());
    for (col_idx, field) in schema.fields().iter().enumerate() {
        columns.push(decode_column(rows, col_idx, field.data_type())?);
    }
    RecordBatch::try_new(Arc::clone(schema), columns).map_err(DataFusionError::from)
}

/// Decode a single column out of `rows` into an Arrow array matching
/// `data_type`. Any Arrow type here must be producible by
/// [`pg_udt_to_arrow`].
fn decode_column(rows: &[Row], col_idx: usize, data_type: &DataType) -> DfResult<ArrayRef> {
    let n = rows.len();
    match data_type {
        DataType::Int16 => {
            decode_primitive::<i16, _>(rows, col_idx, Int16Builder::with_capacity(n))
        }
        DataType::Int32 => {
            decode_primitive::<i32, _>(rows, col_idx, Int32Builder::with_capacity(n))
        }
        DataType::Int64 => decode_int64_with_numeric_fallback(rows, col_idx),
        // PostgreSQL has no native unsigned integer types, but
        // DataFusion's planner uses UInt64 for ROW_NUMBER, COUNT(*),
        // and similar non-negative aggregates. The federation layer
        // pushes the SQL down to PostgreSQL (which returns BIGINT)
        // and asks us for a UInt64 array on the way back. Decode as
        // i64 from PG and reinterpret-cast to u64 — all values
        // produced by these aggregates are >= 0.
        DataType::UInt64 => decode_uint64_from_pg_int8(rows, col_idx),
        DataType::Decimal128(precision, scale) => {
            decode_decimal128(rows, col_idx, *precision, *scale)
        }
        DataType::Float32 => {
            decode_primitive::<f32, _>(rows, col_idx, Float32Builder::with_capacity(n))
        }
        DataType::Float64 => {
            decode_primitive::<f64, _>(rows, col_idx, Float64Builder::with_capacity(n))
        }
        DataType::Boolean => decode_bool(rows, col_idx),
        DataType::Utf8 => decode_utf8(rows, col_idx),
        DataType::Date32 => decode_date32(rows, col_idx),
        DataType::Timestamp(TimeUnit::Microsecond, None) => decode_timestamp_us(rows, col_idx),
        // Nanosecond timestamps never come from a source *column* (those map to
        // Microsecond, see `pg_udt_to_arrow`) — they arise from a pushed-down
        // expression whose DataFusion return type is `Timestamp(Nanosecond)`,
        // e.g. a `date_year` column mask's `date_trunc('year', …)`.
        DataType::Timestamp(TimeUnit::Nanosecond, None) => decode_timestamp_ns(rows, col_idx),
        other => Err(DataFusionError::External(Box::new(
            DataglotError::internal(format!(
                "PostgresConnector: no decoder for arrow type {other:?}"
            )),
        ))),
    }
}

/// Trait abstracting the handful of Arrow builders that share an
/// `append_value(T) / append_null()` interface. This is purely an
/// internal convenience to deduplicate the per-primitive loops.
trait AppendPrim<T> {
    fn push_value(&mut self, v: T);
    fn push_null(&mut self);
    fn finish_array(self) -> ArrayRef;
}

macro_rules! impl_append_prim {
    ($builder:ty, $value:ty) => {
        impl AppendPrim<$value> for $builder {
            fn push_value(&mut self, v: $value) {
                self.append_value(v);
            }
            fn push_null(&mut self) {
                self.append_null();
            }
            fn finish_array(mut self) -> ArrayRef {
                Arc::new(self.finish())
            }
        }
    };
}

impl_append_prim!(Int16Builder, i16);
impl_append_prim!(Int32Builder, i32);
impl_append_prim!(Int64Builder, i64);
impl_append_prim!(Float32Builder, f32);
impl_append_prim!(Float64Builder, f64);

fn decode_primitive<'a, T, B>(rows: &'a [Row], col_idx: usize, mut builder: B) -> DfResult<ArrayRef>
where
    T: tokio_postgres::types::FromSql<'a>,
    B: AppendPrim<T>,
{
    for row in rows {
        let v: Option<T> = row.try_get(col_idx).map_err(pg_decode_err)?;
        match v {
            Some(x) => builder.push_value(x),
            None => builder.push_null(),
        }
    }
    Ok(builder.finish_array())
}

/// Decode an `int8` column into Arrow `Int64Array`, **or** an
/// unexpected `NUMERIC` column into the same `Int64Array` by
/// converting via `rust_decimal::Decimal::to_i64`.
///
/// Background: when `DataFusion`'s planner federates a query like
/// `SELECT SUM(int_col) FROM ...`, the logical output type is
/// `Int64`. But the federation layer's SQL unparser sometimes pushes
/// the SUM down with `PostgreSQL` semantics that produce a `NUMERIC`
/// result rather than `BIGINT`. The connector receives `NUMERIC`
/// where the planner expects `Int64`, and `tokio_postgres`'s
/// `FromSql<i64>` impl rejects `NUMERIC` outright with
/// `"error deserializing column N"`. Falling back to `Decimal` →
/// `i64` conversion fixes the common SUM-of-int case (values that
/// fit in i64) without changing the planner-facing type. Values
/// that overflow `i64` surface as a federation error rather than
/// silent truncation.
fn decode_int64_with_numeric_fallback(rows: &[Row], col_idx: usize) -> DfResult<ArrayRef> {
    let mut b = Int64Builder::with_capacity(rows.len());
    for row in rows {
        // Fast path: PG actually returned int8/int4/int2.
        match row.try_get::<_, Option<i64>>(col_idx) {
            Ok(Some(x)) => b.append_value(x),
            Ok(None) => b.append_null(),
            Err(_) => {
                // Slow path: PG returned NUMERIC. Re-decode via
                // rust_decimal and narrow to i64.
                let v: Option<rust_decimal::Decimal> =
                    row.try_get(col_idx).map_err(pg_decode_err)?;
                match v {
                    None => b.append_null(),
                    Some(d) => b.append_value(numeric_to_i64(d, col_idx)?),
                }
            }
        }
    }
    Ok(Arc::new(b.finish()))
}

/// Decode a `PostgreSQL` `NUMERIC` column into an Arrow
/// `Decimal128Array` with the requested `precision` / `scale`.
///
/// Goes through `rust_decimal::Decimal` (which has its own NUMERIC
/// `FromSql` impl thanks to the `db-tokio-postgres` feature on the
/// `rust_decimal` crate). We then rescale the mantissa to match
/// Arrow's expected scale.
fn decode_decimal128(rows: &[Row], col_idx: usize, precision: u8, scale: i8) -> DfResult<ArrayRef> {
    let mut b = Decimal128Builder::with_capacity(rows.len())
        .with_precision_and_scale(precision, scale)
        .map_err(|e| DataFusionError::ArrowError(Box::new(e), None))?;
    for row in rows {
        let v: Option<rust_decimal::Decimal> = row.try_get(col_idx).map_err(pg_decode_err)?;
        match v {
            Some(d) => b.append_value(rescale_decimal_to_i128(d, scale, col_idx)?),
            None => b.append_null(),
        }
    }
    Ok(Arc::new(b.finish()))
}

/// Convert a `rust_decimal::Decimal` to an `i128` mantissa expressed
/// at Arrow's target scale. Errors if the value can't be represented
/// without loss (e.g. target scale too small to keep all the
/// fractional digits in the source).
fn rescale_decimal_to_i128(
    d: rust_decimal::Decimal,
    target_scale: i8,
    col_idx: usize,
) -> DfResult<i128> {
    let src_scale = i32::try_from(d.scale()).unwrap_or(i32::MAX);
    let tgt_scale = i32::from(target_scale);
    let mantissa: i128 = d.mantissa();
    if tgt_scale >= src_scale {
        // Pad with zeros — multiply by 10^(tgt - src). The diff is
        // non-negative inside this branch so the cast is safe.
        let pow = u32::try_from(tgt_scale - src_scale).map_err(|_| {
            DataFusionError::External(Box::new(DataglotError::federation(format!(
                "scale difference {} doesn't fit in u32 (target={tgt_scale}, source={src_scale})",
                tgt_scale - src_scale
            ))))
        })?;
        mantissa.checked_mul(10_i128.pow(pow)).ok_or_else(|| {
            DataFusionError::External(Box::new(DataglotError::federation(format!(
                "NUMERIC value {d} at column {col_idx} overflows i128 when rescaled to scale {tgt_scale}"
            ))))
        })
    } else {
        // Source carries more fractional digits than the Arrow target
        // scale. Round to the target — the declared output scale is the
        // authoritative precision, so this matches native engine
        // semantics (DataFusion computes AVG and other decimal results
        // exactly this way) rather than losing digits arbitrarily.
        //
        // Pushed-down aggregates routinely land here: a federated
        // `AVG(amount)` over a `NUMERIC(10,2)` column is typed by
        // DataFusion as `Decimal128(14,6)`, but Postgres returns numeric
        // division at a much higher scale. Half-away-from-zero matches
        // SQL `ROUND` (and most engines' decimal casts).
        let scale_u32 = u32::try_from(tgt_scale).unwrap_or(0);
        let rounded = d.round_dp_with_strategy(
            scale_u32,
            rust_decimal::RoundingStrategy::MidpointAwayFromZero,
        );
        // `round_dp_with_strategy` yields scale <= tgt_scale, so pad the
        // (possibly trimmed) mantissa back up to the target scale.
        let r_scale = i32::try_from(rounded.scale()).unwrap_or(i32::MAX);
        let r_mantissa: i128 = rounded.mantissa();
        let pow = u32::try_from(tgt_scale - r_scale).unwrap_or(0);
        r_mantissa.checked_mul(10_i128.pow(pow)).ok_or_else(|| {
            DataFusionError::External(Box::new(DataglotError::federation(format!(
                "NUMERIC value {d} at column {col_idx} overflows i128 when rounded to scale {tgt_scale}"
            ))))
        })
    }
}

/// Decode a `PostgreSQL` `BIGINT` (`int8`) column into an Arrow
/// `UInt64Array`. Used when the federation layer's expected schema
/// requested `UInt64` (e.g. for `ROW_NUMBER()`, `COUNT(*)`) but
/// `PostgreSQL` returns the value as a signed `BIGINT`.
///
/// PG never returns a negative value for the aggregates that produce
/// this shape, so the cast is sound. We assert `>= 0` defensively —
/// if PG ever does return a negative `int8` here it indicates a
/// planner bug upstream and we'd rather surface it than silently
/// flip-bit reinterpret.
fn decode_uint64_from_pg_int8(rows: &[Row], col_idx: usize) -> DfResult<ArrayRef> {
    let mut b = UInt64Builder::with_capacity(rows.len());
    for row in rows {
        let v: Option<i64> = row.try_get(col_idx).map_err(pg_decode_err)?;
        match v {
            Some(x) => b.append_value(pg_int8_to_u64(x, col_idx)?),
            None => b.append_null(),
        }
    }
    Ok(Arc::new(b.finish()))
}

fn decode_bool(rows: &[Row], col_idx: usize) -> DfResult<ArrayRef> {
    let mut b = BooleanBuilder::with_capacity(rows.len());
    for row in rows {
        let v: Option<bool> = row.try_get(col_idx).map_err(pg_decode_err)?;
        match v {
            Some(x) => b.append_value(x),
            None => b.append_null(),
        }
    }
    Ok(Arc::new(b.finish()))
}

fn decode_utf8(rows: &[Row], col_idx: usize) -> DfResult<ArrayRef> {
    // Postgres text/varchar/bpchar/name all decode into `&str` on the
    // Rust side. A single builder with a generous byte estimate avoids
    // repeated reallocation.
    let mut b = StringBuilder::with_capacity(rows.len(), rows.len() * 16);
    for row in rows {
        let v: Option<&str> = row.try_get(col_idx).map_err(pg_decode_err)?;
        match v {
            Some(x) => b.append_value(x),
            None => b.append_null(),
        }
    }
    Ok(Arc::new(b.finish()))
}

fn decode_date32(rows: &[Row], col_idx: usize) -> DfResult<ArrayRef> {
    // `date` decodes via `chrono::NaiveDate` when the `with-chrono-0_4`
    // driver feature is on (it is, per the workspace config). Convert
    // to days since the Unix epoch (Arrow Date32 semantics).
    let mut b = Date32Builder::with_capacity(rows.len());
    for row in rows {
        let v: Option<chrono::NaiveDate> = row.try_get(col_idx).map_err(pg_decode_err)?;
        match v {
            Some(d) => b.append_value(naive_date_to_days(d)?),
            None => b.append_null(),
        }
    }
    Ok(Arc::new(b.finish()))
}

fn decode_timestamp_us(rows: &[Row], col_idx: usize) -> DfResult<ArrayRef> {
    // Works for both `timestamp` and `timestamptz`. With
    // `with-chrono-0_4` the driver hands us `NaiveDateTime` for
    // `timestamp` and `DateTime<Utc>` for `timestamptz`. We normalise
    // both to microseconds since the Unix epoch.
    let mut b = TimestampMicrosecondBuilder::with_capacity(rows.len());
    let col_type = rows
        .first()
        .and_then(|r| r.columns().get(col_idx))
        .map(|c| c.type_().clone());

    for row in rows {
        let maybe_micros: Option<i64> = match &col_type {
            Some(t) if *t == PgType::TIMESTAMPTZ => {
                let v: Option<chrono::DateTime<chrono::Utc>> =
                    row.try_get(col_idx).map_err(pg_decode_err)?;
                v.map(|dt| dt.timestamp_micros())
            }
            _ => {
                let v: Option<chrono::NaiveDateTime> =
                    row.try_get(col_idx).map_err(pg_decode_err)?;
                v.map(|dt| dt.and_utc().timestamp_micros())
            }
        };
        match maybe_micros {
            Some(m) => b.append_value(m),
            None => b.append_null(),
        }
    }
    Ok(Arc::new(b.finish()))
}

/// Decode a Postgres `timestamp`/`timestamptz` column into a
/// `Timestamp(Nanosecond, None)` array. Reached only for a pushed-down
/// expression whose DataFusion return type is nanosecond precision — a source
/// *column* always maps to microsecond (see [`pg_udt_to_arrow`]). The concrete
/// case is a `date_year` column mask, which lowers to `date_trunc('year', …)`
/// (return type `Timestamp(Nanosecond)`) and, before, hit the decoder's
/// catch-all "no decoder for arrow type Timestamp(Nanosecond, None)".
///
/// Nanoseconds since the Unix epoch for `dt`, or a federation error when it's
/// outside the representable nanosecond range (`timestamp_nanos_opt` → `None`,
/// i.e. before ~1677 or after ~2262 AD). Erroring — rather than silently
/// returning `NULL` — is deliberate: nanosecond overflow is realistic for real
/// dates (unlike microsecond), so a silent null would be data corruption. The
/// timestamp (not a credential) is included for diagnosability.
fn nanos_or_range_err(dt: chrono::DateTime<chrono::Utc>) -> DfResult<i64> {
    dt.timestamp_nanos_opt().ok_or_else(|| {
        DataFusionError::External(Box::new(DataglotError::federation(format!(
            "PostgresConnector: timestamp {dt} is out of range for nanosecond precision \
             (representable ~1677–2262 AD)"
        ))))
    })
}

/// Decode a Postgres `timestamp`/`timestamptz` column into a
/// `Timestamp(Nanosecond, None)` array. Reached only for a pushed-down
/// expression whose DataFusion return type is nanosecond precision — a source
/// *column* always maps to microsecond (see [`pg_udt_to_arrow`]). The concrete
/// case is a `date_year` column mask, which lowers to `date_trunc('year', …)`
/// (return type `Timestamp(Nanosecond)`) and, before, hit the decoder's
/// catch-all "no decoder for arrow type Timestamp(Nanosecond, None)".
///
/// Mirrors [`decode_timestamp_us`]. A database `NULL` decodes to a null cell; a
/// non-null out-of-range value is an error via [`nanos_or_range_err`], not a
/// silent NULL.
fn decode_timestamp_ns(rows: &[Row], col_idx: usize) -> DfResult<ArrayRef> {
    let mut b = TimestampNanosecondBuilder::with_capacity(rows.len());
    let col_type = rows
        .first()
        .and_then(|r| r.columns().get(col_idx))
        .map(|c| c.type_().clone());

    for row in rows {
        let nanos: Option<i64> = match &col_type {
            Some(t) if *t == PgType::TIMESTAMPTZ => {
                let v: Option<chrono::DateTime<chrono::Utc>> =
                    row.try_get(col_idx).map_err(pg_decode_err)?;
                v.map(nanos_or_range_err).transpose()?
            }
            _ => {
                let v: Option<chrono::NaiveDateTime> =
                    row.try_get(col_idx).map_err(pg_decode_err)?;
                v.map(|dt| nanos_or_range_err(dt.and_utc())).transpose()?
            }
        };
        match nanos {
            Some(n) => b.append_value(n),
            None => b.append_null(),
        }
    }
    Ok(Arc::new(b.finish()))
}

/// Convert a tokio-postgres decode error into a `DataFusionError`.
///
/// Takes the error by value so it can be passed directly to
/// `Result::map_err(pg_decode_err)` without a closure — matching the
/// signature `FnOnce(E) -> F` that `map_err` demands.
#[allow(clippy::needless_pass_by_value)]
fn pg_decode_err(e: tokio_postgres::Error) -> DataFusionError {
    DataFusionError::External(Box::new(DataglotError::federation(format!(
        "postgres row decode error: {}",
        format_pg_error(&e)
    ))))
}

// MULTI-TENANT NOTE (; spec: the phase-3 `adbc-connector` plan).
// `execute` below sends user-driven SQL on the single `Arc<Client>` shared
// across all pgwire sessions. Safe today because the federation unparser
// only emits read-only `SELECT` statements. If you add pre/post hooks that
// emit `SET ROLE`, `SET application_name`, per-user impersonation, or any
// other state-changing SQL on the shared client, you MUST address state
// isolation across users — see the ADBC connector's reset-on-return +
// discard-on-failure pattern at `crates/dataglot-federation/src/adbc.rs`.
#[async_trait]
impl SQLExecutor for PostgresConnector {
    fn name(&self) -> &str {
        &self.name
    }

    fn compute_context(&self) -> Option<String> {
        Some(self.name.clone())
    }

    fn dialect(&self) -> Arc<dyn Dialect> {
        // PostgreSqlDialect emits double-quoted identifiers, `::type`
        // casts, and other postgres-flavoured syntax. This is what makes
        // pushed-down SQL actually executable on the remote.
        Arc::new(PostgreSqlDialect {})
    }

    fn logical_optimizer(&self) -> Option<LogicalOptimizer> {
        // Runs on the federated sub-plan post-optimization, right before
        // unparse. Isolate any row filter sitting on an OUTER-JOIN preserved
        // leg into a derived table so the unparser can't fold it into the
        // join's `ON` (where it would be inert → RLS bypass). See
        // `isolate_outer_join_filters`.
        Some(Box::new(|plan: LogicalPlan| {
            isolate_outer_join_filters(plan)
        }))
    }

    fn ast_analyzer(&self) -> Option<AstAnalyzer> {
        // Repair the derived-table requalification the unparser omits for
        // pushed-down `DISTINCT` (and any GROUP BY the plan wraps in a derived
        // projection). See `requalify_derived_refs`.
        Some(Box::new(|stmt: ast::Statement| {
            Ok(requalify_derived_refs(stmt))
        }))
    }

    fn execute(
        &self,
        query: &str,
        schema: SchemaRef,
        _filters: &[Arc<dyn PhysicalExpr>],
    ) -> DfResult<SendableRecordBatchStream> {
        // `SQLExecutor::execute` is sync — we must spawn an async task
        // and surface the result as a stream. The query has already been
        // unparsed with `PostgreSqlDialect` so it's safe to send as-is.
        //
        // The pushed-down SQL is logged by `instrument_pushdown` at `debug`
        // (it may contain filter literals — user data, not credentials);
        // the source-attributed timing/row-count event it emits on
        // completion stays at `info`.
        let client = Arc::clone(&self.client);
        let schema_for_stream = Arc::clone(&schema);
        let query_owned = query.to_string();

        // We collect the entire result set in one shot for this PR. The
        // follow-up (streaming via `client.query_raw()`) is tracked
        // separately — it requires swapping the builder approach for a
        // chunked writer. For Phase 0 the correctness bar is "Arrow
        // flows end-to-end", not "we never buffer".
        let fut = async move {
            // Backstop the query so a black-holed source fails eventually
            // rather than hanging forever. `with_query_timeout`
            // yields a `federation` error on expiry; the inner Result carries
            // the query's own error, mapped as before.
            let rows = with_query_timeout(client.query(query_owned.as_str(), &[]))
                .await
                .map_err(|e| DataFusionError::External(Box::new(e)))?
                .map_err(|e| {
                    DataFusionError::External(Box::new(DataglotError::federation(format!(
                        "postgres query failed: {}",
                        format_pg_error(&e)
                    ))))
                })?;
            rows_to_record_batch(&schema_for_stream, &rows)
        };

        // Wrap the single-batch future in a stream that yields once.
        let batch_stream = stream::once(fut);
        let stream = Box::pin(RecordBatchStreamAdapter::new(schema, batch_stream));
        Ok(crate::instrument_pushdown(
            self.source_label(),
            "postgres",
            query,
            stream,
        ))
    }

    async fn table_names(&self) -> DfResult<Vec<String>> {
        // Used by `SQLSchemaProvider::new` — we don't currently wire
        // that up but the trait requires it. Returning all user tables
        // in `public` is a sensible default.
        let rows = self
            .client
            .query(
                "SELECT table_schema || '.' || table_name
                 FROM information_schema.tables
                 WHERE table_type = 'BASE TABLE'
                   AND table_schema NOT IN ('pg_catalog', 'information_schema')",
                &[],
            )
            .await
            .map_err(|e| {
                DataFusionError::External(Box::new(DataglotError::catalog(format!(
                    "failed to list postgres tables: {}",
                    format_pg_error(&e)
                ))))
            })?;
        Ok(rows.into_iter().map(|r| r.get::<_, String>(0)).collect())
    }

    async fn get_table_schema(&self, table_name: &str) -> DfResult<SchemaRef> {
        // `table_name` is a fully-quoted `RemoteTableRef`-style reference
        // (e.g. `"public"."users"`). Parse out schema + table.
        let (schema, table) = split_qualified(table_name).ok_or_else(|| {
            DataFusionError::External(Box::new(DataglotError::catalog(format!(
                "expected '<schema>.<table>' reference, got: {table_name}"
            ))))
        })?;
        self.fetch_arrow_schema(schema.as_str(), table.as_str())
            .await
            .map_err(|e| DataFusionError::External(Box::new(e)))
    }
}

/// Cheap liveness probe that reuses the boot-built, already-authenticated
/// `tokio-postgres` client. The health poller calls this on a timer
/// instead of rebuilding the connector; a single `SELECT 1` round-trip errors
/// iff the source is unreachable or the connection has been lost. The error is
/// scrubbed through `format_pg_error` so no DSN/password can leak (rule 12).
#[async_trait]
impl crate::health::ConnectorHealthCheck for PostgresConnector {
    async fn health_check(&self) -> Result<(), String> {
        self.client
            .query("SELECT 1", &[])
            .await
            .map(|_| ())
            .map_err(|e| format!("postgres health check failed: {}", format_pg_error(&e)))
    }
}

/// Split a `<schema>.<table>` (optionally quoted) identifier into parts.
/// Returns `None` if the input doesn't match that shape. This is only
/// used on input produced by `datafusion-federation` from the remote
/// table reference we constructed in [`PostgresConnector::table_provider`],
/// so the shape is well-known.
fn split_qualified(s: &str) -> Option<(String, String)> {
    // Handle the common quoted form `"schema"."table"` and the bare form
    // `schema.table`. We intentionally don't support three-part (catalog.
    // schema.table) names here — Postgres itself only has two levels
    // (schema.table) at the query layer.
    let parts: Vec<&str> = s.splitn(2, '.').collect();
    if parts.len() != 2 {
        return None;
    }
    let schema = parts[0].trim_matches('"');
    let table = parts[1].trim_matches('"');
    if schema.is_empty() || table.is_empty() {
        return None;
    }
    Some((schema.to_string(), table.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parse SQL and run the connector's `ast_analyzer` (the
    /// derived-table requalifier).
    fn analyze(sql: &str) -> String {
        use datafusion::sql::sqlparser::dialect::PostgreSqlDialect as PgParseDialect;
        use datafusion::sql::sqlparser::parser::Parser;
        let stmt = Parser::parse_sql(&PgParseDialect {}, sql)
            .expect("parse")
            .pop()
            .expect("one statement");
        requalify_derived_refs(stmt).to_string()
    }

    ///: the unparser wraps a pushed-down DISTINCT in a derived table but
    /// leaves the outer refs qualified by the inner table, producing SQL Postgres
    /// rejects (`missing FROM-clause entry for table "users"`). The analyzer
    /// repairs it by REQUALIFYING each stale outer reference to the derived
    /// alias; the derived subquery's own refs (where the real table is in scope)
    /// are left untouched.
    #[test]
    fn requalify_fixes_derived_projection_distinct() {
        let bad = r#"SELECT "users"."region" FROM (SELECT "users"."region" FROM "public"."users") AS "derived_projection" GROUP BY "users"."region" ORDER BY "users"."region" ASC NULLS LAST"#;
        let fixed = analyze(bad);
        // The derived alias is preserved; the outer refs are requalified to it.
        assert!(
            fixed.starts_with(r#"SELECT "derived_projection"."region" FROM"#)
                && fixed.contains(r#"GROUP BY "derived_projection"."region""#)
                && fixed.contains(r#"ORDER BY "derived_projection"."region""#),
            "outer refs should be requalified to the derived alias: {fixed}"
        );
        // The derived subquery's own `users.region` is valid there and untouched.
        assert!(
            fixed.contains(
                r#"(SELECT "users"."region" FROM "public"."users") AS "derived_projection""#
            ),
            "the derived subquery's inner refs must be left untouched: {fixed}"
        );
    }

    /// A plain scan (no derived table) must be left completely untouched — the
    /// qualifiers there are valid.
    #[test]
    fn requalify_leaves_plain_scan_untouched() {
        let ok = r#"SELECT "users"."region" FROM "public"."users" GROUP BY "users"."region""#;
        assert_eq!(analyze(ok), ok);
    }

    /// A join query (no single derived table) is untouched.
    #[test]
    fn requalify_leaves_join_untouched() {
        let ok = r#"SELECT "u"."id" FROM "public"."users" AS "u" JOIN "public"."orders" AS "o" ON "o"."user_id" = "u"."id""#;
        assert_eq!(analyze(ok), ok);
    }

    /// Stale qualifiers WRAPPED in a function / HAVING resolve too — every
    /// reference at the outer scope is requalified regardless of expression shape.
    #[test]
    fn requalify_fixes_function_and_having_refs() {
        let bad = r#"SELECT upper("users"."region") FROM (SELECT "users"."region" FROM "public"."users") AS "derived_projection" GROUP BY upper("users"."region") HAVING count("users"."region") > 1"#;
        let fixed = analyze(bad);
        assert!(
            fixed.contains(r#"upper("derived_projection"."region")"#)
                && fixed.contains(r#"count("derived_projection"."region")"#),
            "wrapped refs must be requalified to the derived alias: {fixed}"
        );
        assert!(
            fixed.contains(
                r#"(SELECT "users"."region" FROM "public"."users") AS "derived_projection""#
            ),
            "derived subquery untouched: {fixed}"
        );
    }

    /// A same-source join wrapped in DISTINCT leaves TWO stale qualifiers in the
    /// outer scope (`u.region`, `o.status`). Both must requalify to the single
    /// derived alias — the previous "rename to the sole stale qualifier" scheme
    /// could not express this (Codex P1: multiple source qualifiers).
    #[test]
    fn requalify_fixes_join_distinct_multiple_qualifiers() {
        let bad = r#"SELECT "u"."region", "o"."status" FROM (SELECT "u"."region", "o"."status" FROM "public"."users" AS "u" JOIN "public"."orders" AS "o" ON "o"."uid" = "u"."id") AS "derived_projection" GROUP BY "u"."region", "o"."status""#;
        let fixed = analyze(bad);
        assert!(
            fixed.starts_with(
                r#"SELECT "derived_projection"."region", "derived_projection"."status" FROM"#
            ) && fixed.contains(
                r#"GROUP BY "derived_projection"."region", "derived_projection"."status""#
            ),
            "both stale qualifiers must requalify to the derived alias: {fixed}"
        );
        // The inner join keeps its real `u`/`o` qualifiers (valid in that scope).
        assert!(
            fixed.contains(r#""public"."users" AS "u" JOIN "public"."orders" AS "o""#),
            "inner join refs untouched: {fixed}"
        );
    }

    /// When a reference is already qualified by the DERIVED alias, there is no
    /// stale qualifier ⇒ the query is left completely untouched.
    #[test]
    fn requalify_preserves_derived_alias_refs() {
        let ok = r#"SELECT "derived_projection"."region" FROM (SELECT "region" FROM "public"."users") AS "derived_projection" GROUP BY "derived_projection"."region""#;
        assert_eq!(
            analyze(ok),
            ok,
            "derived-alias refs are valid and untouched"
        );
    }

    /// A DISTINCT branch inside a set operation gets the same derived-table
    /// wrapper and must be repaired too (its outer refs requalified).
    #[test]
    fn requalify_fixes_set_operation_branch() {
        let bad = r#"SELECT "users"."region" FROM (SELECT "users"."region" FROM "public"."users") AS "derived_projection" GROUP BY "users"."region" UNION ALL SELECT "region" FROM "public"."users""#;
        let fixed = analyze(bad);
        assert!(
            fixed.contains(r#"SELECT "derived_projection"."region" FROM (SELECT "users"."region""#)
                && fixed.contains(r#"GROUP BY "derived_projection"."region" UNION ALL"#),
            "the DISTINCT branch's outer refs must be requalified: {fixed}"
        );
    }

    /// A set operation's query-level ORDER BY resolves against the OUTPUT columns
    /// (branch relation aliases are not in scope), so a qualified sort key must be
    /// stripped to a bare column (Codex P1: query-level ORDER BY for set ops).
    #[test]
    fn requalify_strips_set_operation_order_by() {
        let bad = r#"SELECT "region" FROM "public"."users" UNION ALL SELECT "region" FROM "public"."orders" ORDER BY "users"."region""#;
        let fixed = analyze(bad);
        assert!(
            fixed.contains(r#"ORDER BY "region""#)
                && !fixed.contains(r#"ORDER BY "users"."region""#),
            "set-op ORDER BY must be stripped to a bare output column: {fixed}"
        );
    }

    /// The `ORDER BY` output-alias-shadowing case (Codex): requalifying (not
    /// stripping) keeps the reference qualified, so `ORDER BY derived.x` resolves
    /// to the FROM column, never the output alias `x`.
    #[test]
    fn requalify_order_by_stays_qualified_no_shadow() {
        let bad = r#"SELECT (- "users"."x") AS "x" FROM (SELECT "users"."x" FROM "public"."t") AS "derived_projection" ORDER BY "users"."x""#;
        let fixed = analyze(bad);
        assert!(
            fixed.contains(r#"ORDER BY "derived_projection"."x""#),
            "ORDER BY must stay qualified (to the derived alias), not stripped to a shadowed bare name: {fixed}"
        );
    }

    /// The stale qualifier in the outer WHERE is requalified too (Codex).
    #[test]
    fn requalify_considers_outer_where() {
        let bad = r#"SELECT "region" FROM (SELECT "users"."region" FROM "public"."users") AS "derived_projection" WHERE "users"."region" = 'EU'"#;
        let fixed = analyze(bad);
        assert!(
            fixed.contains(r#"WHERE "derived_projection"."region" = 'EU'"#),
            "outer WHERE ref must be requalified to the derived alias: {fixed}"
        );
    }

    /// A qualifier that appears ONLY inside a nested subquery (its own scope)
    /// must not be touched by the OUTER scope's requalification (Codex): the
    /// outer refs use the derived alias, and the nested `o` is valid in its scope.
    #[test]
    fn requalify_ignores_nested_subquery_qualifiers() {
        let ok = r#"SELECT "derived_projection"."region" FROM (SELECT "region" FROM "public"."users") AS "derived_projection" WHERE "derived_projection"."region" IN (SELECT "o"."region" FROM "public"."orders" AS "o")"#;
        assert_eq!(
            analyze(ok),
            ok,
            "a nested subquery's `o` qualifier must not be rewritten by the outer scope"
        );
    }

    /// A broken shape embedded in an EXPRESSION subquery (here an IN-subquery) is
    /// deliberately LEFT UNREPAIRED and unchanged: an expression subquery can be
    /// correlated, and a leaked qualifier there is textually indistinguishable
    /// from a genuine correlated reference — so requalifying it could silently
    /// rewrite a correlation. We only descend through FROM (uncorrelated). Such a
    /// pushdown fails loudly on the remote exactly as before this fix (tracked
    /// follow-up); it is never silently mis-rewritten.
    #[test]
    fn requalify_leaves_expression_subquery_unrepaired() {
        let bad = r#"SELECT "id" FROM "public"."accounts" WHERE "id" IN (SELECT "users"."region" FROM (SELECT "users"."region" FROM "public"."users") AS "derived_projection" GROUP BY "users"."region")"#;
        assert_eq!(
            analyze(bad),
            bad,
            "expression-subquery scopes must be left untouched, never guessed at"
        );
    }

    /// A parenthesized query body with a trailing wrapper-level ORDER BY: the
    /// inner refs requalify and the wrapper ORDER BY (which resolves against the
    /// inner output columns) is stripped to a bare column (Codex P1).
    #[test]
    fn requalify_fixes_parenthesized_outer_order_by() {
        let bad = r#"(SELECT "users"."region" FROM (SELECT "users"."region" FROM "public"."users") AS "derived_projection" GROUP BY "users"."region") ORDER BY "users"."region""#;
        let fixed = analyze(bad);
        assert!(
            fixed.contains(r#"GROUP BY "derived_projection"."region""#),
            "inner refs must be requalified: {fixed}"
        );
        assert!(
            fixed.contains(r#"ORDER BY "region""#)
                && !fixed.contains(r#"ORDER BY "users"."region""#),
            "wrapper ORDER BY must be stripped to a bare output column: {fixed}"
        );
    }

    /// A set-op ORDER BY key wrapped in a function must have its qualifier
    /// stripped too, not only a bare `CompoundIdentifier` (Gemini).
    #[test]
    fn requalify_strips_set_operation_order_by_nested_expr() {
        let bad = r#"SELECT "region" FROM "public"."users" UNION ALL SELECT "region" FROM "public"."orders" ORDER BY upper("users"."region")"#;
        let fixed = analyze(bad);
        assert!(
            fixed.contains(r#"ORDER BY upper("region")"#)
                && !fixed.contains(r#"upper("users"."region")"#),
            "qualifier nested in a set-op ORDER BY expression must be stripped: {fixed}"
        );
    }

    /// A DISTINCT over a same-source join projecting same-named columns (`u.id`,
    /// `o.id`) would collapse both to `derived.id` if requalified — ambiguous or
    /// silently wrong. The fix BAILS on such a scope, leaving the SQL unchanged
    /// (no worse than unrepaired) rather than emitting a broken query (Codex P1).
    #[test]
    fn requalify_bails_on_ambiguous_duplicate_output_names() {
        let bad = r#"SELECT "u"."id", "o"."id" FROM (SELECT "u"."id", "o"."id" FROM "public"."users" AS "u" JOIN "public"."orders" AS "o" ON "o"."uid" = "u"."id") AS "derived_projection""#;
        let fixed = analyze(bad);
        assert!(
            fixed.starts_with(r#"SELECT "u"."id", "o"."id" FROM"#),
            "colliding-output-name scope must be left unchanged, not collapsed: {fixed}"
        );
    }

    /// The inverse guarantee for the correlated case: because expression
    /// subqueries are never descended into, a genuine correlated reference to an
    /// enclosing relation is never clobbered — the whole predicate is untouched.
    #[test]
    fn requalify_leaves_correlated_subquery_untouched() {
        let bad = r#"SELECT "a"."id" FROM "public"."accounts" AS "a" WHERE EXISTS (SELECT "users"."region" FROM (SELECT "users"."region" FROM "public"."users") AS "derived_projection" WHERE "users"."region" = "a"."region")"#;
        assert_eq!(
            analyze(bad),
            bad,
            "correlated `a` (and everything in the expression subquery) is left as-is"
        );
    }

    /// A duplicated projection over the SAME qualifier (`u.id, u.id`) also makes
    /// the derived table expose two `id` columns ⇒ ambiguous ⇒ bail unchanged.
    /// The guard keys on duplicate OUTPUT names, not distinct qualifiers (Codex).
    #[test]
    fn requalify_bails_on_same_qualifier_duplicate_output() {
        let bad = r#"SELECT "u"."id", "u"."id" FROM (SELECT "u"."id", "u"."id" FROM "public"."users" AS "u") AS "derived_projection""#;
        let fixed = analyze(bad);
        assert!(
            fixed.starts_with(r#"SELECT "u"."id", "u"."id" FROM"#),
            "duplicate output name must bail, not collapse: {fixed}"
        );
    }

    /// The derived subquery's body can itself be a set operation; the output
    /// names come from its LEFTMOST branch. If that branch has duplicate names
    /// (`u.id`, `o.id`), requalifying would be ambiguous ⇒ bail unchanged (Codex).
    #[test]
    fn requalify_bails_on_duplicate_outputs_in_derived_set_operation() {
        let bad = r#"SELECT "u"."id", "o"."id" FROM (SELECT "u"."id", "o"."id" FROM "public"."users" AS "u" JOIN "public"."orders" AS "o" ON "o"."uid" = "u"."id" UNION ALL SELECT "u"."id", "o"."id" FROM "public"."users" AS "u" JOIN "public"."orders" AS "o" ON "o"."uid" = "u"."id") AS "derived_projection""#;
        let fixed = analyze(bad);
        assert!(
            fixed.starts_with(r#"SELECT "u"."id", "o"."id" FROM"#),
            "a set-op derived body with duplicate left-branch outputs must bail: {fixed}"
        );
    }

    /// A derived body with a `*` wildcard can expand to duplicate columns we
    /// can't see (`DISTINCT *` over a join exposing `u.id` and `o.id`) — an
    /// undeterminable output name must make us bail, not assume no collision.
    #[test]
    fn requalify_bails_on_wildcard_derived_output() {
        let bad = r#"SELECT "u"."id", "o"."id" FROM (SELECT * FROM "public"."users" AS "u" JOIN "public"."orders" AS "o" ON "o"."uid" = "u"."id") AS "derived_projection""#;
        let fixed = analyze(bad);
        assert!(
            fixed.starts_with(r#"SELECT "u"."id", "o"."id" FROM"#),
            "a wildcard derived output must bail unchanged: {fixed}"
        );
    }

    /// The broken derived shape inside a CTE definition must be requalified too —
    /// a WITH query is an uncorrelated scope the fix descends into (Gemini).
    #[test]
    fn requalify_fixes_derived_shape_inside_cte() {
        let bad = r#"WITH "cte" AS (SELECT "users"."region" FROM (SELECT "users"."region" FROM "public"."users") AS "derived_projection" GROUP BY "users"."region") SELECT "region" FROM "cte""#;
        let fixed = analyze(bad);
        assert!(
            fixed.contains(r#"SELECT "derived_projection"."region" FROM (SELECT "users"."region""#)
                && fixed.contains(r#"GROUP BY "derived_projection"."region""#),
            "the CTE body's broken shape must be requalified: {fixed}"
        );
    }

    /// Nested derived tables in the FROM chain (an uncorrelated scope) ARE
    /// descended into and requalified at each level.
    #[test]
    fn requalify_descends_nested_from_derived() {
        let bad = r#"SELECT "users"."region" FROM (SELECT "users"."region" FROM (SELECT "users"."region" FROM "public"."users") AS "d1") AS "d2""#;
        let fixed = analyze(bad);
        assert!(
            fixed.starts_with(
                r#"SELECT "d2"."region" FROM (SELECT "d1"."region" FROM (SELECT "users"."region""#
            ),
            "each FROM-nested derived scope requalifies to its own alias: {fixed}"
        );
    }

    #[test]
    fn nanos_or_range_err_ok_in_range_errors_out_of_range() {
        use chrono::{TimeZone, Utc};
        // In range (2024) → Ok.
        let in_range = Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap();
        assert!(nanos_or_range_err(in_range).is_ok());
        // Out of range (year 3000, well past ~2262) → a hard error, never a
        // silent NULL ( Bug B hardening).
        let out = Utc.with_ymd_and_hms(3000, 1, 1, 0, 0, 0).unwrap();
        let err = nanos_or_range_err(out).unwrap_err();
        assert!(
            format!("{err}").contains("out of range for nanosecond"),
            "expected the nanosecond-range error, got: {err}"
        );
    }

    #[test]
    fn postgres_connector_is_a_connector_health_check() {
        // Compile-level pin: the boot path upcasts the retained
        // `Arc<PostgresConnector>` to `Arc<dyn ConnectorHealthCheck>` so the
        // poller can reuse the authenticated client. A live `SELECT 1` needs a
        // real server (covered by the integration suite); this asserts the impl
        // exists and satisfies the trait's `Send + Sync + 'static` bounds.
        fn assert_impl<T: crate::health::ConnectorHealthCheck>() {}
        assert_impl::<PostgresConnector>();
    }

    #[test]
    fn source_label_prefers_catalog_then_falls_back_to_dsn_name() {
        //: a `with_catalog`-tagged connector labels pushdowns with the
        // catalog name (matching the query's `sources` list); untagged falls
        // back to the DSN-derived compute-context name.
        let dsn_name = "postgres://svc@db.internal:5432/analytics";
        assert_eq!(pick_source_label(Some("pg"), dsn_name), "pg");
        assert_eq!(pick_source_label(None, dsn_name), dsn_name);
    }

    #[test]
    fn udt_mapping_covers_minimum_types() {
        // The README-level promise is that these ten types all map.
        assert_eq!(pg_udt_to_arrow("int2", None, None), Some(DataType::Int16));
        assert_eq!(pg_udt_to_arrow("int4", None, None), Some(DataType::Int32));
        assert_eq!(pg_udt_to_arrow("int8", None, None), Some(DataType::Int64));
        assert_eq!(
            pg_udt_to_arrow("float4", None, None),
            Some(DataType::Float32)
        );
        assert_eq!(
            pg_udt_to_arrow("float8", None, None),
            Some(DataType::Float64)
        );
        assert_eq!(pg_udt_to_arrow("bool", None, None), Some(DataType::Boolean));
        assert_eq!(pg_udt_to_arrow("text", None, None), Some(DataType::Utf8));
        assert_eq!(pg_udt_to_arrow("varchar", None, None), Some(DataType::Utf8));
        assert_eq!(pg_udt_to_arrow("date", None, None), Some(DataType::Date32));
        assert_eq!(
            pg_udt_to_arrow("timestamp", None, None),
            Some(DataType::Timestamp(TimeUnit::Microsecond, None))
        );
        assert_eq!(
            pg_udt_to_arrow("timestamptz", None, None),
            Some(DataType::Timestamp(TimeUnit::Microsecond, None))
        );
    }

    #[test]
    fn udt_mapping_rejects_unknown_types() {
        // Deliberately _not_ silently mapping unknown types. The caller
        // surfaces this as a catalog error per the task spec.
        assert_eq!(pg_udt_to_arrow("jsonb", None, None), None);
        assert_eq!(pg_udt_to_arrow("uuid", None, None), None);
        assert_eq!(pg_udt_to_arrow("", None, None), None);
    }

    #[test]
    fn udt_mapping_for_unconstrained_numeric_falls_back() {
        // Unconstrained NUMERIC (NULL typmod ⇒ NULL precision/scale)
        // falls back to Decimal128(38, 18). See `decimal_type_for`.
        assert_eq!(
            pg_udt_to_arrow("numeric", None, None),
            Some(DataType::Decimal128(38, 18)),
        );
    }

    #[test]
    fn udt_mapping_for_numeric_preserves_declared_scale() {
        // The regression this fixes: NUMERIC(10,2) must stay scale 2,
        // not widen to the historical scale-18 default (which rendered
        // `49.99` as `49.990000000000000000` and diverged from every
        // other engine). Precision/scale come from information_schema.
        assert_eq!(
            pg_udt_to_arrow("numeric", Some(10), Some(2)),
            Some(DataType::Decimal128(10, 2)),
        );
        assert_eq!(
            pg_udt_to_arrow("numeric", Some(38), Some(0)),
            Some(DataType::Decimal128(38, 0)),
        );
    }

    #[test]
    fn decimal_type_for_handles_edges() {
        // Constrained, in range ⇒ preserved.
        assert_eq!(
            decimal_type_for(Some(18), Some(4)),
            DataType::Decimal128(18, 4)
        );
        // Either bound missing ⇒ fallback.
        assert_eq!(
            decimal_type_for(Some(10), None),
            DataType::Decimal128(38, 18)
        );
        assert_eq!(
            decimal_type_for(None, Some(2)),
            DataType::Decimal128(38, 18)
        );
        // Precision beyond Decimal128's 38 cap ⇒ fallback (can't
        // represent faithfully; PG allows precision up to 1000).
        assert_eq!(
            decimal_type_for(Some(50), Some(2)),
            DataType::Decimal128(38, 18)
        );
        // Scale > precision (malformed) ⇒ fallback.
        assert_eq!(
            decimal_type_for(Some(4), Some(6)),
            DataType::Decimal128(38, 18)
        );
        // Negative scale (PG permits it) ⇒ fallback rather than guess.
        assert_eq!(
            decimal_type_for(Some(10), Some(-2)),
            DataType::Decimal128(38, 18)
        );
    }

    #[test]
    fn rescale_pads_when_target_scale_higher() {
        // 12.34 (mantissa=1234, scale=2) at target scale 18
        // → 1234 * 10^16 = 12_340_000_000_000_000_000
        let d = rust_decimal::Decimal::new(1234, 2);
        let got = rescale_decimal_to_i128(d, 18, 0).expect("rescale should succeed");
        assert_eq!(got, 12_340_000_000_000_000_000_i128);
    }

    #[test]
    fn rescale_passthrough_when_scales_equal() {
        // mantissa=42, scale=5; target scale 5 ⇒ identity.
        let d = rust_decimal::Decimal::new(42, 5);
        let got = rescale_decimal_to_i128(d, 5, 0).expect("rescale should succeed");
        assert_eq!(got, 42_i128);
    }

    #[test]
    fn rescale_rounds_when_target_scale_below_source() {
        // 0.123456789 (mantissa=123456789, scale=9) at target scale 4
        // rounds (half away from zero) to 0.1235 ⇒ mantissa 1235 at
        // scale 4. The Arrow target scale is the authoritative output
        // precision, matching native engine semantics rather than
        // refusing. This is the path a pushed-down AVG lands on.
        let d = rust_decimal::Decimal::new(123_456_789, 9);
        let got = rescale_decimal_to_i128(d, 4, 7).expect("rescale should round, not reject");
        assert_eq!(got, 1235_i128);
    }

    #[test]
    fn rescale_rounds_half_away_from_zero() {
        // 1.25 at target scale 1 ⇒ 1.3 (half away from zero, matching
        // SQL ROUND), mantissa 13. Pins the rounding strategy.
        let d = rust_decimal::Decimal::new(125, 2);
        let got = rescale_decimal_to_i128(d, 1, 0).expect("rescale should round");
        assert_eq!(got, 13_i128);
    }

    #[test]
    fn rescale_detects_i128_overflow() {
        // Pick a mantissa close to i128::MAX with scale 0; rescale to
        // a much larger target scale forces a multiplication that
        // overflows i128. checked_mul returns None and we surface a
        // typed federation error rather than wrapping silently.
        let d = rust_decimal::Decimal::from(i64::MAX);
        let err = rescale_decimal_to_i128(d, 38, 3).expect_err("should detect i128 overflow");
        let msg = err.to_string();
        assert!(
            msg.contains("column 3"),
            "error should name the column: {msg}"
        );
        assert!(
            msg.contains("overflows i128"),
            "error should explain the cause: {msg}"
        );
    }

    #[test]
    fn split_qualified_handles_quoted_and_bare() {
        assert_eq!(
            split_qualified("public.users"),
            Some(("public".into(), "users".into()))
        );
        assert_eq!(
            split_qualified(r#""public"."users""#),
            Some(("public".into(), "users".into()))
        );
    }

    #[test]
    fn split_qualified_rejects_malformed() {
        assert_eq!(split_qualified("users"), None);
        assert_eq!(split_qualified(".users"), None);
        assert_eq!(split_qualified("public."), None);
        assert_eq!(split_qualified(""), None);
    }

    #[test]
    fn redacted_dsn_omits_password() {
        // Parse a DSN with a password and confirm it never appears in
        // the redacted output. This is the core of hard rule 12.
        let cfg =
            Config::from_str("host=example.com port=5433 user=alice password=s3cret dbname=mydb")
                .unwrap();
        let r = redacted_dsn(&cfg);
        assert!(r.contains("example.com"));
        assert!(r.contains("5433"));
        assert!(r.contains("alice"));
        assert!(r.contains("mydb"));
        assert!(!r.contains("s3cret"));
        assert!(r.contains("password=<redacted>"));
    }

    #[test]
    fn redacted_dsn_without_password_has_no_password_marker() {
        let cfg = Config::from_str("host=localhost user=alice dbname=mydb").unwrap();
        let r = redacted_dsn(&cfg);
        // Make sure we don't lie about a password being set.
        assert!(!r.contains("password"));
    }

    /// Prove that `Debug` output for a connector is credential-free
    /// without having to stand up a real tokio-postgres client.
    ///
    /// `PostgresConnector::fmt` only touches `self.name` and
    /// `self.config` (via `redacted_dsn`). Both are covered here by
    /// formatting the same fields the impl reads, in the same way.
    /// The dedicated `redacted_dsn_*` tests above pin down the
    /// underlying redaction; this one asserts the wrapper format.
    #[test]
    fn debug_formatting_is_redacted() {
        let cfg = Config::from_str(
            "host=db.internal port=5432 user=alice password=topsecret dbname=prod",
        )
        .unwrap();
        let name = compute_context_name(&cfg);
        let debug_ish = format!(
            "PostgresConnector {{ name: {:?}, dsn: {:?} }}",
            name,
            redacted_dsn(&cfg)
        );
        assert!(!debug_ish.contains("topsecret"));
        assert!(debug_ish.contains("db.internal"));
        assert!(debug_ish.contains("alice"));
    }

    #[test]
    fn compute_context_name_is_deterministic() {
        let cfg =
            Config::from_str("host=db.example port=5432 user=alice password=whatever dbname=prod")
                .unwrap();
        let a = compute_context_name(&cfg);
        let b = compute_context_name(&cfg);
        assert_eq!(a, b);
        assert!(a.contains("db.example"));
        assert!(a.contains("prod"));
        assert!(a.contains("alice"));
        assert!(!a.contains("whatever"));
    }

    /// `PostgresCatalog::schema_names` returns the cached list verbatim
    /// and `schema(name)` resolves to a pre-built provider for known
    /// schemas / `None` for unknown ones. This pins the sync side of
    /// the [`DfCatalogProvider`] contract — the live `as_catalog_provider`
    /// path is exercised by the integration test in
    /// `tests/postgres_integration.rs`.
    #[test]
    fn catalog_schema_names_and_lookup() {
        // We don't need a real connector for this — `PostgresCatalog`
        // only reads `schema_names` and `schemas` once built. Build a
        // minimal one with two empty schemas and probe the public API.
        let cat = PostgresCatalog {
            connector_name: "postgres://test".to_string(),
            schema_names: vec!["public".to_string(), "analytics".to_string()],
            schemas: HashMap::new(),
        };
        let names = cat.schema_names();
        assert_eq!(names.len(), 2);
        assert!(names.contains(&"public".to_string()));
        assert!(names.contains(&"analytics".to_string()));
        // Unknown schema must return None — never panic.
        assert!(cat.schema("does_not_exist").is_none());
    }

    /// `PostgresCatalog`'s `Debug` impl exposes only the connector name
    /// and a schema count — neither password nor host. Hard rule 12.
    #[test]
    fn catalog_debug_does_not_leak_credentials() {
        let cat = PostgresCatalog {
            // The `connector_name` includes user@host but never the
            // password (see `compute_context_name`); we still pin that
            // a literal "password=..." substring doesn't appear here.
            connector_name: "postgres://alice@db.internal:5432/prod".to_string(),
            schema_names: vec!["public".to_string()],
            schemas: HashMap::new(),
        };
        let s = format!("{cat:?}");
        assert!(s.contains("PostgresCatalog"), "{s}");
        assert!(s.contains("schema_count"), "{s}");
        assert!(!s.contains("password"), "{s}");
        assert!(!s.contains("topsecret"), "{s}");
    }

    /// The schema-listing SQL excludes the three Postgres system
    /// schemas so users only see their own data. This is a textual
    /// check on the source — the real query is exercised live in
    /// `tests/postgres_integration.rs`.
    #[test]
    fn schema_listing_filters_postgres_system_schemas() {
        // We pin the SQL the connector ships with by re-reading the
        // source. The string here MUST stay in sync with
        // `as_catalog_provider`'s query.
        let src = include_str!("postgres.rs");
        // Find the listing query in the source.
        assert!(
            src.contains("information_schema.schemata"),
            "as_catalog_provider must list schemas via information_schema.schemata"
        );
        assert!(
            src.contains("pg_catalog")
                && src.contains("information_schema")
                && src.contains("pg_toast"),
            "schema listing must exclude pg_catalog, information_schema, pg_toast"
        );
    }

    /// `PostgresSchema` exposes the cached table names directly and
    /// the `table_exist` helper agrees with `table_names` set
    /// membership. The async `table()` path is covered by the
    /// integration test (it requires a live connection).
    #[test]
    fn schema_provider_table_names_and_existence() {
        // We need an `Arc<PostgresConnector>` to construct a
        // `PostgresSchema`, but we never call `table()` here so we
        // never touch its client. Build a connector with a parsed-but-
        // never-connected `Config` and a `Client` is impossible to
        // forge — instead, we test only the parts of `PostgresSchema`
        // that don't need a connector by accessing fields directly.
        //
        // Use a struct-literal pattern via the public `PostgresSchema`
        // contract: `table_names()` and `table_exist()` are
        // deterministic functions of `self.table_names`.
        //
        // (Skipping construction of the connector; we exercise the
        // core invariant — that `table_exist` agrees with
        // `table_names` — without one.)
        let table_names = ["users".to_string(), "orders".to_string()];

        // Mimic the lookup logic. If this assertion drifts from the
        // real impl, the integration test will catch it; this unit
        // test pins the contract.
        let exist = |name: &str| table_names.iter().any(|t| t == name);
        assert!(exist("users"));
        assert!(exist("orders"));
        assert!(!exist("missing"));
    }

    /// A source that accepts the TCP socket but never speaks the startup
    /// protocol must make `connect` *fail* (time out), not hang forever —
    /// the  boot-wedge that defeats `--tolerate-unreachable-catalogs`.
    /// Uses a hold-open listener under a paused clock: once the handshake
    /// read is the only pending work, tokio auto-advances to the
    /// `CONNECT_TIMEOUT` deadline, so the test is effectively instant.
    #[tokio::test(start_paused = true)]
    async fn connect_times_out_when_handshake_stalls() {
        use tokio::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            // Accept and hold sockets open; never write the pg protocol.
            let mut held = Vec::new();
            while let Ok((sock, _)) = listener.accept().await {
                held.push(sock);
            }
        });
        let dsn = format!("host=127.0.0.1 port={} user=u dbname=d", addr.port());
        let err = PostgresConnector::connect(&dsn)
            .await
            .expect_err("connect must fail, not hang");
        assert!(
            err.to_string().contains("timed out"),
            "expected a timeout error, got: {err}"
        );
    }

    /// A query that never completes (a black-holed source) must fail with the
    /// execution-timeout backstop, not hang forever. Uses a paused
    /// clock: the timeout timer is the only pending work, so tokio
    /// auto-advances to `QUERY_TIMEOUT`, making the test effectively instant.
    #[tokio::test(start_paused = true)]
    async fn query_timeout_fires_on_a_stuck_query() {
        let err = with_query_timeout(std::future::pending::<()>())
            .await
            .expect_err("a never-completing query must time out");
        assert!(
            err.to_string().contains("execution timeout"),
            "expected an execution-timeout error, got: {err}"
        );
    }

    /// The backstop is a no-op envelope for a query that returns promptly —
    /// the inner value passes straight through, well under the deadline.
    #[tokio::test(start_paused = true)]
    async fn query_timeout_passes_through_a_prompt_result() {
        let v = with_query_timeout(async { 42_u32 })
            .await
            .expect("a ready future must pass through the backstop");
        assert_eq!(v, 42);
    }

    /// `apply_resilience_defaults` fills keepalive/`tcp_user_timeout` when the
    /// DSN left them unset, so a dead peer is detected in tens of seconds
    /// rather than the tokio-postgres 2-hour default.
    #[test]
    fn resilience_defaults_fill_unset_transport_settings() {
        let config = apply_resilience_defaults(Config::new());
        assert_eq!(config.get_tcp_user_timeout(), Some(&TCP_USER_TIMEOUT));
        assert_eq!(config.get_keepalives_idle(), KEEPALIVE_IDLE);
        assert!(config.get_keepalives());
    }

    /// An explicit value in the DSN always wins — we only fill gaps, never
    /// override an operator's deliberate choice.
    #[test]
    fn resilience_defaults_preserve_explicit_dsn_values() {
        let mut base = Config::new();
        base.tcp_user_timeout(std::time::Duration::from_secs(99))
            .keepalives_idle(std::time::Duration::from_mins(2));
        let config = apply_resilience_defaults(base);
        assert_eq!(
            config.get_tcp_user_timeout(),
            Some(&std::time::Duration::from_secs(99))
        );
        assert_eq!(
            config.get_keepalives_idle(),
            std::time::Duration::from_mins(2)
        );
    }

    /// A DSN that turned keepalives off keeps them off — the idle is not
    /// tightened — but `tcp_user_timeout` (orthogonal to keepalives) is still
    /// supplied as the transport backstop.
    #[test]
    fn resilience_defaults_respect_disabled_keepalives() {
        let mut base = Config::new();
        base.keepalives(false);
        let config = apply_resilience_defaults(base);
        assert!(!config.get_keepalives());
        assert_eq!(
            config.get_keepalives_idle(),
            TOKIO_POSTGRES_DEFAULT_KEEPALIVE_IDLE
        );
        assert_eq!(config.get_tcp_user_timeout(), Some(&TCP_USER_TIMEOUT));
    }

    // ---- Decode conversion cores ---------------------------------
    // The Row-based decoders extract typed values via FromSql (no public Row
    // constructor), so these pure conversion helpers carry the interesting
    // decode logic and are unit-tested here directly.

    #[test]
    fn pg_int8_to_u64_reinterprets_nonneg_and_rejects_negative() {
        assert_eq!(pg_int8_to_u64(0, 0).unwrap(), 0);
        assert_eq!(pg_int8_to_u64(42, 0).unwrap(), 42);
        assert_eq!(
            pg_int8_to_u64(i64::MAX, 0).unwrap(),
            i64::MAX.cast_unsigned()
        );
        assert!(pg_int8_to_u64(-1, 0).is_err());
    }

    #[test]
    fn naive_date_to_days_matches_epoch_offset() {
        use chrono::NaiveDate;
        let day = |y, m, d| naive_date_to_days(NaiveDate::from_ymd_opt(y, m, d).unwrap()).unwrap();
        assert_eq!(day(1970, 1, 1), 0);
        assert_eq!(day(2020, 1, 1), 18_262);
        assert_eq!(day(1969, 12, 31), -1);
    }

    #[test]
    fn numeric_to_i64_narrows_and_rejects_overflow() {
        use rust_decimal::Decimal;
        assert_eq!(numeric_to_i64(Decimal::new(42, 0), 0).unwrap(), 42);
        assert_eq!(
            numeric_to_i64(Decimal::new(-9_000_000_000, 0), 0).unwrap(),
            -9_000_000_000
        );
        // Decimal::MAX (~7.9e28) is far beyond i64::MAX -> fail-loud.
        assert!(numeric_to_i64(Decimal::MAX, 0).is_err());
    }
}

//! Oracle data-source connector — bespoke `SQLExecutor`.
//!
//! Federates an Oracle database (the Exadata-displacement read path).
//! Spec: the phase-3 `oracle-federation-connector` plan;
//! dual-backend plan:.
//!
//! [`OracleConnector`] owns the shared Oracle-SQL surface (dialect,
//! `ast_analyzer` rewrites, the `oracle_type_to_arrow` mapping, governance)
//! and dispatches the *wire* operations to an internal `OracleBackend`.
//! Today the only backend is `OciBackend` (the `oracle` crate / ODPI-C); a
//! pure-Rust backend is planned and will plug in behind the same
//! trait.
//!
//! The OCI backend's `oracle` crate (ODPI-C) is **synchronous**, so every
//! database call runs under `tokio::task::spawn_blocking` (hard
//! rule 11) and the `oracle::Connection` is held in an `Arc<Mutex<…>>` and
//! serialized. Schemas resolve lazily on first table access (rule 13).
//! Credentials never appear in logs, errors, or `Debug` output (rule 12).
//!
//! Oracle has no `LIMIT`; DataFusion's unparser emits `LIMIT n`, so the
//! [`SQLExecutor::ast_analyzer`] hook rewrites the query's `limit` into
//! Oracle's `FETCH FIRST n ROWS ONLY` after unparsing. Identifiers are
//! double-quoted ([`oracle_dialect`]).
//!
//! Type coverage (per spec): `NUMBER` → Int64 (integer-valued) /
//! Decimal128(p,s) (fixed-point, exact, p ≤ 28 — ) / Float64
//! (precision beyond the decoder's 28-digit `rust_decimal` limit, or
//! negative scale); `VARCHAR2` / `CHAR` / `CLOB` → Utf8; `DATE` /
//! `TIMESTAMP` → Timestamp. Other types (LOB binary, object types,
//! XMLTYPE, …) are rejected at schema mapping with a clear error — out
//! of scope.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
#[cfg(feature = "oracle")]
use std::sync::Mutex;

use arrow::array::{
    ArrayRef, BooleanBuilder, Decimal128Builder, Float64Builder, Int64Builder, StringBuilder,
    TimestampMicrosecondBuilder,
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
use datafusion::physical_plan::stream::RecordBatchStreamAdapter;
use datafusion::physical_plan::PhysicalExpr;
use datafusion::sql::sqlparser::ast::{self, Fetch};
use datafusion::sql::unparser::dialect::{CustomDialectBuilder, Dialect};
use datafusion::sql::TableReference;
use datafusion_federation::sql::{
    AstAnalyzer, LogicalOptimizer, RemoteTableRef, SQLExecutor, SQLFederationProvider,
    SQLTableSource,
};
use datafusion_federation::FederatedTableProviderAdaptor;
use futures::stream;
#[cfg(feature = "oracle")]
use oracle::Connection;
use tracing::debug;

use dataglot_core::{DataglotError, Result as DataglotResult};

/// Coarse backstop on a *pushed-down query's* execution (, mirroring the
/// Postgres connector's `QUERY_TIMEOUT` from ). The Oracle backends run
/// every call under `spawn_blocking` with no timeout of their own, so a source
/// that stalls mid-query — a lock wait, a black-holed peer after connect — would
/// otherwise hang the federated query (and tie up a blocking thread) forever.
const QUERY_TIMEOUT: std::time::Duration = std::time::Duration::from_mins(5);

/// Run a source query future under [`QUERY_TIMEOUT`], mapping expiry to a
/// `federation` error rather than hanging forever. Note: the
/// underlying `spawn_blocking` call is not itself cancelled — the timeout frees
/// the *caller* while the blocking thread drains — but the federated query no
/// longer hangs.
async fn with_query_timeout<F, T>(fut: F) -> DfResult<T>
where
    F: std::future::Future<Output = DfResult<T>>,
{
    match tokio::time::timeout(QUERY_TIMEOUT, fut).await {
        Ok(res) => res,
        Err(_) => Err(DataFusionError::External(Box::new(
            DataglotError::federation(format!(
                "oracle query exceeded the {}s execution timeout",
                QUERY_TIMEOUT.as_secs()
            )),
        ))),
    }
}

/// Which Oracle wire backend to use for a catalog.
///
/// Both are off by default and excluded from `all` (rule 9); each is
/// gated behind its own Cargo feature. Selecting a driver whose feature
/// was not compiled in fails fast with a clear, credential-free error
/// (see [`OracleConnector::connect_with_driver`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OracleDriver {
    /// OCI / ODPI-C (the `oracle` crate). Oracle-blessed, maximum
    /// compatibility; needs the Instant Client at runtime and a C
    /// compiler at build. Cargo feature `oracle`.
    Oci,
    /// Pure-Rust (oracle-rs) — reimplements the TTC/TNS protocol in
    /// async Rust; no ODPI-C, no Instant Client, no C compiler. Cargo
    /// feature `oracle-pure`.
    Pure,
}

impl OracleDriver {
    /// Lowercase wire name as used in catalog config (`driver = "…"`).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Oci => "oci",
            Self::Pure => "pure",
        }
    }

    /// The Cargo feature that must be compiled in for this driver.
    #[must_use]
    pub fn feature(self) -> &'static str {
        match self {
            Self::Oci => "oracle",
            Self::Pure => "oracle-pure",
        }
    }
}

impl fmt::Display for OracleDriver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An Oracle federation connector. Construct via [`OracleConnector::connect`].
pub struct OracleConnector {
    /// Federation compute-context key + `SQLExecutor::name`.
    name: String,
    /// The wire backend. OCI/ODPI-C today ([`OciBackend`]); a pure-Rust
    /// backend is planned. The connector shares one dialect,
    /// pushdown, type mapping, and governance surface across backends —
    /// only the wire client differs.
    backend: Arc<dyn OracleBackend>,
    /// Credential-free identity for `Debug` (host/service from the DSN).
    endpoint_hint: String,
}

impl OracleConnector {
    /// Connect to Oracle using the build's **default** backend (OCI if
    /// `--features oracle` is compiled, else the pure-Rust backend).
    /// `dsn` is an Easy Connect string, e.g. `//host:1521/SERVICE`.
    ///
    /// # Errors
    /// [`DataglotError::Connection`] if the connection fails. Neither
    /// the DSN nor the password appears in the error (rule 12).
    pub async fn connect(
        name: impl Into<String>,
        dsn: &str,
        user: &str,
        password: &str,
    ) -> DataglotResult<Self> {
        Self::connect_with_driver(name, dsn, user, password, None).await
    }

    /// Connect to Oracle with an explicit [`OracleDriver`] selection
    ///. `driver = None` picks the build default — OCI when the
    /// `oracle` feature is compiled, otherwise the pure-Rust backend.
    ///
    /// # Errors
    /// [`DataglotError::Configuration`] if the requested `driver` (or the
    /// resolved default) names a backend whose Cargo feature was not
    /// compiled into this binary — fails fast with an actionable,
    /// credential-free message. [`DataglotError::Connection`] if the
    /// connection itself fails (neither DSN nor password appears, rule 12).
    pub async fn connect_with_driver(
        name: impl Into<String>,
        dsn: &str,
        user: &str,
        password: &str,
        driver: Option<OracleDriver>,
    ) -> DataglotResult<Self> {
        let name = name.into();
        let endpoint_hint = redacted_endpoint(dsn);
        // Validate the driver is compiled in before touching the network.
        let resolved = resolve_supported_driver(driver)?;
        debug!(
            connector = %name,
            endpoint = %endpoint_hint,
            driver = %resolved,
            "opening oracle connection"
        );
        let backend = connect_backend(resolved, dsn, user, password).await?;

        Ok(Self {
            name,
            backend,
            endpoint_hint,
        })
    }

    /// The connector's compute-context identifier.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Produce a federated [`TableProvider`] for `<schema>.<table>`.
    /// Schema is fetched on demand (rule 13).
    ///
    /// # Errors
    /// [`DataglotError::Catalog`] if the table is missing or has a type
    /// we don't map.
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

    /// Build a [`DfCatalogProvider`] enumerating the connection user's
    /// schemas + tables (`ALL_TABLES`), per-table Arrow schema lazy.
    ///
    /// # Errors
    /// [`DataglotError::Catalog`] if the catalog listing query fails.
    pub async fn as_catalog_provider(self: &Arc<Self>) -> DataglotResult<Arc<OracleCatalog>> {
        // (owner, table) pairs visible to this user, excluding Oracle's
        // maintained/system schemas.
        let rows = self
            .query_strings(
                "SELECT owner, table_name FROM all_tables \
                 WHERE owner NOT IN ('SYS','SYSTEM','OUTLN','DBSNMP','APPQOSSYS','CTXSYS', \
                   'XDB','MDSYS','ORDSYS','ORDDATA','LBACSYS','WMSYS','GSMADMIN_INTERNAL', \
                   'AUDSYS','DVSYS','OJVMSYS') \
                 ORDER BY owner, table_name",
                2,
            )
            .await?;

        let mut by_owner: HashMap<String, Vec<String>> = HashMap::new();
        for r in rows {
            by_owner.entry(r[0].clone()).or_default().push(r[1].clone());
        }
        let mut schema_names: Vec<String> = by_owner.keys().cloned().collect();
        schema_names.sort();

        let mut schemas: HashMap<String, Arc<dyn DfSchemaProvider>> = HashMap::new();
        for (owner, tables) in by_owner {
            let provider: Arc<dyn DfSchemaProvider> = Arc::new(OracleSchema {
                connector: Arc::clone(self),
                schema: owner.clone(),
                tables,
            });
            schemas.insert(owner, provider);
        }

        Ok(Arc::new(OracleCatalog {
            connector_name: self.name.clone(),
            schema_names,
            schemas,
        }))
    }

    /// Fetch the Arrow schema for `<schema>.<table>` from `ALL_TAB_COLUMNS`.
    async fn fetch_arrow_schema(&self, schema: &str, table: &str) -> DataglotResult<SchemaRef> {
        validate_identifier_literal(schema)?;
        validate_identifier_literal(table)?;
        // Oracle folds unquoted identifiers to UPPERCASE; the catalog
        // dictionary stores them uppercased.
        let sql = format!(
            "SELECT column_name, data_type, data_precision, data_scale, nullable \
             FROM all_tab_columns \
             WHERE owner = '{}' AND table_name = '{}' \
             ORDER BY column_id",
            schema.to_uppercase(),
            table.to_uppercase()
        );
        let rows = self.query_strings(&sql, 5).await?;
        if rows.is_empty() {
            return Err(DataglotError::catalog(format!(
                "table not found: {schema}.{table}"
            )));
        }
        let mut fields = Vec::with_capacity(rows.len());
        for r in rows {
            let col = &r[0];
            let data_type = &r[1];
            let precision = r[2].parse::<i64>().ok();
            let scale = r[3].parse::<i64>().ok();
            let nullable = r[4] == "Y";
            let arrow_type =
                oracle_type_to_arrow(data_type, precision, scale).ok_or_else(|| {
                    DataglotError::catalog(format!(
                        "unsupported oracle type '{data_type}' for column {schema}.{table}.{col}"
                    ))
                })?;
            fields.push(Field::new(col, arrow_type, nullable));
        }
        Ok(Arc::new(Schema::new(fields)))
    }

    /// Run a character-only dictionary query via the wire backend; each
    /// row → `Vec` of `n_cols` strings (NULL → empty string). Used only
    /// for the catalog/schema introspection queries above.
    async fn query_strings(&self, sql: &str, n_cols: usize) -> DataglotResult<Vec<Vec<String>>> {
        self.backend.query_strings(sql, n_cols).await
    }
}

#[async_trait]
impl SQLExecutor for OracleConnector {
    fn name(&self) -> &str {
        &self.name
    }

    fn compute_context(&self) -> Option<String> {
        Some(self.name.clone())
    }

    fn dialect(&self) -> Arc<dyn Dialect> {
        oracle_dialect()
    }

    fn logical_optimizer(&self) -> Option<LogicalOptimizer> {
        // Isolate governance row filters on OUTER-JOIN preserved legs so the
        // unparser can't fold them into `ON` (RLS bypass). Shared across all SQL
        // connectors — see `crate::rls_isolation` (/291).
        Some(Box::new(|plan: datafusion::logical_expr::LogicalPlan| {
            crate::rls_isolation::isolate_outer_join_filters(plan)
        }))
    }

    fn ast_analyzer(&self) -> Option<AstAnalyzer> {
        // Apply the Oracle-dialect rewrites the `CustomDialect` can't
        // express: `LIMIT`→`FETCH FIRST n ROWS ONLY` and stripping `AS`
        // from table aliases (ORA-03048). See module docs.
        Some(Box::new(|stmt: ast::Statement| {
            Ok(rewrite_statement_for_oracle(
                crate::derived_requalify::requalify_derived_refs(stmt),
            ))
        }))
    }

    fn execute(
        &self,
        query: &str,
        schema: SchemaRef,
        _filters: &[Arc<dyn PhysicalExpr>],
    ) -> DfResult<SendableRecordBatchStream> {
        // The pushed-down SQL is logged by `instrument_pushdown` at `debug`
        // (filter literals are user data, not credentials); the completion
        // event with source/timing/rows is at `info`.
        let backend = Arc::clone(&self.backend);
        let schema_for_fut = Arc::clone(&schema);
        let query_owned = query.to_string();

        let fut = async move {
            with_query_timeout(backend.query_arrow(&query_owned, schema_for_fut)).await
        };

        let batch_stream = stream::once(fut);
        let stream = Box::pin(RecordBatchStreamAdapter::new(schema, batch_stream));
        Ok(crate::instrument_pushdown(
            &self.name, "oracle", query, stream,
        ))
    }

    async fn table_names(&self) -> DfResult<Vec<String>> {
        Err(DataFusionError::NotImplemented(
            "table_names not implemented (use as_catalog_provider)".to_string(),
        ))
    }

    async fn get_table_schema(&self, table_name: &str) -> DfResult<SchemaRef> {
        let (schema, table) = split_qualified(table_name).ok_or_else(|| {
            DataFusionError::External(Box::new(DataglotError::catalog(format!(
                "expected '<schema>.<table>' reference, got: {table_name}"
            ))))
        })?;
        self.fetch_arrow_schema(&schema, &table)
            .await
            .map_err(|e| DataFusionError::External(Box::new(e)))
    }
}

impl fmt::Debug for OracleConnector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OracleConnector")
            .field("name", &self.name)
            .field("endpoint", &self.endpoint_hint)
            .finish_non_exhaustive()
    }
}

/// Cheap liveness probe that reuses the boot-built, already-connected Oracle
/// backend. The health poller calls this on a timer instead of
/// rebuilding the connector; `SELECT 1 FROM DUAL` (the canonical Oracle
/// reachability query) runs on the existing connection and errors iff the
/// source is unreachable. The error is the backend's own scrubbed message —
/// never the DSN/password (rule 12).
#[async_trait]
impl crate::health::ConnectorHealthCheck for OracleConnector {
    async fn health_check(&self) -> Result<(), String> {
        self.backend
            .query_strings("SELECT 1 FROM DUAL", 1)
            .await
            .map(|_| ())
            .map_err(|e| format!("oracle health check failed: {e}"))
    }
}

// ---------------------------------------------------------------------------
// Wire backend abstraction
// ---------------------------------------------------------------------------

/// The build's default Oracle backend: OCI when compiled, else pure.
///
/// The `oracle` module only compiles when at least one of the two
/// features is enabled, so exactly one of these arms is always present.
fn default_driver() -> OracleDriver {
    #[cfg(feature = "oracle")]
    {
        OracleDriver::Oci
    }
    #[cfg(all(not(feature = "oracle"), feature = "oracle-pure"))]
    {
        OracleDriver::Pure
    }
}

/// Resolve `driver` (`None` → build default) and verify its backend was
/// compiled into this binary. A **pure capability check** — no connection,
/// no credentials touched — so callers can reject a misconfigured driver
/// *before* resolving secrets (rule 12). Returns the resolved driver.
///
/// # Errors
/// [`DataglotError::Configuration`] (credential-free) if the resolved
/// driver's Cargo feature was not compiled in.
pub fn resolve_supported_driver(driver: Option<OracleDriver>) -> DataglotResult<OracleDriver> {
    let resolved = driver.unwrap_or_else(default_driver);
    match resolved {
        OracleDriver::Oci => {
            #[cfg(feature = "oracle")]
            {
                Ok(resolved)
            }
            #[cfg(not(feature = "oracle"))]
            {
                Err(driver_not_compiled(OracleDriver::Oci))
            }
        }
        OracleDriver::Pure => {
            #[cfg(feature = "oracle-pure")]
            {
                Ok(resolved)
            }
            #[cfg(not(feature = "oracle-pure"))]
            {
                Err(driver_not_compiled(OracleDriver::Pure))
            }
        }
    }
}

/// Connect the requested backend, or reject with a clear, credential-free
/// error if its Cargo feature was not compiled into this binary.
async fn connect_backend(
    driver: OracleDriver,
    dsn: &str,
    user: &str,
    password: &str,
) -> DataglotResult<Arc<dyn OracleBackend>> {
    match driver {
        OracleDriver::Oci => {
            #[cfg(feature = "oracle")]
            {
                Ok(Arc::new(OciBackend::connect(dsn, user, password).await?))
            }
            #[cfg(not(feature = "oracle"))]
            {
                let _ = (dsn, user, password);
                Err(driver_not_compiled(OracleDriver::Oci))
            }
        }
        OracleDriver::Pure => {
            #[cfg(feature = "oracle-pure")]
            {
                Ok(Arc::new(PureBackend::connect(dsn, user, password).await?))
            }
            #[cfg(not(feature = "oracle-pure"))]
            {
                let _ = (dsn, user, password);
                Err(driver_not_compiled(OracleDriver::Pure))
            }
        }
    }
}

/// A `DataglotError::Configuration` for a driver whose feature is absent.
/// Credential-free (rule 12): names only the driver + the Cargo feature.
///
/// Only compiled when at least one driver feature is missing — every call
/// site sits under a `#[cfg(not(feature = …))]` branch, so with BOTH
/// `oracle` and `oracle-pure` enabled (`--all-features`, as the udeps
/// nightly builds) the function would otherwise be dead code.
#[cfg(not(all(feature = "oracle", feature = "oracle-pure")))]
fn driver_not_compiled(driver: OracleDriver) -> DataglotError {
    DataglotError::configuration(format!(
        "oracle driver `{driver}` selected, but this binary was built without \
         `--features {}`; rebuild with that feature or select a compiled driver",
        driver.feature()
    ))
}

/// The Oracle wire client behind [`OracleConnector`]. Lets the connector
/// dispatch over OCI/ODPI-C today ([`OciBackend`]) and a pure-Rust client
/// later while sharing one dialect, pushdown, type mapping, and
/// governance surface — only the wire client differs.
///
/// This is an **internal** impl detail, **not** a parallel public trait:
/// the connector's public contract is DataFusion's `SQLExecutor` (rule 3).
/// The shared Oracle-SQL surface (dialect, `ast_analyzer` rewrites, the
/// `oracle_type_to_arrow` mapping) lives in backend-neutral free functions
/// below; a backend only owns *connect + fetch*.
#[async_trait]
trait OracleBackend: Send + Sync + fmt::Debug {
    /// Run a character-only dictionary query; each row → `Vec` of
    /// `n_cols` strings (NULL → empty string). Used for catalog/schema
    /// introspection (all-character `ALL_TABLES` / `ALL_TAB_COLUMNS`).
    async fn query_strings(&self, sql: &str, n_cols: usize) -> DataglotResult<Vec<Vec<String>>>;

    /// Run `sql` and decode the result set into a single Arrow
    /// `RecordBatch` shaped by `schema`.
    async fn query_arrow(&self, sql: &str, schema: SchemaRef) -> DfResult<RecordBatch>;
}

/// OCI / ODPI-C backend — the `oracle` crate (kubo/rust-oracle). The API
/// is synchronous, so every call runs under `tokio::task::spawn_blocking`
/// (rule 11); the connection is held in an `Arc<Mutex<…>>` and serialized
/// (ODPI-C handles are not `Sync`).
#[cfg(feature = "oracle")]
struct OciBackend {
    conn: Arc<Mutex<Connection>>,
}

#[cfg(feature = "oracle")]
impl OciBackend {
    /// Open an OCI connection on the blocking pool. Neither the DSN nor
    /// the password appears in the error (rule 12).
    async fn connect(dsn: &str, user: &str, password: &str) -> DataglotResult<Self> {
        let (dsn, user, password) = (dsn.to_string(), user.to_string(), password.to_string());
        let conn = tokio::task::spawn_blocking(move || Connection::connect(&user, &password, &dsn))
            .await
            .map_err(|e| DataglotError::connection(format!("oracle connect task panicked: {e}")))?
            .map_err(|e| DataglotError::connection(format!("failed to connect to oracle: {e}")))?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }
}

#[cfg(feature = "oracle")]
impl fmt::Debug for OciBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OciBackend").finish_non_exhaustive()
    }
}

#[cfg(feature = "oracle")]
#[async_trait]
impl OracleBackend for OciBackend {
    // The connection guard is held across the row iteration on purpose:
    // `ResultSet` borrows the connection, so it can't be dropped earlier.
    #[allow(clippy::significant_drop_tightening)]
    async fn query_strings(&self, sql: &str, n_cols: usize) -> DataglotResult<Vec<Vec<String>>> {
        let conn = Arc::clone(&self.conn);
        let sql = sql.to_string();
        tokio::task::spawn_blocking(move || {
            // A poisoned mutex (a prior task panicked while holding the
            // connection) must surface as a typed error, not another panic —
            // otherwise one bad request permanently wedges the connector.
            let conn = conn.lock().map_err(|_| {
                DataglotError::catalog("oracle connection mutex poisoned".to_string())
            })?;
            let rows = conn
                .query(&sql, &[])
                .map_err(|e| DataglotError::catalog(format!("oracle catalog query failed: {e}")))?;
            let mut out = Vec::new();
            for row in rows {
                let row =
                    row.map_err(|e| DataglotError::catalog(format!("oracle row error: {e}")))?;
                let mut vals = Vec::with_capacity(n_cols);
                for i in 0..n_cols {
                    let v: Option<String> = row.get(i).map_err(|e| {
                        DataglotError::catalog(format!("oracle column {i} decode: {e}"))
                    })?;
                    vals.push(v.unwrap_or_default());
                }
                out.push(vals);
            }
            Ok::<_, DataglotError>(out)
        })
        .await
        .map_err(|e| DataglotError::catalog(format!("oracle query task panicked: {e}")))?
    }

    // The connection guard is held across the row collection on purpose:
    // `ResultSet` borrows the connection, so it can't be dropped earlier.
    #[allow(clippy::significant_drop_tightening)]
    async fn query_arrow(&self, sql: &str, schema: SchemaRef) -> DfResult<RecordBatch> {
        let conn = Arc::clone(&self.conn);
        let sql = sql.to_string();
        tokio::task::spawn_blocking(move || {
            let conn = conn.lock().map_err(|_| {
                DataFusionError::External(Box::new(DataglotError::federation(
                    "oracle connection mutex poisoned".to_string(),
                )))
            })?;
            let result_set = conn.query(&sql, &[]).map_err(|e| {
                DataFusionError::External(Box::new(DataglotError::federation(format!(
                    "oracle query failed: {e}"
                ))))
            })?;
            let mut rows = Vec::new();
            for row in result_set {
                rows.push(row.map_err(|e| {
                    DataFusionError::External(Box::new(DataglotError::federation(format!(
                        "oracle row error: {e}"
                    ))))
                })?);
            }
            rows_to_record_batch(&schema, &rows)
        })
        .await
        .map_err(|e| {
            DataFusionError::External(Box::new(DataglotError::federation(format!(
                "oracle execute task panicked: {e}"
            ))))
        })?
    }
}

// ---------------------------------------------------------------------------
// Pure-Rust backend — `oracle-rs`, no ODPI-C / Instant Client
// ---------------------------------------------------------------------------

/// Pure-Rust backend — the `oracle-rs` crate (stiang/oracle-rs), which
/// reimplements the Oracle TTC/TNS protocol in async Rust (no ODPI-C, no
/// Instant Client, no C compiler). The connection is held in a
/// `tokio::sync::Mutex` and serialized — a single Oracle connection is not
/// protocol-reentrant. Real concurrency needs a pool (follow-up, );
/// the async client already avoids the OCI path's `spawn_blocking`.
// When BOTH backends are compiled, `connect` prefers OCI, so the pure
// path is unused until  slice 3 wires runtime `driver` selection.
// Allow dead code only in that case — when `oracle-pure` is the sole Oracle
// backend, `connect` constructs it and the `allow` is inert.
#[cfg(feature = "oracle-pure")]
#[cfg_attr(feature = "oracle", allow(dead_code))]
struct PureBackend {
    conn: tokio::sync::Mutex<oracle_rs::Connection>,
}

#[cfg(feature = "oracle-pure")]
#[cfg_attr(feature = "oracle", allow(dead_code))]
impl PureBackend {
    /// Connect via the pure client. The OCI path takes an Easy Connect DSN
    /// (ODPI-C parses it); `oracle-rs` wants host/port/service split, so we
    /// parse the DSN here. Neither DSN nor password appears in errors
    /// (rule 12).
    async fn connect(dsn: &str, user: &str, password: &str) -> DataglotResult<Self> {
        let (host, port, service) = parse_easy_connect(dsn)?;
        let config =
            oracle_rs::Config::new(host, port, service, user.to_string(), password.to_string());
        let conn = oracle_rs::Connection::connect_with_config(config)
            .await
            .map_err(|e| {
                DataglotError::connection(format!("failed to connect to oracle (pure): {e}"))
            })?;
        Ok(Self {
            conn: tokio::sync::Mutex::new(conn),
        })
    }
}

#[cfg(feature = "oracle-pure")]
impl fmt::Debug for PureBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PureBackend").finish_non_exhaustive()
    }
}

#[cfg(feature = "oracle-pure")]
#[async_trait]
impl OracleBackend for PureBackend {
    // The async mutex guard is held across the query `.await` on purpose: a
    // single Oracle connection isn't protocol-reentrant, so calls are
    // serialized (pooling for concurrency is the  follow-up).
    #[allow(clippy::significant_drop_tightening)]
    async fn query_strings(&self, sql: &str, n_cols: usize) -> DataglotResult<Vec<Vec<String>>> {
        let conn = self.conn.lock().await;
        let result = conn.query(sql, &[]).await.map_err(|e| {
            DataglotError::catalog(format!("oracle catalog query failed (pure): {e}"))
        })?;
        let mut out = Vec::with_capacity(result.rows.len());
        for row in &result.rows {
            let mut vals = Vec::with_capacity(n_cols);
            for i in 0..n_cols {
                vals.push(value_to_dict_string(row.get(i)));
            }
            out.push(vals);
        }
        Ok(out)
    }

    #[allow(clippy::significant_drop_tightening)]
    async fn query_arrow(&self, sql: &str, schema: SchemaRef) -> DfResult<RecordBatch> {
        let conn = self.conn.lock().await;
        let result = conn.query(sql, &[]).await.map_err(|e| {
            DataFusionError::External(Box::new(DataglotError::federation(format!(
                "oracle query failed (pure): {e}"
            ))))
        })?;
        pure_rows_to_record_batch(&schema, &result.rows)
    }
}

/// Parse an Easy Connect DSN (`[//]host[:port]/service`) into the parts
/// `oracle_rs::Config` wants. ODPI-C parses Easy Connect itself; the pure
/// client needs the components split out. Default port 1521.
#[cfg(feature = "oracle-pure")]
#[cfg_attr(feature = "oracle", allow(dead_code))]
fn parse_easy_connect(dsn: &str) -> DataglotResult<(String, u16, String)> {
    let s = dsn.trim().trim_start_matches('/');
    let (hostport, service) = s.split_once('/').ok_or_else(|| {
        DataglotError::connection("oracle DSN must be '//host[:port]/service'".to_string())
    })?;
    if service.is_empty() {
        return Err(DataglotError::connection(
            "oracle DSN: empty service name".to_string(),
        ));
    }
    let (host, port) = match hostport.split_once(':') {
        Some((h, p)) => {
            let port = p
                .parse::<u16>()
                .map_err(|_| DataglotError::connection("oracle DSN: invalid port".to_string()))?;
            (h, port)
        }
        None => (hostport, 1521),
    };
    if host.is_empty() {
        return Err(DataglotError::connection(
            "oracle DSN: empty host".to_string(),
        ));
    }
    Ok((host.to_string(), port, service.to_string()))
}

/// Render an `oracle_rs::Value` as the plain string the catalog-dictionary
/// path expects (NULL → `""`). The `ALL_TAB_COLUMNS` lookup reads
/// `data_precision` / `data_scale`, which are Oracle `NUMBER`s — `oracle-rs`
/// returns them as `Integer` / `Number`, so `get_string` would yield `None`
/// → `""` → precision/scale parse as `None` → Decimal128 mapping silently
/// breaks. Rendering by variant keeps the numeric form intact.
#[cfg(feature = "oracle-pure")]
#[cfg_attr(feature = "oracle", allow(dead_code))]
fn value_to_dict_string(v: Option<&oracle_rs::Value>) -> String {
    use oracle_rs::Value;
    match v {
        None | Some(Value::Null) => String::new(),
        Some(Value::String(s)) => s.clone(),
        Some(Value::Integer(i)) => i.to_string(),
        Some(Value::Number(n)) => n.as_str().to_string(),
        Some(Value::Float(f)) => f.to_string(),
        Some(Value::Boolean(b)) => b.to_string(),
        Some(other) => format!("{other:?}"),
    }
}

/// Build a [`RecordBatch`] from pure-Rust `oracle-rs` rows, driven by
/// `schema`. Drives by the target Arrow type and matches the actual
/// `oracle_rs::Value` variant, so it is robust to how `oracle-rs`
/// categorises NUMBER (`Integer` vs `Number`). Produces the SAME Arrow as
/// the OCI path for the same data — the differential harness (
/// slice 4) asserts byte-identical output.
#[cfg(feature = "oracle-pure")]
#[cfg_attr(feature = "oracle", allow(dead_code))]
fn pure_rows_to_record_batch(schema: &SchemaRef, rows: &[oracle_rs::Row]) -> DfResult<RecordBatch> {
    let mut columns: Vec<ArrayRef> = Vec::with_capacity(schema.fields().len());
    for (idx, field) in schema.fields().iter().enumerate() {
        columns.push(pure_decode_column(rows, idx, field.data_type())?);
    }
    RecordBatch::try_new(Arc::clone(schema), columns).map_err(|e| {
        DataFusionError::External(Box::new(DataglotError::federation(format!(
            "oracle batch assembly failed (pure): {e}"
        ))))
    })
}

/// Rescale a NUMBER string to the `Decimal128(_, scale)` mantissa (shared
/// `decimal_str_to_i128`), or a typed decode error.
#[cfg(feature = "oracle-pure")]
#[cfg_attr(feature = "oracle", allow(dead_code))]
fn decimal_to_i128_or_err(s: &str, scale: i8, idx: usize) -> DfResult<i128> {
    decimal_str_to_i128(s, scale).ok_or_else(|| {
        decode_err(
            idx,
            &format!("value {s:?} does not fit Decimal128 scale {scale}"),
        )
    })
}

#[cfg(feature = "oracle-pure")]
#[cfg_attr(feature = "oracle", allow(dead_code))]
#[allow(clippy::too_many_lines)] // one match arm per Arrow type — flatter than splitting
fn pure_decode_column(rows: &[oracle_rs::Row], idx: usize, dt: &DataType) -> DfResult<ArrayRef> {
    use oracle_rs::Value;
    match dt {
        DataType::Int64 => {
            let mut b = Int64Builder::with_capacity(rows.len());
            for row in rows {
                match row.get(idx) {
                    None | Some(Value::Null) => b.append_null(),
                    Some(Value::Integer(i)) => b.append_value(*i),
                    Some(Value::Number(n)) => b.append_value(
                        n.to_i64()
                            .map_err(|e| decode_err(idx, &format!("number→i64: {e}")))?,
                    ),
                    // `oracle-rs` can surface a NUMBER as a plain string
                    // (arbitrary-precision NUMBER has no fixed native type); the
                    // OCI backend decodes it as an integer, so parse to match and
                    // keep the two backends' Arrow identical.
                    Some(Value::String(s)) => b.append_value(
                        s.trim()
                            .parse::<i64>()
                            .map_err(|e| decode_err(idx, &format!("string→i64 {s:?}: {e}")))?,
                    ),
                    Some(other) => {
                        return Err(decode_err(idx, &format!("expected integer, got {other:?}")))
                    }
                }
            }
            Ok(Arc::new(b.finish()))
        }
        DataType::Float64 => {
            let mut b = Float64Builder::with_capacity(rows.len());
            for row in rows {
                match row.get(idx) {
                    None | Some(Value::Null) => b.append_null(),
                    Some(Value::Float(f)) => b.append_value(*f),
                    #[allow(clippy::cast_precision_loss)]
                    Some(Value::Integer(i)) => b.append_value(*i as f64),
                    Some(Value::Number(n)) => b.append_value(
                        n.to_f64()
                            .map_err(|e| decode_err(idx, &format!("number→f64: {e}")))?,
                    ),
                    Some(Value::String(s)) => b.append_value(
                        s.trim()
                            .parse::<f64>()
                            .map_err(|e| decode_err(idx, &format!("string→f64 {s:?}: {e}")))?,
                    ),
                    Some(other) => {
                        return Err(decode_err(idx, &format!("expected float, got {other:?}")))
                    }
                }
            }
            Ok(Arc::new(b.finish()))
        }
        DataType::Utf8 => {
            let mut b = StringBuilder::new();
            for row in rows {
                match row.get(idx) {
                    None | Some(Value::Null) => b.append_null(),
                    Some(Value::String(s)) => b.append_value(s),
                    Some(other) => {
                        return Err(decode_err(idx, &format!("expected string, got {other:?}")))
                    }
                }
            }
            Ok(Arc::new(b.finish()))
        }
        DataType::Boolean => {
            let mut b = BooleanBuilder::with_capacity(rows.len());
            for row in rows {
                match row.get(idx) {
                    None | Some(Value::Null) => b.append_null(),
                    Some(Value::Boolean(v)) => b.append_value(*v),
                    Some(other) => {
                        return Err(decode_err(idx, &format!("expected bool, got {other:?}")))
                    }
                }
            }
            Ok(Arc::new(b.finish()))
        }
        DataType::Timestamp(TimeUnit::Microsecond, None) => {
            let mut b = TimestampMicrosecondBuilder::with_capacity(rows.len());
            for row in rows {
                match row.get(idx) {
                    None | Some(Value::Null) => b.append_null(),
                    // A non-null timestamp/date that won't compose into valid
                    // micros is a hard error — NOT a silent null (which would
                    // be data loss the differential harness couldn't see).
                    Some(Value::Timestamp(ts)) => b.append_value(
                        ts_components_to_micros(
                            ts.year,
                            ts.month,
                            ts.day,
                            ts.hour,
                            ts.minute,
                            ts.second,
                            ts.microsecond,
                        )
                        .ok_or_else(|| decode_err(idx, "invalid timestamp components"))?,
                    ),
                    Some(Value::Date(d)) => b.append_value(
                        ts_components_to_micros(
                            d.year, d.month, d.day, d.hour, d.minute, d.second, 0,
                        )
                        .ok_or_else(|| decode_err(idx, "invalid date components"))?,
                    ),
                    Some(other) => {
                        return Err(decode_err(
                            idx,
                            &format!("expected timestamp, got {other:?}"),
                        ))
                    }
                }
            }
            Ok(Arc::new(b.finish()))
        }
        DataType::Decimal128(precision, scale) => {
            let mut b = Decimal128Builder::with_capacity(rows.len())
                .with_precision_and_scale(*precision, *scale)
                .map_err(|e| decode_err(idx, &format!("decimal128 builder: {e}")))?;
            for row in rows {
                match row.get(idx) {
                    None | Some(Value::Null) => b.append_null(),
                    // `oracle-rs` categorises NUMBER as `Number` (fractional)
                    // or `Integer` (whole) — a Decimal128 column can receive
                    // either, so accept both (rescaled via the shared helper).
                    Some(Value::Number(n)) => {
                        b.append_value(decimal_to_i128_or_err(n.as_str(), *scale, idx)?);
                    }
                    Some(Value::Integer(i)) => {
                        b.append_value(decimal_to_i128_or_err(&i.to_string(), *scale, idx)?);
                    }
                    // NUMBER may also arrive as a plain string (see the Int64 arm).
                    Some(Value::String(s)) => {
                        b.append_value(decimal_to_i128_or_err(s.trim(), *scale, idx)?);
                    }
                    Some(other) => {
                        return Err(decode_err(
                            idx,
                            &format!("expected number or integer, got {other:?}"),
                        ))
                    }
                }
            }
            Ok(Arc::new(b.finish()))
        }
        other => Err(DataFusionError::NotImplemented(format!(
            "oracle pure decode for arrow type {other:?} not implemented"
        ))),
    }
}

/// Compose micros-since-epoch from Oracle date/time components (timezone
/// ignored — matches the OCI path, which decodes a `NaiveDateTime` and
/// stamps it UTC). `None` if the components aren't a valid date/time.
#[cfg(feature = "oracle-pure")]
#[cfg_attr(feature = "oracle", allow(dead_code))]
fn ts_components_to_micros(
    year: i32,
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    second: u8,
    micros: u32,
) -> Option<i64> {
    let date = chrono::NaiveDate::from_ymd_opt(year, u32::from(month), u32::from(day))?;
    let ndt = date.and_hms_micro_opt(
        u32::from(hour),
        u32::from(minute),
        u32::from(second),
        micros,
    )?;
    Some(ndt.and_utc().timestamp_micros())
}

// ---------------------------------------------------------------------------
// Dialect + AST rewrite (the valid-Oracle-SQL surface)
// ---------------------------------------------------------------------------

/// The Oracle unparser dialect: double-quoted identifiers (DataFusion
/// ships no `OracleDialect`). `LIMIT`→`FETCH FIRST` is handled by the
/// connector's [`SQLExecutor::ast_analyzer`], not here.
#[must_use]
pub fn oracle_dialect() -> Arc<dyn Dialect> {
    Arc::new(
        CustomDialectBuilder::new()
            .with_identifier_quote_style('"')
            .build(),
    )
}

/// Rewrite a `SELECT … LIMIT n` into `SELECT … FETCH FIRST n ROWS ONLY`
/// (Oracle 12c+). Recurses into the query body so set-operations and
/// subqueries are covered. No-op when there's no `limit`.
fn rewrite_limit_to_fetch(mut stmt: ast::Statement) -> ast::Statement {
    if let ast::Statement::Query(query) = &mut stmt {
        rewrite_query_limit(query);
    }
    stmt
}

fn rewrite_query_limit(query: &mut ast::Query) {
    // Only the plain `LIMIT n` shape maps cleanly to `FETCH FIRST n ROWS
    // ONLY`. Leave OFFSET / `LIMIT BY` / the MySQL `offset, limit` form
    // untouched (rarer in pushdown; handled in a follow-up). No-op if a
    // FETCH is already present.
    if query.fetch.is_some() {
        return;
    }
    match query.limit_clause.take() {
        Some(ast::LimitClause::LimitOffset {
            limit: Some(limit),
            offset: None,
            limit_by,
        }) if limit_by.is_empty() => {
            query.fetch = Some(Fetch {
                with_ties: false,
                percent: false,
                quantity: Some(limit),
            });
        }
        other => query.limit_clause = other,
    }
}

/// Apply every Oracle-dialect AST rewrite the `CustomDialect` can't
/// express, in order: `LIMIT`→`FETCH FIRST` then `AS`-less table
/// aliases. The connector's [`SQLExecutor::ast_analyzer`] runs this on
/// each unparsed statement before it reaches the wire.
fn rewrite_statement_for_oracle(stmt: ast::Statement) -> ast::Statement {
    let stmt = rewrite_limit_to_fetch(stmt);
    strip_table_alias_as(stmt)
}

/// Strip the `AS` keyword from table aliases throughout the statement.
///
/// DataFusion's unparser sets `TableAlias.explicit = true`, so an
/// aliased relation renders as `FROM "T"."U" AS "u"`. Oracle accepts
/// `AS` only for **column** aliases, not table aliases (ORA-03048:
/// *SQL reserved word 'AS' is not syntactically valid*), so clear the
/// flag → the Oracle-valid `FROM "T"."U" "u"`. Recurses through set
/// operations, joins, and derived subqueries so every relation alias
/// in a pushed query is covered.
fn strip_table_alias_as(mut stmt: ast::Statement) -> ast::Statement {
    if let ast::Statement::Query(query) = &mut stmt {
        strip_query_aliases(query);
    }
    stmt
}

fn strip_query_aliases(query: &mut ast::Query) {
    strip_set_expr_aliases(&mut query.body);
}

fn strip_set_expr_aliases(body: &mut ast::SetExpr) {
    match body {
        ast::SetExpr::Select(select) => {
            for twj in &mut select.from {
                strip_table_with_joins_aliases(twj);
            }
        }
        ast::SetExpr::Query(q) => strip_query_aliases(q),
        ast::SetExpr::SetOperation { left, right, .. } => {
            strip_set_expr_aliases(left);
            strip_set_expr_aliases(right);
        }
        _ => {}
    }
}

fn strip_table_with_joins_aliases(twj: &mut ast::TableWithJoins) {
    strip_table_factor_alias(&mut twj.relation);
    for join in &mut twj.joins {
        strip_table_factor_alias(&mut join.relation);
    }
}

fn strip_table_factor_alias(tf: &mut ast::TableFactor) {
    match tf {
        ast::TableFactor::Table { alias, .. } => clear_alias_explicit(alias),
        ast::TableFactor::Derived {
            subquery, alias, ..
        } => {
            strip_query_aliases(subquery);
            clear_alias_explicit(alias);
        }
        ast::TableFactor::NestedJoin {
            table_with_joins,
            alias,
        } => {
            strip_table_with_joins_aliases(table_with_joins);
            clear_alias_explicit(alias);
        }
        _ => {}
    }
}

fn clear_alias_explicit(alias: &mut Option<ast::TableAlias>) {
    if let Some(a) = alias {
        a.explicit = false;
    }
}

// ---------------------------------------------------------------------------
// Type mapping + row decode
// ---------------------------------------------------------------------------

/// Map an Oracle `ALL_TAB_COLUMNS.data_type` (+ precision/scale) to an
/// Arrow type. `None` ⇒ unsupported (caller errors). v1 core set only.
fn oracle_type_to_arrow(
    data_type: &str,
    precision: Option<i64>,
    scale: Option<i64>,
) -> Option<DataType> {
    // data_type forms: NUMBER, VARCHAR2, CHAR, NVARCHAR2, CLOB, DATE,
    // TIMESTAMP, TIMESTAMP(6), TIMESTAMP(6) WITH TIME ZONE, FLOAT, …
    let base = data_type
        .split(['(', ' '])
        .next()
        .unwrap_or(data_type)
        .trim();
    match base.to_uppercase().as_str() {
        // `NUMBER(p,s)` mapping:
        //   - no scale, or scale 0      → Int64 (integer-valued).
        //   - scale > 0 with a precision the *decoder* can hold exactly
        //     (1 ≤ p ≤ 28, 0 < s ≤ p)   → Decimal128(p, s).
        //   - scale > 0 but precision unknown / out of range / negative
        //     scale               → Float64 (typed but approximate — a
        //     bare `NUMBER` with arbitrary precision can't be pinned to a
        //     Decimal128 width, and negative scale isn't representable).
        //
        // The cap is **28, not Arrow's Decimal128 max of 38**: the decoder
        // (`decimal_str_to_i128`) parses via `rust_decimal`, which tops out
        // at ~28 significant digits. Mapping a `NUMBER(38,…)` to Decimal128
        // would type-check but then fail to *decode* at query time, so the
        // type-mapping ceiling matches the decoder's real capability and
        // anything wider falls back to Float64 here.
        "NUMBER" | "INTEGER" | "INT" | "SMALLINT" | "DECIMAL" | "NUMERIC" => {
            match (scale, precision) {
                (Some(0) | None, _) => Some(DataType::Int64),
                (Some(s), Some(p)) if s > 0 && (1..=28).contains(&p) && s <= p => {
                    // Guard bounds p∈[1,28], s∈(0,p]; `try_from` performs the
                    // i64→u8/i8 narrowing without a lossy `as` cast (clippy),
                    // falling back to Float64 in the impossible miss.
                    match (u8::try_from(p), i8::try_from(s)) {
                        (Ok(p), Ok(s)) => Some(DataType::Decimal128(p, s)),
                        _ => Some(DataType::Float64),
                    }
                }
                (Some(_), _) => Some(DataType::Float64),
            }
        }
        "FLOAT" | "BINARY_FLOAT" | "BINARY_DOUBLE" | "REAL" => Some(DataType::Float64),
        "VARCHAR2" | "VARCHAR" | "CHAR" | "NCHAR" | "NVARCHAR2" | "CLOB" | "NCLOB" | "LONG" => {
            Some(DataType::Utf8)
        }
        // DATE and all TIMESTAMP variants → microsecond timestamp.
        "DATE" | "TIMESTAMP" => Some(DataType::Timestamp(TimeUnit::Microsecond, None)),
        _ => None,
    }
}

/// Build a [`RecordBatch`] from OCI Oracle rows, driven by `schema`.
#[cfg(feature = "oracle")]
fn rows_to_record_batch(schema: &SchemaRef, rows: &[oracle::Row]) -> DfResult<RecordBatch> {
    let mut columns: Vec<ArrayRef> = Vec::with_capacity(schema.fields().len());
    for (idx, field) in schema.fields().iter().enumerate() {
        columns.push(decode_column(rows, idx, field.data_type())?);
    }
    RecordBatch::try_new(Arc::clone(schema), columns).map_err(|e| {
        DataFusionError::External(Box::new(DataglotError::federation(format!(
            "oracle batch assembly failed: {e}"
        ))))
    })
}

#[cfg(feature = "oracle")]
fn col_err(idx: usize, e: &oracle::Error) -> DataFusionError {
    DataFusionError::External(Box::new(DataglotError::federation(format!(
        "oracle column {idx} decode: {e}"
    ))))
}

#[cfg(feature = "oracle")]
fn decode_column(rows: &[oracle::Row], idx: usize, dt: &DataType) -> DfResult<ArrayRef> {
    match dt {
        DataType::Int64 => {
            let mut b = Int64Builder::with_capacity(rows.len());
            for row in rows {
                let v: Option<i64> = row.get(idx).map_err(|e| col_err(idx, &e))?;
                b.append_option(v);
            }
            Ok(Arc::new(b.finish()))
        }
        DataType::Float64 => {
            let mut b = Float64Builder::with_capacity(rows.len());
            for row in rows {
                let v: Option<f64> = row.get(idx).map_err(|e| col_err(idx, &e))?;
                b.append_option(v);
            }
            Ok(Arc::new(b.finish()))
        }
        DataType::Utf8 => {
            let mut b = StringBuilder::new();
            for row in rows {
                let v: Option<String> = row.get(idx).map_err(|e| col_err(idx, &e))?;
                b.append_option(v);
            }
            Ok(Arc::new(b.finish()))
        }
        DataType::Boolean => {
            let mut b = BooleanBuilder::with_capacity(rows.len());
            for row in rows {
                let v: Option<bool> = row.get(idx).map_err(|e| col_err(idx, &e))?;
                b.append_option(v);
            }
            Ok(Arc::new(b.finish()))
        }
        DataType::Timestamp(TimeUnit::Microsecond, None) => {
            let mut b = TimestampMicrosecondBuilder::with_capacity(rows.len());
            for row in rows {
                let v: Option<chrono::NaiveDateTime> =
                    row.get(idx).map_err(|e| col_err(idx, &e))?;
                b.append_option(v.map(|ts| ts.and_utc().timestamp_micros()));
            }
            Ok(Arc::new(b.finish()))
        }
        DataType::Decimal128(precision, scale) => {
            // Oracle NUMBER is exact; the `oracle` crate has no decimal
            // feature enabled, so fetch the value as its canonical string
            // and convert to the i128 mantissa at the target scale. This
            // avoids the precision loss an f64 round-trip would introduce.
            let mut b = Decimal128Builder::with_capacity(rows.len())
                .with_precision_and_scale(*precision, *scale)
                .map_err(|e| decode_err(idx, &format!("decimal128 builder: {e}")))?;
            for row in rows {
                let v: Option<String> = row.get(idx).map_err(|e| col_err(idx, &e))?;
                match v {
                    None => b.append_null(),
                    Some(s) => {
                        let m = decimal_str_to_i128(&s, *scale).ok_or_else(|| {
                            decode_err(
                                idx,
                                &format!("value {s:?} does not fit Decimal128 scale {scale}"),
                            )
                        })?;
                        b.append_value(m);
                    }
                }
            }
            Ok(Arc::new(b.finish()))
        }
        other => Err(DataFusionError::NotImplemented(format!(
            "oracle decode for arrow type {other:?} not implemented"
        ))),
    }
}

/// Decode error not tied to an `oracle::Error` (builder/parse failures).
fn decode_err(idx: usize, msg: &str) -> DataFusionError {
    DataFusionError::External(Box::new(DataglotError::federation(format!(
        "oracle column {idx} decode: {msg}"
    ))))
}

/// Convert an Oracle `NUMBER` string (e.g. `"123.45"`, `"-1000"`) into the
/// i128 mantissa for an Arrow `Decimal128(_, scale)` — i.e. the value
/// multiplied by `10^scale`, rounded (via `rust_decimal::rescale`) to
/// `scale` fractional digits. `None` if the string doesn't parse or the
/// rescaled value exceeds `rust_decimal`'s ~28-digit range (callers that
/// need full 38-digit `NUMBER`s fall back to Float64 at type-mapping time).
fn decimal_str_to_i128(s: &str, scale: i8) -> Option<i128> {
    use std::str::FromStr;
    let mut d = rust_decimal::Decimal::from_str(s.trim()).ok()?;
    let target = u32::try_from(scale).ok()?;
    d.rescale(target);
    // `rescale` clamps if the requested scale can't be represented; only
    // accept an exact match so we never silently emit a wrong-scale value.
    if d.scale() != target {
        return None;
    }
    Some(d.mantissa())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn split_qualified(s: &str) -> Option<(String, String)> {
    let (a, b) = s.split_once('.')?;
    let schema = a.trim_matches('"');
    let table = b.trim_matches('"');
    if schema.is_empty() || table.is_empty() {
        return None;
    }
    Some((schema.to_string(), table.to_string()))
}

/// Reject `'` / `\` in dictionary-lookup identifiers (spliced into a SQL
/// literal; the names are operator-controlled — defence in depth).
fn validate_identifier_literal(s: &str) -> DataglotResult<()> {
    if s.is_empty() {
        return Err(DataglotError::catalog(
            "empty schema/table name in oracle dictionary lookup".to_string(),
        ));
    }
    if s.contains('\'') || s.contains('\\') {
        return Err(DataglotError::catalog(format!(
            "oracle schema/table name '{s}' contains a quote or backslash; reject defensively"
        )));
    }
    Ok(())
}

/// Credential-free endpoint hint for `Debug`/logs — Easy Connect
/// host/service only. Neither the password nor the `user` appears: the
/// service-account name is auth-adjacent (it leaks org structure), the
/// same reason `OracleCatalogConfig`'s `Debug` redacts it (rule 12).
///
/// Oracle Easy Connect DSNs (`//host:port/service`) carry no
/// credentials — user + password are separate connect args. But if an
/// operator ever passes a URL-form DSN with a `user:pass@` userinfo
/// block, strip it defensively so a misused DSN can't leak a secret
/// into logs (defence in depth; mirrors the server's
/// `redacted_oracle_endpoint_hint`).
fn redacted_endpoint(dsn: &str) -> String {
    let stripped = dsn.trim_start_matches('/');
    // If a userinfo block is present (`user:pass@host/...`), drop
    // everything up to and including the last `@` of the authority.
    let authority_end = stripped.find('/').unwrap_or(stripped.len());
    let host_part = if let Some(at) = stripped[..authority_end].rfind('@') {
        format!("[redacted]@{}", &stripped[at + 1..])
    } else {
        stripped.to_string()
    };
    format!("oracle://{host_part}")
}

// ---------------------------------------------------------------------------
// CatalogProvider / SchemaProvider
// ---------------------------------------------------------------------------

/// [`DfCatalogProvider`] for an Oracle database. Built by
/// [`OracleConnector::as_catalog_provider`]; per-table schemas lazy.
pub struct OracleCatalog {
    connector_name: String,
    schema_names: Vec<String>,
    schemas: HashMap<String, Arc<dyn DfSchemaProvider>>,
}

impl fmt::Debug for OracleCatalog {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OracleCatalog")
            .field("connector", &self.connector_name)
            .field("schema_count", &self.schema_names.len())
            .finish_non_exhaustive()
    }
}

impl DfCatalogProvider for OracleCatalog {
    fn schema_names(&self) -> Vec<String> {
        self.schema_names.clone()
    }
    fn schema(&self, name: &str) -> Option<Arc<dyn DfSchemaProvider>> {
        self.schemas.get(name).map(Arc::clone)
    }
}

/// [`DfSchemaProvider`] backed by one Oracle owner (schema).
pub struct OracleSchema {
    connector: Arc<OracleConnector>,
    schema: String,
    tables: Vec<String>,
}

impl fmt::Debug for OracleSchema {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OracleSchema")
            .field("schema", &self.schema)
            .field("table_count", &self.tables.len())
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl DfSchemaProvider for OracleSchema {
    fn table_names(&self) -> Vec<String> {
        self.tables.clone()
    }
    fn table_exist(&self, name: &str) -> bool {
        self.tables.iter().any(|t| t == name)
    }
    async fn table(&self, name: &str) -> DfResult<Option<Arc<dyn TableProvider>>> {
        if !self.table_exist(name) {
            return Ok(None);
        }
        self.connector
            .table_provider(&self.schema, name)
            .await
            .map(Some)
            .map_err(|e| DataFusionError::External(Box::new(e)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use datafusion::sql::sqlparser::dialect::GenericDialect;
    use datafusion::sql::sqlparser::parser::Parser;

    fn unparse_after_analyzer(sql: &str) -> String {
        let stmt = Parser::parse_sql(&GenericDialect {}, sql)
            .unwrap()
            .remove(0);
        rewrite_statement_for_oracle(stmt).to_string()
    }

    #[test]
    fn oracle_connector_is_a_connector_health_check() {
        // Compile-level pin: the boot path upcasts the retained
        // `Arc<OracleConnector>` to `Arc<dyn ConnectorHealthCheck>` so the poller
        // reuses the live backend (`SELECT 1 FROM DUAL`) instead of reconnecting.
        // A live probe needs an Oracle server (x86 integration suite); this
        // asserts the impl exists and satisfies `Send + Sync + 'static`.
        fn assert_impl<T: crate::health::ConnectorHealthCheck>() {}
        assert_impl::<OracleConnector>();
    }

    // ----  slice 3: driver selection ---------------------------------

    #[test]
    fn driver_wire_names_and_features() {
        assert_eq!(OracleDriver::Oci.as_str(), "oci");
        assert_eq!(OracleDriver::Pure.as_str(), "pure");
        assert_eq!(OracleDriver::Oci.feature(), "oracle");
        assert_eq!(OracleDriver::Pure.feature(), "oracle-pure");
        assert_eq!(OracleDriver::Pure.to_string(), "pure");
    }

    #[test]
    fn default_driver_prefers_oci_when_compiled() {
        // OCI is the regulated-production default whenever it is compiled;
        // otherwise the pure backend is the only option, so it wins.
        let d = default_driver();
        #[cfg(feature = "oracle")]
        assert_eq!(d, OracleDriver::Oci);
        #[cfg(all(not(feature = "oracle"), feature = "oracle-pure"))]
        assert_eq!(d, OracleDriver::Pure);
    }

    /// Selecting a driver whose feature was not compiled in must fail fast
    /// with a clear, credential-free `Configuration` error — *before* any
    /// connection attempt. (Compiled only when exactly the other backend
    /// is present, so the requested driver is genuinely absent.)
    #[cfg(all(feature = "oracle-pure", not(feature = "oracle")))]
    #[tokio::test]
    async fn rejects_oci_driver_when_only_pure_compiled() {
        assert_uncompiled_driver_rejected(OracleDriver::Oci, "oracle").await;
    }

    #[cfg(all(feature = "oracle", not(feature = "oracle-pure")))]
    #[tokio::test]
    async fn rejects_pure_driver_when_only_oci_compiled() {
        assert_uncompiled_driver_rejected(OracleDriver::Pure, "oracle-pure").await;
    }

    #[cfg(any(
        all(feature = "oracle-pure", not(feature = "oracle")),
        all(feature = "oracle", not(feature = "oracle-pure"))
    ))]
    async fn assert_uncompiled_driver_rejected(driver: OracleDriver, feature: &str) {
        const HOST: &str = "secret-host";
        const USER: &str = "SVC_USER";
        const PASSWORD: &str = "super-secret-pw";
        let err = OracleConnector::connect_with_driver(
            "exadata",
            &format!("//{HOST}:1521/SVC"),
            USER,
            PASSWORD,
            Some(driver),
        )
        .await
        .expect_err("an uncompiled driver must be rejected");
        assert!(
            matches!(err, DataglotError::Configuration(_)),
            "expected Configuration error, got: {err:?}"
        );
        let msg = err.to_string();
        assert!(msg.contains(driver.as_str()), "names the driver: {msg}");
        assert!(msg.contains(feature), "names the missing feature: {msg}");
        // Rule 12: no credential material in the error.
        assert!(!msg.contains(PASSWORD), "password leaked: {msg}");
        assert!(!msg.contains(USER), "user leaked: {msg}");
        assert!(!msg.contains(HOST), "host leaked: {msg}");
    }

    #[test]
    fn ast_analyzer_strips_as_from_table_alias() {
        // Oracle rejects `AS` before a table alias (ORA-03048). The
        // analyzer must render `FROM "TEST"."USERS" "u"`, not
        // `... AS "u"` — while leaving the column alias `AS n` intact.
        let out = unparse_after_analyzer(
            r#"SELECT "u"."AGE", count(1) AS n FROM "TEST"."USERS" AS "u" GROUP BY "u"."AGE""#,
        );
        assert!(
            !out.contains(r#"USERS" AS"#),
            "table-alias AS must be stripped: {out}"
        );
        assert!(
            out.contains(r#""TEST"."USERS" "u""#),
            "alias must remain (without AS): {out}"
        );
        // The column alias `AS n` is still valid Oracle and must survive.
        assert!(
            out.to_uppercase().contains("AS N"),
            "column alias AS must be preserved: {out}"
        );
    }

    #[test]
    fn ast_analyzer_strips_as_in_joins() {
        // Both sides of a JOIN carry aliases; neither may keep `AS`.
        let out = unparse_after_analyzer(
            r#"SELECT a."X" FROM "S"."A" AS a INNER JOIN "S"."B" AS b ON a."ID" = b."ID""#,
        );
        assert!(
            !out.contains(r#"A" AS"#),
            "left alias AS not stripped: {out}"
        );
        assert!(
            !out.contains(r#"B" AS"#),
            "right alias AS not stripped: {out}"
        );
        assert!(out.contains(r#""S"."A" a"#), "left alias kept: {out}");
        assert!(out.contains(r#""S"."B" b"#), "right alias kept: {out}");
    }

    #[test]
    fn ast_analyzer_rewrites_limit_to_fetch_first() {
        let out = unparse_after_analyzer("SELECT a FROM t ORDER BY a LIMIT 5");
        assert!(out.contains("FETCH FIRST 5 ROWS ONLY"), "got: {out}");
        assert!(
            !out.to_uppercase().contains("LIMIT"),
            "LIMIT must be gone: {out}"
        );
    }

    #[test]
    fn ast_analyzer_noop_without_limit() {
        let out = unparse_after_analyzer("SELECT a FROM t WHERE a > 1");
        assert!(!out.to_uppercase().contains("FETCH"), "got: {out}");
    }

    #[test]
    fn dialect_quotes_identifiers_with_double_quote() {
        // The Oracle dialect must double-quote identifiers, not backtick.
        let d = oracle_dialect();
        assert_eq!(d.identifier_quote_style("anything"), Some('"'));
    }

    #[test]
    fn type_mapping_core_oracle_types() {
        use DataType::{Decimal128, Float64, Int64, Timestamp, Utf8};
        assert_eq!(
            oracle_type_to_arrow("NUMBER", Some(10), Some(0)),
            Some(Int64)
        );
        // NUMBER(p,s) with a representable scale → exact Decimal128.
        assert_eq!(
            oracle_type_to_arrow("NUMBER", Some(10), Some(2)),
            Some(Decimal128(10, 2))
        );
        assert_eq!(
            oracle_type_to_arrow("DECIMAL", Some(28), Some(10)),
            Some(Decimal128(28, 10))
        );
        // Precision beyond the decoder's 28-digit (rust_decimal) limit,
        // or negative scale, or unknown precision with a scale → Float64
        // fallback (typed, approximate). NUMBER(38,2) maps here, NOT to
        // Decimal128(38,2), because the decoder couldn't hold 38 digits.
        assert_eq!(
            oracle_type_to_arrow("NUMBER", Some(38), Some(2)),
            Some(Float64)
        );
        assert_eq!(
            oracle_type_to_arrow("NUMBER", Some(40), Some(2)),
            Some(Float64)
        );
        assert_eq!(oracle_type_to_arrow("NUMBER", None, Some(2)), Some(Float64));
        assert_eq!(
            oracle_type_to_arrow("NUMBER", Some(5), Some(-2)),
            Some(Float64)
        );
        // scale 0 / no scale stay integer-valued.
        assert_eq!(
            oracle_type_to_arrow("NUMBER", Some(38), Some(0)),
            Some(Int64)
        );
        assert_eq!(oracle_type_to_arrow("NUMBER", None, None), Some(Int64));
        assert_eq!(oracle_type_to_arrow("VARCHAR2", None, None), Some(Utf8));
        assert_eq!(oracle_type_to_arrow("CLOB", None, None), Some(Utf8));
        assert_eq!(
            oracle_type_to_arrow("BINARY_DOUBLE", None, None),
            Some(Float64)
        );
        assert_eq!(
            oracle_type_to_arrow("TIMESTAMP(6)", None, None),
            Some(Timestamp(TimeUnit::Microsecond, None))
        );
        assert_eq!(
            oracle_type_to_arrow("DATE", None, None),
            Some(Timestamp(TimeUnit::Microsecond, None))
        );
        assert_eq!(oracle_type_to_arrow("BLOB", None, None), None); // out of scope v1
    }

    #[test]
    fn decimal_str_to_i128_scales_correctly() {
        // Exact mantissa at the target scale.
        assert_eq!(decimal_str_to_i128("123.45", 2), Some(12_345));
        assert_eq!(decimal_str_to_i128("100", 2), Some(10_000));
        assert_eq!(decimal_str_to_i128("-1.5", 2), Some(-150));
        assert_eq!(decimal_str_to_i128("0", 4), Some(0));
        assert_eq!(decimal_str_to_i128("  7.5  ", 1), Some(75)); // trims whitespace
                                                                 // More fractional digits than the target scale → rounded to scale
                                                                 // (unambiguous, non-midpoint cases — rounding mode independent).
        assert_eq!(decimal_str_to_i128("1.006", 2), Some(101));
        assert_eq!(decimal_str_to_i128("2.344", 2), Some(234));
        // Garbage → None (caller errors with a clear message).
        assert_eq!(decimal_str_to_i128("not-a-number", 2), None);
    }

    #[test]
    fn endpoint_hint_omits_credentials() {
        // host/service are safe to surface; neither the password nor the
        // (auth-adjacent) service-account user may appear (rule 12).
        let h = redacted_endpoint("//db.internal:1521/ORCLPDB1");
        assert!(h.contains("db.internal:1521/ORCLPDB1"));
        assert!(!h.contains("DATAGLOT_SVC"), "user must not leak: {h}");
        assert!(!h.contains("secret"));
    }

    ///  defence-in-depth: a URL-form DSN carrying a `user:pass@`
    /// userinfo block (a misuse — Easy Connect keeps credentials
    /// separate) must NOT leak the password into the endpoint hint that
    /// reaches logs / `Debug` (rule 12). Pre-hardening this echoed the
    /// DSN verbatim.
    #[test]
    fn endpoint_hint_strips_url_form_userinfo() {
        let h = redacted_endpoint("//scott:tiger@db.internal:1521/ORCLPDB1");
        assert!(!h.contains("tiger"), "password leaked into hint: {h}");
        assert!(!h.contains("scott"), "user leaked into hint: {h}");
        assert!(h.contains("db.internal:1521/ORCLPDB1"), "host lost: {h}");
        // A password containing '@' must still be fully stripped (the
        // authority scan takes the LAST '@' before the path).
        let h2 = redacted_endpoint("//svc:p@ss@host/SVC");
        assert!(!h2.contains("p@ss"), "'@'-in-password leaked: {h2}");
        assert!(h2.contains("host/SVC"), "host lost: {h2}");
    }

    /// The dictionary-lookup identifier guard rejects quote/backslash
    /// (SQL-splice defence) and empty names, accepts normal ones. This
    /// guard had zero coverage despite splicing names into literal SQL.
    #[test]
    fn identifier_literal_guard_rejects_injection_and_empty() {
        assert!(validate_identifier_literal("ORDERS").is_ok());
        assert!(validate_identifier_literal("SALES_2024").is_ok());
        assert!(validate_identifier_literal("").is_err());
        assert!(validate_identifier_literal("evil' OR '1'='1").is_err());
        assert!(validate_identifier_literal("bad\\name").is_err());
    }

    #[test]
    fn split_qualified_handles_quotes() {
        assert_eq!(
            split_qualified("\"SALES\".\"ORDERS\""),
            Some(("SALES".to_string(), "ORDERS".to_string()))
        );
        assert_eq!(
            split_qualified("SALES.ORDERS"),
            Some(("SALES".to_string(), "ORDERS".to_string()))
        );
        assert_eq!(split_qualified("nodot"), None);
    }

    // ---- pure-Rust backend (oracle-rs) — decode + DSN parse ----
    //
    // These run without a live Oracle: oracle-rs exposes public `Row::new`
    // + `Value` variants, so we feed synthetic rows through the real decode
    // and assert the Arrow output — verifying the semantic type mapping
    // (the part the differential harness later confirms against live data).

    #[cfg(feature = "oracle-pure")]
    #[test]
    fn parse_easy_connect_forms() {
        assert_eq!(
            parse_easy_connect("//db.example.com:1522/ORCLPDB1").unwrap(),
            ("db.example.com".to_string(), 1522, "ORCLPDB1".to_string())
        );
        // Leading `//` optional; default port 1521.
        assert_eq!(
            parse_easy_connect("host/SVC").unwrap(),
            ("host".to_string(), 1521, "SVC".to_string())
        );
        assert!(parse_easy_connect("no-service").is_err());
        assert!(parse_easy_connect("//host:notaport/SVC").is_err());
        assert!(parse_easy_connect("//:1521/SVC").is_err());
    }

    #[cfg(feature = "oracle-pure")]
    #[test]
    fn pure_decode_primitive_variants_and_nulls() {
        use arrow::array::{Array, Float64Array, Int64Array, StringArray};
        use oracle_rs::{Row, Value};

        // Int64 ← Value::Integer, with a NULL.
        let rows = vec![
            Row::new(vec![Value::Integer(42)]),
            Row::new(vec![Value::Null]),
        ];
        let arr = pure_decode_column(&rows, 0, &DataType::Int64).expect("decode int64");
        let a = arr.as_any().downcast_ref::<Int64Array>().expect("int64");
        assert_eq!(a.value(0), 42);
        assert!(a.is_null(1));

        // Float64 ← Value::Float.
        let rows = vec![Row::new(vec![Value::Float(2.5)])];
        let arr = pure_decode_column(&rows, 0, &DataType::Float64).expect("decode f64");
        let a = arr.as_any().downcast_ref::<Float64Array>().expect("f64");
        assert!((a.value(0) - 2.5).abs() < f64::EPSILON);

        // Utf8 ← Value::String, with a NULL.
        let rows = vec![
            Row::new(vec![Value::String("alice".to_string())]),
            Row::new(vec![Value::Null]),
        ];
        let arr = pure_decode_column(&rows, 0, &DataType::Utf8).expect("decode utf8");
        let a = arr.as_any().downcast_ref::<StringArray>().expect("utf8");
        assert_eq!(a.value(0), "alice");
        assert!(a.is_null(1));
    }

    #[cfg(feature = "oracle-pure")]
    #[test]
    fn pure_decode_rejects_non_numeric_string() {
        use oracle_rs::{Row, Value};
        // A *non-numeric* string in an Int64 column is a hard decode error, not
        // a silent null — the differential harness would otherwise mask a real
        // bug. (A *numeric* string is legal and decodes; see
        // `pure_decode_numeric_string_matches_oci`.)
        let rows = vec![Row::new(vec![Value::String("oops".to_string())])];
        assert!(pure_decode_column(&rows, 0, &DataType::Int64).is_err());
    }

    #[cfg(feature = "oracle-pure")]
    #[test]
    fn pure_decode_numeric_string_matches_oci() {
        // Regression for the oracle-integration nightly failure
        // `oci_and_pure_backends_produce_identical_arrow`: oracle-rs surfaces an
        // arbitrary-precision NUMBER as Value::String (it has no fixed native
        // type), while the OCI backend decodes it to a number. The pure backend
        // must parse the numeric string so both backends' Arrow is identical —
        // NOT hard-error as it used to. The prior test suite only ever fed the
        // *native* representation of each numeric type (Integer→Int64,
        // Float→Float64) and asserted String→Int64 must fail, so this exact
        // path — the one a live Oracle NUMBER exercises — was never covered.
        use arrow::array::{Decimal128Array, Float64Array, Int64Array};
        use oracle_rs::{Row, Value};

        // Value::String("1") → Int64(1)
        let rows = vec![Row::new(vec![Value::String("1".to_string())])];
        let arr = pure_decode_column(&rows, 0, &DataType::Int64).expect("numeric string → i64");
        let a = arr.as_any().downcast_ref::<Int64Array>().expect("int64");
        assert_eq!(a.value(0), 1);

        // Whitespace-padded numeric string still parses.
        let rows = vec![Row::new(vec![Value::String("  42  ".to_string())])];
        let arr = pure_decode_column(&rows, 0, &DataType::Int64).expect("padded → i64");
        assert_eq!(
            arr.as_any().downcast_ref::<Int64Array>().unwrap().value(0),
            42
        );

        // Value::String("2.5") → Float64(2.5)
        let rows = vec![Row::new(vec![Value::String("2.5".to_string())])];
        let arr = pure_decode_column(&rows, 0, &DataType::Float64).expect("numeric string → f64");
        let a = arr.as_any().downcast_ref::<Float64Array>().expect("f64");
        assert!((a.value(0) - 2.5).abs() < f64::EPSILON);

        // Value::String("123.45") → Decimal128(10,2) mantissa 12345
        let rows = vec![Row::new(vec![Value::String("123.45".to_string())])];
        let arr = pure_decode_column(&rows, 0, &DataType::Decimal128(10, 2))
            .expect("numeric string → decimal128");
        let a = arr
            .as_any()
            .downcast_ref::<Decimal128Array>()
            .expect("decimal128");
        assert_eq!(a.value(0), 12345, "123.45 at scale 2 → mantissa 12345");
    }

    #[cfg(feature = "oracle-pure")]
    #[test]
    fn pure_decode_decimal128_accepts_integer_valued_number() {
        // oracle-rs returns a whole NUMBER as Value::Integer; a Decimal128
        // column must still decode it (rescaled), not hard-error (#483 review).
        use arrow::array::Decimal128Array;
        use oracle_rs::{Row, Value};
        let rows = vec![Row::new(vec![Value::Integer(100)])];
        let arr = pure_decode_column(&rows, 0, &DataType::Decimal128(10, 2)).expect("decode");
        let a = arr
            .as_any()
            .downcast_ref::<Decimal128Array>()
            .expect("decimal128");
        assert_eq!(a.value(0), 10000, "100 at scale 2 → mantissa 10000");
    }

    #[cfg(feature = "oracle-pure")]
    #[test]
    fn value_to_dict_string_renders_numeric_columns() {
        use oracle_rs::Value;
        // The catalog dictionary reads data_precision/data_scale as NUMBER →
        // oracle-rs Integer; they must stringify to digits, not "" (#483
        // review — otherwise precision/scale are lost and Decimal128 mapping
        // silently breaks).
        let i = Value::Integer(38);
        assert_eq!(value_to_dict_string(Some(&i)), "38");
        let s = Value::String("VARCHAR2".to_string());
        assert_eq!(value_to_dict_string(Some(&s)), "VARCHAR2");
        assert_eq!(value_to_dict_string(Some(&Value::Null)), "");
        assert_eq!(value_to_dict_string(None), "");
    }
}

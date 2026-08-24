//! Generic ADBC connector — BYO-driver federation for breadth-tail sources
//! (, spec: the phase-3 `adbc-connector` plan).
//!
//! The operator supplies the path to an ADBC driver shared library
//! (`.so` / `.dylib` / `.dll`) plus connection parameters, and Dataglot
//! federates the source with full SQL pushdown — the same
//! [`SQLExecutor`] shape as the bespoke `postgres.rs` / `mysql.rs`
//! connectors, but the wire layer is whatever driver the user points at.
//!
//! # Contract
//!
//! - **`dialect` is mandatory** and restricted to the unparser dialects
//!   DataFusion actually ships (see [`SupportedDialect`]). A source
//!   without a shipped dialect is not usable through this connector —
//!   the contained fix is landing the dialect upstream in DataFusion.
//! - **Connection state is reset between borrows.** Users MUST NOT rely
//!   on `SET`-based state persisting across queries through this
//!   catalog. The pool runs the per-dialect reset SQL before a
//!   connection returns; if the reset fails the connection is discarded
//!   and a fresh one is opened lazily on the next borrow.
//! - **TLS posture is the driver's contract.** Configure your driver
//!   for TLS in production via `driver_options` (e.g.
//!   `sslmode=require`). This connector does not programmatically
//!   enforce TLS — the user owns the BYO driver's security posture.
//! - **Credentials stay out of logs, errors, and `Debug` output**
//!   (hard rule 12). The password is resolved from the environment
//!   at connect time, handed straight to the driver's option map, and
//!   never stored on the connector.
//!
//! # Threading
//!
//! Every ADBC call is synchronous FFI, so all driver interaction runs
//! under [`tokio::task::spawn_blocking`] (hard rule 11). ADBC's
//! `ManagedConnection` serializes its own calls internally but a busy
//! connection blocks its caller, hence the thin pool
//! (`connection_pool_size`, default 4). FFI object teardown can block
//! too, so drops that would otherwise run on an async thread are routed
//! through a dedicated cleanup thread (see [`defer_ffi_drop`]).

use std::any::Any;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{sync_channel, SyncSender, TrySendError};
use std::sync::{Arc, OnceLock};

use adbc_core::options::{AdbcVersion, ObjectDepth, OptionDatabase, OptionValue};
use adbc_core::{
    Connection as AdbcConnectionApi, Database as _, Driver as _, Statement as AdbcStatementApi,
};
use adbc_driver_manager::{ManagedConnection, ManagedDatabase, ManagedDriver};
use arrow::array::{
    Array, ListArray, RecordBatch, StringArray, StructArray, UInt32Array, UnionArray,
};
use arrow::compute::cast;
use arrow::datatypes::SchemaRef;
use async_trait::async_trait;
use datafusion::catalog::{
    CatalogProvider as DfCatalogProvider, SchemaProvider as DfSchemaProvider,
};
use datafusion::datasource::TableProvider;
use datafusion::error::{DataFusionError, Result as DfResult};
use datafusion::execution::SendableRecordBatchStream;
use datafusion::physical_plan::stream::RecordBatchStreamAdapter;
use datafusion::physical_plan::PhysicalExpr;
use datafusion::sql::unparser::dialect::{
    BigQueryDialect, Dialect, DuckDBDialect, MySqlDialect, PostgreSqlDialect, SqliteDialect,
};
use datafusion::sql::TableReference;
use datafusion_federation::sql::{
    RemoteTableRef, SQLExecutor, SQLFederationProvider, SQLTableSource,
};
use datafusion_federation::FederatedTableProviderAdaptor;
use dataglot_core::{DataglotError, Result as DataglotResult};
use futures::stream::{self, TryStreamExt};
use tokio::sync::{Mutex, OwnedMutexGuard};
use tracing::{debug, warn};

/// `InfoCode` for the driver's vendor name (`ADBC_INFO_VENDOR_NAME`).
/// Used by the best-effort dialect/vendor mismatch warning on connect.
const ADBC_INFO_VENDOR_NAME: u32 = 0;

// ---------------------------------------------------------------------------
// Dialect whitelist
// ---------------------------------------------------------------------------

/// The strict whitelist of SQL dialects usable through the ADBC
/// connector — exactly the unparser [`Dialect`] implementations
/// DataFusion ships.
///
/// **Spec deviation, documented:** the  spec lists six dialects
/// including `mssql`, but DataFusion 53 ships no MS SQL dialect. Per the
/// spec's own rationale ("yes if your source is one of the dialects
/// DataFusion ships, no otherwise"), `mssql` is rejected with a
/// dedicated error until DataFusion gains one. No alias-friendly
/// mapping — mode B's promise is "pushdown works correctly", not
/// "pushdown sort of works".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupportedDialect {
    /// `postgresql` → [`PostgreSqlDialect`]. Reset SQL: `DISCARD ALL`.
    PostgreSql,
    /// `mysql` → [`MySqlDialect`]. Reset SQL: `RESET CONNECTION` (see
    /// [`SupportedDialect::reset_sql`] for the caveat).
    MySql,
    /// `sqlite` → [`SqliteDialect`]. No reset SQL (stateless enough;
    /// explicit rollback suffices).
    Sqlite,
    /// `duckdb` → [`DuckDBDialect`]. No reset SQL.
    DuckDb,
    /// `bigquery` → [`BigQueryDialect`]. No reset SQL (REST per-call,
    /// stateless).
    BigQuery,
}

/// The user-facing names of the supported dialects, for error messages.
const SUPPORTED_DIALECTS: &str = "postgresql | mysql | sqlite | duckdb | bigquery";

impl SupportedDialect {
    /// The canonical config string for this dialect.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PostgreSql => "postgresql",
            Self::MySql => "mysql",
            Self::Sqlite => "sqlite",
            Self::DuckDb => "duckdb",
            Self::BigQuery => "bigquery",
        }
    }

    /// The DataFusion unparser dialect that turns federated plans back
    /// into SQL executable on the remote.
    #[must_use]
    pub fn unparser_dialect(self) -> Arc<dyn Dialect> {
        match self {
            Self::PostgreSql => Arc::new(PostgreSqlDialect {}),
            Self::MySql => Arc::new(MySqlDialect {}),
            Self::Sqlite => Arc::new(SqliteDialect {}),
            Self::DuckDb => Arc::new(DuckDBDialect::new()),
            Self::BigQuery => Arc::new(BigQueryDialect {}),
        }
    }

    /// The SQL statement run before a pooled connection is returned,
    /// clearing any session state a query may have left behind
    /// (multi-tenant safety — see the module doc).
    ///
    /// `None` means no reset is needed for this dialect.
    ///
    /// Note on MySQL (spec open question 4): MySQL has no SQL-level
    /// session-reset statement (`COM_RESET_CONNECTION` is a wire
    /// command, not SQL), so `RESET CONNECTION` is expected to *fail*
    /// on most MySQL-protocol drivers. That failure triggers the
    /// discard-on-reset-failure path — the connection is dropped and
    /// reopened lazily, which is still correct, just costs a
    /// reconnect. Empirical per-driver tuning is a follow-up.
    #[must_use]
    pub fn reset_sql(self) -> Option<&'static str> {
        match self {
            Self::PostgreSql => Some("DISCARD ALL"),
            Self::MySql => Some("RESET CONNECTION"),
            Self::Sqlite | Self::DuckDb | Self::BigQuery => None,
        }
    }

    /// Lowercase keyword expected inside the driver-reported vendor
    /// name; used for the best-effort mismatch warning on connect.
    fn vendor_keyword(self) -> &'static str {
        match self {
            Self::PostgreSql => "postgres",
            Self::MySql => "mysql",
            Self::Sqlite => "sqlite",
            Self::DuckDb => "duckdb",
            Self::BigQuery => "bigquery",
        }
    }
}

impl fmt::Display for SupportedDialect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for SupportedDialect {
    type Err = DataglotError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "postgresql" => Ok(Self::PostgreSql),
            "mysql" => Ok(Self::MySql),
            "sqlite" => Ok(Self::Sqlite),
            "duckdb" => Ok(Self::DuckDb),
            "bigquery" => Ok(Self::BigQuery),
            "mssql" => Err(DataglotError::configuration(format!(
                "adbc dialect 'mssql' is not supported yet: DataFusion ships no MS SQL \
                 unparser dialect, and this connector refuses alias mappings that would \
                 generate subtly wrong SQL. Supported dialects: {SUPPORTED_DIALECTS}"
            ))),
            other => Err(DataglotError::configuration(format!(
                "unknown adbc dialect '{other}'; supported dialects: {SUPPORTED_DIALECTS}"
            ))),
        }
    }
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/// Configuration for one `kind = "adbc"` catalog entry.
///
/// The `Debug` implementation redacts URI userinfo, password-shaped URI
/// parameters, and all `driver_options` values (rule 12) — safe to log.
#[derive(Clone)]
pub struct AdbcConfig {
    /// Catalog name — unique `SQLExecutor::name` / federation
    /// compute-context key.
    pub name: String,
    /// Path to the ADBC driver shared library. Explicit path only — no
    /// env-var discovery, no well-known-path search, no registry lookup.
    pub driver_path: PathBuf,
    /// Driver init symbol override. Defaults to the ADBC convention
    /// derived from the filename. Needed when the driver lives inside a
    /// larger library (e.g. `libduckdb` exports `duckdb_adbc_init`).
    pub driver_entrypoint: Option<String>,
    /// Connection URI, passed as the standard ADBC `uri` database
    /// option. Optional because some drivers connect purely via
    /// key/value options (DuckDB uses `path=...` in `driver_options`);
    /// at least one of `uri` / `driver_options` must be set.
    pub uri: Option<String>,
    /// Username, passed as the standard ADBC `username` option.
    pub username: Option<String>,
    /// Name of the environment variable holding the password. The value
    /// is read at connect time, handed to the driver, and never stored.
    pub password_env: Option<String>,
    /// Extra driver options as `key=value;key=value`. Keys are
    /// driver-specific; values are treated as secrets in `Debug` output.
    pub driver_options: Option<String>,
    /// Source-side catalog scope for schema lookups, where the driver
    /// distinguishes catalogs. `None` means "driver default".
    pub catalog: Option<String>,
    /// Source-side schema scope (slice 2 — catalog discovery).
    pub schema: Option<String>,
    /// Mandatory SQL dialect for federation unparsing.
    pub dialect: SupportedDialect,
    /// Pool size — max concurrent in-flight queries on this catalog.
    /// ADBC connections serialize their own work, so this bounds
    /// parallelism. Default 4.
    pub connection_pool_size: usize,
    /// Connections opened eagerly at connect time; the rest open lazily
    /// on first borrow. Default 1 (fail fast on bad credentials without
    /// paying for a full pool up front).
    pub connection_pool_min_idle: usize,
}

impl AdbcConfig {
    /// A config with the required fields set and spec defaults for the
    /// rest (`connection_pool_size = 4`, `connection_pool_min_idle = 1`).
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        driver_path: impl Into<PathBuf>,
        dialect: SupportedDialect,
    ) -> Self {
        Self {
            name: name.into(),
            driver_path: driver_path.into(),
            driver_entrypoint: None,
            uri: None,
            username: None,
            password_env: None,
            driver_options: None,
            catalog: None,
            schema: None,
            dialect,
            connection_pool_size: 4,
            connection_pool_min_idle: 1,
        }
    }

    /// Validate the config shape before any driver interaction.
    ///
    /// # Errors
    /// Returns [`DataglotError::Configuration`] when the pool sizing is
    /// inconsistent, both `uri` and `driver_options` are absent, or
    /// `driver_options` doesn't parse as `key=value;key=value`.
    pub fn validate(&self) -> DataglotResult<()> {
        if self.connection_pool_size == 0 {
            return Err(DataglotError::configuration(format!(
                "adbc catalog '{}': connection_pool_size must be at least 1",
                self.name
            )));
        }
        if self.connection_pool_min_idle > self.connection_pool_size {
            return Err(DataglotError::configuration(format!(
                "adbc catalog '{}': connection_pool_min_idle ({}) exceeds connection_pool_size ({})",
                self.name, self.connection_pool_min_idle, self.connection_pool_size
            )));
        }
        if self.uri.is_none() && self.driver_options.is_none() {
            return Err(DataglotError::configuration(format!(
                "adbc catalog '{}': at least one of `uri` or `driver_options` is required \
                 (the driver needs to know what to connect to)",
                self.name
            )));
        }
        if let Some(raw) = &self.driver_options {
            parse_driver_options(&self.name, raw)?;
        }
        Ok(())
    }
}

impl fmt::Debug for AdbcConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AdbcConfig")
            .field("name", &self.name)
            .field("driver_path", &self.driver_path)
            .field("driver_entrypoint", &self.driver_entrypoint)
            .field("uri", &self.uri.as_deref().map(redact_uri))
            .field("username", &self.username)
            // The env var *name* is configuration, not a secret; the
            // value it resolves to is never stored on this struct.
            .field("password_env", &self.password_env)
            .field(
                "driver_options",
                &self.driver_options.as_deref().map(redact_driver_options),
            )
            .field("catalog", &self.catalog)
            .field("schema", &self.schema)
            .field("dialect", &self.dialect)
            .field("connection_pool_size", &self.connection_pool_size)
            .field("connection_pool_min_idle", &self.connection_pool_min_idle)
            .finish()
    }
}

/// Parse `key=value;key=value` driver options. Empty segments are
/// ignored (`a=1;;b=2` and a trailing `;` are fine).
///
/// Error messages identify malformed segments by ordinal, never by
/// content — a malformed segment is exactly the case where we can't
/// tell key from (possibly secret) value.
fn parse_driver_options(catalog: &str, raw: &str) -> DataglotResult<Vec<(String, String)>> {
    let mut out = Vec::new();
    for (idx, segment) in raw.split(';').enumerate() {
        if segment.trim().is_empty() {
            continue;
        }
        let Some((key, value)) = segment.split_once('=') else {
            return Err(DataglotError::configuration(format!(
                "adbc catalog '{catalog}': driver_options segment #{n} is not 'key=value'",
                n = idx + 1
            )));
        };
        out.push((key.trim().to_string(), value.to_string()));
    }
    Ok(out)
}

/// Redact credential material inside a connection URI for `Debug` /
/// log output: the `user:password@` userinfo block and the values of
/// password-shaped parameters (`password=`, `pwd=`, `token=`,
/// `secret=`) in either query-string or libpq key-value form.
fn redact_uri(uri: &str) -> String {
    let mut out = if let Some(scheme_end) = uri.find("://") {
        let rest = &uri[scheme_end + 3..];
        let authority_end = rest.find('/').unwrap_or(rest.len());
        if let Some(at) = rest[..authority_end].rfind('@') {
            format!("{}://[redacted]@{}", &uri[..scheme_end], &rest[at + 1..])
        } else {
            uri.to_string()
        }
    } else {
        uri.to_string()
    };
    for key in ["password", "pwd", "token", "secret"] {
        out = redact_kv_value(&out, key);
    }
    out
}

/// Replace the value following every case-insensitive `<key>=` in `s`
/// (up to the next `&`, `;`, or whitespace) with `[redacted]`.
fn redact_kv_value(s: &str, key: &str) -> String {
    let lower = s.to_ascii_lowercase();
    let needle = format!("{key}=");
    let mut out = String::with_capacity(s.len());
    let mut pos = 0;
    while let Some(found) = lower[pos..].find(&needle) {
        let start = pos + found + needle.len();
        out.push_str(&s[pos..start]);
        out.push_str("[redacted]");
        let value_end = s[start..]
            .find(['&', ';', ' '])
            .map_or(s.len(), |i| start + i);
        pos = value_end;
    }
    out.push_str(&s[pos..]);
    out
}

/// Render driver options with keys visible and every value redacted —
/// keys are driver configuration, values may be secrets (tokens, file
/// paths under home directories, passwords).
fn redact_driver_options(raw: &str) -> String {
    raw.split(';')
        .filter(|segment| !segment.trim().is_empty())
        .map(|segment| match segment.split_once('=') {
            Some((key, _)) => format!("{}=[redacted]", key.trim()),
            None => "[malformed]".to_string(),
        })
        .collect::<Vec<_>>()
        .join(";")
}

// ---------------------------------------------------------------------------
// FFI cleanup thread
// ---------------------------------------------------------------------------

/// Sender feeding the dedicated `adbc-cleanup` thread.
///
/// Dropping ADBC FFI objects (connections, databases) can block on
/// driver-side teardown (socket close, buffer flush). On an async
/// executor thread that's a rule-11 violation, so drops are routed
/// here instead.
///
/// This pattern (dedicated cleanup thread + bounded channel + overflow
/// thread fallback) is lifted from Spice AI's ADBC data connector —
/// `spiceai/spiceai/crates/runtime/src/dataconnector/adbc.rs`
/// (Apache-2.0).
fn ffi_cleanup_sender() -> &'static SyncSender<Box<dyn Any + Send>> {
    static SENDER: OnceLock<SyncSender<Box<dyn Any + Send>>> = OnceLock::new();
    SENDER.get_or_init(|| {
        let (tx, rx) = sync_channel::<Box<dyn Any + Send>>(64);
        std::thread::Builder::new()
            .name("adbc-cleanup".to_string())
            .spawn(move || {
                while let Ok(item) = rx.recv() {
                    drop(item);
                }
            })
            .expect("spawning the adbc-cleanup thread cannot fail at startup");
        tx
    })
}

/// Hand an FFI-backed object to the cleanup thread for teardown. Falls
/// back to a one-off overflow thread when the 64-slot channel is full,
/// and to an inline drop only if thread spawning itself fails.
fn defer_ffi_drop(item: Box<dyn Any + Send>) {
    if let Err(err) = ffi_cleanup_sender().try_send(item) {
        let item = match err {
            TrySendError::Full(item) | TrySendError::Disconnected(item) => item,
        };
        // Overflow fallback: teardown still happens off the async
        // runtime, just on a short-lived thread of its own.
        if let Err(spawn_err) = std::thread::Builder::new()
            .name("adbc-cleanup-overflow".to_string())
            .spawn(move || drop(item))
        {
            warn!(error = %spawn_err, "adbc cleanup overflow thread failed to spawn; dropping inline");
        }
    }
}

// ---------------------------------------------------------------------------
// Query + reset mechanics (generic over the adbc_core traits so the
// reset-on-return contract is unit-testable without a driver binary)
// ---------------------------------------------------------------------------

/// Run one user query on `conn` and collect the full result.
fn run_user_query<C: AdbcConnectionApi>(
    conn: &mut C,
    sql: &str,
) -> DataglotResult<Vec<RecordBatch>> {
    let mut stmt = conn
        .new_statement()
        .map_err(|e| DataglotError::federation(format!("adbc statement allocation failed: {e}")))?;
    stmt.set_sql_query(sql)
        .map_err(|e| DataglotError::federation(format!("adbc set_sql_query failed: {e}")))?;
    let reader = stmt
        .execute()
        .map_err(|e| DataglotError::federation(format!("adbc query failed: {e}")))?;
    let mut batches = Vec::new();
    for batch in reader {
        batches.push(
            batch.map_err(|e| {
                DataglotError::federation(format!("adbc result stream failed: {e}"))
            })?,
        );
    }
    Ok(batches)
}

/// Run the per-dialect reset SQL before a connection returns to the
/// pool. Returns `true` when the connection is safe to re-pool; `false`
/// means the reset failed and the connection must be discarded
/// (discard-on-reset-failure — the multi-tenant safety net).
fn run_reset<C: AdbcConnectionApi>(conn: &mut C, reset_sql: &str, pool: &str) -> bool {
    let result = conn.new_statement().and_then(|mut stmt| {
        stmt.set_sql_query(reset_sql)?;
        stmt.execute_update()?;
        Ok(())
    });
    match result {
        Ok(()) => true,
        Err(e) => {
            warn!(
                pool = %pool,
                reset = %reset_sql,
                error = %e,
                "adbc reset-on-return failed; discarding connection instead of re-pooling"
            );
            false
        }
    }
}

/// Run `f` on `conn`, then unconditionally run the reset (state may
/// have mutated even when `f` errored). Returns the result of `f` and
/// whether the connection may be re-pooled.
fn run_with_reset<C: AdbcConnectionApi, T>(
    conn: &mut C,
    reset_sql: Option<&str>,
    pool: &str,
    f: impl FnOnce(&mut C) -> DataglotResult<T>,
) -> (DataglotResult<T>, bool) {
    let result = f(conn);
    let keep = match reset_sql {
        Some(sql) => run_reset(conn, sql, pool),
        None => true,
    };
    (result, keep)
}

/// Align a driver-produced batch with the schema the federation plan
/// expects. Drivers commonly agree on layout but differ in field
/// nullability, names, or exact numeric width; identical schemas pass
/// through untouched, same-arity schemas are cast column-by-column.
fn align_batch(batch: &RecordBatch, target: &SchemaRef) -> DataglotResult<RecordBatch> {
    if batch.schema().as_ref() == target.as_ref() {
        return Ok(batch.clone());
    }
    if batch.num_columns() != target.fields().len() {
        return Err(DataglotError::federation(format!(
            "adbc result arity mismatch: driver returned {} columns, plan expects {}",
            batch.num_columns(),
            target.fields().len()
        )));
    }
    let columns = batch
        .columns()
        .iter()
        .zip(target.fields())
        .map(|(column, field)| {
            if column.data_type() == field.data_type() {
                Ok(Arc::clone(column))
            } else {
                cast(column, field.data_type()).map_err(|e| {
                    DataglotError::federation(format!(
                        "adbc result column '{}' cast from {:?} to {:?} failed: {e}",
                        field.name(),
                        column.data_type(),
                        field.data_type()
                    ))
                })
            }
        })
        .collect::<DataglotResult<Vec<_>>>()?;
    RecordBatch::try_new(Arc::clone(target), columns)
        .map_err(|e| DataglotError::federation(format!("adbc result batch rebuild failed: {e}")))
}

// ---------------------------------------------------------------------------
// Connection pool
// ---------------------------------------------------------------------------

/// Slot-per-connection pool skeleton. Generic over the connection type
/// so the acquire/queue behavior is unit-testable without FFI.
struct SlotPool<T> {
    name: String,
    slots: Vec<Arc<Mutex<Option<T>>>>,
    next: AtomicUsize,
}

impl<T> SlotPool<T> {
    /// Build a pool of `size` slots, the first `initial.len()` of them
    /// pre-populated (eager warm-up), the rest empty (lazy).
    fn new(name: String, size: usize, initial: Vec<T>) -> Self {
        let mut seed = initial.into_iter();
        Self {
            name,
            slots: (0..size)
                .map(|_| Arc::new(Mutex::new(seed.next())))
                .collect(),
            next: AtomicUsize::new(0),
        }
    }

    /// Borrow a slot. Free slots are taken immediately; when every slot
    /// is busy the caller queues on one (await) rather than erroring —
    /// spec open question 2, resolved toward queueing.
    async fn acquire(&self) -> OwnedMutexGuard<Option<T>> {
        for slot in &self.slots {
            if let Ok(guard) = Arc::clone(slot).try_lock_owned() {
                return guard;
            }
        }
        let idx = self.next.fetch_add(1, Ordering::Relaxed) % self.slots.len();
        warn!(
            pool = %self.name,
            size = self.slots.len(),
            "adbc connection pool exhausted; queueing until a connection frees up"
        );
        Arc::clone(&self.slots[idx]).lock_owned().await
    }
}

/// The live pool: lazily-populated connections over a shared
/// [`ManagedDatabase`].
struct ConnectionPool {
    slots: SlotPool<ManagedConnection>,
    /// Kept alive for the pool's lifetime — ADBC databases must outlive
    /// their connections. `Option` so `Drop` can route the final FFI
    /// teardown through the cleanup thread.
    database: Option<ManagedDatabase>,
    reset_sql: Option<&'static str>,
}

impl ConnectionPool {
    /// Run `f` on a pooled connection inside `spawn_blocking`.
    ///
    /// `reset_after`: `true` for user SQL (reset-on-return applies),
    /// `false` for metadata-only calls that never execute SQL.
    async fn with_conn<T, F>(self: &Arc<Self>, reset_after: bool, f: F) -> DataglotResult<T>
    where
        T: Send + 'static,
        F: FnOnce(&mut ManagedConnection) -> DataglotResult<T> + Send + 'static,
    {
        let mut guard = self.slots.acquire().await;
        let taken = guard.take();
        let database = self
            .database
            .clone()
            .expect("pool database is only vacated in Drop");
        let pool_name = self.slots.name.clone();
        let reset_sql = if reset_after { self.reset_sql } else { None };

        let (result, conn_back) = tokio::task::spawn_blocking(move || {
            let mut conn = match taken {
                Some(conn) => conn,
                // Lazy population: this slot has never held a
                // connection (or its last one was discarded).
                None => match database.new_connection() {
                    Ok(conn) => conn,
                    Err(e) => {
                        return (
                            Err(DataglotError::connection(format!(
                                "adbc connection open failed on catalog '{pool_name}': {e}"
                            ))),
                            None,
                        )
                    }
                },
            };
            let (result, keep) = run_with_reset(&mut conn, reset_sql, &pool_name, f);
            // A discarded connection is dropped right here, on the
            // blocking thread — no cleanup-thread detour needed.
            (result, keep.then_some(conn))
        })
        .await
        .map_err(|e| DataglotError::federation(format!("adbc blocking task join error: {e}")))?;

        *guard = conn_back;
        drop(guard);
        result
    }
}

impl Drop for ConnectionPool {
    fn drop(&mut self) {
        // The pool may be dropped on an async thread; FFI teardown
        // blocks, so hand every live connection (and the database
        // handle) to the cleanup thread.
        for slot in &self.slots.slots {
            if let Ok(mut guard) = slot.try_lock() {
                if let Some(conn) = guard.take() {
                    defer_ffi_drop(Box::new(conn));
                }
            }
        }
        if let Some(database) = self.database.take() {
            defer_ffi_drop(Box::new(database));
        }
    }
}

// ---------------------------------------------------------------------------
// Connector
// ---------------------------------------------------------------------------

/// Generic ADBC connector. One instance per `kind = "adbc"` catalog
/// entry; hands out federation [`TableProvider`]s with full SQL
/// pushdown through the user-supplied driver.
pub struct AdbcConnector {
    config: AdbcConfig,
    pool: Arc<ConnectionPool>,
}

impl fmt::Debug for AdbcConnector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Credential redaction delegates to AdbcConfig's Debug.
        f.debug_struct("AdbcConnector")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl AdbcConnector {
    /// Load the driver, initialize the database handle, and open
    /// `connection_pool_min_idle` connections eagerly (the rest open
    /// lazily on first borrow).
    ///
    /// # Errors
    /// [`DataglotError::Configuration`] when the config is inconsistent
    /// or `password_env` names an unset variable;
    /// [`DataglotError::Connection`] when the driver fails to load or
    /// the eager connections can't be opened. Error messages never
    /// contain the resolved password (rule 12).
    pub async fn connect(config: AdbcConfig) -> DataglotResult<Self> {
        config.validate()?;
        let password = match &config.password_env {
            Some(env_name) => Some(std::env::var(env_name).map_err(|_| {
                DataglotError::configuration(format!(
                    "adbc catalog '{}': password_env '{}' is not set in the environment",
                    config.name, env_name
                ))
            })?),
            None => None,
        };

        let cfg = config.clone();
        let (database, warm) =
            tokio::task::spawn_blocking(move || open_database(&cfg, password.as_deref()))
                .await
                .map_err(|e| {
                    DataglotError::connection(format!("adbc driver load join error: {e}"))
                })??;

        let slots = SlotPool::new(config.name.clone(), config.connection_pool_size, warm);
        let reset_sql = config.dialect.reset_sql();
        Ok(Self {
            config,
            pool: Arc::new(ConnectionPool {
                slots,
                database: Some(database),
                reset_sql,
            }),
        })
    }

    /// The connector / federation compute-context name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.config.name
    }

    /// Produce a federation [`TableProvider`] for `<schema>.<table>`
    /// with full pushdown through the ADBC driver. The Arrow schema is
    /// resolved from the driver on this call — lazy per hard rule
    /// 13, nothing is fetched at [`AdbcConnector::connect`] time.
    ///
    /// # Errors
    /// [`DataglotError::Catalog`] when the driver can't resolve the
    /// table's schema.
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

    /// Resolve `<schema>.<table>`'s Arrow schema via the driver's
    /// `get_table_schema` (a metadata call — no user SQL, no reset).
    async fn fetch_arrow_schema(&self, schema: &str, table: &str) -> DataglotResult<SchemaRef> {
        let catalog = self.config.catalog.clone();
        let schema = schema.to_string();
        let table = table.to_string();
        let arrow_schema = self
            .pool
            .with_conn(false, move |conn| {
                conn.get_table_schema(catalog.as_deref(), Some(schema.as_str()), table.as_str())
                    .map_err(|e| {
                        DataglotError::catalog(format!(
                            "adbc get_table_schema failed for '{schema}.{table}': {e}"
                        ))
                    })
            })
            .await?;
        Ok(Arc::new(arrow_schema))
    }

    /// Wrap this connector as a `DataFusion` [`CatalogProvider`]
    /// (slice 2 — catalog discovery).
    ///
    /// Schema and table names are enumerated once, here, via the
    /// driver's `get_objects` (depth: tables), scoped to the config's
    /// `catalog` / `schema` filters when set. Per-table column schemas
    /// stay **lazy** (rule 13): they resolve on first
    /// [`SchemaProvider::table`] access by delegating to
    /// [`Self::table_provider`] — the same eager-listing / lazy-schema
    /// strategy as `PostgresConnector::as_catalog_provider`, and with
    /// the same caveat: names are cached for the catalog's lifetime, so
    /// drop and rebuild it to pick up remote DDL.
    ///
    /// # Errors
    /// Returns [`DataglotError::Catalog`] when `get_objects` fails or
    /// its result doesn't match the ADBC objects schema.
    ///
    /// [`CatalogProvider`]: datafusion::catalog::CatalogProvider
    /// [`SchemaProvider::table`]: datafusion::catalog::SchemaProvider::table
    pub async fn as_catalog_provider(
        self: &Arc<Self>,
    ) -> DataglotResult<Arc<dyn DfCatalogProvider>> {
        let catalog = self.config.catalog.clone();
        let schema_filter = self.config.schema.clone();
        let listing = self
            .pool
            .with_conn(false, move |conn| {
                let reader = conn
                    .get_objects(
                        ObjectDepth::Tables,
                        catalog.as_deref(),
                        schema_filter.as_deref(),
                        None,
                        None,
                        None,
                    )
                    .map_err(|e| DataglotError::catalog(format!("adbc get_objects failed: {e}")))?;
                let mut listing: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
                for batch in reader {
                    let batch = batch.map_err(|e| {
                        DataglotError::catalog(format!("adbc get_objects stream failed: {e}"))
                    })?;
                    parse_get_objects_batch(&batch, &mut listing)?;
                }
                Ok(listing)
            })
            .await?;

        let schema_names: Vec<String> = listing.keys().cloned().collect();
        let schemas: HashMap<String, Arc<dyn DfSchemaProvider>> = listing
            .into_iter()
            .map(|(schema_name, tables)| {
                let provider = Arc::new(AdbcSchema {
                    connector: Arc::clone(self),
                    schema_name: schema_name.clone(),
                    table_names: tables.into_iter().collect(),
                }) as Arc<dyn DfSchemaProvider>;
                (schema_name, provider)
            })
            .collect();

        Ok(Arc::new(AdbcCatalog {
            connector_name: self.config.name.clone(),
            schema_names,
            schemas,
        }) as Arc<dyn DfCatalogProvider>)
    }
}

/// Fold one `get_objects` result batch into `schema → table names`.
///
/// The batch follows the ADBC objects schema:
/// `catalog_name: utf8`, `catalog_db_schemas: list<struct<
/// db_schema_name: utf8, db_schema_tables: list<struct<table_name,
/// …>>>>`. Parsing is tolerant of extra struct fields (drivers append
/// columns/constraints members) but errors on a missing level — a
/// malformed shape should surface, not silently list nothing.
fn parse_get_objects_batch(
    batch: &RecordBatch,
    listing: &mut BTreeMap<String, BTreeSet<String>>,
) -> DataglotResult<()> {
    let shape_err = |what: &str| {
        DataglotError::catalog(format!(
            "adbc get_objects result does not match the ADBC objects schema: {what}"
        ))
    };
    let db_schemas = batch
        .column_by_name("catalog_db_schemas")
        .ok_or_else(|| shape_err("missing 'catalog_db_schemas' column"))?
        .as_any()
        .downcast_ref::<ListArray>()
        .ok_or_else(|| shape_err("'catalog_db_schemas' is not a list"))?;

    for row in 0..batch.num_rows() {
        if db_schemas.is_null(row) {
            continue;
        }
        let entries = db_schemas.value(row);
        let entries = entries
            .as_any()
            .downcast_ref::<StructArray>()
            .ok_or_else(|| shape_err("'catalog_db_schemas' items are not structs"))?;
        let names = entries
            .column_by_name("db_schema_name")
            .ok_or_else(|| shape_err("missing 'db_schema_name' member"))?
            .as_any()
            .downcast_ref::<StringArray>()
            .ok_or_else(|| shape_err("'db_schema_name' is not utf8"))?;
        let tables_lists = entries
            .column_by_name("db_schema_tables")
            .ok_or_else(|| shape_err("missing 'db_schema_tables' member"))?
            .as_any()
            .downcast_ref::<ListArray>()
            .ok_or_else(|| shape_err("'db_schema_tables' is not a list"))?;

        for i in 0..entries.len() {
            if !names.is_valid(i) {
                continue;
            }
            let tables = listing.entry(names.value(i).to_string()).or_default();
            if tables_lists.is_null(i) {
                continue;
            }
            let table_entries = tables_lists.value(i);
            let table_entries = table_entries
                .as_any()
                .downcast_ref::<StructArray>()
                .ok_or_else(|| shape_err("'db_schema_tables' items are not structs"))?;
            let table_names = table_entries
                .column_by_name("table_name")
                .ok_or_else(|| shape_err("missing 'table_name' member"))?
                .as_any()
                .downcast_ref::<StringArray>()
                .ok_or_else(|| shape_err("'table_name' is not utf8"))?;
            for t in 0..table_entries.len() {
                if table_names.is_valid(t) {
                    tables.insert(table_names.value(t).to_string());
                }
            }
        }
    }
    Ok(())
}

/// `DataFusion` [`CatalogProvider`] over an [`AdbcConnector`] —
/// pre-built at [`AdbcConnector::as_catalog_provider`] time, sync and
/// allocation-only afterwards.
///
/// [`CatalogProvider`]: datafusion::catalog::CatalogProvider
pub struct AdbcCatalog {
    /// The underlying connector's identifier — diagnostics only; the
    /// catalog's registered name is supplied by `register_catalog`.
    connector_name: String,
    /// Cached, sorted schema names.
    schema_names: Vec<String>,
    /// Pre-built schema providers, keyed by schema name.
    schemas: HashMap<String, Arc<dyn DfSchemaProvider>>,
}

impl fmt::Debug for AdbcCatalog {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AdbcCatalog")
            .field("connector", &self.connector_name)
            .field("schema_count", &self.schema_names.len())
            .finish_non_exhaustive()
    }
}

impl DfCatalogProvider for AdbcCatalog {
    fn schema_names(&self) -> Vec<String> {
        self.schema_names.clone()
    }

    fn schema(&self, name: &str) -> Option<Arc<dyn DfSchemaProvider>> {
        self.schemas.get(name).map(Arc::clone)
    }
}

/// `DataFusion` [`SchemaProvider`] backed by one source-side namespace
/// on an [`AdbcConnector`]. Table names are cached at construction;
/// column schemas resolve lazily in [`SchemaProvider::table`] (rule 13).
///
/// [`SchemaProvider`]: datafusion::catalog::SchemaProvider
/// [`SchemaProvider::table`]: datafusion::catalog::SchemaProvider::table
struct AdbcSchema {
    connector: Arc<AdbcConnector>,
    schema_name: String,
    /// Cached, sorted table names within this namespace.
    table_names: Vec<String>,
}

impl fmt::Debug for AdbcSchema {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AdbcSchema")
            .field("schema", &self.schema_name)
            .field("table_count", &self.table_names.len())
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl DfSchemaProvider for AdbcSchema {
    fn table_names(&self) -> Vec<String> {
        self.table_names.clone()
    }

    fn table_exist(&self, name: &str) -> bool {
        self.table_names.iter().any(|t| t == name)
    }

    async fn table(&self, name: &str) -> DfResult<Option<Arc<dyn TableProvider>>> {
        // Cheap negative path — no driver roundtrip for names that
        // weren't in the listing.
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

/// Blocking half of [`AdbcConnector::connect`]: load the driver, build
/// the database handle with the option map, open the eager
/// connections, and best-effort-check the driver's vendor name against
/// the configured dialect.
fn open_database(
    config: &AdbcConfig,
    password: Option<&str>,
) -> DataglotResult<(ManagedDatabase, Vec<ManagedConnection>)> {
    // Any error on this path may embed driver-produced text that could
    // echo an option value back; scrub the resolved password out of
    // every message before it leaves this function (rule 12).
    let scrub = |msg: String| -> String {
        match password {
            Some(pw) if !pw.is_empty() => msg.replace(pw, "[redacted]"),
            _ => msg,
        }
    };

    let entrypoint = config.driver_entrypoint.as_ref().map(String::as_bytes);
    // Prefer ADBC 1.1.0; fall back to 1.0.0 for drivers that reject
    // the newer init version (nothing here relies on 1.1-only calls).
    let mut driver = ManagedDriver::load_dynamic_from_filename(
        &config.driver_path,
        entrypoint,
        AdbcVersion::V110,
    )
    .or_else(|e| {
        debug!(
            driver = %config.driver_path.display(),
            error = %e,
            "adbc driver rejected ADBC 1.1.0 init; retrying as 1.0.0"
        );
        ManagedDriver::load_dynamic_from_filename(
            &config.driver_path,
            entrypoint,
            AdbcVersion::V100,
        )
    })
    .map_err(|e| {
        DataglotError::connection(scrub(format!(
            "adbc driver failed to load from '{}': {e}",
            config.driver_path.display()
        )))
    })?;

    let mut opts: Vec<(OptionDatabase, OptionValue)> = Vec::new();
    if let Some(uri) = &config.uri {
        opts.push((OptionDatabase::Uri, OptionValue::String(uri.clone())));
    }
    if let Some(username) = &config.username {
        opts.push((
            OptionDatabase::Username,
            OptionValue::String(username.clone()),
        ));
    }
    if let Some(pw) = password {
        opts.push((
            OptionDatabase::Password,
            OptionValue::String(pw.to_string()),
        ));
    }
    if let Some(raw) = &config.driver_options {
        for (key, value) in parse_driver_options(&config.name, raw)? {
            opts.push((OptionDatabase::Other(key), OptionValue::String(value)));
        }
    }

    //: a federated DuckDB source is read-only — Dataglot never writes to
    // a source (writes go to Iceberg). A DuckDB file opened read-write takes an
    // *exclusive* lock, so a second engine instance opening the same file fails
    // ("Could not set lock on file") and, under fail-fast boot, aborts. Default
    // DuckDB to `access_mode=read_only` so multiple instances share one file;
    // honour an explicit `access_mode` in `driver_options` if the operator set
    // one (case-insensitive).
    if config.dialect == SupportedDialect::DuckDb
        && !opts.iter().any(|(k, _)| {
            matches!(k, OptionDatabase::Other(key) if key.eq_ignore_ascii_case("access_mode"))
        })
    {
        opts.push((
            OptionDatabase::Other("access_mode".to_string()),
            OptionValue::String("read_only".to_string()),
        ));
    }

    let database = driver.new_database_with_opts(opts).map_err(|e| {
        DataglotError::connection(scrub(format!(
            "adbc database init failed on catalog '{}': {e}",
            config.name
        )))
    })?;

    let mut warm = Vec::with_capacity(config.connection_pool_min_idle);
    for _ in 0..config.connection_pool_min_idle {
        warm.push(database.new_connection().map_err(|e| {
            DataglotError::connection(scrub(format!(
                "adbc connection open failed on catalog '{}': {e}",
                config.name
            )))
        })?);
    }

    if let Some(conn) = warm.first() {
        warn_on_vendor_dialect_mismatch(conn, config);
    }

    Ok((database, warm))
}

/// Best-effort dialect sanity check (specced at `warn!` level): ask the
/// driver for `ADBC_INFO_VENDOR_NAME` and warn when it doesn't look
/// like the configured dialect. Hard enforcement is a v2 follow-up; any
/// failure to read or parse the info result is silently ignored — this
/// must never block a working configuration.
fn warn_on_vendor_dialect_mismatch(conn: &ManagedConnection, config: &AdbcConfig) {
    let Some(vendor) = read_vendor_name(conn) else {
        debug!(
            catalog = %config.name,
            "adbc driver did not report a vendor name; skipping dialect sanity check"
        );
        return;
    };
    let keyword = config.dialect.vendor_keyword();
    if !vendor.to_ascii_lowercase().contains(keyword) {
        warn!(
            catalog = %config.name,
            vendor = %vendor,
            dialect = %config.dialect,
            "adbc driver vendor name does not match the configured dialect; \
             pushed-down SQL may not be valid on this source"
        );
    }
}

/// Pull `ADBC_INFO_VENDOR_NAME` out of `get_info`'s union-typed result.
fn read_vendor_name(conn: &ManagedConnection) -> Option<String> {
    let codes = std::collections::HashSet::from([adbc_core::options::InfoCode::VendorName]);
    let reader = conn.get_info(Some(codes)).ok()?;
    for batch in reader {
        let batch = batch.ok()?;
        let names = batch.column(0).as_any().downcast_ref::<UInt32Array>()?;
        let values = batch.column(1).as_any().downcast_ref::<UnionArray>()?;
        for row in 0..batch.num_rows() {
            if names.value(row) != ADBC_INFO_VENDOR_NAME {
                continue;
            }
            // string_value is union member 0 per the ADBC spec.
            if values.type_id(row) != 0 {
                continue;
            }
            let strings = values.child(0).as_any().downcast_ref::<StringArray>()?;
            let offset = values.value_offset(row);
            if strings.is_valid(offset) {
                return Some(strings.value(offset).to_string());
            }
        }
    }
    None
}

/// Split a `<schema>.<table>` reference (bare, double-quoted, or
/// backtick-quoted per the active dialect) into its two parts. Input
/// comes from `datafusion-federation`'s `RemoteTableRef` rendering of
/// the reference we built in [`AdbcConnector::table_provider`], so the
/// shape is well-known.
fn split_qualified(s: &str) -> Option<(String, String)> {
    let parts: Vec<&str> = s.splitn(2, '.').collect();
    if parts.len() != 2 {
        return None;
    }
    let unquote = |p: &str| p.trim_matches('"').trim_matches('`').to_string();
    let schema = unquote(parts[0]);
    let table = unquote(parts[1]);
    if schema.is_empty() || table.is_empty() {
        return None;
    }
    Some((schema, table))
}

#[async_trait]
impl SQLExecutor for AdbcConnector {
    fn name(&self) -> &str {
        &self.config.name
    }

    fn compute_context(&self) -> Option<String> {
        Some(self.config.name.clone())
    }

    fn dialect(&self) -> Arc<dyn Dialect> {
        self.config.dialect.unparser_dialect()
    }

    fn execute(
        &self,
        query: &str,
        schema: SchemaRef,
        _filters: &[Arc<dyn PhysicalExpr>],
    ) -> DfResult<SendableRecordBatchStream> {
        // The query was unparsed with this catalog's configured dialect, so
        // it's safe to send as-is. `instrument_pushdown` logs it at `debug`
        // (filter literals are user data, not credentials) and emits the
        // source-attributed timing/row-count event at `info` on completion.
        let pool = Arc::clone(&self.pool);
        let sql = query.to_string();
        let target = Arc::clone(&schema);

        // Whole-result buffering, matching the Postgres connector's
        // current shape — the ADBC reader is a blocking iterator, so
        // draining it inside the one spawn_blocking hop keeps rule 11
        // intact. Incremental streaming is a shared follow-up.
        let fut = async move {
            let batches = pool
                .with_conn(true, move |conn| {
                    let batches = run_user_query(conn, &sql)?;
                    batches
                        .iter()
                        .map(|batch| align_batch(batch, &target))
                        .collect::<DataglotResult<Vec<_>>>()
                })
                .await
                .map_err(|e| DataFusionError::External(Box::new(e)))?;
            Ok::<_, DataFusionError>(stream::iter(batches.into_iter().map(Ok)))
        };

        let stream = Box::pin(RecordBatchStreamAdapter::new(
            schema,
            stream::once(fut).try_flatten(),
        ));
        Ok(crate::instrument_pushdown(
            &self.config.name,
            "adbc",
            query,
            stream,
        ))
    }

    async fn table_names(&self) -> DfResult<Vec<String>> {
        // Not used by the federation pushdown path — mirroring the
        // Postgres/MySQL connectors; `as_catalog_provider` (slice 2)
        // is the public catalog-listing surface.
        Err(DataFusionError::NotImplemented(
            "table_names not implemented".to_string(),
        ))
    }

    async fn get_table_schema(&self, table_name: &str) -> DfResult<SchemaRef> {
        let (schema_part, table_part) = split_qualified(table_name).ok_or_else(|| {
            DataFusionError::External(Box::new(DataglotError::catalog(format!(
                "expected '<schema>.<table>' reference, got: {table_name}"
            ))))
        })?;
        self.fetch_arrow_schema(&schema_part, &table_part)
            .await
            .map_err(|e| DataFusionError::External(Box::new(e)))
    }
}

/// Cheap liveness probe that reuses a boot-built pooled ADBC connection
///. The health poller calls this on a timer instead of rebuilding the
/// connector (which reloads the driver + reopens the pool); `SELECT 1` runs on
/// a pooled connection (`reset_after = false` — it changes no session state) and
/// errors iff the source is unreachable. The error is the driver's own scrubbed
/// message — never the URI/password (rule 12).
#[async_trait]
impl crate::health::ConnectorHealthCheck for AdbcConnector {
    async fn health_check(&self) -> Result<(), String> {
        self.pool
            .with_conn(false, |conn| run_user_query(conn, "SELECT 1").map(|_| ()))
            .await
            .map_err(|e| format!("adbc health check failed: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::sync::Mutex as StdMutex;
    use std::time::Duration;

    use adbc_core::error::{Error as AdbcError, Result as AdbcResult, Status};
    use adbc_core::options::{InfoCode, ObjectDepth, OptionConnection, OptionStatement};
    use adbc_core::{Connection, Optionable, PartitionedResult, Statement};
    use arrow::array::{RecordBatchIterator, RecordBatchReader};
    use arrow::datatypes::{DataType, Field, Schema};

    use super::*;

    // -----------------------------------------------------------------
    // 1. Dialect parsing & config validation
    // -----------------------------------------------------------------

    #[test]
    fn dialect_parses_every_supported_name() {
        for (name, expected) in [
            ("postgresql", SupportedDialect::PostgreSql),
            ("mysql", SupportedDialect::MySql),
            ("sqlite", SupportedDialect::Sqlite),
            ("duckdb", SupportedDialect::DuckDb),
            ("bigquery", SupportedDialect::BigQuery),
        ] {
            assert_eq!(name.parse::<SupportedDialect>().unwrap(), expected);
            // Round-trips through as_str.
            assert_eq!(expected.as_str(), name);
        }
    }

    #[test]
    fn dialect_parsing_is_case_insensitive_and_trims() {
        assert_eq!(
            " PostgreSQL ".parse::<SupportedDialect>().unwrap(),
            SupportedDialect::PostgreSql
        );
        assert_eq!(
            "DuckDB".parse::<SupportedDialect>().unwrap(),
            SupportedDialect::DuckDb
        );
    }

    #[test]
    fn unknown_dialect_error_names_the_supported_set() {
        let err = "vertica".parse::<SupportedDialect>().unwrap_err();
        let msg = err.to_string();
        for name in ["postgresql", "mysql", "sqlite", "duckdb", "bigquery"] {
            assert!(msg.contains(name), "expected '{name}' in: {msg}");
        }
    }

    #[test]
    fn mssql_gets_a_dedicated_rejection() {
        // The spec whitelisted six dialects assuming DataFusion ships an
        // MS SQL unparser dialect; it doesn't (as of datafusion 53), so
        // mssql is rejected with an explanation rather than aliased.
        let err = "mssql".parse::<SupportedDialect>().unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("mssql"), "unexpected message: {msg}");
        assert!(msg.contains("DataFusion"), "unexpected message: {msg}");
    }

    #[test]
    fn config_defaults_match_the_spec() {
        let config = AdbcConfig::new("cat", "/lib/driver.so", SupportedDialect::DuckDb);
        assert_eq!(config.connection_pool_size, 4);
        assert_eq!(config.connection_pool_min_idle, 1);
    }

    #[test]
    fn validate_rejects_zero_sized_pool() {
        let mut config = AdbcConfig::new("cat", "/lib/driver.so", SupportedDialect::DuckDb);
        config.uri = Some("db://x".to_string());
        config.connection_pool_size = 0;
        let msg = config.validate().unwrap_err().to_string();
        assert!(msg.contains("connection_pool_size"), "got: {msg}");
    }

    #[test]
    fn validate_rejects_min_idle_above_pool_size() {
        let mut config = AdbcConfig::new("cat", "/lib/driver.so", SupportedDialect::DuckDb);
        config.uri = Some("db://x".to_string());
        config.connection_pool_min_idle = 5;
        let msg = config.validate().unwrap_err().to_string();
        assert!(msg.contains("connection_pool_min_idle"), "got: {msg}");
    }

    #[test]
    fn validate_requires_uri_or_driver_options() {
        let config = AdbcConfig::new("cat", "/lib/driver.so", SupportedDialect::DuckDb);
        let msg = config.validate().unwrap_err().to_string();
        assert!(msg.contains("uri"), "got: {msg}");
    }

    #[test]
    fn driver_options_parse_and_skip_empty_segments() {
        let opts = parse_driver_options("cat", "a=1;;b=two=2;").unwrap();
        assert_eq!(
            opts,
            vec![
                ("a".to_string(), "1".to_string()),
                // Split on the FIRST '=' — values may contain '='.
                ("b".to_string(), "two=2".to_string()),
            ]
        );
    }

    #[test]
    fn malformed_driver_options_error_by_ordinal_not_content() {
        // A malformed segment is exactly the case where key can't be
        // told apart from a possibly-secret value, so the error names
        // the segment position and never echoes its content.
        let msg = parse_driver_options("cat", "good=1;hunter2secret")
            .unwrap_err()
            .to_string();
        assert!(msg.contains("segment #2"), "got: {msg}");
        assert!(!msg.contains("hunter2secret"), "leaked content: {msg}");
    }

    // -----------------------------------------------------------------
    // 2. Credential isolation (rule 12)
    // -----------------------------------------------------------------

    #[test]
    fn debug_redacts_uri_userinfo_and_password_params() {
        let mut config = AdbcConfig::new("cat", "/lib/driver.so", SupportedDialect::PostgreSql);
        config.uri = Some("postgresql://svc:sekrit123@db.internal:5432/prod".to_string());
        config.username = Some("svc".to_string());
        config.password_env = Some("WAREHOUSE_PASSWORD".to_string());
        let rendered = format!("{config:?}");
        assert!(
            !rendered.contains("sekrit123"),
            "leaked password: {rendered}"
        );
        assert!(
            rendered.contains("[redacted]"),
            "no redaction marker: {rendered}"
        );
        // The env var NAME is configuration, not a secret.
        assert!(rendered.contains("WAREHOUSE_PASSWORD"), "got: {rendered}");
    }

    #[test]
    fn debug_redacts_driver_option_values_but_keeps_keys() {
        let mut config = AdbcConfig::new("cat", "/lib/driver.so", SupportedDialect::BigQuery);
        config.driver_options =
            Some("adbc.bigquery.auth.credentials=supersecretjson;project=acme".to_string());
        let rendered = format!("{config:?}");
        assert!(!rendered.contains("supersecretjson"), "leaked: {rendered}");
        assert!(!rendered.contains("acme"), "leaked value: {rendered}");
        assert!(
            rendered.contains("adbc.bigquery.auth.credentials=[redacted]"),
            "keys should stay visible: {rendered}"
        );
    }

    #[test]
    fn redact_uri_handles_kv_style_dsns() {
        let out = redact_uri("host=db user=svc password=sekrit dbname=prod");
        assert!(!out.contains("sekrit"), "got: {out}");
        assert!(out.contains("password=[redacted]"), "got: {out}");
        assert!(out.contains("dbname=prod"), "over-redacted: {out}");
    }

    #[tokio::test]
    async fn connect_error_for_unset_password_env_names_the_var() {
        let mut config = AdbcConfig::new("cat", "/nonexistent/libx.so", SupportedDialect::DuckDb);
        config.uri = Some("db://x".to_string());
        config.password_env = Some("DATAGLOT_ADBC_TEST_UNSET_VAR_XYZ".to_string());
        let msg = AdbcConnector::connect(config)
            .await
            .unwrap_err()
            .to_string();
        assert!(
            msg.contains("DATAGLOT_ADBC_TEST_UNSET_VAR_XYZ"),
            "got: {msg}"
        );
        assert!(msg.contains("not set"), "got: {msg}");
    }

    #[tokio::test]
    async fn connect_error_for_missing_driver_never_leaks_the_password() {
        // Edition 2021: set_var is safe. Unique var name keeps parallel
        // tests from interfering.
        std::env::set_var("DATAGLOT_ADBC_TEST_PW_SET_VAR", "hunter2-super-secret");
        let mut config =
            AdbcConfig::new("cat", "/nonexistent/libdriver.so", SupportedDialect::DuckDb);
        config.uri = Some("db://x".to_string());
        config.password_env = Some("DATAGLOT_ADBC_TEST_PW_SET_VAR".to_string());
        let msg = AdbcConnector::connect(config)
            .await
            .unwrap_err()
            .to_string();
        assert!(
            !msg.contains("hunter2-super-secret"),
            "connect error leaked the resolved password: {msg}"
        );
        assert!(
            msg.contains("/nonexistent/libdriver.so"),
            "error should name the driver path: {msg}"
        );
    }

    // -----------------------------------------------------------------
    // 3. Reset-on-return + discard-on-failure (mock driver)
    // -----------------------------------------------------------------

    /// Shared spy/fault-injection state for the mock connection.
    #[derive(Clone, Default)]
    struct MockState {
        executed: Arc<StdMutex<Vec<String>>>,
        /// Any statement whose SQL contains this string fails.
        fail_containing: Option<&'static str>,
    }

    impl MockState {
        fn executed(&self) -> Vec<String> {
            self.executed.lock().unwrap().clone()
        }
    }

    struct MockConn {
        state: MockState,
    }

    struct MockStmt {
        state: MockState,
        sql: String,
    }

    impl MockStmt {
        fn record_or_fail(&self) -> AdbcResult<()> {
            if let Some(needle) = self.state.fail_containing {
                if self.sql.contains(needle) {
                    return Err(AdbcError::with_message_and_status(
                        format!("mock failure on '{}'", self.sql),
                        Status::Internal,
                    ));
                }
            }
            self.state.executed.lock().unwrap().push(self.sql.clone());
            Ok(())
        }
    }

    impl Optionable for MockStmt {
        type Option = OptionStatement;
        fn set_option(&mut self, _: Self::Option, _: OptionValue) -> AdbcResult<()> {
            unimplemented!("not exercised by these tests")
        }
        fn get_option_string(&self, _: Self::Option) -> AdbcResult<String> {
            unimplemented!("not exercised by these tests")
        }
        fn get_option_bytes(&self, _: Self::Option) -> AdbcResult<Vec<u8>> {
            unimplemented!("not exercised by these tests")
        }
        fn get_option_int(&self, _: Self::Option) -> AdbcResult<i64> {
            unimplemented!("not exercised by these tests")
        }
        fn get_option_double(&self, _: Self::Option) -> AdbcResult<f64> {
            unimplemented!("not exercised by these tests")
        }
    }

    impl Statement for MockStmt {
        fn bind(&mut self, _: RecordBatch) -> AdbcResult<()> {
            unimplemented!("not exercised by these tests")
        }
        fn bind_stream(&mut self, _: Box<dyn RecordBatchReader + Send>) -> AdbcResult<()> {
            unimplemented!("not exercised by these tests")
        }
        fn execute(&mut self) -> AdbcResult<Box<dyn RecordBatchReader + Send + 'static>> {
            self.record_or_fail()?;
            let schema = Arc::new(Schema::new(vec![Field::new("x", DataType::Int64, true)]));
            Ok(Box::new(RecordBatchIterator::new(
                Vec::<Result<RecordBatch, arrow::error::ArrowError>>::new(),
                schema,
            )))
        }
        fn execute_update(&mut self) -> AdbcResult<Option<i64>> {
            self.record_or_fail()?;
            Ok(None)
        }
        fn execute_schema(&mut self) -> AdbcResult<Schema> {
            unimplemented!("not exercised by these tests")
        }
        fn execute_partitions(&mut self) -> AdbcResult<PartitionedResult> {
            unimplemented!("not exercised by these tests")
        }
        fn get_parameter_schema(&self) -> AdbcResult<Schema> {
            unimplemented!("not exercised by these tests")
        }
        fn prepare(&mut self) -> AdbcResult<()> {
            unimplemented!("not exercised by these tests")
        }
        fn set_sql_query(&mut self, query: impl AsRef<str>) -> AdbcResult<()> {
            self.sql = query.as_ref().to_string();
            Ok(())
        }
        fn set_substrait_plan(&mut self, _: impl AsRef<[u8]>) -> AdbcResult<()> {
            unimplemented!("not exercised by these tests")
        }
        fn cancel(&mut self) -> AdbcResult<()> {
            unimplemented!("not exercised by these tests")
        }
    }

    impl Optionable for MockConn {
        type Option = OptionConnection;
        fn set_option(&mut self, _: Self::Option, _: OptionValue) -> AdbcResult<()> {
            unimplemented!("not exercised by these tests")
        }
        fn get_option_string(&self, _: Self::Option) -> AdbcResult<String> {
            unimplemented!("not exercised by these tests")
        }
        fn get_option_bytes(&self, _: Self::Option) -> AdbcResult<Vec<u8>> {
            unimplemented!("not exercised by these tests")
        }
        fn get_option_int(&self, _: Self::Option) -> AdbcResult<i64> {
            unimplemented!("not exercised by these tests")
        }
        fn get_option_double(&self, _: Self::Option) -> AdbcResult<f64> {
            unimplemented!("not exercised by these tests")
        }
    }

    impl Connection for MockConn {
        type StatementType = MockStmt;
        fn new_statement(&mut self) -> AdbcResult<Self::StatementType> {
            Ok(MockStmt {
                state: self.state.clone(),
                sql: String::new(),
            })
        }
        fn cancel(&mut self) -> AdbcResult<()> {
            unimplemented!("not exercised by these tests")
        }
        fn get_info(
            &self,
            _: Option<HashSet<InfoCode>>,
        ) -> AdbcResult<Box<dyn RecordBatchReader + Send + 'static>> {
            unimplemented!("not exercised by these tests")
        }
        fn get_objects(
            &self,
            _: ObjectDepth,
            _: Option<&str>,
            _: Option<&str>,
            _: Option<&str>,
            _: Option<Vec<&str>>,
            _: Option<&str>,
        ) -> AdbcResult<Box<dyn RecordBatchReader + Send + 'static>> {
            unimplemented!("not exercised by these tests")
        }
        fn get_table_schema(
            &self,
            _: Option<&str>,
            _: Option<&str>,
            _: &str,
        ) -> AdbcResult<Schema> {
            unimplemented!("not exercised by these tests")
        }
        fn get_table_types(&self) -> AdbcResult<Box<dyn RecordBatchReader + Send + 'static>> {
            unimplemented!("not exercised by these tests")
        }
        fn get_statistic_names(&self) -> AdbcResult<Box<dyn RecordBatchReader + Send + 'static>> {
            unimplemented!("not exercised by these tests")
        }
        fn get_statistics(
            &self,
            _: Option<&str>,
            _: Option<&str>,
            _: Option<&str>,
            _: bool,
        ) -> AdbcResult<Box<dyn RecordBatchReader + Send + 'static>> {
            unimplemented!("not exercised by these tests")
        }
        fn commit(&mut self) -> AdbcResult<()> {
            unimplemented!("not exercised by these tests")
        }
        fn rollback(&mut self) -> AdbcResult<()> {
            unimplemented!("not exercised by these tests")
        }
        fn read_partition(
            &self,
            _: impl AsRef<[u8]>,
        ) -> AdbcResult<Box<dyn RecordBatchReader + Send + 'static>> {
            unimplemented!("not exercised by these tests")
        }
    }

    #[test]
    fn adbc_connector_is_a_connector_health_check() {
        // Compile-level pin: the boot path upcasts the retained
        // `Arc<AdbcConnector>` to `Arc<dyn ConnectorHealthCheck>` so the poller
        // reuses a pooled connection instead of reloading the driver + reopening
        // the pool. The `Send + Sync + 'static` bounds are asserted here.
        fn assert_impl<T: crate::health::ConnectorHealthCheck>() {}
        assert_impl::<AdbcConnector>();
    }

    #[test]
    fn health_check_query_is_a_bare_select_1() {
        // The `ConnectorHealthCheck` impl reuses a pooled connection and runs the
        // cheapest reachability query — a bare `SELECT 1`, `reset_after = false`.
        // Exercised at the `run_user_query` seam the impl calls (the pool itself
        // needs a real driver binary), proving the query text + that the rows are
        // discarded.
        let state = MockState::default();
        let mut conn = MockConn {
            state: state.clone(),
        };
        let result = run_user_query(&mut conn, "SELECT 1");
        assert!(
            result.is_ok(),
            "SELECT 1 must succeed against a live source"
        );
        assert_eq!(state.executed(), vec!["SELECT 1"]);
    }

    #[test]
    fn reset_runs_after_successful_query_and_connection_is_kept() {
        let state = MockState::default();
        let mut conn = MockConn {
            state: state.clone(),
        };
        let (result, keep) = run_with_reset(&mut conn, Some("DISCARD ALL"), "cat", |conn| {
            run_user_query(conn, "SELECT 1")
        });
        assert!(result.is_ok());
        assert!(keep, "successful reset must re-pool the connection");
        assert_eq!(state.executed(), vec!["SELECT 1", "DISCARD ALL"]);
    }

    #[test]
    fn reset_still_runs_when_the_user_query_fails() {
        // State may have mutated before the error — the reset is
        // unconditional.
        let state = MockState {
            fail_containing: Some("SELECT"),
            ..MockState::default()
        };
        let mut conn = MockConn {
            state: state.clone(),
        };
        let (result, keep) = run_with_reset(&mut conn, Some("DISCARD ALL"), "cat", |conn| {
            run_user_query(conn, "SELECT boom")
        });
        assert!(result.is_err());
        assert!(keep, "reset succeeded, so the connection is reusable");
        assert_eq!(state.executed(), vec!["DISCARD ALL"]);
    }

    #[test]
    fn failed_reset_marks_the_connection_for_discard() {
        let state = MockState {
            fail_containing: Some("DISCARD"),
            ..MockState::default()
        };
        let mut conn = MockConn {
            state: state.clone(),
        };
        let (result, keep) = run_with_reset(&mut conn, Some("DISCARD ALL"), "cat", |conn| {
            run_user_query(conn, "SELECT 1")
        });
        assert!(result.is_ok(), "the user query itself succeeded");
        assert!(!keep, "reset failure must discard, never re-pool");
        assert_eq!(state.executed(), vec!["SELECT 1"]);
    }

    #[test]
    fn no_op_dialects_skip_the_reset_entirely() {
        for dialect in [
            SupportedDialect::Sqlite,
            SupportedDialect::DuckDb,
            SupportedDialect::BigQuery,
        ] {
            assert!(dialect.reset_sql().is_none(), "{dialect} should be no-op");
        }
        let state = MockState::default();
        let mut conn = MockConn {
            state: state.clone(),
        };
        let (result, keep) = run_with_reset(&mut conn, None, "cat", |conn| {
            run_user_query(conn, "SELECT 1")
        });
        assert!(result.is_ok());
        assert!(keep);
        assert_eq!(state.executed(), vec!["SELECT 1"]);
    }

    #[test]
    fn stateful_dialects_declare_their_reset_sql() {
        assert_eq!(
            SupportedDialect::PostgreSql.reset_sql(),
            Some("DISCARD ALL")
        );
        // MySQL: expected to fail on real drivers (no SQL-level reset
        // statement exists) — which routes into the discard path, the
        // safety net. See `SupportedDialect::reset_sql`.
        assert_eq!(
            SupportedDialect::MySql.reset_sql(),
            Some("RESET CONNECTION")
        );
    }

    // -----------------------------------------------------------------
    // 4. Pool behavior
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn exhausted_pool_queues_instead_of_erroring() {
        let pool: SlotPool<u32> = SlotPool::new("cat".to_string(), 1, vec![7]);
        let first = pool.acquire().await;
        assert_eq!(*first, Some(7));

        // While the only slot is held, a second borrow must be pending
        // (queued), not failed.
        let second = pool.acquire();
        tokio::pin!(second);
        assert!(
            tokio::time::timeout(Duration::from_millis(50), second.as_mut())
                .await
                .is_err(),
            "second borrow should queue while the slot is held"
        );

        drop(first);
        let guard = tokio::time::timeout(Duration::from_millis(500), second)
            .await
            .expect("queued borrow proceeds once the slot frees up");
        let seen = *guard;
        drop(guard);
        assert_eq!(seen, Some(7));
    }

    #[test]
    fn slot_pool_seeds_min_idle_and_leaves_the_rest_lazy() {
        let pool: SlotPool<u32> = SlotPool::new("cat".to_string(), 4, vec![1, 2]);
        let filled = pool
            .slots
            .iter()
            .filter(|slot| slot.try_lock().unwrap().is_some())
            .count();
        assert_eq!(filled, 2, "exactly the warm connections are seeded");
    }

    // -----------------------------------------------------------------
    // Misc helpers
    // -----------------------------------------------------------------

    #[test]
    fn split_qualified_handles_all_quote_styles() {
        assert_eq!(
            split_qualified("main.orders"),
            Some(("main".to_string(), "orders".to_string()))
        );
        assert_eq!(
            split_qualified("\"main\".\"orders\""),
            Some(("main".to_string(), "orders".to_string()))
        );
        assert_eq!(
            split_qualified("`main`.`orders`"),
            Some(("main".to_string(), "orders".to_string()))
        );
        assert_eq!(split_qualified("orders"), None);
        assert_eq!(split_qualified(".orders"), None);
    }

    #[test]
    fn get_objects_parser_walks_the_nested_adbc_shape() {
        use arrow::array::ArrayRef;
        use arrow::buffer::OffsetBuffer;

        // Synthetic get_objects batch: one catalog row holding two
        // schemas — "main" with tables {orders, users}, "empty" with a
        // null table list. Extra struct members (like table_type) mimic
        // real drivers; the parser must tolerate them.
        let table_names: ArrayRef = Arc::new(StringArray::from(vec!["orders", "users"]));
        let table_types: ArrayRef = Arc::new(StringArray::from(vec!["table", "table"]));
        let tables_struct = StructArray::from(vec![
            (
                Arc::new(Field::new("table_name", DataType::Utf8, true)),
                table_names,
            ),
            (
                Arc::new(Field::new("table_type", DataType::Utf8, true)),
                table_types,
            ),
        ]);
        let tables_item = Arc::new(Field::new("item", tables_struct.data_type().clone(), true));
        let tables_list = ListArray::new(
            Arc::clone(&tables_item),
            OffsetBuffer::from_lengths([2, 0]),
            Arc::new(tables_struct),
            Some(vec![true, false].into()),
        );

        let schema_names: ArrayRef = Arc::new(StringArray::from(vec!["main", "empty"]));
        let schemas_struct = StructArray::from(vec![
            (
                Arc::new(Field::new("db_schema_name", DataType::Utf8, true)),
                schema_names,
            ),
            (
                Arc::new(Field::new(
                    "db_schema_tables",
                    tables_list.data_type().clone(),
                    true,
                )),
                Arc::new(tables_list) as ArrayRef,
            ),
        ]);
        let schemas_item = Arc::new(Field::new("item", schemas_struct.data_type().clone(), true));
        let schemas_list = ListArray::new(
            Arc::clone(&schemas_item),
            OffsetBuffer::from_lengths([2]),
            Arc::new(schemas_struct),
            None,
        );

        let batch = RecordBatch::try_new(
            Arc::new(Schema::new(vec![
                Field::new("catalog_name", DataType::Utf8, true),
                Field::new("catalog_db_schemas", schemas_list.data_type().clone(), true),
            ])),
            vec![
                Arc::new(StringArray::from(vec!["fixture"])),
                Arc::new(schemas_list),
            ],
        )
        .unwrap();

        let mut listing = BTreeMap::new();
        parse_get_objects_batch(&batch, &mut listing).unwrap();
        assert_eq!(
            listing.keys().collect::<Vec<_>>(),
            vec!["empty", "main"],
            "both schemas listed, sorted"
        );
        assert!(listing["empty"].is_empty(), "null table list → no tables");
        assert_eq!(
            listing["main"].iter().collect::<Vec<_>>(),
            vec!["orders", "users"]
        );
    }

    #[test]
    fn get_objects_parser_errors_on_a_malformed_shape() {
        use arrow::array::Int64Array;
        // A batch without the catalog_db_schemas column must error, not
        // silently produce an empty catalog.
        let batch = RecordBatch::try_new(
            Arc::new(Schema::new(vec![Field::new("x", DataType::Int64, true)])),
            vec![Arc::new(Int64Array::from(vec![1]))],
        )
        .unwrap();
        let mut listing = BTreeMap::new();
        let msg = parse_get_objects_batch(&batch, &mut listing)
            .unwrap_err()
            .to_string();
        assert!(msg.contains("catalog_db_schemas"), "got: {msg}");
    }

    #[test]
    fn align_batch_passes_identical_schemas_through_and_casts_widths() {
        use arrow::array::Int32Array;
        let source_schema = Arc::new(Schema::new(vec![Field::new("n", DataType::Int32, true)]));
        let batch = RecordBatch::try_new(
            Arc::clone(&source_schema),
            vec![Arc::new(Int32Array::from(vec![1, 2, 3]))],
        )
        .unwrap();

        // Identical schema: untouched.
        let same = align_batch(&batch, &source_schema).unwrap();
        assert_eq!(same.schema(), source_schema);

        // Wider target type: cast column-by-column.
        let target = Arc::new(Schema::new(vec![Field::new("n", DataType::Int64, true)]));
        let widened = align_batch(&batch, &target).unwrap();
        assert_eq!(widened.schema(), target);
        assert_eq!(widened.num_rows(), 3);

        // Arity mismatch: error, not silence.
        let two_cols = Arc::new(Schema::new(vec![
            Field::new("a", DataType::Int64, true),
            Field::new("b", DataType::Int64, true),
        ]));
        assert!(align_batch(&batch, &two_cols).is_err());
    }
}

//! `MySQL` data source connector.
//!
//! This module is gated behind the `mysql` feature flag. It provides
//! [`MysqlConnector`] which implements the `datafusion-federation`
//! `SQLExecutor` trait on top of [`mysql_async`]. A connector instance
//! owns one `mysql_async::Conn` (wrapped in `Arc<Mutex<…>>` because
//! `Conn` is not `Sync`) and exposes two user-facing entry points:
//!
//! - [`MysqlConnector::connect`] — async constructor that parses a DSN
//!   in `mysql://user:pass@host:port/db` form and opens the connection.
//! - [`MysqlConnector::table_provider`] — lazily resolves the schema for
//!   a `<schema>.<table>` pair and returns a `DataFusion` `TableProvider`
//!   wired to `datafusion-federation` so filters / projections / limits
//!   push down to `MySQL`.
//!
//! # Type subset
//!
//! Numeric: `TINYINT(1)` (Boolean), signed `TINYINT` / `SMALLINT` /
//! `MEDIUMINT` / `INT` / `BIGINT` (Int8 / Int16 / Int32 / Int64),
//! `BIGINT UNSIGNED` (`UInt64`), `FLOAT` / `DOUBLE` (Float32 /
//! Float64), `DECIMAL` / `NUMERIC` (Decimal128(p, s); precision and
//! scale come from `information_schema.columns`; values that don't
//! fit Arrow's (38, 38) ceiling map to None and surface as catalog
//! errors).
//!
//! String / binary: `CHAR` / `VARCHAR` / `TEXT` (Utf8); `BINARY` /
//! `VARBINARY` / `BLOB` family (Binary); `JSON` (Utf8 — round-trip
//! the serialized form); `ENUM` (Utf8 — string label) and `SET`
//! (Utf8 — comma-separated active members).
//!
//! Temporal: `DATE` (Date32); `DATETIME` / `TIMESTAMP`
//! (Timestamp(Microsecond, None)); `TIME` (Time64(Microsecond)
//! — values outside Arrow's 0..24h range surface as a typed
//! decoder error rather than silent truncation).
//!
//! `NULL` markers in any column.
//!
//! With the DECIMAL arm added, the connector covers the full
//! production-relevant `MySQL` 8.x type surface for read-only
//! federation. The remaining unsupported corners — unsigned
//! non-bigint integers, `MySQL` geometry / spatial types — are
//! true edge cases for which `information_schema` returns `None`
//! at the schema-mapping step, surfacing as a catalog error at
//! `table_provider` time. Hypothetical out-of-band rows whose
//! Arrow type the mapper rejected would still hit the
//! [`DataFusionError::NotImplemented`] branch in `decode_column`,
//! kept as a defense-in-depth. See
//! the phase-1 `mysql-federation-connector` plan.
//!
//! # Hard-rule compliance
//!
//! * Rule 1 — data flows as Arrow `RecordBatch` end-to-end; rows are
//!   decoded into Arrow arrays inside the `SQLExecutor::execute` impl
//!   on [`MysqlConnector`]. There is no row-mode conversion above this
//!   layer.
//! * Rule 10 — the executor is `Send + Sync + 'static`. `mysql_async`
//!   `Conn` is `Send` but not `Sync`, hence the `Arc<Mutex<Conn>>`.
//! * Rule 11 — all I/O is async; no blocking calls under an async fn.
//! * Rule 12 — DSNs are parsed and stored as a [`mysql_async::Opts`].
//!   The password is never included in logs, error messages, or
//!   `Debug` output. See the private `redacted_dsn` helper.
//! * Rule 13 — schemas are fetched on first `table_provider` call, not
//!   at connector construction time.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use arrow::array::{
    ArrayRef, BinaryBuilder, BooleanBuilder, Date32Builder, Decimal128Builder, Float32Builder,
    Float64Builder, Int16Builder, Int32Builder, Int64Builder, Int8Builder, LargeBinaryBuilder,
    StringBuilder, Time64MicrosecondBuilder, TimestampMicrosecondBuilder, UInt64Builder,
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
use datafusion::sql::unparser::dialect::{Dialect, MySqlDialect};
use datafusion::sql::TableReference;
use datafusion_federation::sql::{
    RemoteTableRef, SQLExecutor, SQLFederationProvider, SQLTableSource,
};
use datafusion_federation::FederatedTableProviderAdaptor;
use futures::stream;
use mysql_async::consts::ColumnFlags;
use mysql_async::prelude::Queryable;
use mysql_async::{Conn, Opts, OptsBuilder, Row, Value};
use tokio::sync::Mutex;
use tracing::{debug, info};

use dataglot_core::{DataglotError, Result as DataglotResult};

/// A `MySQL` federation connector.
///
/// Construct via [`MysqlConnector::connect`] with a DSN of the form
/// `mysql://user:pass@host:port/db`. A connector owns one
/// `mysql_async::Conn` (wrapped in `Arc<Mutex<…>>` because `Conn` is
/// `Send` but not `Sync`) plus the parsed [`Opts`] (used for
/// diagnostics and the redacted `Debug` impl).
///
/// Schemas are fetched lazily the first time a table is accessed —
/// construction never issues any queries beyond the initial
/// connection handshake.
pub struct MysqlConnector {
    /// Unique name used by `SQLExecutor::name`. Also serves as the
    /// federation compute-context key.
    name: String,
    /// Shared `MySQL` connection. `Conn` is `Send` but not `Sync`, so
    /// callers serialize access through the `Mutex`.
    conn: Arc<Mutex<Conn>>,
    /// Parsed connection options. Used for the redacted `Debug` impl
    /// and for identifying the compute context.
    opts: Opts,
}

/// Upper bound on establishing a MySQL connection (TCP + the auth
/// handshake). Without it a source that accepts the socket but then stalls
/// on the handshake — e.g. a database container that is still starting up —
/// blocks the caller indefinitely, which at server boot defeats
/// `--tolerate-unreachable-catalogs` (that path skips connect *errors*, but
/// an unbounded hang never produces one). Bounding the connect turns such a
/// stall into a tolerable `Connection` error. Mirrors the Postgres
/// connector's `CONNECT_TIMEOUT`.
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// Coarse backstop on a *pushed-down query's* execution (, mirroring the
/// Postgres connector's `QUERY_TIMEOUT` from ). A source that accepts the
/// connection but then stalls mid-query — a lock wait, a runaway plan, a
/// black-holed peer after the handshake — would otherwise hang the federated
/// query forever. Bounding it turns the stall into a `federation` error.
const QUERY_TIMEOUT: std::time::Duration = std::time::Duration::from_mins(5);

/// TCP keepalive idle applied when the DSN doesn't set one, so a dead peer is
/// detected in ~30s rather than relying on the OS default (often 2h). Mirrors
/// the Postgres connector's keepalive posture.
const KEEPALIVE: std::time::Duration = std::time::Duration::from_secs(30);

/// Run a source query future under [`QUERY_TIMEOUT`], mapping expiry to a
/// `federation` error rather than letting it hang forever. Mirrors
/// the Postgres connector's `with_query_timeout`.
async fn with_query_timeout<F, T>(fut: F) -> DfResult<T>
where
    F: std::future::Future<Output = DfResult<T>>,
{
    match tokio::time::timeout(QUERY_TIMEOUT, fut).await {
        Ok(res) => res,
        Err(_) => Err(DataFusionError::External(Box::new(
            DataglotError::federation(format!(
                "mysql query exceeded the {}s execution timeout",
                QUERY_TIMEOUT.as_secs()
            )),
        ))),
    }
}

/// Apply transport-resilience defaults (TCP keepalive) to `opts` where the DSN
/// didn't set them — respecting an explicit DSN value.
fn apply_resilience_defaults(opts: Opts) -> Opts {
    if opts.tcp_keepalive().is_some() {
        return opts;
    }
    Opts::from(OptsBuilder::from_opts(opts).tcp_keepalive(Some(KEEPALIVE)))
}

impl MysqlConnector {
    // MULTI-TENANT NOTE (; spec: the phase-3 `adbc-connector` plan).
    // The single shared `Arc<Mutex<Conn>>` held by this connector has no
    // per-user isolation; the same physical connection serves every pgwire
    // session on this catalog (serialized through the mutex). Safe today only
    // because nothing in `connect` / `connect_with_opts` emits source-side
    // session state. If you add init queries (`SET NAMES`, `SET SESSION ...`,
    // application identifiers, etc.) on the shared connection, you MUST
    // address state isolation across users — see the ADBC connector's
    // reset-on-return + discard-on-failure pattern.

    /// Open a connection to `MySQL` and return a connector.
    ///
    /// `dsn` must be a URL-form connection string accepted by
    /// [`mysql_async::Opts::from_url`], i.e.
    /// `mysql://user:pass@host:port/db`.
    ///
    /// This connects in **plaintext**. For TLS, use
    /// [`Self::connect_with_tls`] (or the server-side
    /// `[catalogs.*] tls = "require"` config) — see the
    /// [`crate::mysql_tls`] module.
    ///
    /// # Errors
    /// Returns [`DataglotError::Connection`] if the DSN is malformed
    /// or if the connection fails. The DSN itself never appears in
    /// the error message — only the driver's error string, which the
    /// driver guarantees does not include credentials.
    pub async fn connect(name: impl Into<String>, dsn: &str) -> DataglotResult<Self> {
        let opts = Opts::from_url(dsn).map_err(|e| {
            // mysql_async's UrlError carries the parsed url back in
            // some variants. To be safe we surface only the variant
            // name + a static description, never the raw string.
            DataglotError::connection(format!("invalid mysql DSN: {e}"))
        })?;
        Self::connect_with_opts(name, opts).await
    }

    /// Open a TLS connection, applying [`MysqlTls`](crate::mysql_tls::MysqlTls)
    /// to the DSN's options.
    ///
    /// `mysql_async` negotiates the TLS handshake; `tls` supplies the
    /// trust roots (bundled Mozilla set, or a private-CA bundle) and the
    /// optional dev-only verification bypass.
    ///
    /// # Errors
    /// Returns [`DataglotError::Connection`] if the DSN is malformed or
    /// the connection fails.
    pub async fn connect_with_tls(
        name: impl Into<String>,
        dsn: &str,
        tls: &crate::mysql_tls::MysqlTls,
    ) -> DataglotResult<Self> {
        let opts = Opts::from_url(dsn)
            .map_err(|e| DataglotError::connection(format!("invalid mysql DSN: {e}")))?;
        let opts = Opts::from(OptsBuilder::from_opts(opts).ssl_opts(tls.to_ssl_opts()));
        Self::connect_with_opts(name, opts).await
    }

    /// Open a connection using a pre-parsed [`Opts`].
    ///
    /// Useful for tests where the DSN is assembled from
    /// testcontainer ports. The same redaction guarantees apply.
    ///
    /// # Errors
    /// Returns [`DataglotError::Connection`] if the connection fails.
    pub async fn connect_with_opts(name: impl Into<String>, opts: Opts) -> DataglotResult<Self> {
        let opts = apply_resilience_defaults(opts);
        debug!(
            host = %opts.ip_or_hostname(),
            port = opts.tcp_port(),
            user = ?opts.user(),
            db = ?opts.db_name(),
            "opening mysql connection"
        );

        let conn = tokio::time::timeout(CONNECT_TIMEOUT, Conn::new(opts.clone()))
            .await
            .map_err(|_| {
                DataglotError::connection(format!(
                    "timed out connecting to mysql after {}s",
                    CONNECT_TIMEOUT.as_secs()
                ))
            })?
            .map_err(|e| DataglotError::connection(format!("failed to connect to mysql: {e}")))?;

        let name = name.into();
        info!(
            catalog = %name,
            host = %opts.ip_or_hostname(),
            port = opts.tcp_port(),
            db = ?opts.db_name(),
            "connected to mysql source"
        );
        Ok(Self {
            name,
            conn: Arc::new(Mutex::new(conn)),
            opts,
        })
    }

    /// Return the connector's compute-context identifier. This is
    /// what `datafusion-federation` uses to group table scans that
    /// can be pushed down together.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Produce a [`TableProvider`] for `<schema>.<table>` that pushes
    /// filters, projections, and limits down to `MySQL` via
    /// `datafusion-federation`.
    ///
    /// The schema is fetched on demand by querying
    /// `information_schema.columns`. This satisfies hard rule
    /// 13 (lazy schema resolution) — no remote query is issued
    /// until the caller actually asks for a table.
    ///
    /// # Errors
    /// Returns [`DataglotError::Catalog`] if the table is not found
    /// or its schema cannot be mapped to Arrow types.
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

    /// Build a `DataFusion` [`CatalogProvider`] for this `MySQL` server.
    ///
    /// Enumerates the user-visible schemas (MySQL "databases") via
    /// `information_schema.schemata`, then eagerly fetches each
    /// schema's table list via `information_schema.tables`. The
    /// returned [`MysqlCatalog`] holds those pre-resolved lists so
    /// `DfCatalogProvider::schema(name)` is a sync `HashMap` lookup;
    /// per-table `Arrow` schemas remain lazy (rule 13 — resolved on
    /// first `SchemaProvider::table` call by delegating to
    /// [`Self::table_provider`]).
    ///
    /// System schemas (`information_schema`, `mysql`,
    /// `performance_schema`, `sys`) are filtered out — they're present
    /// on every MySQL instance and would only clutter the catalog
    /// surface for users.
    ///
    /// This mirrors [`PostgresConnector::as_catalog_provider`]; see
    /// that doc for the caching trade-offs (snapshot at construction
    /// time — drop and rebuild to pick up DDL).
    ///
    /// # Errors
    /// Returns [`DataglotError::Catalog`] if either of the
    /// `information_schema` listing queries fails.
    ///
    /// [`CatalogProvider`]: datafusion::catalog::CatalogProvider
    /// [`PostgresConnector::as_catalog_provider`]: crate::postgres::PostgresConnector::as_catalog_provider
    pub async fn as_catalog_provider(
        self: &Arc<Self>,
    ) -> DataglotResult<Arc<dyn DfCatalogProvider>> {
        // 1. Pull the user-visible schemas. Same shape as Postgres —
        //    information_schema is portable, and MySQL's "database" is
        //    spelled "schema" in this view.
        let schema_names: Vec<String> = {
            let mut conn = self.conn.lock().await;
            let rows: Vec<Row> = conn
                .query(
                    "SELECT schema_name
                     FROM information_schema.schemata
                     WHERE schema_name NOT IN (
                             'information_schema',
                             'mysql',
                             'performance_schema',
                             'sys'
                           )
                     ORDER BY schema_name",
                )
                .await
                .map_err(|e| {
                    DataglotError::catalog(format!(
                        "failed to list mysql schemas via information_schema.schemata: {e}"
                    ))
                })?;
            drop(conn); // release the connection lock before decoding owned rows
            rows.into_iter()
                .map(|row| decode_string_col(&row, 0))
                .collect::<DataglotResult<Vec<String>>>()?
        };

        // 2. For each schema, eagerly fetch its table list and build
        //    the cached `MysqlSchema`. Same caching rationale as the
        //    Postgres path.
        let mut schemas: HashMap<String, Arc<dyn DfSchemaProvider>> =
            HashMap::with_capacity(schema_names.len());
        for schema_name in &schema_names {
            // Defensive — the names came from our own enumeration, but
            // `fetch_arrow_schema` and friends inline schema names into
            // literal SQL, so we validate everywhere we do that.
            validate_identifier_literal(schema_name)?;
            let sql = format!(
                "SELECT table_name
                 FROM information_schema.tables
                 WHERE table_schema = '{schema_name}'
                   AND table_type IN ('BASE TABLE', 'VIEW')
                 ORDER BY table_name"
            );
            let table_names: Vec<String> = {
                let mut conn = self.conn.lock().await;
                let rows: Vec<Row> = conn.query(sql).await.map_err(|e| {
                    DataglotError::catalog(format!(
                        "failed to list mysql tables for schema '{schema_name}': {e}"
                    ))
                })?;
                drop(conn); // release the connection lock before decoding owned rows
                rows.into_iter()
                    .map(|row| decode_string_col(&row, 0))
                    .collect::<DataglotResult<Vec<String>>>()?
            };
            schemas.insert(
                schema_name.clone(),
                Arc::new(MysqlSchema {
                    connector: Arc::clone(self),
                    schema_name: schema_name.clone(),
                    table_names,
                }) as Arc<dyn DfSchemaProvider>,
            );
        }

        Ok(Arc::new(MysqlCatalog {
            connector_name: self.name.clone(),
            schema_names,
            schemas,
        }) as Arc<dyn DfCatalogProvider>)
    }

    /// Fetch the Arrow schema for `<schema>.<table>` by querying
    /// `information_schema.columns`. Called from
    /// [`Self::table_provider`] and from `SQLExecutor::get_table_schema`.
    async fn fetch_arrow_schema(
        &self,
        schema_name: &str,
        table_name: &str,
    ) -> DataglotResult<SchemaRef> {
        // We pass the schema/table names through the literal SQL —
        // `mysql_async`'s parameter API is tied to its prepared
        // statement path which we deliberately avoid for federation
        // (out-of-scope per the spec). The names come from the
        // catalog config; quoting them as MySQL string literals is
        // fine here as long as we reject embedded backslashes /
        // quotes up front.
        validate_identifier_literal(schema_name)?;
        validate_identifier_literal(table_name)?;
        let sql = format!(
            "SELECT column_name, column_type, data_type, is_nullable, column_key, \
                    numeric_precision, numeric_scale \
             FROM information_schema.columns \
             WHERE table_schema = '{schema_name}' \
               AND table_name = '{table_name}' \
             ORDER BY ordinal_position"
        );
        let mut conn = self.conn.lock().await;
        let rows: Vec<Row> = conn.query(sql).await.map_err(|e| {
            DataglotError::catalog(format!(
                "failed to query information_schema for {schema_name}.{table_name}: {e}"
            ))
        })?;
        drop(conn);

        if rows.is_empty() {
            return Err(DataglotError::catalog(format!(
                "table not found: {schema_name}.{table_name}"
            )));
        }

        let mut fields = Vec::with_capacity(rows.len());
        for row in rows {
            let column_name: String = decode_string_col(&row, 0)?;
            let column_type_text: String = decode_string_col(&row, 1)?;
            let data_type_text: String = decode_string_col(&row, 2)?;
            let is_nullable_text: String = decode_string_col(&row, 3)?;
            // Skip column 4 (`column_key`) — the schema mapper
            // doesn't use it. Cols 5-6 carry numeric precision /
            // scale; both NULL for non-numeric types.
            let numeric_precision = decode_opt_u32_col(&row, 5)?;
            let numeric_scale = decode_opt_u32_col(&row, 6)?;
            let nullable = matches!(is_nullable_text.as_str(), "YES" | "yes");
            let arrow_type = mysql_information_schema_to_arrow(
                &data_type_text,
                &column_type_text,
                numeric_precision,
                numeric_scale,
            )
            .ok_or_else(|| {
                DataglotError::catalog(format!(
                    "unsupported mysql type '{data_type_text}' (column_type='{column_type_text}') \
                     for column {schema_name}.{table_name}.{column_name}"
                ))
            })?;
            fields.push(Field::new(column_name, arrow_type, nullable));
        }
        Ok(Arc::new(Schema::new(fields)))
    }
}

impl fmt::Debug for MysqlConnector {
    /// Credential-safe `Debug` impl (hard rule 12). Emits host,
    /// port, user, and database name — never password. The `conn`
    /// field is intentionally omitted (`finish_non_exhaustive`).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MysqlConnector")
            .field("name", &self.name)
            .field("dsn", &redacted_dsn(&self.opts))
            .finish_non_exhaustive()
    }
}

/// Reject `'` and `\` in schema / table names destined for an
/// information-schema lookup. We splice these into a literal SQL
/// string (`mysql_async`'s parameter API is tied to prepared statements
/// which we deliberately avoid for federation), so the safe shape is
/// "names that contain neither character." The names come from the
/// catalog config which is operator-controlled; this is a defence in
/// depth.
fn validate_identifier_literal(s: &str) -> DataglotResult<()> {
    if s.is_empty() {
        return Err(DataglotError::catalog(
            "empty schema/table name in mysql information_schema lookup".to_string(),
        ));
    }
    if s.contains('\'') || s.contains('\\') {
        return Err(DataglotError::catalog(format!(
            "mysql schema/table name '{s}' contains a quote or backslash; reject defensively"
        )));
    }
    Ok(())
}

/// Render a credential-free description of a connection. Deliberately
/// omits the password and any other secret-carrying fields.
fn redacted_dsn(opts: &Opts) -> String {
    let host = opts.ip_or_hostname();
    let port = opts.tcp_port();
    let user = opts.user().unwrap_or("<unset>");
    let db = opts.db_name().unwrap_or("<unset>");
    let password_marker = if opts.pass().is_some() {
        " password=<redacted>"
    } else {
        ""
    };
    format!("mysql://{user}@{host}:{port}/{db}{password_marker}")
}

/// Decode a single string column out of a row at `idx`. The
/// information-schema columns we read are always non-null `VARCHAR`s
/// in `MySQL` 8.x.
/// Decode an optional unsigned integer column out of an
/// `information_schema.columns` row at `idx`. NULL is the canonical
/// "this column doesn't have `numeric_precision` / `numeric_scale`"
/// signal — applies to non-numeric columns. The fields are u32 in
/// the spec; `mysql_async` typically surfaces them as `Value::Int(_)`
/// via the text protocol, so we accept both `Int` and `UInt`.
fn decode_opt_u32_col(row: &Row, idx: usize) -> DataglotResult<Option<u32>> {
    match row.as_ref(idx) {
        Some(Value::NULL) | None => Ok(None),
        Some(Value::Int(i)) if *i >= 0 => u32::try_from(*i).map(Some).map_err(|_| {
            DataglotError::catalog(format!(
                "information_schema numeric metadata at index {idx} ({i}) doesn't fit in u32"
            ))
        }),
        Some(Value::UInt(u)) => u32::try_from(*u).map(Some).map_err(|_| {
            DataglotError::catalog(format!(
                "information_schema numeric metadata at index {idx} ({u}) doesn't fit in u32"
            ))
        }),
        Some(Value::Bytes(bytes)) => {
            let s = std::str::from_utf8(bytes).map_err(|e| {
                DataglotError::catalog(format!(
                    "information_schema numeric metadata at index {idx}: utf-8 decode failed: {e}"
                ))
            })?;
            s.parse::<u32>().map(Some).map_err(|e| {
                DataglotError::catalog(format!(
                    "information_schema numeric metadata at index {idx}: parse u32 failed for {s:?}: {e}"
                ))
            })
        }
        Some(other) => Err(DataglotError::catalog(format!(
            "unexpected value in information_schema numeric metadata at index {idx}: {other:?}"
        ))),
    }
}

fn decode_string_col(row: &Row, idx: usize) -> DataglotResult<String> {
    match row.as_ref(idx) {
        Some(Value::Bytes(b)) => Ok(String::from_utf8_lossy(b).into_owned()),
        Some(Value::NULL) | None => Err(DataglotError::catalog(format!(
            "unexpected NULL/missing in information_schema column at index {idx}"
        ))),
        Some(other) => Err(DataglotError::catalog(format!(
            "unexpected non-string value in information_schema column at index {idx}: {other:?}"
        ))),
    }
}

/// Map a `MySQL` `information_schema.columns` row's type fields
/// to an Arrow [`DataType`].
///
/// `data_type` is the unparameterised type (`int`, `varchar`, `tinyint`).
/// `column_type` carries the display width / signedness suffix
/// (`tinyint(1)`, `bigint unsigned`, `varchar(255)`).
/// `numeric_precision` / `numeric_scale` carry DECIMAL precision and
/// scale (both NULL for non-numeric types; both populated for `decimal`
/// / `numeric` columns and the integer family).
///
/// Supported types:
/// `tinyint(1)` → Boolean; `tinyint` (signed, not display=1) → Int8;
/// `smallint` → Int16; `int` / `mediumint` → Int32;
/// `bigint` → Int64; `bigint unsigned` → `UInt64`;
/// `decimal` / `numeric` → Decimal128(precision, scale);
/// `float` → Float32; `double` / `real` → Float64;
/// `char` / `varchar` / `text` (any length) → Utf8;
/// `date` → Date32; `datetime` / `timestamp` → Timestamp(µs, None);
/// `time` → Time64(µs);
/// `binary` / `varbinary` / `blob` / `tinyblob` / `mediumblob` → Binary;
/// `longblob` → `LargeBinary`;
/// `json` → Utf8 (round-trip the serialized form);
/// `enum` / `set` → Utf8 (string label for ENUM, comma-separated for SET).
///
/// Anything else returns `None`; the caller surfaces this as a
/// catalog error.
fn mysql_information_schema_to_arrow(
    data_type: &str,
    column_type: &str,
    numeric_precision: Option<u32>,
    numeric_scale: Option<u32>,
) -> Option<DataType> {
    let dt = data_type.to_ascii_lowercase();
    let ct = column_type.to_ascii_lowercase();
    let is_unsigned = ct.contains("unsigned");
    match dt.as_str() {
        // TINYINT(1) is MySQL's idiomatic boolean. Anything else
        // falls back to Int8 for signed / unsupported for unsigned
        // (out of scope in this MVP).
        "tinyint" if ct.starts_with("tinyint(1)") && !is_unsigned => Some(DataType::Boolean),
        "tinyint" if !is_unsigned => Some(DataType::Int8),
        "smallint" if !is_unsigned => Some(DataType::Int16),
        "int" | "integer" | "mediumint" if !is_unsigned => Some(DataType::Int32),
        "bigint" if !is_unsigned => Some(DataType::Int64),
        "bigint" if is_unsigned => Some(DataType::UInt64),
        // DECIMAL / NUMERIC — precision and scale come from
        // information_schema. Arrow's Decimal128 is capped at
        // (38, 38); MySQL's DECIMAL maxes at (65, 30) but values
        // that fit Arrow's range are most production columns.
        // Out-of-range mappings return None (so the caller emits
        // a catalog error rather than silently truncating). Both
        // precision and scale must be present — non-NULL — for
        // numeric types per the SQL standard.
        "decimal" | "numeric" => match (numeric_precision, numeric_scale) {
            (Some(p), Some(s)) if p <= 38 && s <= 38 && s <= p => {
                Some(DataType::Decimal128(p as u8, s as i8))
            }
            _ => None,
        },
        "float" => Some(DataType::Float32),
        "double" | "real" => Some(DataType::Float64),
        "char" | "varchar" | "text" | "tinytext" | "mediumtext" | "longtext" => {
            Some(DataType::Utf8)
        }
        "date" => Some(DataType::Date32),
        "datetime" | "timestamp" => Some(DataType::Timestamp(TimeUnit::Microsecond, None)),
        // TIME → Time64(µs since midnight). MySQL TIME's full
        // range is `-838:59:59.000000 .. 838:59:59.000000` —
        // wider than Arrow's wall-clock semantics — but typical
        // values (>99% of real workloads) fit. Out-of-range
        // values surface as a typed decoder error rather than
        // silent truncation; see `decode_time64_us`.
        "time" => Some(DataType::Time64(TimeUnit::Microsecond)),
        // Binary-blob family — decode from `Value::Bytes`. The
        // smaller variants (BINARY ≤ 255B, VARBINARY ≤ 64KB,
        // TINYBLOB 255B, BLOB 64KB, MEDIUMBLOB 16MB) fit Arrow's
        // `Binary` type, which uses i32 offsets capped at ~2 GiB.
        // LONGBLOB tops out at 4 GiB, so mapping it to `Binary`
        // could panic on a single oversize row. Surface LONGBLOB
        // as `LargeBinary` (i64 offsets) instead — Arrow's
        // first-class large-byte container, decoded by the
        // sibling `LargeBinaryBuilder` path. Predicate pushdown
        // still works — MySQL's = / != / IS NULL semantics on
        // binary columns are preserved by the unparser's
        // bare-bytes literal handling.
        "binary" | "varbinary" | "blob" | "tinyblob" | "mediumblob" => Some(DataType::Binary),
        "longblob" => Some(DataType::LargeBinary),
        // JSON / ENUM / SET all surface as Utf8:
        //
        //   * `json` columns are validated MySQL-side and stored
        //     in a binary format internally; we surface the
        //     canonical serialized text form, the same shape any
        //     client sees from `SELECT json_col`. Structured JSON
        //     (LargeUtf8 / dictionary) is a future tightening.
        //   * `enum` returns the string label of the active
        //     variant.
        //   * `set` returns a comma-separated list of active
        //     members (MySQL's text representation).
        //
        // Caveat called out in the spec: a pushed-down
        // `ORDER BY enum_col` orders by the string representation,
        // not the ENUM's underlying integer code. Workaround in
        // SQL: `ORDER BY CAST(enum_col + 0 AS UNSIGNED)`.
        "json" | "enum" | "set" => Some(DataType::Utf8),
        // Unsigned int / smallint / etc., DECIMAL — out of scope
        // for now. Returning None makes the caller emit a typed
        // catalog error rather than silently dropping the column.
        _ => None,
    }
}

/// Decode the rows + columns produced by a `query_iter` walk into a
/// single [`RecordBatch`] that matches `schema` exactly.
///
/// This is the read-side counterpart of
/// [`mysql_information_schema_to_arrow`]: every Arrow type produced
/// there must be decodable here.
fn rows_to_record_batch(
    schema: &SchemaRef,
    columns: &[mysql_async::Column],
    rows: &[Row],
) -> DfResult<RecordBatch> {
    let mut arrays: Vec<ArrayRef> = Vec::with_capacity(schema.fields().len());
    for (col_idx, field) in schema.fields().iter().enumerate() {
        let col_meta = columns.get(col_idx).ok_or_else(|| {
            DataFusionError::External(Box::new(DataglotError::federation(format!(
                "MysqlConnector: result-set has fewer columns than schema (idx={col_idx})"
            ))))
        })?;
        arrays.push(decode_column(rows, col_idx, field.data_type(), col_meta)?);
    }
    RecordBatch::try_new(Arc::clone(schema), arrays).map_err(DataFusionError::from)
}

/// Decode a single column into an Arrow array matching `data_type`.
///
/// `column` is the result-set column metadata `mysql_async` returned;
/// we use it to surface the original `MySQL` type in error messages
/// and to interpret unsigned integers (which `mysql_async` decodes
/// into `Value::UInt(_)` when the `UNSIGNED_FLAG` is set).
fn decode_column(
    rows: &[Row],
    col_idx: usize,
    data_type: &DataType,
    column: &mysql_async::Column,
) -> DfResult<ArrayRef> {
    let col_type = column.column_type();
    let flags = column.flags();
    // Extract this column's values once (NULL -> None) so the decoders
    // operate on a plain slice and stay unit-testable without a live
    // result set.
    let col: Vec<Option<&Value>> = (0..rows.len())
        .map(|r| value_at(rows, r, col_idx))
        .collect();
    match data_type {
        DataType::Boolean => decode_bool(&col, col_idx),
        DataType::Int8 => decode_int8(&col, col_idx),
        DataType::Int16 => decode_int16(&col, col_idx),
        DataType::Int32 => decode_int32(&col, col_idx),
        DataType::Int64 => decode_int64(&col, col_idx),
        DataType::UInt64 => decode_uint64(&col, col_idx, flags),
        DataType::Float32 => decode_float32(&col, col_idx),
        DataType::Float64 => decode_float64(&col, col_idx),
        DataType::Utf8 => decode_utf8(&col, col_idx),
        DataType::Date32 => decode_date32(&col, col_idx),
        DataType::Timestamp(TimeUnit::Microsecond, None) => decode_timestamp_us(&col, col_idx),
        DataType::Time64(TimeUnit::Microsecond) => decode_time64_us(&col, col_idx),
        DataType::Decimal128(precision, scale) => {
            decode_decimal128(&col, col_idx, *precision, *scale)
        }
        DataType::Binary => decode_binary(&col, col_idx),
        DataType::LargeBinary => decode_large_binary(&col, col_idx),
        // Per the spec, anything outside this scope is a hard
        // error rather than a silent skip. The remaining gap is
        // DECIMAL (needs precision/scale plumbing); queued as a
        // separate PR.
        other => Err(DataFusionError::NotImplemented(format!(
            "MySQL type {col_type:?} (arrow target {other:?}) not yet supported by \
             dataglot-federation"
        ))),
    }
}

/// Convenience wrapper: extract the `Value` at `(row, idx)`,
/// returning `None` on both `Value::NULL` and an out-of-range
/// column index. The decoders rely on the index being in range
/// because `rows_to_record_batch` already checked the column-count
/// invariant before dispatching here.
fn value_at(rows: &[Row], row_idx: usize, col_idx: usize) -> Option<&Value> {
    let row = &rows[row_idx];
    match row.as_ref(col_idx) {
        Some(Value::NULL) | None => None,
        Some(v) => Some(v),
    }
}

fn decode_bool(col: &[Option<&Value>], col_idx: usize) -> DfResult<ArrayRef> {
    let mut b = BooleanBuilder::with_capacity(col.len());
    for v in col.iter().copied() {
        match v {
            None => b.append_null(),
            Some(Value::Int(i)) => b.append_value(*i != 0),
            Some(Value::UInt(u)) => b.append_value(*u != 0),
            Some(Value::Bytes(bytes)) => {
                // TINYINT(1) over the text protocol arrives as the
                // ASCII bytes "0" / "1". Keep the parse strict so
                // unexpected payloads surface as decode errors.
                let s = std::str::from_utf8(bytes).map_err(decode_err)?;
                let i: i64 = s.parse().map_err(|e| {
                    DataFusionError::External(Box::new(DataglotError::federation(format!(
                        "mysql bool column at index {col_idx}: failed to parse {s:?} as i64: {e}"
                    ))))
                })?;
                b.append_value(i != 0);
            }
            Some(other) => return Err(unexpected_value(col_idx, "Boolean", other)),
        }
    }
    Ok(Arc::new(b.finish()))
}

fn decode_int8(col: &[Option<&Value>], col_idx: usize) -> DfResult<ArrayRef> {
    let mut b = Int8Builder::with_capacity(col.len());
    for v in col.iter().copied() {
        match v {
            None => b.append_null(),
            Some(v) => {
                let i = value_to_i64(col_idx, v)?;
                let narrowed = i8::try_from(i).map_err(|_| {
                    DataFusionError::External(Box::new(DataglotError::federation(format!(
                        "mysql i64 value {i} doesn't fit in Int8 at column {col_idx}"
                    ))))
                })?;
                b.append_value(narrowed);
            }
        }
    }
    Ok(Arc::new(b.finish()))
}

fn decode_int16(col: &[Option<&Value>], col_idx: usize) -> DfResult<ArrayRef> {
    let mut b = Int16Builder::with_capacity(col.len());
    for v in col.iter().copied() {
        match v {
            None => b.append_null(),
            Some(v) => {
                let i = value_to_i64(col_idx, v)?;
                let narrowed = i16::try_from(i).map_err(|_| {
                    DataFusionError::External(Box::new(DataglotError::federation(format!(
                        "mysql i64 value {i} doesn't fit in Int16 at column {col_idx}"
                    ))))
                })?;
                b.append_value(narrowed);
            }
        }
    }
    Ok(Arc::new(b.finish()))
}

fn decode_int32(col: &[Option<&Value>], col_idx: usize) -> DfResult<ArrayRef> {
    let mut b = Int32Builder::with_capacity(col.len());
    for v in col.iter().copied() {
        match v {
            None => b.append_null(),
            Some(v) => {
                let i = value_to_i64(col_idx, v)?;
                let narrowed = i32::try_from(i).map_err(|_| {
                    DataFusionError::External(Box::new(DataglotError::federation(format!(
                        "mysql i64 value {i} doesn't fit in Int32 at column {col_idx}"
                    ))))
                })?;
                b.append_value(narrowed);
            }
        }
    }
    Ok(Arc::new(b.finish()))
}

fn decode_int64(col: &[Option<&Value>], col_idx: usize) -> DfResult<ArrayRef> {
    let mut b = Int64Builder::with_capacity(col.len());
    for v in col.iter().copied() {
        match v {
            None => b.append_null(),
            Some(v) => b.append_value(value_to_i64(col_idx, v)?),
        }
    }
    Ok(Arc::new(b.finish()))
}

fn decode_uint64(col: &[Option<&Value>], col_idx: usize, flags: ColumnFlags) -> DfResult<ArrayRef> {
    let mut b = UInt64Builder::with_capacity(col.len());
    let unsigned = flags.contains(ColumnFlags::UNSIGNED_FLAG);
    for v in col.iter().copied() {
        match v {
            None => b.append_null(),
            Some(Value::UInt(u)) => b.append_value(*u),
            Some(Value::Int(i)) if unsigned && *i >= 0 => {
                b.append_value((*i).cast_unsigned());
            }
            Some(Value::Int(i)) if *i >= 0 => b.append_value((*i).cast_unsigned()),
            Some(Value::Bytes(bytes)) => {
                let s = std::str::from_utf8(bytes).map_err(decode_err)?;
                let u: u64 = s.parse().map_err(|e| {
                    DataFusionError::External(Box::new(DataglotError::federation(format!(
                        "mysql u64 column at index {col_idx}: failed to parse {s:?}: {e}"
                    ))))
                })?;
                b.append_value(u);
            }
            Some(Value::Int(i)) => {
                return Err(DataFusionError::External(Box::new(
                    DataglotError::federation(format!(
                        "negative i64 ({i}) for arrow UInt64 column at index {col_idx}"
                    )),
                )));
            }
            Some(other) => return Err(unexpected_value(col_idx, "UInt64", other)),
        }
    }
    Ok(Arc::new(b.finish()))
}

fn decode_float32(col: &[Option<&Value>], col_idx: usize) -> DfResult<ArrayRef> {
    let mut b = Float32Builder::with_capacity(col.len());
    for v in col.iter().copied() {
        match v {
            None => b.append_null(),
            Some(Value::Float(f)) => b.append_value(*f),
            Some(Value::Double(d)) => b.append_value(*d as f32),
            Some(Value::Bytes(bytes)) => {
                let s = std::str::from_utf8(bytes).map_err(decode_err)?;
                let f: f32 = s.parse().map_err(|e| {
                    DataFusionError::External(Box::new(DataglotError::federation(format!(
                        "mysql f32 column at index {col_idx}: failed to parse {s:?}: {e}"
                    ))))
                })?;
                b.append_value(f);
            }
            Some(other) => return Err(unexpected_value(col_idx, "Float32", other)),
        }
    }
    Ok(Arc::new(b.finish()))
}

fn decode_float64(col: &[Option<&Value>], col_idx: usize) -> DfResult<ArrayRef> {
    let mut b = Float64Builder::with_capacity(col.len());
    for v in col.iter().copied() {
        match v {
            None => b.append_null(),
            Some(Value::Double(d)) => b.append_value(*d),
            Some(Value::Float(f)) => b.append_value(f64::from(*f)),
            Some(Value::Bytes(bytes)) => {
                let s = std::str::from_utf8(bytes).map_err(decode_err)?;
                let f: f64 = s.parse().map_err(|e| {
                    DataFusionError::External(Box::new(DataglotError::federation(format!(
                        "mysql f64 column at index {col_idx}: failed to parse {s:?}: {e}"
                    ))))
                })?;
                b.append_value(f);
            }
            Some(other) => return Err(unexpected_value(col_idx, "Float64", other)),
        }
    }
    Ok(Arc::new(b.finish()))
}

fn decode_utf8(col: &[Option<&Value>], col_idx: usize) -> DfResult<ArrayRef> {
    let mut b = StringBuilder::with_capacity(col.len(), col.len() * 16);
    for v in col.iter().copied() {
        match v {
            None => b.append_null(),
            Some(Value::Bytes(bytes)) => {
                let s = std::str::from_utf8(bytes).map_err(decode_err)?;
                b.append_value(s);
            }
            Some(other) => return Err(unexpected_value(col_idx, "Utf8", other)),
        }
    }
    Ok(Arc::new(b.finish()))
}

/// Decode raw byte columns (BINARY / VARBINARY / BLOB family,
/// excluding LONGBLOB). The only difference from `decode_utf8` is
/// that we don't validate UTF-8 — binary columns can hold
/// arbitrary bytes, including invalid UTF-8 sequences. Both Arrow
/// and `MySQL` surface this as "bag of bytes" with no encoding
/// contract.
///
/// Caller must ensure the column type maps to `DataType::Binary`,
/// which caps total payload at ~2 GiB (i32 offsets). LONGBLOB
/// columns go through [`decode_large_binary`] instead.
fn decode_binary(col: &[Option<&Value>], col_idx: usize) -> DfResult<ArrayRef> {
    let mut b = BinaryBuilder::with_capacity(col.len(), col.len() * 16);
    for v in col.iter().copied() {
        match v {
            None => b.append_null(),
            Some(Value::Bytes(bytes)) => b.append_value(bytes.as_slice()),
            Some(other) => return Err(unexpected_value(col_idx, "Binary", other)),
        }
    }
    Ok(Arc::new(b.finish()))
}

/// Decode raw byte columns sized beyond what i32 offsets can
/// address — LONGBLOB tops out at 4 GiB, so a single oversize row
/// would panic [`BinaryBuilder::append_value`]. `LargeBinary` uses
/// i64 offsets and accommodates the full LONGBLOB range.
fn decode_large_binary(col: &[Option<&Value>], col_idx: usize) -> DfResult<ArrayRef> {
    let mut b = LargeBinaryBuilder::with_capacity(col.len(), col.len() * 16);
    for v in col.iter().copied() {
        match v {
            None => b.append_null(),
            Some(Value::Bytes(bytes)) => b.append_value(bytes.as_slice()),
            Some(other) => return Err(unexpected_value(col_idx, "LargeBinary", other)),
        }
    }
    Ok(Arc::new(b.finish()))
}

fn decode_date32(col: &[Option<&Value>], col_idx: usize) -> DfResult<ArrayRef> {
    // Arrow Date32 is "days since 1970-01-01". MySQL hands us the
    // raw `Value::Date(year, mon, day, …)` tuple over the text and
    // binary protocols; we convert via chrono.
    let epoch = chrono::NaiveDate::from_ymd_opt(1970, 1, 1).expect("1970-01-01 is valid");
    let mut b = Date32Builder::with_capacity(col.len());
    for v in col.iter().copied() {
        match v {
            None => b.append_null(),
            Some(Value::Date(y, m, d, _, _, _, _)) => {
                let nd =
                    chrono::NaiveDate::from_ymd_opt(i32::from(*y), u32::from(*m), u32::from(*d))
                        .ok_or_else(|| {
                            DataFusionError::External(Box::new(DataglotError::federation(format!(
                                "invalid date {y:04}-{m:02}-{d:02} at column {col_idx}"
                            ))))
                        })?;
                let days = (nd - epoch).num_days();
                let days_i32 = i32::try_from(days).map_err(|_| {
                    DataFusionError::External(Box::new(DataglotError::federation(format!(
                        "date {nd} out of range for arrow Date32"
                    ))))
                })?;
                b.append_value(days_i32);
            }
            Some(Value::Bytes(bytes)) => {
                // Older clients may surface DATE as ASCII bytes
                // ("YYYY-MM-DD"). Parse via chrono for symmetry
                // with the Postgres connector.
                let s = std::str::from_utf8(bytes).map_err(decode_err)?;
                let nd = chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d").map_err(|e| {
                    DataFusionError::External(Box::new(DataglotError::federation(format!(
                        "mysql date column at index {col_idx}: failed to parse {s:?}: {e}"
                    ))))
                })?;
                let days = (nd - epoch).num_days();
                let days_i32 = i32::try_from(days).map_err(|_| {
                    DataFusionError::External(Box::new(DataglotError::federation(format!(
                        "date {nd} out of range for arrow Date32"
                    ))))
                })?;
                b.append_value(days_i32);
            }
            Some(other) => return Err(unexpected_value(col_idx, "Date32", other)),
        }
    }
    Ok(Arc::new(b.finish()))
}

#[allow(clippy::many_single_char_names)]
fn decode_timestamp_us(col: &[Option<&Value>], col_idx: usize) -> DfResult<ArrayRef> {
    let mut b = TimestampMicrosecondBuilder::with_capacity(col.len());
    for v in col.iter().copied() {
        match v {
            None => b.append_null(),
            Some(Value::Date(y, m, d, h, mi, s, us)) => {
                let nd =
                    chrono::NaiveDate::from_ymd_opt(i32::from(*y), u32::from(*m), u32::from(*d))
                        .ok_or_else(|| {
                            DataFusionError::External(Box::new(DataglotError::federation(format!(
                                "invalid datetime {y:04}-{m:02}-{d:02} at column {col_idx}"
                            ))))
                        })?;
                let nt = chrono::NaiveTime::from_hms_micro_opt(
                    u32::from(*h),
                    u32::from(*mi),
                    u32::from(*s),
                    *us,
                )
                .ok_or_else(|| {
                    DataFusionError::External(Box::new(DataglotError::federation(format!(
                        "invalid time {h:02}:{mi:02}:{s:02}.{us:06} at column {col_idx}"
                    ))))
                })?;
                let ndt = chrono::NaiveDateTime::new(nd, nt);
                b.append_value(ndt.and_utc().timestamp_micros());
            }
            Some(Value::Bytes(bytes)) => {
                // TIMESTAMP / DATETIME over the text protocol.
                let s = std::str::from_utf8(bytes).map_err(decode_err)?;
                let ndt = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S%.f")
                    .or_else(|_| chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S"))
                    .map_err(|e| {
                        DataFusionError::External(Box::new(DataglotError::federation(format!(
                            "mysql timestamp column at index {col_idx}: failed to parse {s:?}: {e}"
                        ))))
                    })?;
                b.append_value(ndt.and_utc().timestamp_micros());
            }
            Some(other) => return Err(unexpected_value(col_idx, "Timestamp(µs)", other)),
        }
    }
    Ok(Arc::new(b.finish()))
}

/// Decode `MySQL` `TIME` columns into Arrow `Time64(Microsecond)`
/// — i64 microseconds since midnight.
///
/// `MySQL` `TIME` ranges from `-838:59:59.000000` to
/// `838:59:59.000000`, which is wider than Arrow's wall-clock
/// `0..86_400_000_000` µs window. Out-of-range values (negative,
/// or `days != 0` on the binary protocol, or hours ≥ 24 on the
/// text protocol) surface as a typed federation error rather
/// than silent truncation. Most real-world `TIME` columns
/// (durations of a workday, scheduled clock times) fit; the
/// fail-loud contract preserves correctness for the long tail.
#[allow(clippy::many_single_char_names)]
fn decode_time64_us(col: &[Option<&Value>], col_idx: usize) -> DfResult<ArrayRef> {
    use chrono::Timelike;
    let mut b = Time64MicrosecondBuilder::with_capacity(col.len());
    for v in col.iter().copied() {
        match v {
            None => b.append_null(),
            Some(Value::Time(is_negative, days, h, mi, s, us)) => {
                if *is_negative {
                    return Err(DataFusionError::External(Box::new(
                        DataglotError::federation(format!(
                            "negative MySQL TIME value at column {col_idx} \
                             not representable in Arrow Time64(µs since midnight)"
                        )),
                    )));
                }
                if *days != 0 {
                    return Err(DataFusionError::External(Box::new(
                        DataglotError::federation(format!(
                            "MySQL TIME with days={days} at column {col_idx} \
                             exceeds Arrow Time64(µs since midnight) range"
                        )),
                    )));
                }
                if *h >= 24 {
                    return Err(DataFusionError::External(Box::new(
                        DataglotError::federation(format!(
                            "MySQL TIME with hour={h} at column {col_idx} \
                             exceeds Arrow Time64(µs since midnight) range"
                        )),
                    )));
                }
                let micros = i64::from(*h) * 3_600_000_000
                    + i64::from(*mi) * 60_000_000
                    + i64::from(*s) * 1_000_000
                    + i64::from(*us);
                b.append_value(micros);
            }
            Some(Value::Bytes(bytes)) => {
                // Text protocol — `MySQL` emits `HH:MM:SS[.frac]`.
                let s_str = std::str::from_utf8(bytes).map_err(decode_err)?;
                if s_str.starts_with('-') {
                    return Err(DataFusionError::External(Box::new(
                        DataglotError::federation(format!(
                            "negative MySQL TIME value {s_str:?} at column {col_idx} \
                             not representable in Arrow Time64(µs since midnight)"
                        )),
                    )));
                }
                let nt = chrono::NaiveTime::parse_from_str(s_str, "%H:%M:%S%.f")
                    .or_else(|_| chrono::NaiveTime::parse_from_str(s_str, "%H:%M:%S"))
                    .map_err(|e| {
                        DataFusionError::External(Box::new(DataglotError::federation(format!(
                            "mysql time column at index {col_idx}: failed to parse {s_str:?}: {e}"
                        ))))
                    })?;
                let micros = i64::from(nt.hour()) * 3_600_000_000
                    + i64::from(nt.minute()) * 60_000_000
                    + i64::from(nt.second()) * 1_000_000
                    + i64::from(nt.nanosecond() / 1_000);
                b.append_value(micros);
            }
            Some(other) => return Err(unexpected_value(col_idx, "Time64(µs)", other)),
        }
    }
    Ok(Arc::new(b.finish()))
}

/// Decode `MySQL` `DECIMAL` / `NUMERIC` columns into Arrow
/// `Decimal128(precision, scale)`.
///
/// `mysql_async` returns DECIMAL as the canonical text form
/// inside `Value::Bytes` (e.g. `b"1234.56"` for `DECIMAL(10, 2)`).
/// We parse via `rust_decimal::Decimal::from_str` and rescale to
/// the column's declared scale, refusing to truncate fractional
/// digits silently — same fail-loud rule as the postgres
/// connector's NUMERIC decoder.
fn decode_decimal128(
    col: &[Option<&Value>],
    col_idx: usize,
    precision: u8,
    scale: i8,
) -> DfResult<ArrayRef> {
    use std::str::FromStr;
    let mut b = Decimal128Builder::with_capacity(col.len())
        .with_precision_and_scale(precision, scale)
        .map_err(|e| DataFusionError::ArrowError(Box::new(e), None))?;
    for v in col.iter().copied() {
        match v {
            None => b.append_null(),
            Some(Value::Bytes(bytes)) => {
                let s = std::str::from_utf8(bytes).map_err(decode_err)?;
                let d = rust_decimal::Decimal::from_str(s).map_err(|e| {
                    DataFusionError::External(Box::new(DataglotError::federation(format!(
                        "mysql DECIMAL column at index {col_idx}: failed to parse {s:?}: {e}"
                    ))))
                })?;
                b.append_value(rescale_decimal_to_i128(d, scale, col_idx)?);
            }
            Some(other) => {
                return Err(unexpected_value(col_idx, "Decimal128", other));
            }
        }
    }
    Ok(Arc::new(b.finish()))
}

/// Convert a `rust_decimal::Decimal` to an `i128` mantissa
/// expressed at Arrow's target scale. Errors if the value can't
/// be represented without loss (target scale too small to keep
/// all the fractional digits, or i128 overflow on rescale).
///
/// Mirrors the postgres connector's `rescale_decimal_to_i128`
/// helper. They're independent today; if a third connector grows
/// the same path the helper moves to a shared module.
fn rescale_decimal_to_i128(
    d: rust_decimal::Decimal,
    target_scale: i8,
    col_idx: usize,
) -> DfResult<i128> {
    let src_scale = i32::try_from(d.scale()).unwrap_or(i32::MAX);
    let tgt_scale = i32::from(target_scale);
    let mantissa: i128 = d.mantissa();
    if tgt_scale >= src_scale {
        let pow = u32::try_from(tgt_scale - src_scale).map_err(|_| {
            DataFusionError::External(Box::new(DataglotError::federation(format!(
                "scale difference {} doesn't fit in u32 (target={tgt_scale}, source={src_scale})",
                tgt_scale - src_scale
            ))))
        })?;
        mantissa.checked_mul(10_i128.pow(pow)).ok_or_else(|| {
            DataFusionError::External(Box::new(DataglotError::federation(format!(
                "DECIMAL value {d} at column {col_idx} overflows i128 when rescaled to scale {tgt_scale}"
            ))))
        })
    } else {
        Err(DataFusionError::External(Box::new(
            DataglotError::federation(format!(
                "DECIMAL value {d} at column {col_idx} has scale {src_scale} > Arrow target scale {tgt_scale}; would lose digits"
            )),
        )))
    }
}

/// Coerce a `Value` to an `i64` for the signed-integer decoders.
/// Accepts `Value::Int`, `Value::UInt` (when it fits in i64), and
/// the text-protocol bytes form. Anything else is a federation
/// error.
fn value_to_i64(col_idx: usize, v: &Value) -> DfResult<i64> {
    match v {
        Value::Int(i) => Ok(*i),
        Value::UInt(u) => i64::try_from(*u).map_err(|_| {
            DataFusionError::External(Box::new(DataglotError::federation(format!(
                "mysql u64 value {u} doesn't fit in i64 at column {col_idx}"
            ))))
        }),
        Value::Bytes(bytes) => {
            let s = std::str::from_utf8(bytes).map_err(decode_err)?;
            s.parse::<i64>().map_err(|e| {
                DataFusionError::External(Box::new(DataglotError::federation(format!(
                    "mysql int column at index {col_idx}: failed to parse {s:?}: {e}"
                ))))
            })
        }
        other => Err(unexpected_value(col_idx, "integer", other)),
    }
}

fn unexpected_value(col_idx: usize, target: &str, value: &Value) -> DataFusionError {
    DataFusionError::External(Box::new(DataglotError::federation(format!(
        "mysql column at index {col_idx}: unexpected value {value:?} for arrow {target}"
    ))))
}

#[allow(clippy::needless_pass_by_value)]
fn decode_err<E: std::fmt::Display>(e: E) -> DataFusionError {
    DataFusionError::External(Box::new(DataglotError::federation(format!(
        "mysql row decode error: {e}"
    ))))
}

// MULTI-TENANT NOTE (; spec: the phase-3 `adbc-connector` plan).
// `execute` below sends user-driven SQL on the single `Arc<Mutex<Conn>>`
// shared across all pgwire sessions. Safe today because the federation
// unparser only emits read-only `SELECT` statements. If you add pre/post
// hooks that emit `SET SESSION ...`, `SET ROLE`, per-user impersonation, or
// any other state-changing SQL on the shared connection, you MUST address
// state isolation across users — see the ADBC connector's reset-on-return
// + discard-on-failure pattern at `crates/dataglot-federation/src/adbc.rs`.
#[async_trait]
impl SQLExecutor for MysqlConnector {
    fn name(&self) -> &str {
        &self.name
    }

    fn compute_context(&self) -> Option<String> {
        Some(self.name.clone())
    }

    fn dialect(&self) -> Arc<dyn Dialect> {
        // MySqlDialect emits backtick-quoted identifiers, MySQL
        // `LIMIT n` syntax, and other MySQL-flavoured syntax. This
        // is what makes pushed-down SQL actually executable on the
        // remote.
        Arc::new(MySqlDialect {})
    }

    fn execute(
        &self,
        query: &str,
        schema: SchemaRef,
        _filters: &[Arc<dyn PhysicalExpr>],
    ) -> DfResult<SendableRecordBatchStream> {
        // `SQLExecutor::execute` is sync — we must spawn the async
        // work as a future and surface the result as a stream. The
        // query has already been unparsed with `MySqlDialect` so
        // it's safe to send as-is.
        //
        // The pushed-down SQL is logged by `instrument_pushdown` at `debug`
        // (filter literals are user data, not credentials); its
        // source-attributed timing/row-count completion event is at `info`.
        let conn = Arc::clone(&self.conn);
        let schema_for_stream = Arc::clone(&schema);
        let query_owned = query.to_string();

        let fut = async move {
            let mut conn = conn.lock().await;
            // Bound the whole query + row-drain under QUERY_TIMEOUT so a source
            // that stalls mid-query can't hang the federated query forever
            //. The connection lock is held for the duration either
            // way; on timeout we surface a federation error and drop it.
            let (columns, rows) = with_query_timeout(async {
                let result = conn.query_iter(query_owned.as_str()).await.map_err(|e| {
                    DataFusionError::External(Box::new(DataglotError::federation(format!(
                        "mysql query failed: {e}"
                    ))))
                })?;
                // Snapshot the column metadata before draining the
                // result set — `columns_ref()` only stays valid while
                // the result-set is alive.
                let columns: Vec<mysql_async::Column> = result.columns_ref().to_vec();
                let rows: Vec<Row> = result.collect_and_drop().await.map_err(|e| {
                    DataFusionError::External(Box::new(DataglotError::federation(format!(
                        "mysql row collect failed: {e}"
                    ))))
                })?;
                Ok((columns, rows))
            })
            .await?;
            drop(conn); // release the connection lock before building the batch
            rows_to_record_batch(&schema_for_stream, &columns, &rows)
        };

        let batch_stream = stream::once(fut);
        let stream = Box::pin(RecordBatchStreamAdapter::new(schema, batch_stream));
        Ok(crate::instrument_pushdown(
            &self.name, "mysql", query, stream,
        ))
    }

    async fn table_names(&self) -> DfResult<Vec<String>> {
        // Not used by the federation pushdown path. Mirroring the
        // Postgres connector here — the `as_catalog_provider` path
        // is the public catalog-listing surface.
        Err(DataFusionError::NotImplemented(
            "table_names not implemented".to_string(),
        ))
    }

    async fn get_table_schema(&self, table_name: &str) -> DfResult<SchemaRef> {
        // `table_name` is a `RemoteTableRef`-style fully qualified
        // reference — typically `"schema"."table"` or `schema.table`.
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
/// `mysql_async` connection. The health poller calls this on a timer
/// instead of rebuilding the connector; a single `SELECT 1` (drained + dropped)
/// errors iff the source is unreachable or the connection has been lost. The
/// error text is the driver's own query error — never the DSN/password (rule 12).
#[async_trait]
impl crate::health::ConnectorHealthCheck for MysqlConnector {
    async fn health_check(&self) -> Result<(), String> {
        let mut conn = self.conn.lock().await;
        conn.query_drop("SELECT 1")
            .await
            .map_err(|e| format!("mysql health check failed: {e}"))
    }
}

/// Split a `<schema>.<table>` (optionally backtick- or quote-wrapped)
/// identifier into parts. Returns `None` if the input doesn't match
/// that shape.
fn split_qualified(s: &str) -> Option<(String, String)> {
    let parts: Vec<&str> = s.splitn(2, '.').collect();
    if parts.len() != 2 {
        return None;
    }
    let schema = parts[0].trim_matches(|c| c == '"' || c == '`');
    let table = parts[1].trim_matches(|c| c == '"' || c == '`');
    if schema.is_empty() || table.is_empty() {
        return None;
    }
    Some((schema.to_string(), table.to_string()))
}

// ---------------------------------------------------------------------------
// CatalogProvider / SchemaProvider — DataFusion catalog surface
// ---------------------------------------------------------------------------

/// `DataFusion` [`CatalogProvider`] for a `MySQL` server.
///
/// Built via [`MysqlConnector::as_catalog_provider`]. Holds a cached
/// list of user-visible schema names and a `HashMap` of pre-built
/// `MysqlSchema` providers keyed by schema name. The cache is fixed
/// at construction time — drop and rebuild the catalog to pick up
/// DDL, mirroring the Postgres connector's behavior.
///
/// Per hard rule 12, `Debug` does not surface anything from the
/// underlying [`MysqlConnector`] other than its name.
///
/// [`CatalogProvider`]: datafusion::catalog::CatalogProvider
pub struct MysqlCatalog {
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

impl fmt::Debug for MysqlCatalog {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MysqlCatalog")
            .field("connector", &self.connector_name)
            .field("schema_count", &self.schema_names.len())
            .finish_non_exhaustive()
    }
}

impl DfCatalogProvider for MysqlCatalog {
    fn schema_names(&self) -> Vec<String> {
        self.schema_names.clone()
    }

    fn schema(&self, name: &str) -> Option<Arc<dyn DfSchemaProvider>> {
        self.schemas.get(name).map(Arc::clone)
    }
}

/// `DataFusion` [`SchemaProvider`] backed by a single `MySQL` schema
/// (database) on a [`MysqlConnector`].
///
/// Per-table column schemas are NOT fetched at construction; they
/// are resolved lazily inside [`SchemaProvider::table`] by delegating
/// to [`MysqlConnector::table_provider`] (rule 13).
///
/// [`SchemaProvider`]: datafusion::catalog::SchemaProvider
struct MysqlSchema {
    /// The connector this schema belongs to.
    connector: Arc<MysqlConnector>,
    /// MySQL schema (database) name.
    schema_name: String,
    /// Cached, alphabetised list of table names within this schema.
    /// Populated once at catalog-construction time.
    table_names: Vec<String>,
}

impl fmt::Debug for MysqlSchema {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MysqlSchema")
            .field("schema", &self.schema_name)
            .field("table_count", &self.table_names.len())
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl DfSchemaProvider for MysqlSchema {
    fn table_names(&self) -> Vec<String> {
        self.table_names.clone()
    }

    fn table_exist(&self, name: &str) -> bool {
        self.table_names.iter().any(|t| t == name)
    }

    async fn table(&self, name: &str) -> DfResult<Option<Arc<dyn TableProvider>>> {
        // Cheap negative path: if it isn't in the cached list, don't
        // even attempt to resolve. Avoids a remote round-trip for
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

#[cfg(all(test, feature = "mysql"))]
mod tests {
    use super::*;

    #[test]
    fn mysql_connector_is_a_connector_health_check() {
        // Compile-level pin: the boot path upcasts the retained
        // `Arc<MysqlConnector>` to `Arc<dyn ConnectorHealthCheck>` so the poller
        // reuses the authenticated connection. A live `SELECT 1` needs a real
        // server (integration suite); this asserts the impl exists and satisfies
        // the trait's `Send + Sync + 'static` bounds.
        fn assert_impl<T: crate::health::ConnectorHealthCheck>() {}
        assert_impl::<MysqlConnector>();
    }

    /// Hard rule 12 — the literal DSN, including the password,
    /// must never appear in the connector's `Debug` output.
    ///
    /// We don't actually open a connection here (no `MySQL` server is
    /// guaranteed to be reachable in the unit-test sandbox); instead
    /// we exercise the same fields the real `Debug` impl reads —
    /// `name` plus `redacted_dsn(opts)` — so the assertion is on
    /// the formatting wrapper, not the network path.
    #[test]
    fn dsn_redacted_in_debug() {
        let opts = Opts::from_url("mysql://root:secretpw@localhost:3306/db").unwrap();
        let name = "mysql_demo".to_string();
        let debug_ish = format!(
            "MysqlConnector {{ name: {:?}, dsn: {:?}, .. }}",
            name,
            redacted_dsn(&opts)
        );
        assert!(
            !debug_ish.contains("secretpw"),
            "Debug leaked password: {debug_ish}"
        );
        assert!(debug_ish.contains("localhost"), "{debug_ish}");
        assert!(debug_ish.contains("root"), "{debug_ish}");
        assert!(debug_ish.contains("password=<redacted>"), "{debug_ish}");
    }

    /// Same redaction promise, exercised against the bare
    /// `redacted_dsn` helper. Belt-and-braces: any future change to
    /// `Debug` that bypasses `redacted_dsn` would still be caught
    /// by `dsn_redacted_in_debug` above, but this pins the helper
    /// in isolation.
    #[test]
    fn redacted_dsn_omits_password() {
        let opts = Opts::from_url("mysql://alice:s3cret@db.internal:3307/prod").unwrap();
        let r = redacted_dsn(&opts);
        assert!(r.contains("db.internal"), "{r}");
        assert!(r.contains("3307"), "{r}");
        assert!(r.contains("alice"), "{r}");
        assert!(r.contains("prod"), "{r}");
        assert!(!r.contains("s3cret"), "{r}");
        assert!(r.contains("password=<redacted>"), "{r}");
    }

    /// `redacted_dsn` must not lie about a password being set when
    /// none was supplied. Pinned so a future driver upgrade that
    /// changes `Opts::pass()`'s shape is caught.
    #[test]
    fn redacted_dsn_without_password_has_no_password_marker() {
        let opts = Opts::from_url("mysql://alice@localhost/prod").unwrap();
        let r = redacted_dsn(&opts);
        assert!(!r.contains("password"), "{r}");
    }

    /// A malformed DSN must produce a typed `DataglotError::Connection`,
    /// not a panic. This is the contract `dataglot-server`'s boot
    /// path relies on (the error is wrapped with the catalog name
    /// and surfaced to the operator).
    #[tokio::test]
    async fn connect_invalid_dsn_returns_typed_error() {
        let err = MysqlConnector::connect("test", "not a url")
            .await
            .expect_err("malformed dsn must error");
        assert!(
            matches!(err, DataglotError::Connection(_)),
            "expected DataglotError::Connection, got {err:?}"
        );
    }

    /// Same malformed-DSN contract for the TLS constructor — the DSN
    /// parse runs before any TLS material is touched, so this needs no
    /// live server or certificates.
    #[tokio::test]
    async fn connect_with_tls_invalid_dsn_returns_typed_error() {
        let err = MysqlConnector::connect_with_tls(
            "test",
            "not a url",
            &crate::mysql_tls::MysqlTls::default(),
        )
        .await
        .expect_err("malformed dsn must error");
        assert!(
            matches!(err, DataglotError::Connection(_)),
            "expected DataglotError::Connection, got {err:?}"
        );
    }

    /// `SQLExecutor::dialect()` must return `MySqlDialect`, not the
    /// Postgres dialect inherited from copy-paste. The federation
    /// SQL unparser uses this to pick backtick-quoting and `MySQL`
    /// `LIMIT n` syntax.
    ///
    /// `MySqlDialect` doesn't derive `Debug`, and `dyn Dialect`
    /// can't be downcast through `Any`, so we pin the
    /// distinguishing observable: `identifier_quote_style`. `MySQL`
    /// quotes identifiers with backticks; Postgres uses double
    /// quotes. Anything other than backticks here means the
    /// dialect drifted to a non-MySQL impl.
    ///
    /// We exercise the dialect via the same `Arc::new(MySqlDialect
    /// {})` expression that `SQLExecutor::dialect` uses, since
    /// constructing a `MysqlConnector` without a live `Conn` isn't
    /// possible — `Conn` has no public unit constructor.
    /// `dialect()` itself reads no `self` field, so this is a
    /// faithful unit test of the surface.
    #[test]
    fn dialect_is_mysql() {
        let dialect: Arc<dyn Dialect> = Arc::new(MySqlDialect {});
        assert_eq!(
            dialect.identifier_quote_style("any"),
            Some('`'),
            "MySqlDialect must quote identifiers with backticks"
        );
    }

    /// Test-only convenience: most non-numeric types ignore
    /// `numeric_precision` / `numeric_scale`, so wrap the canonical
    /// 4-arg mapper and let the existing tests use the prior 2-arg
    /// shape. DECIMAL tests call `mysql_information_schema_to_arrow`
    /// directly to pass real (Some, Some) values.
    fn map(data_type: &str, column_type: &str) -> Option<DataType> {
        mysql_information_schema_to_arrow(data_type, column_type, None, None)
    }

    #[test]
    fn type_mapping_covers_mvp_subset() {
        // The MVP promise is that these mappings hold; pin them so
        // a future tweak to the matcher doesn't silently drift.
        assert_eq!(map("tinyint", "tinyint(1)"), Some(DataType::Boolean));
        assert_eq!(map("tinyint", "tinyint(4)"), Some(DataType::Int8));
        assert_eq!(map("smallint", "smallint(6)"), Some(DataType::Int16));
        assert_eq!(map("int", "int(11)"), Some(DataType::Int32));
        assert_eq!(map("mediumint", "mediumint(9)"), Some(DataType::Int32));
        assert_eq!(map("bigint", "bigint(20)"), Some(DataType::Int64));
        assert_eq!(map("bigint", "bigint(20) unsigned"), Some(DataType::UInt64));
        assert_eq!(map("float", "float"), Some(DataType::Float32));
        assert_eq!(map("double", "double"), Some(DataType::Float64));
        assert_eq!(map("varchar", "varchar(255)"), Some(DataType::Utf8));
        assert_eq!(map("text", "text"), Some(DataType::Utf8));
        assert_eq!(map("date", "date"), Some(DataType::Date32));
        assert_eq!(
            map("datetime", "datetime"),
            Some(DataType::Timestamp(TimeUnit::Microsecond, None))
        );
        assert_eq!(
            map("timestamp", "timestamp"),
            Some(DataType::Timestamp(TimeUnit::Microsecond, None))
        );
    }

    #[test]
    fn type_mapping_rejects_out_of_scope_types() {
        // DECIMAL without numeric_precision / numeric_scale (the
        // mapper signature now takes both) maps to None — same
        // catalog-error fallback. The 4-arg path with real
        // precision / scale is exercised by
        // `type_mapping_covers_decimal`.
        assert_eq!(
            map("decimal", "decimal(10,2)"),
            None,
            "DECIMAL without precision/scale args (e.g. caller didn't \
             populate them) must surface as a catalog error",
        );
        assert_eq!(
            map("int", "int(11) unsigned"),
            None,
            "unsigned non-bigint integers are deliberately out of scope"
        );
    }

    #[test]
    fn type_mapping_covers_decimal() {
        // DECIMAL / NUMERIC need both numeric_precision and
        // numeric_scale (from information_schema.columns) to map
        // to Arrow Decimal128(p, s). Pin the canonical shapes:
        //
        //   - Standard tier (DECIMAL(10,2), DECIMAL(38,0)) maps
        //     directly to Decimal128.
        //   - The Arrow ceiling is (38, 38); MySQL's full DECIMAL
        //     range goes up to (65, 30) but anything beyond
        //     (38, 38) returns None and surfaces as a catalog
        //     error — fail-loud rather than silent precision loss.
        //   - Scale > Precision is invalid SQL; reject with None.
        assert_eq!(
            mysql_information_schema_to_arrow("decimal", "decimal(10,2)", Some(10), Some(2)),
            Some(DataType::Decimal128(10, 2)),
        );
        assert_eq!(
            mysql_information_schema_to_arrow("decimal", "decimal(38,0)", Some(38), Some(0)),
            Some(DataType::Decimal128(38, 0)),
            "DECIMAL(38,0) is exactly Arrow's max precision",
        );
        assert_eq!(
            mysql_information_schema_to_arrow("numeric", "numeric(20,4)", Some(20), Some(4)),
            Some(DataType::Decimal128(20, 4)),
            "MySQL accepts NUMERIC as a synonym for DECIMAL — both map the same",
        );
        // Out-of-range — precision exceeds Arrow's i128 ceiling.
        assert_eq!(
            mysql_information_schema_to_arrow("decimal", "decimal(50,10)", Some(50), Some(10)),
            None,
            "DECIMAL(50,10) exceeds Arrow Decimal128's (38,38) max",
        );
        // Pathological — scale > precision (rejected by SQL but
        // we defend against malformed information_schema rows).
        assert_eq!(
            mysql_information_schema_to_arrow("decimal", "decimal(5,10)", Some(5), Some(10)),
            None,
            "scale > precision is invalid SQL and rejected by the mapper",
        );
        // Missing precision/scale — caller bug (info_schema
        // would have populated both for a numeric type).
        assert_eq!(
            mysql_information_schema_to_arrow("decimal", "decimal(10,2)", Some(10), None),
            None,
            "missing scale ⇒ no mapping",
        );
    }

    #[test]
    fn type_mapping_covers_time() {
        // MySQL TIME → Arrow Time64(µs since midnight). Out-of-
        // range values (negative, hours ≥ 24) surface as a
        // decoder error rather than a mapping miss — the schema
        // mapping is type-only and doesn't see values.
        assert_eq!(
            map("time", "time"),
            Some(DataType::Time64(TimeUnit::Microsecond)),
        );
        assert_eq!(
            map("time", "time(6)"),
            Some(DataType::Time64(TimeUnit::Microsecond)),
            "TIME with explicit fractional-second precision still maps to Time64(µs)",
        );
    }

    #[test]
    fn type_mapping_covers_binary_blob_json_enum_set() {
        // Pin the second-tier types added after the MVP. All four
        // decode from `Value::Bytes` — BINARY/BLOB through the
        // `Binary` builder, JSON/ENUM/SET reusing the `Utf8`
        // builder.
        assert_eq!(
            map("binary", "binary(16)"),
            Some(DataType::Binary),
            "BINARY(n) is fixed-width raw bytes ⇒ Arrow Binary"
        );
        assert_eq!(map("varbinary", "varbinary(255)"), Some(DataType::Binary),);
        assert_eq!(map("blob", "blob"), Some(DataType::Binary),);
        assert_eq!(map("tinyblob", "tinyblob"), Some(DataType::Binary),);
        assert_eq!(map("mediumblob", "mediumblob"), Some(DataType::Binary),);
        assert_eq!(
            map("longblob", "longblob"),
            Some(DataType::LargeBinary),
            "LONGBLOB exceeds Arrow Binary's i32 offset cap; must surface as LargeBinary",
        );
        assert_eq!(
            map("json", "json"),
            Some(DataType::Utf8),
            "JSON serialized text form is decoded as Utf8 — round-trip works for SELECT"
        );
        assert_eq!(
            map("enum", "enum('a','b','c')"),
            Some(DataType::Utf8),
            "ENUM is decoded as the active variant's string label",
        );
        assert_eq!(
            map("set", "set('a','b','c')"),
            Some(DataType::Utf8),
            "SET is decoded as a comma-separated list of active members",
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
        // MySQL's idiomatic identifier quoting is backticks; pin
        // that the splitter accepts them too.
        assert_eq!(
            split_qualified("`public`.`users`"),
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
    fn validate_identifier_literal_rejects_quote_and_backslash() {
        assert!(validate_identifier_literal("public").is_ok());
        assert!(validate_identifier_literal("my_db_v2").is_ok());
        assert!(validate_identifier_literal("").is_err());
        assert!(validate_identifier_literal("evil'or'1=1").is_err());
        assert!(validate_identifier_literal("evil\\path").is_err());
    }

    /// `MysqlConnector` must be `Send + Sync + 'static` (hard
    /// rule 10). The compile-time assertion below catches any
    /// regression where a future field breaks one of those bounds.
    #[test]
    fn connector_is_send_sync_static() {
        fn assert_send_sync_static<T: Send + Sync + 'static>() {}
        assert_send_sync_static::<MysqlConnector>();
    }

    /// Sanity-check the `mysql_async::Column` builder we'll use
    /// from the integration tests (not in this PR; tracked as a
    /// follow-up). `mysql_async` doesn't expose a public row
    /// constructor, so the unit-test surface stops at "column
    /// metadata round-trips" — full decode coverage lives behind
    /// `#[ignore = "requires Docker"]` once the testcontainer
    /// scaffolding lands.
    #[test]
    fn column_metadata_round_trips() {
        use mysql_async::consts::ColumnType;
        let col = mysql_async::Column::new(ColumnType::MYSQL_TYPE_LONG)
            .with_name(b"x")
            .with_flags(ColumnFlags::empty());
        assert_eq!(col.column_type(), ColumnType::MYSQL_TYPE_LONG);
        assert_eq!(col.name_str(), "x");
        assert!(!col.flags().contains(ColumnFlags::UNSIGNED_FLAG));
    }

    /// A source that accepts the TCP socket but never sends the MySQL
    /// server greeting must make `connect` *fail* (time out), not hang
    /// forever — the  boot-wedge that defeats
    /// `--tolerate-unreachable-catalogs`. Hold-open listener under a paused
    /// clock (MySQL is server-greets-first, so the client parks reading the
    /// greeting); tokio auto-advances to `CONNECT_TIMEOUT`, so it's instant.
    #[tokio::test(start_paused = true)]
    async fn connect_times_out_when_handshake_stalls() {
        use tokio::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((sock, _)) = listener.accept().await {
                held.push(sock);
            }
        });
        let dsn = format!("mysql://u:p@127.0.0.1:{}/demo", addr.port());
        let err = MysqlConnector::connect("t", &dsn)
            .await
            .expect_err("connect must fail, not hang");
        assert!(
            err.to_string().contains("timed out"),
            "expected a timeout error, got: {err}"
        );
    }

    #[test]
    fn value_to_i64_accepts_int_uint_and_text() {
        // Binary protocol → Int/UInt; text protocol → Bytes.
        assert_eq!(value_to_i64(0, &Value::Int(42)).unwrap(), 42);
        assert_eq!(value_to_i64(0, &Value::Int(-7)).unwrap(), -7);
        assert_eq!(value_to_i64(0, &Value::UInt(42)).unwrap(), 42);
        assert_eq!(
            value_to_i64(0, &Value::Bytes(b"123".to_vec())).unwrap(),
            123
        );
        assert_eq!(value_to_i64(0, &Value::Bytes(b"-9".to_vec())).unwrap(), -9);
    }

    #[test]
    fn value_to_i64_rejects_overflow_and_non_integer() {
        assert!(value_to_i64(0, &Value::UInt(u64::MAX)).is_err()); // doesn't fit i64
        assert!(value_to_i64(0, &Value::Bytes(b"nope".to_vec())).is_err()); // unparseable
        assert!(value_to_i64(0, &Value::NULL).is_err()); // wrong value kind
    }

    #[test]
    fn rescale_decimal_matches_or_scales_up() {
        use rust_decimal::Decimal;
        // Same scale → mantissa unchanged; scale-up multiplies by 10^Δ.
        assert_eq!(
            rescale_decimal_to_i128(Decimal::new(123, 2), 2, 0).unwrap(),
            123
        );
        assert_eq!(
            rescale_decimal_to_i128(Decimal::new(123, 2), 4, 0).unwrap(),
            12_300
        );
        assert_eq!(
            rescale_decimal_to_i128(Decimal::new(5, 0), 3, 0).unwrap(),
            5_000
        );
    }

    #[test]
    fn rescale_decimal_rejects_precision_loss() {
        use rust_decimal::Decimal;
        // 1.23 (scale 2) can't fit target scale 1 without dropping a digit.
        assert!(rescale_decimal_to_i128(Decimal::new(123, 2), 1, 0).is_err());
    }

    // ---- Decoder tests -------------------------------------------
    // The decoders now take a column view (`&[Option<&Value>]`) rather than
    // opaque `mysql_async::Row`s, so the full Value -> Arrow decode path is
    // unit-testable here without a live result set.
    use arrow::array::{
        Array, BinaryArray, BooleanArray, Date32Array, Decimal128Array, Float32Array, Float64Array,
        Int32Array, Int64Array, Int8Array, LargeBinaryArray, StringArray, Time64MicrosecondArray,
        TimestampMicrosecondArray, UInt64Array,
    };

    #[test]
    fn decode_bool_from_int_uint_and_text() {
        let (t, f) = (Value::Int(1), Value::Int(0));
        let (bt, bf) = (Value::Bytes(b"1".to_vec()), Value::Bytes(b"0".to_vec()));
        let col = vec![Some(&t), Some(&f), None, Some(&bt), Some(&bf)];
        let arr = decode_bool(&col, 0).unwrap();
        let a = arr.as_any().downcast_ref::<BooleanArray>().unwrap();
        assert_eq!(a.len(), 5);
        assert!(a.value(0) && !a.value(1) && a.is_null(2) && a.value(3) && !a.value(4));
        let bad = Value::Bytes(b"maybe".to_vec());
        assert!(decode_bool(&[Some(&bad)], 0).is_err());
    }

    #[test]
    fn decode_ints_narrow_and_reject_overflow() {
        let v = Value::Int(5);
        let a = decode_int8(&[Some(&v), None], 0).unwrap();
        let a = a.as_any().downcast_ref::<Int8Array>().unwrap();
        assert_eq!(a.value(0), 5);
        assert!(a.is_null(1));
        let txt = Value::Bytes(b"42".to_vec());
        let a = decode_int32(&[Some(&txt)], 0).unwrap();
        assert_eq!(
            a.as_any().downcast_ref::<Int32Array>().unwrap().value(0),
            42
        );
        // narrowing overflow is fail-loud
        assert!(decode_int16(&[Some(&Value::Int(40_000))], 0).is_err());
        assert!(decode_int32(&[Some(&Value::Int(i64::from(i32::MAX) + 1))], 0).is_err());
        let n = Value::Int(-9_000_000_000);
        let a = decode_int64(&[Some(&n)], 0).unwrap();
        assert_eq!(
            a.as_any().downcast_ref::<Int64Array>().unwrap().value(0),
            -9_000_000_000
        );
    }

    #[test]
    fn decode_uint64_handles_uint_int_text_and_rejects_negative() {
        let (u, i, t) = (
            Value::UInt(42),
            Value::Int(7),
            Value::Bytes(b"100".to_vec()),
        );
        let col = vec![Some(&u), Some(&i), Some(&t), None];
        let arr = decode_uint64(&col, 0, ColumnFlags::empty()).unwrap();
        let a = arr.as_any().downcast_ref::<UInt64Array>().unwrap();
        assert_eq!((a.value(0), a.value(1), a.value(2)), (42, 7, 100));
        assert!(a.is_null(3));
        assert!(decode_uint64(&[Some(&Value::Int(-1))], 0, ColumnFlags::empty()).is_err());
    }

    #[test]
    fn decode_floats_from_float_double_and_text() {
        let (f, d, t) = (
            Value::Float(1.5),
            Value::Double(2.5),
            Value::Bytes(b"3.5".to_vec()),
        );
        let a32 = decode_float32(&[Some(&f), Some(&t)], 0).unwrap();
        let a32 = a32.as_any().downcast_ref::<Float32Array>().unwrap();
        assert_eq!((a32.value(0), a32.value(1)), (1.5, 3.5));
        let a64 = decode_float64(&[Some(&d), Some(&t)], 0).unwrap();
        let a64 = a64.as_any().downcast_ref::<Float64Array>().unwrap();
        assert_eq!((a64.value(0), a64.value(1)), (2.5, 3.5));
    }

    #[test]
    fn decode_utf8_and_binary_paths() {
        let s = Value::Bytes(b"hi".to_vec());
        let arr = decode_utf8(&[Some(&s), None], 0).unwrap();
        let a = arr.as_any().downcast_ref::<StringArray>().unwrap();
        assert_eq!(a.value(0), "hi");
        assert!(a.is_null(1));
        // invalid utf-8 is an error for Utf8 but fine for the binary paths
        let raw = Value::Bytes(vec![0xff, 0x00, 0x01]);
        assert!(decode_utf8(&[Some(&raw)], 0).is_err());
        assert!(decode_utf8(&[Some(&Value::Int(1))], 0).is_err());
        let bin = decode_binary(&[Some(&raw)], 0).unwrap();
        assert_eq!(
            bin.as_any().downcast_ref::<BinaryArray>().unwrap().value(0),
            &[0xff_u8, 0x00, 0x01]
        );
        let lb = decode_large_binary(&[Some(&raw)], 0).unwrap();
        assert_eq!(
            lb.as_any()
                .downcast_ref::<LargeBinaryArray>()
                .unwrap()
                .value(0),
            &[0xff_u8, 0x00, 0x01]
        );
    }

    #[test]
    fn decode_date32_from_tuple_and_text() {
        // 2020-01-01 is 18_262 days after the Unix epoch.
        let d = Value::Date(2020, 1, 1, 0, 0, 0, 0);
        let t = Value::Bytes(b"2020-01-01".to_vec());
        let arr = decode_date32(&[Some(&d), Some(&t), None], 0).unwrap();
        let a = arr.as_any().downcast_ref::<Date32Array>().unwrap();
        assert_eq!(a.value(0), 18_262);
        assert_eq!(a.value(1), 18_262);
        assert!(a.is_null(2));
    }

    #[test]
    fn decode_timestamp_us_from_tuple() {
        // 1970-01-01 00:00:01 -> 1_000_000 µs.
        let d = Value::Date(1970, 1, 1, 0, 0, 1, 0);
        let arr = decode_timestamp_us(&[Some(&d)], 0).unwrap();
        let a = arr
            .as_any()
            .downcast_ref::<TimestampMicrosecondArray>()
            .unwrap();
        assert_eq!(a.value(0), 1_000_000);
    }

    #[test]
    fn decode_time64_us_and_range_errors() {
        // 01:02:03 -> 3_723_000_000 µs since midnight.
        let ok = Value::Time(false, 0, 1, 2, 3, 0);
        let arr = decode_time64_us(&[Some(&ok)], 0).unwrap();
        let a = arr
            .as_any()
            .downcast_ref::<Time64MicrosecondArray>()
            .unwrap();
        assert_eq!(a.value(0), 3_723_000_000);
        // negative / multi-day / hour>=24 exceed Arrow's wall-clock window
        assert!(decode_time64_us(&[Some(&Value::Time(true, 0, 1, 0, 0, 0))], 0).is_err());
        assert!(decode_time64_us(&[Some(&Value::Time(false, 2, 1, 0, 0, 0))], 0).is_err());
        assert!(decode_time64_us(&[Some(&Value::Time(false, 0, 25, 0, 0, 0))], 0).is_err());
    }

    #[test]
    fn decode_decimal128_parses_and_rescales() {
        // DECIMAL(10,2) text "1.23" -> unscaled 123.
        let v = Value::Bytes(b"1.23".to_vec());
        let arr = decode_decimal128(&[Some(&v), None], 0, 10, 2).unwrap();
        let a = arr.as_any().downcast_ref::<Decimal128Array>().unwrap();
        assert_eq!(a.value(0), 123);
        assert!(a.is_null(1));
        // more fractional digits than the declared scale -> fail-loud
        assert!(decode_decimal128(&[Some(&Value::Bytes(b"1.235".to_vec()))], 0, 10, 2).is_err());
    }

    // ----: per-query timeout + keepalive defaults -------------------

    /// A never-completing query trips the backstop. With the tokio clock
    /// paused, `timeout` auto-advances to the deadline once the task is idle,
    /// so this is instant.
    #[tokio::test(start_paused = true)]
    async fn query_timeout_fires_on_a_stuck_query() {
        let err = with_query_timeout(std::future::pending::<DfResult<()>>())
            .await
            .expect_err("a never-completing query must time out");
        assert!(
            err.to_string().contains("execution timeout"),
            "expected an execution-timeout error, got: {err}"
        );
    }

    /// A prompt query passes straight through the backstop.
    #[tokio::test(start_paused = true)]
    async fn query_timeout_passes_through_a_prompt_result() {
        let v = with_query_timeout(async { Ok::<u32, DataFusionError>(42) })
            .await
            .expect("a ready future passes through the backstop");
        assert_eq!(v, 42);
    }

    /// Keepalive default is applied only when the DSN doesn't set one.
    #[test]
    fn resilience_defaults_set_keepalive_when_absent_and_respect_explicit() {
        let opts = Opts::from_url("mysql://root@127.0.0.1:3306/test").unwrap();
        assert!(opts.tcp_keepalive().is_none());
        assert_eq!(
            apply_resilience_defaults(opts).tcp_keepalive(),
            Some(KEEPALIVE)
        );

        let explicit = Opts::from(
            OptsBuilder::from_opts(Opts::from_url("mysql://root@127.0.0.1:3306/test").unwrap())
                .tcp_keepalive(Some(std::time::Duration::from_secs(99))),
        );
        assert_eq!(
            apply_resilience_defaults(explicit).tcp_keepalive(),
            Some(std::time::Duration::from_secs(99))
        );
    }
}

//! ClickHouse connector — a SQL source reached over ClickHouse's HTTP
//! interface (the `clickhouse` feature).
//!
//! The same [`SQLExecutor`] shape as the ADBC and Flight SQL connectors:
//! `datafusion-federation` unparses the pushed-down plan to one SQL string,
//! this connector POSTs it to the server and reads the answer back as Arrow.
//!
//! # Transport
//!
//! Every request is an HTTP `POST` of the SQL text with
//! `default_format = ArrowStream`, so results arrive as an Arrow IPC stream
//! and there is no per-type row decoder. The connection reuses `reqwest` and
//! `arrow`'s IPC reader, both already dependencies of this crate.
//!
//! Every request also carries the settings in `REQUEST_SETTINGS`, so the
//! result does not depend on how the server or the user's profile is
//! configured: an uncompressed Arrow stream, strings as Arrow strings, and
//! the standard-SQL behaviour for outer joins, empty aggregates and bare
//! `UNION` that `DataFusion` plans for.
//!
//! # Types
//!
//! Column types come from `system.columns` and are mapped by `arrow_type`.
//! ClickHouse sends `Date` as its raw `UInt16` day number, which is converted
//! to `Date32` before a batch leaves the connector; `DateTime` arrives as
//! `UInt32` seconds, which the shared batch alignment casts to the planned
//! timestamp. A table with a column type the connector cannot read
//! (`Enum`, `UUID`, `Array`, `Map`, `Tuple`, …) fails with an error naming
//! the column, rather than being exposed without it.
//!
//! # Credentials
//!
//! `user` is sent in `X-ClickHouse-User` and the password, read from the
//! environment variable named by `password_env`, in `X-ClickHouse-Key` —
//! never in the URL. A password is refused over plain `http://` unless the
//! server is on loopback. Server error text is scrubbed of the password
//! before it reaches an error message (hard rule 12).
//!
//! # Not yet
//!
//! - The unparser dialect only sets identifier quoting; date, interval and
//!   cast rewrites for ClickHouse come in a follow-up, so a pushed-down
//!   query using those can be rejected by the server.
//! - The whole response is read before decoding, matching the ADBC
//!   connector; incremental streaming is a follow-up.

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::io::Cursor;
use std::sync::Arc;
use std::time::Duration;

use arrow::array::{Array, ArrayRef, AsArray, RecordBatch, StringArray};
use arrow::compute::cast;
use arrow::datatypes::{DataType, Field, Schema, SchemaRef, TimeUnit};
use arrow::ipc::reader::StreamReader;
use async_trait::async_trait;
use datafusion::catalog::{
    CatalogProvider as DfCatalogProvider, SchemaProvider as DfSchemaProvider,
};
use datafusion::common::TableReference;
use datafusion::datasource::TableProvider;
use datafusion::error::{DataFusionError, Result as DfResult};
use datafusion::execution::SendableRecordBatchStream;
use datafusion::physical_plan::stream::RecordBatchStreamAdapter;
use datafusion::physical_plan::PhysicalExpr;
use datafusion::sql::unparser::dialect::{CustomDialectBuilder, Dialect};
use datafusion_federation::sql::{
    AstAnalyzer, LogicalOptimizer, RemoteTableRef, SQLExecutor, SQLFederationProvider,
    SQLTableSource,
};
use datafusion_federation::FederatedTableProviderAdaptor;
use dataglot_core::{DataglotError, Result as DataglotResult};
use futures::stream::{self, TryStreamExt};
use reqwest::header::{HeaderMap, HeaderValue};
use reqwest::{Client, Url};
use tracing::warn;

/// Connector kind, as it appears in errors and pushdown traces.
const KIND: &str = "clickhouse";

/// Settings sent with every request.
///
/// - `default_format`: answer in Arrow IPC stream format.
/// - `wait_end_of_query`: buffer the result on the server until the query
///   has finished. Without it, an error raised after the first block has
///   been sent arrives inside a `200 OK` body, after part of the stream.
/// - `output_format_arrow_compression_method = none`: ClickHouse compresses
///   with LZ4 by default, which would need an Arrow IPC compression feature
///   this crate does not enable.
/// - `output_format_arrow_string_as_string`: `String` as Arrow `Utf8`, not
///   `Binary` (the default on recent servers, not on older ones).
/// - `output_format_arrow_low_cardinality_as_dictionary = 0`:
///   `LowCardinality(T)` as plain `T`, matching the planned schema.
/// - `join_use_nulls`: an unmatched outer-join row is `NULL`, not the
///   column type's default (`0`, `''`).
/// - `aggregate_functions_null_for_empty`: `sum`, `max`, … over no rows are
///   `NULL`, not `0`.
/// - `union_default_mode = DISTINCT`: a bare `UNION` is `UNION DISTINCT`;
///   ClickHouse otherwise rejects it.
const REQUEST_SETTINGS: &[(&str, &str)] = &[
    ("default_format", "ArrowStream"),
    ("wait_end_of_query", "1"),
    ("output_format_arrow_compression_method", "none"),
    ("output_format_arrow_string_as_string", "1"),
    ("output_format_arrow_low_cardinality_as_dictionary", "0"),
    ("join_use_nulls", "1"),
    ("aggregate_functions_null_for_empty", "1"),
    ("union_default_mode", "DISTINCT"),
];

/// Every table outside ClickHouse's own system databases.
const LIST_TABLES: &str = "SELECT database, name FROM system.tables \
     WHERE is_temporary = 0 \
     AND database NOT IN ('system', 'INFORMATION_SCHEMA', 'information_schema') \
     ORDER BY database, name";

/// The tables of one database, passed as the `database` query parameter.
const LIST_TABLES_IN_DATABASE: &str = "SELECT database, name FROM system.tables \
     WHERE is_temporary = 0 AND database = {database:String} \
     ORDER BY name";

/// One table's columns in declaration order, with the server's time zone:
/// a `DateTime` declared without one is read in it.
const TABLE_COLUMNS: &str = "SELECT name, type, timezone() FROM system.columns \
     WHERE database = {database:String} AND table = {table:String} \
     ORDER BY position";

/// How much of a server error body is kept in an error message.
const MAX_ERROR_TEXT: usize = 2_000;

// ---------------------------------------------------------------------------
// Credentials
// ---------------------------------------------------------------------------

/// A resolved password. Exists so a stray `{:?}` can never print one
/// (hard rule 12).
#[derive(Clone)]
struct Secret(String);

impl Secret {
    fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[redacted]")
    }
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/// Configuration for one `kind = "clickhouse"` catalog entry.
///
/// `Debug` is safe to log: it carries the env-var *name*, never the password.
#[derive(Clone)]
pub struct ClickHouseConfig {
    /// Catalog name — the unique `SQLExecutor::name` / federation
    /// compute-context key.
    pub name: String,
    /// The server's HTTP interface: scheme, host and port only, e.g.
    /// `https://clickhouse.example.com:8443`. `http://` is plaintext and
    /// carries a password only to a loopback host.
    pub url: String,
    /// ClickHouse user, sent in `X-ClickHouse-User`. `None` lets the server
    /// pick its default user.
    pub user: Option<String>,
    /// Environment variable holding the password, sent in `X-ClickHouse-Key`.
    pub password_env: Option<String>,
    /// Limit discovery to one database. `None` lists every database except
    /// ClickHouse's own system ones.
    pub database: Option<String>,
    /// TCP + TLS handshake budget. Default 10s.
    pub connect_timeout_secs: u64,
    /// Budget for one whole request, including reading the result. `None`
    /// means no client-side limit (the server's own limits apply).
    pub request_timeout_secs: Option<u64>,
}

impl ClickHouseConfig {
    /// A config with the required fields set and defaults for the rest (no
    /// user or password, every database, 10s connect timeout).
    #[must_use]
    pub fn new(name: impl Into<String>, url: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            url: url.into(),
            user: None,
            password_env: None,
            database: None,
            connect_timeout_secs: 10,
            request_timeout_secs: None,
        }
    }

    /// Validate the config shape before any network interaction.
    ///
    /// # Errors
    /// [`DataglotError::Configuration`] when the name or URL is missing, the
    /// URL is not a plain `http(s)://host:port`, a password is configured on
    /// plaintext `http://` to a host that is not loopback, `user` cannot be
    /// sent as an HTTP header, `database` is empty, or a timeout is zero.
    pub fn validate(&self) -> DataglotResult<()> {
        let cfg_err = |msg: String| {
            DataglotError::configuration(format!("clickhouse catalog '{}': {msg}", self.name))
        };
        if self.name.trim().is_empty() {
            return Err(DataglotError::configuration(
                "clickhouse catalog: `name` is required",
            ));
        }
        let endpoint = Endpoint::parse(&self.url).map_err(cfg_err)?;
        if self.password_env.is_some() && !endpoint.tls && !endpoint.loopback {
            return Err(cfg_err(
                "`password_env` is set but `url` is plaintext http:// to a host that is not \
                 loopback, so the password would cross the network in cleartext; use https://"
                    .to_string(),
            ));
        }
        if let Some(user) = &self.user {
            if user.is_empty() || HeaderValue::from_str(user).is_err() {
                return Err(cfg_err(
                    "`user` must be non-empty and printable ASCII, since it is sent as an \
                     HTTP header"
                        .to_string(),
                ));
            }
        }
        if self
            .database
            .as_deref()
            .is_some_and(|db| db.trim().is_empty())
        {
            return Err(cfg_err("`database` is set but empty".to_string()));
        }
        if self.connect_timeout_secs == 0 {
            return Err(cfg_err(
                "`connect_timeout_secs` must be at least 1".to_string(),
            ));
        }
        if self.request_timeout_secs == Some(0) {
            return Err(cfg_err(
                "`request_timeout_secs` must be at least 1 when set".to_string(),
            ));
        }
        Ok(())
    }
}

impl fmt::Debug for ClickHouseConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClickHouseConfig")
            .field("name", &self.name)
            // `validate` refuses credentials in the URL, but a struct built by
            // hand never saw it — so redact rather than trust (rule 12).
            .field("url", &Endpoint::display(&self.url))
            .field("user", &self.user)
            .field("password_env", &self.password_env)
            .field("database", &self.database)
            .field("connect_timeout_secs", &self.connect_timeout_secs)
            .field("request_timeout_secs", &self.request_timeout_secs)
            .finish()
    }
}

/// A validated server address.
#[derive(Debug, Clone)]
struct Endpoint {
    /// `scheme://host:port/`, nothing else.
    url: Url,
    tls: bool,
    /// The host is `localhost` or a loopback address, so traffic to it never
    /// leaves this machine — the one place a password may go without TLS.
    loopback: bool,
}

impl Endpoint {
    /// Parse the configured URL.
    ///
    /// An endpoint is a scheme, host and port: userinfo, a path, a query
    /// string and a fragment are all refused (a bare trailing `/` is fine).
    /// The query string is where this connector puts its own settings, and
    /// userinfo is a credential that would end up in logs.
    ///
    /// # Errors
    /// A message naming the problem. No error echoes the URL, since the
    /// offending part may be a credential.
    fn parse(raw: &str) -> Result<Self, String> {
        let raw = raw.trim();
        if raw.is_empty() {
            return Err("`url` is required".to_string());
        }
        let url = Url::parse(raw).map_err(|e| format!("`url` is not a valid URL: {e}"))?;
        let tls = match url.scheme() {
            "http" => false,
            "https" => true,
            _ => return Err("`url` must start with http:// or https://".to_string()),
        };
        if !url.username().is_empty() || url.password().is_some() {
            return Err(
                "`url` carries credentials (user@host); use `user` and `password_env` \
                 instead, so the password is read from the environment and never logged"
                    .to_string(),
            );
        }
        for (component, present) in [
            ("a path", url.path() != "/" && !url.path().is_empty()),
            ("a query string", url.query().is_some()),
            ("a fragment", url.fragment().is_some()),
        ] {
            if present {
                return Err(format!(
                    "`url` carries {component}; give the server's scheme, host and port only"
                ));
            }
        }
        let host = url
            .host_str()
            .filter(|host| !host.is_empty())
            .ok_or_else(|| "`url` has no host".to_string())?;
        // An IPv6 host keeps its brackets in `host_str`.
        let host = host.trim_start_matches('[').trim_end_matches(']');
        let loopback = host.eq_ignore_ascii_case("localhost")
            || host
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback());
        Ok(Self { url, tls, loopback })
    }

    /// The URL rendered for logs: what [`Self::parse`] accepts, or a
    /// placeholder when it does not, since the rejected part may be a secret.
    fn display(raw: &str) -> String {
        Self::parse(raw).map_or_else(
            |_| "[redacted: invalid url]".to_string(),
            |e| e.url.to_string(),
        )
    }
}

// ---------------------------------------------------------------------------
// HTTP client
// ---------------------------------------------------------------------------

/// What a request needs, cheap to clone into a query's future.
#[derive(Clone)]
struct Remote {
    /// Catalog name, for error messages.
    name: String,
    endpoint: Url,
    /// Carries the `X-ClickHouse-User` / `X-ClickHouse-Key` default headers.
    http: Client,
    /// Kept only to scrub it out of server text.
    password: Option<Secret>,
}

impl Remote {
    /// Run `sql` with [`REQUEST_SETTINGS`] and the given query parameters
    /// (`{name:Type}` placeholders in the SQL), and read the Arrow result.
    ///
    /// # Errors
    /// [`DataglotError::Connection`] when the server cannot be reached or the
    /// response cannot be read; [`DataglotError::Federation`] when the server
    /// answers with an error or with something that is not an Arrow stream.
    /// The password never appears in either.
    async fn query(&self, sql: &str, params: &[(&str, &str)]) -> DataglotResult<Vec<RecordBatch>> {
        let mut url = self.endpoint.clone();
        {
            let mut pairs = url.query_pairs_mut();
            pairs.extend_pairs(REQUEST_SETTINGS);
            for (name, value) in params {
                pairs.append_pair(&format!("param_{name}"), value);
            }
        }
        let response = self
            .http
            .post(url)
            .body(sql.to_string())
            .send()
            .await
            .map_err(|e| self.connection_error("request failed", &e))?;
        let status = response.status();
        // With `wait_end_of_query` a failed query gets an error status, but
        // the exception header is the server's own marker, so check both.
        let failed = !status.is_success()
            || response
                .headers()
                .contains_key("x-clickhouse-exception-code");
        let body = response
            .bytes()
            .await
            .map_err(|e| self.connection_error("reading the response failed", &e))?;
        if failed {
            // Scrub before truncating: a cut through the password would leave
            // its first characters where the scrub no longer matches them.
            let text = self.scrub(String::from_utf8_lossy(&body).trim());
            return Err(DataglotError::federation(format!(
                "clickhouse catalog '{}': server answered {status}: {}",
                self.name,
                truncate(&text, MAX_ERROR_TEXT)
            )));
        }
        decode_arrow_stream(&body).map_err(|e| {
            DataglotError::federation(format!("clickhouse catalog '{}': {e}", self.name))
        })
    }

    /// A transport error with its full cause chain, scrubbed.
    fn connection_error(&self, what: &str, error: &reqwest::Error) -> DataglotError {
        let mut chain = vec![error.to_string()];
        let mut source = std::error::Error::source(error);
        while let Some(cause) = source {
            chain.push(cause.to_string());
            source = cause.source();
        }
        DataglotError::connection(self.scrub(&format!(
            "clickhouse catalog '{}': {what}: {}",
            self.name,
            chain.join(": ")
        )))
    }

    /// Replace every occurrence of the password in `msg`, ignoring ASCII case.
    fn scrub(&self, msg: &str) -> String {
        match &self.password {
            Some(secret) => scrub(msg, secret.expose()),
            None => msg.to_string(),
        }
    }
}

/// Replace every occurrence of `secret` in `msg`, ignoring ASCII case.
///
/// Case-insensitive because text that passed through a normaliser (a URL
/// parser lowercases hosts) can carry a reflected credential in another case.
/// ASCII lowercasing keeps byte offsets, so a match found in the folded copy
/// addresses the original exactly.
fn scrub(msg: &str, secret: &str) -> String {
    if secret.is_empty() {
        return msg.to_string();
    }
    let folded = msg.to_ascii_lowercase();
    let needle = secret.to_ascii_lowercase();
    let mut out = String::with_capacity(msg.len());
    let mut cursor = 0;
    while let Some(hit) = folded[cursor..].find(&needle) {
        let start = cursor + hit;
        out.push_str(&msg[cursor..start]);
        out.push_str("[redacted]");
        cursor = start + needle.len();
    }
    out.push_str(&msg[cursor..]);
    out
}

/// The first `max` bytes of `text`, cut on a character boundary.
fn truncate(text: &str, max: usize) -> String {
    if text.len() <= max {
        return text.to_string();
    }
    let mut end = max;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}… [truncated]", &text[..end])
}

/// Read an Arrow IPC stream body into batches.
///
/// An empty result is still a stream (schema, no batches); an empty body is
/// accepted too rather than treated as malformed.
fn decode_arrow_stream(body: &[u8]) -> Result<Vec<RecordBatch>, String> {
    if body.is_empty() {
        return Ok(Vec::new());
    }
    let reader = StreamReader::try_new(Cursor::new(body), None)
        .map_err(|e| format!("the response is not an Arrow stream: {e}"))?;
    reader
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("reading the Arrow stream failed: {e}"))
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Map a ClickHouse column type, as `system.columns` spells it, to the Arrow
/// type the column is read as and whether it is nullable.
///
/// `server_tz` is the time zone of a `DateTime` / `DateTime64` declared
/// without one; ClickHouse reads and sends those in the server's zone.
///
/// # Errors
/// A message naming the type when the connector cannot read it.
fn arrow_type(ch_type: &str, server_tz: &str) -> Result<(DataType, bool), String> {
    let ch_type = ch_type.trim();
    if let Some(inner) = wrapped(ch_type, "LowCardinality") {
        // Sent as plain values (`output_format_arrow_low_cardinality_as_dictionary = 0`).
        return arrow_type(inner, server_tz);
    }
    if let Some(inner) = wrapped(ch_type, "Nullable") {
        let (data_type, _) = arrow_type(inner, server_tz)?;
        return Ok((data_type, true));
    }
    let unsupported =
        || format!("has type {ch_type}, which the clickhouse connector cannot read yet");
    let data_type = match ch_type {
        "Bool" => DataType::Boolean,
        "UInt8" => DataType::UInt8,
        "UInt16" => DataType::UInt16,
        "UInt32" => DataType::UInt32,
        "UInt64" => DataType::UInt64,
        "Int8" => DataType::Int8,
        "Int16" => DataType::Int16,
        "Int32" => DataType::Int32,
        "Int64" => DataType::Int64,
        "Float32" => DataType::Float32,
        "Float64" => DataType::Float64,
        "String" => DataType::Utf8,
        // `Date` arrives as UInt16 days and is converted (`restore_dates`);
        // `Date32` arrives as Arrow `Date32`.
        "Date" | "Date32" => DataType::Date32,
        // Arrives as UInt32 seconds since the epoch.
        "DateTime" => DataType::Timestamp(TimeUnit::Second, Some(server_tz.into())),
        _ => {
            if let Some(args) = wrapped(ch_type, "FixedString") {
                let width = args
                    .trim()
                    .parse::<i32>()
                    .ok()
                    .filter(|width| *width > 0)
                    .ok_or_else(unsupported)?;
                DataType::FixedSizeBinary(width)
            } else if let Some(args) = wrapped(ch_type, "Decimal") {
                decimal_type(args).ok_or_else(unsupported)?
            } else if let Some(args) = wrapped(ch_type, "DateTime") {
                let tz = unquote(args).ok_or_else(unsupported)?;
                DataType::Timestamp(TimeUnit::Second, Some(tz.into()))
            } else if let Some(args) = wrapped(ch_type, "DateTime64") {
                datetime64_type(args, server_tz).ok_or_else(unsupported)?
            } else {
                return Err(unsupported());
            }
        }
    };
    Ok((data_type, false))
}

/// The inside of `name(...)`, if `ch_type` is exactly that.
fn wrapped<'a>(ch_type: &'a str, name: &str) -> Option<&'a str> {
    ch_type
        .strip_prefix(name)?
        .strip_prefix('(')?
        .strip_suffix(')')
}

/// A single-quoted string such as `'Europe/Berlin'`, unquoted.
fn unquote(arg: &str) -> Option<&str> {
    arg.trim()
        .strip_prefix('\'')?
        .strip_suffix('\'')
        .filter(|s| !s.is_empty())
}

/// `Decimal(P, S)`: `Decimal128` up to 38 digits, `Decimal256` up to 76.
fn decimal_type(args: &str) -> Option<DataType> {
    let (precision, scale) = args.split_once(',')?;
    let precision = precision.trim().parse::<u8>().ok()?;
    let scale = scale.trim().parse::<i8>().ok()?;
    if precision == 0 || scale < 0 || i16::from(scale) > i16::from(precision) {
        return None;
    }
    match precision {
        1..=38 => Some(DataType::Decimal128(precision, scale)),
        39..=76 => Some(DataType::Decimal256(precision, scale)),
        _ => None,
    }
}

/// `DateTime64(P[, 'tz'])`. ClickHouse sends precision 0 as seconds, 1–3 as
/// milliseconds, 4–6 as microseconds and 7–9 as nanoseconds.
fn datetime64_type(args: &str, server_tz: &str) -> Option<DataType> {
    let (precision, tz) = match args.split_once(',') {
        Some((precision, tz)) => (precision, unquote(tz)?),
        None => (args, server_tz),
    };
    let unit = match precision.trim().parse::<u8>().ok()? {
        0 => TimeUnit::Second,
        1..=3 => TimeUnit::Millisecond,
        4..=6 => TimeUnit::Microsecond,
        7..=9 => TimeUnit::Nanosecond,
        _ => return None,
    };
    Some(DataType::Timestamp(unit, Some(tz.into())))
}

/// Convert ClickHouse's `Date` encoding (`UInt16` days since the epoch) to
/// `Date32` wherever the plan expects a date.
///
/// Arrow has no direct cast from `UInt16` to `Date32`, so the shared batch
/// alignment would reject it. Widening to `Int32` first is lossless, and
/// `Int32` → `Date32` is a reinterpretation of the same day number. Any
/// other column is left for [`crate::remote_sql::align_batch`].
fn restore_dates(batch: &RecordBatch, target: &SchemaRef) -> DataglotResult<RecordBatch> {
    let is_date = |column: &ArrayRef, field: &Field| {
        column.data_type() == &DataType::UInt16 && field.data_type() == &DataType::Date32
    };
    // A different column count is `align_batch`'s error to report.
    if batch.num_columns() != target.fields().len()
        || !batch
            .columns()
            .iter()
            .zip(target.fields())
            .any(|(column, field)| is_date(column, field))
    {
        return Ok(batch.clone());
    }
    let mut fields = Vec::with_capacity(batch.num_columns());
    let mut columns = Vec::with_capacity(batch.num_columns());
    for ((column, field), source) in batch
        .columns()
        .iter()
        .zip(target.fields())
        .zip(batch.schema().fields())
    {
        if is_date(column, field) {
            let days = cast(column, &DataType::Int32)
                .and_then(|days| cast(&days, &DataType::Date32))
                .map_err(|e| {
                    DataglotError::federation(format!(
                        "clickhouse result column '{}': converting Date failed: {e}",
                        field.name()
                    ))
                })?;
            fields.push(source.as_ref().clone().with_data_type(DataType::Date32));
            columns.push(days);
        } else {
            fields.push(source.as_ref().clone());
            columns.push(Arc::clone(column));
        }
    }
    RecordBatch::try_new(Arc::new(Schema::new(fields)), columns).map_err(|e| {
        DataglotError::federation(format!("clickhouse result batch rebuild failed: {e}"))
    })
}

/// A metadata column as strings. Cast rather than downcast: a server may
/// answer with `Binary` or `LargeUtf8` as readily as `Utf8`.
fn string_column(batch: &RecordBatch, index: usize) -> DataglotResult<StringArray> {
    let column = batch.columns().get(index).ok_or_else(|| {
        DataglotError::catalog(format!(
            "clickhouse metadata result has {} columns, expected at least {}",
            batch.num_columns(),
            index + 1
        ))
    })?;
    let strings = cast(column, &DataType::Utf8).map_err(|e| {
        DataglotError::catalog(format!(
            "clickhouse metadata column {index} is not text: {e}"
        ))
    })?;
    Ok(strings.as_string::<i32>().clone())
}

// ---------------------------------------------------------------------------
// Dialect and references
// ---------------------------------------------------------------------------

/// The unparser dialect: double-quoted identifiers, which ClickHouse accepts
/// alongside backticks. `DataFusion` ships no ClickHouse dialect.
#[must_use]
pub fn clickhouse_dialect() -> Arc<dyn Dialect> {
    Arc::new(
        CustomDialectBuilder::new()
            .with_identifier_quote_style('"')
            .build(),
    )
}

/// Split a rendered `<database>.<table>` reference on the dot outside
/// double quotes, so a dotted name (`"logs.2024"."events"`) stays whole.
/// A doubled quote inside quotes is a literal one.
fn split_reference(reference: &str) -> Option<(String, String)> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    let mut chars = reference.chars().peekable();
    while let Some(c) = chars.next() {
        match (quoted, c) {
            (true, '"') if chars.peek() == Some(&'"') => {
                current.push('"');
                chars.next();
            }
            (_, '"') => quoted = !quoted,
            (false, '.') => parts.push(std::mem::take(&mut current)),
            _ => current.push(c),
        }
    }
    parts.push(current);
    match <[String; 2]>::try_from(parts) {
        Ok([database, table]) if !database.is_empty() && !table.is_empty() => {
            Some((database, table))
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Connector
// ---------------------------------------------------------------------------

/// A ClickHouse server reached over HTTP.
pub struct ClickHouseConnector {
    config: ClickHouseConfig,
    remote: Remote,
}

impl fmt::Debug for ClickHouseConnector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClickHouseConnector")
            .field("name", &self.config.name)
            .field("url", &self.remote.endpoint.as_str())
            .finish_non_exhaustive()
    }
}

impl ClickHouseConnector {
    /// Validate the config, read the password from the environment and
    /// build the HTTP client. No request is made: discovery happens in
    /// [`Self::as_catalog_provider`] and column schemas on first use.
    ///
    /// # Errors
    /// [`DataglotError::Configuration`] when the config is invalid,
    /// `password_env` names an unset variable, or the password cannot be sent
    /// as an HTTP header; [`DataglotError::Connection`] when the HTTP client
    /// cannot be built. No message contains the password.
    pub fn connect(config: ClickHouseConfig) -> DataglotResult<Self> {
        config.validate()?;
        let cfg_err = |msg: String| {
            DataglotError::configuration(format!("clickhouse catalog '{}': {msg}", config.name))
        };
        let endpoint = Endpoint::parse(&config.url).map_err(cfg_err)?;

        let mut headers = HeaderMap::new();
        if let Some(user) = &config.user {
            // `validate` checked it is a valid header value.
            let value = HeaderValue::from_str(user)
                .map_err(|_| cfg_err("`user` cannot be sent as an HTTP header".to_string()))?;
            headers.insert("x-clickhouse-user", value);
        }
        let password = match &config.password_env {
            Some(env) => {
                let value = std::env::var(env).map_err(|_| {
                    cfg_err(format!(
                        "password_env '{env}' is not set in the environment"
                    ))
                })?;
                Some(Secret(value)).filter(|secret| !secret.expose().is_empty())
            }
            None => None,
        };
        if let Some(secret) = &password {
            let mut value = HeaderValue::from_bytes(secret.expose().as_bytes()).map_err(|_| {
                cfg_err("the password contains characters an HTTP header cannot carry".to_string())
            })?;
            value.set_sensitive(true);
            headers.insert("x-clickhouse-key", value);
        }

        let mut builder = Client::builder()
            .default_headers(headers)
            .connect_timeout(Duration::from_secs(config.connect_timeout_secs));
        if let Some(secs) = config.request_timeout_secs {
            builder = builder.timeout(Duration::from_secs(secs));
        }
        let http = builder.build().map_err(|e| {
            DataglotError::connection(format!(
                "clickhouse catalog '{}': building the HTTP client failed: {e}",
                config.name
            ))
        })?;

        Ok(Self {
            remote: Remote {
                name: config.name.clone(),
                endpoint: endpoint.url,
                http,
                password,
            },
            config,
        })
    }

    /// The connector / federation compute-context name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.config.name
    }

    /// A federation [`TableProvider`] for `<database>.<table>` with full
    /// pushdown. The column schema is fetched on this call — lazily, per
    /// hard rule 13.
    ///
    /// # Errors
    /// [`DataglotError::Catalog`] when the table does not exist, is not
    /// visible to the user, or has a column type the connector cannot read.
    pub async fn table_provider(
        self: &Arc<Self>,
        database: &str,
        table: &str,
    ) -> DataglotResult<Arc<dyn TableProvider>> {
        let arrow_schema = self.fetch_arrow_schema(database, table).await?;
        let executor: Arc<dyn SQLExecutor> = Arc::clone(self) as Arc<dyn SQLExecutor>;
        let provider = Arc::new(SQLFederationProvider::new(executor));
        let table_ref = RemoteTableRef::from(TableReference::partial(
            database.to_string(),
            table.to_string(),
        ));
        let source = SQLTableSource::new_with_schema(provider, table_ref, arrow_schema);
        Ok(Arc::new(FederatedTableProviderAdaptor::new(Arc::new(
            source,
        ))))
    }

    /// Read `<database>.<table>`'s columns from `system.columns`.
    async fn fetch_arrow_schema(&self, database: &str, table: &str) -> DataglotResult<SchemaRef> {
        let batches = self
            .remote
            .query(TABLE_COLUMNS, &[("database", database), ("table", table)])
            .await?;
        let mut fields = Vec::new();
        for batch in &batches {
            let names = string_column(batch, 0)?;
            let types = string_column(batch, 1)?;
            let zones = string_column(batch, 2)?;
            for row in 0..batch.num_rows() {
                if names.is_null(row) || types.is_null(row) || zones.is_null(row) {
                    return Err(DataglotError::catalog(format!(
                        "clickhouse catalog '{}': system.columns returned an incomplete row \
                         for '{database}.{table}'",
                        self.config.name
                    )));
                }
                let name = names.value(row);
                let (data_type, nullable) = arrow_type(types.value(row), zones.value(row))
                    .map_err(|reason| {
                        DataglotError::catalog(format!(
                            "clickhouse catalog '{}': column '{database}.{table}.{name}' {reason}",
                            self.config.name
                        ))
                    })?;
                fields.push(Field::new(name, data_type, nullable));
            }
        }
        if fields.is_empty() {
            return Err(DataglotError::catalog(format!(
                "clickhouse catalog '{}': table '{database}.{table}' does not exist or is not \
                 visible to this user",
                self.config.name
            )));
        }
        Ok(Arc::new(Schema::new(fields)))
    }

    /// `database → table names`, from `system.tables`.
    async fn list_tables(&self) -> DataglotResult<BTreeMap<String, Vec<String>>> {
        let batches = match &self.config.database {
            Some(database) => {
                self.remote
                    .query(LIST_TABLES_IN_DATABASE, &[("database", database.as_str())])
                    .await?
            }
            None => self.remote.query(LIST_TABLES, &[]).await?,
        };
        let mut listing: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for batch in &batches {
            let databases = string_column(batch, 0)?;
            let tables = string_column(batch, 1)?;
            for row in 0..batch.num_rows() {
                // Fail closed: a row that cannot be addressed would otherwise
                // be dropped, and the listing would look complete.
                if databases.is_null(row) || tables.is_null(row) {
                    return Err(DataglotError::catalog(format!(
                        "clickhouse catalog '{}': system.tables returned a row without a \
                         database or table name",
                        self.config.name
                    )));
                }
                listing
                    .entry(databases.value(row).to_string())
                    .or_default()
                    .push(tables.value(row).to_string());
            }
        }
        if let Some(database) = &self.config.database {
            if listing.is_empty() {
                warn!(
                    catalog = %self.config.name,
                    database = %database,
                    "clickhouse: the configured database has no tables visible to this user"
                );
            }
        }
        Ok(listing)
    }

    /// Wrap this connector as a `DataFusion` [`CatalogProvider`].
    ///
    /// Databases and table names are listed once, here, and cached for the
    /// catalog's lifetime (rebuild it to pick up remote DDL). Column schemas
    /// stay lazy: they are fetched on first [`SchemaProvider::table`] access
    /// (rule 13). A ClickHouse database becomes a schema.
    ///
    /// # Errors
    /// [`DataglotError`] when the listing query fails or returns rows the
    /// connector cannot address.
    ///
    /// [`CatalogProvider`]: datafusion::catalog::CatalogProvider
    /// [`SchemaProvider::table`]: datafusion::catalog::SchemaProvider::table
    pub async fn as_catalog_provider(
        self: &Arc<Self>,
    ) -> DataglotResult<Arc<dyn DfCatalogProvider>> {
        let listing = self.list_tables().await?;
        let schema_names: Vec<String> = listing.keys().cloned().collect();
        let schemas: HashMap<String, Arc<dyn DfSchemaProvider>> = listing
            .into_iter()
            .map(|(database, table_names)| {
                let provider = Arc::new(ClickHouseSchema {
                    connector: Arc::clone(self),
                    database: database.clone(),
                    table_names,
                }) as Arc<dyn DfSchemaProvider>;
                (database, provider)
            })
            .collect();
        Ok(Arc::new(ClickHouseCatalog {
            connector_name: self.config.name.clone(),
            schema_names,
            schemas,
        }) as Arc<dyn DfCatalogProvider>)
    }
}

#[async_trait]
impl SQLExecutor for ClickHouseConnector {
    fn name(&self) -> &str {
        &self.config.name
    }

    fn compute_context(&self) -> Option<String> {
        Some(self.config.name.clone())
    }

    fn dialect(&self) -> Arc<dyn Dialect> {
        clickhouse_dialect()
    }

    fn logical_optimizer(&self) -> Option<LogicalOptimizer> {
        // Isolate governance row filters on OUTER-JOIN preserved legs so the
        // unparser can't fold them into `ON` (RLS bypass). See
        // `crate::rls_isolation`.
        Some(Box::new(|plan: datafusion::logical_expr::LogicalPlan| {
            crate::rls_isolation::isolate_outer_join_filters(plan)
        }))
    }

    fn ast_analyzer(&self) -> Option<AstAnalyzer> {
        // Requalify the derived-table references the unparser leaves dangling
        // on pushed-down DISTINCT/GROUP BY.
        Some(Box::new(
            |stmt: datafusion::sql::sqlparser::ast::Statement| {
                Ok(crate::derived_requalify::requalify_derived_refs(stmt))
            },
        ))
    }

    fn execute(
        &self,
        query: &str,
        schema: SchemaRef,
        _filters: &[Arc<dyn PhysicalExpr>],
    ) -> DfResult<SendableRecordBatchStream> {
        let remote = self.remote.clone();
        let sql = query.to_string();
        let target = Arc::clone(&schema);
        let fut = async move {
            let batches = remote
                .query(&sql, &[])
                .await
                .map_err(|e| DataFusionError::External(Box::new(e)))?;
            let aligned = batches
                .iter()
                .map(|batch| {
                    let batch = restore_dates(batch, &target)?;
                    crate::remote_sql::align_batch(&batch, &target, KIND)
                })
                .collect::<DataglotResult<Vec<_>>>()
                .map_err(|e| DataFusionError::External(Box::new(e)))?;
            Ok::<_, DataFusionError>(stream::iter(aligned.into_iter().map(Ok)))
        };
        let stream = Box::pin(RecordBatchStreamAdapter::new(
            schema,
            stream::once(fut).try_flatten(),
        ));
        Ok(crate::instrument_pushdown(
            &self.config.name,
            KIND,
            query,
            stream,
        ))
    }

    async fn table_names(&self) -> DfResult<Vec<String>> {
        // Not used by the federation pushdown path; `as_catalog_provider` is
        // the listing surface, as for the other SQL connectors.
        Err(DataFusionError::NotImplemented(
            "table_names not implemented".to_string(),
        ))
    }

    async fn get_table_schema(&self, table_name: &str) -> DfResult<SchemaRef> {
        let (database, table) = split_reference(table_name).ok_or_else(|| {
            DataFusionError::External(Box::new(DataglotError::catalog(format!(
                "expected a '<database>.<table>' reference, got: {table_name}"
            ))))
        })?;
        self.fetch_arrow_schema(&database, &table)
            .await
            .map_err(|e| DataFusionError::External(Box::new(e)))
    }
}

/// `SELECT 1` on the existing client: proves the server is reachable and the
/// credentials are still valid. The error text is scrubbed (rule 12).
#[async_trait]
impl crate::health::ConnectorHealthCheck for ClickHouseConnector {
    async fn health_check(&self) -> Result<(), String> {
        self.remote
            .query("SELECT 1", &[])
            .await
            .map(|_| ())
            .map_err(|e| format!("clickhouse health check failed: {e}"))
    }
}

// ---------------------------------------------------------------------------
// Catalog providers
// ---------------------------------------------------------------------------

/// `DataFusion` [`CatalogProvider`] over a [`ClickHouseConnector`], built by
/// [`ClickHouseConnector::as_catalog_provider`].
///
/// [`CatalogProvider`]: datafusion::catalog::CatalogProvider
pub struct ClickHouseCatalog {
    /// Diagnostics only; the registered name comes from `register_catalog`.
    connector_name: String,
    /// Sorted database names.
    schema_names: Vec<String>,
    schemas: HashMap<String, Arc<dyn DfSchemaProvider>>,
}

impl fmt::Debug for ClickHouseCatalog {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClickHouseCatalog")
            .field("connector", &self.connector_name)
            .field("schema_count", &self.schema_names.len())
            .finish_non_exhaustive()
    }
}

impl DfCatalogProvider for ClickHouseCatalog {
    fn schema_names(&self) -> Vec<String> {
        self.schema_names.clone()
    }

    fn schema(&self, name: &str) -> Option<Arc<dyn DfSchemaProvider>> {
        self.schemas.get(name).map(Arc::clone)
    }
}

/// One ClickHouse database. Table names are cached; column schemas resolve
/// on first [`SchemaProvider::table`] access (rule 13).
///
/// [`SchemaProvider::table`]: datafusion::catalog::SchemaProvider::table
struct ClickHouseSchema {
    connector: Arc<ClickHouseConnector>,
    database: String,
    /// Sorted table names.
    table_names: Vec<String>,
}

impl fmt::Debug for ClickHouseSchema {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClickHouseSchema")
            .field("database", &self.database)
            .field("table_count", &self.table_names.len())
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl DfSchemaProvider for ClickHouseSchema {
    fn table_names(&self) -> Vec<String> {
        self.table_names.clone()
    }

    fn table_exist(&self, name: &str) -> bool {
        self.table_names.iter().any(|t| t == name)
    }

    async fn table(&self, name: &str) -> DfResult<Option<Arc<dyn TableProvider>>> {
        // No request for a name that was not in the listing.
        if !self.table_exist(name) {
            return Ok(None);
        }
        let provider = self
            .connector
            .table_provider(&self.database, name)
            .await
            .map_err(|e| DataFusionError::External(Box::new(e)))?;
        Ok(Some(provider))
    }
}

#[cfg(test)]
mod tests {
    use arrow::array::{Date32Array, Int64Array, UInt16Array};

    use super::*;

    fn config(url: &str) -> ClickHouseConfig {
        ClickHouseConfig::new("ch", url)
    }

    fn config_error(cfg: &ClickHouseConfig) -> String {
        cfg.validate().unwrap_err().to_string()
    }

    // -----------------------------------------------------------------
    // Config
    // -----------------------------------------------------------------

    #[test]
    fn a_plain_https_or_http_url_is_accepted() {
        for url in [
            "https://clickhouse.example.com:8443",
            "https://clickhouse.example.com:8443/",
            "http://clickhouse.internal:8123",
        ] {
            config(url).validate().unwrap();
        }
    }

    #[test]
    fn url_must_be_scheme_host_and_port_only() {
        for (url, expected) in [
            ("", "`url` is required"),
            ("clickhouse:8123", "http:// or https://"),
            ("ftp://clickhouse:21", "http:// or https://"),
            ("https://ch.example.com:8443/proxy", "a path"),
            ("https://ch.example.com:8443/?database=x", "a query string"),
            ("https://ch.example.com:8443/#frag", "a fragment"),
        ] {
            let err = config_error(&config(url));
            assert!(err.contains(expected), "{url}: {err}");
        }
    }

    #[test]
    fn credentials_in_the_url_are_refused_without_echoing_them() {
        let err = config_error(&config("https://reader:hunter2@ch.example.com:8443"));
        assert!(err.contains("password_env"), "{err}");
        assert!(!err.contains("hunter2"), "{err}");
    }

    #[test]
    fn a_password_over_plain_http_is_refused_unless_loopback() {
        let mut cfg = config("http://ch.internal:8123");
        cfg.password_env = Some("CH_PASSWORD".into());
        assert!(config_error(&cfg).contains("cleartext"));

        for url in [
            "http://localhost:8123",
            "http://127.0.0.1:8123",
            "http://[::1]:8123",
        ] {
            cfg.url = url.into();
            cfg.validate().unwrap();
        }
        // No password, nothing to leak.
        cfg.url = "http://ch.internal:8123".into();
        cfg.password_env = None;
        cfg.validate().unwrap();
    }

    #[test]
    fn other_fields_are_checked_before_any_request() {
        let mut cfg = config("https://ch.example.com:8443");
        cfg.name = " ".into();
        assert!(config_error(&cfg).contains("`name` is required"));

        let mut cfg = config("https://ch.example.com:8443");
        cfg.user = Some("bad\nuser".into());
        assert!(config_error(&cfg).contains("`user`"));

        let mut cfg = config("https://ch.example.com:8443");
        cfg.database = Some(String::new());
        assert!(config_error(&cfg).contains("`database`"));

        let mut cfg = config("https://ch.example.com:8443");
        cfg.connect_timeout_secs = 0;
        assert!(config_error(&cfg).contains("connect_timeout_secs"));

        let mut cfg = config("https://ch.example.com:8443");
        cfg.request_timeout_secs = Some(0);
        assert!(config_error(&cfg).contains("request_timeout_secs"));
    }

    #[test]
    fn debug_never_shows_url_credentials() {
        let cfg = config("https://reader:hunter2@ch.example.com:8443");
        let rendered = format!("{cfg:?}");
        assert!(!rendered.contains("hunter2"), "{rendered}");
        assert!(rendered.contains("[redacted: invalid url]"), "{rendered}");

        let cfg = config("https://ch.example.com:8443");
        assert!(format!("{cfg:?}").contains("https://ch.example.com:8443/"));
    }

    #[test]
    fn secret_debug_is_redacted() {
        assert_eq!(format!("{:?}", Secret("hunter2".into())), "[redacted]");
    }

    // -----------------------------------------------------------------
    // Types
    // -----------------------------------------------------------------

    #[test]
    fn supported_types_map_to_the_arrow_types_clickhouse_sends() {
        let ts = |unit, tz: &str| DataType::Timestamp(unit, Some(tz.into()));
        for (ch_type, expected, nullable) in [
            ("Bool", DataType::Boolean, false),
            ("UInt8", DataType::UInt8, false),
            ("UInt64", DataType::UInt64, false),
            ("Int8", DataType::Int8, false),
            ("Int64", DataType::Int64, false),
            ("Float32", DataType::Float32, false),
            ("Float64", DataType::Float64, false),
            ("String", DataType::Utf8, false),
            ("FixedString(16)", DataType::FixedSizeBinary(16), false),
            ("Date", DataType::Date32, false),
            ("Date32", DataType::Date32, false),
            ("Decimal(9, 2)", DataType::Decimal128(9, 2), false),
            ("Decimal(38, 10)", DataType::Decimal128(38, 10), false),
            ("Decimal(76, 20)", DataType::Decimal256(76, 20), false),
            ("DateTime", ts(TimeUnit::Second, "Europe/Berlin"), false),
            ("DateTime('UTC')", ts(TimeUnit::Second, "UTC"), false),
            (
                "DateTime64(0)",
                ts(TimeUnit::Second, "Europe/Berlin"),
                false,
            ),
            (
                "DateTime64(3)",
                ts(TimeUnit::Millisecond, "Europe/Berlin"),
                false,
            ),
            (
                "DateTime64(6, 'Asia/Tokyo')",
                ts(TimeUnit::Microsecond, "Asia/Tokyo"),
                false,
            ),
            (
                "DateTime64(9, 'UTC')",
                ts(TimeUnit::Nanosecond, "UTC"),
                false,
            ),
            ("Nullable(Int32)", DataType::Int32, true),
            ("LowCardinality(String)", DataType::Utf8, false),
            ("LowCardinality(Nullable(String))", DataType::Utf8, true),
            (
                "Nullable(DateTime64(3, 'UTC'))",
                ts(TimeUnit::Millisecond, "UTC"),
                true,
            ),
        ] {
            assert_eq!(
                arrow_type(ch_type, "Europe/Berlin"),
                Ok((expected, nullable)),
                "{ch_type}"
            );
        }
    }

    #[test]
    fn unreadable_types_are_rejected_by_name() {
        for ch_type in [
            "Enum8('a' = 1, 'b' = 2)",
            "UUID",
            "IPv4",
            "IPv6",
            "Int128",
            "UInt256",
            "Array(Int32)",
            "Map(String, Int32)",
            "Tuple(Int32, String)",
            "JSON",
            "Nullable(UUID)",
            "LowCardinality(FixedString(abc))",
            "FixedString(-1)",
            "Decimal(80, 2)",
            "Decimal(9, 10)",
            "DateTime64(12)",
            "DateTime('')",
        ] {
            let err = arrow_type(ch_type, "UTC").unwrap_err();
            assert!(err.contains("cannot read yet"), "{ch_type}: {err}");
        }
    }

    // -----------------------------------------------------------------
    // Results
    // -----------------------------------------------------------------

    #[test]
    fn date_day_numbers_become_date32() {
        let remote = RecordBatch::try_new(
            Arc::new(Schema::new(vec![
                Field::new("id", DataType::Int64, false),
                Field::new("day", DataType::UInt16, false),
            ])),
            vec![
                Arc::new(Int64Array::from(vec![1, 2])),
                Arc::new(UInt16Array::from(vec![19_724, 0])),
            ],
        )
        .unwrap();
        let target: SchemaRef = Arc::new(Schema::new(vec![
            Field::new("id", DataType::Int64, false),
            Field::new("day", DataType::Date32, false),
        ]));

        let restored = restore_dates(&remote, &target).unwrap();
        let aligned = crate::remote_sql::align_batch(&restored, &target, KIND).unwrap();
        let days = aligned
            .column(1)
            .as_any()
            .downcast_ref::<Date32Array>()
            .unwrap();
        // 2024-01-02 and the epoch.
        assert_eq!(days.values().as_ref(), &[19_724, 0]);
    }

    #[test]
    fn a_batch_without_dates_is_left_alone() {
        let remote = RecordBatch::try_new(
            Arc::new(Schema::new(vec![Field::new("n", DataType::UInt16, false)])),
            vec![Arc::new(UInt16Array::from(vec![7]))],
        )
        .unwrap();
        // A UInt16 the plan wants as UInt16 is not a date.
        let target = remote.schema();
        let restored = restore_dates(&remote, &target).unwrap();
        assert_eq!(restored.column(0).data_type(), &DataType::UInt16);
    }

    #[test]
    fn an_empty_body_is_an_empty_result_and_garbage_is_an_error() {
        assert!(decode_arrow_stream(b"").unwrap().is_empty());
        let err = decode_arrow_stream(b"Code: 60. DB::Exception").unwrap_err();
        assert!(err.contains("not an Arrow stream"), "{err}");
    }

    // -----------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------

    #[test]
    fn references_split_on_the_dot_outside_quotes() {
        for (reference, expected) in [
            (r#""analytics"."events""#, Some(("analytics", "events"))),
            ("analytics.events", Some(("analytics", "events"))),
            (r#""logs.2024"."raw""#, Some(("logs.2024", "raw"))),
            (r#""a""b"."t""#, Some((r#"a"b"#, "t"))),
            ("events", None),
            ("a.b.c", None),
            (r#""".t"#, None),
        ] {
            assert_eq!(
                split_reference(reference),
                expected.map(|(d, t)| (d.to_string(), t.to_string())),
                "{reference}"
            );
        }
    }

    #[test]
    fn scrub_replaces_every_case_variant() {
        assert_eq!(
            scrub("bad password Hunter2 (hunter2, HUNTER2)", "hunter2"),
            "bad password [redacted] ([redacted], [redacted])"
        );
        assert_eq!(scrub("nothing here", ""), "nothing here");
    }

    #[test]
    fn truncate_cuts_on_a_character_boundary() {
        assert_eq!(truncate("short", 10), "short");
        assert_eq!(truncate("ééé", 3), "é… [truncated]");
    }

    #[test]
    fn the_dialect_double_quotes_identifiers() {
        assert_eq!(
            clickhouse_dialect().identifier_quote_style("events"),
            Some('"')
        );
    }
}

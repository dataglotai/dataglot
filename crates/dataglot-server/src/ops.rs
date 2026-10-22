//! `dataglot ops`: read-only views of a running server.
//!
//! The commands read the HTTP API the dashboard uses, served on the server's
//! metrics address (`127.0.0.1:9090` unless configured otherwise). Each one is
//! a single GET. `--format json` prints the response body exactly as the
//! server sent it, so scripts get every field; table and CSV show the columns
//! worth reading at a glance.
//!
//! Exit codes match client mode: 0 when the server answered, 1 when it
//! answered with an error (an endpoint this server doesn't have, say), 2 when
//! there was no usable answer at all.

use std::io::Write;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use datafusion::arrow::array::{ArrayRef, RecordBatch, StringArray};
use datafusion::arrow::datatypes::{DataType, Field, Schema};
use datafusion::arrow::error::ArrowError;
use serde_json::Value;

use crate::cli::{OpsArgs, OpsCommand, OutputFormat, QueriesCommand};

/// How long one request may take, connecting included.
const TIMEOUT: Duration = Duration::from_secs(10);

/// A `sql` cell longer than this is cut short in table output. CSV and JSON
/// keep it whole.
const SQL_IN_TABLE: usize = 60;

/// What can go wrong talking to the API.
#[derive(Debug, thiserror::Error)]
pub enum OpsError {
    /// `--api` isn't an http(s) URL.
    #[error("invalid --api value {0:?}: expected an http:// or https:// URL")]
    InvalidUrl(String),
    /// Nothing answered, or the connection broke off.
    #[error("could not reach {url}: {message}")]
    Unreachable {
        /// The API's origin, without any credentials.
        url: String,
        /// Why.
        message: String,
    },
    /// The server answered with an error status.
    #[error("{url} answered {status}: {message}")]
    Server {
        /// The full request URL, without credentials.
        url: String,
        /// HTTP status, e.g. `404 Not Found`.
        status: String,
        /// The server's own error message, or a hint.
        message: String,
    },
    /// Something answered, but not with JSON, so probably not a Dataglot API.
    #[error("{url} didn't answer with JSON ({message}); is --api the server's metrics address?")]
    NotJson {
        /// The full request URL, without credentials.
        url: String,
        /// The parse error.
        message: String,
    },
    /// Writing to stdout failed.
    #[error("writing output: {0}")]
    Output(String),
}

impl OpsError {
    /// Process exit code: 2 without a usable answer, 1 for an error the
    /// server reported or a failed write.
    #[must_use]
    pub fn exit_code(&self) -> ExitCode {
        match self {
            Self::InvalidUrl(_) | Self::Unreachable { .. } | Self::NotJson { .. } => {
                ExitCode::from(2)
            }
            Self::Server { .. } | Self::Output(_) => ExitCode::FAILURE,
        }
    }
}

impl From<std::io::Error> for OpsError {
    fn from(e: std::io::Error) -> Self {
        Self::Output(e.to_string())
    }
}

impl From<ArrowError> for OpsError {
    fn from(e: ArrowError) -> Self {
        Self::Output(e.to_string())
    }
}

/// `dataglot ops ...`: run the command, print the result to stdout and any
/// error to stderr, and return the exit code.
pub async fn run(args: &OpsArgs) -> ExitCode {
    run_with(args, &mut std::io::stdout(), &mut std::io::stderr()).await
}

/// [`run`] with the output streams passed in, for tests.
pub async fn run_with<O: Write, E: Write>(args: &OpsArgs, out: &mut O, err: &mut E) -> ExitCode {
    match execute(args, out).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            let _ = writeln!(err, "error: {e}");
            e.exit_code()
        }
    }
}

async fn execute<O: Write>(args: &OpsArgs, out: &mut O) -> Result<(), OpsError> {
    let api = Api::new(&args.api)?;
    let (path, table): (&str, fn(&Value) -> Rows) = match &args.command {
        OpsCommand::Status => ("api/server", status_rows),
        OpsCommand::Sources => ("api/connectors", source_rows),
        OpsCommand::Sessions => ("api/sessions", session_rows),
        OpsCommand::Queries(q) => match q.command.unwrap_or(QueriesCommand::List) {
            QueriesCommand::List => ("api/queries", running_rows),
            QueriesCommand::History => ("api/queries/history", history_rows),
        },
        OpsCommand::ControlPlane => ("api/control-plane", control_plane_rows),
    };
    let (body, value) = api.get(path).await.map_err(|e| match e {
        // The route only exists when the server has a meta store.
        OpsError::Server { url, status, .. }
            if path == "api/control-plane" && status.starts_with("404") =>
        {
            OpsError::Server {
                url,
                status,
                message: "this server has no control plane (it runs without [catalog_service])"
                    .to_string(),
            }
        }
        e => e,
    })?;
    if matches!(args.format, OutputFormat::Json) {
        out.write_all(&body)?;
        writeln!(out)?;
    } else {
        table(&value).write(args.format, out)?;
    }
    out.flush()?;
    Ok(())
}

/// The server's HTTP API.
struct Api {
    base: reqwest::Url,
    http: reqwest::Client,
}

impl Api {
    fn new(base: &str) -> Result<Self, OpsError> {
        let mut url =
            reqwest::Url::parse(base).map_err(|_| OpsError::InvalidUrl(base.to_string()))?;
        if !matches!(url.scheme(), "http" | "https") || url.host().is_none() {
            return Err(OpsError::InvalidUrl(base.to_string()));
        }
        // Without a trailing slash, `join` would replace the last path segment
        // of an API behind a prefix (`http://proxy/dataglot`).
        if !url.path().ends_with('/') {
            let path = format!("{}/", url.path());
            url.set_path(&path);
        }
        let http = reqwest::Client::builder()
            .timeout(TIMEOUT)
            .build()
            .map_err(|e| OpsError::Unreachable {
                url: origin(&url),
                message: e.to_string(),
            })?;
        Ok(Self { base: url, http })
    }

    /// GET `path`: the body as sent, and parsed.
    async fn get(&self, path: &str) -> Result<(Vec<u8>, Value), OpsError> {
        let url = self
            .base
            .join(path)
            .map_err(|_| OpsError::InvalidUrl(self.base.to_string()))?;
        let unreachable = |e: &reqwest::Error| OpsError::Unreachable {
            url: origin(&self.base),
            message: describe(e),
        };
        let response = self
            .http
            .get(url.clone())
            .send()
            .await
            .map_err(|e| unreachable(&e))?;
        let status = response.status();
        let body = response.bytes().await.map_err(|e| unreachable(&e))?;
        if !status.is_success() {
            return Err(OpsError::Server {
                url: without_credentials(&url),
                status: status.to_string(),
                message: server_message(&body),
            });
        }
        let value = serde_json::from_slice(&body).map_err(|e| OpsError::NotJson {
            url: without_credentials(&url),
            message: e.to_string(),
        })?;
        Ok((body.to_vec(), value))
    }
}

/// `scheme://host:port`, for messages. Never contains a password.
fn origin(url: &reqwest::Url) -> String {
    url.origin().ascii_serialization()
}

fn without_credentials(url: &reqwest::Url) -> String {
    let mut url = url.clone();
    let _ = url.set_username("");
    let _ = url.set_password(None);
    url.to_string()
}

/// The innermost cause of a reqwest error. Its own message is a generic
/// "error sending request for url (...)".
fn describe(e: &reqwest::Error) -> String {
    if e.is_timeout() {
        return format!("no answer within {}s", TIMEOUT.as_secs());
    }
    let mut cause: &dyn std::error::Error = e;
    while let Some(next) = cause.source() {
        cause = next;
    }
    cause.to_string()
}

/// The `error` field of a JSON error body, or the body itself if it's short
/// text, or nothing.
fn server_message(body: &[u8]) -> String {
    if let Ok(Value::Object(map)) = serde_json::from_slice::<Value>(body) {
        if let Some(Value::String(message)) = map.get("error") {
            return message.clone();
        }
    }
    let text = String::from_utf8_lossy(body);
    let text = text.trim();
    if text.is_empty() || text.len() > 200 {
        "no details".to_string()
    } else {
        text.to_string()
    }
}

/// Rows for table or CSV output, every cell already text.
struct Rows {
    columns: &'static [&'static str],
    rows: Vec<Vec<String>>,
}

impl Rows {
    fn write<W: Write>(self, format: OutputFormat, out: &mut W) -> Result<(), OpsError> {
        let fields: Vec<Field> = self
            .columns
            .iter()
            .map(|name| Field::new(*name, DataType::Utf8, false))
            .collect();
        let table = matches!(format, OutputFormat::Table);
        let arrays: Vec<ArrayRef> = (0..self.columns.len())
            .map(|i| {
                let shorten = table && self.columns[i] == "sql";
                let column: StringArray = self
                    .rows
                    .iter()
                    .map(|row| {
                        let value = cell(row, i);
                        Some(if shorten {
                            shortened(value)
                        } else {
                            value.to_string()
                        })
                    })
                    .collect();
                Arc::new(column) as ArrayRef
            })
            .collect();
        let batch = RecordBatch::try_new(Arc::new(Schema::new(fields)), arrays)?;
        match format {
            OutputFormat::Csv => {
                datafusion::arrow::csv::WriterBuilder::new()
                    .with_header(true)
                    .build(&mut *out)
                    .write(&batch)?;
            }
            // JSON never gets here; it prints the response as is.
            OutputFormat::Table | OutputFormat::Json => {
                let table = datafusion::arrow::util::pretty::pretty_format_batches(&[batch])?;
                writeln!(out, "{table}")?;
            }
        }
        Ok(())
    }
}

fn cell(row: &[String], i: usize) -> &str {
    row.get(i).map_or("", String::as_str)
}

/// A JSON value as one cell: strings without quotes, lists comma-separated,
/// `null` empty.
fn text(value: &Value) -> String {
    match value {
        Value::Null => String::new(),
        Value::String(s) => s.clone(),
        Value::Array(items) => items.iter().map(text).collect::<Vec<_>>().join(", "),
        other => other.to_string(),
    }
}

fn field(value: &Value, key: &str) -> String {
    text(value.get(key).unwrap_or(&Value::Null))
}

fn items<'a>(value: &'a Value, key: Option<&str>) -> &'a [Value] {
    let list = match key {
        Some(key) => value.get(key),
        None => Some(value),
    };
    list.and_then(Value::as_array).map_or(&[], Vec::as_slice)
}

/// `status`: every setting `/api/server` reports, one per row, sorted by
/// name, nested ones as `security.auth_mode` and so on.
fn status_rows(value: &Value) -> Rows {
    let mut rows = Vec::new();
    flatten("", value, &mut rows);
    Rows {
        columns: &["setting", "value"],
        rows,
    }
}

fn flatten(prefix: &str, value: &Value, rows: &mut Vec<Vec<String>>) {
    match value {
        Value::Object(map) => {
            for (key, inner) in map {
                let name = if prefix.is_empty() {
                    key.clone()
                } else {
                    format!("{prefix}.{key}")
                };
                flatten(&name, inner, rows);
            }
        }
        other => rows.push(vec![prefix.to_string(), text(other)]),
    }
}

/// `sources`: the configured catalogs. The families that could still be set up
/// are only in the JSON.
fn source_rows(value: &Value) -> Rows {
    let rows = items(value, Some("configured"))
        .iter()
        .map(|source| {
            let health = source.get("health");
            let live = match health.and_then(|h| h.get("live")).and_then(Value::as_bool) {
                Some(live) => live.to_string(),
                None => "unknown".to_string(),
            };
            let latency = health
                .and_then(|h| h.get("latency_ms"))
                .map(text)
                .unwrap_or_default();
            vec![
                field(source, "name"),
                field(source, "kind"),
                field(source, "registered"),
                live,
                latency,
                health.map(|h| field(h, "error")).unwrap_or_default(),
            ]
        })
        .collect();
    Rows {
        columns: &["name", "kind", "registered", "live", "latency_ms", "error"],
        rows,
    }
}

/// `sessions`: who is connected over pg-wire, longest-connected first.
fn session_rows(value: &Value) -> Rows {
    let now = now_ms();
    let rows = items(value, None)
        .iter()
        .map(|session| {
            let connected = session
                .get("connected_at_ms")
                .and_then(Value::as_u64)
                .map(|at| duration(now.saturating_sub(at)))
                .unwrap_or_default();
            vec![
                field(session, "session_id"),
                field(session, "user"),
                field(session, "org"),
                field(session, "peer"),
                connected,
            ]
        })
        .collect();
    Rows {
        columns: &["session_id", "user", "org", "peer", "connected_for"],
        rows,
    }
}

/// `queries`: what's running, longest-running first.
fn running_rows(value: &Value) -> Rows {
    let rows = items(value, None)
        .iter()
        .map(|query| {
            vec![
                field(query, "run_id"),
                field(query, "state"),
                elapsed(query),
                field(query, "user"),
                field(query, "sources"),
                one_line(&field(query, "sql")),
            ]
        })
        .collect();
    Rows {
        columns: &["run_id", "state", "elapsed", "user", "sources", "sql"],
        rows,
    }
}

/// `queries history`: recently finished queries, newest first.
fn history_rows(value: &Value) -> Rows {
    let rows = items(value, None)
        .iter()
        .map(|query| {
            vec![
                field(query, "run_id"),
                field(query, "outcome"),
                elapsed(query),
                field(query, "user"),
                field(query, "sources"),
                one_line(&field(query, "sql")),
                field(query, "error"),
            ]
        })
        .collect();
    Rows {
        columns: &[
            "run_id", "outcome", "elapsed", "user", "sources", "sql", "error",
        ],
        rows,
    }
}

/// `control-plane`: every stored object, one per row.
fn control_plane_rows(value: &Value) -> Rows {
    let mut rows = vec![vec!["org".to_string(), field(value, "org"), String::new()]];
    let mut add = |kind: &str, name: String, detail: String| {
        rows.push(vec![kind.to_string(), name, detail]);
    };
    for c in items(value, Some("catalogs")) {
        let detail = [field(c, "kind"), field(c, "endpoint")]
            .into_iter()
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join(" ");
        add("catalog", field(c, "name"), detail);
    }
    for s in items(value, Some("secrets")) {
        add("secret", text(s), String::new());
    }
    for u in items(value, Some("users")) {
        let detail = if u.get("is_superuser").and_then(Value::as_bool) == Some(true) {
            "superuser".to_string()
        } else {
            String::new()
        };
        add("user", field(u, "name"), detail);
    }
    for r in items(value, Some("roles")) {
        let members = field(r, "members");
        let detail = if members.is_empty() {
            String::new()
        } else {
            format!("members: {members}")
        };
        add("role", field(r, "name"), detail);
    }
    for g in items(value, Some("grants")) {
        add(
            "grant",
            format!("{} {}", field(g, "grantee_kind"), field(g, "grantee")),
            format!("{} on {}", field(g, "privilege"), field(g, "object")),
        );
    }
    for p in items(value, Some("policies")) {
        add("policy", field(p, "name"), field(p, "kind"));
    }
    for d in items(value, Some("derived_products")) {
        let target = [field(d, "catalog"), field(d, "schema")]
            .into_iter()
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join(".");
        add("derived_product", field(d, "name"), target);
    }
    Rows {
        columns: &["type", "name", "detail"],
        rows,
    }
}

fn elapsed(query: &Value) -> String {
    query
        .get("elapsed_ms")
        .and_then(Value::as_u64)
        .map(duration)
        .unwrap_or_default()
}

/// SQL on one line, so a multi-line statement doesn't break a table or a
/// CSV row.
fn one_line(sql: &str) -> String {
    sql.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn shortened(text: &str) -> String {
    if text.chars().count() > SQL_IN_TABLE {
        let cut: String = text.chars().take(SQL_IN_TABLE - 1).collect();
        format!("{cut}…")
    } else {
        text.to_string()
    }
}

/// `850ms`, `12.3s`, `4m 05s`, `2h 10m`.
fn duration(ms: u64) -> String {
    match ms {
        0..1_000 => format!("{ms}ms"),
        1_000..60_000 => format!("{}.{}s", ms / 1_000, ms % 1_000 / 100),
        60_000..3_600_000 => format!("{}m {:02}s", ms / 60_000, ms % 60_000 / 1_000),
        _ => format!("{}h {:02}m", ms / 3_600_000, ms % 3_600_000 / 60_000),
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn render(rows: Rows, format: OutputFormat) -> String {
        let mut out = Vec::new();
        rows.write(format, &mut out).expect("write");
        String::from_utf8(out).expect("utf-8")
    }

    #[test]
    fn status_flattens_nested_settings() {
        let rows = status_rows(&json!({
            "dataglot_version": "0.5.2",
            "pgwire_port": 5432,
            "security": {"auth_mode": "md5", "rate_limiting": false},
            "build": {"features": ["dashboard", "flight_sql"]},
            "limits": {"max_connections": null},
        }));
        let csv = render(rows, OutputFormat::Csv);
        assert_eq!(
            csv,
            "setting,value\n\
             build.features,\"dashboard, flight_sql\"\n\
             dataglot_version,0.5.2\n\
             limits.max_connections,\n\
             pgwire_port,5432\n\
             security.auth_mode,md5\n\
             security.rate_limiting,false\n"
        );
    }

    #[test]
    fn sources_show_health_or_unknown() {
        let rows = source_rows(&json!({
            "configured": [
                {"name": "pg", "kind": "postgres", "registered": true,
                 "health": {"live": true, "latency_ms": 4, "checked_at_ms": 1}},
                {"name": "files", "kind": "object_storage", "registered": false},
                {"name": "down", "kind": "mysql", "registered": true,
                 "health": {"live": false, "latency_ms": 2000, "checked_at_ms": 1,
                            "error": "connection refused"}},
            ],
            "available": [{"name": "OData", "feature": "odata", "note": ""}],
        }));
        assert_eq!(
            render(rows, OutputFormat::Csv),
            "name,kind,registered,live,latency_ms,error\n\
             pg,postgres,true,true,4,\n\
             files,object_storage,false,unknown,,\n\
             down,mysql,true,false,2000,connection refused\n"
        );
    }

    #[test]
    fn queries_put_sql_on_one_line_and_shorten_it_only_in_tables() {
        let long = format!("SELECT\n  {}\nFROM t", "x, ".repeat(40));
        let running = json!([
            {"run_id": "r1", "sql": long, "elapsed_ms": 1_500, "state": "running",
             "sources": ["pg", "files"], "user": "alice", "org": null, "pushdowns": []},
        ]);
        let rows = running_rows(&running);
        let sql = &rows.rows[0][5];
        assert!(!sql.contains('\n'), "{sql}");
        assert!(
            sql.starts_with("SELECT x, x,") && sql.ends_with("x, FROM t"),
            "{sql}"
        );
        assert_eq!(rows.rows[0][2], "1.5s");
        assert_eq!(rows.rows[0][4], "pg, files");

        let csv = render(running_rows(&running), OutputFormat::Csv);
        assert!(
            csv.contains(sql.as_str()),
            "CSV keeps the whole statement: {csv}"
        );
        let table = render(running_rows(&running), OutputFormat::Table);
        let cut: String = sql.chars().take(SQL_IN_TABLE - 1).collect();
        assert!(table.contains(&format!("{cut}…")), "{table}");
        assert!(!table.contains("FROM t"), "{table}");
    }

    #[test]
    fn history_shows_the_error() {
        let rows = history_rows(&json!([
            {"run_id": "r2", "sql": "SELECT nope", "elapsed_ms": 3, "outcome": "failed",
             "error": "table not found", "sources": [], "user": null, "org": null,
             "pushdowns": []},
        ]));
        assert_eq!(
            rows.rows,
            [[
                "r2",
                "failed",
                "3ms",
                "",
                "",
                "SELECT nope",
                "table not found"
            ]]
        );
    }

    #[test]
    fn control_plane_lists_every_object() {
        let rows = control_plane_rows(&json!({
            "org": "default",
            "catalogs": [{"name": "files", "kind": "object_storage", "endpoint": "file:///data"}],
            "secrets": ["pg_password"],
            "users": [{"name": "admin", "is_superuser": true}, {"name": "bob", "is_superuser": false}],
            "roles": [{"name": "analysts", "members": ["bob"]}],
            "grants": [{"grantee_kind": "role", "grantee": "analysts", "privilege": "SELECT",
                        "object": "files.public.users"}],
            "policies": [{"name": "email_mask", "kind": "mask"}],
            "derived_products": [{"name": "v", "catalog": "dataglot", "schema": null}],
        }));
        assert_eq!(
            rows.rows,
            [
                ["org", "default", ""],
                ["catalog", "files", "object_storage file:///data"],
                ["secret", "pg_password", ""],
                ["user", "admin", "superuser"],
                ["user", "bob", ""],
                ["role", "analysts", "members: bob"],
                ["grant", "role analysts", "SELECT on files.public.users"],
                ["policy", "email_mask", "mask"],
                ["derived_product", "v", "dataglot"],
            ]
        );
    }

    #[test]
    fn an_empty_list_still_prints_the_header() {
        let table = render(session_rows(&json!([])), OutputFormat::Table);
        assert!(
            table.contains("| session_id | user | org | peer | connected_for |"),
            "{table}"
        );
    }

    #[test]
    fn durations_read_naturally() {
        assert_eq!(duration(850), "850ms");
        assert_eq!(duration(12_345), "12.3s");
        assert_eq!(duration(245_000), "4m 05s");
        assert_eq!(duration(7_800_000), "2h 10m");
    }

    #[test]
    fn api_urls_must_be_http() {
        for bad in [
            "localhost:9090",
            "127.0.0.1:9090",
            "ftp://h",
            "http://",
            "not a url",
        ] {
            assert!(
                matches!(Api::new(bad), Err(OpsError::InvalidUrl(_))),
                "{bad} should be rejected"
            );
        }
        let api = Api::new("http://h:9090/dataglot").expect("valid");
        assert_eq!(
            api.base.join("api/server").expect("join").as_str(),
            "http://h:9090/dataglot/api/server"
        );
    }

    #[test]
    fn messages_never_show_credentials() {
        let url = reqwest::Url::parse("http://ops:s3cret@h:9090/api/server").expect("url");
        assert_eq!(origin(&url), "http://h:9090");
        assert_eq!(without_credentials(&url), "http://h:9090/api/server");
    }

    #[test]
    fn server_errors_use_the_json_error_field() {
        assert_eq!(
            server_message(br#"{"error":"meta store down"}"#),
            "meta store down"
        );
        assert_eq!(server_message(b"Not Found"), "Not Found");
        assert_eq!(server_message(b""), "no details");
    }

    #[test]
    fn exit_codes_follow_client_mode() {
        let unreachable = OpsError::Unreachable {
            url: String::new(),
            message: String::new(),
        };
        assert_eq!(unreachable.exit_code(), ExitCode::from(2));
        assert_eq!(
            OpsError::InvalidUrl(String::new()).exit_code(),
            ExitCode::from(2)
        );
        let server = OpsError::Server {
            url: String::new(),
            status: String::new(),
            message: String::new(),
        };
        assert_eq!(server.exit_code(), ExitCode::FAILURE);
    }
}

//! Client mode for `dataglot query` and `dataglot shell`.
//!
//! With `--server`, nothing is planned in-process. Statements go to a running
//! Dataglot server over the Postgres wire protocol and the server handles all
//! of it: governance, control-plane DDL, catalogs created at runtime. The CLI
//! only prints what comes back.
//!
//! Statements are sent with the simple query protocol, which is what psql uses
//! for typed-in SQL, so `;`-separated statements in one call work and the
//! server sees exactly the text the user wrote. The trade-off is that the
//! simple protocol returns every value as text without type information, so
//! result columns are strings here. Tables and CSV look the same as in
//! embedded mode; JSON values come out quoted.
//!
//! The connection string follows libpq: `sslmode` and `sslrootcert` work as in psql,
//! and `PGHOST`, `PGPORT`, `PGUSER`, `PGPASSWORD`, `PGDATABASE`, `PGSSLMODE` and `PGSSLROOTCERT`
//! fill in whatever `--server` leaves out.
//!
//! Instead of `--server`, `--profile <name>` picks a named connection from a
//! profiles file (see [`Endpoint::from_profile`]).

mod profile;
mod settings;

pub use profile::OpsTarget;

use std::io::{BufWriter, Write};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use datafusion::arrow::array::{ArrayRef, RecordBatch, RecordBatchOptions, StringBuilder};
use datafusion::arrow::datatypes::{DataType, Field, Schema, SchemaRef};
use datafusion::arrow::error::ArrowError;
use dataglot_federation::pg_tls::PgTls;
use futures::StreamExt;
use tokio_postgres::config::Host;
use tokio_postgres::tls::MakeTlsConnect;
use tokio_postgres::{Config, NoTls, SimpleColumn, SimpleQueryMessage, SimpleQueryRow, Socket};

use crate::cli::OutputFormat;
use crate::interrupt::{CtrlC, INTERRUPTED};

/// Rows per Arrow batch while a result streams in.
const ROWS_PER_BATCH: usize = 1024;

/// What can go wrong in client mode. The variant decides the exit code and
/// whether the shell can keep going.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// `--server` or a `PG*` variable has a value that can't be used.
    #[error("invalid --server value: {0}")]
    InvalidServer(String),
    /// The server couldn't be reached, or refused the connection.
    #[error("could not connect to {target}: {message}")]
    Connect {
        /// `host:port` of the server.
        target: String,
        /// Why.
        message: String,
    },
    /// The server rejected the statement. The connection is still usable.
    #[error("{0}")]
    Statement(String),
    /// The connection went away mid-session.
    #[error("lost the connection to {target}: {message}")]
    ConnectionLost {
        /// `host:port` of the server.
        target: String,
        /// Why.
        message: String,
    },
    /// The result couldn't be written to stdout.
    #[error("writing output: {0}")]
    Output(String),
    /// `--profile` couldn't be resolved: no profiles file, no such profile,
    /// or a profile that can't be used as written.
    #[error("{0}")]
    Profile(String),
    /// Ctrl-C stopped the statement. A cancel request went to the server.
    #[error("query cancelled")]
    Cancelled,
}

impl ClientError {
    /// Process exit code, following psql: 2 when there is no usable
    /// connection, 1 when a statement or the output failed.
    #[must_use]
    pub fn exit_code(&self) -> ExitCode {
        match self {
            Self::InvalidServer(_)
            | Self::Connect { .. }
            | Self::ConnectionLost { .. }
            | Self::Profile(_) => ExitCode::from(2),
            Self::Statement(_) | Self::Output(_) => ExitCode::FAILURE,
            Self::Cancelled => ExitCode::from(INTERRUPTED),
        }
    }

    /// Whether every later statement would fail too, so the shell should stop
    /// instead of printing the same error at each prompt.
    #[must_use]
    pub fn is_fatal(&self) -> bool {
        matches!(self, Self::ConnectionLost { .. })
    }
}

impl From<ArrowError> for ClientError {
    fn from(e: ArrowError) -> Self {
        Self::Output(e.to_string())
    }
}

impl From<std::io::Error> for ClientError {
    fn from(e: std::io::Error) -> Self {
        Self::Output(e.to_string())
    }
}

/// Where client mode connects: a `--server` value as given, or the one a
/// profile resolved to, together with the profile's password.
///
/// No `Debug`, so the password can't end up in a log line by accident.
pub struct Endpoint {
    server: String,
    password: Option<String>,
}

impl Endpoint {
    /// Look up profile `name` in the profiles file: `DATAGLOT_CLI_CONFIG`
    /// if set, otherwise `%APPDATA%\dataglot\cli.toml` on Windows and
    /// `$XDG_CONFIG_HOME/dataglot/cli.toml` (or `~/.config/dataglot/cli.toml`)
    /// elsewhere.
    ///
    /// # Errors
    /// [`ClientError::Profile`] if the file is missing or invalid, the
    /// profile doesn't exist, its url carries a password, or the variable
    /// its `password_env` names isn't set.
    pub fn from_profile(name: &str) -> Result<Self, ClientError> {
        profile::load(name)
    }

    /// Like [`Self::from_profile`], with the profiles file at `path`.
    ///
    /// # Errors
    /// As for [`Self::from_profile`].
    pub fn from_profile_file(path: &std::path::Path, name: &str) -> Result<Self, ClientError> {
        profile::load_from(path, name, &|key| std::env::var(key).ok())
    }

    /// The endpoint `--server` / `--profile` ask for, or `None` for
    /// embedded mode. clap already keeps the two flags apart.
    ///
    /// # Errors
    /// As for [`Self::from_profile`].
    pub fn from_args(
        server: Option<&str>,
        profile: Option<&str>,
    ) -> Result<Option<Self>, ClientError> {
        match (server, profile) {
            (Some(server), _) => Ok(Some(server.into())),
            (None, Some(name)) => Self::from_profile(name).map(Some),
            (None, None) => Ok(None),
        }
    }
}

impl From<&str> for Endpoint {
    fn from(server: &str) -> Self {
        Self {
            server: server.to_string(),
            password: None,
        }
    }
}

impl From<String> for Endpoint {
    fn from(server: String) -> Self {
        Self {
            server,
            password: None,
        }
    }
}

/// A connection to a running Dataglot server
pub struct RemoteSession {
    client: tokio_postgres::Client,
    target: String,
    /// Kept for cancel requests, which open a connection of their own.
    tls: Option<PgTls>,
}

impl RemoteSession {
    /// Connect to `server`, a `postgres://` URL or a libpq-style
    /// `key=value` string. Anything it leaves out comes from the `PG*`
    /// environment variables, then from the defaults: user `dataglot`, host
    /// `localhost`, `sslmode=prefer`. Without a database the server picks
    /// its default catalog.
    ///
    /// # Errors
    /// [`ClientError::InvalidServer`] if `server` or a `PG*` variable can't
    /// be used, [`ClientError::Connect`] if the TLS setup, the connection or
    /// the login fails.
    pub async fn connect(server: &str) -> Result<Self, ClientError> {
        Self::connect_to(&server.into()).await
    }

    /// Connect to `endpoint`. A profile's password takes precedence over
    /// `PGPASSWORD`.
    ///
    /// # Errors
    /// As for [`Self::connect`].
    pub async fn connect_to(endpoint: &Endpoint) -> Result<Self, ClientError> {
        let password = endpoint.password.clone();
        // The profile's password stands in for `PGPASSWORD`, so it wins
        // over the environment variable.
        let env = move |key: &str| match (key, &password) {
            ("PGPASSWORD", Some(password)) => Some(password.clone()),
            _ => std::env::var(key).ok(),
        };
        let settings =
            settings::resolve(&endpoint.server, &env).map_err(ClientError::InvalidServer)?;
        let target = target(&settings.config);
        let tls = settings.tls();
        let opened = match tls.clone() {
            None => open(&settings.config, NoTls).await,
            Some(tls) => {
                // Loading the trust store or CA file is blocking file I/O.
                match tokio::task::spawn_blocking(move || tls.make_connector()).await {
                    Ok(Ok(connector)) => open(&settings.config, connector).await,
                    Ok(Err(e)) => Err(e.to_string()),
                    Err(e) => Err(format!("TLS setup failed: {e}")),
                }
            }
        };
        match opened {
            Ok(client) => Ok(Self {
                client,
                target,
                tls,
            }),
            Err(message) => Err(ClientError::Connect { target, message }),
        }
    }

    /// `host:port` of the server, for messages.
    #[must_use]
    pub fn target(&self) -> &str {
        &self.target
    }

    /// Run `sql` and write each result set to `out`. Statements that return
    /// no rows (DDL, `SET`, ...) print nothing.
    ///
    /// CSV and JSON stream a batch at a time; a table is printed once its
    /// result set is complete, since the column widths depend on every row.
    ///
    /// # Errors
    /// [`ClientError::Statement`] if the server rejects a statement (output
    /// of earlier statements in `sql` has been written by then) or `sql` is a
    /// `COPY ... TO STDOUT`,
    /// [`ClientError::ConnectionLost`] if the connection drops,
    /// [`ClientError::Output`] if writing fails.
    pub async fn execute<W: Write>(
        &self,
        sql: &str,
        format: OutputFormat,
        out: &mut W,
    ) -> Result<(), ClientError> {
        // The server does answer COPY TO STDOUT, but over the simple protocol
        // tokio-postgres only reports "unexpected message from server".
        if dataglot_pgwire::copy::detect_copy_to_stdout(sql).is_some() {
            return Err(ClientError::Statement(
                "`COPY ... TO STDOUT` isn't supported with --server yet; run the query itself \
                 with `--format csv` for CSV output"
                    .to_string(),
            ));
        }
        let stream = self
            .client
            .simple_query_raw(sql)
            .await
            .map_err(|e| self.classify(&e))?;

        let mut stream = std::pin::pin!(stream);
        let mut out = BufWriter::new(out);
        let mut current: Option<ResultSet> = None;

        while let Some(message) = stream.next().await {
            match message.map_err(|e| self.classify(&e))? {
                SimpleQueryMessage::RowDescription(columns) => {
                    current = Some(ResultSet::new(&columns, format));
                }
                SimpleQueryMessage::Row(row) => {
                    current
                        .get_or_insert_with(|| ResultSet::new(row.columns(), format))
                        .push(&row, &mut out)?;
                }
                SimpleQueryMessage::CommandComplete(_) => {
                    if let Some(set) = current.take() {
                        set.finish(&mut out)?;
                    }
                }
                _ => {}
            }
        }
        out.flush()?;
        Ok(())
    }

    /// Like [`Self::execute`], but Ctrl-C stops it: the server gets a cancel
    /// request and this returns [`ClientError::Cancelled`] without waiting for
    /// the server to confirm. The session stays usable.
    ///
    /// # Errors
    /// As for [`Self::execute`], plus [`ClientError::Cancelled`].
    pub async fn execute_until<W: Write>(
        &self,
        sql: &str,
        format: OutputFormat,
        out: &mut W,
        ctrl_c: &CtrlC,
    ) -> Result<(), ClientError> {
        let seen = ctrl_c.count();
        tokio::select! {
            result = self.execute(sql, format, out) => result,
            () = ctrl_c.after(seen) => {
                // A second Ctrl-C stops waiting for the cancel request to go out.
                tokio::select! {
                    () = self.cancel() => {}
                    () = ctrl_c.after(seen + 1) => {}
                }
                Err(ClientError::Cancelled)
            }
        }
    }

    /// Ask the server to stop whatever this session is running. Best effort:
    /// failures are ignored and it gives up after two seconds.
    pub async fn cancel(&self) {
        let token = self.client.cancel_token();
        let tls = self.tls.clone();
        let send = async move {
            match tls {
                None => {
                    let _ = token.cancel_query(NoTls).await;
                }
                Some(tls) => {
                    if let Ok(Ok(connector)) =
                        tokio::task::spawn_blocking(move || tls.make_connector()).await
                    {
                        let _ = token.cancel_query(connector).await;
                    }
                }
            }
        };
        let _ = tokio::time::timeout(Duration::from_secs(2), send).await;
    }

    fn classify(&self, e: &tokio_postgres::Error) -> ClientError {
        // A FATAL from the server (shutdown, terminated backend) closes the
        // connection right after, possibly before `is_closed` notices.
        let fatal = e
            .as_db_error()
            .is_some_and(|db| matches!(db.severity(), "FATAL" | "PANIC"));
        if fatal || e.is_closed() || self.client.is_closed() {
            ClientError::ConnectionLost {
                target: self.target.clone(),
                message: describe(e),
            }
        } else {
            ClientError::Statement(describe(e))
        }
    }
}

/// Open the connection and hand its I/O future to the runtime.
async fn open<T>(config: &Config, tls: T) -> Result<tokio_postgres::Client, String>
where
    T: MakeTlsConnect<Socket>,
    T::Stream: Send + 'static,
{
    let (client, connection) = config.connect(tls).await.map_err(|e| {
        let message = describe(&e);
        if message == "password missing" {
            "the server asked for a password; put it in the URL or set PGPASSWORD".to_string()
        } else {
            message
        }
    })?;
    // The connection future does the socket I/O. Once it ends, calls on
    // `client` fail as closed to show a dead server.
    tokio::spawn(async move {
        let _ = connection.await;
    });
    Ok(client)
}

/// `dataglot query --server`: connect, run `sql`, write the results to `out`
/// and any error to `err`.
///
/// Returns the exit code rather than an error so a failed statement exits 1
/// and a failed connection exits 2.
pub async fn run_query<O: Write, E: Write>(
    endpoint: impl Into<Endpoint>,
    sql: &str,
    format: OutputFormat,
    out: &mut O,
    err: &mut E,
) -> ExitCode {
    run_query_with_ctrl_c(endpoint, sql, format, out, err, &CtrlC::never()).await
}

/// [`run_query`] that stops on Ctrl-C: a statement gets cancelled on the
/// server, and the exit code is 130.
pub async fn run_query_with_ctrl_c<O: Write, E: Write>(
    endpoint: impl Into<Endpoint>,
    sql: &str,
    format: OutputFormat,
    out: &mut O,
    err: &mut E,
    ctrl_c: &CtrlC,
) -> ExitCode {
    let endpoint = endpoint.into();
    let result = tokio::select! {
        connected = RemoteSession::connect_to(&endpoint) => match connected {
            Ok(session) => session.execute_until(sql, format, out, ctrl_c).await,
            Err(e) => Err(e),
        },
        () = ctrl_c.after(0) => Err(ClientError::Cancelled),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(ClientError::Cancelled) => {
            let _ = writeln!(err, "Cancelled.");
            ExitCode::from(INTERRUPTED)
        }
        Err(e) => {
            let _ = writeln!(err, "error: {e}");
            e.exit_code()
        }
    }
}

/// One result set as it streams in.
struct ResultSet {
    format: OutputFormat,
    schema: SchemaRef,
    columns: Vec<StringBuilder>,
    rows: usize,
    /// Finished batches, held back for the table renderer.
    table: Vec<RecordBatch>,
    /// Set once the CSV header has been written.
    header_written: bool,
}

impl ResultSet {
    fn new(columns: &[SimpleColumn], format: OutputFormat) -> Self {
        let fields: Vec<Field> = columns
            .iter()
            .map(|c| Field::new(c.name(), DataType::Utf8, true))
            .collect();
        Self {
            format,
            schema: Arc::new(Schema::new(fields)),
            columns: columns.iter().map(|_| StringBuilder::new()).collect(),
            rows: 0,
            table: Vec::new(),
            header_written: false,
        }
    }

    fn push<W: Write>(&mut self, row: &SimpleQueryRow, out: &mut W) -> Result<(), ClientError> {
        for (i, column) in self.columns.iter_mut().enumerate() {
            column.append_option(row.try_get(i).ok().flatten());
        }
        self.rows += 1;
        if self.rows == ROWS_PER_BATCH {
            let batch = self.take_batch()?;
            self.emit(&batch, out)?;
        }
        Ok(())
    }

    fn finish<W: Write>(mut self, out: &mut W) -> Result<(), ClientError> {
        // An empty result still gets its header in table and CSV output.
        let nothing_written = match self.format {
            OutputFormat::Table => self.table.is_empty(),
            OutputFormat::Csv => !self.header_written,
            OutputFormat::Json => false,
        };
        if self.rows > 0 || nothing_written {
            let batch = self.take_batch()?;
            self.emit(&batch, out)?;
        }
        if matches!(self.format, OutputFormat::Table) {
            let table = datafusion::arrow::util::pretty::pretty_format_batches(&self.table)?;
            writeln!(out, "{table}")?;
        }
        Ok(())
    }

    fn take_batch(&mut self) -> Result<RecordBatch, ClientError> {
        let arrays: Vec<ArrayRef> = self
            .columns
            .iter_mut()
            .map(|c| Arc::new(c.finish()) as ArrayRef)
            .collect();
        // The row count matters for a result with no columns at all.
        let options = RecordBatchOptions::new().with_row_count(Some(self.rows));
        self.rows = 0;
        Ok(RecordBatch::try_new_with_options(
            Arc::clone(&self.schema),
            arrays,
            &options,
        )?)
    }

    fn emit<W: Write>(&mut self, batch: &RecordBatch, out: &mut W) -> Result<(), ClientError> {
        match self.format {
            OutputFormat::Table => self.table.push(batch.clone()),
            OutputFormat::Csv => {
                let mut writer = datafusion::arrow::csv::WriterBuilder::new()
                    .with_header(!self.header_written)
                    .build(&mut *out);
                writer.write(batch)?;
                self.header_written = true;
            }
            OutputFormat::Json => {
                let mut writer = datafusion::arrow::json::LineDelimitedWriter::new(&mut *out);
                writer.write(batch)?;
                writer.finish()?;
            }
        }
        // Flush per batch so `| head` or a slow reader sees rows as they come.
        out.flush()?;
        Ok(())
    }
}

/// `host:port` for messages. Built from the parsed config, not the
/// `--server` text, so a password in the URL never ends up in an error.
fn target(config: &Config) -> String {
    let host = match config.get_hosts().first() {
        Some(Host::Tcp(host)) => host.clone(),
        #[cfg(unix)]
        Some(Host::Unix(dir)) => dir.display().to_string(),
        None => config
            .get_hostaddrs()
            .first()
            .map_or_else(|| "localhost".to_string(), ToString::to_string),
    };
    let port = config.get_ports().first().copied().unwrap_or(5432);
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// The useful part of a tokio-postgres error. Its own `Display` starts with
/// a generic kind ("db error", "error connecting to server") and, for server
/// errors, leaves out DETAIL and HINT.
fn describe(e: &tokio_postgres::Error) -> String {
    if let Some(db) = e.as_db_error() {
        let mut text = db.message().to_string();
        if let Some(detail) = db.detail() {
            text.push_str("\nDETAIL: ");
            text.push_str(detail);
        }
        if let Some(hint) = db.hint() {
            text.push_str("\nHINT: ");
            text.push_str(hint);
        }
        return text;
    }
    match std::error::Error::source(e) {
        Some(cause) => cause.to_string(),
        None => e.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_never_contains_the_password() {
        let config: Config = "postgres://alice:s3cret@db.example.com:6543/files"
            .parse()
            .expect("parse");
        assert_eq!(target(&config), "db.example.com:6543");
    }

    #[test]
    fn target_defaults_the_port_and_brackets_ipv6() {
        let config: Config = "host=localhost".parse().expect("parse");
        assert_eq!(target(&config), "localhost:5432");
        let config: Config = "postgres://[::1]:5433".parse().expect("parse");
        assert_eq!(target(&config), "[::1]:5433");
    }

    #[test]
    fn exit_codes_follow_psql() {
        let no_connection = [
            ClientError::InvalidServer(String::new()),
            ClientError::Connect {
                target: String::new(),
                message: String::new(),
            },
            ClientError::ConnectionLost {
                target: String::new(),
                message: String::new(),
            },
            ClientError::Profile(String::new()),
        ];
        for e in no_connection {
            assert_eq!(e.exit_code(), ExitCode::from(2), "{e:?}");
        }
        assert_eq!(
            ClientError::Statement(String::new()).exit_code(),
            ExitCode::FAILURE
        );
        assert_eq!(
            ClientError::Output(String::new()).exit_code(),
            ExitCode::FAILURE
        );
    }

    #[test]
    fn from_args_picks_server_profile_or_embedded() {
        let endpoint = Endpoint::from_args(Some("postgres://h"), None)
            .expect("server")
            .expect("client mode");
        assert_eq!(endpoint.server, "postgres://h");
        assert!(endpoint.password.is_none());
        assert!(Endpoint::from_args(None, None).expect("embedded").is_none());
    }

    #[test]
    fn only_a_lost_connection_is_fatal() {
        assert!(ClientError::ConnectionLost {
            target: String::new(),
            message: String::new(),
        }
        .is_fatal());
        assert!(!ClientError::Statement(String::new()).is_fatal());
    }

    #[test]
    fn cancelled_exits_130_and_isnt_fatal() {
        assert_eq!(ClientError::Cancelled.exit_code(), ExitCode::from(130));
        assert!(!ClientError::Cancelled.is_fatal());
    }

    #[tokio::test]
    async fn ctrl_c_before_the_connection_is_up_exits_130() {
        let port = dataglot_test_support::reserve_loopback_port();
        let (press, ctrl_c) = CtrlC::manual();
        press.send(1).expect("press");
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run_query_with_ctrl_c(
            format!("postgres://127.0.0.1:{port}"),
            "SELECT 1",
            OutputFormat::Table,
            &mut out,
            &mut err,
            &ctrl_c,
        )
        .await;
        assert_eq!(code, ExitCode::from(130));
        assert_eq!(String::from_utf8(err).expect("utf-8"), "Cancelled.\n");
    }

    /// Ctrl-C during a long query cancels it on the server, so the same
    /// connection is free for the next statement right away.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ctrl_c_cancels_a_running_query_on_the_server() {
        use std::time::{Duration, Instant};

        let port = dataglot_test_support::reserve_loopback_port();
        let config = crate::config::ServerConfig {
            host: "127.0.0.1".to_string(),
            port,
            observability: crate::observability::ObservabilityConfig {
                metrics_addr: None,
                ..crate::observability::ObservabilityConfig::default()
            },
            ..crate::config::ServerConfig::default()
        };
        let server = Box::pin(crate::server::DataglotServer::new(config))
            .await
            .expect("server boots");
        tokio::spawn(async move {
            let _ = server.run().await;
        });
        let url = format!("postgres://127.0.0.1:{port}");
        let mut session = None;
        for _ in 0..50 {
            if let Ok(connected) = RemoteSession::connect(&url).await {
                session = Some(connected);
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let session = session.expect("server ready");

        let (press, ctrl_c) = CtrlC::manual();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(500)).await;
            let _ = press.send(1);
            // Keep the channel open so a second press never happens by accident.
            std::future::pending::<()>().await;
        });
        let started = Instant::now();
        let mut out = Vec::new();
        let result = session
            .execute_until(
                "SELECT count(*) FROM generate_series(1, 100000000000)",
                OutputFormat::Csv,
                &mut out,
                &ctrl_c,
            )
            .await;
        assert!(matches!(result, Err(ClientError::Cancelled)), "{result:?}");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "cancel took too long"
        );

        // If the server were still counting, this would queue behind it.
        let mut out = Vec::new();
        tokio::time::timeout(
            Duration::from_secs(10),
            session.execute("SELECT 1 AS n", OutputFormat::Csv, &mut out),
        )
        .await
        .expect("the server stopped the cancelled query")
        .expect("next statement runs");
        assert_eq!(String::from_utf8(out).expect("utf-8"), "n\n1\n");
    }

    #[tokio::test]
    async fn bad_server_value_is_rejected_before_connecting() {
        let Err(e) = RemoteSession::connect("postgres://host:notaport").await else {
            panic!("an invalid port must not parse");
        };
        assert!(matches!(e, ClientError::InvalidServer(_)), "{e:?}");
    }

    #[tokio::test]
    async fn run_query_reports_a_refused_connection_with_exit_code_2() {
        let port = dataglot_test_support::reserve_loopback_port();
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run_query(
            format!("postgres://127.0.0.1:{port}"),
            "SELECT 1",
            OutputFormat::Table,
            &mut out,
            &mut err,
        )
        .await;
        assert_eq!(code, ExitCode::from(2));
        assert!(out.is_empty());
        let err = String::from_utf8(err).expect("utf-8");
        assert!(
            err.starts_with(&format!("error: could not connect to 127.0.0.1:{port}: ")),
            "{err}"
        );
    }
}

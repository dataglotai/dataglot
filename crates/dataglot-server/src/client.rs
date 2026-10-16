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

use std::io::{BufWriter, Write};
use std::process::ExitCode;
use std::sync::Arc;

use datafusion::arrow::array::{ArrayRef, RecordBatch, RecordBatchOptions, StringBuilder};
use datafusion::arrow::datatypes::{DataType, Field, Schema, SchemaRef};
use datafusion::arrow::error::ArrowError;
use futures::StreamExt;
use tokio_postgres::config::Host;
use tokio_postgres::{Config, NoTls, SimpleColumn, SimpleQueryMessage, SimpleQueryRow};

use crate::cli::OutputFormat;

/// User name sent when the URL doesn't have one. Matches the embedded
/// `--user` default.
const DEFAULT_USER: &str = "dataglot";

/// Rows per Arrow batch while a result streams in.
const ROWS_PER_BATCH: usize = 1024;

/// What can go wrong in client mode. The variant decides the exit code and
/// whether the shell can keep going.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// `--server` isn't a URL or `key=value` string tokio-postgres accepts.
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
}

impl ClientError {
    /// Process exit code, following psql: 2 when there is no usable
    /// connection, 1 when a statement or the output failed.
    #[must_use]
    pub fn exit_code(&self) -> ExitCode {
        match self {
            Self::InvalidServer(_) | Self::Connect { .. } | Self::ConnectionLost { .. } => {
                ExitCode::from(2)
            }
            Self::Statement(_) | Self::Output(_) => ExitCode::FAILURE,
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

/// A connection to a running Dataglot server
pub struct RemoteSession {
    client: tokio_postgres::Client,
    target: String,
}

impl RemoteSession {
    /// Connect to `server`, a `postgres://` URL or a libpq-style
    /// `key=value` string. A missing user defaults to `dataglot`, a missing
    /// host to `localhost`. Without a database the server picks its default
    /// catalog.
    ///
    /// # Errors
    /// [`ClientError::InvalidServer`] if `server` doesn't parse,
    /// [`ClientError::Connect`] if the connection or the login fails.
    pub async fn connect(server: &str) -> Result<Self, ClientError> {
        let mut config: Config = server
            .parse()
            .map_err(|e: tokio_postgres::Error| ClientError::InvalidServer(describe(&e)))?;
        if config.get_user().is_none() {
            config.user(DEFAULT_USER);
        }
        if config.get_hosts().is_empty() && config.get_hostaddrs().is_empty() {
            config.host("localhost");
        }
        let target = target(&config);
        // No TLS yet, that is a follow up. Until then `sllmode=require` fails to connect.
        let (client, connection) = match config.connect(NoTls).await {
            Ok(connected) => connected,
            Err(e) => {
                return Err(ClientError::Connect {
                    target,
                    message: describe(&e),
                })
            }
        };
        // The connection future does the socket I/O. Once it ends, calls on
        // `client` fail as closed, to show up a dead server.
        tokio::spawn(async move {
            let _ = connection.await;
        });
        Ok(Self { client, target })
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

/// `dataglot query --server`: connect, run `sql`, write the results to `out`
/// and any error to `err`.
///
/// Returns the exit code rather than an error so a failed statement exits 1
/// and a failed connection exits 2.
pub async fn run_query<O: Write, E: Write>(
    server: &str,
    sql: &str,
    format: OutputFormat,
    out: &mut O,
    err: &mut E,
) -> ExitCode {
    let result = match RemoteSession::connect(server).await {
        Ok(session) => session.execute(sql, format, out).await,
        Err(e) => Err(e),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
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
    fn only_a_lost_connection_is_fatal() {
        assert!(ClientError::ConnectionLost {
            target: String::new(),
            message: String::new(),
        }
        .is_fatal());
        assert!(!ClientError::Statement(String::new()).is_fatal());
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
            &format!("postgres://127.0.0.1:{port}"),
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

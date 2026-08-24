//! `dataglot query` — run a single SQL statement against the configured
//! catalogs in-process and print the result, then exit.
//!
//! Reuses the exact session the server builds
//! ([`DataglotServer::create_session`]) — federation + plan-time governance +
//! the `pg_catalog` overlay — minus the pg-wire listener. The point is a
//! "try it in one command" path: a user who installed the binary can run a
//! query without `psql` or a running server.
//!
//! Governance note: the embedded session applies the same plan-time policy
//! rules as the server. Today's masking/row-filter enforcers are static (they
//! don't branch on a connection identity), so they apply here regardless of
//! `--user`. `--user` sets what `current_user` / `session_user` return, and
//! becomes policy-relevant once identity-aware rules land.

use std::io::{Read, Write};

use anyhow::{Context, Result};
use datafusion::arrow::array::RecordBatch;
use datafusion::prelude::SessionContext;

use crate::cli::{Args, OutputFormat, QueryArgs};
use crate::config::ServerConfig;
use crate::server::DataglotServer;

/// Resolve the SQL text from the positional argument, `--file`, or stdin.
///
/// Precedence: `--file` wins; then a positional argument that isn't `-`; then
/// stdin (reached by `-`, by omitting the argument, or by piping).
fn resolve_sql(q: &QueryArgs) -> Result<String> {
    if let Some(path) = &q.file {
        return std::fs::read_to_string(path)
            .with_context(|| format!("reading SQL from {}", path.display()));
    }
    match q.sql.as_deref() {
        Some("-") | None => {
            let mut buf = String::new();
            std::io::stdin()
                .read_to_string(&mut buf)
                .context("reading SQL from stdin")?;
            Ok(buf)
        }
        Some(s) => Ok(s.to_string()),
    }
}

/// Build the embedded engine and a session context — the same session the
/// server builds (federation + plan-time governance + `pg_catalog` overlay),
/// minus the pg-wire listener. `user` sets what `current_user` /
/// `session_user` return (the pg-wire path registers this per connection via
/// the `StartupObserver`; the embedded path does it here).
///
/// Returns the server too: it owns catalog/cluster handles the context relies
/// on, so the caller must keep it alive for as long as the context is used.
///
/// # Errors
/// If config load or engine construction fails (e.g. an unreachable catalog,
/// unless `--tolerate-unreachable-catalogs`).
pub(crate) async fn build_session(
    args: &Args,
    user: &str,
) -> Result<(DataglotServer, SessionContext)> {
    let mut config = ServerConfig::load(args)?;
    // One-shot CLI: run single-node in-process. A client `query`/`shell` must
    // not stand up a distributed Ballista scheduler — it's heavy, and it
    // collides on the fixed scheduler gRPC port with an already-running cluster
    //. A distributed one-shot, if ever wanted, is a separate explicit
    // opt-in, not the default.
    config.ballista = None;
    // Same construction as the server; no listener is started (we never call
    // `DataglotServer::run`).
    let server = DataglotServer::new(config)
        .await
        .context("initializing the engine (catalogs / federation)")?;
    let ctx = server.create_session();
    // Make both `session_user` and `current_user` reflect `--user`. Over pgwire
    // datafusion-pg-catalog rewrites `current_user` → `session_user`; that
    // rewrite isn't active in the embedded `ctx.sql()` path, so register both
    // explicitly.
    ctx.register_udf(dataglot_core::functions::session_user_udf(user));
    ctx.register_udf(dataglot_core::functions::current_user_udf(user));
    Ok((server, ctx))
}

/// Plan + execute one statement against `ctx` and print the result.
///
/// # Errors
/// If the query fails to plan or execute, or the result can't be formatted.
pub(crate) async fn execute_and_print(
    ctx: &SessionContext,
    sql: &str,
    format: OutputFormat,
) -> Result<()> {
    let batches = ctx
        .sql(sql)
        .await
        .context("planning the query")?
        .collect()
        .await
        .context("executing the query")?;
    print_batches(&batches, format)
}

/// Run `dataglot query`: load config (honouring the global `--config`), build
/// the federation + governance session, execute one statement, print it.
///
/// # Errors
/// If no SQL is provided, the engine fails to initialize, or the query fails.
pub async fn run(args: &Args, q: &QueryArgs) -> Result<()> {
    let sql = resolve_sql(q)?;
    let sql = sql.trim();
    if sql.is_empty() {
        anyhow::bail!("no SQL provided (pass a statement, --file <path>, or pipe via stdin)");
    }
    let (_server, ctx) = build_session(args, &q.user).await?;
    execute_and_print(&ctx, sql, q.format).await
}

/// Render `batches` to stdout in the requested format.
fn print_batches(batches: &[RecordBatch], format: OutputFormat) -> Result<()> {
    let mut out = std::io::stdout().lock();
    match format {
        OutputFormat::Table => {
            let table = datafusion::arrow::util::pretty::pretty_format_batches(batches)
                .context("formatting results as a table")?;
            writeln!(out, "{table}").context("writing table output")?;
        }
        OutputFormat::Csv => {
            let mut writer = datafusion::arrow::csv::Writer::new(&mut out);
            for b in batches {
                writer.write(b).context("writing CSV output")?;
            }
        }
        OutputFormat::Json => {
            let mut writer = datafusion::arrow::json::LineDelimitedWriter::new(&mut out);
            for b in batches {
                writer.write(b).context("writing JSON output")?;
            }
            writer.finish().context("finishing JSON output")?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;
    use crate::cli::{Args, OutputFormat, QueryArgs};

    fn qargs(sql: Option<&str>, file: Option<std::path::PathBuf>) -> QueryArgs {
        QueryArgs {
            sql: sql.map(str::to_string),
            file,
            format: OutputFormat::Table,
            user: "dataglot".to_string(),
        }
    }

    #[test]
    fn resolve_sql_uses_the_positional_argument() {
        let q = qargs(Some("SELECT 1"), None);
        assert_eq!(resolve_sql(&q).expect("resolve"), "SELECT 1");
    }

    #[test]
    fn resolve_sql_reads_a_file_and_it_wins() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("q.sql");
        std::fs::write(&path, "SELECT 2\n").expect("write");
        // `--file` takes precedence even if a positional were also present.
        let q = qargs(Some("SELECT 1"), Some(path));
        assert_eq!(resolve_sql(&q).expect("resolve").trim(), "SELECT 2");
    }

    /// End-to-end: a constant query must plan and execute through the same
    /// session the server builds, with no config and no listener.
    #[tokio::test]
    async fn runs_a_constant_query_end_to_end() {
        // `["dataglot"]` → default Args (no --config), command left unset.
        let args = Args::try_parse_from(["dataglot"]).expect("parse default args");
        let q = qargs(Some("SELECT 1 AS n, 'x' AS s"), None);
        run(&args, &q)
            .await
            .expect("constant query runs in-process");
    }

    /// A missing table surfaces as an error, not a panic — the CLI exits
    /// non-zero with the planner's message in the cause chain.
    #[tokio::test]
    async fn missing_table_is_an_error() {
        let args = Args::try_parse_from(["dataglot"]).expect("parse default args");
        let q = qargs(Some("SELECT * FROM does_not_exist"), None);
        assert!(run(&args, &q).await.is_err(), "unknown table must error");
    }

    /// `--user` sets what BOTH `session_user` and `current_user` return in the
    /// embedded session. The pg-wire path gets `current_user` via
    /// `datafusion-pg-catalog`'s `current_user` → `session_user` rewrite; the
    /// embedded `ctx.sql()` path doesn't, so `build_session` registers both
    /// UDFs. Regression guard for  (`current_user` used to error with
    /// `No field named current_user`).
    #[tokio::test]
    async fn user_flag_sets_session_and_current_user() {
        let args = Args::try_parse_from(["dataglot"]).expect("parse default args");
        let (_server, ctx) = build_session(&args, "alice").await.expect("build session");
        for expr in ["session_user", "current_user"] {
            let batches = ctx
                .sql(&format!("SELECT {expr} AS u"))
                .await
                .unwrap_or_else(|e| panic!("plan {expr}: {e}"))
                .collect()
                .await
                .unwrap_or_else(|e| panic!("execute {expr}: {e}"));
            let rendered = datafusion::arrow::util::pretty::pretty_format_batches(&batches)
                .unwrap()
                .to_string();
            assert!(
                rendered.contains("alice"),
                "{expr} must reflect --user; got:\n{rendered}"
            );
        }
    }
}

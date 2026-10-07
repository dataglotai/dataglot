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
//! rules as the server, under the identity a trust-mode pg-wire connection
//! with the same username would get (`DataglotServer::embedded_session_identity`).
//! `--user` therefore selects whose masks, row filters, grants and column
//! whitelists apply — including org-scoped rules created at runtime with
//! `CREATE MASK` / `CREATE ROW FILTER` — as well as what `current_user` /
//! `session_user` return.

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

/// An embedded (in-process) session: the engine, its `SessionContext`, and
/// the policy identity every statement runs under.
///
/// Holds the server too: it owns catalog/cluster handles the context relies
/// on, so it must stay alive for as long as the context is used.
pub(crate) struct EmbeddedSession {
    _server: DataglotServer,
    ctx: SessionContext,
    identity: dataglot_policy::Identity,
}

impl EmbeddedSession {
    /// Plan and execute one statement under this session's identity.
    ///
    /// Both steps run inside [`dataglot_policy::with_session_identity`]:
    /// `DataFrame::collect` is where DataFusion runs the optimizer (and with
    /// it the policy rule), so scoping only `ctx.sql()` would not be enough.
    /// Without the scope the policy rule sees an anonymous, org-less identity
    /// and org-scoped runtime masks / row filters silently never fire.
    ///
    /// # Errors
    /// If the query fails to plan or execute.
    pub(crate) async fn execute(&self, sql: &str) -> Result<Vec<RecordBatch>> {
        Box::pin(dataglot_policy::with_session_identity(
            self.identity.clone(),
            async {
                self.ctx
                    .sql(sql)
                    .await
                    .context("planning the query")?
                    .collect()
                    .await
                    .context("executing the query")
            },
        ))
        .await
    }

    /// [`Self::execute`] one statement and print the result.
    ///
    /// # Errors
    /// If the query fails to plan or execute, or the result can't be formatted.
    pub(crate) async fn execute_and_print(&self, sql: &str, format: OutputFormat) -> Result<()> {
        let batches = self.execute(sql).await?;
        print_batches(&batches, format)
    }
}

/// Build the embedded engine and a session — the same session the server
/// builds (federation + plan-time governance + `pg_catalog` overlay), minus
/// the pg-wire listener, running under `user`'s policy identity.
///
/// `user` resolves to the identity a trust-mode pg-wire connection with that
/// username would get ([`DataglotServer::embedded_session_identity`]), and
/// also sets what `current_user` / `session_user` return (the pg-wire path
/// registers those per connection via the `StartupObserver`; the embedded
/// path does it here).
///
/// # Errors
/// If config load or engine construction fails (e.g. an unreachable catalog,
/// unless `--tolerate-unreachable-catalogs`), or `user` belongs to an org this
/// embedded session can't serve.
pub(crate) async fn build_session(args: &Args, user: &str) -> Result<EmbeddedSession> {
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
    let identity = server.embedded_session_identity(user)?;
    let ctx = server.create_session();
    // Make both `session_user` and `current_user` reflect `--user`. Over pgwire
    // datafusion-pg-catalog rewrites `current_user` → `session_user`; that
    // rewrite isn't active in the embedded `ctx.sql()` path, so register both
    // explicitly.
    ctx.register_udf(dataglot_core::functions::session_user_udf(user));
    ctx.register_udf(dataglot_core::functions::current_user_udf(user));
    Ok(EmbeddedSession {
        _server: server,
        ctx,
        identity,
    })
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
    let session = build_session(args, &q.user).await?;
    session.execute_and_print(sql, q.format).await
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
        let session = build_session(&args, "alice").await.expect("build session");
        for expr in ["session_user", "current_user"] {
            let batches = session
                .execute(&format!("SELECT {expr} AS u"))
                .await
                .unwrap_or_else(|e| panic!("run {expr}: {e:#}"));
            let rendered = datafusion::arrow::util::pretty::pretty_format_batches(&batches)
                .unwrap()
                .to_string();
            assert!(
                rendered.contains("alice"),
                "{expr} must reflect --user; got:\n{rendered}"
            );
        }
    }

    /// Write a config with an embedded meta store and one CSV-backed catalog
    /// (`files.public.users`, rows `1 alice@acme.com` / `2 bob@acme.com`),
    /// and seed that store with `ddl` exactly as the pg-wire handler applies
    /// it for a trust-mode session: under the boot org, `"default"`.
    ///
    /// `extra_toml` is appended to the config (e.g. `[identities.*]`).
    async fn fixture_with_policy(
        ddl: dataglot_pgwire::policy_ddl::PolicyDdl,
        extra_toml: &str,
    ) -> (tempfile::TempDir, Args) {
        use std::sync::Arc;

        use dataglot_catalog::{MetaStore, RedbMetaStore};
        use dataglot_pgwire::policy_admin::PolicyAdmin;
        use dataglot_policy::{InMemoryRuleStore, InitialRules};

        let dir = tempfile::tempdir().expect("tempdir");
        let csv = dir.path().join("users.csv");
        std::fs::write(&csv, "id,email\n1,alice@acme.com\n2,bob@acme.com\n").expect("write csv");
        let meta = dir.path().join("meta.redb");
        let config = dir.path().join("dataglot.toml");
        std::fs::write(
            &config,
            format!(
                "[catalog_service]\npath = '{}'\n\n\
                 [catalogs.files]\nkind = \"object_storage\"\n\n\
                 [[catalogs.files.tables]]\nname = \"users\"\nurl = 'file://{}'\nformat = \"csv\"\n\n\
                 {extra_toml}",
                meta.display(),
                csv.display(),
            ),
        )
        .expect("write config");

        {
            // Scoped so the store (and redb's exclusive file lock) is released
            // before the embedded session opens the same file.
            let store: Arc<dyn MetaStore> = Arc::new(
                RedbMetaStore::open(&meta, "default")
                    .await
                    .expect("open meta store"),
            );
            let rules = InMemoryRuleStore::new(InitialRules::default()).expect("rule store");
            crate::policy_admin::StorePolicyAdmin::new(store, rules)
                .apply("default", ddl)
                .await
                .expect("apply policy DDL under the boot org");
        }

        let args = Args::try_parse_from(["dataglot", "-c", config.to_str().expect("utf-8 path")])
            .expect("parse args");
        (dir, args)
    }

    async fn users_table(session: &EmbeddedSession) -> String {
        let batches = session
            .execute("SELECT id, email FROM files.public.users ORDER BY id")
            .await
            .expect("query files.public.users");
        datafusion::arrow::util::pretty::pretty_format_batches(&batches)
            .expect("format")
            .to_string()
    }

    /// Regression: a mask created at runtime (`CREATE MASK` over pg-wire,
    /// persisted under the session's org) must apply in the embedded CLI
    /// session too. It used to be skipped: the CLI ran without a session
    /// identity, so the policy rule saw an org-less anonymous identity and
    /// `org_rule_applies(Some("default"), ..)` never matched.
    #[tokio::test]
    async fn runtime_mask_applies_in_embedded_session() {
        use dataglot_pgwire::policy_ddl::{PolicyDdl, PolicyMask};

        let (_dir, args) = fixture_with_policy(
            PolicyDdl::CreateMask {
                name: "email_mask".to_string(),
                table: "files.public.users".to_string(),
                column: "email".to_string(),
                mask: PolicyMask::Literal("***@example.com".to_string()),
                if_not_exists: false,
            },
            "",
        )
        .await;
        let session = build_session(&args, "dataglot")
            .await
            .expect("build session");
        let out = users_table(&session).await;
        assert!(
            out.contains("***@example.com"),
            "mask must apply; got:\n{out}"
        );
        assert!(
            !out.contains("alice@acme.com"),
            "raw value must not leak; got:\n{out}"
        );
    }

    /// Regression: same as [`runtime_mask_applies_in_embedded_session`] for a
    /// runtime `CREATE ROW FILTER`.
    #[tokio::test]
    async fn runtime_row_filter_applies_in_embedded_session() {
        use dataglot_pgwire::policy_ddl::PolicyDdl;

        let (_dir, args) = fixture_with_policy(
            PolicyDdl::CreateRowFilter {
                name: "only_alice".to_string(),
                table: "files.public.users".to_string(),
                predicate: "id = 1".to_string(),
                if_not_exists: false,
            },
            "",
        )
        .await;
        let session = build_session(&args, "dataglot")
            .await
            .expect("build session");
        let out = users_table(&session).await;
        assert!(
            out.contains("alice@acme.com"),
            "allowed row must remain; got:\n{out}"
        );
        assert!(
            !out.contains("bob@acme.com"),
            "filtered row must not leak; got:\n{out}"
        );
    }

    /// An org-less `--user` resolves to the boot org — the same identity a
    /// trust-mode pg-wire connection gets (F4 org resolution).
    #[tokio::test]
    async fn orgless_user_resolves_to_boot_org() {
        let args = Args::try_parse_from(["dataglot"]).expect("parse default args");
        let session = build_session(&args, "alice").await.expect("build session");
        assert_eq!(session.identity.user.as_deref(), Some("alice"));
        assert_eq!(session.identity.org.as_deref(), Some("default"));
    }

    /// A config identity keeps its own org and groups when no control plane
    /// is configured (nothing org-scoped to mismatch) — as on pg-wire.
    #[tokio::test]
    async fn config_identity_keeps_its_org_and_groups() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = dir.path().join("dataglot.toml");
        std::fs::write(
            &config,
            "[identities.bob]\norg = \"acme\"\ngroups = [\"analyst\"]\n",
        )
        .expect("write config");
        let args = Args::try_parse_from(["dataglot", "-c", config.to_str().expect("utf-8 path")])
            .expect("parse args");
        let session = build_session(&args, "bob").await.expect("build session");
        assert_eq!(session.identity.org.as_deref(), Some("acme"));
        assert_eq!(session.identity.org_groups, vec!["analyst".to_string()]);
    }

    /// With a control plane, a user from another org is refused: the embedded
    /// session only carries the boot org's catalogs, so running it would pair
    /// the boot org's data with the other org's policies.
    #[tokio::test]
    async fn foreign_org_user_is_refused_with_control_plane() {
        use dataglot_pgwire::policy_ddl::{PolicyDdl, PolicyMask};

        let (_dir, args) = fixture_with_policy(
            PolicyDdl::CreateMask {
                name: "email_mask".to_string(),
                table: "files.public.users".to_string(),
                column: "email".to_string(),
                mask: PolicyMask::Literal("***@example.com".to_string()),
                if_not_exists: false,
            },
            "[identities.bob]\norg = \"acme\"\n",
        )
        .await;
        let Err(e) = build_session(&args, "bob").await else {
            panic!("a foreign-org user must be refused");
        };
        let msg = format!("{e:#}");
        assert!(
            msg.contains("boot org"),
            "error must explain why; got: {msg}"
        );
    }
}

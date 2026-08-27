//! Dataglot — boots `DataFusion`, federation, and pg wire.
//!
//! This is the main entry point for the Dataglot server, which:
//! 1. Parses CLI arguments
//! 2. Loads configuration
//! 3. Initializes observability (tracing + Prometheus metrics)
//! 4. Bootstraps the `SessionContext` with all subsystems
//! 5. Starts the pg wire server
//!
//! `--healthcheck` short-circuits all of the above — see the
//! [`run_healthcheck`] helper.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use anyhow::Result;

use dataglot_server::cli::Args;
use dataglot_server::config::ServerConfig;
use dataglot_server::observability;
use dataglot_server::server::DataglotServer;

/// One-shot health probe used by the distroless runtime image's
/// `HEALTHCHECK` directive (which can't shell out to `nc -z`
/// anymore) and by `docker-compose` healthcheck definitions.
///
/// Mirrors the contract `nc -z localhost <port>` provided: TCP
/// connect to the loopback address with a short timeout, exit 0
/// on success and 1 on failure. We deliberately do not perform a
/// pg-wire handshake — the existing healthcheck probes don't, and
/// a successful TCP connect is the strongest signal a network-
/// level probe can give without taking on protocol semantics.
///
/// Returns the process exit code so the caller can `std::process::exit`
/// with it; that keeps `main` itself testable.
///
/// # Why async
/// hard rule 11 forbids blocking IO in async context. The
/// original implementation used `std::net::TcpStream::connect_timeout`
/// directly inside `#[tokio::main]`, which would have blocked the
/// runtime thread for up to 2 seconds. The async path uses
/// `tokio::net::TcpStream::connect` + `tokio::time::timeout` so the
/// probe stays cooperative — even though we exit the process right
/// after, leaving the rule's invariants intact is cheaper than
/// surprising the next reader.
async fn run_healthcheck(port: u16) -> i32 {
    // Use loopback explicitly rather than `args.host` — the server
    // typically binds `0.0.0.0` and a healthcheck running inside
    // the same container should reach it via `127.0.0.1`, not the
    // bind wildcard.
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
    match tokio::time::timeout(Duration::from_secs(2), tokio::net::TcpStream::connect(addr)).await {
        Ok(Ok(_)) => 0,
        Ok(Err(e)) => {
            // Stderr so docker-compose / k8s probe logs surface the
            // reason without polluting the JSON-formatted server
            // log stream (which isn't initialized on this path).
            eprintln!("healthcheck: failed to connect to {addr}: {e}");
            1
        }
        Err(_) => {
            eprintln!("healthcheck: timeout connecting to {addr} after 2s");
            1
        }
    }
}

/// Worker-thread stack size for the tokio runtime.
///
/// The default (2 MiB) is too small for the deep plan recursion on the
/// distributed (Ballista) execution path: an SF10 TPC-H query overflowed a
/// `tokio-rt-worker` stack *after* execution finished, aborting the whole
/// process with `fatal runtime error: stack overflow`. Ballista's
/// nested query-stage / shuffle plans plus DataFusion's recursive plan and
/// `Drop` walks stack deeper than 2 MiB. Verified: `RUST_MIN_STACK=64M`
/// makes the same queries complete cleanly. Larger stacks are reserved
/// address space committed lazily, so the cost of the headroom is
/// negligible — and it protects deep single-node plans too.
const WORKER_STACK_SIZE: usize = 64 * 1024 * 1024; // 64 MiB

fn main() -> Result<()> {
    // A hand-built runtime (vs `#[tokio::main]`) so worker threads get a
    // larger stack — see `WORKER_STACK_SIZE`.
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_stack_size(WORKER_STACK_SIZE)
        .build()?
        .block_on(run())
}

async fn run() -> Result<()> {
    // Parse CLI arguments first — we need the resolved config before we can
    // initialize tracing, since the format/filter are part of the config.
    let args = Args::parse_args();

    // Completion-script short-circuit: print to stdout and exit, before any
    // config/tracing work, so `dataglot completions <shell>` output is clean.
    if let Some(dataglot_server::cli::Command::Completions(c)) = &args.command {
        dataglot_server::cli::print_completions(c.shell);
        return Ok(());
    }

    // Subcommand short-circuit (one-shot utilities that never boot the
    // server). Runs first so `dataglot init` doesn't touch config/tracing.
    if let Some(dataglot_server::cli::Command::Init(init)) = &args.command {
        dataglot_server::first_run::write_starter_config(&init.path, init.force)?;
        // Status → stderr so stdout stays clean; guide the next two steps.
        eprintln!(
            "Wrote {} — a starter config with one Postgres catalog and a mask example.",
            init.path.display()
        );
        eprintln!(
            "Next: set the DSN env var it names, then run:  dataglot --config {}",
            init.path.display()
        );
        return Ok(());
    }

    // Print-example-config short-circuit. Runs before everything else so
    // `dataglot --print-example-config > dataglot.json` emits exactly the
    // starter file (no tracing/banner noise on stdout).
    if args.print_example_config {
        dataglot_server::first_run::print_example_config()?;
        return Ok(());
    }

    // Health-probe short-circuit. Runs before config loading and
    // tracing init so a misconfigured container with a broken
    // config file still has a working healthcheck — useful for
    // diagnosing "why is the container restart-looping".
    if args.healthcheck {
        // Legit hard-exit: the `healthcheck` subcommand is a standalone probe
        // that must map its result straight to a process exit code (no server
        // is running, so there's nothing to drain). Every other exit path
        // goes through graceful shutdown — hence the disallowed-methods ban.
        // `args.port` is `None` unless `--port`/`DATAGLOT_PORT` was
        // given; this probe runs before config load, so the pg-wire
        // default (`5432`) is the right fallback here.
        #[allow(clippy::disallowed_methods)]
        std::process::exit(run_healthcheck(args.port.unwrap_or(5432)).await);
    }

    // Query short-circuit: run one SQL statement in-process and exit. It
    // loads config + builds the engine itself (no pg-wire listener) and prints
    // results to stdout, so it runs before tracing init to keep stdout clean.
    if let Some(dataglot_server::cli::Command::Query(q)) = &args.command {
        return dataglot_server::query::run(&args, q).await;
    }

    // Interactive shell short-circuit: same embedded engine as `query`, in a
    // REPL. Runs before tracing init so stdout stays result-only.
    if let Some(dataglot_server::cli::Command::Shell(s)) = &args.command {
        return dataglot_server::shell::run(&args, s).await;
    }

    // Load configuration
    let config = ServerConfig::load(&args)?;

    // Initialize tracing using the resolved observability config. This is
    // the earliest point at which we can emit structured logs.
    observability::init_tracing(&config.observability)?;

    // Record which configuration source was used, now that tracing is up
    // (config load itself runs before this, so it can't log). An operator
    // debugging a restart-loop can confirm *which* file was read — or that
    // none was.
    if let Some(path) = &args.config {
        tracing::info!(config_path = %path.display(), "loaded configuration from file");
    } else {
        tracing::info!("no --config provided; using built-in defaults with env/CLI overrides");
    }

    tracing::info!(
        // Dataglot's own version (matches `dataglot --version`), not the
        // DataFusion/Ballista crate version — same source as the CLI and the
        // dashboard ServerInfo.
        version = env!("CARGO_PKG_VERSION"),
        datafusion_version = dataglot_core::datafusion_version(),
        host = %config.host,
        port = config.port,
        metrics_addr = ?config.observability.metrics_addr,
        log_format = ?config.observability.log_format,
        "Starting Dataglot"
    );

    // Zero-catalog boot is a dead end for a first-time user — surface it
    // loudly with the exact fix instead of starting up silently.
    if config.catalogs.is_empty() {
        tracing::warn!(
            "{}",
            dataglot_server::first_run::no_catalogs_banner(&config.host, config.port)
        );
    }

    // The dashboard's per-query pushdown treeview (Queries → detail) only
    // populates under single-partition execution: DataFusion's partition
    // tasks don't inherit the pushdown-correlation task-local. Warn
    // so an operator who enabled capture doesn't stare at a silently empty
    // profile and assume it's broken — the source list and incoming SQL still
    // work at any partition count. Only fires for plain DataFusion single-node:
    // with Ballista the treeview is fed from executor pushdown metrics after
    // each job regardless of partitions, so `partitions = 1` is a false remedy
    // there — see `ServerConfig::should_warn_empty_treeview`.
    if config.should_warn_empty_treeview() {
        tracing::warn!(
            partitions = config.partitions,
            "observability.capture_query_sources is on but partitions > 1: the \
             per-query pushdown-SQL treeview will stay empty. Set partitions = 1 \
             to populate it (the Queries list + incoming SQL are unaffected)."
        );
    }

    // Create and start the server. `new` is async because it eagerly
    // connects every catalog configured in `[catalogs.*]` so the
    // operator finds out at boot — not on the first query — that a
    // source is unreachable.
    let server = DataglotServer::new(config).await?;
    server.run().await?;

    Ok(())
}

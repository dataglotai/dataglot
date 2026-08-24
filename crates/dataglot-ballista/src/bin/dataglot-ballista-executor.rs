//! `dataglot-ballista-executor` — standalone Ballista executor binary.
//!
//! Phase 2 slice 5a. Wraps Apache Ballista's `start_executor_process`
//! entry point with Dataglot-specific overrides:
//!
//! - **Credential resolver injection.** `--credentials-config` loads
//!   the resolver shape `dataglot-core::CredentialResolverConfig`
//!   describes, then attaches the resulting `Arc<dyn CredentialResolver>`
//!   to every per-task `SessionConfig` via the executor's
//!   `override_config_producer` hook.
//! - **Federation logical codec parity** with what the coordinator
//!   installs on its `BallistaContextFactory`. (Federation physical
//!   plans across multi-process are slice 5a.2 — they need a
//!   `ConnectorRegistry` the minimal cut doesn't ship.)
//!
//! Most of the runtime logic lives in `dataglot_ballista::executor` so
//! it's unit-testable without spawning the binary. This file is a
//! thin `main`: parse, set up tracing, hand off to `run_executor`.

use clap::Parser;
use dataglot_ballista::ExecutorArgs;
use std::process::ExitCode;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> ExitCode {
    let args = ExecutorArgs::parse();

    // Subscribe early so the resolver-construction / Ballista-startup
    // logs surface. `RUST_LOG` overrides; otherwise default to INFO
    // on everything plus a quiet floor for noisy crates Ballista
    // pulls (h2, hyper) at DEBUG/TRACE.
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,h2=warn,hyper=warn"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();

    tracing::info!(
        scheduler = format!("{}:{}", args.scheduler_host, args.scheduler_port),
        bind = format!("{}:{}", args.bind_host, args.bind_port),
        credentials_config = ?args.credentials_config,
        "dataglot-ballista-executor starting"
    );

    match dataglot_ballista::run_executor(args).await {
        Ok(()) => {
            tracing::info!("dataglot-ballista-executor exited cleanly");
            ExitCode::SUCCESS
        }
        Err(e) => {
            // The fail-fast paths from slice 3b surface here as
            // DataglotError::Configuration; Ballista RPC failures
            // surface as DataglotError::Internal. Either way the
            // operator gets a single diagnostic line + non-zero
            // exit. CLAUDE.md rule 12 — the resolver Debug impls
            // redact secrets, so this Display is credential-safe.
            tracing::error!(error = %e, "dataglot-ballista-executor failed");
            eprintln!("dataglot-ballista-executor: {e}");
            ExitCode::FAILURE
        }
    }
}

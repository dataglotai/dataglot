//! `dataglot-ballista-scheduler` — standalone Ballista scheduler binary.
//!
//! Phase 2 slice 8.2a. Boots a Ballista scheduler that listens for
//! gRPC executor registrations on the configured bind address. The
//! companion to `dataglot-ballista-executor` for the docker-compose
//! multi-process cluster shape.
//!
//! Most of the runtime logic lives in `dataglot_ballista::scheduler`
//! so it's unit-testable without spawning the binary. This file is
//! a thin `main`: parse, set up tracing, hand off to `run_scheduler`.

use clap::Parser;
use dataglot_ballista::SchedulerArgs;
use std::process::ExitCode;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> ExitCode {
    let args = SchedulerArgs::parse();

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,h2=warn,hyper=warn"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();

    tracing::info!(
        bind = format!("{}:{}", args.bind_host, args.bind_port),
        external_host = %args.external_host,
        namespace = %args.namespace,
        "dataglot-ballista-scheduler starting"
    );

    match dataglot_ballista::run_scheduler(args).await {
        Ok(()) => {
            tracing::info!("dataglot-ballista-scheduler exited cleanly");
            ExitCode::SUCCESS
        }
        Err(e) => {
            tracing::error!(error = %e, "dataglot-ballista-scheduler failed");
            eprintln!("dataglot-ballista-scheduler: {e}");
            ExitCode::FAILURE
        }
    }
}

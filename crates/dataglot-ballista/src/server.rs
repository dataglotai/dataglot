//! Server-side TLS wiring for Phase 2 slice 7b.
//!
//! Architecture §12 commits to "mTLS with port separation — control
//! plane vs. data plane on separate ports." Slice 7a shipped the
//! client-side plumbing — every outbound gRPC endpoint Ballista mints
//! routes through `endpoint.tls_config(ClientTlsConfig{...})` when the
//! `--tls-*` flags are configured. But the server sides remained on
//! Apache Ballista's plaintext `start_server` /
//! `start_executor_process` entry points — those functions don't plumb
//! a `ServerTlsConfig` through their public config types. A
//! fully-configured client dialing those plaintext peers fails the
//! TLS handshake by design.
//!
//! Slice 7b closes the §12 commitment by bypassing those entries and
//! assembling the gRPC servers ourselves via
//! `tonic::transport::Server::builder().tls_config(ServerTlsConfig)`.
//! Apache ships the canonical reference at
//! `examples/examples/mtls-cluster.rs` — this module ports that
//! pattern into the Dataglot binaries.
//!
//! # Architectural commit: pull-mode dispatch when TLS is enabled
//!
//! Ballista has two scheduling modes:
//!
//! - **Push mode** (Dataglot's plaintext default since slice 5a):
//!   the scheduler dials the executor's gRPC control port (50052) to
//!   dispatch tasks. `start_executor_process` binds both the Flight
//!   data port and the gRPC control port and runs the registration /
//!   heartbeat loops internally.
//! - **Pull mode** (Apache's `mtls-cluster.rs` pattern): the executor
//!   binds only Flight (50051) with `grpc_port: 0` in its registration,
//!   then runs `execution_loop::poll_loop(...)` which long-polls the
//!   scheduler for work.
//!
//! Apache's example uses pull mode for TLS because it sidesteps having
//! to inline the entirety of `start_executor_process`'s push-mode
//! registration logic. Replicating push mode would mean carrying
//! non-trivial Ballista internals (registration, heartbeats, signal
//! handling) and re-syncing them on every upstream bump. Pull mode is
//! a one-line dispatch (`poll_loop(scheduler, executor, codec).await`)
//! and is what Apache officially recommends for TLS.
//!
//! Tradeoff: pull-mode polling has slightly higher idle-time CPU than
//! push-mode (the executor polls even when the scheduler has no
//! work), and dispatch latency includes one poll-interval round-trip.
//! For Phase 2 the security commitment outweighs the dispatch
//! micro-overhead. If a future workload benchmark surfaces a
//! quantifiable gap, a push-mode-TLS sub-spec would replicate
//! `start_executor_process` with TLS attached at both listeners; not
//! in scope today.
//!
//! Plaintext deployments keep push mode unchanged — slice 7b's
//! changes are inert when `--insecure` is passed (or, by 7b's
//! default-deny rule, when TLS is configured).
//!
//! # What this module ships
//!
//! - [`run_scheduler_tls`] — boot the scheduler in TLS mode. Inlines
//!   the relevant gRPC-server assembly that `start_server` would have
//!   done, attaches `ServerTlsConfig`, serves on the configured bind
//!   address. Loses `start_server`'s embedded axum REST routes and
//!   the flight-proxy service (acceptable — Dataglot doesn't rely on
//!   those today; the scheduler-to-flight-proxy path is single-process
//!   internal and is only meaningful in `BallistaClient::flight()`
//!   call patterns we don't exercise).
//! - [`run_executor_tls`] — boot the executor in pull-mode TLS shape:
//!   construct `Executor` directly (vs `start_executor_process`),
//!   spawn the Flight server with `ServerTlsConfig`, connect to the
//!   scheduler over client-TLS, run the pull-based execution loop.

use std::net::SocketAddr;
use std::sync::Arc;

use arrow_flight::flight_service_server::FlightServiceServer;
use ballista_core::error::{BallistaError, Result as BallistaResult};
use ballista_core::serde::protobuf::executor_resource::Resource;
use ballista_core::serde::protobuf::scheduler_grpc_client::SchedulerGrpcClient;
use ballista_core::serde::protobuf::scheduler_grpc_server::SchedulerGrpcServer;
use ballista_core::serde::protobuf::{
    ExecutorRegistration, ExecutorResource, ExecutorSpecification,
};
use ballista_core::serde::{BallistaCodec, BallistaPhysicalExtensionCodec};
use ballista_core::utils::create_grpc_client_endpoint;
use ballista_core::{ConfigProducer, RuntimeProducer};
use ballista_executor::execution_loop;
use ballista_executor::executor::Executor;
use ballista_executor::flight_service::BallistaFlightService;
use ballista_executor::metrics::LoggingMetricsCollector;
use ballista_scheduler::cluster::BallistaCluster;
use ballista_scheduler::scheduler_server::SchedulerServer;
use datafusion_proto::protobuf::{LogicalPlanNode, PhysicalPlanNode};
use dataglot_core::error::{DataglotError, Result};
use dataglot_core::CredentialResolver;
use dataglot_federation::{DynConnectorRegistry, FederationPlanCodec};
use tonic::transport::Server;

use crate::codec::FederationLogicalCodec;
use crate::executor::{CredentialResolverExtension, ExecutorArgs};
use crate::scheduler::SchedulerArgs;
use crate::tls::BallistaTlsConfig;

/// Maximum gRPC message size for both scheduler and executor servers
/// — matches Apache's `mtls-cluster.rs` reference. 16 MiB is the
/// Ballista-stock value for control-plane messages (the data plane
/// uses Arrow Flight streaming and isn't constrained by this knob).
const GRPC_MAX_MESSAGE_SIZE_BYTES: usize = 16 * 1024 * 1024;

/// Boot the scheduler with server-side TLS attached to the gRPC
/// listener.
///
/// Equivalent to `run_scheduler_single` in [`crate::scheduler`] but
/// bypasses Ballista's `start_server` so we can call
/// `tonic::transport::Server::builder().tls_config(...)` directly.
/// Apache's `examples/mtls-cluster.rs` reference does the same.
///
/// What this preserves from the plaintext path:
///
/// - The same `SchedulerConfig` shape the plaintext path uses
///   (bind host/port, namespace, external host, the slice-7a
///   `override_create_grpc_client_endpoint` for outbound client TLS).
/// - The same [`BallistaCluster`] backend (in-memory variant by
///   default; slice 5b's object-store HA already runs above this
///   layer via [`crate::scheduler::run_scheduler`]).
///
/// What this drops vs. `start_server`:
///
/// - axum REST routes (job monitoring UI). Not used by Dataglot;
///   plaintext deployments needing the UI can opt out of TLS.
/// - The flight-proxy service. Only meaningful for cross-process
///   shuffle reads via a scheduler intermediary — Dataglot's pgwire
///   client reads results from the scheduler over the standard
///   gRPC path, not the flight proxy.
///
/// # Errors
/// - [`BallistaError::Configuration`] for bind-address parse failure.
/// - Bubble-up from `BallistaCluster::new_from_config` (in-memory
///   backend should never fail; reserved for slice 5b's object-store
///   variants if/when this module is extended).
/// - `tonic::transport::Error` wrapped into `BallistaError::Internal`
///   for TLS-config setup failures (malformed cert payloads tonic
///   detects only at handshake time).
pub async fn run_scheduler_tls(
    args: &SchedulerArgs,
    tls: &BallistaTlsConfig,
) -> BallistaResult<()> {
    let addr: SocketAddr = args
        .bind_socket_addr()
        .map_err(BallistaError::Configuration)?;

    // SchedulerConfig with both slots set by slice 7a's
    // `apply_tls_to_scheduler_config` for outbound TLS — we mirror
    // that here so the inlined boot path matches the plaintext path's
    // outbound TLS plumbing exactly.
    let mut config = args.build_scheduler_config();
    config.use_tls = true;
    let tls_arc = Arc::new(tls.clone());
    config.override_create_grpc_client_endpoint = Some(tls_arc.into_endpoint_override());

    let cluster = BallistaCluster::new_from_config(&config).await?;

    // The codec — pull-mode dispatch sends serialized plans over the
    // wire, so the scheduler-side codec needs to match the executor-
    // side one. Stock BallistaPhysicalExtensionCodec is fine here
    // because the scheduler doesn't decode federation plans; it
    // forwards them. The executor (pull side) is where federation
    // codecs matter, and `run_executor_tls` installs ours there.
    let codec: BallistaCodec<LogicalPlanNode, PhysicalPlanNode> = BallistaCodec::default();

    let metrics_collector = ballista_scheduler::metrics::default_metrics_collector()
        .map_err(|e| BallistaError::Internal(format!("metrics collector init failed: {e}")))?;

    let scheduler_name = config.scheduler_name();
    let mut scheduler: SchedulerServer<LogicalPlanNode, PhysicalPlanNode> = SchedulerServer::new(
        scheduler_name,
        cluster,
        codec,
        Arc::new(config),
        metrics_collector,
    );
    scheduler
        .init()
        .await
        .map_err(|e| BallistaError::Internal(format!("scheduler init failed: {e}")))?;

    let scheduler_grpc = SchedulerGrpcServer::new(scheduler)
        .max_decoding_message_size(GRPC_MAX_MESSAGE_SIZE_BYTES)
        .max_encoding_message_size(GRPC_MAX_MESSAGE_SIZE_BYTES);

    tracing::info!(
        addr = %addr,
        domain = %tls.domain(),
        "scheduler: serving gRPC with server-side TLS (slice 7b)"
    );

    Server::builder()
        .tls_config(tls.server_tls_config())
        .map_err(|e| BallistaError::Internal(format!("server TLS config failed: {e}")))?
        .add_service(scheduler_grpc)
        .serve(addr)
        .await
        .map_err(|e| BallistaError::Internal(format!("scheduler serve loop exited: {e}")))?;

    Ok(())
}

/// Boot the executor in pull-mode with server-side TLS attached to
/// the Arrow Flight data-plane listener.
///
/// Equivalent to [`crate::executor::run_executor`]'s
/// `start_executor_process` call but assembles the executor manually
/// so we can attach TLS to the Flight listener and use pull-mode
/// dispatch. Apache's `examples/mtls-cluster.rs` reference is the
/// canonical pattern.
///
/// # Errors
/// - [`DataglotError::Configuration`] for bind-address parse failure
///   or scheduler-URL parse failure.
/// - [`DataglotError::Internal`] wrapping any tonic / Flight / poll-
///   loop failure that surfaces during the serve / poll lifetime.
///
/// # Panics
/// The Flight service and the pull-loop run as sibling tokio tasks
/// inside a `tokio::select!`; if either task panics, the `select!`
/// arm's `JoinHandle::await?` re-raises the panic. That's a real
/// process exit and is the intended behavior — propagating a panic
/// to the operator surface is preferable to silently keeping the
/// half-running other half alive.
#[allow(clippy::too_many_lines)]
pub async fn run_executor_tls(
    args: &ExecutorArgs,
    resolver: &Arc<dyn CredentialResolver>,
    registry: &DynConnectorRegistry,
    tls: &BallistaTlsConfig,
) -> Result<()> {
    use datafusion_proto::logical_plan::LogicalExtensionCodec;
    use datafusion_proto::physical_plan::PhysicalExtensionCodec;

    let flight_addr: SocketAddr = format!("{}:{}", args.bind_host, args.bind_port)
        .parse()
        .map_err(|e| {
            DataglotError::Configuration(format!(
                "flight bind address `{}:{}` not parseable: {e}",
                args.bind_host, args.bind_port
            ))
        })?;

    let executor_id = uuid::Uuid::new_v4().to_string();
    let host = args
        .external_host
        .clone()
        .unwrap_or_else(|| "localhost".to_string());

    let concurrent_tasks = args
        .concurrent_tasks
        .unwrap_or_else(num_cpus_logical_fallback);

    // Pull-mode registration: `grpc_port: 0` tells the scheduler the
    // executor doesn't accept push-mode dispatch over a gRPC port —
    // the executor will long-poll instead.
    let executor_meta = ExecutorRegistration {
        id: executor_id.clone(),
        host: Some(host),
        port: u32::from(args.bind_port),
        grpc_port: 0,
        specification: Some(ExecutorSpecification {
            resources: vec![ExecutorResource {
                resource: Some(Resource::TaskSlots(
                    u32::try_from(concurrent_tasks).unwrap_or(u32::MAX),
                )),
            }],
        }),
        os_info: None,
    };

    // Work dir for shuffle data. Slice 7b's MVP roots the work dir
    // under the system temp dir with a uuid subdir per executor
    // process; a follow-up could surface this as a CLI flag (parity
    // with stock `ExecutorProcessConfig.work_dir`). We don't use
    // `tempfile::tempdir` because that's a dev-dep — production
    // binaries should not pull it in. The directory persists for the
    // lifetime of the process; OS temp-dir scrubbing or operator
    // tooling handles cleanup (matches Ballista's stock executor
    // process default).
    let work_dir_path = std::env::temp_dir().join(format!("dataglot-executor-{executor_id}"));
    std::fs::create_dir_all(&work_dir_path).map_err(|e| {
        DataglotError::Configuration(format!(
            "executor work dir create failed at `{}`: {e}",
            work_dir_path.display()
        ))
    })?;
    let work_dir_str = work_dir_path.to_string_lossy().into_owned();

    // Config producer: every per-task SessionConfig the executor mints
    // gets both the credential resolver (slice 3b extension) AND the
    // outbound client TLS override (slice 7a parity). The
    // `with_ballista_use_tls(true)` flag flips the URL scheme to
    // `https://` for any client connection Ballista constructs.
    let resolver_for_config = Arc::clone(resolver);
    let client_tls = tls.client_tls_config();
    let config_producer: ConfigProducer = Arc::new(move || {
        use ballista::datafusion::prelude::SessionConfig as DfSessionConfig;
        use ballista::prelude::SessionConfigExt;
        let tls = client_tls.clone();
        DfSessionConfig::new_with_ballista()
            .with_ballista_use_tls(true)
            .with_ballista_override_create_grpc_client_endpoint(Arc::new(move |endpoint| {
                endpoint
                    .tls_config(tls.clone())
                    .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
            }))
            .with_extension(Arc::new(CredentialResolverExtension(Arc::clone(
                &resolver_for_config,
            ))))
    });

    // Runtime producer. Same shape as `ExecutorProcessConfig::default()`
    // populates; tempdir-rooted so executor work doesn't escape the
    // process.
    let wd = work_dir_str.clone();
    let runtime_producer: RuntimeProducer = Arc::new(move |_| {
        use ballista::datafusion::execution::runtime_env::RuntimeEnvBuilder;
        Ok(Arc::new(
            RuntimeEnvBuilder::new()
                .with_temp_file_path(wd.clone())
                .build()?,
        ))
    });

    let executor = Arc::new(Executor::with_default_execution_engine(
        executor_meta,
        &work_dir_str,
        runtime_producer,
        config_producer,
        Arc::default(),
        Arc::new(LoggingMetricsCollector::default()),
        concurrent_tasks,
    ));

    // Codec: registry-aware federation codec so a `FederatedPlanNode`
    // arriving over the wire decodes back to the correct connector
    // dispatch. Mirrors `build_executor_process_config`'s codec
    // construction for the plaintext path.
    let logical_codec: Arc<dyn LogicalExtensionCodec> =
        Arc::new(FederationLogicalCodec::with_registry(Arc::clone(registry)));
    let physical_codec: Arc<dyn PhysicalExtensionCodec> = if registry.is_empty() {
        Arc::new(BallistaPhysicalExtensionCodec::default())
    } else {
        Arc::new(
            FederationPlanCodec::with_logical_codec(
                Arc::clone(registry),
                Arc::clone(&logical_codec),
            )
            .with_inner_physical_codec(Arc::new(BallistaPhysicalExtensionCodec::default())),
        )
    };
    let codec: BallistaCodec<LogicalPlanNode, PhysicalPlanNode> =
        BallistaCodec::new(logical_codec, physical_codec);

    // Flight service with TLS on the data-plane port.
    let flight_service = FlightServiceServer::new(BallistaFlightService::new(work_dir_str.clone()))
        .max_decoding_message_size(GRPC_MAX_MESSAGE_SIZE_BYTES)
        .max_encoding_message_size(GRPC_MAX_MESSAGE_SIZE_BYTES);
    let server_tls = tls.server_tls_config();

    tracing::info!(
        flight_addr = %flight_addr,
        executor_id = %executor_id,
        scheduler = %format!("https://{}:{}", args.scheduler_host, args.scheduler_port),
        "executor: serving Flight with server-side TLS + pull-mode dispatch (slice 7b)"
    );

    let flight_handle = tokio::spawn(async move {
        Server::builder()
            .tls_config(server_tls)
            .map_err(|e| DataglotError::Internal(format!("flight TLS config failed: {e}")))?
            .add_service(flight_service)
            .serve(flight_addr)
            .await
            .map_err(|e| DataglotError::Internal(format!("flight serve loop exited: {e}")))
    });

    // Connect to the scheduler with client TLS. The `https://` scheme
    // is required when TLS is configured (tonic refuses TLS over an
    // `http://` URL).
    let scheduler_url = format!("https://{}:{}", args.scheduler_host, args.scheduler_port);
    let endpoint = create_grpc_client_endpoint(scheduler_url.clone(), None)
        .map_err(|e| {
            DataglotError::Configuration(format!("scheduler endpoint construction failed: {e}"))
        })?
        .tls_config(tls.client_tls_config())
        .map_err(|e| {
            DataglotError::Configuration(format!("scheduler client TLS config failed: {e}"))
        })?;
    let connection = endpoint.connect().await.map_err(|e| {
        DataglotError::Internal(format!("scheduler connect failed at {scheduler_url}: {e}"))
    })?;

    let scheduler = SchedulerGrpcClient::new(connection)
        .max_encoding_message_size(GRPC_MAX_MESSAGE_SIZE_BYTES)
        .max_decoding_message_size(GRPC_MAX_MESSAGE_SIZE_BYTES);

    let poll_handle =
        tokio::spawn(async move { execution_loop::poll_loop(scheduler, executor, codec).await });

    // Either task exiting means the executor is no longer functional —
    // surface the error and shut down.
    tokio::select! {
        result = flight_handle => {
            result
                .map_err(|e| DataglotError::Internal(format!("flight task panicked: {e}")))?
        }
        result = poll_handle => {
            result
                .map_err(|e| DataglotError::Internal(format!("poll task panicked: {e}")))?
                .map_err(|e| DataglotError::Internal(format!("poll loop exited: {e}")))?;
            Ok(())
        }
    }
}

/// Fallback for `concurrent_tasks` when the CLI flag is omitted and
/// `num_cpus` isn't available. Match `ExecutorProcessConfig::default()`'s
/// behavior of using `std::thread::available_parallelism`.
fn num_cpus_logical_fallback() -> usize {
    std::thread::available_parallelism().map_or(2, std::num::NonZeroUsize::get)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fallback_returns_at_least_one() {
        // Smoke test the fallback doesn't return 0 — `poll_loop`
        // would deadlock immediately with zero task slots.
        assert!(num_cpus_logical_fallback() >= 1);
    }

    /// Confirms the GRPC message-size constant matches Apache's
    /// `mtls-cluster.rs` reference — 16 MiB. If a future Ballista bump
    /// changes the convention, this test fails loud so the constant
    /// stays in sync with upstream rather than silently drifting.
    #[test]
    fn grpc_max_message_size_matches_apache_reference() {
        assert_eq!(GRPC_MAX_MESSAGE_SIZE_BYTES, 16 * 1024 * 1024);
    }
}

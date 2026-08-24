//! In-process standalone Ballista cluster **with the scheduler REST API
//! served** — the enabler for live cluster monitoring in the testbench
//! (executors, jobs, per-stage progress, execution-DAG graphs).
//!
//! ## Why this module replicates upstream code
//!
//! Ballista's scheduler ships a full observability REST surface
//! (`ballista_scheduler::api::get_routes`: `/api/state`, `/api/executors`,
//! `/api/jobs`, `/api/job/{id}/stages`, `/api/job/{id}/dot[_svg]`,
//! `/api/metrics`) — but only the *multi-process* scheduler binary mounts
//! it. The standalone helpers (`new_standalone_scheduler_from_state`)
//! construct the `SchedulerServer`, spawn its gRPC service, and **discard
//! the handle**, so an in-process cluster has no way to serve those
//! routes. This module is upstream's ~40-line standalone boot
//! (`ballista-scheduler/src/standalone.rs` + the executor half of
//! `ballista/src/extension.rs::setup_standalone`) with one change: the
//! `SchedulerServer` handle is kept and its REST router is served on a
//! caller-chosen port.
//!
//! Tracked against upstream 53.0.0 — if a Ballista release exposes the
//! handle (or mounts the API) from the standalone path, delete this and
//! call theirs.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use ballista::datafusion::execution::SessionState;
use ballista::datafusion::prelude::{SessionConfig as DfSessionConfig, SessionContext};
use ballista_core::extension::{SessionConfigExt, SessionStateExt};
use ballista_core::serde::protobuf::scheduler_grpc_client::SchedulerGrpcClient;
use ballista_core::serde::protobuf::scheduler_grpc_server::SchedulerGrpcServer;
use ballista_core::serde::BallistaCodec;
use ballista_core::utils::{create_grpc_server, GrpcServerConfig};
use ballista_scheduler::config::SchedulerConfig;
use ballista_scheduler::metrics::default_metrics_collector;
use ballista_scheduler::scheduler_server::SchedulerServer;
use datafusion_proto::protobuf::{LogicalPlanNode, PhysicalPlanNode};
use dataglot_core::error::{DataglotError, Result};

/// A booted in-process cluster: the client context plus where the
/// scheduler's REST API ended up (if requested).
pub struct MonitoredStandalone {
    /// Ballista-backed `SessionContext` driving the cluster — the same
    /// thing `SessionContext::standalone_with_state` returns.
    pub context: SessionContext,
    /// Where the scheduler observability REST API is listening
    /// (`/api/state`, `/api/executors`, `/api/jobs`, …), when an
    /// `api_bind` was given and the bind succeeded.
    pub api_addr: Option<SocketAddr>,
}

/// Boot a standalone (in-process) Ballista cluster from `session_state`,
/// optionally serving the scheduler's observability REST API on
/// `api_bind`.
///
/// Behaviourally identical to
/// `SessionContext::standalone_with_state(session_state)` — same
/// scheduler config (pull-staged policy), same gRPC bring-up, same
/// executor — plus the REST router. An `api_bind` of `None` gives
/// exactly the upstream shape (no API listener).
///
/// A failed API bind (port in use) is downgraded to a WARN and
/// `api_addr: None` rather than failing the cluster: monitoring is an
/// observability add-on, never a reason queries can't run.
///
/// # Errors
/// Same failure surface as upstream standalone bring-up: scheduler gRPC
/// bind, executor registration, or client-state construction.
pub async fn boot_monitored_standalone(
    session_state: &SessionState,
    api_bind: Option<SocketAddr>,
    executor_timeout_seconds: u64,
) -> Result<MonitoredStandalone> {
    let internal = |e: &dyn std::fmt::Display, what: &str| {
        DataglotError::Internal(format!("ballista standalone {what}: {e}"))
    };

    // ---- scheduler (upstream standalone.rs, handle kept) --------------
    // Pull-staged to match the in-process executor booted below (the
    // same pairing upstream's standalone uses).
    let (scheduler_server, grpc_addr) = boot_scheduler_from_state(
        session_state,
        ballista_core::config::TaskSchedulingPolicy::PullStaged,
        executor_timeout_seconds,
    )
    .await?;

    // ---- REST observability API (the reason this module exists) -------
    let api_addr = serve_rest_api(&scheduler_server, api_bind).await;

    // ---- executor (upstream extension.rs::setup_standalone) -----------
    let scheduler_url = format!("http://localhost:{}", grpc_addr.port());
    let mut attempts: u32 = 0;
    let scheduler_client = loop {
        match SchedulerGrpcClient::connect(scheduler_url.clone()).await {
            Err(e) => {
                attempts += 1;
                // A wedged in-process scheduler (bind failure upstream,
                // resource exhaustion) would otherwise retry forever at
                // debug — invisible at default log level. Escalate to warn
                // roughly every 5s so a stuck boot is diagnosable, and log
                // the connection error either way.
                if attempts.is_multiple_of(50) {
                    tracing::warn!(
                        attempts,
                        error = %e,
                        "still waiting for in-process ballista scheduler grpc after ~{}s",
                        attempts / 10
                    );
                } else {
                    tracing::debug!(error = %e, "waiting for in-process ballista scheduler grpc...");
                }
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            }
            Ok(client) => break client,
        }
    };
    let concurrent_tasks = session_state.config().ballista_standalone_parallelism();
    ballista_executor::new_standalone_executor_from_state(
        scheduler_client,
        concurrent_tasks,
        session_state,
    )
    .await
    .map_err(|e| internal(&e, "executor bring-up"))?;

    // ---- client context (upstream extension.rs) ------------------------
    // `upgrade_for_ballista` — NOT `new_ballista_state` — because it
    // carries the caller's session config forward, including the
    // `ballista_logical_extension_codec` the federation wiring installs.
    // `new_ballista_state` builds a *default*-codec client (the shape
    // upstream's `remote()` uses), which silently breaks every custom
    // `TableProvider` at plan-serialization time:
    // `NotImplemented("LogicalExtensionCodec is not provided")` on any
    // federated (pg/mysql/snowflake) query. This is exactly what
    // upstream's `standalone_with_state` does with the same state
    // ( — the initial version of this module got it wrong).
    let client_state = session_state
        .clone()
        .upgrade_for_ballista(scheduler_url.clone())
        .map_err(|e| internal(&e, "client state"))?;
    // Cancel-on-drop: abandoning a result stream (pgwire
    // cancel, dropped connection) must cancel the Ballista job, not
    // orphan it on the executors. Decorates the planner the upgrade
    // installed; `BallistaCluster::create_session` inherits it through
    // `template.query_planner()`.
    let planner = Arc::new(crate::cancel_on_drop::CancelOnDropQueryPlanner::new(
        Arc::clone(client_state.query_planner()),
        scheduler_url,
    ));
    // Pull-mode CLIENT to pair with this module's pull-staged
    // scheduler ( finding): the default push-mode client learns
    // the job id from scheduler-pushed status events, but a pull-staged
    // scheduler only emits the *terminal* event — so a long-running
    // job's id is unknowable client-side and an abandoned query could
    // not be cancelled. The pull client gets the id synchronously from
    // `ExecuteQuery` and polls status every 50ms (same order as the
    // push path's dispatch latency for short queries).
    let client_config = client_state
        .config()
        .clone()
        .set_str(ballista_core::config::BALLISTA_CLIENT_PULL, "true");
    let client_state =
        ballista::datafusion::execution::session_state::SessionStateBuilder::new_from_existing(
            client_state,
        )
        .with_config(client_config)
        .with_query_planner(planner)
        .build();
    Ok(MonitoredStandalone {
        context: SessionContext::new_with_state(client_state),
        api_addr,
    })
}

/// Boot a codec-carrying standalone scheduler from `session_state` with
/// an explicit [`TaskSchedulingPolicy`], returning the live
/// `SchedulerServer` handle and the bound gRPC address.
///
/// Extracted from [`boot_monitored_standalone`] so multi-process tests
/// can pair a scheduler with the **real executor binary** — which boots
/// with Ballista's default `PushStaged` policy. Upstream's standalone
/// helper hard-codes `PullStaged`; pairing that with a push-mode
/// subprocess executor queues every job forever (the executor waits to
/// be pushed tasks, the scheduler waits to be polled — 's first
/// live run hung exactly there).
///
/// [`TaskSchedulingPolicy`]: ballista_core::config::TaskSchedulingPolicy
///
/// # Errors
/// Scheduler init or gRPC bind failure.
pub async fn boot_scheduler_from_state(
    session_state: &SessionState,
    policy: ballista_core::config::TaskSchedulingPolicy,
    executor_timeout_seconds: u64,
) -> Result<(
    SchedulerServer<LogicalPlanNode, PhysicalPlanNode>,
    SocketAddr,
)> {
    // Ephemeral gRPC port — the in-process/standalone callers hand the bound
    // address straight to the executor they boot, so the port needn't be
    // known ahead of time.
    boot_scheduler_from_state_on(
        session_state,
        policy,
        "localhost:0",
        executor_timeout_seconds,
    )
    .await
}

/// As [`boot_scheduler_from_state`], but binds the scheduler gRPC listener to
/// a caller-chosen address instead of an ephemeral port.
///
/// Needed by [`boot_monitored_scheduler_only`]: **external** executor
/// processes are spawned separately (by the testbench launcher) and must be
/// told the scheduler port up front, so it has to be pinnable. The advertised
/// name is derived from the bound port either way, so a push-staged executor
/// connecting *back* still reaches a listening socket (the  wedge).
///
/// # Errors
/// Scheduler init or gRPC bind failure.
/// Build the embedded scheduler's config: upstream defaults, our task
/// policy, and the caller's executor-liveness timeout.
///
/// `executor_timeout_seconds` is how long the scheduler tolerates a silent
/// executor before declaring it dead. Upstream's default is 180s, which
/// culls healthy external executors whenever the host pauses longer than
/// that (laptop sleep, load spike, a long idle between interactive queries),
/// leaving the cluster with zero workers and every in-flight job stuck at 0%
///. Callers pass a wider value — `DataglotServer` from the
/// `[ballista]` config's `executor_timeout_seconds` (default 3600). Split
/// out so a unit test can pin the wiring without booting a scheduler.
fn scheduler_config(
    policy: ballista_core::config::TaskSchedulingPolicy,
    executor_timeout_seconds: u64,
) -> SchedulerConfig {
    let mut config = SchedulerConfig::default().with_scheduler_policy(policy);
    config.executor_timeout_seconds = executor_timeout_seconds;
    config
}

async fn boot_scheduler_from_state_on(
    session_state: &SessionState,
    policy: ballista_core::config::TaskSchedulingPolicy,
    grpc_bind: &str,
    executor_timeout_seconds: u64,
) -> Result<(
    SchedulerServer<LogicalPlanNode, PhysicalPlanNode>,
    SocketAddr,
)> {
    let internal = |e: &dyn std::fmt::Display, what: &str| {
        DataglotError::Internal(format!("ballista standalone {what}: {e}"))
    };
    let logical = session_state.config().ballista_logical_extension_codec();
    let physical = session_state.config().ballista_physical_extension_codec();
    let codec: BallistaCodec<LogicalPlanNode, PhysicalPlanNode> =
        BallistaCodec::new(logical, physical);
    let session_config = session_state.config().clone();
    let state_for_builder = session_state.clone();
    let session_builder = Arc::new(move |_: DfSessionConfig| Ok(state_for_builder.clone()));
    let config_producer = Arc::new(move || session_config.clone());

    // Bind BEFORE constructing the server so the advertised scheduler
    // name is the address that actually listens. Upstream's standalone
    // hard-codes "localhost:50050" as the advertise name while binding
    // an ephemeral port — harmless for pull-staged in-process executors
    // (they poll the address they were given), but a push-staged
    // executor connects BACK to the advertised name and gets
    // connection-refused, silently wedging every job (found via the
    //  multi-process harness diagnostics).
    let listener = tokio::net::TcpListener::bind(grpc_bind)
        .await
        .map_err(|e| internal(&e, "scheduler grpc bind"))?;
    let grpc_addr = listener
        .local_addr()
        .map_err(|e| internal(&e, "scheduler grpc addr"))?;
    let advertise = format!("{}:{}", advertise_host(grpc_addr.ip()), grpc_addr.port());

    let cluster = ballista_scheduler::cluster::BallistaCluster::new_memory(
        advertise.clone(),
        session_builder,
        config_producer,
    );
    let metrics_collector =
        default_metrics_collector().map_err(|e| internal(&e, "metrics collector"))?;
    let mut scheduler_server: SchedulerServer<LogicalPlanNode, PhysicalPlanNode> =
        SchedulerServer::new(
            advertise,
            cluster,
            codec,
            Arc::new(scheduler_config(policy, executor_timeout_seconds)),
            metrics_collector,
        );
    scheduler_server
        .init()
        .await
        .map_err(|e| internal(&e, "scheduler init"))?;

    let max_message_size = session_state
        .config()
        .ballista_grpc_client_max_message_size();
    let grpc_service = SchedulerGrpcServer::new(scheduler_server.clone())
        .max_decoding_message_size(max_message_size)
        .max_encoding_message_size(max_message_size);
    tokio::spawn(
        create_grpc_server(&GrpcServerConfig::default())
            .add_service(grpc_service)
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener)),
    );
    Ok((scheduler_server, grpc_addr))
}

/// The host an executor (or client) should dial to reach a scheduler bound to
/// `ip`. A wildcard (`0.0.0.0`/`::`) or loopback bind is reachable via
/// `localhost`; a specific interface IP must be advertised verbatim (IPv6
/// bracketed) — otherwise a push-staged executor connects back to the wrong
/// name and gets connection-refused, wedging every job (gemini review,;
/// same class as the  advertise wedge).
fn advertise_host(ip: IpAddr) -> String {
    if ip.is_unspecified() || ip.is_loopback() {
        "localhost".to_string()
    } else {
        match ip {
            IpAddr::V4(v4) => v4.to_string(),
            IpAddr::V6(v6) => format!("[{v6}]"),
        }
    }
}

/// Bind `api_bind` (if any) and serve the scheduler's REST router on it.
/// A failed bind is a WARN + `None` — monitoring is additive and never a
/// reason the cluster can't run.
async fn serve_rest_api(
    scheduler_server: &SchedulerServer<LogicalPlanNode, PhysicalPlanNode>,
    api_bind: Option<SocketAddr>,
) -> Option<SocketAddr> {
    let bind = api_bind?;
    match tokio::net::TcpListener::bind(bind).await {
        Ok(api_listener) => {
            let addr = api_listener.local_addr().ok();
            let router = ballista_scheduler::api::get_routes(Arc::new(scheduler_server.clone()));
            tokio::spawn(async move {
                if let Err(e) = axum::serve(api_listener, router).await {
                    tracing::warn!(error = %e, "ballista scheduler REST API server exited");
                }
            });
            tracing::info!(addr = ?addr, "ballista scheduler REST API serving");
            addr
        }
        Err(e) => {
            tracing::warn!(
                bind = %bind,
                error = %e,
                "ballista scheduler REST API bind failed; cluster runs without it"
            );
            None
        }
    }
}

/// A scheduler-only monitored cluster: an in-process scheduler + REST monitor
/// API + a client context, but **no in-process executor**. Executors are
/// separate processes that register over gRPC (the testbench spawns them).
/// See [`boot_monitored_scheduler_only`].
pub struct MonitoredScheduler {
    /// Ballista-backed client `SessionContext` that submits queries to the
    /// scheduler (push-mode — paired with push-staged external executors).
    pub context: SessionContext,
    /// Where the scheduler observability REST API listens (`/api/state`,
    /// `/api/executors`, …), when an `api_bind` was given and bound.
    pub api_addr: Option<SocketAddr>,
    /// The scheduler's gRPC address — where external executor processes
    /// register (`--scheduler-host` / `--scheduler-port`).
    pub grpc_addr: SocketAddr,
}

/// Boot a **scheduler-only** monitored cluster from `session_state`: a
/// push-staged scheduler bound to `grpc_bind`, the REST monitor API on
/// `api_bind`, and a push-mode client context — but **no in-process
/// executor**. External `dataglot-ballista-executor` processes register with
/// the returned [`MonitoredScheduler::grpc_addr`] to form the worker pool.
///
/// This is the multi-executor counterpart to [`boot_monitored_standalone`]
///. The differences are deliberate and load-bearing:
/// * **`PushStaged`** policy (not `PullStaged`) — real executor binaries boot
///   push-mode; a pull-staged scheduler would queue every job forever
/// * **Pinnable gRPC port** (`grpc_bind`) — the launcher spawns executors
///   separately and must know the port up front.
/// * **No embedded executor** and a **push-mode client** (no
///   `BALLISTA_CLIENT_PULL`) — the pull client only exists to pair with the
///   in-process pull executor, which isn't here.
///
/// Codec parity is preserved exactly as in [`boot_monitored_standalone`]:
/// the client is minted via `upgrade_for_ballista` (carrying the caller's
/// `ballista_logical_extension_codec`), never `new_ballista_state`, so
/// federated (`pg`/`mysql`/…) plans serialize across the wire.
///
/// # Errors
/// Scheduler bind/init, or client-state construction failure.
pub async fn boot_monitored_scheduler_only(
    session_state: &SessionState,
    api_bind: Option<SocketAddr>,
    grpc_bind: &str,
    executor_timeout_seconds: u64,
) -> Result<MonitoredScheduler> {
    let internal = |e: &dyn std::fmt::Display, what: &str| {
        DataglotError::Internal(format!("ballista scheduler-only {what}: {e}"))
    };

    let (scheduler_server, grpc_addr) = boot_scheduler_from_state_on(
        session_state,
        ballista_core::config::TaskSchedulingPolicy::PushStaged,
        grpc_bind,
        executor_timeout_seconds,
    )
    .await?;

    let api_addr = serve_rest_api(&scheduler_server, api_bind).await;

    // Push-mode client carrying the caller's codec (see the doc note and
    // `boot_monitored_standalone` for why `upgrade_for_ballista`, not
    // `new_ballista_state`). No `BALLISTA_CLIENT_PULL`: that's only for the
    // in-process pull executor, which this path doesn't run.
    let scheduler_url = format!(
        "http://{}:{}",
        advertise_host(grpc_addr.ip()),
        grpc_addr.port()
    );
    let client_state = session_state
        .clone()
        .upgrade_for_ballista(scheduler_url.clone())
        .map_err(|e| internal(&e, "client state"))?;
    // Cancel-on-drop: a dropped pgwire connection must cancel the
    // Ballista job, not orphan tasks on the executors.
    let planner = Arc::new(crate::cancel_on_drop::CancelOnDropQueryPlanner::new(
        Arc::clone(client_state.query_planner()),
        scheduler_url,
    ));
    let client_state =
        ballista::datafusion::execution::session_state::SessionStateBuilder::new_from_existing(
            client_state,
        )
        .with_query_planner(planner)
        .build();

    Ok(MonitoredScheduler {
        context: SessionContext::new_with_state(client_state),
        api_addr,
        grpc_addr,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::factory::BallistaContextFactory;

    /// Boot the scheduler-only monitored cluster: scheduler + REST
    /// API + push-mode client, but NO in-process executor. Proves the exact
    /// shape the multi-executor testbench relies on — the worker pool is
    /// external, so `/api/executors` is empty until a process registers.
    #[test]
    fn advertise_host_maps_wildcard_and_loopback_to_localhost() {
        // Wildcard (0.0.0.0 — the multi-executor default) and loopback both
        // reach the scheduler via localhost.
        assert_eq!(advertise_host("0.0.0.0".parse().unwrap()), "localhost");
        assert_eq!(advertise_host("127.0.0.1".parse().unwrap()), "localhost");
        assert_eq!(advertise_host("::".parse().unwrap()), "localhost");
        assert_eq!(advertise_host("::1".parse().unwrap()), "localhost");
        // A specific interface IP is advertised verbatim (IPv6 bracketed) so
        // executors dial the right name.
        assert_eq!(
            advertise_host("192.168.1.100".parse().unwrap()),
            "192.168.1.100"
        );
        assert_eq!(
            advertise_host("2001:db8::5".parse().unwrap()),
            "[2001:db8::5]"
        );
    }

    #[tokio::test]
    async fn monitored_scheduler_only_has_no_inprocess_executor() {
        let factory = BallistaContextFactory::with_defaults();
        let state = factory.build_federated_state();
        let boot = boot_monitored_scheduler_only(
            &state,
            Some("127.0.0.1:0".parse().unwrap()),
            "localhost:0",
            3600,
        )
        .await
        .expect("scheduler-only boots");
        let api = boot.api_addr.expect("REST API bound");

        // Push-mode client — the opposite of the standalone's pull client;
        // it pairs with push-staged *external* executors (/).
        assert!(
            !boot
                .context
                .state()
                .config()
                .ballista_config()
                .client_pull(),
            "scheduler-only client must be push-mode (external push-staged executors)"
        );

        // The scheduler answers…
        let body = reqwest_lite(&format!("http://{api}/api/state")).await;
        assert!(
            body.contains("started") || body.contains("version"),
            "scheduler state endpoint should answer, got: {body}"
        );

        // …but NO executor is registered — the whole point: the worker pool
        // is external. (Registration is async in the standalone case; here
        // there is simply nothing to register.)
        let executors = reqwest_lite(&format!("http://{api}/api/executors")).await;
        assert!(
            !executors.contains("executor_id") && !executors.contains("\"id\""),
            "scheduler-only must have no in-process executor, got: {executors}"
        );

        // The gRPC port is a real bound port external executors can target.
        assert_ne!(boot.grpc_addr.port(), 0, "scheduler gRPC must be bound");
    }

    /// Boot the monitored standalone and hit the REST API — proves the
    /// whole point of the module: an in-process cluster whose scheduler
    /// state is observable over HTTP. `SELECT` through the returned
    /// context afterwards pins that monitoring didn't break execution.
    #[tokio::test]
    #[allow(clippy::too_many_lines)] // boot + REST assertions + chain pin in one boot
    async fn monitored_standalone_serves_rest_api_and_executes() {
        let factory = BallistaContextFactory::with_defaults();
        let (context, api_addr) = factory
            .create_monitored_standalone_context(Some("127.0.0.1:0".parse().unwrap()))
            .await
            .expect("monitored standalone boots");
        let boot = MonitoredStandalone { context, api_addr };
        let api = boot.api_addr.expect("REST API bound");

        //  pairing pin: this standalone boots a PULL-staged
        // scheduler, so the client must be pull-mode too — a push-mode
        // client only receives *terminal* status events from a
        // pull-staged scheduler, which makes a long-running job's id
        // unknowable and cancel-on-drop impossible.
        assert!(
            boot.context
                .state()
                .config()
                .ballista_config()
                .client_pull(),
            "standalone client must be pull-mode to pair with the \
             pull-staged scheduler"
        );

        //  chain pin: the monitored context must carry the
        // CancelOnDropQueryPlanner decorating the BallistaQueryPlanner, so
        // abandoning a result stream (pgwire cancel / dropped connection)
        // cancels the distributed job instead of orphaning it on the
        // executors. A boot test that only checks execution would keep
        // passing even if the cancel decorator were dropped.
        let planner = format!("{:?}", boot.context.state().query_planner());
        let cancel = planner
            .find("CancelOnDropQueryPlanner")
            .expect("monitored context must wrap the planner in CancelOnDropQueryPlanner");
        let ballista = planner
            .find("BallistaQueryPlanner")
            .expect("monitored context must dispatch through a BallistaQueryPlanner");
        assert!(
            cancel < ballista,
            "CancelOnDrop must wrap (be outside) the BallistaQueryPlanner, got: {planner}"
        );

        // /api/state answers with scheduler metadata.
        let body = reqwest_lite(&format!("http://{api}/api/state")).await;
        assert!(
            body.contains("started") || body.contains("version"),
            "scheduler state endpoint should answer, got: {body}"
        );

        // /api/executors lists the in-process executor once it registers.
        // Registration is async — poll briefly.
        let mut executors = String::new();
        for _ in 0..50 {
            executors = reqwest_lite(&format!("http://{api}/api/executors")).await;
            if executors.contains("executor_id") || executors.contains("\"id\"") {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        assert!(
            executors.contains("executor_id") || executors.contains("\"id\""),
            "executor should register and appear in /api/executors, got: {executors}"
        );

        // The cluster still executes queries. Bounded ( #3): the
        // standalone boot pairs a pull-staged scheduler with a
        // pull-mode in-process executor — if someone flips the policy
        // on one side only, the job queues forever and this would hang
        // CI instead of failing. The timeout converts that
        // reintroduction into a clean, named failure.
        let batches = tokio::time::timeout(std::time::Duration::from_mins(1), async {
            boot.context
                .sql("SELECT 1 + 1 AS two")
                .await
                .expect("plans")
                .collect()
                .await
                .expect("executes")
        })
        .await
        .expect(
            "standalone query hung 60s — scheduling-policy mismatch? \
             boot_monitored_standalone must pair PullStaged with the \
             in-process (pull-mode) executor",
        );
        assert_eq!(batches[0].num_rows(), 1);

        // /api/metrics serves Prometheus exposition text: this
        // endpoint is the documented scrape target for cluster metrics —
        // pin it so an upstream route change can't silently break the
        // monitoring story in docs/configuration.md.
        let metrics = reqwest_lite(&format!("http://{api}/api/metrics")).await;
        assert!(
            metrics.contains("# TYPE") || metrics.contains("# HELP"),
            "scheduler /api/metrics should serve Prometheus text, got: {metrics}"
        );

        // Upstream-payload canary: the testbench's Cluster tab
        // reads these exact field names from Ballista's REST payloads
        // with a *tolerant* parser — an upstream rename would silently
        // blank the tab instead of failing a test. Pin the shape here so
        // a Ballista upgrade turns silent degradation into a red build.
        // Consumers: crates/dataglot-testbench/frontend/src/routes/Cluster.tsx.
        let jobs = get_json(&format!("http://{api}/api/jobs")).await;
        let jobs = jobs["jobs"]
            .as_array()
            .cloned()
            .unwrap_or_else(|| jobs.as_array().cloned().expect("jobs array"));
        let job = jobs
            .first()
            .expect("the executed query must appear as a job");
        for key in [
            "job_id",
            "job_status",
            "num_stages",
            "start_time",
            "end_time",
        ] {
            assert!(
                job.get(key).is_some(),
                "JobResponse lost field '{key}' — update the Cluster tab \
                 (jobs table / duration column / stage-tax) with this \
                 upgrade. Payload: {job}"
            );
        }

        let job_id = job["job_id"].as_str().expect("job_id is a string");
        let stages = get_json(&format!("http://{api}/api/job/{job_id}/stages")).await;
        let stages = stages["stages"]
            .as_array()
            .cloned()
            .unwrap_or_else(|| stages.as_array().cloned().expect("stages array"));
        let stage = stages.first().expect("job has at least one stage");
        for key in [
            "stage_id",
            "stage_status",
            "input_rows",
            "output_rows",
            "elapsed_compute",
        ] {
            assert!(
                stage.get(key).is_some(),
                "QueryStageSummary lost field '{key}' — update the Cluster \
                 tab's stage cards / stage-tax parser with this upgrade. \
                 Payload: {stage}"
            );
        }
    }

    ///  regression pin — the monitored standalone's client context
    /// (and every per-session context minted from a cluster around it,
    /// which is how `DataglotServer` serves pgwire connections) must
    /// carry the factory's configured `LogicalExtensionCodec`.
    ///
    /// The original monitor boot built the client via
    /// `SessionState::new_ballista_state` — a *default*-codec context —
    /// so any federated `TableProvider` failed at plan-serialization
    /// time with `NotImplemented("LogicalExtensionCodec is not
    /// provided")`. The fix routes through `upgrade_for_ballista`,
    /// which preserves the session config (codec included). Pointer
    /// identity is the strongest observable: same `Arc`, not just same
    /// type.
    #[tokio::test]
    async fn monitored_standalone_sessions_keep_the_configured_codec() {
        use datafusion_proto::logical_plan::LogicalExtensionCodec;

        let codec: Arc<dyn LogicalExtensionCodec> =
            Arc::new(crate::codec::FederationLogicalCodec::default());
        let factory =
            BallistaContextFactory::with_defaults().with_logical_codec(Arc::clone(&codec));

        // No REST API: not under test, and a bind is one more flake source.
        let (cluster, api_addr) = factory
            .boot_monitored_standalone_cluster(None)
            .await
            .expect("monitored standalone cluster boots");
        assert!(api_addr.is_none(), "no API requested");

        // The reference (client) context carries OUR codec…
        let reference_codec = cluster
            .reference_session()
            .state()
            .config()
            .ballista_logical_extension_codec();
        assert!(
            Arc::ptr_eq(&reference_codec, &codec),
            "client context must keep the factory's codec — a default \
             codec here reintroduces the capability-boundary bug (federation queries fail to \
             serialize in distributed mode)"
        );

        // …and so does every per-session context minted the way
        // `DataglotServer` mints pgwire sessions.
        let session = cluster.create_session();
        let session_codec = session.state().config().ballista_logical_extension_codec();
        assert!(
            Arc::ptr_eq(&session_codec, &codec),
            "per-session contexts must inherit the codec from the \
             reference context"
        );
    }

    /// Minimal HTTP GET without pulling a client crate into the deps:
    /// the endpoints are plain HTTP/1.1 + JSON on loopback.
    /// GET `url` and parse the body as JSON. Speaks HTTP/1.0 so hyper
    /// answers with a Content-Length body (no chunked framing to strip).
    async fn get_json(url: &str) -> serde_json::Value {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let url = url.strip_prefix("http://").unwrap();
        let (host, path) = url.split_once('/').unwrap();
        let mut stream = tokio::net::TcpStream::connect(host).await.expect("connect");
        stream
            .write_all(format!("GET /{path} HTTP/1.0\r\nHost: {host}\r\n\r\n").as_bytes())
            .await
            .expect("write");
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.expect("read");
        let raw = String::from_utf8_lossy(&buf);
        let body = raw
            .split_once("\r\n\r\n")
            .map(|(_, b)| b)
            .unwrap_or_default();
        serde_json::from_str(body)
            .unwrap_or_else(|e| panic!("{url} returned non-JSON ({e}): {body}"))
    }

    async fn reqwest_lite(url: &str) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let url = url.strip_prefix("http://").unwrap();
        let (host, path) = url.split_once('/').unwrap();
        let mut stream = tokio::net::TcpStream::connect(host).await.expect("connect");
        stream
            .write_all(
                format!("GET /{path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n")
                    .as_bytes(),
            )
            .await
            .expect("write");
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.expect("read");
        String::from_utf8_lossy(&buf).into_owned()
    }

    /// `scheduler_config` must carry the caller's executor-liveness timeout
    /// onto the `SchedulerConfig` — the knob that lets `DataglotServer` widen
    /// it past upstream's 180s default so a host idle/pause doesn't cull
    /// healthy executors and strand distributed jobs at 0%.
    #[test]
    fn scheduler_config_applies_executor_timeout() {
        let cfg = scheduler_config(
            ballista_core::config::TaskSchedulingPolicy::PushStaged,
            3600,
        );
        assert_eq!(cfg.executor_timeout_seconds, 3600);
        // A distinct value flows through unchanged (not hardcoded).
        let cfg2 = scheduler_config(ballista_core::config::TaskSchedulingPolicy::PullStaged, 42);
        assert_eq!(cfg2.executor_timeout_seconds, 42);
    }

    /// The scheduling policy must land on the returned `SchedulerConfig`, not
    /// just the timeout. A push-vs-pull mismatch between scheduler and
    /// executors wedges every job forever, so pin that the caller's
    /// choice is actually applied.
    #[test]
    fn scheduler_config_applies_policy() {
        use ballista_core::config::TaskSchedulingPolicy;
        let push = scheduler_config(TaskSchedulingPolicy::PushStaged, 3600);
        assert!(matches!(
            push.scheduling_policy,
            TaskSchedulingPolicy::PushStaged
        ));
        let pull = scheduler_config(TaskSchedulingPolicy::PullStaged, 3600);
        assert!(matches!(
            pull.scheduling_policy,
            TaskSchedulingPolicy::PullStaged
        ));
    }

    /// A 0-second timeout is passed through verbatim (immediate cull) — pin
    /// the boundary as intentional pass-through, not an accidental default.
    #[test]
    fn scheduler_config_passes_zero_timeout_verbatim() {
        let cfg = scheduler_config(ballista_core::config::TaskSchedulingPolicy::PushStaged, 0);
        assert_eq!(cfg.executor_timeout_seconds, 0);
    }
}

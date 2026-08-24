//! Standalone Ballista scheduler wiring for Phase 2 slice 8.2a.
//!
//! Slice 3a's `BallistaCluster` boots an in-process scheduler that
//! `standalone_with_state` hard-codes to `localhost:0` (per Ballista's
//! `ballista/scheduler/src/standalone.rs:106`). That's fine for the
//! single-process embedded path, but it can't accept connections
//! from executor containers running on another host on the docker
//! network.
//!
//! This module is the `dataglot-ballista`-side wrapper around
//! Apache Ballista's `start_server` scheduler-process entry point —
//! same shape as the executor binary in `executor.rs`. It builds a
//! `BallistaCluster` + `SchedulerConfig`, picks the bind address
//! from CLI args (`--bind-host`, `--bind-port`), and hands off to
//! Ballista's `start_server`. The scheduler then listens on the
//! configured interface and accepts gRPC registrations from
//! executor containers.
//!
//! # What this slice doesn't ship
//!
//! - **Codec parity with the executor.** Slice 5a.2's executor binary
//!   wires registry-aware `FederationLogicalCodec` +
//!   `FederationPlanCodec` from a `--catalogs-config`. This scheduler
//!   binary uses Ballista's *defaults* — no `--catalogs-config` flag,
//!   no `FederationLogicalCodec`. Federation queries dispatched
//!   through this cluster will fail at codec-decode time. TPC-H over
//!   local parquet (file-system-rooted, no federation) survives.
//!   Slice 8.2b lifts codec parity into the scheduler.
//! - **`CredentialResolver` injection.** The scheduler doesn't run
//!   per-task `SessionContext`s — those are minted on the executor
//!   side. Slice 3b's resolver plumbing lives on the executor binary
//!   (via `--credentials-config`); the scheduler doesn't need a
//!   parallel rail.
//! - **Object-store `ETag` HA between scheduler replicas.** Slice 5b's
//!   territory. This binary runs a single scheduler instance —
//!   no leader election, no failover. Suitable for the 8.2a
//!   benchmark cluster; production HA is slice 5b.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ballista_core::error::{BallistaError, Result as BallistaResult};
use ballista_scheduler::cluster::BallistaCluster;
use ballista_scheduler::config::SchedulerConfig;
use ballista_scheduler::scheduler_process::start_server;
use object_store::aws::AmazonS3Builder;
use object_store::path::Path as ObjectPath;
use object_store::ObjectStore;
use url::Url;

use crate::ha::{ClaimOutcome, LeaseError, ObjectStoreLease};

/// Parsed command-line arguments for the
/// `dataglot-ballista-scheduler` binary.
///
/// Focused subset of Ballista's stock scheduler flags — the ones
/// operators tuning a docker-compose deployment actually touch.
/// Wider configuration surface (event-loop buffer sizes, task
/// distribution policy, etc.) defaults via `SchedulerConfig::default()`.
#[derive(clap::Parser, Debug, Clone)]
#[command(
    name = "dataglot-ballista-scheduler",
    version,
    about = "Standalone Ballista scheduler for Dataglot (Phase 2 slice 8.2a).",
    long_about = "Boots a Ballista scheduler process that accepts gRPC executor \
                  registrations on the configured bind address. Wraps Apache \
                  Ballista's `start_server` scheduler-process entry. Slice 8.2a \
                  ships this without codec parity (federation queries will fail \
                  at decode); slice 8.2b lifts codec parity in."
)]
pub struct SchedulerArgs {
    /// Local address the scheduler binds its gRPC service to.
    /// Defaults to `0.0.0.0` so the scheduler is reachable from
    /// executor containers on the docker network.
    #[arg(long, default_value = "0.0.0.0")]
    pub bind_host: String,

    /// Port for the scheduler's gRPC service. Default 50050 matches
    /// Ballista's stock convention; the executor binary's
    /// `--scheduler-port` defaults the same.
    #[arg(long, default_value_t = 50050)]
    pub bind_port: u16,

    /// External hostname advertised to executors when they register.
    /// On docker-compose this is the service hostname (e.g. `scheduler`);
    /// on a real host this is the public DNS name or IP. Defaults to
    /// `localhost` to match Ballista's stock; deployments override.
    #[arg(long, default_value = "localhost")]
    pub external_host: String,

    /// Namespace tag for this scheduler instance. Used in log file
    /// names and (eventually) for slice 5b's object-store HA
    /// coordination. Single-scheduler 8.2a deployments leave the
    /// default.
    #[arg(long, default_value = "dataglot")]
    pub namespace: String,

    /// Phase 2 slice 5b — object-store URL where the scheduler-HA
    /// lease lives. When unset, the scheduler runs single-instance
    /// (slice 8.2a behaviour, backward compatible). When set, two
    /// or more scheduler processes compete for the lease via
    /// `PutMode::Create` / `PutMode::Update(etag)` conditional
    /// writes; only the holder serves gRPC.
    ///
    /// The backend **must support conditional updates** (`PutMode::Update`
    /// with an ETag) — that's the primitive leader heartbeat renewal is
    /// built on. `s3://` (incl. S3-compatible object stores) and `gs://`
    /// do; `object_store`'s `LocalFileSystem` (`file://`) does **not**, so
    /// a `file://` lease is rejected at boot rather than letting the leader
    /// heartbeat-fail and step down forever. `memory://` is per-process, so
    /// two scheduler *processes* would never share it (split-brain) — it's
    /// only meaningful for single-process in-code tests.
    ///
    /// For `s3://`, the store is built from the standard `AWS_*` environment,
    /// so an **S3-compatible on-prem endpoint** (`MinIO`, Ceph RGW) works by
    /// setting `AWS_ENDPOINT` (+ `AWS_ALLOW_HTTP=true` for plaintext),
    /// `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and `AWS_REGION`.
    ///
    /// Examples:
    /// - `s3://my-bucket/dataglot/scheduler-lease.json`
    /// - `gs://my-bucket/dataglot/scheduler-lease.json`
    #[arg(long, value_name = "URL")]
    pub ha_state_uri: Option<String>,

    /// Lease duration in seconds. The holder must heartbeat
    /// before this elapses or lose leadership. Default 30 s is
    /// generous enough to absorb network blips while keeping
    /// failover fast.
    #[arg(long, default_value_t = 30)]
    pub ha_lease_duration_secs: u64,

    /// Heartbeat interval in seconds. Should be at least 2-3×
    /// faster than the lease duration so transient backend
    /// latency doesn't accidentally surrender leadership.
    /// Default 10 s pairs with the 30 s lease default.
    #[arg(long, default_value_t = 10)]
    pub ha_heartbeat_interval_secs: u64,

    /// Phase 2 slice 7a — mTLS material for outbound connections
    /// (the embedded flight-proxy client that fans queries to
    /// executors). All four `--tls-*` flags must be supplied together
    /// or all omitted; partial configs fail-fast at boot. The
    /// scheduler's own gRPC server listener stays plaintext until
    /// slice 7b lights up the inbound TLS path.
    #[command(flatten)]
    pub tls: crate::tls::TlsArgs,
}

impl SchedulerArgs {
    /// Materialise the scheduler config from parsed args. Fills the
    /// rest of `SchedulerConfig`'s fields from `default()`.
    #[must_use]
    pub fn build_scheduler_config(&self) -> SchedulerConfig {
        SchedulerConfig {
            namespace: self.namespace.clone(),
            external_host: self.external_host.clone(),
            bind_host: self.bind_host.clone(),
            bind_port: self.bind_port,
            ..SchedulerConfig::default()
        }
    }

    /// Resolve the bind socket address from the parsed args.
    ///
    /// # Errors
    /// Returns the underlying `AddrParseError` wrapped as `String`
    /// if `bind_host:bind_port` doesn't parse as a `SocketAddr`.
    pub fn bind_socket_addr(&self) -> Result<SocketAddr, String> {
        format!("{}:{}", self.bind_host, self.bind_port)
            .parse()
            .map_err(|e| {
                format!(
                    "bind address `{}:{}` not parseable: {e}",
                    self.bind_host, self.bind_port
                )
            })
    }
}

/// Boot the scheduler.
///
/// When `args.ha_state_uri` is `None`, runs the single-instance
/// path: build cluster + config, hand off to Ballista's
/// `start_server`, block until shutdown. This is slice 8.2a's
/// shape, preserved for backward compatibility.
///
/// When `args.ha_state_uri` is `Some(url)`, runs the slice-5b HA
/// loop: claim the object-store lease, run the scheduler when
/// holding it, abort and re-claim on heartbeat-loss. See the
/// internal `run_scheduler_ha` for the state machine.
///
/// # Errors
/// - Address parse failure when `bind_host:bind_port` is malformed
///   (surfaced as `BallistaError::Configuration`).
/// - HA lease backend / URL parse failures (also `Configuration`).
/// - Ballista's own startup errors (port-bind collision, etc.).
pub async fn run_scheduler(args: SchedulerArgs) -> BallistaResult<()> {
    crate::tls::install_default_crypto_provider();
    // Slice 7b — default-deny: a configured TLS bundle wins; without
    // one, the operator must explicitly opt out via `--insecure`.
    // Loading errors fail-fast (slice 7a `TlsArgs::load` contract).
    let tls = args.tls.load().map_err(|e| {
        BallistaError::Configuration(format!("tls flags load failed (slice 7a fail-fast): {e}"))
    })?;
    enforce_default_deny(tls.is_some(), args.tls.insecure, "scheduler")?;
    if args.ha_state_uri.is_some() {
        validate_ha_timing_args(&args)?;
        if tls.is_some() {
            // Slice 7b MVP scope: HA + TLS requires inlining
            // `run_scheduler_tls` inside the lease-holder branch of
            // the HA loop. Tracked as a slice-7b follow-up; the
            // honest thing to do for now is refuse rather than ship
            // a mixed-security configuration.
            return Err(BallistaError::Configuration(
                "scheduler: --ha-state-uri + --tls-* combination not yet supported \
                 (slice 7b follow-up). Run plaintext HA with --insecure, \
                 or single-instance TLS without --ha-state-uri."
                    .to_string(),
            ));
        }
    }

    // The long-running scheduler future for the selected mode.
    let scheduler = async move {
        if args.ha_state_uri.is_some() {
            run_scheduler_ha(args).await
        } else if let Some(ref tls_cfg) = tls {
            // TLS-mode single-instance path: bypass `start_server` and
            // attach `ServerTlsConfig` via `tonic::transport::Server::builder()`.
            crate::server::run_scheduler_tls(&args, tls_cfg).await
        } else {
            run_scheduler_single(args).await
        }
    };

    // Race it against a termination signal so SIGINT / SIGTERM produce a logged,
    // clean exit (0). Without this the scheduler ignores SIGINT (has to be
    // SIGKILLed) and SIGTERM — the signal an init system / Kubernetes sends —
    // hard-kills it with rc=143 and no shutdown log. Ballista's `start_server`
    // exposes no graceful-shutdown hook and scheduler job state is in-memory
    // (clients re-submit), so an intentional abrupt exit is the right shape here
    tokio::select! {
        res = scheduler => res,
        signal = wait_for_termination_signal() => {
            tracing::info!(%signal, "termination signal received, scheduler shutting down");
            Ok(())
        }
    }
}

/// Await the next process-termination signal, returning its name for logging.
/// On Unix both SIGINT (Ctrl-C) and SIGTERM (init / Kubernetes stop) resolve
/// here; on other platforms only Ctrl-C is available.
#[cfg(unix)]
async fn wait_for_termination_signal() -> &'static str {
    use tokio::signal::unix::{signal, SignalKind};
    let mut sigint = signal(SignalKind::interrupt()).expect("install SIGINT handler");
    let mut sigterm = signal(SignalKind::terminate()).expect("install SIGTERM handler");
    tokio::select! {
        _ = sigint.recv() => "SIGINT",
        _ = sigterm.recv() => "SIGTERM",
    }
}

/// Non-Unix fallback: only Ctrl-C is available.
#[cfg(not(unix))]
async fn wait_for_termination_signal() -> &'static str {
    let _ = tokio::signal::ctrl_c().await;
    "Ctrl-C"
}

/// Slice 7b — refuse to boot in fully-plaintext mode unless the
/// operator explicitly passes `--insecure`. The §12 commitment is
/// "default-deny on plaintext; localhost-dev mode keeps `--insecure`
/// flag with a loud warning at boot."
///
/// Returns Ok if either:
/// - TLS is configured (the secure default), or
/// - `--insecure` was passed (operator-acknowledged plaintext).
///
/// The `process_label` is interpolated into the error message so
/// operators see which binary refused to start.
fn enforce_default_deny(
    tls_configured: bool,
    insecure_flag: bool,
    process_label: &str,
) -> BallistaResult<()> {
    if !tls_configured && !insecure_flag {
        return Err(BallistaError::Configuration(format!(
            "{process_label}: refusing to boot in plaintext mode (Architecture §12 default-deny). \
             Pass --tls-ca/--tls-cert/--tls-key/--tls-domain to enable mTLS, \
             or --insecure to acknowledge plaintext operation."
        )));
    }
    Ok(())
}

/// Apply slice 7a's client-side TLS override to a `SchedulerConfig`
/// if `--tls-*` flags are present, and emit the boot-time log line
/// noting which mode the scheduler is in.
///
/// # Errors
/// - Bubble-up of [`crate::tls::TlsArgs::load`] wrapped into
///   `BallistaError::Configuration` (slice 7a fail-fast).
fn apply_tls_to_scheduler_config(
    args: &SchedulerArgs,
    config: &mut SchedulerConfig,
) -> BallistaResult<()> {
    let tls = args.tls.load().map_err(|e| {
        BallistaError::Configuration(format!("tls flags load failed (slice 7a fail-fast): {e}"))
    })?;
    if let Some(ref tls) = tls {
        // Ballista's `use_tls` flag flips the client URL scheme to
        // `https://`; the actual TLS config comes from the endpoint
        // override below.
        config.use_tls = true;
        let tls_arc = Arc::new(tls.clone());
        config.override_create_grpc_client_endpoint = Some(tls_arc.into_endpoint_override());
        tracing::info!(
            domain = %tls.domain(),
            "scheduler: client-side TLS configured (slice 7a — server-side plaintext until 7b)"
        );
    } else if args.tls.insecure {
        tracing::warn!(
            "scheduler: --insecure supplied; plaintext on the wire \
             (slice 7a default; slice 7b will enforce default-deny)"
        );
    }
    Ok(())
}

/// Reject HA timing arguments that would either crash
/// (`Duration::ZERO` through `tokio::time::interval`) or guarantee
/// instant leadership loss (heartbeat interval ≥ lease duration).
/// Reject `--ha-state-uri` schemes that can't back the lease. Leader
/// heartbeat renewal needs conditional `PutMode::Update` (ETag) writes;
/// `object_store`'s `LocalFileSystem` (`file://`) doesn't implement them, so
/// a `file://` lease would let the leader claim once, fail every heartbeat,
/// and step down forever (silent no-serve loop). Fail fast with an
/// actionable message instead. `memory://` is per-process — two scheduler
/// processes can't share it — so it can't provide real cross-process HA
/// either. (Remove the `file` guard if a future `object_store` implements
/// conditional local updates.)
fn reject_unsupported_ha_scheme(url: &Url) -> BallistaResult<()> {
    match url.scheme() {
        "file" => Err(BallistaError::Configuration(format!(
            "--ha-state-uri `{url}` uses `file://`, which cannot back the HA lease: \
             the local filesystem object store does not support the conditional \
             updates (`PutMode::Update`) leader-election heartbeats require, so the \
             leader would step down on its first heartbeat. Use `s3://` (incl. an \
             S3-compatible endpoint like MinIO/Ceph) or `gs://`."
        ))),
        "memory" => Err(BallistaError::Configuration(format!(
            "--ha-state-uri `{url}` uses `memory://`, which is per-process: separate \
             scheduler processes would each get their own store and both claim \
             leadership (split-brain). Use a shared `s3://` or `gs://` backend."
        ))),
        _ => Ok(()),
    }
}

/// Open the object store that backs the HA lease from `url`.
///
/// `object_store::parse_url` gives us the object path (scheme-agnostic) and
/// validates the URL, but for `s3://` it builds a store with *default* AWS
/// resolution — it ignores `AWS_ENDPOINT` and friends, so it can only ever
/// reach real AWS. Regulated on-prem deployments run **S3-compatible** object
/// stores (`MinIO`, Ceph RGW), so for `s3://`/`s3a://` we rebuild the store from
/// the standard `AWS_*` environment instead: `AWS_ENDPOINT` (the custom
/// endpoint), `AWS_ALLOW_HTTP`, `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`,
/// `AWS_REGION`, `AWS_SESSION_TOKEN`. The lease object still lands at the path
/// from the URL.
///
/// # Errors
/// Returns `Configuration` if the URL can't be opened as an object store or
/// the S3 builder can't be constructed from the environment.
fn build_lease_store(url: &Url) -> BallistaResult<(Arc<dyn ObjectStore>, ObjectPath)> {
    let (default_store, path) = object_store::parse_url(url).map_err(|e| {
        BallistaError::Configuration(format!(
            "--ha-state-uri `{url}` could not be opened as an object store: {e}"
        ))
    })?;
    let store: Arc<dyn ObjectStore> = match url.scheme() {
        "s3" | "s3a" => Arc::new(
            AmazonS3Builder::from_env()
                .with_url(url.as_str())
                .build()
                .map_err(|e| {
                    BallistaError::Configuration(format!(
                        "--ha-state-uri `{url}`: building the S3 lease store from the \
                         environment failed (check AWS_ENDPOINT / AWS_ACCESS_KEY_ID / \
                         AWS_SECRET_ACCESS_KEY / AWS_REGION): {e}"
                    ))
                })?,
        ),
        // file:// / memory:// are already rejected by
        // `reject_unsupported_ha_scheme`; anything else parse_url accepted
        // (e.g. a future gs:// with the gcp feature) uses its default store.
        _ => Arc::from(default_store),
    };
    Ok((store, path))
}

fn validate_ha_timing_args(args: &SchedulerArgs) -> BallistaResult<()> {
    if args.ha_lease_duration_secs == 0 {
        return Err(BallistaError::Configuration(
            "--ha-lease-duration-secs must be > 0".to_string(),
        ));
    }
    if args.ha_heartbeat_interval_secs == 0 {
        return Err(BallistaError::Configuration(
            "--ha-heartbeat-interval-secs must be > 0".to_string(),
        ));
    }
    if args.ha_heartbeat_interval_secs >= args.ha_lease_duration_secs {
        return Err(BallistaError::Configuration(format!(
            "--ha-heartbeat-interval-secs ({hb}) must be strictly less than \
             --ha-lease-duration-secs ({lease}); otherwise the lease expires \
             before the next heartbeat can refresh it",
            hb = args.ha_heartbeat_interval_secs,
            lease = args.ha_lease_duration_secs,
        )));
    }
    Ok(())
}

/// Single-instance scheduler (no HA). Backward-compatible slice
/// 8.2a behaviour.
async fn run_scheduler_single(args: SchedulerArgs) -> BallistaResult<()> {
    let addr: SocketAddr = args
        .bind_socket_addr()
        .map_err(BallistaError::Configuration)?;

    let mut config = args.build_scheduler_config();
    apply_tls_to_scheduler_config(&args, &mut config)?;
    let cluster = BallistaCluster::new_from_config(&config).await?;

    start_server(cluster, addr, Arc::new(config)).await
}

/// Phase 2 slice 5b — two-active HA scheduler with object-store
/// lease coordination.
///
/// Loop:
///
/// 1. **Claim.** Try to acquire the lease via
///    `ObjectStoreLease::try_claim`. On `HeldByOther`, sleep one
///    heartbeat interval and retry.
/// 2. **Run.** On `Acquired`, spawn `start_server` in a child task
///    and start a heartbeat ticker.
/// 3. **Heartbeat.** Every `ha_heartbeat_interval_secs`, refresh
///    the lease with the current ETag. On success, thread the new
///    ETag through. On `LeadershipLost`, abort the scheduler task
///    and restart the loop. On `Backend`, surface the error and
///    exit (caller decides whether to retry or fail-fast).
///
/// # Errors
/// - Configuration / URL parse failures at startup.
/// - Backend errors that persist across the entire run.
// The function reads as a coherent three-step state machine —
// breaking it into smaller helpers would scatter the loop body
// across the file and obscure the flow. Holding the
// too-many-lines line is the right tradeoff here.
#[allow(clippy::too_many_lines)]
async fn run_scheduler_ha(args: SchedulerArgs) -> BallistaResult<()> {
    let uri = args
        .ha_state_uri
        .as_ref()
        .expect("run_scheduler_ha called without --ha-state-uri");
    let url = Url::parse(uri).map_err(|e| {
        BallistaError::Configuration(format!("--ha-state-uri `{uri}` is not a valid URL: {e}"))
    })?;
    reject_unsupported_ha_scheme(&url)?;
    let (store, path) = build_lease_store(&url)?;

    let holder_id = uuid::Uuid::new_v4().to_string();
    let lease_duration = Duration::from_secs(args.ha_lease_duration_secs);
    let heartbeat_interval = Duration::from_secs(args.ha_heartbeat_interval_secs);
    let lease = ObjectStoreLease::new(
        store,
        ObjectPath::from(path.as_ref()),
        holder_id,
        lease_duration,
    );

    tracing::info!(
        holder_id = %lease.holder_id(),
        uri = %uri,
        lease_secs = args.ha_lease_duration_secs,
        heartbeat_secs = args.ha_heartbeat_interval_secs,
        "HA scheduler entering claim loop"
    );

    loop {
        // Step 1 — try to claim. Loop here until we win.
        let etag = loop {
            match lease.try_claim().await {
                Ok(ClaimOutcome::Acquired { etag, payload }) => {
                    tracing::info!(
                        holder_id = %lease.holder_id(),
                        expires_at = %payload.expires_at,
                        "claimed scheduler lease"
                    );
                    break etag;
                }
                Ok(ClaimOutcome::HeldByOther { payload }) => {
                    tracing::debug!(
                        current_holder = %payload.holder_id,
                        expires_at = %payload.expires_at,
                        "scheduler lease held by another; waiting"
                    );
                    tokio::time::sleep(heartbeat_interval).await;
                }
                Err(LeaseError::Backend(msg)) => {
                    tracing::warn!(error = %msg, "lease backend transient error; retrying");
                    tokio::time::sleep(heartbeat_interval).await;
                }
                Err(LeaseError::Malformed { path, source }) => {
                    return Err(BallistaError::Configuration(format!(
                        "lease payload at `{path}` is malformed and not safe to overwrite: {source}"
                    )));
                }
                Err(LeaseError::LeadershipLost) => {
                    // Unexpected here (we're in claim, not heartbeat),
                    // but cheap to handle the same as Backend.
                    tracing::warn!(
                        "unexpected LeadershipLost during claim — retrying after heartbeat interval"
                    );
                    tokio::time::sleep(heartbeat_interval).await;
                }
            }
        };

        // Step 2 — we hold the lease. Spawn the scheduler.
        let addr: SocketAddr = args
            .bind_socket_addr()
            .map_err(BallistaError::Configuration)?;
        let mut config = args.build_scheduler_config();
        apply_tls_to_scheduler_config(&args, &mut config)?;
        let cluster = BallistaCluster::new_from_config(&config).await?;
        let scheduler_task =
            tokio::spawn(async move { start_server(cluster, addr, Arc::new(config)).await });

        // Step 3 — heartbeat ticker. On loss, abort + re-claim.
        let mut current_etag = etag;
        let mut ticker = tokio::time::interval(heartbeat_interval);
        // Skip the immediate-tick to avoid an instant heartbeat
        // before any real work has happened.
        ticker.tick().await;
        // `scheduler_task` needs to be mutable to be polled directly
        // in select!; JoinHandle<T> impls Future via &mut.
        let mut scheduler_task = scheduler_task;
        // Track the wall-clock of the last successful heartbeat (or
        // claim). If consecutive backend failures stretch past the
        // lease duration, the lease has expired remotely even though
        // we haven't observed `LeadershipLost` yet — step down before
        // a competing scheduler can claim it and create a split-brain
        // window.
        let mut last_successful_heartbeat = Instant::now();
        loop {
            tokio::select! {
                // Scheduler task exits on its own (panic, signal,
                // upstream error) — propagate and exit the HA loop.
                join_result = &mut scheduler_task => {
                    return join_result
                        .map_err(|e| BallistaError::Internal(format!("scheduler task panicked: {e}")))?;
                }
                _ = ticker.tick() => {
                    match lease.heartbeat(&current_etag).await {
                        Ok(new_etag) => {
                            tracing::trace!(holder_id = %lease.holder_id(), "heartbeat ok");
                            current_etag = new_etag;
                            last_successful_heartbeat = Instant::now();
                        }
                        Err(LeaseError::LeadershipLost) => {
                            tracing::warn!(
                                holder_id = %lease.holder_id(),
                                "leadership lost — aborting scheduler task and re-entering claim loop"
                            );
                            scheduler_task.abort();
                            // Wait briefly for the OS to release the port
                            // before re-binding on the next loop iteration.
                            // Documented limitation: rapid failover may
                            // briefly hit "address already in use".
                            tokio::time::sleep(Duration::from_millis(500)).await;
                            break;
                        }
                        Err(LeaseError::Backend(msg)) => {
                            let since_last_ok = last_successful_heartbeat.elapsed();
                            if since_last_ok >= lease_duration {
                                tracing::warn!(
                                    holder_id = %lease.holder_id(),
                                    error = %msg,
                                    since_last_ok_secs = since_last_ok.as_secs(),
                                    lease_secs = lease_duration.as_secs(),
                                    "heartbeat backend failures exceeded lease duration — \
                                     stepping down to avoid split-brain and re-entering claim loop"
                                );
                                scheduler_task.abort();
                                tokio::time::sleep(Duration::from_millis(500)).await;
                                break;
                            }
                            tracing::warn!(
                                error = %msg,
                                since_last_ok_secs = since_last_ok.as_secs(),
                                "heartbeat backend transient error; continuing"
                            );
                        }
                        Err(LeaseError::Malformed { path, source }) => {
                            scheduler_task.abort();
                            return Err(BallistaError::Configuration(format!(
                                "lease payload at `{path}` corrupted mid-run: {source}"
                            )));
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn args_default_parse() {
        let args = SchedulerArgs::parse_from(["dataglot-ballista-scheduler"]);
        assert_eq!(args.bind_host, "0.0.0.0");
        assert_eq!(args.bind_port, 50050);
        assert_eq!(args.external_host, "localhost");
        assert_eq!(args.namespace, "dataglot");
    }

    #[test]
    fn args_full_parse() {
        let args = SchedulerArgs::parse_from([
            "dataglot-ballista-scheduler",
            "--bind-host",
            "10.0.0.5",
            "--bind-port",
            "55555",
            "--external-host",
            "scheduler.example",
            "--namespace",
            "phase2-bench",
        ]);
        assert_eq!(args.bind_host, "10.0.0.5");
        assert_eq!(args.bind_port, 55555);
        assert_eq!(args.external_host, "scheduler.example");
        assert_eq!(args.namespace, "phase2-bench");
    }

    #[test]
    fn bind_socket_addr_resolves_ipv4() {
        let args = SchedulerArgs::parse_from([
            "dataglot-ballista-scheduler",
            "--bind-host",
            "127.0.0.1",
            "--bind-port",
            "50050",
        ]);
        let addr = args.bind_socket_addr().expect("parses");
        assert_eq!(addr.to_string(), "127.0.0.1:50050");
    }

    #[test]
    fn bind_socket_addr_rejects_non_numeric_host() {
        let args = SchedulerArgs::parse_from([
            "dataglot-ballista-scheduler",
            "--bind-host",
            "scheduler.example",
            "--bind-port",
            "50050",
        ]);
        // Hostnames don't parse as SocketAddr — the binary's `run_scheduler`
        // surfaces this as a Configuration error; operators should use
        // either 0.0.0.0 / specific IP for bind, or rely on the default.
        let Err(msg) = args.bind_socket_addr() else {
            panic!("hostnames should not parse as SocketAddr")
        };
        assert!(msg.contains("scheduler.example"));
    }

    #[test]
    fn validate_ha_rejects_zero_lease() {
        let mut args = SchedulerArgs::parse_from(["dataglot-ballista-scheduler"]);
        args.ha_lease_duration_secs = 0;
        let err = validate_ha_timing_args(&args).expect_err("zero lease should reject");
        assert!(err.to_string().contains("ha-lease-duration-secs"));
    }

    #[test]
    fn validate_ha_rejects_zero_heartbeat() {
        let mut args = SchedulerArgs::parse_from(["dataglot-ballista-scheduler"]);
        args.ha_heartbeat_interval_secs = 0;
        let err = validate_ha_timing_args(&args).expect_err("zero heartbeat should reject");
        assert!(err.to_string().contains("ha-heartbeat-interval-secs"));
    }

    #[test]
    fn validate_ha_rejects_heartbeat_geq_lease() {
        let mut args = SchedulerArgs::parse_from(["dataglot-ballista-scheduler"]);
        args.ha_lease_duration_secs = 10;
        args.ha_heartbeat_interval_secs = 10;
        let err = validate_ha_timing_args(&args).expect_err("heartbeat >= lease should reject");
        assert!(err.to_string().contains("strictly less than"));
    }

    #[test]
    fn validate_ha_accepts_defaults() {
        let args = SchedulerArgs::parse_from(["dataglot-ballista-scheduler"]);
        assert!(validate_ha_timing_args(&args).is_ok());
    }

    #[test]
    fn ha_scheme_guard_rejects_file_and_memory_accepts_object_stores() {
        // `file://` can't do conditional updates → leader would step down
        // forever; reject at boot with an actionable message.
        let file = Url::parse("file:///tmp/dataglot/lease.json").unwrap();
        let err = reject_unsupported_ha_scheme(&file).expect_err("file:// must reject");
        let msg = err.to_string();
        assert!(
            msg.contains("file://") && msg.contains("conditional"),
            "{msg}"
        );
        assert!(
            msg.contains("s3://"),
            "error must point to a supported backend: {msg}"
        );

        // `memory://` is per-process → split-brain across processes.
        let mem = Url::parse("memory:///lease.json").unwrap();
        assert!(reject_unsupported_ha_scheme(&mem)
            .expect_err("memory:// must reject")
            .to_string()
            .contains("split-brain"),);

        // Conditional-update-capable object stores pass the guard.
        for uri in [
            "s3://bucket/dataglot/lease.json",
            "gs://bucket/dataglot/lease.json",
        ] {
            let url = Url::parse(uri).unwrap();
            assert!(
                reject_unsupported_ha_scheme(&url).is_ok(),
                "{uri} should pass the scheme guard"
            );
        }
    }

    /// `build_scheduler_config` carries the four configured fields
    /// straight onto `SchedulerConfig`; everything else defaults.
    #[test]
    fn build_scheduler_config_round_trips_args() {
        let args = SchedulerArgs::parse_from([
            "dataglot-ballista-scheduler",
            "--bind-host",
            "10.1.2.3",
            "--bind-port",
            "60000",
            "--external-host",
            "host.docker.internal",
            "--namespace",
            "ns-test",
        ]);
        let cfg = args.build_scheduler_config();
        assert_eq!(cfg.bind_host, "10.1.2.3");
        assert_eq!(cfg.bind_port, 60000);
        assert_eq!(cfg.external_host, "host.docker.internal");
        assert_eq!(cfg.namespace, "ns-test");
    }

    /// Slice 7a — no TLS flags supplied: scheduler config keeps
    /// `use_tls = false` and the endpoint override stays unset
    /// (backward-compat plaintext).
    #[test]
    fn apply_tls_skips_when_no_flags() {
        let args = SchedulerArgs::parse_from(["dataglot-ballista-scheduler"]);
        let mut cfg = args.build_scheduler_config();
        apply_tls_to_scheduler_config(&args, &mut cfg).expect("no-tls path");
        assert!(!cfg.use_tls);
        assert!(cfg.override_create_grpc_client_endpoint.is_none());
    }

    /// Slice 7a — partial TLS flags fail-fast before any cluster boot.
    #[test]
    fn apply_tls_rejects_partial_flags() {
        let args = SchedulerArgs::parse_from([
            "dataglot-ballista-scheduler",
            "--tls-ca",
            "/etc/dataglot/ca.pem",
        ]);
        let mut cfg = args.build_scheduler_config();
        let err = apply_tls_to_scheduler_config(&args, &mut cfg)
            .expect_err("partial flags should reject");
        assert!(err.to_string().contains("tls flags load failed"));
    }

    // --- Architecture §12 default-deny (`enforce_default_deny`) -------------
    // The plaintext-boot refusal is the security gate; a boolean regression
    // here would silently ship a plaintext scheduler. Pure fn, so unit-tested
    // directly (the full boot paths need an e2e harness).

    #[test]
    fn enforce_default_deny_rejects_plaintext_without_insecure() {
        let err = enforce_default_deny(false, false, "scheduler")
            .expect_err("plaintext without --insecure must be refused");
        assert!(matches!(err, BallistaError::Configuration(_)));
        assert!(err.to_string().contains("default-deny"));
    }

    #[test]
    fn enforce_default_deny_allows_when_tls_configured() {
        assert!(enforce_default_deny(true, false, "scheduler").is_ok());
    }

    #[test]
    fn enforce_default_deny_allows_with_insecure_flag() {
        assert!(enforce_default_deny(false, true, "scheduler").is_ok());
    }

    #[test]
    fn enforce_default_deny_allows_tls_and_insecure_together() {
        // Belt-and-suspenders: both set is not a contradiction, still Ok.
        assert!(enforce_default_deny(true, true, "scheduler").is_ok());
    }

    #[test]
    fn enforce_default_deny_interpolates_process_label() {
        let err =
            enforce_default_deny(false, false, "my-scheduler-label").expect_err("must refuse");
        assert!(err.to_string().contains("my-scheduler-label"));
    }
}

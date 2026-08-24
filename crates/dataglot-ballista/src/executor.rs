//! Standalone Ballista executor wiring for Phase 2 slice 5a.
//!
//! Today's standalone cluster (slice 3a) runs scheduler + executor in
//! the same process — handy for tests and single-host deployments,
//! but it's not what slice 5b's two-active-scheduler HA shape needs.
//! Multi-process Ballista wants real executor binaries that connect
//! to a remote scheduler over gRPC; this module is the
//! `dataglot-ballista`-side wrapper around Apache Ballista's existing
//! executor process entry point.
//!
//! # Why a wrapper, not Ballista's own binary
//!
//! Ballista ships a `ballista-executor` binary out of the box. We
//! intentionally don't ship that — we ship our own thin wrapper for
//! three reasons.
//!
//! **Credential resolver injection.** The `--credentials-config`
//! flag and the resulting `Arc<dyn CredentialResolver>` are Dataglot
//! abstractions; Ballista's stock binary doesn't know about them.
//! Slice 3b's plumbing is wasted unless the executor binary actually
//! constructs the resolver at boot and attaches it to every per-task
//! `SessionContext`.
//!
//! **Codec parity with the coordinator.** The
//! `FederationLogicalCodec` and `FederationPlanCodec` overrides have
//! to match what `DataglotServer` installs on its
//! `BallistaContextFactory`, otherwise the scheduler's serialized
//! plan won't decode on the executor side. Slice 5a's minimal cut
//! wires the default (registry-less) codecs — sufficient for
//! non-federation queries; federation across multi-process is slice
//! 5a.2 / a follow-up.
//!
//! **Fail-fast contract from slice 3b.** The promise was that a
//! worker which can't materialize its credential resolver refuses to
//! register with the scheduler. Our wrapper enforces that at
//! `main`'s entry, before any Ballista RPC startup. Failure → the
//! process exits non-zero before the scheduler sees the executor at
//! all.
//!
//! # What slice 5a does NOT ship
//!
//! - **Federation-across-the-wire.** The executor's codecs are
//!   default-constructed (no `ConnectorRegistry`), so a serialized
//!   `FederatedPlanNode` arriving from the scheduler will fail to
//!   decode. Slice 5a.2 (or a follow-up sub-slice) takes a
//!   `--catalogs-config` flag and builds the registry.
//! - **Resolver consumption.** Today no connector reads the
//!   `Arc<dyn CredentialResolver>` off the session config. The Phase
//!   1 connector migration introduces consumers; the rail is here
//!   waiting.
//! - **Subprocess-based multi-process integration test.** The
//!   `executor_binary_cli.rs` test exercises CLI surface only (help,
//!   fail-fast on bad config). A real "spawn the binary + boot a
//!   scheduler + run a SELECT" test is heavier; sized for a follow-up
//!   PR.

use std::path::PathBuf;
use std::sync::Arc;

use ballista_executor::executor_process::ExecutorProcessConfig;
use dataglot_core::error::{DataglotError, Result};
use dataglot_core::{CredentialResolver, CredentialResolverConfig};
use dataglot_federation::{DynConnectorRegistry, FederationPlanCodec, InMemoryConnectorRegistry};

use crate::catalogs_config::CatalogsConfig;
use crate::codec::FederationLogicalCodec;

/// Sized newtype carrying the executor's credential resolver onto
/// per-task `SessionConfig` extensions.
///
/// DataFusion's `SessionConfig::with_extension::<T>` /
/// `get_extension::<T>` require `T: Sized`, so we can't store the
/// trait object directly. This wrapper is the typed key the
/// extension store reaches for — consumers (Phase 1 connector
/// migration) call `config.get_extension::<CredentialResolverExtension>()`
/// then pull the inner `Arc<dyn CredentialResolver>`.
///
/// `Debug` redacts to a presence marker per hard rule 12.
#[derive(Clone)]
pub struct CredentialResolverExtension(pub Arc<dyn CredentialResolver>);

impl std::fmt::Debug for CredentialResolverExtension {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CredentialResolverExtension")
            .field("inner", &"<dyn CredentialResolver>")
            .finish()
    }
}

/// Parsed command-line arguments for the
/// `dataglot-ballista-executor` binary.
///
/// Defines a focused subset of Ballista's stock executor flags — the
/// ones operators actually tune — plus the Dataglot-specific
/// `--credentials-config` flag. Round-tripped into an
/// [`ExecutorProcessConfig`] by [`build_executor_process_config`].
#[derive(clap::Parser, Debug, Clone)]
#[command(
    name = "dataglot-ballista-executor",
    version,
    about = "Standalone Ballista executor for Dataglot (Phase 2 slice 5a).",
    long_about = "Boots a Ballista executor process that registers with a separate \
                  scheduler over gRPC. Wraps Apache Ballista's `start_executor_process` \
                  with Dataglot-specific overrides: federation codecs matching the \
                  coordinator's, and a coordinator-shape `CredentialResolver` injected \
                  into every per-task SessionContext."
)]
pub struct ExecutorArgs {
    /// Hostname (or IP) of the Ballista scheduler this executor
    /// should register with.
    #[arg(long, default_value = "localhost")]
    pub scheduler_host: String,

    /// Port of the scheduler's gRPC service.
    #[arg(long, default_value_t = 50050)]
    pub scheduler_port: u16,

    /// Local address the executor binds its services to.
    #[arg(long, default_value = "0.0.0.0")]
    pub bind_host: String,

    /// External hostname/IP advertised to the scheduler for
    /// peer-to-peer connectivity. If unset, the scheduler infers
    /// from the connection's source address.
    #[arg(long)]
    pub external_host: Option<String>,

    /// Port for the Arrow Flight service (shuffle data plane).
    #[arg(long, default_value_t = 50051)]
    pub bind_port: u16,

    /// Port for the executor's gRPC service (task control plane).
    #[arg(long, default_value_t = 50052)]
    pub bind_grpc_port: u16,

    /// Number of concurrent tasks the executor will run. Defaults
    /// to the host's logical-core count.
    #[arg(long)]
    pub concurrent_tasks: Option<usize>,

    /// Optional path to a JSON file shaped per
    /// [`CredentialResolverConfig`]. When omitted, the executor boots
    /// with an empty static resolver — fine for non-federation
    /// queries today, since no connector consumes the resolver yet.
    /// When present, slice 3b's fail-fast contract applies: failure
    /// to load or parse exits the process non-zero before any
    /// scheduler RPC.
    #[arg(long, value_name = "PATH")]
    pub credentials_config: Option<PathBuf>,

    /// Optional path to a JSON file shaped per
    /// [`CatalogsConfig`]. Phase 2 slice 5a.2 — populates the
    /// `ConnectorRegistry` the executor's federation codecs key on,
    /// so a `FederatedPlanNode` arriving over the wire decodes back
    /// to the correct `SQLExecutor`.
    ///
    /// When omitted, the executor boots with an empty registry; the
    /// codecs default to Ballista's stock behaviour and federation
    /// queries that name a catalog fail at decode time. This is
    /// fine for non-federation workloads (the slice-5a default).
    ///
    /// When present, slice 3b's fail-fast principle extends to this
    /// flag: an unreadable file / malformed JSON / unset env var /
    /// failed connection-at-boot exits the process non-zero before
    /// any scheduler RPC. The registry the coordinator builds and
    /// the registry the executor builds **must** name the same
    /// catalogs with the same connector kinds — federation plans
    /// decode by name and connector dispatch.
    #[arg(long, value_name = "PATH")]
    pub catalogs_config: Option<PathBuf>,

    /// Phase 2 slice 7a — mTLS material for outbound connections
    /// (executor → scheduler heartbeat, executor → other executors
    /// for shuffle reads). All four `--tls-*` flags must be supplied
    /// together or all omitted; partial configs fail-fast at boot.
    ///
    /// Slice 7a wires *client-side* TLS only; the server-side
    /// listeners stay on Ballista's plaintext `start_executor_process`
    /// path. Slice 7b lights up the server side so a fully-configured
    /// executor handshakes over real TLS end-to-end.
    #[command(flatten)]
    pub tls: crate::tls::TlsArgs,
}

impl ExecutorArgs {
    /// Construct the `Arc<dyn CredentialResolver>` from the
    /// `--credentials-config` flag.
    ///
    /// Returns an empty static resolver when no config file is
    /// supplied — the slice-5a default for non-federation queries.
    ///
    /// # Errors
    /// - [`DataglotError::Configuration`] if the config file is
    ///   unreadable, malformed, or names an unknown variant. This is
    ///   the load-bearing fail-fast path: surfaced to the binary's
    ///   `main`, which exits non-zero before any RPC startup.
    pub fn load_credential_resolver(&self) -> Result<Arc<dyn CredentialResolver>> {
        let Some(path) = &self.credentials_config else {
            // Empty static resolver — same shape, no entries.
            return CredentialResolverConfig::Static {
                entries: std::collections::HashMap::default(),
            }
            .into_resolver()
            .map_err(|e| {
                DataglotError::Configuration(format!(
                    "empty static resolver construction failed: {e}"
                ))
            });
        };
        let cfg = CredentialResolverConfig::from_json_file(path).map_err(|e| {
            DataglotError::Configuration(format!(
                "credentials-config load failed (slice 3b fail-fast): {e}"
            ))
        })?;
        cfg.into_resolver().map_err(|e| {
            DataglotError::Configuration(format!(
                "credentials-config materialisation failed (slice 3b fail-fast): {e}"
            ))
        })
    }

    /// Construct the `ConnectorRegistry` from the
    /// `--catalogs-config` flag.
    ///
    /// Returns an empty registry when no config file is supplied —
    /// the executor boots with no federation sources, codecs
    /// default to Ballista's stock behaviour for any plan that
    /// doesn't reference a registered connector.
    ///
    /// Async because each SQL source connects to its backend at
    /// boot (`PostgresConnector::connect`). Slice 3b's fail-fast
    /// principle extends here: connection failure exits the process
    /// non-zero before any scheduler RPC.
    ///
    /// # Errors
    /// - [`DataglotError::Configuration`] wrapping
    ///   [`crate::catalogs_config::CatalogsConfigError`] for any of
    ///   the load / parse / DSN-resolve / connect failure paths.
    pub async fn load_catalogs_registry(&self) -> Result<DynConnectorRegistry> {
        Ok(self.load_catalogs_registries().await?.0)
    }

    /// As [`Self::load_catalogs_registry`], but returning the
    /// warehouse (Iceberg) registry alongside the SQL one.
    /// Both are empty when no `--catalogs-config` was supplied.
    ///
    /// # Errors
    /// Same surface as [`Self::load_catalogs_registry`], plus
    /// warehouse credential-resolution and REST-connect failures.
    pub async fn load_catalogs_registries(
        &self,
    ) -> Result<(
        DynConnectorRegistry,
        dataglot_federation::iceberg::DynWarehouseRegistry,
    )> {
        let Some(path) = &self.catalogs_config else {
            return Ok((
                Arc::new(InMemoryConnectorRegistry::new(
                    std::collections::HashMap::default(),
                )),
                Arc::new(dataglot_federation::iceberg::WarehouseRegistry::default()),
            ));
        };
        let cfg = CatalogsConfig::from_json_file(path).map_err(|e| {
            DataglotError::Configuration(format!(
                "catalogs-config load failed (slice 5a.2 fail-fast): {e}"
            ))
        })?;
        cfg.into_registries().await.map_err(|e| {
            DataglotError::Configuration(format!(
                "catalogs-config materialisation failed (slice 5a.2 fail-fast): {e}"
            ))
        })
    }
}

/// Build an [`ExecutorProcessConfig`] from parsed CLI args, an
/// already-constructed `Arc<dyn CredentialResolver>`, and an
/// already-constructed `DynConnectorRegistry`.
///
/// Pure function — no IO, no Ballista RPC. Lets tests assert the
/// shape of the config we hand Ballista without standing up an
/// executor. Resolver and registry are taken pre-constructed so
/// both fail-fast contracts (slice 3b for credentials, slice 5a.2
/// for catalogs) are enforced at the binary's `main` entry, before
/// this function is reached.
///
/// Overrides installed:
///
/// - `override_logical_codec`: registry-aware
///   [`FederationLogicalCodec::with_registry`]. Decodes federation
///   plans referencing registered catalogs; delegates to Ballista's
///   stock codec for everything else. Same construction as
///   `dataglot-server::ballista::build_factory`'s coordinator-side
///   codec — the registries on both sides have to name the same
///   catalogs.
/// - `override_physical_codec`: registry-aware
///   [`FederationPlanCodec`] threaded with the same logical codec
///   in its inner-logical slot, wrapping Ballista's stock physical
///   codec so shuffle nodes still round-trip. Only installed when
///   the registry has entries — empty registry means no federation
///   sources, so the stock physical codec suffices and avoiding the
///   wrapper saves one Arc-clone per task.
/// - `override_config_producer`: a closure that mints a fresh
///   `SessionConfig` for each task, attaching the resolver as a
///   typed extension. Consumers (Phase 1 connector migration) pull
///   the resolver off `state().config().get_extension()`.
/// - `override_create_grpc_client_endpoint`: when `tls` is `Some`,
///   the closure attaches our `ClientTlsConfig` to every gRPC
///   endpoint Ballista mints — executor → scheduler heartbeat,
///   shuffle reads, etc. Slice 7a wiring; effective once slice 7b
///   lights up the server-side listeners (today, a TLS client
///   dialing a plaintext server fails the handshake by design).
#[must_use]
pub fn build_executor_process_config(
    args: &ExecutorArgs,
    resolver: &Arc<dyn CredentialResolver>,
    registry: &DynConnectorRegistry,
    warehouses: &dataglot_federation::iceberg::DynWarehouseRegistry,
    tls: Option<&crate::tls::BallistaTlsConfig>,
) -> ExecutorProcessConfig {
    use datafusion_proto::logical_plan::LogicalExtensionCodec;
    use datafusion_proto::physical_plan::PhysicalExtensionCodec;

    let mut config = ExecutorProcessConfig {
        bind_host: args.bind_host.clone(),
        external_host: args.external_host.clone(),
        port: args.bind_port,
        grpc_port: args.bind_grpc_port,
        scheduler_host: args.scheduler_host.clone(),
        scheduler_port: args.scheduler_port,
        ..ExecutorProcessConfig::default()
    };
    if let Some(slots) = args.concurrent_tasks {
        config.concurrent_tasks = slots;
    }

    // Logical codec — registry-aware variant so a `FederatedPlanNode`
    // arriving on the wire decodes back to the correct
    // `Arc<dyn FederationPlanner>` via the connector registry.
    // Mirrors the coordinator's `build_factory` codec construction.
    let logical_codec: Arc<dyn LogicalExtensionCodec> = Arc::new(
        FederationLogicalCodec::with_registry(Arc::clone(registry))
            .with_warehouse_registry(Arc::clone(warehouses)),
    );
    config.override_logical_codec = Some(Arc::clone(&logical_codec));

    // Physical codec — only installed when the registry has
    // entries. Federation physical plans (`VirtualExecutionPlan` +
    // wrappers) need this to round-trip; non-federation plans use
    // Ballista's stock physical codec which is the default when no
    // override is supplied. The wrapper threads our logical codec
    // into the inner-logical slot so the `VirtualExecutionPlan.plan()`
    // walk reaches federation's `try_encode_table_provider` —
    // same shape as `dataglot-server::ballista::build_factory`.
    if !registry.is_empty() || !warehouses.is_empty() {
        let physical_codec: Arc<dyn PhysicalExtensionCodec> = Arc::new(
            FederationPlanCodec::with_logical_codec(
                Arc::clone(registry),
                Arc::clone(&logical_codec),
            )
            .with_warehouse_registry(Arc::clone(warehouses))
            .with_inner_physical_codec(Arc::new(
                ballista_core::serde::BallistaPhysicalExtensionCodec::default(),
            )),
        );
        config.override_physical_codec = Some(physical_codec);
    }

    // SessionConfig producer — attach the resolver as a typed
    // extension on every per-task config the executor mints. The
    // resolver Arc is captured by the closure; cheap clone per task.
    // Wrapped in `CredentialResolverExtension` so DataFusion's
    // `Sized` bound on `with_extension::<T>` / `get_extension::<T>`
    // is satisfied.
    let resolver_for_closure = Arc::clone(resolver);
    config.override_config_producer = Some(Arc::new(move || {
        use ballista::datafusion::prelude::SessionConfig as DfSessionConfig;
        use ballista::prelude::SessionConfigExt;
        DfSessionConfig::new_with_ballista().with_extension(Arc::new(CredentialResolverExtension(
            Arc::clone(&resolver_for_closure),
        )))
    }));

    // Phase 2 slice 7a — client-side TLS for outbound gRPC. When
    // present, route every endpoint Ballista constructs through
    // `endpoint.tls_config(...)` carrying our CA + identity + SNI.
    // Effective once slice 7b lights up server-side listeners; until
    // then dialing succeeds at the TCP layer but the TLS handshake
    // fails when the peer is plaintext (by design).
    if let Some(tls) = tls {
        let tls_arc = Arc::new(tls.clone());
        config.override_create_grpc_client_endpoint = Some(tls_arc.into_endpoint_override());
    }

    config
}

/// Boot the executor: parse-validate args, install crypto provider,
/// load resolver / registry / TLS, build `ExecutorProcessConfig`,
/// hand off to Ballista's `start_executor_process`. Blocks until
/// shutdown signal.
///
/// # Errors
/// - Bubble-up of [`ExecutorArgs::load_credential_resolver`] (slice
///   3b fail-fast on bad config).
/// - Bubble-up of [`crate::tls::TlsArgs::load`] (slice 7a fail-fast
///   on missing / malformed PEM, or partial `--tls-*` config).
/// - Ballista's own startup errors (port-bind collision, scheduler
///   unreachable on first attempt, etc.) wrapped into
///   [`DataglotError::Internal`].
pub async fn run_executor(args: ExecutorArgs) -> Result<()> {
    crate::tls::install_default_crypto_provider();
    let resolver = args.load_credential_resolver()?;
    let (registry, warehouses) = args.load_catalogs_registries().await?;
    let tls = args.tls.load().map_err(|e| {
        DataglotError::Configuration(format!("tls flags load failed (slice 7a fail-fast): {e}"))
    })?;
    // Slice 7b — default-deny.
    if tls.is_none() && !args.tls.insecure {
        return Err(DataglotError::Configuration(
            "executor: refusing to boot in plaintext mode (Architecture §12 default-deny). \
             Pass --tls-ca/--tls-cert/--tls-key/--tls-domain to enable mTLS, \
             or --insecure to acknowledge plaintext operation."
                .to_string(),
        ));
    }
    if let Some(ref cfg) = tls {
        tracing::info!(
            domain = %cfg.domain(),
            "executor: server-side TLS configured (slice 7b — pull-mode dispatch + Flight TLS)"
        );
        // Slice 7b path: pull-mode + Flight TLS + scheduler client TLS.
        // Bypasses `start_executor_process` entirely.
        return crate::server::run_executor_tls(&args, &resolver, &registry, cfg).await;
    }
    tracing::warn!(
        "executor: --insecure supplied; plaintext on the wire \
         (Architecture §12 commitment opted out for this binary)"
    );
    let config =
        build_executor_process_config(&args, &resolver, &registry, &warehouses, tls.as_ref());
    ballista_executor::executor_process::start_executor_process(Arc::new(config))
        .await
        .map_err(|e| DataglotError::Internal(format!("ballista executor process exited: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    ///  #3 — scheduling-policy pairing pin. The executor binary
    /// inherits Ballista's default `PushStaged`; the production
    /// scheduler binary and the multi-process test harnesses pair with
    /// push-staged schedulers, while the in-process standalone path
    /// pairs pull-with-pull (`monitor.rs`). A `PullStaged` executor
    /// against a push scheduler (or vice versa) does not error — it
    /// queues every job forever ('s first live run hung exactly
    /// there). If this pin fails, someone changed the default: re-check
    /// every pairing before shipping.
    #[test]
    fn executor_config_defaults_to_push_staged() {
        use ballista_core::config::TaskSchedulingPolicy;

        let args = ExecutorArgs::parse_from(["dataglot-ballista-executor"]);
        let resolver = args
            .load_credential_resolver()
            .expect("empty static resolver");
        let registry: DynConnectorRegistry =
            Arc::new(dataglot_federation::InMemoryConnectorRegistry::default());
        let warehouses: dataglot_federation::iceberg::DynWarehouseRegistry =
            Arc::new(dataglot_federation::iceberg::WarehouseRegistry::default());
        let config = build_executor_process_config(&args, &resolver, &registry, &warehouses, None);
        assert!(
            matches!(
                config.task_scheduling_policy,
                TaskSchedulingPolicy::PushStaged
            ),
            "executor default scheduling policy changed from PushStaged — \
             re-verify pairing with the scheduler binary, the multi-process \
             harnesses, and monitor.rs's pull-staged standalone"
        );
    }

    /// Default arg-set boots cleanly through the parser. Sanity
    /// pin — clap derives can drift if the struct grows fields
    /// without proper defaults.
    #[test]
    fn args_default_parse() {
        let args = ExecutorArgs::parse_from(["dataglot-ballista-executor"]);
        assert_eq!(args.scheduler_host, "localhost");
        assert_eq!(args.scheduler_port, 50050);
        assert_eq!(args.bind_port, 50051);
        assert_eq!(args.bind_grpc_port, 50052);
        assert!(args.credentials_config.is_none());
        assert!(args.concurrent_tasks.is_none());
    }

    /// Custom scheduler + ports + credentials path round-trip through
    /// the parser.
    #[test]
    fn args_full_parse() {
        let args = ExecutorArgs::parse_from([
            "dataglot-ballista-executor",
            "--scheduler-host",
            "sched.example",
            "--scheduler-port",
            "55555",
            "--bind-host",
            "10.0.0.5",
            "--bind-port",
            "60001",
            "--bind-grpc-port",
            "60002",
            "--external-host",
            "exec.example",
            "--concurrent-tasks",
            "4",
            "--credentials-config",
            "/etc/dataglot/creds.json",
        ]);
        assert_eq!(args.scheduler_host, "sched.example");
        assert_eq!(args.scheduler_port, 55555);
        assert_eq!(args.bind_host, "10.0.0.5");
        assert_eq!(args.bind_port, 60001);
        assert_eq!(args.bind_grpc_port, 60002);
        assert_eq!(args.external_host.as_deref(), Some("exec.example"));
        assert_eq!(args.concurrent_tasks, Some(4));
        assert_eq!(
            args.credentials_config.as_deref(),
            Some(std::path::Path::new("/etc/dataglot/creds.json"))
        );
    }

    /// Slice 3b fail-fast contract — missing config file surfaces as
    /// a typed error message identifying the load step. The binary's
    /// `main` exits non-zero on this path before any RPC startup.
    #[test]
    fn load_credential_resolver_missing_file_errors() {
        let args = ExecutorArgs::parse_from([
            "dataglot-ballista-executor",
            "--credentials-config",
            "/tmp/definitely-not-a-real-creds-file-9999.json",
        ]);
        let Err(err) = args.load_credential_resolver() else {
            panic!("missing config must fail-fast")
        };
        let msg = format!("{err}");
        assert!(
            msg.contains("credentials-config load failed"),
            "error should name the load step: {msg}"
        );
        // Defensive — the underlying io::Error path should surface.
        assert!(
            msg.contains("definitely-not-a-real-creds-file-9999.json"),
            "error should include the offending path: {msg}"
        );
    }

    /// Slice 3b fail-fast — malformed JSON in the config file also
    /// exits non-zero. Distinct error path from missing-file (parse
    /// vs. IO) so logs are diagnostic.
    #[test]
    fn load_credential_resolver_bad_json_errors() {
        let tmp = std::env::temp_dir().join("dataglot-bad-creds.json");
        std::fs::write(&tmp, b"{ malformed").expect("write tmp");
        let args = ExecutorArgs::parse_from([
            "dataglot-ballista-executor",
            "--credentials-config",
            tmp.to_str().unwrap(),
        ]);
        let Err(err) = args.load_credential_resolver() else {
            panic!("malformed JSON must fail-fast")
        };
        let msg = format!("{err}");
        assert!(
            msg.contains("credentials-config load failed"),
            "error should name the load step: {msg}"
        );
        let _ = std::fs::remove_file(&tmp);
    }

    /// Slice 5a.2 — `--catalogs-config` flag parses and round-trips
    /// through `ExecutorArgs`.
    #[test]
    fn args_catalogs_config_round_trips() {
        let args = ExecutorArgs::parse_from([
            "dataglot-ballista-executor",
            "--catalogs-config",
            "/etc/dataglot/catalogs.json",
        ]);
        assert_eq!(
            args.catalogs_config.as_deref(),
            Some(std::path::Path::new("/etc/dataglot/catalogs.json"))
        );
    }

    /// Slice 5a.2 — no `--catalogs-config` flag → empty registry,
    /// no boot RPC. Mirrors the default-resolver path.
    #[tokio::test]
    async fn load_catalogs_registry_default_is_empty() {
        let args = ExecutorArgs::parse_from(["dataglot-ballista-executor"]);
        let registry = args
            .load_catalogs_registry()
            .await
            .expect("empty registry never fails");
        assert_eq!(registry.len(), 0);
    }

    /// Slice 5a.2 fail-fast — `--catalogs-config` pointing at a
    /// missing file exits the load path with a typed error message
    /// naming the load step. The binary's `main` exits non-zero on
    /// this path before any RPC.
    #[tokio::test]
    async fn load_catalogs_registry_missing_file_errors() {
        let args = ExecutorArgs::parse_from([
            "dataglot-ballista-executor",
            "--catalogs-config",
            "/tmp/never-exists-catalogs-cli-5a2.json",
        ]);
        let Err(err) = args.load_catalogs_registry().await else {
            panic!("missing config must fail-fast")
        };
        let msg = format!("{err}");
        assert!(
            msg.contains("catalogs-config load failed"),
            "error should name the load step: {msg}"
        );
        assert!(
            msg.contains("never-exists-catalogs-cli-5a2.json"),
            "error should include the offending path: {msg}"
        );
    }

    /// No `--credentials-config` flag — the executor boots with an
    /// empty static resolver. This is the slice-5a default for
    /// non-federation queries.
    #[test]
    fn load_credential_resolver_default_is_empty_static() {
        let args = ExecutorArgs::parse_from(["dataglot-ballista-executor"]);
        let resolver = args
            .load_credential_resolver()
            .expect("default resolver constructs");
        let Err(err) = resolver.resolve(&dataglot_core::CredentialHandle::new("anything")) else {
            panic!("empty resolver should return NotFound, got Ok")
        };
        assert!(matches!(err, dataglot_core::CredentialError::NotFound(_)));
    }

    /// `build_executor_process_config` translates CLI args into the
    /// fields Ballista consumes, with overrides for codecs and the
    /// `SessionConfig` producer carrying the resolver.
    ///
    /// Slice 5a.2 added the registry argument; with an empty registry
    /// the physical codec is intentionally NOT installed (one fewer
    /// Arc-clone per task — Ballista's stock physical codec is the
    /// default).
    #[test]
    fn build_config_round_trips_cli_into_ballista_shape() {
        let args = ExecutorArgs::parse_from([
            "dataglot-ballista-executor",
            "--scheduler-host",
            "sched",
            "--scheduler-port",
            "9000",
            "--bind-host",
            "127.0.0.1",
            "--bind-port",
            "8001",
            "--bind-grpc-port",
            "8002",
            "--concurrent-tasks",
            "2",
        ]);
        let resolver = args.load_credential_resolver().unwrap();
        let registry: dataglot_federation::DynConnectorRegistry = Arc::new(
            InMemoryConnectorRegistry::new(std::collections::HashMap::default()),
        );
        let warehouses: dataglot_federation::iceberg::DynWarehouseRegistry =
            Arc::new(dataglot_federation::iceberg::WarehouseRegistry::default());
        let cfg = build_executor_process_config(&args, &resolver, &registry, &warehouses, None);

        assert_eq!(cfg.scheduler_host, "sched");
        assert_eq!(cfg.scheduler_port, 9000);
        assert_eq!(cfg.bind_host, "127.0.0.1");
        assert_eq!(cfg.port, 8001);
        assert_eq!(cfg.grpc_port, 8002);
        assert_eq!(cfg.concurrent_tasks, 2);

        // Codec slot is filled — the federation logical codec
        // wrapping Ballista's stock codec.
        assert!(
            cfg.override_logical_codec.is_some(),
            "logical codec must be installed"
        );
        // Empty registry → physical codec slot stays None per the
        // optimization. Non-federation queries use Ballista's stock
        // physical codec via Ballista's default; federation queries
        // would fail at decode (which is the correct behaviour when
        // no federation sources are configured).
        assert!(
            cfg.override_physical_codec.is_none(),
            "empty registry must not install physical codec"
        );
        // Config producer is set — the closure attaches the
        // resolver as an extension on every minted SessionConfig.
        assert!(
            cfg.override_config_producer.is_some(),
            "config producer must inject the resolver extension"
        );
    }

    // The non-empty-registry → physical-codec branch is covered by
    // the Docker-gated integration test
    // `tests/executor_multi_process_federation.rs`, which constructs
    // a registry from a real `PostgresConnector` and asserts the
    // federation query round-trips. Recreating a non-empty registry
    // here would require either a real `PostgresConnector` (needs
    // Docker for the underlying Postgres) or a stub `SQLExecutor`
    // boilerplate that just proves `is_empty() == false` — the
    // integration test already does both jobs more directly.

    /// Concrete check that the config producer's minted
    /// `SessionConfig` actually carries the resolver — the rail
    /// consumers (Phase 1 connector migration) will pull from.
    #[test]
    fn config_producer_attaches_resolver_extension() {
        use ballista::datafusion::prelude::SessionConfig as DfSessionConfig;
        use dataglot_core::{Credentials, StaticCredentialResolver};

        let mut r = StaticCredentialResolver::new();
        r.insert("pg_main", Credentials::Token("tok".into()));
        let resolver: Arc<dyn CredentialResolver> = Arc::new(r);

        let args = ExecutorArgs::parse_from(["dataglot-ballista-executor"]);
        let registry: dataglot_federation::DynConnectorRegistry = Arc::new(
            InMemoryConnectorRegistry::new(std::collections::HashMap::default()),
        );
        let warehouses: dataglot_federation::iceberg::DynWarehouseRegistry =
            Arc::new(dataglot_federation::iceberg::WarehouseRegistry::default());
        let cfg = build_executor_process_config(&args, &resolver, &registry, &warehouses, None);
        let producer = cfg
            .override_config_producer
            .expect("config producer installed");

        let session_config: DfSessionConfig = producer();
        let wrapped = session_config
            .get_extension::<CredentialResolverExtension>()
            .expect("minted SessionConfig must carry the resolver extension");
        assert!(
            Arc::ptr_eq(&wrapped.0, &resolver),
            "extension must be the same Arc the binary handed in (slice 3b identity-preservation contract)"
        );
    }

    /// Slice 7a — passing `None` for the `tls` parameter must leave
    /// the `override_create_grpc_client_endpoint` slot empty so
    /// existing plaintext deployments keep working unchanged.
    #[test]
    fn build_config_without_tls_leaves_endpoint_override_unset() {
        let resolver: Arc<dyn CredentialResolver> =
            Arc::new(dataglot_core::StaticCredentialResolver::new());
        let registry: dataglot_federation::DynConnectorRegistry = Arc::new(
            InMemoryConnectorRegistry::new(std::collections::HashMap::default()),
        );
        let args = ExecutorArgs::parse_from(["dataglot-ballista-executor"]);
        let warehouses: dataglot_federation::iceberg::DynWarehouseRegistry =
            Arc::new(dataglot_federation::iceberg::WarehouseRegistry::default());
        let cfg = build_executor_process_config(&args, &resolver, &registry, &warehouses, None);
        assert!(cfg.override_create_grpc_client_endpoint.is_none());
    }

    /// Slice 7a — when TLS is configured, the
    /// `override_create_grpc_client_endpoint` closure is installed.
    /// We can't easily verify what the closure produces (that needs
    /// a live `tonic::transport::Endpoint`), but the presence of the
    /// override is the load-bearing fact for slice 7b to bridge to.
    #[test]
    fn build_config_with_tls_installs_endpoint_override() {
        use tempfile::TempDir;
        // Reuse the PEM fixtures from `tls::tests` — they're hermetic
        // base64 that rustls-pemfile parses without panicking.
        const CERT: &str = "-----BEGIN CERTIFICATE-----
MIIBkTCCATegAwIBAgIUMQQjjxBmYJEFGyN9yT/V6XJ6jK4wCgYIKoZIzj0EAwIw
GjEYMBYGA1UEAwwPdGVzdC5leGFtcGxlLmNvbTAeFw0yNjA1MjYxMDAwMDBaFw0y
NzA1MjYxMDAwMDBaMBoxGDAWBgNVBAMMD3Rlc3QuZXhhbXBsZS5jb20wWTATBgcq
hkjOPQIBBggqhkjOPQMBBwNCAATDQs9DBmf01EXLDp4Jv6Tw8jr4HHF9ZVL5JFvW
hG7ND6ny5tDh8X8Khv5wG7JLqTfL3rZW1eOk/uTGiqYf28Zlo1MwUTAdBgNVHQ4E
FgQUE3WX9hLZHa4Bf6E6Hb/v1c0CTaIwHwYDVR0jBBgwFoAUE3WX9hLZHa4Bf6E6
Hb/v1c0CTaIwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNHADBEAiAJxFqU
KKnEYsJYBxNyXqV7G9CqVHsDpWOcv0vYx3VqaQIgQYnpa6jHnNxX/CXEoFn4HJEN
F4XBgGOd2WuKsIQNQwM=
-----END CERTIFICATE-----
";
        const KEY: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgXcGqzKZ+G7Wq+TUz
EeHL2tD6jJyD6Z9q5j5p5BJqfgmhRANCAATDQs9DBmf01EXLDp4Jv6Tw8jr4HHF9
ZVL5JFvWhG7ND6ny5tDh8X8Khv5wG7JLqTfL3rZW1eOk/uTGiqYf28Zl
-----END PRIVATE KEY-----
";
        let dir = TempDir::new().unwrap();
        let ca = dir.path().join("ca.pem");
        let cert = dir.path().join("cert.pem");
        let key = dir.path().join("key.pem");
        std::fs::write(&ca, CERT).unwrap();
        std::fs::write(&cert, CERT).unwrap();
        std::fs::write(&key, KEY).unwrap();

        let tls = crate::tls::BallistaTlsConfig::from_paths(&ca, &cert, &key, "sched.local")
            .expect("load test PEM");
        let resolver: Arc<dyn CredentialResolver> =
            Arc::new(dataglot_core::StaticCredentialResolver::new());
        let registry: dataglot_federation::DynConnectorRegistry = Arc::new(
            InMemoryConnectorRegistry::new(std::collections::HashMap::default()),
        );
        let args = ExecutorArgs::parse_from(["dataglot-ballista-executor"]);
        let warehouses: dataglot_federation::iceberg::DynWarehouseRegistry =
            Arc::new(dataglot_federation::iceberg::WarehouseRegistry::default());
        let cfg =
            build_executor_process_config(&args, &resolver, &registry, &warehouses, Some(&tls));
        assert!(cfg.override_create_grpc_client_endpoint.is_some());
    }

    /// Slice 7a — `--tls-*` flags parse through clap and surface on
    /// the inner `TlsArgs` flattened field.
    #[test]
    fn tls_flags_parse_via_command_flatten() {
        let args = ExecutorArgs::parse_from([
            "dataglot-ballista-executor",
            "--tls-ca",
            "/etc/dataglot/ca.pem",
            "--tls-cert",
            "/etc/dataglot/exec.crt",
            "--tls-key",
            "/etc/dataglot/exec.key",
            "--tls-domain",
            "scheduler.cluster.local",
        ]);
        assert_eq!(
            args.tls.tls_ca.as_deref(),
            Some(std::path::Path::new("/etc/dataglot/ca.pem"))
        );
        assert_eq!(
            args.tls.tls_domain.as_deref(),
            Some("scheduler.cluster.local")
        );
        assert!(!args.tls.insecure);
    }

    /// Hard rule 12 — the `CredentialResolverExtension` `Debug` impl is
    /// the enforcement point that keeps a resolver's secrets out of logs /
    /// plan reprs. Pin that it renders only the presence marker and never
    /// delegates to the inner resolver (which would risk leaking entries).
    #[test]
    fn credential_resolver_extension_debug_is_redacted() {
        use dataglot_core::{Credentials, StaticCredentialResolver};

        let mut resolver = StaticCredentialResolver::new();
        resolver.insert(
            "pg",
            Credentials::Token("super-secret-token-value".to_string()),
        );
        let ext = CredentialResolverExtension(Arc::new(resolver));

        let rendered = format!("{ext:?}");
        assert!(
            rendered.contains("CredentialResolverExtension"),
            "keeps the type name: {rendered}"
        );
        assert!(
            rendered.contains("<dyn CredentialResolver>"),
            "renders the presence marker, not the inner resolver: {rendered}"
        );
        assert!(
            !rendered.contains("super-secret-token-value"),
            "must never surface secret material: {rendered}"
        );
    }
}

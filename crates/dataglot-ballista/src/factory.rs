//! `BallistaContextFactory` — sibling to `dataglot-core`'s
//! `SessionContextFactory`. Phase 2 spec 02 slice 2.
//!
//! Produces a `SessionContext` backed by a standalone Apache Ballista
//! cluster (1 coordinator + 1 executor, in-process) with the
//! federation analyzer rules + physical `FilterPushdown` strip that
//! `SessionContextFactory::create_federated_context` applies on the
//! single-node side.
//!
//! # What is — and is NOT — installed
//!
//! - ✅ **Federation analyzer rules** (`datafusion-federation`'s
//!   `default_optimizer_rules`) — these run at the logical-plan
//!   optimization stage, before the query planner. Same rules
//!   single-node uses. Federated source detection + virtual exec
//!   node rewrite happen here.
//! - ✅ **`FilterPushdown` strip** — same `datafusion-federation
//!   0.5.3` correctness workaround `SessionContextFactory` applies
//!   on single-node. Stripping the physical-optimizer rule on both
//!   sides keeps single-node and cluster results identical.
//! - ✅ **`FederatedQueryPlanner`** — installed via
//!   `SessionStateBuilder::with_query_planner` on the state we hand
//!   `standalone_with_state`. The *coordinator-side* context that
//!   `standalone_with_state` returns gets its planner replaced with
//!   `BallistaQueryPlanner` (via `upgrade_for_ballista`), so
//!   `BallistaQueryPlanner` is what's installed there — but the
//!   *scheduler-side* `SessionContext` (built from the same state
//!   via `new_standalone_scheduler_from_state`) keeps the planner
//!   we installed. That's what physically plans the deserialized
//!   logical plan after `DistributedQueryExec` ships it across.
//!   Without this, the scheduler hits "No installed planner was
//!   able to convert the custom node to an execution plan: Federated"
//!   the moment a federation query lands on a worker. Slice 4b.3
//!   follow-up: PR #272's e2e surfaced this as the third failure
//!   mode after the codec round-trip + table-provider envelope.
//!
//! Slice 4 closes the federation-through-Ballista gap. Slice 2 ships
//! the factory shape, the analyzer-rule parity, the
//! `FilterPushdown` strip, and the codec-registration entry point
//! that slice 4 plumbs into.
//!
//! # Why a sibling factory, not an enum or trait?
//!
//! Locked in spec 02's "Decided up front" section:
//!
//! - **Sibling factory** (this design) — zero blast radius on
//!   existing single-node consumers. They keep using
//!   `SessionContextFactory`; operators flipping to Ballista import
//!   the parallel factory at the boot site.
//! - An `enum Factory { Direct(SessionContextFactory),
//!   Ballista(BallistaContextFactory) }` was rejected — every caller
//!   in `dataglot-server` would need to match.
//! - A `trait ContextFactory` was rejected as upstream-API-fragile —
//!   the trait surface would have to track `DataFusion` + Ballista
//!   evolution forever.
//!
//! # Why the factory lives in `dataglot-ballista`, not `dataglot-core`
//!
//! Spec 02 sketched the API as `dataglot-core/src/ballista_context.rs`,
//! but `dataglot-core` cannot depend on `dataglot-ballista` (would
//! violate hard rule 4's strict dependency direction; the
//! Ballista crate is heavy enough that pulling it into core's
//! workspace-default build path would dominate everyone's compile).
//! Placing the factory next to slice 1's smoke test keeps Ballista's
//! cost contained to operators who opt in via `dataglot-ballista`.
//!
//! # Slice-1 finding — codec registration (slice-4 follow-up)
//!
//! Slice 1's smoke test surfaced that *even in standalone mode*
//! Ballista round-trips every logical plan through `datafusion-proto`.
//! Any `TableProvider` lacking a `LogicalExtensionCodec` panics with
//! `NotImplemented("LogicalExtensionCodec is not provided")`.
//! Filesystem-rooted providers (parquet, CSV, JSON) work today via
//! Ballista's built-in `BallistaLogicalExtensionCodec` defaults;
//! non-filesystem providers (federation's `VirtualExecutionPlan`,
//! warehouse / Iceberg) need slice 4 to wire spec 01's
//! `FederationPlanCodec` into Ballista's codec list. The factory in
//! its slice-2 shape does **not** yet expose a public codec input
//! path — slice 4 introduces that surface together with the actual
//! plumbing into Ballista's codec registry, so we don't ship a
//! stub that pretends to accept codecs but stores them inert.
//!
//! # Cross-version `DataFusion` sourcing
//!
//! `dataglot-ballista` imports `DataFusion` via Ballista's re-export
//! (`ballista::datafusion::*`) rather than the workspace `datafusion`
//! dep directly. Both Cargo paths resolve to the same `DataFusion` 53.x
//! crate from crates.io because (a) ballista pins `datafusion = "53"`
//! in its workspace deps, (b) our workspace also pins `datafusion =
//! "53"`, (c) Cargo unifies them. `datafusion-federation` (the workspace
//! dep we DO need here for analyzer rules + query planner) likewise
//! pulls `datafusion = "53"` and unifies.

use std::sync::Arc;

use ballista::datafusion::execution::session_state::SessionStateBuilder;
use ballista::datafusion::physical_optimizer::optimizer::PhysicalOptimizer;
use ballista::datafusion::prelude::{SessionConfig as DfSessionConfig, SessionContext};
use ballista::prelude::{SessionConfigExt, SessionContextExt};
use datafusion_proto::logical_plan::LogicalExtensionCodec;
use datafusion_proto::physical_plan::PhysicalExtensionCodec;
use dataglot_core::error::{DataglotError, Result};
use dataglot_core::{CredentialResolver, SessionConfig};

use crate::cluster::BallistaCluster;
use crate::codec::FederationLogicalCodec;

/// Number of executor slots the standalone cluster boots with by
/// default. Mirrors slice 1's smoke test (`with_ballista_standalone_parallelism(2)`)
/// — enough to exercise scheduling without burning CI runners.
/// Slice 4's split-level parallelism work will tune this per-config.
const DEFAULT_STANDALONE_PARALLELISM: usize = 2;

/// Default scheduler executor-liveness timeout (seconds). Wider than
/// Ballista's upstream 180s so a host pause doesn't cull healthy executors
/// and strand distributed jobs; overridable per deployment.
const DEFAULT_EXECUTOR_TIMEOUT_SECONDS: u64 = 3600;

/// Factory for creating Ballista-backed `SessionContext` instances.
///
/// One factory per server-side configuration; each `create_*` call
/// boots a fresh standalone cluster (slice 2) or returns a client
/// context against a remote scheduler (slice 5+, not yet implemented).
#[derive(Clone)]
pub struct BallistaContextFactory {
    config: SessionConfig,
    parallelism: usize,
    /// Seconds the scheduler waits without a heartbeat before marking an
    /// executor dead. Defaults to [`DEFAULT_EXECUTOR_TIMEOUT_SECONDS`];
    /// `DataglotServer` overrides it from the `[ballista]` config's
    /// `executor_timeout_seconds` via [`Self::with_executor_timeout_seconds`].
    executor_timeout_seconds: u64,
    /// Number of **external** executor processes in the cluster (0 = embedded
    /// standalone). Used to size the distributed session's `target_partitions`
    /// to the *aggregate* cluster slots (`external_executors × parallelism`)
    /// rather than a single node's — otherwise a query under-parallelizes and
    /// leaves most executor slots idle. Set by
    /// [`Self::with_external_executors`].
    external_executors: usize,
    /// `LogicalExtensionCodec` handed to Ballista via
    /// `SessionConfig::with_ballista_logical_extension_codec`. Phase 2
    /// slice 4a wires the codec slot; the default is
    /// [`FederationLogicalCodec`] which today delegates to Ballista's
    /// stock codec (so observable behaviour is unchanged from slice 3a)
    /// but reserves the federation extension point for slice 4b.
    /// Callers wanting a custom codec set it via
    /// [`Self::with_logical_codec`].
    logical_codec: Arc<dyn LogicalExtensionCodec>,
    /// `PhysicalExtensionCodec` handed to Ballista via
    /// `SessionConfig::with_ballista_physical_extension_codec`. Slice
    /// 4b.4 wires the codec slot. `None` is the default; with no
    /// physical codec installed, federated queries fail when
    /// `DistributedQueryExec` ships the scheduler's physical plan
    /// across — `BallistaPhysicalExtensionCodec` only knows about
    /// its own shuffle nodes, so `VirtualExecutionPlan` +
    /// `SchemaCastScanExec` + `CooperativeExec` wrappers error
    /// with "unsupported plan type". Production sets the
    /// `FederationPlanCodec` from `dataglot-federation` here via
    /// [`Self::with_physical_codec`].
    physical_codec: Option<Arc<dyn PhysicalExtensionCodec>>,
    /// Coordinator-side `CredentialResolver`. Phase 2 slice 3b plumbs
    /// the resolver from `DataglotServer` through the factory into the
    /// cluster handle so per-worker resolution shares the coordinator's
    /// source of truth (vault / env / IAM indirection works the same on
    /// every host).
    ///
    /// In standalone mode (the only mode shipped today) the "worker" is
    /// the same process, so the per-worker model trivially collapses to
    /// one `Arc<dyn CredentialResolver>` shared by reference. The
    /// distinction matters once slice 5's multi-process HA scheduler
    /// ships: each executor binary will construct its own resolver
    /// instance from the same config the coordinator uses, fail
    /// construction if the backend is unreachable, and exit before
    /// registering with the scheduler. Coordinator never serializes
    /// resolved tokens onto the wire (hard rule 12).
    ///
    /// `None` is the default — callers that don't ship credentials in
    /// the Ballista path leave the slot empty. The accessor on
    /// [`BallistaCluster`] reflects this back to consumers so they can
    /// branch on resolver presence.
    credential_resolver: Option<Arc<dyn CredentialResolver>>,
    /// Chaos-monkey fault injection for distributed resilience testing
    /// ( phase 3, new in Ballista 54.0.0). `None` = disabled
    /// (production default). When `Some`, [`Self::build_federated_state`]
    /// turns on Ballista's AQE planner (`ballista.planner.adaptive.enabled`)
    /// so the scheduler-side `ChaosCreatingRule` wraps stage execution in
    /// `ChaosExec` and injects the configured fault. Set via
    /// [`Self::with_chaos_execution`].
    chaos: Option<ChaosConfig>,
}

/// Chaos-monkey fault-injection settings for [`BallistaContextFactory`]
/// ( phase 3). Drives Ballista 54.0.0's `ChaosExec` — via the AQE
/// planner — to inject a deterministic fault into distributed stage
/// execution, so a resilience test can assert the query path survives or
/// recovers. **Test/diagnostics only** — never set on a production path.
#[derive(Clone, Debug)]
pub struct ChaosConfig {
    /// Fault to inject: `"transient"` (recoverable IO error on the first
    /// batch), `"fatal"` (non-recoverable), `"panic"`, `"delay"`, or
    /// `"delay:N"` (sleep N ms per batch).
    pub fault_type: String,
    /// RNG seed — pin it for reproducible CI runs.
    pub seed: u64,
    /// Failure probability, `0.0`–`1.0`.
    pub probability: f64,
}

impl std::fmt::Debug for BallistaContextFactory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BallistaContextFactory")
            .field("config", &self.config)
            .field("parallelism", &self.parallelism)
            .field("executor_timeout_seconds", &self.executor_timeout_seconds)
            .field("external_executors", &self.external_executors)
            .field("logical_codec", &"<dyn LogicalExtensionCodec>")
            .field(
                "physical_codec",
                &self
                    .physical_codec
                    .as_ref()
                    .map_or("None", |_| "<dyn PhysicalExtensionCodec>"),
            )
            .field(
                "credential_resolver",
                &self
                    .credential_resolver
                    .as_ref()
                    .map_or("None", |_| "<dyn CredentialResolver>"),
            )
            .field("chaos", &self.chaos)
            .finish()
    }
}

impl BallistaContextFactory {
    /// Create a new factory with the given session config and the
    /// default [`FederationLogicalCodec`] (delegates to Ballista's
    /// stock codec; slice 4b plugs federation handling in).
    #[must_use]
    pub fn new(config: SessionConfig) -> Self {
        Self {
            config,
            parallelism: DEFAULT_STANDALONE_PARALLELISM,
            executor_timeout_seconds: DEFAULT_EXECUTOR_TIMEOUT_SECONDS,
            external_executors: 0,
            logical_codec: Arc::new(FederationLogicalCodec::default()),
            physical_codec: None,
            credential_resolver: None,
            chaos: None,
        }
    }

    /// Create a new factory with default configuration.
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(SessionConfig::default())
    }

    /// Set the standalone-cluster executor parallelism (task slots).
    /// No effect on remote-scheduler contexts; that path uses the
    /// scheduler's configured executor pool.
    #[must_use]
    pub fn with_standalone_parallelism(mut self, slots: usize) -> Self {
        self.parallelism = slots;
        self
    }

    /// Set the scheduler's executor-liveness timeout in seconds — how long
    /// it waits without a heartbeat before declaring an executor dead
    ///. `DataglotServer` passes the `[ballista]` config's
    /// `executor_timeout_seconds`.
    #[must_use]
    pub fn with_executor_timeout_seconds(mut self, seconds: u64) -> Self {
        self.executor_timeout_seconds = seconds;
        self
    }

    /// Set the number of external executor processes in the cluster (0 =
    /// embedded standalone). Drives the distributed session's
    /// `target_partitions` so a query splits across *all* cluster slots
    /// instead of one node's worth. `DataglotServer` passes the
    /// `[ballista]` config's `external_executors`.
    #[must_use]
    pub fn with_external_executors(mut self, external_executors: usize) -> Self {
        self.external_executors = external_executors;
        self
    }

    /// Enable chaos-monkey fault injection for distributed resilience
    /// testing ( phase 3; Ballista 54.0.0). Turns on the AQE planner
    /// and the scheduler-side `ChaosCreatingRule` so `ChaosExec` injects the
    /// given fault into stage execution. `fault_type` is one of
    /// `"transient"` / `"fatal"` / `"panic"` / `"delay"` / `"delay:N"`;
    /// `seed` is pinned for reproducibility; `probability` is `0.0`–`1.0`.
    /// **Test/diagnostics only** — never call on a production context.
    #[must_use]
    pub fn with_chaos_execution(
        mut self,
        fault_type: impl Into<String>,
        seed: u64,
        probability: f64,
    ) -> Self {
        self.chaos = Some(ChaosConfig {
            fault_type: fault_type.into(),
            seed,
            probability,
        });
        self
    }

    /// Distributed `target_partitions`: the aggregate task slots across the
    /// cluster (`external_executors × parallelism`) in external-executor mode,
    /// so the query fans out to every slot rather than a single node's worth.
    /// Embedded standalone (0 external) keeps the session's configured
    /// `target_partitions`..
    fn distributed_target_partitions(&self) -> usize {
        if self.external_executors > 0 {
            (self.external_executors * self.parallelism).max(1)
        } else {
            self.config.target_partitions
        }
    }

    /// Override the `LogicalExtensionCodec` Ballista uses for plan
    /// serialization. Phase 2 slice 4a's wiring point — slice 4b
    /// constructs a [`FederationLogicalCodec`] backed by the
    /// `dataglot-federation` `ConnectorRegistry` and plugs it in here,
    /// teaching the cluster how to round-trip `FederatedPlanNode` on
    /// the wire. The default is the slice-4a delegating wrapper
    /// (functionally equivalent to Ballista's stock codec).
    #[must_use]
    pub fn with_logical_codec(mut self, codec: Arc<dyn LogicalExtensionCodec>) -> Self {
        self.logical_codec = codec;
        self
    }

    /// Borrow the currently-installed logical codec. Tests inspect
    /// this to assert the slot is correctly wired; production code
    /// rarely needs it.
    #[must_use]
    pub fn logical_codec(&self) -> &Arc<dyn LogicalExtensionCodec> {
        &self.logical_codec
    }

    /// Override the `PhysicalExtensionCodec` Ballista uses for
    /// physical-plan serialization across the scheduler→executor
    /// boundary. Slice 4b.4's wiring point — production builds a
    /// `FederationPlanCodec` (from `dataglot-federation`) backed by
    /// the same `ConnectorRegistry` the logical codec uses and plugs
    /// it in here, teaching the cluster how to round-trip
    /// `VirtualExecutionPlan` + `SchemaCastScanExec` +
    /// `CooperativeExec` on the wire. The default is `None` (no
    /// federation handling); federation queries against that
    /// variant error at the physical-plan serialization step.
    #[must_use]
    pub fn with_physical_codec(mut self, codec: Arc<dyn PhysicalExtensionCodec>) -> Self {
        self.physical_codec = Some(codec);
        self
    }

    /// Borrow the currently-installed physical codec, if any. Tests
    /// inspect this to assert the slot is wired correctly.
    #[must_use]
    pub fn physical_codec(&self) -> Option<&Arc<dyn PhysicalExtensionCodec>> {
        self.physical_codec.as_ref()
    }

    /// Attach a coordinator-side `CredentialResolver` to be propagated
    /// onto the [`BallistaCluster`] handle at boot time. Phase 2 slice
    /// 3b's wiring point — resolves Gap 2 of the distributed-readiness
    /// audit (resolver-per-worker model).
    ///
    /// In standalone mode the "worker" is the same process; the cluster
    /// holds the same `Arc<dyn CredentialResolver>` as the coordinator,
    /// so resolution is identity-shared with no wire serialization.
    /// When slice 5 lands the multi-process executor binary, the
    /// `--credentials-config` flag will let each executor construct its
    /// own resolver instance from the same config the coordinator uses;
    /// the coordinator's instance never travels across the wire.
    ///
    /// The fail-fast contract — "worker refuses to register if its
    /// credential backend is unreachable" — is enforced at
    /// resolver-construction time, not at this factory entry point.
    /// `CredentialResolver` impls are required to pre-fetch their
    /// source of truth at `new()`-time (see the trait docs); a backend
    /// that's down on boot already failed construction and never
    /// reached this method. In-process collapse trivially preserves
    /// that semantic because the coordinator's successful construction
    /// is the same instance the cluster holds.
    #[must_use]
    pub fn with_credential_resolver(mut self, resolver: Arc<dyn CredentialResolver>) -> Self {
        self.credential_resolver = Some(resolver);
        self
    }

    /// Borrow the currently-attached credential resolver, if any. Tests
    /// inspect this to assert the slot is wired correctly; production
    /// code reaches for [`BallistaCluster::credential_resolver`]
    /// after boot.
    #[must_use]
    pub fn credential_resolver(&self) -> Option<&Arc<dyn CredentialResolver>> {
        self.credential_resolver.as_ref()
    }

    /// Get the session configuration.
    #[must_use]
    pub fn config(&self) -> &SessionConfig {
        &self.config
    }

    /// Get the standalone-cluster parallelism setting.
    #[must_use]
    pub fn standalone_parallelism(&self) -> usize {
        self.parallelism
    }

    /// Build the federated `SessionState`. Same physical-optimizer
    /// strip (`FilterPushdown` removed to work around
    /// `datafusion-federation 0.5.3`'s pushdown bug) and same
    /// federation analyzer rules `SessionContextFactory::create_federated_context`
    /// applies on the single-node side.
    ///
    /// Slice 4b.3 follow-up — installs `FederatedQueryPlanner` on the
    /// state. The *coordinator-side* `SessionContext` that
    /// `standalone_with_state` returns has this planner replaced by
    /// `BallistaQueryPlanner` (via `upgrade_for_ballista`); but the
    /// *scheduler-side* `SessionContext` built from the same state via
    /// `new_standalone_scheduler_from_state` keeps the planner we
    /// install here. That's the one that does logical→physical
    /// conversion when `DistributedQueryExec` ships the plan over;
    /// without this hook the scheduler errors with "No installed
    /// planner was able to convert the custom node to an execution
    /// plan: Federated" the moment a federation query is submitted.
    /// Build the shared `RuntimeEnv` for Ballista-backed sessions from the
    /// resource knobs on the workspace `SessionConfig` — the
    /// same fair-spill-pool + spill-dir shape
    /// `dataglot_core::SessionContextFactory` applies on the single-node
    /// path (duplicated here with ballista's re-exported datafusion types
    /// so this crate keeps depending only on `ballista` + `dataglot-core`).
    /// Neither knob set ⇒ the default (unbounded) runtime.
    ///
    /// Distributed execution is the memory-hungriest path (shuffle-heavy
    /// joins), so bounding it matters most here: attached to the session
    /// state, the pool guards the coordinator-side operators (final
    /// aggregation / merge / result collection) of every context minted
    /// from this factory.
    fn build_runtime_env(
        &self,
    ) -> Result<ballista::datafusion::execution::runtime_env::RuntimeEnv> {
        use ballista::datafusion::execution::memory_pool::FairSpillPool;
        use ballista::datafusion::execution::runtime_env::{RuntimeEnv, RuntimeEnvBuilder};

        if self.config.memory_limit_bytes.is_none() && self.config.spill_dir.is_none() {
            return Ok(RuntimeEnv::default());
        }
        let mut builder = RuntimeEnvBuilder::new();
        if let Some(bytes) = self.config.memory_limit_bytes {
            builder = builder.with_memory_pool(Arc::new(FairSpillPool::new(bytes)));
        }
        if let Some(dir) = &self.config.spill_dir {
            builder = builder.with_temp_file_path(dir.clone());
        }
        builder.build().map_err(|e| {
            DataglotError::Internal(format!("ballista runtime-env construction failed: {e}"))
        })
    }

    fn build_federated_state_builder(&self) -> SessionStateBuilder {
        // Ballista needs its SessionConfig variant (carries
        // `ballista_*` extension fields the standalone scheduler
        // reads). Start there, then apply the workspace
        // `SessionConfig` settings on top so single-node and Ballista
        // paths surface identical batch sizes / partition counts /
        // catalog defaults.
        //
        // Shuffle-fetch resilience: `new_with_ballista()` also
        // carries Ballista 54's reduce-side buffered shuffle-fetch retry —
        // `io_retries_times` (default 3) × `io_retry_wait_time_ms` (default
        // 3000 ms) around `fetch_partition_buffered`, gated by
        // `is_retriable_fetch_error` (`GrpcConnectionError | FetchFailed`).
        // Buffering the partition body makes a mid-stream transport break (the
        // SF100-spill h2 broken pipe in ) retriable without emitting
        // duplicate batches — the resilience Ballista 53 lacked. We inherit the
        // defaults here (never override them to 0); `shuffle_fetch_retry_is_active`
        // pins that so a future bump can't silently disable it.
        let mut df_config: DfSessionConfig = DfSessionConfig::new_with_ballista()
            .with_batch_size(self.config.batch_size)
            // Distributed sizing: split to the aggregate cluster slots, not a
            // single node's, so external executors aren't left idle.
            .with_target_partitions(self.distributed_target_partitions())
            .with_default_catalog_and_schema(
                &self.config.default_catalog,
                &self.config.default_schema,
            )
            .with_information_schema(self.config.information_schema)
            .with_ballista_standalone_parallelism(self.parallelism)
            // Phase 2 slice 4a — plug our logical codec into Ballista.
            // Today's `FederationLogicalCodec` default delegates 100% to
            // Ballista's stock codec, so behaviour matches slice 3a.
            // Slice 4b replaces this with a federation-aware codec via
            // `with_logical_codec` on the factory.
            .with_ballista_logical_extension_codec(Arc::clone(&self.logical_codec));
        // Slice 4b.4 — plug the physical codec into Ballista when
        // set. `new_standalone_scheduler_from_state` reads this
        // off `SessionConfig` to wire the codec into both the
        // scheduler and the standalone executor; that's what
        // lets `VirtualExecutionPlan` / `SchemaCastScanExec` /
        // `CooperativeExec` survive the physical-plan ship-across.
        if let Some(physical_codec) = self.physical_codec.as_ref() {
            df_config =
                df_config.with_ballista_physical_extension_codec(Arc::clone(physical_codec));
        }

        //  phase 3 — chaos-monkey fault injection (Ballista 54.0.0).
        // `None` in production; only a resilience test sets it. Enabling chaos
        // also turns on the AQE planner, because the rule that wraps a stage in
        // `ChaosExec` (`ChaosCreatingRule`) lives in the scheduler's adaptive
        // optimizer. The keys are Ballista config constants, so a bad set here
        // is a programming error, not a runtime condition.
        if let Some(chaos) = self.chaos.as_ref() {
            let opts = df_config.options_mut();
            for (key, value) in [
                ("ballista.planner.adaptive.enabled", "true".to_string()),
                (
                    "ballista.testing.chaos_execution.enabled",
                    "true".to_string(),
                ),
                (
                    "ballista.testing.chaos_execution.fault_type",
                    chaos.fault_type.clone(),
                ),
                (
                    "ballista.testing.chaos_execution.probability",
                    chaos.probability.to_string(),
                ),
                (
                    "ballista.testing.chaos_execution.seed",
                    chaos.seed.to_string(),
                ),
            ] {
                opts.set(key, &value)
                    .unwrap_or_else(|e| panic!("set ballista chaos option {key}: {e}"));
            }
        }

        let mut kept_rules: Vec<_> = PhysicalOptimizer::default()
            .rules
            .into_iter()
            .filter(|rule| {
                let name = rule.name();
                name != "FilterPushdown" && name != "FilterPushdown(Post)"
            })
            .collect();
        //  — wrap each federation scan in a `PushdownMetricsExec` so its
        // per-source row/batch/elapsed counts ride Ballista's task-metric channel
        // back to the coordinator (the query-profile treeview reads them via
        // `get_job_metrics`). Runs last; the node round-trips through the physical
        // codec so scheduler and worker plans stay operator-count-symmetric.
        kept_rules.push(Arc::new(dataglot_federation::WrapFederatedScansForMetrics));

        SessionStateBuilder::new()
            .with_config(df_config)
            .with_default_features()
            // Federation defaults + the  dedup-unparse guard —
            // same rule set as dataglot-core's federated context, via
            // the shared constructor so the wiring can't drift.
            .with_optimizer_rules(
                dataglot_core::federation_dedup_guard::federated_optimizer_rules(),
            )
            .with_physical_optimizer_rules(kept_rules)
            // Slice 4b.3 — the scheduler side needs this to turn
            // `FederatedPlanNode` into `VirtualExecutionPlan`; see
            // doc-comment on this method for the full rationale.
            // The coordinator-side context replaces this planner
            // with `BallistaQueryPlanner` at `upgrade_for_ballista`
            // time, so this install only affects the scheduler-side
            // state (which is exactly what we want).
            .with_query_planner(Arc::new(datafusion_federation::FederatedQueryPlanner::new()))
    }

    /// Boot a standalone Ballista cluster (1 scheduler + 1 executor,
    /// in-process) and return a `SessionContext` driving it. The
    /// federation analyzer rules are installed; Ballista replaces the
    /// query planner with `BallistaQueryPlanner` to dispatch (see
    /// the module doc's "What is — and is NOT — installed" section
    /// for the architectural detail). The `FilterPushdown`
    /// physical-optimizer rule is stripped (same
    /// `datafusion-federation 0.5.3` workaround the single-node side
    /// applies).
    ///
    /// Returns an error if Ballista's standalone bring-up fails.
    /// The error path is most commonly a port-bind collision when
    /// multiple Ballista contexts are created in the same process
    /// without dropping the previous one.
    ///
    /// # Errors
    /// Wraps `ballista`'s `DataFusionError` into the workspace
    /// `DataglotError::Internal` shape so call sites can use the
    /// shared error type.
    pub async fn create_standalone_context(&self) -> Result<SessionContext> {
        // Attach the (possibly resource-guarded, ) runtime before
        // the state is built, so every operator this context runs is
        // accounted against the configured memory pool.
        let runtime = Arc::new(self.build_runtime_env()?);
        let state = self
            .build_federated_state_builder()
            .with_runtime_env(runtime)
            .build();
        SessionContext::standalone_with_state(state)
            .await
            .map_err(|e| {
                DataglotError::Internal(format!("ballista standalone context bring-up failed: {e}"))
            })
    }

    /// Build the federated `SessionState` this factory would hand to a
    /// standalone boot — federation analyzer rules, `FilterPushdown`
    /// strip, query planner, and (crucially) the ballista logical +
    /// physical codec config extensions. Public so multi-process tests
    /// can boot a scheduler from this state
    /// (`new_standalone_scheduler_from_state`) and mint a client via
    /// `upgrade_for_ballista` **without** the in-process executor that
    /// `create_standalone_context` always spawns (: the
    /// subprocess-executor e2e needs scheduler + client only).
    #[must_use]
    pub fn build_federated_state(
        &self,
    ) -> ballista::datafusion::execution::session_state::SessionState {
        self.build_federated_state_builder().build()
    }

    /// Like [`Self::create_standalone_context`], but the scheduler's
    /// observability REST API (`/api/state`, `/api/executors`,
    /// `/api/jobs`, `/api/job/{id}/stages`, DOT graphs) is served on
    /// `api_bind` — the data source for the testbench's live cluster
    /// view. See [`crate::monitor`] for why upstream's standalone boot
    /// can't do this.
    ///
    /// Returns the Ballista-backed context and the bound API address
    /// (`None` if `api_bind` was `None` or the bind failed — monitoring
    /// is additive and never blocks the cluster).
    ///
    /// # Errors
    /// Same failure surface as [`Self::create_standalone_context`].
    pub async fn create_monitored_standalone_context(
        &self,
        api_bind: Option<std::net::SocketAddr>,
    ) -> Result<(SessionContext, Option<std::net::SocketAddr>)> {
        let state = self.build_federated_state_builder().build();
        let boot = crate::monitor::boot_monitored_standalone(
            &state,
            api_bind,
            self.executor_timeout_seconds,
        )
        .await?;
        Ok((boot.context, boot.api_addr))
    }

    /// Server-mode entry point — boots a standalone Ballista cluster
    /// and returns a [`BallistaCluster`] handle. The cluster lives
    /// for as long as the returned handle (or any clones of it) is
    /// alive; per-pgwire-session contexts are minted from it via
    /// [`BallistaCluster::create_session`].
    ///
    /// Distinct from [`Self::create_standalone_context`] which is
    /// the test-shaped entry point: that one returns a single
    /// `SessionContext` directly, suitable for one-shot tests that
    /// want a fresh cluster per test. The cluster handle is what
    /// `DataglotServer::new` calls — boot once at server start, mint
    /// many sessions over the server's lifetime.
    ///
    /// # Errors
    /// Wraps `ballista`'s `DataFusionError` into the workspace
    /// `DataglotError::Internal` shape so call sites can use the
    /// shared error type.
    pub async fn boot_standalone_cluster(&self) -> Result<BallistaCluster> {
        let reference_ctx = self.create_standalone_context().await?;
        Ok(BallistaCluster::new(
            reference_ctx,
            self.credential_resolver.clone(),
        ))
    }

    /// Like [`Self::boot_standalone_cluster`], with the scheduler's
    /// observability REST API served on `api_bind` (see
    /// [`crate::monitor`]). Returns the cluster handle and the bound
    /// API address (`None` when unrequested or the bind failed —
    /// monitoring never blocks the cluster).
    ///
    /// # Errors
    /// Same failure surface as [`Self::boot_standalone_cluster`].
    pub async fn boot_monitored_standalone_cluster(
        &self,
        api_bind: Option<std::net::SocketAddr>,
    ) -> Result<(BallistaCluster, Option<std::net::SocketAddr>)> {
        let (reference_ctx, api_addr) = self.create_monitored_standalone_context(api_bind).await?;
        Ok((
            BallistaCluster::new(reference_ctx, self.credential_resolver.clone()),
            api_addr,
        ))
    }

    /// Boot a **scheduler-only** cluster: an in-process scheduler
    /// bound to `grpc_bind` + the REST API on `api_bind`, but **no
    /// in-process executor**. External `dataglot-ballista-executor` processes
    /// register with the returned gRPC address to form the worker pool.
    ///
    /// The multi-executor counterpart to [`Self::boot_monitored_standalone_cluster`].
    /// Returns the cluster handle, the bound REST API address (`None` if
    /// unrequested / bind failed), and the scheduler's gRPC address (where
    /// executors register). See [`crate::monitor::boot_monitored_scheduler_only`].
    ///
    /// # Errors
    /// Scheduler bind/init or client-state construction failure.
    pub async fn boot_monitored_scheduler_only_cluster(
        &self,
        api_bind: Option<std::net::SocketAddr>,
        grpc_bind: &str,
    ) -> Result<(
        BallistaCluster,
        Option<std::net::SocketAddr>,
        std::net::SocketAddr,
    )> {
        let state = self.build_federated_state_builder().build();
        let boot = crate::monitor::boot_monitored_scheduler_only(
            &state,
            api_bind,
            grpc_bind,
            self.executor_timeout_seconds,
        )
        .await?;
        Ok((
            BallistaCluster::new(boot.context, self.credential_resolver.clone()),
            boot.api_addr,
            boot.grpc_addr,
        ))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ballista::datafusion::arrow::array::RecordBatch;
    use ballista::datafusion::arrow::util::pretty::pretty_format_batches;

    #[test]
    fn factory_takes_session_config() {
        let factory = BallistaContextFactory::new(
            SessionConfig::new()
                .with_default_catalog("dataglot")
                .with_default_schema("public"),
        );
        assert_eq!(factory.config().default_catalog, "dataglot");
        assert_eq!(factory.config().default_schema, "public");
        assert_eq!(
            factory.standalone_parallelism(),
            DEFAULT_STANDALONE_PARALLELISM
        );
    }

    ///  pin: Ballista 54's buffered shuffle-fetch retry must stay
    /// ACTIVE in the distributed session config we build. The reduce-side
    /// `with_retry(io_retries_times, io_retry_wait_time_ms,
    /// is_retriable_fetch_error, fetch_partition_buffered)` is what turns a
    /// transient mid-stream shuffle-fetch break (an h2 broken pipe under
    /// SF100 spill pressure) into a retried fetch instead of a failed job —
    /// the resilience Ballista 53 lacked. We inherit its defaults via
    /// `new_with_ballista()` and never override them; this fails loudly if a
    /// future upgrade flips the default or a change sets `io_retries_times = 0`.
    #[test]
    fn shuffle_fetch_retry_is_active_in_distributed_config() {
        let state = BallistaContextFactory::with_defaults().build_federated_state();
        let bc = state.config().ballista_config();
        assert!(
            bc.io_retries_times() >= 1,
            "Ballista shuffle-fetch retry must be active — io_retries_times = {}",
            bc.io_retries_times()
        );
        assert!(
            bc.io_retry_wait_time_ms() > 0,
            "shuffle-fetch retry backoff must be positive — io_retry_wait_time_ms = {}",
            bc.io_retry_wait_time_ms()
        );
    }

    #[test]
    fn factory_with_defaults_matches_session_config_defaults() {
        let factory = BallistaContextFactory::with_defaults();
        assert_eq!(factory.config().default_catalog, "dataglot");
        assert_eq!(factory.config().default_schema, "public");
    }

    #[test]
    fn distributed_target_partitions_scales_to_cluster_slots() {
        // External-executor mode: split to the aggregate cluster slots
        // (external_executors × parallelism), not one node's worth — so a
        // query fans out to every slot instead of leaving half idle.
        let external = BallistaContextFactory::with_defaults()
            .with_standalone_parallelism(4)
            .with_external_executors(2);
        assert_eq!(external.distributed_target_partitions(), 8);

        // Embedded standalone (0 external) keeps the session's configured value.
        let embedded = BallistaContextFactory::with_defaults().with_standalone_parallelism(4);
        assert_eq!(
            embedded.distributed_target_partitions(),
            embedded.config().target_partitions
        );
    }

    #[test]
    fn runtime_env_builds_with_and_without_resource_guardrails() {
        //  — default config: the unguarded default runtime.
        let plain = BallistaContextFactory::with_defaults();
        assert!(plain.build_runtime_env().is_ok());

        // Memory limit + spill dir: the guarded runtime must construct
        // (the pool/limit itself is exercised end-to-end in
        // dataglot-core's `memory_limit_turns_oom_into_a_typed_error`).
        let guarded = BallistaContextFactory::new(
            SessionConfig::new()
                .with_memory_limit_bytes(64 * 1024 * 1024)
                .with_spill_dir(std::env::temp_dir()),
        );
        assert!(guarded.build_runtime_env().is_ok());
    }

    #[test]
    fn parallelism_builder_preserved() {
        let factory = BallistaContextFactory::with_defaults().with_standalone_parallelism(4);
        assert_eq!(factory.standalone_parallelism(), 4);
    }

    /// Slice 4b.4 — the factory exposes a physical-codec slot for
    /// federation handling. Default is `None`; a custom codec
    /// round-trips through the `with_physical_codec` builder.
    #[test]
    fn physical_codec_builder_preserved() {
        use datafusion_proto::physical_plan::PhysicalExtensionCodec;
        use dataglot_federation::{FederationPlanCodec, InMemoryConnectorRegistry};
        use std::sync::Arc;

        // Default: None — slice-2/3a behaviour, no federation
        // physical-codec installed.
        let default_factory = BallistaContextFactory::with_defaults();
        assert!(
            default_factory.physical_codec().is_none(),
            "default factory must not install a physical codec — \
             callers opt in via with_physical_codec()"
        );

        // Round-trip a real FederationPlanCodec.
        let registry = Arc::new(InMemoryConnectorRegistry::empty());
        let codec: Arc<dyn PhysicalExtensionCodec> = Arc::new(FederationPlanCodec::new(registry));
        let factory =
            BallistaContextFactory::with_defaults().with_physical_codec(Arc::clone(&codec));
        let stored = factory
            .physical_codec()
            .expect("physical codec stored after with_physical_codec");
        let stored_repr = format!("{stored:?}");
        assert!(
            stored_repr.contains("FederationPlanCodec"),
            "expected FederationPlanCodec to round-trip through with_physical_codec, got: {stored_repr}"
        );
    }

    /// Phase 2 slice 4a — the factory exposes the logical-codec slot
    /// and a custom codec round-trips through the `with_logical_codec`
    /// builder. The codec's debug repr is the most stable way to
    /// fingerprint it from outside the impl since `LogicalExtensionCodec`
    /// isn't `Eq` and the trait object has no inspect surface.
    #[test]
    fn logical_codec_builder_preserved() {
        // Default is FederationLogicalCodec (wraps Ballista's stock codec).
        let default_factory = BallistaContextFactory::with_defaults();
        let default_repr = format!("{:?}", default_factory.logical_codec());
        assert!(
            default_repr.contains("FederationLogicalCodec"),
            "default factory should install FederationLogicalCodec, got: {default_repr}"
        );

        // Custom codec round-trips. Use Ballista's stock codec directly
        // as the "alternate" — its debug repr is distinguishable from
        // our wrapper's.
        let custom: std::sync::Arc<dyn datafusion_proto::logical_plan::LogicalExtensionCodec> =
            std::sync::Arc::new(ballista_core::serde::BallistaLogicalExtensionCodec::default());
        let custom_repr_input = format!("{custom:?}");
        let factory = BallistaContextFactory::with_defaults().with_logical_codec(custom);
        let custom_repr_stored = format!("{:?}", factory.logical_codec());
        assert_eq!(
            custom_repr_input, custom_repr_stored,
            "custom codec was not preserved through the builder"
        );
        assert!(
            !custom_repr_stored.contains("FederationLogicalCodec"),
            "expected the stock Ballista codec, not our wrapper, after override: {custom_repr_stored}"
        );
    }

    /// Phase 2 slice 3b — default factory carries no credential
    /// resolver. Callers that don't ship credentials through the
    /// Ballista path must leave the slot empty so consumers can
    /// branch cleanly on resolver presence.
    #[test]
    fn factory_default_has_no_credential_resolver() {
        let factory = BallistaContextFactory::with_defaults();
        assert!(
            factory.credential_resolver().is_none(),
            "default factory must not install a credential resolver"
        );
    }

    /// Phase 2 slice 3b — the `with_credential_resolver` builder
    /// stores the resolver and the accessor returns the exact `Arc`
    /// that was attached. `Arc::ptr_eq` pins the identity-shared
    /// contract: the resolver never gets re-allocated or re-wrapped
    /// inside the factory, so the in-process collapse semantic holds
    /// (one allocation shared between coordinator and the standalone
    /// "worker").
    #[test]
    fn with_credential_resolver_preserves_arc_identity() {
        use dataglot_core::StaticCredentialResolver;

        let resolver: Arc<dyn CredentialResolver> = Arc::new(StaticCredentialResolver::new());
        let factory =
            BallistaContextFactory::with_defaults().with_credential_resolver(Arc::clone(&resolver));

        let stored = factory
            .credential_resolver()
            .expect("resolver stored after with_credential_resolver");
        assert!(
            Arc::ptr_eq(stored, &resolver),
            "resolver Arc identity not preserved — factory must store the same allocation"
        );
    }

    /// Phase 2 slice 3b — the factory's `Debug` impl must never leak
    /// resolver contents (hard rule 12). The resolver slot
    /// surfaces only as a presence marker.
    #[test]
    fn factory_debug_does_not_leak_resolver_contents() {
        use dataglot_core::{Credentials, StaticCredentialResolver};

        let mut r = StaticCredentialResolver::new();
        r.insert("pg_main", Credentials::Token("hunter2".into()));
        let factory: BallistaContextFactory =
            BallistaContextFactory::with_defaults().with_credential_resolver(Arc::new(r));

        let debug = format!("{factory:?}");
        assert!(
            !debug.contains("hunter2"),
            "factory Debug leaked a credential secret:\n{debug}"
        );
        assert!(
            !debug.contains("pg_main"),
            "factory Debug leaked a credential handle name (could indicate Debug of inner resolver state):\n{debug}"
        );
        assert!(
            debug.contains("credential_resolver"),
            "factory Debug should record resolver presence:\n{debug}"
        );
    }

    /// Smoke test: the factory's standalone context boots and runs
    /// the same `SELECT 1 + 1` literal slice 1's smoke test ran.
    /// Slice 1 instantiated the standalone cluster inline; this
    /// test proves the factory wraps that bring-up correctly.
    #[tokio::test]
    async fn standalone_context_select_literal() {
        let factory = BallistaContextFactory::with_defaults();
        let ctx = factory
            .create_standalone_context()
            .await
            .expect("ballista standalone boots");
        let batches = ctx
            .sql("SELECT 1 + 1 AS two")
            .await
            .expect("plan SELECT 1 + 1")
            .collect()
            .await
            .expect("execute SELECT 1 + 1");
        let printed = pretty_format_batches(&batches).expect("format").to_string();
        assert_eq!(
            batches.iter().map(RecordBatch::num_rows).sum::<usize>(),
            1,
            "expected one row, got:\n{printed}"
        );
        assert!(
            printed.contains('2'),
            "expected literal `2` in result:\n{printed}"
        );
    }

    /// Multi-executor: the scheduler-only cluster boots with a
    /// bound gRPC port (external executors need it), serves the REST API, and
    /// mints **push-mode** sessions (paired with push-staged external
    /// executors) — with NO in-process executor.
    #[tokio::test]
    async fn scheduler_only_cluster_is_bound_and_push_mode() {
        let factory = BallistaContextFactory::with_defaults();
        let (cluster, api_addr, grpc_addr) = factory
            .boot_monitored_scheduler_only_cluster(
                Some("127.0.0.1:0".parse().unwrap()),
                "localhost:0",
            )
            .await
            .expect("scheduler-only cluster boots");
        assert_ne!(grpc_addr.port(), 0, "scheduler gRPC must be bound");
        assert!(api_addr.is_some(), "REST API should bind");
        assert!(
            !cluster
                .reference_session()
                .state()
                .config()
                .ballista_config()
                .client_pull(),
            "scheduler-only cluster must mint push-mode sessions (external push-staged executors)"
        );
    }

    /// Defensive guard pinning the slice-2 + slice-4b.3 split:
    /// the COORDINATOR-side `SessionContext` Ballista returns has
    /// `BallistaQueryPlanner` (it has to — the planner ships work to
    /// workers via `DistributedQueryExec`). Slice 4b.3 additionally
    /// installs `FederatedQueryPlanner` on the underlying state we
    /// hand `standalone_with_state`, so the SCHEDULER-side context
    /// (built from the same state via
    /// `new_standalone_scheduler_from_state`) gets that planner.
    /// We can only observe the coordinator side from here, so this
    /// test still asserts `BallistaQueryPlanner` is the visible
    /// planner — the scheduler side's planner is exercised by the
    /// Docker-gated e2e in `tests/ballista_federation_codec.rs`.
    #[tokio::test]
    async fn standalone_context_query_planner_is_ballista() {
        let factory = BallistaContextFactory::with_defaults();
        let ctx = factory
            .create_standalone_context()
            .await
            .expect("ballista standalone boots");
        let planner = ctx.state().query_planner().clone();
        let debug_repr = format!("{planner:?}");
        assert!(
            debug_repr.contains("BallistaQueryPlanner"),
            "expected Ballista standalone context to use BallistaQueryPlanner \
             on the coordinator side, got debug repr: {debug_repr}"
        );
    }

    /// Defensive guard: same as
    /// `SessionContextFactory::test_federated_context_strips_filter_pushdown_rule`.
    /// If the strip ever stops working on the Ballista side, the
    /// `datafusion-federation 0.5.3` pushdown bug re-introduces and
    /// cross-source JOIN+WHERE results diverge between single-node
    /// and cluster — exactly the regression Phase 2 exit-criterion
    /// #1 forbids.
    #[tokio::test]
    async fn standalone_context_strips_filter_pushdown_rule() {
        let factory = BallistaContextFactory::with_defaults();
        let ctx = factory
            .create_standalone_context()
            .await
            .expect("ballista standalone boots");
        let state = ctx.state();
        let names: Vec<&str> = state
            .physical_optimizers()
            .iter()
            .map(|r| r.name())
            .collect();
        assert!(
            !names.contains(&"FilterPushdown"),
            "FilterPushdown was not stripped from the Ballista SessionContext: {names:?}"
        );
        assert!(
            !names.contains(&"FilterPushdown(Post)"),
            "FilterPushdown(Post) was not stripped from the Ballista SessionContext: {names:?}"
        );
    }

    // --- executor_timeout_seconds threading ----------------------
    // The default + override drive how long an idle/paused executor survives
    // before the scheduler culls it. Verified via the Debug repr (no
    // accessor); a regression that dropped the override would revert to the
    // 180s upstream cull and silently break host-pause resilience.

    #[test]
    fn factory_default_executor_timeout_is_3600() {
        let repr = format!("{:?}", BallistaContextFactory::with_defaults());
        assert!(
            repr.contains("executor_timeout_seconds: 3600"),
            "default should be 3600s: {repr}"
        );
    }

    // --- chaos-monkey fault injection ( phase 3) --------------------

    #[test]
    fn chaos_defaults_to_disabled() {
        let repr = format!("{:?}", BallistaContextFactory::with_defaults());
        assert!(
            repr.contains("chaos: None"),
            "production default must be chaos-disabled: {repr}"
        );
    }

    #[test]
    fn with_chaos_execution_stores_config() {
        let repr = format!(
            "{:?}",
            BallistaContextFactory::with_defaults().with_chaos_execution("transient", 7, 1.0)
        );
        assert!(
            repr.contains("fault_type: \"transient\"")
                && repr.contains("seed: 7")
                && repr.contains("probability: 1.0"),
            "chaos config should round-trip through Debug: {repr}"
        );
    }

    #[test]
    fn with_executor_timeout_seconds_overrides_default() {
        let repr = format!(
            "{:?}",
            BallistaContextFactory::with_defaults().with_executor_timeout_seconds(900)
        );
        assert!(
            repr.contains("executor_timeout_seconds: 900"),
            "override should stick: {repr}"
        );
        assert!(!repr.contains("3600"), "default must be replaced: {repr}");
    }

    // --- distributed_target_partitions boundaries ----------------

    #[test]
    fn distributed_target_partitions_guards_zero_parallelism() {
        // external > 0 but parallelism 0 would compute 0 slots; the `.max(1)`
        // guard keeps target_partitions from collapsing to a degenerate 0.
        let factory = BallistaContextFactory::with_defaults()
            .with_standalone_parallelism(0)
            .with_external_executors(2);
        assert_eq!(factory.distributed_target_partitions(), 1);
    }

    #[test]
    fn distributed_target_partitions_single_external_equals_parallelism() {
        // One external executor == that node's slots.
        let factory = BallistaContextFactory::with_defaults()
            .with_standalone_parallelism(3)
            .with_external_executors(1);
        assert_eq!(factory.distributed_target_partitions(), 3);
    }

    #[test]
    fn with_external_executors_preserved_in_debug() {
        // Pin the  knob independent of the sizing arithmetic.
        let repr = format!(
            "{:?}",
            BallistaContextFactory::with_defaults().with_external_executors(5)
        );
        assert!(
            repr.contains("external_executors: 5"),
            "external_executors should round-trip: {repr}"
        );
    }
}

//! `SessionContext` factory and configuration.
//!
//! This module provides the [`SessionContextFactory`] for creating
//! configured `DataFusion` `SessionContext` instances.

use std::sync::Arc;

use datafusion::execution::runtime_env::RuntimeEnv;
use datafusion::prelude::{SessionConfig as DfSessionConfig, SessionContext};
use datafusion_pg_catalog::pg_catalog::context::EmptyContextProvider;
use datafusion_pg_catalog::pg_catalog::{
    array_bounds_udf, create_current_schema_udf, create_current_schemas_udf,
    create_pg_backend_pid_udf, create_pg_encoding_to_char_udf, create_pg_get_constraintdef,
    create_pg_get_partition_ancestors_udf, create_pg_get_partkeydef_udf,
    create_pg_get_statisticsobjdef_columns_udf, create_pg_get_userbyid_udf,
    create_pg_relation_is_publishable_udf, create_pg_relation_size_udf,
    create_pg_stat_get_numscans, create_pg_total_relation_size_udf, create_session_user_udf,
    format_type, has_privilege_udf, pg_get_expr_udf, quote_ident_udf, setup_pg_catalog,
};

use crate::error::Result;

/// Register the `pg_catalog.*` tables that every psql / JDBC client
/// introspects on connect (`pg_settings`, `pg_class`, `pg_namespace`,
/// `pg_attribute`, `pg_type`, ...).
///
/// Without this, `\d` / `\dt` / `\dn` fail with `table
/// 'dataglot.pg_catalog.*' not found`. See  and
/// `docs/phases/phase-3/06-pg-catalog-compatibility.md`.
///
/// **Identity model.** Uses `EmptyContextProvider` for v1; `pg_roles`
/// is empty and `pg_table_is_visible` returns the default visibility
/// for every role. A follow-up task hooks Dataglot's own
/// `dataglot_policy::Identity` into a custom `PgCatalogContextProvider`
/// so role-aware introspection reflects the connected user.
///
/// **`.expect` rationale.** `setup_pg_catalog` can only fail when the
/// passed catalog name doesn't resolve in the session — which cannot
/// happen here because the caller has just built `ctx` with
/// `with_default_catalog_and_schema(default_catalog, …)` one line
/// earlier. A panic here would mean a regression inside this crate's
/// own session-construction path, not a runtime condition the caller
/// could meaningfully recover from.
fn register_pg_catalog(ctx: &SessionContext, default_catalog: &str) {
    if let Err(e) = setup_pg_catalog(ctx, default_catalog, EmptyContextProvider) {
        // Build-time invariant violation (see the `.expect` rationale
        // above). Emit a structured error before the panic so the failure
        // is diagnosable in logs, not just a bare panic string.
        tracing::error!(
            error = %e,
            default_catalog,
            "pg_catalog registration failed on a freshly-built SessionContext"
        );
        panic!("pg_catalog registration must succeed against freshly-built SessionContext: {e}");
    }
    //  — `\df` / `\dT` filter on `pg_function_is_visible` /
    // `pg_type_is_visible`, which `datafusion-pg-catalog` doesn't provide; add
    // the always-true shims so those commands work single-node too.
    register_pg_catalog_visibility_shims(ctx);
}

/// Reserved engine-local catalog name that always provides a **writable** home
/// for runtime objects (derived-product views today; future `CREATE TABLE`).
///
/// DataFusion auto-creates a writable `MemoryCatalog` for the configured
/// `default_catalog`, but when that name is also a federated source the
/// read-only federated `CatalogProvider` replaces it — leaving a session with
/// no writable catalog at all. Guaranteeing this catalog exists means
/// `CREATE VIEW dataglot.public.…` always has somewhere to land, regardless of
/// `default_catalog`. It matches the default-config default catalog name, so a
/// `default_catalog = "dataglot"` deployment already has it (and
/// [`ensure_runtime_catalog`] then no-ops).
pub const RUNTIME_CATALOG: &str = "dataglot";
/// Writable schema within [`RUNTIME_CATALOG`].
pub const RUNTIME_SCHEMA: &str = "public";

/// Ensure the reserved writable runtime catalog/schema ([`RUNTIME_CATALOG`] /
/// [`RUNTIME_SCHEMA`], ) exists on `ctx`, so runtime views have a
/// writable home even when `default_catalog` names a read-only federated source.
///
/// Idempotent and non-destructive: a no-op when a catalog of that name is
/// already present — so a `default_catalog = "dataglot"` session (DataFusion
/// already made it writable) or a source that legitimately claims the name is
/// never clobbered. Registering the `public` schema into a fresh
/// `MemoryCatalogProvider` cannot fail, so the result is discarded.
pub fn ensure_runtime_catalog(ctx: &SessionContext) {
    use datafusion::catalog::{CatalogProvider, MemoryCatalogProvider, MemorySchemaProvider};
    if ctx.catalog(RUNTIME_CATALOG).is_some() {
        return;
    }
    let catalog = MemoryCatalogProvider::new();
    let _ = catalog.register_schema(RUNTIME_SCHEMA, Arc::new(MemorySchemaProvider::new()));
    ctx.register_catalog(RUNTIME_CATALOG, Arc::new(catalog));
}

/// Register the Dataglot-added `pg_catalog` compatibility UDFs that
/// `datafusion-pg-catalog` doesn't provide but Postgres clients rely on.
/// Registered on **every** context — single-node via [`register_pg_catalog`],
/// distributed via [`register_pg_catalog_udfs`] — so the
/// harness/`SessionContextFactory` path gets them, not just the pgwire server
/// hook. `register_udf` replaces by name, so calling this repeatedly is
/// idempotent.
///
/// - `pg_function_is_visible` / `pg_type_is_visible` — psql's `\df` / `\dT`
///   filter on these; `pg_table_is_visible` comes from
///   `setup_pg_catalog` (single-node) / [`register_pg_catalog_udfs`]
///   (distributed), so it isn't repeated here.
/// - `current_setting(name[, missing_ok])` — capability-GUC lookup that
///   Npgsql (Power BI's driver) and other clients issue on connect
fn register_pg_catalog_visibility_shims(ctx: &SessionContext) {
    ctx.register_udf(crate::functions::pg_function_is_visible_udf());
    ctx.register_udf(crate::functions::pg_type_is_visible_udf());
    ctx.register_udf(crate::functions::current_setting_udf());
    // psql \df / \dT / \d+ render function signatures and object comments via
    // these; without them those meta-commands fail with `Invalid function …`
    //. Dataglot models no user functions or object comments, so they
    // are empty/NULL shims.
    ctx.register_udf(crate::functions::pg_get_function_result_udf());
    ctx.register_udf(crate::functions::pg_get_function_arguments_udf());
    ctx.register_udf(crate::functions::obj_description_udf());
    ctx.register_udf(crate::functions::shobj_description_udf());
    ctx.register_udf(crate::functions::col_description_udf());
}

/// Register the session-independent `pg_catalog` **scalar UDFs** on `ctx` —
/// the exact set [`setup_pg_catalog`] installs (`pg_get_userbyid`,
/// `format_type`, `pg_get_expr`, `current_schema`/`current_schemas`,
/// `session_user`, `has_*_privilege`, `quote_ident`/`parse_ident`,
/// `array_upper`/`array_lower`, `pg_relation_size`, …), **minus** the
/// per-session `current_database` (the pgwire `StartupObserver` registers
/// that against the resolved catalog) and **minus** the `pg_catalog` tables
/// (owned by the scoped overlay).
///
/// The single-node `SessionContextFactory` gets these via [`setup_pg_catalog`]
/// on a bare context. The distributed (Ballista) path **cannot** call
/// `setup_pg_catalog` — its context already carries the `pg_catalog` overlay, so
/// `setup_pg_catalog` fails ("schema is owned by the overlay") — so it
/// registers just the UDFs here. Without them psql's `\d` family and BI-tool
/// introspection break under `--distributed`. `register_udf`
/// replaces by name, so this is idempotent.
pub fn register_pg_catalog_udfs(ctx: &SessionContext) {
    ctx.register_udf(create_current_schema_udf());
    ctx.register_udf(create_current_schemas_udf());
    ctx.register_udf(create_pg_get_userbyid_udf());
    ctx.register_udf(has_privilege_udf::create_has_privilege_udf(
        "has_table_privilege",
    ));
    ctx.register_udf(has_privilege_udf::create_has_privilege_udf(
        "has_schema_privilege",
    ));
    ctx.register_udf(has_privilege_udf::create_has_privilege_udf(
        "has_database_privilege",
    ));
    ctx.register_udf(has_privilege_udf::create_has_privilege_udf(
        "has_any_column_privilege",
    ));
    ctx.register_udf(format_type::create_format_type_udf());
    ctx.register_udf(create_session_user_udf());
    ctx.register_udf(pg_get_expr_udf::create_pg_get_expr_udf());
    ctx.register_udf(create_pg_get_partkeydef_udf());
    ctx.register_udf(create_pg_relation_is_publishable_udf());
    ctx.register_udf(create_pg_get_statisticsobjdef_columns_udf());
    ctx.register_udf(create_pg_encoding_to_char_udf());
    ctx.register_udf(create_pg_backend_pid_udf());
    ctx.register_udf(create_pg_relation_size_udf());
    ctx.register_udf(create_pg_total_relation_size_udf());
    ctx.register_udf(create_pg_stat_get_numscans());
    ctx.register_udf(create_pg_get_constraintdef());
    ctx.register_udf(create_pg_get_partition_ancestors_udf());
    ctx.register_udf(quote_ident_udf::create_quote_ident_udf());
    ctx.register_udf(quote_ident_udf::create_parse_ident_udf());
    ctx.register_udf(array_bounds_udf::create_array_upper_udf());
    ctx.register_udf(array_bounds_udf::create_array_lower_udf());
    // pg_table_is_visible (setup_pg_catalog registers the crate's on the
    // single-node path; this UDF-only path must add it) + the \df/\dT shims.
    ctx.register_udf(crate::functions::pg_table_is_visible_udf());
    register_pg_catalog_visibility_shims(ctx);
}

/// Configuration for creating a `SessionContext`.
#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// Maximum batch size for query execution.
    pub batch_size: usize,
    /// Target number of partitions for parallel execution.
    pub target_partitions: usize,
    /// Default catalog name.
    pub default_catalog: String,
    /// Default schema name.
    pub default_schema: String,
    /// Enable query optimization.
    pub enable_optimization: bool,
    /// Information schema enabled.
    pub information_schema: bool,
    /// Cap on query-execution memory, in bytes. `Some(n)`
    /// installs a [`FairSpillPool`] of `n` bytes on the shared
    /// `RuntimeEnv`, so memory-hungry operators (hash joins, sorts,
    /// aggregations) spill to disk — or fail with a typed
    /// `ResourcesExhausted` error — instead of growing until the OS
    /// OOM-kills the whole process. `None` (default) keeps DataFusion's
    /// unbounded default, identical to pre- behaviour.
    ///
    /// [`FairSpillPool`]: datafusion::execution::memory_pool::FairSpillPool
    pub memory_limit_bytes: Option<usize>,
    /// Directory for operator spill files. `Some(dir)` points
    /// the runtime's disk manager there; `None` (default) uses the OS
    /// temp dir. Only meaningful when spilling happens — i.e. paired
    /// with [`Self::memory_limit_bytes`].
    pub spill_dir: Option<std::path::PathBuf>,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            batch_size: 8192,
            target_partitions: num_cpus::get(),
            default_catalog: "dataglot".to_string(),
            default_schema: "public".to_string(),
            enable_optimization: true,
            information_schema: true,
            memory_limit_bytes: None,
            spill_dir: None,
        }
    }
}

impl SessionConfig {
    /// Create a new session configuration with defaults.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the batch size.
    #[must_use]
    pub fn with_batch_size(mut self, size: usize) -> Self {
        self.batch_size = size;
        self
    }

    /// Set the target partitions.
    #[must_use]
    pub fn with_target_partitions(mut self, partitions: usize) -> Self {
        self.target_partitions = partitions;
        self
    }

    /// Set the default catalog name.
    #[must_use]
    pub fn with_default_catalog(mut self, name: impl Into<String>) -> Self {
        self.default_catalog = name.into();
        self
    }

    /// Set the default schema name.
    #[must_use]
    pub fn with_default_schema(mut self, name: impl Into<String>) -> Self {
        self.default_schema = name.into();
        self
    }

    /// Cap query-execution memory at `bytes` (spill-or-error instead of
    /// process OOM). See [`Self::memory_limit_bytes`].
    #[must_use]
    pub fn with_memory_limit_bytes(mut self, bytes: usize) -> Self {
        self.memory_limit_bytes = Some(bytes);
        self
    }

    /// Direct operator spill files to `dir`. See [`Self::spill_dir`].
    #[must_use]
    pub fn with_spill_dir(mut self, dir: impl Into<std::path::PathBuf>) -> Self {
        self.spill_dir = Some(dir.into());
        self
    }

    /// Convert to `DataFusion` `SessionConfig`.
    #[must_use]
    pub fn to_datafusion_config(&self) -> DfSessionConfig {
        let mut config = DfSessionConfig::new()
            .with_batch_size(self.batch_size)
            .with_target_partitions(self.target_partitions)
            .with_default_catalog_and_schema(&self.default_catalog, &self.default_schema)
            .with_information_schema(self.information_schema);
        // Parquet filter pushdown: evaluate predicates *during* the scan
        // (row filter + page-index/row-group pruning) rather than decoding
        // every row into a RecordBatch and dropping most of them in a
        // downstream `FilterExec`. This is a logical/TableProvider-level
        // pushdown driven by the session config, independent of the
        // physical `FilterPushdown` rule that `create_federated_context`
        // strips for federation correctness — so it's safe to enable here.
        //
        // It speeds up the parquet read paths that matter: the Iceberg
        // lakehouse data files and the local `tpch` parquet catalog. Pure
        // SQL-source federation is unaffected (those predicates push to the
        // source as SQL via the federation `SQLExecutor`, never parquet).
        // `reorder_filters` lets the reader apply the cheapest/most
        // selective predicates first.
        let opts = config.options_mut();
        opts.execution.parquet.pushdown_filters = true;
        opts.execution.parquet.reorder_filters = true;
        config
    }
}

/// Build the shared [`RuntimeEnv`] from the resource knobs on
/// [`SessionConfig`]. Neither knob set ⇒ the default runtime,
/// byte-for-byte the pre- behaviour.
///
/// `FairSpillPool` (not `GreedyMemoryPool`) so concurrent operators
/// under one limit each get a fair share and spill-capable operators
/// actually spill rather than one consumer starving the rest into
/// immediate `ResourcesExhausted` errors.
fn build_runtime_env(config: &SessionConfig) -> Result<RuntimeEnv> {
    if config.memory_limit_bytes.is_none() && config.spill_dir.is_none() {
        return Ok(RuntimeEnv::default());
    }
    let mut builder = datafusion::execution::runtime_env::RuntimeEnvBuilder::new();
    if let Some(bytes) = config.memory_limit_bytes {
        builder = builder.with_memory_pool(Arc::new(
            datafusion::execution::memory_pool::FairSpillPool::new(bytes),
        ));
    }
    if let Some(dir) = &config.spill_dir {
        builder = builder.with_temp_file_path(dir.clone());
    }
    Ok(builder.build()?)
}

/// Factory for creating configured `SessionContext` instances.
///
/// This factory encapsulates the setup of `DataFusion` sessions with
/// appropriate configuration for federated query execution.
#[derive(Debug, Clone)]
pub struct SessionContextFactory {
    config: SessionConfig,
    runtime: Arc<RuntimeEnv>,
}

impl SessionContextFactory {
    /// Create a new factory with the given configuration.
    ///
    /// When [`SessionConfig::memory_limit_bytes`] / [`SessionConfig::spill_dir`]
    /// are set, the shared `RuntimeEnv` gets a [`FairSpillPool`] and/or a
    /// pinned spill directory so heavy operators spill or fail
    /// with a typed error instead of the OS OOM-killing the process. With
    /// neither set, this is exactly the pre- default runtime.
    ///
    /// [`FairSpillPool`]: datafusion::execution::memory_pool::FairSpillPool
    ///
    /// # Errors
    /// Returns an error if the runtime environment cannot be created
    /// (e.g. the spill directory can't be used).
    pub fn new(config: SessionConfig) -> Result<Self> {
        let runtime = Arc::new(build_runtime_env(&config)?);
        Ok(Self { config, runtime })
    }

    /// Create a new factory with default configuration.
    ///
    /// # Errors
    /// Returns an error if the runtime environment cannot be created.
    pub fn with_defaults() -> Result<Self> {
        Self::new(SessionConfig::default())
    }

    /// The shared [`RuntimeEnv`] every context this factory creates uses.
    ///
    /// Exposed so the boot path can register object stores (e.g. `s3://`
    /// for object-storage catalogs) on it — a store registered here is
    /// visible to every session created afterwards, since they all clone
    /// this same runtime.
    #[must_use]
    pub fn runtime(&self) -> &Arc<RuntimeEnv> {
        &self.runtime
    }

    /// Create a new `SessionContext` with the factory's configuration.
    ///
    /// Each call creates a fresh context that shares the runtime
    /// environment but has its own state. `pg_catalog.*` is registered
    /// on the returned context so psql / JDBC introspection (`\d`,
    /// `\dt`, `\dn`) works out of the box.
    #[must_use]
    pub fn create_context(&self) -> SessionContext {
        let df_config = self.config.to_datafusion_config();
        let state = datafusion::execution::session_state::SessionStateBuilder::new()
            .with_config(df_config)
            .with_runtime_env(Arc::clone(&self.runtime))
            .with_default_features()
            .build();

        let ctx = SessionContext::new_with_state(state);
        ctx.register_udf(crate::functions::mod_udf());
        register_pg_catalog(&ctx, &self.config.default_catalog);
        tracing::debug!(
            default_catalog = %self.config.default_catalog,
            federated = false,
            "built session context (mod_udf + pg_catalog registered)"
        );
        ctx
    }

    /// Create a `SessionContext` with `datafusion-federation` installed:
    /// federation optimizer rules + `FederatedQueryPlanner` as the query
    /// planner.
    ///
    /// **Federation filter-pushdown handling**: there is a known
    /// correctness bug in `datafusion-federation 0.5.3` where
    /// `VirtualExecutionPlan::handle_child_pushdown_result` claims
    /// `PushedDown::Yes` for parent `FilterExec`s without ever unparsing
    /// them into the federated SQL — `DataFusion`'s physical filter
    /// pushdown then deletes the local `FilterExec` and the predicate is
    /// lost across cross-source JOINs.
    ///
    /// Earlier versions worked around this by stripping the physical
    /// `FilterPushdown` rule wholesale, which also killed scan-time
    /// parquet pushdown on the local Iceberg / object-storage read paths
    ///. Instead this method keeps `FilterPushdown` enabled and
    /// prepends [`WrapFederationNodes`](crate::federation_pushdown::WrapFederationNodes),
    /// which wraps every `VirtualExecutionPlan` in a
    /// [`FederationFilterGuard`](crate::federation_pushdown::FederationFilterGuard)
    /// that declines physical filter pushdown — so the `FilterExec` is
    /// retained above federation nodes (no predicate loss) while parquet
    /// scans still get true scan-time pushdown. See
    /// [`crate::federation_pushdown`] for the full rationale.
    ///
    /// Tracked upstream against `datafusion-contrib/datafusion-federation`.
    /// When a fixed release ships, the guard rule can be dropped and the
    /// default physical optimizer used directly.
    #[must_use]
    pub fn create_federated_context(&self) -> SessionContext {
        use datafusion::physical_optimizer::optimizer::PhysicalOptimizer;
        use datafusion::physical_optimizer::PhysicalOptimizerRule;

        use crate::federation_pushdown::WrapFederationNodes;

        let df_config = self.config.to_datafusion_config();

        // Keep DataFusion's full physical-optimizer pipeline (including
        // `FilterPushdown`), but run `WrapFederationNodes` first so every
        // federation `VirtualExecutionPlan` is guarded before pushdown
        // decisions are made. See the doc comment + `federation_pushdown`.
        let mut physical_rules: Vec<Arc<dyn PhysicalOptimizerRule + Send + Sync>> =
            vec![Arc::new(WrapFederationNodes)];
        physical_rules.extend(PhysicalOptimizer::default().rules);

        let state = datafusion::execution::session_state::SessionStateBuilder::new()
            .with_config(df_config)
            .with_runtime_env(Arc::clone(&self.runtime))
            .with_default_features()
            // Federation defaults + the  dedup-unparse guard
            // (rejects shapes DataFusion 53's unparser would silently
            // corrupt; retires with the  DataFusion 54 bump).
            .with_optimizer_rules(crate::federation_dedup_guard::federated_optimizer_rules())
            .with_query_planner(Arc::new(datafusion_federation::FederatedQueryPlanner::new()))
            .with_physical_optimizer_rules(physical_rules)
            .build();

        let ctx = SessionContext::new_with_state(state);
        ctx.register_udf(crate::functions::mod_udf());
        register_pg_catalog(&ctx, &self.config.default_catalog);
        tracing::debug!(
            default_catalog = %self.config.default_catalog,
            federated = true,
            "built federated session context (federation planner + guards + mod_udf + pg_catalog)"
        );
        ctx
    }

    /// Get the session configuration.
    #[must_use]
    pub fn config(&self) -> &SessionConfig {
        &self.config
    }
}

/// Stub for `num_cpus` when not available as a dependency.
mod num_cpus {
    pub fn get() -> usize {
        std::thread::available_parallelism().map_or(4, std::num::NonZero::get)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_config_defaults() {
        let config = SessionConfig::default();
        assert_eq!(config.batch_size, 8192);
        assert_eq!(config.default_catalog, "dataglot");
        assert_eq!(config.default_schema, "public");
    }

    #[test]
    fn test_session_config_builder() {
        let config = SessionConfig::new()
            .with_batch_size(4096)
            .with_default_catalog("my_catalog")
            .with_default_schema("my_schema");

        assert_eq!(config.batch_size, 4096);
        assert_eq!(config.default_catalog, "my_catalog");
        assert_eq!(config.default_schema, "my_schema");
        // Resource guardrails default OFF — unset means the
        // factory builds the plain default runtime.
        assert_eq!(config.memory_limit_bytes, None);
        assert_eq!(config.spill_dir, None);
    }

    #[test]
    fn session_config_resource_builders_round_trip() {
        let config = SessionConfig::new()
            .with_memory_limit_bytes(512 * 1024 * 1024)
            .with_spill_dir("/tmp/dataglot-spill");
        assert_eq!(config.memory_limit_bytes, Some(512 * 1024 * 1024));
        assert_eq!(
            config.spill_dir.as_deref(),
            Some(std::path::Path::new("/tmp/dataglot-spill"))
        );
    }

    ///  — when `default_catalog` names a (would-be) federated source,
    /// no writable `dataglot` catalog is auto-created, so runtime views have
    /// nowhere to land. `ensure_runtime_catalog` guarantees a writable home.
    #[tokio::test]
    async fn ensure_runtime_catalog_gives_runtime_objects_a_writable_home() {
        use datafusion::arrow::datatypes::{DataType, Field, Schema};
        use datafusion::datasource::empty::EmptyTable;

        // A federated-style default catalog name (mirrors `default_catalog =
        // "snowflake"`): DataFusion auto-creates a placeholder for *that* name,
        // never a writable `dataglot`.
        let factory = SessionContextFactory::new(
            SessionConfig::new()
                .with_default_catalog("snowflake")
                .with_default_schema("tpch_sf1"),
        )
        .unwrap();
        let ctx = factory.create_context();
        assert!(
            ctx.catalog(RUNTIME_CATALOG).is_none(),
            "no writable runtime catalog before ensure"
        );

        ensure_runtime_catalog(&ctx);
        assert!(
            ctx.catalog(RUNTIME_CATALOG).is_some(),
            "runtime catalog present after ensure"
        );

        // The operation that fails without the guarantee: register a runtime
        // object into the reserved writable schema and resolve it back.
        let schema = Arc::new(Schema::new(vec![Field::new("x", DataType::Int64, false)]));
        ctx.register_table(
            datafusion::sql::TableReference::full(RUNTIME_CATALOG, RUNTIME_SCHEMA, "v"),
            Arc::new(EmptyTable::new(schema)),
        )
        .expect("register into reserved writable catalog");
        let rows = ctx
            .sql("SELECT x FROM dataglot.public.v")
            .await
            .unwrap()
            .collect()
            .await
            .unwrap();
        assert!(rows.iter().all(|b| b.num_rows() == 0));

        // Idempotent + non-destructive: a second call keeps the same catalog.
        ensure_runtime_catalog(&ctx);
        assert!(ctx.catalog(RUNTIME_CATALOG).is_some());
    }

    ///  — a configured memory limit turns an over-budget query
    /// into a typed `ResourcesExhausted` error instead of unbounded
    /// growth (the unguarded failure mode is the OS OOM-killing the
    /// whole process). A grouped aggregation over ~1M distinct keys
    /// cannot fit a 2 MiB pool.
    #[tokio::test]
    async fn memory_limit_turns_oom_into_a_typed_error() {
        let factory = SessionContextFactory::new(
            SessionConfig::new().with_memory_limit_bytes(2 * 1024 * 1024),
        )
        .unwrap();
        let ctx = factory.create_context();

        // Small queries still succeed under the limit…
        let ok = ctx.sql("SELECT 1 AS x").await.unwrap().collect().await;
        assert!(ok.is_ok(), "trivial query must fit the pool");

        // …but a wide aggregation over 1M distinct keys must not: it
        // errors (typically "Resources exhausted") rather than aborting.
        let heavy = ctx
            .sql(
                "SELECT v % 1000000 AS k, count(*), sum(v), avg(v), min(v), max(v) \
                 FROM (SELECT unnest(range(0, 1000000)) AS v) t \
                 GROUP BY k",
            )
            .await
            .unwrap()
            .collect()
            .await;
        let err = heavy.expect_err("1M-group aggregation must exceed a 2 MiB pool");
        let msg = err.to_string().to_ascii_lowercase();
        assert!(
            msg.contains("resources exhausted") || msg.contains("memory"),
            "expected a memory/resources error, got: {msg}"
        );
    }

    #[test]
    fn test_factory_creates_context() {
        let factory = SessionContextFactory::with_defaults().unwrap();
        let ctx = factory.create_context();
        // Verify the context was created
        assert!(ctx.state().config().target_partitions() > 0);
    }

    #[test]
    fn datafusion_config_enables_parquet_filter_pushdown() {
        // Parquet filter pushdown + reorder must be on so scan-time
        // predicate evaluation (row filter / page-index pruning) kicks in
        // for the lakehouse + local parquet read paths.
        let df = SessionConfig::default().to_datafusion_config();
        let parquet = &df.options().execution.parquet;
        assert!(parquet.pushdown_filters);
        assert!(parquet.reorder_filters);
    }

    #[test]
    fn datafusion_config_keeps_recursive_ctes_enabled() {
        //  named `WITH RECURSIVE`. DataFusion enables recursive CTEs
        // by default (datafusion.execution.enable_recursive_ctes = true);
        // `to_datafusion_config` must not turn it off.
        let df = SessionConfig::default().to_datafusion_config();
        assert!(df.options().execution.enable_recursive_ctes);
    }

    #[tokio::test]
    async fn recursive_cte_executes_end_to_end() {
        // Proves `WITH RECURSIVE` actually plans + runs through the factory
        // context (not just that the flag is on): a broken/disabled recursive
        // CTE would either fail to plan or return only the anchor row.
        use datafusion::arrow::array::{Array, Int64Array};
        let factory = SessionContextFactory::with_defaults().unwrap();
        let ctx = factory.create_context();
        let batches = ctx
            .sql(
                "WITH RECURSIVE t AS (\
                     SELECT 1 AS n \
                     UNION ALL \
                     SELECT n + 1 FROM t WHERE n < 5\
                 ) SELECT n FROM t ORDER BY n",
            )
            .await
            .expect("recursive CTE plans")
            .collect()
            .await
            .expect("recursive CTE executes");
        let vals: Vec<i64> = batches
            .iter()
            .flat_map(|b| {
                let c = b.column(0).as_any().downcast_ref::<Int64Array>().unwrap();
                (0..c.len()).map(|i| c.value(i)).collect::<Vec<_>>()
            })
            .collect();
        // Recursion iterated 1→5, not just the anchor (which would be [1]).
        assert_eq!(vals, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn federated_context_carries_parquet_pushdown_config() {
        // The federated context strips the *physical* FilterPushdown rule,
        // but the config-driven parquet pushdown must survive into it.
        let factory = SessionContextFactory::with_defaults().unwrap();
        let ctx = factory.create_federated_context();
        // Bind the owned state so the borrowed options outlive the asserts
        // (a `&ctx.state()....` chain borrows a temporary — E0716).
        let state = ctx.state();
        let parquet = &state.config().options().execution.parquet;
        assert!(parquet.pushdown_filters);
        assert!(parquet.reorder_filters);
    }

    #[tokio::test]
    async fn test_context_executes_query() {
        let factory = SessionContextFactory::with_defaults().unwrap();
        let ctx = factory.create_context();

        // Execute a simple query
        let result = ctx.sql("SELECT 1 + 1 as sum").await;
        assert!(result.is_ok());
    }

    /// Regression pin for. psql / JDBC introspection (`\d`,
    /// `\dt`, `\dn`) queries `pg_catalog.pg_class`, `pg_namespace`,
    /// `pg_settings` etc. on connect. Before, these failed
    /// with `table 'dataglot.pg_catalog.<name>' not found` because
    /// `setup_pg_catalog` was never called.
    ///
    /// We don't assert on the *contents* — `pg_settings` happens to
    /// be a `MemTable` populated by `datafusion-pg-catalog` at
    /// startup, but `pg_class` is generated from the current catalog
    /// list and may legitimately be empty in a fresh session. The
    /// load-bearing assertion is that the query plans and executes
    /// (i.e. the table is *registered*); upstream owns what rows
    /// each table returns.
    #[tokio::test]
    async fn pg_catalog_registered_in_create_context() {
        let factory = SessionContextFactory::with_defaults().unwrap();
        let ctx = factory.create_context();

        for table in [
            "pg_catalog.pg_settings",
            "pg_catalog.pg_class",
            "pg_catalog.pg_namespace",
            "pg_catalog.pg_attribute",
            "pg_catalog.pg_type",
        ] {
            let sql = format!("SELECT * FROM {table} LIMIT 1");
            let df = ctx
                .sql(&sql)
                .await
                .unwrap_or_else(|e| panic!("planning {table} failed: {e}"));
            df.collect()
                .await
                .unwrap_or_else(|e| panic!("executing {table} failed: {e}"));
        }
    }

    /// Same regression pin against the federated context — the bypass
    /// in `dataglot_pgwire::catalog_bypass` only triggers when the
    /// `pg_catalog.*` tables are actually registered on the federated
    /// session, so this is the load-bearing case for the production
    /// pg-wire path.
    #[tokio::test]
    async fn pg_catalog_registered_in_create_federated_context() {
        let factory = SessionContextFactory::with_defaults().unwrap();
        let ctx = factory.create_federated_context();

        for table in [
            "pg_catalog.pg_settings",
            "pg_catalog.pg_class",
            "pg_catalog.pg_namespace",
        ] {
            let sql = format!("SELECT * FROM {table} LIMIT 1");
            let df = ctx
                .sql(&sql)
                .await
                .unwrap_or_else(|e| panic!("planning {table} failed: {e}"));
            df.collect()
                .await
                .unwrap_or_else(|e| panic!("executing {table} failed: {e}"));
        }
    }

    /// Pins the specific `pg_settings` query psql issues during
    /// startup (paraphrased). Catches a regression where the table
    /// exists but the schema doesn't match the columns psql binds.
    #[tokio::test]
    async fn pg_settings_returns_name_and_setting_columns() {
        let factory = SessionContextFactory::with_defaults().unwrap();
        let ctx = factory.create_context();

        let df = ctx
            .sql("SELECT name, setting FROM pg_catalog.pg_settings LIMIT 5")
            .await
            .expect("pg_settings projection should plan");
        let batches = df.collect().await.expect("pg_settings should execute");
        // pg_settings is a static table with many rows; assert the
        // schema we projected, not the row count.
        if let Some(batch) = batches.first() {
            let schema = batch.schema();
            assert_eq!(schema.field(0).name(), "name");
            assert_eq!(schema.field(1).name(), "setting");
        }
    }

    #[test]
    fn test_session_config_with_target_partitions() {
        let config = SessionConfig::new().with_target_partitions(16);
        assert_eq!(config.target_partitions, 16);
    }

    #[test]
    fn test_session_config_to_datafusion_config() {
        let config = SessionConfig::new()
            .with_batch_size(2048)
            .with_target_partitions(8)
            .with_default_catalog("test_catalog")
            .with_default_schema("test_schema");

        let df_config = config.to_datafusion_config();
        assert_eq!(df_config.batch_size(), 2048);
        assert_eq!(df_config.target_partitions(), 8);
    }

    #[test]
    fn test_factory_config_access() {
        let config = SessionConfig::new().with_batch_size(1024);
        let factory = SessionContextFactory::new(config).unwrap();
        assert_eq!(factory.config().batch_size, 1024);
    }

    #[test]
    fn test_multiple_contexts_independent() {
        let factory = SessionContextFactory::with_defaults().unwrap();
        let ctx1 = factory.create_context();
        let ctx2 = factory.create_context();

        // Contexts should be independent instances
        // They share runtime but have separate state
        assert!(ctx1.state().config().target_partitions() > 0);
        assert!(ctx2.state().config().target_partitions() > 0);
    }

    #[test]
    fn test_federated_context_creates() {
        let factory = SessionContextFactory::with_defaults().unwrap();
        let ctx = factory.create_federated_context();
        // Proves the SessionState built and the SessionContext is alive.
        assert!(ctx.state().config().target_partitions() > 0);
    }

    #[tokio::test]
    async fn test_federated_context_executes_simple_select() {
        let factory = SessionContextFactory::with_defaults().unwrap();
        let ctx = factory.create_federated_context();

        // Smoke-test: nothing in the SessionState rebuild broke basic
        // execution. We cannot easily pull a scalar out without hauling
        // arrow-array into this crate, so we just round-trip to record
        // batches and check the row count.
        let df = ctx
            .sql("SELECT 1 + 1 AS x")
            .await
            .expect("simple SELECT plans");
        let batches = df.collect().await.expect("simple SELECT executes");
        let total_rows: usize = batches
            .iter()
            .map(arrow::array::RecordBatch::num_rows)
            .sum();
        assert_eq!(total_rows, 1);
    }

    #[test]
    fn test_filter_pushdown_rule_present_in_default_optimizer() {
        // Defensive guard: `create_federated_context` now *keeps*
        // FilterPushdown (relying on the WrapFederationNodes guard for
        // correctness). If datafusion ever renames `FilterPushdown`, the
        // federated parquet-pushdown win silently regresses — this
        // assertion fires so we know to revisit.
        use datafusion::physical_optimizer::optimizer::PhysicalOptimizer;
        let opt = PhysicalOptimizer::default();
        assert!(
            opt.rules.iter().any(|r| r.name() == "FilterPushdown"),
            "Expected a rule named 'FilterPushdown' in the default \
             PhysicalOptimizer; if datafusion has renamed it, revisit \
             SessionContextFactory::create_federated_context. \
             Current rules: {:?}",
            opt.rules.iter().map(|r| r.name()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_federated_context_keeps_filter_pushdown_behind_guard() {
        //: the federated context now retains FilterPushdown for
        // scan-time parquet pushdown, and prepends WrapFederationNodes to
        // guard cross-source correctness. Both must be present, and the
        // guard must run before FilterPushdown.
        let factory = SessionContextFactory::with_defaults().unwrap();
        let ctx = factory.create_federated_context();
        let state = ctx.state();
        let names: Vec<&str> = state
            .physical_optimizers()
            .iter()
            .map(|r| r.name())
            .collect();
        assert!(
            names.contains(&"FilterPushdown"),
            "FilterPushdown must be retained in the federated context: {names:?}"
        );
        assert!(
            names.contains(&"WrapFederationNodes"),
            "WrapFederationNodes guard must be installed: {names:?}"
        );
        let guard_at = names.iter().position(|n| *n == "WrapFederationNodes");
        let pushdown_at = names.iter().position(|n| *n == "FilterPushdown");
        assert!(
            guard_at < pushdown_at,
            "WrapFederationNodes must run before FilterPushdown: {names:?}"
        );
    }

    #[test]
    fn test_federated_context_includes_federated_query_planner() {
        // `QueryPlanner` does not have an `Any` supertrait, so we cannot
        // downcast through the public API. The trait does require
        // `Debug`, and `FederatedQueryPlanner` derives it, so the type
        // name appears in the debug representation. That's a public,
        // stable-enough surface for this assertion.
        let factory = SessionContextFactory::with_defaults().unwrap();
        let ctx = factory.create_federated_context();
        let planner = ctx.state().query_planner().clone();
        let debug_repr = format!("{planner:?}");
        assert!(
            debug_repr.contains("FederatedQueryPlanner"),
            "Expected federated SessionContext to use FederatedQueryPlanner, \
             got debug repr: {debug_repr}"
        );
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn batch_size_always_preserved(size in 1usize..100_000) {
            // Property: batch_size is always preserved through builder
            let config = SessionConfig::new().with_batch_size(size);
            prop_assert_eq!(config.batch_size, size);
        }

        #[test]
        fn target_partitions_always_preserved(partitions in 1usize..256) {
            // Property: target_partitions is always preserved through builder
            let config = SessionConfig::new().with_target_partitions(partitions);
            prop_assert_eq!(config.target_partitions, partitions);
        }

        #[test]
        fn catalog_name_preserved(name in "[a-zA-Z][a-zA-Z0-9_]*") {
            // Property: catalog name is preserved through builder
            let config = SessionConfig::new().with_default_catalog(&name);
            prop_assert_eq!(config.default_catalog, name);
        }

        #[test]
        fn schema_name_preserved(name in "[a-zA-Z][a-zA-Z0-9_]*") {
            // Property: schema name is preserved through builder
            let config = SessionConfig::new().with_default_schema(&name);
            prop_assert_eq!(config.default_schema, name);
        }

        #[test]
        fn chained_builders_preserve_all(
            batch in 1usize..10_000,
            partitions in 1usize..64,
            catalog in "[a-z]+",
            schema in "[a-z]+"
        ) {
            // Property: chained builder calls preserve all values
            let config = SessionConfig::new()
                .with_batch_size(batch)
                .with_target_partitions(partitions)
                .with_default_catalog(&catalog)
                .with_default_schema(&schema);

            prop_assert_eq!(config.batch_size, batch);
            prop_assert_eq!(config.target_partitions, partitions);
            prop_assert_eq!(config.default_catalog, catalog);
            prop_assert_eq!(config.default_schema, schema);
        }

        #[test]
        fn datafusion_config_batch_size_matches(size in 1usize..50_000) {
            // Property: DataFusion config should have same batch size
            let config = SessionConfig::new().with_batch_size(size);
            let df_config = config.to_datafusion_config();
            prop_assert_eq!(df_config.batch_size(), size);
        }
    }
}

/// A logical-plan rewrite applied at the pg-wire **extended-parse** phase.
///
/// The pg wire layer (datafusion-postgres) derives a prepared statement's
/// `RowDescription` from the *parsed* logical plan but executes the *analyzed*
/// plan. A governance rule that changes the output schema — e.g. the
/// column whitelist dropping hidden columns — therefore makes describe and
/// execute disagree (`DataRow` field count does not match). Registered as a
/// [`datafusion::execution::config::SessionConfig`] extension by the server and
/// applied by the pg wire layer's query hook, this rewrite runs on the parsed
/// plan so the same (governed) schema drives both describe and execute.
///
/// The closure reads the session identity from the policy task-local itself, so
/// this type carries no identity — it is registered once per session.
pub type PlanRewriteFn = std::sync::Arc<
    dyn Fn(
            datafusion::logical_expr::LogicalPlan,
        ) -> datafusion::error::Result<datafusion::logical_expr::LogicalPlan>
        + Send
        + Sync,
>;

/// `SessionConfig` extension wrapper for a [`PlanRewriteFn`] (a `Sized` type so
/// `SessionConfig::get_extension` can key on it).
pub struct SessionPlanRewriter(pub PlanRewriteFn);

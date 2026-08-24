//! Materialized data-product refresh (, Trino-retirement slice 2).
//!
//! Two pieces:
//!
//! * [`refresh_product`] — the orchestration unit: execute a derived
//!   product's SQL against a (federated) `SessionContext`, then write the
//!   Arrow result into a standalone warehouse table via the blue-green
//!   overwrite mechanic ([`WarehouseConnector::overwrite_table`], slice 1).
//! * [`RefreshScheduler`] — an in-process tokio scheduler that drives a refresh
//!   on each product's cadence, with bounded retry and shutdown handling.
//!
//! The scheduler home is **in-process tokio** (matching the server's existing
//! background-task pattern). An external trigger / HA story is deferred (spec
//! open question).
//!
//! Boot wiring (instantiating the scheduler in `DataglotServer::new` with the
//! live warehouse connectors) is a follow-up — this module is the tested core
//! the boot path will call.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::Context;
use datafusion::arrow::datatypes::SchemaRef;
use datafusion::catalog::CatalogProvider as DfCatalogProvider;
use datafusion::execution::session_state::SessionStateBuilder;
use datafusion::optimizer::OptimizerRule;
use datafusion::prelude::SessionContext;
use futures::future::BoxFuture;
use tokio::sync::broadcast;
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

use dataglot_core::session::SessionContextFactory;
use dataglot_federation::iceberg::WarehouseConnector;
use dataglot_federation::materialize::MaterializeOutcome;
use dataglot_policy::{PolicyEnforcer, PolicyOptimizerRule};

use crate::config::{parse_refresh_interval, DerivedProductConfig, MaterializationBacking};
use crate::materialization_registry::MaterializationRegistry;

/// Execute `sql` on `ctx` and materialize the Arrow result into
/// `namespace.table` in `warehouse` (full-overwrite, blue-green). `token`
/// disambiguates the transient staging/parked tables for this refresh.
///
/// # Errors
/// If planning or executing the query fails, or the warehouse write fails.
pub async fn refresh_product(
    ctx: &SessionContext,
    sql: &str,
    warehouse: &WarehouseConnector,
    namespace: &str,
    table: &str,
    token: &str,
) -> anyhow::Result<MaterializeOutcome> {
    let df = ctx
        .sql(sql)
        .await
        .with_context(|| format!("planning refresh query for '{table}'"))?;
    // Capture the schema before the frame is consumed — works even when the
    // result is empty.
    let schema: SchemaRef = Arc::new(df.schema().as_arrow().clone());
    // Stream the refresh result straight into the overwrite — the materialized
    // table is never fully buffered in memory. The stream owns its
    // execution state, so the borrowed `ctx` is only needed to build it.
    let batches = df
        .execute_stream()
        .await
        .with_context(|| format!("executing refresh query for '{table}'"))?;
    warehouse
        .overwrite_table_stream(namespace, table, &schema, batches, token)
        .await
        .with_context(|| format!("materializing '{namespace}.{table}'"))
}

/// Build a [`RefreshJob`] per `Materialized` derived product. `connectors`
/// maps a warehouse-catalog name to its [`WarehouseConnector`]; the session
/// pieces (`factory`/`needs_federation`/`catalogs`/`enforcer`) are captured so
/// each refresh runs the product SQL through a governed, catalog-registered
/// session — materialized data reflects what a live governed query returns.
///
/// `Live` products are skipped. Pure given its inputs (no I/O) — unit-testable
/// with an injected in-memory connector.
///
/// # Errors
/// If a product names a warehouse with no connector, or its `refresh_every`
/// doesn't parse. (The `backing`/`materialization` invariant is already
/// enforced at config load.)
pub fn build_refresh_jobs(
    products: &[DerivedProductConfig],
    connectors: &HashMap<String, Arc<WarehouseConnector>>,
    factory: &SessionContextFactory,
    needs_federation: bool,
    catalogs: &Arc<HashMap<String, Arc<dyn DfCatalogProvider>>>,
    enforcer: &Arc<dyn PolicyEnforcer>,
    status: &MaterializationRegistry,
) -> anyhow::Result<Vec<RefreshJob>> {
    let mut jobs = Vec::new();
    // Two products refreshing the same (warehouse, namespace, table) would race
    // overwrites on one table — reject the collision up front.
    let mut seen_targets: std::collections::HashSet<(String, String, String)> =
        std::collections::HashSet::new();
    for p in products {
        if p.backing != MaterializationBacking::Materialized {
            continue;
        }
        let mat = p.materialization.as_ref().with_context(|| {
            format!(
                "product '{}': materialized but no materialization block",
                p.name
            )
        })?;
        let connector = connectors.get(&mat.warehouse).cloned().with_context(|| {
            format!(
                "product '{}': materialization warehouse '{}' has no connector",
                p.name, mat.warehouse
            )
        })?;
        let interval = parse_refresh_interval(&mat.refresh_every)
            .map_err(|e| anyhow::anyhow!("product '{}': {e}", p.name))?;
        let table = mat.table.clone().unwrap_or_else(|| p.name.clone());
        let namespace = mat.namespace.clone();
        if !seen_targets.insert((mat.warehouse.clone(), namespace.clone(), table.clone())) {
            anyhow::bail!(
                "duplicate materialization target '{}.{}.{}' across derived products \
                 (product '{}'); each materialized table must be unique",
                mat.warehouse,
                namespace,
                table,
                p.name
            );
        }
        // Seed the status entry so the dashboard lists this product as
        // `Pending` from boot, before its first refresh runs.
        let target = format!("{}.{}.{}", mat.warehouse, namespace, table);
        #[allow(clippy::cast_possible_truncation)]
        let interval_secs = interval.as_secs();
        status.register(&p.name, &target, interval_secs);

        let sql = p.sql.clone();
        let factory = factory.clone();
        let catalogs = Arc::clone(catalogs);
        let enforcer = Arc::clone(enforcer);
        let status = status.clone();
        let product = p.name.clone();

        let run: RefreshFn = Arc::new(move || {
            let factory = factory.clone();
            let catalogs = Arc::clone(&catalogs);
            let enforcer = Arc::clone(&enforcer);
            let connector = Arc::clone(&connector);
            let sql = sql.clone();
            let namespace = namespace.clone();
            let table = table.clone();
            let status = status.clone();
            let product = product.clone();
            Box::pin(async move {
                status.record_start(&product);
                let started = Instant::now();
                let ctx = build_refresh_session(&factory, needs_federation, &catalogs, &enforcer);
                let result =
                    refresh_product(&ctx, &sql, &connector, &namespace, &table, &refresh_token())
                        .await;
                let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
                match result {
                    Ok(outcome) => {
                        status.record_success(
                            &product,
                            outcome.rows,
                            outcome.data_files,
                            elapsed_ms,
                        );
                        Ok(())
                    }
                    Err(e) => {
                        // Connector/query errors are already credential-scrubbed
                        // (rule 12); record the redacted chain for the dashboard.
                        status.record_failure(&product, format!("{e:#}"), elapsed_ms);
                        Err(e)
                    }
                }
            })
        });
        jobs.push(RefreshJob {
            label: p.name.clone(),
            interval,
            run,
        });
    }
    Ok(jobs)
}

/// Build a governed, catalog-registered session for a refresh query — the
/// scheduler analogue of `DataglotServer::create_session` (without the Ballista
/// branch; materialization runs on the single-node factory context).
fn build_refresh_session(
    factory: &SessionContextFactory,
    needs_federation: bool,
    catalogs: &HashMap<String, Arc<dyn DfCatalogProvider>>,
    enforcer: &Arc<dyn PolicyEnforcer>,
) -> SessionContext {
    let base = if needs_federation {
        factory.create_federated_context()
    } else {
        factory.create_context()
    };
    let policy_rule: Arc<dyn OptimizerRule + Send + Sync> =
        Arc::new(PolicyOptimizerRule::new(Arc::clone(enforcer)));
    let state = base.state();
    let mut rules: Vec<Arc<dyn OptimizerRule + Send + Sync>> = state.optimizers().to_vec();
    rules.insert(0, policy_rule);
    let state = SessionStateBuilder::new_from_existing(state)
        .with_optimizer_rules(rules)
        .build();
    let ctx = SessionContext::new_with_state(state);
    for (name, catalog) in catalogs {
        if ctx.register_catalog(name, Arc::clone(catalog)).is_some() {
            tracing::warn!(
                catalog = %name,
                "two catalogs share this name in the refresh session; the earlier provider was replaced"
            );
        }
    }
    ctx
}

/// A per-refresh token (wall-clock millis) that disambiguates the transient
/// staging/parked tables. Distinct enough across a product's refresh cadence.
fn refresh_token() -> String {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis());
    format!("{millis}")
}

/// One scheduled refresh unit: a labelled job that runs `run` every `interval`.
pub struct RefreshJob {
    /// Human-readable label (the product name) for logs.
    pub label: String,
    /// Refresh cadence.
    pub interval: Duration,
    /// Runs one refresh attempt.
    pub run: RefreshFn,
}

impl std::fmt::Debug for RefreshJob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `run` is an opaque closure — render only the identifying fields.
        f.debug_struct("RefreshJob")
            .field("label", &self.label)
            .field("interval", &self.interval)
            .finish_non_exhaustive()
    }
}

/// A refresh closure: produces a fresh future per attempt so it can retry.
pub type RefreshFn = Arc<dyn Fn() -> BoxFuture<'static, anyhow::Result<()>> + Send + Sync>;

/// Attempts per scheduled tick (1 initial + retries).
const MAX_ATTEMPTS: u32 = 3;

/// In-process refresh scheduler. One tokio task per job; each refreshes once
/// at startup, then every `interval`, until the shutdown broadcast fires.
pub struct RefreshScheduler;

impl RefreshScheduler {
    /// Spawn one task per job. Each task refreshes at startup, then every
    /// `interval` (missed ticks are **skipped**, not bursted), and stops when
    /// `shutdown` fires. Returns the join handles; the caller holds them to
    /// `await` a clean stop.
    ///
    /// Note: dropping a tokio [`JoinHandle`] only *detaches* the task (it keeps
    /// running) — so the shutdown broadcast, not dropping the handle, is what
    /// actually stops these tasks.
    #[must_use]
    pub fn spawn(jobs: Vec<RefreshJob>, shutdown: &broadcast::Sender<()>) -> Vec<JoinHandle<()>> {
        jobs.into_iter()
            .map(|job| {
                let mut shutdown_rx = shutdown.subscribe();
                tokio::spawn(async move {
                    // `interval` fires immediately on the first tick, so a
                    // materialized product is populated at startup, then on
                    // cadence. Skip missed ticks so a slow refresh never
                    // triggers a back-to-back catch-up burst.
                    let mut ticker = tokio::time::interval(job.interval);
                    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                    loop {
                        tokio::select! {
                            _ = shutdown_rx.recv() => {
                                info!(job = %job.label, "refresh scheduler stopping");
                                break;
                            }
                            _ = ticker.tick() => {
                                if run_with_retry(&job, &mut shutdown_rx).await {
                                    info!(job = %job.label, "refresh scheduler stopping");
                                    break;
                                }
                            }
                        }
                    }
                })
            })
            .collect()
    }
}

/// Run a job's refresh, retrying on failure up to [`MAX_ATTEMPTS`]. A failed
/// refresh is non-fatal — the prior snapshot stays intact (slice 1), and the
/// next tick tries again.
///
/// An in-flight attempt is allowed to **complete** even if shutdown fires —
/// aborting mid-overwrite could orphan the staging table, and the blue-green
/// swap is short. The inter-attempt backoff, however, is interrupted by
/// shutdown. Returns `true` if shutdown was observed (the caller should stop).
async fn run_with_retry(job: &RefreshJob, shutdown_rx: &mut broadcast::Receiver<()>) -> bool {
    for attempt in 1..=MAX_ATTEMPTS {
        match (job.run)().await {
            Ok(()) => {
                info!(job = %job.label, attempt, "materialization refresh succeeded");
                return false;
            }
            Err(e) if attempt < MAX_ATTEMPTS => {
                warn!(job = %job.label, attempt, error = %e, "materialization refresh failed; retrying");
                let backoff = Duration::from_millis(200 * u64::from(attempt));
                tokio::select! {
                    _ = shutdown_rx.recv() => {
                        info!(job = %job.label, "shutdown during retry backoff");
                        return true;
                    }
                    () = tokio::time::sleep(backoff) => {}
                }
            }
            Err(e) => {
                error!(
                    job = %job.label,
                    attempts = MAX_ATTEMPTS,
                    error = %e,
                    "materialization refresh failed; prior snapshot retained, will retry next tick"
                );
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use datafusion::arrow::array::{Int32Array, StringArray};
    use datafusion::arrow::datatypes::{DataType, Field, Schema as ArrowSchema};
    use datafusion::arrow::record_batch::RecordBatch;
    use datafusion::datasource::MemTable;
    use dataglot_core::session::SessionConfig;
    use dataglot_policy::NoopPolicyEnforcer;
    use iceberg::io::LocalFsStorageFactory;
    use iceberg::memory::{MemoryCatalogBuilder, MEMORY_CATALOG_WAREHOUSE};
    use iceberg::{Catalog, CatalogBuilder, NamespaceIdent};
    use tempfile::TempDir;

    use super::*;
    use crate::config::MaterializationConfig;

    /// A `Materialized` product config writing `sql` into `wh.<namespace>.<table>`.
    fn materialized(
        name: &str,
        sql: &str,
        wh: &str,
        ns: &str,
        every: &str,
    ) -> DerivedProductConfig {
        DerivedProductConfig {
            name: name.to_string(),
            sql: sql.to_string(),
            catalog: None,
            schema: None,
            backing: MaterializationBacking::Materialized,
            materialization: Some(MaterializationConfig {
                warehouse: wh.to_string(),
                namespace: ns.to_string(),
                table: None,
                refresh_every: every.to_string(),
            }),
        }
    }

    fn empty_catalogs() -> Arc<HashMap<String, Arc<dyn DfCatalogProvider>>> {
        Arc::new(HashMap::new())
    }

    fn noop_enforcer() -> Arc<dyn PolicyEnforcer> {
        Arc::new(NoopPolicyEnforcer)
    }

    fn factory() -> SessionContextFactory {
        SessionContextFactory::new(SessionConfig::default()).unwrap()
    }

    async fn memory_warehouse() -> (WarehouseConnector, TempDir) {
        let dir = TempDir::new().unwrap();
        let path = format!("file://{}", dir.path().to_str().unwrap());
        let catalog = MemoryCatalogBuilder::default()
            .with_storage_factory(Arc::new(LocalFsStorageFactory))
            .load(
                "warehouse",
                HashMap::from([(MEMORY_CATALOG_WAREHOUSE.to_string(), path)]),
            )
            .await
            .unwrap();
        catalog
            .create_namespace(&NamespaceIdent::new("mart".to_string()), HashMap::new())
            .await
            .unwrap();
        let connector = WarehouseConnector::__from_catalog_for_tests(
            "warehouse",
            Arc::new(catalog) as Arc<dyn Catalog>,
        );
        (connector, dir)
    }

    /// Register an in-memory source table on a plain `SessionContext` so a
    /// refresh query has something to read.
    fn ctx_with_source() -> SessionContext {
        let ctx = SessionContext::new();
        let schema = Arc::new(ArrowSchema::new(vec![
            Field::new("id", DataType::Int32, false),
            Field::new("email", DataType::Utf8, false),
        ]));
        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(Int32Array::from(vec![1, 2, 3])),
                Arc::new(StringArray::from(vec!["a@x", "b@x", "c@x"])),
            ],
        )
        .unwrap();
        let table = MemTable::try_new(schema, vec![vec![batch]]).unwrap();
        ctx.register_table("users", Arc::new(table)).unwrap();
        ctx
    }

    #[tokio::test]
    async fn refresh_product_executes_query_and_materializes() {
        let (warehouse, _dir) = memory_warehouse().await;
        let ctx = ctx_with_source();

        let out = refresh_product(
            &ctx,
            "SELECT id, email FROM users WHERE id <= 2",
            &warehouse,
            "mart",
            "active_users",
            "r1",
        )
        .await
        .expect("refresh materializes");
        assert_eq!(out.rows, 2);
        assert_eq!(out.table, "active_users");

        // The materialized table is now readable via the public read path.
        assert!(
            warehouse
                .table_provider("mart", "active_users")
                .await
                .is_ok(),
            "materialized table should be queryable after refresh"
        );
    }

    #[tokio::test]
    async fn scheduler_runs_on_interval_then_stops_on_shutdown() {
        let calls = Arc::new(AtomicUsize::new(0));
        let calls2 = Arc::clone(&calls);
        let run: RefreshFn = Arc::new(move || {
            let c = Arc::clone(&calls2);
            Box::pin(async move {
                c.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
        });
        let (tx, _) = broadcast::channel(1);
        let handles = RefreshScheduler::spawn(
            vec![RefreshJob {
                label: "p".to_string(),
                interval: Duration::from_millis(40),
                run,
            }],
            &tx,
        );

        // ~immediate first tick + a couple of interval ticks.
        tokio::time::sleep(Duration::from_millis(110)).await;
        let _ = tx.send(());
        for h in handles {
            let _ = h.await;
        }
        let n = calls.load(Ordering::SeqCst);
        assert!(n >= 2, "expected several refreshes, got {n}");
    }

    #[tokio::test]
    async fn scheduler_retries_a_failing_refresh() {
        // Fail the first two attempts, succeed the third — within one tick's
        // retry budget (MAX_ATTEMPTS = 3).
        let attempts = Arc::new(AtomicUsize::new(0));
        let attempts2 = Arc::clone(&attempts);
        let run: RefreshFn = Arc::new(move || {
            let a = Arc::clone(&attempts2);
            Box::pin(async move {
                let n = a.fetch_add(1, Ordering::SeqCst) + 1;
                if n < 3 {
                    anyhow::bail!("transient");
                }
                Ok(())
            })
        });
        let (tx, _) = broadcast::channel(1);
        let handles = RefreshScheduler::spawn(
            vec![RefreshJob {
                label: "p".to_string(),
                interval: Duration::from_secs(999), // only the immediate first tick fires in-window
                run,
            }],
            &tx,
        );
        // All three attempts (2 backoffs of 200ms + 400ms) finish well within
        // this window; shutdown fires only after, so it doesn't cut a backoff short.
        tokio::time::sleep(Duration::from_millis(1200)).await;
        let _ = tx.send(());
        for h in handles {
            let _ = h.await;
        }
        // Three attempts in the single tick (2 failures + 1 success).
        assert_eq!(attempts.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn build_refresh_jobs_skips_live_and_runs_materialized_end_to_end() {
        let (warehouse, _dir) = memory_warehouse().await;
        // The connector's catalog is shared via Arc, so the map entry and our
        // assertion handle observe the same warehouse.
        let connectors = HashMap::from([("wh".to_string(), Arc::new(warehouse))]);
        // A Live product (skipped) + a Materialized one (`SELECT 1` needs no
        // source catalog, so it runs through build_refresh_session cleanly).
        let products = vec![
            DerivedProductConfig {
                name: "live_one".to_string(),
                sql: "SELECT 1".to_string(),
                catalog: None,
                schema: None,
                backing: MaterializationBacking::Live,
                materialization: None,
            },
            materialized("ones", "SELECT 1 AS id", "wh", "mart", "1h"),
        ];
        let jobs = build_refresh_jobs(
            &products,
            &connectors,
            &factory(),
            false,
            &empty_catalogs(),
            &noop_enforcer(),
            &MaterializationRegistry::empty(),
        )
        .expect("jobs build");
        assert_eq!(jobs.len(), 1, "Live product must be skipped");
        assert_eq!(jobs[0].label, "ones");

        // Run the job's closure end-to-end → the table materializes.
        (jobs[0].run)().await.expect("refresh runs");
        assert!(connectors["wh"]
            .table_provider("mart", "ones")
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn build_refresh_jobs_tracks_status_pending_then_success() {
        let (warehouse, _dir) = memory_warehouse().await;
        let connectors = HashMap::from([("wh".to_string(), Arc::new(warehouse))]);
        let products = vec![materialized("ones", "SELECT 1 AS id", "wh", "mart", "1h")];
        let status = MaterializationRegistry::empty();
        let jobs = build_refresh_jobs(
            &products,
            &connectors,
            &factory(),
            false,
            &empty_catalogs(),
            &noop_enforcer(),
            &status,
        )
        .expect("jobs build");

        // Registered as Pending before the first run — the dashboard lists it
        // from boot.
        let seeded = status.snapshot();
        assert_eq!(seeded.len(), 1);
        assert_eq!(seeded[0].product, "ones");
        assert_eq!(seeded[0].target, "wh.mart.ones");
        assert_eq!(
            seeded[0].state,
            crate::materialization_registry::RefreshState::Pending
        );

        // After a run, status flips to Success with the written row count.
        (jobs[0].run)().await.expect("refresh runs");
        let done = status.snapshot();
        assert_eq!(
            done[0].state,
            crate::materialization_registry::RefreshState::Success
        );
        assert_eq!(done[0].last_rows, Some(1));
        assert_eq!(done[0].runs, 1);
        assert!(done[0].next_run_at_ms.is_some());
    }

    #[tokio::test]
    async fn build_refresh_jobs_rejects_missing_warehouse_and_bad_interval() {
        let connectors: HashMap<String, Arc<WarehouseConnector>> = HashMap::new();
        // Warehouse "wh" has no connector.
        let missing = vec![materialized("x", "SELECT 1", "wh", "mart", "1h")];
        assert!(build_refresh_jobs(
            &missing,
            &connectors,
            &factory(),
            false,
            &empty_catalogs(),
            &noop_enforcer(),
            &MaterializationRegistry::empty()
        )
        .is_err());

        // Bad refresh interval (connector present, interval unparseable).
        let (warehouse, _dir) = memory_warehouse().await;
        let connectors = HashMap::from([("wh".to_string(), Arc::new(warehouse))]);
        let bad = vec![materialized("x", "SELECT 1", "wh", "mart", "soon")];
        assert!(build_refresh_jobs(
            &bad,
            &connectors,
            &factory(),
            false,
            &empty_catalogs(),
            &noop_enforcer(),
            &MaterializationRegistry::empty()
        )
        .is_err());
    }

    #[tokio::test]
    async fn build_refresh_jobs_rejects_duplicate_targets() {
        let (warehouse, _dir) = memory_warehouse().await;
        let connectors = HashMap::from([("wh".to_string(), Arc::new(warehouse))]);
        // Two distinct products resolving to the same (wh, mart, dup) target.
        let dup_target = || MaterializationConfig {
            warehouse: "wh".to_string(),
            namespace: "mart".to_string(),
            table: Some("dup".to_string()),
            refresh_every: "1h".to_string(),
        };
        let products = vec![
            DerivedProductConfig {
                name: "a".to_string(),
                sql: "SELECT 1".to_string(),
                catalog: None,
                schema: None,
                backing: MaterializationBacking::Materialized,
                materialization: Some(dup_target()),
            },
            DerivedProductConfig {
                name: "b".to_string(),
                sql: "SELECT 2".to_string(),
                catalog: None,
                schema: None,
                backing: MaterializationBacking::Materialized,
                materialization: Some(dup_target()),
            },
        ];
        assert!(build_refresh_jobs(
            &products,
            &connectors,
            &factory(),
            false,
            &empty_catalogs(),
            &noop_enforcer(),
            &MaterializationRegistry::empty()
        )
        .is_err());
    }
}

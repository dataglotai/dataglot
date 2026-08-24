//! Warehouse table maintenance — compaction (, Trino-retirement slice 4).
//!
//! Replaces Trino `OPTIMIZE` / `rewrite_data_files`: read a warehouse table's
//! current rows and rewrite them as fresh, optimally-sized data files via the
//! blue-green overwrite ([`WarehouseConnector::overwrite_table`], slice 1) — the
//! rolling writer bin-packs into few large files, and the swap drops the old
//! (fragmented) snapshot.
//!
//! Note on scope: Peaka's *own* writes (materialization + EL upsert) are
//! copy-on-write, so they already produce consolidated files and never
//! fragment. Compaction matters for tables written by **external tools**
//! (Spark / Trino during migration) or, later, a merge-on-read EL path that
//! accumulates small data + delete files. This is the full-table rewrite form
//! of compaction (maximal consolidation); incremental small-file-only
//! bin-packing is a follow-up.
//!
//! # Shared copy-on-write limitations (tracked follow-ups)
//!
//! These apply to **every** copy-on-write write path (materialization, EL
//! upsert, and compaction) — they are properties of the blue-green overwrite,
//! not of compaction specifically:
//!
//! * **Optimistic concurrency (, shipped).** The path captures the
//!   table's base version before reading and passes it to
//!   [`WarehouseConnector::overwrite_table_stream_checked`] as
//!   [`dataglot_federation::materialize::ExpectedVersion::Snapshot`]. The
//!   blue-green park atomically claims the live table, then the parked
//!   version is validated against that base — a *concurrent* writer that
//!   committed in between is detected and the compaction is refused
//!   (`ConcurrentModification`) rather than silently reverting their data to
//!   this pre-write layout. (A catalog-level conditional rename would remove
//!   even the residual failure-mode noise, but the pinned `iceberg-rust` /
//!   catalog API doesn't expose one.)
//! * **Bounded memory (, shipped).** The rewrite streams the scan
//!   (`df.execute_stream()`) into
//!   [`WarehouseConnector::overwrite_table_stream_checked`], which writes one
//!   `RecordBatch` at a time — the full table is never buffered, so a very
//!   large table no longer risks an OOM. Applies to all three write paths
//!   (materialization, EL upsert, compaction).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use anyhow::Context;
use datafusion::arrow::datatypes::SchemaRef;
use datafusion::prelude::SessionContext;
use tracing::{debug, info};

use dataglot_federation::iceberg::WarehouseConnector;
use dataglot_federation::materialize::ExpectedVersion;

use crate::config::{parse_refresh_interval, CompactionScheduleConfig, OrphanCleanupConfig};
use crate::maintenance_registry::{MaintenanceKind, MaintenanceRegistry};
use crate::materialization::{RefreshFn, RefreshJob};

/// Result of a successful [`compact_table`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompactOutcome {
    /// The compacted table name (within its namespace).
    pub table: String,
    /// Rows preserved through the rewrite.
    pub rows: usize,
    /// Data files after compaction (the consolidation result).
    pub data_files: usize,
}

/// Compact `namespace.table`: read its current rows and rewrite them as fresh,
/// consolidated data files (blue-green overwrite). Data is preserved exactly;
/// only the physical file layout changes. `token` disambiguates the transient
/// staging table for this rewrite.
///
/// # Errors
/// If the table doesn't exist, can't be read, or the rewrite (warehouse write)
/// fails.
pub async fn compact_table(
    warehouse: &WarehouseConnector,
    namespace: &str,
    table: &str,
    token: &str,
) -> anyhow::Result<CompactOutcome> {
    // Capture the base version *before* reading, so the optimistic-concurrency
    // guard can't claim a newer base than we compacted. A concurrent
    // writer that commits after this point makes the swap fail cleanly
    // (ConcurrentModification) rather than reverting their data to this
    // (pre-write) layout.
    let base = warehouse
        .current_snapshot_id(namespace, table)
        .await
        .with_context(|| format!("reading base version of '{namespace}.{table}'"))?;
    // Compaction is a read-modify-write of an existing table; the rewrite must
    // land on exactly the version we read (`Snapshot(None)` also guards an
    // existing-but-empty table against a concurrent first write).
    let expected = ExpectedVersion::Snapshot(base);

    // Read the full current table. `table_provider` already fails clearly on a
    // missing table, so no separate existence probe is needed (one fewer
    // catalog round-trip); a read failure simply aborts the compaction without
    // touching the table.
    let provider = warehouse
        .table_provider(namespace, table)
        .await
        .with_context(|| format!("reading '{namespace}.{table}' for compaction"))?;
    let ctx = SessionContext::new();
    ctx.register_table("t", provider)
        .context("registering table for compaction")?;
    let df = ctx
        .sql("SELECT * FROM t")
        .await
        .context("planning compaction scan")?;
    let schema: SchemaRef = Arc::new(df.schema().as_arrow().clone());
    // Stream the scan straight into the rewrite — the table is never fully
    // buffered in memory. The returned stream owns its execution
    // state, so `ctx` may drop here.
    let scanned = df
        .execute_stream()
        .await
        .context("executing compaction scan")?;

    // Rewrite via blue-green overwrite — the rolling writer consolidates files.
    let outcome = warehouse
        .overwrite_table_stream_checked(namespace, table, &schema, scanned, token, expected)
        .await
        .with_context(|| format!("rewriting '{namespace}.{table}' during compaction"))?;
    debug!(
        table,
        rows = outcome.rows,
        data_files = outcome.data_files,
        "compacted warehouse table"
    );
    Ok(CompactOutcome {
        table: table.to_string(),
        rows: outcome.rows,
        data_files: outcome.data_files,
    })
}

/// Build one `RefreshJob` per configured compaction target (Phase 4 Task 03).
///
/// Reuses the refresh scheduler's job shape so scheduled compaction runs on the
/// same in-process, retry-backed, shutdown-aware background-task lifecycle as
/// materialization — each job compacts its table at startup, then every
/// `compact_every`. Empty input ⇒ empty output (no tasks).
///
/// # Errors
/// If an entry names a warehouse with no connector, its `compact_every` doesn't
/// parse, or two entries target the same `(warehouse, namespace, table)` (which
/// would race overwrites on one table).
pub fn build_compaction_jobs<S: std::hash::BuildHasher>(
    entries: &[CompactionScheduleConfig],
    connectors: &HashMap<String, Arc<WarehouseConnector>, S>,
    status: &MaintenanceRegistry,
) -> anyhow::Result<Vec<RefreshJob>> {
    let mut jobs = Vec::new();
    let mut seen: std::collections::HashSet<(String, String, String)> =
        std::collections::HashSet::new();
    for e in entries {
        let connector = connectors.get(&e.warehouse).cloned().with_context(|| {
            format!(
                "compaction: warehouse '{}' for table '{}.{}' has no connector",
                e.warehouse, e.namespace, e.table
            )
        })?;
        let interval = parse_refresh_interval(&e.compact_every).map_err(|msg| {
            anyhow::anyhow!(
                "compaction '{}.{}.{}': {msg}",
                e.warehouse,
                e.namespace,
                e.table
            )
        })?;
        if !seen.insert((e.warehouse.clone(), e.namespace.clone(), e.table.clone())) {
            anyhow::bail!(
                "duplicate compaction target '{}.{}.{}'; each table may be scheduled once",
                e.warehouse,
                e.namespace,
                e.table
            );
        }
        let namespace = e.namespace.clone();
        let table = e.table.clone();
        let label = format!("compact:{}.{}.{}", e.warehouse, e.namespace, e.table);
        let target = format!("{}.{}.{}", e.warehouse, e.namespace, e.table);
        status.register(
            &label,
            MaintenanceKind::Compaction,
            &target,
            interval.as_secs(),
        );
        let status = status.clone();
        let job = label.clone();
        let run: RefreshFn = Arc::new(move || {
            let connector = Arc::clone(&connector);
            let namespace = namespace.clone();
            let table = table.clone();
            let status = status.clone();
            let job = job.clone();
            Box::pin(async move {
                status.record_start(&job);
                let started = Instant::now();
                let result =
                    compact_table(&connector, &namespace, &table, &compaction_token()).await;
                let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
                match result {
                    Ok(outcome) => {
                        info!(
                            table = %outcome.table,
                            rows = outcome.rows,
                            data_files = outcome.data_files,
                            "scheduled compaction complete"
                        );
                        status.record_compaction(
                            &job,
                            outcome.rows,
                            outcome.data_files,
                            elapsed_ms,
                        );
                        Ok(())
                    }
                    Err(e) => {
                        // Warehouse errors are already credential-scrubbed (rule 12).
                        status.record_failure(&job, format!("{e:#}"), elapsed_ms);
                        Err(e)
                    }
                }
            })
        });
        jobs.push(RefreshJob {
            label,
            interval,
            run,
        });
    }
    Ok(jobs)
}

/// Build one `RefreshJob` per configured orphan-cleanup target (Phase 4
/// Task 03). Each job sweeps its namespace for leftover staging/parked
/// tables older than `min_age`, on the `sweep_every` cadence, via the shared
/// scheduler.
///
/// # Errors
/// If an entry names a warehouse with no connector, its `sweep_every` /
/// `min_age` doesn't parse, or two entries target the same
/// `(warehouse, namespace)`.
pub fn build_orphan_sweep_jobs<S: std::hash::BuildHasher>(
    entries: &[OrphanCleanupConfig],
    connectors: &HashMap<String, Arc<WarehouseConnector>, S>,
    status: &MaintenanceRegistry,
) -> anyhow::Result<Vec<RefreshJob>> {
    let mut jobs = Vec::new();
    let mut seen: std::collections::HashSet<(String, String)> = std::collections::HashSet::new();
    for e in entries {
        let connector = connectors.get(&e.warehouse).cloned().with_context(|| {
            format!(
                "orphan-cleanup: warehouse '{}' for namespace '{}' has no connector",
                e.warehouse, e.namespace
            )
        })?;
        let interval = parse_refresh_interval(&e.sweep_every).map_err(|msg| {
            anyhow::anyhow!(
                "orphan-cleanup '{}.{}': sweep_every {msg}",
                e.warehouse,
                e.namespace
            )
        })?;
        let min_age = parse_refresh_interval(&e.min_age).map_err(|msg| {
            anyhow::anyhow!(
                "orphan-cleanup '{}.{}': min_age {msg}",
                e.warehouse,
                e.namespace
            )
        })?;
        if !seen.insert((e.warehouse.clone(), e.namespace.clone())) {
            anyhow::bail!(
                "duplicate orphan-cleanup target '{}.{}'; each namespace may be swept once",
                e.warehouse,
                e.namespace
            );
        }
        let namespace = e.namespace.clone();
        let label = format!("orphan-sweep:{}.{}", e.warehouse, e.namespace);
        let target = format!("{}.{}", e.warehouse, e.namespace);
        status.register(
            &label,
            MaintenanceKind::OrphanCleanup,
            &target,
            interval.as_secs(),
        );
        let status = status.clone();
        let job = label.clone();
        let run: RefreshFn = Arc::new(move || {
            let connector = Arc::clone(&connector);
            let namespace = namespace.clone();
            let status = status.clone();
            let job = job.clone();
            Box::pin(async move {
                status.record_start(&job);
                let started = Instant::now();
                let result = connector
                    .sweep_orphan_maintenance_tables(&namespace, min_age)
                    .await;
                let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
                match result {
                    Ok(dropped) => {
                        if !dropped.is_empty() {
                            info!(
                                namespace = %namespace,
                                count = dropped.len(),
                                "orphan sweep dropped stale maintenance tables"
                            );
                        }
                        status.record_sweep(&job, dropped.len(), elapsed_ms);
                        Ok(())
                    }
                    Err(e) => {
                        status.record_failure(&job, format!("{e:#}"), elapsed_ms);
                        Err(e.into())
                    }
                }
            })
        });
        jobs.push(RefreshJob {
            label,
            interval,
            run,
        });
    }
    Ok(jobs)
}

/// A per-run token (wall-clock millis) disambiguating the transient
/// staging/parked tables a compaction rewrite creates. Mirrors
/// `materialization::refresh_token`.
fn compaction_token() -> String {
    let millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis());
    format!("compact-{millis}")
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use datafusion::arrow::array::{Int32Array, StringArray};
    use datafusion::arrow::datatypes::{DataType, Field, Schema as ArrowSchema};
    use datafusion::arrow::record_batch::RecordBatch;
    use iceberg::io::LocalFsStorageFactory;
    use iceberg::memory::{MemoryCatalogBuilder, MEMORY_CATALOG_WAREHOUSE};
    use iceberg::{Catalog, CatalogBuilder, NamespaceIdent};
    use tempfile::TempDir;

    use super::*;

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
            .create_namespace(&NamespaceIdent::new("lake".to_string()), HashMap::new())
            .await
            .unwrap();
        let connector = WarehouseConnector::__from_catalog_for_tests(
            "warehouse",
            Arc::new(catalog) as Arc<dyn Catalog>,
        );
        (connector, dir)
    }

    fn schema() -> SchemaRef {
        Arc::new(ArrowSchema::new(vec![
            Field::new("id", DataType::Int32, false),
            Field::new("v", DataType::Utf8, false),
        ]))
    }

    fn batch(ids: Vec<i32>, vs: Vec<&str>) -> RecordBatch {
        RecordBatch::try_new(
            schema(),
            vec![
                Arc::new(Int32Array::from(ids)),
                Arc::new(StringArray::from(vs)),
            ],
        )
        .unwrap()
    }

    async fn read_back(w: &WarehouseConnector, ns: &str, table: &str) -> Vec<(i32, String)> {
        let ctx = SessionContext::new();
        let provider = w.table_provider(ns, table).await.unwrap();
        ctx.register_table("t", provider).unwrap();
        let batches = ctx
            .sql("SELECT id, v FROM t ORDER BY id")
            .await
            .unwrap()
            .collect()
            .await
            .unwrap();
        let mut out = Vec::new();
        for b in batches {
            let ids = b.column(0).as_any().downcast_ref::<Int32Array>().unwrap();
            let vs = b.column(1).as_any().downcast_ref::<StringArray>().unwrap();
            for i in 0..b.num_rows() {
                out.push((ids.value(i), vs.value(i).to_string()));
            }
        }
        out
    }

    #[tokio::test]
    async fn compact_preserves_data_and_consolidates() {
        let (w, _dir) = memory_warehouse().await;
        // Seed a table.
        w.overwrite_table(
            "lake",
            "events",
            &schema(),
            vec![batch(vec![1, 2, 3], vec!["a", "b", "c"])],
            "seed",
        )
        .await
        .expect("seed");
        let before = read_back(&w, "lake", "events").await;

        let out = compact_table(&w, "lake", "events", "c1")
            .await
            .expect("compaction runs");
        assert_eq!(out.rows, 3);
        assert!(out.data_files >= 1);

        // Data is preserved exactly through the rewrite.
        let after = read_back(&w, "lake", "events").await;
        assert_eq!(before, after);
        assert_eq!(
            after,
            vec![(1, "a".into()), (2, "b".into()), (3, "c".into())]
        );
    }

    #[tokio::test]
    async fn compact_missing_table_errors() {
        let (w, _dir) = memory_warehouse().await;
        let err = compact_table(&w, "lake", "absent", "c1")
            .await
            .expect_err("compacting a missing table must error");
        // The error surfaces from table_provider's load failure and names the table.
        assert!(format!("{err:#}").contains("absent"), "{err:#}");
    }

    fn compaction_entry(wh: &str, ns: &str, table: &str, every: &str) -> CompactionScheduleConfig {
        CompactionScheduleConfig {
            warehouse: wh.to_string(),
            namespace: ns.to_string(),
            table: table.to_string(),
            compact_every: every.to_string(),
        }
    }

    /// `build_compaction_jobs` turns config into a runnable job, and running
    /// that job actually compacts the target (config → job → `compact_table`
    /// wiring), preserving data. The tokio ticker itself is the proven
    /// `RefreshScheduler`, so this exercises everything up to `spawn`.
    #[tokio::test]
    async fn build_compaction_jobs_wires_config_to_compaction() {
        let (w, _dir) = memory_warehouse().await;
        w.overwrite_table(
            "lake",
            "events",
            &schema(),
            vec![batch(vec![1, 2], vec!["a", "b"])],
            "seed",
        )
        .await
        .expect("seed");
        let connectors = HashMap::from([("warehouse".to_string(), Arc::new(w))]);

        let jobs = build_compaction_jobs(
            &[compaction_entry("warehouse", "lake", "events", "6h")],
            &connectors,
            &MaintenanceRegistry::empty(),
        )
        .expect("jobs build");
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].label, "compact:warehouse.lake.events");
        assert_eq!(jobs[0].interval.as_secs(), 6 * 3600);

        // Run the job body once — it must compact the table, rows preserved.
        (jobs[0].run)().await.expect("scheduled compaction runs");
        let after = read_back(&connectors["warehouse"], "lake", "events").await;
        assert_eq!(after, vec![(1, "a".into()), (2, "b".into())]);
    }

    #[tokio::test]
    async fn build_compaction_jobs_tracks_status() {
        let (w, _dir) = memory_warehouse().await;
        w.overwrite_table(
            "lake",
            "events",
            &schema(),
            vec![batch(vec![1, 2, 3], vec!["a", "b", "c"])],
            "seed",
        )
        .await
        .expect("seed");
        let connectors = HashMap::from([("warehouse".to_string(), Arc::new(w))]);
        let status = MaintenanceRegistry::empty();
        let jobs = build_compaction_jobs(
            &[compaction_entry("warehouse", "lake", "events", "6h")],
            &connectors,
            &status,
        )
        .expect("jobs build");

        // Seeded Pending before the first run.
        let seeded = status.snapshot();
        assert_eq!(seeded.len(), 1);
        assert_eq!(seeded[0].job, "compact:warehouse.lake.events");
        assert_eq!(seeded[0].target, "warehouse.lake.events");
        assert_eq!(
            seeded[0].kind,
            crate::maintenance_registry::MaintenanceKind::Compaction
        );

        (jobs[0].run)().await.expect("compaction runs");
        let done = status.snapshot();
        assert_eq!(
            done[0].state,
            crate::maintenance_registry::RefreshState::Success
        );
        assert_eq!(done[0].last_rows, Some(3));
        assert!(done[0].last_data_files.is_some());
        assert_eq!(done[0].runs, 1);
    }

    #[tokio::test]
    async fn build_orphan_sweep_jobs_tracks_status() {
        let (w, _dir) = memory_warehouse().await;
        let connectors = HashMap::from([("warehouse".to_string(), Arc::new(w))]);
        let status = MaintenanceRegistry::empty();
        let jobs = build_orphan_sweep_jobs(
            &[orphan_entry("warehouse", "lake", "1h", "6h")],
            &connectors,
            &status,
        )
        .expect("jobs build");
        assert_eq!(status.snapshot()[0].job, "orphan-sweep:warehouse.lake");

        // Empty namespace → 0 swept, but the run is tracked as a success.
        (jobs[0].run)().await.expect("sweep runs");
        let done = status.snapshot();
        assert_eq!(
            done[0].state,
            crate::maintenance_registry::RefreshState::Success
        );
        assert_eq!(done[0].last_swept, Some(0));
    }

    #[test]
    fn build_compaction_jobs_rejects_unknown_warehouse() {
        let connectors: HashMap<String, Arc<WarehouseConnector>> = HashMap::new();
        let err = build_compaction_jobs(
            &[compaction_entry("nope", "lake", "events", "6h")],
            &connectors,
            &MaintenanceRegistry::empty(),
        )
        .expect_err("unknown warehouse must error");
        assert!(format!("{err:#}").contains("nope"), "{err:#}");
    }

    #[tokio::test]
    async fn build_compaction_jobs_rejects_duplicate_and_bad_interval() {
        let (w, _dir) = memory_warehouse().await;
        let connectors = HashMap::from([("warehouse".to_string(), Arc::new(w))]);

        let dup = build_compaction_jobs(
            &[
                compaction_entry("warehouse", "lake", "events", "6h"),
                compaction_entry("warehouse", "lake", "events", "1h"),
            ],
            &connectors,
            &MaintenanceRegistry::empty(),
        )
        .expect_err("duplicate target must error");
        assert!(format!("{dup:#}").contains("duplicate"), "{dup:#}");

        let bad = build_compaction_jobs(
            &[compaction_entry("warehouse", "lake", "events", "banana")],
            &connectors,
            &MaintenanceRegistry::empty(),
        )
        .expect_err("bad interval must error");
        assert!(format!("{bad:#}").contains("events"), "{bad:#}");
    }

    fn orphan_entry(wh: &str, ns: &str, every: &str, min_age: &str) -> OrphanCleanupConfig {
        OrphanCleanupConfig {
            warehouse: wh.to_string(),
            namespace: ns.to_string(),
            sweep_every: every.to_string(),
            min_age: min_age.to_string(),
        }
    }

    /// `build_orphan_sweep_jobs` turns config into a runnable job, and running
    /// it invokes the sweep (config → job → `sweep_orphan_maintenance_tables`
    /// wiring). On an empty namespace it drops nothing and succeeds.
    #[tokio::test]
    async fn build_orphan_sweep_jobs_wires_config_to_sweep() {
        let (w, _dir) = memory_warehouse().await;
        let connectors = HashMap::from([("warehouse".to_string(), Arc::new(w))]);
        let jobs = build_orphan_sweep_jobs(
            &[orphan_entry("warehouse", "lake", "1h", "6h")],
            &connectors,
            &MaintenanceRegistry::empty(),
        )
        .expect("jobs build");
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].label, "orphan-sweep:warehouse.lake");
        assert_eq!(jobs[0].interval.as_secs(), 3600);
        (jobs[0].run)()
            .await
            .expect("sweep runs on empty namespace");
    }

    #[test]
    fn build_orphan_sweep_jobs_rejects_unknown_warehouse() {
        let connectors: HashMap<String, Arc<WarehouseConnector>> = HashMap::new();
        let err = build_orphan_sweep_jobs(
            &[orphan_entry("nope", "lake", "1h", "6h")],
            &connectors,
            &MaintenanceRegistry::empty(),
        )
        .expect_err("unknown warehouse must error");
        assert!(format!("{err:#}").contains("nope"), "{err:#}");
    }

    #[tokio::test]
    async fn build_orphan_sweep_jobs_rejects_duplicate_and_bad_durations() {
        let (w, _dir) = memory_warehouse().await;
        let connectors = HashMap::from([("warehouse".to_string(), Arc::new(w))]);

        let dup = build_orphan_sweep_jobs(
            &[
                orphan_entry("warehouse", "lake", "1h", "6h"),
                orphan_entry("warehouse", "lake", "2h", "6h"),
            ],
            &connectors,
            &MaintenanceRegistry::empty(),
        )
        .expect_err("duplicate namespace must error");
        assert!(format!("{dup:#}").contains("duplicate"), "{dup:#}");

        let bad = build_orphan_sweep_jobs(
            &[orphan_entry("warehouse", "lake", "1h", "banana")],
            &connectors,
            &MaintenanceRegistry::empty(),
        )
        .expect_err("bad min_age must error");
        assert!(format!("{bad:#}").contains("min_age"), "{bad:#}");
    }
}

//! Warehouse table materialization — the detached-table refresh write path
//! (, Trino-retirement slice 1).
//!
//! Takes Arrow `RecordBatch`es (produced by executing a data product's query)
//! and writes them into a **standalone** warehouse table with **full-overwrite**
//! semantics, replacing Trino's materialized-view refresh.
//!
//! # Overwrite via blue-green swap
//!
//! The pinned `iceberg-rust` `Transaction` exposes only `fast_append` — no
//! atomic overwrite action. To get full-overwrite while preserving the
//! *failed-refresh-is-a-no-op-for-readers* property using only the public API,
//! [`WarehouseConnector::overwrite_table`] writes the new snapshot to a
//! **staging** table, then repoints the logical name via catalog
//! `rename_table` (park live → write staging → promote staging → drop parked).
//! A failed staging write never touches the live table; readers see the prior
//! table until the final promote. (Spec decision, `docs/phases/phase-3/07-trino-retirement.md`.)
//!
//! # CLAUDE.md compliance
//!
//! * Rule 1 — batches flow as Arrow straight into the iceberg writer; no
//!   row-mode conversion.
//! * Rule 7 — the public surface says "warehouse table" / "materialize",
//!   never "Iceberg".
//! * Rule 11 — fully async; the iceberg writer's I/O is awaited. (CPU-heavy
//!   Parquet encoding offload to `spawn_blocking` is a profiling-driven
//!   follow-up — the writer API is inherently async here.)

use std::collections::HashMap;

use arrow::datatypes::SchemaRef;
use arrow::record_batch::RecordBatch;
use datafusion::execution::SendableRecordBatchStream;
use datafusion::physical_plan::stream::RecordBatchStreamAdapter;
use futures::{stream, StreamExt};
use iceberg::arrow::{arrow_schema_to_schema_auto_assign_ids, schema_to_arrow_schema};
use iceberg::spec::DataFileFormat;
use iceberg::table::Table;
use iceberg::transaction::{ApplyTransactionAction, Transaction};
use iceberg::writer::base_writer::data_file_writer::DataFileWriterBuilder;
use iceberg::writer::file_writer::location_generator::{
    DefaultFileNameGenerator, DefaultLocationGenerator,
};
use iceberg::writer::file_writer::rolling_writer::RollingFileWriterBuilder;
use iceberg::writer::file_writer::ParquetWriterBuilder;
use iceberg::writer::{IcebergWriter, IcebergWriterBuilder};
use iceberg::{Catalog, NamespaceIdent, TableCreation, TableIdent};
use parquet::file::properties::WriterProperties;
use tracing::{debug, warn};

use dataglot_core::{DataglotError, Result as DataglotResult};

use crate::iceberg::WarehouseConnector;

/// Result of a successful [`WarehouseConnector::overwrite_table`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaterializeOutcome {
    /// The materialized table name (within its namespace).
    pub table: String,
    /// Total rows written this refresh.
    pub rows: usize,
    /// Number of data files the writer produced.
    pub data_files: usize,
}

/// The version a copy-on-write overwrite expects the **target** table to be
/// at when it commits — the optimistic-concurrency guard. Prevents a
/// read-modify-write from silently clobbering a concurrent writer's commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpectedVersion {
    /// No check — last writer wins (the historical behaviour). Correct for a
    /// full-overwrite refresh from a source (materialization), where the
    /// scheduler already serialises writers per table.
    Any,
    /// The target must not exist yet (a first load). If a concurrent writer
    /// created it in the meantime, the overwrite is refused.
    Absent,
    /// The target must currently be at exactly this version — the snapshot id
    /// it was read at, or `None` for an existing-but-empty table (no snapshot
    /// yet). A read-modify-write (EL upsert / compaction) passes what
    /// [`WarehouseConnector::current_snapshot_id`] returned; if a concurrent
    /// writer committed since (advancing or first-populating the table), the
    /// overwrite is refused. `None` therefore also protects empty tables from
    /// a concurrent first write.
    Snapshot(Option<i64>),
}

/// Infix marking a transient staging table (`<table>__dataglot_staging_<token>`).
/// Load-bearing for orphan cleanup: a leftover staging table from a crashed
/// write is identified by this substring.
pub(crate) const STAGING_INFIX: &str = "__dataglot_staging_";
/// Infix marking a parked live table during a blue-green swap
/// (`<table>__dataglot_parked_<token>`). Also load-bearing for orphan cleanup.
pub(crate) const PARKED_INFIX: &str = "__dataglot_parked_";

/// Whether `name` is a transient blue-green maintenance artifact (staging or
/// parked table) — i.e. a candidate for orphan cleanup, never a user table.
pub(crate) fn is_maintenance_artifact(name: &str) -> bool {
    name.contains(STAGING_INFIX) || name.contains(PARKED_INFIX)
}

/// Staging table name for a blue-green refresh of `table`.
fn staging_name(table: &str, token: &str) -> String {
    format!("{table}{STAGING_INFIX}{token}")
}

/// Name the live table is parked under during the swap.
fn parked_name(table: &str, token: &str) -> String {
    format!("{table}{PARKED_INFIX}{token}")
}

/// Rebind one batch onto the field-id-annotated Arrow schema the warehouse
/// writer expects. The columns are unchanged — only the schema (which now
/// carries the iceberg field-id metadata) differs. Applied per batch as the
/// result streams, so no full-result buffer is held.
fn rebind_batch(batch: &RecordBatch, annotated: &SchemaRef) -> DataglotResult<RecordBatch> {
    RecordBatch::try_new(annotated.clone(), batch.columns().to_vec()).map_err(|e| {
        DataglotError::catalog(format!(
            "query result does not match the materialized table schema: {e}"
        ))
    })
}

impl WarehouseConnector {
    /// Materialize `batches` into `namespace.table` with full-overwrite
    /// semantics. `arrow_schema` is the result schema; `token` makes
    /// the transient staging/parked table names unique for this refresh (the
    /// caller supplies it — e.g. a timestamp or run id).
    ///
    /// Writes the new snapshot to a staging table, then promotes it over the
    /// live table via catalog rename (blue-green). On any failure after the
    /// live table is parked, the live table is rolled back into place; a
    /// failure *before* promotion never touches the live table.
    ///
    /// # Errors
    /// [`DataglotError::Catalog`] if the result schema can't be mapped to a
    /// warehouse schema, the staging write fails, or the swap fails.
    pub async fn overwrite_table(
        &self,
        namespace: &str,
        table: &str,
        arrow_schema: &SchemaRef,
        batches: Vec<RecordBatch>,
        token: &str,
    ) -> DataglotResult<MaterializeOutcome> {
        self.overwrite_table_checked(
            namespace,
            table,
            arrow_schema,
            batches,
            token,
            ExpectedVersion::Any,
        )
        .await
    }

    /// As [`Self::overwrite_table`], but with an [`ExpectedVersion`]
    /// optimistic-concurrency guard. The `expected` version is
    /// checked against the live table **after** the blue-green park has
    /// atomically claimed it and **before** the staging promote, so a
    /// concurrent writer that committed since the caller read its base is
    /// detected — returning [`DataglotError::ConcurrentModification`] with no
    /// change to the live table — rather than being silently clobbered.
    ///
    /// # Errors
    /// [`DataglotError::ConcurrentModification`] if the live table no longer
    /// matches `expected` at promote time; otherwise as [`Self::overwrite_table`].
    pub async fn overwrite_table_checked(
        &self,
        namespace: &str,
        table: &str,
        arrow_schema: &SchemaRef,
        batches: Vec<RecordBatch>,
        token: &str,
        expected: ExpectedVersion,
    ) -> DataglotResult<MaterializeOutcome> {
        // Wrap the in-memory batches as a stream and share the streaming path,
        // so there's a single write implementation. Callers that already have
        // a `SendableRecordBatchStream` (the query write paths) should use
        // [`Self::overwrite_table_stream_checked`] directly to stay
        // bounded-memory.
        let stream: SendableRecordBatchStream = Box::pin(RecordBatchStreamAdapter::new(
            arrow_schema.clone(),
            stream::iter(batches.into_iter().map(Ok)),
        ));
        self.overwrite_table_stream_checked(namespace, table, arrow_schema, stream, token, expected)
            .await
    }

    /// Streaming form of [`Self::overwrite_table`] — writes a
    /// [`SendableRecordBatchStream`] (last-writer-wins). See
    /// [`Self::overwrite_table_stream_checked`] for the concurrency guard.
    ///
    /// # Errors
    /// As [`Self::overwrite_table`].
    pub async fn overwrite_table_stream(
        &self,
        namespace: &str,
        table: &str,
        arrow_schema: &SchemaRef,
        stream: SendableRecordBatchStream,
        token: &str,
    ) -> DataglotResult<MaterializeOutcome> {
        self.overwrite_table_stream_checked(
            namespace,
            table,
            arrow_schema,
            stream,
            token,
            ExpectedVersion::Any,
        )
        .await
    }

    /// Streaming, concurrency-guarded overwrite ( + ). Consumes
    /// the result **as a stream** — one batch in flight at a time, never
    /// buffering the whole result in memory — writing it to a staging table
    /// and promoting via the blue-green swap under the [`ExpectedVersion`]
    /// guard. This is the entry point the query write paths use.
    ///
    /// # Errors
    /// [`DataglotError::ConcurrentModification`] if the live table no longer
    /// matches `expected` at promote time; [`DataglotError::Catalog`] if the
    /// schema can't be mapped, a batch can't be read/written, or the swap fails.
    pub async fn overwrite_table_stream_checked(
        &self,
        namespace: &str,
        table: &str,
        arrow_schema: &SchemaRef,
        stream: SendableRecordBatchStream,
        token: &str,
        expected: ExpectedVersion,
    ) -> DataglotResult<MaterializeOutcome> {
        let catalog = self.catalog();
        // Single-level warehouse namespace (a schema). Multi-level namespaces
        // are a follow-up if a deployment needs them.
        let namespace = NamespaceIdent::new(namespace.to_string());

        // 1. Result Arrow schema → iceberg schema (auto field IDs) + the
        //    field-id-annotated Arrow schema the parquet writer requires.
        let iceberg_schema = arrow_schema_to_schema_auto_assign_ids(arrow_schema.as_ref())
            .map_err(|e| {
                DataglotError::catalog(format!(
                    "cannot map query result to a materialized table schema: {e}"
                ))
            })?;
        let annotated: SchemaRef = schema_to_arrow_schema(&iceberg_schema)
            .map_err(|e| {
                DataglotError::catalog(format!(
                    "materialized table schema is not representable as Arrow: {e}"
                ))
            })?
            .into();

        // 2. Create the staging table (clearing any leftover from a crashed
        //    prior run, best-effort).
        let staging_ident = TableIdent::new(namespace.clone(), staging_name(table, token));
        if catalog.table_exists(&staging_ident).await.unwrap_or(false) {
            best_effort_drop(catalog.as_ref(), &staging_ident, "staging cleanup").await;
        }
        let creation = TableCreation::builder()
            .name(staging_ident.name().to_string())
            .schema(iceberg_schema)
            .properties(HashMap::new())
            .build();
        let staging_table = catalog
            .create_table(&namespace, creation)
            .await
            .map_err(|e| {
                DataglotError::catalog(format!("failed to create staging table for refresh: {e}"))
            })?;

        // 3. Stream batches into staging (rebinding each onto the annotated
        //    schema) and commit. An all-empty result writes no files and skips
        //    the commit (staging stays an empty table). Drop staging on any
        //    write failure so a failed refresh leaks nothing.
        let (data_files, rows) =
            match write_stream_and_commit(catalog.as_ref(), &staging_table, stream, &annotated)
                .await
            {
                Ok(x) => x,
                Err(e) => {
                    best_effort_drop(catalog.as_ref(), &staging_ident, "staging cleanup").await;
                    return Err(e);
                }
            };

        // 4. Blue-green swap, gated by the optimistic-concurrency guard. On
        //    any failure the helper drops staging and (if it parked) rolls the
        //    live table back, so a failed/refused overwrite is a no-op.
        blue_green_promote(
            catalog.as_ref(),
            &namespace,
            table,
            &staging_ident,
            token,
            expected,
        )
        .await?;

        debug!(table = %table, rows, data_files, "materialized table refreshed");
        Ok(MaterializeOutcome {
            table: table.to_string(),
            rows,
            data_files,
        })
    }
}

/// Best-effort cleanup drop of an internal staging/parked table on a
/// failure or rollback path. Logs at `warn` on failure (the table is
/// left for `sweep_orphan_maintenance_tables` to reclaim) instead of
/// swallowing the error, so an operator sees the orphan at the moment it
/// happens rather than only via the later sweep. Mirrors the sweep's own
/// per-drop logging. `context` names the path so the log says
/// *which* cleanup failed.
async fn best_effort_drop(catalog: &dyn Catalog, ident: &TableIdent, context: &str) {
    if let Err(e) = catalog.drop_table(ident).await {
        warn!(
            table = ?ident,
            context,
            "materialize: best-effort cleanup drop failed; table may be orphaned until the next sweep: {e}"
        );
    }
}

/// Post-park optimistic-concurrency check: the live table has been claimed
/// (renamed to `parked`), so verify its version still matches the `base` the
/// caller read. On mismatch (or an unreadable parked table) release it back to
/// `target`, drop `staging`, and return the appropriate error — the live
/// table ends up untouched either way.
async fn validate_parked_version(
    catalog: &dyn Catalog,
    table: &str,
    parked: &TableIdent,
    target: &TableIdent,
    staging_ident: &TableIdent,
    base: Option<i64>,
) -> DataglotResult<()> {
    let current = match catalog.load_table(parked).await {
        Ok(t) => t.metadata().current_snapshot().map(|s| s.snapshot_id()),
        Err(e) => {
            // Can't verify — restore and fail rather than risk a clobber.
            if let Err(re) = catalog.rename_table(parked, target).await {
                warn!(
                    table = %table,
                    "rollback after a validation-read failure also failed — live table \
                     left parked as {parked:?}: {re}"
                );
            }
            best_effort_drop(catalog, staging_ident, "staging cleanup").await;
            return Err(DataglotError::catalog(format!(
                "failed to read the parked table to validate its version: {e}"
            )));
        }
    };
    if current != base {
        if let Err(re) = catalog.rename_table(parked, target).await {
            warn!(
                table = %table,
                "conflict rollback failed — live table left parked as {parked:?}: {re}"
            );
        }
        best_effort_drop(catalog, staging_ident, "staging cleanup").await;
        return Err(DataglotError::concurrent_modification(format!(
            "overwrite of {table} expected version {base:?}, but the live table is now at \
             {current:?} — a concurrent writer committed; re-read and retry"
        )));
    }
    Ok(())
}

/// Promote the written `staging` table over the live `namespace.table` via
/// the catalog rename dance (park live → validate → promote staging → drop
/// parked), enforcing the [`ExpectedVersion`] optimistic-concurrency guard.
///
/// The park rename atomically *claims* the live table (a second concurrent
/// writer's park of the same target fails), so validating the parked table's
/// snapshot against `expected` **after** the park — while no other writer can
/// touch it — closes the read-to-commit window: a mismatch means someone
/// committed since the caller read its base, and we release (rename back) and
/// return [`DataglotError::ConcurrentModification`] with the live table
/// untouched. On any failure `staging` is dropped so nothing leaks.
async fn blue_green_promote(
    catalog: &dyn Catalog,
    namespace: &NamespaceIdent,
    table: &str,
    staging_ident: &TableIdent,
    token: &str,
    expected: ExpectedVersion,
) -> DataglotResult<()> {
    let target = TableIdent::new(namespace.clone(), table.to_string());
    let parked = TableIdent::new(namespace.clone(), parked_name(table, token));

    // A same-token retry may have left a parked table behind; clear it so the
    // park rename below cannot collide (defensive).
    if catalog.table_exists(&parked).await.unwrap_or(false) {
        best_effort_drop(catalog, &parked, "pre-clean stale parked table").await;
    }
    let target_exists = match catalog.table_exists(&target).await {
        Ok(exists) => exists,
        Err(e) => {
            best_effort_drop(catalog, staging_ident, "staging cleanup").await;
            return Err(DataglotError::catalog(format!(
                "failed to probe the live table before swap: {e}"
            )));
        }
    };

    // Pre-park expectation checks that don't need the claim.
    match expected {
        ExpectedVersion::Absent if target_exists => {
            best_effort_drop(catalog, staging_ident, "staging cleanup").await;
            return Err(DataglotError::concurrent_modification(format!(
                "overwrite of {table} expected no existing table (first load), but a \
                 concurrent writer created it"
            )));
        }
        ExpectedVersion::Snapshot(base) if !target_exists => {
            best_effort_drop(catalog, staging_ident, "staging cleanup").await;
            return Err(DataglotError::concurrent_modification(format!(
                "overwrite of {table} expected version {base:?}, but the table no longer exists"
            )));
        }
        _ => {}
    }

    if target_exists {
        if let Err(e) = catalog.rename_table(&target, &parked).await {
            best_effort_drop(catalog, staging_ident, "staging cleanup").await;
            return Err(DataglotError::catalog(format!(
                "failed to park the live table before swap: {e}"
            )));
        }
        // Post-park validation: the live table is now claimed (renamed to
        // `parked`), so no other writer can advance it. If its version no
        // longer matches the base the caller read, someone committed in
        // between — release and refuse.
        if let ExpectedVersion::Snapshot(base) = expected {
            validate_parked_version(catalog, table, &parked, &target, staging_ident, base).await?;
        }
    }

    if let Err(e) = catalog.rename_table(staging_ident, &target).await {
        // Promote failed. If we parked, roll the live table back.
        if target_exists {
            if let Err(re) = catalog.rename_table(&parked, &target).await {
                warn!(
                    table = %table,
                    "CRITICAL: refresh promote failed AND rollback failed — live table \
                     left parked as {parked:?}, {target:?} is missing: {re}"
                );
            }
        }
        best_effort_drop(catalog, staging_ident, "staging cleanup").await;
        // With `Absent`, a promote failure most likely means a concurrent
        // writer created the target between our probe and our promote.
        if matches!(expected, ExpectedVersion::Absent)
            && catalog.table_exists(&target).await.unwrap_or(false)
        {
            return Err(DataglotError::concurrent_modification(format!(
                "overwrite of {table} (first load) lost the race — a concurrent writer created \
                 the table; re-read and retry"
            )));
        }
        return Err(DataglotError::catalog(format!(
            "failed to promote the refreshed table (rolled back): {e}"
        )));
    }

    // Drop the parked (old) table — best-effort; orphan cleanup is the
    // maintenance suite (slice 4).
    if target_exists {
        if let Err(e) = catalog.drop_table(&parked).await {
            warn!(
                table = %table,
                "refresh promoted but dropping the parked table failed (orphan): {e}"
            );
        }
    }
    Ok(())
}

/// Stream `stream`'s batches into `table` (rebinding each onto `annotated`)
/// and commit them via `fast_append`. One batch is held at a time — the full
/// result is never buffered. Returns `(data_files, rows)`. An empty
/// stream (or all-empty batches) writes no files and skips the commit,
/// leaving `table` empty.
async fn write_stream_and_commit(
    catalog: &dyn Catalog,
    table: &Table,
    mut stream: SendableRecordBatchStream,
    annotated: &SchemaRef,
) -> DataglotResult<(usize, usize)> {
    let table_schema = table.metadata().current_schema().clone();
    let location_gen = DefaultLocationGenerator::new(table.metadata()).map_err(|e| {
        DataglotError::catalog(format!("failed to initialize warehouse file layout: {e}"))
    })?;
    let file_name_gen =
        DefaultFileNameGenerator::new("dataglot".to_string(), None, DataFileFormat::Parquet);
    let parquet_builder =
        ParquetWriterBuilder::new(WriterProperties::builder().build(), table_schema);
    let rolling = RollingFileWriterBuilder::new_with_default_file_size(
        parquet_builder,
        table.file_io().clone(),
        location_gen,
        file_name_gen,
    );
    let mut writer = DataFileWriterBuilder::new(rolling)
        .build(None)
        .await
        .map_err(|e| DataglotError::catalog(format!("failed to open warehouse writer: {e}")))?;

    let mut rows = 0usize;
    let mut wrote_any = false;
    while let Some(batch) = stream.next().await {
        let batch = batch.map_err(|e| {
            DataglotError::catalog(format!("failed to read a query-result batch to write: {e}"))
        })?;
        rows += batch.num_rows();
        if batch.num_rows() == 0 {
            // Skip empty batches so they don't force an empty data file.
            continue;
        }
        let batch = rebind_batch(&batch, annotated)?;
        writer.write(batch).await.map_err(|e| {
            DataglotError::catalog(format!("failed to write batch to warehouse: {e}"))
        })?;
        wrote_any = true;
    }
    let data_files = writer
        .close()
        .await
        .map_err(|e| DataglotError::catalog(format!("failed to finalize warehouse files: {e}")))?;

    // Nothing written ⇒ leave the (freshly-created) staging table empty; a
    // `fast_append` of zero data files is pointless (and some catalogs reject
    // it).
    if !wrote_any || data_files.is_empty() {
        return Ok((0, rows));
    }
    let n = data_files.len();

    let tx = Transaction::new(table);
    let append = tx.fast_append().add_data_files(data_files);
    let tx = append
        .apply(tx)
        .map_err(|e| DataglotError::catalog(format!("failed to stage warehouse append: {e}")))?;
    tx.commit(catalog)
        .await
        .map_err(|e| DataglotError::catalog(format!("failed to commit warehouse append: {e}")))?;
    Ok((n, rows))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use arrow::array::{Int32Array, StringArray};
    use arrow::datatypes::{DataType, Field, Schema as ArrowSchema};
    use iceberg::io::LocalFsStorageFactory;
    use iceberg::memory::{MemoryCatalogBuilder, MEMORY_CATALOG_WAREHOUSE};
    use iceberg::{Catalog, CatalogBuilder, NamespaceIdent};
    use tempfile::TempDir;

    use super::*;

    fn sample_schema() -> SchemaRef {
        Arc::new(ArrowSchema::new(vec![
            Field::new("id", DataType::Int32, false),
            Field::new("name", DataType::Utf8, false),
        ]))
    }

    fn batch(ids: Vec<i32>, names: Vec<&str>) -> RecordBatch {
        RecordBatch::try_new(
            sample_schema(),
            vec![
                Arc::new(Int32Array::from(ids)),
                Arc::new(StringArray::from(names)),
            ],
        )
        .unwrap()
    }

    #[test]
    fn staging_and_parked_names_are_distinct_and_namespaced_by_token() {
        assert_eq!(staging_name("users", "t1"), "users__dataglot_staging_t1");
        assert_eq!(parked_name("users", "t1"), "users__dataglot_parked_t1");
        assert_ne!(staging_name("users", "t1"), staging_name("users", "t2"));
    }

    #[test]
    fn rebind_batch_attaches_schema_and_rejects_mismatch() {
        // The annotated schema (field-id metadata) accepts the same columns.
        let iceberg_schema =
            arrow_schema_to_schema_auto_assign_ids(sample_schema().as_ref()).unwrap();
        let annotated: SchemaRef = schema_to_arrow_schema(&iceberg_schema).unwrap().into();
        let out = rebind_batch(&batch(vec![1, 2], vec!["a", "b"]), &annotated).unwrap();
        assert_eq!(out.num_rows(), 2);
        assert_eq!(out.schema(), annotated);

        // A column-count mismatch is rejected, not silently dropped.
        let wrong: SchemaRef = Arc::new(ArrowSchema::new(vec![Field::new(
            "id",
            DataType::Int32,
            false,
        )]));
        assert!(rebind_batch(&batch(vec![1], vec!["a"]), &wrong).is_err());
    }

    /// Build an in-memory warehouse on the local filesystem (no Docker).
    async fn memory_warehouse() -> (WarehouseConnector, NamespaceIdent, TempDir) {
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
        let ns = NamespaceIdent::new("analytics".to_string());
        catalog.create_namespace(&ns, HashMap::new()).await.unwrap();
        let connector = WarehouseConnector::__from_catalog_for_tests(
            "warehouse",
            Arc::new(catalog) as Arc<dyn Catalog>,
        );
        (connector, ns, dir)
    }

    /// Read the `total-records` from the table's current snapshot summary —
    /// proves the *effective* row count without a full scan.
    async fn total_records(
        connector: &WarehouseConnector,
        ns: &NamespaceIdent,
        table: &str,
    ) -> i64 {
        let ident = TableIdent::new(ns.clone(), table.to_string());
        let t = connector.catalog().load_table(&ident).await.unwrap();
        let snap = t.metadata().current_snapshot().expect("a snapshot exists");
        snap.summary()
            .additional_properties
            .get("total-records")
            .and_then(|v| v.parse::<i64>().ok())
            .unwrap_or(-1)
    }

    #[tokio::test]
    async fn overwrite_creates_then_fully_replaces() {
        let (connector, ns, _dir) = memory_warehouse().await;
        let schema = sample_schema();

        // First refresh: 3 rows into a brand-new table.
        let out = connector
            .overwrite_table(
                "analytics",
                "customers",
                &schema,
                vec![batch(vec![1, 2, 3], vec!["a", "b", "c"])],
                "r1",
            )
            .await
            .expect("first refresh materializes");
        assert_eq!(out.rows, 3);
        assert!(out.data_files >= 1);
        assert_eq!(total_records(&connector, &ns, "customers").await, 3);

        // Second refresh: 2 different rows. Full-overwrite ⇒ 2, NOT 5.
        let out = connector
            .overwrite_table(
                "analytics",
                "customers",
                &schema,
                vec![batch(vec![10, 11], vec!["x", "y"])],
                "r2",
            )
            .await
            .expect("second refresh materializes");
        assert_eq!(out.rows, 2);
        assert_eq!(
            total_records(&connector, &ns, "customers").await,
            2,
            "blue-green refresh must replace, not accumulate"
        );

        // The transient staging/parked tables are gone after the swap.
        let tables = connector
            .catalog()
            .list_tables(&ns)
            .await
            .unwrap()
            .into_iter()
            .map(|t| t.name().to_string())
            .collect::<Vec<_>>();
        assert_eq!(
            tables,
            vec!["customers".to_string()],
            "no orphan tables: {tables:?}"
        );
    }

    #[tokio::test]
    async fn checked_overwrite_rejects_stale_snapshot_and_leaves_table_untouched() {
        let (connector, ns, _dir) = memory_warehouse().await;
        let schema = sample_schema();

        // Create the table (r1), then capture the base version a reader/merger
        // would have seen.
        connector
            .overwrite_table(
                "analytics",
                "t",
                &schema,
                vec![batch(vec![1], vec!["a"])],
                "r1",
            )
            .await
            .expect("create");
        let base = connector
            .current_snapshot_id("analytics", "t")
            .await
            .unwrap();
        assert!(base.is_some(), "a populated table has a snapshot");

        // A concurrent writer commits (r2), advancing the snapshot past `base`.
        connector
            .overwrite_table(
                "analytics",
                "t",
                &schema,
                vec![batch(vec![2], vec!["b"])],
                "r2",
            )
            .await
            .expect("concurrent write");

        // Our overwrite, based on the now-stale `base`, must be refused.
        let err = connector
            .overwrite_table_checked(
                "analytics",
                "t",
                &schema,
                vec![batch(vec![9], vec!["z"])],
                "r3",
                ExpectedVersion::Snapshot(base),
            )
            .await
            .expect_err("stale base must be rejected");
        assert!(err.is_concurrent_modification(), "got: {err}");

        // The concurrent writer's data (r2) is intact — not clobbered by ours,
        // and not reverted.
        assert_eq!(total_records(&connector, &ns, "t").await, 1);
        // No orphan staging/parked tables from the refused write.
        let tables = connector
            .catalog()
            .list_tables(&ns)
            .await
            .unwrap()
            .into_iter()
            .map(|t| t.name().to_string())
            .collect::<Vec<_>>();
        assert_eq!(tables, vec!["t".to_string()], "no orphans: {tables:?}");
    }

    #[tokio::test]
    async fn checked_overwrite_succeeds_on_matching_snapshot() {
        let (connector, ns, _dir) = memory_warehouse().await;
        let schema = sample_schema();
        connector
            .overwrite_table(
                "analytics",
                "t",
                &schema,
                vec![batch(vec![1], vec!["a"])],
                "r1",
            )
            .await
            .expect("create");
        let base = connector
            .current_snapshot_id("analytics", "t")
            .await
            .unwrap();
        // Base still current → the checked overwrite commits.
        connector
            .overwrite_table_checked(
                "analytics",
                "t",
                &schema,
                vec![batch(vec![2, 3], vec!["b", "c"])],
                "r2",
                ExpectedVersion::Snapshot(base),
            )
            .await
            .expect("matching base commits");
        assert_eq!(total_records(&connector, &ns, "t").await, 2);
    }

    #[tokio::test]
    async fn checked_overwrite_protects_empty_table_from_concurrent_first_write() {
        // An existing-but-empty table has base version `None`. A concurrent
        // writer that populates it must be detected, not clobbered.
        let (connector, ns, _dir) = memory_warehouse().await;
        let schema = sample_schema();
        connector
            .overwrite_table("analytics", "t", &schema, vec![], "r1")
            .await
            .expect("create empty");
        let base = connector
            .current_snapshot_id("analytics", "t")
            .await
            .unwrap();
        assert_eq!(base, None, "an empty table has no snapshot");

        // Concurrent writer populates it (now has a snapshot).
        connector
            .overwrite_table(
                "analytics",
                "t",
                &schema,
                vec![batch(vec![1], vec!["a"])],
                "r2",
            )
            .await
            .expect("concurrent populate");

        // Our write based on the empty (None) version is refused.
        let err = connector
            .overwrite_table_checked(
                "analytics",
                "t",
                &schema,
                vec![batch(vec![9], vec!["z"])],
                "r3",
                ExpectedVersion::Snapshot(base),
            )
            .await
            .expect_err("stale empty base must be rejected");
        assert!(err.is_concurrent_modification(), "got: {err}");
        assert_eq!(total_records(&connector, &ns, "t").await, 1, "r2 intact");
    }

    #[tokio::test]
    async fn checked_overwrite_absent_conflicts_when_table_exists() {
        let (connector, _ns, _dir) = memory_warehouse().await;
        let schema = sample_schema();
        connector
            .overwrite_table(
                "analytics",
                "t",
                &schema,
                vec![batch(vec![1], vec!["a"])],
                "r1",
            )
            .await
            .expect("create");
        // A "first load" (Absent) that races an existing table is refused.
        let err = connector
            .overwrite_table_checked(
                "analytics",
                "t",
                &schema,
                vec![batch(vec![2], vec!["b"])],
                "r2",
                ExpectedVersion::Absent,
            )
            .await
            .expect_err("absent-expectation must conflict with an existing table");
        assert!(err.is_concurrent_modification(), "got: {err}");
    }

    #[tokio::test]
    async fn checked_overwrite_absent_creates_when_table_missing() {
        let (connector, ns, _dir) = memory_warehouse().await;
        let schema = sample_schema();
        connector
            .overwrite_table_checked(
                "analytics",
                "fresh",
                &schema,
                vec![batch(vec![1], vec!["a"])],
                "r1",
                ExpectedVersion::Absent,
            )
            .await
            .expect("absent-expectation creates a fresh table");
        assert_eq!(total_records(&connector, &ns, "fresh").await, 1);
    }

    #[tokio::test]
    async fn overwrite_with_empty_result_yields_empty_table() {
        let (connector, ns, _dir) = memory_warehouse().await;
        let schema = sample_schema();
        let out = connector
            .overwrite_table("analytics", "empties", &schema, vec![], "r1")
            .await
            .expect("empty refresh still materializes an (empty) table");
        assert_eq!(out.rows, 0);
        assert_eq!(out.data_files, 0);
        let ident = TableIdent::new(ns.clone(), "empties".to_string());
        assert!(connector.catalog().table_exists(&ident).await.unwrap());
    }

    /// Build a `SendableRecordBatchStream` over `batches` for the streaming
    /// write-path tests.
    fn batch_stream(schema: &SchemaRef, batches: Vec<RecordBatch>) -> SendableRecordBatchStream {
        Box::pin(RecordBatchStreamAdapter::new(
            schema.clone(),
            stream::iter(batches.into_iter().map(Ok)),
        ))
    }

    #[tokio::test]
    async fn overwrite_stream_writes_all_batches() {
        let (connector, ns, _dir) = memory_warehouse().await;
        let schema = sample_schema();
        // Several batches arriving as a stream — exercises the bounded-memory
        // write path (one batch in flight at a time).
        let batches = vec![
            batch(vec![1, 2], vec!["a", "b"]),
            batch(vec![3], vec!["c"]),
            batch(vec![4, 5], vec!["d", "e"]),
        ];
        let out = connector
            .overwrite_table_stream(
                "analytics",
                "s",
                &schema,
                batch_stream(&schema, batches),
                "r1",
            )
            .await
            .expect("streaming overwrite");
        assert_eq!(out.rows, 5);
        assert!(out.data_files >= 1);
        assert_eq!(total_records(&connector, &ns, "s").await, 5);
    }

    #[tokio::test]
    async fn overwrite_stream_empty_yields_empty_table() {
        let (connector, ns, _dir) = memory_warehouse().await;
        let schema = sample_schema();
        let empty: Vec<RecordBatch> = vec![];
        let out = connector
            .overwrite_table_stream(
                "analytics",
                "e",
                &schema,
                batch_stream(&schema, empty),
                "r1",
            )
            .await
            .expect("empty stream still materializes an (empty) table");
        assert_eq!(out.rows, 0);
        assert_eq!(out.data_files, 0);
        let ident = TableIdent::new(ns.clone(), "e".to_string());
        assert!(connector.catalog().table_exists(&ident).await.unwrap());
    }

    #[tokio::test]
    async fn overwrite_stream_checked_rejects_stale_base() {
        // The streaming path enforces the same OCC guard as the Vec path.
        let (connector, ns, _dir) = memory_warehouse().await;
        let schema = sample_schema();
        connector
            .overwrite_table(
                "analytics",
                "t",
                &schema,
                vec![batch(vec![1], vec!["a"])],
                "r1",
            )
            .await
            .expect("create");
        let base = connector
            .current_snapshot_id("analytics", "t")
            .await
            .unwrap();
        connector
            .overwrite_table(
                "analytics",
                "t",
                &schema,
                vec![batch(vec![2], vec!["b"])],
                "r2",
            )
            .await
            .expect("concurrent write advances the version");
        let err = connector
            .overwrite_table_stream_checked(
                "analytics",
                "t",
                &schema,
                batch_stream(&schema, vec![batch(vec![9], vec!["z"])]),
                "r3",
                ExpectedVersion::Snapshot(base),
            )
            .await
            .expect_err("stale base must be rejected on the streaming path too");
        assert!(err.is_concurrent_modification(), "got: {err}");
        assert_eq!(total_records(&connector, &ns, "t").await, 1, "r2 intact");
    }
}

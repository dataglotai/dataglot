//! EL ingest — copy-on-write upsert into a warehouse table (,
//! Trino-retirement slice 3).
//!
//! Replaces Trino `MERGE INTO` for SaaS-connector ingest. The pinned
//! `iceberg-rust` can *write* equality-delete files but cannot *commit* them
//! (no rowDelta/overwrite snapshot action — only `fast_append`), so
//! merge-on-read is unavailable. This uses **copy-on-write** (spec decision):
//! read the current table, merge the incoming batch by key in DataFusion, and
//! full-overwrite via the blue-green swap ([`WarehouseConnector::overwrite_table`],
//! slice 1). Correct `MERGE` semantics; rewrites the whole table per batch.
//!
//! Scope: **upsert** (insert + update by key). A first load (target absent)
//! writes the incoming batch directly. Tombstone/delete handling and the REST
//! ingest endpoint + per-tenant concurrency are follow-ups — this module is the
//! tested merge core they call.

// Transitional: the merge core below is server-internal (rule 7) and exercised
// by this module's tests, but its in-crate consumer (the REST ingest endpoint)
// lands in a follow-up. Until then it reads as dead code to the non-test build.
#![allow(dead_code)]

use std::sync::Arc;

use anyhow::{bail, Context};
use datafusion::arrow::datatypes::SchemaRef;
use datafusion::arrow::record_batch::RecordBatch;
use datafusion::datasource::MemTable;
use datafusion::prelude::SessionContext;
use tracing::debug;

use dataglot_federation::iceberg::WarehouseConnector;
use dataglot_federation::materialize::ExpectedVersion;

/// Outcome of a successful [`upsert_into_table`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpsertOutcome {
    /// The target table name (within its namespace).
    pub table: String,
    /// Total rows in the table after the merge.
    pub rows: usize,
}

/// Quote a SQL identifier, escaping embedded double-quotes by doubling them.
fn quote_ident(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}

/// Copy-on-write merge SQL: incoming rows win on a key match; current rows
/// whose key is absent from `incoming` are retained. `columns` is the explicit,
/// pre-quoted projection used identically on **both** sides so `UNION ALL`
/// aligns by name, not position. Keys are matched with equality (NULL keys
/// don't match — upsert identity is assumed non-null); both `columns` and the
/// key predicate are built from already-quoted, schema-validated identifiers
/// (no raw interpolation — no SQL injection).
fn merge_sql(key_columns: &[String], columns: &str) -> String {
    let pred = key_columns
        .iter()
        .map(|k| {
            let q = quote_ident(k);
            format!("i.{q} = c.{q}")
        })
        .collect::<Vec<_>>()
        .join(" AND ");
    format!(
        "SELECT {columns} FROM incoming \
         UNION ALL \
         SELECT {columns} FROM current AS c \
         WHERE NOT EXISTS (SELECT 1 FROM incoming AS i WHERE {pred})"
    )
}

/// Upsert `incoming` into `namespace.table` keyed by `key_columns`
/// (copy-on-write). Reads the current table (if any), merges by key in
/// DataFusion, and writes the full result via blue-green overwrite. `token`
/// disambiguates the transient staging tables for this write.
///
/// # Errors
/// If `key_columns` is empty, the merge query fails to plan/execute, or the
/// warehouse write fails.
pub async fn upsert_into_table(
    warehouse: &WarehouseConnector,
    namespace: &str,
    table: &str,
    key_columns: &[String],
    incoming: Vec<RecordBatch>,
    incoming_schema: SchemaRef,
    token: &str,
) -> anyhow::Result<UpsertOutcome> {
    if key_columns.is_empty() {
        bail!("upsert into '{namespace}.{table}': at least one key column is required");
    }
    // Validate every key against the incoming schema — catches typos early and,
    // since only real schema field names reach the SQL, removes any injection
    // surface from `key_columns`.
    for k in key_columns {
        if incoming_schema.field_with_name(k).is_err() {
            bail!(
                "upsert into '{namespace}.{table}': key column '{k}' is not in the incoming schema"
            );
        }
    }

    // Decide first-load by *existence*, not by swallowing read errors: a
    // transient catalog/network failure must propagate, never be mistaken for
    // an empty table (which would overwrite existing data —  review).
    let exists = warehouse
        .table_exists(namespace, table)
        .await
        .with_context(|| format!("checking existence of '{namespace}.{table}'"))?;

    // Capture the base version *before* reading the current table for the
    // merge, so the optimistic-concurrency check can never claim a newer base
    // than we actually merged against (which would risk a silent clobber —
    // ). A concurrent commit after this point makes the promote fail
    // cleanly (ConcurrentModification), not lose data.
    let base = if exists {
        warehouse
            .current_snapshot_id(namespace, table)
            .await
            .with_context(|| format!("reading base version of '{namespace}.{table}'"))?
    } else {
        None
    };
    let expected = if exists {
        // Read-modify-write — the table must still be at the version we read
        // (`Snapshot(None)` for an existing-but-empty table also refuses a
        // concurrent first write).
        ExpectedVersion::Snapshot(base)
    } else {
        // First load — no table may exist at promote time.
        ExpectedVersion::Absent
    };

    let outcome = if exists {
        let provider = warehouse
            .table_provider(namespace, table)
            .await
            .with_context(|| format!("reading current '{namespace}.{table}' for merge"))?;
        // Project an explicit, quoted column list (the existing table's schema
        // order) on both sides so UNION ALL aligns by name, not position.
        let columns = provider
            .schema()
            .fields()
            .iter()
            .map(|f| quote_ident(f.name()))
            .collect::<Vec<_>>()
            .join(", ");
        let ctx = SessionContext::new();
        let incoming_table = MemTable::try_new(incoming_schema, vec![incoming])
            .context("registering incoming batch")?;
        ctx.register_table("incoming", Arc::new(incoming_table))
            .context("registering incoming table")?;
        ctx.register_table("current", provider)
            .context("registering current table")?;
        let df = ctx
            .sql(&merge_sql(key_columns, &columns))
            .await
            .context("planning merge query")?;
        let schema: SchemaRef = Arc::new(df.schema().as_arrow().clone());
        // Stream the merge result straight into the write path — the full
        // merged table is never buffered in memory. The returned
        // stream owns its execution state, so `ctx` may drop here.
        let merged = df.execute_stream().await.context("executing merge query")?;
        warehouse
            .overwrite_table_stream_checked(namespace, table, &schema, merged, token, expected)
            .await
    } else {
        debug!(table, "upsert first load — no existing table");
        // A first load is a single incoming batch (small); the Vec path wraps
        // it into a stream internally.
        warehouse
            .overwrite_table_checked(
                namespace,
                table,
                &incoming_schema,
                incoming,
                token,
                expected,
            )
            .await
    }
    .with_context(|| format!("writing upsert result to '{namespace}.{table}'"))?;

    Ok(UpsertOutcome {
        table: table.to_string(),
        rows: outcome.rows,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use datafusion::arrow::array::{Int32Array, StringArray};
    use datafusion::arrow::datatypes::{DataType, Field, Schema as ArrowSchema};
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
            .create_namespace(&NamespaceIdent::new("cdc".to_string()), HashMap::new())
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

    /// Read the whole table back as (id, v) pairs, sorted by id.
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

    #[test]
    fn merge_sql_builds_multi_key_predicate_and_explicit_projection() {
        let sql = merge_sql(&["a".to_string(), "b".to_string()], r#""a", "b", "v""#);
        assert!(sql.contains(r#"i."a" = c."a" AND i."b" = c."b""#), "{sql}");
        assert!(sql.contains("NOT EXISTS"));
        // Explicit projection on both sides (no `*`), aligns UNION ALL by name.
        assert!(
            sql.contains(r#"SELECT "a", "b", "v" FROM incoming"#),
            "{sql}"
        );
        assert!(
            sql.contains(r#"SELECT "a", "b", "v" FROM current"#),
            "{sql}"
        );
        assert!(!sql.contains("SELECT *"), "{sql}");
    }

    #[test]
    fn quote_ident_escapes_embedded_quotes() {
        assert_eq!(quote_ident("id"), r#""id""#);
        assert_eq!(quote_ident(r#"a"b"#), r#""a""b""#);
    }

    #[tokio::test]
    async fn upsert_rejects_key_not_in_schema() {
        let (w, _dir) = memory_warehouse().await;
        // Key "missing" is not a column → rejected before any query/injection.
        let err = upsert_into_table(
            &w,
            "cdc",
            "users",
            &["missing".to_string()],
            vec![batch(vec![1], vec!["a"])],
            schema(),
            "r1",
        )
        .await
        .expect_err("unknown key must error");
        assert!(format!("{err:#}").contains("not in the incoming schema"));
    }

    #[tokio::test]
    async fn upsert_first_load_then_merges_by_key() {
        let (w, _dir) = memory_warehouse().await;
        let keys = vec!["id".to_string()];

        // First load: 2 rows into a fresh table.
        let out = upsert_into_table(
            &w,
            "cdc",
            "users",
            &keys,
            vec![batch(vec![1, 2], vec!["a", "b"])],
            schema(),
            "r1",
        )
        .await
        .expect("first load");
        assert_eq!(out.rows, 2);
        assert_eq!(
            read_back(&w, "cdc", "users").await,
            vec![(1, "a".into()), (2, "b".into())]
        );

        // Upsert: update id=2 (b→B), insert id=3. id=1 untouched.
        let out = upsert_into_table(
            &w,
            "cdc",
            "users",
            &keys,
            vec![batch(vec![2, 3], vec!["B", "c"])],
            schema(),
            "r2",
        )
        .await
        .expect("upsert merge");
        assert_eq!(out.rows, 3, "1 kept + 1 updated + 1 inserted");
        assert_eq!(
            read_back(&w, "cdc", "users").await,
            vec![(1, "a".into()), (2, "B".into()), (3, "c".into())],
            "id=2 updated to B (not duplicated), id=3 inserted, id=1 retained"
        );
    }

    #[tokio::test]
    async fn upsert_rejects_empty_key_columns() {
        let (w, _dir) = memory_warehouse().await;
        let err = upsert_into_table(
            &w,
            "cdc",
            "users",
            &[],
            vec![batch(vec![1], vec!["a"])],
            schema(),
            "r1",
        )
        .await
        .expect_err("empty keys must error");
        assert!(format!("{err:#}").contains("key column"));
    }
}

//! End-to-end test for the Object Storage connector.
//!
//! Pre-registers a parquet file in a tempdir, builds an
//! `ObjectStorageCatalogConfig` pointing at it, runs the catalog
//! through `build_connectors`, and queries the resulting
//! `Arc<dyn DfCatalogProvider>` directly via a `SessionContext`.
//! No Docker — local filesystem only — so this test is part of the
//! standard `cargo test --workspace` run.
//!
//! Spec: `docs/phases/phase-1/04-object-storage-connector.md`.

use std::collections::HashMap;
use std::fs::File;
use std::sync::Arc;

use datafusion::arrow::array::{AsArray, Int32Array, RecordBatch, StringArray};
use datafusion::arrow::datatypes::{DataType, Field, Schema};
use datafusion::arrow::util::pretty::pretty_format_batches;
use datafusion::prelude::SessionContext;
use parquet::arrow::ArrowWriter;
use parquet::file::properties::WriterProperties;
use tempfile::TempDir;

use dataglot_server::config::{
    build_connectors, CatalogConfig, ObjectStorageCatalogConfig, ObjectStorageFormat,
    ObjectStorageTableConfig,
};

/// Seed a tempdir with `users.parquet` containing three rows:
///
/// | id | name  |
/// |----|-------|
/// | 1  | Alice |
/// | 2  | Bob   |
/// | 3  | Carol |
///
/// Returns the tempdir handle (caller must keep alive) and the
/// `file://` URL pointing at the seeded file.
fn seed_users_parquet() -> (TempDir, String) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("users.parquet");

    let schema = Arc::new(Schema::new(vec![
        Field::new("id", DataType::Int32, false),
        Field::new("name", DataType::Utf8, false),
    ]));
    let batch = RecordBatch::try_new(
        Arc::clone(&schema),
        vec![
            Arc::new(Int32Array::from(vec![1, 2, 3])),
            Arc::new(StringArray::from(vec!["Alice", "Bob", "Carol"])),
        ],
    )
    .expect("build seed batch");

    let file = File::create(&path).expect("create parquet file");
    let mut writer = ArrowWriter::try_new(file, schema, Some(WriterProperties::builder().build()))
        .expect("build ArrowWriter");
    writer.write(&batch).expect("write seed batch");
    writer.close().expect("finalize parquet");

    // Use forward-slashes so the URL parses on both Windows and
    // POSIX. `Path::display()` keeps platform-native separators
    // which `ListingTableUrl::parse` rejects on Windows.
    let posix_path = path.display().to_string().replace('\\', "/");
    let url = format!("file:///{}", posix_path.trim_start_matches('/'));
    (tmp, url)
}

/// End-to-end: register a `kind = "object_storage"` catalog with
/// one parquet table, query it via `SessionContext::sql`, assert
/// row count + content + schema fidelity.
#[tokio::test]
async fn object_storage_catalog_serves_parquet_rows() {
    let (_tmp, url) = seed_users_parquet();

    let mut catalogs = HashMap::new();
    catalogs.insert(
        "files".to_string(),
        CatalogConfig::ObjectStorage(ObjectStorageCatalogConfig {
            s3: None,
            tables: vec![ObjectStorageTableConfig {
                name: "users".into(),
                url,
                format: ObjectStorageFormat::Parquet,
                schema: None, // defaults to "public"
            }],
        }),
    );

    // Boot path — schema inference happens here, not at query
    // time. A missing file / wrong format would surface as a
    // typed catalog error from build_connectors.
    let providers = build_connectors(&catalogs).await.expect("build catalogs");
    let files_catalog = providers.get("files").expect("files catalog present");

    // Drive a query through SessionContext directly — pgwire
    // round-trip is exercised by the existing e2e suite.
    let ctx = SessionContext::new();
    ctx.register_catalog("files", Arc::clone(files_catalog));

    let df = ctx
        .sql("SELECT id, name FROM files.public.users ORDER BY id")
        .await
        .expect("SQL parses + plans");
    let batches = df.collect().await.expect("query runs");

    let total_rows: usize = batches.iter().map(RecordBatch::num_rows).sum();
    assert_eq!(
        total_rows,
        3,
        "expected 3 seeded rows, got:\n{}",
        pretty_format_batches(&batches).unwrap()
    );

    // Decode columns directly to pin exact (id, name) pairs.
    // Substring matching on the pretty-print is false-pass-prone
    // — the cross-source-joins suite (#166) learned the same
    // lesson. `AsArray::as_string` handles the
    // Utf8 / LargeUtf8 / Utf8View polymorphism that DataFusion's
    // ParquetFormat may surface (the actual type depends on
    // upstream ScanConfig defaults).
    let mut got: Vec<(i32, String)> = Vec::new();
    for batch in &batches {
        let ids = batch
            .column(0)
            .as_any()
            .downcast_ref::<Int32Array>()
            .expect("id is Int32");
        let name_col = batch.column(1);
        for row in 0..batch.num_rows() {
            let name = match name_col.data_type() {
                DataType::Utf8 => name_col.as_string::<i32>().value(row).to_string(),
                DataType::LargeUtf8 => name_col.as_string::<i64>().value(row).to_string(),
                DataType::Utf8View => name_col.as_string_view().value(row).to_string(),
                other => panic!("unexpected name column type: {other:?}"),
            };
            got.push((ids.value(row), name));
        }
    }
    assert_eq!(
        got,
        vec![
            (1, "Alice".to_string()),
            (2, "Bob".to_string()),
            (3, "Carol".to_string()),
        ]
    );

    // Schema fidelity: the projected output schema reflects what
    // we wrote (Int32, string-family). DataFusion's ParquetFormat
    // may surface `Utf8`, `LargeUtf8`, or `Utf8View` depending on
    // version — accept any of the three. Anything else fails
    // loud.
    let out_schema = batches[0].schema();
    assert_eq!(out_schema.field(0).name(), "id");
    assert_eq!(out_schema.field(0).data_type(), &DataType::Int32);
    assert_eq!(out_schema.field(1).name(), "name");
    let name_dt = out_schema.field(1).data_type();
    assert!(
        matches!(
            name_dt,
            DataType::Utf8 | DataType::LargeUtf8 | DataType::Utf8View
        ),
        "name column should be a string-family Arrow type, got {name_dt:?}"
    );
}

/// Custom-schema variant: the catalog config declares
/// `schema: "sales"` and the resulting table is reachable as
/// `files.sales.users` rather than `files.public.users`. Pin the
/// override path because it's the only thing distinguishing
/// `<catalog>.public.<table>` from `<catalog>.<custom>.<table>`.
#[tokio::test]
async fn object_storage_catalog_honors_custom_schema_name() {
    let (_tmp, url) = seed_users_parquet();

    let mut catalogs = HashMap::new();
    catalogs.insert(
        "files".to_string(),
        CatalogConfig::ObjectStorage(ObjectStorageCatalogConfig {
            s3: None,
            tables: vec![ObjectStorageTableConfig {
                name: "users".into(),
                url,
                format: ObjectStorageFormat::Parquet,
                schema: Some("sales".to_string()),
            }],
        }),
    );

    let providers = build_connectors(&catalogs).await.expect("build catalogs");
    let files_catalog = providers.get("files").expect("files catalog present");

    let ctx = SessionContext::new();
    ctx.register_catalog("files", Arc::clone(files_catalog));

    // Custom schema works.
    let df = ctx
        .sql("SELECT id FROM files.sales.users ORDER BY id")
        .await
        .expect("SQL parses on custom schema");
    let batches = df.collect().await.expect("query runs");
    let total_rows: usize = batches.iter().map(RecordBatch::num_rows).sum();
    assert_eq!(total_rows, 3);

    // Default schema is *not* registered when an explicit one
    // was provided.
    let missing = ctx.sql("SELECT id FROM files.public.users").await;
    assert!(
        missing.is_err(),
        "files.public.users should not exist when schema is overridden to 'sales'"
    );
}

/// Multiple tables in one catalog get registered together. Pin
/// the per-table independence — registering one doesn't shadow
/// the other.
#[tokio::test]
async fn object_storage_catalog_registers_multiple_tables() {
    let (_tmp, url1) = seed_users_parquet();
    let (_tmp2, url2) = seed_users_parquet();

    let mut catalogs = HashMap::new();
    catalogs.insert(
        "files".to_string(),
        CatalogConfig::ObjectStorage(ObjectStorageCatalogConfig {
            s3: None,
            tables: vec![
                ObjectStorageTableConfig {
                    name: "users".into(),
                    url: url1,
                    format: ObjectStorageFormat::Parquet,
                    schema: None,
                },
                ObjectStorageTableConfig {
                    name: "people".into(),
                    url: url2,
                    format: ObjectStorageFormat::Parquet,
                    schema: None,
                },
            ],
        }),
    );

    let providers = build_connectors(&catalogs).await.expect("build catalogs");
    let files_catalog = providers.get("files").expect("files catalog present");

    let ctx = SessionContext::new();
    ctx.register_catalog("files", Arc::clone(files_catalog));

    let users_rows: usize = ctx
        .sql("SELECT id FROM files.public.users")
        .await
        .expect("users SQL")
        .collect()
        .await
        .expect("users runs")
        .iter()
        .map(RecordBatch::num_rows)
        .sum();
    let people_rows: usize = ctx
        .sql("SELECT id FROM files.public.people")
        .await
        .expect("people SQL")
        .collect()
        .await
        .expect("people runs")
        .iter()
        .map(RecordBatch::num_rows)
        .sum();
    assert_eq!(users_rows, 3, "users table");
    assert_eq!(people_rows, 3, "people table");
}

/// Bad path — non-existent file surfaces as a typed catalog
/// error at boot, not at first-query runtime. This is the spec's
/// fail-fast contract: missing-table / wrong-format / unreadable
/// storage all surface here.
#[tokio::test]
async fn object_storage_missing_file_fails_at_boot() {
    let mut catalogs = HashMap::new();
    catalogs.insert(
        "files".to_string(),
        CatalogConfig::ObjectStorage(ObjectStorageCatalogConfig {
            s3: None,
            tables: vec![ObjectStorageTableConfig {
                name: "users".into(),
                url: "file:///nonexistent/path/to/no_such_file.parquet".into(),
                format: ObjectStorageFormat::Parquet,
                schema: None,
            }],
        }),
    );

    let err = build_connectors(&catalogs).await.unwrap_err();
    let msg = format!("{err:#}");
    // The error chain should mention the missing path and
    // include the table name (so operators can locate the bad
    // entry in their config).
    assert!(
        msg.contains("users") && msg.contains("no_such_file.parquet"),
        "expected missing-file error to name table + path, got:\n{msg}"
    );
}

//!  — a pgwire client that names an unregistered `database` in
//! its startup parameters must be refused with Postgres
//! `3D000 invalid_catalog_name`, not silently connected to the server's
//! default catalog (which would run its queries against the wrong data).
//!
//! No Docker: boots a `DataglotServer` with a single in-memory-ish
//! object-storage catalog over a seeded temp parquet file, then drives
//! real `tokio_postgres` connections with different `dbname` values.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use datafusion::arrow::array::{Int32Array, StringArray};
use datafusion::arrow::datatypes::{DataType, Field, Schema};
use datafusion::arrow::record_batch::RecordBatch;
use dataglot_server::config::{
    CatalogConfig, ObjectStorageCatalogConfig, ObjectStorageFormat, ObjectStorageTableConfig,
    ServerConfig,
};
use dataglot_server::observability::ObservabilityConfig;
use dataglot_server::server::DataglotServer;
use parquet::arrow::ArrowWriter;
use parquet::file::properties::WriterProperties;
use std::fs::File;
use tempfile::TempDir;
use tokio_postgres::NoTls;

fn ephemeral_port() -> u16 {
    //: delegate to the shared, race-hardened helper.
    dataglot_test_support::reserve_loopback_port()
}

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
    .expect("seed batch");
    let file = File::create(&path).expect("create parquet");
    let mut writer = ArrowWriter::try_new(file, schema, Some(WriterProperties::builder().build()))
        .expect("writer");
    writer.write(&batch).expect("write");
    writer.close().expect("close");
    let posix = path.display().to_string().replace('\\', "/");
    (tmp, format!("file:///{}", posix.trim_start_matches('/')))
}

/// Boot a server with one object-storage catalog named `files`, whose
/// name is also the server default catalog. Returns the pgwire port
/// (and keeps the tempdir alive).
async fn boot(default_catalog: &str) -> (u16, TempDir) {
    let (tmp, url) = seed_users_parquet();
    let mut catalogs = HashMap::new();
    catalogs.insert(
        "files".to_string(),
        CatalogConfig::ObjectStorage(ObjectStorageCatalogConfig {
            s3: None,
            tables: vec![ObjectStorageTableConfig {
                name: "users".into(),
                url,
                format: ObjectStorageFormat::Parquet,
                schema: None,
            }],
        }),
    );
    let pg_port = ephemeral_port();
    let config = ServerConfig {
        host: "127.0.0.1".to_string(),
        port: pg_port,
        default_catalog: default_catalog.to_string(),
        observability: ObservabilityConfig {
            metrics_addr: None,
            ..ObservabilityConfig::default()
        },
        catalogs,
        ..ServerConfig::default()
    };
    let server = DataglotServer::new(config).await.expect("server boots");
    tokio::spawn(async move {
        server.run().await.expect("server runs");
    });
    // Readiness: the default-catalog connection must succeed.
    let ready = format!("host=127.0.0.1 port={pg_port} user=dataglot dbname={default_catalog}");
    for _ in 0..50 {
        if tokio_postgres::connect(&ready, NoTls).await.is_ok() {
            return (pg_port, tmp);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("server did not become ready on {pg_port}");
}

/// A `dbname` naming a registered catalog connects and can query it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn registered_database_connects_and_queries() {
    let (pg_port, _tmp) = boot("files").await;
    let conn_str = format!("host=127.0.0.1 port={pg_port} user=dataglot dbname=files");
    let (client, connection) = tokio_postgres::connect(&conn_str, NoTls)
        .await
        .expect("registered dbname connects");
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let rows = client
        .query("SELECT COUNT(*) FROM files.public.users", &[])
        .await
        .expect("query runs against the named catalog");
    let n: i64 = rows[0].get(0);
    assert_eq!(n, 3);
}

/// ** regression pin.** A `dbname` that names no registered
/// catalog is refused with `3D000 invalid_catalog_name` — not silently
/// connected to the default catalog.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unknown_database_is_refused_with_3d000() {
    let (pg_port, _tmp) = boot("files").await;
    let conn_str =
        format!("host=127.0.0.1 port={pg_port} user=dataglot dbname=definitely_not_a_catalog");
    let Err(err) = tokio_postgres::connect(&conn_str, NoTls).await else {
        panic!("unknown dbname must be refused, but the connection succeeded");
    };
    let db_err = err
        .as_db_error()
        .expect("a server DbError, not a transport error");
    assert_eq!(
        db_err.code(),
        &tokio_postgres::error::SqlState::INVALID_CATALOG_NAME,
        "expected 3D000 invalid_catalog_name, got {:?}: {}",
        db_err.code(),
        db_err.message()
    );
    assert!(
        db_err.message().contains("definitely_not_a_catalog"),
        "error should name the missing database: {}",
        db_err.message()
    );
}

/// Regression guard for the change itself: a server whose
/// `default_catalog` has NO matching `[catalogs.*]` entry still accepts
/// a `dbname=<default>` connection (the session's placeholder default
/// catalog resolves) — the fix must not turn the default connection
/// into a 3D000.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn default_catalog_without_matching_config_still_connects() {
    // default_catalog "dataglot" is the ServerConfig default and has no
    // matching object-storage entry (only "files" is configured).
    let (pg_port, _tmp) = boot("dataglot").await;
    let conn_str = format!("host=127.0.0.1 port={pg_port} user=dataglot dbname=dataglot");
    let (client, connection) = tokio_postgres::connect(&conn_str, NoTls)
        .await
        .expect("default-catalog connection must still succeed");
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let rows = client
        .query("SELECT 1::int AS one", &[])
        .await
        .expect("query runs");
    let one: i32 = rows[0].get(0);
    assert_eq!(one, 1);
}

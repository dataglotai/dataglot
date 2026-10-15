//! Client mode (`dataglot query --server` / `dataglot shell --server`) against
//! a real `DataglotServer` over pg-wire.
//!
//! The server runs with an embedded meta store so control-plane DDL works, and
//! one object-storage catalog `files` over a seeded parquet file.

use std::collections::HashMap;
use std::fs::File;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use datafusion::arrow::array::{Int32Array, StringArray};
use datafusion::arrow::datatypes::{DataType, Field, Schema};
use datafusion::arrow::record_batch::RecordBatch;
use dataglot_server::cli::OutputFormat;
use dataglot_server::client::{self, ClientError, RemoteSession};
use dataglot_server::config::{
    CatalogConfig, CatalogServiceConfig, EmbeddedStoreConfig, ObjectStorageCatalogConfig,
    ObjectStorageFormat, ObjectStorageTableConfig, ServerConfig,
};
use dataglot_server::observability::ObservabilityConfig;
use dataglot_server::server::DataglotServer;
use parquet::arrow::ArrowWriter;
use tempfile::TempDir;

fn seed_users_parquet(dir: &TempDir) -> String {
    let path = dir.path().join("users.parquet");
    let schema = Arc::new(Schema::new(vec![
        Field::new("id", DataType::Int32, false),
        Field::new("name", DataType::Utf8, true),
    ]));
    let batch = RecordBatch::try_new(
        Arc::clone(&schema),
        vec![
            Arc::new(Int32Array::from(vec![1, 2, 3])),
            Arc::new(StringArray::from(vec![Some("Alice"), None, Some("Carol")])),
        ],
    )
    .expect("seed batch");
    let file = File::create(&path).expect("create parquet");
    let mut writer = ArrowWriter::try_new(file, schema, None).expect("writer");
    writer.write(&batch).expect("write");
    writer.close().expect("close");
    let posix = path.display().to_string().replace('\\', "/");
    format!("file:///{}", posix.trim_start_matches('/'))
}

/// Boot the server and return a `--server` URL for it (and the tempdir that
/// holds its data and meta store).
async fn boot() -> (String, TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let url = seed_users_parquet(&dir);
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
    let port = dataglot_test_support::reserve_loopback_port();
    let config = ServerConfig {
        host: "127.0.0.1".to_string(),
        port,
        default_catalog: "files".to_string(),
        observability: ObservabilityConfig {
            metrics_addr: None,
            ..ObservabilityConfig::default()
        },
        catalogs,
        catalog_service: Some(CatalogServiceConfig::Embedded(EmbeddedStoreConfig {
            path: dir.path().join("meta.redb"),
            org_id: "default".to_string(),
        })),
        ..ServerConfig::default()
    };
    let server = DataglotServer::new(config).await.expect("server boots");
    tokio::spawn(async move {
        server.run().await.expect("server runs");
    });
    let server_url = format!("postgres://admin@127.0.0.1:{port}");
    for _ in 0..50 {
        if RemoteSession::connect(&server_url).await.is_ok() {
            return (server_url, dir);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("server did not become ready on {port}");
}

/// `run_query` with captured stdout / stderr.
async fn query(server: &str, sql: &str, format: OutputFormat) -> (ExitCode, String, String) {
    let mut out = Vec::new();
    let mut err = Vec::new();
    let code = client::run_query(server, sql, format, &mut out, &mut err).await;
    (
        code,
        String::from_utf8(out).expect("utf-8 stdout"),
        String::from_utf8(err).expect("utf-8 stderr"),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn prints_a_table_like_embedded_mode() {
    let (server, _dir) = boot().await;
    let (code, out, err) = query(
        &server,
        "SELECT id, name FROM files.public.users ORDER BY id",
        OutputFormat::Table,
    )
    .await;
    assert_eq!(code, ExitCode::SUCCESS, "{err}");
    assert_eq!(
        out,
        "+----+-------+\n\
         | id | name  |\n\
         +----+-------+\n\
         | 1  | Alice |\n\
         | 2  |       |\n\
         | 3  | Carol |\n\
         +----+-------+\n"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn csv_and_json_output() {
    let (server, _dir) = boot().await;
    let sql = "SELECT id, name FROM files.public.users ORDER BY id";
    let (code, out, err) = query(&server, sql, OutputFormat::Csv).await;
    assert_eq!(code, ExitCode::SUCCESS, "{err}");
    assert_eq!(out, "id,name\n1,Alice\n2,\n3,Carol\n");

    // Values come back as text over the simple protocol, so JSON has strings.
    let (code, out, err) = query(&server, sql, OutputFormat::Json).await;
    assert_eq!(code, ExitCode::SUCCESS, "{err}");
    assert_eq!(
        out,
        "{\"id\":\"1\",\"name\":\"Alice\"}\n{\"id\":\"2\"}\n{\"id\":\"3\",\"name\":\"Carol\"}\n"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_empty_result_still_prints_its_header() {
    let (server, _dir) = boot().await;
    let sql = "SELECT id, name FROM files.public.users WHERE id > 100";
    let (_, out, _) = query(&server, sql, OutputFormat::Table).await;
    assert_eq!(
        out,
        "+----+------+\n| id | name |\n+----+------+\n+----+------+\n"
    );
    let (_, out, _) = query(&server, sql, OutputFormat::Csv).await;
    assert_eq!(out, "id,name\n");
}

/// The point of client mode: control-plane DDL and governance run on the
/// server, so a mask created through the CLI applies to the next query.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn create_mask_through_the_client_masks_later_queries() {
    let (server, _dir) = boot().await;
    let (code, out, err) = query(
        &server,
        "CREATE MASK name_mask ON files.public.users (name) AS '***'",
        OutputFormat::Table,
    )
    .await;
    assert_eq!(code, ExitCode::SUCCESS, "{err}");
    assert_eq!(out, "", "DDL prints nothing");

    let (code, out, err) = query(
        &server,
        "SELECT name FROM files.public.users ORDER BY id",
        OutputFormat::Csv,
    )
    .await;
    assert_eq!(code, ExitCode::SUCCESS, "{err}");
    assert_eq!(out, "name\n***\n***\n***\n");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn several_statements_print_one_result_each() {
    let (server, _dir) = boot().await;
    let (code, out, err) = query(&server, "SELECT 1 AS a; SELECT 2 AS b;", OutputFormat::Csv).await;
    assert_eq!(code, ExitCode::SUCCESS, "{err}");
    assert_eq!(out, "a\n1\nb\n2\n");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rejected_statement_exits_1_and_the_session_survives() {
    let (server, _dir) = boot().await;
    let (code, out, err) = query(&server, "SELECT * FROM no_such_table", OutputFormat::Table).await;
    assert_eq!(code, ExitCode::FAILURE);
    assert_eq!(out, "");
    assert!(err.starts_with("error: "), "{err}");
    assert!(err.contains("no_such_table"), "{err}");

    // What the shell relies on: after a statement error the same connection
    // keeps working.
    let session = RemoteSession::connect(&server).await.expect("connect");
    let mut out = Vec::new();
    let e = session
        .execute("SELECT * FROM no_such_table", OutputFormat::Csv, &mut out)
        .await
        .expect_err("unknown table");
    assert!(matches!(e, ClientError::Statement(_)), "{e:?}");
    assert!(!e.is_fatal());
    session
        .execute("SELECT 1 AS n", OutputFormat::Csv, &mut out)
        .await
        .expect("connection still usable");
    assert_eq!(String::from_utf8(out).expect("utf-8"), "n\n1\n");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn copy_to_stdout_is_refused_with_a_clear_message() {
    let (server, _dir) = boot().await;
    let (code, out, err) = query(
        &server,
        "COPY (SELECT 1 AS n) TO STDOUT",
        OutputFormat::Table,
    )
    .await;
    assert_eq!(code, ExitCode::FAILURE);
    assert_eq!(out, "");
    assert!(
        err.contains("`COPY ... TO STDOUT` isn't supported"),
        "{err}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unknown_database_exits_2() {
    let (server, _dir) = boot().await;
    let (code, out, err) = query(
        &format!("{server}/no_such_catalog"),
        "SELECT 1",
        OutputFormat::Table,
    )
    .await;
    assert_eq!(code, ExitCode::from(2));
    assert_eq!(out, "");
    assert!(
        err.starts_with("error: could not connect to 127.0.0.1:"),
        "{err}"
    );
    assert!(
        err.contains("database \"no_such_catalog\" does not exist"),
        "{err}"
    );
}

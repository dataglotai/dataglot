//! Phase 1 · §11 Interface #2 slice 3 end-to-end test.
//!
//! Spec: the phase-1 `data-product-registration` plan.
//!
//! What this test pins beyond the per-slice unit tests:
//!
//! - Slice 2 (`dataglot-server::governance::tests::http_*`) pins
//!   the `DataHubPublisher` HTTP wire shape and the failure-
//!   isolation contract against a `wiremock` backend, but never
//!   boots a `DataglotServer`.
//! - Slice 3's `publish_all_bindings_*` unit tests pin the
//!   binding-fan-out helper in isolation with a synthetic
//!   `HashMap` — they never exercise the server-boot path.
//!
//! This test joins them: it boots a real `DataglotServer` with a
//! `governance_publishers` config block pointing at a `wiremock`-
//! backed `DataHub` stand-in and an `[catalogs.*]` block declaring
//! three real catalogs, then asserts that one
//! `MetadataChangeProposal` POST lands per configured catalog
//! within the spec's 5-second boot window. If anyone ever breaks
//! the `DataglotServer::new` → `publish_all_bindings()` boot
//! wiring, this test fails.
//!
//! Why not Docker-gated against a real `DataHub`: per the slice
//! spec "Boot real `DataglotServer` ... pointing at a wiremock-
//! backed `DataHub` stand-in (no real `DataHub` container — too
//! heavy for CI; `DataHub` uses Kafka + Elasticsearch + `MySQL` +
//! GMS)". wiremock covers the protocol-level integration without
//! Docker; the operator-facing `DataHub` UI check is a deferred
//! follow-up. Keeping this in-process means the test runs on every
//! `cargo test --workspace` and stays in the fast pre-PR gate.

use std::collections::HashMap;
use std::fs::File;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use datafusion::arrow::array::{Int32Array, RecordBatch, StringArray};
use datafusion::arrow::datatypes::{DataType, Field, Schema};
use parquet::arrow::ArrowWriter;
use parquet::file::properties::WriterProperties;
use serde_json::Value;
use tempfile::TempDir;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

use dataglot_server::config::{
    CatalogConfig, GovernancePublisherConfig, ObjectStorageCatalogConfig, ObjectStorageFormat,
    ObjectStorageTableConfig, ServerConfig,
};
use dataglot_server::observability::ObservabilityConfig;
use dataglot_server::server::DataglotServer;

/// Reserve an ephemeral port and return it; the caller re-binds.
/// Small race window between drop and re-bind but tolerable for
/// tests — same pattern the lineage e2e uses.
fn ephemeral_port() -> u16 {
    //: delegate to the shared, race-hardened helper.
    dataglot_test_support::reserve_loopback_port()
}

/// Seed a tempdir with a single `seed.parquet` file. We point
/// every test catalog at this same file with a different `name`
/// so each catalog has a valid table backing it — the
/// object-storage connector rejects empty `tables` arrays at
/// boot, and the e2e test only cares about the *catalog-level*
/// governance publish.
fn seed_one_parquet_file() -> (TempDir, String) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let parquet_path = tmp.path().join("seed.parquet");

    let schema = Arc::new(Schema::new(vec![
        Field::new("id", DataType::Int32, false),
        Field::new("name", DataType::Utf8, false),
    ]));
    let batch = RecordBatch::try_new(
        Arc::clone(&schema),
        vec![
            Arc::new(Int32Array::from(vec![1, 2, 3])),
            Arc::new(StringArray::from(vec!["a", "b", "c"])),
        ],
    )
    .expect("build seed batch");

    let file = File::create(&parquet_path).expect("create parquet file");
    let mut writer = ArrowWriter::try_new(file, schema, Some(WriterProperties::builder().build()))
        .expect("ArrowWriter");
    writer.write(&batch).expect("write seed batch");
    writer.close().expect("finalize parquet");

    let posix_path = parquet_path.display().to_string().replace('\\', "/");
    let url = format!("file:///{}", posix_path.trim_start_matches('/'));
    (tmp, url)
}

fn object_storage_catalog(seed_url: &str, table_name: &str) -> CatalogConfig {
    CatalogConfig::ObjectStorage(ObjectStorageCatalogConfig {
        s3: None,
        tables: vec![ObjectStorageTableConfig {
            name: table_name.into(),
            url: seed_url.into(),
            format: ObjectStorageFormat::Parquet,
            schema: None,
        }],
    })
}

/// End-to-end: `DataglotServer::new` walks the configured catalog
/// bindings and POSTs one `MetadataChangeProposal` per catalog to
/// the configured governance publisher. Per the spec's exit
/// criterion every binding publishes within ~5 s of boot
/// completing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn server_boot_publishes_one_mcp_per_configured_catalog() {
    let backend = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/aspects"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&backend)
        .await;

    let pg_port = ephemeral_port();
    let metrics_port = ephemeral_port();
    let metrics_addr: SocketAddr = format!("127.0.0.1:{metrics_port}").parse().unwrap();

    let (_tmp, seed_url) = seed_one_parquet_file();

    let mut catalogs: HashMap<String, CatalogConfig> = HashMap::new();
    catalogs.insert(
        "fs_a".to_string(),
        object_storage_catalog(&seed_url, "table_a"),
    );
    catalogs.insert(
        "fs_b".to_string(),
        object_storage_catalog(&seed_url, "table_b"),
    );
    catalogs.insert(
        "fs_c".to_string(),
        object_storage_catalog(&seed_url, "table_c"),
    );

    let config = ServerConfig {
        host: "127.0.0.1".to_string(),
        port: pg_port,
        observability: ObservabilityConfig {
            metrics_addr: Some(metrics_addr),
            health_check_enabled: true,
            ..ObservabilityConfig::default()
        },
        catalogs,
        governance_publishers: vec![GovernancePublisherConfig::Datahub {
            gms_endpoint: backend.uri(),
            bearer_token_env: None,
        }],
        ..ServerConfig::default()
    };

    // `DataglotServer::new` is what runs the boot publish — the
    // assertion below already holds before we ever call run().
    let _server = DataglotServer::new(config)
        .await
        .expect("server boots with governance_publishers config");

    // Spec: "exactly one MCP POST lands on the configured GMS
    // endpoint within 5 s of boot completing". The current impl
    // awaits `publish_all_bindings` serially in `new`, so by the
    // time `new` returns the POSTs have landed. We poll up to 5s
    // to stay resilient if that ever becomes `tokio::spawn`-ed.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let mut received: Vec<Value> = Vec::new();
    while std::time::Instant::now() < deadline {
        let captured = backend.received_requests().await.unwrap_or_default();
        received = captured
            .iter()
            .filter_map(|r: &Request| serde_json::from_slice::<Value>(&r.body).ok())
            .collect();
        if received.len() >= 3 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(
        received.len(),
        3,
        "expected exactly 3 MCP POSTs (one per catalog), got {}",
        received.len()
    );

    // Pin each POST's outer MCP shape.
    for payload in &received {
        let proposal = &payload["proposal"];
        assert_eq!(proposal["entityType"], "dataset");
        assert_eq!(proposal["changeType"], "UPSERT");
        assert_eq!(proposal["aspectName"], "schemaMetadata");
        assert!(
            proposal["entityUrn"]
                .as_str()
                .is_some_and(|s| s.starts_with("urn:li:dataset:")),
            "expected LinkedIn URN, got {:?}",
            proposal["entityUrn"]
        );
    }

    // Pin the catalog-level sentinel flows through to the wire so
    // a Phase 2 swap to real per-table breakdown surfaces as a
    // failing assertion.
    let urns: Vec<String> = received
        .iter()
        .filter_map(|p| p["proposal"]["entityUrn"].as_str().map(str::to_string))
        .collect();
    for urn in &urns {
        assert!(
            urn.contains("_catalog._catalog"),
            "Phase 1 publishes catalog-level sentinel in the URN; got {urn}"
        );
    }
    let urn_set: std::collections::HashSet<&str> = urns.iter().map(String::as_str).collect();
    assert_eq!(
        urn_set.len(),
        3,
        "each catalog must produce a distinct URN; got {urns:?}"
    );
}

/// Phase 1 must stay bit-identical to pre-slice-3 behaviour when
/// no `governance_publishers` are configured — no POSTs fire,
/// `DataglotServer::new` does not reach any HTTP backend, server
/// boots fine.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn server_boot_without_governance_publishers_fires_no_posts() {
    // Backend that fails every request — proves we never hit it.
    let backend = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&backend)
        .await;

    let pg_port = ephemeral_port();
    let (_tmp, seed_url) = seed_one_parquet_file();

    let mut catalogs: HashMap<String, CatalogConfig> = HashMap::new();
    catalogs.insert("fs".to_string(), object_storage_catalog(&seed_url, "tbl"));

    let config = ServerConfig {
        host: "127.0.0.1".to_string(),
        port: pg_port,
        catalogs,
        // governance_publishers is intentionally Default = empty.
        ..ServerConfig::default()
    };

    let _server = DataglotServer::new(config)
        .await
        .expect("server boots without governance_publishers");

    tokio::time::sleep(Duration::from_millis(200)).await;

    let received = backend.received_requests().await.unwrap_or_default();
    assert!(
        received.is_empty(),
        "no governance publisher configured, but {} POSTs landed",
        received.len()
    );
}

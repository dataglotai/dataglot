//! Phase 1 · `OpenLineage` emitter MVP — slice 5 end-to-end test.
//!
//! Spec: the phase-1 `openlineage-emitter` plan.
//!
//! What's covered here that other tests don't cover individually:
//!
//! - Slice 2 (`dataglot-server::lineage::tests::http_emitter_*`) pins
//!   the `OpenLineage` JSON wire shape against a real `reqwest::Client`
//!   driving a `wiremock` backend.
//! - Slice 3 (`dataglot-pgwire::observer::tests`) pins the
//!   `QueryObserver` trait + `CompositeQueryObserver` fan-out and the
//!   shared-`run_id` invariant.
//! - Slice 4 (`dataglot-server::lineage::tests::lineage_observer_*`)
//!   pins the `LineageObserver` bridge — spawning the emitter task,
//!   extracting inputs from the per-connection `SessionContext`.
//!
//! This test joins all of those: it boots a real `DataglotServer`
//! with a `lineage` config block pointing at a `wiremock` backend,
//! runs simple-query SQL through pgwire via `tokio-postgres`, and
//! asserts the backend received both a `START` and a `COMPLETE`
//! `OpenLineage` event with matching `run.runId`. If anyone ever
//! forgets to wire `LineageObserver` into the pgwire path, or breaks
//! the `CompositeQueryObserver` plumbing, this test fails.
//!
//! Why not Docker-gated against Marquez: per the slice-5 spec the
//! Marquez container variant was considered. wiremock covers the
//! protocol-level integration without Docker; the operator-facing
//! Marquez UI check is a deferred follow-up. Keeping this in-process
//! means the test runs on every `cargo test --workspace` and stays in
//! the fast pre-PR gate (rather than the Docker-gated `--ignored`
//! tier).

use std::net::SocketAddr;
use std::time::Duration;

use dataglot_server::config::{LineageConfig, ServerConfig};
use dataglot_server::observability::ObservabilityConfig;
use dataglot_server::server::DataglotServer;
use serde_json::Value;
use tokio_postgres::NoTls;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

/// Reserve an ephemeral port and return it; the caller re-binds. There
/// is a small race window between drop and re-bind but it's tolerable
/// for tests.
fn ephemeral_port() -> u16 {
    //: delegate to the shared, race-hardened helper.
    dataglot_test_support::reserve_loopback_port()
}

/// Wait until the pgwire listener answers. Each retry is cheap; the
/// loop bounds total wait at ~5s.
async fn wait_until_pgwire_ready(pg_port: u16) {
    let pg_conn_str = format!("host=127.0.0.1 port={pg_port} user=dataglot dbname=dataglot");
    for _ in 0..50 {
        if tokio_postgres::connect(&pg_conn_str, NoTls).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("server did not become ready on pg={pg_port}");
}

/// End-to-end: a `DataglotServer` booted with a `lineage` config block
/// POSTs `START` + `COMPLETE` `OpenLineage` events to the configured
/// endpoint for every pgwire query. The two events share a `run.runId`
/// (per the slice-3 trait extension), and the `COMPLETE` event reports
/// `eventType=COMPLETE` for a successful query.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pgwire_query_emits_start_and_complete_to_lineage_backend() {
    // Stand up the wiremock backend first; we need its URL in the
    // server's config.
    let backend = MockServer::start().await;
    // Match every POST to /api/v1/lineage and respond 201. We assert
    // on captured requests *after* the test runs queries — letting
    // wiremock record everything is simpler than building per-event
    // mocks.
    Mock::given(method("POST"))
        .and(path("/api/v1/lineage"))
        .respond_with(ResponseTemplate::new(201))
        .mount(&backend)
        .await;

    let pg_port = ephemeral_port();
    let metrics_port = ephemeral_port();
    let metrics_addr: SocketAddr = format!("127.0.0.1:{metrics_port}").parse().unwrap();

    let config = ServerConfig {
        host: "127.0.0.1".to_string(),
        port: pg_port,
        observability: ObservabilityConfig {
            metrics_addr: Some(metrics_addr),
            health_check_enabled: true,
            ..ObservabilityConfig::default()
        },
        lineage: Some(LineageConfig::OpenlineageHttp {
            endpoint: format!("{}/api/v1/lineage", backend.uri()),
            namespace: "dataglot.test".to_string(),
        }),
        ..ServerConfig::default()
    };

    let server = DataglotServer::new(config)
        .await
        .expect("server boots with lineage config");

    let server_handle = tokio::spawn(async move {
        server.run().await.expect("server runs");
    });

    wait_until_pgwire_ready(pg_port).await;

    // Run one successful simple query through tokio-postgres.
    let conn_str = format!("host=127.0.0.1 port={pg_port} user=dataglot dbname=dataglot");
    let (client, connection) = tokio_postgres::connect(&conn_str, NoTls)
        .await
        .expect("pgwire connect");
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("pgwire driver: {e}");
        }
    });

    let rows = client
        .simple_query("SELECT 1 as v")
        .await
        .expect("simple SELECT succeeds");
    assert!(
        !rows.is_empty(),
        "simple query yields at least CommandComplete"
    );

    // Drop the client so the per-connection task drains. The
    // LineageObserver fires the emitter on `tokio::spawn`-ed tasks,
    // so we need a tick after drop for them to land.
    drop(client);
    tokio::time::sleep(Duration::from_millis(250)).await;

    // Inspect the captured requests. The query should have produced
    // exactly one START and one COMPLETE event with matching run id.
    let received = backend.received_requests().await.unwrap_or_default();

    let payloads: Vec<Value> = received
        .iter()
        .filter_map(|r: &Request| serde_json::from_slice::<Value>(&r.body).ok())
        .collect();

    assert!(
        payloads.len() >= 2,
        "expected at least START + COMPLETE events, got {}\npayloads: {:?}",
        payloads.len(),
        payloads
    );

    let starts: Vec<&Value> = payloads
        .iter()
        .filter(|p| p["eventType"] == "START")
        .collect();
    let completes: Vec<&Value> = payloads
        .iter()
        .filter(|p| p["eventType"] == "COMPLETE")
        .collect();

    assert_eq!(
        starts.len(),
        1,
        "expected exactly one START event, got {}\npayloads: {:?}",
        starts.len(),
        payloads
    );
    assert_eq!(
        completes.len(),
        1,
        "expected exactly one COMPLETE event, got {}\npayloads: {:?}",
        completes.len(),
        payloads
    );

    // Pin the shared-run-id invariant from slice 3. START and
    // COMPLETE for the same query must share `run.runId` — that's how
    // the OpenLineage backend correlates them in its UI.
    let start_run_id = starts[0]["run"]["runId"].as_str().expect("START runId");
    let complete_run_id = completes[0]["run"]["runId"]
        .as_str()
        .expect("COMPLETE runId");
    assert_eq!(
        start_run_id, complete_run_id,
        "START and COMPLETE must share runId"
    );

    // Pin the configured namespace flows through to the wire.
    assert_eq!(starts[0]["job"]["namespace"], "dataglot.test");
    assert_eq!(completes[0]["job"]["namespace"], "dataglot.test");

    // Tear down the server task.
    server_handle.abort();
    let _ = server_handle.await;
}

/// A failed query (garbled SQL) produces a `FAIL` event with an
/// `errorMessage` facet — not a missing event and not a `COMPLETE`.
/// Pins the slice-2 `outcome → eventType` mapping end-to-end.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pgwire_failed_query_emits_fail_event_to_lineage_backend() {
    let backend = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/lineage"))
        .respond_with(ResponseTemplate::new(201))
        .mount(&backend)
        .await;

    let pg_port = ephemeral_port();
    let metrics_port = ephemeral_port();
    let metrics_addr: SocketAddr = format!("127.0.0.1:{metrics_port}").parse().unwrap();

    let config = ServerConfig {
        host: "127.0.0.1".to_string(),
        port: pg_port,
        observability: ObservabilityConfig {
            metrics_addr: Some(metrics_addr),
            health_check_enabled: true,
            ..ObservabilityConfig::default()
        },
        lineage: Some(LineageConfig::OpenlineageHttp {
            endpoint: format!("{}/api/v1/lineage", backend.uri()),
            namespace: "dataglot.test".to_string(),
        }),
        ..ServerConfig::default()
    };

    let server = DataglotServer::new(config)
        .await
        .expect("server boots with lineage config");
    let server_handle = tokio::spawn(async move {
        server.run().await.expect("server runs");
    });

    wait_until_pgwire_ready(pg_port).await;

    let conn_str = format!("host=127.0.0.1 port={pg_port} user=dataglot dbname=dataglot");
    let (client, connection) = tokio_postgres::connect(&conn_str, NoTls)
        .await
        .expect("pgwire connect");
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("pgwire driver: {e}");
        }
    });

    // Garbled SQL → Error outcome → FAIL event.
    let bad = client.simple_query("SELEC 1").await;
    assert!(bad.is_err(), "garbled SQL must error at the wire");

    drop(client);
    tokio::time::sleep(Duration::from_millis(250)).await;

    let received = backend.received_requests().await.unwrap_or_default();
    let payloads: Vec<Value> = received
        .iter()
        .filter_map(|r: &Request| serde_json::from_slice::<Value>(&r.body).ok())
        .collect();

    let fails: Vec<&Value> = payloads
        .iter()
        .filter(|p| p["eventType"] == "FAIL")
        .collect();
    let completes: Vec<&Value> = payloads
        .iter()
        .filter(|p| p["eventType"] == "COMPLETE")
        .collect();

    assert_eq!(
        fails.len(),
        1,
        "expected exactly one FAIL event, got {}\npayloads: {:?}",
        fails.len(),
        payloads
    );
    assert!(
        completes.is_empty(),
        "failed query must not emit COMPLETE; got {} COMPLETE\npayloads: {:?}",
        completes.len(),
        payloads
    );

    // The FAIL event must carry the errorMessage facet with a
    // non-empty `message` field — operators rely on this to surface
    // failure reason in the run-history UI.
    let err_facet = &fails[0]["run"]["facets"]["errorMessage"];
    assert!(
        err_facet.is_object(),
        "expected errorMessage facet on FAIL event, got {fails:?}"
    );
    assert!(
        err_facet["message"].as_str().is_some_and(|s| !s.is_empty()),
        "errorMessage.message must be non-empty, got {err_facet:?}"
    );

    server_handle.abort();
    let _ = server_handle.await;
}

/// When the lineage backend is unreachable (no listener at the
/// configured URL), the query path must still succeed end-to-end.
/// Pins the slice-2 failure-isolation contract at the full wire
/// integration level — a lineage outage MUST NOT propagate to the
/// pgwire client.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pgwire_query_succeeds_when_lineage_backend_is_unreachable() {
    let pg_port = ephemeral_port();
    let metrics_port = ephemeral_port();
    let metrics_addr: SocketAddr = format!("127.0.0.1:{metrics_port}").parse().unwrap();

    // Point lineage at an unbound port on loopback — every emit
    // attempt will hit connection-refused. The emitter swallows this
    // (logs at WARN, drops the event) and the query path stays green.
    let config = ServerConfig {
        host: "127.0.0.1".to_string(),
        port: pg_port,
        observability: ObservabilityConfig {
            metrics_addr: Some(metrics_addr),
            health_check_enabled: true,
            ..ObservabilityConfig::default()
        },
        lineage: Some(LineageConfig::OpenlineageHttp {
            endpoint: "http://127.0.0.1:1/api/v1/lineage".to_string(),
            namespace: "dataglot.test".to_string(),
        }),
        ..ServerConfig::default()
    };

    let server = DataglotServer::new(config)
        .await
        .expect("server boots with lineage config");
    let server_handle = tokio::spawn(async move {
        server.run().await.expect("server runs");
    });

    wait_until_pgwire_ready(pg_port).await;

    let conn_str = format!("host=127.0.0.1 port={pg_port} user=dataglot dbname=dataglot");
    let (client, connection) = tokio_postgres::connect(&conn_str, NoTls)
        .await
        .expect("pgwire connect");
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("pgwire driver: {e}");
        }
    });

    // The query must succeed even though the lineage backend is
    // unreachable. This is the contract pinned by the slice-2
    // `http_emitter_swallows_connection_refused` test, but at the
    // server-integration level.
    let rows = client
        .simple_query("SELECT 1 as v")
        .await
        .expect("simple SELECT succeeds despite lineage backend outage");
    assert!(!rows.is_empty());

    drop(client);
    server_handle.abort();
    let _ = server_handle.await;
}

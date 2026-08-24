//! Integration test for the metrics HTTP server.
//!
//! Boots the metrics endpoint on an OS-assigned port, scrapes `/metrics` and
//! `/health` over real TCP via `reqwest`, and asserts the response is a
//! well-formed Prometheus exposition that contains every metric family we
//! registered.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::sync::broadcast;

use dataglot_server::observability::{build_router, spawn_metrics_server, Metrics};

/// Pick an ephemeral port without leaking the listener to the OS afterwards.
async fn ephemeral_addr() -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    addr
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn metrics_endpoint_serves_well_formed_prometheus_text() {
    let metrics = Metrics::new().expect("metrics registration");
    // Pre-populate so we can assert non-zero values flow through to the wire.
    metrics
        .queries_total
        .with_label_values(&["pgwire", "success"])
        .inc_by(7);
    metrics.pgwire_connections_active.set(2);
    metrics
        .query_duration_seconds
        .with_label_values(&["pgwire"])
        .observe(0.42);

    let addr = ephemeral_addr().await;
    let (shutdown_tx, shutdown_rx) = broadcast::channel::<()>(1);

    let handle = spawn_metrics_server(
        addr,
        metrics.clone(),
        true,
        &dataglot_server::lineage_snapshot::LineageSnapshot::default(),
        dataglot_server::query_registry::QueryRegistry::new(),
        dataglot_server::session_registry::SessionRegistry::new(),
        dataglot_server::cluster::ClusterMonitor::new(None),
        dataglot_server::connectors::ConnectorMonitor::empty(),
        dataglot_server::materialization_registry::MaterializationRegistry::empty(),
        dataglot_server::maintenance_registry::MaintenanceRegistry::empty(),
        dataglot_server::observability::ServerInfo::for_tests(),
        None,
        shutdown_rx,
    )
    .await
    .expect("spawn metrics server");

    // Give axum::serve a moment to actually start accepting.
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();

    // Tiny retry loop so this test isn't flaky on slow machines.
    let url = format!("http://{addr}/metrics");
    let mut last_err = None;
    let mut body = String::new();
    let mut content_type = String::new();
    for _ in 0..20 {
        match client.get(&url).send().await {
            Ok(resp) => {
                assert_eq!(resp.status(), reqwest::StatusCode::OK);
                content_type = resp
                    .headers()
                    .get(reqwest::header::CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or_default()
                    .to_string();
                body = resp.text().await.unwrap();
                last_err = None;
                break;
            }
            Err(e) => {
                last_err = Some(e);
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }
    if let Some(err) = last_err {
        panic!("Failed to scrape /metrics after retries: {err}");
    }

    assert!(
        content_type.starts_with("text/plain"),
        "unexpected Content-Type: {content_type}"
    );

    // All four registered metric families must be present.
    for needle in [
        "dataglot_queries_total",
        "dataglot_query_duration_seconds",
        "dataglot_pgwire_connections_active",
        "dataglot_uptime_seconds",
    ] {
        assert!(
            body.contains(needle),
            "metric {needle} missing from /metrics body:\n{body}"
        );
    }

    // Prometheus text format requires HELP/TYPE comments before each family.
    assert!(body.contains("# HELP dataglot_queries_total"));
    assert!(body.contains("# TYPE dataglot_queries_total counter"));
    assert!(body.contains("# TYPE dataglot_query_duration_seconds histogram"));
    assert!(body.contains("# TYPE dataglot_pgwire_connections_active gauge"));

    // Pre-populated values must round-trip.
    assert!(body.contains("dataglot_pgwire_connections_active 2"));
    assert!(body.contains("dataglot_queries_total{outcome=\"success\",protocol=\"pgwire\"} 7"));

    // Histograms emit a _count line; we observed exactly one sample.
    assert!(body.contains("dataglot_query_duration_seconds_count{protocol=\"pgwire\"} 1"));

    // /health must respond 200 with the documented body.
    let health_url = format!("http://{addr}/health");
    let health = client.get(&health_url).send().await.unwrap();
    assert_eq!(health.status(), reqwest::StatusCode::OK);
    let health_body = health.text().await.unwrap();
    assert_eq!(health_body, r#"{"status":"ok"}"#);

    // Unknown paths must 404, not leak the metric body.
    let other = client
        .get(format!("http://{addr}/admin"))
        .send()
        .await
        .unwrap();
    assert_eq!(other.status(), reqwest::StatusCode::NOT_FOUND);

    // Graceful shutdown.
    shutdown_tx.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(5), handle)
        .await
        .expect("metrics server task should drain on shutdown")
        .expect("task should not panic");
}

#[tokio::test]
async fn router_uses_prometheus_text_content_type() {
    // Smoke check that the in-process axum router (no real socket) produces
    // a Content-Type acceptable to a Prometheus scraper.
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    let metrics = Metrics::new().unwrap();
    let app = build_router(
        metrics,
        true,
        &dataglot_server::lineage_snapshot::LineageSnapshot::default(),
        dataglot_server::query_registry::QueryRegistry::new(),
        dataglot_server::session_registry::SessionRegistry::new(),
        dataglot_server::cluster::ClusterMonitor::new(None),
        dataglot_server::connectors::ConnectorMonitor::empty(),
        dataglot_server::materialization_registry::MaterializationRegistry::empty(),
        dataglot_server::maintenance_registry::MaintenanceRegistry::empty(),
        dataglot_server::observability::ServerInfo::for_tests(),
    );

    let response = app
        .oneshot(
            Request::builder()
                .uri("/metrics")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let ct = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    assert!(ct.contains("text/plain"));
    assert!(ct.contains("version=0.0.4"));
}

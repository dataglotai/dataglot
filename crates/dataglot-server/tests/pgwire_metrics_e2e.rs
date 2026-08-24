//! Phase 0.5 · Task 03 — full e2e for the pgwire → `MetricsObserver` → /metrics
//! chain.
//!
//! Spec: `docs/phases/phase-0.5/03-pgwire-query-observer-hook.md`.
//!
//! What's tested here that the other tests don't cover individually:
//!
//! - `dataglot-pgwire/src/observer.rs` unit tests prove the trait fires.
//! - `dataglot-tests/tests/e2e/pgwire_observer.rs` proves the hook fires
//!   over real TCP via a `CountingObserver` fixture.
//! - `dataglot-server/src/server.rs::metrics_observer_increments_counters`
//!   proves the production `MetricsObserver` impl bumps the right counters.
//! - `dataglot-server/tests/observability.rs` proves a populated
//!   `Metrics` instance reaches `/metrics`.
//!
//! This test joins all of those: it boots a real `DataglotServer`, runs
//! a mix of success and error queries through tokio-postgres, scrapes
//! `/metrics`, and asserts the counters reflect the runs. If anyone
//! ever forgets to wire `MetricsObserver` into the pgwire path, this
//! test fails.

use std::net::SocketAddr;
use std::time::Duration;

use dataglot_server::config::ServerConfig;
use dataglot_server::observability::ObservabilityConfig;
use dataglot_server::server::DataglotServer;
use tokio_postgres::NoTls;

/// Reserve an ephemeral port and return it; the caller re-binds. There
/// is a small race window between drop and re-bind but it's tolerable
/// for tests.
fn ephemeral_port() -> u16 {
    //: delegate to the shared, race-hardened helper.
    dataglot_test_support::reserve_loopback_port()
}

/// Wait until both the pgwire and `/metrics` listeners answer. Each
/// retry is cheap; the loop bounds total wait at ~5 s.
async fn wait_until_ready(pg_port: u16, metrics_addr: SocketAddr) {
    let pg_conn_str = format!("host=127.0.0.1 port={pg_port} user=dataglot dbname=dataglot");
    let metrics_url = format!("http://{metrics_addr}/metrics");
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap();

    for _ in 0..50 {
        let pg_ok = tokio_postgres::connect(&pg_conn_str, NoTls).await.is_ok();
        let metrics_ok = http
            .get(&metrics_url)
            .send()
            .await
            .is_ok_and(|r| r.status().is_success());
        if pg_ok && metrics_ok {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("server did not become ready on pg={pg_port} metrics={metrics_addr}");
}

/// Boot a real `DataglotServer` on ephemeral ports, run a mix of
/// queries through tokio-postgres, scrape `/metrics`, and assert the
/// counters reflect the runs end-to-end.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pgwire_queries_increment_metrics_visible_at_metrics_endpoint() {
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
        ..ServerConfig::default()
    };

    let server = DataglotServer::new(config)
        .await
        .expect("server boots with default config");
    let shutdown = server.shutdown_receiver();
    drop(shutdown);

    // Spawn the server in a background task. `run` blocks until
    // shutdown so we can't `.await` it inline.
    let server_handle = tokio::spawn(async move {
        server.run().await.expect("server runs");
    });

    wait_until_ready(pg_port, metrics_addr).await;

    // Connect via tokio-postgres and exercise both outcomes through
    // the simple-query path (the extended path returns syntax errors
    // during Parse, which fires before our observer).
    let conn_str = format!("host=127.0.0.1 port={pg_port} user=dataglot dbname=dataglot");
    let (client, connection) = tokio_postgres::connect(&conn_str, NoTls)
        .await
        .expect("pgwire connect");
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("pgwire driver: {e}");
        }
    });

    // Three successful simple queries.
    for _ in 0..3 {
        let rows = client
            .simple_query("SELECT 1 as v")
            .await
            .expect("simple SELECT succeeds");
        // simple_query returns a Vec<SimpleQueryMessage>; just sanity
        // check that we got something back.
        assert!(
            !rows.is_empty(),
            "simple query yields at least CommandComplete"
        );
    }

    // One garbled simple query → Error outcome.
    let bad = client.simple_query("SELEC 1").await;
    assert!(bad.is_err(), "garbled SQL must error");

    // Drop the client so the connection task drains and the observer
    // calls finalise before we scrape.
    drop(client);
    tokio::time::sleep(Duration::from_millis(150)).await;

    // Scrape /metrics and parse the relevant lines.
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap();
    let body = http
        .get(format!("http://{metrics_addr}/metrics"))
        .send()
        .await
        .expect("metrics scrape")
        .text()
        .await
        .expect("metrics body");

    // Helper: pluck a counter line value, e.g.
    // `dataglot_queries_total{outcome="success",protocol="pgwire"} 3`.
    let extract = |line_starts_with: &str| -> Option<u64> {
        for line in body.lines() {
            if line.starts_with(line_starts_with) {
                return line.split_whitespace().last().and_then(|s| s.parse().ok());
            }
        }
        None
    };

    let success = extract(r#"dataglot_queries_total{outcome="success",protocol="pgwire"}"#)
        .expect("success counter present");
    let errored = extract(r#"dataglot_queries_total{outcome="error",protocol="pgwire"}"#)
        .expect("error counter present");
    assert!(
        success >= 3,
        "expected >= 3 success queries reflected at /metrics, got {success}\n\nbody:\n{body}"
    );
    assert!(
        errored >= 1,
        "expected >= 1 error queries reflected at /metrics, got {errored}\n\nbody:\n{body}"
    );

    // Histogram: at least 4 samples (3 success + 1 error).
    let hist_count = extract(r#"dataglot_query_duration_seconds_count{protocol="pgwire"}"#)
        .expect("histogram count line present");
    assert!(
        hist_count >= 4,
        "expected >= 4 histogram samples, got {hist_count}\n\nbody:\n{body}"
    );

    // Tear down the server task. There's no public shutdown handle on
    // a `DataglotServer` after `run()` consumed it, so abort the task
    // and let the process clean up the listener.
    server_handle.abort();
    let _ = server_handle.await;
}

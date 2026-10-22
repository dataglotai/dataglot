//! `dataglot ops` against a real `DataglotServer` and its HTTP API.

use std::net::SocketAddr;
use std::process::ExitCode;
use std::time::Duration;

use clap::Parser;
use dataglot_server::cli::{Args, Command, OutputFormat};
use dataglot_server::client::RemoteSession;
use dataglot_server::config::ServerConfig;
use dataglot_server::observability::ObservabilityConfig;
use dataglot_server::ops;
use dataglot_server::server::DataglotServer;

/// Run `dataglot ops <words...>` and return the exit code, stdout and stderr.
async fn ops(words: &[&str]) -> (ExitCode, String, String) {
    let parsed = Args::try_parse_from(["dataglot", "ops"].iter().chain(words)).expect("parse");
    let Some(Command::Ops(ops_args)) = parsed.command else {
        panic!("not an ops command");
    };
    let mut out = Vec::new();
    let mut err = Vec::new();
    let code = ops::run_with(&ops_args, &mut out, &mut err).await;
    (
        code,
        String::from_utf8(out).expect("utf-8 stdout"),
        String::from_utf8(err).expect("utf-8 stderr"),
    )
}

/// Boot a server with its HTTP API on a free port. Returns the pg-wire URL
/// and the API's base URL.
async fn boot() -> (String, String) {
    let pg_port = dataglot_test_support::reserve_loopback_port();
    let api_port = dataglot_test_support::reserve_loopback_port();
    let config = ServerConfig {
        host: "127.0.0.1".to_string(),
        port: pg_port,
        observability: ObservabilityConfig {
            metrics_addr: Some(SocketAddr::from(([127, 0, 0, 1], api_port))),
            ..ObservabilityConfig::default()
        },
        ..ServerConfig::default()
    };
    // Boxed so this future stays small (`clippy::large_futures`).
    let server = Box::pin(DataglotServer::new(config))
        .await
        .expect("server boots");
    tokio::spawn(async move {
        server.run().await.expect("server runs");
    });
    let api = format!("http://127.0.0.1:{api_port}");
    for _ in 0..50 {
        if ops(&["--api", &api, "status"]).await.0 == ExitCode::SUCCESS {
            return (format!("postgres://dataglot@127.0.0.1:{pg_port}"), api);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("the HTTP API at {api} did not come up");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ops_commands_read_a_running_server() {
    let (pg, api) = boot().await;
    let pg_port = pg.rsplit(':').next().expect("port");

    // status: one row per setting, nested ones dotted.
    let (code, out, err) = ops(&["--api", &api, "status"]).await;
    assert_eq!(code, ExitCode::SUCCESS, "{err}");
    assert!(out.contains("| security.auth_mode "), "{out}");
    assert!(out.contains("| execution_mode "), "{out}");

    // --format json is the server's own response.
    let (code, out, err) = ops(&["--api", &api, "status", "--format", "json"]).await;
    assert_eq!(code, ExitCode::SUCCESS, "{err}");
    let status: serde_json::Value = serde_json::from_str(&out).expect("valid JSON");
    assert_eq!(status["pgwire_port"].to_string(), pg_port);

    // No catalogs configured: a header and nothing else.
    let (code, out, err) = ops(&["--api", &api, "sources", "--format", "csv"]).await;
    assert_eq!(code, ExitCode::SUCCESS, "{err}");
    assert_eq!(out, "name,kind,registered,live,latency_ms,error\n");

    // A pg-wire session shows up, and so does a query it ran.
    let session = RemoteSession::connect(&pg).await.expect("connect");
    let mut sink = Vec::new();
    session
        .execute("SELECT 41 + 1 AS answer", OutputFormat::Csv, &mut sink)
        .await
        .expect("query");

    let (code, out, err) = ops(&["--api", &api, "sessions", "--format", "csv"]).await;
    assert_eq!(code, ExitCode::SUCCESS, "{err}");
    assert!(
        out.starts_with("session_id,user,org,peer,connected_for\n"),
        "{out}"
    );
    assert!(out.contains(",dataglot,"), "{out}");
    assert!(out.contains("127.0.0.1:"), "{out}");

    let (code, out, err) = ops(&["--api", &api, "queries", "history", "--format", "csv"]).await;
    assert_eq!(code, ExitCode::SUCCESS, "{err}");
    assert!(out.contains("SELECT 41 + 1 AS answer"), "{out}");

    // Nothing is running any more. `queries` and `queries list` are the same.
    for words in [
        ["--api", &api, "queries", "--format", "csv"].as_slice(),
        ["--api", &api, "queries", "list", "--format", "csv"].as_slice(),
    ] {
        let (code, out, err) = ops(words).await;
        assert_eq!(code, ExitCode::SUCCESS, "{err}");
        assert_eq!(out, "run_id,state,elapsed,user,sources,sql\n", "{words:?}");
    }

    // Without a catalog service there is no control plane endpoint.
    let (code, out, err) = ops(&["--api", &api, "control-plane"]).await;
    assert_eq!(code, ExitCode::FAILURE, "{err}");
    assert_eq!(out, "");
    assert!(err.contains("404"), "{err}");
    assert!(err.contains("without [catalog_service]"), "{err}");
}

#[tokio::test]
async fn nothing_listening_exits_2() {
    let port = dataglot_test_support::reserve_loopback_port();
    let api = format!("http://127.0.0.1:{port}");
    let (code, out, err) = ops(&["--api", &api, "status"]).await;
    assert_eq!(code, ExitCode::from(2), "{err}");
    assert_eq!(out, "");
    assert!(
        err.starts_with(&format!("error: could not reach {api}: ")),
        "{err}"
    );
}

#[tokio::test]
async fn an_api_url_without_scheme_is_refused() {
    let (code, _, err) = ops(&["--api", "localhost:9090", "status"]).await;
    assert_eq!(code, ExitCode::from(2), "{err}");
    assert!(err.contains("expected an http:// or https:// URL"), "{err}");
}

//! `dataglot ops` against a real `DataglotServer` and its HTTP endpoints.

use std::net::SocketAddr;
use std::process::ExitCode;
use std::time::Duration;

use clap::Parser;
use dataglot_server::cli::{Args, Command, OutputFormat};
use dataglot_server::client::{ClientError, RemoteSession};
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancel_stops_a_running_query() {
    let (pg, api) = boot().await;
    let session = RemoteSession::connect(&pg).await.expect("connect");
    let running = tokio::spawn(async move {
        let mut sink = Vec::new();
        session
            .execute(
                "SELECT count(*) FROM generate_series(1, 100000000000)",
                OutputFormat::Csv,
                &mut sink,
            )
            .await
    });

    // Find its run id the way a script would.
    let mut run_id = None;
    for _ in 0..50 {
        let (_, out, _) = ops(&["--api", &api, "queries", "--format", "json"]).await;
        let queries: serde_json::Value = serde_json::from_str(&out).expect("JSON");
        if let Some(id) = queries[0]["run_id"].as_str() {
            run_id = Some(id.to_string());
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let run_id = run_id.expect("the query shows up as running");

    let (code, out, err) = ops(&["--api", &api, "queries", "cancel", &run_id]).await;
    assert_eq!(code, ExitCode::SUCCESS, "{err}");
    assert_eq!(out, format!("Cancel sent to {run_id}.\n"));

    let result = tokio::time::timeout(Duration::from_secs(10), running)
        .await
        .expect("the query stopped")
        .expect("query task");
    assert!(
        matches!(result, Err(ClientError::Statement(_))),
        "{result:?}"
    );

    // Once it's gone there's nothing left to cancel.
    let (code, _, err) = ops(&["--api", &api, "queries", "cancel", &run_id]).await;
    assert_eq!(code, ExitCode::FAILURE, "{err}");
    assert!(err.contains("404"), "{err}");
}

/// A server with one CSV table and the policy-explain endpoint behind a
/// token. Returns the explain URL, the name of the variable holding the
/// token, and the temp dir keeping the files alive.
async fn boot_with_explain() -> (String, String, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let csv = dir.path().join("users.csv");
    std::fs::write(&csv, "id,email\n1,alice@acme.com\n").expect("write csv");
    let pg_port = dataglot_test_support::reserve_loopback_port();
    let explain_port = dataglot_test_support::reserve_loopback_port();
    // Unique per run, so nothing else in the process reads or writes it.
    let token_env = format!("DATAGLOT_OPS_E2E_TOKEN_{explain_port}");
    std::env::set_var(&token_env, "t0ken");
    let config_file = dir.path().join("dataglot.toml");
    std::fs::write(
        &config_file,
        format!(
            r#"
[catalogs.files]
kind = "object_storage"

[[catalogs.files.tables]]
name = "users"
url = "file://{csv}"
format = "csv"

[policy_explain]
addr = "127.0.0.1:{explain_port}"
token_env = "{token_env}"
"#,
            csv = csv.display(),
        ),
    )
    .expect("write config");
    let args = Args::try_parse_from([
        "dataglot",
        "--config",
        config_file.to_str().expect("utf-8 path"),
        "--host",
        "127.0.0.1",
        "--port",
        &pg_port.to_string(),
        "--metrics-addr",
        "off",
    ])
    .expect("parse");
    let config = ServerConfig::load(&args).expect("config loads");
    let server = Box::pin(DataglotServer::new(config))
        .await
        .expect("server boots");
    tokio::spawn(async move {
        server.run().await.expect("server runs");
    });
    let explain = format!("http://127.0.0.1:{explain_port}");
    for _ in 0..50 {
        if tokio::net::TcpStream::connect(("127.0.0.1", explain_port))
            .await
            .is_ok()
        {
            return (explain, token_env, dir);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("the policy-explain endpoint did not come up");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn policy_explain_uses_the_profile_and_its_token() {
    let (explain, token_env, dir) = boot_with_explain().await;
    let profiles = dir.path().join("cli.toml");
    std::fs::write(
        &profiles,
        format!(
            r#"
[profiles.with_token]
url = "postgres://127.0.0.1"
explain_url = "{explain}"
api_token_env = "{token_env}"

[profiles.without_token]
url = "postgres://127.0.0.1"
explain_url = "{explain}"

[profiles.sql_only]
url = "postgres://127.0.0.1"
"#
        ),
    )
    .expect("write profiles");
    // Only this test reads profiles, so setting this for the process is fine.
    std::env::set_var("DATAGLOT_CLI_CONFIG", &profiles);
    let sql = "SELECT email FROM files.public.users";

    let (code, out, err) = ops(&[
        "policy",
        "explain",
        "--user",
        "alice",
        sql,
        "--profile",
        "with_token",
        "--format",
        "csv",
    ])
    .await;
    assert_eq!(code, ExitCode::SUCCESS, "{err}");
    // What the decisions are is the endpoint's business (and its own
    // tests'); here it's enough that the token got the request through.
    assert!(out.starts_with("action,resource,detail\n"), "{out}");

    let (code, out, err) = ops(&["policy", "explain", sql, "--profile", "with_token"]).await;
    assert_eq!(code, ExitCode::SUCCESS, "{err}");
    assert!(
        out.starts_with("Policy decisions for anonymous session:\n"),
        "{out}"
    );

    // Without the token the endpoint refuses, and the message says where
    // the token goes.
    let (code, out, err) = ops(&["policy", "explain", sql, "--profile", "without_token"]).await;
    assert_eq!(code, ExitCode::FAILURE, "{err}");
    assert_eq!(out, "");
    assert!(err.contains("401"), "{err}");
    assert!(err.contains("DATAGLOT_API_TOKEN"), "{err}");

    // A profile that only knows pg-wire can't be used for ops.
    let (code, _, err) = ops(&["status", "--profile", "sql_only"]).await;
    assert_eq!(code, ExitCode::from(2), "{err}");
    assert!(err.contains("has no api_url"), "{err}");
}

#[tokio::test]
async fn explain_without_an_endpoint_says_what_to_check() {
    let port = dataglot_test_support::reserve_loopback_port();
    let explain = format!("http://127.0.0.1:{port}");
    let (code, _, err) = ops(&["--explain-api", &explain, "policy", "explain", "SELECT 1"]).await;
    assert_eq!(code, ExitCode::from(2), "{err}");
    assert!(err.contains("[policy_explain]"), "{err}");
}

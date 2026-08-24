//! `dataglot-ballista-executor` multi-process integration test —
//! Phase 2 slice 5a.2.
//!
//! Proof-of-life for the multi-process foundation:
//!
//! 1. Boot Postgres in a testcontainer (catalogs config target).
//! 2. Boot a Ballista scheduler in-process via `new_standalone_scheduler()`.
//! 3. Write valid `catalogs.json` + `credentials.json` files.
//! 4. Spawn `dataglot-ballista-executor` as a subprocess pointing
//!    at the scheduler, with the catalogs / credentials configs.
//! 5. Sleep briefly to let the registration handshake happen.
//! 6. Assert the executor process is still running (it didn't
//!    crash on resolver / catalogs / scheduler-connect boot paths).
//!
//! # What this test claims (and doesn't)
//!
//! - ✅ The binary boots end-to-end: parses CLI, loads
//!   credentials config (`StaticCredentialResolver` from JSON),
//!   loads catalogs config (real `PostgresConnector::connect` to
//!   the testcontainer), wires both into `ExecutorProcessConfig`,
//!   and hands off to `start_executor_process` without exiting.
//! - ✅ The binary actually reaches the scheduler's gRPC endpoint
//!   (it wouldn't stay alive if scheduler-connect failed at boot
//!   with `scheduler_connect_timeout_seconds = 0`).
//! - ❌ Full federation roundtrip through the multi-process pair.
//!   That requires a Ballista client `SessionContext` connecting
//!   to the in-process scheduler with the same codec wiring, then
//!   running a federation query that gets dispatched to the
//!   subprocess executor — slice 8's territory. The codec parity
//!   between scheduler and executor IS already exercised by
//!   `ballista_federation_codec.rs` (in-process standalone), so
//!   slice 5a.2's distinct claim is "the binary plumbing works,"
//!   not "federation works on the wire" (already proven).
//!
//! # Why not poll the scheduler's executor list?
//!
//! `new_standalone_scheduler()` returns a `SocketAddr` but no
//! handle to interrogate the scheduler's internal state.
//! "Executor is still running after 5 s" is a weaker but
//! sufficient signal — if the binary crashed on any boot path
//! (bad CLI parse, bad config, scheduler unreachable, etc.) it
//! would have exited well before then.
//!
//! # Docker requirement
//!
//! `#[ignore = "requires Docker"]` per the existing pattern. The
//! `ballista (Phase 2)` CI job runs with `--ignored` to exercise
//! it; PR-level ballista CI without Docker still benefits from
//! the unit tests in `src/{executor,catalogs_config}.rs` + the
//! `executor_binary_cli.rs` subprocess tests.

use std::net::TcpListener;
use std::time::Duration;

use ballista_scheduler::standalone::new_standalone_scheduler;
use testcontainers::runners::AsyncRunner;
use testcontainers::ContainerAsync;
use testcontainers_modules::postgres::Postgres;

/// Grab a free TCP port by binding to `127.0.0.1:0`, reading the
/// kernel-assigned port, and dropping the listener. Standard
/// race-condition-prone idiom; acceptable for tests where another
/// process snatching the port between us-dropping-it and the
/// binary-binding-it is highly unlikely.
fn pick_free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind 0");
    listener.local_addr().expect("local_addr").port()
}

async fn setup_postgres() -> ContainerAsync<Postgres> {
    Postgres::default()
        .start()
        .await
        .expect("postgres container starts")
}

#[tokio::test]
#[ignore = "requires Docker"]
async fn executor_binary_boots_and_stays_alive_against_real_scheduler() {
    let pg_container = setup_postgres().await;
    let pg_host = pg_container.get_host().await.expect("postgres host");
    let pg_port = pg_container
        .get_host_port_ipv4(5432)
        .await
        .expect("postgres port");
    let dsn =
        format!("host={pg_host} port={pg_port} user=postgres password=postgres dbname=postgres");

    // 2. Boot scheduler-only in-process. The scheduler stays alive
    //    for as long as this test's tokio runtime; the returned
    //    address is what the executor subprocess connects to.
    //
    // Ballista's `new_standalone_scheduler` binds to `localhost:0`
    // and returns the OS-assigned SocketAddr. On many CI runners
    // `localhost` resolves to IPv6 (`::1`) first, so the returned
    // IP can be IPv6 — passing `::1` unbracketed to the executor's
    // gRPC endpoint builder hits "Could not create endpoint to
    // scheduler" (URL parse failure). Print the address so future
    // failures are diagnostic, and bracket IPv6 hosts when handing
    // them to the binary.
    let scheduler_addr = new_standalone_scheduler()
        .await
        .expect("standalone scheduler boots");
    eprintln!("scheduler bound to {scheduler_addr}");
    let scheduler_host = match scheduler_addr.ip() {
        std::net::IpAddr::V4(ip) => ip.to_string(),
        std::net::IpAddr::V6(ip) => format!("[{ip}]"),
    };

    // 3. Build tempfiles for the two configs. Both stay alive for
    //    the duration of the test (RAII via `NamedTempFile`).
    let creds_file = tempfile::NamedTempFile::new().expect("creds tempfile");
    std::fs::write(creds_file.path(), br#"{"kind": "static", "entries": {}}"#)
        .expect("write creds");

    let catalogs_file = tempfile::NamedTempFile::new().expect("catalogs tempfile");
    let catalogs_json = serde_json::json!({
        "pg_main": { "type": "postgres", "dsn": dsn },
    })
    .to_string();
    std::fs::write(catalogs_file.path(), catalogs_json.as_bytes()).expect("write catalogs");

    // 4. Spawn the binary. `assert_cmd::cargo::cargo_bin` gives us
    //    the compiled binary path; we use `tokio::process::Command`
    //    rather than the sync `assert_cmd::Command` because we need
    //    `try_wait` + `kill` for the still-running check.
    let bin = assert_cmd::cargo::cargo_bin("dataglot-ballista-executor");
    let bind_port = pick_free_port();
    let bind_grpc_port = pick_free_port();

    let mut child = tokio::process::Command::new(&bin)
        .args([
            "--scheduler-host",
            &scheduler_host,
            "--scheduler-port",
            &scheduler_addr.port().to_string(),
            "--bind-host",
            "127.0.0.1",
            "--bind-port",
            &bind_port.to_string(),
            "--bind-grpc-port",
            &bind_grpc_port.to_string(),
            "--external-host",
            "127.0.0.1",
            "--concurrent-tasks",
            "1",
            "--credentials-config",
            creds_file.path().to_str().expect("creds path utf-8"),
            "--catalogs-config",
            catalogs_file.path().to_str().expect("catalogs path utf-8"),
            // Slice 7b default-deny: this multi-process integration
            // test runs against an in-process Ballista scheduler
            // (plaintext) and asserts the executor stays alive past
            // the registration handshake. TLS isn't part of the
            // surface under test here; opt out explicitly.
            "--insecure",
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn executor binary");

    // 5. Sleep briefly for the registration handshake. Five
    //    seconds covers a cold tokio-postgres connect to the
    //    testcontainer + the Ballista gRPC handshake with margin.
    tokio::time::sleep(Duration::from_secs(5)).await;

    // 6. Assert still running. `try_wait` returns `Ok(None)` if the
    //    process is still alive; `Ok(Some(status))` if it exited.
    let exit_status = child.try_wait().expect("try_wait");
    let kill_result = child.kill().await;
    let _ = child.wait().await;

    if let Some(status) = exit_status {
        // Read any stderr the failed child emitted, for diagnostics.
        let stderr_bytes = {
            use tokio::io::AsyncReadExt;
            let mut buf = Vec::new();
            if let Some(mut s) = child.stderr.take() {
                let _ = s.read_to_end(&mut buf).await;
            }
            buf
        };
        let stderr = String::from_utf8_lossy(&stderr_bytes);
        panic!("executor binary exited early with {status:?}; stderr:\n{stderr}");
    }
    kill_result.expect("kill executor");

    // Hold the container alive until here so the executor's
    // connection survives the full test window.
    drop(pg_container);
}

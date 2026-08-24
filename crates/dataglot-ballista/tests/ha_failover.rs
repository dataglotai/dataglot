//! Scheduler HA failover e2e —  item 2.
//!
//! `scheduler_death.rs` proves a *single* scheduler's death yields a bounded
//! typed client error. `ha.rs` unit-tests the lease/election state machine.
//! Neither exercises the whole thing at the process level: **two scheduler
//! processes contending for one lease, the leader killed, the standby
//! promoting and serving a query.** That's the slice-5b HA promise end to
//! end, and this is the test that pins it.
//!
//! Backend: a **`MinIO`** container as the S3-compatible lease store. The
//! `file://`/`memory://` object stores can't back the lease (no conditional
//! `PutMode::Update` / not shared across processes — see the
//! `reject_unsupported_ha_scheme` guard), so a real shared S3 endpoint is
//! required. The schedulers reach it via the standard `AWS_*` environment
//! (`AWS_ENDPOINT` → `MinIO`), which is exactly the on-prem S3 path
//! `run_scheduler_ha` builds the lease store from.
//!
//! Shape:
//!   - `MinIO` up; a `dataglot` bucket created (via the `mc` bundled in the
//!     image).
//!   - Two `dataglot-ballista-scheduler` processes share
//!     `s3://dataglot/scheduler-lease.json`. Distinct bind ports.
//!   - A wins the lease and binds; B blocks in the claim loop (standby — it
//!     does *not* bind its port yet).
//!   - A client query against A succeeds (baseline).
//!   - Kill A. After the lease expires, B claims it and binds.
//!   - A fresh client (pointed at B — a VIP would do this in production) runs
//!     the same query and it succeeds: the standby promoted and serves.
//!
//! Short lease (3 s) / heartbeat (1 s) keep the failover window tight.
//! `#[ignore]` (Docker + four subprocesses + a failover window); the
//! `ballista (Phase 2)` CI job runs it with `--ignored`.

#![allow(clippy::too_many_lines)] // linear failover scenario; child lifetimes pin the flow

use std::time::Duration;

use ballista::datafusion::prelude::{ParquetReadOptions, SessionContext};
use ballista_core::extension::SessionStateExt;
use dataglot_ballista::BallistaContextFactory;
use testcontainers::core::ExecCommand;
use testcontainers::runners::AsyncRunner;
use testcontainers_modules::minio::MinIO;

const MINIO_USER: &str = "minioadmin";
const MINIO_PASSWORD: &str = "minioadmin";
const LEASE_BUCKET: &str = "dataglot";

/// Allocate `n` *distinct* free ports. Binds all `n` listeners at once (so the
/// OS can't hand back the same port twice — a real hazard when two scheduler
/// ports, or an executor's bind + flight ports, collide) then releases them.
fn free_ports(n: usize) -> Vec<u16> {
    let listeners: Vec<std::net::TcpListener> = (0..n)
        .map(|_| std::net::TcpListener::bind("127.0.0.1:0").expect("bind 0"))
        .collect();
    listeners
        .iter()
        .map(|l| l.local_addr().expect("addr").port())
        .collect()
}

fn seed_parquet(dir: &std::path::Path) -> std::path::PathBuf {
    use ballista::datafusion::arrow::array::{Int64Array, RecordBatch};
    use ballista::datafusion::arrow::datatypes::{DataType, Field, Schema};
    use parquet::arrow::ArrowWriter;
    use std::sync::Arc;

    let path = dir.join("nums.parquet");
    let schema = Arc::new(Schema::new(vec![Field::new("n", DataType::Int64, false)]));
    let batch = RecordBatch::try_new(
        Arc::clone(&schema),
        vec![Arc::new(Int64Array::from_iter_values(0..1000))],
    )
    .expect("batch");
    let file = std::fs::File::create(&path).expect("create");
    let mut writer = ArrowWriter::try_new(file, schema, None).expect("writer");
    writer.write(&batch).expect("write");
    writer.close().expect("close");
    path
}

async fn drain_output(child: &mut tokio::process::Child) -> String {
    use tokio::io::AsyncReadExt;
    let mut out = String::new();
    if let Some(mut so) = child.stdout.take() {
        let _ = so.read_to_string(&mut out).await;
    }
    if let Some(mut se) = child.stderr.take() {
        let _ = se.read_to_string(&mut out).await;
    }
    out
}

/// Spawn an HA scheduler on `port` sharing `lease_uri`, pointed at `MinIO` via
/// the standard `AWS_*` env. Short lease/heartbeat so a killed leader is
/// stolen quickly.
fn spawn_ha_scheduler(port: u16, lease_uri: &str, s3_endpoint: &str) -> tokio::process::Child {
    let bin = assert_cmd::cargo::cargo_bin("dataglot-ballista-scheduler");
    tokio::process::Command::new(&bin)
        .args([
            "--bind-host",
            "127.0.0.1",
            "--bind-port",
            &port.to_string(),
            "--external-host",
            "127.0.0.1",
            "--ha-state-uri",
            lease_uri,
            "--ha-lease-duration-secs",
            "3",
            "--ha-heartbeat-interval-secs",
            "1",
            "--insecure",
        ])
        .env("AWS_ENDPOINT", s3_endpoint)
        .env("AWS_ACCESS_KEY_ID", MINIO_USER)
        .env("AWS_SECRET_ACCESS_KEY", MINIO_PASSWORD)
        .env("AWS_ALLOW_HTTP", "true")
        .env("AWS_REGION", "us-east-1")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn HA scheduler binary")
}

/// Spawn an executor pointed at a scheduler `port`.
fn spawn_executor(
    scheduler_port: u16,
    creds: &std::path::Path,
    catalogs: &std::path::Path,
) -> tokio::process::Child {
    let bin = assert_cmd::cargo::cargo_bin("dataglot-ballista-executor");
    let ports = free_ports(2); // distinct bind + flight ports
    tokio::process::Command::new(&bin)
        .args([
            "--scheduler-host",
            "127.0.0.1",
            "--scheduler-port",
            &scheduler_port.to_string(),
            "--bind-host",
            "127.0.0.1",
            "--bind-port",
            &ports[0].to_string(),
            "--bind-grpc-port",
            &ports[1].to_string(),
            "--external-host",
            "127.0.0.1",
            "--concurrent-tasks",
            "2",
            "--credentials-config",
            creds.to_str().expect("utf-8"),
            "--catalogs-config",
            catalogs.to_str().expect("utf-8"),
            "--insecure",
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn executor binary")
}

/// Poll until a TCP listener accepts on `port`, or `timeout` elapses.
async fn wait_for_listener(port: u16, timeout: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + timeout;
    while tokio::time::Instant::now() < deadline {
        if tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_ok()
        {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    false
}

/// Run `SELECT COUNT(*)` against the scheduler at `port`, returning the count.
async fn count_via(port: u16, parquet: &std::path::Path) -> Result<i64, String> {
    use ballista::datafusion::arrow::array::Int64Array;

    let state = BallistaContextFactory::with_defaults().build_federated_state();
    let ctx = SessionContext::new_with_state(
        state
            .upgrade_for_ballista(format!("http://127.0.0.1:{port}"))
            .map_err(|e| format!("client state: {e}"))?,
    );
    ctx.register_parquet(
        "nums",
        parquet.display().to_string(),
        ParquetReadOptions::default(),
    )
    .await
    .map_err(|e| format!("register parquet: {e}"))?;
    let batches = ctx
        .sql("SELECT COUNT(*) AS c FROM nums")
        .await
        .map_err(|e| format!("plan: {e}"))?
        .collect()
        .await
        .map_err(|e| format!("collect: {e}"))?;
    let c = batches
        .first()
        .and_then(|b| b.column(0).as_any().downcast_ref::<Int64Array>())
        .map(|a| a.value(0))
        .ok_or_else(|| "no count column".to_string())?;
    Ok(c)
}

/// `count_via` with a bounded retry — a freshly-registered executor may not
/// have its Flight port serving on the first job submission, so re-submit
/// (each attempt re-plans + re-fetches) until it succeeds or `timeout` passes.
/// A readiness wait, not a correctness relaxation: a wrong answer fails now.
async fn count_via_ready(port: u16, parquet: &std::path::Path, timeout: Duration) -> i64 {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        match count_via(port, parquet).await {
            Ok(c) => return c,
            Err(e) => {
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "query never succeeded against 127.0.0.1:{port} within {timeout:?}; last error: {e}"
                );
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires Docker (MinIO) + scheduler/executor subprocesses + a failover window"]
async fn standby_scheduler_promotes_on_leader_death_and_serves_queries() {
    // ---- `MinIO` as the S3-compatible lease backend ----------------------------
    let minio = MinIO::default().start().await.expect("start MinIO");
    let s3_port = minio
        .get_host_port_ipv4(9000)
        .await
        .expect("minio host port");
    let s3_endpoint = format!("http://127.0.0.1:{s3_port}");

    // Create the lease bucket with the `mc` bundled in the minio image
    // (localhost:9000 inside the container).
    let mc = format!(
        "mc alias set local http://localhost:9000 {MINIO_USER} {MINIO_PASSWORD} && \
         mc mb --ignore-existing local/{LEASE_BUCKET}"
    );
    let mut exec = minio
        .exec(ExecCommand::new(["/bin/sh", "-c", &mc]))
        .await
        .expect("exec mc bucket create");
    // Draining stdout/stderr also waits for the command to finish, so the
    // exit code is available (it's `None` while the exec is still running).
    let out = exec.stdout_to_vec().await.unwrap_or_default();
    let err = exec.stderr_to_vec().await.unwrap_or_default();
    let code = exec.exit_code().await.expect("mc exit code");
    assert_eq!(
        code,
        Some(0),
        "creating the lease bucket via mc failed (exit {code:?}):\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out),
        String::from_utf8_lossy(&err),
    );

    let lease_uri = format!("s3://{LEASE_BUCKET}/scheduler-lease.json");

    // ---- fixtures ------------------------------------------------------------
    let tmp = tempfile::tempdir().expect("tempdir");
    let parquet = seed_parquet(tmp.path());
    let creds = tempfile::NamedTempFile::new().expect("creds tmp");
    std::fs::write(creds.path(), br#"{"kind": "static", "entries": {}}"#).expect("creds");
    let catalogs = tempfile::NamedTempFile::new().expect("catalogs tmp");
    std::fs::write(catalogs.path(), b"{}").expect("catalogs");

    let sched_ports = free_ports(2);
    let (port_a, port_b) = (sched_ports[0], sched_ports[1]);

    // ---- Scheduler A: wins the lease and binds --------------------------------
    let mut sched_a = spawn_ha_scheduler(port_a, &lease_uri, &s3_endpoint);
    assert!(
        wait_for_listener(port_a, Duration::from_secs(30)).await,
        "leader (A) never bound its gRPC port; output:\n{}",
        drain_output(&mut sched_a).await
    );

    // ---- Scheduler B: standby — blocks in the claim loop, does NOT bind -------
    let mut sched_b = spawn_ha_scheduler(port_b, &lease_uri, &s3_endpoint);
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(
        tokio::net::TcpStream::connect(("127.0.0.1", port_b))
            .await
            .is_err(),
        "standby (B) bound its port while A still held the lease — election is broken"
    );

    // ---- Executor for A + baseline query --------------------------------------
    let mut exec_a = spawn_executor(port_a, creds.path(), catalogs.path());
    tokio::time::sleep(Duration::from_secs(4)).await;
    if let Some(status) = exec_a.try_wait().expect("try_wait exec_a") {
        panic!(
            "executor A exited during registration ({status:?}); output:\n{}",
            drain_output(&mut exec_a).await
        );
    }
    let baseline = count_via_ready(port_a, &parquet, Duration::from_secs(30)).await;
    assert_eq!(baseline, 1000, "leader must return the seeded row count");

    // ---- Kill the leader; the standby must promote ----------------------------
    sched_a.kill().await.expect("kill leader A");
    let _ = sched_a.wait().await;
    let _ = exec_a.kill().await; // its scheduler is gone

    assert!(
        wait_for_listener(port_b, Duration::from_secs(30)).await,
        "standby (B) never promoted + bound after the leader died; output:\n{}",
        drain_output(&mut sched_b).await
    );

    // ---- Executor for the promoted B + recovery query -------------------------
    let mut exec_b = spawn_executor(port_b, creds.path(), catalogs.path());
    tokio::time::sleep(Duration::from_secs(4)).await;
    if let Some(status) = exec_b.try_wait().expect("try_wait exec_b") {
        panic!(
            "executor B exited during registration ({status:?}); output:\n{}",
            drain_output(&mut exec_b).await
        );
    }

    // The whole point: the promoted standby serves the same query, same result.
    let recovered = count_via_ready(port_b, &parquet, Duration::from_secs(30)).await;
    assert_eq!(
        recovered, 1000,
        "the promoted standby must serve the same query with the same result"
    );

    let _ = sched_b.kill().await;
    let _ = exec_b.kill().await;
}

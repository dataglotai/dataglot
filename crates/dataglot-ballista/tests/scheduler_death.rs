//! Scheduler-death client behavior ( #1).
//!
//! The suite proves *executor* death is survivable
//! (`multi_process_query_e2e`), but nothing ever killed the
//! *scheduler* — the other process an operator will lose. This test
//! pins the client-side contract: after the scheduler dies, a query
//! surfaces a **typed error within bounded time**, never an indefinite
//! hang. (Full HA failover with a standby scheduler is a follow-up;
//! this is the single-scheduler experience.)
//!
//! Shape: real `dataglot-ballista-scheduler` + `dataglot-ballista-executor`
//! subprocesses (both killable), local parquet through the default
//! codec — no Docker.

#![allow(clippy::too_many_lines)] // linear scenario; child lifetimes pin the flow

use std::time::Duration;

use ballista::datafusion::prelude::{ParquetReadOptions, SessionContext};
use ballista_core::extension::SessionStateExt;
use dataglot_ballista::BallistaContextFactory;

fn free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind 0");
    l.local_addr().expect("addr").port()
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
    if let Some(mut s) = child.stderr.take() {
        let mut buf = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(2), s.read_to_end(&mut buf)).await;
        out.push_str(&String::from_utf8_lossy(&buf));
        out.push('\n');
    }
    if let Some(mut s) = child.stdout.take() {
        let mut buf = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(2), s.read_to_end(&mut buf)).await;
        out.push_str(&String::from_utf8_lossy(&buf));
    }
    out
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn scheduler_death_yields_bounded_typed_error_not_a_hang() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let parquet = seed_parquet(tmp.path());

    // ---- scheduler subprocess (killable — the point of the test) ----------
    let scheduler_port = free_port();
    let scheduler_bin = assert_cmd::cargo::cargo_bin("dataglot-ballista-scheduler");
    let mut scheduler = tokio::process::Command::new(&scheduler_bin)
        .args([
            "--bind-host",
            "127.0.0.1",
            "--bind-port",
            &scheduler_port.to_string(),
            "--external-host",
            "127.0.0.1",
            "--insecure",
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn scheduler binary");

    // Wait for the gRPC listener.
    let mut up = false;
    for _ in 0..100 {
        if tokio::net::TcpStream::connect(("127.0.0.1", scheduler_port))
            .await
            .is_ok()
        {
            up = true;
            break;
        }
        if let Some(status) = scheduler.try_wait().expect("try_wait") {
            panic!(
                "scheduler exited during boot with {status:?}; output:\n{}",
                drain_output(&mut scheduler).await
            );
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(up, "scheduler gRPC never came up");

    // ---- executor subprocess ------------------------------------------------
    let creds = tempfile::NamedTempFile::new().expect("creds tmp");
    std::fs::write(creds.path(), br#"{"kind": "static", "entries": {}}"#).expect("creds");
    let catalogs = tempfile::NamedTempFile::new().expect("catalogs tmp");
    std::fs::write(catalogs.path(), b"{}").expect("catalogs");
    let executor_bin = assert_cmd::cargo::cargo_bin("dataglot-ballista-executor");
    let mut executor = tokio::process::Command::new(&executor_bin)
        .args([
            "--scheduler-host",
            "127.0.0.1",
            "--scheduler-port",
            &scheduler_port.to_string(),
            "--bind-host",
            "127.0.0.1",
            "--bind-port",
            &free_port().to_string(),
            "--bind-grpc-port",
            &free_port().to_string(),
            "--external-host",
            "127.0.0.1",
            "--concurrent-tasks",
            "2",
            "--credentials-config",
            creds.path().to_str().expect("utf-8"),
            "--catalogs-config",
            catalogs.path().to_str().expect("utf-8"),
            "--insecure",
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn executor binary");
    tokio::time::sleep(Duration::from_secs(4)).await;
    if let Some(status) = executor.try_wait().expect("try_wait") {
        panic!(
            "executor exited during registration with {status:?}; output:\n{}",
            drain_output(&mut executor).await
        );
    }

    // ---- client, and a healthy baseline query ------------------------------
    let state = BallistaContextFactory::with_defaults().build_federated_state();
    let ctx = SessionContext::new_with_state(
        state
            .upgrade_for_ballista(format!("http://127.0.0.1:{scheduler_port}"))
            .expect("client state"),
    );
    ctx.register_parquet(
        "nums",
        parquet.display().to_string(),
        ParquetReadOptions::default(),
    )
    .await
    .expect("register parquet");

    let healthy = tokio::time::timeout(Duration::from_mins(1), async {
        ctx.sql("SELECT COUNT(*) AS c FROM nums")
            .await
            .expect("plans")
            .collect()
            .await
            .expect("executes while scheduler is alive")
    })
    .await
    .expect("baseline query must complete while the cluster is healthy");
    assert_eq!(healthy[0].num_rows(), 1);

    // ---- kill the scheduler, then query again -------------------------------
    scheduler.kill().await.expect("kill scheduler");
    let _ = scheduler.wait().await;

    let after = tokio::time::timeout(Duration::from_secs(30), async {
        match ctx.sql("SELECT COUNT(*) AS c FROM nums").await {
            // Planning may already fail (job submission dials the dead
            // scheduler) — that's an acceptable typed surface too.
            Err(e) => Err(e),
            Ok(df) => df.collect().await.map(|_| ()),
        }
    })
    .await;

    // (`let else` rather than a match: CI's clippy denies wildcard
    // `Err(_)` arms — `match_wild_err_arm`.)
    let Ok(outcome) = after else {
        panic!(
            "query against a dead scheduler hung >30s — the client must \
             surface a typed error, not wait forever"
        );
    };
    match outcome {
        Ok(()) => panic!(
            "query 'succeeded' against a killed scheduler — the kill did \
             not take, or results came from nowhere"
        ),
        Err(e) => {
            let msg = e.to_string();
            assert!(
                !msg.trim().is_empty(),
                "error surface must be non-empty and diagnosable"
            );
        }
    }

    let _ = executor.kill().await;
}

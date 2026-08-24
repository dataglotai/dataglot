//! Partial-cluster survival: losing ONE of several executors must not
//! take down the cluster ( follow-up; distributed resilience).
//!
//! Every existing failure test kills the *only* executor
//! (`multi_process_query_e2e.rs`, `scheduler_death.rs`) or the scheduler,
//! so they exercise total-outage-then-recovery — never a *degraded but
//! live* cluster. This pins the property that actually matters for a
//! multi-node deployment: when one executor dies, the scheduler must
//! detect it, stop scheduling tasks to the dead node, and keep serving
//! correct distributed results on the survivors.
//!
//! Shape:
//! 1. Push-staged scheduler, no in-process executor.
//! 2. **Three** `dataglot-ballista-executor` subprocesses, one slot each.
//! 3. Kill one after all three register.
//! 4. A GROUP BY that forces a cross-executor shuffle must still return
//!    exact per-group totals — proof the scheduler excluded the dead node
//!    (had it kept assigning stage tasks to the corpse, the job would
//!    hang and the 3-minute timeout would fire).
//!
//! Local parquet only (default codec serializes `ListingTable`
//! natively) — no Docker; runs in the default `-p dataglot-ballista` pass.

#![allow(clippy::too_many_lines)] // linear scenario; child lifetimes pin the flow

use std::time::Duration;

use ballista::datafusion::arrow::array::{Float64Array, Int64Array};
use ballista::datafusion::prelude::{ParquetReadOptions, SessionContext};
use ballista_core::config::TaskSchedulingPolicy;
use ballista_core::extension::SessionStateExt;
use dataglot_ballista::BallistaContextFactory;

/// 8 files × 12 500 rows = 100 000 rows; row `g` has `k = g % 100` and
/// `v = g`. Every group `k` has exactly 1 000 rows and a closed-form Σv.
const FILES: usize = 8;
const ROWS_PER_FILE: usize = 12_500;
const GROUPS: i64 = 100;

fn seed_parquet_dir() -> tempfile::TempDir {
    use ballista::datafusion::arrow::array::RecordBatch;
    use ballista::datafusion::arrow::datatypes::{DataType, Field, Schema};
    use parquet::arrow::ArrowWriter;
    use std::sync::Arc;

    let tmp = tempfile::tempdir().expect("tempdir");
    let schema = Arc::new(Schema::new(vec![
        Field::new("k", DataType::Int64, false),
        Field::new("v", DataType::Float64, false),
    ]));
    for f in 0..FILES {
        let start = f * ROWS_PER_FILE;
        #[allow(clippy::cast_possible_wrap)] // ≤ 100k, nowhere near i64::MAX
        let globals = (start..start + ROWS_PER_FILE).map(|g| g as i64);
        #[allow(clippy::cast_precision_loss)] // test data, exact below 2^53
        let batch = RecordBatch::try_new(
            Arc::clone(&schema),
            vec![
                Arc::new(Int64Array::from_iter_values(
                    globals.clone().map(|g| g % GROUPS),
                )),
                Arc::new(Float64Array::from_iter_values(globals.map(|g| g as f64))),
            ],
        )
        .expect("batch");
        let file =
            std::fs::File::create(tmp.path().join(format!("part-{f}.parquet"))).expect("create");
        let mut writer = ArrowWriter::try_new(file, Arc::clone(&schema), None).expect("writer");
        writer.write(&batch).expect("write");
        writer.close().expect("close");
    }
    tmp
}

fn free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind 0");
    l.local_addr().expect("addr").port()
}

/// Spawn one executor subprocess with a **single task slot**.
fn spawn_executor(
    scheduler_host: &str,
    scheduler_port: u16,
    creds: &std::path::Path,
    catalogs: &std::path::Path,
) -> tokio::process::Child {
    let bin = assert_cmd::cargo::cargo_bin("dataglot-ballista-executor");
    tokio::process::Command::new(&bin)
        .args([
            "--scheduler-host",
            scheduler_host,
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
            "1",
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

async fn drain_output(child: &mut tokio::process::Child) -> String {
    use tokio::io::AsyncReadExt;
    let mut out = String::new();
    for stream in [
        child
            .stderr
            .take()
            .map(|s| Box::new(s) as Box<dyn tokio::io::AsyncRead + Unpin + Send>),
        child
            .stdout
            .take()
            .map(|s| Box::new(s) as Box<dyn tokio::io::AsyncRead + Unpin + Send>),
    ]
    .into_iter()
    .flatten()
    {
        let mut s = stream;
        let mut buf = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(2), s.read_to_end(&mut buf)).await;
        out.push_str(&String::from_utf8_lossy(&buf));
        out.push('\n');
    }
    out
}

/// GET the scheduler REST API and parse JSON (HTTP/1.0 ⇒ unchunked).
async fn get_json(api: std::net::SocketAddr, path: &str) -> serde_json::Value {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let Ok(mut stream) = tokio::net::TcpStream::connect(api).await else {
        return serde_json::Value::Null;
    };
    let req = format!("GET {path} HTTP/1.0\r\nHost: {api}\r\n\r\n");
    if stream.write_all(req.as_bytes()).await.is_err() {
        return serde_json::Value::Null;
    }
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(3), stream.read_to_end(&mut buf)).await;
    let raw = String::from_utf8_lossy(&buf);
    let body = raw.split_once("\r\n\r\n").map_or("", |(_, b)| b);
    serde_json::from_str(body).unwrap_or(serde_json::Value::Null)
}

/// Number of executors the scheduler currently reports (shape-tolerant).
async fn registered_executors(api: std::net::SocketAddr) -> usize {
    let v = get_json(api, "/api/executors").await;
    v.as_array()
        .map(Vec::len)
        .or_else(|| v["executors"].as_array().map(Vec::len))
        .unwrap_or(0)
}

/// Run the cross-shuffle GROUP BY and assert exact per-group totals.
/// Returns the number of groups seen so the caller can sanity-check.
fn assert_exact_groups(batches: &[ballista::datafusion::arrow::array::RecordBatch]) {
    let mut groups = Vec::new();
    for b in batches {
        let k = b
            .column(0)
            .as_any()
            .downcast_ref::<Int64Array>()
            .expect("k Int64");
        let c = b
            .column(1)
            .as_any()
            .downcast_ref::<Int64Array>()
            .expect("count Int64");
        let s = b
            .column(2)
            .as_any()
            .downcast_ref::<Float64Array>()
            .expect("sum Float64");
        for i in 0..b.num_rows() {
            groups.push((k.value(i), c.value(i), s.value(i)));
        }
    }
    assert_eq!(
        groups.len(),
        usize::try_from(GROUPS).unwrap(),
        "every group must survive the degraded-cluster shuffle exactly once"
    );
    #[allow(clippy::cast_possible_wrap)] // 100k rows, fits comfortably
    let per_group = (FILES * ROWS_PER_FILE) as i64 / GROUPS; // 1000
    for (k, c, s) in groups {
        assert_eq!(c, per_group, "group {k}: count");
        #[allow(clippy::cast_precision_loss)]
        let expected = (per_group * k + GROUPS * (999 * per_group / 2)) as f64;
        assert!(
            (s - expected).abs() < 1e-6,
            "group {k}: sum {s} != {expected} — a shuffle partition was \
             dropped or fetched from the dead executor"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn surviving_executors_serve_after_one_dies() {
    // ---- data + scheduler -------------------------------------------------
    let data = seed_parquet_dir();
    let factory = BallistaContextFactory::with_defaults();
    let state = factory.build_federated_state();
    let (scheduler, scheduler_addr) = dataglot_ballista::monitor::boot_scheduler_from_state(
        &state,
        TaskSchedulingPolicy::PushStaged,
        3600,
    )
    .await
    .expect("push-staged scheduler boots");

    let api_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("api bind");
    let api_addr = api_listener.local_addr().expect("api addr");
    let router = ballista_scheduler::api::get_routes(std::sync::Arc::new(scheduler.clone()));
    tokio::spawn(async move {
        let _ = axum::serve(api_listener, router).await;
    });

    // ---- three subprocess executors, one slot each ------------------------
    let creds = tempfile::NamedTempFile::new().expect("creds tmp");
    std::fs::write(creds.path(), br#"{"kind": "static", "entries": {}}"#).expect("creds");
    let catalogs = tempfile::NamedTempFile::new().expect("catalogs tmp");
    std::fs::write(catalogs.path(), b"{}").expect("catalogs");

    let scheduler_host = match scheduler_addr.ip() {
        std::net::IpAddr::V4(ip) => ip.to_string(),
        std::net::IpAddr::V6(ip) => format!("[{ip}]"),
    };
    let spawn = || {
        spawn_executor(
            &scheduler_host,
            scheduler_addr.port(),
            creds.path(),
            catalogs.path(),
        )
    };
    let mut exec_a = spawn();
    let mut exec_b = spawn();
    let mut exec_c = spawn();

    // All three must register before we kill one.
    let mut n = 0;
    for _ in 0..60 {
        n = registered_executors(api_addr).await;
        if n >= 3 {
            break;
        }
        for (label, child) in [("A", &mut exec_a), ("B", &mut exec_b), ("C", &mut exec_c)] {
            if let Some(status) = child.try_wait().expect("try_wait") {
                panic!(
                    "executor {label} exited during registration with {status:?}; output:\n{}",
                    drain_output(child).await
                );
            }
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert_eq!(n, 3, "all three executors must register with the scheduler");

    // ---- kill one executor ------------------------------------------------
    exec_c.kill().await.expect("kill executor C");
    let _ = exec_c.wait().await;

    // Give the scheduler a chance to notice the death and drop C from the
    // roster. Not a hard assertion (heartbeat-expiry timing varies) — the
    // load-bearing assertion is that the query below still succeeds; if the
    // scheduler kept dispatching stage tasks to the dead node the job would
    // hang and the timeout would fire.
    let mut survivors = 3;
    for _ in 0..60 {
        survivors = registered_executors(api_addr).await;
        if survivors <= 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    // ---- query the degraded cluster ---------------------------------------
    let client_state = state
        .upgrade_for_ballista(format!("http://{scheduler_host}:{}", scheduler_addr.port()))
        .expect("client state");
    let ctx = SessionContext::new_with_state(client_state);
    ctx.register_parquet(
        "wide",
        format!("{}/", data.path().display()),
        ParquetReadOptions::default(),
    )
    .await
    .expect("register parquet dir");

    let run = async {
        ctx.sql("SELECT k, COUNT(*) AS c, SUM(v) AS s FROM wide GROUP BY k ORDER BY k")
            .await
            .expect("plans")
            .collect()
            .await
    };
    let batches = match tokio::time::timeout(Duration::from_mins(3), run).await {
        Ok(Ok(b)) => b,
        Ok(Err(e)) => {
            let jobs = get_json(api_addr, "/api/jobs").await;
            let _ = exec_a.kill().await;
            let _ = exec_b.kill().await;
            panic!(
                "degraded-cluster aggregation failed after one executor died \
                 (survivors reported: {survivors}): {e}\njobs: {jobs}\n\
                 executor A:\n{}\nexecutor B:\n{}",
                drain_output(&mut exec_a).await,
                drain_output(&mut exec_b).await
            );
        }
        Err(_) => {
            let jobs = get_json(api_addr, "/api/jobs").await;
            let _ = exec_a.kill().await;
            let _ = exec_b.kill().await;
            panic!(
                "query hung 180s after one of three executors died \
                 (survivors reported: {survivors}) — the scheduler likely kept \
                 dispatching tasks to the dead node.\njobs: {jobs}\n\
                 executor A:\n{}\nexecutor B:\n{}",
                drain_output(&mut exec_a).await,
                drain_output(&mut exec_b).await
            );
        }
    };

    assert_exact_groups(&batches);

    let _ = exec_a.kill().await;
    let _ = exec_b.kill().await;
}

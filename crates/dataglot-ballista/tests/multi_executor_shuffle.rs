//! Multi-executor cross-shuffle correctness.
//!
//! Every other test in the suite runs **one** executor — which
//! exercises plan serialization but not *distribution*: a
//! shuffle-addressing bug (executor A unable to fetch executor B's
//! shuffle partitions over Flight) would pass all of them. This test
//! pins the real thing:
//!
//! 1. Push-staged scheduler, **no in-process executor**.
//! 2. **Two** `dataglot-ballista-executor` subprocesses, one task slot
//!    each — with 8 scan partitions pending, the push scheduler fills
//!    every free slot, so both processes take stage-1 tasks and write
//!    shuffle partitions into their *own* work dirs.
//! 3. A GROUP BY forces a repartition: every stage-2 task must fetch
//!    shuffle partitions from **both** executors. The aggregation
//!    result being exactly right is therefore proof that
//!    cross-executor shuffle reads work — there is no way to compute
//!    the correct totals from one executor's half of the data.
//!
//! Local parquet only (default codec serializes `ListingTable`
//! natively), so unlike the federation multi-process tests this needs
//! no Docker and runs in the default CI pass.

#![allow(clippy::too_many_lines)] // linear scenario; child lifetimes pin the flow

use std::time::Duration;

use ballista::datafusion::arrow::array::{Float64Array, Int64Array};
use ballista::datafusion::prelude::{ParquetReadOptions, SessionContext};
use ballista_core::config::TaskSchedulingPolicy;
use ballista_core::extension::SessionStateExt;
use dataglot_ballista::BallistaContextFactory;

/// 8 files × 12 500 rows = 100 000 rows; row `g` (global index) has
/// `k = g % 100` and `v = g`. Every group `k` therefore has exactly
/// 1 000 rows and `Σv = 1000·k + 100·(999·1000/2)` — a closed form the
/// test asserts per group.
const FILES: usize = 8;
const ROWS_PER_FILE: usize = 12_500;
const GROUPS: i64 = 100;

fn seed_parquet_dir() -> tempfile::TempDir {
    use ballista::datafusion::arrow::array::{Float64Array, Int64Array, RecordBatch};
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

/// Spawn one executor subprocess with a **single task slot** (the
/// spread-forcing constraint) and no federation catalogs.
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

/// Number of executors the scheduler currently reports (shape-tolerant:
/// upstream serves either a bare array or `{"executors": [...]}`).
async fn registered_executors(api: std::net::SocketAddr) -> usize {
    let v = get_json(api, "/api/executors").await;
    v.as_array()
        .map(Vec::len)
        .or_else(|| v["executors"].as_array().map(Vec::len))
        .unwrap_or(0)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn aggregation_is_exact_across_two_executors() {
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

    // REST API for the registration probe + failure diagnostics.
    let api_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("api bind");
    let api_addr = api_listener.local_addr().expect("api addr");
    let router = ballista_scheduler::api::get_routes(std::sync::Arc::new(scheduler.clone()));
    tokio::spawn(async move {
        let _ = axum::serve(api_listener, router).await;
    });

    // ---- two subprocess executors, one slot each ---------------------------
    let creds = tempfile::NamedTempFile::new().expect("creds tmp");
    std::fs::write(creds.path(), br#"{"kind": "static", "entries": {}}"#).expect("creds");
    let catalogs = tempfile::NamedTempFile::new().expect("catalogs tmp");
    std::fs::write(catalogs.path(), b"{}").expect("catalogs");

    // The scheduler binds `localhost`, which may resolve to the IPv6
    // loopback — derive the dial-back host from the *actual* bound IP
    // (hard-coding 127.0.0.1 fails on ::1 binds).
    let scheduler_host = match scheduler_addr.ip() {
        std::net::IpAddr::V4(ip) => ip.to_string(),
        std::net::IpAddr::V6(ip) => format!("[{ip}]"),
    };
    let mut exec_a = spawn_executor(
        &scheduler_host,
        scheduler_addr.port(),
        creds.path(),
        catalogs.path(),
    );
    let mut exec_b = spawn_executor(
        &scheduler_host,
        scheduler_addr.port(),
        creds.path(),
        catalogs.path(),
    );

    // Both must register before the query, or the "spread" premise is
    // untested (one executor could serve everything).
    let mut n = 0;
    for _ in 0..60 {
        n = registered_executors(api_addr).await;
        if n >= 2 {
            break;
        }
        for (label, child) in [("A", &mut exec_a), ("B", &mut exec_b)] {
            if let Some(status) = child.try_wait().expect("try_wait") {
                panic!(
                    "executor {label} exited during registration with {status:?}; output:\n{}",
                    drain_output(child).await
                );
            }
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert_eq!(n, 2, "both executors must register with the scheduler");

    // ---- client + query ----------------------------------------------------
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
    let batches = match tokio::time::timeout(Duration::from_mins(2), run).await {
        Ok(Ok(b)) => b,
        Ok(Err(e)) => {
            let jobs = get_json(api_addr, "/api/jobs").await;
            let _ = exec_a.kill().await;
            let _ = exec_b.kill().await;
            panic!(
                "distributed aggregation failed: {e}\njobs: {jobs}\nexecutor A:\n{}\nexecutor B:\n{}",
                drain_output(&mut exec_a).await,
                drain_output(&mut exec_b).await
            );
        }
        Err(_) => {
            let jobs = get_json(api_addr, "/api/jobs").await;
            let _ = exec_a.kill().await;
            let _ = exec_b.kill().await;
            panic!(
                "query hung 120s — tasks queued but never spread/completed.\njobs: {jobs}\nexecutor A:\n{}\nexecutor B:\n{}",
                drain_output(&mut exec_a).await,
                drain_output(&mut exec_b).await
            );
        }
    };

    // ---- exact per-group assertions ----------------------------------------
    let mut groups = Vec::new();
    for b in &batches {
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
        "every group must survive the cross-executor shuffle exactly once"
    );
    #[allow(clippy::cast_possible_wrap)] // 100k rows, fits comfortably
    let per_group = (FILES * ROWS_PER_FILE) as i64 / GROUPS; // 1000
    for (k, c, s) in groups {
        assert_eq!(c, per_group, "group {k}: count");
        // Σ over g ≡ k (mod 100), g < 100 000: 1000·k + 100·(999·1000/2).
        #[allow(clippy::cast_precision_loss)]
        let expected = (per_group * k + GROUPS * (999 * per_group / 2)) as f64;
        assert!(
            (s - expected).abs() < 1e-6,
            "group {k}: sum {s} != {expected} — a shuffle partition was \
             dropped, duplicated, or fetched from the wrong executor"
        );
    }

    let _ = exec_a.kill().await;
    let _ = exec_b.kill().await;
}

// ===========================================================================
// High-fan-out variant
// ===========================================================================
//
// The test above proves cross-executor shuffle at MINIMAL fan-out (2
// executors × 1 slot). A dropped / duplicated / misaddressed shuffle fetch
// that only manifests when a reduce task must gather partitions from MANY
// producers would pass it. This variant widens the shuffle: 4 executor
// subprocesses, 16 scan partitions, 1000 groups — so stage-1 scan tasks
// spread across all four processes and every stage-2 reduce task fetches
// shuffle partitions from all four. The exact per-group total is still a
// closed form (integer sums are exact in f64 below 2^53), so a single
// mis-shuffled partition is caught deterministically.

const WIDE_EXECUTORS: usize = 4;
const WIDE_FILES: usize = 16;
const WIDE_ROWS_PER_FILE: usize = 8_000; // 128k rows total
const WIDE_GROUPS: i64 = 1_000; // 128 rows per group

fn seed_parquet_wide() -> tempfile::TempDir {
    use ballista::datafusion::arrow::array::{Float64Array, Int64Array, RecordBatch};
    use ballista::datafusion::arrow::datatypes::{DataType, Field, Schema};
    use parquet::arrow::ArrowWriter;
    use std::sync::Arc;

    let tmp = tempfile::tempdir().expect("tempdir");
    let schema = Arc::new(Schema::new(vec![
        Field::new("k", DataType::Int64, false),
        Field::new("v", DataType::Float64, false),
    ]));
    for f in 0..WIDE_FILES {
        let start = f * WIDE_ROWS_PER_FILE;
        #[allow(clippy::cast_possible_wrap)] // 128k rows, nowhere near i64::MAX
        let globals = (start..start + WIDE_ROWS_PER_FILE).map(|g| g as i64);
        #[allow(clippy::cast_precision_loss)] // exact below 2^53
        let batch = RecordBatch::try_new(
            Arc::clone(&schema),
            vec![
                Arc::new(Int64Array::from_iter_values(
                    globals.clone().map(|g| g % WIDE_GROUPS),
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn aggregation_exact_across_four_executors_high_fanout() {
    // ---- data + scheduler -------------------------------------------------
    let data = seed_parquet_wide();
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

    // ---- four subprocess executors, one slot each --------------------------
    let creds = tempfile::NamedTempFile::new().expect("creds tmp");
    std::fs::write(creds.path(), br#"{"kind": "static", "entries": {}}"#).expect("creds");
    let catalogs = tempfile::NamedTempFile::new().expect("catalogs tmp");
    std::fs::write(catalogs.path(), b"{}").expect("catalogs");

    let scheduler_host = match scheduler_addr.ip() {
        std::net::IpAddr::V4(ip) => ip.to_string(),
        std::net::IpAddr::V6(ip) => format!("[{ip}]"),
    };
    let mut execs: Vec<tokio::process::Child> = (0..WIDE_EXECUTORS)
        .map(|_| {
            spawn_executor(
                &scheduler_host,
                scheduler_addr.port(),
                creds.path(),
                catalogs.path(),
            )
        })
        .collect();

    // All four must register, or the "spread across four" premise is untested
    // (a subset could serve every partition).
    let mut n = 0;
    for _ in 0..60 {
        n = registered_executors(api_addr).await;
        if n >= WIDE_EXECUTORS {
            break;
        }
        for (i, child) in execs.iter_mut().enumerate() {
            if let Some(status) = child.try_wait().expect("try_wait") {
                panic!(
                    "executor {i} exited during registration with {status:?}; output:\n{}",
                    drain_output(child).await
                );
            }
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert_eq!(
        n, WIDE_EXECUTORS,
        "all {WIDE_EXECUTORS} executors must register with the scheduler"
    );

    // ---- client + query ----------------------------------------------------
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
            for c in &mut execs {
                let _ = c.kill().await;
            }
            panic!("distributed aggregation failed: {e}\njobs: {jobs}");
        }
        Err(_) => {
            let jobs = get_json(api_addr, "/api/jobs").await;
            for c in &mut execs {
                let _ = c.kill().await;
            }
            panic!("query hung 180s — tasks queued but never spread/completed.\njobs: {jobs}");
        }
    };

    // ---- exact per-group assertions ----------------------------------------
    let mut groups = Vec::new();
    for b in &batches {
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
        usize::try_from(WIDE_GROUPS).unwrap(),
        "every group must survive the 4-way cross-executor shuffle exactly once"
    );
    #[allow(clippy::cast_possible_wrap)] // 128k rows, fits comfortably
    let per_group = (WIDE_FILES * WIDE_ROWS_PER_FILE) as i64 / WIDE_GROUPS; // 128
    for (k, c, s) in groups {
        assert_eq!(c, per_group, "group {k}: count");
        // Σ over g ≡ k (mod WIDE_GROUPS), g < 128 000: per_group·k +
        // WIDE_GROUPS·((per_group-1)·per_group/2). Integer-exact in f64.
        #[allow(clippy::cast_precision_loss)]
        let expected = (per_group * k + WIDE_GROUPS * ((per_group - 1) * per_group / 2)) as f64;
        assert!(
            (s - expected).abs() < 1e-6,
            "group {k}: sum {s} != {expected} — a shuffle partition was dropped, \
             duplicated, or fetched from the wrong one of {WIDE_EXECUTORS} executors"
        );
    }

    for c in &mut execs {
        let _ = c.kill().await;
    }
}

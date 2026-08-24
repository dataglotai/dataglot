//! Slot saturation: more concurrent jobs than task slots must QUEUE and
//! DRAIN, not deadlock or error (distributed backpressure; ).
//!
//! The existing concurrency coverage (`ballista_e2e.rs`) uses a handful
//! of clients against an in-process standalone cluster with ample slots,
//! so it never actually saturates the scheduler. A prior investigation
//! saw distributed queries *queue* and look stuck when every
//! executor slot was busy — the open question was whether the scheduler
//! drains that backlog or wedges. Nothing pinned it.
//!
//! Shape:
//! 1. Push-staged scheduler, no in-process executor.
//! 2. **Two** executors, **one slot each** → 2 total task slots.
//! 3. Fire **six** concurrent multi-stage GROUP BY jobs (each needs
//!    several stage tasks). With 2 slots, at most 2 run at once; the
//!    other four must queue.
//! 4. Every one of the six must complete with EXACT results within a
//!    generous timeout — proof the scheduler drains the backlog instead
//!    of deadlocking or erroring under contention.
//!
//! Local parquet only — no Docker; runs in the default
//! `-p dataglot-ballista` pass.

#![allow(clippy::too_many_lines)] // linear scenario; child lifetimes pin the flow

use std::sync::Arc;
use std::time::Duration;

use ballista::datafusion::arrow::array::{Float64Array, Int64Array, RecordBatch};
use ballista::datafusion::prelude::{ParquetReadOptions, SessionContext};
use ballista_core::config::TaskSchedulingPolicy;
use ballista_core::extension::SessionStateExt;
use dataglot_ballista::BallistaContextFactory;

const FILES: usize = 8;
const ROWS_PER_FILE: usize = 12_500;
const GROUPS: i64 = 100;
const CONCURRENT_JOBS: usize = 6;

fn seed_parquet_dir() -> tempfile::TempDir {
    use ballista::datafusion::arrow::datatypes::{DataType, Field, Schema};
    use parquet::arrow::ArrowWriter;

    let tmp = tempfile::tempdir().expect("tempdir");
    let schema = Arc::new(Schema::new(vec![
        Field::new("k", DataType::Int64, false),
        Field::new("v", DataType::Float64, false),
    ]));
    for f in 0..FILES {
        let start = f * ROWS_PER_FILE;
        #[allow(clippy::cast_possible_wrap)]
        let globals = (start..start + ROWS_PER_FILE).map(|g| g as i64);
        #[allow(clippy::cast_precision_loss)]
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

async fn registered_executors(api: std::net::SocketAddr) -> usize {
    let v = get_json(api, "/api/executors").await;
    v.as_array()
        .map(Vec::len)
        .or_else(|| v["executors"].as_array().map(Vec::len))
        .unwrap_or(0)
}

/// Assert one query's result carries every group exactly once with the
/// closed-form count + sum.
fn assert_exact_groups(batches: &[RecordBatch], tag: usize) {
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
        "job {tag}: every group must survive exactly once under saturation"
    );
    #[allow(clippy::cast_possible_wrap)]
    let per_group = (FILES * ROWS_PER_FILE) as i64 / GROUPS;
    for (k, c, s) in groups {
        assert_eq!(c, per_group, "job {tag} group {k}: count");
        #[allow(clippy::cast_precision_loss)]
        let expected = (per_group * k + GROUPS * (999 * per_group / 2)) as f64;
        assert!(
            (s - expected).abs() < 1e-6,
            "job {tag} group {k}: sum {s} != {expected}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn saturated_scheduler_queues_and_drains() {
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

    // ---- two subprocess executors, one slot each = 2 total slots ----------
    let creds = tempfile::NamedTempFile::new().expect("creds tmp");
    std::fs::write(creds.path(), br#"{"kind": "static", "entries": {}}"#).expect("creds");
    let catalogs = tempfile::NamedTempFile::new().expect("catalogs tmp");
    std::fs::write(catalogs.path(), b"{}").expect("catalogs");

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
    assert_eq!(n, 2, "both executors must register (2 total slots)");

    // ---- fire more concurrent jobs than slots -----------------------------
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
    let ctx = Arc::new(ctx);

    // CONCURRENT_JOBS (6) multi-stage GROUP BY jobs against 2 slots: at most
    // two execute at a time; the rest must queue in the scheduler and drain
    // as slots free. If the scheduler deadlocks or rejects queued jobs under
    // contention, the timeout below fires with diagnostics.
    let mut handles = Vec::with_capacity(CONCURRENT_JOBS);
    for job in 0..CONCURRENT_JOBS {
        let ctx = Arc::clone(&ctx);
        handles.push(tokio::spawn(async move {
            let batches = ctx
                .sql("SELECT k, COUNT(*) AS c, SUM(v) AS s FROM wide GROUP BY k ORDER BY k")
                .await
                .map_err(|e| format!("job {job} plan: {e}"))?
                .collect()
                .await
                .map_err(|e| format!("job {job} execute: {e}"))?;
            Ok::<(usize, Vec<RecordBatch>), String>((job, batches))
        }));
    }

    let all = async {
        let mut out = Vec::with_capacity(CONCURRENT_JOBS);
        for h in handles {
            out.push(h.await.expect("task join")?);
        }
        Ok::<Vec<(usize, Vec<RecordBatch>)>, String>(out)
    };

    let results = match tokio::time::timeout(Duration::from_mins(4), all).await {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => {
            let jobs = get_json(api_addr, "/api/jobs").await;
            let _ = exec_a.kill().await;
            let _ = exec_b.kill().await;
            panic!("a saturated job failed instead of queuing: {e}\njobs: {jobs}");
        }
        Err(_) => {
            let jobs = get_json(api_addr, "/api/jobs").await;
            let _ = exec_a.kill().await;
            let _ = exec_b.kill().await;
            panic!(
                "{CONCURRENT_JOBS} concurrent jobs against 2 slots did not all drain in 240s \
                 — the scheduler likely wedged under saturation instead of queuing/draining \
.\njobs: {jobs}\nexecutor A:\n{}\nexecutor B:\n{}",
                drain_output(&mut exec_a).await,
                drain_output(&mut exec_b).await
            );
        }
    };

    // Every queued job drained AND returned correct results.
    assert_eq!(results.len(), CONCURRENT_JOBS, "all jobs must complete");
    for (job, batches) in &results {
        assert_exact_groups(batches, *job);
    }

    let _ = exec_a.kill().await;
    let _ = exec_b.kill().await;
}

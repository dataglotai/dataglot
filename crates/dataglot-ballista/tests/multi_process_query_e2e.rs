//! Multi-process distributed **query** e2e + executor failure/recovery
//! ( — the last two gaps from the 2026-07-11 coverage audit).
//!
//! `executor_multi_process_federation.rs` (slice 5a.2) proved the
//! executor *binary* boots and registers; `multi_process_cluster.rs`
//! (slice 8.2a) proved a compose cluster registers — but nothing ever
//! ran a query where the work executes in a **separate process**. The
//! codec/credential path on a subprocess executor is genuinely
//! different from in-process standalone (the executor rebuilds
//! providers from its own `--catalogs-config`), which is exactly what
//! these tests pin.
//!
//! Harness shape:
//! 1. Postgres testcontainer, seeded with the same `customers` table
//!    the codec e2e uses.
//! 2. Scheduler **from a state carrying the federation codecs**
//!    (`new_standalone_scheduler_from_state` — codec parity with the
//!    client) and **no in-process executor**.
//! 3. `dataglot-ballista-executor` spawned as a real subprocess with a
//!    `--catalogs-config` naming the same connector the client-side
//!    registry uses (the envelope's name must resolve on both sides).
//! 4. Client `SessionContext` minted via `upgrade_for_ballista` — the
//!    codec-preserving path ('s lesson).
//!
//! The recovery test additionally kills the executor subprocess,
//! asserts the scheduler+client survive (query errors or times out —
//! never hangs the harness or kills anything else), then spawns a
//! fresh executor and asserts the next query succeeds.

#![allow(clippy::too_many_lines)] // linear scenarios; container/child lifetimes pin the flow

use std::sync::Arc;
use std::time::Duration;

use ballista::datafusion::prelude::SessionContext;
use ballista_core::config::TaskSchedulingPolicy;
use ballista_core::extension::SessionStateExt;
use datafusion_proto::logical_plan::LogicalExtensionCodec;
use datafusion_proto::physical_plan::PhysicalExtensionCodec;
use dataglot_ballista::{
    BallistaContextFactory, BallistaPhysicalExtensionCodec, FederationLogicalCodec,
};
use dataglot_core::SessionConfig;
use dataglot_federation::{
    postgres::PostgresConnector, DynConnectorRegistry, InMemoryConnectorRegistry, SQLExecutor,
};
use testcontainers::runners::AsyncRunner;
use testcontainers_modules::postgres::Postgres;
use tokio_postgres::NoTls;

const CONNECTOR_NAME: &str = "pg_demo";

const SEED_SQL: &str = "
    CREATE TABLE public.customers (
        id     INT PRIMARY KEY,
        region VARCHAR(32) NOT NULL,
        name   VARCHAR(64) NOT NULL
    );
    INSERT INTO public.customers (id, region, name) VALUES
        (1, 'EU', 'Alice'),
        (2, 'EU', 'Bob'),
        (3, 'US', 'Carol'),
        (4, 'EU', 'Dave'),
        (5, 'US', 'Eve');
";

/// Everything a test needs from the booted harness. Field order is
/// drop order: context/connector first, executor child before the
/// container so `kill_on_drop` fires while the network target exists.
struct Harness {
    ctx: SessionContext,
    api_addr: std::net::SocketAddr,
    _pg: Arc<PostgresConnector>,
    executor: tokio::process::Child,
    scheduler_host: String,
    scheduler_port: u16,
    creds_file: tempfile::NamedTempFile,
    catalogs_file: tempfile::NamedTempFile,
    _container: testcontainers::ContainerAsync<Postgres>,
}

/// Spawn the executor binary against `scheduler` with the given config
/// files. Extracted so the recovery test can respawn.
fn spawn_executor(
    scheduler_host: &str,
    scheduler_port: u16,
    creds: &std::path::Path,
    catalogs: &std::path::Path,
) -> tokio::process::Child {
    let bin = assert_cmd::cargo::cargo_bin("dataglot-ballista-executor");
    let ports = free_ports(2); // distinct bind + grpc ports
    let (bind_port, bind_grpc_port) = (ports[0], ports[1]);
    tokio::process::Command::new(&bin)
        .args([
            "--scheduler-host",
            scheduler_host,
            "--scheduler-port",
            &scheduler_port.to_string(),
            "--bind-host",
            "127.0.0.1",
            "--bind-port",
            &bind_port.to_string(),
            "--bind-grpc-port",
            &bind_grpc_port.to_string(),
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

/// Read whatever the (dead or dying) executor wrote to stderr+stdout.
/// The binary's tracing subscriber writes to stdout, so both matter.
async fn drain_stderr(child: &mut tokio::process::Child) -> String {
    use tokio::io::AsyncReadExt;
    let mut out = String::new();
    if let Some(mut s) = child.stderr.take() {
        let mut buf = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(2), s.read_to_end(&mut buf)).await;
        out.push_str(&String::from_utf8_lossy(&buf));
    }
    if let Some(mut s) = child.stdout.take() {
        let mut buf = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(2), s.read_to_end(&mut buf)).await;
        out.push_str("\n--- stdout ---\n");
        out.push_str(&String::from_utf8_lossy(&buf));
    }
    out
}

/// Allocate `n` *distinct* free ports at once, so the OS can't hand the same
/// port back twice — a real hazard when the executor's `--bind-port` and
/// `--bind-grpc-port` collide, which makes the second bind fail and the
/// executor exit during boot (one of this suite's intermittent-failure modes).
fn free_ports(n: usize) -> Vec<u16> {
    let listeners: Vec<std::net::TcpListener> = (0..n)
        .map(|_| std::net::TcpListener::bind("127.0.0.1:0").expect("bind 0"))
        .collect();
    listeners
        .iter()
        .map(|l| l.local_addr().expect("addr").port())
        .collect()
}

/// The federation query both tests run — same shape as the codec e2e:
/// predicate pushes to the source, three EU rows come back.
const QUERY: &str = "SELECT id, name FROM customers WHERE region = 'EU' ORDER BY id";

async fn run_query(ctx: &SessionContext) -> Result<Vec<(i32, String)>, String> {
    use ballista::datafusion::arrow::array::{Int32Array, StringArray};
    let df = ctx.sql(QUERY).await.map_err(|e| e.to_string())?;
    let batches = df.collect().await.map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for b in &batches {
        let ids = b
            .column(0)
            .as_any()
            .downcast_ref::<Int32Array>()
            .ok_or("id col type")?;
        let names = b
            .column(1)
            .as_any()
            .downcast_ref::<StringArray>()
            .ok_or("name col type")?;
        for i in 0..b.num_rows() {
            out.push((ids.value(i), names.value(i).to_string()));
        }
    }
    Ok(out)
}

/// Ask the scheduler who is registered (plain HTTP GET, loopback).
async fn probe_executors(api: std::net::SocketAddr) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let Ok(mut stream) = tokio::net::TcpStream::connect(api).await else {
        return "<api unreachable>".to_string();
    };
    let req = format!("GET /api/executors HTTP/1.1\r\nHost: {api}\r\nConnection: close\r\n\r\n");
    if stream.write_all(req.as_bytes()).await.is_err() {
        return "<write failed>".to_string();
    }
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(3), stream.read_to_end(&mut buf)).await;
    String::from_utf8_lossy(&buf)
        .split("\r\n\r\n")
        .nth(1)
        .unwrap_or("<no body>")
        .chars()
        .take(600)
        .collect()
}

/// Has at least one executor registered? The `/api/executors` body is a JSON
/// array — `[]` when empty, `[{…}]` once an executor registers.
async fn any_executor_registered(api: std::net::SocketAddr) -> bool {
    probe_executors(api).await.contains('{')
}

/// Spawn an executor and wait until it actually registers with the scheduler,
/// **respawning if it dies during the handshake**. The upstream executor
/// exits the process on a transient registration blip (a gRPC "Internal
/// error" from the scheduler under load) rather than retrying, so a single
/// unlucky handshake used to fail the whole test. A fresh spawn then
/// registers cleanly. Waiting on the scheduler's own view (`/api/executors`)
/// is also deterministic — no more fixed-sleep guessing about when
/// registration finished.
async fn spawn_registered_executor(
    scheduler_host: &str,
    scheduler_port: u16,
    creds: &std::path::Path,
    catalogs: &std::path::Path,
    api_addr: std::net::SocketAddr,
) -> tokio::process::Child {
    const ATTEMPTS: usize = 4;
    let mut last = String::new();
    for attempt in 1..=ATTEMPTS {
        let mut executor = spawn_executor(scheduler_host, scheduler_port, creds, catalogs);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(25);
        loop {
            if let Some(status) = executor.try_wait().expect("try_wait") {
                last = format!(
                    "attempt {attempt}/{ATTEMPTS}: executor exited during registration \
                     ({status:?}); stderr:\n{}",
                    drain_stderr(&mut executor).await
                );
                eprintln!("{last}");
                break; // respawn
            }
            if any_executor_registered(api_addr).await {
                return executor;
            }
            if tokio::time::Instant::now() >= deadline {
                // Still alive but the API hasn't shown it yet — accept it.
                // The executor exits on registration failure, so a live one
                // has registered; the API probe is a best-effort accelerator.
                return executor;
            }
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
    }
    panic!("executor never registered after {ATTEMPTS} attempts; last:\n{last}");
}

const EXPECTED: &[(i32, &str)] = &[(1, "Alice"), (2, "Bob"), (4, "Dave")];

fn assert_eu_rows(rows: &[(i32, String)]) {
    let got: Vec<(i32, &str)> = rows.iter().map(|(i, n)| (*i, n.as_str())).collect();
    assert_eq!(got, EXPECTED, "EU customers must round-trip the subprocess");
}

/// Boot the whole harness: container + seed, codec-carrying scheduler
/// (no in-process executor), subprocess executor, codec-preserving
/// client context with the federated table registered.
async fn boot_harness() -> Harness {
    // ---- source ---------------------------------------------------------
    let container = Postgres::default().start().await.expect("pg starts");
    let host = container.get_host().await.expect("pg host");
    let port = container.get_host_port_ipv4(5432).await.expect("pg port");
    let dsn = format!("host={host} port={port} user=postgres password=postgres dbname=postgres");
    let (seed, conn) = tokio_postgres::connect(&dsn, NoTls)
        .await
        .expect("seed connect");
    tokio::spawn(async move {
        let _ = conn.await;
    });
    seed.batch_execute(SEED_SQL).await.expect("seed customers");

    // ---- codec-carrying state (client + scheduler share it) -------------
    let pg = Arc::new(
        PostgresConnector::connect(&dsn)
            .await
            .expect("pg connector"),
    );
    let executor_iface: Arc<dyn SQLExecutor> = pg.clone();
    let registry: DynConnectorRegistry = Arc::new(InMemoryConnectorRegistry::from_iter([(
        CONNECTOR_NAME.to_string(),
        executor_iface,
    )]));
    let logical: Arc<dyn LogicalExtensionCodec> =
        Arc::new(FederationLogicalCodec::with_registry(Arc::clone(&registry)));
    let physical: Arc<dyn PhysicalExtensionCodec> = Arc::new(
        dataglot_federation::FederationPlanCodec::with_logical_codec(
            registry,
            Arc::clone(&logical),
        )
        .with_inner_physical_codec(Arc::new(BallistaPhysicalExtensionCodec::default())),
    );
    let factory = BallistaContextFactory::new(SessionConfig::new())
        .with_logical_codec(logical)
        .with_physical_codec(physical);
    let state = factory.build_federated_state();

    // ---- scheduler from state, NO in-process executor --------------------
    // PUSH-staged: the real executor binary boots with Ballista's
    // default PushStaged policy (production scheduler binary pairs the
    // same way). Upstream's pull-staged standalone helper would queue
    // every job forever against a push-mode executor.
    let (scheduler_handle, scheduler_addr) = dataglot_ballista::monitor::boot_scheduler_from_state(
        &state,
        TaskSchedulingPolicy::PushStaged,
        3600,
    )
    .await
    .expect("push-staged scheduler boots from codec-carrying state");
    // Serve the scheduler's REST API so diagnostics can ask "did the
    // executor register?" — splits registration failures from dispatch
    // failures without guessing.
    let api_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("api bind");
    let api_addr = api_listener.local_addr().expect("api addr");
    let router = ballista_scheduler::api::get_routes(Arc::new(scheduler_handle.clone()));
    tokio::spawn(async move {
        let _ = axum::serve(api_listener, router).await;
    });
    let scheduler_host = match scheduler_addr.ip() {
        std::net::IpAddr::V4(ip) => ip.to_string(),
        std::net::IpAddr::V6(ip) => format!("[{ip}]"),
    };

    // ---- subprocess executor ---------------------------------------------
    // The executor's catalogs-config entry name must equal the
    // registry name the client encodes into the envelope — that name
    // is how the executor-side codec rebuilds the connector.
    let creds_file = tempfile::NamedTempFile::new().expect("creds tmp");
    std::fs::write(creds_file.path(), br#"{"kind": "static", "entries": {}}"#).expect("creds");
    let catalogs_file = tempfile::NamedTempFile::new().expect("catalogs tmp");
    std::fs::write(
        catalogs_file.path(),
        serde_json::json!({ CONNECTOR_NAME: { "type": "postgres", "dsn": dsn } }).to_string(),
    )
    .expect("catalogs");
    // Spawn the executor and wait for it to actually register (respawns if it
    // dies mid-handshake on a transient gRPC blip). A silent early exit would
    // otherwise turn into an infinite queue-wait on the first query.
    let executor = spawn_registered_executor(
        &scheduler_host,
        scheduler_addr.port(),
        creds_file.path(),
        catalogs_file.path(),
        api_addr,
    )
    .await;

    // ---- codec-preserving client (the  lesson) ---------------------
    let scheduler_url = format!("http://{scheduler_host}:{}", scheduler_addr.port());
    let client_state = state
        .upgrade_for_ballista(scheduler_url)
        .expect("client state upgrades with codecs intact");
    let ctx = SessionContext::new_with_state(client_state);
    let provider = pg
        .table_provider("public", "customers")
        .await
        .expect("customers provider");
    ctx.register_table("customers", provider)
        .expect("register customers");

    Harness {
        ctx,
        api_addr,
        _pg: pg,
        executor,
        scheduler_host,
        scheduler_port: scheduler_addr.port(),
        creds_file,
        catalogs_file,
        _container: container,
    }
}

/// ** #1** — a federation query executes with the work running
/// in a *separate executor process*: the client's codec envelope names
/// the connector, the subprocess rebuilds it from its own
/// `--catalogs-config`, and the rows round-trip.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires Docker"]
async fn federation_query_executes_on_subprocess_executor() {
    let mut h = boot_harness().await;
    let res = tokio::time::timeout(Duration::from_mins(1), run_query(&h.ctx)).await;
    let diagnostics = if matches!(&res, Ok(Ok(_))) {
        String::new()
    } else {
        let executors = probe_executors(h.api_addr).await;
        let _ = h.executor.kill().await;
        format!(
            "scheduler /api/executors: {executors}\nexecutor output:\n{}",
            drain_stderr(&mut h.executor).await
        )
    };
    let rows = res
        .unwrap_or_else(|_| {
            panic!(
                "query hung 60s — scheduler queued work the executor never \
                 took (registration or codec mismatch). Executor stderr:\n{diagnostics}"
            )
        })
        .unwrap_or_else(|e| panic!("query failed: {e}\nExecutor stderr:\n{diagnostics}"));
    assert_eu_rows(&rows);
    let _ = h.executor.kill().await;
}

/// ** #2** — executor death is survivable and recoverable:
/// after killing the subprocess, a query fails or times out (never
/// wedges the scheduler); after spawning a fresh executor, the next
/// query succeeds.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires Docker"]
async fn executor_death_is_survivable_and_recoverable() {
    let mut h = boot_harness().await;

    // Baseline: healthy round-trip.
    let rows = run_query(&h.ctx).await.expect("baseline query succeeds");
    assert_eu_rows(&rows);

    // Kill the only executor.
    h.executor.kill().await.expect("kill executor");
    let _ = h.executor.wait().await;

    // A query now must fail or time out — the scheduler queues work
    // for executors that never come, so a bounded wait is the correct
    // observation. What it must NOT do is take down the harness.
    let orphaned = tokio::time::timeout(Duration::from_secs(10), run_query(&h.ctx)).await;
    match orphaned {
        Ok(Ok(rows)) => panic!(
            "query cannot succeed with no executor alive, got {} rows",
            rows.len()
        ),
        Ok(Err(e)) => eprintln!("query failed cleanly with no executor: {e}"),
        Err(_) => eprintln!("query timed out with no executor (scheduler queued it)"),
    }

    // Recovery: fresh executor, wait for registration (respawn on a transient
    // handshake failure), query again.
    let mut replacement = spawn_registered_executor(
        &h.scheduler_host,
        h.scheduler_port,
        h.creds_file.path(),
        h.catalogs_file.path(),
        h.api_addr,
    )
    .await;
    let rows = tokio::time::timeout(Duration::from_secs(30), run_query(&h.ctx))
        .await
        .expect("recovery query must not hang")
        .expect("recovery query must succeed once a fresh executor registers");
    assert_eu_rows(&rows);
    let _ = replacement.kill().await;
}

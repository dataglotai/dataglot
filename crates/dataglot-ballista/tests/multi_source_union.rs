//! Phase 2 slice 4c.B — multi-source UNION dispatch.
//!
//! The re-scoped slice 4c (see `docs/phases/phase-2/02-ballista-
//! distributed-execution.md`) proves multi-worker parallelism via N
//! parallel single-partition federated reads against N distinct
//! catalog backends, unioned at the coordinator. Each leg is one
//! `VirtualExecutionPlan` — single-partition by upstream
//! `datafusion-federation 0.5.3` design — but the legs are
//! independent, so Ballista's scheduler dispatches them across
//! worker slots.
//!
//! # What the test asserts (and what it doesn't)
//!
//! - ✅ Correctness: a UNION of four single-table SELECTs against
//!   four independent Postgres backends returns all rows from all
//!   four sources, with the source-tag column preserved.
//! - ✅ Multi-worker dispatch: each leg scans a Postgres-side view
//!   that pays `pg_sleep(SLEEP_S)` once per scan. A fully-serial
//!   scheduler would wall-clock around `SLEEP_S * NUM_SOURCES`
//!   seconds; the test asserts `< (NUM_SOURCES - 1) * SLEEP_S`,
//!   which means "at least one leg ran concurrent with another."
//!   Threshold is intentionally loose — slice 8 owns the strict
//!   ≥5× single-node claim against the TPC-H baseline.
//! - ❌ Per-source split parallelism. A single 100-GB Iceberg table
//!   still runs single-worker until upstream `iceberg-rust` ships
//!   output-partitioning. See spec 02 slice 4c for the rationale.
//!
//! # Docker requirement
//!
//! `#[ignore = "requires Docker"]` — same shape as
//! `ballista_federation_codec.rs`. The `ballista (Phase 2)` CI job
//! runs with `--ignored` to exercise this path.
//!
//! # Why four sources (not two, not eight)
//!
//! Two would be observable parallelism but trivially achievable
//! even on a one-slot scheduler that interleaves I/O. Eight
//! triples CI minutes for diminishing demonstration value on a
//! standalone (1-process, M-slot) cluster. Four lines up with
//! Phase 2 exit-criterion #3's headline ("4-worker cluster") and
//! is the smallest number that's hard to fake.

use std::sync::Arc;
use std::time::{Duration, Instant};

use ballista::datafusion::arrow::array::RecordBatch;
use ballista::datafusion::arrow::util::pretty::pretty_format_batches;
use ballista::datafusion::prelude::SessionContext;
use datafusion_federation::sql::SQLExecutor;
use datafusion_proto::logical_plan::LogicalExtensionCodec;
use datafusion_proto::physical_plan::PhysicalExtensionCodec;
use dataglot_ballista::{BallistaContextFactory, FederationLogicalCodec};
use dataglot_core::SessionConfig;
use dataglot_federation::postgres::PostgresConnector;
use dataglot_federation::{DynConnectorRegistry, FederationPlanCodec, InMemoryConnectorRegistry};
use testcontainers::runners::AsyncRunner;
use testcontainers::ContainerAsync;
use testcontainers_modules::postgres::Postgres;
use tokio_postgres::NoTls;

/// Number of independent Postgres backends in the UNION. See
/// module doc for why four.
const NUM_SOURCES: usize = 4;

/// Per-leg sleep, in seconds. Drives the parallel-dispatch
/// timing assertion: serial total ≈ `NUM_SOURCES * SLEEP_S`,
/// parallel total ≈ `SLEEP_S`.
const SLEEP_S: u64 = 1;

/// Seed SQL for each Postgres backend.
///
/// Two tag-distinct relations per source:
///
/// - `events_<tag>` — the underlying table holding two seed rows
///   tagged by source.
/// - `events_sleep_<tag>` — a VIEW that wraps `events_<tag>` and
///   pays `pg_sleep(SLEEP_S)` once per scan via a `CROSS JOIN`
///   with a one-row sleep subquery.
///
/// Tag-distinct names sidestep the `RemoteTableRef` collision
/// that PR #276 surfaced (four sources sharing a single
/// `public.events` ref confused federation's analyzer). The view
/// is what federation queries; the sleep lets the wall-clock
/// timing assertion prove parallel dispatch.
fn seed_sql(source_tag: &str, sleep_s: u64) -> String {
    let table_name = format!("events_{source_tag}");
    let view_name = format!("events_sleep_{source_tag}");
    format!(
        "
        CREATE TABLE public.{table_name} (
            id         INT PRIMARY KEY,
            source_tag VARCHAR(16) NOT NULL,
            payload    VARCHAR(64) NOT NULL
        );
        INSERT INTO public.{table_name} (id, source_tag, payload) VALUES
            (1, '{source_tag}', '{source_tag}-event-1'),
            (2, '{source_tag}', '{source_tag}-event-2');

        -- `events_sleep_<tag>` pays `pg_sleep({sleep_s})` once per
        -- scan. The LIMIT 1 subquery is the standard trick: the
        -- scalar materialises exactly once when wrapped in a
        -- derived table, so the CROSS JOIN multiplies by exactly
        -- one row. Federation queries this view by name; the
        -- sleep happens server-side, opaque to `DataFusion`.
        CREATE VIEW public.{view_name} AS
        SELECT e.id, e.source_tag, e.payload
        FROM public.{table_name} e
        CROSS JOIN (SELECT pg_sleep({sleep_s}) LIMIT 1) sleep_once;
        "
    )
}

/// Bring up one Postgres container + seed its `events` table.
/// Returns the DSN, the source tag (e.g. `pg_a`) it seeded with,
/// and the running container handle. Caller MUST keep the
/// container handle alive for the duration of the test — the
/// database tears down on `Drop`.
async fn setup_postgres(source_tag: &str) -> (String, ContainerAsync<Postgres>) {
    let container = Postgres::default()
        .start()
        .await
        .expect("postgres container starts");
    let host = container.get_host().await.expect("postgres host resolves");
    let port = container
        .get_host_port_ipv4(5432)
        .await
        .expect("postgres port resolves");

    let dsn = format!("host={host} port={port} user=postgres password=postgres dbname=postgres");

    let (client, connection) = tokio_postgres::connect(&dsn, NoTls)
        .await
        .expect("connect to postgres for seeding");
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            // tokio-postgres errors are credential-free.
            eprintln!("seed connection error: {e}");
        }
    });

    client
        .batch_execute(&seed_sql(source_tag, SLEEP_S))
        .await
        .expect("seed events table + sleep view");

    (dsn, container)
}

/// Bring up all `NUM_SOURCES` Postgres containers in parallel
/// (so the test doesn't pay serialised container-start latency)
/// and register them as catalogs on a single Ballista cluster.
/// Returns the session context + the live connector + container
/// handles (drops on test exit close pg connections).
async fn build_multi_source_ballista_session() -> (
    SessionContext,
    Vec<Arc<PostgresConnector>>,
    Vec<ContainerAsync<Postgres>>,
) {
    // Source tags `pg_a` ... `pg_d` — opaque catalog names that
    // match the `[catalogs.*]` config shape an operator would
    // declare. Drop one if `NUM_SOURCES` shrinks; ditto add one
    // if it grows.
    let source_tags: Vec<&str> = (0..NUM_SOURCES)
        .map(|i| match i {
            0 => "pg_a",
            1 => "pg_b",
            2 => "pg_c",
            3 => "pg_d",
            _ => panic!("extend the source_tag list if NUM_SOURCES > 4"),
        })
        .collect();

    // Bring up containers concurrently — testcontainers' AsyncRunner
    // is happy to overlap pulls + starts. Serial bring-up would add
    // ~4-8 s of wall-clock to the test on a cold pull.
    let setup_futures = source_tags.iter().map(|tag| setup_postgres(tag));
    let setups: Vec<(String, ContainerAsync<Postgres>)> =
        futures::future::join_all(setup_futures).await;

    let mut connectors: Vec<Arc<PostgresConnector>> = Vec::with_capacity(NUM_SOURCES);
    let mut containers: Vec<ContainerAsync<Postgres>> = Vec::with_capacity(NUM_SOURCES);
    let mut executors: Vec<(String, Arc<dyn SQLExecutor>)> = Vec::with_capacity(NUM_SOURCES);

    for ((tag, _idx), (dsn, container)) in source_tags.iter().zip(0..).zip(setups) {
        let pg = Arc::new(
            PostgresConnector::connect(&dsn)
                .await
                .unwrap_or_else(|e| panic!("postgres connector for {tag} connects: {e}")),
        );
        let executor: Arc<dyn SQLExecutor> = pg.clone();
        executors.push(((*tag).to_string(), executor));
        connectors.push(pg);
        containers.push(container);
    }

    let registry: DynConnectorRegistry =
        Arc::new(executors.into_iter().collect::<InMemoryConnectorRegistry>());

    let logical_codec: Arc<dyn LogicalExtensionCodec> =
        Arc::new(FederationLogicalCodec::with_registry(Arc::clone(&registry)));
    let physical_codec: Arc<dyn PhysicalExtensionCodec> = Arc::new(
        FederationPlanCodec::with_logical_codec(Arc::clone(&registry), Arc::clone(&logical_codec))
            .with_inner_physical_codec(Arc::new(
                ballista_core::serde::BallistaPhysicalExtensionCodec::default(),
            )),
    );

    // `with_standalone_parallelism(NUM_SOURCES)` is the hook that
    // gives the in-process executor enough task slots to fan out
    // the UNION's N legs. The default (2) would bottleneck the
    // timing assertion at half the legs running concurrently.
    let factory = BallistaContextFactory::new(SessionConfig::new())
        .with_standalone_parallelism(NUM_SOURCES)
        .with_logical_codec(logical_codec)
        .with_physical_codec(physical_codec);
    let cluster = factory
        .boot_standalone_cluster()
        .await
        .expect("ballista standalone boots");

    let ctx = cluster.create_session();
    for (idx, pg) in connectors.iter().enumerate() {
        // The DataFusion-side registration name (`events_<tag>`)
        // is what the UNION query body references; the Postgres-
        // side table the federation provider points at is the
        // `events_sleep_<tag>` view — so each scan pays the
        // server-side `pg_sleep(SLEEP_S)` and the wall-clock
        // timing assertion measures real parallel dispatch.
        // RemoteTableRef-side names are still tag-distinct, so
        // the PR #276 collision workaround stays intact.
        let df_table = format!("events_{}", source_tags[idx]);
        let pg_view = format!("events_sleep_{}", source_tags[idx]);
        let provider = pg
            .table_provider("public", &pg_view)
            .await
            .unwrap_or_else(|e| panic!("table provider for {}: {e}", source_tags[idx]));
        ctx.register_table(&df_table, provider)
            .unwrap_or_else(|e| panic!("register table {df_table}: {e}"));
    }

    (ctx, connectors, containers)
}

/// Build the UNION query body. Each leg targets a registered
/// table whose name embeds the source tag — same name on both
/// the `DataFusion` side and the Postgres side so the federation
/// unparser produces self-consistent SQL.
fn union_all_query() -> String {
    let legs: Vec<String> = ["pg_a", "pg_b", "pg_c", "pg_d"]
        .iter()
        .map(|tag| format!("SELECT id, source_tag, payload FROM events_{tag}"))
        .collect();
    legs.join(" UNION ALL ")
}

/// **The wedge test.** Multi-source UNION across four Postgres
/// backends, dispatched in parallel across four worker slots.
/// Asserts correctness (all rows from all sources present) and
/// parallelism (wall-clock demonstrably faster than fully serial).
#[tokio::test]
#[ignore = "requires Docker"]
async fn multi_source_union_parallel_dispatch() {
    let (ctx, _connectors, _containers) = build_multi_source_ballista_session().await;

    // Warm-up query — first execution pays cluster-bring-up + plan
    // compilation. Without this the parallel-timing assertion can
    // fail on slow CI runners because the first leg amortises
    // boot cost.
    let _ = ctx
        .sql("SELECT 1")
        .await
        .expect("warm-up plan")
        .collect()
        .await
        .expect("warm-up execute");

    let sql = union_all_query();
    let start = Instant::now();
    let batches = ctx
        .sql(&sql)
        .await
        .expect("plan UNION")
        .collect()
        .await
        .expect("execute UNION");
    let elapsed = start.elapsed();

    let total_rows: usize = batches.iter().map(RecordBatch::num_rows).sum();
    let printed = pretty_format_batches(&batches)
        .expect("format batches")
        .to_string();

    eprintln!("=== multi-source UNION result (elapsed {elapsed:?}) ===\n{printed}");

    // 2 rows per source × NUM_SOURCES sources = 8 rows total.
    assert_eq!(
        total_rows,
        2 * NUM_SOURCES,
        "expected {} rows ({} per source × {}), got {total_rows}:\n{printed}",
        2 * NUM_SOURCES,
        2,
        NUM_SOURCES
    );

    // Each source-tag must appear — proves the codec round-tripped
    // all four legs through the wire and they all returned data.
    for tag in ["pg_a", "pg_b", "pg_c", "pg_d"] {
        assert!(
            printed.contains(tag),
            "expected source_tag '{tag}' in result, got:\n{printed}"
        );
    }

    // Parallel-dispatch timing assertion. Each leg scans the
    // `events_sleep_<tag>` view, which pays `pg_sleep(SLEEP_S)`
    // on every scan, so:
    //   - fully serial: ~SLEEP_S * NUM_SOURCES seconds
    //   - fully parallel: ~SLEEP_S seconds (+ DataFusion overhead)
    //   - ≥2-way concurrency: < (NUM_SOURCES - 1) * SLEEP_S
    //
    // Threshold = `(NUM_SOURCES - 1) * SLEEP_S` so the assertion
    // is "at least one leg ran concurrent with another." Slice 8
    // owns the strict ≥5× single-node claim against the TPC-H
    // baseline; this test's job is to prove the standalone
    // scheduler honours `with_standalone_parallelism` and doesn't
    // silently serialise.
    let serial_threshold = Duration::from_secs(((NUM_SOURCES - 1) as u64) * SLEEP_S);
    assert!(
        elapsed < serial_threshold,
        "UNION wall-clock {elapsed:?} ≥ serial threshold {serial_threshold:?} — \
         Ballista's standalone scheduler appears to be serialising the {NUM_SOURCES} \
         federated legs instead of dispatching them across the {NUM_SOURCES} task \
         slots. Investigate `with_standalone_parallelism` propagation through \
         `BallistaContextFactory`."
    );
}

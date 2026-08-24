//! Phase 2 slice 4b.3 — end-to-end validation that federation
//! queries survive the Ballista wire format.
//!
//! Boots Postgres in a testcontainer, registers it via
//! `dataglot-federation::PostgresConnector`, builds a registry-aware
//! [`FederationLogicalCodec`](dataglot_ballista::FederationLogicalCodec),
//! and runs a federation query through the standalone Ballista
//! cluster. Asserts the result matches what the single-node path
//! produces — proving the new codec's encode → wire → decode
//! round-trip is correct on a live federated plan.
//!
//! # What the test asserts (and what it doesn't)
//!
//! - ✅ A federation `SELECT` against Postgres returns the same rows
//!   when run through Ballista's standalone cluster as it does
//!   through the single-node `SessionContext` factory.
//! - ✅ The codec exercises the real
//!   `find_name_by_compute_context` / `lookup_planner` paths on the
//!   registry — slice 4b.3's compute_context-keyed reverse-lookup
//!   validated in anger. (Slice 4b.1 originally relied on
//!   `Arc::ptr_eq`; the first run of this test on PR #272 surfaced
//!   that gamble as a false negative, which is what slice 4b.3
//!   replaced.)
//! - ❌ Multi-source distributed JOIN — slice 4c work; this test
//!   uses one federation source.
//! - ❌ Multi-worker parallelism — the standalone cluster is one
//!   coord + one executor; split-level parallelism is slice 4c.
//!
//! # Docker requirement
//!
//! `#[ignore = "requires Docker"]` — same shape as
//! `dataglot-tests/tests/e2e/phase0_gate.rs`. The `ballista (Phase 2)`
//! CI job runs with `--ignored` to exercise this path; PR-level
//! ballista CI without Docker still benefits from the existing
//! unit tests + the no-Docker smoke harness.

use std::sync::Arc;

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

const CONNECTOR_NAME: &str = "pg_demo";

/// Mirrors the Phase 0 exit-gate seed — same five-row `customers`
/// table so the EU-filter expectation is identical across this
/// test and `dataglot-tests/tests/e2e/phase0_gate.rs`. Keeping the
/// seed identical lets us reuse the same row-count assertion shape.
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

/// Bring up Postgres + seed `public.customers`. Returns the DSN
/// and the running container handle (caller must hold the latter
/// so the database doesn't get torn down before the test finishes).
async fn setup_postgres() -> (String, ContainerAsync<Postgres>) {
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
        .batch_execute(SEED_SQL)
        .await
        .expect("seed customers table");

    (dsn, container)
}

/// Boot a Ballista cluster with the federation-aware codec and
/// register the Postgres `customers` table on it. Returns the
/// session context for assertion-time queries plus the connector
/// (caller holds it alive — drops cascade to close pg connections).
async fn build_ballista_session_with_postgres(
    dsn: &str,
) -> (SessionContext, Arc<PostgresConnector>) {
    let pg = Arc::new(
        PostgresConnector::connect(dsn)
            .await
            .expect("postgres connector connects"),
    );

    // `Arc<PostgresConnector>` coerces to `Arc<dyn SQLExecutor>`
    // because `PostgresConnector` implements `SQLExecutor`. The
    // registry holds the executor by name; at construction it also
    // builds a `compute_context → name` index from
    // `PostgresConnector::compute_context()` — that index is what
    // the codec's slice-4b.3 reverse-lookup queries on encode.
    let executor: Arc<dyn SQLExecutor> = pg.clone();
    let registry: DynConnectorRegistry = Arc::new(InMemoryConnectorRegistry::from_iter([(
        CONNECTOR_NAME.to_string(),
        executor,
    )]));

    let logical_codec: Arc<dyn LogicalExtensionCodec> =
        Arc::new(FederationLogicalCodec::with_registry(Arc::clone(&registry)));

    // Slice 4b.4 — the physical codec teaches Ballista how to
    // round-trip `VirtualExecutionPlan` + `SchemaCastScanExec` +
    // `CooperativeExec` across the scheduler→executor wire. Without
    // it, the SELECT path errors with "unsupported plan type:
    // SchemaCastScanExec" once the scheduler tries to ship the
    // physical plan over. EXPLAIN survives without it because the
    // plan never leaves the coordinator.
    //
    // The codec WRAPS `BallistaPhysicalExtensionCodec` rather than
    // replacing it — Ballista's own `ShuffleWriterExec`,
    // `ShuffleReaderExec`, `SortShuffleWriterExec`, and
    // `UnresolvedShuffleExec` still need to round-trip through the
    // scheduler→executor wire too. The first slice-4b.4 push
    // (938f067) missed this; ea5e9c2 fixed it.
    //
    // The codec ALSO threads our `FederationLogicalCodec` in as the
    // inner logical codec, not `DefaultLogicalExtensionCodec` —
    // because `VirtualExecutionPlan.plan()`'s inner `LogicalPlan`
    // still contains a `TableScan` whose source is a
    // `FederatedTableProviderAdaptor`. The default logical codec
    // hits "LogicalExtensionCodec is not provided" on it; our
    // codec knows how to encode it via the connector-name envelope.
    // ea5e9c2's first push missed this — surfaced as the next CI
    // failure shape.
    let physical_codec: Arc<dyn PhysicalExtensionCodec> = Arc::new(
        FederationPlanCodec::with_logical_codec(Arc::clone(&registry), Arc::clone(&logical_codec))
            .with_inner_physical_codec(Arc::new(
                ballista_core::serde::BallistaPhysicalExtensionCodec::default(),
            )),
    );

    // The factory's `with_logical_codec` (slice 4a) + `with_physical_codec`
    // (slice 4b.4) hooks are the production plug points. Once the
    // standalone cluster boots, every session it mints inherits both
    // codec configurations.
    let factory = BallistaContextFactory::new(SessionConfig::new())
        .with_logical_codec(logical_codec)
        .with_physical_codec(physical_codec);
    let cluster = factory
        .boot_standalone_cluster()
        .await
        .expect("ballista standalone boots");

    let ctx = cluster.create_session();
    let pg_table = pg
        .table_provider("public", "customers")
        .await
        .expect("customers table provider resolves");
    ctx.register_table("customers", pg_table)
        .expect("register customers table");

    // Also register the connector as a *catalog* named `pg` — the way
    // `DataglotServer::create_session` wires `[catalogs.*]` — so tests can
    // exercise catalog-qualified `pg.public.customers` references, not just
    // the bare `customers` table. (Both registrations coexist harmlessly.)
    let pg_catalog = pg
        .as_catalog_provider()
        .await
        .expect("postgres catalog provider builds");
    ctx.register_catalog("pg", pg_catalog);

    (ctx, pg)
}

/// **The wedge test.** Federation `SELECT` against Postgres,
/// running through the Ballista standalone cluster with the
/// registry-aware codec. If the slice-4b codec works on the wire,
/// this returns the same three EU rows the single-node Phase 0
/// gate produces. If the codec is broken — encode error, decode
/// mismatch, lookup miss — the query fails before returning data
/// and the assertion fires.
#[tokio::test]
#[ignore = "requires Docker"]
async fn federation_select_through_ballista_returns_eu_customers() {
    let (dsn, _container) = setup_postgres().await;
    let (ctx, _pg) = build_ballista_session_with_postgres(&dsn).await;

    let batches = ctx
        .sql(
            "SELECT id, region, name
             FROM customers
             WHERE region = 'EU'
             ORDER BY id",
        )
        .await
        .expect("plan federation SELECT through Ballista")
        .collect()
        .await
        .expect(
            "execute federation SELECT through Ballista — \
                 if this errors, the codec is broken on the wire",
        );

    let total_rows: usize = batches.iter().map(RecordBatch::num_rows).sum();
    let printed = pretty_format_batches(&batches)
        .expect("format result batches")
        .to_string();

    // Same expectation as `dataglot-tests/tests/e2e/phase0_gate.rs`:
    // three EU rows (Alice, Bob, Dave). If we got fewer, the
    // federation predicate didn't make it through the codec; if we
    // got more, the WHERE evaluation broke; if we got names that
    // aren't in {Alice, Bob, Dave}, something deeper is wrong.
    assert_eq!(
        total_rows, 3,
        "expected exactly 3 EU rows, got {total_rows}:\n{printed}"
    );
    for needle in ["Alice", "Bob", "Dave"] {
        assert!(
            printed.contains(needle),
            "expected EU customer {needle} in result, got:\n{printed}"
        );
    }
    // US customers must NOT leak through the WHERE.
    assert!(
        !printed.contains("Carol"),
        "US row Carol leaked through the EU filter:\n{printed}"
    );
    assert!(
        !printed.contains("Eve"),
        "US row Eve leaked through the EU filter:\n{printed}"
    );
}

/// **Catalog-qualified regression.** The same federation `SELECT`, but
/// referencing the table by its full three-part `pg.public.customers`
/// name (the form the testbench sidebar and a real `psql` session use),
/// not the bare `customers`.
///
/// On the coordinator, `PostgresConnector::table_provider` builds a
/// *two-part* `public.customers` `RemoteTableRef` — the Dataglot catalog
/// name `pg` is a federation-only concept Postgres knows nothing about.
/// But `datafusion-proto` reconstructs the coordinator's three-part
/// `TableReference` from the wire and hands it to the logical codec on
/// the executor; before the fix in `codec.rs`, that catalog qualifier
/// was passed straight through and the pushed SQL became
/// `FROM "pg"."public"."customers"`, which Postgres rejects with
/// `cross-database references are not implemented`. The fix strips the
/// catalog on decode to match single-node; this test pins it.
#[tokio::test]
#[ignore = "requires Docker"]
async fn catalog_qualified_federation_select_through_ballista_returns_eu_customers() {
    let (dsn, _container) = setup_postgres().await;
    let (ctx, _pg) = build_ballista_session_with_postgres(&dsn).await;

    let batches = ctx
        .sql(
            "SELECT id, region, name
             FROM pg.public.customers
             WHERE region = 'EU'
             ORDER BY id",
        )
        .await
        .expect("plan catalog-qualified federation SELECT through Ballista")
        .collect()
        .await
        .expect(
            "execute catalog-qualified federation SELECT through Ballista — \
             if this errors with `cross-database references are not \
             implemented`, the codec failed to strip the catalog qualifier \
             before pushing SQL to Postgres",
        );

    let total_rows: usize = batches.iter().map(RecordBatch::num_rows).sum();
    let printed = pretty_format_batches(&batches)
        .expect("format result batches")
        .to_string();

    // Identical expectation to the bare-name wedge test: three EU rows,
    // no US leakage. The only difference is the three-part reference.
    assert_eq!(
        total_rows, 3,
        "expected exactly 3 EU rows from pg.public.customers, got {total_rows}:\n{printed}"
    );
    for needle in ["Alice", "Bob", "Dave"] {
        assert!(
            printed.contains(needle),
            "expected EU customer {needle} in result, got:\n{printed}"
        );
    }
    assert!(
        !printed.contains("Carol") && !printed.contains("Eve"),
        "US row leaked through the EU filter:\n{printed}"
    );
}

/// Plan-shape check: the same query planned through the cluster
/// must contain the federation `VirtualExecutionPlan` node in its
/// EXPLAIN output. If the optimizer somehow bypassed federation —
/// e.g. by collapsing the query to a local scan — the codec
/// wouldn't be exercised and the previous test would pass for the
/// wrong reasons. This test pins the "we're actually federating"
/// invariant.
#[tokio::test]
#[ignore = "requires Docker"]
async fn federation_plan_routes_through_virtual_execution_plan() {
    let (dsn, _container) = setup_postgres().await;
    let (ctx, _pg) = build_ballista_session_with_postgres(&dsn).await;

    let explain_df = ctx
        .sql(
            "EXPLAIN
             SELECT id, region, name
             FROM customers
             WHERE region = 'EU'",
        )
        .await
        .expect("EXPLAIN parses");
    let explain_batches = explain_df.collect().await.expect("EXPLAIN runs");
    let explain_str = pretty_format_batches(&explain_batches)
        .expect("format EXPLAIN")
        .to_string();
    let explain_lower = explain_str.to_lowercase();

    eprintln!("=== federation EXPLAIN ===\n{explain_str}");

    // Federation routes through `VirtualExecutionPlan` (the
    // physical-side wrapper that owns the remote SQL). Slice
    // 4b.2's codec round-trips the wrapping `FederatedPlanNode`
    // — its EXPLAIN serialization should still surface the
    // physical wrapper name in the plan.
    assert!(
        explain_lower.contains("virtualexecutionplan")
            || explain_lower.contains("sql_federation_exec"),
        "expected federation virtual exec node in EXPLAIN — the codec \
         appears to have failed to reconstruct the federated plan:\n{explain_str}"
    );
}

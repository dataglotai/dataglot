//! Phase 2 slice 6 — governance-on-workers parity.
//!
//! Strategy v3.0 exit criterion line 1: *"same results and governance
//! as single node."* Phase 1 bakes column-masking and row-filter
//! enforcement into the `LogicalPlan` at optimization time — masks
//! become `Projection.expr` rewrites, row filters become a `Filter`
//! wrapped around the matching `TableScan`. Both shapes are stock
//! `DataFusion` plan nodes (no federation / Ballista extensions),
//! so the hypothesis going in is that `datafusion-proto`'s default
//! `LogicalPlanNode` encoding round-trips them across Ballista's
//! wire untouched. This test pins that hypothesis: build the *same*
//! `PolicyOptimizerRule` against two sessions — one single-node,
//! one driving a multi-slot Ballista standalone cluster — run the
//! same query, and assert the pretty-printed output matches
//! row-by-row.
//!
//! # What the test asserts (and what it doesn't)
//!
//! - ✅ **Parity**: single-node and Ballista produce byte-identical
//!   pretty-printed output for a query against a table covered by
//!   both a column mask and a row filter.
//! - ✅ **Policy fired**: the masked literal is present, real
//!   emails are not, and the row-filter predicate has trimmed the
//!   result down to the matching row.
//! - ❌ **Identity-aware routing.** The MVP enforcers ignore
//!   identity; once the typed-tag system from Architecture
//!   Decisions §10 lands, a sibling test will exercise the
//!   per-identity branch. Today every caller sees the same masked
//!   shape — which is enough to lock in the codec-level guarantee.
//! - ❌ **Multi-process worker parity.** The standalone cluster
//!   runs everything in one process; slice 5's HA scheduler is
//!   what proves cross-host parity. The serialization path is the
//!   same shape (proto + extension codec), so this test's pass
//!   is a necessary but not sufficient condition for multi-process.
//!
//! # Docker requirement
//!
//! `#[ignore = "requires Docker"]` — same shape as the rest of the
//! `dataglot-ballista` integration tests. The `ballista (Phase 2)`
//! CI job runs with `--ignored` to exercise this path.

use std::sync::Arc;

use ballista::datafusion::arrow::array::RecordBatch;
use ballista::datafusion::arrow::util::pretty::pretty_format_batches;
use ballista::datafusion::execution::session_state::SessionStateBuilder;
use ballista::datafusion::logical_expr::{col, lit};
use ballista::datafusion::optimizer::OptimizerRule;
use ballista::datafusion::prelude::SessionContext;
use ballista::datafusion::sql::TableReference;
use datafusion_federation::sql::SQLExecutor;
use datafusion_proto::logical_plan::LogicalExtensionCodec;
use datafusion_proto::physical_plan::PhysicalExtensionCodec;
use dataglot_ballista::{BallistaContextFactory, FederationLogicalCodec};
use dataglot_core::{SessionConfig, SessionContextFactory};
use dataglot_federation::postgres::PostgresConnector;
use dataglot_federation::{DynConnectorRegistry, FederationPlanCodec, InMemoryConnectorRegistry};
use dataglot_policy::{
    ColumnMask, ColumnMaskingEnforcer, CompositeEnforcer, PolicyEnforcer, PolicyOptimizerRule,
    RowFilter, RowFilterEnforcer,
};
use testcontainers::runners::AsyncRunner;
use testcontainers::ContainerAsync;
use testcontainers_modules::postgres::Postgres;
use tokio_postgres::NoTls;

/// Two task slots is the minimum that proves the standalone executor
/// fans out independently of how many physical CPUs the runner has.
/// Slice 6 is about plan-shape parity, not throughput — bumping this
/// to 4 wouldn't change what the assertion proves.
const STANDALONE_PARALLELISM: usize = 2;

/// Mirrors the `users` table the governance demo at
/// `examples/demo/dataglot-with-governance.toml` exercises: three
/// rows so the row-filter assertion can fail loudly if more or fewer
/// rows survive. Same column shape (id, name, email) the demo's
/// `mask-pii-analyst` + `filter-pii-analyst` rules target.
const SEED_SQL: &str = r"
CREATE TABLE public.users (
    id    INT PRIMARY KEY,
    name  VARCHAR(32) NOT NULL,
    email VARCHAR(64) NOT NULL
);
INSERT INTO public.users (id, name, email) VALUES
    (1, 'Alice', 'alice@example.com'),
    (2, 'Bob',   'bob@example.com'),
    (3, 'Carol', 'carol@example.com');
";

/// Query that touches every rule:
/// - `email` is masked in the projection.
/// - `users` is filtered to only Bob's row.
/// - `ORDER BY id` makes pretty-printed output deterministic so the
///   parity assertion compares structure, not row order from
///   parallel scans.
const QUERY: &str = "SELECT id, name, email FROM users ORDER BY id";

/// Bring up one Postgres container + seed the demo `users` table.
/// Returns the DSN the federation connectors use. Caller MUST keep
/// the container handle alive — the database tears down on `Drop`.
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
            eprintln!("seed connection error: {e}");
        }
    });

    client
        .batch_execute(SEED_SQL)
        .await
        .expect("seed users table");

    (dsn, container)
}

/// Build the composite `PolicyOptimizerRule` shared by both sessions.
/// Two enforcers stacked via `CompositeEnforcer`:
///
/// 1. **Column mask** — `users.email` is rewritten to the literal
///    `'***@example.com'` inside every `Projection` that references
///    it. This mirrors `mask-pii-analyst` in the governance demo.
///
/// 2. **Row filter** — `users` is wrapped in a `Filter` that retains
///    only rows where `email = 'bob@example.com'`. Mirrors
///    `filter-pii-analyst`.
///
/// Note: the row-filter predicate references the *original* `email`
/// value — masking never rewrites predicates (`Filter`/`Join` are
/// skipped), so an admin RLS predicate always evaluates on real data.
/// Masking reaches output-reaching expressions (projection, aggregate,
/// sort), which is what closed the aggregate bypass in.
fn build_policy_rule() -> Arc<PolicyOptimizerRule> {
    let mask = ColumnMaskingEnforcer::new([ColumnMask {
        table: TableReference::bare("users"),
        column: "email".to_string(),
        mask: lit("***@example.com"),
        org: None,
        groups: None,
    }])
    .expect("mask enforcer builds");

    let filter = RowFilterEnforcer::new([RowFilter {
        table: TableReference::bare("users"),
        predicate: col("email").eq(lit("bob@example.com")),
        org: None,
        groups: None,
    }])
    .expect("filter enforcer builds");

    let composite = CompositeEnforcer::new(vec![
        Arc::new(mask) as Arc<dyn PolicyEnforcer>,
        Arc::new(filter) as Arc<dyn PolicyEnforcer>,
    ]);

    Arc::new(PolicyOptimizerRule::new(Arc::new(composite)))
}

/// Mirror of [`dataglot_server::DataglotServer::create_session`]'s
/// policy wiring: insert the rule at position 0 so it fires *before*
/// any optimizer rule that could rewrite the shape the policy walker
/// matches on (notably projection pushdown — appending would let the
/// pushdown collapse the projection before the mask sees it). See
/// the server doc comment for the full rationale.
fn prepend_policy_rule(
    base: &SessionContext,
    policy_rule: Arc<PolicyOptimizerRule>,
) -> SessionContext {
    let state = base.state();
    let mut rules: Vec<Arc<dyn OptimizerRule + Send + Sync>> = state.optimizers().to_vec();
    rules.insert(0, policy_rule as Arc<dyn OptimizerRule + Send + Sync>);
    let state = SessionStateBuilder::new_from_existing(state)
        .with_optimizer_rules(rules)
        .build();
    SessionContext::new_with_state(state)
}

/// Register the `users` table on a session from a fresh
/// `PostgresConnector` against `dsn`. Federation registers under the
/// bare name `users` so the policy rule's
/// `TableReference::bare("users")` keys match.
async fn register_users(ctx: &SessionContext, dsn: &str) -> Arc<PostgresConnector> {
    let pg = Arc::new(
        PostgresConnector::connect(dsn)
            .await
            .expect("postgres connector connects"),
    );
    let provider = pg
        .table_provider("public", "users")
        .await
        .expect("users table provider");
    ctx.register_table("users", provider)
        .expect("register users");
    pg
}

async fn run_query(ctx: &SessionContext) -> Vec<RecordBatch> {
    ctx.sql(QUERY)
        .await
        .expect("plan query")
        .collect()
        .await
        .expect("execute query")
}

/// **The parity test.** Same enforcer, same query, two execution
/// paths — assert they produce byte-identical pretty-printed output.
/// Any divergence here means the codec is dropping the policy
/// rewrites, which would silently violate the strategy v3.0 exit
/// criterion.
#[tokio::test]
#[ignore = "requires Docker"]
#[allow(clippy::too_many_lines)] // one cohesive parity + governance scenario
async fn governance_round_trips_through_ballista_workers() {
    let (dsn, _container) = setup_postgres().await;

    // ---- Single-node baseline ----------------------------------------
    let single_factory =
        SessionContextFactory::new(SessionConfig::new()).expect("single-node factory");
    let single_base = single_factory.create_federated_context();
    let _pg_single = register_users(&single_base, &dsn).await;
    let single_ctx = prepend_policy_rule(&single_base, build_policy_rule());
    let single_batches = run_query(&single_ctx).await;

    // ---- Ballista standalone cluster ---------------------------------
    let pg_for_registry = Arc::new(
        PostgresConnector::connect(&dsn)
            .await
            .expect("postgres connector for registry"),
    );
    let registry_executor: Arc<dyn SQLExecutor> = pg_for_registry.clone();
    let registry: DynConnectorRegistry = Arc::new(
        vec![("pg".to_string(), registry_executor)]
            .into_iter()
            .collect::<InMemoryConnectorRegistry>(),
    );

    let logical_codec: Arc<dyn LogicalExtensionCodec> =
        Arc::new(FederationLogicalCodec::with_registry(Arc::clone(&registry)));
    let physical_codec: Arc<dyn PhysicalExtensionCodec> = Arc::new(
        FederationPlanCodec::with_logical_codec(Arc::clone(&registry), Arc::clone(&logical_codec))
            .with_inner_physical_codec(Arc::new(
                ballista_core::serde::BallistaPhysicalExtensionCodec::default(),
            )),
    );

    let factory = BallistaContextFactory::new(SessionConfig::new())
        .with_standalone_parallelism(STANDALONE_PARALLELISM)
        .with_logical_codec(logical_codec)
        .with_physical_codec(physical_codec);
    let cluster = factory
        .boot_standalone_cluster()
        .await
        .expect("ballista standalone boots");

    let ballista_base = cluster.create_session();
    let _pg_ballista = register_users(&ballista_base, &dsn).await;
    let ballista_ctx = prepend_policy_rule(&ballista_base, build_policy_rule());
    let ballista_batches = run_query(&ballista_ctx).await;

    // ---- Assertion 1: byte-identical output --------------------------
    let single_printed = pretty_format_batches(&single_batches)
        .expect("format single-node batches")
        .to_string();
    let ballista_printed = pretty_format_batches(&ballista_batches)
        .expect("format ballista batches")
        .to_string();

    eprintln!("=== single-node ===\n{single_printed}");
    eprintln!("=== ballista ===\n{ballista_printed}");

    assert_eq!(
        single_printed, ballista_printed,
        "governance enforcement produced different output single-node vs Ballista — \
         the codec or the optimizer-rule ordering on the Ballista side dropped a \
         policy rewrite. Single-node output above ≠ Ballista output above."
    );

    // ---- Assertion 2: policy actually fired --------------------------
    // The row-filter trims to Bob only; the column-mask replaces every
    // `email` value with the literal. Each branch must show in the
    // output, otherwise we'd be asserting "parity at nothing."
    let total_rows: usize = ballista_batches.iter().map(RecordBatch::num_rows).sum();
    assert_eq!(
        total_rows, 1,
        "row-filter `email = 'bob@example.com'` should leave exactly one row \
         (Bob, id=2); got {total_rows}. Output:\n{ballista_printed}"
    );
    assert!(
        ballista_printed.contains("***@example.com"),
        "column-mask should rewrite `email` to the masked literal in the \
         output; got:\n{ballista_printed}"
    );
    assert!(
        ballista_printed.contains("Bob"),
        "Bob (id=2) is the only row passing the row-filter; got:\n{ballista_printed}"
    );
    for forbidden in [
        "alice@example.com",
        "bob@example.com",
        "carol@example.com",
        "Alice",
        "Carol",
    ] {
        assert!(
            !ballista_printed.contains(forbidden),
            "post-policy output must not contain `{forbidden}` (mask + filter \
             together hide every name except Bob and every real email); got:\n\
             {ballista_printed}"
        );
    }

    // ---- Assertion 3:  — an ALIASED filtered table ------------
    // `FROM users u` must still enforce *and* must not push invalid SQL to
    // the source: the row-filter predicate has to be qualified to the alias
    // (`u.email`), not the base table (`users.email`), which is invalid under
    // the aliased `FROM users AS u` the federation layer emits. Before the
    // fix this failed with Postgres "invalid reference to FROM-clause entry
    // for table users". The federation unparse is identical single-node and
    // distributed, so exercising the single-node context keeps this cheap
    // (no second cluster) while still driving the real Postgres pushdown.
    let aliased = single_ctx
        .sql("SELECT u.email FROM users u")
        .await
        .expect("plan aliased query")
        .collect()
        .await
        .expect(
            "aliased query must execute — a row-filter on an aliased table must \
             qualify its predicate to the alias, not push `users.email` under \
             `FROM users AS u`",
        );
    let aliased_printed = pretty_format_batches(&aliased)
        .expect("format aliased batches")
        .to_string();
    let aliased_rows: usize = aliased.iter().map(RecordBatch::num_rows).sum();
    assert_eq!(
        aliased_rows, 1,
        "row-filter must still trim to Bob under an alias; got:\n{aliased_printed}"
    );
    assert!(
        aliased_printed.contains("***@example.com"),
        "column-mask must still fire under an alias; got:\n{aliased_printed}"
    );
    for forbidden in ["bob@example.com", "alice@example.com", "carol@example.com"] {
        assert!(
            !aliased_printed.contains(forbidden),
            "no real email may leak under an alias; got:\n{aliased_printed}"
        );
    }
}

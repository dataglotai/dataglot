//! Pre-serialization guard for distributed query plans (DEV-3719 / GH #418).
//!
//! Under distributed execution, a query that is a **GROUP BY aggregate
//! over a JOIN spanning two distinct federated sources** can make
//! `datafusion-federation 0.5.3` emit a cyclic / self-referential
//! `LogicalPlan` for the federated subplan. When `DistributedQueryExec`
//! serializes that plan to ship it to the scheduler, `datafusion-proto`'s
//! recursive `LogicalPlanNode` traversal follows the cycle with no base
//! case and **overflows the worker stack** — `fatal runtime error: stack
//! overflow, aborting` takes down the whole `dataglot-server` process
//! (DoS-class: the pgwire connection dies and the server is gone).
//!
//! We can't fix `datafusion-proto`'s missing cycle detection from here,
//! and a recursion-depth guard inside our own codec doesn't help (the
//! overflow happens in `datafusion-proto`'s traversal, not in our
//! `encode_federation`). Instead [`SerializationGuardQueryPlanner`] wraps
//! the coordinator's `BallistaQueryPlanner` and validates the logical
//! plan with a **bounded, iterative** walk *before* it can reach
//! `DistributedQueryExec`. A cyclic / pathologically-deep plan trips the
//! node-count cap and is rejected with a typed error, so the server
//! survives and the client gets a clean message instead of a dead
//! connection. The query still won't run distributed — but `--distributed`
//! becomes shippable rather than a process-abort waiting to happen.
//!
//! The walk is deliberately iterative: a recursive validator would
//! overflow on the very cycle it is trying to detect.

use std::sync::Arc;

use async_trait::async_trait;
use ballista::datafusion::common::Result as DfResult;
use ballista::datafusion::error::DataFusionError;
use ballista::datafusion::execution::context::QueryPlanner;
use ballista::datafusion::execution::session_state::SessionState;
use ballista::datafusion::logical_expr::LogicalPlan;
use ballista::datafusion::physical_plan::ExecutionPlan;
use datafusion_federation::FederatedPlanNode;

/// Upper bound on logical-plan nodes traversed before declaring a plan
/// unfit for distributed serialization.
///
/// Real query plans are tiny — tens of nodes, low hundreds for the
/// gnarliest federated joins. This cap sits far above any legitimate
/// plan, so it only ever trips on the pathological cyclic /
/// self-referential plans `datafusion-federation` emits for ambiguous
/// cross-source aggregates (DEV-3719). A cyclic plan generates unbounded
/// nodes and trips it near-instantly.
const MAX_PLAN_NODES: usize = 10_000;

/// Walk `plan` iteratively and reject it if it is cyclic or
/// pathologically deep (more than `MAX_PLAN_NODES` nodes).
///
/// # Errors
/// [`DataFusionError::NotImplemented`] when the node budget is exceeded —
/// the signal for "this plan would overflow `datafusion-proto`'s
/// serializer; don't hand it to the distributed path".
pub fn validate_serializable_plan(plan: &LogicalPlan) -> DfResult<()> {
    validate_with_cap(plan, MAX_PLAN_NODES)
}

/// [`validate_serializable_plan`] with an explicit node budget. Split out
/// so tests can exercise the cap with a small budget + a shallow plan
/// (constructing a real 10 000-node plan would overflow the test's own
/// stack on `Drop` — the very failure mode we guard against).
fn validate_with_cap(plan: &LogicalPlan, max_nodes: usize) -> DfResult<()> {
    // Explicit heap worklist — NEVER recurse here. A recursive walk would
    // overflow on the same cycle `datafusion-proto` does; the whole point
    // is to terminate where it can't.
    let mut stack: Vec<&LogicalPlan> = vec![plan];
    let mut visited: usize = 0;

    while let Some(node) = stack.pop() {
        visited += 1;
        if visited > max_nodes {
            return Err(DataFusionError::NotImplemented(
                "distributed execution of this query is not supported: its federated \
                 plan is cyclic or pathologically deep (typically an ambiguous \
                 cross-source GROUP BY aggregate that cannot be pushed to a single \
                 source). Re-run without distributed execution. Tracked as GH #418."
                    .to_string(),
            ));
        }

        for input in node.inputs() {
            stack.push(input);
        }
        // `datafusion-federation` tucks a single-source subplan inside the
        // `FederatedPlanNode` extension; `LogicalPlan::inputs()` may present
        // that node as a leaf, so descend into its inner plan explicitly to
        // catch a cycle living there too.
        if let LogicalPlan::Extension(ext) = node {
            if let Some(fed) = ext.node.as_any().downcast_ref::<FederatedPlanNode>() {
                stack.push(&fed.plan);
            }
        }
    }
    Ok(())
}

/// A [`QueryPlanner`] that validates the logical plan for safe
/// serialization (see [`validate_serializable_plan`]) before delegating
/// to the wrapped planner — the coordinator's `BallistaQueryPlanner`.
///
/// This converts the DEV-3719 stack-overflow process-abort into a clean,
/// per-query typed error.
#[derive(Debug)]
pub struct SerializationGuardQueryPlanner {
    inner: Arc<dyn QueryPlanner + Send + Sync>,
    max_nodes: usize,
}

impl SerializationGuardQueryPlanner {
    /// Wrap `inner` (the coordinator's `BallistaQueryPlanner`).
    #[must_use]
    pub fn new(inner: Arc<dyn QueryPlanner + Send + Sync>) -> Self {
        Self {
            inner,
            max_nodes: MAX_PLAN_NODES,
        }
    }

    /// Test-only constructor with an explicit node budget, so the
    /// reject-before-delegate path can be driven through the planner with a
    /// shallow plan instead of a 10 000-node one (which would overflow the
    /// test's own stack on `Drop` — the very failure mode this guards).
    #[cfg(test)]
    pub(crate) fn with_cap(inner: Arc<dyn QueryPlanner + Send + Sync>, max_nodes: usize) -> Self {
        Self { inner, max_nodes }
    }
}

#[async_trait]
impl QueryPlanner for SerializationGuardQueryPlanner {
    async fn create_physical_plan(
        &self,
        logical_plan: &LogicalPlan,
        session_state: &SessionState,
    ) -> DfResult<Arc<dyn ExecutionPlan>> {
        validate_with_cap(logical_plan, self.max_nodes)?;
        self.inner
            .create_physical_plan(logical_plan, session_state)
            .await
    }
}

#[cfg(test)]
mod metadata_tests {
    use super::*;
    use ballista::datafusion::logical_expr::builder::table_source;
    use ballista::datafusion::logical_expr::LogicalPlanBuilder;

    use ballista::datafusion::arrow::datatypes::{DataType, Field, Schema};

    fn scan_named(name: &str) -> LogicalPlan {
        let schema = Schema::new(vec![Field::new("a", DataType::Int32, false)]);
        LogicalPlanBuilder::scan(name, table_source(&schema), None)
            .expect("scan")
            .build()
            .expect("plan")
    }

    ///  — `pg_catalog` scans are detected wherever they sit;
    /// ordinary and `information_schema` scans are not (the latter
    /// serialize fine and stay distributed).
    #[test]
    fn detects_pg_catalog_scans_only() {
        assert!(references_pg_catalog(&scan_named("pg_catalog.pg_class")));
        assert!(!references_pg_catalog(&scan_named("public.users")));
        assert!(!references_pg_catalog(&scan_named(
            "information_schema.tables"
        )));
    }

    ///: a `pg_catalog` scan nested INSIDE a `FederatedPlanNode`
    /// must still be detected. `detects_pg_catalog_scans_only` only
    /// covers top-level scans; if the extension-descent branch
    /// (`references_pg_catalog`'s Extension arm) regresses, a JDBC
    /// `DatabaseMetaData` query wrapped by the federation analyzer
    /// routes to the distributed planner, its virtual `pg_catalog`
    /// provider fails `try_encode_table_provider`, and every schema
    /// browser breaks distributed again ( recurrence).
    #[test]
    fn detects_pg_catalog_nested_in_federated_plan_node() {
        use datafusion_federation::sql::{SQLExecutor, SQLFederationPlanner};
        use datafusion_federation::FederatedPlanNode;

        let inner = scan_named("pg_catalog.pg_class");
        let planner = Arc::new(SQLFederationPlanner::new(Arc::new(
            super::super_test_support::CountingStubExecutor,
        ) as Arc<dyn SQLExecutor>));
        let fed = FederatedPlanNode::new(inner, planner);
        let plan = LogicalPlan::Extension(ballista::datafusion::logical_expr::Extension {
            node: Arc::new(fed),
        });
        assert!(
            references_pg_catalog(&plan),
            "pg_catalog scan hidden inside a FederatedPlanNode must be detected"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use ballista::datafusion::arrow::datatypes::{DataType, Field, Schema};
    use ballista::datafusion::logical_expr::builder::table_source;
    use ballista::datafusion::logical_expr::{lit, LogicalPlanBuilder};

    fn scan() -> LogicalPlanBuilder {
        let schema = Schema::new(vec![Field::new("a", DataType::Int32, false)]);
        LogicalPlanBuilder::scan("t", table_source(&schema), None).expect("scan builder")
    }

    ///  — an input-less query (`SELECT 1`: a projection over an
    /// `EmptyRelation`, no `TableScan`) must be recognized as local-only, so
    /// the planner runs it in-process instead of dispatching it to Ballista
    /// (where it hangs extended-protocol clients like psycopg/pgcli/dbt).
    #[test]
    fn input_less_query_routes_local() {
        // An `EmptyRelation` producing one row — the shape `SELECT 1` bottoms
        // out in; no `TableScan`.
        let plan = LogicalPlanBuilder::empty(true)
            .build()
            .expect("build an input-less plan");
        assert!(is_input_less(&plan), "an EmptyRelation has no TableScan");
        assert!(should_plan_locally(&plan), "SELECT 1 must plan locally");
    }

    /// A query that scans a real table is NOT input-less and stays on the
    /// distributed path (no false-positive local routing).
    #[test]
    fn table_query_stays_distributed() {
        let plan = scan().build().expect("build a table scan");
        assert!(!is_input_less(&plan), "a TableScan plan is not input-less");
        assert!(
            !should_plan_locally(&plan),
            "a plain table scan must stay on the distributed path"
        );
    }

    /// A trivial finite plan passes the guard (real cap).
    #[test]
    fn accepts_a_normal_plan() {
        let plan = scan()
            .filter(lit(true))
            .and_then(LogicalPlanBuilder::build)
            .expect("build a trivial plan");
        assert!(validate_serializable_plan(&plan).is_ok());
    }

    /// A plan exceeding the budget is rejected with the typed error.
    /// Uses a small cap + a shallow plan so we exercise the exact
    /// rejection path a cyclic plan hits, without building (and then
    /// recursively dropping) a 10 000-deep plan that would overflow the
    /// test's own stack.
    #[test]
    fn rejects_a_plan_over_the_cap() {
        // scan -> filter -> filter -> filter = 4 nodes; cap of 3 trips.
        let plan = scan()
            .filter(lit(true))
            .and_then(|b| b.filter(lit(true)))
            .and_then(|b| b.filter(lit(true)))
            .and_then(LogicalPlanBuilder::build)
            .expect("build a 4-node plan");
        let err = validate_with_cap(&plan, 3).expect_err("over-cap plan must be rejected");
        assert!(
            matches!(err, DataFusionError::NotImplemented(_)),
            "expected NotImplemented, got {err:?}"
        );
        // The same plan is fine under the real (generous) cap.
        assert!(validate_serializable_plan(&plan).is_ok());
    }

    /// **The load-bearing DoS-guard path.** The whole reason
    /// this file exists is the cyclic subplan that lives INSIDE the
    /// `FederatedPlanNode` extension — `LogicalPlan::inputs()` presents
    /// that node as a leaf, so the guard must descend into `fed.plan`
    /// explicitly (plan_guard.rs:91-95) to count its nodes. Both other
    /// cap tests use plain scan/filter plans, so if that downcast ever
    /// stops matching (e.g. a `datafusion-federation` type-identity
    /// change on upgrade), a cyclic federated subplan sails straight
    /// through to `datafusion-proto` and stack-overflows the whole
    /// process. This test proves inner nodes are actually counted.
    #[test]
    fn descends_into_federated_plan_node_inner_plan() {
        use datafusion_federation::sql::{SQLExecutor, SQLFederationPlanner};

        // Inner plan: scan -> filter -> filter = 3 nodes.
        let inner = scan()
            .filter(lit(true))
            .and_then(|b| b.filter(lit(true)))
            .and_then(LogicalPlanBuilder::build)
            .expect("build a 3-node inner plan");
        let planner = Arc::new(SQLFederationPlanner::new(Arc::new(
            super::super_test_support::CountingStubExecutor,
        ) as Arc<dyn SQLExecutor>));
        let fed = FederatedPlanNode::new(inner, planner);
        let plan = LogicalPlan::Extension(ballista::datafusion::logical_expr::Extension {
            node: Arc::new(fed),
        });

        // Outer Extension node (1) + 3 inner nodes = 4 total. A cap of
        // 3 must trip ONLY if the inner plan is descended into; if the
        // descent branch regressed, the walk sees just the 1 extension
        // node and wrongly passes.
        let err = validate_with_cap(&plan, 3)
            .expect_err("inner federated nodes must count toward the cap (DoS guard)");
        assert!(
            matches!(err, DataFusionError::NotImplemented(_)),
            "expected NotImplemented, got {err:?}"
        );
    }
}

/// Shared minimal `SQLExecutor` for the guard tests — federated-plan
/// construction needs an executor to build a `SQLFederationPlanner`,
/// but these tests never execute or serialize, so every data method is
/// unreachable.
#[cfg(test)]
mod super_test_support {
    use std::sync::Arc;

    use async_trait::async_trait;
    use ballista::datafusion::arrow::datatypes::SchemaRef;
    use ballista::datafusion::common::Result as DfResultDf;
    use ballista::datafusion::execution::SendableRecordBatchStream;
    use ballista::datafusion::physical_plan::PhysicalExpr;
    use ballista::datafusion::sql::unparser::dialect::{DefaultDialect, Dialect};
    use datafusion_federation::sql::SQLExecutor;

    #[derive(Debug)]
    pub(super) struct CountingStubExecutor;

    #[async_trait]
    impl SQLExecutor for CountingStubExecutor {
        #[allow(clippy::unnecessary_literal_bound)] // trait ties lifetime to &self
        fn name(&self) -> &str {
            "counting_stub"
        }
        fn compute_context(&self) -> Option<String> {
            Some("counting_stub".to_string())
        }
        fn dialect(&self) -> Arc<dyn Dialect> {
            Arc::new(DefaultDialect {})
        }
        fn execute(
            &self,
            _query: &str,
            _schema: SchemaRef,
            _filters: &[Arc<dyn PhysicalExpr>],
        ) -> DfResultDf<SendableRecordBatchStream> {
            unimplemented!("guard tests never execute")
        }
        async fn table_names(&self) -> DfResultDf<Vec<String>> {
            Ok(Vec::new())
        }
        async fn get_table_schema(&self, _table: &str) -> DfResultDf<SchemaRef> {
            unimplemented!("guard tests never fetch schemas")
        }
    }
}

// ===========================================================
// Local planning for catalog-metadata queries
// ===========================================================

/// Whether `plan` scans any `pg_catalog` table.
///
/// Those tables are **in-process virtual providers** (the pgwire
/// layer's Postgres-catalog emulation) with no serialization codec —
/// shipping such a plan to Ballista fails at
/// `try_encode_table_provider`. JDBC's `DatabaseMetaData` calls (the
/// introspection path under `DBeaver` / `DataGrip` / Metabase) are exactly
/// these queries, so on a distributed server every schema browser
/// broke (found by the  client-compat matrix).
///
/// `information_schema` is deliberately *not* matched: DataFusion's
/// native views serialize fine and already run distributed.
#[must_use]
pub fn references_pg_catalog(plan: &LogicalPlan) -> bool {
    // Iterative walk, same discipline as the serialization guard
    // above (and the same generous safety cap — a plan that big is
    // not a metadata query).
    let mut stack = vec![plan];
    let mut visited = 0usize;
    while let Some(node) = stack.pop() {
        visited += 1;
        if visited > 100_000 {
            return false;
        }
        if let LogicalPlan::TableScan(scan) = node {
            if scan.table_name.schema() == Some("pg_catalog") {
                return true;
            }
        }
        for input in node.inputs() {
            stack.push(input);
        }
        if let LogicalPlan::Extension(ext) = node {
            if let Some(fed) = ext.node.as_any().downcast_ref::<FederatedPlanNode>() {
                stack.push(&fed.plan);
            }
        }
    }
    false
}

/// Whether `plan` scans **no table at all** — a constant / input-less query
/// such as `SELECT 1`, `SELECT current_setting('…')`, `SELECT version()`, or
/// `VALUES (…)`.
///
/// Such a plan bottoms out in an `EmptyRelation` / `PlaceholderRowExec`, so
/// there is **nothing to distribute**; shipping it to Ballista is pure
/// overhead and — worse — its result never streams back to an
/// extended-protocol client, so psycopg-based tools (pgcli, dbt) **hang** on
/// the `SELECT 1` they issue on connect. Route these to local
/// planning, exactly like `pg_catalog` metadata queries.
///
/// Detection is "no `TableScan` anywhere", including inside a
/// [`FederatedPlanNode`] — a real federated read (`… FROM pg.t`) wraps a
/// `TableScan`, so it correctly stays on the distributed path.
#[must_use]
pub fn is_input_less(plan: &LogicalPlan) -> bool {
    let mut stack = vec![plan];
    let mut visited = 0usize;
    while let Some(node) = stack.pop() {
        visited += 1;
        // An input-less query is tiny; something this large has real inputs.
        if visited > 100_000 {
            return false;
        }
        if matches!(node, LogicalPlan::TableScan(_)) {
            return false;
        }
        for input in node.inputs() {
            stack.push(input);
        }
        if let LogicalPlan::Extension(ext) = node {
            if let Some(fed) = ext.node.as_any().downcast_ref::<FederatedPlanNode>() {
                stack.push(&fed.plan);
            }
        }
    }
    true
}

/// Whether `plan` must be planned **locally** instead of dispatched to
/// Ballista: `pg_catalog` metadata queries (their virtual providers can't
/// serialize — ) and input-less queries (nothing to distribute, and
/// they otherwise hang extended-protocol clients — ).
#[must_use]
pub fn should_plan_locally(plan: &LogicalPlan) -> bool {
    references_pg_catalog(plan) || is_input_less(plan)
}

/// A [`QueryPlanner`] that plans metadata / input-less queries
/// **locally** (DataFusion's default planner, in-process) and
/// delegates everything else to the wrapped distributed planner.
///
/// Metadata queries are tiny and read process-local state — there is
/// nothing to distribute, and their virtual providers can't serialize
/// anyway (see [`references_pg_catalog`]).
#[derive(Debug)]
pub struct LocalMetadataQueryPlanner {
    inner: Arc<dyn QueryPlanner + Send + Sync>,
}

impl LocalMetadataQueryPlanner {
    /// Wrap `inner` (the distributed planner chain).
    #[must_use]
    pub fn new(inner: Arc<dyn QueryPlanner + Send + Sync>) -> Self {
        Self { inner }
    }
}

#[async_trait]
impl QueryPlanner for LocalMetadataQueryPlanner {
    async fn create_physical_plan(
        &self,
        logical_plan: &LogicalPlan,
        session_state: &SessionState,
    ) -> DfResult<Arc<dyn ExecutionPlan>> {
        if should_plan_locally(logical_plan) {
            use ballista::datafusion::physical_planner::{DefaultPhysicalPlanner, PhysicalPlanner};
            return DefaultPhysicalPlanner::default()
                .create_physical_plan(logical_plan, session_state)
                .await;
        }
        self.inner
            .create_physical_plan(logical_plan, session_state)
            .await
    }
}

// =====================================================================
// Planner DISPATCH coverage: the decorator planners themselves, not just
// their predicates.
//
// `should_plan_locally` / `is_input_less` / `references_pg_catalog` and
// `validate_serializable_plan` are all unit-tested above as free
// functions. What was NOT covered is the `QueryPlanner` impls that ACT on
// them — the routing decision (plan-locally vs. delegate) and the
// reject-before-delegate guard. A regression in the dispatch (rather than
// the predicate) would silently reintroduce  (schema browsers),
//  (psycopg/dbt SELECT 1 hang), or GH #418 (serializer stack
// overflow) while every predicate test kept passing. These tests drive
// the planners with a recording stub in place of the real distributed
// chain, so no cluster is needed.
// =====================================================================
#[cfg(test)]
mod planner_dispatch_tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use async_trait::async_trait;
    use ballista::datafusion::arrow::datatypes::{DataType, Field, Schema};
    use ballista::datafusion::common::Result as DfResult;
    use ballista::datafusion::error::DataFusionError;
    use ballista::datafusion::execution::context::{QueryPlanner, SessionContext};
    use ballista::datafusion::execution::session_state::SessionState;
    use ballista::datafusion::logical_expr::builder::table_source;
    use ballista::datafusion::logical_expr::{lit, LogicalPlan, LogicalPlanBuilder};
    use ballista::datafusion::physical_plan::empty::EmptyExec;
    use ballista::datafusion::physical_plan::ExecutionPlan;

    use super::{LocalMetadataQueryPlanner, SerializationGuardQueryPlanner};

    // Stand-in for the distributed planner chain: records how many times it
    // is asked to plan, and returns a trivial physical plan. Lets the
    // decorator planners be tested for their dispatch decision (delegate
    // vs. handle-locally / reject) without booting a Ballista cluster.
    #[derive(Debug)]
    struct RecordingPlanner {
        calls: Arc<AtomicUsize>,
    }

    impl RecordingPlanner {
        fn new() -> (Arc<Self>, Arc<AtomicUsize>) {
            let calls = Arc::new(AtomicUsize::new(0));
            (
                Arc::new(Self {
                    calls: Arc::clone(&calls),
                }),
                calls,
            )
        }
    }

    #[async_trait]
    impl QueryPlanner for RecordingPlanner {
        async fn create_physical_plan(
            &self,
            logical_plan: &LogicalPlan,
            _session_state: &SessionState,
        ) -> DfResult<Arc<dyn ExecutionPlan>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let schema = Arc::new(logical_plan.schema().as_arrow().clone());
            Ok(Arc::new(EmptyExec::new(schema)))
        }
    }

    fn table_scan() -> LogicalPlan {
        let schema = Schema::new(vec![Field::new("a", DataType::Int32, false)]);
        LogicalPlanBuilder::scan("t", table_source(&schema), None)
            .expect("scan builder")
            .build()
            .expect("scan plan")
    }

    fn session() -> SessionState {
        SessionContext::new().state()
    }

    // ---- LocalMetadataQueryPlanner: the routing DISPATCH ( / ) ----

    // A `should_plan_locally` plan (input-less `SELECT 1`) must be planned
    // in-process and NEVER delegated to the distributed inner planner. The
    // predicate is unit-tested above; this proves the planner that acts on
    // it actually short-circuits.
    #[tokio::test]
    async fn local_metadata_planner_handles_local_plan_without_delegating() {
        let (inner, calls) = RecordingPlanner::new();
        let planner = LocalMetadataQueryPlanner::new(inner);
        let plan = LogicalPlanBuilder::empty(true)
            .build()
            .expect("input-less plan");

        planner
            .create_physical_plan(&plan, &session())
            .await
            .expect("a local plan must be planned in-process");

        // A zero call-count proves the plan was handled in-process by the
        // DefaultPhysicalPlanner and never dispatched to the distributed
        // inner planner.
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "an input-less/local plan must NOT be dispatched to the distributed planner"
        );
    }

    // A real table scan has nothing local about it and MUST be delegated to
    // the distributed inner planner (no false-positive local routing).
    #[tokio::test]
    async fn local_metadata_planner_delegates_distributed_plan() {
        let (inner, calls) = RecordingPlanner::new();
        let planner = LocalMetadataQueryPlanner::new(inner);

        planner
            .create_physical_plan(&table_scan(), &session())
            .await
            .expect("a distributed plan must be delegated and planned");

        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "a table-scan plan must be dispatched to the distributed planner exactly once"
        );
    }

    // ---- SerializationGuardQueryPlanner: reject-before-delegate (GH #418) ----

    // A serializable plan passes the guard and is delegated to inner.
    #[tokio::test]
    async fn serialization_guard_delegates_valid_plan() {
        let (inner, calls) = RecordingPlanner::new();
        let planner = SerializationGuardQueryPlanner::new(inner);

        planner
            .create_physical_plan(&table_scan(), &session())
            .await
            .expect("a normal plan must pass the guard and be delegated");

        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "a valid plan must reach the inner distributed planner"
        );
    }

    // A plan over the node cap is rejected with a typed error and the inner
    // distributed planner is NEVER invoked — the whole point of the guard
    // is that the pathological plan never reaches datafusion-proto.
    #[tokio::test]
    async fn serialization_guard_rejects_over_cap_without_delegating() {
        let (inner, calls) = RecordingPlanner::new();
        // scan -> filter -> filter -> filter = 4 nodes; a cap of 3 trips.
        let plan = LogicalPlanBuilder::scan(
            "t",
            table_source(&Schema::new(vec![Field::new("a", DataType::Int32, false)])),
            None,
        )
        .expect("scan builder")
        .filter(lit(true))
        .and_then(|b| b.filter(lit(true)))
        .and_then(|b| b.filter(lit(true)))
        .and_then(LogicalPlanBuilder::build)
        .expect("4-node plan");
        let planner = SerializationGuardQueryPlanner::with_cap(inner, 3);

        let err = planner
            .create_physical_plan(&plan, &session())
            .await
            .expect_err("an over-cap plan must be rejected by the guard");
        assert!(
            matches!(err, DataFusionError::NotImplemented(_)),
            "expected NotImplemented, got {err:?}"
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "a rejected plan must NEVER reach the inner distributed planner"
        );
    }
}

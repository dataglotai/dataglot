//! Defensive guard against the DataFusion 54 unparser MARK-JOIN drop
//! — rejects federated plans that would unparse to broken SQL
//! instead of executing them.
//!
//! # The bug (upstream, DataFusion 54.1)
//!
//! A `LeftMark`/`RightMark` join is the decorrelated form of a subquery
//! predicate that sits inside a DISJUNCTION and so cannot become a plain
//! semi/anti join — e.g. `WHERE amount > 25 OR customer_id IN (SELECT
//! id FROM customers)`. DataFusion plans it as a mark join that produces
//! an internal boolean `mark` column, which the outer `Filter` then
//! references:
//!
//! ```text
//! Filter: orders.amount > 25 OR __correlated_sq_1.mark
//!   LeftMark Join: orders.customer_id = __correlated_sq_1.id
//!     TableScan: orders
//!     SubqueryAlias: __correlated_sq_1  (customers)
//! ```
//!
//! The SQL unparser has no surface syntax for a mark column, and instead
//! of rendering the equivalent `OR EXISTS (...)` it DROPS the mark join
//! entirely, leaving the `mark` reference dangling:
//!
//! ```sql
//! SELECT orders.amount
//! FROM (SELECT orders.amount, __correlated_sq_1.mark FROM orders)   -- no join!
//! WHERE ((orders.amount > 25) OR __correlated_sq_1.mark)            -- unresolved
//! ```
//!
//! `__correlated_sq_1` is not in the `FROM`, so the generated SQL is
//! invalid (unresolved column) — and if a source resolved it loosely,
//! the result would be wrong. This is reachable whenever both the outer
//! table and the subquery table live in the SAME federated source, so
//! datafusion-federation collapses the whole mark join into one pushed
//! statement.
//!
//! # Why reject rather than fix up
//!
//! Correct-but-unavailable beats silently-wrong (and beats a cryptic
//! remote "column `__correlated_sq_1.mark` does not exist"). The error
//! names a working rewrite: split the disjunction into two **disjoint**
//! branches — `WHERE cond` UNION ALL `WHERE cond IS NOT TRUE AND col IN
//! (…)`. Disjointness matters: a bare `UNION` would dedup rows the `OR`
//! preserves, and a naive `UNION ALL` of `cond` / `col IN (…)` would
//! double-count rows matching both. The `cond IS NOT TRUE` guard on the
//! second branch keeps them disjoint (and NULL-safe — a NULL `cond` still
//! lands in exactly one branch), so row multiplicity is preserved.
//! Alternatively, evaluate the `OR`-ed subquery outside the federated
//! source.

use datafusion::common::tree_node::{Transformed, TreeNode};
use datafusion::error::{DataFusionError, Result as DfResult};
use datafusion::logical_expr::{JoinType, LogicalPlan};
use datafusion::optimizer::optimizer::ApplyOrder;
use datafusion::optimizer::{OptimizerConfig, OptimizerRule};
use datafusion_federation::FederatedPlanNode;

/// The user-facing rejection. Kept greppable: operators search logs for
/// it, and `rule_rejects_federated_mark_join` pins it.
pub const MARK_JOIN_UNPARSE_GUARD_ERROR: &str =
    "this federated query contains a subquery predicate inside an OR (e.g. \
     `WHERE cond OR col IN (SELECT …)`), which DataFusion plans as a MARK join — \
     and DataFusion 54's SQL unparser silently DROPS that join, emitting SQL that \
     references a non-existent correlated table (invalid, or wrong if loosely \
     resolved). Rewrite it as two DISJOINT branches so no row is dropped or \
     double-counted — `SELECT … WHERE cond` UNION ALL `SELECT … WHERE cond IS NOT \
     TRUE AND col IN (SELECT …)` — or evaluate the OR-ed subquery outside the \
     federated source.";

/// Logical optimizer rule that runs AFTER the federation optimizer (so
/// collapsed federated subtrees exist as [`FederatedPlanNode`]
/// extensions) and fails planning when a collapsed subtree contains a
/// mark join.
#[derive(Debug, Default)]
pub struct FederatedMarkJoinGuard;

impl OptimizerRule for FederatedMarkJoinGuard {
    #[allow(clippy::unnecessary_literal_bound)] // trait signature fixes the lifetime
    fn name(&self) -> &str {
        "federated_mark_join_unparse_guard"
    }

    fn apply_order(&self) -> Option<ApplyOrder> {
        // Whole-plan inspection; we do our own traversal.
        None
    }

    fn supports_rewrite(&self) -> bool {
        true
    }

    fn rewrite(
        &self,
        plan: LogicalPlan,
        _config: &dyn OptimizerConfig,
    ) -> DfResult<Transformed<LogicalPlan>> {
        let violation = plan.exists(|node| {
            Ok(match node {
                LogicalPlan::Extension(ext) => ext
                    .node
                    .as_any()
                    .downcast_ref::<FederatedPlanNode>()
                    .is_some_and(|fed| plan_contains_mark_join(&fed.plan)),
                _ => false,
            })
        })?;
        if violation {
            return Err(DataFusionError::Plan(
                MARK_JOIN_UNPARSE_GUARD_ERROR.to_string(),
            ));
        }
        Ok(Transformed::no(plan))
    }
}

/// Whether `plan` (a to-be-unparsed federated subtree) contains a
/// `LeftMark`/`RightMark` join anywhere — the exact shape DataFusion
/// 54's unparser drops. Every other join type has a faithful SQL
/// rendering, so only mark joins are flagged.
fn plan_contains_mark_join(plan: &LogicalPlan) -> bool {
    // The closure never errors, so the walk itself can't fail.
    plan.exists(|node| {
        Ok(matches!(
            node,
            LogicalPlan::Join(join)
                if matches!(join.join_type, JoinType::LeftMark | JoinType::RightMark)
        ))
    })
    .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use datafusion::arrow::array::{Int32Array, RecordBatch};
    use datafusion::arrow::datatypes::{DataType, Field, Schema};
    use datafusion::execution::session_state::SessionState;
    use datafusion::logical_expr::Extension;
    use datafusion::optimizer::OptimizerContext;
    use datafusion::physical_plan::ExecutionPlan;
    use datafusion::prelude::SessionContext;
    use datafusion_federation::FederationPlanner;

    use super::*;

    /// A `FederationPlanner` the guard never invokes — it only reads
    /// `fed.plan`. Lets a test wrap a plan in a real `FederatedPlanNode`
    /// so the rule's outer traversal + downcast are exercised for real.
    #[derive(Debug)]
    struct UnusedPlanner;

    #[async_trait::async_trait]
    impl FederationPlanner for UnusedPlanner {
        async fn plan_federation(
            &self,
            _node: &FederatedPlanNode,
            _state: &SessionState,
        ) -> DfResult<Arc<dyn ExecutionPlan>> {
            unreachable!("the guard inspects fed.plan and never plans the federation")
        }
    }

    /// Wrap `plan` in a `FederatedPlanNode` extension, as the federation
    /// optimizer does before this guard runs.
    fn federate(plan: LogicalPlan) -> LogicalPlan {
        let node = Arc::new(FederatedPlanNode::new(plan, Arc::new(UnusedPlanner)));
        LogicalPlan::Extension(Extension { node })
    }

    fn ctx() -> SessionContext {
        let ctx = SessionContext::new();
        let customers = RecordBatch::try_new(
            Arc::new(Schema::new(vec![Field::new("id", DataType::Int32, false)])),
            vec![Arc::new(Int32Array::from(vec![1, 2]))],
        )
        .unwrap();
        let orders = RecordBatch::try_new(
            Arc::new(Schema::new(vec![
                Field::new("customer_id", DataType::Int32, false),
                Field::new("amount", DataType::Int32, false),
            ])),
            vec![
                Arc::new(Int32Array::from(vec![1, 1, 2])),
                Arc::new(Int32Array::from(vec![10, 20, 30])),
            ],
        )
        .unwrap();
        ctx.register_batch("customers", customers).unwrap();
        ctx.register_batch("orders", orders).unwrap();
        ctx
    }

    async fn optimized(ctx: &SessionContext, sql: &str) -> LogicalPlan {
        ctx.sql(sql)
            .await
            .expect("plans")
            .into_optimized_plan()
            .expect("optimizes")
    }

    /// A subquery predicate inside an `OR` decorrelates to a mark join —
    /// which the unparser drops, so the guard's walk must flag it.
    #[tokio::test]
    async fn flags_or_in_subquery_mark_join() {
        let ctx = ctx();
        let plan = optimized(
            &ctx,
            "SELECT amount FROM orders \
             WHERE amount > 25 OR customer_id IN (SELECT id FROM customers)",
        )
        .await;
        assert!(
            plan_contains_mark_join(&plan),
            "an OR-ed IN subquery must plan as a mark join:\n{}",
            plan.display_indent()
        );
    }

    /// The same shape with `OR EXISTS` also decorrelates to a mark join.
    #[tokio::test]
    async fn flags_or_exists_subquery_mark_join() {
        let ctx = ctx();
        let plan = optimized(
            &ctx,
            "SELECT amount FROM orders o \
             WHERE amount > 25 OR EXISTS (SELECT 1 FROM customers c WHERE c.id = o.customer_id)",
        )
        .await;
        assert!(
            plan_contains_mark_join(&plan),
            "an OR-ed EXISTS subquery must plan as a mark join:\n{}",
            plan.display_indent()
        );
    }

    /// A plain (AND-able) `IN` subquery plans as a SEMI join, which
    /// unparses faithfully — it must NOT be flagged.
    #[tokio::test]
    async fn allows_plain_in_subquery_semi_join() {
        let ctx = ctx();
        let plan = optimized(
            &ctx,
            "SELECT amount FROM orders WHERE customer_id IN (SELECT id FROM customers)",
        )
        .await;
        assert!(
            !plan_contains_mark_join(&plan),
            "a plain IN subquery is a semi join, not a mark join:\n{}",
            plan.display_indent()
        );
    }

    /// An ordinary join carries no mark — never flagged.
    #[tokio::test]
    async fn allows_ordinary_join() {
        let ctx = ctx();
        let plan = optimized(
            &ctx,
            "SELECT o.amount FROM orders o JOIN customers c ON c.id = o.customer_id",
        )
        .await;
        assert!(!plan_contains_mark_join(&plan));
    }

    /// End-to-end: the rule itself (not just the walk) must FAIL planning
    /// when a collapsed `FederatedPlanNode` contains a mark join — this
    /// exercises the outer traversal, the downcast, and the error path.
    #[tokio::test]
    async fn rule_rejects_federated_mark_join() {
        let ctx = ctx();
        let plan = optimized(
            &ctx,
            "SELECT amount FROM orders \
             WHERE amount > 25 OR customer_id IN (SELECT id FROM customers)",
        )
        .await;
        let err = FederatedMarkJoinGuard
            .rewrite(federate(plan), &OptimizerContext::new())
            .expect_err("a federated mark join must be rejected");
        assert!(
            err.to_string().contains(MARK_JOIN_UNPARSE_GUARD_ERROR),
            "the guard's public error must surface: {err}"
        );
    }

    /// End-to-end negative: a federated subtree with no mark join passes
    /// the rule untouched (no false positive, no spurious rewrite).
    #[tokio::test]
    async fn rule_allows_federated_plain_join() {
        let ctx = ctx();
        let plan = optimized(
            &ctx,
            "SELECT o.amount FROM orders o JOIN customers c ON c.id = o.customer_id",
        )
        .await;
        let out = FederatedMarkJoinGuard
            .rewrite(federate(plan), &OptimizerContext::new())
            .expect("a federated plan without a mark join must pass");
        assert!(!out.transformed, "the guard must not rewrite the plan");
    }

    /// A mark join that is NOT inside a `FederatedPlanNode` (executed
    /// locally) is none of the guard's business — it must pass.
    #[tokio::test]
    async fn rule_ignores_non_federated_mark_join() {
        let ctx = ctx();
        let plan = optimized(
            &ctx,
            "SELECT amount FROM orders \
             WHERE amount > 25 OR customer_id IN (SELECT id FROM customers)",
        )
        .await;
        // No `federate(...)` wrapper: a bare mark-join plan.
        FederatedMarkJoinGuard
            .rewrite(plan, &OptimizerContext::new())
            .expect("a non-federated mark join is not this guard's concern");
    }
}

//! Defensive guard against the DataFusion 53 unparser dedup drop
//! — rejects federated plans that would silently return
//! WRONG results instead of executing them.
//!
//! # The bug (upstream, fixed in DataFusion 54)
//!
//! DataFusion's SQL unparser silently drops a deduplicating
//! `Aggregate` (`aggr_expr` empty — the optimized form of
//! `SELECT DISTINCT` / `GROUP BY` without aggregates) whenever that
//! node ends up inside a **derived-table scope** of the generated SQL:
//! below a `Join` input or below a `SubqueryAlias`. The classic victim:
//!
//! ```sql
//! SELECT c.name
//! FROM customers c
//! JOIN (SELECT DISTINCT customer_id FROM orders) o ON o.customer_id = c.id
//! ```
//!
//! federates to remote SQL **without** the `DISTINCT`, duplicating
//! every customer with more than one order. Reported against
//! `datafusion-federation` as
//! [#82](https://github.com/datafusion-contrib/datafusion-federation/issues/82),
//! but the root cause is the core unparser; DataFusion **54** emits the
//! `GROUP BY` correctly, so this whole module retires with the
//! coordinated ecosystem bump.
//!
//! Verified-safe shapes (pinned by the federation contract suite) are
//! deliberately NOT flagged: dedup at the top of a select scope
//! (top-level `DISTINCT`, `INTERSECT` / `EXCEPT` rewrites — their
//! dedup `Aggregate` sits *above* the semi/anti join), and any
//! `Aggregate` with real aggregate expressions.
//!
//! # Why reject rather than fix up
//!
//! Correct-but-unavailable beats silently-wrong. The error names the
//! working rewrites (`IN (subquery)` / `EXISTS`, which plan as semi
//! joins and push down correctly — no dedup `Aggregate` involved).

use std::sync::Arc;

use datafusion::common::tree_node::{Transformed, TreeNode, TreeNodeRecursion};
use datafusion::error::{DataFusionError, Result as DfResult};
use datafusion::logical_expr::LogicalPlan;
use datafusion::optimizer::optimizer::ApplyOrder;
use datafusion::optimizer::{OptimizerConfig, OptimizerRule};
use datafusion_federation::FederatedPlanNode;

/// The user-facing rejection. Kept greppable: the federation contract
/// suite pins it, and operators search logs for it.
pub const DEDUP_UNPARSE_GUARD_ERROR: &str =
    "this federated query contains a DISTINCT (or GROUP BY without aggregates) inside a \
     joined subquery — DataFusion 53's SQL unparser silently DROPS that deduplication, \
     which would return duplicated rows (upstream datafusion-federation #82; \
     fixed in DataFusion 54). Rewrite the subquery as `WHERE ... IN (SELECT ...)` or \
     `WHERE EXISTS (...)` (both push down correctly), or deduplicate outside the \
     federated source.";

/// Logical optimizer rule that runs AFTER the federation optimizer
/// (so collapsed federated subtrees exist as [`FederatedPlanNode`]
/// extensions) and fails planning when a collapsed subtree contains a
/// dedup `Aggregate` in a derived-table position.
#[derive(Debug, Default)]
pub struct FederatedDedupUnparseGuard;

impl OptimizerRule for FederatedDedupUnparseGuard {
    #[allow(clippy::unnecessary_literal_bound)] // trait signature fixes the lifetime
    fn name(&self) -> &str {
        "federated_dedup_unparse_guard"
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
        let mut violation = false;
        plan.apply(|node| {
            if let LogicalPlan::Extension(ext) = node {
                if let Some(fed) = ext.node.as_any().downcast_ref::<FederatedPlanNode>() {
                    if plan_loses_dedup_on_unparse(&fed.plan, false) {
                        violation = true;
                        return Ok(TreeNodeRecursion::Stop);
                    }
                }
            }
            Ok(TreeNodeRecursion::Continue)
        })?;
        if violation {
            return Err(DataFusionError::Plan(DEDUP_UNPARSE_GUARD_ERROR.to_string()));
        }
        Ok(Transformed::no(plan))
    }
}

/// Convenience: the production optimizer rule set — federation's
/// defaults plus this guard, in the order that matters (the guard must
/// see the post-collapse plan). Both `dataglot-core`'s federated
/// context and `dataglot-ballista`'s factory use this so the wiring
/// can't drift.
#[must_use]
pub fn federated_optimizer_rules() -> Vec<Arc<dyn OptimizerRule + Send + Sync>> {
    let mut rules = datafusion_federation::default_optimizer_rules();
    rules.push(Arc::new(FederatedDedupUnparseGuard));
    rules.push(Arc::new(
        crate::federation_mark_join_guard::FederatedMarkJoinGuard,
    ));
    rules
}

/// Walk a to-be-unparsed plan and report whether it contains a dedup
/// `Aggregate` (no aggregate expressions) in a derived-table position —
/// the exact shape DataFusion 53's unparser mangles.
///
/// `in_derived_scope` starts `false` at the unparse root and flips
/// `true` when descending into `Join` inputs or through a
/// `SubqueryAlias` — both become derived-table subqueries in the
/// generated SQL. A dedup `Aggregate` reached with the flag still
/// `false` is at the top of its select scope, which the unparser
/// handles correctly (top-level `DISTINCT`, `INTERSECT` / `EXCEPT`).
fn plan_loses_dedup_on_unparse(plan: &LogicalPlan, in_derived_scope: bool) -> bool {
    match plan {
        LogicalPlan::Aggregate(agg) => {
            if agg.aggr_expr.is_empty() && in_derived_scope {
                return true;
            }
            // A real aggregation starts a fresh SELECT scope in the
            // generated SQL; anything below it is a derived table.
            plan_loses_dedup_on_unparse(&agg.input, true)
        }
        LogicalPlan::Join(join) => {
            use datafusion::logical_expr::JoinType;
            match join.join_type {
                // Semi / anti / mark joins unparse as `WHERE [NOT]
                // EXISTS (...)`: the LEFT input stays in the CURRENT
                // select scope (this is how INTERSECT / EXCEPT keep
                // their dedup — verified empirically on df53), and the
                // right side lives inside the EXISTS, where row
                // multiplicity cannot affect results — a dropped dedup
                // there is harmless, so it is skipped entirely.
                JoinType::LeftSemi | JoinType::LeftAnti | JoinType::LeftMark => {
                    plan_loses_dedup_on_unparse(&join.left, in_derived_scope)
                }
                JoinType::RightSemi | JoinType::RightAnti | JoinType::RightMark => {
                    plan_loses_dedup_on_unparse(&join.right, in_derived_scope)
                }
                // Plain joins put BOTH inputs into derived-table
                // subqueries — the scope the df53 unparser mangles.
                JoinType::Inner | JoinType::Left | JoinType::Right | JoinType::Full => {
                    plan_loses_dedup_on_unparse(&join.left, true)
                        || plan_loses_dedup_on_unparse(&join.right, true)
                }
            }
        }
        LogicalPlan::SubqueryAlias(alias) => plan_loses_dedup_on_unparse(&alias.input, true),
        other => other
            .inputs()
            .iter()
            .any(|input| plan_loses_dedup_on_unparse(input, in_derived_scope)),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use datafusion::arrow::array::{Int32Array, RecordBatch};
    use datafusion::arrow::datatypes::{DataType, Field, Schema};
    use datafusion::prelude::SessionContext;

    use super::*;

    /// Build a context with two tiny in-memory tables; the *walk* is
    /// pure plan-shape analysis, so memory tables stand in for
    /// federated scans (the end-to-end federated rejection is pinned
    /// by `dataglot-federation`'s contract suite).
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

    #[tokio::test]
    async fn flags_distinct_subquery_under_a_join() {
        let ctx = ctx();
        let plan = optimized(
            &ctx,
            "SELECT c.id FROM customers c \
             JOIN (SELECT DISTINCT customer_id FROM orders) o ON o.customer_id = c.id",
        )
        .await;
        assert!(plan_loses_dedup_on_unparse(&plan, false));
    }

    #[tokio::test]
    async fn flags_aliased_distinct_subquery_without_a_join() {
        let ctx = ctx();
        let plan = optimized(
            &ctx,
            "SELECT customer_id FROM (SELECT DISTINCT customer_id FROM orders) t \
             WHERE customer_id > 1",
        )
        .await;
        assert!(plan_loses_dedup_on_unparse(&plan, false));
    }

    #[tokio::test]
    async fn flags_group_by_without_aggregates_under_a_join() {
        let ctx = ctx();
        let plan = optimized(
            &ctx,
            "SELECT c.id FROM customers c \
             JOIN (SELECT customer_id FROM orders GROUP BY customer_id) o \
               ON o.customer_id = c.id",
        )
        .await;
        assert!(plan_loses_dedup_on_unparse(&plan, false));
    }

    #[tokio::test]
    async fn allows_top_level_distinct() {
        let ctx = ctx();
        let plan = optimized(&ctx, "SELECT DISTINCT customer_id FROM orders").await;
        assert!(!plan_loses_dedup_on_unparse(&plan, false));
    }

    #[tokio::test]
    async fn allows_aggregating_subquery_under_a_join() {
        let ctx = ctx();
        let plan = optimized(
            &ctx,
            "SELECT c.id, t.n FROM customers c \
             JOIN (SELECT customer_id, COUNT(*) AS n FROM orders GROUP BY customer_id) t \
               ON t.customer_id = c.id",
        )
        .await;
        assert!(!plan_loses_dedup_on_unparse(&plan, false));
    }

    #[tokio::test]
    async fn allows_intersect_shape_dedup_above_the_semi_join() {
        let ctx = ctx();
        let plan = optimized(
            &ctx,
            "SELECT customer_id FROM orders WHERE amount <= 20 \
             INTERSECT \
             SELECT customer_id FROM orders WHERE amount >= 10",
        )
        .await;
        assert!(
            !plan_loses_dedup_on_unparse(&plan, false),
            "INTERSECT's dedup Aggregate sits at the top of its scope — the unparser \
             emits its GROUP BY correctly (verified empirically on df53); flagging it \
             would be a false positive:\n{}",
            plan.display_indent()
        );
    }

    #[tokio::test]
    async fn allows_in_subquery_semi_join_rewrite() {
        let ctx = ctx();
        let plan = optimized(
            &ctx,
            "SELECT amount FROM orders \
             WHERE customer_id IN (SELECT id FROM customers)",
        )
        .await;
        assert!(
            !plan_loses_dedup_on_unparse(&plan, false),
            "the recommended workaround must never itself be rejected:\n{}",
            plan.display_indent()
        );
    }
}

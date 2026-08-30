//!  /  — dialect-independent isolation of governance row filters
//! that sit on an OUTER-JOIN preserved leg or an ANTI/SEMI-join leg, shared by
//! every SQL connector's
//! [`SQLExecutor::logical_optimizer`](datafusion_federation::sql::SQLExecutor).
//!
//! A row filter (RLS) is enforced as a `Filter` node on the filtered table's
//! scan. DataFusion's unparser then mis-renders that `Filter` in two join
//! shapes, each a silent RLS bypass:
//!
//!   * **Outer-join preserved leg** — the filter folds into the join's `ON`
//!     (`users u LEFT JOIN orders o ON (o.user_id = u.id AND u.active)`). An
//!     `ON` predicate does NOT drop preserved-side rows (they survive
//!     NULL-extended), so `u.active` there is inert and inactive rows reappear.
//!   * **Anti/semi-join leg** — these unparse to `[NOT] EXISTS (SELECT 1 FROM
//!     <probe> WHERE <on>)`. DF 54.1 DROPS a probe-side (inner-EXISTS) filter
//!     outright and mis-folds a preserved-side one, so the filter vanishes.
//!
//! [`isolate_outer_join_filters`] runs as the connector's `logical_optimizer` —
//! after DataFusion's optimizer, right before the federation unparse — so the
//! barrier it adds is not optimized away. It rewrites a `Filter` NODE on an
//! affected leg (both legs of an anti/semi join, the preserved leg of an outer
//! join) into `SubqueryAlias(rel, Projection(cols, Filter))`, which the unparser
//! emits as `(SELECT cols FROM … WHERE pred) AS rel` — an outer derived table,
//! or one nested inside the `EXISTS` for an anti/semi probe leg. It never moves a
//! predicate between `ON` and `WHERE`, so it is strictly semantics-preserving: a
//! user's own `ON` condition lives in `Join.on`, not as a `Filter` node, and is
//! untouched. The logic is pure `LogicalPlan` surgery with no dialect specifics,
//! so it is correct for every SQL source (Postgres/MySQL/Oracle/Snowflake).

use std::sync::Arc;

use datafusion::common::tree_node::{Transformed, TreeNode};
use datafusion::common::Column;
use datafusion::error::Result as DfResult;
use datafusion::logical_expr::{Expr, Extension, JoinType, LogicalPlan, LogicalPlanBuilder};
use datafusion::sql::TableReference;
use datafusion_federation::FederatedPlanNode;

/// Entry point for a connector's `logical_optimizer`. See the module docs.
pub(crate) fn isolate_outer_join_filters(plan: LogicalPlan) -> DfResult<LogicalPlan> {
    // The federated sub-plan reaches us wrapped in a `Federated` extension node
    // whose `inputs()` is empty, so `transform_down` cannot descend into it.
    // Unwrap, rewrite the inner plan, and re-wrap (schema is preserved, which
    // datafusion-federation asserts after each logical optimizer).
    if let LogicalPlan::Extension(ext) = &plan {
        if let Some(fed) = ext.node.as_any().downcast_ref::<FederatedPlanNode>() {
            let inner = isolate_in_plan(fed.plan.clone())?;
            let node = Arc::new(FederatedPlanNode::new(inner, fed.planner.clone()));
            return Ok(LogicalPlan::Extension(Extension { node }));
        }
    }
    isolate_in_plan(plan)
}

fn isolate_in_plan(plan: LogicalPlan) -> DfResult<LogicalPlan> {
    Ok(plan
        .transform_down(|node| {
            let LogicalPlan::Join(mut join) = node else {
                return Ok(Transformed::no(node));
            };
            // Which leg(s) carry a governance Filter the unparser mis-renders?
            //
            // OUTER joins keep rows that fail the `ON` predicate, so a Filter
            // folded into `ON` is inert on the PRESERVED leg — isolate it:
            //   - LEFT  → left preserved; RIGHT → right preserved; FULL → both.
            //
            // ANTI/SEMI joins unparse to `[NOT] EXISTS (SELECT 1 FROM <probe>
            // WHERE <on>)`. DF 54.1's unparser then MIS-RENDERS a leg Filter:
            // it silently DROPS a probe-side (inner-EXISTS) Filter entirely and
            // mis-folds a preserved-side one. Both are RLS bypasses. Isolating
            // BOTH legs fixes both — the probe Filter becomes a derived table
            // *inside* the EXISTS, the preserved Filter an outer derived table;
            // wrapping a leg is semantics-preserving, so wrapping the leg that
            // happened to render correctly is harmless.
            //
            // MARK joins can't be salvaged this way — the unparser drops the
            // whole mark/EXISTS structure regardless of wrapping — so leave them
            // best-effort here; their unparse-lossiness needs a separate guard.
            let (fix_left, fix_right) = match join.join_type {
                JoinType::Left | JoinType::LeftMark => (true, false),
                JoinType::Right | JoinType::RightMark => (false, true),
                JoinType::Full
                | JoinType::LeftAnti
                | JoinType::LeftSemi
                | JoinType::RightAnti
                | JoinType::RightSemi => (true, true),
                JoinType::Inner => (false, false), // `ON` ≡ `WHERE`, already correct
            };
            let mut changed = false;
            if fix_left {
                if let Some(barrier) = barrier_for_join_leg(join.left.as_ref())? {
                    join.left = Arc::new(barrier);
                    changed = true;
                }
            }
            if fix_right {
                if let Some(barrier) = barrier_for_join_leg(join.right.as_ref())? {
                    join.right = Arc::new(barrier);
                    changed = true;
                }
            }
            Ok(if changed {
                Transformed::yes(LogicalPlan::Join(join))
            } else {
                Transformed::no(LogicalPlan::Join(join))
            })
        })?
        .data)
}

/// If `leg` is a `Filter` whose output columns are all qualified by a single
/// relation, wrap it in `SubqueryAlias(rel, Projection(cols, Filter))` — a
/// derived table that unparses to an isolated `WHERE`. Returns `None` (leave the
/// leg as-is) when `leg` is not a `Filter`, or its output mixes relations / has
/// an unqualified column (no single alias to give the derived table).
fn barrier_for_join_leg(leg: &LogicalPlan) -> DfResult<Option<LogicalPlan>> {
    // Wrap a leg only if it exposes a `Filter` the unparser would fold into the
    // join's `ON`: a bare `Filter`, or one left under a `Projection` (projection
    // pushdown can leave `Projection(Filter(…))`). A leg already isolated in a
    // derived table (a `SubqueryAlias` above a `Projection`) is left alone.
    if !leg_exposes_filter(leg) {
        return Ok(None);
    }
    let schema = leg.schema();
    // Every output column must share ONE qualifier — that becomes the derived
    // alias (the unparser renders even a schema-qualified reference as a bare
    // `AS <table>`, and outer `rel.col` references render consistently, so they
    // still resolve). An UNQUALIFIED column bails: `SubqueryAlias` would
    // requalify it to `rel`, changing the field's qualified name — which
    // DataFusion 54's `assert_expected_schema` rejects when a `logical_optimizer`
    // must preserve the schema. A filtered-table leg is always fully qualified,
    // so this never blocks the real RLS case.
    let mut rel: Option<&TableReference> = None;
    for (qualifier, _field) in schema.iter() {
        match qualifier {
            Some(q) if rel.is_none_or(|r| r == q) => rel = Some(q),
            _ => return Ok(None), // unqualified, or a second distinct relation
        }
    }
    let Some(rel) = rel.cloned() else {
        return Ok(None); // empty schema — nothing to alias by
    };
    let projection: Vec<Expr> = schema
        .iter()
        .map(|(q, f)| Expr::Column(Column::new(q.cloned(), f.name())))
        .collect();
    let wrapped = LogicalPlanBuilder::from(leg.clone())
        .project(projection)?
        .alias(rel)?
        .build()?;
    Ok(Some(wrapped))
}

/// Whether a join leg exposes a `Filter` node the unparser would fold into the
/// join's `ON`. A `Filter` at the top qualifies; so does one left directly under
/// `Projection`(s) by projection pushdown. Descent stops at any other node
/// (`SubqueryAlias`, `Join`, `TableScan`, …) — a filter already inside a derived
/// table is isolated and must not be re-wrapped.
fn leg_exposes_filter(plan: &LogicalPlan) -> bool {
    // Iterative to avoid recursion over an arbitrarily deep `Projection` chain.
    let mut current = plan;
    loop {
        match current {
            LogicalPlan::Filter(_) => return true,
            LogicalPlan::Projection(p) => current = p.input.as_ref(),
            _ => return false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use datafusion::arrow::datatypes::{DataType, Field, Schema};
    use datafusion::functions_aggregate::expr_fn::count;
    use datafusion::logical_expr::builder::LogicalTableSource;
    use datafusion::logical_expr::col;
    use datafusion::sql::unparser::plan_to_sql;

    fn users_source() -> Arc<LogicalTableSource> {
        Arc::new(LogicalTableSource::new(Arc::new(Schema::new(vec![
            Field::new("id", DataType::Int32, false),
            Field::new("active", DataType::Boolean, false),
        ]))))
    }

    fn orders_source() -> Arc<LogicalTableSource> {
        Arc::new(LogicalTableSource::new(Arc::new(Schema::new(vec![
            Field::new("id", DataType::Int32, false),
            Field::new("user_id", DataType::Int32, false),
        ]))))
    }

    /// A `Filter` on the aliased LEFT-JOIN preserved leg must land in an isolated
    /// derived-table `WHERE`, NOT the join's `ON`.
    #[test]
    fn isolate_filter_puts_it_in_derived_where_not_on() {
        let left = LogicalPlanBuilder::scan("users", users_source(), None)
            .unwrap()
            .alias("u")
            .unwrap()
            .filter(col("u.active"))
            .unwrap()
            .build()
            .unwrap();
        let right = LogicalPlanBuilder::scan("orders", orders_source(), None)
            .unwrap()
            .alias("o")
            .unwrap()
            .build()
            .unwrap();
        let plan = LogicalPlanBuilder::from(left)
            .join_on(right, JoinType::Left, [col("o.user_id").eq(col("u.id"))])
            .unwrap()
            .aggregate(vec![col("u.id")], vec![count(col("o.id"))])
            .unwrap()
            .build()
            .unwrap();

        let fixed = isolate_outer_join_filters(plan).unwrap();
        let sql = plan_to_sql(&fixed).unwrap().to_string();
        assert!(
            sql.contains("WHERE u.active") && !sql.contains("AND u.active"),
            "filter must be isolated as a derived-table WHERE, not folded into ON: {sql}"
        );
        assert!(
            sql.contains("ON (o.user_id = u.id)"),
            "the join key stays in ON: {sql}"
        );
    }

    /// An UNALIASED (schema-qualified) preserved leg is also isolated — the
    /// unparser renders the qualified alias as a bare `AS users` (/291).
    #[test]
    fn isolate_filter_on_unaliased_qualified_leg() {
        let left = LogicalPlanBuilder::scan("pg.public.users", users_source(), None)
            .unwrap()
            .filter(col("pg.public.users.active"))
            .unwrap()
            .build()
            .unwrap();
        let right = LogicalPlanBuilder::scan("pg.public.orders", orders_source(), None)
            .unwrap()
            .build()
            .unwrap();
        let plan = LogicalPlanBuilder::from(left)
            .join_on(
                right,
                JoinType::Left,
                [col("pg.public.orders.user_id").eq(col("pg.public.users.id"))],
            )
            .unwrap()
            .build()
            .unwrap();

        let fixed = isolate_outer_join_filters(plan).unwrap();
        let sql = plan_to_sql(&fixed).unwrap().to_string();
        // The derived alias equals the leg's relation, so outer refs stay
        // consistent (no dangling qualifiers) and the filter is an isolated WHERE.
        assert!(
            sql.contains("WHERE users.active")
                && !sql.to_lowercase().contains("and users.active")
                && sql.contains("ON (orders.user_id = users.id)"),
            "an unaliased qualified leg must still isolate the filter to WHERE with consistent refs: {sql}"
        );
    }

    /// Build `users u [anti/semi]JOIN (orders o WHERE o.user_id > 0)` with the
    /// governance Filter on the RIGHT (probe) leg, and return the isolated SQL.
    fn probe_side_isolated_sql(jt: JoinType) -> String {
        let left = LogicalPlanBuilder::scan("users", users_source(), None)
            .unwrap()
            .alias("u")
            .unwrap()
            .build()
            .unwrap();
        let right = LogicalPlanBuilder::scan("orders", orders_source(), None)
            .unwrap()
            .alias("o")
            .unwrap()
            .filter(col("o.user_id").gt(datafusion::logical_expr::lit(0)))
            .unwrap()
            .build()
            .unwrap();
        let plan = LogicalPlanBuilder::from(left)
            .join_on(right, jt, [col("o.user_id").eq(col("u.id"))])
            .unwrap()
            .build()
            .unwrap();
        let fixed = isolate_outer_join_filters(plan).unwrap();
        plan_to_sql(&fixed).unwrap().to_string()
    }

    /// A governance `Filter` on the PROBE leg of a `LeftAnti`/`LeftSemi` join
    /// must land INSIDE the `[NOT] EXISTS` subquery, not be dropped. Without
    /// isolation DF 54.1's unparser silently drops it — an RLS bypass.
    #[test]
    fn isolate_probe_side_filter_of_left_anti_semi() {
        for jt in [JoinType::LeftAnti, JoinType::LeftSemi] {
            let sql = probe_side_isolated_sql(jt);
            assert!(
                sql.contains("EXISTS (SELECT 1 FROM (SELECT o.id, o.user_id FROM orders AS o WHERE (o.user_id > 0)) AS o"),
                "{jt:?}: probe-side filter must be isolated inside the EXISTS subquery, got: {sql}"
            );
        }
    }

    /// The PRESERVED right leg of a `RightSemi` was previously missed (semi fell
    /// through to the no-op arm), dropping its filter. It must now isolate.
    #[test]
    fn isolate_preserved_side_filter_of_right_semi() {
        let sql = probe_side_isolated_sql(JoinType::RightSemi);
        assert!(
            sql.contains(
                "FROM (SELECT o.id, o.user_id FROM orders AS o WHERE (o.user_id > 0)) AS o"
            ) && sql.contains("EXISTS"),
            "RightSemi preserved-leg filter must be isolated into a derived table, got: {sql}"
        );
    }

    /// A `Filter` on an INNER-join leg is left untouched — its `ON` folding is
    /// already correct (`ON` ≡ `WHERE`), so no derived table is added.
    #[test]
    fn inner_join_filter_left_untouched() {
        let left = LogicalPlanBuilder::scan("users", users_source(), None)
            .unwrap()
            .alias("u")
            .unwrap()
            .filter(col("u.active"))
            .unwrap()
            .build()
            .unwrap();
        let right = LogicalPlanBuilder::scan("orders", orders_source(), None)
            .unwrap()
            .alias("o")
            .unwrap()
            .build()
            .unwrap();
        let plan = LogicalPlanBuilder::from(left)
            .join_on(right, JoinType::Inner, [col("o.user_id").eq(col("u.id"))])
            .unwrap()
            .build()
            .unwrap();
        let out = isolate_outer_join_filters(plan.clone()).unwrap();
        assert_eq!(
            format!("{}", plan.display_indent()),
            format!("{}", out.display_indent()),
            "inner-join filter must be left untouched"
        );
    }
}

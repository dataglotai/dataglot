//! Column-level whitelist / positive column authorization —.
//!
//! The complement to [`crate::access_deny`]'s deny-list. A whitelist names the
//! **only** columns of a table a matching identity may see; every other column
//! is treated as if it were not there:
//!
//! - `SELECT *` (and any bare-column projection) resolves to the **visible
//!   subset** — hidden columns are dropped from the projection output, not
//!   masked, not nulled, not errored (the Governance-slide-11 model:
//!   *"Unlisted columns are absent from the schema entirely."*).
//! - A hidden column referenced anywhere it **cannot** be pruned — a filter
//!   predicate, join condition, group-by / aggregate, sort, or a computed /
//!   aliased projection expression — raises a **deny error**. It is not
//!   visible, so it may not silently drive the query, and a `SELECT <hidden>`
//!   that reduces a projection to nothing is likewise denied.
//!
//! This is safe by construction: hidden data can only reach the client through
//! a bare `Expr::Column` in a projection, which is exactly what is dropped;
//! every other reference is refused.
//!
//! ## Scope
//!
//! Rules are **org + group conditional** (reuse `org_rule_applies` +
//! `subject_matches`), the same model masks and row filters use —
//! closing the access-deny group-only scope gap noted in. Privileges
//! are **additive**: for one table, the visible set is the *union* of the
//! whitelisted columns across every rule that applies to the identity (the
//! GRANT model — more grants widen access, never narrow it).
//!
//! A table with **no** applicable whitelist is unrestricted (the feature is
//! opt-in per table — back-compat).

use std::collections::{HashMap, HashSet};

use datafusion::common::tree_node::{Transformed, TreeNode};
use datafusion::common::{Column, DataFusionError, TableReference};
use datafusion::logical_expr::{Expr, LogicalPlan, Projection};

use crate::{Identity, OrgGroupId, PolicyEnforcer};

/// One column-whitelist rule: on `table`, the identities selected by
/// `(org, groups)` may see only `columns`.
#[derive(Debug, Clone)]
pub struct ColumnWhitelist {
    /// Target table — bare, partial, or fully-qualified.
    pub table: TableReference,
    /// The whitelisted (visible) column names on `table`.
    pub columns: Vec<String>,
    /// Tenant scope. `None` ⇒ operator-wide; `Some(org)` ⇒ only that org.
    pub org: Option<String>,
    /// Group scope. `None` ⇒ all subjects; `Some(groups)` ⇒ only identities
    /// in one of `groups`.
    pub groups: Option<Vec<OrgGroupId>>,
}

/// A registered rule's scope + visible-column set.
type WhitelistEntry = (Option<String>, Option<Vec<OrgGroupId>>, HashSet<String>);

/// [`PolicyEnforcer`] that enforces per-identity column whitelists.
#[derive(Debug)]
pub struct ColumnWhitelistEnforcer {
    /// `table → [(org, groups, visible-columns)]`. Keyed by the rule's table
    /// reference at its declared qualification; query relations are matched
    /// against it via `match_candidates` (/ parity).
    rules: HashMap<TableReference, Vec<WhitelistEntry>>,
}

impl ColumnWhitelistEnforcer {
    /// Build an enforcer from a stream of [`ColumnWhitelist`] rules.
    #[must_use]
    pub fn new(rules: impl IntoIterator<Item = ColumnWhitelist>) -> Self {
        let mut map: HashMap<TableReference, Vec<WhitelistEntry>> = HashMap::new();
        for ColumnWhitelist {
            table,
            columns,
            org,
            groups,
        } in rules
        {
            map.entry(table).or_default().push((
                org,
                groups,
                columns.into_iter().collect::<HashSet<_>>(),
            ));
        }
        Self { rules: map }
    }

    /// A real-but-empty enforcer (registers no rules; a no-op for any plan).
    #[must_use]
    pub fn empty() -> Self {
        Self {
            rules: HashMap::new(),
        }
    }

    /// Number of registered rules (summed across every scope).
    #[must_use]
    pub fn rule_count(&self) -> usize {
        self.rules.values().map(Vec::len).sum()
    }

    /// The visible-column set for `rel` under `identity`, or `None` if the
    /// table carries no whitelist that applies (⇒ unrestricted). The set is
    /// the **union** of the columns from every applicable rule (additive
    /// grants). `alias_map` resolves `FROM users u` back to `users`.
    fn visible_columns(
        &self,
        rel: &TableReference,
        alias_map: &HashMap<TableReference, TableReference>,
        identity: &Identity,
    ) -> Option<HashSet<String>> {
        let mut candidates = crate::match_candidates(rel);
        if let Some(original) = alias_map.get(rel) {
            candidates.extend(crate::match_candidates(original));
        }
        let mut visible: Option<HashSet<String>> = None;
        for cand in candidates {
            let Some(entries) = self.rules.get(&cand) else {
                continue;
            };
            for (org, groups, cols) in entries {
                if crate::org_rule_applies(org.as_deref(), identity)
                    && crate::subject_matches(groups.as_deref(), &identity.org_groups)
                {
                    visible
                        .get_or_insert_with(HashSet::new)
                        .extend(cols.clone());
                }
            }
        }
        visible
    }

    /// Is `col` a hidden column of a governed table (a table with an applicable
    /// whitelist that does not list `col`)? Columns with no relation, or on
    /// ungoverned tables, are never hidden.
    fn is_hidden(
        &self,
        col: &Column,
        alias_map: &HashMap<TableReference, TableReference>,
        identity: &Identity,
    ) -> bool {
        let Some(rel) = &col.relation else {
            return false;
        };
        self.visible_columns(rel, alias_map, identity)
            .is_some_and(|visible| !visible.contains(&col.name))
    }

    /// True if `expr` references any hidden governed column.
    fn expr_touches_hidden(
        &self,
        expr: &Expr,
        alias_map: &HashMap<TableReference, TableReference>,
        identity: &Identity,
    ) -> bool {
        let mut touched = false;
        // `apply` visits every sub-expression, including columns inside
        // functions, casts, and operators.
        let _ = expr.apply(|e| {
            if let Expr::Column(c) = e {
                if self.is_hidden(c, alias_map, identity) {
                    touched = true;
                    return Ok(datafusion::common::tree_node::TreeNodeRecursion::Stop);
                }
            }
            Ok(datafusion::common::tree_node::TreeNodeRecursion::Continue)
        });
        touched
    }

    /// Enforce whitelists at a single plan node (its expression subqueries are
    /// already handled by the caller's recursive descent).
    fn enforce_node(
        &self,
        node: LogicalPlan,
        alias_map: &HashMap<TableReference, TableReference>,
        identity: &Identity,
    ) -> Result<Transformed<LogicalPlan>, DataFusionError> {
        match node {
            // Projections are the one place a hidden column may be *dropped*:
            // a bare `Column` output for a hidden column is pruned (the
            // `SELECT *` → visible-subset behaviour). Any other expression that
            // touches a hidden column (computed, aliased, `hidden AS x`) is
            // denied — it would surface the value.
            LogicalPlan::Projection(proj) => {
                let Projection { expr, input, .. } = proj;
                let mut kept = Vec::with_capacity(expr.len());
                for e in expr {
                    if let Expr::Column(c) = &e {
                        if self.is_hidden(c, alias_map, identity) {
                            crate::audit::record_decision("column-hide", identity, &qualified(c));
                            continue; // drop from the projection
                        }
                    } else if self.expr_touches_hidden(&e, alias_map, identity) {
                        return Err(hidden_use_error(&e));
                    }
                    kept.push(e);
                }
                if kept.is_empty() {
                    return Err(DataFusionError::Plan(
                        "column access denied by policy: the query selects only columns that \
                         are not visible to this role"
                            .to_string(),
                    ));
                }
                let new = Projection::try_new(kept, input)?;
                Ok(Transformed::yes(LogicalPlan::Projection(new)))
            }
            // A governed table's scan is denied if any of its pushed-down
            // filters reference a hidden column (the scan itself needs no
            // reshaping: `SELECT *` is expanded to an explicit `Projection` of
            // every column by the SQL planner *before* this analyzer rule runs,
            // and projection pushdown — which would collapse that projection
            // into the scan — runs later, in the optimizer. The Projection arm
            // above therefore sees and prunes the hidden columns. Reshaping the
            // scan here would not survive datafusion-federation's replanning and
            // would re-fire every analyzer pass, so it is deliberately avoided.)
            LogicalPlan::TableScan(scan) => {
                for filter in &scan.filters {
                    if self.expr_touches_hidden(filter, alias_map, identity) {
                        return Err(hidden_use_error(filter));
                    }
                }
                Ok(Transformed::no(LogicalPlan::TableScan(scan)))
            }
            // Every other node: a hidden column in a filter, join key,
            // group-by, aggregate, or sort cannot be pruned without changing
            // the query's meaning, so referencing one is denied.
            other => {
                let mut denied: Option<DataFusionError> = None;
                other
                    .apply_expressions(|e| {
                        if self.expr_touches_hidden(e, alias_map, identity) {
                            denied = Some(hidden_use_error(e));
                            Ok(datafusion::common::tree_node::TreeNodeRecursion::Stop)
                        } else {
                            Ok(datafusion::common::tree_node::TreeNodeRecursion::Continue)
                        }
                    })
                    .ok();
                if let Some(err) = denied {
                    return Err(err);
                }
                Ok(Transformed::no(other))
            }
        }
    }
}

/// `catalog.schema.table.column`-style label for audit / errors (no values).
fn qualified(col: &Column) -> String {
    match &col.relation {
        Some(rel) => format!("{rel}.{}", col.name),
        None => col.name.clone(),
    }
}

/// Value-free deny error naming the first hidden column an expression touches.
fn hidden_use_error(_expr: &Expr) -> DataFusionError {
    DataFusionError::Plan(
        "column access denied by policy: a column not visible to this role is referenced in a \
         predicate, join, grouping, or computed expression"
            .to_string(),
    )
}

impl PolicyEnforcer for ColumnWhitelistEnforcer {
    fn rewrite(
        &self,
        plan: LogicalPlan,
        identity: &Identity,
    ) -> Result<Transformed<LogicalPlan>, DataFusionError> {
        if self.rules.is_empty() {
            return Ok(Transformed::no(plan));
        }
        // Alias map for the whole `rewrite` call (an alias declared in a join
        // leg is referenceable from any node above it).
        let mut alias_map: HashMap<TableReference, TableReference> = HashMap::new();
        collect_alias_targets(&plan, &mut alias_map);

        // `transform_down` walks the main plan tree (node *inputs*) but not
        // subqueries embedded in *expressions* (`InSubquery` / `Exists` /
        // scalar subselects), which DataFusion treats as opaque. At every node
        // we therefore (1) recurse this full whitelist rewrite into each
        // embedded subquery plan — so a hidden column reached via
        // `WHERE x IN (SELECT hidden FROM t)` is denied/pruned there too — then
        // (2) apply the local prune/deny to the node itself ( pattern,
        // mirroring mask/filter).
        plan.transform_down(|node| {
            let Transformed {
                data: node,
                transformed: sub_changed,
                ..
            } = node.map_expressions(|expr| {
                expr.transform_down(|e| {
                    crate::map_subquery_plans(e, &mut |subplan| {
                        let out =
                            self.rewrite(std::sync::Arc::unwrap_or_clone(subplan), identity)?;
                        Ok(out.update_data(std::sync::Arc::new))
                    })
                })
            })?;

            let local = self.enforce_node(node, &alias_map, identity)?;
            Ok(if sub_changed || local.transformed {
                Transformed::yes(local.data)
            } else {
                Transformed::no(local.data)
            })
        })
    }

    fn explain(&self, plan: &LogicalPlan, identity: &Identity) -> Vec<crate::PolicyDecision> {
        use crate::{PolicyAction, PolicyDecision};
        if self.rules.is_empty() {
            return Vec::new();
        }
        let mut alias_map = HashMap::new();
        collect_alias_targets(plan, &mut alias_map);
        let mut out = Vec::new();
        for col in crate::collect_plan_columns(plan) {
            if self.is_hidden(&col, &alias_map, identity) {
                out.push(PolicyDecision {
                    action: PolicyAction::Deny,
                    resource: qualified(&col),
                    detail: "column not visible to this role (column whitelist)".to_string(),
                });
            }
        }
        out.sort_by(|a, b| a.resource.cmp(&b.resource));
        out.dedup_by(|a, b| a.resource == b.resource);
        out
    }
}

/// Collect direct `SubqueryAlias → TableScan` mappings (keyed by the bare
/// alias). Mirrors the mask enforcer's alias resolution so `FROM users u`
/// resolves back to `users`.
fn collect_alias_targets(plan: &LogicalPlan, out: &mut HashMap<TableReference, TableReference>) {
    if let LogicalPlan::SubqueryAlias(sa) = plan {
        if let LogicalPlan::TableScan(ts) = sa.input.as_ref() {
            out.insert(
                TableReference::bare(sa.alias.table().to_string()),
                ts.table_name.clone(),
            );
        }
    }
    for child in plan.inputs() {
        collect_alias_targets(child, out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use datafusion::arrow::array::{Int32Array, StringArray};
    use datafusion::arrow::datatypes::{DataType, Field, Schema};
    use datafusion::arrow::record_batch::RecordBatch;
    use datafusion::datasource::MemTable;
    use datafusion::prelude::SessionContext;

    use crate::Identity;

    /// A `emp(id, email, salary, contract_value, customer_bank_ref)` table —
    /// the slide-11 sensitive shape.
    fn ctx() -> SessionContext {
        let schema = Arc::new(Schema::new(vec![
            Field::new("id", DataType::Int32, false),
            Field::new("email", DataType::Utf8, false),
            Field::new("salary", DataType::Int32, false),
            Field::new("contract_value", DataType::Int32, false),
            Field::new("customer_bank_ref", DataType::Utf8, false),
        ]));
        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(Int32Array::from(vec![1, 2])),
                Arc::new(StringArray::from(vec!["a@x.com", "b@x.com"])),
                Arc::new(Int32Array::from(vec![100, 200])),
                Arc::new(Int32Array::from(vec![9, 8])),
                Arc::new(StringArray::from(vec!["QNB-1", "QNB-2"])),
            ],
        )
        .unwrap();
        let ctx = SessionContext::new();
        ctx.register_table(
            "emp",
            Arc::new(MemTable::try_new(schema, vec![vec![batch]]).unwrap()),
        )
        .unwrap();
        ctx
    }

    /// Whitelist `emp → {id, email}` scoped to group `QC-OpsAnalyst`.
    fn ops_whitelist() -> ColumnWhitelistEnforcer {
        ColumnWhitelistEnforcer::new([ColumnWhitelist {
            table: TableReference::bare("emp"),
            columns: vec!["id".into(), "email".into()],
            org: None,
            groups: Some(vec![OrgGroupId::new("QC-OpsAnalyst")]),
        }])
    }

    fn ops_analyst() -> Identity {
        Identity::user("ops").with_groups(["QC-OpsAnalyst"])
    }

    async fn rewrite(
        ctx: &SessionContext,
        sql: &str,
        e: &ColumnWhitelistEnforcer,
        id: &Identity,
    ) -> Result<LogicalPlan, DataFusionError> {
        // The unoptimized plan — the shape `PolicyOptimizerRule` sees during
        // the optimizer pipeline, before projection pushdown collapses things.
        let plan = ctx.sql(sql).await.unwrap().logical_plan().clone();
        Ok(e.rewrite(plan, id)?.data)
    }

    fn out_columns(plan: &LogicalPlan) -> Vec<String> {
        plan.schema()
            .fields()
            .iter()
            .map(|f| f.name().clone())
            .collect()
    }

    async fn nrows(ctx: &SessionContext, plan: LogicalPlan) -> usize {
        ctx.execute_logical_plan(plan)
            .await
            .unwrap()
            .collect()
            .await
            .unwrap()
            .iter()
            .map(RecordBatch::num_rows)
            .sum()
    }

    #[tokio::test]
    async fn select_star_hides_non_whitelisted_columns() {
        let ctx = ctx();
        let plan = rewrite(&ctx, "SELECT * FROM emp", &ops_whitelist(), &ops_analyst())
            .await
            .unwrap();
        assert_eq!(
            out_columns(&plan),
            vec!["id", "email"],
            "SELECT * must expose only the whitelist"
        );
        assert_eq!(nrows(&ctx, plan).await, 2, "rows unchanged, just narrower");
    }

    #[tokio::test]
    async fn unmatched_identity_sees_everything() {
        // A different group ⇒ no applicable rule ⇒ table unrestricted (opt-in).
        let ctx = ctx();
        let admin = Identity::user("admin").with_groups(["QC-Admin"]);
        let plan = rewrite(&ctx, "SELECT * FROM emp", &ops_whitelist(), &admin)
            .await
            .unwrap();
        assert_eq!(
            out_columns(&plan).len(),
            5,
            "privileged session sees all columns"
        );
    }

    #[tokio::test]
    async fn explicit_hidden_column_is_pruned_from_projection() {
        let ctx = ctx();
        let plan = rewrite(
            &ctx,
            "SELECT id, salary FROM emp",
            &ops_whitelist(),
            &ops_analyst(),
        )
        .await
        .unwrap();
        assert_eq!(
            out_columns(&plan),
            vec!["id"],
            "hidden salary dropped from an explicit projection"
        );
    }

    #[tokio::test]
    async fn selecting_only_hidden_columns_is_denied() {
        let ctx = ctx();
        let err = rewrite(
            &ctx,
            "SELECT salary, contract_value FROM emp",
            &ops_whitelist(),
            &ops_analyst(),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("denied by policy"), "{err}");
    }

    #[tokio::test]
    async fn hidden_column_in_filter_is_denied() {
        let ctx = ctx();
        let err = rewrite(
            &ctx,
            "SELECT id FROM emp WHERE salary > 100",
            &ops_whitelist(),
            &ops_analyst(),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("denied by policy"), "{err}");
    }

    #[tokio::test]
    async fn hidden_column_in_computed_expr_is_denied() {
        let ctx = ctx();
        let err = rewrite(
            &ctx,
            "SELECT salary + contract_value AS total FROM emp",
            &ops_whitelist(),
            &ops_analyst(),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("denied by policy"), "{err}");
    }

    #[tokio::test]
    async fn additive_grants_union_visible_columns() {
        // Two rules for the same identity ⇒ visible = union {id,email} ∪ {salary}.
        let e = ColumnWhitelistEnforcer::new([
            ColumnWhitelist {
                table: TableReference::bare("emp"),
                columns: vec!["id".into(), "email".into()],
                org: None,
                groups: Some(vec![OrgGroupId::new("QC-OpsAnalyst")]),
            },
            ColumnWhitelist {
                table: TableReference::bare("emp"),
                columns: vec!["salary".into()],
                org: None,
                groups: Some(vec![OrgGroupId::new("QC-OpsAnalyst")]),
            },
        ]);
        let ctx = ctx();
        let plan = rewrite(&ctx, "SELECT * FROM emp", &e, &ops_analyst())
            .await
            .unwrap();
        assert_eq!(out_columns(&plan), vec!["id", "email", "salary"]);
    }

    #[tokio::test]
    async fn empty_enforcer_is_identity() {
        let ctx = ctx();
        let plan = rewrite(
            &ctx,
            "SELECT * FROM emp",
            &ColumnWhitelistEnforcer::empty(),
            &ops_analyst(),
        )
        .await
        .unwrap();
        assert_eq!(out_columns(&plan).len(), 5);
    }

    #[tokio::test]
    async fn org_scoped_rule_only_fires_for_that_org() {
        let e = ColumnWhitelistEnforcer::new([ColumnWhitelist {
            table: TableReference::bare("emp"),
            columns: vec!["id".into()],
            org: Some("acme".into()),
            groups: None,
        }]);
        let ctx = ctx();
        // Matching org ⇒ restricted to {id}.
        let acme = Identity::user("u").with_org("acme");
        let p1 = rewrite(&ctx, "SELECT * FROM emp", &e, &acme).await.unwrap();
        assert_eq!(out_columns(&p1), vec!["id"]);
        // Different org ⇒ rule does not apply ⇒ unrestricted.
        let other = Identity::user("u").with_org("globex");
        let p2 = rewrite(&ctx, "SELECT * FROM emp", &e, &other)
            .await
            .unwrap();
        assert_eq!(out_columns(&p2).len(), 5);
    }

    #[tokio::test]
    async fn hidden_column_in_subquery_is_denied() {
        let ctx = ctx();
        let err = rewrite(
            &ctx,
            "SELECT id FROM emp WHERE id IN (SELECT salary FROM emp)",
            &ops_whitelist(),
            &ops_analyst(),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("denied by policy"), "{err}");
    }
}

//! Row-level filtering — second concrete `PolicyEnforcer`
//! implementation, companion to [`crate::mask`].
//!
//! [`RowFilterEnforcer`] takes a map of
//! `TableReference → predicate Expr` rules and rewrites a
//! `LogicalPlan` so every `TableScan` whose name matches a rule is
//! wrapped in a `Filter` node carrying the registered predicate.
//! Downstream optimizer passes (predicate pushdown) collapse the
//! `Filter` into the `TableScan.filters` list when the underlying
//! `TableProvider` supports it; when it doesn't, the `Filter` is
//! evaluated locally against the rows the source returns. Either
//! way, the predicate is mandatory — there's no caller-side path
//! that bypasses it.
//!
//! # Semantics
//!
//! Per CLAUDE.md hard rule 6, row filters are `DataFusion` `Expr`
//! predicates baked into the plan. *No* UDFs, *no* runtime SQL
//! rewriting. The predicate evaluates against the row values that
//! reach the `TableScan` — meaning predicates registered as a row
//! filter operate on the **same un-masked** column values that
//! `ColumnMaskingEnforcer`'s option-A semantics rely on. A row
//! filter `email = 'alice@example.com'` finds Alice's row even when
//! `email` is masked to `'***@example.com'` in the projection.
//!
//! # Rule precedence and matching
//!
//! Rules are stored keyed by `TableReference` and matched by
//! *strict* `TableReference` equality (same convention as
//! [`crate::mask`]). Loose matching ("any schema") is a Phase 1
//! Task 03 affordance built on top of the typed tag model from
//! Architecture Decisions §10. Until then, callers must register
//! rules using the same `TableReference` shape `DataFusion`'s
//! planner produces during planning. Operators registering rules
//! against `users` (bare) on a session that resolves to
//! `pg.public.users` (full) will find the rule never fires.
//!
//! # What this MVP does NOT do
//!
//! - **No identity / RBAC.** Rules are registered against a static
//!   enforcer instance. Per-user / per-org filtering is Task 02.
//! - **No persistent rule store.** Rules live in process memory.
//!   Task 04 wires the catalog service.
//! - **No predicate validation.** A predicate that references a
//!   non-existent column or has a type mismatch surfaces as a
//!   `DataFusion` planning error at query time, not registration
//!   time.

use std::collections::HashMap;

use datafusion::common::tree_node::{Transformed, TreeNode, TreeNodeRecursion};
use datafusion::common::Column;
use datafusion::error::DataFusionError;
use datafusion::logical_expr::{Expr, Filter, LogicalPlan};
use datafusion::sql::TableReference;

use crate::{Identity, PolicyEnforcer};

/// The scoped row-filter rules registered on one `table`:
/// `(rule org, rule groups, predicate Expr)` triples, at most one per distinct
/// `(org, groups)` scope ( F4 org dimension +  group dimension).
/// `None` org = operator-wide, `Some(x)` = tenant-scoped; `None` groups = all
/// subjects, `Some(gs)` = group-scoped. A group-scoped and an all-groups filter
/// on the same `(table, org)` coexist — when both match an identity their
/// predicates are AND-ed (see [`RowFilterEnforcer::resolve_predicate`]).
type OrgTaggedFilters = Vec<(Option<String>, Option<Vec<crate::OrgGroupId>>, Expr)>;

/// Re-qualify every column reference in `predicate` to `alias`.
///
/// A row-filter predicate is registered against a table and references only
/// that table's columns, so when the filter is applied *above* a
/// `SubqueryAlias`, every column belongs to the single aliased relation —
/// qualifying them all to the alias is correct and makes the predicate
/// resolve against (and unparse to) the aliased relation (`alias.col`).
/// Without this, a predicate qualified to the base table name unparses to
/// invalid SQL under the aliased `FROM` the federation layer emits
fn requalify_columns(predicate: Expr, alias: &TableReference) -> Expr {
    predicate
        .transform(|e| match e {
            Expr::Column(c) => Ok(Transformed::yes(Expr::Column(Column::new(
                Some(alias.clone()),
                c.name,
            )))),
            other => Ok(Transformed::no(other)),
        })
        .expect("column re-qualification never fails (pure Expr rewrite)")
        .data
}

/// Wrap `node` in the `Transformed` a node needs when the *only* change (if
/// any) was the subquery descent: `yes`/`no` per `changed`, with the default
/// `Continue` recursion so `transform_down` still visits the node's main-tree
/// children (e.g. a `Filter` whose predicate embedded a subquery still lets its
/// `TableScan` input get wrapped below).
fn subquery_only(node: LogicalPlan, changed: bool) -> Transformed<LogicalPlan> {
    if changed {
        Transformed::yes(node)
    } else {
        Transformed::no(node)
    }
}

/// One row-level filter rule.
///
/// `RowFilter` is the **input shape**; [`RowFilterEnforcer`]
/// decomposes a stream of these into its internal lookup map at
/// construction time.
#[derive(Debug, Clone)]
pub struct RowFilter {
    /// Fully-qualified table the rule applies to. Match is strict
    /// (`TableReference` `Eq`) — see the module-level docs.
    pub table: TableReference,
    /// `DataFusion` `Expr` predicate that must evaluate to `true` for
    /// a row to survive the filter. Any boolean-returning `Expr` is
    /// accepted; a non-boolean predicate surfaces as a
    /// `DataFusion` planning error at query time.
    pub predicate: Expr,
    /// Owning organization / tenant. `None` =
    /// **operator-wide** — the filter applies to *every* session
    /// regardless of org (what a file-config `[[row_filters]]` entry
    /// maps to, preserving single-org behaviour). `Some(x)` =
    /// **tenant-scoped** — the filter applies only for a session whose
    /// `Identity.org` is exactly `x` (what a runtime `CREATE ROW FILTER`
    /// maps to, tagged with the creating session's org). Selection
    /// happens at `rewrite` time (a rule applies iff its org is `None`
    /// or equals the session's org); the filtering itself stays a
    /// plan-time `Filter`/`Expr` predicate (rule 6).
    pub org: Option<String>,
    /// Org-groups / roles the filter applies to ( — role-conditional row
    /// filters). `None` = **all subjects** in the org scope: the filter applies
    /// to every session (what a file-config `[[row_filters]]` entry with no
    /// `groups` maps to, preserving pre- behaviour). `Some(gs)` =
    /// **group-scoped**: the filter applies only for a session whose
    /// [`crate::Identity::org_groups`] intersects `gs`. Selection combines with
    /// [`Self::org`] — a rule fires iff `org_rule_applies(org) &&
    /// subject_matches(groups)`; when several scoped filters match one session
    /// their predicates are AND-ed. Mirrors [`crate::AccessDenial::groups`] so
    /// masks, row filters, and access-deny all condition on group membership the
    /// same way. See `subject_matches`.
    pub groups: Option<Vec<crate::OrgGroupId>>,
}

/// Errors raised when constructing a [`RowFilterEnforcer`].
#[derive(Debug, thiserror::Error)]
pub enum BuildError {
    /// Two rules target the same `table`. The MVP rejects this
    /// rather than picking a winner; operators that want compound
    /// predicates can `AND` them in a single rule. Phase 1 Task 03
    /// introduces priority / layering.
    #[error("duplicate row-filter rule for table `{table}`")]
    DuplicateRule {
        /// The table with duplicate rules.
        table: TableReference,
    },
}

/// `PolicyEnforcer` implementation that wraps every matching
/// `TableScan` in a `Filter` carrying the registered predicate.
///
/// Constructed via [`RowFilterEnforcer::new`]. Matches strictly on
/// `TableReference` equality. The rewrite touches only `TableScan`
/// nodes — `Projection`, `Join`, `Aggregate`, etc. flow through
/// unchanged; the filter is applied as close to the source as the
/// optimizer can move it.
#[derive(Debug, Default)]
pub struct RowFilterEnforcer {
    /// `table` → the org-tagged row-filter rules for that table. Multiple
    /// orgs can register a filter on the *same* table (e.g. each tenant
    /// scopes `orders` to its own rows), so the value is a list keyed by
    /// the rule's `org`; `rewrite`/`explain` pick the entry that applies
    /// to the session identity via [`crate::org_rule_applies`]. At most
    /// one rule per distinct org per table (enforced at construction).
    filters: HashMap<TableReference, OrgTaggedFilters>,
}

impl RowFilterEnforcer {
    /// Build an enforcer from a stream of [`RowFilter`] rules.
    ///
    /// # Errors
    ///
    /// Returns [`BuildError::DuplicateRule`] if two input rules share
    /// the same `(table, org)` pair. Two rules on the same `table` but
    /// **different** orgs are *not* duplicates — they are distinct
    /// per-tenant (or tenant-vs-operator-wide) filters that coexist and
    /// are disambiguated per session at `rewrite` time.
    pub fn new(filters: impl IntoIterator<Item = RowFilter>) -> Result<Self, BuildError> {
        let mut map: HashMap<TableReference, OrgTaggedFilters> = HashMap::new();
        for RowFilter {
            table,
            predicate,
            org,
            groups,
        } in filters
        {
            // `get_mut` + `insert` rather than `entry(table.clone())` so the
            // `TableReference` isn't cloned per rule — it moves into either the
            // error or the map (Gemini perf review). The `entry` API can't be
            // used here because the duplicate-error path needs the un-consumed
            // `table`.
            match map.get_mut(&table) {
                Some(entries) => {
                    // Uniqueness key is `(org, groups)` — two filters on the
                    // same `table` that differ in org *or* group scope coexist
                    //. Only an exact `(org, groups)` repeat duplicates.
                    if entries.iter().any(|(existing_org, existing_groups, _)| {
                        existing_org == &org && existing_groups == &groups
                    }) {
                        return Err(BuildError::DuplicateRule { table });
                    }
                    entries.push((org, groups, predicate));
                }
                None => {
                    map.insert(table, vec![(org, groups, predicate)]);
                }
            }
        }
        Ok(Self { filters: map })
    }

    /// Build a real-but-empty enforcer. Registers no rules; behaves
    /// identically to `NoopPolicyEnforcer` for any plan.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            filters: HashMap::new(),
        }
    }

    /// Number of rules registered (summed across every org). Surfaced
    /// for diagnostics — not used in the rewrite path.
    #[must_use]
    pub fn rule_count(&self) -> usize {
        self.filters.values().map(Vec::len).sum()
    }

    /// Resolve the row-filter predicate that applies to `identity` for a
    /// scanned `table` ( F4 org +  group).
    ///
    /// Gathers the scoped candidates across **every** matching qualification
    /// (`crate::match_candidates` — most- to least-qualified, ) and
    /// selects along two dimensions:
    ///
    /// - **Org tier (tenant beats operator-wide):** a matching **tenant-scoped**
    ///   rule (`org == Some(session-org)`) shadows an **operator-wide** rule
    ///   (`org == None`) — the tenant's filter replaces, not narrows, the
    ///   operator default (so an `org = 'default'` operator filter can't blank a
    ///   tenant's own rows). Another org's tenant rule is invisible.
    /// - **Group scope (AND within the winning tier):** unlike masks — where a
    ///   single mask wins per column — *all* group-scoped and all-subject
    ///   filters that match the identity within the chosen tier are **AND-ed**
    ///   together (the governance-safe, more-restrictive direction; §10's
    ///   `apply_row_filters` folds conjunctively). So an all-subjects
    ///   `tenant_active` filter and a `QC-Support` filter both apply to a
    ///   QC-Support session, intersecting their row sets.
    ///
    /// Selecting over the *union* of qualifications (rather than the first
    /// candidate key that happens to exist) closes the cross-tenant shadowing
    /// leak: a session that doesn't match a tenant rule registered under one
    /// qualification (`pg.public.orders`) must still get an operator-wide rule
    /// registered under another (bare `orders`). Within one tier the first
    /// (most-qualified) candidate's predicate set is used, preserving.
    ///
    /// Returns an owned `Expr` because the result may be a freshly-built
    /// conjunction of several matching predicates.
    fn resolve_predicate(&self, table: &TableReference, identity: &Identity) -> Option<Expr> {
        let mut tenant: Option<Expr> = None;
        let mut operator_wide: Option<Expr> = None;
        for cand in crate::match_candidates(table) {
            let Some(entries) = self.filters.get(&cand) else {
                continue;
            };
            // Combine this candidate's applicable predicates per tier, AND-ing
            // group-scoped and all-subject filters that match the identity.
            let mut cand_tenant: Option<Expr> = None;
            let mut cand_operator: Option<Expr> = None;
            for (org, groups, predicate) in entries {
                if !crate::subject_matches(groups.as_deref(), &identity.org_groups) {
                    continue;
                }
                let slot = match org {
                    Some(_) if crate::org_rule_applies(org.as_deref(), identity) => {
                        &mut cand_tenant
                    }
                    None => &mut cand_operator,
                    // Another org's tenant rule — never applies.
                    Some(_) => continue,
                };
                *slot = Some(match slot.take() {
                    Some(acc) => acc.and(predicate.clone()),
                    None => predicate.clone(),
                });
            }
            // Most-qualified candidate wins per tier (keep the first non-empty).
            if tenant.is_none() {
                tenant = cand_tenant;
            }
            if operator_wide.is_none() {
                operator_wide = cand_operator;
            }
        }
        tenant.or(operator_wide)
    }
}

impl PolicyEnforcer for RowFilterEnforcer {
    fn explain(&self, plan: &LogicalPlan, identity: &Identity) -> Vec<crate::PolicyDecision> {
        use datafusion::common::tree_node::{TreeNode, TreeNodeRecursion};

        use crate::{PolicyAction, PolicyDecision};
        if self.filters.is_empty() {
            return Vec::new();
        }
        let mut out: Vec<PolicyDecision> = Vec::new();
        if let Err(err) = plan.apply(|node| {
            if let LogicalPlan::TableScan(scan) = node {
                // Org filter (`resolve_predicate`) mirrors rewrite, so explain
                // reports a filter only for the session it would fire for (F4).
                if let Some(predicate) = self.resolve_predicate(&scan.table_name, identity) {
                    let resource = scan.table_name.to_string();
                    if !out.iter().any(|d| d.resource == resource) {
                        out.push(PolicyDecision::new(
                            PolicyAction::RowFilter,
                            resource,
                            format!("rows kept where: {predicate}"),
                        ));
                    }
                }
            }
            Ok(TreeNodeRecursion::Continue)
        }) {
            // A traversal failure here means `explain` under-reports the
            // active row filters — surface it rather than silently
            // returning a partial decision list ( 1b).
            tracing::warn!(
                error = %err,
                "policy: plan traversal failed while explaining row filters; the decision list may be incomplete"
            );
        }
        out
    }

    fn rewrite(
        &self,
        plan: LogicalPlan,
        identity: &Identity,
    ) -> Result<Transformed<LogicalPlan>, DataFusionError> {
        // Identity does not drive rule *dispatch* here — row-filter
        // rules are static `table → predicate Expr` (identity-aware
        // dispatch lives in `TagBasedEnforcer`, which delegates back
        // to this enforcer). It IS recorded on every row-filter
        // decision's audit event (`crate::audit`).
        //
        // Empty enforcer ⇒ identity. Same fast-path
        // `ColumnMaskingEnforcer` uses so the optimizer fixed-point
        // loop converges in one pass.
        if self.filters.is_empty() {
            return Ok(Transformed::no(plan));
        }

        // Governance must reach filtered tables no matter how deeply they hide.
        // `transform_down` walks the main plan tree (node *inputs*) but not
        // subqueries embedded in *expressions* (`Expr::ScalarSubquery` /
        // `InSubquery` / `SetComparison` / `Exists`, each holding a
        // `Subquery { subquery: Arc<LogicalPlan> }`) — DataFusion's `TreeNode`
        // walk treats those as opaque, so a `TableScan` inside such a subquery
        // would return rows the policy should hide. At every node we therefore
        // also rewrite the node's expressions, recursively re-running this full
        // row-filter rewrite on each embedded subquery plan and rebuilding the
        // enclosing `Subquery`/`Expr` (`crate::map_subquery_plans`, which
        // preserves `outer_ref_columns` so a correlated subquery's outer refs —
        // the parent's columns — are untouched; only the subquery's own scans
        // are filtered). Nesting is handled because the recursive `rewrite`
        // walks the subquery the same way.
        plan.transform_down(|node| {
            // Descend into expression subqueries on this node first (any node
            // type). A `TableScan` / `SubqueryAlias` carries no expression
            // subqueries, so this is a no-op for the branches below; it fires on
            // the `Filter` / `Projection` / … nodes whose predicates or
            // projections embed a subquery.
            let Transformed {
                data: node,
                transformed: sub_changed,
                ..
            } = node.map_expressions(|expr| {
                // A subquery can sit anywhere in the expression tree (bare
                // predicate, inside an `Alias`, a `BinaryExpr`, …), so walk
                // every sub-expr and rewrite each embedded subquery plan.
                expr.transform_down(|e| {
                    crate::map_subquery_plans(e, &mut |subplan| {
                        let out =
                            self.rewrite(std::sync::Arc::unwrap_or_clone(subplan), identity)?;
                        Ok(out.update_data(std::sync::Arc::new))
                    })
                })
            })?;

            // Aliased scan (`FROM users u`): wrap the Filter ABOVE the
            // `SubqueryAlias`, with the predicate re-qualified to the alias.
            // The federation unparser renders the scan as `FROM users AS u`,
            // so a predicate qualified to the *base* table (`users.col`) is
            // invalid under the alias — Postgres rejects it with "invalid
            // reference to FROM-clause entry for table users".
            // Qualifying to the alias (`u.col`) matches the aliased FROM and
            // mirrors where DataFusion places user-written filters (above the
            // alias). `Jump` so we don't also wrap the inner `TableScan`.
            if let LogicalPlan::SubqueryAlias(alias) = &node {
                if let LogicalPlan::TableScan(scan) = alias.input.as_ref() {
                    if let Some(predicate) = self.resolve_predicate(&scan.table_name, identity) {
                        crate::audit::record_decision(
                            "row_filter",
                            identity,
                            &scan.table_name.to_string(),
                        );
                        let predicate = requalify_columns(predicate, &alias.alias);
                        let filter = Filter::try_new(predicate, std::sync::Arc::new(node.clone()))?;
                        return Ok(Transformed::new(
                            LogicalPlan::Filter(filter),
                            true,
                            TreeNodeRecursion::Jump,
                        ));
                    }
                }
                return Ok(subquery_only(node, sub_changed));
            }
            let LogicalPlan::TableScan(scan) = &node else {
                // Any other node type (Projection, Filter, Aggregate, …): the
                // only change here is whatever the subquery descent above made.
                return Ok(subquery_only(node, sub_changed));
            };
            // Match at each qualification level (most- to least-qualified)
            // so a less-qualified rule (bare `users`) covers a more-qualified
            // scan (`pg.public.users`) — qualifying a table can't dodge the
            // filter. See `crate::match_candidates` (closes ). The org
            // selection then keeps only the rule that applies to `identity`.
            let Some(predicate) = self.resolve_predicate(&scan.table_name, identity) else {
                return Ok(subquery_only(node, sub_changed));
            };
            // Ranger audit parity: every row-filter decision is
            // recorded with the session identity (`crate::audit`).
            crate::audit::record_decision("row_filter", identity, &scan.table_name.to_string());
            // `Filter::try_new` builds a Filter wrapping its input,
            // preserving the input's schema. Predicate pushdown will
            // later collapse this into `TableScan.filters` when the
            // underlying TableProvider supports it; when not, the
            // Filter evaluates locally on rows the source returns.
            //
            // `TreeNodeRecursion::Jump` is mandatory here: without
            // it, `transform_down` would recurse into the new
            // `Filter`'s child — which is the same `TableScan` we
            // just wrapped — match the rule again, wrap in another
            // `Filter`, and so on until the stack overflows.
            // `Jump` says "I changed this node; do not re-visit its
            // subtree." That's exactly the contract we want — the
            // wrapper is the final shape for this branch.
            let filter = Filter::try_new(predicate, std::sync::Arc::new(node.clone()))?;
            Ok(Transformed::new(
                LogicalPlan::Filter(filter),
                true,
                TreeNodeRecursion::Jump,
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Arc;

    use datafusion::arrow::array::{Int32Array, StringArray};
    use datafusion::arrow::datatypes::{DataType, Field, Schema};
    use datafusion::arrow::record_batch::RecordBatch;
    use datafusion::common::DFSchema;
    use datafusion::common::TableReference;
    use datafusion::datasource::MemTable;
    use datafusion::logical_expr::{col, lit, EmptyRelation, LogicalPlan};
    use datafusion::optimizer::{OptimizerContext, OptimizerRule};
    use datafusion::prelude::SessionContext;

    use crate::PolicyOptimizerRule;

    /// Mirror of `mask::tests::ctx_with_users`. Three rows; ids 1,
    /// 2, 3; ASCII emails. Returned `TableReference` matches the
    /// shape `DataFusion`'s planner emits for the unqualified
    /// `SELECT ... FROM users` — see the convention pinned in #123.
    fn ctx_with_users() -> (SessionContext, TableReference) {
        let schema = Arc::new(Schema::new(vec![
            Field::new("id", DataType::Int32, false),
            Field::new("email", DataType::Utf8, false),
        ]));
        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(Int32Array::from(vec![1, 2, 3])),
                Arc::new(StringArray::from(vec![
                    "alice@example.com",
                    "bob@example.com",
                    "carol@example.com",
                ])),
            ],
        )
        .expect("build batch");

        let table = MemTable::try_new(schema, vec![vec![batch]]).expect("build memtable");
        let ctx = SessionContext::new();
        ctx.register_table("users", Arc::new(table))
            .expect("register users");

        (ctx, TableReference::bare("users"))
    }

    fn filter_id_gt_one(table: &TableReference) -> RowFilter {
        RowFilter {
            table: table.clone(),
            predicate: col("id").gt(lit(1_i32)),
            org: None,
            groups: None,
        }
    }

    /// Apply an enforcer to the unoptimized plan for `sql` and
    /// return the rewritten `LogicalPlan`. Same convention
    /// `mask::tests::rewrite_sql` uses — the rewrite is meant for
    /// the unoptimized plan; `into_optimized_plan` would have
    /// already pushed predicates / collapsed `TableScan` projections.
    async fn rewrite_sql(
        ctx: &SessionContext,
        enforcer: &RowFilterEnforcer,
        sql: &str,
    ) -> LogicalPlan {
        let df = ctx.sql(sql).await.expect("plan SQL");
        let plan = df.logical_plan().clone();
        enforcer
            .rewrite(plan, &crate::Identity::anonymous())
            .expect("rewrite succeeds")
            .data
    }

    /// Execute `plan` against `ctx` and return result rows as
    /// `Vec<Vec<String>>` per row. Mirror of `mask::tests::execute_plan`.
    async fn execute_plan(ctx: &SessionContext, plan: LogicalPlan) -> Vec<Vec<String>> {
        let df = ctx.execute_logical_plan(plan).await.expect("execute");
        let batches = df.collect().await.expect("collect");
        let mut rows: Vec<Vec<String>> = Vec::new();
        for batch in batches {
            let cols = batch.num_columns();
            for i in 0..batch.num_rows() {
                let mut cells: Vec<String> = Vec::with_capacity(cols);
                for c in 0..cols {
                    let column = batch.column(c);
                    if let Some(arr) = column.as_any().downcast_ref::<StringArray>() {
                        cells.push(arr.value(i).to_string());
                    } else if let Some(arr) = column.as_any().downcast_ref::<Int32Array>() {
                        cells.push(arr.value(i).to_string());
                    } else {
                        cells.push(format!("<unknown@{c}>"));
                    }
                }
                rows.push(cells);
            }
        }
        rows
    }

    // ---- Construction tests ----

    #[test]
    fn duplicate_rules_rejected_at_construction() {
        let table = TableReference::bare("users");
        let err = RowFilterEnforcer::new([
            RowFilter {
                table: table.clone(),
                predicate: col("id").gt(lit(0_i32)),
                org: None,
                groups: None,
            },
            RowFilter {
                table: table.clone(),
                predicate: col("id").gt(lit(5_i32)),
                org: None,
                groups: None,
            },
        ])
        .unwrap_err();
        match err {
            BuildError::DuplicateRule { table: t } => assert_eq!(t, table),
        }
    }

    #[test]
    fn rules_on_distinct_tables_coexist() {
        let users = TableReference::bare("users");
        let orders = TableReference::bare("orders");
        let enforcer = RowFilterEnforcer::new([
            RowFilter {
                table: users,
                predicate: col("id").gt(lit(0_i32)),
                org: None,
                groups: None,
            },
            RowFilter {
                table: orders,
                predicate: col("status").eq(lit("active")),
                org: None,
                groups: None,
            },
        ])
        .expect("two distinct-table rules build");
        assert_eq!(enforcer.rule_count(), 2);
    }

    #[test]
    fn empty_enforcer_has_zero_rules() {
        let enforcer = RowFilterEnforcer::empty();
        assert_eq!(enforcer.rule_count(), 0);
    }

    // ---- Rewrite tests ----

    #[tokio::test]
    async fn row_filter_drops_non_matching_rows() {
        let (ctx, users) = ctx_with_users();
        let enforcer = RowFilterEnforcer::new([filter_id_gt_one(&users)]).expect("build");
        let plan = rewrite_sql(&ctx, &enforcer, "SELECT id, email FROM users").await;
        let rows = execute_plan(&ctx, plan).await;
        // Only rows with id > 1 survive — bob (2) and carol (3),
        // not alice (1).
        assert_eq!(
            rows.len(),
            2,
            "row filter must drop alice (id=1); got rows: {rows:?}",
        );
        let ids: Vec<&str> = rows.iter().map(|r| r[0].as_str()).collect();
        assert!(!ids.contains(&"1"), "alice's row leaked: {rows:?}");
        assert!(ids.contains(&"2"));
        assert!(ids.contains(&"3"));
    }

    #[tokio::test]
    async fn row_filter_with_no_matching_rule_is_identity() {
        let (ctx, _users) = ctx_with_users();
        let other = TableReference::bare("orders");
        let enforcer = RowFilterEnforcer::new([RowFilter {
            table: other,
            predicate: col("id").gt(lit(0_i32)),
            org: None,
            groups: None,
        }])
        .expect("build");
        let plan_in = ctx
            .sql("SELECT id FROM users")
            .await
            .expect("plan")
            .logical_plan()
            .clone();
        let out = enforcer
            .rewrite(plan_in, &crate::Identity::anonymous())
            .expect("rewrite");
        assert!(
            !out.transformed,
            "non-matching rule must produce Transformed::no",
        );
    }

    #[tokio::test]
    async fn row_filter_table_ref_qualified_is_strict() {
        let (ctx, _users) = ctx_with_users();
        // `users` is registered as Bare. A Full-qualified rule must
        // not match — `Eq` is the only matcher today.
        let other = TableReference::full("datafusion", "private", "users");
        let enforcer = RowFilterEnforcer::new([RowFilter {
            table: other,
            predicate: col("id").gt(lit(1_i32)),
            org: None,
            groups: None,
        }])
        .expect("build");
        let plan = rewrite_sql(&ctx, &enforcer, "SELECT id FROM users").await;
        let rows = execute_plan(&ctx, plan).await;
        // All 3 rows survive — strict matching means the rule
        // doesn't fire on `Bare("users")`.
        assert_eq!(rows.len(), 3, "strict match must not fire; got: {rows:?}");
    }

    #[tokio::test]
    async fn row_filter_via_optimizer_rule_adapter() {
        let (ctx, users) = ctx_with_users();
        let enforcer = Arc::new(RowFilterEnforcer::new([filter_id_gt_one(&users)]).expect("build"));
        let rule = PolicyOptimizerRule::new(enforcer);
        let plan = ctx
            .sql("SELECT id FROM users")
            .await
            .expect("plan")
            .logical_plan()
            .clone();
        let cfg = OptimizerContext::default();
        let out = rule.rewrite(plan, &cfg).expect("rule rewrite");
        assert!(out.transformed, "rule must report Transformed::yes");
    }

    #[tokio::test]
    async fn row_filter_empty_enforcer_is_noop_equivalent() {
        let (ctx, _users) = ctx_with_users();
        let enforcer = RowFilterEnforcer::empty();
        assert_eq!(enforcer.rule_count(), 0);
        let plan_in = ctx
            .sql("SELECT id FROM users")
            .await
            .expect("plan")
            .logical_plan()
            .clone();
        let out = enforcer
            .rewrite(plan_in, &crate::Identity::anonymous())
            .expect("rewrite");
        assert!(
            !out.transformed,
            "empty enforcer must produce Transformed::no",
        );
    }

    #[tokio::test]
    async fn row_filter_combines_with_user_predicate() {
        // The rule's predicate is mandatory. A user-supplied WHERE
        // narrows the result further but cannot widen past the
        // rule. Pin: rule says id > 1; user says email LIKE
        // 'alice%'. Result: empty (alice's id is 1, blocked by rule).
        let (ctx, users) = ctx_with_users();
        let enforcer = RowFilterEnforcer::new([filter_id_gt_one(&users)]).expect("build");
        let plan = rewrite_sql(
            &ctx,
            &enforcer,
            "SELECT id, email FROM users WHERE email LIKE 'alice%'",
        )
        .await;
        let rows = execute_plan(&ctx, plan).await;
        assert!(
            rows.is_empty(),
            "rule blocks alice; user predicate finds only alice; intersection empty: {rows:?}",
        );
    }

    #[tokio::test]
    async fn row_filter_rule_can_be_widened_by_user_predicate() {
        // Pin the converse: rule says id > 1; user says id = 2.
        // Result: just bob's row.
        let (ctx, users) = ctx_with_users();
        let enforcer = RowFilterEnforcer::new([filter_id_gt_one(&users)]).expect("build");
        let plan = rewrite_sql(&ctx, &enforcer, "SELECT id, email FROM users WHERE id = 2").await;
        let rows = execute_plan(&ctx, plan).await;
        assert_eq!(rows.len(), 1, "exactly bob's row: {rows:?}");
        assert_eq!(rows[0][0], "2");
        assert!(rows[0][1].starts_with("bob"));
    }

    /// Pin the contract the module docs promise: a row-filter
    /// predicate evaluates against **un-masked** column values
    /// even when a `ColumnMaskingEnforcer` for the same column is
    /// active in the same session. The two enforcers touch
    /// disjoint parts of the plan (`Filter` wraps `TableScan`;
    /// the column mask rewrites only `Projection.expr`), so they
    /// commute and the row-filter sees real data regardless of
    /// rewrite order.
    ///
    /// Setup:
    ///   - row-filter rule: `email LIKE 'alice%'`
    ///   - column-mask rule: `email → '***@example.com'`
    ///   - query:           `SELECT email FROM users`
    ///
    /// Expected:
    ///   - exactly 1 row survives (Alice's, matched on her real
    ///     email — masking the predicate would have produced
    ///     0 rows since `'***@example.com'` does NOT match
    ///     `'alice%'`)
    ///   - the projected `email` reads as the mask literal
    ///     `'***@example.com'`
    #[tokio::test]
    async fn row_filter_predicate_sees_unmasked_values_even_with_column_mask() {
        use crate::mask::{ColumnMask, ColumnMaskingEnforcer};

        let (ctx, users) = ctx_with_users();

        let row_enforcer = RowFilterEnforcer::new([RowFilter {
            table: users.clone(),
            predicate: col("email").like(lit("alice%")),
            org: None,
            groups: None,
        }])
        .expect("build row enforcer");

        let mask_enforcer = ColumnMaskingEnforcer::new([ColumnMask {
            table: users.clone(),
            column: "email".to_string(),
            mask: lit("***@example.com"),
            org: None,
            groups: None,
        }])
        .expect("build mask enforcer");

        let plan = ctx
            .sql("SELECT email FROM users")
            .await
            .expect("plan SELECT")
            .logical_plan()
            .clone();

        // Apply row filter THEN mask. Order shouldn't matter
        // (disjoint plan regions), but pin a fixed order so any
        // future ordering bug surfaces here.
        let plan = row_enforcer
            .rewrite(plan, &crate::Identity::anonymous())
            .expect("row rewrite")
            .data;
        let plan = mask_enforcer
            .rewrite(plan, &crate::Identity::anonymous())
            .expect("mask rewrite")
            .data;

        let rows = execute_plan(&ctx, plan).await;
        assert_eq!(
            rows.len(),
            1,
            "row-filter predicate must see un-masked email values to find \
             Alice's row; got rows: {rows:?}",
        );
        assert_eq!(
            rows[0][0], "***@example.com",
            "Alice's projected email must show the mask literal, not raw",
        );
    }

    /// Companion to the above — same setup but apply mask FIRST,
    /// row-filter SECOND. Pins commutativity. If a future
    /// refactor introduces an ordering dependency (e.g.,
    /// composing both into a single optimizer pass that batches
    /// rewrites), one of these two tests will surface it.
    #[tokio::test]
    async fn row_filter_and_column_mask_compose_in_either_order() {
        use crate::mask::{ColumnMask, ColumnMaskingEnforcer};

        let (ctx, users) = ctx_with_users();

        let row_enforcer = RowFilterEnforcer::new([RowFilter {
            table: users.clone(),
            predicate: col("email").like(lit("alice%")),
            org: None,
            groups: None,
        }])
        .expect("build row enforcer");

        let mask_enforcer = ColumnMaskingEnforcer::new([ColumnMask {
            table: users.clone(),
            column: "email".to_string(),
            mask: lit("***@example.com"),
            org: None,
            groups: None,
        }])
        .expect("build mask enforcer");

        let plan = ctx
            .sql("SELECT email FROM users")
            .await
            .expect("plan SELECT")
            .logical_plan()
            .clone();

        // Mask first, row-filter second — opposite of the test
        // above.
        let plan = mask_enforcer
            .rewrite(plan, &crate::Identity::anonymous())
            .expect("mask rewrite")
            .data;
        let plan = row_enforcer
            .rewrite(plan, &crate::Identity::anonymous())
            .expect("row rewrite")
            .data;

        let rows = execute_plan(&ctx, plan).await;
        assert_eq!(
            rows.len(),
            1,
            "either order must produce the same 1-row result; got: {rows:?}",
        );
        assert_eq!(rows[0][0], "***@example.com");
    }

    /// Empty-relation plan: no `TableScan` nodes ⇒ rewrite is a
    /// no-op even with rules registered. Pins that the walker
    /// doesn't trip on plans with nothing to filter.
    #[test]
    fn row_filter_on_plan_without_table_scan_is_noop() {
        let users = TableReference::bare("users");
        let enforcer = RowFilterEnforcer::new([filter_id_gt_one(&users)]).expect("build");
        let plan = LogicalPlan::EmptyRelation(EmptyRelation {
            produce_one_row: false,
            schema: Arc::new(DFSchema::empty()),
        });
        let out = enforcer
            .rewrite(plan, &crate::Identity::anonymous())
            .expect("rewrite");
        assert!(
            !out.transformed,
            "no TableScan ⇒ Transformed::no (rule didn't fire)",
        );
    }

    /// Regression for: a rule registered on the **bare** `users` must
    /// fire whether the query references the table bare, schema-qualified, or
    /// fully-qualified — qualifying a table name cannot be used to dodge a
    /// row filter.
    #[tokio::test]
    async fn row_filter_fires_regardless_of_reference_qualification() {
        let (ctx, table) = ctx_with_users(); // bare("users")
        let enforcer = RowFilterEnforcer::new([filter_id_gt_one(&table)]).expect("build");
        for sql in [
            "SELECT id FROM users",
            "SELECT id FROM public.users",
            "SELECT id FROM datafusion.public.users",
        ] {
            let plan = rewrite_sql(&ctx, &enforcer, sql).await;
            let rows = execute_plan(&ctx, plan).await;
            assert_eq!(
                rows.len(),
                2,
                "row filter (id > 1) should fire for `{sql}` — got {rows:?}",
            );
        }
    }

    /// Every row-filter decision emits a `dataglot::audit` event with
    /// the session identity and the filtered table — the filter-side
    /// half of the audit-completeness follow-up (Ranger parity).
    #[tokio::test]
    async fn row_filter_decision_is_audited_with_identity() {
        let (ctx, users) = ctx_with_users();
        let enforcer = RowFilterEnforcer::new([filter_id_gt_one(&users)]).expect("build enforcer");
        let df = ctx.sql("SELECT id FROM users").await.expect("plan SQL");
        let plan = df.logical_plan().clone();

        let identity = crate::Identity::user("carol").with_groups(["auditor"]);
        let logged = crate::audit::test_capture::capture_logs(|| {
            enforcer.rewrite(plan, &identity).expect("rewrite succeeds");
        });

        assert!(logged.contains("dataglot::audit"), "target: {logged}");
        assert!(logged.contains("row_filter"), "action: {logged}");
        assert!(logged.contains("users"), "resource: {logged}");
        assert!(logged.contains("carol"), "user: {logged}");
    }

    // ----: row filters on an aliased table ----

    /// Unparse a plan with the PostgreSQL dialect (what the federation layer
    /// uses to push predicates to a Postgres source).
    fn unparse_pg(plan: &LogicalPlan) -> String {
        use datafusion::sql::unparser::dialect::PostgreSqlDialect;
        use datafusion::sql::unparser::Unparser;
        Unparser::new(&PostgreSqlDialect {})
            .plan_to_sql(plan)
            .expect("plan unparses")
            .to_string()
    }

    /// **The  regression.** When the filtered table is aliased
    /// (`FROM users u`), the injected predicate must be qualified to the
    /// alias (`u.email`), and the `Filter` must sit **above** the
    /// `SubqueryAlias` — so the federation-pushed SQL (`FROM users AS u …`)
    /// stays valid. Before the fix the predicate kept the base table name,
    /// which the federation unparser rendered as `WHERE "users"."email"` —
    /// invalid under the alias (Postgres: "invalid reference to FROM-clause
    /// entry for table users").
    #[tokio::test]
    async fn aliased_row_filter_predicate_is_qualified_to_the_alias() {
        let (ctx, users) = ctx_with_users();
        let enforcer = RowFilterEnforcer::new([RowFilter {
            table: users,
            predicate: col("email").eq(lit("bob@example.com")),
            org: None,
            groups: None,
        }])
        .expect("build enforcer");

        let plan = rewrite_sql(&ctx, &enforcer, "SELECT u.email FROM users u").await;

        // Structure: Projection → Filter → SubqueryAlias → TableScan. The
        // Filter is ABOVE the alias (not wrapped around the raw scan).
        let LogicalPlan::Projection(proj) = &plan else {
            panic!("expected a Projection at the root, got {plan:?}");
        };
        assert!(
            matches!(proj.input.as_ref(), LogicalPlan::Filter(f)
                if matches!(f.input.as_ref(), LogicalPlan::SubqueryAlias(_))),
            "row-filter Filter must sit above the SubqueryAlias; got {:?}",
            proj.input
        );

        // Unparse: the WHERE must reference the alias, never the base table.
        let sql = unparse_pg(&plan);
        assert!(
            sql.contains(r#""u"."email""#),
            "predicate must be alias-qualified (u.email); got: {sql}"
        );
        assert!(
            !sql.contains(r#""users"."email""#),
            "predicate must NOT reference the base table under an alias; got: {sql}"
        );
    }

    /// Every column of a multi-column (`sql`-style) predicate is re-qualified
    /// to the alias, not just the first — a predicate touching two columns
    /// must not leave one qualified to the base table.
    #[tokio::test]
    async fn aliased_row_filter_requalifies_every_column() {
        let (ctx, users) = ctx_with_users();
        let enforcer = RowFilterEnforcer::new([RowFilter {
            table: users,
            // references both `email` and `id`
            predicate: col("email")
                .eq(lit("bob@example.com"))
                .and(col("id").gt(lit(0_i32))),
            org: None,
            groups: None,
        }])
        .expect("build enforcer");

        let plan = rewrite_sql(&ctx, &enforcer, "SELECT u.id FROM users u").await;
        let sql = unparse_pg(&plan);
        assert!(
            sql.contains(r#""u"."email""#) && sql.contains(r#""u"."id""#),
            "both columns must be alias-qualified; got: {sql}"
        );
        assert!(
            !sql.contains(r#""users"."#),
            "no column may reference the base table under an alias; got: {sql}"
        );
    }

    /// The unaliased path is unchanged and still valid — the Filter wraps the
    /// `TableScan` and the predicate resolves against the base table.
    #[tokio::test]
    async fn unaliased_row_filter_still_wraps_the_scan() {
        let (ctx, users) = ctx_with_users();
        let enforcer = RowFilterEnforcer::new([RowFilter {
            table: users,
            predicate: col("email").eq(lit("bob@example.com")),
            org: None,
            groups: None,
        }])
        .expect("build enforcer");

        let plan = rewrite_sql(&ctx, &enforcer, "SELECT email FROM users").await;
        // Filter directly over the TableScan (no alias in play).
        let LogicalPlan::Projection(proj) = &plan else {
            panic!("expected Projection root");
        };
        assert!(
            matches!(proj.input.as_ref(), LogicalPlan::Filter(f)
                if matches!(f.input.as_ref(), LogicalPlan::TableScan(_))),
            "unaliased row-filter must wrap the TableScan directly; got {:?}",
            proj.input
        );
        let sql = unparse_pg(&plan);
        assert!(
            sql.to_lowercase().contains("where"),
            "filter applied: {sql}"
        );
    }

    /// Similar source: the fix is dialect-agnostic (it rewrites the plan, not
    /// the SQL text), so a MySQL-federated aliased table is alias-qualified
    /// too — `` `u`.`email` ``, never `` `users`.`email` `` under the alias.
    #[tokio::test]
    async fn aliased_row_filter_is_alias_qualified_for_mysql_dialect() {
        use datafusion::sql::unparser::dialect::MySqlDialect;
        use datafusion::sql::unparser::Unparser;
        let (ctx, users) = ctx_with_users();
        let enforcer = RowFilterEnforcer::new([RowFilter {
            table: users,
            predicate: col("email").eq(lit("bob@example.com")),
            org: None,
            groups: None,
        }])
        .expect("build enforcer");
        let plan = rewrite_sql(&ctx, &enforcer, "SELECT u.email FROM users u").await;
        let sql = Unparser::new(&MySqlDialect {})
            .plan_to_sql(&plan)
            .expect("plan unparses")
            .to_string();
        assert!(
            sql.contains("`u`.`email`"),
            "MySQL predicate must be alias-qualified; got: {sql}"
        );
        assert!(
            !sql.contains("`users`.`email`"),
            "must not reference the base table under an alias; got: {sql}"
        );
    }

    // ----  F4: per-org (tenant-scoped) row-filter isolation ----

    /// A row filter created under org `acme` (`org = Some("acme")`) filters
    /// rows only for an `acme` session; a `beta` session sees unfiltered
    /// rows, and so does an anonymous session.
    #[tokio::test]
    async fn tenant_row_filter_only_fires_for_its_own_org() {
        let (ctx, users) = ctx_with_users();
        // acme keeps only id > 1 (drops alice, id=1).
        let enforcer = RowFilterEnforcer::new([RowFilter {
            table: users,
            predicate: col("id").gt(lit(1_i32)),
            org: Some("acme".to_string()),
            groups: None,
        }])
        .expect("build");

        // acme → filtered (2 rows).
        let plan = ctx
            .sql("SELECT id FROM users")
            .await
            .expect("plan")
            .logical_plan()
            .clone();
        let acme = crate::Identity::user("a").with_org("acme");
        let plan = enforcer.rewrite(plan, &acme).expect("rewrite").data;
        let rows = execute_plan(&ctx, plan).await;
        assert_eq!(rows.len(), 2, "acme must see only id>1 rows; got {rows:?}");

        // beta → unfiltered (all 3 rows), and rewrite is a no-op.
        let plan = ctx
            .sql("SELECT id FROM users")
            .await
            .expect("plan")
            .logical_plan()
            .clone();
        let beta = crate::Identity::user("b").with_org("beta");
        let out = enforcer.rewrite(plan, &beta).expect("rewrite");
        assert!(
            !out.transformed,
            "an acme-scoped row filter must not touch a beta session"
        );
        let rows = execute_plan(&ctx, out.data).await;
        assert_eq!(rows.len(), 3, "beta must see all rows; got {rows:?}");

        // anonymous → unfiltered too.
        let plan = ctx
            .sql("SELECT id FROM users")
            .await
            .expect("plan")
            .logical_plan()
            .clone();
        let out = enforcer
            .rewrite(plan, &crate::Identity::anonymous())
            .expect("rewrite");
        assert!(
            !out.transformed,
            "an acme-scoped row filter must not touch an anonymous session"
        );
    }

    ///: a **group-scoped** row filter (`groups = Some(["support"])`)
    /// filters rows for a session in that group and leaves them unfiltered for
    /// a session in a different group — per-role RLS (slide 11). Proven
    /// end-to-end: the plan is rewritten *and executed*, and the row count is
    /// asserted.
    #[tokio::test]
    async fn group_scoped_row_filter_only_fires_for_matching_group() {
        let (ctx, users) = ctx_with_users();
        // support-group sessions keep only id > 1 (drops alice, id=1).
        let enforcer = RowFilterEnforcer::new([RowFilter {
            table: users,
            predicate: col("id").gt(lit(1_i32)),
            org: None,
            groups: Some(vec![crate::OrgGroupId::new("support")]),
        }])
        .expect("build");

        // In-group session → filtered (2 rows).
        let plan = ctx
            .sql("SELECT id FROM users")
            .await
            .expect("plan")
            .logical_plan()
            .clone();
        let support = crate::Identity::user("s").with_groups(["support"]);
        let plan = enforcer.rewrite(plan, &support).expect("rewrite").data;
        let rows = execute_plan(&ctx, plan).await;
        assert_eq!(
            rows.len(),
            2,
            "a support-group session must see only id>1 rows; got {rows:?}"
        );

        // Different-group session → unfiltered (all 3 rows), rewrite is a no-op.
        let plan = ctx
            .sql("SELECT id FROM users")
            .await
            .expect("plan")
            .logical_plan()
            .clone();
        let finance = crate::Identity::user("f").with_groups(["finance"]);
        let out = enforcer.rewrite(plan, &finance).expect("rewrite");
        assert!(
            !out.transformed,
            "a support-scoped row filter must not touch a finance-group session"
        );
        let rows = execute_plan(&ctx, out.data).await;
        assert_eq!(rows.len(), 3, "finance must see all rows; got {rows:?}");
    }

    /// An operator-wide row filter (`org = None`) applies to every org —
    /// backward-compat with the file-config path.
    #[tokio::test]
    async fn operator_wide_row_filter_applies_to_every_org() {
        let (ctx, users) = ctx_with_users();
        let enforcer = RowFilterEnforcer::new([filter_id_gt_one(&users)]).expect("build");
        for identity in [
            crate::Identity::user("a").with_org("acme"),
            crate::Identity::user("b").with_org("beta"),
            crate::Identity::anonymous(),
        ] {
            let plan = ctx
                .sql("SELECT id FROM users")
                .await
                .expect("plan")
                .logical_plan()
                .clone();
            let plan = enforcer.rewrite(plan, &identity).expect("rewrite").data;
            let rows = execute_plan(&ctx, plan).await;
            assert_eq!(
                rows.len(),
                2,
                "operator-wide filter must apply for {identity:?}; got {rows:?}"
            );
        }
    }

    /// Two tenants may register a filter on the **same** table without a
    /// `DuplicateRule` error; each session sees only its own tenant's rows.
    #[tokio::test]
    async fn distinct_tenants_coexist_on_same_table() {
        let (ctx, users) = ctx_with_users();
        // acme keeps id=2; beta keeps id=3.
        let acme = RowFilter {
            table: users.clone(),
            predicate: col("id").eq(lit(2_i32)),
            org: Some("acme".to_string()),
            groups: None,
        };
        let beta = RowFilter {
            table: users.clone(),
            predicate: col("id").eq(lit(3_i32)),
            org: Some("beta".to_string()),
            groups: None,
        };
        let enforcer =
            RowFilterEnforcer::new([acme, beta]).expect("distinct-org filters on same table");
        assert_eq!(enforcer.rule_count(), 2);

        for (org, keep_id) in [("acme", "2"), ("beta", "3")] {
            let plan = ctx
                .sql("SELECT id FROM users")
                .await
                .expect("plan")
                .logical_plan()
                .clone();
            let identity = crate::Identity::user("u").with_org(org);
            let plan = enforcer.rewrite(plan, &identity).expect("rewrite").data;
            let rows = execute_plan(&ctx, plan).await;
            assert_eq!(rows.len(), 1, "{org} sees exactly one row; got {rows:?}");
            assert_eq!(rows[0][0], keep_id, "{org} keeps id={keep_id}");
        }
    }

    /// Rewrite the unoptimized plan for `sql` under an explicit `identity`
    /// (the [`rewrite_sql`] helper hardcodes anonymous). Used by the
    /// cross-qualification shadowing regression below.
    async fn rewrite_sql_as(
        ctx: &SessionContext,
        enforcer: &RowFilterEnforcer,
        sql: &str,
        identity: &crate::Identity,
    ) -> LogicalPlan {
        let df = ctx.sql(sql).await.expect("plan SQL");
        let plan = df.logical_plan().clone();
        enforcer.rewrite(plan, identity).expect("rewrite").data
    }

    /// **Cross-tenant shadowing regression (`CodeRabbit` "Major").** A tenant
    /// rule registered under one qualification (`datafusion.public.users`)
    /// must NOT shadow an operator-wide rule registered under another (bare
    /// `users`) on the same logical table. Before the union fix,
    /// `resolve_predicate` stopped at the first candidate key that existed in
    /// the map (the full-qualified tenant rule) and a non-tenant session got
    /// **no filter at all** — a governance leak.
    #[tokio::test]
    async fn operator_wide_filter_is_not_shadowed_by_tenant_rule_under_other_qualification() {
        let (ctx, _users) = ctx_with_users();
        let enforcer = RowFilterEnforcer::new([
            // acme tenant rule, keyed on the FULLY-qualified table.
            RowFilter {
                table: TableReference::full("datafusion", "public", "users"),
                predicate: col("id").eq(lit(2_i32)),
                org: Some("acme".to_string()),
                groups: None,
            },
            // Operator-wide rule, keyed on the BARE table.
            RowFilter {
                table: TableReference::bare("users"),
                predicate: col("id").gt(lit(1_i32)),
                org: None,
                groups: None,
            },
        ])
        .expect("build");

        // (a) A non-tenant (beta) session scanning the fully-qualified table
        // must still get the operator-wide filter (id > 1 ⇒ 2 rows). The acme
        // rule under the full key must not shadow it away.
        let beta = crate::Identity::user("b").with_org("beta");
        let plan = rewrite_sql_as(
            &ctx,
            &enforcer,
            "SELECT id FROM datafusion.public.users",
            &beta,
        )
        .await;
        let rows = execute_plan(&ctx, plan).await;
        assert_eq!(
            rows.len(),
            2,
            "operator-wide filter must fire for a non-tenant session (no shadowing); got {rows:?}"
        );

        // (b) The acme session gets its own tenant rule (id = 2 ⇒ 1 row) —
        // tenant wins over the operator-wide fallback.
        let acme = crate::Identity::user("a").with_org("acme");
        let plan = rewrite_sql_as(
            &ctx,
            &enforcer,
            "SELECT id FROM datafusion.public.users",
            &acme,
        )
        .await;
        let rows = execute_plan(&ctx, plan).await;
        assert_eq!(
            rows.len(),
            1,
            "acme tenant rule keeps only id=2; got {rows:?}"
        );
        assert_eq!(rows[0][0], "2");
    }

    /// Same `(table, org)` twice is still a `DuplicateRule` — the org
    /// dimension narrows the uniqueness key, it doesn't remove it.
    #[test]
    fn same_table_org_is_still_duplicate() {
        let table = TableReference::bare("users");
        let err = RowFilterEnforcer::new([
            RowFilter {
                table: table.clone(),
                predicate: col("id").gt(lit(0_i32)),
                org: Some("acme".to_string()),
                groups: None,
            },
            RowFilter {
                table: table.clone(),
                predicate: col("id").gt(lit(5_i32)),
                org: Some("acme".to_string()),
                groups: None,
            },
        ])
        .unwrap_err();
        match err {
            BuildError::DuplicateRule { table: t } => assert_eq!(t, table),
        }
    }

    // ----  follow-up: row filters descend into expression subqueries ----

    /// Register `orders(id, user_id, amount)` alongside `users` so a subquery
    /// can read one table while the outer query reads another.
    fn ctx_with_users_and_orders() -> (SessionContext, TableReference) {
        let (ctx, users_ref) = ctx_with_users();
        let schema = Arc::new(Schema::new(vec![
            Field::new("id", DataType::Int32, false),
            Field::new("user_id", DataType::Int32, false),
            Field::new("amount", DataType::Int32, false),
        ]));
        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(Int32Array::from(vec![101, 102, 103, 104])),
                Arc::new(Int32Array::from(vec![1, 2, 2, 3])),
                Arc::new(Int32Array::from(vec![49, 19, 199, 79])),
            ],
        )
        .expect("build orders batch");
        let table = MemTable::try_new(schema, vec![vec![batch]]).expect("build orders memtable");
        ctx.register_table("orders", Arc::new(table))
            .expect("register orders");
        (ctx, users_ref)
    }

    /// Whether `needle` appears in the Debug of any subquery plan embedded in
    /// `plan`'s expressions, to any depth. `Subquery`'s own Debug collapses to
    /// `<subquery>`, so we pull each embedded `Arc<LogicalPlan>` out and render
    /// *it* (whose tree shows the injected `Filter`).
    fn any_subquery_plan_contains(plan: &LogicalPlan, needle: &str) -> bool {
        let mut found = false;
        let _ = plan.apply(|node| {
            for expr in node.expressions() {
                let _ = expr.apply(|e| {
                    if let Some(sub) = crate::embedded_subquery(e) {
                        if format!("{:?}", sub.as_ref()).contains(needle)
                            || any_subquery_plan_contains(sub, needle)
                        {
                            found = true;
                        }
                    }
                    Ok(TreeNodeRecursion::Continue)
                });
            }
            Ok(TreeNodeRecursion::Continue)
        });
        found
    }

    /// A row filter registered on `users` fires **inside an `IN` subquery** even
    /// when the outer query reads a different table: the subquery sees only the
    /// filtered rows. Outer reads `orders` (no rule); the `IN (SELECT id FROM
    /// users)` subquery is filtered to `id > 1`, so `orders.user_id` can only
    /// match `{2, 3}` — 3 of the 4 orders survive (without descent all 4 would).
    #[tokio::test]
    async fn row_filter_applies_inside_in_subquery() {
        let (ctx, users) = ctx_with_users_and_orders();
        let enforcer = RowFilterEnforcer::new([filter_id_gt_one(&users)]).expect("build");
        let plan = rewrite_sql(
            &ctx,
            &enforcer,
            "SELECT o.id FROM orders o WHERE o.user_id IN (SELECT id FROM users)",
        )
        .await;
        let rows = execute_plan(&ctx, plan).await;
        assert_eq!(
            rows.len(),
            3,
            "subquery filtered to id>1 ⇒ user_id ∈ {{2,3}} matches 3 orders; got {rows:?}"
        );
    }

    /// **Correlated** subquery: the subquery's own scan (`users`) is wrapped in
    /// the row-filter `Filter`, while the outer reference (`orders.user_id`, an
    /// `OuterReferenceColumn` belonging to the parent) is left untouched. A
    /// `LIMIT`-correlated scalar subquery is not decorrelatable, so assert on
    /// the plan: a `Filter` is injected inside the subquery and the correlation
    /// (`OuterReferenceColumn`) survives — proving `outer_ref_columns` was
    /// preserved and the outer ref was not filtered as if it were the
    /// subquery's own scan.
    #[tokio::test]
    async fn row_filter_applies_inside_correlated_subquery_but_not_outer_ref() {
        let (ctx, users) = ctx_with_users_and_orders();
        let enforcer = RowFilterEnforcer::new([filter_id_gt_one(&users)]).expect("build");
        let plan = rewrite_sql(
            &ctx,
            &enforcer,
            "SELECT o.id, \
             (SELECT id FROM users WHERE users.id = o.user_id LIMIT 1) AS uid \
             FROM orders o",
        )
        .await;
        assert!(
            any_subquery_plan_contains(&plan, "Filter("),
            "correlated subquery's own users scan must be wrapped in a Filter; got {plan:?}"
        );
        assert!(
            any_subquery_plan_contains(&plan, "OuterReferenceColumn"),
            "correlated outer ref must be preserved untouched in the subquery; got {plan:?}"
        );
    }

    // ---- symmetry with mask.rs: filter fires inside every subquery variant --
    // Mirrors mask.rs's scalar / exists / = ANY / nested subquery coverage.
    // A `LIMIT`-bounded or `EXISTS`/`= ANY` subquery is not decorrelatable, so
    // (as in the correlated test) we assert on the plan: the row-filter
    // `Filter` is injected into the subquery's own `users` scan.

    /// (scalar) The subquery projecting `users` in the projection position is
    /// wrapped in the row-filter `Filter`.
    #[tokio::test]
    async fn row_filter_applies_inside_scalar_subquery() {
        let (ctx, users) = ctx_with_users_and_orders();
        let enforcer = RowFilterEnforcer::new([filter_id_gt_one(&users)]).expect("build");
        let plan = rewrite_sql(
            &ctx,
            &enforcer,
            "SELECT (SELECT id FROM users LIMIT 1) AS uid",
        )
        .await;
        assert!(
            any_subquery_plan_contains(&plan, "Filter("),
            "scalar subquery's users scan must be wrapped in a Filter; got {plan:?}"
        );
    }

    /// (`EXISTS`) The subquery scanning `users` is filtered even though only its
    /// non-emptiness reaches the outer query.
    #[tokio::test]
    async fn row_filter_applies_inside_exists_subquery() {
        let (ctx, users) = ctx_with_users_and_orders();
        let enforcer = RowFilterEnforcer::new([filter_id_gt_one(&users)]).expect("build");
        let plan = rewrite_sql(
            &ctx,
            &enforcer,
            "SELECT o.id FROM orders o WHERE EXISTS (SELECT 1 FROM users)",
        )
        .await;
        assert!(
            any_subquery_plan_contains(&plan, "Filter("),
            "EXISTS subquery's users scan must be wrapped in a Filter; got {plan:?}"
        );
    }

    /// (`= ANY`) The `SetComparison` subquery's `users` scan is filtered.
    #[tokio::test]
    async fn row_filter_applies_inside_any_subquery() {
        let (ctx, users) = ctx_with_users_and_orders();
        let enforcer = RowFilterEnforcer::new([filter_id_gt_one(&users)]).expect("build");
        let plan = rewrite_sql(
            &ctx,
            &enforcer,
            "SELECT o.id FROM orders o WHERE o.user_id = ANY (SELECT id FROM users)",
        )
        .await;
        assert!(
            any_subquery_plan_contains(&plan, "Filter("),
            "= ANY subquery's users scan must be wrapped in a Filter; got {plan:?}"
        );
    }

    /// (nested) A subquery within a subquery: the innermost `users` scan (two
    /// expression-subquery levels deep) is still filtered.
    #[tokio::test]
    async fn row_filter_applies_inside_nested_subquery() {
        let (ctx, users) = ctx_with_users_and_orders();
        let enforcer = RowFilterEnforcer::new([filter_id_gt_one(&users)]).expect("build");
        let plan = rewrite_sql(
            &ctx,
            &enforcer,
            "SELECT (SELECT (SELECT id FROM users LIMIT 1)) AS uid",
        )
        .await;
        assert!(
            any_subquery_plan_contains(&plan, "Filter("),
            "doubly-nested subquery's users scan must be wrapped in a Filter; got {plan:?}"
        );
    }

    /// No applicable rule ⇒ the subquery descent is a strict no-op: a query
    /// whose only scan lives inside a subquery, with a rule on a *different*
    /// table, must report `Transformed::no`.
    #[tokio::test]
    async fn row_filter_subquery_descent_is_noop_without_rule() {
        let (ctx, _users) = ctx_with_users_and_orders();
        let other = TableReference::bare("nonexistent");
        let enforcer = RowFilterEnforcer::new([filter_id_gt_one(&other)]).expect("build");
        let plan_in = ctx
            .sql("SELECT o.id FROM orders o WHERE o.user_id IN (SELECT id FROM users)")
            .await
            .expect("plan")
            .logical_plan()
            .clone();
        let out = enforcer
            .rewrite(plan_in, &crate::Identity::anonymous())
            .expect("rewrite");
        assert!(
            !out.transformed,
            "no applicable rule ⇒ subquery descent must be Transformed::no",
        );
    }
}

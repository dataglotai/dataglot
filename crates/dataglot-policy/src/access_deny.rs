//! Access-deny enforcement — Apache Ranger access-policy parity (Ranger
//! policy-parity slice 2).
//!
//! Ranger's core policy type is **access control**: "group X cannot see
//! table/column Y." Dataglot already masks and row-filters, but had no
//! way to deny access outright. [`AccessDenyEnforcer`] closes that gap.
//!
//! Because Dataglot's pgwire surface is read-only, "deny" means **reject
//! the query** — a denied resource referenced by the plan raises a
//! planning error (`permission denied: …`), surfaced to the client the
//! same way Postgres surfaces an authorization failure. Enforcement is
//! plan-time, like every other Dataglot policy.
//!
//! Two granularities, both group-scoped:
//!
//! - **Table-level** ([`AccessDenial::column`] = `None`): any scan of the
//!   table is denied.
//! - **Column-level** ([`AccessDenial::column`] = `Some`): a *reference*
//!   to the column (in the projection, a predicate, `SELECT *`, …) is
//!   denied; queries that never touch the column still run.
//!
//! Group scoping mirrors the tag-based enforcer: a denial with an empty
//! [`AccessDenial::groups`] applies to **everyone**; otherwise it applies
//! only when the session [`Identity::org_groups`] intersects the list.
//!
//! Table matching reuses `match_candidates`, so a bare-name
//! denial (`users`) covers a qualified scan (`pg.public.users`) —
//! qualifying a table can't dodge the denial (same convention as the
//! row-filter / mask enforcers).
//!
//! # Limitations (slice 2)
//!
//! Column-level denial matches **qualified** column references
//! (`relation` present), which is what DataFusion's planner emits for
//! `SELECT col FROM t`, `SELECT *`, and predicate references. An
//! unqualified reference in a multi-table context is not matched; the
//! follow-up precedence/RBAC slices tighten this.

use datafusion::common::tree_node::{TreeNode, TreeNodeRecursion};
use datafusion::error::DataFusionError;
use datafusion::logical_expr::{Expr, LogicalPlan};
use datafusion::sql::TableReference;

use crate::{Identity, PolicyEnforcer};

/// One access-deny rule.
#[derive(Debug, Clone)]
pub struct AccessDenial {
    /// Table the denial targets. Matched at every qualification level
    /// (see `match_candidates`).
    pub table: TableReference,
    /// Column within `table` to deny, or `None` to deny the whole table.
    pub column: Option<String>,
    /// Org-groups the denial applies to. Empty ⇒ applies to all
    /// identities; otherwise applies when the session identity is in any
    /// listed group.
    pub groups: Vec<String>,
}

impl AccessDenial {
    /// Whether this denial applies to `identity`.
    fn applies_to(&self, identity: &Identity) -> bool {
        self.groups.is_empty()
            || self
                .groups
                .iter()
                .any(|g| identity.org_groups.iter().any(|og| og == g))
    }
}

/// `PolicyEnforcer` that rejects queries touching a denied table/column.
#[derive(Debug, Default)]
pub struct AccessDenyEnforcer {
    denials: Vec<AccessDenial>,
}

impl AccessDenyEnforcer {
    /// Build an enforcer from a set of denial rules.
    #[must_use]
    pub fn new(denials: impl IntoIterator<Item = AccessDenial>) -> Self {
        Self {
            denials: denials.into_iter().collect(),
        }
    }

    /// An enforcer with no rules (a no-op).
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Number of denial rules.
    #[must_use]
    pub fn rule_count(&self) -> usize {
        self.denials.len()
    }
}

fn table_denied(table: &TableReference) -> DataFusionError {
    DataFusionError::Plan(format!(
        "permission denied: access to table \"{table}\" is denied by policy"
    ))
}

fn column_denied(table: &TableReference, column: &str) -> DataFusionError {
    DataFusionError::Plan(format!(
        "permission denied: access to column \"{column}\" of table \"{table}\" is denied by policy"
    ))
}

/// Does `denial.table` match `reference` at any qualification level?
fn table_matches(denial: &TableReference, reference: &TableReference) -> bool {
    crate::match_candidates(reference)
        .iter()
        .any(|cand| cand == denial)
}

/// Reject a qualified reference to a denied column anywhere in `plan`,
/// **descending into subqueries embedded in expressions** — which
/// [`LogicalPlan::apply`] / [`Expr::apply`] would otherwise skip, letting a
/// denied column referenced only inside a subquery
/// (`SELECT (SELECT ssn FROM t)`, `WHERE x IN (SELECT ssn FROM t)`, …) slip
/// past enforcement. The matching itself (column-vs-table, group scoping) is
/// unchanged from the top-level walk — only the traversal reaches deeper.
///
/// The first match returns `Err`, short-circuiting the whole walk.
fn deny_columns_in(
    plan: &LogicalPlan,
    applicable: &[&AccessDenial],
    identity: &Identity,
) -> Result<(), DataFusionError> {
    plan.apply(|node| {
        for expr in node.expressions() {
            expr.apply(|e| {
                if let Expr::Column(c) = e {
                    if let Some(relation) = &c.relation {
                        for denial in applicable {
                            if let Some(col) = &denial.column {
                                if col == &c.name && table_matches(&denial.table, relation) {
                                    crate::audit::record_decision(
                                        "deny",
                                        identity,
                                        &format!("{}.{col}", denial.table),
                                    );
                                    return Err(column_denied(&denial.table, col));
                                }
                            }
                        }
                    }
                } else if let Some(subplan) = crate::embedded_subquery(e) {
                    // `Expr::apply` treats the subquery-bearing variants as
                    // leaves (or follows only the compare expr), so recurse into
                    // the subquery plan by hand to reach columns nested inside
                    // it, to any depth — over the same four variants the rewrite
                    // and explain paths descend into.
                    deny_columns_in(subplan, applicable, identity)?;
                }
                Ok(TreeNodeRecursion::Continue)
            })?;
        }
        Ok(TreeNodeRecursion::Continue)
    })
    .map(|_| ())
}

impl PolicyEnforcer for AccessDenyEnforcer {
    fn explain(&self, plan: &LogicalPlan, identity: &Identity) -> Vec<crate::PolicyDecision> {
        use crate::{PolicyAction, PolicyDecision};
        let applicable: Vec<&AccessDenial> = self
            .denials
            .iter()
            .filter(|d| d.applies_to(identity))
            .collect();
        if applicable.is_empty() {
            return Vec::new();
        }
        let mut out: Vec<PolicyDecision> = Vec::new();
        let add = |resource: String, out: &mut Vec<PolicyDecision>| {
            if !out.iter().any(|d| d.resource == resource) {
                out.push(PolicyDecision::new(
                    PolicyAction::Deny,
                    resource,
                    "access denied by policy",
                ));
            }
        };
        // Table-level denials: any scan of a denied table, including scans
        // nested in expression subqueries that a plain
        // `LogicalPlan::apply` would skip.
        if let Err(err) = crate::try_for_each_table_scan(plan, &mut |scan| {
            for denial in &applicable {
                if denial.column.is_none() && table_matches(&denial.table, &scan.table_name) {
                    add(denial.table.to_string(), &mut out);
                }
            }
            Ok(())
        }) {
            // A traversal failure means `explain` under-reports the
            // table-level denials in force — surface it ( 1b).
            tracing::warn!(
                error = %err,
                "policy: plan traversal failed while explaining table denials; the decision list may be incomplete"
            );
        }
        // Column-level denials: a qualified reference to a denied column.
        for col in crate::collect_plan_columns(plan) {
            let Some(rel) = &col.relation else { continue };
            for denial in &applicable {
                if let Some(denied_col) = &denial.column {
                    if denied_col == &col.name && table_matches(&denial.table, rel) {
                        add(format!("{}.{denied_col}", denial.table), &mut out);
                    }
                }
            }
        }
        out
    }

    fn rewrite(
        &self,
        plan: LogicalPlan,
        identity: &Identity,
    ) -> Result<datafusion::common::tree_node::Transformed<LogicalPlan>, DataFusionError> {
        use datafusion::common::tree_node::Transformed;

        if self.denials.is_empty() {
            return Ok(Transformed::no(plan));
        }
        let applicable: Vec<&AccessDenial> = self
            .denials
            .iter()
            .filter(|d| d.applies_to(identity))
            .collect();
        if applicable.is_empty() {
            return Ok(Transformed::no(plan));
        }

        // Walk the plan. Any match raises a planning error (the deny),
        // which propagates out as the query failure. The plan is never
        // mutated — deny is all-or-nothing.
        //
        // Both walks descend into subqueries embedded in expressions, which a
        // plain `LogicalPlan::apply` skips — otherwise a denied table/column
        // reached via `SELECT (SELECT … FROM denied)` (or `IN`/`EXISTS`)
        // escapes enforcement.

        // Table-level: deny a scan of a denied table, including scans nested
        // in expression subqueries.
        crate::try_for_each_table_scan(&plan, &mut |scan| {
            for denial in &applicable {
                if denial.column.is_none() && table_matches(&denial.table, &scan.table_name) {
                    crate::audit::record_decision("deny", identity, &denial.table.to_string());
                    return Err(table_denied(&denial.table));
                }
            }
            Ok(())
        })?;

        // Column-level: deny a qualified reference to a denied column,
        // descending into subqueries as well.
        deny_columns_in(&plan, &applicable, identity)?;

        Ok(Transformed::no(plan))
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

    fn ctx() -> SessionContext {
        let schema = Arc::new(Schema::new(vec![
            Field::new("id", DataType::Int32, false),
            Field::new("email", DataType::Utf8, false),
        ]));
        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(Int32Array::from(vec![1, 2])),
                Arc::new(StringArray::from(vec!["a@x.com", "b@x.com"])),
            ],
        )
        .unwrap();
        let ctx = SessionContext::new();
        ctx.register_table(
            "users",
            Arc::new(MemTable::try_new(schema, vec![vec![batch]]).unwrap()),
        )
        .unwrap();
        ctx
    }

    /// [`ctx`] plus a second, **ungoverned** `docs` table used as the outer
    /// `FROM` of an `IN` / `EXISTS` / `= ANY` subquery test, so any denial the
    /// test observes comes strictly from the governed `users` scan *inside* the
    /// subquery — isolating the expression-subquery traversal.
    fn ctx_with_users_and_docs() -> SessionContext {
        let ctx = ctx();
        let schema = Arc::new(Schema::new(vec![Field::new("id", DataType::Int32, false)]));
        let table = Arc::new(MemTable::try_new(schema, vec![vec![]]).unwrap());
        ctx.register_table("docs", table).unwrap();
        ctx
    }

    async fn plan_of(ctx: &SessionContext, sql: &str) -> LogicalPlan {
        ctx.state().create_logical_plan(sql).await.unwrap()
    }

    fn deny_table(table: &str) -> AccessDenyEnforcer {
        AccessDenyEnforcer::new([AccessDenial {
            table: TableReference::from(table),
            column: None,
            groups: vec![],
        }])
    }

    fn deny_column(table: &str, column: &str, groups: Vec<String>) -> AccessDenyEnforcer {
        AccessDenyEnforcer::new([AccessDenial {
            table: TableReference::from(table),
            column: Some(column.to_string()),
            groups,
        }])
    }

    #[tokio::test]
    async fn table_level_deny_rejects_scan() {
        let ctx = ctx();
        let plan = plan_of(&ctx, "SELECT id FROM users").await;
        let res = deny_table("users").rewrite(plan, &Identity::anonymous());
        assert!(res.is_err(), "table denial should reject the query");
        assert!(res.unwrap_err().to_string().contains("permission denied"));
    }

    #[tokio::test]
    async fn column_deny_rejects_when_selected() {
        let ctx = ctx();
        let plan = plan_of(&ctx, "SELECT email FROM users").await;
        let res = deny_column("users", "email", vec![]).rewrite(plan, &Identity::anonymous());
        assert!(res.is_err(), "selecting a denied column should be rejected");
    }

    #[tokio::test]
    async fn column_deny_rejects_select_star() {
        let ctx = ctx();
        let plan = plan_of(&ctx, "SELECT * FROM users").await;
        let res = deny_column("users", "email", vec![]).rewrite(plan, &Identity::anonymous());
        assert!(
            res.is_err(),
            "SELECT * over a denied column should be rejected"
        );
    }

    #[tokio::test]
    async fn column_deny_allows_when_not_referenced() {
        let ctx = ctx();
        let plan = plan_of(&ctx, "SELECT id FROM users").await;
        let res = deny_column("users", "email", vec![]).rewrite(plan, &Identity::anonymous());
        assert!(
            res.is_ok(),
            "a query not touching the denied column must run"
        );
    }

    #[tokio::test]
    async fn qualifying_the_table_does_not_dodge_deny() {
        let ctx = ctx();
        // bare-name denial must still catch a schema-qualified scan
        let plan = plan_of(&ctx, "SELECT id FROM users").await;
        let res = deny_table("users").rewrite(plan, &Identity::anonymous());
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn group_scoped_deny_only_fires_for_member() {
        let ctx = ctx();
        let enforcer = deny_column("users", "email", vec!["contractor".to_string()]);

        // identity NOT in the denied group → allowed
        let plan = plan_of(&ctx, "SELECT email FROM users").await;
        let analyst = Identity::user("a").with_groups(["analyst"]);
        assert!(enforcer.rewrite(plan, &analyst).is_ok());

        // identity IN the denied group → denied
        let plan = plan_of(&ctx, "SELECT email FROM users").await;
        let contractor = Identity::user("c").with_groups(["contractor"]);
        assert!(enforcer.rewrite(plan, &contractor).is_err());
    }

    #[tokio::test]
    async fn table_deny_is_caught_inside_a_subquery() {
        //: a denied table reached through an expression-position
        // scalar subquery must still be rejected — `LogicalPlan::apply` alone
        // would not descend into the subquery, letting the read slip past.
        let ctx = ctx();
        let plan = plan_of(&ctx, "SELECT (SELECT id FROM users LIMIT 1)").await;
        let res = deny_table("users").rewrite(plan, &Identity::anonymous());
        assert!(
            res.is_err(),
            "a denied table scanned inside a subquery must be rejected"
        );
        assert!(res.unwrap_err().to_string().contains("permission denied"));
    }

    // ---- table denial caught through each subquery-bearing Expr ----------
    //: a denied table reached only through an `IN` / `EXISTS` /
    // `= ANY` subquery must still be rejected. `LogicalPlan::apply` alone would
    // not descend into these expression subqueries, letting the read slip past;
    // `try_for_each_table_scan` descends into all four variants. The outer
    // `docs` scan is ungoverned, so every denial here originates in the
    // subquery.

    #[tokio::test]
    async fn table_deny_caught_inside_in_subquery() {
        let ctx = ctx_with_users_and_docs();
        let plan = plan_of(
            &ctx,
            "SELECT id FROM docs WHERE id IN (SELECT id FROM users)",
        )
        .await;
        let res = deny_table("users").rewrite(plan, &Identity::anonymous());
        assert!(res.is_err(), "denied table inside IN-subquery must reject");
        assert!(res.unwrap_err().to_string().contains("permission denied"));
    }

    #[tokio::test]
    async fn table_deny_caught_inside_exists_subquery() {
        let ctx = ctx_with_users_and_docs();
        let plan = plan_of(
            &ctx,
            "SELECT id FROM docs WHERE EXISTS (SELECT 1 FROM users)",
        )
        .await;
        let res = deny_table("users").rewrite(plan, &Identity::anonymous());
        assert!(
            res.is_err(),
            "denied table inside EXISTS-subquery must reject"
        );
        assert!(res.unwrap_err().to_string().contains("permission denied"));
    }

    #[tokio::test]
    async fn table_deny_caught_inside_any_subquery() {
        // `= ANY (subquery)` → the `SetComparison` Expr variant.
        let ctx = ctx_with_users_and_docs();
        let plan = plan_of(
            &ctx,
            "SELECT id FROM docs WHERE id = ANY (SELECT id FROM users)",
        )
        .await;
        let res = deny_table("users").rewrite(plan, &Identity::anonymous());
        assert!(
            res.is_err(),
            "denied table inside = ANY-subquery must reject"
        );
        assert!(res.unwrap_err().to_string().contains("permission denied"));
    }

    #[tokio::test]
    async fn column_deny_caught_inside_in_subquery() {
        // A denied column reached only through an `IN` subquery projection.
        let ctx = ctx_with_users_and_docs();
        let plan = plan_of(
            &ctx,
            "SELECT id FROM docs WHERE 'a@x.com' IN (SELECT email FROM users)",
        )
        .await;
        let res = deny_column("users", "email", vec![]).rewrite(plan, &Identity::anonymous());
        assert!(
            res.is_err(),
            "denied column referenced inside an IN-subquery must reject"
        );
        assert!(res.unwrap_err().to_string().contains("permission denied"));
    }

    // ---- CTE / alias name collision cannot dodge a table denial ----------
    // adapted from Trino TestRowFilter "SQL injection prevention"

    #[tokio::test]
    async fn cte_named_like_governed_table_does_not_dodge_deny() {
        // A CTE named exactly like the governed table must not shield the real
        // `users` scan inside the CTE body from the denial: the outer
        // `FROM users` resolves to the CTE, but the body still scans the
        // governed base table, which must be rejected.
        let ctx = ctx();
        let plan = plan_of(
            &ctx,
            "WITH users AS (SELECT id FROM users) SELECT id FROM users",
        )
        .await;
        let res = deny_table("users").rewrite(plan, &Identity::anonymous());
        assert!(
            res.is_err(),
            "a CTE aliasing the governed table must not dodge the deny"
        );
        assert!(res.unwrap_err().to_string().contains("permission denied"));
    }

    #[tokio::test]
    async fn empty_enforcer_is_noop() {
        let ctx = ctx();
        let plan = plan_of(&ctx, "SELECT * FROM users").await;
        assert!(AccessDenyEnforcer::empty()
            .rewrite(plan, &Identity::anonymous())
            .is_ok());
    }

    #[tokio::test]
    async fn column_deny_is_caught_inside_a_subquery() {
        //: a denied column referenced only inside an expression
        // subquery must still be rejected — the rewrite descends into the
        // subquery plan (via `deny_columns_in`).
        let ctx = ctx();
        let plan = plan_of(&ctx, "SELECT (SELECT email FROM users LIMIT 1)").await;
        let res = deny_column("users", "email", vec![]).rewrite(plan, &Identity::anonymous());
        assert!(
            res.is_err(),
            "a denied column referenced inside a subquery must be rejected"
        );
    }

    /// `explain` must agree with `rewrite`: a table-level denial reached only
    /// through a subquery scan, and a column-level denial referenced only inside
    /// a subquery, are now both *reported* by `explain`. Before the
    /// `collect_plan_columns` / `try_for_each_table_scan` subquery descent,
    /// `explain` walked the main tree only and under-reported a denial that
    /// `rewrite` actually enforces (the deferred #900 explain gap, ).
    #[tokio::test]
    async fn explain_reports_denial_nested_in_subquery() {
        let ctx = ctx();

        // Table-level denial reached only through a subquery scan.
        let plan = plan_of(&ctx, "SELECT (SELECT id FROM users LIMIT 1)").await;
        let table_decisions = deny_table("users").explain(&plan, &Identity::anonymous());
        assert!(
            table_decisions.iter().any(|d| d.resource == "users"),
            "explain must report a table denial nested in a subquery; got {table_decisions:?}"
        );

        // Column-level denial referenced only inside a subquery.
        let plan = plan_of(&ctx, "SELECT (SELECT email FROM users LIMIT 1)").await;
        let col_decisions =
            deny_column("users", "email", vec![]).explain(&plan, &Identity::anonymous());
        assert!(
            col_decisions.iter().any(|d| d.resource.contains("email")),
            "explain must report a column denial nested in a subquery; got {col_decisions:?}"
        );
    }
}

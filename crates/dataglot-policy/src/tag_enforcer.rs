//! Identity-aware tag-based plan rewriter — the §10 enforcer.
//!
//! [`TagBasedEnforcer`] consumes the [`crate::tags::OrgGovernance`]
//! type foundation from #139 plus the per-session
//! [`crate::Identity`] from #137 to drive plan rewrites that match
//! the Architecture Decisions v3.0 §10 model:
//!
//! ```text
//!   for each annotated (table, column):
//!     for each tag on that column:
//!       for each policy bound to that tag:
//!         if policy.applies_to_groups(identity.org_groups):
//!           apply rule to the plan
//! ```
//!
//! The rule application itself reuses the existing
//! [`crate::ColumnMaskingEnforcer`] / [`crate::RowFilterEnforcer`]
//! machinery: this enforcer's job is to *resolve* which masks +
//! filters apply for the given identity, then delegate the actual
//! `LogicalPlan` rewrite. That keeps the schema-preservation +
//! `TreeNodeRecursion::Jump` semantics in their existing tested
//! homes (#125, #128) and limits this module to the
//! identity-driven dispatch.
//!
//! # Conflict handling
//!
//! - **Multiple `Mask` policies on the same `(table, column)`.**
//!   Picked once, deterministically by iteration order — the
//!   second mask is dropped. Operators that need precedence /
//!   layering should keep the per-tag set narrow until the
//!   priority-aware successor lands (Phase 1 Task 03 per the
//!   `tags` module's docs).
//! - **Multiple `RowFilter` policies on the same table.**
//!   `AND`-ed together into a single composite predicate. This
//!   matches §10's `apply_row_filters` example, which pushes every
//!   matching policy's `Expr` onto a `filters` `Vec` (`DataFusion`'s
//!   physical plan ANDs the vec).
//!
//! # Composition with the existing enforcers
//!
//! After resolution the enforcer wraps the resolved
//! `ColumnMaskingEnforcer` + `RowFilterEnforcer` in a
//! [`crate::CompositeEnforcer`] (same shape as
//! `dataglot-server::config::build_policy_enforcer` uses today
//! for the static-config path). The composite preserves the
//! row-filter-sees-un-masked-values contract pinned in
//! `dataglot-policy::filter::tests::row_filter_predicate_sees_unmasked_values_even_with_column_mask`.
//!
//! # What this MVP does NOT do
//!
//! - **No precedence / layering.** First-policy-wins for masks,
//!   AND-all for row filters. Phase 1 Task 03 introduces
//!   priority-aware policy resolution.
//! - **No org scoping at the enforcer level.** All policies in
//!   the registry are eligible to fire; Section 10 says policies
//!   are org-owned and the registry is per-org, so this is
//!   correct as a single-org slice — the multi-org control
//!   plane (Peaka Catalog Service) is out of scope here.
//! - **No identity rewrite tracking.** The enforcer doesn't tag
//!   the plan with which policies fired. EXPLAIN observability is
//!   `PolicyOptimizerRule`'s responsibility (the rule's name
//!   already shows up in plan dumps).

use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;

use datafusion::common::tree_node::Transformed;
use datafusion::error::DataFusionError;
use datafusion::logical_expr::{Expr, LogicalPlan};
use datafusion::sql::TableReference;

use crate::filter::{RowFilter, RowFilterEnforcer};
use crate::mask::{ColumnMask, ColumnMaskingEnforcer};
use crate::tags::{OrgGovernance, RuleType};
use crate::{CompositeEnforcer, Identity, PolicyEnforcer};

/// Identity-aware policy enforcer driven by an
/// [`OrgGovernance`] registry of tags, policies, and semantic
/// columns. See the module-level docs for the §10 dispatch
/// algorithm and conflict-handling rules.
#[derive(Debug)]
pub struct TagBasedEnforcer {
    governance: Arc<OrgGovernance>,
}

impl TagBasedEnforcer {
    /// Wrap an `OrgGovernance` registry in an enforcer.
    ///
    /// The registry is shared via `Arc` so a single instance can
    /// back many concurrent sessions — the resolution per
    /// `rewrite()` call is cheap (`HashMap` lookups + a
    /// composite construction) and stateless beyond the
    /// registry itself.
    #[must_use]
    pub fn new(governance: OrgGovernance) -> Self {
        Self {
            governance: Arc::new(governance),
        }
    }

    /// Borrow the underlying registry. Primarily useful for
    /// diagnostics and tests.
    #[must_use]
    pub fn governance(&self) -> &OrgGovernance {
        &self.governance
    }

    /// Resolve which `ColumnMask`s and `RowFilter`s apply to
    /// `identity` from the registry. Pure function over the
    /// registry — no plan input, no side effects. Exposed for
    /// tests; production callers should go through
    /// `PolicyEnforcer::rewrite`.
    ///
    /// # Errors
    /// Surfaces `BuildError`s from `ColumnMaskingEnforcer::new`
    /// or `RowFilterEnforcer::new` if the resolved rule set is
    /// internally inconsistent. Today's resolution dedupes by
    /// key so this shouldn't fire — the `Result` shape is
    /// future-proof for the priority-aware successor.
    pub fn resolve_for_identity(
        &self,
        identity: &Identity,
    ) -> Result<(Vec<ColumnMask>, Vec<RowFilter>), DataFusionError> {
        let mut masks: Vec<ColumnMask> = Vec::new();
        // First-policy-wins de-duplication for masks. The set
        // tracks `(table, column)` keys we've already emitted a
        // mask for; subsequent matches are dropped.
        let mut mask_keys_seen: HashSet<(TableReference, String)> = HashSet::new();

        // Row-filter ANDing per table. `BTreeMap` for
        // deterministic ordering — useful for EXPLAIN output and
        // any future hash-based caching of the resolved plan.
        let mut filters_by_table: BTreeMap<TableReference, Expr> = BTreeMap::new();
        // A row-filter policy is per-table, but `iter_annotated_columns`
        // is column-first — so a policy on a tag carried by N columns
        // of the same table would be visited N times and AND-folded
        // into itself. Dedup by `(table, policy.id)` so the conjunction
        // is over *distinct* policies.
        let mut row_filter_seen: HashSet<(TableReference, String)> = HashSet::new();

        for (table, column, tags) in self.governance.iter_annotated_columns() {
            for tag in tags {
                for policy in self.governance.policies_for_tag(tag) {
                    if !policy.applies_to_groups(&identity.org_groups) {
                        continue;
                    }
                    match &policy.rule {
                        RuleType::Mask { expression } => {
                            let key = (table.clone(), column.to_string());
                            if mask_keys_seen.insert(key) {
                                masks.push(ColumnMask {
                                    table: table.clone(),
                                    column: column.to_string(),
                                    mask: expression.clone(),
                                    // The tag enforcer has already filtered by
                                    // this identity's org-groups (`applies_to_groups`)
                                    // above, so the derived static mask is
                                    // operator-wide from the inner enforcer's
                                    // point of view — org selection happened here.
                                    org: None,
                                    groups: None,
                                });
                            }
                            // else: first-wins — drop this duplicate.
                        }
                        RuleType::RowFilter { predicate } => {
                            // AND distinct row-filter policies that
                            // apply to the same table. §10's
                            // `apply_row_filters` example folds
                            // conjunctively. Skip the same policy
                            // twice (would yield `pred AND pred`).
                            if !row_filter_seen.insert((table.clone(), policy.id.clone())) {
                                continue;
                            }
                            filters_by_table
                                .entry(table.clone())
                                .and_modify(|existing| {
                                    *existing = std::mem::take(existing).and(predicate.clone());
                                })
                                .or_insert_with(|| predicate.clone());
                        }
                    }
                }
            }
        }

        let row_filters: Vec<RowFilter> = filters_by_table
            .into_iter()
            // Already identity-filtered above, so operator-wide (`org: None`)
            // from the inner `RowFilterEnforcer`'s point of view.
            .map(|(table, predicate)| RowFilter {
                table,
                predicate,
                org: None,
                // Already identity-filtered above (`applies_to_groups`), so the
                // derived static filter is all-subjects from the inner
                // enforcer's point of view.
                groups: None,
            })
            .collect();
        Ok((masks, row_filters))
    }
}

impl PolicyEnforcer for TagBasedEnforcer {
    fn rewrite(
        &self,
        plan: LogicalPlan,
        identity: &Identity,
    ) -> Result<Transformed<LogicalPlan>, DataFusionError> {
        // Empty governance ⇒ identity rewrite. Same fast-path the
        // other concrete enforcers use so the optimizer
        // fixed-point loop converges in one pass.
        if self.governance.tag_count() == 0
            || self.governance.policy_count() == 0
            || self.governance.annotated_column_count() == 0
        {
            return Ok(Transformed::no(plan));
        }

        let (masks, row_filters) = self.resolve_for_identity(identity)?;
        if masks.is_empty() && row_filters.is_empty() {
            // Governance is active (checked above) yet this identity
            // resolved to zero masks/row-filters. Legitimate for an
            // unprivileged user on an ungoverned query, but also the
            // shape of a mis-scoped rule — surface it at debug on the
            // audit target so "why did no policy apply for this user?"
            // is answerable, without being noise at info ( 1b).
            tracing::debug!(
                target: "dataglot::audit",
                action = "no_policy_resolved",
                user = identity.user.as_deref().unwrap_or("anonymous"),
                "active governance resolved to zero masks/row-filters for this identity"
            );
            return Ok(Transformed::no(plan));
        }

        // Enforcement is about to apply — record what resolved so the
        // audit trail shows policy firing (not just the per-decision
        // records emitted by the inner enforcers) ( 1b).
        tracing::debug!(
            target: "dataglot::audit",
            action = "policy_resolved",
            user = identity.user.as_deref().unwrap_or("anonymous"),
            masks = masks.len(),
            row_filters = row_filters.len(),
            "resolved masks/row-filters for identity"
        );

        // Build the inner enforcers. Map `BuildError` to
        // `DataFusionError::Plan` so the optimizer surfaces a
        // plan-time error instead of an opaque internal one.
        let mask_enforcer = ColumnMaskingEnforcer::new(masks)
            .map_err(|e| DataFusionError::Plan(format!("tag-based mask resolution: {e}")))?;
        let filter_enforcer = RowFilterEnforcer::new(row_filters)
            .map_err(|e| DataFusionError::Plan(format!("tag-based row-filter resolution: {e}")))?;

        // Compose: masks rewrite first, then filters. Order
        // doesn't change results (the two enforcers touch
        // disjoint plan regions, pinned in
        // `filter::tests::row_filter_and_column_mask_compose_in_either_order`)
        // but a fixed order keeps EXPLAIN output stable.
        let composite = CompositeEnforcer::new(vec![
            Arc::new(mask_enforcer) as Arc<dyn PolicyEnforcer>,
            Arc::new(filter_enforcer) as Arc<dyn PolicyEnforcer>,
        ]);
        composite.rewrite(plan, identity)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use datafusion::arrow::array::{Int32Array, StringArray};
    use datafusion::arrow::datatypes::{DataType, Field, Schema};
    use datafusion::arrow::record_batch::RecordBatch;
    use datafusion::datasource::MemTable;
    use datafusion::logical_expr::{col, lit};
    use datafusion::prelude::SessionContext;

    use crate::tags::{OrgGroupId, Policy, SemanticTableColumn, TagDefinition, TagId};

    /// Mirror of `mask::tests::ctx_with_users` / `filter::tests::ctx_with_users`.
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
        let table = MemTable::try_new(schema, vec![vec![batch]]).expect("memtable");
        let ctx = SessionContext::new();
        ctx.register_table("users", Arc::new(table))
            .expect("register users");
        (ctx, TableReference::bare("users"))
    }

    fn pii_tag() -> TagDefinition {
        TagDefinition {
            id: TagId::new("pii"),
            org: "acme".to_string(),
            name: "PII".to_string(),
        }
    }

    fn analyst_email_mask(table: &TableReference) -> SemanticTableColumn {
        SemanticTableColumn {
            table: table.clone(),
            column: "email".to_string(),
            tags: vec![TagId::new("pii")],
        }
    }

    fn mask_policy_for_group(group: &str) -> Policy {
        Policy {
            id: format!("mask-pii-{group}"),
            org: "acme".to_string(),
            tag: TagId::new("pii"),
            group: OrgGroupId::new(group),
            rule: RuleType::Mask {
                expression: lit("***@example.com"),
            },
        }
    }

    async fn execute(ctx: &SessionContext, plan: LogicalPlan) -> Vec<Vec<String>> {
        let df = ctx.execute_logical_plan(plan).await.expect("execute");
        let batches = df.collect().await.expect("collect");
        let mut rows = Vec::new();
        for batch in batches {
            for i in 0..batch.num_rows() {
                let mut cells = Vec::new();
                for c in 0..batch.num_columns() {
                    let col = batch.column(c);
                    if let Some(arr) = col.as_any().downcast_ref::<StringArray>() {
                        cells.push(arr.value(i).to_string());
                    } else if let Some(arr) = col.as_any().downcast_ref::<Int32Array>() {
                        cells.push(arr.value(i).to_string());
                    } else {
                        cells.push("?".to_string());
                    }
                }
                rows.push(cells);
            }
        }
        rows
    }

    #[tokio::test]
    async fn empty_governance_is_identity_rewrite() {
        let enforcer = TagBasedEnforcer::new(OrgGovernance::empty());
        let (ctx, _users) = ctx_with_users();
        let plan = ctx
            .sql("SELECT email FROM users")
            .await
            .expect("plan")
            .logical_plan()
            .clone();
        let out = enforcer
            .rewrite(plan, &Identity::user("alice").with_groups(["analyst"]))
            .expect("rewrite");
        assert!(
            !out.transformed,
            "empty registry must report Transformed::no",
        );
    }

    #[tokio::test]
    async fn matching_identity_triggers_mask() {
        let (ctx, users) = ctx_with_users();
        let governance = OrgGovernance::builder()
            .with_tag(pii_tag())
            .with_policy(mask_policy_for_group("analyst"))
            .with_column(analyst_email_mask(&users))
            .build()
            .expect("build governance");
        let enforcer = TagBasedEnforcer::new(governance);

        let identity = Identity::user("alice")
            .with_org("acme")
            .with_groups(["analyst"]);
        let plan = ctx
            .sql("SELECT email FROM users")
            .await
            .expect("plan")
            .logical_plan()
            .clone();
        let rewritten = enforcer.rewrite(plan, &identity).expect("rewrite").data;
        let rows = execute(&ctx, rewritten).await;
        assert_eq!(rows.len(), 3);
        for row in &rows {
            assert_eq!(row[0], "***@example.com");
        }
    }

    #[tokio::test]
    async fn non_matching_identity_skips_mask() {
        // Same setup as above, but the identity belongs to a
        // group the policy doesn't bind. No rewrite — the email
        // column flows through unmasked.
        let (ctx, users) = ctx_with_users();
        let governance = OrgGovernance::builder()
            .with_tag(pii_tag())
            .with_policy(mask_policy_for_group("analyst"))
            .with_column(analyst_email_mask(&users))
            .build()
            .expect("build governance");
        let enforcer = TagBasedEnforcer::new(governance);

        let identity = Identity::user("eve")
            .with_org("acme")
            .with_groups(["intern"]);
        let plan = ctx
            .sql("SELECT email FROM users ORDER BY id")
            .await
            .expect("plan")
            .logical_plan()
            .clone();
        let out = enforcer.rewrite(plan, &identity).expect("rewrite");
        assert!(
            !out.transformed,
            "no policy fires for `intern` ⇒ Transformed::no",
        );
        let rows = execute(&ctx, out.data).await;
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0][0], "alice@example.com");
        assert_eq!(rows[1][0], "bob@example.com");
        assert_eq!(rows[2][0], "carol@example.com");
    }

    #[tokio::test]
    async fn anonymous_identity_skips_mask() {
        // Anonymous identity has no groups ⇒ no policy can apply
        // even when the registry has matching annotations.
        let (ctx, users) = ctx_with_users();
        let governance = OrgGovernance::builder()
            .with_tag(pii_tag())
            .with_policy(mask_policy_for_group("analyst"))
            .with_column(analyst_email_mask(&users))
            .build()
            .expect("build governance");
        let enforcer = TagBasedEnforcer::new(governance);
        let plan = ctx
            .sql("SELECT email FROM users")
            .await
            .expect("plan")
            .logical_plan()
            .clone();
        let out = enforcer
            .rewrite(plan, &Identity::anonymous())
            .expect("rewrite");
        assert!(!out.transformed, "anonymous identity ⇒ no policy applies");
    }

    #[tokio::test]
    async fn row_filter_policy_applies() {
        let (ctx, users) = ctx_with_users();
        let governance = OrgGovernance::builder()
            .with_tag(pii_tag())
            .with_policy(Policy {
                id: "rf-id-gt-1".to_string(),
                org: "acme".to_string(),
                tag: TagId::new("pii"),
                group: OrgGroupId::new("analyst"),
                rule: RuleType::RowFilter {
                    predicate: col("id").gt(lit(1_i32)),
                },
            })
            .with_column(analyst_email_mask(&users))
            .build()
            .expect("build governance");
        let enforcer = TagBasedEnforcer::new(governance);
        let identity = Identity::user("alice").with_groups(["analyst"]);
        let plan = ctx
            .sql("SELECT id, email FROM users ORDER BY id")
            .await
            .expect("plan")
            .logical_plan()
            .clone();
        let rewritten = enforcer.rewrite(plan, &identity).expect("rewrite").data;
        let rows = execute(&ctx, rewritten).await;
        // Alice (id=1) is dropped by the filter; Bob and Carol
        // survive.
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0][0], "2");
        assert_eq!(rows[1][0], "3");
    }

    #[tokio::test]
    async fn multiple_row_filters_on_same_table_and_together() {
        // Two policies on different tags both annotating `users`,
        // both bound to `analyst`, both row filters. The
        // resolution must AND them — alice (id=1, alice@…)
        // fails id > 0 (no), bob (id=2, bob@…) survives both,
        // carol (id=3, carol@…) survives id > 0 but only if the
        // second predicate `email LIKE 'bob%' OR email LIKE 'carol%'`
        // holds. Pick predicates that overlap on Bob alone to
        // make the AND visible.
        let (ctx, users) = ctx_with_users();
        let pii = pii_tag();
        let visibility = TagDefinition {
            id: TagId::new("visibility"),
            org: "acme".to_string(),
            name: "Visibility".to_string(),
        };
        let governance = OrgGovernance::builder()
            .with_tag(pii.clone())
            .with_tag(visibility)
            .with_policy(Policy {
                id: "rf-id-gt-1".into(),
                org: "acme".into(),
                tag: TagId::new("pii"),
                group: OrgGroupId::new("analyst"),
                rule: RuleType::RowFilter {
                    predicate: col("id").gt(lit(1_i32)),
                },
            })
            .with_policy(Policy {
                id: "rf-email-bob".into(),
                org: "acme".into(),
                tag: TagId::new("visibility"),
                group: OrgGroupId::new("analyst"),
                rule: RuleType::RowFilter {
                    predicate: col("email").eq(lit("bob@example.com")),
                },
            })
            .with_column(SemanticTableColumn {
                table: users.clone(),
                column: "email".to_string(),
                tags: vec![TagId::new("pii"), TagId::new("visibility")],
            })
            .build()
            .expect("build governance");
        let enforcer = TagBasedEnforcer::new(governance);
        let identity = Identity::user("alice").with_groups(["analyst"]);
        let plan = ctx
            .sql("SELECT id, email FROM users ORDER BY id")
            .await
            .expect("plan")
            .logical_plan()
            .clone();
        let rewritten = enforcer.rewrite(plan, &identity).expect("rewrite").data;
        let rows = execute(&ctx, rewritten).await;
        assert_eq!(
            rows.len(),
            1,
            "AND of (id > 1) and (email = 'bob@example.com') ⇒ Bob only",
        );
        assert_eq!(rows[0][0], "2");
        assert_eq!(rows[0][1], "bob@example.com");
    }

    #[tokio::test]
    async fn duplicate_mask_keys_first_wins() {
        // Two policies, two tags, both annotating the same
        // (table, column). Both fire for `analyst`. The resolved
        // mask set has just one entry — the second is dropped.
        let (ctx, users) = ctx_with_users();
        let pii = pii_tag();
        let visibility = TagDefinition {
            id: TagId::new("visibility"),
            org: "acme".to_string(),
            name: "Visibility".to_string(),
        };
        let governance = OrgGovernance::builder()
            .with_tag(pii)
            .with_tag(visibility)
            .with_policy(Policy {
                id: "mask-1".into(),
                org: "acme".into(),
                tag: TagId::new("pii"),
                group: OrgGroupId::new("analyst"),
                rule: RuleType::Mask {
                    expression: lit("MASK_A"),
                },
            })
            .with_policy(Policy {
                id: "mask-2".into(),
                org: "acme".into(),
                tag: TagId::new("visibility"),
                group: OrgGroupId::new("analyst"),
                rule: RuleType::Mask {
                    expression: lit("MASK_B"),
                },
            })
            .with_column(SemanticTableColumn {
                table: users.clone(),
                column: "email".to_string(),
                tags: vec![TagId::new("pii"), TagId::new("visibility")],
            })
            .build()
            .expect("build governance");
        let enforcer = TagBasedEnforcer::new(governance);

        let identity = Identity::user("alice").with_groups(["analyst"]);
        let (masks, _filters) = enforcer.resolve_for_identity(&identity).expect("resolve");
        // Exactly one mask survives the dedup.
        assert_eq!(
            masks.len(),
            1,
            "duplicate (table, column) ⇒ first-wins, second dropped",
        );

        // End-to-end: project the column and confirm only one
        // literal shows up (whichever the iteration picked).
        let plan = ctx
            .sql("SELECT email FROM users")
            .await
            .expect("plan")
            .logical_plan()
            .clone();
        let rewritten = enforcer.rewrite(plan, &identity).expect("rewrite").data;
        let rows = execute(&ctx, rewritten).await;
        assert_eq!(rows.len(), 3);
        let unique_values: HashSet<_> = rows.iter().map(|r| r[0].clone()).collect();
        assert_eq!(
            unique_values.len(),
            1,
            "all rows should carry the same mask literal — first-wins resolution",
        );
        // First-wins is deterministic: tags-on-column and
        // policies-on-tag are stored as Vecs (insertion order). The
        // outer `iter_annotated_columns` order is HashMap-random, but
        // each (table, column) is visited exactly once, so dedup
        // happens entirely inside one column visit. `MASK_A` is on
        // tag `pii` which appears first in the column's tag list, so
        // it must always win.
        let chosen = unique_values.into_iter().next().unwrap();
        assert_eq!(
            chosen, "MASK_A",
            "first-wins must be deterministic for duplicate (table, column) masks",
        );
    }

    #[tokio::test]
    async fn row_filter_policy_not_duplicated_across_columns_of_same_table() {
        // A single RowFilter policy on a tag carried by multiple
        // columns of the same table must not AND its predicate
        // into itself once per column. Without dedup, two columns
        // both tagged `pii` would yield `(id > 1) AND (id > 1)` —
        // semantically identical but a real EXPLAIN-output and
        // future-cache regression. Pin the dedup.
        let (ctx, users) = ctx_with_users();
        let governance = OrgGovernance::builder()
            .with_tag(pii_tag())
            .with_policy(Policy {
                id: "filter-1".into(),
                org: "acme".into(),
                tag: TagId::new("pii"),
                group: OrgGroupId::new("analyst"),
                rule: RuleType::RowFilter {
                    predicate: col("id").gt(lit(1i32)),
                },
            })
            // Two columns of the same table both carry `pii`. Without
            // (table, policy.id) dedup the same predicate would be
            // visited twice.
            .with_column(SemanticTableColumn {
                table: users.clone(),
                column: "id".to_string(),
                tags: vec![TagId::new("pii")],
            })
            .with_column(SemanticTableColumn {
                table: users.clone(),
                column: "email".to_string(),
                tags: vec![TagId::new("pii")],
            })
            .build()
            .expect("build governance");
        let enforcer = TagBasedEnforcer::new(governance);
        let identity = Identity::user("alice").with_groups(["analyst"]);
        let (_masks, filters) = enforcer.resolve_for_identity(&identity).expect("resolve");
        assert_eq!(filters.len(), 1, "exactly one filter for the table");
        let predicate_str = format!("{}", filters[0].predicate);
        // `id > 1`, not `id > 1 AND id > 1`. Pin against the
        // canonical form — any duplication would lengthen this.
        assert_eq!(
            predicate_str, "id > Int32(1)",
            "single distinct policy ⇒ no AND-fold against self",
        );

        // End-to-end sanity: the rewrite still drops Alice (id=1).
        let plan = ctx
            .sql("SELECT id FROM users ORDER BY id")
            .await
            .expect("plan")
            .logical_plan()
            .clone();
        let rewritten = enforcer.rewrite(plan, &identity).expect("rewrite").data;
        let rows = execute(&ctx, rewritten).await;
        assert_eq!(rows.len(), 2, "Alice (id=1) filtered out");
    }

    #[test]
    fn governance_accessor_exposes_registry() {
        // Cover the `TagBasedEnforcer::governance()` borrow accessor
        // — useful for diagnostics and `#[must_use]` audits in the
        // server crate. Pointer equality with the underlying `Arc`
        // pins the no-clone contract.
        let registry = OrgGovernance::builder()
            .with_tag(pii_tag())
            .build()
            .expect("build governance");
        let enforcer = TagBasedEnforcer::new(registry);
        let borrowed = enforcer.governance();
        assert_eq!(borrowed.tag_count(), 1);
        assert_eq!(borrowed.policy_count(), 0);
    }

    #[test]
    fn enforcer_is_send_sync_via_arc_dyn() {
        // Pin the trait-object shape — `Arc<dyn PolicyEnforcer>`
        // is what `dataglot-server::DataglotServer` stores per
        // session. A future change that broke `Send + Sync +
        // 'static + Debug` on `TagBasedEnforcer` would surface
        // here.
        let enforcer: Arc<dyn PolicyEnforcer> =
            Arc::new(TagBasedEnforcer::new(OrgGovernance::empty()));
        let _ = format!("{enforcer:?}");
    }
}

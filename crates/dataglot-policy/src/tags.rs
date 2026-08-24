//! Tag / Policy / `SemanticTableColumn` — the governance type foundation.
//!
//! Plants the tag/policy data model for governance enforcement.
//! No enforcement logic yet — those land in a follow-up PR that
//! consumes [`OrgGovernance`] + an [`crate::Identity`] to resolve
//! row-filter and column-mask `Expr`s at planning time.
//!
//! # The model
//!
//! Three primitives:
//!
//! ```text
//!   TagDefinition          { id, org, name }
//!   Policy                 { id, org, tag, group, rule: Mask|RowFilter, expr }
//!   SemanticTableColumn    { table, column, tags: [TagId] }
//! ```
//!
//! Read it as: **tags** are per-organization labels (PII,
//! Confidential, HIPAA, …); a **policy** binds a tag to a rule
//! (mask or row-filter `Expr`) for a specific org-group;
//! **semantic-table columns** annotate physical columns with the
//! tags they carry.
//!
//! At query time, a future enforcer walks the plan, reads each
//! `TableScan`'s column tags from the `SemanticTableColumn`
//! registry, finds every `Policy` binding any of those tags to a
//! group the session [`crate::Identity`] belongs to, and rewrites
//! the plan accordingly. The tag becomes the guarantee — the
//! per-`(table, column)` rules of today's
//! [`crate::ColumnMaskingEnforcer`] / [`crate::RowFilterEnforcer`]
//! will be a thin shim over this model once that PR lands.
//!
//! # Why types-only first
//!
//! The §10 enforcer is a meaningful chunk of design and code; the
//! identity-aware plan rewrite needs the typed-tag model AND the
//! group-membership predicate AND the per-table-column lookup
//! path before any of it works end-to-end. Landing the type
//! surface here means follow-up PRs can be crisply about
//! enforcement logic against a stable shape, with the operator
//! config surface (org-level governance YAML / API) layered on
//! top.
//!
//! # What this MVP does NOT do
//!
//! - **No enforcer.** No `TagBasedEnforcer` consuming
//!   `OrgGovernance`. Today's
//!   [`crate::ColumnMaskingEnforcer`] / [`crate::RowFilterEnforcer`]
//!   keep working on per-`(table, column)` rules from in-process
//!   API and JSON config.
//! - **No persistence.** `OrgGovernance` is an in-memory
//!   registry. The Peaka Catalog Service that hosts org-level
//!   policy lives in `dataglot-server`'s config surface and the
//!   future control plane — out of scope here.
//! - **No identity-driven matching.** [`Policy::applies_to_groups`]
//!   is the predicate the enforcer will call; it lives here, but
//!   no caller consumes it yet.
//! - **No ingestion from external governance platforms.**
//!   §11 covers that surface.

use std::collections::HashMap;

use datafusion::logical_expr::Expr;
use datafusion::sql::TableReference;

/// Stable identifier for a [`TagDefinition`]. Newtype around
/// `String` so a tag id can never be confused with a column or
/// table name at the call site.
///
/// Construction is intentionally `pub` (no validation) — the
/// canonical generator lives in the future Peaka Catalog Service;
/// in-process tests construct tag ids directly.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TagId(pub String);

impl TagId {
    /// Construct from any string-like input.
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Borrow the inner identifier as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for TagId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Stable identifier for an org-group. Same shape as [`TagId`];
/// kept distinct to prevent accidental swaps at call sites that
/// take both (e.g., the [`Policy`] struct fields `tag` and
/// `group`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OrgGroupId(pub String);

impl OrgGroupId {
    /// Construct from any string-like input.
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Borrow the inner identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for OrgGroupId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Tag declaration. One per `(org, name)` pair — defined at the
/// organization level so policies bind uniformly when Project B
/// queries Project A's attached semantic catalog (§10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TagDefinition {
    /// Globally-unique tag id.
    pub id: TagId,
    /// Owning organization. Tags are org-scoped per §10.
    pub org: String,
    /// Human-readable name. Convention: `PII`, `Confidential`,
    /// `HIPAA`, etc.
    pub name: String,
}

/// What a [`Policy`] does to a matched plan node.
///
/// One variant per rule kind in §10. Both carry a `DataFusion`
/// `Expr`; the future enforcer threads it into the plan exactly
/// the way [`crate::ColumnMaskingEnforcer`] /
/// [`crate::RowFilterEnforcer`] do today (projection rewrite for
/// `Mask`, `Filter` wrap for `RowFilter`).
#[derive(Debug, Clone)]
pub enum RuleType {
    /// Replace the matched column's projection with the carried
    /// `Expr` — same shape as `crate::ColumnMask::mask`.
    Mask {
        /// `Expr` returned in place of the column at projection
        /// time. Typically a literal; any `Expr` of compatible
        /// type is accepted.
        expression: Expr,
    },
    /// Wrap every `TableScan` of a table whose semantic column
    /// carries the policy's tag in a `Filter` whose predicate is
    /// this `Expr`. Same shape as `crate::RowFilter::predicate`.
    RowFilter {
        /// Boolean-returning predicate.
        predicate: Expr,
    },
}

/// Rule that fires when a tagged column is touched by a session
/// belonging to a target group.
///
/// `tag` × `group` is the matching key the future enforcer will
/// dispatch on; the `org` discriminator scopes both. A session
/// whose [`crate::Identity::org_groups`] contains [`Policy::group`]
/// activates the rule.
#[derive(Debug, Clone)]
pub struct Policy {
    /// Globally-unique policy id.
    pub id: String,
    /// Owning organization. Policies are org-owned per §10.
    pub org: String,
    /// Tag this policy attaches to.
    pub tag: TagId,
    /// Group the policy applies to. Sessions whose identity
    /// includes this group activate the rule.
    pub group: OrgGroupId,
    /// What the rule does. See [`RuleType`].
    pub rule: RuleType,
}

impl Policy {
    /// Whether this policy fires for a session belonging to any
    /// of `groups`. The future enforcer uses this exactly:
    ///
    /// ```ignore
    /// for policy in governance.policies_for_tag(&tag) {
    ///     if policy.applies_to_groups(&identity.org_groups) {
    ///         filters.push(policy.expr_for_session(...));
    ///     }
    /// }
    /// ```
    ///
    /// Returns `true` if `groups` contains the policy's group as
    /// a string match.
    #[must_use]
    pub fn applies_to_groups(&self, groups: &[String]) -> bool {
        groups.iter().any(|g| g.as_str() == self.group.as_str())
    }
}

/// Annotation linking a physical `(table, column)` to one or
/// more tags. The future enforcer walks the plan, finds the
/// matching `SemanticTableColumn` per scanned column, then
/// resolves policies against each carried tag.
///
/// `table` matches by *strict* `TableReference` equality (same
/// convention as [`crate::ColumnMaskingEnforcer`] /
/// [`crate::RowFilterEnforcer`]). Loose matching ("any catalog")
/// is a follow-up affordance once the org-governance config
/// surface lands.
#[derive(Debug, Clone)]
pub struct SemanticTableColumn {
    /// Target table. Strict `TableReference` match.
    pub table: TableReference,
    /// Column name within `table`.
    pub column: String,
    /// Tags carried by this column. Empty list ⇒ no policy fires.
    pub tags: Vec<TagId>,
}

/// In-process registry of an organization's tag / policy /
/// semantic-column data. The future enforcer reads from one of
/// these to resolve `(table, column) → tags` and `tag → policies`.
///
/// Build via [`OrgGovernance::builder`]; lookups are O(1) on the
/// keys the enforcer will need.
#[derive(Debug, Default, Clone)]
pub struct OrgGovernance {
    tags: HashMap<TagId, TagDefinition>,
    policies_by_tag: HashMap<TagId, Vec<Policy>>,
    columns: HashMap<(TableReference, String), Vec<TagId>>,
}

impl OrgGovernance {
    /// Empty registry. Useful as a typed null.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Start building a registry with the fluent API.
    #[must_use]
    pub fn builder() -> OrgGovernanceBuilder {
        OrgGovernanceBuilder::default()
    }

    /// Look up a tag by id.
    #[must_use]
    pub fn tag(&self, id: &TagId) -> Option<&TagDefinition> {
        self.tags.get(id)
    }

    /// Iterate every registered tag.
    pub fn tags(&self) -> impl Iterator<Item = &TagDefinition> {
        self.tags.values()
    }

    /// Every policy attached to a tag, in insertion order. Empty
    /// slice when no policy targets the tag.
    #[must_use]
    pub fn policies_for_tag(&self, tag: &TagId) -> &[Policy] {
        self.policies_by_tag.get(tag).map_or(&[], Vec::as_slice)
    }

    /// Tags attached to a `(table, column)`. Empty slice when no
    /// `SemanticTableColumn` annotates this column.
    #[must_use]
    pub fn tags_for_column(&self, table: &TableReference, column: &str) -> &[TagId] {
        let key = (table.clone(), column.to_string());
        self.columns.get(&key).map_or(&[], Vec::as_slice)
    }

    /// Iterate every annotated column with its tags. The order is
    /// `HashMap` iteration order — non-deterministic between runs.
    /// Callers that need a deterministic walk should sort by
    /// `(TableReference, column)`. Used by
    /// [`crate::TagBasedEnforcer`] to resolve plan rewrites.
    pub fn iter_annotated_columns(
        &self,
    ) -> impl Iterator<Item = (&TableReference, &str, &[TagId])> {
        self.columns
            .iter()
            .map(|((table, column), tags)| (table, column.as_str(), tags.as_slice()))
    }

    /// Number of tag definitions registered.
    #[must_use]
    pub fn tag_count(&self) -> usize {
        self.tags.len()
    }

    /// Total policy count across all tags.
    #[must_use]
    pub fn policy_count(&self) -> usize {
        self.policies_by_tag.values().map(Vec::len).sum()
    }

    /// Number of `(table, column)` pairs that carry at least one
    /// tag.
    #[must_use]
    pub fn annotated_column_count(&self) -> usize {
        self.columns.len()
    }
}

/// Errors raised when assembling an [`OrgGovernance`].
#[derive(Debug, thiserror::Error)]
pub enum OrgGovernanceBuildError {
    /// Two `TagDefinition`s share an id. Rejected at build time
    /// rather than picking a winner — the canonical generator
    /// (Peaka Catalog Service) is responsible for global
    /// uniqueness; in-process construction must declare it.
    #[error("duplicate tag id `{id}`")]
    DuplicateTag {
        /// The repeated id.
        id: TagId,
    },
    /// A `Policy` references a tag id that no `TagDefinition`
    /// declared.
    #[error("policy `{policy}` references unknown tag `{tag}`")]
    UnknownTag {
        /// The dangling policy id.
        policy: String,
        /// The unknown tag.
        tag: TagId,
    },
    /// A `SemanticTableColumn` references a tag id that no
    /// `TagDefinition` declared.
    #[error("column `{table}`.`{column}` references unknown tag `{tag}`")]
    UnknownTagOnColumn {
        /// Table the dangling annotation lives on.
        table: TableReference,
        /// Column.
        column: String,
        /// The unknown tag.
        tag: TagId,
    },
}

/// Fluent builder for [`OrgGovernance`]. Use
/// [`OrgGovernance::builder`].
#[derive(Debug, Default)]
pub struct OrgGovernanceBuilder {
    tags: Vec<TagDefinition>,
    policies: Vec<Policy>,
    columns: Vec<SemanticTableColumn>,
}

impl OrgGovernanceBuilder {
    /// Add a tag definition. Multiple calls accumulate.
    #[must_use]
    pub fn with_tag(mut self, def: TagDefinition) -> Self {
        self.tags.push(def);
        self
    }

    /// Add a policy. Multiple policies on the same tag accumulate.
    #[must_use]
    pub fn with_policy(mut self, policy: Policy) -> Self {
        self.policies.push(policy);
        self
    }

    /// Annotate a `(table, column)` with one or more tags.
    #[must_use]
    pub fn with_column(mut self, column: SemanticTableColumn) -> Self {
        self.columns.push(column);
        self
    }

    /// Validate cross-references and build.
    ///
    /// # Errors
    /// See [`OrgGovernanceBuildError`].
    pub fn build(self) -> Result<OrgGovernance, OrgGovernanceBuildError> {
        let mut tags: HashMap<TagId, TagDefinition> = HashMap::with_capacity(self.tags.len());
        for def in self.tags {
            if tags.contains_key(&def.id) {
                return Err(OrgGovernanceBuildError::DuplicateTag { id: def.id });
            }
            tags.insert(def.id.clone(), def);
        }

        let mut policies_by_tag: HashMap<TagId, Vec<Policy>> = HashMap::new();
        for policy in self.policies {
            if !tags.contains_key(&policy.tag) {
                return Err(OrgGovernanceBuildError::UnknownTag {
                    policy: policy.id.clone(),
                    tag: policy.tag.clone(),
                });
            }
            policies_by_tag
                .entry(policy.tag.clone())
                .or_default()
                .push(policy);
        }

        let mut columns: HashMap<(TableReference, String), Vec<TagId>> =
            HashMap::with_capacity(self.columns.len());
        for SemanticTableColumn {
            table,
            column,
            tags: column_tags,
        } in self.columns
        {
            for tag in &column_tags {
                if !tags.contains_key(tag) {
                    return Err(OrgGovernanceBuildError::UnknownTagOnColumn {
                        table: table.clone(),
                        column: column.clone(),
                        tag: tag.clone(),
                    });
                }
            }
            columns
                .entry((table, column))
                .or_default()
                .extend(column_tags);
        }

        Ok(OrgGovernance {
            tags,
            policies_by_tag,
            columns,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use datafusion::logical_expr::lit;

    fn pii() -> TagDefinition {
        TagDefinition {
            id: TagId::new("pii"),
            org: "acme".to_string(),
            name: "PII".to_string(),
        }
    }

    fn analyst_pii_mask() -> Policy {
        Policy {
            id: "policy-001".to_string(),
            org: "acme".to_string(),
            tag: TagId::new("pii"),
            group: OrgGroupId::new("analyst"),
            rule: RuleType::Mask {
                expression: lit("***@example.com"),
            },
        }
    }

    #[test]
    fn empty_registry_is_zero_everywhere() {
        let g = OrgGovernance::empty();
        assert_eq!(g.tag_count(), 0);
        assert_eq!(g.policy_count(), 0);
        assert_eq!(g.annotated_column_count(), 0);
    }

    #[test]
    fn builder_minimal_round_trip() {
        let g = OrgGovernance::builder()
            .with_tag(pii())
            .with_policy(analyst_pii_mask())
            .with_column(SemanticTableColumn {
                table: TableReference::bare("users"),
                column: "email".to_string(),
                tags: vec![TagId::new("pii")],
            })
            .build()
            .expect("valid registry");
        assert_eq!(g.tag_count(), 1);
        assert_eq!(g.policy_count(), 1);
        assert_eq!(g.annotated_column_count(), 1);
        assert!(g.tag(&TagId::new("pii")).is_some());
        assert_eq!(g.policies_for_tag(&TagId::new("pii")).len(), 1);
        let users_email_tags = g.tags_for_column(&TableReference::bare("users"), "email");
        assert_eq!(users_email_tags, &[TagId::new("pii")]);
    }

    #[test]
    fn duplicate_tag_id_rejected_at_build() {
        let err = OrgGovernance::builder()
            .with_tag(pii())
            .with_tag(pii())
            .build()
            .unwrap_err();
        match err {
            OrgGovernanceBuildError::DuplicateTag { id } => {
                assert_eq!(id, TagId::new("pii"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn policy_referencing_unknown_tag_rejected() {
        // Policy targets a tag the registry never declared.
        let err = OrgGovernance::builder()
            .with_policy(analyst_pii_mask())
            .build()
            .unwrap_err();
        match err {
            OrgGovernanceBuildError::UnknownTag { policy, tag } => {
                assert_eq!(policy, "policy-001");
                assert_eq!(tag, TagId::new("pii"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn column_referencing_unknown_tag_rejected() {
        let err = OrgGovernance::builder()
            .with_column(SemanticTableColumn {
                table: TableReference::bare("users"),
                column: "email".to_string(),
                tags: vec![TagId::new("pii")],
            })
            .build()
            .unwrap_err();
        match err {
            OrgGovernanceBuildError::UnknownTagOnColumn { table, column, tag } => {
                assert_eq!(table, TableReference::bare("users"));
                assert_eq!(column, "email");
                assert_eq!(tag, TagId::new("pii"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn multiple_policies_on_same_tag_accumulate() {
        // A tag can carry several policies (e.g., one mask for
        // `analyst`, another for `support`). All survive the
        // build and surface in policies_for_tag.
        let support_mask = Policy {
            id: "policy-002".to_string(),
            org: "acme".to_string(),
            tag: TagId::new("pii"),
            group: OrgGroupId::new("support"),
            rule: RuleType::Mask {
                expression: lit("[redacted]"),
            },
        };
        let g = OrgGovernance::builder()
            .with_tag(pii())
            .with_policy(analyst_pii_mask())
            .with_policy(support_mask)
            .build()
            .expect("valid registry");
        assert_eq!(g.policies_for_tag(&TagId::new("pii")).len(), 2);
    }

    #[test]
    fn applies_to_groups_matches_only_member_groups() {
        // The dispatch predicate the future enforcer calls.
        let policy = analyst_pii_mask();
        assert!(policy.applies_to_groups(&["analyst".to_string()]));
        assert!(policy.applies_to_groups(&["analyst".to_string(), "other".to_string()]));
        assert!(!policy.applies_to_groups(&["support".to_string()]));
        assert!(!policy.applies_to_groups(&[]));
    }

    #[test]
    fn tags_for_unknown_column_is_empty() {
        let g = OrgGovernance::empty();
        let tags = g.tags_for_column(&TableReference::bare("nope"), "missing");
        assert!(tags.is_empty());
    }

    #[test]
    fn policies_for_unknown_tag_is_empty() {
        let g = OrgGovernance::empty();
        assert!(g.policies_for_tag(&TagId::new("nope")).is_empty());
    }

    #[test]
    fn iter_annotated_columns_yields_every_pair_with_tags() {
        // Direct coverage for the iterator the TagBasedEnforcer
        // walks. Insertion order is HashMap-random across runs, so
        // the assertion compares a sorted snapshot.
        let g = OrgGovernance::builder()
            .with_tag(pii())
            .with_column(SemanticTableColumn {
                table: TableReference::bare("users"),
                column: "email".to_string(),
                tags: vec![TagId::new("pii")],
            })
            .with_column(SemanticTableColumn {
                table: TableReference::bare("orders"),
                column: "billing_email".to_string(),
                tags: vec![TagId::new("pii")],
            })
            .build()
            .expect("valid registry");
        let mut yielded: Vec<(String, String, Vec<TagId>)> = g
            .iter_annotated_columns()
            .map(|(t, c, tags)| (t.to_string(), c.to_string(), tags.to_vec()))
            .collect();
        // `TagId` doesn't impl `Ord`; sort by the deterministic
        // (table, column) prefix only.
        yielded.sort_by(|a, b| (&a.0, &a.1).cmp(&(&b.0, &b.1)));
        assert_eq!(yielded.len(), 2);
        assert_eq!(yielded[0].0, "orders");
        assert_eq!(yielded[0].1, "billing_email");
        assert_eq!(yielded[0].2, vec![TagId::new("pii")]);
        assert_eq!(yielded[1].0, "users");
        assert_eq!(yielded[1].1, "email");
        assert_eq!(yielded[1].2, vec![TagId::new("pii")]);
    }

    #[test]
    fn rule_type_carries_expr_intact() {
        // Pin that the Expr threaded through Mask survives
        // construction. (Same shape as RowFilter; checking one
        // is enough.)
        let p = analyst_pii_mask();
        match p.rule {
            RuleType::Mask { expression } => {
                let dbg = format!("{expression:?}");
                assert!(dbg.contains("Literal") || dbg.contains("***"));
            }
            RuleType::RowFilter { .. } => panic!("expected Mask"),
        }
    }
}

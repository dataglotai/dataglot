//! Policy enforcement for Dataglot.
//!
//! Phase 1 prep. This crate plants the `PolicyEnforcer` trait and the
//! [`PolicyOptimizerRule`] adapter that turns a `PolicyEnforcer` into a
//! `DataFusion` `OptimizerRule`. Phase 1 fills in the actual row-level
//! filtering and column masking; today the scaffolding ships with
//! [`NoopPolicyEnforcer`] (identity rewrite) so the integration point
//! is exercised end-to-end without changing query results.
//!
//! Per hard rule 6 every policy lands as a planning-time
//! `LogicalPlan` rewrite — not a UDF, not runtime SQL rewriting. The
//! adapter satisfies that by registering as an optimizer rule.
//!
//! # Wiring (Phase 1)
//!
//! ```ignore
//! use std::sync::Arc;
//! use dataglot_policy::{NoopPolicyEnforcer, PolicyEnforcer, PolicyOptimizerRule};
//!
//! let enforcer: Arc<dyn PolicyEnforcer> = Arc::new(NoopPolicyEnforcer);
//! let rule = Arc::new(PolicyOptimizerRule::new(enforcer));
//!
//! // The server crate (Phase 1) will register the rule on its
//! // SessionStateBuilder alongside the federation rules:
//! //   .with_optimizer_rules({
//! //       let mut rules = datafusion_federation::default_optimizer_rules();
//! //       rules.push(rule.clone());
//! //       rules
//! //   })
//! ```
//!
//! `dataglot-core::SessionContextFactory` does not consume policy
//! today — it cannot, per the strict crate dependency direction (core
//! is below policy in the DAG). Phase 1 wires this up from
//! `dataglot-server`.
//!
//! # Concrete enforcers
//!
//! - [`mask::ColumnMaskingEnforcer`] (Phase 1 · Task 01): the first
//!   real `PolicyEnforcer`. Rewrites projections to substitute a
//!   registered masking `Expr` for matching column references.
//!   Predicates, joins, sorts, aggregates see the original column.
//! - [`filter::RowFilterEnforcer`] (Phase 1 · Task 05): row-level
//!   policy enforcement. Wraps every matching `TableScan` in a
//!   `Filter` node carrying a registered predicate `Expr`. The
//!   filter is mandatory — there's no caller-side path that
//!   bypasses it. Composes with `ColumnMaskingEnforcer` via
//!   sequenced rewrites: the row-filter predicate sees un-masked
//!   column values (option A in spec 01), so a row filter
//!   `email = 'alice@example.com'` finds Alice's row even when
//!   `email` is masked in the projection.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used))]
// bare .unwrap() panics without context on a live server; use .expect("why") or return an error. Tests exempt.
#![warn(missing_docs)]
#![cfg_attr(not(test), deny(clippy::print_stdout, clippy::print_stderr))]

use std::sync::Arc;

use datafusion::common::tree_node::Transformed;
use datafusion::config::ConfigOptions;
use datafusion::error::DataFusionError;
use datafusion::logical_expr::LogicalPlan;
use datafusion::optimizer::{AnalyzerRule, OptimizerConfig, OptimizerRule};
use datafusion::sql::TableReference;

/// Candidate keys for matching a query's table reference against registered
/// policy rules, ordered most- to least-qualified.
///
/// A rule registered with a *less*-qualified reference (e.g. bare `users`)
/// must match a *more*-qualified query reference (`pg.public.users`) — so a
/// user can't dodge a mask / row-filter just by qualifying the table name.
/// The fail-safe direction for a governance engine is to **over-enforce, not
/// under-enforce**; matching most-qualified first preserves more-specific
/// rule precedence. Closes  (qualified-name policy bypass).
///
/// - `Full(c,s,t)`   → `[c.s.t, s.t, t]`
/// - `Partial(s,t)`  → `[s.t, t]`
/// - `Bare(t)`       → `[t]`
#[must_use]
pub(crate) fn match_candidates(rel: &TableReference) -> Vec<TableReference> {
    let mut out = vec![rel.clone()];
    if let Some(schema) = rel.schema() {
        let table = rel.table();
        // Full (catalog present) also falls back to schema-qualified.
        if rel.catalog().is_some() {
            out.push(TableReference::partial(
                schema.to_string(),
                table.to_string(),
            ));
        }
        // Both Full and Partial fall back to the bare table name.
        out.push(TableReference::bare(table.to_string()));
    }
    out
}

/// Whether a policy rule tagged with `rule_org` applies to a session
/// carrying `identity` ( F4, per-org enforcement).
///
/// - `None` = **operator-wide**: applies to every session regardless of
///   org. This is what file-config masks / row filters map to, so
///   single-org behaviour is preserved byte-for-byte.
/// - `Some(x)` = **tenant-scoped**: applies only when the session's
///   `Identity.org` is exactly `x`. This is what runtime policy DDL
///   (`CREATE MASK` / `CREATE ROW FILTER`) maps to, tagged with the
///   creating session's org.
///
/// An anonymous / no-org identity (`identity.org == None`) therefore
/// sees only operator-wide (`None`) rules — a tenant-scoped rule never
/// leaks to a session that isn't in that tenant.
pub(crate) fn org_rule_applies(rule_org: Option<&str>, identity: &Identity) -> bool {
    rule_org.is_none() || rule_org == identity.org.as_deref()
}

/// Whether a policy rule scoped to `rule_groups` applies to a session whose
/// org-group memberships are `identity_groups` (, role/group-conditional
/// masks + row filters).
///
/// This is the mask/row-filter analogue of [`org_rule_applies`] on the *group*
/// dimension, and mirrors [`access_deny::AccessDenial::applies_to`] semantics
/// exactly (an intersection test) so all three policy kinds condition on
/// [`Identity::org_groups`] the same way:
///
/// - `None` = **all subjects**: the rule applies to every session in its org
///   scope, regardless of group. This is what a file-config mask / row filter
///   (which carries no group) maps to, so single-role behaviour is preserved
///   byte-for-byte (back-compat).
/// - `Some(gs)` = **group-scoped**: the rule applies only when at least one of
///   `gs` is one of the session's `identity_groups` (set intersection). A
///   session in none of the listed groups never sees the rule.
///
/// `identity_groups` is `&[String]` because [`Identity::org_groups`] is stored
/// as `Vec<String>`; the rule side carries the typed [`OrgGroupId`] newtype, so
/// the comparison is by name ([`OrgGroupId::as_str`]). An empty
/// `identity_groups` matches only `None` rules — a session with no group
/// membership sees all-subject rules but no group-scoped one.
pub(crate) fn subject_matches(
    rule_groups: Option<&[OrgGroupId]>,
    identity_groups: &[String],
) -> bool {
    match rule_groups {
        None => true,
        Some(groups) => groups
            .iter()
            .any(|g| identity_groups.iter().any(|ig| ig == g.as_str())),
    }
}

pub mod access_deny;
mod audit;
pub mod filter;
pub mod grant;
pub mod mask;
pub mod mask_kinds;
pub mod mutable;
pub mod store;
pub mod tag_enforcer;
pub mod tags;
pub mod whitelist;
pub use access_deny::{AccessDenial, AccessDenyEnforcer};
pub use filter::{BuildError as RowFilterBuildError, RowFilter, RowFilterEnforcer};
pub use grant::{AuthzMode, Grant, GrantEnforcer, GrantObject, GrantPrivilege};
pub use mask::{BuildError as ColumnMaskBuildError, ColumnMask, ColumnMaskingEnforcer};
pub use mask_kinds::MaskKind;
pub use mutable::MutableEnforcer;
pub use store::{ApplyError, InMemoryRuleStore, InitialRules, RuleChange, RuleStore};
pub use tag_enforcer::TagBasedEnforcer;
pub use tags::{
    OrgGovernance, OrgGovernanceBuildError, OrgGovernanceBuilder, OrgGroupId, Policy, RuleType,
    SemanticTableColumn, TagDefinition, TagId,
};
pub use whitelist::{ColumnWhitelist, ColumnWhitelistEnforcer};

/// Returns the policy module version for diagnostics.
#[must_use]
pub fn policy_version() -> &'static str {
    "0.1.0"
}

/// Identity context passed to every `PolicyEnforcer::rewrite` call.
///
/// Phase 1 plants this type as the per-session identity surface so
/// follow-up enforcers can branch on `user` / `org` / role without
/// another trait-signature break. Today's MVP enforcers
/// (`ColumnMaskingEnforcer`, `RowFilterEnforcer`) ignore the
/// argument — their rules are static. The identity-aware
/// successors land when the typed tag system arrives — see
/// [`crate::tags`] for the type foundation.
///
/// Construction:
/// * [`Identity::anonymous`] — no user, no org, no groups. The
///   default for any pgwire connection that hasn't
///   authenticated.
/// * [`Identity::user`] / [`Identity::with_org`] /
///   [`Identity::with_groups`] — populate fields explicitly.
///   Used by tests today; will be used by the pgwire
///   startup-params extractor when that PR lands.
///
/// `Identity` is intentionally a leaf data struct (no
/// credentials, no tokens, no opaque handles). Per hard
/// rule 12 credentials never appear in logs / error messages /
/// plan representations; the identity surfaces by name only.
/// Authentication of the claimed identity is the pgwire layer's
/// concern, not this struct's.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Identity {
    /// Authenticated user name. `None` means anonymous /
    /// pre-auth — the policy default for unidentified sessions.
    pub user: Option<String>,
    /// Owning organization / tenant. `None` means single-tenant
    /// or unknown.
    pub org: Option<String>,
    /// Org-group memberships (e.g. `["analyst", "on-call"]`).
    /// Per Architecture Decisions §10 the future tag-system
    /// enforcer dispatches policies on group match —
    /// [`tags::Policy::applies_to_groups`] reads exactly this
    /// list. Empty list ⇒ session belongs to no groups.
    pub org_groups: Vec<String>,
    /// RBAC role memberships: the roles this session
    /// holds, resolved from the control-plane store's
    /// `role → user` memberships at connection time. **Distinct
    /// from [`org_groups`](Self::org_groups)** — `org_groups` drives
    /// tag-based mask/row-filter policies (Architecture Decisions
    /// §10), while `roles` drives GRANT/REVOKE privilege resolution
    /// ([`grant::GrantEnforcer`]). A privilege grant applies to the
    /// session when its grantee name equals [`user`](Self::user) **or**
    /// is one of these role names. Empty ⇒ the session holds no roles.
    pub roles: Vec<String>,
    /// Whether this session authenticated as a superuser (
    /// F5b). A superuser bypasses GRANT/REVOKE enforcement entirely
    /// ([`grant::GrantEnforcer`] allows every table). It does **not**
    /// bypass column masks or row filters — those are governance
    /// guarantees, not access privileges. `false` for every anonymous
    /// / non-superuser session (the default).
    pub is_superuser: bool,
}

impl Identity {
    /// The default identity for any session that hasn't supplied
    /// a user, org, or groups.
    #[must_use]
    pub fn anonymous() -> Self {
        Self::default()
    }

    /// Build an identity from a user name only.
    #[must_use]
    pub fn user(name: impl Into<String>) -> Self {
        Self {
            user: Some(name.into()),
            org: None,
            org_groups: Vec::new(),
            roles: Vec::new(),
            is_superuser: false,
        }
    }

    /// Add an org qualifier to an existing identity (typically
    /// chained: `Identity::user("alice").with_org("acme")`).
    #[must_use]
    pub fn with_org(mut self, org: impl Into<String>) -> Self {
        self.org = Some(org.into());
        self
    }

    /// Set the org-group memberships. Replaces any existing
    /// groups. Typical chain:
    ///
    /// ```ignore
    /// let id = Identity::user("alice")
    ///     .with_org("acme")
    ///     .with_groups(["analyst", "on-call"]);
    /// ```
    #[must_use]
    pub fn with_groups<I, S>(mut self, groups: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.org_groups = groups.into_iter().map(Into::into).collect();
        self
    }

    /// Set the RBAC role memberships. Replaces any
    /// existing roles. These are the role names a privilege grant's
    /// grantee is matched against (alongside [`user`](Self::user)) by
    /// [`grant::GrantEnforcer`]; they are **not** folded into
    /// [`org_groups`](Self::org_groups). Typical chain:
    ///
    /// ```ignore
    /// let id = Identity::user("alice")
    ///     .with_org("acme")
    ///     .with_roles(["analyst"]);
    /// ```
    #[must_use]
    pub fn with_roles<I, S>(mut self, roles: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.roles = roles.into_iter().map(Into::into).collect();
        self
    }

    /// Mark the identity as a superuser — bypasses
    /// GRANT/REVOKE enforcement. Chainable:
    /// `Identity::user("root").as_superuser()`.
    #[must_use]
    pub fn as_superuser(mut self) -> Self {
        self.is_superuser = true;
        self
    }

    /// Whether the identity carries no user, no org, and no
    /// groups. The default for any pgwire connection that
    /// hasn't authenticated.
    ///
    /// Note: roles / superuser are deliberately **not** part of this
    /// predicate — an anonymous session never carries either, so the
    /// check is unchanged, and the fields default empty/`false`.
    #[must_use]
    pub fn is_anonymous(&self) -> bool {
        self.user.is_none() && self.org.is_none() && self.org_groups.is_empty()
    }
}

/// The kind of policy decision surfaced by [`PolicyEnforcer::explain`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyAction {
    /// A column value is masked.
    Mask,
    /// A table's rows are filtered.
    RowFilter,
    /// Access to a resource is denied (the query would be rejected).
    Deny,
}

impl PolicyAction {
    /// Lowercase wire/display label (`"mask"` / `"row_filter"` / `"deny"`).
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            PolicyAction::Mask => "mask",
            PolicyAction::RowFilter => "row_filter",
            PolicyAction::Deny => "deny",
        }
    }
}

/// One policy decision that applies to a query under a given identity —
/// the unit of "why was this column masked?" explainability. Produced by
/// [`PolicyEnforcer::explain`] without mutating or executing the plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyDecision {
    /// What the policy does.
    pub action: PolicyAction,
    /// Affected resource — `"table"` or `"table.column"`.
    pub resource: String,
    /// Human-readable detail: the mask expression, filter predicate, or
    /// denial reason.
    pub detail: String,
}

impl PolicyDecision {
    /// Convenience constructor.
    #[must_use]
    pub fn new(
        action: PolicyAction,
        resource: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            action,
            resource: resource.into(),
            detail: detail.into(),
        }
    }
}

/// Trait every policy backend implements.
///
/// A `PolicyEnforcer` rewrites a `DataFusion` `LogicalPlan` to inject
/// row-level filters and column masks before execution, and (via
/// [`PolicyEnforcer::explain`]) reports the decisions that apply without
/// mutating the plan. The default implementation is identity (no policy).
///
/// `identity` is the per-session identity context (see [`Identity`]).
/// Per rule 10 the trait is `Send + Sync + 'static` so a single
/// `Arc<dyn PolicyEnforcer>` is shared across pgwire sessions.
pub trait PolicyEnforcer: Send + Sync + std::fmt::Debug + 'static {
    /// Rewrite `plan` to apply this policy under `identity`.
    ///
    /// Default implementation returns the plan unchanged. The trait's
    /// `Transformed` return value lets the optimizer detect whether
    /// the plan was actually modified — essential for the optimizer's
    /// fixed-point loop.
    ///
    /// # Errors
    /// Returns a `DataFusionError` if rewriting fails. Implementations
    /// should map their internal errors via
    /// `DataFusionError::External` so error chains stay typed.
    fn rewrite(
        &self,
        plan: LogicalPlan,
        identity: &Identity,
    ) -> Result<Transformed<LogicalPlan>, DataFusionError> {
        let _ = identity;
        Ok(Transformed::no(plan))
    }

    /// Report — without mutating or executing — the policy decisions that
    /// would apply to `plan` under `identity`. Powers policy
    /// explainability ("why was this column masked?").
    ///
    /// Default returns no decisions; enforcers override.
    fn explain(&self, plan: &LogicalPlan, identity: &Identity) -> Vec<PolicyDecision> {
        let _ = (plan, identity);
        Vec::new()
    }
}

/// The `Arc<LogicalPlan>` embedded directly in a subquery-bearing `Expr`, for
/// the **four** variants that carry one — `ScalarSubquery`, `InSubquery`,
/// `SetComparison` (`= ANY (…)` / `> ALL (…)`), and `Exists`. Every other
/// `Expr` returns `None`.
///
/// This is the *read-only* companion to [`map_subquery_plans`] (which
/// *transforms* the embedded plan): both centralize the single fact that these
/// four variants are the ones `LogicalPlan::apply` / `Expr::apply` treat as
/// opaque, so a `TableScan` / column reference nested inside is otherwise never
/// reached. Keep both exhaustive over the four — a new subquery-bearing variant
/// added upstream that is missed here is a **silent governance leak** (an
/// unmasked/unfiltered/undenied read through the subquery).
pub(crate) fn embedded_subquery(
    expr: &datafusion::logical_expr::Expr,
) -> Option<&Arc<LogicalPlan>> {
    use datafusion::logical_expr::expr::{Exists, InSubquery, SetComparison};
    use datafusion::logical_expr::Expr;
    match expr {
        Expr::ScalarSubquery(sq)
        | Expr::InSubquery(InSubquery { subquery: sq, .. })
        | Expr::SetComparison(SetComparison { subquery: sq, .. })
        | Expr::Exists(Exists { subquery: sq, .. }) => Some(&sq.subquery),
        _ => None,
    }
}

/// Rewrite the `LogicalPlan` embedded in a subquery-bearing `Expr` by applying
/// `f` to its `Arc<LogicalPlan>`, rebuilding the enclosing `Subquery` and
/// `Expr` around the result. `f`'s `Transformed` flag is threaded through, so
/// the caller learns whether anything actually changed; a non-subquery `Expr`
/// passes through as `Transformed::no`.
///
/// The `Subquery`'s `outer_ref_columns` (and `spans`) are preserved verbatim —
/// they name the *parent's* columns a correlated subquery references and must
/// never be governed as if they were the subquery's own scans; only
/// `subquery.subquery` (the embedded plan) is handed to `f`.
///
/// Exhaustive over the same four variants as [`embedded_subquery`]; see its
/// note on why a missed variant is a silent leak. This is the transform used by
/// `mask` / `filter` `rewrite` to descend governance into expression subqueries
pub(crate) fn map_subquery_plans<F>(
    expr: datafusion::logical_expr::Expr,
    f: &mut F,
) -> Result<Transformed<datafusion::logical_expr::Expr>, DataFusionError>
where
    F: FnMut(Arc<LogicalPlan>) -> Result<Transformed<Arc<LogicalPlan>>, DataFusionError>,
{
    use datafusion::logical_expr::expr::{Exists, InSubquery, SetComparison};
    use datafusion::logical_expr::{Expr, Subquery};

    fn rebuild<F>(sq: Subquery, f: &mut F) -> Result<Transformed<Subquery>, DataFusionError>
    where
        F: FnMut(Arc<LogicalPlan>) -> Result<Transformed<Arc<LogicalPlan>>, DataFusionError>,
    {
        let Subquery {
            subquery,
            outer_ref_columns,
            spans,
        } = sq;
        Ok(f(subquery)?.update_data(|subquery| Subquery {
            subquery,
            outer_ref_columns,
            spans,
        }))
    }

    match expr {
        Expr::ScalarSubquery(sq) => Ok(rebuild(sq, f)?.update_data(Expr::ScalarSubquery)),
        Expr::InSubquery(InSubquery {
            expr,
            subquery,
            negated,
        }) => Ok(rebuild(subquery, f)?
            .update_data(|subquery| Expr::InSubquery(InSubquery::new(expr, subquery, negated)))),
        Expr::SetComparison(SetComparison {
            expr,
            subquery,
            op,
            quantifier,
        }) => Ok(rebuild(subquery, f)?.update_data(|subquery| {
            Expr::SetComparison(SetComparison::new(expr, subquery, op, quantifier))
        })),
        Expr::Exists(Exists { subquery, negated }) => Ok(rebuild(subquery, f)?
            .update_data(|subquery| Expr::Exists(Exists::new(subquery, negated)))),
        other => Ok(Transformed::no(other)),
    }
}

/// Collect every qualified column reference in `plan` (for explain paths),
/// **descending into subqueries embedded in expressions** (the four variants
/// [`embedded_subquery`] enumerates) to any depth — which
/// [`LogicalPlan::apply`] / [`datafusion::common::tree_node::TreeNode::apply`]
/// would otherwise skip. This keeps `explain` consistent with `rewrite`: now
/// that `mask` (and, via `try_for_each_table_scan`, `access_deny`) govern
/// columns nested in a subquery, `explain` must *report* them too, or it
/// under-reports a mask/denial that `rewrite` actually applies.
///
/// Duplicates are kept; callers dedup as needed. Correlated-subquery outer
/// references are `Expr::OuterReferenceColumn` (not `Expr::Column`) and belong
/// to the parent, so they are never collected here — matching the rewrite,
/// which governs the subquery's own scans, not the outer refs.
pub(crate) fn collect_plan_columns(plan: &LogicalPlan) -> Vec<datafusion::common::Column> {
    let mut cols = Vec::new();
    collect_plan_columns_into(plan, &mut cols);
    cols
}

/// Recursive worker for [`collect_plan_columns`]. Nested subquery plans are
/// gathered during the walk and recursed into afterwards (rather than inside
/// the borrowing closure) so the `&mut cols` borrow stays single-threaded.
fn collect_plan_columns_into(plan: &LogicalPlan, cols: &mut Vec<datafusion::common::Column>) {
    use datafusion::common::tree_node::{TreeNode, TreeNodeRecursion};
    let mut nested: Vec<Arc<LogicalPlan>> = Vec::new();
    if let Err(err) = plan.apply(|node| {
        for expr in node.expressions() {
            if let Err(err) = expr.apply(|e| {
                if let datafusion::logical_expr::Expr::Column(c) = e {
                    cols.push(c.clone());
                } else if let Some(sub) = embedded_subquery(e) {
                    // `Expr::apply` treats these as opaque, so queue the nested
                    // plan for a separate recursive pass.
                    nested.push(Arc::clone(sub));
                }
                Ok(TreeNodeRecursion::Continue)
            }) {
                // A per-expression traversal failure drops columns from
                // the set that feeds the explain paths, silently
                // under-reporting which columns a policy would mask/deny.
                tracing::warn!(error = %err, "policy: expression traversal failed during column collection; explain may under-report enforcement");
            }
        }
        Ok(TreeNodeRecursion::Continue)
    }) {
        tracing::warn!(error = %err, "policy: plan traversal failed during column collection; explain may under-report enforcement");
    }
    for sub in nested {
        collect_plan_columns_into(&sub, cols);
    }
}

/// Visit every [`TableScan`](datafusion::logical_expr::TableScan) in `plan`,
/// **including** those nested in subqueries embedded in expressions (the four
/// subquery-bearing variants [`embedded_subquery`] enumerates — `ScalarSubquery`
/// / `InSubquery` / `SetComparison` / `Exists`, each holding a
/// `Subquery { subquery: Arc<LogicalPlan> }`), to any depth.
///
/// [`LogicalPlan::apply`] walks the main plan tree (node *inputs*) but does
/// **not** descend into an expression-position subquery — and
/// [`Expr::apply`](datafusion::common::tree_node::TreeNode::apply) treats
/// `ScalarSubquery`/`Exists` as leaves and only follows `InSubquery`'s /
/// `SetComparison`'s compare expression, never the subquery plan. So a
/// `TableScan` inside such a subquery is otherwise never visited. For the
/// *check-only* enforcers ([`grant::GrantEnforcer`],
/// [`access_deny::AccessDenyEnforcer`]) that is a security hole: an ungranted /
/// denied table reached through `SELECT (SELECT … FROM secret)`,
/// `WHERE x IN (SELECT … FROM secret)`, `WHERE x = ANY (SELECT … FROM secret)`,
/// or `WHERE EXISTS (SELECT … FROM secret)` would escape the walk.
///
/// `f` is called once per `TableScan`. `f` returning `Err` stops the walk and
/// propagates the error out — the enforcers use this to raise the first
/// permission denial. Nesting (a subquery inside a subquery) is handled by
/// recursion.
///
/// # Errors
/// Propagates the first `Err` returned by `f` (a permission denial), and any
/// structural traversal error surfaced by the underlying `TreeNode` walk.
pub(crate) fn try_for_each_table_scan<F>(
    plan: &LogicalPlan,
    f: &mut F,
) -> Result<(), DataFusionError>
where
    F: FnMut(&datafusion::logical_expr::TableScan) -> Result<(), DataFusionError>,
{
    use datafusion::common::tree_node::{TreeNode, TreeNodeRecursion};

    plan.apply(|node| {
        if let LogicalPlan::TableScan(scan) = node {
            // A denial from `f` becomes the closure's `Err`, which
            // `TreeNode::apply` propagates out — stopping the whole walk.
            f(scan)?;
        }
        // Descend into subqueries embedded in this node's expressions, which
        // `LogicalPlan::apply` skips. `Expr::apply` visits the subquery-
        // carrying node itself, so we can pull its `Arc<LogicalPlan>` out and
        // recurse (handling arbitrary nesting).
        for expr in node.expressions() {
            expr.apply(|e| {
                if let Some(subplan) = embedded_subquery(e) {
                    try_for_each_table_scan(subplan, f)?;
                }
                Ok(TreeNodeRecursion::Continue)
            })?;
        }
        Ok(TreeNodeRecursion::Continue)
    })
    .map(|_| ())
}

/// Default no-op policy enforcer used when no policy is configured.
///
/// Cheap to construct, cheap to call — `rewrite` falls through to the
/// trait's identity default.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopPolicyEnforcer;

impl PolicyEnforcer for NoopPolicyEnforcer {}

/// Sequence multiple `PolicyEnforcer`s into one.
///
/// `CompositeEnforcer::rewrite(plan)` calls each inner enforcer's
/// `rewrite` in declared order, threading the rewritten plan from
/// one to the next, and reports `Transformed::yes` if any inner
/// enforcer reported a change. The order is the construction
/// order — operators get a stable rewrite pipeline.
///
/// Designed for the Phase 1 `mask + row_filter` pair: a server
/// configured with both a `ColumnMaskingEnforcer` and a
/// `RowFilterEnforcer` wraps them in a single
/// `Arc<CompositeEnforcer>` and registers it on every session
/// (see `dataglot-server::config::build_policy_enforcer`).
///
/// Order independence is *not* guaranteed by this composer; it is
/// guaranteed by the inner enforcers' rewriting disjoint plan
/// regions (`Filter`/`TableScan` for row filters; `Projection.expr`
/// for column masks). Pinned in
/// `dataglot-policy::filter::tests::row_filter_and_column_mask_compose_in_either_order`.
#[derive(Debug)]
pub struct CompositeEnforcer {
    inner: Vec<Arc<dyn PolicyEnforcer>>,
}

impl CompositeEnforcer {
    /// Build a composite from a sequence of enforcers. The order of
    /// `inner` is the rewrite order at runtime; an empty `inner` is
    /// accepted and is observably identical to `NoopPolicyEnforcer`.
    #[must_use]
    pub fn new(inner: Vec<Arc<dyn PolicyEnforcer>>) -> Self {
        Self { inner }
    }

    /// Number of inner enforcers. Surfaced for diagnostics.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Whether the composite holds zero inner enforcers.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl PolicyEnforcer for CompositeEnforcer {
    fn rewrite(
        &self,
        plan: datafusion::logical_expr::LogicalPlan,
        identity: &Identity,
    ) -> Result<Transformed<datafusion::logical_expr::LogicalPlan>, DataFusionError> {
        use datafusion::common::tree_node::TreeNodeRecursion;

        let mut current = plan;
        let mut any_changed = false;
        // Default `tnr` for an empty composite or all-Continue chain.
        // When an inner enforcer signals a non-default `tnr`, the
        // last inner's signal wins (see #129's CodeRabbit follow-up
        // commit for the rationale).
        let mut latest_tnr = TreeNodeRecursion::Continue;
        for e in &self.inner {
            let Transformed {
                data,
                transformed,
                tnr,
            } = e.rewrite(current, identity)?;
            current = data;
            if transformed {
                any_changed = true;
            }
            latest_tnr = tnr;
        }
        Ok(Transformed::new(current, any_changed, latest_tnr))
    }

    fn explain(&self, plan: &LogicalPlan, identity: &Identity) -> Vec<PolicyDecision> {
        self.inner
            .iter()
            .flat_map(|e| e.explain(plan, identity))
            .collect()
    }
}

// Per-task session identity, set by the pgwire startup-handler (via
// the server crate) and read back here at optimizer-rewrite time.
//
// Why a task-local: the pgwire `SessionContext` is built before the
// startup phase reads the `StartupMessage`, so the
// `PolicyOptimizerRule` registered on the SessionStateBuilder can't
// know the username at construction time. Per-task storage lets the
// caller (`dataglot-server`) scope an identity to a connection's task
// — set initial via [`with_session_identity`], swap once the username
// arrives via [`set_session_identity`]. Same task = same identity for
// every query on the connection; different tasks (different
// connections, or unit tests) get isolated identities.
//
// Why not a thread-local: tokio task-locals correctly migrate with
// futures across threads in the multi-threaded runtime, while a
// thread-local would attach to whatever thread happens to poll the
// future. Same-task semantics are the property we want.
//
// Caveat — tokio task-locals don't propagate across `tokio::spawn`.
// `PolicyOptimizerRule::rewrite` runs during query planning which is
// sequential within the connection's task, so this is fine in
// practice. If a future caller wants to plumb identity through a
// spawned helper, they have to clone-and-rescope explicitly.
tokio::task_local! {
    static CURRENT_IDENTITY: std::cell::RefCell<Identity>;
}

/// Run `future` with `initial` bound as the current task's session
/// identity. While the future runs (and any non-spawned await chain
/// it produces), [`PolicyOptimizerRule::rewrite`] uses this identity
/// instead of the constructor-passed default.
///
/// The pgwire startup handler captures the username from the
/// `StartupMessage` and updates the bound identity via
/// [`set_session_identity`]. Wrapping a connection's lifetime in a
/// scope means every query on that connection sees the right
/// identity, even though the `SessionContext` (and its
/// `PolicyOptimizerRule`) was built earlier with no name to bind.
pub async fn with_session_identity<F: std::future::Future>(
    initial: Identity,
    future: F,
) -> F::Output {
    CURRENT_IDENTITY
        .scope(std::cell::RefCell::new(initial), future)
        .await
}

/// Replace the current task's session identity. Intended for the
/// pgwire startup-handler callback path: extract the username,
/// resolve groups, swap the identity in. Subsequent
/// [`PolicyOptimizerRule::rewrite`] calls in the same task observe
/// the new value.
///
/// # Panics
/// Panics if called outside a [`with_session_identity`] scope.
/// Production callers should always wrap connection futures in the
/// scope; for tests or one-off code paths that aren't sure, use
/// [`try_set_session_identity`].
pub fn set_session_identity(identity: Identity) {
    CURRENT_IDENTITY.with(|cell| *cell.borrow_mut() = identity);
}

/// Best-effort variant of [`set_session_identity`] — no-op outside
/// a [`with_session_identity`] scope. Useful when the calling code
/// can't statically guarantee a scope is active (e.g., a generic
/// startup-handler callback that's also exercised by unit tests).
pub fn try_set_session_identity(identity: Identity) {
    let _ = CURRENT_IDENTITY.try_with(|cell| *cell.borrow_mut() = identity);
}

/// Clone the current task's session identity, if any.
///
/// `None` ⇒ no [`with_session_identity`] scope is active for the
/// current task. Production callers go through
/// [`PolicyOptimizerRule::rewrite`], which falls back to its stored
/// identity in that case; this accessor is for diagnostics and tests.
#[must_use]
pub fn current_session_identity() -> Option<Identity> {
    CURRENT_IDENTITY.try_with(|cell| cell.borrow().clone()).ok()
}

/// `DataFusion` `OptimizerRule` adapter that delegates to a
/// `PolicyEnforcer`.
///
/// This is the integration point Phase 1 plugs into the
/// `SessionStateBuilder`. The rule's name (`DataglotPolicyEnforcer`)
/// surfaces in `EXPLAIN VERBOSE` and is what tests / regression
/// guards match on.
pub struct PolicyOptimizerRule {
    enforcer: Arc<dyn PolicyEnforcer>,
    /// Identity threaded into every `enforcer.rewrite` call. The
    /// rule is constructed once per pgwire session in
    /// `dataglot-server::create_session`, so the identity reflects
    /// the session's caller; it stays stable for every query on
    /// that session. `Identity::anonymous()` is the default for
    /// the no-op path and any session that hasn't authenticated.
    identity: Identity,
}

impl std::fmt::Debug for PolicyOptimizerRule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PolicyOptimizerRule")
            .field("enforcer", &self.enforcer)
            .field("identity", &self.identity)
            .finish()
    }
}

impl PolicyOptimizerRule {
    /// Wrap a `PolicyEnforcer` in an `OptimizerRule` adapter,
    /// defaulting to anonymous identity. Use
    /// [`Self::with_identity`] to inject a real identity.
    #[must_use]
    pub fn new(enforcer: Arc<dyn PolicyEnforcer>) -> Self {
        Self::with_identity(enforcer, Identity::anonymous())
    }

    /// Wrap a `PolicyEnforcer` with a specific session identity.
    /// This is the constructor `dataglot-server::create_session`
    /// uses once the pgwire startup-params extractor lands; the
    /// MVP server still calls `new` (anonymous).
    #[must_use]
    pub fn with_identity(enforcer: Arc<dyn PolicyEnforcer>, identity: Identity) -> Self {
        Self { enforcer, identity }
    }

    /// Build a rule that applies no policy. Convenience for tests
    /// and for the no-op boot path.
    #[must_use]
    pub fn noop() -> Self {
        Self::new(Arc::new(NoopPolicyEnforcer))
    }
}

impl OptimizerRule for PolicyOptimizerRule {
    fn name(&self) -> &'static str {
        "DataglotPolicyEnforcer"
    }

    fn rewrite(
        &self,
        plan: LogicalPlan,
        _config: &dyn OptimizerConfig,
    ) -> Result<Transformed<LogicalPlan>, DataFusionError> {
        // Prefer the task-local identity when a session scope is
        // active (set by the pgwire startup-handler via the server
        // crate). Outside a scope — unit tests, direct callers,
        // synthetic optimizer drivers — fall back to the
        // constructor-passed identity. This preserves the historical
        // anonymous-by-default behaviour for everything that isn't
        // an active pgwire connection.
        let active = current_session_identity().unwrap_or_else(|| self.identity.clone());
        self.enforcer.rewrite(plan, &active)
    }
}

/// [`AnalyzerRule`] adapter for enforcers that must change the plan's **output
/// schema** — specifically the column whitelist ([`ColumnWhitelistEnforcer`]),
/// which drops hidden columns.
///
/// Such rewrites cannot run as an [`OptimizerRule`]: DataFusion verifies that
/// each optimizer rule preserves the plan's output schema, and dropping a
/// column changes it. The analyzer stage runs *before* optimization and is
/// expressly allowed to reshape the schema (type coercion, wildcard expansion),
/// so schema-changing governance runs here. The masking / row-filter / deny /
/// grant enforcers stay on [`PolicyOptimizerRule`] (they preserve the schema or
/// reject). Identity is read from the same task-local session scope.
pub struct PolicyAnalyzerRule {
    enforcer: Arc<dyn PolicyEnforcer>,
    identity: Identity,
}

impl std::fmt::Debug for PolicyAnalyzerRule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PolicyAnalyzerRule")
            .field("enforcer", &self.enforcer)
            .field("identity", &self.identity)
            .finish()
    }
}

impl PolicyAnalyzerRule {
    /// Wrap a `PolicyEnforcer` in an `AnalyzerRule` adapter (anonymous default).
    #[must_use]
    pub fn new(enforcer: Arc<dyn PolicyEnforcer>) -> Self {
        Self::with_identity(enforcer, Identity::anonymous())
    }

    /// Wrap a `PolicyEnforcer` with a specific fallback session identity.
    #[must_use]
    pub fn with_identity(enforcer: Arc<dyn PolicyEnforcer>, identity: Identity) -> Self {
        Self { enforcer, identity }
    }
}

impl AnalyzerRule for PolicyAnalyzerRule {
    fn name(&self) -> &'static str {
        "DataglotColumnAuthorization"
    }

    fn analyze(
        &self,
        plan: LogicalPlan,
        _config: &ConfigOptions,
    ) -> Result<LogicalPlan, DataFusionError> {
        // Same task-local-first identity resolution as `PolicyOptimizerRule`.
        let active = current_session_identity().unwrap_or_else(|| self.identity.clone());
        Ok(self.enforcer.rewrite(plan, &active)?.data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use datafusion::common::tree_node::Transformed;
    use datafusion::logical_expr::{LogicalPlan, LogicalPlanBuilder};

    fn empty_plan() -> LogicalPlan {
        LogicalPlanBuilder::empty(true).build().expect("empty plan")
    }

    /// Tracks how many times `rewrite` was called, so tests can assert
    /// the optimizer adapter actually delegated.
    #[derive(Debug, Default)]
    struct CountingEnforcer {
        calls: std::sync::atomic::AtomicUsize,
    }

    impl CountingEnforcer {
        fn calls(&self) -> usize {
            self.calls.load(std::sync::atomic::Ordering::Relaxed)
        }
    }

    impl PolicyEnforcer for CountingEnforcer {
        fn rewrite(
            &self,
            plan: LogicalPlan,
            _identity: &Identity,
        ) -> Result<Transformed<LogicalPlan>, DataFusionError> {
            self.calls
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Ok(Transformed::no(plan))
        }
    }

    #[test]
    fn version_is_non_empty() {
        let v = policy_version();
        assert!(!v.is_empty());
    }

    #[test]
    fn noop_enforcer_returns_plan_unchanged() {
        let enforcer = NoopPolicyEnforcer;
        let plan = empty_plan();
        let out = enforcer
            .rewrite(plan.clone(), &Identity::anonymous())
            .expect("noop succeeds");
        // Noop must signal Transformed::no so the optimizer's fixed-
        // point loop converges immediately.
        assert!(!out.transformed, "noop must return Transformed::no");
    }

    #[test]
    fn enforcer_can_be_held_via_arc_dyn() {
        // Phase 1's Arc<dyn PolicyEnforcer> shape — must be object-safe.
        let _enforcer: Arc<dyn PolicyEnforcer> = Arc::new(NoopPolicyEnforcer);
    }

    #[test]
    fn optimizer_rule_name_is_stable() {
        // The rule name surfaces in EXPLAIN VERBOSE and in regression
        // guards. Pinning it here means renames are an explicit
        // breaking change.
        let rule = PolicyOptimizerRule::noop();
        assert_eq!(rule.name(), "DataglotPolicyEnforcer");
    }

    #[test]
    fn optimizer_rule_delegates_to_enforcer() {
        let counting = Arc::new(CountingEnforcer::default());
        let counting_clone = Arc::clone(&counting);
        let rule = PolicyOptimizerRule::new(counting as Arc<dyn PolicyEnforcer>);

        let plan = empty_plan();
        // OptimizerRule::rewrite needs an OptimizerConfig — use the
        // default impl that ships with datafusion-optimizer.
        let cfg = datafusion::optimizer::OptimizerContext::default();
        rule.rewrite(plan, &cfg).expect("rule rewrite succeeds");

        assert_eq!(
            counting_clone.calls(),
            1,
            "PolicyOptimizerRule::rewrite must delegate to the enforcer exactly once"
        );
    }

    #[test]
    fn optimizer_rule_with_noop_returns_unchanged_plan() {
        let rule = PolicyOptimizerRule::noop();
        let plan = empty_plan();
        let cfg = datafusion::optimizer::OptimizerContext::default();
        let out = rule.rewrite(plan, &cfg).expect("noop rewrite succeeds");
        assert!(!out.transformed, "noop adapter must signal Transformed::no");
    }

    #[test]
    fn optimizer_rule_debug_does_not_panic() {
        let rule = PolicyOptimizerRule::noop();
        let _ = format!("{rule:?}");
    }

    #[test]
    fn enforcer_default_method_is_identity() {
        // Implementer that overrides nothing: the default-method
        // identity body must hold. This is what makes
        // NoopPolicyEnforcer one line.
        #[derive(Debug)]
        struct EmptyEnforcer;
        impl PolicyEnforcer for EmptyEnforcer {}

        let plan = empty_plan();
        let out = EmptyEnforcer
            .rewrite(plan, &Identity::anonymous())
            .expect("default-impl succeeds");
        assert!(!out.transformed);
    }

    // -- Identity --------------------------------------------------------

    #[test]
    fn identity_anonymous_is_default() {
        // `Identity::default()` and `Identity::anonymous()` must
        // produce the same value. The `anonymous()` constructor
        // exists for readability at the call site.
        assert_eq!(Identity::default(), Identity::anonymous());
        assert!(Identity::anonymous().is_anonymous());
    }

    #[test]
    fn identity_user_with_org_chains() {
        // `Identity::user("alice").with_org("acme")` is the
        // canonical chained construction. Both fields populated;
        // not anonymous.
        let id = Identity::user("alice").with_org("acme");
        assert_eq!(id.user.as_deref(), Some("alice"));
        assert_eq!(id.org.as_deref(), Some("acme"));
        assert!(!id.is_anonymous());
    }

    #[test]
    fn identity_user_alone_is_not_anonymous() {
        // A user without an org is still identified.
        let id = Identity::user("bob");
        assert_eq!(id.user.as_deref(), Some("bob"));
        assert_eq!(id.org, None);
        assert!(id.org_groups.is_empty());
        assert!(!id.is_anonymous());
    }

    #[test]
    fn identity_with_groups_chains() {
        // Architecture Decisions §10 dispatches policies on group
        // match — `Identity::with_groups` is what populates the
        // list the future enforcer reads via `Policy::applies_to_groups`.
        let id = Identity::user("alice")
            .with_org("acme")
            .with_groups(["analyst", "on-call"]);
        assert_eq!(id.user.as_deref(), Some("alice"));
        assert_eq!(id.org.as_deref(), Some("acme"));
        assert_eq!(id.org_groups, vec!["analyst", "on-call"]);
        assert!(!id.is_anonymous());
    }

    #[test]
    fn org_rule_applies_semantics() {
        // Operator-wide (None) applies to everyone: acme, beta, anonymous.
        assert!(org_rule_applies(
            None,
            &Identity::user("a").with_org("acme")
        ));
        assert!(org_rule_applies(
            None,
            &Identity::user("b").with_org("beta")
        ));
        assert!(org_rule_applies(None, &Identity::anonymous()));

        // Tenant-scoped (Some) applies only to the exact matching org.
        assert!(org_rule_applies(
            Some("acme"),
            &Identity::user("a").with_org("acme")
        ));
        assert!(!org_rule_applies(
            Some("acme"),
            &Identity::user("b").with_org("beta")
        ));
        // ... and never to an anonymous / no-org session.
        assert!(!org_rule_applies(Some("acme"), &Identity::anonymous()));
    }

    #[test]
    fn identity_groups_only_is_not_anonymous() {
        // Edge case: an identity with only group memberships
        // (no user, no org). Still not anonymous — the future
        // enforcer can dispatch on group alone.
        let id = Identity::default().with_groups(["analyst"]);
        assert_eq!(id.org_groups, vec!["analyst"]);
        assert!(!id.is_anonymous());
    }

    #[test]
    fn subject_matches_semantics() {
        //: the within-tenant role gate used by masks / row-filters
        // (mirrors `access_deny`'s group intersection).
        let support = [OrgGroupId::new("support")];
        // `None` rule-groups → applies to every subject (all-groups).
        assert!(subject_matches(None, &[]));
        assert!(subject_matches(None, &["finance".to_string()]));
        // `Some` → applies iff the identity is in one of the named groups.
        assert!(subject_matches(Some(&support), &["support".to_string()]));
        assert!(subject_matches(
            Some(&support),
            &["finance".to_string(), "support".to_string()]
        ));
        assert!(!subject_matches(Some(&support), &["finance".to_string()]));
        // A group-scoped rule never matches an identity with no groups.
        assert!(!subject_matches(Some(&support), &[]));
    }

    #[test]
    fn identity_with_groups_replaces_existing() {
        // `with_groups` replaces, not appends — calling twice
        // keeps only the latest. Pin so a future change to
        // append-semantics is an explicit decision.
        let id = Identity::user("alice")
            .with_groups(["a", "b"])
            .with_groups(["c"]);
        assert_eq!(id.org_groups, vec!["c"]);
    }

    /// Capturing enforcer — records the most recent `Identity`
    /// it was rewritten with. Used to assert the
    /// `PolicyOptimizerRule` adapter actually threads the
    /// session identity into the enforcer.
    #[derive(Debug, Default)]
    struct IdentityCapturingEnforcer {
        last_seen: std::sync::Mutex<Option<Identity>>,
    }

    impl PolicyEnforcer for IdentityCapturingEnforcer {
        fn rewrite(
            &self,
            plan: LogicalPlan,
            identity: &Identity,
        ) -> Result<Transformed<LogicalPlan>, DataFusionError> {
            *self.last_seen.lock().unwrap() = Some(identity.clone());
            Ok(Transformed::no(plan))
        }
    }

    #[test]
    fn optimizer_rule_threads_identity_to_enforcer() {
        // Pin the per-session contract: the identity given at
        // rule construction is what the enforcer sees on every
        // rewrite. This is the integration point the future
        // pgwire startup-params extractor will rely on.
        let captured = Arc::new(IdentityCapturingEnforcer::default());
        let captured_clone = Arc::clone(&captured);
        let identity = Identity::user("alice").with_org("acme");
        let rule = PolicyOptimizerRule::with_identity(
            captured as Arc<dyn PolicyEnforcer>,
            identity.clone(),
        );

        let cfg = datafusion::optimizer::OptimizerContext::default();
        rule.rewrite(empty_plan(), &cfg).expect("rule rewrite");

        let seen = captured_clone
            .last_seen
            .lock()
            .unwrap()
            .clone()
            .expect("enforcer was called");
        assert_eq!(seen, identity);
    }

    #[test]
    fn optimizer_rule_new_defaults_to_anonymous_identity() {
        // The `new` constructor is the no-pgwire-extractor-yet
        // path; it MUST default to anonymous. Pin so a future
        // ctor change can't silently change the default.
        let captured = Arc::new(IdentityCapturingEnforcer::default());
        let captured_clone = Arc::clone(&captured);
        let rule = PolicyOptimizerRule::new(captured as Arc<dyn PolicyEnforcer>);

        let cfg = datafusion::optimizer::OptimizerContext::default();
        rule.rewrite(empty_plan(), &cfg).expect("rule rewrite");

        let seen = captured_clone.last_seen.lock().unwrap().clone().unwrap();
        assert!(
            seen.is_anonymous(),
            "PolicyOptimizerRule::new must default to anonymous identity",
        );
    }

    // -- CompositeEnforcer --------------------------------------------

    /// `Transformed::yes`-returning enforcer that re-uses the input
    /// plan. Used to assert composite ordering and aggregation.
    #[derive(Debug)]
    struct YesEnforcer;
    impl PolicyEnforcer for YesEnforcer {
        fn rewrite(
            &self,
            plan: LogicalPlan,
            _identity: &Identity,
        ) -> Result<Transformed<LogicalPlan>, DataFusionError> {
            Ok(Transformed::yes(plan))
        }
    }

    #[test]
    fn composite_with_no_inner_is_identity() {
        let composite = CompositeEnforcer::new(Vec::new());
        assert!(composite.is_empty());
        assert_eq!(composite.len(), 0);
        let plan = empty_plan();
        let out = composite
            .rewrite(plan, &Identity::anonymous())
            .expect("rewrite succeeds");
        assert!(
            !out.transformed,
            "empty composite must report Transformed::no — no inner enforcer to drive a change",
        );
    }

    #[test]
    fn composite_calls_each_inner_in_order() {
        // Two counting enforcers — distinct instances so we can
        // assert call counts independently.
        let first = Arc::new(CountingEnforcer::default());
        let second = Arc::new(CountingEnforcer::default());
        let composite = CompositeEnforcer::new(vec![
            Arc::clone(&first) as Arc<dyn PolicyEnforcer>,
            Arc::clone(&second) as Arc<dyn PolicyEnforcer>,
        ]);
        let plan = empty_plan();
        composite
            .rewrite(plan, &Identity::anonymous())
            .expect("rewrite succeeds");
        assert_eq!(first.calls(), 1, "first inner must be called exactly once");
        assert_eq!(
            second.calls(),
            1,
            "second inner must be called exactly once"
        );
    }

    #[test]
    fn composite_aggregates_transformed_yes_from_any_inner() {
        // Pin the aggregation rule: a Composite reports
        // Transformed::yes if ANY inner reported yes, even when
        // others reported no. Without this, the optimizer's
        // fixed-point loop wouldn't know to re-run the rule and
        // we'd silently miss propagating a real rewrite.
        let noop = Arc::new(CountingEnforcer::default());
        let yes = Arc::new(YesEnforcer);
        let composite = CompositeEnforcer::new(vec![
            noop as Arc<dyn PolicyEnforcer>,
            yes as Arc<dyn PolicyEnforcer>,
        ]);
        let out = composite
            .rewrite(empty_plan(), &Identity::anonymous())
            .expect("rewrite succeeds");
        assert!(
            out.transformed,
            "composite must report Transformed::yes when any inner did",
        );
    }

    #[test]
    fn composite_reports_no_when_all_inner_are_no() {
        // Converse of the above — all noops ⇒ composite is a noop.
        let a = Arc::new(CountingEnforcer::default());
        let b = Arc::new(CountingEnforcer::default());
        let composite = CompositeEnforcer::new(vec![
            a as Arc<dyn PolicyEnforcer>,
            b as Arc<dyn PolicyEnforcer>,
        ]);
        let out = composite
            .rewrite(empty_plan(), &Identity::anonymous())
            .expect("rewrite succeeds");
        assert!(
            !out.transformed,
            "composite must report Transformed::no when no inner reported a change",
        );
    }

    // -- Per-task session identity (task-local) --------------------------

    #[test]
    fn current_session_identity_is_none_outside_scope() {
        // Without a `with_session_identity` scope the accessor must
        // return None — that's what tells `PolicyOptimizerRule::rewrite`
        // to fall back to its constructor identity. Pinned so a future
        // refactor (e.g., a default scope at task root) doesn't silently
        // change the no-scope contract.
        assert!(current_session_identity().is_none());
    }

    #[tokio::test]
    async fn with_session_identity_makes_initial_visible() {
        // The initial identity passed to the scope is observable
        // immediately, before any `set_session_identity` call.
        let initial = Identity::user("alice");
        let observed = with_session_identity(initial.clone(), async {
            current_session_identity().expect("inside scope")
        })
        .await;
        assert_eq!(observed, initial);
    }

    #[tokio::test]
    async fn set_session_identity_replaces_in_active_scope() {
        // The pgwire startup handler's job: extract the username,
        // call `set_session_identity` with the resolved Identity.
        // Subsequent reads must see the new value.
        let observed = with_session_identity(Identity::anonymous(), async {
            set_session_identity(Identity::user("bob").with_groups(["analyst"]));
            current_session_identity().expect("inside scope")
        })
        .await;
        assert_eq!(observed.user.as_deref(), Some("bob"));
        assert_eq!(observed.org_groups, vec!["analyst".to_string()]);
    }

    #[test]
    fn try_set_session_identity_outside_scope_is_no_op() {
        // Pre-condition: no scope active in this synchronous test.
        assert!(current_session_identity().is_none());
        // Calling try_set without a scope must not panic.
        try_set_session_identity(Identity::user("alice"));
        // And must not somehow create a scope.
        assert!(current_session_identity().is_none());
    }

    #[tokio::test]
    async fn optimizer_rule_prefers_task_local_over_constructor_identity() {
        // The integration the pgwire identity extractor relies on:
        // a rule built with `Identity::anonymous()` (the only thing
        // available when SessionContext is constructed) must observe
        // the per-task identity when run inside a session scope.
        let captured = Arc::new(IdentityCapturingEnforcer::default());
        let captured_clone = Arc::clone(&captured);
        let rule = PolicyOptimizerRule::new(captured as Arc<dyn PolicyEnforcer>);

        let task_identity = Identity::user("carol").with_groups(["support"]);
        with_session_identity(task_identity.clone(), async {
            let cfg = datafusion::optimizer::OptimizerContext::default();
            rule.rewrite(empty_plan(), &cfg).expect("rule rewrite");
        })
        .await;

        let seen = captured_clone
            .last_seen
            .lock()
            .unwrap()
            .clone()
            .expect("enforcer was called");
        assert_eq!(seen, task_identity);
    }

    #[tokio::test]
    async fn optimizer_rule_falls_back_to_constructor_identity_when_no_scope() {
        // The other side of the contract: outside a scope, the
        // constructor-passed identity is what the enforcer sees.
        // This is what keeps every existing test (and the no-pgwire
        // boot path) green.
        let captured = Arc::new(IdentityCapturingEnforcer::default());
        let captured_clone = Arc::clone(&captured);
        let ctor_identity = Identity::user("dave");
        let rule = PolicyOptimizerRule::with_identity(
            captured as Arc<dyn PolicyEnforcer>,
            ctor_identity.clone(),
        );

        let cfg = datafusion::optimizer::OptimizerContext::default();
        rule.rewrite(empty_plan(), &cfg).expect("rule rewrite");

        let seen = captured_clone
            .last_seen
            .lock()
            .unwrap()
            .clone()
            .expect("enforcer was called");
        assert_eq!(seen, ctor_identity);
    }

    #[tokio::test]
    async fn sibling_tasks_have_isolated_session_identities() {
        // Two concurrent connections must not see each other's
        // identity. tokio task-locals don't propagate across
        // `tokio::spawn`, which is exactly the property we want here:
        // each connection task sees only its own scope.
        let alice = tokio::spawn(with_session_identity(
            Identity::user("alice").with_groups(["analyst"]),
            async { current_session_identity().expect("alice scope") },
        ));
        let bob = tokio::spawn(with_session_identity(
            Identity::user("bob").with_groups(["support"]),
            async { current_session_identity().expect("bob scope") },
        ));

        let alice_id = alice.await.expect("alice task");
        let bob_id = bob.await.expect("bob task");
        assert_eq!(alice_id.user.as_deref(), Some("alice"));
        assert_eq!(alice_id.org_groups, vec!["analyst".to_string()]);
        assert_eq!(bob_id.user.as_deref(), Some("bob"));
        assert_eq!(bob_id.org_groups, vec!["support".to_string()]);
    }
}

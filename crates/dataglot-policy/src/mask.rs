//! Column masking — first concrete `PolicyEnforcer` implementation.
//!
//! [`ColumnMaskingEnforcer`] is the Phase 1 governance MVP. It takes a
//! map of `(TableReference, ColumnName) → masking Expr` rules and
//! rewrites a `LogicalPlan` so every matching column reference inside
//! a `Projection` returns the registered mask `Expr` instead of the
//! original column. Predicates, joins, sorts, and aggregates see the
//! original column values — see [option A in spec
//! 01](../../../../docs/phases/phase-1/01-column-masking-mvp.md) for
//! the design rationale (industry-standard semantics: Snowflake /
//! `BigQuery` / Databricks DYNAMIC DATA MASKING).
//!
//! # Rule precedence and matching
//!
//! Rules are stored keyed by `(TableReference, String)` and matched
//! by *strict* `TableReference` equality — `Bare`, `Partial`, and
//! `Full` variants must agree exactly. Loose matching ("any schema")
//! is a Phase 1 Task 03 affordance built on top of the typed tag
//! model from Architecture Decisions §10. Until then, callers must
//! register rules using the same `TableReference` shape `DataFusion`'s
//! planner produces during planning.
//!
//! ## Alias resolution (one-directional fallback)
//!
//! Strict equality alone misses aliased projections —
//! `SELECT u.email FROM users u` lands a column reference whose
//! relation is the SQL alias `u`, not the source table `users`. To
//! mask it, the enforcer scans the plan once for `SubqueryAlias →
//! TableScan` mappings (one per `FROM x y` or join leg) and, on a
//! strict-match miss, retries the lookup under the underlying table.
//! Direction is asymmetric: a rule keyed on the alias does **not**
//! mask references to the source table — that would reopen the
//! cross-catalog collision risk strict matching exists to prevent.
//! See `column_mask_alias_fallback_is_one_directional` for the
//! regression. Aliases over subplans
//! (`SELECT u.x FROM (SELECT … FROM users) u`) are not resolved yet
//! — only `SubqueryAlias` whose immediate input is a `TableScan`
//! enters the map.
//!
//! # What this MVP does NOT do
//!
//! - **No identity / RBAC.** Rules are registered against a static
//!   enforcer instance. Per-user / per-org filtering is Task 02.
//! - **No persistent rule store.** Rules live in process memory.
//!   Task 04 wires the catalog service.
//! - **No row-level filters.** Task 05.
//! - **No mask-expression validation.** A wrong-typed mask
//!   (`Int64` literal masking a `Utf8` column) surfaces as a
//!   `DataFusion` planning error, not a registration error. Task 03
//!   adds typed validation.

use std::collections::HashMap;

use datafusion::common::tree_node::{Transformed, TreeNode};
use datafusion::error::DataFusionError;
use datafusion::logical_expr::{Expr, LogicalPlan, Projection};
use datafusion::sql::TableReference;

use crate::{Identity, PolicyEnforcer};

/// The scoped mask rules registered on one `(table, column)` key:
/// `(rule org, rule groups, mask Expr)` triples, at most one per distinct
/// `(org, groups)` scope ( F4 org dimension +  group dimension).
/// `None` org = operator-wide, `Some(x)` = tenant-scoped; `None` groups = all
/// subjects, `Some(gs)` = group-scoped. A group-scoped and an all-groups rule
/// on the same `(table, column, org)` coexist — the group-scoped one wins for a
/// matching identity (see [`ColumnMaskingEnforcer::lookup_mask`]).
/// One mask candidate on a `(table, column)` key: org scope, group scope, and
/// the masking expression.
type MaskEntry = (Option<String>, Option<Vec<crate::OrgGroupId>>, Expr);
type OrgTaggedMasks = Vec<MaskEntry>;

/// One column-masking rule.
///
/// `ColumnMask` is the **input shape**; `ColumnMaskingEnforcer`
/// decomposes a stream of these into its internal lookup map at
/// construction time.
#[derive(Debug, Clone)]
pub struct ColumnMask {
    /// Fully-qualified table the rule applies to. Match is strict
    /// (`TableReference` `Eq`) — see the module-level docs.
    pub table: TableReference,
    /// Column name within `table`.
    pub column: String,
    /// `DataFusion` `Expr` returned in place of the column. Typically
    /// a literal (`Expr::Literal('***@example.com')`) but any `Expr`
    /// that produces a compatible type is accepted.
    pub mask: Expr,
    /// Owning organization / tenant. `None` =
    /// **operator-wide** — the rule masks the column for *every*
    /// session regardless of org (what a file-config `[[masks]]` entry
    /// maps to, preserving single-org behaviour). `Some(x)` =
    /// **tenant-scoped** — the rule masks only for a session whose
    /// `Identity.org` is exactly `x` (what a runtime `CREATE MASK`
    /// maps to, tagged with the creating session's org). Selection
    /// happens at `rewrite` time (a rule applies iff its org is `None`
    /// or equals the session's org); the masking itself stays a
    /// plan-time `Expr` substitution (rule 6).
    pub org: Option<String>,
    /// Org-groups / roles the mask applies to ( — role-conditional
    /// masks). `None` = **all subjects** in the org scope: the rule masks the
    /// column for every session (what a file-config `[[masks]]` entry with no
    /// `groups` maps to, preserving pre- behaviour). `Some(gs)` =
    /// **group-scoped**: the rule masks only for a session whose
    /// [`crate::Identity::org_groups`] intersects `gs`. Selection combines with
    /// [`Self::org`] — a rule fires iff `org_rule_applies(org) &&
    /// subject_matches(groups)`. Mirrors [`crate::AccessDenial::groups`] so
    /// masks, row filters, and access-deny all condition on group membership
    /// the same way. See `subject_matches`.
    pub groups: Option<Vec<crate::OrgGroupId>>,
}

/// Errors raised when constructing a [`ColumnMaskingEnforcer`].
#[derive(Debug, thiserror::Error)]
pub enum BuildError {
    /// Two rules target the same `(table, column)` pair. The MVP
    /// rejects this rather than picking a winner — Phase 1 Task 03
    /// introduces priority / layering.
    #[error("duplicate masking rule for column `{column}` of table `{table}`")]
    DuplicateRule {
        /// The table whose column has duplicate rules.
        table: TableReference,
        /// The column name with duplicate rules.
        column: String,
    },
}

/// `PolicyEnforcer` implementation that rewrites projections to
/// substitute registered masking expressions for matching column
/// references.
///
/// Constructed via [`ColumnMaskingEnforcer::new`]. Matches strictly
/// on `TableReference` equality and only rewrites inside
/// `Projection` nodes — predicates, joins, sorts, aggregates, and
/// `TableScan` see the original column values (option A in the
/// spec). See the module-level docs.
#[derive(Debug, Default)]
pub struct ColumnMaskingEnforcer {
    /// `(table, column)` → the org-tagged mask rules for that column.
    /// Multiple orgs can register a mask on the *same* `(table, column)`
    /// (e.g. every tenant masks `users.email` under its own org), so the
    /// value is a list keyed by the rule's `org`; `rewrite`/`explain`
    /// pick the entry that applies to the session identity via
    /// [`crate::org_rule_applies`]. At most one rule per distinct org per
    /// key (enforced at construction).
    masks: HashMap<(TableReference, String), OrgTaggedMasks>,
    /// Session default `(catalog, schema)` used to *upgrade* an
    /// under-qualified query reference when matching a more-qualified
    /// mask key. `None` (the default) disables upgrade matching, so
    /// behaviour is exactly the historical downgrade-only matching.
    ///
    /// This is what lets a fully-qualified mask (e.g. a lineage-
    /// propagated mask keyed `cat.schema.v` for cross-catalog
    /// collision safety — ) still match a bare-written query
    /// (`SELECT … FROM v`) that resolves to that catalog/schema. The
    /// existing `match_candidates` downgrade only handles the inverse
    /// (a bare mask matching a qualified query).
    session_defaults: Option<(String, String)>,
    /// `(table, column)` pairs already reported by [`Self::warn_unfireable_masks`]
    /// so a mask rule whose column is absent from the table's schema warns
    /// once per enforcer instance, not once per optimizer pass per query
    ///. Shared + interior-mutable because `rewrite` takes `&self`.
    warned_unfireable:
        std::sync::Arc<std::sync::Mutex<std::collections::HashSet<(TableReference, String)>>>,
}

impl ColumnMaskingEnforcer {
    /// Build an enforcer from a stream of [`ColumnMask`] rules.
    ///
    /// # Errors
    ///
    /// Returns [`BuildError::DuplicateRule`] if two input rules share
    /// the same `(table, column, org)` triple. Two rules on the same
    /// `(table, column)` but **different** orgs are *not* duplicates —
    /// they are distinct per-tenant (or tenant-vs-operator-wide) rules
    /// that coexist and are disambiguated per session at `rewrite` time.
    pub fn new(masks: impl IntoIterator<Item = ColumnMask>) -> Result<Self, BuildError> {
        let mut map: HashMap<(TableReference, String), OrgTaggedMasks> = HashMap::new();
        for ColumnMask {
            table,
            column,
            mask,
            org,
            groups,
        } in masks
        {
            // `get_mut` + `insert` rather than `entry((table.clone(),
            // column.clone()))` so the `(TableReference, String)` key isn't
            // cloned per rule — it moves into either the error or the map
            // (Gemini perf review). The `entry` API can't be used here because
            // the duplicate-error path needs the un-consumed `table`/`column`.
            let key = (table, column);
            match map.get_mut(&key) {
                Some(entries) => {
                    // The uniqueness key is `(org, groups)` — two rules on the
                    // same `(table, column)` that differ in org *or* in group
                    // scope are distinct and coexist. Only an exact
                    // `(org, groups)` repeat is a duplicate.
                    if entries.iter().any(|(existing_org, existing_groups, _)| {
                        existing_org == &org && existing_groups == &groups
                    }) {
                        let (table, column) = key;
                        return Err(BuildError::DuplicateRule { table, column });
                    }
                    entries.push((org, groups, mask));
                }
                None => {
                    map.insert(key, vec![(org, groups, mask)]);
                }
            }
        }
        Ok(Self {
            masks: map,
            session_defaults: None,
            warned_unfireable: std::sync::Arc::default(),
        })
    }

    /// Set the session default `(catalog, schema)` used to upgrade an
    /// under-qualified query reference during matching, so a
    /// fully-qualified mask matches a bare/partial query that resolves
    /// to that catalog/schema. Additive — without it,
    /// matching is the historical downgrade-only behaviour. Returns
    /// `self` for chaining.
    #[must_use]
    pub fn with_session_defaults(
        mut self,
        catalog: impl Into<String>,
        schema: impl Into<String>,
    ) -> Self {
        self.session_defaults = Some((catalog.into(), schema.into()));
        self
    }

    /// Build a real-but-empty enforcer. Registers no rules; behaves
    /// identically to `NoopPolicyEnforcer` for any plan.
    ///
    /// Useful in tests that need an enforcer of the right type
    /// without any rules.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            masks: HashMap::new(),
            session_defaults: None,
            warned_unfireable: std::sync::Arc::default(),
        }
    }

    /// Number of rules registered (summed across every org). Surfaced
    /// for diagnostics — not used in the rewrite path.
    #[must_use]
    pub fn rule_count(&self) -> usize {
        self.masks.values().map(Vec::len).sum()
    }

    /// Rewrite a single projection-level expression.
    ///
    /// For top-level `Expr::Column` matching a rule, wraps the mask
    /// in `Expr::alias_qualified(relation, name)` so the projected
    /// schema's field keeps both the column name AND the original
    /// table qualifier (`SELECT email FROM users` ⇒ output field is
    /// still `users.email`, not unqualified `email`). The qualifier
    /// matters because `DataFusion`'s per-rule invariant checker
    /// compares schemas via `DFSchema::compatible`, which fails on
    /// `Some(table) → None` qualifier transitions; downstream rules
    /// like `optimize_projections` then trip
    /// `Internal("Assertion failed: compatible: Failed due to a
    /// difference in schemas")` and the query fails. Plain `alias`
    /// (qualifier=None) was the shape used by the pre-server-wiring
    /// MVP — its tests called `enforcer.rewrite` directly and
    /// bypassed the optimizer pipeline, so this never surfaced.
    /// For nested column references (e.g., `UPPER(email)`),
    /// substitutes the mask directly — `DataFusion` derives the new
    /// output name from the rewritten expression and there's no
    /// top-level qualifier to preserve.
    ///
    /// `aliases` is a precomputed map of `SubqueryAlias → underlying
    /// TableReference` collected from the plan's input subtree. If a
    /// column's relation doesn't hit a rule directly, we retry under
    /// the alias's underlying table — so a rule on `users.email`
    /// masks `SELECT u.email FROM users u`.
    fn mask_projection_expr(
        &self,
        expr: Expr,
        alias_map: &HashMap<TableReference, TableReference>,
        identity: &Identity,
    ) -> Result<Transformed<Expr>, DataFusionError> {
        // Top-level Column branch — preserve both the projected name
        // and the original table qualifier.
        if let Expr::Column(c) = &expr {
            if let Some(rel) = &c.relation {
                if let Some(mask) = self.lookup_mask(rel, &c.name, alias_map, identity) {
                    // Ranger audit parity: every mask decision is
                    // recorded with the session identity (`crate::audit`).
                    crate::audit::record_decision("mask", identity, &format!("{rel}.{}", c.name));
                    let aliased = mask
                        .clone()
                        .alias_qualified(Some(rel.clone()), c.name.clone());
                    return Ok(Transformed::yes(aliased));
                }
            }
            return Ok(Transformed::no(expr));
        }

        // Otherwise recurse: substitute any nested matching column
        // without preserving names — DataFusion will derive the new
        // output column name from the rewritten expression tree.
        expr.transform_down(|e| {
            if let Expr::Column(c) = &e {
                if let Some(rel) = &c.relation {
                    if let Some(mask) = self.lookup_mask(rel, &c.name, alias_map, identity) {
                        crate::audit::record_decision(
                            "mask",
                            identity,
                            &format!("{rel}.{}", c.name),
                        );
                        return Ok(Transformed::yes(mask.clone()));
                    }
                }
            }
            Ok(Transformed::no(e))
        })
    }

    /// Look up a mask by column. Tries the column's relation as
    /// reported by the planner first (strict match — the documented
    /// semantics); on miss, retries under the alias-resolved
    /// underlying table. The alias fallback handles
    /// `SELECT u.email FROM users u` and the join cases that surface
    /// it (`FROM users u JOIN orders o ON …`), where the planner
    /// stamps the column relation as the SQL alias rather than the
    /// original table.
    fn lookup_mask(
        &self,
        rel: &TableReference,
        column: &str,
        alias_map: &HashMap<TableReference, TableReference>,
        identity: &Identity,
    ) -> Option<&Expr> {
        // All candidate table keys to consult, in precedence order: the query
        // relation at each candidate qualification (most- to least-qualified
        // downgrade, plus session-default upgrade) so a less-qualified rule
        // (bare `users`) matches a more-qualified reference (`pg.public.users`)
        // —  — *and* a more-qualified rule matches a query that resolves
        // to it —; then the alias-resolved underlying table's candidates
        // (the one-directional alias fallback for `SELECT u.email FROM users u`).
        let mut candidates = self.candidate_refs(rel);
        if let Some(original) = alias_map.get(rel) {
            candidates.extend(self.candidate_refs(original));
        }
        // Select over the *union* of all candidates in a single pass, keeping
        // the highest-precedence *applicable* mask. Precedence combines two
        // dimensions ( F4 org +  group), most-specific first:
        //   tenant + group-specific  (rank 3)
        //   tenant + all-groups       (rank 2)   ── tenant beats operator-wide
        //   operator-wide + group-specific (rank 1)
        //   operator-wide + all-groups     (rank 0)
        // i.e. a matching **tenant-scoped** mask beats an **operator-wide** one,
        // and within one org tier a **group-scoped** mask beats an **all-groups**
        // one for a matching identity. Selecting over the union (rather than
        // returning on the first candidate that yielded *any* applicable mask)
        // keeps a matching tenant/group rule under a *later* candidate from being
        // shadowed by a broader rule under an earlier one. Ties (equal rank) keep
        // the first encountered — candidates run most- to least-qualified, so the
        // most-qualified rule wins the tie (the / invariant).
        let mut best: Option<(u8, &Expr)> = None;
        for cand in candidates {
            let Some(entries) = self.masks.get(&(cand, column.to_string())) else {
                continue;
            };
            for (org, groups, mask) in entries {
                if let Some(rank) =
                    Self::applicable_rank(org.as_deref(), groups.as_deref(), identity)
                {
                    if best.is_none_or(|(r, _)| rank > r) {
                        best = Some((rank, mask));
                    }
                }
            }
        }
        best.map(|(_, mask)| mask)
    }

    /// Precedence rank of a mask rule scoped to `(org, groups)` for `identity`,
    /// or `None` when the rule does not apply. Higher rank = more specific =
    /// wins. See [`Self::lookup_mask`] for the four-way ordering.
    ///
    /// A rule applies iff [`crate::org_rule_applies`] **and**
    /// `subject_matches` — org matches (or is operator-wide) *and* the
    /// group scope matches (or is all-subjects).
    fn applicable_rank(
        org: Option<&str>,
        groups: Option<&[crate::OrgGroupId]>,
        identity: &Identity,
    ) -> Option<u8> {
        if !crate::org_rule_applies(org, identity)
            || !crate::subject_matches(groups, &identity.org_groups)
        {
            return None;
        }
        let tenant_bit = u8::from(org.is_some());
        let group_bit = u8::from(groups.is_some());
        Some(tenant_bit * 2 + group_bit)
    }

    /// Choose the mask rule that applies to `identity` from the scoped
    /// candidates registered on one `(table, column)` key ( F4 org +
    ///  group). Mirrors [`Self::lookup_mask`]'s precedence over a single
    /// entries slice; used by [`PolicyEnforcer::explain`].
    fn pick_applicable<'a>(entries: &'a [MaskEntry], identity: &Identity) -> Option<&'a Expr> {
        let mut best: Option<(u8, &Expr)> = None;
        for (org, groups, mask) in entries {
            if let Some(rank) = Self::applicable_rank(org.as_deref(), groups.as_deref(), identity) {
                if best.is_none_or(|(r, _)| rank > r) {
                    best = Some((rank, mask));
                }
            }
        }
        best.map(|(_, mask)| mask)
    }

    /// Candidate mask keys for a query relation, **ordered most- to
    /// least-qualified** so the most-specific matching rule wins (the
    /// governance precedence invariant `lookup_mask` relies on).
    ///
    /// Without session defaults this is exactly [`crate::match_candidates`]
    /// — the *downgrade* chain (a less-qualified mask matches a
    /// more-qualified query — ). With session defaults set, an
    /// under-qualified query reference is first *upgraded* to the session
    /// catalog/schema and the upgraded (more-qualified) candidates are
    /// placed **first**, so a fully-qualified mask matches a bare/partial
    /// query that resolves there *and* still outranks a bare mask (;
    /// fixes the precedence regression flagged on #480 where appended
    /// upgrade candidates let the bare mask win).
    fn candidate_refs(&self, rel: &TableReference) -> Vec<TableReference> {
        let Some((dc, ds)) = &self.session_defaults else {
            return crate::match_candidates(rel);
        };
        let table = rel.table().to_string();
        match (rel.catalog(), rel.schema()) {
            // Bare `t` → most→least: `dc.ds.t`, `ds.t`, `t`.
            (None, None) => vec![
                TableReference::full(dc.clone(), ds.clone(), table.clone()),
                TableReference::partial(ds.clone(), table.clone()),
                TableReference::bare(table),
            ],
            // Partial `s.t` → most→least: `dc.s.t`, `s.t`, `t`.
            (None, Some(schema)) => vec![
                TableReference::full(dc.clone(), schema.to_string(), table.clone()),
                TableReference::partial(schema.to_string(), table.clone()),
                TableReference::bare(table),
            ],
            // Already fully qualified — plain downgrade chain.
            _ => crate::match_candidates(rel),
        }
    }

    /// Read-only pre-pass over `plan`: warn about mask rules that can
    /// **never** fire because their target column is absent from the
    /// scanned table's schema — a silent-bypass misconfiguration (a
    /// typo'd or renamed column) that leaves the intended data unmasked
    ///
    /// Uses the scan's *source* schema (the full table schema, before
    /// projection pushdown) as ground truth, so it never false-positives
    /// on a column the query merely didn't select — and, unlike a
    /// "rule matched no reference" heuristic, it can't be confused by a
    /// different table that happens to share a name. Each unfireable
    /// `(table, column)` warns once per enforcer instance (dedup via
    /// [`Self::warned_unfireable`]) rather than once per optimizer pass.
    fn warn_unfireable_masks(&self, plan: &LogicalPlan) {
        use datafusion::common::tree_node::TreeNodeRecursion;
        let _ = plan.apply(|node| {
            if let LogicalPlan::TableScan(scan) = node {
                let schema = scan.source.schema();
                let candidates = self.candidate_refs(&scan.table_name);
                for (rule_table, rule_col) in self.masks.keys() {
                    // Only rules that target *this* scanned table.
                    if !candidates.iter().any(|cand| cand == rule_table) {
                        continue;
                    }
                    // Ground truth: if the column exists in the table, the
                    // rule can fire (when the column is selected) — nothing
                    // to warn about.
                    if schema.field_with_name(rule_col).is_ok() {
                        continue;
                    }
                    let key = (rule_table.clone(), rule_col.clone());
                    // Warn once per (table, column) for this enforcer.
                    let mut warned = self
                        .warned_unfireable
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    if warned.insert(key) {
                        tracing::warn!(
                            target: "dataglot::audit",
                            action = "mask_rule_unfireable",
                            table = %rule_table,
                            column = %rule_col,
                            scanned_table = %scan.table_name,
                            "mask rule targets a column absent from the table's schema; it can never fire and the intended data is left unmasked — check for a typo or renamed column"
                        );
                    }
                }
            }
            Ok(TreeNodeRecursion::Continue)
        });
    }
}

/// Walk a `LogicalPlan` subtree and collect every direct
/// `SubqueryAlias`→`TableScan` mapping into `out`, keyed by the alias
/// as a `Bare` `TableReference`.
///
/// Only `SubqueryAlias` whose input is a `TableScan` is recorded:
/// `FROM users u` introduces exactly that shape, as does each leg of
/// `FROM users u JOIN orders o …`. Aliases over arbitrary subplans
/// (`SELECT u.x FROM (SELECT … FROM users) u`) intentionally don't
/// get an entry here — resolving those requires schema-walking the
/// inner plan and is the next slice of this work. For the MVP fix
/// that targets the reported cross-source-join bug, the
/// `SubqueryAlias → TableScan` cases cover the surface.
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

impl PolicyEnforcer for ColumnMaskingEnforcer {
    fn explain(&self, plan: &LogicalPlan, identity: &Identity) -> Vec<crate::PolicyDecision> {
        use crate::{PolicyAction, PolicyDecision};
        if self.masks.is_empty() {
            return Vec::new();
        }
        let mut out: Vec<PolicyDecision> = Vec::new();
        for col in crate::collect_plan_columns(plan) {
            let Some(rel) = &col.relation else { continue };
            // Match at each candidate qualification via `candidate_refs` —
            // the SAME matcher the rewrite path uses. This includes the
            // session-default *upgrade*, so `explain` reports a
            // fully-qualified propagated mask as applied to a bare-written
            // query. Using the downgrade-only `match_candidates`
            // here made `/policy/explain` under-report: it said "not masked"
            // for a bare query that `rewrite` actually masks. The org filter
            // (`pick_applicable`) mirrors rewrite too, so explain reports a
            // mask only for the session it would actually fire for (F4).
            let masked = self.candidate_refs(rel).iter().any(|cand| {
                self.masks
                    .get(&(cand.clone(), col.name.clone()))
                    .is_some_and(|entries| Self::pick_applicable(entries, identity).is_some())
            });
            if !masked {
                continue;
            }
            let resource = format!("{rel}.{}", col.name);
            if !out.iter().any(|d| d.resource == resource) {
                out.push(PolicyDecision::new(
                    PolicyAction::Mask,
                    resource,
                    "column value masked at projection",
                ));
            }
        }
        out
    }

    fn rewrite(
        &self,
        plan: LogicalPlan,
        identity: &Identity,
    ) -> Result<Transformed<LogicalPlan>, DataFusionError> {
        // Identity does not drive rule *dispatch* here — column-masking
        // rules are static `(table, column) → mask Expr` (identity-aware
        // dispatch lives in `TagBasedEnforcer`, which delegates back to
        // this enforcer). It IS recorded on every mask decision's audit
        // event (`crate::audit`), so the trail says who saw the masked
        // value.
        //
        // Empty enforcer ⇒ identity rewrite. Skip the walk entirely so
        // the optimizer's fixed-point loop converges immediately.
        if self.masks.is_empty() {
            return Ok(Transformed::no(plan));
        }

        // Read-only pre-pass: surface any mask rule that can never fire
        // because its column is absent from the scanned table.
        // Deduped, so it costs a set lookup at most once per unfireable
        // rule per enforcer.
        self.warn_unfireable_masks(&plan);

        // Build the alias map once per `rewrite()` call. Reused for
        // every Projection node the walker visits below — cheaper than
        // walking the subtree per Projection, and the mapping is
        // plan-wide anyway (an alias declared deep in a join's leg is
        // referenceable from any Projection above the join).
        let mut alias_map: HashMap<TableReference, TableReference> = HashMap::new();
        collect_alias_targets(&plan, &mut alias_map);

        // Governance must reach masked columns no matter how deeply they hide.
        // `transform_down` walks the main plan tree (node *inputs*) but not
        // subqueries embedded in *expressions* (`Expr::ScalarSubquery` /
        // `InSubquery` / `SetComparison` / `Exists`, each holding a
        // `Subquery { subquery: Arc<LogicalPlan> }`) — DataFusion's `TreeNode`
        // walk treats those as opaque, so a Projection inside such a subquery
        // would return its columns UNMASKED. At every node we therefore also
        // rewrite the node's expressions, recursively re-running this full
        // masking rewrite on each embedded subquery plan and rebuilding the
        // enclosing `Subquery`/`Expr` (`crate::map_subquery_plans`, which
        // preserves `outer_ref_columns` so a correlated subquery's outer refs —
        // the parent's columns — are never masked; only the subquery's own
        // scans are). Nesting is handled because the recursive `rewrite` walks
        // the subquery the same way.
        plan.transform_down(|node| {
            // (1) Descend into expression subqueries on this node (any node
            // type). `map_expressions` preserves a `Projection`'s DFSchema — it
            // reuses the `schema` field rather than recomputing it — so the
            // careful qualifier preservation below is not disturbed.
            let Transformed {
                data: node,
                transformed: sub_changed,
                ..
            } = node.map_expressions(|expr| {
                // A subquery can sit anywhere in the expression tree — bare
                // (`Filter` predicate), inside an `Alias` (`SELECT (…) AS e`), a
                // `BinaryExpr`, etc. — so walk every sub-expr, not just the top
                // level, and rewrite each embedded subquery plan in place.
                expr.transform_down(|e| {
                    crate::map_subquery_plans(e, &mut |subplan| {
                        let out =
                            self.rewrite(std::sync::Arc::unwrap_or_clone(subplan), identity)?;
                        Ok(out.update_data(std::sync::Arc::new))
                    })
                })
            })?;

            // (2) Main-tree projection masking (unchanged semantics).
            let LogicalPlan::Projection(proj) = node else {
                return Ok(if sub_changed {
                    Transformed::yes(node)
                } else {
                    Transformed::no(node)
                });
            };

            let Projection {
                expr: exprs,
                input,
                schema,
                ..
            } = proj;

            let mut any_changed = sub_changed;
            let mut new_exprs: Vec<Expr> = Vec::with_capacity(exprs.len());
            for e in exprs {
                let Transformed {
                    data,
                    transformed,
                    tnr: _,
                } = self.mask_projection_expr(e, &alias_map, identity)?;
                if transformed {
                    any_changed = true;
                }
                new_exprs.push(data);
            }

            // Use `try_new_with_schema` rather than `try_new` so the
            // *original* DFSchema (with its field qualifiers — e.g.
            // `Some(TableReference::Bare("users"))` for `users.email`)
            // is preserved across the rewrite. DataFusion runs a
            // per-rule invariant checker that compares output schemas
            // for compatibility; an `Expr::Alias(literal, "email")`
            // recomputes a field with qualifier `None` and trips
            // `Internal("Assertion failed: compatible: Failed due to a
            // difference in schemas")`. The mask preserves field name
            // and data type by construction (the rule's `Expr` is
            // chosen by the operator to match the masked column's
            // type), so reusing the original schema is safe.
            if any_changed {
                let new_proj = Projection::try_new_with_schema(new_exprs, input, schema)?;
                Ok(Transformed::yes(LogicalPlan::Projection(new_proj)))
            } else {
                // No change ⇒ reconstruct unchanged so input ownership
                // balances. `try_new_with_schema` is semantically a
                // no-op when the expressions match the schema.
                let proj = Projection::try_new_with_schema(new_exprs, input, schema)?;
                Ok(Transformed::no(LogicalPlan::Projection(proj)))
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use arrow::array::{Int32Array, StringArray};
    use arrow::datatypes::{DataType, Field, Schema};
    use arrow::record_batch::RecordBatch;
    use datafusion::datasource::MemTable;
    use datafusion::prelude::SessionContext;

    use super::*;

    /// Build a `SessionContext` with a `users(id INT, email TEXT)`
    /// `MemTable` containing 3 rows. Returns the context plus the
    /// fully-qualified `TableReference` the planner uses for `users`,
    /// so test rules can use the exact key shape required by strict
    /// matching.
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
        // `DataFusion`'s planner uses `TableReference::Bare` for
        // column references in unqualified queries (`SELECT email
        // FROM users`). The rule store does *strict* `Eq` matching,
        // so test rules must use the same shape. Loose matching that
        // accepts any qualifying-prefix is a Task 03 affordance once
        // the typed tag system from Architecture Decisions §10
        // lands. Until then, callers register rules against the
        // exact shape the planner emits — which for these in-memory
        // tests means `Bare`.
        let users_ref = TableReference::bare("users");
        (ctx, users_ref)
    }

    /// Build the standard mask rule: replace `users.email` with the
    /// literal `'***@example.com'`.
    fn mask_email_literal(table: &TableReference) -> ColumnMask {
        ColumnMask {
            table: table.clone(),
            column: "email".to_string(),
            mask: datafusion::prelude::lit("***@example.com"),
            org: None,
            groups: None,
        }
    }

    /// Apply an enforcer to the **unoptimized** plan for `sql` and
    /// return the rewritten `LogicalPlan`.
    ///
    /// The MVP rewrites `Projection.expr` lists. After
    /// `into_optimized_plan` runs, projection pushdown can collapse
    /// `SELECT col FROM t` into `TableScan` with `projection=[col]`
    /// and there's no `Projection` node left to walk. The real
    /// integration via `PolicyOptimizerRule` runs early in the
    /// optimizer pipeline, before pushdown — so tests should mirror
    /// that and feed the unoptimized plan.
    async fn rewrite_sql(
        ctx: &SessionContext,
        enforcer: &ColumnMaskingEnforcer,
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
    /// `Vec<String>` per row (one cell per projected column).
    /// `String` for `Int32` and `Utf8` columns; tests downcast
    /// types they care about themselves.
    async fn execute_plan(ctx: &SessionContext, plan: LogicalPlan) -> Vec<Vec<String>> {
        let df = ctx.execute_logical_plan(plan).await.expect("execute");
        let batches = df.collect().await.expect("collect");
        let mut rows: Vec<Vec<String>> = Vec::new();
        for batch in batches {
            let cols = batch.num_columns();
            for i in 0..batch.num_rows() {
                let mut cells: Vec<String> = Vec::with_capacity(cols);
                for c in 0..cols {
                    let col = batch.column(c);
                    if let Some(arr) = col.as_any().downcast_ref::<StringArray>() {
                        cells.push(arr.value(i).to_string());
                    } else if let Some(arr) = col.as_any().downcast_ref::<Int32Array>() {
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

    // ---- Tests pinning option A (mask only in projection) ----

    ///: a mask rule whose target column is absent from the
    /// table's schema can never fire — warn about the silent bypass.
    #[tokio::test]
    async fn mask_rule_for_absent_column_warns_unfireable() {
        let (ctx, users) = ctx_with_users();
        // `users` has (id, email); this rule targets a typo'd column.
        let enforcer = ColumnMaskingEnforcer::new([ColumnMask {
            table: users.clone(),
            column: "emial".to_string(),
            mask: datafusion::prelude::lit("***"),
            org: None,
            groups: None,
        }])
        .expect("build enforcer");

        let plan = ctx
            .sql("SELECT id FROM users")
            .await
            .expect("plan SQL")
            .logical_plan()
            .clone();

        let logged = crate::audit::test_capture::capture_logs(|| {
            enforcer
                .rewrite(plan, &crate::Identity::anonymous())
                .expect("rewrite succeeds");
        });

        assert!(
            logged.contains("mask_rule_unfireable"),
            "expected an unfireable-mask warn: {logged}"
        );
        assert!(
            logged.contains("emial"),
            "warn should name the absent column: {logged}"
        );
    }

    ///: the unfireable check must NOT fire for a rule whose
    /// column exists in the table — even when the query doesn't select
    /// it (the column is present in the schema, so the rule *can* fire).
    #[tokio::test]
    async fn mask_rule_for_present_column_does_not_warn_unfireable() {
        let (ctx, users) = ctx_with_users();
        let enforcer =
            ColumnMaskingEnforcer::new([mask_email_literal(&users)]).expect("build enforcer");

        // Deliberately does not select `email`; it still exists in the
        // schema, so this is a legitimate no-op, not a misconfiguration.
        let plan = ctx
            .sql("SELECT id FROM users")
            .await
            .expect("plan SQL")
            .logical_plan()
            .clone();

        let logged = crate::audit::test_capture::capture_logs(|| {
            enforcer
                .rewrite(plan, &crate::Identity::anonymous())
                .expect("rewrite succeeds");
        });

        assert!(
            !logged.contains("mask_rule_unfireable"),
            "email exists in the table — must not warn: {logged}"
        );
    }

    #[tokio::test]
    async fn column_mask_replaces_simple_select() {
        let (ctx, users) = ctx_with_users();
        let enforcer = ColumnMaskingEnforcer::new([mask_email_literal(&users)]).expect("build");
        let plan = rewrite_sql(&ctx, &enforcer, "SELECT email FROM users").await;
        let rows = execute_plan(&ctx, plan).await;
        assert_eq!(rows.len(), 3, "all 3 users still returned");
        for row in &rows {
            assert_eq!(row[0], "***@example.com");
        }
    }

    #[tokio::test]
    async fn column_mask_with_no_matching_rule_is_identity() {
        let (ctx, _users) = ctx_with_users();
        // Rule on a different schema's `users.email` — strict
        // matching means it should NOT trigger.
        let other = TableReference::full("datafusion", "private", "users");
        let enforcer = ColumnMaskingEnforcer::new([mask_email_literal(&other)]).expect("build");
        let plan_in = ctx
            .sql("SELECT email FROM users")
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
    async fn column_mask_preserves_other_columns() {
        let (ctx, users) = ctx_with_users();
        let enforcer = ColumnMaskingEnforcer::new([mask_email_literal(&users)]).expect("build");
        let plan = rewrite_sql(&ctx, &enforcer, "SELECT id, email FROM users ORDER BY id").await;
        let rows = execute_plan(&ctx, plan).await;
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0][0], "1");
        assert_eq!(rows[1][0], "2");
        assert_eq!(rows[2][0], "3");
        for row in &rows {
            assert_eq!(row[1], "***@example.com");
        }
    }

    #[tokio::test]
    async fn column_mask_filter_evaluates_on_real_data() {
        // Pins option A: predicates evaluate against the *original*
        // column values, the projection returns the masked literal.
        let (ctx, users) = ctx_with_users();
        let enforcer = ColumnMaskingEnforcer::new([mask_email_literal(&users)]).expect("build");
        let plan = rewrite_sql(
            &ctx,
            &enforcer,
            "SELECT email FROM users WHERE email = 'alice@example.com'",
        )
        .await;
        let rows = execute_plan(&ctx, plan).await;
        // Predicate sees real data ⇒ exactly the alice row matches.
        assert_eq!(rows.len(), 1, "filter on real data returns 1 row");
        // Projection returns masked value.
        assert_eq!(rows[0][0], "***@example.com");
    }

    #[tokio::test]
    async fn column_mask_table_ref_qualified() {
        // Strict matching: a rule on `private.users.email` must not
        // mask `public.users.email`.
        let (ctx, _users) = ctx_with_users();
        let other = TableReference::full("datafusion", "private", "users");
        let enforcer = ColumnMaskingEnforcer::new([mask_email_literal(&other)]).expect("build");
        let plan = rewrite_sql(&ctx, &enforcer, "SELECT email FROM users").await;
        let rows = execute_plan(&ctx, plan).await;
        assert_eq!(rows.len(), 3);
        // Original values flow through unchanged.
        let emails: Vec<&str> = rows.iter().map(|r| r[0].as_str()).collect();
        assert!(emails.contains(&"alice@example.com"));
        assert!(emails.contains(&"bob@example.com"));
        assert!(emails.contains(&"carol@example.com"));
    }

    #[tokio::test]
    async fn column_mask_via_optimizer_rule_adapter() {
        // Drives the rewrite through the existing `PolicyOptimizerRule`
        // adapter — proves the integration point Phase 1 wires into
        // `SessionStateBuilder` works with a real enforcer.
        use crate::PolicyOptimizerRule;
        use datafusion::optimizer::{OptimizerContext, OptimizerRule};

        let (ctx, users) = ctx_with_users();
        let enforcer =
            Arc::new(ColumnMaskingEnforcer::new([mask_email_literal(&users)]).expect("build"));
        let rule = PolicyOptimizerRule::new(enforcer);
        // Drive the unoptimized logical plan — the same point the
        // real `PolicyOptimizerRule` integration sees during the
        // optimizer pipeline, before projection pushdown collapses
        // simple `SELECT col FROM t` into a `TableScan` with a baked
        // projection (and no `Projection` node left to walk).
        let plan = ctx
            .sql("SELECT email FROM users")
            .await
            .expect("plan")
            .logical_plan()
            .clone();
        let cfg = OptimizerContext::default();
        let out = rule.rewrite(plan, &cfg).expect("rule rewrite");
        assert!(out.transformed, "rule must report Transformed::yes");
    }

    #[tokio::test]
    async fn column_mask_empty_enforcer_is_noop_equivalent() {
        let (ctx, _users) = ctx_with_users();
        let enforcer = ColumnMaskingEnforcer::empty();
        assert_eq!(enforcer.rule_count(), 0);
        let plan_in = ctx
            .sql("SELECT email FROM users")
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

    // ---- Construction-error tests ----

    #[test]
    fn duplicate_rules_rejected_at_construction() {
        let table = TableReference::full("datafusion", "public", "users");
        let one = ColumnMask {
            table: table.clone(),
            column: "email".to_string(),
            mask: datafusion::prelude::lit("***"),
            org: None,
            groups: None,
        };
        let two = ColumnMask {
            table,
            column: "email".to_string(),
            mask: datafusion::prelude::lit("xxx"),
            org: None,
            groups: None,
        };
        let err = ColumnMaskingEnforcer::new([one, two]).expect_err("must error");
        match err {
            BuildError::DuplicateRule { column, .. } => {
                assert_eq!(column, "email");
            }
        }
    }

    #[test]
    fn rules_on_distinct_columns_coexist() {
        let table = TableReference::full("datafusion", "public", "users");
        let email_mask = ColumnMask {
            table: table.clone(),
            column: "email".to_string(),
            mask: datafusion::prelude::lit("***"),
            org: None,
            groups: None,
        };
        let id_mask = ColumnMask {
            table,
            column: "id".to_string(),
            mask: datafusion::prelude::lit(0i32),
            org: None,
            groups: None,
        };
        let enforcer = ColumnMaskingEnforcer::new([email_mask, id_mask]).expect("distinct cols ok");
        assert_eq!(enforcer.rule_count(), 2);
    }

    /// Register `users(id, email)` + `orders(id, user_id, amount)` so
    /// tests can exercise joins. Mirrors the demo stack's shape
    /// (`pg.public.users` + `pg_orders.public.orders`) without the
    /// federation indirection.
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

    /// `SELECT u.email FROM users u` — the column reference at the
    /// projection level is `Bare("u").email`, NOT `Bare("users").email`.
    /// Strict `TableReference` equality would miss the rule on
    /// `users`; the alias-resolution fallback must catch it.
    ///
    /// Regression for the cross-source-join bug discovered while
    /// verifying the testbench's "Cross-source join" example
    /// (PR #349 follow-up).
    #[tokio::test]
    async fn column_mask_resolves_simple_alias() {
        let (ctx, users) = ctx_with_users();
        let enforcer = ColumnMaskingEnforcer::new([mask_email_literal(&users)]).expect("build");
        let plan = rewrite_sql(&ctx, &enforcer, "SELECT u.email FROM users u").await;
        let rows = execute_plan(&ctx, plan).await;
        assert_eq!(rows.len(), 3, "all 3 rows still flow through");
        for r in &rows {
            assert_eq!(
                r[0], "***@example.com",
                "aliased projection must still be masked, got {r:?}"
            );
        }
    }

    /// `SELECT u.email FROM users u JOIN orders o ON u.id = o.user_id`
    /// — the cross-source-join shape that surfaced the bug. The mask
    /// on `users.email` must fire for `u.email` projections produced
    /// by the join too; the row-count is driven by the join (one row
    /// per matching order).
    #[tokio::test]
    async fn column_mask_resolves_alias_in_join() {
        let (ctx, users) = ctx_with_users_and_orders();
        let enforcer = ColumnMaskingEnforcer::new([mask_email_literal(&users)]).expect("build");
        let plan = rewrite_sql(
            &ctx,
            &enforcer,
            "SELECT u.email, o.amount \
             FROM users u \
             JOIN orders o ON u.id = o.user_id \
             ORDER BY o.amount",
        )
        .await;
        let rows = execute_plan(&ctx, plan).await;
        assert_eq!(rows.len(), 4, "one row per order");
        for r in &rows {
            assert_eq!(
                r[0], "***@example.com",
                "joined u.email must be masked, got {r:?}"
            );
        }
    }

    /// The alias fallback is a fallback only — a rule that uses the
    /// alias as the table reference must STILL not match the source
    /// table directly. Otherwise loose matching reopens the
    /// cross-catalog collision risk the strict-equality contract was
    /// designed to prevent.
    #[tokio::test]
    async fn column_mask_alias_fallback_is_one_directional() {
        let (ctx, _users) = ctx_with_users();
        // Rule on `u` (an alias) — there's no actual `u` table.
        let rule_on_alias = ColumnMask {
            table: TableReference::bare("u"),
            column: "email".to_string(),
            mask: datafusion::prelude::lit("***@example.com"),
            org: None,
            groups: None,
        };
        let enforcer = ColumnMaskingEnforcer::new([rule_on_alias]).expect("build");
        // Unaliased query: column relation is `users`, alias map
        // doesn't contain `users` → no match → no mask.
        let plan = rewrite_sql(&ctx, &enforcer, "SELECT email FROM users").await;
        let rows = execute_plan(&ctx, plan).await;
        let emails: Vec<&str> = rows.iter().map(|r| r[0].as_str()).collect();
        assert!(
            emails.contains(&"alice@example.com"),
            "rule keyed on an alias must NOT mask unaliased references, got {emails:?}"
        );
    }

    /// Regression for: a mask registered on the **bare** `users` must
    /// apply whether the query references the table bare, schema-qualified,
    /// or fully-qualified — qualifying a table name cannot dodge the mask.
    #[tokio::test]
    async fn column_mask_fires_regardless_of_reference_qualification() {
        let (ctx, table) = ctx_with_users(); // bare("users")
        let enforcer = ColumnMaskingEnforcer::new([mask_email_literal(&table)]).expect("build");
        for sql in [
            "SELECT id, email FROM users",
            "SELECT id, email FROM public.users",
            "SELECT id, email FROM datafusion.public.users",
        ] {
            let plan = rewrite_sql(&ctx, &enforcer, sql).await;
            let rows = execute_plan(&ctx, plan).await;
            assert!(
                !rows.is_empty() && rows.iter().all(|r| r[1] == "***@example.com"),
                "mask should apply for `{sql}` — got {rows:?}",
            );
        }
    }

    ///  upgrade direction: a *fully-qualified* mask
    /// (`datafusion.public.users.email`) must fire on a *bare*-written
    /// query (`SELECT email FROM users`) once the enforcer carries the
    /// session defaults that the bare reference resolves to. This is
    /// the inverse of `match_candidates`' downgrade and is what makes
    /// collision-safe full-qualified propagated masks enforceable.
    #[tokio::test]
    async fn full_qualified_mask_matches_bare_query_with_session_defaults() {
        let (ctx, _) = ctx_with_users();
        let mask = ColumnMask {
            table: TableReference::full("datafusion", "public", "users"),
            column: "email".to_string(),
            mask: datafusion::prelude::lit("***@example.com"),
            org: None,
            groups: None,
        };
        let enforcer = ColumnMaskingEnforcer::new([mask])
            .expect("build")
            .with_session_defaults("datafusion", "public");
        for sql in [
            "SELECT id, email FROM users",
            "SELECT id, email FROM public.users",
            "SELECT id, email FROM datafusion.public.users",
        ] {
            let plan = rewrite_sql(&ctx, &enforcer, sql).await;
            let rows = execute_plan(&ctx, plan).await;
            assert!(
                !rows.is_empty() && rows.iter().all(|r| r[1] == "***@example.com"),
                "full mask should fire on `{sql}` with session defaults — got {rows:?}",
            );
        }
    }

    ///: `explain` must mirror `rewrite`. A fully-qualified propagated
    /// mask (`datafusion.public.users`) has to be *reported* as applied for a
    /// bare-written query that resolves to the session defaults — the
    /// `/policy/explain` diagnostic previously used the downgrade-only
    /// matcher and under-reported (said "not masked" for a query `rewrite`
    /// actually masks). Pairs with the rewrite test above.
    #[tokio::test]
    async fn explain_reports_full_mask_for_bare_query_with_session_defaults() {
        let (ctx, _) = ctx_with_users();
        let full_mask = || ColumnMask {
            table: TableReference::full("datafusion", "public", "users"),
            column: "email".to_string(),
            mask: datafusion::prelude::lit("***@example.com"),
            org: None,
            groups: None,
        };
        let bare_plan = ctx
            .sql("SELECT id, email FROM users")
            .await
            .unwrap()
            .logical_plan()
            .clone();

        // With session defaults: explain reports the propagated full mask.
        let enforcer = ColumnMaskingEnforcer::new([full_mask()])
            .expect("build")
            .with_session_defaults("datafusion", "public");
        let decisions = enforcer.explain(&bare_plan, &crate::Identity::anonymous());
        assert!(
            decisions.iter().any(|d| d.resource.contains("email")),
            "explain must report the full-qualified propagated mask on a bare query — got {decisions:?}",
        );

        // Control: without session defaults the upgrade is inert, so explain
        // (like rewrite) does not report it — pins the fix is driven by
        // `candidate_refs` + session defaults, not an always-on change.
        let no_defaults = ColumnMaskingEnforcer::new([full_mask()]).expect("build");
        assert!(
            no_defaults
                .explain(&bare_plan, &crate::Identity::anonymous())
                .is_empty(),
            "without session defaults, explain must not report a full mask for a bare query",
        );
    }

    /// Precedence ( / #480): when both a fully-qualified mask and a
    /// bare mask target the same column, the *more-qualified* rule must win
    /// for a bare query that resolves to the session defaults — not the bare
    /// one. Guards the candidate ordering (`candidate_refs` puts upgraded
    /// candidates first).
    #[tokio::test]
    async fn full_qualified_mask_outranks_bare_mask_for_bare_query() {
        let (ctx, _) = ctx_with_users();
        let full = ColumnMask {
            table: TableReference::full("datafusion", "public", "users"),
            column: "email".to_string(),
            mask: datafusion::prelude::lit("FULL"),
            org: None,
            groups: None,
        };
        let bare = ColumnMask {
            table: TableReference::bare("users"),
            column: "email".to_string(),
            mask: datafusion::prelude::lit("BARE"),
            org: None,
            groups: None,
        };
        let enforcer = ColumnMaskingEnforcer::new([full, bare])
            .expect("build")
            .with_session_defaults("datafusion", "public");
        let plan = rewrite_sql(&ctx, &enforcer, "SELECT id, email FROM users").await;
        let rows = execute_plan(&ctx, plan).await;
        assert!(
            !rows.is_empty() && rows.iter().all(|r| r[1] == "FULL"),
            "fully-qualified mask must outrank the bare mask — got {rows:?}",
        );
    }

    /// Control: without session defaults the upgrade is inert, so a
    /// fully-qualified mask does *not* match a bare query — pins that
    /// the new matching is opt-in and the upgrade candidates are
    /// what enable it (no silent always-on behaviour change).
    #[tokio::test]
    async fn full_qualified_mask_does_not_match_bare_query_without_defaults() {
        let (ctx, _) = ctx_with_users();
        let mask = ColumnMask {
            table: TableReference::full("datafusion", "public", "users"),
            column: "email".to_string(),
            mask: datafusion::prelude::lit("***@example.com"),
            org: None,
            groups: None,
        };
        let enforcer = ColumnMaskingEnforcer::new([mask]).expect("build");
        let plan = rewrite_sql(&ctx, &enforcer, "SELECT id, email FROM users").await;
        let rows = execute_plan(&ctx, plan).await;
        assert!(
            !rows.is_empty() && rows.iter().all(|r| r[1] != "***@example.com"),
            "without session defaults a full mask must not match a bare query — got {rows:?}",
        );
    }

    /// Every mask decision emits a `dataglot::audit` event carrying the
    /// session identity and the masked resource — the mask-side half of
    /// the audit-completeness follow-up to deny auditing (Ranger parity).
    #[tokio::test]
    async fn mask_decision_is_audited_with_identity() {
        let (ctx, users) = ctx_with_users();
        let enforcer =
            ColumnMaskingEnforcer::new([mask_email_literal(&users)]).expect("build enforcer");
        let df = ctx.sql("SELECT email FROM users").await.expect("plan SQL");
        let plan = df.logical_plan().clone();

        let identity = crate::Identity::user("alice").with_groups(["analyst"]);
        let logged = crate::audit::test_capture::capture_logs(|| {
            enforcer.rewrite(plan, &identity).expect("rewrite succeeds");
        });

        assert!(logged.contains("dataglot::audit"), "target: {logged}");
        assert!(logged.contains("mask"), "action: {logged}");
        assert!(logged.contains("users.email"), "resource: {logged}");
        assert!(logged.contains("alice"), "user: {logged}");
    }

    // ----  F4: per-org (tenant-scoped) mask isolation ----

    /// Build the acme-scoped email mask (`org = Some("acme")`).
    fn acme_email_mask(table: &TableReference) -> ColumnMask {
        ColumnMask {
            table: table.clone(),
            column: "email".to_string(),
            mask: datafusion::prelude::lit("***@example.com"),
            org: Some("acme".to_string()),
            groups: None,
        }
    }

    /// **The core cross-tenant isolation guarantee.** A mask created under
    /// org `acme` (`org = Some("acme")`) masks the column for an `acme`
    /// session, and does NOT mask it for a `beta` session, and does NOT
    /// mask it for an anonymous (no-org) session.
    #[tokio::test]
    async fn tenant_mask_only_fires_for_its_own_org() {
        let (ctx, users) = ctx_with_users();
        let enforcer = ColumnMaskingEnforcer::new([acme_email_mask(&users)]).expect("build");

        // acme session → masked.
        let plan = ctx
            .sql("SELECT email FROM users")
            .await
            .expect("plan")
            .logical_plan()
            .clone();
        let acme = crate::Identity::user("a").with_org("acme");
        let plan = enforcer.rewrite(plan, &acme).expect("rewrite").data;
        let rows = execute_plan(&ctx, plan).await;
        assert!(
            rows.iter().all(|r| r[0] == "***@example.com"),
            "acme session must see the acme mask; got {rows:?}"
        );

        // beta session → NOT masked (real values flow through).
        let plan = ctx
            .sql("SELECT email FROM users")
            .await
            .expect("plan")
            .logical_plan()
            .clone();
        let beta = crate::Identity::user("b").with_org("beta");
        let out = enforcer.rewrite(plan, &beta).expect("rewrite");
        assert!(
            !out.transformed,
            "a beta session must not be touched by an acme-scoped mask"
        );
        let rows = execute_plan(&ctx, out.data).await;
        let emails: Vec<&str> = rows.iter().map(|r| r[0].as_str()).collect();
        assert!(
            emails.contains(&"alice@example.com"),
            "beta must see real emails, not the acme mask; got {emails:?}"
        );

        // anonymous session → NOT masked either.
        let plan = ctx
            .sql("SELECT email FROM users")
            .await
            .expect("plan")
            .logical_plan()
            .clone();
        let out = enforcer
            .rewrite(plan, &crate::Identity::anonymous())
            .expect("rewrite");
        assert!(
            !out.transformed,
            "an anonymous session must not be touched by an acme-scoped mask"
        );
    }

    // ----: group/role-scoped mask conditioning ----

    /// A **group-scoped** mask (`groups = Some(["support"])`) masks the column
    /// for a session in that group and leaves it clear for a session in a
    /// different group — the per-role divergence slide 11 requires. Proven
    /// end-to-end: the plan is rewritten *and executed*, and the actual row
    /// values are asserted.
    #[tokio::test]
    async fn group_scoped_mask_only_fires_for_matching_group() {
        let (ctx, users) = ctx_with_users();
        let support_mask = ColumnMask {
            table: users.clone(),
            column: "email".to_string(),
            mask: datafusion::prelude::lit("***@example.com"),
            org: None,
            groups: Some(vec![crate::OrgGroupId::new("support")]),
        };
        let enforcer = ColumnMaskingEnforcer::new([support_mask]).expect("build");

        // In-group session → masked.
        let plan = ctx
            .sql("SELECT email FROM users")
            .await
            .expect("plan")
            .logical_plan()
            .clone();
        let support = crate::Identity::user("s").with_groups(["support"]);
        let plan = enforcer.rewrite(plan, &support).expect("rewrite").data;
        let rows = execute_plan(&ctx, plan).await;
        assert!(
            rows.iter().all(|r| r[0] == "***@example.com"),
            "a support-group session must see the mask; got {rows:?}"
        );

        // Different-group session → NOT masked (real values flow through).
        let plan = ctx
            .sql("SELECT email FROM users")
            .await
            .expect("plan")
            .logical_plan()
            .clone();
        let finance = crate::Identity::user("f").with_groups(["finance"]);
        let out = enforcer.rewrite(plan, &finance).expect("rewrite");
        assert!(
            !out.transformed,
            "a finance-group session must not be touched by a support-scoped mask"
        );
        let rows = execute_plan(&ctx, out.data).await;
        let emails: Vec<&str> = rows.iter().map(|r| r[0].as_str()).collect();
        assert!(
            emails.contains(&"alice@example.com"),
            "finance must see real emails, not the support mask; got {emails:?}"
        );
    }

    /// Precedence: when a group-scoped mask and an all-groups mask both cover
    /// the same column, the **group-scoped** one wins for a matching session
    /// (`applicable_rank` ranks group-scoped above all-groups).
    #[tokio::test]
    async fn group_scoped_mask_takes_precedence_over_all_groups() {
        let (ctx, users) = ctx_with_users();
        let all_groups = ColumnMask {
            table: users.clone(),
            column: "email".to_string(),
            mask: datafusion::prelude::lit("ALL@example.com"),
            org: None,
            groups: None,
        };
        let support = ColumnMask {
            table: users.clone(),
            column: "email".to_string(),
            mask: datafusion::prelude::lit("GRP@example.com"),
            org: None,
            groups: Some(vec![crate::OrgGroupId::new("support")]),
        };
        let enforcer = ColumnMaskingEnforcer::new([all_groups, support]).expect("build");

        let plan = ctx
            .sql("SELECT email FROM users")
            .await
            .expect("plan")
            .logical_plan()
            .clone();
        let id = crate::Identity::user("s").with_groups(["support"]);
        let plan = enforcer.rewrite(plan, &id).expect("rewrite").data;
        let rows = execute_plan(&ctx, plan).await;
        assert!(
            rows.iter().all(|r| r[0] == "GRP@example.com"),
            "the group-scoped mask must win for a matching session; got {rows:?}"
        );
    }

    /// A **config** mask (`org = None`) is operator-wide: it applies to
    /// acme, beta, and anonymous alike — the F1–F3 single-org behaviour is
    /// preserved byte-for-byte.
    #[tokio::test]
    async fn operator_wide_mask_applies_to_every_org() {
        let (ctx, users) = ctx_with_users();
        // `mask_email_literal` builds an `org = None` (operator-wide) rule.
        let enforcer = ColumnMaskingEnforcer::new([mask_email_literal(&users)]).expect("build");

        for identity in [
            crate::Identity::user("a").with_org("acme"),
            crate::Identity::user("b").with_org("beta"),
            crate::Identity::anonymous(),
        ] {
            let plan = ctx
                .sql("SELECT email FROM users")
                .await
                .expect("plan")
                .logical_plan()
                .clone();
            let plan = enforcer.rewrite(plan, &identity).expect("rewrite").data;
            let rows = execute_plan(&ctx, plan).await;
            assert!(
                rows.iter().all(|r| r[0] == "***@example.com"),
                "operator-wide mask must apply for {identity:?}; got {rows:?}"
            );
        }
    }

    /// Two tenants can register a mask on the **same** `(table, column)`;
    /// each session sees only its own tenant's mask, and a tenant-scoped
    /// rule outranks a coexisting operator-wide rule on the same key.
    #[tokio::test]
    async fn distinct_tenants_and_operator_wide_coexist_on_same_key() {
        let (ctx, users) = ctx_with_users();
        let acme = ColumnMask {
            table: users.clone(),
            column: "email".to_string(),
            mask: datafusion::prelude::lit("ACME"),
            org: Some("acme".to_string()),
            groups: None,
        };
        let beta = ColumnMask {
            table: users.clone(),
            column: "email".to_string(),
            mask: datafusion::prelude::lit("BETA"),
            org: Some("beta".to_string()),
            groups: None,
        };
        let wide = ColumnMask {
            table: users.clone(),
            column: "email".to_string(),
            mask: datafusion::prelude::lit("WIDE"),
            org: None,
            groups: None,
        };
        // Distinct orgs on the same key are NOT duplicates.
        let enforcer =
            ColumnMaskingEnforcer::new([acme, beta, wide]).expect("distinct-org rules coexist");
        assert_eq!(enforcer.rule_count(), 3);

        let cases = [
            (crate::Identity::user("x").with_org("acme"), "ACME"),
            (crate::Identity::user("y").with_org("beta"), "BETA"),
            // A third org falls back to the operator-wide rule.
            (crate::Identity::user("z").with_org("gamma"), "WIDE"),
            // Anonymous also sees only the operator-wide rule.
            (crate::Identity::anonymous(), "WIDE"),
        ];
        for (identity, expected) in cases {
            let plan = ctx
                .sql("SELECT email FROM users")
                .await
                .expect("plan")
                .logical_plan()
                .clone();
            let plan = enforcer.rewrite(plan, &identity).expect("rewrite").data;
            let rows = execute_plan(&ctx, plan).await;
            assert!(
                rows.iter().all(|r| r[0] == expected),
                "identity {identity:?} must see {expected}; got {rows:?}"
            );
        }
    }

    /// Rewrite the unoptimized plan for `sql` under an explicit `identity`
    /// (the [`rewrite_sql`] helper hardcodes anonymous). Used by the
    /// cross-qualification tiebreak regression below.
    async fn rewrite_sql_as(
        ctx: &SessionContext,
        enforcer: &ColumnMaskingEnforcer,
        sql: &str,
        identity: &crate::Identity,
    ) -> LogicalPlan {
        let df = ctx.sql(sql).await.expect("plan SQL");
        let plan = df.logical_plan().clone();
        enforcer.rewrite(plan, identity).expect("rewrite").data
    }

    /// **Cross-tenant tiebreak regression (`CodeRabbit` "Major", mask side).**
    /// When an operator-wide mask sits under one qualification
    /// (`datafusion.public.users.email`) and a matching tenant mask under
    /// another (bare `users.email`) on the same logical column, the
    /// **tenant** mask must win for the tenant session — even though the
    /// operator-wide rule sits at an *earlier* (more-qualified) candidate.
    /// Before the across-all-candidates fix, `lookup_mask` returned on the
    /// first candidate that yielded *an* applicable mask, so the operator-wide
    /// rule shadowed the tenant rule ("tenant wins" violated).
    #[tokio::test]
    async fn tenant_mask_wins_over_operator_wide_under_other_qualification() {
        let (ctx, _users) = ctx_with_users();
        let enforcer = ColumnMaskingEnforcer::new([
            // Operator-wide mask, keyed on the FULLY-qualified table (earlier
            // candidate in the downgrade chain).
            ColumnMask {
                table: TableReference::full("datafusion", "public", "users"),
                column: "email".to_string(),
                mask: datafusion::prelude::lit("WIDE"),
                org: None,
                groups: None,
            },
            // acme tenant mask, keyed on the BARE table (later candidate).
            ColumnMask {
                table: TableReference::bare("users"),
                column: "email".to_string(),
                mask: datafusion::prelude::lit("ACME"),
                org: Some("acme".to_string()),
                groups: None,
            },
        ])
        .expect("build");

        // (b) The acme session must see its tenant mask, not the operator-wide
        // one at the earlier candidate — tenant wins across all candidates.
        let acme = crate::Identity::user("a").with_org("acme");
        let plan = rewrite_sql_as(
            &ctx,
            &enforcer,
            "SELECT email FROM datafusion.public.users",
            &acme,
        )
        .await;
        let rows = execute_plan(&ctx, plan).await;
        assert!(
            rows.iter().all(|r| r[0] == "ACME"),
            "acme session must see the tenant mask, not the operator-wide one; got {rows:?}"
        );

        // (a) A non-tenant (beta) session falls back to the operator-wide mask.
        let beta = crate::Identity::user("b").with_org("beta");
        let plan = rewrite_sql_as(
            &ctx,
            &enforcer,
            "SELECT email FROM datafusion.public.users",
            &beta,
        )
        .await;
        let rows = execute_plan(&ctx, plan).await;
        assert!(
            rows.iter().all(|r| r[0] == "WIDE"),
            "non-tenant session must fall back to the operator-wide mask; got {rows:?}"
        );
    }

    /// Same `(table, column, org)` twice is still a `DuplicateRule` error —
    /// the org dimension narrows the uniqueness key, it doesn't remove it.
    #[test]
    fn same_table_column_org_is_still_duplicate() {
        let table = TableReference::bare("users");
        let a = ColumnMask {
            table: table.clone(),
            column: "email".to_string(),
            mask: datafusion::prelude::lit("***"),
            org: Some("acme".to_string()),
            groups: None,
        };
        let b = ColumnMask {
            table,
            column: "email".to_string(),
            mask: datafusion::prelude::lit("xxx"),
            org: Some("acme".to_string()),
            groups: None,
        };
        let err = ColumnMaskingEnforcer::new([a, b]).expect_err("same org+key duplicates");
        match err {
            BuildError::DuplicateRule { column, .. } => assert_eq!(column, "email"),
        }
    }

    // ----  follow-up: masking descends into expression subqueries ----

    /// Whether `needle` appears in the Debug of any subquery plan embedded in
    /// `plan`'s expressions, to any depth. `Subquery`'s own Debug collapses to
    /// `<subquery>`, so we pull each embedded `Arc<LogicalPlan>` out and render
    /// *it* (whose projection shows the injected mask literal) — recursing for
    /// deeper nesting. This is how tests observe a mask `Expr` injected inside a
    /// subquery whose value never reaches the output (IN / ANY / EXISTS).
    fn any_subquery_plan_contains(plan: &LogicalPlan, needle: &str) -> bool {
        use datafusion::common::tree_node::{TreeNode, TreeNodeRecursion};
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

    /// (a) A masked column read through a **scalar subquery** in the projection
    /// returns the masked value — the enforcer descends into the embedded plan
    /// and masks its projection, so the outer scalar is the mask literal.
    #[tokio::test]
    async fn mask_applies_inside_scalar_subquery_projection() {
        let (ctx, users) = ctx_with_users();
        let enforcer = ColumnMaskingEnforcer::new([mask_email_literal(&users)]).expect("build");
        let plan = rewrite_sql(
            &ctx,
            &enforcer,
            "SELECT (SELECT email FROM users LIMIT 1) AS e",
        )
        .await;
        assert!(
            any_subquery_plan_contains(&plan, "***@example.com"),
            "scalar subquery's email must be masked in the plan: {plan:?}"
        );
        let rows = execute_plan(&ctx, plan).await;
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0][0], "***@example.com",
            "scalar subquery must return the masked value; got {rows:?}"
        );
    }

    /// (b) `IN (subquery)`: the subquery projecting the masked column is
    /// rewritten to the mask literal. Observable effect — the outer (un-masked,
    /// predicate-position) email can no longer be `IN` a set of masked
    /// literals, so the row set collapses; without descent all 3 rows match.
    #[tokio::test]
    async fn mask_applies_inside_in_subquery() {
        let (ctx, users) = ctx_with_users();
        let enforcer = ColumnMaskingEnforcer::new([mask_email_literal(&users)]).expect("build");
        let plan = rewrite_sql(
            &ctx,
            &enforcer,
            "SELECT id FROM users WHERE email IN (SELECT email FROM users)",
        )
        .await;
        assert!(
            any_subquery_plan_contains(&plan, "***@example.com"),
            "IN-subquery email must be masked in the plan: {plan:?}"
        );
        let rows = execute_plan(&ctx, plan).await;
        assert!(
            rows.is_empty(),
            "real outer email is not IN a set of masked literals ⇒ 0 rows; got {rows:?}"
        );
    }

    /// (c) `= ANY (subquery)` — the `SetComparison` variant, the fourth
    /// subquery-bearing `Expr`. Assert on the plan (like EXISTS): the mask is
    /// injected into the `SetComparison` subquery. We deliberately do **not**
    /// assert on executed row-count — the subquery's column is never projected
    /// to the output of a `WHERE … = ANY` (so no data leak), and this fork's
    /// `SetComparison` decorrelation is immature (it degenerates to an EXISTS-
    /// like mark even for the unmasked query), which would make a row-count
    /// assertion test the optimizer, not the mask.
    #[tokio::test]
    async fn mask_applies_inside_any_subquery() {
        let (ctx, users) = ctx_with_users();
        let enforcer = ColumnMaskingEnforcer::new([mask_email_literal(&users)]).expect("build");
        let plan = rewrite_sql(
            &ctx,
            &enforcer,
            "SELECT id FROM users WHERE email = ANY (SELECT email FROM users)",
        )
        .await;
        assert!(
            any_subquery_plan_contains(&plan, "***@example.com"),
            "= ANY subquery email must be masked in the plan: {plan:?}"
        );
    }

    /// (d) `EXISTS (subquery)`: the masked value never reaches the output (EXISTS
    /// only checks non-emptiness), so assert on the plan — the mask `Expr` is
    /// injected into the EXISTS subquery's projection.
    #[tokio::test]
    async fn mask_applies_inside_exists_subquery() {
        let (ctx, users) = ctx_with_users();
        let enforcer = ColumnMaskingEnforcer::new([mask_email_literal(&users)]).expect("build");
        let plan = rewrite_sql(
            &ctx,
            &enforcer,
            "SELECT id FROM users u \
             WHERE EXISTS (SELECT email FROM users WHERE email = 'alice@example.com')",
        )
        .await;
        assert!(
            any_subquery_plan_contains(&plan, "***@example.com"),
            "EXISTS subquery's projected email must be masked in the plan: {plan:?}"
        );
    }

    /// (e) A **nested** subquery (scalar inside scalar): the recursion reaches
    /// the innermost `users` scan at depth 2 and masks it.
    #[tokio::test]
    async fn mask_applies_inside_nested_subquery() {
        let (ctx, users) = ctx_with_users();
        let enforcer = ColumnMaskingEnforcer::new([mask_email_literal(&users)]).expect("build");
        let plan = rewrite_sql(
            &ctx,
            &enforcer,
            "SELECT (SELECT (SELECT email FROM users LIMIT 1)) AS e",
        )
        .await;
        assert!(
            any_subquery_plan_contains(&plan, "***@example.com"),
            "doubly-nested subquery email must be masked in the plan: {plan:?}"
        );
        let rows = execute_plan(&ctx, plan).await;
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0][0], "***@example.com",
            "nested subquery must return the masked value; got {rows:?}"
        );
    }

    /// **Correlated** subquery: the subquery's *own* scan (`users.email`) is
    /// masked, while the outer reference (`orders.user_id`, an
    /// `OuterReferenceColumn` belonging to the parent) is left untouched. We
    /// assert on the plan — a `LIMIT`-correlated scalar subquery is not
    /// decorrelatable by DataFusion, but the governance rewrite runs on the
    /// logical plan regardless: the mask literal is injected inside the
    /// subquery, and the correlation (`OuterReferenceColumn`) survives, proving
    /// `outer_ref_columns` was preserved and the outer ref was never masked.
    #[tokio::test]
    async fn mask_applies_inside_correlated_subquery_but_not_outer_ref() {
        let (ctx, users) = ctx_with_users_and_orders();
        // Mask the subquery's own column only; no rule on `orders`.
        let enforcer = ColumnMaskingEnforcer::new([mask_email_literal(&users)]).expect("build");
        let plan = rewrite_sql(
            &ctx,
            &enforcer,
            "SELECT o.id, \
             (SELECT email FROM users WHERE users.id = o.user_id LIMIT 1) AS em \
             FROM orders o",
        )
        .await;
        // The subquery's own scan (users.email) is masked.
        assert!(
            any_subquery_plan_contains(&plan, "***@example.com"),
            "correlated subquery's own email must be masked; got {plan:?}"
        );
        // The outer reference survives as an OuterReferenceColumn — the
        // correlation is intact (outer_ref_columns preserved) and the outer ref
        // was not turned into a mask literal.
        assert!(
            any_subquery_plan_contains(&plan, "OuterReferenceColumn"),
            "correlated outer ref must be preserved untouched in the subquery; got {plan:?}"
        );
    }

    /// No applicable rule ⇒ the subquery descent is a strict no-op: a query
    /// whose only column lives inside a subquery, with a rule on a *different*
    /// table, must report `Transformed::no`.
    #[tokio::test]
    async fn subquery_descent_is_noop_without_applicable_rule() {
        let (ctx, _users) = ctx_with_users();
        let other = TableReference::full("datafusion", "private", "users");
        let enforcer = ColumnMaskingEnforcer::new([mask_email_literal(&other)]).expect("build");
        let plan_in = ctx
            .sql("SELECT (SELECT email FROM users LIMIT 1) AS e")
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

    /// `explain` must agree with `rewrite`: a mask that fires only inside a
    /// subquery is now *reported* (previously `collect_plan_columns` walked the
    /// main tree only and under-reported).  explain/rewrite consistency.
    #[tokio::test]
    async fn explain_reports_mask_nested_in_subquery() {
        let (ctx, users) = ctx_with_users();
        let enforcer = ColumnMaskingEnforcer::new([mask_email_literal(&users)]).expect("build");
        let plan = ctx
            .sql("SELECT id FROM users WHERE email IN (SELECT email FROM users)")
            .await
            .expect("plan")
            .logical_plan()
            .clone();
        let decisions = enforcer.explain(&plan, &crate::Identity::anonymous());
        assert!(
            decisions.iter().any(|d| d.resource.contains("email")),
            "explain must report a mask nested in a subquery; got {decisions:?}"
        );
    }
}

//! Column masking — first concrete `PolicyEnforcer` implementation.
//!
//! [`ColumnMaskingEnforcer`] is the Phase 1 governance MVP. It takes a
//! map of `(TableReference, ColumnName) → masking Expr` rules and
//! rewrites a `LogicalPlan` so every reference to a masked column —
//! projections, aggregate and window arguments, **and** `WHERE` / join /
//! `ORDER BY` / pushed-down scan predicates — evaluates the registered
//! mask `Expr` instead of the original column. A masked user therefore
//! cannot probe the real value through a predicate (`WHERE ssn = '…'`,
//! `LIKE '123-%'`, a join against a probe table, an `ORDER BY … LIMIT`
//! walk): the value oracle Burak reported as. This is the
//! Snowflake / `BigQuery` / Databricks dynamic-data-masking semantic:
//! the mask applies wherever the column is accessed.
//!
//! The one exception is **admin row filters**: a predicate the
//! [`crate::RowFilterEnforcer`] injects must keep evaluating on real data
//! or RLS silently breaks. The optimizer merges and pushes predicates
//! around between passes, so those predicates cannot be recognised by
//! shape; instead the *columns* the row filter that applies to the session
//! references are exempt from predicate masking on that table
//! ([`ColumnMaskingEnforcer::with_row_filter_exemptions`], wired
//! automatically by [`crate::CompositeEnforcer`]). Output positions of
//! such a column stay masked.
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

use datafusion::common::tree_node::{Transformed, TreeNode, TreeNodeRecursion};
use datafusion::common::TableReference;
use datafusion::error::DataFusionError;
use datafusion::logical_expr::{
    Expr, Filter, Join, LogicalPlan, LogicalPlanBuilder, Sort, SortExpr, TableScan,
};

use std::sync::Arc;

use crate::filter::RowFilterEnforcer;
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
    // Shared, not copied, on `clone()`: the composite wiring clones the
    // enforcer to hand it row-filter sources.
    masks: Arc<HashMap<(TableReference, String), OrgTaggedMasks>>,
    /// The layers that inject admin row filters (static or tag-derived),
    /// composed with this enforcer. A predicate over a column the filter that
    /// applies to the session references is left on real values, so RLS keeps
    /// working (see the module docs); output positions stay masked.
    rls: Vec<Arc<dyn PolicyEnforcer>>,
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
            masks: Arc::new(map),
            rls: Vec::new(),
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

    /// Exempt from **predicate** masking the columns the admin row filter
    /// that applies to a session references. An RLS predicate such
    /// as `email LIKE '%@corp.example'` on a masked `email` must keep
    /// evaluating on the real value, and the optimizer reshapes and pushes
    /// predicates between passes, so the exemption is by column, not by
    /// predicate identity — resolved through `rls` with the same
    /// tenant/operator precedence and group scoping the filter itself uses.
    /// [`crate::CompositeEnforcer`] wires this automatically whenever masks and
    /// row filters are composed. A user predicate over such a column is exempt
    /// too — an admin filtering on that column has made it a governance key;
    /// documented in `docs/access-control.md`. Output positions stay masked.
    #[must_use]
    pub fn with_row_filter_exemptions(mut self, rls: Arc<RowFilterEnforcer>) -> Self {
        self.rls.push(rls);
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
            masks: Arc::new(HashMap::new()),
            rls: Vec::new(),
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

    /// Look up a mask by column. Tries the column's relation as
    /// reported by the planner first (strict match — the documented
    /// semantics); on miss, retries under the alias-resolved
    /// underlying table. The alias fallback handles
    /// `SELECT u.email FROM users u` and the join cases that surface
    /// it (`FROM users u JOIN orders o ON …`), where the planner
    /// stamps the column relation as the SQL alias rather than the
    /// original table.
    /// Mask every reference to a masked column inside one node-level
    /// expression, **preserving the expression's output field name**.
    ///
    /// A top-level `Expr::Column` matching a rule becomes the mask aliased
    /// with the original `(qualifier, name)`, so `SELECT email` still outputs
    /// the field `users.email`. A nested reference (`UPPER(email)`,
    /// `max(email)`) has the mask substituted *inside* the expression and the
    /// whole result aliased back to its ORIGINAL derived name
    /// (`upper(users.email)`, `max(users.email)`) whenever the substitution
    /// would otherwise change that name. Keeping every field name stable means
    /// the enclosing node's output schema is byte-identical before and after —
    /// DataFusion requires an optimizer rule to preserve schema, and preserving
    /// it is exactly what avoids the `optimize_projections` invariant panic on
    /// an un-aliased masked expression. Because this is pure
    /// expression substitution (no new plan node, no re-scoping subquery), the
    /// rewritten plan unparses to valid SQL for federated pushdown.
    fn mask_expr(
        &self,
        expr: Expr,
        alias_map: &HashMap<TableReference, TableReference>,
        identity: &Identity,
    ) -> Result<Transformed<Expr>, DataFusionError> {
        // Top-level column: preserve both the projected name and qualifier.
        if let Expr::Column(c) = &expr {
            if let Some(rel) = &c.relation {
                if let Some(mask) = self.lookup_mask(rel, &c.name, alias_map, identity) {
                    crate::audit::record_decision("mask", identity, &format!("{rel}.{}", c.name));
                    return Ok(Transformed::yes(
                        requalify_mask(mask.clone(), rel, alias_map.get(rel))
                            .alias_qualified(Some(rel.clone()), c.name.clone()),
                    ));
                }
            }
            return Ok(Transformed::no(expr));
        }

        // Nested reference: substitute the mask, then alias back to the
        // original derived name if the substitution changed it.
        let original_name = expr.schema_name().to_string();
        let out = expr.transform_down(|e| {
            if self.is_substituted_mask(&e, alias_map, identity) {
                return Ok(Transformed::new(e, false, TreeNodeRecursion::Jump));
            }
            match self.substitute_reference(&e, alias_map, identity, "mask")? {
                Some(masked) => Ok(Transformed::new(masked, true, TreeNodeRecursion::Jump)),
                None => Ok(Transformed::no(e)),
            }
        })?;
        if !out.transformed {
            return Ok(Transformed::no(out.data));
        }
        if out.data.schema_name().to_string() == original_name {
            Ok(Transformed::yes(out.data))
        } else {
            Ok(Transformed::yes(out.data.alias(original_name)))
        }
    }

    /// Step 2a of [`PolicyEnforcer::rewrite`]: substitute the mask IN PLACE
    /// (no alias — these positions define no output field) in `Filter`
    /// predicates, pushed-down `TableScan.filters`, `Join` conditions and
    /// `Sort` keys, so the real value cannot be probed through `WHERE` /
    /// `LIKE` / `JOIN` / `ORDER BY`. Columns an admin row filter
    /// references are exempt so RLS keeps evaluating on real data in every
    /// optimizer pass. `Ok(Err(node))` hands any other node back untouched.
    #[allow(clippy::type_complexity)]
    fn mask_predicate_positions(
        &self,
        node: LogicalPlan,
        alias_map: &HashMap<TableReference, TableReference>,
        identity: &Identity,
        sub_changed: bool,
        cache: &ExemptCache,
        scanned: &ScannedTables,
    ) -> Result<Result<Transformed<LogicalPlan>, LogicalPlan>, DataFusionError> {
        match node {
            LogicalPlan::Filter(f) => {
                // `FROM a, b WHERE a.email = b.email` plans as a Filter over a
                // cross join (a Join with no keys and no filter) — possibly
                // behind a derived table's alias/projection, which the
                // optimizer inlines; a masked predicate that folds to TRUE
                // would leave the full N×M product standing — the same hazard
                // `mask_join` refuses. Likewise a predicate that RELATED the
                // two inputs before masking must still do so afterwards:
                // `'***' = '***' AND u.id > 0` keeps a one-sided residual over
                // the product.
                let cross = keyless_join_beneath(&f.input).is_some();
                let side_of = |c: &datafusion::common::Column| base_sides(c, &f.input);
                let had_cross = cross && relates_inputs(&f.predicate, &side_of);
                let out = self.mask_predicate(f.predicate, alias_map, identity, cache, scanned)?;
                // A derived column whose expression masks to a constant IS that
                // constant once inlined: substitute it so the guards see it.
                let out = if cross {
                    self.derived_constants(
                        out,
                        &[f.input.as_ref()],
                        alias_map,
                        identity,
                        cache,
                        scanned,
                    )?
                } else {
                    out
                };
                let changed = out.transformed;
                if cross && changed {
                    let column_free = out.data.column_refs().is_empty();
                    match fold_constant(&out.data, f.input.schema()) {
                        Fold::True => return Err(constant_join_error()),
                        // A column-free predicate the simplifier cannot fold
                        // may still evaluate TRUE per row: fail closed, as the
                        // Join path does.
                        Fold::Unknown if column_free => return Err(constant_join_error()),
                        _ => {}
                    }
                    if had_cross
                        && !restricts_pairing(&simplify(&out.data, f.input.schema()), &side_of)
                    {
                        return Err(constant_join_error());
                    }
                }
                // `Filter` is non-exhaustive: rebuild through its constructor.
                let rebuilt = Filter::try_new(out.data, f.input)?;
                Ok(Ok(flag(
                    LogicalPlan::Filter(rebuilt),
                    changed || sub_changed,
                )))
            }
            LogicalPlan::TableScan(scan) => {
                let mut changed = false;
                let mut filters = Vec::with_capacity(scan.filters.len());
                for e in scan.filters {
                    let out = self.mask_predicate(e, alias_map, identity, cache, scanned)?;
                    changed |= out.transformed;
                    filters.push(out.data);
                }
                Ok(Ok(flag(
                    LogicalPlan::TableScan(TableScan { filters, ..scan }),
                    changed || sub_changed,
                )))
            }
            LogicalPlan::Join(j) => {
                self.mask_join(j, alias_map, identity, sub_changed, cache, scanned)
            }
            LogicalPlan::Sort(srt) => {
                let mut changed = false;
                let mut expr = Vec::with_capacity(srt.expr.len());
                for se in srt.expr {
                    let out = self.mask_predicate(se.expr, alias_map, identity, cache, scanned)?;
                    changed |= out.transformed;
                    // A key that became a literal (a literal mask) orders
                    // nothing — and `ORDER BY '***'` is invalid SQL on
                    // PostgreSQL ("non-integer constant in ORDER BY") once
                    // pushed down — so it is dropped. Only literals: a
                    // zero-column mask may still be volatile (`random()`) and
                    // then orders per row.
                    if out.transformed && matches!(out.data, Expr::Literal(_, _)) {
                        continue;
                    }
                    expr.push(SortExpr {
                        expr: out.data,
                        asc: se.asc,
                        nulls_first: se.nulls_first,
                    });
                }
                if expr.is_empty() {
                    // Every key was a masked literal: the Sort orders
                    // nothing. Keep only its LIMIT, if any. The replacement
                    // takes this node's slot, so `transform_down` would not
                    // call us on it again — rewrite the subtree explicitly
                    // and stop the walk here.
                    let input = std::sync::Arc::unwrap_or_clone(srt.input);
                    let input = self.rewrite_with(input, identity, alias_map, scanned)?.data;
                    let plan = match srt.fetch {
                        Some(fetch) => LogicalPlanBuilder::from(input)
                            .limit(0, Some(fetch))?
                            .build()?,
                        None => input,
                    };
                    return Ok(Ok(Transformed::new(plan, true, TreeNodeRecursion::Jump)));
                }
                Ok(Ok(flag(
                    LogicalPlan::Sort(Sort { expr, ..srt }),
                    changed || sub_changed,
                )))
            }
            other => Ok(Err(other)),
        }
    }

    fn mask_join(
        &self,
        j: Join,
        alias_map: &HashMap<TableReference, TableReference>,
        identity: &Identity,
        sub_changed: bool,
        cache: &ExemptCache,
        scanned: &ScannedTables,
    ) -> Result<Result<Transformed<LogicalPlan>, LogicalPlan>, DataFusionError> {
        let mut changed = false;
        let side_of = |c: &datafusion::common::Column| Sides {
            left: j.left.schema().has_column(c),
            right: j.right.schema().has_column(c),
        };
        // Did the condition relate the two inputs before masking? An `on` pair
        // always does; a filter only through a term that reads both sides.
        let related_before = !j.on.is_empty()
            || j.filter
                .as_ref()
                .is_some_and(|f| relates_inputs(f, &side_of));
        // Semi/anti/mark joins emit each retained input row at most once, so a
        // constant condition cannot multiply rows there.
        let multiplicative = matches!(
            j.join_type,
            datafusion::logical_expr::JoinType::Inner
                | datafusion::logical_expr::JoinType::Left
                | datafusion::logical_expr::JoinType::Right
                | datafusion::logical_expr::JoinType::Full
        );
        // A key or filter column of a derived input whose expression masks to
        // a constant (`a.ue` over `SELECT u.email AS ue …`) IS that constant
        // once the optimizer inlines the projection: substitute it so the
        // guards below see the constants (`derived_constants`).
        let inputs = [j.left.as_ref(), j.right.as_ref()];
        // Each `on` tuple is one AND term of the join condition. A tuple whose
        // two sides became column-free constants is TRUE (`'***' = '***'`),
        // FALSE (`'a' = 'b'`, the join is empty), or unfoldable (treated as
        // TRUE, fail closed). TRUE tuples are dropped; FALSE/NULL ones move
        // into the join filter — an equi-key of two literals does not behave
        // as a key at execution (the hash join paired every row), whereas a
        // FALSE filter empties the join. The join is refused only if nothing
        // restrictive remains (`ON u.email = v.email AND u.id = v.id` keeps
        // `id`).
        let mut on = Vec::with_capacity(j.on.len());
        let mut false_terms: Vec<Expr> = Vec::new();
        for (l, r) in j.on {
            let l = self.mask_predicate(l, alias_map, identity, cache, scanned)?;
            let l = self.derived_constants(l, &inputs, alias_map, identity, cache, scanned)?;
            let r = self.mask_predicate(r, alias_map, identity, cache, scanned)?;
            let r = self.derived_constants(r, &inputs, alias_map, identity, cache, scanned)?;
            changed |= l.transformed || r.transformed;
            let constant_pair = (l.transformed || r.transformed)
                && l.data.column_refs().is_empty()
                && r.data.column_refs().is_empty();
            if constant_pair {
                let eq_expr = l.data.eq(r.data);
                match fold_constant(&eq_expr, &j.schema) {
                    // TRUE restricts nothing: drop it, decide below.
                    Fold::True => continue,
                    // FALSE or NULL rejects every pair: keep it as a filter.
                    Fold::FalseOrNull => {
                        false_terms.push(eq_expr);
                        continue;
                    }
                    // A constant we cannot fold: fail closed.
                    Fold::Unknown => return Err(constant_join_error()),
                }
            }
            on.push((l.data, r.data));
        }
        let mut filter_true = false;
        let filter = match j.filter {
            Some(e) => {
                let out = self.mask_predicate(e, alias_map, identity, cache, scanned)?;
                let out =
                    self.derived_constants(out, &inputs, alias_map, identity, cache, scanned)?;
                changed |= out.transformed;
                // The SQL planner keeps `ON a = b` here until a later optimizer
                // rule extracts equi-keys; a masked condition that folds to
                // TRUE (`'***' = '***' OR u.id = v.id`) or is an unfoldable
                // constant restricts nothing.
                let column_free = out.transformed && out.data.column_refs().is_empty();
                match fold_constant(&out.data, &j.schema) {
                    Fold::True if out.transformed => {
                        filter_true = true;
                        None
                    }
                    Fold::Unknown if column_free => return Err(constant_join_error()),
                    _ => Some(out.data),
                }
            }
            None => None,
        };
        let filter = false_terms.into_iter().fold(filter, |acc, term| {
            Some(match acc {
                Some(f) => f.and(term),
                None => term,
            })
        });
        // What survives must still RELATE the two inputs. An `on` key does
        // only while BOTH sides still read a column: a key masked on one side
        // (`'***' = o.email`) is a filter on that side, not a pairing
        // constraint. A filter does if it folds to FALSE/NULL (empty join) or
        // its simplified form relates them (`relates_inputs`: `u.id > 0 AND
        // v.id > 0` spans both schemas yet leaves the pairing unconstrained;
        // `('***' = '***' OR u.id = v.id) AND u.id > 0` simplifies to a
        // one-sided term). A condition that related the inputs before masking
        // and no longer does is the unbounded cross product: refused.
        let relates_after = on
            .iter()
            .any(|(l, r)| !l.column_refs().is_empty() && !r.column_refs().is_empty())
            || filter
                .as_ref()
                .is_some_and(|f| restricts_pairing(&simplify(f, &j.schema), &side_of));
        if multiplicative && !relates_after && (filter_true || (changed && related_before)) {
            return Err(constant_join_error());
        }
        Ok(Ok(flag(
            LogicalPlan::Join(Join { on, filter, ..j }),
            changed || sub_changed,
        )))
    }

    /// Substitute, in a predicate over `inputs`, every column of a derived
    /// input whose defining expression masks to a constant
    /// (`constant_of_derived`) by that constant — what the predicate compares
    /// once the optimizer inlines the derived table's projection.
    fn derived_constants(
        &self,
        expr: Transformed<Expr>,
        inputs: &[&LogicalPlan],
        alias_map: &HashMap<TableReference, TableReference>,
        identity: &Identity,
        cache: &ExemptCache,
        scanned: &ScannedTables,
    ) -> Result<Transformed<Expr>, DataFusionError> {
        let Transformed {
            data, transformed, ..
        } = expr;
        let out = data.transform_down(|e| {
            if let Expr::Column(c) = &e {
                for input in inputs {
                    if let Some(k) =
                        self.constant_of_derived(c, input, alias_map, identity, cache, scanned)?
                    {
                        return Ok(Transformed::new(k, true, TreeNodeRecursion::Jump));
                    }
                }
            }
            Ok(Transformed::no(e))
        })?;
        Ok(Transformed::new(
            out.data,
            transformed || out.transformed,
            TreeNodeRecursion::Continue,
        ))
    }

    /// The constant that column `c` of `input`'s output becomes when its
    /// defining expression is masked — `'***'` for `x.ue` over `SELECT
    /// u.email AS ue` under a literal mask on `users.email`; `None` when `c`
    /// is not a derived column or does not mask to a constant. Follows
    /// alias/projection/filter wrappers to any depth, resolving each derived
    /// scope's own aliases.
    fn constant_of_derived(
        &self,
        c: &datafusion::common::Column,
        input: &LogicalPlan,
        aliases: &HashMap<TableReference, TableReference>,
        identity: &Identity,
        cache: &ExemptCache,
        scanned: &ScannedTables,
    ) -> Result<Option<Expr>, DataFusionError> {
        match input {
            LogicalPlan::SubqueryAlias(sa) => {
                let Some(inner) = derived_inner_column(c, sa) else {
                    return Ok(None);
                };
                let inner_aliases = scope_aliases(&sa.input, aliases);
                self.constant_of_derived(
                    &inner,
                    &sa.input,
                    &inner_aliases,
                    identity,
                    cache,
                    scanned,
                )
            }
            LogicalPlan::Projection(p) => {
                let Ok(idx) = p.schema.index_of_column(c) else {
                    return Ok(None);
                };
                let defining = p.expr[idx].clone().unalias();
                let masked = self.mask_predicate(defining, aliases, identity, cache, scanned)?;
                if masked.transformed && masked.data.column_refs().is_empty() {
                    return Ok(Some(simplify(&masked.data, p.input.schema())));
                }
                match masked.data {
                    Expr::Column(inner) if !masked.transformed => self
                        .constant_of_derived(&inner, &p.input, aliases, identity, cache, scanned),
                    _ => Ok(None),
                }
            }
            // Every other wrapper passes its input's columns through (a window
            // expression itself is never a masked constant).
            other => match passthrough_input(other, c) {
                Some(inner) => {
                    self.constant_of_derived(c, inner, aliases, identity, cache, scanned)
                }
                None => Ok(None),
            },
        }
    }

    /// Substitute the mask for every reference to a masked column in a
    /// predicate / join condition / sort key — in place, no alias (these
    /// positions define no output field). Skips RLS-exempt columns and never
    /// descends into an already-substituted mask (idempotent across
    /// optimizer passes).
    fn mask_predicate(
        &self,
        expr: Expr,
        alias_map: &HashMap<TableReference, TableReference>,
        identity: &Identity,
        cache: &ExemptCache,
        scanned: &ScannedTables,
    ) -> Result<Transformed<Expr>, DataFusionError> {
        expr.transform_down(|e| {
            if self.is_substituted_mask(&e, alias_map, identity) {
                return Ok(Transformed::new(e, false, TreeNodeRecursion::Jump));
            }
            if let Some((rel, name)) = referenced_column(&e) {
                if self.is_rls_exempt(rel, name, alias_map, identity, cache, scanned) {
                    return Ok(Transformed::no(e));
                }
            }
            match self.substitute_reference(&e, alias_map, identity, "mask (predicate)")? {
                Some(masked) => Ok(Transformed::new(masked, true, TreeNodeRecursion::Jump)),
                None => Ok(Transformed::no(e)),
            }
        })
    }

    /// Is `e` exactly the mask that applies (to this identity) for one of the
    /// columns it references, bound to that column's relation — i.e. a
    /// substitution made by an earlier optimizer pass? Without this, a mask
    /// that embeds its column (`md5(email)`) would nest on every pass. A user
    /// who writes the applicable mask by hand gets… the mask value, which the
    /// masked projection shows anyway; for deterministic masks that reveals
    /// nothing beyond what the mask itself reveals.
    fn is_substituted_mask(
        &self,
        e: &Expr,
        alias_map: &HashMap<TableReference, TableReference>,
        identity: &Identity,
    ) -> bool {
        // Leaves can never be a substituted mask (a mask that is itself a bare
        // column would resolve through `lookup_mask` below anyway), so the
        // per-node cost is paid only on composite nodes — and each candidate
        // comparison is bounded by the (small) mask expression.
        if matches!(
            e,
            Expr::Column(_) | Expr::Literal(_, _) | Expr::OuterReferenceColumn(_, _)
        ) {
            return false;
        }
        let mut refs: Vec<(
            Option<datafusion::arrow::datatypes::FieldRef>,
            &datafusion::common::Column,
        )> = Vec::new();
        e.apply(|n| {
            match n {
                Expr::Column(c) => refs.push((None, c)),
                Expr::OuterReferenceColumn(field, c) => refs.push((Some(Arc::clone(field)), c)),
                _ => {}
            }
            Ok(TreeNodeRecursion::Continue)
        })
        .expect("infallible walk");
        refs.into_iter().any(|(outer_field, c)| {
            let Some(rel) = c.relation.as_ref() else {
                return false;
            };
            let Some(mask) = self.lookup_mask(rel, &c.name, alias_map, identity) else {
                return false;
            };
            let bound = requalify_mask(mask.clone(), rel, alias_map.get(rel));
            let candidate = match outer_field {
                // The substitution made for a correlated outer reference
                // re-wraps the mask's own column as an outer reference.
                Some(field) => as_outer_reference(bound, &field, &c.name, rel),
                None => bound,
            };
            candidate == *e
        })
    }

    /// If `e` is a reference to a masked column — a plain `Column`, or an
    /// `OuterReferenceColumn` inside a correlated subquery — return the mask
    /// to put in its place. For an outer reference the mask's own reference
    /// to the column is re-wrapped as an outer reference of the same field;
    /// a mask that also reads *other* columns cannot be expressed there and
    /// fails closed (plan error) rather than leaving the real value exposed.
    fn substitute_reference(
        &self,
        e: &Expr,
        alias_map: &HashMap<TableReference, TableReference>,
        identity: &Identity,
        action: &str,
    ) -> Result<Option<Expr>, DataFusionError> {
        let Some((rel, name)) = referenced_column(e) else {
            return Ok(None);
        };
        let Some(mask) = self.lookup_mask(rel, name, alias_map, identity) else {
            return Ok(None);
        };
        crate::audit::record_decision(action, identity, &format!("{rel}.{name}"));
        // The mask reads its column unqualified (`md5(CAST(email …))`); bind
        // that reference to the relation being replaced, or it is ambiguous
        // the moment two aliases of the table meet (a self-join).
        let mask = requalify_mask(mask.clone(), rel, alias_map.get(rel));
        match e {
            Expr::OuterReferenceColumn(field, outer) => {
                let rewrapped = mask.transform_down(|m| match m {
                    Expr::Column(c)
                        if c.name == outer.name
                            && c.relation.as_ref().is_none_or(|r| r.resolved_eq(rel)) =>
                    {
                        Ok(Transformed::new(
                            Expr::OuterReferenceColumn(Arc::clone(field), c),
                            true,
                            TreeNodeRecursion::Jump,
                        ))
                    }
                    Expr::Column(c) => Err(DataFusionError::Plan(format!(
                        "mask on {rel}.{name} reads {c} and cannot be applied to a correlated \
                         outer reference; rewrite the query without the correlation"
                    ))),
                    other => Ok(Transformed::no(other)),
                })?;
                Ok(Some(rewrapped.data))
            }
            _ => Ok(Some(mask)),
        }
    }

    /// Is `column` of `rel` referenced by the admin row filter that applies to
    /// `identity` on that table (resolved through the same qualification
    /// candidates and alias map as [`Self::lookup_mask`])?
    fn is_rls_exempt(
        &self,
        rel: &TableReference,
        column: &str,
        alias_map: &HashMap<TableReference, TableReference>,
        identity: &Identity,
        cache: &ExemptCache,
        scanned: &ScannedTables,
    ) -> bool {
        if self.rls.is_empty() {
            return false;
        }
        // Resolve ONCE for the actual scan table (alias-resolved): each source
        // applies its own qualification candidates and tenant/operator
        // precedence internally. Iterating candidates here would let a
        // shadowed fallback rule leak columns the winning rule does not read.
        let table = alias_map.get(rel).unwrap_or(rel);
        let mut cache = cache.borrow_mut();
        let cols = cache.entry(table.clone()).or_insert_with(|| {
            self.rls
                .iter()
                .filter_map(|src| src.rls_referenced_columns(table, identity, scanned))
                .flatten()
                .collect()
        });
        cols.contains(column)
    }

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

/// The alias→table map of ONE lexical scope: the enclosing scopes' entries,
/// shadowed by the relations this scope declares — each `SubqueryAlias` over
/// a scan (`FROM users u`), each unaliased scan bound to itself (so an outer
/// `FROM users AS entitlements` cannot capture an inner `FROM entitlements`),
/// and each derived table's alias bound to itself. Collection stops at scope
/// boundaries ([`scope_children`]): a `UNION` branch's `u` is not this
/// scope's `u`, and a derived table's inner aliases are invisible outside it.
/// Every consumer that resolves references builds its map with this: the
/// masking rewrite, the row-filter exemption collector, access-deny, the
/// column whitelist and every `explain`.
pub(crate) fn scope_aliases(
    plan: &LogicalPlan,
    enclosing: &HashMap<TableReference, TableReference>,
) -> HashMap<TableReference, TableReference> {
    let mut out = enclosing.clone();
    collect_scope_relations(plan, &mut out);
    out
}

fn collect_scope_relations(plan: &LogicalPlan, out: &mut HashMap<TableReference, TableReference>) {
    match plan {
        LogicalPlan::SubqueryAlias(sa) => {
            let alias = TableReference::bare(sa.alias.table().to_string());
            if let LogicalPlan::TableScan(ts) = sa.input.as_ref() {
                out.insert(alias, ts.table_name.clone());
                out.insert(ts.table_name.clone(), ts.table_name.clone());
            } else {
                // Derived table: its own scope; only the alias is visible here.
                out.insert(alias.clone(), alias);
            }
            return;
        }
        LogicalPlan::TableScan(ts) => {
            out.insert(ts.table_name.clone(), ts.table_name.clone());
        }
        // Each branch is its own scope.
        LogicalPlan::Union(_) => return,
        _ => {}
    }
    for child in plan.inputs() {
        collect_scope_relations(child, out);
    }
}

/// The child scopes a node opens — each `UNION` branch, a derived table's
/// plan — which resolve their references with their OWN relations (this
/// scope's map as their enclosing one), never with this scope's. Empty for
/// every other node.
pub(crate) fn scope_children(node: &LogicalPlan) -> Vec<Arc<LogicalPlan>> {
    match node {
        LogicalPlan::Union(u) => u.inputs.clone(),
        LogicalPlan::SubqueryAlias(sa)
            if !matches!(sa.input.as_ref(), LogicalPlan::TableScan(_)) =>
        {
            vec![Arc::clone(&sa.input)]
        }
        _ => Vec::new(),
    }
}

/// The callback of [`for_each_expr_scoped`]: an expression and the alias map
/// of its own lexical scope.
pub(crate) type ScopedExprVisitor<'a> =
    dyn FnMut(&Expr, &HashMap<TableReference, TableReference>) -> Result<(), DataFusionError> + 'a;

/// Visit every expression of `plan` scope by scope: `on_expr(expr, aliases)`
/// receives the alias map of the expression's own lexical scope
/// ([`scope_aliases`] over `enclosing`); child scopes ([`scope_children`])
/// and the plans of embedded subqueries recurse with that map as their
/// enclosing one. `Expr::apply` treats subquery-bearing variants as opaque,
/// so `on_expr` never sees a nested plan's expressions twice.
pub(crate) fn for_each_expr_scoped(
    plan: &LogicalPlan,
    enclosing: &HashMap<TableReference, TableReference>,
    on_expr: &mut ScopedExprVisitor<'_>,
) -> Result<(), DataFusionError> {
    let aliases = scope_aliases(plan, enclosing);
    let mut nested: Vec<Arc<LogicalPlan>> = Vec::new();
    plan.apply(|node| {
        let children = scope_children(node);
        if !children.is_empty() {
            nested.extend(children);
            return Ok(TreeNodeRecursion::Jump);
        }
        for e in node.expressions() {
            on_expr(&e, &aliases)?;
            e.apply(|x| {
                if let Some(sub) = crate::embedded_subquery(x) {
                    nested.push(Arc::clone(sub));
                }
                Ok(TreeNodeRecursion::Continue)
            })?;
        }
        Ok(TreeNodeRecursion::Continue)
    })?;
    for sub in nested {
        for_each_expr_scoped(&sub, &aliases, on_expr)?;
    }
    Ok(())
}

/// Which inputs of a join a column comes from.
#[derive(Clone, Copy, Default)]
struct Sides {
    left: bool,
    right: bool,
}

impl Sides {
    const NONE: Self = Self {
        left: false,
        right: false,
    };
    fn or(self, o: Self) -> Self {
        Self {
            left: self.left || o.left,
            right: self.right || o.right,
        }
    }
    fn both(self) -> bool {
        self.left && self.right
    }
}

/// Does `predicate` RELATE the two inputs of a join — restrict which left
/// row pairs with which right row? An atomic condition does when its columns
/// come from both sides (`side_of`; `u.id = v.id`, `u.a < v.b`); `AND` does
/// when any term does; `OR` only when every branch does (`u.id > 0 OR v.id >
/// 0` spans both schemas, yet each branch filters one side and the pairing
/// stays the full product); `NOT` flips the two by De Morgan. `u.id > 0 AND
/// v.id > 0` therefore does not relate — it is the product of two filtered
/// inputs.
fn relates_inputs(
    predicate: &Expr,
    side_of: &dyn Fn(&datafusion::common::Column) -> Sides,
) -> bool {
    fn go(e: &Expr, side_of: &dyn Fn(&datafusion::common::Column) -> Sides, negated: bool) -> bool {
        use datafusion::logical_expr::{BinaryExpr, Operator};
        match e {
            Expr::BinaryExpr(BinaryExpr {
                left: a,
                op: Operator::And,
                right: b,
            }) if !negated => go(a, side_of, false) || go(b, side_of, false),
            Expr::BinaryExpr(BinaryExpr {
                left: a,
                op: Operator::Or,
                right: b,
            }) if negated => go(a, side_of, true) || go(b, side_of, true),
            Expr::BinaryExpr(BinaryExpr {
                left: a,
                op: Operator::And | Operator::Or,
                right: b,
            }) => go(a, side_of, negated) && go(b, side_of, negated),
            Expr::Not(inner) => go(inner, side_of, !negated),
            atom => atom
                .column_refs()
                .iter()
                .fold(Sides::NONE, |acc, c| acc.or(side_of(c)))
                .both(),
        }
    }
    go(predicate, side_of, false)
}

/// Bind the mask's table-local references to `rel`, the relation whose
/// reference the mask replaces: every unqualified column (the masked column
/// itself, or a sibling a custom mask reads — `CASE WHEN region = 'EU' …`),
/// and any reference qualified with the relation itself or with the source
/// table it aliases (a mask registered as `users.email` applied under alias
/// `u`, `source` = `users`). References to other tables are left alone.
fn requalify_mask(mask: Expr, rel: &TableReference, source: Option<&TableReference>) -> Expr {
    // Full-qualifier comparison (catalog/schema too, where both sides carry
    // them): a mask that reads `catalog_b.public.users.token` must not be
    // rebound onto `catalog_a.public.users`.
    let same_table =
        |r: &TableReference| r.resolved_eq(rel) || source.is_some_and(|src| r.resolved_eq(src));
    mask.transform_down(|m| match m {
        Expr::Column(c) if c.relation.is_none() || c.relation.as_ref().is_some_and(same_table) => {
            Ok(Transformed::new(
                Expr::Column(datafusion::common::Column::new(Some(rel.clone()), c.name)),
                true,
                TreeNodeRecursion::Jump,
            ))
        }
        other => Ok(Transformed::no(other)),
    })
    .expect("pure Expr rewrite never fails")
    .data
}

/// What a (masked) condition folds to under DataFusion's own simplifier.
enum Fold {
    True,
    /// FALSE or NULL — both reject every row pair.
    FalseOrNull,
    Unknown,
}

/// `condition` under DataFusion's own simplifier (constant folding, `TRUE OR
/// x` → `TRUE`, `TRUE AND y` → `y`); the condition itself when it cannot be
/// simplified.
fn simplify(condition: &Expr, schema: &datafusion::common::DFSchemaRef) -> Expr {
    use datafusion::logical_expr::simplify::SimplifyContext;
    use datafusion::optimizer::simplify_expressions::ExprSimplifier;

    let ctx = SimplifyContext::builder()
        .with_schema(Arc::clone(schema))
        .build();
    ExprSimplifier::new(ctx)
        .simplify(condition.clone())
        .unwrap_or_else(|_| condition.clone())
}

fn fold_constant(condition: &Expr, schema: &datafusion::common::DFSchemaRef) -> Fold {
    fold_of(&simplify(condition, schema))
}

/// [`Fold`] of an already-simplified condition.
fn fold_of(simplified: &Expr) -> Fold {
    use datafusion::common::ScalarValue;
    match simplified {
        Expr::Literal(ScalarValue::Boolean(Some(true)), _) => Fold::True,
        Expr::Literal(ScalarValue::Boolean(Some(false) | None) | ScalarValue::Null, _) => {
            Fold::FalseOrNull
        }
        _ => Fold::Unknown,
    }
}

/// Does a (masked, simplified) join condition still restrict the pairing of
/// the two inputs? Either it rejects every pair (FALSE/NULL — the join is
/// empty, kept) or it relates them (`relates_inputs`).
fn restricts_pairing(
    simplified: &Expr,
    side_of: &dyn Fn(&datafusion::common::Column) -> Sides,
) -> bool {
    matches!(fold_of(simplified), Fold::FalseOrNull) || relates_inputs(simplified, side_of)
}

/// The keyless join (`FROM a, b` / `CROSS JOIN`: no `on`, no filter) a
/// predicate above `plan` conditions, looking through every single-input
/// wrapper a derived table may add (alias, projection, filter, sort, limit,
/// window, distinct, …) — the optimizer inlines those, leaving the predicate
/// directly over the product. Stops at a filter that already RELATES the
/// join's inputs (`… WHERE u.id = v.id` inside the derived table): the
/// pairing is restricted there, whatever happens above.
fn keyless_join_beneath(plan: &LogicalPlan) -> Option<&Join> {
    match plan {
        LogicalPlan::Join(j) if j.on.is_empty() && j.filter.is_none() => Some(j),
        LogicalPlan::Filter(f) => {
            let beneath = keyless_join_beneath(&f.input)?;
            let side_of = |c: &datafusion::common::Column| base_sides(c, &f.input);
            if relates_inputs(&f.predicate, &side_of) {
                None
            } else {
                Some(beneath)
            }
        }
        _ => match plan.inputs().as_slice() {
            [only] => keyless_join_beneath(only),
            _ => None,
        },
    }
}

/// The single input of `node` whose output still carries column `c`
/// unchanged — the pass-through case of every wrapper (filter, sort, limit,
/// distinct, a window's input columns, …).
fn passthrough_input<'a>(
    node: &'a LogicalPlan,
    c: &datafusion::common::Column,
) -> Option<&'a LogicalPlan> {
    match node.inputs().as_slice() {
        [only] if only.schema().index_of_column(c).is_ok() => Some(only),
        _ => None,
    }
}

/// The inputs of the keyless join beneath `input` that column `c` derives
/// from — through derived-table aliases, projections and pass-through
/// wrappers (`x.ue` over `SELECT u.email AS ue …` comes from the left input).
fn base_sides(c: &datafusion::common::Column, input: &LogicalPlan) -> Sides {
    match input {
        LogicalPlan::Join(j) if j.on.is_empty() && j.filter.is_none() => Sides {
            left: j.left.schema().has_column(c),
            right: j.right.schema().has_column(c),
        },
        LogicalPlan::SubqueryAlias(sa) => match derived_inner_column(c, sa) {
            Some(inner) => base_sides(&inner, &sa.input),
            None => Sides::NONE,
        },
        LogicalPlan::Projection(p) => match p.schema.index_of_column(c) {
            Ok(idx) => p.expr[idx]
                .column_refs()
                .iter()
                .fold(Sides::NONE, |acc, col| acc.or(base_sides(col, &p.input))),
            Err(_) => Sides::NONE,
        },
        // A window expression's own output derives from the columns it reads.
        LogicalPlan::Window(w) if w.input.schema().index_of_column(c).is_err() => {
            match w.schema.index_of_column(c) {
                Ok(idx) => w.window_expr[idx - w.input.schema().fields().len()]
                    .column_refs()
                    .iter()
                    .fold(Sides::NONE, |acc, col| acc.or(base_sides(col, &w.input))),
                Err(_) => Sides::NONE,
            }
        }
        other => match passthrough_input(other, c) {
            Some(inner) => base_sides(c, inner),
            None => Sides::NONE,
        },
    }
}

/// The column of `sa.input`'s output that `c` (a reference to the alias, or
/// unqualified) names.
fn derived_inner_column(
    c: &datafusion::common::Column,
    sa: &datafusion::logical_expr::SubqueryAlias,
) -> Option<datafusion::common::Column> {
    if c.relation
        .as_ref()
        .is_some_and(|r| !r.resolved_eq(&sa.alias))
    {
        return None;
    }
    let idx = sa.input.schema().index_of_column_by_name(None, &c.name)?;
    let (qualifier, field) = sa.input.schema().qualified_field(idx);
    Some(datafusion::common::Column::new(
        qualifier.cloned(),
        field.name(),
    ))
}

fn constant_join_error() -> DataFusionError {
    DataFusionError::Plan(
        "cannot join on a masked column whose mask is a constant: the join condition would \
         compare constants and match every row pair"
            .to_string(),
    )
}

/// The form a mask takes when substituted for a correlated outer reference:
/// its own references to `column` (bound to `rel`) become
/// `OuterReferenceColumn`s of `field`.
fn as_outer_reference(
    mask: Expr,
    field: &datafusion::arrow::datatypes::FieldRef,
    column: &str,
    rel: &TableReference,
) -> Expr {
    mask.transform_down(|m| match m {
        Expr::Column(c)
            if c.name == column && c.relation.as_ref().is_none_or(|r| r.resolved_eq(rel)) =>
        {
            Ok(Transformed::new(
                Expr::OuterReferenceColumn(Arc::clone(field), c),
                true,
                TreeNodeRecursion::Jump,
            ))
        }
        other => Ok(Transformed::no(other)),
    })
    .expect("pure Expr rewrite never fails")
    .data
}

/// The row filters actually injected into a plan are those on the tables it
/// scans (by the name each scan carries, never an alias).
type ScannedTables = std::collections::HashSet<TableReference>;

/// The tables a scope scans DIRECTLY — not those of its child scopes
/// (embedded subqueries, derived tables, UNION branches). A row filter is
/// injected at the scan of its table, so the filters active for a scope's
/// own predicates are those on the enclosing scopes' direct scans plus its
/// own; a child scope's filter is never active in its parent or siblings
/// (treating it so reopened the oracle for a parent predicate on a column
/// that filter reads). When the optimizer later flattens a subquery or a
/// derived table into this scope, its scans become direct scans here and
/// the next pass sees them.
fn direct_scans(plan: &LogicalPlan) -> ScannedTables {
    let mut direct = ScannedTables::new();
    plan.apply(|node| {
        if !scope_children(node).is_empty() {
            return Ok(TreeNodeRecursion::Jump);
        }
        if let LogicalPlan::TableScan(scan) = node {
            direct.insert(scan.table_name.clone());
        }
        Ok(TreeNodeRecursion::Continue)
    })
    .expect("infallible walk");
    direct
}

/// Per-rewrite memo of RLS-exempt columns by table (see
/// [`ColumnMaskingEnforcer::is_rls_exempt`]).
type ExemptCache = std::cell::RefCell<HashMap<TableReference, std::collections::HashSet<String>>>;

/// The `(relation, column)` a plain or outer-reference column expression
/// names; `None` for anything else or an unqualified reference.
fn referenced_column(e: &Expr) -> Option<(&TableReference, &str)> {
    match e {
        Expr::Column(c) | Expr::OuterReferenceColumn(_, c) => {
            c.relation.as_ref().map(|rel| (rel, c.name.as_str()))
        }
        _ => None,
    }
}

/// `Transformed::yes`/`no` per `changed`, default recursion.
fn flag(plan: LogicalPlan, changed: bool) -> Transformed<LogicalPlan> {
    if changed {
        Transformed::yes(plan)
    } else {
        Transformed::no(plan)
    }
}

impl ColumnMaskingEnforcer {
    /// [`PolicyEnforcer::explain`] with references resolved scope by scope
    /// (`scope_aliases`/`scope_children`, the SAME resolution the rewrite
    /// uses: a subquery's or a UNION branch's `u` is not the outer `u`) and
    /// the same RLS-exemption decision in predicate positions (Filter, scan
    /// filters, Join, Sort): a column the active row filter exempts and that
    /// the query reads only in a predicate is not masked anywhere, so it is
    /// not reported; an output position is always masked.
    fn explain_scope(
        &self,
        plan: &LogicalPlan,
        identity: &Identity,
        enclosing: &HashMap<TableReference, TableReference>,
        enclosing_scans: &ScannedTables,
        out: &mut Vec<crate::PolicyDecision>,
    ) {
        use crate::{PolicyAction, PolicyDecision};
        let alias_map = scope_aliases(plan, enclosing);
        let mut scanned = enclosing_scans.clone();
        scanned.extend(direct_scans(plan));
        // Exemptions depend on the active scans, which differ per scope:
        // memoise per scope, as the rewrite does.
        let cache: ExemptCache = std::cell::RefCell::new(HashMap::new());
        let mut nested: Vec<Arc<LogicalPlan>> = Vec::new();
        plan.apply(|node| {
            let children = scope_children(node);
            if !children.is_empty() {
                nested.extend(children);
                return Ok(TreeNodeRecursion::Jump);
            }
            let predicate_position = matches!(
                node,
                LogicalPlan::Filter(_)
                    | LogicalPlan::TableScan(_)
                    | LogicalPlan::Join(_)
                    | LogicalPlan::Sort(_)
            );
            for e in node.expressions() {
                e.apply(|x| {
                    // `lookup_mask` is the SAME matcher the rewrite uses
                    // (candidate qualifications, session-default upgrade, org
                    // filter), so explain reports exactly what rewrite masks.
                    if let Some((rel, name)) = referenced_column(x) {
                        let exempt = predicate_position
                            && self
                                .is_rls_exempt(rel, name, &alias_map, identity, &cache, &scanned);
                        if !exempt && self.lookup_mask(rel, name, &alias_map, identity).is_some() {
                            let resource = format!("{rel}.{name}");
                            if !out.iter().any(|d| d.resource == resource) {
                                out.push(PolicyDecision::new(
                                    PolicyAction::Mask,
                                    resource,
                                    "column value masked at projection",
                                ));
                            }
                        }
                    } else if let Some(sub) = crate::embedded_subquery(x) {
                        nested.push(Arc::clone(sub));
                    }
                    Ok(TreeNodeRecursion::Continue)
                })
                .expect("infallible walk");
            }
            Ok(TreeNodeRecursion::Continue)
        })
        .expect("infallible walk");
        for sub in nested {
            self.explain_scope(&sub, identity, &alias_map, &scanned, out);
        }
    }

    /// [`PolicyEnforcer::rewrite`] with the alias→table map of the enclosing
    /// plans inherited: a correlated subquery references the outer relation
    /// by its alias (`u.email` in `EXISTS (… WHERE u.email = …)`), and that
    /// alias is declared in the OUTER plan, not the subquery.
    fn rewrite_with(
        &self,
        plan: LogicalPlan,
        identity: &Identity,
        inherited: &HashMap<TableReference, TableReference>,
        enclosing_scans: &ScannedTables,
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
        // This scope's relations shadow the inherited ones (`scope_aliases`).
        let alias_map = scope_aliases(&plan, inherited);
        // RLS exemptions resolved once per (table, session) for this rewrite,
        // and only from row filters whose table this plan actually scans.
        let cache: ExemptCache = std::cell::RefCell::new(HashMap::new());
        // The enclosing scopes' scans stay active inside a subquery: an
        // injected row filter `EXISTS (SELECT 1 … WHERE users.email <> …)`
        // is exempt because the OUTER `users` scan is filtered, and a pass
        // that descends into that subquery must still see it.
        // The row filters active here: on the enclosing scopes' direct scans
        // and this scope's own (`direct_scans`); child scopes inherit the
        // same — never a sibling's.
        let mut scanned = enclosing_scans.clone();
        scanned.extend(direct_scans(&plan));

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
            // (0) Scope boundaries: each UNION branch and each derived table
            // is rewritten as its own scope (own relations; this scope's map
            // as its enclosing one) and skipped by this walk.
            if !scope_children(&node).is_empty() {
                let out = node.map_children(|child| {
                    self.rewrite_with(child, identity, &alias_map, &scanned)
                })?;
                return Ok(Transformed::new(
                    out.data,
                    out.transformed,
                    TreeNodeRecursion::Jump,
                ));
            }

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
                        let out = self.rewrite_with(
                            std::sync::Arc::unwrap_or_clone(subplan),
                            identity,
                            &alias_map,
                            &scanned,
                        )?;
                        Ok(out.update_data(std::sync::Arc::new))
                    })
                })
            })?;

            // (2a) Predicates, join conditions, sort keys and pushed-down scan
            // filters (see `mask_predicate_positions`).
            let node = match self.mask_predicate_positions(
                node,
                &alias_map,
                identity,
                sub_changed,
                &cache,
                &scanned,
            )? {
                Ok(done) => return Ok(done),
                Err(node) => node,
            };

            // (2b) Output-reaching positions (projection, aggregate, window,
            // …): substitute the mask and alias it back to the original
            // derived field name so the node's output schema is unchanged
            // (avoids the `optimize_projections` invariant panic on an
            // un-aliased `UPPER(email)` — ).
            let Transformed {
                data: node,
                transformed: masked,
                ..
            } = node.map_expressions(|e| self.mask_expr(e, &alias_map, identity))?;

            Ok(if masked || sub_changed {
                Transformed::yes(node)
            } else {
                Transformed::no(node)
            })
        })
    }
}

impl Clone for ColumnMaskingEnforcer {
    fn clone(&self) -> Self {
        Self {
            masks: Arc::clone(&self.masks),
            rls: self.rls.clone(),
            session_defaults: self.session_defaults.clone(),
            warned_unfireable: Arc::clone(&self.warned_unfireable),
        }
    }
}

impl PolicyEnforcer for ColumnMaskingEnforcer {
    fn with_rls_sources(
        &self,
        sources: Vec<Arc<dyn PolicyEnforcer>>,
    ) -> Option<Arc<dyn PolicyEnforcer>> {
        let mut copy = self.clone();
        copy.rls.extend(sources);
        Some(Arc::new(copy))
    }

    fn explain(&self, plan: &LogicalPlan, identity: &Identity) -> Vec<crate::PolicyDecision> {
        if self.masks.is_empty() {
            return Vec::new();
        }
        let mut out = Vec::new();
        self.explain_scope(
            plan,
            identity,
            &HashMap::new(),
            &ScannedTables::new(),
            &mut out,
        );
        out
    }

    fn rewrite(
        &self,
        plan: LogicalPlan,
        identity: &Identity,
    ) -> Result<Transformed<LogicalPlan>, DataFusionError> {
        self.rewrite_with(plan, identity, &HashMap::new(), &ScannedTables::new())
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

    ///  (Urgent) — the predicate value oracle is closed: a user `WHERE`
    /// on a masked column evaluates on the MASKED value, so probing the real
    /// value (`= 'alice@example.com'`, `LIKE 'alice%'`) matches nothing, while
    /// the mask value matches every row. (Supersedes the original "option A"
    /// rule, under which predicates saw real data.)
    #[tokio::test]
    async fn column_mask_predicates_evaluate_on_the_masked_value() {
        let (ctx, users) = ctx_with_users();
        let enforcer = ColumnMaskingEnforcer::new([mask_email_literal(&users)]).expect("build");

        let plan = rewrite_sql(
            &ctx,
            &enforcer,
            "SELECT email FROM users WHERE email = 'alice@example.com'",
        )
        .await;
        let rows = execute_plan(&ctx, plan).await;
        assert!(rows.is_empty(), "exact-match oracle closed; got {rows:?}");

        let plan = rewrite_sql(
            &ctx,
            &enforcer,
            "SELECT id FROM users WHERE email LIKE 'alice%'",
        )
        .await;
        let rows = execute_plan(&ctx, plan).await;
        assert!(rows.is_empty(), "prefix oracle closed; got {rows:?}");

        let plan = rewrite_sql(
            &ctx,
            &enforcer,
            "SELECT id, email FROM users WHERE email = '***@example.com' ORDER BY id",
        )
        .await;
        let rows = execute_plan(&ctx, plan).await;
        assert_eq!(
            rows.len(),
            3,
            "the predicate sees the mask ⇒ every row; got {rows:?}"
        );
        for row in &rows {
            assert_eq!(row[1], "***@example.com", "projection is masked");
        }
    }

    ///  — a join condition on a masked column compares masked values
    /// (Snowflake semantics). With a deterministic non-literal mask (`md5`)
    /// equality is preserved, so a self-join on email still yields one row
    /// per user — on masked values.
    #[tokio::test]
    async fn column_mask_join_condition_sees_masked_values() {
        let (ctx, users) = ctx_with_users();
        let enforcer = ColumnMaskingEnforcer::new([ColumnMask {
            table: users.clone(),
            column: "email".to_string(),
            mask: crate::MaskKind::Hash.to_expr("email"),
            org: None,
            groups: None,
        }])
        .expect("build");
        let plan = rewrite_sql(
            &ctx,
            &enforcer,
            "SELECT u.id, v.id FROM users u JOIN users v ON u.email = v.email ORDER BY u.id",
        )
        .await;
        let mut saw_masked_key = false;
        plan.apply(|n| {
            if let LogicalPlan::Join(j) = n {
                let exprs: Vec<&Expr> =
                    j.on.iter()
                        .flat_map(|(l, r)| [l, r])
                        .chain(j.filter.iter())
                        .collect();
                // The mask itself reads `email` (`md5(CAST(email …))`), so the
                // check is that no BARE email reference is compared: the
                // displayed condition must not contain `u.email = v.email`.
                let shown = exprs
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(" ");
                saw_masked_key = shown.contains("md5") && !shown.contains("u.email = v.email");
            }
            Ok(datafusion::common::tree_node::TreeNodeRecursion::Continue)
        })
        .unwrap();
        assert!(
            saw_masked_key,
            "join condition compares masked values: {plan}"
        );
        let rows = execute_plan(&ctx, plan).await;
        assert_eq!(
            rows.len(),
            3,
            "hash-equality preserves the self-join; got {rows:?}"
        );
        // Projecting the masked column over the self-join binds the mask's
        // own reference to the right alias (no "ambiguous reference").
        let plan = rewrite_sql(
            &ctx,
            &enforcer,
            "SELECT u.email, v.email FROM users u JOIN users v ON u.id = v.id",
        )
        .await;
        // (md5 yields Utf8View, which the string helper renders opaquely; the
        // point here is that the query plans and executes unambiguously.)
        let rows = execute_plan(&ctx, plan).await;
        assert_eq!(rows.len(), 3);
    }

    ///  — a predicate already pushed into `TableScan.filters` (a later
    /// optimizer pass) is masked too; otherwise the probe would reach the
    /// remote source verbatim.
    #[tokio::test]
    async fn column_mask_reaches_pushed_down_scan_filters() {
        use datafusion::datasource::provider_as_source;
        use datafusion::logical_expr::{col, lit, LogicalPlanBuilder};

        let (ctx, users) = ctx_with_users();
        let enforcer = ColumnMaskingEnforcer::new([mask_email_literal(&users)]).expect("build");
        let provider = ctx.table_provider("users").await.expect("provider");
        let plan = LogicalPlanBuilder::scan_with_filters(
            users.clone(),
            provider_as_source(provider),
            None,
            // Qualified, as the planner leaves pushed-down predicates.
            vec![Expr::Column(datafusion::common::Column::new(
                Some(users.clone()),
                "email",
            ))
            .eq(lit("alice@example.com"))],
        )
        .expect("scan")
        .project(vec![col("id")])
        .expect("project")
        .build()
        .expect("build");
        let out = enforcer
            .rewrite(plan, &crate::Identity::anonymous())
            .expect("rewrite");
        assert!(out.transformed, "scan filter must be rewritten");
        let LogicalPlan::Projection(p) = &out.data else {
            panic!("projection on top")
        };
        let LogicalPlan::TableScan(scan) = p.input.as_ref() else {
            panic!("scan below")
        };
        let filter = format!("{:?}", scan.filters[0]);
        assert!(
            filter.contains("***@example.com"),
            "masked scan filter: {filter}"
        );
        assert!(
            !filter.contains("Column"),
            "no raw column reference left: {filter}"
        );
    }

    ///  — columns an admin row filter references are exempt from
    /// predicate masking, so RLS keeps evaluating on real data (and so does a
    /// user predicate on that column — documented); the projection stays
    /// masked.
    #[tokio::test]
    async fn rls_referenced_columns_keep_real_values_in_predicates() {
        use datafusion::logical_expr::{col, lit};

        let (ctx, users) = ctx_with_users();
        let rls = crate::RowFilter {
            table: users.clone(),
            predicate: col("email").like(lit("alice%")),
            org: None,
            groups: None,
        };
        let rls = Arc::new(RowFilterEnforcer::new([rls]).expect("build rls"));
        let enforcer = ColumnMaskingEnforcer::new([mask_email_literal(&users)])
            .expect("build")
            .with_row_filter_exemptions(rls);
        let plan = rewrite_sql(
            &ctx,
            &enforcer,
            "SELECT id, email FROM users WHERE email = 'alice@example.com'",
        )
        .await;
        let rows = execute_plan(&ctx, plan).await;
        assert_eq!(rows.len(), 1, "exempt column: predicate on the real value");
        assert_eq!(rows[0][1], "***@example.com", "projection still masked");
    }

    ///  — a sort key that becomes a constant under a literal mask is
    /// dropped (`ORDER BY '***'` is invalid on PostgreSQL and orders nothing);
    /// a Sort left with no keys collapses to its LIMIT.
    #[tokio::test]
    async fn literal_masked_sort_key_is_dropped_and_limit_kept() {
        let (ctx, users) = ctx_with_users();
        let enforcer = ColumnMaskingEnforcer::new([mask_email_literal(&users)]).expect("build");
        let plan = rewrite_sql(
            &ctx,
            &enforcer,
            "SELECT id FROM users ORDER BY email LIMIT 2",
        )
        .await;
        let mut sorts = 0usize;
        let mut has_limit = false;
        plan.apply(|n| {
            match n {
                LogicalPlan::Sort(s) => {
                    sorts += 1;
                    assert!(
                        s.expr.iter().all(|e| !e.expr.column_refs().is_empty()),
                        "no constant sort key: {:?}",
                        s.expr
                    );
                }
                LogicalPlan::Limit(_) => has_limit = true,
                _ => {}
            }
            Ok(datafusion::common::tree_node::TreeNodeRecursion::Continue)
        })
        .unwrap();
        assert_eq!(sorts, 0, "the constant-only Sort is gone");
        assert!(has_limit, "LIMIT survives");
        let rows = execute_plan(&ctx, plan).await;
        assert_eq!(rows.len(), 2);
        // A mixed key list keeps the real key.
        let plan = rewrite_sql(
            &ctx,
            &enforcer,
            "SELECT id FROM users ORDER BY email, id DESC",
        )
        .await;
        let rows = execute_plan(&ctx, plan).await;
        assert_eq!(
            rows.iter().map(|r| r[0].as_str()).collect::<Vec<_>>(),
            ["3", "2", "1"]
        );
    }

    ///  — a correlated outer reference to the masked column inside a
    /// subquery predicate (`EXISTS (… WHERE u.email = …)`) is masked too.
    #[tokio::test]
    async fn column_mask_reaches_correlated_outer_references() {
        let (ctx, users) = ctx_with_users();
        let enforcer = ColumnMaskingEnforcer::new([mask_email_literal(&users)]).expect("build");
        let plan = rewrite_sql(
            &ctx,
            &enforcer,
            "SELECT u.id FROM users u WHERE EXISTS \
             (SELECT 1 FROM users v WHERE v.id = u.id AND u.email = 'alice@example.com')",
        )
        .await;
        let rows = execute_plan(&ctx, plan).await;
        assert!(
            rows.is_empty(),
            "outer-reference oracle closed; got {rows:?}"
        );
        let plan = rewrite_sql(
            &ctx,
            &enforcer,
            "SELECT u.id FROM users u WHERE EXISTS \
             (SELECT 1 FROM users v WHERE v.id = u.id AND u.email = '***@example.com')",
        )
        .await;
        let rows = execute_plan(&ctx, plan).await;
        assert_eq!(
            rows.len(),
            3,
            "the mask value matches for every row; got {rows:?}"
        );
    }

    ///  — a row-filter exemption is scoped to the sessions that filter
    /// applies to: another tenant's row filter on `email` does not open the
    /// oracle for this tenant.
    #[tokio::test]
    async fn rls_exemption_is_scoped_to_the_filter_identity() {
        use datafusion::logical_expr::{col, lit};

        let (ctx, users) = ctx_with_users();
        let other_tenant = crate::RowFilter {
            table: users.clone(),
            predicate: col("email").like(lit("alice%")),
            org: Some("other-tenant".to_string()),
            groups: None,
        };
        let rls = Arc::new(RowFilterEnforcer::new([other_tenant]).expect("build rls"));
        let enforcer = ColumnMaskingEnforcer::new([mask_email_literal(&users)])
            .expect("build")
            .with_row_filter_exemptions(rls);
        let plan = rewrite_sql(
            &ctx,
            &enforcer,
            "SELECT id FROM users WHERE email = 'alice@example.com'",
        )
        .await;
        let rows = execute_plan(&ctx, plan).await;
        assert!(
            rows.is_empty(),
            "another tenant's filter must not exempt this session; got {rows:?}"
        );
    }

    ///  — joining on two literal-masked keys would compare constants
    /// and match every pair: rejected with a plan error instead.
    #[tokio::test]
    async fn join_on_two_literal_masked_keys_is_rejected() {
        let (ctx, users) = ctx_with_users();
        let enforcer = ColumnMaskingEnforcer::new([mask_email_literal(&users)]).expect("build");
        let plan = ctx
            .sql("SELECT u.id, v.id FROM users u JOIN users v ON u.email = v.email")
            .await
            .expect("plan")
            .logical_plan()
            .clone();
        let err = enforcer
            .rewrite(plan, &crate::Identity::anonymous())
            .expect_err("constant-vs-constant join key must be rejected");
        assert!(err.to_string().contains("masked column"), "{err}");
    }

    ///  — a row filter on a table the plan does NOT scan is not
    /// injected and must not exempt anything, even if its predicate reads the
    /// masked column of the scanned table.
    #[tokio::test]
    async fn rls_exemption_requires_the_filtered_table_to_be_scanned() {
        use datafusion::logical_expr::{col, lit};

        let (ctx, users) = ctx_with_users();
        let unrelated = crate::RowFilter {
            table: TableReference::bare("orders_probe"),
            predicate: col("email").like(lit("alice%")),
            org: None,
            groups: None,
        };
        let rls = Arc::new(RowFilterEnforcer::new([unrelated]).expect("build rls"));
        let enforcer = ColumnMaskingEnforcer::new([mask_email_literal(&users)])
            .expect("build")
            .with_row_filter_exemptions(rls);
        let plan = rewrite_sql(
            &ctx,
            &enforcer,
            "SELECT id FROM users WHERE email = 'alice@example.com'",
        )
        .await;
        let rows = execute_plan(&ctx, plan).await;
        assert!(
            rows.is_empty(),
            "an unscanned table's filter exempts nothing; got {rows:?}"
        );
    }

    ///  — the exemption follows row-filter precedence: for a tenant
    /// session, a tenant-scoped filter on `id` shadows an operator-wide filter
    /// on `email`, so `email` is NOT exempt and stays masked in predicates.
    #[tokio::test]
    async fn rls_exemption_follows_filter_precedence() {
        use datafusion::logical_expr::{col, lit};

        let (ctx, users) = ctx_with_users();
        let rls = Arc::new(
            RowFilterEnforcer::new([
                crate::RowFilter {
                    table: users.clone(),
                    predicate: col("email").like(lit("%")),
                    org: None,
                    groups: None,
                },
                crate::RowFilter {
                    table: users.clone(),
                    predicate: col("id").gt(lit(0_i32)),
                    org: Some("acme".to_string()),
                    groups: None,
                },
            ])
            .expect("build rls"),
        );
        let enforcer = ColumnMaskingEnforcer::new([mask_email_literal(&users)])
            .expect("build")
            .with_row_filter_exemptions(rls);
        let tenant = crate::Identity::anonymous().with_org("acme");
        let plan = ctx
            .sql("SELECT id FROM users WHERE email = 'alice@example.com'")
            .await
            .expect("plan")
            .logical_plan()
            .clone();
        let plan = enforcer.rewrite(plan, &tenant).expect("rewrite").data;
        let rows = execute_plan(&ctx, plan).await;
        assert!(
            rows.is_empty(),
            "shadowed operator-wide filter must not exempt email; got {rows:?}"
        );
    }

    ///  — `FROM users u, users v WHERE u.email = v.email` plans as a
    /// Filter over a cross join; the masked predicate folds to TRUE, which
    /// would leave the full cross product — refused like a constant join key.
    #[tokio::test]
    async fn masked_filter_over_cross_join_folding_to_true_is_rejected() {
        let (ctx, users) = ctx_with_users();
        let enforcer = ColumnMaskingEnforcer::new([mask_email_literal(&users)]).expect("build");
        let plan = ctx
            .sql("SELECT u.id FROM users u, users v WHERE u.email = v.email")
            .await
            .expect("plan")
            .logical_plan()
            .clone();
        let err = enforcer
            .rewrite(plan, &crate::Identity::anonymous())
            .expect_err("constant-true masked filter over a cross join must be rejected");
        assert!(err.to_string().contains("masked column"), "{err}");
    }

    ///  — `ON u.email = v.email AND u.id = v.id` under a literal mask:
    /// the constant email pair is dropped, `id` still restricts the join, and
    /// the query is allowed (one row per user).
    #[tokio::test]
    async fn join_keeps_restrictive_key_when_masked_pair_is_constant() {
        let (ctx, users) = ctx_with_users();
        let enforcer = ColumnMaskingEnforcer::new([mask_email_literal(&users)]).expect("build");
        let plan = rewrite_sql(
            &ctx,
            &enforcer,
            "SELECT u.id FROM users u JOIN users v ON u.email = v.email AND u.id = v.id",
        )
        .await;
        let rows = execute_plan(&ctx, plan).await;
        assert_eq!(rows.len(), 3, "id still restricts the join; got {rows:?}");
    }

    ///  — two DIFFERENT literal masks on the joined columns compare
    /// two constants that are never equal: the join is empty, not a cross
    /// product, and is allowed through.
    #[tokio::test]
    async fn join_on_two_different_literal_masks_is_allowed_and_empty() {
        use datafusion::logical_expr::lit;

        let (ctx, users) = ctx_with_users();
        let batch = datafusion::arrow::record_batch::RecordBatch::try_from_iter(vec![(
            "email",
            Arc::new(datafusion::arrow::array::StringArray::from(vec![
                "alice@example.com",
            ])) as datafusion::arrow::array::ArrayRef,
        )])
        .unwrap();
        ctx.register_batch("orders_probe", batch).unwrap();
        let enforcer = ColumnMaskingEnforcer::new([
            mask_email_literal(&users),
            ColumnMask {
                table: TableReference::bare("orders_probe"),
                column: "email".to_string(),
                mask: lit("###"),
                org: None,
                groups: None,
            },
        ])
        .expect("build");
        let plan = rewrite_sql(
            &ctx,
            &enforcer,
            "SELECT u.id FROM users u JOIN orders_probe o ON u.email = o.email",
        )
        .await;
        let rows = execute_plan(&ctx, plan).await;
        assert!(rows.is_empty(), "'***' = '###' is never true; got {rows:?}");
    }

    ///  — `ON u.email = v.email OR u.id = v.id` under a literal mask
    /// folds to TRUE (`'***' = '***' OR …`): rejected like a constant key.
    #[tokio::test]
    async fn join_condition_that_folds_to_true_is_rejected() {
        let (ctx, users) = ctx_with_users();
        let enforcer = ColumnMaskingEnforcer::new([mask_email_literal(&users)]).expect("build");
        let plan = ctx
            .sql("SELECT u.id FROM users u JOIN users v ON u.email = v.email OR u.id = v.id")
            .await
            .expect("plan")
            .logical_plan()
            .clone();
        let err = enforcer
            .rewrite(plan, &crate::Identity::anonymous())
            .expect_err("constant-true masked join condition must be rejected");
        assert!(err.to_string().contains("masked column"), "{err}");
    }

    ///  — a second optimizer pass is a no-op, including for a mask that
    /// embeds its column (`md5`): the already-substituted mask is recognised
    /// per identity and not nested again.
    #[tokio::test]
    async fn masking_is_idempotent_across_passes() {
        let (ctx, users) = ctx_with_users();
        for mask in [
            crate::MaskKind::Hash.to_expr("email"),
            crate::MaskKind::PartialShowLast(4).to_expr("email"),
        ] {
            let enforcer = ColumnMaskingEnforcer::new([ColumnMask {
                table: users.clone(),
                column: "email".to_string(),
                mask,
                org: None,
                groups: None,
            }])
            .expect("build");
            let plan = ctx
                .sql("SELECT id, email FROM users WHERE email LIKE 'a%' ORDER BY email")
                .await
                .expect("plan")
                .logical_plan()
                .clone();
            let once = enforcer
                .rewrite(plan, &crate::Identity::anonymous())
                .expect("first pass");
            assert!(once.transformed);
            let twice = enforcer
                .rewrite(once.data.clone(), &crate::Identity::anonymous())
                .expect("second pass");
            assert!(!twice.transformed, "second pass must be a no-op");
            assert_eq!(
                format!("{}", twice.data.display_indent()),
                format!("{}", once.data.display_indent())
            );
        }
    }

    ///  — masks are applied on every optimizer pass; the `MaskKind`
    /// masks are idempotent by nature, so a second pass yields the same rows.
    #[tokio::test]
    async fn second_pass_yields_the_same_rows() {
        let (ctx, users) = ctx_with_users();
        let enforcer = ColumnMaskingEnforcer::new([ColumnMask {
            table: users.clone(),
            column: "email".to_string(),
            mask: crate::MaskKind::PartialShowLast(4).to_expr("email"),
            org: None,
            groups: None,
        }])
        .expect("build");
        let plan = ctx
            .sql("SELECT id, email FROM users WHERE email LIKE 'a%' ORDER BY id")
            .await
            .expect("plan")
            .logical_plan()
            .clone();
        let once = enforcer
            .rewrite(plan, &crate::Identity::anonymous())
            .expect("first pass")
            .data;
        let twice = enforcer
            .rewrite(once.clone(), &crate::Identity::anonymous())
            .expect("second pass")
            .data;
        let rows1 = execute_plan(&ctx, once).await;
        let rows2 = execute_plan(&ctx, twice).await;
        assert_eq!(rows1, rows2);
        // The prefix probe matched nothing: every masked value starts with X.
        assert!(rows1.is_empty(), "{rows1:?}");
    }

    ///  — composing masks with row filters through
    /// `CompositeEnforcer` wires the exemption automatically, in either
    /// order, so an admin filter on the masked column keeps evaluating on
    /// real data across passes while the projection stays masked.
    #[tokio::test]
    async fn composite_wires_row_filter_exemptions_in_either_order() {
        use datafusion::logical_expr::{col, lit};

        let (ctx, users) = ctx_with_users();
        let mask: Arc<dyn PolicyEnforcer> =
            Arc::new(ColumnMaskingEnforcer::new([mask_email_literal(&users)]).expect("build"));
        let rls: Arc<dyn PolicyEnforcer> = Arc::new(
            RowFilterEnforcer::new([crate::RowFilter {
                table: users.clone(),
                predicate: col("email").like(lit("alice%")),
                org: None,
                groups: None,
            }])
            .expect("build rls"),
        );
        for layers in [
            vec![Arc::clone(&mask), Arc::clone(&rls)],
            vec![Arc::clone(&rls), Arc::clone(&mask)],
        ] {
            let composite = crate::CompositeEnforcer::new(layers);
            let plan = ctx
                .sql("SELECT id, email FROM users")
                .await
                .expect("plan")
                .logical_plan()
                .clone();
            let identity = crate::Identity::anonymous();
            let once = composite.rewrite(plan, &identity).expect("pass 1").data;
            let twice = composite.rewrite(once, &identity).expect("pass 2").data;
            let rows = execute_plan(&ctx, twice).await;
            assert_eq!(
                rows.len(),
                1,
                "RLS on the real value keeps Alice only; got {rows:?}"
            );
            assert_eq!(rows[0][1], "***@example.com", "projection masked");
        }
    }

    ///  (Urgent) — masking must NOT be bypassable through an aggregate.
    /// The mask now reaches aggregate arguments, so `max(email)` aggregates over
    /// masked values and the result is the mask, never cleartext PII. Pre-fix
    /// this leaked the real max email because masking only touched the final
    /// `Projection`.
    #[tokio::test]
    async fn column_mask_not_bypassed_by_aggregate() {
        let (ctx, users) = ctx_with_users();
        let enforcer = ColumnMaskingEnforcer::new([mask_email_literal(&users)]).expect("build");

        // Bare aggregate.
        let plan = rewrite_sql(&ctx, &enforcer, "SELECT max(email) AS m FROM users").await;
        let rows = execute_plan(&ctx, plan).await;
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0][0], "***@example.com",
            "max() over a masked column must not leak cleartext; got {rows:?}"
        );

        // The reported GROUP BY shape.
        let plan = rewrite_sql(
            &ctx,
            &enforcer,
            "SELECT id, max(email) AS m FROM users GROUP BY id ORDER BY id",
        )
        .await;
        let rows = execute_plan(&ctx, plan).await;
        assert_eq!(rows.len(), 3);
        for row in &rows {
            assert_eq!(
                row[1], "***@example.com",
                "grouped max(email) must be masked; got {rows:?}"
            );
        }
    }

    ///  (High) — a scalar function on a masked column WITHOUT an alias
    /// must not crash the optimizer. Source-level masking keeps the column name
    /// at the scan, so `upper(email)` derives its usual field name and
    /// DataFusion's schema-invariant checker is satisfied. Pre-fix the
    /// projection-level rewrite changed the derived name to `upper(Utf8("***"))`
    /// and panicked `optimize_projections`.
    #[tokio::test]
    async fn column_mask_unaliased_scalar_fn_does_not_crash_optimizer() {
        let (ctx, users) = ctx_with_users();
        let enforcer = ColumnMaskingEnforcer::new([mask_email_literal(&users)]).expect("build");
        let plan = rewrite_sql(&ctx, &enforcer, "SELECT UPPER(email) FROM users ORDER BY 1").await;
        let rows = execute_plan(&ctx, plan).await;
        assert_eq!(rows.len(), 3);
        for row in &rows {
            assert_eq!(
                row[0], "***@EXAMPLE.COM",
                "upper() over the masked value; got {rows:?}"
            );
        }
    }

    /// `ORDER BY <masked column>` must not crash: the sort key is masked in
    /// place ( — ordering by the real value is an oracle via `LIMIT`),
    /// with no alias wrapping. The query plans, executes, and the masked
    /// column is never projected as cleartext.
    #[tokio::test]
    async fn column_mask_order_by_masked_column_does_not_crash() {
        let (ctx, users) = ctx_with_users();
        let enforcer = ColumnMaskingEnforcer::new([mask_email_literal(&users)]).expect("build");
        // ORDER BY the masked column (not projected) — must not panic.
        let plan = rewrite_sql(&ctx, &enforcer, "SELECT id FROM users ORDER BY email").await;
        let rows = execute_plan(&ctx, plan).await;
        assert_eq!(rows.len(), 3, "all rows returned; got {rows:?}");
        // And when the masked column IS projected alongside the ORDER BY, it is
        // still masked in the output.
        let plan = rewrite_sql(
            &ctx,
            &enforcer,
            "SELECT id, email FROM users ORDER BY email",
        )
        .await;
        let rows = execute_plan(&ctx, plan).await;
        assert_eq!(rows.len(), 3);
        for row in &rows {
            assert_eq!(
                row[1], "***@example.com",
                "projected email masked; got {rows:?}"
            );
        }
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
    /// rewritten to the mask literal (a projection), and — since  — so
    /// is the outer `email` in the `WHERE … IN` predicate. `'***' IN (SELECT
    /// '***')` holds for every row, so all three come back, and the plan
    /// carries the mask inside the subquery — the observable proof both sides
    /// were masked.
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
        assert_eq!(
            rows.len(),
            3,
            "masked outer email IS IN the set of masked literals ⇒ every row; got {rows:?}"
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

    ///  — the exemption follows the SCANNED table's own precedence: a
    /// more-qualified rule on a sibling catalog's `users` does not shadow the
    /// bare fallback that `resolve_predicate` injects for this catalog's scan,
    /// so the fallback's `email` stays exempt (and the injected administrative
    /// predicate is never masked).
    #[tokio::test]
    async fn rls_exemption_uses_the_scanned_tables_own_precedence() {
        use datafusion::logical_expr::{col, lit};

        let (ctx, users) = ctx_with_users();
        let rls = Arc::new(
            RowFilterEnforcer::new([
                crate::RowFilter {
                    table: TableReference::full("other_cat", "public", "users"),
                    predicate: col("id").gt(lit(0_i32)),
                    org: None,
                    groups: None,
                },
                crate::RowFilter {
                    table: TableReference::bare("users"),
                    predicate: col("email").not_eq(lit("blocked")),
                    org: None,
                    groups: None,
                },
            ])
            .expect("build rls"),
        );
        let enforcer = ColumnMaskingEnforcer::new([mask_email_literal(&users)])
            .expect("build")
            .with_row_filter_exemptions(rls);
        let plan = rewrite_sql(
            &ctx,
            &enforcer,
            "SELECT id FROM users WHERE email = 'alice@example.com'",
        )
        .await;
        let rows = execute_plan(&ctx, plan).await;
        assert_eq!(
            rows.len(),
            1,
            "the bare fallback applies to this scan and exempts email; got {rows:?}"
        );
    }

    ///  — an unaliased scan inside a subquery shadows an enclosing alias
    /// of the same name: `FROM users orders_probe WHERE EXISTS (SELECT … FROM
    /// orders_probe …)` — the inner `orders_probe.email` is the physical table
    /// (unmasked here), not the outer alias of masked `users`.
    #[tokio::test]
    async fn inner_scan_shadows_enclosing_alias_of_the_same_name() {
        let (ctx, users) = ctx_with_users();
        let batch = datafusion::arrow::record_batch::RecordBatch::try_from_iter(vec![(
            "email",
            Arc::new(datafusion::arrow::array::StringArray::from(vec![
                "alice@example.com",
            ])) as datafusion::arrow::array::ArrayRef,
        )])
        .unwrap();
        ctx.register_batch("orders_probe", batch).unwrap();
        let enforcer = ColumnMaskingEnforcer::new([mask_email_literal(&users)]).expect("build");
        let plan = rewrite_sql(
            &ctx,
            &enforcer,
            "SELECT orders_probe.id FROM users orders_probe WHERE EXISTS \
             (SELECT 1 FROM orders_probe WHERE orders_probe.email = 'alice@example.com')",
        )
        .await;
        let rows = execute_plan(&ctx, plan).await;
        assert_eq!(
            rows.len(),
            3,
            "the inner physical orders_probe.email must not inherit users' mask; got {rows:?}"
        );
    }

    ///  — `FROM u, v WHERE u.email = v.email AND u.id > 0` under a
    /// literal mask leaves `TRUE AND u.id > 0`: a one-sided residual over the
    /// cross product, rejected like the constant-true case.
    #[tokio::test]
    async fn masked_cross_join_filter_with_one_sided_residual_is_rejected() {
        let (ctx, users) = ctx_with_users();
        let enforcer = ColumnMaskingEnforcer::new([mask_email_literal(&users)]).expect("build");
        let plan = ctx
            .sql("SELECT u.id FROM users u, users v WHERE u.email = v.email AND u.id > 0")
            .await
            .expect("plan")
            .logical_plan()
            .clone();
        let err = enforcer
            .rewrite(plan, &crate::Identity::anonymous())
            .expect_err("one-sided residual over a cross join must be rejected");
        assert!(err.to_string().contains("masked column"), "{err}");
    }

    ///  — a cross-join predicate that still relates both inputs after
    /// masking (`'***' <> 'x' AND u.id = v.id`) is allowed.
    #[tokio::test]
    async fn masked_cross_join_filter_keeping_a_cross_term_is_allowed() {
        let (ctx, users) = ctx_with_users();
        let enforcer = ColumnMaskingEnforcer::new([mask_email_literal(&users)]).expect("build");
        let plan = rewrite_sql(
            &ctx,
            &enforcer,
            "SELECT u.id FROM users u, users v WHERE u.email <> 'x' AND u.id = v.id",
        )
        .await;
        let rows = execute_plan(&ctx, plan).await;
        assert_eq!(rows.len(), 3, "id still relates the inputs; got {rows:?}");
    }

    ///  — `ON u.email = v.email AND u.id > 0 AND v.id > 0`: the masked
    /// key is dropped and the surviving filter spans both schemas, but no
    /// single term relates them — the product of two filtered inputs. Rejected.
    #[tokio::test]
    async fn join_filter_with_separable_conjuncts_is_rejected() {
        let (ctx, users) = ctx_with_users();
        let enforcer = ColumnMaskingEnforcer::new([mask_email_literal(&users)]).expect("build");
        let plan = ctx
            .sql(
                "SELECT u.id FROM users u JOIN users v \
                 ON u.email = v.email AND u.id > 0 AND v.id > 0",
            )
            .await
            .expect("plan")
            .logical_plan()
            .clone();
        let err = enforcer
            .rewrite(plan, &crate::Identity::anonymous())
            .expect_err("separable one-sided terms must not count as relating the inputs");
        assert!(err.to_string().contains("masked column"), "{err}");
    }

    ///  — explain resolves aliases per scope: the outer `u` is `users`
    /// even when a subquery re-uses `u` for another table.
    #[tokio::test]
    async fn explain_resolves_aliases_per_scope() {
        let (ctx, users) = ctx_with_users_and_orders();
        let enforcer = ColumnMaskingEnforcer::new([mask_email_literal(&users)]).expect("build");
        let plan = ctx
            .sql("SELECT u.email FROM users u WHERE EXISTS (SELECT 1 FROM orders u WHERE u.user_id > 0)")
            .await
            .expect("plan")
            .logical_plan()
            .clone();
        let decisions = enforcer.explain(&plan, &crate::Identity::anonymous());
        assert!(
            decisions.iter().any(|d| d.resource == "u.email"),
            "outer u.email must resolve to users.email despite the inner alias u; got {decisions:?}"
        );
    }

    ///  — an injected row filter whose predicate reads the masked column
    /// through a correlated subquery (`EXISTS (SELECT 1 FROM orders_probe
    /// WHERE orders_probe.email = users.email)`) stays exempt on the NEXT
    /// optimizer pass: descending into the subquery keeps the outer, filtered
    /// `users` scan active, so the administrative test is never masked.
    #[tokio::test]
    async fn rls_subquery_exemption_survives_a_second_pass() {
        let (ctx, users) = ctx_with_users();
        let batch = datafusion::arrow::record_batch::RecordBatch::try_from_iter(vec![(
            "email",
            Arc::new(datafusion::arrow::array::StringArray::from(vec![
                "alice@example.com",
            ])) as datafusion::arrow::array::ArrayRef,
        )])
        .unwrap();
        ctx.register_batch("orders_probe", batch).unwrap();
        // Borrow the planner for the predicate shape (correlated EXISTS).
        let shape = ctx
            .sql(
                "SELECT id FROM users WHERE EXISTS \
                 (SELECT 1 FROM orders_probe WHERE orders_probe.email = users.email)",
            )
            .await
            .expect("plan")
            .logical_plan()
            .clone();
        let mut predicate = None;
        shape
            .apply(|n| {
                if let LogicalPlan::Filter(f) = n {
                    predicate = Some(f.predicate.clone());
                }
                Ok(TreeNodeRecursion::Continue)
            })
            .expect("walk");
        let rls = Arc::new(
            RowFilterEnforcer::new([crate::RowFilter {
                table: users.clone(),
                predicate: predicate.expect("filter predicate"),
                org: None,
                groups: None,
            }])
            .expect("build rls"),
        );
        let mask = ColumnMaskingEnforcer::new([mask_email_literal(&users)])
            .expect("build")
            .with_row_filter_exemptions(Arc::clone(&rls));
        let identity = crate::Identity::anonymous();
        let plan = ctx
            .sql("SELECT id FROM users")
            .await
            .expect("plan")
            .logical_plan()
            .clone();
        // Pass 1 injects the row filter; pass 2 is the mask layer revisiting it.
        let injected = rls.rewrite(plan, &identity).expect("inject").data;
        let second = mask.rewrite(injected, &identity).expect("second pass").data;
        let rows = execute_plan(&ctx, second).await;
        assert_eq!(
            rows.len(),
            1,
            "the RLS subquery must keep reading the real email; got {rows:?}"
        );
    }

    ///  — `ON u.email = o.email` with a mask on `users.email` only:
    /// the key becomes `'***' = o.email`, a filter on `o` that no longer pairs
    /// rows — rejected like a constant key.
    #[tokio::test]
    async fn join_key_masked_on_one_side_only_is_rejected() {
        let (ctx, users) = ctx_with_users();
        let batch = datafusion::arrow::record_batch::RecordBatch::try_from_iter(vec![(
            "email",
            Arc::new(datafusion::arrow::array::StringArray::from(vec!["***"]))
                as datafusion::arrow::array::ArrayRef,
        )])
        .unwrap();
        ctx.register_batch("orders_probe", batch).unwrap();
        let enforcer = ColumnMaskingEnforcer::new([mask_email_literal(&users)]).expect("build");
        let plan = ctx
            .sql("SELECT u.id FROM users u JOIN orders_probe o ON u.email = o.email")
            .await
            .expect("plan")
            .logical_plan()
            .clone();
        let err = enforcer
            .rewrite(plan, &crate::Identity::anonymous())
            .expect_err("a key masked on one side only must be rejected");
        assert!(err.to_string().contains("masked column"), "{err}");
    }

    ///  — `ON u.email = v.email AND (u.id > 0 OR v.id > 0)`: after the
    /// masked key folds away, the disjunction spans both schemas but neither
    /// branch relates a left row to a right row — rejected.
    #[tokio::test]
    async fn join_filter_with_one_sided_disjunction_is_rejected() {
        let (ctx, users) = ctx_with_users();
        let enforcer = ColumnMaskingEnforcer::new([mask_email_literal(&users)]).expect("build");
        let plan = ctx
            .sql(
                "SELECT u.id FROM users u JOIN users v \
                 ON u.email = v.email AND (u.id > 0 OR v.id > 0)",
            )
            .await
            .expect("plan")
            .logical_plan()
            .clone();
        let err = enforcer
            .rewrite(plan, &crate::Identity::anonymous())
            .expect_err("a disjunction of one-sided terms must not count as relating");
        assert!(err.to_string().contains("masked column"), "{err}");
    }

    ///  — `ON u.email = v.email AND (u.id = v.id OR u.id < v.id)`: every
    /// branch relates the inputs, so the join is allowed (rows: 3 equal + 3
    /// less-than pairs).
    #[tokio::test]
    async fn join_filter_with_relating_disjunction_is_allowed() {
        let (ctx, users) = ctx_with_users();
        let enforcer = ColumnMaskingEnforcer::new([mask_email_literal(&users)]).expect("build");
        let plan = rewrite_sql(
            &ctx,
            &enforcer,
            "SELECT u.id FROM users u JOIN users v ON u.email = v.email AND (u.id = v.id OR u.id < v.id)",
        )
        .await;
        let rows = execute_plan(&ctx, plan).await;
        assert_eq!(
            rows.len(),
            6,
            "both branches relate the inputs; got {rows:?}"
        );
    }

    ///  — sibling UNION branches re-using one alias for different
    /// tables resolve it separately: the `users` branch's `u.email` is masked
    /// (no row), the probe branch's is not (one row).
    #[tokio::test]
    async fn union_branches_resolve_aliases_separately() {
        let (ctx, users) = ctx_with_users();
        let batch = datafusion::arrow::record_batch::RecordBatch::try_from_iter(vec![
            (
                "id",
                Arc::new(datafusion::arrow::array::Int32Array::from(vec![9]))
                    as datafusion::arrow::array::ArrayRef,
            ),
            (
                "email",
                Arc::new(datafusion::arrow::array::StringArray::from(vec![
                    "alice@example.com",
                ])) as datafusion::arrow::array::ArrayRef,
            ),
        ])
        .unwrap();
        ctx.register_batch("orders_probe", batch).unwrap();
        let enforcer = ColumnMaskingEnforcer::new([mask_email_literal(&users)]).expect("build");
        let plan = rewrite_sql(
            &ctx,
            &enforcer,
            "SELECT id FROM users u WHERE u.email = 'alice@example.com' \
             UNION ALL SELECT id FROM orders_probe u WHERE u.email = 'alice@example.com'",
        )
        .await;
        let rows = execute_plan(&ctx, plan).await;
        assert_eq!(
            rows,
            vec![vec!["9".to_string()]],
            "only the unmasked probe branch may match; got {rows:?}"
        );
    }

    ///  — an already-extracted `Join.on` key whose two sides become
    /// two DIFFERENT literal masks folds to FALSE: moved into the join filter
    /// (as a literal equi-key it paired every row at execution), counted as
    /// restrictive, allowed — and the join is empty.
    #[tokio::test]
    async fn extracted_join_key_folding_to_false_is_kept_and_allowed() {
        use datafusion::logical_expr::lit;
        use datafusion::optimizer::{Optimizer, OptimizerContext};

        let (ctx, users) = ctx_with_users();
        let batch = datafusion::arrow::record_batch::RecordBatch::try_from_iter(vec![(
            "email",
            Arc::new(datafusion::arrow::array::StringArray::from(vec![
                "alice@example.com",
            ])) as datafusion::arrow::array::ArrayRef,
        )])
        .unwrap();
        ctx.register_batch("orders_probe", batch).unwrap();
        let enforcer = ColumnMaskingEnforcer::new([
            mask_email_literal(&users),
            ColumnMask {
                table: TableReference::bare("orders_probe"),
                column: "email".to_string(),
                mask: lit("###"),
                org: None,
                groups: None,
            },
        ])
        .expect("build");
        let plan = ctx
            .sql("SELECT u.id FROM users u JOIN orders_probe o ON u.email = o.email")
            .await
            .expect("plan")
            .logical_plan()
            .clone();
        let plan = Optimizer::with_rules(vec![Arc::new(
            datafusion::optimizer::extract_equijoin_predicate::ExtractEquijoinPredicate,
        )])
        .optimize(plan, &OptimizerContext::new(), |_, _| {})
        .expect("extract equi-keys");
        let mut extracted = false;
        plan.apply(|n| {
            if let LogicalPlan::Join(j) = n {
                extracted |= !j.on.is_empty();
            }
            Ok(TreeNodeRecursion::Continue)
        })
        .expect("walk");
        assert!(extracted, "precondition: the key must sit in Join.on");
        let plan = enforcer
            .rewrite(plan, &crate::Identity::anonymous())
            .expect("a provably false key restricts the join")
            .data;
        let rows = execute_plan(&ctx, plan).await;
        assert!(rows.is_empty(), "'***' = '###' is never true; got {rows:?}");
    }

    fn register_orders_probe(ctx: &SessionContext) {
        let batch = datafusion::arrow::record_batch::RecordBatch::try_from_iter(vec![
            (
                "id",
                Arc::new(datafusion::arrow::array::Int32Array::from(vec![9]))
                    as datafusion::arrow::array::ArrayRef,
            ),
            (
                "email",
                Arc::new(datafusion::arrow::array::StringArray::from(vec![
                    "alice@example.com",
                ])) as datafusion::arrow::array::ArrayRef,
            ),
        ])
        .unwrap();
        ctx.register_batch("orders_probe", batch).unwrap();
    }

    /// The Filter predicate of a planned query — to borrow the planner for a
    /// row-filter predicate shape (subqueries) tests cannot build by hand.
    async fn filter_predicate_of(ctx: &SessionContext, sql: &str) -> Expr {
        let shape = ctx.sql(sql).await.expect("plan").logical_plan().clone();
        let mut predicate = None;
        shape
            .apply(|n| {
                if let LogicalPlan::Filter(f) = n {
                    predicate = Some(f.predicate.clone());
                }
                Ok(TreeNodeRecursion::Continue)
            })
            .expect("walk");
        predicate.expect("filter predicate")
    }

    ///  — a UNION branch does not inherit its sibling's active row
    /// filters: branch B scans `users`, whose row filter reads
    /// `orders_probe.email`; that exempts nothing in branch A, whose predicate
    /// on masked `orders_probe.email` stays masked (no row).
    #[tokio::test]
    async fn union_branch_does_not_inherit_sibling_branch_exemptions() {
        use datafusion::logical_expr::lit;

        let (ctx, users) = ctx_with_users();
        register_orders_probe(&ctx);
        let predicate = filter_predicate_of(
            &ctx,
            "SELECT id FROM users WHERE EXISTS \
             (SELECT 1 FROM orders_probe WHERE orders_probe.email <> 'blocked')",
        )
        .await;
        let rls = Arc::new(
            RowFilterEnforcer::new([crate::RowFilter {
                table: users.clone(),
                predicate,
                org: None,
                groups: None,
            }])
            .expect("build rls"),
        );
        let enforcer = ColumnMaskingEnforcer::new([ColumnMask {
            table: TableReference::bare("orders_probe"),
            column: "email".to_string(),
            mask: lit("***"),
            org: None,
            groups: None,
        }])
        .expect("build")
        .with_row_filter_exemptions(rls);
        let plan = rewrite_sql(
            &ctx,
            &enforcer,
            "SELECT id FROM orders_probe WHERE email = 'alice@example.com' \
             UNION ALL SELECT id FROM users",
        )
        .await;
        let rows = execute_plan(&ctx, plan).await;
        assert_eq!(
            rows.len(),
            3,
            "branch A must stay masked (0 rows) + 3 users; got {rows:?}"
        );
    }

    ///  — a cross join hidden behind a derived table: the inner
    /// projection masks both emails to the same constant, so the outer
    /// `x.ue = x.ve` is `'***' = '***'` once inlined — rejected.
    #[tokio::test]
    async fn cross_join_hidden_behind_a_derived_table_is_guarded() {
        let (ctx, users) = ctx_with_users();
        let enforcer = ColumnMaskingEnforcer::new([mask_email_literal(&users)]).expect("build");
        let plan = ctx
            .sql(
                "SELECT * FROM (SELECT u.email AS ue, v.email AS ve \
                 FROM users u CROSS JOIN users v) x WHERE x.ue = x.ve",
            )
            .await
            .expect("plan")
            .logical_plan()
            .clone();
        let err = enforcer
            .rewrite(plan, &crate::Identity::anonymous())
            .expect_err("constant-true condition over a hidden cross join must be rejected");
        assert!(err.to_string().contains("masked column"), "{err}");
    }

    ///  — the same shape keeping a relating term (`x.ui = x.vi`) is
    /// allowed: one row per user.
    #[tokio::test]
    async fn derived_cross_join_keeping_a_relating_term_is_allowed() {
        let (ctx, users) = ctx_with_users();
        let enforcer = ColumnMaskingEnforcer::new([mask_email_literal(&users)]).expect("build");
        let plan = rewrite_sql(
            &ctx,
            &enforcer,
            "SELECT x.ui FROM (SELECT u.id AS ui, v.id AS vi, u.email AS ue, v.email AS ve \
             FROM users u CROSS JOIN users v) x WHERE x.ue = x.ve AND x.ui = x.vi",
        )
        .await;
        let rows = execute_plan(&ctx, plan).await;
        assert_eq!(rows.len(), 3, "id still relates the inputs; got {rows:?}");
    }

    ///  — a join whose keys are derived columns that mask to the same
    /// constant (`a.ue = b.ve` over two derived tables) is rejected.
    #[tokio::test]
    async fn join_on_derived_constant_columns_is_rejected() {
        let (ctx, users) = ctx_with_users();
        let enforcer = ColumnMaskingEnforcer::new([mask_email_literal(&users)]).expect("build");
        let plan = ctx
            .sql(
                "SELECT a.ue FROM (SELECT u.email AS ue FROM users u) a \
                 JOIN (SELECT v.email AS ve FROM users v) b ON a.ue = b.ve",
            )
            .await
            .expect("plan")
            .logical_plan()
            .clone();
        let err = enforcer
            .rewrite(plan, &crate::Identity::anonymous())
            .expect_err("derived constant keys must be rejected");
        assert!(err.to_string().contains("masked column"), "{err}");
    }

    ///  — explain agrees with the rewrite on RLS exemptions: a column
    /// the active row filter exempts and that the query reads only in a
    /// predicate is not masked, so no mask decision; read in the output it is.
    #[tokio::test]
    async fn explain_omits_a_predicate_only_column_the_row_filter_exempts() {
        use datafusion::logical_expr::{col, lit};

        let (ctx, users) = ctx_with_users();
        let rls = Arc::new(
            RowFilterEnforcer::new([crate::RowFilter {
                table: users.clone(),
                predicate: col("email").like(lit("%")),
                org: None,
                groups: None,
            }])
            .expect("build rls"),
        );
        let enforcer = ColumnMaskingEnforcer::new([mask_email_literal(&users)])
            .expect("build")
            .with_row_filter_exemptions(rls);
        let identity = crate::Identity::anonymous();
        let plan = ctx
            .sql("SELECT id FROM users WHERE email = 'alice@example.com'")
            .await
            .expect("plan")
            .logical_plan()
            .clone();
        let decisions = enforcer.explain(&plan, &identity);
        assert!(
            !decisions.iter().any(|d| d.resource.contains("email")),
            "an exempt predicate-only column is not masked; got {decisions:?}"
        );
        let plan = ctx
            .sql("SELECT email FROM users WHERE email = 'alice@example.com'")
            .await
            .expect("plan")
            .logical_plan()
            .clone();
        let decisions = enforcer.explain(&plan, &identity);
        assert!(
            decisions.iter().any(|d| d.resource.contains("email")),
            "the projected email is masked; got {decisions:?}"
        );
    }

    ///  — sibling expression subqueries do not share active row
    /// filters either: subquery B scans `users`, whose row filter reads
    /// `orders_probe.email`; that exempts nothing in subquery A, whose
    /// predicate on masked `orders_probe.email` stays masked (no row).
    #[tokio::test]
    async fn sibling_subquery_does_not_inherit_the_others_exemptions() {
        use datafusion::logical_expr::lit;

        let (ctx, users) = ctx_with_users();
        register_orders_probe(&ctx);
        let predicate = filter_predicate_of(
            &ctx,
            "SELECT id FROM users WHERE EXISTS \
             (SELECT 1 FROM orders_probe WHERE orders_probe.email <> 'blocked')",
        )
        .await;
        let rls = Arc::new(
            RowFilterEnforcer::new([crate::RowFilter {
                table: users.clone(),
                predicate,
                org: None,
                groups: None,
            }])
            .expect("build rls"),
        );
        let enforcer = ColumnMaskingEnforcer::new([ColumnMask {
            table: TableReference::bare("orders_probe"),
            column: "email".to_string(),
            mask: lit("***"),
            org: None,
            groups: None,
        }])
        .expect("build")
        .with_row_filter_exemptions(rls);
        let plan = rewrite_sql(
            &ctx,
            &enforcer,
            "SELECT o.id FROM orders_probe o WHERE \
             EXISTS (SELECT 1 FROM orders_probe p WHERE p.email = 'alice@example.com') \
             AND EXISTS (SELECT 1 FROM users)",
        )
        .await;
        let rows = execute_plan(&ctx, plan).await;
        assert!(
            rows.is_empty(),
            "subquery A must stay masked despite subquery B's users scan; got {rows:?}"
        );
    }

    ///  — a child scope's row filter is not active in its parent: the
    /// parent predicate on masked `orders_probe.email` stays masked although
    /// a sibling `EXISTS (SELECT 1 FROM users)` scans `users`, whose row
    /// filter reads `orders_probe.email` (no row).
    #[tokio::test]
    async fn parent_scope_does_not_inherit_a_child_scopes_exemptions() {
        use datafusion::logical_expr::lit;

        let (ctx, users) = ctx_with_users();
        register_orders_probe(&ctx);
        let predicate = filter_predicate_of(
            &ctx,
            "SELECT id FROM users WHERE EXISTS \
             (SELECT 1 FROM orders_probe WHERE orders_probe.email <> 'blocked')",
        )
        .await;
        let rls = Arc::new(
            RowFilterEnforcer::new([crate::RowFilter {
                table: users.clone(),
                predicate,
                org: None,
                groups: None,
            }])
            .expect("build rls"),
        );
        let enforcer = ColumnMaskingEnforcer::new([ColumnMask {
            table: TableReference::bare("orders_probe"),
            column: "email".to_string(),
            mask: lit("***"),
            org: None,
            groups: None,
        }])
        .expect("build")
        .with_row_filter_exemptions(rls);
        let plan = rewrite_sql(
            &ctx,
            &enforcer,
            "SELECT o.id FROM orders_probe o WHERE o.email = 'alice@example.com' \
             AND EXISTS (SELECT 1 FROM users)",
        )
        .await;
        let rows = execute_plan(&ctx, plan).await;
        assert!(
            rows.is_empty(),
            "the parent predicate must stay masked despite the child's users scan; got {rows:?}"
        );
    }

    ///  — a window node between the derived table's projection and
    /// the cross join does not hide the join from the guard.
    #[tokio::test]
    async fn cross_join_behind_a_window_in_a_derived_table_is_guarded() {
        let (ctx, users) = ctx_with_users();
        let enforcer = ColumnMaskingEnforcer::new([mask_email_literal(&users)]).expect("build");
        let plan = ctx
            .sql(
                "SELECT * FROM (SELECT u.email AS ue, v.email AS ve, row_number() OVER () AS rn \
                 FROM users u CROSS JOIN users v) x WHERE x.ue = x.ve",
            )
            .await
            .expect("plan")
            .logical_plan()
            .clone();
        let err = enforcer
            .rewrite(plan, &crate::Identity::anonymous())
            .expect_err("a window node must not hide the cross join from the guard");
        assert!(err.to_string().contains("masked column"), "{err}");
    }

    ///  — `DISTINCT` (or any other single-input wrapper) inside the
    /// derived table does not hide the cross join from the guard.
    #[tokio::test]
    async fn cross_join_behind_distinct_in_a_derived_table_is_guarded() {
        let (ctx, users) = ctx_with_users();
        let enforcer = ColumnMaskingEnforcer::new([mask_email_literal(&users)]).expect("build");
        let plan = ctx
            .sql(
                "SELECT * FROM (SELECT DISTINCT u.id AS ui, v.id AS vi, u.email AS ue, v.email AS ve \
                 FROM users u CROSS JOIN users v) x WHERE x.ue = x.ve",
            )
            .await
            .expect("plan")
            .logical_plan()
            .clone();
        let err = enforcer
            .rewrite(plan, &crate::Identity::anonymous())
            .expect_err("DISTINCT must not hide the cross join from the guard");
        assert!(err.to_string().contains("masked column"), "{err}");
    }

    ///  — a derived table that already restricts its cross join
    /// (`WHERE u.id = v.id` inside) is not a cross product: the outer masked
    /// equality folding to TRUE is harmless and the query is allowed.
    #[tokio::test]
    async fn derived_table_with_its_own_relating_filter_is_allowed() {
        let (ctx, users) = ctx_with_users();
        let enforcer = ColumnMaskingEnforcer::new([mask_email_literal(&users)]).expect("build");
        let plan = rewrite_sql(
            &ctx,
            &enforcer,
            "SELECT x.ue FROM (SELECT u.email AS ue, v.email AS ve FROM users u CROSS JOIN users v \
             WHERE u.id = v.id) x WHERE x.ue = x.ve",
        )
        .await;
        let rows = execute_plan(&ctx, plan).await;
        assert_eq!(
            rows.len(),
            3,
            "the inner filter restricts the pairing; got {rows:?}"
        );
    }
}

//! Federation aggregate-alias normalizer ( / ).
//!
//! # The bug this closes
//!
//! Several optimizer passes rewrite an aggregate's argument and then wrap the
//! result in an `Expr::Alias` carrying the *pre-rewrite* derived name, so the
//! node's output schema is unchanged:
//!
//! * `simplify_expressions` folding a coerced literal —
//!   `sum(t.a * CAST(Int64(2) AS Float64))` becomes
//!   `sum(t.a * Float64(2)) AS "sum(pg.public.t.a * Int64(2))"`;
//! * the policy mask rewrite substituting a masked column —
//!   `count(email)` becomes `count('***') AS "count(pg.public.users.email)"`
//!
//! Those aliases live *inside* `Aggregate.aggr_expr`. When the federated
//! subplan is pushed down, `datafusion-federation` rewrites every table
//! reference from the Dataglot catalog to the connector's remote name
//! (3-part `pg.public.t` → 2-part `public.t`) — including the qualifier
//! buried in **flat column-name strings** such as the Projection's
//! `Column("sum(pg.public.t.a * Int64(2))")`, which becomes
//! `sum(public.t.a * Int64(2))`. But an `Alias`'s `name` is never rewritten,
//! so the Aggregate's output field keeps the 3-part text. Reference and field
//! disagree and planning the pushdown fails:
//! `Schema error: No field named "sum(public.t.a * Int64(2))"`. Only literal
//! coercion / masking triggers it because only then does an alias exist —
//! `sum(t.a * 1.2)` needs no coercion and works.
//!
//! # The fix
//!
//! A qualifier-embedding alias is only safe where nothing references it *by
//! name inside the pushed SQL*: the plan root. So, before the federation
//! optimizer collapses the plan, every alias inside an `Aggregate` (aggregate
//! and group expressions) **whose name embeds a scanned table's name** is
//! replaced by a synthetic qualifier-free alias (`__dataglot_norm_N`, the
//! same shape as DataFusion's own `__always_true`), and every ancestor
//! reference is renamed to match — including `Sort`/`Filter`/`Join`
//! references, which the flat-name rewrite then handles symmetrically. The
//! user-visible column label is restored at the root only: in place when the
//! root is the `Projection` that outputs the field, otherwise through a thin
//! wrapper `Projection` (e.g. `ORDER BY` the anonymous aggregate puts a `Sort`
//! on top). Re-attaching the label any deeper reproduces the desync one level
//! up (verified: the `Sort` of `ORDER BY 2` referenced the restored alias and
//! the remote reported `column "sum(main.orders…)" not found`).
//!
//! Aliases without an embedded table name are left strictly alone:
//! decorrelation's `Boolean(true) AS __always_true` marker and the planner's
//! `count(Int64(1)) AS count(*)` are referenced *by* those names and rewrite
//! fine (verified: stripping them broke correlated scalar subqueries on the
//! remote — `no column named "Boolean(true)"`).
//!
//! Single-node counterpart of the Ballista codec normalization in
//! (#1067).

use std::collections::HashSet;

use datafusion::common::tree_node::{Transformed, TreeNode, TreeNodeRecursion};
use datafusion::common::{Column, TableReference};
use datafusion::error::Result as DfResult;
use datafusion::logical_expr::{
    Aggregate, Distinct, DistinctOn, Expr, LogicalPlan, Projection, SortExpr, Window,
};
use datafusion::optimizer::optimizer::ApplyOrder;
use datafusion::optimizer::{OptimizerConfig, OptimizerRule};

/// Logical optimizer rule that un-aliases optimizer-introduced aliases inside
/// `Aggregate` nodes and re-points ancestor references (see module docs).
#[derive(Debug, Default)]
pub struct FederatedAggregateAliasNormalizer;

impl OptimizerRule for FederatedAggregateAliasNormalizer {
    #[allow(clippy::unnecessary_literal_bound)] // trait signature fixes the lifetime
    fn name(&self) -> &str {
        "federated_aggregate_alias_normalizer"
    }

    fn apply_order(&self) -> Option<ApplyOrder> {
        // Children before parents: an Aggregate is normalized before the
        // ancestors that reference its output, so the rename map is ready.
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
        normalize(plan)
    }
}

/// Bottom-up pass.
///
/// `renames` maps an old flat field name (a replaced alias) to its synthetic
/// name. Scoping is by **schema visibility**, not by node type: a rename is
/// applied to a node only when one of that node's inputs exposes the synthetic
/// name (so a sibling branch of a `Join` is never touched and never drops the
/// other branch's entry), and an entry is pruned as soon as the node's own
/// output no longer carries the synthetic name (nothing above can reference
/// it). Root labels are then restored positionally from the pre-normalization
/// schema, which covers bare aggregates and composite expressions alike.
///
/// # Errors
/// Propagates DataFusion plan-construction errors from rebuilding an
/// `Aggregate`/`Projection` or recomputing a node schema.
pub fn normalize(plan: LogicalPlan) -> DfResult<Transformed<LogicalPlan>> {
    let quals = scan_qualifiers(&plan)?;
    if quals.is_empty() {
        return Ok(Transformed::no(plan));
    }
    let original_plan = plan.clone();
    let original_root: Vec<(Option<TableReference>, String)> = plan
        .schema()
        .iter()
        .map(|(q, f)| (q.cloned(), f.name().clone()))
        .collect();
    // Every field name anywhere in the plan: synthetic names must not collide
    // with one (`__dataglot_norm_1` is a legal, unreserved identifier).
    let mut taken = all_field_names(&plan)?;
    let mut renames: Vec<Rename> = Vec::new();
    let mut counter = 0usize;
    let mut any = false;
    // Post-order visits the root last: the root Projection carries the
    // RESTORED (qualifier-embedding) labels of a previous pass and must not
    // have them stripped again — idempotence.
    let total = node_count(&plan)?;
    let mut visited = 0usize;
    let plan = plan
        .transform_up(|node| {
            visited += 1;
            let at_root = visited == total;
            // 1. Re-point this node's references — only the renames whose
            //    synthetic name one of its inputs actually exposes.
            let input_names: HashSet<String> = node
                .inputs()
                .iter()
                .flat_map(|input| input.schema().fields().iter().map(|f| f.name().clone()))
                .collect();
            let applicable: Vec<Rename> = renames
                .iter()
                .filter(|r| input_names.contains(&r.new))
                .cloned()
                .collect();
            let node = if applicable.is_empty() {
                Transformed::no(node)
            } else {
                repoint_references(
                    node,
                    &applicable,
                    &mut renames,
                    &mut counter,
                    &mut taken,
                    &quals,
                )?
            };
            let repointed = node.transformed;
            let node = node.data;

            // 2. Replace qualifier-embedding aliases inside an Aggregate or a
            //    Window (the nodes whose own expressions carry them).
            let node = strip_node_aliases(
                node,
                &quals,
                &mut renames,
                &mut counter,
                &mut taken,
                repointed,
                at_root,
            )?;
            any |= node.transformed;

            // 3. Prune renames that this node CONSUMED (saw in an input) but did
            //    not pass on, and re-key the ones it passes on under whatever
            //    qualifier its output gives the synthetic field: a
            //    `SubqueryAlias l` turns `old` into `l.old`, so two self-join
            //    branches carrying the SAME stale alias stay distinct entries
            //    (`l.old → n1`, `r.old → n2`) instead of overwriting each other.
            //    A sibling branch that never saw the synthetic name must not
            //    prune it — the Join above still needs it.
            let out_cols = node.data.schema().columns();
            renames.retain_mut(|r| {
                if !input_names.contains(&r.new) {
                    return true;
                }
                match out_cols.iter().find(|c| c.name == r.new) {
                    Some(c) => {
                        r.key = Column::new(c.relation.clone(), r.key.name.clone());
                        true
                    }
                    None => false,
                }
            });
            Ok(node)
        })?
        .data;
    if !any {
        return Ok(Transformed::no(plan));
    }
    // 4. Restore the user-visible labels at the root (see module docs for
    //    why nowhere deeper). If that cannot be done unambiguously, leave the
    //    plan exactly as it was — never hand the optimizer a changed schema.
    match restore_root_labels(plan, &original_root)? {
        Some(plan) => Ok(Transformed::yes(plan)),
        None => Ok(Transformed::no(original_plan)),
    }
}

/// Step 2 of [`normalize`] for the nodes whose OWN expressions carry
/// qualifier-embedding aliases — `Aggregate`, `Window` and `Projection` (a
/// Window's or Projection's name-preserving alias, `sum(t.a * Int64(2)) OVER
/// ()` / `t.a * Int64(2)`, is the same hazard as an Aggregate alias). Those are rebuilt with a recomputed schema when
/// anything changed (or was repointed) and with their cached schema otherwise;
/// every other node kind is passed through, schema-refreshed when a rename is
/// pending below it.
fn strip_node_aliases(
    node: LogicalPlan,
    quals: &[String],
    renames: &mut Vec<Rename>,
    counter: &mut usize,
    taken: &mut HashSet<String>,
    repointed: bool,
    at_root: bool,
) -> DfResult<Transformed<LogicalPlan>> {
    let mut changed = false;
    let out = match node {
        LogicalPlan::Aggregate(agg) => {
            let group_expr =
                strip_aliases(agg.group_expr, quals, renames, counter, taken, &mut changed);
            let aggr_expr =
                strip_aliases(agg.aggr_expr, quals, renames, counter, taken, &mut changed);
            if changed || repointed {
                Transformed::yes(LogicalPlan::Aggregate(Aggregate::try_new(
                    agg.input, group_expr, aggr_expr,
                )?))
            } else {
                Transformed::no(LogicalPlan::Aggregate(Aggregate::try_new_with_schema(
                    agg.input, group_expr, aggr_expr, agg.schema,
                )?))
            }
        }
        LogicalPlan::Window(w) => {
            let window_expr =
                strip_aliases(w.window_expr, quals, renames, counter, taken, &mut changed);
            if changed || repointed {
                Transformed::yes(LogicalPlan::Window(Window::try_new(window_expr, w.input)?))
            } else {
                Transformed::no(LogicalPlan::Window(Window::try_new_with_schema(
                    window_expr,
                    w.input,
                    w.schema,
                )?))
            }
        }
        // A Projection's own name-preserving alias (`t.a * Float64(2) AS
        // "t.a * Int64(2)"` after literal coercion, referenced by a Sort
        // above) is the same hazard again — except at the root, where such a
        // label is exactly what `restore_root_labels` puts back.
        LogicalPlan::Projection(p) if !at_root => {
            let expr = strip_aliases(p.expr, quals, renames, counter, taken, &mut changed);
            if changed || repointed {
                Transformed::yes(LogicalPlan::Projection(Projection::try_new(expr, p.input)?))
            } else {
                Transformed::no(LogicalPlan::Projection(Projection::try_new_with_schema(
                    expr, p.input, p.schema,
                )?))
            }
        }
        // `DISTINCT ON`'s own select expressions can carry the stale alias
        // as well; ON keys and sort expressions never define fields.
        LogicalPlan::Distinct(Distinct::On(d)) => {
            let first_new = renames.len();
            let select_expr =
                strip_aliases(d.select_expr, quals, renames, counter, taken, &mut changed);
            // Repoint (never alias) the ON keys and sorts with the renames just
            // created, should any of them reference a stripped label.
            let fresh: Vec<Rename> = renames[first_new..].to_vec();
            let mut on_expr = Vec::with_capacity(d.on_expr.len());
            for e in d.on_expr {
                on_expr.push(rename_refs(e, &fresh)?.data);
            }
            let sort_expr = d
                .sort_expr
                .map(|sorts| {
                    sorts
                        .into_iter()
                        .map(|s| {
                            Ok(SortExpr {
                                expr: rename_refs(s.expr, &fresh)?.data,
                                asc: s.asc,
                                nulls_first: s.nulls_first,
                            })
                        })
                        .collect::<DfResult<Vec<_>>>()
                })
                .transpose()?;
            let rebuilt = DistinctOn::try_new(on_expr, select_expr, sort_expr, d.input)?;
            if changed || repointed {
                Transformed::yes(LogicalPlan::Distinct(Distinct::On(rebuilt)))
            } else {
                Transformed::no(LogicalPlan::Distinct(Distinct::On(rebuilt)))
            }
        }
        other if repointed => Transformed::yes(other),
        other if renames.is_empty() => Transformed::no(other),
        // Not repointed, but a child below changed its output names. Some
        // nodes (Join, SubqueryAlias, …) are rebuilt with their OLD cached
        // schema, which would hide the synthetic names from the parent's
        // visibility check and leave stale names in the plan — refresh it
        // (#1067 recomputes for the same reason).
        other => Transformed::yes(other.recompute_schema()?),
    };
    Ok(out)
}

/// Number of nodes `transform_up` will visit (inputs only, like `apply`).
fn node_count(plan: &LogicalPlan) -> DfResult<usize> {
    let mut n = 0usize;
    plan.apply(|_| {
        n += 1;
        Ok(TreeNodeRecursion::Continue)
    })?;
    Ok(n)
}

/// One pending rename: the field a parent would reference as `key`
/// (qualifier + stale alias name) is exposed by the node below under the
/// synthetic name `new`. Kept as a list, not a map keyed by the flat name:
/// two branches may legitimately carry the same stale name (self-joins).
#[derive(Debug, Clone)]
struct Rename {
    key: Column,
    new: String,
}

/// The rename a reference `col` selects among `applicable`: a (qualifier,
/// name) match first — qualifiers compared with `TableReference::resolved_eq`
/// — then an unqualified reference matches by name when exactly one candidate
/// has it. Anything ambiguous is left untouched.
fn lookup<'a>(applicable: &'a [Rename], col: &Column) -> Option<&'a Rename> {
    // Qualified match with DataFusion's own resolution semantics: a `Bare`
    // or `Partial` reference matches a `Full` field of the same table.
    let same_relation = |r: &Rename| match (&r.key.relation, &col.relation) {
        (Some(a), Some(b)) => a.resolved_eq(b),
        (None, None) => true,
        _ => false,
    };
    if let Some(r) = applicable
        .iter()
        .find(|r| r.key.name == col.name && same_relation(r))
    {
        return Some(r);
    }
    if col.relation.is_some() {
        return None;
    }
    let mut by_name = applicable.iter().filter(|r| r.key.name == col.name);
    match (by_name.next(), by_name.next()) {
        (Some(r), None) => Some(r),
        _ => None,
    }
}

/// Every field name of every node schema in the plan.
fn all_field_names(plan: &LogicalPlan) -> DfResult<HashSet<String>> {
    let mut names = HashSet::new();
    plan.apply(|node| {
        names.extend(node.schema().fields().iter().map(|f| f.name().clone()));
        Ok(TreeNodeRecursion::Continue)
    })?;
    Ok(names)
}

/// The next `__dataglot_norm_N` that no schema in the plan already uses.
fn next_synthetic(counter: &mut usize, taken: &mut HashSet<String>) -> String {
    loop {
        *counter += 1;
        let candidate = format!("__dataglot_norm_{counter}");
        if taken.insert(candidate.clone()) {
            return candidate;
        }
    }
}

/// Restore the root schema — labels AND qualifiers — to exactly what it was
/// before normalization, positionally. Nothing references the root's fields
/// by name inside the pushed SQL, so qualifier-embedding labels are safe here.
/// `None` means the restoration would be ambiguous; the caller then keeps the
/// original plan.
fn restore_root_labels(
    plan: LogicalPlan,
    original: &[(Option<TableReference>, String)],
) -> DfResult<Option<LogicalPlan>> {
    let current: Vec<(Option<TableReference>, String)> = plan
        .schema()
        .iter()
        .map(|(q, f)| (q.cloned(), f.name().clone()))
        .collect();
    if current == original {
        return Ok(Some(plan));
    }
    // Normalization never adds or drops root fields; if it ever did, a
    // positional restore would corrupt the plan — keep the original instead.
    if current.len() != original.len() {
        return Ok(None);
    }
    match plan {
        // Root Projection: re-alias in place the exprs whose derived name moved.
        LogicalPlan::Projection(p) => {
            let exprs = p
                .expr
                .into_iter()
                .zip(original.iter())
                .map(|(e, (q0, name0))| {
                    let name = e.schema_name().to_string();
                    if &name == name0 {
                        e
                    } else {
                        // A composite got a synthetic alias on the way up;
                        // peel it so we don't stack aliases.
                        e.unalias().alias_qualified(q0.clone(), name0)
                    }
                })
                .collect();
            Ok(Some(LogicalPlan::Projection(Projection::try_new(
                exprs, p.input,
            )?)))
        }
        // Anything else on top (Sort, Filter, Limit…): a thin wrapper that
        // restores every field to its original (qualifier, label). The wrapper
        // unparses as a derived table, so it references its input UNQUALIFIED
        // — `"orders"."region"` would dangle outside the subquery (the
        // class) — while `alias_qualified` puts the original qualifier back on
        // the output field: DataFusion's optimizer invariant requires the root
        // schema, qualifiers included, to be unchanged. Duplicate field names
        // (self-join outputs) keep the qualified reference, since a bare name
        // would be ambiguous; a duplicate WITHOUT a qualifier cannot be
        // referenced unambiguously at all (DFSchema rejects such schemas, so
        // this is defensive), and the caller keeps the original plan.
        other => {
            let schema = other.schema();
            let mut exprs = Vec::with_capacity(original.len());
            for ((qualifier, field), (q0, name0)) in schema.iter().zip(original.iter()) {
                let dup = schema
                    .fields()
                    .iter()
                    .filter(|f| f.name() == field.name())
                    .count()
                    > 1;
                let column = match (dup, qualifier) {
                    (false, _) => Expr::Column(Column::new_unqualified(field.name())),
                    (true, Some(_)) => Expr::Column(Column::from((qualifier, field))),
                    (true, None) => return Ok(None),
                };
                exprs.push(column.alias_qualified(q0.clone(), name0));
            }
            Ok(Some(LogicalPlan::Projection(Projection::try_new(
                exprs,
                std::sync::Arc::new(other),
            )?)))
        }
    }
}

/// Every `TableScan` name in the plan, rendered as it appears inside derived
/// field names (`orders.`, `duck_contract.main.orders.`) — the substrings the
/// federation pushdown later rewrites in flat column names. Deduplicated
/// (self-joins scan the same table twice).
fn scan_qualifiers(plan: &LogicalPlan) -> DfResult<Vec<String>> {
    let mut quals = Vec::new();
    plan.apply(|node| {
        if let LogicalPlan::TableScan(scan) = node {
            quals.push(format!("{}.", scan.table_name));
        }
        Ok(TreeNodeRecursion::Continue)
    })?;
    quals.sort();
    quals.dedup();
    Ok(quals)
}

/// Does `name` contain one of `quals` as a whole qualifier token — i.e. not as
/// the tail of a longer identifier (`reorders.` must not match `orders.`, and
/// `main.orders.` is a different qualifier from `orders.`)?
fn embeds_qualifier(name: &str, quals: &[String]) -> bool {
    quals.iter().any(|q| {
        name.match_indices(q.as_str()).any(|(idx, _)| {
            idx == 0
                || name[..idx]
                    .chars()
                    .next_back()
                    .is_none_or(|c| !(c.is_alphanumeric() || c == '_' || c == '.'))
        })
    })
}

/// Re-alias each `Alias(expr, name)` whose name differs from the expression's
/// own derived name **and embeds a scanned table's name** to a synthetic,
/// qualifier-free name (`__dataglot_norm_N`), recording `name → synthetic`.
///
/// Why a synthetic alias rather than the bare derived name: the derived name
/// (`sum(duck_contract.main.orders.amount * Float64(2))`) embeds the qualifier
/// too, so a reference to it that crosses a derived-table boundary — the
/// `ORDER BY <aggregate>` wrapper — is rewritten to 2-part by the federation
/// pass while the inner SELECT carries no matching alias, and the remote
/// reports the column missing. A name with no qualifier is never rewritten,
/// unparses identically inside and outside derived tables, and is exactly
/// the shape DataFusion's own decorrelation uses (`__always_true`).
/// Qualified aliases (`relation.is_some()`) and qualifier-free aliases are
/// left alone.
fn strip_aliases(
    exprs: Vec<Expr>,
    quals: &[String],
    renames: &mut Vec<Rename>,
    counter: &mut usize,
    taken: &mut HashSet<String>,
    changed: &mut bool,
) -> Vec<Expr> {
    exprs
        .into_iter()
        .map(|e| match e {
            Expr::Alias(alias)
                if alias.relation.is_none() && embeds_qualifier(&alias.name, quals) =>
            {
                if alias.expr.schema_name().to_string() == alias.name {
                    // Redundant alias: the label already IS the derived name.
                    // Keeping it would still break pushdown — the federation
                    // rewrite updates the derived name (2-part qualifier) and
                    // every reference, but never an `Alias.name` — so strip it
                    // and let the name follow the expression.
                    *changed = true;
                    return *alias.expr;
                }
                let synthetic = next_synthetic(counter, taken);
                renames.push(Rename {
                    key: Column::new_unqualified(alias.name),
                    new: synthetic.clone(),
                });
                *changed = true;
                (*alias.expr).alias(synthetic)
            }
            other => other,
        })
        .collect()
}

/// Rewrite references to renamed fields in `node`'s own expressions (plain
/// rename — labels are restored at the root, never here) and recompute the
/// node schema when anything changed.
///
/// Field-defining nodes (`Projection`, `Aggregate`, `Window`) get one more
/// treatment: a **composite** expression that now contains a synthetic
/// reference (e.g. `- __dataglot_norm_1`, `sum(__dataglot_norm_1) OVER ()`) would
/// otherwise derive a field name that is unparsed with no alias — and a
/// reference to that field across a derived-table boundary (the root wrapper
/// for `ORDER BY`) fails on the remote, which names the column differently.
/// So such an expression is itself aliased to a fresh synthetic name and the
/// rename (`old derived name → synthetic`) is recorded, exactly like an
/// Aggregate alias. Bare column references are left as they are.
fn repoint_references(
    node: LogicalPlan,
    applicable: &[Rename],
    renames: &mut Vec<Rename>,
    counter: &mut usize,
    taken: &mut HashSet<String>,
    quals: &[String],
) -> DfResult<Transformed<LogicalPlan>> {
    let mut any = false;
    let plan = match node {
        // `DISTINCT ON`: only `select_expr` defines output fields. The ON
        // keys and the sort expressions are repointed but never aliased —
        // wrapping a sort expression would break its shape.
        LogicalPlan::Distinct(Distinct::On(d)) => {
            let mut on_expr = Vec::with_capacity(d.on_expr.len());
            for e in d.on_expr {
                let t = rename_refs(e, applicable)?;
                any |= t.transformed;
                on_expr.push(t.data);
            }
            let mut select_expr = Vec::with_capacity(d.select_expr.len());
            for e in d.select_expr {
                let before = e.schema_name().to_string();
                let t = rename_refs(e, applicable)?;
                any |= t.transformed;
                select_expr.push(if t.transformed {
                    stabilize(t.data, before, renames, counter, taken, quals)
                } else {
                    t.data
                });
            }
            let sort_expr = match d.sort_expr {
                None => None,
                Some(sorts) => {
                    let mut out = Vec::with_capacity(sorts.len());
                    for s in sorts {
                        let t = rename_refs(s.expr, applicable)?;
                        any |= t.transformed;
                        out.push(SortExpr {
                            expr: t.data,
                            asc: s.asc,
                            nulls_first: s.nulls_first,
                        });
                    }
                    Some(out)
                }
            };
            if !any {
                return Ok(Transformed::no(LogicalPlan::Distinct(Distinct::On(
                    DistinctOn::try_new(on_expr, select_expr, sort_expr, d.input)?,
                ))));
            }
            LogicalPlan::Distinct(Distinct::On(DistinctOn::try_new(
                on_expr,
                select_expr,
                sort_expr,
                d.input,
            )?))
        }
        node => {
            // Nodes whose expressions DEFINE output fields by derived name: a
            // composite expression over a renamed field would otherwise derive
            // a new field name that the parent still references under the old
            // one.
            let defines_fields = matches!(
                node,
                LogicalPlan::Projection(_) | LogicalPlan::Aggregate(_) | LogicalPlan::Window(_)
            );
            let node = node.map_expressions(|expr| {
                let before = expr.schema_name().to_string();
                let out = rename_refs(expr, applicable)?;
                if !out.transformed || !defines_fields {
                    return Ok(out);
                }
                any = true;
                Ok(Transformed::yes(stabilize(
                    out.data, before, renames, counter, taken, quals,
                )))
            })?;
            any |= node.transformed;
            if !any {
                return Ok(Transformed::no(node.data));
            }
            match node.data {
                LogicalPlan::Projection(p) => {
                    LogicalPlan::Projection(Projection::try_new(p.expr, p.input)?)
                }
                other => other.recompute_schema()?,
            }
        }
    };
    Ok(Transformed::yes(plan))
}

/// Rename every `Column` reference in `expr` that selects one of `applicable`.
fn rename_refs(expr: Expr, applicable: &[Rename]) -> DfResult<Transformed<Expr>> {
    expr.transform_up(|e| {
        if let Expr::Column(col) = &e {
            if let Some(r) = lookup(applicable, col) {
                let mut target = col.clone();
                target.name.clone_from(&r.new);
                return Ok(Transformed::yes(Expr::Column(target)));
            }
        }
        Ok(Transformed::no(e))
    })
}

/// Give a repointed **field-defining** expression a stable, qualifier-free
/// name of its own (`before` is its derived name prior to repointing):
///
/// * a bare column reference or a qualifier-free alias is left as it is;
/// * an alias whose unqualified label embeds a scanned table's name — the
///   stale, name-preserving label DataFusion keeps after simplification — is
///   re-aliased to a synthetic name, exactly like an Aggregate alias;
/// * any other composite gets a synthetic alias.
///
/// In both rewritten cases the `old → synthetic` rename is recorded for the
/// ancestors, which would otherwise reference a name the federation rewrite
/// changes while the label stays.
fn stabilize(
    e: Expr,
    before: String,
    renames: &mut Vec<Rename>,
    counter: &mut usize,
    taken: &mut HashSet<String>,
    quals: &[String],
) -> Expr {
    let (inner, old) = match e {
        Expr::Alias(alias) if alias.relation.is_none() && embeds_qualifier(&alias.name, quals) => {
            (*alias.expr, alias.name)
        }
        e @ (Expr::Column(_) | Expr::Alias(_)) => return e,
        e => (e, before),
    };
    let synthetic = next_synthetic(counter, taken);
    renames.push(Rename {
        key: Column::new_unqualified(old),
        new: synthetic.clone(),
    });
    inner.alias(synthetic)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use arrow::array::{Float64Array, Int32Array};
    use arrow::datatypes::{DataType, Field, Schema};
    use arrow::record_batch::RecordBatch;
    use datafusion::datasource::MemTable;
    use datafusion::functions_aggregate::expr_fn::sum;
    use datafusion::logical_expr::{col, lit, LogicalPlanBuilder};
    use datafusion::optimizer::OptimizerContext;
    use datafusion::prelude::SessionContext;

    use super::*;

    fn ctx_with_t() -> SessionContext {
        let schema = Arc::new(Schema::new(vec![
            Field::new("k", DataType::Int32, false),
            Field::new("a", DataType::Float64, false),
        ]));
        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(Int32Array::from(vec![1, 1, 2])),
                Arc::new(Float64Array::from(vec![10.0, 20.0, 30.0])),
            ],
        )
        .unwrap();
        let ctx = SessionContext::new();
        ctx.register_table(
            "t",
            Arc::new(MemTable::try_new(schema, vec![vec![batch]]).unwrap()),
        )
        .unwrap();
        ctx
    }

    /// The optimizer-emitted shape: a rewritten aggregate argument aliased
    /// back to its pre-rewrite derived name, referenced by the Projection
    /// above under that stale name.
    async fn aliased_aggregate_plan(ctx: &SessionContext) -> (LogicalPlan, String) {
        let scan = ctx.table("t").await.unwrap().into_unoptimized_plan();
        let stale = "sum(t.a * Int64(2))".to_string();
        let agg = sum(col("a") * lit(2.0_f64)).alias(&stale);
        let plan = LogicalPlanBuilder::from(scan)
            .aggregate(vec![col("k")], vec![agg])
            .unwrap()
            .project(vec![col("k"), col(&stale)])
            .unwrap()
            .build()
            .unwrap();
        (plan, stale)
    }

    #[tokio::test]
    async fn replaces_aggregate_alias_with_synthetic_and_preserves_output_name() {
        let ctx = ctx_with_t();
        let (plan, stale) = aliased_aggregate_plan(&ctx).await;
        let before: Vec<String> = plan
            .schema()
            .fields()
            .iter()
            .map(|f| f.name().clone())
            .collect();

        let out = normalize(plan).unwrap();
        assert!(out.transformed, "the aliased aggregate is normalized");
        let plan = out.data;

        // Output names are unchanged: the root Projection re-attached the label.
        let after: Vec<String> = plan
            .schema()
            .fields()
            .iter()
            .map(|f| f.name().clone())
            .collect();
        assert_eq!(after, before, "user-visible column names preserved");
        assert!(after.contains(&stale));

        // Inside, the Aggregate carries a synthetic qualifier-free alias — the
        // only shape every federation rewrite leaves untouched.
        let LogicalPlan::Projection(p) = &plan else {
            panic!("projection on top")
        };
        let LogicalPlan::Aggregate(agg) = p.input.as_ref() else {
            panic!("aggregate below")
        };
        let name = agg.aggr_expr[0].schema_name().to_string();
        assert!(
            name.starts_with("__dataglot_norm_"),
            "synthetic alias, got {name}"
        );
        assert!(!name.contains("t."), "no qualifier embedded: {name}");
        assert!(agg.schema.fields().iter().any(|f| f.name() == &name));

        // And the plan still executes with the same answers.
        let batches = ctx
            .execute_logical_plan(plan)
            .await
            .unwrap()
            .collect()
            .await
            .unwrap();
        assert_eq!(batches.iter().map(RecordBatch::num_rows).sum::<usize>(), 2);
    }

    #[tokio::test]
    async fn idempotent_and_inert_without_aliases() {
        let ctx = ctx_with_t();
        let (plan, _) = aliased_aggregate_plan(&ctx).await;
        let once = normalize(plan).unwrap().data;
        let twice = normalize(once.clone()).unwrap();
        assert!(!twice.transformed, "second pass finds nothing to do");
        assert_eq!(
            format!("{}", twice.data.display_indent()),
            format!("{}", once.display_indent())
        );

        // A plain aggregate (no alias) is untouched.
        let scan = ctx.table("t").await.unwrap().into_unoptimized_plan();
        let unaliased = LogicalPlanBuilder::from(scan)
            .aggregate(vec![col("k")], vec![sum(col("a"))])
            .unwrap()
            .build()
            .unwrap();
        assert!(!normalize(unaliased).unwrap().transformed);
    }

    /// Decorrelation's `Boolean(true) AS __always_true` marker and the
    /// planner's `count(Int64(1)) AS count(*)` embed no table name — they
    /// are referenced by exactly those aliases downstream and must survive.
    #[tokio::test]
    async fn qualifier_free_aliases_are_left_alone() {
        let ctx = ctx_with_t();
        let scan = ctx.table("t").await.unwrap().into_unoptimized_plan();
        let plan = LogicalPlanBuilder::from(scan)
            .aggregate(
                vec![col("k"), lit(true).alias("__always_true")],
                vec![datafusion::functions_aggregate::expr_fn::count(lit(1_i64)).alias("count(*)")],
            )
            .unwrap()
            .build()
            .unwrap();
        assert!(!normalize(plan).unwrap().transformed);
    }

    #[test]
    fn embeds_qualifier_respects_token_boundaries() {
        let quals = vec!["orders.".to_string(), "pg.public.users.".to_string()];
        assert!(embeds_qualifier("sum(orders.amount * Int64(2))", &quals));
        assert!(embeds_qualifier("count(pg.public.users.email)", &quals));
        assert!(embeds_qualifier("orders.amount", &quals));
        assert!(
            !embeds_qualifier("sum(reorders.amount)", &quals),
            "tail of a longer identifier"
        );
        assert!(
            !embeds_qualifier("sum(main.orders.amount)", &quals),
            "preceded by '.' — a different qualifier"
        );
        assert!(!embeds_qualifier("__always_true", &quals));
        assert!(!embeds_qualifier("count(*)", &quals));
    }

    /// Codex P1 on #1116 — `ORDER BY` the anonymous rewritten aggregate is
    /// `Sort -> Projection -> Aggregate`. The label must be restored at the
    /// ROOT (a wrapper Projection above the Sort), never inside: an alias
    /// embedding the table qualifier that a `Sort` references by name
    /// desyncs again through the federation rewrite. So the Sort must
    /// reference the NEW derived name, and the root schema — names AND
    /// qualifiers, which DataFusion's optimizer invariant checks — must be
    /// unchanged.
    #[tokio::test]
    async fn sort_above_projection_references_derived_name_labels_restored_at_root() {
        let ctx = ctx_with_t();
        let (plan, stale) = aliased_aggregate_plan(&ctx).await;
        let plan = LogicalPlanBuilder::from(plan)
            .sort(vec![col(&stale).sort(true, true)])
            .unwrap()
            .build()
            .unwrap();
        let before: Vec<(Option<TableReference>, String)> = plan
            .schema()
            .iter()
            .map(|(q, f)| (q.cloned(), f.name().clone()))
            .collect();

        let out = normalize(plan).unwrap();
        assert!(out.transformed);
        let plan = out.data;

        let after: Vec<(Option<TableReference>, String)> = plan
            .schema()
            .iter()
            .map(|(q, f)| (q.cloned(), f.name().clone()))
            .collect();
        assert_eq!(after, before, "root schema (qualifiers + labels) preserved");
        assert!(after.iter().any(|(_, n)| n == &stale));

        // Root is the wrapper Projection; the Sort under it references the
        // derived name, not the stale alias.
        let LogicalPlan::Projection(wrapper) = &plan else {
            panic!("wrapper projection on top")
        };
        let LogicalPlan::Sort(sort) = wrapper.input.as_ref() else {
            panic!("sort under the wrapper")
        };
        let sort_text = format!("{:?}", sort.expr);
        assert!(
            !sort_text.contains(&stale),
            "Sort no longer references the stale alias: {sort_text}"
        );
        assert!(
            sort_text.contains("__dataglot_norm_"),
            "Sort references the synthetic alias: {sort_text}"
        );

        let batches = ctx
            .execute_logical_plan(plan)
            .await
            .unwrap()
            .collect()
            .await
            .unwrap();
        assert_eq!(batches.iter().map(RecordBatch::num_rows).sum::<usize>(), 2);
    }

    /// Codex P1 on #1116: a COMPOSITE root expression over the renamed
    /// aggregate (`SELECT -sum(a * 2) … ORDER BY 1`) must keep its original
    /// label too — restoration is positional over the whole root schema, not
    /// limited to bare columns.
    #[tokio::test]
    async fn composite_root_expression_keeps_its_label() {
        let ctx = ctx_with_t();
        let (plan, stale) = aliased_aggregate_plan(&ctx).await;
        // Projection(k, -stale) above the aliased-aggregate plan, then ORDER BY.
        let plan = LogicalPlanBuilder::from(plan)
            .project(vec![col("k"), Expr::Negative(Box::new(col(&stale)))])
            .unwrap()
            .sort(vec![col("k").sort(true, true)])
            .unwrap()
            .build()
            .unwrap();
        let before: Vec<(Option<TableReference>, String)> = plan
            .schema()
            .iter()
            .map(|(q, f)| (q.cloned(), f.name().clone()))
            .collect();
        assert!(
            before[1].1.contains(&stale),
            "composite label embeds the stale name"
        );

        let out = normalize(plan).unwrap();
        assert!(out.transformed);
        let plan = out.data;
        let after: Vec<(Option<TableReference>, String)> = plan
            .schema()
            .iter()
            .map(|(q, f)| (q.cloned(), f.name().clone()))
            .collect();
        assert_eq!(
            after, before,
            "root schema preserved for the composite expression"
        );
        let batches = ctx
            .execute_logical_plan(plan)
            .await
            .unwrap()
            .collect()
            .await
            .unwrap();
        assert_eq!(batches.iter().map(RecordBatch::num_rows).sum::<usize>(), 2);
    }

    /// Codex P1 on #1116: two renamed aggregates under one Join. Postorder
    /// visits the whole left branch, then the right; a node-type-based
    /// "clear the map" would drop the left entry before the Join could apply
    /// it. Visibility scoping keeps both alive exactly until the Join.
    #[tokio::test]
    async fn join_of_two_renamed_aggregates_repoints_both_sides() {
        let ctx = ctx_with_t();
        let stale_l = "sum(t.a * Int64(2))".to_string();
        let stale_r = "sum(t.a * Int64(3))".to_string();
        let left = LogicalPlanBuilder::from(ctx.table("t").await.unwrap().into_unoptimized_plan())
            .aggregate(
                vec![col("k")],
                vec![sum(col("a") * lit(2.0_f64)).alias(&stale_l)],
            )
            .unwrap()
            .alias("l")
            .unwrap()
            .build()
            .unwrap();
        let right = LogicalPlanBuilder::from(ctx.table("t").await.unwrap().into_unoptimized_plan())
            .aggregate(
                vec![col("k")],
                vec![sum(col("a") * lit(3.0_f64)).alias(&stale_r)],
            )
            .unwrap()
            .alias("r")
            .unwrap()
            .build()
            .unwrap();
        let plan = LogicalPlanBuilder::from(left)
            .join(
                right,
                datafusion::logical_expr::JoinType::Inner,
                (
                    vec![Column::new(Some("l"), "k")],
                    vec![Column::new(Some("r"), "k")],
                ),
                None,
            )
            .unwrap()
            .project(vec![
                Expr::Column(Column::new(Some("l"), "k")),
                Expr::Column(Column::new(Some("l"), &stale_l)),
                Expr::Column(Column::new(Some("r"), &stale_r)),
            ])
            .unwrap()
            .build()
            .unwrap();
        let before: Vec<String> = plan
            .schema()
            .fields()
            .iter()
            .map(|f| f.name().clone())
            .collect();

        let out = normalize(plan).unwrap();
        assert!(out.transformed);
        let plan = out.data;
        let after: Vec<String> = plan
            .schema()
            .fields()
            .iter()
            .map(|f| f.name().clone())
            .collect();
        assert_eq!(after, before, "both labels restored at the root");
        let batches = ctx
            .execute_logical_plan(plan)
            .await
            .unwrap()
            .collect()
            .await
            .unwrap();
        assert_eq!(
            batches.iter().map(RecordBatch::num_rows).sum::<usize>(),
            2,
            "2 groups joined"
        );
    }

    #[tokio::test]
    async fn runs_as_an_optimizer_rule() {
        let ctx = ctx_with_t();
        let (plan, _) = aliased_aggregate_plan(&ctx).await;
        let rule = FederatedAggregateAliasNormalizer;
        let out = rule.rewrite(plan, &OptimizerContext::new()).unwrap();
        assert!(out.transformed);
        assert_eq!(rule.name(), "federated_aggregate_alias_normalizer");
    }

    /// Codex P1 (round 2) on #1116: two self-join branches carrying the SAME
    /// stale alias. A rename map keyed by the flat name would let the right
    /// branch overwrite the left entry, leaving `l."sum(..)"` unresolved.
    /// Entries are re-keyed under the branch qualifier (`l.old`, `r.old`)
    /// as they pass through the `SubqueryAlias`, so both resolve.
    #[tokio::test]
    async fn identical_stale_aliases_across_self_join_branches_repoint_independently() {
        let ctx = ctx_with_t();
        let stale = "sum(t.a * Int64(2))".to_string();
        let branch = |ctx: &SessionContext, name: &'static str| {
            let ctx = ctx.clone();
            let stale = stale.clone();
            async move {
                LogicalPlanBuilder::from(ctx.table("t").await.unwrap().into_unoptimized_plan())
                    .aggregate(
                        vec![col("k")],
                        vec![sum(col("a") * lit(2.0_f64)).alias(&stale)],
                    )
                    .unwrap()
                    .alias(name)
                    .unwrap()
                    .build()
                    .unwrap()
            }
        };
        let left = branch(&ctx, "l").await;
        let right = branch(&ctx, "r").await;
        let plan = LogicalPlanBuilder::from(left)
            .join(
                right,
                datafusion::logical_expr::JoinType::Inner,
                (
                    vec![Column::new(Some("l"), "k")],
                    vec![Column::new(Some("r"), "k")],
                ),
                None,
            )
            .unwrap()
            .project(vec![
                Expr::Column(Column::new(Some("l"), "k")),
                Expr::Column(Column::new(Some("l"), &stale)),
                Expr::Column(Column::new(Some("r"), &stale)),
            ])
            .unwrap()
            .build()
            .unwrap();
        let before: Vec<(Option<TableReference>, String)> = plan
            .schema()
            .iter()
            .map(|(q, f)| (q.cloned(), f.name().clone()))
            .collect();

        let out = normalize(plan).unwrap();
        assert!(out.transformed);
        let plan = out.data;
        let after: Vec<(Option<TableReference>, String)> = plan
            .schema()
            .iter()
            .map(|(q, f)| (q.cloned(), f.name().clone()))
            .collect();
        assert_eq!(
            after, before,
            "both labels and qualifiers restored at the root"
        );

        // Each branch got its own synthetic name and no stale alias survives
        // below the root.
        let mut synthetics = Vec::new();
        plan.apply(|node| {
            if let LogicalPlan::Aggregate(agg) = node {
                for e in &agg.aggr_expr {
                    let name = e.schema_name().to_string();
                    assert!(
                        name.starts_with("__dataglot_norm_"),
                        "stale alias left: {name}"
                    );
                    synthetics.push(name);
                }
            }
            Ok(TreeNodeRecursion::Continue)
        })
        .unwrap();
        synthetics.sort();
        synthetics.dedup();
        assert_eq!(
            synthetics.len(),
            2,
            "one synthetic per branch: {synthetics:?}"
        );

        let batches = ctx
            .execute_logical_plan(plan)
            .await
            .unwrap()
            .collect()
            .await
            .unwrap();
        assert_eq!(batches.iter().map(RecordBatch::num_rows).sum::<usize>(), 2);
    }

    /// Codex P2 on #1116: `__dataglot_norm_1` is a legal identifier a user (or
    /// another pass) may already have used. Synthetic names skip every field
    /// name present anywhere in the plan.
    #[tokio::test]
    async fn synthetic_names_avoid_existing_field_names() {
        let ctx = ctx_with_t();
        let stale = "sum(t.a * Int64(2))".to_string();
        let plan = LogicalPlanBuilder::from(ctx.table("t").await.unwrap().into_unoptimized_plan())
            .project(vec![col("k"), col("a").alias("__dataglot_norm_1")])
            .unwrap()
            .aggregate(
                vec![col("k")],
                vec![sum(col("__dataglot_norm_1") * lit(2.0_f64)).alias(&stale)],
            )
            .unwrap()
            .project(vec![col("k"), col(&stale)])
            .unwrap()
            .build()
            .unwrap();
        let before: Vec<String> = plan
            .schema()
            .fields()
            .iter()
            .map(|f| f.name().clone())
            .collect();

        let out = normalize(plan).unwrap();
        assert!(out.transformed);
        let plan = out.data;
        let after: Vec<String> = plan
            .schema()
            .fields()
            .iter()
            .map(|f| f.name().clone())
            .collect();
        assert_eq!(after, before);

        let LogicalPlan::Projection(p) = &plan else {
            panic!("projection on top")
        };
        let LogicalPlan::Aggregate(agg) = p.input.as_ref() else {
            panic!("aggregate below")
        };
        let name = agg.aggr_expr[0].schema_name().to_string();
        assert_eq!(
            name, "__dataglot_norm_2",
            "must not collide with the user's field"
        );
        assert_eq!(
            agg.schema
                .fields()
                .iter()
                .filter(|f| f.name() == "__dataglot_norm_1")
                .count(),
            0,
            "the aggregate output never carries the user's colliding name twice"
        );

        let batches = ctx
            .execute_logical_plan(plan)
            .await
            .unwrap()
            .collect()
            .await
            .unwrap();
        assert_eq!(batches.iter().map(RecordBatch::num_rows).sum::<usize>(), 2);
    }

    /// Codex P1 (round 3) and the `CodeRabbit` review on #1116: `Projection -> Window ->
    /// Aggregate`. The Window expression over the renamed aggregate derives
    /// a NEW field name once repointed; without the synthetic-name treatment
    /// the parent Projection still references the old one.
    #[tokio::test]
    async fn window_over_renamed_aggregate_keeps_parent_reference_valid() {
        use datafusion::functions_aggregate::sum::sum_udaf;
        use datafusion::logical_expr::expr::WindowFunction;
        use datafusion::logical_expr::WindowFunctionDefinition;

        let ctx = ctx_with_t();
        let stale = "sum(t.a * Int64(2))".to_string();
        let wexpr = Expr::WindowFunction(Box::new(WindowFunction::new(
            WindowFunctionDefinition::AggregateUDF(sum_udaf()),
            vec![col(&stale)],
        )));
        let wname = wexpr.schema_name().to_string();
        let plan = LogicalPlanBuilder::from(ctx.table("t").await.unwrap().into_unoptimized_plan())
            .aggregate(
                vec![col("k")],
                vec![sum(col("a") * lit(2.0_f64)).alias(&stale)],
            )
            .unwrap()
            .window(vec![wexpr])
            .unwrap()
            .project(vec![col("k"), col(&wname)])
            .unwrap()
            .build()
            .unwrap();
        let before: Vec<String> = plan
            .schema()
            .fields()
            .iter()
            .map(|f| f.name().clone())
            .collect();

        let out = normalize(plan).unwrap();
        assert!(out.transformed);
        let plan = out.data;
        let after: Vec<String> = plan
            .schema()
            .fields()
            .iter()
            .map(|f| f.name().clone())
            .collect();
        assert_eq!(after, before, "root labels restored");
        let batches = ctx
            .execute_logical_plan(plan)
            .await
            .unwrap()
            .collect()
            .await
            .unwrap();
        assert_eq!(batches.iter().map(RecordBatch::num_rows).sum::<usize>(), 2);
    }

    /// Same class for a nested Aggregate: a composite GROUP BY and an
    /// aggregate over the renamed field both derive new names.
    #[tokio::test]
    async fn nested_aggregate_over_renamed_aggregate_keeps_parent_reference_valid() {
        use datafusion::functions_aggregate::expr_fn::count;

        let ctx = ctx_with_t();
        let stale = "sum(t.a * Int64(2))".to_string();
        let group = col(&stale) + lit(1.0_f64);
        // Qualified like the planner leaves it, so the derived name matches.
        let cnt = count(Expr::Column(Column::new(Some("t"), "k")));
        let (gname, cname) = (
            group.schema_name().to_string(),
            cnt.schema_name().to_string(),
        );
        let plan = LogicalPlanBuilder::from(ctx.table("t").await.unwrap().into_unoptimized_plan())
            .aggregate(
                vec![col("k")],
                vec![sum(col("a") * lit(2.0_f64)).alias(&stale)],
            )
            .unwrap()
            .aggregate(vec![group], vec![cnt])
            .unwrap()
            .project(vec![col(&gname), col(&cname)])
            .unwrap()
            .build()
            .unwrap();
        let before: Vec<String> = plan
            .schema()
            .fields()
            .iter()
            .map(|f| f.name().clone())
            .collect();

        let out = normalize(plan).unwrap();
        assert!(out.transformed);
        let plan = out.data;
        let after: Vec<String> = plan
            .schema()
            .fields()
            .iter()
            .map(|f| f.name().clone())
            .collect();
        assert_eq!(after, before, "root labels restored");
        let batches = ctx
            .execute_logical_plan(plan)
            .await
            .unwrap()
            .collect()
            .await
            .unwrap();
        // Both k-groups sum to 60, so the outer GROUP BY yields one row.
        assert_eq!(batches.iter().map(RecordBatch::num_rows).sum::<usize>(), 1);
    }

    /// Gemini on #1116: an alias whose label already equals the derived name
    /// is not harmless — the federation rewrite updates the derived name and
    /// the references but never the alias label. It is stripped instead.
    #[tokio::test]
    async fn redundant_qualifier_alias_is_stripped() {
        let ctx = ctx_with_t();
        let name = "sum(t.a)".to_string();
        let plan = LogicalPlanBuilder::from(ctx.table("t").await.unwrap().into_unoptimized_plan())
            .aggregate(vec![col("k")], vec![sum(col("a")).alias(&name)])
            .unwrap()
            .project(vec![col("k"), col(&name)])
            .unwrap()
            .build()
            .unwrap();
        let before: Vec<String> = plan
            .schema()
            .fields()
            .iter()
            .map(|f| f.name().clone())
            .collect();

        let out = normalize(plan).unwrap();
        assert!(out.transformed);
        let plan = out.data;
        let after: Vec<String> = plan
            .schema()
            .fields()
            .iter()
            .map(|f| f.name().clone())
            .collect();
        assert_eq!(after, before);
        let LogicalPlan::Projection(p) = &plan else {
            panic!("projection on top")
        };
        let LogicalPlan::Aggregate(agg) = p.input.as_ref() else {
            panic!("aggregate below")
        };
        assert!(
            !matches!(agg.aggr_expr[0], Expr::Alias(_)),
            "redundant alias stripped: {:?}",
            agg.aggr_expr[0]
        );
        assert_eq!(agg.aggr_expr[0].schema_name().to_string(), name);
        let batches = ctx
            .execute_logical_plan(plan)
            .await
            .unwrap()
            .collect()
            .await
            .unwrap();
        assert_eq!(batches.iter().map(RecordBatch::num_rows).sum::<usize>(), 2);
    }

    /// Codex P1 (round 4) on #1116: a composite over the renamed aggregate
    /// that is ALREADY wrapped in a stale, qualifier-embedding alias (name
    /// preservation after simplification) must get the synthetic treatment
    /// too — otherwise the Sort above still references the stale label.
    #[tokio::test]
    async fn pre_aliased_composite_over_renamed_aggregate_gets_synthetic_name() {
        let ctx = ctx_with_t();
        let stale = "sum(t.a * Int64(2))".to_string();
        let cname = "sum(t.a * Int64(2)) + Int64(1)".to_string();
        let plan = LogicalPlanBuilder::from(ctx.table("t").await.unwrap().into_unoptimized_plan())
            .aggregate(
                vec![col("k")],
                vec![sum(col("a") * lit(2.0_f64)).alias(&stale)],
            )
            .unwrap()
            .project(vec![col("k"), (col(&stale) + lit(1.0_f64)).alias(&cname)])
            .unwrap()
            .sort(vec![col(&cname).sort(true, false)])
            .unwrap()
            .build()
            .unwrap();
        let before: Vec<(Option<TableReference>, String)> = plan
            .schema()
            .iter()
            .map(|(q, f)| (q.cloned(), f.name().clone()))
            .collect();

        let out = normalize(plan).unwrap();
        assert!(out.transformed);
        let plan = out.data;
        let after: Vec<(Option<TableReference>, String)> = plan
            .schema()
            .iter()
            .map(|(q, f)| (q.cloned(), f.name().clone()))
            .collect();
        assert_eq!(after, before, "root labels and qualifiers restored");

        // Below the root nothing carries a qualifier-embedding alias anymore.
        let root_ptr: *const LogicalPlan = &raw const plan;
        plan.apply(|node| {
            if std::ptr::eq(node, root_ptr) {
                return Ok(TreeNodeRecursion::Continue);
            }
            for e in node.expressions() {
                if let Expr::Alias(a) = &e {
                    assert!(
                        !a.name.contains("t."),
                        "stale alias survived below the root: {}",
                        a.name
                    );
                }
            }
            Ok(TreeNodeRecursion::Continue)
        })
        .unwrap();

        let batches = ctx
            .execute_logical_plan(plan)
            .await
            .unwrap()
            .collect()
            .await
            .unwrap();
        assert_eq!(batches.iter().map(RecordBatch::num_rows).sum::<usize>(), 2);
    }

    /// Codex P1 (round 5) on #1116: the Window node's OWN name-preserving
    /// alias — `sum(t.a * Int64(2)) OVER ()` re-labelled after simplification
    /// — with no renamed child below. Same hazard as an Aggregate alias.
    #[tokio::test]
    async fn window_own_stale_alias_is_normalized() {
        use datafusion::functions_aggregate::sum::sum_udaf;
        use datafusion::logical_expr::expr::WindowFunction;
        use datafusion::logical_expr::WindowFunctionDefinition;

        let ctx = ctx_with_t();
        let stale = "sum(t.a * Int64(2)) OVER ()".to_string();
        let wexpr = Expr::WindowFunction(Box::new(WindowFunction::new(
            WindowFunctionDefinition::AggregateUDF(sum_udaf()),
            vec![col("a") * lit(2.0_f64)],
        )))
        .alias(&stale);
        let plan = LogicalPlanBuilder::from(ctx.table("t").await.unwrap().into_unoptimized_plan())
            .window(vec![wexpr])
            .unwrap()
            .project(vec![col("k"), col(&stale)])
            .unwrap()
            .build()
            .unwrap();
        let before: Vec<String> = plan
            .schema()
            .fields()
            .iter()
            .map(|f| f.name().clone())
            .collect();

        let out = normalize(plan).unwrap();
        assert!(out.transformed, "the Window's stale alias is normalized");
        let plan = out.data;
        let after: Vec<String> = plan
            .schema()
            .fields()
            .iter()
            .map(|f| f.name().clone())
            .collect();
        assert_eq!(after, before, "root labels restored");
        let LogicalPlan::Projection(p) = &plan else {
            panic!("projection on top")
        };
        let LogicalPlan::Window(w) = p.input.as_ref() else {
            panic!("window below")
        };
        let name = w.window_expr[0].schema_name().to_string();
        assert!(
            name.starts_with("__dataglot_norm_"),
            "synthetic alias, got {name}"
        );
        let batches = ctx
            .execute_logical_plan(plan)
            .await
            .unwrap()
            .collect()
            .await
            .unwrap();
        assert_eq!(batches.iter().map(RecordBatch::num_rows).sum::<usize>(), 3);
    }

    /// Codex P2 (round 5) on #1116: `DistinctOn.select_expr` defines output
    /// fields too; a composite over the renamed aggregate must get a stable
    /// name so the Projection above keeps resolving.
    #[tokio::test]
    async fn distinct_on_composite_over_renamed_aggregate_keeps_parent_reference_valid() {
        let ctx = ctx_with_t();
        let stale = "sum(t.a * Int64(2))".to_string();
        let neg = -col(&stale);
        let nname = neg.schema_name().to_string();
        let plan = LogicalPlanBuilder::from(ctx.table("t").await.unwrap().into_unoptimized_plan())
            .aggregate(
                vec![col("k")],
                vec![sum(col("a") * lit(2.0_f64)).alias(&stale)],
            )
            .unwrap()
            .distinct_on(vec![col("k")], vec![col("k"), neg], None)
            .unwrap()
            .project(vec![col("k"), col(&nname)])
            .unwrap()
            .build()
            .unwrap();
        let before: Vec<String> = plan
            .schema()
            .fields()
            .iter()
            .map(|f| f.name().clone())
            .collect();

        let out = normalize(plan).unwrap();
        assert!(out.transformed);
        let plan = out.data;
        let after: Vec<String> = plan
            .schema()
            .fields()
            .iter()
            .map(|f| f.name().clone())
            .collect();
        assert_eq!(after, before, "root labels restored");
        let batches = ctx
            .execute_logical_plan(plan)
            .await
            .unwrap()
            .collect()
            .await
            .unwrap();
        assert_eq!(batches.iter().map(RecordBatch::num_rows).sum::<usize>(), 2);
    }

    /// Codex P2 (round 6) on #1116: a composite `DISTINCT ON` key and a sort
    /// expression over the renamed aggregate are repointed but must NOT be
    /// aliased (a wrapped sort expression is not a valid sort expression);
    /// only `select_expr` gets the synthetic-name treatment.
    #[tokio::test]
    async fn distinct_on_composite_key_and_sort_over_renamed_aggregate() {
        let ctx = ctx_with_t();
        let stale = "sum(t.a * Int64(2))".to_string();
        let neg = -col(&stale);
        let nname = neg.schema_name().to_string();
        let plan = LogicalPlanBuilder::from(ctx.table("t").await.unwrap().into_unoptimized_plan())
            .aggregate(
                vec![col("k")],
                vec![sum(col("a") * lit(2.0_f64)).alias(&stale)],
            )
            .unwrap()
            .distinct_on(
                vec![neg.clone()],
                vec![col("k"), neg.clone()],
                Some(vec![neg.sort(true, false), col("k").sort(true, false)]),
            )
            .unwrap()
            .project(vec![col("k"), col(&nname)])
            .unwrap()
            .build()
            .unwrap();
        let before: Vec<String> = plan
            .schema()
            .fields()
            .iter()
            .map(|f| f.name().clone())
            .collect();

        let out = normalize(plan).unwrap();
        assert!(out.transformed);
        let plan = out.data;
        let after: Vec<String> = plan
            .schema()
            .fields()
            .iter()
            .map(|f| f.name().clone())
            .collect();
        assert_eq!(after, before, "root labels restored");
        // The ON key and the sort expressions carry no alias.
        plan.apply(|node| {
            if let LogicalPlan::Distinct(Distinct::On(d)) = node {
                assert!(
                    d.on_expr.iter().all(|e| !matches!(e, Expr::Alias(_))),
                    "{:?}",
                    d.on_expr
                );
                if let Some(sorts) = &d.sort_expr {
                    assert!(sorts.iter().all(|s| !matches!(s.expr, Expr::Alias(_))));
                }
            }
            Ok(TreeNodeRecursion::Continue)
        })
        .unwrap();
        let batches = ctx
            .execute_logical_plan(plan)
            .await
            .unwrap()
            .collect()
            .await
            .unwrap();
        // Both k-groups sum to 60, so DISTINCT ON (-60) keeps one row.
        assert_eq!(batches.iter().map(RecordBatch::num_rows).sum::<usize>(), 1);
    }

    /// Codex P1 (round 7) on #1116: a Projection's OWN name-preserving alias
    /// — `SELECT amount * 2 … ORDER BY 1` after literal coercion — with the
    /// Sort above referencing it. Stripped like an Aggregate alias; the root
    /// wrapper restores the label.
    #[tokio::test]
    async fn projection_own_stale_alias_under_sort_is_normalized() {
        let ctx = ctx_with_t();
        let stale = "t.a * Int64(2)".to_string();
        let plan = LogicalPlanBuilder::from(ctx.table("t").await.unwrap().into_unoptimized_plan())
            .project(vec![col("k"), (col("a") * lit(2.0_f64)).alias(&stale)])
            .unwrap()
            .sort(vec![col(&stale).sort(true, false)])
            .unwrap()
            .build()
            .unwrap();
        let before: Vec<(Option<TableReference>, String)> = plan
            .schema()
            .iter()
            .map(|(q, f)| (q.cloned(), f.name().clone()))
            .collect();

        let out = normalize(plan).unwrap();
        assert!(
            out.transformed,
            "the Projection's stale alias is normalized"
        );
        let plan = out.data;
        let after: Vec<(Option<TableReference>, String)> = plan
            .schema()
            .iter()
            .map(|(q, f)| (q.cloned(), f.name().clone()))
            .collect();
        assert_eq!(after, before, "root labels and qualifiers restored");
        let root_ptr: *const LogicalPlan = &raw const plan;
        plan.apply(|node| {
            if std::ptr::eq(node, root_ptr) {
                return Ok(TreeNodeRecursion::Continue);
            }
            for e in node.expressions() {
                if let Expr::Alias(a) = &e {
                    assert!(
                        !a.name.contains("t."),
                        "stale alias survived below the root: {}",
                        a.name
                    );
                }
            }
            Ok(TreeNodeRecursion::Continue)
        })
        .unwrap();
        let batches = ctx
            .execute_logical_plan(plan)
            .await
            .unwrap()
            .collect()
            .await
            .unwrap();
        assert_eq!(batches.iter().map(RecordBatch::num_rows).sum::<usize>(), 3);
    }

    /// Codex P1 (round 8) on #1116: a `DISTINCT ON` node's OWN select
    /// expression carrying the stale alias (no renamed child), referenced by
    /// the Projection above.
    #[tokio::test]
    async fn distinct_on_own_stale_alias_is_normalized() {
        let ctx = ctx_with_t();
        let stale = "t.a * Int64(2)".to_string();
        let plan = LogicalPlanBuilder::from(ctx.table("t").await.unwrap().into_unoptimized_plan())
            .distinct_on(
                vec![col("k")],
                vec![col("k"), (col("a") * lit(2.0_f64)).alias(&stale)],
                Some(vec![col("k").sort(true, false)]),
            )
            .unwrap()
            .project(vec![col("k"), col(&stale)])
            .unwrap()
            .build()
            .unwrap();
        let before: Vec<String> = plan
            .schema()
            .fields()
            .iter()
            .map(|f| f.name().clone())
            .collect();

        let out = normalize(plan).unwrap();
        assert!(
            out.transformed,
            "the DISTINCT ON select alias is normalized"
        );
        let plan = out.data;
        let after: Vec<String> = plan
            .schema()
            .fields()
            .iter()
            .map(|f| f.name().clone())
            .collect();
        assert_eq!(after, before, "root labels restored");
        let LogicalPlan::Projection(p) = &plan else {
            panic!("projection on top")
        };
        let LogicalPlan::Distinct(Distinct::On(d)) = p.input.as_ref() else {
            panic!("distinct on below")
        };
        let name = d.select_expr[1].schema_name().to_string();
        assert!(
            name.starts_with("__dataglot_norm_"),
            "synthetic alias, got {name}"
        );
        assert!(d.on_expr.iter().all(|e| !matches!(e, Expr::Alias(_))));
        let batches = ctx
            .execute_logical_plan(plan)
            .await
            .unwrap()
            .collect()
            .await
            .unwrap();
        assert_eq!(batches.iter().map(RecordBatch::num_rows).sum::<usize>(), 2);
    }
}

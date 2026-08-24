//! Lineage emitter scaffolding for Phase 1's `OpenLineage` MVP.
//!
//! This module plants the trait the per-query lineage hook
//! rides on; the actual HTTP emitter implementation lives in
//! `dataglot-server::lineage` (where `reqwest` is acceptable
//! as a runtime dep). The split honours CLAUDE.md rule 4 —
//! `dataglot-core` stays the minimum-deps crate, and the
//! cross-crate consumers (`dataglot-pgwire`, `dataglot-server`,
//! and eventually `dataglot-policy` for the audit-trail hook)
//! all reference the trait through `dataglot-core` without a
//! lateral dependency between them.
//!
//! Spec: `docs/phases/phase-1/06-openlineage-emitter.md`.
//!
//! # Failure-isolation contract
//!
//! Emitter methods are `async fn` returning `()`, **not**
//! `Result<(), E>`. That's intentional — every concrete
//! emitter is required to absorb its own failure modes
//! (logging at WARN, dropping the event) so that the query
//! path stays green even when the lineage backend is down.
//! See the spec's "Lineage emission MUST NOT propagate
//! failures" exit criterion.
//!
//! # Status
//!
//! Trait + types + noop default + `extract_inputs` (table-level)
//! and `column_lineage` (column-level, structural) analyzers.
//! The HTTP emitter, the pgwire `QueryObserver` extension, and
//! the `dataglot-server` config surface land in follow-up PRs;
//! the `columnLineage` facet emission + the internal lineage
//! graph for propagated enforcement are  slices 2–5
//! (`docs/phases/phase-3/05-lineage-closure.md`).

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::Arc;
use std::time::SystemTime;

use datafusion::common::tree_node::{TreeNode, TreeNodeRecursion};
use datafusion::common::TableReference;
use datafusion::error::DataFusionError;
use datafusion::logical_expr::{Expr, LogicalPlan};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Stable handle for a single query execution, mapped to
/// `OpenLineage`'s `run.runId` field. Constructed as a fresh
/// `UUIDv4` per query — collision risk is effectively zero, but
/// see the spec's "Open questions" for the deterministic-runId
/// follow-up if customers need replay semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RunId(pub Uuid);

impl RunId {
    /// Generate a fresh `UUIDv4`-based run identifier.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for RunId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for RunId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// Outcome of one query execution. Maps to `OpenLineage`'s
/// `eventType` field on the finish event: `COMPLETE` for
/// success, `FAIL` for error. `EXPLAIN`-only queries that
/// never actually execute are intentionally not represented
/// — see the spec's "Lineage events for `EXPLAIN` queries"
/// out-of-scope bullet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryOutcome {
    /// Query executed successfully and returned a result set.
    Success,
    /// Query failed during planning, optimization, or execution.
    /// `QueryFinishContext::error_message` carries the diagnostic.
    Error,
}

/// One source dataset referenced by a query. Each
/// `LogicalPlan::TableScan` in a plan yields exactly one
/// `DatasetRef`; the `OpenLineage` HTTP emitter renders each
/// into the `inputs[i].namespace` + `inputs[i].name` pair on
/// the wire.
///
/// Three-part naming matches the rest of the
/// `dataglot-server` surface (`<catalog>.<schema>.<table>`)
/// so a cross-source JOIN's inputs render consistently
/// regardless of which connector produced them.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct DatasetRef {
    /// Catalog name (the `catalogs.<name>` entry from
    /// `dataglot.toml`, e.g. `"pg"`, `"mysql_demo"`, `"files"`).
    pub catalog: String,
    /// Schema name (`"public"` is the default for sources
    /// without an explicit schema).
    pub schema: String,
    /// Table name within the schema.
    pub table: String,
}

/// Context the emitter sees when a query begins executing.
/// Mapped to the `OpenLineage` `START` event by the HTTP
/// emitter.
#[derive(Debug, Clone)]
pub struct QueryStartContext<'a> {
    /// Stable identifier for this run; paired with the
    /// matching `QueryFinishContext::run_id`.
    pub run_id: RunId,
    /// The SQL string the client submitted. Used for the
    /// `OpenLineage` `job.name` field (shape TBD per the spec's
    /// "Open questions").
    pub sql: &'a str,
    /// The connecting session's identity. The HTTP emitter
    /// renders the user / org / groups as a Dataglot-specific
    /// custom facet (`dataglot.identity`).
    pub identity: &'a Identity,
    /// Wall-clock start time. Mapped to `OpenLineage`'s
    /// `eventTime` and `run.facets.nominalTime.nominalStartTime`.
    pub started_at: SystemTime,
}

/// Context the emitter sees when a query finishes (success
/// or failure). Mapped to the `OpenLineage` `COMPLETE` or
/// `FAIL` event by the HTTP emitter.
#[derive(Debug, Clone)]
pub struct QueryFinishContext<'a> {
    /// Same value as the matching
    /// `QueryStartContext::run_id`.
    pub run_id: RunId,
    /// Whether the query succeeded.
    pub outcome: QueryOutcome,
    /// Wall-clock finish time. The emitter computes
    /// duration as `finished_at - started_at` rather than
    /// putting duration on the wire — `OpenLineage` doesn't
    /// have a duration field; downstream consumers infer it.
    pub finished_at: SystemTime,
    /// Error diagnostic when `outcome` is
    /// [`QueryOutcome::Error`]. Mapped to the
    /// `run.facets.errorMessage` facet.
    pub error_message: Option<&'a str>,
    /// Source datasets the query referenced, deduplicated.
    /// Extracted from the executed plan via
    /// [`extract_inputs`].
    pub input_datasets: &'a [DatasetRef],
    /// Column-level lineage for the query's output columns, from
    /// [`column_lineage`] (with masking overlaid by the emitter).
    /// `None` when column lineage wasn't computed (e.g. a planning
    /// failure, or a query with no inputs). Rendered as the
    /// `OpenLineage` `columnLineage` facet on the output dataset.
    pub column_lineage: Option<&'a ColumnLineage>,
}

/// Identity context — same shape as
/// `dataglot_policy::Identity` but re-declared here because
/// `dataglot-core` cannot depend on `dataglot-policy` (the
/// dependency direction goes the other way per CLAUDE.md
/// rule 4). The two structs are kept in sync by hand.
///
/// The HTTP emitter renders the populated fields as a
/// `dataglot.identity` custom facet on the `RunEvent`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Identity {
    /// Authenticated user name.
    pub user: Option<String>,
    /// Owning organization / tenant.
    pub org: Option<String>,
    /// Org-group memberships.
    pub org_groups: Vec<String>,
}

/// Per-query lineage emitter. Implementations capture the
/// `START` + `COMPLETE`/`FAIL` event pair and ship it to a
/// governance backend (`OpenLineage` HTTP, future Kafka, etc).
///
/// **Failure isolation** — the trait methods return `()`, not
/// `Result`. Implementations are required to absorb their own
/// failure modes (log at WARN, drop the event) so the query
/// path stays green even when the lineage backend is down.
/// See the module-level doc + the spec's "Lineage emission
/// MUST NOT propagate failures" exit criterion.
#[async_trait::async_trait]
pub trait LineageEmitter: Send + Sync + std::fmt::Debug + 'static {
    /// Called before query execution starts. Maps to the
    /// `OpenLineage` `START` event in the HTTP emitter.
    async fn on_query_start(&self, ctx: &QueryStartContext<'_>);

    /// Called after query execution finishes (success or
    /// error). Maps to `OpenLineage` `COMPLETE` / `FAIL`.
    async fn on_query_finish(&self, ctx: &QueryFinishContext<'_>);
}

/// Default lineage emitter — silently drops every event.
///
/// Used as the default when `dataglot.toml` doesn't declare
/// a `lineage` block. Matches the no-op shape of
/// `dataglot_policy::NoopPolicyEnforcer` and
/// `dataglot_pgwire::NoopObserver`. The runtime cost is two
/// async-trait pointer indirections per query — effectively
/// free.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoopLineageEmitter;

#[async_trait::async_trait]
impl LineageEmitter for NoopLineageEmitter {
    async fn on_query_start(&self, _ctx: &QueryStartContext<'_>) {}
    async fn on_query_finish(&self, _ctx: &QueryFinishContext<'_>) {}
}

/// Walk a `LogicalPlan` and collect every referenced
/// `(catalog, schema, table)` triple, deduplicated.
///
/// Used by the `OpenLineage` HTTP emitter to populate the
/// `inputs[]` array on the `COMPLETE` event. The function is
/// pure (no `Result`, just empty Vec on no inputs) so the
/// emitter can call it without error-handling ceremony in the
/// hot path.
///
/// Naming convention: tables registered without an explicit
/// catalog / schema are normalised to the catalog's default
/// (`"default"` / `"public"`), matching `DataFusion`'s planner
/// behaviour. Tables registered with a partial name (only
/// schema + table, no catalog) get the catalog filled in
/// from the resolution context.
///
/// # Errors
/// Returns a [`DataFusionError`] only on traversal-level
/// failures (e.g., a custom plan node with a broken
/// `children()` impl). Normal table-scan walks succeed.
pub fn extract_inputs(plan: &LogicalPlan) -> Result<Vec<DatasetRef>, DataFusionError> {
    let mut seen = Vec::<DatasetRef>::new();
    plan.apply(|node| {
        if let LogicalPlan::TableScan(scan) = node {
            let dr = dataset_of(&scan.table_name);
            if !seen.contains(&dr) {
                seen.push(dr);
            }
        }
        Ok(TreeNodeRecursion::Continue)
    })?;
    Ok(seen)
}

/// Normalise a `TableReference` to the three-part
/// `(catalog, schema, table)` [`DatasetRef`].
///
/// `TableReference` is one of `Bare(table)` /
/// `Partial(schema, table)` / `Full(catalog, schema, table)`.
/// Missing components default to `"default"` / `"public"`,
/// matching `DataFusion`'s planner behaviour, so downstream
/// consumers (table- and column-level lineage alike) see a
/// stable shape.
fn dataset_of(r: &TableReference) -> DatasetRef {
    dataset_of_with_defaults(r, "default", "public")
}

/// Like [`extract_inputs`], but fills a catalog/schema-less table
/// reference from the caller's configured session defaults rather than the
/// `"default"` / `"public"` placeholders.
///
/// The observability query registry uses this so a bare `nation` submitted
/// in a session whose `default_catalog` is `snowflake` is attributed to the
/// `snowflake` catalog — the placeholder `"default"` catalog does not exist
/// and made the dashboard's per-query source list useless.
/// Lineage keeps the placeholder defaults via [`extract_inputs`] so its
/// output shape is unchanged.
///
/// # Errors
/// Returns a [`DataFusionError`] only on traversal-level failures, exactly
/// as [`extract_inputs`].
pub fn extract_inputs_with_defaults(
    plan: &LogicalPlan,
    default_catalog: &str,
    default_schema: &str,
) -> Result<Vec<DatasetRef>, DataFusionError> {
    let mut seen = Vec::<DatasetRef>::new();
    plan.apply(|node| {
        if let LogicalPlan::TableScan(scan) = node {
            let dr = dataset_of_with_defaults(&scan.table_name, default_catalog, default_schema);
            if !seen.contains(&dr) {
                seen.push(dr);
            }
        }
        Ok(TreeNodeRecursion::Continue)
    })?;
    Ok(seen)
}

/// Shared normaliser: fill any missing `catalog` / `schema` component of a
/// `TableReference` from the supplied fallbacks.
fn dataset_of_with_defaults(
    r: &TableReference,
    default_catalog: &str,
    default_schema: &str,
) -> DatasetRef {
    DatasetRef {
        catalog: r.catalog().unwrap_or(default_catalog).to_string(),
        schema: r.schema().unwrap_or(default_schema).to_string(),
        table: r.table().to_string(),
    }
}

// ===========================================================
// Column-level lineage ( slice 1 — structural analyzer)
// ===========================================================
//
// Pure `LogicalPlan` analysis: for each *output* column of a
// plan, which source `(catalog, schema, table, field)` columns
// contributed, and how (the [`TransformationType`]). This is the
// data behind the `OpenLineage` `columnLineage` facet and the
// internal lineage graph used for propagated tag enforcement
// (Interface 4) — see `docs/phases/phase-3/05-lineage-closure.md`.
//
// Crate-placement note (rule 4): this is **structural only** and
// has no `dataglot-policy` dependency. The policy masking rewrite
// surfaces here as an ordinary `TRANSFORMATION` (a non-trivial
// projection expression); *labelling* that transformation as a
// mask is applied server-side in the emitter, where both `core`
// and `policy` are visible. Keeping the analyzer in `core`
// alongside `extract_inputs` avoids a new crate entirely.

/// One source field — a column of a source dataset, identified
/// by its three-part [`DatasetRef`] plus the field name.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct FieldRef {
    /// The source dataset the field belongs to.
    pub dataset: DatasetRef,
    /// The column name within that dataset.
    pub field: String,
}

/// How an output column derives from a contributing source
/// field — the strongest transformation seen along the path
/// from the base table column up to this output column.
///
/// Ordered by "derived-ness" (`Identity` < `Transformation` <
/// `Aggregation`); when a field flows through multiple nodes the
/// path keeps the **maximum** (see [`TransformationType::combine`]).
/// This ranking is what the propagation pass (slice 4) consults:
/// `Identity`/`Transformation` are value-preserving and propagate
/// a source tag by default; `Aggregation` breaks the value chain
/// and does **not** propagate unless a policy opts in (see the
/// spec's resolved decision 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransformationType {
    /// Bare-column passthrough — including GROUP BY key columns.
    /// The output value *is* the input value.
    Identity,
    /// Scalar transformation (`CAST` / `CASE` / string ops /
    /// arithmetic, and the policy masking rewrite). Not
    /// byte-identical, but derived from a single row's value —
    /// value-preserving for tag propagation.
    Transformation,
    /// Aggregate output (`SUM` / `COUNT` / `AVG` / `MIN` / `MAX`).
    /// A derived statistic over many rows; breaks the
    /// column-identity chain.
    Aggregation,
}

impl TransformationType {
    fn rank(self) -> u8 {
        match self {
            Self::Identity => 0,
            Self::Transformation => 1,
            Self::Aggregation => 2,
        }
    }

    /// The stronger (more-derived) of two transformations.
    #[must_use]
    pub fn combine(self, other: Self) -> Self {
        if self.rank() >= other.rank() {
            self
        } else {
            other
        }
    }
}

/// A single contribution of a source field to an output column,
/// tagged with how it was transformed along the way.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InputFieldContribution {
    /// The contributing source field.
    pub field: FieldRef,
    /// The strongest transformation along the path from `field`
    /// to the output column.
    pub transform: TransformationType,
    /// Whether a column-masking policy was applied to this field
    /// in producing the output column. The structural analyzer
    /// always leaves this `false` — it has no policy knowledge
    /// (rule 4). It is set by the policy-aware emitter
    /// (`dataglot-server`), which overlays the configured masks
    /// onto the analyzer's output. Maps to the `OpenLineage`
    /// `columnLineage` transformation's `masking` boolean.
    #[serde(default)]
    pub masking: bool,
}

/// Column lineage for one output column: its name plus the set
/// of source fields that contributed to it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutputFieldLineage {
    /// The output column name (as it appears in the plan's
    /// output schema).
    pub output_field: String,
    /// Contributing source fields, deduplicated by field
    /// (keeping the strongest transformation).
    pub inputs: Vec<InputFieldContribution>,
}

/// Column-level lineage for a whole plan — one
/// [`OutputFieldLineage`] per column of the plan's output
/// schema, positional with that schema.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ColumnLineage {
    /// One entry per output column, in output-schema order.
    pub fields: Vec<OutputFieldLineage>,
}

/// Add a contribution to an accumulator, deduplicating by
/// [`FieldRef`] and keeping the strongest transformation.
fn merge_contribution(acc: &mut Vec<InputFieldContribution>, c: InputFieldContribution) {
    if let Some(existing) = acc.iter_mut().find(|e| e.field == c.field) {
        existing.transform = existing.transform.combine(c.transform);
        existing.masking |= c.masking;
    } else {
        acc.push(c);
    }
}

/// Strip nested `Expr::Alias` wrappers to reach the underlying
/// expression (so `col AS x` is recognised as a bare column).
fn strip_alias(e: &Expr) -> &Expr {
    match e {
        Expr::Alias(a) => strip_alias(&a.expr),
        other => other,
    }
}

/// Map one projection/group/aggregate expression to its source
/// contributions, given the positional lineage of the node's
/// input columns.
///
/// `extra` is the transformation the expression itself imposes:
/// `Transformation` for scalar projection/group exprs,
/// `Aggregation` for aggregate exprs. A bare column reference
/// (possibly aliased) imposes nothing — it passes the child
/// contribution through unchanged.
fn expr_contributions(
    expr: &Expr,
    input_schema: &datafusion::common::DFSchema,
    input_map: &[Vec<InputFieldContribution>],
    extra: TransformationType,
) -> Vec<InputFieldContribution> {
    let is_bare = matches!(strip_alias(expr), Expr::Column(_));
    let mut out = Vec::new();
    for col in expr.column_refs() {
        let idx = if let Ok(idx) = input_schema.index_of_column(col) {
            idx
        } else {
            // Qualified lookup failed — qualifiers can be stripped
            // or rewritten by optimizer passes. Fall back to an
            // *unambiguous* name-only match so the lineage edge
            // isn't silently lost; bail only if the name is absent
            // or ambiguous (a column not from this input, e.g. a
            // correlated outer ref — its lineage is captured at
            // the owning node).
            let mut by_name = input_schema
                .fields()
                .iter()
                .enumerate()
                .filter(|(_, f)| f.name() == &col.name)
                .map(|(i, _)| i);
            match (by_name.next(), by_name.next()) {
                (Some(i), None) => i,
                _ => continue,
            }
        };
        for contrib in &input_map[idx] {
            let transform = if is_bare {
                contrib.transform
            } else {
                contrib.transform.combine(extra)
            };
            merge_contribution(
                &mut out,
                InputFieldContribution {
                    field: contrib.field.clone(),
                    transform,
                    masking: contrib.masking,
                },
            );
        }
    }
    out
}

/// Column lineage for an `Aggregate` node. Output schema is the
/// group exprs followed by the aggregate exprs. GROUP BY keys
/// preserve the value (bare key → `Identity`); aggregate outputs
/// are `Aggregation`. `GROUPING SETS`/`ROLLUP` add a synthetic
/// grouping-id column — if the output arity doesn't match the
/// plain group+aggr shape, stay conservative (empty provenance).
fn aggregate_lineage(
    agg: &datafusion::logical_expr::Aggregate,
) -> Result<Vec<Vec<InputFieldContribution>>, DataFusionError> {
    let input_map = lineage_map(&agg.input)?;
    let input_schema = agg.input.schema();
    let expected = agg.group_expr.len() + agg.aggr_expr.len();
    if agg.schema.fields().len() != expected {
        return Ok(vec![Vec::new(); agg.schema.fields().len()]);
    }
    let mut out = Vec::with_capacity(expected);
    for e in &agg.group_expr {
        out.push(expr_contributions(
            e,
            input_schema,
            &input_map,
            TransformationType::Transformation,
        ));
    }
    for e in &agg.aggr_expr {
        out.push(expr_contributions(
            e,
            input_schema,
            &input_map,
            TransformationType::Aggregation,
        ));
    }
    Ok(out)
}

/// Column lineage for a `Join` node. The output schema shape
/// depends on the join type — only inner/outer joins concatenate
/// both sides. Semi/anti joins keep just the matched side; mark
/// joins keep one side plus a synthetic boolean `mark` column
/// (no source provenance). (Cross joins are inner `Join` nodes
/// with no condition in DataFusion 53.) Mis-handling this
/// mis-attributes right-side output columns to left-side sources
/// — flagged critical in review.
fn join_lineage(
    join: &datafusion::logical_expr::Join,
) -> Result<Vec<Vec<InputFieldContribution>>, DataFusionError> {
    use datafusion::logical_expr::JoinType;
    match join.join_type {
        JoinType::Inner | JoinType::Left | JoinType::Right | JoinType::Full => {
            let mut out = lineage_map(&join.left)?;
            out.extend(lineage_map(&join.right)?);
            Ok(out)
        }
        JoinType::LeftSemi | JoinType::LeftAnti => lineage_map(&join.left),
        JoinType::RightSemi | JoinType::RightAnti => lineage_map(&join.right),
        JoinType::LeftMark => {
            let mut out = lineage_map(&join.left)?;
            out.push(Vec::new());
            Ok(out)
        }
        JoinType::RightMark => {
            let mut out = lineage_map(&join.right)?;
            out.push(Vec::new());
            Ok(out)
        }
    }
}

/// Positional column lineage for a plan node: one contribution
/// set per column of `plan.schema()`, in schema order.
///
/// Recurses bottom-up. Handles the node types that carry
/// column-provenance information explicitly (`TableScan`,
/// `Projection`, `Aggregate`, `Join`, `Union`, `SubqueryAlias`);
/// for any other single-input node whose output arity matches
/// its input (`Filter`, `Sort`, `Limit`, `Distinct`,
/// `Repartition`, …) it passes the child lineage through
/// unchanged. Genuinely unhandled shapes yield empty
/// contributions for their columns (conservative: "unknown
/// provenance", never a wrong edge).
fn lineage_map(plan: &LogicalPlan) -> Result<Vec<Vec<InputFieldContribution>>, DataFusionError> {
    match plan {
        LogicalPlan::TableScan(scan) => {
            let dataset = dataset_of(&scan.table_name);
            Ok(scan
                .projected_schema
                .fields()
                .iter()
                .map(|f| {
                    vec![InputFieldContribution {
                        field: FieldRef {
                            dataset: dataset.clone(),
                            field: f.name().clone(),
                        },
                        transform: TransformationType::Identity,
                        masking: false,
                    }]
                })
                .collect())
        }
        LogicalPlan::Projection(proj) => {
            let input_map = lineage_map(&proj.input)?;
            let input_schema = proj.input.schema();
            Ok(proj
                .expr
                .iter()
                .map(|e| {
                    expr_contributions(
                        e,
                        input_schema,
                        &input_map,
                        TransformationType::Transformation,
                    )
                })
                .collect())
        }
        LogicalPlan::Aggregate(agg) => aggregate_lineage(agg),
        LogicalPlan::Join(join) => join_lineage(join),
        LogicalPlan::Union(union) => {
            // Output schema follows the first input; each output
            // column unions the corresponding column across all
            // branches.
            let branch_maps = union
                .inputs
                .iter()
                .map(|i| lineage_map(i))
                .collect::<Result<Vec<_>, _>>()?;
            let width = union.schema.fields().len();
            let mut out = vec![Vec::new(); width];
            for branch in &branch_maps {
                for (i, contribs) in branch.iter().enumerate().take(width) {
                    for c in contribs {
                        merge_contribution(&mut out[i], c.clone());
                    }
                }
            }
            Ok(out)
        }
        LogicalPlan::SubqueryAlias(alias) => {
            // Re-qualification only — columns map positionally.
            lineage_map(&alias.input)
        }
        other => {
            let inputs = other.inputs();
            if inputs.len() == 1 {
                let child = lineage_map(inputs[0])?;
                if child.len() == other.schema().fields().len() {
                    // Filter / Sort / Limit / Distinct / Repartition:
                    // same columns, same order, pass through.
                    return Ok(child);
                }
            }
            // Unknown shape — conservative empty provenance.
            Ok(vec![Vec::new(); other.schema().fields().len()])
        }
    }
}

/// Compute column-level lineage for a plan: for each output
/// column, which source `(catalog, schema, table, field)`
/// columns contributed and how.
///
/// Pure `LogicalPlan` analysis (rule 2 — no engine
/// reimplementation). The result feeds the `OpenLineage`
/// `columnLineage` facet (slice 2) and the internal lineage
/// graph used for propagated tag enforcement (slice 4). See
/// `docs/phases/phase-3/05-lineage-closure.md`.
///
/// # Errors
/// Returns a [`DataFusionError`] only on traversal-level
/// failures; normal plans succeed (unknown node shapes yield
/// empty — never wrong — provenance).
pub fn column_lineage(plan: &LogicalPlan) -> Result<ColumnLineage, DataFusionError> {
    let map = lineage_map(plan)?;
    let fields = plan
        .schema()
        .fields()
        .iter()
        .zip(map)
        .map(|(f, inputs)| OutputFieldLineage {
            output_field: f.name().clone(),
            inputs,
        })
        .collect();
    Ok(ColumnLineage { fields })
}

// ===========================================================
// Internal lineage graph
// ===========================================================
//
// The resolution primitive for propagated tag enforcement
// (Interface 4, slice 4): accumulate the per-product column
// lineage produced by `column_lineage` into a directed graph,
// then answer "which columns descend from this source column?".
//
// Decision 1 (spec): this internal graph is the source of truth
// for enforcement (no synchronous DataHub call on the plan-time
// hot path — rules 9 & 11). It's pure data over `FieldRef` nodes
// with no policy dependency (rule 4); slice 4 consults it during
// plan-time enforcement to extend a source column's policy to its
// descendants.

/// A directed edge in the [`LineageGraph`]: a derived field and
/// the strongest transformation by which it depends on the source.
#[derive(Debug, Clone, PartialEq, Eq)]
struct LineageEdge {
    to: FieldRef,
    transform: TransformationType,
}

/// An in-memory column-lineage graph. Edges point from a source
/// field to each derived field that depends on it; the transitive
/// forward closure from a source column is its set of descendants.
///
/// Built by registering each derived product's [`ColumnLineage`]
/// (a view, saved query, or other derived dataset — the MVP
/// targets per decision 3). Per decision 1 this graph is rebuilt
/// from the data-product registry at startup; it holds no policy
/// state itself.
#[derive(Debug, Default, Clone)]
pub struct LineageGraph {
    /// Adjacency: source field → edges to dependent derived fields.
    edges: HashMap<FieldRef, Vec<LineageEdge>>,
}

impl LineageGraph {
    /// An empty graph.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a derived product's column lineage. Each output
    /// column of `lineage` becomes a derived field
    /// `FieldRef { dataset: product, field: <output_field> }`, with
    /// an edge from every contributing source field to it. Adding
    /// the same `(source, derived)` pair again keeps the strongest
    /// transformation (so a chained re-registration never weakens
    /// an existing edge).
    pub fn add_product(&mut self, product: &DatasetRef, lineage: &ColumnLineage) {
        for ofl in &lineage.fields {
            let derived = FieldRef {
                dataset: product.clone(),
                field: ofl.output_field.clone(),
            };
            for c in &ofl.inputs {
                self.add_edge(&c.field, &derived, c.transform);
            }
        }
    }

    // Takes the endpoints by reference and clones only when a new
    // node/edge is actually inserted — re-adding an existing edge
    // allocates nothing.
    fn add_edge(&mut self, from: &FieldRef, to: &FieldRef, transform: TransformationType) {
        if let Some(adj) = self.edges.get_mut(from) {
            if let Some(existing) = adj.iter_mut().find(|e| &e.to == to) {
                existing.transform = existing.transform.combine(transform);
            } else {
                adj.push(LineageEdge {
                    to: to.clone(),
                    transform,
                });
            }
        } else {
            self.edges.insert(
                from.clone(),
                vec![LineageEdge {
                    to: to.clone(),
                    transform,
                }],
            );
        }
    }

    /// Every field that has at least one outgoing edge — i.e. a
    /// source/intermediate column some derived column depends on.
    /// Lets callers match a (possibly under-qualified) rule against
    /// the graph's actual source nodes rather than guessing their
    /// exact qualification (see the propagated-mask matcher, ).
    pub fn source_fields(&self) -> impl Iterator<Item = &FieldRef> {
        self.edges.keys()
    }

    /// Every edge in the graph, as `(source, derived, transform)`
    /// triples — the read-only serialization surface for
    /// observability endpoints ('s lineage view). Order is
    /// unspecified (adjacency-map iteration).
    pub fn edges(&self) -> impl Iterator<Item = (&FieldRef, &FieldRef, TransformationType)> {
        self.edges
            .iter()
            .flat_map(|(from, adj)| adj.iter().map(move |e| (from, &e.to, e.transform)))
    }

    /// Every field that transitively derives from `root`.
    ///
    /// By default (`propagate_through_aggregation = false`)
    /// traversal does **not** cross `AGGREGATION` edges — the value
    /// chain breaks there, so a tag on a source column does not
    /// propagate through `SUM`/`COUNT`/… by default (resolved
    /// decision 4). Pass `true` for stricter regimes that propagate
    /// through aggregates. The `root` itself is never included.
    /// Cycle-safe.
    #[must_use]
    pub fn descendants(
        &self,
        root: &FieldRef,
        propagate_through_aggregation: bool,
    ) -> BTreeSet<FieldRef> {
        // Traverse over borrowed nodes (all live in `self.edges`,
        // plus the external `root`); clone only when inserting into
        // the returned set.
        let mut out = BTreeSet::new();
        let mut visited: HashSet<&FieldRef> = HashSet::new();
        visited.insert(root);
        let mut stack: Vec<&FieldRef> = vec![root];
        while let Some(node) = stack.pop() {
            let Some(adj) = self.edges.get(node) else {
                continue;
            };
            for edge in adj {
                if matches!(edge.transform, TransformationType::Aggregation)
                    && !propagate_through_aggregation
                {
                    continue;
                }
                if visited.insert(&edge.to) {
                    out.insert(edge.to.clone());
                    stack.push(&edge.to);
                }
            }
        }
        out
    }
}

/// Trait object alias the cross-crate consumers store.
/// Matches the `Arc<dyn QueryObserver>` shape pgwire uses.
pub type DynLineageEmitter = Arc<dyn LineageEmitter>;

#[cfg(test)]
mod tests {
    use super::*;

    use datafusion::arrow::array::{Int32Array, RecordBatch, StringArray};
    use datafusion::arrow::datatypes::{DataType, Field, Schema};
    use datafusion::datasource::MemTable;
    use datafusion::prelude::SessionContext;

    fn empty_session() -> SessionContext {
        SessionContext::new()
    }

    async fn plan_for(ctx: &SessionContext, sql: &str) -> LogicalPlan {
        ctx.sql(sql)
            .await
            .expect("sql parses")
            .logical_plan()
            .clone()
    }

    fn register_users(ctx: &SessionContext) {
        let schema = Arc::new(Schema::new(vec![
            Field::new("id", DataType::Int32, false),
            Field::new("name", DataType::Utf8, false),
        ]));
        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(Int32Array::from(vec![1, 2])),
                Arc::new(StringArray::from(vec!["Alice", "Bob"])),
            ],
        )
        .expect("batch");
        let table = MemTable::try_new(schema, vec![vec![batch]]).expect("memtable");
        ctx.register_table("users", Arc::new(table)).unwrap();
    }

    fn register_orders(ctx: &SessionContext) {
        let schema = Arc::new(Schema::new(vec![
            Field::new("id", DataType::Int32, false),
            Field::new("user_id", DataType::Int32, false),
        ]));
        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(Int32Array::from(vec![100, 101])),
                Arc::new(Int32Array::from(vec![1, 2])),
            ],
        )
        .expect("batch");
        let table = MemTable::try_new(schema, vec![vec![batch]]).expect("memtable");
        ctx.register_table("orders", Arc::new(table)).unwrap();
    }

    #[tokio::test]
    async fn extract_inputs_returns_empty_for_const_query() {
        // `SELECT 1` has no TableScan node. The walker
        // returns an empty Vec rather than erroring.
        let ctx = empty_session();
        let plan = plan_for(&ctx, "SELECT 1").await;
        let inputs = extract_inputs(&plan).expect("walk succeeds");
        assert!(
            inputs.is_empty(),
            "expected no inputs for SELECT 1, got {inputs:?}"
        );
    }

    #[tokio::test]
    async fn extract_inputs_returns_one_for_single_table() {
        // SELECT against a registered MemTable yields one
        // DatasetRef. `users` is registered as a bare name,
        // so the catalog/schema default to
        // ("default", "public") per the normalisation rule.
        let ctx = empty_session();
        register_users(&ctx);
        let plan = plan_for(&ctx, "SELECT id FROM users").await;
        let inputs = extract_inputs(&plan).expect("walk succeeds");
        assert_eq!(inputs.len(), 1, "expected one input, got {inputs:?}");
        assert_eq!(inputs[0].table, "users");
        // Default normalisation
        assert_eq!(inputs[0].schema, "public");
        assert_eq!(inputs[0].catalog, "default");
    }

    #[tokio::test]
    async fn extract_inputs_with_defaults_resolves_bare_reference_to_session_catalog() {
        // Same bare `users` scan, but the defaults-aware extractor fills the
        // missing catalog/schema from the *session's* configured defaults —
        // so a query submitted in a `snowflake`/`tpch_sf1` session is
        // attributed to the `snowflake` catalog, not the `"default"`
        // placeholder that made the dashboard's per-query source list useless
        //. Regression guard for that dashboard bug.
        let ctx = empty_session();
        register_users(&ctx);
        let plan = plan_for(&ctx, "SELECT id FROM users").await;

        // The placeholder extractor (kept for lineage) still yields "default".
        assert_eq!(extract_inputs(&plan).expect("walk")[0].catalog, "default");

        // The defaults-aware extractor fills from the supplied session defaults.
        let inputs =
            extract_inputs_with_defaults(&plan, "snowflake", "tpch_sf1").expect("walk succeeds");
        assert_eq!(inputs.len(), 1);
        assert_eq!(inputs[0].table, "users");
        assert_eq!(inputs[0].schema, "tpch_sf1");
        assert_eq!(inputs[0].catalog, "snowflake");
    }

    #[test]
    fn dataset_of_with_defaults_fills_only_missing_components() {
        use datafusion::common::TableReference;
        // Bare: both catalog and schema come from the defaults.
        let d = dataset_of_with_defaults(&TableReference::bare("t"), "cat", "sch");
        assert_eq!(
            (d.catalog.as_str(), d.schema.as_str(), d.table.as_str()),
            ("cat", "sch", "t")
        );
        // Partial (schema.table): schema is kept, only catalog is filled.
        let d = dataset_of_with_defaults(&TableReference::partial("s2", "t"), "cat", "sch");
        assert_eq!((d.catalog.as_str(), d.schema.as_str()), ("cat", "s2"));
        // Full: nothing is overridden by the defaults.
        let d = dataset_of_with_defaults(&TableReference::full("c3", "s3", "t"), "cat", "sch");
        assert_eq!((d.catalog.as_str(), d.schema.as_str()), ("c3", "s3"));
    }

    #[tokio::test]
    async fn extract_inputs_returns_two_for_join_deduplicated() {
        // JOIN across two tables yields both inputs. If the
        // same table appears twice (e.g. self-join), the
        // walker deduplicates — pin both invariants.
        let ctx = empty_session();
        register_users(&ctx);
        register_orders(&ctx);
        let plan = plan_for(
            &ctx,
            "SELECT u.id, o.id FROM users u JOIN orders o ON u.id = o.user_id",
        )
        .await;
        let inputs = extract_inputs(&plan).expect("walk succeeds");
        assert_eq!(inputs.len(), 2, "expected two inputs, got {inputs:?}");
        let tables: Vec<&str> = inputs.iter().map(|d| d.table.as_str()).collect();
        assert!(tables.contains(&"users"));
        assert!(tables.contains(&"orders"));
    }

    #[tokio::test]
    async fn extract_inputs_dedups_self_join() {
        // Self-join references the same table twice via
        // aliases; both TableScans resolve to the same
        // DatasetRef and the walker drops the duplicate.
        let ctx = empty_session();
        register_users(&ctx);
        let plan = plan_for(&ctx, "SELECT a.id FROM users a JOIN users b ON a.id = b.id").await;
        let inputs = extract_inputs(&plan).expect("walk succeeds");
        assert_eq!(
            inputs.len(),
            1,
            "self-join must produce exactly one DatasetRef, got {inputs:?}"
        );
    }

    #[tokio::test]
    async fn noop_emitter_drops_events_silently() {
        // Default trait impl. Two calls, no panic, no
        // side effect, no return value to check.
        let e = NoopLineageEmitter;
        let id = Identity::default();
        let start = QueryStartContext {
            run_id: RunId::new(),
            sql: "SELECT 1",
            identity: &id,
            started_at: SystemTime::now(),
        };
        e.on_query_start(&start).await;
        let inputs: Vec<DatasetRef> = vec![];
        let finish = QueryFinishContext {
            run_id: start.run_id,
            outcome: QueryOutcome::Success,
            finished_at: SystemTime::now(),
            error_message: None,
            input_datasets: &inputs,
            column_lineage: None,
        };
        e.on_query_finish(&finish).await;
    }

    #[test]
    fn run_id_is_fresh_per_call() {
        // `UUIDv4` collision probability is effectively zero;
        // pin that two consecutive calls produce different
        // values so the production usage never accidentally
        // shares run IDs across queries.
        let a = RunId::new();
        let b = RunId::new();
        assert_ne!(a, b);
    }

    #[test]
    fn run_id_displays_as_uuid_string() {
        // The HTTP emitter serializes RunId to JSON; pin
        // the Display impl shape so log lines and JSON
        // payloads match.
        let id = RunId::new();
        let s = format!("{id}");
        // `UUIDv4` string is 36 chars including 4 hyphens.
        assert_eq!(s.len(), 36);
        assert_eq!(s.chars().filter(|c| *c == '-').count(), 4);
    }

    #[test]
    fn emitter_is_send_sync_via_arc_dyn() {
        // Cross-crate consumers store `Arc<dyn LineageEmitter>`.
        // Pin the trait-object shape — a future signature
        // change that broke Send + Sync + 'static would
        // surface here.
        let _e: DynLineageEmitter = Arc::new(NoopLineageEmitter);
    }

    // -------- column-level lineage (column_lineage) --------

    /// Find the lineage entry for a named output column.
    fn field<'a>(cl: &'a ColumnLineage, name: &str) -> &'a OutputFieldLineage {
        cl.fields
            .iter()
            .find(|f| f.output_field == name)
            .unwrap_or_else(|| panic!("output column {name} not found in {cl:?}"))
    }

    /// Assert a single contribution from `table.field` with the
    /// given transform.
    fn assert_only(ofl: &OutputFieldLineage, table: &str, fname: &str, t: TransformationType) {
        assert_eq!(
            ofl.inputs.len(),
            1,
            "{} expected one contribution, got {:?}",
            ofl.output_field,
            ofl.inputs
        );
        let c = &ofl.inputs[0];
        assert_eq!(
            c.field.dataset.table, table,
            "table for {}",
            ofl.output_field
        );
        assert_eq!(c.field.field, fname, "field for {}", ofl.output_field);
        assert_eq!(c.transform, t, "transform for {}", ofl.output_field);
    }

    #[test]
    fn transformation_type_combine_keeps_strongest() {
        use TransformationType::{Aggregation, Identity, Transformation};
        assert_eq!(Identity.combine(Transformation), Transformation);
        assert_eq!(Transformation.combine(Identity), Transformation);
        assert_eq!(Transformation.combine(Aggregation), Aggregation);
        assert_eq!(Aggregation.combine(Identity), Aggregation);
        assert_eq!(Identity.combine(Identity), Identity);
    }

    #[tokio::test]
    async fn column_lineage_projection_identity() {
        // Bare-column projection → IDENTITY passthrough to the
        // base table column.
        let ctx = empty_session();
        register_users(&ctx);
        let plan = plan_for(&ctx, "SELECT id, name FROM users").await;
        let cl = column_lineage(&plan).expect("analyze");
        assert_eq!(cl.fields.len(), 2);
        assert_only(
            field(&cl, "id"),
            "users",
            "id",
            TransformationType::Identity,
        );
        assert_only(
            field(&cl, "name"),
            "users",
            "name",
            TransformationType::Identity,
        );
    }

    #[tokio::test]
    async fn column_lineage_scalar_expr_is_transformation() {
        // A non-trivial projection expression (what the policy
        // masking rewrite also produces structurally) marks the
        // contribution TRANSFORMATION, traced back to the source
        // column it reads.
        let ctx = empty_session();
        register_users(&ctx);
        let plan = plan_for(&ctx, "SELECT upper(name) AS shout FROM users").await;
        let cl = column_lineage(&plan).expect("analyze");
        assert_only(
            field(&cl, "shout"),
            "users",
            "name",
            TransformationType::Transformation,
        );
    }

    #[tokio::test]
    async fn column_lineage_passes_through_filter() {
        // Filter is a single-input, same-arity node → lineage
        // passes through unchanged (still IDENTITY to the base).
        let ctx = empty_session();
        register_users(&ctx);
        let plan = plan_for(&ctx, "SELECT id FROM users WHERE name = 'Alice'").await;
        let cl = column_lineage(&plan).expect("analyze");
        assert_only(
            field(&cl, "id"),
            "users",
            "id",
            TransformationType::Identity,
        );
    }

    #[tokio::test]
    async fn column_lineage_join_fans_in_from_both_sides() {
        // A join's output columns trace to their respective
        // source tables.
        let ctx = empty_session();
        register_users(&ctx);
        register_orders(&ctx);
        let plan = plan_for(
            &ctx,
            "SELECT u.name, o.id AS order_id \
             FROM users u JOIN orders o ON u.id = o.user_id",
        )
        .await;
        let cl = column_lineage(&plan).expect("analyze");
        assert_only(
            field(&cl, "name"),
            "users",
            "name",
            TransformationType::Identity,
        );
        assert_only(
            field(&cl, "order_id"),
            "orders",
            "id",
            TransformationType::Identity,
        );
    }

    #[tokio::test]
    async fn column_lineage_aggregate_marks_agg_and_keeps_group_key_identity() {
        // GROUP BY key column stays IDENTITY (the key *is* the
        // sensitive value — resolved decision 4); the aggregate
        // output is AGGREGATION, traced to the aggregated column.
        let ctx = empty_session();
        register_orders(&ctx);
        let plan = plan_for(
            &ctx,
            "SELECT user_id, count(id) AS n FROM orders GROUP BY user_id",
        )
        .await;
        let cl = column_lineage(&plan).expect("analyze");
        assert_only(
            field(&cl, "user_id"),
            "orders",
            "user_id",
            TransformationType::Identity,
        );
        assert_only(
            field(&cl, "n"),
            "orders",
            "id",
            TransformationType::Aggregation,
        );
    }

    #[tokio::test]
    async fn column_lineage_const_has_no_inputs() {
        // A literal output column has no source provenance.
        let ctx = empty_session();
        let plan = plan_for(&ctx, "SELECT 1 AS one").await;
        let cl = column_lineage(&plan).expect("analyze");
        assert!(
            field(&cl, "one").inputs.is_empty(),
            "literal column should have no inputs, got {:?}",
            field(&cl, "one").inputs
        );
    }

    #[tokio::test]
    async fn column_lineage_aggregation_dominates_over_inner_transform() {
        // sum(id + 1): the inner arithmetic is a TRANSFORMATION
        // but the enclosing aggregate dominates → AGGREGATION.
        let ctx = empty_session();
        register_orders(&ctx);
        let plan = plan_for(&ctx, "SELECT sum(id + 1) AS s FROM orders").await;
        let cl = column_lineage(&plan).expect("analyze");
        assert_only(
            field(&cl, "s"),
            "orders",
            "id",
            TransformationType::Aggregation,
        );
    }

    // -------- semi / anti / mark joins (output-schema shape) --------
    //
    // Built directly via LogicalPlanBuilder: the optimizer is what
    // produces the Right* variants, so SQL alone won't reliably
    // yield them. These pin the join-type-aware kept-side logic —
    // the critical bug where right-side output columns were
    // attributed to left-side sources.

    async fn scan_plan(ctx: &SessionContext, name: &str) -> LogicalPlan {
        ctx.table(name)
            .await
            .expect("table exists")
            .into_unoptimized_plan()
    }

    /// All output columns of `cl` trace solely to `table`.
    fn assert_all_from(cl: &ColumnLineage, table: &str) {
        for ofl in &cl.fields {
            for c in &ofl.inputs {
                assert_eq!(
                    c.field.dataset.table, table,
                    "output {} traced to {} (expected only {table})",
                    ofl.output_field, c.field.dataset.table
                );
            }
        }
    }

    #[tokio::test]
    async fn column_lineage_left_semi_keeps_left_only() {
        use datafusion::logical_expr::{JoinType, LogicalPlanBuilder};
        use datafusion::prelude::col;
        let ctx = empty_session();
        register_users(&ctx);
        register_orders(&ctx);
        let left = scan_plan(&ctx, "users").await;
        let right = scan_plan(&ctx, "orders").await;
        let plan = LogicalPlanBuilder::from(left)
            .join_on(
                right,
                JoinType::LeftSemi,
                [col("users.id").eq(col("orders.user_id"))],
            )
            .expect("join")
            .build()
            .expect("build");
        let cl = column_lineage(&plan).expect("analyze");
        // Output schema is the left (users) side only.
        assert_eq!(cl.fields.len(), 2, "left-semi outputs left arity");
        assert_all_from(&cl, "users");
    }

    #[tokio::test]
    async fn column_lineage_right_semi_keeps_right_only() {
        use datafusion::logical_expr::{JoinType, LogicalPlanBuilder};
        use datafusion::prelude::col;
        let ctx = empty_session();
        register_users(&ctx);
        register_orders(&ctx);
        let left = scan_plan(&ctx, "users").await;
        let right = scan_plan(&ctx, "orders").await;
        let plan = LogicalPlanBuilder::from(left)
            .join_on(
                right,
                JoinType::RightSemi,
                [col("users.id").eq(col("orders.user_id"))],
            )
            .expect("join")
            .build()
            .expect("build");
        let cl = column_lineage(&plan).expect("analyze");
        // Output schema is the right (orders) side only — the
        // regression was attributing these to `users`.
        assert_eq!(cl.fields.len(), 2, "right-semi outputs right arity");
        assert_all_from(&cl, "orders");
    }

    #[tokio::test]
    async fn column_lineage_right_anti_keeps_right_only() {
        use datafusion::logical_expr::{JoinType, LogicalPlanBuilder};
        use datafusion::prelude::col;
        let ctx = empty_session();
        register_users(&ctx);
        register_orders(&ctx);
        let left = scan_plan(&ctx, "users").await;
        let right = scan_plan(&ctx, "orders").await;
        let plan = LogicalPlanBuilder::from(left)
            .join_on(
                right,
                JoinType::RightAnti,
                [col("users.id").eq(col("orders.user_id"))],
            )
            .expect("join")
            .build()
            .expect("build");
        let cl = column_lineage(&plan).expect("analyze");
        assert_eq!(cl.fields.len(), 2, "right-anti outputs right arity");
        assert_all_from(&cl, "orders");
    }

    #[tokio::test]
    async fn column_lineage_left_mark_appends_provenance_free_mark() {
        use datafusion::logical_expr::{JoinType, LogicalPlanBuilder};
        use datafusion::prelude::col;
        let ctx = empty_session();
        register_users(&ctx);
        register_orders(&ctx);
        let left = scan_plan(&ctx, "users").await;
        let right = scan_plan(&ctx, "orders").await;
        let plan = LogicalPlanBuilder::from(left)
            .join_on(
                right,
                JoinType::LeftMark,
                [col("users.id").eq(col("orders.user_id"))],
            )
            .expect("join")
            .build()
            .expect("build");
        let cl = column_lineage(&plan).expect("analyze");
        // Left (users) columns + a synthetic `mark` boolean with
        // no source provenance.
        assert_eq!(cl.fields.len(), 3, "left-mark = left arity + mark");
        let mark = cl.fields.last().expect("mark column");
        assert!(
            mark.inputs.is_empty(),
            "mark column has no source provenance, got {:?}",
            mark.inputs
        );
        // The two non-mark columns trace to users.
        for ofl in &cl.fields[..2] {
            for c in &ofl.inputs {
                assert_eq!(c.field.dataset.table, "users");
            }
        }
    }

    // -------- internal lineage graph (LineageGraph) --------

    fn dref(table: &str) -> DatasetRef {
        DatasetRef {
            catalog: "default".into(),
            schema: "public".into(),
            table: table.into(),
        }
    }

    fn fref(table: &str, field: &str) -> FieldRef {
        FieldRef {
            dataset: dref(table),
            field: field.into(),
        }
    }

    /// A one-column `ColumnLineage`: `output` ← `src_table.src_field`
    /// via `transform`.
    fn one_col(
        output: &str,
        src_table: &str,
        src_field: &str,
        transform: TransformationType,
    ) -> ColumnLineage {
        ColumnLineage {
            fields: vec![OutputFieldLineage {
                output_field: output.into(),
                inputs: vec![InputFieldContribution {
                    field: fref(src_table, src_field),
                    transform,
                    masking: false,
                }],
            }],
        }
    }

    #[test]
    fn lineage_graph_single_hop_descendant() {
        // View `v` projects users.email → v.email (IDENTITY).
        let mut g = LineageGraph::new();
        g.add_product(
            &dref("v"),
            &one_col("email", "users", "email", TransformationType::Identity),
        );
        let desc = g.descendants(&fref("users", "email"), false);
        assert!(desc.contains(&fref("v", "email")));
        assert_eq!(desc.len(), 1);
        // The source column is never its own descendant.
        assert!(!desc.contains(&fref("users", "email")));
    }

    #[test]
    fn lineage_graph_transitive_through_chain() {
        // users.email → v.email → w.addr. A tag on users.email must
        // reach both derived columns.
        let mut g = LineageGraph::new();
        g.add_product(
            &dref("v"),
            &one_col("email", "users", "email", TransformationType::Identity),
        );
        g.add_product(
            &dref("w"),
            &one_col("addr", "v", "email", TransformationType::Transformation),
        );
        let desc = g.descendants(&fref("users", "email"), false);
        assert!(desc.contains(&fref("v", "email")));
        assert!(desc.contains(&fref("w", "addr")));
        assert_eq!(desc.len(), 2);
    }

    #[test]
    fn lineage_graph_aggregation_edge_blocks_by_default() {
        // total ← orders.amount via AGGREGATION. By default the tag
        // does NOT propagate through the aggregate (decision 4).
        let mut g = LineageGraph::new();
        g.add_product(
            &dref("revenue"),
            &one_col("total", "orders", "amount", TransformationType::Aggregation),
        );
        assert!(g.descendants(&fref("orders", "amount"), false).is_empty());
        // …but a strict regime can opt in.
        let strict = g.descendants(&fref("orders", "amount"), true);
        assert!(strict.contains(&fref("revenue", "total")));
    }

    #[test]
    fn lineage_graph_aggregation_blocks_only_past_the_aggregate() {
        // users.email → v.email (IDENTITY) → agg.cnt (AGGREGATION).
        // Default traversal reaches v.email but stops before agg.cnt.
        let mut g = LineageGraph::new();
        g.add_product(
            &dref("v"),
            &one_col("email", "users", "email", TransformationType::Identity),
        );
        g.add_product(
            &dref("agg"),
            &one_col("cnt", "v", "email", TransformationType::Aggregation),
        );
        let desc = g.descendants(&fref("users", "email"), false);
        assert!(desc.contains(&fref("v", "email")));
        assert!(!desc.contains(&fref("agg", "cnt")));
    }

    #[test]
    fn lineage_graph_unknown_source_has_no_descendants() {
        let g = LineageGraph::new();
        assert!(g.descendants(&fref("ghost", "col"), false).is_empty());
    }

    #[test]
    fn lineage_graph_add_edge_keeps_strongest_transform() {
        // Re-registering the same edge with a weaker transform must
        // not downgrade it: once TRANSFORMATION, an IDENTITY re-add
        // stays TRANSFORMATION (so an aggregate edge can't be
        // silently turned value-preserving).
        let mut g = LineageGraph::new();
        g.add_product(
            &dref("v"),
            &one_col("c", "t", "x", TransformationType::Transformation),
        );
        g.add_product(
            &dref("v"),
            &one_col("c", "t", "x", TransformationType::Identity),
        );
        // Edge remains TRANSFORMATION → still traversed by default.
        assert!(g
            .descendants(&fref("t", "x"), false)
            .contains(&fref("v", "c")));
        // Now make it an aggregate edge; default traversal drops it.
        g.add_product(
            &dref("v"),
            &one_col("c", "t", "x", TransformationType::Aggregation),
        );
        assert!(g.descendants(&fref("t", "x"), false).is_empty());
    }

    #[test]
    fn lineage_graph_is_cycle_safe() {
        // Construct a cycle a→b→a; descendants must terminate.
        let mut g = LineageGraph::new();
        g.add_product(
            &dref("b"),
            &one_col("x", "a", "x", TransformationType::Identity),
        );
        g.add_product(
            &dref("a"),
            &one_col("x", "b", "x", TransformationType::Identity),
        );
        let desc = g.descendants(&fref("a", "x"), false);
        // Terminates with b.x; the root a.x is not re-added as its
        // own descendant despite the back-edge.
        assert_eq!(desc.len(), 1);
        assert!(desc.contains(&fref("b", "x")));
        assert!(!desc.contains(&fref("a", "x")));
    }
}

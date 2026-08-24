//! `FederationLogicalCodec` — Phase 2 slice 4b.
//!
//! Wraps Ballista's stock `BallistaLogicalExtensionCodec` and adds a
//! federation hook so cross-source queries survive the Ballista wire
//! format. Routes `FederatedPlanNode` (federation's UDLN) through a
//! `prost`-encoded envelope keyed on the connector name; falls back
//! to Ballista's inner codec for every other plan-node shape it
//! already handles (parquet, CSV, JSON, Arrow, Avro file formats +
//! `BallistaCacheNode`).
//!
//! # Wire shape
//!
//! Encoded payload is a `LogicalCodecPayload` (crate-private)
//! protobuf message with three fields:
//!
//! 1. `connector_name: String` — opaque identifier matching the key
//!    in the operator's `dataglot.toml` `[catalogs.*]` block. The
//!    worker-side decoder looks this up in the `ConnectorRegistry`
//!    to recover an `Arc<dyn FederationPlanner>`.
//! 2. `inner_plan: Vec<u8>` — the inner `LogicalPlan` from
//!    `FederatedPlanNode.plan` encoded via `datafusion-proto`'s
//!    `LogicalPlanNode`. Uses Ballista's stock codec for the encode/
//!    decode so file-format providers nested under the federation
//!    boundary keep working.
//! 3. `version: u32` — wire-format version tag. Bumped in lockstep
//!    with any breaking field-shape change; decoder rejects unknown
//!    versions with a typed `DataFusionError::Internal`.
//!
//! Spec 02 slice 4b's design PR (#268) deliberately picked a
//! **distinct** prost message from the physical-side
//! `FederationPlanCodec`'s `CodecPayload` even though the field
//! shapes are identical — separate type names protect against a
//! cross-side decode call silently succeeding on bytes that should
//! have gone to the other codec.
//!
//! # Reverse-lookup by `compute_context` (post-slice-4b.3)
//!
//! The encoder downcasts `Extension.node` to `FederatedPlanNode` via
//! `UserDefinedLogicalNode::as_any()`, then walks `node.plan` for a
//! `LogicalPlan::TableScan` whose source resolves to a
//! `FederatedTableProviderAdaptor` (via federation's public
//! `get_table_source` helper). From the recovered
//! `FederatedTableSource` it pulls the `FederationProvider` and
//! asks for `compute_context()` — a stable, opaque string identity
//! the executor exposes through the trait. The registry's
//! `find_name_by_compute_context(...)` translates that string into
//! the registered connector name written onto the wire.
//!
//! ## Why not `Arc::ptr_eq` (slice 4b.1's failed gamble)
//!
//! Slice 4b.1 keyed the reverse-lookup on
//! `Arc::ptr_eq(stored_planner, fed_node.planner)`. The contract held
//! in unit tests because the same Arc round-tripped through the
//! registry. In production it never did: every
//! `SQLFederationProvider::new(executor)` call constructs a fresh
//! `Arc<SQLFederationPlanner>` independent of whatever the registry
//! holds. PR #272's testcontainer e2e was the first run on the real
//! construction path; the lookup missed; codec encoding failed.
//! Slice 4b.3 routes identity through the string `compute_context()`
//! produces — same identity guarantee, no pointer-allocation
//! coupling between registry construction and federation analysis.
//!
//! # Backward compatibility with slice 4a
//!
//! `FederationLogicalCodec::default()` still works — produces a
//! registry-less wrapper that pure-delegates to Ballista's stock
//! codec. Federation queries through that codec still panic at the
//! `"LogicalExtensionCodec is not provided"` boundary. The new
//! `FederationLogicalCodec::new(registry)` constructor is what
//! unlocks federation-through-Ballista; the
//! `BallistaContextFactory::with_logical_codec` slot from slice 4a
//! is where it gets plugged in.

use std::sync::Arc;

use ballista::datafusion::arrow::datatypes::SchemaRef;
use ballista::datafusion::catalog::TableProvider;
use ballista::datafusion::common::tree_node::{Transformed, TreeNode, TreeNodeRecursion};
use ballista::datafusion::common::{Result as DfResult, TableReference};
use ballista::datafusion::error::DataFusionError;
use ballista::datafusion::execution::TaskContext;
use ballista::datafusion::logical_expr::{Expr, Extension, LogicalPlan, SubqueryAlias, TableScan};
use ballista_core::serde::BallistaLogicalExtensionCodec;
use datafusion_federation::sql::{SQLFederationProvider, SQLTableSource};
use datafusion_federation::{get_table_source, FederatedPlanNode, FederatedTableProviderAdaptor};
use datafusion_proto::logical_plan::{AsLogicalPlan, LogicalExtensionCodec};
use datafusion_proto::protobuf::LogicalPlanNode;
use dataglot_federation::registry::DynConnectorRegistry;
use prost::Message;

/// The pre-submission failure WARN — the *only* server-side trace an
/// -class failure leaves (it fires client-side before any
/// Ballista job exists, so nothing reaches scheduler state).
///
/// CONTRACT: the testbench's Cluster tab counts these
/// failures by scanning the server log for the substring
/// `"cannot be serialized for distributed execution"` — see
/// `count_presubmission_failures` in
/// `crates/dataglot-testbench/src/cluster.rs`. Reword this message and
/// that banner silently dies; the
/// `presubmission_warn_stays_greppable_by_the_testbench` test below
/// fails first and points you here.
pub const PRESUBMISSION_WARN: &str = "table's provider cannot be serialized \
     for distributed execution; the query will fail — run this catalog \
     single-node";

/// Client-facing message for a query touching a federated source whose
/// kind isn't wired into the distributed connector registry. Raised as a
/// clean `NotImplemented` at this codec boundary, and re-applied
/// by `crate::cancel_on_drop` when Ballista's plan-serialization path
/// re-wraps it in an `Internal` error that would otherwise reach the client
/// with a misleading "bug in DataFusion — file a report" tail.
///
/// What lands here: the direct-`TableProvider` sources (OData / SAP / REST)
/// always run single-node — they don't produce a SQL fragment to serialize.
/// Oracle and ADBC distribute only when the server *and* every executor were
/// built with their feature (`--features oracle-pure` / `--features adbc`,
/// ); without it they also fall through to this message. Postgres,
/// MySQL, and Snowflake are always distributable.
pub(crate) const DISTRIBUTED_SOURCE_UNSUPPORTED: &str =
    "this query touches a federated source that is not available in \
     distributed mode: its source kind is not wired into the distributed \
     connector registry. Direct-TableProvider sources (OData / SAP / REST) \
     always run single-node; Oracle and ADBC distribute only when the \
     server and executors were built with their feature (--features \
     oracle-pure / adbc). Query it on a single-node server, or move the \
     data to a supported catalog (postgres / mysql / snowflake federated \
     sources, Iceberg warehouses, and local/object-storage files work \
     distributed).";

/// Wire-format version tag carried on every encoded payload.
/// Bumped in lockstep with any breaking change to the crate-private
/// `LogicalCodecPayload` field shape. The decoder rejects unknown
/// versions with a typed error so mixed-version clusters fail
/// loudly.
const LOGICAL_CODEC_VERSION: u32 = 1;

/// Protobuf-encoded envelope for a [`FederatedPlanNode`].
///
/// Crate-private — slice 4b.2's design decision (PR #268) was to
/// keep the wire envelope local to this codec rather than re-using
/// `dataglot-federation::codec::CodecPayload`. Same field shape, but
/// the distinct type name eliminates the "mixed-side decode call
/// silently succeeds on the wrong bytes" failure mode.
///
/// Field tag numbers are stable — adding a new field requires
/// picking a fresh unused tag and bumping [`LOGICAL_CODEC_VERSION`].
/// Renaming or repurposing an existing tag is a wire-break.
#[derive(Clone, PartialEq, Message)]
struct LogicalCodecPayload {
    #[prost(string, tag = "1")]
    connector_name: String,
    #[prost(bytes, tag = "2")]
    inner_plan: Vec<u8>,
    #[prost(uint32, tag = "3")]
    version: u32,
}

/// Protobuf-encoded envelope for a federated `TableProvider`.
///
/// Slice 4b.3 follow-up — datafusion-proto walks the inner
/// `FederatedPlanNode.plan` and calls `try_encode_table_provider`
/// on every `TableScan`'s source. Without this envelope the call
/// hits the inner Ballista codec, which doesn't know about
/// `FederatedTableProviderAdaptor` and errors with
/// `"LogicalExtensionCodec is not provided"` (PR #272's second
/// failure mode). The wire shape is intentionally tiny: just the
/// connector name + version. The worker rebuilds the full
/// `SQLFederationProvider → SQLTableSource → FederatedTableProviderAdaptor`
/// chain from the executor it looks up by name plus the
/// `table_ref` + `schema` datafusion-proto passes at decode time.
#[derive(Clone, PartialEq, Message)]
struct TableProviderPayload {
    #[prost(string, tag = "1")]
    connector_name: String,
    #[prost(uint32, tag = "2")]
    version: u32,
    /// Provider family discriminator. Empty (the prost
    /// default, so pre-118 payloads keep decoding) ⇒ registry SQL
    /// source; [`PROVIDER_KIND_WAREHOUSE`] ⇒ Iceberg warehouse table,
    /// rebuilt lazily from the warehouse registry.
    #[prost(string, tag = "3")]
    provider_kind: String,
}

/// [`TableProviderPayload::provider_kind`] value for warehouse tables.
const PROVIDER_KIND_WAREHOUSE: &str = "warehouse";

/// Ballista-compatible `LogicalExtensionCodec` for the Dataglot stack.
///
/// Slice 4b: wraps `BallistaLogicalExtensionCodec` for file-format
/// providers and adds federation handling via the
/// [`ConnectorRegistry`](dataglot_federation::ConnectorRegistry).
pub struct FederationLogicalCodec {
    inner: Arc<BallistaLogicalExtensionCodec>,
    /// `Some(registry)` enables federation encode/decode via
    /// connector-name lookup. `None` (the slice-4a default) means
    /// pure-delegation to the inner codec — federation queries through
    /// that variant still panic at the encode boundary. The
    /// `BallistaContextFactory::with_logical_codec` slot is where
    /// production boot plugs the federation-aware variant in.
    registry: Option<DynConnectorRegistry>,
    /// Warehouse (Iceberg) connectors for lazily-rebuilt lakehouse
    /// tables. `None` ⇒ warehouse tables fail encode with
    /// the  guidance error, as before.
    warehouses: Option<dataglot_federation::iceberg::DynWarehouseRegistry>,
}

impl FederationLogicalCodec {
    /// Construct a registry-less codec (slice-4a behaviour: pure
    /// delegation to Ballista's stock codec). Federation queries
    /// through this variant still fail at the encode boundary.
    /// Equivalent to `FederationLogicalCodec::default()`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Construct a federation-aware codec backed by `registry`.
    /// The encoder downcasts `Extension.node` to `FederatedPlanNode`,
    /// walks the inner plan tree for a federated `TableScan`, pulls
    /// `FederationProvider::compute_context()` off it, and uses
    /// `registry.find_name_by_compute_context(...)` to write the
    /// connector name into the wire envelope; the decoder uses
    /// `registry.lookup_planner(name)` to reconstruct the planner
    /// Arc. Slice 4b.2 wire shape, slice 4b.3 reverse-lookup.
    #[must_use]
    pub fn with_registry(registry: DynConnectorRegistry) -> Self {
        Self {
            inner: Arc::new(BallistaLogicalExtensionCodec::default()),
            registry: Some(registry),
            warehouses: None,
        }
    }

    /// Register warehouse (Iceberg) connectors so lakehouse tables
    /// serialize for distributed dispatch. A table whose
    /// catalog qualifier matches a registered warehouse name encodes
    /// as a lazy identity envelope; the decoding side rebuilds a
    /// [`dataglot_federation::iceberg::LazyWarehouseTableProvider`]
    /// from *its* registry — the catalog `load_table` happens at
    /// execute time, never at decode.
    #[must_use]
    pub fn with_warehouse_registry(
        mut self,
        warehouses: dataglot_federation::iceberg::DynWarehouseRegistry,
    ) -> Self {
        self.warehouses = Some(warehouses);
        self
    }

    /// True when warehouse (Iceberg) tables are serializable through
    /// this codec ( wiring inspection, mirrors
    /// [`Self::has_registry`]).
    #[must_use]
    pub fn has_warehouse_registry(&self) -> bool {
        self.warehouses.is_some()
    }

    /// True when this codec is configured for federation handling
    /// (a registry was supplied at construction). Used by tests
    /// and adjacent code to inspect the wiring state.
    #[must_use]
    pub fn has_registry(&self) -> bool {
        self.registry.is_some()
    }
}

impl Default for FederationLogicalCodec {
    fn default() -> Self {
        Self {
            inner: Arc::new(BallistaLogicalExtensionCodec::default()),
            registry: None,
            warehouses: None,
        }
    }
}

// Deliberate `missing_fields_in_debug` allow: same shape as the
// `dataglot-federation::InMemoryConnectorRegistry` impl — the
// registry trait object could surface implementation details.
#[allow(clippy::missing_fields_in_debug)]
impl std::fmt::Debug for FederationLogicalCodec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FederationLogicalCodec")
            .field("inner", &"BallistaLogicalExtensionCodec::default()")
            .field(
                "registry",
                &if self.registry.is_some() {
                    "<dyn ConnectorRegistry>"
                } else {
                    "None"
                },
            )
            .finish()
    }
}

impl LogicalExtensionCodec for FederationLogicalCodec {
    fn try_decode(
        &self,
        buf: &[u8],
        inputs: &[LogicalPlan],
        ctx: &TaskContext,
    ) -> DfResult<Extension> {
        // Federation path: if we have a registry AND the bytes parse
        // as a `LogicalCodecPayload` with our version tag, treat it
        // as a federation envelope. Otherwise fall through to the
        // inner Ballista codec, which handles every native plan-node
        // shape Ballista itself emits.
        //
        // Passing `self` (rather than `DefaultLogicalExtensionCodec`)
        // as the inner logical codec on the recursive walk lets the
        // `FederatedPlanNode.plan`'s nested `TableScan` round-trip
        // through `try_decode_table_provider` for federated sources
        // (slice 4b.3 follow-up). The slice-4a default codec would
        // hit "LogicalExtensionCodec is not provided" on every real
        // federation query.
        if let Some(registry) = self.registry.as_ref() {
            if let Some(extension) = try_decode_federation(buf, ctx, registry, self)? {
                return Ok(extension);
            }
        }
        self.inner.try_decode(buf, inputs, ctx)
    }

    fn try_encode(&self, node: &Extension, buf: &mut Vec<u8>) -> DfResult<()> {
        // Federation path: if we have a registry AND the node
        // downcasts to `FederatedPlanNode`, encode our envelope.
        // Otherwise delegate. See `try_decode` for why the recursive
        // codec is `self`, not the stock default.
        if let Some(registry) = self.registry.as_ref() {
            if let Some(fed_node) = node.node.as_any().downcast_ref::<FederatedPlanNode>() {
                return encode_federation(fed_node, registry, self, buf);
            }
        }
        self.inner.try_encode(node, buf)
    }

    fn try_decode_table_provider(
        &self,
        buf: &[u8],
        table_ref: &TableReference,
        schema: SchemaRef,
        ctx: &TaskContext,
    ) -> DfResult<Arc<dyn TableProvider>> {
        // Warehouse path: rebuild a lazy provider from this
        // side's warehouse registry. No IO — the catalog `load_table`
        // stays deferred to execute time.
        if let Some(warehouses) = self.warehouses.as_ref() {
            if let Some(provider) =
                try_decode_warehouse_table_provider(buf, table_ref, &schema, warehouses)?
            {
                return Ok(provider);
            }
        }
        // Federation path: if we have a registry AND the bytes parse
        // as our `TableProviderPayload`, rebuild a
        // `FederatedTableProviderAdaptor` from the connector name.
        // Otherwise fall through to Ballista's inner codec.
        if let Some(registry) = self.registry.as_ref() {
            if let Some(provider) =
                try_decode_table_provider_federation(buf, table_ref, &schema, registry)?
            {
                // The federated provider MUST reach the plan unwrapped: federation's
                // SQL generator re-plans from these `TableScan` sources and panics
                // (`get_table_source().expect()`) on anything that isn't a
                // `FederatedTableProviderAdaptor`.  per-source metrics are
                // instead attached at *physical* decode, above the resulting
                // `VirtualExecutionPlan` (see `dataglot_federation::codec`).
                return Ok(provider);
            }
        }
        self.inner
            .try_decode_table_provider(buf, table_ref, schema, ctx)
    }

    fn try_encode_table_provider(
        &self,
        table_ref: &TableReference,
        node: Arc<dyn TableProvider>,
        buf: &mut Vec<u8>,
    ) -> DfResult<()> {
        // Warehouse path: a table whose catalog qualifier
        // names a registered warehouse encodes as a lazy identity
        // envelope — the catalog name IS the identity, no downcast on
        // the provider needed (the server only registers Iceberg
        // catalogs in the warehouse registry).
        if let Some(warehouses) = self.warehouses.as_ref() {
            if let Some(catalog) = table_ref.catalog() {
                if warehouses.lookup(catalog).is_some() {
                    return encode_warehouse_table_provider(catalog, buf);
                }
            }
        }
        // Federation path: if we have a registry AND the provider
        // downcasts to `FederatedTableProviderAdaptor`, emit our
        // envelope so the worker can rebuild the chain by name.
        // Otherwise delegate.
        if let Some(registry) = self.registry.as_ref() {
            if let Some(adaptor) = (node.as_ref() as &dyn std::any::Any)
                .downcast_ref::<FederatedTableProviderAdaptor>()
            {
                return encode_federated_table_provider(table_ref, adaptor, registry, buf);
            }
        }
        self.inner
            .try_encode_table_provider(table_ref, node, buf)
            .map_err(|source| {
                //  part C — a provider neither we nor Ballista's
                // stock codec can serialize (e.g. the Iceberg/warehouse
                // `TableProvider`, tracked separately for real support).
                // Two problems with letting `source` propagate raw:
                //
                // 1. The message is `NotImplemented("LogicalExtensionCodec
                //    is not provided")` — it names no table and, once
                //    Ballista wraps it in `DataFusionError::Internal`,
                //    DataFusion appends "file a bug report in our issue
                //    tracker" boilerplate that sends operators upstream
                //    for what is a Dataglot capability boundary.
                // 2. It fails *client-side, before job submission* — no
                //    Ballista job exists, so nothing shows in scheduler
                //    state, and the pgwire error path doesn't log. It was
                //    completely invisible server-side.
                //
                // The WARN fixes the log blind spot; the rewritten message
                // leads with the table name and the actionable next step.
                tracing::warn!(
                    table = %table_ref,
                    error = %source,
                    "{}",
                    PRESUBMISSION_WARN
                );
                DataFusionError::NotImplemented(format!(
                    "table '{table_ref}' is not available in distributed \
                     mode yet: its provider has no plan-serialization \
                     codec (this is a Dataglot limitation, not a DataFusion \
                     bug). Query it on a single-node server, or move the \
                     data to a supported catalog (federated SQL sources, \
                     Iceberg warehouses, and local/object-storage files \
                     work distributed). Underlying error: {source}"
                ))
            })
    }

    fn try_decode_file_format(
        &self,
        buf: &[u8],
        ctx: &TaskContext,
    ) -> DfResult<Arc<dyn ballista::datafusion::datasource::file_format::FileFormatFactory>> {
        self.inner.try_decode_file_format(buf, ctx)
    }

    fn try_encode_file_format(
        &self,
        buf: &mut Vec<u8>,
        node: Arc<dyn ballista::datafusion::datasource::file_format::FileFormatFactory>,
    ) -> DfResult<()> {
        self.inner.try_encode_file_format(buf, node)
    }

    fn try_decode_udf(
        &self,
        name: &str,
        buf: &[u8],
    ) -> DfResult<Arc<ballista::datafusion::logical_expr::ScalarUDF>> {
        self.inner.try_decode_udf(name, buf)
    }

    fn try_encode_udf(
        &self,
        node: &ballista::datafusion::logical_expr::ScalarUDF,
        buf: &mut Vec<u8>,
    ) -> DfResult<()> {
        self.inner.try_encode_udf(node, buf)
    }

    fn try_decode_udaf(
        &self,
        name: &str,
        buf: &[u8],
    ) -> DfResult<Arc<ballista::datafusion::logical_expr::AggregateUDF>> {
        self.inner.try_decode_udaf(name, buf)
    }

    fn try_encode_udaf(
        &self,
        node: &ballista::datafusion::logical_expr::AggregateUDF,
        buf: &mut Vec<u8>,
    ) -> DfResult<()> {
        self.inner.try_encode_udaf(node, buf)
    }

    fn try_decode_udwf(
        &self,
        name: &str,
        buf: &[u8],
    ) -> DfResult<Arc<ballista::datafusion::logical_expr::WindowUDF>> {
        self.inner.try_decode_udwf(name, buf)
    }

    fn try_encode_udwf(
        &self,
        node: &ballista::datafusion::logical_expr::WindowUDF,
        buf: &mut Vec<u8>,
    ) -> DfResult<()> {
        self.inner.try_encode_udwf(node, buf)
    }
}

// ---------------------------------------------------------------------------
// Federation encode/decode helpers
// ---------------------------------------------------------------------------

fn encode_federation(
    fed_node: &FederatedPlanNode,
    registry: &DynConnectorRegistry,
    inner_logical_codec: &dyn LogicalExtensionCodec,
    buf: &mut Vec<u8>,
) -> DfResult<()> {
    // Slice 4b.3 reverse-lookup. The previous slice (4b.1) used
    // `Arc::ptr_eq` on `fed_node.planner`; that path is dead because
    // federation allocates a fresh planner Arc inside every
    // `SQLFederationProvider::new`. See the module-level doc comment
    // for the full rationale.
    let context = compute_context_from_plan(&fed_node.plan)?.ok_or_else(|| {
        DataFusionError::Internal(
            "FederationLogicalCodec: federated plan does not contain a TableScan \
             backed by FederatedTableProviderAdaptor — cannot anchor connector \
             identity for wire encoding"
                .to_string(),
        )
    })?;

    let name = registry
        .find_name_by_compute_context(&context)
        .ok_or_else(|| {
            // This lookup runs against the COORDINATOR's own registry
            // at plan-encode time, so a miss means the source kind was
            // never wired for distributed execution (`registry_sql_kind`
            // classified it to `None`: OData / SAP / REST, plus Oracle /
            // ADBC when their feature wasn't built — ) — NOT
            // coordinator/worker config drift. Surface
            // the  capability-boundary error with the
            // actionable next step; the old Internal(`…check
            // [catalogs.*] agreement…`) shape sent operators chasing a
            // phantom config bug (found by the  distributed-adbc
            // e2e). Don't leak the raw compute_context — SQL
            // connectors often encode host/database/user identity into
            // it (CLAUDE.md rule 12). CodeRabbit flagged this on
            // PR #272.
            tracing::warn!("{}", PRESUBMISSION_WARN);
            DataFusionError::NotImplemented(DISTRIBUTED_SOURCE_UNSUPPORTED.to_string())
        })?
        .to_string();

    // Encode the inner LogicalPlan via datafusion-proto. Uses the
    // default logical codec (which handles every node DataFusion's
    // stock planner emits) — nested federation nodes would re-enter
    // this codec via the outer pass.
    let inner_plan = LogicalPlanNode::try_from_logical_plan(&fed_node.plan, inner_logical_codec)?;
    let mut inner_plan_bytes = Vec::new();
    inner_plan
        .encode(&mut inner_plan_bytes)
        .map_err(|e| DataFusionError::Internal(format!("inner LogicalPlanNode encode: {e}")))?;

    let payload = LogicalCodecPayload {
        connector_name: name,
        inner_plan: inner_plan_bytes,
        version: LOGICAL_CODEC_VERSION,
    };
    payload
        .encode(buf)
        .map_err(|e| DataFusionError::Internal(format!("LogicalCodecPayload encode: {e}")))?;
    Ok(())
}

/// Walk a `FederatedPlanNode`'s inner plan looking for the first
/// `TableScan` whose `TableSource` resolves to a federated source
/// (a `FederatedTableProviderAdaptor`), and pull the
/// `FederationProvider::compute_context()` off it.
///
/// The walk uses `TreeNodeRecursion::Stop` on the first match — a
/// `FederatedPlanNode` produced by federation's analyzer is, by
/// construction, a single-provider subplan. If multiple federated
/// scans were ever present in one node we'd still encode under the
/// first `compute_context` we find; that matches the analyzer's own
/// "same `FederationProvider`" grouping invariant.
///
/// Returns `Ok(None)` if no federated `TableScan` was found — the
/// caller surfaces this as the missing-anchor error. Errors from
/// `get_table_source` (e.g. malformed `TableSource`) propagate.
fn compute_context_from_plan(plan: &LogicalPlan) -> DfResult<Option<String>> {
    let mut context: Option<String> = None;
    plan.apply(|node| {
        if let LogicalPlan::TableScan(ts) = node {
            if let Some(fed_source) = get_table_source(&ts.source)? {
                if let Some(ctx) = fed_source.federation_provider().compute_context() {
                    context = Some(ctx);
                    return Ok(TreeNodeRecursion::Stop);
                }
            }
        }
        Ok(TreeNodeRecursion::Continue)
    })?;
    Ok(context)
}

fn try_decode_federation(
    buf: &[u8],
    ctx: &TaskContext,
    registry: &DynConnectorRegistry,
    inner_logical_codec: &dyn LogicalExtensionCodec,
) -> DfResult<Option<Extension>> {
    // First, try parsing as our envelope. If it doesn't parse as a
    // `LogicalCodecPayload` (e.g. it's Ballista-native bytes), return
    // Ok(None) so the caller can delegate. A successful parse with
    // an unrecognised version tag is a hard error — that's a
    // mixed-version cluster bug we want to fail loudly on.
    let Ok(payload) = LogicalCodecPayload::decode(buf) else {
        return Ok(None);
    };

    // Heuristic: empty connector_name + zero version is what a
    // not-actually-our-envelope decode produces (all-zero defaults).
    // Treat that as "not our payload, delegate". Real envelopes
    // always carry both fields populated.
    if payload.connector_name.is_empty() && payload.version == 0 {
        return Ok(None);
    }

    if payload.version != LOGICAL_CODEC_VERSION {
        return Err(DataFusionError::Internal(format!(
            "FederationLogicalCodec: unsupported LogicalCodecPayload version {}, \
             expected {}",
            payload.version, LOGICAL_CODEC_VERSION
        )));
    }

    let planner = registry
        .lookup_planner(&payload.connector_name)
        .ok_or_else(|| {
            DataFusionError::Plan(format!(
                "FederationLogicalCodec: connector '{}' not registered on this worker — \
             check `[catalogs.*]` agreement between coordinator and worker config",
                payload.connector_name
            ))
        })?;

    // Decode the inner LogicalPlan via the wrapped logical codec.
    let inner_plan_node = LogicalPlanNode::decode(payload.inner_plan.as_slice())
        .map_err(|e| DataFusionError::Internal(format!("inner LogicalPlanNode decode: {e}")))?;
    let inner_plan = inner_plan_node.try_into_logical_plan(ctx, inner_logical_codec)?;

    //: `try_decode_table_provider_federation` strips the Dataglot
    // catalog qualifier from each federated scan's *remote* SQL ref (3-part
    // `catalog.schema.table` → 2-part `schema.table`), but datafusion-proto
    // rebuilds the DataFusion-side plan from the coordinator's untouched
    // 3-part `table_name`: the decoded `TableScan`, its projected schema, and
    // every `Column` (including those buried inside an arithmetic aggregate
    // arg such as `sum(l_extendedprice * (1 - l_discount))`, whose flattened
    // name DataFusion bakes into the aggregate's output field) all stay
    // 3-part. The DataFusion plan is thus internally 3-part while the remote
    // source it re-plans against is 2-part, so federation's pushdown
    // re-resolution fails with `FieldNotFound`. Collapse the whole decoded
    // subtree to the same 2-part shape the scan strip already uses.
    let inner_plan = strip_federation_catalog_qualifiers(inner_plan)?;

    let fed_node = FederatedPlanNode::new(inner_plan, planner);
    Ok(Some(Extension {
        node: Arc::new(fed_node),
    }))
}

/// Reduce a 3-part `catalog.schema.table` reference to the 2-part
/// `schema.table` form `try_decode_table_provider_federation` hands the
/// stripped scan. Returns `None` when there is no catalog to drop (the
/// reference is already 2-part or bare) so callers can skip the rebuild.
///
/// This is the SAME reduction `try_decode_table_provider_federation`
/// applies to the remote SQL ref (codec.rs) — the Dataglot catalog name is
/// a federation-only concept the remote source never sees, so every
/// qualifier on the decoded plan must collapse to it uniformly.
fn reduce_catalog_ref(reference: &TableReference) -> Option<TableReference> {
    // No catalog ⇒ already 2-part or bare; nothing to strip.
    reference.catalog()?;
    Some(match reference.schema() {
        Some(schema) => TableReference::partial(schema.to_string(), reference.table().to_string()),
        None => TableReference::bare(reference.table().to_string()),
    })
}

/// The `<catalog>.<schema>.<table>.` → `<schema>.<table>.` string prefix a
/// federated 3-part scan bakes into DataFusion's flattened expression names.
///
/// `from` carries the trailing `.` so a substring replace only ever matches a
/// full qualifier that is actually followed by a column segment (never a table
/// whose name is a prefix of a sibling's).
struct FlatNamePrefix {
    from: String,
    to: String,
}

/// Collect the flattened-name prefix reductions implied by every
/// catalog-qualified [`TableScan`] in `plan`.
///
/// DataFusion renders a qualified column into an expression's *display name*
/// via [`Column::flat_name`] — dotted and unquoted, exactly matching
/// [`TableReference`]'s `Display` — and bakes that string into an `Aggregate`'s
/// output field name (`sum(pg.public.lineitem.a * Int64(1) - ...)`). A
/// `Projection` above the aggregate then refers to that field through a
/// `Column` whose `relation` is `None` and whose `name` still embeds the 3-part
/// prefix. Relation rewriting can never reach those buried prefixes, so we
/// substring-replace them (mirroring datafusion-federation's
/// `RewriteTableScanAnalyzer`, which requalifies by substring).  review.
fn collect_flat_name_prefixes(plan: &LogicalPlan) -> DfResult<Vec<FlatNamePrefix>> {
    let mut prefixes: Vec<FlatNamePrefix> = Vec::new();
    plan.apply(|node| {
        if let LogicalPlan::TableScan(scan) = node {
            if let Some(reduced) = reduce_catalog_ref(&scan.table_name) {
                let from = format!("{}.", scan.table_name);
                if !prefixes.iter().any(|p| p.from == from) {
                    prefixes.push(FlatNamePrefix {
                        from,
                        to: format!("{reduced}."),
                    });
                }
            }
        }
        Ok(TreeNodeRecursion::Continue)
    })?;
    Ok(prefixes)
}

/// Apply the collected flattened-name reductions to a column `name`, returning
/// the rewritten string only when at least one prefix actually matched.
fn reduce_flat_name(name: &str, prefixes: &[FlatNamePrefix]) -> Option<String> {
    // Only rewrite DataFusion-generated flattened EXPRESSION names — those
    // always contain a `(` (a function/aggregate/cast, e.g. `sum(…)`,
    // `Int64(1)`) or whitespace (a binary operator, e.g. `a * b`). A plain
    // user column/alias is a single identifier path (possibly dotted/quoted)
    // with neither, so it is left untouched even if it coincidentally embeds a
    // scanned table's qualifier — avoiding the false rewrite of a user column
    // literally named like a table path ( review, Codex).
    if !name.contains('(') && !name.contains(char::is_whitespace) {
        return None;
    }
    let mut out: Option<String> = None;
    for prefix in prefixes {
        let current = out.as_deref().unwrap_or(name);
        if current.contains(prefix.from.as_str()) {
            out = Some(current.replace(prefix.from.as_str(), &prefix.to));
        }
    }
    out
}

/// Normalize every catalog qualifier in a decoded federated plan to the
/// 2-part `schema.table` shape.
///
/// Walks the plan bottom-up ([`TreeNode::transform_up`]) so each node's
/// schema is rebuilt only after its children have already settled. For
/// every node:
///
/// * a [`TableScan`] is rebuilt via [`TableScan::try_new`] from the reduced
///   `table_name`, which requalifies its projected schema — a `TableScan`
///   carries a schema keyed by `table_name`, and [`LogicalPlan::recompute_schema`]
///   is a no-op for `TableScan`, so reducing the name alone would leave
///   3-part field qualifiers behind;
/// * a [`SubqueryAlias`] whose `alias` is a 3-part `TableReference` is rebuilt
///   with the reduced alias (the alias is a bare `TableReference`, not an
///   `Expr`, so `map_expressions` never touches it —  review, Gemini);
/// * every `Column` in the node's own expressions drops the catalog from its
///   `relation` AND has any 3-part prefix rewritten out of its flattened
///   `name`. `transform_up` on the `Expr` reaches columns nested inside
///   arbitrary arithmetic; the flattened-name rewrite catches the
///   projection-over-aggregate output references whose `relation` is `None`
///   (the  review's TPC-H Q1 gap). Equi-join keys need no special case:
///   in DataFusion 54 `Join.on` is `Vec<(Expr, Expr)>`, which `map_expressions`
///   already routes through this closure;
/// * the node's schema is recomputed so no stale 3-part field qualifier
///   survives into the re-planned pushdown.
fn strip_federation_catalog_qualifiers(plan: LogicalPlan) -> DfResult<LogicalPlan> {
    let flat_name_prefixes = collect_flat_name_prefixes(&plan)?;

    plan.transform_up(|node| {
        // 1. Rebuild the non-`Expr` qualifier carriers.
        //    - `TableScan`: `table_name` AND its qualified `projected_schema`
        //      collapse to 2-part together.
        //    - `SubqueryAlias`: the `alias` `TableReference` collapses; the
        //      recompute below requalifies the aliased fields.
        let node = match node {
            LogicalPlan::TableScan(scan) => match reduce_catalog_ref(&scan.table_name) {
                Some(reduced) => LogicalPlan::TableScan(TableScan::try_new(
                    reduced,
                    scan.source,
                    scan.projection,
                    scan.filters,
                    scan.fetch,
                )?),
                None => LogicalPlan::TableScan(scan),
            },
            LogicalPlan::SubqueryAlias(alias) => match reduce_catalog_ref(&alias.alias) {
                Some(reduced) => {
                    LogicalPlan::SubqueryAlias(SubqueryAlias::try_new(alias.input, reduced)?)
                }
                None => LogicalPlan::SubqueryAlias(alias),
            },
            other => other,
        };

        // 2. Reduce every `Column` in this node's own expressions: drop the
        //    catalog from `relation`, AND rewrite any 3-part prefix buried in
        //    the flattened `name` (the projection-over-aggregate output
        //    references, whose `relation` is `None`). `transform_up` on the
        //    `Expr` reaches columns nested inside arbitrary arithmetic.
        let node = node
            .map_expressions(|expr| {
                expr.transform_up(|inner| {
                    if let Expr::Column(mut col) = inner {
                        let mut changed = false;
                        if let Some(reduced) = col.relation.as_ref().and_then(reduce_catalog_ref) {
                            col.relation = Some(reduced);
                            changed = true;
                        }
                        if let Some(name) = reduce_flat_name(&col.name, &flat_name_prefixes) {
                            col.name = name;
                            changed = true;
                        }
                        if changed {
                            Ok(Transformed::yes(Expr::Column(col)))
                        } else {
                            Ok(Transformed::no(Expr::Column(col)))
                        }
                    } else {
                        Ok(Transformed::no(inner))
                    }
                })
            })?
            .data;

        // 3. Recompute this node's schema from the now-2-part children and
        //    expressions so the output field qualifiers match.
        node.recompute_schema().map(Transformed::yes)
    })
    .map(|transformed| transformed.data)
}

// ---------------------------------------------------------------------------
// Federated TableProvider encode/decode helpers
//
// The outer `FederatedPlanNode` envelope wraps the inner `LogicalPlan`,
// and datafusion-proto recursively walks that inner plan when it
// encodes the bytes. Every `TableScan` inside surfaces a custom
// `TableProvider` (federation's `FederatedTableProviderAdaptor`) that
// the wrapped codec doesn't know how to serialize. These helpers add
// federation-aware handling so the inner walk completes cleanly.
// ---------------------------------------------------------------------------

/// Encode a warehouse table's identity envelope: the
/// catalog name is the whole identity — namespace + table travel in
/// the `TableReference` datafusion-proto already serializes alongside
/// the provider bytes, and the schema arrives at decode via the
/// `TableScan` proto.
fn encode_warehouse_table_provider(catalog: &str, buf: &mut Vec<u8>) -> DfResult<()> {
    let payload = TableProviderPayload {
        connector_name: catalog.to_string(),
        version: LOGICAL_CODEC_VERSION,
        provider_kind: PROVIDER_KIND_WAREHOUSE.to_string(),
    };
    payload.encode(buf).map_err(|e| {
        DataFusionError::Internal(format!(
            "FederationLogicalCodec: warehouse provider payload encode failed: {e}"
        ))
    })
}

/// Decode a warehouse identity envelope into a
/// [`dataglot_federation::iceberg::LazyWarehouseTableProvider`]
///. `Ok(None)` ⇒ bytes are not a warehouse envelope, caller
/// falls through to the SQL/inner paths.
fn try_decode_warehouse_table_provider(
    buf: &[u8],
    table_ref: &TableReference,
    schema: &SchemaRef,
    warehouses: &dataglot_federation::iceberg::DynWarehouseRegistry,
) -> DfResult<Option<Arc<dyn TableProvider>>> {
    let Ok(payload) = TableProviderPayload::decode(buf) else {
        return Ok(None);
    };
    if payload.version == 0 || payload.provider_kind != PROVIDER_KIND_WAREHOUSE {
        return Ok(None);
    }
    if payload.version != LOGICAL_CODEC_VERSION {
        return Err(DataFusionError::Internal(format!(
            "FederationLogicalCodec: warehouse payload version mismatch: \
             payload={}, codec={LOGICAL_CODEC_VERSION}",
            payload.version
        )));
    }
    let connector = warehouses.lookup(&payload.connector_name).ok_or_else(|| {
        DataFusionError::Plan(format!(
            "no warehouse connector registered under name {:?} on this side; \
             registry has {} entries — coordinator and executor [catalogs.*] \
             names must match",
            payload.connector_name,
            warehouses.len()
        ))
    })?;
    // `catalog.schema.table` → Iceberg `namespace` = the schema part.
    let namespace = table_ref.schema().unwrap_or("public").to_string();
    let table = table_ref.table().to_string();
    Ok(Some(Arc::new(
        dataglot_federation::iceberg::LazyWarehouseTableProvider::new(
            connector,
            payload.connector_name,
            namespace,
            table,
            Arc::clone(schema),
        ),
    )))
}

fn encode_federated_table_provider(
    table_ref: &TableReference,
    adaptor: &FederatedTableProviderAdaptor,
    registry: &DynConnectorRegistry,
    buf: &mut Vec<u8>,
) -> DfResult<()> {
    // Slice 4b.3 design — same compute_context-keyed reverse-lookup
    // the logical-extension encoder uses. The adaptor's source
    // already carries a `FederationProvider`; ask it directly.
    let context = adaptor
        .source
        .federation_provider()
        .compute_context()
        .ok_or_else(|| {
            DataFusionError::Internal(
                "FederationLogicalCodec: FederatedTableProviderAdaptor's provider \
                 returned no compute_context — cannot anchor connector identity"
                    .to_string(),
            )
        })?;
    let name = registry
        .find_name_by_compute_context(&context)
        .ok_or_else(|| {
            // This is the COORDINATOR's own registry, so a miss here
            // doesn't mean coordinator/worker config drift — it means
            // this federated SQL source was never wired for distributed
            // execution at all (`registry_sql_kind` in the server's
            // ballista module classifies it to `None`: the direct-provider
            // OData / SAP / REST sources, plus Oracle / ADBC when their
            // feature wasn't compiled — ). Surface the same
            // friendly  capability-boundary error the
            // unserializable-provider path uses, not an Internal that
            // sends operators chasing config agreement (and gets
            // DataFusion's "file a bug report" boilerplate appended).
            // Don't leak the raw compute_context (CLAUDE.md rule 12).
            tracing::warn!(table = %table_ref, "{}", PRESUBMISSION_WARN);
            DataFusionError::NotImplemented(format!(
                "table '{table_ref}' is not available in distributed mode: \
                 its source kind is not wired into the distributed \
                 connector registry. Direct-TableProvider sources (OData / \
                 SAP / REST) always run single-node; Oracle and ADBC \
                 distribute only when the server and executors were built \
                 with their feature (--features oracle-pure / adbc). Query \
                 it on a single-node server, or move the data to a \
                 supported catalog (postgres / mysql / snowflake federated \
                 sources, Iceberg warehouses, and local/object-storage \
                 files work distributed)."
            ))
        })?
        .to_string();

    let payload = TableProviderPayload {
        connector_name: name,
        version: LOGICAL_CODEC_VERSION,
        // Empty = SQL family; pre-118 decoders ignore the field.
        provider_kind: String::new(),
    };
    payload
        .encode(buf)
        .map_err(|e| DataFusionError::Internal(format!("TableProviderPayload encode: {e}")))?;
    Ok(())
}

fn try_decode_table_provider_federation(
    buf: &[u8],
    table_ref: &TableReference,
    schema: &SchemaRef,
    registry: &DynConnectorRegistry,
) -> DfResult<Option<Arc<dyn TableProvider>>> {
    // First, try parsing as our envelope. Non-federation bytes
    // (e.g. ballista-native) return Ok(None) so the caller falls
    // through to the inner codec. Same "all-defaults looks like
    // not-our-envelope" sniff as the logical extension path.
    let Ok(payload) = TableProviderPayload::decode(buf) else {
        return Ok(None);
    };
    if payload.connector_name.is_empty() && payload.version == 0 {
        return Ok(None);
    }

    if payload.version != LOGICAL_CODEC_VERSION {
        return Err(DataFusionError::Internal(format!(
            "FederationLogicalCodec: unsupported TableProviderPayload version {}, \
             expected {}",
            payload.version, LOGICAL_CODEC_VERSION
        )));
    }

    let executor = registry.lookup(&payload.connector_name).ok_or_else(|| {
        DataFusionError::Plan(format!(
            "FederationLogicalCodec: connector '{}' not registered on this worker — \
             check `[catalogs.*]` agreement between coordinator and worker config",
            payload.connector_name
        ))
    })?;

    // Strip the Dataglot federation catalog qualifier so the pushed-down
    // remote SQL matches what the coordinator's connector built. The
    // coordinator's `Connector::table_provider` constructs a *2-part*
    // `schema.table` RemoteTableRef — the Dataglot catalog name (the
    // `[catalogs.*]` key) is a federation-only concept the remote source
    // knows nothing about. But `datafusion-proto` reconstructs the
    // coordinator-side *3-part* `catalog.schema.table` TableReference from
    // the wire and hands it to us here, so passing it through verbatim
    // would unparse to `FROM "pg"."public"."t"` and a 2-level source like
    // Postgres rejects it (`cross-database references are not
    // implemented`). Drop the catalog to mirror dataglot-federation's
    // `postgres.rs::table_provider` (single-node parity).
    let remote_ref = match table_ref.schema() {
        Some(schema) => TableReference::partial(schema.to_string(), table_ref.table().to_string()),
        None => TableReference::bare(table_ref.table().to_string()),
    };

    // Rebuild the same chain `PostgresConnector::table_provider` builds:
    // `SQLFederationProvider::new(executor)` → `SQLTableSource::new_with_schema`
    // (uses the schema datafusion-proto passes in, so we don't need to
    // re-fetch from the remote) → `FederatedTableProviderAdaptor`.
    let provider = Arc::new(SQLFederationProvider::new(executor));
    let table_source =
        SQLTableSource::new_with_schema(provider, remote_ref.into(), Arc::clone(schema));
    Ok(Some(Arc::new(FederatedTableProviderAdaptor::new(
        Arc::new(table_source),
    ))))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_constructs_without_registry() {
        let codec = FederationLogicalCodec::default();
        assert!(!codec.has_registry());
        let debug = format!("{codec:?}");
        assert!(debug.contains("FederationLogicalCodec"));
        assert!(debug.contains("None"));
    }

    #[test]
    fn new_equals_default() {
        let a = FederationLogicalCodec::new();
        let b = FederationLogicalCodec::default();
        assert_eq!(format!("{a:?}"), format!("{b:?}"));
    }

    #[test]
    fn with_registry_marks_codec_as_federation_aware() {
        use dataglot_federation::InMemoryConnectorRegistry;
        let registry: DynConnectorRegistry = Arc::new(InMemoryConnectorRegistry::empty());
        let codec = FederationLogicalCodec::with_registry(registry);
        assert!(codec.has_registry());
        let debug = format!("{codec:?}");
        assert!(debug.contains("<dyn ConnectorRegistry>"));
    }

    /// Decode of empty bytes returns `Ok(None)` from the federation
    /// path so the caller delegates to Ballista's inner codec. Pins
    /// the "is-this-our-envelope?" sniff heuristic — empty payload
    /// must NOT be treated as federation.
    #[test]
    fn empty_payload_not_treated_as_federation() {
        // An all-zero / empty payload parses successfully as
        // LogicalCodecPayload (everything defaults) but our heuristic
        // recognises it as "not really our envelope" and returns None.
        let payload = LogicalCodecPayload {
            connector_name: String::new(),
            inner_plan: Vec::new(),
            version: 0,
        };
        let mut buf = Vec::new();
        payload.encode(&mut buf).unwrap();
        let reparsed = LogicalCodecPayload::decode(buf.as_slice()).unwrap();
        assert!(reparsed.connector_name.is_empty());
        assert_eq!(reparsed.version, 0);
        // The codec's `try_decode_federation` would return Ok(None) here.
    }

    /// Defensive version check — a payload with a future version
    /// tag must surface as an error, not silently mis-decode. Pins
    /// the mixed-version cluster failure mode (loud, not quiet).
    #[test]
    fn future_version_tag_is_a_hard_error() {
        let payload = LogicalCodecPayload {
            connector_name: "pg".to_string(),
            inner_plan: Vec::new(),
            version: 999,
        };
        let mut buf = Vec::new();
        payload.encode(&mut buf).unwrap();

        let reparsed = LogicalCodecPayload::decode(buf.as_slice()).unwrap();
        assert_eq!(reparsed.version, 999);
        assert_ne!(reparsed.version, LOGICAL_CODEC_VERSION);
        // The codec's `try_decode_federation` would return
        // DataFusionError::Internal here (verified via the
        // version-mismatch branch in the impl).
    }

    /// The codec version constant is non-zero. Pins the "empty
    /// payload looks like version 0" sniff heuristic — if we ever
    /// bumped this to a value that conflicts with the empty default,
    /// the sniff breaks.
    #[test]
    fn version_constant_is_distinguishable_from_default() {
        assert_ne!(LOGICAL_CODEC_VERSION, 0);
    }

    // ----- Phase 2 slice 4b.3 — compute_context-keyed encode path -----
    //
    // These tests pin the replacement for slice 4b.1's pointer-identity
    // reverse-lookup. They construct a federated plan tree along the
    // same path the production analyzer takes (`SQLFederationProvider::
    // new(executor)` → `SQLTableSource` → `FederatedTableProviderAdaptor`
    // → `TableScan`), then verify that walking the resulting LogicalPlan
    // produces the executor's compute_context — the exact string the
    // registry's reverse index is keyed on.
    //
    // The point of running this in unit tests is that the failure mode
    // PR #272 surfaced (the codec couldn't anchor identity) is now
    // catchable without Docker. The Docker-gated e2e in
    // `tests/ballista_federation_codec.rs` is still the load-bearing
    // proof on the wire; this is the fast feedback path.

    use async_trait::async_trait;
    use ballista::datafusion::arrow::datatypes::{DataType, Field, Schema};
    use ballista::datafusion::common::Result as DfResultDf;
    use ballista::datafusion::datasource::DefaultTableSource;
    use ballista::datafusion::execution::SendableRecordBatchStream;
    use ballista::datafusion::logical_expr::{LogicalPlanBuilder, TableSource};
    use ballista::datafusion::physical_plan::PhysicalExpr;
    use ballista::datafusion::sql::unparser::dialect::{DefaultDialect, Dialect};
    use datafusion_federation::sql::{SQLExecutor, SQLFederationProvider, SQLTableSource};
    use datafusion_federation::FederatedTableProviderAdaptor;

    /// Minimal `SQLExecutor` whose `compute_context()` returns a
    /// known marker string. Mirrors `dataglot-federation`'s
    /// `FakeExecutor` shape but lives here so the codec-side test
    /// doesn't need a crate-private export.
    #[derive(Debug)]
    struct StubExecutor {
        name: String,
        ctx: String,
    }

    #[async_trait]
    impl SQLExecutor for StubExecutor {
        fn name(&self) -> &str {
            &self.name
        }

        fn compute_context(&self) -> Option<String> {
            Some(self.ctx.clone())
        }

        fn dialect(&self) -> Arc<dyn Dialect> {
            Arc::new(DefaultDialect {})
        }

        fn execute(
            &self,
            _query: &str,
            _schema: SchemaRef,
            _filters: &[Arc<dyn PhysicalExpr>],
        ) -> DfResultDf<SendableRecordBatchStream> {
            unimplemented!("compute_context tests don't run physical plans")
        }

        async fn table_names(&self) -> DfResultDf<Vec<String>> {
            Ok(Vec::new())
        }

        async fn get_table_schema(&self, _table: &str) -> DfResultDf<SchemaRef> {
            unimplemented!("compute_context tests don't fetch schemas")
        }
    }

    /// Build a `TableScan`-rooted `LogicalPlan` whose `source` is a
    /// `FederatedTableProviderAdaptor` over a `SQLFederationProvider`
    /// — same chain the federation analyzer emits in production.
    /// Wraps in `DefaultTableSource` because `LogicalPlanBuilder::scan`
    /// takes an `Arc<dyn TableSource>` and the adaptor implements
    /// `TableProvider`; `DefaultTableSource::new` is `DataFusion`'s
    /// standard provider→source adapter, and federation's own
    /// `get_table_source` helper unwraps it back to the adaptor.
    fn federated_table_scan(ctx: &str) -> LogicalPlan {
        let executor: Arc<dyn SQLExecutor> = Arc::new(StubExecutor {
            name: "stub".to_string(),
            ctx: ctx.to_string(),
        });
        let provider = Arc::new(SQLFederationProvider::new(executor));
        let schema = Arc::new(Schema::new(vec![
            Field::new("id", DataType::Int64, false),
            Field::new("region", DataType::Utf8, false),
        ]));
        let table = Arc::new(datafusion_federation::sql::RemoteTable::new(
            "customers".to_string().try_into().unwrap(),
            Arc::clone(&schema),
        ));
        let table_source = Arc::new(SQLTableSource::new_with_table(provider, table));
        let adaptor = Arc::new(FederatedTableProviderAdaptor::new(table_source));
        let source: Arc<dyn TableSource> = Arc::new(DefaultTableSource::new(adaptor));
        LogicalPlanBuilder::scan("customers", source, None)
            .expect("scan builder")
            .build()
            .expect("plan builds")
    }

    /// ** distributed pin (coordinator-side).** A federated
    /// table whose executor is NOT in the distributed connector
    /// registry (a direct-provider OData / SAP / REST source, or
    /// Oracle / ADBC built without their feature — ) must fail
    /// encode with the friendly  "not available in distributed mode"
    /// capability-boundary error — not the old
    /// `Internal("…check [catalogs.*] agreement…")` that sent
    /// operators chasing coordinator/worker config drift for a
    /// source that was never distributed-wired at all.
    #[test]
    fn unregistered_federated_provider_encodes_to_the_friendly_error() {
        use ballista::datafusion::sql::TableReference;
        use datafusion_proto::logical_plan::LogicalExtensionCodec as _;
        use dataglot_federation::InMemoryConnectorRegistry;

        let executor: Arc<dyn SQLExecutor> = Arc::new(StubExecutor {
            name: "byoduck".to_string(),
            ctx: "byoduck".to_string(),
        });
        let provider = Arc::new(SQLFederationProvider::new(executor));
        let schema = Arc::new(Schema::new(vec![Field::new("id", DataType::Int64, false)]));
        let table = Arc::new(datafusion_federation::sql::RemoteTable::new(
            "customer_ltv".to_string().try_into().unwrap(),
            Arc::clone(&schema),
        ));
        let table_source = Arc::new(SQLTableSource::new_with_table(provider, table));
        let adaptor = Arc::new(FederatedTableProviderAdaptor::new(table_source));

        // Empty registry — exactly what the coordinator holds for a
        // source kind `registry_sql_kind` classifies to `None`.
        let registry: DynConnectorRegistry = Arc::new(InMemoryConnectorRegistry::new(
            std::collections::HashMap::new(),
        ));
        let codec = FederationLogicalCodec::with_registry(registry);

        let mut buf = Vec::new();
        let err = codec
            .try_encode_table_provider(
                &TableReference::partial("main", "customer_ltv"),
                adaptor,
                &mut buf,
            )
            .expect_err("unregistered federated provider must not encode");
        let msg = err.to_string();
        assert!(
            msg.contains("not available in distributed mode"),
            "expected the capability-boundary error, got: {msg}"
        );
        assert!(
            msg.contains("single-node"),
            "error must state the actionable next step: {msg}"
        );
        assert!(
            !msg.contains("agreement"),
            "must not send operators chasing config drift: {msg}"
        );
    }

    /// **The wedge test.** Walking a real federated plan tree must
    /// surface the executor's `compute_context()` — *not* depend on
    /// any Arc identity. If this passes, the slice-4b.3 encode path
    /// works end-to-end at the unit-test level (PR #272's docker
    /// e2e then proves it on the wire).
    #[test]
    fn compute_context_from_plan_extracts_executor_context() {
        let plan = federated_table_scan("postgres://h:5432/db:u");
        let ctx = compute_context_from_plan(&plan)
            .expect("walk succeeds")
            .expect("plan has a federated TableScan");
        assert_eq!(ctx, "postgres://h:5432/db:u");
    }

    /// Non-federated plan — no `TableScan`, no `FederatedTableProviderAdaptor`.
    /// Walk must return `Ok(None)`; the codec encoder translates that
    /// into a typed "no anchor" error rather than panicking.
    #[test]
    fn compute_context_from_plan_returns_none_when_no_federated_scan() {
        let plan = LogicalPlanBuilder::empty(true)
            .build()
            .expect("empty plan builds");
        let result = compute_context_from_plan(&plan).expect("walk succeeds");
        assert!(
            result.is_none(),
            "non-federated plan must produce None, got {result:?}"
        );
    }

    /// **: multi-executor determinism.** A plan referencing TWO
    /// federated scans from DIFFERENT executors must anchor on the same
    /// one every time. The encoder keys the whole pushed subplan on a
    /// single connector name, so if the tree-walk order ever drifted
    /// (a DataFusion change to `TreeNode::apply` ordering) the plan
    /// would silently encode under the wrong connector and the worker
    /// would run the pushed SQL against the WRONG database — a silent
    /// wrong-source result, not an error. Pin the anchor.
    #[test]
    fn compute_context_from_plan_is_deterministic_with_two_executors() {
        let plan = LogicalPlanBuilder::from(federated_table_scan("ctx_a"))
            .union(federated_table_scan("ctx_b"))
            .expect("union builds")
            .build()
            .expect("plan builds");
        let first = compute_context_from_plan(&plan)
            .expect("walk succeeds")
            .expect("a federated scan is present");
        // Deterministic across repeated walks.
        for _ in 0..8 {
            assert_eq!(
                compute_context_from_plan(&plan).unwrap().as_deref(),
                Some(first.as_str()),
                "compute_context_from_plan must be deterministic across walks"
            );
        }
        assert!(
            first == "ctx_a" || first == "ctx_b",
            "anchor must be one of the two executors, got {first:?}"
        );
    }

    /// ** decode-side, version mismatch.** A `LogicalCodecPayload`
    /// carrying an unrecognized version tag (mixed-version cluster) must
    /// be a HARD `Internal` error, not a silent fallthrough — otherwise
    /// a worker on an incompatible codec version could misinterpret the
    /// wire bytes. The prior test only round-tripped the prost message;
    /// this drives `try_decode_federation` itself.
    #[test]
    fn decode_rejects_unknown_payload_version() {
        use ballista::datafusion::execution::TaskContext;
        use dataglot_federation::InMemoryConnectorRegistry;

        let payload = LogicalCodecPayload {
            connector_name: "pg_demo".to_string(),
            inner_plan: Vec::new(),
            version: 999,
        };
        let mut buf = Vec::new();
        payload.encode(&mut buf).unwrap();

        let registry: DynConnectorRegistry = Arc::new(InMemoryConnectorRegistry::empty());
        let inner = datafusion_proto::logical_plan::DefaultLogicalExtensionCodec {};
        let err = try_decode_federation(&buf, &TaskContext::default(), &registry, &inner)
            .expect_err("unknown version must be a hard error");
        assert!(
            matches!(err, DataFusionError::Internal(ref m) if m.contains("version")),
            "expected an Internal version error, got {err:?}"
        );
    }

    /// ** decode-side, worker registry miss.** A correctly
    /// versioned payload naming a connector this worker doesn't have
    /// must fail with a clear `Plan` error citing config drift — the
    /// ops-facing signature of coordinator/worker `[catalogs.*]`
    /// disagreement — not a panic or silent None.
    #[test]
    fn decode_reports_worker_registry_miss() {
        use ballista::datafusion::execution::TaskContext;
        use dataglot_federation::InMemoryConnectorRegistry;

        let payload = LogicalCodecPayload {
            connector_name: "ghost".to_string(),
            inner_plan: Vec::new(),
            version: LOGICAL_CODEC_VERSION,
        };
        let mut buf = Vec::new();
        payload.encode(&mut buf).unwrap();

        let registry: DynConnectorRegistry = Arc::new(InMemoryConnectorRegistry::empty());
        let inner = datafusion_proto::logical_plan::DefaultLogicalExtensionCodec {};
        let err = try_decode_federation(&buf, &TaskContext::default(), &registry, &inner)
            .expect_err("unregistered connector must error");
        assert!(
            matches!(err, DataFusionError::Plan(ref m) if m.contains("ghost")),
            "expected a Plan error naming the missing connector, got {err:?}"
        );
    }

    /// **Full encode round-trip on a real `FederatedPlanNode`.**
    ///
    /// This is the test PR #272's second failure mode demanded — the
    /// e2e surfaced that walking `FederatedPlanNode.plan` through
    /// `LogicalPlanNode::try_from_logical_plan` hits the inner
    /// `TableScan`'s `FederatedTableProviderAdaptor` source and asks
    /// the recursive logical-extension codec to serialize it. Slice
    /// 4b.3's first iteration left that path running through
    /// `DefaultLogicalExtensionCodec`, which fails with
    /// "`LogicalExtensionCodec` is not provided".
    ///
    /// The fix routes the recursive walk back through `self` so the
    /// codec's `try_encode_table_provider` handles the adaptor via
    /// the connector-name envelope. This test exercises that full
    /// chain (`Extension` → `FederatedPlanNode` → inner `LogicalPlan`
    /// walk → `TableScan` → `TableProvider` → connector name) without
    /// needing Docker.
    #[test]
    fn full_encode_round_trips_federated_plan_node() {
        use dataglot_federation::InMemoryConnectorRegistry;
        use std::collections::HashMap;

        let ctx_string = "postgres://h:5432/db:u";
        let executor: Arc<dyn SQLExecutor> = Arc::new(StubExecutor {
            name: "stub".to_string(),
            ctx: ctx_string.to_string(),
        });
        let mut executors: HashMap<String, Arc<dyn SQLExecutor>> = HashMap::new();
        executors.insert("pg_demo".to_string(), executor.clone());
        let registry: DynConnectorRegistry = Arc::new(InMemoryConnectorRegistry::new(executors));

        // Build a `FederatedPlanNode` wrapping a TableScan whose
        // source is a `FederatedTableProviderAdaptor` — same shape
        // federation's analyzer emits in production.
        let inner_plan = federated_table_scan(ctx_string);
        let provider = Arc::new(SQLFederationProvider::new(executor));
        let planner: Arc<dyn datafusion_federation::FederationPlanner> = Arc::new(
            datafusion_federation::sql::SQLFederationPlanner::new(Arc::clone(&provider.executor)),
        );
        let fed_node = FederatedPlanNode::new(inner_plan, planner);
        let extension = Extension {
            node: Arc::new(fed_node),
        };

        // The smoking gun: try_encode must NOT bubble up
        // "LogicalExtensionCodec is not provided". If this assertion
        // fires with that string we've regressed the slice 4b.3
        // table-provider fix.
        let codec = FederationLogicalCodec::with_registry(Arc::clone(&registry));
        let mut buf = Vec::new();
        codec
            .try_encode(&extension, &mut buf)
            .expect("federation try_encode round-trips end-to-end");
        assert!(!buf.is_empty(), "encoded buffer should be non-empty");

        // The encoded outer LogicalCodecPayload must carry the
        // resolved connector name (proves the reverse-lookup wired
        // through). Decoding the prost message directly is the
        // tightest assertion we can make without standing up a
        // TaskContext.
        let outer = LogicalCodecPayload::decode(buf.as_slice())
            .expect("encoded bytes parse as LogicalCodecPayload");
        assert_eq!(outer.connector_name, "pg_demo");
        assert_eq!(outer.version, LOGICAL_CODEC_VERSION);
        assert!(
            !outer.inner_plan.is_empty(),
            "inner plan bytes must be present — proves the recursive walk \
             reached and serialized the TableScan / TableProvider"
        );
    }

    ///  contract pin — the testbench's Cluster tab counts
    /// pre-submission failures by grepping the server log for this
    /// exact substring (`count_presubmission_failures`,
    /// `crates/dataglot-testbench/src/cluster.rs`). If this test fails
    /// you reworded [`PRESUBMISSION_WARN`]: either restore the phrase
    /// or update the testbench scanner *in the same change*.
    #[test]
    fn presubmission_warn_stays_greppable_by_the_testbench() {
        const TESTBENCH_SCANNER_PATTERN: &str = "cannot be serialized for distributed execution";
        assert!(
            PRESUBMISSION_WARN.contains(TESTBENCH_SCANNER_PATTERN),
            "PRESUBMISSION_WARN no longer contains the substring the \
             testbench scans for; update \
             crates/dataglot-testbench/src/cluster.rs::count_presubmission_failures \
             together with this message. WARN is now: {PRESUBMISSION_WARN}"
        );
        // The WARN must stay a single log line — the scanner counts
        // per-line matches in the JSON log stream.
        assert!(!PRESUBMISSION_WARN.contains('\n'));
    }

    ///  part C — a provider with no serialization codec (here a
    /// `MemTable`, standing in for the Iceberg/warehouse provider) must
    /// fail with an error that names the table and points the operator
    /// at single-node — not upstream's bare
    /// `NotImplemented("LogicalExtensionCodec is not provided")`, which
    /// (once Ballista wraps it in `Internal`) tells users to file a
    /// DataFusion bug for what is a Dataglot capability boundary.
    #[test]
    fn unsupported_provider_error_names_table_and_gives_guidance() {
        use ballista::datafusion::arrow::array::{Int32Array, RecordBatch};
        use ballista::datafusion::arrow::datatypes::{DataType, Field, Schema};
        use ballista::datafusion::datasource::MemTable;

        let schema = Arc::new(Schema::new(vec![Field::new("id", DataType::Int32, false)]));
        let batch = RecordBatch::try_new(
            Arc::clone(&schema),
            vec![Arc::new(Int32Array::from(vec![1]))],
        )
        .unwrap();
        let provider: Arc<dyn TableProvider> =
            Arc::new(MemTable::try_new(schema, vec![vec![batch]]).unwrap());

        let codec = FederationLogicalCodec::default();
        let table_ref = TableReference::parse_str("lakehouse.demo.orders");
        let mut buf = Vec::new();
        let err = codec
            .try_encode_table_provider(&table_ref, provider, &mut buf)
            .expect_err("an uncodable provider must not silently encode");

        let msg = err.to_string();
        assert!(
            msg.contains("lakehouse.demo.orders"),
            "error must name the failing table, got: {msg}"
        );
        assert!(
            msg.contains("not available in distributed mode"),
            "error must state the capability boundary, got: {msg}"
        );
        assert!(
            msg.contains("single-node"),
            "error must give the actionable next step, got: {msg}"
        );
        assert!(
            msg.contains("not a DataFusion bug"),
            "error must counter the upstream-bug boilerplate, got: {msg}"
        );
    }

    // --- try_decode_table_provider_federation (decode-side reconstruction) --
    // Previously zero direct coverage: the `empty_payload_*` / `future_version_*`
    // tests above only round-trip the prost message and assert what the codec
    // *would* do — they never call it. These drive the free fn directly,
    // covering both catalog-stripping match arms and the typed error paths.

    fn one_connector_registry(name: &str) -> DynConnectorRegistry {
        use dataglot_federation::InMemoryConnectorRegistry;
        use std::collections::HashMap;
        let executor: Arc<dyn SQLExecutor> = Arc::new(StubExecutor {
            name: name.to_string(),
            ctx: format!("postgres://h/db:{name}"),
        });
        let mut executors: HashMap<String, Arc<dyn SQLExecutor>> = HashMap::new();
        executors.insert(name.to_string(), executor);
        Arc::new(InMemoryConnectorRegistry::new(executors))
    }

    fn table_provider_payload_bytes(connector_name: &str, version: u32) -> Vec<u8> {
        let payload = TableProviderPayload {
            connector_name: connector_name.to_string(),
            version,
            provider_kind: String::new(),
        };
        let mut buf = Vec::new();
        payload.encode(&mut buf).expect("payload encodes");
        buf
    }

    fn two_col_schema() -> SchemaRef {
        Arc::new(Schema::new(vec![
            Field::new("id", DataType::Int64, false),
            Field::new("region", DataType::Utf8, false),
        ]))
    }

    #[test]
    fn decode_table_provider_federation_three_part_ref_reconstructs_provider() {
        // 3-part `catalog.schema.table` ref exercises the Some(schema)
        // catalog-strip arm (the documented Postgres cross-database fix).
        let registry = one_connector_registry("pg_demo");
        let buf = table_provider_payload_bytes("pg_demo", LOGICAL_CODEC_VERSION);
        let schema = two_col_schema();
        let table_ref = TableReference::full("pg", "public", "customers");
        let provider = try_decode_table_provider_federation(&buf, &table_ref, &schema, &registry)
            .expect("decode ok")
            .expect("federation envelope recognised");
        assert_eq!(
            provider.schema(),
            schema,
            "the wire schema threads through decode unchanged"
        );
    }

    #[test]
    fn decode_table_provider_federation_bare_ref_reconstructs_provider() {
        // Bare table ref exercises the None catalog-strip arm.
        let registry = one_connector_registry("pg_demo");
        let buf = table_provider_payload_bytes("pg_demo", LOGICAL_CODEC_VERSION);
        let schema = two_col_schema();
        let table_ref = TableReference::bare("customers");
        let provider = try_decode_table_provider_federation(&buf, &table_ref, &schema, &registry)
            .expect("decode ok")
            .expect("federation envelope recognised");
        assert_eq!(provider.schema(), schema);
    }

    #[test]
    fn decode_table_provider_federation_rejects_version_mismatch() {
        let registry = one_connector_registry("pg_demo");
        let buf = table_provider_payload_bytes("pg_demo", 999);
        let err = try_decode_table_provider_federation(
            &buf,
            &TableReference::bare("customers"),
            &two_col_schema(),
            &registry,
        )
        .expect_err("future version must be a hard error");
        assert!(matches!(err, DataFusionError::Internal(_)));
        assert!(err
            .to_string()
            .contains("unsupported TableProviderPayload version"));
    }

    #[test]
    fn decode_table_provider_federation_rejects_unknown_connector() {
        // Valid version, but the payload names a connector the worker
        // doesn't hold — the coordinator/worker `[catalogs.*]` drift case.
        let registry = one_connector_registry("pg_demo");
        let buf = table_provider_payload_bytes("not_registered", LOGICAL_CODEC_VERSION);
        let err = try_decode_table_provider_federation(
            &buf,
            &TableReference::bare("customers"),
            &two_col_schema(),
            &registry,
        )
        .expect_err("unknown connector must error");
        assert!(matches!(err, DataFusionError::Plan(_)));
        assert!(err.to_string().contains("not registered on this worker"));
    }

    #[test]
    fn decode_table_provider_federation_ignores_non_envelope_bytes() {
        let registry = one_connector_registry("pg_demo");
        let schema = two_col_schema();
        let table_ref = TableReference::bare("customers");
        // Bytes that don't parse as the payload → delegate (Ok(None)).
        let garbage = try_decode_table_provider_federation(
            b"\xff\xff not a payload \x00",
            &table_ref,
            &schema,
            &registry,
        )
        .expect("non-parsing bytes are not an error");
        assert!(
            garbage.is_none(),
            "unparseable bytes delegate to the inner codec"
        );
        // All-default payload (empty name + version 0) is the "not our
        // envelope" sniff → Ok(None), NOT a version error.
        let default_buf = table_provider_payload_bytes("", 0);
        let sniffed =
            try_decode_table_provider_federation(&default_buf, &table_ref, &schema, &registry)
                .expect("default payload sniffs as non-envelope");
        assert!(sniffed.is_none());
    }

    // ---: arithmetic-aggregate qualifier normalization on decode ---

    /// Build `scan(table_ref) -> Aggregate[group k; sum(a), sum(a*(1-b))]`
    /// over a `FederatedTableProviderAdaptor` whose executor reports `ctx`
    /// (so the codec's reverse compute-context lookup can anchor the
    /// connector name). This is TPC-H Q1's arithmetic-aggregate shape:
    /// `LogicalPlanBuilder::aggregate` normalizes every column — the bare
    /// `sum(a)` arg, the GROUP BY key, AND the columns buried inside
    /// `sum(a * (1 - b))` — to `table_ref`'s qualifier.
    fn arith_agg_plan(table_ref: TableReference, ctx: &str) -> LogicalPlan {
        use ballista::datafusion::functions_aggregate::expr_fn::sum;
        use ballista::datafusion::logical_expr::{col, lit};

        let executor: Arc<dyn SQLExecutor> = Arc::new(StubExecutor {
            name: "stub".to_string(),
            ctx: ctx.to_string(),
        });
        let provider = Arc::new(SQLFederationProvider::new(executor));
        let schema = Arc::new(Schema::new(vec![
            Field::new("a", DataType::Int64, false),
            Field::new("b", DataType::Int64, false),
            Field::new("k", DataType::Utf8, false),
        ]));
        let table = Arc::new(datafusion_federation::sql::RemoteTable::new(
            table_ref.table().to_string().try_into().unwrap(),
            Arc::clone(&schema),
        ));
        let table_source = Arc::new(SQLTableSource::new_with_table(provider, table));
        let adaptor = Arc::new(FederatedTableProviderAdaptor::new(table_source));
        let source: Arc<dyn TableSource> = Arc::new(DefaultTableSource::new(adaptor));
        LogicalPlanBuilder::scan(table_ref, source, None)
            .expect("scan builder")
            .aggregate(
                vec![col("k")],
                vec![sum(col("a")), sum(col("a") * (lit(1_i64) - col("b")))],
            )
            .expect("aggregate builds")
            .build()
            .expect("aggregate plan builds")
    }

    /// ** distributed pin.** An aggregate over an arithmetic
    /// expression (TPC-H Q1's `sum(l_extendedprice * (1 - l_discount))`)
    /// must survive the `--distributed` codec round-trip with uniformly
    /// 2-part qualifiers.
    ///
    /// `try_decode_table_provider_federation` strips each federated scan's
    /// *remote* ref to 2-part `schema.table`, but datafusion-proto rebuilds
    /// the DataFusion-side `TableScan` (and every `Column` that re-resolves
    /// against it) from the coordinator's untouched 3-part
    /// `catalog.schema.table` `table_name`. Without the fix the decoded plan
    /// stays uniformly 3-part — scan name, projected schema, GROUP BY key,
    /// and the columns buried in `sum(a * (1 - b))` whose flattened names
    /// DataFusion bakes into the aggregate's output fields — while the remote
    /// source it re-plans against is 2-part, so federation's pushdown
    /// re-resolution hits `FieldNotFound`. Pre-fix this test fails (a `pg.`
    /// catalog survives and the aggregate field names diverge from the 2-part
    /// reference); post-fix the whole subtree is 2-part.
    #[test]
    fn reduce_flat_name_only_rewrites_expression_names() {
        let prefixes = vec![FlatNamePrefix {
            from: "pg.public.lineitem.".to_string(),
            to: "public.lineitem.".to_string(),
        }];
        // A flattened aggregate/expression name (contains `(` / whitespace) is
        // rewritten to the 2-part qualifier.
        assert_eq!(
            reduce_flat_name("sum(pg.public.lineitem.a * Int64(1))", &prefixes).as_deref(),
            Some("sum(public.lineitem.a * Int64(1))")
        );
        // A plain user column/alias name that coincidentally embeds the
        // qualifier is a single identifier — left untouched, no false rewrite
        // ( review).
        assert_eq!(
            reduce_flat_name("pg.public.lineitem.metric", &prefixes),
            None
        );
    }

    #[test]
    fn decode_normalizes_arithmetic_aggregate_catalog_qualifiers() {
        use ballista::datafusion::prelude::SessionContext;
        use datafusion_proto::logical_plan::AsLogicalPlan;
        use std::cell::Cell;

        // Connector "pg_demo" with compute_context "postgres://h/db:pg_demo"
        // — the exact shape `one_connector_registry` builds.
        let name = "pg_demo";
        let ctx_string = format!("postgres://h/db:{name}");
        let registry = one_connector_registry(name);

        // Coordinator-side plan: a 3-part `pg.public.lineitem` federated
        // scan under the arithmetic aggregate.
        let inner_plan = arith_agg_plan(
            TableReference::full("pg", "public", "lineitem"),
            &ctx_string,
        );

        let executor = registry.lookup(name).expect("executor registered");
        let planner: Arc<dyn datafusion_federation::FederationPlanner> = Arc::new(
            datafusion_federation::sql::SQLFederationPlanner::new(executor),
        );
        let plan = LogicalPlan::Extension(Extension {
            node: Arc::new(FederatedPlanNode::new(inner_plan, planner)),
        });

        // Round-trip through the codec: encode the FederatedPlanNode
        // envelope, then decode it back.
        let codec = FederationLogicalCodec::with_registry(Arc::clone(&registry));
        let encoded =
            LogicalPlanNode::try_from_logical_plan(&plan, &codec).expect("federated plan encodes");
        let session = SessionContext::new();
        let task_ctx = session.task_ctx();
        let decoded = encoded
            .try_into_logical_plan(task_ctx.as_ref(), &codec)
            .expect("federated plan decodes");

        let LogicalPlan::Extension(ext) = &decoded else {
            panic!("decoded plan must be a FederatedPlanNode Extension, got {decoded:?}");
        };
        let fed = ext
            .node
            .as_any()
            .downcast_ref::<FederatedPlanNode>()
            .expect("decoded extension is a FederatedPlanNode");
        let decoded_inner = &fed.plan;

        // (1) No 3-part catalog qualifier may survive anywhere: not on a
        //     scan `table_name`, not on a schema field, not on a `Column`
        //     buried in an expression.
        let had_catalog = Cell::new(false);
        decoded_inner
            .apply(|node| {
                if let LogicalPlan::TableScan(ts) = node {
                    if ts.table_name.catalog().is_some() {
                        had_catalog.set(true);
                    }
                }
                for (qualifier, _) in node.schema().iter() {
                    if qualifier.and_then(TableReference::catalog).is_some() {
                        had_catalog.set(true);
                    }
                }
                node.apply_expressions(|expr| {
                    expr.apply(|e| {
                        if let Expr::Column(c) = e {
                            if c.relation
                                .as_ref()
                                .and_then(TableReference::catalog)
                                .is_some()
                            {
                                had_catalog.set(true);
                            }
                        }
                        Ok(TreeNodeRecursion::Continue)
                    })
                })?;
                Ok(TreeNodeRecursion::Continue)
            })
            .expect("plan walk succeeds");
        assert!(
            !had_catalog.get(),
            "decoded plan still carries a 3-part catalog qualifier; the decoder must \
             collapse it to 2-part: {decoded_inner:?}"
        );

        // (2) The decoded aggregate must be field-for-field identical to the
        //     SAME aggregate planned over a 2-part `public.lineitem` scan —
        //     the shape the stripped remote scan re-plans to. Pre-fix the
        //     arithmetic-agg output field name embeds `pg.public.lineitem`
        //     while `sum(a)` and the GROUP BY key are 2-part, so this vector
        //     diverges and the 2-part downstream lookup misses the
        //     arithmetic field (FieldNotFound). Post-fix every name is 2-part.
        let reference = arith_agg_plan(TableReference::partial("public", "lineitem"), &ctx_string);
        assert_eq!(
            decoded_inner.schema().field_names(),
            reference.schema().field_names(),
            "decoded aggregate output field names must match the 2-part reference plan"
        );
    }

    /// Build the TRUE TPC-H Q1 shape:
    /// `scan(table_ref) -> Aggregate[group k; sum(a), sum(a*(1-b))] -> Projection`
    /// where the `Projection` selects each aggregate output *by reference*.
    ///
    /// The point is the projection columns for the two `sum(...)` results:
    /// DataFusion flattens each aggregate expression into the child field's
    /// *name* (`sum(<catalog>.<schema>.<table>.a * Int64(1) - ...)`), and the
    /// projection refers to that field through a `Column` whose `relation` is
    /// `None` and whose `name` embeds the 3-part catalog qualifier. Relation
    /// rewriting alone can never reach that buried prefix — the  review
    /// gap.
    fn proj_over_arith_agg_plan(table_ref: TableReference, ctx: &str) -> LogicalPlan {
        use ballista::datafusion::functions_aggregate::expr_fn::sum;
        use ballista::datafusion::logical_expr::{col, lit};

        let executor: Arc<dyn SQLExecutor> = Arc::new(StubExecutor {
            name: "stub".to_string(),
            ctx: ctx.to_string(),
        });
        let provider = Arc::new(SQLFederationProvider::new(executor));
        let schema = Arc::new(Schema::new(vec![
            Field::new("a", DataType::Int64, false),
            Field::new("b", DataType::Int64, false),
            Field::new("k", DataType::Utf8, false),
        ]));
        let table = Arc::new(datafusion_federation::sql::RemoteTable::new(
            table_ref.table().to_string().try_into().unwrap(),
            Arc::clone(&schema),
        ));
        let table_source = Arc::new(SQLTableSource::new_with_table(provider, table));
        let adaptor = Arc::new(FederatedTableProviderAdaptor::new(table_source));
        let source: Arc<dyn TableSource> = Arc::new(DefaultTableSource::new(adaptor));
        let aggregated = LogicalPlanBuilder::scan(table_ref, source, None)
            .expect("scan builder")
            .aggregate(
                vec![col("k")],
                vec![sum(col("a")), sum(col("a") * (lit(1_i64) - col("b")))],
            )
            .expect("aggregate builds");
        // Project every aggregate output *by reference*. Each `Column` here
        // carries the aggregate field's own qualifier/name: the GROUP BY key
        // keeps its (relation-qualified) `k`, while the two `sum(...)` outputs
        // arrive with `relation = None` and a flattened, catalog-qualified
        // `name` — exactly the projection shape TPC-H Q1 produces.
        let projections: Vec<Expr> = aggregated
            .schema()
            .columns()
            .into_iter()
            .map(Expr::Column)
            .collect();
        aggregated
            .project(projections)
            .expect("projection builds")
            .build()
            .expect("projection plan builds")
    }

    /// ** review pin — projection over an arithmetic aggregate.**
    ///
    /// The real TPC-H Q1 has a `Projection` above the `Aggregate`. Its
    /// column names are the flattened aggregate-output strings
    /// (`sum(pg.public.lineitem.a * Int64(1) - pg.public.lineitem.b)`), with
    /// `relation = None` — the 3-part catalog qualifier lives *inside the
    /// name*. Reducing only `Column.relation` normalizes the child aggregate's
    /// output field to `sum(public.lineitem.a * ...)` but leaves the parent
    /// projection's stale 3-part name behind, so recomputing the projection
    /// resolves it against the 2-part child schema and returns `FieldNotFound`
    /// — the decode itself fails.
    ///
    /// Pre-fix (relation-only rewrite) this test fails at decode; post-fix the
    /// flattened names are rewritten too, decode succeeds, and no 3-part
    /// qualifier survives anywhere — scan name, field qualifiers, field names,
    /// column relations, or flattened projection column names.
    #[test]
    fn decode_normalizes_projection_over_arithmetic_aggregate() {
        use ballista::datafusion::prelude::SessionContext;
        use datafusion_proto::logical_plan::AsLogicalPlan;
        use std::cell::Cell;

        const CATALOG_PREFIX: &str = "pg.public.lineitem";

        let name = "pg_demo";
        let ctx_string = format!("postgres://h/db:{name}");
        let registry = one_connector_registry(name);

        // Coordinator-side plan: 3-part `pg.public.lineitem` federated scan
        // under an arithmetic aggregate, with a projection on top (Q1 shape).
        let inner_plan = proj_over_arith_agg_plan(
            TableReference::full("pg", "public", "lineitem"),
            &ctx_string,
        );

        let executor = registry.lookup(name).expect("executor registered");
        let planner: Arc<dyn datafusion_federation::FederationPlanner> = Arc::new(
            datafusion_federation::sql::SQLFederationPlanner::new(executor),
        );
        let plan = LogicalPlan::Extension(Extension {
            node: Arc::new(FederatedPlanNode::new(inner_plan, planner)),
        });

        let codec = FederationLogicalCodec::with_registry(Arc::clone(&registry));
        let encoded =
            LogicalPlanNode::try_from_logical_plan(&plan, &codec).expect("federated plan encodes");
        let session = SessionContext::new();
        let task_ctx = session.task_ctx();
        // On the pre-fix branch this decode FAILS: normalizing the aggregate's
        // inner columns renames its output field to `sum(public.lineitem...)`,
        // but the projection's flattened `Column` name still says
        // `sum(pg.public.lineitem...)`, so recomputing the projection returns
        // FieldNotFound. Post-fix the flattened names are rewritten and decode
        // succeeds.
        let decoded = encoded
            .try_into_logical_plan(task_ctx.as_ref(), &codec)
            .expect("projection-over-aggregate federated plan decodes");

        let LogicalPlan::Extension(ext) = &decoded else {
            panic!("decoded plan must be a FederatedPlanNode Extension, got {decoded:?}");
        };
        let fed = ext
            .node
            .as_any()
            .downcast_ref::<FederatedPlanNode>()
            .expect("decoded extension is a FederatedPlanNode");
        let decoded_inner = &fed.plan;

        // No 3-part qualifier may survive anywhere: not on a scan `table_name`,
        // not on a schema field qualifier, not on a `Column.relation`, and not
        // embedded in a schema field NAME or a flattened `Column.name`.
        let had_catalog = Cell::new(false);
        let had_flattened = Cell::new(false);
        decoded_inner
            .apply(|node| {
                if let LogicalPlan::TableScan(ts) = node {
                    if ts.table_name.catalog().is_some() {
                        had_catalog.set(true);
                    }
                }
                for (qualifier, field) in node.schema().iter() {
                    if qualifier.and_then(TableReference::catalog).is_some() {
                        had_catalog.set(true);
                    }
                    if field.name().contains(CATALOG_PREFIX) {
                        had_flattened.set(true);
                    }
                }
                node.apply_expressions(|expr| {
                    expr.apply(|e| {
                        if let Expr::Column(c) = e {
                            if c.relation
                                .as_ref()
                                .and_then(TableReference::catalog)
                                .is_some()
                            {
                                had_catalog.set(true);
                            }
                            if c.name.contains(CATALOG_PREFIX) {
                                had_flattened.set(true);
                            }
                        }
                        Ok(TreeNodeRecursion::Continue)
                    })
                })?;
                Ok(TreeNodeRecursion::Continue)
            })
            .expect("plan walk succeeds");
        assert!(
            !had_catalog.get(),
            "decoded plan still carries a 3-part catalog qualifier; the decoder must \
             collapse it to 2-part: {decoded_inner:?}"
        );
        assert!(
            !had_flattened.get(),
            "decoded plan still embeds the 3-part `{CATALOG_PREFIX}` prefix in a \
             flattened column/field name; the decoder must rewrite it: \
             {decoded_inner:?}"
        );

        // Field-for-field identical to the SAME projection-over-aggregate
        // planned over a 2-part `public.lineitem` scan — the shape the stripped
        // remote scan re-plans to.
        let reference =
            proj_over_arith_agg_plan(TableReference::partial("public", "lineitem"), &ctx_string);
        assert_eq!(
            decoded_inner.schema().field_names(),
            reference.schema().field_names(),
            "decoded projection output field names must match the 2-part reference plan"
        );
    }
}

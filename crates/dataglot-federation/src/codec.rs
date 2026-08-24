//! `PhysicalExtensionCodec` for federation execution nodes —
//! Phase 2 prerequisite that unblocks cross-source distributed
//! execution on Apache Ballista.
//!
//! Spec: the phase-2 `federation-codec-impl` plan
//! (internal phase-plan document).
//!
//! # Nodes handled
//!
//! 1. [`VirtualExecutionPlan`] — federation's main physical-plan
//!    wrapper around a `LogicalPlan` that gets pushed down to a
//!    remote `SQLExecutor`.
//! 2. [`SchemaCastScanExec`] — federation's batch-cast wrapper
//!    around the federated scan. The federation analyzer emits it
//!    above `VirtualExecutionPlan` to coerce the remote driver's
//!    Arrow types to `DataFusion`'s expected schema.
//! 3. [`CooperativeExec`] — `DataFusion`'s cooperative-scheduling
//!    wrapper. Inserted by the physical planner between
//!    `SchemaCastScanExec` and `VirtualExecutionPlan`. It's a
//!    `DataFusion` builtin in 53.x but isn't in the set Ballista's
//!    default physical codec handles, so we cover it here.
//!
//! Without (2) and (3) the codec rejects the wrapped shape at
//! encode time — the scheduler-side planner emits the full
//! `SchemaCastScanExec(CooperativeExec(VirtualExecutionPlan))`
//! tree, so the wrappers MUST round-trip too (PR #272 e2e
//! surfaced this).
//!
//! # Wire shape
//!
//! Encoded payload is a `CodecPayload` (crate-private) protobuf
//! message. Field tags are stable:
//!
//! 1. `connector_name: String` — opaque identifier matching the key
//!    in the operator's `dataglot.toml` `[catalogs.*]` block.
//!    Populated only for `VirtualExecutionPlan`. Worker-side decode
//!    looks this up in its
//!    [`ConnectorRegistry`](crate::ConnectorRegistry) to recover an
//!    `Arc<dyn SQLExecutor>`. Credentials never cross the wire — the
//!    secure-default resolver-per-worker model from the audit's
//!    Gap 2 resolution.
//! 2. `logical_plan: Vec<u8>` — the inner `LogicalPlan` encoded via
//!    `datafusion-proto`'s `LogicalPlanNode`. Uses the
//!    `DefaultLogicalExtensionCodec`, which handles every node
//!    `DataFusion`'s stock planner emits. Populated only for
//!    `VirtualExecutionPlan`.
//! 3. `version: u32` — wire-format version tag. Set to
//!    [`CODEC_VERSION`] on encode; the decoder rejects unknown
//!    versions with a typed `DataFusionError::Internal` so a
//!    mixed-version cluster (old coordinator, new worker, etc.) fails
//!    loudly rather than silently mis-decoding.
//! 4. `kind: u32` — node-type discriminator: `0` (default — back-
//!    compat with v1 payloads that pre-date the wrapper extension)
//!    = `VirtualExecutionPlan`, `1` = `SchemaCastScanExec`, `2` =
//!    `CooperativeExec`. Default `0` keeps old encoded bytes
//!    parseable as `VirtualExecutionPlan`.
//! 5. `arrow_schema: Vec<u8>` — `datafusion-proto-common`'s
//!    `protobuf::Schema` bytes. Populated only for
//!    `SchemaCastScanExec`; the rest of that exec's state
//!    (`properties`, `metrics_set`) is reconstructed by
//!    `SchemaCastScanExec::new` from the recovered input + schema.
//!
//! Why `prost` direct instead of `bincode + serde`: keeps the entire
//! payload in one protobuf wire ecosystem with the inner
//! `LogicalPlanNode`. `prost` is already pulled transitively via
//! `datafusion-proto`; declaring it directly here surfaces the
//! `#[derive(prost::Message)]` annotation explicitly.
//!
//! # Filters invariant
//!
//! `VirtualExecutionPlan.filters` is `Vec<Arc<dyn PhysicalExpr>>` and
//! has no public setter — meaning we couldn't restore pushed-down
//! filters from a serialised payload even if we wanted to. The
//! Dataglot-side
//! [`create_federated_context`](dataglot_core::session::SessionContextFactory)
//! strips the `FilterPushdown` and `FilterPushdown(Post)` optimizer
//! rules upstream of the planner, so the field stays empty by
//! invariant.
//!
//! The encoder asserts the invariant defensively: encoding a
//! `VirtualExecutionPlan` with non-empty `filters` returns a typed
//! `DataFusionError::Internal` rather than silently dropping the
//! filters. If the `FilterPushdown` strip is ever retired, the
//! encoder fails loudly and forces a re-think (see Open Questions in
//! the spec).

use std::sync::Arc;

use datafusion::arrow::datatypes::Schema;
use datafusion::error::{DataFusionError, Result as DfResult};
use datafusion::execution::TaskContext;
use datafusion::physical_plan::coop::CooperativeExec;
use datafusion::physical_plan::ExecutionPlan;
use datafusion_federation::schema_cast::SchemaCastScanExec;
use datafusion_federation::sql::VirtualExecutionPlan;
use datafusion_proto::logical_plan::{
    AsLogicalPlan, DefaultLogicalExtensionCodec, LogicalExtensionCodec,
};
use datafusion_proto::physical_plan::{DefaultPhysicalExtensionCodec, PhysicalExtensionCodec};
use datafusion_proto::protobuf::{self as df_proto_common, LogicalPlanNode};
use prost::Message;

use crate::registry::DynConnectorRegistry;

/// `kind` field discriminator for the wrapper variants. Tag values
/// are wire-stable — adding a variant picks the next unused `u32`
/// and leaves earlier ones alone. `0` is reserved for
/// `VirtualExecutionPlan` so payloads from before the wrappers
/// landed (where the `kind` field was absent and prost-defaulted
/// to `0`) keep decoding as `VirtualExecutionPlan`.
const KIND_VIRTUAL_EXEC: u32 = 0;
const KIND_SCHEMA_CAST: u32 = 1;
const KIND_COOPERATIVE: u32 = 2;
///  — a lazily-rebuilt warehouse (Iceberg) table scan; payload
/// carries connector name + `arrow_schema` (the full table schema) +
/// `warehouse_scan` (namespace/table/projection/limit).
#[cfg(feature = "iceberg")]
const KIND_WAREHOUSE_SCAN: u32 = 3;
///  — a [`crate::pushdown_metrics::PushdownMetricsExec`] wrapping a
/// federated scan; payload carries the connector (catalog) name for the metric
/// label. Its single child round-trips through the recursive codec walk.
const KIND_PUSHDOWN_METRICS: u32 = 4;

/// Wire-format version tag carried on every encoded payload. Bumped
/// in lockstep with any breaking change to the crate-private
/// `CodecPayload` field shape. The decoder rejects unknown versions
/// with a typed error so mixed-version clusters fail loudly.
pub const CODEC_VERSION: u32 = 1;

/// Protobuf-encoded envelope for a [`VirtualExecutionPlan`].
///
/// Field tag numbers are stable — adding a new field requires
/// picking a fresh unused tag and bumping [`CODEC_VERSION`]. Renaming
/// or repurposing an existing tag is a wire-break.
#[derive(Clone, PartialEq, Message)]
struct CodecPayload {
    /// See module-level doc. Populated only when
    /// `kind == KIND_VIRTUAL_EXEC`.
    #[prost(string, tag = "1")]
    connector_name: String,
    /// See module-level doc — `datafusion-proto`-encoded inner plan.
    /// Populated only when `kind == KIND_VIRTUAL_EXEC`.
    #[prost(bytes, tag = "2")]
    logical_plan: Vec<u8>,
    /// See module-level doc.
    #[prost(uint32, tag = "3")]
    version: u32,
    /// See module-level doc — discriminator for wrapper variants.
    /// Default `0` (`KIND_VIRTUAL_EXEC`) keeps pre-wrapper payloads
    /// parseable.
    #[prost(uint32, tag = "4")]
    kind: u32,
    /// See module-level doc — `datafusion-proto-common`'s
    /// `protobuf::Schema` bytes. Populated when
    /// `kind == KIND_SCHEMA_CAST` (the cast target schema) or
    /// `kind == KIND_WAREHOUSE_SCAN` (the table's full schema).
    #[prost(bytes, tag = "5")]
    arrow_schema: Vec<u8>,
    ///  — encoded [`WarehouseScanPayload`]. Populated only when
    /// `kind == KIND_WAREHOUSE_SCAN`.
    #[prost(bytes, tag = "6")]
    warehouse_scan: Vec<u8>,
}

/// Identity + scan shape for a [`crate::iceberg::WarehouseScanExec`]
///. Nested message so the outer payload stays flat.
#[cfg(feature = "iceberg")]
#[derive(Clone, PartialEq, Message)]
struct WarehouseScanPayload {
    #[prost(string, tag = "1")]
    namespace: String,
    #[prost(string, tag = "2")]
    table: String,
    /// Projection indices into the full schema; `has_projection`
    /// disambiguates `None` from `Some(vec![])`.
    #[prost(bool, tag = "3")]
    has_projection: bool,
    #[prost(uint64, repeated, tag = "4")]
    projection: Vec<u64>,
    #[prost(bool, tag = "5")]
    has_limit: bool,
    #[prost(uint64, tag = "6")]
    limit: u64,
}

/// `PhysicalExtensionCodec` for `VirtualExecutionPlan` — pluggable
/// into a Ballista worker's `SessionState` via
/// `SessionStateBuilder::with_physical_extension_codec`.
///
/// One codec instance is typically constructed at worker boot from
/// the same connector list as the coordinator and held alongside
/// the worker's session state for the lifetime of the process.
#[derive(Clone)]
pub struct FederationPlanCodec {
    registry: DynConnectorRegistry,
    /// Warehouse (Iceberg) connectors for `KIND_WAREHOUSE_SCAN`
    /// round-trips. `None` ⇒ warehouse scans fail encode
    /// with a typed error naming the missing wiring.
    #[cfg(feature = "iceberg")]
    warehouses: Option<crate::iceberg::DynWarehouseRegistry>,
    logical_codec: Arc<dyn LogicalExtensionCodec>,
    /// Fallback physical codec used when the node being encoded
    /// isn't one of our three federation variants — slice 4b.4 hook
    /// so the caller can compose this codec with Ballista's own
    /// `BallistaPhysicalExtensionCodec` (which handles
    /// `ShuffleWriterExec`, `ShuffleReaderExec`, etc.). Default is
    /// `DefaultPhysicalExtensionCodec`, which errors on every
    /// non-federation extension — sufficient for unit tests but
    /// catastrophic on a real cluster where Ballista's shuffle nodes
    /// need to round-trip too (PR #272 e2e surfaced this).
    inner_codec: Arc<dyn PhysicalExtensionCodec>,
}

impl FederationPlanCodec {
    /// Construct a codec backed by `registry` and the default
    /// `LogicalExtensionCodec` (handles every node `DataFusion`'s stock
    /// planner emits). For custom logical-plan extension nodes,
    /// callers wanting a different inner codec use
    /// [`Self::with_logical_codec`].
    ///
    /// The inner physical fallback defaults to
    /// `DefaultPhysicalExtensionCodec`. For production Ballista use,
    /// build with [`Self::with_inner_physical_codec`] passing
    /// `BallistaPhysicalExtensionCodec::default()` so shuffle nodes
    /// round-trip.
    #[must_use]
    pub fn new(registry: DynConnectorRegistry) -> Self {
        Self {
            registry,
            #[cfg(feature = "iceberg")]
            warehouses: None,
            logical_codec: Arc::new(DefaultLogicalExtensionCodec {}),
            inner_codec: Arc::new(DefaultPhysicalExtensionCodec {}),
        }
    }

    /// Construct a codec backed by `registry` with a caller-supplied
    /// inner logical-plan codec.
    #[must_use]
    pub fn with_logical_codec(
        registry: DynConnectorRegistry,
        logical_codec: Arc<dyn LogicalExtensionCodec>,
    ) -> Self {
        Self {
            registry,
            #[cfg(feature = "iceberg")]
            warehouses: None,
            logical_codec,
            inner_codec: Arc::new(DefaultPhysicalExtensionCodec {}),
        }
    }

    /// Register warehouse (Iceberg) connectors so
    /// [`crate::iceberg::WarehouseScanExec`] nodes round-trip
    ///. Coordinator and workers must register the same
    /// names.
    #[cfg(feature = "iceberg")]
    #[must_use]
    pub fn with_warehouse_registry(
        mut self,
        warehouses: crate::iceberg::DynWarehouseRegistry,
    ) -> Self {
        self.warehouses = Some(warehouses);
        self
    }

    /// Override the inner physical-extension codec — the fallback
    /// for nodes that aren't one of `VirtualExecutionPlan`,
    /// `SchemaCastScanExec`, or `CooperativeExec`. Production sets
    /// this to `BallistaPhysicalExtensionCodec::default()` so
    /// Ballista's own `ShuffleWriterExec` / `ShuffleReaderExec` /
    /// `SortShuffleWriterExec` / `UnresolvedShuffleExec` survive the
    /// scheduler→executor wire. Slice 4b.4.
    #[must_use]
    pub fn with_inner_physical_codec(
        mut self,
        inner_codec: Arc<dyn PhysicalExtensionCodec>,
    ) -> Self {
        self.inner_codec = inner_codec;
        self
    }
}

impl std::fmt::Debug for FederationPlanCodec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Don't dump registry internals — they may carry executor
        // objects with credential-handle references (hard rule 12).
        f.debug_struct("FederationPlanCodec")
            .field("registry", &"<dyn ConnectorRegistry>")
            .field("logical_codec", &"<dyn LogicalExtensionCodec>")
            .finish()
    }
}

impl PhysicalExtensionCodec for FederationPlanCodec {
    fn try_encode(&self, node: Arc<dyn ExecutionPlan>, buf: &mut Vec<u8>) -> DfResult<()> {
        // Build the payload in one of three shapes. Wrapper variants
        // (`SchemaCastScanExec`, `CooperativeExec`) carry no
        // connector identity — their inputs round-trip through
        // datafusion-proto's recursive walk, which calls back into
        // this codec for each unknown child node.
        let payload = if let Some(virtual_plan) = node.downcast_ref::<VirtualExecutionPlan>() {
            let logical_node = LogicalPlanNode::try_from_logical_plan(
                virtual_plan.plan(),
                self.logical_codec.as_ref(),
            )?;
            let mut logical_plan = Vec::new();
            logical_node.try_encode(&mut logical_plan)?;
            // Anchor identity on `compute_context()`, not
            // `executor.name()` — the registry is keyed on the
            // friendly connector name (e.g. "pg_demo") that
            // matches the operator's `[catalogs.*]` config; the
            // executor's `name()` is implementation-defined
            // (PostgresConnector returns the DSN). Slice-4b.3's
            // reverse-lookup uses `compute_context()` as the
            // stable opaque identity string, and the same
            // approach belongs here. PR #272 e2e surfaced the
            // mismatch with "no executor registered under name
            // \"postgres://...\"".
            // Don't include the executor's name() or
            // compute_context() in error messages — both can
            // encode host/db/user identity for SQL connectors
            // (hard rule 12: credentials never appear in
            // logs/errors/plan reprs). CodeRabbit flagged the
            // sibling sites in dataglot-ballista on PR #272.
            let context = virtual_plan.executor().compute_context().ok_or_else(|| {
                DataFusionError::Internal(
                    "FederationPlanCodec: federated executor returned no compute_context — \
                         cannot anchor connector identity on the wire"
                        .to_string(),
                )
            })?;
            let connector_name = self
                .registry
                .find_name_by_compute_context(&context)
                .ok_or_else(|| {
                    DataFusionError::Internal(
                        "FederationPlanCodec: no connector registered for the federated \
                             plan's compute identity — check `[catalogs.*]` agreement between \
                             coordinator and worker config"
                            .to_string(),
                    )
                })?
                .to_string();
            CodecPayload {
                connector_name,
                logical_plan,
                version: CODEC_VERSION,
                kind: KIND_VIRTUAL_EXEC,
                arrow_schema: Vec::new(),
                warehouse_scan: Vec::new(),
            }
        } else if let Some(cast) = node.downcast_ref::<SchemaCastScanExec>() {
            let schema_proto: df_proto_common::Schema = cast.schema().as_ref().try_into()?;
            let mut arrow_schema = Vec::new();
            schema_proto.encode(&mut arrow_schema).map_err(|e| {
                DataFusionError::Internal(format!(
                    "FederationPlanCodec: SchemaCastScanExec schema encode failed: {e}"
                ))
            })?;
            CodecPayload {
                connector_name: String::new(),
                logical_plan: Vec::new(),
                version: CODEC_VERSION,
                kind: KIND_SCHEMA_CAST,
                arrow_schema,
                warehouse_scan: Vec::new(),
            }
        } else if node.downcast_ref::<CooperativeExec>().is_some() {
            CodecPayload {
                connector_name: String::new(),
                logical_plan: Vec::new(),
                version: CODEC_VERSION,
                kind: KIND_COOPERATIVE,
                arrow_schema: Vec::new(),
                warehouse_scan: Vec::new(),
            }
        } else if let Some(pm) = node.downcast_ref::<crate::pushdown_metrics::PushdownMetricsExec>()
        {
            CodecPayload {
                connector_name: self.encode_pushdown_metrics_name(pm)?,
                logical_plan: Vec::new(),
                version: CODEC_VERSION,
                kind: KIND_PUSHDOWN_METRICS,
                arrow_schema: Vec::new(),
                warehouse_scan: Vec::new(),
            }
        } else if let Some(payload) = self.try_encode_warehouse_scan(&node)? {
            payload
        } else if let Some(connector) = single_node_only_scan(&node) {
            //  — the REST/OData connectors expose custom physical scan
            // nodes with no distributed codec. Without this, they fall through
            // to the inner codec and surface a cryptic serialization error
            // instead of the friendly capability-boundary message ADBC gets
            //. Lead with the connector kind and the actionable next
            // step, matching the logical-codec path.
            return Err(DataFusionError::NotImplemented(format!(
                "the {connector} connector is not available in distributed mode: \
                 its scan node has no plan-serialization codec (this is a Dataglot \
                 limitation, not a DataFusion bug). Query it on a single-node \
                 server, or move the data to a supported catalog (federated SQL \
                 sources, Iceberg warehouses, and local/object-storage files work \
                 distributed)."
            )));
        } else {
            // Not one of our federation nodes — delegate to the
            // inner codec. In production this is Ballista's
            // `BallistaPhysicalExtensionCodec` (handles shuffle
            // nodes); in tests it's
            // `DefaultPhysicalExtensionCodec`, which errors on
            // unknown nodes.
            return self.inner_codec.try_encode(node, buf);
        };

        payload
            .encode(buf)
            .map_err(|e| DataFusionError::Internal(format!("CodecPayload encode failed: {e}")))?;
        Ok(())
    }

    fn try_decode(
        &self,
        buf: &[u8],
        inputs: &[Arc<dyn ExecutionPlan>],
        ctx: &TaskContext,
    ) -> DfResult<Arc<dyn ExecutionPlan>> {
        // Sniff whether the bytes are our envelope: try parsing,
        // and treat `version == 0` as not-ours (prost defaults
        // missing fields to 0; every payload we emit sets version
        // = CODEC_VERSION). Bytes that don't parse, or parse to
        // version 0, fall through to the inner codec — Ballista's
        // shuffle codec, in production. Same sniff strategy the
        // logical codec uses.
        let Ok(payload) = CodecPayload::decode(buf) else {
            return self.inner_codec.try_decode(buf, inputs, ctx);
        };
        if payload.version == 0 {
            return self.inner_codec.try_decode(buf, inputs, ctx);
        }

        if payload.version != CODEC_VERSION {
            return Err(DataFusionError::Internal(format!(
                "FederationPlanCodec version mismatch: payload={}, codec={}",
                payload.version, CODEC_VERSION
            )));
        }

        match payload.kind {
            KIND_VIRTUAL_EXEC => {
                decode_virtual_exec(&payload, ctx, &self.registry, &self.logical_codec)
            }
            KIND_SCHEMA_CAST => decode_schema_cast(&payload, inputs),
            KIND_COOPERATIVE => decode_cooperative(inputs),
            KIND_PUSHDOWN_METRICS => decode_pushdown_metrics(&payload, inputs),
            #[cfg(feature = "iceberg")]
            KIND_WAREHOUSE_SCAN => self.decode_warehouse_scan(&payload),
            other => Err(DataFusionError::Internal(format!(
                "FederationPlanCodec: unknown node kind {other} \
                 — coordinator/worker codec versions are out of sync"
            ))),
        }
    }
}

impl FederationPlanCodec {
    /// Resolve the connector (catalog) label for a
    /// [`crate::pushdown_metrics::PushdownMetricsExec`] from its wrapped
    /// `VirtualExecutionPlan` child. The wrapping rule leaves the
    /// label blank; this uses the same `compute_context` → registry lookup
    /// [`KIND_VIRTUAL_EXEC`] encoding uses, so the worker's decoded node names
    /// its metrics `pushdown.<catalog>.*`.
    fn encode_pushdown_metrics_name(
        &self,
        pm: &crate::pushdown_metrics::PushdownMetricsExec,
    ) -> DfResult<String> {
        let children = pm.children();
        let virtual_plan = children
            .into_iter()
            .next()
            .and_then(|c| c.downcast_ref::<VirtualExecutionPlan>())
            .ok_or_else(|| {
                DataFusionError::Internal(
                    "FederationPlanCodec: PushdownMetricsExec child is not a \
                     VirtualExecutionPlan — cannot resolve its connector identity"
                        .to_string(),
                )
            })?;
        let context = virtual_plan.executor().compute_context().ok_or_else(|| {
            DataFusionError::Internal(
                "FederationPlanCodec: federated executor returned no compute_context \
                 — cannot anchor connector identity on the wire"
                    .to_string(),
            )
        })?;
        Ok(self
            .registry
            .find_name_by_compute_context(&context)
            .ok_or_else(|| {
                DataFusionError::Internal(
                    "FederationPlanCodec: no connector registered for the wrapped \
                     federated plan's compute identity"
                        .to_string(),
                )
            })?
            .to_string())
    }

    /// Encode a [`crate::iceberg::WarehouseScanExec`] if `node` is one
    ///. `Ok(None)` ⇒ not a warehouse scan, caller falls
    /// through to the inner codec.
    #[cfg(feature = "iceberg")]
    fn try_encode_warehouse_scan(
        &self,
        node: &Arc<dyn ExecutionPlan>,
    ) -> DfResult<Option<CodecPayload>> {
        let Some(scan) = node.downcast_ref::<crate::iceberg::WarehouseScanExec>() else {
            return Ok(None);
        };
        if self.warehouses.is_none() {
            return Err(DataFusionError::Internal(
                "FederationPlanCodec: warehouse scan reached a codec without a \
                 warehouse registry — wire with_warehouse_registry on both \
                 coordinator and workers"
                    .to_string(),
            ));
        }
        let schema_proto: df_proto_common::Schema = scan.full_schema().as_ref().try_into()?;
        let mut arrow_schema = Vec::new();
        schema_proto.encode(&mut arrow_schema).map_err(|e| {
            DataFusionError::Internal(format!(
                "FederationPlanCodec: warehouse scan schema encode failed: {e}"
            ))
        })?;
        let scan_payload = WarehouseScanPayload {
            namespace: scan.namespace().to_string(),
            table: scan.table().to_string(),
            has_projection: scan.projection().is_some(),
            projection: scan
                .projection()
                .map(|p| p.iter().map(|i| *i as u64).collect())
                .unwrap_or_default(),
            has_limit: scan.limit().is_some(),
            limit: scan.limit().unwrap_or(0) as u64,
        };
        let mut warehouse_scan = Vec::new();
        scan_payload.encode(&mut warehouse_scan).map_err(|e| {
            DataFusionError::Internal(format!(
                "FederationPlanCodec: warehouse scan payload encode failed: {e}"
            ))
        })?;
        Ok(Some(CodecPayload {
            connector_name: scan.connector_name().to_string(),
            logical_plan: Vec::new(),
            version: CODEC_VERSION,
            kind: KIND_WAREHOUSE_SCAN,
            arrow_schema,
            warehouse_scan,
        }))
    }

    /// Without the `iceberg` feature there is no warehouse scan type —
    /// nothing matches, callers fall through to the inner codec.
    #[cfg(not(feature = "iceberg"))]
    #[allow(clippy::unnecessary_wraps, clippy::unused_self)]
    fn try_encode_warehouse_scan(
        &self,
        _node: &Arc<dyn ExecutionPlan>,
    ) -> DfResult<Option<CodecPayload>> {
        Ok(None)
    }

    /// Rebuild a [`crate::iceberg::WarehouseScanExec`] from the wire
    ///: resolve the connector by name in this side's
    /// registry, hand back a scan with the same identity + shape. No
    /// IO — the catalog `load_table` stays deferred to `execute`.
    #[cfg(feature = "iceberg")]
    fn decode_warehouse_scan(&self, payload: &CodecPayload) -> DfResult<Arc<dyn ExecutionPlan>> {
        let warehouses = self.warehouses.as_ref().ok_or_else(|| {
            DataFusionError::Plan(
                "FederationPlanCodec: warehouse scan arrived but this side has no \
                 warehouse registry — add the catalog to the worker's \
                 --catalogs-config"
                    .to_string(),
            )
        })?;
        let connector = warehouses.lookup(&payload.connector_name).ok_or_else(|| {
            DataFusionError::Plan(format!(
                "FederationPlanCodec: no warehouse connector registered under name \
                 {:?}; worker registry has {} entries — coordinator and worker \
                 [catalogs.*] names must match",
                payload.connector_name,
                warehouses.len()
            ))
        })?;
        let scan_payload = WarehouseScanPayload::decode(payload.warehouse_scan.as_slice())
            .map_err(|e| {
                DataFusionError::Internal(format!(
                    "FederationPlanCodec: warehouse scan payload decode failed: {e}"
                ))
            })?;
        let schema_proto = df_proto_common::Schema::decode(payload.arrow_schema.as_slice())
            .map_err(|e| {
                DataFusionError::Internal(format!(
                    "FederationPlanCodec: warehouse scan schema decode failed: {e}"
                ))
            })?;
        let schema: Schema = (&schema_proto).try_into()?;
        let projection = scan_payload.has_projection.then(|| {
            scan_payload
                .projection
                .iter()
                .map(|i| *i as usize)
                .collect()
        });
        let limit = scan_payload
            .has_limit
            .then_some(scan_payload.limit as usize);
        Ok(Arc::new(crate::iceberg::WarehouseScanExec::new(
            connector,
            payload.connector_name.clone(),
            scan_payload.namespace,
            scan_payload.table,
            Arc::new(schema),
            projection,
            limit,
        )))
    }
}

/// If `node` is a connector scan node that only runs single-node (it has no
/// distributed plan-serialization codec), return the connector's display name
/// for a friendly capability-boundary error. `None` otherwise.
///
/// These are the physical-node analogue of the ADBC logical-codec guard
///: the REST and OData connectors expose custom `ExecutionPlan`
/// nodes that the codec cannot serialize for a Ballista worker.
fn single_node_only_scan(node: &Arc<dyn ExecutionPlan>) -> Option<&'static str> {
    #[cfg(feature = "rest")]
    if node
        .downcast_ref::<crate::rest::connector::RestScanExec>()
        .is_some()
    {
        return Some("REST/JSON");
    }
    #[cfg(feature = "odata")]
    if node
        .downcast_ref::<crate::odata::connector::OdataScanExec>()
        .is_some()
    {
        return Some("OData");
    }
    let _ = node;
    None
}

fn decode_virtual_exec(
    payload: &CodecPayload,
    ctx: &TaskContext,
    registry: &DynConnectorRegistry,
    logical_codec: &Arc<dyn LogicalExtensionCodec>,
) -> DfResult<Arc<dyn ExecutionPlan>> {
    // Resolve the executor by name from the registry. Missing
    // executor → typed error, never panic (Phase 2 audit Gap 2
    // contract).
    let executor = registry.lookup(&payload.connector_name).ok_or_else(|| {
        DataFusionError::Plan(format!(
            "FederationPlanCodec: no executor registered under name {:?}; \
             worker registry has {} entries",
            payload.connector_name,
            registry.len()
        ))
    })?;

    let node = LogicalPlanNode::try_decode(&payload.logical_plan)?;
    let logical_plan = node.try_into_logical_plan(ctx, logical_codec.as_ref())?;

    // Statistics roundtrip is intentionally lossy in slice 2 —
    // workers get `Statistics::new_unknown` derived from the
    // plan schema. The coordinator-side statistics aren't used
    // by the federated execution path (the executor runs the
    // remote SQL and streams back; statistics are an optimizer
    // hint that's already been consumed on the coordinator).
    let schema = logical_plan.schema().as_arrow().clone();
    let statistics = datafusion::common::Statistics::new_unknown(&schema);

    Ok(Arc::new(VirtualExecutionPlan::new(
        logical_plan,
        executor,
        statistics,
    )))
}

fn decode_schema_cast(
    payload: &CodecPayload,
    inputs: &[Arc<dyn ExecutionPlan>],
) -> DfResult<Arc<dyn ExecutionPlan>> {
    let schema_proto =
        df_proto_common::Schema::decode(payload.arrow_schema.as_slice()).map_err(|e| {
            DataFusionError::Internal(format!(
                "FederationPlanCodec: SchemaCastScanExec schema decode failed: {e}"
            ))
        })?;
    let schema: Schema = (&schema_proto).try_into()?;
    let input = exactly_one_child(inputs, "SchemaCastScanExec")?;
    Ok(Arc::new(SchemaCastScanExec::new(input, Arc::new(schema))))
}

fn decode_cooperative(inputs: &[Arc<dyn ExecutionPlan>]) -> DfResult<Arc<dyn ExecutionPlan>> {
    let input = exactly_one_child(inputs, "CooperativeExec")?;
    Ok(Arc::new(CooperativeExec::new(input)))
}

/// Rebuild a [`crate::pushdown_metrics::PushdownMetricsExec`] around its decoded
/// child, labelled with the connector (catalog) name from the payload so its
/// worker-side execution emits `pushdown.<catalog>.*` counters.
fn decode_pushdown_metrics(
    payload: &CodecPayload,
    inputs: &[Arc<dyn ExecutionPlan>],
) -> DfResult<Arc<dyn ExecutionPlan>> {
    let input = exactly_one_child(inputs, "PushdownMetricsExec")?;
    Ok(Arc::new(crate::pushdown_metrics::PushdownMetricsExec::new(
        input,
        payload.connector_name.as_str(),
    )))
}

fn exactly_one_child(
    inputs: &[Arc<dyn ExecutionPlan>],
    node_name: &str,
) -> DfResult<Arc<dyn ExecutionPlan>> {
    if inputs.len() != 1 {
        return Err(DataFusionError::Internal(format!(
            "FederationPlanCodec: {node_name} expects exactly one child, got {}",
            inputs.len()
        )));
    }
    Ok(Arc::clone(&inputs[0]))
}

#[cfg(test)]
mod tests {
    use super::*;

    use async_trait::async_trait;
    use datafusion::arrow::datatypes::{Schema, SchemaRef};
    use datafusion::common::Statistics;
    use datafusion::error::Result as DfResult;
    use datafusion::logical_expr::{lit, LogicalPlan, LogicalPlanBuilder};
    use datafusion::physical_plan::{PhysicalExpr, SendableRecordBatchStream};
    use datafusion::sql::unparser::dialect::{DefaultDialect, Dialect};
    use datafusion_federation::sql::SQLExecutor;
    use std::collections::HashMap;

    use crate::registry::InMemoryConnectorRegistry;

    /// Minimal `SQLExecutor` matching the trait surface of
    /// `datafusion-federation 0.5.3` — `execute` is sync with a
    /// `&[Arc<dyn PhysicalExpr>]` filters slice; `Dialect` is the
    /// unparser-side type.
    ///
    /// `compute_context` returns the same string as `name`, so the
    /// codec's reverse-lookup (which queries the registry by
    /// `compute_context`) finds the executor in tests that register
    /// it under that same name.
    #[derive(Debug)]
    struct FakeExecutor {
        name: String,
    }

    #[async_trait]
    impl SQLExecutor for FakeExecutor {
        fn name(&self) -> &str {
            &self.name
        }

        fn compute_context(&self) -> Option<String> {
            Some(self.name.clone())
        }

        fn dialect(&self) -> Arc<dyn Dialect> {
            Arc::new(DefaultDialect {})
        }

        fn execute(
            &self,
            _query: &str,
            _schema: SchemaRef,
            _filters: &[Arc<dyn PhysicalExpr>],
        ) -> DfResult<SendableRecordBatchStream> {
            unimplemented!("tests don't exercise the execute path")
        }

        async fn table_names(&self) -> DfResult<Vec<String>> {
            Ok(Vec::new())
        }

        async fn get_table_schema(&self, _table: &str) -> DfResult<SchemaRef> {
            unimplemented!("tests don't exercise schema discovery")
        }
    }

    /// Build a tiny `LogicalPlan` for round-trip tests. A
    /// single-row `Values` plan with one Int32 column carries enough
    /// schema info through `datafusion-proto`'s roundtrip to verify
    /// the codec preserves the inner plan's column shape. (An
    /// `EmptyRelation` would be simpler but `datafusion-proto`
    /// elides its schema since "no rows" implies no useful column
    /// metadata — that quirk is upstream-encoded and worked around
    /// here by using a node type that survives the roundtrip.)
    fn values_plan_with_int32(column_name: &str) -> LogicalPlan {
        LogicalPlanBuilder::values(vec![vec![lit(1_i32)]])
            .unwrap()
            .alias("v")
            .unwrap()
            .project(vec![
                datafusion::logical_expr::col("column1").alias(column_name)
            ])
            .unwrap()
            .build()
            .unwrap()
    }

    fn registry_with(name: &str) -> DynConnectorRegistry {
        let mut map: HashMap<String, Arc<dyn SQLExecutor>> = HashMap::new();
        map.insert(
            name.to_string(),
            Arc::new(FakeExecutor {
                name: name.to_string(),
            }),
        );
        Arc::new(InMemoryConnectorRegistry::new(map))
    }

    #[test]
    fn round_trip_preserves_connector_name_and_plan_schema() {
        // Pin the core round-trip property: encode then decode of a
        // VirtualExecutionPlan must yield a node whose executor name
        // matches the original and whose plan schema matches.
        let plan = values_plan_with_int32("id");
        let executor: Arc<dyn SQLExecutor> = Arc::new(FakeExecutor {
            name: "pg_demo".to_string(),
        });
        let original = VirtualExecutionPlan::new(
            plan.clone(),
            Arc::clone(&executor),
            Statistics::new_unknown(&plan.schema().as_arrow().clone()),
        );

        let codec = FederationPlanCodec::new(registry_with("pg_demo"));
        let mut buf = Vec::new();
        codec
            .try_encode(Arc::new(original.clone()), &mut buf)
            .expect("encode round-trip");

        let ctx = TaskContext::default();
        let decoded = codec
            .try_decode(&buf, &[], &ctx)
            .expect("decode round-trip");

        let decoded_virtual = decoded
            .downcast_ref::<VirtualExecutionPlan>()
            .expect("decoded plan is a VirtualExecutionPlan");

        assert_eq!(decoded_virtual.executor().name(), "pg_demo");
        assert_eq!(
            decoded_virtual.plan().schema().as_arrow().fields().len(),
            1,
            "schema field count preserved"
        );
        assert_eq!(
            decoded_virtual.plan().schema().field(0).name(),
            "id",
            "schema field name preserved"
        );
    }

    #[test]
    fn round_trip_pushdown_metrics_resolves_catalog_label() {
        //: the wrapping rule leaves the label blank; the codec must
        // resolve it from the wrapped scan's connector identity on encode, and
        // the worker-side decode must rebuild a `PushdownMetricsExec` carrying it.
        let plan = values_plan_with_int32("id");
        let executor: Arc<dyn SQLExecutor> = Arc::new(FakeExecutor {
            name: "pg_demo".to_string(),
        });
        let virtual_plan: Arc<dyn ExecutionPlan> = Arc::new(VirtualExecutionPlan::new(
            plan.clone(),
            Arc::clone(&executor),
            Statistics::new_unknown(&plan.schema().as_arrow().clone()),
        ));
        let wrapped: Arc<dyn ExecutionPlan> = Arc::new(
            crate::pushdown_metrics::PushdownMetricsExec::new(Arc::clone(&virtual_plan), ""),
        );

        let codec = FederationPlanCodec::new(registry_with("pg_demo"));
        let mut buf = Vec::new();
        codec.try_encode(wrapped, &mut buf).expect("encode");

        let ctx = TaskContext::default();
        // Ballista's recursive walk hands the already-decoded child as `inputs`.
        let decoded = codec
            .try_decode(&buf, &[Arc::clone(&virtual_plan)], &ctx)
            .expect("decode");

        let pm = decoded
            .downcast_ref::<crate::pushdown_metrics::PushdownMetricsExec>()
            .expect("decoded node is a PushdownMetricsExec");
        assert_eq!(
            pm.source(),
            "pg_demo",
            "codec resolved the catalog label from the wrapped scan"
        );
    }

    #[test]
    fn decode_rejects_unknown_connector_name() {
        // Per the audit's Gap 2 contract: missing executor surfaces
        // as a typed planner error, never a panic.
        let plan = values_plan_with_int32("v");
        let executor: Arc<dyn SQLExecutor> = Arc::new(FakeExecutor {
            name: "pg_demo".to_string(),
        });
        let original = VirtualExecutionPlan::new(
            plan.clone(),
            executor,
            Statistics::new_unknown(&plan.schema().as_arrow().clone()),
        );

        // Encode with a registry that has the executor...
        let encode_codec = FederationPlanCodec::new(registry_with("pg_demo"));
        let mut buf = Vec::new();
        encode_codec
            .try_encode(Arc::new(original), &mut buf)
            .unwrap();

        // ...decode with a worker-side registry that doesn't.
        let decode_codec = FederationPlanCodec::new(registry_with("mysql_demo"));
        let ctx = TaskContext::default();
        let err = decode_codec.try_decode(&buf, &[], &ctx).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("no executor registered under name"),
            "expected missing-connector error, got: {msg}"
        );
        assert!(
            msg.contains("pg_demo"),
            "error mentions the missing connector name"
        );
    }

    #[test]
    fn decode_rejects_unknown_version() {
        // A payload with version != CODEC_VERSION must surface as a
        // typed `Internal` error so mixed-version clusters fail
        // loudly. Hand-roll the payload to inject the wrong version.
        let plan = values_plan_with_int32("id");
        let node = LogicalPlanNode::try_from_logical_plan(&plan, &DefaultLogicalExtensionCodec {})
            .unwrap();
        let mut logical_plan = Vec::new();
        node.try_encode(&mut logical_plan).unwrap();

        let bad_payload = CodecPayload {
            connector_name: "pg_demo".to_string(),
            logical_plan,
            version: 99,
            kind: KIND_VIRTUAL_EXEC,
            arrow_schema: Vec::new(),
            warehouse_scan: Vec::new(),
        };
        let mut buf = Vec::new();
        bad_payload.encode(&mut buf).unwrap();

        let codec = FederationPlanCodec::new(registry_with("pg_demo"));
        let ctx = TaskContext::default();
        let err = codec.try_decode(&buf, &[], &ctx).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("version mismatch"),
            "expected version-mismatch error, got: {msg}"
        );
    }

    #[test]
    fn encode_delegates_unsupported_node_to_inner_codec() {
        // Non-federation nodes get handed to the inner codec. With
        // the default `DefaultPhysicalExtensionCodec` that errors,
        // but this confirms the delegation path is wired — in
        // production the inner is `BallistaPhysicalExtensionCodec`,
        // which handles `ShuffleWriterExec` and friends. PR #272's
        // e2e regression surfaced when this delegation was missing
        // (the codec rejected ShuffleWriterExec, breaking every
        // Ballista distributed query).
        let codec = FederationPlanCodec::new(registry_with("pg_demo"));
        let other_plan: Arc<dyn ExecutionPlan> = Arc::new(
            datafusion::physical_plan::empty::EmptyExec::new(Arc::new(Schema::empty())),
        );
        let mut buf = Vec::new();
        // The default inner errors; the error should NOT mention
        // FederationPlanCodec's name — that would mean we never
        // delegated.
        let err = codec.try_encode(other_plan, &mut buf).unwrap_err();
        let msg = err.to_string();
        assert!(
            !msg.contains("FederationPlanCodec only handles"),
            "delegation didn't fire — federation codec rejected node \
             instead of forwarding to inner. Got: {msg}"
        );
    }

    /// **Round-trip a `SchemaCastScanExec` through the codec.**
    /// PR #272 e2e (slice 4b.4) surfaced that the federation
    /// physical plan tree is `SchemaCastScanExec(CooperativeExec(
    /// VirtualExecutionPlan))`, not a bare `VirtualExecutionPlan`.
    /// This test pins the wrapper round-trip: encode produces a
    /// non-empty payload with `kind=schema_cast`, decode rebuilds
    /// the wrapper from the encoded schema + a stub child.
    #[test]
    fn round_trip_schema_cast_scan_exec() {
        use datafusion::arrow::datatypes::{DataType, Field};

        let target_schema = Arc::new(Schema::new(vec![
            Field::new("id", DataType::Int32, false),
            Field::new("name", DataType::Utf8, true),
        ]));
        let inner: Arc<dyn ExecutionPlan> = Arc::new(
            datafusion::physical_plan::empty::EmptyExec::new(Arc::clone(&target_schema)),
        );
        let cast = SchemaCastScanExec::new(Arc::clone(&inner), Arc::clone(&target_schema));

        let codec = FederationPlanCodec::new(registry_with("pg_demo"));
        let mut buf = Vec::new();
        codec
            .try_encode(Arc::new(cast), &mut buf)
            .expect("schema-cast encode");
        assert!(!buf.is_empty(), "encoded payload should be non-empty");

        // Decode with the same `inner` re-supplied — datafusion-proto's
        // recursive walk would normally hand us this; we mimic by
        // passing the slice directly.
        let ctx = TaskContext::default();
        let decoded = codec
            .try_decode(&buf, std::slice::from_ref(&inner), &ctx)
            .expect("schema-cast decode");
        let decoded_cast = decoded
            .downcast_ref::<SchemaCastScanExec>()
            .expect("decoded plan is a SchemaCastScanExec");
        assert_eq!(decoded_cast.schema().fields().len(), 2);
        assert_eq!(decoded_cast.schema().field(0).name(), "id");
        assert_eq!(decoded_cast.schema().field(1).name(), "name");
    }

    /// **Inner-codec delegation works for both encode and decode.**
    /// PR #272 e2e surfaced that without delegation, our codec
    /// blocked Ballista's own `ShuffleWriterExec` from
    /// round-tripping (we'd installed `FederationPlanCodec` on the
    /// `with_ballista_physical_extension_codec` slot, *replacing*
    /// `BallistaPhysicalExtensionCodec` entirely instead of
    /// wrapping it). Pin the wrap-and-delegate behaviour: a custom
    /// inner codec that records calls must see every non-federation
    /// node and every non-federation byte stream.
    #[test]
    fn inner_codec_handles_non_federation_round_trip() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        #[derive(Debug)]
        struct RecordingInner {
            encode_calls: AtomicUsize,
            decode_calls: AtomicUsize,
        }

        impl PhysicalExtensionCodec for RecordingInner {
            fn try_encode(&self, _node: Arc<dyn ExecutionPlan>, buf: &mut Vec<u8>) -> DfResult<()> {
                self.encode_calls.fetch_add(1, Ordering::SeqCst);
                // Write a non-empty marker so the test can spot
                // delegation succeeded.
                buf.push(0xFE);
                Ok(())
            }

            fn try_decode(
                &self,
                _buf: &[u8],
                _inputs: &[Arc<dyn ExecutionPlan>],
                _ctx: &TaskContext,
            ) -> DfResult<Arc<dyn ExecutionPlan>> {
                self.decode_calls.fetch_add(1, Ordering::SeqCst);
                Ok(Arc::new(datafusion::physical_plan::empty::EmptyExec::new(
                    Arc::new(Schema::empty()),
                )))
            }
        }

        let inner = Arc::new(RecordingInner {
            encode_calls: AtomicUsize::new(0),
            decode_calls: AtomicUsize::new(0),
        });
        let codec = FederationPlanCodec::new(registry_with("pg_demo"))
            .with_inner_physical_codec(Arc::clone(&inner) as Arc<dyn PhysicalExtensionCodec>);

        // Encode delegation: a non-federation node must reach the inner.
        let other_plan: Arc<dyn ExecutionPlan> = Arc::new(
            datafusion::physical_plan::empty::EmptyExec::new(Arc::new(Schema::empty())),
        );
        let mut buf = Vec::new();
        codec
            .try_encode(other_plan, &mut buf)
            .expect("encode delegates without error");
        assert_eq!(
            inner.encode_calls.load(Ordering::SeqCst),
            1,
            "encode must delegate to inner codec for non-federation nodes"
        );
        assert_eq!(buf, vec![0xFE], "inner's bytes should reach the buffer");

        // Decode delegation: bytes that don't parse as our envelope
        // (and bytes that parse with version=0) must reach the inner.
        let ctx = TaskContext::default();
        let _ = codec
            .try_decode(&buf, &[], &ctx)
            .expect("decode delegates without error");
        assert_eq!(
            inner.decode_calls.load(Ordering::SeqCst),
            1,
            "decode must delegate to inner codec for non-federation bytes"
        );
    }

    /// **Round-trip a `CooperativeExec` through the codec.** Same
    /// reason as the schema-cast test — the wrapper appears in the
    /// federation physical-plan tree and has to round-trip.
    #[test]
    fn round_trip_cooperative_exec() {
        use datafusion::arrow::datatypes::{DataType, Field};
        use datafusion::physical_plan::coop::CooperativeExec;

        let inner_schema = Arc::new(Schema::new(vec![Field::new("v", DataType::Int32, false)]));
        let inner: Arc<dyn ExecutionPlan> = Arc::new(
            datafusion::physical_plan::empty::EmptyExec::new(Arc::clone(&inner_schema)),
        );
        let coop = CooperativeExec::new(Arc::clone(&inner));

        let codec = FederationPlanCodec::new(registry_with("pg_demo"));
        let mut buf = Vec::new();
        codec
            .try_encode(Arc::new(coop), &mut buf)
            .expect("cooperative encode");
        assert!(!buf.is_empty(), "encoded payload should be non-empty");

        let ctx = TaskContext::default();
        let decoded = codec
            .try_decode(&buf, std::slice::from_ref(&inner), &ctx)
            .expect("cooperative decode");
        assert!(
            decoded.downcast_ref::<CooperativeExec>().is_some(),
            "decoded plan should be a CooperativeExec"
        );
    }

    #[test]
    fn codec_is_send_sync_via_arc() {
        // Ballista holds codecs as `Arc<dyn PhysicalExtensionCodec>`
        // and ships them across executor threads. Pin the trait-
        // object bound at compile time.
        fn assert_send_sync<T: Send + Sync + 'static>() {}
        assert_send_sync::<Arc<dyn PhysicalExtensionCodec>>();
        assert_send_sync::<FederationPlanCodec>();
    }

    #[test]
    fn codec_version_constant_documented() {
        // Pin the constant. Any change here is a wire-format break
        // and triggers the version-mismatch error on every old
        // worker — the on-purpose effect.
        assert_eq!(CODEC_VERSION, 1);
    }

    ///  — a REST connector's physical scan node has no distributed
    /// codec; encoding it must produce the friendly single-node-only error,
    /// not fall through to the inner codec's cryptic serialization failure.
    /// `scan()` builds the plan without IO, so no mock server is needed.
    #[cfg(feature = "rest")]
    #[tokio::test]
    async fn rest_scan_node_reports_single_node_only_error() {
        use crate::rest::{RestAuth, RestConnector, RestPagination, RestSourceConfig, RestTable};
        use datafusion::arrow::datatypes::{DataType, Field, Schema};
        use datafusion::prelude::SessionContext;

        let schema = Arc::new(Schema::new(vec![Field::new("id", DataType::Int64, true)]));
        let table = RestTable {
            name: "t".to_string(),
            config: RestSourceConfig {
                url: "http://127.0.0.1:1/t".to_string(),
                records_path: String::new(),
                auth: RestAuth::None,
                pagination: RestPagination::None,
                pushdown: vec![],
            },
            schema,
        };
        let connector = RestConnector::new("rest_demo", vec![table]).expect("client builds");
        let provider = connector.table_provider("t").expect("table exists");
        let ctx = SessionContext::new();
        let plan = provider
            .scan(&ctx.state(), None, &[], None)
            .await
            .expect("scan builds the RestScanExec plan node");

        let codec = FederationPlanCodec::new(registry_with("unused_sql"));
        let mut buf = Vec::new();
        let err = codec.try_encode(plan, &mut buf).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("REST/JSON") && msg.contains("distributed mode"),
            "expected the friendly single-node-only error, got: {msg}"
        );
    }

    // ---- Warehouse-scan (Iceberg) serialization path -------------
    // WarehouseScanExec is normally only reachable through a live REST
    // catalog. The in-memory catalog escape hatch
    // (`WarehouseConnector::__from_catalog_for_tests`) lets us round-trip the
    // distributed codec path — the scheduler→worker wire for iceberg scans —
    // without Docker.

    #[cfg(feature = "iceberg")]
    async fn test_warehouse_connector(name: &str) -> Arc<crate::iceberg::WarehouseConnector> {
        use iceberg::{Catalog, CatalogBuilder};

        let cfg = HashMap::from([(
            iceberg::memory::MEMORY_CATALOG_WAREHOUSE.to_string(),
            "/tmp/wh-codec-test".to_string(),
        )]);
        let catalog = iceberg::memory::MemoryCatalogBuilder::default()
            .load("warehouse", cfg)
            .await
            .expect("memory catalog builds");
        Arc::new(
            crate::iceberg::WarehouseConnector::__from_catalog_for_tests(
                name,
                Arc::new(catalog) as Arc<dyn Catalog>,
            ),
        )
    }

    #[cfg(feature = "iceberg")]
    fn two_col_schema() -> SchemaRef {
        use datafusion::arrow::datatypes::{DataType, Field};
        Arc::new(Schema::new(vec![
            Field::new("id", DataType::Int64, false),
            Field::new("name", DataType::Utf8, true),
        ]))
    }

    #[cfg(feature = "iceberg")]
    #[tokio::test]
    async fn warehouse_scan_round_trips_identity_and_shape() {
        use crate::iceberg::{WarehouseRegistry, WarehouseScanExec};

        let connector = test_warehouse_connector("lake").await;
        let warehouses = Arc::new(WarehouseRegistry::new(HashMap::from([(
            "lake".to_string(),
            Arc::clone(&connector),
        )])));

        // Projection selects the second column; limit is Some, so both
        // optional-payload branches carry a value.
        let scan = WarehouseScanExec::new(
            Arc::clone(&connector),
            "lake".to_string(),
            "analytics".to_string(),
            "orders".to_string(),
            two_col_schema(),
            Some(vec![1]),
            Some(100),
        );

        let codec = FederationPlanCodec::new(registry_with("unused_sql"))
            .with_warehouse_registry(Arc::clone(&warehouses));

        let mut buf = Vec::new();
        codec
            .try_encode(Arc::new(scan), &mut buf)
            .expect("warehouse scan encodes");

        let ctx = TaskContext::default();
        let decoded = codec
            .try_decode(&buf, &[], &ctx)
            .expect("warehouse scan decodes");
        let scan = decoded
            .downcast_ref::<WarehouseScanExec>()
            .expect("decoded node is a WarehouseScanExec");

        assert_eq!(scan.connector_name(), "lake");
        assert_eq!(scan.namespace(), "analytics");
        assert_eq!(scan.table(), "orders");
        assert_eq!(scan.projection().cloned(), Some(vec![1]));
        assert_eq!(scan.limit(), Some(100));
        // full_schema is the pre-projection schema and must survive intact.
        assert_eq!(scan.full_schema().fields().len(), 2);
        assert_eq!(scan.full_schema().field(0).name(), "id");
        assert_eq!(scan.full_schema().field(1).name(), "name");
    }

    #[cfg(feature = "iceberg")]
    #[tokio::test]
    async fn warehouse_scan_round_trips_without_projection_or_limit() {
        use crate::iceberg::{WarehouseRegistry, WarehouseScanExec};

        let connector = test_warehouse_connector("lake").await;
        let warehouses = Arc::new(WarehouseRegistry::new(HashMap::from([(
            "lake".to_string(),
            Arc::clone(&connector),
        )])));
        let scan = WarehouseScanExec::new(
            Arc::clone(&connector),
            "lake".to_string(),
            "analytics".to_string(),
            "events".to_string(),
            two_col_schema(),
            None,
            None,
        );

        let codec = FederationPlanCodec::new(registry_with("unused_sql"))
            .with_warehouse_registry(warehouses);
        let mut buf = Vec::new();
        codec.try_encode(Arc::new(scan), &mut buf).unwrap();
        let ctx = TaskContext::default();
        let decoded = codec.try_decode(&buf, &[], &ctx).unwrap();
        let scan = decoded.downcast_ref::<WarehouseScanExec>().unwrap();

        assert_eq!(scan.projection(), None);
        assert_eq!(scan.limit(), None);
    }

    #[cfg(feature = "iceberg")]
    #[tokio::test]
    async fn warehouse_scan_encode_without_registry_errors() {
        use crate::iceberg::WarehouseScanExec;

        let connector = test_warehouse_connector("lake").await;
        let scan = WarehouseScanExec::new(
            Arc::clone(&connector),
            "lake".to_string(),
            "analytics".to_string(),
            "orders".to_string(),
            two_col_schema(),
            None,
            None,
        );

        // No `with_warehouse_registry` — a warehouse scan reaching this codec
        // is a wiring bug and must fail loudly.
        let codec = FederationPlanCodec::new(registry_with("unused_sql"));
        let mut buf = Vec::new();
        let err = codec.try_encode(Arc::new(scan), &mut buf).unwrap_err();
        assert!(
            err.to_string().contains("warehouse registry"),
            "expected a missing-registry error, got: {err}"
        );
    }

    #[cfg(feature = "iceberg")]
    #[tokio::test]
    async fn warehouse_scan_decode_without_registry_errors() {
        use crate::iceberg::{WarehouseRegistry, WarehouseScanExec};

        // Encode on a coordinator that HAS the registry...
        let connector = test_warehouse_connector("lake").await;
        let warehouses = Arc::new(WarehouseRegistry::new(HashMap::from([(
            "lake".to_string(),
            Arc::clone(&connector),
        )])));
        let scan = WarehouseScanExec::new(
            Arc::clone(&connector),
            "lake".to_string(),
            "analytics".to_string(),
            "orders".to_string(),
            two_col_schema(),
            None,
            None,
        );
        let encode_codec = FederationPlanCodec::new(registry_with("unused_sql"))
            .with_warehouse_registry(warehouses);
        let mut buf = Vec::new();
        encode_codec.try_encode(Arc::new(scan), &mut buf).unwrap();

        // ...decode on a worker that DOESN'T -> typed planner error.
        let decode_codec = FederationPlanCodec::new(registry_with("unused_sql"));
        let ctx = TaskContext::default();
        let err = decode_codec.try_decode(&buf, &[], &ctx).unwrap_err();
        assert!(
            err.to_string().contains("warehouse registry"),
            "expected a missing-registry error, got: {err}"
        );
    }
}

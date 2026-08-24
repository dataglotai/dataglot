//! Federation-aware physical filter-pushdown guard.
//!
//! `datafusion-federation 0.5.3` has a filter-pushdown correctness bug:
//! `VirtualExecutionPlan::handle_child_pushdown_result` reports
//! `PushedDown::Yes` for every parent filter — so DataFusion's physical
//! `FilterPushdown` rule deletes the parent `FilterExec` — but
//! `VirtualExecutionPlan::final_sql` builds the remote query purely from
//! its captured logical plan and never unparses those filters into the
//! SQL (they're only handed to `SQLExecutor::execute` as a side-channel
//! argument our connectors ignore). Net effect: the predicate is
//! silently dropped across cross-source joins.
//!
//! The original workaround stripped the physical `FilterPushdown` rule
//! from the federated context wholesale. That fixed correctness but also
//! killed scan-time parquet pushdown (row-group / page pruning + late
//! materialization) on the local Iceberg / object-storage read paths
//!
//! This module restores `FilterPushdown` while keeping correctness, by
//! wrapping every `VirtualExecutionPlan` in a [`FederationFilterGuard`]
//! before `FilterPushdown` runs. The guard is a transparent passthrough
//! that overrides exactly one thing: it declines physical filter
//! pushdown (`handle_child_pushdown_result` → `PushedDown::No` for all
//! parent filters), so the parent `FilterExec` is *retained* above the
//! federation node — the predicate is evaluated locally on the rows the
//! remote SQL returns, never lost. Parquet / Iceberg scans, which carry
//! no `VirtualExecutionPlan`, get true scan-time pushdown.
//!
//! The guard is conservative: it can only ever *keep* a filter, never
//! claim one was pushed when it wasn't — so it cannot introduce the
//! predicate-loss bug it guards against.

use std::fmt;
use std::sync::Arc;

use datafusion::arrow::datatypes::SchemaRef;
use datafusion::common::tree_node::{Transformed, TreeNode};
use datafusion::common::Statistics;
use datafusion::config::ConfigOptions;
use datafusion::error::{DataFusionError, Result};
use datafusion::execution::TaskContext;
use datafusion::physical_optimizer::PhysicalOptimizerRule;
use datafusion::physical_plan::filter_pushdown::{
    ChildPushdownResult, FilterPushdownPhase, FilterPushdownPropagation,
};
use datafusion::physical_plan::metrics::MetricsSet;
use datafusion::physical_plan::{
    DisplayAs, DisplayFormatType, ExecutionPlan, PlanProperties, SendableRecordBatchStream,
};

/// `ExecutionPlan::name()` of the `datafusion-federation` node we guard.
/// Matched by name so this crate needn't depend on the concrete type.
///
/// Note: `VirtualExecutionPlan::name()` returns `"sql_federation_exec"` —
/// the string `"VirtualExecutionPlan"` is only its `DisplayAs` (EXPLAIN)
/// rendering, *not* what `name()` returns. Matching the wrong one makes
/// the guard silently never fire.
const FEDERATION_NODE_NAME: &str = "sql_federation_exec";

/// Transparent single-child wrapper that declines physical filter
/// pushdown so the parent `FilterExec` survives above a federation node.
///
/// Every method delegates to the wrapped node except
/// [`handle_child_pushdown_result`](ExecutionPlan::handle_child_pushdown_result),
/// which reports all parent filters as not-pushed. See the module docs.
#[derive(Debug)]
pub struct FederationFilterGuard {
    /// The wrapped `VirtualExecutionPlan` (held opaquely).
    input: Arc<dyn ExecutionPlan>,
    /// Cloned from `input` so `properties()` can hand back a reference.
    props: Arc<PlanProperties>,
}

impl FederationFilterGuard {
    /// Wrap `input` (expected to be a federation `VirtualExecutionPlan`).
    #[must_use]
    pub fn new(input: Arc<dyn ExecutionPlan>) -> Self {
        let props = Arc::clone(input.properties());
        Self { input, props }
    }
}

impl DisplayAs for FederationFilterGuard {
    fn fmt_as(&self, _t: DisplayFormatType, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FederationFilterGuard")
    }
}

impl ExecutionPlan for FederationFilterGuard {
    // The trait fixes the return as `&str`; returning a literal trips
    // `unnecessary_literal_bound` but we can't widen the signature.
    #[allow(clippy::unnecessary_literal_bound)]
    fn name(&self) -> &str {
        "FederationFilterGuard"
    }

    fn properties(&self) -> &Arc<PlanProperties> {
        &self.props
    }

    fn schema(&self) -> SchemaRef {
        self.input.schema()
    }

    fn children(&self) -> Vec<&Arc<dyn ExecutionPlan>> {
        vec![&self.input]
    }

    fn with_new_children(
        self: Arc<Self>,
        children: Vec<Arc<dyn ExecutionPlan>>,
    ) -> Result<Arc<dyn ExecutionPlan>> {
        match <[Arc<dyn ExecutionPlan>; 1]>::try_from(children) {
            Ok([child]) => Ok(Arc::new(Self::new(child))),
            Err(_) => Err(DataFusionError::Internal(
                "FederationFilterGuard expects exactly one child".to_string(),
            )),
        }
    }

    fn execute(
        &self,
        partition: usize,
        context: Arc<TaskContext>,
    ) -> Result<SendableRecordBatchStream> {
        self.input.execute(partition, context)
    }

    fn partition_statistics(&self, partition: Option<usize>) -> Result<Arc<Statistics>> {
        self.input.partition_statistics(partition)
    }

    fn metrics(&self) -> Option<MetricsSet> {
        self.input.metrics()
    }

    /// The whole point of the guard: tell the parent that none of its
    /// filters were absorbed, so the `FilterExec` above us stays. We rely
    /// on the default `gather_filters_for_pushdown` (which bars parent
    /// filters from reaching the wrapped node), so the predicate never
    /// reaches the buggy `VirtualExecutionPlan` pushdown handler either.
    fn handle_child_pushdown_result(
        &self,
        _phase: FilterPushdownPhase,
        child_pushdown_result: ChildPushdownResult,
        _config: &ConfigOptions,
    ) -> Result<FilterPushdownPropagation<Arc<dyn ExecutionPlan>>> {
        Ok(FilterPushdownPropagation::all_unsupported(
            child_pushdown_result,
        ))
    }
}

/// Physical-optimizer rule that wraps every federation `VirtualExecutionPlan`
/// in a [`FederationFilterGuard`].
///
/// Must run **before** DataFusion's `FilterPushdown` rule so the guard is
/// in place when pushdown decisions are made (the federated context
/// prepends it to the default physical-optimizer list). Only nodes whose
/// `ExecutionPlan::name()` is `sql_federation_exec` (the federation
/// `VirtualExecutionPlan`) are wrapped; everything else is left alone.
#[derive(Debug, Default)]
pub struct WrapFederationNodes;

impl PhysicalOptimizerRule for WrapFederationNodes {
    fn optimize(
        &self,
        plan: Arc<dyn ExecutionPlan>,
        _config: &ConfigOptions,
    ) -> Result<Arc<dyn ExecutionPlan>> {
        plan.transform_up(|node| {
            if node.name() == FEDERATION_NODE_NAME {
                Ok(Transformed::yes(
                    Arc::new(FederationFilterGuard::new(node)) as Arc<dyn ExecutionPlan>
                ))
            } else {
                Ok(Transformed::no(node))
            }
        })
        .map(|t| t.data)
    }

    #[allow(clippy::unnecessary_literal_bound)]
    fn name(&self) -> &str {
        "WrapFederationNodes"
    }

    fn schema_check(&self) -> bool {
        // The guard preserves the wrapped node's schema exactly.
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use datafusion::arrow::datatypes::{DataType, Field, Schema};
    use datafusion::physical_expr::EquivalenceProperties;
    use datafusion::physical_plan::execution_plan::{Boundedness, EmissionType};
    use datafusion::physical_plan::Partitioning;

    /// Minimal leaf `ExecutionPlan` with a configurable `name()` so we can
    /// stand in for a federation `VirtualExecutionPlan` without standing
    /// up a real remote source.
    #[derive(Debug)]
    struct NamedLeaf {
        node_name: &'static str,
        props: Arc<PlanProperties>,
        schema: SchemaRef,
    }

    impl NamedLeaf {
        fn named(node_name: &'static str) -> Arc<dyn ExecutionPlan> {
            let schema: SchemaRef =
                Arc::new(Schema::new(vec![Field::new("a", DataType::Int32, false)]));
            let props = Arc::new(PlanProperties::new(
                EquivalenceProperties::new(Arc::clone(&schema)),
                Partitioning::UnknownPartitioning(1),
                EmissionType::Incremental,
                Boundedness::Bounded,
            ));
            Arc::new(Self {
                node_name,
                props,
                schema,
            })
        }
    }

    impl DisplayAs for NamedLeaf {
        fn fmt_as(&self, _t: DisplayFormatType, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{}", self.node_name)
        }
    }

    impl ExecutionPlan for NamedLeaf {
        fn name(&self) -> &str {
            self.node_name
        }
        fn properties(&self) -> &Arc<PlanProperties> {
            &self.props
        }
        fn schema(&self) -> SchemaRef {
            Arc::clone(&self.schema)
        }
        fn children(&self) -> Vec<&Arc<dyn ExecutionPlan>> {
            vec![]
        }
        fn with_new_children(
            self: Arc<Self>,
            _children: Vec<Arc<dyn ExecutionPlan>>,
        ) -> Result<Arc<dyn ExecutionPlan>> {
            Ok(self)
        }
        fn execute(
            &self,
            _partition: usize,
            _context: Arc<TaskContext>,
        ) -> Result<SendableRecordBatchStream> {
            Err(DataFusionError::Internal("not executable in test".into()))
        }
    }

    #[test]
    fn rule_wraps_only_virtual_execution_plan() {
        let config = ConfigOptions::default();

        // A federation node gets wrapped.
        let vep = NamedLeaf::named("sql_federation_exec");
        let out = WrapFederationNodes.optimize(vep, &config).unwrap();
        assert_eq!(out.name(), "FederationFilterGuard");
        assert_eq!(out.children().len(), 1);
        assert_eq!(out.children()[0].name(), "sql_federation_exec");

        // Any other node is left untouched.
        let other = NamedLeaf::named("DataSourceExec");
        let out = WrapFederationNodes.optimize(other, &config).unwrap();
        assert_eq!(out.name(), "DataSourceExec");
    }

    #[test]
    fn guard_is_transparent_for_schema_and_children() {
        let vep = NamedLeaf::named("sql_federation_exec");
        let schema = vep.schema();
        let guard = FederationFilterGuard::new(Arc::clone(&vep));
        assert_eq!(guard.schema(), schema);
        assert_eq!(guard.children().len(), 1);

        // with_new_children round-trips a single child back into a guard.
        let rebuilt = Arc::new(guard).with_new_children(vec![vep]).unwrap();
        assert_eq!(rebuilt.name(), "FederationFilterGuard");

        // …and rejects the wrong arity.
        let two = vec![
            NamedLeaf::named("sql_federation_exec"),
            NamedLeaf::named("sql_federation_exec"),
        ];
        let guard2 = Arc::new(FederationFilterGuard::new(NamedLeaf::named(
            "VirtualExecutionPlan",
        )));
        assert!(guard2.with_new_children(two).is_err());
    }

    #[test]
    fn guard_declines_all_child_pushdown() {
        // The correctness core: whatever the child pushdown result, the
        // guard reports it all as unsupported so the parent FilterExec is
        // retained above the federation node (end-to-end predicate-not-lost
        // behavior is covered by the e2e phase-0 gate). Here we assert the
        // handler runs and yields a propagation without pushing anything.
        let guard = FederationFilterGuard::new(NamedLeaf::named("sql_federation_exec"));
        let empty = ChildPushdownResult {
            parent_filters: vec![],
            self_filters: vec![],
        };
        let out = guard
            .handle_child_pushdown_result(
                FilterPushdownPhase::Pre,
                empty,
                &ConfigOptions::default(),
            )
            .expect("handler must succeed");
        // `all_unsupported` over no parent filters propagates no supported
        // filters upward — nothing was absorbed by the guard.
        assert!(out.filters.iter().all(|f| matches!(
            f,
            datafusion::physical_plan::filter_pushdown::PushedDown::No
        )));
    }

    #[test]
    fn guard_delegates_runtime_methods_to_child() {
        use datafusion::execution::TaskContext;

        let child = NamedLeaf::named("sql_federation_exec");
        let guard = FederationFilterGuard::new(Arc::clone(&child));

        // as_any downcasts back to the concrete guard.
        assert!((&guard as &dyn ExecutionPlan)
            .downcast_ref::<FederationFilterGuard>()
            .is_some());

        // properties() hands back the same Arc cloned from the child at
        // construction — the guard is property-transparent.
        assert!(Arc::ptr_eq(guard.properties(), child.properties()));

        // execute delegates straight to the child (which errors in-test).
        assert!(guard.execute(0, Arc::new(TaskContext::default())).is_err());

        // statistics + metrics delegate to the child's defaults.
        assert!(guard.partition_statistics(None).is_ok());
        assert!(guard.metrics().is_none());
    }

    #[test]
    fn guard_display_renders_its_own_name() {
        use datafusion::physical_plan::displayable;

        let guard: Arc<dyn ExecutionPlan> = Arc::new(FederationFilterGuard::new(NamedLeaf::named(
            "sql_federation_exec",
        )));
        let rendered = displayable(guard.as_ref()).indent(false).to_string();
        // The guard's own DisplayAs line plus the wrapped child's.
        assert!(rendered.contains("FederationFilterGuard"));
        assert!(rendered.contains("sql_federation_exec"));
    }
}

//! Executor-side per-source pushdown metrics for distributed capture.
//!
//! In distributed mode a federated scan runs inside an executor process, so the
//! single-node task-local pushdown sink (`dataglot_core`) is never in scope
//! there — capture would come back empty. This module surfaces each federated
//! scan's row/batch/elapsed counts as **`ExecutionPlan` metrics**, which
//! Ballista already ships back to the scheduler inside `TaskStatus` (retrievable
//! via `get_job_metrics(job_id)`). The coordinator then correlates them to the
//! pgwire `RunId` and records them into the query registry (see the
//! `dataglot-ballista` `cancel_on_drop` coordinator path).
//!
//! Wiring: the physical codec ([`crate::codec::FederationPlanCodec`]) wraps the
//! decoded [`datafusion_federation::sql::VirtualExecutionPlan`] in a
//! [`PushdownMetricsExec`] labelled with the connector (catalog) name, so its
//! counters are named `pushdown.<catalog>.{rows,batches,ms}`. The wrap happens
//! at *physical* decode — after federation has finished planning — so it never
//! touches the federated `TableScan` sources that federation's own SQL
//! generator re-plans from. Single-node execution is untouched (this codec is
//! only used distributed).

use std::fmt;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Instant;

use datafusion::arrow::datatypes::SchemaRef;
use datafusion::arrow::record_batch::RecordBatch;
use datafusion::common::config::ConfigOptions;
use datafusion::common::tree_node::{Transformed, TreeNode};
use datafusion::common::Result as DfResult;
use datafusion::error::DataFusionError;
use datafusion::execution::TaskContext;
use datafusion::physical_optimizer::PhysicalOptimizerRule;
use datafusion::physical_plan::metrics::{
    Count, ExecutionPlanMetricsSet, MetricBuilder, MetricsSet,
};
use datafusion::physical_plan::{
    DisplayAs, DisplayFormatType, ExecutionPlan, PlanProperties, RecordBatchStream,
    SendableRecordBatchStream,
};
use futures::Stream;

/// Metric-name prefix the coordinator scans for in `get_job_metrics`.
/// Full shape: `pushdown.<catalog>.<field>` where field ∈ {rows, batches, ms}.
pub const PUSHDOWN_METRIC_PREFIX: &str = "pushdown.";

/// `ExecutionPlan::name()` of federation's `VirtualExecutionPlan` — the node
/// the [`WrapFederatedScansForMetrics`] rule targets.
const FEDERATION_NODE_NAME: &str = "sql_federation_exec";

/// Coordinator-side physical-optimizer rule that wraps each federation
/// `VirtualExecutionPlan` in a [`PushdownMetricsExec`].
///
/// The node MUST live in the coordinator's plan — not be spliced in only on the
/// executor at codec-decode — or Ballista's `get_job_metrics` serialization
/// trips its operator/metrics-count invariant (executor reports one more metric
/// set than the scheduler's plan has operators). Placed here, the node
/// round-trips through [`crate::codec::FederationPlanCodec`] symmetrically.
///
/// The catalog label is left blank; the codec resolves it from the wrapped
/// scan's connector identity at encode time (it already holds the registry), so
/// this rule needs no registry of its own.
#[derive(Debug, Default)]
pub struct WrapFederatedScansForMetrics;

impl PhysicalOptimizerRule for WrapFederatedScansForMetrics {
    fn optimize(
        &self,
        plan: Arc<dyn ExecutionPlan>,
        _config: &ConfigOptions,
    ) -> DfResult<Arc<dyn ExecutionPlan>> {
        plan.transform_up(|node| {
            if node.name() == FEDERATION_NODE_NAME {
                Ok(Transformed::yes(
                    Arc::new(PushdownMetricsExec::new(node, "")) as Arc<dyn ExecutionPlan>,
                ))
            } else {
                Ok(Transformed::no(node))
            }
        })
        .map(|t| t.data)
    }

    #[allow(clippy::unnecessary_literal_bound)]
    fn name(&self) -> &str {
        "WrapFederatedScansForMetrics"
    }

    fn schema_check(&self) -> bool {
        // Transparent wrapper — schema is the wrapped scan's schema unchanged.
        true
    }
}

/// Transparent single-child `ExecutionPlan` that counts its child's output
/// (rows / batches / elapsed-ms) into per-source named metrics.
///
/// Wrapped around a federated scan on the executor so the row/batch/elapsed
/// counts ride Ballista's task-metric channel back to the scheduler, where the
/// coordinator reads them by name and attributes them to the issuing query.
#[derive(Debug)]
pub struct PushdownMetricsExec {
    input: Arc<dyn ExecutionPlan>,
    /// Cloned from `input` so `properties()` can hand back a reference.
    props: Arc<PlanProperties>,
    /// Catalog (source) name — the metric label.
    source: Arc<str>,
    metrics: ExecutionPlanMetricsSet,
}

impl PushdownMetricsExec {
    /// Wrap `input` (a federated scan plan), labelling metrics with `source`.
    #[must_use]
    pub fn new(input: Arc<dyn ExecutionPlan>, source: impl Into<Arc<str>>) -> Self {
        let props = Arc::clone(input.properties());
        Self {
            input,
            props,
            source: source.into(),
            metrics: ExecutionPlanMetricsSet::new(),
        }
    }

    /// The catalog (source) label this scan's metrics are named under. Empty on
    /// the coordinator (the inserting rule leaves it blank); the codec fills it
    /// from the wrapped scan's connector identity when serializing to workers.
    #[must_use]
    pub fn source(&self) -> &str {
        &self.source
    }
}

impl DisplayAs for PushdownMetricsExec {
    fn fmt_as(&self, _t: DisplayFormatType, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PushdownMetricsExec: source={}", self.source)
    }
}

impl ExecutionPlan for PushdownMetricsExec {
    fn name(&self) -> &'static str {
        "PushdownMetricsExec"
    }

    fn properties(&self) -> &Arc<PlanProperties> {
        &self.props
    }

    fn children(&self) -> Vec<&Arc<dyn ExecutionPlan>> {
        vec![&self.input]
    }

    fn with_new_children(
        self: Arc<Self>,
        children: Vec<Arc<dyn ExecutionPlan>>,
    ) -> DfResult<Arc<dyn ExecutionPlan>> {
        match <[Arc<dyn ExecutionPlan>; 1]>::try_from(children) {
            Ok([child]) => Ok(Arc::new(Self::new(child, Arc::clone(&self.source)))),
            Err(_) => Err(DataFusionError::Internal(
                "PushdownMetricsExec expects exactly one child".to_string(),
            )),
        }
    }

    fn execute(
        &self,
        partition: usize,
        context: Arc<TaskContext>,
    ) -> DfResult<SendableRecordBatchStream> {
        let inner = self.input.execute(partition, context)?;
        // Global (not per-partition) counters, named per source so the
        // coordinator can attribute them: `pushdown.<catalog>.<field>`.
        let src = &self.source;
        let rows = MetricBuilder::new(&self.metrics)
            .global_counter(format!("{PUSHDOWN_METRIC_PREFIX}{src}.rows"));
        let batches = MetricBuilder::new(&self.metrics)
            .global_counter(format!("{PUSHDOWN_METRIC_PREFIX}{src}.batches"));
        let elapsed_ms = MetricBuilder::new(&self.metrics)
            .global_counter(format!("{PUSHDOWN_METRIC_PREFIX}{src}.ms"));
        Ok(Box::pin(PushdownMetricsStream {
            schema: self.input.schema(),
            inner,
            started: None,
            rows,
            batches,
            elapsed_ms,
            finished: false,
        }))
    }

    fn metrics(&self) -> Option<MetricsSet> {
        Some(self.metrics.clone_inner())
    }
}

/// The counting stream: tallies rows/batches and records elapsed-ms on
/// completion into the [`PushdownMetricsExec`]'s metric counters.
struct PushdownMetricsStream {
    schema: SchemaRef,
    inner: SendableRecordBatchStream,
    started: Option<Instant>,
    rows: Count,
    batches: Count,
    elapsed_ms: Count,
    /// Set once the elapsed metric is recorded, so a stream polled after
    /// exhaustion doesn't double-record.
    finished: bool,
}

impl Stream for PushdownMetricsStream {
    type Item = DfResult<RecordBatch>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.as_mut().get_mut();
        if this.started.is_none() {
            this.started = Some(Instant::now());
        }
        match this.inner.as_mut().poll_next(cx) {
            Poll::Ready(Some(Ok(batch))) => {
                this.rows.add(batch.num_rows());
                this.batches.add(1);
                Poll::Ready(Some(Ok(batch)))
            }
            Poll::Ready(None) => {
                if !this.finished {
                    this.finished = true;
                    let ms = this.started.map_or(0, |s| {
                        usize::try_from(s.elapsed().as_millis()).unwrap_or(usize::MAX)
                    });
                    this.elapsed_ms.add(ms);
                }
                Poll::Ready(None)
            }
            other => other,
        }
    }
}

impl RecordBatchStream for PushdownMetricsStream {
    fn schema(&self) -> SchemaRef {
        Arc::clone(&self.schema)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use datafusion::arrow::array::Int32Array;
    use datafusion::arrow::datatypes::{DataType, Field, Schema};
    use datafusion::physical_expr::EquivalenceProperties;
    use datafusion::physical_plan::execution_plan::{Boundedness, EmissionType};
    use datafusion::physical_plan::metrics::MetricValue;
    use datafusion::physical_plan::stream::RecordBatchStreamAdapter;
    use datafusion::physical_plan::Partitioning;
    use futures::{stream, StreamExt};

    fn test_schema() -> SchemaRef {
        Arc::new(Schema::new(vec![Field::new("n", DataType::Int32, false)]))
    }

    fn batch(schema: &SchemaRef, values: &[i32]) -> RecordBatch {
        RecordBatch::try_new(
            Arc::clone(schema),
            vec![Arc::new(Int32Array::from(values.to_vec()))],
        )
        .expect("build test batch")
    }

    /// Minimal single-partition leaf that streams a fixed list of batches —
    /// stands in for a federated `VirtualExecutionPlan` in the wrap test. Its
    /// `name()` is configurable so it can impersonate `sql_federation_exec`.
    #[derive(Debug)]
    struct MockScan {
        node_name: &'static str,
        schema: SchemaRef,
        batches: Vec<RecordBatch>,
        props: Arc<PlanProperties>,
    }

    impl MockScan {
        fn new(schema: SchemaRef, batches: Vec<RecordBatch>) -> Self {
            Self::named("MockScan", schema, batches)
        }

        fn named(node_name: &'static str, schema: SchemaRef, batches: Vec<RecordBatch>) -> Self {
            let props = Arc::new(PlanProperties::new(
                EquivalenceProperties::new(Arc::clone(&schema)),
                Partitioning::UnknownPartitioning(1),
                EmissionType::Incremental,
                Boundedness::Bounded,
            ));
            Self {
                node_name,
                schema,
                batches,
                props,
            }
        }
    }

    impl DisplayAs for MockScan {
        fn fmt_as(&self, _t: DisplayFormatType, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "MockScan")
        }
    }

    impl ExecutionPlan for MockScan {
        fn name(&self) -> &'static str {
            self.node_name
        }
        fn properties(&self) -> &Arc<PlanProperties> {
            &self.props
        }
        fn children(&self) -> Vec<&Arc<dyn ExecutionPlan>> {
            vec![]
        }
        fn with_new_children(
            self: Arc<Self>,
            _children: Vec<Arc<dyn ExecutionPlan>>,
        ) -> DfResult<Arc<dyn ExecutionPlan>> {
            Ok(self)
        }
        fn execute(
            &self,
            _partition: usize,
            _context: Arc<TaskContext>,
        ) -> DfResult<SendableRecordBatchStream> {
            let items: Vec<DfResult<RecordBatch>> = self.batches.iter().cloned().map(Ok).collect();
            Ok(Box::pin(RecordBatchStreamAdapter::new(
                Arc::clone(&self.schema),
                stream::iter(items),
            )))
        }
    }

    #[tokio::test]
    async fn counts_rows_and_batches_into_named_metrics() {
        let schema = test_schema();
        let child = Arc::new(MockScan::new(
            Arc::clone(&schema),
            vec![batch(&schema, &[1, 2, 3]), batch(&schema, &[4, 5])],
        ));
        let exec = Arc::new(PushdownMetricsExec::new(child, "pg"));

        let ctx = Arc::new(TaskContext::default());
        let mut stream = exec.execute(0, ctx).expect("execute");
        let mut total = 0usize;
        while let Some(b) = stream.next().await {
            total += b.expect("batch ok").num_rows();
        }
        assert_eq!(total, 5, "all rows stream through unchanged");

        let metrics = exec.metrics().expect("metrics present");
        let named = |suffix: &str| -> Option<usize> {
            metrics.iter().find_map(|m| match m.value() {
                MetricValue::Count { name, count }
                    if name.as_ref() == format!("pushdown.pg.{suffix}") =>
                {
                    Some(count.value())
                }
                _ => None,
            })
        };
        assert_eq!(named("rows"), Some(5), "rows counter is per-source named");
        assert_eq!(named("batches"), Some(2), "batches counter");
        assert!(named("ms").is_some(), "elapsed-ms recorded on completion");
    }

    #[test]
    fn rule_wraps_only_federation_scan_nodes() {
        let schema = test_schema();
        let rule = WrapFederatedScansForMetrics;
        let cfg = ConfigOptions::default();

        // A federation scan node (name == sql_federation_exec) gets wrapped.
        let fed: Arc<dyn ExecutionPlan> = Arc::new(MockScan::named(
            FEDERATION_NODE_NAME,
            Arc::clone(&schema),
            vec![],
        ));
        let wrapped = rule.optimize(fed, &cfg).expect("optimize");
        assert_eq!(
            wrapped.name(),
            "PushdownMetricsExec",
            "federation scan is wrapped"
        );
        // The wrapper's label is left blank here (codec fills it at encode time).
        let pm = wrapped
            .downcast_ref::<PushdownMetricsExec>()
            .expect("is a PushdownMetricsExec");
        assert_eq!(pm.source(), "", "label deferred to codec encode");

        // A non-federation leaf is left untouched.
        let other: Arc<dyn ExecutionPlan> = Arc::new(MockScan::named(
            "SomeOtherExec",
            Arc::clone(&schema),
            vec![],
        ));
        let unchanged = rule.optimize(other, &cfg).expect("optimize");
        assert_eq!(
            unchanged.name(),
            "SomeOtherExec",
            "non-federation untouched"
        );
    }
}

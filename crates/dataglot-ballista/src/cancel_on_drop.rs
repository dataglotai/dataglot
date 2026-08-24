//! Job cancellation on client abandonment.
//!
//! Upstream's `DistributedQueryExec` (Ballista 53) submits a job and
//! streams its results — but has **no cancel-on-drop**: when the
//! client stops consuming (a pgwire cancel, a dropped connection, a
//! timed-out caller), dropping the stream merely stops *polling*. The
//! job keeps running on the scheduler and executors, holding task
//! slots until it finishes on its own. A cancelled cross join burns
//! the cluster indefinitely.
//!
//! This module closes the gap without forking upstream, using two
//! hooks Ballista already exposes:
//!
//! - `DistributedQueryExec::job_id()` — the submitted job's id,
//!   readable from outside the stream;
//! - the scheduler's `CancelJob` gRPC.
//!
//! [`CancelOnDropQueryPlanner`] decorates the coordinator's planner
//! (same pattern as [`crate::plan_guard::SerializationGuardQueryPlanner`],
//! which composes with it transparently) and wraps every produced plan
//! in [`CancelOnDropExec`]. Its stream arms a guard that, if dropped
//! before the stream ran to completion, fires `CancelJob` at the
//! scheduler on a background task.

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use async_trait::async_trait;
use ballista::datafusion::arrow::datatypes::SchemaRef;
use ballista::datafusion::arrow::record_batch::RecordBatch;
use ballista::datafusion::error::{DataFusionError, Result as DfResult};
use ballista::datafusion::execution::context::QueryPlanner;
use ballista::datafusion::execution::{SessionState, TaskContext};
use ballista::datafusion::logical_expr::LogicalPlan;
use ballista::datafusion::physical_plan::{
    DisplayAs, DisplayFormatType, ExecutionPlan, PlanProperties, RecordBatchStream,
    SendableRecordBatchStream,
};
use ballista_core::execution_plans::DistributedQueryExec;
use ballista_core::serde::protobuf::scheduler_grpc_client::SchedulerGrpcClient;
use ballista_core::serde::protobuf::{operator_metric, CancelJobParams, GetJobMetricsParams};
use datafusion_proto::protobuf::LogicalPlanNode;
use futures::Stream;

/// A [`QueryPlanner`] decorator that wraps every produced physical
/// plan in [`CancelOnDropExec`], so abandoning the result stream
/// cancels the underlying Ballista job.
#[derive(Debug)]
pub struct CancelOnDropQueryPlanner {
    inner: Arc<dyn QueryPlanner + Send + Sync>,
    scheduler_url: String,
}

impl CancelOnDropQueryPlanner {
    /// Wrap `inner` (the coordinator's `BallistaQueryPlanner`, possibly
    /// already decorated). `scheduler_url` is where `CancelJob` is sent.
    #[must_use]
    pub fn new(inner: Arc<dyn QueryPlanner + Send + Sync>, scheduler_url: String) -> Self {
        Self {
            inner,
            scheduler_url,
        }
    }
}

#[async_trait]
impl QueryPlanner for CancelOnDropQueryPlanner {
    async fn create_physical_plan(
        &self,
        logical_plan: &LogicalPlan,
        session_state: &SessionState,
    ) -> DfResult<Arc<dyn ExecutionPlan>> {
        let plan = self
            .inner
            .create_physical_plan(logical_plan, session_state)
            .await?;
        // Only distributed plans have a job to cancel. DDL / session
        // statements fall through the Ballista planner as ordinary
        // plans — leave them untouched.
        if plan
            .downcast_ref::<DistributedQueryExec<LogicalPlanNode>>()
            .is_none()
        {
            return Ok(plan);
        }
        Ok(Arc::new(CancelOnDropExec {
            properties: plan.properties().clone(),
            inner: plan,
            scheduler_url: self.scheduler_url.clone(),
        }))
    }
}

/// Transparent [`ExecutionPlan`] decorator over
/// [`DistributedQueryExec`] whose stream cancels the Ballista job if
/// dropped before completion.
#[derive(Debug)]
pub struct CancelOnDropExec {
    inner: Arc<dyn ExecutionPlan>,
    properties: Arc<PlanProperties>,
    scheduler_url: String,
}

impl DisplayAs for CancelOnDropExec {
    fn fmt_as(&self, t: DisplayFormatType, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        // Render as the inner plan: this wrapper is an execution-time
        // detail, not a plan shape users should see in EXPLAIN.
        self.inner.fmt_as(t, f)
    }
}

impl ExecutionPlan for CancelOnDropExec {
    // The trait fixes the `&str` return; the literal is naturally
    // 'static (same shape as upstream `DistributedQueryExec::name`).
    #[allow(clippy::unnecessary_literal_bound)]
    fn name(&self) -> &str {
        "CancelOnDropExec"
    }

    fn schema(&self) -> SchemaRef {
        self.inner.schema()
    }

    fn properties(&self) -> &Arc<PlanProperties> {
        &self.properties
    }

    fn children(&self) -> Vec<&Arc<dyn ExecutionPlan>> {
        vec![&self.inner]
    }

    fn with_new_children(
        self: Arc<Self>,
        children: Vec<Arc<dyn ExecutionPlan>>,
    ) -> DfResult<Arc<dyn ExecutionPlan>> {
        let inner = children
            .into_iter()
            .next()
            .unwrap_or_else(|| Arc::clone(&self.inner));
        Ok(Arc::new(Self {
            properties: inner.properties().clone(),
            inner,
            scheduler_url: self.scheduler_url.clone(),
        }))
    }

    fn execute(
        &self,
        partition: usize,
        context: Arc<TaskContext>,
    ) -> DfResult<SendableRecordBatchStream> {
        let inner_stream = self
            .inner
            .execute(partition, context)
            .map_err(remap_distributed_source_error)?;
        let schema = self.inner.schema();

        // Drive the inner stream from a spawned task and hand batches
        // to the consumer over a small channel. The task — not the
        // consumer — owns the stream, which closes the abandonment
        // race: Ballista submits the job inside the stream's first
        // poll, so a consumer that drops mid-submission would abort
        // the in-flight `ExecuteQuery` and the job id would never
        // become known (while the scheduler, which already received
        // the request, runs the job anyway). Owning the stream here
        // lets the task keep driving submission after abandonment
        // until the id lands, then fire `CancelJob`.
        //  distributed capture: snapshot the pushdown sink + run_id on
        // THIS (pgwire connection) task while they're in scope. The per-source
        // stats come back from the executors after the job finishes, on the
        // spawned task below where the task-local is gone — so we record them
        // through this snapshot. `None` when capture isn't active.
        let captured = dataglot_core::capture_pushdown_context();
        let (tx, rx) = tokio::sync::mpsc::channel::<DfResult<RecordBatch>>(2);
        let exec = Arc::clone(&self.inner);
        let scheduler_url = self.scheduler_url.clone();
        tokio::spawn(async move {
            use futures::StreamExt;
            let mut stream = inner_stream;
            let mut errored = false;
            // `tx.closed()` is the abandonment signal: a long-running
            // job can sit in `stream.next()` for minutes without a
            // single batch (e.g. one aggregate row at the very end),
            // so waiting for a failed `send` would never notice the
            // consumer is gone.
            let abandoned = loop {
                tokio::select! {
                    () = tx.closed() => break true,
                    item = stream.next() => match item {
                        Some(item) => {
                            // Re-surface the distributed-unsupported-source
                            // limitation cleanly; Ballista reports
                            // it on the stream's first poll as an Internal
                            // "failed to serialize logical plan" error.
                            let item = item.map_err(remap_distributed_source_error);
                            let terminal = item.is_err();
                            if tx.send(item).await.is_err() {
                                // Consumer dropped the receiver mid-query.
                                break true;
                            }
                            if terminal {
                                errored = true;
                                break false;
                            }
                        }
                        // Natural end — job completed; nothing to cancel.
                        None => break false,
                    },
                }
            };
            if abandoned {
                // Info, not debug: the cancel *outcome* below logs at info
                // (`cancelled abandoned ballista job`), so the trigger must
                // too — otherwise slot churn from cancellations is
                // uncorrelatable at default log level.
                tracing::info!("consumer abandoned distributed query; resolving job for cancel");
                cancel_abandoned_job(exec, stream, scheduler_url).await;
            } else if !errored {
                // Job completed successfully — pull the per-source pushdown
                // metrics the executors reported and record them for the
                // dashboard treeview. No-op unless capture is active.
                if let Some(captured) = captured {
                    fetch_and_record_pushdown_metrics(&exec, &scheduler_url, &captured).await;
                }
            }
        });

        Ok(Box::pin(ChannelBatchStream { schema, rx }))
    }

    fn metrics(&self) -> Option<ballista::datafusion::physical_plan::metrics::MetricsSet> {
        self.inner.metrics()
    }
}

/// Consumer-facing stream: batches forwarded from the driver task.
/// Dropping it closes the channel, which is how the driver learns the
/// consumer abandoned the query.
struct ChannelBatchStream {
    schema: SchemaRef,
    rx: tokio::sync::mpsc::Receiver<DfResult<RecordBatch>>,
}

impl Stream for ChannelBatchStream {
    type Item = DfResult<RecordBatch>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.rx.poll_recv(cx)
    }
}

impl RecordBatchStream for ChannelBatchStream {
    fn schema(&self) -> SchemaRef {
        Arc::clone(&self.schema)
    }
}

/// Fetch the executors' per-source pushdown metrics for the just-completed job
/// and record them through `captured` for the dashboard query-profile treeview
/// (, distributed capture — piece 3).
///
/// The executor-side [`PushdownMetricsExec`](dataglot_federation::PushdownMetricsExec)
/// emits counters named `pushdown.<catalog>.{rows,batches,ms}`; Ballista ships them
/// back inside `TaskStatus`, and the scheduler re-serves them via
/// `get_job_metrics`. We aggregate per catalog and record one
/// [`PushdownStat`](dataglot_core::PushdownStat) each. Best-effort: an
/// unresolved job id, an unreachable scheduler, or no such metrics is a debug
/// no-op — the query itself already succeeded. (Numeric-first: the connector
/// kind and pushed SQL don't ride the metric channel; those are a follow-up.)
async fn fetch_and_record_pushdown_metrics(
    exec: &Arc<dyn ExecutionPlan>,
    scheduler_url: &str,
    captured: &dataglot_core::CapturedPushdownContext,
) {
    let Some(job_id) = exec
        .downcast_ref::<DistributedQueryExec<LogicalPlanNode>>()
        .and_then(DistributedQueryExec::job_id)
    else {
        return;
    };
    let mut client = match SchedulerGrpcClient::connect(scheduler_url.to_string()).await {
        Ok(c) => c,
        Err(e) => {
            tracing::debug!(error = %e, "pushdown metrics: scheduler connect failed");
            return;
        }
    };
    let stages = match client
        .get_job_metrics(GetJobMetricsParams {
            job_id: job_id.to_string(),
        })
        .await
    {
        Ok(r) => r.into_inner().stages,
        Err(e) => {
            tracing::debug!(error = %e, "pushdown metrics: get_job_metrics failed");
            return;
        }
    };
    // Aggregate `pushdown.<catalog>.<field>` counters across every stage/operator
    // (a source scanned across partitions/stages reports several — sum them).
    let mut per_source: std::collections::HashMap<String, (u64, u64, u64)> =
        std::collections::HashMap::new();
    for stage in &stages {
        for op in &stage.operators {
            for m in &op.metrics {
                let Some(operator_metric::Metric::Count(nc)) = &m.metric else {
                    continue;
                };
                let Some(rest) = nc
                    .name
                    .strip_prefix(dataglot_federation::PUSHDOWN_METRIC_PREFIX)
                else {
                    continue;
                };
                let Some((catalog, field)) = rest.rsplit_once('.') else {
                    continue;
                };
                let entry = per_source.entry(catalog.to_string()).or_default();
                match field {
                    "rows" => entry.0 = entry.0.saturating_add(nc.value),
                    "batches" => entry.1 = entry.1.saturating_add(nc.value),
                    "ms" => entry.2 = entry.2.saturating_add(nc.value),
                    _ => {}
                }
            }
        }
    }
    for (catalog, (rows, batches, elapsed_ms)) in per_source {
        captured.record(dataglot_core::PushdownStat {
            source: catalog,
            kind: String::new(),
            sql: String::new(),
            rows,
            batches,
            elapsed_ms,
            outcome: dataglot_core::PushdownOutcome::Completed,
        });
    }
}

/// The consumer abandoned the query: learn the job id (driving the
/// still-owned stream until the in-flight submission response lands,
/// if needed), then fire `CancelJob` at the scheduler.
async fn cancel_abandoned_job(
    exec: Arc<dyn ExecutionPlan>,
    mut stream: SendableRecordBatchStream,
    scheduler_url: String,
) {
    use futures::StreamExt;

    let job_id_of = |exec: &Arc<dyn ExecutionPlan>| {
        exec.downcast_ref::<DistributedQueryExec<LogicalPlanNode>>()
            .and_then(DistributedQueryExec::job_id)
    };

    // Drive submission to completion if the id isn't known yet. Each
    // stream poll advances the in-flight `ExecuteQuery`; the 100ms tick
    // re-checks the shared id slot while the (long-running) job blocks
    // the stream in its status-poll loop.
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
    let job_id = loop {
        if let Some(id) = job_id_of(&exec) {
            break Some(id);
        }
        if tokio::time::Instant::now() >= deadline {
            break None;
        }
        match tokio::time::timeout(std::time::Duration::from_millis(100), stream.next()).await {
            // Stream ended by itself — job terminal, nothing to cancel.
            Ok(None) => return,
            // Submission errored before an id existed — no job to cancel.
            // Trace the error so an abandoned-then-failed query isn't a
            // total blank; if a job id *did* land, this arm's
            // guard fails and the loop catches it on the next turn.
            Ok(Some(Err(err))) if job_id_of(&exec).is_none() => {
                tracing::debug!(
                    error = %err,
                    "abandoned distributed query errored before a job id existed; nothing to cancel"
                );
                return;
            }
            _ => {}
        }
    };
    drop(stream);

    let Some(job_id) = job_id else {
        tracing::warn!(
            "abandoned distributed query never yielded a job id within 30s; \
             cannot cancel (job may be orphaned on the scheduler)"
        );
        return;
    };

    match SchedulerGrpcClient::connect(scheduler_url).await {
        Ok(mut client) => {
            let result = client
                .cancel_job(CancelJobParams {
                    job_id: job_id.to_string(),
                })
                .await;
            match result {
                Ok(_) => tracing::info!(
                    job_id = %job_id,
                    "cancelled abandoned ballista job (client stopped consuming)"
                ),
                Err(e) => tracing::warn!(
                    job_id = %job_id,
                    error = %e,
                    "failed to cancel abandoned ballista job"
                ),
            }
        }
        Err(e) => tracing::warn!(
            job_id = %job_id,
            error = %e,
            "could not reach scheduler to cancel abandoned job"
        ),
    }
}

/// Ballista's plan-serialization path wraps dataglot's intentional
/// "source not supported in distributed mode" limitation — a clean
/// [`DataFusionError::NotImplemented`] from [`crate::codec`] — in a
/// `DataFusionError::Internal("failed to serialize logical plan: …")`.
/// `Internal`'s `Display` then appends a "likely a bug in DataFusion's
/// code … file a bug report" tail, so the limitation reaches the client
/// looking like an upstream crash and points them at the wrong issue
/// tracker.
///
/// Detect that shape by its stable sentinel (present in every codec
/// variant of the limitation and surviving the `Internal` re-wrap) and
/// re-surface a clean `NotImplemented` — whose `Display` is just
/// "This feature is not implemented: …", no bug-report tail — keeping
/// the actionable guidance. Any other error passes through unchanged.
fn remap_distributed_source_error(e: DataFusionError) -> DataFusionError {
    if e.to_string().contains("not available in distributed mode") {
        return DataFusionError::NotImplemented(
            crate::codec::DISTRIBUTED_SOURCE_UNSUPPORTED.to_string(),
        );
    }
    e
}

#[cfg(test)]
mod tests {
    use super::*;

    use ballista::datafusion::arrow::array::Int32Array;
    use ballista::datafusion::arrow::datatypes::{DataType, Field, Schema};
    use ballista::datafusion::common::DFSchema;
    use ballista::datafusion::execution::TaskContext;
    use ballista::datafusion::logical_expr::EmptyRelation;
    use ballista::datafusion::physical_expr::EquivalenceProperties;
    use ballista::datafusion::physical_plan::common::collect;
    use ballista::datafusion::physical_plan::execution_plan::{Boundedness, EmissionType};
    use ballista::datafusion::physical_plan::{displayable, Partitioning};
    use ballista::datafusion::prelude::SessionContext;

    /// A leaf [`ExecutionPlan`] that is *not* a [`DistributedQueryExec`],
    /// standing in for the ordinary (DDL / session-statement) plans the
    /// decorator must leave untouched, and — when it yields batches — for
    /// a completed distributed plan the consumer drains normally.
    #[derive(Debug)]
    struct StubStreamExec {
        properties: Arc<PlanProperties>,
        batches: Vec<RecordBatch>,
    }

    impl StubStreamExec {
        fn new(schema: SchemaRef, batches: Vec<RecordBatch>) -> Self {
            let properties = Arc::new(PlanProperties::new(
                EquivalenceProperties::new(schema),
                Partitioning::UnknownPartitioning(1),
                EmissionType::Incremental,
                Boundedness::Bounded,
            ));
            Self {
                properties,
                batches,
            }
        }
    }

    impl DisplayAs for StubStreamExec {
        fn fmt_as(&self, _t: DisplayFormatType, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            write!(f, "StubStreamExec")
        }
    }

    impl ExecutionPlan for StubStreamExec {
        #[allow(clippy::unnecessary_literal_bound)]
        fn name(&self) -> &str {
            "StubStreamExec"
        }
        fn schema(&self) -> SchemaRef {
            Arc::clone(self.properties.eq_properties.schema())
        }
        fn properties(&self) -> &Arc<PlanProperties> {
            &self.properties
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
            use ballista::datafusion::physical_plan::stream::RecordBatchStreamAdapter;
            let schema = self.schema();
            let batches: Vec<DfResult<RecordBatch>> =
                self.batches.iter().cloned().map(Ok).collect();
            Ok(Box::pin(RecordBatchStreamAdapter::new(
                schema,
                futures::stream::iter(batches),
            )))
        }
    }

    /// A [`QueryPlanner`] that always returns the same stub plan, letting
    /// us drive `CancelOnDropQueryPlanner` without a real Ballista planner.
    #[derive(Debug)]
    struct StubPlanner {
        plan: Arc<dyn ExecutionPlan>,
    }

    #[async_trait]
    impl QueryPlanner for StubPlanner {
        async fn create_physical_plan(
            &self,
            _logical_plan: &LogicalPlan,
            _session_state: &SessionState,
        ) -> DfResult<Arc<dyn ExecutionPlan>> {
            Ok(Arc::clone(&self.plan))
        }
    }

    fn schema() -> SchemaRef {
        Arc::new(Schema::new(vec![Field::new("a", DataType::Int32, false)]))
    }

    fn batch(vals: Vec<i32>) -> RecordBatch {
        RecordBatch::try_new(schema(), vec![Arc::new(Int32Array::from(vals))]).expect("batch")
    }

    fn trivial_logical_plan() -> LogicalPlan {
        LogicalPlan::EmptyRelation(EmptyRelation {
            produce_one_row: false,
            schema: Arc::new(DFSchema::empty()),
        })
    }

    /// The load-bearing safety property: only `DistributedQueryExec`
    /// plans have a job to cancel, so DDL / session statements (any
    /// non-distributed plan) must pass through the planner **unwrapped**.
    /// If the downcast guard (`cancel_on_drop.rs:82-88`) regressed, every
    /// `SET`/`CREATE` would get a spurious `CancelOnDropExec` around it.
    #[tokio::test]
    async fn leaves_non_distributed_plans_unwrapped() {
        let inner = Arc::new(StubStreamExec::new(schema(), vec![])) as Arc<dyn ExecutionPlan>;
        let planner = CancelOnDropQueryPlanner::new(
            Arc::new(StubPlanner {
                plan: Arc::clone(&inner),
            }),
            "df://scheduler:50050".to_string(),
        );
        let state = SessionContext::new().state();
        let out = planner
            .create_physical_plan(&trivial_logical_plan(), &state)
            .await
            .expect("plan");

        assert!(
            out.downcast_ref::<CancelOnDropExec>().is_none(),
            "a non-distributed plan must not be wrapped in CancelOnDropExec"
        );
        assert!(
            out.downcast_ref::<StubStreamExec>().is_some(),
            "the inner plan must be returned untouched"
        );
    }

    /// The wrapper is an execution-time detail, not a plan shape users
    /// should see: `EXPLAIN` must render the inner node, never
    /// `CancelOnDropExec` (`cancel_on_drop.rs:107-113`). A regression here
    /// would add a spurious node to every distributed plan's EXPLAIN.
    #[test]
    fn display_renders_as_inner_not_the_wrapper() {
        let inner = Arc::new(StubStreamExec::new(schema(), vec![]));
        let exec = CancelOnDropExec {
            properties: inner.properties().clone(),
            inner: Arc::clone(&inner) as Arc<dyn ExecutionPlan>,
            scheduler_url: "df://scheduler:50050".to_string(),
        };
        let rendered = displayable(&exec).one_line().to_string();
        assert!(
            rendered.contains("StubStreamExec"),
            "EXPLAIN should render the inner plan, got: {rendered}"
        );
        assert!(
            !rendered.contains("CancelOnDropExec"),
            "the cancel-on-drop wrapper must be invisible in EXPLAIN, got: {rendered}"
        );
    }

    /// The decorator delegates schema/children to its inner plan, reports
    /// its own `name()`, and rebuilds cleanly under `with_new_children`.
    #[test]
    fn delegates_trait_methods_to_inner() {
        let inner = Arc::new(StubStreamExec::new(schema(), vec![]));
        let exec = Arc::new(CancelOnDropExec {
            properties: inner.properties().clone(),
            inner: Arc::clone(&inner) as Arc<dyn ExecutionPlan>,
            scheduler_url: "df://scheduler:50050".to_string(),
        });

        assert_eq!(exec.name(), "CancelOnDropExec");
        assert_eq!(exec.schema().fields().len(), 1);
        assert_eq!(exec.children().len(), 1, "the inner plan is the sole child");

        // Rebuild with a fresh inner and confirm the swap took.
        let new_inner = Arc::new(StubStreamExec::new(schema(), vec![])) as Arc<dyn ExecutionPlan>;
        let rebuilt = exec
            .with_new_children(vec![Arc::clone(&new_inner)])
            .expect("rebuild");
        let rebuilt = rebuilt
            .downcast_ref::<CancelOnDropExec>()
            .expect("rebuild stays a CancelOnDropExec");
        assert!(
            Arc::ptr_eq(&rebuilt.inner, &new_inner),
            "with_new_children must adopt the supplied child"
        );
    }

    /// Transparency for the normal (fully-consumed) path: every batch the
    /// inner plan produces reaches the consumer, in order, unchanged. This
    /// exercises the spawned driver task, the mpsc forwarding, and the
    /// natural-end branch (`abandoned = false`, no cancel fired).
    #[tokio::test]
    async fn forwards_all_inner_batches_when_fully_consumed() {
        let inner = Arc::new(StubStreamExec::new(
            schema(),
            vec![batch(vec![1, 2]), batch(vec![3])],
        ));
        let exec = CancelOnDropExec {
            properties: inner.properties().clone(),
            inner: Arc::clone(&inner) as Arc<dyn ExecutionPlan>,
            scheduler_url: "df://scheduler:50050".to_string(),
        };
        let stream = exec
            .execute(0, Arc::new(TaskContext::default()))
            .expect("execute");
        let out = collect(stream).await.expect("collect");
        let total: usize = out.iter().map(RecordBatch::num_rows).sum();
        assert_eq!(out.len(), 2, "both inner batches must be forwarded");
        assert_eq!(total, 3, "all rows must survive the decorator");
    }

    ///: the distributed-unsupported-source limitation, after
    /// Ballista re-wraps it in an `Internal("failed to serialize logical
    /// plan: …")`, must reach the client as a clean `NotImplemented`
    /// with the actionable guidance and WITHOUT the "bug in DataFusion —
    /// file a report" tail that `Internal`'s Display appends.
    #[test]
    fn remaps_wrapped_distributed_limitation_to_clean_message() {
        // Reproduce the exact shape Ballista produces on the wire.
        let inner = DataFusionError::NotImplemented(
            crate::codec::DISTRIBUTED_SOURCE_UNSUPPORTED.to_string(),
        );
        let wrapped =
            DataFusionError::Internal(format!("failed to serialize logical plan: {inner:?}"));
        // Sanity: the raw wrapped error carries the misleading tail.
        assert!(wrapped.to_string().contains("bug in DataFusion"));

        let remapped = remap_distributed_source_error(wrapped);
        assert!(
            matches!(remapped, DataFusionError::NotImplemented(_)),
            "should re-surface as NotImplemented, got {remapped:?}"
        );
        let msg = remapped.to_string();
        assert!(
            msg.contains("single-node"),
            "actionable guidance must survive: {msg}"
        );
        assert!(
            !msg.contains("bug in DataFusion") && !msg.contains("issue tracker"),
            "the DataFusion-bug boilerplate must be gone: {msg}"
        );
    }

    /// Unrelated errors pass through untouched — the remap must not
    /// swallow or rewrite genuine failures.
    #[test]
    fn passes_through_unrelated_errors() {
        let e = DataFusionError::Internal("some other internal failure".to_string());
        let out = remap_distributed_source_error(e);
        assert!(matches!(out, DataFusionError::Internal(_)));
        assert!(out.to_string().contains("some other internal failure"));
    }

    // --- drop → abandonment path + in-stream remap ----------------

    use std::sync::atomic::{AtomicBool, Ordering};

    fn plan_props() -> Arc<PlanProperties> {
        Arc::new(PlanProperties::new(
            EquivalenceProperties::new(schema()),
            Partitioning::UnknownPartitioning(1),
            EmissionType::Incremental,
            Boundedness::Bounded,
        ))
    }

    /// A leaf plan whose stream blocks (`Pending`) on its first poll, then
    /// ends (`None`). Lets a test park the driver in its select loop, drop the
    /// consumer to trip the `tx.closed()` abandonment branch, and observe that
    /// the driver keeps driving the *owned* stream afterwards (via
    /// `cancel_abandoned_job`) — `ended` flips only when that drains the
    /// stream, since the select loop stops polling once abandoned.
    #[derive(Debug)]
    struct AbandonProbeExec {
        properties: Arc<PlanProperties>,
        ended: Arc<AtomicBool>,
    }
    impl DisplayAs for AbandonProbeExec {
        fn fmt_as(&self, _t: DisplayFormatType, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            write!(f, "AbandonProbeExec")
        }
    }
    impl ExecutionPlan for AbandonProbeExec {
        #[allow(clippy::unnecessary_literal_bound)]
        fn name(&self) -> &str {
            "AbandonProbeExec"
        }
        fn schema(&self) -> SchemaRef {
            Arc::clone(self.properties.eq_properties.schema())
        }
        fn properties(&self) -> &Arc<PlanProperties> {
            &self.properties
        }
        fn children(&self) -> Vec<&Arc<dyn ExecutionPlan>> {
            vec![]
        }
        fn with_new_children(
            self: Arc<Self>,
            _c: Vec<Arc<dyn ExecutionPlan>>,
        ) -> DfResult<Arc<dyn ExecutionPlan>> {
            Ok(self)
        }
        fn execute(&self, _p: usize, _c: Arc<TaskContext>) -> DfResult<SendableRecordBatchStream> {
            Ok(Box::pin(AbandonProbeStream {
                schema: self.schema(),
                polls: 0,
                ended: Arc::clone(&self.ended),
            }))
        }
    }
    struct AbandonProbeStream {
        schema: SchemaRef,
        polls: usize,
        ended: Arc<AtomicBool>,
    }
    impl Stream for AbandonProbeStream {
        type Item = DfResult<RecordBatch>;
        fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            let this = self.get_mut();
            if this.polls == 0 {
                // Park: the wake comes from `tx.closed()` on consumer drop,
                // not from us — we never register a waker.
                this.polls += 1;
                Poll::Pending
            } else {
                this.ended.store(true, Ordering::SeqCst);
                Poll::Ready(None)
            }
        }
    }
    impl RecordBatchStream for AbandonProbeStream {
        fn schema(&self) -> SchemaRef {
            Arc::clone(&self.schema)
        }
    }

    /// The core promise: dropping the consumer before it reads a batch trips
    /// the `tx.closed()` abandonment branch, and the driver keeps driving the
    /// owned stream via `cancel_abandoned_job` — which, for a
    /// non-`DistributedQueryExec` (no job id), exits cleanly when the stream
    /// ends. Proves drop-handling runs end-to-end with no live scheduler and
    /// no 30s job-id deadline hang.
    #[tokio::test]
    async fn dropping_consumer_drives_abandonment_path_to_completion() {
        let ended = Arc::new(AtomicBool::new(false));
        let inner = Arc::new(AbandonProbeExec {
            properties: plan_props(),
            ended: Arc::clone(&ended),
        });
        let exec = CancelOnDropExec {
            properties: inner.properties().clone(),
            inner: Arc::clone(&inner) as Arc<dyn ExecutionPlan>,
            scheduler_url: "df://unreachable:50050".to_string(),
        };
        let consumer = exec
            .execute(0, Arc::new(TaskContext::default()))
            .expect("execute");
        // Abandon immediately — before reading a single batch.
        drop(consumer);
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while !ended.load(Ordering::SeqCst) {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("abandonment path must drive the owned stream to completion (no 30s hang)");
    }

    /// A leaf plan whose stream yields a single error of the exact shape
    /// Ballista emits for the distributed-unsupported-source limitation.
    #[derive(Debug)]
    struct DistUnsupportedExec {
        properties: Arc<PlanProperties>,
    }
    impl DisplayAs for DistUnsupportedExec {
        fn fmt_as(&self, _t: DisplayFormatType, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            write!(f, "DistUnsupportedExec")
        }
    }
    impl ExecutionPlan for DistUnsupportedExec {
        #[allow(clippy::unnecessary_literal_bound)]
        fn name(&self) -> &str {
            "DistUnsupportedExec"
        }
        fn schema(&self) -> SchemaRef {
            Arc::clone(self.properties.eq_properties.schema())
        }
        fn properties(&self) -> &Arc<PlanProperties> {
            &self.properties
        }
        fn children(&self) -> Vec<&Arc<dyn ExecutionPlan>> {
            vec![]
        }
        fn with_new_children(
            self: Arc<Self>,
            _c: Vec<Arc<dyn ExecutionPlan>>,
        ) -> DfResult<Arc<dyn ExecutionPlan>> {
            Ok(self)
        }
        fn execute(&self, _p: usize, _c: Arc<TaskContext>) -> DfResult<SendableRecordBatchStream> {
            use ballista::datafusion::physical_plan::stream::RecordBatchStreamAdapter;
            let inner = DataFusionError::NotImplemented(
                crate::codec::DISTRIBUTED_SOURCE_UNSUPPORTED.to_string(),
            );
            let wrapped =
                DataFusionError::Internal(format!("failed to serialize logical plan: {inner:?}"));
            let items: Vec<DfResult<RecordBatch>> = vec![Err(wrapped)];
            Ok(Box::pin(RecordBatchStreamAdapter::new(
                self.schema(),
                futures::stream::iter(items),
            )))
        }
    }

    /// The distributed-unsupported error surfaces mid-stream (not from
    /// `execute()` itself); the driver must remap it to a clean
    /// `NotImplemented` before the consumer sees it (in `execute()`'s driver).
    #[tokio::test]
    async fn remaps_in_stream_distributed_error_before_consumer() {
        let inner = Arc::new(DistUnsupportedExec {
            properties: plan_props(),
        });
        let exec = CancelOnDropExec {
            properties: inner.properties().clone(),
            inner: Arc::clone(&inner) as Arc<dyn ExecutionPlan>,
            scheduler_url: "df://scheduler:50050".to_string(),
        };
        let stream = exec
            .execute(0, Arc::new(TaskContext::default()))
            .expect("execute");
        let err = collect(stream)
            .await
            .expect_err("the stream yields the distributed-unsupported error");
        assert!(
            matches!(err, DataFusionError::NotImplemented(_)),
            "in-stream error must be remapped to NotImplemented, got {err:?}"
        );
        assert!(!err.to_string().contains("bug in DataFusion"));
    }

    /// `with_new_children(vec![])` keeps the existing inner (the
    /// `unwrap_or_else` clone in `with_new_children`).
    #[test]
    fn with_new_children_empty_keeps_existing_inner() {
        let inner = Arc::new(StubStreamExec::new(schema(), vec![])) as Arc<dyn ExecutionPlan>;
        let exec = Arc::new(CancelOnDropExec {
            properties: inner.properties().clone(),
            inner: Arc::clone(&inner),
            scheduler_url: "df://scheduler:50050".to_string(),
        });
        let rebuilt = exec
            .with_new_children(vec![])
            .expect("rebuild with no children");
        let rebuilt = rebuilt
            .downcast_ref::<CancelOnDropExec>()
            .expect("still a CancelOnDropExec");
        assert!(
            Arc::ptr_eq(&rebuilt.inner, &inner),
            "empty children must keep the existing inner"
        );
    }
}

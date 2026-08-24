//! Structured tracing for federated query pushdown.
//!
//! Every SQL connector renders a sub-plan to dialect SQL and ships it to a
//! remote source (Snowflake, Postgres, MySQL, Oracle, an ADBC driver). Before
//! this module that send was observable only at `debug!`, with no source
//! attribution on most connectors and no timing or row counts anywhere —
//! "which query went to Snowflake, and was it slow?" could not be answered
//! from production logs.
//!
//! [`instrument_pushdown`] wraps the connector's result stream so each
//! pushdown emits a `debug!` START event (carrying the SQL) followed by
//! exactly one terminal event as the stream is consumed:
//! - `info!` COMPLETE — clean end, with `rows` / `batches` / `elapsed_ms`,
//! - `warn!` FAILED — the remote returned an error,
//! - `info!` PARTIAL — the stream was dropped before exhaustion (e.g. a
//!   `LIMIT` satisfied by the local plan, or a cancelled query upstream).
//!
//! The START event carries the SQL and so stays at `debug!` — filter literals
//! are user data (CLAUDE.md rule 12). The terminal events never repeat the
//! SQL, so they are safe to leave on at the default `dataglot=info` filter.
//! All events use the [`PUSHDOWN_TARGET`] tracing target, mirroring the
//! `dataglot::audit` convention so a subscriber can route pushdown telemetry
//! independently.
//!
//! Alongside the tracing event, each terminal state also reports a structured
//! [`dataglot_core::PushdownStat`] via [`dataglot_core::record_pushdown`] — a
//! no-op unless the host (the server) has installed a sink and stamped a
//! `RunId`. That is the correlation feed for the per-query dashboard view

use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Instant;

use datafusion::arrow::datatypes::SchemaRef;
use datafusion::arrow::record_batch::RecordBatch;
use datafusion::error::Result as DfResult;
use datafusion::execution::{RecordBatchStream, SendableRecordBatchStream};
use dataglot_core::{record_pushdown, PushdownOutcome, PushdownStat};
use futures::Stream;
use tracing::{debug, info, warn};

/// Tracing target for federation pushdown events.
///
/// Mirrors the `dataglot::audit` target convention so a subscriber can route
/// pushdown telemetry (start / complete / failed) independently of the
/// default `dataglot` target.
pub const PUSHDOWN_TARGET: &str = "dataglot::federation";

/// Wrap a pushed-down query's result stream with structured tracing.
///
/// The connectors hand us a *lazy* stream (`stream::once(fut)`), so START
/// emission and the timer both fire on the **first `poll_next`** — the moment
/// the remote query actually begins — not at construction time. A stream that
/// DataFusion builds but never polls (or drops before polling) emits nothing,
/// and `elapsed_ms` measures remote execution rather than scheduling latency.
///
/// After the first poll, exactly one terminal event is emitted as the stream
/// is consumed: `info!` on clean completion, `warn!` on stream error, or
/// `info!` PARTIAL if a polled stream is dropped before exhaustion.
///
/// `source` is the catalog name; `kind` is the connector type (`"snowflake"`,
/// `"postgres"`, `"mysql"`, `"oracle"`, `"adbc"`). The START event carries the
/// SQL and stays at `debug!` (filter literals are user data, rule 12); the
/// COMPLETE and FAILED events do not repeat the SQL, so both are safe at the
/// default `dataglot=info` filter.
#[must_use]
pub fn instrument_pushdown(
    source: &str,
    kind: &'static str,
    query: &str,
    stream: SendableRecordBatchStream,
) -> SendableRecordBatchStream {
    Box::pin(InstrumentedPushdown {
        source: source.to_string(),
        kind,
        query: query.to_string(),
        inner: stream,
        started: None,
        rows: 0,
        batches: 0,
        terminated: false,
    })
}

/// A `RecordBatchStream` decorator that counts rows/batches, times the
/// remote execution, and emits a single terminal tracing event.
struct InstrumentedPushdown {
    source: String,
    kind: &'static str,
    query: String,
    inner: SendableRecordBatchStream,
    /// `None` until the first `poll_next`; `Some` once the remote query has
    /// started. Doubles as the "was this stream ever polled?" flag so the
    /// `Drop` impl stays silent for a never-executed stream.
    started: Option<Instant>,
    rows: u64,
    batches: u64,
    /// Set once a terminal event (complete/failed) has been emitted, so the
    /// `Drop` impl doesn't emit a second (PARTIAL) event for the same stream.
    terminated: bool,
}

impl InstrumentedPushdown {
    /// Report this pushdown's terminal stats to the host's sink (a no-op
    /// unless one is installed and a `RunId` is stamped). Called alongside the
    /// terminal tracing event so tracing and the dashboard feed stay in sync.
    ///
    /// The task-local read only sees a `RunId` when this runs on the pgwire
    /// connection task. DataFusion's parallel execution spawns the scan onto
    /// partition tasks that don't inherit it, so capture requires
    /// single-partition execution — which `capture_query_sources` pins for
    /// exactly this reason.
    fn record_stat(&self, outcome: PushdownOutcome) {
        record_pushdown(PushdownStat {
            source: self.source.clone(),
            kind: self.kind.to_string(),
            sql: self.query.clone(),
            rows: self.rows,
            batches: self.batches,
            elapsed_ms: elapsed_ms(self.started),
            outcome,
        });
    }
}

impl Stream for InstrumentedPushdown {
    type Item = DfResult<RecordBatch>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.as_mut().get_mut();
        if this.started.is_none() {
            // First poll — the remote query starts now. Emit START and begin
            // the timer here so a never-polled stream stays silent and the
            // elapsed time reflects remote execution, not scheduling latency.
            this.started = Some(Instant::now());
            debug!(
                target: PUSHDOWN_TARGET,
                source = %this.source,
                kind = this.kind,
                query = %this.query,
                "federation pushdown \u{2192} executing",
            );
        }
        match this.inner.as_mut().poll_next(cx) {
            Poll::Ready(Some(Ok(batch))) => {
                this.rows += batch.num_rows() as u64;
                this.batches += 1;
                Poll::Ready(Some(Ok(batch)))
            }
            Poll::Ready(Some(Err(err))) => {
                if !this.terminated {
                    this.terminated = true;
                    warn!(
                        target: PUSHDOWN_TARGET,
                        source = %this.source,
                        kind = this.kind,
                        rows = this.rows,
                        batches = this.batches,
                        elapsed_ms = elapsed_ms(this.started),
                        error = %err,
                        "federation pushdown \u{2717} failed",
                    );
                    this.record_stat(PushdownOutcome::Failed);
                }
                Poll::Ready(Some(Err(err)))
            }
            Poll::Ready(None) => {
                if !this.terminated {
                    this.terminated = true;
                    info!(
                        target: PUSHDOWN_TARGET,
                        source = %this.source,
                        kind = this.kind,
                        rows = this.rows,
                        batches = this.batches,
                        elapsed_ms = elapsed_ms(this.started),
                        "federation pushdown \u{2713} completed",
                    );
                    this.record_stat(PushdownOutcome::Completed);
                }
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl RecordBatchStream for InstrumentedPushdown {
    fn schema(&self) -> SchemaRef {
        self.inner.schema()
    }
}

impl Drop for InstrumentedPushdown {
    fn drop(&mut self) {
        // Only report a PARTIAL for a stream that actually started (was
        // polled at least once) but never reached a terminal event. A stream
        // DataFusion built but never polled has `started == None` and stays
        // silent — no START, no PARTIAL.
        if self.started.is_some() && !self.terminated {
            // The stream was dropped before it ran dry — typically a `LIMIT`
            // satisfied by the local plan, or a cancelled/failed query
            // upstream. Record what was consumed so the pushdown still shows
            // in the timeline rather than vanishing.
            info!(
                target: PUSHDOWN_TARGET,
                source = %self.source,
                kind = self.kind,
                rows = self.rows,
                batches = self.batches,
                elapsed_ms = elapsed_ms(self.started),
                "federation pushdown \u{2913} stream dropped before exhaustion (partial)",
            );
            self.record_stat(PushdownOutcome::Partial);
        }
    }
}

/// Milliseconds elapsed since `started`, saturating at `u64::MAX`. Returns 0
/// if the timer never started (the stream was never polled) — a defensive
/// case, since every terminal event is reached through a poll.
fn elapsed_ms(started: Option<Instant>) -> u64 {
    started.map_or(0, |s| {
        u64::try_from(s.elapsed().as_millis()).unwrap_or(u64::MAX)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use datafusion::arrow::array::Int32Array;
    use datafusion::arrow::datatypes::{DataType, Field, Schema};
    use datafusion::error::DataFusionError;
    use datafusion::physical_plan::stream::RecordBatchStreamAdapter;
    use futures::{stream, StreamExt};
    use std::sync::Arc;

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

    /// Build a `SendableRecordBatchStream` from a fixed list of results.
    fn make_stream(
        schema: &SchemaRef,
        items: Vec<DfResult<RecordBatch>>,
    ) -> SendableRecordBatchStream {
        Box::pin(RecordBatchStreamAdapter::new(
            Arc::clone(schema),
            stream::iter(items),
        ))
    }

    #[tokio::test]
    async fn counts_rows_and_batches_and_preserves_schema() {
        let schema = test_schema();
        let inner = make_stream(
            &schema,
            vec![Ok(batch(&schema, &[1, 2, 3])), Ok(batch(&schema, &[4, 5]))],
        );

        let mut wrapped = instrument_pushdown("cat", "postgres", "SELECT n FROM t", inner);
        // Schema is forwarded unchanged so the decorator is transparent to
        // DataFusion's `RecordBatchStream` contract.
        assert_eq!(wrapped.schema(), schema);

        let mut total = 0;
        while let Some(item) = wrapped.next().await {
            total += item.expect("batch ok").num_rows();
        }
        // Two batches, five rows, drained to completion without panicking —
        // exercises the COMPLETE terminal path (row/batch tallies are
        // reported via the `info!` event, verified structurally here).
        assert_eq!(total, 5);
    }

    #[tokio::test]
    async fn passes_through_and_terminates_on_error() {
        let schema = test_schema();
        let inner = make_stream(
            &schema,
            vec![
                Ok(batch(&schema, &[1])),
                Err(DataFusionError::External(
                    "remote blew up".to_string().into(),
                )),
            ],
        );

        let mut wrapped = instrument_pushdown("cat", "snowflake", "SELECT 1", inner);

        let first = wrapped.next().await.expect("first item");
        assert_eq!(first.expect("ok batch").num_rows(), 1);

        let second = wrapped.next().await.expect("second item");
        assert!(second.is_err(), "error is passed through unchanged");
    }

    #[tokio::test]
    async fn empty_stream_completes_cleanly() {
        let schema = test_schema();
        let inner = make_stream(&schema, vec![]);
        let mut wrapped = instrument_pushdown("cat", "mysql", "SELECT 1 WHERE false", inner);
        assert!(wrapped.next().await.is_none());
    }

    #[tokio::test]
    async fn reports_stats_to_installed_sink_when_run_id_stamped() {
        use dataglot_core::{set_pushdown_run_id, with_pushdown_sink, PushdownSink, RunId};
        use std::sync::Mutex;

        #[derive(Default)]
        struct Collector(Mutex<Vec<PushdownStat>>);
        impl PushdownSink for Collector {
            fn record(&self, _run_id: RunId, stat: PushdownStat) {
                self.0.lock().expect("lock").push(stat);
            }
        }

        let collector = Arc::new(Collector::default());
        let sink: Arc<dyn PushdownSink> = collector.clone();
        with_pushdown_sink(sink, async {
            set_pushdown_run_id(RunId::new());
            let schema = test_schema();
            let inner = make_stream(
                &schema,
                vec![Ok(batch(&schema, &[1, 2, 3])), Ok(batch(&schema, &[4, 5]))],
            );
            let mut wrapped =
                instrument_pushdown("wh_snowflake", "snowflake", "SELECT n FROM t", inner);
            while wrapped.next().await.is_some() {}
        })
        .await;

        let captured = collector.0.lock().expect("lock").clone();
        assert_eq!(captured.len(), 1, "one terminal stat per drained pushdown");
        let s = &captured[0];
        assert_eq!(s.source, "wh_snowflake");
        assert_eq!(s.kind, "snowflake");
        assert_eq!(s.rows, 5);
        assert_eq!(s.batches, 2);
        assert_eq!(s.outcome, PushdownOutcome::Completed);
    }

    #[tokio::test]
    async fn never_polled_stream_stays_silent_on_drop() {
        // A stream DataFusion constructs but never polls must not emit START
        // or PARTIAL — the timer never starts and `Drop` sees `started ==
        // None`. We can't assert on log output without a subscriber, but the
        // `started`-guarded `Drop` path must not panic.
        let schema = test_schema();
        let inner = make_stream(&schema, vec![Ok(batch(&schema, &[1]))]);
        let wrapped = instrument_pushdown("cat", "adbc", "SELECT n FROM t", inner);
        drop(wrapped);
    }

    #[tokio::test]
    async fn dropping_early_does_not_panic() {
        // Consuming one batch then dropping the stream exercises the
        // `Drop` PARTIAL path (a `LIMIT` satisfied upstream drops the
        // source stream before exhaustion).
        let schema = test_schema();
        let inner = make_stream(
            &schema,
            vec![Ok(batch(&schema, &[1])), Ok(batch(&schema, &[2]))],
        );
        let mut wrapped = instrument_pushdown("cat", "oracle", "SELECT n FROM t", inner);
        let _ = wrapped.next().await;
        drop(wrapped);
    }
}

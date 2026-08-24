//! Per-query federation pushdown stats — the correlation layer that ties a
//! remote pushdown (the dialect SQL sent to Snowflake/Postgres/…) back to the
//! pgwire [`RunId`] that issued it, so the operational dashboard can show a
//! per-source breakdown of a single query (, slice 2).
//!
//! `dataglot-federation`'s `instrument_pushdown` already emits a *tracing*
//! event per pushdown; with this module it *also* reports a structured
//! [`PushdownStat`] to a [`PushdownSink`] the server installs. Correlation uses
//! a tokio task-local, mirroring `dataglot-pgwire`'s `session_org`: the server
//! wraps each connection's future in [`with_pushdown_sink`], the pgwire handler
//! stamps the active [`RunId`] per query via [`set_pushdown_run_id`], and the
//! connector calls [`record_pushdown`] from within that same task.
//!
//! # Same-task, best-effort
//!
//! Task-locals migrate with a future across worker threads but do **not** cross
//! `tokio::spawn`. A connection's queries are drained inline in the connection
//! task, so a single-source pushdown (the common Snowflake debugging case) is
//! captured. A pushdown polled on a tokio-spawned sub-task — e.g. the parallel
//! scans of a cross-source join under a repartition — does not inherit the
//! task-local and is not captured. This is a documented v1 limitation, not a
//! correctness issue: [`record_pushdown`] is a no-op whenever no scope or no
//! `run_id` is active, so connectors call it unconditionally.

use std::cell::RefCell;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::lineage::RunId;

/// How a pushdown's result stream ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PushdownOutcome {
    /// The stream drained to completion.
    Completed,
    /// The remote returned an error mid-stream.
    Failed,
    /// The stream was dropped before exhaustion (e.g. a `LIMIT` satisfied by
    /// the local plan, or a cancelled query upstream).
    Partial,
}

/// One remote pushdown's execution stats, reported when its result stream
/// reaches a terminal state.
///
/// `sql` is the dialect-rendered statement sent to the source; like filter
/// literals it is user data (CLAUDE.md rule 12), so the server stores it under
/// the same visibility as the query's own SQL (both surface only on the
/// operator-facing query registry, never in logs above `debug`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushdownStat {
    /// Catalog (source) name the sub-query was pushed to.
    pub source: String,
    /// Connector kind: `"snowflake"`, `"postgres"`, `"mysql"`, `"oracle"`,
    /// `"adbc"`.
    pub kind: String,
    /// Dialect-rendered SQL sent to the remote source.
    pub sql: String,
    /// Rows returned by the remote.
    pub rows: u64,
    /// `RecordBatch`es returned by the remote.
    pub batches: u64,
    /// Wall-clock milliseconds from the first poll to the terminal state.
    pub elapsed_ms: u64,
    /// How the stream ended.
    pub outcome: PushdownOutcome,
}

/// A sink the server installs to collect per-query [`PushdownStat`]s.
///
/// The implementation (in `dataglot-server`) routes each stat to the query
/// registry entry for `run_id`. Implementors must not re-enter
/// [`record_pushdown`]/[`set_pushdown_run_id`] from within [`record`]
/// ([`record`] runs after the task-local borrow is released, but re-entrant
/// mutation would still be surprising).
///
/// [`record`]: PushdownSink::record
///
/// `Send + Sync + 'static` per CLAUDE.md rule 10 — the sink is stored as an
/// `Arc<dyn PushdownSink>` in a task-local that outlives any single query.
pub trait PushdownSink: Send + Sync + 'static {
    /// Record one pushdown stat against the query identified by `run_id`.
    fn record(&self, run_id: RunId, stat: PushdownStat);
}

/// Task-local pushdown context: the installed sink plus the `run_id` of the
/// query currently executing on this task (`None` between queries).
struct PushdownCtx {
    sink: Arc<dyn PushdownSink>,
    run_id: Option<RunId>,
}

tokio::task_local! {
    static CURRENT_PUSHDOWN: RefCell<PushdownCtx>;
}

/// Run `future` with `sink` installed as the current task's pushdown sink.
///
/// The server wraps a connection's whole lifetime in this scope; the active
/// [`RunId`] is then stamped per query via [`set_pushdown_run_id`].
pub async fn with_pushdown_sink<F: std::future::Future>(
    sink: Arc<dyn PushdownSink>,
    future: F,
) -> F::Output {
    CURRENT_PUSHDOWN
        .scope(RefCell::new(PushdownCtx { sink, run_id: None }), future)
        .await
}

/// Stamp the [`RunId`] of the query now executing on this task.
///
/// No-op outside a [`with_pushdown_sink`] scope (unit tests, or a host that
/// hasn't installed a sink).
pub fn set_pushdown_run_id(run_id: RunId) {
    let _ = CURRENT_PUSHDOWN.try_with(|cell| cell.borrow_mut().run_id = Some(run_id));
}

/// Clear the active `run_id` when a query finishes, so a later `Drop`-time
/// PARTIAL (or a pushdown outside any query) isn't misattributed to it.
///
/// No-op outside a [`with_pushdown_sink`] scope.
pub fn clear_pushdown_run_id() {
    let _ = CURRENT_PUSHDOWN.try_with(|cell| cell.borrow_mut().run_id = None);
}

/// A snapshot of the active pushdown context (sink + `run_id`), captured on the
/// connection task so it can be recorded to later from a different task.
///
/// Used by the distributed (Ballista) coordinator path: the pushdown
/// stats come back from executors *after* execution, on a spawned task with no
/// task-local — so the coordinator snapshots the context up front (via
/// [`capture_pushdown_context`]) and records the executor-reported stats
/// through it.
#[derive(Clone)]
pub struct CapturedPushdownContext {
    sink: Arc<dyn PushdownSink>,
    run_id: RunId,
}

impl CapturedPushdownContext {
    /// Record `stat` against the captured `run_id`, from any task.
    pub fn record(&self, stat: PushdownStat) {
        self.sink.record(self.run_id, stat);
    }

    /// The captured `run_id`.
    #[must_use]
    pub fn run_id(&self) -> RunId {
        self.run_id
    }
}

impl std::fmt::Debug for CapturedPushdownContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CapturedPushdownContext")
            .field("run_id", &self.run_id)
            .finish_non_exhaustive()
    }
}

/// Snapshot the active pushdown context (sink + `run_id`) for deferred
/// recording, if a [`with_pushdown_sink`] scope is active and a `run_id` is
/// stamped. Call on the connection task; `None` otherwise.
#[must_use]
pub fn capture_pushdown_context() -> Option<CapturedPushdownContext> {
    CURRENT_PUSHDOWN
        .try_with(|cell| {
            let ctx = cell.borrow();
            ctx.run_id.map(|run_id| CapturedPushdownContext {
                sink: Arc::clone(&ctx.sink),
                run_id,
            })
        })
        .ok()
        .flatten()
}

/// Report one pushdown stat to the installed sink, attributed to the active
/// `run_id`.
///
/// No-op if there is no [`with_pushdown_sink`] scope or no `run_id` has been
/// stamped — so connectors call it unconditionally. The task-local is only
/// visible on the pgwire connection task; DataFusion's parallel execution
/// spawns the federated scan onto partition tasks that don't inherit it, so
/// single-node capture requires single-partition execution (an explicit
/// `partitions = 1`), and distributed capture goes through
/// [`capture_pushdown_context`] instead.
pub fn record_pushdown(stat: PushdownStat) {
    // Resolve the sink + run_id and release the task-local borrow *before*
    // calling into the sink, so a sink impl that touches the task-local can't
    // hit an already-borrowed panic.
    let target = CURRENT_PUSHDOWN
        .try_with(|cell| {
            let ctx = cell.borrow();
            ctx.run_id.map(|run_id| (Arc::clone(&ctx.sink), run_id))
        })
        .ok()
        .flatten();
    if let Some((sink, run_id)) = target {
        sink.record(run_id, stat);
    }
}

/// The active pushdown [`RunId`], if any — for callers that want to tag their
/// own telemetry with the issuing query id. `None` outside a scope or between
/// queries.
#[must_use]
pub fn current_pushdown_run_id() -> Option<RunId> {
    CURRENT_PUSHDOWN
        .try_with(|cell| cell.borrow().run_id)
        .ok()
        .flatten()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Default)]
    struct Collector(Mutex<Vec<(RunId, PushdownStat)>>);

    impl PushdownSink for Collector {
        fn record(&self, run_id: RunId, stat: PushdownStat) {
            self.0.lock().expect("lock").push((run_id, stat));
        }
    }

    fn stat(source: &str) -> PushdownStat {
        PushdownStat {
            source: source.to_string(),
            kind: "postgres".to_string(),
            sql: "SELECT 1".to_string(),
            rows: 3,
            batches: 1,
            elapsed_ms: 7,
            outcome: PushdownOutcome::Completed,
        }
    }

    #[test]
    fn record_outside_scope_is_a_no_op() {
        // Must not panic when no sink is installed.
        record_pushdown(stat("s"));
        set_pushdown_run_id(RunId::new());
        clear_pushdown_run_id();
        assert!(current_pushdown_run_id().is_none());
    }

    #[tokio::test]
    async fn records_only_after_run_id_is_stamped() {
        let collector = Arc::new(Collector::default());
        let sink: Arc<dyn PushdownSink> = collector.clone();
        with_pushdown_sink(sink, async {
            // No run_id yet → dropped.
            record_pushdown(stat("before"));
            assert!(current_pushdown_run_id().is_none());

            let run_id = RunId::new();
            set_pushdown_run_id(run_id);
            assert_eq!(current_pushdown_run_id(), Some(run_id));
            record_pushdown(stat("during"));

            // Cleared → dropped again.
            clear_pushdown_run_id();
            record_pushdown(stat("after"));

            let captured = collector.0.lock().expect("lock").clone();
            assert_eq!(captured.len(), 1, "only the stamped-run_id stat is kept");
            assert_eq!(captured[0].0, run_id);
            assert_eq!(captured[0].1.source, "during");
        })
        .await;
    }

    #[tokio::test]
    async fn run_ids_are_isolated_per_query() {
        let collector = Arc::new(Collector::default());
        let sink: Arc<dyn PushdownSink> = collector.clone();
        with_pushdown_sink(sink, async {
            let q1 = RunId::new();
            set_pushdown_run_id(q1);
            record_pushdown(stat("q1"));
            clear_pushdown_run_id();

            let q2 = RunId::new();
            set_pushdown_run_id(q2);
            record_pushdown(stat("q2"));

            let captured = collector.0.lock().expect("lock").clone();
            assert_eq!(captured.len(), 2);
            assert_eq!(captured[0].0, q1);
            assert_eq!(captured[1].0, q2);
        })
        .await;
    }
}

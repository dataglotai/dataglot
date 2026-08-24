//! Per-query observation hook.
//!
//! Pg wire is the only crate that knows when a query started and ended,
//! so it owns the abstraction. Higher layers (the server crate, or any
//! other consumer) plug in their own `QueryObserver` implementation to
//! react — typically by incrementing Prometheus counters, recording
//! latency histograms, or emitting `OpenLineage` `START`/`COMPLETE`
//! event pairs (see `dataglot-server::lineage::LineageObserver`).
//!
//! Per hard rule 4 the dataglot-server metric types do not leak
//! into this crate; the observer is a Send+Sync trait object that
//! pg wire calls without knowing what it does on the other side.
//!
//! # Slice 3 trait extension
//!
//! The trait grew an [`on_query_start`](QueryObserver::on_query_start)
//! callback and a `run_id` parameter on
//! [`on_query_complete`](QueryObserver::on_query_complete) so the
//! lineage emitter can pair `START` and `COMPLETE` events. `run_id`
//! is allocated by pg wire (the only layer that knows when a query
//! starts) and shared across every observer in a
//! [`CompositeQueryObserver`] — both observers see the same id, which
//! is what the `OpenLineage` backend needs to correlate the pair.

use std::sync::Arc;
use std::time::Duration;

use datafusion::logical_expr::LogicalPlan;
use dataglot_core::lineage::RunId;

/// Outcome of a single query's execution, as observed at the pg wire
/// boundary.
///
/// `Error` covers everything that didn't reach the wire as a successful
/// `CommandComplete` — protocol errors, planner errors, executor
/// errors, runtime panics surfaced as errors. The mapping is
/// intentionally coarse so the metric label cardinality stays bounded
/// (see Phase 0.5 Task 03 spec, "Open questions").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryOutcome {
    /// The handler returned a non-error response.
    Success,
    /// The handler returned an error to the client.
    Error,
}

/// A hook the pg wire layer calls once per query.
///
/// The observer fires on the Simple Query and Extended Query
/// `do_query` paths — once before execution starts
/// ([`on_query_start`](Self::on_query_start)) and once when the query's
/// result stream is fully drained or dropped
/// ([`on_query_complete`](Self::on_query_complete)). Results stream
/// lazily, so completion is deliberately deferred past `do_query`'s
/// return to the true end of streaming; this is what makes the "what's
/// running" registry and the reported duration reflect real execution
/// rather than planning alone. The same [`RunId`] is threaded
/// through both calls so observers can correlate the pair (the
/// `OpenLineage` emitter uses it as the `run.runId` field).
///
/// Implementations must be cheap and non-blocking — pg wire calls
/// these inline on the connection task, so any heavy work would
/// back-pressure the wire. The lineage emitter sidesteps this by
/// spawning a tokio task in its `on_query_start` /
/// `on_query_complete` impls; see `dataglot_server::lineage`.
pub trait QueryObserver: Send + Sync + 'static {
    /// Called once per query, just before the inner handler runs.
    ///
    /// Default impl is a no-op so existing observers
    /// (`MetricsObserver`, test counters) don't need to opt in. The
    /// `run_id` is allocated by pg wire and shared with the matching
    /// `on_query_complete` so observers can pair start + finish
    /// events.
    fn on_query_start(&self, run_id: RunId, query: &str) {
        let _ = (run_id, query);
    }

    /// Whether this observer wants the executed `LogicalPlan` handed to
    /// [`on_query_complete`](Self::on_query_complete).
    ///
    /// Default `false`. The pg wire handler only plans the query to
    /// populate `plan` when *some* observer returns `true` — so a
    /// deployment with only metrics observers pays no extra planning.
    /// The lineage observer overrides this to `true` so it can extract
    /// inputs / column lineage from the plan that actually executed,
    /// instead of re-planning the SQL on the completion path.
    fn wants_plan(&self) -> bool {
        false
    }

    /// Called once per query when its result stream is fully drained (or
    /// dropped on client disconnect) — **not** when `do_query` returns.
    /// `duration` is therefore the wall-clock time from `on_query_start`
    /// through the end of streaming, and `outcome` is `Error` if the
    /// stream fails or is cancelled mid-flight, even though `do_query`
    /// itself returned `Ok`. The same `run_id` passed to
    /// [`on_query_start`](Self::on_query_start) is threaded through.
    /// `query` is the SQL the client submitted (already
    /// EXPLAIN-FEDERATION-rewritten on the simple-query path).
    ///
    /// Fires exactly once; for a statement that produces no result
    /// stream (DDL, empty, or a planning error) it fires as soon as
    /// `do_query` returns, since there is nothing to drain.
    ///
    /// `plan` is the **unoptimized** `LogicalPlan` captured *before*
    /// execution, when [`wants_plan`](Self::wants_plan) is `true` and
    /// planning succeeded — on the simple-query path only. It's `None`
    /// when no observer wanted it, when planning failed, or on the
    /// extended-query path. Capturing before execution is what makes
    /// `CREATE TABLE t AS …` lineage work: re-planning the SQL after the
    /// table exists would fail.
    fn on_query_complete(
        &self,
        run_id: RunId,
        query: &str,
        plan: Option<Arc<LogicalPlan>>,
        outcome: QueryOutcome,
        duration: Duration,
    );

    /// Called once per query, right after
    /// [`on_query_start`](Self::on_query_start), with a handle that can
    /// cancel the running query out-of-band. The
    /// server's query registry stores it by `run_id` so the dashboard's
    /// `POST /api/queries/{id}/cancel` can abort a query it only knows by
    /// id. Default no-op — only observers exposing a kill path override
    /// it. Not fired when the connection has no cancel slot.
    fn on_query_cancellable(&self, _run_id: RunId, _cancel: crate::QueryHandle) {}

    /// Called once per query, before execution, with the captured
    /// pre-execution `LogicalPlan` — but only when
    /// [`wants_plan`](Self::wants_plan) is `true` and planning
    /// succeeded. Lets an observer derive per-query facts from the plan
    /// while the query is still running (the server's query registry
    /// extracts the federated source catalogs for the dashboard —
    ///  slice 5b). Default no-op.
    fn on_query_plan(&self, _run_id: RunId, _plan: Arc<LogicalPlan>) {}

    /// Called once per query, right after
    /// [`on_query_start`](Self::on_query_start), with the connection's
    /// pg wire startup username. Lets an observer attribute a running
    /// query to who submitted it (the dashboard's per-query `user`
    /// column — ). Default no-op; only observers that surface
    /// identity override it. Not fired when the connection reported no
    /// username. The username is metadata, never a credential (rule 12).
    fn on_query_identity(&self, _run_id: RunId, _user: &str) {}

    /// Called once for a query that ends in an **error**, with the
    /// redacted, client-facing error message — fired just before the
    /// matching [`on_query_complete`](Self::on_query_complete) reports an
    /// `Error` outcome. Lets an observer retain *why* a query failed (the
    /// dashboard's History error detail — ). Default no-op; only
    /// observers that surface error detail override it. Never fired for a
    /// successful query. The message is exactly the text the client
    /// received, so it carries no credential (rule 12; connector and
    /// planner errors are already scrubbed at their source). Currently
    /// fired on the streaming/`do_query` path (`QueryCompletion`), which
    /// covers planner, executor, and cancellation errors.
    fn on_query_error(&self, _run_id: RunId, _message: &str) {}
}

/// Default observer that does nothing.
///
/// Used by callers (tests, smoke runs) that don't want metrics. Cheap
/// to construct and to call — the methods are inlined to nothing in
/// release builds.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopObserver;

impl QueryObserver for NoopObserver {
    #[inline]
    fn on_query_complete(
        &self,
        _run_id: RunId,
        _query: &str,
        _plan: Option<Arc<LogicalPlan>>,
        _outcome: QueryOutcome,
        _duration: Duration,
    ) {
    }
}

/// Compose multiple observers behind a single trait object.
///
/// `DataglotServer` constructs this with a `MetricsObserver` and a
/// `LineageObserver` so a single per-query hook drives both
/// Prometheus counters and `OpenLineage` event emission. Mirrors the
/// `CompositeEnforcer` pattern in `dataglot-policy`.
///
/// All inner observers see the same `RunId` — the composite generates
/// one in `on_query_start` and shares it; the inner observers'
/// return values from any future stateful API would be ignored. This
/// is the property the `OpenLineage` backend needs to pair `START`
/// and `COMPLETE` events.
#[derive(Clone)]
pub struct CompositeQueryObserver {
    observers: Vec<Arc<dyn QueryObserver>>,
}

impl std::fmt::Debug for CompositeQueryObserver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompositeQueryObserver")
            .field("observer_count", &self.observers.len())
            .finish()
    }
}

impl CompositeQueryObserver {
    /// Build a composite from the given inner observers. Order is
    /// preserved — `on_query_start` and `on_query_complete` fire the
    /// observers in the order they were passed.
    #[must_use]
    pub fn new(observers: Vec<Arc<dyn QueryObserver>>) -> Self {
        Self { observers }
    }

    /// Number of inner observers — useful for tests.
    #[must_use]
    pub fn len(&self) -> usize {
        self.observers.len()
    }

    /// Returns true when no inner observers were configured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.observers.is_empty()
    }
}

impl QueryObserver for CompositeQueryObserver {
    /// The handler should capture the plan if *any* inner observer wants it.
    fn wants_plan(&self) -> bool {
        self.observers.iter().any(|o| o.wants_plan())
    }

    fn on_query_start(&self, run_id: RunId, query: &str) {
        for obs in &self.observers {
            obs.on_query_start(run_id, query);
        }
    }

    fn on_query_cancellable(&self, run_id: RunId, cancel: crate::QueryHandle) {
        for obs in &self.observers {
            obs.on_query_cancellable(run_id, cancel.clone());
        }
    }

    fn on_query_plan(&self, run_id: RunId, plan: Arc<LogicalPlan>) {
        for obs in &self.observers {
            obs.on_query_plan(run_id, Arc::clone(&plan));
        }
    }

    fn on_query_identity(&self, run_id: RunId, user: &str) {
        for obs in &self.observers {
            obs.on_query_identity(run_id, user);
        }
    }

    fn on_query_error(&self, run_id: RunId, message: &str) {
        for obs in &self.observers {
            obs.on_query_error(run_id, message);
        }
    }

    fn on_query_complete(
        &self,
        run_id: RunId,
        query: &str,
        plan: Option<Arc<LogicalPlan>>,
        outcome: QueryOutcome,
        duration: Duration,
    ) {
        for obs in &self.observers {
            // Cheap `Arc` clone per inner observer (usually 1–2).
            obs.on_query_complete(run_id, query, plan.clone(), outcome, duration);
        }
    }
}

#[cfg(test)]
// Tests hold a lock guard to the end of the body to assert on its
// contents — harmless. `significant_drop_tightening` exists to prevent
// the over-held guards that cause production deadlocks, so relax it here.
#[allow(clippy::significant_drop_tightening)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    /// Test observer that counts calls per outcome.
    struct CountingObserver {
        starts: AtomicUsize,
        success: AtomicUsize,
        error: AtomicUsize,
        seen_run_ids: Mutex<Vec<RunId>>,
    }

    impl CountingObserver {
        fn new() -> Self {
            Self {
                starts: AtomicUsize::new(0),
                success: AtomicUsize::new(0),
                error: AtomicUsize::new(0),
                seen_run_ids: Mutex::new(Vec::new()),
            }
        }
    }

    impl QueryObserver for CountingObserver {
        fn on_query_start(&self, run_id: RunId, _query: &str) {
            self.starts.fetch_add(1, Ordering::Relaxed);
            self.seen_run_ids.lock().unwrap().push(run_id);
        }

        fn on_query_complete(
            &self,
            run_id: RunId,
            _query: &str,
            _plan: Option<Arc<LogicalPlan>>,
            outcome: QueryOutcome,
            _duration: Duration,
        ) {
            self.seen_run_ids.lock().unwrap().push(run_id);
            match outcome {
                QueryOutcome::Success => self.success.fetch_add(1, Ordering::Relaxed),
                QueryOutcome::Error => self.error.fetch_add(1, Ordering::Relaxed),
            };
        }
    }

    #[test]
    fn noop_observer_compiles_and_runs() {
        let obs = NoopObserver;
        let id = RunId::new();
        obs.on_query_start(id, "SELECT 1");
        obs.on_query_complete(
            id,
            "SELECT 1",
            None,
            QueryOutcome::Success,
            Duration::from_millis(5),
        );
        obs.on_query_complete(
            id,
            "SELECT bad",
            None,
            QueryOutcome::Error,
            Duration::from_millis(10),
        );
    }

    #[test]
    fn observer_can_be_used_via_dyn_trait() {
        let obs: Arc<dyn QueryObserver> = Arc::new(CountingObserver::new());
        let id = RunId::new();
        obs.on_query_start(id, "SELECT 1");
        obs.on_query_complete(
            id,
            "SELECT 1",
            None,
            QueryOutcome::Success,
            Duration::from_millis(1),
        );
        obs.on_query_complete(
            id,
            "SELECT 1",
            None,
            QueryOutcome::Success,
            Duration::from_millis(1),
        );
        obs.on_query_complete(
            id,
            "SELECT bad",
            None,
            QueryOutcome::Error,
            Duration::from_millis(1),
        );
    }

    #[test]
    fn outcome_eq_and_copy() {
        assert_eq!(QueryOutcome::Success, QueryOutcome::Success);
        assert_ne!(QueryOutcome::Success, QueryOutcome::Error);
        let a = QueryOutcome::Success;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn composite_fans_out_to_each_inner_observer() {
        // Two observers, one start + one complete each — both must
        // see the calls.
        let a = Arc::new(CountingObserver::new());
        let b = Arc::new(CountingObserver::new());
        let composite =
            CompositeQueryObserver::new(vec![a.clone() as Arc<dyn QueryObserver>, b.clone() as _]);
        assert_eq!(composite.len(), 2);
        assert!(!composite.is_empty());

        let id = RunId::new();
        composite.on_query_start(id, "SELECT 1");
        composite.on_query_complete(
            id,
            "SELECT 1",
            None,
            QueryOutcome::Success,
            Duration::from_millis(1),
        );

        assert_eq!(a.starts.load(Ordering::Relaxed), 1);
        assert_eq!(b.starts.load(Ordering::Relaxed), 1);
        assert_eq!(a.success.load(Ordering::Relaxed), 1);
        assert_eq!(b.success.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn composite_shares_one_run_id_across_observers() {
        // The pgwire layer allocates `run_id` once per query and the
        // composite must propagate the same value to every inner
        // observer — that's what lets the `OpenLineage` backend pair
        // START + COMPLETE events.
        let a = Arc::new(CountingObserver::new());
        let b = Arc::new(CountingObserver::new());
        let composite =
            CompositeQueryObserver::new(vec![a.clone() as Arc<dyn QueryObserver>, b.clone() as _]);

        let id = RunId::new();
        composite.on_query_start(id, "SELECT 1");
        composite.on_query_complete(
            id,
            "SELECT 1",
            None,
            QueryOutcome::Success,
            Duration::from_millis(1),
        );

        let a_ids = a.seen_run_ids.lock().unwrap();
        let b_ids = b.seen_run_ids.lock().unwrap();
        assert_eq!(*a_ids, *b_ids, "both observers must see the same run ids");
        assert_eq!(a_ids.len(), 2);
        assert_eq!(a_ids[0], a_ids[1], "start + complete share one run_id");
    }

    #[test]
    fn empty_composite_is_a_noop() {
        let composite = CompositeQueryObserver::new(vec![]);
        assert!(composite.is_empty());
        let id = RunId::new();
        composite.on_query_start(id, "SELECT 1");
        composite.on_query_complete(
            id,
            "SELECT 1",
            None,
            QueryOutcome::Success,
            Duration::from_millis(1),
        );
        // Reached this line without panic — the empty case is well-defined.
    }
}

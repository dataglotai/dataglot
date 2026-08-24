//! Live registry of in-flight queries — the data plane behind the
//! operational dashboard's "what's running" view ( slice 1,
//! ).
//!
//! pg wire is the only layer that knows when a query starts and ends,
//! so it owns the [`QueryObserver`] hook. [`QueryRegistryObserver`]
//! bridges that hook into a shared in-memory map keyed by [`RunId`]:
//! `on_query_start` inserts, `on_query_complete` removes. A point-in-time
//! [`snapshot`](QueryRegistry::snapshot) backs the `GET /api/queries`
//! endpoint (see [`crate::observability`]).
//!
//! This is the engine-served analogue of `Trino`'s running-query list
//! and `CockroachDB`'s *Active Executions* — the piece that was
//! previously only reachable through the dev testbench.
//!
//! # Scope (slice 1)
//!
//! Active queries only — completed queries are dropped on
//! `on_query_complete`; fingerprint history is a later slice. The
//! observer records what the pg wire hook provides (run id, SQL text,
//! wall-clock elapsed); per-query user / catalog enrichment needs a
//! trait extension and lands with the query-detail slice.
//!
//! # Rule 12
//!
//! Only the SQL **text** is retained (truncated to [`MAX_SQL_LEN`]);
//! connection credentials never reach this layer — they live inside the
//! connector clients' opaque session state, not in the query string.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use datafusion::logical_expr::LogicalPlan;
use dataglot_core::lineage::{extract_inputs_with_defaults, RunId};
use dataglot_core::{PushdownSink, PushdownStat};
use dataglot_pgwire::{QueryHandle, QueryObserver, QueryOutcome};
use serde::Serialize;

/// Upper bound on retained SQL text per query. Keeps the registry light
/// and bounds any accidental payload; the dashboard renders a prefix.
pub const MAX_SQL_LEN: usize = 4096;

/// How many most-recently-finished queries the history ring retains
///. Bounded so the registry stays a fixed-size,
/// in-memory structure — not a query log.
pub const HISTORY_CAP: usize = 100;

/// Upper bound on per-source pushdown stats retained per query (
/// slice 2). A query normally pushes to a handful of sources; the cap
/// keeps a pathological many-branch query from growing an entry without
/// bound. Stats beyond the cap are dropped (the query still runs).
pub const MAX_PUSHDOWNS_PER_QUERY: usize = 64;

/// One in-flight query, as tracked internally.
#[derive(Debug)]
struct ActiveQuery {
    sql: String,
    started: Instant,
    /// Cancel trigger for this query, attached by `on_query_cancellable`
    /// just after start. `None` in the brief window
    /// before it arrives, or when the connection has no cancel slot.
    cancel: Option<QueryHandle>,
    /// Distinct source catalogs this query federates across, extracted
    /// from the pre-execution plan. Empty unless
    /// `observability.capture_query_sources` is on.
    sources: Vec<String>,
    /// pg wire startup username that submitted the query, attached by
    /// `on_query_identity` just after start. `None` in the brief window
    /// before it arrives, or when the connection reported no username.
    user: Option<String>,
    /// Resolved tenant/org of the session that submitted the query — the
    /// governance-relevant attribution, attached alongside `user` from the
    /// connection's session-org task-local. `None` before it arrives, or on
    /// a trust/default session that resolved no org.
    org: Option<String>,
    /// The (redacted, client-facing) error message if this query failed,
    /// attached by `on_query_error` just before completion. `None`
    /// while running and for successful queries.
    error: Option<String>,
    /// Set when this query's cancel handle was fired via [`Self::cancel`], so
    /// completion can report `cancelled` rather than a bare `error` — an
    /// operator-initiated abort reads very differently from a query failure.
    cancelled: bool,
    /// Per-source pushdown stats reported by the federation connectors as the
    /// query executes, in completion order. Populated via
    /// the [`PushdownSink`] impl only when `capture_query_sources` is on (the
    /// observer stamps this query's `run_id` into the pushdown task-local then).
    /// Capped at [`MAX_PUSHDOWNS_PER_QUERY`].
    pushdowns: Vec<PushdownStat>,
}

/// Shared, cheaply-cloneable registry of currently-executing queries.
///
/// Cloning shares the same underlying map (an `Arc`), so the copy handed
/// to the axum router and the copy wired into each connection's observer
/// see the same live state.
#[derive(Clone, Default)]
pub struct QueryRegistry {
    inner: Arc<RwLock<HashMap<RunId, ActiveQuery>>>,
    /// Bounded ring of the most-recently-finished queries ( slice
    /// 5d), newest at the back. Capped at [`HISTORY_CAP`].
    history: Arc<RwLock<VecDeque<CompletedQueryView>>>,
}

impl std::fmt::Debug for QueryRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the queries themselves — just the counts.
        let active = self.inner.read().map_or(0, |m| m.len());
        let history = self.history.read().map_or(0, |h| h.len());
        f.debug_struct("QueryRegistry")
            .field("active", &active)
            .field("history", &history)
            .finish()
    }
}

/// One in-flight query as exposed by `GET /api/queries`.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ActiveQueryView {
    /// Query run id (uuid string), stable across start → complete.
    pub run_id: String,
    /// SQL text, truncated to [`MAX_SQL_LEN`].
    pub sql: String,
    /// Milliseconds elapsed since the query began executing.
    pub elapsed_ms: u64,
    /// Execution state. Always `"running"` for entries in this list;
    /// present so the UI renders a state pill without special-casing.
    pub state: &'static str,
    /// Distinct source catalogs the query federates across (
    /// slice 5b). Empty unless `capture_query_sources` is enabled.
    pub sources: Vec<String>,
    /// pg wire username that submitted the query. `None` when the
    /// connection reported no username.
    pub user: Option<String>,
    /// Resolved tenant/org of the submitting session — the governance-relevant
    /// attribution. `None` on a trust/default session with no org.
    pub org: Option<String>,
    /// Per-source pushdown stats captured so far — the
    /// dialect SQL sent to each source with its rows/timing. Empty unless
    /// `capture_query_sources` is enabled; may be partial while running.
    pub pushdowns: Vec<PushdownStat>,
}

/// One finished query, as exposed by `GET /api/queries/history`
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CompletedQueryView {
    /// Query run id (uuid string).
    pub run_id: String,
    /// SQL text, truncated to [`MAX_SQL_LEN`].
    pub sql: String,
    /// Total wall-clock duration in milliseconds.
    pub elapsed_ms: u64,
    /// Terminal outcome: `"success"`, `"error"`, or `"cancelled"` (an
    /// operator-initiated abort via the dashboard cancel button).
    pub outcome: &'static str,
    /// Redacted error message when the query failed. Present for
    /// `error` / `cancelled` outcomes that carried a message; omitted on
    /// success. Never a credential (rule 12 — already scrubbed at source).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Distinct source catalogs it federated across (empty unless
    /// `capture_query_sources` was enabled).
    pub sources: Vec<String>,
    /// pg wire username that submitted the query. `None` when the
    /// connection reported no username.
    pub user: Option<String>,
    /// Resolved tenant/org of the submitting session — the governance-relevant
    /// attribution. `None` on a trust/default session with no org.
    pub org: Option<String>,
    /// Per-source pushdown stats for this query — the
    /// dialect SQL sent to each source with its rows/batches/timing, in
    /// completion order. Empty unless `capture_query_sources` was enabled.
    /// This is the data behind the dashboard's query-profile treeview.
    pub pushdowns: Vec<PushdownStat>,
}

impl QueryRegistry {
    /// Create an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a query as started. Truncates the SQL to [`MAX_SQL_LEN`]
    /// on a UTF-8 char boundary. A poisoned lock is swallowed — losing
    /// an observability entry must never break the query path.
    fn start(&self, run_id: RunId, sql: &str) {
        let sql = truncate_on_boundary(sql, MAX_SQL_LEN);
        if let Ok(mut map) = self.inner.write() {
            map.insert(
                run_id,
                ActiveQuery {
                    sql,
                    started: Instant::now(),
                    cancel: None,
                    sources: Vec::new(),
                    user: None,
                    org: None,
                    error: None,
                    cancelled: false,
                    pushdowns: Vec::new(),
                },
            );
        }
    }

    /// Attach the cancel handle to an already-started query (fired from
    /// `on_query_cancellable`, which always follows `on_query_start`).
    fn attach_cancel(&self, run_id: RunId, handle: QueryHandle) {
        if let Ok(mut map) = self.inner.write() {
            if let Some(q) = map.get_mut(&run_id) {
                q.cancel = Some(handle);
            }
        }
    }

    /// Attach the federated source catalogs to an already-started query
    /// (fired from `on_query_plan` —  slice 5b).
    fn attach_sources(&self, run_id: RunId, sources: Vec<String>) {
        if let Ok(mut map) = self.inner.write() {
            if let Some(q) = map.get_mut(&run_id) {
                q.sources = sources;
            }
        }
    }

    /// Append one per-source pushdown stat to a query, fired
    /// from the [`PushdownSink`] impl as each federated sub-query's result
    /// stream reaches a terminal state. Bounded at [`MAX_PUSHDOWNS_PER_QUERY`];
    /// excess stats are dropped.
    ///
    /// Attaches to the **active** entry (the common single-node, inline-capture
    /// path). If the query is no longer active it falls back to the **history**
    /// ring: distributed (Ballista) pushdown stats are collected from executor
    /// task-metrics and land *after* `on_query_complete` has already moved the
    /// entry to history, so late-arriving stats update the finished
    /// entry in place. A stat for a `run_id` in neither map is dropped (an
    /// unknown query, or one that aged out of history).
    fn attach_pushdown(&self, run_id: RunId, mut stat: PushdownStat) {
        // Bound the rendered SQL like the query's own SQL (rule 12 / registry
        // stays a fixed-size structure): a pathological pushed statement must
        // not grow an active record — or a history entry — without bound.
        stat.sql = truncate_on_boundary(&stat.sql, MAX_SQL_LEN);
        // Active entry — the single-node, inline-capture path.
        if let Ok(mut map) = self.inner.write() {
            if let Some(q) = map.get_mut(&run_id) {
                if q.pushdowns.len() < MAX_PUSHDOWNS_PER_QUERY {
                    q.pushdowns.push(stat);
                }
                return;
            }
        }
        // Not active: a distributed late-arrival. Update the finished
        // entry in the history ring in place. The `inner` write lock is already
        // released above, so we never hold both at once.
        if let Ok(mut hist) = self.history.write() {
            let id = run_id.to_string();
            if let Some(q) = hist.iter_mut().find(|q| q.run_id == id) {
                if q.pushdowns.len() < MAX_PUSHDOWNS_PER_QUERY {
                    q.pushdowns.push(stat);
                }
            }
        }
    }

    /// Attach the submitting username to an already-started query (fired
    /// from `on_query_identity`, which follows `on_query_start`).
    fn attach_user(&self, run_id: RunId, user: &str) {
        if let Ok(mut map) = self.inner.write() {
            if let Some(q) = map.get_mut(&run_id) {
                q.user = Some(user.to_string());
            }
        }
    }

    /// Attach the submitting session's resolved org to an already-started
    /// query. Fired alongside `attach_user` from `on_query_identity`, reading
    /// the org the server bridged into the pgwire session-org task-local
    /// (`None` on a trust/default session). Mirrors [`Self::attach_user`].
    fn attach_org(&self, run_id: RunId, org: Option<String>) {
        if let Ok(mut map) = self.inner.write() {
            if let Some(q) = map.get_mut(&run_id) {
                q.org = org;
            }
        }
    }

    /// Attach the (redacted) error message to a still-running query, fired
    /// from `on_query_error` just before completion. Carries through to
    /// history as the failure detail. `None`-guarded: a message for an
    /// unknown/already-removed query is dropped.
    fn attach_error(&self, run_id: RunId, message: &str) {
        if let Ok(mut map) = self.inner.write() {
            if let Some(q) = map.get_mut(&run_id) {
                q.error = Some(truncate_on_boundary(message, MAX_SQL_LEN));
            }
        }
    }

    /// Best-effort cancel of a running query by its run-id string. Fires
    /// the query's cancel handle (aborting its row stream) and flags the
    /// entry as cancelled so completion reports `cancelled` rather than a
    /// bare `error`. The entry is removed later by `on_query_complete` when
    /// the aborted query unwinds. Returns `true` if a cancellable query was
    /// found.
    #[must_use]
    pub fn cancel(&self, run_id: &str) -> bool {
        let Ok(mut map) = self.inner.write() else {
            return false;
        };
        for (id, q) in map.iter_mut() {
            if id.to_string() == run_id {
                if let Some(handle) = &q.cancel {
                    q.cancelled = true;
                    handle.cancel();
                    return true;
                }
                return false;
            }
        }
        false
    }

    /// Record a query as finished — remove it from the live set and push
    /// it onto the bounded history ring.
    fn complete(&self, run_id: RunId, outcome: QueryOutcome, duration: Duration) {
        let removed = self
            .inner
            .write()
            .ok()
            .and_then(|mut map| map.remove(&run_id));
        let Some(q) = removed else {
            return; // unknown / never started under this registry
        };
        // A fired cancel reports as `cancelled` rather than a bare `error`,
        // so an operator-initiated abort is distinguishable from a genuine
        // query failure in the History view.
        let outcome = match outcome {
            QueryOutcome::Success => "success",
            QueryOutcome::Error if q.cancelled => "cancelled",
            QueryOutcome::Error => "error",
        };
        let record = CompletedQueryView {
            run_id: run_id.to_string(),
            sql: q.sql,
            elapsed_ms: u64::try_from(duration.as_millis()).unwrap_or(u64::MAX),
            outcome,
            error: q.error,
            sources: q.sources,
            user: q.user,
            org: q.org,
            pushdowns: q.pushdowns,
        };
        if let Ok(mut hist) = self.history.write() {
            hist.push_back(record);
            while hist.len() > HISTORY_CAP {
                hist.pop_front();
            }
        }
    }

    /// Snapshot of the most-recently-finished queries, **newest first**.
    #[must_use]
    pub fn history(&self) -> Vec<CompletedQueryView> {
        let Ok(hist) = self.history.read() else {
            return Vec::new();
        };
        hist.iter().rev().cloned().collect()
    }

    /// Point-in-time snapshot of running queries, **longest-running
    /// first** — the ones an operator most likely cares about.
    #[must_use]
    pub fn snapshot(&self) -> Vec<ActiveQueryView> {
        let Ok(map) = self.inner.read() else {
            return Vec::new();
        };
        let mut out: Vec<ActiveQueryView> = map
            .iter()
            .map(|(run_id, q)| ActiveQueryView {
                run_id: run_id.to_string(),
                sql: q.sql.clone(),
                elapsed_ms: u64::try_from(q.started.elapsed().as_millis()).unwrap_or(u64::MAX),
                state: "running",
                sources: q.sources.clone(),
                user: q.user.clone(),
                org: q.org.clone(),
                pushdowns: q.pushdowns.clone(),
            })
            .collect();
        out.sort_by_key(|q| std::cmp::Reverse(q.elapsed_ms));
        out
    }

    /// Look up a single running query by its run-id string.
    #[must_use]
    pub fn get(&self, run_id: &str) -> Option<ActiveQueryView> {
        self.snapshot().into_iter().find(|q| q.run_id == run_id)
    }

    /// Look up a single **finished** query by its run-id string, from the
    /// bounded history ring. Backs the query-detail endpoint's fallback for a
    /// query that already completed ( slice 2 — the treeview is usually
    /// inspected after the query finishes).
    #[must_use]
    pub fn history_get(&self, run_id: &str) -> Option<CompletedQueryView> {
        let hist = self.history.read().ok()?;
        hist.iter().rev().find(|q| q.run_id == run_id).cloned()
    }

    /// Number of currently-running queries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.read().map_or(0, |m| m.len())
    }

    /// Whether no queries are currently running.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// The registry is the sink for per-source pushdown stats:
/// `dataglot-federation` reports each pushdown's terminal stats via
/// `dataglot_core::record_pushdown`, which routes here when the server has
/// installed the registry as the task-local sink (`with_pushdown_sink`, in
/// `server.rs`) and the observer has stamped the query's `run_id`.
impl PushdownSink for QueryRegistry {
    fn record(&self, run_id: RunId, stat: PushdownStat) {
        self.attach_pushdown(run_id, stat);
    }
}

/// Truncate `s` to at most `max` bytes, respecting UTF-8 char
/// boundaries (never splits a multi-byte character).
fn truncate_on_boundary(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

/// A [`QueryObserver`] that records in-flight queries into a
/// [`QueryRegistry`]. Wired into the per-connection
/// `CompositeQueryObserver` alongside the metrics and lineage
/// observers.
#[derive(Debug, Clone)]
pub struct QueryRegistryObserver {
    registry: QueryRegistry,
    /// When true, request the pre-execution plan and record the source
    /// catalogs each query federates across. Off by
    /// default so non-dashboard deployments don't plan every query.
    capture_sources: bool,
    /// Session default catalog/schema, used to resolve catalog/schema-less
    /// table references (a bare `nation`) to the real catalog they route to
    /// instead of the `"default"` placeholder.
    default_catalog: String,
    default_schema: String,
}

impl QueryRegistryObserver {
    /// Build an observer that feeds `registry`. `capture_sources` mirrors
    /// `observability.capture_query_sources`; `default_catalog` /
    /// `default_schema` mirror the session defaults so bare table references
    /// resolve to the catalog they actually federate to.
    #[must_use]
    pub fn new(
        registry: QueryRegistry,
        capture_sources: bool,
        default_catalog: impl Into<String>,
        default_schema: impl Into<String>,
    ) -> Self {
        Self {
            registry,
            capture_sources,
            default_catalog: default_catalog.into(),
            default_schema: default_schema.into(),
        }
    }
}

impl QueryObserver for QueryRegistryObserver {
    fn on_query_start(&self, run_id: RunId, query: &str) {
        self.registry.start(run_id, query);
        // Stamp this query's run_id into the pushdown task-local so the
        // federation connectors' stats route to this entry.
        // Gated on the same flag as source capture — both feed the dashboard's
        // per-query detail. No-op unless the server installed a sink
        // (`with_pushdown_sink`), so it's safe on a non-dashboard host.
        if self.capture_sources {
            dataglot_core::set_pushdown_run_id(run_id);
        }
    }

    fn on_query_cancellable(&self, run_id: RunId, cancel: QueryHandle) {
        self.registry.attach_cancel(run_id, cancel);
    }

    fn on_query_identity(&self, run_id: RunId, user: &str) {
        self.registry.attach_user(run_id, user);
        // The org the server bridged into the pgwire session-org task-local
        // for this connection (rule 4: the server owns identity bridging; this
        // observer only reads the already-resolved value). `on_query_identity`
        // runs on the connection task, inside its `with_session_org` scope, so
        // this returns the same org the session resolved at startup — `None`
        // for a trust/default session with no org. Rule 12: org is a tenant
        // name, not a credential.
        self.registry
            .attach_org(run_id, dataglot_pgwire::current_session_org());
    }

    fn on_query_error(&self, run_id: RunId, message: &str) {
        self.registry.attach_error(run_id, message);
    }

    fn wants_plan(&self) -> bool {
        self.capture_sources
    }

    fn on_query_plan(&self, run_id: RunId, plan: std::sync::Arc<LogicalPlan>) {
        if !self.capture_sources {
            return;
        }
        // Distinct source catalogs, sorted — the federation breadth of
        // this query. Bare/partial references resolve against the session
        // defaults so they surface the real catalog, not `"default"`.
        // Plan-extraction failure just yields no sources.
        let mut catalogs: Vec<String> =
            extract_inputs_with_defaults(&plan, &self.default_catalog, &self.default_schema)
                .unwrap_or_default()
                .into_iter()
                .map(|d| d.catalog)
                .collect();
        catalogs.sort_unstable();
        catalogs.dedup();
        self.registry.attach_sources(run_id, catalogs);
    }

    fn on_query_complete(
        &self,
        run_id: RunId,
        _query: &str,
        _plan: Option<Arc<LogicalPlan>>,
        outcome: QueryOutcome,
        duration: Duration,
    ) {
        // Clear the pushdown run_id first so a late `Drop`-time PARTIAL from
        // this query's just-dropped streams isn't misattributed to the next
        // query on the connection.
        if self.capture_sources {
            dataglot_core::clear_pushdown_run_id();
        }
        self.registry.complete(run_id, outcome, duration);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn start_then_complete_leaves_registry_empty() {
        let reg = QueryRegistry::new();
        let id = RunId::new();
        assert!(reg.is_empty());

        reg.start(id, "SELECT 1");
        assert_eq!(reg.len(), 1);
        let snap = reg.snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].sql, "SELECT 1");
        assert_eq!(snap[0].state, "running");
        assert_eq!(snap[0].run_id, id.to_string());

        reg.complete(id, QueryOutcome::Success, Duration::from_millis(5));
        assert!(reg.is_empty());
        assert!(reg.snapshot().is_empty());
        // The finished query moves to history.
        let hist = reg.history();
        assert_eq!(hist.len(), 1);
        assert_eq!(hist[0].run_id, id.to_string());
        assert_eq!(hist[0].sql, "SELECT 1");
        assert_eq!(hist[0].outcome, "success");
    }

    #[test]
    fn user_is_captured_and_surfaced_in_snapshot_and_history() {
        let reg = QueryRegistry::new();
        let id = RunId::new();
        reg.start(id, "SELECT 1");
        // Before on_query_identity fires, user is unknown.
        assert_eq!(reg.snapshot()[0].user, None);
        // on_query_identity → attach_user surfaces it while running…
        reg.attach_user(id, "alice");
        assert_eq!(reg.snapshot()[0].user.as_deref(), Some("alice"));
        // …and it carries through to history on completion.
        reg.complete(id, QueryOutcome::Success, Duration::from_millis(1));
        assert_eq!(reg.history()[0].user.as_deref(), Some("alice"));
    }

    #[test]
    fn org_is_captured_and_surfaced_in_snapshot_and_history() {
        let reg = QueryRegistry::new();
        let id = RunId::new();
        reg.start(id, "SELECT 1");
        // Before attach_org fires, org is unknown.
        assert_eq!(reg.snapshot()[0].org, None);
        // attach_org surfaces it while running…
        reg.attach_org(id, Some("acme".to_string()));
        assert_eq!(reg.snapshot()[0].org.as_deref(), Some("acme"));
        // …and it carries through to history on completion.
        reg.complete(id, QueryOutcome::Success, Duration::from_millis(1));
        assert_eq!(reg.history()[0].org.as_deref(), Some("acme"));
    }

    #[test]
    fn attach_org_with_none_leaves_org_unset() {
        // A trust/default session resolves no org — attach_org(None) must
        // keep the field `None`, not panic or fabricate a value.
        let reg = QueryRegistry::new();
        let id = RunId::new();
        reg.start(id, "SELECT 1");
        reg.attach_org(id, None);
        assert_eq!(reg.snapshot()[0].org, None);
    }

    #[test]
    fn error_message_carries_to_history() {
        let reg = QueryRegistry::new();
        let id = RunId::new();
        reg.start(id, "SELECT * FROM missing");
        reg.attach_error(id, "table 'missing' not found");
        reg.complete(id, QueryOutcome::Error, Duration::from_millis(3));
        let h = reg.history();
        assert_eq!(h[0].outcome, "error");
        assert_eq!(h[0].error.as_deref(), Some("table 'missing' not found"));
    }

    #[test]
    fn cancelled_query_reports_cancelled_not_error() {
        let reg = QueryRegistry::new();
        let id = RunId::new();
        reg.start(id, "SELECT pg_sleep(60)");
        reg.attach_cancel(id, QueryHandle::detached());
        assert!(reg.cancel(&id.to_string()), "cancellable");
        // The aborted stream completes with an Error outcome from pgwire, but
        // because the operator cancelled it, history shows `cancelled`.
        reg.complete(id, QueryOutcome::Error, Duration::from_millis(5));
        assert_eq!(reg.history()[0].outcome, "cancelled");
    }

    #[test]
    fn successful_query_has_no_error_detail() {
        let reg = QueryRegistry::new();
        let id = RunId::new();
        reg.start(id, "SELECT 1");
        reg.complete(id, QueryOutcome::Success, Duration::from_millis(1));
        let h = reg.history();
        assert_eq!(h[0].outcome, "success");
        assert_eq!(h[0].error, None);
    }

    #[test]
    fn observer_on_query_error_attaches_message() {
        let reg = QueryRegistry::new();
        let obs = QueryRegistryObserver::new(reg.clone(), false, "dataglot", "public");
        let id = RunId::new();
        obs.on_query_start(id, "SELECT bad");
        obs.on_query_error(id, "type mismatch");
        obs.on_query_complete(
            id,
            "SELECT bad",
            None,
            QueryOutcome::Error,
            Duration::from_millis(2),
        );
        assert_eq!(reg.history()[0].error.as_deref(), Some("type mismatch"));
    }

    #[test]
    fn observer_on_query_identity_attaches_user() {
        let reg = QueryRegistry::new();
        let obs = QueryRegistryObserver::new(reg.clone(), false, "dataglot", "public");
        let id = RunId::new();
        obs.on_query_start(id, "SELECT 1");
        obs.on_query_identity(id, "svc_bi");
        assert_eq!(reg.snapshot()[0].user.as_deref(), Some("svc_bi"));
        // Outside a `with_session_org` scope the task-local is unset, so the
        // observer attaches org `None` (it never fabricates one).
        assert_eq!(reg.snapshot()[0].org, None);
    }

    #[test]
    fn history_is_newest_first_and_bounded() {
        let reg = QueryRegistry::new();
        // Push more than the cap; oldest should be evicted.
        for i in 0..(HISTORY_CAP + 5) {
            let id = RunId::new();
            reg.start(id, &format!("SELECT {i}"));
            let outcome = if i % 2 == 0 {
                QueryOutcome::Success
            } else {
                QueryOutcome::Error
            };
            reg.complete(id, outcome, Duration::from_millis(1));
        }
        let hist = reg.history();
        assert_eq!(hist.len(), HISTORY_CAP, "ring is bounded");
        // Newest first: the last-completed query is at the front.
        assert_eq!(hist[0].sql, format!("SELECT {}", HISTORY_CAP + 4));
    }

    #[tokio::test]
    async fn snapshot_orders_longest_running_first() {
        let reg = QueryRegistry::new();
        let older = RunId::new();
        let newer = RunId::new();
        reg.start(older, "SELECT /* older */ 1");
        // tokio::time::sleep, not std::thread::sleep — rule 11 (the
        // disallowed-methods lint bans blocking sleep even in tests).
        tokio::time::sleep(Duration::from_millis(8)).await;
        reg.start(newer, "SELECT /* newer */ 2");

        let snap = reg.snapshot();
        assert_eq!(snap.len(), 2);
        // Longest-running (older) first.
        assert_eq!(snap[0].run_id, older.to_string());
        assert_eq!(snap[1].run_id, newer.to_string());
        assert!(snap[0].elapsed_ms >= snap[1].elapsed_ms);
    }

    #[test]
    fn get_finds_by_run_id_string() {
        let reg = QueryRegistry::new();
        let id = RunId::new();
        reg.start(id, "SELECT 42");
        assert_eq!(reg.get(&id.to_string()).unwrap().sql, "SELECT 42");
        assert!(reg.get("does-not-exist").is_none());
    }

    #[test]
    fn sql_is_truncated_on_char_boundary() {
        let reg = QueryRegistry::new();
        let id = RunId::new();
        // Multi-byte chars straddling the limit must not panic or split.
        let long = "é".repeat(MAX_SQL_LEN); // 2 bytes each → 2*MAX bytes
        reg.start(id, &long);
        let got = &reg.snapshot()[0].sql;
        assert!(got.len() <= MAX_SQL_LEN);
        // Still valid UTF-8 (didn't split a char) — implicit: it's a String.
        assert!(got.chars().all(|c| c == 'é'));
    }

    #[test]
    fn observer_bridges_start_and_complete() {
        let reg = QueryRegistry::new();
        let obs = QueryRegistryObserver::new(reg.clone(), false, "dataglot", "public");
        let id = RunId::new();

        obs.on_query_start(id, "SELECT now()");
        assert_eq!(reg.len(), 1);

        obs.on_query_complete(
            id,
            "SELECT now()",
            None,
            QueryOutcome::Success,
            Duration::from_millis(3),
        );
        assert!(reg.is_empty());
    }

    #[test]
    fn cancel_returns_false_for_missing_or_handleless_query() {
        let reg = QueryRegistry::new();
        // Nothing running.
        assert!(!reg.cancel("does-not-exist"));
        // Started but no cancel handle attached yet → not cancellable.
        let id = RunId::new();
        reg.start(id, "SELECT 1");
        assert!(!reg.cancel(&id.to_string()));
    }

    #[test]
    fn cancel_fires_attached_handle() {
        let reg = QueryRegistry::new();
        let id = RunId::new();
        reg.start(id, "SELECT 1");
        reg.attach_cancel(id, QueryHandle::detached());
        // Found + fired.
        assert!(reg.cancel(&id.to_string()));
        // The entry stays until on_query_complete removes it (the aborted
        // query unwinds); a second cancel still finds the handle.
        assert!(reg.cancel(&id.to_string()));
    }

    #[test]
    fn observer_attaches_cancel_handle() {
        let reg = QueryRegistry::new();
        let obs = QueryRegistryObserver::new(reg.clone(), false, "dataglot", "public");
        let id = RunId::new();
        obs.on_query_start(id, "SELECT 1");
        assert!(!reg.cancel(&id.to_string()), "no handle yet");
        obs.on_query_cancellable(id, QueryHandle::detached());
        assert!(reg.cancel(&id.to_string()), "handle attached → cancellable");
    }

    #[test]
    fn observer_wants_plan_mirrors_capture_flag() {
        // wants_plan gates the (non-free) pre-execution plan capture, so
        // it must be off unless source-capture was explicitly enabled.
        assert!(
            !QueryRegistryObserver::new(QueryRegistry::new(), false, "dataglot", "public")
                .wants_plan()
        );
        assert!(
            QueryRegistryObserver::new(QueryRegistry::new(), true, "dataglot", "public")
                .wants_plan()
        );
    }

    fn pushdown(source: &str, rows: u64) -> PushdownStat {
        PushdownStat {
            source: source.to_string(),
            kind: "snowflake".to_string(),
            sql: format!("SELECT * FROM {source}.t"),
            rows,
            batches: 1,
            elapsed_ms: 42,
            outcome: dataglot_core::PushdownOutcome::Completed,
        }
    }

    #[test]
    fn pushdowns_surface_in_snapshot_and_carry_to_history() {
        let reg = QueryRegistry::new();
        let id = RunId::new();
        reg.start(id, "SELECT * FROM sf.t");
        // The PushdownSink impl routes here.
        reg.record(id, pushdown("sf", 100));
        let snap = reg.snapshot();
        assert_eq!(snap[0].pushdowns.len(), 1);
        assert_eq!(snap[0].pushdowns[0].source, "sf");
        assert_eq!(snap[0].pushdowns[0].rows, 100);
        // Carries through to history on completion, and is retrievable via
        // history_get (the detail endpoint's post-completion lookup).
        reg.complete(id, QueryOutcome::Success, Duration::from_millis(5));
        let done = reg.history_get(&id.to_string()).expect("in history");
        assert_eq!(done.pushdowns.len(), 1);
        assert_eq!(done.pushdowns[0].rows, 100);
    }

    #[test]
    fn pushdowns_are_bounded_per_query() {
        let reg = QueryRegistry::new();
        let id = RunId::new();
        reg.start(id, "SELECT 1");
        for i in 0..(MAX_PUSHDOWNS_PER_QUERY + 10) {
            reg.record(id, pushdown(&format!("s{i}"), i as u64));
        }
        assert_eq!(reg.snapshot()[0].pushdowns.len(), MAX_PUSHDOWNS_PER_QUERY);
    }

    #[test]
    fn pushdown_sql_is_bounded_on_char_boundary() {
        let reg = QueryRegistry::new();
        let id = RunId::new();
        reg.start(id, "SELECT 1");
        // A pathological rendered statement must not grow the entry without
        // bound; multi-byte chars straddling the limit must not split.
        let mut stat = pushdown("sf", 1);
        stat.sql = "é".repeat(MAX_SQL_LEN); // 2 bytes each → 2*MAX bytes
        reg.record(id, stat);
        let stored = &reg.snapshot()[0].pushdowns[0].sql;
        assert!(stored.len() <= MAX_SQL_LEN);
        assert!(stored.chars().all(|c| c == 'é'));
    }

    #[test]
    fn pushdown_late_attaches_to_history_after_completion() {
        //  distributed: executor task-metrics arrive after the query
        // completed and moved to history; the stat must update the finished
        // entry in place, not be dropped.
        let reg = QueryRegistry::new();
        let id = RunId::new();
        reg.start(id, "SELECT * FROM sf.t");
        reg.complete(id, QueryOutcome::Success, Duration::from_millis(5));
        assert!(reg.is_empty(), "moved to history");
        assert!(reg
            .history_get(&id.to_string())
            .unwrap()
            .pushdowns
            .is_empty());
        // Late stat (via the PushdownSink impl) lands on the history entry.
        reg.record(id, pushdown("sf", 42));
        let done = reg.history_get(&id.to_string()).expect("still in history");
        assert_eq!(done.pushdowns.len(), 1);
        assert_eq!(done.pushdowns[0].rows, 42);
    }

    #[test]
    fn pushdown_for_unknown_query_is_dropped() {
        // A late Drop-time PARTIAL after the query was removed must not panic
        // or resurrect an entry.
        let reg = QueryRegistry::new();
        reg.record(RunId::new(), pushdown("sf", 1));
        assert!(reg.is_empty());
    }

    #[test]
    fn attach_sources_surfaces_in_snapshot() {
        let reg = QueryRegistry::new();
        let id = RunId::new();
        reg.start(id, "SELECT * FROM pg.public.t JOIN sf.public.u USING (k)");
        reg.attach_sources(id, vec!["pg".to_string(), "sf".to_string()]);
        assert_eq!(reg.snapshot()[0].sources, vec!["pg", "sf"]);
    }

    #[tokio::test]
    async fn on_query_plan_resolves_bare_table_to_session_default_catalog() {
        // Regression for the dashboard bug where a bare `nation` submitted in
        // a `snowflake`/`tpch_sf1` session surfaced as source `"default"`.
        // The observer now resolves catalog/schema-less references against the
        // session defaults it was constructed with, so the dashboard's
        // per-query source list shows the real federated catalog.
        use datafusion::arrow::datatypes::{DataType, Field, Schema};
        use datafusion::datasource::MemTable;
        use datafusion::prelude::SessionContext;

        let ctx = SessionContext::new();
        let schema = Arc::new(Schema::new(vec![Field::new(
            "n_name",
            DataType::Utf8,
            true,
        )]));
        ctx.register_table(
            "nation",
            Arc::new(MemTable::try_new(schema, vec![vec![]]).unwrap()),
        )
        .expect("register");
        let plan = ctx
            .table("nation")
            .await
            .expect("table")
            .into_unoptimized_plan();

        let reg = QueryRegistry::new();
        let obs = QueryRegistryObserver::new(reg.clone(), true, "snowflake", "tpch_sf1");
        let id = RunId::new();
        obs.on_query_start(id, "select n_name from nation");
        obs.on_query_plan(id, Arc::new(plan));

        assert_eq!(
            reg.snapshot()[0].sources,
            vec!["snowflake".to_string()],
            "bare `nation` should resolve to the session default catalog, not `default`",
        );
    }

    #[test]
    fn debug_does_not_leak_sql() {
        let reg = QueryRegistry::new();
        reg.start(RunId::new(), "SELECT secret_column FROM t");
        let dbg = format!("{reg:?}");
        assert!(dbg.contains("active"));
        assert!(!dbg.contains("secret_column"));
    }
}

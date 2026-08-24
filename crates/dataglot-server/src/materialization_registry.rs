//! Runtime status tracking for materialized-product refreshes ( / the
//! operations-dashboard materialization panel).
//!
//! The refresh scheduler (`materialization::RefreshScheduler`) drives each
//! `Materialized` derived product on its cadence but, on its own, only emits
//! `tracing` logs — an operator can't see *from the dashboard* whether a
//! product is fresh, how many rows it last wrote, or when it will run again.
//!
//! This registry is the missing observable surface. It's a cheap-to-clone,
//! `Arc`-backed map keyed by product name; the refresh closures built in
//! `materialization::build_refresh_jobs` write a start/success/failure
//! record on every attempt, and `GET /api/materialization` serializes a
//! snapshot. Products are seeded (`Pending`) at job-build time so the dashboard
//! lists every declared materialization from boot, before the first run.
//!
//! Only redacted status is stored — product name, target, counts, timings, and
//! the (already credential-scrubbed) error string (CLAUDE.md rule 12).

use std::collections::HashMap;
use std::sync::{Arc, PoisonError, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

/// Lifecycle of a product's most-recent refresh attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RefreshState {
    /// Declared but not yet run in this process.
    Pending,
    /// A refresh is currently executing.
    Running,
    /// The most-recent refresh completed and promoted a new snapshot.
    Success,
    /// The most-recent refresh failed; the prior snapshot is retained.
    Error,
}

/// One materialized product's live status — the serialized shape behind
/// `GET /api/materialization`.
#[derive(Debug, Clone, Serialize)]
pub struct MaterializationStatus {
    /// Derived-product name (the registry key).
    pub product: String,
    /// Fully-qualified write target, `warehouse.namespace.table`.
    pub target: String,
    /// Configured refresh cadence, in seconds.
    pub interval_secs: u64,
    /// State of the most-recent attempt.
    pub state: RefreshState,
    /// When the most-recent attempt started (Unix epoch ms).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_started_at_ms: Option<u64>,
    /// When the most-recent attempt finished, success or failure (epoch ms).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_finished_at_ms: Option<u64>,
    /// Wall-clock of the most-recent finished attempt, in milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_duration_ms: Option<u64>,
    /// Rows written by the most-recent successful refresh.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_rows: Option<u64>,
    /// Data files written by the most-recent successful refresh.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_data_files: Option<u64>,
    /// Redacted error from the most-recent failed attempt (cleared on success).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    /// Approximate next run (`last_finished + interval`), epoch ms. Absent until
    /// the first attempt finishes. Approximate: the scheduler ticks on a fixed
    /// cadence from boot, not from the previous finish.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_run_at_ms: Option<u64>,
    /// Total attempts observed (successes + failures).
    pub runs: u64,
    /// How many of those attempts failed.
    pub failures: u64,
}

impl MaterializationStatus {
    fn seed(product: String, target: String, interval_secs: u64) -> Self {
        Self {
            product,
            target,
            interval_secs,
            state: RefreshState::Pending,
            last_started_at_ms: None,
            last_finished_at_ms: None,
            last_duration_ms: None,
            last_rows: None,
            last_data_files: None,
            last_error: None,
            next_run_at_ms: None,
            runs: 0,
            failures: 0,
        }
    }
}

/// Shared, cheap-to-clone tracker of materialization-refresh status. Clones
/// share one backing map, so the refresh closures and the HTTP handler observe
/// the same state.
#[derive(Clone, Default)]
pub struct MaterializationRegistry {
    inner: Arc<RwLock<HashMap<String, MaterializationStatus>>>,
}

impl MaterializationRegistry {
    /// An empty registry — nothing materialized (single-node demos / tests).
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Seed (or update the static fields of) a product's entry at job-build
    /// time, so the dashboard lists it as `Pending` before the first run.
    pub fn register(&self, product: &str, target: &str, interval_secs: u64) {
        let mut map = self.inner.write().unwrap_or_else(PoisonError::into_inner);
        map.entry(product.to_string())
            .and_modify(|s| {
                s.target = target.to_string();
                s.interval_secs = interval_secs;
            })
            .or_insert_with(|| {
                MaterializationStatus::seed(product.to_string(), target.to_string(), interval_secs)
            });
    }

    /// Mark a product's refresh as started.
    pub fn record_start(&self, product: &str) {
        self.mutate(product, |s| {
            s.state = RefreshState::Running;
            s.last_started_at_ms = Some(now_ms());
        });
    }

    /// Record a successful refresh: `rows`/`data_files` written and how long it
    /// took. Clears any prior error and advances the run counter.
    pub fn record_success(&self, product: &str, rows: usize, data_files: usize, duration_ms: u64) {
        let finished = now_ms();
        self.mutate(product, |s| {
            s.state = RefreshState::Success;
            s.last_finished_at_ms = Some(finished);
            s.last_duration_ms = Some(duration_ms);
            s.last_rows = Some(rows as u64);
            s.last_data_files = Some(data_files as u64);
            s.last_error = None;
            s.next_run_at_ms = Some(finished + s.interval_secs.saturating_mul(1000));
            s.runs += 1;
        });
    }

    /// Record a failed refresh with a (already credential-scrubbed) message.
    /// The prior snapshot stays intact; only status is updated.
    pub fn record_failure(&self, product: &str, error: String, duration_ms: u64) {
        let finished = now_ms();
        self.mutate(product, |s| {
            s.state = RefreshState::Error;
            s.last_finished_at_ms = Some(finished);
            s.last_duration_ms = Some(duration_ms);
            s.last_error = Some(error);
            s.next_run_at_ms = Some(finished + s.interval_secs.saturating_mul(1000));
            s.runs += 1;
            s.failures += 1;
        });
    }

    /// A snapshot of every tracked product, sorted by name for a stable UI.
    #[must_use]
    pub fn snapshot(&self) -> Vec<MaterializationStatus> {
        let mut out: Vec<MaterializationStatus> = {
            let map = self.inner.read().unwrap_or_else(PoisonError::into_inner);
            map.values().cloned().collect()
        };
        out.sort_by(|a, b| a.product.cmp(&b.product));
        out
    }

    /// Apply `f` to a product's entry if it exists (a refresh for an
    /// unregistered product is a no-op rather than a panic).
    fn mutate(&self, product: &str, f: impl FnOnce(&mut MaterializationStatus)) {
        let mut map = self.inner.write().unwrap_or_else(PoisonError::into_inner);
        if let Some(entry) = map.get_mut(product) {
            f(entry);
        }
    }
}

/// Current wall-clock time as Unix epoch milliseconds (saturating).
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| u64::try_from(d.as_millis()).ok())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_registry_snapshots_nothing() {
        assert!(MaterializationRegistry::empty().snapshot().is_empty());
    }

    #[test]
    fn register_seeds_a_pending_entry() {
        let reg = MaterializationRegistry::empty();
        reg.register("active_users", "wh.mart.active_users", 900);
        let snap = reg.snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].product, "active_users");
        assert_eq!(snap[0].target, "wh.mart.active_users");
        assert_eq!(snap[0].interval_secs, 900);
        assert_eq!(snap[0].state, RefreshState::Pending);
        assert_eq!(snap[0].runs, 0);
        assert!(snap[0].next_run_at_ms.is_none());
    }

    #[test]
    fn success_records_counts_and_derives_next_run() {
        let reg = MaterializationRegistry::empty();
        reg.register("p", "wh.mart.p", 60);
        reg.record_start("p");
        reg.record_success("p", 42, 3, 120);
        let s = &reg.snapshot()[0];
        assert_eq!(s.state, RefreshState::Success);
        assert_eq!(s.last_rows, Some(42));
        assert_eq!(s.last_data_files, Some(3));
        assert_eq!(s.last_duration_ms, Some(120));
        assert_eq!(s.runs, 1);
        assert_eq!(s.failures, 0);
        assert!(s.last_error.is_none());
        // next_run = last_finished + 60s.
        let finished = s.last_finished_at_ms.unwrap();
        assert_eq!(s.next_run_at_ms, Some(finished + 60_000));
    }

    #[test]
    fn failure_records_error_and_bumps_failure_counter() {
        let reg = MaterializationRegistry::empty();
        reg.register("p", "wh.mart.p", 60);
        reg.record_failure("p", "planning refresh query failed".to_string(), 15);
        let s = &reg.snapshot()[0];
        assert_eq!(s.state, RefreshState::Error);
        assert_eq!(
            s.last_error.as_deref(),
            Some("planning refresh query failed")
        );
        assert_eq!(s.runs, 1);
        assert_eq!(s.failures, 1);
    }

    #[test]
    fn success_after_failure_clears_the_error() {
        let reg = MaterializationRegistry::empty();
        reg.register("p", "wh.mart.p", 60);
        reg.record_failure("p", "boom".to_string(), 10);
        reg.record_success("p", 7, 1, 30);
        let s = &reg.snapshot()[0];
        assert_eq!(s.state, RefreshState::Success);
        assert!(s.last_error.is_none(), "a later success clears the error");
        assert_eq!(s.runs, 2);
        assert_eq!(s.failures, 1, "the historical failure count is retained");
    }

    #[test]
    fn recording_an_unregistered_product_is_a_noop() {
        let reg = MaterializationRegistry::empty();
        reg.record_success("ghost", 1, 1, 1);
        assert!(reg.snapshot().is_empty());
    }
}

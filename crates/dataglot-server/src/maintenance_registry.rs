//! Runtime status tracking for scheduled warehouse maintenance — compaction
//! and orphan-cleanup (Phase 4 Task 03) — for the operations
//! dashboard.
//!
//! Like materialization refreshes, maintenance jobs run on the shared
//! `materialization::RefreshScheduler` but on their own emit only `tracing`
//! logs, so an operator can't see from the dashboard whether the lakehouse is
//! being kept tidy. This registry is the observable surface: the closures
//! built in `maintenance::build_compaction_jobs` /
//! `maintenance::build_orphan_sweep_jobs` write a start/success/failure record
//! on every run, and `GET /api/maintenance` serializes a
//! snapshot. Jobs are seeded (`Pending`) at build time so every configured
//! maintenance task is listed from boot.
//!
//! Only redacted status is stored — job label, target, counts, timings, and
//! the (already credential-scrubbed) error string (CLAUDE.md rule 12).

use std::collections::HashMap;
use std::sync::{Arc, PoisonError, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

pub use crate::materialization_registry::RefreshState;

/// Which kind of maintenance a tracked job performs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MaintenanceKind {
    /// Full-table rewrite that consolidates data files (Trino `OPTIMIZE`).
    Compaction,
    /// Sweep of stale staging/parked maintenance tables in a namespace.
    OrphanCleanup,
}

/// One maintenance job's live status — the serialized shape behind
/// `GET /api/maintenance`.
#[derive(Debug, Clone, Serialize)]
pub struct MaintenanceStatus {
    /// Job label (the registry key), e.g. `compact:wh.lake.events`.
    pub job: String,
    /// What this job does.
    pub kind: MaintenanceKind,
    /// The target it acts on: `warehouse.namespace.table` (compaction) or
    /// `warehouse.namespace` (orphan cleanup).
    pub target: String,
    /// Configured cadence, in seconds.
    pub interval_secs: u64,
    /// State of the most-recent run.
    pub state: RefreshState,
    /// When the most-recent run started (Unix epoch ms).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_started_at_ms: Option<u64>,
    /// When the most-recent run finished (Unix epoch ms).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_finished_at_ms: Option<u64>,
    /// Wall-clock of the most-recent finished run, in milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_duration_ms: Option<u64>,
    /// Rows preserved through the most-recent compaction (compaction only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_rows: Option<u64>,
    /// Data files after the most-recent compaction — the consolidation result
    /// (compaction only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_data_files: Option<u64>,
    /// Stale tables dropped by the most-recent sweep (orphan cleanup only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_swept: Option<u64>,
    /// Redacted error from the most-recent failed run (cleared on success).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    /// Approximate next run (`last_finished + interval`), epoch ms.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_run_at_ms: Option<u64>,
    /// Total runs observed.
    pub runs: u64,
    /// How many of those runs failed.
    pub failures: u64,
}

impl MaintenanceStatus {
    fn seed(job: String, kind: MaintenanceKind, target: String, interval_secs: u64) -> Self {
        Self {
            job,
            kind,
            target,
            interval_secs,
            state: RefreshState::Pending,
            last_started_at_ms: None,
            last_finished_at_ms: None,
            last_duration_ms: None,
            last_rows: None,
            last_data_files: None,
            last_swept: None,
            last_error: None,
            next_run_at_ms: None,
            runs: 0,
            failures: 0,
        }
    }
}

/// Shared, cheap-to-clone tracker of warehouse-maintenance status. Clones
/// share one backing map, so the job closures and the HTTP handler observe the
/// same state.
#[derive(Clone, Default)]
pub struct MaintenanceRegistry {
    inner: Arc<RwLock<HashMap<String, MaintenanceStatus>>>,
}

impl MaintenanceRegistry {
    /// An empty registry — no maintenance configured (tests / simple demos).
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Seed (or update the static fields of) a job's entry at build time, so
    /// the dashboard lists it as `Pending` before its first run.
    pub fn register(&self, job: &str, kind: MaintenanceKind, target: &str, interval_secs: u64) {
        let mut map = self.inner.write().unwrap_or_else(PoisonError::into_inner);
        map.entry(job.to_string())
            .and_modify(|s| {
                s.kind = kind;
                s.target = target.to_string();
                s.interval_secs = interval_secs;
            })
            .or_insert_with(|| {
                MaintenanceStatus::seed(job.to_string(), kind, target.to_string(), interval_secs)
            });
    }

    /// Mark a job's run as started.
    pub fn record_start(&self, job: &str) {
        self.mutate(job, |s| {
            s.state = RefreshState::Running;
            s.last_started_at_ms = Some(now_ms());
        });
    }

    /// Record a successful compaction run (rows preserved + consolidated file
    /// count) and how long it took.
    pub fn record_compaction(&self, job: &str, rows: usize, data_files: usize, duration_ms: u64) {
        let finished = now_ms();
        self.mutate(job, |s| {
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

    /// Record a successful orphan-cleanup sweep (`swept` stale tables dropped).
    pub fn record_sweep(&self, job: &str, swept: usize, duration_ms: u64) {
        let finished = now_ms();
        self.mutate(job, |s| {
            s.state = RefreshState::Success;
            s.last_finished_at_ms = Some(finished);
            s.last_duration_ms = Some(duration_ms);
            s.last_swept = Some(swept as u64);
            s.last_error = None;
            s.next_run_at_ms = Some(finished + s.interval_secs.saturating_mul(1000));
            s.runs += 1;
        });
    }

    /// Record a failed maintenance run with a (credential-scrubbed) message.
    pub fn record_failure(&self, job: &str, error: String, duration_ms: u64) {
        let finished = now_ms();
        self.mutate(job, |s| {
            s.state = RefreshState::Error;
            s.last_finished_at_ms = Some(finished);
            s.last_duration_ms = Some(duration_ms);
            s.last_error = Some(error);
            s.next_run_at_ms = Some(finished + s.interval_secs.saturating_mul(1000));
            s.runs += 1;
            s.failures += 1;
        });
    }

    /// A snapshot of every tracked job, sorted by label for a stable UI.
    #[must_use]
    pub fn snapshot(&self) -> Vec<MaintenanceStatus> {
        let mut out: Vec<MaintenanceStatus> = {
            let map = self.inner.read().unwrap_or_else(PoisonError::into_inner);
            map.values().cloned().collect()
        };
        out.sort_by(|a, b| a.job.cmp(&b.job));
        out
    }

    /// Apply `f` to a job's entry if it exists (a run for an unregistered job
    /// is a no-op rather than a panic).
    fn mutate(&self, job: &str, f: impl FnOnce(&mut MaintenanceStatus)) {
        let mut map = self.inner.write().unwrap_or_else(PoisonError::into_inner);
        if let Some(entry) = map.get_mut(job) {
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
        assert!(MaintenanceRegistry::empty().snapshot().is_empty());
    }

    #[test]
    fn compaction_run_records_rows_and_files() {
        let reg = MaintenanceRegistry::empty();
        reg.register(
            "compact:wh.lake.events",
            MaintenanceKind::Compaction,
            "wh.lake.events",
            21_600,
        );
        reg.record_start("compact:wh.lake.events");
        reg.record_compaction("compact:wh.lake.events", 1000, 2, 450);
        let s = &reg.snapshot()[0];
        assert_eq!(s.kind, MaintenanceKind::Compaction);
        assert_eq!(s.state, RefreshState::Success);
        assert_eq!(s.last_rows, Some(1000));
        assert_eq!(s.last_data_files, Some(2));
        assert_eq!(s.last_swept, None);
        assert_eq!(s.runs, 1);
        assert!(s.next_run_at_ms.is_some());
    }

    #[test]
    fn sweep_run_records_dropped_count() {
        let reg = MaintenanceRegistry::empty();
        reg.register(
            "orphan-sweep:wh.lake",
            MaintenanceKind::OrphanCleanup,
            "wh.lake",
            3600,
        );
        reg.record_start("orphan-sweep:wh.lake");
        reg.record_sweep("orphan-sweep:wh.lake", 4, 90);
        let s = &reg.snapshot()[0];
        assert_eq!(s.kind, MaintenanceKind::OrphanCleanup);
        assert_eq!(s.last_swept, Some(4));
        assert_eq!(s.last_data_files, None);
        assert_eq!(s.runs, 1);
    }

    #[test]
    fn failure_bumps_counters_and_records_error() {
        let reg = MaintenanceRegistry::empty();
        reg.register(
            "compact:wh.lake.t",
            MaintenanceKind::Compaction,
            "wh.lake.t",
            60,
        );
        reg.record_failure(
            "compact:wh.lake.t",
            "concurrent modification".to_string(),
            12,
        );
        let s = &reg.snapshot()[0];
        assert_eq!(s.state, RefreshState::Error);
        assert_eq!(s.last_error.as_deref(), Some("concurrent modification"));
        assert_eq!(s.runs, 1);
        assert_eq!(s.failures, 1);
    }

    #[test]
    fn success_after_failure_clears_error_keeps_failure_count() {
        let reg = MaintenanceRegistry::empty();
        reg.register("j", MaintenanceKind::Compaction, "wh.ns.t", 60);
        reg.record_failure("j", "boom".to_string(), 5);
        reg.record_compaction("j", 10, 1, 20);
        let s = &reg.snapshot()[0];
        assert_eq!(s.state, RefreshState::Success);
        assert!(s.last_error.is_none());
        assert_eq!(s.runs, 2);
        assert_eq!(s.failures, 1);
    }
}

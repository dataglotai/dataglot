//! Cluster monitoring proxy — the engine-served backend of the
//! operational dashboard's Cluster view.
//!
//! When the server boots Ballista with `ballista.rest_api_port` set, the
//! scheduler serves its observability REST API on loopback: `/api/state`,
//! `/api/executors`, `/api/jobs`, `/api/job/{id}/stages`,
//! `/api/job/{id}/dot[_svg]`. [`ClusterMonitor`] proxies a curated slice
//! of it so the dashboard has a same-origin endpoint (the scheduler's
//! router sets no CORS) and one "is monitoring even available?" answer.
//!
//! This logic previously lived only in the dev testbench
//! (`dataglot-testbench::cluster`); slice 2 promotes it into the engine
//! so the dashboard ships with `dataglot-server` itself.
//!
//! Upstream payloads are forwarded as raw JSON (`serde_json::Value`)
//! rather than re-typed: the shapes belong to Ballista and re-declaring
//! them here would add a drift surface for zero gain — the UI consumes
//! them read-only.
//!
//! **Failure posture**: an unreachable scheduler (single-node run,
//! monitoring disabled, or the server just restarting) is a *state*, not
//! an error — [`summary`](ClusterMonitor::summary) reports
//! `available: false` and the dashboard renders guidance instead of an
//! error. Timeouts are short (1s) so a dead monitor can't stall the
//! UI's poll loop.

use std::time::Duration;

use serde::Serialize;

/// One poll's view of the cluster, combined from the scheduler's
/// `/api/state` + `/api/executors` + `/api/jobs` so the dashboard needs
/// a single request per tick.
#[derive(Debug, Clone, Serialize)]
pub struct ClusterSummary {
    /// `true` when the scheduler REST API answered. `false` covers both
    /// "ballista not configured / no `rest_api_port`" and "configured
    /// but unreachable" — `note` distinguishes them for the UI copy.
    pub available: bool,
    /// Human-readable reason when `available` is `false`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// Raw `/api/state` payload (scheduler version, boot time, policy).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scheduler: Option<serde_json::Value>,
    /// Raw `/api/executors` payload — one entry per registered executor
    /// (id, host, port, task slots, last-seen).
    pub executors: Vec<serde_json::Value>,
    /// Raw `/api/jobs` payload, **capped** to the most-recent
    /// `MAX_JOBS` by start time (newest first). The scheduler retains
    /// every finished job — a benchmark sweep can leave tens of thousands
    /// — so returning them all floods the payload and hangs the dashboard.
    /// The cap keeps the poll bounded; [`Self::jobs_total`] carries the
    /// true count for the UI.
    pub jobs: Vec<serde_json::Value>,
    /// Total jobs the scheduler is holding (before the `MAX_JOBS` cap),
    /// so the UI can render "showing N of M".
    pub jobs_total: usize,
    /// Count of non-terminal (running / queued) jobs across **all** jobs,
    /// computed before the cap so the "running jobs" stat stays accurate.
    pub running_jobs: usize,
}

impl ClusterSummary {
    fn unavailable(note: impl Into<String>) -> Self {
        Self {
            available: false,
            note: Some(note.into()),
            scheduler: None,
            executors: Vec::new(),
            jobs: Vec::new(),
            jobs_total: 0,
            running_jobs: 0,
        }
    }
}

/// Cap on jobs returned per poll. The scheduler keeps every finished job;
/// the dashboard only needs the running ones plus recent history, so we
/// return the newest this many and surface the true total separately.
const MAX_JOBS: usize = 100;

/// A job is terminal when its status reads completed / failed / cancelled.
/// Used to count running jobs over the full set before capping.
fn job_is_terminal(job: &serde_json::Value) -> bool {
    let s = job
        .get("job_status")
        .or_else(|| job.get("status"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
        .to_ascii_lowercase();
    s.contains("completed")
        || s.contains("success")
        || s.contains("failed")
        || s.contains("error")
        || s.contains("cancel")
}

/// Scheduler `start_time` (epoch ms) for newest-first ordering; 0 when absent.
fn job_start(job: &serde_json::Value) -> i64 {
    job.get("start_time")
        .or_else(|| job.get("start"))
        .and_then(serde_json::Value::as_i64)
        .unwrap_or(0)
}

/// Count running jobs over the full set, then return the newest `MAX_JOBS`
/// (running jobs sort to the top by start time). Split out from
/// [`ClusterMonitor::summary`] so the cap + counts are unit-testable without
/// a live scheduler. Returns `(capped_jobs, total, running)`.
fn summarize_jobs(mut jobs: Vec<serde_json::Value>) -> (Vec<serde_json::Value>, usize, usize) {
    let jobs_total = jobs.len();
    let running_jobs = jobs.iter().filter(|j| !job_is_terminal(j)).count();
    jobs.sort_by_key(|j| std::cmp::Reverse(job_start(j)));
    jobs.truncate(MAX_JOBS);
    (jobs, jobs_total, running_jobs)
}

/// Proxy to the Ballista scheduler's observability REST API. Cheap to
/// clone (the inner `reqwest::Client` is `Arc`-backed), so a copy can be
/// handed to the metrics/dashboard axum router.
#[derive(Debug, Clone)]
pub struct ClusterMonitor {
    /// Scheduler API base URL (no trailing slash), `None` when Ballista
    /// monitoring isn't configured (single-node, or no `rest_api_port`).
    base_url: Option<String>,
    client: reqwest::Client,
}

impl ClusterMonitor {
    /// Build from an explicit base URL (trailing slash trimmed). `None`
    /// disables the proxy (reports `available: false`).
    #[must_use]
    pub fn new(base_url: Option<String>) -> Self {
        Self {
            base_url: base_url.map(|u| u.trim_end_matches('/').to_string()),
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(1))
                .build()
                .unwrap_or_default(),
        }
    }

    /// Build from the server's Ballista `rest_api_port`. The scheduler
    /// binds its REST API on loopback (see `crate::ballista`), so we dial
    /// `http://127.0.0.1:{port}`. `None` port ⇒ monitoring disabled.
    #[must_use]
    pub fn from_rest_api_port(port: Option<u16>) -> Self {
        Self::new(port.map(|p| format!("http://127.0.0.1:{p}")))
    }

    /// Whether a scheduler API was configured at all (regardless of
    /// current reachability).
    #[must_use]
    pub fn configured(&self) -> bool {
        self.base_url.is_some()
    }

    /// One combined poll: `/api/state` + `/api/executors` + `/api/jobs`.
    pub async fn summary(&self) -> ClusterSummary {
        let Some(base) = &self.base_url else {
            return ClusterSummary::unavailable(
                "cluster monitoring not configured — run distributed with \
                 `ballista.rest_api_port` set",
            );
        };
        let Ok(state) = self.get_json(&format!("{base}/api/state")).await else {
            return ClusterSummary::unavailable(format!(
                "scheduler API at {base} not answering — the server may be \
                 single-node, restarting, or monitoring is disabled"
            ));
        };
        let executors = self
            .get_json(&format!("{base}/api/executors"))
            .await
            .ok()
            .and_then(|v| v.as_array().cloned())
            .unwrap_or_default();
        let jobs = self
            .get_json(&format!("{base}/api/jobs"))
            .await
            .ok()
            .and_then(|v| v.as_array().cloned())
            .unwrap_or_default();
        let (jobs, jobs_total, running_jobs) = summarize_jobs(jobs);
        ClusterSummary {
            available: true,
            note: None,
            scheduler: Some(state),
            executors,
            jobs,
            jobs_total,
            running_jobs,
        }
    }

    /// Passthrough: per-stage progress for one job
    /// (`/api/job/{id}/stages`). `None` when unconfigured/unreachable.
    pub async fn job_stages(&self, job_id: &str) -> Option<serde_json::Value> {
        let base = self.base_url.as_ref()?;
        self.get_json(&format!("{base}/api/job/{job_id}/stages"))
            .await
            .ok()
    }

    /// Passthrough: the job's execution graph as `GraphViz` DOT text
    /// (`/api/job/{id}/dot`). `None` when unconfigured/unreachable.
    pub async fn job_dot(&self, job_id: &str) -> Option<String> {
        let base = self.base_url.as_ref()?;
        let resp = self
            .client
            .get(format!("{base}/api/job/{job_id}/dot"))
            .send()
            .await
            .ok()?;
        if !resp.status().is_success() {
            return None;
        }
        resp.text().await.ok()
    }

    async fn get_json(&self, url: &str) -> Result<serde_json::Value, reqwest::Error> {
        self.client
            .get(url)
            .send()
            .await?
            .error_for_status()?
            .json::<serde_json::Value>()
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn summary_unavailable_when_not_configured() {
        let m = ClusterMonitor::new(None);
        assert!(!m.configured());
        let s = m.summary().await;
        assert!(!s.available);
        assert!(s.note.is_some());
        assert!(s.executors.is_empty());
        assert!(s.jobs.is_empty());
    }

    #[tokio::test]
    async fn summary_unavailable_when_scheduler_unreachable() {
        // Port 9 (discard) refuses/kills quickly → not answering.
        let m = ClusterMonitor::new(Some("http://127.0.0.1:9".to_string()));
        assert!(m.configured());
        let s = m.summary().await;
        assert!(!s.available);
        assert!(s.note.unwrap().contains("not answering"));
    }

    #[test]
    fn from_rest_api_port_builds_loopback_url_or_none() {
        assert!(!ClusterMonitor::from_rest_api_port(None).configured());
        let m = ClusterMonitor::from_rest_api_port(Some(50060));
        assert_eq!(m.base_url.as_deref(), Some("http://127.0.0.1:50060"));
    }

    #[test]
    fn new_trims_trailing_slash() {
        let m = ClusterMonitor::new(Some("http://x:1/".to_string()));
        assert_eq!(m.base_url.as_deref(), Some("http://x:1"));
    }

    #[test]
    fn unavailable_summary_serializes_without_null_noise() {
        let v = serde_json::to_value(ClusterSummary::unavailable("why")).unwrap();
        assert_eq!(v["available"], false);
        assert_eq!(v["note"], "why");
        // scheduler is skipped when None (no `"scheduler":null`).
        assert!(v.get("scheduler").is_none());
        assert!(v["executors"].as_array().unwrap().is_empty());
    }

    #[test]
    fn summarize_jobs_caps_and_counts() {
        // Simulate a sweep leaving many jobs: 250 total, 3 running.
        let mut jobs: Vec<serde_json::Value> = Vec::new();
        for i in 0..250 {
            let terminal = i >= 3; // first 3 are Running, rest Completed
            jobs.push(serde_json::json!({
                "job_id": format!("j{i}"),
                "job_status": if terminal { "Completed. Elapsed time: 5 ms." } else { "Running" },
                // Running jobs get the latest start times so they survive the cap.
                "start_time": if terminal { i } else { 1_000_000 + i },
            }));
        }
        let (capped, total, running) = summarize_jobs(jobs);
        assert_eq!(total, 250, "total is the pre-cap count");
        assert_eq!(running, 3, "running counted over the full set");
        assert_eq!(capped.len(), MAX_JOBS, "payload capped");
        // Newest-first: the running jobs (highest start_time) lead.
        assert_eq!(capped[0]["job_status"], "Running");
        assert!(!job_is_terminal(&capped[0]));
    }

    #[test]
    fn small_job_sets_are_returned_whole() {
        let jobs = vec![
            serde_json::json!({"job_id": "a", "job_status": "Running", "start_time": 2}),
            serde_json::json!({"job_id": "b", "job_status": "Completed.", "start_time": 1}),
        ];
        let (capped, total, running) = summarize_jobs(jobs);
        assert_eq!((capped.len(), total, running), (2, 2, 1));
    }
}

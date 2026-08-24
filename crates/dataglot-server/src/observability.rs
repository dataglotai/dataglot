//! Observability primitives — tracing init, Prometheus metrics, and the
//! `/metrics` + `/health` HTTP endpoint.
//!
//! This module is the single boundary at which Dataglot exposes its
//! operational telemetry. It does three things:
//!
//! 1. Initializes `tracing-subscriber` with either a human-readable or JSON
//!    formatter, both stamped with ISO-8601 UTC timestamps.
//! 2. Owns a process-local Prometheus `Registry` and registers the baseline
//!    metric set used by the server.
//! 3. Spawns an axum HTTP listener that serves `GET /metrics` (Prometheus
//!    text exposition format) and `GET /health`.
//!
//! Per hard rule 5 the server crate does not reach into other crates to
//! instrument them. Per-query counters require a hook in `dataglot-pgwire`
//! that does not yet exist; see [`Metrics::queries_total`] for a TODO marker.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use axum::extract::{Path, State};
use axum::http::{header, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};

use crate::cluster::ClusterMonitor;
use crate::query_registry::QueryRegistry;
use crate::session_registry::SessionRegistry;
use prometheus::{
    Encoder, Gauge, HistogramOpts, HistogramVec, IntCounterVec, IntGauge, IntGaugeVec, Opts,
    Registry, TextEncoder,
};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tokio::sync::broadcast;
use tracing_subscriber::fmt::time::ChronoUtc;
use tracing_subscriber::{prelude::*, EnvFilter};

/// Default `RUST_LOG`-style filter directive applied when neither the env var
/// nor an explicit config value is set.
pub const DEFAULT_LOG_FILTER: &str = "dataglot=info,datafusion=warn,pgwire=warn";

/// Environment variable that selects between plain and JSON log formats.
///
/// The value is matched case-insensitively. Anything other than `"json"`
/// (or unset) selects the human-readable formatter.
pub const LOG_FORMAT_ENV: &str = "DATAGLOT_LOG_FORMAT";

/// Log output format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
#[value(rename_all = "lowercase")]
pub enum LogFormat {
    /// Human-readable single-line output (the default).
    #[default]
    Plain,
    /// One JSON object per record, suitable for log aggregators.
    Json,
}

impl LogFormat {
    /// Resolve a [`LogFormat`] from the configured value, allowing the
    /// `DATAGLOT_LOG_FORMAT` environment variable to override it.
    #[must_use]
    pub fn resolve(configured: Self) -> Self {
        match std::env::var(LOG_FORMAT_ENV) {
            Ok(v) if v.eq_ignore_ascii_case("json") => Self::Json,
            Ok(v) if v.eq_ignore_ascii_case("plain") => Self::Plain,
            _ => configured,
        }
    }
}

/// Observability configuration block.
///
/// This is owned by [`crate::config::ServerConfig`] and propagated into the
/// observability subsystem at startup. Defaults are chosen so that running
/// `dataglot` with no flags still produces useful logs and exposes metrics
/// on a loopback port.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservabilityConfig {
    /// Output format for the tracing subscriber.
    #[serde(default)]
    pub log_format: LogFormat,
    /// `tracing-subscriber::EnvFilter` directive applied when `RUST_LOG`
    /// is not set.
    #[serde(default = "default_log_filter")]
    pub log_filter: String,
    /// Address the metrics HTTP server should bind to. `None` disables the
    /// `/metrics` endpoint entirely.
    #[serde(default = "default_metrics_addr")]
    pub metrics_addr: Option<SocketAddr>,
    /// Whether to expose `/health` alongside `/metrics`.
    #[serde(default = "default_true")]
    pub health_check_enabled: bool,
    /// Capture, per running query, the source catalogs it federates
    /// across (from the pre-execution plan) for the dashboard's
    /// federation breakdown (`/api/queries`,  slice 5b). Off by
    /// default: it plans every query once up front, a cost non-dashboard
    /// deployments shouldn't pay.
    #[serde(default)]
    pub capture_query_sources: bool,
    /// Interval, in seconds, between background source-health probes that feed
    /// the dashboard's live connector status and the `dataglot_connector_up`
    /// gauge. Defaults to 30s. Set to `0` to disable the poller
    /// entirely — the sources then carry zero monitoring load and liveness
    /// appears only after an on-demand "Check now" in the dashboard.
    #[serde(default = "default_connector_health_interval_secs")]
    pub connector_health_interval_secs: u64,
}

const fn default_connector_health_interval_secs() -> u64 {
    30
}

fn default_log_filter() -> String {
    DEFAULT_LOG_FILTER.to_string()
}

// Returns Option<SocketAddr> because the field is optional (None disables
// the listener); clippy's `unnecessary_wraps` lint is wrong here.
#[allow(clippy::unnecessary_wraps)]
fn default_metrics_addr() -> Option<SocketAddr> {
    Some(SocketAddr::from(([127, 0, 0, 1], 9090)))
}

const fn default_true() -> bool {
    true
}

impl Default for ObservabilityConfig {
    fn default() -> Self {
        Self {
            log_format: LogFormat::default(),
            log_filter: default_log_filter(),
            metrics_addr: default_metrics_addr(),
            health_check_enabled: true,
            capture_query_sources: false,
            connector_health_interval_secs: default_connector_health_interval_secs(),
        }
    }
}

/// Initialize the global tracing subscriber.
///
/// This must be called exactly once at process start. The subscriber emits
/// to **stderr** (not stdout) so that it does not get tangled with anything
/// the binary might write to stdout on the happy path.
///
/// `RUST_LOG` overrides the filter directive supplied via configuration.
///
/// # Errors
/// Returns an error if a global subscriber is already installed or if the
/// configured filter directive cannot be parsed.
pub fn init_tracing(config: &ObservabilityConfig) -> Result<()> {
    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(&config.log_filter))
        .with_context(|| format!("Invalid log filter directive: {}", config.log_filter))?;

    let format = LogFormat::resolve(config.log_format);
    let timer = ChronoUtc::rfc_3339();

    match format {
        LogFormat::Plain => {
            let layer = tracing_subscriber::fmt::layer()
                .with_writer(std::io::stderr)
                .with_timer(timer)
                .with_target(true);
            tracing_subscriber::registry()
                .with(filter)
                .with(layer)
                .try_init()
                .context("Failed to install tracing subscriber")?;
        }
        LogFormat::Json => {
            let layer = tracing_subscriber::fmt::layer()
                .json()
                .with_writer(std::io::stderr)
                .with_timer(timer)
                .with_current_span(true)
                .with_span_list(false);
            tracing_subscriber::registry()
                .with(filter)
                .with(layer)
                .try_init()
                .context("Failed to install tracing subscriber")?;
        }
    }
    Ok(())
}

/// Process-wide Prometheus metrics handle.
///
/// Cloning a [`Metrics`] only clones `Arc`s — it is cheap and safe to share
/// across tasks.
#[derive(Clone)]
pub struct Metrics {
    registry: Arc<Registry>,
    /// Total queries handled by the server, labeled by `protocol` and
    /// `outcome`.
    ///
    /// Bumped from the `MetricsObserver` impl in `server.rs`, which
    /// the server passes into `dataglot_pgwire::handle_connection_with_observer`
    /// (Phase 0.5 Task 03).
    pub queries_total: IntCounterVec,
    /// Wall-clock duration of completed queries in seconds, labeled by
    /// `protocol`.
    ///
    /// Observed from the same `MetricsObserver` hook as
    /// [`Self::queries_total`].
    pub query_duration_seconds: HistogramVec,
    /// Number of pgwire connections currently being served.
    pub pgwire_connections_active: IntGauge,
    /// Total pgwire connections refused admission by the rate limiter,
    /// labelled by `reason` (`global` | `per_ip`). Always registered so
    /// dashboards see a stable shape even when no `[rate_limit]` block is
    /// configured (the counter simply stays at 0). See
    /// [`crate::rate_limit`].
    pub pgwire_connections_rejected_total: IntCounterVec,
    /// Process uptime in seconds, refreshed lazily on every scrape.
    pub uptime_seconds: Gauge,
    /// Total inbound governance webhook events seen by the server,
    /// labelled by `event_type` (the wire-format event discriminator
    /// — e.g. `tag.assigned`) and `status` (`accepted`,
    /// `rejected_signature`, `missing_signature`,
    /// `rejected_too_large`, `rejected_malformed`,
    /// `rejected_unsupported_version`).
    ///
    /// Bumped from the webhook handler in [`crate::webhook`]. Only
    /// populated when the operator has opted into the webhook by
    /// setting `webhook` in `dataglot.toml`; the metric family is
    /// always registered so dashboards see a stable shape and
    /// `count` queries return 0 for a server without inbound
    /// governance, not `not found`.
    pub governance_webhook_events_total: IntCounterVec,
    /// Reachability of each configured source from the most-recent health
    /// probe — `1` reachable, `0` down — labelled by `connector` and `kind`.
    ///
    /// Set by the background health poller
    /// ([`spawn_connector_health_poller`]); the metric family is registered
    /// eagerly so `/metrics` has a stable shape, but per-source series only
    /// appear once polling runs (disabled ⇒ no series, not `0`).
    pub connector_up: IntGaugeVec,
    started_at: Instant,
}

impl Metrics {
    /// Construct and register all baseline metrics on a fresh registry.
    ///
    /// # Errors
    /// Returns an error if any metric fails to register (the only realistic
    /// cause is a duplicate registration, which would indicate a logic bug).
    pub fn new() -> Result<Self> {
        let registry = Registry::new();

        let queries_total = IntCounterVec::new(
            Opts::new(
                "dataglot_queries_total",
                "Total number of queries handled, partitioned by wire protocol and outcome",
            ),
            &["protocol", "outcome"],
        )
        .context("Failed to build dataglot_queries_total")?;

        let query_duration_seconds = HistogramVec::new(
            HistogramOpts::new(
                "dataglot_query_duration_seconds",
                "Wall-clock duration of completed queries in seconds",
            )
            // Buckets aimed at OLAP-ish latencies: sub-ms for cached metadata
            // through tens of seconds for warehouse scans.
            .buckets(vec![
                0.001, 0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0,
            ]),
            &["protocol"],
        )
        .context("Failed to build dataglot_query_duration_seconds")?;

        let pgwire_connections_active = IntGauge::new(
            "dataglot_pgwire_connections_active",
            "Number of active pgwire connections currently being served",
        )
        .context("Failed to build dataglot_pgwire_connections_active")?;

        let pgwire_connections_rejected_total = IntCounterVec::new(
            Opts::new(
                "dataglot_pgwire_connections_rejected_total",
                "Total pgwire connections refused admission by the rate limiter, \
                 partitioned by reason",
            ),
            &["reason"],
        )
        .context("Failed to build dataglot_pgwire_connections_rejected_total")?;

        let uptime_seconds = Gauge::new(
            "dataglot_uptime_seconds",
            "Process uptime in seconds since the server began listening",
        )
        .context("Failed to build dataglot_uptime_seconds")?;

        let governance_webhook_events_total = IntCounterVec::new(
            Opts::new(
                "dataglot_governance_webhook_events_total",
                "Total inbound governance webhook events handled by the server, \
                 partitioned by event_type and disposition status",
            ),
            &["event_type", "status"],
        )
        .context("Failed to build dataglot_governance_webhook_events_total")?;

        let connector_up = IntGaugeVec::new(
            Opts::new(
                "dataglot_connector_up",
                "Source reachability from the most-recent health probe \
                 (1 = reachable, 0 = down), partitioned by connector and kind",
            ),
            &["connector", "kind"],
        )
        .context("Failed to build dataglot_connector_up")?;

        registry
            .register(Box::new(queries_total.clone()))
            .context("Failed to register dataglot_queries_total")?;
        registry
            .register(Box::new(query_duration_seconds.clone()))
            .context("Failed to register dataglot_query_duration_seconds")?;
        registry
            .register(Box::new(pgwire_connections_active.clone()))
            .context("Failed to register dataglot_pgwire_connections_active")?;
        registry
            .register(Box::new(pgwire_connections_rejected_total.clone()))
            .context("Failed to register dataglot_pgwire_connections_rejected_total")?;
        registry
            .register(Box::new(uptime_seconds.clone()))
            .context("Failed to register dataglot_uptime_seconds")?;
        registry
            .register(Box::new(governance_webhook_events_total.clone()))
            .context("Failed to register dataglot_governance_webhook_events_total")?;
        registry
            .register(Box::new(connector_up.clone()))
            .context("Failed to register dataglot_connector_up")?;

        // Pre-register the common label combinations so that the metric
        // families show up in `/metrics` immediately, even before the first
        // query lands.
        let _ = queries_total.with_label_values(&["pgwire", "success"]);
        let _ = queries_total.with_label_values(&["pgwire", "error"]);
        let _ = query_duration_seconds.with_label_values(&["pgwire"]);
        let _ = pgwire_connections_rejected_total.with_label_values(&["global"]);
        let _ = pgwire_connections_rejected_total.with_label_values(&["per_ip"]);
        let _ = pgwire_connections_rejected_total.with_label_values(&["rate_ip"]);
        let _ = pgwire_connections_rejected_total.with_label_values(&["identity"]);

        Ok(Self {
            registry: Arc::new(registry),
            queries_total,
            query_duration_seconds,
            pgwire_connections_active,
            pgwire_connections_rejected_total,
            uptime_seconds,
            governance_webhook_events_total,
            connector_up,
            started_at: Instant::now(),
        })
    }

    /// Borrow the underlying registry — useful for testing or for plugging
    /// in additional collectors.
    #[must_use]
    #[allow(dead_code)] // surfaced for tests and future extension.
    pub fn registry(&self) -> &Registry {
        &self.registry
    }

    /// Refresh the uptime gauge to the current value and return a Prometheus
    /// text-format snapshot of all registered metrics.
    fn snapshot(&self) -> Result<String> {
        #[allow(clippy::cast_precision_loss)]
        let uptime = self.started_at.elapsed().as_secs_f64();
        self.uptime_seconds.set(uptime);

        let mut buf = Vec::new();
        let encoder = TextEncoder::new();
        encoder
            .encode(&self.registry.gather(), &mut buf)
            .context("Failed to encode Prometheus metrics")?;
        String::from_utf8(buf).context("Prometheus text encoder produced non-UTF-8 output")
    }
}

/// Shared state for the metrics HTTP server.
/// Static server metadata for the dashboard header: versions,
/// listening ports, and execution mode. Built once at boot from config;
/// never contains credentials (rule 12).
#[derive(Debug, Clone, Serialize)]
pub struct ServerInfo {
    /// dataglot-server crate version.
    pub dataglot_version: &'static str,
    /// DataFusion engine version.
    pub datafusion_version: &'static str,
    /// pgwire host clients connect to.
    pub pgwire_host: String,
    /// pgwire port clients connect to.
    pub pgwire_port: u16,
    /// Port this dashboard + observability API is served on.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dashboard_port: Option<u16>,
    /// `"single-node"` or `"distributed"`.
    pub execution_mode: String,
    /// Ballista ports when running distributed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ballista: Option<BallistaInfo>,
    /// Security posture (auth mode, ingress/source TLS, rate limiting).
    pub security: SecurityPosture,
    /// Governance posture (authz mode + active policy-rule counts).
    pub governance: GovernancePosture,
    /// Build provenance (profile + enabled optional features).
    pub build: BuildInfo,
    /// Configured resource ceilings (connection + memory limits). The live
    /// usage against these is served by `GET /api/limits`.
    pub limits: ResourceLimits,
}

/// Configured resource ceilings — the static half of the dashboard's
/// "limits vs usage" view ( / ). `None` on a field means that
/// limit is unset (unlimited). Built once at boot from config.
#[derive(Debug, Clone, Serialize)]
pub struct ResourceLimits {
    /// Global concurrent-connection ceiling. `None` ⇒ unlimited.
    pub max_connections: Option<usize>,
    /// Per-source-IP concurrent-connection ceiling. `None` ⇒ unlimited.
    pub max_connections_per_ip: Option<usize>,
    /// Per-authenticated-identity concurrent-connection ceiling. `None` ⇒
    /// unlimited.
    pub max_connections_per_identity: Option<usize>,
    /// Per-IP new-connection rate ceiling (connections/minute). `None` ⇒ no
    /// rate limit.
    pub max_new_connections_per_ip_per_minute: Option<u32>,
    /// Query-execution memory ceiling in bytes (spill pool). `None` ⇒
    /// DataFusion's unbounded default.
    pub memory_limit_bytes: Option<usize>,
}

impl ResourceLimits {
    /// Extract the configured ceilings from a [`crate::config::ServerConfig`].
    #[must_use]
    pub fn from_config(config: &crate::config::ServerConfig) -> Self {
        let rl = config.rate_limit.as_ref();
        Self {
            max_connections: rl.and_then(|r| r.max_connections),
            max_connections_per_ip: rl.and_then(|r| r.max_connections_per_ip),
            max_connections_per_identity: rl.and_then(|r| r.max_connections_per_identity),
            max_new_connections_per_ip_per_minute: rl
                .and_then(|r| r.max_new_connections_per_ip_per_minute),
            memory_limit_bytes: config.memory_limit_bytes,
        }
    }

    /// An all-unlimited set — for tests and unconfigured deployments.
    #[must_use]
    pub fn unlimited() -> Self {
        Self {
            max_connections: None,
            max_connections_per_ip: None,
            max_connections_per_identity: None,
            max_new_connections_per_ip_per_minute: None,
            memory_limit_bytes: None,
        }
    }
}

/// The `GET /api/limits` view: the configured ceilings plus live usage
/// against them (active connections, the busiest IP / identity bucket, and
/// cumulative rejections by reason). Lets an operator see headroom at a
/// glance — "180 / 200 connections, busiest IP 12 / 20".
#[derive(Debug, Clone, Serialize)]
pub struct ResourceUsageView {
    /// The configured ceilings (echoed for a self-contained response).
    pub limits: ResourceLimits,
    /// Connections currently being served (the live `pgwire_connections_active`
    /// gauge).
    pub active_connections: i64,
    /// Connections held by the busiest single source IP right now.
    pub busiest_ip_connections: usize,
    /// Connections held by the busiest single identity right now.
    pub busiest_identity_connections: usize,
    /// Cumulative connections rejected by the global concurrency ceiling.
    pub rejected_global: u64,
    /// Cumulative connections rejected by the per-IP concurrency ceiling.
    pub rejected_per_ip: u64,
    /// Cumulative connections rejected by the per-IP new-connection rate limit.
    pub rejected_new_conn_rate: u64,
    /// Cumulative connections rejected by the per-identity ceiling.
    pub rejected_identity: u64,
}

/// Security posture surfaced to operators (rule 12: never any secret —
/// only *whether* a control is on, and which mode). Lets a regulated operator
/// confirm at a glance that the listener isn't in `trust`/plaintext.
#[derive(Debug, Clone, Serialize)]
pub struct SecurityPosture {
    /// pgwire authentication mode: `trust` | `md5` | `scram-sha-256` | `jwt`
    /// | `ldap`.
    pub auth_mode: String,
    /// pgwire **ingress** TLS: `off` | `prefer` | `require`.
    pub ingress_tls: String,
    /// Whether pgwire connection rate limiting is configured.
    pub rate_limiting: bool,
}

/// Governance posture surfaced to operators — is enforcement even on, and how
/// many rules of each kind are active.
#[derive(Debug, Clone, Serialize)]
pub struct GovernancePosture {
    /// Authorization mode: `open` (no enforcement) | `grant`
    /// (deny-unless-granted).
    pub authz_mode: String,
    /// Configured column masks.
    pub masks: usize,
    /// Configured row filters.
    pub row_filters: usize,
    /// Configured table/column access-denials.
    pub access_denials: usize,
    /// Configured column-level whitelists.
    pub column_grants: usize,
}

/// Build provenance for the support desk.
#[derive(Debug, Clone, Serialize)]
pub struct BuildInfo {
    /// `debug` | `release`.
    pub profile: &'static str,
    /// Enabled optional cargo features that change the runtime surface.
    pub features: Vec<&'static str>,
}

impl BuildInfo {
    /// Capture the current build's profile + enabled optional features.
    #[must_use]
    pub fn current() -> Self {
        let mut features = Vec::new();
        if cfg!(feature = "ballista") {
            features.push("ballista");
        }
        if cfg!(feature = "flight_sql") {
            features.push("flight_sql");
        }
        if cfg!(feature = "dashboard") {
            features.push("dashboard");
        }
        Self {
            profile: if cfg!(debug_assertions) {
                "debug"
            } else {
                "release"
            },
            features,
        }
    }
}

/// Ballista listener ports, surfaced when distributed.
#[derive(Debug, Clone, Serialize)]
pub struct BallistaInfo {
    /// Scheduler gRPC port external executors register on.
    pub scheduler_grpc_port: u16,
    /// Scheduler observability REST API port (backs `/api/cluster`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rest_api_port: Option<u16>,
    /// Number of external executor processes (0 = embedded standalone).
    pub external_executors: usize,
}

impl ServerInfo {
    /// Minimal instance for tests / router construction without a full
    /// server config.
    #[doc(hidden)]
    #[must_use]
    pub fn for_tests() -> Self {
        Self {
            dataglot_version: "0.0.0-test",
            datafusion_version: "0.0.0",
            pgwire_host: "127.0.0.1".to_string(),
            pgwire_port: 5432,
            dashboard_port: Some(9090),
            execution_mode: "single-node".to_string(),
            ballista: None,
            security: SecurityPosture {
                auth_mode: "trust".to_string(),
                ingress_tls: "off".to_string(),
                rate_limiting: false,
            },
            governance: GovernancePosture {
                authz_mode: "open".to_string(),
                masks: 0,
                row_filters: 0,
                access_denials: 0,
                column_grants: 0,
            },
            build: BuildInfo::current(),
            limits: ResourceLimits::unlimited(),
        }
    }
}

#[derive(Clone)]
struct AppState {
    metrics: Metrics,
    health_check_enabled: bool,
    /// Boot-time lineage snapshot, pre-serialized once (it never
    /// changes after boot — see [`crate::lineage_snapshot`]).
    lineage_json: std::sync::Arc<String>,
    /// Live in-flight query registry backing `/api/queries`.
    queries: QueryRegistry,
    /// Live connected-session registry backing `/api/sessions` — the
    /// "who is connected" view (user · org · client · connected-since).
    sessions: SessionRegistry,
    /// Ballista scheduler proxy backing `/api/cluster*`.
    cluster: ClusterMonitor,
    /// Configured connectors + on-demand liveness backing `/api/connectors*`
    connectors: crate::connectors::ConnectorMonitor,
    /// Materialized-product refresh status backing `GET /api/materialization`
    /// ( — freshness, last rows/duration, next run).
    materialization: crate::materialization_registry::MaterializationRegistry,
    /// Warehouse-maintenance status backing `GET /api/maintenance` ( —
    /// compaction / orphan-cleanup state, last run, next run).
    maintenance: crate::maintenance_registry::MaintenanceRegistry,
    /// Static server metadata backing `GET /api/server` (dashboard header).
    server_info: ServerInfo,
}

/// Build the axum [`Router`] used by the metrics HTTP server.
///
/// Exposed for testing — production code should call [`spawn_metrics_server`].
// Aggregates several independent observability surfaces (metrics, health,
// lineage, queries, sessions, cluster, connectors, server-info); passing them
// individually is clearer than a bespoke params struct used in one place.
#[allow(clippy::too_many_arguments)]
pub fn build_router(
    metrics: Metrics,
    health_check_enabled: bool,
    lineage: &crate::lineage_snapshot::LineageSnapshot,
    queries: QueryRegistry,
    sessions: SessionRegistry,
    cluster: ClusterMonitor,
    connectors: crate::connectors::ConnectorMonitor,
    materialization: crate::materialization_registry::MaterializationRegistry,
    maintenance: crate::maintenance_registry::MaintenanceRegistry,
    server_info: ServerInfo,
) -> Router {
    let state = AppState {
        metrics,
        health_check_enabled,
        lineage_json: std::sync::Arc::new(
            serde_json::to_string(lineage).unwrap_or_else(|_| "{}".to_string()),
        ),
        queries,
        sessions,
        cluster,
        connectors,
        materialization,
        maintenance,
        server_info,
    };

    let mut router = Router::new()
        .route("/metrics", get(metrics_handler))
        .route("/lineage", get(lineage_handler))
        .route("/api/server", get(server_info_handler))
        .route("/api/queries", get(queries_handler))
        .route("/api/queries/history", get(queries_history_handler))
        .route("/api/queries/{run_id}", get(query_detail_handler))
        .route("/api/queries/{run_id}/cancel", post(query_cancel_handler))
        .route("/api/sessions", get(sessions_handler))
        .route("/api/cluster", get(cluster_handler))
        .route(
            "/api/cluster/job/{job_id}/stages",
            get(cluster_stages_handler),
        )
        .route("/api/cluster/job/{job_id}/dot", get(cluster_dot_handler))
        .route("/api/connectors", get(connectors_handler))
        .route(
            "/api/connectors/{name}/probe",
            post(connector_probe_handler),
        )
        .route("/api/materialization", get(materialization_handler))
        .route("/api/maintenance", get(maintenance_handler))
        .route("/api/limits", get(limits_handler));
    if state.health_check_enabled {
        router = router.route("/health", get(health_handler));
    }
    // Embedded operational dashboard at /ui, behind the
    // `dashboard` feature. API routes above take precedence; the SPA
    // handler serves assets and falls back to index.html for deep links.
    // Three routes so every shell entrypoint lands on index.html: `/ui`
    // (bare), `/ui/` (trailing slash — the `{*path}` wildcard does NOT
    // match an empty segment, so without this a pasted `/ui/` 404s), and
    // `/ui/{*path}` (assets + deep links).
    #[cfg(feature = "dashboard")]
    {
        router = router
            .route("/ui", get(crate::embed::serve))
            .route("/ui/", get(crate::embed::serve))
            .route("/ui/{*path}", get(crate::embed::serve));
    }
    router.with_state(state)
}

/// `GET /api/queries/history` — the most-recently-finished queries,
/// newest first. A bounded in-memory ring, not a
/// query log.
async fn queries_history_handler(State(state): State<AppState>) -> impl IntoResponse {
    Json(state.queries.history())
}

/// `POST /api/queries/{run_id}/cancel` — best-effort kill of a running
/// query. 200 when a cancellable query was found and
/// signalled, 404 otherwise (already finished, unknown, or not yet
/// cancellable). Loopback-only, same posture as the rest of `/api`.
async fn query_cancel_handler(
    State(state): State<AppState>,
    Path(run_id): Path<String>,
) -> impl IntoResponse {
    if state.queries.cancel(&run_id) {
        (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/json")],
            r#"{"cancelled":true}"#,
        )
            .into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            [(header::CONTENT_TYPE, "application/json")],
            r#"{"error":"query not found, already finished, or not cancellable"}"#,
        )
            .into_response()
    }
}

/// `GET /api/cluster` — one combined poll of the Ballista scheduler
/// (state + executors + jobs), or an `available:false` summary when
/// monitoring isn't configured/reachable.
async fn cluster_handler(State(state): State<AppState>) -> impl IntoResponse {
    Json(state.cluster.summary().await)
}

/// `GET /api/cluster/job/{job_id}/stages` — per-stage progress for one
/// job (raw scheduler JSON), 404 when unconfigured/unreachable.
async fn cluster_stages_handler(
    State(state): State<AppState>,
    Path(job_id): Path<String>,
) -> impl IntoResponse {
    match state.cluster.job_stages(&job_id).await {
        Some(v) => (StatusCode::OK, Json(v)).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            [(header::CONTENT_TYPE, "application/json")],
            r#"{"error":"job stages unavailable"}"#,
        )
            .into_response(),
    }
}

/// `GET /api/cluster/job/{job_id}/dot` — the job's execution DAG as
/// `GraphViz` DOT text, 404 when unconfigured/unreachable.
async fn cluster_dot_handler(
    State(state): State<AppState>,
    Path(job_id): Path<String>,
) -> impl IntoResponse {
    match state.cluster.job_dot(&job_id).await {
        Some(dot) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "text/vnd.graphviz")],
            dot,
        )
            .into_response(),
        None => (
            StatusCode::NOT_FOUND,
            [(header::CONTENT_TYPE, "application/json")],
            r#"{"error":"job DAG unavailable"}"#,
        )
            .into_response(),
    }
}

/// `GET /api/connectors` — configured connectors (kind + boot registration
/// status) plus the supported families that are available but not configured
///. No credentials (rule 12).
async fn connectors_handler(State(state): State<AppState>) -> impl IntoResponse {
    Json(state.connectors.view())
}

/// `POST /api/connectors/{name}/probe` — on-demand liveness for one connector
/// (a fresh connect under a timeout). 404 when `name` isn't configured.
async fn connector_probe_handler(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    match state.connectors.probe(&name).await {
        Some(result) => (StatusCode::OK, Json(result)).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            [(header::CONTENT_TYPE, "application/json")],
            r#"{"error":"no such configured connector"}"#,
        )
            .into_response(),
    }
}

/// `GET /api/materialization` — refresh status of every materialized derived
/// product (state, last rows/duration, next run), sorted by name.
/// Same read-only, loopback-only posture as the rest of `/api`. Never includes
/// credentials (rule 12) — errors are already scrubbed by the write path.
async fn materialization_handler(State(state): State<AppState>) -> impl IntoResponse {
    Json(state.materialization.snapshot())
}

/// `GET /api/maintenance` — status of every scheduled warehouse-maintenance
/// job (compaction / orphan cleanup): state, last run, files affected, next
/// run — sorted by label. Same read-only, loopback-only posture as
/// the rest of `/api`. Never includes credentials (rule 12).
async fn maintenance_handler(State(state): State<AppState>) -> impl IntoResponse {
    Json(state.maintenance.snapshot())
}

/// `GET /api/limits` — configured resource ceilings plus live usage against
/// them ( / ): active connections vs the global cap, the busiest
/// IP / identity bucket vs their per-bucket caps, cumulative rejections by
/// reason, and the memory ceiling. The dashboard's headroom view. Never
/// includes credentials (rule 12 — only counts and caps).
async fn limits_handler(State(state): State<AppState>) -> impl IntoResponse {
    // Live per-bucket peaks from the connected-session set: the single busiest
    // source IP and identity right now, to compare against the per-IP /
    // per-identity ceilings.
    let sessions = state.sessions.list();
    let mut per_ip: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    let mut per_identity: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    for s in &sessions {
        // Strip the `:port` suffix so all connections from one host bucket
        // together (handles IPv6 `[::1]:5432` — split on the last colon).
        let ip = s
            .peer
            .rsplit_once(':')
            .map_or(s.peer.as_str(), |(host, _)| host);
        *per_ip.entry(ip).or_default() += 1;
        if let Some(user) = &s.user {
            *per_identity.entry(user.as_str()).or_default() += 1;
        }
    }
    let rejected = |reason: &str| {
        state
            .metrics
            .pgwire_connections_rejected_total
            .with_label_values(&[reason])
            .get()
    };
    let view = ResourceUsageView {
        limits: state.server_info.limits.clone(),
        active_connections: state.metrics.pgwire_connections_active.get(),
        busiest_ip_connections: per_ip.into_values().max().unwrap_or(0),
        busiest_identity_connections: per_identity.into_values().max().unwrap_or(0),
        rejected_global: rejected("global"),
        rejected_per_ip: rejected("per_ip"),
        rejected_new_conn_rate: rejected("rate_ip"),
        rejected_identity: rejected("identity"),
    };
    Json(view)
}

/// `GET /api/server` — static server metadata for the dashboard header:
/// dataglot + DataFusion versions, pgwire/dashboard/ballista ports, and
/// execution mode. Never includes credentials (rule 12).
async fn server_info_handler(State(state): State<AppState>) -> impl IntoResponse {
    Json(state.server_info.clone())
}

/// `GET /api/queries` — snapshot of currently-executing queries,
/// longest-running first. The "what's running" data plane for
/// the operational dashboard. Same read-only, loopback-only posture as
/// `/metrics`.
async fn queries_handler(State(state): State<AppState>) -> impl IntoResponse {
    Json(state.queries.snapshot())
}

/// `GET /api/sessions` — snapshot of currently-connected pgwire sessions
/// (user · org · client address · connected-since), longest-connected
/// first. The "who is connected" data plane for the operational dashboard;
/// the per-connection detail behind the aggregate
/// `dataglot_pgwire_connections_active` gauge. Same read-only, loopback-only
/// posture as `/metrics`. Never includes credentials (rule 12).
async fn sessions_handler(State(state): State<AppState>) -> impl IntoResponse {
    Json(state.sessions.list())
}

/// `GET /api/queries/{run_id}` — a single query's detail, including its
/// per-source pushdown profile. Returns the live in-flight
/// entry if it's still running, else the finished entry from the history ring
/// (the profile is usually inspected after the query completes), else 404 if
/// it's unknown or has aged out of the bounded history.
async fn query_detail_handler(
    State(state): State<AppState>,
    Path(run_id): Path<String>,
) -> impl IntoResponse {
    if let Some(view) = state.queries.get(&run_id) {
        return (StatusCode::OK, Json(view)).into_response();
    }
    if let Some(done) = state.queries.history_get(&run_id) {
        return (StatusCode::OK, Json(done)).into_response();
    }
    (
        StatusCode::NOT_FOUND,
        [(header::CONTENT_TYPE, "application/json")],
        r#"{"error":"query not found (unknown or aged out of history)"}"#,
    )
        .into_response()
}

/// `GET /lineage` — the derived-products / mask-propagation graph as
/// JSON. Static after boot; same read-only, loopback-only
/// posture as `/metrics`.
async fn lineage_handler(State(state): State<AppState>) -> impl IntoResponse {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        state.lineage_json.as_ref().clone(),
    )
}

async fn metrics_handler(State(state): State<AppState>) -> impl IntoResponse {
    match state.metrics.snapshot() {
        Ok(body) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
            body,
        )
            .into_response(),
        Err(err) => {
            tracing::error!(error = %err, "Failed to encode metrics");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
                format!("metrics encoding failed: {err}"),
            )
                .into_response()
        }
    }
}

async fn health_handler() -> impl IntoResponse {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        r#"{"status":"ok"}"#,
    )
}

/// Spawn the metrics HTTP server on a tokio task.
///
/// The server runs until either the supplied shutdown receiver fires or
/// the listener errors out.
///
/// # Errors
/// Returns an error if the listener cannot bind to `addr`.
// The observability listener aggregates several independent surfaces
// (metrics, health, lineage, queries, cluster, server-info); passing them
// individually is clearer than a bespoke params struct used in one place.
#[allow(clippy::too_many_arguments)]
pub async fn spawn_metrics_server(
    addr: SocketAddr,
    metrics: Metrics,
    health_check_enabled: bool,
    lineage: &crate::lineage_snapshot::LineageSnapshot,
    queries: QueryRegistry,
    sessions: SessionRegistry,
    cluster: ClusterMonitor,
    connectors: crate::connectors::ConnectorMonitor,
    materialization: crate::materialization_registry::MaterializationRegistry,
    maintenance: crate::maintenance_registry::MaintenanceRegistry,
    server_info: ServerInfo,
    control_plane: Option<(Arc<dyn dataglot_catalog::MetaStore>, String)>,
    mut shutdown: broadcast::Receiver<()>,
) -> Result<tokio::task::JoinHandle<()>> {
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("Failed to bind metrics server to {addr}"))?;
    let bound = listener.local_addr().unwrap_or(addr);
    let mut router = build_router(
        metrics,
        health_check_enabled,
        lineage,
        queries,
        sessions,
        cluster,
        connectors,
        materialization,
        maintenance,
        server_info,
    );
    // Add the read-only Control Plane view only when a meta store is
    // configured; without one the route is absent and the dashboard
    // tab shows its "not configured" state.
    if let Some((store, org)) = control_plane {
        router = router.merge(crate::control_plane::router(store, org));
    }

    tracing::info!(%bound, "Metrics HTTP server listening");
    // Announce the operational dashboard when it's compiled in — otherwise the
    // SPA is served silently at /ui and an operator has no way to learn from the
    // logs that it exists or its URL.
    #[cfg(feature = "dashboard")]
    tracing::info!(url = %format!("http://{bound}/ui"), "operational dashboard available");

    let handle = tokio::spawn(async move {
        let serve = axum::serve(listener, router).with_graceful_shutdown(async move {
            let _ = shutdown.recv().await;
        });
        if let Err(err) = serve.await {
            tracing::error!(error = %err, "Metrics HTTP server exited with error");
        } else {
            tracing::info!("Metrics HTTP server stopped");
        }
    });

    Ok(handle)
}

/// Spawn the background source-health poller ( continuous mode).
///
/// Every `interval` it probes each configured connector (concurrently, via
/// [`crate::connectors::ConnectorMonitor::refresh_health`]), refreshing both
/// the monitor's cached health — surfaced by `/api/connectors` — and the
/// `dataglot_connector_up` gauge. The `connectors` handle is a clone that
/// shares the same cache as the one held by the metrics router, so the
/// dashboard and the gauge stay in lockstep.
///
/// The first probe fires immediately (tokio interval semantics), so live
/// status is available seconds after boot rather than after the first period.
/// Shares the server's broadcast shutdown channel so a single Ctrl-C stops it.
#[must_use]
pub fn spawn_connector_health_poller(
    connectors: crate::connectors::ConnectorMonitor,
    metrics: Metrics,
    interval: Duration,
    mut shutdown: broadcast::Receiver<()>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        // If a sweep runs long (a source at the probe timeout), skip the
        // backlog rather than firing catch-up ticks back-to-back.
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        tracing::info!(
            interval_secs = interval.as_secs(),
            "Connector health poller started"
        );
        loop {
            tokio::select! {
                _ = shutdown.recv() => break,
                _ = ticker.tick() => {
                    for (name, kind, live) in connectors.refresh_health().await {
                        // Both labels must be the same `&str` type: `name` is
                        // a `String`, `kind` a `&'static str`. Passing
                        // `&[&name, kind]` mixes `&String` + `&str` — newer
                        // rustc coerces it in the array literal, but the 1.94
                        // MSRV rejects it (E0308). `name.as_str()` keeps the
                        // slice homogeneous across both.
                        metrics
                            .connector_up
                            .with_label_values(&[name.as_str(), kind])
                            .set(i64::from(live));
                    }
                }
            }
        }
        tracing::info!("Connector health poller stopped");
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    #[test]
    fn observability_config_defaults_are_sane() {
        let cfg = ObservabilityConfig::default();
        assert_eq!(cfg.log_format, LogFormat::Plain);
        assert_eq!(cfg.log_filter, DEFAULT_LOG_FILTER);
        assert_eq!(
            cfg.metrics_addr,
            Some(SocketAddr::from(([127, 0, 0, 1], 9090)))
        );
        assert!(cfg.health_check_enabled);
    }

    #[test]
    fn log_format_serde_roundtrip() {
        let json = serde_json::to_string(&LogFormat::Json).unwrap();
        assert_eq!(json, "\"json\"");
        let plain: LogFormat = serde_json::from_str("\"plain\"").unwrap();
        assert_eq!(plain, LogFormat::Plain);
    }

    #[test]
    fn observability_config_serde_roundtrip() {
        let cfg = ObservabilityConfig::default();
        let json = serde_json::to_string(&cfg).unwrap();
        let parsed: ObservabilityConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.log_format, cfg.log_format);
        assert_eq!(parsed.log_filter, cfg.log_filter);
        assert_eq!(parsed.metrics_addr, cfg.metrics_addr);
        assert_eq!(parsed.health_check_enabled, cfg.health_check_enabled);
    }

    #[test]
    fn observability_config_disables_metrics_when_addr_is_null() {
        let json = r#"{"log_format":"json","log_filter":"dataglot=debug","metrics_addr":null,"health_check_enabled":false}"#;
        let cfg: ObservabilityConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.log_format, LogFormat::Json);
        assert_eq!(cfg.log_filter, "dataglot=debug");
        assert!(cfg.metrics_addr.is_none());
        assert!(!cfg.health_check_enabled);
    }

    #[test]
    fn log_filter_must_parse_via_env_filter() {
        EnvFilter::try_new(DEFAULT_LOG_FILTER).expect("default filter must be valid");
        EnvFilter::try_new("dataglot=trace,datafusion=info,pgwire=debug")
            .expect("custom filter must be valid");
    }

    #[test]
    fn log_format_resolve_passes_through_configured_value_when_env_unset() {
        // We deliberately do NOT mutate the process environment from tests
        // (workspace forbids `unsafe_code` and `std::env::set_var` is now
        // `unsafe fn`). The env-override branch is covered by the binary's
        // own startup path, which reads `DATAGLOT_LOG_FORMAT` once.
        if std::env::var(LOG_FORMAT_ENV).is_err() {
            assert_eq!(LogFormat::resolve(LogFormat::Plain), LogFormat::Plain);
            assert_eq!(LogFormat::resolve(LogFormat::Json), LogFormat::Json);
        }
    }

    #[test]
    fn metrics_registration_is_idempotent_per_instance() {
        let m1 = Metrics::new().expect("first registry must build");
        let m2 = Metrics::new().expect("second independent registry must also build");
        // Two separate registries — no cross-instance collision.
        assert!(!Arc::ptr_eq(&m1.registry, &m2.registry));
    }

    #[test]
    fn metrics_snapshot_contains_all_registered_families() {
        let metrics = Metrics::new().unwrap();
        metrics.pgwire_connections_active.set(3);
        metrics
            .queries_total
            .with_label_values(&["pgwire", "success"])
            .inc_by(2);
        metrics
            .query_duration_seconds
            .with_label_values(&["pgwire"])
            .observe(0.123);

        metrics
            .connector_up
            .with_label_values(&["pg_main", "postgres"])
            .set(1);

        let body = metrics.snapshot().expect("snapshot must encode");
        assert!(body.contains("dataglot_queries_total"));
        assert!(body.contains("dataglot_query_duration_seconds"));
        assert!(body.contains("dataglot_pgwire_connections_active 3"));
        assert!(body.contains("dataglot_uptime_seconds"));
        assert!(
            body.contains("dataglot_connector_up{connector=\"pg_main\",kind=\"postgres\"} 1"),
            "connector_up gauge must serialize its labelled series"
        );
        // # HELP / # TYPE lines are mandatory for valid Prometheus exposition.
        assert!(body.contains("# HELP dataglot_queries_total"));
        assert!(body.contains("# TYPE dataglot_queries_total counter"));
    }

    #[tokio::test]
    async fn router_serves_metrics_endpoint() {
        let metrics = Metrics::new().unwrap();
        let app = build_router(
            metrics,
            true,
            &crate::lineage_snapshot::LineageSnapshot::default(),
            QueryRegistry::new(),
            SessionRegistry::new(),
            ClusterMonitor::new(None),
            crate::connectors::ConnectorMonitor::empty(),
            crate::materialization_registry::MaterializationRegistry::empty(),
            crate::maintenance_registry::MaintenanceRegistry::empty(),
            ServerInfo::for_tests(),
        );

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/metrics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let ct = response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        assert!(
            ct.starts_with("text/plain"),
            "unexpected content-type: {ct}"
        );

        let body_bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        let body = String::from_utf8(body_bytes.to_vec()).unwrap();
        assert!(body.contains("dataglot_queries_total"));
    }

    // Every SPA shell entrypoint must land on index.html: `/ui` (bare),
    // `/ui/` (trailing slash — regression guard: axum's `{*path}` wildcard
    // does not match an empty segment, so `/ui/` 404s without its own
    // route), and a client-side deep link. Assets are served separately.
    #[cfg(feature = "dashboard")]
    #[tokio::test]
    async fn router_serves_dashboard_shell_on_ui_paths() {
        for uri in ["/ui", "/ui/", "/ui/queries"] {
            let app = build_router(
                Metrics::new().unwrap(),
                true,
                &crate::lineage_snapshot::LineageSnapshot::default(),
                QueryRegistry::new(),
                SessionRegistry::new(),
                ClusterMonitor::new(None),
                crate::connectors::ConnectorMonitor::empty(),
                crate::materialization_registry::MaterializationRegistry::empty(),
                crate::maintenance_registry::MaintenanceRegistry::empty(),
                ServerInfo::for_tests(),
            );
            let response = app
                .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::OK,
                "{uri} should serve the shell"
            );
            let ct = response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_string();
            assert!(
                ct.starts_with("text/html"),
                "{uri}: unexpected content-type {ct}"
            );
            let body_bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
                .await
                .unwrap();
            let body = String::from_utf8(body_bytes.to_vec()).unwrap();
            // Assert on markup shared by BOTH the real vite build and the
            // Node-free stub `build.rs` embeds, so `cargo test --features
            // dashboard` passes without npm. (The real shell adds
            // `<div id="root">`; the stub does not.)
            assert!(
                body.to_ascii_lowercase().contains("<!doctype html"),
                "{uri} should return the dashboard HTML shell"
            );
        }
    }

    #[tokio::test]
    async fn router_serves_active_queries() {
        use dataglot_pgwire::QueryObserver;
        let metrics = Metrics::new().unwrap();
        let registry = QueryRegistry::new();
        // Register an in-flight query through the public observer path.
        crate::query_registry::QueryRegistryObserver::new(
            registry.clone(),
            false,
            "dataglot",
            "public",
        )
        .on_query_start(dataglot_core::lineage::RunId::new(), "SELECT 1");

        let app = build_router(
            metrics,
            true,
            &crate::lineage_snapshot::LineageSnapshot::default(),
            registry,
            SessionRegistry::new(),
            ClusterMonitor::new(None),
            crate::connectors::ConnectorMonitor::empty(),
            crate::materialization_registry::MaterializationRegistry::empty(),
            crate::maintenance_registry::MaintenanceRegistry::empty(),
            ServerInfo::for_tests(),
        );

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/queries")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body_bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        let body = String::from_utf8(body_bytes.to_vec()).unwrap();
        assert!(body.contains(r#""state":"running""#), "body: {body}");
        assert!(body.contains("SELECT 1"), "body: {body}");
    }

    #[tokio::test]
    async fn router_serves_sessions() {
        let metrics = Metrics::new().unwrap();
        let sessions = SessionRegistry::new();
        // Register a connected session through the public registry path and
        // resolve its identity, the way the server's connection handler does.
        let id = sessions.next_id();
        sessions.register(id, "10.0.0.7:52344");
        sessions.set_identity(id, Some("alice".to_string()), Some("acme".to_string()));

        let app = build_router(
            metrics,
            true,
            &crate::lineage_snapshot::LineageSnapshot::default(),
            QueryRegistry::new(),
            sessions,
            ClusterMonitor::new(None),
            crate::connectors::ConnectorMonitor::empty(),
            crate::materialization_registry::MaterializationRegistry::empty(),
            crate::maintenance_registry::MaintenanceRegistry::empty(),
            ServerInfo::for_tests(),
        );

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/sessions")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body_bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        let body = String::from_utf8(body_bytes.to_vec()).unwrap();
        assert!(body.contains("10.0.0.7:52344"), "body: {body}");
        assert!(body.contains(r#""user":"alice""#), "body: {body}");
        assert!(body.contains(r#""org":"acme""#), "body: {body}");
        assert!(body.contains("connected_at_ms"), "body: {body}");
    }

    #[tokio::test]
    async fn cancel_route_200_when_cancellable_404_otherwise() {
        use dataglot_pgwire::{QueryHandle, QueryObserver};
        let metrics = Metrics::new().unwrap();
        let registry = QueryRegistry::new();
        let id = dataglot_core::lineage::RunId::new();
        let obs = crate::query_registry::QueryRegistryObserver::new(
            registry.clone(),
            false,
            "dataglot",
            "public",
        );
        obs.on_query_start(id, "SELECT 1");
        obs.on_query_cancellable(id, QueryHandle::detached());

        let app = build_router(
            metrics,
            true,
            &crate::lineage_snapshot::LineageSnapshot::default(),
            registry,
            SessionRegistry::new(),
            ClusterMonitor::new(None),
            crate::connectors::ConnectorMonitor::empty(),
            crate::materialization_registry::MaterializationRegistry::empty(),
            crate::maintenance_registry::MaintenanceRegistry::empty(),
            ServerInfo::for_tests(),
        );

        // Cancellable → 200.
        let ok = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/api/queries/{id}/cancel"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(ok.status(), StatusCode::OK);

        // Unknown id → 404.
        let missing = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/queries/nope/cancel")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(missing.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn history_route_returns_finished_queries() {
        use dataglot_pgwire::{QueryObserver, QueryOutcome};
        let metrics = Metrics::new().unwrap();
        let registry = QueryRegistry::new();
        let id = dataglot_core::lineage::RunId::new();
        let obs = crate::query_registry::QueryRegistryObserver::new(
            registry.clone(),
            false,
            "dataglot",
            "public",
        );
        obs.on_query_start(id, "SELECT 7");
        obs.on_query_complete(
            id,
            "SELECT 7",
            None,
            QueryOutcome::Success,
            std::time::Duration::from_millis(2),
        );

        let app = build_router(
            metrics,
            true,
            &crate::lineage_snapshot::LineageSnapshot::default(),
            registry,
            SessionRegistry::new(),
            ClusterMonitor::new(None),
            crate::connectors::ConnectorMonitor::empty(),
            crate::materialization_registry::MaterializationRegistry::empty(),
            crate::maintenance_registry::MaintenanceRegistry::empty(),
            ServerInfo::for_tests(),
        );
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/queries/history")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body_bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        let body = String::from_utf8(body_bytes.to_vec()).unwrap();
        assert!(body.contains("SELECT 7"), "body: {body}");
        assert!(body.contains(r#""outcome":"success""#), "body: {body}");
    }

    #[test]
    fn resource_limits_from_config_extracts_ceilings() {
        let mut config = crate::config::ServerConfig::default();
        config.rate_limit = Some(crate::config::RateLimitConfig {
            max_connections: Some(200),
            max_connections_per_ip: Some(20),
            max_connections_per_identity: Some(5),
            max_new_connections_per_ip_per_minute: Some(120),
        });
        config.memory_limit_bytes = Some(1 << 30);
        let limits = ResourceLimits::from_config(&config);
        assert_eq!(limits.max_connections, Some(200));
        assert_eq!(limits.max_connections_per_ip, Some(20));
        assert_eq!(limits.max_connections_per_identity, Some(5));
        assert_eq!(limits.max_new_connections_per_ip_per_minute, Some(120));
        assert_eq!(limits.memory_limit_bytes, Some(1 << 30));

        // No rate-limit block ⇒ every connection ceiling is unset.
        let bare = ResourceLimits::from_config(&crate::config::ServerConfig::default());
        assert_eq!(bare.max_connections, None);
        assert_eq!(bare.max_connections_per_ip, None);
    }

    #[tokio::test]
    async fn router_serves_resource_limits_with_live_usage() {
        let metrics = Metrics::new().unwrap();
        metrics.pgwire_connections_active.set(2);
        metrics
            .pgwire_connections_rejected_total
            .with_label_values(&["global"])
            .inc_by(4);
        let sessions = SessionRegistry::new();
        // Two connections from the same source IP; one carries an identity.
        let a = sessions.next_id();
        sessions.register(a, "10.0.0.7:5001");
        sessions.set_identity(a, Some("svc_bi".to_string()), None);
        let b = sessions.next_id();
        sessions.register(b, "10.0.0.7:5002");
        let app = build_router(
            metrics,
            true,
            &crate::lineage_snapshot::LineageSnapshot::default(),
            QueryRegistry::new(),
            sessions,
            ClusterMonitor::new(None),
            crate::connectors::ConnectorMonitor::empty(),
            crate::materialization_registry::MaterializationRegistry::empty(),
            crate::maintenance_registry::MaintenanceRegistry::empty(),
            ServerInfo::for_tests(),
        );
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/limits")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body_bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        let body = String::from_utf8(body_bytes.to_vec()).unwrap();
        assert!(body.contains(r#""active_connections":2"#), "body: {body}");
        assert!(
            body.contains(r#""busiest_ip_connections":2"#),
            "both sessions share an IP: {body}"
        );
        assert!(
            body.contains(r#""busiest_identity_connections":1"#),
            "one session carries an identity: {body}"
        );
        assert!(body.contains(r#""rejected_global":4"#), "body: {body}");
    }

    #[tokio::test]
    async fn router_serves_materialization_status() {
        let metrics = Metrics::new().unwrap();
        let materialization = crate::materialization_registry::MaterializationRegistry::empty();
        materialization.register("active_users", "wh.mart.active_users", 900);
        materialization.record_success("active_users", 128, 2, 45);
        let app = build_router(
            metrics,
            true,
            &crate::lineage_snapshot::LineageSnapshot::default(),
            QueryRegistry::new(),
            SessionRegistry::new(),
            ClusterMonitor::new(None),
            crate::connectors::ConnectorMonitor::empty(),
            materialization,
            crate::maintenance_registry::MaintenanceRegistry::empty(),
            ServerInfo::for_tests(),
        );
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/materialization")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body_bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        let body = String::from_utf8(body_bytes.to_vec()).unwrap();
        assert!(body.contains("active_users"), "body: {body}");
        assert!(body.contains(r#""state":"success""#), "body: {body}");
        assert!(body.contains(r#""last_rows":128"#), "body: {body}");
    }

    #[tokio::test]
    async fn router_serves_maintenance_status() {
        let metrics = Metrics::new().unwrap();
        let maintenance = crate::maintenance_registry::MaintenanceRegistry::empty();
        maintenance.register(
            "compact:wh.lake.events",
            crate::maintenance_registry::MaintenanceKind::Compaction,
            "wh.lake.events",
            21_600,
        );
        maintenance.record_compaction("compact:wh.lake.events", 5000, 3, 900);
        let app = build_router(
            metrics,
            true,
            &crate::lineage_snapshot::LineageSnapshot::default(),
            QueryRegistry::new(),
            SessionRegistry::new(),
            ClusterMonitor::new(None),
            crate::connectors::ConnectorMonitor::empty(),
            crate::materialization_registry::MaterializationRegistry::empty(),
            maintenance,
            ServerInfo::for_tests(),
        );
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/maintenance")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body_bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        let body = String::from_utf8(body_bytes.to_vec()).unwrap();
        assert!(body.contains("compact:wh.lake.events"), "body: {body}");
        assert!(body.contains(r#""kind":"compaction""#), "body: {body}");
        assert!(body.contains(r#""last_data_files":3"#), "body: {body}");
    }

    #[tokio::test]
    async fn router_serves_server_info() {
        let metrics = Metrics::new().unwrap();
        let app = build_router(
            metrics,
            true,
            &crate::lineage_snapshot::LineageSnapshot::default(),
            QueryRegistry::new(),
            SessionRegistry::new(),
            ClusterMonitor::new(None),
            crate::connectors::ConnectorMonitor::empty(),
            crate::materialization_registry::MaterializationRegistry::empty(),
            crate::maintenance_registry::MaintenanceRegistry::empty(),
            ServerInfo::for_tests(),
        );
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/server")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body_bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        let body = String::from_utf8(body_bytes.to_vec()).unwrap();
        assert!(body.contains("dataglot_version"), "body: {body}");
        assert!(body.contains("pgwire_port"), "body: {body}");
        assert!(body.contains("execution_mode"), "body: {body}");
    }

    #[tokio::test]
    async fn router_serves_cluster_summary_unavailable_when_unconfigured() {
        let metrics = Metrics::new().unwrap();
        let app = build_router(
            metrics,
            true,
            &crate::lineage_snapshot::LineageSnapshot::default(),
            QueryRegistry::new(),
            SessionRegistry::new(),
            ClusterMonitor::new(None),
            crate::connectors::ConnectorMonitor::empty(),
            crate::materialization_registry::MaterializationRegistry::empty(),
            crate::maintenance_registry::MaintenanceRegistry::empty(),
            ServerInfo::for_tests(),
        );

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/cluster")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body_bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        let body = String::from_utf8(body_bytes.to_vec()).unwrap();
        assert!(body.contains(r#""available":false"#), "body: {body}");
    }

    ///  — `/lineage` serves the boot-time snapshot as JSON with
    /// the wire shape the testbench's Lineage tab consumes
    /// (`products` / `nodes` / `edges`, arrays never null).
    #[tokio::test]
    async fn router_serves_lineage_snapshot() {
        let metrics = Metrics::new().unwrap();
        let app = build_router(
            metrics,
            true,
            &crate::lineage_snapshot::LineageSnapshot::default(),
            QueryRegistry::new(),
            SessionRegistry::new(),
            ClusterMonitor::new(None),
            crate::connectors::ConnectorMonitor::empty(),
            crate::materialization_registry::MaterializationRegistry::empty(),
            crate::maintenance_registry::MaintenanceRegistry::empty(),
            ServerInfo::for_tests(),
        );

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/lineage")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let ct = response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        assert!(ct.starts_with("application/json"), "content-type: {ct}");
        let body = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json["products"].as_array().is_some());
        assert!(json["nodes"].as_array().is_some());
        assert!(json["edges"].as_array().is_some());
    }

    #[tokio::test]
    async fn router_serves_health_when_enabled() {
        let metrics = Metrics::new().unwrap();
        let app = build_router(
            metrics,
            true,
            &crate::lineage_snapshot::LineageSnapshot::default(),
            QueryRegistry::new(),
            SessionRegistry::new(),
            ClusterMonitor::new(None),
            crate::connectors::ConnectorMonitor::empty(),
            crate::materialization_registry::MaterializationRegistry::empty(),
            crate::maintenance_registry::MaintenanceRegistry::empty(),
            ServerInfo::for_tests(),
        );

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body_bytes = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap();
        assert_eq!(&body_bytes[..], br#"{"status":"ok"}"#);
    }

    #[tokio::test]
    async fn router_omits_health_when_disabled() {
        let metrics = Metrics::new().unwrap();
        let app = build_router(
            metrics,
            false,
            &crate::lineage_snapshot::LineageSnapshot::default(),
            QueryRegistry::new(),
            SessionRegistry::new(),
            ClusterMonitor::new(None),
            crate::connectors::ConnectorMonitor::empty(),
            crate::materialization_registry::MaterializationRegistry::empty(),
            crate::maintenance_registry::MaintenanceRegistry::empty(),
            ServerInfo::for_tests(),
        );

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn router_returns_404_for_unknown_path() {
        let metrics = Metrics::new().unwrap();
        let app = build_router(
            metrics,
            true,
            &crate::lineage_snapshot::LineageSnapshot::default(),
            QueryRegistry::new(),
            SessionRegistry::new(),
            ClusterMonitor::new(None),
            crate::connectors::ConnectorMonitor::empty(),
            crate::materialization_registry::MaterializationRegistry::empty(),
            crate::maintenance_registry::MaintenanceRegistry::empty(),
            ServerInfo::for_tests(),
        );

        let response = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}

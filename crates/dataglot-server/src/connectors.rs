//! Connector availability + liveness (on-demand + background poll) for the
//! operations dashboard.
//!
//! Three states an operator cares about:
//! - **configured** — declared in `[catalogs.*]` (always known).
//! - **registered** — came up at boot and is in the live catalog set. With
//!   `--tolerate-unreachable-catalogs`, a source that was down is skipped, so
//!   `registered == false` means "configured but didn't start".
//! - **live** — reachable *right now*. Probed two ways, both feeding the same
//!   cached [`ConnectorHealth`]: **on demand** (a dashboard "Check now" button)
//!   and, when enabled, a **background poller** ([`ConnectorMonitor::refresh_health`],
//!   driven from `crate::observability`) that refreshes every source on an
//!   interval and drives the `dataglot_connector_up` gauge. The poller is
//!   opt-out: set `connector_health_interval_secs = 0` for zero background load
//!   on the sources (health then appears only after an on-demand check).
//!
//! The liveness probe prefers **reusing** the boot-built connector:
//! every SQL connector hands the boot path a
//! [`dataglot_federation::ConnectorHealthCheck`] handle over its
//! already-authenticated client, and the probe checks liveness with a cheap
//! `SELECT 1` on it — no rebuild, no re-auth, no eager `INFORMATION_SCHEMA`
//! walk. Only sources without a handle (non-SQL connectors, or one that wasn't
//! reachable at boot) fall back to rebuilding the connector from config via
//! [`crate::config::build_one_connector`] — the exact boot path, so DSN /
//! `dsn_env` / catalog-service / TLS resolution stays identical with no
//! duplicated connection logic. Credentials never leave this module: only
//! `{name, kind, registered/live, latency, redacted-error}` is serialized
//! (CLAUDE.md rule 12).

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, PoisonError, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::Serialize;

use crate::config::{catalog_kind, CatalogConfig};

/// Per-probe timeout. A source that doesn't complete a fresh connect within
/// this is reported `live: false` rather than hanging the HTTP request.
const PROBE_TIMEOUT: Duration = Duration::from_secs(10);

/// Backs `/api/connectors*`. Cheap to clone (all fields `Arc`); clones share
/// the same health cache, so the background poller and the HTTP handler that
/// serves `/api/connectors` observe the same live status.
#[derive(Clone)]
pub struct ConnectorMonitor {
    /// All configured catalogs (name → config). Carries credentials, so it is
    /// used only to resolve/probe — never serialized.
    configured: Arc<HashMap<String, CatalogConfig>>,
    /// Names that registered successfully into the live catalog set at boot.
    registered: Arc<HashSet<String>>,
    /// Most-recent liveness per connector, written by [`Self::refresh_health`]
    /// (background poller) and [`Self::probe`] (on-demand), read by
    /// [`Self::list`]. Empty until the first probe completes.
    health: Arc<RwLock<HashMap<String, ConnectorHealth>>>,
    /// Cheap-liveness handles over the boot-built SQL connectors,
    /// keyed by catalog name. When a name has a handle, [`Self::probe`] /
    /// [`Self::refresh_health`] check liveness with `handle.health_check()` — a
    /// `SELECT 1` on the already-authenticated client — instead of rebuilding
    /// the connector from config (a full re-auth + eager `INFORMATION_SCHEMA`
    /// walk that was then thrown away). Non-SQL connectors (REST / OData /
    /// warehouse / object-storage) have no handle and keep the rebuild probe.
    health_handles: Arc<HashMap<String, crate::config::ConnectorHealthHandle>>,
}

/// A supported connector *family* Dataglot can federate, whether or not this
/// server has one configured. Backs the "available but not configured" tier so
/// the dashboard shows the whole menu, not just what's wired (parity with the
/// old testbench Connectors inventory).
struct Family {
    /// Display name (e.g. "PostgreSQL", "Snowflake").
    name: &'static str,
    /// Cargo feature / build note (e.g. "postgres", "oracle / oracle-pure").
    feature: &'static str,
    /// `catalog_kind` values that satisfy this family — a configured catalog
    /// of any of these kinds means the family is in use (not "available").
    kinds: &'static [&'static str],
    /// One-line capability note.
    note: &'static str,
}

/// The connector families Dataglot supports. A family with no configured
/// catalog of its `kinds` shows up under `available` in `/api/connectors`.
const INVENTORY: &[Family] = &[
    Family {
        name: "PostgreSQL",
        feature: "postgres",
        kinds: &["postgres"],
        note: "SQLExecutor — predicate / GROUP BY / aggregate pushdown",
    },
    Family {
        name: "MySQL",
        feature: "mysql",
        kinds: &["mysql"],
        note: "SQLExecutor — predicate / GROUP BY / aggregate pushdown",
    },
    Family {
        name: "Iceberg lakehouse",
        feature: "iceberg",
        kinds: &["warehouse"],
        note: "Lakekeeper REST catalog + S3 (warehouse, iceberg-datafusion)",
    },
    Family {
        name: "Snowflake",
        feature: "snowflake",
        kinds: &["snowflake"],
        note: "dataglot-federation `snowflake` feature; configure with SNOWFLAKE_* credentials",
    },
    Family {
        name: "Oracle",
        feature: "oracle / oracle-pure",
        kinds: &["oracle"],
        note: "Exadata displacement — OCI (max compatibility) or pure-Rust backends",
    },
    Family {
        name: "Object storage (Parquet / CSV / JSON)",
        feature: "built-in",
        kinds: &["object_storage"],
        note: "Query files on S3-compatible stores or local paths directly; always compiled in",
    },
    Family {
        name: "ADBC (generic)",
        feature: "adbc",
        kinds: &["adbc"],
        note: "SQLExecutor over a BYO Arrow ADBC driver, dialect from the DataFusion whitelist",
    },
    Family {
        name: "OData v2 (SAP S/4HANA, ServiceNow, Workday, Dataverse)",
        feature: "odata",
        kinds: &["odata", "sap_s4hana"],
        note: "Direct TableProvider over OData v2: $filter/$select/$top pushdown",
    },
    Family {
        name: "REST / JSON API (Salesforce, athenahealth, generic)",
        feature: "rest",
        kinds: &["rest"],
        note: "Direct TableProvider over a JSON REST API: records[] rows, \
               next-link pagination, static / OAuth2 client-credentials auth",
    },
];

/// A supported connector family with nothing configured for it — the
/// "available to wire up" tier.
#[derive(Debug, Serialize)]
pub struct AvailableConnector {
    /// Display name.
    pub name: &'static str,
    /// Cargo feature / build note.
    pub feature: &'static str,
    /// Capability note.
    pub note: &'static str,
}

/// The full `/api/connectors` view: what's configured (with boot status) plus
/// the supported families that are available but not configured.
#[derive(Debug, Serialize)]
pub struct ConnectorsView {
    /// Catalogs declared in `[catalogs.*]`, with boot-registration status.
    pub configured: Vec<ConnectorSummary>,
    /// Supported connector families with no configured catalog — the menu of
    /// what could still be wired up.
    pub available: Vec<AvailableConnector>,
}

/// One connector's status — a `configured` entry in [`ConnectorsView`].
#[derive(Debug, Serialize)]
pub struct ConnectorSummary {
    /// Catalog name (the `[catalogs.<name>]` key / three-part-ref prefix).
    pub name: String,
    /// Source kind: `postgres` / `mysql` / `warehouse` / …
    pub kind: &'static str,
    /// `true` when the catalog is in the live registry (it came up at boot).
    /// `false` ⇒ configured but skipped (unreachable under
    /// `--tolerate-unreachable-catalogs`).
    pub registered: bool,
    /// Most-recent liveness from the background poller or an on-demand probe.
    /// `None` until the first probe completes (or when health polling is
    /// disabled) — the dashboard renders that as "unknown".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub health: Option<ConnectorHealth>,
}

/// Cached liveness of one connector — the "reachable right now" state, shared
/// by the on-demand probe and the background poller. Serialized into
/// [`ConnectorSummary::health`]; carries only redacted status (rule 12).
#[derive(Debug, Clone, Serialize)]
pub struct ConnectorHealth {
    /// `true` when the most-recent probe connected within `PROBE_TIMEOUT`.
    pub live: bool,
    /// Wall-clock of that probe in milliseconds.
    pub latency_ms: u128,
    /// When the probe ran, as Unix epoch milliseconds — lets the UI age the
    /// reading ("checked 4s ago").
    pub checked_at_ms: u64,
    /// Redacted failure reason when `!live`. Absent on success.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Result of an on-demand liveness probe.
#[derive(Debug, Serialize)]
pub struct ProbeResult {
    /// Echoed connector name.
    pub name: String,
    /// Echoed kind.
    pub kind: &'static str,
    /// `true` when a fresh connector build/connect succeeded within the
    /// timeout.
    pub live: bool,
    /// Wall-clock of the probe in milliseconds.
    pub latency_ms: u128,
    /// Redacted failure reason when `!live` (connector errors already scrub
    /// credentials). Absent on success.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl ConnectorMonitor {
    /// Build from the configured catalogs, the set of names that registered at
    /// boot (typically `server.config.catalogs` + `server.catalogs.keys()`), and
    /// the boot-built health handles for the SQL connectors that expose
    /// a cheap-liveness probe. A name absent from `health_handles` falls back to
    /// the rebuild probe.
    #[must_use]
    pub fn new(
        configured: Arc<HashMap<String, CatalogConfig>>,
        registered: Arc<HashSet<String>>,
        health_handles: Arc<HashMap<String, crate::config::ConnectorHealthHandle>>,
    ) -> Self {
        Self {
            configured,
            registered,
            health: Arc::new(RwLock::new(HashMap::new())),
            health_handles,
        }
    }

    /// An empty monitor — no connectors configured (single-node demos / tests).
    #[must_use]
    pub fn empty() -> Self {
        Self {
            configured: Arc::new(HashMap::new()),
            registered: Arc::new(HashSet::new()),
            health: Arc::new(RwLock::new(HashMap::new())),
            health_handles: Arc::new(HashMap::new()),
        }
    }

    /// The configured connectors with their boot-registration status, sorted
    /// by name for a stable UI order.
    #[must_use]
    pub fn list(&self) -> Vec<ConnectorSummary> {
        let health = self.health.read().unwrap_or_else(PoisonError::into_inner);
        let mut out: Vec<ConnectorSummary> = self
            .configured
            .iter()
            .map(|(name, cfg)| ConnectorSummary {
                name: name.clone(),
                kind: catalog_kind(cfg),
                registered: self.registered.contains(name),
                health: health.get(name).cloned(),
            })
            .collect();
        out.sort_by(|a, b| a.name.cmp(&b.name));
        out
    }

    /// Supported connector families with **no** configured catalog — the
    /// "available but not wired" tier, so the dashboard shows the whole menu.
    #[must_use]
    pub fn available(&self) -> Vec<AvailableConnector> {
        let configured_kinds: HashSet<&'static str> =
            self.configured.values().map(catalog_kind).collect();
        INVENTORY
            .iter()
            .filter(|fam| !fam.kinds.iter().any(|k| configured_kinds.contains(k)))
            .map(|fam| AvailableConnector {
                name: fam.name,
                feature: fam.feature,
                note: fam.note,
            })
            .collect()
    }

    /// The combined view backing `GET /api/connectors`: configured catalogs +
    /// available-but-not-configured families.
    #[must_use]
    pub fn view(&self) -> ConnectorsView {
        ConnectorsView {
            configured: self.list(),
            available: self.available(),
        }
    }

    /// Probe one connector's reachability *now* under a fixed timeout
    /// (`PROBE_TIMEOUT`), and record the result in the shared health cache so
    /// `/api/connectors` reflects it. `None` when `name` isn't a configured
    /// catalog.
    ///
    /// When a boot-built health handle exists for `name` (SQL connectors), the
    /// probe reuses it (a cheap `SELECT 1`); otherwise it falls back to
    /// rebuilding the connector from config.
    pub async fn probe(&self, name: &str) -> Option<ProbeResult> {
        let cfg = self.configured.get(name)?;
        let result = probe_one(name, cfg, self.health_handles.get(name)).await;
        self.record(&result);
        Some(result)
    }

    /// Probe **every** configured connector concurrently, refresh the health
    /// cache, and return `(name, kind, live)` for each so the caller can drive
    /// the `dataglot_connector_up` gauge. Backs the background health poller
    /// (`crate::observability::spawn_connector_health_poller`).
    pub async fn refresh_health(&self) -> Vec<(String, &'static str, bool)> {
        let entries: Vec<(&String, &CatalogConfig)> = self.configured.iter().collect();
        // join_all polls all probes concurrently on this task — no spawning,
        // so the whole sweep costs one `PROBE_TIMEOUT` in the worst case, not
        // one per source. Each probe reuses the boot-built handle when present
        //, else rebuilds.
        let results = futures::future::join_all(
            entries
                .iter()
                .map(|(name, cfg)| probe_one(name, cfg, self.health_handles.get(name.as_str()))),
        )
        .await;
        {
            let mut health = self.health.write().unwrap_or_else(PoisonError::into_inner);
            for r in &results {
                health.insert(r.name.clone(), ConnectorHealth::from(r));
            }
        }
        results
            .into_iter()
            .map(|r| (r.name, r.kind, r.live))
            .collect()
    }

    /// Store one probe result in the shared health cache.
    fn record(&self, result: &ProbeResult) {
        self.health
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(result.name.clone(), ConnectorHealth::from(result));
    }
}

impl From<&ProbeResult> for ConnectorHealth {
    fn from(r: &ProbeResult) -> Self {
        Self {
            live: r.live,
            latency_ms: r.latency_ms,
            checked_at_ms: now_ms(),
            error: r.error.clone(),
        }
    }
}

/// Current wall-clock time as Unix epoch milliseconds (saturating; `0` if the
/// clock is before the epoch).
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| u64::try_from(d.as_millis()).ok())
        .unwrap_or(0)
}

/// Probe one connector's liveness under [`PROBE_TIMEOUT`] and report whether it
/// is reachable. Free function (no `self`) so the concurrent sweep in
/// [`ConnectorMonitor::refresh_health`] can fan it out without borrow churn.
///
/// When `handle` is `Some` (a boot-built SQL connector, ), liveness is a
/// cheap `SELECT 1` on the already-authenticated client — no rebuild, no
/// re-auth. When `None` (non-SQL sources, or a source that wasn't reachable at
/// boot so no handle was captured), it falls back to rebuilding the connector
/// from config — the exact boot path — so DSN / TLS / catalog-service
/// resolution stays identical. Either way, credentials never leave this module:
/// the reuse handle's error string is credential-safe by contract (rule 12), and
/// the rebuild path's connector errors already scrub credentials.
async fn probe_one(
    name: &str,
    cfg: &CatalogConfig,
    handle: Option<&crate::config::ConnectorHealthHandle>,
) -> ProbeResult {
    let kind = catalog_kind(cfg);
    let start = Instant::now();
    let (live, error) = if let Some(handle) = handle {
        // Reuse path: cheap SELECT 1 on the existing client.
        match tokio::time::timeout(PROBE_TIMEOUT, handle.health_check()).await {
            Ok(Ok(())) => (true, None),
            Ok(Err(msg)) => (false, Some(msg)),
            Err(_) => (
                false,
                Some(format!(
                    "probe timed out after {}s",
                    PROBE_TIMEOUT.as_secs()
                )),
            ),
        }
    } else {
        // Fallback: rebuild the connector from config.
        match tokio::time::timeout(PROBE_TIMEOUT, crate::config::build_one_connector(name, cfg))
            .await
        {
            Ok(Ok(_provider)) => (true, None),
            Ok(Err(e)) => (false, Some(format!("{e:#}"))),
            Err(_) => (
                false,
                Some(format!(
                    "probe timed out after {}s",
                    PROBE_TIMEOUT.as_secs()
                )),
            ),
        }
    };
    let latency_ms = start.elapsed().as_millis();
    ProbeResult {
        name: name.to_string(),
        kind,
        live,
        latency_ms,
        error,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{CatalogConfig, PostgresCatalogConfig};

    fn pg(dsn: &str) -> CatalogConfig {
        CatalogConfig::Postgres(PostgresCatalogConfig {
            dsn: Some(dsn.to_string()),
            ..Default::default()
        })
    }

    fn monitor() -> ConnectorMonitor {
        let mut configured = HashMap::new();
        configured.insert("pg".to_string(), pg("postgres://u@h:5432/db"));
        configured.insert("pg_down".to_string(), pg("postgres://u@h:5432/db"));
        let registered: HashSet<String> = ["pg".to_string()].into_iter().collect();
        // No health handles ⇒ every probe takes the rebuild fallback (the
        // pre- behaviour these tests exercise).
        ConnectorMonitor::new(
            Arc::new(configured),
            Arc::new(registered),
            Arc::new(HashMap::new()),
        )
    }

    /// A `ConnectorHealthCheck` that counts calls and returns a fixed outcome —
    /// proves the reuse path calls `health_check` (no rebuild).
    struct CountingHealthCheck {
        calls: Arc<std::sync::atomic::AtomicUsize>,
        ok: bool,
    }

    #[async_trait::async_trait]
    impl dataglot_federation::ConnectorHealthCheck for CountingHealthCheck {
        async fn health_check(&self) -> Result<(), String> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if self.ok {
                Ok(())
            } else {
                Err("mock source down".to_string())
            }
        }
    }

    #[test]
    fn list_reports_kind_and_registration_sorted() {
        let list = monitor().list();
        assert_eq!(list.len(), 2);
        // Sorted by name: pg, pg_down.
        assert_eq!(list[0].name, "pg");
        assert_eq!(list[0].kind, "postgres");
        assert!(list[0].registered, "pg came up at boot");
        assert_eq!(list[1].name, "pg_down");
        assert!(!list[1].registered, "pg_down configured but not registered");
    }

    #[test]
    fn empty_monitor_lists_nothing() {
        assert!(ConnectorMonitor::empty().list().is_empty());
    }

    #[test]
    fn available_excludes_configured_families_and_lists_the_rest() {
        // Only Postgres is configured, so PostgreSQL drops out of `available`
        // while unconfigured families (Snowflake, Oracle, …) remain.
        let names: Vec<&str> = monitor().available().iter().map(|a| a.name).collect();
        assert!(
            !names.contains(&"PostgreSQL"),
            "a configured family must not appear as available: {names:?}"
        );
        assert!(
            names.contains(&"Snowflake"),
            "unconfigured family listed: {names:?}"
        );
        assert!(names.contains(&"Oracle"));
    }

    #[test]
    fn empty_monitor_makes_every_family_available() {
        // Nothing configured ⇒ the whole inventory is on offer.
        assert_eq!(ConnectorMonitor::empty().available().len(), INVENTORY.len());
    }

    #[test]
    fn view_combines_configured_and_available() {
        let v = monitor().view();
        assert_eq!(v.configured.len(), 2);
        // Whole inventory minus the one configured family (PostgreSQL).
        assert_eq!(v.available.len(), INVENTORY.len() - 1);
    }

    #[test]
    fn rest_family_is_in_the_inventory_keyed_on_the_rest_kind() {
        // Regression: the generic REST connector (, `kind = "rest"`) was
        // missing from the inventory — it lived only inside the OData family's
        // name, with no `rest` kind — so a `kind = "rest"` catalog never showed
        // as configured and there was no REST tile in `available`.
        let rest = INVENTORY
            .iter()
            .find(|f| f.kinds.contains(&"rest"))
            .expect("a family keyed on the `rest` catalog kind must exist");
        assert!(rest.name.contains("REST"));
        // And OData stays its own family (not conflated with REST).
        assert!(INVENTORY
            .iter()
            .any(|f| f.kinds.contains(&"odata") && !f.kinds.contains(&"rest")));
    }

    #[tokio::test]
    async fn probe_unknown_connector_is_none() {
        assert!(monitor().probe("nope").await.is_none());
    }

    #[test]
    fn list_reports_no_health_before_any_probe() {
        // Health is `None` until the first probe/refresh — the UI shows that
        // as "unknown", distinct from "down".
        let list = monitor().list();
        assert!(list.iter().all(|c| c.health.is_none()));
    }

    #[tokio::test]
    async fn on_demand_probe_populates_the_health_cache() {
        // An on-demand probe of an unroutable host records a `live: false`
        // reading that a subsequent `list()` surfaces.
        let mut configured = HashMap::new();
        configured.insert(
            "pg".to_string(),
            pg("postgres://user:hunter2@127.0.0.1:1/db"),
        );
        let m = ConnectorMonitor::new(
            Arc::new(configured),
            Arc::new(HashSet::new()),
            Arc::new(HashMap::new()),
        );
        m.probe("pg").await.expect("configured connector probes");
        let summary = m.list();
        let health = summary[0].health.as_ref().expect("probe recorded health");
        assert!(!health.live, "unroutable host must cache as down");
        assert!(health.checked_at_ms > 0, "a timestamp must be stamped");
        if let Some(err) = &health.error {
            assert!(
                !err.contains("hunter2"),
                "cached error must not leak DSN: {err}"
            );
        }
    }

    #[tokio::test]
    async fn refresh_health_probes_every_connector_and_reports_liveness() {
        // Two unroutable connectors: the sweep must return a `(name, kind,
        // live)` tuple per connector and populate the cache for both.
        let m = monitor();
        let states = m.refresh_health().await;
        assert_eq!(states.len(), 2, "one tuple per configured connector");
        assert!(states
            .iter()
            .all(|(_, kind, live)| *kind == "postgres" && !*live));
        let names: Vec<&str> = states.iter().map(|(n, _, _)| n.as_str()).collect();
        assert!(names.contains(&"pg") && names.contains(&"pg_down"));
        // Both connectors now carry a cached (down) reading.
        assert!(m
            .list()
            .iter()
            .all(|c| c.health.as_ref().is_some_and(|h| !h.live)));
    }

    #[tokio::test]
    async fn probe_unreachable_connector_reports_not_live_without_leaking_dsn() {
        // Points at an unroutable host; the build/connect fails (or times out),
        // and the result must be `live: false` with a redacted error that does
        // not surface the DSN password.
        let mut configured = HashMap::new();
        configured.insert(
            "pg".to_string(),
            pg("postgres://user:hunter2@127.0.0.1:1/db"),
        );
        let m = ConnectorMonitor::new(
            Arc::new(configured),
            Arc::new(HashSet::new()),
            Arc::new(HashMap::new()),
        );
        let r = m.probe("pg").await.expect("configured connector probes");
        assert!(!r.live, "unroutable connector must not be live");
        assert_eq!(r.kind, "postgres");
        if let Some(err) = &r.error {
            assert!(
                !err.contains("hunter2"),
                "probe error must not leak the DSN password: {err}"
            );
        }
    }

    #[tokio::test]
    async fn probe_reuses_health_handle_without_rebuilding() {
        //: when a boot-built handle exists for a catalog, the on-demand
        // probe checks liveness via `health_check` (a SELECT 1 on the existing
        // client) — NOT by rebuilding the connector. The DSN points at an
        // unroutable host, so a rebuild probe would report `live: false`; the
        // reuse path instead reports the handle's `Ok` as live AND increments the
        // call counter, proving `health_check` ran.
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut configured = HashMap::new();
        configured.insert("pg".to_string(), pg("postgres://u@127.0.0.1:1/db"));
        let handle: crate::config::ConnectorHealthHandle = Arc::new(CountingHealthCheck {
            calls: Arc::clone(&calls),
            ok: true,
        });
        let handles = HashMap::from([("pg".to_string(), handle)]);
        let m = ConnectorMonitor::new(
            Arc::new(configured),
            Arc::new(HashSet::new()),
            Arc::new(handles),
        );

        let r = m.probe("pg").await.expect("configured connector probes");
        assert!(
            r.live,
            "reuse path must report the handle's Ok as live (no rebuild of the unroutable DSN)"
        );
        assert_eq!(
            calls.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "health_check must be called exactly once (reuse, not rebuild)"
        );
        // The live reading is cached for `/api/connectors`.
        assert!(m.list()[0].health.as_ref().is_some_and(|h| h.live));
    }

    #[tokio::test]
    async fn refresh_health_uses_handle_for_reuse_and_rebuild_for_the_rest() {
        // Mixed sweep: `pg` has a (failing) handle → reuse path; `pg_down` has no
        // handle → rebuild fallback. Both must be probed, and the handled one's
        // `health_check` must be the thing that ran (counter increments).
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut configured = HashMap::new();
        configured.insert("pg".to_string(), pg("postgres://u@127.0.0.1:1/db"));
        configured.insert("pg_down".to_string(), pg("postgres://u@127.0.0.1:1/db"));
        let handle: crate::config::ConnectorHealthHandle = Arc::new(CountingHealthCheck {
            calls: Arc::clone(&calls),
            ok: false,
        });
        let handles = HashMap::from([("pg".to_string(), handle)]);
        let m = ConnectorMonitor::new(
            Arc::new(configured),
            Arc::new(HashSet::new()),
            Arc::new(handles),
        );

        let states = m.refresh_health().await;
        assert_eq!(states.len(), 2, "one tuple per configured connector");
        // The handled connector's health_check ran exactly once.
        assert_eq!(
            calls.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "the handle's health_check must run once for the reuse path"
        );
        // Both are down (handle returned Err; the other's rebuild fails on the
        // unroutable DSN), and the handle's redacted message is surfaced.
        let pg = m
            .list()
            .into_iter()
            .find(|c| c.name == "pg")
            .expect("pg listed");
        let health = pg.health.expect("pg has a cached reading");
        assert!(!health.live);
        assert_eq!(health.error.as_deref(), Some("mock source down"));
    }
}

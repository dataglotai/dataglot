//! Dataglot server implementation.
//!
//! This module contains the main server that:
//! 1. Bootstraps the `SessionContext` with federation and policy support
//! 2. Wires up all subsystems
//! 3. Starts the pg wire listener
//! 4. Spawns the Prometheus `/metrics` HTTP listener as a sibling task

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use datafusion::catalog::{
    CatalogProvider as DfCatalogProvider, CatalogProviderList, MemoryCatalogProvider,
    MemoryCatalogProviderList,
};
use datafusion::execution::session_state::SessionStateBuilder;
use std::time::Duration;

use datafusion::optimizer::{AnalyzerRule, OptimizerRule};
use datafusion::prelude::SessionContext;
use tokio::net::TcpListener;
use tokio::sync::broadcast;

use dataglot_core::governance::DynDataProductPublisher;
use dataglot_core::lineage::DynLineageEmitter;
use dataglot_core::{
    build_scoped_pg_catalog_schema_with_roles, CatalogBinding, PgCatalogOverlayProvider,
    PgRoleSpec, SessionContextFactory,
};
use dataglot_policy::{
    ColumnWhitelistEnforcer, InMemoryRuleStore, PolicyAnalyzerRule, PolicyEnforcer,
    PolicyOptimizerRule,
};

use dataglot_catalog::{CatalogProviderCache, CatalogService, MetaStore, RedbMetaStore};
// The JSON `EmbeddedMetaStore` is now only a test double (production embedded
// storage is `RedbMetaStore`); import it just for the tests below.
#[cfg(test)]
use dataglot_catalog::EmbeddedMetaStore;

use crate::config::{
    build_connectors_with_health, build_one_connector, build_rule_store_with_lineage,
    build_warehouse_connector, resolve_identity_with_roles, CatalogConfig, CatalogServiceConfig,
    DerivedProductConfig, MaterializationBacking, ServerConfig,
};
use crate::governance::{build_publishers, publish_all_bindings, spawn_binding_change_publisher};
use crate::lineage::{build_lineage_emitter, LineageObserver};
use crate::maintenance::{build_compaction_jobs, build_orphan_sweep_jobs};
use crate::materialization::{build_refresh_jobs, RefreshScheduler};
use crate::observability::{spawn_metrics_server, Metrics};
use crate::query_registry::{QueryRegistry, QueryRegistryObserver};
use crate::session_registry::SessionRegistry;
use crate::webhook::spawn_webhook_server;
use dataglot_federation::iceberg::WarehouseConnector;

/// Outcome of authenticating a Flight SQL request.
///
/// Mirrors the pg-wire auth posture so the Flight listener is never a weaker
/// door: `Trust` honours the asserted username, `Md5` verifies the Basic
/// password against the same [`PasswordSource`](dataglot_pgwire::PasswordSource)
/// the pg-wire md5 path uses.
#[cfg(feature = "flight_sql")]
pub(crate) enum FlightAuth {
    /// Run the request under this resolved identity.
    Ok(dataglot_policy::Identity),
    /// Credentials required or invalid (md5 mode) — maps to gRPC `UNAUTHENTICATED`.
    Unauthenticated(&'static str),
    /// Malformed `authorization` header — maps to gRPC `UNAUTHENTICATED` with a
    /// format hint (treated as an auth failure, not `INVALID_ARGUMENT`).
    BadHeader(&'static str),
}

/// Parse `Authorization: Basic <base64(user:password)>` into `(user, password)`.
/// Returns `None` for any other scheme or a malformed value. Rule 12: the
/// decoded password is returned only for an immediate constant-time compare and
/// is never logged.
#[cfg(feature = "flight_sql")]
fn parse_basic_auth(header: &str) -> Option<(String, String)> {
    use base64::Engine as _;
    let b64 = header
        .strip_prefix("Basic ")
        .or_else(|| header.strip_prefix("basic "))?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .ok()?;
    let creds = String::from_utf8(decoded).ok()?;
    let (user, password) = creds.split_once(':')?;
    Some((user.to_string(), password.to_string()))
}

/// Constant-time byte equality for the password compare — folds XOR over the
/// bytes so a wrong password can't be recovered by timing. The length check
/// leaks only length (immaterial for a password sent over TLS). A small helper
/// rather than a new crypto dependency for a single comparison.
#[cfg(feature = "flight_sql")]
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// A snapshot of the registered federated catalogs, keyed by the name used
/// in three-part references. Shared as an `Arc` so a session clones a cheap
/// pointer, and swapped atomically by the control-plane refresh task.
type CatalogSnapshot = HashMap<String, Arc<dyn DfCatalogProvider>>;

/// Live, swappable catalog registry (slice B; per-org since  M2).
/// Keyed by org, each entry is that org's current `Arc<CatalogSnapshot>`.
/// Readers (`current_catalogs_for_org`) `.read()` and clone the requested
/// org's `Arc`; the single refresh task `.write()`s a rebuilt snapshot for
/// **only the changed org** (`BindingChange.org_id`). Lock-free on the read
/// path (the guard is held only long enough to clone one `Arc`). An org with
/// no entry has no catalogs (empty snapshot).
type LiveCatalogRegistry = Arc<std::sync::RwLock<HashMap<String, Arc<CatalogSnapshot>>>>;

/// The main Dataglot server.
pub struct DataglotServer {
    config: ServerConfig,
    session_factory: SessionContextFactory,
    /// Phase 2 spec 02 slice 3a — `Some(...)` when `config.ballista`
    /// is set AND the `ballista` feature is compiled in. Boots once at
    /// `Self::new` and stays alive for the server's whole lifetime;
    /// per-pgwire-session contexts are minted from it via
    /// `BallistaCluster::create_session`. `None` ⇒ single-node path,
    /// `create_session` falls back to `session_factory`.
    #[cfg(feature = "ballista")]
    ballista_cluster: Option<Arc<dataglot_ballista::BallistaCluster>>,
    /// Federated catalogs to register on every new pgwire session.
    /// Keys are the names that appear in three-part references
    /// (`<catalog>.<schema>.<table>`). The `Arc` is shared across all
    /// sessions because the underlying `*Catalog` types cache their
    /// schema lists at construction time.
    catalogs: HashMap<String, Arc<dyn DfCatalogProvider>>,
    /// Cheap-liveness handles over the boot-built SQL connectors,
    /// keyed by catalog name. The connector-health poller / on-demand probe uses
    /// a handle's `health_check` (a `SELECT 1` on the already-authenticated
    /// client) instead of rebuilding the connector every tick. Non-SQL catalogs
    /// have no entry; the poller falls back to the rebuild probe for them.
    /// Handed to [`crate::connectors::ConnectorMonitor`] at metrics-server boot.
    health_handles: Arc<HashMap<String, crate::config::ConnectorHealthHandle>>,
    /// Live catalog registry for the control-plane path (slice B). `Some`
    /// when a `catalog_service` is configured: `create_session` reads the
    /// current snapshot from here instead of the static `catalogs` above,
    /// and a background refresh task swaps in a rebuilt snapshot on every
    /// store `BindingChange` — so a NEW connection sees an out-of-band
    /// store change (external tooling, a second instance, or slice C's DDL)
    /// with no restart. `None` on the no-control-plane path, where the
    /// static `catalogs` is authoritative.
    live_catalogs: Option<LiveCatalogRegistry>,
    /// The org the boot/file catalogs are registered under (: the
    /// configured `catalog_service.org_id`, default `"default"`). `create_session`
    /// builds every connection with this org's catalog set (the org isn't known
    /// until the pgwire startup handshake); the `StartupObserver` re-registers
    /// per the connection's resolved org when it differs.
    boot_org: String,
    /// The live meta-store handle, kept for the read-only Control Plane
    /// dashboard view (`GET /api/control-plane`, ). `Some` exactly when a
    /// `catalog_service` is configured (a clone of the slice-C `ddl_store`).
    control_plane_store: Option<Arc<dyn MetaStore>>,
    /// SQL-native catalog-DDL executor. `Some` when a
    /// `catalog_service` is configured — it holds the same meta-store handle
    /// the live registry refreshes from, so a `CREATE / ALTER / DROP CATALOG`
    /// persists through here and the store's change feed refreshes
    /// [`Self::live_catalogs`] for every *other* session. Handed to each
    /// connection via the [`dataglot_pgwire::ConnectionSecurity`] bundle, so
    /// the pgwire handler effects `CREATE / ALTER / DROP CATALOG` at the wire
    /// boundary and reflects it into the issuing session.
    catalog_admin: Option<Arc<dyn dataglot_pgwire::catalog_admin::CatalogAdmin>>,
    /// SQL-native secret-DDL executor. `Some` only when both a
    /// control-plane store and a `DATAGLOT_SECRET_KEY` envelope key are present;
    /// handed to each connection so `CREATE / DROP SECRET` encrypts + persists.
    secret_admin: Option<Arc<dyn dataglot_pgwire::secret_admin::SecretAdmin>>,
    /// SQL-native user/role-DDL executor. `Some` when a
    /// control-plane store is present; handed to each connection so
    /// `CREATE / ALTER / DROP USER` + `CREATE / DROP ROLE` persist, and a
    /// runtime-created user can then authenticate via md5 (see the store-backed
    /// `PasswordSource` layered into [`Self::auth`]).
    user_admin: Option<Arc<dyn dataglot_pgwire::user_admin::UserAdmin>>,
    /// SQL-native policy-DDL executor. `Some` when a
    /// control-plane store is present (production boot always builds a
    /// `rule_store`); handed to each connection so `CREATE / DROP MASK` +
    /// `CREATE / DROP ROW FILTER` apply to the live enforcer
    /// ([`Self::rule_store`]) and persist to the store, surviving restart.
    policy_admin: Option<Arc<dyn dataglot_pgwire::policy_admin::PolicyAdmin>>,
    /// SQL-native grant-DDL executor. `Some` when a
    /// control-plane store is present; handed to each connection so
    /// `GRANT / REVOKE` persists privileges + role memberships to the store.
    /// **F5a stores only — no enforcement** (that is F5b), so this changes no
    /// query behaviour.
    grant_admin: Option<Arc<dyn dataglot_pgwire::grant_admin::GrantAdmin>>,
    /// SQL-native view-DDL executor. `Some` when a
    /// control-plane store is present; handed to each connection so
    /// `CREATE / DROP VIEW` persists a derived product and registers it into
    /// [`Self::live_views`], making it queryable by subsequent connections.
    view_admin: Option<Arc<dyn dataglot_pgwire::view_admin::ViewAdmin>>,
    /// Live registry of derived-product views per org.
    /// `Some` on the control-plane path: `create_session` reads it to register
    /// each org's views as queryable tables, and [`Self::view_admin`] writes it
    /// on a runtime `CREATE / DROP VIEW` — so a NEW connection sees the change
    /// with no restart (the same visibility model as [`Self::live_catalogs`]).
    /// `None` on the no-control-plane fast path.
    live_views: Option<crate::view_admin::LiveViewRegistry>,
    /// Policy enforcer registered as the first `OptimizerRule` on
    /// every new pgwire session. Production boot installs the
    /// `MutableEnforcer` published by the
    /// [`rule_store`](Self::rule_store) — a static enforcer in
    /// disguise until slice 3's webhook handler starts calling
    /// `RuleStore::apply`. Tests inject a fully-static enforcer via
    /// `new_with_catalogs_and_enforcer`. With the no-op (or empty)
    /// enforcer, the rule's `rewrite` returns `Transformed::no` and
    /// `DataFusion`'s fixed-point loop drops it after one pass —
    /// the runtime cost is a couple of pointer indirections per
    /// query.
    enforcer: Arc<dyn PolicyEnforcer>,
    /// Column-level whitelist enforcer, or `None` when no
    /// `[[column_grants]]` are configured. Runs as an **analyzer-stage** rule
    /// (installed in [`Self::create_session`]) rather than in `enforcer` above,
    /// because it changes the plan's output schema — which an `OptimizerRule`
    /// may not.
    whitelist_enforcer: Option<Arc<ColumnWhitelistEnforcer>>,
    /// Inbound governance rule store (Phase 2 spec 04 slice 2).
    /// `Some(...)` for the production boot path that goes through
    /// [`Self::new`]; `None` for tests that inject a static
    /// `enforcer` directly via `new_with_catalogs_and_enforcer`.
    ///
    /// Slice 3's webhook handler will take a `Arc<InMemoryRuleStore>`
    /// out of this field to call `apply(change)` on incoming events;
    /// the `enforcer` field is itself the `Arc<MutableEnforcer>`
    /// the store publishes to, so a successful `apply` is visible
    /// to every active session on the next query without any
    /// further plumbing.
    rule_store: Option<Arc<InMemoryRuleStore>>,
    /// Lineage emitter built from `config.lineage`. `None` config
    /// ⇒ `NoopLineageEmitter` — emission cost is two trait-object
    /// indirections per query. The `Arc<dyn LineageEmitter>` is
    /// cheap to clone into the per-connection `LineageObserver`.
    lineage_emitter: DynLineageEmitter,
    /// Configured column masks, parsed once at boot and shared
    /// (cloned `Arc`) into every connection's `LineageObserver`
    /// to overlay the `masking` flag on emitted column lineage.
    masked_columns: Arc<crate::lineage::MaskedColumns>,
    /// Boot-time lineage snapshot served at `GET /lineage` on the
    /// observability listener: the derived-products graph
    /// plus configured/propagated mask annotations, frozen at boot —
    /// the same graph the rule store consumed for propagation.
    lineage_snapshot: Arc<crate::lineage_snapshot::LineageSnapshot>,
    /// Typed classification of each registered catalog
    /// (Architecture Decisions v3.0 §09). Keys match `catalogs`
    /// by construction. Informational only in Phase 1 — the
    /// upcoming Peaka Catalog Service spec (task 08) consumes
    /// it for invalidation routing and sharing-policy
    /// enforcement. Read via [`Self::bindings`].
    bindings: HashMap<String, CatalogBinding>,
    /// Catalog-provider read-path cache (Phase 1 task 09). Set
    /// when `config.catalog_service` is configured; pre-warmed
    /// at boot for every entry in `config.catalogs`. Phase 1
    /// invalidates the cache on LISTEN/NOTIFY events but
    /// doesn't propagate evictions to *existing* sessions —
    /// new sessions see the latest, old ones keep their
    /// snapshot. Phase 2 adds the dynamic-propagation proxy.
    _cache: Option<Arc<CatalogProviderCache>>,
    /// Handle for the cache's LISTEN/NOTIFY invalidation task. `run` moves it
    /// into [`BackgroundTasks`] at startup and drains it on shutdown.
    cache_invalidation: Option<tokio::task::JoinHandle<()>>,
    /// Handle for the governance-publisher `BindingChange`
    /// subscriber task — Phase 1 §11 Interface #2 slice 3.
    /// `Some(...)` when both a catalog service is configured
    /// *and* at least one governance publisher is configured. `run` moves it
    /// into [`BackgroundTasks`] and drains it on shutdown.
    governance_invalidation: Option<tokio::task::JoinHandle<()>>,
    /// Handles for the materialization refresh scheduler tasks, one
    /// per `Materialized` derived product. `run` moves them into
    /// [`BackgroundTasks`] and drains them on shutdown.
    materialization_refresh: Vec<tokio::task::JoinHandle<()>>,
    /// Governance data-product publishers built from config (Phase 1 §11).
    /// Held on `self` so `run` can spawn the `BindingChange` subscriber
    /// *after* the pgwire listener binds, rather than in `new`.
    publishers: Vec<DynDataProductPublisher>,
    /// Whether any catalog needs the federation optimizer/planner. Held so
    /// the refresh scheduler can be spawned post-bind in `run`.
    needs_federation: bool,
    /// Live status of each materialized product's refresh (state, last
    /// rows/duration, next run). Written by the refresh scheduler's closures
    /// and read by `GET /api/materialization` — the dashboard's freshness view
    ///. Empty when nothing is materialized.
    materialization_status: crate::materialization_registry::MaterializationRegistry,
    /// Live status of scheduled warehouse maintenance (compaction / orphan
    /// cleanup). Written by the maintenance job closures and read by
    /// `GET /api/maintenance` — the dashboard's lakehouse-upkeep view.
    /// Empty when no maintenance is configured.
    maintenance_status: crate::maintenance_registry::MaintenanceRegistry,
    shutdown_tx: broadcast::Sender<()>,
    metrics: Metrics,
    /// Live in-flight query registry. Shared into every
    /// connection's per-query observer and read by `GET /api/queries`
    /// on the metrics HTTP server — the dashboard's "what's running".
    query_registry: QueryRegistry,
    /// Live registry of connected pgwire sessions (user · org · peer ·
    /// connected-since). Shared into the connection handler — which
    /// registers on connect, resolves identity from the `StartupObserver`,
    /// and deregisters on drop — and read by `GET /api/sessions`, the
    /// dashboard's "who is connected" view. The per-connection detail behind
    /// the aggregate `pgwire_connections_active` gauge.
    session_registry: SessionRegistry,
    /// Server-wide registry of live pgwire connections' backend keys +
    /// cancel senders. Shared into every connection's handler
    /// factory so a `CancelRequest` — which arrives on its own TCP
    /// connection — can cancel a query running on any other connection.
    cancel_registry: Arc<dataglot_pgwire::CancelRegistry>,
    /// Connection authentication mode, built once at boot from
    /// `config.auth` + the credentials named by each identity's
    /// `password_env` (resolved from the environment). Cloned (cheap —
    /// `Arc` inside) into every connection's pgwire handler. Defaults to
    /// [`dataglot_pgwire::AuthMode::Trust`].
    auth: dataglot_pgwire::AuthMode,
    /// pgwire ingress TLS (acceptor + require flag), built once at boot
    /// from `config.pgwire_tls`. `None` ⇒ plaintext listener. Cloned
    /// (cheap — `Arc` inside) into every connection.
    pgwire_tls: Option<dataglot_pgwire::IngressTls>,
    /// pgwire connection rate limiter (concurrent-connection ceilings),
    /// built once at boot from `config.rate_limit`. `None` ⇒ no admission
    /// control. Borrowed on the accept path before the handshake.
    rate_limiter: Option<crate::rate_limit::ConnectionLimiter>,
    /// Per-identity admission control (bounds connections per username),
    /// built once at boot from `config.rate_limit.max_connections_per_identity`.
    /// `None` ⇒ no per-identity limit. Passed into the pgwire handler, which
    /// consults it on the startup message.
    identity_admission: Option<Arc<dyn dataglot_pgwire::IdentityAdmission>>,
    /// Directory-group resolver, built once at boot from `config.auth`
    /// (derived from the same [`AuthMode`](dataglot_pgwire::AuthMode) value):
    /// [`ConfigGroupResolver`](crate::group_resolver::ConfigGroupResolver) for
    /// trust / md5 / scram, or the JWT / LDAP resolver in those modes. Cloned
    /// into every connection's startup observer, where its sync
    /// [`resolve_session_groups`](crate::group_resolver::GroupResolver::resolve_session_groups)
    /// maps the auth-resolved directory groups into `Identity::org_groups`.
    group_resolver: Arc<dyn crate::group_resolver::GroupResolver>,
}

/// Per-task drain timeout on shutdown before a stuck background task is
/// aborted, so shutdown can't hang on one that ignores the shutdown signal.
const BG_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

/// The long-lived background tasks spawned at boot — cache invalidation, the
/// governance `BindingChange` subscriber, and the materialization refresh
/// scheduler. Held *outside* the connection-serving `Arc<Self>` so
/// [`DataglotServer::run`] can drain them explicitly on shutdown, and abort
/// them if foreground startup fails, rather than relying on the
/// `shutdown_tx` Sender-drop.
struct BackgroundTasks {
    handles: Vec<tokio::task::JoinHandle<()>>,
}

impl BackgroundTasks {
    /// Move the long-lived task handles out of `server` (leaving its fields
    /// empty), so they aren't buried in the `Arc<Self>` the accept loop shares.
    fn take_from(server: &mut DataglotServer) -> Self {
        let mut handles = Vec::new();
        handles.extend(server.cache_invalidation.take());
        handles.extend(server.governance_invalidation.take());
        handles.append(&mut server.materialization_refresh);
        Self { handles }
    }

    /// Add handles spawned after the collection was taken — the
    /// post-bind tasks (`run` spawns them once the pgwire listener is up),
    /// so they still drain on shutdown alongside the boot-time handles.
    fn extend(&mut self, handles: Vec<tokio::task::JoinHandle<()>>) {
        self.handles.extend(handles);
    }

    /// Abort every task immediately — the foreground-startup-failed path,
    /// where there's nothing to drain gracefully.
    fn abort_all(&self) {
        for h in &self.handles {
            h.abort();
        }
    }

    /// Await each task to finish (they observe the shutdown broadcast), with a
    /// bounded per-task timeout after which the task is aborted so shutdown
    /// can't hang on a task that doesn't honor the signal. Tasks are drained
    /// concurrently, so total shutdown time is bounded by one timeout, not
    /// `N × timeout`.
    async fn drain(self) {
        futures::future::join_all(self.handles.into_iter().map(|h| async move {
            let abort = h.abort_handle();
            if tokio::time::timeout(BG_DRAIN_TIMEOUT, h).await.is_err() {
                abort.abort();
            }
        }))
        .await;
    }
}

/// The foreground listeners started by [`DataglotServer::run`] after the
/// background tasks are in hand — the pgwire listener plus the optional
/// sibling servers. Bundled so a startup failure can be handled in one place
/// (abort the background tasks, then propagate).
struct ForegroundListeners {
    listener: TcpListener,
    metrics_handle: Option<tokio::task::JoinHandle<()>>,
    webhook_handle: Option<crate::webhook::WebhookServerHandle>,
    policy_explain_handle: Option<crate::policy_explain::PolicyExplainServerHandle>,
}

/// Decision for how a pgwire connection's `database` startup parameter
/// maps to the session's default catalog (Postgres `\c <db>` semantics).
/// Split out from the startup closure so the decision is unit-testable
/// without standing up a live pgwire connection.
#[derive(Debug, PartialEq, Eq)]
enum ConnectionDefaultCatalog {
    /// `database` named a registered catalog — set it as the default.
    Apply(String),
    /// `database` was provided but isn't a registered catalog — keep the
    /// server default and warn (carries the name for the log line).
    UnknownCatalog(String),
    /// No (or empty) `database` — keep the server's configured default.
    Keep,
}

/// Resolve the per-connection default-catalog decision from the pgwire
/// `database` startup parameter and a catalog-existence predicate.
fn connection_default_catalog(
    database: Option<&str>,
    is_registered: impl Fn(&str) -> bool,
) -> ConnectionDefaultCatalog {
    match database {
        None => ConnectionDefaultCatalog::Keep,
        Some(db) if is_registered(db) => ConnectionDefaultCatalog::Apply(db.to_string()),
        Some(db) => ConnectionDefaultCatalog::UnknownCatalog(db.to_string()),
    }
}

/// Resolve the **concrete** org a session belongs to.
///
/// Precedence: a config-defined / authenticated identity's `org` wins;
/// otherwise the store-resolved auth org (md5 global-unique usernames);
/// otherwise the boot org. Crucially this **never** returns `None` — a
/// trust/default (org-less) session resolves to `boot_org`. That is what
/// keeps a session's *effective* org and the org its policy DDL is tagged
/// with in agreement: a `CREATE MASK` such a session runs is applied under
/// `boot_org`, and its own identity now also carries `Some(boot_org)`, so
/// `dataglot_policy::org_rule_applies(Some(boot_org), identity)` matches and
/// the mask fires for its creator. Before F4 the applied org (`"default"`)
/// and the enforcement org (`None`) disagreed and the mask never fired.
fn resolved_session_org(
    identity_org: Option<&str>,
    auth_org: Option<String>,
    boot_org: &str,
) -> String {
    identity_org
        .map(str::to_string)
        .or(auth_org)
        .unwrap_or_else(|| boot_org.to_string())
}

///  — human-readable execution mode for this server, derived from
/// the resolved config: `"single-node"`, or
/// `"distributed (parallelism N)"` when a `[ballista]` block is present.
///
/// A `Some(ballista)` config on a running server implies the cluster
/// actually booted: without the `ballista` feature, boot rejects that
/// config outright, and with it, a failed cluster boot aborts `new()`.
/// So the config is a faithful proxy for the live execution mode.
fn execution_mode_label(ballista: Option<&crate::config::BallistaServerConfig>) -> String {
    match ballista {
        Some(b) => format!("distributed (parallelism {})", b.standalone_parallelism),
        None => "single-node".to_string(),
    }
}

///  — register a per-session `current_database()` UDF that returns
/// `ctx`'s *effective* default catalog (Model A: catalog-as-database),
/// overriding `datafusion-pg-catalog`'s hardcoded `"datafusion"`.
///
/// Called from the `StartupObserver` *after* the `database` startup
/// parameter has been mapped to the session's `default_catalog`, so
/// reading the value back from session config covers every mapping arm
/// uniformly (a named registered catalog, or the server default when the
/// client named an unknown/empty database). `SessionContext::register_udf`
/// replaces by name, so this shadows the upstream UDF for this session.
fn register_session_current_database(ctx: &SessionContext) {
    let current_db = {
        let state_ref = ctx.state_ref();
        let state = state_ref.read();
        state.config().options().catalog.default_catalog.clone()
    };
    ctx.register_udf(dataglot_core::functions::current_database_udf(&current_db));
    // psql v16+'s `\dt` filters on `pg_table_is_visible(c.oid)` —
    // register the always-true shim alongside.
    ctx.register_udf(dataglot_core::functions::pg_table_is_visible_udf());
    // psql `\df` / `\dT` filter on `pg_function_is_visible` /
    // `pg_type_is_visible`; datafusion-pg-catalog doesn't provide these, so
    // register always-true shims here (both modes) so those commands work
    ctx.register_udf(dataglot_core::functions::pg_function_is_visible_udf());
    ctx.register_udf(dataglot_core::functions::pg_type_is_visible_udf());
}

/// Register every catalog in `catalogs` into `ctx`, each wrapped with its
/// `pg_catalog` schema overlay (/48) so psql / JDBC introspection works
/// regardless of the connected `--database`. Shared by `create_session` (boot
/// org, at connect time) and the `StartupObserver`'s per-org re-registration
///, so both paths build identical overlays.
///
/// `register_catalog` returning a previous provider is the NORMAL case here,
/// not a collision, so the return is discarded: it replaces the
/// `default_catalog` placeholder (single-node base) or the raw federated
/// catalog (Ballista base) with its overlay-wrapped form. `flat_catalog_list`
/// backs the flat `pg_database` view (`\l`) and must enumerate exactly these
/// catalogs.
fn register_overlay_catalogs(
    ctx: &SessionContext,
    catalogs: &CatalogSnapshot,
    pg_roles: &[PgRoleSpec],
) {
    let flat_catalog_list: Arc<dyn CatalogProviderList> = {
        let list = MemoryCatalogProviderList::new();
        for (name, catalog) in catalogs {
            list.register_catalog(name.clone(), Arc::clone(catalog));
        }
        Arc::new(list)
    };
    for (name, catalog) in catalogs {
        let scoped = build_scoped_pg_catalog_schema_with_roles(
            name,
            Arc::clone(catalog),
            Arc::clone(&flat_catalog_list),
            pg_roles,
        )
        .expect("scoped pg_catalog build must succeed against a freshly-registered catalog");
        let wrapped: Arc<dyn DfCatalogProvider> =
            Arc::new(PgCatalogOverlayProvider::new(Arc::clone(catalog), scoped));
        ctx.register_catalog(name, wrapped);
    }
}

///  — prewarm the process-wide `pg_catalog` static-table cache off
/// the connection path. Those ~60 embedded tables decode exactly once;
/// running that CPU-bound decode here under `spawn_blocking` keeps it off
/// the first client connection's Tokio worker (rule 11), so every
/// `create_session` after boot only reads an initialized `OnceLock`.
/// Idempotent — `create_session` falls back to lazy init if skipped.
async fn prewarm_pg_catalog() -> Result<()> {
    tokio::task::spawn_blocking(dataglot_core::prewarm_pg_catalog_static_tables)
        .await
        .context("pg_catalog static-table prewarm task panicked")?
        .context("Failed to prewarm pg_catalog static tables")?;
    Ok(())
}

/// Build the connection rate limiter from `[rate_limit]` config, once at
/// boot. `None` ⇒ no admission control (unchanged behavior).
fn build_rate_limiter(
    cfg: Option<&crate::config::RateLimitConfig>,
) -> Option<crate::rate_limit::ConnectionLimiter> {
    cfg.map(crate::rate_limit::ConnectionLimiter::new)
}

/// Build the per-identity admission limiter from
/// `[rate_limit].max_connections_per_identity`, once at boot. `None` ⇒ no
/// per-identity limit. Bumps the rejection metric (`reason="identity"`) on
/// refusal.
fn build_identity_admission(
    config: &ServerConfig,
    metrics: &Metrics,
) -> Option<Arc<dyn dataglot_pgwire::IdentityAdmission>> {
    config
        .rate_limit
        .as_ref()
        .and_then(|c| c.max_connections_per_identity)
        .map(|max| {
            let rejected = metrics.pgwire_connections_rejected_total.clone();
            Arc::new(crate::rate_limit::IdentityLimiter::new(max, rejected))
                as Arc<dyn dataglot_pgwire::IdentityAdmission>
        })
}

/// Build the pgwire ingress TLS acceptor from `[pgwire_tls]` config, once
/// at boot. The cert/key read + parse is blocking, so it runs under
/// `spawn_blocking` (rule 11). A bad cert/key fails the boot here
/// (fail-safe), not per connection. Returns `(acceptor, required)`.
async fn build_ingress_tls(
    cfg: Option<crate::config::PgwireTlsConfig>,
) -> Result<Option<dataglot_pgwire::IngressTls>> {
    let Some(t) = cfg else {
        return Ok(None);
    };
    let required = t.mode == crate::config::PgwireTlsMode::Require;
    let acceptor = tokio::task::spawn_blocking(move || {
        dataglot_pgwire::build_tls_acceptor(&t.cert_file, &t.key_file)
    })
    .await
    .context("pgwire TLS acceptor build task panicked")?
    .context("pgwire TLS: failed to build acceptor from configured cert/key")?;
    Ok(Some(dataglot_pgwire::IngressTls { acceptor, required }))
}

/// Register the S3 object stores declared by `object_storage` catalogs on
/// the factory's shared runtime, so `s3://` reads resolve for every session.
/// Runs at boot, before any catalog is built. See
/// [`crate::config::object_storage_s3_stores`].
fn register_object_storage_stores<S: std::hash::BuildHasher>(
    factory: &SessionContextFactory,
    catalogs: &HashMap<String, CatalogConfig, S>,
) -> Result<()> {
    for (cat_name, cat_cfg) in catalogs {
        if let CatalogConfig::ObjectStorage(os) = cat_cfg {
            for (store_url, store) in crate::config::object_storage_s3_stores(cat_name, os)? {
                factory.runtime().register_object_store(&store_url, store);
            }
        }
    }
    Ok(())
}

/// Await the next process-termination signal, returning its name for logging.
///
/// On Unix both **SIGINT** (Ctrl-C) and **SIGTERM** (the signal an init system or
/// Kubernetes sends on stop / rolling update / pod eviction) resolve here, so the
/// server shuts down gracefully on either. On non-Unix only Ctrl-C is available.
/// `Signal::recv` is cancel-safe, so a signal delivered while the caller is in
/// another `select!` branch is latched and picked up on the next poll.
#[cfg(unix)]
async fn wait_for_termination_signal(
    sigint: &mut tokio::signal::unix::Signal,
    sigterm: &mut tokio::signal::unix::Signal,
) -> &'static str {
    tokio::select! {
        _ = sigint.recv() => "SIGINT",
        _ = sigterm.recv() => "SIGTERM",
    }
}

/// Non-Unix fallback: only Ctrl-C is available.
#[cfg(not(unix))]
async fn wait_for_termination_signal() -> &'static str {
    let _ = tokio::signal::ctrl_c().await;
    "Ctrl-C"
}

impl DataglotServer {
    /// Create a new server with the given configuration.
    ///
    /// This is async because it eagerly connects to every configured
    /// catalog at boot — failing fast if a source is unreachable. The
    /// resulting catalog providers are reusable across pgwire sessions
    /// (no per-session reconnect).
    ///
    /// # Errors
    /// Returns an error if the session factory cannot be created, if
    /// any baseline metric cannot be registered, or if a configured
    /// catalog cannot be connected.
    // Boot orchestration: sequentially stands up the factory, object stores,
    // catalogs, cache, governance, lineage, and materialization. Linear by
    // nature — one line over the lint after 's store registration.
    #[allow(clippy::too_many_lines)]
    pub async fn new(config: ServerConfig) -> Result<Self> {
        let session_factory = SessionContextFactory::new(config.to_session_config())
            .context("Failed to create session factory")?;

        register_object_storage_stores(&session_factory, &config.catalogs)?;

        let (shutdown_tx, _) = broadcast::channel(1);

        let metrics = Metrics::new().context("Failed to register baseline metrics")?;

        prewarm_pg_catalog().await?;

        // Connect every configured catalog up front. Two paths:
        //
        // 1. `catalog_service: None` (default) — direct boot via
        //    `build_connectors`. No cache. Same shape as
        //    pre-task-09 behaviour.
        //
        // 2. `Some(...)` — build the cache with a closure that
        //    captures `build_one_connector` over the existing
        //    `config.catalogs` map; pre-warm by calling
        //    `cache.get(name)` for every entry; spawn the
        //    LISTEN/NOTIFY invalidation task.
        //
        // The cache is informational in Phase 1 — eviction
        // affects the *cache* but not existing sessions'
        // registered `Arc<dyn CatalogProvider>` values. Phase 2's
        // runtime-mutation work adds the proxy that makes
        // eviction live-propagate to active sessions.
        // SQL-native secrets (slice D): an envelope cipher from
        // `DATAGLOT_SECRET_KEY`. A malformed key fails boot; an unset key ⇒ no
        // cipher ⇒ secret DDL + `*_secret` references are refused with a clear
        // error (catalogs with inline `dsn`/`dsn_env` are unaffected). Built
        // before the catalogs so the boot + refresh build paths can resolve
        // `dsn_secret` references too.
        let secret_cipher = crate::secret_crypto::SecretCipher::from_env()
            .context("invalid DATAGLOT_SECRET_KEY")?
            .map(Arc::new);

        let (catalogs, cache_handle, cache_task, live_catalogs, ddl_store, health_handles) =
            build_catalogs_and_cache(
                &config.catalogs,
                config.catalog_service.as_ref(),
                config.tolerate_unreachable_catalogs,
                secret_cipher.clone(),
            )
            .await
            .context("Failed to build configured catalogs")?;

        // SQL-native catalog-DDL admin (slice C): present exactly when a
        // control-plane store is configured. Wraps the same store the live
        // registry refreshes from, so a persisted DDL change fans out to other
        // sessions via that refresh. With a cipher present it also gains a
        // secret resolver so `dsn_secret` catalog options resolve at build time.
        // Boot org: the org the file/boot catalogs register under
        // (defaults to `"default"`). Since M2 the DDL admins are org-agnostic —
        // the pgwire handler threads the connection's resolved org per `apply`
        // call — so this value only seeds the boot catalog set + live registry.
        let boot_org: String = config
            .catalog_service
            .as_ref()
            .map_or_else(|| "default".to_string(), |c| c.org_id().to_string());

        let catalog_admin: Option<Arc<dyn dataglot_pgwire::catalog_admin::CatalogAdmin>> =
            ddl_store.as_ref().map(|store| {
                let mut admin = crate::catalog_admin::StoreCatalogAdmin::new(Arc::clone(store));
                if let Some(cipher) = &secret_cipher {
                    let resolver: Arc<dyn crate::config::SecretResolver> =
                        Arc::new(crate::secret_admin::StoreSecretResolver::new(
                            Arc::clone(store),
                            Arc::clone(cipher),
                        ));
                    admin = admin.with_secret_resolver(resolver);
                }
                Arc::new(admin) as Arc<dyn dataglot_pgwire::catalog_admin::CatalogAdmin>
            });

        // SQL-native secret-DDL admin (slice D): present only when BOTH a
        // control-plane store and an envelope key exist.
        let secret_admin: Option<Arc<dyn dataglot_pgwire::secret_admin::SecretAdmin>> =
            match (&ddl_store, &secret_cipher) {
                (Some(store), Some(cipher)) => {
                    Some(Arc::new(crate::secret_admin::StoreSecretAdmin::new(
                        Arc::clone(store),
                        Arc::clone(cipher),
                    ))
                        as Arc<dyn dataglot_pgwire::secret_admin::SecretAdmin>)
                }
                _ => None,
            };

        // SQL-native user/role-DDL admin (slice M3b): present whenever a
        // control-plane store exists. Roles + passwordless users need no key; a
        // statement that sets a password errors clearly without a cipher (like
        // CREATE SECRET), so the cipher is passed through as optional.
        let user_admin: Option<Arc<dyn dataglot_pgwire::user_admin::UserAdmin>> =
            ddl_store.as_ref().map(|store| {
                Arc::new(crate::user_admin::StoreUserAdmin::new(
                    Arc::clone(store),
                    secret_cipher.clone(),
                )) as Arc<dyn dataglot_pgwire::user_admin::UserAdmin>
            });

        // Auth (slice M3b): in md5 mode a user may live in the control-plane
        // store (created at runtime via CREATE USER) OR in config.identities
        // (the boot pre-seed). Layer a store-backed PasswordSource over the
        // config source so a runtime-created user authenticates with no config
        // entry — store wins, config is the fallback (existing configs keep
        // working). Decrypting a stored password needs the envelope key; without
        // it, auth stays config-only (and CREATE USER … PASSWORD is refused, so
        // no store passwords exist to read). Trust mode is untouched.
        let auth = crate::config::build_auth_mode(&config.auth, &config.identities)?;
        let auth = match (&ddl_store, &secret_cipher) {
            (Some(store), Some(cipher)) => {
                // Layer the store-backed source over the config source once;
                // md5 and scram-sha-256 both consume the identical merged
                // `PasswordSource` (store wins, config is the fallback), so a
                // runtime-created user authenticates under either mode.
                let merge = |config_source: Arc<dyn dataglot_pgwire::PasswordSource>| {
                    let store_source: Arc<dyn dataglot_pgwire::PasswordSource> =
                        Arc::new(crate::user_admin::StoreUserPasswordSource::new(
                            Arc::clone(store),
                            Arc::clone(cipher),
                        ));
                    Arc::new(crate::user_admin::MergedPasswordSource::new(
                        store_source,
                        config_source,
                    )) as Arc<dyn dataglot_pgwire::PasswordSource>
                };
                match auth {
                    dataglot_pgwire::AuthMode::Md5(config_source) => {
                        dataglot_pgwire::AuthMode::Md5(merge(config_source))
                    }
                    dataglot_pgwire::AuthMode::ScramSha256(config_source) => {
                        dataglot_pgwire::AuthMode::ScramSha256(merge(config_source))
                    }
                    // Trust needs no PasswordSource; nothing to merge. JWT /
                    // LDAP authenticate against the token / directory,
                    // not a store-backed PasswordSource, so they pass through
                    // unchanged too.
                    other @ (dataglot_pgwire::AuthMode::Trust
                    | dataglot_pgwire::AuthMode::Jwt(_)
                    | dataglot_pgwire::AuthMode::Ldap(_)) => other,
                }
            }
            _ => auth,
        };

        // Build the rule store from the `masks`, `row_filters`, and
        // (optionally) `governance` blocks. Empty everywhere ⇒ the
        // store's snapshot is a `NoopPolicyEnforcer`, identical to
        // pre-slice-2 boot. The store keeps the rules in their
        // primitive form so slice 3's webhook handler can mutate
        // them via `RuleStore::apply`; the enforcer field below
        // holds the `MutableEnforcer` the store publishes to, so
        // every session sees the latest enforcer on its next query
        // without any further wiring.
        // Build the column-lineage graph from the declared derived
        // products (Interface 4,  4b): each product's SQL is
        // planned once here so a source-column mask propagates to the
        // derived columns that descend from it. Best-effort — a product
        // that can't plan is logged + skipped, never blocks boot.
        let needs_federation = config
            .catalogs
            .values()
            .any(CatalogConfig::requires_federation);

        //  F9: merge config `[[derived_products]]` with the boot org's
        // persisted `CREATE VIEW` products so a runtime-created view feeds the
        // lineage graph (mask propagation) exactly like a config one. Persisted
        // products are plain (`Live`) views. Best-effort store read — a failure
        // leaves the config list unchanged.
        let mut lineage_products = config.derived_products.clone();
        if let Some(store) = ddl_store.as_ref() {
            match store.list_derived_products(&boot_org).await {
                Ok(persisted) => {
                    lineage_products.extend(persisted.into_iter().map(|r| DerivedProductConfig {
                        name: r.name,
                        sql: r.sql,
                        catalog: r.catalog,
                        schema: r.schema,
                        backing: MaterializationBacking::Live,
                        materialization: None,
                    }));
                }
                Err(e) => tracing::warn!(
                    error = %format!("{e:#}"),
                    "view: listing persisted derived products for lineage failed; using config only"
                ),
            }
        }

        let lineage_graph = build_lineage_graph(
            &lineage_products,
            &session_factory,
            &catalogs,
            needs_federation,
            &config.default_catalog,
            &config.default_schema,
        )
        .await;

        let rule_store = build_rule_store_with_lineage(
            &config.masks,
            &config.row_filters,
            config.governance.as_ref(),
            &lineage_graph,
            // Session defaults let a fully-qualified propagated mask match
            // a bare-written query that resolves to them.
            Some((
                config.default_catalog.clone(),
                config.default_schema.clone(),
            )),
        )
        .context("Failed to build rule store from config")?;

        // Boot-load SQL-native policies ( M4b + F4): replay every
        // `CREATE MASK` / `CREATE ROW FILTER` persisted under *every* org into
        // the freshly-built rule store — each tagged with its owning org so
        // enforcement stays per-tenant after a restart. Precedence is
        // **store-wins**: config `[[masks]]` / `[[row_filters]]` seed the
        // store above (operator-wide); these upserts replace by
        // (table, column, org) / (table, org). Only present when a
        // control-plane store is configured (otherwise there's nowhere to
        // have persisted them).
        if let Some(store) = ddl_store.as_ref() {
            load_persisted_policies(store.as_ref(), &rule_store)
                .await
                .context("Failed to load persisted policies from the control-plane store")?;
        }

        // SQL-native policy-DDL admin: present when a
        // control-plane store exists (the rule store always exists on this
        // boot path). Applies `CREATE / DROP MASK` + `CREATE / DROP ROW
        // FILTER` to the live enforcer and persists them.
        let policy_admin: Option<Arc<dyn dataglot_pgwire::policy_admin::PolicyAdmin>> =
            ddl_store.as_ref().map(|store| {
                Arc::new(crate::policy_admin::StorePolicyAdmin::new(
                    Arc::clone(store),
                    Arc::clone(&rule_store),
                )) as Arc<dyn dataglot_pgwire::policy_admin::PolicyAdmin>
            });

        // GRANT/REVOKE enforcer. In `[authz] mode = "grant"`,
        // pre-load **every org's** persisted grants (lowered to policy-crate
        // `Grant`s tagged with their org, like `load_persisted_policies` does
        // for masks) and build the live enforcer; in `open` mode this is
        // `None` (no enforcement, existing deployments unchanged). Kept in a
        // named binding so `StoreGrantAdmin` can republish the fresh set on a
        // runtime `GRANT` / `REVOKE`.
        let grant_enforcer = match config.authz.mode {
            crate::config::AuthzMode::Open => None,
            crate::config::AuthzMode::Grant => {
                let grants = match ddl_store.as_ref() {
                    Some(store) => load_all_grants(store.as_ref())
                        .await
                        .context("Failed to load persisted grants from the control-plane store")?,
                    None => Vec::new(),
                };
                crate::config::build_grant_enforcer(
                    config.authz.mode,
                    grants,
                    &config.default_catalog,
                    &config.default_schema,
                )
            }
        };

        // SQL-native grant-DDL admin ( F5a persistence + F5b
        // enforcement freshness): present when a control-plane store exists.
        // Persists `GRANT / REVOKE`, and — in grant mode — republishes the
        // full grant set into `grant_enforcer` so the change goes live for
        // every session's next query (the same visibility model as
        // `CREATE / DROP MASK`).
        let grant_admin: Option<Arc<dyn dataglot_pgwire::grant_admin::GrantAdmin>> =
            ddl_store.as_ref().map(|store| {
                Arc::new(crate::grant_admin::StoreGrantAdmin::new(
                    Arc::clone(store),
                    grant_enforcer.clone(),
                )) as Arc<dyn dataglot_pgwire::grant_admin::GrantAdmin>
            });

        // SQL-native view-DDL (derived products,  F9): present when a
        // control-plane store exists. Build the per-org live view registry
        // (boot-load every persisted `CREATE VIEW` + register config `Live`
        // derived products as queryable views through the *same* builder), then
        // the admin over that registry + store. `create_session` reads the
        // registry so a NEW connection sees runtime-created views; the admin
        // writes it on `CREATE / DROP VIEW`. A masked source column stays masked
        // through a view because the view plan is inlined at query time (rule 6).
        let (view_admin, live_views): (
            Option<Arc<dyn dataglot_pgwire::view_admin::ViewAdmin>>,
            Option<crate::view_admin::LiveViewRegistry>,
        ) = if let Some(store) = ddl_store.as_ref() {
            let registry: crate::view_admin::LiveViewRegistry =
                Arc::new(std::sync::RwLock::new(HashMap::new()));
            crate::view_admin::load_persisted_derived_products(
                store.as_ref(),
                &session_factory,
                &catalogs,
                needs_federation,
                &registry,
            )
            .await
            .context("Failed to load persisted derived products from the control-plane store")?;
            // Config `Live` derived products become queryable views through the
            // same builder (Materialized ones are exposed as warehouse tables by
            // the scheduler, not inlined views — skip them here).
            for p in &config.derived_products {
                if p.backing == MaterializationBacking::Live {
                    let record = dataglot_catalog::DerivedProductRecord {
                        name: p.name.clone(),
                        sql: p.sql.clone(),
                        catalog: p.catalog.clone(),
                        schema: p.schema.clone(),
                    };
                    crate::view_admin::register_config_derived_product_view(
                        &session_factory,
                        &catalogs,
                        needs_federation,
                        &registry,
                        &boot_org,
                        &record,
                    )
                    .await;
                }
            }
            let admin: Arc<dyn dataglot_pgwire::view_admin::ViewAdmin> = Arc::new(
                crate::view_admin::StoreViewAdmin::new(Arc::clone(store), Arc::clone(&registry)),
            );
            (Some(admin), Some(registry))
        } else {
            (None, None)
        };

        // Freeze the graph into the observability snapshot
        // while it's still in hand — it's consumed for propagation and
        // otherwise discarded. Mask annotation replays the exact
        // propagation above, so the view can't disagree with the
        // enforcer.
        let lineage_snapshot = Arc::new(crate::lineage_snapshot::build_lineage_snapshot(
            &lineage_graph,
            &lineage_products,
            &crate::config::build_mask_rules(&config.masks)?,
            &config.default_catalog,
            &config.default_schema,
        ));
        // Access-deny (Ranger parity) and the grant enforcer (F5b) both run
        // before masking — see config::compose_policy_enforcer.
        let enforcer = crate::config::compose_policy_enforcer(
            &rule_store,
            &config.access_denials,
            grant_enforcer,
        )?;

        // Build the lineage emitter from the `lineage` config block.
        // None ⇒ NoopLineageEmitter — zero-cost when no operator
        // declared a lineage backend.
        let lineage_emitter = build_lineage_emitter(config.lineage.as_ref())
            .context("Failed to build lineage emitter from config")?;

        // Parse the configured column masks once into the lineage
        // overlay set, so every connection's LineageObserver marks
        // masked source fields in emitted column lineage without
        // re-parsing per query.
        let masked_columns = Arc::new(crate::lineage::MaskedColumns::new(
            config
                .masks
                .iter()
                .map(|m| (m.table.as_str(), m.column.as_str())),
        ));

        // Build the typed bindings map. Two paths:
        //
        // 1. `config.catalog_service: None` (pre-task-08 fast
        //    path) — populate `bindings` directly from
        //    `[catalogs.*]`. No Postgres dep at boot.
        //
        // 2. `Some(...)` — connect to the catalog service,
        //    upsert every `[catalogs.*]` entry (JSON wins on
        //    conflict in Phase 1), then `list_bindings` for
        //    the canonical snapshot. The service path stays
        //    informational in Phase 1; the cache (task 09 /
        //    impl PR 4) is what actually consumes the
        //    `BindingChange` stream the service emits.
        let bindings = build_bindings(&config.catalogs, config.catalog_service.as_ref())
            .await
            .context("Failed to build catalog bindings map")?;

        // Build governance publishers from config (Phase 1 §11
        // Interface #2). Empty / omitted ⇒ no work — same shape
        // as the lineage emitter / catalog service code paths.
        let publishers = build_publishers(&config.governance_publishers)
            .context("Failed to build governance publishers from config")?;

        // Boot-time publish: walk every binding and POST one
        // MetadataChangeProposal per (binding × publisher). Per-
        // publisher failure isolation lives inside each `publish()`
        // impl — a DataHub outage at boot logs WARN and does not
        // propagate to the boot path.
        publish_all_bindings(&publishers, &bindings).await;

        // The long-lived `BindingChange` subscriber (when a catalog service
        // *and* a publisher are configured) and the materialization/
        // maintenance refresh scheduler are **not** spawned here.
        // They're deferred to `run`, spawned only after the pgwire listener
        // binds, so no background task runs before the server accepts
        // connections. `run` calls `spawn_deferred_background`
        // using `self.publishers` / `self.needs_federation` (stored below).
        //
        // The status registries are still *built* here — they're read by the
        // dashboard and handed to the scheduler when it spawns — so nothing
        // observable changes for callers other than *when* the tasks start.
        let materialization_status =
            crate::materialization_registry::MaterializationRegistry::empty();
        let maintenance_status = crate::maintenance_registry::MaintenanceRegistry::empty();

        // Phase 2 spec 02 slice 3a — boot the Ballista standalone
        // cluster if the config requests it. The feature-gate split
        // is in `crate::ballista`: with `ballista` enabled, we boot
        // once at server start and stash the handle; without it, a
        // `Some(...)` config block is a hard configuration error.
        #[cfg(feature = "ballista")]
        let ballista_cluster = if config.ballista.is_some() {
            Some(crate::ballista::boot_cluster(&config).await?)
        } else {
            None
        };
        #[cfg(not(feature = "ballista"))]
        if config.ballista.is_some() {
            return Err(crate::ballista::reject_ballista_without_feature());
        }

        // Surface insecure auth postures (trust+policies, md5-without-TLS)
        // as boot warnings before we accept connections.
        config.warn_insecure_auth();

        //  — the directory-group resolver, derived from the same built
        // `auth` value so the JWT verifier / LDAP authenticator are shared (no
        // second key read / bind). Trust / md5 / scram resolve groups from the
        // static `[identities]` config (byte-identical to the pre-
        // path); jwt / ldap resolve from the verified token / directory.
        let group_resolver: Arc<dyn crate::group_resolver::GroupResolver> = {
            use crate::group_resolver::{ConfigGroupResolver, JwtGroupResolver, LdapGroupResolver};
            match &auth {
                dataglot_pgwire::AuthMode::Jwt(verifier) => {
                    Arc::new(JwtGroupResolver::new(Arc::clone(verifier)))
                }
                dataglot_pgwire::AuthMode::Ldap(authenticator) => {
                    Arc::new(LdapGroupResolver::new(Arc::clone(authenticator)))
                }
                dataglot_pgwire::AuthMode::Trust
                | dataglot_pgwire::AuthMode::Md5(_)
                | dataglot_pgwire::AuthMode::ScramSha256(_) => Arc::new(ConfigGroupResolver::new(
                    Arc::new(config.identities.clone()),
                )),
            }
        };

        //  — column whitelist enforcer, built once at boot (a bad table
        // ref fails boot here, not per-connection). Installed as an analyzer
        // rule in `create_session`. `None` when no column grants are declared.
        let whitelist_enforcer =
            crate::config::build_column_whitelist_enforcer(&config.column_grants)?;

        Ok(Self {
            // Built above (before `config` is moved below): the config source
            // (each identity's `password_env`, resolved from the env — a
            // misconfig fails boot here, not per-connection) layered under the
            // store-backed source for runtime-created users.
            auth,
            pgwire_tls: build_ingress_tls(config.pgwire_tls.clone()).await?,
            rate_limiter: build_rate_limiter(config.rate_limit.as_ref()),
            identity_admission: build_identity_admission(&config, &metrics),
            group_resolver,
            config,
            session_factory,
            #[cfg(feature = "ballista")]
            ballista_cluster,
            catalogs,
            health_handles: Arc::new(health_handles),
            live_catalogs,
            boot_org,
            control_plane_store: ddl_store.clone(),
            catalog_admin,
            secret_admin,
            user_admin,
            policy_admin,
            grant_admin,
            view_admin,
            live_views,
            enforcer,
            whitelist_enforcer,
            rule_store: Some(rule_store),
            lineage_emitter,
            masked_columns,
            lineage_snapshot,
            bindings,
            _cache: cache_handle,
            cache_invalidation: cache_task,
            // Spawned post-bind in `run` — empty at construction.
            governance_invalidation: None,
            materialization_refresh: Vec::new(),
            publishers,
            needs_federation,
            materialization_status,
            maintenance_status,
            shutdown_tx,
            metrics,
            query_registry: QueryRegistry::new(),
            session_registry: SessionRegistry::new(),
            cancel_registry: Arc::new(dataglot_pgwire::CancelRegistry::new()),
        })
    }

    /// Borrow the live rule store the inbound governance webhook
    /// publishes rule changes to. Returns `None` for the test
    /// constructor that injects a static enforcer directly — every
    /// production boot via [`Self::new`] returns `Some(_)`.
    #[must_use]
    pub fn rule_store(&self) -> Option<&Arc<InMemoryRuleStore>> {
        self.rule_store.as_ref()
    }

    /// Test-only constructor that bypasses `build_connectors`.
    ///
    /// Lets unit tests plumb pre-built `Arc<dyn CatalogProvider>`s
    /// directly without standing up real `PostgreSQL` / warehouse
    /// containers, and inject a custom `PolicyEnforcer` so the
    /// session-level masking integration can be exercised
    /// end-to-end without a TOML config-surface. The production
    /// boot path goes through [`Self::new`] and always installs
    /// `NoopPolicyEnforcer`.
    #[cfg(test)]
    fn new_with_catalogs(
        config: ServerConfig,
        catalogs: HashMap<String, Arc<dyn DfCatalogProvider>>,
        enforcer: Arc<dyn PolicyEnforcer>,
    ) -> Result<Self> {
        let session_config = config.to_session_config();
        let session_factory = SessionContextFactory::new(session_config)
            .context("Failed to create session factory")?;
        let (shutdown_tx, _) = broadcast::channel(1);
        let metrics = Metrics::new().context("Failed to register baseline metrics")?;
        let lineage_emitter: DynLineageEmitter = Arc::new(dataglot_core::NoopLineageEmitter);
        let masked_columns = Arc::new(crate::lineage::MaskedColumns::new(
            config
                .masks
                .iter()
                .map(|m| (m.table.as_str(), m.column.as_str())),
        ));
        let bindings: HashMap<String, CatalogBinding> = config
            .catalogs
            .iter()
            .map(|(name, cfg)| (name.clone(), cfg.binding()))
            .collect();
        // Trust mode ⇒ the config-backed group resolver (byte-identical to the
        // pre- path). Built before the struct literal moves `config`.
        let group_resolver: Arc<dyn crate::group_resolver::GroupResolver> = Arc::new(
            crate::group_resolver::ConfigGroupResolver::new(Arc::new(config.identities.clone())),
        );
        Ok(Self {
            config,
            session_factory,
            // Test constructor: auth is not the unit under test here, so
            // keep trust mode (production boot goes through `Self::new`).
            auth: dataglot_pgwire::AuthMode::Trust,
            pgwire_tls: None,
            rate_limiter: None,
            identity_admission: None,
            group_resolver,
            #[cfg(feature = "ballista")]
            ballista_cluster: None,
            catalogs,
            // Test constructor bypasses `build_connectors`, so there are no
            // boot-built connectors to reuse — the monitor falls back to the
            // rebuild probe for everything (unchanged pre- behaviour).
            health_handles: Arc::new(HashMap::new()),
            live_catalogs: None,
            boot_org: "default".to_string(),
            control_plane_store: None,
            catalog_admin: None,
            secret_admin: None,
            user_admin: None,
            policy_admin: None,
            grant_admin: None,
            view_admin: None,
            live_views: None,
            enforcer,
            whitelist_enforcer: None,
            rule_store: None,
            lineage_emitter,
            masked_columns,
            lineage_snapshot: Arc::default(),
            bindings,
            _cache: None,
            cache_invalidation: None,
            governance_invalidation: None,
            materialization_refresh: Vec::new(),
            publishers: Vec::new(),
            needs_federation: false,
            materialization_status: crate::materialization_registry::MaterializationRegistry::empty(
            ),
            maintenance_status: crate::maintenance_registry::MaintenanceRegistry::empty(),
            shutdown_tx,
            metrics,
            query_registry: QueryRegistry::new(),
            session_registry: SessionRegistry::new(),
            cancel_registry: Arc::new(dataglot_pgwire::CancelRegistry::new()),
        })
    }

    /// Get the server address.
    ///
    /// # Panics
    /// Panics if the address cannot be parsed (should not happen with valid config).
    #[must_use]
    pub fn addr(&self) -> SocketAddr {
        format!("{}:{}", self.config.host, self.config.port)
            .parse()
            .expect("Invalid address")
    }

    /// Build the "base" `SessionContext` for a per-connection
    /// session — federation rules + planner installed, no policy or
    /// catalog wiring yet. Dispatches between two paths:
    ///
    /// - **Single-node** (`ballista_cluster: None` or feature off):
    ///   `SessionContextFactory::create_federated_context()`, same
    ///   shape since Phase 0.
    /// - **Ballista standalone** (`ballista_cluster: Some(...)` with
    ///   feature on): `BallistaCluster::create_session()`, which
    ///   clones the cluster's reference state so the new context's
    ///   `BallistaQueryPlanner` points at the same in-process
    ///   scheduler. Boot of the cluster happened once at
    ///   `Self::new` time; this method is sync and per-session.
    ///
    /// The split is intentionally tucked under a single helper so
    /// `create_session`'s outer body — policy wiring + catalog
    /// registration — stays identical between modes.
    fn base_session_context(&self) -> SessionContext {
        #[cfg(feature = "ballista")]
        if let Some(cluster) = self.ballista_cluster.as_ref() {
            let ctx = cluster.create_session();
            //  — distributed parity. The single-node SessionContextFactory
            // registers the pg_catalog introspection UDFs (pg_get_userbyid,
            // format_type, pg_get_expr, current_schema, session_user, …) via
            // setup_pg_catalog, but the Ballista base context never did — so
            // psql `\d` and BI-tool introspection silently broke under
            // `--distributed`. We register only the UDFs (not full
            // setup_pg_catalog): the Ballista context already carries the
            // pg_catalog table overlay — setup_pg_catalog would fail claiming
            // the schema is overlay-owned — and the UDFs are session scalars
            // with no distributed-codec or schema-ownership concern.
            // `current_database` + the visibility shims are added per-session
            // by the StartupObserver hook below.
            dataglot_core::session::register_pg_catalog_udfs(&ctx);
            return ctx;
        }
        //: `create_federated_context` strips DataFusion's physical
        // `FilterPushdown` rule to dodge a `datafusion-federation 0.5.3`
        // correctness bug — but that strip also kills scan-time parquet
        // pushdown (row filter + page/row-group pruning) on the local
        // Iceberg / object-storage read paths. The bug only manifests when a
        // `VirtualExecutionPlan` is in the plan, which only a federated SQL
        // source (Postgres/MySQL/Snowflake) can produce. So when no such
        // source is configured, use the plain context: pushdown fires and
        // there is provably no federation node for the strip to protect.
        // Mixed servers (at least one SQL source) keep the safe federated
        // context — local-catalog pushdown there is the remaining  gap.
        if self.needs_federation() {
            self.session_factory.create_federated_context()
        } else {
            self.session_factory.create_context()
        }
    }

    /// Whether any configured catalog is a federated SQL source
    /// (Postgres/MySQL/Snowflake) — see [`CatalogConfig::requires_federation`].
    /// Drives the [`Self::base_session_context`] strategy: `false` keeps the
    /// full physical optimizer (parquet pushdown intact), `true` installs the
    /// federation context that strips `FilterPushdown` for correctness.
    fn needs_federation(&self) -> bool {
        // A federated SQL source in the file/env config needs the federation
        // context. When `catalog_service` is configured we additionally can't
        // enumerate the DB-sourced catalogs here — they're resolved at boot in
        // `build_catalogs_and_cache`, after this factory was built — and any of
        // them may be a federated SQL source (task 12 slice 1). Without the
        // federation context their `FederatedTableProviderAdaptor` never gets
        // rewritten and every scan fails with "cannot scan". So install it
        // conservatively whenever the control plane is on. The cost is the
        //  `FilterPushdown` strip (scan-time parquet pushdown) for a
        // control-plane deploy that turns out to be warehouse/object-storage
        // only — correctness over that pushdown; a precise per-effective-catalog
        // decision is a later optimisation.
        self.config
            .catalogs
            .values()
            .any(CatalogConfig::requires_federation)
            || self.config.catalog_service.is_some()
    }

    /// Create a new session context for a client connection.
    ///
    /// Builds a federation-aware `SessionContext` (rules + planner
    /// from `datafusion-federation`), prepends the configured
    /// `PolicyOptimizerRule` so plan-time governance runs *before*
    /// any rule that could rewrite the shape the policy walker
    /// matches on (notably projection pushdown — appending via
    /// `add_optimizer_rule` is not enough; pushdown collapses
    /// `Projection -> TableScan` into a `TableScan` with a baked
    /// projection list before an appended rule sees the plan, and
    /// the column-mask rewrite then silently no-ops). Finally
    /// registers every catalog the server was booted with;
    /// catalogs are shared by `Arc`-clone across sessions and
    /// per-table schema fetching is still lazy (rule 13).
    ///
    /// When `config.ballista = Some(...)` and the `ballista`
    /// feature is compiled in, the base context is minted from the
    /// running Ballista cluster instead of the single-node
    /// `SessionContextFactory`; the rest of the wiring is identical
    /// so plan-time governance + catalog registrations apply the
    /// same way.
    ///
    /// # Panics
    /// Panics if the base [`SessionContext`] does not have a
    /// `pg_catalog` schema under the configured `default_catalog`.
    /// `SessionContextFactory` always registers it; a panic here
    /// would indicate a regression in `dataglot-core`'s
    /// session-construction path, not a runtime condition.
    #[must_use]
    pub fn create_session(&self) -> SessionContext {
        let base = self.base_session_context();
        let policy_rule: Arc<dyn OptimizerRule + Send + Sync> =
            Arc::new(PolicyOptimizerRule::new(Arc::clone(&self.enforcer)));

        let state = base.state();
        let mut rules: Vec<Arc<dyn OptimizerRule + Send + Sync>> = state.optimizers().to_vec();
        rules.insert(0, policy_rule);

        let mut builder =
            SessionStateBuilder::new_from_existing(state.clone()).with_optimizer_rules(rules);

        //  — the column whitelist runs at the ANALYZER stage: it drops
        // hidden columns, changing the plan's output schema, which an
        // `OptimizerRule` may not do (the optimizer verifies schema stability).
        // Prepend it so it reshapes the plan before type coercion / optimization.
        if let Some(whitelist) = &self.whitelist_enforcer {
            let rule: Arc<dyn AnalyzerRule + Send + Sync> = Arc::new(PolicyAnalyzerRule::new(
                Arc::clone(whitelist) as Arc<dyn PolicyEnforcer>,
            ));
            let mut analyzer_rules = state.analyzer().rules.clone();
            analyzer_rules.insert(0, rule);
            builder = builder.with_analyzer_rules(analyzer_rules);

            // The analyzer rule enforces execution, but datafusion-postgres
            // derives a prepared statement's RowDescription from the *parsed*
            // (un-analyzed) plan — so a schema-changing whitelist would make
            // the extended-protocol describe (6 cols) disagree with execution
            // (visible subset). Register a plan-rewrite the pg wire hook runs at
            // extended-parse time so both see the governed schema. The closure
            // reads the session identity from the policy task-local per query.
            let wl = Arc::clone(whitelist);
            let rewriter: dataglot_core::PlanRewriteFn = Arc::new(move |plan| {
                let id = dataglot_policy::current_session_identity()
                    .unwrap_or_else(dataglot_policy::Identity::anonymous);
                Ok(wl.rewrite(plan, &id)?.data)
            });
            let mut config = state.config().clone();
            config.set_extension(Arc::new(dataglot_core::SessionPlanRewriter(rewriter)));
            builder = builder.with_config(config);
        }
        let state = builder.build();
        let ctx = SessionContext::new_with_state(state);

        //  +  — wrap every federated catalog with a
        // `pg_catalog` schema overlay so psql / JDBC introspection
        // (`\d`, `\dt`, `\l`, `pg_table_is_visible`, ...) succeeds
        // regardless of which `--database` the client connected with.
        //
        // Without the overlay, `register_catalog(name, federated)`
        // REPLACES the slot the factory's `setup_pg_catalog` filled
        // (the empty default `MemoryCatalogProvider`), so any
        // connection whose `database` matches a federated catalog
        // name resolves `pg_catalog.x` against a federated provider
        // that has no `pg_catalog` schema — planning fails.
        //
        // ** (Layer B)** — Each federated catalog now gets its
        // OWN `pg_catalog` `SchemaProvider`, scoped to enumerate
        // only that catalog's tables (Model A: catalog-as-database).
        // `build_scoped_pg_catalog_schema` hands the upstream
        // `PgCatalogSchemaProvider::try_new` a single-catalog
        // `CatalogProviderList`, so `pg_class` / `pg_namespace` rows
        // are naturally restricted to the wrapping catalog — no
        // reimplementation of the upstream tables needed.
        //
        // Schema enumeration stays lazy (rule 13). Identity / role
        // scope is `EmptyContextProvider` for now —  covers
        // the `current_database()` UDF; identity-aware pg_roles is
        // a separate follow-up.
        //
        // `flat_catalog_list` backs the flat half (`pg_database` — what
        // `\l` reads). It must enumerate EXACTLY the configured federated
        // catalogs, so we build it from `self.catalogs` rather than from
        // the session's live `catalog_list()`. The live list still holds
        // the placeholder default catalog that
        // `with_default_catalog_and_schema` created at session boot; that
        // name is one of ours only if a config's `default_catalog` happens
        // to match a federated catalog (the demo sets `default_catalog:
        // "pg"`, which does — masking this in manual testing). When it
        // does NOT match, the placeholder would leak into `pg_database`
        // and `\l` would advertise a phantom database. Building from
        // `self.catalogs` lists only real catalogs and is independent of
        // registration order. Catalogs are static post-boot (see
        // `catalogs()` below). The session captures a *snapshot* of the
        // current catalog set (static map, or the live control-plane
        // registry — slice B), so a session is internally consistent; a
        // later store change swaps the registry for the *next* session.
        //  — surface the configured identities/roles as `pg_roles`
        // rows so `\du` and BI-tool role introspection aren't empty. Built
        // once (same for every catalog); privileges stay permissive until a
        // grant model exists.
        // The session is built with the boot org's catalog set (the connection's
        // org isn't known until the pgwire startup handshake); the
        // `StartupObserver` re-registers per the resolved org when it differs
        let catalogs = self.current_catalogs();
        let pg_roles = self.pg_role_specs();
        register_overlay_catalogs(&ctx, &catalogs, &pg_roles);
        //  — guarantee a writable engine-local catalog so runtime views
        // (registered just below, and via `CREATE VIEW`) have a home even when
        // `default_catalog` points at a read-only federated source. Per-session
        // (the ctx is fresh here), so views stay isolated to their org's set.
        dataglot_core::ensure_runtime_catalog(&ctx);
        //  F9 — register the boot org's derived-product views as
        // queryable tables (config `Live` products + persisted `CREATE VIEW`s).
        // The connection's real org isn't known until startup; the
        // `StartupObserver` re-registers per the resolved org when it differs.
        self.register_org_views(&ctx, &self.boot_org);
        ctx
    }

    /// Register an org's derived-product views as queryable tables
    /// in `ctx`, from the live view registry. No-op on the no-control-plane fast
    /// path (`live_views` is `None`) or for an org with no views. Best-effort per
    /// view — one whose (optionally qualified) target schema isn't present in the
    /// session is logged and skipped, never breaking session creation.
    fn register_org_views(&self, ctx: &SessionContext, org: &str) {
        let Some(registry) = &self.live_views else {
            return;
        };
        let guard = registry
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(views) = guard.get(org) {
            for view in views.values() {
                // On the distributed path the base SessionContext shares its
                // catalog list across sessions (Ballista `reference_ctx`), so a
                // view registered by an earlier connection is already present —
                // re-registering it would error "table already exists". It's the
                // same view; skip it. Only a genuinely new view needs
                // registering here.
                if ctx.table_exist(view.reference.clone()).unwrap_or(false) {
                    continue;
                }
                if let Err(e) =
                    ctx.register_table(view.reference.clone(), Arc::clone(&view.provider))
                {
                    tracing::warn!(
                        view = %view.reference, org = %org, error = %e,
                        "view: register into session failed; skipping"
                    );
                }
            }
        }
    }

    /// The catalog set a fresh session is built with: the **boot org**'s
    /// snapshot. The connection's real org isn't known until the pgwire startup
    /// handshake, so `create_session` uses this and the `StartupObserver`
    /// re-registers per the resolved org when it differs.
    fn current_catalogs(&self) -> Arc<CatalogSnapshot> {
        self.current_catalogs_for_org(&self.boot_org)
    }

    /// The live control-plane snapshot for `org` (slice B; per-org since M2 —
    /// so a new connection reflects out-of-band store changes for its own
    /// tenant), else the static boot map on the no-control-plane fast path.
    /// An org with no registry entry yet has no catalogs (empty snapshot).
    /// Returned as an `Arc` so the caller iterates without cloning the
    /// providers.
    fn current_catalogs_for_org(&self, org: &str) -> Arc<CatalogSnapshot> {
        match &self.live_catalogs {
            // Recover from a poisoned lock instead of panicking: a writer
            // panic in the refresh task must not break session creation.
            Some(reg) => {
                let guard = reg
                    .read()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                guard
                    .get(org)
                    .map_or_else(|| Arc::new(CatalogSnapshot::new()), Arc::clone)
            }
            // Fast path: a single implicit org, the static boot catalogs.
            None => Arc::new(self.catalogs.clone()),
        }
    }

    /// Build the `pg_roles` rows from the server's identity/role config
    ///: one login-capable role per configured **identity** (a user),
    /// one non-login (group) role per configured **role**. Sorted by name and
    /// de-duplicated so a role sharing an identity's name appears once. Empty
    /// config ⇒ empty `pg_roles` (the pre- behaviour). Attributes only
    /// — there is no grant/ACL model yet.
    fn pg_role_specs(&self) -> Vec<PgRoleSpec> {
        let mut by_name: std::collections::BTreeMap<String, PgRoleSpec> =
            std::collections::BTreeMap::new();
        for user in self.config.identities.keys() {
            by_name.insert(
                user.clone(),
                PgRoleSpec {
                    name: user.clone(),
                    is_superuser: false,
                    can_login: true,
                },
            );
        }
        for role in self.config.roles.keys() {
            // A configured identity of the same name wins (it can log in).
            by_name.entry(role.clone()).or_insert_with(|| PgRoleSpec {
                name: role.clone(),
                is_superuser: false,
                can_login: false,
            });
        }
        by_name.into_values().collect()
    }

    /// Get a shutdown receiver.
    #[must_use]
    pub fn shutdown_receiver(&self) -> broadcast::Receiver<()> {
        self.shutdown_tx.subscribe()
    }

    /// Borrow the metrics handle. Exposed for tests and for any future
    /// in-process integrations.
    #[must_use]
    #[allow(dead_code)] // public surface for tests and follow-up wiring.
    pub fn metrics(&self) -> &Metrics {
        &self.metrics
    }

    /// Borrow the typed catalog bindings (Architecture Decisions
    /// v3.0 §09). One entry per configured catalog, keyed by the
    /// same name that appears in three-part references
    /// (`<catalog>.<schema>.<table>`).
    ///
    /// Read-only — Phase 1 doesn't dynamically add or remove
    /// catalogs after boot. The Peaka Catalog Service (task 08)
    /// is the first consumer; nothing else uses this yet.
    #[must_use]
    pub fn bindings(&self) -> &HashMap<String, CatalogBinding> {
        &self.bindings
    }

    /// Number of configured catalogs registered on each session.
    /// Test-only accessor; not part of the public surface.
    #[cfg(test)]
    fn registered_catalog_count(&self) -> usize {
        self.catalogs.len()
    }

    /// Spawn the background connector-health poller when it's enabled and there
    /// are sources to probe ( continuous mode). `None` when
    /// `connector_health_interval_secs == 0` (opt-out — sources carry zero
    /// monitoring load) or nothing is configured. The returned poller shares
    /// the shutdown channel and the health cache in `connectors`.
    fn maybe_spawn_connector_health_poller(
        &self,
        connectors: &crate::connectors::ConnectorMonitor,
    ) -> Option<tokio::task::JoinHandle<()>> {
        let secs = self.config.observability.connector_health_interval_secs;
        if secs == 0 || self.config.catalogs.is_empty() {
            return None;
        }
        Some(crate::observability::spawn_connector_health_poller(
            connectors.clone(),
            self.metrics.clone(),
            std::time::Duration::from_secs(secs),
            self.shutdown_tx.subscribe(),
        ))
    }

    /// Spawn the policy-explain endpoint if configured. A session context
    /// with catalogs registered is minted so the endpoint can plan
    /// federated SQL (`create_logical_plan` analyzes but does not run the
    /// policy optimizer rule, so `explain` sees the un-enforced plan).
    async fn maybe_spawn_policy_explain(
        &self,
    ) -> Result<Option<crate::policy_explain::PolicyExplainServerHandle>> {
        let Some(cfg) = self.config.policy_explain.as_ref() else {
            return Ok(None);
        };
        let handle = crate::policy_explain::spawn_policy_explain_server(
            cfg,
            Arc::new(self.create_session()),
            Arc::clone(&self.enforcer),
            Arc::new(self.config.identities.clone()),
            Arc::new(self.config.roles.clone()),
            self.shutdown_tx.subscribe(),
        )
        .await
        .context("Failed to start policy-explain server")?;
        Ok(Some(handle))
    }

    /// Static server metadata for the dashboard header (versions + ports +
    /// execution mode) — backs `GET /api/server`. No credentials (rule 12).
    fn server_info(&self) -> crate::observability::ServerInfo {
        crate::observability::ServerInfo {
            dataglot_version: env!("CARGO_PKG_VERSION"),
            datafusion_version: dataglot_core::datafusion_version(),
            pgwire_host: self.config.host.clone(),
            pgwire_port: self.config.port,
            dashboard_port: self.config.observability.metrics_addr.map(|a| a.port()),
            execution_mode: execution_mode_label(self.config.ballista.as_ref()),
            ballista: self
                .config
                .ballista
                .as_ref()
                .map(|b| crate::observability::BallistaInfo {
                    scheduler_grpc_port: b.scheduler_grpc_port,
                    rest_api_port: b.rest_api_port,
                    external_executors: b.external_executors,
                }),
            security: crate::observability::SecurityPosture {
                auth_mode: match self.config.auth.mode {
                    crate::config::AuthMode::Trust => "trust",
                    crate::config::AuthMode::Md5 => "md5",
                    crate::config::AuthMode::ScramSha256 => "scram-sha-256",
                    crate::config::AuthMode::Jwt => "jwt",
                    crate::config::AuthMode::Ldap => "ldap",
                }
                .to_string(),
                ingress_tls: self
                    .config
                    .pgwire_tls
                    .as_ref()
                    .map_or("off", |t| match t.mode {
                        crate::config::PgwireTlsMode::Prefer => "prefer",
                        crate::config::PgwireTlsMode::Require => "require",
                    })
                    .to_string(),
                rate_limiting: self.config.rate_limit.is_some(),
            },
            governance: crate::observability::GovernancePosture {
                authz_mode: match self.config.authz.mode {
                    crate::config::AuthzMode::Open => "open",
                    crate::config::AuthzMode::Grant => "grant",
                }
                .to_string(),
                masks: self.config.masks.len(),
                row_filters: self.config.row_filters.len(),
                access_denials: self.config.access_denials.len(),
                column_grants: self.config.column_grants.len(),
            },
            build: crate::observability::BuildInfo::current(),
            limits: crate::observability::ResourceLimits::from_config(&self.config),
        }
    }

    /// Bind the pgwire listener and spawn the sibling servers (metrics,
    /// webhook, policy-explain). Split out of [`Self::run`] so a startup
    /// failure here can be handled in one place — `run` aborts the background
    /// tasks before propagating the error.
    // Binds the pgwire listener and spawns every sibling server inline; the
    // sequence is inherently long but reads as one linear startup script.
    #[allow(clippy::too_many_lines)]
    async fn start_foreground(&self) -> Result<ForegroundListeners> {
        let addr = self.addr();
        let listener = TcpListener::bind(&addr).await.map_err(|e| {
            // Turn the two first-run bind failures into actionable advice
            // rather than a raw OS error.
            match e.kind() {
                std::io::ErrorKind::AddrInUse => anyhow::anyhow!(
                    "port {} is already in use (another process — perhaps another Dataglot \
                     or a real PostgreSQL — is bound to {addr}). Stop it, or start Dataglot on \
                     another port with `--port <N>` (or DATAGLOT_PORT).",
                    addr.port()
                ),
                std::io::ErrorKind::PermissionDenied => anyhow::anyhow!(
                    "permission denied binding {addr}. Ports below 1024 are privileged; \
                     pick a high port with `--port <N>` (e.g. 5432) or run with the needed \
                     privileges."
                ),
                _ => anyhow::Error::new(e)
                    .context(format!("failed to bind pgwire listener to {addr}")),
            }
        })?;

        tracing::info!(%addr, "Listening for connections");

        // Track the sibling servers' abort handles as they spawn, so a
        // *mid*-startup failure (e.g. the webhook binds but policy-explain
        // fails) aborts the already-spawned ones instead of leaking them —
        // the same explicit-lifecycle discipline the background tasks get.
        let mut spawned: Vec<tokio::task::AbortHandle> = Vec::new();
        let build = async {
            // Spawn the metrics HTTP server as a sibling task. It shares the
            // server's broadcast shutdown channel so a single Ctrl-C drains
            // everything cleanly.
            let metrics_handle = if let Some(metrics_addr) = self.config.observability.metrics_addr
            {
                // Cluster proxy dials the Ballista scheduler's loopback
                // REST API. Disabled (available:false)
                // when ballista/rest_api_port isn't configured.
                let cluster_monitor = crate::cluster::ClusterMonitor::from_rest_api_port(
                    self.config.ballista.as_ref().and_then(|b| b.rest_api_port),
                );
                let server_info = self.server_info();
                //  — configured connectors + which registered at boot,
                // for the dashboard Connectors tab + on-demand liveness probe.
                let connectors = crate::connectors::ConnectorMonitor::new(
                    Arc::new(self.config.catalogs.clone()),
                    Arc::new(self.catalogs.keys().cloned().collect()),
                    //: reuse the boot-built connectors for cheap liveness
                    // probes instead of rebuilding on every poll tick.
                    Arc::clone(&self.health_handles),
                );
                //  continuous mode — a background poller refreshes each
                // source's liveness, feeding both the dashboard Connectors tab
                // (via the shared health cache in `connectors`) and the
                // `dataglot_connector_up` gauge.
                if let Some(poller) = self.maybe_spawn_connector_health_poller(&connectors) {
                    spawned.push(poller.abort_handle());
                }
                let h = spawn_metrics_server(
                    metrics_addr,
                    self.metrics.clone(),
                    self.config.observability.health_check_enabled,
                    &self.lineage_snapshot,
                    self.query_registry.clone(),
                    self.session_registry.clone(),
                    cluster_monitor,
                    connectors,
                    self.materialization_status.clone(),
                    self.maintenance_status.clone(),
                    server_info,
                    self.control_plane_store
                        .as_ref()
                        .map(|s| (Arc::clone(s), self.boot_org.clone())),
                    self.shutdown_tx.subscribe(),
                )
                .await
                .context("Failed to start metrics HTTP server")?;
                spawned.push(h.abort_handle());
                Some(h)
            } else {
                tracing::info!("Metrics HTTP server disabled by configuration");
                None
            };

            // Spawn the inbound governance webhook on its own port, mirroring
            // the metrics-server pattern above. Same broadcast shutdown channel
            // so a single Ctrl-C tears down both. Spec 04 slice 1 commits to a
            // sibling axum server (not a route on /metrics) — different auth
            // posture (HMAC vs unauthenticated), different exposure
            // (governance-platform network vs internal scrape).
            let webhook_handle = if let Some(webhook_cfg) = self.config.webhook.as_ref() {
                // Spec 04 slice 3 commits to: webhook ⇒ rule store. Production
                // boot always populates `rule_store` (the `None` branch is
                // test-only), so a webhook config without a store is a
                // bootstrap bug — refuse to start rather than echo events
                // into the void.
                let rule_store = self.rule_store.clone().ok_or_else(|| {
                    anyhow::anyhow!(
                        "Inbound governance webhook is configured but no rule store \
                         is bound; this is a server-bootstrap bug — the production \
                         path through DataglotServer::new always builds the store."
                    )
                })?;
                let h = spawn_webhook_server(
                    webhook_cfg,
                    self.metrics.governance_webhook_events_total.clone(),
                    rule_store,
                    self.shutdown_tx.subscribe(),
                )
                .await
                .context("Failed to start inbound governance webhook server")?;
                spawned.push(h.join.abort_handle());
                Some(h)
            } else {
                tracing::info!("Inbound governance webhook disabled by configuration");
                None
            };

            // Optional policy-explainability endpoint (POST /policy/explain).
            let policy_explain_handle = self.maybe_spawn_policy_explain().await?;

            Ok::<_, anyhow::Error>((metrics_handle, webhook_handle, policy_explain_handle))
        };

        match build.await {
            Ok((metrics_handle, webhook_handle, policy_explain_handle)) => {
                Ok(ForegroundListeners {
                    listener,
                    metrics_handle,
                    webhook_handle,
                    policy_explain_handle,
                })
            }
            Err(e) => {
                // Abort whatever sibling servers already started before the
                // failing step, so a partial startup leaks nothing.
                for abort in spawned {
                    abort.abort();
                }
                Err(e)
            }
        }
    }

    /// Authenticate a Flight SQL request from its `authorization` metadata and
    /// resolve the identity its query runs under — the SAME identity→policy seam
    /// pg-wire uses (`resolve_identity_with_roles`; the caller wraps execution in
    /// `dataglot_policy::with_session_identity`).
    ///
    /// - **Trust** mode: honour an asserted Basic username (no password check),
    ///   matching pg-wire trust; a missing header ⇒ anonymous (behaviour-neutral).
    /// - **Md5** mode: verify the Basic password (constant-time) against the same
    ///   [`PasswordSource`](dataglot_pgwire::PasswordSource) the pg-wire md5 path
    ///   uses; a missing/invalid credential is refused, so Flight can't bypass the
    ///   pg-wire md5 gate. An unknown user still runs a compare (no cheap probe).
    /// - `Bearer`/other schemes: not supported yet (slice-3 follow-up).
    ///
    /// Rule 12: the password is compared, never logged.
    #[cfg(feature = "flight_sql")]
    pub(crate) async fn authenticate_flight(&self, authorization: Option<&str>) -> FlightAuth {
        use dataglot_pgwire::AuthMode;
        match &self.auth {
            AuthMode::Trust => match authorization.and_then(parse_basic_auth) {
                Some((user, _pw)) => FlightAuth::Ok(self.resolve_flight_identity(&user)),
                None => FlightAuth::Ok(dataglot_policy::Identity::anonymous()),
            },
            // md5 and scram-sha-256 both verify a Basic password against the
            // same cleartext-returning `PasswordSource`; the SCRAM wire
            // exchange is pgwire-ingress-specific, so Flight uses the identical
            // constant-time compare for either mode.
            AuthMode::Md5(source) | AuthMode::ScramSha256(source) => {
                let Some(header) = authorization else {
                    return FlightAuth::Unauthenticated(
                        "Flight SQL requires Basic authentication (server is in password auth mode)",
                    );
                };
                let Some((user, password)) = parse_basic_auth(header) else {
                    return FlightAuth::BadHeader(
                        "expected `Authorization: Basic <base64(username:password)>`",
                    );
                };
                let ok = if let Some(expected) = source.password(&user).await {
                    ct_eq(password.as_bytes(), expected.as_bytes())
                } else {
                    // Unknown user: still burn a compare so response timing doesn't
                    // distinguish "no such user" from "wrong password" — the same
                    // posture as the pg-wire `AuthSource`.
                    let _ = ct_eq(password.as_bytes(), password.as_bytes());
                    false
                };
                if ok {
                    FlightAuth::Ok(self.resolve_flight_identity(&user))
                } else {
                    FlightAuth::Unauthenticated("invalid username or password")
                }
            }
            //: JWT / LDAP directory auth is a pgwire-ingress feature.
            // Flight SQL bearer/LDAP auth is a documented follow-up; until then
            // a password-auth Flight request under these modes is refused
            // (fail-closed) rather than silently trusted.
            AuthMode::Jwt(_) | AuthMode::Ldap(_) => FlightAuth::Unauthenticated(
                "Flight SQL does not yet support jwt/ldap auth modes (pgwire ingress only)",
            ),
        }
    }

    /// Resolve a verified/trusted username to its policy [`Identity`](dataglot_policy::Identity),
    /// applying role membership — identical to the pg-wire `StartupObserver` path.
    #[cfg(feature = "flight_sql")]
    fn resolve_flight_identity(&self, user: &str) -> dataglot_policy::Identity {
        resolve_identity_with_roles(user, &self.config.identities, &self.config.roles)
    }

    /// TLS config for the Flight SQL listener, if `[flight_sql].tls` is set.
    #[cfg(feature = "flight_sql")]
    pub(crate) fn flight_sql_tls(&self) -> Option<&crate::config::FlightSqlTlsConfig> {
        self.config.flight_sql.as_ref().and_then(|c| c.tls.as_ref())
    }

    /// Bind the Arrow Flight SQL listener if `[flight_sql]` is configured.
    ///
    /// Returns `Ok(None)` when the feature-gated surface is not configured
    /// (the default). Bound up front in [`Self::run`] — before any task
    /// spawns — so an addr-in-use error fails fast and cleanly, mirroring
    /// the pgwire bind's actionable errors.
    ///
    /// # Errors
    /// Returns an error if the configured address cannot be parsed or bound.
    #[cfg(feature = "flight_sql")]
    async fn bind_flight_sql(&self) -> Result<Option<TcpListener>> {
        let Some(cfg) = self.config.flight_sql.as_ref() else {
            return Ok(None);
        };
        let addr: SocketAddr = cfg
            .addr
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid [flight_sql] addr {:?}: {e}", cfg.addr))?;
        let listener = TcpListener::bind(&addr).await.map_err(|e| match e.kind() {
            std::io::ErrorKind::AddrInUse => anyhow::anyhow!(
                "Flight SQL port {} is already in use (another process is bound to {addr}). \
                 Stop it, or set a different [flight_sql] addr.",
                addr.port()
            ),
            std::io::ErrorKind::PermissionDenied => anyhow::anyhow!(
                "permission denied binding Flight SQL to {addr}. Pick a high port in \
                 [flight_sql] addr, or run with the needed privileges."
            ),
            _ => anyhow::Error::new(e)
                .context(format!("failed to bind Flight SQL listener to {addr}")),
        })?;
        tracing::info!(%addr, "Listening for Arrow Flight SQL connections");
        Ok(Some(listener))
    }

    /// Spawn the long-lived background tasks that `new` builds inputs for but
    /// defers to post-bind: the governance `BindingChange`
    /// subscriber (when a catalog service *and* a publisher are configured)
    /// and the materialization/maintenance refresh scheduler.
    /// Returns their handles so `run` can drain them on shutdown. Neither
    /// configured ⇒ an empty `Vec`, identical to the pre- boot.
    ///
    /// The cache-invalidation subscriber stays built-and-spawned in `new`
    /// (inside `build_catalogs_and_cache`, which is a single cohesive
    /// build step); its pre-bind window is a passive LISTEN connection.
    ///
    /// # Errors
    /// Propagates a failure to subscribe the governance stream or to start
    /// the refresh scheduler (e.g. an unreachable meta store / warehouse).
    async fn spawn_deferred_background(&self) -> Result<Vec<tokio::task::JoinHandle<()>>> {
        let mut handles = Vec::new();
        handles.extend(
            spawn_governance_invalidation(
                self.config.catalog_service.as_ref(),
                &self.bindings,
                &self.publishers,
            )
            .await
            .context("Failed to spawn governance BindingChange subscriber")?,
        );
        handles.extend(
            spawn_scheduled_maintenance(
                &self.config,
                &self.session_factory,
                self.needs_federation,
                &self.catalogs,
                &self.enforcer,
                &self.shutdown_tx,
                &self.materialization_status,
                &self.maintenance_status,
            )
            .await
            .context("Failed to start scheduled-maintenance scheduler")?,
        );
        Ok(handles)
    }

    /// Run the server until shutdown.
    ///
    /// # Errors
    /// Returns an error if the server cannot bind to the address or if a
    /// sibling listener (metrics / webhook / policy-explain) fails to start.
    // Top-level boot orchestration: bind foreground listeners, spawn the
    // deferred background tasks post-bind, serve, then drain on
    // shutdown. The steps are sequential and share locals (the shutdown
    // broadcast, the background-task set), so keeping them in one function
    // reads better than threading that state through helpers — same
    // rationale as `build_catalogs_and_cache`.
    #[allow(clippy::too_many_lines)]
    pub async fn run(mut self) -> Result<()> {
        // Built without the `flight_sql` feature but the operator configured a
        // [flight_sql] block: fail fast rather than silently ignoring it (same
        // posture as the connector features — a config that can't be honored is
        // an error, not a no-op).
        #[cfg(not(feature = "flight_sql"))]
        if self.config.flight_sql.is_some() {
            anyhow::bail!(
                "[flight_sql] is configured, but this binary was built without the \
                 `flight_sql` feature. Rebuild with `--features flight_sql`, or remove \
                 the [flight_sql] config block."
            );
        }

        // Take the long-lived background tasks (cache invalidation, governance
        // subscriber, refresh scheduler) out of `self` so they live outside
        // the connection-serving `Arc` — this lets us abort them if foreground
        // startup fails, and drain them explicitly on shutdown.
        let mut background = BackgroundTasks::take_from(&mut self);

        // Bind the Flight SQL listener up front (fail-fast, before any task
        // spawns) so an addr-in-use error aborts cleanly. Served after the
        // connection-serving `Arc` exists, below.
        #[cfg(feature = "flight_sql")]
        let flight_sql_listener = match self.bind_flight_sql().await {
            Ok(listener) => listener,
            Err(e) => {
                background.abort_all();
                return Err(e);
            }
        };

        let ForegroundListeners {
            listener,
            metrics_handle,
            webhook_handle,
            policy_explain_handle,
        } = match self.start_foreground().await {
            Ok(fg) => fg,
            Err(e) => {
                // A boot that fails after `new` spawned the background tasks
                // must not leave them running.
                background.abort_all();
                return Err(e);
            }
        };

        //  — the pgwire listener is now bound, so spawn the deferred
        // long-lived tasks (governance `BindingChange` subscriber +
        // materialization/maintenance refresh scheduler) that `new` used to
        // spawn pre-bind. On failure, abort the boot-time tasks and
        // propagate; the foreground siblings exit when `self`'s shutdown
        // broadcast Sender drops on return.
        match self.spawn_deferred_background().await {
            Ok(handles) => background.extend(handles),
            Err(e) => {
                background.abort_all();
                return Err(e);
            }
        }

        let server = Arc::new(self);

        // Serve Flight SQL on the pre-bound listener (drains on the shared
        // shutdown broadcast, like the metrics/webhook siblings). `serve`
        // fails fast if `[flight_sql].tls` names an unreadable cert/key.
        #[cfg(feature = "flight_sql")]
        let flight_sql_handle = flight_sql_listener
            .map(|listener| crate::flight_sql::serve(Arc::clone(&server), listener))
            .transpose()?;

        let mut shutdown_rx = server.shutdown_receiver();

        // Termination signals. SIGTERM is what an init system / Kubernetes sends
        // on stop, rolling update, or pod eviction; SIGINT is Ctrl-C. Both drive
        // the same graceful shutdown. Streams are created once (not per accept
        // iteration) and `Signal::recv` is cancel-safe, so a signal delivered
        // while we're servicing an `accept()` is latched and handled next loop.
        #[cfg(unix)]
        let (mut sigint, mut sigterm) = {
            use tokio::signal::unix::{signal, SignalKind};
            (
                signal(SignalKind::interrupt()).context("install SIGINT handler")?,
                signal(SignalKind::terminate()).context("install SIGTERM handler")?,
            )
        };

        loop {
            tokio::select! {
                accept_result = listener.accept() => {
                    match accept_result {
                        Ok((stream, peer_addr)) => {
                            tracing::debug!(%peer_addr, "Accepted connection");

                            let server = Arc::clone(&server);
                            tokio::spawn(async move {
                                // Box::pin — the connection future is large; keep it off
                                // the task stack (clippy::large_futures).
                                if let Err(e) =
                                    Box::pin(server.handle_connection(stream, peer_addr)).await
                                {
                                    tracing::error!(%peer_addr, error = %e, "Connection error");
                                }
                            });
                        }
                        Err(e) => {
                            tracing::error!(error = %e, "Accept error");
                        }
                    }
                }
                _ = shutdown_rx.recv() => {
                    tracing::info!("Shutdown signal received");
                    break;
                }
                signal = wait_for_termination_signal(
                    #[cfg(unix)] &mut sigint,
                    #[cfg(unix)] &mut sigterm,
                ) => {
                    tracing::info!(%signal, "termination signal received, shutting down gracefully");
                    // Fan the signal out to sibling tasks (metrics server).
                    if let Err(e) = server.shutdown_tx.send(()) {
                        tracing::debug!(error = %e, "shutdown broadcast had no active subscribers");
                    }
                    break;
                }
            }
        }

        // Broadcast shutdown to every subscriber (idempotent if a Ctrl-C or an
        // external `shutdown_tx.send` already fired), then drain the background
        // tasks so they finish their current iteration instead of being
        // detached mid-work.
        if let Err(e) = server.shutdown_tx.send(()) {
            tracing::debug!(error = %e, "shutdown broadcast had no active subscribers");
        }
        background.drain().await;

        // Best-effort: give sibling tasks a chance to drain. If one hangs we
        // drop it on process exit.
        Self::drain_sibling(metrics_handle, "metrics").await;
        if let Some(handle) = webhook_handle {
            // Same best-effort drain for the inbound governance webhook
            // task. The shared broadcast::Receiver already fired above,
            // so axum's graceful_shutdown future has resolved; this await
            // just collects the join handle.
            if let Err(e) = handle.join.await {
                tracing::warn!(
                    error = %e,
                    task = "governance_webhook",
                    "background task did not shut down cleanly (panicked or was cancelled)"
                );
            }
        }
        if let Some(handle) = policy_explain_handle {
            if let Err(e) = handle.join.await {
                tracing::warn!(
                    error = %e,
                    task = "policy_explain",
                    "background task did not shut down cleanly (panicked or was cancelled)"
                );
            }
        }
        // tonic's graceful shutdown future resolved when the broadcast fired
        // above; this await just collects the join handle.
        #[cfg(feature = "flight_sql")]
        Self::drain_sibling(flight_sql_handle, "flight_sql").await;

        Ok(())
    }

    /// Best-effort drain of a sibling `JoinHandle<()>` task on shutdown,
    /// logging (but not propagating) a panic/cancel. No-op if `handle` is
    /// `None`. Shared by the metrics and Flight SQL siblings.
    async fn drain_sibling(handle: Option<tokio::task::JoinHandle<()>>, task: &'static str) {
        if let Some(handle) = handle {
            if let Err(e) = handle.await {
                tracing::warn!(
                    error = %e,
                    task,
                    "background task did not shut down cleanly (panicked or was cancelled)"
                );
            }
        }
    }

    /// Handle a client connection using the pg wire protocol.
    ///
    /// # Errors
    /// Returns an error if the connection cannot be processed.
    // The per-connection wiring (observers, identity/org resolution, the
    // per-org catalog swap, and the DDL-admin bundle) is inherently sequential
    // setup; splitting it would scatter the shared closure captures.
    #[allow(clippy::too_many_lines)]
    #[tracing::instrument(skip(self, stream), fields(%peer_addr))]
    async fn handle_connection(
        &self,
        stream: tokio::net::TcpStream,
        peer_addr: SocketAddr,
    ) -> Result<()> {
        tracing::info!(%peer_addr, "Connection established");

        // Admission control — gate *before* the session, gauge, and
        // pgwire handshake so a refused connection costs almost nothing. The
        // permit releases its slot(s) on drop (held for the whole handler).
        let _rate_permit = if let Some(limiter) = &self.rate_limiter {
            match limiter.try_admit(peer_addr.ip()) {
                Ok(permit) => Some(permit),
                Err(reason) => {
                    self.metrics
                        .pgwire_connections_rejected_total
                        .with_label_values(&[reason.as_str()])
                        .inc();
                    // Audit-visible (same target as the failed-auth audit) —
                    // peer + reason only, no credential in scope (rule 12).
                    tracing::warn!(
                        target: "dataglot::audit",
                        action = "connection_rejected",
                        peer = %peer_addr,
                        reason = reason.as_str(),
                        "connection refused: rate limit reached"
                    );
                    // A rejection is not a *server* error; drop the socket
                    // (closing the client connection) and return cleanly.
                    return Ok(());
                }
            }
        } else {
            None
        };

        // Track connection lifecycle in the active-connections gauge. The
        // RAII guard ensures we decrement on every exit path, including
        // panics propagating through the pgwire handler.
        let _conn_guard = ConnectionGuard::new(&self.metrics);

        // Live-session registry — the per-connection detail behind
        // that gauge, backing GET /api/sessions ("who is connected"). Register
        // now, while the peer address and connect time are known; the
        // `StartupObserver` below fills in the resolved user + org once the
        // handshake completes. A sibling RAII guard deregisters on every exit
        // path, the same seam as the gauge's `.dec()`. Rule 4: pgwire never
        // learns about the registry — the server owns and drives it. Rule 12:
        // only the peer address is recorded here (no credential).
        let session_id = self.session_registry.next_id();
        self.session_registry
            .register(session_id, peer_addr.to_string());
        let _session_guard = SessionGuard::new(&self.session_registry, session_id);

        let ctx = Arc::new(self.create_session());

        // Per-query observers: MetricsObserver (counters /
        // histograms) and LineageObserver (OpenLineage event
        // emission, scoped to *this* connection's session
        // context for input-dataset extraction). Wrapping in
        // CompositeQueryObserver gives pgwire a single trait
        // object and keeps the two observers logically
        // independent — same shape as `CompositeEnforcer` for
        // policy.
        let metrics_obs: Arc<dyn dataglot_pgwire::QueryObserver> =
            Arc::new(MetricsObserver::new(self.metrics.clone()));
        let lineage_obs: Arc<dyn dataglot_pgwire::QueryObserver> = Arc::new(LineageObserver::new(
            Arc::clone(&self.lineage_emitter),
            Arc::clone(&ctx),
            Arc::clone(&self.masked_columns),
        ));
        // QueryRegistryObserver feeds the live "what's running" set read
        // by GET /api/queries — the dashboard data plane.
        let registry_obs: Arc<dyn dataglot_pgwire::QueryObserver> =
            Arc::new(QueryRegistryObserver::new(
                self.query_registry.clone(),
                self.config.observability.capture_query_sources,
                self.config.default_catalog.clone(),
                self.config.default_schema.clone(),
            ));
        let observer: Arc<dyn dataglot_pgwire::QueryObserver> =
            Arc::new(dataglot_pgwire::CompositeQueryObserver::new(vec![
                metrics_obs,
                lineage_obs,
                registry_obs,
            ]));

        // Per-task session identity wiring (Architecture Decisions §10
        // operative path — see #145, #147, #149 for the planning-time
        // resolver, governance config surface, and pgwire StartupMessage
        // extractor). The pgwire startup handler calls this closure
        // once per connection with the username from the
        // StartupMessage; `resolve_identity` consults the
        // `ServerConfig::identities` map to populate `org_groups`
        // (and optionally `org`) so `TagBasedEnforcer::rewrite` can
        // dispatch policies on group match. `try_set_*` is the safe
        // variant — `with_session_identity` below is the only place
        // that establishes the scope, but a defensive caller in this
        // seam is cheap insurance against future refactors.
        //
        // The closure captures an `Arc`-clone of the identities map
        // so each connection's task gets its own borrow without
        // touching `self`. The map itself is read-only after boot;
        // a future PR can swap the lookup for an external IdP query
        // without changing this seam.
        //  — the directory-group resolver, cloned into the observer so
        // it can overlay externally-resolved (jwt/ldap) groups onto the
        // session identity. For trust/md5/scram this is the config resolver and
        // the overlay is a no-op (groups already resolved from `identities`).
        let group_resolver = Arc::clone(&self.group_resolver);
        let identities = Arc::new(self.config.identities.clone());
        // Role definitions (Ranger role parity) — folded into the
        // session's effective groups at connection time.
        let roles = Arc::new(self.config.roles.clone());
        // Captured for the default-catalog override below. The closure runs
        // once, post-startup, before any query on this connection — so
        // mutating this connection's own `SessionContext` here is visible to
        // every subsequent query and races nothing.
        let catalog_ctx = Arc::clone(&ctx);
        //  M2 — captured so the observer can re-register this
        // connection's catalogs from its resolved org's snapshot (the session
        // was built at connect time with the boot org's set; see below).
        let live_catalogs = self.live_catalogs.clone();
        //  F9 — captured so the per-org startup swap can re-register the
        // connection's derived-product views from its resolved org (the session
        // was built with the boot org's views in `create_session`).
        let live_views = self.live_views.clone();
        let boot_org = self.boot_org.clone();
        let pg_roles = self.pg_role_specs();
        let boot_snapshot = self.current_catalogs_for_org(&self.boot_org);
        //  — the server's execution mode, computed once and closed
        // over so every session can answer `dataglot_execution_mode()`.
        let execution_mode = execution_mode_label(self.config.ballista.as_ref());
        //  — captured so the observer can attach this connection's
        // resolved user + org to its session-registry entry (registered at
        // connect above). `session_id` is `Copy`, so the move-closure takes
        // its own copy.
        let session_registry = self.session_registry.clone();
        //  — captured so the observer can decide whether this session may
        // run control-plane DDL. Trust mode has no real identity, so every
        // session is an admin (matches the "trust is fully open" posture).
        let trust_mode = matches!(self.config.auth.mode, crate::config::AuthMode::Trust);
        let startup_observer: dataglot_pgwire::StartupObserver =
            Arc::new(move |info: &dataglot_pgwire::StartupInfo<'_>| {
                let identity = resolve_identity_with_roles(info.user, &identities, &roles);
                //  F5b — overlay the RBAC roles + superuser flag the
                // async md5 auth path resolved from the control-plane store,
                // bridged here via the pgwire auth-principal task-local (rule 4:
                // the server carries the value pgwire ⇄ policy; rule 11: the
                // observer is sync and never re-queries the store). The
                // `GrantEnforcer` matches a privilege grant's grantee against
                // the session user OR one of these roles, and skips enforcement
                // entirely for a superuser. Absent (trust mode / config
                // identity / unknown user) ⇒ no roles, not superuser — a
                // fail-closed default that keeps existing behaviour unchanged.
                let principal = dataglot_pgwire::current_auth_principal();
                let is_superuser = principal.as_ref().is_some_and(|p| p.is_superuser);
                //  — who may run control-plane DDL. Trust mode (no real
                // auth) OR a config-defined identity (operator-provisioned) OR a
                // store superuser. Kept separate from `is_superuser` so a
                // config-defined analyst can be an admin surface OR a
                // grant-enforced reader independently — here it authorizes DDL
                // without bypassing read-time grant / column-whitelist checks.
                let can_admin = trust_mode || identities.contains_key(info.user) || is_superuser;
                // Bridge `can_admin` (and preserve roles / is_superuser) into the
                // task-local the pgwire DDL handler reads. The store `PasswordSource`
                // may have set roles + is_superuser during async auth; recompute
                // `can_admin` here where trust-mode / config-identity is known.
                dataglot_pgwire::try_set_auth_principal(dataglot_pgwire::AuthPrincipal {
                    roles: principal
                        .as_ref()
                        .map(|p| p.roles.clone())
                        .unwrap_or_default(),
                    is_superuser,
                    can_admin,
                });
                let identity = match principal {
                    Some(principal) => {
                        let mut id = identity;
                        if !principal.roles.is_empty() {
                            id = id.with_roles(principal.roles);
                        }
                        // Only the store superuser flag bypasses grant enforcement
                        // — NOT `can_admin` ( keeps the two decoupled).
                        if principal.is_superuser {
                            id = id.as_superuser();
                        }
                        id
                    }
                    None => identity,
                };
                //  — overlay the directory groups an external IdP
                // resolved for this connection during the (async) jwt/ldap
                // auth handshake, bridged here via `current_auth_groups` (the
                // sync observer must not do async IO — rule 11). The config
                // resolver returns `None` (its groups are already in the
                // identity), so trust/md5/scram are byte-identical. On an IdP
                // resolver the resolved groups REPLACE the identity's groups
                // (directory is authoritative), and roles are re-folded so a
                // role scoped to a directory group still activates. An
                // `Unavailable` resolution grants NO groups (least privilege)
                // and logs a WARN — never groups-on-error.
                let identity = match group_resolver
                    .resolve_session_groups(dataglot_pgwire::current_auth_groups().as_ref())
                {
                    Some(resolution) => {
                        if matches!(
                            resolution,
                            crate::group_resolver::GroupResolution::Unavailable
                        ) {
                            tracing::warn!(
                                target: "dataglot::audit",
                                action = "group_resolution_unavailable",
                                user = info.user,
                                "directory group resolution failed after authentication; \
                                 granting no groups (least privilege)"
                            );
                        }
                        let with_groups = identity.with_groups(resolution.group_names());
                        crate::config::fold_roles_into_groups(with_groups, &roles)
                    }
                    None => identity,
                };
                //  M2 — mirror the resolved org into the pgwire
                // session-org task-local so the handler scopes catalog / secret
                // DDL to this connection's tenant. Rule 4 forbids pgwire
                // depending on dataglot-policy, so the server (which depends on
                // both) bridges the value across. The org is a tenant name, not
                // a credential (rule 12).
                //
                //  F3 precedence — a config-defined identity's org wins;
                // otherwise the org resolved from the store during md5 auth
                // (global-unique usernames), read back from the pgwire auth-org
                // task-local the store-backed `PasswordSource` populated on this
                // connection; otherwise the boot org. This keeps config-defined
                // identities and the no-control-plane fast path (`live_catalogs`
                // is `None`, `current_auth_org` is `None`) unchanged.
                //
                //  F4 — resolve a *concrete* org for this session and keep
                // three values consistent: the identity's `.org`, the pgwire
                // session-org task-local, and the org the policy-DDL handler tags
                // rules with. A trust/default (org-less) session resolves to
                // `boot_org`, so a `CREATE MASK` it runs is tagged
                // `Some(boot_org)` and the enforcer's
                // `org_rule_applies(Some(boot_org), identity)` matches for that
                // very session — otherwise the applied org (`"default"`) and the
                // enforcement org (`None`) disagreed and the mask never fired,
                // not even for its own creator (the F4 e2e regression).
                let resolved_org = resolved_session_org(
                    identity.org.as_deref(),
                    dataglot_pgwire::current_auth_org(),
                    &boot_org,
                );
                // Publish an identity whose `.org` is the concrete resolved org
                // so the enforcer matches on the same value the DDL path tags
                // rules with. Only fill it in when the identity carried no org —
                // a config identity or a real multi-org user (`Some("acme")`)
                // keeps its own org untouched, so multi-org behaviour is
                // unchanged. File-config masks stay `org = None` (operator-wide)
                // and still apply to everyone, so single-org config behaviour is
                // preserved byte-for-byte.
                let identity = if identity.org.is_none() {
                    identity.with_org(resolved_org.clone())
                } else {
                    identity
                };
                // Mirror the resolved org into the pgwire session-org task-local
                // so the handler's `current_session_org().unwrap_or_else(|| "default")`
                // always takes the `Some` branch and `PolicyAdmin::apply`
                // receives the SAME org the enforcer matches on. Rule 4 forbids
                // pgwire depending on dataglot-policy, so the server (which
                // depends on both) bridges the value across. The org is a tenant
                // name, not a credential (rule 12).
                dataglot_pgwire::try_set_session_org(Some(resolved_org.clone()));
                dataglot_policy::try_set_session_identity(identity);

                //  — now that the handshake has resolved the username
                // and the concrete org, attach them to this connection's live
                // session-registry entry so GET /api/sessions shows *who* is
                // connected, per-org. An empty startup username (trust mode)
                // surfaces as `None`. Rule 12: user + org (a tenant name) are
                // safe to show; no credential is in scope here.
                let session_user = if info.user.is_empty() {
                    None
                } else {
                    Some(info.user.to_string())
                };
                session_registry.set_identity(session_id, session_user, Some(resolved_org.clone()));

                //  M2 — post-startup per-org catalog swap. `create_session`
                // built this connection with the boot org's catalog set (the org
                // wasn't known at connect time). Now that the identity's org is
                // resolved, if it differs, re-register the session's catalogs
                // from that org's live snapshot and shadow any boot-org catalog
                // the org lacks (an empty `MemoryCatalogProvider`, so it stops
                // resolving). For the boot org this is a no-op. Skipped entirely
                // on the no-control-plane fast path (`live_catalogs` is `None`).
                let org = resolved_org;
                if org != boot_org {
                    if let Some(registry) = &live_catalogs {
                        let org_snapshot = {
                            let guard = registry
                                .read()
                                .unwrap_or_else(std::sync::PoisonError::into_inner);
                            guard
                                .get(&org)
                                .map_or_else(|| Arc::new(CatalogSnapshot::new()), Arc::clone)
                        };
                        register_overlay_catalogs(&catalog_ctx, &org_snapshot, &pg_roles);
                        for name in boot_snapshot.keys() {
                            if !org_snapshot.contains_key(name) {
                                catalog_ctx.register_catalog(
                                    name.clone(),
                                    Arc::new(MemoryCatalogProvider::new()),
                                );
                            }
                        }
                    }
                    //  F9 — swap derived-product views to the resolved
                    // org: drop the boot org's views this session got in
                    // `create_session`, then register the resolved org's, so
                    // views stay tenant-isolated (mirrors the catalog swap).
                    if let Some(registry) = &live_views {
                        let guard = registry
                            .read()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        if let Some(boot_views) = guard.get(&boot_org) {
                            for view in boot_views.values() {
                                let _ = catalog_ctx.deregister_table(view.reference.clone());
                            }
                        }
                        if let Some(org_views) = guard.get(&org) {
                            for view in org_views.values() {
                                if let Err(e) = catalog_ctx.register_table(
                                    view.reference.clone(),
                                    Arc::clone(&view.provider),
                                ) {
                                    tracing::warn!(
                                        view = %view.reference, org = %org, error = %e,
                                        "view: register into session failed; skipping"
                                    );
                                }
                            }
                        }
                    }
                }

                // Honor the pgwire `database` startup parameter as this
                // connection's default catalog — standard Postgres `\c <db>`
                // semantics — but only when it names a catalog the server
                // actually registered. An unknown/empty database leaves the
                // server's configured default_catalog in place (no error), so
                // existing clients are unaffected. This is what lets one
                // server serve, say, `dbname=pg` (unqualified names resolve
                // against Postgres) and `dbname=tpch` (against the TPC-H
                // parquet catalog) on different connections.
                match connection_default_catalog(info.database, |c| {
                    catalog_ctx.catalog(c).is_some()
                }) {
                    ConnectionDefaultCatalog::Apply(db) => {
                        let state_ref = catalog_ctx.state_ref();
                        let mut state = state_ref.write();
                        state.config_mut().options_mut().catalog.default_catalog = db;
                    }
                    ConnectionDefaultCatalog::UnknownCatalog(db) => {
                        //: refuse the connection like Postgres — an
                        // unknown `database` startup parameter is a
                        // `3D000 invalid_catalog_name` FATAL, not a silent
                        // fallback to the default catalog (which would run
                        // the client's queries against the wrong data). The
                        // database name is a catalog name, not a credential
                        // (rule 12) — safe to name in the error/log.
                        tracing::warn!(
                            database = %db,
                            "pgwire connection requested an unregistered database/catalog; \
                             refusing with 3D000 (invalid_catalog_name)"
                        );
                        return Err(dataglot_pgwire::StartupRejection {
                            sqlstate: "3D000".to_string(),
                            message: format!("database \"{db}\" does not exist"),
                        });
                    }
                    ConnectionDefaultCatalog::Keep => {}
                }

                //  — register a per-session `current_database()` that
                // reflects this connection's default catalog, overriding
                // `datafusion-pg-catalog`'s hardcoded `"datafusion"`. Runs
                // after the mapping above so it sees the resolved catalog.
                register_session_current_database(&catalog_ctx);

                //  — register a per-session `session_user()` (and thus
                // `current_user`, which the upstream SQL-rewrites to it) that
                // reports the role this connection authenticated as, replacing
                // the upstream hardcoded `"postgres"`.
                catalog_ctx.register_udf(dataglot_core::functions::session_user_udf(info.user));

                //  — expose the server's execution mode so clients
                // (the testbench badge) can ask the engine itself whether
                // it runs single-node or distributed.
                catalog_ctx.register_udf(dataglot_core::functions::execution_mode_udf(
                    &execution_mode,
                ));

                Ok(())
            });

        // Scope the connection's task in `with_session_identity` so
        // the optimizer rule sees the right identity for every query
        // on this connection — even though the SessionContext (and
        // its `PolicyOptimizerRule`) was built before the username
        // arrived. The initial value is `Identity::anonymous()`; the
        // pgwire startup handler calls `startup_observer` after the
        // StartupMessage parses, replacing it before any query runs.
        let conn_future = dataglot_pgwire::handle_connection_with_security(
            stream,
            peer_addr,
            ctx,
            observer,
            startup_observer,
            dataglot_pgwire::ConnectionSecurity {
                auth: self.auth.clone(),
                tls: self.pgwire_tls.clone(),
                admission: self.identity_admission.clone(),
                // Server-wide: a CancelRequest arrives on its own TCP
                // connection and must resolve keys registered by every
                // other connection.
                cancel_registry: Some(Arc::clone(&self.cancel_registry)),
                // SQL-native catalog DDL: `Some` iff a
                // control-plane store is configured.
                catalog_admin: self.catalog_admin.clone(),
                // SQL-native secrets: `Some` iff a store +
                // envelope key are configured.
                secret_admin: self.secret_admin.clone(),
                // SQL-native users: `Some` iff a store is
                // configured.
                user_admin: self.user_admin.clone(),
                // SQL-native policies: `Some` iff a store
                // is configured; applies masks/row-filters to the live
                // enforcer and persists them.
                policy_admin: self.policy_admin.clone(),
                // SQL-native grants: `Some` iff a store is
                // configured; persists GRANT/REVOKE. Stores only — no
                // enforcement (F5b).
                grant_admin: self.grant_admin.clone(),
                // SQL-native views / derived products:
                // `Some` iff a store is configured; persists CREATE/DROP VIEW
                // and registers it into the live view registry.
                view_admin: self.view_admin.clone(),
            },
        );
        // Nest a pgwire session-org scope inside the identity scope (
        // M2): the startup observer sets the resolved org into it, and the
        // handler reads it back to scope catalog / secret DDL. Initial `None`
        // ⇒ `"default"` until the observer runs, matching the pre-M2 boot org.
        //
        // Innermost is the  F3 auth-org scope: the store-backed
        // `PasswordSource` writes the org it resolved during md5 auth into it,
        // and the startup observer (which runs afterwards, in the same task)
        // reads it back to route the session to that tenant. Both scopes wrap
        // the whole connection future, so auth (which happens inside it) and the
        // observer share the task-locals.
        // Box::pin — the composed connection future is large (pgwire handler +
        // nested scopes); boxing keeps it off the stack (clippy::large_futures).
        // Innermost also carries the  F5b auth-principal scope: the
        // store-backed `PasswordSource` writes the roles + superuser flag it
        // resolved during md5 auth into it, and the startup observer (same
        // task, runs afterwards) reads them back to build the session identity.
        // Innermost still: the  slice-2 pushdown sink. Installing the
        // query registry as the task-local sink lets the federation connectors'
        // per-source pushdown stats route to the right query entry — the
        // observer stamps each query's run_id (gated on capture_query_sources),
        // and the stream drain runs inline in this same task, so connector
        // polls see the task-local. Installed unconditionally (a cheap Arc);
        // capture is gated at the run_id stamp in the observer.
        //
        // `Box::pin` the pushdown-scoped composite *here*, not just at the
        // outer scope: `conn_future` is already a very large future, and
        // building another scope layer around it inline materializes the whole
        // thing on the stack (the in-process e2e boots overflow the stack —
        // same reasoning as the outer boxing below). Boxing keeps it on the
        // heap so the surrounding scope chain only holds a pointer-sized future.
        let pushdown_sink: Arc<dyn dataglot_core::PushdownSink> =
            Arc::new(self.query_registry.clone());
        let conn_future = Box::pin(dataglot_core::with_pushdown_sink(
            pushdown_sink,
            conn_future,
        ));
        Box::pin(dataglot_policy::with_session_identity(
            dataglot_policy::Identity::anonymous(),
            dataglot_pgwire::with_session_org(
                None,
                dataglot_pgwire::with_auth_org(
                    None,
                    dataglot_pgwire::with_auth_principal(
                        dataglot_pgwire::AuthPrincipal::default(),
                        //  — innermost auth-groups scope: the jwt/ldap
                        // startup handler writes the directory groups it
                        // resolved during (async) auth into it, and the sync
                        // startup observer (same task, runs afterwards) reads
                        // them back to populate `Identity::org_groups`.
                        dataglot_pgwire::with_auth_groups(None, conn_future),
                    ),
                ),
            ),
        ))
        .await
        .with_context(|| format!("Failed to handle connection from {peer_addr}"))?;

        // Info (not debug) to balance the `info` "Connection established"
        // above — otherwise every open logs at default level with no
        // matching close, so connections that never close can't be spotted
        tracing::info!(%peer_addr, "Connection closed");
        Ok(())
    }
}

/// Build the typed bindings map at server boot.
///
/// Two paths, selected by `service_cfg`:
///
/// - **`None`** (pre-task-08 fast path): bindings come directly
///   from `[catalogs.*]` via `CatalogConfig::binding()`. No
///   Postgres dependency at boot. This is the default and the
///   shape every existing `dataglot.toml` keeps working with.
/// - **`Some(...)`**: connect to the catalog service, upsert
///   every `[catalogs.*]` entry (JSON wins on conflict in
///   Phase 1), then call `list_bindings` for the canonical
///   snapshot. Future external writers (e.g. a teammate
///   inserting via the runtime-mutation API in Phase 2) will
///   surface on subsequent boots — and on the cache's
///   `subscribe` stream (impl PR 4 — task 09).
///
/// # Errors
/// `Some` path may fail on service connect, on schema-version
/// mismatch, on upsert errors, or on a malformed binding in
/// the database — all surfaced through the `anyhow::Result`.
async fn build_bindings(
    catalogs: &HashMap<String, CatalogConfig>,
    service_cfg: Option<&CatalogServiceConfig>,
) -> Result<HashMap<String, CatalogBinding>> {
    let Some(svc_cfg) = service_cfg else {
        // Fast path: just compute bindings locally from the
        // existing catalog config.
        return Ok(catalogs
            .iter()
            .map(|(name, cfg)| (name.clone(), cfg.binding()))
            .collect());
    };

    // Slow path: connect the store, sync JSON → store, then read back. Every
    // store call is scoped to the configured boot org ( M1: still a
    // single org until M2 threads the real per-connection org).
    let org = svc_cfg.org_id();
    let svc = connect_meta_store(svc_cfg).await?;

    for (name, cfg) in catalogs {
        svc.upsert_binding(org, name, &cfg.binding())
            .await
            .with_context(|| format!("catalog service upsert for {name:?}"))?;
        // Task 12 slice 1: also persist the full (credential-free) source
        // config so the control plane can rebuild the live provider — the
        // basis for managing catalogs in the DB rather than the file.
        let source_config = serde_json::to_value(cfg)
            .with_context(|| format!("serialize source config for {name:?}"))?;
        svc.set_source_config(org, name, &source_config)
            .await
            .with_context(|| format!("catalog service set_source_config for {name:?}"))?;
    }

    svc.list_bindings(org)
        .await
        .context("catalog service list_bindings after upsert sync")
}

/// Replay **every org's** SQL-native policies into the live `rule_store`,
/// each tagged with its owning org. Iterates
/// [`MetaStore::list_orgs`] and, for each, lowers every stored
/// `MaskConfig` / `RowFilterConfig` through the *same* config→enforcer path a
/// boot-config rule uses (`config::build_mask_rules` /
/// `config::build_row_filter_rules`) and applies it as a `RuleChange` upsert —
/// so a `CREATE MASK` issued at runtime under any tenant enforces again for
/// *that tenant* after a restart.
///
/// The config→enforcer path returns operator-wide (`org: None`) rules (the
/// file-config default); here we override each with `org = Some(store_org)`
/// so the reloaded rule is tenant-scoped exactly like the runtime DDL that
/// created it. The org comes from the store key, not the persisted JSON, so
/// the on-disk `MaskConfig` / `RowFilterConfig` shape is unchanged (F4 §5).
///
/// Store-wins precedence: config rules are already seeded, and a tenant-scoped
/// upsert replaces by `(table, column, org)` / `(table, org)`, so it never
/// collapses another tenant's rule on the same resource.
async fn load_persisted_policies(
    store: &dyn MetaStore,
    rule_store: &InMemoryRuleStore,
) -> Result<()> {
    use dataglot_policy::{RuleChange, RuleStore};

    for org in store.list_orgs().await? {
        for record in store.list_policies(&org).await? {
            let Some((kind, value)) = store.get_policy(&org, &record.name).await? else {
                continue; // Raced a delete between list and get — nothing to load.
            };
            match kind.as_str() {
                "mask" => {
                    let cfg: crate::config::MaskConfig = serde_json::from_value(value)
                        .with_context(|| format!("persisted mask {:?} is corrupt", record.name))?;
                    for mut mask in crate::config::build_mask_rules(std::slice::from_ref(&cfg))? {
                        mask.org = Some(org.clone());
                        rule_store
                            .apply(RuleChange::MaskUpserted(mask))
                            .with_context(|| {
                                format!("apply persisted mask {:?} for org {org:?}", record.name)
                            })?;
                    }
                }
                "row_filter" => {
                    let cfg: crate::config::RowFilterConfig = serde_json::from_value(value)
                        .with_context(|| {
                            format!("persisted row filter {:?} is corrupt", record.name)
                        })?;
                    for mut filter in
                        crate::config::build_row_filter_rules(std::slice::from_ref(&cfg))?
                    {
                        filter.org = Some(org.clone());
                        rule_store
                            .apply(RuleChange::RowFilterUpserted(filter))
                            .with_context(|| {
                                format!(
                                    "apply persisted row filter {:?} for org {org:?}",
                                    record.name
                                )
                            })?;
                    }
                }
                other => {
                    tracing::warn!(
                        policy = %record.name,
                        org = %org,
                        kind = %other,
                        "skipping persisted policy of unknown kind at boot"
                    );
                }
            }
        }
    }
    Ok(())
}

/// Load **every org's** persisted grants, lowered to
/// policy-crate `Grant`s tagged with their owning org — the grant analogue of
/// [`load_persisted_policies`]. The [`GrantEnforcer`](dataglot_policy::GrantEnforcer)
/// narrows this set to a session at rewrite time (grantee + org match). Also
/// the reload path `StoreGrantAdmin` runs after a runtime `GRANT` / `REVOKE`
/// to republish the fresh set.
pub(crate) async fn load_all_grants(store: &dyn MetaStore) -> Result<Vec<dataglot_policy::Grant>> {
    let mut out = Vec::new();
    for org in store.list_orgs().await? {
        for record in store.list_grants(&org).await? {
            out.push(crate::config::build_grant(&org, &record));
        }
    }
    Ok(out)
}

/// Connect the configured control-plane [`MetaStore`]: Postgres
/// (`CatalogService`, HA / multi-node) or the pure-Rust embedded
/// single-file `redb` store (zero-external-dependency default,
/// slice A). Returned as `Arc<dyn MetaStore>` so the boot helpers stay
/// backend-agnostic.
///
/// # Errors
/// Surfaces the backend's connect/open failure — Postgres connect +
/// schema-version guard, or embedded open + version guard.
async fn connect_meta_store(cfg: &CatalogServiceConfig) -> Result<Arc<dyn MetaStore>> {
    match cfg {
        CatalogServiceConfig::Postgres(pg) => {
            let svc = CatalogService::connect(&pg.dsn, &pg.org_id)
                .await
                .with_context(|| {
                    format!("catalog store: Postgres connect for org {:?}", pg.org_id)
                })?;
            let store: Arc<dyn MetaStore> = Arc::new(svc);
            Ok(store)
        }
        CatalogServiceConfig::Embedded(em) => {
            //: the production embedded backend is the single-file redb
            // store (the whole-file JSON `EmbeddedMetaStore` remains only as an
            // in-test double).
            let svc = RedbMetaStore::open(&em.path, &em.org_id)
                .await
                .with_context(|| {
                    format!("catalog store: embedded redb open at {}", em.path.display())
                })?;
            let store: Arc<dyn MetaStore> = Arc::new(svc);
            Ok(store)
        }
    }
}

/// Build the `catalogs` map (and optionally the
/// `CatalogProviderCache` + invalidation task) at server boot.
///
/// Two paths:
/// - `service_cfg: None` → direct `build_connectors` (same as
///   pre-task-09 fast path). Returns the catalogs map plus
///   `(None, None)` for the cache + task.
/// - `service_cfg: Some(...)` → connect to the catalog
///   service, build the cache with a closure that captures
///   `config.catalogs` and routes per-name to
///   `build_one_connector`, pre-warm every entry into the
///   cache, then spawn the LISTEN/NOTIFY invalidation task.
///   Returns the catalogs map (sourced from the cache for
///   parity), the cache handle, and the task handle.
///
/// # Errors
/// Surfaces connector connect failures, catalog-service
/// connect failures, and pre-warm errors.
/// Plan each derived product's SQL once and accumulate its column
/// lineage into a [`dataglot_core::lineage::LineageGraph`], so column
/// masks propagate to the product's derived columns (Interface 4,
///  slice 4b). The product is registered as a node named
/// `name`, qualified by its `catalog`/`schema` or the server defaults.
///
/// Best-effort per product: one that fails to plan (unreachable
/// source, bad SQL) or whose lineage can't be computed is logged and
/// skipped — masks simply won't propagate to it, and boot is never
/// blocked. Returns an empty graph when no products are configured.
async fn build_lineage_graph(
    products: &[DerivedProductConfig],
    factory: &SessionContextFactory,
    catalogs: &HashMap<String, Arc<dyn DfCatalogProvider>>,
    needs_federation: bool,
    default_catalog: &str,
    default_schema: &str,
) -> dataglot_core::lineage::LineageGraph {
    use dataglot_core::lineage::{column_lineage, DatasetRef, LineageGraph};

    let mut graph = LineageGraph::new();
    if products.is_empty() {
        return graph;
    }
    let ctx = if needs_federation {
        factory.create_federated_context()
    } else {
        factory.create_context()
    };
    for (name, catalog) in catalogs {
        // Replacing the `default_catalog` placeholder is expected (see
        // `create_session`); `catalogs` is a map so no real collision is
        // possible — discard the returned provider without warning.
        ctx.register_catalog(name, Arc::clone(catalog));
    }
    for p in products {
        let plan = match ctx.state().create_logical_plan(&p.sql).await {
            Ok(plan) => plan,
            Err(err) => {
                tracing::warn!(
                    product = %p.name, error = %err,
                    "lineage: derived product failed to plan; skipping (masks won't propagate to it)"
                );
                continue;
            }
        };
        let lineage = match column_lineage(&plan) {
            Ok(lineage) => lineage,
            Err(err) => {
                tracing::warn!(
                    product = %p.name, error = %err,
                    "lineage: column_lineage failed for derived product; skipping"
                );
                continue;
            }
        };
        let dataset = DatasetRef {
            catalog: p
                .catalog
                .clone()
                .unwrap_or_else(|| default_catalog.to_string()),
            schema: p
                .schema
                .clone()
                .unwrap_or_else(|| default_schema.to_string()),
            table: p.name.clone(),
        };
        graph.add_product(&dataset, &lineage);
    }
    graph
}

/// Resolve the effective catalog set the server builds providers from, with
/// the **control-plane store authoritative** (slice A2).
///
/// `build_catalogs_and_cache` reconciles the file/env catalogs into the store
/// first, so `db_configs` already carries the current file view; this function
/// takes the store's configs as truth. Fallbacks keep boot resilient:
/// - a stored config that doesn't deserialize falls back to the file/env
///   config for that name (a corrupt store entry can't take down a
///   file-declared catalog);
/// - a name present only in the file/env (e.g. its store seed-write failed) is
///   added defensively so the catalog isn't silently lost;
/// - a name present only in the store (added out-of-band / by runtime DDL) is
///   kept.
///
/// Pure (no I/O) so the precedence decision is unit-tested directly. Returns
/// the effective map plus `(name, error)` for stored configs that neither
/// parsed nor had a file fallback — the caller logs and skips those.
fn merge_effective_catalogs(
    file_env: &HashMap<String, CatalogConfig>,
    db_configs: HashMap<String, serde_json::Value>,
) -> (HashMap<String, CatalogConfig>, Vec<(String, String)>) {
    let mut effective = HashMap::with_capacity(db_configs.len().max(file_env.len()));
    let mut skipped = Vec::new();
    // Store wins: take each stored config, falling back to the file only when
    // the stored one is unparseable.
    for (name, json) in db_configs {
        match serde_json::from_value::<CatalogConfig>(json) {
            Ok(cfg) => {
                effective.insert(name, cfg);
            }
            Err(e) => {
                if let Some(file_cfg) = file_env.get(&name) {
                    effective.insert(name, file_cfg.clone());
                } else {
                    skipped.push((name, e.to_string()));
                }
            }
        }
    }
    // Defensive: a file/env name that never reached the store (seed write
    // failed) is still added rather than silently dropped.
    for (name, cfg) in file_env {
        effective.entry(name.clone()).or_insert_with(|| cfg.clone());
    }
    (effective, skipped)
}

// Boot-time orchestration: connect the store, reconcile file→store, resolve
// precedence, build the cache + live registry + secret resolver. The steps are
// sequential and share locals, so keeping them in one function reads better
// than threading state through several helpers.
#[allow(clippy::too_many_lines)]
async fn build_catalogs_and_cache(
    catalogs_cfg: &HashMap<String, CatalogConfig>,
    service_cfg: Option<&CatalogServiceConfig>,
    tolerate_unreachable: bool,
    // Envelope cipher (slice D); enables `dsn_secret` resolution on the boot +
    // refresh build paths. `None` ⇒ inline-credential catalogs only.
    secret_cipher: Option<Arc<crate::secret_crypto::SecretCipher>>,
) -> Result<(
    HashMap<String, Arc<dyn DfCatalogProvider>>,
    Option<Arc<CatalogProviderCache>>,
    Option<tokio::task::JoinHandle<()>>,
    // Live registry (slice B); `None` on the no-control-plane fast path.
    Option<LiveCatalogRegistry>,
    // Meta-store handle for the catalog-DDL admin (slice C); `None` on the
    // no-control-plane fast path. Same store the registry refresh reads.
    Option<Arc<dyn MetaStore>>,
    // Cheap-liveness handles over the boot-built SQL connectors; the
    // connector-health poller reuses these instead of rebuilding on every tick.
    // Non-SQL connectors contribute no entry (poller falls back to rebuild).
    HashMap<String, crate::config::ConnectorHealthHandle>,
)> {
    let Some(svc_cfg) = service_cfg else {
        // Fast path: no cache, no live registry, no DDL store.
        let (catalogs, health_handles) =
            build_connectors_with_health(catalogs_cfg, tolerate_unreachable).await?;
        return Ok((catalogs, None, None, None, None, health_handles));
    };

    // Connect the store once — used both to read the control plane's stored
    // source configs (the store is a source of truth for catalogs, not only
    // the file) and, below, for the invalidation stream. Postgres or the
    // embedded backend, per config. Every store call is scoped to the
    // configured boot org ( M1; M2 threads the per-connection org).
    let org = svc_cfg.org_id().to_string();
    let service = connect_meta_store(svc_cfg).await?;

    // Secret resolver over this store + the envelope cipher (slice D), so the
    // boot cache closure and the refresh path resolve `dsn_secret` references.
    let resolver: Option<Arc<dyn crate::config::SecretResolver>> = secret_cipher.map(|cipher| {
        Arc::new(crate::secret_admin::StoreSecretResolver::new(
            Arc::clone(&service),
            cipher,
        )) as Arc<dyn crate::config::SecretResolver>
    });

    // Reconcile file/env catalogs INTO the store (slice A2), then read the
    // store as the authoritative set. Re-seeding the current file every boot
    // keeps file edits working (behavior-preserving) while the *running server*
    // now sources catalogs from the store — the pivot that lets runtime SQL DDL
    // (later slices) change what a live server serves. Best-effort: a store
    // write failure WARNs and continues; `merge_effective_catalogs` falls back
    // to the file for any name that didn't make it in. A store-only catalog
    // (added out-of-band / by DDL) survives — reconcile only upserts, never
    // deletes. (`build_bindings` re-runs this reconcile for the bindings map; a
    // later slice consolidates the two into one seeded connection.)
    for (name, cfg) in catalogs_cfg {
        let source_config = match serde_json::to_value(cfg) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(
                    catalog = %name, error = %e,
                    "catalog store: serialize source config failed; skipping seed"
                );
                continue;
            }
        };
        if let Err(e) = service.upsert_binding(&org, name, &cfg.binding()).await {
            tracing::warn!(catalog = %name, error = %e, "catalog store: seed upsert_binding failed; continuing");
            continue;
        }
        if let Err(e) = service.set_source_config(&org, name, &source_config).await {
            tracing::warn!(catalog = %name, error = %e, "catalog store: seed set_source_config failed; continuing");
        }
    }

    // Effective catalog set: the store's stored source configs, authoritative,
    // with file/env fallbacks (see `merge_effective_catalogs`). A store read
    // failure falls back to file/env only.
    let effective = match service.list_source_configs(&org).await {
        Ok(db_configs) => {
            let (effective, skipped) = merge_effective_catalogs(catalogs_cfg, db_configs);
            for (name, err) in skipped {
                tracing::warn!(
                    catalog = %name, error = %err,
                    "catalog service: stored source_config didn't parse; skipping"
                );
            }
            effective
        }
        Err(e) => {
            tracing::warn!(
                error = format!("{e:#}"),
                "catalog service: list_source_configs failed; using file/env catalogs only"
            );
            catalogs_cfg.clone()
        }
    };

    // Build the cache. The closure clones the relevant
    // `CatalogConfig` for each catalog and routes per-name
    // to `build_one_connector`. CLAUDE.md rule 4 — the cache
    // crate doesn't depend on dataglot-server; the closure
    // captures the helper here.
    let owned_cfg: HashMap<String, CatalogConfig> = effective.clone();
    let build_resolver = resolver.clone();
    let build_org = org.clone();
    // Side channel for the  health handles: the cache's `ProviderBuilder`
    // only hands back the provider, so the SQL connectors' cheap-liveness handles
    // are stashed here as each catalog is (re)built. Shared with the closure,
    // which also runs on later cold cache rebuilds — refreshing a name's handle
    // in place, which is exactly what we want.
    let health_handles: Arc<
        std::sync::Mutex<HashMap<String, crate::config::ConnectorHealthHandle>>,
    > = Arc::new(std::sync::Mutex::new(HashMap::new()));
    let build_health_handles = Arc::clone(&health_handles);
    let build: dataglot_catalog::cache::ProviderBuilder = Arc::new(move |name: String| {
        let cfg_map = owned_cfg.clone();
        let resolver = build_resolver.clone();
        let org = build_org.clone();
        let health_handles = Arc::clone(&build_health_handles);
        Box::pin(async move {
            let Some(cfg) = cfg_map.get(&name) else {
                // Returning a typed catalog error here keeps
                // the cache's `Result` type-aligned. The
                // closure runs only for keys the cache was
                // primed with, so this is defensive.
                return Err(dataglot_catalog::CatalogServiceError::Pool(format!(
                    "catalog {name:?} not in config"
                )));
            };
            // Resolve `dsn_secret` references (slice D) into a runtime config
            // before building; a config without one is returned unchanged.
            let runtime = crate::config::resolve_catalog_secrets(cfg, &org, resolver.as_deref())
                .await
                .map_err(|e| {
                    dataglot_catalog::CatalogServiceError::Pool(format!(
                        "catalog {name:?} secret resolution failed: {e:#}"
                    ))
                })?;
            let (provider, handle) =
                crate::config::build_one_connector_with_health(&name, &runtime)
                    .await
                    .map_err(|e| {
                        dataglot_catalog::CatalogServiceError::Pool(format!(
                            "catalog {name:?} build failed: {e:#}"
                        ))
                    })?;
            if let Some(handle) = handle {
                if let Ok(mut map) = health_handles.lock() {
                    map.insert(name.clone(), handle);
                }
            }
            Ok(provider)
        })
    });
    let cache = Arc::new(CatalogProviderCache::new(build));

    // Pre-warm: call cache.get() for every effective catalog
    // (file/env + control-plane). Warm hits feed the catalogs
    // map; cold hits run `build_one_connector` via the closure.
    // `service` (connected above) is handed to the invalidation
    // stream below.
    let mut catalogs = HashMap::with_capacity(effective.len());
    for name in effective.keys() {
        match cache.get(name).await {
            Ok(provider) => {
                catalogs.insert(name.clone(), provider);
            }
            Err(e) if tolerate_unreachable => {
                // Same skip-and-WARN contract as the no-cache path
                // (`build_connectors_with`). The cache error wraps the
                // connector error chain — catalog name + redacted
                // connect failure, never credentials.
                tracing::warn!(
                    catalog = %name,
                    error = format!("{e:#}"),
                    "catalog unreachable at boot; skipping (tolerate_unreachable_catalogs)"
                );
            }
            Err(e) => {
                return Err(e).with_context(|| format!("catalog cache: pre-warm {name:?}"));
            }
        }
    }

    // Spawn the invalidation task. Drop of the JoinHandle
    // doesn't cancel; the server keeps the handle for its
    // lifetime so the task survives.
    // Live registry (slice B): seed with the boot snapshot, then spawn a
    // refresh task that rebuilds + swaps it on every store `BindingChange`
    // so a NEW session reflects out-of-band store changes (external tooling,
    // a second instance sharing the store, or slice C's DDL). `service` is an
    // `Arc` — cheap to share between the refresh task and the cache below.
    // Per-org registry: seed the boot org's snapshot; other orgs
    // populate lazily as their `BindingChange`s arrive.
    let registry: LiveCatalogRegistry = Arc::new(std::sync::RwLock::new(HashMap::from([(
        org.clone(),
        Arc::new(catalogs.clone()),
    )])));
    spawn_registry_refresh(
        Arc::clone(&service),
        org.clone(),
        catalogs_cfg.clone(),
        Arc::clone(&registry),
        resolver.clone(),
    );

    // Keep a handle for the catalog-DDL admin (slice C) before `service` is
    // moved into the cache's invalidation task below.
    let ddl_store = Arc::clone(&service);

    let task = cache
        .start_invalidation(service)
        .await
        .context("catalog cache: start invalidation task")?;

    // Snapshot the handles captured during pre-warm. Later cold cache
    // rebuilds refresh the shared map in place; the monitor holds this boot
    // snapshot, which covers every catalog that was reachable at boot.
    let health_handles = health_handles.lock().map(|m| m.clone()).unwrap_or_default();

    Ok((
        catalogs,
        Some(cache),
        Some(task),
        Some(registry),
        Some(ddl_store),
        health_handles,
    ))
}

/// Background task (control-plane path, slice B; per-org since  M2):
/// subscribe to the store's change feed and, on every `BindingChange`, rebuild
/// **only the changed org's** snapshot (`BindingChange.org_id`) and swap just
/// that org's registry entry. A new session for that org then reads the fresh
/// snapshot via `current_catalogs_for_org`. Spawned detached — it lives for
/// the process; a store-stream loss pauses live updates (logged) until restart,
/// and the last snapshots keep serving (stale-but-up).
///
/// The file/env `catalogs_cfg` is a fallback for **only** the boot org (that's
/// where boot seeded them); other orgs are store-only, so a boot file catalog
/// never leaks into another tenant's snapshot.
fn spawn_registry_refresh(
    service: Arc<dyn MetaStore>,
    boot_org: String,
    catalogs_cfg: HashMap<String, CatalogConfig>,
    registry: LiveCatalogRegistry,
    resolver: Option<Arc<dyn crate::config::SecretResolver>>,
) {
    use futures::StreamExt;
    tokio::spawn(async move {
        let mut stream = match service.subscribe().await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "catalog registry refresh: subscribe failed; live catalog updates disabled until restart"
                );
                return;
            }
        };
        let empty_cfg: HashMap<String, CatalogConfig> = HashMap::new();
        while let Some(change) = stream.next().await {
            let org = change.org_id;
            // File/env fallback applies to the boot org only (see fn docs).
            let file_cfg = if org == boot_org {
                &catalogs_cfg
            } else {
                &empty_cfg
            };
            let snapshot =
                build_effective_snapshot(service.as_ref(), &org, file_cfg, resolver.as_deref())
                    .await;
            let len = snapshot.len();
            if let Ok(mut w) = registry.write() {
                w.insert(org.clone(), Arc::new(snapshot));
                tracing::debug!(
                    %org,
                    catalogs = len,
                    "catalog registry refreshed from store change"
                );
            }
        }
        tracing::warn!(
            "catalog registry refresh: store change stream closed; live catalog updates paused until restart"
        );
    });
}

/// Rebuild the effective catalog set from the store (slice B refresh path):
/// read the store's source configs, resolve precedence with the file/env
/// config (`merge_effective_catalogs`), and build a provider for each.
/// Best-effort — a source that fails to build is logged and skipped (a
/// background rebuild can't fail anything), so one bad catalog can't wipe the
/// registry.
async fn build_effective_snapshot(
    service: &dyn MetaStore,
    org: &str,
    catalogs_cfg: &HashMap<String, CatalogConfig>,
    resolver: Option<&dyn crate::config::SecretResolver>,
) -> CatalogSnapshot {
    let db_configs = match service.list_source_configs(org).await {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(
                error = %e,
                "catalog registry refresh: list_source_configs failed; keeping the current snapshot"
            );
            HashMap::new()
        }
    };
    let (effective, skipped) = merge_effective_catalogs(catalogs_cfg, db_configs);
    for (name, err) in skipped {
        tracing::warn!(catalog = %name, error = %err, "catalog registry refresh: stored source_config didn't parse; skipping");
    }
    let mut snapshot = CatalogSnapshot::with_capacity(effective.len());
    for (name, cfg) in effective {
        // Resolve `dsn_secret` (slice D) into a runtime config first; unchanged
        // for catalogs without one. A resolution failure skips the catalog.
        let runtime = match crate::config::resolve_catalog_secrets(&cfg, org, resolver).await {
            Ok(rt) => rt,
            Err(e) => {
                tracing::warn!(catalog = %name, error = format!("{e:#}"), "catalog registry refresh: secret resolution failed; skipping this refresh");
                continue;
            }
        };
        match build_one_connector(&name, &runtime).await {
            Ok(provider) => {
                snapshot.insert(name, provider);
            }
            Err(e) => {
                // Background rebuild is never fatal (`tolerate_unreachable`
                // gates *boot*, not this). Log + skip.
                tracing::warn!(catalog = %name, error = format!("{e:#}"), "catalog registry refresh: catalog build failed; skipping this refresh");
            }
        }
    }
    snapshot
}

/// Spawn the governance-publisher `BindingChange` subscriber task,
/// if a catalog service is configured *and* at least one
/// governance publisher exists.
///
/// Returns `Ok(None)` when either prerequisite is missing — same
/// zero-cost shape as the lineage / cache-invalidation code paths.
///
/// The helper opens a *separate* `CatalogService` connection for
/// the subscriber (Postgres LISTEN fan-out is cheap; one extra
/// connection per subscriber keeps the cache and the governance
/// subscriber decoupled).
///
/// # Errors
/// Surfaces the initial `CatalogService::connect` failure and the
/// `subscribe()` call failure. Subsequent stream loss is absorbed
/// by the spawned task and logged at WARN.
async fn spawn_governance_invalidation(
    service_cfg: Option<&CatalogServiceConfig>,
    bindings: &HashMap<String, CatalogBinding>,
    publishers: &[DynDataProductPublisher],
) -> Result<Option<tokio::task::JoinHandle<()>>> {
    let Some(svc_cfg) = service_cfg else {
        return Ok(None);
    };
    if publishers.is_empty() {
        return Ok(None);
    }
    let service = connect_meta_store(svc_cfg).await?;
    let bindings_arc = Arc::new(bindings.clone());
    let publishers_arc = Arc::new(publishers.to_vec());
    let handle = spawn_binding_change_publisher(service, bindings_arc, publishers_arc)
        .await
        .map_err(|e| anyhow::anyhow!("governance subscriber: initial subscribe failed: {e}"))?;
    Ok(Some(handle))
}

/// Start the in-process scheduler for materialization refresh and
/// warehouse compaction (Phase 4 Task 03). Builds a dedicated
/// [`WarehouseConnector`] per warehouse referenced by a `Materialized` derived
/// product **or** a `[[maintenance.compaction]]` entry, constructs a
/// [`RefreshJob`] per product + per compaction target, and spawns the shared
/// [`RefreshScheduler`]. Nothing configured ⇒ no connectors, no tasks (empty
/// `Vec`), identical to pre- boot.
///
/// [`RefreshJob`]: crate::materialization::RefreshJob
///
/// # Errors
/// If a product or compaction entry names a warehouse that isn't a configured
/// `kind = "warehouse"` catalog, a warehouse connect fails, a `refresh_every` /
/// `compact_every` doesn't parse, or a target is duplicated.
// Threads the session/enforcer pieces plus both status registries through to
// the job builders; a params struct used in exactly one call site would be
// less clear than the explicit list.
#[allow(clippy::too_many_arguments)]
async fn spawn_scheduled_maintenance(
    config: &ServerConfig,
    factory: &SessionContextFactory,
    needs_federation: bool,
    catalogs: &HashMap<String, Arc<dyn DfCatalogProvider>>,
    enforcer: &Arc<dyn PolicyEnforcer>,
    shutdown_tx: &broadcast::Sender<()>,
    status: &crate::materialization_registry::MaterializationRegistry,
    maintenance_status: &crate::maintenance_registry::MaintenanceRegistry,
) -> Result<Vec<tokio::task::JoinHandle<()>>> {
    // Distinct warehouse names referenced by materialized products or by
    // compaction schedules — one connector serves both.
    let mut warehouses: std::collections::BTreeSet<&str> = config
        .derived_products
        .iter()
        .filter(|p| p.backing == MaterializationBacking::Materialized)
        .filter_map(|p| p.materialization.as_ref().map(|m| m.warehouse.as_str()))
        .collect();
    warehouses.extend(
        config
            .maintenance
            .compaction
            .iter()
            .map(|c| c.warehouse.as_str()),
    );
    warehouses.extend(
        config
            .maintenance
            .orphan_cleanup
            .iter()
            .map(|o| o.warehouse.as_str()),
    );
    if warehouses.is_empty() {
        return Ok(Vec::new());
    }

    let mut connectors: HashMap<String, Arc<WarehouseConnector>> = HashMap::new();
    for wh_name in warehouses {
        let Some(CatalogConfig::Warehouse(wh)) = config.catalogs.get(wh_name) else {
            anyhow::bail!(
                "scheduled maintenance: warehouse '{wh_name}' is not a configured \
                 `kind = \"warehouse\"` catalog"
            );
        };
        let connector = build_warehouse_connector(wh_name, wh).await?;
        connectors.insert(wh_name.to_string(), connector);
    }

    let catalogs_arc = Arc::new(catalogs.clone());
    let mut jobs = build_refresh_jobs(
        &config.derived_products,
        &connectors,
        factory,
        needs_federation,
        &catalogs_arc,
        enforcer,
        status,
    )?;
    jobs.extend(build_compaction_jobs(
        &config.maintenance.compaction,
        &connectors,
        maintenance_status,
    )?);
    jobs.extend(build_orphan_sweep_jobs(
        &config.maintenance.orphan_cleanup,
        &connectors,
        maintenance_status,
    )?);
    Ok(RefreshScheduler::spawn(jobs, shutdown_tx))
}

/// Implementation of [`dataglot_pgwire::QueryObserver`] that bumps the
/// per-query Prometheus counters on every observed query.
///
/// Holds a clone of [`Metrics`] (cheap — `Arc` inside) so the
/// per-connection cost is just an `Arc::clone` and a counter bump.
struct MetricsObserver {
    metrics: Metrics,
}

impl MetricsObserver {
    fn new(metrics: Metrics) -> Self {
        Self { metrics }
    }
}

impl dataglot_pgwire::QueryObserver for MetricsObserver {
    // Metrics don't need the plan (leaves `wants_plan()` at its `false`
    // default, so the handler skips plan capture for metrics-only setups).
    fn on_query_complete(
        &self,
        _run_id: dataglot_core::lineage::RunId,
        _query: &str,
        _plan: Option<std::sync::Arc<datafusion::logical_expr::LogicalPlan>>,
        outcome: dataglot_pgwire::QueryOutcome,
        duration: std::time::Duration,
    ) {
        let label = match outcome {
            dataglot_pgwire::QueryOutcome::Success => "success",
            dataglot_pgwire::QueryOutcome::Error => "error",
        };
        self.metrics
            .queries_total
            .with_label_values(&["pgwire", label])
            .inc();
        self.metrics
            .query_duration_seconds
            .with_label_values(&["pgwire"])
            .observe(duration.as_secs_f64());
    }
}

/// RAII guard that bumps the active-connection gauge for its lifetime.
struct ConnectionGuard<'a> {
    metrics: &'a Metrics,
}

impl<'a> ConnectionGuard<'a> {
    fn new(metrics: &'a Metrics) -> Self {
        metrics.pgwire_connections_active.inc();
        Self { metrics }
    }
}

impl Drop for ConnectionGuard<'_> {
    fn drop(&mut self) {
        self.metrics.pgwire_connections_active.dec();
    }
}

/// RAII guard that removes this connection's entry from the live
/// [`SessionRegistry`] when it drops — on every exit path, including a panic
/// unwinding through the pgwire handler. Mirrors [`ConnectionGuard`]; the two
/// bracket the same connection lifetime (the gauge count and the session list
/// stay consistent).
struct SessionGuard<'a> {
    registry: &'a SessionRegistry,
    session_id: crate::session_registry::SessionId,
}

impl<'a> SessionGuard<'a> {
    fn new(registry: &'a SessionRegistry, session_id: crate::session_registry::SessionId) -> Self {
        Self {
            registry,
            session_id,
        }
    }
}

impl Drop for SessionGuard<'_> {
    fn drop(&mut self) {
        self.registry.deregister(self.session_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use dataglot_policy::NoopPolicyEnforcer;

    ///  F4 boot: `load_persisted_policies` iterates every org and
    /// reloads each tenant's masks tagged with that org, so per-org
    /// enforcement survives a restart. Persists two tenants' masks on the
    /// *same* `(table, column)` via the runtime-DDL admin, then simulates a
    /// restart by loading into a fresh rule store and asserts each session
    /// sees only its own tenant's mask.
    #[tokio::test]
    async fn load_persisted_policies_reloads_every_org_tagged() {
        use datafusion::arrow::array::StringArray;
        use datafusion::arrow::datatypes::{DataType, Field, Schema};
        use datafusion::arrow::record_batch::RecordBatch;
        use datafusion::datasource::MemTable;
        use datafusion::prelude::SessionContext;
        use dataglot_pgwire::policy_admin::PolicyAdmin;
        use dataglot_pgwire::policy_ddl::{PolicyDdl, PolicyMask};
        use dataglot_policy::{Identity, InitialRules, RuleStore};

        // Declared before any statement (clippy::items_after_statements).
        async fn email(ctx: &SessionContext, rs: &InMemoryRuleStore, id: &Identity) -> String {
            let plan = ctx
                .sql("SELECT email FROM users")
                .await
                .unwrap()
                .logical_plan()
                .clone();
            let rewritten = rs.snapshot().rewrite(plan, id).expect("rewrite").data;
            let batches = ctx
                .execute_logical_plan(rewritten)
                .await
                .unwrap()
                .collect()
                .await
                .unwrap();
            batches[0]
                .column(0)
                .as_any()
                .downcast_ref::<StringArray>()
                .unwrap()
                .value(0)
                .to_string()
        }

        let dir = tempfile::tempdir().expect("tempdir");
        let store: Arc<dyn MetaStore> = Arc::new(
            EmbeddedMetaStore::open(dir.path().join("m.json"), "default")
                .await
                .expect("store"),
        );

        // Persist an acme mask and a beta mask on the same (table, column)
        // through the real runtime-DDL path (each tagged with its org).
        let seed_store = InMemoryRuleStore::new(InitialRules::default()).expect("seed rule store");
        let admin = crate::policy_admin::StorePolicyAdmin::new(Arc::clone(&store), seed_store);
        let mask_ddl = |name: &str, literal: &str| PolicyDdl::CreateMask {
            name: name.to_string(),
            table: "users".to_string(),
            column: "email".to_string(),
            mask: PolicyMask::Literal(literal.to_string()),
            if_not_exists: false,
        };
        admin
            .apply("acme", mask_ddl("m", "ACME"))
            .await
            .expect("acme mask");
        admin
            .apply("beta", mask_ddl("m", "BETA"))
            .await
            .expect("beta mask");

        // Simulate a restart: a fresh rule store, reloaded from the store.
        let rule_store = InMemoryRuleStore::new(InitialRules::default()).expect("fresh rule store");
        load_persisted_policies(store.as_ref(), &rule_store)
            .await
            .expect("reload");

        // Enforcement is per-org after the reload.
        let schema = Arc::new(Schema::new(vec![Field::new(
            "email",
            DataType::Utf8,
            false,
        )]));
        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![Arc::new(StringArray::from(vec!["real@x.com"]))],
        )
        .unwrap();
        let ctx = SessionContext::new();
        ctx.register_table(
            "users",
            Arc::new(MemTable::try_new(schema, vec![vec![batch]]).unwrap()),
        )
        .unwrap();

        assert_eq!(
            email(&ctx, &rule_store, &Identity::user("a").with_org("acme")).await,
            "ACME"
        );
        assert_eq!(
            email(&ctx, &rule_store, &Identity::user("b").with_org("beta")).await,
            "BETA"
        );
        assert_eq!(
            email(&ctx, &rule_store, &Identity::anonymous()).await,
            "real@x.com",
            "no tenant mask leaks to an anonymous session after reload"
        );
    }

    /// ** F5b server-level enforcement (no Docker).** Persists grants
    /// through the real `StoreGrantAdmin` path, reloads them with
    /// `load_all_grants`, composes the `GrantEnforcer` into the session stack
    /// via `compose_policy_enforcer`, and drives full-qualified scans through
    /// it — proving deny-by-default, USAGE+SELECT allow, cross-org isolation,
    /// and superuser bypass end-to-end across the catalog→policy translation.
    #[tokio::test]
    async fn grant_enforcer_denies_and_allows_through_composed_stack() {
        use datafusion::arrow::datatypes::{DataType, Field, Schema};
        use datafusion::catalog::{
            CatalogProvider, MemoryCatalogProvider, MemorySchemaProvider, SchemaProvider,
        };
        use datafusion::datasource::MemTable;
        use datafusion::prelude::SessionContext;
        use dataglot_pgwire::grant_admin::GrantAdmin;
        use dataglot_pgwire::grant_ddl::GrantDdl;
        use dataglot_policy::{Identity, InitialRules};

        // A SessionContext whose `pg.public.orders` yields a full 3-part scan.
        let ctx = SessionContext::new();
        let schema = Arc::new(Schema::new(vec![Field::new("id", DataType::Int32, false)]));
        let table = Arc::new(MemTable::try_new(schema, vec![vec![]]).expect("memtable"));
        let public = Arc::new(MemorySchemaProvider::new());
        public
            .register_table("orders".to_string(), table)
            .expect("register table");
        let catalog = Arc::new(MemoryCatalogProvider::new());
        catalog.register_schema("public", public).expect("schema");
        ctx.register_catalog("pg", catalog);

        let plan = || async {
            ctx.sql("SELECT id FROM pg.public.orders")
                .await
                .unwrap()
                .logical_plan()
                .clone()
        };

        let dir = tempfile::tempdir().expect("tempdir");
        let store: Arc<dyn MetaStore> = Arc::new(
            EmbeddedMetaStore::open(dir.path().join("m.json"), "acme")
                .await
                .expect("store"),
        );
        let admin = crate::grant_admin::StoreGrantAdmin::new(Arc::clone(&store), None);
        admin
            .apply(
                "acme",
                GrantDdl::GrantUsage {
                    catalog: "pg".into(),
                    grantee: "alice".into(),
                },
            )
            .await
            .expect("grant usage");
        admin
            .apply(
                "acme",
                GrantDdl::GrantSelect {
                    catalog: "pg".into(),
                    schema: "public".into(),
                    table: "orders".into(),
                    grantee: "alice".into(),
                },
            )
            .await
            .expect("grant select");

        // Reload via the boot helper + compose the full session stack.
        let grants = load_all_grants(store.as_ref()).await.expect("load grants");
        let grant_enforcer = crate::config::build_grant_enforcer(
            crate::config::AuthzMode::Grant,
            grants,
            "pg",
            "public",
        );
        let rule_store = InMemoryRuleStore::new(InitialRules::default()).expect("rule store");
        let enforcer = crate::config::compose_policy_enforcer(&rule_store, &[], grant_enforcer)
            .expect("compose");

        // Granted alice@acme → allowed.
        assert!(
            enforcer
                .rewrite(plan().await, &Identity::user("alice").with_org("acme"))
                .is_ok(),
            "USAGE + SELECT granted ⇒ allowed"
        );
        // Ungranted bob@acme → denied.
        assert!(
            enforcer
                .rewrite(plan().await, &Identity::user("bob").with_org("acme"))
                .is_err(),
            "no grants ⇒ denied"
        );
        // Cross-org: alice@beta (same name, other org) → denied.
        assert!(
            enforcer
                .rewrite(plan().await, &Identity::user("alice").with_org("beta"))
                .is_err(),
            "a grant in acme must not authorize alice in beta"
        );
        // Superuser bypass with no grants → allowed.
        assert!(
            enforcer
                .rewrite(
                    plan().await,
                    &Identity::user("root").with_org("acme").as_superuser()
                )
                .is_ok(),
            "superuser bypasses grant enforcement"
        );
    }

    /// Open mode composes to **no** grant enforcement: an ungranted session
    /// reads freely, preserving existing deployments.
    #[tokio::test]
    async fn open_mode_composes_without_grant_enforcement() {
        use datafusion::arrow::datatypes::{DataType, Field, Schema};
        use datafusion::catalog::{
            CatalogProvider, MemoryCatalogProvider, MemorySchemaProvider, SchemaProvider,
        };
        use datafusion::datasource::MemTable;
        use datafusion::prelude::SessionContext;
        use dataglot_policy::{Identity, InitialRules};

        let ctx = SessionContext::new();
        let schema = Arc::new(Schema::new(vec![Field::new("id", DataType::Int32, false)]));
        let table = Arc::new(MemTable::try_new(schema, vec![vec![]]).expect("memtable"));
        let public = Arc::new(MemorySchemaProvider::new());
        public
            .register_table("orders".to_string(), table)
            .expect("register table");
        let catalog = Arc::new(MemoryCatalogProvider::new());
        catalog.register_schema("public", public).expect("schema");
        ctx.register_catalog("pg", catalog);
        let plan = ctx
            .sql("SELECT id FROM pg.public.orders")
            .await
            .unwrap()
            .logical_plan()
            .clone();

        // Open mode ⇒ build_grant_enforcer returns None ⇒ no grant layer.
        let grant_enforcer = crate::config::build_grant_enforcer(
            crate::config::AuthzMode::Open,
            vec![],
            "pg",
            "public",
        );
        assert!(grant_enforcer.is_none(), "open mode ⇒ no grant enforcer");
        let rule_store = InMemoryRuleStore::new(InitialRules::default()).expect("rule store");
        let enforcer = crate::config::compose_policy_enforcer(&rule_store, &[], grant_enforcer)
            .expect("compose");
        assert!(
            enforcer
                .rewrite(plan, &Identity::user("nobody").with_org("acme"))
                .is_ok(),
            "open mode applies zero enforcement — an ungranted read succeeds"
        );
    }

    /// `resolved_session_org` never yields `None`: an org-less (trust/default)
    /// session resolves to the boot org, while a config/auth org still wins.
    #[test]
    fn resolved_session_org_falls_back_to_boot_org() {
        // org-less session → boot org (the F4 fix's core guarantee).
        assert_eq!(resolved_session_org(None, None, "default"), "default");
        // A config/identity org wins over everything.
        assert_eq!(
            resolved_session_org(Some("acme"), Some("store".to_string()), "default"),
            "acme"
        );
        // Else the store-resolved auth org (md5 global-unique usernames).
        assert_eq!(
            resolved_session_org(None, Some("store".to_string()), "default"),
            "store"
        );
    }

    /// **Defect 1 (F4 e2e regression) reproduced in-process — no Docker.**
    ///
    /// A trust/default session's identity carries `org = None`, but a
    /// `CREATE MASK` it runs is applied under the *concrete* resolved org
    /// (`resolved_session_org(None, None, boot_org) == "default"`), so the
    /// persisted mask is tagged `Some("default")`. The fix sets such a
    /// session's identity org to that same resolved value, so
    /// `org_rule_applies(Some("default"), identity)` matches and the mask
    /// fires for its own creator. The negative assertion on the *pre-fix*
    /// org-less identity pins the bug precisely: while the applied org
    /// (`Some("default")`) and the enforcement org (`None`) disagreed, the
    /// mask never fired — exactly the e2e
    /// `create_mask_masks_source_column_then_drop_unmasks` failure. Because
    /// the mask now fires for the resolved default session, that Docker e2e
    /// (which runs on a trust/default connection) passes.
    #[tokio::test]
    async fn orgless_session_mask_fires_once_identity_org_is_resolved() {
        use datafusion::arrow::array::StringArray;
        use datafusion::arrow::datatypes::{DataType, Field, Schema};
        use datafusion::arrow::record_batch::RecordBatch;
        use datafusion::datasource::MemTable;
        use datafusion::prelude::SessionContext;
        use dataglot_pgwire::policy_admin::PolicyAdmin;
        use dataglot_pgwire::policy_ddl::{PolicyDdl, PolicyMask};
        use dataglot_policy::{Identity, InitialRules, RuleStore};

        // Declared before any statement (clippy::items_after_statements).
        async fn email(ctx: &SessionContext, rs: &InMemoryRuleStore, id: &Identity) -> String {
            let plan = ctx
                .sql("SELECT email FROM users")
                .await
                .unwrap()
                .logical_plan()
                .clone();
            let rewritten = rs.snapshot().rewrite(plan, id).expect("rewrite").data;
            let batches = ctx
                .execute_logical_plan(rewritten)
                .await
                .unwrap()
                .collect()
                .await
                .unwrap();
            batches[0]
                .column(0)
                .as_any()
                .downcast_ref::<StringArray>()
                .unwrap()
                .value(0)
                .to_string()
        }

        let boot_org = "default";
        let dir = tempfile::tempdir().expect("tempdir");
        let store: Arc<dyn MetaStore> = Arc::new(
            EmbeddedMetaStore::open(dir.path().join("m.json"), boot_org)
                .await
                .expect("store"),
        );

        // An org-less session resolves to the boot org, and the pgwire handler
        // applies its `CREATE MASK` under that concrete org (`"default"`).
        let applied_org = resolved_session_org(None, None, boot_org);
        assert_eq!(applied_org, "default");
        let seed_store = InMemoryRuleStore::new(InitialRules::default()).expect("seed rule store");
        let admin = crate::policy_admin::StorePolicyAdmin::new(Arc::clone(&store), seed_store);
        admin
            .apply(
                &applied_org,
                PolicyDdl::CreateMask {
                    name: "m".to_string(),
                    table: "users".to_string(),
                    column: "email".to_string(),
                    mask: PolicyMask::Literal("MASKED".to_string()),
                    if_not_exists: false,
                },
            )
            .await
            .expect("create mask under the resolved org");

        // Load the persisted mask into a fresh rule store (as boot replay does).
        let rule_store = InMemoryRuleStore::new(InitialRules::default()).expect("fresh rule store");
        load_persisted_policies(store.as_ref(), &rule_store)
            .await
            .expect("reload");

        let schema = Arc::new(Schema::new(vec![Field::new(
            "email",
            DataType::Utf8,
            false,
        )]));
        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![Arc::new(StringArray::from(vec!["real@x.com"]))],
        )
        .unwrap();
        let ctx = SessionContext::new();
        ctx.register_table(
            "users",
            Arc::new(MemTable::try_new(schema, vec![vec![batch]]).unwrap()),
        )
        .unwrap();

        // With the fix: the session's identity org is resolved to `"default"`
        // (what the observer now sets), so the mask fires for its creator.
        let resolved_identity = Identity::user("trust").with_org(applied_org.clone());
        assert_eq!(
            email(&ctx, &rule_store, &resolved_identity).await,
            "MASKED",
            "a `CREATE MASK` from a default session must fire for that same session",
        );

        // Pre-fix behaviour (the bug): an org-less identity does NOT match the
        // `Some(\"default\")`-tagged mask — the applied org and enforcement org
        // disagreed and the mask never fired.
        assert_eq!(
            email(&ctx, &rule_store, &Identity::user("trust")).await,
            "real@x.com",
            "without org resolution the applied-vs-enforced org disagree (the F4 bug)",
        );
    }

    /// `drain` awaits tasks that observe the shutdown signal and exit — it
    /// returns promptly, well under the per-task timeout.
    #[tokio::test]
    async fn background_tasks_drain_awaits_signalled_tasks() {
        let (tx, _keep) = broadcast::channel::<()>(1);
        let handles = (0..3)
            .map(|_| {
                let mut rx = tx.subscribe();
                tokio::spawn(async move {
                    let _ = rx.recv().await;
                })
            })
            .collect();
        let bg = BackgroundTasks { handles };
        // Signal shutdown, then drain — every task should have exited.
        tx.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(2), bg.drain())
            .await
            .expect("drain completes once tasks observe the shutdown signal");
    }

    /// `abort_all` stops tasks that never observe shutdown; a subsequent drain
    /// then completes immediately (the handles resolve to a cancelled join).
    #[tokio::test]
    async fn background_tasks_abort_all_stops_running_tasks() {
        let handles = (0..3)
            .map(|_| {
                // Never completes on its own — only `abort` stops it.
                tokio::spawn(std::future::pending::<()>())
            })
            .collect();
        let bg = BackgroundTasks { handles };
        bg.abort_all();
        tokio::time::timeout(Duration::from_secs(2), bg.drain())
            .await
            .expect("aborted tasks drain immediately");
    }

    use datafusion::catalog::{
        CatalogProvider as DfCatalogProvider, SchemaProvider as DfSchemaProvider,
    };

    /// Minimal `DataFusion` `CatalogProvider` for tests. We only need
    /// `schema_names()` to be probable via the public API; the deeper
    /// async paths are covered by the federation integration tests.
    #[derive(Debug)]
    struct FakeCatalog {
        schemas: Vec<String>,
    }

    impl DfCatalogProvider for FakeCatalog {
        fn schema_names(&self) -> Vec<String> {
            self.schemas.clone()
        }
        fn schema(&self, _name: &str) -> Option<Arc<dyn DfSchemaProvider>> {
            // None of the assertions in this module call `.schema()` —
            // we only need `register_catalog` to accept the provider
            // and `catalog_names()` / `schema_names()` to round-trip.
            None
        }
    }

    #[tokio::test]
    async fn test_server_creation() {
        let config = ServerConfig::default();
        let server = DataglotServer::new(config).await.unwrap();
        assert_eq!(server.addr().port(), 5432);
    }

    /// `server_info()` surfaces the governance + security posture the dashboard
    /// needs (authz mode, active rule counts, auth mode, ingress-TLS, rate
    /// limiting) — never any secret.
    #[tokio::test]
    async fn server_info_reports_governance_and_security_posture() {
        let config = ServerConfig {
            access_denials: vec![crate::config::AccessDenyConfig {
                table: "pg.public.t".to_string(),
                column: Some("ssn".to_string()),
                groups: vec![],
            }],
            column_grants: vec![crate::config::ColumnGrantConfig {
                table: "pg.public.t".to_string(),
                columns: vec!["id".to_string()],
                org: None,
                groups: vec![],
            }],
            rate_limit: Some(crate::config::RateLimitConfig::default()),
            ..Default::default()
        };
        let server = DataglotServer::new(config).await.unwrap();
        let info = server.server_info();

        // Defaults: trust auth, no ingress TLS, open authz.
        assert_eq!(info.security.auth_mode, "trust");
        assert_eq!(info.security.ingress_tls, "off");
        assert!(info.security.rate_limiting, "rate_limit configured");
        assert_eq!(info.governance.authz_mode, "open");

        // Rule counts reflect config.
        assert_eq!(info.governance.access_denials, 1);
        assert_eq!(info.governance.column_grants, 1);
        assert_eq!(info.governance.masks, 0);
        assert_eq!(info.governance.row_filters, 0);

        // Build info is populated.
        assert!(matches!(info.build.profile, "debug" | "release"));

        // Rule 12: the serialized posture carries no secret-bearing field.
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"auth_mode\":\"trust\""));
        assert!(json.contains("\"authz_mode\":\"open\""));
    }

    /// Pins the [`DataglotServer::rule_store`] accessor contract:
    /// the production boot via `new` always returns `Some(_)`, even
    /// for an empty policy config (the store wraps a `NoopEnforcer` in
    /// that case). Slice 3's webhook handler depends on this — if
    /// the store is `None`, there's nowhere to publish rule changes.
    #[tokio::test]
    async fn rule_store_is_some_for_production_boot() {
        let config = ServerConfig::default();
        let server = DataglotServer::new(config).await.unwrap();
        assert!(
            server.rule_store().is_some(),
            "production boot via DataglotServer::new must always populate rule_store"
        );
    }

    /// The test-only constructor `new_with_catalogs` injects a
    /// pre-built static enforcer and leaves `rule_store` as `None`.
    /// The webhook handler in slice 3 must tolerate this — tests
    /// that don't care about the rule store shouldn't be forced to
    /// stand one up.
    #[test]
    fn rule_store_is_none_for_test_constructor_with_static_enforcer() {
        let enforcer: Arc<dyn PolicyEnforcer> = Arc::new(NoopPolicyEnforcer);
        let server =
            DataglotServer::new_with_catalogs(ServerConfig::default(), HashMap::new(), enforcer)
                .expect("test-only constructor");
        assert!(
            server.rule_store().is_none(),
            "new_with_catalogs must NOT populate rule_store — that path injects a static enforcer"
        );
    }

    /// Smoke: a server with no `[catalogs]` block still creates
    /// sessions and runs trivial SQL. Pins backwards-compatible
    /// behaviour for the operator who hasn't yet supplied a config
    /// file.
    #[tokio::test]
    async fn server_with_no_catalogs_creates_session() {
        let config = ServerConfig::default();
        let server = DataglotServer::new(config).await.unwrap();
        assert_eq!(server.registered_catalog_count(), 0);
        assert!(
            server.bindings().is_empty(),
            "no catalogs ⇒ no bindings populated"
        );
        let ctx = server.create_session();
        let result = ctx.sql("SELECT 1 + 1 as result").await;
        assert!(result.is_ok());
    }

    ///  — `current_database()` reflects the session's resolved
    /// default catalog and is isolated per session, overriding
    /// `datafusion-pg-catalog`'s hardcoded `"datafusion"`. Exercises the
    /// exact `StartupObserver` seam (`register_session_current_database`
    /// on a `create_session` context, which already carries the upstream
    /// UDF from `setup_pg_catalog`) so the assertion proves the override,
    /// not just a fresh registration.
    #[tokio::test]
    async fn startup_observer_current_database_is_per_session() {
        async fn current_db(ctx: &SessionContext) -> String {
            let batches = ctx
                .sql("SELECT current_database() AS db")
                .await
                .unwrap()
                .collect()
                .await
                .unwrap();
            batches[0]
                .column(0)
                .as_any()
                .downcast_ref::<datafusion::arrow::array::StringArray>()
                .expect("Utf8 result")
                .value(0)
                .to_string()
        }

        let server = DataglotServer::new_with_catalogs(
            ServerConfig::default(),
            HashMap::new(),
            Arc::new(NoopPolicyEnforcer),
        )
        .unwrap();

        // Session A → resolved to "pg" (mirrors the StartupObserver's
        // Apply arm setting default_catalog, then registering the UDF).
        let ctx_a = server.create_session();
        ctx_a
            .state_ref()
            .write()
            .config_mut()
            .options_mut()
            .catalog
            .default_catalog = "pg".to_string();
        register_session_current_database(&ctx_a);
        assert_eq!(current_db(&ctx_a).await, "pg");

        // Session B → "pg_orders": a second session's value is independent.
        let ctx_b = server.create_session();
        ctx_b
            .state_ref()
            .write()
            .config_mut()
            .options_mut()
            .catalog
            .default_catalog = "pg_orders".to_string();
        register_session_current_database(&ctx_b);
        assert_eq!(current_db(&ctx_b).await, "pg_orders");

        // Session A is untouched by B — per-session isolation.
        assert_eq!(current_db(&ctx_a).await, "pg");
    }

    ///: a server with no federated SQL source must serve sessions
    /// from the *plain* context so DataFusion's physical `FilterPushdown`
    /// rule survives — that rule is what pushes predicates into the
    /// parquet scan (scan-time row filter + page/row-group pruning). The
    /// federated context strips it for a federation-correctness workaround;
    /// a local-only (Iceberg / object-storage / parquet) server has no
    /// `VirtualExecutionPlan` to protect, so the strip is pure loss.
    #[test]
    fn local_only_server_keeps_filter_pushdown() {
        use crate::config::{CatalogConfig, ObjectStorageCatalogConfig};
        let config = ServerConfig {
            catalogs: HashMap::from([(
                "lake".to_string(),
                CatalogConfig::ObjectStorage(ObjectStorageCatalogConfig {
                    s3: None,
                    tables: vec![],
                }),
            )]),
            ..ServerConfig::default()
        };
        let server =
            DataglotServer::new_with_catalogs(config, HashMap::new(), Arc::new(NoopPolicyEnforcer))
                .unwrap();
        assert!(!server.needs_federation());
        let ctx = server.create_session();
        let state = ctx.state();
        let names: Vec<&str> = state
            .physical_optimizers()
            .iter()
            .map(|r| r.name())
            .collect();
        assert!(
            names.contains(&"FilterPushdown"),
            "local-only server must retain FilterPushdown, got {names:?}"
        );
    }

    /// The mirror of the above: a server with a federated SQL source uses
    /// the federated context, which (since 's mixed-server fix) now
    /// *keeps* `FilterPushdown` for scan-time parquet pushdown and instead
    /// installs the `WrapFederationNodes` guard for cross-source
    /// correctness. So even a federation server gets parquet pushdown.
    #[test]
    fn federated_server_keeps_filter_pushdown_behind_guard() {
        use crate::config::{CatalogConfig, PostgresCatalogConfig};
        let config = ServerConfig {
            catalogs: HashMap::from([(
                "pg".to_string(),
                CatalogConfig::Postgres(PostgresCatalogConfig {
                    dsn: Some("postgres://h/db".into()),
                    dsn_env: None,
                    ..Default::default()
                }),
            )]),
            ..ServerConfig::default()
        };
        let server =
            DataglotServer::new_with_catalogs(config, HashMap::new(), Arc::new(NoopPolicyEnforcer))
                .unwrap();
        assert!(server.needs_federation());
        let ctx = server.create_session();
        let state = ctx.state();
        let names: Vec<&str> = state
            .physical_optimizers()
            .iter()
            .map(|r| r.name())
            .collect();
        assert!(
            names.contains(&"FilterPushdown"),
            "federated server must retain FilterPushdown (mixed pushdown): {names:?}"
        );
        assert!(
            names.contains(&"WrapFederationNodes"),
            "federated server must install the WrapFederationNodes guard: {names:?}"
        );
    }

    // ---- execution_mode_label ( badge source) ----

    #[test]
    fn execution_mode_label_reflects_ballista_config() {
        assert_eq!(execution_mode_label(None), "single-node");
        let cfg = crate::config::BallistaServerConfig {
            standalone_parallelism: 8,
            ..Default::default()
        };
        assert_eq!(
            execution_mode_label(Some(&cfg)),
            "distributed (parallelism 8)"
        );
    }

    // ---- connection_default_catalog (#454 per-connection \c <db>) ----

    #[test]
    fn connection_default_catalog_applies_a_registered_db() {
        // `database` names a registered catalog → set it as the default.
        let registered = |c: &str| c == "pg" || c == "tpch";
        assert_eq!(
            connection_default_catalog(Some("pg"), registered),
            ConnectionDefaultCatalog::Apply("pg".to_string())
        );
        assert_eq!(
            connection_default_catalog(Some("tpch"), registered),
            ConnectionDefaultCatalog::Apply("tpch".to_string())
        );
    }

    #[test]
    fn connection_default_catalog_flags_an_unregistered_db() {
        // Provided but not a catalog → keep server default + warn (carries
        // the name so the warn is actionable).
        assert_eq!(
            connection_default_catalog(Some("typo"), |c| c == "pg"),
            ConnectionDefaultCatalog::UnknownCatalog("typo".to_string())
        );
    }

    #[test]
    fn connection_default_catalog_keeps_default_when_absent() {
        // No database param → keep the server's configured default.
        assert_eq!(
            connection_default_catalog(None, |_| true),
            ConnectionDefaultCatalog::Keep
        );
    }

    /// `create_session` registers every configured catalog under the
    /// configured name. Bypasses [`build_connectors_with`] (which would need
    /// real network IO) by plumbing pre-built `Arc<dyn CatalogProvider>`s
    /// directly via the test-only constructor.
    #[tokio::test]
    async fn create_session_registers_configured_catalogs() {
        let mut catalogs: HashMap<String, Arc<dyn DfCatalogProvider>> = HashMap::new();
        catalogs.insert(
            "pg_users".to_string(),
            Arc::new(FakeCatalog {
                schemas: vec!["public".to_string()],
            }),
        );
        catalogs.insert(
            "warehouse".to_string(),
            Arc::new(FakeCatalog {
                schemas: vec!["sales".to_string(), "marketing".to_string()],
            }),
        );

        let server = DataglotServer::new_with_catalogs(
            ServerConfig::default(),
            catalogs,
            Arc::new(NoopPolicyEnforcer),
        )
        .unwrap();
        let ctx = server.create_session();

        let names = ctx.catalog_names();
        assert!(
            names.contains(&"pg_users".to_string()),
            "missing pg_users in {names:?}"
        );
        assert!(
            names.contains(&"warehouse".to_string()),
            "missing warehouse in {names:?}"
        );

        // Round-trip through the registered catalog: `pg_users`
        // schema_names must come back as we registered them, plus the
        // `pg_catalog` overlay every catalog gets via 's
        // `PgCatalogOverlayProvider` wrapper at `create_session` time.
        let pg = ctx
            .catalog("pg_users")
            .expect("pg_users catalog resolves by name");
        let mut pg_schemas = pg.schema_names();
        pg_schemas.sort();
        assert_eq!(
            pg_schemas,
            vec!["pg_catalog".to_string(), "public".to_string()]
        );

        let wh = ctx
            .catalog("warehouse")
            .expect("warehouse catalog resolves by name");
        let mut wh_schemas = wh.schema_names();
        wh_schemas.sort();
        assert_eq!(
            wh_schemas,
            vec![
                "marketing".to_string(),
                "pg_catalog".to_string(),
                "sales".to_string(),
            ]
        );
    }

    /// CR1 — `pg_database` (the flat half, what `\l` reads)
    /// must enumerate only the configured federated catalogs, never the
    /// placeholder default catalog that `with_default_catalog_and_schema`
    /// creates at session boot.
    ///
    /// Regression guard: `ServerConfig::default().default_catalog` is
    /// `"dataglot"`, which is NOT among the catalogs configured here.
    /// Before the fix, `create_session` fed the session's live
    /// `catalog_list()` (still holding that empty `"dataglot"`
    /// placeholder) into the flat half, so `\l` advertised a phantom
    /// `dataglot` database. Building the flat list from `self.catalogs`
    /// lists only real catalogs and is independent of registration order.
    #[tokio::test]
    async fn create_session_pg_database_excludes_placeholder_default_catalog() {
        use datafusion::arrow::array::Array;

        let mut catalogs: HashMap<String, Arc<dyn DfCatalogProvider>> = HashMap::new();
        catalogs.insert(
            "pg_users".to_string(),
            Arc::new(FakeCatalog {
                schemas: vec!["public".to_string()],
            }),
        );
        catalogs.insert(
            "warehouse".to_string(),
            Arc::new(FakeCatalog {
                schemas: vec!["sales".to_string()],
            }),
        );

        // The leak-vector name must not be one of our catalogs, or the
        // test couldn't distinguish a leak from a legitimate entry.
        let config = ServerConfig::default();
        assert_eq!(config.default_catalog, "dataglot");
        assert!(
            !catalogs.contains_key(&config.default_catalog),
            "test precondition: default_catalog must not be a configured catalog"
        );

        let server =
            DataglotServer::new_with_catalogs(config, catalogs, Arc::new(NoopPolicyEnforcer))
                .unwrap();
        let ctx = server.create_session();

        let df = ctx
            .sql("SELECT datname FROM pg_users.pg_catalog.pg_database ORDER BY datname")
            .await
            .expect("pg_database query must plan");
        let batches = df.collect().await.expect("pg_database query must execute");

        let mut datnames: Vec<String> = Vec::new();
        for batch in &batches {
            let col = batch
                .column(0)
                .as_any()
                .downcast_ref::<datafusion::arrow::array::StringArray>()
                .expect("datname is a String column");
            for i in 0..col.len() {
                if !col.is_null(i) {
                    datnames.push(col.value(i).to_string());
                }
            }
        }

        assert!(
            datnames.contains(&"pg_users".to_string())
                && datnames.contains(&"warehouse".to_string()),
            "pg_database must list the configured catalogs; got {datnames:?}"
        );
        assert!(
            !datnames.contains(&"dataglot".to_string()),
            "pg_database leaked the placeholder default catalog 'dataglot' — the flat \
             list was built from the live session list, not self.catalogs. Got {datnames:?}"
        );
    }

    /// Slice B (per-org since M2): when a live registry is installed,
    /// `current_catalogs` (the boot org's set, used by every new session) reads
    /// its current snapshot instead of the static boot map, and a swap of that
    /// org's entry is reflected on the next read — the mechanism by which a new
    /// connection sees an out-of-band store change. `current_catalogs_for_org`
    /// isolates orgs: a different org reads only its own entry (empty if none).
    #[tokio::test]
    async fn current_catalogs_reads_live_registry_and_reflects_swaps() {
        let mut static_map: HashMap<String, Arc<dyn DfCatalogProvider>> = HashMap::new();
        static_map.insert(
            "boot_cat".to_string(),
            Arc::new(FakeCatalog { schemas: vec![] }),
        );
        let mut server = DataglotServer::new_with_catalogs(
            ServerConfig::default(),
            static_map,
            Arc::new(NoopPolicyEnforcer),
        )
        .unwrap();
        // `new_with_catalogs` boots under the "default" org.
        assert_eq!(server.boot_org, "default");

        // No live registry → the static boot map is authoritative.
        assert!(server.current_catalogs().contains_key("boot_cat"));

        // Install a live registry: the boot org holds `live_a`, and a separate
        // org "acme" holds its own catalog.
        let mut snap_default: CatalogSnapshot = HashMap::new();
        snap_default.insert(
            "live_a".to_string(),
            Arc::new(FakeCatalog { schemas: vec![] }),
        );
        let mut snap_acme: CatalogSnapshot = HashMap::new();
        snap_acme.insert(
            "acme_cat".to_string(),
            Arc::new(FakeCatalog { schemas: vec![] }),
        );
        let registry: LiveCatalogRegistry = Arc::new(std::sync::RwLock::new(HashMap::from([
            ("default".to_string(), Arc::new(snap_default)),
            ("acme".to_string(), Arc::new(snap_acme)),
        ])));
        server.live_catalogs = Some(Arc::clone(&registry));

        // Boot org reads its own snapshot; the static map is bypassed.
        let cur = server.current_catalogs();
        assert!(cur.contains_key("live_a"), "live snapshot is read");
        assert!(!cur.contains_key("boot_cat"), "static map is bypassed");

        // Org isolation: "acme" reads only its entry; an unknown org is empty.
        assert!(server
            .current_catalogs_for_org("acme")
            .contains_key("acme_cat"));
        assert!(!server
            .current_catalogs_for_org("acme")
            .contains_key("live_a"));
        assert!(server.current_catalogs_for_org("ghost").is_empty());

        // Swap only the boot org's entry as the refresh task would.
        let mut snap_b: CatalogSnapshot = HashMap::new();
        snap_b.insert(
            "live_b".to_string(),
            Arc::new(FakeCatalog { schemas: vec![] }),
        );
        registry
            .write()
            .unwrap()
            .insert("default".to_string(), Arc::new(snap_b));

        let cur = server.current_catalogs();
        assert!(
            cur.contains_key("live_b"),
            "swap reflected on the next read"
        );
        assert!(!cur.contains_key("live_a"), "old snapshot no longer served");
        // "acme" untouched by the boot-org swap.
        assert!(server
            .current_catalogs_for_org("acme")
            .contains_key("acme_cat"));
    }

    /// Each `create_session` call returns an independent
    /// `SessionContext`, but they share the same `Arc<dyn CatalogProvider>`
    /// via `register_catalog`. Pins that the catalog cache built at
    /// boot is in fact reused across pgwire connections.
    #[tokio::test]
    async fn create_session_shares_catalog_across_sessions() {
        let mut catalogs: HashMap<String, Arc<dyn DfCatalogProvider>> = HashMap::new();
        catalogs.insert(
            "pg_users".to_string(),
            Arc::new(FakeCatalog {
                schemas: vec!["public".to_string()],
            }),
        );
        let server = DataglotServer::new_with_catalogs(
            ServerConfig::default(),
            catalogs,
            Arc::new(NoopPolicyEnforcer),
        )
        .unwrap();

        let ctx1 = server.create_session();
        let ctx2 = server.create_session();
        assert!(ctx1.catalog_names().contains(&"pg_users".to_string()));
        assert!(ctx2.catalog_names().contains(&"pg_users".to_string()));
    }

    #[tokio::test]
    async fn test_session_creation() {
        let config = ServerConfig::default();
        let server = DataglotServer::new(config).await.unwrap();
        let _ctx = server.create_session();
        // Session was created successfully
    }

    /// End-to-end pinned: a `DataglotServer` configured with a real
    /// `ColumnMaskingEnforcer` rewrites `SELECT email FROM users` so
    /// the projected column comes back as the masking literal, not
    /// the raw `users.email` value. Goes through the full
    /// server-built `SessionContext` rather than constructing one
    /// in-line as `dataglot-policy`'s own tests do — the
    /// `create_session` integration is what's actually new.
    #[tokio::test]
    async fn create_session_applies_column_masking_enforcer() {
        use datafusion::arrow::array::{Int32Array, StringArray};
        use datafusion::arrow::datatypes::{DataType, Field, Schema};
        use datafusion::arrow::record_batch::RecordBatch;
        use datafusion::common::TableReference;
        use datafusion::datasource::MemTable;
        use datafusion::logical_expr::lit;
        use dataglot_policy::{ColumnMask, ColumnMaskingEnforcer};

        let schema = Arc::new(Schema::new(vec![
            Field::new("id", DataType::Int32, false),
            Field::new("email", DataType::Utf8, false),
        ]));
        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(Int32Array::from(vec![1, 2])),
                Arc::new(StringArray::from(vec![
                    "alice@example.com",
                    "bob@example.com",
                ])),
            ],
        )
        .unwrap();
        let users_table = Arc::new(MemTable::try_new(schema, vec![vec![batch]]).unwrap());

        // Match the planner-emitted column-ref shape (`Bare("users")`)
        // — same convention dataglot-policy tests pinned in #123.
        let users_ref = TableReference::bare("users");
        let mask = ColumnMask {
            table: users_ref,
            column: "email".to_string(),
            mask: lit("***@example.com"),
            org: None,
            groups: None,
        };
        let enforcer = Arc::new(ColumnMaskingEnforcer::new([mask]).expect("build enforcer"));

        let server =
            DataglotServer::new_with_catalogs(ServerConfig::default(), HashMap::new(), enforcer)
                .unwrap();

        let ctx = server.create_session();
        ctx.register_table("users", users_table)
            .expect("register users");

        let df = ctx
            .sql("SELECT email FROM users")
            .await
            .expect("plan SELECT");
        let batches = df.collect().await.expect("collect");

        let mut emails: Vec<String> = Vec::new();
        for batch in &batches {
            let col = batch
                .column(0)
                .as_any()
                .downcast_ref::<datafusion::arrow::array::StringArray>()
                .expect("email column is utf8");
            for i in 0..batch.num_rows() {
                emails.push(col.value(i).to_string());
            }
        }
        assert_eq!(
            emails.len(),
            2,
            "two seeded rows must round-trip through the federated context",
        );
        for email in &emails {
            assert_eq!(
                email, "***@example.com",
                "session-installed PolicyOptimizerRule must mask projected emails",
            );
        }
    }

    /// End-to-end pinned: an operator-style boot where masks come
    /// from `ServerConfig.masks` (the on-disk JSON shape) — not
    /// constructed in-line as the previous test does. Proves the
    /// config → `build_policy_enforcer` → `DataglotServer::new` →
    /// `create_session` path works without any test-only ctor
    /// affordances.
    #[tokio::test]
    async fn server_new_loads_masks_from_config() {
        use crate::config::MaskConfig;
        use datafusion::arrow::array::{Int32Array, StringArray};
        use datafusion::arrow::datatypes::{DataType, Field, Schema};
        use datafusion::arrow::record_batch::RecordBatch;
        use datafusion::datasource::MemTable;

        let schema = Arc::new(Schema::new(vec![
            Field::new("id", DataType::Int32, false),
            Field::new("email", DataType::Utf8, false),
        ]));
        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(Int32Array::from(vec![7])),
                Arc::new(StringArray::from(vec!["dave@example.com"])),
            ],
        )
        .unwrap();
        let users_table = Arc::new(MemTable::try_new(schema, vec![vec![batch]]).unwrap());

        // Config-driven boot: the mask is declared in JSON-equivalent
        // shape, exactly as an operator would write it.
        let config = ServerConfig {
            masks: vec![MaskConfig {
                table: "users".to_string(),
                column: "email".to_string(),
                mask_literal: "***@example.com".to_string(),
                mask_type: None,
                priority: 0,
                mask_expr: None,
                groups: None,
            }],
            ..ServerConfig::default()
        };

        // `Self::new` routes through `build_policy_enforcer` and
        // `build_connectors`. The latter returns an empty map for
        // `config.catalogs`, so the only async work is the metric
        // registration — no real network IO.
        let server = DataglotServer::new(config).await.unwrap();

        let ctx = server.create_session();
        ctx.register_table("users", users_table)
            .expect("register users");

        let df = ctx
            .sql("SELECT email FROM users")
            .await
            .expect("plan SELECT");
        let batches = df.collect().await.expect("collect");

        let mut emails: Vec<String> = Vec::new();
        for batch in &batches {
            let col = batch
                .column(0)
                .as_any()
                .downcast_ref::<datafusion::arrow::array::StringArray>()
                .expect("email column is utf8");
            for i in 0..batch.num_rows() {
                emails.push(col.value(i).to_string());
            }
        }
        assert_eq!(emails.len(), 1);
        assert_eq!(
            emails[0], "***@example.com",
            "config-loaded mask must fire on every session",
        );
    }

    /// End-to-end pinned: an operator-style boot with **both** a
    /// `masks` block and a `row_filters` block in the on-disk
    /// JSON config. Goes through the full
    /// `build_policy_enforcer` → `CompositeEnforcer` →
    /// `create_session` path. Asserts:
    ///
    /// 1. The row filter sees un-masked column values (only rows
    ///    where `id > 1` survive — predicate evaluated on the real
    ///    underlying column, not on the mask literal).
    /// 2. The column mask still fires on the surviving rows.
    ///
    /// This is the operator-config-driven counterpart to
    /// `dataglot-policy::filter::tests::row_filter_predicate_sees_unmasked_values_even_with_column_mask`.
    #[tokio::test]
    async fn server_new_composes_masks_and_row_filters_from_config() {
        use crate::config::{MaskConfig, RowFilterConfig, RowPredicateConfig};
        use datafusion::arrow::array::{Int32Array, StringArray};
        use datafusion::arrow::datatypes::{DataType, Field, Schema};
        use datafusion::arrow::record_batch::RecordBatch;
        use datafusion::datasource::MemTable;

        let schema = Arc::new(Schema::new(vec![
            Field::new("id", DataType::Int32, false),
            Field::new("email", DataType::Utf8, false),
        ]));
        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(Int32Array::from(vec![1, 2, 3])),
                Arc::new(StringArray::from(vec![
                    "alice@example.com",
                    "bob@example.com",
                    "carol@example.com",
                ])),
            ],
        )
        .unwrap();
        let users_table = Arc::new(MemTable::try_new(schema, vec![vec![batch]]).unwrap());

        let config = ServerConfig {
            masks: vec![MaskConfig {
                table: "users".to_string(),
                column: "email".to_string(),
                mask_literal: "***@example.com".to_string(),
                mask_type: None,
                priority: 0,
                mask_expr: None,
                groups: None,
            }],
            row_filters: vec![RowFilterConfig {
                table: "users".to_string(),
                predicate: RowPredicateConfig::GtInt {
                    column: "id".to_string(),
                    value: 1,
                },
                groups: None,
            }],
            ..ServerConfig::default()
        };
        let server = DataglotServer::new(config).await.unwrap();

        let ctx = server.create_session();
        ctx.register_table("users", users_table)
            .expect("register users");

        let df = ctx
            .sql("SELECT id, email FROM users ORDER BY id")
            .await
            .expect("plan SELECT");
        let batches = df.collect().await.expect("collect");

        let mut rows: Vec<(i32, String)> = Vec::new();
        for batch in &batches {
            let id_col = batch
                .column(0)
                .as_any()
                .downcast_ref::<datafusion::arrow::array::Int32Array>()
                .expect("id col is int32");
            let email_col = batch
                .column(1)
                .as_any()
                .downcast_ref::<datafusion::arrow::array::StringArray>()
                .expect("email col is utf8");
            for i in 0..batch.num_rows() {
                rows.push((id_col.value(i), email_col.value(i).to_string()));
            }
        }

        // Row filter (id > 1) drops alice (id=1). Mask replaces
        // every projected email.
        assert_eq!(rows.len(), 2, "row filter must drop alice; got: {rows:?}");
        assert_eq!(rows[0].0, 2);
        assert_eq!(rows[1].0, 3);
        for (_, email) in &rows {
            assert_eq!(
                email, "***@example.com",
                "config-loaded mask must fire on every session",
            );
        }
    }

    #[tokio::test]
    async fn test_session_executes_query() {
        let config = ServerConfig::default();
        let server = DataglotServer::new(config).await.unwrap();
        let ctx = server.create_session();

        let result = ctx.sql("SELECT 1 + 1 as result").await;
        assert!(result.is_ok());
    }

    /// End-to-end pinned: an operator-style boot with a row
    /// filter declared via the `Sql` predicate variant — the SQL
    /// fragment goes through boot-time parsing, lands in the
    /// `RowFilterEnforcer` as a regular `Expr`, and fires on real
    /// queries with column references resolved at plan time.
    ///
    /// The fragment uses Utf8-on-Utf8 comparisons throughout
    /// (`email LIKE 'alice%' AND email LIKE '%@example.com'`) —
    /// the documented "no type-coercion across widths" caveat
    /// means SQL-fragment integer comparisons need a CAST or the
    /// declarative `gt_int` / `eq_int` variants. That limitation
    /// is pinned by `server_new_sql_predicate_int_compare_needs_cast`
    /// below.
    ///
    /// Setup:
    ///   - row filter: `email LIKE 'alice%' AND email LIKE '%@example.com'`
    ///   - query:      `SELECT id, email FROM users ORDER BY id`
    ///
    /// Expected: 1 row (Alice). Both LIKE arms match her;
    /// Bob/Carol fail the first.
    #[tokio::test]
    async fn server_new_supports_sql_predicate_row_filter() {
        use crate::config::{RowFilterConfig, RowPredicateConfig};
        use datafusion::arrow::array::{Int32Array, StringArray};
        use datafusion::arrow::datatypes::{DataType, Field, Schema};
        use datafusion::arrow::record_batch::RecordBatch;
        use datafusion::datasource::MemTable;

        let schema = Arc::new(Schema::new(vec![
            Field::new("id", DataType::Int32, false),
            Field::new("email", DataType::Utf8, false),
        ]));
        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(Int32Array::from(vec![1, 2, 3])),
                Arc::new(StringArray::from(vec![
                    "alice@example.com",
                    "bob@example.com",
                    "carol@example.com",
                ])),
            ],
        )
        .unwrap();
        let users_table = Arc::new(MemTable::try_new(schema, vec![vec![batch]]).unwrap());

        let config = ServerConfig {
            row_filters: vec![RowFilterConfig {
                table: "users".to_string(),
                predicate: RowPredicateConfig::Sql {
                    sql: "email LIKE 'alice%' AND email LIKE '%@example.com'".to_string(),
                },
                groups: None,
            }],
            ..ServerConfig::default()
        };
        let server = DataglotServer::new(config).await.unwrap();

        let ctx = server.create_session();
        ctx.register_table("users", users_table)
            .expect("register users");

        let df = ctx
            .sql("SELECT id, email FROM users ORDER BY id")
            .await
            .expect("plan SELECT");
        let batches = df.collect().await.expect("collect");

        let total: usize = batches
            .iter()
            .map(datafusion::arrow::array::RecordBatch::num_rows)
            .sum();
        assert_eq!(
            total, 1,
            "AND of two Utf8 LIKE comparisons matches Alice only",
        );
    }

    /// Pin the documented caveat: a SQL fragment comparing an
    /// `Int32` column to an integer literal will fail at query
    /// time because the synthetic-schema parser declares the
    /// column `Utf8` and `DataFusion`'s `TypeCoercion` doesn't
    /// auto-cast across `Utf8 → Int*`. Operators get a clear
    /// runtime error and the workarounds (declarative `gt_int` /
    /// `eq_int`, or explicit `CAST(id AS BIGINT)`) are
    /// documented on `RowPredicateConfig::Sql`.
    ///
    /// This test exists so the limitation can't silently slip
    /// (e.g. if a future `DataFusion` update relaxes the coercion
    /// rule, this test will start failing and we update the docs).
    #[tokio::test]
    async fn server_new_sql_predicate_int_compare_needs_cast() {
        use crate::config::{RowFilterConfig, RowPredicateConfig};
        use datafusion::arrow::array::{Int32Array, StringArray};
        use datafusion::arrow::datatypes::{DataType, Field, Schema};
        use datafusion::arrow::record_batch::RecordBatch;
        use datafusion::datasource::MemTable;

        let schema = Arc::new(Schema::new(vec![
            Field::new("id", DataType::Int32, false),
            Field::new("email", DataType::Utf8, false),
        ]));
        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(Int32Array::from(vec![1, 2, 3])),
                Arc::new(StringArray::from(vec![
                    "alice@example.com",
                    "bob@example.com",
                    "carol@example.com",
                ])),
            ],
        )
        .unwrap();
        let users_table = Arc::new(MemTable::try_new(schema, vec![vec![batch]]).unwrap());

        let config = ServerConfig {
            row_filters: vec![RowFilterConfig {
                table: "users".to_string(),
                predicate: RowPredicateConfig::Sql {
                    sql: "id > 1".to_string(),
                },
                groups: None,
            }],
            ..ServerConfig::default()
        };
        // Boot succeeds — SQL parses fine.
        let server = DataglotServer::new(config).await.unwrap();
        let ctx = server.create_session();
        ctx.register_table("users", users_table)
            .expect("register users");

        // ...but query-time coercion fails because the synthetic
        // schema typed `id` as Utf8 and the literal as Int64.
        let df = ctx
            .sql("SELECT id, email FROM users")
            .await
            .expect("plan SELECT");
        let Err(err) = df.collect().await else {
            panic!(
                "expected the Int32 column vs Int64 literal compare to fail; \
                 if this passed, DataFusion has loosened its coercion rules — \
                 update the doc comment on RowPredicateConfig::Sql",
            );
        };
        let msg = format!("{err:#}").to_lowercase();
        assert!(
            msg.contains("compari") || msg.contains("type") || msg.contains("cast"),
            "expected a coercion-shaped error, got: {err:#}",
        );
    }

    /// Companion to the above: a simpler `Sql` predicate that
    /// matches Bob alone. Pins that the parser handles a single
    /// equality expression and that column resolution against
    /// `Bare("users")` works through the full pipeline.
    #[tokio::test]
    async fn server_new_sql_predicate_matches_one_row() {
        use crate::config::{RowFilterConfig, RowPredicateConfig};
        use datafusion::arrow::array::{Int32Array, StringArray};
        use datafusion::arrow::datatypes::{DataType, Field, Schema};
        use datafusion::arrow::record_batch::RecordBatch;
        use datafusion::datasource::MemTable;

        let schema = Arc::new(Schema::new(vec![
            Field::new("id", DataType::Int32, false),
            Field::new("email", DataType::Utf8, false),
        ]));
        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(Int32Array::from(vec![1, 2, 3])),
                Arc::new(StringArray::from(vec![
                    "alice@example.com",
                    "bob@example.com",
                    "carol@example.com",
                ])),
            ],
        )
        .unwrap();
        let users_table = Arc::new(MemTable::try_new(schema, vec![vec![batch]]).unwrap());

        let config = ServerConfig {
            row_filters: vec![RowFilterConfig {
                table: "users".to_string(),
                predicate: RowPredicateConfig::Sql {
                    sql: "email = 'bob@example.com'".to_string(),
                },
                groups: None,
            }],
            ..ServerConfig::default()
        };
        let server = DataglotServer::new(config).await.unwrap();

        let ctx = server.create_session();
        ctx.register_table("users", users_table)
            .expect("register users");

        let df = ctx
            .sql("SELECT id, email FROM users")
            .await
            .expect("plan SELECT");
        let batches = df.collect().await.expect("collect");
        let total: usize = batches
            .iter()
            .map(datafusion::arrow::array::RecordBatch::num_rows)
            .sum();
        assert_eq!(total, 1, "only Bob's row matches the SQL predicate");
    }

    /// Pin the documented int-coercion workaround:
    /// `CAST(id AS BIGINT) > 1` against an `Int32` column should
    /// succeed end-to-end. The SQL fragment parses at boot
    /// (`collect_identifiers` recurses into the cast operand),
    /// query-time `TypeCoercion` accepts the explicit cast, and
    /// the row-filter fires.
    ///
    /// Without the cast-recursion in `collect_identifiers`, the
    /// inner `id` would be missed, the synthetic schema would
    /// lack the column, and `parse_sql_expr` would fail at boot
    /// with `"No field named id"` — making the documented
    /// workaround actually unusable.
    #[tokio::test]
    async fn server_new_sql_predicate_int_compare_works_with_cast_workaround() {
        use crate::config::{RowFilterConfig, RowPredicateConfig};
        use datafusion::arrow::array::{Int32Array, StringArray};
        use datafusion::arrow::datatypes::{DataType, Field, Schema};
        use datafusion::arrow::record_batch::RecordBatch;
        use datafusion::datasource::MemTable;

        let schema = Arc::new(Schema::new(vec![
            Field::new("id", DataType::Int32, false),
            Field::new("email", DataType::Utf8, false),
        ]));
        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(Int32Array::from(vec![1, 2, 3])),
                Arc::new(StringArray::from(vec![
                    "alice@example.com",
                    "bob@example.com",
                    "carol@example.com",
                ])),
            ],
        )
        .unwrap();
        let users_table = Arc::new(MemTable::try_new(schema, vec![vec![batch]]).unwrap());

        let config = ServerConfig {
            row_filters: vec![RowFilterConfig {
                table: "users".to_string(),
                predicate: RowPredicateConfig::Sql {
                    sql: "CAST(id AS BIGINT) > 1".to_string(),
                },
                groups: None,
            }],
            ..ServerConfig::default()
        };
        let server = DataglotServer::new(config).await.unwrap();
        let ctx = server.create_session();
        ctx.register_table("users", users_table)
            .expect("register users");

        let df = ctx
            .sql("SELECT id FROM users ORDER BY id")
            .await
            .expect("plan SELECT");
        let batches = df.collect().await.expect("collect");

        // Pin the exact rows that survive — `total == 2` would
        // accept any wrong-rows-but-right-count regression. The
        // contract is "drop Alice (id=1), keep Bob (2) and Carol
        // (3)"; the predicate's correctness is in WHICH rows
        // come back, not just how many.
        let mut ids: Vec<i32> = Vec::new();
        for batch in &batches {
            let col = batch
                .column(0)
                .as_any()
                .downcast_ref::<datafusion::arrow::array::Int32Array>()
                .expect("id col is int32");
            for i in 0..batch.num_rows() {
                ids.push(col.value(i));
            }
        }
        assert_eq!(
            ids,
            vec![2, 3],
            "CAST(id AS BIGINT) > 1 must drop only Alice (id=1); \
             ORDER BY id pins the surviving rows as Bob (2) and Carol (3)",
        );
    }

    /// Pin: a malformed SQL fragment produces a clear error at
    /// boot (during `DataglotServer::new`) rather than silently
    /// accepting a broken rule and surfacing a planner error at
    /// query time.
    #[tokio::test]
    async fn server_new_fails_fast_on_invalid_sql_predicate() {
        use crate::config::{RowFilterConfig, RowPredicateConfig};

        let config = ServerConfig {
            row_filters: vec![RowFilterConfig {
                table: "users".to_string(),
                predicate: RowPredicateConfig::Sql {
                    sql: "definitely not a sql expression !!!".to_string(),
                },
                groups: None,
            }],
            ..ServerConfig::default()
        };
        // `DataglotServer` doesn't implement Debug (and shouldn't
        // — its internals carry credential bytes per CLAUDE.md
        // rule 12), so `unwrap_err` won't compile. let-else
        // instead.
        let Err(err) = DataglotServer::new(config).await else {
            panic!("expected `DataglotServer::new` to fail on invalid SQL predicate");
        };
        let msg = format!("{err:#}").to_lowercase();
        assert!(
            msg.contains("parse") || msg.contains("sql"),
            "error must surface the parse failure; got: {err:#}",
        );
    }

    #[tokio::test]
    async fn test_metrics_handle_is_available() {
        let config = ServerConfig::default();
        let server = DataglotServer::new(config).await.unwrap();
        // Baseline metric must be registered and starting at zero.
        assert_eq!(server.metrics().pgwire_connections_active.get(), 0);
    }

    #[tokio::test]
    async fn test_connection_guard_increments_and_decrements() {
        let config = ServerConfig::default();
        let server = DataglotServer::new(config).await.unwrap();
        assert_eq!(server.metrics().pgwire_connections_active.get(), 0);
        {
            let _guard = ConnectionGuard::new(server.metrics());
            assert_eq!(server.metrics().pgwire_connections_active.get(), 1);
        }
        assert_eq!(server.metrics().pgwire_connections_active.get(), 0);
    }

    /// `MetricsObserver` bumps `queries_total{outcome=...}` and records
    /// a sample in `query_duration_seconds{protocol="pgwire"}` per call.
    /// Two success + one error => `success=2, error=1, histogram_count=3`.
    #[tokio::test]
    async fn metrics_observer_increments_counters() {
        use dataglot_core::lineage::RunId;
        use dataglot_pgwire::{QueryObserver, QueryOutcome};
        use std::time::Duration;

        let metrics = crate::observability::Metrics::new().unwrap();
        let observer = MetricsObserver::new(metrics.clone());

        let id = RunId::new();
        observer.on_query_complete(
            id,
            "SELECT 1",
            None,
            QueryOutcome::Success,
            Duration::from_millis(5),
        );
        observer.on_query_complete(
            id,
            "SELECT 1",
            None,
            QueryOutcome::Success,
            Duration::from_millis(7),
        );
        observer.on_query_complete(
            id,
            "SELECT bad",
            None,
            QueryOutcome::Error,
            Duration::from_millis(1),
        );

        assert_eq!(
            metrics
                .queries_total
                .with_label_values(&["pgwire", "success"])
                .get(),
            2
        );
        assert_eq!(
            metrics
                .queries_total
                .with_label_values(&["pgwire", "error"])
                .get(),
            1
        );
        let hist = metrics
            .query_duration_seconds
            .with_label_values(&["pgwire"]);
        assert_eq!(hist.get_sample_count(), 3);
    }

    // ------------------------------------------------------------------
    // Phase 2 spec 02 slice 3a — Ballista boot + dispatch tests.
    //
    // Gated on the `ballista` feature so default `cargo test` runs
    // (which skip dataglot-ballista per the workspace `default-members`
    // exclusion) don't try to compile this section. The `ballista`
    // CI job picks them up.
    // ------------------------------------------------------------------

    #[cfg(feature = "ballista")]
    mod ballista_integration {
        use super::*;
        use crate::config::BallistaServerConfig;

        /// With `ballista = Some(...)` and the feature on, server
        /// boot succeeds and `create_session()` returns a context
        /// whose query planner is Ballista's, not single-node's.
        #[tokio::test]
        async fn server_with_ballista_config_creates_ballista_session() {
            let config = ServerConfig {
                ballista: Some(BallistaServerConfig {
                    standalone_parallelism: 2,
                    // No REST API in this test: a fixed default port
                    // would collide with a locally running distributed
                    // demo (or a parallel test) and the WARN-and-continue
                    // path isn't what's under test here.
                    rest_api_port: None,
                    ..Default::default()
                }),
                ..ServerConfig::default()
            };
            let server = DataglotServer::new(config)
                .await
                .expect("server boots with ballista config");
            let ctx = server.create_session();
            let planner = format!("{:?}", ctx.state().query_planner().clone());
            assert!(
                planner.contains("BallistaQueryPlanner"),
                "expected Ballista-routed session, got planner: {planner}"
            );
        }

        /// Smoke: a Ballista-routed session runs a literal SELECT
        /// end-to-end. Proves dispatch works through the cluster.
        #[tokio::test]
        async fn ballista_session_runs_literal_select() {
            let config = ServerConfig {
                ballista: Some(BallistaServerConfig::default()),
                ..ServerConfig::default()
            };
            let server = DataglotServer::new(config)
                .await
                .expect("server boots with ballista config");
            let ctx = server.create_session();
            let batches = ctx
                .sql("SELECT 1 + 1 AS two")
                .await
                .expect("plan SELECT")
                .collect()
                .await
                .expect("execute SELECT");
            let total: usize = batches
                .iter()
                .map(datafusion::arrow::array::RecordBatch::num_rows)
                .sum();
            assert_eq!(total, 1);
        }

        /// Without `ballista = ...` in the config, the server falls
        /// back to single-node even when the feature is compiled in.
        /// Pins the opt-in shape — operators don't pay for Ballista
        /// just because the binary supports it.
        #[tokio::test]
        async fn server_without_ballista_config_uses_single_node() {
            let config = ServerConfig::default();
            let server = DataglotServer::new(config)
                .await
                .expect("server boots without ballista config");
            let ctx = server.create_session();
            let planner = format!("{:?}", ctx.state().query_planner().clone());
            assert!(
                !planner.contains("BallistaQueryPlanner"),
                "expected single-node session when no ballista config, got: {planner}"
            );
        }
    }

    // ------------------------------------------------------------------
    // Slice 3a — feature-off behaviour: `ballista = Some(...)` config
    // with the feature OFF must fail at boot, not silently fall back.
    // ------------------------------------------------------------------

    #[cfg(not(feature = "ballista"))]
    #[tokio::test]
    async fn ballista_config_without_feature_fails_boot() {
        let config = ServerConfig {
            ballista: Some(crate::config::BallistaServerConfig {
                standalone_parallelism: 2,
                ..Default::default()
            }),
            ..ServerConfig::default()
        };
        // `DataglotServer` doesn't implement `Debug` (holds internal
        // task handles), so we match on the Result manually rather
        // than `.expect_err(..)` which requires `T: Debug`.
        match DataglotServer::new(config).await {
            Ok(_) => panic!("expected boot to fail when ballista feature is off"),
            Err(err) => {
                let msg = format!("{err:?}");
                assert!(
                    msg.contains("--features ballista"),
                    "expected helpful error pointing at the feature flag, got: {msg}"
                );
            }
        }
    }

    ///  4b: `build_lineage_graph` plans each derived product's SQL
    /// against the registered catalogs and records its column lineage, so
    /// a mask on a source column can later propagate to the product. Here
    /// the derived product `v` is `SELECT email FROM users`; the graph must
    /// then show `v.email` descending from the source `users.email`.
    #[tokio::test]
    async fn build_lineage_graph_records_derived_product_lineage() {
        use datafusion::arrow::array::{RecordBatch, StringArray};
        use datafusion::arrow::datatypes::{DataType, Field, Schema};
        use datafusion::catalog::{MemoryCatalogProvider, MemorySchemaProvider};
        use datafusion::datasource::MemTable;
        use dataglot_core::lineage::{DatasetRef, FieldRef};

        // In-memory `users(email)` registered under the default catalog so
        // the derived product's SQL plans without a live source.
        let schema = Arc::new(Schema::new(vec![Field::new(
            "email",
            DataType::Utf8,
            false,
        )]));
        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![Arc::new(StringArray::from(vec!["a@x.com"]))],
        )
        .unwrap();
        let table = Arc::new(MemTable::try_new(schema, vec![vec![batch]]).unwrap());
        let sp = Arc::new(MemorySchemaProvider::new());
        sp.register_table("users".to_string(), table).unwrap();
        let cp = Arc::new(MemoryCatalogProvider::new());
        cp.register_schema("public", sp).unwrap();
        let catalogs: HashMap<String, Arc<dyn DfCatalogProvider>> =
            HashMap::from([("dataglot".to_string(), cp as Arc<dyn DfCatalogProvider>)]);

        let products = vec![DerivedProductConfig {
            name: "v".to_string(),
            sql: "SELECT email FROM users".to_string(),
            catalog: None,
            schema: None,
            backing: crate::config::MaterializationBacking::default(),
            materialization: None,
        }];
        let factory =
            SessionContextFactory::new(ServerConfig::default().to_session_config()).unwrap();

        let graph =
            build_lineage_graph(&products, &factory, &catalogs, false, "dataglot", "public").await;

        // Robust to how the planner qualifies the bare `users` scan.
        let found = ["dataglot", "datafusion", "default"].iter().any(|cat| {
            let source = FieldRef {
                dataset: DatasetRef {
                    catalog: (*cat).to_string(),
                    schema: "public".to_string(),
                    table: "users".to_string(),
                },
                field: "email".to_string(),
            };
            graph
                .descendants(&source, false)
                .iter()
                .any(|d| d.dataset.table == "v" && d.field == "email")
        });
        assert!(
            found,
            "derived product v.email must descend from users.email in the lineage graph"
        );
    }

    ///  F9: a runtime `CREATE VIEW` (a persisted [`DerivedProductRecord`])
    /// feeds the lineage graph exactly like a config `[[derived_products]]` entry
    /// — the boot path maps the record into a `Live` `DerivedProductConfig` and
    /// runs the SAME `build_lineage_graph`. Reuses the fixture above.
    #[tokio::test]
    async fn persisted_derived_product_record_emits_lineage_like_config() {
        use datafusion::arrow::array::{RecordBatch, StringArray};
        use datafusion::arrow::datatypes::{DataType, Field, Schema};
        use datafusion::catalog::{MemoryCatalogProvider, MemorySchemaProvider};
        use datafusion::datasource::MemTable;
        use dataglot_catalog::DerivedProductRecord;
        use dataglot_core::lineage::{DatasetRef, FieldRef};

        let schema = Arc::new(Schema::new(vec![Field::new(
            "email",
            DataType::Utf8,
            false,
        )]));
        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![Arc::new(StringArray::from(vec!["a@x.com"]))],
        )
        .unwrap();
        let table = Arc::new(MemTable::try_new(schema, vec![vec![batch]]).unwrap());
        let sp = Arc::new(MemorySchemaProvider::new());
        sp.register_table("users".to_string(), table).unwrap();
        let cp = Arc::new(MemoryCatalogProvider::new());
        cp.register_schema("public", sp).unwrap();
        let catalogs: HashMap<String, Arc<dyn DfCatalogProvider>> =
            HashMap::from([("dataglot".to_string(), cp as Arc<dyn DfCatalogProvider>)]);

        // Start from a store record (what `CREATE VIEW` persists) and apply the
        // exact boot-merge conversion into a `Live` config product.
        let record = DerivedProductRecord {
            name: "v".to_string(),
            sql: "SELECT email FROM users".to_string(),
            catalog: None,
            schema: None,
        };
        let products = vec![DerivedProductConfig {
            name: record.name.clone(),
            sql: record.sql.clone(),
            catalog: record.catalog.clone(),
            schema: record.schema.clone(),
            backing: MaterializationBacking::Live,
            materialization: None,
        }];
        let factory =
            SessionContextFactory::new(ServerConfig::default().to_session_config()).unwrap();
        let graph =
            build_lineage_graph(&products, &factory, &catalogs, false, "dataglot", "public").await;

        let found = ["dataglot", "datafusion", "default"].iter().any(|cat| {
            let source = FieldRef {
                dataset: DatasetRef {
                    catalog: (*cat).to_string(),
                    schema: "public".to_string(),
                    table: "users".to_string(),
                },
                field: "email".to_string(),
            };
            graph
                .descendants(&source, false)
                .iter()
                .any(|d| d.dataset.table == "v" && d.field == "email")
        });
        assert!(
            found,
            "a persisted CREATE VIEW must emit lineage identical to a config derived product"
        );
    }

    ///  closed loop (exit criterion, in-process): a mask configured
    /// on the SOURCE column `users.email` must mask the DERIVED product
    /// `v.email` — which is never masked directly — purely via lineage
    /// propagation. `v` is a separate (materialized) table, so the query
    /// doesn't inline back to `users`; only propagation can mask it.
    /// Uses the real boot helpers (`build_lineage_graph` +
    /// `build_rule_store_with_lineage`) so the whole chain is exercised:
    /// plan product → column lineage → propagate mask → session-default
    /// upgrade-match → enforce on the derived-product query.
    #[tokio::test]
    async fn closed_loop_source_mask_propagates_to_derived_product() {
        use crate::config::build_rule_store_with_lineage;
        use crate::config::{DerivedProductConfig, MaskConfig};
        use datafusion::arrow::array::{RecordBatch, StringArray};
        use datafusion::arrow::datatypes::{DataType, Field, Schema};
        use datafusion::catalog::{MemoryCatalogProvider, MemorySchemaProvider};
        use datafusion::datasource::MemTable;

        fn email_table(val: &str) -> Arc<MemTable> {
            let schema = Arc::new(Schema::new(vec![Field::new(
                "email",
                DataType::Utf8,
                false,
            )]));
            let batch = RecordBatch::try_new(
                schema.clone(),
                vec![Arc::new(StringArray::from(vec![val.to_string()]))],
            )
            .unwrap();
            Arc::new(MemTable::try_new(schema, vec![vec![batch]]).unwrap())
        }

        // `users` (source) and `v` (materialized derived product) are
        // SEPARATE tables — `SELECT email FROM v` never touches `users`.
        let sp = Arc::new(MemorySchemaProvider::new());
        sp.register_table("users".to_string(), email_table("real@x.com"))
            .unwrap();
        sp.register_table("v".to_string(), email_table("real@x.com"))
            .unwrap();
        let cp = Arc::new(MemoryCatalogProvider::new());
        cp.register_schema("public", sp).unwrap();
        let catalogs: HashMap<String, Arc<dyn DfCatalogProvider>> =
            HashMap::from([("dataglot".to_string(), cp as Arc<dyn DfCatalogProvider>)]);

        let products = vec![DerivedProductConfig {
            name: "v".to_string(),
            sql: "SELECT email FROM users".to_string(),
            catalog: None,
            schema: None,
            backing: crate::config::MaterializationBacking::default(),
            materialization: None,
        }];
        let masks = vec![MaskConfig {
            table: "users".to_string(),
            column: "email".to_string(),
            mask_literal: "***@example.com".to_string(),
            mask_type: None,
            priority: 0,
            mask_expr: None,
            groups: None,
        }];
        let config = ServerConfig {
            masks: masks.clone(),
            derived_products: products.clone(),
            ..ServerConfig::default()
        };

        // Real boot wiring: graph from the product, then propagate the
        // source mask + set session defaults.
        let factory = SessionContextFactory::new(config.to_session_config()).unwrap();
        let graph = build_lineage_graph(
            &products,
            &factory,
            &catalogs,
            false,
            &config.default_catalog,
            &config.default_schema,
        )
        .await;
        let store = build_rule_store_with_lineage(
            &masks,
            &[],
            None,
            &graph,
            Some((
                config.default_catalog.clone(),
                config.default_schema.clone(),
            )),
        )
        .expect("rule store builds");
        let enforcer = store.enforcer();

        let server =
            DataglotServer::new_with_catalogs(config, catalogs, enforcer).expect("server boots");
        let ctx = server.create_session();

        // The derived product — masked ONLY via propagation (no rule on `v`).
        let batches = ctx
            .sql("SELECT email FROM v")
            .await
            .expect("plan SELECT FROM v")
            .collect()
            .await
            .expect("collect");
        let col = batches[0]
            .column(0)
            .as_any()
            .downcast_ref::<StringArray>()
            .expect("utf8");
        assert_eq!(
            col.value(0),
            "***@example.com",
            "derived product v.email must be masked via lineage propagation alone (no rule on v)"
        );
    }

    /// Slice 1 exit criterion: a Flight SQL client connects to the served
    /// listener, runs a `SELECT`, and receives Arrow `RecordBatch`es back
    /// end to end (statement query → ticket → `do_get`). Governance parity
    /// and identity are exercised in later slices; this proves the wire.
    #[cfg(feature = "flight_sql")]
    #[tokio::test]
    async fn flight_sql_executes_select_end_to_end() {
        use arrow_flight::sql::client::FlightSqlServiceClient;
        use datafusion::arrow::record_batch::RecordBatch;
        use futures::TryStreamExt;

        // A minimal server is enough — `SELECT 1` needs no catalogs.
        let server = Arc::new(
            DataglotServer::new_with_catalogs(
                ServerConfig::default(),
                HashMap::new(),
                Arc::new(NoopPolicyEnforcer),
            )
            .expect("build test server"),
        );

        // Bind an ephemeral port and serve Flight SQL on it.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = crate::flight_sql::serve(Arc::clone(&server), listener).expect("serve");

        // Connect a Flight SQL client and run the query.
        let channel = tonic::transport::Channel::from_shared(format!("http://{addr}"))
            .unwrap()
            .connect()
            .await
            .expect("client connects to Flight SQL listener");
        let mut client = FlightSqlServiceClient::new(channel);

        let info = client
            .execute("SELECT 1 AS n".to_string(), None)
            .await
            .expect("get_flight_info_statement");
        let ticket = info.endpoint[0]
            .ticket
            .clone()
            .expect("endpoint carries a ticket");
        let batches: Vec<_> = client
            .do_get(ticket)
            .await
            .expect("do_get_statement")
            .try_collect()
            .await
            .expect("collect result batches");

        let rows: usize = batches.iter().map(RecordBatch::num_rows).sum();
        assert_eq!(rows, 1, "expected exactly one row from SELECT 1");
        assert_eq!(batches[0].num_columns(), 1, "expected a single column");

        // Drain the server: broadcast shutdown, then join the serve task.
        server.shutdown_tx.send(()).unwrap();
        handle.await.expect("Flight SQL server task joins cleanly");
    }

    // ──  slice 2: identity → policy parity + auth + TLS ────────────

    /// An `Authorization: Basic` header for `user:password`.
    #[cfg(feature = "flight_sql")]
    fn basic_header(user: &str, password: &str) -> String {
        use base64::Engine as _;
        format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}"))
        )
    }

    /// Minimal single-user [`PasswordSource`](dataglot_pgwire::PasswordSource)
    /// for the md5 auth tests.
    #[cfg(feature = "flight_sql")]
    #[derive(Debug)]
    struct OneUser {
        user: String,
        password: String,
    }
    #[cfg(feature = "flight_sql")]
    #[async_trait::async_trait]
    impl dataglot_pgwire::PasswordSource for OneUser {
        async fn password(&self, user: &str) -> Option<String> {
            (user == self.user).then(|| self.password.clone())
        }
    }

    #[cfg(feature = "flight_sql")]
    #[test]
    fn parse_basic_auth_decodes_and_rejects() {
        use base64::Engine as _;
        // A password may itself contain ':' — only the FIRST ':' splits.
        assert_eq!(
            parse_basic_auth(&basic_header("alice", "s3:cret")),
            Some(("alice".to_string(), "s3:cret".to_string())),
        );
        // Wrong scheme, non-base64, and a value with no ':' are all rejected.
        assert!(parse_basic_auth("Bearer token").is_none());
        assert!(parse_basic_auth("Basic !not-base64!").is_none());
        let no_colon = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode("alice")
        );
        assert!(parse_basic_auth(&no_colon).is_none());
    }

    #[cfg(feature = "flight_sql")]
    #[test]
    fn ct_eq_matches_only_equal_bytes() {
        assert!(ct_eq(b"correct-horse", b"correct-horse"));
        assert!(!ct_eq(b"correct-horse", b"correct-hors3"));
        assert!(!ct_eq(b"short", b"longer-value"));
    }

    #[cfg(feature = "flight_sql")]
    #[tokio::test]
    async fn authenticate_flight_trust_honours_username_else_anonymous() {
        let server = DataglotServer::new_with_catalogs(
            ServerConfig::default(),
            HashMap::new(),
            Arc::new(NoopPolicyEnforcer),
        )
        .expect("server");
        // Trust: an asserted Basic username is honoured (no password check).
        match server
            .authenticate_flight(Some(&basic_header("alice", "ignored")))
            .await
        {
            FlightAuth::Ok(id) => assert!(!id.is_anonymous(), "asserted user → named identity"),
            _ => panic!("trust mode must accept an asserted username"),
        }
        // Trust: no header → anonymous (behaviour-neutral default, matches pg-wire).
        match server.authenticate_flight(None).await {
            FlightAuth::Ok(id) => assert!(id.is_anonymous(), "no header → anonymous"),
            _ => panic!("trust with no header → anonymous"),
        }
    }

    #[cfg(feature = "flight_sql")]
    #[tokio::test]
    async fn authenticate_flight_md5_verifies_password() {
        use dataglot_pgwire::AuthMode;
        let mut server = DataglotServer::new_with_catalogs(
            ServerConfig::default(),
            HashMap::new(),
            Arc::new(NoopPolicyEnforcer),
        )
        .expect("server");
        server.auth = AuthMode::Md5(Arc::new(OneUser {
            user: "alice".into(),
            password: "s3cret".into(),
        }));

        // Correct credentials authenticate.
        assert!(
            matches!(
                server
                    .authenticate_flight(Some(&basic_header("alice", "s3cret")))
                    .await,
                FlightAuth::Ok(_)
            ),
            "correct password authenticates"
        );
        // Wrong password, unknown user, and a missing header are all refused —
        // Flight must not be a weaker door than the pg-wire md5 gate.
        assert!(matches!(
            server
                .authenticate_flight(Some(&basic_header("alice", "wrong")))
                .await,
            FlightAuth::Unauthenticated(_)
        ));
        assert!(matches!(
            server
                .authenticate_flight(Some(&basic_header("mallory", "s3cret")))
                .await,
            FlightAuth::Unauthenticated(_)
        ));
        assert!(matches!(
            server.authenticate_flight(None).await,
            FlightAuth::Unauthenticated(_)
        ));
        // A non-Basic scheme is a header error.
        assert!(matches!(
            server.authenticate_flight(Some("Bearer xyz")).await,
            FlightAuth::BadHeader(_)
        ));
    }

    /// TLS wiring fails fast at boot when the configured cert can't be read,
    /// rather than spawning a listener that dies on first connect.
    #[cfg(feature = "flight_sql")]
    #[tokio::test]
    async fn flight_sql_serve_fails_fast_on_unreadable_tls_cert() {
        use crate::config::{FlightSqlConfig, FlightSqlTlsConfig};
        let config = ServerConfig {
            flight_sql: Some(FlightSqlConfig {
                addr: "127.0.0.1:0".to_string(),
                tls: Some(FlightSqlTlsConfig {
                    cert_file: "/nonexistent/dataglot-flight-cert.pem".into(),
                    key_file: "/nonexistent/dataglot-flight-key.pem".into(),
                }),
            }),
            ..ServerConfig::default()
        };
        let server = Arc::new(
            DataglotServer::new_with_catalogs(config, HashMap::new(), Arc::new(NoopPolicyEnforcer))
                .expect("server"),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let err = crate::flight_sql::serve(Arc::clone(&server), listener)
            .expect_err("serve must fail fast when the TLS cert is unreadable");
        assert!(
            err.to_string().contains("cert_file"),
            "error should name the missing cert file: {err}"
        );
    }

    /// Governance parity (the Flight half of the exit criterion): a query over
    /// Flight SQL applies the SAME configured column mask the pg-wire path
    /// applies — both run through `create_session()` + `with_session_identity`.
    /// `v` is masked ONLY via lineage propagation from the `users.email` source
    /// mask, so a masked value proves the full governance pipeline runs on this
    /// egress, not just a direct rule.
    #[cfg(feature = "flight_sql")]
    #[tokio::test]
    #[allow(clippy::too_many_lines)] // end-to-end test: catalog + mask + lineage setup, serve, client
    async fn flight_sql_applies_column_mask_over_the_wire() {
        use crate::config::{build_rule_store_with_lineage, DerivedProductConfig, MaskConfig};
        use arrow_flight::sql::client::FlightSqlServiceClient;
        use datafusion::arrow::array::{RecordBatch, StringArray};
        use datafusion::arrow::datatypes::{DataType, Field, Schema};
        use datafusion::catalog::{MemoryCatalogProvider, MemorySchemaProvider};
        use datafusion::datasource::MemTable;
        use futures::TryStreamExt;

        fn email_table(val: &str) -> Arc<MemTable> {
            let schema = Arc::new(Schema::new(vec![Field::new(
                "email",
                DataType::Utf8,
                false,
            )]));
            let batch = RecordBatch::try_new(
                schema.clone(),
                vec![Arc::new(StringArray::from(vec![val.to_string()]))],
            )
            .unwrap();
            Arc::new(MemTable::try_new(schema, vec![vec![batch]]).unwrap())
        }

        let sp = Arc::new(MemorySchemaProvider::new());
        sp.register_table("users".to_string(), email_table("real@x.com"))
            .unwrap();
        sp.register_table("v".to_string(), email_table("real@x.com"))
            .unwrap();
        let cp = Arc::new(MemoryCatalogProvider::new());
        cp.register_schema("public", sp).unwrap();
        let catalogs: HashMap<String, Arc<dyn DfCatalogProvider>> =
            HashMap::from([("dataglot".to_string(), cp as Arc<dyn DfCatalogProvider>)]);

        let products = vec![DerivedProductConfig {
            name: "v".to_string(),
            sql: "SELECT email FROM users".to_string(),
            catalog: None,
            schema: None,
            backing: crate::config::MaterializationBacking::default(),
            materialization: None,
        }];
        let masks = vec![MaskConfig {
            table: "users".to_string(),
            column: "email".to_string(),
            mask_literal: "***@example.com".to_string(),
            mask_type: None,
            priority: 0,
            mask_expr: None,
            groups: None,
        }];
        let config = ServerConfig {
            masks: masks.clone(),
            derived_products: products.clone(),
            ..ServerConfig::default()
        };
        let factory = SessionContextFactory::new(config.to_session_config()).unwrap();
        let graph = build_lineage_graph(
            &products,
            &factory,
            &catalogs,
            false,
            &config.default_catalog,
            &config.default_schema,
        )
        .await;
        let store = build_rule_store_with_lineage(
            &masks,
            &[],
            None,
            &graph,
            Some((
                config.default_catalog.clone(),
                config.default_schema.clone(),
            )),
        )
        .expect("rule store builds");
        let server = Arc::new(
            DataglotServer::new_with_catalogs(config, catalogs, store.enforcer()).expect("server"),
        );

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = crate::flight_sql::serve(Arc::clone(&server), listener).expect("serve");

        let channel = tonic::transport::Channel::from_shared(format!("http://{addr}"))
            .unwrap()
            .connect()
            .await
            .expect("client connects");
        let mut client = FlightSqlServiceClient::new(channel);
        let info = client
            .execute("SELECT email FROM v".to_string(), None)
            .await
            .expect("get_flight_info_statement");
        let ticket = info.endpoint[0].ticket.clone().expect("endpoint ticket");
        let batches: Vec<_> = client
            .do_get(ticket)
            .await
            .expect("do_get_statement")
            .try_collect()
            .await
            .expect("collect batches");

        let col = batches[0]
            .column(0)
            .as_any()
            .downcast_ref::<StringArray>()
            .expect("utf8");
        assert_eq!(
            col.value(0),
            "***@example.com",
            "the configured mask must apply over the Flight SQL egress, via lineage propagation alone"
        );

        server.shutdown_tx.send(()).unwrap();
        handle.await.expect("Flight SQL server task joins cleanly");
    }

    /// Governance-parity exit criterion (slice 3): the SAME query run by the
    /// SAME (anonymous) identity over **both** pg-wire and Flight SQL against
    /// the same server returns **identical** governed output — the configured
    /// mask applies byte-for-byte on both egresses. Boots one real
    /// `DataglotServer` serving pg-wire + Flight together (via `run()`),
    /// queries a masked column over `tokio_postgres` and over the arrow-flight
    /// client, and asserts the two agree (and are actually masked).
    #[cfg(feature = "flight_sql")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[allow(clippy::too_many_lines)] // one server, two full client stacks
    async fn governance_output_is_identical_over_pgwire_and_flight() {
        use crate::config::{build_rule_store_with_lineage, FlightSqlConfig, MaskConfig};
        use arrow_flight::sql::client::FlightSqlServiceClient;
        use datafusion::arrow::array::StringArray;
        use datafusion::arrow::datatypes::{DataType, Field, Schema};
        use datafusion::arrow::record_batch::RecordBatch;
        use datafusion::catalog::{MemoryCatalogProvider, MemorySchemaProvider};
        use datafusion::datasource::MemTable;
        use futures::TryStreamExt;
        use tokio_postgres::NoTls;

        fn ephemeral_port() -> u16 {
            //: delegate to the shared, race-hardened helper.
            dataglot_test_support::reserve_loopback_port()
        }

        // In-memory `dataglot.public.users` with a single email row.
        let schema = Arc::new(Schema::new(vec![Field::new(
            "email",
            DataType::Utf8,
            false,
        )]));
        let batch = RecordBatch::try_new(
            Arc::clone(&schema),
            vec![Arc::new(StringArray::from(vec![
                "real@example.com".to_string()
            ]))],
        )
        .unwrap();
        let sp = Arc::new(MemorySchemaProvider::new());
        sp.register_table(
            "users".to_string(),
            Arc::new(MemTable::try_new(schema, vec![vec![batch]]).unwrap()),
        )
        .unwrap();
        let cp = Arc::new(MemoryCatalogProvider::new());
        cp.register_schema("public", sp).unwrap();
        let catalogs: HashMap<String, Arc<dyn DfCatalogProvider>> =
            HashMap::from([("dataglot".to_string(), cp as Arc<dyn DfCatalogProvider>)]);

        let masks = vec![MaskConfig {
            table: "users".to_string(),
            column: "email".to_string(),
            mask_literal: "REDACTED".to_string(),
            mask_type: None,
            priority: 0,
            mask_expr: None,
            groups: None,
        }];

        let pg_port = ephemeral_port();
        let flight_port = ephemeral_port();
        let config = ServerConfig {
            host: "127.0.0.1".to_string(),
            port: pg_port,
            default_catalog: "dataglot".to_string(),
            default_schema: "public".to_string(),
            masks: masks.clone(),
            flight_sql: Some(FlightSqlConfig {
                addr: format!("127.0.0.1:{flight_port}"),
                tls: None,
            }),
            // No sibling metrics listener — it defaults to a fixed port that
            // collides across parallel tests; this test only needs the two
            // query egresses.
            observability: crate::observability::ObservabilityConfig {
                metrics_addr: None,
                ..Default::default()
            },
            ..ServerConfig::default()
        };

        // Enforcer from the mask (no derived products → empty lineage graph).
        let factory = SessionContextFactory::new(config.to_session_config()).unwrap();
        let graph = build_lineage_graph(
            &[],
            &factory,
            &catalogs,
            false,
            &config.default_catalog,
            &config.default_schema,
        )
        .await;
        let store = build_rule_store_with_lineage(
            &masks,
            &[],
            None,
            &graph,
            Some((
                config.default_catalog.clone(),
                config.default_schema.clone(),
            )),
        )
        .expect("rule store builds");

        let server = DataglotServer::new_with_catalogs(config, catalogs, store.enforcer())
            .expect("server boots");
        let shutdown_tx = server.shutdown_tx.clone();
        let server_handle = tokio::spawn(async move { server.run().await.expect("server runs") });

        // Wait until pg-wire answers.
        let pg_conn = format!("host=127.0.0.1 port={pg_port} user=dataglot dbname=dataglot");
        for i in 0..50 {
            if tokio_postgres::connect(&pg_conn, NoTls).await.is_ok() {
                break;
            }
            assert!(i < 49, "pg-wire never became ready on {pg_port}");
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }

        // pg-wire result.
        let (client, conn) = tokio_postgres::connect(&pg_conn, NoTls)
            .await
            .expect("pgwire connect");
        tokio::spawn(async move {
            let _ = conn.await;
        });
        let pg_rows = client
            .query("SELECT email FROM users", &[])
            .await
            .expect("pgwire query");
        let pg_email: String = pg_rows[0].get(0);
        drop(client);

        // Flight SQL result (retry connect while the listener finishes binding).
        let mut channel = None;
        for _ in 0..50 {
            if let Ok(c) =
                tonic::transport::Channel::from_shared(format!("http://127.0.0.1:{flight_port}"))
                    .unwrap()
                    .connect()
                    .await
            {
                channel = Some(c);
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        let mut fclient = FlightSqlServiceClient::new(channel.expect("Flight SQL listener ready"));
        let info = fclient
            .execute("SELECT email FROM users".to_string(), None)
            .await
            .expect("flight info");
        let ticket = info.endpoint[0].ticket.clone().expect("ticket");
        let fbatches: Vec<_> = fclient
            .do_get(ticket)
            .await
            .expect("do_get")
            .try_collect()
            .await
            .expect("collect");
        let flight_email = fbatches[0]
            .column(0)
            .as_any()
            .downcast_ref::<StringArray>()
            .expect("utf8")
            .value(0)
            .to_string();

        // Byte-identical governed output on both egresses, and actually masked.
        assert_eq!(
            pg_email, flight_email,
            "the same query+identity must yield identical governed output over pg-wire and Flight SQL"
        );
        assert_eq!(
            pg_email, "REDACTED",
            "the mask must actually apply (not a coincidental match)"
        );

        let _ = shutdown_tx.send(());
        server_handle.abort();
        let _ = server_handle.await;
    }
}

#[cfg(test)]
mod effective_catalog_tests {
    use std::collections::HashMap;

    use serde_json::json;

    use super::merge_effective_catalogs;
    use crate::config::CatalogConfig;

    fn from_json(v: serde_json::Value) -> CatalogConfig {
        serde_json::from_value(v).expect("valid catalog config")
    }

    /// Slice A2 precedence: the store is **authoritative**. Its config wins for
    /// a shared name (was file-wins in slice 1); a store-only catalog is kept; an
    /// unparseable store config falls back to the file when the file declares
    /// that name, else it's skipped; and a file-only name (store seed missing)
    /// is still added defensively.
    #[test]
    fn store_authoritative_db_wins_file_fallback() {
        let mut file = HashMap::new();
        file.insert(
            "pg".to_string(),
            from_json(json!({"kind": "postgres", "dsn_env": "FILE_DSN"})),
        );
        // In the file, not in the store (seed missing) → added defensively.
        file.insert(
            "only_file".to_string(),
            from_json(json!({"kind": "postgres", "dsn_env": "ONLY_FILE"})),
        );
        // In the file AND corrupt in the store → the file is the fallback.
        file.insert(
            "corrupt".to_string(),
            from_json(json!({"kind": "postgres", "dsn_env": "CORRUPT_FILE"})),
        );

        let mut db = HashMap::new();
        // Same name as the file → the STORE wins now.
        db.insert(
            "pg".to_string(),
            json!({"kind": "postgres", "dsn_env": "DB_DSN"}),
        );
        // Store-only → kept.
        db.insert(
            "analytics".to_string(),
            json!({"kind": "mysql", "dsn_env": "AN_DSN"}),
        );
        // Unparseable, not in the file → skipped, reported, not fatal.
        db.insert("broken".to_string(), json!({"kind": "no_such_kind"}));
        // Unparseable, but the file has it → file fallback.
        db.insert("corrupt".to_string(), json!({"kind": "no_such_kind"}));

        let (eff, skipped) = merge_effective_catalogs(&file, db);

        let pg_json = serde_json::to_value(&eff["pg"]).unwrap();
        assert_eq!(
            pg_json["dsn_env"], "DB_DSN",
            "store config wins for a name declared in both"
        );
        assert!(
            matches!(eff["analytics"], CatalogConfig::Mysql(_)),
            "a store-only catalog is kept"
        );
        let only_file_json = serde_json::to_value(&eff["only_file"]).unwrap();
        assert_eq!(
            only_file_json["dsn_env"], "ONLY_FILE",
            "a file-only catalog (store seed missing) is added defensively"
        );
        let corrupt_json = serde_json::to_value(&eff["corrupt"]).unwrap();
        assert_eq!(
            corrupt_json["dsn_env"], "CORRUPT_FILE",
            "an unparseable store config falls back to the file"
        );
        assert!(
            !eff.contains_key("broken"),
            "unparseable store config with no file fallback is skipped"
        );
        assert_eq!(skipped.len(), 1);
        assert_eq!(skipped[0].0, "broken");
    }

    #[test]
    fn empty_db_returns_file_only() {
        let mut file = HashMap::new();
        file.insert(
            "pg".to_string(),
            from_json(json!({"kind": "postgres", "dsn_env": "X"})),
        );
        let (eff, skipped) = merge_effective_catalogs(&file, HashMap::new());
        assert_eq!(eff.len(), 1);
        assert!(eff.contains_key("pg"));
        assert!(skipped.is_empty());
    }
}

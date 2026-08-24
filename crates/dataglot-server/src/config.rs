//! Server configuration loading and management.
//!
//! Configures the pg wire listener (`host`, `port`), the `DataFusion`
//! `SessionContext` defaults (`batch_size`, `partitions`,
//! `default_catalog`, `default_schema`), the observability subsystem
//! (`observability` block — see [`crate::observability`]), and the
//! federated [`catalogs`](ServerConfig::catalogs) registered on every new
//! pgwire `SessionContext`.
//!
//! # Catalog config
//!
//! The `catalogs` map is keyed by the name `DataFusion` exposes in
//! three-part references (`<catalog>.<schema>.<table>`). Each entry is a
//! [`CatalogConfig`] tagged by its `kind`:
//!
//! ```json
//! {
//!   "host": "0.0.0.0",
//!   "port": 5432,
//!   "catalogs": {
//!     "pg_users": {
//!       "kind": "postgres",
//!       "dsn_env": "PG_USERS_DSN"
//!     },
//!     "warehouse": {
//!       "kind": "warehouse",
//!       "catalog_url": "http://lakekeeper:8181/catalog",
//!       "warehouse": "main",
//!       "s3_endpoint": "http://minio:9000",
//!       "s3_region": "us-east-1",
//!       "credentials": {
//!         "kind": "static",
//!         "access_key_id": "AKIA...",
//!         "secret_access_key_env": "WAREHOUSE_SECRET"
//!       }
//!     }
//!   }
//! }
//! ```
//!
//! Per CLAUDE.md rule 12, [`PostgresCatalogConfig`] and
//! [`WarehouseCredentialsConfig::Static`] have hand-written `Debug`
//! implementations that redact the DSN and the secret-access-key. Any
//! `DSN` or secret values held in env vars are looked up at boot via
//! `build_connectors` and never logged.

use std::collections::HashMap;
use std::fmt;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use datafusion::catalog::CatalogProvider as DfCatalogProvider;
use datafusion::common::TableReference;
use datafusion::logical_expr::{col, lit};
use dataglot_core::{CatalogBinding, IcebergCacheBinding, LiveConnectorBinding, LiveConnectorKind};
#[cfg(test)]
use dataglot_policy::RuleStore;
use dataglot_policy::{
    AccessDenial, AccessDenyEnforcer, ColumnMask, ColumnWhitelist, ColumnWhitelistEnforcer,
    CompositeEnforcer, Grant, GrantEnforcer, InMemoryRuleStore, InitialRules, MaskKind, OrgGroupId,
    Policy, PolicyEnforcer, RowFilter, RuleType, SemanticTableColumn, TagDefinition, TagId,
};
use serde::{Deserialize, Serialize};

use crate::cli::{Args, MetricsAddr};
use crate::observability::ObservabilityConfig;
use crate::webhook::WebhookConfig;

/// Server configuration.
// Container-level `#[serde(default)]`: any field the config file omits
// falls back to `ServerConfig::default()`. This makes a minimal (even
// empty `{}`) config load with sane defaults — so first-run configs
// don't hit a one-field-at-a-time "missing field `batch_size`" wall
// (the scalars are also re-set from CLI/env in `load`). Matches the
// "an empty {} boots a server" promise in docs/configuration.md.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    /// Host address to bind to.
    pub host: String,
    /// Port to listen on.
    pub port: u16,
    /// Batch size for query execution.
    pub batch_size: usize,
    /// Number of partitions for parallel execution.
    pub partitions: usize,
    /// Default catalog name.
    pub default_catalog: String,
    /// Default schema name.
    pub default_schema: String,
    /// Cap on query-execution memory, in bytes. When set,
    /// every session's runtime gets a fair spill pool of this size, so
    /// memory-hungry operators (hash joins, sorts, aggregations) spill
    /// to disk — or fail with a typed "resources exhausted" error —
    /// instead of growing until the OS kills the whole server. Unset
    /// (default) keeps DataFusion's unbounded default. Especially
    /// relevant with `[ballista]` distributed execution, whose
    /// shuffle-heavy joins are the memory-hungriest path.
    #[serde(default)]
    pub memory_limit_bytes: Option<usize>,
    /// Directory for operator spill files. Unset ⇒ the OS
    /// temp dir. Only meaningful together with `memory_limit_bytes`.
    #[serde(default)]
    pub spill_dir: Option<std::path::PathBuf>,
    /// When `true`, a catalog that fails to connect at boot is logged
    /// at WARN and skipped instead of aborting startup; the server
    /// boots with the catalogs that did connect. Default `false`
    /// (fail-fast — a misconfigured source is a hard configuration
    /// error, the safest behaviour for production).
    ///
    /// Intended for demo / auto-detected sources where degrading to
    /// the reachable catalogs beats refusing to start — e.g. the
    /// testbench's Snowflake auto-on path, where stale or absent
    /// credentials shouldn't take the whole server down. Set via
    /// `--tolerate-unreachable-catalogs` /
    /// `DATAGLOT_TOLERATE_UNREACHABLE_CATALOGS`.
    ///
    /// Note: some connectors (e.g. Snowflake) connect eagerly at boot
    /// to enumerate schemas, so an unreachable one is caught here;
    /// connectors with fully lazy schema resolution (rule 13) only
    /// surface a bad source on first query regardless of this flag.
    #[serde(default)]
    pub tolerate_unreachable_catalogs: bool,
    /// Observability (logging + Prometheus metrics) configuration.
    #[serde(default)]
    pub observability: ObservabilityConfig,
    /// Catalogs to register on each new pgwire `SessionContext`.
    /// Keyed by the name `DataFusion` exposes in three-part references
    /// like `<catalog>.<schema>.<table>`.
    #[serde(default)]
    pub catalogs: HashMap<String, CatalogConfig>,
    /// Column-masking rules registered on every pgwire session as
    /// the first `OptimizerRule`. See [`MaskConfig`] for the entry
    /// shape. Empty list ⇒ `NoopPolicyEnforcer` is installed (the
    /// pre-#125 default behaviour) and there is no observable
    /// runtime cost beyond a single optimizer-pass identity check.
    #[serde(default)]
    pub masks: Vec<MaskConfig>,
    /// Derived data products (views / saved queries) whose lineage is
    /// tracked so column masks **propagate** from a source column to
    /// the derived columns that descend from it (Interface 4, ).
    /// Each is planned once at boot to extract column lineage; empty ⇒
    /// no propagation (masks apply only where configured). See
    /// [`DerivedProductConfig`].
    #[serde(default)]
    pub derived_products: Vec<DerivedProductConfig>,
    /// Scheduled warehouse maintenance — compaction (Phase 4 Task 03).
    /// Empty ⇒ no maintenance tasks, identical to prior boot. See
    /// [`MaintenanceConfig`].
    #[serde(default)]
    pub maintenance: MaintenanceConfig,
    /// Row-level filter rules registered on every pgwire session.
    /// See [`RowFilterConfig`] for the entry shape. When both
    /// `masks` and `row_filters` are non-empty, the two enforcers
    /// are wrapped in a `dataglot_policy::CompositeEnforcer` and
    /// run in declared order on every plan. Order doesn't change
    /// the result (the two enforcers rewrite disjoint plan
    /// regions) but it's stable for diagnostics.
    #[serde(default)]
    pub row_filters: Vec<RowFilterConfig>,
    /// Optional tag-based governance registry — Architecture
    /// Decisions §10. Defines a set of tags, the policies that
    /// attach to each tag (mask or row-filter rules per group),
    /// and the column annotations that bind tags to specific
    /// columns. Resolved into a `TagBasedEnforcer` and composed
    /// with the static `masks` / `row_filters` arrays at boot.
    /// Operators using only the static arrays can omit this
    /// section entirely; the field defaults to `None`.
    #[serde(default)]
    pub governance: Option<OrgGovernanceConfig>,
    /// Map of pgwire username → identity profile (org + group
    /// memberships). The pgwire startup observer reads this map
    /// once per connection and seeds the per-task `Identity` so
    /// `TagBasedEnforcer` can dispatch policies on
    /// `org_groups`. Sessions whose `user` is missing from the
    /// map fall back to `Identity::user(name)` with empty groups
    /// — effectively read-only against any tag-based row filter
    /// or column mask that requires a group match.
    ///
    /// JSON shape:
    ///
    /// ```json
    /// {
    ///   "identities": {
    ///     "alice": { "org": "acme", "groups": ["analyst"] },
    ///     "bob":   { "org": "acme", "groups": ["analyst", "support"] }
    ///   }
    /// }
    /// ```
    ///
    /// MVP-shape only: this is a static authoritative map, not
    /// a directory integration. Production deployments will swap
    /// the lookup for an external `IdP` / LDAP query in a follow-up
    /// PR; the trait-level seam (`StartupObserver` callback) is
    /// stable.
    #[serde(default)]
    pub identities: HashMap<String, IdentityProfileConfig>,
    /// Role definitions — Apache Ranger role parity. A role is a named
    /// collection of users and/or groups; a session *holds* a role when
    /// its user is listed, or any of its groups is listed. Held role
    /// names are folded into the session's effective group set, so any
    /// policy/denial scoped to a group name also matches a role of that
    /// name. Empty ⇒ no roles. See [`RoleConfig`].
    #[serde(default)]
    pub roles: HashMap<String, RoleConfig>,
    /// Optional policy-explainability HTTP endpoint (`POST /policy/explain`).
    /// `None` ⇒ not bound. See [`crate::policy_explain::PolicyExplainConfig`].
    #[serde(default)]
    pub policy_explain: Option<crate::policy_explain::PolicyExplainConfig>,
    /// Connection authentication. Omitted ⇒ trust mode (the asserted
    /// username is trusted, pre-Phase-3 behavior). See [`AuthConfig`].
    #[serde(default)]
    pub auth: AuthConfig,
    /// GRANT/REVOKE authorization enforcement. Omitted ⇒
    /// `open` mode: no enforcement, existing deployments unchanged. See
    /// [`AuthzConfig`].
    #[serde(default)]
    pub authz: AuthzConfig,
    /// pgwire ingress TLS (client↔server). `None` ⇒ plaintext listener
    /// (unchanged). See [`PgwireTlsConfig`].
    #[serde(default)]
    pub pgwire_tls: Option<PgwireTlsConfig>,
    /// Arrow Flight SQL egress — the native-Arrow query interface
    /// on `:32010`, alongside pg-wire. `None` ⇒ no Flight SQL listener
    /// (unchanged). Requires the `flight_sql` build feature; a block set
    /// without it is rejected at boot. See [`FlightSqlConfig`].
    #[serde(default)]
    pub flight_sql: Option<FlightSqlConfig>,
    /// pgwire connection rate limiting (concurrent-connection ceilings).
    /// `None` ⇒ no admission control (unchanged). See [`RateLimitConfig`].
    #[serde(default)]
    pub rate_limit: Option<RateLimitConfig>,
    /// Access-deny rules — Apache Ranger access-policy parity. Each entry
    /// denies access to a table (or a specific column) for the listed
    /// groups; an empty `groups` denies everyone. Denials are enforced
    /// plan-time *before* masking/row-filtering: a query touching a
    /// denied resource is rejected with `permission denied`. See
    /// [`AccessDenyConfig`].
    #[serde(default)]
    pub access_denials: Vec<AccessDenyConfig>,
    /// Column-level **whitelists** (positive column authorization, ).
    /// For a table with a matching whitelist, only the listed columns are
    /// visible to the identity — unlisted columns are projected away
    /// (`SELECT *` returns the visible subset; a hidden column used in a
    /// filter/join/computation is denied). Org+group-scoped. A table with no
    /// applicable whitelist is unrestricted. See [`ColumnGrantConfig`].
    #[serde(default)]
    pub column_grants: Vec<ColumnGrantConfig>,
    /// Catalog service (Phase 1 task 08) configuration. `None` ⇒
    /// the server populates `bindings` directly from
    /// `[catalogs.*]` per #182 (pre-task-08 fast path, no
    /// Postgres dep at boot). `Some(...)` ⇒ connect to the
    /// service, upsert every `[catalogs.*]` entry, then
    /// populate `bindings` from `CatalogService::list_bindings`.
    /// JSON wins on conflict in Phase 1.
    ///
    /// JSON shape:
    ///
    /// ```json
    /// {
    ///   "catalog_service": {
    ///     "dsn": "host=catalog-db port=5432 user=dataglot password=... dbname=catalog",
    ///     "org_id": "default"
    ///   }
    /// }
    /// ```
    ///
    /// Spec: `docs/phases/phase-1/08-catalog-service.md`.
    #[serde(default)]
    pub catalog_service: Option<CatalogServiceConfig>,
    /// Lineage emitter configuration — Architecture Decisions §10.
    /// `None` ⇒ `dataglot_core::NoopLineageEmitter`, no events
    /// are emitted. `Some(LineageConfig::OpenlineageHttp { … })`
    /// installs the HTTP emitter and POSTs an `OpenLineage`
    /// `START` + `COMPLETE`/`FAIL` event pair on every pgwire
    /// query.
    ///
    /// JSON shape:
    ///
    /// ```json
    /// {
    ///   "lineage": {
    ///     "kind": "openlineage_http",
    ///     "endpoint": "http://marquez:5000/api/v1/lineage",
    ///     "namespace": "dataglot.acme"
    ///   }
    /// }
    /// ```
    ///
    /// See `docs/phases/phase-1/06-openlineage-emitter.md`.
    #[serde(default)]
    pub lineage: Option<LineageConfig>,
    /// Governance backends to publish data products to —
    /// Architecture Decisions §11 Interface #2. Empty / omitted
    /// ⇒ no publisher constructed, no boot-time POSTs, no
    /// `BindingChange` hook. Array-of-publishers shape so a
    /// future deployment can fan out to `DataHub` + `OpenMetadata`
    /// simultaneously.
    ///
    /// JSON shape:
    ///
    /// ```json
    /// {
    ///   "governance_publishers": [
    ///     {
    ///       "kind": "datahub",
    ///       "gms_endpoint": "http://datahub-gms:8080",
    ///       "bearer_token_env": "DATAGLOT_DATAHUB_TOKEN"
    ///     }
    ///   ]
    /// }
    /// ```
    ///
    /// Spec: `docs/phases/phase-1/10-data-product-registration.md`.
    #[serde(default)]
    pub governance_publishers: Vec<GovernancePublisherConfig>,
    /// Optional Ballista distributed-execution configuration
    /// (Phase 2 spec 02 slice 3a). `None` ⇒ single-node boot path,
    /// bit-identical to pre-slice-3a behaviour. `Some(...)` ⇒ at
    /// `DataglotServer::new` boot, spin up an in-process Ballista
    /// standalone cluster (1 scheduler + 1 executor) and route every
    /// `create_session()` call through it instead of the
    /// `SessionContextFactory`.
    ///
    /// The actual cluster bring-up code lives in the optional
    /// `dataglot-ballista` dep — this struct compiles regardless of
    /// the `ballista` feature flag (so `dataglot.toml` parsing
    /// stays uniform), but a `Some(...)` value with the feature OFF
    /// is a configuration error and is rejected at `DataglotServer::new`.
    ///
    /// JSON shape:
    ///
    /// ```json
    /// {
    ///   "ballista": {
    ///     "standalone_parallelism": 2
    ///   }
    /// }
    /// ```
    ///
    /// Spec: `docs/phases/phase-2/02-ballista-distributed-execution.md`
    /// slice 3a.
    #[serde(default)]
    pub ballista: Option<BallistaServerConfig>,
    /// Inbound governance webhook configuration — Phase 2 spec 04
    /// slice 1. Receives policy events (tag assignment, policy
    /// upsert, certification) from a governance platform's Actions
    /// Framework (`DataHub`, Informatica IDMC) on a dedicated HTTP
    /// port with HMAC-SHA256 auth.
    ///
    /// Omitting the block keeps server boot bit-identical to the
    /// pre-slice-1 behaviour: no extra port bound and no shared-secret
    /// env var required. (The `dataglot_governance_webhook_events_total`
    /// counter is registered unconditionally so dashboards see a stable
    /// shape, but it stays at zero on servers without the webhook
    /// enabled.) Operators turn it on by setting both `addr` and
    /// `secret_env`.
    ///
    /// JSON shape:
    ///
    /// ```json
    /// {
    ///   "webhook": {
    ///     "addr": "0.0.0.0:8080",
    ///     "secret_env": "DATAGLOT_WEBHOOK_SECRET"
    ///   }
    /// }
    /// ```
    ///
    /// Spec: `docs/phases/phase-2/04-inbound-governance-integration.md`.
    /// Slice 1 ships the echo path (HMAC verify + envelope parse +
    /// 200 ack); slices 2/3 add the rule-store mutation and the
    /// DataHub-shape adapter.
    #[serde(default)]
    pub webhook: Option<WebhookConfig>,
}

/// Ballista distributed-execution configuration block. Phase 2
/// slice 3a ships the standalone (in-process scheduler + executor)
/// shape; remote-scheduler operation lands in slice 5+ as a future
/// variant on this struct.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BallistaServerConfig {
    /// Executor task slots for the standalone cluster.
    /// Slice 1's smoke test used 2; the spec leaves slice 4 to tune
    /// this once split-level parallelism is measured. The default
    /// matches slice 1.
    #[serde(default = "default_standalone_parallelism")]
    pub standalone_parallelism: usize,
    /// Port for the scheduler's observability REST API
    /// (`/api/state`, `/api/executors`, `/api/jobs`,
    /// `/api/job/{id}/stages`, DOT execution graphs) — the data
    /// source for the testbench's live cluster view. Bound to
    /// **127.0.0.1 only** (the endpoints are unauthenticated and can
    /// expose query text). Default `50050` (Ballista's conventional
    /// scheduler port); set to `null` to disable. A failed bind is a
    /// boot WARN, never a boot failure.
    #[serde(default = "default_rest_api_port")]
    pub rest_api_port: Option<u16>,
    /// Number of **external** executor processes expected to register with
    /// an in-process scheduler. `0` (default) keeps the embedded
    /// standalone shape (scheduler + one in-process executor, task slots =
    /// [`Self::standalone_parallelism`]). When `> 0`, the server boots a
    /// **scheduler-only** cluster — no in-process executor — on
    /// [`Self::scheduler_grpc_port`], and the launcher/operator spawns this
    /// many `dataglot-ballista-executor` processes to form the worker pool.
    #[serde(default)]
    pub external_executors: usize,
    /// gRPC port the in-process scheduler binds when
    /// [`Self::external_executors`] `> 0`, so externally-spawned executors
    /// can register with it (their `--scheduler-port`). Ignored in the
    /// embedded-standalone shape (the in-process executor is handed the
    /// ephemeral scheduler address directly). Default `50051`.
    #[serde(default = "default_scheduler_grpc_port")]
    pub scheduler_grpc_port: u16,
    /// Seconds the scheduler waits without a heartbeat before declaring an
    /// executor dead. Ballista's upstream default is 180s, which culls
    /// healthy external executors whenever the host pauses longer than that
    /// (laptop sleep, load spike, a long idle between interactive queries),
    /// leaving the cluster with zero workers and every in-flight job stuck
    /// at 0%. Default 3600 (an hour) so idle gaps don't destroy
    /// the pool; a real multi-node deployment that wants faster dead-node
    /// detection can lower it.
    #[serde(default = "default_executor_timeout_seconds")]
    pub executor_timeout_seconds: u64,
}

const fn default_standalone_parallelism() -> usize {
    2
}

const fn default_scheduler_grpc_port() -> u16 {
    50051
}

const fn default_executor_timeout_seconds() -> u64 {
    3600
}

// The `Option` wrap is the point: the field is `Option<u16>` so operators
// can write `"rest_api_port": null` to disable, while omitting the key
// gets this default.
#[allow(clippy::unnecessary_wraps)]
const fn default_rest_api_port() -> Option<u16> {
    Some(50050)
}

impl Default for BallistaServerConfig {
    fn default() -> Self {
        Self {
            standalone_parallelism: default_standalone_parallelism(),
            rest_api_port: default_rest_api_port(),
            external_executors: 0,
            scheduler_grpc_port: default_scheduler_grpc_port(),
            executor_timeout_seconds: default_executor_timeout_seconds(),
        }
    }
}

/// Lineage backend configuration.
///
/// Single variant in the MVP; new transports (`Kafka`, `File`,
/// etc.) will join the enum without breaking existing JSON.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum LineageConfig {
    /// HTTP-based `OpenLineage` emitter — POSTs `RunEvent` JSON
    /// to the configured endpoint on every query. Compatible
    /// with Marquez, `DataHub`, `OpenMetadata`, and Informatica
    /// out of the box.
    OpenlineageHttp {
        /// Full URL to the `OpenLineage` HTTP intake (typically
        /// `http://<host>:5000/api/v1/lineage` for Marquez).
        endpoint: String,
        /// `OpenLineage` `job.namespace` — operators typically
        /// use `dataglot.<tenant>` so events from different
        /// Dataglot instances are scoped in the backend's UI.
        namespace: String,
    },
}

/// Governance publisher configuration — Architecture Decisions §11
/// Interface #2.
///
/// Single variant in Phase 1 (`DataHub`); new backends
/// (`OpenMetadata`, `Informatica`) join the enum without breaking
/// existing JSON.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum GovernancePublisherConfig {
    /// `DataHub` GMS endpoint that receives `MetadataChangeProposal`
    /// HTTP POSTs. See [`crate::governance::DataHubPublisher`].
    Datahub {
        /// Full `DataHub` GMS URL — typically
        /// `http://<host>:8080` for the in-cluster deployment.
        /// The `/aspects?action=ingestProposal` ingest path is
        /// appended by the publisher; do not include it here.
        gms_endpoint: String,
        /// Name of the env var that holds the bearer token. The
        /// literal token is intentionally *not* on disk per
        /// CLAUDE.md rule 12 — operators wire it through the
        /// process environment. Resolved once at boot; rotation
        /// requires a server restart (Phase 2 follow-up).
        ///
        /// `None` ⇒ no `Authorization` header is sent (matches
        /// the no-auth path that local `DataHub` dev deployments
        /// run with).
        #[serde(default)]
        bearer_token_env: Option<String>,
    },
}

/// Catalog-service (Phase 1 task 08) configuration block.
///
/// `dsn` is the Postgres libpq DSN of the catalog-service
/// database; per CLAUDE.md rule 12, [`Debug`] redacts it.
/// Postgres-backed control-plane store — the HA / multi-node backend.
///
/// `org_id` is the tenant scope; Phase 1 hardcodes `"default"`.
#[derive(Clone, Deserialize, Serialize)]
pub struct PostgresStoreConfig {
    /// Postgres libpq DSN of the catalog-service database. Today only a
    /// literal DSN is supported (parity with `CatalogService::connect`).
    pub dsn: String,
    /// Tenant scope. Phase 1 expects `"default"`; any other value is
    /// accepted at the config layer but rejected by `CatalogService::connect`
    /// until multi-tenancy lands.
    #[serde(default = "default_org_id")]
    pub org_id: String,
}

impl fmt::Debug for PostgresStoreConfig {
    /// Credential-safe `Debug`: the literal DSN is `<redacted>`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PostgresStoreConfig")
            .field("dsn", &"<redacted>")
            .field("org_id", &self.org_id)
            .finish()
    }
}

/// Embedded pure-Rust single-file store — the zero-external-dependency
/// default (CLAUDE.md rule 15 clean; no C, no Postgres). Production uses the
/// `redb` backend (`dataglot_catalog::RedbMetaStore`,  slice A):
/// single-file, ACID/MVCC, transactional per-key.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EmbeddedStoreConfig {
    /// Backing file the store persists to (a single `redb` database, created
    /// on first open and tightened to `0600` — it holds secret ciphertext and
    /// password hashes). A `.redb` extension is conventional but not required.
    pub path: std::path::PathBuf,
    /// Tenant scope. Phase 1 expects `"default"`.
    #[serde(default = "default_org_id")]
    pub org_id: String,
}

/// Control-plane meta store selection. Deserialized **untagged** for
/// backward compatibility: a block with `dsn` selects the Postgres backend,
/// one with `path` selects the embedded backend.
///
/// ```json
/// "catalog_service": { "dsn": "host=catalog-db ...", "org_id": "default" }
/// "catalog_service": { "path": "/var/lib/dataglot/meta.json" }
/// ```
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum CatalogServiceConfig {
    /// Postgres-backed store (HA / multi-node).
    Postgres(PostgresStoreConfig),
    /// Embedded atomic-file store (zero-dependency default).
    Embedded(EmbeddedStoreConfig),
}

impl CatalogServiceConfig {
    /// Tenant scope of whichever backend is selected.
    #[must_use]
    pub fn org_id(&self) -> &str {
        match self {
            Self::Postgres(p) => &p.org_id,
            Self::Embedded(e) => &e.org_id,
        }
    }
}

fn default_org_id() -> String {
    "default".to_string()
}

/// Per-username profile consulted by the pgwire startup observer
/// to populate [`dataglot_policy::Identity::org`] and
/// [`dataglot_policy::Identity::org_groups`].
///
/// Both fields are optional / default-empty so a profile can
/// declare just an org, just groups, or both.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IdentityProfileConfig {
    /// Organization the user belongs to.
    #[serde(default)]
    pub org: Option<String>,
    /// Org-group memberships. Empty ⇒ no group activation, no
    /// tag-based policies fire for this user (effectively
    /// read-only against governance enforcement).
    #[serde(default)]
    pub groups: Vec<String>,
    /// Name of the environment variable holding this user's cleartext
    /// password, consulted only when [`AuthConfig::mode`] is
    /// [`AuthMode::Md5`](crate::config::AuthMode). The password itself
    /// never appears in the config file (CLAUDE.md rule 12) — only the
    /// env-var *name* does. `None` ⇒ the user cannot authenticate under
    /// md5 mode (no credential), though their profile still resolves for
    /// authorization once authenticated by some other means.
    #[serde(default)]
    pub password_env: Option<String>,
}

/// Connection authentication configuration.
///
/// ```toml
/// [auth]
/// mode = "md5"          # "trust" (default) | "md5" | "scram-sha-256"
///
/// [identities.alice]
/// groups = ["analyst"]
/// password_env = "DATAGLOT_PW_ALICE"   # env var holds the secret
/// ```
///
/// Trust mode (the default) preserves the pre-Phase-3 behavior: the
/// asserted username is trusted without a password. MD5 and
/// `scram-sha-256` mode both require each connecting user to complete a
/// Postgres password exchange, validated against the cleartext password
/// read at boot from the env var named by
/// [`IdentityProfileConfig::password_env`] (plus any runtime-created
/// users). `scram-sha-256` is the stronger of the two — a salted
/// challenge–response that never puts a replayable password-equivalent on
/// the wire — and consumes the exact same credentials as md5.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuthConfig {
    /// Authentication method. Defaults to [`AuthMode::Trust`].
    #[serde(default)]
    pub mode: AuthMode,
    /// JWT verification parameters, required when `mode = "jwt"`.
    /// Absent in every other mode.
    #[serde(default)]
    pub jwt: Option<JwtAuthConfig>,
    /// LDAP / Active Directory parameters, required when `mode = "ldap"`
    ///. Absent in every other mode.
    #[serde(default)]
    pub ldap: Option<LdapAuthConfig>,
}

/// Authentication method selector (the `[auth] mode` key):
/// `"trust" | "md5" | "scram-sha-256" | "jwt" | "ldap"`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthMode {
    /// No password check — the asserted username is trusted. Dev default.
    #[default]
    Trust,
    /// Postgres MD5 password authentication.
    Md5,
    /// Postgres SCRAM-SHA-256 (SASL) password authentication (F7). Stronger
    /// than md5 — a salted challenge–response that puts no replayable
    /// password-equivalent on the wire — backed by the same credentials.
    #[serde(rename = "scram-sha-256")]
    ScramSha256,
    /// JWT authentication: the client presents a signed JWT as its
    /// password; its verified `groups` claim drives directory-group policy.
    /// Requires [`AuthConfig::jwt`].
    Jwt,
    /// LDAP / Active Directory authentication: the connection binds
    /// to the directory as the user, and a group search drives directory-group
    /// policy. Requires [`AuthConfig::ldap`].
    Ldap,
}

/// Signing-algorithm selector for [`JwtAuthConfig`] (`hs256 | rs256 | es256`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum JwtAlgorithmConfig {
    /// HMAC-SHA256 with a shared secret (from [`JwtAuthConfig::secret_env`]).
    #[default]
    Hs256,
    /// RSA SHA-256 with a PEM public key ([`JwtAuthConfig::public_key_file`]).
    Rs256,
    /// ECDSA P-256 SHA-256 with a PEM public key
    /// ([`JwtAuthConfig::public_key_file`]).
    Es256,
}

impl JwtAlgorithmConfig {
    fn to_pgwire(self) -> dataglot_pgwire::JwtAlgorithm {
        match self {
            JwtAlgorithmConfig::Hs256 => dataglot_pgwire::JwtAlgorithm::Hs256,
            JwtAlgorithmConfig::Rs256 => dataglot_pgwire::JwtAlgorithm::Rs256,
            JwtAlgorithmConfig::Es256 => dataglot_pgwire::JwtAlgorithm::Es256,
        }
    }
}

fn default_groups_claim() -> String {
    "groups".to_string()
}

fn default_jwt_leeway_secs() -> u64 {
    60
}

/// JWT verification config (`[auth.jwt]`),.
///
/// ```toml
/// [auth]
/// mode = "jwt"
///
/// [auth.jwt]
/// algorithm = "hs256"                 # "hs256" | "rs256" | "es256"
/// secret_env = "DATAGLOT_JWT_SECRET"  # HS256: env var holds the shared secret
/// # public_key_file = "/etc/dataglot/idp.pem"  # RS256/ES256: PEM public key
/// groups_claim = "groups"             # claim carrying the group array
/// issuer = "https://idp.example"      # optional; validated if set
/// audience = "dataglot"               # optional; validated if set
/// leeway_secs = 60                    # clock-skew tolerance on exp/nbf
/// ```
///
/// The HMAC secret is never inlined (rule 12) — only the *name* of the env
/// var holding it is configured (like [`IdentityProfileConfig::password_env`]).
/// RS256 / ES256 reference the **public** key by path (not a secret).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtAuthConfig {
    /// Signing algorithm the verifier accepts. Pinned — a token whose header
    /// names a different algorithm is rejected.
    #[serde(default)]
    pub algorithm: JwtAlgorithmConfig,
    /// Env var holding the HS256 shared secret. Required for `hs256`.
    #[serde(default)]
    pub secret_env: Option<String>,
    /// Path to the PEM-encoded public key. Required for `rs256` / `es256`.
    #[serde(default)]
    pub public_key_file: Option<std::path::PathBuf>,
    /// Claim carrying the group-name array. Defaults to `"groups"`.
    #[serde(default = "default_groups_claim")]
    pub groups_claim: String,
    /// Required issuer (`iss`), validated when set.
    #[serde(default)]
    pub issuer: Option<String>,
    /// Required audience (`aud`), validated when set.
    #[serde(default)]
    pub audience: Option<String>,
    /// Clock-skew tolerance (seconds) on `exp` / `nbf`. Defaults to 60.
    #[serde(default = "default_jwt_leeway_secs")]
    pub leeway_secs: u64,
}

fn default_group_filter() -> String {
    "(member={userdn})".to_string()
}

fn default_group_name_attr() -> String {
    "cn".to_string()
}

/// LDAP / Active Directory config (`[auth.ldap]`),.
///
/// ```toml
/// [auth]
/// mode = "ldap"
///
/// [auth.ldap]
/// url = "ldap://dir.example:389"
/// bind_dn_template = "uid={user},ou=people,dc=example,dc=com"
/// group_search_base = "ou=groups,dc=example,dc=com"
/// group_filter = "(member={userdn})"   # {user} + {userdn} substituted
/// group_name_attr = "cn"
/// ```
///
/// No secret lives here — the per-connection bind password comes from the
/// client, not from config (rule 12). A bind DN template is not a secret.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LdapAuthConfig {
    /// Directory URL (`ldap://` or `ldaps://`).
    pub url: String,
    /// Bind DN template; `{user}` is the (escaped) startup username.
    pub bind_dn_template: String,
    /// Group search base DN.
    pub group_search_base: String,
    /// Group search filter template (`{user}` / `{userdn}` substituted).
    #[serde(default = "default_group_filter")]
    pub group_filter: String,
    /// Attribute on a matched group entry read as the group name.
    #[serde(default = "default_group_name_attr")]
    pub group_name_attr: String,
    /// Optional read-only **service-account DN** to bind as for the group
    /// search. Required by directories that forbid anonymous search.
    /// When set, [`search_bind_password_env`](Self::search_bind_password_env)
    /// must name an env var holding its password. Absent ⇒ the group search
    /// runs anonymously (the default / back-compat path).
    #[serde(default)]
    pub search_bind_dn: Option<String>,
    /// Env var holding the service-account password (rule 12 — the secret is
    /// never inlined in config). Read once at boot; required when
    /// [`search_bind_dn`](Self::search_bind_dn) is set.
    #[serde(default)]
    pub search_bind_password_env: Option<String>,
}

/// Authorization (GRANT/REVOKE enforcement) configuration.
///
/// ```toml
/// [authz]
/// mode = "grant"   # "open" (default) | "grant"
/// ```
///
/// `open` (the default) applies **zero** enforcement — every existing
/// deployment is unchanged. `grant` turns on deny-unless-granted: reading a
/// table needs `USAGE` on its catalog **and** `SELECT` on the table (see
/// [`AuthzMode`]).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthzConfig {
    /// Authorization mode. Defaults to [`AuthzMode::Open`].
    #[serde(default)]
    pub mode: AuthzMode,
}

/// Authorization mode selector (the `[authz] mode` key).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthzMode {
    /// No authorization enforcement — the historical behaviour.
    #[default]
    Open,
    /// Deny a table read unless the session holds `USAGE` on the catalog and
    /// `SELECT` on the table.
    Grant,
}

impl AuthzMode {
    /// Lower to the policy-crate enforcement mode.
    #[must_use]
    pub fn to_policy(self) -> dataglot_policy::AuthzMode {
        match self {
            AuthzMode::Open => dataglot_policy::AuthzMode::Open,
            AuthzMode::Grant => dataglot_policy::AuthzMode::Grant,
        }
    }
}

/// pgwire **ingress** TLS — encrypt the client↔server link.
///
/// ```toml
/// [pgwire_tls]
/// cert_file = "/etc/dataglot/server.crt"   # PEM chain
/// key_file  = "/etc/dataglot/server.key"   # PEM private key
/// mode = "require"                          # "prefer" (default) | "require"
/// ```
///
/// Omitting the block leaves the listener plaintext (unchanged). The
/// cert/key are referenced by **path**, not inlined (rule 12 — a private
/// key is a secret, but a path is not).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PgwireTlsConfig {
    /// PEM certificate chain presented to clients.
    pub cert_file: std::path::PathBuf,
    /// PEM private key for `cert_file`.
    pub key_file: std::path::PathBuf,
    /// `prefer` (default) accepts both TLS and plaintext clients;
    /// `require` rejects any client that connects without TLS.
    #[serde(default)]
    pub mode: PgwireTlsMode,
}

/// pgwire ingress TLS posture (the `[pgwire_tls] mode` key).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PgwireTlsMode {
    /// Offer TLS but still accept plaintext clients. Eases rollout.
    #[default]
    Prefer,
    /// Reject any client that does not negotiate TLS.
    Require,
}

/// Arrow Flight SQL egress — the native-Arrow query interface,
/// alongside pg-wire. Shares the same `SessionContext` + plan-time policy
/// enforcement, so masks / row-filters / denies apply identically.
///
/// ```toml
/// [flight_sql]
/// addr = "0.0.0.0:32010"   # default
/// # tls = { cert_file = "...", key_file = "...", mode = "require" }
/// ```
///
/// Requires the `flight_sql` build feature. Cert/key referenced by path,
/// not inlined (rule 12).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlightSqlConfig {
    /// gRPC bind address. Default `0.0.0.0:32010`.
    #[serde(default = "default_flight_sql_addr")]
    pub addr: String,
    /// Optional TLS on the Flight listener. `None` ⇒ plaintext gRPC
    /// (h2c). Same cert/key shape as [`PgwireTlsConfig`].
    #[serde(default)]
    pub tls: Option<FlightSqlTlsConfig>,
}

impl Default for FlightSqlConfig {
    fn default() -> Self {
        Self {
            addr: default_flight_sql_addr(),
            tls: None,
        }
    }
}

fn default_flight_sql_addr() -> String {
    "0.0.0.0:32010".to_string()
}

/// TLS for the Flight SQL listener (mirrors [`PgwireTlsConfig`]).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlightSqlTlsConfig {
    /// PEM certificate chain presented to clients.
    pub cert_file: std::path::PathBuf,
    /// PEM private key for `cert_file`.
    pub key_file: std::path::PathBuf,
}

/// pgwire connection rate limiting — a ceiling on *concurrent* connections
///
/// ```toml
/// [rate_limit]
/// max_connections        = 200   # global concurrent-connection ceiling
/// max_connections_per_ip = 20    # per-source-IP concurrent ceiling
/// ```
///
/// All fields are independent and optional; omitting the block (or a
/// field) means "no limit" — behavior is unchanged (non-breaking). See
/// [`crate::rate_limit::ConnectionLimiter`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Global concurrent-connection ceiling across all clients. `None` ⇒
    /// unlimited.
    #[serde(default)]
    pub max_connections: Option<usize>,
    /// Per-source-IP concurrent-connection ceiling. `None` ⇒ unlimited.
    #[serde(default)]
    pub max_connections_per_ip: Option<usize>,
    /// Per-source-IP ceiling on the *rate* of new connections, expressed as
    /// connections per minute. Enforced as a token bucket (capacity = this
    /// value, refilling at `value / 60` tokens per second), so a burst up to
    /// the full value is allowed and then throttled to the steady rate. This
    /// is the brute-force / churn defense the concurrency ceilings above
    /// don't cover (a client that opens and closes fast). `None` ⇒ no rate
    /// limit.
    #[serde(default)]
    pub max_new_connections_per_ip_per_minute: Option<u32>,
    /// Per-authenticated-identity ceiling on concurrent connections. Unlike
    /// the per-IP limits (enforced at the TCP accept path), this is checked
    /// against the username asserted in the pgwire startup message — so it
    /// bounds how many connections one role may hold at once, regardless of
    /// source IP. `None` ⇒ unlimited. See
    /// [`crate::rate_limit::IdentityLimiter`].
    #[serde(default)]
    pub max_connections_per_identity: Option<usize>,
}

/// A [`dataglot_pgwire::PasswordSource`] backed by an in-memory map of
/// `username → cleartext password`, resolved from environment variables
/// at boot by [`build_auth_mode`].
///
/// The cleartext lives only in this struct's heap allocation; its
/// [`Debug`] impl deliberately renders neither the usernames nor the
/// passwords (CLAUDE.md rule 12).
#[derive(Clone)]
pub struct ConfigPasswordSource {
    creds: Arc<HashMap<String, String>>,
}

impl fmt::Debug for ConfigPasswordSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Redact: count only, never the secrets or the user list.
        f.debug_struct("ConfigPasswordSource")
            .field("users", &self.creds.len())
            .finish()
    }
}

#[async_trait::async_trait]
impl dataglot_pgwire::PasswordSource for ConfigPasswordSource {
    async fn password(&self, user: &str) -> Option<String> {
        self.creds.get(user).cloned()
    }
}

/// Build the pgwire [`AuthMode`](dataglot_pgwire::AuthMode) from config.
///
/// Trust mode maps straight through. MD5 and `scram-sha-256` mode both
/// resolve every identity's
/// [`password_env`](IdentityProfileConfig::password_env) via the process
/// environment into the same `username → cleartext`
/// [`ConfigPasswordSource`] (rule 12: the secret never appears in config,
/// only the env-var name) via one shared factory. Only the pgwire wire
/// protocol differs between the two.
///
/// # Errors
///
/// - An identity declares a `password_env` whose variable is unset or
///   empty (fail-fast on a misconfigured deployment).
/// - A password mode is selected but no identity yields a credential (the
///   server would reject every connection — almost certainly a mistake).
pub fn build_auth_mode<S: std::hash::BuildHasher>(
    auth: &AuthConfig,
    identities: &HashMap<String, IdentityProfileConfig, S>,
) -> Result<dataglot_pgwire::AuthMode> {
    build_auth_mode_with_env(auth, identities, &|n: &str| std::env::var(n))
}

/// Test-friendly variant of [`build_auth_mode`] that takes an injected
/// env-var lookup (avoids `std::env::set_var`, which is `unsafe fn` as
/// of Rust 1.92).
fn build_auth_mode_with_env<S: std::hash::BuildHasher>(
    auth: &AuthConfig,
    identities: &HashMap<String, IdentityProfileConfig, S>,
    env: &dyn Fn(&str) -> std::result::Result<String, std::env::VarError>,
) -> Result<dataglot_pgwire::AuthMode> {
    match auth.mode {
        AuthMode::Trust => Ok(dataglot_pgwire::AuthMode::Trust),
        // md5 and scram-sha-256 verify against the exact same credentials —
        // build the config-backed `PasswordSource` identically, and only the
        // pgwire wire-protocol wrapper differs.
        AuthMode::Md5 => Ok(dataglot_pgwire::AuthMode::Md5(
            build_config_password_source(identities, env, "md5")?,
        )),
        AuthMode::ScramSha256 => Ok(dataglot_pgwire::AuthMode::ScramSha256(
            build_config_password_source(identities, env, "scram-sha-256")?,
        )),
        AuthMode::Jwt => Ok(dataglot_pgwire::AuthMode::Jwt(Arc::new(
            build_jwt_verifier(auth.jwt.as_ref(), env)?,
        ))),
        AuthMode::Ldap => Ok(dataglot_pgwire::AuthMode::Ldap(Arc::new(
            build_ldap_authenticator(auth.ldap.as_ref(), env)?,
        ))),
    }
}

/// Build the pgwire [`JwtVerifier`](dataglot_pgwire::JwtVerifier) from
/// `[auth.jwt]` config.
///
/// The HS256 secret is read from the env var named by
/// [`JwtAuthConfig::secret_env`] (rule 12 — never inlined); RS256 / ES256 read
/// the PEM **public** key from [`JwtAuthConfig::public_key_file`]. The file
/// read is a one-shot at boot, before any connection is served.
///
/// # Errors
/// - `[auth.jwt]` is absent while `mode = "jwt"`.
/// - HS256 without a resolvable `secret_env`, or RS/ES without a readable
///   `public_key_file`.
/// - The key material fails to parse.
fn build_jwt_verifier(
    cfg: Option<&JwtAuthConfig>,
    env: &dyn Fn(&str) -> std::result::Result<String, std::env::VarError>,
) -> Result<dataglot_pgwire::JwtVerifier> {
    let cfg = cfg.ok_or_else(|| {
        anyhow::anyhow!("auth.mode=\"jwt\" requires an [auth.jwt] configuration block")
    })?;

    // Resolve the key material per algorithm. HS256 = shared secret (env);
    // RS256/ES256 = PEM public key (file).
    let key_material: Vec<u8> = match cfg.algorithm {
        JwtAlgorithmConfig::Hs256 => {
            let env_name = cfg.secret_env.as_deref().ok_or_else(|| {
                anyhow::anyhow!(
                    "auth.jwt.algorithm=\"hs256\" requires `secret_env` (the env var holding \
                     the HMAC shared secret)"
                )
            })?;
            let secret = env(env_name)
                .ok()
                .filter(|v| !v.is_empty())
                .ok_or_else(|| {
                    // Name the env var (not a secret) so the misconfig is debuggable.
                    anyhow::anyhow!(
                        "auth.jwt: secret_env {env_name:?} is unset or empty; every connection \
                     would be rejected"
                    )
                })?;
            secret.into_bytes()
        }
        JwtAlgorithmConfig::Rs256 | JwtAlgorithmConfig::Es256 => {
            let path = cfg.public_key_file.as_ref().ok_or_else(|| {
                anyhow::anyhow!(
                    "auth.jwt.algorithm={:?} requires `public_key_file` (the PEM public key)",
                    cfg.algorithm
                )
            })?;
            std::fs::read(path).with_context(|| {
                format!(
                    "auth.jwt: failed to read public_key_file {}",
                    path.display()
                )
            })?
        }
    };

    dataglot_pgwire::JwtVerifier::new(
        cfg.algorithm.to_pgwire(),
        &key_material,
        cfg.groups_claim.clone(),
        cfg.issuer.clone(),
        cfg.audience.clone(),
        cfg.leeway_secs,
    )
    .map_err(|e| anyhow::anyhow!("auth.jwt: {e}"))
}

/// Build the pgwire [`LdapAuthenticator`](dataglot_pgwire::LdapAuthenticator)
/// from `[auth.ldap]` config, backed by the real pure-Rust `ldap3`
/// connection.
///
/// When [`search_bind_dn`](LdapAuthConfig::search_bind_dn) is set, the
/// group-search connection binds as that read-only service account first —
/// its password is read once from
/// [`search_bind_password_env`](LdapAuthConfig::search_bind_password_env)
/// (rule 12 — never inlined) and held only inside the `ldap3` backend, never in
/// [`LdapConfig`]. Absent ⇒ the group search runs anonymously (back-compat).
///
/// # Errors
/// - `[auth.ldap]` is absent while `mode = "ldap"`.
/// - `search_bind_dn` is set without a `search_bind_password_env`, or that env
///   var is unset/empty.
fn build_ldap_authenticator(
    cfg: Option<&LdapAuthConfig>,
    env: &dyn Fn(&str) -> std::result::Result<String, std::env::VarError>,
) -> Result<dataglot_pgwire::LdapAuthenticator> {
    let cfg = cfg.ok_or_else(|| {
        anyhow::anyhow!("auth.mode=\"ldap\" requires an [auth.ldap] configuration block")
    })?;
    //: optional read-only service-account bind for the group search.
    let connection = match cfg.search_bind_dn.as_deref() {
        Some(dn) => {
            let env_name = cfg.search_bind_password_env.as_deref().ok_or_else(|| {
                anyhow::anyhow!(
                    "auth.ldap.search_bind_dn requires `search_bind_password_env` (the env var \
                     holding the service-account password)"
                )
            })?;
            let password = env(env_name)
                .ok()
                .filter(|v| !v.is_empty())
                .ok_or_else(|| {
                    // Name the env var (not the secret) so the misconfig is debuggable.
                    anyhow::anyhow!(
                        "auth.ldap.search_bind_password_env=\"{env_name}\" is unset or empty"
                    )
                })?;
            Arc::new(dataglot_pgwire::Ldap3Connection::with_search_bind(
                cfg.url.clone(),
                dn.to_string(),
                password,
            ))
        }
        None => Arc::new(dataglot_pgwire::Ldap3Connection::new(cfg.url.clone())),
    };
    Ok(dataglot_pgwire::LdapAuthenticator::new(
        dataglot_pgwire::LdapConfig {
            url: cfg.url.clone(),
            bind_dn_template: cfg.bind_dn_template.clone(),
            group_search_base: cfg.group_search_base.clone(),
            group_filter_template: cfg.group_filter.clone(),
            group_name_attr: cfg.group_name_attr.clone(),
        },
        connection,
    ))
}

/// Resolve every identity's [`password_env`](IdentityProfileConfig::password_env)
/// into a `username → cleartext` [`ConfigPasswordSource`], shared verbatim by
/// the md5 and `scram-sha-256` arms of [`build_auth_mode_with_env`] (rule 12:
/// the secret never appears in config, only the env-var name; only the count is
/// ever rendered).
///
/// `mode_label` names the selected mode in the fail-fast messages so a
/// misconfigured deployment is debuggable.
///
/// # Errors
/// - An identity declares a `password_env` whose variable is unset or empty.
/// - No identity yields a credential (the server would reject every connection).
fn build_config_password_source<S: std::hash::BuildHasher>(
    identities: &HashMap<String, IdentityProfileConfig, S>,
    env: &dyn Fn(&str) -> std::result::Result<String, std::env::VarError>,
    mode_label: &str,
) -> Result<Arc<ConfigPasswordSource>> {
    let mut creds = HashMap::new();
    for (user, profile) in identities {
        let Some(env_name) = profile.password_env.as_deref() else {
            continue;
        };
        let value = env(env_name).ok().filter(|v| !v.is_empty());
        let Some(value) = value else {
            // Name the env var (not a secret) so the misconfig is
            // debuggable; never log the value.
            anyhow::bail!(
                "auth.mode={mode_label}: identity {user:?} declares password_env \
                 {env_name:?} but that environment variable is unset or empty"
            );
        };
        creds.insert(user.clone(), value);
    }
    if creds.is_empty() {
        anyhow::bail!(
            "auth.mode={mode_label} but no identity has a resolvable password_env; \
             every connection would be rejected"
        );
    }
    Ok(Arc::new(ConfigPasswordSource {
        creds: Arc::new(creds),
    }))
}

/// One role definition — Apache Ranger role parity. A role is a named
/// collection of users and/or member groups.
///
/// ```json
///   "roles": {
///     "pii_reader": { "groups": ["analyst"], "users": ["alice"] }
///   }
/// ```
///
/// A session holds the role when its user is in `users` or any of its
/// groups is in `groups`. Held role names are folded into the session's
/// effective groups (see [`resolve_identity_with_roles`]).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RoleConfig {
    /// Users that are members of this role.
    #[serde(default)]
    pub users: Vec<String>,
    /// Groups whose members inherit this role.
    #[serde(default)]
    pub groups: Vec<String>,
}

/// One column-masking rule loaded from the JSON config.
///
/// The MVP only supports Utf8 literal masks (`mask_literal`). Future
/// enrichments — arbitrary SQL expressions, `CASE WHEN role = 'analyst'
/// THEN '***' ELSE email END`, etc. — will land as additional fields
/// on this struct without breaking existing configs.
///
/// JSON shape:
///
/// ```json
/// {
///   "table": "users",
///   "column": "email",
///   "mask_literal": "***@example.com"
/// }
/// ```
///
/// `table` accepts the three forms `DataFusion`'s `TableReference`
/// understands: bare (`users`), partial (`public.users`), and full
/// (`pg.public.users`). The form must match the shape `DataFusion`'s
/// SQL planner emits for the column reference at query time —
/// unqualified `SELECT email FROM users` produces a `Bare("users")`
/// reference, so a rule keyed on `pg.public.users` will not fire on
/// that query. See `dataglot-policy::mask::tests` for the convention.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaskConfig {
    /// Target table — bare, partial, or full reference.
    pub table: String,
    /// Target column name within `table`.
    pub column: String,
    /// Replacement value as a Utf8 literal. The masked field's data
    /// type must be Utf8 for the rewrite to type-check; non-Utf8
    /// columns will surface as a planner error at query time.
    ///
    /// Used when [`MaskConfig::mask_type`] is absent. Defaults to the
    /// empty string so a config that supplies `mask_type` can omit it.
    #[serde(default)]
    pub mask_literal: String,
    /// Named mask type (Apache Ranger parity — redact / partial / hash /
    /// nullify / date-year / constant). When present it takes precedence
    /// over [`MaskConfig::mask_literal`]. See [`MaskTypeConfig`].
    #[serde(default)]
    pub mask_type: Option<MaskTypeConfig>,
    /// **Custom mask expression** — an arbitrary SQL scalar expression
    /// evaluated in place of the column (Apache Ranger `MASK_CUSTOM`
    /// parity, and the mask analogue of the row-filter `sql` escape hatch).
    /// This is what makes *conditional* and *entitlement/mapping-driven*
    /// masks expressible — anything the fixed `mask_type` vocabulary can't
    /// say. The expression may reference the masked column by name, other
    /// columns, `CASE WHEN`, functions, and scalar subqueries against a
    /// mapping/entitlement table. Examples:
    ///
    /// - reveal only to entitled rows:
    ///   `CASE WHEN region = 'EU' THEN salary ELSE NULL END`
    /// - partial-by-condition:
    ///   `CASE WHEN char_length(email) > 40 THEN email ELSE '***' END`
    /// - mapping-table lookup:
    ///   `CASE WHEN email IN (SELECT email FROM entitled) THEN email ELSE '***' END`
    ///
    /// Highest precedence: when set it wins over `mask_type` /
    /// `mask_literal`. Setting both `mask_expr` and `mask_type` is a
    /// configuration error (two conflicting "how to mask" sources). Parsed
    /// once at boot; a malformed expression fails fast. Like the row-filter
    /// `sql` variant, identifiers resolve against a synthetic `Utf8` schema,
    /// so it's aimed at text columns (the common PII case).
    #[serde(default)]
    pub mask_expr: Option<String>,
    /// Precedence (Apache Ranger override/normal parity). When more than
    /// one mask rule targets the same `(table, column)`, the highest
    /// `priority` wins. A *tie* at the top priority stays a configuration
    /// error (the existing duplicate-rule guard) — set distinct
    /// priorities to layer policies. Defaults to `0`, so an unprioritized
    /// config behaves exactly as before (duplicates still rejected).
    #[serde(default)]
    pub priority: i32,
    /// Org-groups / roles this mask applies to ( — role-conditional
    /// masks). Absent / `null` = **all subjects**: the mask applies to every
    /// session regardless of group (the pre- default, so existing
    /// configs are unchanged). Non-empty = **group-scoped**: the mask applies
    /// only to a session whose org-groups intersect this list (the same
    /// `Identity.org_groups` that `access_deny` conditions on). Threaded into
    /// [`dataglot_policy::ColumnMask::groups`].
    #[serde(default)]
    pub groups: Option<Vec<String>>,
}

/// Named column-mask type loaded from config, mapping Apache Ranger's
/// built-in mask vocabulary onto [`dataglot_policy::MaskKind`].
///
/// ```json
///   { "table": "users", "column": "email",
///     "mask_type": { "kind": "show_last", "keep": 4 } }
/// ```
///
/// `kind` discriminates: `redact` | `show_last` | `show_first` |
/// `hash` | `nullify` | `date_year` | `constant`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MaskTypeConfig {
    /// Letters→`x`, digits→`n` (Ranger `MASK`).
    Redact,
    /// Show the last `keep` characters; mask the rest.
    ShowLast {
        /// Number of trailing characters left visible.
        keep: usize,
    },
    /// Show the first `keep` characters; mask the rest.
    ShowFirst {
        /// Number of leading characters left visible.
        keep: usize,
    },
    /// MD5 hex digest (Ranger `MASK_HASH`).
    Hash,
    /// Type-preserving `NULL` (Ranger `MASK_NULL`).
    Nullify,
    /// Date/timestamp truncated to the year (Ranger `MASK_DATE_SHOW_YEAR`).
    DateYear,
    /// Constant Utf8 literal — equivalent to `mask_literal`.
    Constant {
        /// The replacement value.
        value: String,
    },
}

impl MaskTypeConfig {
    /// Lower this config variant into the policy-engine [`MaskKind`].
    #[must_use]
    pub fn to_mask_kind(&self) -> MaskKind {
        match self {
            MaskTypeConfig::Redact => MaskKind::Redact,
            MaskTypeConfig::ShowLast { keep } => MaskKind::PartialShowLast(*keep),
            MaskTypeConfig::ShowFirst { keep } => MaskKind::PartialShowFirst(*keep),
            MaskTypeConfig::Hash => MaskKind::Hash,
            MaskTypeConfig::Nullify => MaskKind::Nullify,
            MaskTypeConfig::DateYear => MaskKind::DateYear,
            MaskTypeConfig::Constant { value } => MaskKind::Constant(value.clone()),
        }
    }
}

/// One access-deny rule loaded from config — Apache Ranger access-policy
/// parity.
///
/// ```json
///   { "table": "users", "column": "ssn", "groups": ["contractor"] }
///   { "table": "secrets" }            // deny the whole table, everyone
/// ```
///
/// `column` absent ⇒ deny the whole table. `groups` absent/empty ⇒ deny
/// for every identity; otherwise deny only sessions in a listed group.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessDenyConfig {
    /// Target table — bare, partial, or full reference.
    pub table: String,
    /// Column to deny within `table`; omit to deny the whole table.
    #[serde(default)]
    pub column: Option<String>,
    /// Groups the denial applies to. Empty ⇒ applies to everyone.
    #[serde(default)]
    pub groups: Vec<String>,
}

/// One column-level whitelist (positive column authorization, ) — the
/// slide-11 "column whitelist per role" model.
///
/// ```toml
/// [[column_grants]]
/// table   = "pg.public.employees"
/// columns = ["id", "name", "department"]   # the ONLY visible columns
/// groups  = ["QC-OpsAnalyst"]              # for these groups
/// # org   = "qatarcool"                    # optionally tenant-scoped
/// ```
///
/// For a matching identity, only `columns` are visible on `table`; every other
/// column is projected away (absent from the result — not masked, not null).
/// `groups` empty ⇒ applies to every subject; `org` absent ⇒ operator-wide.
/// Multiple grants on one table are **additive** (the visible set is their
/// union). A table with no applicable grant is unrestricted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ColumnGrantConfig {
    /// Target table — bare, partial, or full reference.
    pub table: String,
    /// The visible (whitelisted) columns on `table`.
    pub columns: Vec<String>,
    /// Tenant scope. Absent ⇒ operator-wide; `Some(org)` ⇒ only that org.
    #[serde(default)]
    pub org: Option<String>,
    /// Group scope. Empty ⇒ all subjects; otherwise only sessions in a
    /// listed group.
    #[serde(default)]
    pub groups: Vec<String>,
}

/// One derived data product whose column lineage is tracked so masks
/// propagate to it (Interface 4,  slice 4b).
///
/// At boot the server plans `sql` once and extracts column lineage,
/// registering the product as a node named `name` (qualified by
/// `catalog`/`schema`, defaulting to the server's
/// `default_catalog`/`default_schema`). A column mask on any source
/// column then extends to the product's columns that descend from it.
///
/// ```json
/// {
///   "name": "active_users",
///   "sql": "SELECT id, email FROM users WHERE active = true"
/// }
/// ```
///
/// `name` should match how the product is referenced at query time
/// (e.g. a registered view/table); `catalog`/`schema` should match
/// where it resolves, so the propagated (fully-qualified) mask matches
/// the query (the enforcer's `session_defaults` bridges bare queries).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DerivedProductConfig {
    /// The product's table name (as referenced in queries).
    pub name: String,
    /// The defining query — planned once at boot for lineage only.
    pub sql: String,
    /// Catalog the product resolves under. Defaults to the server's
    /// `default_catalog`.
    #[serde(default)]
    pub catalog: Option<String>,
    /// Schema the product resolves under. Defaults to the server's
    /// `default_schema`.
    #[serde(default)]
    pub schema: Option<String>,
    /// Backing type (, Trino-retirement slice 2). `Live` (default)
    /// plans the query on each read; `Materialized` refreshes a standalone
    /// warehouse table on a schedule (the detached-table model). Fixed at
    /// creation per the spec.
    #[serde(default)]
    pub backing: MaterializationBacking,
    /// Materialization settings — required when `backing = "materialized"`,
    /// ignored otherwise.
    #[serde(default)]
    pub materialization: Option<MaterializationConfig>,
}

/// How a derived product is backed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MaterializationBacking {
    /// Planned on each read (the Phase-1 behaviour).
    #[default]
    Live,
    /// Refreshed into a standalone warehouse table on a schedule.
    Materialized,
}

/// Materialization settings for a `Materialized` derived product.
///
/// The product's defining SQL is executed on the `refresh_every` cadence and
/// written (full-overwrite, blue-green) into `<warehouse>.<namespace>.<table>`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaterializationConfig {
    /// Name of the `kind = "warehouse"` catalog the table is written to.
    pub warehouse: String,
    /// Warehouse namespace (schema) for the materialized table.
    pub namespace: String,
    /// Materialized table name. Defaults to the product `name`.
    #[serde(default)]
    pub table: Option<String>,
    /// Refresh cadence — a duration like `30s`, `15m`, `1h`, `2d`.
    pub refresh_every: String,
}

/// Scheduled warehouse maintenance (Phase 4 Task 03). Compaction +
/// orphan-cleanup today; snapshot-expiry joins here once it lands (blocked
/// on an `iceberg-rust` upstream API — see
/// `docs/phases/phase-4/03-compaction-and-maintenance.md`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MaintenanceConfig {
    /// Tables to compact on a cadence. Each entry targets one warehouse
    /// table; see [`CompactionScheduleConfig`].
    #[serde(default)]
    pub compaction: Vec<CompactionScheduleConfig>,
    /// Namespaces to sweep for leftover blue-green maintenance artifacts
    /// (staging / parked tables from a crashed write); see
    /// [`OrphanCleanupConfig`].
    #[serde(default)]
    pub orphan_cleanup: Vec<OrphanCleanupConfig>,
}

/// One scheduled compaction target (Phase 4 Task 03).
///
/// Compaction rewrites `<warehouse>.<namespace>.<table>` into consolidated
/// data files on the `compact_every` cadence via the existing full-table
/// blue-green rewrite. It's aimed at **externally-written** tables (legacy
/// Trino during migration, future external writes) — Peaka's own
/// copy-on-write writes never fragment.
///
/// JSON shape (a `[[maintenance.compaction]]` list entry):
///
/// ```json
/// { "warehouse": "warehouse", "namespace": "sales", "table": "orders", "compact_every": "6h" }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompactionScheduleConfig {
    /// Name of the `kind = "warehouse"` catalog holding the table.
    pub warehouse: String,
    /// Warehouse namespace (schema) of the table.
    pub namespace: String,
    /// Table name within the namespace.
    pub table: String,
    /// Compaction cadence — a duration like `30m`, `6h`, `1d` (same
    /// grammar as `refresh_every`, parsed by [`parse_refresh_interval`]).
    pub compact_every: String,
}

/// One scheduled orphan-cleanup target (Phase 4 Task 03).
///
/// Sweeps `<warehouse>.<namespace>` on the `sweep_every` cadence, dropping
/// leftover blue-green **staging / parked** tables (from a write that
/// crashed mid-swap) older than `min_age`. The `min_age` grace window keeps
/// an in-flight write's staging table safe; user tables are never touched.
///
/// JSON shape (a `[[maintenance.orphan_cleanup]]` list entry):
///
/// ```json
/// { "warehouse": "warehouse", "namespace": "sales", "sweep_every": "1h", "min_age": "6h" }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrphanCleanupConfig {
    /// Name of the `kind = "warehouse"` catalog holding the namespace.
    pub warehouse: String,
    /// Warehouse namespace (schema) to sweep.
    pub namespace: String,
    /// Sweep cadence — a duration like `1h`, `1d` (parsed by
    /// [`parse_refresh_interval`]).
    pub sweep_every: String,
    /// Minimum age an artifact must reach before it's eligible to drop — the
    /// grace window protecting in-flight writes. A duration like `6h`.
    pub min_age: String,
}

/// Parse a simple `<n><unit>` duration (`s`/`m`/`h`/`d`) into a
/// [`std::time::Duration`].
///
/// Deliberately tiny — avoids a new dependency for the handful of cadence
/// strings materialization configs use. Whitespace is trimmed; the value
/// must be a positive integer followed by a single unit suffix.
///
/// # Errors
/// Returns a message if the string is empty, has no/unknown unit, the number
/// doesn't parse, or the duration is zero.
pub fn parse_refresh_interval(s: &str) -> std::result::Result<std::time::Duration, String> {
    let s = s.trim();
    let (num, unit) = s
        .split_at_checked(s.len().saturating_sub(1))
        .filter(|_| !s.is_empty())
        .ok_or_else(|| "empty refresh interval".to_string())?;
    let secs_per = match unit {
        "s" => 1u64,
        "m" => 60,
        "h" => 3600,
        "d" => 86_400,
        other => {
            return Err(format!(
                "refresh interval '{s}': unknown unit '{other}' (use s/m/h/d)"
            ))
        }
    };
    let n: u64 = num
        .trim()
        .parse()
        .map_err(|_| format!("refresh interval '{s}': '{num}' is not a positive integer"))?;
    let total = n
        .checked_mul(secs_per)
        .ok_or_else(|| format!("refresh interval '{s}': overflow"))?;
    if total == 0 {
        return Err(format!("refresh interval '{s}': must be greater than zero"));
    }
    Ok(std::time::Duration::from_secs(total))
}

/// One row-level filter rule loaded from the JSON config.
///
/// The MVP supports a small enumeration of declarative predicate
/// shapes — enough to land tenant-id filtering, "active rows
/// only", and similar without requiring a SQL-fragment parser at
/// boot. Future PRs can add a `predicate_sql` variant once we
/// have a session context at config-load time to parse against.
///
/// JSON shape:
///
/// ```json
/// {
///   "table": "users",
///   "predicate": {
///     "kind": "eq_string",
///     "column": "tenant_id",
///     "value": "acme"
///   }
/// }
/// ```
///
/// `table` follows the same `TableReference` rules as [`MaskConfig`].
/// See [`RowPredicateConfig`] for the supported predicate variants.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RowFilterConfig {
    /// Target table — bare, partial, or full reference.
    pub table: String,
    /// Predicate that must evaluate true for a row to survive.
    pub predicate: RowPredicateConfig,
    /// Org-groups / roles this filter applies to ( — role-conditional
    /// row filters). Absent / `null` = **all subjects**: the filter applies to
    /// every session regardless of group (the pre- default, so existing
    /// configs are unchanged). Non-empty = **group-scoped**: the filter applies
    /// only to a session whose org-groups intersect this list. Threaded into
    /// [`dataglot_policy::RowFilter::groups`].
    #[serde(default)]
    pub groups: Option<Vec<String>>,
}

/// Declarative predicate shapes accepted in [`RowFilterConfig`].
///
/// Each variant maps to a single `DataFusion` `Expr`:
///
/// | Variant       | Expr                                |
/// |---------------|-------------------------------------|
/// | `eq_string`   | `col(column).eq(lit(value: Utf8))`  |
/// | `eq_int`      | `col(column).eq(lit(value: Int64))` |
/// | `gt_int`      | `col(column).gt(lit(value: Int64))` |
/// | `sql`         | `SessionContext::parse_sql_expr(sql, …)` — arbitrary boolean SQL expression |
///
/// The declarative variants are convenience for common shapes; the
/// `sql` variant is the escape hatch for anything richer
/// (`AND` / `OR` / `IS NULL` / `LIKE` / `BETWEEN`, etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RowPredicateConfig {
    /// `column = '<value>'` against a Utf8 column.
    EqString {
        /// Column name to test.
        column: String,
        /// Literal value to compare against.
        value: String,
    },
    /// `column = <value>` against an Int64 column.
    EqInt {
        /// Column name to test.
        column: String,
        /// Literal value to compare against.
        value: i64,
    },
    /// `column > <value>` against an Int64 column.
    GtInt {
        /// Column name to test.
        column: String,
        /// Literal value to compare against.
        value: i64,
    },
    /// Arbitrary SQL expression — parsed at boot. Operators get the
    /// full SQL surface area for predicates: `AND` / `OR`,
    /// `IS NULL`, `LIKE`, `BETWEEN`, parenthesisation, etc.
    ///
    /// JSON shape:
    ///
    /// ```json
    /// {
    ///   "kind": "sql",
    ///   "sql": "tenant_id = 'acme' AND email LIKE '%@acme.com'"
    /// }
    /// ```
    ///
    /// Parse failures surface at boot, before any pgwire session is
    /// accepted — operators see the error in the server log instead
    /// of getting silently-broken queries.
    ///
    /// # Type-coercion caveat
    ///
    /// Boot-time parsing can't see the source's column types, so
    /// the parser builds a synthetic `DFSchema` where every
    /// referenced column is `Utf8`. At query time
    /// `DataFusion`'s `TypeCoercion` analyzer rebinds the column
    /// references to the real `TableScan` schema and inserts casts
    /// for compatible types — but a `Utf8` literal compared to an
    /// `Int32` column won't auto-coerce. Workarounds:
    ///
    /// * Use the declarative variants (`gt_int`, `eq_int`) — they
    ///   emit an explicit `cast(col, Int64)` and work for any
    ///   integer width.
    /// * Or write the cast in the SQL itself:
    ///   `CAST(id AS BIGINT) > 1`.
    ///
    /// `Utf8`-on-`Utf8` (the common shape for tenant-id /
    /// pattern-match filters) works without further effort.
    Sql {
        /// SQL fragment for a single boolean expression. Anything
        /// `parse_sql_expr` accepts; one expression, not a full
        /// statement.
        sql: String,
    },
}

/// Tag-based governance registry — Architecture Decisions §10.
///
/// Three lists, all flat, all `#[serde(default)]` and therefore
/// optional in the JSON config — omitted lists default to empty
/// `Vec`s. A section with all three empty is treated as absent
/// at boot (no `TagBasedEnforcer` layer is installed).
/// Build-time validation runs over whatever is declared, so a
/// partial config (e.g. tags only, policies and columns to
/// follow) is well-formed.
///
/// * `tags` — every tag the registry recognizes. A tag is a named
///   handle like `pii` or `pci`. Policies attach to tags; columns
///   carry tags.
/// * `policies` — the rules that fire when an authorized session
///   reads through a tagged column. A policy targets one tag and
///   one group; sessions whose identity includes that group
///   activate the rule.
/// * `columns` — the (table, column) → tag bindings. A single
///   column can carry multiple tags; the column-first walk feeds
///   the `TagBasedEnforcer`'s resolver.
///
/// JSON shape:
///
/// ```json
/// {
///   "tags": [
///     { "id": "pii", "org": "acme", "name": "PII" }
///   ],
///   "policies": [
///     {
///       "id": "mask-pii-analyst",
///       "org": "acme",
///       "tag": "pii",
///       "group": "analyst",
///       "rule": { "kind": "mask", "mask_literal": "***@example.com" }
///     }
///   ],
///   "columns": [
///     { "table": "users", "column": "email", "tags": ["pii"] }
///   ]
/// }
/// ```
///
/// Build-time validation rejects duplicate tag ids and policies /
/// columns that reference unknown tags — the same rules
/// `OrgGovernance::builder()` enforces. Errors surface at boot
/// before any pgwire session is accepted.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OrgGovernanceConfig {
    /// Every tag the registry recognizes.
    #[serde(default)]
    pub tags: Vec<TagDefinitionConfig>,
    /// Mask / row-filter rules attached to tags.
    #[serde(default)]
    pub policies: Vec<PolicyConfig>,
    /// `(table, column) → [tag]` bindings.
    #[serde(default)]
    pub columns: Vec<SemanticTableColumnConfig>,
}

/// One tag declaration.
///
/// JSON shape:
///
/// ```json
/// { "id": "pii", "org": "acme", "name": "PII" }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TagDefinitionConfig {
    /// Globally-unique tag id (within the registry's `org`).
    pub id: String,
    /// Owning organization.
    pub org: String,
    /// Human-readable display name.
    pub name: String,
}

/// One policy declaration.
///
/// JSON shape:
///
/// ```json
/// {
///   "id": "mask-pii-analyst",
///   "org": "acme",
///   "tag": "pii",
///   "group": "analyst",
///   "rule": { "kind": "mask", "mask_literal": "***@example.com" }
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    /// Globally-unique policy id.
    pub id: String,
    /// Owning organization.
    pub org: String,
    /// Tag this policy attaches to.
    pub tag: String,
    /// Group the policy applies to.
    pub group: String,
    /// What the rule does.
    pub rule: PolicyRuleConfig,
}

/// What a policy does — the same `Mask` / `RowFilter` choice the
/// underlying `dataglot_policy::RuleType` exposes, but in a
/// serde-friendly shape that uses the existing
/// [`RowPredicateConfig`] for predicates and a Utf8 literal for
/// masks.
///
/// `kind` discriminates: `"mask"` ⇒ Utf8 literal mask;
/// `"row_filter"` ⇒ predicate from the same vocabulary as
/// [`RowFilterConfig`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PolicyRuleConfig {
    /// Replace the column value with a Utf8 literal — same shape as
    /// [`MaskConfig::mask_literal`].
    Mask {
        /// Replacement value. Same Utf8-only constraint as
        /// [`MaskConfig`]; non-Utf8 columns surface as a planner
        /// error at query time.
        mask_literal: String,
    },
    /// Filter rows so the predicate must evaluate true. Reuses the
    /// existing [`RowPredicateConfig`] vocabulary (`eq_string`,
    /// `eq_int`, `gt_int`, `sql`).
    RowFilter {
        /// The predicate. See [`RowPredicateConfig`].
        predicate: RowPredicateConfig,
    },
}

/// A column-tag binding. A single column can carry multiple tags;
/// each tag is independently looked up in the policy table at
/// resolution time.
///
/// JSON shape:
///
/// ```json
/// { "table": "users", "column": "email", "tags": ["pii"] }
/// ```
///
/// `table` follows the same `TableReference` rules as
/// [`MaskConfig::table`] — bare, partial, or full.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SemanticTableColumnConfig {
    /// Target table — bare, partial, or full reference.
    pub table: String,
    /// Target column name within `table`.
    pub column: String,
    /// Tags the column carries.
    pub tags: Vec<String>,
}

/// A user-registered federated catalog.
///
/// One entry under `[catalogs.<name>]` in the config file becomes a
/// single registered catalog on every pgwire `SessionContext`. The
/// `kind` discriminator selects the underlying connector; the rest of
/// the fields are connector-specific.
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CatalogConfig {
    /// `PostgreSQL` source — see [`PostgresCatalogConfig`].
    Postgres(PostgresCatalogConfig),
    /// `MySQL` source — see [`MysqlCatalogConfig`].
    Mysql(MysqlCatalogConfig),
    /// Snowflake source — see [`SnowflakeCatalogConfig`]. Phase 1
    /// spec task 05. The federation connector
    /// (`dataglot-federation::snowflake`) and its catalog-listing
    /// path (`as_catalog_provider`, eager `INFORMATION_SCHEMA`
    /// enumeration) are both wired through [`build_one_connector`].
    Snowflake(SnowflakeCatalogConfig),
    /// Oracle source — see [`OracleCatalogConfig`]. Phase 3 spec
    /// task 04 (, Exadata displacement). Unlike the other SQL
    /// sources the connector is compiled only under the server's
    /// `oracle` feature (Oracle Instant Client is a C-runtime dep);
    /// the config surface is always present, and a `kind = "oracle"`
    /// catalog on a server built without the feature is rejected at
    /// boot by [`build_one_connector`] with a clear error.
    Oracle(OracleCatalogConfig),
    /// Lakehouse warehouse source (REST catalog + S3 storage) — see
    /// [`WarehouseCatalogConfig`]. Per CLAUDE.md rule 7 the underlying
    /// table format is never surfaced to users.
    Warehouse(WarehouseCatalogConfig),
    /// Direct object-storage table reads (parquet via
    /// `DataFusion`'s built-in `ListingTable`) — see
    /// [`ObjectStorageCatalogConfig`]. MVP is local filesystem
    /// only; S3 / GCS / ADLS land in a follow-up.
    ObjectStorage(ObjectStorageCatalogConfig),
    /// Generic OData v2 REST source — see [`OdataCatalogConfig`].
    /// Phase 4 task 01. A direct `TableProvider` (rule 3),
    /// not a SQL connector; each entity set is a table.
    Odata(OdataCatalogConfig),
    /// SAP S/4HANA OData source — see [`SapS4hanaCatalogConfig`].
    /// Phase 4 task 01. Same connector as [`Self::Odata`]
    /// plus the SAP `sap-client` / `sap-language` request headers.
    SapS4hana(SapS4hanaCatalogConfig),
    /// Generic ADBC BYO-driver source — see [`AdbcCatalogConfig`].
    /// Phase 3 task 02. Like `Oracle`, the config surface is
    /// always compiled but the connector only exists under the
    /// server's `adbc` feature; a `kind = "adbc"` catalog on a server
    /// built without it is rejected at boot with a clear error.
    Adbc(AdbcCatalogConfig),
    /// Generic REST/JSON source — see [`RestCatalogConfig`]. Phase 4
    ///. A direct `TableProvider` (rule 3), sibling of
    /// [`Self::Odata`]; unlike OData there's no metadata document, so each
    /// table's Arrow schema is declared. Pure-Rust, always compiled in.
    Rest(RestCatalogConfig),
}

impl fmt::Debug for CatalogConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Delegate to the inner config — each inner type has
        // a hand-written, redaction-aware `Debug` impl.
        match self {
            Self::Postgres(c) => f.debug_tuple("Postgres").field(c).finish(),
            Self::Mysql(c) => f.debug_tuple("Mysql").field(c).finish(),
            Self::Snowflake(c) => f.debug_tuple("Snowflake").field(c).finish(),
            Self::Oracle(c) => f.debug_tuple("Oracle").field(c).finish(),
            Self::Warehouse(c) => f.debug_tuple("Warehouse").field(c).finish(),
            Self::ObjectStorage(c) => f.debug_tuple("ObjectStorage").field(c).finish(),
            Self::Odata(c) => f.debug_tuple("Odata").field(c).finish(),
            Self::SapS4hana(c) => f.debug_tuple("SapS4hana").field(c).finish(),
            Self::Adbc(c) => f.debug_tuple("Adbc").field(c).finish(),
            Self::Rest(c) => f.debug_tuple("Rest").field(c).finish(),
        }
    }
}

impl CatalogConfig {
    /// Classify this catalog into a [`CatalogBinding`] for
    /// downstream consumers (catalog service, lineage event
    /// subtype, cache invalidation).
    ///
    /// Each variant maps deterministically:
    /// - `Postgres` / `Mysql` → `LiveConnector` with a
    ///   credential-redacted `endpoint_hint` derived from the
    ///   DSN host;
    /// - `Warehouse` → `IcebergCache` with the configured
    ///   `catalog_url` + `warehouse`; `table_path` empty at
    ///   boot (lazy resolution);
    /// - `ObjectStorage` → `LiveConnector` with the first
    ///   table's URL as the hint (or `"<no tables>"` for an
    ///   empty config — defensive, won't happen for valid
    ///   configs).
    ///
    /// Per CLAUDE.md rule 12 the binding never carries
    /// credentials. The `endpoint_hint` is the
    /// `<scheme>://<host>:<port>` form for SQL DSNs, with the
    /// userinfo segment stripped.
    #[must_use]
    pub fn binding(&self) -> CatalogBinding {
        match self {
            Self::Postgres(c) => CatalogBinding::LiveConnector(LiveConnectorBinding {
                kind: LiveConnectorKind::Postgres,
                endpoint_hint: redacted_endpoint_hint(c.dsn.as_deref(), c.dsn_env.as_deref()),
            }),
            Self::Mysql(c) => CatalogBinding::LiveConnector(LiveConnectorBinding {
                kind: LiveConnectorKind::Mysql,
                endpoint_hint: redacted_endpoint_hint(c.dsn.as_deref(), c.dsn_env.as_deref()),
            }),
            Self::Snowflake(c) => CatalogBinding::LiveConnector(LiveConnectorBinding {
                kind: LiveConnectorKind::Snowflake,
                // Snowflake doesn't have a DSN; the account
                // identifier is the public "host" equivalent
                // (`<orgname>-<accountname>` — appears verbatim in
                // the public Snowsight URL). Safe to surface as
                // the endpoint hint per CLAUDE.md rule 12.
                endpoint_hint: c.account.clone(),
            }),
            Self::Oracle(c) => CatalogBinding::LiveConnector(LiveConnectorBinding {
                kind: LiveConnectorKind::Oracle,
                // The Oracle DSN is an Easy Connect string
                // (`//host:port/service`); credentials are passed
                // separately (user + password/password_env), never in
                // the DSN, so the common case is the literal DSN. The
                // helper additionally strips any `user/pass@` userinfo
                // prefix as defense-in-depth (CLAUDE.md rule 12).
                endpoint_hint: redacted_oracle_endpoint_hint(&c.dsn),
            }),
            Self::Warehouse(c) => CatalogBinding::IcebergCache(IcebergCacheBinding {
                catalog_url: c.catalog_url.clone(),
                warehouse: c.warehouse.clone(),
                table_path: Vec::new(),
            }),
            Self::ObjectStorage(c) => CatalogBinding::LiveConnector(LiveConnectorBinding {
                kind: LiveConnectorKind::ObjectStorage,
                endpoint_hint: c
                    .tables
                    .first()
                    .map_or_else(|| "<no tables>".to_string(), |t| t.url.clone()),
            }),
            // The service URL carries no credentials (auth is a separate
            // field), so it's safe as the endpoint hint (CLAUDE.md rule 12).
            Self::Odata(c) => CatalogBinding::LiveConnector(LiveConnectorBinding {
                kind: LiveConnectorKind::Odata,
                endpoint_hint: c.service_url.clone(),
            }),
            Self::SapS4hana(c) => CatalogBinding::LiveConnector(LiveConnectorBinding {
                kind: LiveConnectorKind::Odata,
                endpoint_hint: c.service_url.clone(),
            }),
            // The ADBC `uri` may embed userinfo (driver-dependent), so
            // the hint is derived from the credential-free driver path
            // instead (rule 12: never risk a credential in a binding).
            Self::Adbc(c) => CatalogBinding::LiveConnector(LiveConnectorBinding {
                kind: LiveConnectorKind::Adbc,
                endpoint_hint: format!("adbc:{}", c.driver_path),
            }),
            // A table URL may embed a query string but never credentials
            // (auth is a separate field), so the first table's URL is a safe
            // hint (rule 12). `<no tables>` is defensive — boot rejects an
            // empty table list.
            Self::Rest(c) => CatalogBinding::LiveConnector(LiveConnectorBinding {
                kind: LiveConnectorKind::Rest,
                endpoint_hint: c
                    .tables
                    .first()
                    .map_or_else(|| "<no tables>".to_string(), |t| t.url.clone()),
            }),
        }
    }

    /// Whether this catalog is a federated **SQL** source — one that
    /// `datafusion-federation` plans as a `VirtualExecutionPlan`
    /// (Postgres / MySQL / Snowflake / Oracle / Adbc).
    ///
    /// Only these can produce the cross-source federation node that
    /// triggers the `datafusion-federation 0.5.3` filter-pushdown
    /// correctness bug (see `SessionContextFactory::create_federated_context`
    /// in `dataglot-core`). `Warehouse` (Iceberg) and `ObjectStorage`
    /// are served by plain
    /// `TableProvider`s — no `VirtualExecutionPlan`, so a server built
    /// only from those needs no `FilterPushdown` strip and keeps
    /// scan-time parquet pushdown.
    #[must_use]
    pub fn requires_federation(&self) -> bool {
        // OData / SAP / REST are direct `TableProvider`s (rule 3) — like
        // Warehouse / ObjectStorage, they produce no `VirtualExecutionPlan`,
        // so they don't need the federation filter-pushdown strip.
        // Adbc is a `SQLExecutor` source like the four bespoke SQL
        // connectors — without this classification its
        // `FederatedTableProviderAdaptor` never gets rewritten and
        // every scan fails with "cannot scan".
        matches!(
            self,
            Self::Postgres(_)
                | Self::Mysql(_)
                | Self::Snowflake(_)
                | Self::Oracle(_)
                | Self::Adbc(_)
        )
    }
}

/// Render a credential-safe endpoint hint for SQL DSN
/// configs. CLAUDE.md rule 12: the hint is what the catalog-
/// service UI surfaces; no password / user portion of the DSN
/// ever appears here.
///
/// Falls back to `"<env:VAR>"` when the literal DSN is not
/// set (env-var indirection — we don't resolve env vars at
/// hint-build time; that's an execution-time concern). Falls
/// back to `"<unset>"` if neither is configured (defensive;
/// the surrounding config validation rejects this case before
/// the binding is built).
fn redacted_endpoint_hint(dsn: Option<&str>, dsn_env: Option<&str>) -> String {
    if let Some(dsn) = dsn {
        // Strip userinfo from a `<scheme>://user:pass@host:port/...`
        // shape. Best-effort: if the DSN doesn't parse as that
        // shape (e.g. libpq's `host=... user=...` form), fall
        // back to `<host: redacted>` so we never leak the
        // literal DSN to the UI.
        if let Some(after_scheme) = dsn.find("://") {
            let scheme = &dsn[..after_scheme];
            let rest = &dsn[after_scheme + 3..];
            // Drop userinfo if `@` appears before the first `/`.
            let path_start = rest.find('/').unwrap_or(rest.len());
            let authority = &rest[..path_start];
            let host_port = match authority.rfind('@') {
                Some(at) => &authority[at + 1..],
                None => authority,
            };
            return format!("{scheme}://{host_port}");
        }
        return "<host: redacted>".to_string();
    }
    if let Some(env_name) = dsn_env {
        return format!("<env:{env_name}>");
    }
    "<unset>".to_string()
}

/// Render a credential-safe endpoint hint for an Oracle Easy Connect
/// DSN. CLAUDE.md rule 12.
///
/// Oracle Easy Connect (`[//]host[:port][/service]`) carries no
/// credentials — `user` / `password` are separate config fields — so
/// the common case returns the DSN verbatim (and, unlike the
/// `<scheme>://`-oriented [`redacted_endpoint_hint`], preserves the
/// useful host:port/service the catalog-service UI wants to show).
/// Defense-in-depth: if an operator nonetheless embeds a `user/pass@`
/// userinfo prefix (some Oracle tooling accepts
/// `user/pass@//host/service`), everything up to and including the
/// last `@` is stripped so the prefix never reaches logs / catalog
/// metadata.
fn redacted_oracle_endpoint_hint(dsn: &str) -> String {
    match dsn.rfind('@') {
        Some(at) => dsn[at + 1..].to_string(),
        None => dsn.to_string(),
    }
}

/// `PostgreSQL` catalog configuration.
///
/// Exactly one of `dsn` (literal) or `dsn_env` (name of the env var that
/// holds the DSN) must be set. The env-var indirection exists so that
/// production deployments can keep the DSN out of the on-disk config.
///
/// # Redaction
///
/// `Debug` never prints the literal DSN — only an indication that one
/// was set. CLAUDE.md rule 12.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct PostgresCatalogConfig {
    /// Literal libpq DSN. Mutually exclusive with `dsn_env` / `dsn_secret`.
    #[serde(default)]
    pub dsn: Option<String>,
    /// Name of an environment variable holding the DSN. Resolved at
    /// boot, never logged.
    #[serde(default)]
    pub dsn_env: Option<String>,
    /// Name of a control-plane **secret** holding the DSN.
    /// This is the value persisted in the meta store — the *reference*, never
    /// the DSN itself (rule 12) — resolved + decrypted at connect-build time.
    /// Set via `CREATE CATALOG … WITH (kind='postgres', dsn_secret='<name>')`
    /// after a matching `CREATE SECRET`. Mutually exclusive with `dsn`/`dsn_env`.
    #[serde(default)]
    pub dsn_secret: Option<String>,
    /// Source-connection TLS mode. `disable` (default) connects in
    /// plaintext; `require` negotiates TLS (encrypted; the server
    /// certificate is verified — see `tls_ca_file` /
    /// `tls_accept_invalid_certs`). A DSN `sslmode=require` also enables
    /// TLS with secure defaults even when this is left `disable`.
    #[serde(default)]
    pub tls: SourceTlsMode,
    /// PEM CA-bundle file used to verify the server certificate under
    /// `tls = "require"`. `None` ⇒ the OS/corporate trust store. Set
    /// this for a private-CA / self-signed source. Not a secret (a
    /// public certificate), so it is safe to keep in config.
    #[serde(default)]
    pub tls_ca_file: Option<std::path::PathBuf>,
    /// **DANGER, dev/test only** — skip server-certificate
    /// verification under `tls = "require"`. Leaves the connection
    /// open to MITM; never set in production.
    #[serde(default)]
    pub tls_accept_invalid_certs: bool,
}

/// Source-connection TLS mode for a SQL catalog (`[catalogs.*] tls`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SourceTlsMode {
    /// Plaintext (the pre-TLS default). A DSN `sslmode=require` can
    /// still opt into TLS with secure defaults.
    #[default]
    Disable,
    /// Negotiate TLS; verify the server certificate.
    Require,
}

impl fmt::Debug for PostgresCatalogConfig {
    /// Credential-safe `Debug`. The literal DSN is replaced with
    /// `<redacted>`; the env-var **name** is shown (it is not itself
    /// secret — it is the indirection key).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PostgresCatalogConfig")
            .field(
                "dsn",
                &if self.dsn.is_some() {
                    "<redacted>"
                } else {
                    "<unset>"
                },
            )
            .field("dsn_env", &self.dsn_env)
            // A secret *name*, not a value — safe to show (rule 12).
            .field("dsn_secret", &self.dsn_secret)
            .field("tls", &self.tls)
            .field("tls_ca_file", &self.tls_ca_file)
            .field("tls_accept_invalid_certs", &self.tls_accept_invalid_certs)
            .finish()
    }
}

/// `MySQL` catalog configuration.
///
/// Mirrors [`PostgresCatalogConfig`] one-for-one. Exactly one of
/// `dsn` (literal) or `dsn_env` (name of the env var that holds the
/// DSN) must be set. The env-var indirection exists so that
/// production deployments can keep the DSN out of the on-disk
/// config.
///
/// # Redaction
///
/// `Debug` never prints the literal DSN — only an indication that
/// one was set. CLAUDE.md rule 12.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct MysqlCatalogConfig {
    /// Literal `mysql_async` DSN, of the form
    /// `mysql://user:pass@host:port/db`. Mutually exclusive with
    /// `dsn_env`.
    #[serde(default)]
    pub dsn: Option<String>,
    /// Name of an environment variable holding the DSN. Resolved
    /// at boot, never logged.
    #[serde(default)]
    pub dsn_env: Option<String>,
    /// Source-connection TLS mode. `disable` (default) connects in
    /// plaintext; `require` negotiates TLS and verifies the server
    /// certificate (see `tls_ca_file` / `tls_accept_invalid_certs`).
    #[serde(default)]
    pub tls: SourceTlsMode,
    /// PEM CA-bundle file used to verify the server certificate under
    /// `tls = "require"`. `None` ⇒ the bundled Mozilla trust set. A
    /// public certificate, so it is safe to keep in config.
    #[serde(default)]
    pub tls_ca_file: Option<std::path::PathBuf>,
    /// **DANGER, dev/test only** — skip server-certificate verification
    /// (and hostname validation) under `tls = "require"`. Never in
    /// production (MITM-open).
    #[serde(default)]
    pub tls_accept_invalid_certs: bool,
}

impl fmt::Debug for MysqlCatalogConfig {
    /// Credential-safe `Debug`. The literal DSN is replaced with
    /// `<redacted>`; the env-var **name** is shown (it is not
    /// itself secret — it is the indirection key).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MysqlCatalogConfig")
            .field(
                "dsn",
                &if self.dsn.is_some() {
                    "<redacted>"
                } else {
                    "<unset>"
                },
            )
            .field("dsn_env", &self.dsn_env)
            .field("tls", &self.tls)
            .field("tls_ca_file", &self.tls_ca_file)
            .field("tls_accept_invalid_certs", &self.tls_accept_invalid_certs)
            .finish()
    }
}

/// Snowflake catalog configuration.
///
/// Snowflake's REST API authenticates with several discrete fields
/// rather than a single DSN; each is its own typed field here.
/// Exactly one of `password` (literal) or `password_env` (name of
/// the env var holding the password) must be set. The env-var
/// indirection exists so production deployments can keep the
/// password out of the on-disk config (CLAUDE.md rule 12).
///
/// # Redaction
///
/// `Debug` never prints the literal password — only an indication
/// that one was set. Other auth-adjacent fields (`user`, `role`)
/// are also redacted — they can leak organisation structure to log
/// readers even though they're not strictly credentials. The
/// account / warehouse / database / schema fields are operational
/// targeting metadata and stay visible so operators can identify
/// which catalog a log line refers to.
///
/// # Pairs with
///
/// `dataglot_federation::snowflake::SnowflakeConfig` carries the
/// same shape on the federation side. The two are deliberately
/// separate types — the server is a peer of `dataglot-federation`,
/// not a downstream consumer (CLAUDE.md rule 4) — but the field
/// names match so an operator inspecting both sees the same
/// vocabulary.
#[derive(Clone, Serialize, Deserialize)]
pub struct SnowflakeCatalogConfig {
    /// Snowflake account identifier, e.g. `acme-corp.us-east-1`.
    /// Appears in the public Snowsight URL; not a credential.
    pub account: String,
    /// Compute warehouse, e.g. `COMPUTE_WH`.
    pub warehouse: String,
    /// Default database, e.g. `ANALYTICS`.
    pub database: String,
    /// Service-account username.
    pub user: String,
    /// Literal Snowflake password. Mutually exclusive with
    /// `password_env`. Production deployments should prefer the
    /// env-var indirection — a literal here is an explicit
    /// dev-only escape hatch.
    #[serde(default)]
    pub password: Option<String>,
    /// Name of an environment variable holding the Snowflake
    /// password. Mutually exclusive with `password`. Resolved at
    /// boot, never logged.
    #[serde(default)]
    pub password_env: Option<String>,
    /// Name of an environment variable holding the **RSA private key**
    /// (PEM) for key-pair (JWT) auth. When set and non-empty, the
    /// connector uses key-pair auth instead of password — the
    /// non-interactive path that isn't blocked by the account's MFA
    /// requirement. Resolved at boot, never logged. When
    /// present, `password`/`password_env` become optional.
    #[serde(default)]
    pub private_key_env: Option<String>,
    /// Optional default schema (`PUBLIC`-style) for unqualified
    /// table references.
    #[serde(default)]
    pub schema: Option<String>,
    /// Optional warehouse-role override. Useful when the service
    /// account's default role doesn't match what the source needs.
    #[serde(default)]
    pub role: Option<String>,
}

impl fmt::Debug for SnowflakeCatalogConfig {
    /// Credential-safe `Debug` per CLAUDE.md rule 12.
    ///
    /// Visible: `account`, `warehouse`, `database`, `schema`,
    /// `password_env` / `private_key_env` (env-var names, not their
    /// values). Redacted: `password` (literal), `user` (auth-adjacent —
    /// service-account names leak org structure), `role` (same
    /// reasoning).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SnowflakeCatalogConfig")
            .field("account", &self.account)
            .field("warehouse", &self.warehouse)
            .field("database", &self.database)
            .field("schema", &self.schema)
            .field("user", &"<redacted>")
            .field("role", &"<redacted>")
            .field(
                "password",
                &if self.password.is_some() {
                    "<redacted>"
                } else {
                    "<unset>"
                },
            )
            .field("password_env", &self.password_env)
            .field("private_key_env", &self.private_key_env)
            .finish()
    }
}

/// Which Oracle wire backend a catalog uses. Maps to
/// `dataglot_federation::oracle::OracleDriver` (a feature-gated type, so
/// not linked here). Parsed from `driver = "oci" | "pure"`; omitted → the
/// build default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OracleDriverConfig {
    /// OCI / ODPI-C — needs `--features oracle` (C runtime dep).
    Oci,
    /// Pure-Rust (oracle-rs) — needs `--features oracle-pure` (no C).
    Pure,
}

/// Oracle catalog configuration — Phase 3 spec task 04.
///
/// Declared under `[catalogs.<name>]` with `kind = "oracle"`:
///
/// ```toml
/// [catalogs.exadata]
/// kind = "oracle"
/// dsn = "//db.internal:1521/ORCLPDB1"   # Oracle Easy Connect
/// user = "DATAGLOT_SVC"
/// password_env = "EXADATA_PASSWORD"
/// # optional: schema = "SALES"
/// # optional: driver = "oci"   # or "pure" — defaults to the build's
/// #                            # default backend (OCI if compiled)
/// ```
///
/// # Credentials
///
/// The `dsn` is an Oracle Easy Connect string
/// (`//host:port/service`) and carries **no** userinfo — `user` and
/// the password (literal `password` or `password_env` indirection)
/// are separate fields. Per CLAUDE.md rule 12 the password never
/// appears in `Debug`/logs; the `user` is redacted too
/// (service-account names leak org structure), matching the
/// Snowflake config's treatment.
///
/// # Pairs with
///
/// `dataglot_federation::oracle::OracleConnector::connect_with_driver(name,
/// dsn, user, password, driver)` on the federation side (the `driver`
/// maps from [`OracleDriverConfig`]). The server is a peer of
/// `dataglot-federation`, not a downstream consumer (CLAUDE.md rule
/// 4); the field vocabulary is kept aligned deliberately.
#[derive(Clone, Serialize, Deserialize)]
pub struct OracleCatalogConfig {
    /// Oracle Easy Connect DSN, e.g. `//db.internal:1521/ORCLPDB1`.
    /// No credentials embedded — surfaced verbatim as the binding's
    /// endpoint hint.
    pub dsn: String,
    /// Service-account username. Oracle folds unquoted identifiers
    /// to uppercase; introspection uses the uppercased owner.
    pub user: String,
    /// Literal Oracle password. Mutually exclusive with
    /// `password_env`. Production deployments should prefer the
    /// env-var indirection — a literal here is an explicit dev-only
    /// escape hatch.
    #[serde(default)]
    pub password: Option<String>,
    /// Name of an environment variable holding the Oracle password.
    /// Mutually exclusive with `password`. Resolved at boot, never
    /// logged.
    #[serde(default)]
    pub password_env: Option<String>,
    /// Optional default schema (owner) for unqualified table
    /// references. Oracle owners are uppercase.
    #[serde(default)]
    pub schema: Option<String>,
    /// Optional wire backend selection. `None` → the build's
    /// default (OCI when `--features oracle` is compiled). Selecting a
    /// driver whose feature was not compiled in fails fast at boot with
    /// a clear, credential-free error.
    #[serde(default)]
    pub driver: Option<OracleDriverConfig>,
}

impl fmt::Debug for OracleCatalogConfig {
    /// Credential-safe `Debug` per CLAUDE.md rule 12.
    ///
    /// Visible: `dsn` (credential-free Easy Connect string),
    /// `schema`, `password_env` (the env-var name, not its value).
    /// Redacted: `password` (literal), `user` (auth-adjacent).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OracleCatalogConfig")
            .field("dsn", &self.dsn)
            .field("schema", &self.schema)
            .field("driver", &self.driver)
            .field("user", &"<redacted>")
            .field(
                "password",
                &if self.password.is_some() {
                    "<redacted>"
                } else {
                    "<unset>"
                },
            )
            .field("password_env", &self.password_env)
            .finish()
    }
}

/// Generic ADBC catalog configuration — Phase 3 spec task 02 (,
/// BYO-driver federation for breadth-tail sources).
///
/// Declared under `[catalogs.<name>]` with `kind = "adbc"`:
///
/// ```toml
/// [catalogs.warehouse]
/// kind = "adbc"
/// driver_path = "/usr/local/lib/libadbc_driver_postgresql.so"
/// uri = "postgresql://host/db"
/// username = "svc_dataglot"
/// password_env = "WAREHOUSE_PASSWORD"
/// driver_options = "sslmode=require;application_name=dataglot"
/// dialect = "postgresql"
/// ```
///
/// `dialect` is **mandatory** and restricted to the unparser dialects
/// DataFusion ships (`postgresql | mysql | sqlite | duckdb | bigquery`);
/// an unknown value is rejected at boot with a message naming the
/// supported set. TLS posture is the driver's contract via
/// `driver_options` — configure your driver for TLS in production.
///
/// # Credentials
///
/// The password comes only from `password_env` (resolved at connect,
/// never stored). The `uri` may embed userinfo for drivers that demand
/// it, so `Debug` redacts it wholesale; `driver_options` values are
/// redacted too (tokens, key material). Per CLAUDE.md rule 12 none of
/// these surface in logs or errors.
///
/// # Pairs with
///
/// `dataglot_federation::adbc::AdbcConnector::connect(AdbcConfig)` on
/// the federation side; the field vocabulary is kept aligned
/// deliberately (CLAUDE.md rule 4 — the server is a peer, not a
/// downstream consumer).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdbcCatalogConfig {
    /// Path to the ADBC driver shared library (`.so`/`.dylib`/`.dll`).
    /// Explicit path only — no discovery.
    pub driver_path: String,
    /// Driver init symbol override for drivers whose entrypoint is not
    /// derivable from the filename (e.g. `libduckdb` exports
    /// `duckdb_adbc_init`).
    #[serde(default)]
    pub driver_entrypoint: Option<String>,
    /// Connection URI (standard ADBC `uri` option). Optional — some
    /// drivers connect purely via `driver_options` key/values; at
    /// least one of the two must be set.
    #[serde(default)]
    pub uri: Option<String>,
    /// Username (standard ADBC `username` option).
    #[serde(default)]
    pub username: Option<String>,
    /// Name of an environment variable holding the password. Resolved
    /// at boot, handed to the driver, never stored or logged.
    #[serde(default)]
    pub password_env: Option<String>,
    /// Extra driver options as `key=value;key=value`. Values are
    /// treated as secrets in `Debug` output.
    #[serde(default)]
    pub driver_options: Option<String>,
    /// Source-side catalog scope, where the driver distinguishes
    /// catalogs.
    #[serde(default)]
    pub catalog: Option<String>,
    /// Source-side schema scope for catalog discovery.
    #[serde(default)]
    pub schema: Option<String>,
    /// Mandatory SQL dialect for federation unparsing. Validated at
    /// boot against the strict whitelist.
    pub dialect: String,
    /// Pool size — max concurrent in-flight queries on this catalog.
    #[serde(default = "default_adbc_pool_size")]
    pub connection_pool_size: usize,
    /// Connections opened eagerly at boot; the rest open lazily.
    #[serde(default = "default_adbc_pool_min_idle")]
    pub connection_pool_min_idle: usize,
}

/// Spec default: 4 pooled connections per ADBC catalog.
fn default_adbc_pool_size() -> usize {
    4
}

/// Spec default: 1 eager connection (fail fast on bad credentials
/// without paying for a full pool up front).
fn default_adbc_pool_min_idle() -> usize {
    1
}

impl fmt::Debug for AdbcCatalogConfig {
    /// Credential-safe `Debug` per CLAUDE.md rule 12.
    ///
    /// Visible: `driver_path`, `dialect`, scopes, pool sizing,
    /// `password_env` (the env-var name, not its value). Redacted:
    /// `uri` (may embed userinfo), `username` (auth-adjacent, matching
    /// the Oracle/Snowflake treatment), `driver_options` values
    /// (tokens / key material — keys aren't distinguishable here
    /// without parsing, so the whole string is redacted).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AdbcCatalogConfig")
            .field("driver_path", &self.driver_path)
            .field("driver_entrypoint", &self.driver_entrypoint)
            .field("uri", &self.uri.as_ref().map(|_| "<redacted>"))
            .field("username", &self.username.as_ref().map(|_| "<redacted>"))
            .field("password_env", &self.password_env)
            .field(
                "driver_options",
                &self.driver_options.as_ref().map(|_| "<redacted>"),
            )
            .field("catalog", &self.catalog)
            .field("schema", &self.schema)
            .field("dialect", &self.dialect)
            .field("connection_pool_size", &self.connection_pool_size)
            .field("connection_pool_min_idle", &self.connection_pool_min_idle)
            .finish()
    }
}

/// Lakehouse warehouse catalog configuration.
///
/// All fields are forwarded to
/// `dataglot_federation::iceberg::WarehouseConnector::connect` at boot.
/// Credentials live in [`WarehouseCredentialsConfig`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WarehouseCatalogConfig {
    /// Base URL of the warehouse REST catalog (e.g.
    /// `http://lakekeeper:8181/catalog`).
    pub catalog_url: String,
    /// Logical warehouse identifier within the catalog.
    pub warehouse: String,
    /// How to obtain S3 credentials for the underlying object store.
    pub credentials: WarehouseCredentialsConfig,
    /// Optional S3 endpoint (used when the object store is something
    /// other than AWS S3, like `MinIO`).
    pub s3_endpoint: Option<String>,
    /// Optional S3 region (e.g. `us-east-1`).
    pub s3_region: Option<String>,
}

/// How a warehouse credential is sourced.
///
/// Mirrors `dataglot_federation::iceberg::WarehouseCredentials` at the
/// config layer. A first-class `CredentialResolver` abstraction in
/// `dataglot-core` will replace this in a future Phase (see "trait gaps"
/// in this PR's description).
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WarehouseCredentialsConfig {
    /// Read credentials from the standard AWS environment variables.
    Environment,
    /// Static credentials. `secret_access_key_env` overrides
    /// `secret_access_key` when both are set.
    Static {
        /// S3 access-key id. Not itself a secret — kept visible for ops.
        access_key_id: String,
        /// Literal secret-access-key. Mutually exclusive in spirit
        /// with `secret_access_key_env`; if both are set the env-var
        /// value wins. Redacted in `Debug`.
        secret_access_key: Option<String>,
        /// Name of an environment variable holding the secret-access
        /// key. The variable's **value** is never logged or
        /// surfaced; only the variable name is.
        secret_access_key_env: Option<String>,
    },
}

impl fmt::Debug for WarehouseCredentialsConfig {
    /// Credential-safe `Debug`. The static `secret_access_key` is
    /// replaced with `<redacted>`. CLAUDE.md rule 12.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Environment => f.write_str("Environment"),
            Self::Static {
                access_key_id,
                secret_access_key,
                secret_access_key_env,
            } => f
                .debug_struct("Static")
                .field("access_key_id", access_key_id)
                .field(
                    "secret_access_key",
                    &if secret_access_key.is_some() {
                        "<redacted>"
                    } else {
                        "<unset>"
                    },
                )
                .field("secret_access_key_env", secret_access_key_env)
                .finish(),
        }
    }
}

/// Object-storage catalog configuration. Direct parquet reads via
/// `DataFusion`'s built-in `ListingTable` + `object_store` plumbing
/// — no SQL pushdown ceremony, just file → Arrow `RecordBatch`.
///
/// JSON shape:
///
/// ```json
/// {
///   "kind": "object_storage",
///   "s3": { "endpoint": "http://minio:9000", "region": "us-east-1",
///           "access_key_id": "AKIA...", "secret_access_key_env": "S3_SECRET" },
///   "tables": [
///     { "name": "users", "url": "s3://bucket/users.parquet", "format": "parquet" },
///     { "name": "events", "url": "file:///data/events.csv", "format": "csv", "schema": "raw" },
///     { "name": "logs", "url": "file:///data/logs.json", "format": "json" }
///   ]
/// }
/// ```
///
/// Formats: `parquet`, `csv` (header assumed), and `json` (newline-
/// delimited). Schemes: `file://` always; `s3://` when the optional
/// `[s3]` block is present (GCS / ADLS are future follow-ups). All
/// backed by `DataFusion`'s `ListingTable`, so glob URLs
/// (`.../part-*.parquet`) work. See.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectStorageCatalogConfig {
    /// Optional S3 access for `s3://` table URLs. When absent, only
    /// `file://` tables are allowed. See [`ObjectStorageS3Config`].
    #[serde(default)]
    pub s3: Option<ObjectStorageS3Config>,
    /// Tables this catalog exposes. Each one becomes a queryable
    /// Arrow-shaped table on every pgwire `SessionContext` —
    /// reachable as `<catalog>.<schema>.<name>` (where `<schema>`
    /// defaults to `"public"` if not declared).
    pub tables: Vec<ObjectStorageTableConfig>,
}

/// S3 access for an [`ObjectStorageCatalogConfig`]'s `s3://` tables.
///
/// Mirrors the credential shape the warehouse connector already uses:
/// static `access_key_id` + `secret_access_key` (or its `*_env` twin,
/// which wins — rule 12, no inline secret needed). `endpoint` targets
/// S3-compatibles (`MinIO`, R2, …); omit it for real AWS. `region`
/// defaults to `us-east-1`. `path_style_access` (default `true`) suits
/// `MinIO` and most self-hosted gateways; set `false` for virtual-hosted
/// AWS buckets.
#[derive(Clone, Serialize, Deserialize)]
pub struct ObjectStorageS3Config {
    /// Custom endpoint for S3-compatible stores (e.g. `http://minio:9000`).
    /// Omit for AWS S3.
    #[serde(default)]
    pub endpoint: Option<String>,
    /// AWS region. Defaults to `us-east-1` when omitted.
    #[serde(default)]
    pub region: Option<String>,
    /// Access key id (non-secret). Required for private buckets.
    #[serde(default)]
    pub access_key_id: Option<String>,
    /// Secret access key, inline (dev-only escape hatch).
    #[serde(default)]
    pub secret_access_key: Option<String>,
    /// Name of an env var holding the secret access key. Overrides
    /// `secret_access_key` when both are set (rule 12).
    #[serde(default)]
    pub secret_access_key_env: Option<String>,
    /// Path-style addressing (`http://host/bucket/key`). Default `true`
    /// (`MinIO` / most self-hosted). Set `false` for virtual-hosted AWS.
    #[serde(default = "default_true")]
    pub path_style_access: bool,
}

impl fmt::Debug for ObjectStorageS3Config {
    /// Credential-safe `Debug`. The inline `secret_access_key` is
    /// replaced with `<redacted>`; every other field (endpoint, region,
    /// non-secret access key id, the env-var *name*, addressing mode) is
    /// shown. CLAUDE.md rule 12 — matches the hand-written `Debug` on the
    /// sibling credential configs.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ObjectStorageS3Config")
            .field("endpoint", &self.endpoint)
            .field("region", &self.region)
            .field("access_key_id", &self.access_key_id)
            .field(
                "secret_access_key",
                &if self.secret_access_key.is_some() {
                    "<redacted>"
                } else {
                    "<unset>"
                },
            )
            .field("secret_access_key_env", &self.secret_access_key_env)
            .field("path_style_access", &self.path_style_access)
            .finish()
    }
}

/// serde default for [`ObjectStorageS3Config::path_style_access`].
fn default_true() -> bool {
    true
}

/// One table inside an [`ObjectStorageCatalogConfig`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectStorageTableConfig {
    /// Table name (visible to SQL as `<catalog>.<schema>.<name>`).
    pub name: String,
    /// File or object URL. `file://…` always; `s3://bucket/key…` when
    /// the catalog declares an `[s3]` block. Globs are honored
    /// (`file:///data/part-*.parquet`). `gs://` / `abfs://` are future
    /// follow-ups.
    pub url: String,
    /// File format: `"parquet"`, `"csv"`, or `"json"` (newline-delimited).
    pub format: ObjectStorageFormat,
    /// Optional schema name; defaults to `"public"`. Lets
    /// operators group tables under a non-default schema name.
    #[serde(default)]
    pub schema: Option<String>,
}

/// File format for an [`ObjectStorageTableConfig`].
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectStorageFormat {
    /// Apache Parquet — self-describing schema, columnar
    /// reads, and predicate / projection pushdown handled by
    /// `DataFusion`'s built-in `ParquetFormat`. Files end `.parquet`.
    Parquet,
    /// CSV — schema inferred from the header + a sample of rows by
    /// `DataFusion`'s `CsvFormat` (header assumed present). Files end
    /// `.csv`.
    Csv,
    /// Newline-delimited JSON (one object per line) — schema inferred by
    /// `DataFusion`'s `JsonFormat`. Files end `.json`. (Not a single
    /// top-level JSON array; that's a different shape.)
    Json,
}

impl ObjectStorageFormat {
    /// File extension `ListingTable` matches for this format.
    #[must_use]
    fn file_extension(self) -> &'static str {
        match self {
            Self::Parquet => ".parquet",
            Self::Csv => ".csv",
            Self::Json => ".json",
        }
    }
}

/// Generic OData v2 catalog configuration (Phase 4 task 01, ).
///
/// JSON shape:
///
/// ```json
/// {
///   "kind": "odata",
///   "service_url": "https://host/odata/v2/MyService",
///   "auth": { "kind": "basic", "user": "svc", "password_env": "ODATA_PW" }
/// }
/// ```
///
/// Every entity set of the service becomes a table under one schema
/// named after the EDMX entity container:
/// `<catalog>.<container>.<EntitySet>`. OData names are case-sensitive,
/// so quote them in SQL.
#[derive(Clone, Serialize, Deserialize)]
pub struct OdataCatalogConfig {
    /// Service root URL (no trailing `/$metadata`), e.g.
    /// `https://host/sap/opu/odata/sap/API_BUSINESS_PARTNER`.
    pub service_url: String,
    /// How to authenticate — see [`OdataAuthConfig`].
    pub auth: OdataAuthConfig,
}

impl fmt::Debug for OdataCatalogConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // `auth` has its own redacting Debug; `service_url` is
        // credential-free. No secret rendered (CLAUDE.md rule 12).
        f.debug_struct("OdataCatalogConfig")
            .field("service_url", &self.service_url)
            .field("auth", &self.auth)
            .finish()
    }
}

/// SAP S/4HANA OData catalog configuration (Phase 4 task 01, ) —
/// the generic OData source plus SAP request headers.
///
/// JSON shape:
///
/// ```json
/// {
///   "kind": "sap_s4hana",
///   "service_url": "https://s4h.example.com/sap/opu/odata/sap/API_BUSINESS_PARTNER",
///   "auth": { "kind": "basic", "user": "DATAGLOT_SVC", "password_env": "SAP_PW" },
///   "sap_client": "100"
/// }
/// ```
#[derive(Clone, Serialize, Deserialize)]
pub struct SapS4hanaCatalogConfig {
    /// Service root URL (the full `/sap/opu/odata/sap/<service>` prefix).
    pub service_url: String,
    /// How to authenticate — see [`OdataAuthConfig`].
    pub auth: OdataAuthConfig,
    /// The SAP client / mandant (`sap-client` header), e.g. `"100"`.
    #[serde(default)]
    pub sap_client: Option<String>,
    /// The logon language (`sap-language` header), e.g. `"EN"`.
    #[serde(default)]
    pub sap_language: Option<String>,
}

impl fmt::Debug for SapS4hanaCatalogConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SapS4hanaCatalogConfig")
            .field("service_url", &self.service_url)
            .field("auth", &self.auth)
            .field("sap_client", &self.sap_client)
            .field("sap_language", &self.sap_language)
            .finish()
    }
}

/// How an OData / SAP catalog authenticates. Tagged by an inner `kind`
/// so the JSON reads `"auth": { "kind": "basic", … }`.
///
/// For each method exactly one of the literal / `*_env` fields must be
/// set — the literal for inline config, the `*_env` name for env-var
/// indirection (resolved at boot, never logged; CLAUDE.md rule 12).
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum OdataAuthConfig {
    /// HTTP Basic auth.
    Basic {
        /// The user name.
        user: String,
        /// Literal password (prefer `password_env`).
        #[serde(default)]
        password: Option<String>,
        /// Name of the env var holding the password.
        #[serde(default)]
        password_env: Option<String>,
    },
    /// A static OAuth 2.0 bearer token (refresh is the operator's job).
    Bearer {
        /// Literal token (prefer `token_env`).
        #[serde(default)]
        token: Option<String>,
        /// Name of the env var holding the token.
        #[serde(default)]
        token_env: Option<String>,
    },
}

impl fmt::Debug for OdataAuthConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never render the literal secret; the `*_env` *name* is safe
        // (it's a variable name, not the value). CLAUDE.md rule 12.
        match self {
            Self::Basic {
                user, password_env, ..
            } => f
                .debug_struct("Basic")
                .field("user", user)
                .field("password", &"<redacted>")
                .field("password_env", password_env)
                .finish(),
            Self::Bearer { token_env, .. } => f
                .debug_struct("Bearer")
                .field("token", &"<redacted>")
                .field("token_env", token_env)
                .finish(),
        }
    }
}

/// Generic REST/JSON catalog configuration (Phase 4, ).
///
/// Unlike OData there is no metadata document, so each table declares its URL,
/// where the row array lives (`records_path`), its Arrow columns, and how to
/// paginate. Every table becomes `<catalog>.<schema>.<name>`; REST/JSON field
/// names are case-sensitive, so quote them in SQL.
///
/// JSON shape:
///
/// ```json
/// {
///   "kind": "rest",
///   "schema": "public",
///   "auth": { "kind": "bearer", "token_env": "SF_TOKEN" },
///   "tables": [
///     {
///       "name": "account",
///       "url": "https://my.salesforce.com/services/data/v58.0/query?q=SELECT+Id,Name+FROM+Account",
///       "records_path": "records",
///       "pagination": { "kind": "next_link", "next_path": "nextRecordsUrl" },
///       "columns": [
///         { "name": "Id", "type": "utf8" },
///         { "name": "Name", "type": "utf8" }
///       ]
///     }
///   ]
/// }
/// ```
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RestCatalogConfig {
    /// Schema the tables are exposed under (default `"public"`).
    #[serde(default = "default_rest_schema")]
    pub schema: String,
    /// How to authenticate — see [`RestAuthConfig`]. Shared by every table
    /// (default: no auth).
    #[serde(default)]
    pub auth: RestAuthConfig,
    /// Speak HTTP/2 with prior knowledge (`h2c`/`h2`) instead of HTTP/1.1, so
    /// many in-flight requests multiplex over a few connections instead of one
    /// socket per request. Only for endpoints known to speak HTTP/2.
    /// Default `false`.
    #[serde(default)]
    pub http2_prior_knowledge: bool,
    /// The declared tables (at least one; boot rejects an empty list).
    pub tables: Vec<RestTableConfig>,
}

fn default_rest_schema() -> String {
    "public".to_string()
}

/// One declared REST table.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RestTableConfig {
    /// Table name as exposed in the catalog.
    pub name: String,
    /// Fully-qualified request URL for the table's collection endpoint.
    pub url: String,
    /// Dot-path to the row array in the JSON response (`""` = the body is
    /// itself the array). E.g. `"records"` for Salesforce.
    #[serde(default)]
    pub records_path: String,
    /// How to fetch subsequent pages (default: none).
    #[serde(default)]
    pub pagination: RestPaginationConfig,
    /// Equality filters to push to the API as query parameters (default: none).
    /// A `WHERE <column> = <literal>` on a listed column is sent as
    /// `?<param>=<literal>` on the request; unlisted columns are filtered
    /// locally.
    #[serde(default)]
    pub pushdown: Vec<RestPushdownParamConfig>,
    /// The declared Arrow columns (at least one).
    pub columns: Vec<RestColumnConfig>,
}

/// One equality-filter → query-parameter mapping for REST predicate pushdown.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RestPushdownParamConfig {
    /// The table column an equality filter is matched against.
    pub column: String,
    /// The query-parameter name to set (defaults to `column` when omitted).
    #[serde(default)]
    pub param: Option<String>,
}

/// One declared REST column: JSON field name → Arrow type.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RestColumnConfig {
    /// JSON field name (also the Arrow column name; case-sensitive).
    pub name: String,
    /// Arrow type: one of `utf8`, `boolean`, `int32`, `int64`, `float64`.
    #[serde(rename = "type")]
    pub data_type: String,
    /// Whether the column may be null (default `true`).
    #[serde(default = "default_true")]
    pub nullable: bool,
}

/// How a REST table paginates. Tagged by an inner `kind`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RestPaginationConfig {
    /// A single request; the whole result set is one response.
    #[default]
    None,
    /// Follow a "next page" URL at `next_path` (a dot-path into each
    /// response) until absent — e.g. Salesforce's `nextRecordsUrl`.
    NextLink {
        /// Dot-path to the next-page URL in the JSON response.
        next_path: String,
    },
}

/// How a REST catalog authenticates. Tagged by an inner `kind` so the JSON
/// reads `"auth": { "kind": "bearer", … }`. Defaults to [`Self::None`].
///
/// For `basic` / `bearer` / `header`, exactly one of the literal / `*_env`
/// field must be set — the literal for inline config, the `*_env` name for
/// env-var indirection (resolved at boot, never logged; CLAUDE.md rule 12).
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RestAuthConfig {
    /// No authentication (public endpoint).
    #[default]
    None,
    /// HTTP Basic auth.
    Basic {
        /// The user name.
        user: String,
        /// Literal password (prefer `password_env`).
        #[serde(default)]
        password: Option<String>,
        /// Name of the env var holding the password.
        #[serde(default)]
        password_env: Option<String>,
    },
    /// A static bearer token (e.g. a Salesforce session token).
    Bearer {
        /// Literal token (prefer `token_env`).
        #[serde(default)]
        token: Option<String>,
        /// Name of the env var holding the token.
        #[serde(default)]
        token_env: Option<String>,
    },
    /// A custom header carrying an API key (e.g. `x-api-key`).
    Header {
        /// Header name (not a secret).
        name: String,
        /// Literal header value (prefer `value_env`).
        #[serde(default)]
        value: Option<String>,
        /// Name of the env var holding the header value.
        #[serde(default)]
        value_env: Option<String>,
    },
    /// OAuth 2.0 client-credentials — the connector acquires and refreshes its
    /// own bearer from `token_url` (e.g. Salesforce). Connector-level: one token
    /// serves every table.
    Oauth2 {
        /// Token endpoint, e.g.
        /// `https://login.salesforce.com/services/oauth2/token`.
        token_url: String,
        /// OAuth client id.
        #[serde(default)]
        client_id: Option<String>,
        /// Name of the env var holding the client id.
        #[serde(default)]
        client_id_env: Option<String>,
        /// OAuth client secret (prefer `client_secret_env`).
        #[serde(default)]
        client_secret: Option<String>,
        /// Name of the env var holding the client secret.
        #[serde(default)]
        client_secret_env: Option<String>,
        /// Optional `scope` form parameter.
        #[serde(default)]
        scope: Option<String>,
    },
}

impl fmt::Debug for RestAuthConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never render a literal secret; the `*_env` *name* is safe (a
        // variable name, not the value). CLAUDE.md rule 12.
        match self {
            Self::None => f.write_str("None"),
            Self::Basic {
                user, password_env, ..
            } => f
                .debug_struct("Basic")
                .field("user", user)
                .field("password", &"<redacted>")
                .field("password_env", password_env)
                .finish(),
            Self::Bearer { token_env, .. } => f
                .debug_struct("Bearer")
                .field("token", &"<redacted>")
                .field("token_env", token_env)
                .finish(),
            Self::Header {
                name, value_env, ..
            } => f
                .debug_struct("Header")
                .field("name", name)
                .field("value", &"<redacted>")
                .field("value_env", value_env)
                .finish(),
            Self::Oauth2 {
                token_url,
                client_id,
                client_id_env,
                client_secret_env,
                scope,
                ..
            } => f
                .debug_struct("Oauth2")
                .field("token_url", token_url)
                .field("client_id", client_id)
                .field("client_id_env", client_id_env)
                .field("client_secret", &"<redacted>")
                .field("client_secret_env", client_secret_env)
                .field("scope", scope)
                .finish(),
        }
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 5432,
            batch_size: 8192,
            partitions: num_cpus(),
            maintenance: MaintenanceConfig::default(),
            default_catalog: "dataglot".to_string(),
            default_schema: "public".to_string(),
            memory_limit_bytes: None,
            spill_dir: None,
            tolerate_unreachable_catalogs: false,
            observability: ObservabilityConfig::default(),
            catalogs: HashMap::new(),
            masks: Vec::new(),
            derived_products: Vec::new(),
            row_filters: Vec::new(),
            governance: None,
            identities: HashMap::new(),
            roles: HashMap::new(),
            policy_explain: None,
            auth: AuthConfig::default(),
            authz: AuthzConfig::default(),
            pgwire_tls: None,
            rate_limit: None,
            access_denials: Vec::new(),
            column_grants: Vec::new(),
            catalog_service: None,
            lineage: None,
            governance_publishers: Vec::new(),
            ballista: None,
            webhook: None,
            flight_sql: None,
        }
    }
}

/// Resolve a pgwire username to a [`dataglot_policy::Identity`]
/// using the [`ServerConfig::identities`] map.
///
/// Used by the pgwire startup observer in `DataglotServer` once per
/// connection. Lookup rules:
///
/// * Empty `user` (`StartupMessage` didn't carry a `user` key)
///   ⇒ `Identity::anonymous`.
/// * `user` present but no profile in the map
///   ⇒ `Identity::user(name)` with no org and no groups. The
///   identity carries the name (visible in logs / diagnostics)
///   but tag-based policies that require a group match still
///   short-circuit.
/// * `user` present *and* profile in the map
///   ⇒ full identity with the configured org and groups.
///
/// The function is pure (no side effects) so the closure that
/// captures it via `Arc<HashMap<…>>` clone is `Send + Sync` and
/// reusable across connections. The hasher is generic so the
/// caller can pass a `HashMap` built with any `BuildHasher` —
/// matters for tests that swap in a deterministic hasher and for
/// the `Arc<HashMap>` we share across connections.
#[must_use]
pub fn resolve_identity<S: std::hash::BuildHasher>(
    user: &str,
    profiles: &HashMap<String, IdentityProfileConfig, S>,
) -> dataglot_policy::Identity {
    if user.is_empty() {
        return dataglot_policy::Identity::anonymous();
    }
    let mut identity = dataglot_policy::Identity::user(user);
    if let Some(profile) = profiles.get(user) {
        if let Some(org) = profile.org.as_deref() {
            identity = identity.with_org(org);
        }
        if !profile.groups.is_empty() {
            identity = identity.with_groups(profile.groups.iter().cloned());
        }
    }
    identity
}

/// Whether `identity` holds `role` — its user is listed, or any of its
/// groups is a member group of the role.
fn identity_holds_role(identity: &dataglot_policy::Identity, role: &RoleConfig) -> bool {
    if let Some(user) = identity.user.as_deref() {
        if role.users.iter().any(|u| u == user) {
            return true;
        }
    }
    role.groups
        .iter()
        .any(|g| identity.org_groups.iter().any(|og| og == g))
}

/// Resolve a session identity (as [`resolve_identity`]) and then **fold
/// the roles it holds into its effective group set** — Apache Ranger role
/// parity. Role names join `org_groups`, so any policy or access-denial
/// scoped to a group name transparently matches a role of that name with
/// no change to the enforcers. Role and group names share one matching
/// namespace; operators should keep them distinct.
pub fn resolve_identity_with_roles<S1, S2>(
    user: &str,
    profiles: &HashMap<String, IdentityProfileConfig, S1>,
    roles: &HashMap<String, RoleConfig, S2>,
) -> dataglot_policy::Identity
where
    S1: std::hash::BuildHasher,
    S2: std::hash::BuildHasher,
{
    fold_roles_into_groups(resolve_identity(user, profiles), roles)
}

/// Fold the roles `identity` holds into its `org_groups` — Apache Ranger role
/// parity. Held role names join the group set (deduped), so a policy or
/// access-denial scoped to a group name transparently matches a role of that
/// name. Idempotent and order-independent.
///
/// Factored out of [`resolve_identity_with_roles`] so the  startup
/// observer can re-fold roles after it overlays externally-resolved (JWT /
/// LDAP) directory groups onto the identity — otherwise a role whose member
/// group is a directory group would not activate.
pub(crate) fn fold_roles_into_groups<S2>(
    identity: dataglot_policy::Identity,
    roles: &HashMap<String, RoleConfig, S2>,
) -> dataglot_policy::Identity
where
    S2: std::hash::BuildHasher,
{
    if identity.is_anonymous() || roles.is_empty() {
        return identity;
    }
    let mut groups: Vec<String> = identity.org_groups.clone();
    for (name, role) in roles {
        if identity_holds_role(&identity, role) && !groups.contains(name) {
            groups.push(name.clone());
        }
    }
    if groups.len() == identity.org_groups.len() {
        return identity; // no roles held — avoid a needless rebuild
    }
    identity.with_groups(groups)
}

/// Parse a configured `table` string into a `TableReference`.
///
/// Accepts bare (`users`), partial (`public.users`), and full
/// (`pg.public.users`) shapes — same forms `TableReference::parse_str`
/// recognises. Anything with more than three dotted segments is
/// rejected at boot rather than producing a silent never-matches rule.
pub(crate) fn parse_table_ref(raw: &str) -> Result<TableReference> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        anyhow::bail!("mask `table` must not be empty");
    }
    // Reject 4+-segment shapes up front. `TableReference::parse_str`
    // happily accepts them by collapsing the first into the catalog
    // slot, which would silently produce a rule that never matches
    // any planner-emitted column reference.
    if trimmed.split('.').count() > 3 {
        anyhow::bail!(
            "mask `table` '{raw}' has more than 3 dotted segments — \
             use catalog.schema.table at most"
        );
    }
    Ok(TableReference::parse_str(trimmed))
}

/// Convert a [`RowPredicateConfig`] into a `DataFusion` `Expr`.
///
/// One predicate variant ⇒ one `Expr`. Future declarative variants
/// (`between`, `like_string`, `is_not_null`, etc.) extend the match
/// without breaking existing configs.
///
/// Integer variants emit `cast(col(column), Int64) <op> lit(value)`
/// rather than the bare `col(column) <op> lit(value)`. Without
/// the explicit cast, `DataFusion`'s interval-analysis phase rejects
/// cross-type comparisons (`Int32` column vs `Int64` literal)
/// before the type-coercion analyzer can normalise them — surfaces
/// as `Internal("Assertion failed: lhs_type == rhs_type")` at
/// physical-plan creation. The cast is logically free for `Int64`
/// columns (`DataFusion`'s optimizer removes redundant casts) and
/// makes the rule fire correctly for `Int32`/`Int16`/`Int8` columns
/// without operators having to declare a column-type field.
///
/// The `Sql` variant uses
/// [`datafusion::prelude::SessionContext::parse_sql_expr`] against
/// an empty `DFSchema` at boot. Column references in the parsed
/// `Expr` are left unbound — `DataFusion`'s analyzer pass binds
/// them to the real `TableScan` schema at query time.
///
/// # Errors
/// Returns an error if the `Sql` variant's SQL fails to parse
/// (syntax error, unsupported expression). Declarative variants
/// are infallible.
fn predicate_to_expr(pred: &RowPredicateConfig) -> Result<datafusion::logical_expr::Expr> {
    use datafusion::arrow::datatypes::DataType;
    use datafusion::logical_expr::{Cast, Expr};
    Ok(match pred {
        RowPredicateConfig::EqString { column, value } => col(column).eq(lit(value.clone())),
        RowPredicateConfig::EqInt { column, value } => {
            let casted = Expr::Cast(Cast::new(Box::new(col(column)), DataType::Int64));
            casted.eq(lit(*value))
        }
        RowPredicateConfig::GtInt { column, value } => {
            let casted = Expr::Cast(Cast::new(Box::new(col(column)), DataType::Int64));
            casted.gt(lit(*value))
        }
        RowPredicateConfig::Sql { sql } => parse_sql_predicate(sql)?,
    })
}

/// Parse a SQL fragment row-filter predicate into a `DataFusion`
/// `Expr` at config-load time.
///
/// Two phases:
///
/// 1. Walk the SQL via `sqlparser` to harvest every referenced
///    column name. We don't know the real types until query time,
///    so we synthesize a `DFSchema` where every harvested column
///    is `Utf8` — just enough for `parse_sql_expr`'s identifier
///    resolution to succeed.
/// 2. Call `SessionContext::parse_sql_expr` against the synthetic
///    schema to convert the SQL to an `Expr`. Column references in
///    the resulting `Expr` carry the synthetic `Utf8` type; at
///    query time, `DataFusion`'s `TypeCoercion` analyzer rebinds
///    them to the real `TableScan` schema and inserts casts where
///    needed.
pub(crate) fn parse_sql_predicate(sql: &str) -> Result<datafusion::logical_expr::Expr> {
    use datafusion::arrow::datatypes::{DataType, Field, Schema};
    use datafusion::common::DFSchema;
    use datafusion::prelude::SessionContext;
    use datafusion::sql::sqlparser::dialect::PostgreSqlDialect;
    use datafusion::sql::sqlparser::parser::Parser;

    // Phase 1 — AST parse + identifier harvest.
    let dialect = PostgreSqlDialect {};
    let mut parser = Parser::new(&dialect)
        .try_with_sql(sql)
        .with_context(|| format!("failed to parse SQL predicate `{sql}`"))?;
    let ast = parser
        .parse_expr()
        .with_context(|| format!("failed to parse SQL predicate `{sql}`"))?;
    let mut idents: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    collect_identifiers(&ast, &mut idents);

    // Phase 2 — synthetic schema + parse_sql_expr.
    let fields: Vec<Field> = idents
        .into_iter()
        .map(|name| Field::new(name, DataType::Utf8, true))
        .collect();
    let arrow_schema = Schema::new(fields);
    let dfschema = DFSchema::try_from(arrow_schema)
        .context("failed to build synthetic DFSchema for SQL predicate parsing")?;
    let ctx = SessionContext::new();
    ctx.parse_sql_expr(sql, &dfschema)
        .with_context(|| format!("failed to parse SQL predicate `{sql}`"))
}

/// Walk a `sqlparser` AST `Expr` and collect every referenced
/// identifier into `out`. Compound identifiers (`t.col`) contribute
/// their last segment — the column name — since the synthetic
/// schema has no qualifier.
///
/// Walks the *entire* AST via `sqlparser`'s [`Visit`] trait — so every
/// identifier is harvested no matter how deeply it's nested (inside a
/// `CASE`, a function call like `char_length(email)`, a `BETWEEN`, or a
/// scalar subquery). This is what lets both the row-filter `sql` variant
/// and the custom `mask_expr` use the full SQL expression grammar; the
/// earlier hand-rolled matcher only covered a fixed set of node kinds and
/// silently missed columns inside `CASE`/functions (they'd resolve to
/// "No field named …" at boot).
fn collect_identifiers(
    expr: &datafusion::sql::sqlparser::ast::Expr,
    out: &mut std::collections::BTreeSet<String>,
) {
    use datafusion::sql::sqlparser::ast::{Expr as E, Visit, Visitor};
    use std::ops::ControlFlow;

    struct IdentCollector<'a>(&'a mut std::collections::BTreeSet<String>);
    impl Visitor for IdentCollector<'_> {
        type Break = ();
        fn pre_visit_expr(&mut self, expr: &E) -> ControlFlow<()> {
            match expr {
                E::Identifier(id) => {
                    self.0.insert(id.value.clone());
                }
                // For `t.col`, the synthetic schema keys on the column, so
                // the trailing segment is the one that must exist.
                E::CompoundIdentifier(parts) => {
                    if let Some(last) = parts.last() {
                        self.0.insert(last.value.clone());
                    }
                }
                _ => {}
            }
            ControlFlow::Continue(())
        }
    }

    let _ = expr.visit(&mut IdentCollector(out));
}

/// Build the policy enforcer registered on every new pgwire session.
///
/// Composes up to three enforcers in this fixed order:
///
/// 1. `TagBasedEnforcer` (from `governance`, if non-empty) — resolves
///    Architecture Decisions §10 tag/policy bindings against the
///    session identity. The §10 enforcer internally builds a
///    `ColumnMaskingEnforcer` + `RowFilterEnforcer` per call.
/// 2. `ColumnMaskingEnforcer` (from static `[[masks]]`).
/// 3. `RowFilterEnforcer` (from static `[[row_filters]]`).
///
/// Empty sources collapse:
///
/// * No governance, no static rules ⇒ `NoopPolicyEnforcer`.
/// * Exactly one source non-empty ⇒ the bare enforcer (no composite
///   wrapping) for cheaper EXPLAIN output.
/// * Two or more sources non-empty ⇒ wrapped in a single
///   `CompositeEnforcer` in the order above.
///
/// Order is stable for diagnostics; the three enforcers rewrite
/// disjoint plan regions, so order doesn't change the result.
///
/// # Errors
/// Returns an error if any `table` cannot be parsed (see
/// [`parse_table_ref`]), if either static rule set has duplicates,
/// or if the governance section fails validation
/// (`OrgGovernanceBuildError`).
/// Test-only assembly of an `OrgGovernance` from config — exists so
/// the legacy `build_governance_*` tests still exercise the
/// config-shape → `OrgGovernance` translation. Production code goes
/// through [`build_rule_store`] which uses
/// [`build_governance_primitives`] instead, skipping the final
/// builder step until the rule store rebuilds the enforcer.
#[cfg(test)]
pub(crate) fn build_governance(
    config: &OrgGovernanceConfig,
) -> Result<dataglot_policy::OrgGovernance> {
    let (tags, policies, columns) = build_governance_primitives(config)?;
    let mut builder = dataglot_policy::OrgGovernance::builder();
    for t in tags {
        builder = builder.with_tag(t);
    }
    for p in policies {
        builder = builder.with_policy(p);
    }
    for c in columns {
        builder = builder.with_column(c);
    }
    builder
        .build()
        .context("OrgGovernance validation failed; check tags / policies / columns cross-refs")
}

#[cfg(test)]
pub(crate) fn build_policy_enforcer(
    masks: &[MaskConfig],
    row_filters: &[RowFilterConfig],
    governance: Option<&OrgGovernanceConfig>,
) -> Result<Arc<dyn PolicyEnforcer>> {
    // Slice 2 made the rule store the source of truth; the static
    // enforcer this returns is the store's first snapshot. Kept as a
    // test-only thin wrapper so the existing
    // `build_policy_enforcer_*` tests still exercise the composition
    // path; the production boot in `DataglotServer::new` goes
    // through [`build_rule_store`] directly so it can hold the
    // mutable store for the inbound governance webhook.
    let store = build_rule_store(masks, row_filters, governance)?;
    Ok(store.snapshot())
}

/// Decompose `[[masks]]` config entries into native
/// [`ColumnMask`] primitives. Phase 2 spec 04 slice 2 needs the
/// `(table, column, mask Expr)` shape directly so the
/// [`InMemoryRuleStore`] can keep the rules in its storage.
/// Build an [`AccessDenyEnforcer`] from config, or `None` when there are
/// no denials (so the boot path can skip composing it).
pub(crate) fn build_access_deny_enforcer(
    denials: &[AccessDenyConfig],
) -> Result<Option<Arc<AccessDenyEnforcer>>> {
    if denials.is_empty() {
        return Ok(None);
    }
    let mut rules = Vec::with_capacity(denials.len());
    for d in denials {
        let table = parse_table_ref(&d.table)
            .with_context(|| format!("access_denial for table '{}'", d.table))?;
        rules.push(AccessDenial {
            table,
            column: d.column.clone(),
            groups: d.groups.clone(),
        });
    }
    Ok(Some(Arc::new(AccessDenyEnforcer::new(rules))))
}

/// Prepend the configured access-deny layer — and, in grant mode, the
/// GRANT/REVOKE enforcer — in front of the rule store's masking/row-filter
/// enforcer, so access checks are evaluated *before* any masking. Both
/// pre-layers can reject the query outright (`permission denied`); masking /
/// row-filtering only ever runs on a query that cleared them. Returns the
/// store enforcer unchanged when neither pre-layer is present.
///
/// `grant_enforcer` is `Some` only when `[authz] mode = "grant"` (see
/// [`build_grant_enforcer`]); in `open` mode it is absent, so there is no
/// enforcement and zero added cost.
/// Build a [`ColumnWhitelistEnforcer`] from config, or `None` when there are no
/// column grants (so boot can skip composing it)..
pub(crate) fn build_column_whitelist_enforcer(
    grants: &[ColumnGrantConfig],
) -> Result<Option<Arc<ColumnWhitelistEnforcer>>> {
    if grants.is_empty() {
        return Ok(None);
    }
    let mut rules = Vec::with_capacity(grants.len());
    for g in grants {
        let table = parse_table_ref(&g.table)
            .with_context(|| format!("column_grant for table '{}'", g.table))?;
        rules.push(ColumnWhitelist {
            table,
            columns: g.columns.clone(),
            org: g.org.clone(),
            groups: config_groups(Some(&g.groups)),
        });
    }
    Ok(Some(Arc::new(ColumnWhitelistEnforcer::new(rules))))
}

pub(crate) fn compose_policy_enforcer(
    rule_store: &InMemoryRuleStore,
    denials: &[AccessDenyConfig],
    grant_enforcer: Option<Arc<GrantEnforcer>>,
) -> Result<Arc<dyn PolicyEnforcer>> {
    let store_enforcer = rule_store.enforcer();
    let deny = build_access_deny_enforcer(denials)
        .context("Failed to build access-deny rules from config")?;

    // Order: access-deny → grant → mask/row-filter. The two access layers
    // both short-circuit with an error, so their relative order is
    // immaterial; both must run before masking so a denied/ungranted query
    // never reaches (and can't be shaped by) the rewrite path.
    //
    // Column whitelists are NOT composed here: they change the
    // plan's output schema, which an `OptimizerRule` may not do, so they run
    // as a separate analyzer-stage rule (see `build_column_whitelist_enforcer`
    // + `DataglotServer::create_session`).
    let mut layers: Vec<Arc<dyn PolicyEnforcer>> = Vec::new();
    if let Some(deny) = deny {
        layers.push(deny as Arc<dyn PolicyEnforcer>);
    }
    if let Some(grant) = grant_enforcer {
        layers.push(grant as Arc<dyn PolicyEnforcer>);
    }
    if layers.is_empty() {
        return Ok(store_enforcer);
    }
    layers.push(store_enforcer);
    Ok(Arc::new(CompositeEnforcer::new(layers)))
}

/// Lower a stored `dataglot_catalog::GrantRecord` (read under `org`) into a
/// policy-crate [`Grant`]. The catalog layer stores grants per-org and the
/// policy layer must not depend on `dataglot-catalog` (rule 4), so the server
/// bridges the two shapes here — the grant analogue of [`build_mask_rules`].
pub(crate) fn build_grant(org: &str, record: &dataglot_catalog::GrantRecord) -> Grant {
    match record.object() {
        dataglot_catalog::GrantObject::Catalog(catalog) => {
            Grant::usage(record.grantee.clone(), Some(org.to_string()), catalog)
        }
        dataglot_catalog::GrantObject::Table {
            catalog,
            schema,
            table,
        } => Grant::select(
            record.grantee.clone(),
            Some(org.to_string()),
            catalog,
            schema,
            table,
        ),
    }
}

/// Build the GRANT/REVOKE enforcer for `authz.mode`. In `open` mode returns
/// `None` (no enforcement); in `grant` mode returns an enforcer pre-loaded
/// with `grants` (every org's, already lowered via [`build_grant`]). The
/// server keeps the returned `Arc<GrantEnforcer>` so a runtime `GRANT` /
/// `REVOKE` can republish the fresh set (see `StoreGrantAdmin`).
pub(crate) fn build_grant_enforcer(
    mode: AuthzMode,
    grants: Vec<Grant>,
    default_catalog: &str,
    default_schema: &str,
) -> Option<Arc<GrantEnforcer>> {
    match mode {
        AuthzMode::Open => None,
        // Supply the session defaults so a bare/partial scan (`FROM users`)
        // is resolved to `default_catalog.default_schema.users` and governed —
        // without this a deny-unless-granted check would skip it (a bypass).
        AuthzMode::Grant => Some(Arc::new(
            GrantEnforcer::with_grants(dataglot_policy::AuthzMode::Grant, grants)
                .with_session_defaults(Some((
                    default_catalog.to_string(),
                    default_schema.to_string(),
                ))),
        )),
    }
}

pub(crate) fn build_mask_rules(masks: &[MaskConfig]) -> Result<Vec<ColumnMask>> {
    // Precedence (Ranger override/normal): when several rules target the
    // same (table, column), the highest `priority` wins. A *tie* at the
    // top priority is genuinely ambiguous, so all tied rules are kept and
    // flow through to `ColumnMaskingEnforcer`, which raises its
    // `DuplicateRule` error — the operator must set distinct priorities
    // to layer them. Lower-priority rules for a resolved key are dropped.
    let mut by_key: HashMap<(String, String), Vec<&MaskConfig>> = HashMap::new();
    for m in masks {
        by_key
            .entry((m.table.clone(), m.column.clone()))
            .or_default()
            .push(m);
    }
    let mut chosen: Vec<&MaskConfig> = Vec::new();
    for group in by_key.values() {
        let top = group.iter().map(|m| m.priority).max().unwrap_or(0);
        chosen.extend(group.iter().copied().filter(|m| m.priority == top));
    }

    let mut rules = Vec::with_capacity(chosen.len());
    for m in chosen {
        let table =
            parse_table_ref(&m.table).with_context(|| format!("mask for column '{}'", m.column))?;
        // Precedence: a custom `mask_expr` (Ranger MASK_CUSTOM) wins, then a
        // named `mask_type` (Ranger parity), then the plain Utf8
        // `mask_literal`. `mask_expr` + `mask_type` together is ambiguous —
        // two conflicting "how to mask" sources — so reject it (same
        // exactly-one shape as `dsn`/`dsn_env`).
        if m.mask_expr.is_some() && m.mask_type.is_some() {
            anyhow::bail!(
                "mask for column '{}': set exactly one of `mask_expr` or `mask_type`, not both",
                m.column
            );
        }
        let mask = match (&m.mask_expr, &m.mask_type) {
            (Some(expr), _) => parse_sql_predicate(expr).with_context(|| {
                format!(
                    "custom mask expression (`mask_expr`) for column '{}'",
                    m.column
                )
            })?,
            (None, Some(mask_type)) => mask_type.to_mask_kind().to_expr(&m.column),
            (None, None) => lit(m.mask_literal.clone()),
        };
        rules.push(ColumnMask {
            table,
            column: m.column.clone(),
            mask,
            // File-config masks are operator-wide: they apply to every
            // session regardless of org. Runtime `CREATE MASK`
            // tags the rule with the issuing session's org instead.
            org: None,
            //: an absent `groups` stays all-subjects (back-compat); a
            // non-empty list scopes the mask to those org-groups / roles.
            groups: config_groups(m.groups.as_deref()),
        });
    }
    Ok(rules)
}

/// Decompose `[[row_filters]]` config entries into native
/// [`RowFilter`] primitives. Mirrors [`build_mask_rules`].
pub(crate) fn build_row_filter_rules(row_filters: &[RowFilterConfig]) -> Result<Vec<RowFilter>> {
    let mut rules = Vec::with_capacity(row_filters.len());
    for rf in row_filters {
        let table =
            parse_table_ref(&rf.table).with_context(|| format!("row filter on '{}'", rf.table))?;
        let predicate = predicate_to_expr(&rf.predicate)
            .with_context(|| format!("row filter on '{}'", rf.table))?;
        // File-config row filters are operator-wide; runtime
        // `CREATE ROW FILTER` tags the rule with the issuing session's org.
        rules.push(RowFilter {
            table,
            predicate,
            org: None,
            //: absent `groups` stays all-subjects (back-compat).
            groups: config_groups(rf.groups.as_deref()),
        });
    }
    Ok(rules)
}

/// Map a config `groups` list (`Option<Vec<String>>`) to the policy layer's
/// `Option<Vec<OrgGroupId>>`. `None` and `Some([])` both mean
/// **all subjects** — an operator that writes `"groups": []` clearly intends
/// "everyone", not "no one", so an empty list collapses to `None` rather than a
/// group scope that can never match.
fn config_groups(groups: Option<&[String]>) -> Option<Vec<OrgGroupId>> {
    match groups {
        // `None` or an empty list both mean "all subjects" (unscoped).
        None | Some([]) => None,
        Some(gs) => Some(gs.iter().map(|g| OrgGroupId::new(g.clone())).collect()),
    }
}

/// Decompose a `governance` config block into native primitives
/// (`Vec<TagDefinition>`, `Vec<Policy>`, `Vec<SemanticTableColumn>`).
/// Slice 2's [`InMemoryRuleStore`] holds rules in these shapes;
/// when a webhook event lands, the store mutates the primitives
/// directly and rebuilds an `OrgGovernance` for the new enforcer.
fn build_governance_primitives(
    config: &OrgGovernanceConfig,
) -> Result<(Vec<TagDefinition>, Vec<Policy>, Vec<SemanticTableColumn>)> {
    let mut tags = Vec::with_capacity(config.tags.len());
    for t in &config.tags {
        tags.push(TagDefinition {
            id: TagId::new(&t.id),
            org: t.org.clone(),
            name: t.name.clone(),
        });
    }

    let mut policies = Vec::with_capacity(config.policies.len());
    for p in &config.policies {
        let rule = match &p.rule {
            PolicyRuleConfig::Mask { mask_literal } => RuleType::Mask {
                expression: lit(mask_literal.clone()),
            },
            PolicyRuleConfig::RowFilter { predicate } => RuleType::RowFilter {
                predicate: predicate_to_expr(predicate)
                    .with_context(|| format!("policy `{}` row-filter predicate", p.id))?,
            },
        };
        policies.push(Policy {
            id: p.id.clone(),
            org: p.org.clone(),
            tag: TagId::new(&p.tag),
            group: OrgGroupId::new(&p.group),
            rule,
        });
    }

    let mut columns = Vec::with_capacity(config.columns.len());
    for c in &config.columns {
        let table = parse_table_ref(&c.table)
            .with_context(|| format!("column annotation for '{}'", c.column))?;
        columns.push(SemanticTableColumn {
            table,
            column: c.column.clone(),
            tags: c.tags.iter().map(TagId::new).collect(),
        });
    }

    Ok((tags, policies, columns))
}

/// Build an [`InMemoryRuleStore`] from the same `[[masks]]`,
/// `[[row_filters]]`, and `[governance]` blocks
/// [`build_policy_enforcer`] consumes — but returning the mutable
/// store rather than the static `Arc<dyn PolicyEnforcer>`. Phase 2
/// spec 04 slice 2 wires this into [`crate::DataglotServer::new`]
/// so the inbound governance webhook (slice 3) has somewhere to
/// publish rule changes.
///
/// # Errors
/// Returns an error if any `table` cannot be parsed, if either
/// static rule set has duplicates, or if the governance section
/// fails validation (`OrgGovernanceBuildError`). Same failure
/// surface as [`build_policy_enforcer`]; the store is built once
/// at boot, and any subsequent
/// [`dataglot_policy::RuleStore::apply`] failure surfaces at the
/// webhook handler instead.
// Test-only thin wrapper: production boot goes through
// `build_rule_store_with_lineage` (it threads the lineage graph +
// session defaults). Retained so the existing rule-store tests read
// cleanly without an empty graph + `None` at every call site.
#[cfg(test)]
pub(crate) fn build_rule_store(
    masks: &[MaskConfig],
    row_filters: &[RowFilterConfig],
    governance: Option<&OrgGovernanceConfig>,
) -> Result<Arc<InMemoryRuleStore>> {
    build_rule_store_with_lineage(
        masks,
        row_filters,
        governance,
        &dataglot_core::lineage::LineageGraph::new(),
        None,
    )
}

/// Like [`build_rule_store`], but additionally **propagates** the
/// configured column masks down the lineage `graph` (Interface 4 —
/// a mask on a source column extends to every derived column that
/// descends from it) and sets the column-mask enforcer's
/// `session_defaults` so a fully-qualified propagated mask matches a
/// bare query that resolves to those defaults. An empty
/// graph + `None` defaults reduces to [`build_rule_store`].
pub(crate) fn build_rule_store_with_lineage(
    masks: &[MaskConfig],
    row_filters: &[RowFilterConfig],
    governance: Option<&OrgGovernanceConfig>,
    graph: &dataglot_core::lineage::LineageGraph,
    session_defaults: Option<(String, String)>,
) -> Result<Arc<InMemoryRuleStore>> {
    // Configured masks → policy rules, then extend to lineage
    // descendants (no-op for an empty graph; aggregation outputs are
    // not propagated by default — decision 4).
    let mask_rules = crate::propagation::propagate_masks(&build_mask_rules(masks)?, graph, false);
    let filter_rules = build_row_filter_rules(row_filters)?;
    let (tag_defs, policies, columns) = match governance {
        Some(g) => build_governance_primitives(g)?,
        None => (Vec::new(), Vec::new(), Vec::new()),
    };

    let initial = InitialRules {
        masks: mask_rules,
        filters: filter_rules,
        tags: tag_defs,
        policies,
        columns,
        session_defaults,
    };

    InMemoryRuleStore::new(initial)
        .context("failed to build initial rule store from policy/governance config")
}

/// Env-var prefix for declaring a catalog with no config file:
/// `DATAGLOT_CATALOG_<NAME>=<json>`, where the value is a [`CatalogConfig`]
/// JSON object, e.g. `{"kind":"postgres","dsn_env":"PG_DSN"}`. The `<NAME>`
/// suffix is lowercased to form the catalog name used in SQL
/// (`DATAGLOT_CATALOG_PG_ORDERS` → `pg_orders`), so a container can run
/// fully fileless. An env catalog overrides a file catalog of the same name.
const ENV_CATALOG_PREFIX: &str = "DATAGLOT_CATALOG_";

/// Parse `DATAGLOT_CATALOG_<NAME>` entries from an iterator of `(key, value)`
/// environment pairs. Split out from [`ServerConfig::load`] so it is testable
/// without mutating the process environment. Returns `(name, config)` pairs
/// sorted by name for deterministic merge/log order.
///
/// # Errors
/// If a value is not valid [`CatalogConfig`] JSON, or the name suffix is empty.
fn parse_env_catalogs<I>(vars: I) -> Result<Vec<(String, CatalogConfig)>>
where
    I: IntoIterator<Item = (String, String)>,
{
    let mut out = Vec::new();
    for (key, value) in vars {
        let Some(suffix) = key.strip_prefix(ENV_CATALOG_PREFIX) else {
            continue;
        };
        if suffix.is_empty() {
            anyhow::bail!("{key}: env catalog name is empty (expected {ENV_CATALOG_PREFIX}<NAME>)");
        }
        let catalog: CatalogConfig = serde_json::from_str(&value).map_err(|e| {
            anyhow::anyhow!(
                "{key}: invalid catalog JSON ({e}); expected an object like \
                 {{\"kind\":\"postgres\",\"dsn_env\":\"PG_DSN\"}}"
            )
        })?;
        out.push((suffix.to_ascii_lowercase(), catalog));
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

impl ServerConfig {
    /// Load configuration from CLI args and optional config file.
    ///
    /// # Errors
    /// Returns an error if the config file cannot be read or parsed.
    pub fn load(args: &Args) -> Result<Self> {
        // Start with defaults
        let mut config = Self::default();

        // Load from file if provided
        if let Some(config_path) = &args.config {
            config = Self::load_from_file(config_path)?;
        }

        // Override with CLI args. `host`/`port`/`batch_size` are
        // `Option` (see `cli::Args`): `Some` only when the user passed
        // the flag or set the env var. `None` means "leave whatever the
        // config file declared (or the `Default` fallback) in place" —
        // earlier these fields carried clap `default_value`s that
        // silently clobbered the JSON config's network settings (a
        // `"port": 15499` bound 5432 until `--port` was passed, ).
        // Net precedence: CLI/env > config file > `Default::default()`,
        // matching `default_catalog` / `partitions` below.
        if let Some(host) = &args.host {
            config.host.clone_from(host);
        }
        if let Some(port) = args.port {
            config.port = port;
        }
        if let Some(batch_size) = args.batch_size {
            config.batch_size = batch_size;
        }
        if let Some(partitions) = args.partitions {
            config.partitions = partitions;
        }
        // CLI > env > config file > `Default::default()`. `args.default_catalog`
        // is `Option<String>`: `Some` only when the user passed `--default-catalog`
        // or set `DATAGLOT_DEFAULT_CATALOG`. `None` means "leave whatever the
        // config file declared (or the `Default` fallback) in place" — earlier
        // the field carried a clap `default_value = "dataglot"` that silently
        // clobbered the JSON config (caught during  diagnosis).
        if let Some(catalog) = &args.default_catalog {
            config.default_catalog.clone_from(catalog);
        }
        if let Some(schema) = &args.default_schema {
            config.default_schema.clone_from(schema);
        }
        // Enabling-only: the CLI/env flag can turn tolerance ON; a
        // config file that already set it stays ON. (A bool flag can't
        // express "force off", and this toggle is purely permissive.)
        config.tolerate_unreachable_catalogs |= args.tolerate_unreachable_catalogs;

        // Observability overrides — CLI/env trump the file.
        if let Some(format) = args.log_format {
            config.observability.log_format = format;
        }
        if let Some(filter) = &args.log_filter {
            config.observability.log_filter.clone_from(filter);
        }
        match args.metrics_addr {
            Some(MetricsAddr::Bind(addr)) => config.observability.metrics_addr = Some(addr),
            Some(MetricsAddr::Disabled) => config.observability.metrics_addr = None,
            None => {}
        }
        if args.disable_health_check {
            config.observability.health_check_enabled = false;
        }

        // Env-declared catalogs (`DATAGLOT_CATALOG_<NAME>=<json>`) — the
        // fileless path for containerized deploys. Merged after the file so an
        // env catalog overrides a file catalog of the same name.
        for (name, catalog) in parse_env_catalogs(std::env::vars())? {
            config.catalogs.insert(name, catalog);
        }

        config.validate()?;
        Ok(config)
    }

    /// Validate cross-field invariants the serde shape can't express.
    ///
    /// # Errors
    /// If a derived product declares `backing = "materialized"` without a
    /// `materialization` block (an invalid shape that would otherwise fail
    /// later, at refresh time).
    fn validate(&self) -> Result<()> {
        for p in &self.derived_products {
            if p.backing == MaterializationBacking::Materialized && p.materialization.is_none() {
                anyhow::bail!(
                    "derived product '{}': backing = \"materialized\" requires a \
                     `materialization` block (warehouse + namespace + refresh_every)",
                    p.name
                );
            }
        }
        // Multi-executor: external executors are spawned by a
        // launcher that must be told a concrete scheduler gRPC port up front,
        // so an ephemeral `0` would leave them unable to register. Reject the
        // combination before boot rather than hanging on registration.
        if let Some(b) = &self.ballista {
            if b.external_executors > 0 && b.scheduler_grpc_port == 0 {
                anyhow::bail!(
                    "ballista.scheduler_grpc_port must be a fixed non-zero port when \
                     external_executors > 0 (external executors need a known port to \
                     register with); got 0"
                );
            }
        }
        Ok(())
    }

    /// Load configuration from a JSON file.
    ///
    /// Both failure paths are tuned for a first-time operator: a missing
    /// file points at `--print-example-config`, and a parse error keeps
    /// `serde_json`'s line/column (which locates the offending JSON) and
    /// adds the same recovery hint.
    fn load_from_file(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                anyhow::anyhow!(
                    "config file not found: {}\n\
                     Create a starter config with:  dataglot --print-example-config > dataglot.toml\n\
                     then point at it with:          dataglot --config dataglot.toml",
                    path.display()
                )
            } else {
                anyhow::Error::new(e)
                    .context(format!("could not read config file: {}", path.display()))
            }
        })?;

        // Format is chosen by extension: `.json` still parses (back-compat),
        // everything else — including the canonical `.toml` — parses as TOML
        //. Both go through the same serde structs.
        let is_json = path
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("json"));

        let parse_hint = |e: &dyn std::fmt::Display| {
            // serde's Display for both formats already includes the line/column
            // that locates the offending key/value — keep it and add the hint.
            anyhow::anyhow!(
                "invalid config file {}: {e}\n\
                 Check that position against docs/configuration.md (or regenerate a \
                 known-good starter with `dataglot --print-example-config`).",
                path.display()
            )
        };

        if is_json {
            serde_json::from_str(&content).map_err(|e| parse_hint(&e))
        } else {
            toml::from_str(&content).map_err(|e| parse_hint(&e))
        }
    }

    /// Convert to dataglot-core `SessionConfig`.
    ///
    /// Note: `capture_query_sources` does **not** change
    /// `target_partitions`. An earlier revision pinned it to 1 when capture was
    /// on so the per-query pushdown profile would populate (the correlation
    /// task-local doesn't survive DataFusion's partition-task spawns), but that
    /// silently serialized *all* local execution — crippling compute-heavy
    /// local queries (e.g. a TPC-H aggregation over parquet) for a query-detail
    /// feature. Capture stays cheap (full parallelism); the pushdown treeview
    /// populates only under single-partition single-node execution, which the
    /// operator opts into explicitly via `partitions = 1` (documented). The
    /// parallelism-preserving fix is upstream-gated — see.
    #[must_use]
    pub fn to_session_config(&self) -> dataglot_core::SessionConfig {
        let mut config = dataglot_core::SessionConfig::new()
            .with_batch_size(self.batch_size)
            .with_target_partitions(self.partitions)
            .with_default_catalog(&self.default_catalog)
            .with_default_schema(&self.default_schema);
        // Resource guardrails — both optional, both off by
        // default, so unconfigured servers keep the unbounded runtime.
        if let Some(bytes) = self.memory_limit_bytes {
            config = config.with_memory_limit_bytes(bytes);
        }
        if let Some(dir) = &self.spill_dir {
            config = config.with_spill_dir(dir.clone());
        }
        config
    }

    /// `true` if any *enforcement* policy is configured — column masks,
    /// row filters, access denials, or a tag-based governance block.
    /// Identity/role maps alone don't count: without a policy they
    /// enforce nothing.
    #[must_use]
    pub fn has_governance_policies(&self) -> bool {
        !self.masks.is_empty()
            || !self.row_filters.is_empty()
            || !self.access_denials.is_empty()
            || !self.column_grants.is_empty()
            || self.governance.is_some()
    }

    /// `true` when the operator should be warned that the dashboard's
    /// per-query pushdown-SQL treeview will stay empty.
    ///
    /// The remedy ("set partitions = 1") is actionable *only* for plain
    /// DataFusion single-node execution: there the treeview is fed by a
    /// partition-local pushdown-correlation task-local that only
    /// survives single-partition runs. With Ballista configured — embedded
    /// standalone *or* external executors — the treeview is instead populated
    /// from executor pushdown metrics after each completed job
    /// (`dataglot-ballista`'s `fetch_and_record_pushdown_metrics`), regardless
    /// of `target_partitions`, and the scheduler overrides `target_partitions`
    /// anyway. So advising `partitions = 1` would be wrong whenever Ballista is
    /// in play — gate on `ballista.is_none()`.
    #[must_use]
    pub fn should_warn_empty_treeview(&self) -> bool {
        self.observability.capture_query_sources && self.partitions > 1 && self.ballista.is_none()
    }

    /// Emit boot-time security warnings for insecure auth postures.
    /// Warnings (not errors): an operator may knowingly run this way on
    /// a trusted/isolated network, but the risk must be visible.
    ///
    /// 1. **Trust mode + policies** — governance is keyed on the pgwire
    ///    startup username, which trust mode accepts without proof. Any
    ///    client can then impersonate any identity and read masked/
    ///    filtered data, so the policies are spoofable.
    /// 2. **A password mode (md5 / scram-sha-256) without transport
    ///    encryption** — without pgwire ingress TLS the query results (and,
    ///    for md5, the replayable password hash) cross the network in
    ///    plaintext. SCRAM's challenge–response is not itself replayable, but
    ///    the data it protects still is; both warrant TLS. Track: pgwire
    ///    ingress TLS.
    pub(crate) fn warn_insecure_auth(&self) {
        match self.auth.mode {
            AuthMode::Trust if self.has_governance_policies() => {
                tracing::warn!(
                    "auth.mode is \"trust\" but governance policies are configured: the \
                     startup username is accepted without authentication, so any client can \
                     impersonate any identity and bypass masking / row filters. Set \
                     auth.mode = \"md5\" or \"scram-sha-256\" (or run only on a trusted network)."
                );
            }
            // Only warn when the transport can still be plaintext. With
            // `[pgwire_tls] mode = "require"` credentials/results never cross
            // the wire in clear, so the warning would be wrong.
            // md5/scram put a password (or its replayable hash) on the wire;
            // jwt/ldap put the bearer token / bind password on the wire as a
            // cleartext-password message. All four warrant transport
            // encryption when TLS is not required.
            AuthMode::Md5 | AuthMode::ScramSha256 | AuthMode::Jwt | AuthMode::Ldap
                if self.pgwire_tls.as_ref().map(|t| t.mode) != Some(PgwireTlsMode::Require) =>
            {
                tracing::warn!(
                    "auth.mode requires a password but pgwire ingress TLS is not required: the \
                     credentials and query results may cross the network in plaintext. Set \
                     [pgwire_tls] mode = \"require\" (or terminate TLS in front of the server)."
                );
            }
            AuthMode::Md5
            | AuthMode::ScramSha256
            | AuthMode::Trust
            | AuthMode::Jwt
            | AuthMode::Ldap => {}
        }
    }
}

/// Look up an environment variable by name. Returns `Err` with a
/// description if the variable is unset. Wraps `std::env::var` so the
/// resolver functions below can be tested with an injected lookup
/// closure (the workspace forbids `unsafe_code`, which means tests
/// cannot mutate the process env directly).
type EnvLookup<'a> = &'a dyn Fn(&str) -> std::result::Result<String, std::env::VarError>;

/// Resolve a `PostgresCatalogConfig` into a libpq DSN string.
///
/// Exactly one of `dsn` (literal) or `dsn_env` (env-var name) must be
/// set. The DSN value is never logged — only the env-var name appears
/// in error messages when the variable is missing.
pub(crate) fn resolve_postgres_dsn(name: &str, cfg: &PostgresCatalogConfig) -> Result<String> {
    // Wrap `std::env::var` in a closure with a fixed `&str` parameter
    // so the higher-ranked-lifetime requirement on `EnvLookup` is
    // satisfied (the function itself is generic over `AsRef<OsStr>`).
    resolve_postgres_dsn_with_env(name, cfg, &|n: &str| std::env::var(n))
}

/// Test-friendly variant of [`resolve_postgres_dsn`] that takes an
/// injected env-var lookup. Production code goes through
/// `resolve_postgres_dsn`.
fn resolve_postgres_dsn_with_env(
    name: &str,
    cfg: &PostgresCatalogConfig,
    env: EnvLookup<'_>,
) -> Result<String> {
    // `dsn_secret` must already have been resolved into `dsn` by
    // `resolve_catalog_secrets` (an async step, before this sync build). If it's
    // still set here, no secret backend resolved it.
    if cfg.dsn_secret.is_some() {
        anyhow::bail!(
            "catalogs.{name}: `dsn_secret` is set but no secret backend resolved it — \
             a catalog_service and a DATAGLOT_SECRET_KEY are required for secret references"
        );
    }
    match (&cfg.dsn, &cfg.dsn_env) {
        (Some(_), Some(_)) => {
            anyhow::bail!("catalogs.{name}: set exactly one of `dsn` or `dsn_env`, not both")
        }
        (None, None) => anyhow::bail!(
            "catalogs.{name}: set one of `dsn` (inline DSN, dev only) or \
             `dsn_env` (name of an env var holding the DSN)"
        ),
        (Some(dsn), None) => Ok(dsn.clone()),
        (None, Some(env_name)) => env(env_name).with_context(|| {
            // We only mention the variable name — never any value (rule 12).
            format!(
                "catalogs.{name}.dsn_env: environment variable `{env_name}` is not set. \
                 Set it, e.g.  export {env_name}='host=localhost port=5432 user=me \
                 password=... dbname=mydb'"
            )
        }),
    }
}

/// Resolve a `MysqlCatalogConfig` into a `mysql_async`-style DSN
/// string. Mirrors [`resolve_postgres_dsn`] one-for-one.
pub(crate) fn resolve_mysql_dsn(name: &str, cfg: &MysqlCatalogConfig) -> Result<String> {
    resolve_mysql_dsn_with_env(name, cfg, &|n: &str| std::env::var(n))
}

/// Test-friendly variant of [`resolve_mysql_dsn`] that takes an
/// injected env-var lookup.
fn resolve_mysql_dsn_with_env(
    name: &str,
    cfg: &MysqlCatalogConfig,
    env: EnvLookup<'_>,
) -> Result<String> {
    match (&cfg.dsn, &cfg.dsn_env) {
        (Some(_), Some(_)) => {
            anyhow::bail!("catalogs.{name}: set exactly one of `dsn` or `dsn_env`, not both")
        }
        (None, None) => anyhow::bail!(
            "catalogs.{name}: set one of `dsn` (inline DSN, dev only) or \
             `dsn_env` (name of an env var holding the DSN)"
        ),
        (Some(dsn), None) => Ok(dsn.clone()),
        (None, Some(env_name)) => env(env_name).with_context(|| {
            format!(
                "catalogs.{name}.dsn_env: environment variable `{env_name}` is not set. \
                 Set it, e.g.  export {env_name}='mysql://user:pass@localhost:3306/mydb'"
            )
        }),
    }
}

/// Resolve a `SnowflakeCatalogConfig`'s password — either the
/// literal `password` field (dev-only escape hatch) or the value
/// of the env var named by `password_env` (production indirection
/// per CLAUDE.md rule 12).
///
/// Required-field validation for `account` / `warehouse` /
/// `database` / `user` is the operator's job (a malformed config
/// fails serde deserialization); this helper only handles the
/// password indirection because that's the only field with the
/// "literal or env-var, never both" shape.
// Only the injected-env variant is used at runtime (via
// `resolve_snowflake_config_with_env`); this convenience wrapper is
// exercised by the unit tests below.
#[cfg(test)]
fn resolve_snowflake_password(name: &str, cfg: &SnowflakeCatalogConfig) -> Result<String> {
    resolve_snowflake_password_with_env(name, cfg, &|n: &str| std::env::var(n))
}

/// Test-friendly variant of [`resolve_snowflake_password`] that
/// takes an injected env-var lookup.
fn resolve_snowflake_password_with_env(
    name: &str,
    cfg: &SnowflakeCatalogConfig,
    env: EnvLookup<'_>,
) -> Result<String> {
    match (&cfg.password, &cfg.password_env) {
        (Some(_), Some(_)) => {
            anyhow::bail!(
                "catalog '{name}': both `password` and `password_env` are set; specify exactly one"
            )
        }
        (None, None) => {
            anyhow::bail!("catalog '{name}': either `password` or `password_env` must be set")
        }
        (Some(pw), None) => Ok(pw.clone()),
        (None, Some(env_name)) => env(env_name).with_context(|| {
            // Variable name, never the resolved value (CLAUDE.md rule 12).
            format!(
                "catalog '{name}': environment variable '{env_name}' \
                 (configured via `password_env`) is not set"
            )
        }),
    }
}

/// Resolve a `SnowflakeCatalogConfig` into the federation-side
/// [`SnowflakeConfig`] the connector's constructor takes — resolving the
/// password (literal or `password_env`) per rule 12.
///
/// Shared by the single-node catalog build (`build_connectors`) and the
/// ballista distributed-registry build (`ballista::build_executor_registry`)
/// so both reconstruct an identical connector. The returned value carries
/// the resolved password but has a redacting `Debug`, so it never surfaces
/// in logs/errors.
///
/// [`SnowflakeConfig`]: dataglot_federation::snowflake::SnowflakeConfig
pub(crate) fn resolve_snowflake_config(
    name: &str,
    cfg: &SnowflakeCatalogConfig,
) -> Result<dataglot_federation::snowflake::SnowflakeConfig> {
    resolve_snowflake_config_with_env(name, cfg, &|n: &str| std::env::var(n))
}

/// Test-friendly variant of [`resolve_snowflake_config`] with an injected
/// env lookup. Key-pair (JWT) auth takes precedence: when
/// `private_key_env` names a populated variable, its PEM is carried and
/// `password`/`password_env` become optional (and ignored). Otherwise the
/// password indirection applies exactly as before.
fn resolve_snowflake_config_with_env(
    name: &str,
    cfg: &SnowflakeCatalogConfig,
    env: EnvLookup<'_>,
) -> Result<dataglot_federation::snowflake::SnowflakeConfig> {
    let private_key_pem = match cfg.private_key_env.as_deref() {
        Some(var) => {
            let key = env(var).with_context(|| {
                // Variable name only, never the key (CLAUDE.md rule 12).
                format!(
                    "catalog '{name}': environment variable '{var}' \
                     (configured via `private_key_env`) is not set"
                )
            })?;
            // Empty ⇒ treat as "no key" and fall through to password.
            (!key.trim().is_empty()).then_some(key)
        }
        None => None,
    };
    // With a private key, password is optional (key-pair is the credential);
    // without one, keep the strict "exactly one of password/password_env" rule.
    let password = if private_key_pem.is_some() {
        match (&cfg.password, &cfg.password_env) {
            (Some(pw), None) => pw.clone(),
            (None, Some(env_name)) => env(env_name).unwrap_or_default(),
            _ => String::new(),
        }
    } else {
        resolve_snowflake_password_with_env(name, cfg, env)?
    };
    Ok(dataglot_federation::snowflake::SnowflakeConfig {
        account: cfg.account.clone(),
        warehouse: cfg.warehouse.clone(),
        database: cfg.database.clone(),
        user: cfg.user.clone(),
        password,
        private_key_pem,
        schema: cfg.schema.clone(),
        role: cfg.role.clone(),
    })
}

/// Resolve an `OracleCatalogConfig`'s password — either the literal
/// `password` field (dev-only escape hatch) or the value of the env
/// var named by `password_env` (production indirection per CLAUDE.md
/// rule 12). Same "literal or env-var, never both" shape as
/// [`resolve_snowflake_password`].
///
/// Compiled only under `--features oracle` (the sole non-test caller
/// is `build_oracle_catalog`) or in `cfg(test)`; the
/// reject-without-feature path never resolves a password, so without
/// either cfg this would be dead code.
#[cfg(any(feature = "oracle", feature = "oracle-pure", test))]
pub(crate) fn resolve_oracle_password(name: &str, cfg: &OracleCatalogConfig) -> Result<String> {
    resolve_oracle_password_with_env(name, cfg, &|n: &str| std::env::var(n))
}

/// Test-friendly variant of [`resolve_oracle_password`] that takes an
/// injected env-var lookup.
#[cfg(any(feature = "oracle", feature = "oracle-pure", test))]
fn resolve_oracle_password_with_env(
    name: &str,
    cfg: &OracleCatalogConfig,
    env: EnvLookup<'_>,
) -> Result<String> {
    match (&cfg.password, &cfg.password_env) {
        (Some(_), Some(_)) => {
            anyhow::bail!(
                "catalog '{name}': both `password` and `password_env` are set; specify exactly one"
            )
        }
        (None, None) => {
            anyhow::bail!("catalog '{name}': either `password` or `password_env` must be set")
        }
        (Some(pw), None) => Ok(pw.clone()),
        (None, Some(env_name)) => env(env_name).with_context(|| {
            // Variable name, never the resolved value (CLAUDE.md rule 12).
            format!(
                "catalog '{name}': environment variable '{env_name}' \
                 (configured via `password_env`) is not set"
            )
        }),
    }
}

/// Resolve a `WarehouseCredentialsConfig` into the federation crate's
/// runtime credentials enum.
///
/// `secret_access_key_env` takes precedence over an inline
/// `secret_access_key`. Missing env vars are reported by **name**, not
/// value.
fn resolve_warehouse_credentials(
    name: &str,
    cfg: &WarehouseCredentialsConfig,
) -> Result<dataglot_federation::iceberg::WarehouseCredentials> {
    // See the comment in `resolve_postgres_dsn` for why this is wrapped.
    resolve_warehouse_credentials_with_env(name, cfg, &|n: &str| std::env::var(n))
}

/// Test-friendly variant of [`resolve_warehouse_credentials`] with an
/// injected env-var lookup.
fn resolve_warehouse_credentials_with_env(
    name: &str,
    cfg: &WarehouseCredentialsConfig,
    env: EnvLookup<'_>,
) -> Result<dataglot_federation::iceberg::WarehouseCredentials> {
    use dataglot_federation::iceberg::WarehouseCredentials;
    match cfg {
        WarehouseCredentialsConfig::Environment => Ok(WarehouseCredentials::Environment),
        WarehouseCredentialsConfig::Static {
            access_key_id,
            secret_access_key,
            secret_access_key_env,
        } => {
            // Spec: env-var indirection wins over the inline value when
            // both happen to be set. Treats the env var as the
            // production-grade source of truth.
            let secret = if let Some(env_name) = secret_access_key_env {
                env(env_name).with_context(|| {
                    format!(
                        "catalog '{name}': environment variable '{env_name}' \
                         (configured via `secret_access_key_env`) is not set"
                    )
                })?
            } else if let Some(s) = secret_access_key {
                s.clone()
            } else {
                anyhow::bail!(
                    "catalog '{name}': static credentials require either \
                     `secret_access_key` or `secret_access_key_env`"
                );
            };
            Ok(WarehouseCredentials::Static {
                access_key_id: access_key_id.clone(),
                secret_access_key: secret,
            })
        }
    }
}

/// Build `Arc<dyn CatalogProvider>` instances for every entry in
/// `catalogs`.
///
/// Each connector is connected once at server boot. The resulting
/// catalog providers are reusable across pgwire sessions
/// (`PostgresCatalog` / `WarehouseCatalog` cache their schema lists at
/// construction time — see the `as_catalog_provider` doc comments in
/// `dataglot-federation`).
///
/// Connection failures are propagated with the catalog NAME for
/// operator triage. Credential bytes never appear in error context.
///
/// Fail-fast: the first catalog that can't connect aborts boot. For
/// the tolerant variant (skip + WARN), see [`build_connectors_with`].
///
/// # Errors
/// Returns an error if any catalog cannot be resolved or if the
/// underlying connector fails to connect.
pub async fn build_connectors<S: std::hash::BuildHasher>(
    catalogs: &HashMap<String, CatalogConfig, S>,
) -> Result<HashMap<String, Arc<dyn DfCatalogProvider>>> {
    build_connectors_with(catalogs, false).await
}

/// Build `Arc<dyn CatalogProvider>` instances for every entry in
/// `catalogs`, with selectable failure handling.
///
/// `tolerate_unreachable = false` is the fail-fast default (identical
/// to [`build_connectors`]): the first connect failure aborts boot.
///
/// `tolerate_unreachable = true` logs each connect failure at WARN
/// (catalog name + kind + error chain — never credentials, per
/// CLAUDE.md rule 12) and skips that catalog; the returned map holds
/// only the catalogs that connected. A fully unreachable set yields an
/// empty map rather than an error. See
/// [`ServerConfig::tolerate_unreachable_catalogs`].
///
/// # Errors
/// In fail-fast mode, returns the first connector error. In tolerant
/// mode, never returns `Err` for a connect failure (each is logged and
/// skipped).
pub async fn build_connectors_with<S: std::hash::BuildHasher>(
    catalogs: &HashMap<String, CatalogConfig, S>,
    tolerate_unreachable: bool,
) -> Result<HashMap<String, Arc<dyn DfCatalogProvider>>> {
    let mut out: HashMap<String, Arc<dyn DfCatalogProvider>> =
        HashMap::with_capacity(catalogs.len());
    for (name, cfg) in catalogs {
        // Names are safe to log (CLAUDE.md rule 12 covers credentials,
        // not catalog identifiers).
        tracing::info!(catalog = %name, kind = catalog_kind(cfg), "registering federated catalog");
        match build_one_connector(name, cfg).await {
            Ok(provider) => {
                out.insert(name.clone(), provider);
            }
            Err(e) if tolerate_unreachable => {
                // The connector error chain carries the catalog name
                // and the redacted connect failure; it's the same
                // content fail-fast would propagate to the operator,
                // here downgraded to a skip.
                tracing::warn!(
                    catalog = %name,
                    kind = catalog_kind(cfg),
                    error = format!("{e:#}"),
                    "catalog unreachable at boot; skipping (tolerate_unreachable_catalogs)"
                );
            }
            Err(e) => return Err(e),
        }
    }
    Ok(out)
}

/// Like [`build_connectors_with`], but also returns the per-catalog
/// [`ConnectorHealthHandle`] map for the connectors that expose one.
///
/// Each connector is still built exactly once. SQL sources hand back a handle
/// over their boot-built, authenticated client so the connector-health poller
/// can `SELECT 1` on it instead of rebuilding; non-SQL sources contribute no
/// handle (the poller falls back to the rebuild probe for them). In tolerant
/// mode a connect failure is logged + skipped, contributing neither a provider
/// nor a handle — identical failure semantics to [`build_connectors_with`].
///
/// # Errors
/// Same as [`build_connectors_with`]: in fail-fast mode, the first connect
/// error; in tolerant mode, never for a connect failure.
pub async fn build_connectors_with_health<S: std::hash::BuildHasher>(
    catalogs: &HashMap<String, CatalogConfig, S>,
    tolerate_unreachable: bool,
) -> Result<(
    HashMap<String, Arc<dyn DfCatalogProvider>>,
    HashMap<String, ConnectorHealthHandle>,
)> {
    let mut providers: HashMap<String, Arc<dyn DfCatalogProvider>> =
        HashMap::with_capacity(catalogs.len());
    let mut handles: HashMap<String, ConnectorHealthHandle> = HashMap::new();
    for (name, cfg) in catalogs {
        // Names are safe to log (CLAUDE.md rule 12 covers credentials,
        // not catalog identifiers).
        tracing::info!(catalog = %name, kind = catalog_kind(cfg), "registering federated catalog");
        match build_one_connector_with_health(name, cfg).await {
            Ok((provider, handle)) => {
                providers.insert(name.clone(), provider);
                if let Some(handle) = handle {
                    handles.insert(name.clone(), handle);
                }
            }
            Err(e) if tolerate_unreachable => {
                tracing::warn!(
                    catalog = %name,
                    kind = catalog_kind(cfg),
                    error = format!("{e:#}"),
                    "catalog unreachable at boot; skipping (tolerate_unreachable_catalogs)"
                );
            }
            Err(e) => return Err(e),
        }
    }
    Ok((providers, handles))
}

/// Stable string label for the `kind` discriminator. Used only for
/// diagnostic logging — never as a credential.
pub(crate) fn catalog_kind(cfg: &CatalogConfig) -> &'static str {
    match cfg {
        CatalogConfig::Postgres(_) => "postgres",
        CatalogConfig::Mysql(_) => "mysql",
        CatalogConfig::Snowflake(_) => "snowflake",
        CatalogConfig::Oracle(_) => "oracle",
        CatalogConfig::Warehouse(_) => "warehouse",
        CatalogConfig::ObjectStorage(_) => "object_storage",
        CatalogConfig::Odata(_) => "odata",
        CatalogConfig::SapS4hana(_) => "sap_s4hana",
        CatalogConfig::Adbc(_) => "adbc",
        CatalogConfig::Rest(_) => "rest",
    }
}

/// Build a single catalog provider from one config entry.
///
/// Build a [`WarehouseConnector`] for the materialization write path
///. Unlike [`build_one_connector`]'s warehouse arm — which returns
/// only the read-side catalog provider — this hands back the connector itself
/// so the refresh worker can call `overwrite_table`. A dedicated connection
/// (the REST handshake is cheap + lazy) keeps the writer independent of the
/// read-path provider.
///
/// [`WarehouseConnector`]: dataglot_federation::iceberg::WarehouseConnector
///
/// # Errors
/// Surfaces credential-resolution and warehouse-connect failures.
pub async fn build_warehouse_connector(
    name: &str,
    wh: &WarehouseCatalogConfig,
) -> Result<Arc<dataglot_federation::iceberg::WarehouseConnector>> {
    let credentials = resolve_warehouse_credentials(name, &wh.credentials)?;
    let warehouse_cfg = dataglot_federation::iceberg::WarehouseConfig {
        catalog_url: wh.catalog_url.clone(),
        warehouse: wh.warehouse.clone(),
        credentials,
        s3_endpoint: wh.s3_endpoint.clone(),
        s3_region: wh.s3_region.clone(),
    };
    let connector = dataglot_federation::iceberg::WarehouseConnector::connect(name, warehouse_cfg)
        .await
        .with_context(|| format!("catalog '{name}': warehouse connect failed (materialization)"))?;
    Ok(Arc::new(connector))
}

/// Reject TLS knobs (`tls_ca_file` / `tls_accept_invalid_certs`) set
/// without `tls = "require"` — otherwise they'd be silently ignored and
/// an operator would think the connection is encrypted when it isn't.
fn check_tls_knobs(
    name: &str,
    mode: SourceTlsMode,
    ca_file: Option<&std::path::PathBuf>,
    accept_invalid: bool,
) -> Result<()> {
    if mode == SourceTlsMode::Disable && (ca_file.is_some() || accept_invalid) {
        anyhow::bail!(
            "catalog '{name}': `tls_ca_file` / `tls_accept_invalid_certs` are set but \
             `tls` is \"disable\" — set `tls = \"require\"` to use them"
        );
    }
    Ok(())
}

/// Build a Postgres catalog provider, negotiating TLS when `tls = "require"`.
///
/// Returns the provider **and** a health handle over the same boot-built,
/// authenticated connector: the retained `Arc<PostgresConnector>` is
/// handed back so the liveness poller can `SELECT 1` on it instead of
/// rebuilding + re-authenticating on every tick.
async fn build_postgres_connector(
    name: &str,
    pg: &PostgresCatalogConfig,
) -> Result<(Arc<dyn DfCatalogProvider>, ConnectorHealthHandle)> {
    let dsn = resolve_postgres_dsn(name, pg)?;
    check_tls_knobs(
        name,
        pg.tls,
        pg.tls_ca_file.as_ref(),
        pg.tls_accept_invalid_certs,
    )?;
    let connector = if pg.tls == SourceTlsMode::Require {
        // Explicit TLS: a CA file selects a private-CA root, else the OS store.
        let tls = dataglot_federation::pg_tls::PgTls {
            roots: pg.tls_ca_file.clone().map_or(
                dataglot_federation::pg_tls::TlsRoots::Native,
                dataglot_federation::pg_tls::TlsRoots::CaFile,
            ),
            accept_invalid_certs: pg.tls_accept_invalid_certs,
        };
        let config = dsn
            .parse()
            .with_context(|| format!("catalog '{name}': invalid postgres DSN"))?;
        dataglot_federation::postgres::PostgresConnector::connect_with_tls(config, &tls)
            .await
            .with_context(|| format!("catalog '{name}': postgres TLS connect failed"))?
    } else {
        // Plaintext, or TLS driven by a DSN `sslmode=require` (in `connect`).
        dataglot_federation::postgres::PostgresConnector::connect(&dsn)
            .await
            .with_context(|| format!("catalog '{name}': postgres connect failed"))?
    }
    //: label pushdown telemetry with the catalog name, not the DSN.
    .with_catalog(name);
    let connector = Arc::new(connector);
    let provider = connector
        .as_catalog_provider()
        .await
        .with_context(|| format!("catalog '{name}': failed to build catalog provider"))?;
    Ok((provider, connector as ConnectorHealthHandle))
}

/// Build a MySQL catalog provider, negotiating TLS when `tls = "require"`.
///
/// Returns the provider **and** a health handle over the same boot-built,
/// authenticated connector — see [`build_postgres_connector`].
async fn build_mysql_connector(
    name: &str,
    my: &MysqlCatalogConfig,
) -> Result<(Arc<dyn DfCatalogProvider>, ConnectorHealthHandle)> {
    let dsn = resolve_mysql_dsn(name, my)?;
    check_tls_knobs(
        name,
        my.tls,
        my.tls_ca_file.as_ref(),
        my.tls_accept_invalid_certs,
    )?;
    let connector = if my.tls == SourceTlsMode::Require {
        let tls = dataglot_federation::mysql_tls::MysqlTls {
            ca_file: my.tls_ca_file.clone(),
            accept_invalid_certs: my.tls_accept_invalid_certs,
        };
        dataglot_federation::mysql::MysqlConnector::connect_with_tls(name.to_string(), &dsn, &tls)
            .await
            .with_context(|| format!("catalog '{name}': mysql TLS connect failed"))?
    } else {
        dataglot_federation::mysql::MysqlConnector::connect(name.to_string(), &dsn)
            .await
            .with_context(|| format!("catalog '{name}': mysql connect failed"))?
    };
    let connector = Arc::new(connector);
    let provider = connector
        .as_catalog_provider()
        .await
        .with_context(|| format!("catalog '{name}': failed to build catalog provider"))?;
    Ok((provider, connector as ConnectorHealthHandle))
}

/// Resolves a control-plane secret name to its plaintext value ( slice
/// D). Implemented in [`crate::secret_admin`]; keeping it a trait here lets the
/// config layer stay unaware of the meta store + envelope cipher.
#[async_trait::async_trait]
pub trait SecretResolver: Send + Sync {
    /// Resolve `name` **within `org`** to plaintext ( M2: the org is
    /// threaded per call so one resolver serves every tenant). Rule 12: callers
    /// must not log the result.
    ///
    /// # Errors
    /// If the secret doesn't exist or can't be decrypted.
    async fn resolve(&self, org: &str, name: &str) -> Result<String>;
}

/// Return a runtime copy of `cfg` with any `*_secret` reference resolved to its
/// plaintext value via `resolver`, ready for [`build_one_connector`] (
/// slice D). The *persisted* config keeps the reference; only this in-memory
/// copy carries the resolved value (rule 12). A config with no secret reference
/// is returned unchanged (and `resolver` may be `None`).
///
/// # Errors
/// If a secret is referenced but `resolver` is `None`, if `_secret` collides
/// with an inline `dsn`/`dsn_env`, or if resolution fails.
pub async fn resolve_catalog_secrets(
    cfg: &CatalogConfig,
    org: &str,
    resolver: Option<&dyn SecretResolver>,
) -> Result<CatalogConfig> {
    let mut cfg = cfg.clone();
    if let CatalogConfig::Postgres(pg) = &mut cfg {
        if let Some(secret) = pg.dsn_secret.take() {
            if pg.dsn.is_some() || pg.dsn_env.is_some() {
                anyhow::bail!("catalog: set only one of `dsn`, `dsn_env`, or `dsn_secret`");
            }
            let resolver = resolver.ok_or_else(|| {
                anyhow::anyhow!(
                    "catalog references secret {secret:?} but this server has no secret \
                     backend (needs a catalog_service and a DATAGLOT_SECRET_KEY)"
                )
            })?;
            pg.dsn = Some(resolver.resolve(org, &secret).await?);
        }
    }
    Ok(cfg)
}

/// A cheap-liveness handle over an already-built, already-authenticated
/// connector. Returned alongside the provider by
/// [`build_one_connector_with_health`] for SQL sources so the health poller can
/// reuse the boot-built client instead of rebuilding it every tick. `None` for
/// non-SQL sources (REST / OData / warehouse / object-storage), which keep the
/// rebuild-probe fallback.
pub type ConnectorHealthHandle = Arc<dyn dataglot_federation::ConnectorHealthCheck>;

/// Build a single connector into a [`DfCatalogProvider`]. Public for
/// `dataglot-server::server`'s catalog-cache wiring (Phase 1 task 09) — the
/// cache's `ProviderBuilder` closure routes here. Any `*_secret` references
/// must already be resolved via [`resolve_catalog_secrets`].
///
/// Thin wrapper over [`build_one_connector_with_health`] that discards the
/// health handle — for callers (the cache closure, background refresh) that
/// only need the provider.
///
/// # Errors
/// Surfaces per-connector connect failures (DSN parse, network error, schema
/// discovery).
pub async fn build_one_connector(
    name: &str,
    cfg: &CatalogConfig,
) -> Result<Arc<dyn DfCatalogProvider>> {
    build_one_connector_with_health(name, cfg)
        .await
        .map(|(provider, _handle)| provider)
}

/// Build a single connector, returning the provider **and** — for SQL sources —
/// a [`ConnectorHealthHandle`] over the same boot-built, authenticated client
///. The boot path captures the handle so the connector-health poller
/// probes liveness with a cheap `SELECT 1` on the existing client rather than
/// rebuilding the connector (a full re-auth + eager `INFORMATION_SCHEMA` walk
/// for e.g. Snowflake) on every tick.
///
/// Non-SQL sources (warehouse / object-storage / OData / SAP / REST) return
/// `None`; the poller keeps the current rebuild-probe for them. The construction
/// is byte-identical to what [`build_one_connector`] did before — only the
/// retained `Arc<Connector>` is new.
///
/// # Errors
/// Surfaces per-connector connect failures (DSN parse, network error, schema
/// discovery).
pub async fn build_one_connector_with_health(
    name: &str,
    cfg: &CatalogConfig,
) -> Result<(Arc<dyn DfCatalogProvider>, Option<ConnectorHealthHandle>)> {
    match cfg {
        CatalogConfig::Postgres(pg) => {
            let (provider, handle) = build_postgres_connector(name, pg).await?;
            Ok((provider, Some(handle)))
        }
        CatalogConfig::Mysql(my) => {
            let (provider, handle) = build_mysql_connector(name, my).await?;
            Ok((provider, Some(handle)))
        }
        CatalogConfig::Warehouse(wh) => {
            let credentials = resolve_warehouse_credentials(name, &wh.credentials)?;
            let warehouse_cfg = dataglot_federation::iceberg::WarehouseConfig {
                catalog_url: wh.catalog_url.clone(),
                warehouse: wh.warehouse.clone(),
                credentials,
                s3_endpoint: wh.s3_endpoint.clone(),
                s3_region: wh.s3_region.clone(),
            };
            let connector =
                dataglot_federation::iceberg::WarehouseConnector::connect(name, warehouse_cfg)
                    .await
                    .with_context(|| format!("catalog '{name}': warehouse connect failed"))?;
            let connector = Arc::new(connector);
            let provider = connector
                .as_catalog_provider()
                .await
                .with_context(|| format!("catalog '{name}': failed to build catalog provider"))?;
            // Warehouse is `iceberg-datafusion`, not a `SQLExecutor` — no cheap
            // reuse handle; the poller falls back to the rebuild probe.
            Ok((provider, None))
        }
        CatalogConfig::Snowflake(sf) => {
            // `SnowflakeConnector::as_catalog_provider` performs eager
            // schema + table-name discovery against the configured
            // Snowflake database's `INFORMATION_SCHEMA`. Snowflake's
            // auth handshake fires on the first query (the schema-
            // listing one), so misconfigured `password_env` / wrong
            // account identifier / network-unreachable account all
            // surface here with a clear catalog-error message.
            //
            // Resolving the config (incl. password) first so a
            // misconfigured `password_env` produces its specific env-var
            // error message rather than getting masked by the generic
            // client-build failure below. Shared with the ballista
            // distributed registry so both paths build an identical client.
            let sf_config = resolve_snowflake_config(name, sf)?;
            let connector = dataglot_federation::snowflake::SnowflakeConnector::connect(
                name.to_string(),
                sf_config,
            )
            .with_context(|| format!("catalog '{name}': snowflake client build failed"))?;
            let connector = Arc::new(connector);
            let provider = connector
                .as_catalog_provider()
                .await
                .with_context(|| format!("catalog '{name}': failed to build catalog provider"))?;
            // Reuse the authenticated client for liveness: the poller
            // `SELECT 1`s instead of paying another ~0.87s re-auth per tick.
            Ok((provider, Some(connector as ConnectorHealthHandle)))
        }
        CatalogConfig::Oracle(o) => build_oracle_catalog(name, o).await,
        CatalogConfig::ObjectStorage(os) => {
            Ok((build_object_storage_catalog(name, os).await?, None))
        }
        CatalogConfig::Odata(od) => Ok((build_odata_catalog(name, od).await?, None)),
        CatalogConfig::SapS4hana(sap) => Ok((build_sap_catalog(name, sap).await?, None)),
        CatalogConfig::Adbc(a) => build_adbc_catalog(name, a).await,
        CatalogConfig::Rest(r) => Ok((build_rest_catalog(name, r).await?, None)),
    }
}

/// Build a `kind = "adbc"` catalog into a [`DfCatalogProvider`]
///. Compiled only under `--features adbc` — same
/// reject-without-feature shape as `build_oracle_catalog`: the config
/// surface always parses, the connector is opt-in.
///
/// Boot-time validation order (all errors name the catalog, none carry
/// credentials — rule 12): dialect whitelist first (pure capability
/// check, no I/O), then the connector's own config validation +
/// `password_env` resolution inside `AdbcConnector::connect`.
#[cfg(feature = "adbc")]
async fn build_adbc_catalog(
    name: &str,
    a: &AdbcCatalogConfig,
) -> Result<(Arc<dyn DfCatalogProvider>, Option<ConnectorHealthHandle>)> {
    use dataglot_federation::adbc::{AdbcConfig, AdbcConnector, SupportedDialect};

    let dialect: SupportedDialect = a
        .dialect
        .parse()
        .with_context(|| format!("catalog '{name}': invalid adbc dialect"))?;
    let mut config = AdbcConfig::new(name, a.driver_path.clone(), dialect);
    config.driver_entrypoint = a.driver_entrypoint.clone();
    config.uri = a.uri.clone();
    config.username = a.username.clone();
    config.password_env = a.password_env.clone();
    config.driver_options = a.driver_options.clone();
    config.catalog = a.catalog.clone();
    config.schema = a.schema.clone();
    config.connection_pool_size = a.connection_pool_size;
    config.connection_pool_min_idle = a.connection_pool_min_idle;

    let connector = AdbcConnector::connect(config)
        .await
        .with_context(|| format!("catalog '{name}': adbc connect failed"))?;
    let connector = Arc::new(connector);
    let provider = connector
        .as_catalog_provider()
        .await
        .with_context(|| format!("catalog '{name}': failed to build adbc catalog provider"))?;
    // Reuse a pooled connection for liveness instead of reloading the
    // driver + reopening the pool on every poll tick.
    Ok((provider, Some(connector as ConnectorHealthHandle)))
}

/// Reject a `kind = "adbc"` catalog when the server was built without
/// the `adbc` feature: the config deserializes fine, but boot fails
/// fast with an actionable message instead of silently dropping the
/// source (same pattern as the Oracle stub above).
#[cfg(not(feature = "adbc"))]
#[allow(clippy::unused_async)] // signature parity with the feature-on variant
async fn build_adbc_catalog(
    name: &str,
    _a: &AdbcCatalogConfig,
) -> Result<(Arc<dyn DfCatalogProvider>, Option<ConnectorHealthHandle>)> {
    anyhow::bail!(
        "catalog '{name}': kind = \"adbc\" requires this server to be built with \
         `--features adbc` (the generic BYO-driver connector); this binary was built without it"
    )
}

/// Resolve an [`OdataAuthConfig`] into the federation crate's
/// [`OdataAuth`], enforcing exactly-one of literal / `*_env` per method
/// and reading the env var at boot. Never renders a secret in an error
/// (CLAUDE.md rule 12).
///
/// [`OdataAuth`]: dataglot_federation::odata::OdataAuth
fn resolve_odata_auth(
    name: &str,
    auth: &OdataAuthConfig,
) -> Result<dataglot_federation::odata::OdataAuth> {
    resolve_odata_auth_with_env(name, auth, &|n: &str| std::env::var(n))
}

fn resolve_odata_auth_with_env(
    name: &str,
    auth: &OdataAuthConfig,
    env: EnvLookup<'_>,
) -> Result<dataglot_federation::odata::OdataAuth> {
    use dataglot_federation::odata::OdataAuth;
    // Shared "exactly one of literal / env" resolver — `field` names the
    // literal key, `env_field` its `*_env` sibling, for a clear message.
    let pick = |literal: &Option<String>,
                env_var: &Option<String>,
                field: &str,
                env_field: &str|
     -> Result<String> {
        match (literal, env_var) {
            (Some(_), Some(_)) => anyhow::bail!(
                "catalog '{name}': both `{field}` and `{env_field}` are set; specify exactly one"
            ),
            (None, None) => {
                anyhow::bail!("catalog '{name}': either `{field}` or `{env_field}` must be set")
            }
            (Some(v), None) => Ok(v.clone()),
            (None, Some(env_name)) => env(env_name).with_context(|| {
                // Variable name, never the resolved value (rule 12).
                format!(
                    "catalog '{name}': environment variable '{env_name}' \
                     (configured via `{env_field}`) is not set"
                )
            }),
        }
    };
    match auth {
        OdataAuthConfig::Basic {
            user,
            password,
            password_env,
        } => Ok(OdataAuth::Basic {
            user: user.clone(),
            password: pick(password, password_env, "password", "password_env")?,
        }),
        OdataAuthConfig::Bearer { token, token_env } => Ok(OdataAuth::Bearer {
            token: pick(token, token_env, "token", "token_env")?,
        }),
    }
}

/// Build a `kind = "odata"` catalog into a [`DfCatalogProvider`]. Fetches
/// `$metadata` once at boot to enumerate entity sets (fail-fast on an
/// unreachable service); per-set schemas stay lazy.
async fn build_odata_catalog(
    name: &str,
    cfg: &OdataCatalogConfig,
) -> Result<Arc<dyn DfCatalogProvider>> {
    let auth = resolve_odata_auth(name, &cfg.auth)?;
    let connector =
        dataglot_federation::odata::OdataConnector::connect(name, cfg.service_url.clone(), auth)
            .with_context(|| format!("catalog '{name}': odata client build failed"))?;
    let connector = Arc::new(connector);
    connector
        .as_catalog_provider()
        .await
        .with_context(|| format!("catalog '{name}': failed to build odata catalog provider"))
}

/// Build a `kind = "sap_s4hana"` catalog into a [`DfCatalogProvider`] —
/// the same as [`build_odata_catalog`] plus the SAP `sap-client` /
/// `sap-language` request headers.
async fn build_sap_catalog(
    name: &str,
    cfg: &SapS4hanaCatalogConfig,
) -> Result<Arc<dyn DfCatalogProvider>> {
    let auth = resolve_odata_auth(name, &cfg.auth)?;
    let options = dataglot_federation::odata::SapOptions {
        sap_client: cfg.sap_client.clone(),
        sap_language: cfg.sap_language.clone(),
    };
    let connector = dataglot_federation::odata::SapConnector::connect(
        name,
        cfg.service_url.clone(),
        auth,
        &options,
    )
    .with_context(|| format!("catalog '{name}': SAP client build failed"))?;
    connector
        .as_catalog_provider()
        .await
        .with_context(|| format!("catalog '{name}': failed to build SAP catalog provider"))
}

/// Map a declared REST column type string to an Arrow `DataType`.
///
/// Kept in lockstep with the types `dataglot_federation::rest::decode` can
/// build; anything else is a boot error naming the table + column (never a
/// silent drop).
fn rest_column_type(
    table: &str,
    column: &str,
    ty: &str,
) -> Result<datafusion::arrow::datatypes::DataType> {
    use datafusion::arrow::datatypes::DataType;
    Ok(match ty.to_ascii_lowercase().as_str() {
        "utf8" | "string" => DataType::Utf8,
        "boolean" | "bool" => DataType::Boolean,
        "int32" | "i32" => DataType::Int32,
        "int64" | "i64" => DataType::Int64,
        "float64" | "f64" | "double" => DataType::Float64,
        other => anyhow::bail!(
            "catalog table '{table}' column '{column}': unsupported REST type '{other}' \
             (supported: utf8, boolean, int32, int64, float64)"
        ),
    })
}

/// Resolve a [`RestAuthConfig`] into the federation crate's [`RestAuth`],
/// enforcing exactly-one of literal / `*_env` per credential field and reading
/// the env var at boot. Never renders a secret in an error (CLAUDE.md rule 12).
///
/// [`RestAuth`]: dataglot_federation::rest::RestAuth
fn resolve_rest_auth(
    name: &str,
    auth: &RestAuthConfig,
) -> Result<dataglot_federation::rest::RestAuth> {
    resolve_rest_auth_with_env(name, auth, &|n: &str| std::env::var(n))
}

fn resolve_rest_auth_with_env(
    name: &str,
    auth: &RestAuthConfig,
    env: EnvLookup<'_>,
) -> Result<dataglot_federation::rest::RestAuth> {
    use dataglot_federation::rest::RestAuth;
    // Shared "exactly one of literal / env" resolver (mirrors the OData one).
    let pick = |literal: &Option<String>,
                env_var: &Option<String>,
                field: &str,
                env_field: &str|
     -> Result<String> {
        match (literal, env_var) {
            (Some(_), Some(_)) => anyhow::bail!(
                "catalog '{name}': both `{field}` and `{env_field}` are set; specify exactly one"
            ),
            (None, None) => {
                anyhow::bail!("catalog '{name}': either `{field}` or `{env_field}` must be set")
            }
            (Some(v), None) => Ok(v.clone()),
            (None, Some(env_name)) => env(env_name).with_context(|| {
                // Variable name, never the resolved value (rule 12).
                format!(
                    "catalog '{name}': environment variable '{env_name}' \
                     (configured via `{env_field}`) is not set"
                )
            }),
        }
    };
    match auth {
        RestAuthConfig::None => Ok(RestAuth::None),
        RestAuthConfig::Basic {
            user,
            password,
            password_env,
        } => Ok(RestAuth::Basic {
            user: user.clone(),
            password: pick(password, password_env, "password", "password_env")?,
        }),
        RestAuthConfig::Bearer { token, token_env } => Ok(RestAuth::Bearer {
            token: pick(token, token_env, "token", "token_env")?,
        }),
        RestAuthConfig::Header {
            name: header_name,
            value,
            value_env,
        } => Ok(RestAuth::Header {
            name: header_name.clone(),
            value: pick(value, value_env, "value", "value_env")?,
        }),
        // OAuth2 is connector-level (a live, refreshed bearer), not a static
        // per-request credential — `build_rest_catalog` resolves it via
        // `resolve_rest_oauth2` before this is reached.
        RestAuthConfig::Oauth2 { .. } => anyhow::bail!(
            "catalog '{name}': internal error — OAuth2 auth must be resolved at the catalog level"
        ),
    }
}

/// Resolve a [`RestAuthConfig::Oauth2`] into the federation crate's
/// [`OAuth2Config`], resolving the client id/secret (exactly-one-of literal /
/// `*_env`) at boot and never leaking a secret in an error (rule 12).
///
/// [`OAuth2Config`]: dataglot_federation::rest::OAuth2Config
fn resolve_rest_oauth2(
    name: &str,
    auth: &RestAuthConfig,
) -> Result<dataglot_federation::rest::OAuth2Config> {
    resolve_rest_oauth2_with_env(name, auth, &|n: &str| std::env::var(n))
}

fn resolve_rest_oauth2_with_env(
    name: &str,
    auth: &RestAuthConfig,
    env: EnvLookup<'_>,
) -> Result<dataglot_federation::rest::OAuth2Config> {
    use dataglot_federation::rest::OAuth2Config;
    let RestAuthConfig::Oauth2 {
        token_url,
        client_id,
        client_id_env,
        client_secret,
        client_secret_env,
        scope,
    } = auth
    else {
        anyhow::bail!("catalog '{name}': internal error — expected OAuth2 auth");
    };
    let pick = |literal: &Option<String>,
                env_var: &Option<String>,
                field: &str,
                env_field: &str|
     -> Result<String> {
        match (literal, env_var) {
            (Some(_), Some(_)) => anyhow::bail!(
                "catalog '{name}': both `{field}` and `{env_field}` are set; specify exactly one"
            ),
            (None, None) => {
                anyhow::bail!("catalog '{name}': either `{field}` or `{env_field}` must be set")
            }
            (Some(v), None) => Ok(v.clone()),
            (None, Some(env_name)) => env(env_name).with_context(|| {
                format!(
                    "catalog '{name}': environment variable '{env_name}' \
                     (configured via `{env_field}`) is not set"
                )
            }),
        }
    };
    let extra_params = scope
        .clone()
        .map(|s| vec![("scope".to_string(), s)])
        .unwrap_or_default();
    Ok(OAuth2Config {
        token_url: token_url.clone(),
        client_id: pick(client_id, client_id_env, "client_id", "client_id_env")?,
        client_secret: pick(
            client_secret,
            client_secret_env,
            "client_secret",
            "client_secret_env",
        )?,
        extra_params,
    })
}

/// Build a `kind = "rest"` catalog into a [`DfCatalogProvider`]. Each declared
/// table becomes a `TableProvider` over its endpoint. Schemas are declared (no
/// metadata document), so — unlike OData — there is no boot-time network fetch.
// No `.await` inside: REST schemas are declared, not fetched. `async` is kept
// for signature parity with the other `build_*_catalog` arms in the dispatch.
#[allow(clippy::unused_async)]
async fn build_rest_catalog(
    name: &str,
    cfg: &RestCatalogConfig,
) -> Result<Arc<dyn DfCatalogProvider>> {
    use datafusion::arrow::datatypes::{Field, Schema};
    use dataglot_federation::rest::{
        RestAuth, RestClientOptions, RestConnector, RestPagination, RestPushdownParam,
        RestSourceConfig, RestTable,
    };

    if cfg.tables.is_empty() {
        anyhow::bail!("catalog '{name}': kind = \"rest\" requires at least one table");
    }
    // OAuth2 is connector-level (one refreshed bearer for the whole source); it
    // overrides per-table static auth, which is then `None`. Any other auth is
    // resolved as the shared static credential.
    let oauth2 = match &cfg.auth {
        RestAuthConfig::Oauth2 { .. } => Some(resolve_rest_oauth2(name, &cfg.auth)?),
        _ => None,
    };
    let auth = if oauth2.is_some() {
        RestAuth::None
    } else {
        resolve_rest_auth(name, &cfg.auth)?
    };

    let mut tables = Vec::with_capacity(cfg.tables.len());
    for t in &cfg.tables {
        if t.columns.is_empty() {
            anyhow::bail!(
                "catalog '{name}' table '{}': at least one column must be declared",
                t.name
            );
        }
        let fields = t
            .columns
            .iter()
            .map(|c| {
                Ok(Field::new(
                    c.name.clone(),
                    rest_column_type(&t.name, &c.name, &c.data_type)?,
                    c.nullable,
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        let pagination = match &t.pagination {
            RestPaginationConfig::None => RestPagination::None,
            RestPaginationConfig::NextLink { next_path } => RestPagination::NextLink {
                next_path: next_path.clone(),
            },
        };
        // Fail fast on a pushdown column that isn't declared (a config typo) —
        // otherwise it would silently never match and never push.
        for p in &t.pushdown {
            if !t.columns.iter().any(|c| c.name == p.column) {
                anyhow::bail!(
                    "catalog '{name}' table '{}': pushdown column '{}' is not a declared column",
                    t.name,
                    p.column
                );
            }
        }
        let pushdown = t
            .pushdown
            .iter()
            .map(|p| RestPushdownParam {
                column: p.column.clone(),
                // Default the query-param name to the column name.
                param: p.param.clone().unwrap_or_else(|| p.column.clone()),
            })
            .collect();
        tables.push(RestTable {
            name: t.name.clone(),
            config: RestSourceConfig {
                url: t.url.clone(),
                records_path: t.records_path.clone(),
                auth: auth.clone(),
                pagination,
                pushdown,
            },
            schema: Arc::new(Schema::new(fields)),
        });
    }

    let opts = RestClientOptions {
        http2_prior_knowledge: cfg.http2_prior_knowledge,
    };
    let mut connector = RestConnector::new_with_options(name, tables, &opts)
        .with_context(|| format!("catalog '{name}': rest client build failed"))?;
    if let Some(oauth2_config) = oauth2 {
        connector = connector.with_oauth2_config(oauth2_config);
    }
    Ok(Arc::new(connector).as_catalog_provider(cfg.schema.clone()))
}

/// Build a `kind = "oracle"` catalog into a [`DfCatalogProvider`].
///
/// Split into its own `#[cfg]`-gated helper (rather than an inline
/// `match` arm) so the feature-gating reads cleanly and the
/// reject-without-feature path mirrors `dataglot-ballista`'s
/// `reject_ballista_without_feature`: the `CatalogConfig::Oracle`
/// surface is **always** compiled (so configs parse + redact
/// identically regardless of build), but the connector itself only
/// exists under `--features oracle` because the ODPI-C-backed
/// `oracle` crate dlopen's the **Oracle Instant Client** (a C runtime
/// dependency) — unlike the pure-Rust pg / mysql / snowflake clients,
/// which are compiled in unconditionally.
#[cfg(any(feature = "oracle", feature = "oracle-pure"))]
async fn build_oracle_catalog(
    name: &str,
    o: &OracleCatalogConfig,
) -> Result<(Arc<dyn DfCatalogProvider>, Option<ConnectorHealthHandle>)> {
    use dataglot_federation::oracle::OracleDriver;

    // Map the config driver to the federation enum; `None` → build default.
    let driver = o.driver.map(|d| match d {
        OracleDriverConfig::Oci => OracleDriver::Oci,
        OracleDriverConfig::Pure => OracleDriver::Pure,
    });
    // Reject an uncompiled driver *before* resolving secrets: a pure
    // capability check (no I/O, no credentials), so a misconfigured
    // `driver` reports its own clear error instead of being masked by a
    // missing-`password_env` failure (rule 12 — don't resolve a secret we
    // won't use).
    dataglot_federation::oracle::resolve_supported_driver(driver)
        .with_context(|| format!("catalog '{name}': unsupported oracle driver"))?;
    // Then resolve the password (a misconfigured `password_env` reports its
    // specific env-var error rather than being masked by a generic connect
    // failure — same ordering as the Snowflake arm).
    let password = resolve_oracle_password(name, o)?;
    let connector = dataglot_federation::oracle::OracleConnector::connect_with_driver(
        name.to_string(),
        &o.dsn,
        &o.user,
        &password,
        driver,
    )
    .await
    .with_context(|| format!("catalog '{name}': oracle connect failed"))?;
    let connector = Arc::new(connector);
    // `OracleConnector::as_catalog_provider` returns the concrete
    // `Arc<OracleCatalog>`; the binding-site coercion upcasts it to the
    // `Arc<dyn DfCatalogProvider>` this function hands back.
    let provider: Arc<dyn DfCatalogProvider> = connector
        .as_catalog_provider()
        .await
        .with_context(|| format!("catalog '{name}': failed to build catalog provider"))?;
    // Reuse the live backend for liveness: `SELECT 1 FROM DUAL` on the
    // existing connection instead of reconnecting on every poll tick.
    Ok((provider, Some(connector as ConnectorHealthHandle)))
}

/// Reject a `kind = "oracle"` catalog when the server was built with
/// **neither** Oracle backend feature. Mirrors `dataglot_ballista`-style
/// reject-without-feature stubs: the config deserializes fine, but boot
/// fails fast with an actionable message instead of silently dropping the
/// source. (When at least one backend is compiled, the feature-on variant
/// runs and rejects a specific uncompiled `driver` selection itself.)
#[cfg(not(any(feature = "oracle", feature = "oracle-pure")))]
#[allow(clippy::unused_async)] // signature parity with the feature-on variant
async fn build_oracle_catalog(
    name: &str,
    _o: &OracleCatalogConfig,
) -> Result<(Arc<dyn DfCatalogProvider>, Option<ConnectorHealthHandle>)> {
    anyhow::bail!(
        "catalog '{name}': kind = \"oracle\" requires this server to be built with an \
         Oracle backend — `--features oracle` (OCI / ODPI-C, a C runtime dependency) or \
         `--features oracle-pure` (pure-Rust); this binary was built with neither"
    )
}

/// Build an [`ObjectStorageCatalogConfig`] into a
/// `MemoryCatalogProvider` whose schemas hold one
/// `ListingTable` per declared file.
///
/// Schema inference happens here, at boot — `ListingTable::try_new`
/// reads the parquet footer once. A missing file, wrong format,
/// or unreadable storage surfaces immediately as a typed catalog
/// error rather than a first-query mystery.
///
/// Per the spec, only `file://` URLs are accepted in the MVP.
/// Non-`file` schemes return a typed configuration error so
/// operators see the gap clearly.
/// Validate an object-storage table URL scheme at boot. `file://` is
/// always allowed; `s3://` requires the catalog to declare an `[s3]`
/// block; everything else is a typed config error.
fn validate_object_storage_url(
    catalog: &str,
    table: &str,
    url: &str,
    s3_configured: bool,
) -> Result<()> {
    if url.starts_with("file://") {
        return Ok(());
    }
    if url.starts_with("s3://") {
        if s3_configured {
            return Ok(());
        }
        anyhow::bail!(
            "catalog '{catalog}', table '{table}': url '{url}' is `s3://` but this catalog has \
             no `[s3]` block — add one (endpoint / region / access_key_id / \
             secret_access_key_env) to enable S3 access"
        );
    }
    anyhow::bail!(
        "catalog '{catalog}', table '{table}': unsupported URL scheme in '{url}' — use `file://` \
         (always available) or `s3://` (with an `[s3]` block). gs:// / abfs:// are not yet supported"
    )
}

/// Build one `AmazonS3` object store per distinct bucket referenced by the
/// catalog's `s3://` tables, returning `(registration-url, store)` pairs to
/// register on a `SessionContext` / `RuntimeEnv`. Empty when no table uses
/// `s3://`. The secret is resolved once (rule 12: `*_env` wins, never
/// logged).
///
/// # Errors
/// A malformed `s3://` URL, an `s3://` table with no `[s3]` block, an unset
/// `secret_access_key_env`, or the object-store builder rejecting the config.
pub(crate) fn object_storage_s3_stores(
    catalog: &str,
    cfg: &ObjectStorageCatalogConfig,
) -> Result<Vec<(url::Url, Arc<dyn object_store::ObjectStore>)>> {
    use std::collections::BTreeSet;

    let mut buckets: BTreeSet<String> = BTreeSet::new();
    for t in &cfg.tables {
        if let Some(rest) = t.url.strip_prefix("s3://") {
            let bucket = rest.split('/').next().unwrap_or_default();
            if bucket.is_empty() {
                anyhow::bail!(
                    "catalog '{catalog}', table '{}': malformed s3 url '{}' (no bucket)",
                    t.name,
                    t.url
                );
            }
            buckets.insert(bucket.to_string());
        }
    }
    if buckets.is_empty() {
        return Ok(Vec::new());
    }

    let s3 = cfg.s3.as_ref().ok_or_else(|| {
        anyhow::anyhow!("catalog '{catalog}': has `s3://` tables but no `[s3]` block")
    })?;
    let secret = resolve_s3_secret(catalog, s3)?;
    let region = s3.region.clone().unwrap_or_else(|| "us-east-1".to_string());

    let mut out = Vec::with_capacity(buckets.len());
    for bucket in buckets {
        let mut builder = object_store::aws::AmazonS3Builder::new()
            .with_bucket_name(&bucket)
            .with_region(&region)
            // path_style_access=true → NOT virtual-hosted (MinIO default).
            .with_virtual_hosted_style_request(!s3.path_style_access);
        if let Some(endpoint) = &s3.endpoint {
            builder = builder
                .with_endpoint(endpoint.clone())
                .with_allow_http(endpoint.starts_with("http://"));
        }
        if let Some(key) = &s3.access_key_id {
            builder = builder.with_access_key_id(key.clone());
        }
        if let Some(secret) = &secret {
            builder = builder.with_secret_access_key(secret.clone());
        }
        let store = builder.build().with_context(|| {
            format!("catalog '{catalog}': failed to build the S3 client for bucket '{bucket}'")
        })?;
        let store_url = url::Url::parse(&format!("s3://{bucket}"))
            .with_context(|| format!("catalog '{catalog}': invalid bucket name '{bucket}'"))?;
        out.push((
            store_url,
            Arc::new(store) as Arc<dyn object_store::ObjectStore>,
        ));
    }
    Ok(out)
}

/// Resolve the S3 secret access key: `secret_access_key_env` (looked up
/// now) wins over the inline `secret_access_key`; `None` if neither is
/// set (the object-store client then falls back to the AWS credential
/// chain). The value is never logged (rule 12).
fn resolve_s3_secret(catalog: &str, s3: &ObjectStorageS3Config) -> Result<Option<String>> {
    if let Some(env_name) = &s3.secret_access_key_env {
        let value = std::env::var(env_name).with_context(|| {
            format!(
                "catalog '{catalog}': s3.secret_access_key_env names `{env_name}`, \
                 which is not set. Set it, e.g.  export {env_name}=..."
            )
        })?;
        return Ok(Some(value));
    }
    Ok(s3.secret_access_key.clone())
}

async fn build_object_storage_catalog(
    name: &str,
    cfg: &ObjectStorageCatalogConfig,
) -> Result<Arc<dyn DfCatalogProvider>> {
    use datafusion::catalog::{MemoryCatalogProvider, MemorySchemaProvider, SchemaProvider};
    use datafusion::datasource::file_format::csv::CsvFormat;
    use datafusion::datasource::file_format::json::JsonFormat;
    use datafusion::datasource::file_format::parquet::ParquetFormat;
    use datafusion::datasource::file_format::FileFormat;
    use datafusion::datasource::listing::{
        ListingOptions, ListingTable, ListingTableConfig, ListingTableUrl,
    };
    use datafusion::prelude::SessionContext;

    if cfg.tables.is_empty() {
        // An empty catalog isn't useful — surface as a config
        // error rather than register an unreachable name.
        anyhow::bail!(
            "catalog '{name}': object_storage catalog has no `tables` declared; \
             add at least one `{{ name, url, format }}` entry"
        );
    }

    // Throwaway SessionContext for schema inference. The real
    // SessionContext is built per-pgwire-session later; here we
    // just need a SessionState to feed `infer_schema`. The
    // session-config defaults are fine — schema inference doesn't
    // depend on batch size or partition count.
    let inference_ctx = SessionContext::new();

    // Register S3 stores on the inference context so `s3://` schema
    // inference works here; the same stores are registered on the shared
    // per-session runtime at boot (see `object_storage_s3_stores` callers
    // in server.rs) so query-time reads resolve too.
    for (store_url, store) in object_storage_s3_stores(name, cfg)? {
        inference_ctx.register_object_store(&store_url, store);
    }

    let session_state = inference_ctx.state();

    let catalog = Arc::new(MemoryCatalogProvider::new());

    for table in &cfg.tables {
        // Accept `file://` always and `s3://` when the catalog declares an
        // `[s3]` block; reject anything else with an actionable message.
        validate_object_storage_url(name, &table.name, &table.url, cfg.s3.is_some())?;

        let listing_url = ListingTableUrl::parse(&table.url).with_context(|| {
            format!(
                "catalog '{name}', table '{}': failed to parse url '{}'",
                table.name, table.url
            )
        })?;

        let format: Arc<dyn FileFormat> = match table.format {
            ObjectStorageFormat::Parquet => Arc::new(ParquetFormat::default()),
            // CSV: assume a header row (the overwhelmingly common case for
            // "query my files"); DataFusion infers column names from it.
            ObjectStorageFormat::Csv => Arc::new(CsvFormat::default().with_has_header(true)),
            ObjectStorageFormat::Json => Arc::new(JsonFormat::default()),
        };
        let options =
            ListingOptions::new(format).with_file_extension(table.format.file_extension());

        let resolved_schema = options
            .infer_schema(&session_state, &listing_url)
            .await
            .with_context(|| {
                format!(
                    "catalog '{name}', table '{}': failed to infer schema from '{}'",
                    table.name, table.url
                )
            })?;

        // DataFusion 53.1's `infer_schema` returns Ok(empty schema)
        // when zero files match the URL — a missing path produces a
        // zero-field `Schema`, not an error. Catch that here so the
        // fail-fast contract documented above ("missing-table /
        // wrong-format / unreadable storage all surface here") holds:
        // an empty inferred schema means no files were found, and the
        // server should refuse to boot rather than register a
        // queryable-but-empty table.
        if resolved_schema.fields().is_empty() {
            anyhow::bail!(
                "catalog '{name}', table '{}': no files matched '{}' \
                 (file may not exist or have an extension other than `{}`)",
                table.name,
                table.url,
                table.format.file_extension()
            );
        }

        let listing_cfg = ListingTableConfig::new(listing_url)
            .with_listing_options(options)
            .with_schema(resolved_schema);
        let listing_table = ListingTable::try_new(listing_cfg).with_context(|| {
            format!(
                "catalog '{name}', table '{}': failed to build ListingTable",
                table.name
            )
        })?;

        let schema_name = table.schema.as_deref().unwrap_or("public");

        // Lookup-or-insert per schema. Several tables may share
        // the same schema name; we register them all on one
        // `MemorySchemaProvider`.
        let schema_provider = if let Some(existing) = catalog.schema(schema_name) {
            existing
        } else {
            let new_schema = Arc::new(MemorySchemaProvider::new());
            catalog
                .register_schema(
                    schema_name,
                    Arc::clone(&new_schema) as Arc<dyn SchemaProvider>,
                )
                .with_context(|| {
                    format!("catalog '{name}': failed to register schema '{schema_name}'")
                })?;
            Arc::clone(&new_schema) as Arc<dyn SchemaProvider>
        };
        schema_provider
            .register_table(table.name.clone(), Arc::new(listing_table))
            .with_context(|| {
                format!(
                    "catalog '{name}', table '{}': failed to register table on schema '{schema_name}'",
                    table.name
                )
            })?;
    }

    Ok(catalog as Arc<dyn DfCatalogProvider>)
}

fn num_cpus() -> usize {
    std::thread::available_parallelism().map_or(4, std::num::NonZero::get)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn test_default_config() {
        let config = ServerConfig::default();
        assert_eq!(config.host, "127.0.0.1");
        assert_eq!(config.port, 5432);
        assert_eq!(config.batch_size, 8192);
        assert!(config.catalogs.is_empty());
        assert!(
            config.masks.is_empty(),
            "default config has no masks ⇒ NoopPolicyEnforcer at boot",
        );
        assert!(
            config.lineage.is_none(),
            "default config has no lineage block ⇒ NoopLineageEmitter at boot",
        );
    }

    #[test]
    fn lineage_config_serde_roundtrip_openlineage_http() {
        // Pin the wire shape — operators write this JSON in
        // `dataglot.toml`. Any rename / retag breaks operator
        // configs, so this is a regression guard.
        let cfg = LineageConfig::OpenlineageHttp {
            endpoint: "http://marquez:5000/api/v1/lineage".into(),
            namespace: "dataglot.acme".into(),
        };
        let json = serde_json::to_value(&cfg).unwrap();
        assert_eq!(json["kind"], "openlineage_http");
        assert_eq!(json["endpoint"], "http://marquez:5000/api/v1/lineage");
        assert_eq!(json["namespace"], "dataglot.acme");

        let parsed: LineageConfig = serde_json::from_value(json).unwrap();
        assert_eq!(parsed, cfg);
    }

    #[test]
    fn server_config_lineage_defaults_to_none_when_omitted() {
        // ServerConfig with no `lineage` key parses cleanly and
        // surfaces `None`. Mirrors the pattern for other optional
        // top-level blocks (`governance`, etc.).
        let json = r#"{
            "host": "0.0.0.0",
            "port": 5432,
            "batch_size": 8192,
            "partitions": 4,
            "default_catalog": "dataglot",
            "default_schema": "public"
        }"#;
        let cfg: ServerConfig = serde_json::from_str(json).unwrap();
        assert!(cfg.lineage.is_none());
    }

    #[test]
    fn server_config_webhook_defaults_to_none_when_omitted() {
        // ServerConfig with no `webhook` key parses cleanly and
        // surfaces `None`. Mirrors the lineage and governance
        // patterns: an opt-in block whose absence keeps boot
        // bit-identical to pre-slice-1 behaviour.
        let json = r#"{
            "host": "0.0.0.0",
            "port": 5432,
            "batch_size": 8192,
            "partitions": 4,
            "default_catalog": "dataglot",
            "default_schema": "public"
        }"#;
        let cfg: ServerConfig = serde_json::from_str(json).unwrap();
        assert!(cfg.webhook.is_none());
    }

    #[test]
    fn server_config_parses_webhook_block() {
        // Pins the documented JSON shape (spec 04 §"Slice 1"). Any
        // rename of `addr` / `secret_env` here breaks operator
        // configs in the field — this assertion is the regression
        // guard.
        let json = r#"{
            "host": "0.0.0.0",
            "port": 5432,
            "batch_size": 8192,
            "partitions": 4,
            "default_catalog": "dataglot",
            "default_schema": "public",
            "webhook": {
                "addr": "0.0.0.0:8080",
                "secret_env": "DATAGLOT_WEBHOOK_SECRET"
            }
        }"#;
        let cfg: ServerConfig = serde_json::from_str(json).unwrap();
        let webhook = cfg.webhook.expect("webhook block parses to Some");
        assert_eq!(webhook.addr.port(), 8080);
        assert_eq!(webhook.secret_env, "DATAGLOT_WEBHOOK_SECRET");
    }

    #[test]
    fn server_config_parses_lineage_block() {
        let json = r#"{
            "host": "0.0.0.0",
            "port": 5432,
            "batch_size": 8192,
            "partitions": 4,
            "default_catalog": "dataglot",
            "default_schema": "public",
            "lineage": {
                "kind": "openlineage_http",
                "endpoint": "http://marquez:5000/api/v1/lineage",
                "namespace": "dataglot.acme"
            }
        }"#;
        let cfg: ServerConfig = serde_json::from_str(json).unwrap();
        match cfg.lineage {
            Some(LineageConfig::OpenlineageHttp {
                endpoint,
                namespace,
            }) => {
                assert_eq!(endpoint, "http://marquez:5000/api/v1/lineage");
                assert_eq!(namespace, "dataglot.acme");
            }
            other => panic!("expected OpenlineageHttp, got {other:?}"),
        }
    }

    // ----- CatalogServiceConfig (Phase 1 task 08) tests ------------

    #[test]
    fn catalog_service_config_serde_roundtrip() {
        let cfg = CatalogServiceConfig::Postgres(PostgresStoreConfig {
            dsn: "host=catalog-db port=5432 user=dataglot dbname=catalog".into(),
            org_id: "default".into(),
        });
        // Untagged: the Postgres variant serializes to its inner fields.
        let json = serde_json::to_value(&cfg).unwrap();
        assert_eq!(json["org_id"], "default");
        let parsed: CatalogServiceConfig = serde_json::from_value(json).unwrap();
        assert_eq!(parsed.org_id(), "default");
        let CatalogServiceConfig::Postgres(p) = &parsed else {
            panic!("dsn block must parse to the Postgres variant");
        };
        assert!(p.dsn.contains("catalog-db"));
    }

    #[test]
    fn catalog_service_config_embedded_variant_from_path() {
        // A block with `path` (no dsn) selects the embedded backend.
        let json = r#"{ "path": "/var/lib/dataglot/meta.json" }"#;
        let cfg: CatalogServiceConfig = serde_json::from_str(json).unwrap();
        let CatalogServiceConfig::Embedded(e) = &cfg else {
            panic!("path block must parse to the Embedded variant");
        };
        assert_eq!(
            e.path,
            std::path::PathBuf::from("/var/lib/dataglot/meta.json")
        );
        assert_eq!(e.org_id, "default");
    }

    #[test]
    fn catalog_service_config_org_id_defaults_to_default() {
        // Operator omits org_id → serde-default fills it in.
        let json = r#"{ "dsn": "host=x" }"#;
        let cfg: CatalogServiceConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.org_id(), "default");
    }

    #[test]
    fn catalog_service_config_debug_redacts_dsn() {
        // CLAUDE.md rule 12 regression guard.
        let cfg = CatalogServiceConfig::Postgres(PostgresStoreConfig {
            dsn: "postgresql://datasvc:supersecret@10.0.0.5:5432/catalog".into(),
            org_id: "default".into(),
        });
        let s = format!("{cfg:?}");
        assert!(
            !s.contains("supersecret"),
            "Debug must not leak DSN password: {s}"
        );
        assert!(s.contains("<redacted>"), "expected <redacted> marker: {s}");
        assert!(s.contains("default"), "expected org_id visible: {s}");
    }

    #[test]
    fn server_config_catalog_service_defaults_to_none_when_omitted() {
        let json = r#"{
            "host": "0.0.0.0",
            "port": 5432,
            "batch_size": 8192,
            "partitions": 4,
            "default_catalog": "dataglot",
            "default_schema": "public"
        }"#;
        let cfg: ServerConfig = serde_json::from_str(json).unwrap();
        assert!(cfg.catalog_service.is_none());
    }

    #[test]
    fn toml_roundtrips_full_server_config() {
        //: TOML is the canonical config format. Pin that the `toml`
        // crate round-trips a rich ServerConfig — internally-tagged
        // catalog/auth/pagination enums, the untagged catalog_service enum,
        // nested rest tables/columns, the identities map, and the masks
        // array — so a format regression is caught here.
        let json = r#"{
            "host": "0.0.0.0", "port": 5432,
            "auth": { "mode": "trust" },
            "identities": { "ops": { "groups": ["QC"], "password_env": "OPS_PW" } },
            "catalogs": {
                "pg": { "kind": "postgres", "dsn_env": "PG_DSN" },
                "api": {
                    "kind": "rest", "schema": "public",
                    "auth": { "kind": "bearer", "token_env": "SF_TOKEN" },
                    "tables": [
                        { "name": "account",
                          "url": "https://x/services/data/v58.0/query?q=SELECT+Id+FROM+Account",
                          "records_path": "records",
                          "pagination": { "kind": "next_link", "next_path": "nextRecordsUrl" },
                          "columns": [ {"name":"Id","type":"utf8"}, {"name":"Name","type":"utf8"} ] }
                    ]
                }
            },
            "masks": [ { "table": "pg.public.account", "column": "Name", "mask_literal": "***" } ],
            "catalog_service": { "path": "/tmp/meta.json" }
        }"#;
        let cfg: ServerConfig = serde_json::from_str(json).expect("json fixture parses");

        let toml_str = toml::to_string(&cfg).expect("ServerConfig serializes to TOML");
        let back: ServerConfig =
            toml::from_str(&toml_str).unwrap_or_else(|e| panic!("TOML re-parse: {e}\n{toml_str}"));
        assert_eq!(back.catalogs.len(), 2, "both catalogs survive");
        assert!(
            back.catalog_service.is_some(),
            "untagged catalog_service survives"
        );
        assert_eq!(back.masks.len(), 1, "masks survive");
    }

    #[test]
    fn loads_config_from_toml_and_json_by_extension() {
        //: `.toml` parses as TOML, `.json` still parses as JSON
        // (back-compat) — both through the same serde structs.
        use std::io::Write as _;
        let dir = tempfile::tempdir().unwrap();

        let toml_path = dir.path().join("dataglot.toml");
        let mut f = std::fs::File::create(&toml_path).unwrap();
        writeln!(f, "host = \"0.0.0.0\"\nport = 5455\n[catalogs.pg]\nkind = \"postgres\"\ndsn_env = \"PG_DSN\"").unwrap();
        let cfg = ServerConfig::load_from_file(&toml_path).expect("toml loads");
        assert_eq!(cfg.port, 5455);
        assert_eq!(cfg.catalogs.len(), 1);

        let json_path = dir.path().join("dataglot.json");
        std::fs::write(
            &json_path,
            r#"{"port":5456,"catalogs":{"pg":{"kind":"postgres","dsn_env":"PG_DSN"}}}"#,
        )
        .unwrap();
        let cfg2 = ServerConfig::load_from_file(&json_path).expect("json still loads");
        assert_eq!(cfg2.port, 5456);
    }

    #[test]
    fn server_config_parses_catalog_service_block() {
        let json = r#"{
            "host": "0.0.0.0",
            "port": 5432,
            "batch_size": 8192,
            "partitions": 4,
            "default_catalog": "dataglot",
            "default_schema": "public",
            "catalog_service": {
                "dsn": "host=catalog-db port=5432 user=dataglot password=secret dbname=catalog",
                "org_id": "default"
            }
        }"#;
        let cfg: ServerConfig = serde_json::from_str(json).unwrap();
        let svc = cfg.catalog_service.expect("present");
        assert_eq!(svc.org_id(), "default");
        let CatalogServiceConfig::Postgres(p) = &svc else {
            panic!("dsn block must parse to the Postgres variant");
        };
        assert!(p.dsn.contains("catalog-db"));
    }

    // ----- BallistaServerConfig (Phase 2 slice 3a) tests --------------
    //
    // The `[ballista]` config block compiles regardless of the
    // `ballista` feature flag (so JSON parsing stays uniform across
    // dataglot-server feature configurations); these tests live in
    // the default-feature test set on purpose. Behaviour beyond
    // parsing (boot dispatch, feature-off error) is exercised in
    // `crate::server::tests`.

    #[test]
    fn server_config_ballista_block_omitted_defaults_to_none() {
        let json = r#"{
            "host": "0.0.0.0",
            "port": 5432,
            "batch_size": 8192,
            "partitions": 4,
            "default_catalog": "dataglot",
            "default_schema": "public"
        }"#;
        let cfg: ServerConfig = serde_json::from_str(json).unwrap();
        assert!(
            cfg.ballista.is_none(),
            "expected `ballista` to default to None when omitted"
        );
    }

    #[test]
    fn server_config_empty_ballista_block_picks_up_defaults() {
        let json = r#"{
            "host": "0.0.0.0",
            "port": 5432,
            "batch_size": 8192,
            "partitions": 4,
            "default_catalog": "dataglot",
            "default_schema": "public",
            "ballista": {}
        }"#;
        let cfg: ServerConfig = serde_json::from_str(json).unwrap();
        let ballista = cfg.ballista.expect("ballista block present");
        assert_eq!(
            ballista.standalone_parallelism, 2,
            "empty ballista block should pick up the default parallelism (2)"
        );
        // Multi-executor defaults: embedded standalone shape.
        assert_eq!(
            ballista.external_executors, 0,
            "default is embedded standalone (0 external executors)"
        );
        assert_eq!(
            ballista.scheduler_grpc_port, 50051,
            "default scheduler gRPC port"
        );
    }

    #[test]
    fn server_config_external_executors_round_trips() {
        //: opting into multi-executor mode via config.
        let json = r#"{
            "host": "0.0.0.0",
            "port": 5432,
            "batch_size": 8192,
            "partitions": 4,
            "default_catalog": "dataglot",
            "default_schema": "public",
            "ballista": {
                "standalone_parallelism": 4,
                "external_executors": 2,
                "scheduler_grpc_port": 50060
            }
        }"#;
        let cfg: ServerConfig = serde_json::from_str(json).unwrap();
        let ballista = cfg.ballista.expect("ballista block present");
        assert_eq!(ballista.external_executors, 2);
        assert_eq!(ballista.scheduler_grpc_port, 50060);
        assert_eq!(ballista.standalone_parallelism, 4);
    }

    #[test]
    fn validate_rejects_zero_scheduler_grpc_port_with_external_executors() {
        //: external executors need a fixed port to register with.
        let cfg = ServerConfig {
            ballista: Some(BallistaServerConfig {
                external_executors: 2,
                scheduler_grpc_port: 0,
                ..Default::default()
            }),
            ..ServerConfig::default()
        };
        let err = cfg
            .validate()
            .expect_err("port 0 + external executors must fail");
        assert!(
            err.to_string().contains("scheduler_grpc_port"),
            "error should name the offending field, got: {err}"
        );

        // Port 0 is fine in embedded-standalone mode (no external executors).
        let ok = ServerConfig {
            ballista: Some(BallistaServerConfig {
                external_executors: 0,
                scheduler_grpc_port: 0,
                ..Default::default()
            }),
            ..ServerConfig::default()
        };
        assert!(
            ok.validate().is_ok(),
            "port 0 is fine without external executors"
        );
    }

    #[test]
    fn server_config_explicit_ballista_parallelism_round_trips() {
        let json = r#"{
            "host": "0.0.0.0",
            "port": 5432,
            "batch_size": 8192,
            "partitions": 4,
            "default_catalog": "dataglot",
            "default_schema": "public",
            "ballista": {
                "standalone_parallelism": 8
            }
        }"#;
        let cfg: ServerConfig = serde_json::from_str(json).unwrap();
        let ballista = cfg.ballista.as_ref().expect("ballista block present");
        assert_eq!(ballista.standalone_parallelism, 8);

        // Round-trip: re-serialize and re-parse, value should survive.
        let serialized = serde_json::to_string(&cfg).expect("serialize");
        let reparsed: ServerConfig = serde_json::from_str(&serialized).expect("re-parse");
        assert_eq!(
            reparsed.ballista.as_ref().map(|b| b.standalone_parallelism),
            Some(8)
        );
    }

    // ----- CatalogBinding (Phase 1 task 07) tests ------------------

    #[test]
    fn postgres_catalog_binding_strips_userinfo_from_dsn() {
        // CLAUDE.md rule 12 — credentials never appear on the
        // binding. The DSN's `user:pass@` segment must be elided.
        let cfg = CatalogConfig::Postgres(PostgresCatalogConfig {
            dsn: Some("postgresql://datasvc:supersecret@10.0.0.5:5432/billing".into()),
            dsn_env: None,
            ..Default::default()
        });
        let CatalogBinding::LiveConnector(b) = cfg.binding() else {
            panic!("postgres must bind to LiveConnector");
        };
        assert_eq!(b.kind, LiveConnectorKind::Postgres);
        assert!(
            !b.endpoint_hint.contains("supersecret"),
            "endpoint hint must not contain the DSN password, got {:?}",
            b.endpoint_hint
        );
        assert!(
            !b.endpoint_hint.contains("datasvc"),
            "endpoint hint must not contain the DSN user, got {:?}",
            b.endpoint_hint
        );
        assert!(
            b.endpoint_hint.contains("10.0.0.5:5432"),
            "endpoint hint should expose host:port, got {:?}",
            b.endpoint_hint
        );
    }

    #[test]
    fn postgres_catalog_binding_renders_env_var_indirection() {
        // dsn-env variant: hint records the env var name as a
        // visible indirection without resolving (resolution is
        // an execution-time concern).
        let cfg = CatalogConfig::Postgres(PostgresCatalogConfig {
            dsn: None,
            dsn_env: Some("PG_USERS_DSN".into()),
            ..Default::default()
        });
        let CatalogBinding::LiveConnector(b) = cfg.binding() else {
            panic!("postgres must bind to LiveConnector");
        };
        assert_eq!(b.endpoint_hint, "<env:PG_USERS_DSN>");
    }

    #[test]
    fn mysql_catalog_binding_strips_userinfo_from_dsn() {
        let cfg = CatalogConfig::Mysql(MysqlCatalogConfig {
            dsn: Some("mysql://root:rootpass@db.example.com:3306/sales".into()),
            dsn_env: None,
            ..Default::default()
        });
        let CatalogBinding::LiveConnector(b) = cfg.binding() else {
            panic!("mysql must bind to LiveConnector");
        };
        assert_eq!(b.kind, LiveConnectorKind::Mysql);
        assert!(!b.endpoint_hint.contains("rootpass"));
        assert!(!b.endpoint_hint.contains("root"));
        assert!(b.endpoint_hint.contains("db.example.com:3306"));
    }

    #[test]
    fn snowflake_catalog_binding_uses_account_as_endpoint_hint() {
        // Snowflake doesn't have a DSN; the account identifier
        // is the public "host" equivalent and is safe to surface
        // verbatim (it appears in the Snowsight URL anyway).
        // Pin that the hint is the account, never any auth-
        // adjacent field.
        let cfg = CatalogConfig::Snowflake(SnowflakeCatalogConfig {
            account: "acme-corp.us-east-1".into(),
            warehouse: "COMPUTE_WH".into(),
            database: "ANALYTICS".into(),
            user: "DATAGLOT_SVC".into(),
            password: Some("super-secret".into()),
            password_env: None,
            private_key_env: None,
            schema: Some("PUBLIC".into()),
            role: Some("READER".into()),
        });
        let CatalogBinding::LiveConnector(b) = cfg.binding() else {
            panic!("snowflake must bind to LiveConnector");
        };
        assert_eq!(b.kind, LiveConnectorKind::Snowflake);
        assert_eq!(b.endpoint_hint, "acme-corp.us-east-1");
        assert!(!b.endpoint_hint.contains("super-secret"));
        assert!(!b.endpoint_hint.contains("DATAGLOT_SVC"));
        assert!(!b.endpoint_hint.contains("READER"));
    }

    #[test]
    fn oracle_catalog_binding_uses_dsn_as_endpoint_hint() {
        // The Oracle Easy Connect DSN carries no userinfo —
        // user/password are separate fields — so the literal DSN is
        // safe to surface verbatim. Pin that neither the password nor
        // the (auth-adjacent) user leaks into the hint.
        let cfg = CatalogConfig::Oracle(OracleCatalogConfig {
            dsn: "//db.internal:1521/ORCLPDB1".into(),
            user: "DATAGLOT_SVC".into(),
            password: Some("super-secret".into()),
            password_env: None,
            schema: Some("SALES".into()),
            driver: None,
        });
        let CatalogBinding::LiveConnector(b) = cfg.binding() else {
            panic!("oracle must bind to LiveConnector");
        };
        assert_eq!(b.kind, LiveConnectorKind::Oracle);
        assert_eq!(b.endpoint_hint, "//db.internal:1521/ORCLPDB1");
        assert!(!b.endpoint_hint.contains("super-secret"));
        assert!(!b.endpoint_hint.contains("DATAGLOT_SVC"));
    }

    #[test]
    fn oracle_endpoint_hint_strips_embedded_userinfo() {
        // Defense-in-depth: even though the Oracle config keeps creds
        // in separate fields, a DSN that embeds a `user/pass@` prefix
        // (some Oracle tooling accepts it) must never surface that
        // prefix in the binding hint (CLAUDE.md rule 12).
        let cfg = CatalogConfig::Oracle(OracleCatalogConfig {
            dsn: "scott/tiger@//db.internal:1521/ORCLPDB1".into(),
            user: "DATAGLOT_SVC".into(),
            password: None,
            password_env: Some("EXADATA_PASSWORD".into()),
            schema: None,
            driver: None,
        });
        let CatalogBinding::LiveConnector(b) = cfg.binding() else {
            panic!("oracle must bind to LiveConnector");
        };
        assert_eq!(b.endpoint_hint, "//db.internal:1521/ORCLPDB1");
        assert!(
            !b.endpoint_hint.contains("scott"),
            "user leaked: {}",
            b.endpoint_hint
        );
        assert!(
            !b.endpoint_hint.contains("tiger"),
            "password leaked: {}",
            b.endpoint_hint
        );
    }

    /// Pin the on-disk serde shape: a `kind = "oracle"` config object
    /// deserializes into `CatalogConfig::Oracle` and round-trips
    /// through serialize → deserialize unchanged.
    #[test]
    fn catalog_config_oracle_serde_roundtrip() {
        let json = r#"{
            "kind": "oracle",
            "dsn": "//db.internal:1521/ORCLPDB1",
            "user": "DATAGLOT_SVC",
            "password_env": "EXADATA_PASSWORD",
            "schema": "SALES"
        }"#;
        let cfg: CatalogConfig = serde_json::from_str(json).expect("kind=oracle parses");
        let CatalogConfig::Oracle(o) = &cfg else {
            panic!("expected CatalogConfig::Oracle, got {cfg:?}");
        };
        assert_eq!(o.dsn, "//db.internal:1521/ORCLPDB1");
        assert_eq!(o.user, "DATAGLOT_SVC");
        assert_eq!(o.password, None);
        assert_eq!(o.password_env.as_deref(), Some("EXADATA_PASSWORD"));
        assert_eq!(o.schema.as_deref(), Some("SALES"));
        // `driver` omitted → None (the build default applies at connect).
        assert_eq!(o.driver, None);

        // Round-trip: serialize → deserialize → same variant + fields.
        let reser = serde_json::to_string(&cfg).expect("serializes");
        let back: CatalogConfig = serde_json::from_str(&reser).expect("re-parses");
        let CatalogConfig::Oracle(o2) = &back else {
            panic!("round-trip lost the Oracle variant: {back:?}");
        };
        assert_eq!(o2.dsn, o.dsn);
        assert_eq!(o2.user, o.user);
        assert_eq!(o2.password_env, o.password_env);
        assert_eq!(o2.schema, o.schema);
        assert_eq!(o2.driver, o.driver);
    }

    ///: the per-catalog `driver` field parses the lowercase wire
    /// names `"oci"` / `"pure"` and round-trips. The config surface is
    /// always compiled regardless of which backend feature is on.
    #[test]
    fn catalog_config_oracle_driver_parses() {
        for (literal, expected) in [
            ("oci", OracleDriverConfig::Oci),
            ("pure", OracleDriverConfig::Pure),
        ] {
            let json = format!(
                r#"{{ "kind": "oracle", "dsn": "//h:1521/SVC", "user": "U", "driver": "{literal}" }}"#
            );
            let cfg: CatalogConfig =
                serde_json::from_str(&json).expect("kind=oracle with driver parses");
            let CatalogConfig::Oracle(o) = &cfg else {
                panic!("expected CatalogConfig::Oracle, got {cfg:?}");
            };
            assert_eq!(o.driver, Some(expected), "driver = {literal:?}");

            // Round-trips back to the same lowercase literal.
            let reser = serde_json::to_string(&cfg).expect("serializes");
            assert!(
                reser.contains(&format!("\"{literal}\"")),
                "driver should serialize to {literal:?}: {reser}"
            );
        }

        // An unknown driver is rejected by serde (closed enum).
        let bad = r#"{ "kind": "oracle", "dsn": "//h:1521/SVC", "user": "U", "driver": "thick" }"#;
        assert!(
            serde_json::from_str::<CatalogConfig>(bad).is_err(),
            "unknown driver must not deserialize"
        );
    }

    #[test]
    fn warehouse_catalog_binding_is_iceberg_cache() {
        let cfg = CatalogConfig::Warehouse(WarehouseCatalogConfig {
            catalog_url: "http://lakekeeper:8181/catalog".into(),
            warehouse: "main".into(),
            s3_endpoint: Some("http://minio:9000".into()),
            s3_region: Some("us-east-1".into()),
            credentials: WarehouseCredentialsConfig::Static {
                access_key_id: "AKIA".into(),
                secret_access_key: None,
                secret_access_key_env: Some("WH_SECRET".into()),
            },
        });
        let CatalogBinding::IcebergCache(b) = cfg.binding() else {
            panic!("warehouse must bind to IcebergCache");
        };
        assert_eq!(b.catalog_url, "http://lakekeeper:8181/catalog");
        assert_eq!(b.warehouse, "main");
        assert!(
            b.table_path.is_empty(),
            "table_path is lazily resolved; empty at boot"
        );
    }

    #[test]
    fn requires_federation_only_for_sql_sources() {
        // SQL sources plan as a VirtualExecutionPlan → need the
        // federation context.
        assert!(CatalogConfig::Postgres(PostgresCatalogConfig {
            dsn: Some("postgres://h/db".into()),
            dsn_env: None,
            ..Default::default()
        })
        .requires_federation());
        assert!(CatalogConfig::Mysql(MysqlCatalogConfig {
            dsn: Some("mysql://h/db".into()),
            dsn_env: None,
            ..Default::default()
        })
        .requires_federation());
        assert!(CatalogConfig::Snowflake(SnowflakeCatalogConfig {
            account: "acme".into(),
            warehouse: "WH".into(),
            database: "DB".into(),
            user: "U".into(),
            password: Some("p".into()),
            password_env: None,
            private_key_env: None,
            schema: None,
            role: None,
        })
        .requires_federation());
        assert!(CatalogConfig::Oracle(OracleCatalogConfig {
            dsn: "//h:1521/SVC".into(),
            user: "U".into(),
            password: Some("p".into()),
            password_env: None,
            schema: None,
            driver: None,
        })
        .requires_federation());
        // The generic ADBC connector is a SQLExecutor source too —
        // regression pin for the  slice-2 gap where a missing
        // classification made every byoduck scan fail with
        // "FederatedTableProviderAdaptor cannot scan".
        assert!(CatalogConfig::Adbc(sample_adbc_cfg()).requires_federation());

        // Plain TableProvider sources never produce a federation
        // node → no FilterPushdown strip needed.
        assert!(!CatalogConfig::ObjectStorage(ObjectStorageCatalogConfig {
            s3: None,
            tables: vec![]
        })
        .requires_federation());
        assert!(!CatalogConfig::Warehouse(WarehouseCatalogConfig {
            catalog_url: "http://c/catalog".into(),
            warehouse: "main".into(),
            s3_endpoint: None,
            s3_region: None,
            credentials: WarehouseCredentialsConfig::Static {
                access_key_id: "AKIA".into(),
                secret_access_key: Some("s".into()),
                secret_access_key_env: None,
            },
        })
        .requires_federation());
    }

    #[test]
    fn object_storage_catalog_binding_uses_first_table_url() {
        let cfg = CatalogConfig::ObjectStorage(ObjectStorageCatalogConfig {
            s3: None,
            tables: vec![
                ObjectStorageTableConfig {
                    name: "events".into(),
                    url: "file:///var/data/events.parquet".into(),
                    format: ObjectStorageFormat::Parquet,
                    schema: None,
                },
                ObjectStorageTableConfig {
                    name: "users".into(),
                    url: "file:///var/data/users.parquet".into(),
                    format: ObjectStorageFormat::Parquet,
                    schema: None,
                },
            ],
        });
        let CatalogBinding::LiveConnector(b) = cfg.binding() else {
            panic!("object_storage must bind to LiveConnector");
        };
        assert_eq!(b.kind, LiveConnectorKind::ObjectStorage);
        assert_eq!(b.endpoint_hint, "file:///var/data/events.parquet");
    }

    #[test]
    fn object_storage_empty_tables_renders_placeholder_hint() {
        // Defensive — the surrounding config validation rejects
        // an empty `tables` array, but the binding path must not
        // panic on the empty case.
        let cfg = CatalogConfig::ObjectStorage(ObjectStorageCatalogConfig {
            s3: None,
            tables: vec![],
        });
        let CatalogBinding::LiveConnector(b) = cfg.binding() else {
            panic!("object_storage must bind to LiveConnector");
        };
        assert_eq!(b.endpoint_hint, "<no tables>");
    }

    #[test]
    fn parse_table_ref_accepts_one_two_three_segments() {
        // Bare — what `SELECT email FROM users` produces in the
        // unqualified case. Most common shape for in-process tests.
        let r = parse_table_ref("users").unwrap();
        assert_eq!(r, TableReference::bare("users"));

        // Partial — `schema.table`. What you'd write when the
        // session-default schema isn't right.
        let r = parse_table_ref("public.users").unwrap();
        assert_eq!(r, TableReference::partial("public", "users"));

        // Full — `catalog.schema.table`. Required when the column
        // reference at query time is fully qualified (e.g. when the
        // operator queries another federated catalog).
        let r = parse_table_ref("pg.public.users").unwrap();
        assert_eq!(r, TableReference::full("pg", "public", "users"));
    }

    #[test]
    fn parse_table_ref_rejects_empty() {
        let err = parse_table_ref("").unwrap_err();
        assert!(err.to_string().contains("must not be empty"));
        let err = parse_table_ref("   ").unwrap_err();
        assert!(err.to_string().contains("must not be empty"));
    }

    #[test]
    fn parse_table_ref_rejects_more_than_three_segments() {
        // 4-segment shapes are silently accepted by
        // `TableReference::parse_str` (it slots the first segment
        // into the catalog) — the resulting rule would never match
        // any planner-emitted column reference. Reject up front.
        let err = parse_table_ref("a.b.c.d").unwrap_err();
        assert!(err.to_string().contains("more than 3 dotted segments"));
    }

    /// Pins the new production-boot path (`build_rule_store`)
    /// directly. The legacy `build_policy_enforcer` tests exercise
    /// composition indirectly, but slice 3's webhook handler depends
    #[test]
    fn higher_priority_mask_wins() {
        let masks = vec![
            MaskConfig {
                table: "users".into(),
                column: "email".into(),
                mask_literal: "LOW".into(),
                mask_type: None,
                priority: 0,
                mask_expr: None,
                groups: None,
            },
            MaskConfig {
                table: "users".into(),
                column: "email".into(),
                mask_literal: "HIGH".into(),
                mask_type: None,
                priority: 10,
                mask_expr: None,
                groups: None,
            },
        ];
        let rules = build_mask_rules(&masks).expect("build");
        assert_eq!(rules.len(), 1, "conflicting masks collapse to one winner");
        assert!(
            format!("{:?}", rules[0].mask).contains("HIGH"),
            "highest priority should win, got {:?}",
            rules[0].mask
        );
    }

    #[test]
    fn equal_priority_duplicate_still_errors() {
        // A tie at the top priority is ambiguous and must still be
        // rejected (the pre-existing duplicate-rule guard), so operators
        // are forced to disambiguate with distinct priorities.
        let masks = vec![
            MaskConfig {
                table: "users".into(),
                column: "email".into(),
                mask_literal: "FIRST".into(),
                mask_type: None,
                priority: 5,
                mask_expr: None,
                groups: None,
            },
            MaskConfig {
                table: "users".into(),
                column: "email".into(),
                mask_literal: "SECOND".into(),
                mask_type: None,
                priority: 5,
                mask_expr: None,
                groups: None,
            },
        ];
        let err =
            dataglot_policy::ColumnMaskingEnforcer::new(build_mask_rules(&masks).expect("build"))
                .unwrap_err();
        assert!(format!("{err}").to_lowercase().contains("duplicate"));
    }

    /// on this entry point and its failure surface — this is the
    /// regression guard.
    #[test]
    fn build_rule_store_returns_store_with_snapshot_enforcer() {
        let store = build_rule_store(
            &[MaskConfig {
                table: "users".to_string(),
                column: "email".to_string(),
                mask_literal: "***@example.com".to_string(),
                mask_type: None,
                priority: 0,
                mask_expr: None,
                groups: None,
            }],
            &[],
            None,
        )
        .expect("build store");

        // The store's published snapshot is a real PolicyEnforcer
        // that survives the boot path. Probe behaviourally — a
        // matching plan should report `Transformed::yes` once the
        // mask rule fires.
        let snapshot = store.snapshot();
        let plan = datafusion::logical_expr::LogicalPlan::EmptyRelation(
            datafusion::logical_expr::EmptyRelation {
                produce_one_row: false,
                schema: Arc::new(datafusion::common::DFSchema::empty()),
            },
        );
        // EmptyRelation has no projection ⇒ no transformation; just
        // assert the enforcer was constructed and runs.
        let _ = snapshot
            .rewrite(plan, &dataglot_policy::Identity::anonymous())
            .expect("snapshot enforcer runs");
    }

    /// `build_rule_store` propagates duplicate-rule failures from
    /// the underlying `InMemoryRuleStore::new` -> `RuleStorage::compose`
    /// chain. Walking the cause chain (same shape as the legacy
    /// `build_policy_enforcer_rejects_duplicate_rule` test) keeps
    /// the failure surface explicit.
    #[test]
    fn build_rule_store_rejects_duplicate_mask() {
        let masks = vec![
            MaskConfig {
                table: "users".to_string(),
                column: "email".to_string(),
                mask_literal: "***".to_string(),
                mask_type: None,
                priority: 0,
                mask_expr: None,
                groups: None,
            },
            MaskConfig {
                table: "users".to_string(),
                column: "email".to_string(),
                mask_literal: "###".to_string(),
                mask_type: None,
                priority: 0,
                mask_expr: None,
                groups: None,
            },
        ];
        let err = build_rule_store(&masks, &[], None).unwrap_err();
        let chain = format!("{err:#}");
        assert!(
            chain.to_lowercase().contains("duplicate masking rule"),
            "expected duplicate-masking-rule error somewhere in the chain, got: {chain}",
        );
    }

    #[test]
    fn build_policy_enforcer_empty_masks_returns_noop() {
        // Empty `masks` ⇒ Noop. We can't downcast `Arc<dyn Trait>`
        // through `dyn PolicyEnforcer`'s default vtable without
        // pulling Any into the trait, so probe behaviourally: a
        // Noop's `rewrite` reports `Transformed::no` on any plan.
        let e = build_policy_enforcer(&[], &[], None).unwrap();
        let plan = datafusion::logical_expr::LogicalPlan::EmptyRelation(
            datafusion::logical_expr::EmptyRelation {
                produce_one_row: false,
                schema: Arc::new(datafusion::common::DFSchema::empty()),
            },
        );
        let out = e
            .rewrite(plan, &dataglot_policy::Identity::anonymous())
            .unwrap();
        assert!(
            !out.transformed,
            "noop enforcer never reports `Transformed::yes`",
        );
    }

    #[test]
    fn build_policy_enforcer_rejects_duplicate_rule() {
        // Same `(table, column)` registered twice ⇒ build error
        // (mirrors `ColumnMaskingEnforcer::new`'s contract).
        let masks = vec![
            MaskConfig {
                table: "users".to_string(),
                column: "email".to_string(),
                mask_literal: "***".to_string(),
                mask_type: None,
                priority: 0,
                mask_expr: None,
                groups: None,
            },
            MaskConfig {
                table: "users".to_string(),
                column: "email".to_string(),
                mask_literal: "###".to_string(),
                mask_type: None,
                priority: 0,
                mask_expr: None,
                groups: None,
            },
        ];
        let err = build_policy_enforcer(&masks, &[], None).unwrap_err();
        // Walk the cause chain — slice 2 surfaces the underlying
        // `mask::BuildError::DuplicateRule` through anyhow's chain,
        // with `build_rule_store` adding context at the top.
        let chain = format!("{err:#}");
        assert!(
            chain.to_lowercase().contains("duplicate masking rule"),
            "expected duplicate-masking-rule error somewhere in the chain, got: {chain}",
        );
    }

    #[test]
    fn config_serializes_with_masks_block() {
        // Round-trip the whole struct through JSON to pin the
        // `masks` field name and shape that operators write.
        let cfg = ServerConfig {
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
        let json = serde_json::to_string(&cfg).unwrap();
        assert!(json.contains("\"masks\":["), "masks block missing: {json}");
        assert!(json.contains("\"table\":\"users\""));
        assert!(json.contains("\"mask_literal\":\"***@example.com\""));

        let back: ServerConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back.masks.len(), 1);
        assert_eq!(back.masks[0].table, "users");
    }

    #[test]
    fn config_serializes_with_row_filters_block() {
        // Round-trip pin for the `row_filters` field — same shape
        // contract operators see, including the tagged-enum
        // `predicate.kind` discriminator.
        let cfg = ServerConfig {
            row_filters: vec![
                RowFilterConfig {
                    table: "users".to_string(),
                    predicate: RowPredicateConfig::EqString {
                        column: "tenant_id".to_string(),
                        value: "acme".to_string(),
                    },
                    groups: None,
                },
                RowFilterConfig {
                    table: "events".to_string(),
                    predicate: RowPredicateConfig::GtInt {
                        column: "occurred_at".to_string(),
                        value: 1_700_000_000,
                    },
                    groups: None,
                },
            ],
            ..ServerConfig::default()
        };
        let json = serde_json::to_string(&cfg).unwrap();
        assert!(
            json.contains("\"row_filters\":["),
            "row_filters block missing: {json}",
        );
        assert!(json.contains("\"kind\":\"eq_string\""));
        assert!(json.contains("\"kind\":\"gt_int\""));

        let back: ServerConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back.row_filters.len(), 2);
    }

    /// Regression guard for the on-disk demo config at
    /// `examples/demo/dataglot.toml`. If a future PR changes the
    /// `ServerConfig` shape (renames a field, retires a predicate
    /// variant, requires a new field) without updating the demo,
    /// CI catches it here rather than in a `make demo` run that
    /// silently diverges from what the README documents.
    #[test]
    fn demo_config_parses_and_builds_enforcer() {
        // Embed at compile time — keeps the test hermetic and
        // version-locked to whatever's checked in.
        let raw = include_str!("../../../examples/demo/dataglot.toml");
        let cfg: ServerConfig =
            toml::from_str(raw).expect("demo config must deserialize as ServerConfig");
        // Pin the demo's governance counts so an accidental edit (extra
        // entry, deleted entry) shows up here. Two masks since
        // enriched the lineage demo (users.email + addresses.postal_code);
        // one row-filter (users).
        assert_eq!(
            cfg.masks.len(),
            2,
            "demo config has two [[masks]] entries (users.email, addresses.postal_code)",
        );
        assert!(
            cfg.masks
                .iter()
                .any(|m| m.table == "users" && m.column == "email"),
            "demo masks include users.email",
        );
        assert!(
            cfg.masks
                .iter()
                .any(|m| m.table == "addresses" && m.column == "postal_code"),
            "demo masks include addresses.postal_code",
        );
        assert_eq!(
            cfg.row_filters.len(),
            1,
            "demo config has one [[row_filters]] entry",
        );
        assert!(
            cfg.catalogs.contains_key("pg"),
            "demo config registers a `pg` catalog",
        );
        // And the enforcer builds without surfacing a
        // duplicate-rule or table-parse error.
        let _ = build_policy_enforcer(&cfg.masks, &cfg.row_filters, cfg.governance.as_ref())
            .expect("demo enforcer must build");
    }

    /// Regression guard for `examples/demo/dataglot-with-lakehouse.toml` —
    /// the lakehouse demo, which carries a **materialized** cross-source
    /// derived product (`customer_360_mart`, federating `pg` + `pg_orders`
    /// into an Iceberg table). This is the  "DBLink-elimination"
    /// pattern: a query that would have been an Oracle `dblink` +
    /// `CREATE TABLE` job, expressed as a governed federated read persisted
    /// to the `lakehouse` warehouse on a schedule. Pins that the config
    /// deserializes, that the materialization block is well-formed, and
    /// that `validate()` accepts it (materialized ⇒ has materialization).
    #[test]
    fn lakehouse_demo_config_parses_and_validates() {
        let raw = include_str!("../../../examples/demo/dataglot-with-lakehouse.toml");
        let cfg: ServerConfig =
            toml::from_str(raw).expect("lakehouse demo config must deserialize as ServerConfig");
        cfg.validate()
            .expect("lakehouse demo config must pass validation");

        assert!(
            cfg.catalogs
                .get("lakehouse")
                .is_some_and(|c| matches!(c, CatalogConfig::Warehouse(_))),
            "lakehouse demo registers a `lakehouse` warehouse catalog",
        );

        let mart = cfg
            .derived_products
            .iter()
            .find(|p| p.name == "customer_360_mart")
            .expect("lakehouse demo declares the customer_360_mart product");
        assert_eq!(
            mart.backing,
            MaterializationBacking::Materialized,
            "customer_360_mart is materialized",
        );
        let m = mart
            .materialization
            .as_ref()
            .expect("materialized product has a materialization block");
        assert_eq!(
            m.warehouse, "lakehouse",
            "materializes to the lakehouse warehouse"
        );
        assert!(
            mart.sql.contains("pg.public.users") && mart.sql.contains("pg_orders.public.orders"),
            "customer_360_mart federates across pg + pg_orders (DBLink-elimination analog)",
        );
    }

    /// Regression guard for `examples/demo/dataglot-with-rest.toml` — the
    /// testbench's mock-SaaS demo, which declares a `rest` catalog (`saas`)
    /// against the `mock-saas` wiremock service. Pins that the REST
    /// catalog config deserializes + validates, and that its table declares
    /// `records_path` + `next_link` pagination + typed columns.
    #[test]
    fn rest_demo_config_parses_and_validates() {
        let raw = include_str!("../../../examples/demo/dataglot-with-rest.toml");
        let cfg: ServerConfig =
            toml::from_str(raw).expect("rest demo config must deserialize as ServerConfig");
        cfg.validate()
            .expect("rest demo config must pass validation");

        let CatalogConfig::Rest(rest) = cfg
            .catalogs
            .get("saas")
            .expect("rest demo declares a `saas` catalog")
        else {
            panic!("`saas` must be a REST catalog");
        };
        let accounts = rest
            .tables
            .iter()
            .find(|t| t.name == "accounts")
            .expect("rest demo declares the accounts table");
        assert_eq!(accounts.records_path, "records");
        assert!(
            matches!(
                accounts.pagination,
                RestPaginationConfig::NextLink { ref next_path } if next_path == "nextRecordsUrl"
            ),
            "accounts paginates via nextRecordsUrl",
        );
        assert!(
            accounts.columns.iter().any(|c| c.name == "Id"),
            "accounts declares typed columns",
        );
    }

    /// The remaining committed demo configs (datahub, governance,
    /// lakehouse-rustfs, tpch) must each deserialize from TOML into a
    /// `ServerConfig` and pass `validate()` — the  TOML switch
    /// converted them, so this pins that they stay loadable.
    #[test]
    fn remaining_demo_configs_parse_and_validate() {
        for (name, raw) in [
            (
                "datahub",
                include_str!("../../../examples/demo/dataglot-with-datahub.toml"),
            ),
            (
                "governance",
                include_str!("../../../examples/demo/dataglot-with-governance.toml"),
            ),
            (
                "lakehouse-rustfs",
                include_str!("../../../examples/demo/dataglot-with-lakehouse-rustfs.toml"),
            ),
            (
                "tpch",
                include_str!("../../../examples/demo/dataglot-tpch.toml"),
            ),
        ] {
            let cfg: ServerConfig = toml::from_str(raw)
                .unwrap_or_else(|e| panic!("demo config {name} must deserialize: {e}"));
            cfg.validate()
                .unwrap_or_else(|e| panic!("demo config {name} must validate: {e}"));
        }
    }

    /// Regression guard for the committed Snowflake demo at
    /// `examples/demo/dataglot-with-snowflake.toml` (the template the
    /// testbench Snowflake runbook copies to `*.local.toml`). Parse-only
    /// and hermetic — no env, no connection — so it pins the config shape
    /// without needing Snowflake credentials. If `SnowflakeCatalogConfig`
    /// gains a required field or the catalog key changes, this catches the
    /// template drifting out of sync with the struct.
    #[test]
    fn snowflake_demo_config_parses_and_registers_catalog() {
        let raw = include_str!("../../../examples/demo/dataglot-with-snowflake.toml");
        let cfg: ServerConfig =
            toml::from_str(raw).expect("snowflake demo config must deserialize as ServerConfig");
        assert_eq!(cfg.default_catalog, "snowflake");
        assert_eq!(cfg.default_schema, "tpch_sf1");
        match cfg
            .catalogs
            .get("snowflake")
            .expect("registers a `snowflake` catalog")
        {
            CatalogConfig::Snowflake(sf) => {
                assert!(!sf.account.is_empty(), "account is set");
                assert!(!sf.warehouse.is_empty(), "warehouse is set");
                assert_eq!(sf.database, "SNOWFLAKE_SAMPLE_DATA");
                // Rule 12: the template carries the env-var *name*, never a
                // literal password.
                assert_eq!(sf.password_env.as_deref(), Some("SNOWFLAKE_PASSWORD"));
                assert!(sf.password.is_none(), "no literal password in the template");
            }
            other => panic!("`snowflake` catalog must be the Snowflake variant, got {other:?}"),
        }
    }

    #[test]
    fn build_policy_enforcer_with_only_row_filters_returns_row_enforcer() {
        // Pin the (None, Some) arm of the composition matrix.
        let rfs = vec![RowFilterConfig {
            table: "users".to_string(),
            predicate: RowPredicateConfig::GtInt {
                column: "id".to_string(),
                value: 1,
            },
            groups: None,
        }];
        let e = build_policy_enforcer(&[], &rfs, None).unwrap();
        // Behavioural check: the resulting enforcer reports
        // Transformed::yes on a plan containing a matching
        // TableScan. We use the same EmptyRelation probe as the
        // noop test — the EmptyRelation has no TableScan, so the
        // RowFilterEnforcer reports Transformed::no for it. The
        // assertion here is just "doesn't panic / builds" — the
        // semantic correctness is in dataglot-policy::filter::tests.
        let plan = datafusion::logical_expr::LogicalPlan::EmptyRelation(
            datafusion::logical_expr::EmptyRelation {
                produce_one_row: false,
                schema: Arc::new(datafusion::common::DFSchema::empty()),
            },
        );
        let _ = e
            .rewrite(plan, &dataglot_policy::Identity::anonymous())
            .unwrap();
    }

    #[test]
    fn build_policy_enforcer_with_both_returns_composite() {
        // Pin the (Some, Some) arm. The Debug repr of
        // CompositeEnforcer surfaces "CompositeEnforcer" — match
        // on that as a stand-in for downcast (which Arc<dyn
        // PolicyEnforcer> doesn't expose without an Any bound).
        let masks = vec![MaskConfig {
            table: "users".to_string(),
            column: "email".to_string(),
            mask_literal: "***".to_string(),
            mask_type: None,
            priority: 0,
            mask_expr: None,
            groups: None,
        }];
        let rfs = vec![RowFilterConfig {
            table: "users".to_string(),
            predicate: RowPredicateConfig::GtInt {
                column: "id".to_string(),
                value: 1,
            },
            groups: None,
        }];
        let e = build_policy_enforcer(&masks, &rfs, None).unwrap();
        let dbg = format!("{e:?}");
        assert!(
            dbg.contains("CompositeEnforcer"),
            "expected CompositeEnforcer, got: {dbg}",
        );
    }

    #[test]
    fn build_policy_enforcer_rejects_duplicate_row_filter() {
        // Mirror of the mask-side duplicate test for row filters.
        let rfs = vec![
            RowFilterConfig {
                table: "users".to_string(),
                predicate: RowPredicateConfig::GtInt {
                    column: "id".to_string(),
                    value: 1,
                },
                groups: None,
            },
            RowFilterConfig {
                table: "users".to_string(),
                predicate: RowPredicateConfig::GtInt {
                    column: "id".to_string(),
                    value: 5,
                },
                groups: None,
            },
        ];
        let err = build_policy_enforcer(&[], &rfs, None).unwrap_err();
        let chain = format!("{err:#}");
        assert!(
            chain.to_lowercase().contains("duplicate row-filter rule"),
            "expected duplicate-row-filter error somewhere in the chain, got: {chain}",
        );
    }

    #[test]
    fn predicate_to_expr_covers_each_variant() {
        // Smoke that each variant builds the right shape. We
        // stringify via Debug rather than asserting on the inner
        // ScalarValue because the Debug repr is stable enough for
        // a regression guard.
        let eq_s = predicate_to_expr(&RowPredicateConfig::EqString {
            column: "tenant_id".into(),
            value: "acme".into(),
        })
        .unwrap();
        assert!(format!("{eq_s:?}").contains("BinaryExpr"));

        let eq_i = predicate_to_expr(&RowPredicateConfig::EqInt {
            column: "id".into(),
            value: 7,
        })
        .unwrap();
        assert!(format!("{eq_i:?}").contains("BinaryExpr"));

        let gt_i = predicate_to_expr(&RowPredicateConfig::GtInt {
            column: "id".into(),
            value: 1,
        })
        .unwrap();
        assert!(format!("{gt_i:?}").contains("BinaryExpr"));
    }

    #[test]
    fn predicate_sql_parses_simple_expression() {
        // Pin: a one-clause predicate parses cleanly against the
        // empty schema. Column ref is unbound at parse time —
        // resolves at query time when the rule wraps a real
        // TableScan.
        let pred = predicate_to_expr(&RowPredicateConfig::Sql {
            sql: "id > 5".to_string(),
        })
        .unwrap();
        let dbg = format!("{pred:?}");
        assert!(
            dbg.contains("BinaryExpr") || dbg.contains("Gt"),
            "expected a > comparison, got: {dbg}",
        );
    }

    #[test]
    fn predicate_sql_parses_compound_expression() {
        // Pin the headline use case: AND / OR / LIKE in one rule.
        // Operators write this as the `sql` variant when a single
        // declarative variant doesn't fit.
        let pred = predicate_to_expr(&RowPredicateConfig::Sql {
            sql: "id > 1 AND email LIKE 'alice%'".to_string(),
        })
        .unwrap();
        let dbg = format!("{pred:?}");
        // The top-level shape after AND-association must contain
        // both halves.
        assert!(dbg.contains("And") || dbg.contains("BinaryExpr"));
        assert!(dbg.contains("LIKE") || dbg.contains("Like") || dbg.contains("alice"));
    }

    #[test]
    fn predicate_sql_rejects_garbage_at_boot() {
        // Pin that parse failures surface at boot time as a
        // typed Result, not at query time as an opaque planning
        // error. Operators should see a clear error in the
        // server log on startup.
        let err = predicate_to_expr(&RowPredicateConfig::Sql {
            sql: "this is not a real expression !".to_string(),
        })
        .unwrap_err();
        let msg = err.to_string().to_lowercase();
        assert!(
            msg.contains("parse"),
            "error must mention parse failure; got: {err}",
        );
    }

    #[test]
    fn predicate_sql_recurses_into_cast_to_harvest_inner_columns() {
        // Pin the documented int-coercion workaround:
        // `CAST(id AS BIGINT) > 1` MUST parse cleanly. Without
        // recursing into the cast operand, `id` would be missed,
        // the synthetic schema would have no fields, and
        // `parse_sql_expr` would error with "No field named id".
        // This is the parse-time half of the workaround pinned by
        // the e2e test
        // `server::tests::server_new_sql_predicate_int_compare_needs_cast_workaround`
        // (which proves the cast path actually executes correctly).
        let pred = predicate_to_expr(&RowPredicateConfig::Sql {
            sql: "CAST(id AS BIGINT) > 1".to_string(),
        })
        .expect("CAST(id AS BIGINT) > 1 must parse — workaround on RowPredicateConfig::Sql");
        let dbg = format!("{pred:?}");
        // The Cast node survives in the parsed Expr.
        assert!(
            dbg.contains("Cast") || dbg.contains("cast"),
            "expected a Cast in the parsed Expr; got: {dbg}",
        );
    }

    // -- identity profile resolution --------------------------------------

    #[test]
    fn resolve_identity_empty_user_returns_anonymous() {
        // The pgwire startup handler passes "" when the
        // StartupMessage didn't carry a `user` key. Map to
        // `Identity::anonymous` regardless of map contents.
        let mut profiles = HashMap::new();
        profiles.insert(
            "alice".to_string(),
            IdentityProfileConfig {
                org: Some("acme".into()),
                groups: vec!["analyst".into()],
                password_env: None,
            },
        );
        let id = resolve_identity("", &profiles);
        assert!(id.is_anonymous());
    }

    #[test]
    fn resolve_identity_unknown_user_keeps_name_no_groups() {
        // User present in StartupMessage but absent from the map.
        // We keep the name (visible in logs / diagnostics) but
        // leave org/groups empty — tag-based policies that require
        // a group match still short-circuit. Callers reading
        // `Identity::user` directly still see the right name.
        let profiles = HashMap::new();
        let id = resolve_identity("carol", &profiles);
        assert_eq!(id.user.as_deref(), Some("carol"));
        assert!(id.org.is_none());
        assert!(id.org_groups.is_empty());
    }

    #[test]
    fn resolve_identity_known_user_populates_org_and_groups() {
        // Headline case: user matches a configured profile, full
        // identity is built. This is what makes TagBasedEnforcer
        // dispatch on `org_groups` actually fire policies.
        let mut profiles = HashMap::new();
        profiles.insert(
            "alice".to_string(),
            IdentityProfileConfig {
                org: Some("acme".into()),
                groups: vec!["analyst".into(), "on-call".into()],
                password_env: None,
            },
        );
        let id = resolve_identity("alice", &profiles);
        assert_eq!(id.user.as_deref(), Some("alice"));
        assert_eq!(id.org.as_deref(), Some("acme"));
        assert_eq!(
            id.org_groups,
            vec!["analyst".to_string(), "on-call".to_string()],
        );
    }

    #[test]
    fn resolve_identity_groups_only_no_org_works() {
        // Profile with groups but no org — the org chain is
        // skipped. Pin that the optional-org branch doesn't
        // accidentally clobber the user name.
        let mut profiles = HashMap::new();
        profiles.insert(
            "bob".to_string(),
            IdentityProfileConfig {
                org: None,
                groups: vec!["support".into()],
                password_env: None,
            },
        );
        let id = resolve_identity("bob", &profiles);
        assert_eq!(id.user.as_deref(), Some("bob"));
        assert!(id.org.is_none());
        assert_eq!(id.org_groups, vec!["support".to_string()]);
    }

    #[test]
    fn resolve_identity_org_only_no_groups_works() {
        // The other half of the optional-fields contract: org but
        // no groups. Identity carries the org but TagBasedEnforcer
        // still short-circuits on the empty group list.
        let mut profiles = HashMap::new();
        profiles.insert(
            "dave".to_string(),
            IdentityProfileConfig {
                org: Some("acme".into()),
                groups: Vec::new(),
                password_env: None,
            },
        );
        let id = resolve_identity("dave", &profiles);
        assert_eq!(id.user.as_deref(), Some("dave"));
        assert_eq!(id.org.as_deref(), Some("acme"));
        assert!(id.org_groups.is_empty());
    }

    #[test]
    fn role_held_via_group_is_folded_into_groups() {
        let mut profiles = HashMap::new();
        profiles.insert(
            "alice".to_string(),
            IdentityProfileConfig {
                org: Some("acme".into()),
                groups: vec!["analyst".into()],
                password_env: None,
            },
        );
        let mut roles = HashMap::new();
        roles.insert(
            "pii_reader".to_string(),
            RoleConfig {
                users: vec![],
                groups: vec!["analyst".into()],
            },
        );
        let id = resolve_identity_with_roles("alice", &profiles, &roles);
        assert!(id.org_groups.iter().any(|g| g == "analyst"));
        assert!(
            id.org_groups.iter().any(|g| g == "pii_reader"),
            "a role held via group membership is folded into the effective groups"
        );
    }

    #[test]
    fn role_held_via_direct_user_listing() {
        // alice absent from profiles → bare user identity, no groups;
        // the role lists her user directly.
        let profiles = HashMap::new();
        let mut roles = HashMap::new();
        roles.insert(
            "admin".to_string(),
            RoleConfig {
                users: vec!["alice".into()],
                groups: vec![],
            },
        );
        let id = resolve_identity_with_roles("alice", &profiles, &roles);
        assert!(id.org_groups.iter().any(|g| g == "admin"));
    }

    #[test]
    fn role_not_held_is_absent() {
        let mut profiles = HashMap::new();
        profiles.insert(
            "bob".to_string(),
            IdentityProfileConfig {
                org: None,
                groups: vec!["support".into()],
                password_env: None,
            },
        );
        let mut roles = HashMap::new();
        roles.insert(
            "pii_reader".to_string(),
            RoleConfig {
                users: vec![],
                groups: vec!["analyst".into()],
            },
        );
        let id = resolve_identity_with_roles("bob", &profiles, &roles);
        assert!(!id.org_groups.iter().any(|g| g == "pii_reader"));
        assert!(id.org_groups.iter().any(|g| g == "support"));
    }

    /// End-to-end identity → role → enforcement, in one flow.
    ///
    /// Closes two coverage gaps that were only tested in halves:
    /// 1. a role held *via group membership* is folded in by
    ///    `resolve_identity_with_roles`, and a **role-scoped** policy then
    ///    fires — through real query execution, not just plan inspection;
    /// 2. the session-identity mechanism the pgwire startup observer
    ///    relies on — identity set on the task-local via
    ///    [`with_session_identity`], then read back by `PolicyOptimizerRule`
    ///    at optimize time — drives the right enforcement per identity.
    #[tokio::test]
    async fn role_resolved_from_group_drives_enforcement_end_to_end() {
        use std::sync::Arc;

        use datafusion::arrow::array::{ArrayRef, Int32Array, StringArray};
        use datafusion::arrow::datatypes::{DataType, Field, Schema};
        use datafusion::arrow::record_batch::RecordBatch;
        use datafusion::datasource::MemTable;
        use datafusion::error::DataFusionError;
        use datafusion::optimizer::{OptimizerContext, OptimizerRule};
        use datafusion::prelude::SessionContext;
        use datafusion::sql::TableReference;
        use dataglot_policy::{
            with_session_identity, AccessDenial, AccessDenyEnforcer, PolicyOptimizerRule,
        };

        // Runs under whatever identity is on the task-local (set by
        // `with_session_identity`) — `PolicyOptimizerRule::new` reads it.
        async fn query(
            ctx: &SessionContext,
            enforcer: Arc<dyn dataglot_policy::PolicyEnforcer>,
            sql: &str,
        ) -> Result<usize, DataFusionError> {
            let plan = ctx.sql(sql).await?.into_unoptimized_plan();
            let plan = PolicyOptimizerRule::new(enforcer)
                .rewrite(plan, &OptimizerContext::new())?
                .data;
            let batches = ctx.execute_logical_plan(plan).await?.collect().await?;
            Ok(batches.iter().map(RecordBatch::num_rows).sum())
        }

        // alice ∈ analyst; bob ∈ sales. Role `pii_reader` is granted to
        // the `analyst` group — so alice *holds* it, bob does not.
        let mut identities = HashMap::new();
        identities.insert(
            "alice".to_string(),
            IdentityProfileConfig {
                org: None,
                groups: vec!["analyst".into()],
                password_env: None,
            },
        );
        identities.insert(
            "bob".to_string(),
            IdentityProfileConfig {
                org: None,
                groups: vec!["sales".into()],
                password_env: None,
            },
        );
        let mut roles = HashMap::new();
        roles.insert(
            "pii_reader".to_string(),
            RoleConfig {
                users: vec![],
                groups: vec!["analyst".into()],
            },
        );

        // The exact resolution the startup observer runs on the wire username.
        let alice = resolve_identity_with_roles("alice", &identities, &roles);
        let bob = resolve_identity_with_roles("bob", &identities, &roles);
        assert!(alice.org_groups.iter().any(|g| g == "pii_reader"));
        assert!(!bob.org_groups.iter().any(|g| g == "pii_reader"));

        // emp(id, salary); salary denied to the ROLE `pii_reader`.
        let schema = Arc::new(Schema::new(vec![
            Field::new("id", DataType::Int32, false),
            Field::new("salary", DataType::Utf8, false),
        ]));
        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(Int32Array::from(vec![1])) as ArrayRef,
                Arc::new(StringArray::from(vec!["100k"])) as ArrayRef,
            ],
        )
        .unwrap();
        let ctx = SessionContext::new();
        ctx.register_table(
            "emp",
            Arc::new(MemTable::try_new(schema, vec![vec![batch]]).unwrap()),
        )
        .unwrap();
        let enforcer: Arc<dyn dataglot_policy::PolicyEnforcer> =
            Arc::new(AccessDenyEnforcer::new([AccessDenial {
                table: TableReference::bare("emp"),
                column: Some("salary".into()),
                groups: vec!["pii_reader".into()],
            }]));

        // alice holds pii_reader (via analyst) → salary denied.
        let alice_res = with_session_identity(
            alice,
            query(&ctx, enforcer.clone(), "SELECT salary FROM emp"),
        )
        .await;
        assert!(
            alice_res.is_err_and(|e| e.to_string().contains("permission denied")),
            "alice holds the role via her group → salary must be denied"
        );

        // bob lacks the role → salary readable.
        let bob_res =
            with_session_identity(bob, query(&ctx, enforcer.clone(), "SELECT salary FROM emp"))
                .await;
        assert_eq!(
            bob_res.expect("bob has no denying role → query runs"),
            1,
            "bob reads the row"
        );
    }

    #[test]
    fn identities_config_round_trips_through_json() {
        // Pin the JSON shape operators write. The map is keyed by
        // username, value carries org + groups. Backwards compat:
        // a config that doesn't declare `identities` at all parses
        // (defaults to empty map).
        let raw = r#"{
            "host": "0.0.0.0",
            "port": 5432,
            "batch_size": 8192,
            "partitions": 4,
            "default_catalog": "dataglot",
            "default_schema": "public",
            "identities": {
                "alice": { "org": "acme", "groups": ["analyst"] },
                "bob":   { "groups": ["analyst", "support"] }
            }
        }"#;
        let cfg: ServerConfig = serde_json::from_str(raw).expect("parse");
        assert_eq!(cfg.identities.len(), 2);
        let alice = cfg.identities.get("alice").expect("alice profile");
        assert_eq!(alice.org.as_deref(), Some("acme"));
        assert_eq!(alice.groups, vec!["analyst".to_string()]);
        let bob = cfg.identities.get("bob").expect("bob profile");
        assert!(bob.org.is_none());
        assert_eq!(bob.groups, vec!["analyst".to_string(), "support".into()]);
    }

    #[test]
    fn identities_default_is_empty_omitted_section_parses() {
        // Configs without `identities` at all must continue to parse.
        // Maps to the pre-#154 behaviour where every session got
        // empty groups.
        let raw = r#"{
            "host": "127.0.0.1",
            "port": 5432,
            "batch_size": 8192,
            "partitions": 1,
            "default_catalog": "dataglot",
            "default_schema": "public"
        }"#;
        let cfg: ServerConfig = serde_json::from_str(raw).expect("parse");
        assert!(cfg.identities.is_empty());
    }

    #[test]
    fn governance_config_round_trips_through_json() {
        // Pin the JSON shape operators write. A broken serde
        // contract here would silently misparse production governance
        // configs.
        let raw = r#"{
            "host": "0.0.0.0",
            "port": 5432,
            "batch_size": 8192,
            "partitions": 4,
            "default_catalog": "dataglot",
            "default_schema": "public",
            "governance": {
                "tags": [
                    { "id": "pii", "org": "acme", "name": "PII" }
                ],
                "policies": [
                    {
                        "id": "mask-pii-analyst",
                        "org": "acme",
                        "tag": "pii",
                        "group": "analyst",
                        "rule": { "kind": "mask", "mask_literal": "***@example.com" }
                    },
                    {
                        "id": "filter-pii-analyst",
                        "org": "acme",
                        "tag": "pii",
                        "group": "analyst",
                        "rule": {
                            "kind": "row_filter",
                            "predicate": { "kind": "eq_string", "column": "tenant_id", "value": "acme" }
                        }
                    }
                ],
                "columns": [
                    { "table": "users", "column": "email", "tags": ["pii"] }
                ]
            }
        }"#;
        let cfg: ServerConfig = serde_json::from_str(raw).expect("governance JSON parses");
        let g = cfg.governance.as_ref().expect("governance section present");
        assert_eq!(g.tags.len(), 1);
        assert_eq!(g.tags[0].id, "pii");
        assert_eq!(g.policies.len(), 2);
        assert_eq!(g.columns.len(), 1);

        // Round-trip survives reserialization. Locks the shape a
        // future deserde rename can't accidentally break.
        let reserialized = serde_json::to_string(&cfg).expect("reserialize");
        let cfg2: ServerConfig = serde_json::from_str(&reserialized).expect("re-parse");
        let g2 = cfg2
            .governance
            .as_ref()
            .expect("governance after round-trip");
        assert_eq!(g2.tags.len(), 1);
        assert_eq!(g2.policies.len(), 2);
    }

    #[test]
    fn governance_default_is_none_omitted_section_parses() {
        // Configs that don't declare a `governance` section must
        // continue to parse — same backwards-compat contract the
        // existing `[[masks]]` / `[[row_filters]]` blocks have.
        let raw = r#"{
            "host": "127.0.0.1",
            "port": 5432,
            "batch_size": 8192,
            "partitions": 1,
            "default_catalog": "dataglot",
            "default_schema": "public"
        }"#;
        let cfg: ServerConfig = serde_json::from_str(raw).expect("section-less config parses");
        assert!(cfg.governance.is_none());
    }

    #[test]
    fn build_governance_round_trip_yields_matching_registry() {
        // Walk the full path: JSON → OrgGovernanceConfig →
        // build_governance() → OrgGovernance with the right shape.
        let raw = r#"{
            "tags": [
                { "id": "pii", "org": "acme", "name": "PII" }
            ],
            "policies": [
                {
                    "id": "mask-pii-analyst",
                    "org": "acme",
                    "tag": "pii",
                    "group": "analyst",
                    "rule": { "kind": "mask", "mask_literal": "***" }
                }
            ],
            "columns": [
                { "table": "users", "column": "email", "tags": ["pii"] }
            ]
        }"#;
        let cfg: OrgGovernanceConfig = serde_json::from_str(raw).expect("parse governance");
        let g = build_governance(&cfg).expect("build governance");
        assert_eq!(g.tag_count(), 1);
        assert_eq!(g.policy_count(), 1);
        assert_eq!(g.annotated_column_count(), 1);
        // Tag id passes through verbatim.
        assert!(g.tag(&dataglot_policy::TagId::new("pii")).is_some());
        // Policies survive the build under their tag.
        assert_eq!(
            g.policies_for_tag(&dataglot_policy::TagId::new("pii"))
                .len(),
            1,
        );
    }

    #[test]
    fn build_governance_rejects_unknown_tag_in_policy() {
        // Same validation `OrgGovernance::builder()` enforces. The
        // server layer must surface the typed error at boot.
        let cfg = OrgGovernanceConfig {
            tags: vec![],
            policies: vec![PolicyConfig {
                id: "bad".into(),
                org: "acme".into(),
                tag: "missing".into(),
                group: "analyst".into(),
                rule: PolicyRuleConfig::Mask {
                    mask_literal: "***".into(),
                },
            }],
            columns: vec![],
        };
        let err = build_governance(&cfg).unwrap_err();
        let msg = err.to_string().to_lowercase();
        assert!(
            msg.contains("orggovernance") || msg.contains("validation"),
            "expected validation-failed context; got: {err}",
        );
    }

    #[test]
    fn build_policy_enforcer_with_only_governance_returns_tag_enforcer() {
        // Governance-only path: no static masks or row_filters,
        // governance section populated. The composite collapses to
        // the bare `TagBasedEnforcer` (no wrapping). Pinned via the
        // Debug repr so a future composite-around-everything change
        // surfaces here.
        let g = OrgGovernanceConfig {
            tags: vec![TagDefinitionConfig {
                id: "pii".into(),
                org: "acme".into(),
                name: "PII".into(),
            }],
            policies: vec![PolicyConfig {
                id: "mask-pii".into(),
                org: "acme".into(),
                tag: "pii".into(),
                group: "analyst".into(),
                rule: PolicyRuleConfig::Mask {
                    mask_literal: "***".into(),
                },
            }],
            columns: vec![SemanticTableColumnConfig {
                table: "users".into(),
                column: "email".into(),
                tags: vec!["pii".into()],
            }],
        };
        let e = build_policy_enforcer(&[], &[], Some(&g)).unwrap();
        let dbg = format!("{e:?}");
        assert!(
            dbg.contains("TagBasedEnforcer"),
            "governance-only must surface TagBasedEnforcer; got: {dbg}",
        );
        assert!(
            !dbg.contains("CompositeEnforcer"),
            "single-source must not be wrapped; got: {dbg}",
        );
    }

    #[test]
    fn build_policy_enforcer_governance_plus_static_masks_composes() {
        // Two non-empty sources: governance + static masks. Wrapped
        // in a CompositeEnforcer in the documented order: tag-based
        // first, then static masks.
        let g = OrgGovernanceConfig {
            tags: vec![TagDefinitionConfig {
                id: "pii".into(),
                org: "acme".into(),
                name: "PII".into(),
            }],
            policies: vec![],
            columns: vec![],
        };
        let masks = vec![MaskConfig {
            table: "users".into(),
            column: "email".into(),
            mask_literal: "***".into(),
            mask_type: None,
            priority: 0,
            mask_expr: None,
            groups: None,
        }];
        let e = build_policy_enforcer(&masks, &[], Some(&g)).unwrap();
        let dbg = format!("{e:?}");
        assert!(
            dbg.contains("CompositeEnforcer"),
            "two sources must wrap in composite; got: {dbg}",
        );
        assert!(
            dbg.contains("TagBasedEnforcer") && dbg.contains("ColumnMaskingEnforcer"),
            "composite must contain both layers; got: {dbg}",
        );
    }

    #[test]
    fn build_policy_enforcer_empty_governance_collapses_to_static_layers() {
        // A governance section with empty `tags` / `policies` /
        // `columns` is treated as absent — no TagBasedEnforcer
        // layer, identical shape to the pre-#137 path. Important
        // because a config-template scaffolding tool might emit
        // `"governance": {}` placeholders.
        let g = OrgGovernanceConfig::default();
        let masks = vec![MaskConfig {
            table: "users".into(),
            column: "email".into(),
            mask_literal: "***".into(),
            mask_type: None,
            priority: 0,
            mask_expr: None,
            groups: None,
        }];
        let e = build_policy_enforcer(&masks, &[], Some(&g)).unwrap();
        let dbg = format!("{e:?}");
        assert!(
            !dbg.contains("TagBasedEnforcer"),
            "empty governance must not add a tag layer; got: {dbg}",
        );
        assert!(
            dbg.contains("ColumnMaskingEnforcer"),
            "static masks must still install; got: {dbg}",
        );
    }

    #[test]
    fn governance_row_filter_predicate_uses_existing_sql_vocabulary() {
        // Pin that the §10 row-filter rule reuses the same predicate
        // shapes as the static `[[row_filters]]` block — sql escape
        // hatch included. Operators only learn one predicate
        // language.
        let g = OrgGovernanceConfig {
            tags: vec![TagDefinitionConfig {
                id: "pii".into(),
                org: "acme".into(),
                name: "PII".into(),
            }],
            policies: vec![PolicyConfig {
                id: "filter-pii".into(),
                org: "acme".into(),
                tag: "pii".into(),
                group: "analyst".into(),
                rule: PolicyRuleConfig::RowFilter {
                    predicate: RowPredicateConfig::Sql {
                        sql: "tenant_id = 'acme'".into(),
                    },
                },
            }],
            columns: vec![],
        };
        let registry = build_governance(&g).expect("sql predicate parses at boot");
        assert_eq!(registry.policy_count(), 1);
    }

    #[test]
    fn test_config_serialization() {
        let config = ServerConfig::default();
        let json = serde_json::to_string_pretty(&config).unwrap();
        let parsed: ServerConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.host, config.host);
        assert_eq!(parsed.port, config.port);
        assert!(parsed.catalogs.is_empty());
    }

    #[test]
    fn test_default_includes_observability_defaults() {
        let config = ServerConfig::default();
        assert_eq!(
            config.observability.log_filter,
            crate::observability::DEFAULT_LOG_FILTER
        );
        assert!(config.observability.metrics_addr.is_some());
        assert!(config.observability.health_check_enabled);
    }

    #[test]
    fn test_load_applies_cli_observability_overrides() {
        let args = Args::parse_from([
            "dataglot",
            "--log-format",
            "json",
            "--log-filter",
            "dataglot=debug",
            "--metrics-addr",
            "0.0.0.0:9091",
            "--disable-health-check",
        ]);
        let config = ServerConfig::load(&args).unwrap();
        assert_eq!(
            config.observability.log_format,
            crate::observability::LogFormat::Json
        );
        assert_eq!(config.observability.log_filter, "dataglot=debug");
        assert_eq!(
            config.observability.metrics_addr.map(|a| a.port()),
            Some(9091)
        );
        assert!(!config.observability.health_check_enabled);
    }

    #[test]
    fn test_load_disables_metrics_addr_via_cli() {
        let args = Args::parse_from(["dataglot", "--metrics-addr", "disabled"]);
        let config = ServerConfig::load(&args).unwrap();
        assert!(config.observability.metrics_addr.is_none());
    }

    #[test]
    fn test_tolerate_unreachable_catalogs_defaults_off_and_enables_via_cli() {
        // Default: fail-fast.
        let config = ServerConfig::load(&Args::parse_from(["dataglot"])).unwrap();
        assert!(!config.tolerate_unreachable_catalogs);

        // CLI flag flips it on.
        let args = Args::parse_from(["dataglot", "--tolerate-unreachable-catalogs"]);
        let config = ServerConfig::load(&args).unwrap();
        assert!(config.tolerate_unreachable_catalogs);
    }

    #[test]
    fn test_load_from_file_round_trip() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("dataglot.json");
        let body = serde_json::json!({
            "host": "0.0.0.0",
            "port": 6543,
            "batch_size": 16384,
            "partitions": 8,
            "default_catalog": "dataglot",
            "default_schema": "public",
            "observability": {
                "log_format": "json",
                "log_filter": "dataglot=trace",
                "metrics_addr": "127.0.0.1:9999",
                "health_check_enabled": false
            }
        });
        std::fs::write(&path, serde_json::to_string(&body).unwrap()).unwrap();

        let args = Args::parse_from([
            "dataglot",
            "--config",
            path.to_str().unwrap(),
            // No `--host`/`--port`/`--batch-size` on the CLI: post-
            // these are `Option` with no clap default, so the file values
            // survive untouched.
        ]);
        let config = ServerConfig::load(&args).unwrap();

        // Network fields from the file survive when no CLI flag overrides
        // them ( — previously clap defaults clobbered these).
        assert_eq!(config.host, "0.0.0.0");
        assert_eq!(config.port, 6543);
        assert_eq!(config.batch_size, 16384);

        // File-only fields survive.
        assert_eq!(
            config.observability.log_format,
            crate::observability::LogFormat::Json
        );
        assert_eq!(config.observability.log_filter, "dataglot=trace");
        assert_eq!(
            config.observability.metrics_addr.map(|a| a.port()),
            Some(9999)
        );
        assert!(!config.observability.health_check_enabled);
    }

    #[test]
    fn capture_query_sources_does_not_change_partitions() {
        //: capture must NOT alter parallelism — an earlier revision
        // pinned target_partitions=1 when capture was on, which crippled
        // compute-heavy local queries (e.g. TPC-H over parquet). The configured
        // partitions are honoured regardless of capture.
        let mut config = ServerConfig {
            partitions: 8,
            ..ServerConfig::default()
        };
        assert_eq!(config.to_session_config().target_partitions, 8);
        config.observability.capture_query_sources = true;
        assert_eq!(config.to_session_config().target_partitions, 8);
    }

    /// A minimal (even empty) config object loads to defaults rather than
    /// failing with a cryptic `missing field ...` — the container-level
    /// `#[serde(default)]`. Makes the "empty {} boots" promise in
    /// docs/configuration.md true and removes a first-run wall.
    #[test]
    fn empty_config_object_loads_to_defaults() {
        let cfg: ServerConfig = serde_json::from_str("{}").expect("empty {} must load");
        let defaults = ServerConfig::default();
        assert_eq!(cfg.port, defaults.port);
        assert_eq!(cfg.batch_size, defaults.batch_size);
        assert_eq!(cfg.partitions, defaults.partitions);
        assert_eq!(cfg.default_catalog, defaults.default_catalog);
        assert!(cfg.catalogs.is_empty());
    }

    /// A missing `--config` path is the most common first-run failure —
    /// the error must point at the generator, not surface a raw IO chain
    #[test]
    fn load_from_file_missing_points_at_generator() {
        let tmp = tempfile::tempdir().unwrap();
        let missing = tmp.path().join("does-not-exist.json");
        let err = ServerConfig::load_from_file(&missing).expect_err("missing file must error");
        let msg = format!("{err:#}");
        assert!(msg.contains("not found"), "{msg}");
        assert!(msg.contains("--print-example-config"), "{msg}");
    }

    ///  — T1 from the spec's test inventory.
    ///
    /// Reproduces the 2026-06-07 bug: a clap `default_value =
    /// "dataglot"` on `Args::default_catalog` silently overrode the
    /// JSON config's `default_catalog: "pg"` because `ServerConfig::load`
    /// always did `clone_from(&args.default_catalog)`. The fix made
    /// `Args::default_catalog` an `Option<String>` and made the load
    /// step conditional. This test pins both directions:
    /// - file value survives when neither CLI flag nor env var sets it
    /// - CLI flag overrides the file value when explicitly passed.
    ///
    /// Without the fix, the first assertion failed (config saw
    /// `"dataglot"`, not `"pg"`).
    #[test]
    fn cli_default_catalog_does_not_clobber_file_value_when_unset() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("dataglot.json");
        let body = serde_json::json!({
            "host": "127.0.0.1",
            "port": 5432,
            "batch_size": 8192,
            "partitions": 4,
            "default_catalog": "pg",
            "default_schema": "warehouse_main",
        });
        std::fs::write(&path, serde_json::to_string(&body).unwrap()).unwrap();

        // No `--default-catalog` / `--default-schema` on the CLI.
        let args = Args::parse_from(["dataglot", "--config", path.to_str().unwrap()]);
        let config = ServerConfig::load(&args).unwrap();
        assert_eq!(
            config.default_catalog, "pg",
            "JSON config's default_catalog must survive when CLI flag is unset"
        );
        assert_eq!(
            config.default_schema, "warehouse_main",
            "JSON config's default_schema must survive when CLI flag is unset"
        );

        // Now pass `--default-catalog` explicitly: CLI must win.
        let args = Args::parse_from([
            "dataglot",
            "--config",
            path.to_str().unwrap(),
            "--default-catalog",
            "from_cli",
            "--default-schema",
            "from_cli_schema",
        ]);
        let config = ServerConfig::load(&args).unwrap();
        assert_eq!(config.default_catalog, "from_cli");
        assert_eq!(config.default_schema, "from_cli_schema");
    }

    ///  — companion to the above. When neither CLI nor file
    /// sets `default_catalog`, the `Default::default()` fallback
    /// (`"dataglot"`) applies. Pins that the precedence chain
    /// terminates at the struct's `Default` impl, not at clap.
    #[test]
    fn load_with_no_cli_and_no_file_falls_back_to_struct_default() {
        let args = Args::parse_from(["dataglot"]);
        let config = ServerConfig::load(&args).unwrap();
        assert_eq!(config.default_catalog, "dataglot");
        assert_eq!(config.default_schema, "public");
    }

    ///  — the network-field analogue of the `default_catalog`
    /// regression above.
    ///
    /// Reproduces the live-QA bug: clap `default_value`s on
    /// `Args::{host, port, batch_size}` (`"127.0.0.1"` / `5432` /
    /// `8192`) silently overrode the JSON config because
    /// `ServerConfig::load` unconditionally did `config.port =
    /// args.port` (etc.). A config with `"port": 15499` bound 5432
    /// until `--port` was passed. The fix made those `Args` fields
    /// `Option` and made the override conditional. This pins both
    /// directions:
    /// - file values survive when no CLI flag / env var sets them
    /// - a CLI flag overrides the file value when explicitly passed.
    ///
    /// Without the fix the first block's `port` assertion fails
    /// (config saw `5432`, not `15499`).
    #[test]
    fn cli_network_fields_do_not_clobber_file_values_when_unset() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("dataglot.json");
        let body = serde_json::json!({
            "host": "0.0.0.0",
            "port": 15499,
            "batch_size": 32768,
            "partitions": 4,
            "default_catalog": "dataglot",
            "default_schema": "public",
        });
        std::fs::write(&path, serde_json::to_string(&body).unwrap()).unwrap();

        // No `--host` / `--port` / `--batch-size` on the CLI.
        let args = Args::parse_from(["dataglot", "--config", path.to_str().unwrap()]);
        let config = ServerConfig::load(&args).unwrap();
        assert_eq!(
            config.port, 15499,
            "JSON config's port must survive when --port is unset"
        );
        assert_eq!(
            config.host, "0.0.0.0",
            "JSON config's host must survive when --host is unset"
        );
        assert_eq!(
            config.batch_size, 32768,
            "JSON config's batch_size must survive when --batch-size is unset"
        );

        // Now pass the flags explicitly: CLI must win over the file.
        let args = Args::parse_from([
            "dataglot",
            "--config",
            path.to_str().unwrap(),
            "--host",
            "127.0.0.1",
            "--port",
            "5555",
            "--batch-size",
            "1024",
        ]);
        let config = ServerConfig::load(&args).unwrap();
        assert_eq!(config.host, "127.0.0.1");
        assert_eq!(config.port, 5555);
        assert_eq!(config.batch_size, 1024);
    }

    /// Round-trip a server config containing a `[catalogs.pg_users]`
    /// entry of `kind = "postgres"`. Pins the JSON shape of the
    /// `dsn_env` form.
    #[test]
    fn parses_postgres_catalog_config() {
        let json = serde_json::json!({
            "host": "0.0.0.0",
            "port": 5432,
            "batch_size": 8192,
            "partitions": 4,
            "default_catalog": "dataglot",
            "default_schema": "public",
            "catalogs": {
                "pg_users": {
                    "kind": "postgres",
                    "dsn_env": "PG_USERS_DSN"
                }
            }
        });
        let cfg: ServerConfig = serde_json::from_value(json).unwrap();
        let entry = cfg
            .catalogs
            .get("pg_users")
            .expect("pg_users catalog present");
        match entry {
            CatalogConfig::Postgres(pg) => {
                assert_eq!(pg.dsn_env.as_deref(), Some("PG_USERS_DSN"));
                assert!(pg.dsn.is_none());
            }
            other => panic!("expected Postgres variant, got {other:?}"),
        }
    }

    /// Round-trip a `[catalogs.warehouse]` entry of `kind = "warehouse"`
    /// with static credentials sourced from an env var.
    #[test]
    fn parses_warehouse_catalog_config() {
        let json = serde_json::json!({
            "host": "0.0.0.0",
            "port": 5432,
            "batch_size": 8192,
            "partitions": 4,
            "default_catalog": "dataglot",
            "default_schema": "public",
            "catalogs": {
                "warehouse": {
                    "kind": "warehouse",
                    "catalog_url": "http://lakekeeper:8181/catalog",
                    "warehouse": "main",
                    "s3_endpoint": "http://minio:9000",
                    "s3_region": "us-east-1",
                    "credentials": {
                        "kind": "static",
                        "access_key_id": "AKIA0EXAMPLE0",
                        "secret_access_key_env": "WAREHOUSE_SECRET"
                    }
                }
            }
        });
        let cfg: ServerConfig = serde_json::from_value(json).unwrap();
        let entry = cfg
            .catalogs
            .get("warehouse")
            .expect("warehouse catalog present");
        match entry {
            CatalogConfig::Warehouse(wh) => {
                assert_eq!(wh.catalog_url, "http://lakekeeper:8181/catalog");
                assert_eq!(wh.warehouse, "main");
                assert_eq!(wh.s3_endpoint.as_deref(), Some("http://minio:9000"));
                assert_eq!(wh.s3_region.as_deref(), Some("us-east-1"));
                match &wh.credentials {
                    WarehouseCredentialsConfig::Static {
                        access_key_id,
                        secret_access_key,
                        secret_access_key_env,
                    } => {
                        assert_eq!(access_key_id, "AKIA0EXAMPLE0");
                        assert!(secret_access_key.is_none());
                        assert_eq!(secret_access_key_env.as_deref(), Some("WAREHOUSE_SECRET"));
                    }
                    WarehouseCredentialsConfig::Environment => {
                        panic!("expected Static credentials variant")
                    }
                }
            }
            other => panic!("expected Warehouse variant, got {other:?}"),
        }
    }

    /// `dsn_env` is resolved by [`resolve_postgres_dsn_with_env`]. We
    /// pin both the success path (env var present in the lookup) and
    /// the failure path (env var missing — message must mention the
    /// var **name** but not its value).
    ///
    /// We use the injected-lookup form rather than mutating the
    /// process env: the workspace forbids `unsafe_code` and
    /// `std::env::set_var` is `unsafe fn` in Rust 1.92.
    #[test]
    fn dsn_env_resolution_at_runtime() {
        let cfg = PostgresCatalogConfig {
            dsn: None,
            dsn_env: Some("PG_USERS_DSN".to_string()),
            ..Default::default()
        };

        // Failure path: lookup returns NotPresent.
        let missing: EnvLookup = &|_: &str| Err(std::env::VarError::NotPresent);
        let err =
            resolve_postgres_dsn_with_env("pg_users", &cfg, missing).expect_err("missing env var");
        let msg = format!("{err:#}");
        assert!(msg.contains("pg_users"), "{msg}");
        assert!(msg.contains("PG_USERS_DSN"), "{msg}");

        // Success path: lookup returns the DSN.
        let present: EnvLookup = &|name: &str| {
            assert_eq!(name, "PG_USERS_DSN");
            Ok("host=db.example user=alice dbname=prod".to_string())
        };
        let dsn = resolve_postgres_dsn_with_env("pg_users", &cfg, present).unwrap();
        assert_eq!(dsn, "host=db.example user=alice dbname=prod");
    }

    /// `[catalogs.*]` TLS fields deserialize; omitted ⇒ plaintext default.
    #[test]
    fn postgres_tls_config_deserializes() {
        let cfg: PostgresCatalogConfig = serde_json::from_str(
            r#"{"dsn_env":"PG","tls":"require","tls_ca_file":"/certs/ca.pem","tls_accept_invalid_certs":true}"#,
        )
        .unwrap();
        assert_eq!(cfg.tls, SourceTlsMode::Require);
        assert_eq!(
            cfg.tls_ca_file.as_deref(),
            Some(std::path::Path::new("/certs/ca.pem"))
        );
        assert!(cfg.tls_accept_invalid_certs);

        // Omitted TLS ⇒ plaintext default, no CA, verify on.
        let plain: PostgresCatalogConfig = serde_json::from_str(r#"{"dsn_env":"PG"}"#).unwrap();
        assert_eq!(plain.tls, SourceTlsMode::Disable);
        assert!(plain.tls_ca_file.is_none());
        assert!(!plain.tls_accept_invalid_certs);
    }

    /// TLS knobs without `tls = "require"` fail fast (they'd otherwise be
    /// silently ignored). Bails before any connection attempt.
    #[tokio::test]
    async fn tls_knobs_without_require_error() {
        let cfg = CatalogConfig::Postgres(PostgresCatalogConfig {
            dsn: Some("host=localhost dbname=x".into()),
            tls: SourceTlsMode::Disable,
            tls_ca_file: Some("/certs/ca.pem".into()),
            ..Default::default()
        });
        let err = build_one_connector("pg", &cfg)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("tls_ca_file"), "{err}");
        assert!(err.contains("disable"), "{err}");
    }

    /// `Debug` never leaks the DSN and shows the (non-secret) TLS fields.
    #[test]
    fn postgres_tls_debug_is_credential_safe() {
        let cfg = PostgresCatalogConfig {
            // A distinctive password sentinel — deliberately NOT the word
            // "secret", which now appears as the `dsn_secret` *field name*.
            dsn: Some("host=db user=u password=hunter2 dbname=d".into()),
            tls: SourceTlsMode::Require,
            tls_ca_file: Some("/certs/ca.pem".into()),
            ..Default::default()
        };
        let dbg = format!("{cfg:?}");
        assert!(!dbg.contains("hunter2"), "DSN leaked: {dbg}");
        assert!(!dbg.contains("host=db"), "DSN leaked: {dbg}");
        assert!(dbg.contains("Require"), "{dbg}");
        assert!(dbg.contains("ca.pem"), "{dbg}");
    }

    fn identity_with_pw_env(env_name: &str) -> IdentityProfileConfig {
        IdentityProfileConfig {
            org: None,
            groups: vec!["analyst".into()],
            password_env: Some(env_name.to_string()),
        }
    }

    /// Trust mode ignores credentials entirely and maps to the pgwire
    /// trust authenticator.
    #[test]
    fn build_auth_mode_trust_is_default_and_credential_free() {
        let auth = AuthConfig::default();
        assert_eq!(auth.mode, AuthMode::Trust);
        let never: EnvLookup = &|_: &str| panic!("trust mode must not read env");
        let mode = build_auth_mode_with_env(&auth, &HashMap::new(), never).unwrap();
        assert!(matches!(mode, dataglot_pgwire::AuthMode::Trust));
    }

    /// MD5 mode resolves each identity's `password_env` into a working
    /// `PasswordSource`. Verified via the injected lookup (no
    /// `std::env::set_var` — `unsafe fn` in Rust 1.92).
    #[tokio::test]
    async fn build_auth_mode_md5_resolves_credentials_from_env() {
        let mut identities = HashMap::new();
        identities.insert("alice".to_string(), identity_with_pw_env("PW_ALICE"));

        let auth = AuthConfig {
            mode: AuthMode::Md5,
            ..Default::default()
        };
        let present: EnvLookup = &|name: &str| {
            assert_eq!(name, "PW_ALICE");
            Ok("s3cret".to_string())
        };
        let mode = build_auth_mode_with_env(&auth, &identities, present).unwrap();
        let dataglot_pgwire::AuthMode::Md5(source) = mode else {
            panic!("expected md5 mode");
        };
        assert_eq!(source.password("alice").await.as_deref(), Some("s3cret"));
        assert_eq!(source.password("bob").await, None);
    }

    /// A declared `password_env` whose variable is unset is a fail-fast
    /// misconfiguration; the message names the var but never its value.
    #[test]
    fn build_auth_mode_md5_errors_on_missing_env() {
        let mut identities = HashMap::new();
        identities.insert("alice".to_string(), identity_with_pw_env("PW_ALICE"));
        let auth = AuthConfig {
            mode: AuthMode::Md5,
            ..Default::default()
        };
        let missing: EnvLookup = &|_: &str| Err(std::env::VarError::NotPresent);
        let err = build_auth_mode_with_env(&auth, &identities, missing).expect_err("missing env");
        let msg = format!("{err:#}");
        assert!(msg.contains("PW_ALICE"), "{msg}");
        assert!(msg.contains("alice"), "{msg}");
    }

    /// MD5 mode with zero resolvable credentials would reject every
    /// connection — treat as a configuration error, not silent lockout.
    #[test]
    fn build_auth_mode_md5_errors_when_no_credentials() {
        let auth = AuthConfig {
            mode: AuthMode::Md5,
            ..Default::default()
        };
        // No identities at all.
        let never: EnvLookup = &|_: &str| Err(std::env::VarError::NotPresent);
        let err = build_auth_mode_with_env(&auth, &HashMap::new(), never).expect_err("no creds");
        assert!(format!("{err:#}").contains("no identity"), "{err:#}");
    }

    /// An identity without a `password_env` is skipped (it just can't
    /// authenticate); other identities still produce a working source.
    #[tokio::test]
    async fn build_auth_mode_md5_skips_credential_less_identities() {
        let mut identities = HashMap::new();
        identities.insert("alice".to_string(), identity_with_pw_env("PW_ALICE"));
        identities.insert(
            "bob".to_string(),
            IdentityProfileConfig {
                org: None,
                groups: vec!["support".into()],
                password_env: None,
            },
        );
        let auth = AuthConfig {
            mode: AuthMode::Md5,
            ..Default::default()
        };
        let present: EnvLookup = &|_: &str| Ok("pw".to_string());
        let mode = build_auth_mode_with_env(&auth, &identities, present).unwrap();
        let dataglot_pgwire::AuthMode::Md5(source) = mode else {
            panic!("expected md5");
        };
        assert_eq!(source.password("alice").await.as_deref(), Some("pw"));
        assert_eq!(
            source.password("bob").await,
            None,
            "no password_env ⇒ no credential"
        );
    }

    fn ldap_auth_config(
        search_bind_dn: Option<&str>,
        search_bind_password_env: Option<&str>,
    ) -> LdapAuthConfig {
        LdapAuthConfig {
            url: "ldap://dir.example:389".to_string(),
            bind_dn_template: "uid={user},ou=people,dc=example,dc=com".to_string(),
            group_search_base: "ou=groups,dc=example,dc=com".to_string(),
            group_filter: default_group_filter(),
            group_name_attr: default_group_name_attr(),
            search_bind_dn: search_bind_dn.map(str::to_string),
            search_bind_password_env: search_bind_password_env.map(str::to_string),
        }
    }

    ///: without a `search_bind_dn` the group search is anonymous, so
    /// the build reads no env var (byte-identical to the pre- path).
    #[test]
    fn build_auth_mode_ldap_anonymous_reads_no_env() {
        let auth = AuthConfig {
            mode: AuthMode::Ldap,
            ldap: Some(ldap_auth_config(None, None)),
            ..Default::default()
        };
        let never: EnvLookup = &|name: &str| panic!("anonymous ldap must not read env ({name})");
        let mode = build_auth_mode_with_env(&auth, &HashMap::new(), never).unwrap();
        assert!(matches!(mode, dataglot_pgwire::AuthMode::Ldap(_)));
    }

    ///: a configured service account resolves its password from the
    /// named env var (rule 12 — never inlined) and the authenticator builds.
    #[test]
    fn build_auth_mode_ldap_service_account_resolves_password_env() {
        let auth = AuthConfig {
            mode: AuthMode::Ldap,
            ldap: Some(ldap_auth_config(
                Some("cn=svc-ro,ou=svc,dc=example,dc=com"),
                Some("LDAP_SVC_PW"),
            )),
            ..Default::default()
        };
        let present: EnvLookup = &|name: &str| {
            assert_eq!(name, "LDAP_SVC_PW");
            Ok("svc-secret".to_string())
        };
        let mode = build_auth_mode_with_env(&auth, &HashMap::new(), present).unwrap();
        assert!(matches!(mode, dataglot_pgwire::AuthMode::Ldap(_)));
    }

    ///: a `search_bind_dn` without a `search_bind_password_env` is a
    /// fail-fast misconfiguration (never a silent anonymous downgrade).
    #[test]
    fn build_auth_mode_ldap_service_account_requires_password_env_name() {
        let auth = AuthConfig {
            mode: AuthMode::Ldap,
            ldap: Some(ldap_auth_config(Some("cn=svc-ro,dc=example,dc=com"), None)),
            ..Default::default()
        };
        let never: EnvLookup = &|_: &str| Err(std::env::VarError::NotPresent);
        let err = build_auth_mode_with_env(&auth, &HashMap::new(), never)
            .expect_err("missing password env name");
        assert!(
            format!("{err:#}").contains("search_bind_password_env"),
            "{err:#}"
        );
    }

    ///: the named env var being unset is a fail-fast error that names
    /// the var (a debuggable hint) but never the secret.
    #[test]
    fn build_auth_mode_ldap_service_account_errors_on_unset_env() {
        let auth = AuthConfig {
            mode: AuthMode::Ldap,
            ldap: Some(ldap_auth_config(
                Some("cn=svc-ro,dc=example,dc=com"),
                Some("LDAP_SVC_PW"),
            )),
            ..Default::default()
        };
        let missing: EnvLookup = &|_: &str| Err(std::env::VarError::NotPresent);
        let err = build_auth_mode_with_env(&auth, &HashMap::new(), missing).expect_err("unset env");
        let msg = format!("{err:#}");
        assert!(msg.contains("LDAP_SVC_PW"), "{msg}");
    }

    /// `ConfigPasswordSource`'s `Debug` must not leak usernames or
    /// passwords (CLAUDE.md rule 12).
    #[test]
    fn config_password_source_debug_is_redacted() {
        let mut creds = HashMap::new();
        creds.insert("alice".to_string(), "s3cret".to_string());
        let src = ConfigPasswordSource {
            creds: Arc::new(creds),
        };
        let dbg = format!("{src:?}");
        assert!(!dbg.contains("s3cret"), "password leaked: {dbg}");
        assert!(!dbg.contains("alice"), "username leaked: {dbg}");
        assert!(dbg.contains("users: 1"), "{dbg}");
    }

    #[test]
    fn has_governance_policies_detects_each_enforcement_source() {
        let base = ServerConfig::default();
        assert!(!base.has_governance_policies(), "empty config has none");

        let mut with_mask = ServerConfig::default();
        with_mask.masks.push(MaskConfig {
            table: "users".into(),
            column: "email".into(),
            mask_literal: "***".into(),
            mask_type: None,
            priority: 0,
            mask_expr: None,
            groups: None,
        });
        assert!(with_mask.has_governance_policies(), "a mask counts");

        // Identities/roles alone (no policy) do NOT count.
        let mut only_identities = ServerConfig::default();
        only_identities
            .identities
            .insert("alice".into(), IdentityProfileConfig::default());
        assert!(
            !only_identities.has_governance_policies(),
            "identities without a policy enforce nothing"
        );
    }

    #[test]
    fn warn_insecure_auth_runs_for_each_posture() {
        // Smoke: the warning paths execute without panicking for the
        // three postures (trust+policy, md5, trust-no-policy).
        let mut trust_with_policy = ServerConfig::default();
        trust_with_policy.masks.push(MaskConfig {
            table: "t".into(),
            column: "c".into(),
            mask_literal: "***".into(),
            mask_type: None,
            priority: 0,
            mask_expr: None,
            groups: None,
        });
        assert_eq!(trust_with_policy.auth.mode, AuthMode::Trust);
        trust_with_policy.warn_insecure_auth();

        let md5 = ServerConfig {
            auth: AuthConfig {
                mode: AuthMode::Md5,
                ..Default::default()
            },
            ..ServerConfig::default()
        };
        md5.warn_insecure_auth();

        let scram = ServerConfig {
            auth: AuthConfig {
                mode: AuthMode::ScramSha256,
                ..Default::default()
            },
            ..ServerConfig::default()
        };
        scram.warn_insecure_auth();

        ServerConfig::default().warn_insecure_auth(); // trust, no policy → silent
    }

    /// The empty-treeview warning fires only when it is actionable: capture
    /// on, `partitions > 1`, AND single-node. In distributed mode the
    /// scheduler overrides `target_partitions`, so `partitions = 1` cannot
    /// populate the treeview and the warning must stay silent.
    #[test]
    fn should_warn_empty_treeview_only_single_node() {
        // Single-node, capture on, partitions > 1 → warn (the remedy works).
        let mut cfg = ServerConfig::default();
        cfg.observability.capture_query_sources = true;
        cfg.partitions = 8;
        assert!(cfg.should_warn_empty_treeview());

        // partitions = 1 → treeview already populates, nothing to warn about.
        cfg.partitions = 1;
        assert!(!cfg.should_warn_empty_treeview());

        // Capture off → the treeview isn't wanted, so no warning.
        cfg.partitions = 8;
        cfg.observability.capture_query_sources = false;
        assert!(!cfg.should_warn_empty_treeview());

        // Distributed (external executors) → the treeview is populated from
        // executor pushdown metrics regardless of partitions, and the
        // scheduler overrides target_partitions, so `partitions = 1` can't
        // help; stay silent even with capture on and partitions > 1.
        cfg.observability.capture_query_sources = true;
        cfg.ballista = Some(BallistaServerConfig {
            external_executors: 2,
            ..Default::default()
        });
        assert!(!cfg.should_warn_empty_treeview());

        // Embedded standalone Ballista (no external executors) still runs jobs
        // through the scheduler, so the same executor-metrics path populates
        // the treeview — the warning is a false remedy here too. Silent.
        cfg.ballista = Some(BallistaServerConfig {
            external_executors: 0,
            ..Default::default()
        });
        assert!(!cfg.should_warn_empty_treeview());
    }

    /// The `[auth] mode` key round-trips through serde with lowercase
    /// rename, and an omitted `mode` defaults to trust.
    #[test]
    fn auth_mode_deserializes_lowercase() {
        let cfg: AuthConfig = serde_json::from_str(r#"{"mode":"md5"}"#).unwrap();
        assert_eq!(cfg.mode, AuthMode::Md5);
        let cfg: AuthConfig = serde_json::from_str(r#"{"mode":"trust"}"#).unwrap();
        assert_eq!(cfg.mode, AuthMode::Trust);
        let cfg: AuthConfig = serde_json::from_str("{}").unwrap();
        assert_eq!(cfg.mode, AuthMode::Trust, "omitted mode defaults to trust");
    }

    /// `scram-sha-256` round-trips through serde (both directions) under its
    /// hyphenated rename — the wire name Postgres clients expect.
    #[test]
    fn auth_mode_scram_serde_round_trips() {
        let cfg: AuthConfig = serde_json::from_str(r#"{"mode":"scram-sha-256"}"#).unwrap();
        assert_eq!(cfg.mode, AuthMode::ScramSha256);
        let json = serde_json::to_string(&cfg).unwrap();
        assert!(json.contains("scram-sha-256"), "{json}");
        // The lowercase-but-unhyphenated spelling is NOT accepted.
        assert!(serde_json::from_str::<AuthConfig>(r#"{"mode":"scramsha256"}"#).is_err());
    }

    /// `scram-sha-256` mode resolves credentials exactly like md5 (same
    /// `PasswordSource` factory) and maps to `AuthMode::ScramSha256`.
    #[tokio::test]
    async fn build_auth_mode_scram_maps_and_resolves_credentials() {
        let mut identities = HashMap::new();
        identities.insert("alice".to_string(), identity_with_pw_env("PW_ALICE"));

        let auth = AuthConfig {
            mode: AuthMode::ScramSha256,
            ..Default::default()
        };
        let present: EnvLookup = &|name: &str| {
            assert_eq!(name, "PW_ALICE");
            Ok("s3cret".to_string())
        };
        let mode = build_auth_mode_with_env(&auth, &identities, present).unwrap();
        let dataglot_pgwire::AuthMode::ScramSha256(source) = mode else {
            panic!("expected scram-sha-256 mode");
        };
        assert_eq!(source.password("alice").await.as_deref(), Some("s3cret"));
        assert_eq!(source.password("bob").await, None);
    }

    /// `scram-sha-256` with zero resolvable credentials is a fail-fast
    /// misconfiguration, named by the selected mode (parity with md5).
    #[test]
    fn build_auth_mode_scram_errors_when_no_credentials() {
        let auth = AuthConfig {
            mode: AuthMode::ScramSha256,
            ..Default::default()
        };
        let never: EnvLookup = &|_: &str| Err(std::env::VarError::NotPresent);
        let err = build_auth_mode_with_env(&auth, &HashMap::new(), never).expect_err("no creds");
        let msg = format!("{err:#}");
        assert!(msg.contains("scram-sha-256"), "{msg}");
        assert!(msg.contains("no identity"), "{msg}");
    }

    /// `[pgwire_tls]` deserializes; omitted `mode` defaults to `prefer`.
    #[test]
    fn pgwire_tls_config_deserializes() {
        let cfg: PgwireTlsConfig = serde_json::from_str(
            r#"{"cert_file":"/c/server.crt","key_file":"/c/server.key","mode":"require"}"#,
        )
        .unwrap();
        assert_eq!(cfg.cert_file, std::path::Path::new("/c/server.crt"));
        assert_eq!(cfg.key_file, std::path::Path::new("/c/server.key"));
        assert_eq!(cfg.mode, PgwireTlsMode::Require);

        let prefer: PgwireTlsConfig =
            serde_json::from_str(r#"{"cert_file":"c","key_file":"k"}"#).unwrap();
        assert_eq!(prefer.mode, PgwireTlsMode::Prefer, "omitted ⇒ prefer");
    }

    /// `[flight_sql]` deserializes: omitted `addr` ⇒ the `:32010` default,
    /// omitted `tls` ⇒ `None`, and a supplied TLS block round-trips its
    /// cert/key paths. Absent from `ServerConfig` ⇒ no listener.
    #[test]
    fn flight_sql_config_deserializes() {
        // Empty table ⇒ default addr, TLS off.
        let cfg: FlightSqlConfig = serde_json::from_str("{}").unwrap();
        assert_eq!(cfg.addr, "0.0.0.0:32010", "omitted addr ⇒ :32010 default");
        assert!(cfg.tls.is_none(), "omitted tls ⇒ None");

        // Custom addr + TLS block round-trips.
        let cfg: FlightSqlConfig = serde_json::from_str(
            r#"{"addr":"127.0.0.1:41010","tls":{"cert_file":"/c/f.crt","key_file":"/c/f.key"}}"#,
        )
        .unwrap();
        assert_eq!(cfg.addr, "127.0.0.1:41010");
        let tls = cfg.tls.expect("tls block present");
        assert_eq!(tls.cert_file, std::path::Path::new("/c/f.crt"));
        assert_eq!(tls.key_file, std::path::Path::new("/c/f.key"));

        // Absent from ServerConfig ⇒ no Flight SQL listener.
        assert!(ServerConfig::default().flight_sql.is_none());
    }

    /// `[rate_limit]` deserializes all ceilings; omitted fields ⇒ `None`.
    #[test]
    fn rate_limit_config_deserializes() {
        let cfg: RateLimitConfig = serde_json::from_str(
            r#"{"max_connections":200,"max_connections_per_ip":20,"max_new_connections_per_ip_per_minute":120,"max_connections_per_identity":5}"#,
        )
        .unwrap();
        assert_eq!(cfg.max_connections, Some(200));
        assert_eq!(cfg.max_connections_per_ip, Some(20));
        assert_eq!(cfg.max_new_connections_per_ip_per_minute, Some(120));
        assert_eq!(cfg.max_connections_per_identity, Some(5));

        let partial: RateLimitConfig = serde_json::from_str(r#"{"max_connections":50}"#).unwrap();
        assert_eq!(partial.max_connections, Some(50));
        assert_eq!(
            partial.max_connections_per_ip, None,
            "omitted per-IP ⇒ unlimited"
        );
        assert_eq!(
            partial.max_new_connections_per_ip_per_minute, None,
            "omitted rate ⇒ no rate limit"
        );

        // An absent block leaves the server-level field None.
        assert!(
            ServerConfig::default().rate_limit.is_none(),
            "no block ⇒ no admission control"
        );
    }

    /// `secret_access_key_env` takes precedence over an inline
    /// `secret_access_key` when both are set. Verified via the
    /// injected-lookup form (see the test above for why).
    #[test]
    fn static_credentials_secret_env_takes_precedence() {
        use dataglot_federation::iceberg::WarehouseCredentials;

        let cfg = WarehouseCredentialsConfig::Static {
            access_key_id: "AKIA0EXAMPLE0".to_string(),
            secret_access_key: Some("inline-secret".to_string()),
            secret_access_key_env: Some("WAREHOUSE_SECRET".to_string()),
        };
        let env: EnvLookup = &|name: &str| {
            assert_eq!(name, "WAREHOUSE_SECRET");
            Ok("secret-from-env".to_string())
        };
        let resolved = resolve_warehouse_credentials_with_env("warehouse", &cfg, env).unwrap();
        match resolved {
            WarehouseCredentials::Static {
                access_key_id,
                secret_access_key,
            } => {
                assert_eq!(access_key_id, "AKIA0EXAMPLE0");
                assert_eq!(
                    secret_access_key, "secret-from-env",
                    "env var must override inline value"
                );
            }
            WarehouseCredentials::Environment => panic!("expected Static variant"),
        }
    }

    /// When `secret_access_key_env` is unset, the inline value is
    /// used verbatim. Pinned via injected lookup so the test never
    /// touches the process environment.
    #[test]
    fn static_credentials_uses_inline_when_no_env_var_configured() {
        use dataglot_federation::iceberg::WarehouseCredentials;

        let cfg = WarehouseCredentialsConfig::Static {
            access_key_id: "AKIA0EXAMPLE0".to_string(),
            secret_access_key: Some("inline-secret".to_string()),
            secret_access_key_env: None,
        };
        // The lookup must NOT be called when no env var is configured.
        // Panic loudly if it is — that would be a regression.
        let env: EnvLookup =
            &|name: &str| panic!("env lookup should not be called for {name}; secret is inline");
        let resolved = resolve_warehouse_credentials_with_env("warehouse", &cfg, env).unwrap();
        match resolved {
            WarehouseCredentials::Static {
                secret_access_key, ..
            } => assert_eq!(secret_access_key, "inline-secret"),
            WarehouseCredentials::Environment => panic!("expected Static"),
        }
    }

    /// Missing `secret_access_key_env` surfaces with the env-var name
    /// in the error message. Confirms credential bytes are never
    /// included in error context.
    #[test]
    fn static_credentials_secret_env_missing_reports_var_name() {
        let cfg = WarehouseCredentialsConfig::Static {
            access_key_id: "AKIA0EXAMPLE0".to_string(),
            secret_access_key: None,
            secret_access_key_env: Some("WAREHOUSE_SECRET".to_string()),
        };
        let env: EnvLookup = &|_: &str| Err(std::env::VarError::NotPresent);
        let err =
            resolve_warehouse_credentials_with_env("warehouse", &cfg, env).expect_err("missing");
        let msg = format!("{err:#}");
        assert!(msg.contains("WAREHOUSE_SECRET"), "{msg}");
        assert!(msg.contains("warehouse"), "{msg}");
    }

    /// CLAUDE.md rule 12: the literal DSN never appears in `Debug`
    /// output for [`PostgresCatalogConfig`].
    #[test]
    fn debug_redacts_postgres_dsn() {
        let cfg = PostgresCatalogConfig {
            dsn: Some("host=db user=alice password=topsecret dbname=prod".to_string()),
            dsn_env: None,
            ..Default::default()
        };
        let s = format!("{cfg:?}");
        assert!(!s.contains("topsecret"), "{s}");
        assert!(!s.contains("alice"), "{s}");
        assert!(!s.contains("db"), "{s}");
        assert!(s.contains("<redacted>"), "{s}");
    }

    /// `Debug` for the `CatalogConfig::Postgres` wrapper must also
    /// redact — pinning the full nested path.
    #[test]
    fn debug_redacts_postgres_dsn_via_catalog_config() {
        let cfg = CatalogConfig::Postgres(PostgresCatalogConfig {
            dsn: Some("host=db user=alice password=topsecret dbname=prod".to_string()),
            dsn_env: None,
            ..Default::default()
        });
        let s = format!("{cfg:?}");
        assert!(!s.contains("topsecret"), "{s}");
        assert!(s.contains("<redacted>"), "{s}");
    }

    /// CLAUDE.md rule 12: the literal `secret_access_key` never appears
    /// in `Debug` output for [`WarehouseCredentialsConfig::Static`]. The
    /// access-key-id and the env-var **name** are kept visible — they
    /// are not themselves secrets.
    #[test]
    fn debug_redacts_warehouse_secret() {
        let cfg = WarehouseCredentialsConfig::Static {
            access_key_id: "AKIA0EXAMPLE0".to_string(),
            secret_access_key: Some("totally-secret-do-not-print".to_string()),
            secret_access_key_env: Some("WAREHOUSE_SECRET".to_string()),
        };
        let s = format!("{cfg:?}");
        assert!(
            !s.contains("totally-secret-do-not-print"),
            "Debug leaked secret_access_key: {s}"
        );
        assert!(s.contains("AKIA0EXAMPLE0"), "{s}");
        assert!(s.contains("WAREHOUSE_SECRET"), "{s}");
        assert!(s.contains("<redacted>"), "{s}");
    }

    /// `Environment` credentials have nothing to redact — should still
    /// produce a stable, finite Debug string.
    #[test]
    fn debug_environment_warehouse_credentials_is_terse() {
        let cfg = WarehouseCredentialsConfig::Environment;
        let s = format!("{cfg:?}");
        assert_eq!(s, "Environment");
    }

    /// CLAUDE.md rule 12 regression guard for the inline S3 secret. The
    /// `ObjectStorageS3Config` `Debug` must redact `secret_access_key`
    /// while still showing the non-secret fields ( 1a).
    #[test]
    fn debug_redacts_s3_secret_access_key() {
        let cfg = ObjectStorageS3Config {
            endpoint: Some("http://minio:9000".to_string()),
            region: Some("us-east-1".to_string()),
            access_key_id: Some("AKIA0EXAMPLE0".to_string()),
            secret_access_key: Some("totally-secret-do-not-print".to_string()),
            secret_access_key_env: Some("S3_SECRET".to_string()),
            path_style_access: true,
        };
        let s = format!("{cfg:?}");
        assert!(
            !s.contains("totally-secret-do-not-print"),
            "Debug leaked secret_access_key: {s}"
        );
        assert!(s.contains("<redacted>"), "expected <redacted> marker: {s}");
        assert!(
            s.contains("AKIA0EXAMPLE0"),
            "access_key_id is not secret: {s}"
        );
        assert!(s.contains("us-east-1"), "region should be visible: {s}");
        assert!(s.contains("S3_SECRET"), "env-var name is not secret: {s}");
    }

    /// An S3 config with no inline secret should render `<unset>`, never
    /// panic or leak.
    #[test]
    fn debug_s3_without_inline_secret_is_unset() {
        let cfg = ObjectStorageS3Config {
            endpoint: None,
            region: None,
            access_key_id: None,
            secret_access_key: None,
            secret_access_key_env: Some("S3_SECRET".to_string()),
            path_style_access: true,
        };
        let s = format!("{cfg:?}");
        assert!(s.contains("<unset>"), "expected <unset> marker: {s}");
        assert!(!s.contains("<redacted>"), "{s}");
    }

    /// `resolve_postgres_dsn` rejects a config that sets both `dsn` and
    /// `dsn_env`. Caught at boot, before any connection is opened.
    #[test]
    fn resolve_postgres_dsn_rejects_both_set() {
        let cfg = PostgresCatalogConfig {
            dsn: Some("host=db".to_string()),
            dsn_env: Some("DATAGLOT_TEST_DSN".to_string()),
            ..Default::default()
        };
        let err = resolve_postgres_dsn("pg", &cfg).expect_err("ambiguous config");
        let msg = format!("{err:#}");
        assert!(msg.contains("pg"), "{msg}");
        // Don't leak the dsn value into the error message.
        assert!(!msg.contains("host=db"), "{msg}");
    }

    /// `resolve_postgres_dsn` rejects a config that sets neither `dsn`
    /// nor `dsn_env` — there's nothing to connect to.
    #[test]
    fn resolve_postgres_dsn_rejects_both_unset() {
        let cfg = PostgresCatalogConfig {
            dsn: None,
            dsn_env: None,
            ..Default::default()
        };
        let err = resolve_postgres_dsn("pg", &cfg).expect_err("empty config");
        let msg = format!("{err:#}");
        assert!(msg.contains("pg"), "{msg}");
    }

    /// Static warehouse credentials with no secret source at all is a
    /// configuration error.
    #[test]
    fn resolve_warehouse_credentials_rejects_missing_secret() {
        let cfg = WarehouseCredentialsConfig::Static {
            access_key_id: "k".to_string(),
            secret_access_key: None,
            secret_access_key_env: None,
        };
        let env: EnvLookup = &|_: &str| Err(std::env::VarError::NotPresent);
        let err = resolve_warehouse_credentials_with_env("warehouse", &cfg, env)
            .expect_err("no secret source");
        let msg = format!("{err:#}");
        assert!(msg.contains("warehouse"), "{msg}");
    }

    #[tokio::test]
    async fn build_warehouse_connector_rejects_missing_secret() {
        // Credential resolution runs before any network connect, so a static
        // credential missing both the literal secret and its env var fails
        // deterministically — exercising build_warehouse_connector's error path
        // without a live warehouse.
        let wh = WarehouseCatalogConfig {
            catalog_url: "http://localhost:8181/catalog".to_string(),
            warehouse: "main".to_string(),
            credentials: WarehouseCredentialsConfig::Static {
                access_key_id: "k".to_string(),
                secret_access_key: None,
                secret_access_key_env: None,
            },
            s3_endpoint: None,
            s3_region: None,
        };
        let err = build_warehouse_connector("warehouse", &wh)
            .await
            .expect_err("missing secret must fail before connect");
        assert!(format!("{err:#}").contains("warehouse"));
    }

    /// `Environment` credentials resolve trivially.
    #[test]
    fn resolve_warehouse_credentials_environment_passes_through() {
        use dataglot_federation::iceberg::WarehouseCredentials;
        let cfg = WarehouseCredentialsConfig::Environment;
        let env: EnvLookup =
            &|name: &str| panic!("env lookup should not be called for {name} on Environment");
        let resolved = resolve_warehouse_credentials_with_env("warehouse", &cfg, env).unwrap();
        assert!(matches!(resolved, WarehouseCredentials::Environment));
    }

    /// `build_connectors` over an empty map is a no-op — returns an
    /// empty `HashMap`. No network IO, no error.
    #[tokio::test]
    async fn build_connectors_empty_map_is_ok() {
        let map = HashMap::new();
        let out = build_connectors(&map).await.unwrap();
        assert!(out.is_empty());
    }

    /// `tolerate_unreachable = true` downgrades a boot-time connect
    /// failure to a skip; the fail-fast default still errors. Uses a
    /// missing object-storage file (fails fast, no network).
    #[tokio::test]
    async fn build_connectors_with_tolerant_skips_unreachable() {
        let mut catalogs = HashMap::new();
        catalogs.insert(
            "files".to_string(),
            CatalogConfig::ObjectStorage(ObjectStorageCatalogConfig {
                s3: None,
                tables: vec![ObjectStorageTableConfig {
                    name: "users".into(),
                    url: "file:///nonexistent/path/no_such_file.parquet".into(),
                    format: ObjectStorageFormat::Parquet,
                    schema: None,
                }],
            }),
        );

        // Fail-fast (default): the bad catalog aborts the build.
        assert!(build_connectors_with(&catalogs, false).await.is_err());
        assert!(build_connectors(&catalogs).await.is_err());

        // Tolerant: the bad catalog is skipped, leaving an empty map.
        let out = build_connectors_with(&catalogs, true).await.unwrap();
        assert_eq!(out.len(), 0, "unreachable catalog must be skipped");
    }

    /// Round-trip an `[catalogs.files]` entry of
    /// `kind = "object_storage"`. Pins the JSON shape (tables
    /// array; per-table url + format + optional schema), the
    /// `format = "parquet"` enum tag, the optional schema field,
    /// and the `ObjectStorage` variant being chosen by the
    /// `kind` discriminator.
    #[test]
    fn object_storage_catalog_config_round_trips_through_json() {
        let json = serde_json::json!({
            "host": "0.0.0.0",
            "port": 5432,
            "batch_size": 8192,
            "partitions": 4,
            "default_catalog": "dataglot",
            "default_schema": "public",
            "catalogs": {
                "files": {
                    "kind": "object_storage",
                    "tables": [
                        {
                            "name": "users",
                            "url": "file:///data/users.parquet",
                            "format": "parquet"
                        },
                        {
                            "name": "orders",
                            "url": "file:///data/orders.parquet",
                            "format": "parquet",
                            "schema": "sales"
                        }
                    ]
                }
            }
        });
        let cfg: ServerConfig = serde_json::from_value(json).unwrap();
        let entry = cfg.catalogs.get("files").expect("files catalog present");
        match entry {
            CatalogConfig::ObjectStorage(os) => {
                assert_eq!(os.tables.len(), 2);
                assert_eq!(os.tables[0].name, "users");
                assert_eq!(os.tables[0].url, "file:///data/users.parquet");
                assert!(matches!(os.tables[0].format, ObjectStorageFormat::Parquet));
                // The first table didn't declare a schema — we
                // surface that as None and let
                // `build_object_storage_catalog` default to
                // `"public"` at boot.
                assert!(os.tables[0].schema.is_none());
                // Second table declares `schema = "sales"`.
                assert_eq!(os.tables[1].schema.as_deref(), Some("sales"));
            }
            other => panic!("expected ObjectStorage variant, got {other:?}"),
        }

        // Round-trip survives reserialization. Locks the shape a
        // future serde rename can't accidentally break.
        let reserialized = serde_json::to_string(&cfg).expect("reserialize");
        let cfg2: ServerConfig = serde_json::from_str(&reserialized).expect("re-parse");
        let os2 = match cfg2
            .catalogs
            .get("files")
            .expect("files catalog present after round-trip")
        {
            CatalogConfig::ObjectStorage(os) => os,
            other => panic!("expected ObjectStorage variant after round-trip, got {other:?}"),
        };
        assert_eq!(os2.tables.len(), 2);
    }

    #[tokio::test]
    async fn object_storage_s3_url_without_s3_block_is_rejected() {
        //: `s3://` now requires an `[s3]` block. Without one, the
        // error points at the missing block (not a blanket "file:// only").
        let cfg = ObjectStorageCatalogConfig {
            s3: None,
            tables: vec![ObjectStorageTableConfig {
                name: "users".into(),
                url: "s3://my-bucket/users.parquet".into(),
                format: ObjectStorageFormat::Parquet,
                schema: None,
            }],
        };
        let err = object_storage_s3_stores("files", &cfg).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("[s3]") && msg.contains("files"),
            "expected a missing-[s3]-block message naming the catalog; got:\n{msg}"
        );
    }

    #[tokio::test]
    async fn object_storage_rejects_unsupported_scheme() {
        // gs:// / abfs:// aren't supported yet — a typed error, not a
        // confusing runtime failure.
        let err = validate_object_storage_url("files", "t", "gs://bucket/obj.parquet", false)
            .unwrap_err();
        assert!(
            err.to_string().contains("unsupported URL scheme"),
            "got: {err}"
        );
    }

    #[test]
    fn object_storage_s3_stores_builds_one_store_per_bucket() {
        // Two tables across two buckets → two stores, keyed by `s3://bucket`.
        // Uses an inline secret (dev escape hatch) so the test needs no env
        // and no network — `AmazonS3Builder::build` doesn't connect.
        let cfg = ObjectStorageCatalogConfig {
            s3: Some(ObjectStorageS3Config {
                endpoint: Some("http://minio:9000".into()),
                region: Some("us-east-1".into()),
                access_key_id: Some("AKIA".into()),
                secret_access_key: Some("shh".into()),
                secret_access_key_env: None,
                path_style_access: true,
            }),
            tables: vec![
                ObjectStorageTableConfig {
                    name: "a".into(),
                    url: "s3://bucket-one/a.parquet".into(),
                    format: ObjectStorageFormat::Parquet,
                    schema: None,
                },
                ObjectStorageTableConfig {
                    name: "b".into(),
                    url: "s3://bucket-two/b.csv".into(),
                    format: ObjectStorageFormat::Csv,
                    schema: None,
                },
            ],
        };
        let stores = object_storage_s3_stores("files", &cfg).unwrap();
        let urls: Vec<String> = stores.iter().map(|(u, _)| u.to_string()).collect();
        assert_eq!(stores.len(), 2, "one store per distinct bucket");
        assert!(urls.iter().any(|u| u.contains("bucket-one")));
        assert!(urls.iter().any(|u| u.contains("bucket-two")));
    }

    #[test]
    fn object_storage_s3_stores_empty_without_s3_tables() {
        // No s3:// tables ⇒ no stores, even if an [s3] block is present.
        let cfg = ObjectStorageCatalogConfig {
            s3: None,
            tables: vec![ObjectStorageTableConfig {
                name: "local".into(),
                url: "file:///data/x.parquet".into(),
                format: ObjectStorageFormat::Parquet,
                schema: None,
            }],
        };
        assert!(object_storage_s3_stores("files", &cfg).unwrap().is_empty());
    }

    #[tokio::test]
    async fn object_storage_infers_csv_and_json_from_local_files() {
        //  slice 1a: CSV + JSON local files build a queryable
        // catalog with schemas inferred at boot. Proves format wiring +
        // per-format file extensions end to end.
        let dir = tempfile::tempdir().unwrap();
        let csv = dir.path().join("people.csv");
        std::fs::write(&csv, "id,name\n1,alice\n2,bob\n").unwrap();
        let json = dir.path().join("events.json");
        std::fs::write(
            &json,
            "{\"id\":1,\"kind\":\"click\"}\n{\"id\":2,\"kind\":\"view\"}\n",
        )
        .unwrap();

        let to_url = |p: &std::path::Path| format!("file://{}", p.display());
        let cfg = ObjectStorageCatalogConfig {
            s3: None,
            tables: vec![
                ObjectStorageTableConfig {
                    name: "people".into(),
                    url: to_url(&csv),
                    format: ObjectStorageFormat::Csv,
                    schema: None,
                },
                ObjectStorageTableConfig {
                    name: "events".into(),
                    url: to_url(&json),
                    format: ObjectStorageFormat::Json,
                    schema: None,
                },
            ],
        };

        let catalog = build_object_storage_catalog("files", &cfg)
            .await
            .expect("csv + json catalog builds");
        let schema = catalog.schema("public").expect("public schema present");
        let mut tables = schema.table_names();
        tables.sort();
        assert_eq!(tables, vec!["events".to_string(), "people".to_string()]);
    }

    #[tokio::test]
    async fn object_storage_rejects_empty_tables_with_typed_error() {
        // An empty catalog isn't useful — surfaces a config
        // error rather than register an unreachable name.
        let cfg = ObjectStorageCatalogConfig {
            s3: None,
            tables: vec![],
        };
        let err = build_object_storage_catalog("files", &cfg)
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("no `tables` declared") || msg.contains("at least one"),
            "expected empty-tables error message; got:\n{msg}"
        );
    }

    /// Round-trip a `[catalogs.mysql_demo]` entry of `kind = "mysql"`.
    /// Pins the JSON shape of the `dsn_env` form, the `Debug`
    /// redaction, and the `Mysql` variant being chosen by the
    /// `kind` discriminator.
    #[test]
    fn mysql_catalog_config_round_trips_through_json() {
        let json = serde_json::json!({
            "host": "0.0.0.0",
            "port": 5432,
            "batch_size": 8192,
            "partitions": 4,
            "default_catalog": "dataglot",
            "default_schema": "public",
            "catalogs": {
                "mysql_demo": {
                    "kind": "mysql",
                    "dsn_env": "DEMO_MYSQL_DSN"
                }
            }
        });
        let cfg: ServerConfig = serde_json::from_value(json).unwrap();
        let entry = cfg
            .catalogs
            .get("mysql_demo")
            .expect("mysql_demo catalog present");
        match entry {
            CatalogConfig::Mysql(my) => {
                assert_eq!(my.dsn_env.as_deref(), Some("DEMO_MYSQL_DSN"));
                assert!(my.dsn.is_none());
            }
            other => panic!("expected Mysql variant, got {other:?}"),
        }
    }

    /// CLAUDE.md rule 12: the literal DSN never appears in `Debug`
    /// output for [`MysqlCatalogConfig`]. The env-var **name** is
    /// kept visible since it is not itself a secret.
    #[test]
    fn debug_redacts_mysql_dsn() {
        let cfg = MysqlCatalogConfig {
            dsn: Some("mysql://root:topsecret@localhost:3306/db".to_string()),
            dsn_env: None,
            ..Default::default()
        };
        let s = format!("{cfg:?}");
        assert!(!s.contains("topsecret"), "{s}");
        assert!(!s.contains("root"), "{s}");
        assert!(s.contains("<redacted>"), "{s}");
    }

    /// MySQL `[catalogs.*]` TLS fields deserialize; omitted ⇒ plaintext.
    #[test]
    fn mysql_tls_config_deserializes() {
        let cfg: MysqlCatalogConfig = serde_json::from_str(
            r#"{"dsn_env":"MY","tls":"require","tls_ca_file":"/certs/ca.pem","tls_accept_invalid_certs":true}"#,
        )
        .unwrap();
        assert_eq!(cfg.tls, SourceTlsMode::Require);
        assert_eq!(
            cfg.tls_ca_file.as_deref(),
            Some(std::path::Path::new("/certs/ca.pem"))
        );
        assert!(cfg.tls_accept_invalid_certs);

        let plain: MysqlCatalogConfig = serde_json::from_str(r#"{"dsn_env":"MY"}"#).unwrap();
        assert_eq!(plain.tls, SourceTlsMode::Disable);
        assert!(plain.tls_ca_file.is_none());
    }

    /// MySQL TLS knobs without `tls = "require"` fail fast. Bails before
    /// any connection attempt.
    #[tokio::test]
    async fn mysql_tls_knobs_without_require_error() {
        let cfg = CatalogConfig::Mysql(MysqlCatalogConfig {
            dsn: Some("mysql://u@localhost:3306/x".into()),
            tls: SourceTlsMode::Disable,
            tls_accept_invalid_certs: true,
            ..Default::default()
        });
        let err = build_one_connector("my", &cfg)
            .await
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("tls_ca_file") || err.contains("accept_invalid"),
            "{err}"
        );
        assert!(err.contains("disable"), "{err}");
    }

    /// `Debug` for `CatalogConfig::Mysql` must also redact — pin
    /// the full nested path.
    #[test]
    fn debug_redacts_mysql_dsn_via_catalog_config() {
        let cfg = CatalogConfig::Mysql(MysqlCatalogConfig {
            dsn: Some("mysql://root:topsecret@db:3306/prod".to_string()),
            dsn_env: None,
            ..Default::default()
        });
        let s = format!("{cfg:?}");
        assert!(!s.contains("topsecret"), "{s}");
        assert!(s.contains("Mysql"), "{s}");
        assert!(s.contains("<redacted>"), "{s}");
    }

    /// `resolve_mysql_dsn_with_env` mirrors the Postgres helper —
    /// success path and failure path. Pin both so a future
    /// refactor that diverges the two surfaces gets caught.
    #[test]
    fn mysql_dsn_env_resolution_at_runtime() {
        let cfg = MysqlCatalogConfig {
            dsn: None,
            dsn_env: Some("DEMO_MYSQL_DSN".to_string()),
            ..Default::default()
        };

        // Failure path: lookup returns NotPresent.
        let missing: EnvLookup = &|_: &str| Err(std::env::VarError::NotPresent);
        let err =
            resolve_mysql_dsn_with_env("mysql_demo", &cfg, missing).expect_err("missing env var");
        let msg = format!("{err:#}");
        assert!(msg.contains("mysql_demo"), "{msg}");
        assert!(msg.contains("DEMO_MYSQL_DSN"), "{msg}");

        // Success path: lookup returns the DSN.
        let present: EnvLookup = &|name: &str| {
            assert_eq!(name, "DEMO_MYSQL_DSN");
            Ok("mysql://root@db.example/prod".to_string())
        };
        let dsn = resolve_mysql_dsn_with_env("mysql_demo", &cfg, present).unwrap();
        assert_eq!(dsn, "mysql://root@db.example/prod");
    }

    /// `resolve_mysql_dsn` rejects a config that sets both `dsn`
    /// and `dsn_env`. Caught at boot, before any connection is
    /// opened. The error must mention the catalog name but never
    /// the DSN value.
    #[test]
    fn resolve_mysql_dsn_rejects_both_set() {
        let cfg = MysqlCatalogConfig {
            dsn: Some("mysql://root@db/db".to_string()),
            dsn_env: Some("DEMO_MYSQL_DSN".to_string()),
            ..Default::default()
        };
        let err = resolve_mysql_dsn("mysql_demo", &cfg).expect_err("ambiguous config");
        let msg = format!("{err:#}");
        assert!(msg.contains("mysql_demo"), "{msg}");
        assert!(!msg.contains("mysql://root@db/db"), "{msg}");
    }

    /// `resolve_mysql_dsn` rejects a config that sets neither
    /// `dsn` nor `dsn_env`.
    #[test]
    fn resolve_mysql_dsn_rejects_both_unset() {
        let cfg = MysqlCatalogConfig {
            dsn: None,
            dsn_env: None,
            ..Default::default()
        };
        let err = resolve_mysql_dsn("mysql_demo", &cfg).expect_err("empty config");
        let msg = format!("{err:#}");
        assert!(msg.contains("mysql_demo"), "{msg}");
    }

    // ──────────────────────────────────────────────────────────
    // Snowflake catalog config — Debug redaction + password
    // resolver + build_one_connector typed-error path.
    // ──────────────────────────────────────────────────────────

    fn sample_snowflake_cfg() -> SnowflakeCatalogConfig {
        SnowflakeCatalogConfig {
            account: "acme-corp.us-east-1".to_string(),
            warehouse: "COMPUTE_WH".to_string(),
            database: "ANALYTICS".to_string(),
            user: "DATAGLOT_SVC".to_string(),
            password: Some("super-secret".to_string()),
            password_env: None,
            private_key_env: None,
            schema: Some("PUBLIC".to_string()),
            role: Some("READER".to_string()),
        }
    }

    /// Debug must never leak the password, the user (service-
    /// account name is org-structure-adjacent), or the role.
    /// Operational targeting (account/warehouse/database/schema)
    /// stays visible.
    #[test]
    fn debug_redacts_snowflake_credentials() {
        let cfg = sample_snowflake_cfg();
        let s = format!("{cfg:?}");
        assert!(!s.contains("super-secret"), "password leaked: {s}");
        assert!(!s.contains("DATAGLOT_SVC"), "user leaked: {s}");
        assert!(!s.contains("READER"), "role leaked: {s}");
        assert!(s.contains("<redacted>"), "redaction marker missing: {s}");
        // Non-secret fields visible — these are what operators
        // need to identify which catalog a log line refers to.
        assert!(s.contains("acme-corp.us-east-1"), "{s}");
        assert!(s.contains("COMPUTE_WH"), "{s}");
        assert!(s.contains("ANALYTICS"), "{s}");
    }

    /// Same redaction must hold through the `CatalogConfig::Snowflake`
    /// outer wrapper — pin the full nested path.
    #[test]
    fn debug_redacts_snowflake_via_catalog_config() {
        let cfg = CatalogConfig::Snowflake(sample_snowflake_cfg());
        let s = format!("{cfg:?}");
        assert!(!s.contains("super-secret"), "{s}");
        assert!(!s.contains("DATAGLOT_SVC"), "{s}");
        assert!(s.contains("Snowflake"), "{s}");
        assert!(s.contains("<redacted>"), "{s}");
    }

    /// `password_env` shows the variable NAME (not a credential)
    /// when no literal password is set.
    #[test]
    fn debug_shows_password_env_name_not_value() {
        let cfg = SnowflakeCatalogConfig {
            password: None,
            password_env: Some("DEMO_SF_PASSWORD".to_string()),
            ..sample_snowflake_cfg()
        };
        let s = format!("{cfg:?}");
        assert!(
            s.contains("DEMO_SF_PASSWORD"),
            "env var name should be visible: {s}"
        );
        assert!(
            s.contains("<unset>"),
            "password literal should show <unset>: {s}"
        );
    }

    /// `resolve_snowflake_password` success + failure paths via the
    /// injected env-var lookup. Mirrors `mysql_dsn_env_resolution_at_runtime`.
    #[test]
    fn snowflake_password_env_resolution_at_runtime() {
        let cfg = SnowflakeCatalogConfig {
            password: None,
            password_env: Some("DEMO_SF_PASSWORD".to_string()),
            ..sample_snowflake_cfg()
        };

        // Failure path: env var not set.
        let missing: EnvLookup = &|_: &str| Err(std::env::VarError::NotPresent);
        let err = resolve_snowflake_password_with_env("sf_demo", &cfg, missing)
            .expect_err("missing env var should fail");
        let msg = format!("{err:#}");
        assert!(msg.contains("sf_demo"), "{msg}");
        assert!(msg.contains("DEMO_SF_PASSWORD"), "{msg}");

        // Success path: env var set.
        let present: EnvLookup = &|name: &str| {
            assert_eq!(name, "DEMO_SF_PASSWORD");
            Ok("secret-from-env".to_string())
        };
        let pw = resolve_snowflake_password_with_env("sf_demo", &cfg, present).unwrap();
        assert_eq!(pw, "secret-from-env");
    }

    ///  key-pair path: when `private_key_env` names a populated
    /// var, `resolve_snowflake_config` carries the PEM and no password is
    /// required; an empty key falls back to the password path.
    #[test]
    fn snowflake_key_pair_env_resolution_at_runtime() {
        // Key-pair only — no password/password_env at all.
        let cfg = SnowflakeCatalogConfig {
            password: None,
            password_env: None,
            private_key_env: Some("DEMO_SF_KEY".to_string()),
            ..sample_snowflake_cfg()
        };
        let with_key: EnvLookup = &|name: &str| {
            assert_eq!(name, "DEMO_SF_KEY");
            Ok("-----BEGIN PRIVATE KEY-----\nMII...\n-----END PRIVATE KEY-----".to_string())
        };
        let resolved = resolve_snowflake_config_with_env("sf_demo", &cfg, with_key)
            .expect("key-pair config resolves without a password");
        assert!(
            resolved
                .private_key_pem
                .as_deref()
                .is_some_and(|k| k.contains("BEGIN PRIVATE KEY")),
            "private key should be carried",
        );
        assert!(resolved.password.is_empty(), "no password expected");

        // Empty key env ⇒ fall back to password requirement (and fail when
        // neither is present).
        let empty_key: EnvLookup = &|_: &str| Ok(String::new());
        let err = resolve_snowflake_config_with_env("sf_demo", &cfg, empty_key)
            .expect_err("empty key + no password must fail");
        assert!(format!("{err:#}").contains("sf_demo"));
    }

    /// `resolve_snowflake_password` rejects setting both `password`
    /// and `password_env`. Caught at boot; error mentions the catalog
    /// name and the conflicting fields, never the password value.
    #[test]
    fn resolve_snowflake_password_rejects_both_set() {
        let cfg = SnowflakeCatalogConfig {
            password: Some("literal-pwd".to_string()),
            password_env: Some("DEMO_SF_PASSWORD".to_string()),
            ..sample_snowflake_cfg()
        };
        let err = resolve_snowflake_password("sf_demo", &cfg).expect_err("ambiguous config");
        let msg = format!("{err:#}");
        assert!(msg.contains("sf_demo"), "{msg}");
        assert!(
            !msg.contains("literal-pwd"),
            "password leaked in error: {msg}"
        );
    }

    /// `resolve_snowflake_password` rejects neither `password` nor
    /// `password_env` set.
    #[test]
    fn resolve_snowflake_password_rejects_both_unset() {
        let cfg = SnowflakeCatalogConfig {
            password: None,
            password_env: None,
            ..sample_snowflake_cfg()
        };
        let err = resolve_snowflake_password("sf_demo", &cfg).expect_err("empty config");
        let msg = format!("{err:#}");
        assert!(msg.contains("sf_demo"), "{msg}");
    }

    /// `resolve_snowflake_password` happy path with a literal
    /// `password` field returns it verbatim.
    #[test]
    fn resolve_snowflake_password_literal_passthrough() {
        let cfg = sample_snowflake_cfg();
        let pw = resolve_snowflake_password("sf_demo", &cfg).expect("literal resolves");
        assert_eq!(pw, "super-secret");
    }

    fn sample_adbc_cfg() -> AdbcCatalogConfig {
        AdbcCatalogConfig {
            driver_path: "/usr/local/lib/libadbc_driver_postgresql.so".to_string(),
            driver_entrypoint: None,
            uri: Some("postgresql://svc:adbc-super-secret@db.internal/prod".to_string()),
            username: Some("svc_dataglot".to_string()),
            password_env: Some("WAREHOUSE_PASSWORD".to_string()),
            driver_options: Some("token=opaque-secret-token;sslmode=require".to_string()),
            catalog: None,
            schema: None,
            dialect: "postgresql".to_string(),
            connection_pool_size: 4,
            connection_pool_min_idle: 1,
        }
    }

    /// Pin the on-disk serde shape: a `kind = "adbc"` config object
    /// deserializes into `CatalogConfig::Adbc` with the spec defaults
    /// applied to the pool sizing.
    #[test]
    fn catalog_config_adbc_serde_roundtrip() {
        let json = r#"{
            "kind": "adbc",
            "driver_path": "/usr/local/lib/libadbc_driver_postgresql.so",
            "uri": "postgresql://db.internal/prod",
            "username": "svc_dataglot",
            "password_env": "WAREHOUSE_PASSWORD",
            "dialect": "postgresql"
        }"#;
        let cfg: CatalogConfig = serde_json::from_str(json).expect("kind=adbc parses");
        let CatalogConfig::Adbc(a) = &cfg else {
            panic!("expected CatalogConfig::Adbc, got {cfg:?}");
        };
        assert_eq!(a.dialect, "postgresql");
        assert_eq!(a.password_env.as_deref(), Some("WAREHOUSE_PASSWORD"));
        // Spec defaults applied when the fields are omitted.
        assert_eq!(a.connection_pool_size, 4);
        assert_eq!(a.connection_pool_min_idle, 1);

        let reser = serde_json::to_string(&cfg).expect("serializes");
        let back: CatalogConfig = serde_json::from_str(&reser).expect("re-parses");
        assert!(matches!(back, CatalogConfig::Adbc(_)));
    }

    /// Debug must never leak the URI (may embed userinfo), the
    /// username, or driver-option values; the driver path, dialect,
    /// and the password env-var *name* stay visible for operator
    /// identification (CLAUDE.md rule 12).
    #[test]
    fn debug_redacts_adbc_credentials() {
        let cfg = CatalogConfig::Adbc(sample_adbc_cfg());
        let s = format!("{cfg:?}");
        assert!(!s.contains("adbc-super-secret"), "uri secret leaked: {s}");
        assert!(
            !s.contains("opaque-secret-token"),
            "option value leaked: {s}"
        );
        assert!(!s.contains("svc_dataglot"), "username leaked: {s}");
        assert!(s.contains("<redacted>"), "redaction marker missing: {s}");
        assert!(s.contains("libadbc_driver_postgresql.so"), "{s}");
        assert!(s.contains("WAREHOUSE_PASSWORD"), "{s}");
        assert!(s.contains("postgresql"), "{s}");
    }

    /// On a server built **without** `--features adbc`, a
    /// `kind = "adbc"` catalog must be rejected at boot with an
    /// actionable error naming the catalog and the missing feature —
    /// never silently dropped. (Compiled only in the feature-off
    /// configuration; the feature-on path is exercised by the
    /// federation crate's driver-gated `adbc_integration.rs`.)
    #[cfg(not(feature = "adbc"))]
    #[tokio::test]
    async fn build_one_connector_adbc_rejected_without_feature() {
        let cfg = CatalogConfig::Adbc(sample_adbc_cfg());
        let err = build_one_connector("byo", &cfg)
            .await
            .expect_err("adbc catalog must be rejected without the feature");
        let msg = format!("{err:#}");
        assert!(msg.contains("byo"), "error names the catalog: {msg}");
        assert!(msg.contains("adbc"), "error names the feature: {msg}");
        assert!(!msg.contains("adbc-super-secret"), "secret leaked: {msg}");
    }

    /// With the feature compiled in, an invalid `dialect` string is a
    /// boot error naming the supported set — before any driver IO.
    #[cfg(feature = "adbc")]
    #[tokio::test]
    async fn build_one_connector_adbc_rejects_unknown_dialect() {
        let mut a = sample_adbc_cfg();
        a.dialect = "vertica".to_string();
        let err = build_one_connector("byo", &CatalogConfig::Adbc(a))
            .await
            .expect_err("unknown dialect must fail at boot");
        let msg = format!("{err:#}");
        assert!(msg.contains("byo"), "error names the catalog: {msg}");
        assert!(
            msg.contains("duckdb"),
            "error names the supported set: {msg}"
        );
        assert!(!msg.contains("adbc-super-secret"), "secret leaked: {msg}");
    }

    fn sample_oracle_cfg() -> OracleCatalogConfig {
        OracleCatalogConfig {
            dsn: "//db.internal:1521/ORCLPDB1".to_string(),
            user: "DATAGLOT_SVC".to_string(),
            password: Some("super-secret".to_string()),
            password_env: None,
            schema: Some("SALES".to_string()),
            driver: None,
        }
    }

    /// Debug must never leak the password or the user (service-
    /// account name is org-structure-adjacent). The DSN (credential-
    /// free) and schema stay visible for operator identification.
    #[test]
    fn debug_redacts_oracle_credentials() {
        let cfg = sample_oracle_cfg();
        let s = format!("{cfg:?}");
        assert!(!s.contains("super-secret"), "password leaked: {s}");
        assert!(!s.contains("DATAGLOT_SVC"), "user leaked: {s}");
        assert!(s.contains("<redacted>"), "redaction marker missing: {s}");
        assert!(s.contains("//db.internal:1521/ORCLPDB1"), "{s}");
        assert!(s.contains("SALES"), "{s}");
    }

    /// Same redaction must hold through the `CatalogConfig::Oracle`
    /// outer wrapper.
    #[test]
    fn debug_redacts_oracle_via_catalog_config() {
        let cfg = CatalogConfig::Oracle(sample_oracle_cfg());
        let s = format!("{cfg:?}");
        assert!(!s.contains("super-secret"), "{s}");
        assert!(!s.contains("DATAGLOT_SVC"), "{s}");
        assert!(s.contains("Oracle"), "{s}");
        assert!(s.contains("<redacted>"), "{s}");
    }

    /// `resolve_oracle_password` success + failure paths via the
    /// injected env-var lookup.
    #[test]
    fn oracle_password_env_resolution_at_runtime() {
        let cfg = OracleCatalogConfig {
            password: None,
            password_env: Some("EXADATA_PASSWORD".to_string()),
            ..sample_oracle_cfg()
        };

        // Failure path: env var not set.
        let missing: EnvLookup = &|_: &str| Err(std::env::VarError::NotPresent);
        let err = resolve_oracle_password_with_env("exadata", &cfg, missing)
            .expect_err("missing env var should fail");
        let msg = format!("{err:#}");
        assert!(msg.contains("exadata"), "{msg}");
        assert!(msg.contains("EXADATA_PASSWORD"), "{msg}");

        // Success path: env var set.
        let present: EnvLookup = &|name: &str| {
            assert_eq!(name, "EXADATA_PASSWORD");
            Ok("secret-from-env".to_string())
        };
        let pw = resolve_oracle_password_with_env("exadata", &cfg, present).unwrap();
        assert_eq!(pw, "secret-from-env");
    }

    /// `resolve_oracle_password` rejects both `password` and
    /// `password_env`; error names the catalog, never the password.
    #[test]
    fn resolve_oracle_password_rejects_both_set() {
        let cfg = OracleCatalogConfig {
            password: Some("literal-pwd".to_string()),
            password_env: Some("EXADATA_PASSWORD".to_string()),
            ..sample_oracle_cfg()
        };
        let err = resolve_oracle_password("exadata", &cfg).expect_err("ambiguous config");
        let msg = format!("{err:#}");
        assert!(msg.contains("exadata"), "{msg}");
        assert!(
            !msg.contains("literal-pwd"),
            "password leaked in error: {msg}"
        );
    }

    /// `resolve_oracle_password` rejects neither field set.
    #[test]
    fn resolve_oracle_password_rejects_both_unset() {
        let cfg = OracleCatalogConfig {
            password: None,
            password_env: None,
            ..sample_oracle_cfg()
        };
        let err = resolve_oracle_password("exadata", &cfg).expect_err("empty config");
        let msg = format!("{err:#}");
        assert!(msg.contains("exadata"), "{msg}");
    }

    /// `resolve_oracle_password` literal passthrough.
    #[test]
    fn resolve_oracle_password_literal_passthrough() {
        let cfg = sample_oracle_cfg();
        let pw = resolve_oracle_password("exadata", &cfg).expect("literal resolves");
        assert_eq!(pw, "super-secret");
    }

    /// On a server built **without** `--features oracle`, a
    /// `kind = "oracle"` catalog must be rejected at boot with an
    /// actionable error that names the catalog and the missing
    /// feature — never silently dropped. (Compiled only in the
    /// feature-off configuration; the feature-on path is exercised by
    /// the credentials/Docker-gated `oracle_integration.rs`.)
    #[cfg(not(feature = "oracle"))]
    #[tokio::test]
    async fn build_one_connector_oracle_rejected_without_feature() {
        let cfg = CatalogConfig::Oracle(sample_oracle_cfg());
        let err = build_one_connector("exadata", &cfg)
            .await
            .expect_err("oracle catalog must be rejected without the feature");
        let msg = format!("{err:#}");
        assert!(msg.contains("exadata"), "error names the catalog: {msg}");
        assert!(msg.contains("oracle"), "error names the feature: {msg}");
        // CLAUDE.md rule 12: the password never surfaces in the error.
        assert!(!msg.contains("super-secret"), "password leaked: {msg}");
    }

    /// `build_one_connector` for a Snowflake catalog now goes
    /// through `SnowflakeConnector::as_catalog_provider`, which
    /// performs eager schema discovery against the configured
    /// account's `INFORMATION_SCHEMA`. The test config points at
    /// a syntactic-only account (`acme-corp.us-east-1`) with a
    /// fake password — auth fires on the first remote query, so
    /// the call fails with a connection / auth error rather than
    /// succeeding.
    ///
    /// We pin three properties of the failure mode:
    ///   1. it fails (no silent no-op)
    ///   2. the error message mentions the catalog name (so
    ///      operators see which catalog booted unhealthy)
    ///   3. the password never appears in the error chain
    ///      (CLAUDE.md rule 12)
    ///
    /// The previous test asserted a typed "not yet wired" error
    /// when `as_catalog_provider` was still a stub on the
    /// federation side; that follow-up has now landed, so the
    /// assertion shifts to the failure-on-bad-creds shape.
    /// Successful boot against a real Snowflake account is
    /// exercised by the credentials-gated integration tests in
    /// `dataglot-tests/tests/integration/snowflake_federation.rs`.
    #[tokio::test]
    async fn build_one_connector_snowflake_fails_with_fake_credentials() {
        let cfg = CatalogConfig::Snowflake(sample_snowflake_cfg());
        let err = build_one_connector("sf_demo", &cfg)
            .await
            .expect_err("fake credentials cannot reach a real account");
        let msg = format!("{err:#}");
        assert!(msg.contains("sf_demo"), "catalog name missing: {msg}");
        assert!(
            !msg.contains("super-secret"),
            "password leaked into error: {msg}"
        );
    }

    /// JSON parse of a complete Snowflake catalog block, then
    /// round-trip back through `Debug` to check redaction holds
    /// through the full deserialize → display path.
    #[test]
    fn snowflake_catalog_json_roundtrip_with_redaction() {
        let json = r#"{
            "kind": "snowflake",
            "account": "acme-corp.us-east-1",
            "warehouse": "COMPUTE_WH",
            "database": "ANALYTICS",
            "user": "DATAGLOT_SVC",
            "password": "from-the-json",
            "schema": "PUBLIC",
            "role": "READER"
        }"#;
        let cfg: CatalogConfig = serde_json::from_str(json).unwrap();
        let CatalogConfig::Snowflake(sf) = &cfg else {
            panic!("expected Snowflake variant");
        };
        assert_eq!(sf.account, "acme-corp.us-east-1");
        assert_eq!(sf.warehouse, "COMPUTE_WH");
        assert_eq!(sf.user, "DATAGLOT_SVC");
        assert_eq!(sf.password.as_deref(), Some("from-the-json"));

        // Debug must redact.
        let s = format!("{cfg:?}");
        assert!(!s.contains("from-the-json"), "{s}");
        assert!(!s.contains("DATAGLOT_SVC"), "{s}");
    }

    #[test]
    fn parses_sap_s4hana_catalog_and_redacts() {
        let json = r#"{
            "kind": "sap_s4hana",
            "service_url": "https://s4h.example.com/sap/opu/odata/sap/API_BUSINESS_PARTNER",
            "auth": { "kind": "basic", "user": "DATAGLOT_SVC", "password": "from-the-json" },
            "sap_client": "100"
        }"#;
        let cfg: CatalogConfig = serde_json::from_str(json).unwrap();
        let CatalogConfig::SapS4hana(sap) = &cfg else {
            panic!("expected SapS4hana variant, got {cfg:?}");
        };
        assert_eq!(
            sap.service_url,
            "https://s4h.example.com/sap/opu/odata/sap/API_BUSINESS_PARTNER"
        );
        assert_eq!(sap.sap_client.as_deref(), Some("100"));
        assert!(sap.sap_language.is_none());
        let OdataAuthConfig::Basic { user, password, .. } = &sap.auth else {
            panic!("expected Basic auth");
        };
        assert_eq!(user, "DATAGLOT_SVC");
        assert_eq!(password.as_deref(), Some("from-the-json"));

        // Debug (both inner + via CatalogConfig wrapper) must redact.
        let s = format!("{cfg:?}");
        assert!(!s.contains("from-the-json"), "password leaked: {s}");
        assert!(s.contains("<redacted>"), "redaction marker missing: {s}");
        assert!(s.contains("SapS4hana"), "{s}");

        // Classification: non-SQL (no federation strip), stable kind label,
        // credential-free endpoint hint.
        assert!(!cfg.requires_federation());
        assert_eq!(catalog_kind(&cfg), "sap_s4hana");
        let CatalogBinding::LiveConnector(b) = cfg.binding() else {
            panic!("expected LiveConnector binding");
        };
        assert_eq!(b.kind, LiveConnectorKind::Odata);
        assert!(b.endpoint_hint.contains("s4h.example.com"));
        assert!(!b.endpoint_hint.contains("from-the-json"));
    }

    #[test]
    fn parses_odata_catalog_with_bearer_env() {
        let json = r#"{
            "kind": "odata",
            "service_url": "https://host/odata/v2/Svc",
            "auth": { "kind": "bearer", "token_env": "ODATA_TOKEN" }
        }"#;
        let cfg: CatalogConfig = serde_json::from_str(json).unwrap();
        let CatalogConfig::Odata(od) = &cfg else {
            panic!("expected Odata variant");
        };
        assert_eq!(od.service_url, "https://host/odata/v2/Svc");
        let OdataAuthConfig::Bearer { token_env, .. } = &od.auth else {
            panic!("expected Bearer auth");
        };
        assert_eq!(token_env.as_deref(), Some("ODATA_TOKEN"));
        assert_eq!(catalog_kind(&cfg), "odata");
    }

    #[test]
    fn resolve_odata_auth_basic_env_and_errors() {
        // Env-var resolution success.
        let auth = OdataAuthConfig::Basic {
            user: "svc".into(),
            password: None,
            password_env: Some("ODATA_PW".into()),
        };
        let present: EnvLookup = &|n: &str| {
            assert_eq!(n, "ODATA_PW");
            Ok("secret-from-env".to_string())
        };
        let resolved = resolve_odata_auth_with_env("od", &auth, present).expect("resolves");
        match resolved {
            dataglot_federation::odata::OdataAuth::Basic { user, password } => {
                assert_eq!(user, "svc");
                assert_eq!(password, "secret-from-env");
            }
            dataglot_federation::odata::OdataAuth::Bearer { .. } => panic!("expected Basic"),
        }

        // Missing env var → error naming the catalog + var, no secret.
        let missing: EnvLookup = &|_: &str| Err(std::env::VarError::NotPresent);
        let err = resolve_odata_auth_with_env("od", &auth, missing).expect_err("missing env");
        let msg = format!("{err:#}");
        assert!(msg.contains("od") && msg.contains("ODATA_PW"), "{msg}");
    }

    #[test]
    fn resolve_odata_auth_rejects_both_and_neither() {
        let both = OdataAuthConfig::Basic {
            user: "svc".into(),
            password: Some("literal-pw".into()),
            password_env: Some("ODATA_PW".into()),
        };
        let env: EnvLookup = &|_: &str| Ok("x".to_string());
        let err = resolve_odata_auth_with_env("od", &both, env).expect_err("ambiguous");
        let msg = format!("{err:#}");
        assert!(msg.contains("od"), "{msg}");
        assert!(!msg.contains("literal-pw"), "password leaked: {msg}");

        let neither = OdataAuthConfig::Bearer {
            token: None,
            token_env: None,
        };
        let err = resolve_odata_auth_with_env("od", &neither, env).expect_err("empty");
        assert!(format!("{err:#}").contains("od"));
    }

    #[test]
    fn rest_catalog_parses_binds_and_classifies() {
        let json = r#"{
            "kind": "rest",
            "schema": "public",
            "auth": { "kind": "bearer", "token_env": "SF_TOKEN" },
            "tables": [
                {
                    "name": "account",
                    "url": "https://acme.my.salesforce.com/services/data/v58.0/query?q=SELECT+Id",
                    "records_path": "records",
                    "pagination": { "kind": "next_link", "next_path": "nextRecordsUrl" },
                    "columns": [
                        { "name": "Id", "type": "utf8" },
                        { "name": "AnnualRevenue", "type": "float64", "nullable": true }
                    ]
                }
            ]
        }"#;
        let cfg: CatalogConfig = serde_json::from_str(json).expect("parse rest config");
        assert_eq!(catalog_kind(&cfg), "rest");
        // REST is a direct TableProvider — not a federated SQL source.
        assert!(!cfg.requires_federation());

        let CatalogConfig::Rest(r) = &cfg else {
            panic!("expected Rest variant");
        };
        assert_eq!(r.schema, "public");
        assert_eq!(r.tables.len(), 1);
        assert_eq!(r.tables[0].columns.len(), 2);
        assert_eq!(r.tables[0].records_path, "records");

        match cfg.binding() {
            CatalogBinding::LiveConnector(lc) => {
                assert_eq!(lc.kind, LiveConnectorKind::Rest);
                // Endpoint hint is the (credential-free) first table URL.
                assert!(
                    lc.endpoint_hint.contains("acme.my.salesforce.com"),
                    "{lc:?}"
                );
            }
            other => panic!("expected LiveConnector binding, got {other:?}"),
        }
    }

    #[test]
    fn rest_pushdown_and_http2_parse_with_defaults() {
        // Explicit `http2_prior_knowledge` + a pushdown map with an explicit
        // param name.
        let json = r#"{
            "kind": "rest",
            "http2_prior_knowledge": true,
            "tables": [{
                "name": "sleep",
                "url": "http://127.0.0.1:8080/sleep",
                "records_path": "records",
                "pushdown": [{ "column": "time", "param": "t" }],
                "columns": [{ "name": "time", "type": "int64" }]
            }]
        }"#;
        let cfg: CatalogConfig = serde_json::from_str(json).expect("parse");
        let CatalogConfig::Rest(r) = &cfg else {
            panic!("expected Rest variant");
        };
        assert!(r.http2_prior_knowledge);
        assert_eq!(r.tables[0].pushdown.len(), 1);
        assert_eq!(r.tables[0].pushdown[0].column, "time");
        assert_eq!(r.tables[0].pushdown[0].param.as_deref(), Some("t"));

        // Both new fields default: http2 off, `param` omitted (builder falls
        // back to the column name).
        let json = r#"{
            "kind": "rest",
            "tables": [{
                "name": "sleep",
                "url": "http://127.0.0.1:8080/sleep",
                "pushdown": [{ "column": "time" }],
                "columns": [{ "name": "time", "type": "int64" }]
            }]
        }"#;
        let cfg: CatalogConfig = serde_json::from_str(json).expect("parse defaults");
        let CatalogConfig::Rest(r) = &cfg else {
            panic!("expected Rest variant");
        };
        assert!(!r.http2_prior_knowledge);
        assert_eq!(r.tables[0].pushdown[0].param, None);
    }

    #[test]
    fn resolve_rest_auth_variants_and_errors() {
        use dataglot_federation::rest::RestAuth;

        // Bearer via env.
        let bearer = RestAuthConfig::Bearer {
            token: None,
            token_env: Some("SF_TOKEN".into()),
        };
        let present: EnvLookup = &|n: &str| {
            assert_eq!(n, "SF_TOKEN");
            Ok("tok-from-env".to_string())
        };
        match resolve_rest_auth_with_env("restcat", &bearer, present).expect("resolves") {
            RestAuth::Bearer { token } => assert_eq!(token, "tok-from-env"),
            other => panic!("expected Bearer, got {other:?}"),
        }

        // Header (API key) via env.
        let header = RestAuthConfig::Header {
            name: "x-api-key".into(),
            value: None,
            value_env: Some("API_KEY".into()),
        };
        let key_present: EnvLookup = &|n: &str| {
            assert_eq!(n, "API_KEY");
            Ok("ak-from-env".to_string())
        };
        match resolve_rest_auth_with_env("restcat", &header, key_present).expect("resolves") {
            RestAuth::Header { name, value } => {
                assert_eq!(name, "x-api-key");
                assert_eq!(value, "ak-from-env");
            }
            other => panic!("expected Header, got {other:?}"),
        }

        // None passes through.
        let env: EnvLookup = &|_: &str| Ok("x".to_string());
        assert!(matches!(
            resolve_rest_auth_with_env("restcat", &RestAuthConfig::None, env).expect("none"),
            RestAuth::None
        ));

        // Both literal + env set → error naming the catalog, no secret leaked.
        let both = RestAuthConfig::Bearer {
            token: Some("literal-tok".into()),
            token_env: Some("SF_TOKEN".into()),
        };
        let err = resolve_rest_auth_with_env("restcat", &both, env).expect_err("ambiguous");
        let msg = format!("{err:#}");
        assert!(msg.contains("restcat"), "{msg}");
        assert!(!msg.contains("literal-tok"), "token leaked: {msg}");
    }

    #[test]
    fn rest_column_type_maps_and_rejects() {
        use datafusion::arrow::datatypes::DataType;
        assert_eq!(rest_column_type("t", "c", "utf8").unwrap(), DataType::Utf8);
        assert_eq!(
            rest_column_type("t", "c", "INT64").unwrap(),
            DataType::Int64
        ); // case-insensitive
        assert_eq!(
            rest_column_type("t", "c", "boolean").unwrap(),
            DataType::Boolean
        );
        assert_eq!(
            rest_column_type("t", "c", "double").unwrap(),
            DataType::Float64
        );
        let err = rest_column_type("account", "payload", "blob").expect_err("unsupported");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("account") && msg.contains("payload") && msg.contains("blob"),
            "{msg}"
        );
    }

    #[tokio::test]
    async fn build_rest_catalog_rejects_empty_and_exposes_tables() {
        // No tables → boot error naming the catalog (no network needed).
        let empty = RestCatalogConfig {
            schema: "public".into(),
            auth: RestAuthConfig::None,
            http2_prior_knowledge: false,
            tables: vec![],
        };
        let err = build_rest_catalog("restcat", &empty)
            .await
            .expect_err("empty table list rejected");
        assert!(format!("{err:#}").contains("restcat"));

        // Valid config builds a provider exposing the declared schema + table.
        // Schemas are declared, so this does no network I/O.
        let cfg = RestCatalogConfig {
            schema: "public".into(),
            auth: RestAuthConfig::None,
            http2_prior_knowledge: false,
            tables: vec![RestTableConfig {
                name: "account".into(),
                url: "https://acme.example.com/q".into(),
                records_path: "records".into(),
                pagination: RestPaginationConfig::None,
                pushdown: vec![],
                columns: vec![RestColumnConfig {
                    name: "Id".into(),
                    data_type: "utf8".into(),
                    nullable: true,
                }],
            }],
        };
        let provider = build_rest_catalog("restcat", &cfg).await.expect("builds");
        assert_eq!(provider.schema_names(), vec!["public".to_string()]);
        let schema = provider.schema("public").expect("schema present");
        assert!(schema.table_names().contains(&"account".to_string()));
    }

    #[test]
    fn rest_oauth2_parses_and_resolves() {
        let json = r#"{
            "kind": "rest",
            "auth": {
                "kind": "oauth2",
                "token_url": "https://login.salesforce.com/services/oauth2/token",
                "client_id_env": "SF_CLIENT_ID",
                "client_secret_env": "SF_CLIENT_SECRET",
                "scope": "api"
            },
            "tables": [
                { "name": "account",
                  "url": "https://acme.my.salesforce.com/services/data/v58.0/query?q=SELECT+Id",
                  "records_path": "records",
                  "columns": [ { "name": "Id", "type": "utf8" } ] }
            ]
        }"#;
        let cfg: CatalogConfig = serde_json::from_str(json).expect("parse oauth2 rest config");
        let CatalogConfig::Rest(r) = &cfg else {
            panic!("expected Rest variant");
        };
        assert!(matches!(r.auth, RestAuthConfig::Oauth2 { .. }));

        // Resolve the client id/secret from env; token_url + scope carried through.
        let env: EnvLookup = &|n: &str| match n {
            "SF_CLIENT_ID" => Ok("cid-from-env".to_string()),
            "SF_CLIENT_SECRET" => Ok("csecret-from-env".to_string()),
            other => panic!("unexpected env var {other}"),
        };
        let oauth = resolve_rest_oauth2_with_env("sf", &r.auth, env).expect("resolves");
        assert_eq!(
            oauth.token_url,
            "https://login.salesforce.com/services/oauth2/token"
        );
        assert_eq!(oauth.client_id, "cid-from-env");
        assert_eq!(oauth.client_secret, "csecret-from-env");
        assert_eq!(
            oauth.extra_params,
            vec![("scope".to_string(), "api".to_string())]
        );

        // A RestAuthConfig::Oauth2 Debug never renders the literal secret.
        let with_literal = RestAuthConfig::Oauth2 {
            token_url: "https://x/token".into(),
            client_id: Some("cid".into()),
            client_id_env: None,
            client_secret: Some("literal-secret".into()),
            client_secret_env: None,
            scope: None,
        };
        let printed = format!("{with_literal:?}");
        assert!(
            !printed.contains("literal-secret"),
            "secret leaked: {printed}"
        );
    }

    #[test]
    fn resolve_rest_oauth2_rejects_both_and_neither() {
        let both = RestAuthConfig::Oauth2 {
            token_url: "https://x/token".into(),
            client_id: Some("cid".into()),
            client_id_env: None,
            client_secret: Some("literal-secret".into()),
            client_secret_env: Some("SF_CLIENT_SECRET".into()),
            scope: None,
        };
        let env: EnvLookup = &|_: &str| Ok("x".to_string());
        let err = resolve_rest_oauth2_with_env("sf", &both, env).expect_err("ambiguous secret");
        let msg = format!("{err:#}");
        assert!(msg.contains("sf"), "{msg}");
        assert!(!msg.contains("literal-secret"), "secret leaked: {msg}");
    }

    #[tokio::test]
    async fn build_rest_catalog_with_oauth2_builds() {
        // OAuth2 catalogs build without any network (the token is fetched lazily
        // on first query, not at boot).
        let cfg = RestCatalogConfig {
            schema: "public".into(),
            auth: RestAuthConfig::Oauth2 {
                token_url: "https://login.example.com/services/oauth2/token".into(),
                client_id: Some("cid".into()),
                client_id_env: None,
                client_secret: Some("csecret".into()),
                client_secret_env: None,
                scope: None,
            },
            http2_prior_knowledge: false,
            tables: vec![RestTableConfig {
                name: "account".into(),
                url: "https://acme.example.com/q".into(),
                records_path: "records".into(),
                pagination: RestPaginationConfig::None,
                pushdown: vec![],
                columns: vec![RestColumnConfig {
                    name: "Id".into(),
                    data_type: "utf8".into(),
                    nullable: true,
                }],
            }],
        };
        let provider = build_rest_catalog("sf", &cfg).await.expect("builds");
        assert_eq!(provider.schema_names(), vec!["public".to_string()]);
    }

    #[tokio::test]
    async fn build_rest_catalog_rejects_unknown_pushdown_column() {
        // A pushdown mapping on a column that isn't declared is a config typo —
        // boot should reject it, naming the catalog, table, and column.
        let cfg = RestCatalogConfig {
            schema: "public".into(),
            auth: RestAuthConfig::None,
            http2_prior_knowledge: false,
            tables: vec![RestTableConfig {
                name: "sleep".into(),
                url: "http://127.0.0.1:8080/sleep".into(),
                records_path: String::new(),
                pagination: RestPaginationConfig::None,
                pushdown: vec![RestPushdownParamConfig {
                    column: "nope".into(),
                    param: None,
                }],
                columns: vec![RestColumnConfig {
                    name: "time".into(),
                    data_type: "int64".into(),
                    nullable: true,
                }],
            }],
        };
        let err = build_rest_catalog("api", &cfg)
            .await
            .expect_err("unknown pushdown column rejected");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("api") && msg.contains("sleep") && msg.contains("nope"),
            "{msg}"
        );
    }

    #[test]
    fn parses_maintenance_compaction_block() {
        let json = serde_json::json!({
            "host": "0.0.0.0", "port": 5432, "batch_size": 8192, "partitions": 4,
            "default_catalog": "dataglot", "default_schema": "public",
            "maintenance": {
                "compaction": [
                    { "warehouse": "warehouse", "namespace": "sales", "table": "orders", "compact_every": "6h" }
                ]
            }
        });
        let cfg: ServerConfig = serde_json::from_value(json).expect("parses");
        assert_eq!(cfg.maintenance.compaction.len(), 1);
        let c = &cfg.maintenance.compaction[0];
        assert_eq!(c.warehouse, "warehouse");
        assert_eq!(c.namespace, "sales");
        assert_eq!(c.table, "orders");
        assert_eq!(c.compact_every, "6h");
    }

    #[test]
    fn maintenance_defaults_to_empty_when_absent() {
        let json = serde_json::json!({
            "host": "0.0.0.0", "port": 5432, "batch_size": 8192, "partitions": 4,
            "default_catalog": "dataglot", "default_schema": "public"
        });
        let cfg: ServerConfig = serde_json::from_value(json).expect("parses");
        assert!(cfg.maintenance.compaction.is_empty());
        assert!(cfg.maintenance.orphan_cleanup.is_empty());
    }

    #[test]
    fn parses_maintenance_orphan_cleanup_block() {
        let json = serde_json::json!({
            "host": "0.0.0.0", "port": 5432, "batch_size": 8192, "partitions": 4,
            "default_catalog": "dataglot", "default_schema": "public",
            "maintenance": {
                "orphan_cleanup": [
                    { "warehouse": "warehouse", "namespace": "sales", "sweep_every": "1h", "min_age": "6h" }
                ]
            }
        });
        let cfg: ServerConfig = serde_json::from_value(json).expect("parses");
        assert_eq!(cfg.maintenance.orphan_cleanup.len(), 1);
        let o = &cfg.maintenance.orphan_cleanup[0];
        assert_eq!(o.warehouse, "warehouse");
        assert_eq!(o.namespace, "sales");
        assert_eq!(o.sweep_every, "1h");
        assert_eq!(o.min_age, "6h");
    }

    #[test]
    fn parse_refresh_interval_handles_units_and_errors() {
        // Compare via as_secs() to sidestep pedantic Duration-unit lints.
        assert_eq!(parse_refresh_interval("30s").unwrap().as_secs(), 30);
        assert_eq!(parse_refresh_interval("15m").unwrap().as_secs(), 900);
        assert_eq!(parse_refresh_interval("2h").unwrap().as_secs(), 7200);
        assert_eq!(parse_refresh_interval("1d").unwrap().as_secs(), 86_400);
        assert_eq!(parse_refresh_interval("  45m ").unwrap().as_secs(), 2700);
        // Errors: empty, missing/unknown unit, non-numeric, zero.
        assert!(parse_refresh_interval("").is_err());
        assert!(parse_refresh_interval("10").is_err());
        assert!(parse_refresh_interval("10y").is_err());
        assert!(parse_refresh_interval("abcm").is_err());
        assert!(parse_refresh_interval("0s").is_err());
    }

    #[test]
    fn materialization_backing_defaults_to_live_and_parses_snake_case() {
        assert_eq!(
            MaterializationBacking::default(),
            MaterializationBacking::Live
        );
        let m: MaterializationBacking = serde_json::from_str("\"materialized\"").unwrap();
        assert_eq!(m, MaterializationBacking::Materialized);
        // A product config omitting backing/materialization defaults to Live.
        let p: DerivedProductConfig =
            serde_json::from_str(r#"{ "name": "v", "sql": "SELECT 1" }"#).unwrap();
        assert_eq!(p.backing, MaterializationBacking::Live);
        assert!(p.materialization.is_none());
    }

    // --- parse_sql_predicate / collect_identifiers ---------------------
    //
    // `parse_sql_predicate` builds its synthetic DFSchema *only* from the
    // identifiers `collect_identifiers` harvests from the AST, then feeds
    // the SQL to `parse_sql_expr` against that schema. So a successful
    // parse is a proof that every column reference in the predicate was
    // harvested — if an arm of `collect_identifiers` missed an
    // identifier, the synthetic schema would lack it and `parse_sql_expr`
    // would fail with "No field named …". Each case below drives one AST
    // arm; `is_ok()` is the assertion that the arm collected its operands.
    // These predicate forms are exactly what an operator can write in a
    // `[[row_filters]]` `sql = "…"` entry, so this is a config-surface
    // regression guard, not just line coverage.

    /// Parse `sql` as a predicate expression and return the identifier
    /// set `collect_identifiers` harvests from it. Lets the compound-
    /// identifier arm be asserted precisely — `parse_sql_predicate`'s
    /// end-to-end path can't, because a qualified ref (`t.col`) won't
    /// resolve against the unqualified synthetic schema even though the
    /// column name was harvested.
    fn harvest(sql: &str) -> std::collections::BTreeSet<String> {
        use datafusion::sql::sqlparser::dialect::PostgreSqlDialect;
        use datafusion::sql::sqlparser::parser::Parser;
        let ast = Parser::new(&PostgreSqlDialect {})
            .try_with_sql(sql)
            .unwrap()
            .parse_expr()
            .unwrap();
        let mut out = std::collections::BTreeSet::new();
        collect_identifiers(&ast, &mut out);
        out
    }

    #[test]
    fn collect_identifiers_compound_takes_last_segment() {
        // `t.col` contributes its last segment (the column name) only —
        // the synthetic schema is unqualified.
        assert_eq!(
            harvest("orders.customer_id = 42"),
            ["customer_id".to_string()].into_iter().collect()
        );
    }

    #[test]
    fn collect_identifiers_gathers_every_referenced_column() {
        // A compound predicate mixing several arms harvests each distinct
        // column exactly once (BTreeSet dedups and orders).
        assert_eq!(
            harvest("age BETWEEN lo AND hi AND status IN ('a') AND name LIKE 'x%'"),
            ["age", "hi", "lo", "name", "status"]
                .into_iter()
                .map(String::from)
                .collect()
        );
    }

    #[test]
    fn parse_sql_predicate_cast_recurses_into_operand() {
        // The documented int-coercion workaround: `CAST(id AS BIGINT)`
        // must recurse so the inner `age` reaches the synthetic schema.
        assert!(parse_sql_predicate("CAST(age AS BIGINT) > 18").is_ok());
    }

    #[test]
    fn parse_sql_predicate_unary_and_nested_recurse() {
        // `NOT (deleted)` = UnaryOp wrapping Nested wrapping Identifier —
        // exercises both the UnaryOp/Cast arm and the Nested arm.
        assert!(parse_sql_predicate("NOT (deleted)").is_ok());
    }

    #[test]
    fn parse_sql_predicate_like_and_ilike_harvest_operands() {
        assert!(parse_sql_predicate("name LIKE 'A%'").is_ok());
        assert!(parse_sql_predicate("name ILIKE 'a%'").is_ok());
    }

    #[test]
    fn parse_sql_predicate_is_null_and_boolean_predicates() {
        for sql in [
            "email IS NULL",
            "email IS NOT NULL",
            "active IS TRUE",
            "active IS NOT TRUE",
            "active IS FALSE",
            "active IS NOT FALSE",
        ] {
            assert!(
                parse_sql_predicate(sql).is_ok(),
                "predicate should harvest its operand: {sql}"
            );
        }
    }

    #[test]
    fn parse_sql_predicate_between_harvests_all_three_operands() {
        // Between recurses expr + low + high; all three must resolve.
        assert!(parse_sql_predicate("age BETWEEN 18 AND 65").is_ok());
    }

    #[test]
    fn parse_sql_predicate_in_list_harvests_expr_and_items() {
        assert!(parse_sql_predicate("status IN ('active', 'pending')").is_ok());
    }

    #[test]
    fn parse_sql_predicate_rejects_malformed_sql() {
        // An unterminated string literal fails tokenization before any
        // identifier harvest — the parse/context error path.
        assert!(parse_sql_predicate("'unterminated").is_err());
        // A syntactically invalid expression fails `parse_expr`.
        assert!(parse_sql_predicate("age >").is_err());
    }

    #[test]
    fn parse_sql_predicate_harvests_identifiers_inside_functions_and_case() {
        // The `Visit`-based harvester recurses the whole AST, so columns
        // nested inside function calls and CASE branches resolve — the
        // former MVP limitation (function args not recursed) is lifted.
        assert!(
            parse_sql_predicate("lower(name) = 'x'").is_ok(),
            "column inside a function call must be harvested"
        );
        assert!(
            parse_sql_predicate("CASE WHEN region = 'EU' THEN salary ELSE 'x' END = salary")
                .is_ok(),
            "columns inside CASE branches must be harvested"
        );
    }

    // ---- custom mask expression (Ranger MASK_CUSTOM parity) ----

    #[test]
    fn mask_expr_config_round_trips() {
        let m: MaskConfig = serde_json::from_str(
            r#"{"table":"emp","column":"salary","mask_expr":"CASE WHEN region = 'EU' THEN salary ELSE '***' END"}"#,
        )
        .unwrap();
        assert_eq!(
            m.mask_expr.as_deref(),
            Some("CASE WHEN region = 'EU' THEN salary ELSE '***' END")
        );
        assert!(m.mask_type.is_none());
    }

    #[test]
    fn build_mask_rules_rejects_mask_expr_with_mask_type() {
        let masks = vec![MaskConfig {
            table: "emp".into(),
            column: "salary".into(),
            mask_literal: String::new(),
            mask_type: Some(MaskTypeConfig::Redact),
            mask_expr: Some("salary".into()),
            priority: 0,
            groups: None,
        }];
        let err = build_mask_rules(&masks).expect_err("mask_expr + mask_type must be rejected");
        assert!(
            err.to_string().contains("exactly one"),
            "error should name the exactly-one rule: {err}"
        );
    }

    /// The wedge: a **conditional / entitlement-driven mask** — the class
    /// the fixed `mask_type` vocabulary can't express. `mask_expr` reveals
    /// `salary` only for entitled (EU) rows and masks everyone else, by
    /// referencing a *sibling* column in a `CASE`. Proves the custom
    /// expression parses from config, installs through the standard
    /// `PolicyOptimizerRule`, and evaluates row-by-row at plan time.
    #[tokio::test]
    async fn custom_mask_expr_applies_conditional_mask() {
        use datafusion::arrow::array::{RecordBatch, StringArray};
        use datafusion::arrow::datatypes::{DataType, Field, Schema};
        use datafusion::datasource::MemTable;
        use datafusion::optimizer::{OptimizerContext, OptimizerRule};
        use datafusion::prelude::SessionContext;
        use dataglot_policy::{ColumnMaskingEnforcer, PolicyOptimizerRule};
        use std::sync::Arc;

        let schema = Arc::new(Schema::new(vec![
            Field::new("region", DataType::Utf8, false),
            Field::new("salary", DataType::Utf8, false),
        ]));
        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(StringArray::from(vec!["EU", "US"])),
                Arc::new(StringArray::from(vec!["100k", "200k"])),
            ],
        )
        .unwrap();
        let ctx = SessionContext::new();
        ctx.register_table(
            "emp",
            Arc::new(MemTable::try_new(schema, vec![vec![batch]]).unwrap()),
        )
        .unwrap();

        let rules = build_mask_rules(&[MaskConfig {
            table: "emp".into(),
            column: "salary".into(),
            mask_literal: String::new(),
            mask_type: None,
            mask_expr: Some("CASE WHEN region = 'EU' THEN salary ELSE '***' END".into()),
            priority: 0,
            groups: None,
        }])
        .expect("build custom-expr mask");
        let enforcer = Arc::new(ColumnMaskingEnforcer::new(rules).expect("enforcer"));

        let plan = ctx
            .sql("SELECT region, salary FROM emp ORDER BY region")
            .await
            .unwrap()
            .into_unoptimized_plan();
        let plan = PolicyOptimizerRule::new(enforcer)
            .rewrite(plan, &OptimizerContext::new())
            .unwrap()
            .data;
        let batches = ctx
            .execute_logical_plan(plan)
            .await
            .unwrap()
            .collect()
            .await
            .unwrap();

        let mut got = Vec::new();
        for b in &batches {
            let region = b.column(0).as_any().downcast_ref::<StringArray>().unwrap();
            let salary = b.column(1).as_any().downcast_ref::<StringArray>().unwrap();
            for i in 0..b.num_rows() {
                got.push((region.value(i).to_string(), salary.value(i).to_string()));
            }
        }
        assert_eq!(
            got,
            vec![
                ("EU".to_string(), "100k".to_string()), // entitled → real value
                ("US".to_string(), "***".to_string()),  // not entitled → masked
            ],
            "custom mask_expr must reveal salary only for the entitled (EU) row"
        );
    }
}

#[cfg(test)]
mod env_catalog_tests {
    use std::collections::HashMap;

    use super::{parse_env_catalogs, CatalogConfig};

    fn vars(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    /// `DATAGLOT_CATALOG_<NAME>` entries are parsed, names lowercased, and
    /// unrelated env vars ignored; output is sorted by name.
    #[test]
    fn parses_lowercases_and_filters() {
        let got = parse_env_catalogs(vars(&[
            (
                "DATAGLOT_CATALOG_PG",
                r#"{"kind":"postgres","dsn_env":"PG_DSN"}"#,
            ),
            (
                "DATAGLOT_CATALOG_MY_ORDERS",
                r#"{"kind":"mysql","dsn_env":"MY_DSN"}"#,
            ),
            ("DATAGLOT_HOST", "127.0.0.1"),
            ("UNRELATED", "x"),
        ]))
        .expect("parse");
        let names: Vec<_> = got.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(
            names,
            vec!["my_orders", "pg"],
            "sorted + lowercased + filtered"
        );
        // The `pg` entry (second after sort) deserialized to the postgres variant.
        assert!(matches!(got[1].1, CatalogConfig::Postgres(_)));
    }

    #[test]
    fn invalid_json_is_an_error() {
        assert!(parse_env_catalogs(vars(&[("DATAGLOT_CATALOG_PG", "not json")])).is_err());
    }

    #[test]
    fn empty_name_is_an_error() {
        assert!(parse_env_catalogs(vars(&[(
            "DATAGLOT_CATALOG_",
            r#"{"kind":"postgres","dsn_env":"X"}"#,
        )]))
        .is_err());
    }

    /// Mirrors `load()`'s merge: an env catalog overrides a same-named file
    /// catalog (env is applied after the file into the same map).
    #[test]
    fn env_catalog_overrides_same_name() {
        let mut catalogs: HashMap<String, CatalogConfig> = HashMap::new();
        for (n, c) in parse_env_catalogs(vars(&[(
            "DATAGLOT_CATALOG_PG",
            r#"{"kind":"postgres","dsn_env":"A"}"#,
        )]))
        .unwrap()
        {
            catalogs.insert(n, c);
        }
        for (n, c) in parse_env_catalogs(vars(&[(
            "DATAGLOT_CATALOG_PG",
            r#"{"kind":"mysql","dsn_env":"B"}"#,
        )]))
        .unwrap()
        {
            catalogs.insert(n, c);
        }
        assert!(
            matches!(catalogs["pg"], CatalogConfig::Mysql(_)),
            "env wins over file"
        );
    }
}

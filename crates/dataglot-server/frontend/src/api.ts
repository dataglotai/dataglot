// REST client for the engine dashboard. Everything is a plain fetch
// against dataglot-server's axum routes: /api/queries (slice
// 1) and /api/cluster (slice 2). No auth here — the endpoints are
// loopback-only, same posture as /metrics.

/** One remote pushdown's stats — mirrors `PushdownStat` in
 *  dataglot-core/pushdown_stats.rs. The dialect SQL sent to one
 *  source with its rows/timing; the per-branch data of the query profile. */
export interface Pushdown {
  /** Catalog (source) name the sub-query was pushed to. */
  source: string;
  /** Connector kind: "snowflake" | "postgres" | "mysql" | "oracle" | "adbc". */
  kind: string;
  /** Dialect-rendered SQL sent to the remote source. */
  sql: string;
  rows: number;
  batches: number;
  elapsed_ms: number;
  /** "completed" | "failed" | "partial" (note: distinct from the query-level
   *  outcome strings success/error/cancelled). */
  outcome: "completed" | "failed" | "partial";
}

/** One in-flight query — mirrors `ActiveQueryView` in query_registry.rs. */
export interface ActiveQuery {
  run_id: string;
  sql: string;
  elapsed_ms: number;
  state: string;
  /** Distinct source catalogs the query federates across (slice 5b).
   *  Empty unless the server has `capture_query_sources` enabled. */
  sources: string[];
  /** pg wire username that submitted the query; null when unknown. */
  user: string | null;
  /** Resolved tenant/org of the submitting session; null when unknown. */
  org: string | null;
  /** Per-source pushdown stats captured so far; empty unless
   *  `capture_query_sources` is on, and may be partial while running. */
  pushdowns: Pushdown[];
}

/** One finished query — mirrors `CompletedQueryView` in query_registry.rs. */
export interface CompletedQuery {
  run_id: string;
  sql: string;
  elapsed_ms: number;
  /** "success" | "error" | "cancelled". */
  outcome: string;
  /** Redacted failure message for error/cancelled outcomes; absent on success. */
  error?: string;
  sources: string[];
  /** pg wire username that submitted the query; null when unknown. */
  user: string | null;
  /** Resolved tenant/org of the submitting session; null when unknown. */
  org: string | null;
  /** Per-source pushdown stats for this query; empty unless
   *  `capture_query_sources` was on. The data behind the query profile. */
  pushdowns: Pushdown[];
}

/** `GET /api/queries/{run_id}` detail — the live entry if still running, else
 *  the finished entry from history. Superset of the two views: `state` is set
 *  while running, `outcome`/`error` once finished. */
export interface QueryDetail {
  run_id: string;
  sql: string;
  elapsed_ms: number;
  sources: string[];
  user: string | null;
  org: string | null;
  pushdowns: Pushdown[];
  /** "running" while in-flight. */
  state?: string;
  /** "success" | "error" | "cancelled" once finished. */
  outcome?: string;
  error?: string;
}

/** One connected pgwire session — mirrors `SessionInfoView` in
 *  session_registry.rs. The "who is connected" detail behind the aggregate
 *  active-connection count. */
export interface Session {
  session_id: string;
  /** pg wire startup username; null when unknown (e.g. trust mode). */
  user: string | null;
  /** Resolved tenant/org — the governance-relevant column; null when unknown. */
  org: string | null;
  /** Client socket address (ip:port). */
  peer: string;
  /** Connect time as Unix epoch milliseconds. */
  connected_at_ms: number;
}

/** Raw Ballista JSON (shape owned upstream) — read defensively. */
export type Json = Record<string, unknown>;

/** Combined cluster poll — mirrors `ClusterSummary` in cluster.rs. */
export interface ClusterSummary {
  available: boolean;
  note?: string;
  scheduler?: Json;
  executors: Json[];
  /** Most-recent jobs (server caps this; see `jobs_total` for the real count). */
  jobs: Json[];
  /** Total jobs the scheduler holds, before the server-side cap. */
  jobs_total?: number;
  /** Non-terminal jobs across all jobs (accurate even when `jobs` is capped). */
  running_jobs?: number;
}

async function getJson<T>(url: string, signal?: AbortSignal): Promise<T> {
  const res = await fetch(url, { signal, headers: { accept: "application/json" } });
  if (!res.ok) throw new Error(`${url} → ${res.status}`);
  return (await res.json()) as T;
}

export const getQueries = (signal?: AbortSignal) =>
  getJson<ActiveQuery[]>("/api/queries", signal);

export const getQueriesHistory = (signal?: AbortSignal) =>
  getJson<CompletedQuery[]>("/api/queries/history", signal);

/** One query's detail incl. its per-source pushdown profile.
 *  Resolves the live entry if still running, else the finished entry from
 *  the bounded history ring; rejects (404) if unknown / aged out. */
export const getQuery = (runId: string, signal?: AbortSignal) =>
  getJson<QueryDetail>(`/api/queries/${encodeURIComponent(runId)}`, signal);

export const getSessions = (signal?: AbortSignal) =>
  getJson<Session[]>("/api/sessions", signal);

export const getCluster = (signal?: AbortSignal) =>
  getJson<ClusterSummary>("/api/cluster", signal);

// ── Control Plane — read-only view of the meta store's objects ──

export interface ControlPlaneCatalog {
  name: string;
  kind: string;
  endpoint: string;
}
export interface ControlPlaneUser {
  name: string;
  is_superuser: boolean;
}
export interface ControlPlaneRole {
  name: string;
  members: string[];
}
export interface ControlPlaneGrant {
  grantee_kind: string;
  grantee: string;
  privilege: string;
  object: string;
}
export interface ControlPlanePolicy {
  name: string;
  kind: string;
}
export interface ControlPlaneProduct {
  name: string;
  catalog: string | null;
  schema: string | null;
}
/** Mirrors the server's `ControlPlaneView`. Secrets are names only; users
 *  carry no password hash — the endpoint never serializes either (rule 12). */
export interface ControlPlaneView {
  org: string;
  catalogs: ControlPlaneCatalog[];
  secrets: string[];
  users: ControlPlaneUser[];
  roles: ControlPlaneRole[];
  grants: ControlPlaneGrant[];
  policies: ControlPlanePolicy[];
  derived_products: ControlPlaneProduct[];
}
/** `GET /api/control-plane`. The route is absent (404) when the server has no
 *  `catalog_service` configured — the tab treats that as "not configured". */
export const getControlPlane = (signal?: AbortSignal) =>
  getJson<ControlPlaneView>("/api/control-plane", signal);

/** Static server metadata for the header — mirrors `ServerInfo`. */
export interface ServerInfo {
  dataglot_version: string;
  datafusion_version: string;
  pgwire_host: string;
  pgwire_port: number;
  dashboard_port?: number;
  execution_mode: string;
  ballista?: {
    scheduler_grpc_port: number;
    rest_api_port?: number;
    external_executors: number;
  };
  security: {
    auth_mode: string;
    ingress_tls: string;
    rate_limiting: boolean;
  };
  governance: {
    authz_mode: string;
    masks: number;
    row_filters: number;
    access_denials: number;
    column_grants: number;
  };
  build: {
    profile: string;
    features: string[];
  };
  limits: ResourceLimits;
}

/** Configured resource ceilings — mirrors `ResourceLimits`. `null` ⇒ unset. */
export interface ResourceLimits {
  max_connections: number | null;
  max_connections_per_ip: number | null;
  max_connections_per_identity: number | null;
  max_new_connections_per_ip_per_minute: number | null;
  memory_limit_bytes: number | null;
}

/** `/api/limits` — ceilings + live usage. Mirrors `ResourceUsageView`. */
export interface ResourceUsageView {
  limits: ResourceLimits;
  active_connections: number;
  busiest_ip_connections: number;
  busiest_identity_connections: number;
  rejected_global: number;
  rejected_per_ip: number;
  rejected_new_conn_rate: number;
  rejected_identity: number;
}

export const getServerInfo = (signal?: AbortSignal) =>
  getJson<ServerInfo>("/api/server", signal);

export const getLimits = (signal?: AbortSignal) =>
  getJson<ResourceUsageView>("/api/limits", signal);

/** Per-stage progress for one job (raw Ballista JSON — an array, or an
 *  object with a `stages` array). Normalize with `asStages`. */
export const getClusterJobStages = (jobId: string, signal?: AbortSignal) =>
  getJson<Json | Json[]>(`/api/cluster/job/${encodeURIComponent(jobId)}/stages`, signal);

/** Normalize the stages payload to a plain array (Ballista returns
 *  either `[...]` or `{ stages: [...] }`). */
export function asStages(raw: Json | Json[] | null): Json[] {
  if (Array.isArray(raw)) return raw as Json[];
  const inner = (raw as Json | null)?.stages;
  return Array.isArray(inner) ? (inner as Json[]) : [];
}

/** One column in the boot-time lineage/mask graph — mirrors
 *  `LineageNode` in lineage_snapshot.rs. */
export interface LineageNode {
  catalog: string;
  schema: string;
  table: string;
  field: string;
  /** "source" | "derived". */
  kind: string;
  /** "configured" (a config mask covers it) | "propagated" (masked only
   *  through lineage) | undefined (unmasked). */
  mask?: string;
}

/** One column-lineage edge — mirrors `LineageEdge` in lineage_snapshot.rs.
 *  `from`/`to` index into `LineageSnapshot.nodes`. */
export interface LineageEdge {
  from: number;
  to: number;
  /** How the target derives from the source, e.g. "identity", "aggregation". */
  transform: string;
}

export interface LineageSnapshot {
  nodes: LineageNode[];
  edges: LineageEdge[];
}

export const getLineage = (signal?: AbortSignal) =>
  getJson<LineageSnapshot>("/lineage", signal);

/** Cached liveness of a connector — mirrors `ConnectorHealth`. Populated by
 *  the background health poller (and on-demand probes); absent until the first
 *  probe completes or when polling is disabled. */
export interface ConnectorHealth {
  live: boolean;
  latency_ms: number;
  /** When the probe ran, Unix epoch milliseconds. */
  checked_at_ms: number;
  /** Redacted failure reason when !live. */
  error?: string;
}

/** One configured connector — mirrors `ConnectorSummary` in connectors.rs. */
export interface ConnectorSummary {
  name: string;
  /** "postgres" | "mysql" | "warehouse" | "snowflake" | … */
  kind: string;
  /** Registered into the live catalog set at boot (false ⇒ configured but
   *  skipped, e.g. unreachable under --tolerate-unreachable-catalogs). */
  registered: boolean;
  /** Most-recent liveness from the background poller / an on-demand probe.
   *  Undefined until the first probe completes or when polling is disabled. */
  health?: ConnectorHealth;
}

/** On-demand liveness result — mirrors `ProbeResult` in connectors.rs. */
export interface ProbeResult {
  name: string;
  kind: string;
  live: boolean;
  latency_ms: number;
  /** Redacted failure reason when !live. */
  error?: string;
}

/** A supported connector family with nothing configured — mirrors
 *  `AvailableConnector`. The "available to wire up" tier. */
export interface AvailableConnector {
  name: string;
  /** Cargo feature / build note. */
  feature: string;
  note: string;
}

/** Combined `/api/connectors` view — mirrors `ConnectorsView`. */
export interface ConnectorsView {
  configured: ConnectorSummary[];
  available: AvailableConnector[];
}

export const getConnectors = (signal?: AbortSignal) =>
  getJson<ConnectorsView>("/api/connectors", signal);

/** One materialized product's refresh status — mirrors `MaterializationStatus`
 *  in materialization_registry.rs. */
export interface MaterializationStatus {
  product: string;
  /** Fully-qualified target, "warehouse.namespace.table". */
  target: string;
  interval_secs: number;
  /** "pending" | "running" | "success" | "error". */
  state: string;
  last_started_at_ms?: number;
  last_finished_at_ms?: number;
  last_duration_ms?: number;
  last_rows?: number;
  last_data_files?: number;
  /** Redacted error from the most-recent failed refresh. */
  last_error?: string;
  /** Approximate next run (last_finished + interval), epoch ms. */
  next_run_at_ms?: number;
  runs: number;
  failures: number;
}

export const getMaterialization = (signal?: AbortSignal) =>
  getJson<MaterializationStatus[]>("/api/materialization", signal);

/** One maintenance job's status — mirrors `MaintenanceStatus` in
 *  maintenance_registry.rs. */
export interface MaintenanceStatus {
  job: string;
  /** "compaction" | "orphan_cleanup". */
  kind: string;
  /** "warehouse.namespace.table" (compaction) or "warehouse.namespace". */
  target: string;
  interval_secs: number;
  /** "pending" | "running" | "success" | "error". */
  state: string;
  last_started_at_ms?: number;
  last_finished_at_ms?: number;
  last_duration_ms?: number;
  /** Rows preserved through the last compaction (compaction only). */
  last_rows?: number;
  /** Data files after the last compaction (compaction only). */
  last_data_files?: number;
  /** Stale tables dropped by the last sweep (orphan cleanup only). */
  last_swept?: number;
  last_error?: string;
  next_run_at_ms?: number;
  runs: number;
  failures: number;
}

export const getMaintenance = (signal?: AbortSignal) =>
  getJson<MaintenanceStatus[]>("/api/maintenance", signal);

/** On-demand liveness probe for one connector (POST). Rejects on transport
 *  failure; the caller renders the thrown message as "down". */
export async function probeConnector(name: string): Promise<ProbeResult> {
  const res = await fetch(`/api/connectors/${encodeURIComponent(name)}/probe`, {
    method: "POST",
  });
  if (!res.ok) throw new Error(`probe ${name} → ${res.status}`);
  return (await res.json()) as ProbeResult;
}

/** Best-effort kill of a running query. Resolves true
 *  when the server signalled a cancellable query (HTTP 200). */
export async function cancelQuery(runId: string): Promise<boolean> {
  const res = await fetch(`/api/queries/${encodeURIComponent(runId)}/cancel`, {
    method: "POST",
  });
  return res.ok;
}

// ---- defensive readers for the upstream Ballista JSON --------------------

/** Read the first present key from an object (optionally nested), as a
 *  value of unknown type. Ballista's executor/job JSON nests some fields
 *  under `metadata` / `specification` and varies key names across
 *  versions, so every access tries a few candidates. */
export function field(obj: Json | undefined, ...keys: string[]): unknown {
  if (!obj) return undefined;
  for (const k of keys) {
    if (obj[k] !== undefined && obj[k] !== null) return obj[k];
  }
  // Try one level of nesting through common containers.
  for (const container of ["metadata", "specification"]) {
    const inner = obj[container];
    if (inner && typeof inner === "object") {
      const v = field(inner as Json, ...keys);
      if (v !== undefined) return v;
    }
  }
  return undefined;
}

export const str = (v: unknown): string =>
  v === undefined || v === null ? "" : String(v);

export const num = (v: unknown): number => {
  const n = typeof v === "number" ? v : Number(v);
  return Number.isFinite(n) ? n : 0;
};

/** A job is "active" unless it's in a terminal state. */
export const isTerminal = (status: string): boolean =>
  /success|completed|failed|error|cancel/i.test(status);

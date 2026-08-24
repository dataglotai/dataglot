import { useCallback, useEffect, useState } from "react";

import {
  type ActiveQuery,
  type ClusterSummary,
  getCluster,
  getQueries,
  getServerInfo,
  getSessions,
  type ServerInfo,
  type Session,
} from "./api";
import { Cluster } from "./Cluster";
import { Connectors } from "./Connectors";
import { ControlPlane } from "./ControlPlane";
import { Governance } from "./Governance";
import { History } from "./History";
import { MaintenancePanel } from "./Maintenance";
import { Materialization } from "./Materialization";
import { Queries } from "./Queries";
import { QueryProfile } from "./QueryProfile";
import { Sessions } from "./Sessions";

type Tab =
  | "cluster"
  | "queries"
  | "sessions"
  | "connectors"
  | "materialization"
  | "governance"
  | "controlplane"
  | "history";
const POLL_MS = 2000;

export function App() {
  const [tab, setTab] = useState<Tab>("cluster");
  const [cluster, setCluster] = useState<ClusterSummary | null>(null);
  const [queries, setQueries] = useState<ActiveQuery[]>([]);
  const [sessions, setSessions] = useState<Session[]>([]);
  const [online, setOnline] = useState(true);
  const [server, setServer] = useState<ServerInfo | null>(null);
  // run_id whose per-source pushdown profile overlay is open.
  const [profileRunId, setProfileRunId] = useState<string | null>(null);

  // Static server metadata (version + ports) — fetch once for the header.
  useEffect(() => {
    const ctrl = new AbortController();
    getServerInfo(ctrl.signal)
      .then(setServer)
      .catch(() => {});
    return () => ctrl.abort();
  }, []);

  const poll = useCallback(async (signal: AbortSignal) => {
    try {
      // All endpoints in parallel; one failing shouldn't blank the others.
      const [c, q, s] = await Promise.allSettled([
        getCluster(signal),
        getQueries(signal),
        getSessions(signal),
      ]);
      if (c.status === "fulfilled") setCluster(c.value);
      if (q.status === "fulfilled") setQueries(q.value);
      if (s.status === "fulfilled") setSessions(s.value);
      setOnline(
        c.status === "fulfilled" || q.status === "fulfilled" || s.status === "fulfilled",
      );
    } catch {
      setOnline(false);
    }
  }, []);

  useEffect(() => {
    let stop = false;
    const ctrl = new AbortController();
    const tick = async () => {
      if (stop) return;
      await poll(ctrl.signal);
    };
    void tick();
    const h = setInterval(() => void tick(), POLL_MS);
    return () => {
      stop = true;
      ctrl.abort();
      clearInterval(h);
    };
  }, [poll]);

  return (
    <>
      <div className="bar">
        <span className="brand">
          dataglot <span className="dim">· operations</span>
        </span>
        {server && (
          <span className="meta">
            v{server.dataglot_version} · pgwire :{server.pgwire_port}
            {server.dashboard_port ? ` · ui :${server.dashboard_port}` : ""} ·{" "}
            {server.execution_mode}
            {server.ballista
              ? ` (${server.ballista.external_executors || 1} exec` +
                (server.ballista.scheduler_grpc_port
                  ? `, grpc :${server.ballista.scheduler_grpc_port}`
                  : "") +
                ")"
              : ""}{" "}
            · df {server.datafusion_version}
          </span>
        )}
        {server && (
          <span className="meta posture" title="Security & governance posture">
            auth{" "}
            <b className={server.security.auth_mode === "trust" ? "warn" : "ok"}>
              {server.security.auth_mode}
            </b>{" "}
            · tls{" "}
            <b className={server.security.ingress_tls === "off" ? "warn" : "ok"}>
              {server.security.ingress_tls}
            </b>{" "}
            · authz{" "}
            <b
              className={
                server.governance.authz_mode === "open" ? "warn" : "ok"
              }
            >
              {server.governance.authz_mode}
            </b>
            {server.security.rate_limiting ? " · rate-limited" : ""}
          </span>
        )}
        <span className="status">
          <span className={`dot ${online ? "ok" : "off"}`} />
          {online ? "live" : "offline"}
        </span>
      </div>
      <div className="tabs">
        <button
          className={`tab ${tab === "cluster" ? "active" : ""}`}
          onClick={() => setTab("cluster")}
        >
          Cluster
        </button>
        <button
          className={`tab ${tab === "queries" ? "active" : ""}`}
          onClick={() => setTab("queries")}
        >
          Running queries{queries.length ? ` (${queries.length})` : ""}
        </button>
        <button
          className={`tab ${tab === "sessions" ? "active" : ""}`}
          onClick={() => setTab("sessions")}
        >
          Sessions{sessions.length ? ` (${sessions.length})` : ""}
        </button>
        <button
          className={`tab ${tab === "connectors" ? "active" : ""}`}
          onClick={() => setTab("connectors")}
        >
          Connectors
        </button>
        <button
          className={`tab ${tab === "materialization" ? "active" : ""}`}
          onClick={() => setTab("materialization")}
        >
          Materialization
        </button>
        <button
          className={`tab ${tab === "governance" ? "active" : ""}`}
          onClick={() => setTab("governance")}
        >
          Governance
        </button>
        <button
          className={`tab ${tab === "controlplane" ? "active" : ""}`}
          onClick={() => setTab("controlplane")}
        >
          Control Plane
        </button>
        <button
          className={`tab ${tab === "history" ? "active" : ""}`}
          onClick={() => setTab("history")}
        >
          History
        </button>
      </div>
      <div className="wrap">
        {tab === "cluster" && (
          <Cluster cluster={cluster} server={server} runningCount={queries.length} />
        )}
        {tab === "queries" && <Queries queries={queries} onSelect={setProfileRunId} />}
        {tab === "sessions" && <Sessions sessions={sessions} />}
        {tab === "connectors" && <Connectors />}
        {tab === "materialization" && (
          <>
            <Materialization />
            <MaintenancePanel />
          </>
        )}
        {tab === "governance" && <Governance server={server} />}
        {tab === "controlplane" && <ControlPlane />}
        {tab === "history" && <History onSelect={setProfileRunId} />}
      </div>
      {profileRunId && (
        <QueryProfile runId={profileRunId} onClose={() => setProfileRunId(null)} />
      )}
    </>
  );
}

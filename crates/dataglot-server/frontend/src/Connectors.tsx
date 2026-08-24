import { useEffect, useState } from "react";

import {
  type AvailableConnector,
  type ConnectorHealth,
  type ConnectorSummary,
  getConnectors,
  type ProbeResult,
  probeConnector,
} from "./api";

/** Per-connector liveness state driven by the on-demand "Check now" probe. */
type Liveness =
  | { state: "idle" }
  | { state: "checking" }
  | { state: "done"; result: ProbeResult }
  | { state: "error"; message: string };

/** How often the configured/health view is re-polled. Health is refreshed
 *  server-side by the background poller; this just pulls the latest snapshot. */
const POLL_MS = 5000;

/** Compact "4s ago" / "2m ago" from an epoch-ms timestamp. */
function ago(ms: number): string {
  const s = Math.max(0, Math.round((Date.now() - ms) / 1000));
  if (s < 60) return `${s}s ago`;
  const m = Math.round(s / 60);
  if (m < 60) return `${m}m ago`;
  return `${Math.round(m / 60)}h ago`;
}

/** The Connectors tab: the sources the server was booted with, which
 *  registered at boot, and which are reachable right now. Liveness comes from
 *  the server's background health poller (refreshed on a timer, surfaced in the
 *  polled snapshot); "Check now" additionally forces a fresh on-demand probe. */
export function Connectors() {
  const [connectors, setConnectors] = useState<ConnectorSummary[] | null>(null);
  const [available, setAvailable] = useState<AvailableConnector[]>([]);
  const [error, setError] = useState(false);
  const [live, setLive] = useState<Record<string, Liveness>>({});

  useEffect(() => {
    let stop = false;
    const ctrl = new AbortController();
    const tick = async () => {
      if (stop) return;
      try {
        const v = await getConnectors(ctrl.signal);
        setConnectors(v.configured);
        setAvailable(v.available);
        setError(false);
      } catch {
        // Keep the last good snapshot; only blank on the very first failure.
        setConnectors((prev) => {
          if (prev === null) setError(true);
          return prev;
        });
      }
    };
    void tick();
    const h = setInterval(() => void tick(), POLL_MS);
    return () => {
      stop = true;
      ctrl.abort();
      clearInterval(h);
    };
  }, []);

  const check = async (name: string) => {
    setLive((p) => ({ ...p, [name]: { state: "checking" } }));
    try {
      const result = await probeConnector(name);
      setLive((p) => ({ ...p, [name]: { state: "done", result } }));
    } catch (e) {
      setLive((p) => ({
        ...p,
        [name]: { state: "error", message: e instanceof Error ? e.message : "probe failed" },
      }));
    }
  };

  const checkAll = () => {
    for (const c of connectors ?? []) void check(c.name);
  };

  if (error) {
    return <p className="err">Could not load connectors (/api/connectors).</p>;
  }
  if (!connectors) {
    return <p className="muted">Loading connectors…</p>;
  }
  if (connectors.length === 0 && available.length === 0) {
    return (
      <div className="empty">
        <p>
          <b>No connectors configured.</b>
        </p>
        <p className="muted">
          Federated sources declared in <span className="mono">[catalogs.*]</span> appear here with
          their kind, whether they registered at boot, and their live reachability.
        </p>
      </div>
    );
  }

  const registeredCount = connectors.filter((c) => c.registered).length;
  // Total known connectors on this server = configured catalogs + the
  // supported families that are available but not wired up.
  const totalCount = connectors.length + available.length;
  // Live now, from the background poller's most-recent reading.
  const liveCount = connectors.filter((c) => c.health?.live).length;
  const downCount = connectors.filter((c) => c.health && !c.health.live).length;

  return (
    <>
      <div className="stat-row">
        <div className="stat">
          <div className="k">Connectors</div>
          <div className="v">{totalCount}</div>
        </div>
        <div className="stat">
          <div className="k">Registered</div>
          <div className="v" style={{ color: registeredCount < totalCount ? "var(--queue)" : undefined }}>
            {registeredCount}
            <small> / {totalCount}</small>
          </div>
        </div>
        <div className="stat">
          <div className="k">Live now</div>
          <div className="v" style={{ color: downCount > 0 ? "var(--fail)" : undefined }}>
            {liveCount}
            <small> / {connectors.length}</small>
          </div>
        </div>
        <div className="stat">
          <div className="k">Available</div>
          <div className="v">{available.length}</div>
        </div>
      </div>

      <div className="section-h" style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <span>Sources ({connectors.length})</span>
        <button className="btn-check" onClick={checkAll}>
          Check all
        </button>
      </div>

      <div className="tbl-wrap">
        <table>
          <thead>
            <tr>
              <th>Catalog</th>
              <th>Kind</th>
              <th>At boot</th>
              <th>Liveness</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {connectors.map((c) => {
              const l = live[c.name] ?? { state: "idle" };
              return (
                <tr key={c.name}>
                  <td className="mono">{c.name}</td>
                  <td>
                    <span className="chip">{c.kind}</span>
                  </td>
                  <td>
                    <span className={`pill ${c.registered ? "idle" : "queue"}`}>
                      {c.registered ? "REGISTERED" : "SKIPPED"}
                    </span>
                  </td>
                  <td>
                    <LivenessCell liveness={l} health={c.health} />
                  </td>
                  <td>
                    <button
                      className="btn-check"
                      disabled={l.state === "checking"}
                      onClick={() => void check(c.name)}
                    >
                      {l.state === "checking" ? "Checking…" : "Check now"}
                    </button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      <p className="caption muted" style={{ marginTop: 10 }}>
        <b>At boot</b>: <span className="mono">REGISTERED</span> came up when the server started;{" "}
        <span className="mono">SKIPPED</span> was configured but unreachable (tolerated).{" "}
        <b>Liveness</b> is refreshed automatically by the server's background health poller;{" "}
        <b>Check now</b> forces an immediate fresh probe. Set{" "}
        <span className="mono">connector_health_interval_secs = 0</span> to disable background
        polling.
      </p>

      {available.length > 0 && (
        <>
          <div className="section-h">Available — not configured ({available.length})</div>
          <div className="exec-strip">
            {available.map((a) => (
              <div className="exec exec-avail" key={a.name} title={a.note}>
                <div className="id">{a.name}</div>
                <div className="m">
                  <span className="chip">{a.feature}</span>
                </div>
                <div className="m avail-note">{a.note}</div>
              </div>
            ))}
          </div>
          <p className="caption muted" style={{ marginTop: 10 }}>
            Connector families Dataglot supports that have no{" "}
            <span className="mono">[catalogs.*]</span> entry on this server — wire one up to
            federate it.
          </p>
        </>
      )}
    </>
  );
}

/** Render one row's liveness. A fresh on-demand probe (operator clicked "Check
 *  now") takes precedence; otherwise fall back to the background poller's
 *  cached reading; otherwise "unknown". */
function LivenessCell({
  liveness,
  health,
}: {
  liveness: Liveness;
  health?: ConnectorHealth;
}) {
  if (liveness.state === "checking") return <span className="muted">checking…</span>;
  if (liveness.state === "error") {
    return (
      <span className="pill fail" title={liveness.message}>
        DOWN
      </span>
    );
  }
  if (liveness.state === "done") {
    const { result } = liveness;
    return (
      <span title={result.error ?? `${result.latency_ms}ms`}>
        <span className={`pill ${result.live ? "run" : "fail"}`}>
          {result.live ? "LIVE" : "DOWN"}
        </span>{" "}
        <span className="mono muted">{result.latency_ms}ms · just now</span>
      </span>
    );
  }
  // idle → background poller's cached reading, if any.
  if (health) {
    return (
      <span title={health.error ?? `${health.latency_ms}ms`}>
        <span className={`pill ${health.live ? "run" : "fail"}`}>
          {health.live ? "LIVE" : "DOWN"}
        </span>{" "}
        <span className="mono muted">
          {health.latency_ms}ms · {ago(health.checked_at_ms)}
        </span>
      </span>
    );
  }
  return <span className="muted">unknown</span>;
}

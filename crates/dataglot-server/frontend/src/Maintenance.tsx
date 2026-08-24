import { useEffect, useState } from "react";

import { getMaintenance, type MaintenanceStatus } from "./api";

const POLL_MS = 5000;

/** Compact "4s ago" / "2m ago" from a past epoch-ms timestamp. */
function ago(ms: number): string {
  const s = Math.max(0, Math.round((Date.now() - ms) / 1000));
  if (s < 60) return `${s}s ago`;
  const m = Math.round(s / 60);
  if (m < 60) return `${m}m ago`;
  return `${Math.round(m / 60)}h ago`;
}

/** Compact "in 12s" / "in 5m" / "due" for a future epoch-ms timestamp. */
function until(ms: number): string {
  const s = Math.round((ms - Date.now()) / 1000);
  if (s <= 0) return "due";
  if (s < 60) return `in ${s}s`;
  const m = Math.round(s / 60);
  if (m < 60) return `in ${m}m`;
  return `in ${Math.round(m / 60)}h`;
}

function statePill(state: string): { cls: string; label: string } {
  switch (state) {
    case "success":
      return { cls: "run", label: "OK" };
    case "error":
      return { cls: "fail", label: "FAILED" };
    case "running":
      return { cls: "queue", label: "RUNNING" };
    default:
      return { cls: "idle", label: "PENDING" };
  }
}

/** Human label for the maintenance kind. */
function kindLabel(kind: string): string {
  return kind === "compaction" ? "compaction" : "orphan cleanup";
}

/** The "what did the last run do" cell, per kind: compaction reports rows +
 *  consolidated files; orphan cleanup reports stale tables dropped. */
function resultCell(r: MaintenanceStatus): string {
  if (r.state === "pending") return "—";
  if (r.kind === "compaction") {
    if (r.last_data_files === undefined) return "—";
    const rows = r.last_rows?.toLocaleString() ?? "?";
    return `${r.last_data_files} files · ${rows} rows`;
  }
  if (r.last_swept === undefined) return "—";
  return r.last_swept === 0 ? "nothing stale" : `${r.last_swept} dropped`;
}

/** Warehouse-maintenance panel: compaction + orphan-cleanup jobs
 *  scheduled against the lakehouse, with each job's freshness, what its last
 *  run did, and roughly when it runs next. Self-fetches on a poll; renders
 *  nothing when no maintenance is configured, so it stays out of the way on
 *  deployments that don't use it. Shown below the materialized products —
 *  both are scheduled warehouse background work. */
export function MaintenancePanel() {
  const [rows, setRows] = useState<MaintenanceStatus[] | null>(null);

  useEffect(() => {
    let stop = false;
    const ctrl = new AbortController();
    const tick = async () => {
      try {
        const v = await getMaintenance(ctrl.signal);
        if (!stop) setRows(v);
      } catch {
        /* transient — keep the last view */
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

  // Nothing configured (or not loaded yet) → render nothing.
  if (!rows || rows.length === 0) return null;

  const failing = rows.filter((r) => r.state === "error").length;

  return (
    <>
      <div className="section-h" style={{ marginTop: 24 }}>
        Warehouse maintenance ({rows.length})
      </div>
      <div className="tbl-wrap">
        <table>
          <thead>
            <tr>
              <th>Job</th>
              <th>Kind</th>
              <th>Target</th>
              <th>State</th>
              <th>Last run</th>
              <th>Result</th>
              <th>Next</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => {
              const pill = statePill(r.state);
              return (
                <tr key={r.job}>
                  <td className="mono">{r.job}</td>
                  <td>
                    <span className="chip">{kindLabel(r.kind)}</span>
                  </td>
                  <td className="mono muted">{r.target}</td>
                  <td>
                    <span
                      className={`pill ${pill.cls}`}
                      title={r.state === "error" ? r.last_error : undefined}
                    >
                      {pill.label}
                    </span>
                  </td>
                  <td className="mono muted">
                    {r.last_finished_at_ms === undefined ? "never" : ago(r.last_finished_at_ms)}
                    {r.last_duration_ms !== undefined && (
                      <span className="muted"> · {r.last_duration_ms}ms</span>
                    )}
                  </td>
                  <td className="mono">{resultCell(r)}</td>
                  <td className="mono muted">
                    {r.next_run_at_ms === undefined
                      ? `every ${r.interval_secs}s`
                      : until(r.next_run_at_ms)}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      {failing > 0 && (
        <div className="tbl-wrap" style={{ marginTop: 12 }}>
          <table>
            <thead>
              <tr>
                <th>Job</th>
                <th>Error</th>
              </tr>
            </thead>
            <tbody>
              {rows
                .filter((r) => r.state === "error" && r.last_error)
                .map((r) => (
                  <tr key={r.job}>
                    <td className="mono">{r.job}</td>
                    <td className="mono" style={{ color: "var(--fail)" }}>
                      {r.last_error}
                    </td>
                  </tr>
                ))}
            </tbody>
          </table>
        </div>
      )}
      <p className="caption muted" style={{ marginTop: 10 }}>
        <b>Compaction</b> rewrites a table into fewer, larger files (Trino <span className="mono">
        OPTIMIZE</span>); <b>orphan cleanup</b> sweeps stale staging tables. A failed run is
        non-fatal — the prior state is retained and the scheduler retries next tick. <b>Next</b> is
        approximate (last finish + cadence).
      </p>
    </>
  );
}

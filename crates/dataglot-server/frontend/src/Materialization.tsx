import { useEffect, useState } from "react";

import { getMaterialization, type MaterializationStatus } from "./api";

/** Poll cadence — refresh status changes on the scheduler's cadence, not
 *  sub-second, so a relaxed interval is plenty. */
const POLL_MS = 5000;

/** Compact "4s ago" / "2m ago" from an epoch-ms timestamp in the past. */
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

/** Map a refresh state to a status pill class + label. */
function statePill(state: string): { cls: string; label: string } {
  switch (state) {
    case "success":
      return { cls: "run", label: "FRESH" };
    case "error":
      return { cls: "fail", label: "FAILED" };
    case "running":
      return { cls: "queue", label: "REFRESHING" };
    default:
      return { cls: "idle", label: "PENDING" };
  }
}

/** The Materialization tab: the freshness view for materialized
 *  derived products. Each product's SQL is refreshed into an Iceberg table on
 *  a cadence; this shows the last run's outcome (rows written, duration), when
 *  it ran, and roughly when it runs next — the operator's answer to "is this
 *  data fresh, and did the last refresh work?". No reference engine surfaces
 *  materialization freshness as an operational plane like this. */
export function Materialization() {
  const [rows, setRows] = useState<MaterializationStatus[] | null>(null);
  const [error, setError] = useState(false);

  useEffect(() => {
    let stop = false;
    const ctrl = new AbortController();
    const tick = async () => {
      if (stop) return;
      try {
        const v = await getMaterialization(ctrl.signal);
        setRows(v);
        setError(false);
      } catch {
        setRows((prev) => {
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

  if (error) {
    return <p className="err">Could not load materialization status (/api/materialization).</p>;
  }
  if (!rows) {
    return <p className="muted">Loading materialization…</p>;
  }
  if (rows.length === 0) {
    return (
      <div className="empty">
        <p>
          <b>No materialized data products.</b>
        </p>
        <p className="muted">
          Derived products declared with <span className="mono">backing = "materialized"</span> are
          refreshed into an Iceberg table on their <span className="mono">refresh_every</span>{" "}
          cadence and appear here with their freshness, last row count, and next scheduled run.
        </p>
      </div>
    );
  }

  const fresh = rows.filter((r) => r.state === "success").length;
  const failing = rows.filter((r) => r.state === "error").length;

  return (
    <>
      <div className="stat-row">
        <div className="stat">
          <div className="k">Products</div>
          <div className="v">{rows.length}</div>
        </div>
        <div className="stat">
          <div className="k">Fresh</div>
          <div className="v" style={{ color: fresh < rows.length ? "var(--queue)" : undefined }}>
            {fresh}
            <small> / {rows.length}</small>
          </div>
        </div>
        <div className="stat">
          <div className="k">Failing</div>
          <div className="v" style={{ color: failing > 0 ? "var(--fail)" : undefined }}>
            {failing}
          </div>
        </div>
      </div>

      <div className="section-h">Materialized products ({rows.length})</div>
      <div className="tbl-wrap">
        <table>
          <thead>
            <tr>
              <th>Product</th>
              <th>Target</th>
              <th>State</th>
              <th>Rows</th>
              <th>Last refresh</th>
              <th>Next</th>
              <th>Runs</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => {
              const pill = statePill(r.state);
              return (
                <tr key={r.product}>
                  <td className="mono">{r.product}</td>
                  <td className="mono muted">{r.target}</td>
                  <td>
                    <span
                      className={`pill ${pill.cls}`}
                      title={r.state === "error" ? r.last_error : undefined}
                    >
                      {pill.label}
                    </span>
                  </td>
                  <td className="mono">
                    {r.last_rows === undefined ? "—" : r.last_rows.toLocaleString()}
                    {r.last_duration_ms !== undefined && (
                      <span className="muted"> · {r.last_duration_ms}ms</span>
                    )}
                  </td>
                  <td className="mono muted">
                    {r.last_finished_at_ms === undefined ? "never" : ago(r.last_finished_at_ms)}
                  </td>
                  <td className="mono muted">
                    {r.next_run_at_ms === undefined
                      ? `every ${r.interval_secs}s`
                      : until(r.next_run_at_ms)}
                  </td>
                  <td className="mono muted">
                    {r.runs}
                    {r.failures > 0 && (
                      <span style={{ color: "var(--fail)" }}> · {r.failures} failed</span>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {failing > 0 && (
        <div className="tbl-wrap" style={{ marginTop: 16 }}>
          <div className="section-h">Last errors</div>
          <table>
            <thead>
              <tr>
                <th>Product</th>
                <th>Error</th>
              </tr>
            </thead>
            <tbody>
              {rows
                .filter((r) => r.state === "error" && r.last_error)
                .map((r) => (
                  <tr key={r.product}>
                    <td className="mono">{r.product}</td>
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
        A failed refresh is non-fatal — the previous snapshot is retained and the scheduler retries
        on the next tick. <b>Next</b> is approximate (last finish + cadence). Nothing here exposes
        Iceberg internals; a "product" is just its SQL materialized to a governed table.
      </p>
    </>
  );
}

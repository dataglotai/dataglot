import { useEffect, useRef, useState } from "react";

import { getQuery, type Pushdown, type QueryDetail } from "./api";

function elapsed(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  const s = ms / 1000;
  if (s < 60) return `${s.toFixed(1)}s`;
  const m = Math.floor(s / 60);
  return `${m}m ${Math.floor(s % 60)}s`;
}

/** Map a pushdown outcome to a `.pill` modifier. */
function pushdownPill(outcome: Pushdown["outcome"]): string {
  if (outcome === "failed") return "fail";
  if (outcome === "partial") return "queue";
  return "run"; // completed
}

/** Map the query-level state/outcome to a `.pill` modifier + label. */
function queryStatus(q: QueryDetail): { cls: string; label: string } {
  if (q.state) return { cls: "run", label: q.state.toUpperCase() };
  switch (q.outcome) {
    case "success":
      return { cls: "run", label: "SUCCESS" };
    case "error":
      return { cls: "fail", label: "ERROR" };
    case "cancelled":
      return { cls: "queue", label: "CANCELLED" };
    default:
      return { cls: "idle", label: (q.outcome ?? "—").toUpperCase() };
  }
}

/** One pushdown branch of the profile tree — the SQL sent to one source
 *  with its rows/batches/timing and outcome. */
function PushdownBranch({ p, share }: { p: Pushdown; share: number }) {
  return (
    <li className="tree-node">
      <div className="tree-branch">
        <div className="pd-head">
          <span className={`chip kind-${p.kind}`}>{p.kind}</span>
          <span className="pd-source mono">{p.source}</span>
          <span className={`pill ${pushdownPill(p.outcome)}`}>{p.outcome.toUpperCase()}</span>
          <span className="pd-metrics mono">
            {p.rows.toLocaleString()} rows · {p.batches} batch{p.batches === 1 ? "" : "es"} ·{" "}
            <b>{elapsed(p.elapsed_ms)}</b>
          </span>
        </div>
        {/* Time share of the query's total, a quick "which source was slow" read. */}
        <div className="pd-bar" title={`${Math.round(share * 100)}% of query time`}>
          <span style={{ width: `${Math.min(100, Math.round(share * 100))}%` }} />
        </div>
        <pre className="pd-sql mono">{p.sql}</pre>
      </div>
    </li>
  );
}

/** The query-profile treeview: a query root with one branch
 *  per remote pushdown — the "which SQL went to Snowflake, how long, how many
 *  rows" view. Opens as an overlay from a query row. */
export function QueryProfile({ runId, onClose }: { runId: string; onClose: () => void }) {
  const [detail, setDetail] = useState<QueryDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  // Bumped by the refresh button; re-runs the fetch effect below.
  const [refreshKey, setRefreshKey] = useState(0);
  // True while a pointer press that started on the backdrop is in progress —
  // so a text selection dragged out of the panel doesn't dismiss the overlay.
  const pressedBackdrop = useRef(false);

  // Fetch on mount, when the run_id changes, and on manual refresh. The
  // cleanup aborts any in-flight request first, so a slow earlier fetch can't
  // land after a newer one and overwrite the view with stale data.
  useEffect(() => {
    const ctrl = new AbortController();
    setLoading(true);
    getQuery(runId, ctrl.signal)
      .then((d) => {
        setDetail(d);
        setError(null);
      })
      .catch((e: unknown) => {
        if (ctrl.signal.aborted) return;
        setError(e instanceof Error ? e.message : String(e));
      })
      .finally(() => {
        if (!ctrl.signal.aborted) setLoading(false);
      });
    return () => ctrl.abort();
  }, [runId, refreshKey]);

  // Close on Escape.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  const status = detail ? queryStatus(detail) : null;
  const total = detail?.elapsed_ms ?? 0;

  return (
    <div
      className="overlay"
      onMouseDown={(e) => {
        pressedBackdrop.current = e.target === e.currentTarget;
      }}
      onClick={(e) => {
        if (e.target === e.currentTarget && pressedBackdrop.current) onClose();
      }}
    >
      <div className="profile" role="dialog" aria-label="Query profile">
        <div className="profile-head">
          <span className="profile-title">Query profile</span>
          <span className="mono profile-runid" title={runId}>
            {runId}
          </span>
          <button
            className="refresh-btn"
            onClick={() => setRefreshKey((k) => k + 1)}
            title="Refresh"
          >
            refresh
          </button>
          <button className="profile-x" onClick={onClose} title="Close (Esc)">
            ✕
          </button>
        </div>

        {loading && !detail && <p className="muted profile-msg">Loading…</p>}
        {error && (
          <p className="profile-msg fail-text">
            {error.includes("404") ? "Query not found (finished and aged out of history)." : error}
          </p>
        )}

        {detail && (
          <>
            <div className="profile-summary">
              <div className="profile-meta">
                {status && <span className={`pill ${status.cls}`}>{status.label}</span>}
                <span className="mono">
                  <b>{elapsed(total)}</b> total
                </span>
                <span className="muted">
                  {detail.user ?? "—"}
                  {detail.org ? ` · ${detail.org}` : ""}
                </span>
              </div>
              <pre className="pd-sql mono profile-sql">{detail.sql}</pre>
              {detail.error && <p className="fail-text mono profile-err">{detail.error}</p>}
            </div>

            <ul className="tree">
              <li className="tree-node tree-root">
                <div className="tree-branch">
                  <div className="pd-head">
                    <span className="chip">query</span>
                    <span className="pd-source">
                      federates {detail.sources.length}{" "}
                      source{detail.sources.length === 1 ? "" : "s"}
                    </span>
                    <span className="pd-metrics mono">
                      {detail.pushdowns.length} pushdown
                      {detail.pushdowns.length === 1 ? "" : "s"}
                    </span>
                  </div>
                </div>
                {detail.pushdowns.length === 0 ? (
                  <p className="muted profile-msg">
                    No per-source pushdowns — this query reads its sources directly (parquet /
                    Iceberg / REST) or didn't push SQL to a remote engine. Per-source profiles
                    apply only to SQL connectors (postgres, mysql, oracle, snowflake, adbc).
                    (Also empty while a query is still starting, or if{" "}
                    <code>capture_query_sources</code> is off.)
                  </p>
                ) : (
                  <ul className="tree">
                    {detail.pushdowns.map((p, i) => (
                      <PushdownBranch
                        key={`${p.source}-${i}`}
                        p={p}
                        share={total > 0 ? p.elapsed_ms / total : 0}
                      />
                    ))}
                  </ul>
                )}
              </li>
            </ul>
          </>
        )}
      </div>
    </div>
  );
}

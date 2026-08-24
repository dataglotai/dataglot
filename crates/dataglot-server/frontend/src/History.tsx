import { useEffect, useMemo, useState } from "react";

import { type CompletedQuery, getQueriesHistory } from "./api";
import { Donut, FillBar, Histogram, percentile } from "./charts";

/** Count how many completed queries touched each federated source (a query
 *  federating N sources counts once per source), ranked most-hit first. Shows
 *  where the federation load actually lands. */
function sourceLoad(rows: CompletedQuery[]): { source: string; count: number }[] {
  const counts = new Map<string, number>();
  for (const r of rows) {
    for (const s of r.sources) counts.set(s, (counts.get(s) ?? 0) + 1);
  }
  return [...counts.entries()]
    .map(([source, count]) => ({ source, count }))
    .sort((a, b) => b.count - a.count);
}

/** Pill colour class for a completed-query outcome: error = red, cancelled =
 *  amber (operator-initiated, not a failure), success = neutral. */
function outcomePill(outcome: string): string {
  if (outcome === "error") return "fail";
  if (outcome === "cancelled") return "queue";
  return "idle";
}

function elapsed(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  const s = ms / 1000;
  if (s < 60) return `${s.toFixed(1)}s`;
  const m = Math.floor(s / 60);
  return `${m}m ${Math.floor(s % 60)}s`;
}

const HIST_BUCKETS = 28;

/** Bucket completed-query latencies into a fixed number of linear buckets over
 *  [0, max], and locate the p50/p95/p99 markers as fractional x positions. */
function latencyChart(rows: CompletedQuery[]) {
  const lat = rows.map((r) => r.elapsed_ms).filter((n) => Number.isFinite(n) && n >= 0);
  if (lat.length === 0) {
    return { counts: [] as number[], markers: [] as { at: number; label: string }[], p: null };
  }
  const sorted = [...lat].sort((a, b) => a - b);
  const max = Math.max(1, sorted[sorted.length - 1]);
  const counts = new Array<number>(HIST_BUCKETS).fill(0);
  for (const v of lat) {
    const b = Math.min(HIST_BUCKETS - 1, Math.floor((v / max) * HIST_BUCKETS));
    counts[b] += 1;
  }
  const p = {
    p50: percentile(sorted, 50),
    p95: percentile(sorted, 95),
    p99: percentile(sorted, 99),
  };
  const markers = [
    { at: p.p50 / max, label: "p50" },
    { at: p.p95 / max, label: "p95" },
    { at: p.p99 / max, label: "p99" },
  ];
  return { counts, markers, p };
}

/** The History tab: the most-recently-finished
 *  queries from the server's bounded in-memory ring, newest first. */
export function History({ onSelect }: { onSelect: (runId: string) => void }) {
  const [rows, setRows] = useState<CompletedQuery[]>([]);
  const lat = useMemo(() => latencyChart(rows), [rows]);
  const okCount = useMemo(() => rows.filter((r) => r.outcome === "success").length, [rows]);
  const errCount = useMemo(() => rows.filter((r) => r.outcome === "error").length, [rows]);
  const cancelledCount = useMemo(
    () => rows.filter((r) => r.outcome === "cancelled").length,
    [rows],
  );
  const load = useMemo(() => sourceLoad(rows), [rows]);
  const loadMax = load.length > 0 ? load[0].count : 0;

  useEffect(() => {
    let stop = false;
    const ctrl = new AbortController();
    const tick = async () => {
      try {
        const h = await getQueriesHistory(ctrl.signal);
        if (!stop) setRows(h);
      } catch {
        /* transient — keep the last view */
      }
    };
    void tick();
    const h = setInterval(() => void tick(), 2000);
    return () => {
      stop = true;
      ctrl.abort();
      clearInterval(h);
    };
  }, []);

  if (rows.length === 0) {
    return (
      <div className="empty">
        <p>
          <b>No finished queries yet.</b>
        </p>
        <p className="muted">
          The most recent completed queries (up to 100) appear here as they finish, newest first.
        </p>
      </div>
    );
  }

  return (
    <>
      <div className="chart-grid" style={{ marginTop: 18 }}>
        <div className="chart-card chart-wide">
          <div className="metric-head">
            <span>latency distribution · {rows.length} queries</span>
            {lat.p && (
              <span className="mono">
                p50 {elapsed(lat.p.p50)} · p95 {elapsed(lat.p.p95)} · p99 {elapsed(lat.p.p99)}
              </span>
            )}
          </div>
          <Histogram counts={lat.counts} markers={lat.markers} width={560} height={96} />
          <p className="caption muted">
            Buckets are linear over 0…max; dashed red lines mark p50 / p95 / p99.
          </p>
        </div>
        <div className="chart-card donut-card">
          <div className="metric-head">
            <span>outcomes</span>
          </div>
          <div className="donut-wrap">
            <Donut
              segments={[
                { value: okCount, color: "var(--run)", label: "success" },
                { value: errCount, color: "var(--fail)", label: "error" },
                { value: cancelledCount, color: "var(--queue)", label: "cancelled" },
              ]}
            />
            <div className="legend">
              <span>
                <i style={{ background: "var(--run)" }} /> {okCount} success
              </span>
              <span>
                <i style={{ background: "var(--fail)" }} /> {errCount} error
              </span>
              {cancelledCount > 0 && (
                <span>
                  <i style={{ background: "var(--queue)" }} /> {cancelledCount} cancelled
                </span>
              )}
            </div>
          </div>
        </div>
      </div>

      {load.length > 0 && (
        <>
          <div className="section-h">Federation load · queries per source</div>
          <div className="chart-card">
            {load.map((l) => (
              <div className="bar-row" key={l.source}>
                <span className="bar-row-label mono" title={l.source}>
                  {l.source}
                </span>
                <FillBar fraction={loadMax > 0 ? l.count / loadMax : 0} tone="var(--accent)" />
                <span className="bar-row-val mono">{l.count}</span>
              </div>
            ))}
          </div>
          <p className="caption muted" style={{ marginTop: 8 }}>
            How many of the last {rows.length} completed queries touched each source (a query
            federating several sources counts once per source).
          </p>
        </>
      )}

      <div className="tbl-wrap" style={{ marginTop: 18 }}>
        <table>
        <thead>
          <tr>
            <th>Query</th>
            <th>User</th>
            <th>Org</th>
            <th>SQL</th>
            <th>Sources</th>
            <th>Outcome</th>
            <th>Elapsed</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((q) => (
            <tr key={q.run_id}>
              <td className="mono">
                <button
                  className="run-link"
                  title="View query profile"
                  onClick={() => onSelect(q.run_id)}
                >
                  {q.run_id.slice(0, 8)}
                </button>
              </td>
              <td className="mono">{q.user ?? "—"}</td>
              <td>{q.org ? <span className="chip">{q.org}</span> : <span className="muted">—</span>}</td>
              <td className="sql mono" title={q.sql}>
                {q.sql}
                {q.error && (
                  <div
                    className="mono"
                    style={{ color: "var(--fail)", fontSize: "11px", marginTop: 3 }}
                    title={q.error}
                  >
                    {q.error}
                  </div>
                )}
              </td>
              <td>
                {q.sources.length === 0 ? (
                  <span className="muted">—</span>
                ) : (
                  <span className="src-chips">
                    {q.sources.map((s) => (
                      <span className="chip" key={s}>
                        {s}
                      </span>
                    ))}
                  </span>
                )}
              </td>
              <td>
                <span
                  className={`pill ${outcomePill(q.outcome)}`}
                  title={q.error ?? undefined}
                >
                  {q.outcome.toUpperCase()}
                </span>
              </td>
              <td className="mono">{elapsed(q.elapsed_ms)}</td>
            </tr>
          ))}
        </tbody>
        </table>
      </div>
    </>
  );
}

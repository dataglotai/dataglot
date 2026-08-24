import { useState } from "react";

import { type ActiveQuery, cancelQuery } from "./api";

function elapsed(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  const s = ms / 1000;
  if (s < 60) return `${s.toFixed(1)}s`;
  const m = Math.floor(s / 60);
  return `${m}m ${Math.floor(s % 60)}s`;
}

/** The Running-Queries tab: the "what's running" list from
 *  /api/queries (QueryRegistry), longest-running first, with a
 *  best-effort kill button (slice 4). The 2s poll reflects the result. */
export function Queries({
  queries,
  onSelect,
}: {
  queries: ActiveQuery[];
  /** Open the per-source pushdown profile for a run_id. */
  onSelect: (runId: string) => void;
}) {
  // run_ids the user has asked to cancel — disables the button until the
  // poll drops the row.
  const [killing, setKilling] = useState<Set<string>>(new Set());

  const kill = (runId: string) => {
    setKilling((s) => new Set(s).add(runId));
    void cancelQuery(runId);
  };

  if (queries.length === 0) {
    return (
      <div className="empty">
        <p>
          <b>No queries running.</b>
        </p>
        <p className="muted">
          In-flight queries appear here the moment they start executing, longest-running first.
        </p>
      </div>
    );
  }

  return (
    <div className="tbl-wrap" style={{ marginTop: 18 }}>
      <table>
        <thead>
          <tr>
            <th>Query</th>
            <th>User</th>
            <th>Org</th>
            <th>SQL</th>
            <th>Sources</th>
            <th>State</th>
            <th>Elapsed</th>
            <th />
          </tr>
        </thead>
        <tbody>
          {queries.map((q) => (
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
                <span className="pill run">{q.state.toUpperCase()}</span>
              </td>
              <td className="mono">{elapsed(q.elapsed_ms)}</td>
              <td>
                <button
                  className="kill"
                  disabled={killing.has(q.run_id)}
                  onClick={() => kill(q.run_id)}
                  title="Cancel this query"
                >
                  {killing.has(q.run_id) ? "killing…" : "kill"}
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

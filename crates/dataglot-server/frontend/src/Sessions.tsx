import { type Session } from "./api";
import { ResourceLimitsPanel } from "./ResourceLimits";

/** Relative "connected-since" label from a Unix-epoch-ms timestamp, e.g.
 *  "3m 12s" — how long the session has been connected. */
function since(ms: number): string {
  const secs = Math.max(0, Math.floor((Date.now() - ms) / 1000));
  if (secs < 60) return `${secs}s`;
  const m = Math.floor(secs / 60);
  if (m < 60) return `${m}m ${secs % 60}s`;
  const h = Math.floor(m / 60);
  return `${h}h ${m % 60}m`;
}

/** Absolute local-time timestamp for the "Connected" cell's title/subtext. */
function absolute(ms: number): string {
  return new Date(ms).toLocaleString();
}

/** The Sessions tab: the "who is connected" list from /api/sessions
 *  (SessionRegistry), longest-connected first. The per-connection detail —
 *  user · org · client address · connected-since — behind the aggregate
 *  active-connection count. `org` is the governance-relevant, multi-tenant
 *  column. The 2s poll keeps it live. */
export function Sessions({ sessions }: { sessions: Session[] }) {
  return (
    <>
      <ResourceLimitsPanel />
      {sessions.length === 0 ? (
        <div className="empty">
          <p>
            <b>No active sessions.</b>
          </p>
          <p className="muted">
            Each connected pgwire client appears here — its user, org, client address, and how long
            it has been connected — the moment it completes the startup handshake, longest-connected
            first.
          </p>
        </div>
      ) : (
        <>
          <div className="section-h">Connected sessions ({sessions.length})</div>
          <div className="tbl-wrap">
            <table>
              <thead>
                <tr>
                  <th>User</th>
                  <th>Org</th>
                  <th>Client</th>
                  <th>Connected</th>
                </tr>
              </thead>
              <tbody>
                {sessions.map((s) => (
                  <tr key={s.session_id}>
                    <td className="mono">{s.user ?? "—"}</td>
                    <td>
                      {s.org ? (
                        <span className="chip">{s.org}</span>
                      ) : (
                        <span className="muted">—</span>
                      )}
                    </td>
                    <td className="mono">{s.peer}</td>
                    <td className="mono" title={absolute(s.connected_at_ms)}>
                      {since(s.connected_at_ms)} ago
                      <span className="muted"> · {absolute(s.connected_at_ms)}</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </>
  );
}

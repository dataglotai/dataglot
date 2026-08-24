import { useEffect, useState } from "react";

import { getLimits, type ResourceUsageView } from "./api";
import { fmtBytes } from "./charts";

const POLL_MS = 3000;

/** Fill colour for a usage fraction: green with headroom, amber tightening,
 *  red near the ceiling. */
function tone(frac: number): string {
  if (frac >= 0.9) return "var(--fail)";
  if (frac >= 0.75) return "var(--queue)";
  return "var(--run)";
}

/** One "used / limit" meter with a fill bar, or an "unlimited" note when the
 *  ceiling is unset. */
function Meter({ label, used, limit }: { label: string; used: number; limit: number | null }) {
  const frac = limit && limit > 0 ? Math.min(1, used / limit) : 0;
  return (
    <div className="limit-meter">
      <div className="metric-head">
        <span>{label}</span>
        <span className="mono">
          {used}
          {limit == null ? <span className="muted"> / ∞</span> : ` / ${limit}`}
        </span>
      </div>
      {limit == null ? (
        <div className="limit-track limit-unlimited" aria-hidden />
      ) : (
        <div className="limit-track" aria-hidden>
          <span style={{ width: `${Math.round(frac * 100)}%`, background: tone(frac) }} />
        </div>
      )}
    </div>
  );
}

/** The "resource limits vs usage" panel ( / ): configured
 *  connection + memory ceilings and live usage against them — active
 *  connections, the busiest IP / identity bucket, cumulative rejections, and
 *  the memory ceiling. Self-fetches on a poll so it stays live regardless of
 *  the parent tab. Renders nothing until the first successful load. */
export function ResourceLimitsPanel() {
  const [view, setView] = useState<ResourceUsageView | null>(null);

  useEffect(() => {
    let stop = false;
    const ctrl = new AbortController();
    const tick = async () => {
      try {
        const v = await getLimits(ctrl.signal);
        if (!stop) setView(v);
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

  if (!view) return null;

  const { limits: l } = view;
  const rejectedTotal =
    view.rejected_global +
    view.rejected_per_ip +
    view.rejected_new_conn_rate +
    view.rejected_identity;
  const rejectBreakdown = [
    ["global", view.rejected_global],
    ["per-ip", view.rejected_per_ip],
    ["new-conn rate", view.rejected_new_conn_rate],
    ["per-identity", view.rejected_identity],
  ]
    .filter(([, n]) => (n as number) > 0)
    .map(([k, n]) => `${k}: ${n}`)
    .join(" · ");

  return (
    <>
      <div className="section-h">Resource limits</div>
      <div className="chart-card">
        <div className="limit-grid">
          <Meter label="connections" used={view.active_connections} limit={l.max_connections} />
          <Meter
            label="busiest IP"
            used={view.busiest_ip_connections}
            limit={l.max_connections_per_ip}
          />
          <Meter
            label="busiest identity"
            used={view.busiest_identity_connections}
            limit={l.max_connections_per_identity}
          />
          <div className="limit-meter">
            <div className="metric-head">
              <span>new-conn rate cap</span>
              <span className="mono">
                {l.max_new_connections_per_ip_per_minute == null ? (
                  <span className="muted">none</span>
                ) : (
                  `${l.max_new_connections_per_ip_per_minute}/min per IP`
                )}
              </span>
            </div>
          </div>
          <div className="limit-meter">
            <div className="metric-head">
              <span>query memory ceiling</span>
              <span className="mono">
                {l.memory_limit_bytes == null ? (
                  <span className="muted">unbounded</span>
                ) : (
                  fmtBytes(l.memory_limit_bytes)
                )}
              </span>
            </div>
          </div>
          <div className="limit-meter">
            <div className="metric-head">
              <span>rejected connections</span>
              <span className="mono" style={{ color: rejectedTotal > 0 ? "var(--fail)" : undefined }}>
                {rejectedTotal}
              </span>
            </div>
            {rejectBreakdown && <div className="caption muted mono">{rejectBreakdown}</div>}
          </div>
        </div>
      </div>
      <p className="caption muted" style={{ marginTop: 8 }}>
        Live usage against the configured ceilings (<span className="mono">[rate_limit]</span> +{" "}
        <span className="mono">memory_limit_bytes</span>). <b>∞</b> / <b>unbounded</b> means no limit
        is set. Rejections are cumulative since boot.
      </p>
    </>
  );
}

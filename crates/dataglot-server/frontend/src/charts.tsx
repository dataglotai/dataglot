// Self-contained inline-SVG chart primitives for the operations dashboard
//. No external libraries — the dashboard ships CSP-embedded via
// rust-embed, so every visual is hand-authored SVG using the existing CSS
// tokens (var(--run), var(--accent), …). All charts are theme-consistent with
// the light palette in styles.css.

/** Compact byte count: 3_152_019_456 → "2.9 GB". */
export function fmtBytes(n: number): string {
  if (n <= 0) return "0";
  const u = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < u.length - 1) {
    v /= 1024;
    i += 1;
  }
  return `${v >= 100 || i === 0 ? Math.round(v) : v.toFixed(1)} ${u[i]}`;
}

/** Nearest-rank percentile of an already-sorted ascending array. */
export function percentile(sortedAsc: number[], p: number): number {
  if (sortedAsc.length === 0) return 0;
  const rank = Math.ceil((p / 100) * sortedAsc.length);
  const idx = Math.min(sortedAsc.length - 1, Math.max(0, rank - 1));
  return sortedAsc[idx];
}

/** A small line chart over a numeric series. Y auto-scales to [0, max] (or a
 *  caller-supplied `max`, e.g. a peak reference). Renders an area fill under
 *  the line plus an optional dashed peak line. Empty/short series render a
 *  flat baseline so the slot doesn't jump as the buffer fills. */
export function Sparkline({
  values,
  width = 220,
  height = 40,
  stroke = "var(--accent)",
  max,
  peak,
}: {
  values: number[];
  width?: number;
  height?: number;
  stroke?: string;
  max?: number;
  peak?: number;
}) {
  const pad = 2;
  const w = width;
  const h = height;
  const top = max ?? Math.max(1, ...values, peak ?? 0);
  const x = (i: number) =>
    values.length <= 1 ? pad : pad + (i / (values.length - 1)) * (w - 2 * pad);
  const y = (v: number) => h - pad - (v / top) * (h - 2 * pad);
  const pts = values.map((v, i) => `${x(i).toFixed(1)},${y(v).toFixed(1)}`);
  const line = pts.join(" ");
  const area =
    values.length > 0
      ? `${pad},${h - pad} ${line} ${x(values.length - 1).toFixed(1)},${h - pad}`
      : "";
  const peakY = peak != null ? y(peak) : null;
  return (
    <svg
      className="spark"
      viewBox={`0 0 ${w} ${h}`}
      preserveAspectRatio="none"
      role="img"
    >
      {area && <polygon points={area} fill={stroke} opacity="0.12" />}
      {values.length > 1 && (
        <polyline
          points={line}
          fill="none"
          stroke={stroke}
          strokeWidth="1.5"
          strokeLinejoin="round"
          vectorEffect="non-scaling-stroke"
        />
      )}
      {peakY != null && (
        <line
          x1={pad}
          x2={w - pad}
          y1={peakY}
          y2={peakY}
          stroke="var(--ink-3)"
          strokeWidth="1"
          strokeDasharray="3 3"
          vectorEffect="non-scaling-stroke"
        />
      )}
    </svg>
  );
}

/** Horizontal fill bar (0..1). `tone` picks the fill color; the track uses the
 *  neutral line color. Used for disk headroom and query fan-out. */
export function FillBar({
  fraction,
  tone = "var(--run)",
}: {
  fraction: number;
  tone?: string;
}) {
  const pct = Math.max(0, Math.min(1, fraction)) * 100;
  return (
    <div className="fillbar" aria-hidden>
      <span style={{ width: `${pct}%`, background: tone }} />
    </div>
  );
}

/** Vertical-bar histogram over precomputed bucket counts. Optional markers are
 *  drawn as labelled vertical lines at a fractional x position (0..1) — used
 *  for the p50/p95/p99 latency lines. */
export function Histogram({
  counts,
  width = 480,
  height = 90,
  markers = [],
}: {
  counts: number[];
  width?: number;
  height?: number;
  markers?: { at: number; label: string }[];
}) {
  const w = width;
  const h = height;
  const maxC = Math.max(1, ...counts);
  const bw = counts.length > 0 ? w / counts.length : w;
  return (
    <svg
      className="hist"
      viewBox={`0 0 ${w} ${h}`}
      preserveAspectRatio="none"
      role="img"
    >
      {counts.map((c, i) => {
        const bh = (c / maxC) * (h - 2);
        return (
          <rect
            key={i}
            x={i * bw + 0.5}
            y={h - bh}
            width={Math.max(0.5, bw - 1)}
            height={bh}
            fill="var(--accent)"
            opacity={c === 0 ? 0.15 : 0.75}
          />
        );
      })}
      {markers.map((m) => {
        const mx = Math.max(0, Math.min(1, m.at)) * w;
        return (
          <g key={m.label}>
            <line
              x1={mx}
              x2={mx}
              y1={0}
              y2={h}
              stroke="var(--fail)"
              strokeWidth="1"
              strokeDasharray="2 2"
              vectorEffect="non-scaling-stroke"
            />
          </g>
        );
      })}
    </svg>
  );
}

/** Two-plus segment donut. Segments render clockwise from 12 o'clock; a hole
 *  keeps it a ring. Used for the success/error outcome split. */
export function Donut({
  segments,
  size = 96,
}: {
  segments: { value: number; color: string; label: string }[];
  size?: number;
}) {
  const total = segments.reduce((a, s) => a + s.value, 0);
  const r = size / 2 - 8;
  const c = 2 * Math.PI * r;
  let acc = 0;
  return (
    <svg
      className="donut"
      viewBox={`0 0 ${size} ${size}`}
      width={size}
      height={size}
      role="img"
    >
      <g transform={`rotate(-90 ${size / 2} ${size / 2})`}>
        <circle
          cx={size / 2}
          cy={size / 2}
          r={r}
          fill="none"
          stroke="var(--line-2)"
          strokeWidth="10"
        />
        {total > 0 &&
          segments.map((s) => {
            const len = (s.value / total) * c;
            const el = (
              <circle
                key={s.label}
                cx={size / 2}
                cy={size / 2}
                r={r}
                fill="none"
                stroke={s.color}
                strokeWidth="10"
                strokeDasharray={`${len} ${c - len}`}
                strokeDashoffset={-acc}
              />
            );
            acc += len;
            return el;
          })}
      </g>
      <text
        x="50%"
        y="50%"
        textAnchor="middle"
        dominantBaseline="central"
        className="donut-center"
      >
        {total}
      </text>
    </svg>
  );
}

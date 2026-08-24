import { useEffect, useMemo, useState } from "react";

import {
  getLineage,
  type LineageEdge,
  type LineageNode,
  type ServerInfo,
} from "./api";

/** SVG geometry for the lineage graph. */
const NODE_W = 148;
const NODE_H = 42;
const COL_W = 196;
const ROW_H = 60;
const PAD = 14;

/** Fill + stroke for a node given its mask state. Semantic color, separate
 *  from the app accent: configured = red (declared mask), propagated = amber
 *  (masked only through lineage), clean = neutral. */
function maskTone(mask?: string): { fill: string; stroke: string } {
  if (mask === "configured") {
    return { fill: "color-mix(in srgb, var(--fail) 14%, var(--panel))", stroke: "var(--fail)" };
  }
  if (mask === "propagated") {
    return { fill: "color-mix(in srgb, var(--queue) 16%, var(--panel))", stroke: "var(--queue)" };
  }
  return { fill: "var(--panel)", stroke: "var(--line-2)" };
}

function truncate(s: string, n: number): string {
  return s.length > n ? `${s.slice(0, n - 1)}…` : s;
}

interface Placed {
  idx: number;
  node: LineageNode;
  x: number;
  y: number;
}

/** Lay the lineage DAG out left-to-right by longest-path depth. Only nodes
 *  that participate in an edge are placed (isolated columns live in the table
 *  below); this keeps the graph the story of *flow*. */
function layout(nodes: LineageNode[], edges: LineageEdge[]) {
  const connected = new Set<number>();
  for (const e of edges) {
    connected.add(e.from);
    connected.add(e.to);
  }
  // Longest-path layering: relax layer[to] = max(layer[to], layer[from]+1)
  // until stable. Bounded by node count; the graph is tiny.
  const layer = new Map<number, number>();
  for (const i of connected) layer.set(i, 0);
  for (let pass = 0; pass < nodes.length; pass += 1) {
    let changed = false;
    for (const e of edges) {
      const next = (layer.get(e.from) ?? 0) + 1;
      if (next > (layer.get(e.to) ?? 0)) {
        layer.set(e.to, next);
        changed = true;
      }
    }
    if (!changed) break;
  }
  // Stack nodes within each layer.
  const rowOf = new Map<number, number>();
  const perLayer = new Map<number, number>();
  const placed: Placed[] = [];
  // Deterministic order: by layer, then original index.
  const ordered = [...connected].sort(
    (a, b) => (layer.get(a) ?? 0) - (layer.get(b) ?? 0) || a - b,
  );
  for (const idx of ordered) {
    const l = layer.get(idx) ?? 0;
    const row = perLayer.get(l) ?? 0;
    perLayer.set(l, row + 1);
    rowOf.set(idx, row);
    placed.push({
      idx,
      node: nodes[idx],
      x: PAD + l * COL_W,
      y: PAD + row * ROW_H,
    });
  }
  const maxLayer = Math.max(0, ...[...layer.values()]);
  const maxRows = Math.max(1, ...[...perLayer.values()]);
  return {
    placed,
    pos: new Map(placed.map((p) => [p.idx, p])),
    width: PAD * 2 + (maxLayer + 1) * COL_W - (COL_W - NODE_W),
    height: PAD * 2 + maxRows * ROW_H - (ROW_H - NODE_H),
  };
}

function LineageGraph({ nodes, edges }: { nodes: LineageNode[]; edges: LineageEdge[] }) {
  const g = useMemo(() => layout(nodes, edges), [nodes, edges]);
  if (g.placed.length === 0) return null;

  return (
    <div className="lineage-wrap">
      <svg
        className="lineage"
        viewBox={`0 0 ${g.width} ${g.height}`}
        width={g.width}
        height={g.height}
        role="img"
        aria-label="Column lineage graph"
      >
        {edges.map((e, i) => {
          const s = g.pos.get(e.from);
          const t = g.pos.get(e.to);
          if (!s || !t) return null;
          const sx = s.x + NODE_W;
          const sy = s.y + NODE_H / 2;
          const tx = t.x;
          const ty = t.y + NODE_H / 2;
          const c = (sx + tx) / 2;
          // Edges leaving a masked column carry protected data — emphasise
          // them so the propagation path reads at a glance.
          const carriesMask = Boolean(s.node.mask);
          return (
            <path
              key={i}
              d={`M ${sx} ${sy} C ${c} ${sy}, ${c} ${ty}, ${tx} ${ty}`}
              fill="none"
              stroke={carriesMask ? "var(--queue)" : "var(--line-2)"}
              strokeWidth={carriesMask ? 1.75 : 1}
              opacity={carriesMask ? 0.9 : 0.6}
              vectorEffect="non-scaling-stroke"
            >
              <title>{`${s.node.table}.${s.node.field} → ${t.node.table}.${t.node.field} (${e.transform})`}</title>
            </path>
          );
        })}
        {g.placed.map((p) => {
          const tone = maskTone(p.node.mask);
          return (
            <g key={p.idx} transform={`translate(${p.x} ${p.y})`}>
              <rect
                width={NODE_W}
                height={NODE_H}
                rx={7}
                fill={tone.fill}
                stroke={tone.stroke}
                strokeWidth={p.node.mask ? 1.5 : 1}
              />
              <text x={8} y={16} className="ln-tbl">
                {truncate(`${p.node.catalog}.${p.node.table}`, 20)}
              </text>
              <text x={8} y={31} className="ln-fld">
                {truncate(p.node.field, 18)}
              </text>
            </g>
          );
        })}
      </svg>
    </div>
  );
}

/** The Governance tab ( slice 5c; graph ): the masks in effect,
 *  from the boot-time /lineage snapshot — the masked columns table plus a
 *  column-lineage graph that shows *how* the masks propagate to derived
 *  products. No reference engine surfaces plan-time governance like this. */
export function Governance({ server }: { server: ServerInfo | null }) {
  const [nodes, setNodes] = useState<LineageNode[] | null>(null);
  const [edges, setEdges] = useState<LineageEdge[]>([]);
  const [error, setError] = useState(false);

  useEffect(() => {
    const ctrl = new AbortController();
    getLineage(ctrl.signal)
      .then((s) => {
        setNodes(s.nodes ?? []);
        setEdges(s.edges ?? []);
      })
      .catch(() => setError(true));
    return () => ctrl.abort();
  }, []);

  if (error) {
    return <p className="err">Could not load the governance snapshot (/lineage).</p>;
  }
  if (!nodes) {
    return <p className="muted">Loading governance…</p>;
  }

  const posturePanel = server && (
    <div className="posture-panel">
      <div className="section-h">Policy posture</div>
      <div className="posture-grid">
        <span>
          authz{" "}
          <b className={server.governance.authz_mode === "open" ? "warn" : "ok"}>
            {server.governance.authz_mode}
          </b>
        </span>
        <span>
          masks <b>{server.governance.masks}</b>
        </span>
        <span>
          row filters <b>{server.governance.row_filters}</b>
        </span>
        <span>
          access-denies <b>{server.governance.access_denials}</b>
        </span>
        <span>
          column grants <b>{server.governance.column_grants}</b>
        </span>
      </div>
    </div>
  );

  const masked = nodes.filter((n) => n.mask);
  if (masked.length === 0) {
    return (
      <>
        {posturePanel}
        <div className="empty">
        <p>
          <b>No column masks in effect.</b>
        </p>
        <p className="muted">
          Masks declared in <span className="mono">[policy]</span> (and columns they propagate to
          through lineage) appear here, enforced at plan time.
        </p>
        </div>
      </>
    );
  }

  return (
    <>
      {posturePanel}
      {edges.length > 0 && (
        <>
          <div className="section-h">Column lineage · mask propagation</div>
          <LineageGraph nodes={nodes} edges={edges} />
          <div className="legend legend-row">
            <span>
              <i style={{ background: "var(--fail)" }} /> configured mask
            </span>
            <span>
              <i style={{ background: "var(--queue)" }} /> propagated mask
            </span>
            <span>
              <i style={{ background: "var(--line-2)" }} /> unmasked
            </span>
          </div>
          <p className="caption muted" style={{ marginTop: 8 }}>
            Left-to-right column lineage. Amber edges leave a masked column — the plan-time
            guarantee follows the data into every derived product downstream. Hover an edge for
            its transform.
          </p>
        </>
      )}

      <div className="section-h" style={{ marginTop: 24 }}>
        Masked columns ({masked.length})
      </div>
      <div className="tbl-wrap" style={{ marginTop: 4 }}>
        <table>
          <thead>
            <tr>
              <th>Dataset</th>
              <th>Column</th>
              <th>Kind</th>
              <th>Mask</th>
            </tr>
          </thead>
          <tbody>
            {masked.map((n) => {
              const dataset = `${n.catalog}.${n.schema}.${n.table}`;
              const propagated = n.mask === "propagated";
              return (
                <tr key={`${dataset}.${n.field}`}>
                  <td className="mono">{dataset}</td>
                  <td className="mono">{n.field}</td>
                  <td className="mono muted">{n.kind}</td>
                  <td>
                    <span className={`pill ${propagated ? "queue" : "fail"}`}>
                      {propagated ? "PROPAGATED" : "CONFIGURED"}
                    </span>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      <p className="caption muted" style={{ marginTop: 10 }}>
        <b>Configured</b> = a mask declared directly on this column. <b>Propagated</b> = masked
        automatically because it descends (through column lineage) from a masked source — the
        governance guarantee extends to derived products.
      </p>
    </>
  );
}

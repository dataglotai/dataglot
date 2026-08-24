import { Fragment, useEffect, useRef, useState } from "react";

import {
  asStages,
  type ClusterSummary,
  field,
  getClusterJobStages,
  isTerminal,
  type Json,
  num,
  type ServerInfo,
  str,
} from "./api";
import { fmtBytes, FillBar, Sparkline } from "./charts";

/** Read one Ballista executor metric (the `metrics: [{type, value}]` array,
 *  which the generic `field()` reader doesn't descend into). */
function metric(e: Json, type: string): number {
  const arr = field(e, "metrics");
  if (!Array.isArray(arr)) return 0;
  const hit = (arr as Json[]).find((m) => str(field(m as Json, "type")) === type);
  return hit ? num(field(hit as Json, "value")) : 0;
}

/** Read a numeric field from an executor's `os_info` block. */
function osInfo(e: Json, key: string): number {
  return num(field(field(e, "os_info") as Json | undefined, key));
}

/** Heartbeat age (ms) for an executor. The scheduler's `/api/executors`
 *  exposes `last_seen` as the last-heartbeat epoch time in ms
 *  (`Duration::from_secs(hb.timestamp).as_millis()` upstream), so the age is
 *  `now - last_seen`. Returns null when the executor never reported one. */
function heartbeatAge(e: Json): number | null {
  const ls = num(field(e, "last_seen"));
  if (ls <= 0) return null;
  return Math.max(0, Date.now() - ls);
}

/** An executor's health from its heartbeat age. Ballista's default
 *  dead-executor threshold is generous; we flag "warn" early so a lagging
 *  heartbeat is visible before the scheduler evicts the node. */
type Health = "ok" | "warn" | "stale";
const WARN_MS = 15_000;
const STALE_MS = 30_000;
function execHealth(age: number | null): Health {
  if (age == null || age > STALE_MS) return "stale";
  if (age > WARN_MS) return "warn";
  return "ok";
}
const HEALTH_COLOR: Record<Health, string> = {
  ok: "var(--run)",
  warn: "var(--queue)",
  stale: "var(--fail)",
};

/** Compact "N ago" for a heartbeat/uptime age. */
function fmtAge(ms: number | null): string {
  if (ms == null) return "no heartbeat";
  const s = Math.round(ms / 1000);
  if (s < 1) return "just now";
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ${s % 60}s ago`;
  const h = Math.floor(m / 60);
  return `${h}h ${m % 60}m ago`;
}

/** Compact uptime from an epoch-ms start (scheduler `started`). */
function fmtUptime(startedMs: number): string {
  if (startedMs <= 0) return "—";
  const s = Math.max(0, Math.round((Date.now() - startedMs) / 1000));
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ${m % 60}m`;
  return `${Math.floor(h / 24)}d ${h % 24}h`;
}

/** Shorten a long executor id for a node label. */
function shortId(id: string): string {
  return id.length > 14 ? `${id.slice(0, 6)}…${id.slice(-4)}` : id;
}

/** How many poll samples to retain for the live sparklines — ~2 min at the
 *  2 s poll. The APIs are snapshots (no server-side time series), so the
 *  dashboard accumulates its own short history client-side. */
const SAMPLE_CAP = 60;

/** Per-poll history buffers accumulated across the cluster poll. */
interface ClusterHistory {
  /** executor id → recent `proc_physical_memory` samples. */
  mem: Record<string, number[]>;
  /** recent running-job counts. */
  running: number[];
  /** recent jobs-completed-per-tick (Δ of `jobs_total`). */
  done: number[];
}

/** Format a millisecond duration like the Queries / History tabs. */
function fmtElapsed(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  const s = ms / 1000;
  if (s < 60) return `${s.toFixed(1)}s`;
  const m = Math.floor(s / 60);
  return `${m}m ${Math.floor(s % 60)}s`;
}

/** A Ballista job's wall-clock elapsed from its scheduler timestamps.
 *  `start_time` / `end_time` are epoch ms; `end_time` is 0 while the job is
 *  still running, so fall back to `Date.now()` for a live value that ticks
 *  with the 2s poll. Returns "—" until a start time is known. */
function jobElapsed(start: number, end: number): string {
  if (start <= 0) return "—";
  const ms = end > start ? end - start : Date.now() - start;
  return fmtElapsed(Math.max(0, ms));
}

/** Shuffle fan-out of a stage — the partition count its ShuffleWriter emits,
 *  parsed from the physical `stage_plan` (`partitioning=Hash([…], N)` /
 *  `RoundRobinBatch(N)`). This is the "data movement" between stages. */
function stagePartitions(plan: string): number | null {
  const m = plan.match(/partitioning=[A-Za-z]+\([^)]*?(\d+)\)/);
  return m ? Number(m[1]) : null;
}

/** The stage's headline operator (first line of the plan, node type only). */
function stageOp(plan: string): string {
  const first = plan.split("\n", 1)[0]?.trim() ?? "";
  return first.split(/[:\s]/, 1)[0] || first;
}

/** Compact row count (600037902 → "600.0M"). */
function fmtRows(n: number): string {
  if (n <= 0) return "0";
  if (n >= 1e9) return `${(n / 1e9).toFixed(1)}B`;
  if (n >= 1e6) return `${(n / 1e6).toFixed(1)}M`;
  if (n >= 1e3) return `${(n / 1e3).toFixed(1)}K`;
  return `${n}`;
}

/** One node in the stage-flow diagram, derived from a raw stage entry. */
interface StageNode {
  sid: string;
  status: string;
  cls: string;
  op: string;
  parts: number | null;
  inRows: number;
  outRows: number;
  done: number;
  total: number;
  pct: number;
  skew: boolean;
}

/** Derive the ordered stage-flow nodes (execution order = stage_id asc) from
 *  the raw `/api/cluster/job/{id}/stages` entries: status, headline operator,
 *  shuffle fan-out, rows in→out, task progress, and a skew flag. */
function buildStageFlow(stages: Json[]): StageNode[] {
  return stages
    .map((s, i): StageNode => {
      const sid = str(field(s, "stage_id", "id")) || `${i}`;
      const status = str(field(s, "stage_status", "status")) || "—";
      const ok = /success|completed/i.test(status);
      const cls = isTerminal(status) ? (ok ? "idle" : "fail") : "run";
      const plan = str(field(s, "stage_plan"));
      const parts = plan ? stagePartitions(plan) : null;
      const op = plan ? stageOp(plan) : "";
      const inRows = num(field(s, "input_rows"));
      const outRows = num(field(s, "output_rows"));
      const rawTasks = field(s, "tasks");
      const tasks: Json[] = Array.isArray(rawTasks) ? (rawTasks as Json[]) : [];
      const total = tasks.length;
      const done = tasks.filter((t) => num(field(t as Json, "finish_time")) > 0).length;
      const pct = total > 0 ? Math.round((done / total) * 100) : 0;
      const dp = field(s, "task_duration_percentiles") as Json | undefined;
      const median = num(field(dp, "median"));
      const max = num(field(dp, "max"));
      const skew = median > 0 && max / median >= 2;
      return { sid, status, cls, op, parts, inRows, outRows, done, total, pct, skew };
    })
    .sort((a, b) => Number(a.sid) - Number(b.sid));
}

/** Live node-link topology of the distributed cluster, hand-authored as
 *  inline SVG (no viz library — the dashboard is CSP-embedded). A scheduler
 *  node fans out to each registered executor; nodes are stroked by heartbeat
 *  health. Re-renders every cluster poll, so it is live. Responsive: the
 *  intrinsic width grows with executor count and scales down via
 *  `max-width:100%`; wide clusters scroll inside `.topo-wrap`. */
function ClusterTopology({
  scheduler,
  executors,
  server,
  runningJobs,
}: {
  scheduler: Json | undefined;
  executors: Json[];
  server: ServerInfo | null;
  runningJobs: number;
}) {
  const n = executors.length;
  const NODE_W = 152;
  const NODE_H = 84;
  const GAP = 30;
  const SCHED_W = 240;
  const SCHED_H = 64;
  const PAD = 18;
  const rowW = n > 0 ? n * NODE_W + (n - 1) * GAP : 0;
  const W = Math.max(SCHED_W + 2 * PAD, rowW + 2 * PAD, 520);
  const H = PAD + SCHED_H + 60 + NODE_H + PAD;
  const schedCx = W / 2;
  const schedX = schedCx - SCHED_W / 2;
  const schedY = PAD;
  const schedBottom = schedY + SCHED_H;
  const rowY = H - PAD - NODE_H;
  const startX = schedCx - rowW / 2;
  const linkMidY = (schedBottom + rowY) / 2;

  const schedVersion = str(field(scheduler, "version"));
  const schedAddr = server?.ballista
    ? `:${server.ballista.scheduler_grpc_port} grpc`
    : "scheduler";
  const active = runningJobs > 0;

  return (
    <div className="topo-wrap">
      <svg
        className="topo"
        viewBox={`0 0 ${W} ${H}`}
        width={W}
        preserveAspectRatio="xMidYMin meet"
        role="img"
        aria-label={`Cluster topology: scheduler and ${n} executor${n === 1 ? "" : "s"}`}
      >
        {/* edges scheduler → executors */}
        {executors.map((e, i) => {
          const id = str(field(e, "id", "executor_id")) || `exec-${i}`;
          const cx = startX + i * (NODE_W + GAP) + NODE_W / 2;
          const d = `M ${schedCx} ${schedBottom} C ${schedCx} ${linkMidY}, ${cx} ${linkMidY}, ${cx} ${rowY}`;
          return (
            <path
              key={`edge-${id}`}
              className={`topo-edge${active ? " active" : ""}`}
              d={d}
              fill="none"
            />
          );
        })}

        {/* scheduler node */}
        <g className="topo-node">
          <rect
            className={`topo-sched${active ? " active" : ""}`}
            x={schedX}
            y={schedY}
            width={SCHED_W}
            height={SCHED_H}
            rx={10}
          />
          <text className="topo-role" x={schedCx} y={schedY + 20} textAnchor="middle">
            SCHEDULER
          </text>
          <text className="topo-id" x={schedCx} y={schedY + 38} textAnchor="middle">
            {schedVersion ? `ballista ${schedVersion}` : "ballista"}
          </text>
          <text className="topo-sub" x={schedCx} y={schedY + 53} textAnchor="middle">
            {schedAddr}
            {active ? ` · ${runningJobs} running` : " · idle"}
          </text>
        </g>

        {/* executor nodes */}
        {n === 0 && (
          <text className="topo-sub" x={schedCx} y={rowY + NODE_H / 2} textAnchor="middle">
            no executors registered
          </text>
        )}
        {executors.map((e, i) => {
          const id = str(field(e, "id", "executor_id")) || `exec-${i}`;
          const host = str(field(e, "host", "optional_host"));
          const port = str(field(e, "port"));
          const slots = num(field(e, "task_slots"));
          const age = heartbeatAge(e);
          const health = execHealth(age);
          const color = HEALTH_COLOR[health];
          const x = startX + i * (NODE_W + GAP);
          const pips = Math.min(slots, 10);
          return (
            <g className="topo-node" key={`node-${id}`}>
              <rect
                className={`topo-exec${health === "stale" ? " stale" : ""}`}
                x={x}
                y={rowY}
                width={NODE_W}
                height={NODE_H}
                rx={10}
                style={{ stroke: color }}
              />
              <circle cx={x + 14} cy={rowY + 16} r={4} fill={color} />
              <text className="topo-id" x={x + 26} y={rowY + 20} textAnchor="start">
                {shortId(id)}
              </text>
              <text className="topo-sub" x={x + NODE_W / 2} y={rowY + 38} textAnchor="middle">
                {host ? `${host}${port ? `:${port}` : ""}` : "—"}
              </text>
              {/* slot capacity pips (used-per-executor is not exposed) */}
              {Array.from({ length: pips }, (_, k) => (
                <rect
                  key={k}
                  className="topo-slot"
                  x={x + 12 + k * ((NODE_W - 24) / Math.max(1, pips)) }
                  y={rowY + 48}
                  width={Math.max(4, (NODE_W - 24) / Math.max(1, pips) - 3)}
                  height={7}
                  rx={2}
                />
              ))}
              <text className="topo-sub" x={x + NODE_W / 2} y={rowY + 74} textAnchor="middle">
                {slots} slots · {fmtAge(age)}
              </text>
            </g>
          );
        })}
      </svg>
      <div className="legend legend-row">
        <span>
          <i style={{ background: "var(--run)" }} /> alive
        </span>
        <span>
          <i style={{ background: "var(--queue)" }} /> lagging (&gt;{WARN_MS / 1000}s)
        </span>
        <span>
          <i style={{ background: "var(--fail)" }} /> stale (&gt;{STALE_MS / 1000}s)
        </span>
        <span>
          <i style={{ background: "var(--accent)" }} /> scheduler
        </span>
      </div>
    </div>
  );
}

/** Scheduler status card — address/ports from `ServerInfo.ballista`, and
 *  version / DataFusion / scheduling policy / uptime from the live
 *  `/api/state` payload (`cluster.scheduler`). */
function SchedulerCard({
  scheduler,
  server,
}: {
  scheduler: Json | undefined;
  server: ServerInfo | null;
}) {
  const version = str(field(scheduler, "version"));
  const df = str(field(scheduler, "datafusion_version"));
  const policy = str(field(scheduler, "scheduling_policy"));
  const started = num(field(scheduler, "started"));
  const b = server?.ballista;
  return (
    <div className="sched-card">
      <div className="metric-head">
        <span>scheduler</span>
        <span className="mono">{version ? `ballista ${version}` : "—"}</span>
      </div>
      <div className="sched-grid">
        {b && (
          <div>
            <div className="k">grpc</div>
            <div className="v mono">:{b.scheduler_grpc_port}</div>
          </div>
        )}
        {b?.rest_api_port != null && (
          <div>
            <div className="k">rest api</div>
            <div className="v mono">:{b.rest_api_port}</div>
          </div>
        )}
        {df && (
          <div>
            <div className="k">datafusion</div>
            <div className="v mono">{df}</div>
          </div>
        )}
        {policy && (
          <div>
            <div className="k">policy</div>
            <div className="v mono">{policy}</div>
          </div>
        )}
        {started > 0 && (
          <div>
            <div className="k">uptime</div>
            <div className="v mono">{fmtUptime(started)}</div>
          </div>
        )}
      </div>
    </div>
  );
}

/** The Cluster tab: executors + jobs from the Ballista scheduler proxy
 *  (/api/cluster), a headline stat row, and a per-job stage pipeline
 *  drill-down (slice 5a) — Ballista stages form a shuffle-separated
 *  pipeline, so the ordered stage cards *are* the execution diagram. */
export function Cluster({
  cluster,
  server,
  runningCount,
}: {
  cluster: ClusterSummary | null;
  server?: ServerInfo | null;
  runningCount: number;
}) {
  const [selectedJob, setSelectedJob] = useState<string | null>(null);
  const [stages, setStages] = useState<Json[]>([]);

  // Client-side history for the live sparklines (memory + throughput). The
  // cluster prop is a fresh snapshot each poll; we append to a bounded ring.
  const [history, setHistory] = useState<ClusterHistory>({
    mem: {},
    running: [],
    done: [],
  });
  const prevJobsTotal = useRef<number | null>(null);

  useEffect(() => {
    if (!cluster?.available) return;
    const execs = cluster.executors ?? [];
    const total = cluster.jobs_total ?? cluster.jobs?.length ?? 0;
    const doneDelta =
      prevJobsTotal.current == null ? 0 : Math.max(0, total - prevJobsTotal.current);
    prevJobsTotal.current = total;
    const running = cluster.running_jobs ?? 0;
    setHistory((prev) => {
      const mem: Record<string, number[]> = {};
      for (const e of execs) {
        const id = str(field(e, "id", "executor_id")) || "?";
        const rss = metric(e, "proc_physical_memory");
        mem[id] = [...(prev.mem[id] ?? []), rss].slice(-SAMPLE_CAP);
      }
      return {
        mem,
        running: [...prev.running, running].slice(-SAMPLE_CAP),
        done: [...prev.done, doneDelta].slice(-SAMPLE_CAP),
      };
    });
  }, [cluster]);

  // Poll stages for the selected job while it's open.
  useEffect(() => {
    if (!selectedJob) {
      setStages([]);
      return;
    }
    let stop = false;
    const ctrl = new AbortController();
    const tick = async () => {
      try {
        const raw = await getClusterJobStages(selectedJob, ctrl.signal);
        if (!stop) setStages(asStages(raw));
      } catch {
        /* job may have finished/evicted — keep the last view */
      }
    };
    void tick();
    const h = setInterval(() => void tick(), 2000);
    return () => {
      stop = true;
      ctrl.abort();
      clearInterval(h);
    };
  }, [selectedJob]);

  if (!cluster) {
    return <p className="muted">Loading cluster…</p>;
  }

  if (!cluster.available) {
    return (
      <div className="empty">
        <p>
          <b>Cluster monitoring unavailable.</b>
        </p>
        <p>{cluster.note ?? "The scheduler API is not reachable."}</p>
        <p className="muted">
          Run distributed (multi-executor / <span className="mono">--distributed</span>) with{" "}
          <span className="mono">ballista.rest_api_port</span> set to see live executors and jobs.
        </p>
      </div>
    );
  }

  const executors = cluster.executors ?? [];
  const jobs = cluster.jobs ?? [];
  const jobsTotal = cluster.jobs_total ?? jobs.length;
  const totalSlots = executors.reduce((acc, e) => acc + num(field(e, "task_slots")), 0);
  // Prefer the server's count (computed over ALL jobs); fall back to the
  // capped page for an older server without the field.
  const runningJobs =
    cluster.running_jobs ??
    jobs.filter((j) => !isTerminal(str(field(j, "job_status", "status")))).length;

  return (
    <>
      <div className="stat-row">
        <div className="stat">
          <div className="k">Executors</div>
          <div className="v">{executors.length}</div>
        </div>
        <div className="stat">
          <div className="k">Task slots</div>
          <div className="v">{totalSlots}</div>
        </div>
        <div className="stat">
          <div className="k">Running jobs</div>
          <div className="v" style={{ color: runningJobs ? "var(--run)" : undefined }}>
            {runningJobs}
          </div>
        </div>
        <div className="stat">
          <div className="k">Running queries</div>
          <div className="v" style={{ color: runningCount ? "var(--run)" : undefined }}>
            {runningCount}
          </div>
        </div>
      </div>

      <div className="section-h">Topology</div>
      <SchedulerCard scheduler={cluster.scheduler} server={server ?? null} />
      <ClusterTopology
        scheduler={cluster.scheduler}
        executors={executors}
        server={server ?? null}
        runningJobs={runningJobs}
      />

      <div className="section-h">Executors ({executors.length})</div>
      {executors.length === 0 ? (
        <p className="muted">No executors registered.</p>
      ) : (
        <div className="exec-strip">
          {executors.map((e, i) => {
            const id = str(field(e, "id", "executor_id")) || `exec-${i}`;
            const host = str(field(e, "host", "optional_host"));
            const port = str(field(e, "port"));
            const slots = num(field(e, "task_slots"));
            const age = heartbeatAge(e);
            const health = execHealth(age);
            const rss = metric(e, "proc_physical_memory");
            const peak = metric(e, "peak_physical_memory");
            const diskFree = osInfo(e, "total_available_disk_space");
            const diskTotal = osInfo(e, "total_disk_space");
            const diskFrac = diskTotal > 0 ? diskFree / diskTotal : 0;
            const memSeries = history.mem[id] ?? (rss ? [rss] : []);
            return (
              <div className="exec exec-wide" key={id}>
                <div className="id" title={id}>
                  <i
                    className="hb-dot"
                    style={{ background: HEALTH_COLOR[health] }}
                    title={`heartbeat ${fmtAge(age)}`}
                    aria-hidden
                  />
                  {id.length > 18 ? `${id.slice(0, 8)}…${id.slice(-4)}` : id}
                </div>
                <div className="m">
                  {host ? `${host}${port ? `:${port}` : ""}` : "—"} · heartbeat {fmtAge(age)}
                </div>
                {/* Slot capacity — the scheduler does not expose per-executor
                    used/active slot counts, so these pips show total capacity,
                    not utilization (see caption below the strip). */}
                <div className="metric-head">
                  <span>slots (capacity)</span>
                  <span className="mono">{slots}</span>
                </div>
                <div className="slots" aria-hidden>
                  {Array.from({ length: Math.min(slots, 16) }, (_, k) => (
                    <i className="cap" key={k} />
                  ))}
                </div>
                {rss > 0 && (
                  <>
                    <div className="metric-head">
                      <span>memory</span>
                      <span className="mono">
                        {fmtBytes(rss)}
                        {peak > 0 ? ` · peak ${fmtBytes(peak)}` : ""}
                      </span>
                    </div>
                    <Sparkline
                      values={memSeries}
                      max={peak > 0 ? peak : undefined}
                      peak={peak > 0 ? peak : undefined}
                      stroke="var(--accent)"
                      height={34}
                    />
                  </>
                )}
                {diskTotal > 0 && (
                  <>
                    <div className="metric-head">
                      <span>disk free</span>
                      <span className="mono">
                        {fmtBytes(diskFree)} · {Math.round(diskFrac * 100)}%
                      </span>
                    </div>
                    <FillBar
                      fraction={diskFrac}
                      tone={
                        diskFrac < 0.1
                          ? "var(--fail)"
                          : diskFrac < 0.25
                            ? "var(--queue)"
                            : "var(--run)"
                      }
                    />
                  </>
                )}
              </div>
            );
          })}
        </div>
      )}

      {executors.length > 0 && (
        <p className="caption">
          Slot pips show each executor&apos;s <b>task-slot capacity</b>. The scheduler API
          does not report live per-executor slot usage, so no used/free split is shown —
          see the per-job <span className="mono">query fan-out</span> below for how far a
          running query spreads across the cluster.
        </p>
      )}

      <div className="section-h">Cluster activity (last {history.running.length} polls)</div>
      <div className="chart-grid">
        <div className="chart-card">
          <div className="metric-head">
            <span>running jobs</span>
            <span className="mono">{runningJobs}</span>
          </div>
          <Sparkline values={history.running} stroke="var(--run)" height={44} width={320} />
        </div>
        <div className="chart-card">
          <div className="metric-head">
            <span>jobs completed / poll</span>
            <span className="mono">Σ {history.done.reduce((a, b) => a + b, 0)}</span>
          </div>
          <Sparkline values={history.done} stroke="var(--accent)" height={44} width={320} />
        </div>
      </div>

      <div className="section-h">
        Jobs ({jobsTotal > jobs.length ? `${jobs.length} of ${jobsTotal}, newest` : jobsTotal})
      </div>
      {jobs.length === 0 ? (
        <p className="muted">No jobs submitted this session.</p>
      ) : (
        <div className="tbl-wrap">
          <table>
            <thead>
              <tr>
                <th>Job</th>
                <th>Status</th>
                <th>Stages</th>
                <th>Elapsed</th>
              </tr>
            </thead>
            <tbody>
              {jobs.map((j, i) => {
                const id = str(field(j, "id", "job_id")) || `job-${i}`;
                const status = str(field(j, "job_status", "status")) || "unknown";
                // Ballista's job_status is verbose — e.g. "Completed. Produced
                // 1 partition containing 1 row. Elapsed time: 7 ms." Show only
                // the leading state in the pill; the dedicated Elapsed column
                // now carries the timing. Trim at the first "." or ":".
                const statusLabel = status.split(/[.:]/, 1)[0].trim() || status;
                const stagesN = field(j, "num_stages", "total_stages", "stages");
                const startMs = num(field(j, "start_time", "start"));
                const endMs = num(field(j, "end_time", "end"));
                const terminal = isTerminal(status);
                const ok = /success|completed/i.test(status);
                const cls = terminal ? (ok ? "idle" : "fail") : "run";
                const open = selectedJob === id;
                return (
                  <tr
                    key={id}
                    onClick={() => setSelectedJob(open ? null : id)}
                    className={open ? "row-open" : "row-click"}
                  >
                    <td className="mono">
                      {open ? "▾ " : "▸ "}
                      {id}
                    </td>
                    <td>
                      <span className={`pill ${cls}`} title={status}>
                        {statusLabel.toUpperCase()}
                      </span>
                    </td>
                    <td className="mono">{stagesN === undefined ? "—" : num(stagesN)}</td>
                    <td className="mono">{jobElapsed(startMs, endMs)}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {selectedJob && (
        <>
          <div className="section-h">
            Stage pipeline · <span className="mono">{selectedJob}</span>
          </div>
          {stages.length === 0 ? (
            <p className="muted">No stage detail (job finished, evicted, or not yet scheduled).</p>
          ) : (
            <>
              {(() => {
                // Query fan-out: the widest stage's task count against
                // the cluster's total slots — how much of the cluster this query
                // actually spreads across. ≥100% means every slot is in play.
                const flow = buildStageFlow(stages);
                const widest = Math.max(0, ...flow.map((n) => n.total));
                if (widest === 0 || totalSlots === 0) return null;
                const frac = Math.min(widest, totalSlots) / totalSlots;
                return (
                  <div className="chart-card fanout">
                    <div className="metric-head">
                      <span>query fan-out · widest stage</span>
                      <span className="mono">
                        {widest} tasks / {totalSlots} slots
                        {widest >= totalSlots ? " · full" : ""}
                      </span>
                    </div>
                    <FillBar
                      fraction={frac}
                      tone={frac >= 0.99 ? "var(--run)" : "var(--queue)"}
                    />
                  </div>
                );
              })()}
              <div className="stage-flow">
                {buildStageFlow(stages).map((n, i, arr) => (
                  <Fragment key={n.sid}>
                    {i > 0 && (
                      <div
                        className="stage-edge"
                        title={
                          arr[i - 1].parts != null
                            ? `${arr[i - 1].parts} shuffle partitions`
                            : "data movement"
                        }
                      >
                        <span className="arrow">→</span>
                        {arr[i - 1].parts != null && (
                          <span className="parts">{arr[i - 1].parts}p</span>
                        )}
                      </div>
                    )}
                    <div className="exec stage-node">
                      <div className="id">
                        stage {n.sid}{" "}
                        <span className={`pill ${n.cls}`}>{n.status.toUpperCase()}</span>
                      </div>
                      <div className="m">
                        {n.op}
                        {n.parts != null ? ` · ${n.parts}p` : ""}
                      </div>
                      <div className="m">
                        {fmtRows(n.inRows)} → {fmtRows(n.outRows)} rows
                        {n.skew ? " · skew" : ""}
                      </div>
                      <div className="m">{n.total > 0 ? `${n.done}/${n.total} tasks` : "—"}</div>
                      <div className="progress" aria-hidden>
                        <span style={{ width: `${n.pct}%` }} />
                      </div>
                    </div>
                  </Fragment>
                ))}
              </div>
              <p className="caption">
                Left-to-right execution stages; the arrow label is the shuffle partition
                count (data moved between stages). <span className="mono">skew</span> flags a
                stage whose slowest task ran ≥2× its median.
              </p>
            </>
          )}
        </>
      )}
    </>
  );
}

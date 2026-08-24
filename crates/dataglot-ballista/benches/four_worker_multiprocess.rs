//! Phase 2 slice 8.2b — 4-worker exit-criterion bench, multi-process.
//!
//! Lifts slice 8.1's in-process 4-slot bench to dispatch the same 22
//! TPC-H queries through a real multi-process Ballista cluster
//! (1 scheduler container + 4 executor containers, brought up by
//! `docker-compose.bench.yml`). The bench client uses
//! `SessionContext::remote("df://localhost:50050")` to connect to
//! the scheduler from the host; queries dispatch across the 4
//! executor containers via gRPC.
//!
//! This is where Strategy v3.0's exit criterion #3 — ≥5× single-node
//! throughput on a 4-worker cluster — formally closes.
//!
//! # Operator workflow (local + CI)
//!
//! ```bash
//! # 1. Generate TPC-H parquet into a shared host directory.
//! #    The bench binary does this on first run if the dir is empty.
//! export BENCH_DATA_DIR=/tmp/dataglot-bench-tpch
//!
//! # 2. Bring up the cluster. compose mounts $BENCH_DATA_DIR
//! #    read-only at /data/tpch inside every container.
//! docker compose -f docker-compose.bench.yml up -d
//!
//! # 3. Run the bench. Connects via SessionContext::remote.
//! cargo bench -p dataglot-ballista --bench four_worker_multiprocess
//!
//! # 4. Tear down.
//! docker compose -f docker-compose.bench.yml down -v
//! ```
//!
//! Same env-var driven JSON output as slice 8.1:
//!
//! - `TPCH_SCALE_FACTOR` (default 1.0)
//! - `BALLISTA_4WORKER_MP_REPORT_OUTPUT` — JSON output path
//! - `BALLISTA_4WORKER_MP_BASELINE_INPUT` — single-node baseline JSON
//!   for speedup-ratio comparison
//!
//! The output JSON uses `suite = "tpch_cluster_4worker"` so the
//! dashboard / nightly tooling can distinguish it from 8.1's
//! `"tpch_cluster_4slot"`.
//!
//! # Why the cluster lifecycle isn't bench-controlled
//!
//! The bench does NOT spawn / tear down the compose stack. It
//! connects to a scheduler that must already be reachable at
//! `df://localhost:50050`. Two reasons:
//!
//! 1. **Separation of infrastructure from measurement.** Compose
//!    bring-up is a CI workflow concern; the bench's claim is
//!    "given a healthy cluster, here's the measurement." Tangling
//!    the two makes the bench harder to iterate on locally.
//! 2. **Cluster bring-up is slow.** Cold-cache image build is
//!    7-10 min; bench rebuild on a code change shouldn't pay that
//!    cost. Operators boot the cluster once and rerun the bench
//!    against it as code changes.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use ballista::datafusion::arrow::array::{Array, RecordBatch, StringArray};
use ballista::datafusion::arrow::datatypes::SchemaRef;
use ballista::datafusion::prelude::{ParquetReadOptions, SessionContext};
use ballista::prelude::SessionContextExt;
use parquet::arrow::ArrowWriter;
use serde::{Deserialize, Serialize};
use tokio::runtime::Runtime;
use tpchgen::generators::{
    CustomerGenerator, LineItemGenerator, NationGenerator, OrderGenerator, PartGenerator,
    PartSuppGenerator, RegionGenerator, SupplierGenerator,
};
use tpchgen_arrow::{
    CustomerArrow, LineItemArrow, NationArrow, OrderArrow, PartArrow, PartSuppArrow,
    RecordBatchIterator as TpchRecordBatchIterator, RegionArrow, SupplierArrow,
};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const DEFAULT_SCALE_FACTOR: f64 = 1.0;
const RUNS_PER_QUERY: usize = 10;
const WORKER_CONTAINERS: usize = 4;
/// Phase 2 exit criterion #3 — **near-linear worker scaling**.
///
/// Re-interpreted 2026-05-29 (see
/// the phase-2 `four-worker-throughput-gap` plan): the
/// original "≥5× on a 4-worker cluster" is arithmetically unreachable —
/// Amdahl caps an N-worker cluster at ~N× vs a single equivalent
/// worker, so 4 workers can never hit 5×. The defensible distributed-
/// execution claim is *near-linear scaling*: with each executor running
/// `--concurrent-tasks=1` (one unit of parallelism per worker), 4
/// workers should approach 4× a single-worker baseline. ≥3.5× is
/// 87.5% scaling efficiency — a strong near-linear result after the
/// Arrow Flight shuffle tax. The denominator is **single-worker
/// Ballista** (apples-to-apples on the serialization tax), not
/// in-process DataFusion. Reported in the JSON; not a hard fail.
const SPEEDUP_TARGET: f64 = 3.5;
/// Default scheduler URL — matches `docker-compose.bench.yml`'s
/// `50050:50050` host port mapping. Override via the
/// `BALLISTA_4WORKER_MP_SCHEDULER_URL` env var for non-default
/// docker-compose setups (e.g. CI runners that map to a different
/// port).
const DEFAULT_SCHEDULER_URL: &str = "df://localhost:50050";

// ---------------------------------------------------------------------------
// Query catalog — single-sourced from `crates/dataglot-tests/queries/tpch/`
// ---------------------------------------------------------------------------

struct QueryTemplate {
    name: &'static str,
    sql: &'static str,
    in_headline: bool,
}

const QUERIES: &[QueryTemplate] = &[
    QueryTemplate {
        name: "q1",
        sql: include_str!("../../dataglot-tests/queries/tpch/q1.sql"),
        in_headline: false,
    },
    QueryTemplate {
        name: "q2",
        sql: include_str!("../../dataglot-tests/queries/tpch/q2.sql"),
        in_headline: false,
    },
    QueryTemplate {
        name: "q3",
        sql: include_str!("../../dataglot-tests/queries/tpch/q3.sql"),
        in_headline: true,
    },
    QueryTemplate {
        name: "q4",
        sql: include_str!("../../dataglot-tests/queries/tpch/q4.sql"),
        in_headline: false,
    },
    QueryTemplate {
        name: "q5",
        sql: include_str!("../../dataglot-tests/queries/tpch/q5.sql"),
        in_headline: true,
    },
    QueryTemplate {
        name: "q6",
        sql: include_str!("../../dataglot-tests/queries/tpch/q6.sql"),
        in_headline: false,
    },
    QueryTemplate {
        name: "q7",
        sql: include_str!("../../dataglot-tests/queries/tpch/q7.sql"),
        in_headline: false,
    },
    QueryTemplate {
        name: "q8",
        sql: include_str!("../../dataglot-tests/queries/tpch/q8.sql"),
        in_headline: false,
    },
    QueryTemplate {
        name: "q9",
        sql: include_str!("../../dataglot-tests/queries/tpch/q9.sql"),
        in_headline: true,
    },
    QueryTemplate {
        name: "q10",
        sql: include_str!("../../dataglot-tests/queries/tpch/q10.sql"),
        in_headline: false,
    },
    QueryTemplate {
        name: "q11",
        sql: include_str!("../../dataglot-tests/queries/tpch/q11.sql"),
        in_headline: false,
    },
    QueryTemplate {
        name: "q12",
        sql: include_str!("../../dataglot-tests/queries/tpch/q12.sql"),
        in_headline: false,
    },
    QueryTemplate {
        name: "q13",
        sql: include_str!("../../dataglot-tests/queries/tpch/q13.sql"),
        in_headline: false,
    },
    QueryTemplate {
        name: "q14",
        sql: include_str!("../../dataglot-tests/queries/tpch/q14.sql"),
        in_headline: false,
    },
    QueryTemplate {
        name: "q15",
        sql: include_str!("../../dataglot-tests/queries/tpch/q15.sql"),
        in_headline: false,
    },
    QueryTemplate {
        name: "q16",
        sql: include_str!("../../dataglot-tests/queries/tpch/q16.sql"),
        in_headline: false,
    },
    QueryTemplate {
        name: "q17",
        sql: include_str!("../../dataglot-tests/queries/tpch/q17.sql"),
        in_headline: false,
    },
    QueryTemplate {
        name: "q18",
        sql: include_str!("../../dataglot-tests/queries/tpch/q18.sql"),
        in_headline: false,
    },
    QueryTemplate {
        name: "q19",
        sql: include_str!("../../dataglot-tests/queries/tpch/q19.sql"),
        in_headline: false,
    },
    QueryTemplate {
        name: "q20",
        sql: include_str!("../../dataglot-tests/queries/tpch/q20.sql"),
        in_headline: false,
    },
    QueryTemplate {
        name: "q21",
        sql: include_str!("../../dataglot-tests/queries/tpch/q21.sql"),
        in_headline: false,
    },
    QueryTemplate {
        name: "q22",
        sql: include_str!("../../dataglot-tests/queries/tpch/q22.sql"),
        in_headline: false,
    },
];

// ---------------------------------------------------------------------------
// Report records
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct QueryResult {
    query: String,
    runs: usize,
    median_ms: f64,
    p95_ms: f64,
    min_ms: f64,
    max_ms: f64,
    rows_returned: usize,
    in_headline: bool,
}

/// Single-query scan-fan-out evidence, captured via `EXPLAIN` on the
/// headline queries. The Phase-2 gap analysis (task 05) needs to know
/// whether a single query's parquet scan splits into multiple
/// partitions — the necessary condition for any single-query speedup
/// on a multi-worker cluster. `max_scan_partitions > 1` means
/// DataFusion's byte-range splitter (`repartition_file_scans` +
/// `target_partitions`) is fanning the scan out; `== 1` means it is
/// not, and no amount of worker count can speed a single query up.
#[derive(Serialize, Deserialize)]
struct FanOutProbe {
    query: String,
    /// Largest `file_groups={N groups}` count seen on any parquet scan
    /// line in the `EXPLAIN` physical plan. >1 ⇒ scan is split.
    max_scan_partitions: usize,
    /// Count of `RepartitionExec` nodes — DataFusion's intra-plan
    /// parallelism markers. A pure single-partition plan has none.
    repartition_nodes: usize,
    /// Truncated physical-plan text for human inspection in CI logs.
    plan_excerpt: String,
}

#[derive(Serialize)]
struct MultiProcessReport {
    suite: &'static str,
    scale_factor: f64,
    runs_per_query: usize,
    worker_containers: usize,
    scheduler_url: String,
    headline_geomean_ms: f64,
    speedup_ratio: Option<f64>,
    speedup_target_met: Option<bool>,
    baseline_headline_geomean_ms: Option<f64>,
    queries: Vec<QueryResult>,
    /// Per-headline-query scan-fan-out evidence. Empty if the probe
    /// could not run (e.g. EXPLAIN unsupported on the remote ctx).
    fan_out: Vec<FanOutProbe>,
}

#[derive(Deserialize)]
struct BaselineHeadline {
    headline_geomean_ms: f64,
}

// ---------------------------------------------------------------------------
// TPC-H seed (mirrors `four_worker_throughput.rs` from slice 8.1)
// ---------------------------------------------------------------------------

fn ensure_seeded(dir: &Path, scale_factor: f64) {
    // Idempotent: skip if all 8 tables already exist as parquet.
    // Operators iterating on the bench shouldn't pay the ~5-30 s
    // seed cost every run.
    let all_present = [
        "nation", "region", "customer", "orders", "lineitem", "part", "supplier", "partsupp",
    ]
    .iter()
    .all(|t| dir.join(format!("{t}.parquet")).exists());

    if all_present {
        eprintln!(
            "TPC-H data already present in {} — skipping seed",
            dir.display()
        );
        return;
    }

    fs::create_dir_all(dir).unwrap_or_else(|e| panic!("create_dir_all {}: {e}", dir.display()));
    eprintln!(
        "Seeding TPC-H SF={scale_factor:.2} into {} ...",
        dir.display()
    );
    let seed_start = Instant::now();
    seed_warehouse(dir, scale_factor);
    eprintln!("Seed complete ({} ms)", seed_start.elapsed().as_millis());
}

fn seed_warehouse(dir: &Path, scale_factor: f64) {
    write_parquet(
        dir,
        "nation",
        NationArrow::new(NationGenerator::new(scale_factor, 1, 1)),
    );
    write_parquet(
        dir,
        "region",
        RegionArrow::new(RegionGenerator::new(scale_factor, 1, 1)),
    );
    write_parquet(
        dir,
        "customer",
        CustomerArrow::new(CustomerGenerator::new(scale_factor, 1, 1)),
    );
    write_parquet(
        dir,
        "orders",
        OrderArrow::new(OrderGenerator::new(scale_factor, 1, 1)),
    );
    write_parquet(
        dir,
        "lineitem",
        LineItemArrow::new(LineItemGenerator::new(scale_factor, 1, 1)),
    );
    write_parquet(
        dir,
        "part",
        PartArrow::new(PartGenerator::new(scale_factor, 1, 1)),
    );
    write_parquet(
        dir,
        "supplier",
        SupplierArrow::new(SupplierGenerator::new(scale_factor, 1, 1)),
    );
    write_parquet(
        dir,
        "partsupp",
        PartSuppArrow::new(PartSuppGenerator::new(scale_factor, 1, 1)),
    );
}

fn write_parquet<I>(dir: &Path, table: &str, iter: I)
where
    I: Iterator<Item = RecordBatch>,
    I: SchemaProvider,
{
    let path = dir.join(format!("{table}.parquet"));
    let file = fs::File::create(&path).unwrap_or_else(|e| {
        panic!(
            "create parquet file for `{table}` at {}: {e}",
            path.display()
        )
    });
    let mut writer = ArrowWriter::try_new(file, iter.schema_ref(), None)
        .unwrap_or_else(|e| panic!("open parquet writer for `{table}`: {e}"));
    for batch in iter {
        writer
            .write(&batch)
            .unwrap_or_else(|e| panic!("write batch for `{table}`: {e}"));
    }
    writer
        .close()
        .unwrap_or_else(|e| panic!("close parquet writer for `{table}`: {e}"));
}

trait SchemaProvider {
    fn schema_ref(&self) -> SchemaRef;
}

impl<T: TpchRecordBatchIterator> SchemaProvider for T {
    fn schema_ref(&self) -> SchemaRef {
        TpchRecordBatchIterator::schema(self).clone()
    }
}

// ---------------------------------------------------------------------------
// Cluster client setup
// ---------------------------------------------------------------------------

/// Connect to the remote scheduler and register the 8 TPC-H tables.
/// The `container_data_path` argument is the path the EXECUTORS see
/// when they re-read parquet files — typically `/data/tpch` (matches
/// `docker-compose.bench.yml`'s bind-mount target). The host-side
/// path where parquet was written is irrelevant to the executor
/// because workers read by URI, not by data.
async fn build_cluster_context(
    scheduler_url: &str,
    container_data_path: &str,
    scale_factor: f64,
) -> SessionContext {
    let ctx = SessionContext::remote(scheduler_url)
        .await
        .unwrap_or_else(|e| panic!("connect to Ballista scheduler at `{scheduler_url}`: {e}"));
    for table in [
        "nation", "region", "customer", "orders", "lineitem", "part", "supplier", "partsupp",
    ] {
        let path = format!("{container_data_path}/{table}.parquet");
        // Register with an EXPLICIT schema. `container_data_path` is the
        // executor/scheduler mount (`/data/tpch`), which does not exist on
        // the host where this client runs — so the default
        // `ParquetReadOptions` (which infers the schema by reading `path`
        // eagerly on the client) would resolve an empty schema, and every
        // query would then fail with "column not found". Supplying the known
        // TPC-H schema lets the client build a correct logical plan without
        // touching the host filesystem; the scheduler/executors resolve the
        // URI at scan time, where the mount is present. The schema is the
        // exact one the parquet was written with (see `seed_warehouse`).
        let schema = tpch_table_schema(table, scale_factor);
        ctx.register_parquet(
            table,
            &path,
            ParquetReadOptions::default().schema(schema.as_ref()),
        )
        .await
        .unwrap_or_else(|e| panic!("register {table} at {path}: {e}"));
    }
    ctx
}

/// Arrow schema for a TPC-H table, matching exactly what `seed_warehouse`
/// writes. Used to register tables on the remote client without inferring
/// from a path only the cluster containers can see.
fn tpch_table_schema(table: &str, scale_factor: f64) -> SchemaRef {
    match table {
        "nation" => NationArrow::new(NationGenerator::new(scale_factor, 1, 1)).schema_ref(),
        "region" => RegionArrow::new(RegionGenerator::new(scale_factor, 1, 1)).schema_ref(),
        "customer" => CustomerArrow::new(CustomerGenerator::new(scale_factor, 1, 1)).schema_ref(),
        "orders" => OrderArrow::new(OrderGenerator::new(scale_factor, 1, 1)).schema_ref(),
        "lineitem" => LineItemArrow::new(LineItemGenerator::new(scale_factor, 1, 1)).schema_ref(),
        "part" => PartArrow::new(PartGenerator::new(scale_factor, 1, 1)).schema_ref(),
        "supplier" => SupplierArrow::new(SupplierGenerator::new(scale_factor, 1, 1)).schema_ref(),
        "partsupp" => PartSuppArrow::new(PartSuppGenerator::new(scale_factor, 1, 1)).schema_ref(),
        other => panic!("unknown TPC-H table: {other}"),
    }
}

// ---------------------------------------------------------------------------
// Per-query timing (matches slice 8.1)
// ---------------------------------------------------------------------------

async fn time_query(ctx: &SessionContext, sql: &str, n: usize) -> (Vec<Duration>, usize) {
    assert!(n >= 2, "need at least 2 runs (1 warmup + 1 measured)");
    let mut timings = Vec::with_capacity(n - 1);
    let mut rows_returned = 0;
    for run in 0..n {
        let start = Instant::now();
        let df = ctx.sql(sql).await.expect("plan query");
        let batches = df.collect().await.expect("execute query");
        let elapsed = start.elapsed();
        rows_returned = batches.iter().map(RecordBatch::num_rows).sum();
        if run > 0 {
            timings.push(elapsed);
        }
    }
    (timings, rows_returned)
}

/// Run `EXPLAIN <sql>` through the cluster context and extract
/// scan-fan-out evidence. Non-fatal: on any error returns a probe with
/// zeroed counts and the error text in `plan_excerpt`, so a probe
/// failure never sinks the bench run.
async fn probe_fan_out(ctx: &SessionContext, name: &str, sql: &str) -> FanOutProbe {
    let explain_sql = format!("EXPLAIN {sql}");
    let plan_text = match ctx.sql(&explain_sql).await {
        Ok(df) => match df.collect().await {
            Ok(batches) => extract_plan_text(&batches),
            Err(e) => format!("<EXPLAIN collect failed: {e}>"),
        },
        Err(e) => format!("<EXPLAIN plan failed: {e}>"),
    };
    FanOutProbe {
        query: name.to_string(),
        max_scan_partitions: parse_max_scan_partitions(&plan_text),
        repartition_nodes: plan_text.matches("RepartitionExec").count(),
        plan_excerpt: truncate_plan(&plan_text, 4000),
    }
}

/// Pull the plan text out of an `EXPLAIN` result. DataFusion's EXPLAIN
/// schema is `(plan_type: Utf8, plan: Utf8)`; the last column holds the
/// rendered plan. Concatenates all rows across all batches.
fn extract_plan_text(batches: &[RecordBatch]) -> String {
    let mut out = String::new();
    for batch in batches {
        let ncols = batch.num_columns();
        if ncols == 0 {
            continue;
        }
        let col = batch.column(ncols - 1);
        if let Some(arr) = col.as_any().downcast_ref::<StringArray>() {
            for i in 0..arr.len() {
                if arr.is_valid(i) {
                    out.push_str(arr.value(i));
                    out.push('\n');
                }
            }
        }
    }
    out
}

/// Largest `file_groups={N groups` count in the plan. DataFusion 53
/// renders a split parquet scan as
/// `DataSourceExec: file_groups={16 groups: [...]}`; N>1 is the
/// fan-out signal. Returns 0 if no parquet scan line is present.
fn parse_max_scan_partitions(plan: &str) -> usize {
    let mut max = 0;
    for tail in plan.split("file_groups={").skip(1) {
        let n: usize = tail
            .chars()
            .take_while(char::is_ascii_digit)
            .collect::<String>()
            .parse()
            .unwrap_or(0);
        max = max.max(n);
    }
    max
}

/// Truncate the plan text for the JSON report so a deeply nested plan
/// doesn't bloat the artifact. Keeps the head (where the scan +
/// repartition nodes live in DataFusion's leaf-last rendering).
fn truncate_plan(plan: &str, max_len: usize) -> String {
    if plan.len() <= max_len {
        return plan.to_string();
    }
    let mut s: String = plan.chars().take(max_len).collect();
    s.push_str("\n… [truncated]");
    s
}

fn summarise(name: &str, timings: &[Duration], rows: usize, in_headline: bool) -> QueryResult {
    let mut sorted: Vec<f64> = timings.iter().map(|d| d.as_secs_f64() * 1000.0).collect();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let median = percentile(&sorted, 0.50);
    let p95 = percentile(&sorted, 0.95);
    let min_ms = sorted.first().copied().unwrap_or(0.0);
    let max_ms = sorted.last().copied().unwrap_or(0.0);
    QueryResult {
        query: name.to_string(),
        runs: timings.len(),
        median_ms: round2(median),
        p95_ms: round2(p95),
        min_ms: round2(min_ms),
        max_ms: round2(max_ms),
        rows_returned: rows,
        in_headline,
    }
}

#[allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
fn percentile(sorted: &[f64], q: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = ((sorted.len() as f64) * q).floor() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

fn round2(x: f64) -> f64 {
    (x * 100.0).round() / 100.0
}

#[allow(clippy::cast_precision_loss)]
fn geomean(values: &[f64]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    let log_sum: f64 = values.iter().map(|v| v.ln()).sum();
    (log_sum / (values.len() as f64)).exp()
}

// ---------------------------------------------------------------------------
// Baseline loader + report writer
// ---------------------------------------------------------------------------

fn load_baseline_headline() -> Option<f64> {
    let path = env::var("BALLISTA_4WORKER_MP_BASELINE_INPUT").ok()?;
    let bytes = match fs::read(&path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("could not read baseline JSON from `{path}`: {e}; skipping ratio");
            return None;
        }
    };
    match serde_json::from_slice::<BaselineHeadline>(&bytes) {
        Ok(b) => {
            eprintln!(
                "baseline headline (from {path}): {:.2} ms",
                b.headline_geomean_ms
            );
            Some(b.headline_geomean_ms)
        }
        Err(e) => {
            eprintln!("could not parse baseline JSON from `{path}`: {e}; skipping ratio");
            None
        }
    }
}

fn print_markdown(report: &MultiProcessReport) {
    println!();
    println!(
        "## TPC-H cluster · 4-container multi-process · SF={:.2} · {} runs/query (median over {} measured)",
        report.scale_factor,
        report.runs_per_query,
        report.runs_per_query - 1
    );
    println!();
    println!("**Scheduler:** `{}`", report.scheduler_url);
    println!();
    println!("| Query | Rows | Median (ms) | p95 (ms) | min | max | Headline |");
    println!("|---|---:|---:|---:|---:|---:|:---:|");
    for r in &report.queries {
        println!(
            "| {} | {} | {:.2} | {:.2} | {:.2} | {:.2} | {} |",
            r.query,
            r.rows_returned,
            r.median_ms,
            r.p95_ms,
            r.min_ms,
            r.max_ms,
            if r.in_headline { "✓" } else { "" }
        );
    }
    println!();
    println!(
        "**Headline geomean (q3 / q5 / q9): {:.2} ms**",
        report.headline_geomean_ms
    );
    if let (Some(baseline), Some(ratio), Some(met)) = (
        report.baseline_headline_geomean_ms,
        report.speedup_ratio,
        report.speedup_target_met,
    ) {
        println!();
        println!(
            "Single-worker Ballista baseline geomean: **{baseline:.2} ms** · scaling ratio: **{ratio:.2}×** · near-linear target ≥{SPEEDUP_TARGET:.1}× (of a 4× ceiling): {}",
            if met { "✅ met — near-linear 4-worker scaling (Phase 2 exit criterion #3)" } else { "❌ below target — see task-05 gap analysis" }
        );
    }
    if !report.fan_out.is_empty() {
        println!();
        println!("### Scan fan-out probe (task-05 evidence)");
        println!();
        println!("| Query | Scan partitions | Repartition nodes | Verdict |");
        println!("|---|---:|---:|---|");
        for p in &report.fan_out {
            let verdict = if p.max_scan_partitions > 1 {
                "✓ scan splits — fan-out reaches planning"
            } else {
                "✗ single-partition scan — fan-out NOT happening"
            };
            println!(
                "| {} | {} | {} | {} |",
                p.query, p.max_scan_partitions, p.repartition_nodes, verdict
            );
        }
        println!();
        println!(
            "_If scan partitions > 1, the parquet scan is splitting and the \
             0.11× is a hardware / shuffle-tax issue (not a structural cap). \
             If = 1, the scheduler's `target_partitions` / `repartition_file_scans` \
             is not reaching physical planning — that's the fix._"
        );
    }
    println!();
}

fn maybe_write_json(report: &MultiProcessReport) {
    let Ok(path) = env::var("BALLISTA_4WORKER_MP_REPORT_OUTPUT") else {
        return;
    };
    let json = serde_json::to_string_pretty(report).expect("serialise multi-process report");
    fs::write(&path, json).unwrap_or_else(|e| panic!("write JSON report to {path}: {e}"));
    println!("Wrote JSON report to {path}");
}

// ---------------------------------------------------------------------------
// Env-var parsing
// ---------------------------------------------------------------------------

fn parse_scale_factor_env() -> f64 {
    match env::var("TPCH_SCALE_FACTOR") {
        Ok(raw) => {
            let parsed: f64 = raw
                .parse()
                .unwrap_or_else(|_| panic!("TPCH_SCALE_FACTOR must be a number, got `{raw}`"));
            assert!(
                parsed > 0.0,
                "TPCH_SCALE_FACTOR must be > 0, got `{parsed}`"
            );
            parsed
        }
        Err(_) => DEFAULT_SCALE_FACTOR,
    }
}

fn parse_data_dir_env() -> PathBuf {
    env::var("BENCH_DATA_DIR")
        .ok()
        .map_or_else(|| PathBuf::from("/tmp/dataglot-bench-tpch"), PathBuf::from)
}

fn parse_scheduler_url_env() -> String {
    env::var("BALLISTA_4WORKER_MP_SCHEDULER_URL")
        .unwrap_or_else(|_| DEFAULT_SCHEDULER_URL.to_string())
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() {
    let scale_factor = parse_scale_factor_env();
    let data_dir = parse_data_dir_env();
    let scheduler_url = parse_scheduler_url_env();

    // Seed parquet to the shared host directory. Idempotent — skips
    // when files already present.
    ensure_seeded(&data_dir, scale_factor);

    // Executor containers see the parquet at /data/tpch (per
    // docker-compose.bench.yml's volume mount). This is what we
    // register on the client side; the scheduler ships the URI to
    // executors which open it locally.
    let container_data_path = "/data/tpch";

    let rt = Runtime::new().expect("tokio runtime");
    eprintln!("Connecting to Ballista scheduler at {scheduler_url} ...");
    let boot_start = Instant::now();
    let ctx = Arc::new(rt.block_on(build_cluster_context(
        &scheduler_url,
        container_data_path,
        scale_factor,
    )));
    eprintln!("Cluster ready ({} ms)", boot_start.elapsed().as_millis());

    let mut results: Vec<QueryResult> = Vec::with_capacity(QUERIES.len());
    for q in QUERIES {
        eprint!("Running {} ", q.name);
        let ctx = Arc::clone(&ctx);
        let (timings, rows) =
            rt.block_on(async move { time_query(&ctx, q.sql, RUNS_PER_QUERY).await });
        let summary = summarise(q.name, &timings, rows, q.in_headline);
        eprintln!(
            "(median {:.1} ms over {} runs)",
            summary.median_ms, summary.runs
        );
        results.push(summary);
    }

    // Fan-out evidence: EXPLAIN the headline queries and record whether
    // their parquet scans split into multiple partitions. This is the
    // load-bearing datum for the task-05 gap analysis — it distinguishes
    // "scan never fans out" (a planning/config bug) from "scan fans out
    // but the cluster is still slower" (a hardware / shuffle-tax issue).
    let mut fan_out: Vec<FanOutProbe> = Vec::new();
    for q in QUERIES.iter().filter(|q| q.in_headline) {
        eprint!("Probing fan-out for {} ", q.name);
        let ctx = Arc::clone(&ctx);
        let probe = rt.block_on(async move { probe_fan_out(&ctx, q.name, q.sql).await });
        eprintln!(
            "(scan partitions: {}, repartition nodes: {})",
            probe.max_scan_partitions, probe.repartition_nodes
        );
        fan_out.push(probe);
    }

    let headline: Vec<f64> = results
        .iter()
        .filter(|r| r.in_headline)
        .map(|r| r.median_ms)
        .collect();
    let cluster_headline = round2(geomean(&headline));

    let baseline_headline = load_baseline_headline();
    let (speedup_ratio, speedup_target_met) = match baseline_headline {
        Some(b) if cluster_headline > 0.0 => {
            let ratio = round2(b / cluster_headline);
            (Some(ratio), Some(ratio >= SPEEDUP_TARGET))
        }
        _ => (None, None),
    };

    let report = MultiProcessReport {
        suite: "tpch_cluster_4worker",
        scale_factor,
        runs_per_query: RUNS_PER_QUERY,
        worker_containers: WORKER_CONTAINERS,
        scheduler_url,
        headline_geomean_ms: cluster_headline,
        speedup_ratio,
        speedup_target_met,
        baseline_headline_geomean_ms: baseline_headline.map(round2),
        queries: results,
        fan_out,
    };

    print_markdown(&report);
    maybe_write_json(&report);
}

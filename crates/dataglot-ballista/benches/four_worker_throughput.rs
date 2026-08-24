//! Phase 2 slice 8.1 — 4-worker exit-criterion benchmark (in-process cut).
//!
//! Runs the same 22 TPC-H queries `dataglot-tests::tpch_baseline`
//! runs single-node, but through a Ballista standalone cluster with
//! `with_standalone_parallelism(4)` — measuring how the query path
//! behaves with 4 concurrent worker slots versus the single-node
//! denominator. Outputs JSON in the same shape as
//! `tpch-baseline.json`, plus a `speedup_ratio` and
//! `speedup_target_met` field that compares against the baseline
//! report.
//!
//! # Why "in-process 4-slot" and not "docker-compose 4-container"
//!
//! The spec asks for a real distributed cluster
//! (docker-compose with 4 executor containers + 1 coordinator).
//! Slice 8.1 (this file) intentionally takes the lighter cut:
//! one Ballista standalone cluster boots in-process, `with_standalone_parallelism(4)`
//! gives it 4 concurrent task slots, and the same `BallistaQueryPlanner`
//! that ships work to executors in real clusters dispatches across
//! those slots. The wire format is exercised end-to-end (every
//! query round-trips through `datafusion-proto` to the in-process
//! executor; slice 4b.3 + 4b.4 wire the codecs).
//!
//! What this CAN'T measure: cross-process scheduler latency,
//! gRPC serialization overhead, network shuffle cost, multi-host
//! scheduling contention. Slice 8.2 lifts to docker-compose for
//! those — that's where Strategy v3.0's exit criterion #3 (≥5×
//! throughput on 4-worker cluster) actually gets gated. Slice 8.1
//! is the intermediate measurement point: numbers from an in-
//! process 4-slot run set the floor on what's achievable; the
//! gap between 8.1 and 8.2 surfaces what cross-process costs us.
//!
//! # Running locally
//!
//! ```bash
//! # Default: SF1, all 22 queries, emit markdown to stdout
//! cargo bench -p dataglot-ballista --bench four_worker_throughput
//!
//! # With JSON output (also reads tpch-baseline.json for ratio):
//! BALLISTA_4WORKER_REPORT_OUTPUT=/tmp/phase2-benchmarks.json \
//! BALLISTA_4WORKER_BASELINE_INPUT=path/to/tpch-baseline.json \
//!     cargo bench -p dataglot-ballista --bench four_worker_throughput
//!
//! # Faster local iteration (SF=0.1, smaller dataset):
//! TPCH_SCALE_FACTOR=0.1 cargo bench -p dataglot-ballista --bench four_worker_throughput
//! ```
//!
//! # JSON report shape
//!
//! Mirrors `tpch-baseline.json` byte-for-byte for `queries[]` and
//! `headline_geomean_ms`, plus two new fields:
//!
//! - `speedup_ratio`: `baseline.headline_geomean_ms /
//!   cluster.headline_geomean_ms`. Higher is better. The Phase 2
//!   exit criterion is ≥5.0 in slice 8.2's docker-compose run; 8.1
//!   reports whatever the in-process 4-slot path delivers.
//! - `speedup_target_met`: `bool` — true iff `speedup_ratio >= 5.0`.
//!   Slice 8.1 reports the value but does not panic when false;
//!   the PR description carries the gap analysis per the spec.
//!
//! The `suite` field is `"tpch_cluster_4slot"` (vs the baseline's
//! `"tpch"`) so dashboard / nightly tooling can distinguish.

use std::env;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ballista::datafusion::arrow::array::RecordBatch;
use ballista::datafusion::arrow::datatypes::SchemaRef;
use ballista::datafusion::prelude::{ParquetReadOptions, SessionContext};
use dataglot_ballista::BallistaContextFactory;
use dataglot_core::SessionConfig;
use parquet::arrow::ArrowWriter;
use serde::{Deserialize, Serialize};
use tempfile::TempDir;
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
/// Slice 8 spec: 4-worker exit-criterion benchmark. In 8.1 this is
/// the standalone-parallelism setting handed to
/// `BallistaContextFactory`; in 8.2 it'll be the number of
/// executor containers in `docker-compose.bench.yml`.
const WORKER_SLOTS: usize = 4;
/// Phase 2 exit criterion #3 — ≥5× single-node throughput on the
/// 4-worker cluster. Slice 8.1 reports the ratio (in-process
/// 4-slot vs single-node); slice 8.2 measures it on real
/// docker-compose containers, which is where the criterion
/// formally closes.
const SPEEDUP_TARGET: f64 = 5.0;

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

/// Cluster-side report. Same shape as `tpch-baseline.json`'s
/// `Report` plus two fields capturing the speedup-vs-single-node
/// comparison.
#[derive(Serialize)]
struct ClusterReport {
    suite: &'static str,
    scale_factor: f64,
    runs_per_query: usize,
    worker_slots: usize,
    headline_geomean_ms: f64,
    /// `baseline_headline_geomean_ms / headline_geomean_ms` — higher
    /// is better. `None` when no baseline JSON was supplied (e.g.
    /// local runs without `BALLISTA_4WORKER_BASELINE_INPUT` set).
    speedup_ratio: Option<f64>,
    /// `Some(ratio >= SPEEDUP_TARGET)` when a baseline was loaded;
    /// `None` otherwise.
    speedup_target_met: Option<bool>,
    /// Echo of the baseline's headline geomean for traceability.
    /// `None` when no baseline was loaded.
    baseline_headline_geomean_ms: Option<f64>,
    queries: Vec<QueryResult>,
}

/// Subset of the baseline JSON we need — just the headline geomean.
/// We don't deserialize the full shape because that would couple
/// us to `tpch-baseline.json`'s evolving fields.
#[derive(Deserialize)]
struct BaselineHeadline {
    headline_geomean_ms: f64,
}

// ---------------------------------------------------------------------------
// Data gen + warehouse seed (mirrors tpch_baseline.rs)
// ---------------------------------------------------------------------------

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
// Ballista session-context factory — the slice-8 swap point
// ---------------------------------------------------------------------------

/// Boot a Ballista standalone cluster with `WORKER_SLOTS` task
/// slots, then register the 8 TPC-H tables from the seeded
/// warehouse directory. Returns one `SessionContext` against the
/// running cluster; the cluster lives as long as the `SessionContext`
/// (its `BallistaQueryPlanner` carries the only handle to the
/// in-process scheduler).
async fn build_cluster_context(warehouse_dir: &Path) -> SessionContext {
    let factory =
        BallistaContextFactory::new(SessionConfig::new()).with_standalone_parallelism(WORKER_SLOTS);
    let ctx = factory
        .create_standalone_context()
        .await
        .expect("ballista standalone cluster boots");
    for table in [
        "nation", "region", "customer", "orders", "lineitem", "part", "supplier", "partsupp",
    ] {
        let path = warehouse_dir.join(format!("{table}.parquet"));
        let path_str = path
            .to_str()
            .unwrap_or_else(|| panic!("warehouse path must be utf-8: {}", path.display()));
        ctx.register_parquet(table, path_str, ParquetReadOptions::default())
            .await
            .unwrap_or_else(|e| panic!("register {table}.parquet: {e}"));
    }
    ctx
}

// ---------------------------------------------------------------------------
// Per-query timing (matches tpch_baseline)
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
    let path = env::var("BALLISTA_4WORKER_BASELINE_INPUT").ok()?;
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

fn print_markdown(report: &ClusterReport) {
    println!();
    println!(
        "## TPC-H cluster · 4-slot in-process · SF={:.2} · {} runs/query (median over {} measured)",
        report.scale_factor,
        report.runs_per_query,
        report.runs_per_query - 1
    );
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
            "Single-node baseline geomean: **{baseline:.2} ms** · speedup ratio: **{ratio:.2}×** · target ≥{SPEEDUP_TARGET:.1}×: {}",
            if met { "✅ met" } else { "❌ not met — see PR description for gap analysis" }
        );
    }
    println!();
}

fn maybe_write_json(report: &ClusterReport) {
    let Ok(path) = env::var("BALLISTA_4WORKER_REPORT_OUTPUT") else {
        return;
    };
    let json = serde_json::to_string_pretty(report).expect("serialise cluster report");
    fs::write(&path, json).unwrap_or_else(|e| panic!("write JSON report to {path}: {e}"));
    println!("Wrote JSON report to {path}");
}

// ---------------------------------------------------------------------------
// Env-var parsing (mirrors tpch_baseline)
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

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() {
    let scale_factor = parse_scale_factor_env();

    let warehouse_dir = TempDir::new().expect("seed tempdir");
    eprintln!(
        "Seeding TPC-H SF={scale_factor:.2} into {} ...",
        warehouse_dir.path().display()
    );
    let seed_start = Instant::now();
    seed_warehouse(warehouse_dir.path(), scale_factor);
    eprintln!("Seed complete ({} ms)", seed_start.elapsed().as_millis());

    let rt = Runtime::new().expect("tokio runtime");
    eprintln!("Booting Ballista standalone cluster with {WORKER_SLOTS} worker slots ...");
    let boot_start = Instant::now();
    let ctx = Arc::new(rt.block_on(build_cluster_context(warehouse_dir.path())));
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

    let report = ClusterReport {
        suite: "tpch_cluster_4slot",
        scale_factor,
        runs_per_query: RUNS_PER_QUERY,
        worker_slots: WORKER_SLOTS,
        headline_geomean_ms: cluster_headline,
        speedup_ratio,
        speedup_target_met,
        baseline_headline_geomean_ms: baseline_headline.map(round2),
        queries: results,
    };

    print_markdown(&report);
    maybe_write_json(&report);
}

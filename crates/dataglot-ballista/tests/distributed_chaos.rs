//! Distributed resilience under injected faults ( phase 3) —
//! the chaos-monkey companion to the `distributed_parity` harness.
//!
//! Ballista 54.0.0 shipped `ChaosExec` (`ballista_core::execution_plans`):
//! a seed-deterministic fault injector wired through the scheduler's AQE
//! optimizer (`ChaosCreatingRule`). It wraps stage execution and, per the
//! configured `fault_type`, injects a recoverable IO error (`transient`),
//! a non-recoverable error (`fatal`), a `panic`, or a `delay`. Enabling it
//! (`BallistaContextFactory::with_chaos_execution`) also turns on the AQE
//! planner, since the wrapping rule lives there.
//!
//! This test pins two resilience properties of *our* distributed path
//! (federation codec + retry config), which neither the parity harness nor
//! the single-node tests cover:
//!
//! - **Benign fault ⇒ correct results.** A `delay` fault (never errors,
//!   only sleeps) proves the AQE+chaos path engages *and* the distributed
//!   query still returns exactly the single-node-equivalent results.
//! - **Persistent transient fault ⇒ clean failure, engine survives.** At
//!   `probability = 1.0` every task attempt re-injects, so a `transient`
//!   fault is effectively persistent (Ballista's task retry can't out-run
//!   an always-failing stage). The query must surface a clean
//!   `DataFusionError` — not hang, not crash the in-process cluster — and a
//!   subsequent chaos-free query on a fresh cluster must still succeed.
//!
//! `panic` is deliberately not exercised: it would unwind the in-process
//! standalone executor thread and poison the test binary. Panic-hardening
//! (executor survives a task panic) is a 54.0.0 upstream guarantee and is
//! better covered by the multi-process suite.
//!
//! CSV + in-process standalone cluster (no Docker), like `distributed_parity`.

use std::fs;
use std::time::Duration;

use ballista::datafusion::arrow::array::RecordBatch;
use ballista::datafusion::arrow::util::display::{ArrayFormatter, FormatOptions};
use ballista::datafusion::error::DataFusionError;
use ballista::datafusion::prelude::{CsvReadOptions, SessionContext};
use dataglot_ballista::BallistaContextFactory;
use dataglot_core::{SessionConfig, SessionContextFactory};
use tempfile::TempDir;

/// Above 1 so a JOIN + GROUP BY actually repartitions into shuffle stages —
/// the stages `ChaosCreatingRule` wraps.
const STANDALONE_PARALLELISM: usize = 2;

/// A join + grouped aggregate: forces a multi-stage (shuffle) distributed
/// plan, so there is a stage for `ChaosExec` to wrap.
const SHUFFLE_QUERY: &str = "SELECT r.region, COUNT(*) AS c, SUM(i.price) AS s \
     FROM items i JOIN regions r ON i.id = r.id \
     GROUP BY r.region ORDER BY r.region";

fn seed_csvs() -> TempDir {
    let dir = TempDir::new().expect("seed tempdir");
    fs::write(
        dir.path().join("items.csv"),
        "id,category,price,qty\n\
         1,A,10.5,2\n2,A,20.0,1\n3,B,5.25,4\n4,B,7.75,3\n5,A,3.5,5\n6,C,100.0,1\n",
    )
    .expect("write items.csv");
    fs::write(
        dir.path().join("regions.csv"),
        "id,region\n1,EU\n2,US\n3,EU\n4,APAC\n5,US\n6,EU\n",
    )
    .expect("write regions.csv");
    dir
}

async fn register_all(ctx: &SessionContext, seed: &TempDir) {
    for table in ["items", "regions"] {
        let path = seed.path().join(format!("{table}.csv"));
        ctx.register_csv(
            table,
            path.to_str().expect("utf-8 path"),
            CsvReadOptions::new().has_header(true),
        )
        .await
        .unwrap_or_else(|e| panic!("register {table}: {e}"));
    }
}

/// Plain single-node DataFusion — the correctness oracle.
async fn single_node_ctx(seed: &TempDir) -> SessionContext {
    let ctx = SessionContextFactory::new(SessionConfig::new())
        .expect("single-node factory")
        .create_context();
    register_all(&ctx, seed).await;
    ctx
}

/// Standalone Ballista cluster, optionally with a chaos fault injected.
async fn distributed_ctx(seed: &TempDir, chaos: Option<(&str, f64)>) -> SessionContext {
    let mut factory = BallistaContextFactory::new(SessionConfig::new())
        .with_standalone_parallelism(STANDALONE_PARALLELISM);
    if let Some((fault_type, probability)) = chaos {
        // Fixed seed → reproducible CI runs.
        factory = factory.with_chaos_execution(fault_type, 0x0C0F_FEE5, probability);
    }
    let ctx = factory
        .create_standalone_context()
        .await
        .expect("ballista standalone boots");
    register_all(&ctx, seed).await;
    ctx
}

/// Order-independent, float-normalized rendering of a result set, for a
/// robust equality check across execution paths.
fn rows(batches: &[RecordBatch]) -> Vec<String> {
    let opts = FormatOptions::default();
    let mut out = Vec::new();
    for batch in batches {
        let fmts: Vec<ArrayFormatter> = batch
            .columns()
            .iter()
            .map(|c| ArrayFormatter::try_new(c, &opts).expect("formatter"))
            .collect();
        for row in 0..batch.num_rows() {
            let cells: Vec<String> = fmts
                .iter()
                .map(|f| normalize_cell(&f.value(row).to_string()))
                .collect();
            out.push(cells.join(" | "));
        }
    }
    out.sort();
    out
}

/// Round finite floats so summation-order jitter between paths doesn't read
/// as a mismatch; non-numeric cells pass through unchanged.
fn normalize_cell(s: &str) -> String {
    if let Ok(v) = s.parse::<f64>() {
        if v.is_finite() {
            let trimmed = format!("{v:.6}")
                .trim_end_matches('0')
                .trim_end_matches('.')
                .to_string();
            return if trimmed.is_empty() || trimmed == "-0" {
                "0".to_string()
            } else {
                trimmed
            };
        }
    }
    s.to_string()
}

async fn try_run(ctx: &SessionContext, sql: &str) -> Result<Vec<RecordBatch>, DataFusionError> {
    ctx.sql(sql).await?.collect().await
}

/// A benign `delay` fault must engage the AQE+chaos path yet leave results
/// byte-for-byte equal to the single-node oracle.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn chaos_delay_preserves_correct_results() {
    let seed = seed_csvs();

    let expected = rows(
        &try_run(&single_node_ctx(&seed).await, SHUFFLE_QUERY)
            .await
            .expect("single-node oracle runs"),
    );

    let chaos = distributed_ctx(&seed, Some(("delay:2", 1.0))).await;
    let got = rows(
        &try_run(&chaos, SHUFFLE_QUERY)
            .await
            .expect("delay fault is benign — query must still succeed"),
    );

    assert_eq!(
        got, expected,
        "distributed results under a `delay` chaos fault must match single-node"
    );
}

/// A persistent `transient` fault (probability 1.0 ⇒ re-injected on every
/// retry) must surface as a clean error and leave the engine usable — not
/// hang, not crash the in-process cluster.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn chaos_transient_fault_fails_cleanly_and_engine_survives() {
    let seed = seed_csvs();

    // Bound the whole thing so a regression that *hangs* fails loudly
    // instead of stalling CI.
    let outcome = tokio::time::timeout(Duration::from_secs(90), async {
        let faulty = distributed_ctx(&seed, Some(("transient", 1.0))).await;
        let result = try_run(&faulty, SHUFFLE_QUERY).await;

        // A fresh, chaos-free cluster must still work — proves the injected
        // fault degraded a query, not the engine.
        let clean = distributed_ctx(&seed, None).await;
        let recovered = try_run(&clean, SHUFFLE_QUERY).await;
        (result, recovered)
    })
    .await
    .expect("chaos query must not hang");

    let (faulty_result, recovered) = outcome;

    // The always-on transient fault can't be retried away → clean failure.
    let err = faulty_result
        .expect_err("a persistent transient fault must surface as an error, not succeed");
    let msg = err.to_string();
    assert!(
        !msg.is_empty(),
        "the injected fault must produce a non-empty DataFusionError: {msg}"
    );

    // Engine survived: the subsequent chaos-free query returns correct rows.
    let single = seed_csvs();
    let expected = rows(
        &try_run(&single_node_ctx(&single).await, SHUFFLE_QUERY)
            .await
            .expect("oracle"),
    );
    assert_eq!(
        rows(&recovered.expect("post-chaos query on a clean cluster must succeed")),
        expected,
        "engine must serve correct results again after a chaos-faulted query"
    );
}

//! Single-node vs distributed **result-parity** ( phase 1 #1).
//!
//! For a set of shuffle-exercising queries, run each through a plain
//! single-node DataFusion `SessionContext` *and* a standalone Ballista
//! cluster over the *same* CSV data, and assert the results agree. This
//! is the distributed analogue of a differential oracle — the pattern
//! Apache Ballista uses in its `benchmarks` `--verify` mode
//! (`compare_results`: row-count → schema → cell-by-cell with float
//! tolerance). It catches distribution/codec/planning divergences that
//! neither single-node tests nor the existing (federation-specific)
//! `governance_parity` test would surface, and it's the correctness
//! floor beneath the  scaling work.
//!
//! CSV (not `MemTable`) is used because Ballista round-trips every plan
//! through `datafusion-proto`, which rejects non-serializable providers
//! — the executor re-reads the file by URI (see `smoke_localhost.rs`).
//! No Docker: runs in-process on the fast PR ballista job.

use std::fs;

use ballista::datafusion::arrow::array::RecordBatch;
use ballista::datafusion::arrow::util::display::{ArrayFormatter, FormatOptions};
use ballista::datafusion::prelude::{CsvReadOptions, SessionContext};
use dataglot_ballista::BallistaContextFactory;
use dataglot_core::{SessionConfig, SessionContextFactory};
use tempfile::TempDir;

/// Small enough to boot fast, >1 so shuffles actually repartition.
const STANDALONE_PARALLELISM: usize = 2;

/// Two CSV tables with a shared join key. `price` is `f64` so the
/// float-tolerant comparison path is exercised by `avg`/`sum`.
fn seed_csvs() -> TempDir {
    let dir = TempDir::new().expect("seed tempdir");
    fs::write(
        dir.path().join("items.csv"),
        "id,category,price,qty\n\
         1,A,10.5,2\n\
         2,A,20.0,1\n\
         3,B,5.25,4\n\
         4,B,7.75,3\n\
         5,A,3.5,5\n\
         6,C,100.0,1\n",
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

async fn single_node_ctx(seed: &TempDir) -> SessionContext {
    let ctx = SessionContextFactory::new(SessionConfig::new())
        .expect("single-node factory")
        .create_context();
    register_all(&ctx, seed).await;
    ctx
}

async fn distributed_ctx(seed: &TempDir) -> SessionContext {
    let ctx = BallistaContextFactory::new(SessionConfig::new())
        .with_standalone_parallelism(STANDALONE_PARALLELISM)
        .create_standalone_context()
        .await
        .expect("ballista standalone boots");
    register_all(&ctx, seed).await;
    ctx
}

async fn run(ctx: &SessionContext, sql: &str) -> Vec<RecordBatch> {
    ctx.sql(sql)
        .await
        .unwrap_or_else(|e| panic!("plan `{sql}`: {e}"))
        .collect()
        .await
        .unwrap_or_else(|e| panic!("execute `{sql}`: {e}"))
}

/// Normalize a rendered cell so float jitter between execution paths
/// (e.g. `avg` summed in a different order) doesn't read as a mismatch:
/// anything parseable as a finite float is rounded to 10 places and
/// trailing zeros stripped. Non-numeric cells pass through unchanged.
/// Applied to both sides identically, so it can't hide a real diff in
/// non-float columns.
fn normalize_cell(s: &str) -> String {
    if let Ok(v) = s.parse::<f64>() {
        if v.is_finite() {
            let rounded = format!("{v:.10}");
            let trimmed = rounded.trim_end_matches('0').trim_end_matches('.');
            return match trimmed {
                "" | "-" | "-0" => "0".to_string(),
                other => other.to_string(),
            };
        }
    }
    s.to_string()
}

fn schema_sig(batches: &[RecordBatch]) -> Option<Vec<(String, String)>> {
    batches.first().map(|b| {
        b.schema()
            .fields()
            .iter()
            .map(|f| (f.name().clone(), f.data_type().to_string()))
            .collect()
    })
}

fn to_rows(batches: &[RecordBatch]) -> Vec<Vec<String>> {
    let opts = FormatOptions::default();
    let mut rows = Vec::new();
    for batch in batches {
        let fmts: Vec<ArrayFormatter> = batch
            .columns()
            .iter()
            .map(|c| ArrayFormatter::try_new(c, &opts).expect("array formatter"))
            .collect();
        for r in 0..batch.num_rows() {
            rows.push(
                fmts.iter()
                    .map(|f| normalize_cell(&f.value(r).to_string()))
                    .collect(),
            );
        }
    }
    rows
}

/// Row-count → schema → order-independent, float-tolerant cell compare.
fn compare(single: &[RecordBatch], dist: &[RecordBatch]) -> Result<(), String> {
    if schema_sig(single) != schema_sig(dist) {
        return Err(format!(
            "schema mismatch:\n  single: {:?}\n  dist:   {:?}",
            schema_sig(single),
            schema_sig(dist)
        ));
    }
    let mut s = to_rows(single);
    let mut d = to_rows(dist);
    if s.len() != d.len() {
        return Err(format!("row count: single={} dist={}", s.len(), d.len()));
    }
    // Sort for order-independence: a distributed plan may emit rows in a
    // different order than single-node when the query has no total order.
    s.sort();
    d.sort();
    for (i, (a, b)) in s.iter().zip(d.iter()).enumerate() {
        if a != b {
            return Err(format!(
                "row {i} differs after sort:\n  single: {a:?}\n  dist:   {b:?}"
            ));
        }
    }
    Ok(())
}

/// Queries chosen to exercise the distribution-specific paths: grouped
/// aggregation, joins, windows, DISTINCT, and multi-key group-bys all
/// force repartition/shuffle stages under Ballista.
fn cases() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "project_filter",
            "SELECT id, category, price, qty FROM items WHERE qty >= 2 ORDER BY id",
        ),
        (
            "group_agg",
            "SELECT category, count(*) c, sum(qty) s, min(price) mn, max(price) mx \
             FROM items GROUP BY category ORDER BY category",
        ),
        (
            "group_avg_float",
            "SELECT category, avg(price) a FROM items GROUP BY category ORDER BY category",
        ),
        (
            "inner_join",
            "SELECT i.id, r.region, i.price FROM items i \
             JOIN regions r ON i.id = r.id ORDER BY i.id",
        ),
        (
            "join_group_agg",
            "SELECT r.region, sum(i.price) t, count(*) c FROM items i \
             JOIN regions r ON i.id = r.id GROUP BY r.region ORDER BY r.region",
        ),
        (
            "having",
            "SELECT category, sum(qty) s FROM items GROUP BY category \
             HAVING sum(qty) >= 3 ORDER BY category",
        ),
        (
            "distinct",
            "SELECT DISTINCT category FROM items ORDER BY category",
        ),
        (
            "window",
            "SELECT id, category, sum(qty) OVER (PARTITION BY category ORDER BY id) w \
             FROM items ORDER BY id",
        ),
        (
            "multi_key_group",
            "SELECT category, qty, count(*) c FROM items \
             GROUP BY category, qty ORDER BY category, qty",
        ),
    ]
}

#[tokio::test]
async fn single_node_and_distributed_results_agree() {
    let seed = seed_csvs();
    let single = single_node_ctx(&seed).await;
    let dist = distributed_ctx(&seed).await;

    let mut failures = Vec::new();
    for (name, sql) in cases() {
        let s = run(&single, sql).await;
        let d = run(&dist, sql).await;
        if let Err(diff) = compare(&s, &d) {
            failures.push(format!("[{name}] {sql}\n{diff}"));
        }
    }

    assert!(
        failures.is_empty(),
        "single-node vs distributed parity failures ({}/{}):\n\n{}",
        failures.len(),
        cases().len(),
        failures.join("\n\n")
    );
}

//! Randomized single-node vs distributed differential fuzzing
//! ( phase 2 #4) — the randomized companion to the fixed-query
//! `distributed_parity` harness.
//!
//! A small template generator emits diverse, well-typed SQL over two CSV
//! tables (grouped aggregation, joins, windows, DISTINCT, filters), and
//! each query is run through both a plain single-node DataFusion context
//! and a standalone Ballista cluster, then compared (order-independent,
//! float-tolerant). A divergence — or one path succeeding while the
//! other errors — is a distribution/codec bug. Same idea DataFusion's
//! `aggregation_fuzzer` and RisingWave's `SQLsmith` use (differential
//! oracle over generated queries).
//!
//! Determinism: the PRNG is a fixed-seed inline splitmix64 (no `rand`
//! dep), so **CI runs the same query set every time** — no flakes. Vary
//! locally with `FUZZ_SEED` / `FUZZ_ITERS`; the seed is printed on
//! failure so any divergence reproduces exactly. CSV + in-process, so it
//! runs on the fast PR ballista job.

use std::fs;

use ballista::datafusion::arrow::array::RecordBatch;
use ballista::datafusion::arrow::util::display::{ArrayFormatter, FormatOptions};
use ballista::datafusion::prelude::{CsvReadOptions, SessionContext};
use dataglot_ballista::BallistaContextFactory;
use dataglot_core::{SessionConfig, SessionContextFactory};
use tempfile::TempDir;

const STANDALONE_PARALLELISM: usize = 2;
const DEFAULT_SEED: u64 = 0x5DEE_CE66_D1EF_1234;
/// ~30s on the standalone cluster; bump via `FUZZ_ITERS` locally/nightly.
const DEFAULT_ITERS: usize = 100;

// ---- deterministic inline PRNG (splitmix64) -------------------------

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    fn pick<'a, T>(&mut self, xs: &'a [T]) -> &'a T {
        let i = self.below(xs.len());
        &xs[i]
    }
    fn chance(&mut self) -> bool {
        self.next() & 1 == 1
    }
}

// ---- query generation ------------------------------------------------

/// One well-typed query over `items(id,category,price,qty)` /
/// `regions(id,region)`. Shapes are chosen to force repartition/shuffle
/// stages under Ballista.
fn gen_query(rng: &mut Rng) -> String {
    match rng.below(5) {
        0 => gen_aggregate(rng),
        1 => gen_join_aggregate(rng),
        2 => gen_projection(rng),
        3 => gen_window(rng),
        _ => gen_distinct(rng),
    }
}

fn agg_exprs(rng: &mut Rng, qty: &str, price: &str) -> String {
    let numeric_aggs = [
        format!("sum({qty})"),
        format!("sum({price})"),
        format!("min({qty})"),
        format!("max({qty})"),
        format!("min({price})"),
        format!("max({price})"),
        format!("avg({price})"),
        format!("avg({qty})"),
    ];
    let n = 1 + rng.below(3);
    let mut out = vec!["count(*)".to_string()];
    for _ in 0..n {
        out.push(rng.pick(&numeric_aggs).clone());
    }
    out.iter()
        .enumerate()
        .map(|(i, e)| format!("{e} AS c{i}"))
        .collect::<Vec<_>>()
        .join(", ")
}

fn where_clause(rng: &mut Rng) -> String {
    let preds = [
        format!("qty >= {}", 1 + rng.below(5)),
        format!("qty < {}", 1 + rng.below(6)),
        format!("price > {}", rng.below(50)),
        format!("price <= {}", 10 + rng.below(90)),
        format!("category = '{}'", rng.pick(&["A", "B", "C"])),
        "category IN ('A', 'B')".to_string(),
        "id % 2 = 0".to_string(),
    ];
    let a = rng.pick(&preds).clone();
    if rng.chance() {
        let b = rng.pick(&preds).clone();
        let op = if rng.chance() { "AND" } else { "OR" };
        format!("{a} {op} {b}")
    } else {
        a
    }
}

fn gen_aggregate(rng: &mut Rng) -> String {
    let g = rng.pick(&["category", "qty"]).to_string();
    let aggs = agg_exprs(rng, "qty", "price");
    let wh = if rng.chance() {
        format!(" WHERE {}", where_clause(rng))
    } else {
        String::new()
    };
    let having = if rng.chance() {
        format!(" HAVING count(*) >= {}", 1 + rng.below(3))
    } else {
        String::new()
    };
    format!("SELECT {g}, {aggs} FROM items{wh} GROUP BY {g}{having} ORDER BY {g}")
}

fn gen_join_aggregate(rng: &mut Rng) -> String {
    let aggs = agg_exprs(rng, "i.qty", "i.price");
    let wh = if rng.chance() {
        let p = where_clause(rng)
            .replace("qty", "i.qty")
            .replace("price", "i.price");
        // `category` lives on items in this join.
        let p = p.replace("category", "i.category");
        format!(" WHERE {p}")
    } else {
        String::new()
    };
    format!(
        "SELECT r.region, {aggs} FROM items i JOIN regions r ON i.id = r.id{wh} \
         GROUP BY r.region ORDER BY r.region"
    )
}

fn pick_cols(rng: &mut Rng) -> String {
    let all = ["id", "category", "price", "qty"];
    let k = 1 + rng.below(all.len());
    // Deterministic subset preserving column order.
    let mut chosen: Vec<&str> = Vec::new();
    for c in all {
        if chosen.len() < k && rng.chance() {
            chosen.push(c);
        }
    }
    if chosen.is_empty() {
        chosen.push("id");
    }
    chosen.join(", ")
}

fn gen_projection(rng: &mut Rng) -> String {
    let cols = pick_cols(rng);
    let wh = where_clause(rng);
    let lim = if rng.chance() {
        format!(" LIMIT {}", 1 + rng.below(6))
    } else {
        String::new()
    };
    // ORDER BY id (unique) gives a total order so LIMIT is deterministic.
    format!("SELECT {cols} FROM items WHERE {wh} ORDER BY id{lim}")
}

fn gen_window(rng: &mut Rng) -> String {
    let f = rng.pick(&["sum", "avg", "min", "max", "count"]).to_string();
    let n = rng.pick(&["qty", "price"]).to_string();
    format!(
        "SELECT id, category, {f}({n}) OVER (PARTITION BY category ORDER BY id) AS w \
         FROM items ORDER BY id"
    )
}

fn gen_distinct(rng: &mut Rng) -> String {
    let cols = pick_cols(rng);
    format!("SELECT DISTINCT {cols} FROM items ORDER BY {cols}")
}

// ---- fixtures + contexts --------------------------------------------

fn seed_csvs() -> TempDir {
    let dir = TempDir::new().expect("seed tempdir");
    fs::write(
        dir.path().join("items.csv"),
        "id,category,price,qty\n\
         1,A,10.5,2\n2,A,20.0,1\n3,B,5.25,4\n4,B,7.75,3\n5,A,3.5,5\n\
         6,C,100.0,1\n7,B,1.5,2\n8,C,42.0,4\n9,A,9.0,3\n10,B,3.14,5\n",
    )
    .expect("write items.csv");
    fs::write(
        dir.path().join("regions.csv"),
        "id,region\n1,EU\n2,US\n3,EU\n4,APAC\n5,US\n6,EU\n7,APAC\n8,US\n9,EU\n10,APAC\n",
    )
    .expect("write regions.csv");
    dir
}

async fn register_all(ctx: &SessionContext, seed: &TempDir) {
    for table in ["items", "regions"] {
        ctx.register_csv(
            table,
            seed.path()
                .join(format!("{table}.csv"))
                .to_str()
                .expect("utf-8 path"),
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

async fn run(ctx: &SessionContext, sql: &str) -> Result<Vec<RecordBatch>, String> {
    let df = ctx.sql(sql).await.map_err(|e| e.to_string())?;
    df.collect().await.map_err(|e| e.to_string())
}

// ---- comparison (float-tolerant, order-independent) -----------------

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

fn compare(single: &[RecordBatch], dist: &[RecordBatch]) -> Result<(), String> {
    if schema_sig(single) != schema_sig(dist) {
        return Err(format!(
            "schema mismatch: single={:?} dist={:?}",
            schema_sig(single),
            schema_sig(dist)
        ));
    }
    let mut s = to_rows(single);
    let mut d = to_rows(dist);
    if s.len() != d.len() {
        return Err(format!("row count: single={} dist={}", s.len(), d.len()));
    }
    s.sort();
    d.sort();
    for (i, (a, b)) in s.iter().zip(d.iter()).enumerate() {
        if a != b {
            return Err(format!("row {i}: single={a:?} dist={b:?}"));
        }
    }
    Ok(())
}

fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

// DF54's planner/optimizer recurses more deeply through the nested
// expressions this fuzzer generates, overflowing libtest's default
// 2 MiB test-thread stack. Run the (current-thread) runtime on a
// dedicated thread with a larger stack — same execution model the
// `#[tokio::test]` default gave, just with more headroom.
#[test]
fn randomized_single_node_vs_distributed_parity() {
    std::thread::Builder::new()
        .name("parity-fuzz".into())
        .stack_size(32 * 1024 * 1024)
        .spawn(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(run_parity_fuzz());
        })
        .unwrap()
        .join()
        .unwrap();
}

async fn run_parity_fuzz() {
    let seed = env_u64("FUZZ_SEED", DEFAULT_SEED);
    let iters = env_u64("FUZZ_ITERS", DEFAULT_ITERS as u64) as usize;

    let data = seed_csvs();
    let single = single_node_ctx(&data).await;
    let dist = distributed_ctx(&data).await;

    let mut rng = Rng(seed);
    let mut failures = Vec::new();
    let mut compared = 0usize;
    for i in 0..iters {
        let sql = gen_query(&mut rng);
        match (run(&single, &sql).await, run(&dist, &sql).await) {
            (Ok(sb), Ok(db)) => {
                compared += 1;
                if let Err(diff) = compare(&sb, &db) {
                    failures.push(format!("#{i}  {sql}\n    {diff}"));
                }
            }
            // Both reject the query identically — not a parity failure.
            (Err(_), Err(_)) => {}
            // One path handled it and the other didn't — a real divergence.
            (s, d) => failures.push(format!(
                "#{i}  {sql}\n    single_ok={} dist_ok={}",
                s.is_ok(),
                d.is_ok()
            )),
        }
    }

    assert!(
        failures.is_empty(),
        "FUZZ_SEED={seed}: {} of {iters} generated queries diverged \
         ({compared} compared):\n\n{}",
        failures.len(),
        failures.join("\n\n")
    );
    // Sanity: the generator should mostly produce runnable queries.
    assert!(
        compared >= iters / 2,
        "only {compared}/{iters} queries ran on both paths — generator likely broken"
    );
}

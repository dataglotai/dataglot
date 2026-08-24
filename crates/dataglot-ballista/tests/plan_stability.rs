//! Plan-stability golden tests ( phase 2 #2).
//!
//! Freezes the **optimized logical plan** and **physical plan** for a
//! curated query set as approved text under `tests/plan_stability/
//! approved/`. A change to dataglot's session config, optimizer rules
//! (e.g. the  `FilterPushdown` strip), or the DataFusion version
//! (cf. the  df54 bump) that alters plan shape produces a golden
//! diff — the pattern Apache Ballista uses in `tpch_plan_stability` and
//! RisingWave in its YAML planner snapshots.
//!
//! Determinism: `target_partitions` is pinned (it otherwise defaults to
//! CPU count, so plans would differ CI-vs-laptop) and the temp data
//! path is redacted to `<DATA>`. Regenerate after an intentional change:
//!
//! ```sh
//! GENERATE_GOLDEN=1 cargo test -p dataglot-ballista --test plan_stability
//! ```
//!
//! Scope: single-node (the served query path). Freezing the Ballista
//! *staged* plan and federation-*pushdown* decisions (the highest-value,
//! dataglot-specific targets) needs the ballista stage planner / a live
//! source and is the noted follow-up on.

use std::fs;
use std::path::PathBuf;

use ballista::datafusion::physical_plan::displayable;
use ballista::datafusion::prelude::{CsvReadOptions, SessionContext};
use dataglot_core::{SessionConfig, SessionContextFactory};
use tempfile::TempDir;

/// Pinned so plans don't vary with the runner's core count.
const TARGET_PARTITIONS: usize = 4;

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

async fn ctx(seed: &TempDir) -> SessionContext {
    let ctx =
        SessionContextFactory::new(SessionConfig::new().with_target_partitions(TARGET_PARTITIONS))
            .expect("factory")
            .create_federated_context();
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
    ctx
}

/// Render `<optimized logical plan>` + `<physical plan>` for `sql`,
/// with the (random) temp data path redacted so the golden is stable.
async fn plan_text(ctx: &SessionContext, sql: &str, data_dir: &str) -> String {
    let df = ctx
        .sql(sql)
        .await
        .unwrap_or_else(|e| panic!("plan `{sql}`: {e}"));
    let logical = df
        .clone()
        .into_optimized_plan()
        .unwrap_or_else(|e| panic!("optimize `{sql}`: {e}"))
        .display_indent()
        .to_string();
    let physical = df
        .create_physical_plan()
        .await
        .unwrap_or_else(|e| panic!("physical `{sql}`: {e}"));
    let physical = displayable(physical.as_ref()).indent(true).to_string();

    let body =
        format!("-- Optimized logical plan --\n{logical}\n\n-- Physical plan --\n{physical}");
    // DataFusion renders `DataSourceExec` paths with the leading `/`
    // stripped (object-store style), so redact both forms. Replacing the
    // full temp-dir path (which includes the random `.tmpXXXX` segment)
    // also makes the golden machine-independent (macOS /var/folders vs
    // Linux CI /tmp).
    body.replace(data_dir, "<DATA>")
        .replace(data_dir.trim_start_matches('/'), "<DATA>")
}

fn approved_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/plan_stability/approved")
}

fn cases() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "group_agg",
            "SELECT category, count(*) c, sum(qty) s FROM items GROUP BY category ORDER BY category",
        ),
        (
            "inner_join",
            "SELECT i.id, r.region, i.price FROM items i JOIN regions r ON i.id = r.id ORDER BY i.id",
        ),
        (
            "join_group_agg",
            "SELECT r.region, sum(i.price) t FROM items i JOIN regions r ON i.id = r.id \
             GROUP BY r.region ORDER BY r.region",
        ),
        (
            "filter_project",
            "SELECT id, category FROM items WHERE qty >= 3 AND price < 50 ORDER BY id",
        ),
        (
            "distinct",
            "SELECT DISTINCT category FROM items ORDER BY category",
        ),
    ]
}

#[tokio::test]
async fn plans_are_stable() {
    let seed = seed_csvs();
    let data_dir = seed.path().to_str().expect("utf-8 seed path").to_string();
    let ctx = ctx(&seed).await;
    let dir = approved_dir();
    let generate = std::env::var("GENERATE_GOLDEN").is_ok();
    if generate {
        fs::create_dir_all(&dir).expect("create approved dir");
    }

    let mut failures = Vec::new();
    for (name, sql) in cases() {
        let actual = plan_text(&ctx, sql, &data_dir).await;
        let path = dir.join(format!("{name}.txt"));
        if generate {
            fs::write(&path, format!("{actual}\n")).expect("write golden");
            continue;
        }
        match fs::read_to_string(&path) {
            Ok(expected) if expected.trim_end() == actual.trim_end() => {}
            Ok(expected) => failures.push(format!(
                "[{name}] plan changed — rerun with GENERATE_GOLDEN=1 if intended.\n\
                 --- expected ---\n{expected}\n--- actual ---\n{actual}"
            )),
            Err(e) => failures.push(format!(
                "[{name}] missing golden {} ({e}); run GENERATE_GOLDEN=1",
                path.display()
            )),
        }
    }

    assert!(
        failures.is_empty(),
        "plan-stability failures ({}/{}):\n\n{}",
        failures.len(),
        cases().len(),
        failures.join("\n\n")
    );
}

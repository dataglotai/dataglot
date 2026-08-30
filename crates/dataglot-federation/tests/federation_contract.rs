//! Federation contract suite — pins the pushdown *shapes*
//! Dataglot relies on `datafusion-federation` for, so a crate bump
//! (e.g. the  DataFusion 54 train) can't silently regress them.
//!
//! Pushdown regressions are the nastiest dependency-bump class: results
//! stay CORRECT while the engine quietly re-executes work locally, so
//! only EXPLAIN-shape assertions catch them. Every test here asserts
//! positive space (what must appear inside the federation node) and
//! negative space (which local-execution operators must NOT appear
//! above it) — same discipline as the per-connector pushdown tests.
//!
//! Fixture: the DuckDB ADBC driver (`ADBC_DRIVER_DUCKDB_PATH`, silently
//! skipped when unset) — a real SQL source with **no Docker**, so this
//! suite runs on every PR via the `adbc-driver` CI job. The shapes are
//! connector-agnostic: they exercise the federation optimizer +
//! unparser, not DuckDB specifics.

#![cfg(feature = "adbc")]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use adbc_core::options::{AdbcVersion, OptionDatabase, OptionValue};
use adbc_core::{Connection as _, Database as _, Driver as _, Statement as _};
use adbc_driver_manager::ManagedDriver;
use arrow::array::{Float64Array, RecordBatch};
use arrow::datatypes::DataType;
use arrow::util::pretty::pretty_format_batches;
use datafusion::execution::SessionStateBuilder;
use datafusion::logical_expr::{ColumnarValue, Volatility};
use datafusion::prelude::create_udf;
use dataglot_core::{SessionConfig, SessionContextFactory};
use dataglot_federation::adbc::{AdbcConfig, AdbcConnector, SupportedDialect};

const DUCKDB_ENTRYPOINT: &str = "duckdb_adbc_init";

/// Local-execution operators that must never appear above a federation
/// node when a shape is expected to push down completely.
const FORBIDDEN_LOCAL_OPERATORS: &[&str] = &[
    "AggregateExec",
    "SortExec",
    "FilterExec",
    "GlobalLimitExec",
    "LocalLimitExec",
    "HashJoinExec",
    "SortMergeJoinExec",
    "NestedLoopJoinExec",
    "CrossJoinExec",
];

fn driver_path() -> Option<PathBuf> {
    match std::env::var("ADBC_DRIVER_DUCKDB_PATH") {
        Ok(path) if !path.is_empty() => Some(PathBuf::from(path)),
        _ => {
            eprintln!(
                "skipping: ADBC_DRIVER_DUCKDB_PATH is not set \
                 (run .github/scripts/download-duckdb-adbc-driver.sh)"
            );
            None
        }
    }
}

/// Seed the two-table join fixture: customers × orders, same source.
fn seed_join_fixture(driver_path: &Path, db_file: &str) {
    let mut driver = ManagedDriver::load_dynamic_from_filename(
        driver_path,
        Some(DUCKDB_ENTRYPOINT.as_bytes()),
        AdbcVersion::V110,
    )
    .expect("duckdb adbc driver loads");
    let database = driver
        .new_database_with_opts(vec![(
            OptionDatabase::Other("path".to_string()),
            OptionValue::String(db_file.to_string()),
        )])
        .expect("duckdb database opens");
    let mut conn = database.new_connection().expect("duckdb connection opens");
    for sql in [
        "CREATE TABLE customers (id INTEGER, name VARCHAR, segment VARCHAR)",
        "INSERT INTO customers VALUES
            (1, 'alice', 'enterprise'),
            (2, 'bob',   'pro'),
            (3, 'carol', 'pro'),
            (4, 'dave',  'free')",
        "CREATE TABLE orders (id INTEGER, customer_id INTEGER, amount DOUBLE, region VARCHAR)",
        "INSERT INTO orders VALUES
            (10, 1, 100.0, 'emea'),
            (11, 1,  40.0, 'amer'),
            (12, 2,  25.0, 'emea'),
            (13, 3,  60.0, 'apac'),
            (14, 3,   5.0, 'apac'),
            (15, 4,   1.0, 'emea'),
            (16, 4,   2.0, NULL)",
        "CREATE TABLE regions (code VARCHAR, title VARCHAR)",
        "INSERT INTO regions VALUES
            ('emea', 'Europe / Middle East / Africa'),
            ('amer', 'Americas'),
            ('apac', 'Asia Pacific')",
    ] {
        let mut stmt = conn.new_statement().expect("statement allocates");
        stmt.set_sql_query(sql).expect("sql sets");
        stmt.execute_update().expect("seed statement runs");
    }
}

/// Federation-aware context with both fixture tables registered from
/// ONE connector — the same-source setup every collapse pin needs.
/// Installs the SAME optimizer rule set production uses (federation
/// defaults + the  dedup-unparse guard), so every full-pushdown
/// pin in this suite doubles as a guard false-positive check.
async fn contract_context(driver: &Path, db_file: &str) -> datafusion::prelude::SessionContext {
    contract_context_with(driver, db_file, true).await
}

/// The raw federation stack WITHOUT the  guard — only for the
/// pin that documents the underlying df53 wrong-results behavior.
async fn unguarded_contract_context(
    driver: &Path,
    db_file: &str,
) -> datafusion::prelude::SessionContext {
    contract_context_with(driver, db_file, false).await
}

async fn contract_context_with(
    driver: &Path,
    db_file: &str,
    with_guard: bool,
) -> datafusion::prelude::SessionContext {
    let mut config = AdbcConfig::new("duck_contract", driver, SupportedDialect::DuckDb);
    config.driver_entrypoint = Some(DUCKDB_ENTRYPOINT.to_string());
    config.driver_options = Some(format!("path={db_file}"));
    let connector = Arc::new(
        AdbcConnector::connect(config)
            .await
            .expect("adbc connector connects"),
    );

    let factory = SessionContextFactory::new(
        SessionConfig::new()
            .with_default_catalog("dataglot")
            .with_default_schema("main"),
    )
    .unwrap();
    let ctx = factory.create_context();
    let rules = if with_guard {
        dataglot_core::federation_dedup_guard::federated_optimizer_rules()
    } else {
        datafusion_federation::default_optimizer_rules()
    };
    let fed_state = SessionStateBuilder::new_from_existing(ctx.state())
        .with_optimizer_rules(rules)
        .with_query_planner(Arc::new(datafusion_federation::FederatedQueryPlanner::new()))
        .build();
    let ctx = datafusion::prelude::SessionContext::new_with_state(fed_state);

    for table in ["customers", "orders", "regions"] {
        let provider = connector
            .table_provider("main", table)
            .await
            .unwrap_or_else(|e| panic!("schema resolves for main.{table}: {e}"));
        ctx.register_table(table, provider)
            .expect("register fixture table");
    }
    ctx
}

/// Render EXPLAIN output for `sql`.
async fn explain(ctx: &datafusion::prelude::SessionContext, sql: &str) -> String {
    let df = ctx
        .sql(&format!("EXPLAIN {sql}"))
        .await
        .expect("EXPLAIN parses");
    pretty_format_batches(&df.collect().await.expect("EXPLAIN runs"))
        .unwrap()
        .to_string()
}

/// Assert the full-pushdown contract for `sql`: exactly `nodes`
/// federation nodes, every `pushed` needle inside the plan, and no
/// local-execution operator above the federation node(s).
async fn assert_fully_pushed(
    ctx: &datafusion::prelude::SessionContext,
    sql: &str,
    pushed: &[&str],
) -> String {
    let explain_str = explain(ctx, sql).await;
    let explain_upper = explain_str.to_uppercase();

    let node_count = explain_str
        .lines()
        .filter(|line| {
            line.contains("VirtualExecutionPlan") || line.contains("sql_federation_exec")
        })
        .count();
    assert_eq!(
        node_count, 1,
        "same-source shape must collapse into exactly ONE federation node:\n{explain_str}"
    );
    for needle in pushed {
        assert!(
            explain_upper.contains(&needle.to_uppercase()),
            "expected {needle:?} inside the pushed SQL:\n{explain_str}"
        );
    }
    let leaks: Vec<&str> = FORBIDDEN_LOCAL_OPERATORS
        .iter()
        .copied()
        .filter(|op| explain_str.contains(op))
        .collect();
    assert!(
        leaks.is_empty(),
        "shape leaked local-execution operator(s) {leaks:?} — federation re-did work the \
         source should have handled:\n{explain_str}"
    );
    explain_str
}

/// **The headline pin.** A JOIN between two tables of the SAME source
/// must collapse into one pushed query — two federated scans plus a
/// local `HashJoinExec` would be silently correct and catastrophically
/// slower. No test pinned this before.
#[tokio::test]
async fn same_source_join_collapses_into_one_pushed_query() {
    let Some(driver) = driver_path() else { return };
    let dir = tempfile::tempdir().expect("tempdir");
    let db_file = dir.path().join("contract.duckdb");
    let db_file = db_file.to_str().expect("utf8 temp path");
    seed_join_fixture(&driver, db_file);
    let ctx = contract_context(&driver, db_file).await;

    let sql = "SELECT c.segment, COUNT(*) AS orders, SUM(o.amount) AS revenue
               FROM orders o
               JOIN customers c ON c.id = o.customer_id
               WHERE o.amount >= 5
               GROUP BY c.segment
               ORDER BY revenue DESC
               LIMIT 10";

    // Correctness first: enterprise {100+40}, pro {25+60+5}, free filtered out.
    let batches = ctx
        .sql(sql)
        .await
        .expect("plans")
        .collect()
        .await
        .expect("executes");
    let rendered = pretty_format_batches(&batches).unwrap().to_string();
    let rows: usize = batches.iter().map(RecordBatch::num_rows).sum();
    assert_eq!(
        rows, 2,
        "free's only order (1.0) is filtered out:\n{rendered}"
    );
    assert!(
        rendered.contains("140"),
        "enterprise revenue 140:\n{rendered}"
    );
    assert!(rendered.contains("90"), "pro revenue 90:\n{rendered}");

    assert_fully_pushed(&ctx, sql, &["JOIN", "GROUP BY", "ORDER BY", "LIMIT"]).await;
}

/// An `IN (subquery)` against the same source is a join in disguise —
/// it must collapse the same way.
#[tokio::test]
async fn same_source_in_subquery_collapses() {
    let Some(driver) = driver_path() else { return };
    let dir = tempfile::tempdir().expect("tempdir");
    let db_file = dir.path().join("contract.duckdb");
    let db_file = db_file.to_str().expect("utf8 temp path");
    seed_join_fixture(&driver, db_file);
    let ctx = contract_context(&driver, db_file).await;

    let sql = "SELECT region, SUM(amount) AS total
               FROM orders
               WHERE customer_id IN (SELECT id FROM customers WHERE segment = 'pro')
               GROUP BY region
               ORDER BY region";

    let batches = ctx
        .sql(sql)
        .await
        .expect("plans")
        .collect()
        .await
        .expect("executes");
    let rendered = pretty_format_batches(&batches).unwrap().to_string();
    let rows: usize = batches.iter().map(RecordBatch::num_rows).sum();
    // pro = bob (order 25, emea) + carol (60 + 5, apac) → two regions.
    assert_eq!(rows, 2, "expected apac + emea groups:\n{rendered}");
    assert!(rendered.contains("65"), "apac total 65:\n{rendered}");

    assert_fully_pushed(&ctx, sql, &["GROUP BY", "ORDER BY"]).await;
}

/// CASE + HAVING through federation — the realistic aliased shape
/// (project the CASE in a subquery, aggregate over the alias) must
/// push down fully.
#[tokio::test]
async fn aliased_case_and_having_push_down() {
    let Some(driver) = driver_path() else { return };
    let dir = tempfile::tempdir().expect("tempdir");
    let db_file = dir.path().join("contract.duckdb");
    let db_file = db_file.to_str().expect("utf8 temp path");
    seed_join_fixture(&driver, db_file);
    let ctx = contract_context(&driver, db_file).await;

    let sql = "SELECT bucket, COUNT(*) AS n
               FROM (SELECT CASE WHEN amount >= 50 THEN 'big' ELSE 'small' END AS bucket
                     FROM orders) t
               GROUP BY bucket
               HAVING COUNT(*) >= 1
               ORDER BY bucket";

    let batches = ctx
        .sql(sql)
        .await
        .expect("plans")
        .collect()
        .await
        .expect("executes");
    let rendered = pretty_format_batches(&batches).unwrap().to_string();
    // big: {100, 60} → 2; small: {40, 25, 5, 1} → 4.
    assert!(
        rendered.contains("big") && rendered.contains("small"),
        "{rendered}"
    );

    assert_fully_pushed(&ctx, sql, &["CASE", "GROUP BY"]).await;
}

/// **Known-wart pin.** Grouping directly on an ANONYMOUS `CASE`
/// expression (`GROUP BY 1`, no alias) currently fails at execution
/// with a schema `FieldNotFound`: the expression's derived field name
/// keeps the table qualifier on the plan side
/// (`CASE WHEN main.orders.amount …`) but loses it through the
/// unparse → remote → re-read round-trip (`CASE WHEN orders.amount …`),
/// so the two names never match. Found by 's first run. This pin
/// documents the wart; when a datafusion-federation bump fixes the
/// round-trip naming, this test fails and should be flipped into a
/// full-pushdown assertion.
#[tokio::test]
async fn anonymous_case_group_by_is_a_known_schema_wart() {
    let Some(driver) = driver_path() else { return };
    let dir = tempfile::tempdir().expect("tempdir");
    let db_file = dir.path().join("contract.duckdb");
    let db_file = db_file.to_str().expect("utf8 temp path");
    seed_join_fixture(&driver, db_file);
    let ctx = contract_context(&driver, db_file).await;

    let sql = "SELECT CASE WHEN amount >= 50 THEN 'big' ELSE 'small' END AS bucket,
                      COUNT(*) AS n
               FROM orders
               GROUP BY 1
               ORDER BY bucket";

    let err = ctx
        .sql(sql)
        .await
        .expect("plans")
        .collect()
        .await
        .expect_err(
            "anonymous-CASE grouping currently fails through federation — if this \
             now SUCCEEDS, a dependency bump fixed the qualified-name round-trip: \
             flip this pin into a full-pushdown assertion",
        );
    let msg = err.to_string();
    assert!(
        msg.contains("FieldNotFound") || msg.contains("field") || msg.contains("Schema"),
        "expected the schema-name mismatch shape, got a different failure: {msg}"
    );
}

/// ORDER BY on an expression (not a bare column) + LIMIT.
#[tokio::test]
async fn order_by_expression_with_limit_pushes_down() {
    let Some(driver) = driver_path() else { return };
    let dir = tempfile::tempdir().expect("tempdir");
    let db_file = dir.path().join("contract.duckdb");
    let db_file = db_file.to_str().expect("utf8 temp path");
    seed_join_fixture(&driver, db_file);
    let ctx = contract_context(&driver, db_file).await;

    let sql = "SELECT id, amount FROM orders ORDER BY amount * -1.0, id LIMIT 3";

    let batches = ctx
        .sql(sql)
        .await
        .expect("plans")
        .collect()
        .await
        .expect("executes");
    let rendered = pretty_format_batches(&batches).unwrap().to_string();
    let rows: usize = batches.iter().map(RecordBatch::num_rows).sum();
    assert_eq!(rows, 3, "LIMIT applies:\n{rendered}");
    assert!(
        rendered.contains("100"),
        "highest amount first:\n{rendered}"
    );

    assert_fully_pushed(&ctx, sql, &["ORDER BY", "LIMIT"]).await;
}

/// **Known-wart pin.** A locally-registered UDF over a federated table
/// does NOT split the plan today — datafusion-federation 0.5.3 treats
/// the whole subtree as federatable, unparses `double_local(...)`
/// verbatim, and the remote rejects the unknown function (upstream
/// datafusion-federation #129 is the ask for exactly this control).
/// Found by 's first run: there is no graceful-degradation
/// contract to pin, so pin the failure shape instead — if a bump makes
/// this split-and-succeed, this test fails and should be flipped into
/// the partial-pushdown assertion it was originally written as.
#[tokio::test]
async fn local_udf_over_federated_table_is_a_known_wart() {
    let Some(driver) = driver_path() else { return };
    let dir = tempfile::tempdir().expect("tempdir");
    let db_file = dir.path().join("contract.duckdb");
    let db_file = db_file.to_str().expect("utf8 temp path");
    seed_join_fixture(&driver, db_file);
    let ctx = contract_context(&driver, db_file).await;

    let double_local = create_udf(
        "double_local",
        vec![DataType::Float64],
        DataType::Float64,
        Volatility::Immutable,
        Arc::new(|args: &[ColumnarValue]| {
            let arrays = ColumnarValue::values_to_arrays(args)?;
            let input = arrays[0]
                .as_any()
                .downcast_ref::<Float64Array>()
                .expect("float64 input");
            let doubled: Float64Array = input.iter().map(|v| v.map(|x| x * 2.0)).collect();
            Ok(ColumnarValue::Array(Arc::new(doubled)))
        }),
    );
    ctx.register_udf(double_local);

    let sql = "SELECT region, double_local(amount) AS doubled
               FROM orders
               WHERE amount >= 50
               ORDER BY doubled DESC";

    let err = ctx
        .sql(sql)
        .await
        .expect("plans")
        .collect()
        .await
        .expect_err(
            "local UDFs currently get unparsed to the remote and rejected there — if \
             this now SUCCEEDS, a dependency bump added plan splitting: flip this pin \
             into the partial-pushdown assertion (scan pushes, UDF evaluates locally)",
        );
    let msg = err.to_string();
    assert!(
        msg.contains("double_local"),
        "expected the remote to reject the unknown UDF by name, got: {msg}"
    );
}

/// `EXPLAIN ANALYZE` over a federated plan — upstream broke and fixed
/// this in datafusion-federation 0.5.3 (#168), so it's proven
/// regression-prone surface.
#[tokio::test]
async fn explain_analyze_executes_over_a_federated_plan() {
    let Some(driver) = driver_path() else { return };
    let dir = tempfile::tempdir().expect("tempdir");
    let db_file = dir.path().join("contract.duckdb");
    let db_file = db_file.to_str().expect("utf8 temp path");
    seed_join_fixture(&driver, db_file);
    let ctx = contract_context(&driver, db_file).await;

    let df = ctx
        .sql("EXPLAIN ANALYZE SELECT segment, COUNT(*) FROM customers GROUP BY segment")
        .await
        .expect("EXPLAIN ANALYZE parses");
    let batches = df.collect().await.expect(
        "EXPLAIN ANALYZE must execute over a federated plan (datafusion-federation #168 \
         regression surface)",
    );
    let rendered = pretty_format_batches(&batches).unwrap().to_string();
    assert!(
        rendered.contains("VirtualExecutionPlan") || rendered.contains("sql_federation_exec"),
        "EXPLAIN ANALYZE output must show the federation node with metrics:\n{rendered}"
    );
}

/// **Known-BUG pin (now fails safe under DF54)** — datafusion-federation
/// #82: a JOIN against a subquery containing DISTINCT is mishandled through
/// federation. alice has two orders ≥ 25, so the correct result lists her
/// once (3 rows). On DataFusion 53 the dedup was silently DROPPED, returning
/// WRONG results — alice TWICE, 4 rows. The DataFusion 54 /
/// datafusion-federation 0.5.5 bump **mutated the bug into the
/// safer failure mode**: the unparser now emits a subquery whose `orders`
/// reference is out of scope, so the source (DuckDB) rejects it with a
/// binder error rather than returning wrong data. The original pin noted
/// "wrong results are strictly worse than the error upstream #82 reports" —
/// this is now that error. The underlying dedup-through-federation bug is
/// still unfixed (correct = 3 rows, no error); this pin tracks the current
/// fail-safe shape so the eventual real fix (3 rows) fails loudly and gets
/// reviewed — as does any regression back to df53's silent-wrong-results.
#[tokio::test]
async fn distinct_subquery_join_currently_errors_at_source() {
    let Some(driver) = driver_path() else { return };
    let dir = tempfile::tempdir().expect("tempdir");
    let db_file = dir.path().join("contract.duckdb");
    let db_file = db_file.to_str().expect("utf8 temp path");
    seed_join_fixture(&driver, db_file);
    // Deliberately UNGUARDED: this pin documents the raw federation
    // behavior the  guard exists to intercept.
    let ctx = unguarded_contract_context(&driver, db_file).await;

    let sql = "SELECT c.name
               FROM customers c
               JOIN (SELECT DISTINCT customer_id FROM orders WHERE amount >= 25) o
                 ON o.customer_id = c.id
               ORDER BY c.name";

    // DF54/federation 0.5.5: the pushed subquery's `orders` reference is out
    // of scope, so execution fails at the source binder rather than returning
    // df53's wrong-but-succeeding 4-row result.
    let err = ctx
        .sql(sql)
        .await
        .expect("distinct-subquery join plans")
        .collect()
        .await
        .expect_err(
            "KNOWN BUG (datafusion-federation #82): under DF54 the DISTINCT-subquery \
             join errors at the source instead of returning wrong rows. If this now \
             SUCCEEDS the behavior moved — 3 rows means the bug is FIXED (flip this \
             pin into the correct assertion); 4 rows is a regression to df53's \
             silent-wrong-results shape.",
        );
    let msg = err.to_string();
    assert!(
        msg.contains("not found") || msg.to_lowercase().contains("binder"),
        "expected a source-side binder error (subquery table out of scope), got: {msg}"
    );
}

/// **Guard contract.** A subquery predicate inside an `OR`
/// decorrelates to a MARK join; DataFusion 54.1's unparser DROPS it,
/// emitting SQL that references a dangling correlated table. Both fixture
/// tables live in the one DuckDB source, so federation collapses the mark
/// join into a single pushed statement — where `FederatedMarkJoinGuard`
/// (wired into `federated_optimizer_rules`, so active in `contract_context`)
/// must FAIL planning rather than let the broken SQL reach the source.
/// The in-crate rule tests pin the traversal; this pins the whole
/// federation stack end-to-end.
#[tokio::test]
async fn or_in_subquery_mark_join_is_rejected_by_guard() {
    let Some(driver) = driver_path() else { return };
    let dir = tempfile::tempdir().expect("tempdir");
    let db_file = dir.path().join("contract.duckdb");
    let db_file = db_file.to_str().expect("utf8 temp path");
    seed_join_fixture(&driver, db_file);
    let ctx = contract_context(&driver, db_file).await;

    // `segment = 'pro' OR id IN (…)` cannot be a plain semi join, so it
    // decorrelates to a mark join.
    let sql = "SELECT name FROM customers \
               WHERE segment = 'pro' \
                  OR id IN (SELECT customer_id FROM orders WHERE amount >= 50)";

    // Match on both call sites: the guard runs in the optimizer, which today
    // fires at `collect`, but a future DataFusion could optimize during `sql`.
    let err = match ctx.sql(sql).await {
        Err(e) => e,
        Ok(df) => df.collect().await.expect_err(
            "a federated OR-ed IN subquery is a mark join the unparser drops; \
             FederatedMarkJoinGuard must reject it rather than ship SQL with a \
             dangling correlated reference",
        ),
    };
    let msg = err.to_string();
    assert!(
        msg.contains(dataglot_core::federation_mark_join_guard::MARK_JOIN_UNPARSE_GUARD_ERROR),
        "expected the mark-join guard rejection, got: {msg}"
    );

    // The rewrite the error recommends — two DISJOINT branches — must run on
    // the SAME guarded context (no mark join) and return the correct THREE
    // names: bob/carol (pro) and alice (id 1 has a >= 50 order); dave is
    // neither pro nor has such an order. Proves the hint is executable and
    // bag-equivalent (no dupe for carol, who satisfies both branches' source
    // predicate but lands only in branch 1).
    let rewritten = "SELECT name FROM customers WHERE segment = 'pro' \
                     UNION ALL \
                     SELECT name FROM customers \
                       WHERE (segment = 'pro') IS NOT TRUE \
                         AND id IN (SELECT customer_id FROM orders WHERE amount >= 50) \
                     ORDER BY name";
    let batches = ctx
        .sql(rewritten)
        .await
        .expect("rewrite plans")
        .collect()
        .await
        .expect("rewrite executes");
    let rendered = pretty_format_batches(&batches).unwrap().to_string();
    let rows: usize = batches.iter().map(RecordBatch::num_rows).sum();
    assert_eq!(
        rows, 3,
        "disjoint rewrite returns exactly the 3 matches:\n{rendered}"
    );
    for name in ["alice", "bob", "carol"] {
        assert!(rendered.contains(name), "{name} must appear:\n{rendered}");
    }
    assert!(
        !rendered.contains("dave"),
        "dave must not appear:\n{rendered}"
    );
}

// ---------------------------------------------------------------------------
// Deep-coverage shapes ( second pass — "every level" sweep).
// Each is written optimistically as a full-pushdown assertion first;
// where 0.5.3 reality differs, the test is a behavior pin with an
// upstream reference so the  bump review sees the change.
// ---------------------------------------------------------------------------

/// LEFT OUTER JOIN collapse + NULL-extension semantics: every customer
/// appears even without qualifying orders, and the join still ships as
/// one pushed query.
#[tokio::test]
async fn left_outer_join_collapses_and_null_extends() {
    let Some(driver) = driver_path() else { return };
    let dir = tempfile::tempdir().expect("tempdir");
    let db_file = dir.path().join("contract.duckdb");
    let db_file = db_file.to_str().expect("utf8 temp path");
    seed_join_fixture(&driver, db_file);
    let ctx = contract_context(&driver, db_file).await;

    let sql = "SELECT c.name, SUM(o.amount) AS total
               FROM customers c
               LEFT JOIN orders o ON o.customer_id = c.id AND o.amount >= 25
               GROUP BY c.name
               ORDER BY c.name";

    let batches = ctx
        .sql(sql)
        .await
        .expect("plans")
        .collect()
        .await
        .expect("executes");
    let rendered = pretty_format_batches(&batches).unwrap().to_string();
    let rows: usize = batches.iter().map(RecordBatch::num_rows).sum();
    // All four customers appear; dave has no qualifying order → NULL total.
    assert_eq!(rows, 4, "LEFT JOIN keeps every customer:\n{rendered}");
    assert!(
        rendered.contains("dave"),
        "unmatched row survives:\n{rendered}"
    );

    assert_fully_pushed(&ctx, sql, &["LEFT", "JOIN", "GROUP BY"]).await;
}

/// Self-join (same table twice, aliased) must collapse too.
#[tokio::test]
async fn self_join_collapses() {
    let Some(driver) = driver_path() else { return };
    let dir = tempfile::tempdir().expect("tempdir");
    let db_file = dir.path().join("contract.duckdb");
    let db_file = db_file.to_str().expect("utf8 temp path");
    seed_join_fixture(&driver, db_file);
    let ctx = contract_context(&driver, db_file).await;

    // Pairs of orders by the same customer with the first strictly larger.
    let sql = "SELECT a.id, b.id
               FROM orders a
               JOIN orders b ON b.customer_id = a.customer_id AND a.amount > b.amount
               ORDER BY a.id, b.id";

    let batches = ctx
        .sql(sql)
        .await
        .expect("plans")
        .collect()
        .await
        .expect("executes");
    let rows: usize = batches.iter().map(RecordBatch::num_rows).sum();
    // alice: (100,40); carol: (60,5); dave: (2,1) → 3 pairs.
    assert_eq!(rows, 3, "expected 3 same-customer descending pairs");

    assert_fully_pushed(&ctx, sql, &["JOIN"]).await;
}

/// Three tables of the same source in one query — the collapse must
/// cover the whole chain, not just the first pair.
#[tokio::test]
async fn three_table_join_collapses() {
    let Some(driver) = driver_path() else { return };
    let dir = tempfile::tempdir().expect("tempdir");
    let db_file = dir.path().join("contract.duckdb");
    let db_file = db_file.to_str().expect("utf8 temp path");
    seed_join_fixture(&driver, db_file);
    let ctx = contract_context(&driver, db_file).await;

    let sql = "SELECT r.title, c.segment, SUM(o.amount) AS revenue
               FROM orders o
               JOIN customers c ON c.id = o.customer_id
               JOIN regions r ON r.code = o.region
               GROUP BY r.title, c.segment
               ORDER BY revenue DESC
               LIMIT 10";

    let batches = ctx
        .sql(sql)
        .await
        .expect("plans")
        .collect()
        .await
        .expect("executes");
    let rendered = pretty_format_batches(&batches).unwrap().to_string();
    assert!(
        rendered.contains("Americas") || rendered.contains("Europe"),
        "region titles joined in:\n{rendered}"
    );

    assert_fully_pushed(&ctx, sql, &["JOIN", "GROUP BY", "ORDER BY", "LIMIT"]).await;
}

/// UNION ALL of two same-source queries.
#[tokio::test]
async fn union_all_same_source_collapses() {
    let Some(driver) = driver_path() else { return };
    let dir = tempfile::tempdir().expect("tempdir");
    let db_file = dir.path().join("contract.duckdb");
    let db_file = db_file.to_str().expect("utf8 temp path");
    seed_join_fixture(&driver, db_file);
    let ctx = contract_context(&driver, db_file).await;

    let sql = "SELECT name AS label FROM customers WHERE segment = 'pro'
               UNION ALL
               SELECT region AS label FROM orders WHERE amount >= 100
               ORDER BY label";

    let batches = ctx
        .sql(sql)
        .await
        .expect("plans")
        .collect()
        .await
        .expect("executes");
    let rendered = pretty_format_batches(&batches).unwrap().to_string();
    let rows: usize = batches.iter().map(RecordBatch::num_rows).sum();
    // pro customers {bob, carol} + the single 100.0 order's region {emea}.
    assert_eq!(rows, 3, "2 pro customers + 1 big-order region:\n{rendered}");

    assert_fully_pushed(&ctx, sql, &["UNION"]).await;
}

/// Aggregate diversity in one shot: MIN / MAX / AVG / COUNT(DISTINCT).
#[tokio::test]
async fn aggregate_diversity_including_count_distinct_pushes_down() {
    let Some(driver) = driver_path() else { return };
    let dir = tempfile::tempdir().expect("tempdir");
    let db_file = dir.path().join("contract.duckdb");
    let db_file = db_file.to_str().expect("utf8 temp path");
    seed_join_fixture(&driver, db_file);
    let ctx = contract_context(&driver, db_file).await;

    let sql = "SELECT COUNT(DISTINCT customer_id) AS buyers,
                      MIN(amount) AS lo,
                      MAX(amount) AS hi,
                      AVG(amount) AS mean
               FROM orders";

    let batches = ctx
        .sql(sql)
        .await
        .expect("plans")
        .collect()
        .await
        .expect("executes");
    let rendered = pretty_format_batches(&batches).unwrap().to_string();
    assert!(rendered.contains('4'), "4 distinct buyers:\n{rendered}");
    assert!(rendered.contains("100"), "max 100:\n{rendered}");

    assert_fully_pushed(&ctx, sql, &["DISTINCT", "MIN", "MAX", "AVG"]).await;
}

/// Scalar-expression surface: BETWEEN, LIKE, IS NULL, and a string
/// function all riding one pushed query.
#[tokio::test]
async fn scalar_expression_surface_pushes_down() {
    let Some(driver) = driver_path() else { return };
    let dir = tempfile::tempdir().expect("tempdir");
    let db_file = dir.path().join("contract.duckdb");
    let db_file = db_file.to_str().expect("utf8 temp path");
    seed_join_fixture(&driver, db_file);
    let ctx = contract_context(&driver, db_file).await;

    let sql = "SELECT upper(region) AS reg, amount
               FROM orders
               WHERE (amount BETWEEN 2 AND 90 AND region LIKE 'a%')
                  OR region IS NULL
               ORDER BY amount DESC";

    let batches = ctx
        .sql(sql)
        .await
        .expect("plans")
        .collect()
        .await
        .expect("executes");
    let rendered = pretty_format_batches(&batches).unwrap().to_string();
    let rows: usize = batches.iter().map(RecordBatch::num_rows).sum();
    // amer {40}, apac {60, 5} match the LIKE branch; the NULL-region 2.0 joins.
    assert_eq!(rows, 4, "3 LIKE matches + 1 NULL-region row:\n{rendered}");

    // DataFusion normalizes BETWEEN into `>= AND <=` before the unparse,
    // so the pushed SQL carries the expanded form — assert the operators
    // that survive normalization.
    assert_fully_pushed(&ctx, sql, &["LIKE", "IS NULL", ">=", "<="]).await;
}

/// CTE (`WITH`) over one source.
#[tokio::test]
async fn cte_same_source_collapses() {
    let Some(driver) = driver_path() else { return };
    let dir = tempfile::tempdir().expect("tempdir");
    let db_file = dir.path().join("contract.duckdb");
    let db_file = db_file.to_str().expect("utf8 temp path");
    seed_join_fixture(&driver, db_file);
    let ctx = contract_context(&driver, db_file).await;

    let sql = "WITH big AS (SELECT customer_id, amount FROM orders WHERE amount >= 40)
               SELECT c.name, COUNT(*) AS n
               FROM big JOIN customers c ON c.id = big.customer_id
               GROUP BY c.name
               ORDER BY c.name";

    let batches = ctx
        .sql(sql)
        .await
        .expect("plans")
        .collect()
        .await
        .expect("executes");
    let rendered = pretty_format_batches(&batches).unwrap().to_string();
    let rows: usize = batches.iter().map(RecordBatch::num_rows).sum();
    // ≥40: alice {100, 40}, carol {60}.
    assert_eq!(rows, 2, "alice + carol have big orders:\n{rendered}");

    assert_fully_pushed(&ctx, sql, &["JOIN", "GROUP BY"]).await;
}

/// Window function over a federated table.
#[tokio::test]
async fn window_function_over_federated_table() {
    let Some(driver) = driver_path() else { return };
    let dir = tempfile::tempdir().expect("tempdir");
    let db_file = dir.path().join("contract.duckdb");
    let db_file = db_file.to_str().expect("utf8 temp path");
    seed_join_fixture(&driver, db_file);
    let ctx = contract_context(&driver, db_file).await;

    let sql = "SELECT id, customer_id, amount,
                      ROW_NUMBER() OVER (PARTITION BY customer_id ORDER BY amount DESC) AS rk
               FROM orders
               ORDER BY customer_id, rk";

    let batches = ctx
        .sql(sql)
        .await
        .expect("window over federated table plans")
        .collect()
        .await
        .expect("window over federated table executes");
    let rendered = pretty_format_batches(&batches).unwrap().to_string();
    let rows: usize = batches.iter().map(RecordBatch::num_rows).sum();
    assert_eq!(rows, 7, "one row per order:\n{rendered}");

    assert_fully_pushed(&ctx, sql, &["ROW_NUMBER", "OVER"]).await;
}

/// Correlated EXISTS subquery against the same source.
#[tokio::test]
async fn correlated_exists_same_source() {
    let Some(driver) = driver_path() else { return };
    let dir = tempfile::tempdir().expect("tempdir");
    let db_file = dir.path().join("contract.duckdb");
    let db_file = db_file.to_str().expect("utf8 temp path");
    seed_join_fixture(&driver, db_file);
    let ctx = contract_context(&driver, db_file).await;

    let sql = "SELECT name FROM customers c
               WHERE EXISTS (SELECT 1 FROM orders o
                             WHERE o.customer_id = c.id AND o.amount >= 60)
               ORDER BY name";

    let batches = ctx
        .sql(sql)
        .await
        .expect("correlated EXISTS plans")
        .collect()
        .await
        .expect("correlated EXISTS executes");
    let rendered = pretty_format_batches(&batches).unwrap().to_string();
    let rows: usize = batches.iter().map(RecordBatch::num_rows).sum();
    // ≥60: alice (100), carol (60).
    assert_eq!(rows, 2, "alice + carol:\n{rendered}");

    assert_fully_pushed(&ctx, sql, &[]).await;
}

/// INTERSECT of two same-source queries.
#[tokio::test]
async fn intersect_same_source() {
    let Some(driver) = driver_path() else { return };
    let dir = tempfile::tempdir().expect("tempdir");
    let db_file = dir.path().join("contract.duckdb");
    let db_file = db_file.to_str().expect("utf8 temp path");
    seed_join_fixture(&driver, db_file);
    let ctx = contract_context(&driver, db_file).await;

    // Customers with an emea order ∩ customers with an order ≥ 25.
    let sql = "SELECT customer_id FROM orders WHERE region = 'emea'
               INTERSECT
               SELECT customer_id FROM orders WHERE amount >= 25
               ORDER BY customer_id";

    let batches = ctx
        .sql(sql)
        .await
        .expect("INTERSECT plans")
        .collect()
        .await
        .expect("INTERSECT executes");
    let rendered = pretty_format_batches(&batches).unwrap().to_string();
    let rows: usize = batches.iter().map(RecordBatch::num_rows).sum();
    // emea buyers {1, 2, 4} ∩ ≥25 buyers {1, 2, 3} = {1, 2}.
    assert_eq!(rows, 2, "customers 1 and 2:\n{rendered}");

    // DataFusion rewrites INTERSECT into a LeftSemi JOIN before
    // federation sees the plan, so the pushed SQL carries the join
    // form — the contract is that the WHOLE rewritten plan still
    // collapses into one pushed query.
    assert_fully_pushed(&ctx, sql, &["JOIN"]).await;
}

/// **The  guard in production wiring.** With the guard rule
/// installed (as `contract_context` — and production — does), the
/// wrong-results shape is REJECTED at planning with an actionable
/// error instead of silently returning duplicated rows. Retires
/// together with the guard at the  DataFusion 54 bump, when
/// the sibling raw-behavior pin flips to correct results.
#[tokio::test]
async fn distinct_subquery_join_is_rejected_by_the_dedup_guard() {
    let Some(driver) = driver_path() else { return };
    let dir = tempfile::tempdir().expect("tempdir");
    let db_file = dir.path().join("contract.duckdb");
    let db_file = db_file.to_str().expect("utf8 temp path");
    seed_join_fixture(&driver, db_file);
    let ctx = contract_context(&driver, db_file).await;

    let sql = "SELECT c.name
               FROM customers c
               JOIN (SELECT DISTINCT customer_id FROM orders WHERE amount >= 25) o
                 ON o.customer_id = c.id
               ORDER BY c.name";

    let err = match ctx.sql(sql).await {
        Err(e) => e,
        Ok(df) => df
            .collect()
            .await
            .expect_err("the dedup-unparse guard must reject the wrong-results shape"),
    };
    let msg = err.to_string();
    assert!(
        msg.contains("duplicated rows"),
        "error must describe the failure mode: {msg}"
    );
    assert!(
        msg.contains("IN (SELECT"),
        "error must name the working rewrite: {msg}"
    );

    // The recommended rewrite works on the SAME (guarded) context and
    // returns the correct THREE distinct names.
    let rewritten = "SELECT name FROM customers
                     WHERE id IN (SELECT customer_id FROM orders WHERE amount >= 25)
                     ORDER BY name";
    let batches = ctx
        .sql(rewritten)
        .await
        .expect("rewrite plans")
        .collect()
        .await
        .expect("rewrite executes under the guard");
    let rows: usize = batches.iter().map(RecordBatch::num_rows).sum();
    assert_eq!(rows, 3, "alice, bob, carol — no duplicates");
}

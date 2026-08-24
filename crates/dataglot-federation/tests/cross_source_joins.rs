//! Cross-source JOIN correctness tests.
//!
//! Boots a `PostgreSQL` and a `MySQL` container side-by-side via
//! `testcontainers-modules`, registers both as federated table
//! providers on a single `DataFusion` `SessionContext`, and
//! exercises canonical JOIN shapes that span both sources.
//!
//! These tests pin the Phase 1 "Federation breadth" claim that
//! cross-source queries actually work — not just single-source
//! pushdown. Per the spec at
//! the phase-1 `mysql-federation-connector` plan, the
//! join itself executes inside `DataFusion` (each side's filter /
//! projection / limit pushes down to its source via the
//! datafusion-federation unparser; the join is a `HashJoin` /
//! `NestedLoopJoin` in the cross-source plan).
//!
//! All tests are `#[ignore = "requires Docker"]` because they
//! need both `postgres:latest` and `mysql:8.1` images. They run
//! in CI via the existing
//!   `cargo test --features all -p dataglot-federation --tests --
//!    --ignored --test-threads=1`
//! invocation in `.github/workflows/integration.yml`.

#![cfg(all(feature = "postgres", feature = "mysql"))]

use std::collections::BTreeMap;
use std::sync::Arc;

use datafusion::arrow::array::{Int32Array, Int64Array, RecordBatch, StringArray};
use datafusion::arrow::util::pretty::pretty_format_batches;
use dataglot_core::{SessionConfig, SessionContextFactory};
use dataglot_federation::mysql::MysqlConnector;
use dataglot_federation::postgres::PostgresConnector;
use mysql_async::prelude::Queryable;
use testcontainers::runners::AsyncRunner;
use testcontainers_modules::mysql::Mysql;
use testcontainers_modules::postgres::Postgres;
use tokio_postgres::NoTls;

/// Spin up both containers, seed `pg.public.users` and
/// `mysql.test.orders`, return DSNs and the live container handles
/// (which the caller must keep alive for the test's duration).
///
/// Test data:
///   `users`  (id INT PK, name VARCHAR, age INT)
///       (1, 'Alice', 30)
///       (2, 'Bob',   25)
///       (3, 'Carol', 35)
///
///   `orders` (`id` INT PK, `user_id` INT, total INT)
///       (101, 1, 50)   ← Alice
///       (102, 1, 80)   ← Alice
///       (103, 2, 30)   ← Bob
///       (104, 3, 200)  ← Carol
///       (105, 3, 75)   ← Carol
///
/// `user_id = 4` (no matching user) is intentionally omitted; we
/// could add it for outer-join coverage in a follow-up.
async fn setup_both_sources() -> (
    String,
    String,
    testcontainers::ContainerAsync<Postgres>,
    testcontainers::ContainerAsync<Mysql>,
) {
    // ---- Postgres side ---------------------------------------------
    let pg = Postgres::default()
        .start()
        .await
        .expect("postgres container starts");
    let pg_host = pg.get_host().await.expect("pg host");
    let pg_port = pg.get_host_port_ipv4(5432).await.expect("pg port");
    let pg_dsn =
        format!("host={pg_host} port={pg_port} user=postgres password=postgres dbname=postgres");

    let (pg_client, pg_conn) = tokio_postgres::connect(&pg_dsn, NoTls)
        .await
        .expect("pg seed-side connect");
    tokio::spawn(async move {
        // `tokio_postgres::Error::Display` doesn't include the DSN
        // or password in practice, but log a static message
        // anyway — defense-in-depth. The test framework still
        // captures a backtrace if anything crashes mid-test.
        if pg_conn.await.is_err() {
            eprintln!("postgres connection error (redacted)");
        }
    });
    pg_client
        .batch_execute(
            "CREATE TABLE public.users (
                 id   INT PRIMARY KEY,
                 name VARCHAR(100) NOT NULL,
                 age  INT NOT NULL
             );
             INSERT INTO public.users (id, name, age) VALUES
                 (1, 'Alice', 30),
                 (2, 'Bob',   25),
                 (3, 'Carol', 35);",
        )
        .await
        .expect("seed pg.users");

    // ---- MySQL side ------------------------------------------------
    let my = Mysql::default()
        .start()
        .await
        .expect("mysql container starts");
    let my_host = my.get_host().await.expect("mysql host");
    let my_port = my.get_host_port_ipv4(3306).await.expect("mysql port");
    let my_dsn = format!("mysql://root@{my_host}:{my_port}/test");

    let mut my_conn =
        mysql_async::Conn::new(mysql_async::Opts::from_url(&my_dsn).expect("mysql DSN parses"))
            .await
            .expect("mysql seed-side connect");
    my_conn
        .query_drop(
            "CREATE TABLE orders (
                 id      INT PRIMARY KEY,
                 user_id INT NOT NULL,
                 total   INT NOT NULL
             )",
        )
        .await
        .expect("create mysql.orders");
    my_conn
        .query_drop(
            "INSERT INTO orders (id, user_id, total) VALUES
                (101, 1, 50),
                (102, 1, 80),
                (103, 2, 30),
                (104, 3, 200),
                (105, 3, 75)",
        )
        .await
        .expect("seed mysql.orders");
    my_conn.disconnect().await.expect("mysql conn closes");

    (pg_dsn, my_dsn, pg, my)
}

/// Build a federation-aware `SessionContext` with `users` (from
/// `PostgreSQL`) and `orders` (from `MySQL`) registered as flat
/// table names (1-part references). The federation rule + planner
/// are bolted on so cross-source JOINs route filter/projection
/// pushdown to each source independently.
async fn federated_ctx_with_both(
    pg_dsn: &str,
    my_dsn: &str,
) -> datafusion::prelude::SessionContext {
    let pg = Arc::new(
        PostgresConnector::connect(pg_dsn)
            .await
            .expect("pg connector connects"),
    );
    let pg_provider = pg
        .table_provider("public", "users")
        .await
        .expect("pg.public.users table_provider");

    let my = Arc::new(
        MysqlConnector::connect("mysql_demo", my_dsn)
            .await
            .expect("mysql connector connects"),
    );
    let my_provider = my
        .table_provider("test", "orders")
        .await
        .expect("mysql.test.orders table_provider");

    // Use the *production* federated context: federation rules + planner,
    // FilterPushdown kept for scan-time parquet pushdown, and the
    // `WrapFederationNodes` guard that prevents the datafusion-federation
    // 0.5.3 cross-source WHERE drop. These tests are the
    // regression coverage for that guard.
    let factory = SessionContextFactory::new(SessionConfig::new()).expect("factory");
    let ctx = factory.create_federated_context();

    ctx.register_table("users", pg_provider)
        .expect("register users");
    ctx.register_table("orders", my_provider)
        .expect("register orders");
    ctx
}

/// INNER JOIN spanning `Postgres` `users` and `MySQL` `orders`. Pin:
///
/// * The right rows survive — Alice (2 orders) + Bob (1) + Carol
///   (2) ⇒ 5 rows total, columns `(name, total)`.
/// * EXPLAIN shows two federation virtual exec nodes, one per
///   source. Each side's projection is pushed down independently
///   (only `id`, `name` from pg; only `user_id`, `total` from
///   mysql).
#[tokio::test]
#[ignore = "requires Docker"]
async fn cross_source_inner_join() {
    let (pg_dsn, my_dsn, _pg, _my) = setup_both_sources().await;
    let ctx = federated_ctx_with_both(&pg_dsn, &my_dsn).await;

    let df = ctx
        .sql(
            "SELECT u.name, o.total \
             FROM users u \
             INNER JOIN orders o ON u.id = o.user_id \
             ORDER BY u.name, o.total",
        )
        .await
        .expect("SQL parses and plans");
    let batches = df.collect().await.expect("executes");

    let total_rows: usize = batches.iter().map(RecordBatch::num_rows).sum();
    assert_eq!(
        total_rows,
        5,
        "expected 5 joined rows (3 users × N orders), got:\n{}",
        pretty_format_batches(&batches).unwrap()
    );

    // Decode columns directly and assert per-user multiplicities.
    // Substring `printed.contains("Alice")` would prove presence
    // but not the claimed `Alice=2, Bob=1, Carol=2` distribution
    // — an incorrect join cardinality could still pass.
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for batch in &batches {
        let names = batch
            .column(0)
            .as_any()
            .downcast_ref::<StringArray>()
            .expect("name column is Utf8");
        for row in 0..batch.num_rows() {
            *counts.entry(names.value(row).to_owned()).or_default() += 1;
        }
    }
    assert_eq!(
        counts.get("Alice"),
        Some(&2),
        "Alice should match her 2 orders, got:\n{counts:?}"
    );
    assert_eq!(
        counts.get("Bob"),
        Some(&1),
        "Bob should match his 1 order, got:\n{counts:?}"
    );
    assert_eq!(
        counts.get("Carol"),
        Some(&2),
        "Carol should match her 2 orders, got:\n{counts:?}"
    );

    // Pushdown signal: at least two virtual exec nodes appear in
    // EXPLAIN — one per source. Count distinct lines that mention
    // either federation token (rather than summing substring
    // matches, which could double-count a single line carrying
    // both tokens). We avoid asserting the exact SQL pushed since
    // it depends on the unparser's ordering.
    let explain = ctx
        .sql(
            "EXPLAIN SELECT u.name, o.total FROM users u \
             INNER JOIN orders o ON u.id = o.user_id",
        )
        .await
        .expect("EXPLAIN parses");
    let explain_str = pretty_format_batches(&explain.collect().await.expect("EXPLAIN runs"))
        .unwrap()
        .to_string();
    let federation_lines = explain_str
        .lines()
        .filter(|line| {
            line.contains("VirtualExecutionPlan") || line.contains("sql_federation_exec")
        })
        .count();
    assert!(
        federation_lines >= 2,
        "expected at least two distinct federation exec-node lines (one per source) in:\n{explain_str}"
    );
}

/// **Cross-source WHERE is retained —  regression test.**
///
/// A `WHERE` clause on top of a cross-source JOIN is exactly the case
/// `datafusion-federation 0.5.3` gets wrong: `VirtualExecutionPlan`
/// reports it absorbed the parent `FilterExec` (so DataFusion deletes
/// it) but never unparses the predicate into the remote SQL — the
/// filter is silently dropped and the full 5-row inner join comes back.
///
/// The production federated context (`create_federated_context`, used
/// by `federated_ctx_with_both`) installs the `WrapFederationNodes`
/// guard, which declines that physical pushdown so the `FilterExec` is
/// retained above the federation node. `WHERE o.total > 100` (mysql
/// side, projected column) then keeps only Carol's order #104
/// (total 200) → exactly 1 row.
///
/// History: this was a `#[should_panic]` "flag-when-fixed" sentinel
/// (`..._known_drop`) capturing the broken 5-row behaviour; it was
/// flipped to a hard assertion when the  guard landed.
#[tokio::test]
#[ignore = "requires Docker"]
async fn cross_source_join_with_mysql_side_predicate() {
    let (pg_dsn, my_dsn, _pg, _my) = setup_both_sources().await;
    let ctx = federated_ctx_with_both(&pg_dsn, &my_dsn).await;

    let df = ctx
        .sql(
            "SELECT u.name, o.total \
             FROM users u \
             INNER JOIN orders o ON u.id = o.user_id \
             WHERE o.total > 100",
        )
        .await
        .expect("SQL parses");
    let batches = df.collect().await.expect("executes");
    let total_rows: usize = batches.iter().map(RecordBatch::num_rows).sum();
    assert_eq!(
        total_rows,
        1,
        "cross-source WHERE must be retained: only Carol's 200>100 \
         order survives, got:\n{}",
        pretty_format_batches(&batches).unwrap()
    );
    // The surviving row is Carol / 200 — confirm the predicate filtered
    // on the real value, not a coincidence of cardinality.
    let name = batches[0]
        .column(0)
        .as_any()
        .downcast_ref::<StringArray>()
        .expect("name col");
    // mysql `INT` decodes to Int32 (the aggregation test widens to i64
    // only because SUM's accumulator does).
    let total = batches[0]
        .column(1)
        .as_any()
        .downcast_ref::<Int32Array>()
        .expect("total col is Int32");
    assert_eq!(name.value(0), "Carol");
    assert_eq!(total.value(0), 200);
}

/// Companion to the above on the **pg side**, filtering a
/// *non-projected* column (`u.age`) above the cross-source JOIN — the
/// other shape PR #166 recorded as dropped. With the guard the filter
/// is retained: `age > 28` keeps Alice (30) and Carol (35), so their
/// orders survive (Alice 2 + Carol 2 = 4 rows) and Bob (25) is gone.
#[tokio::test]
#[ignore = "requires Docker"]
async fn cross_source_join_with_pg_side_predicate() {
    let (pg_dsn, my_dsn, _pg, _my) = setup_both_sources().await;
    let ctx = federated_ctx_with_both(&pg_dsn, &my_dsn).await;

    let df = ctx
        .sql(
            "SELECT u.name, o.total \
             FROM users u \
             INNER JOIN orders o ON u.id = o.user_id \
             WHERE u.age > 28",
        )
        .await
        .expect("SQL parses");
    let batches = df.collect().await.expect("executes");
    let total_rows: usize = batches.iter().map(RecordBatch::num_rows).sum();
    assert_eq!(
        total_rows,
        4,
        "pg-side WHERE on a non-projected column must be retained: \
         Alice(30)+Carol(35) orders survive, Bob(25) filtered, got:\n{}",
        pretty_format_batches(&batches).unwrap()
    );

    let mut names: BTreeMap<String, usize> = BTreeMap::new();
    for batch in &batches {
        let col = batch
            .column(0)
            .as_any()
            .downcast_ref::<StringArray>()
            .expect("name col");
        for row in 0..batch.num_rows() {
            *names.entry(col.value(row).to_owned()).or_default() += 1;
        }
    }
    assert_eq!(
        names.get("Alice"),
        Some(&2),
        "Alice's 2 orders, got {names:?}"
    );
    assert_eq!(
        names.get("Carol"),
        Some(&2),
        "Carol's 2 orders, got {names:?}"
    );
    assert_eq!(
        names.get("Bob"),
        None,
        "Bob (age 25) must be filtered, got {names:?}"
    );
}

/// JOIN + GROUP BY across both sources. Pin that aggregation
/// composes correctly even when the inputs come from heterogeneous
/// connectors.
///
/// Expected: per-user totals
///     Alice → 130
///     Bob   → 30
///     Carol → 275
#[tokio::test]
#[ignore = "requires Docker"]
async fn cross_source_join_with_aggregation() {
    let (pg_dsn, my_dsn, _pg, _my) = setup_both_sources().await;
    let ctx = federated_ctx_with_both(&pg_dsn, &my_dsn).await;

    let df = ctx
        .sql(
            "SELECT u.name, SUM(o.total) AS total \
             FROM users u \
             INNER JOIN orders o ON u.id = o.user_id \
             GROUP BY u.name \
             ORDER BY u.name",
        )
        .await
        .expect("SQL parses");
    let batches = df.collect().await.expect("executes");

    let total_rows: usize = batches.iter().map(RecordBatch::num_rows).sum();
    assert_eq!(
        total_rows,
        3,
        "expected 3 grouped rows (one per user), got:\n{}",
        pretty_format_batches(&batches).unwrap()
    );

    // Decode columns directly. Substring contains-on-numbers is
    // false-pass-prone (`"30"` is a substring of `"130"` and
    // `"275"`), so build a name→total map from the actual column
    // arrays and compare exact pairs. SUM's output type is i64
    // when the input column is INT (mysql) — DataFusion widens
    // for accumulator headroom.
    let mut totals: BTreeMap<String, i64> = BTreeMap::new();
    for batch in &batches {
        let names = batch
            .column(0)
            .as_any()
            .downcast_ref::<StringArray>()
            .expect("name column is Utf8");
        let sums = batch
            .column(1)
            .as_any()
            .downcast_ref::<Int64Array>()
            .expect("SUM column is Int64");
        for row in 0..batch.num_rows() {
            totals.insert(names.value(row).to_owned(), sums.value(row));
        }
    }
    assert_eq!(
        totals.get("Alice"),
        Some(&130),
        "Alice 50+80=130, got:\n{totals:?}"
    );
    assert_eq!(totals.get("Bob"), Some(&30), "Bob 30, got:\n{totals:?}");
    assert_eq!(
        totals.get("Carol"),
        Some(&275),
        "Carol 75+200=275, got:\n{totals:?}"
    );
}

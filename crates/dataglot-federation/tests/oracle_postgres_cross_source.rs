//! Cross-source JOIN correctness test — Oracle × `PostgreSQL`.
//!
//!  exit criterion #3: "A cross-source JOIN (Oracle × Postgres)
//! returns correct rows end-to-end (federation composes; Oracle side
//! pushed, join local)." The single-source pushdown parity test lives
//! in `oracle_integration.rs`; this file proves the connector composes
//! with a *second* source in one `SessionContext`.
//!
//! Boots a `gvenzl/oracle-free` and a `postgres` container
//! side-by-side, registers both as federated table providers, and
//! runs canonical JOIN shapes spanning both. The join itself executes
//! inside `DataFusion` (a `HashJoin` in the cross-source plan); each
//! side's projection/filter pushes to its own source via the
//! datafusion-federation unparser — Oracle with `FETCH FIRST` + `"`
//! quoting, Postgres with its own dialect.
//!
//! **x86-only** (same as `oracle_integration.rs`): Oracle DB Free has
//! no ARM image and `testcontainers_modules::oracle` is
//! `#[cfg(not(aarch64))]` upstream. Runs in the x86 Oracle CI job
//! (`.github/workflows/oracle-integration.yml`).
//!
//! Oracle folds unquoted identifiers to UPPERCASE, so Oracle columns
//! are referenced quoted-uppercase (`u."ID"`, `u."NAME"`) while the
//! Postgres columns (lowercase) are bare — exactly the casing rule the
//! single-source test and `snowflake_federation.rs` follow.

#![cfg(all(feature = "oracle", feature = "postgres", not(target_arch = "aarch64")))]

use std::collections::BTreeMap;
use std::sync::Arc;

// `Array` explicitly: arrow-array 58.3 stopped re-surfacing `is_null`
// on concrete arrays without the trait in scope (nightly-only build —
// the `oracle` feature isn't compiled in PR CI, so the 58.3 bump merged
// green and broke here first).
use datafusion::arrow::array::{Array, Int32Array, Int64Array, RecordBatch, StringArray};
use datafusion::arrow::util::pretty::pretty_format_batches;
use dataglot_core::{SessionConfig, SessionContextFactory};
use dataglot_federation::oracle::OracleConnector;
use dataglot_federation::postgres::PostgresConnector;
use testcontainers::runners::AsyncRunner;
use testcontainers_modules::oracle::free::Oracle;
use testcontainers_modules::postgres::Postgres;
use tokio_postgres::NoTls;

/// gvenzl/oracle-free defaults: app user `test` / password `test`,
/// pluggable database service `FREEPDB1`.
const ORA_USER: &str = "test";
const ORA_PASSWORD: &str = "test";

/// Spin up both containers, seed `oracle TEST.USERS` and
/// `pg.public.orders`, return (oracle DSN, pg DSN, container handles).
/// The caller keeps the handles alive for the test's duration.
///
/// Test data (same shape as `cross_source_joins.rs`, plus Dave — a user
/// with no orders — so a LEFT JOIN has an unmatched, NULL-extended side):
///   `USERS`  (id, name, age) — Oracle (folds to ID/NAME/AGE)
///       (1, 'Alice', 30) (2, 'Bob', 25) (3, 'Carol', 35) (4, 'Dave', 40)
///   `orders` (id, user_id, total) — Postgres
///       (101,1,50) (102,1,80) (103,2,30) (104,3,200) (105,3,75)
/// Dave (id 4) intentionally has no matching order, so INNER-JOIN tests are
/// unaffected (he's excluded) while the LEFT-JOIN test gets a NULL row.
async fn setup_both_sources() -> (
    String,
    String,
    testcontainers::ContainerAsync<Oracle>,
    testcontainers::ContainerAsync<Postgres>,
) {
    // ---- Oracle side -----------------------------------------------
    let ora = Oracle::default()
        .start()
        .await
        .expect("oracle-free container starts");
    let ora_host = ora.get_host().await.expect("oracle host");
    let ora_port = ora.get_host_port_ipv4(1521).await.expect("oracle port");
    let ora_dsn = format!("//{ora_host}:{ora_port}/FREEPDB1");

    // Seed via a direct (sync) oracle connection on a blocking thread —
    // the `oracle` crate is synchronous.
    let seed_dsn = ora_dsn.clone();
    tokio::task::spawn_blocking(move || {
        let conn = oracle::Connection::connect(ORA_USER, ORA_PASSWORD, &seed_dsn)
            .expect("seed connection");
        conn.execute(
            "CREATE TABLE users (id NUMBER PRIMARY KEY, name VARCHAR2(100), age NUMBER)",
            &[],
        )
        .expect("create oracle users");
        for (id, name, age) in [
            (1, "Alice", 30),
            (2, "Bob", 25),
            (3, "Carol", 35),
            (4, "Dave", 40),
        ] {
            conn.execute(
                "INSERT INTO users (id, name, age) VALUES (:1, :2, :3)",
                &[&id, &name, &age],
            )
            .expect("insert oracle row");
        }
        conn.commit().expect("commit oracle seed");
    })
    .await
    .expect("oracle seed task");

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
        if pg_conn.await.is_err() {
            eprintln!("postgres connection error (redacted)");
        }
    });
    pg_client
        .batch_execute(
            "CREATE TABLE public.orders (
                 id      INT PRIMARY KEY,
                 user_id INT NOT NULL,
                 total   INT NOT NULL
             );
             INSERT INTO public.orders (id, user_id, total) VALUES
                 (101, 1, 50),
                 (102, 1, 80),
                 (103, 2, 30),
                 (104, 3, 200),
                 (105, 3, 75);",
        )
        .await
        .expect("seed pg.orders");

    (ora_dsn, pg_dsn, ora, pg)
}

/// Build the production federated `SessionContext` with `users` (from
/// Oracle) and `orders` (from Postgres) registered as flat 1-part table
/// names. `create_federated_context` installs the federation
/// rule/planner + the `WrapFederationNodes` guard, so each
/// side's pushdown routes independently and cross-source `WHERE`s are
/// retained.
async fn federated_ctx_with_both(
    ora_dsn: &str,
    pg_dsn: &str,
) -> datafusion::prelude::SessionContext {
    let ora = Arc::new(
        OracleConnector::connect("oracle", ora_dsn, ORA_USER, ORA_PASSWORD)
            .await
            .expect("oracle connector connects"),
    );
    // Oracle folds unquoted identifiers to uppercase — the owner is TEST.
    let ora_provider = ora
        .table_provider("TEST", "USERS")
        .await
        .expect("oracle TEST.USERS table_provider");

    let pg = Arc::new(
        PostgresConnector::connect(pg_dsn)
            .await
            .expect("pg connector connects"),
    );
    let pg_provider = pg
        .table_provider("public", "orders")
        .await
        .expect("pg.public.orders table_provider");

    let factory = SessionContextFactory::new(SessionConfig::new()).expect("factory");
    let ctx = factory.create_federated_context();
    ctx.register_table("users", ora_provider)
        .expect("register users");
    ctx.register_table("orders", pg_provider)
        .expect("register orders");
    ctx
}

/// INNER JOIN spanning Oracle `users` and Postgres `orders`. Pin:
/// * 5 joined rows, with Alice=2 / Bob=1 / Carol=2 multiplicities.
/// * EXPLAIN shows ≥2 federation virtual exec nodes (one per source).
#[tokio::test]
#[ignore = "requires Docker + Oracle Instant Client (x86 CI only)"]
async fn cross_source_inner_join_oracle_postgres() {
    let (ora_dsn, pg_dsn, _ora, _pg) = setup_both_sources().await;
    let ctx = federated_ctx_with_both(&ora_dsn, &pg_dsn).await;

    let df = ctx
        .sql(
            r#"SELECT u."NAME", o.total
               FROM users u
               INNER JOIN orders o ON u."ID" = o.user_id
               ORDER BY u."NAME", o.total"#,
        )
        .await
        .expect("SQL parses and plans");
    let batches = df.collect().await.expect("executes");

    let total_rows: usize = batches.iter().map(RecordBatch::num_rows).sum();
    assert_eq!(
        total_rows,
        5,
        "expected 5 joined rows, got:\n{}",
        pretty_format_batches(&batches).unwrap()
    );

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
    assert_eq!(counts.get("Alice"), Some(&2), "Alice 2 orders:\n{counts:?}");
    assert_eq!(counts.get("Bob"), Some(&1), "Bob 1 order:\n{counts:?}");
    assert_eq!(counts.get("Carol"), Some(&2), "Carol 2 orders:\n{counts:?}");

    // Pushdown signal: at least two federation exec-node lines, one per
    // source (Oracle + Postgres each plan a VirtualExecutionPlan).
    let explain = ctx
        .sql(
            r#"EXPLAIN SELECT u."NAME", o.total FROM users u
               INNER JOIN orders o ON u."ID" = o.user_id"#,
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
        "expected ≥2 federation exec-node lines (one per source) in:\n{explain_str}"
    );
}

/// JOIN + GROUP BY across both sources — per-user order totals.
/// Expected: Alice → 130, Bob → 30, Carol → 275.
#[tokio::test]
#[ignore = "requires Docker + Oracle Instant Client (x86 CI only)"]
async fn cross_source_join_with_aggregation_oracle_postgres() {
    let (ora_dsn, pg_dsn, _ora, _pg) = setup_both_sources().await;
    let ctx = federated_ctx_with_both(&ora_dsn, &pg_dsn).await;

    let df = ctx
        .sql(
            r#"SELECT u."NAME", SUM(o.total) AS total
               FROM users u
               INNER JOIN orders o ON u."ID" = o.user_id
               GROUP BY u."NAME"
               ORDER BY u."NAME""#,
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

    // SUM over Postgres INT widens to Int64 (accumulator headroom).
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
    assert_eq!(totals.get("Alice"), Some(&130), "Alice 50+80:\n{totals:?}");
    assert_eq!(totals.get("Bob"), Some(&30), "Bob 30:\n{totals:?}");
    assert_eq!(totals.get("Carol"), Some(&275), "Carol 200+75:\n{totals:?}");

    // Keep Int32Array import meaningful: assert raw Postgres `total`
    // decodes as Int32 in a plain projection (the SUM above widens it).
    let raw = ctx
        .sql("SELECT total FROM orders ORDER BY total LIMIT 1")
        .await
        .expect("plain projection parses");
    let raw_batches = raw.collect().await.expect("executes");
    let batch = raw_batches
        .first()
        .expect("expected at least one record batch");
    let col = batch
        .column(0)
        .as_any()
        .downcast_ref::<Int32Array>()
        .expect("pg INT decodes as Int32");
    assert_eq!(col.value(0), 30, "smallest order total is 30");
}

/// **Cross-source WHERE is retained — Postgres-side predicate (,
///  #5).** Mirrors `cross_source_joins.rs`'s mysql-side test on the
/// Oracle × Postgres pairing: a `WHERE o.total > 100` above the
/// cross-source JOIN must survive (the `WrapFederationNodes` guard keeps
/// the `FilterExec` above the federation node instead of letting
/// datafusion-federation silently drop it). Only Carol's order #104
/// (total 200) qualifies → exactly 1 row.
#[tokio::test]
#[ignore = "requires Docker + Oracle Instant Client (x86 CI only)"]
async fn cross_source_join_with_pg_side_predicate_oracle_postgres() {
    let (ora_dsn, pg_dsn, _ora, _pg) = setup_both_sources().await;
    let ctx = federated_ctx_with_both(&ora_dsn, &pg_dsn).await;

    let df = ctx
        .sql(
            r#"SELECT u."NAME", o.total
               FROM users u
               INNER JOIN orders o ON u."ID" = o.user_id
               WHERE o.total > 100"#,
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

    // The surviving row is Carol / 200 — confirm the predicate filtered on
    // the real value, not a coincidence of cardinality. Postgres `INT`
    // decodes to Int32 (SUM in the aggregation test widens to i64).
    let name = batches[0]
        .column(0)
        .as_any()
        .downcast_ref::<StringArray>()
        .expect("name col");
    let total = batches[0]
        .column(1)
        .as_any()
        .downcast_ref::<Int32Array>()
        .expect("total col is Int32");
    assert_eq!(name.value(0), "Carol");
    assert_eq!(total.value(0), 200);
}

/// Companion on the **Oracle side**, filtering a *non-projected* column
/// (`u."AGE"`) above the cross-source JOIN (,  #5). With the
/// guard the filter is retained: `AGE > 28` keeps Alice (30) and Carol
/// (35), so their orders survive (Alice 2 + Carol 2 = 4 rows); Bob (25)
/// is filtered and Dave (40, no orders) never joins.
#[tokio::test]
#[ignore = "requires Docker + Oracle Instant Client (x86 CI only)"]
async fn cross_source_join_with_oracle_side_predicate() {
    let (ora_dsn, pg_dsn, _ora, _pg) = setup_both_sources().await;
    let ctx = federated_ctx_with_both(&ora_dsn, &pg_dsn).await;

    let df = ctx
        .sql(
            r#"SELECT u."NAME", o.total
               FROM users u
               INNER JOIN orders o ON u."ID" = o.user_id
               WHERE u."AGE" > 28"#,
        )
        .await
        .expect("SQL parses");
    let batches = df.collect().await.expect("executes");
    let total_rows: usize = batches.iter().map(RecordBatch::num_rows).sum();
    assert_eq!(
        total_rows,
        4,
        "oracle-side WHERE on a non-projected column must be retained \
: Alice(30)+Carol(35) orders survive, Bob(25) filtered, \
         got:\n{}",
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

/// **LEFT (outer) JOIN cardinality across both sources ( #5).**
/// Every Oracle user is preserved even without a matching Postgres order:
/// Alice 2 + Bob 1 + Carol 2 = 5 matched rows, plus Dave (no orders) as
/// one NULL-extended row → 6 rows total, with Dave's `total` NULL. Proves
/// the outer join composes across the federation boundary (the join runs
/// locally in DataFusion; each side still pushes its own scan).
#[tokio::test]
#[ignore = "requires Docker + Oracle Instant Client (x86 CI only)"]
async fn cross_source_left_join_oracle_postgres() {
    let (ora_dsn, pg_dsn, _ora, _pg) = setup_both_sources().await;
    let ctx = federated_ctx_with_both(&ora_dsn, &pg_dsn).await;

    let df = ctx
        .sql(
            r#"SELECT u."NAME", o.total
               FROM users u
               LEFT JOIN orders o ON u."ID" = o.user_id
               ORDER BY u."NAME", o.total"#,
        )
        .await
        .expect("SQL parses");
    let batches = df.collect().await.expect("executes");

    let total_rows: usize = batches.iter().map(RecordBatch::num_rows).sum();
    assert_eq!(
        total_rows,
        6,
        "LEFT JOIN preserves all users: 5 matched + Dave's NULL row, got:\n{}",
        pretty_format_batches(&batches).unwrap()
    );

    // Collect (name, total-is-null) pairs to prove Dave is present exactly
    // once with a NULL total (the outer-join NULL extension), and the
    // matched users have non-NULL totals.
    let mut null_count: BTreeMap<String, usize> = BTreeMap::new();
    let mut matched_count: BTreeMap<String, usize> = BTreeMap::new();
    for batch in &batches {
        let names = batch
            .column(0)
            .as_any()
            .downcast_ref::<StringArray>()
            .expect("name col");
        let totals = batch
            .column(1)
            .as_any()
            .downcast_ref::<Int32Array>()
            .expect("total col is Int32");
        for row in 0..batch.num_rows() {
            let name = names.value(row).to_owned();
            if totals.is_null(row) {
                *null_count.entry(name).or_default() += 1;
            } else {
                *matched_count.entry(name).or_default() += 1;
            }
        }
    }
    assert_eq!(
        null_count.get("Dave"),
        Some(&1),
        "Dave has exactly one NULL-extended row, got null={null_count:?} matched={matched_count:?}"
    );
    assert_eq!(
        matched_count.get("Alice"),
        Some(&2),
        "Alice 2 matched: {matched_count:?}"
    );
    assert_eq!(
        matched_count.get("Bob"),
        Some(&1),
        "Bob 1 matched: {matched_count:?}"
    );
    assert_eq!(
        matched_count.get("Carol"),
        Some(&2),
        "Carol 2 matched: {matched_count:?}"
    );
    assert_eq!(
        matched_count.get("Dave"),
        None,
        "Dave has no matched order: {matched_count:?}"
    );
}

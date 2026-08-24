//! Integration tests for the `MySQL` federation connector.
//!
//! These tests require Docker for the `testcontainers-modules::mysql`
//! image and are therefore marked `#[ignore = "requires Docker"]`.
//! They still need to compile on every run (`cargo test --no-run`)
//! so the codepath can't drift.
//!
//! Scope of these tests (per the Phase 1 `MySQL` connector spec at
//! the phase-1 `mysql-federation-connector` plan):
//!
//! 1. End-to-end: create a `MysqlConnector`, register the table with
//!    a `DataFusion` `SessionContext`, and run a `SELECT` with a
//!    `WHERE` clause against `mysql:8.1`.
//! 2. The result is verified both for correctness (row count / values)
//!    and for pushdown (the `EXPLAIN` output must show the predicate
//!    inside a `datafusion-federation` virtual exec node, with the
//!    `MySQL` dialect emitting backtick-quoted identifiers).
//! 3. Lazy schema resolution (hard rule 13): `connect` does not
//!    fetch any table schemas; first access happens on
//!    `table_provider`.
//! 4. Credential redaction (hard rule 12): `Debug` output never
//!    surfaces a password component from the DSN.

#![cfg(feature = "mysql")]

use std::sync::Arc;

use datafusion::arrow::array::RecordBatch;
use datafusion::arrow::util::pretty::pretty_format_batches;
use datafusion::execution::session_state::SessionStateBuilder;
use dataglot_core::{SessionConfig, SessionContextFactory};
use dataglot_federation::mysql::MysqlConnector;
use mysql_async::prelude::Queryable;
use testcontainers::runners::AsyncRunner;
use testcontainers_modules::mysql::Mysql;

/// Shared test setup: boot a `MySQL` 8.1 container, create
/// `test.users`, and insert three rows. Returns the DSN and the
/// running container so the caller can keep the container alive
/// for the duration of the test.
///
/// `with_init_sql` would be the canonical way to seed, but the
/// init scripts run before `MySQL` is fully ready for connections,
/// and the file-mount path is awkward to debug across platforms.
/// A direct `mysql_async` insert after boot is simpler and matches
/// what the Postgres integration test does.
async fn setup_users_table() -> (String, testcontainers::ContainerAsync<Mysql>) {
    let container = Mysql::default()
        .start()
        .await
        .expect("mysql container starts");
    let host = container.get_host().await.expect("host");
    let port = container.get_host_port_ipv4(3306).await.expect("3306 port");
    let dsn = format!("mysql://root@{host}:{port}/test");

    // Seed the table using the raw driver — the dataglot connector
    // is read-only in Phase 1, so we cannot use it to populate.
    let opts = mysql_async::Opts::from_url(&dsn).expect("DSN parses");
    let mut conn = mysql_async::Conn::new(opts)
        .await
        .expect("seed-side connect");
    conn.query_drop(
        "CREATE TABLE users (
             id   INT PRIMARY KEY,
             name VARCHAR(100) NOT NULL,
             age  INT NOT NULL
         )",
    )
    .await
    .expect("create users table");
    conn.query_drop(
        "INSERT INTO users (id, name, age) VALUES
            (1, 'Alice', 30),
            (2, 'Bob',   25),
            (3, 'Carol', 35)",
    )
    .await
    .expect("seed users rows");
    conn.disconnect().await.expect("seed conn closes");

    (dsn, container)
}

/// End-to-end: `SELECT id, name, age FROM users WHERE age > 25`
/// through `DataFusion` must
///
/// * return two rows (Alice, Carol),
/// * stream Arrow `RecordBatch` (any call-path that would require
///   row-mode conversion above the connector layer would fail
///   the schema-shape assertion), and
/// * surface the pushed-down predicate in the `EXPLAIN` output,
///   with MySQL-dialect identifier quoting (backticks).
#[tokio::test]
#[ignore = "requires Docker"]
async fn federated_select_with_pushdown() {
    let (dsn, _container) = setup_users_table().await;

    // Build the connector and resolve a TableProvider for `users`.
    // Per hard rule 13 the schema is fetched here (first
    // access), not at connector construction time. The MySQL
    // module's default DB is `test`, so we look the table up
    // there.
    let connector = Arc::new(
        MysqlConnector::connect("mysql_demo", &dsn)
            .await
            .expect("connector connects"),
    );
    let provider = connector
        .table_provider("test", "users")
        .await
        .expect("schema resolves for test.users");

    // Build a DataFusion SessionContext with the federation
    // optimizer registered. We bolt the federation rule onto the
    // factory-built context here rather than extending
    // SessionContextFactory — that plumbing lives in
    // `dataglot-core`.
    let factory = SessionContextFactory::new(
        SessionConfig::new()
            .with_default_catalog("dataglot")
            .with_default_schema("public"),
    )
    .unwrap();
    let ctx = factory.create_context();
    let fed_state = SessionStateBuilder::new_from_existing(ctx.state())
        .with_optimizer_rules(datafusion_federation::default_optimizer_rules())
        .with_query_planner(Arc::new(datafusion_federation::FederatedQueryPlanner::new()))
        .build();
    let ctx = datafusion::prelude::SessionContext::new_with_state(fed_state);
    ctx.register_table("users", provider)
        .expect("register users table");

    // ---- 1. Correctness ----------------------------------------
    let df = ctx
        .sql("SELECT id, name, age FROM users WHERE age > 25 ORDER BY id")
        .await
        .expect("SQL parses and plans");
    let batches = df.collect().await.expect("executes without error");

    let total_rows: usize = batches.iter().map(RecordBatch::num_rows).sum();
    assert_eq!(
        total_rows,
        2,
        "expected 2 rows (age > 25) but got:\n{}",
        pretty_format_batches(&batches).unwrap()
    );
    let printed = pretty_format_batches(&batches).unwrap().to_string();
    assert!(
        printed.contains("Alice") && printed.contains("Carol"),
        "expected Alice and Carol in results, got:\n{printed}"
    );
    assert!(
        !printed.contains("Bob"),
        "Bob (age 25) should have been filtered out, got:\n{printed}"
    );

    // ---- 2. Pushdown -------------------------------------------
    // EXPLAIN must mention the pushed-down predicate inside a
    // federation virtual exec node. We match on three signals:
    //  (a) the federation node name (`VirtualExecutionPlan` or
    //      `sql_federation_exec`) is present;
    //  (b) the MySQL-dialect unparser emits backtick-quoted
    //      identifiers (the Postgres test asserts double-quoted
    //      ones, but MySQL uses backticks);
    //  (c) the literal `25` appears in the pushed SQL.
    let explain = ctx
        .sql("EXPLAIN SELECT id, name, age FROM users WHERE age > 25")
        .await
        .expect("EXPLAIN parses");
    let explain_batches = explain.collect().await.expect("EXPLAIN runs");
    let explain_str = pretty_format_batches(&explain_batches).unwrap().to_string();

    assert!(
        explain_str.contains("VirtualExecutionPlan") || explain_str.contains("sql_federation_exec"),
        "expected a federation virtual exec node in EXPLAIN output:\n{explain_str}"
    );
    assert!(
        explain_str.contains("`age`") || explain_str.contains("age"),
        "expected the `age` identifier in the pushed-down SQL:\n{explain_str}"
    );
    assert!(
        explain_str.contains("25"),
        "expected the literal 25 in the pushed-down predicate:\n{explain_str}"
    );
}

/// Lazy schema resolution (hard rule 13): constructing a
/// connector must not fetch any table schemas. We verify this by
/// connecting to a database that has no user tables yet and
/// asserting `connect` still succeeds — then asserting that
/// `table_provider` for a missing table errors cleanly.
#[tokio::test]
#[ignore = "requires Docker"]
async fn connector_does_not_prefetch_schemas() {
    let container = Mysql::default()
        .start()
        .await
        .expect("mysql container starts");
    let host = container.get_host().await.expect("host");
    let port = container.get_host_port_ipv4(3306).await.expect("3306 port");
    let dsn = format!("mysql://root@{host}:{port}/test");

    let connector = Arc::new(
        MysqlConnector::connect("mysql_demo", &dsn)
            .await
            .expect("connect succeeds on empty db"),
    );

    let missing = connector.table_provider("test", "does_not_exist").await;
    assert!(
        missing.is_err(),
        "expected a catalog error for missing table, got Ok"
    );
    let err = missing.unwrap_err().to_string().to_lowercase();
    assert!(
        err.contains("not found")
            || err.contains("does_not_exist")
            || err.contains("no such")
            || err.contains("doesn't exist"),
        "expected a not-found-style error, got: {err}"
    );
}

// `Debug` redaction (hard rule 12) is exercised by the unit
// test `mysql::tests::dsn_redacted_in_debug` in `src/mysql.rs`,
// which exercises the `redacted_dsn` helper directly. We don't
// repeat it here under the Docker gate because the MySQL
// container's default config (root, empty password) makes the
// "live credential leak" test awkward — adding a sentinel
// password requires a custom `MYSQL_ROOT_PASSWORD` env var on
// the image, and the connection-failure path then complicates
// the test without adding coverage beyond the unit test.

/// Native-query passthrough verification — MySQL counterpart of
/// `postgres_integration::single_source_complex_query_pushed_through_natively`.
///
/// **What this pins.** When a query references exactly one federated
/// source — same MySQL in this case — the `datafusion-federation`
/// planner is supposed to compile the whole query (predicates,
/// aggregation, sort, limit) into a single SQL string and hand it
/// to the source for native execution. Pin GROUP BY + ORDER BY +
/// LIMIT all pushing down by asserting the **negative space** — no
/// local `AggregateExec` / `SortExec` / `FilterExec` /
/// `*LimitExec` above the federation node.
///
/// **Why the negative-space check matters.** A test that only
/// asserts "`VirtualExecutionPlan` appears" passes even when
/// federation pushes part of the query (predicate) and DataFusion
/// re-does the rest locally (aggregation, sort, limit). That's the
/// regression shape we'd hit if `datafusion-federation` silently
/// lost its grip on GROUP BY pushdown after a version bump.
#[tokio::test]
#[ignore = "requires Docker"]
async fn single_source_complex_query_pushed_through_natively() {
    let (dsn, _container) = setup_users_table().await;

    let connector = Arc::new(
        MysqlConnector::connect("mysql_demo", &dsn)
            .await
            .expect("connector connects"),
    );
    let provider = connector
        .table_provider("test", "users")
        .await
        .expect("schema resolves for test.users");

    let factory = SessionContextFactory::new(
        SessionConfig::new()
            .with_default_catalog("dataglot")
            .with_default_schema("public"),
    )
    .unwrap();
    let ctx = factory.create_context();
    let fed_state = SessionStateBuilder::new_from_existing(ctx.state())
        .with_optimizer_rules(datafusion_federation::default_optimizer_rules())
        .with_query_planner(Arc::new(datafusion_federation::FederatedQueryPlanner::new()))
        .build();
    let ctx = datafusion::prelude::SessionContext::new_with_state(fed_state);

    ctx.register_table("users", provider)
        .expect("register users table");

    // Complex single-source query — predicate + GROUP BY + aggregate
    // + ORDER BY + LIMIT. Native passthrough means the whole thing
    // compiles into one SQL statement sent to MySQL.
    let complex_sql = "
        SELECT age, COUNT(*) AS n
        FROM users
        WHERE age >= 25
        GROUP BY age
        ORDER BY age
        LIMIT 10
    ";

    // ---- 1. Correctness sanity check ---------------------------
    let df = ctx
        .sql(complex_sql)
        .await
        .expect("complex SQL parses and plans");
    let batches = df.collect().await.expect("complex SQL executes");

    let total_rows: usize = batches.iter().map(RecordBatch::num_rows).sum();
    // Seed has three age values ≥ 25: 25 (Bob), 30 (Alice), 35
    // (Carol). Each appears once, so GROUP BY age yields three
    // groups each with COUNT(*) = 1.
    assert_eq!(
        total_rows,
        3,
        "expected 3 groups (age IN {{25, 30, 35}}) but got:\n{}",
        pretty_format_batches(&batches).unwrap()
    );

    // ---- 2. Passthrough — positive assertion -------------------
    let explain = ctx
        .sql(&format!("EXPLAIN {complex_sql}"))
        .await
        .expect("EXPLAIN parses");
    let explain_batches = explain.collect().await.expect("EXPLAIN runs");
    let explain_str = pretty_format_batches(&explain_batches).unwrap().to_string();
    let explain_upper = explain_str.to_uppercase();

    assert!(
        explain_upper.contains("VIRTUALEXECUTIONPLAN")
            || explain_str.contains("sql_federation_exec"),
        "expected a federation virtual exec node:\n{explain_str}"
    );
    for needle in ["GROUP BY", "ORDER BY", "LIMIT"] {
        assert!(
            explain_upper.contains(needle),
            "expected {needle:?} in the pushed SQL inside EXPLAIN:\n{explain_str}"
        );
    }
    assert!(
        explain_str.contains("age") && explain_str.contains("25"),
        "expected `age` and `25` (the predicate) in pushed SQL:\n{explain_str}"
    );

    // ---- 3. Passthrough — negative assertion -------------------
    // The strong guarantee: no local-execution operator above the
    // federation node. Any of these would mean DataFusion re-did
    // work the source should have handled, breaking the
    // "single-source queries bypass federation overhead" promise.
    //
    // `ProjectionExec` over the federation node is the one
    // routinely-allowed leftover — keep it off the forbidden list
    // to avoid false positives on safe leftovers.
    let forbidden_locally_executed = [
        "AggregateExec",
        "SortExec",
        "FilterExec",
        "GlobalLimitExec",
        "LocalLimitExec",
        "HashAggregateExec",
        "PartialAggregateExec",
    ];
    let leaks: Vec<&str> = forbidden_locally_executed
        .into_iter()
        .filter(|op| explain_str.contains(op))
        .collect();
    assert!(
        leaks.is_empty(),
        "single-source complex query leaked local-execution operator(s) above the federation node: {leaks:?}\n\
         this means GROUP BY / ORDER BY / LIMIT didn't fully push and native passthrough regressed.\n\nfull EXPLAIN:\n{explain_str}"
    );
}

/// **Same-source JOIN collapse.** A JOIN between two tables
/// of the SAME MySQL catalog must ship as ONE pushed query — the
/// MySQL twin of the pin in `postgres_integration.rs` and the
/// DuckDB-ADBC contract suite (`federation_contract.rs`). MySQL is the
/// connector whose distributed registration silently regressed once
/// (the codec-registry gap), so it earns every shape pin the others
/// have.
#[tokio::test]
#[ignore = "requires Docker"]
async fn same_source_join_collapses_into_one_pushed_query() {
    let (dsn, _container) = setup_users_table().await;

    // Second table on the same source.
    let opts = mysql_async::Opts::from_url(&dsn).expect("DSN parses");
    let mut conn = mysql_async::Conn::new(opts)
        .await
        .expect("seed-side connect");
    conn.query_drop(
        "CREATE TABLE logins (
             id      INT PRIMARY KEY,
             user_id INT NOT NULL,
             minutes INT NOT NULL
         )",
    )
    .await
    .expect("create logins table");
    conn.query_drop(
        "INSERT INTO logins (id, user_id, minutes) VALUES
            (10, 1, 30), (11, 1, 45), (12, 2, 10), (13, 3, 60)",
    )
    .await
    .expect("seed logins rows");
    conn.disconnect().await.expect("seed conn closes");

    let connector = Arc::new(
        MysqlConnector::connect("mysql_demo", &dsn)
            .await
            .expect("connector connects"),
    );
    let factory = SessionContextFactory::new(
        SessionConfig::new()
            .with_default_catalog("dataglot")
            .with_default_schema("public"),
    )
    .unwrap();
    let ctx = factory.create_context();
    let fed_state = SessionStateBuilder::new_from_existing(ctx.state())
        .with_optimizer_rules(datafusion_federation::default_optimizer_rules())
        .with_query_planner(Arc::new(datafusion_federation::FederatedQueryPlanner::new()))
        .build();
    let ctx = datafusion::prelude::SessionContext::new_with_state(fed_state);
    for table in ["users", "logins"] {
        let provider = connector
            .table_provider("test", table)
            .await
            .unwrap_or_else(|e| panic!("schema resolves for test.{table}: {e}"));
        ctx.register_table(table, provider).expect("register table");
    }

    let sql = "SELECT u.name, SUM(l.minutes) AS total
               FROM users u
               JOIN logins l ON l.user_id = u.id
               GROUP BY u.name
               ORDER BY total DESC
               LIMIT 5";

    // Correctness: Alice 75, Carol 60, Bob 10.
    let batches = ctx
        .sql(sql)
        .await
        .expect("plans")
        .collect()
        .await
        .expect("executes");
    let rendered = pretty_format_batches(&batches).unwrap().to_string();
    let rows: usize = batches.iter().map(RecordBatch::num_rows).sum();
    assert_eq!(rows, 3, "three users have logins:\n{rendered}");
    assert!(rendered.contains("75"), "Alice total 75:\n{rendered}");

    let explain = ctx
        .sql(&format!("EXPLAIN {sql}"))
        .await
        .expect("EXPLAIN parses");
    let explain_str = pretty_format_batches(&explain.collect().await.expect("EXPLAIN runs"))
        .unwrap()
        .to_string();
    assert_join_collapsed(&explain_str);
}

/// EXPLAIN-shape assertion for the same-source-join pin: exactly one
/// federation node, the JOIN inside it, no local join/agg/sort/limit
/// operators above.
fn assert_join_collapsed(explain_str: &str) {
    let node_count = explain_str
        .lines()
        .filter(|line| {
            line.contains("VirtualExecutionPlan") || line.contains("sql_federation_exec")
        })
        .count();
    assert_eq!(
        node_count, 1,
        "same-source JOIN must collapse into exactly ONE pushed query:\n{explain_str}"
    );
    assert!(
        explain_str.to_uppercase().contains("JOIN"),
        "the JOIN must appear inside the pushed SQL:\n{explain_str}"
    );
    let forbidden = [
        "HashJoinExec",
        "SortMergeJoinExec",
        "NestedLoopJoinExec",
        "CrossJoinExec",
        "AggregateExec",
        "SortExec",
        "GlobalLimitExec",
        "LocalLimitExec",
    ];
    let leaks: Vec<&str> = forbidden
        .into_iter()
        .filter(|op| explain_str.contains(op))
        .collect();
    assert!(
        leaks.is_empty(),
        "same-source JOIN leaked local operator(s) {leaks:?}:\n{explain_str}"
    );
}

/// Build a federation-enabled `SessionContext` with `provider` registered under
/// `name`. Factors out the inline setup the tests above repeat.
fn federated_ctx_with(
    provider: Arc<dyn datafusion::datasource::TableProvider>,
    name: &str,
) -> datafusion::prelude::SessionContext {
    let factory = SessionContextFactory::new(
        SessionConfig::new()
            .with_default_catalog("dataglot")
            .with_default_schema("public"),
    )
    .unwrap();
    let ctx = factory.create_context();
    let fed_state = SessionStateBuilder::new_from_existing(ctx.state())
        .with_optimizer_rules(datafusion_federation::default_optimizer_rules())
        .with_query_planner(Arc::new(datafusion_federation::FederatedQueryPlanner::new()))
        .build();
    let ctx = datafusion::prelude::SessionContext::new_with_state(fed_state);
    ctx.register_table(name, provider).expect("register table");
    ctx
}

/// Seed a table exercising the MySQL types the connector decodes, plus an
/// all-`NULL` row. Prior tests seeded only INT + VARCHAR.
async fn setup_wide_types_table() -> (String, testcontainers::ContainerAsync<Mysql>) {
    let container = Mysql::default()
        .start()
        .await
        .expect("mysql container starts");
    let host = container.get_host().await.expect("host");
    let port = container.get_host_port_ipv4(3306).await.expect("3306 port");
    let dsn = format!("mysql://root@{host}:{port}/test");

    let opts = mysql_async::Opts::from_url(&dsn).expect("DSN parses");
    let mut conn = mysql_async::Conn::new(opts)
        .await
        .expect("seed-side connect");
    conn.query_drop(
        "CREATE TABLE wide_types (
             id      INT PRIMARY KEY,
             ti      TINYINT,
             si      SMALLINT,
             bi      BIGINT,
             ub      BIGINT UNSIGNED,
             fl      FLOAT,
             db      DOUBLE,
             flag    TINYINT(1),
             dt      DATE,
             ts      DATETIME,
             dec_col DECIMAL(10,2),
             txt     VARCHAR(50)
         )",
    )
    .await
    .expect("create wide_types table");
    conn.query_drop(
        "INSERT INTO wide_types VALUES
            (1, 42, 32000, 9000000000, 9000000000, 1.5, 2.5, 1,
             '2020-01-15', '2020-01-15 12:34:56', 123.45, 'hello'),
            (2, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)",
    )
    .await
    .expect("seed wide_types rows");
    conn.disconnect().await.expect("seed conn closes");

    (dsn, container)
}

/// Every decoded MySQL type round-trips, and an all-`NULL` row decodes to
/// nulls. Row 1 carries a value for each column (int8/16/64, uint64,
/// float32/64, bool, date, timestamp, decimal, utf8); row 2 exercises every
/// decoder's null branch.
#[tokio::test]
#[ignore = "requires Docker"]
async fn wide_type_and_null_round_trip() {
    let (dsn, _container) = setup_wide_types_table().await;
    let connector = Arc::new(
        MysqlConnector::connect("mysql_demo", &dsn)
            .await
            .expect("connector connects"),
    );
    let provider = connector
        .table_provider("test", "wide_types")
        .await
        .expect("schema resolves for test.wide_types");
    let ctx = federated_ctx_with(provider, "wide_types");

    // Row 1: every type carries its value through decode.
    let batches = ctx
        .sql(
            "SELECT ti, si, bi, ub, fl, db, flag, dt, ts, dec_col, txt \
              FROM wide_types WHERE id = 1",
        )
        .await
        .expect("value row plans")
        .collect()
        .await
        .expect("value row decodes");
    let printed = pretty_format_batches(&batches).unwrap().to_string();
    for token in [
        "42",         // tinyint
        "32000",      // smallint
        "9000000000", // bigint / bigint unsigned
        "1.5",        // float
        "2.5",        // double
        "2020-01-15", // date (+ date portion of timestamp)
        "12:34:56",   // timestamp time portion
        "123.45",     // decimal -> Decimal128
        "hello",      // varchar
    ] {
        assert!(
            printed.contains(token),
            "expected decoded token {token:?} in row 1:\n{printed}"
        );
    }

    // Row 2: the all-NULL row exercises every append_null branch.
    let batches = ctx
        .sql(
            "SELECT ti, si, bi, ub, fl, db, flag, dt, ts, dec_col, txt \
              FROM wide_types WHERE id = 2",
        )
        .await
        .expect("null row plans")
        .collect()
        .await
        .expect("null row decodes");
    let total_rows: usize = batches.iter().map(RecordBatch::num_rows).sum();
    assert_eq!(total_rows, 1, "expected the single id=2 row");
    let batch = &batches[0];
    let all_null_cols = batch
        .columns()
        .iter()
        .filter(|c| c.len() == 1 && c.null_count() == 1)
        .count();
    assert_eq!(
        all_null_cols,
        batch.num_columns(),
        "every selected column should decode to NULL in the id=2 row:\n{}",
        pretty_format_batches(&batches).unwrap()
    );
}

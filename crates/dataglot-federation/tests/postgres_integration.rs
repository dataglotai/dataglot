//! Integration tests for the `PostgreSQL` federation connector.
//!
//! These tests require Docker for the `testcontainers-modules::postgres`
//! image and are therefore marked `#[ignore = "requires Docker"]`.
//! They still need to compile on every run (`cargo test --no-run`)
//! so the codepath can't drift.
//!
//! Scope of these tests (per the Phase 0 exit criteria):
//!
//! 1. End-to-end: create a `PostgresConnector`, register the table with a
//!    `DataFusion` `SessionContext` via `SessionContextFactory`, and run
//!    a `SELECT` with a `WHERE` clause.
//! 2. The result is verified both for correctness (row count / values)
//!    and for pushdown (the `EXPLAIN` output must show the predicate
//!    inside a `datafusion-federation` virtual exec node).

#![cfg(feature = "postgres")]

use std::sync::Arc;

use datafusion::arrow::array::RecordBatch;
use datafusion::arrow::util::pretty::pretty_format_batches;
use datafusion::execution::session_state::SessionStateBuilder;
use dataglot_core::{SessionConfig, SessionContextFactory};
use dataglot_federation::postgres::PostgresConnector;
use testcontainers::runners::AsyncRunner;
use testcontainers_modules::postgres::Postgres;
use tokio_postgres::NoTls;

/// Shared test setup: boot a PG container, create `public.users`, and
/// insert three rows. Returns the DSN and the running container so the
/// caller can keep the container alive for the duration of the test.
async fn setup_users_table() -> (String, testcontainers::ContainerAsync<Postgres>) {
    let container = Postgres::default().start().await.unwrap();
    let host = container.get_host().await.unwrap();
    let port = container.get_host_port_ipv4(5432).await.unwrap();
    let dsn = format!("host={host} port={port} user=postgres password=postgres dbname=postgres");

    // Seed the table using the raw driver — the dataglot connector is
    // read-only in Phase 0, so we cannot use it to populate the table.
    let (client, connection) = tokio_postgres::connect(&dsn, NoTls)
        .await
        .expect("connect to postgres");
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("postgres connection error: {e}");
        }
    });

    client
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
        .expect("seed users table");

    (dsn, container)
}

/// End-to-end: `SELECT * FROM pg.public.users WHERE age > 25` through
/// `DataFusion` must
///
/// * return two rows (Alice, Carol),
/// * stream Arrow `RecordBatch` (any call-path that would require
///   row-mode conversion above the connector layer would fail the
///   `SELECT *` return-schema assertion), and
/// * surface the pushed-down predicate in the `EXPLAIN` output.
#[tokio::test]
#[ignore = "requires Docker"]
async fn federated_select_with_pushdown() {
    let (dsn, _container) = setup_users_table().await;

    // Build the connector and resolve a TableProvider for public.users.
    // Per CLAUDE.md rule 13 the schema is fetched here (first access),
    // not at connector construction time.
    let connector = Arc::new(
        PostgresConnector::connect(&dsn)
            .await
            .expect("connector connects"),
    );
    let provider = connector
        .table_provider("public", "users")
        .await
        .expect("schema resolves for public.users");

    // Build a DataFusion SessionContext with the federation optimizer
    // registered. We bolt the federation rule onto the factory-built
    // context here rather than extending SessionContextFactory — that
    // plumbing is a follow-up in the `dataglot-core` crate.
    let factory = SessionContextFactory::new(
        SessionConfig::new()
            .with_default_catalog("dataglot")
            .with_default_schema("public"),
    )
    .unwrap();
    let ctx = factory.create_context();

    // Register federation's optimizer rule and planner via a fresh
    // SessionState. We can't mutate an existing context's state, so we
    // rebuild on top of the same runtime.
    let fed_state = SessionStateBuilder::new_from_existing(ctx.state())
        .with_optimizer_rules(datafusion_federation::default_optimizer_rules())
        .with_query_planner(Arc::new(datafusion_federation::FederatedQueryPlanner::new()))
        .build();
    let ctx = datafusion::prelude::SessionContext::new_with_state(fed_state);

    // Register the table under a simple name. datafusion-federation
    // uses the TableReference in the RemoteTable, not the DataFusion
    // registration name, when generating pushed-down SQL — so the
    // remote query will still refer to `public.users`.
    ctx.register_table("users", provider)
        .expect("register users table");

    // ---- 1. Correctness ------------------------------------------------
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

    // Confirm the expected names — rough but sufficient for this smoke.
    let printed = pretty_format_batches(&batches).unwrap().to_string();
    assert!(
        printed.contains("Alice") && printed.contains("Carol"),
        "expected Alice and Carol in results, got:\n{printed}"
    );
    assert!(
        !printed.contains("Bob"),
        "Bob (age 25) should have been filtered out, got:\n{printed}"
    );

    // ---- 2. Pushdown ---------------------------------------------------
    // `EXPLAIN` must mention the pushed-down predicate inside a
    // federation virtual exec node. We match on two signals:
    //  (a) the node name `sql_federation_exec` / `VirtualExecutionPlan`
    //      is present, and
    //  (b) the predicate `age > 25` appears in the pushed SQL string.
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
    // The unparser emits the predicate in PostgreSQL dialect; the
    // literal `25` and the column `age` should both appear in the
    // pushed SQL. We avoid asserting exact SQL since the unparser may
    // quote identifiers or reorder — but both tokens must survive.
    assert!(
        explain_str.contains("age") && explain_str.contains("25"),
        "expected pushed-down predicate on age=25 in EXPLAIN:\n{explain_str}"
    );
}

/// Lazy schema resolution (CLAUDE.md rule 13): constructing a connector
/// must not fetch any table schemas. We verify this by connecting to a
/// database that has no user tables yet and asserting `connect` still
/// succeeds.
#[tokio::test]
#[ignore = "requires Docker"]
async fn connector_does_not_prefetch_schemas() {
    let container = Postgres::default().start().await.unwrap();
    let host = container.get_host().await.unwrap();
    let port = container.get_host_port_ipv4(5432).await.unwrap();
    let dsn = format!("host={host} port={port} user=postgres password=postgres dbname=postgres");

    // No tables have been created — if `connect` tried to eagerly
    // introspect, a subsequent `table_provider` call for a missing
    // table would still succeed (because the schema would be cached
    // empty). Instead we assert: connect succeeds, then table_provider
    // for a missing table errors cleanly — proving the lookup runs on
    // demand.
    let connector = Arc::new(
        PostgresConnector::connect(&dsn)
            .await
            .expect("connect succeeds on empty db"),
    );

    let missing = connector.table_provider("public", "does_not_exist").await;
    assert!(
        missing.is_err(),
        "expected a catalog error for missing table, got Ok"
    );
    let err = missing.unwrap_err().to_string();
    assert!(
        err.to_lowercase().contains("not found") || err.to_lowercase().contains("does_not_exist"),
        "expected a not-found style error, got: {err}"
    );
}

/// End-to-end: register the connector as a `DataFusion` `CatalogProvider`
/// (the API a future `dataglot-server` PR will use) and run a
/// three-part-name `SELECT` against it.
///
/// This pins down the catalog-registration path that
/// `PostgresConnector::as_catalog_provider` is built for:
///
/// * `as_catalog_provider().await` returns a working catalog,
/// * `schema_names()` includes `public` and excludes `pg_catalog`/
///   `information_schema`/`pg_toast` (the rule documented on
///   `as_catalog_provider`),
/// * `ctx.register_catalog("pg", catalog)` accepts it,
/// * `SELECT ... FROM pg.public.users WHERE age > 25` resolves
///   through three-part naming and the rows come back correct.
#[tokio::test]
#[ignore = "requires Docker"]
async fn catalog_provider_three_part_name_select() {
    let (dsn, _container) = setup_users_table().await;

    let connector = Arc::new(
        PostgresConnector::connect(&dsn)
            .await
            .expect("connector connects"),
    );

    // Build the catalog. This is the new API exercised here.
    let catalog = connector
        .as_catalog_provider()
        .await
        .expect("catalog provider builds");

    // System schemas must be filtered out — the listing query shipped
    // by `as_catalog_provider` excludes `pg_catalog`,
    // `information_schema`, and `pg_toast`. `public` must be present
    // because we created `users` there in `setup_users_table`.
    let names = catalog.schema_names();
    assert!(
        names.iter().any(|n| n == "public"),
        "expected `public` in schema_names, got: {names:?}"
    );
    assert!(
        !names.iter().any(|n| n == "pg_catalog"),
        "`pg_catalog` must be filtered out, got: {names:?}"
    );
    assert!(
        !names.iter().any(|n| n == "information_schema"),
        "`information_schema` must be filtered out, got: {names:?}"
    );
    assert!(
        !names.iter().any(|n| n == "pg_toast"),
        "`pg_toast` must be filtered out, got: {names:?}"
    );

    // Build a federation-aware SessionContext and register the
    // catalog under the name the future dataglot-server PR will use.
    let factory = SessionContextFactory::new(SessionConfig::new()).unwrap();
    let ctx = factory.create_context();
    let fed_state = SessionStateBuilder::new_from_existing(ctx.state())
        .with_optimizer_rules(datafusion_federation::default_optimizer_rules())
        .with_query_planner(Arc::new(datafusion_federation::FederatedQueryPlanner::new()))
        .build();
    let ctx = datafusion::prelude::SessionContext::new_with_state(fed_state);
    ctx.register_catalog("pg", catalog);

    // Three-part name resolves through the catalog provider, the
    // schema provider, and into `connector.table_provider("public",
    // "users")`. The lazy schema fetch happens here (rule 13) — not
    // during `as_catalog_provider`.
    let df = ctx
        .sql("SELECT id, name, age FROM pg.public.users WHERE age > 25 ORDER BY id")
        .await
        .expect("three-part-name SQL parses and plans");
    let batches = df.collect().await.expect("executes without error");

    let total_rows: usize = batches.iter().map(RecordBatch::num_rows).sum();
    assert_eq!(
        total_rows,
        2,
        "expected 2 rows (age > 25), got:\n{}",
        pretty_format_batches(&batches).unwrap()
    );
    let printed = pretty_format_batches(&batches).unwrap().to_string();
    assert!(
        printed.contains("Alice") && printed.contains("Carol"),
        "expected Alice and Carol in results, got:\n{printed}"
    );
    assert!(
        !printed.contains("Bob"),
        "Bob (age 25) must be filtered, got:\n{printed}"
    );
}

/// `Debug` output for a connector must never include the password
/// (CLAUDE.md rule 12). This one also runs without Docker since we
/// never actually open the connection — but we still ignore it when
/// Docker is unavailable to keep the whole file under one gate.
#[tokio::test]
#[ignore = "requires Docker"]
async fn debug_does_not_leak_credentials_live() {
    let (dsn, _container) = setup_users_table().await;
    // Append a fake password marker to the DSN to make sure the
    // assertion below would trigger if Debug accidentally serialised
    // the config verbatim.
    let dsn_with_marker = format!("{dsn} application_name=dataglot_probe");
    let connector = PostgresConnector::connect(&dsn_with_marker).await.unwrap();
    let debug = format!("{connector:?}");
    assert!(
        !debug.contains("postgres password=postgres"),
        "Debug output leaked raw credentials:\n{debug}"
    );
    assert!(
        debug.contains("PostgresConnector"),
        "Debug output missing struct name: {debug}"
    );
}

/// Native-query passthrough verification (Phase 1 federation
/// breadth closeout).
///
/// **What this pins.** When a query references exactly one
/// federated source — same Postgres in this case — the
/// `datafusion-federation` planner is supposed to compile the
/// whole query (predicates, aggregation, sort, limit) into a
/// single SQL string and hand it to the source for native
/// execution. The Strategy v3.0 federation breadth section
/// records this as "Native query passthrough — single-source
/// queries bypass federation overhead. Already shipped as
/// DEV-3289; verify integration with `create_federated_context`."
/// `federated_select_with_pushdown` above already covers the
/// `WHERE` predicate case; this test broadens to the full
/// passthrough surface (GROUP BY + ORDER BY + LIMIT all pushed)
/// and asserts the **negative space** — no local
/// `AggregateExec` / `SortExec` / `RepartitionExec` /
/// `FilterExec` above the federation node.
///
/// **Why the negative-space check matters.** A test that only
/// asserts "`VirtualExecutionPlan` appears" passes even when
/// federation pushes part of the query (predicate) and `DataFusion`
/// re-does the rest locally (aggregation, sort, limit). That's
/// the regression shape we'd hit if `datafusion-federation`
/// silently lost its grip on GROUP BY pushdown after a version
/// bump. Pinning the absence of local-execution operators above
/// the federation node is what makes this a real passthrough
/// guard.
#[tokio::test]
#[ignore = "requires Docker"]
async fn single_source_complex_query_pushed_through_natively() {
    let (dsn, _container) = setup_users_table().await;

    let connector = Arc::new(
        PostgresConnector::connect(&dsn)
            .await
            .expect("connector connects"),
    );
    let provider = connector
        .table_provider("public", "users")
        .await
        .expect("schema resolves for public.users");

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

    // Complex single-source query — predicate + GROUP BY +
    // aggregate + ORDER BY + LIMIT. Native passthrough means
    // the whole thing compiles into one SQL statement sent to
    // Postgres. Anything that breaks pushdown for any of the
    // four operators surfaces here.
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
    // Seed has three age values ≥ 25: 25 (Bob), 30 (Alice), 35 (Carol).
    // Each appears once, so GROUP BY age yields three groups each
    // with COUNT(*) = 1.
    assert_eq!(
        total_rows,
        3,
        "expected 3 groups (age IN {{25, 30, 35}}) but got:\n{}",
        pretty_format_batches(&batches).unwrap()
    );

    // ---- 2. Passthrough — positive assertion -------------------
    // EXPLAIN should show the federation virtual exec node with
    // the pushed SQL carrying GROUP BY, ORDER BY, LIMIT, and the
    // predicate — proof every operator made it across.
    let explain = ctx
        .sql(&format!("EXPLAIN {complex_sql}"))
        .await
        .expect("EXPLAIN parses");
    let explain_batches = explain.collect().await.expect("EXPLAIN runs");
    let explain_str = pretty_format_batches(&explain_batches).unwrap().to_string();
    // Match in a case-insensitive way — the unparser may emit
    // SQL keywords in different cases across versions, and
    // operator names use mixed case in plan nodes.
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
    // The strong guarantee: there is NO local-execution operator
    // above the federation node. Any of these would mean
    // DataFusion re-did work the source should have handled,
    // breaking the "single-source queries bypass federation
    // overhead" promise. List the operator names that would
    // signal a regression; failure includes the full plan for
    // diagnosis.
    //
    // `RepartitionExec` is allowed if it's *below* the virtual
    // exec (the planner uses it to set partition counts) — but a
    // text-grep can't distinguish position cheaply. In practice
    // `RepartitionExec` doesn't appear at all when the whole
    // query is pushed, so a plain `contains` is a fair signal.
    //
    // `ProjectionExec` over the federation node is the one
    // routinely-allowed leftover — DataFusion sometimes wraps the
    // virtual exec in a projection that just renames or re-orders
    // columns without actually executing computation locally.
    // Keep it off the forbidden list to avoid false positives on
    // safe leftovers.
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
         this means GROUP BY / ORDER BY / LIMIT didn't fully push and Native query passthrough regressed.\n\nfull EXPLAIN:\n{explain_str}"
    );
}

/// Triggering a Postgres-side error (selecting from a nonexistent
/// table) must surface the actual `DbError` content — SQLSTATE,
/// severity, and message — not the literal "db error" string that
/// `tokio_postgres::Error`'s `Display` would otherwise emit.
///
/// PR #276 (slice 4c.B) surfaced this gap when a federation-
/// unparsed UNION returned `postgres query failed: db error` with
/// no diagnostic detail; this test pins the post-fix shape so a
/// regression in `format_pg_error` lands here rather than as
/// silent CI degradation.
#[tokio::test]
#[ignore = "requires Docker"]
async fn db_error_surfaces_actual_diagnostic_detail() {
    use datafusion::arrow::datatypes::{DataType, Field, Schema};
    use datafusion_federation::sql::SQLExecutor;
    use futures::stream::StreamExt;

    let (dsn, _container) = setup_users_table().await;
    let connector = Arc::new(
        PostgresConnector::connect(&dsn)
            .await
            .expect("connector connects"),
    );

    // Drive the executor directly with a query that Postgres will
    // reject (table doesn't exist). Going through `execute` is
    // what slice 4c.B hit — the federation-unparsed UNION ended
    // up here.
    let executor: Arc<dyn SQLExecutor> = Arc::clone(&connector) as Arc<dyn SQLExecutor>;
    let schema = Arc::new(Schema::new(vec![Field::new("x", DataType::Int32, true)]));
    let mut stream = executor
        .execute(
            "SELECT * FROM public.this_table_does_not_exist",
            Arc::clone(&schema),
            &[],
        )
        .expect("execute kicks off the query stream");
    let err = loop {
        match stream.next().await {
            Some(Ok(_)) => {}
            Some(Err(e)) => break e,
            None => panic!("expected an error before stream completion"),
        }
    };
    let msg = err.to_string();
    eprintln!("=== postgres error surface ===\n{msg}");

    // The pre-fix shape was `postgres query failed: db error` —
    // literally the string `"db error"` with nothing else.
    assert!(
        !msg.contains("postgres query failed: db error\""),
        "postgres error still surfaces as bare `db error` — \
         format_pg_error fix appears to have regressed:\n{msg}"
    );
    // The post-fix shape includes ERROR severity + the actual
    // SQLSTATE message. The exact wording depends on the Postgres
    // version (and may include localisation), so we assert on the
    // shape rather than a specific string.
    assert!(
        msg.contains("ERROR:"),
        "expected ERROR: severity prefix in postgres error, got:\n{msg}"
    );
    // The table name was specific enough to appear in any
    // sensible Postgres `relation does not exist` message.
    assert!(
        msg.contains("this_table_does_not_exist"),
        "expected the missing-table name in postgres error, got:\n{msg}"
    );
}

/// **Same-source JOIN collapse.** A JOIN between two tables
/// of the SAME Postgres catalog must ship as ONE pushed query — two
/// federated scans plus a local `HashJoinExec` would return identical
/// rows while re-doing the join client-side, so only this EXPLAIN
/// pin catches the regression. Mirrors the DuckDB-ADBC contract
/// suite's headline pin (`federation_contract.rs`) on the canonical
/// bespoke connector.
#[tokio::test]
#[ignore = "requires Docker"]
async fn same_source_join_collapses_into_one_pushed_query() {
    let (dsn, _container) = setup_users_table().await;

    // Second table on the same source, seeded via the raw driver.
    let (client, connection) = tokio_postgres::connect(&dsn, NoTls)
        .await
        .expect("connect to postgres");
    tokio::spawn(async move {
        let _ = connection.await;
    });
    client
        .batch_execute(
            "CREATE TABLE public.logins (
                 id      INT PRIMARY KEY,
                 user_id INT NOT NULL,
                 minutes INT NOT NULL
             );
             INSERT INTO public.logins (id, user_id, minutes) VALUES
                 (10, 1, 30), (11, 1, 45), (12, 2, 10), (13, 3, 60);",
        )
        .await
        .expect("seed logins table");

    let connector = Arc::new(
        PostgresConnector::connect(&dsn)
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
            .table_provider("public", table)
            .await
            .unwrap_or_else(|e| panic!("schema resolves for public.{table}: {e}"));
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

    // Shape: exactly ONE federation node, JOIN inside it, and no local
    // join/aggregate/sort/limit above.
    let explain = ctx
        .sql(&format!("EXPLAIN {sql}"))
        .await
        .expect("EXPLAIN parses");
    let explain_str = pretty_format_batches(&explain.collect().await.expect("EXPLAIN runs"))
        .unwrap()
        .to_string();
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

/// Build a federation-enabled `SessionContext` with `provider` registered
/// under `name`. Factors out the inline setup the tests above repeat: a
/// factory-built context rebuilt with federation's optimizer rules +
/// planner. (The remote query still refers to the provider's own
/// `TableReference`, not `name`.)
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

/// Seed a table exercising every Arrow type the connector decodes, plus an
/// all-`NULL` row. Row 1 carries a concrete value for each column; row 2 is
/// `NULL` for every nullable column (so every decoder's `append_null`
/// branch runs).
async fn setup_wide_types_table() -> (String, testcontainers::ContainerAsync<Postgres>) {
    let container = Postgres::default().start().await.unwrap();
    let host = container.get_host().await.unwrap();
    let port = container.get_host_port_ipv4(5432).await.unwrap();
    let dsn = format!("host={host} port={port} user=postgres password=postgres dbname=postgres");

    let (client, connection) = tokio_postgres::connect(&dsn, NoTls)
        .await
        .expect("connect to postgres");
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("postgres connection error: {e}");
        }
    });

    client
        .batch_execute(
            "CREATE TABLE public.wide_types (
                 id   INT PRIMARY KEY,
                 i2   SMALLINT,
                 i8   BIGINT,
                 num  NUMERIC(10,2),
                 f4   REAL,
                 f8   DOUBLE PRECISION,
                 flag BOOLEAN,
                 d    DATE,
                 ts   TIMESTAMP,
                 txt  TEXT,
                 ch   CHAR(4)
             );
             INSERT INTO public.wide_types VALUES
                 (1, 32000, 9000000000, 123.45, 1.5, 2.5, true,
                  '2020-01-15', '2020-01-15 12:34:56', 'hello', 'abcd'),
                 (2, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);",
        )
        .await
        .expect("seed wide_types table");

    (dsn, container)
}

/// Every decoded Arrow type round-trips through the connector, and an
/// all-`NULL` row decodes to nulls. Row 1 previously had integration
/// coverage only for `int4` + `varchar`; this exercises `int2`, `int8`,
/// `numeric` (Decimal128), `float4`, `float8`, `bool`, `date`,
/// `timestamp`, `text`, and `bpchar` too. Row 2 exercises every decoder's
/// null branch — no prior test inserted a NULL.
#[tokio::test]
#[ignore = "requires Docker"]
async fn wide_type_and_null_round_trip() {
    let (dsn, _container) = setup_wide_types_table().await;
    let connector = Arc::new(
        PostgresConnector::connect(&dsn)
            .await
            .expect("connector connects"),
    );
    let provider = connector
        .table_provider("public", "wide_types")
        .await
        .expect("schema resolves for public.wide_types");
    let ctx = federated_ctx_with(provider, "wide_types");

    // ---- Row 1: every type carries its value through decode ------------
    let batches = ctx
        .sql("SELECT i2, i8, num, f4, f8, flag, d, ts, txt, ch FROM wide_types WHERE id = 1")
        .await
        .expect("value row plans")
        .collect()
        .await
        .expect("value row decodes");
    let printed = pretty_format_batches(&batches).unwrap().to_string();
    for token in [
        "32000",      // int2
        "9000000000", // int8
        "123.45",     // numeric -> Decimal128(10,2)
        "1.5",        // float4
        "2.5",        // float8
        "true",       // bool
        "2020-01-15", // date (and the date portion of the timestamp)
        "12:34:56",   // timestamp time portion
        "hello",      // text
        "abcd",       // bpchar / CHAR(4)
    ] {
        assert!(
            printed.contains(token),
            "expected decoded token {token:?} in row 1:\n{printed}"
        );
    }

    // ---- Row 2: the all-NULL row exercises every append_null branch ----
    let batches = ctx
        .sql("SELECT i2, i8, num, f4, f8, flag, d, ts, txt, ch FROM wide_types WHERE id = 2")
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

/// Projection pushdown: selecting a single column must narrow the pushed
/// SQL to just that column — the pruned columns should not appear in the
/// federation node's remote query. Prior tests always selected every
/// column, so column pruning was never asserted.
#[tokio::test]
#[ignore = "requires Docker"]
async fn projection_pushdown_narrows_pushed_columns() {
    let (dsn, _container) = setup_users_table().await;
    let connector = Arc::new(
        PostgresConnector::connect(&dsn)
            .await
            .expect("connector connects"),
    );
    let provider = connector
        .table_provider("public", "users")
        .await
        .expect("schema resolves for public.users");
    let ctx = federated_ctx_with(provider, "users");

    let explain = ctx
        .sql("EXPLAIN SELECT name FROM users")
        .await
        .expect("EXPLAIN parses")
        .collect()
        .await
        .expect("EXPLAIN runs");
    let explain_str = pretty_format_batches(&explain).unwrap().to_string();

    assert!(
        explain_str.contains("VirtualExecutionPlan") || explain_str.contains("sql_federation_exec"),
        "expected a federation virtual exec node:\n{explain_str}"
    );
    assert!(
        explain_str.contains("name"),
        "pushed SQL should select `name`:\n{explain_str}"
    );
    assert!(
        !explain_str.contains("age"),
        "projection pushdown should prune `age` from the pushed SQL:\n{explain_str}"
    );
}

/// Regression for  (Bug B): a pushed-down `date_trunc('year', ts)` has
/// DataFusion return type `Timestamp(Nanosecond, None)`, which a source column
/// never produces (those map to microsecond). Before the fix the Postgres
/// decoder had no nanosecond arm and failed with "no decoder for arrow type
/// Timestamp(Nanosecond, None)" — the exact path a `date_year` column mask
/// takes. Asserts `date_trunc` pushes down (so the ns decoder is exercised) and
/// the truncated values decode correctly.
#[tokio::test]
#[ignore = "requires Docker"]
async fn date_trunc_year_pushdown_decodes_nanosecond_timestamp() {
    let container = Postgres::default().start().await.unwrap();
    let host = container.get_host().await.unwrap();
    let port = container.get_host_port_ipv4(5432).await.unwrap();
    let dsn = format!("host={host} port={port} user=postgres password=postgres dbname=postgres");

    let (client, connection) = tokio_postgres::connect(&dsn, NoTls)
        .await
        .expect("connect to postgres");
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("postgres connection error: {e}");
        }
    });
    client
        .batch_execute(
            "CREATE TABLE public.events (
                 id INT PRIMARY KEY,
                 at TIMESTAMP NOT NULL
             );
             INSERT INTO public.events (id, at) VALUES
                 (1, TIMESTAMP '2023-05-11 08:30:00'),
                 (2, TIMESTAMP '2024-01-20 23:59:59');",
        )
        .await
        .expect("seed events table");

    let connector = Arc::new(
        PostgresConnector::connect(&dsn)
            .await
            .expect("connector connects"),
    );
    let provider = connector
        .table_provider("public", "events")
        .await
        .expect("schema resolves for public.events");

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
    ctx.register_table("events", provider)
        .expect("register events table");

    // date_trunc must push down for the nanosecond decoder to be exercised at
    // all — if it were evaluated locally the source column would arrive as
    // microsecond and this test wouldn't cover the fix.
    let explain = ctx
        .sql("EXPLAIN SELECT date_trunc('year', at) FROM events")
        .await
        .expect("EXPLAIN parses");
    let explain_str = pretty_format_batches(&explain.collect().await.expect("EXPLAIN runs"))
        .unwrap()
        .to_string();
    assert!(
        explain_str.to_lowercase().contains("date_trunc"),
        "date_trunc must push down to exercise the nanosecond decoder:\n{explain_str}"
    );

    // The query itself must now execute (pre-fix: decoder error) and truncate
    // each timestamp to Jan 1 of its year.
    let df = ctx
        .sql("SELECT id, date_trunc('year', at) AS yr FROM events ORDER BY id")
        .await
        .expect("SQL parses and plans");
    let batches = df
        .collect()
        .await
        .expect("executes without error (nanosecond timestamp decodes)");
    let printed = pretty_format_batches(&batches).unwrap().to_string();
    assert!(
        printed.contains("2023-01-01") && printed.contains("2024-01-01"),
        "expected year-truncated timestamps, got:\n{printed}"
    );
}

//! Integration tests for the generic ADBC connector,
//! modelled on the `postgres_integration.rs` precedent and the test
//! scenarios document at `docs/phases/phase-3/02-adbc-connector-tests.md`
//! (section 5).
//!
//! Fixture: the DuckDB shared library, which exports the
//! `duckdb_adbc_init` ADBC entrypoint. The path comes from the
//! `ADBC_DRIVER_DUCKDB_PATH` env var (see
//! `.github/scripts/download-duckdb-adbc-driver.sh`); every test
//! silently skips when it is unset — same shape as the Snowflake
//! nightly job.

#![cfg(feature = "adbc")]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use adbc_core::options::{AdbcVersion, OptionDatabase, OptionValue};
use adbc_core::{Connection as _, Database as _, Driver as _, Statement as _};
use adbc_driver_manager::ManagedDriver;
use arrow::record_batch::RecordBatch;
use arrow::util::pretty::pretty_format_batches;
use datafusion::execution::SessionStateBuilder;
use dataglot_core::{SessionConfig, SessionContextFactory};
use dataglot_federation::adbc::{AdbcConfig, AdbcConnector, SupportedDialect};

/// The ADBC init symbol exported by libduckdb. The default entrypoint
/// derivation expects `libadbc_driver_*` naming, so the fixture always
/// overrides it (this is exactly what `driver_entrypoint` is for).
const DUCKDB_ENTRYPOINT: &str = "duckdb_adbc_init";

/// Driver path from the environment, or `None` → skip the test.
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

/// Seed a DuckDB file database with the `orders` fixture using the raw
/// driver manager, then release every handle so the connector under
/// test gets exclusive access to the file.
fn seed_orders(driver_path: &Path, db_file: &str) {
    let mut driver = ManagedDriver::load_dynamic_from_filename(
        driver_path,
        Some(DUCKDB_ENTRYPOINT.as_bytes()),
        AdbcVersion::V110,
    )
    .or_else(|_| {
        ManagedDriver::load_dynamic_from_filename(
            driver_path,
            Some(DUCKDB_ENTRYPOINT.as_bytes()),
            AdbcVersion::V100,
        )
    })
    .expect("duckdb adbc driver loads");
    let database = driver
        .new_database_with_opts(vec![(
            OptionDatabase::Other("path".to_string()),
            OptionValue::String(db_file.to_string()),
        )])
        .expect("duckdb database opens");
    let mut conn = database.new_connection().expect("duckdb connection opens");
    for sql in [
        "CREATE TABLE orders (
            id INTEGER,
            customer VARCHAR,
            amount DOUBLE,
            region VARCHAR
        )",
        "INSERT INTO orders VALUES
            (1, 'alice',  12.5, 'emea'),
            (2, 'bob',     3.0, 'emea'),
            (3, 'carol',  40.0, 'amer'),
            (4, 'dave',    7.5, 'amer'),
            (5, 'erin',    9.0, 'apac'),
            (6, 'frank',   2.0, 'apac'),
            (7, 'grace',  55.0, 'amer'),
            (8, 'heidi',  18.0, 'emea')",
    ] {
        let mut stmt = conn.new_statement().expect("statement allocates");
        stmt.set_sql_query(sql).expect("sql sets");
        stmt.execute_update().expect("seed statement runs");
    }
    // Handles drop here — DuckDB allows one live database handle per
    // file, so the connector must open after the seeder closes.
}

/// Build a federation-aware `SessionContext` with the connector's
/// `orders` table registered — the same wiring as the Postgres
/// integration tests.
async fn session_with_orders(
    connector: &Arc<AdbcConnector>,
) -> datafusion::prelude::SessionContext {
    let provider = connector
        .table_provider("main", "orders")
        .await
        .expect("schema resolves for main.orders");

    let factory = SessionContextFactory::new(
        SessionConfig::new()
            .with_default_catalog("dataglot")
            .with_default_schema("main"),
    )
    .unwrap();
    let ctx = factory.create_context();
    let fed_state = SessionStateBuilder::new_from_existing(ctx.state())
        .with_optimizer_rules(datafusion_federation::default_optimizer_rules())
        .with_query_planner(Arc::new(datafusion_federation::FederatedQueryPlanner::new()))
        .build();
    let ctx = datafusion::prelude::SessionContext::new_with_state(fed_state);
    ctx.register_table("orders", provider)
        .expect("register orders table");
    ctx
}

async fn connect_fixture(driver: &Path, db_file: &str) -> Arc<AdbcConnector> {
    let mut config = AdbcConfig::new("duck_adbc", driver, SupportedDialect::DuckDb);
    config.driver_entrypoint = Some(DUCKDB_ENTRYPOINT.to_string());
    config.driver_options = Some(format!("path={db_file}"));
    Arc::new(
        AdbcConnector::connect(config)
            .await
            .expect("adbc connector connects to the duckdb fixture"),
    )
}

/// Scenario 5.1–5.3 + 5.5: a complex single-source query (projection +
/// filter + `GROUP BY` + `ORDER BY` + `LIMIT`) returns correct rows,
/// its `EXPLAIN` shows every operator inside the federation node
/// (positive space), and no local execution operator appears above it
/// (negative space). A second query exercises the pool-return path.
#[tokio::test]
async fn single_source_complex_query_pushed_through_natively() {
    let Some(driver) = driver_path() else { return };
    let dir = tempfile::tempdir().expect("tempdir");
    let db_file = dir.path().join("fixture.duckdb");
    let db_file = db_file.to_str().expect("utf8 temp path");
    seed_orders(&driver, db_file);

    let connector = connect_fixture(&driver, db_file).await;
    let ctx = session_with_orders(&connector).await;

    let complex_sql = "
        SELECT region, COUNT(*) AS n, SUM(amount) AS total
        FROM orders
        WHERE amount >= 5
        GROUP BY region
        ORDER BY region
        LIMIT 10
    ";

    // ---- 1. Correctness --------------------------------------------
    let df = ctx.sql(complex_sql).await.expect("complex SQL plans");
    let batches = df.collect().await.expect("complex SQL executes");
    let rendered = pretty_format_batches(&batches).unwrap().to_string();
    let total_rows: usize = batches.iter().map(RecordBatch::num_rows).sum();
    // amount >= 5 keeps 6 of 8 rows across all three regions:
    // amer {40, 7.5, 55}, apac {9}, emea {12.5, 18}.
    assert_eq!(total_rows, 3, "expected 3 region groups:\n{rendered}");
    assert!(rendered.contains("amer"), "missing amer group:\n{rendered}");
    assert!(
        rendered.contains("102.5"),
        "amer SUM(amount) should be 102.5:\n{rendered}"
    );

    // ---- 2. Passthrough — positive space ---------------------------
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
        explain_str.contains("amount") && explain_str.contains('5'),
        "expected the predicate (amount, 5) in pushed SQL:\n{explain_str}"
    );

    // ---- 3. Passthrough — negative space ---------------------------
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
        "single-source complex query leaked local-execution operator(s) above the \
         federation node: {leaks:?}\nfull EXPLAIN:\n{explain_str}"
    );

    // ---- 4. Pool-return path (scenario 5.5) ------------------------
    // A second query on the same connector reuses the pooled
    // connection (DuckDB's reset is a no-op, so a failed re-pool
    // would surface as a reconnect error or a hang here).
    let df = ctx
        .sql("SELECT COUNT(*) AS all_rows FROM orders")
        .await
        .expect("second query plans");
    let batches = df.collect().await.expect("second query executes");
    let rendered = pretty_format_batches(&batches).unwrap().to_string();
    assert!(rendered.contains('8'), "expected 8 rows total:\n{rendered}");
}

/// Scenario 5.4: schema resolution is lazy — `connect` succeeds without
/// touching table metadata, and the driver-resolved Arrow schema only
/// materializes on the first `table_provider` call.
#[tokio::test]
async fn schema_resolves_lazily_via_the_driver() {
    let Some(driver) = driver_path() else { return };
    let dir = tempfile::tempdir().expect("tempdir");
    let db_file = dir.path().join("lazy.duckdb");
    let db_file = db_file.to_str().expect("utf8 temp path");
    seed_orders(&driver, db_file);

    let connector = connect_fixture(&driver, db_file).await;

    // Unknown table: connect already succeeded, the error surfaces at
    // table_provider time — proof schema IO is deferred.
    let err = connector
        .table_provider("main", "does_not_exist")
        .await
        .expect_err("unknown table errors at provider construction");
    let msg = err.to_string();
    assert!(
        msg.contains("does_not_exist"),
        "error should name the missing table: {msg}"
    );

    // Known table: schema comes back with the fixture's four columns.
    let provider = connector
        .table_provider("main", "orders")
        .await
        .expect("orders schema resolves");
    let schema = provider.schema();
    let names: Vec<&str> = schema.fields().iter().map(|f| f.name().as_str()).collect();
    assert_eq!(names, vec!["id", "customer", "amount", "region"]);
}

/// Slice 2 exit criterion: catalog discovery via `get_objects`
/// enumerates schemas and tables (eager listing), and per-table Arrow
/// schemas resolve on first access (lazy, rule 13). Fixture: two
/// schemas with two tables each, per the spec.
#[tokio::test]
async fn catalog_provider_discovers_schemas_and_resolves_lazily() {
    let Some(driver) = driver_path() else { return };
    let dir = tempfile::tempdir().expect("tempdir");
    let db_file = dir.path().join("discovery.duckdb");
    let db_file = db_file.to_str().expect("utf8 temp path");

    // Seed two schemas × two tables via the raw driver.
    {
        let mut raw = ManagedDriver::load_dynamic_from_filename(
            &driver,
            Some(DUCKDB_ENTRYPOINT.as_bytes()),
            AdbcVersion::V110,
        )
        .expect("duckdb adbc driver loads");
        let database = raw
            .new_database_with_opts(vec![(
                OptionDatabase::Other("path".to_string()),
                OptionValue::String(db_file.to_string()),
            )])
            .expect("duckdb database opens");
        let mut conn = database.new_connection().expect("duckdb connection opens");
        for sql in [
            "CREATE SCHEMA sales",
            "CREATE SCHEMA ops",
            "CREATE TABLE sales.orders (id INTEGER, amount DOUBLE)",
            "CREATE TABLE sales.customers (id INTEGER, name VARCHAR)",
            "CREATE TABLE ops.jobs (id INTEGER, state VARCHAR)",
            "CREATE TABLE ops.runs (id INTEGER, took_ms BIGINT)",
        ] {
            let mut stmt = conn.new_statement().expect("statement allocates");
            stmt.set_sql_query(sql).expect("sql sets");
            stmt.execute_update().expect("seed statement runs");
        }
    }

    let connector = connect_fixture(&driver, db_file).await;
    let catalog = connector
        .as_catalog_provider()
        .await
        .expect("catalog provider builds from get_objects");

    // Eager listing: both user schemas appear (DuckDB also reports its
    // built-in main/information_schema etc. — assert containment, not
    // equality).
    let schema_names = catalog.schema_names();
    for expected in ["sales", "ops"] {
        assert!(
            schema_names.iter().any(|s| s == expected),
            "schema '{expected}' missing from {schema_names:?}"
        );
    }

    let sales = catalog.schema("sales").expect("sales schema resolves");
    let mut tables = sales.table_names();
    tables.sort();
    assert_eq!(tables, vec!["customers", "orders"]);

    // Lazy schema resolution on first table access.
    let orders = sales
        .table("orders")
        .await
        .expect("orders table lookup succeeds")
        .expect("orders exists");
    let orders_schema = orders.schema();
    let names: Vec<&str> = orders_schema
        .fields()
        .iter()
        .map(|f| f.name().as_str())
        .collect();
    assert_eq!(names, vec!["id", "amount"]);

    // Negative path: unknown names return None without a driver trip.
    assert!(sales
        .table("does_not_exist")
        .await
        .expect("lookup runs")
        .is_none());
}

///: a federated DuckDB source must open read-only, so multiple engine
/// instances can share one DuckDB file instead of the second failing on
/// DuckDB's single-writer *exclusive* lock (which crashed a second server's
/// boot). Two things are verified:
///
/// 1. `access_mode=read_only` is the right, working DuckDB-ADBC key AND it
///    genuinely opens read-only — a write through such a handle is rejected.
///    (A wrong key would error on open; a no-op key would accept the write.)
/// 2. The connector defaults DuckDB to that mode, so two `AdbcConnector`s open
///    the same file concurrently and both serve queries.
///
/// (Cross-process — the actual  scenario — follows from read-only
/// semantics: a read-only open takes no exclusive lock. A same-process
/// read-write control isn't used: DuckDB permits two read-write handles within
/// one process, so it wouldn't model the cross-process lock.)
#[tokio::test]
async fn duckdb_opens_read_only_so_instances_share_one_file() {
    let Some(driver) = driver_path() else { return };
    let dir = tempfile::tempdir().expect("tempdir");
    let db_file = dir.path().join("shared.duckdb");
    let db_file = db_file.to_str().expect("utf8 temp path");
    seed_orders(&driver, db_file);

    // (1) Raw-driver proof that access_mode=read_only really opens read-only:
    // the open succeeds (valid key) and a write is rejected (genuinely RO).
    {
        let mut raw = ManagedDriver::load_dynamic_from_filename(
            &driver,
            Some(DUCKDB_ENTRYPOINT.as_bytes()),
            AdbcVersion::V110,
        )
        .expect("duckdb adbc driver loads");
        let ro_db = raw
            .new_database_with_opts(vec![
                (
                    OptionDatabase::Other("path".to_string()),
                    OptionValue::String(db_file.to_string()),
                ),
                (
                    OptionDatabase::Other("access_mode".to_string()),
                    OptionValue::String("read_only".to_string()),
                ),
            ])
            .expect("access_mode=read_only is a valid DuckDB-ADBC key; read-only db opens");
        let mut conn = ro_db.new_connection().expect("read-only connection opens");
        let mut stmt = conn.new_statement().expect("statement allocates");
        stmt.set_sql_query("INSERT INTO orders VALUES (99, 'x', 1.0, 'z')")
            .expect("sql sets");
        assert!(
            stmt.execute_update().is_err(),
            "a write through an access_mode=read_only handle must be rejected"
        );
    }

    // (2) The connector defaults DuckDB to read-only (no access_mode set), so
    // two instances open the SAME file concurrently and both serve queries.
    let cfg = |name: &str| {
        let mut config = AdbcConfig::new(name, &driver, SupportedDialect::DuckDb);
        config.driver_entrypoint = Some(DUCKDB_ENTRYPOINT.to_string());
        config.driver_options = Some(format!("path={db_file}"));
        config
    };
    let a = Arc::new(
        AdbcConnector::connect(cfg("ro_a"))
            .await
            .expect("first open (read-only default) succeeds"),
    );
    let b = Arc::new(
        AdbcConnector::connect(cfg("ro_b"))
            .await
            .expect("second open shares the file — read-only default takes no exclusive lock"),
    );
    for c in [&a, &b] {
        let ctx = session_with_orders(c).await;
        let batches = ctx
            .sql("SELECT COUNT(*) AS n FROM orders")
            .await
            .expect("plan")
            .collect()
            .await
            .expect("exec");
        let rendered = pretty_format_batches(&batches).unwrap().to_string();
        assert!(
            rendered.contains('8'),
            "both read-only connectors query the shared file:\n{rendered}"
        );
    }
}

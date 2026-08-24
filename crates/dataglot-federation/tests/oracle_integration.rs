//! Oracle connector integration test.
//!
//! Requires Docker (the `gvenzl/oracle-free` testcontainer) **and**
//! Oracle Instant Client on the host (the `oracle`/ODPI-C crate dlopen's
//! it at runtime). Marked `#[ignore = "requires Docker + Instant Client"]`.
//!
//! **x86-only.** Oracle Database Free has no ARM image, and
//! `testcontainers_modules::oracle` is `#[cfg(not(aarch64))]` upstream —
//! so this whole file is gated off on aarch64 (Apple Silicon). It runs in
//! the dedicated x86 CI Oracle job (see the spec's CI step); it cannot run
//! on Apple-Silicon dev machines.
//!
//! This is the mandatory EXPLAIN pushdown-parity test (CLAUDE.md "SQL
//! connector parity" rule), modelled on
//! `single_source_complex_query_pushed_through_natively` in
//! `postgres_integration.rs`. The Oracle twist: the pushed SQL must carry
//! `FETCH FIRST … ROWS ONLY` (not `LIMIT`), proving the connector's
//! `ast_analyzer` rewrite reached the wire.

#![cfg(all(feature = "oracle", not(target_arch = "aarch64")))]

use std::sync::Arc;

use datafusion::arrow::array::RecordBatch;
use datafusion::arrow::util::pretty::pretty_format_batches;
use datafusion::execution::session_state::SessionStateBuilder;
use dataglot_core::{SessionConfig, SessionContextFactory};
use dataglot_federation::oracle::OracleConnector;
use testcontainers::runners::AsyncRunner;
use testcontainers_modules::oracle::free::Oracle;

/// gvenzl/oracle-free defaults: app user `test` / password `test`,
/// pluggable database service `FREEPDB1`.
const USER: &str = "test";
const PASSWORD: &str = "test";

/// Start Oracle Free, seed `TEST.USERS`, return (easy-connect DSN, container).
async fn setup_users_table() -> (String, testcontainers::ContainerAsync<Oracle>) {
    let container = Oracle::default()
        .start()
        .await
        .expect("oracle-free container starts");
    let host = container.get_host().await.expect("host");
    let port = container
        .get_host_port_ipv4(1521)
        .await
        .expect("oracle port");
    let dsn = format!("//{host}:{port}/FREEPDB1");

    // Seed via a direct (sync) oracle connection on a blocking thread —
    // the `oracle` crate is synchronous.
    let seed_dsn = dsn.clone();
    tokio::task::spawn_blocking(move || {
        let conn = oracle::Connection::connect(USER, PASSWORD, &seed_dsn).expect("seed connection");
        // `balance NUMBER(10,2)` exercises the  Decimal128 decode
        // path (NUMBER with scale -> exact Decimal128, not a lossy f64).
        conn.execute(
            "CREATE TABLE users (id NUMBER PRIMARY KEY, name VARCHAR2(100), age NUMBER, \
             balance NUMBER(10,2))",
            &[],
        )
        .expect("create users");
        for (id, name, age, balance) in [
            (1, "Alice", 30, "100.05"),
            (2, "Bob", 25, "-12.50"),
            (3, "Carol", 35, "9999999.99"),
        ] {
            conn.execute(
                "INSERT INTO users (id, name, age, balance) VALUES (:1, :2, :3, :4)",
                &[&id, &name, &age, &balance],
            )
            .expect("insert row");
        }
        conn.commit().expect("commit seed");
    })
    .await
    .expect("seed task");

    (dsn, container)
}

#[tokio::test]
#[ignore = "requires Docker + Oracle Instant Client (x86 CI only)"]
async fn single_source_complex_query_pushed_through_natively() {
    let (dsn, _container) = setup_users_table().await;

    let connector = Arc::new(
        OracleConnector::connect("oracle", &dsn, USER, PASSWORD)
            .await
            .expect("connector connects"),
    );
    // Oracle folds unquoted identifiers to uppercase — the owner is TEST.
    let provider = connector
        .table_provider("TEST", "USERS")
        .await
        .expect("schema resolves for TEST.USERS");

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

    // Predicate + GROUP BY + aggregate + ORDER BY + LIMIT. Native
    // passthrough compiles the whole thing into one Oracle statement.
    //
    // Column identifiers are double-quoted UPPERCASE (`"AGE"`), exactly
    // as the Snowflake parity test (`snowflake_federation.rs`) does:
    // Oracle folds unquoted identifiers to uppercase, so introspection
    // yields `AGE`/`NAME`/`ID` and the connector's dialect quotes with
    // `"`. A bare `age` would be lowercased by DataFusion's parser and
    // fail to resolve against the `AGE` field. The table name `users`
    // stays unquoted — it's the lowercase name we registered the
    // provider under on the SessionContext.
    let complex_sql = r#"
        SELECT "AGE", COUNT(*) AS n
        FROM users
        WHERE "AGE" >= 25
        GROUP BY "AGE"
        ORDER BY "AGE"
        LIMIT 10
    "#;

    // ---- 1. Correctness ----------------------------------------
    let df = ctx.sql(complex_sql).await.expect("plans");
    let batches = df.collect().await.expect("executes");
    let total_rows: usize = batches.iter().map(RecordBatch::num_rows).sum();
    assert_eq!(
        total_rows,
        3,
        "expected 3 groups (age IN {{25,30,35}}):\n{}",
        pretty_format_batches(&batches).unwrap()
    );

    // ---- 2. Pushdown — positive --------------------------------
    let explain = ctx
        .sql(&format!("EXPLAIN {complex_sql}"))
        .await
        .expect("EXPLAIN parses");
    let explain_str = pretty_format_batches(&explain.collect().await.expect("EXPLAIN runs"))
        .unwrap()
        .to_string();
    let up = explain_str.to_uppercase();

    assert!(
        up.contains("VIRTUALEXECUTIONPLAN") || explain_str.contains("sql_federation_exec"),
        "expected a federation virtual exec node:\n{explain_str}"
    );
    // Oracle dialect: GROUP BY + ORDER BY push down, and the LIMIT must
    // have become FETCH FIRST (the ast_analyzer rewrite reached the wire).
    for needle in ["GROUP BY", "ORDER BY", "FETCH FIRST"] {
        assert!(
            up.contains(needle),
            "expected {needle:?} in pushed Oracle SQL:\n{explain_str}"
        );
    }
    // The federation node's DisplayAs prints BOTH `base_sql=` (the
    // pre-`ast_analyzer` SQL, which still says LIMIT) and
    // `rewritten_executor_sql=` (post-rewrite, what actually reaches
    // Oracle). DataFusion's own logical `Limit:` plan node also prints
    // "Limit". So a blanket "no LIMIT anywhere in EXPLAIN" is wrong —
    // assert specifically on the executor SQL: it must carry FETCH
    // FIRST and must NOT carry LIMIT. Isolate the executor SQL by
    // cutting at the pretty-table cell border (`|`).
    let exec_sql = explain_str
        .split("rewritten_executor_sql=")
        .nth(1)
        .and_then(|s| s.split('|').next())
        .expect("EXPLAIN exposes the federation node's rewritten_executor_sql")
        .to_uppercase();
    assert!(
        exec_sql.contains("FETCH FIRST"),
        "rewritten executor SQL (sent to Oracle) must use FETCH FIRST:\n{explain_str}"
    );
    assert!(
        !exec_sql.contains("LIMIT"),
        "rewritten executor SQL (sent to Oracle) must not contain LIMIT:\n{explain_str}"
    );
    assert!(
        explain_str.to_lowercase().contains("age") && explain_str.contains("25"),
        "expected the predicate (age, 25) in pushed SQL:\n{explain_str}"
    );

    // ---- 3. Pushdown — negative space --------------------------
    // None of these local operators should appear: every operator
    // pushed to Oracle. (The load-bearing assertion — guards against a
    // dialect/federation regression that silently re-does work locally.)
    for forbidden in [
        "AggregateExec",
        "SortExec",
        "FilterExec",
        "GlobalLimitExec",
        "LocalLimitExec",
    ] {
        assert!(
            !explain_str.contains(forbidden),
            "{forbidden} must not appear (pushdown regression):\n{explain_str}"
        );
    }
}

///: `NUMBER(p,s)` columns decode to an exact Arrow `Decimal128`, not
/// a lossy f64. Reads the seeded `balance NUMBER(10,2)` column and asserts
/// the decoded type + exact values (incl. negative + max-width).
#[tokio::test]
#[ignore = "requires Docker + Oracle Instant Client (x86 CI only)"]
async fn number_with_scale_decodes_as_exact_decimal128() {
    use datafusion::arrow::array::{Array, Decimal128Array};
    use datafusion::arrow::datatypes::DataType;

    let (dsn, _container) = setup_users_table().await;
    let connector = Arc::new(
        OracleConnector::connect("oracle", &dsn, USER, PASSWORD)
            .await
            .expect("connector connects"),
    );
    let provider = connector
        .table_provider("TEST", "USERS")
        .await
        .expect("schema resolves for TEST.USERS");

    // Same federated-context construction as the parity test above —
    // the FederatedQueryPlanner is what executes the federated scan.
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

    let batches = ctx
        .sql(r#"SELECT "BALANCE" FROM users ORDER BY "ID""#)
        .await
        .expect("plans")
        .collect()
        .await
        .expect("executes");

    let col = batches[0].column(0);
    assert_eq!(
        col.data_type(),
        &DataType::Decimal128(10, 2),
        "NUMBER(10,2) must decode to Decimal128(10,2), got {:?}",
        col.data_type()
    );
    let dec = col
        .as_any()
        .downcast_ref::<Decimal128Array>()
        .expect("balance column is Decimal128");
    // i128 mantissa at scale 2: 100.05 -> 10005, -12.50 -> -1250,
    // 9999999.99 -> 999999999.
    assert_eq!(dec.value(0), 10_005, "100.05");
    assert_eq!(dec.value(1), -1_250, "-12.50");
    assert_eq!(dec.value(2), 999_999_999, "9999999.99");
}

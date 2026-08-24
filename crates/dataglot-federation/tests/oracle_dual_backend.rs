//! Oracle dual-backend differential harness (, slice 4 of ).
//!
//! `OracleConnector` dispatches wire operations to one of two backends
//! behind a single `SQLExecutor` surface: the OCI/ODPI-C backend
//! (`OracleDriver::Oci`, the `oracle` crate) and the pure-Rust backend
//! (`OracleDriver::Pure`, the `oracle-rs` crate). They share one dialect,
//! pushdown, type mapping, and governance surface — so the *same* query
//! against the *same* Oracle must produce **byte-identical Arrow**
//! regardless of which backend decoded the wire.
//!
//! This harness asserts exactly that: it runs one query through both
//! backends against one live `gvenzl/oracle-free` container and compares
//! the materialized results. A divergence here is a real decode/coercion
//! drift between the two backends — the thing this test exists to catch.
//!
//! ## Gating
//!
//! Requires **both** `feature = "oracle"` (OCI) and `feature =
//! "oracle-pure"` compiled together, plus Docker + the Oracle Instant
//! Client (the OCI backend dlopen's it). x86-only — Oracle-Free has no ARM
//! image and `testcontainers_modules::oracle` is `#[cfg(not(aarch64))]`
//! upstream. `#[ignore]`; runs in the x86 CI Oracle job, `--test-threads=1`.

#![cfg(all(
    feature = "oracle",
    feature = "oracle-pure",
    not(target_arch = "aarch64")
))]

use std::sync::Arc;

use datafusion::arrow::array::RecordBatch;
use datafusion::arrow::util::pretty::pretty_format_batches;
use datafusion::execution::session_state::SessionStateBuilder;
use dataglot_core::{SessionConfig, SessionContextFactory};
use dataglot_federation::oracle::{OracleConnector, OracleDriver};
use testcontainers::runners::AsyncRunner;
use testcontainers_modules::oracle::free::Oracle;

const USER: &str = "test";
const PASSWORD: &str = "test";

/// Start Oracle Free and seed `TEST.WIDE`, returning the easy-connect DSN
/// and the container. The columns span the decode paths most likely to
/// drift between backends: integer `NUMBER`, scaled `NUMBER(p,s)`
/// (Decimal128), `VARCHAR2`, and a `NULL`.
async fn setup_wide() -> (String, testcontainers::ContainerAsync<Oracle>) {
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

    let seed_dsn = dsn.clone();
    tokio::task::spawn_blocking(move || {
        let conn = oracle::Connection::connect(USER, PASSWORD, &seed_dsn).expect("seed connection");
        conn.execute(
            "CREATE TABLE wide (id NUMBER PRIMARY KEY, name VARCHAR2(100), \
             balance NUMBER(10,2), nickname VARCHAR2(50))",
            &[],
        )
        .expect("create wide");
        let rows: [(i32, &str, &str, Option<&str>); 3] = [
            (1, "Alice", "100.05", Some("ali")),
            (2, "Bob", "-12.50", None),
            (3, "Carol", "9999999.99", Some("cc")),
        ];
        for (id, name, balance, nickname) in rows {
            conn.execute(
                "INSERT INTO wide (id, name, balance, nickname) VALUES (:1, :2, :3, :4)",
                &[&id, &name, &balance, &nickname],
            )
            .expect("insert row");
        }
        conn.commit().expect("commit seed");
    })
    .await
    .expect("seed task");

    (dsn, container)
}

/// Run one query through the given backend against `TEST.WIDE` and return
/// the materialized batches rendered as a stable text table.
async fn run_through(driver: OracleDriver, dsn: &str) -> String {
    let connector = Arc::new(
        OracleConnector::connect_with_driver("oracle", dsn, USER, PASSWORD, Some(driver))
            .await
            .unwrap_or_else(|e| panic!("{driver} connector connects: {e}")),
    );
    let provider = connector
        .table_provider("TEST", "WIDE")
        .await
        .unwrap_or_else(|e| panic!("{driver} schema resolves for TEST.WIDE: {e}"));

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
    ctx.register_table("wide", provider)
        .expect("register wide table");

    // A predicate + projection + ORDER BY exercises pushdown through each
    // backend's dialect; the ORDER BY makes the row order deterministic so
    // the two renders are directly comparable.
    let sql = r#"SELECT "ID", "NAME", "BALANCE", "NICKNAME"
        FROM wide WHERE "ID" >= 1 ORDER BY "ID""#;
    let batches: Vec<RecordBatch> = ctx
        .sql(sql)
        .await
        .unwrap_or_else(|e| panic!("{driver} plans: {e}"))
        .collect()
        .await
        .unwrap_or_else(|e| panic!("{driver} executes: {e}"));

    pretty_format_batches(&batches)
        .expect("format batches")
        .to_string()
}

/// The OCI and pure-Rust backends must materialize byte-identical Arrow
/// for the same query against the same Oracle table.
#[tokio::test]
#[ignore = "requires Docker + Oracle Instant Client (x86 CI only)"]
async fn oci_and_pure_backends_produce_identical_arrow() {
    let (dsn, _container) = setup_wide().await;

    let oci = run_through(OracleDriver::Oci, &dsn).await;
    let pure = run_through(OracleDriver::Pure, &dsn).await;

    assert_eq!(
        oci, pure,
        "OCI and pure-Rust backends diverged on the same query — \
         decode/coercion drift.\n\n--- OCI ---\n{oci}\n\n--- PURE ---\n{pure}"
    );
    // Sanity: the comparison isn't vacuously equal on empty output.
    assert!(
        oci.contains("Alice") && oci.contains("Carol"),
        "expected seeded rows:\n{oci}"
    );
}

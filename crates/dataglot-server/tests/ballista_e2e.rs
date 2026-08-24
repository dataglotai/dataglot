//! End-to-end distributed execution: **pgwire → Ballista cluster →
//! result**.
//!
//! The 2026-07-11 ballista test audit found every existing distributed
//! test stops short of the production wire path: `dataglot-ballista`'s
//! suites drive a `SessionContext` directly, and `dataglot-server`'s
//! only ballista-feature test asserts the session's *planner* without
//! executing anything. Nothing proved a real pgwire client gets rows
//! back from a query that actually ran on the in-process Ballista
//! cluster. This file closes that gap — no Docker required (local
//! parquet via an `object_storage` catalog; the standalone cluster is
//! in-process).
//!
//! Also pins two behaviours the demo depends on:
//! - `dataglot_execution_mode()` reports `distributed (parallelism N)`
//!   over the wire ( badge source), and
//! - concurrent pgwire clients can run distributed queries
//!   simultaneously (the audit flagged zero concurrency coverage).
//!
//! Feature-gated: compiled empty without `--features ballista`. Runs in
//! the CI ballista job (which installs protoc).

#![cfg(feature = "ballista")]

use std::fs::File;
use std::sync::Arc;
use std::time::Duration;

use datafusion::arrow::array::{Int32Array, RecordBatch, StringArray};
use datafusion::arrow::datatypes::{DataType, Field, Schema};
use parquet::arrow::ArrowWriter;
use parquet::file::properties::WriterProperties;
use tempfile::TempDir;

use dataglot_server::config::{
    BallistaServerConfig, CatalogConfig, ObjectStorageCatalogConfig, ObjectStorageFormat,
    ObjectStorageTableConfig, ServerConfig,
};
use dataglot_server::server::DataglotServer;
use tokio_postgres::NoTls;

/// Seed `users.parquet` (id, name × 3 rows) and return the tempdir +
/// `file://` URL. Mirrors `object_storage_e2e.rs`.
fn seed_users_parquet() -> (TempDir, String) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("users.parquet");
    let schema = Arc::new(Schema::new(vec![
        Field::new("id", DataType::Int32, false),
        Field::new("name", DataType::Utf8, false),
    ]));
    let batch = RecordBatch::try_new(
        Arc::clone(&schema),
        vec![
            Arc::new(Int32Array::from(vec![1, 2, 3])),
            Arc::new(StringArray::from(vec!["Alice", "Bob", "Carol"])),
        ],
    )
    .expect("build seed batch");
    let file = File::create(&path).expect("create parquet file");
    let mut writer = ArrowWriter::try_new(file, schema, Some(WriterProperties::builder().build()))
        .expect("build ArrowWriter");
    writer.write(&batch).expect("write seed batch");
    writer.close().expect("finalize parquet");
    let posix_path = path.display().to_string().replace('\\', "/");
    let url = format!("file:///{}", posix_path.trim_start_matches('/'));
    (tmp, url)
}

/// Reserve an ephemeral port; the server re-binds it right after.
fn ephemeral_port() -> u16 {
    //: delegate to the shared, race-hardened helper.
    dataglot_test_support::reserve_loopback_port()
}

/// Boot a distributed (in-process Ballista) `DataglotServer` over a
/// local-parquet catalog and return the pgwire port. The returned
/// tempdir must stay alive for the server's lifetime.
async fn boot_distributed_server() -> (u16, TempDir) {
    let (tmp, url) = seed_users_parquet();
    let pg_port = ephemeral_port();
    let config = ServerConfig {
        host: "127.0.0.1".to_string(),
        port: pg_port,
        // No metrics endpoint: the default 9090 bind would collide with
        // a locally running demo and with the sibling test in this file
        // (tests in one binary run concurrently).
        observability: dataglot_server::observability::ObservabilityConfig {
            metrics_addr: None,
            ..Default::default()
        },
        default_catalog: "lake".to_string(),
        catalogs: std::collections::HashMap::from([(
            "lake".to_string(),
            CatalogConfig::ObjectStorage(ObjectStorageCatalogConfig {
                s3: None,
                tables: vec![ObjectStorageTableConfig {
                    name: "users".to_string(),
                    url,
                    format: ObjectStorageFormat::Parquet,
                    schema: None,
                }],
            }),
        )]),
        ballista: Some(BallistaServerConfig {
            standalone_parallelism: 2,
            // No REST API: a fixed port would collide with parallel
            // tests / a locally running demo, and it's not under test.
            rest_api_port: None,
            ..Default::default()
        }),
        ..ServerConfig::default()
    };
    let server = DataglotServer::new(config)
        .await
        .expect("distributed server boots");
    tokio::spawn(async move {
        server.run().await.expect("server runs");
    });

    // Poll until pgwire answers.
    let conn_str = format!("host=127.0.0.1 port={pg_port} user=dataglot dbname=lake");
    for _ in 0..100 {
        if tokio_postgres::connect(&conn_str, NoTls).await.is_ok() {
            return (pg_port, tmp);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("distributed server did not become ready on port {pg_port}");
}

/// Connect a tokio-postgres client and spawn its driver.
async fn connect(pg_port: u16, dbname: &str) -> tokio_postgres::Client {
    let conn_str = format!("host=127.0.0.1 port={pg_port} user=dataglot dbname={dbname}");
    let (client, connection) = tokio_postgres::connect(&conn_str, NoTls)
        .await
        .expect("pgwire connect");
    tokio::spawn(async move {
        let _ = connection.await;
    });
    client
}

/// The core gap-closer: a pgwire client's query executes on the
/// Ballista cluster and returns correct rows — plus the session
/// reports itself distributed (the  badge source).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pgwire_query_executes_on_ballista_and_returns_rows() {
    let (pg_port, _tmp) = boot_distributed_server().await;
    let client = connect(pg_port, "lake").await;

    // The session is genuinely distributed, observable over the wire.
    let mode = client
        .query_one("SELECT dataglot_execution_mode()", &[])
        .await
        .expect("execution-mode UDF answers");
    let mode: String = mode.get(0);
    assert_eq!(
        mode, "distributed (parallelism 2)",
        "session must report the ballista config it booted with"
    );

    // Aggregate over the parquet table — runs through the cluster
    // (scan → shuffle → aggregate) and back out over pgwire.
    let row = client
        .query_one("SELECT count(*) AS n FROM lake.public.users", &[])
        .await
        .expect("distributed aggregate executes");
    let n: i64 = row.get("n");
    assert_eq!(n, 3, "all three seeded rows counted");

    // Ordered projection — pins row *values*, not just counts.
    let rows = client
        .query(
            "SELECT id, name FROM lake.public.users ORDER BY id DESC",
            &[],
        )
        .await
        .expect("distributed ORDER BY executes");
    let got: Vec<(i32, String)> = rows.iter().map(|r| (r.get(0), r.get(1))).collect();
    assert_eq!(
        got,
        vec![
            (3, "Carol".to_string()),
            (2, "Bob".to_string()),
            (1, "Alice".to_string())
        ],
        "ordered values must round-trip the cluster intact"
    );
}

///  regression guard: the `pg_catalog` introspection UDFs behind psql's
/// `\d` family and BI-tool introspection must resolve under `--distributed`,
/// not just single-node. Before the fix these errored with
/// `Invalid function 'pg_get_userbyid'` because the Ballista base context
/// skipped `setup_pg_catalog`; `current_database` / `pg_table_is_visible`
/// worked only because they're re-registered per-session.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pg_catalog_introspection_udfs_resolve_distributed() {
    let (pg_port, _tmp) = boot_distributed_server().await;
    let client = connect(pg_port, "lake").await;

    let schema: String = client
        .query_one("SELECT current_schema() AS s", &[])
        .await
        .expect("current_schema must resolve distributed")
        .get("s");
    assert_eq!(schema, "public", "current_schema() should be public");

    let ft: String = client
        .query_one("SELECT format_type(23, -1) AS t", &[])
        .await
        .expect("format_type must resolve distributed")
        .get("t");
    assert!(
        !ft.is_empty(),
        "format_type(23,-1) should render a type name, got {ft:?}"
    );

    // Owner-name fn behind \dt / \d / \l.
    client
        .query_one("SELECT pg_get_userbyid(CAST(10 AS INT)) AS u", &[])
        .await
        .expect("pg_get_userbyid must resolve distributed");

    // \df / \dT visibility shims.
    let fvis: bool = client
        .query_one("SELECT pg_function_is_visible(1) AS v", &[])
        .await
        .expect("pg_function_is_visible must resolve distributed")
        .get("v");
    let tvis: bool = client
        .query_one("SELECT pg_type_is_visible(1) AS v", &[])
        .await
        .expect("pg_type_is_visible must resolve distributed")
        .get("v");
    assert!(fvis && tvis, "visibility shims must be true");

    // The end-to-end `\dt` shape psql emits: pg_class filtered by
    // pg_table_is_visible. Must plan + return without a missing-function error.
    client
        .query(
            "SELECT c.relname FROM pg_catalog.pg_class c \
             WHERE pg_table_is_visible(c.oid) AND c.relkind = 'r'",
            &[],
        )
        .await
        .expect("\\dt-style pg_class query must resolve distributed");
}

/// Concurrency: four clients fire distributed queries simultaneously;
/// every one succeeds with the right answer. Guards the scheduler /
/// executor sharing path the audit found untested (and the failure
/// mode the SF10 stress runs hit — a dying server takes every
/// connection with it, which this would catch as joined errors).
// Hand-built runtime with production-sized worker stacks: four
// concurrent distributed `count(*)` plans, serialized through the Ballista
// codec on 2 MiB tokio test-worker stacks under the unoptimized `ci`
// profile, overflow — the same failure mode `tpch_q1_q6` and the
// cross-source join already guard against.  added the per-connection
// group-resolver overlay to the startup path, which tipped this
// already-at-the-edge test over; the production binary sets 64 MiB in
// main.rs, `#[tokio::test]` harnesses don't.
#[test]
fn concurrent_pgwire_clients_share_the_cluster() {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(8)
        .thread_stack_size(64 * 1024 * 1024)
        .enable_all()
        .build()
        .expect("test runtime")
        .block_on(concurrent_pgwire_clients_share_the_cluster_impl());
}

async fn concurrent_pgwire_clients_share_the_cluster_impl() {
    let (pg_port, _tmp) = boot_distributed_server().await;

    let mut tasks = Vec::new();
    for i in 0..4 {
        tasks.push(tokio::spawn(async move {
            let client = connect(pg_port, "lake").await;
            // Alternate shapes so the scheduler juggles distinct jobs.
            let sql = if i % 2 == 0 {
                "SELECT count(*) AS n FROM lake.public.users"
            } else {
                "SELECT count(*) AS n FROM lake.public.users WHERE id >= 1"
            };
            let row = client
                .query_one(sql, &[])
                .await
                .unwrap_or_else(|e| panic!("client {i} failed: {e}"));
            let n: i64 = row.get("n");
            assert_eq!(n, 3, "client {i} got the wrong count");
        }));
    }
    for t in tasks {
        t.await.expect("concurrent client task join");
    }
}

// ---------------------------------------------------------------------------
// Docker-gated: distributed federation across pg × mysql over pgwire.
// ---------------------------------------------------------------------------

/// **The regression net for the mysql-in-distributed gap.** The ballista
/// codec registry silently skipped MySQL, so every mysql-touching query
/// failed in `--distributed` with the plan-serialization error while
/// single-node worked — and nothing caught it, because no automated test
/// ran a federated query through the *server's* distributed path (the
/// testbench "Segment revenue" example was the only thing exercising the
/// shape, and examples aren't executed by any test).
///
/// This boots real Postgres + MySQL containers, a distributed
/// `DataglotServer` federating both, and runs the exact cross-source
/// example shape over pgwire. If either SQL-source kind drops out of the
/// codec registry again, this fails with the serialization error.
#[test]
#[ignore = "requires Docker"]
fn distributed_cross_source_pg_mysql_join_over_pgwire() {
    // Hand-built runtime with production-sized worker stacks: the deep
    // federated distributed plan overflows tokio's default 2 MiB test
    // stacks (the exact  failure mode — the production binary
    // sets 64 MiB in main.rs, but #[tokio::test] harnesses don't).
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .thread_stack_size(64 * 1024 * 1024)
        .enable_all()
        .build()
        .expect("test runtime")
        .block_on(distributed_cross_source_pg_mysql_join_impl());
}

// One linear scenario (seed → boot → query → assert); splitting it into
// helpers would scatter container lifetimes that must outlive the server.
#[allow(clippy::too_many_lines)]
async fn distributed_cross_source_pg_mysql_join_impl() {
    use mysql_async::prelude::Queryable;
    use testcontainers::runners::AsyncRunner;
    use testcontainers_modules::{mysql::Mysql, postgres::Postgres};

    // ---- containers + seeds (mirrors federation's cross_source_joins) --
    let pg = Postgres::default().start().await.expect("pg starts");
    let pg_port = pg.get_host_port_ipv4(5432).await.expect("pg port");
    let pg_dsn =
        format!("host=127.0.0.1 port={pg_port} user=postgres password=postgres dbname=postgres");
    let (pg_client, pg_conn) = tokio_postgres::connect(&pg_dsn, NoTls)
        .await
        .expect("pg seed connect");
    tokio::spawn(async move {
        let _ = pg_conn.await;
    });
    pg_client
        .batch_execute(
            "CREATE TABLE public.orders (id INT PRIMARY KEY, user_id INT NOT NULL, amount INT NOT NULL);
             INSERT INTO public.orders VALUES (1, 10, 50), (2, 10, 80), (3, 20, 30);",
        )
        .await
        .expect("seed pg orders");

    let my = Mysql::default().start().await.expect("mysql starts");
    let my_port = my.get_host_port_ipv4(3306).await.expect("mysql port");
    let my_dsn = format!("mysql://root@127.0.0.1:{my_port}/test");
    let mut my_conn =
        mysql_async::Conn::new(mysql_async::Opts::from_url(&my_dsn).expect("mysql dsn"))
            .await
            .expect("mysql seed connect");
    my_conn
        .query_drop(
            "CREATE TABLE customer_segments (user_id INT PRIMARY KEY, segment VARCHAR(32) NOT NULL)",
        )
        .await
        .expect("create segments");
    my_conn
        .query_drop("INSERT INTO customer_segments VALUES (10, 'enterprise'), (20, 'startup')")
        .await
        .expect("seed segments");
    drop(my_conn);

    // ---- distributed server federating both sources --------------------
    let pg_port_srv = ephemeral_port();
    let config = ServerConfig {
        host: "127.0.0.1".to_string(),
        port: pg_port_srv,
        observability: dataglot_server::observability::ObservabilityConfig {
            metrics_addr: None,
            ..Default::default()
        },
        default_catalog: "pg".to_string(),
        catalogs: std::collections::HashMap::from([
            (
                "pg".to_string(),
                CatalogConfig::Postgres(dataglot_server::config::PostgresCatalogConfig {
                    dsn: Some(pg_dsn.clone()),
                    ..Default::default()
                }),
            ),
            (
                "mysql_demo".to_string(),
                CatalogConfig::Mysql(dataglot_server::config::MysqlCatalogConfig {
                    dsn: Some(my_dsn.clone()),
                    ..Default::default()
                }),
            ),
        ]),
        ballista: Some(BallistaServerConfig {
            standalone_parallelism: 2,
            rest_api_port: None,
            ..Default::default()
        }),
        ..ServerConfig::default()
    };
    let server = DataglotServer::new(config)
        .await
        .expect("distributed federated server boots");
    tokio::spawn(async move {
        server.run().await.expect("server runs");
    });
    let conn_str = format!("host=127.0.0.1 port={pg_port_srv} user=dataglot dbname=pg");
    for i in 0..100 {
        if tokio_postgres::connect(&conn_str, NoTls).await.is_ok() {
            break;
        }
        assert!(i < 99, "server not ready");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // ---- the "Segment revenue" example shape, distributed --------------
    let client = connect(pg_port_srv, "pg").await;
    let rows = client
        .query(
            "SELECT s.segment, SUM(o.amount) AS revenue \
             FROM pg.public.orders o \
             JOIN mysql_demo.test.customer_segments s ON s.user_id = o.user_id \
             GROUP BY s.segment ORDER BY revenue DESC",
            &[],
        )
        .await
        .expect(
            "cross-source pg×mysql join must execute distributed — a failure \
             here usually means a SQL-source kind fell out of the ballista \
             codec registry (see registry_sql_kind)",
        );
    let got: Vec<(String, i64)> = rows.iter().map(|r| (r.get(0), r.get(1))).collect();
    assert_eq!(
        got,
        vec![("enterprise".to_string(), 130), ("startup".to_string(), 30)],
        "joined values must round-trip both sources through the cluster"
    );
}

// ---------------------------------------------------------------------------
// TPC-H through the distributed server (coverage audit item: "no TPC-H
// under ballista anywhere in CI").
// ---------------------------------------------------------------------------

/// Seed a miniature `lineitem` with hand-computed expectations, covering
/// exactly the columns the vendored q1/q6 reference. Five rows designed
/// against the real predicates:
/// - q1 (`l_shipdate <= '1998-12-01' - 90 days`): rows 1–4 pass, row 5
///   (1999) filtered → groups (A,F)×2 and (N,O)×2.
/// - q6 (1994 shipdate, discount in [0.05,0.07], quantity < 24): only
///   row 4 qualifies → revenue = 100.0 × 0.06 = 6.0.
fn seed_mini_lineitem() -> (TempDir, String) {
    use datafusion::arrow::array::{Date32Array, Float64Array};

    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("lineitem.parquet");
    let schema = Arc::new(Schema::new(vec![
        Field::new("l_returnflag", DataType::Utf8, false),
        Field::new("l_linestatus", DataType::Utf8, false),
        Field::new("l_quantity", DataType::Float64, false),
        Field::new("l_extendedprice", DataType::Float64, false),
        Field::new("l_discount", DataType::Float64, false),
        Field::new("l_tax", DataType::Float64, false),
        Field::new("l_shipdate", DataType::Date32, false),
    ]));
    // Date32 = days since 1970-01-01 (1994-01-01 = 8766; 1994 not leap).
    let batch = RecordBatch::try_new(
        Arc::clone(&schema),
        vec![
            Arc::new(StringArray::from(vec!["A", "A", "N", "N", "R"])),
            Arc::new(StringArray::from(vec!["F", "F", "O", "O", "F"])),
            Arc::new(Float64Array::from(vec![10.0, 20.0, 30.0, 5.0, 40.0])),
            Arc::new(Float64Array::from(vec![100.0, 200.0, 300.0, 100.0, 400.0])),
            Arc::new(Float64Array::from(vec![0.10, 0.0, 0.20, 0.06, 0.05])),
            Arc::new(Float64Array::from(vec![0.05, 0.0, 0.10, 0.0, 0.0])),
            Arc::new(Date32Array::from(vec![
                8825,  // 1994-03-01
                9282,  // 1995-06-01
                8931,  // 1994-06-15
                8890,  // 1994-05-05
                10592, // 1999-01-01 (q1-filtered)
            ])),
        ],
    )
    .expect("build lineitem batch");
    let file = File::create(&path).expect("create parquet");
    let mut writer = ArrowWriter::try_new(file, schema, Some(WriterProperties::builder().build()))
        .expect("writer");
    writer.write(&batch).expect("write");
    writer.close().expect("close");
    let posix = path.display().to_string().replace('\\', "/");
    (tmp, format!("file:///{}", posix.trim_start_matches('/')))
}

/// The real vendored TPC-H q1 + q6 execute on the distributed cluster
/// over pgwire, with hand-verifiable results. Bare table names resolve
/// via the session default catalog — the exact shape the benchmark
/// uses. Closes the "no TPC-H under ballista in CI" audit gap at the
/// representative-query level (the four-worker bench workflow remains
/// Phase-2 slice 8).
#[test]
fn tpch_q1_q6_execute_distributed_over_pgwire() {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .thread_stack_size(64 * 1024 * 1024) //: deep distributed plans
        .enable_all()
        .build()
        .expect("test runtime")
        .block_on(async {
            let (tmp, url) = seed_mini_lineitem();
            let pg_port = ephemeral_port();
            let config = ServerConfig {
                host: "127.0.0.1".to_string(),
                port: pg_port,
                observability: dataglot_server::observability::ObservabilityConfig {
                    metrics_addr: None,
                    ..Default::default()
                },
                default_catalog: "tpch".to_string(),
                catalogs: std::collections::HashMap::from([(
                    "tpch".to_string(),
                    CatalogConfig::ObjectStorage(ObjectStorageCatalogConfig {
                        s3: None,
                        tables: vec![ObjectStorageTableConfig {
                            name: "lineitem".to_string(),
                            url,
                            format: ObjectStorageFormat::Parquet,
                            schema: None,
                        }],
                    }),
                )]),
                ballista: Some(BallistaServerConfig {
                    standalone_parallelism: 2,
                    rest_api_port: None,
                    ..Default::default()
                }),
                ..ServerConfig::default()
            };
            let server = DataglotServer::new(config).await.expect("server boots");
            tokio::spawn(async move {
                server.run().await.expect("server runs");
            });
            let conn_str = format!("host=127.0.0.1 port={pg_port} user=dataglot dbname=tpch");
            for i in 0..100 {
                if tokio_postgres::connect(&conn_str, NoTls).await.is_ok() {
                    break;
                }
                assert!(i < 99, "server not ready");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            let client = connect(pg_port, "tpch").await;
            let _ = tmp; // keep parquet alive

            // q1 — the real vendored SQL, verbatim.
            let q1 = include_str!("../../dataglot-tests/queries/tpch/q1.sql");
            let rows = client
                .query(q1, &[])
                .await
                .expect("q1 executes distributed");
            assert_eq!(rows.len(), 2, "row 5 (1999) must be date-filtered");
            // Ordered by returnflag, linestatus: (A,F) then (N,O).
            let flags: Vec<(String, String, i64)> = rows
                .iter()
                .map(|r| {
                    (
                        r.get("l_returnflag"),
                        r.get("l_linestatus"),
                        r.get("count_order"),
                    )
                })
                .collect();
            assert_eq!(
                flags,
                vec![
                    ("A".to_string(), "F".to_string(), 2),
                    ("N".to_string(), "O".to_string(), 2)
                ],
                "q1 groups/order/counts must match the hand-computed seed"
            );
            let sum_qty_af: f64 = rows[0].get("sum_qty");
            assert!((sum_qty_af - 30.0).abs() < 1e-9, "A,F qty 10+20");

            // q6 — only row 4 (disc 0.06, qty 5, 1994) qualifies.
            let q6 = include_str!("../../dataglot-tests/queries/tpch/q6.sql");
            let row = client
                .query_one(q6, &[])
                .await
                .expect("q6 executes distributed");
            let revenue: f64 = row.get("revenue");
            assert!(
                (revenue - 6.0).abs() < 1e-9,
                "q6 revenue must be 100.0 * 0.06 = 6.0, got {revenue}"
            );
        });
}

// ---------------------------------------------------------------------------
// Governance parity through the distributed server over pgwire (audit
// item: masks/filters verified live but never automated on this path).
// ---------------------------------------------------------------------------

/// Column mask + row filter enforce identically when the session
/// executes on the Ballista cluster: `users` has 3 rows, the filter
/// keeps only Bob's, the mask hides the email — over the production
/// pgwire path. This was live-verified during; this pins it.
//  (see `concurrent_pgwire_clients_share_the_cluster` above): the
// distributed mask + row-filter plan overflows tokio's default 2 MiB
// test-worker stacks under the unoptimized `ci` profile. 's
// group-conditional enforcement (deeper predicate trees) plus 's
// startup frames pushed this over the edge. Hand-build the runtime with
// 64 MiB worker stacks, matching the sibling distributed tests.
#[test]
#[ignore = "requires Docker"]
fn governance_mask_and_filter_enforced_distributed_over_pgwire() {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .thread_stack_size(64 * 1024 * 1024)
        .enable_all()
        .build()
        .expect("test runtime")
        .block_on(governance_mask_and_filter_enforced_distributed_over_pgwire_impl());
}

async fn governance_mask_and_filter_enforced_distributed_over_pgwire_impl() {
    use testcontainers::runners::AsyncRunner;
    use testcontainers_modules::postgres::Postgres;

    let pg = Postgres::default().start().await.expect("pg starts");
    let port = pg.get_host_port_ipv4(5432).await.expect("pg port");
    let dsn = format!("host=127.0.0.1 port={port} user=postgres password=postgres dbname=postgres");
    let (seed, conn) = tokio_postgres::connect(&dsn, NoTls)
        .await
        .expect("seed connect");
    tokio::spawn(async move {
        let _ = conn.await;
    });
    seed.batch_execute(
        "CREATE TABLE public.users (id INT PRIMARY KEY, email TEXT NOT NULL);
         INSERT INTO public.users VALUES
             (1, 'alice@example.com'), (2, 'bob@example.com'), (3, 'carol@example.com');",
    )
    .await
    .expect("seed users");

    let pg_port_srv = ephemeral_port();
    let config = ServerConfig {
        host: "127.0.0.1".to_string(),
        port: pg_port_srv,
        observability: dataglot_server::observability::ObservabilityConfig {
            metrics_addr: None,
            ..Default::default()
        },
        default_catalog: "pg".to_string(),
        catalogs: std::collections::HashMap::from([(
            "pg".to_string(),
            CatalogConfig::Postgres(dataglot_server::config::PostgresCatalogConfig {
                dsn: Some(dsn.clone()),
                ..Default::default()
            }),
        )]),
        masks: vec![dataglot_server::config::MaskConfig {
            table: "users".to_string(),
            column: "email".to_string(),
            mask_literal: "***@example.com".to_string(),
            mask_type: None,
            priority: 0,
            mask_expr: None,
            groups: None,
        }],
        row_filters: vec![dataglot_server::config::RowFilterConfig {
            table: "users".to_string(),
            predicate: dataglot_server::config::RowPredicateConfig::EqString {
                column: "email".to_string(),
                value: "bob@example.com".to_string(),
            },
            groups: None,
        }],
        ballista: Some(BallistaServerConfig {
            standalone_parallelism: 2,
            rest_api_port: None,
            ..Default::default()
        }),
        ..ServerConfig::default()
    };
    let server = DataglotServer::new(config).await.expect("server boots");
    tokio::spawn(async move {
        server.run().await.expect("server runs");
    });
    let conn_str = format!("host=127.0.0.1 port={pg_port_srv} user=dataglot dbname=pg");
    for i in 0..100 {
        if tokio_postgres::connect(&conn_str, NoTls).await.is_ok() {
            break;
        }
        assert!(i < 99, "server not ready");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let client = connect(pg_port_srv, "pg").await;

    let rows = client
        .query("SELECT id, email FROM pg.public.users ORDER BY id", &[])
        .await
        .expect("governed query executes distributed");
    let got: Vec<(i32, String)> = rows.iter().map(|r| (r.get(0), r.get(1))).collect();
    assert_eq!(
        got,
        vec![(2, "***@example.com".to_string())],
        "row filter keeps only Bob's row; mask hides the email — \
         plan-time policy must survive Ballista execution"
    );
}

// ---------------------------------------------------------------------------
// Bounded stress: the memory guardrail under concurrent distributed load
// (audit item: the OOM-kill scenario is config-guarded but was never
// exercised by an automated test).
// ---------------------------------------------------------------------------

/// Seed ~200k rows with a high-cardinality key so a hash aggregation
/// cannot fit a deliberately tiny memory pool.
fn seed_wide_table() -> (TempDir, String) {
    use datafusion::arrow::array::{Float64Array, Int64Array};

    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("wide.parquet");
    let schema = Arc::new(Schema::new(vec![
        Field::new("k", DataType::Int64, false),
        Field::new("v", DataType::Float64, false),
    ]));
    let n: i64 = 200_000;
    #[allow(clippy::cast_precision_loss)] // test data, exactness irrelevant
    let batch = RecordBatch::try_new(
        Arc::clone(&schema),
        vec![
            Arc::new(Int64Array::from_iter_values(0..n)),
            Arc::new(Float64Array::from_iter_values((0..n).map(|i| i as f64))),
        ],
    )
    .expect("build wide batch");
    let file = File::create(&path).expect("create parquet");
    let mut writer = ArrowWriter::try_new(file, schema, Some(WriterProperties::builder().build()))
        .expect("writer");
    writer.write(&batch).expect("write");
    writer.close().expect("close");
    let posix = path.display().to_string().replace('\\', "/");
    (tmp, format!("file:///{}", posix.trim_start_matches('/')))
}

///  #2 — nothing ever asserted that cancelling a pgwire query
/// actually cancels the distributed job. The silent failure mode is
/// orphaned Ballista jobs eating executor task slots until restart.
/// Contract pinned here: (a) the cancelled query returns to the client
/// promptly (no hang), (b) the connection/server stay usable, and
/// (c) the scheduler stops reporting the job as running.
#[test]
#[allow(clippy::too_many_lines)] // linear scenario: boot, cancel, three assertions
fn pgwire_cancel_aborts_the_distributed_job() {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(8)
        .thread_stack_size(64 * 1024 * 1024) // 
        .enable_all()
        .build()
        .expect("test runtime")
        .block_on(async {
            let _ = tracing_subscriber::fmt()
                .with_env_filter("info,dataglot_pgwire=debug,pgwire=debug,dataglot_ballista=debug")
                .try_init();
            let (tmp, url) = seed_wide_table();
            let pg_port = ephemeral_port();
            let rest_port = ephemeral_port();
            let config = ServerConfig {
                host: "127.0.0.1".to_string(),
                port: pg_port,
                observability: dataglot_server::observability::ObservabilityConfig {
                    metrics_addr: None,
                    ..Default::default()
                },
                default_catalog: "lake".to_string(),
                catalogs: std::collections::HashMap::from([(
                    "lake".to_string(),
                    CatalogConfig::ObjectStorage(ObjectStorageCatalogConfig {
                        s3: None,
                        tables: vec![ObjectStorageTableConfig {
                            name: "wide".to_string(),
                            url,
                            format: ObjectStorageFormat::Parquet,
                            schema: None,
                        }],
                    }),
                )]),
                ballista: Some(BallistaServerConfig {
                    standalone_parallelism: 2,
                    // REST API on: the test asserts scheduler-side job
                    // state after the cancel.
                    rest_api_port: Some(rest_port),
                    ..Default::default()
                }),
                ..ServerConfig::default()
            };
            let server = DataglotServer::new(config).await.expect("server boots");
            tokio::spawn(async move {
                server.run().await.expect("server runs");
            });
            let conn_str = format!("host=127.0.0.1 port={pg_port} user=dataglot dbname=lake");
            for i in 0..100 {
                if tokio_postgres::connect(&conn_str, NoTls).await.is_ok() {
                    break;
                }
                assert!(i < 99, "server not ready");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            let _ = tmp;
            let client = connect(pg_port, "lake").await;
            let cancel_token = client.cancel_token();

            // A query that cannot finish in test time (4x10^10 joined
            // rows) but must die promptly on cancel.
            let long_running = tokio::spawn(async move {
                client
                    .query(
                        "SELECT SUM(a.v * b.v) FROM lake.public.wide a                          CROSS JOIN lake.public.wide b",
                        &[],
                    )
                    .await
            });

            // Let it reach the executors, then cancel.
            tokio::time::sleep(Duration::from_secs(2)).await;
            cancel_token
                .cancel_query(NoTls)
                .await
                .expect("cancel request sends");

            // (a) The client gets control back promptly, with an error.
            let outcome = tokio::time::timeout(Duration::from_secs(30), long_running)
                .await
                .expect("cancelled query must return within 30s, not hang")
                .expect("query task joins");
            let err = outcome.expect_err("cancelled query must error, not succeed");
            // Exact wording varies by layer (pgwire "canceling statement"
            // vs a stream-abort surfaced as ERROR) — pin only that a
            // diagnosable error reaches the client.
            let msg = err.to_string();
            assert!(!msg.trim().is_empty(), "error surface must be diagnosable");

            // (b) The server stays fully usable.
            let fresh = connect(pg_port, "lake").await;
            let rows = fresh.query("SELECT 1", &[]).await.expect("server usable");
            assert_eq!(rows.len(), 1);

            // (c) The scheduler stops reporting the job as running —
            // 's CancelOnDropExec fires CancelJob when the
            // abandoned stream drops, so the job must reach a terminal
            // state instead of orphaning executor slots.
            let http = reqwest::Client::new();
            let mut still_running = usize::MAX;
            for _ in 0..30 {
                let jobs: serde_json::Value = http
                    .get(format!("http://127.0.0.1:{rest_port}/api/jobs"))
                    .send()
                    .await
                    .expect("scheduler REST answers")
                    .json()
                    .await
                    .expect("jobs JSON");
                let list = jobs["jobs"]
                    .as_array()
                    .cloned()
                    .or_else(|| jobs.as_array().cloned())
                    .unwrap_or_default();
                still_running = list
                    .iter()
                    .filter(|j| {
                        j["status"].as_str().unwrap_or("") == "Running"
                            || j["job_status"].as_str().unwrap_or("").starts_with("Running")
                    })
                    .count();
                if still_running == 0 {
                    break;
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            assert_eq!(
                still_running, 0,
                "cancelled job still Running on the scheduler 30s after the \
                 client cancel — CancelOnDropExec did not fire"
            );
        });
}

///  — JDBC's `DatabaseMetaData` (DBeaver / DataGrip / Metabase
/// schema browsers) issues `pg_catalog` queries; those virtual
/// providers can't serialize for Ballista, so on a distributed server
/// every introspection call failed with "failed to serialize logical
/// plan". `LocalMetadataQueryPlanner` plans them in-process instead —
/// this pins that an explicit `pg_catalog` query works over pgwire on a
/// distributed server.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pg_catalog_introspection_works_on_a_distributed_server() {
    let (pg_port, _tmp) = boot_distributed_server().await;
    let client = connect(pg_port, "lake").await;
    let rows = client
        .query(
            "SELECT relname FROM pg_catalog.pg_class WHERE relkind = 'r' LIMIT 5",
            &[],
        )
        .await
        .expect("pg_catalog query plans locally and executes");
    // Content varies with the catalog emulation; the pin is that it
    // executes rather than failing at plan serialization.
    let _ = rows;
}

///  — CI's biggest distributed result set was 5 rows, so no test
/// ever crossed a batch boundary (`batch_size` = 8192): the class of
/// bug that truncates, duplicates, or reorders batches at the
/// shuffle→pgwire seam was invisible. Stream all 200k rows through the
/// full pgwire→cluster path and assert exact cardinality + a value
/// checksum (sum of a 0..n key — any dropped/duplicated batch breaks it).
#[test]
fn streaming_result_crosses_batch_boundaries_distributed() {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(8)
        .thread_stack_size(64 * 1024 * 1024) //
        .enable_all()
        .build()
        .expect("test runtime")
        .block_on(async {
            let (tmp, url) = seed_wide_table();
            let pg_port = ephemeral_port();
            let config = ServerConfig {
                host: "127.0.0.1".to_string(),
                port: pg_port,
                observability: dataglot_server::observability::ObservabilityConfig {
                    metrics_addr: None,
                    ..Default::default()
                },
                default_catalog: "lake".to_string(),
                catalogs: std::collections::HashMap::from([(
                    "lake".to_string(),
                    CatalogConfig::ObjectStorage(ObjectStorageCatalogConfig {
                        s3: None,
                        tables: vec![ObjectStorageTableConfig {
                            name: "wide".to_string(),
                            url,
                            format: ObjectStorageFormat::Parquet,
                            schema: None,
                        }],
                    }),
                )]),
                ballista: Some(BallistaServerConfig {
                    standalone_parallelism: 2,
                    rest_api_port: None,
                    ..Default::default()
                }),
                ..ServerConfig::default()
            };
            let server = DataglotServer::new(config).await.expect("server boots");
            tokio::spawn(async move {
                server.run().await.expect("server runs");
            });
            let conn_str = format!("host=127.0.0.1 port={pg_port} user=dataglot dbname=lake");
            for i in 0..100 {
                if tokio_postgres::connect(&conn_str, NoTls).await.is_ok() {
                    break;
                }
                assert!(i < 99, "server not ready");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            let _ = tmp;
            let client = connect(pg_port, "lake").await;

            let rows = client
                .query("SELECT k FROM lake.public.wide", &[])
                .await
                .expect("full-table streaming select succeeds");
            let n: i64 = 200_000;
            assert_eq!(
                rows.len(),
                usize::try_from(n).unwrap(),
                "exact cardinality across ~24 batch boundaries"
            );
            // Checksum: k is exactly 0..n, so Σk = n(n-1)/2. A dropped,
            // duplicated, or corrupted batch cannot preserve both the
            // count and this sum.
            let sum: i64 = rows.iter().map(|r| r.get::<_, i64>(0)).sum();
            assert_eq!(sum, n * (n - 1) / 2, "value checksum across batches");
        });
}

/// Under a deliberately tiny memory pool, concurrent memory-hungry
/// distributed aggregations must **either succeed (spill) or fail with a
/// typed memory/resources error — and the server must survive**. The
/// unguarded failure mode was the OS killing the whole process (found
/// live during the SF10 stress;  added the pool, this automates
/// the survival contract on the distributed path).
#[test]
fn memory_guardrail_survives_concurrent_distributed_load() {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(8)
        .thread_stack_size(64 * 1024 * 1024) //
        .enable_all()
        .build()
        .expect("test runtime")
        .block_on(async {
            let (tmp, url) = seed_wide_table();
            let pg_port = ephemeral_port();
            let config = ServerConfig {
                host: "127.0.0.1".to_string(),
                port: pg_port,
                observability: dataglot_server::observability::ObservabilityConfig {
                    metrics_addr: None,
                    ..Default::default()
                },
                // Tiny pool: a 200k-key hash aggregation cannot fit; the
                // fair-spill pool must spill or err — never OOM the process.
                memory_limit_bytes: Some(4 * 1024 * 1024),
                default_catalog: "lake".to_string(),
                catalogs: std::collections::HashMap::from([(
                    "lake".to_string(),
                    CatalogConfig::ObjectStorage(ObjectStorageCatalogConfig {
                        s3: None,
                        tables: vec![ObjectStorageTableConfig {
                            name: "wide".to_string(),
                            url,
                            format: ObjectStorageFormat::Parquet,
                            schema: None,
                        }],
                    }),
                )]),
                ballista: Some(BallistaServerConfig {
                    standalone_parallelism: 2,
                    rest_api_port: None,
                    ..Default::default()
                }),
                ..ServerConfig::default()
            };
            let server = DataglotServer::new(config).await.expect("server boots");
            tokio::spawn(async move {
                server.run().await.expect("server runs");
            });
            let conn_str = format!("host=127.0.0.1 port={pg_port} user=dataglot dbname=lake");
            for i in 0..100 {
                if tokio_postgres::connect(&conn_str, NoTls).await.is_ok() {
                    break;
                }
                assert!(i < 99, "server not ready");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            let _ = tmp;

            // Three concurrent memory-hungry aggregations.
            let mut tasks = Vec::new();
            for i in 0..3 {
                let conn_str = conn_str.clone();
                tasks.push(tokio::spawn(async move {
                    let (client, conn) = tokio_postgres::connect(&conn_str, NoTls)
                        .await
                        .unwrap_or_else(|e| panic!("client {i} connect: {e}"));
                    tokio::spawn(async move {
                        let _ = conn.await;
                    });
                    let res = client
                        .query(
                            "SELECT k, COUNT(*) AS c, SUM(v) AS s, AVG(v) AS a \
                             FROM lake.public.wide GROUP BY k ORDER BY s DESC LIMIT 5",
                            &[],
                        )
                        .await;
                    match res {
                        Ok(rows) => assert_eq!(rows.len(), 5, "client {i}: spilled run correct"),
                        Err(e) => {
                            let msg = e.to_string().to_ascii_lowercase();
                            assert!(
                                msg.contains("resources exhausted")
                                    || msg.contains("memory")
                                    || msg.contains("failed to allocate"),
                                "client {i}: only a typed memory error is acceptable, got: {msg}"
                            );
                        }
                    }
                }));
            }
            for t in tasks {
                t.await.expect("stress client join");
            }

            // THE contract: the server survived and still answers.
            let client = connect(pg_port, "lake").await;
            let row = client
                .query_one("SELECT 1 AS alive", &[])
                .await
                .expect("server must survive the memory-pressure barrage");
            let alive: i64 = row.get("alive");
            assert_eq!(alive, 1);
        });
}

/// ** distributed pin (end-to-end).** With the server built
/// `--features adbc`, an adbc catalog now **distributes**: querying its
/// table over a distributed (standalone-parallelism) server fans the
/// federated fragment out and returns real rows, instead of the old
///  "not available in distributed mode" capability-boundary error.
/// The connector is wired into the distributed codec registry
/// (`registry_sql_kind` → `RegistrySqlKind::Adbc`), so encode/decode
/// round-trips the adbc source like Postgres/MySQL/Snowflake.
///
/// (Direct-`TableProvider` sources — OData/SAP/REST — still single-node.)
///
/// Gated on the server's `adbc` feature plus `ADBC_DRIVER_DUCKDB_PATH`
/// (skips when unset — `.github/scripts/download-duckdb-adbc-driver.sh`
/// provisions it; the ballista CI job runs it explicitly).
#[cfg(feature = "adbc")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::too_many_lines)] // linear e2e: seed + boot + connect + assert reads best inline
async fn distributed_adbc_query_succeeds_when_built_with_the_feature() {
    use adbc_core::options::{AdbcVersion, OptionDatabase, OptionValue};
    use adbc_core::{Connection as _, Database as _, Driver as _, Statement as _};
    use dataglot_server::config::AdbcCatalogConfig;

    let Ok(driver_path) = std::env::var("ADBC_DRIVER_DUCKDB_PATH") else {
        eprintln!(
            "skipping: ADBC_DRIVER_DUCKDB_PATH is not set \
             (run .github/scripts/download-duckdb-adbc-driver.sh)"
        );
        return;
    };
    if driver_path.is_empty() {
        return;
    }

    // Seed a DuckDB fixture through the raw driver, then drop every
    // handle so the server's connector gets the file to itself.
    let tmp = TempDir::new().expect("tempdir");
    let db_file = tmp.path().join("distributed.duckdb");
    let db_file = db_file.to_str().expect("utf8 temp path").to_string();
    {
        let mut raw = adbc_driver_manager::ManagedDriver::load_dynamic_from_filename(
            &driver_path,
            Some(b"duckdb_adbc_init"),
            AdbcVersion::V110,
        )
        .expect("duckdb adbc driver loads");
        let database = raw
            .new_database_with_opts(vec![(
                OptionDatabase::Other("path".to_string()),
                OptionValue::String(db_file.clone()),
            )])
            .expect("duckdb database opens");
        let mut conn = database.new_connection().expect("duckdb connection opens");
        let mut stmt = conn.new_statement().expect("statement allocates");
        stmt.set_sql_query(
            "CREATE TABLE customer_ltv (user_id INTEGER, segment VARCHAR, ltv DOUBLE)",
        )
        .expect("sql sets");
        stmt.execute_update().expect("seed runs");
        // Seed rows so the distributed COUNT(*) proves data actually flows
        // back through the fan-out, not just that the plan encoded.
        let mut ins = conn.new_statement().expect("insert statement allocates");
        ins.set_sql_query("INSERT INTO customer_ltv VALUES (1,'A',10.0),(2,'B',20.0),(3,'A',30.0)")
            .expect("insert sql sets");
        ins.execute_update().expect("seed insert runs");
    }

    // Distributed server with the adbc catalog registered.
    let pg_port = ephemeral_port();
    let config = ServerConfig {
        host: "127.0.0.1".to_string(),
        port: pg_port,
        observability: dataglot_server::observability::ObservabilityConfig {
            metrics_addr: None,
            ..Default::default()
        },
        default_catalog: "byoduck".to_string(),
        default_schema: "main".to_string(),
        catalogs: std::collections::HashMap::from([(
            "byoduck".to_string(),
            CatalogConfig::Adbc(AdbcCatalogConfig {
                driver_path: driver_path.clone(),
                driver_entrypoint: Some("duckdb_adbc_init".to_string()),
                uri: None,
                username: None,
                password_env: None,
                driver_options: Some(format!("path={db_file}")),
                catalog: None,
                schema: None,
                dialect: "duckdb".to_string(),
                connection_pool_size: 2,
                connection_pool_min_idle: 1,
            }),
        )]),
        ballista: Some(BallistaServerConfig {
            standalone_parallelism: 2,
            rest_api_port: None,
            ..Default::default()
        }),
        ..ServerConfig::default()
    };
    let server = DataglotServer::new(config)
        .await
        .expect("distributed server with an adbc catalog boots");
    tokio::spawn(async move {
        server.run().await.expect("server runs");
    });
    let conn_str = format!("host=127.0.0.1 port={pg_port} user=dataglot dbname=byoduck");
    let mut ready = false;
    for _ in 0..100 {
        if tokio_postgres::connect(&conn_str, NoTls).await.is_ok() {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(ready, "distributed adbc server did not become ready");
    let client = connect(pg_port, "byoduck").await;

    // The adbc-backed table now distributes: the COUNT(*) fans out and
    // comes back with the seeded cardinality (3), not the  error.
    let rows = client
        .query("SELECT COUNT(*) AS n FROM byoduck.main.customer_ltv", &[])
        .await
        .expect("adbc table distributes when the server is built --features adbc");
    assert_eq!(rows.len(), 1, "COUNT(*) returns one row");
    let n: i64 = rows[0].get("n");
    assert_eq!(n, 3, "distributed adbc scan returns the seeded row count");

    // A filtered aggregate exercises predicate pushdown through the
    // distributed adbc fragment too.
    let rows = client
        .query(
            "SELECT COUNT(*) AS n FROM byoduck.main.customer_ltv WHERE segment = 'A'",
            &[],
        )
        .await
        .expect("filtered adbc aggregate distributes");
    let n: i64 = rows[0].get("n");
    assert_eq!(n, 2, "two rows have segment = 'A'");
}

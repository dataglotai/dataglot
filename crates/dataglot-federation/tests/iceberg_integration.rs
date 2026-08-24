//! Integration tests for the warehouse (Iceberg-backed) connector.
//!
//! # Two flavours of integration test
//!
//! This file hosts **two** flavours of integration test for
//! [`WarehouseConnector`], deliberately kept side-by-side:
//!
//! 1. **In-memory catalog** (the original tests, run on every `cargo
//!    test`). They use [`iceberg::memory::MemoryCatalog`] with a temp
//!    warehouse on the local filesystem. They prove the lazy-schema-
//!    resolution and `CatalogProvider` wiring without paying the cost
//!    of a Docker stack — fast, deterministic, and useful as smoke
//!    tests on every commit.
//!
//! 2. **Real Lakekeeper + `MinIO` + Postgres stack** (the
//!    `lakekeeper_*` tests, gated by `#[ignore = "requires Docker"]`).
//!    These exercise the production REST + S3 path:
//!    [`WarehouseConnector::connect`] talks to a real
//!    `iceberg-catalog-rest` server, parquet is written and read
//!    against `MinIO` over the S3 API, and snapshot commits go through
//!    Lakekeeper's metadata backend (Postgres). This is what the
//!    Phase 0 strategy doc means by "warehouse via Lakekeeper REST
//!    catalog".
//!
//! Both flavours coexist on purpose: the in-memory tests run cheaply
//! in CI, while the Lakekeeper tests run on demand (Docker required)
//! and prove the bootstrap works end-to-end.

#![cfg(feature = "iceberg")]

use std::collections::HashMap;
use std::sync::Arc;

use datafusion::arrow::array::RecordBatch;
use datafusion::arrow::util::pretty::pretty_format_batches;
use datafusion::prelude::SessionContext;
use dataglot_federation::iceberg::WarehouseConnector;
use iceberg::io::LocalFsStorageFactory;
use iceberg::memory::{MemoryCatalogBuilder, MEMORY_CATALOG_WAREHOUSE};
use iceberg::spec::{NestedField, PrimitiveType, Schema, Type};
use iceberg::{Catalog, CatalogBuilder, NamespaceIdent, TableCreation};
use tempfile::TempDir;

/// Build a single-namespace warehouse with one empty table called
/// `sales.orders`. Returns a `WarehouseConnector` over the catalog and
/// the temp dir whose lifetime keeps the warehouse files on disk.
async fn setup_warehouse() -> (WarehouseConnector, TempDir) {
    let warehouse_dir = TempDir::new().expect("temp dir");
    let warehouse_path = warehouse_dir
        .path()
        .to_str()
        .expect("warehouse path must be utf-8")
        .to_string();

    let catalog = MemoryCatalogBuilder::default()
        .with_storage_factory(Arc::new(LocalFsStorageFactory))
        .load(
            "warehouse",
            HashMap::from([(MEMORY_CATALOG_WAREHOUSE.to_string(), warehouse_path)]),
        )
        .await
        .expect("memory catalog loads");

    let namespace = NamespaceIdent::new("sales".to_string());
    catalog
        .create_namespace(&namespace, HashMap::new())
        .await
        .expect("namespace creates");

    // Build a minimal but realistic schema. `id` and `amount` matches
    // the Phase 0 exit-criteria query
    // `JOIN warehouse.sales.orders w USING (id) ... w.amount`.
    let schema = Schema::builder()
        .with_schema_id(0)
        .with_fields(vec![
            NestedField::required(1, "id", Type::Primitive(PrimitiveType::Int)).into(),
            NestedField::required(2, "amount", Type::Primitive(PrimitiveType::Long)).into(),
        ])
        .build()
        .expect("schema builds");

    let creation = TableCreation::builder()
        .name("orders".to_string())
        .schema(schema)
        .properties(HashMap::new())
        .build();

    catalog
        .create_table(&namespace, creation)
        .await
        .expect("table creates");

    let catalog: Arc<dyn Catalog> = Arc::new(catalog);
    let connector = WarehouseConnector::__from_catalog_for_tests("warehouse", catalog);

    (connector, warehouse_dir)
}

/// `WarehouseConnector::table_provider("sales", "orders")` resolves
/// the table and the resulting provider's Arrow schema matches what we
/// declared on creation.
///
/// This is the load-bearing test for the Phase 0 exit criterion's
/// warehouse half: it proves `warehouse.<namespace>.<table>` resolves
/// to a working `DataFusion` provider. Data writing is deferred (see the
/// module docstring) but the schema and the SELECT-* path go through
/// `iceberg-datafusion` end-to-end.
#[tokio::test]
async fn warehouse_table_resolves_with_lazy_schema() {
    let (connector, _warehouse_dir) = setup_warehouse().await;

    let provider = connector
        .table_provider("sales", "orders")
        .await
        .expect("table_provider resolves");

    // Schema must reflect the declared fields. iceberg-rust converts
    // its int -> Arrow Int32, long -> Int64.
    let schema = provider.schema();
    assert_eq!(
        schema.fields().len(),
        2,
        "expected 2 fields, got: {schema:?}"
    );
    assert_eq!(schema.field(0).name(), "id");
    assert_eq!(
        schema.field(0).data_type(),
        &datafusion::arrow::datatypes::DataType::Int32,
        "id should map to Int32"
    );
    assert_eq!(schema.field(1).name(), "amount");
    assert_eq!(
        schema.field(1).data_type(),
        &datafusion::arrow::datatypes::DataType::Int64,
        "amount should map to Int64"
    );
}

/// Plug the warehouse provider into a `DataFusion` `SessionContext` and
/// run a `SELECT *`. The table is empty (no parquet files written —
/// see module docstring); the assertion is therefore "0 rows, no
/// error" — which is non-trivial: it exercises the full
/// `iceberg-datafusion` scan pipeline (manifest list read, snapshot
/// resolution, empty-file-set handling).
#[tokio::test]
async fn warehouse_table_scans_via_datafusion() {
    let (connector, _warehouse_dir) = setup_warehouse().await;

    let provider = connector
        .table_provider("sales", "orders")
        .await
        .expect("table_provider resolves");

    let ctx = SessionContext::new();
    ctx.register_table("orders", provider)
        .expect("register orders table");

    let df = ctx
        .sql("SELECT id, amount FROM orders")
        .await
        .expect("plan SELECT");
    let batches: Vec<RecordBatch> = df.collect().await.expect("execute SELECT");

    let total: usize = batches.iter().map(RecordBatch::num_rows).sum();
    assert_eq!(
        total,
        0,
        "fresh table should be empty, got:\n{}",
        pretty_format_batches(&batches).expect("format batches")
    );
}

/// `table_provider` for a non-existent table errors cleanly. This is
/// the rule-13 negative: the connector did NOT pre-fetch every table
/// at construction time, so a missing table only fails when actually
/// asked for.
#[tokio::test]
async fn warehouse_missing_table_errors() {
    let (connector, _warehouse_dir) = setup_warehouse().await;

    let err = connector
        .table_provider("sales", "does_not_exist")
        .await
        .expect_err("missing table should error");

    let msg = err.to_string();
    // The message must include the qualified name so operators can
    // diagnose. It must NOT say "Iceberg" (rule 7).
    assert!(
        msg.contains("sales.does_not_exist"),
        "expected qualified name in error, got: {msg}"
    );
    let lower = msg.to_lowercase();
    assert!(
        !lower.contains("iceberg"),
        "rule 7: error message must not mention Iceberg, got: {msg}"
    );
}

/// End-to-end: register the warehouse connector as a `DataFusion`
/// `CatalogProvider` and run a three-part-name `SELECT` against it.
///
/// Future `dataglot-server` PR will call
/// `WarehouseConnector::as_catalog_provider()` and
/// `ctx.register_catalog("warehouse", ...)`. This test pins that path
/// down end-to-end:
///
/// * `as_catalog_provider().await` builds without error,
/// * `schema_names()` surfaces the seeded `sales` namespace,
/// * `ctx.register_catalog("warehouse", catalog)` accepts it,
/// * `SELECT * FROM warehouse.sales.orders` resolves through three-
///   part naming and runs the full `iceberg-datafusion` scan path
///   (an empty-table scan, just like
///   `warehouse_table_scans_via_datafusion`).
#[tokio::test]
async fn warehouse_catalog_provider_three_part_name_select() {
    let (connector, _warehouse_dir) = setup_warehouse().await;
    let connector = Arc::new(connector);

    let catalog = connector
        .as_catalog_provider()
        .await
        .expect("catalog provider builds");

    // The seeded namespace must appear; nothing else does (the in-
    // memory catalog only has `sales`).
    let names = catalog.schema_names();
    assert!(
        names.iter().any(|n| n == "sales"),
        "expected `sales` in schema_names, got: {names:?}"
    );

    let ctx = SessionContext::new();
    ctx.register_catalog("warehouse", catalog);

    // Three-part name resolves: warehouse -> CatalogProvider,
    // sales -> SchemaProvider, orders -> TableProvider via the lazy
    // metadata fetch in `WarehouseConnector::table_provider`.
    let df = ctx
        .sql("SELECT id, amount FROM warehouse.sales.orders")
        .await
        .expect("three-part-name SQL parses and plans");
    let batches: Vec<RecordBatch> = df.collect().await.expect("execute SELECT");

    let total: usize = batches.iter().map(RecordBatch::num_rows).sum();
    assert_eq!(
        total,
        0,
        "fresh table should be empty, got:\n{}",
        pretty_format_batches(&batches).expect("format batches")
    );
}

/// `Debug` output of the connector must not leak the inner catalog
/// representation (rule 12 belt-and-braces). The unit test in the
/// crate proves this for the `<redacted>` placeholder; this end-to-end
/// test pins down the same behaviour against a *fully-constructed*
/// connector built via the integration setup.
#[tokio::test]
async fn warehouse_debug_does_not_leak_catalog() {
    let (connector, _warehouse_dir) = setup_warehouse().await;
    let s = format!("{connector:?}");
    assert!(
        !s.contains("MemoryCatalog"),
        "Debug leaked the inner catalog: {s}"
    );
    assert!(s.contains("<redacted>"), "Debug missing redaction: {s}");
    assert!(s.contains("warehouse"), "Debug missing connector name: {s}");
}

// ---------------------------------------------------------------------------
// Lakekeeper-backed integration tests
// ---------------------------------------------------------------------------
//
// Everything below this line stands up a real three-container stack
// (Postgres metadata + MinIO object store + Lakekeeper REST catalog) and
// drives `WarehouseConnector` against it. All four tests share one
// helper, [`lakekeeper::setup_lakekeeper_stack`], which is the load-
// bearing piece of code in this module. It boots the containers, waits
// for them to become ready, bootstraps Lakekeeper, and creates a
// warehouse pointing at MinIO. The tests then carve out their own
// namespaces/tables on top so they don't interfere.
//
// These tests are gated `#[ignore = "requires Docker"]` and so do not
// run on every `cargo test`. Run them with:
//   cargo test --features iceberg -p dataglot-federation \
//       --test iceberg_integration -- --ignored --nocapture
mod lakekeeper {
    use super::{
        Arc, Catalog, HashMap, NamespaceIdent, RecordBatch, SessionContext, TableCreation,
        WarehouseConnector,
    };
    use std::time::Duration;

    use datafusion::arrow::array::{Int32Array, Int64Array};
    use datafusion::arrow::datatypes::{DataType, Field, Schema as ArrowSchema};
    use datafusion::arrow::util::pretty::pretty_format_batches;
    use dataglot_federation::iceberg::{WarehouseConfig, WarehouseCredentials};
    use iceberg::spec::{NestedField, PrimitiveType, Schema as IcebergSchema, Type};
    use iceberg::transaction::{ApplyTransactionAction, Transaction};
    use iceberg::writer::base_writer::data_file_writer::DataFileWriterBuilder;
    use iceberg::writer::file_writer::location_generator::{
        DefaultFileNameGenerator, DefaultLocationGenerator,
    };
    use iceberg::writer::file_writer::rolling_writer::RollingFileWriterBuilder;
    use iceberg::writer::file_writer::ParquetWriterBuilder;
    use iceberg::writer::{IcebergWriter, IcebergWriterBuilder};
    use parquet::arrow::PARQUET_FIELD_ID_META_KEY;
    use parquet::file::properties::WriterProperties;
    use serde_json::json;
    use testcontainers::core::{IntoContainerPort, WaitFor};
    use testcontainers::runners::AsyncRunner;
    use testcontainers::{ContainerAsync, GenericImage, ImageExt};
    use testcontainers_modules::minio::MinIO;
    use testcontainers_modules::postgres::Postgres;

    /// Lakekeeper image. Pinned to a specific tag — `latest` and
    /// `latest-main` move and would silently break the tests across
    /// CI runs.
    ///
    /// Bumped from v0.5.2 → v0.6.0 in  follow-up:
    /// `dataglot-tests::e2e::phase0_gate_lakekeeper` ran the same
    /// fixture without the `--skip lakekeeper::*` workaround that
    /// hides the bug here, and CI confirmed v0.5.2's `migrate`
    /// subcommand silently no-ops the database half — `migrate`
    /// prints "Authorizer migration complete" + "Migrating database..."
    /// and exits with `information_schema.tables` empty in the
    /// public schema (run 25187039977). v0.6.0 is expected to have
    /// the fix; if its `/management/v1` body shape has drifted, the
    /// `bootstrap` / `warehouse_create` JSON below may need to be
    /// updated. Keep both copies of this fixture in lock-step.
    ///
    /// See <https://github.com/lakekeeper/lakekeeper/releases>.
    const LAKEKEEPER_IMAGE: &str = "quay.io/lakekeeper/catalog";
    const LAKEKEEPER_TAG: &str = "v0.12.3";

    /// Image tag used for the bucket-creation sidecar. `mc` (the `MinIO`
    /// client) is small (~30 MB) and its `mb` subcommand is the
    /// least-friction way to create a bucket on a freshly-booted `MinIO`
    /// instance. Pinned for reproducibility.
    const MC_IMAGE: &str = "minio/mc";
    const MC_TAG: &str = "RELEASE.2025-02-21T16-00-46Z";

    /// `MinIO` default credentials. These are not secrets — they're the
    /// vendor-default sentinel values for a fresh `MinIO` container.
    const MINIO_ACCESS_KEY: &str = "minioadmin";
    const MINIO_SECRET_KEY: &str = "minioadmin";

    /// The S3 bucket that backs the Lakekeeper warehouse. Created
    /// during stack setup. Lakekeeper itself does not auto-create
    /// buckets, so we have to do it before the warehouse-create call.
    const WAREHOUSE_BUCKET: &str = "warehouse-bucket";

    /// Logical warehouse name registered with Lakekeeper. The
    /// `WarehouseConnector::connect` call uses this as its
    /// `warehouse` config field.
    const WAREHOUSE_NAME: &str = "main";

    /// Port Lakekeeper listens on inside the container. Mapped to a
    /// random host port for `WarehouseConnector::connect`.
    const LAKEKEEPER_PORT: u16 = 8181;

    /// Owns the running stack for the lifetime of a test. Drop order
    /// (Lakekeeper first, then `MinIO`, then Postgres) does not matter
    /// — Docker tears them down concurrently — but holding all three
    /// here ensures none drops prematurely.
    ///
    /// The leading `_` on the container fields suppresses the unused-
    /// field warning while still keeping the containers alive: the
    /// Drop impl on `ContainerAsync` is what stops the containers, so
    /// the field merely has to exist for the duration of the test.
    pub(super) struct LakekeeperStack {
        _postgres: ContainerAsync<Postgres>,
        _minio: ContainerAsync<MinIO>,
        _lakekeeper: ContainerAsync<GenericImage>,
        /// Base URL for Lakekeeper's Iceberg REST catalog API
        /// (`/catalog`). This is what `WarehouseConnector::connect`
        /// expects as its `catalog_url` field.
        pub catalog_url: String,
        /// Logical warehouse name registered with Lakekeeper.
        pub warehouse_name: String,
        /// Public S3 endpoint URL for `MinIO`, as the Iceberg client
        /// running on the **host** sees it. Used inside
        /// `WarehouseConfig::s3_endpoint` so that parquet reads from
        /// the test process can reach the same blobs Lakekeeper
        /// committed.
        pub s3_endpoint_host: String,
        /// Static S3 credentials for the bucket. Declared `Static`
        /// rather than `Environment` so we don't pollute the
        /// `AWS_*` env vars of whatever process is running the test.
        pub s3_credentials: WarehouseCredentials,
        /// Network name the containers were attached to. Held but
        /// not read by any current test — kept on the struct so a
        /// future test that needs to spin up an extra container on
        /// the same network has a stable handle.
        #[allow(dead_code)]
        pub network_name: String,
    }

    /// Boot the three-container Lakekeeper stack.
    ///
    /// Returns once Lakekeeper is bootstrapped and the warehouse is
    /// created; from that point on
    /// `WarehouseConnector::connect("warehouse", config_with(stack))`
    /// is expected to succeed. Panics with a clear message if any
    /// step fails — these tests are never run silently in CI.
    ///
    /// The function is over the default clippy line budget but the
    /// steps (network, postgres, minio, bucket, lakekeeper, wait,
    /// bootstrap, warehouse) are tightly sequenced and easier to
    /// follow inline than split across helpers; opting out.
    #[allow(clippy::too_many_lines)]
    pub(super) async fn setup_lakekeeper_stack() -> LakekeeperStack {
        // Unique per-call network name. Multiple invocations of this
        // helper (e.g. parallel `--ignored` runs in different test
        // binaries) get isolated networks. Within a single test
        // binary, callers should share the stack via `OnceCell` to
        // amortise the ~30-60s boot cost.
        // Per-test unique suffix for both the Docker network and every
        // container name, so concurrent test runs don't collide on the
        // shared Docker daemon. cargo runs integration tests in parallel
        // by default; without unique names we hit 409 Conflict.
        //
        // Nanos alone is not sufficient — two tests can enter this
        // function within the same nanosecond on macOS (observed at
        // ~10ns clock granularity). Combine an atomic counter with
        // nanos for robust within-process uniqueness, and process id
        // for across-binary uniqueness.
        static TEST_INSTANCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let instance = TEST_INSTANCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let suffix = format!("{pid}-{instance}-{nanos}");
        let network_name = format!("lakekeeper-it-{suffix}");
        let pg_hostname = format!("lakekeeper-pg-{suffix}");
        let minio_hostname = format!("lakekeeper-minio-{suffix}");
        let lakekeeper_hostname = format!("lakekeeper-{suffix}");

        // 1. Postgres — Lakekeeper's metadata backend. We use the
        //    testcontainers-modules image and override its hostname
        //    so the Lakekeeper container can reach it by name.
        // `testcontainers-modules` 0.15 defaults `Postgres` to image
        // `postgres:11-alpine`. Lakekeeper 0.6.0's migration SQL uses the
        // `deterministic` collation attribute, added in Postgres 12 —
        // running against PG11 fails with `collation attribute
        // "deterministic" not recognized`. Pin a PG12+ tag.
        let postgres = Postgres::default()
            .with_db_name("lakekeeper")
            .with_user("lakekeeper")
            .with_password("lakekeeper")
            .with_tag("16-alpine")
            .with_network(&network_name)
            .with_container_name(pg_hostname.clone())
            .with_hostname(pg_hostname.clone())
            .start()
            .await
            .expect("postgres container starts");

        // 2. MinIO — S3-compatible object store. The default
        //    credentials are minioadmin/minioadmin. We expose port
        //    9000 to the host so the test process (running outside
        //    Docker) can also read parquet files committed by
        //    Lakekeeper.
        let minio = MinIO::default()
            .with_network(&network_name)
            .with_container_name(minio_hostname.clone())
            .with_hostname(minio_hostname.clone())
            .start()
            .await
            .expect("minio container starts");
        let minio_host = minio.get_host().await.expect("minio host resolves");
        let minio_host_port = minio
            .get_host_port_ipv4(9000)
            .await
            .expect("minio port resolves");
        let s3_endpoint_host = format!("http://{minio_host}:{minio_host_port}");

        // 3. Pre-create the bucket. Lakekeeper does NOT auto-create
        //    buckets — the warehouse-create call will fail with a
        //    400 if the bucket isn't already there. We use a one-
        //    shot `mc` (MinIO client) container on the same Docker
        //    network: simpler and lighter than pulling in
        //    aws-sdk-s3 just to issue one PutBucket request.
        create_bucket_via_mc(&network_name, &minio_hostname).await;

        // 4a. Run Lakekeeper PG migrations as a one-shot.
        //     v0.5.2 does NOT auto-migrate on `serve` (we tried
        //     LAKEKEEPER__PG_RUN_MIGRATIONS=true and it was ignored —
        //     the serve process panicked with `relation "server" does
        //     not exist`). Run `lakekeeper migrate` to completion
        //     against the same Postgres instance, then start serve.
        run_lakekeeper_migrations(&network_name, &pg_hostname).await;

        // 4b. Lakekeeper itself. Talks to Postgres for metadata and
        //     to MinIO for warehouse storage; both are addressed by
        //     container hostname (NOT the host-published port).
        //
        //     The wait condition matches a substring printed by
        //     Lakekeeper once its HTTP server is up. It's a
        //     string match rather than an HTTP probe because
        //     `testcontainers` natively supports log-substring
        //     waiting and that's the most robust signal across
        //     Lakekeeper versions.
        let lakekeeper_image = GenericImage::new(LAKEKEEPER_IMAGE, LAKEKEEPER_TAG)
            .with_exposed_port(LAKEKEEPER_PORT.tcp())
            // Lakekeeper v0.5.2 prints "Starting server on 0.0.0.0:8181..."
            // (no "Listening on" message). The /health probe below
            // catches actual readiness; this is just the "process
            // hasn't crashed yet" gate so testcontainers releases.
            .with_wait_for(WaitFor::message_on_stdout("Starting server on"))
            .with_cmd(["serve"])
            .with_network(&network_name)
            .with_container_name(lakekeeper_hostname.clone())
            .with_hostname(lakekeeper_hostname.clone())
            .with_env_var(
                "LAKEKEEPER__PG_DATABASE_URL_READ",
                format!("postgres://lakekeeper:lakekeeper@{pg_hostname}:5432/lakekeeper"),
            )
            .with_env_var(
                "LAKEKEEPER__PG_DATABASE_URL_WRITE",
                format!("postgres://lakekeeper:lakekeeper@{pg_hostname}:5432/lakekeeper"),
            )
            .with_env_var("LAKEKEEPER__PG_ENCRYPTION_KEY", "test-encryption-key")
            .with_env_var("LAKEKEEPER__BIND_IP", "0.0.0.0")
            .with_env_var("LAKEKEEPER__LISTEN_PORT", LAKEKEEPER_PORT.to_string())
            .with_env_var("LAKEKEEPER__LOG_LEVEL", "info");

        let lakekeeper = lakekeeper_image
            .start()
            .await
            .expect("lakekeeper container starts");

        // Run pg migrations before serving. We attempt this once via
        // a separate exec; failure here is non-fatal because some
        // builds run migrations as part of `serve`.
        let lakekeeper_host = lakekeeper
            .get_host()
            .await
            .expect("lakekeeper host resolves");
        let lakekeeper_host_port = lakekeeper
            .get_host_port_ipv4(LAKEKEEPER_PORT)
            .await
            .expect("lakekeeper port resolves");
        let lakekeeper_base = format!("http://{lakekeeper_host}:{lakekeeper_host_port}");

        // Wait for Lakekeeper's HTTP API to actually answer. The log
        // wait above is necessary but not sufficient: the listener may
        // be open while migrations are still running, and Lakekeeper's
        // health-endpoint path varies by version. Try several known
        // candidates; first 2xx wins. On total failure, dump the
        // container's stdout so we can see what Lakekeeper printed
        // before timing out — without that the failure surface is just
        // a timeout string with no diagnostic info.
        let probe_paths = ["/health", "/v1/health", "/management/v1/health", "/"];
        let probe_result =
            wait_for_any_http_ready(&lakekeeper_base, &probe_paths, Duration::from_mins(2)).await;
        if let Err(probe_err) = probe_result {
            // Capture both streams. The previous run got connection
            // refused on every probe, meaning the process exited —
            // any panic / config-validation error is on stderr, not
            // stdout, so stdout-only would lose the actual cause.
            let stdout = lakekeeper.stdout_to_vec().await.map_or_else(
                |e| format!("<failed to read container stdout: {e}>"),
                |b| String::from_utf8_lossy(&b).into_owned(),
            );
            let stderr = lakekeeper.stderr_to_vec().await.map_or_else(
                |e| format!("<failed to read container stderr: {e}>"),
                |b| String::from_utf8_lossy(&b).into_owned(),
            );
            panic!(
                "lakekeeper readiness probe failed: {probe_err}\n\
                 ----- lakekeeper container stdout -----\n{stdout}\n\
                 ----- lakekeeper container stderr -----\n{stderr}\n\
                 ----- end of streams -----"
            );
        }

        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("reqwest client builds");

        // 5. Bootstrap. Idempotent across re-runs against the same
        //    Postgres backend, but a fresh PG container means we
        //    always have to call this.
        let bootstrap_resp = http
            .post(format!("{lakekeeper_base}/management/v1/bootstrap"))
            .json(&json!({
                "accept-terms-of-use": true,
            }))
            .send()
            .await
            .expect("bootstrap POST sends");
        assert!(
            bootstrap_resp.status().is_success()
                || bootstrap_resp.status() == reqwest::StatusCode::CONFLICT,
            "bootstrap failed with status {}: {}",
            bootstrap_resp.status(),
            bootstrap_resp
                .text()
                .await
                .unwrap_or_else(|_| "<unreadable body>".to_string()),
        );

        // 6. Create the warehouse. This is the part most sensitive to
        //    Lakekeeper version drift — body field naming has been
        //    revised in 0.6+. The shape below targets v0.5.2.
        let warehouse_body = json!({
            "warehouse-name": WAREHOUSE_NAME,
            "storage-profile": {
                "type": "s3",
                "bucket": WAREHOUSE_BUCKET,
                "key-prefix": "warehouse",
                "endpoint": format!("http://{minio_hostname}:9000"),
                "region": "us-east-1",
                "path-style-access": true,
                "flavor": "minio",
                "sts-enabled": false,
            },
            "storage-credential": {
                "type": "s3",
                "credential-type": "access-key",
                "aws-access-key-id": MINIO_ACCESS_KEY,
                "aws-secret-access-key": MINIO_SECRET_KEY,
            },
        });
        let warehouse_resp = http
            .post(format!("{lakekeeper_base}/management/v1/warehouse"))
            .json(&warehouse_body)
            .send()
            .await
            .expect("warehouse POST sends");
        assert!(
            warehouse_resp.status().is_success(),
            "warehouse create failed with status {}: {}",
            warehouse_resp.status(),
            warehouse_resp
                .text()
                .await
                .unwrap_or_else(|_| "<unreadable body>".to_string()),
        );

        let catalog_url = format!("{lakekeeper_base}/catalog");

        LakekeeperStack {
            _postgres: postgres,
            _minio: minio,
            _lakekeeper: lakekeeper,
            catalog_url,
            warehouse_name: WAREHOUSE_NAME.to_string(),
            s3_endpoint_host,
            s3_credentials: WarehouseCredentials::Static {
                access_key_id: MINIO_ACCESS_KEY.to_string(),
                secret_access_key: MINIO_SECRET_KEY.to_string(),
            },
            network_name,
        }
    }

    /// Run a one-shot `mc` container that creates the warehouse
    /// bucket. Uses the same Docker network so it can reach
    /// `<minio-hostname>:9000`. The container runs to completion
    /// (mc executes its commands and exits) so we don't need to
    /// keep its handle around — testcontainers will clean it up
    /// when the handle drops at the end of this function.
    /// Run a one-shot Lakekeeper container with the `migrate`
    /// subcommand. `serve` does NOT auto-migrate the Postgres metadata
    /// schema, so the serve container would otherwise panic with
    /// `relation "server" does not exist`.
    ///
    /// Wait condition: match the "Post-migration hooks complete." log
    /// line, which Lakekeeper prints last before exiting cleanly. A
    /// prior version of this fixture used `WaitFor::seconds(0)` and
    /// relied on `stdout_to_vec` to block until container EOF, but in
    /// `testcontainers` 0.27 that returns a snapshot of the current
    /// stdout buffer rather than blocking — so the test captured only
    /// the first few migration lines and started `serve` against a
    /// half-populated schema. Matching the completion log line is the
    /// reliable "migrations are actually done" signal.
    async fn run_lakekeeper_migrations(network: &str, pg_hostname: &str) {
        let pg_url = format!("postgres://lakekeeper:lakekeeper@{pg_hostname}:5432/lakekeeper");
        let migrate = GenericImage::new(LAKEKEEPER_IMAGE, LAKEKEEPER_TAG)
            .with_wait_for(WaitFor::message_on_stdout("Post-migration hooks complete"))
            .with_cmd(["migrate"])
            .with_network(network)
            .with_env_var("LAKEKEEPER__PG_DATABASE_URL_READ", &pg_url)
            .with_env_var("LAKEKEEPER__PG_DATABASE_URL_WRITE", &pg_url)
            .with_env_var("LAKEKEEPER__PG_ENCRYPTION_KEY", "test-encryption-key")
            .with_env_var("LAKEKEEPER__LOG_LEVEL", "info")
            .start()
            .await
            .expect("lakekeeper migrate container starts");

        // Block until migrate's stdout closes — i.e. the process
        // exits. Capture stdout + stderr so failures here surface
        // with full context.
        let stdout = migrate.stdout_to_vec().await.map_or_else(
            |e| format!("<failed to read migrate stdout: {e}>"),
            |b| String::from_utf8_lossy(&b).into_owned(),
        );
        let stderr = migrate.stderr_to_vec().await.map_or_else(
            |e| format!("<failed to read migrate stderr: {e}>"),
            |b| String::from_utf8_lossy(&b).into_owned(),
        );

        // Always print so subsequent serve failures have the migrate
        // logs visible in CI output.
        eprintln!("----- lakekeeper migrate stdout -----\n{stdout}");
        eprintln!("----- lakekeeper migrate stderr -----\n{stderr}");
        eprintln!("----- end of migrate logs -----");

        // We don't have a portable way to read the exit code through
        // testcontainers-rs without `bollard`. As a sanity check,
        // panic if stderr mentions a fatal error so the test fails
        // fast with the migrate logs in the panic message.
        let stderr_lower = stderr.to_lowercase();
        assert!(
            !(stderr_lower.contains("error:") || stderr_lower.contains("panicked")),
            "lakekeeper migrate appears to have failed.\n\
             ----- stdout -----\n{stdout}\n\
             ----- stderr -----\n{stderr}"
        );
    }

    async fn create_bucket_via_mc(network: &str, minio_hostname: &str) {
        let mc_cmd = format!(
            "mc alias set local http://{minio_hostname}:9000 \
             {MINIO_ACCESS_KEY} {MINIO_SECRET_KEY} && \
             mc mb --ignore-existing local/{WAREHOUSE_BUCKET}"
        );
        let mc = GenericImage::new(MC_IMAGE, MC_TAG)
            .with_wait_for(WaitFor::message_on_stdout("Bucket created successfully"))
            .with_entrypoint("/bin/sh")
            .with_cmd(["-c", &mc_cmd])
            .with_network(network)
            .start()
            .await;
        // `mc` exits 0 on success, which testcontainers surfaces as a
        // running-then-stopped container. If the wait condition fires
        // before it terminates, we're done. If the bucket already
        // exists, `--ignore-existing` makes that a noop and the
        // command still prints the success line.
        match mc {
            Ok(_handle) => {}
            Err(e) => panic!("mc bucket-create container failed: {e}"),
        }
    }

    /// Poll an HTTP endpoint until it returns a 2xx response, with
    /// exponential backoff. Used because Lakekeeper opens its
    /// listener before its migrations are done — a log-line wait
    /// alone is insufficient.
    /// Poll a list of candidate health paths against `base_url` until
    /// one returns 2xx, or the deadline passes. Returns the first path
    /// that worked. The path list lets us cope with version drift in
    /// Lakekeeper's health-endpoint location (`/health`, `/v1/health`,
    /// `/management/v1/health`, ...).
    async fn wait_for_any_http_ready(
        base_url: &str,
        paths: &[&str],
        timeout: Duration,
    ) -> Result<String, String> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()
            .map_err(|e| format!("reqwest client build: {e}"))?;
        let deadline = std::time::Instant::now() + timeout;
        let mut backoff = Duration::from_millis(200);
        let mut last_status: Vec<(String, String)> = Vec::new();
        loop {
            last_status.clear();
            for path in paths {
                let url = format!("{base_url}{path}");
                match client.get(&url).send().await {
                    Ok(resp) if resp.status().is_success() => return Ok(url),
                    Ok(resp) => last_status.push((path.to_string(), resp.status().to_string())),
                    Err(e) => last_status.push((path.to_string(), format!("err: {e}"))),
                }
            }
            if std::time::Instant::now() >= deadline {
                let summary = last_status
                    .iter()
                    .map(|(p, s)| format!("{p} -> {s}"))
                    .collect::<Vec<_>>()
                    .join(", ");
                return Err(format!(
                    "no probe path responded with 2xx within {timeout:?}; last attempts: {summary}"
                ));
            }
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(Duration::from_secs(2));
        }
    }

    /// Build the `WarehouseConfig` the connector needs to talk to the
    /// stack. Centralised so each test calls the same shape.
    fn warehouse_config(stack: &LakekeeperStack) -> WarehouseConfig {
        WarehouseConfig {
            catalog_url: stack.catalog_url.clone(),
            warehouse: stack.warehouse_name.clone(),
            credentials: stack.s3_credentials.clone(),
            s3_endpoint: Some(stack.s3_endpoint_host.clone()),
            s3_region: Some("us-east-1".to_string()),
        }
    }

    /// Build a `WarehouseConnector` against the live stack.
    async fn connect_against(stack: &LakekeeperStack) -> WarehouseConnector {
        WarehouseConnector::connect("warehouse", warehouse_config(stack))
            .await
            .expect("connector connects to live Lakekeeper stack")
    }

    /// Smoke test: stand up the stack, point the connector at it,
    /// confirm `connect` returns Ok. Proves the REST handshake
    /// against a real Lakekeeper succeeds and that the S3 wiring
    /// reached `MinIO`.
    #[tokio::test]
    #[ignore = "requires Docker"]
    async fn lakekeeper_warehouse_connect_handshake() {
        let stack = setup_lakekeeper_stack().await;
        let connector = connect_against(&stack).await;
        assert_eq!(connector.name(), "warehouse");
    }

    /// Create a namespace through the connector's underlying catalog
    /// (using the iceberg-rust REST client), then list it via the
    /// connector's `as_catalog_provider` and assert it appears.
    ///
    /// Namespace creation goes through the `iceberg-catalog-rest`
    /// client (same as the other tests) rather than raw HTTP. Earlier
    /// versions hand-built `POST {catalog_url}/v1/namespaces`, but
    /// Lakekeeper's REST routing requires the warehouse prefix
    /// (`/catalog/v1/{warehouse-id}/namespaces`) and the unprefixed
    /// path 404s. The REST client handles prefix construction
    /// internally.
    #[tokio::test]
    #[ignore = "requires Docker"]
    async fn lakekeeper_warehouse_namespace_listing() {
        let stack = setup_lakekeeper_stack().await;

        let catalog = build_rest_catalog(&stack).await;
        let namespace = NamespaceIdent::new("sales_listing".to_string());
        catalog
            .create_namespace(&namespace, HashMap::new())
            .await
            .expect("namespace creates");

        // Now drive it through the connector.
        let connector = Arc::new(connect_against(&stack).await);
        let catalog = connector
            .as_catalog_provider()
            .await
            .expect("catalog provider builds");
        let names = catalog.schema_names();
        assert!(
            names.iter().any(|n| n == "sales_listing"),
            "expected `sales_listing` in schema_names, got: {names:?}",
        );
    }

    /// End-to-end: create a table, write a parquet file via
    /// iceberg-rust's writer API (committing through Lakekeeper's
    /// REST catalog and writing the parquet to `MinIO`), then SELECT
    /// the rows back through the connector.
    ///
    /// This is the load-bearing test for the Lakekeeper integration —
    /// it exercises the entire round-trip: REST commit, S3 PUT,
    /// snapshot creation, manifest-list build, S3 GET, parquet read.
    #[tokio::test]
    #[ignore = "requires Docker"]
    async fn lakekeeper_warehouse_table_select() {
        let stack = setup_lakekeeper_stack().await;
        let connector = connect_against(&stack).await;

        // Create the namespace via the same iceberg-rust client the
        // connector wraps. We need a `Catalog` handle for the
        // create_namespace + create_table + load_table calls; the
        // simplest way is to build a separate `RestCatalogBuilder`
        // pointed at the same Lakekeeper instance.
        let catalog = build_rest_catalog(&stack).await;

        let namespace = NamespaceIdent::new("sales_select".to_string());
        catalog
            .create_namespace(&namespace, HashMap::new())
            .await
            .expect("namespace creates");

        let iceberg_schema = IcebergSchema::builder()
            .with_schema_id(0)
            .with_fields(vec![
                NestedField::required(1, "id", Type::Primitive(PrimitiveType::Int)).into(),
                NestedField::required(2, "amount", Type::Primitive(PrimitiveType::Long)).into(),
            ])
            .build()
            .expect("schema builds");

        let creation = TableCreation::builder()
            .name("orders".to_string())
            .schema(iceberg_schema)
            .properties(HashMap::new())
            .build();
        let table = catalog
            .create_table(&namespace, creation)
            .await
            .expect("orders table creates via Lakekeeper REST");

        // ---- write a parquet via iceberg-rust ------------------------
        //
        // Same shape as the Phase 0 gate test. The Arrow schema must
        // carry PARQUET_FIELD_ID_META_KEY so iceberg-rust binds the
        // parquet columns back to the iceberg field IDs.
        let table_schema = table.metadata().current_schema().clone();
        let location_gen =
            DefaultLocationGenerator::new(table.metadata()).expect("location generator builds");
        let file_name_gen = DefaultFileNameGenerator::new(
            "lakekeeper-it".to_string(),
            None,
            iceberg::spec::DataFileFormat::Parquet,
        );
        let parquet_writer_builder =
            ParquetWriterBuilder::new(WriterProperties::builder().build(), table_schema);
        let rolling_builder = RollingFileWriterBuilder::new_with_default_file_size(
            parquet_writer_builder,
            table.file_io().clone(),
            location_gen,
            file_name_gen,
        );
        let mut writer = DataFileWriterBuilder::new(rolling_builder)
            .build(None)
            .await
            .expect("data file writer builds");

        let arrow_schema = Arc::new(ArrowSchema::new(vec![
            Field::new("id", DataType::Int32, false).with_metadata(HashMap::from([(
                PARQUET_FIELD_ID_META_KEY.to_string(),
                "1".to_string(),
            )])),
            Field::new("amount", DataType::Int64, false).with_metadata(HashMap::from([(
                PARQUET_FIELD_ID_META_KEY.to_string(),
                "2".to_string(),
            )])),
        ]));
        let batch = RecordBatch::try_new(
            arrow_schema,
            vec![
                Arc::new(Int32Array::from(vec![1, 2, 3])),
                Arc::new(Int64Array::from(vec![100_i64, 200, 300])),
            ],
        )
        .expect("batch builds");
        writer.write(batch).await.expect("write parquet");
        let data_files = writer.close().await.expect("close writer");

        // ---- commit the data file ------------------------------------
        let tx = Transaction::new(&table);
        let append = tx.fast_append().add_data_files(data_files);
        let tx = append.apply(tx).expect("fast_append applies");
        // `catalog` is `Arc<dyn Catalog>`; `&*catalog` re-borrows it
        // as `&dyn Catalog`, which is what `commit` accepts.
        let _committed = tx
            .commit(&*catalog)
            .await
            .expect("commit through Lakekeeper REST");

        // ---- SELECT through the connector ----------------------------
        let provider = connector
            .table_provider("sales_select", "orders")
            .await
            .expect("table_provider resolves through Lakekeeper");

        // Schema sanity.
        let provider_schema = provider.schema();
        assert_eq!(provider_schema.fields().len(), 2);
        assert_eq!(provider_schema.field(0).name(), "id");
        assert_eq!(provider_schema.field(1).name(), "amount");

        // Row sanity.
        let ctx = SessionContext::new();
        ctx.register_table("orders", provider)
            .expect("register table");
        let batches: Vec<RecordBatch> = ctx
            .sql("SELECT id, amount FROM orders ORDER BY id")
            .await
            .expect("plan SELECT")
            .collect()
            .await
            .expect("execute SELECT");
        let total: usize = batches.iter().map(RecordBatch::num_rows).sum();
        assert_eq!(
            total,
            3,
            "expected 3 rows, got:\n{}",
            pretty_format_batches(&batches).expect("format")
        );
    }

    /// Three-part-name resolution end-to-end: register the connector
    /// as a `CatalogProvider`, then run `SELECT * FROM
    /// warehouse.<ns>.<table>` against the `SessionContext`. Mirrors
    /// `warehouse_catalog_provider_three_part_name_select` above but
    /// against a real Lakekeeper stack.
    #[tokio::test]
    #[ignore = "requires Docker"]
    async fn lakekeeper_warehouse_catalog_provider_three_part_name() {
        let stack = setup_lakekeeper_stack().await;
        let catalog = build_rest_catalog(&stack).await;

        // Seed: namespace + empty table. We don't need data for this
        // test — `SELECT *` on an empty table still exercises the
        // full three-part-name resolution + scan-pipeline path.
        let namespace = NamespaceIdent::new("sales_three_part".to_string());
        catalog
            .create_namespace(&namespace, HashMap::new())
            .await
            .expect("namespace creates");
        let creation = TableCreation::builder()
            .name("orders".to_string())
            .schema(
                IcebergSchema::builder()
                    .with_schema_id(0)
                    .with_fields(vec![
                        NestedField::required(1, "id", Type::Primitive(PrimitiveType::Int)).into(),
                        NestedField::required(2, "amount", Type::Primitive(PrimitiveType::Long))
                            .into(),
                    ])
                    .build()
                    .expect("schema builds"),
            )
            .properties(HashMap::new())
            .build();
        catalog
            .create_table(&namespace, creation)
            .await
            .expect("orders table creates");

        // Build the catalog provider via the connector under test.
        let connector = Arc::new(connect_against(&stack).await);
        let cat = connector
            .as_catalog_provider()
            .await
            .expect("catalog provider builds");
        let names = cat.schema_names();
        assert!(
            names.iter().any(|n| n == "sales_three_part"),
            "expected `sales_three_part` in schema_names, got: {names:?}",
        );

        let ctx = SessionContext::new();
        ctx.register_catalog("warehouse", cat);
        let batches: Vec<RecordBatch> = ctx
            .sql("SELECT id, amount FROM warehouse.sales_three_part.orders")
            .await
            .expect("three-part-name SQL parses")
            .collect()
            .await
            .expect("execute SELECT");
        let total: usize = batches.iter().map(RecordBatch::num_rows).sum();
        assert_eq!(
            total,
            0,
            "fresh table should be empty, got:\n{}",
            pretty_format_batches(&batches).expect("format")
        );
    }

    /// Build a fresh `iceberg-catalog-rest` client pointed at the
    /// running Lakekeeper. Used by the seeding code in the tests
    /// above; the connector under test uses its own internal
    /// client so this side-channel doesn't pollute the assertions.
    async fn build_rest_catalog(stack: &LakekeeperStack) -> Arc<dyn Catalog> {
        use iceberg::CatalogBuilder;
        use iceberg_catalog_rest::{
            RestCatalogBuilder, REST_CATALOG_PROP_URI, REST_CATALOG_PROP_WAREHOUSE,
        };

        let mut props: HashMap<String, String> = HashMap::new();
        props.insert(REST_CATALOG_PROP_URI.to_string(), stack.catalog_url.clone());
        props.insert(
            REST_CATALOG_PROP_WAREHOUSE.to_string(),
            stack.warehouse_name.clone(),
        );
        props.insert(
            iceberg::io::S3_ACCESS_KEY_ID.to_string(),
            MINIO_ACCESS_KEY.to_string(),
        );
        props.insert(
            iceberg::io::S3_SECRET_ACCESS_KEY.to_string(),
            MINIO_SECRET_KEY.to_string(),
        );
        props.insert(
            iceberg::io::S3_ENDPOINT.to_string(),
            stack.s3_endpoint_host.clone(),
        );
        props.insert(iceberg::io::S3_REGION.to_string(), "us-east-1".to_string());
        props.insert(
            iceberg::io::S3_PATH_STYLE_ACCESS.to_string(),
            "true".to_string(),
        );

        let catalog = RestCatalogBuilder::default()
            .with_storage_factory(Arc::new(
                iceberg_storage_opendal::OpenDalStorageFactory::S3 {
                    customized_credential_load: None,
                },
            ))
            .load("warehouse-test-side-channel".to_string(), props)
            .await
            .expect("rest catalog client loads");
        Arc::new(catalog) as Arc<dyn Catalog>
    }

    /// Compile-time `Send` assertion for `LakekeeperStack`.
    ///
    /// The stack is held across test `await` points (via `OnceCell`
    /// in any future shared-stack refactor), so it must be `Send`.
    /// This function is never called; it exists only so that
    /// `cargo build --tests` catches a future `!Send` field drift
    /// (e.g. someone adding a `Cell<_>`-bearing handle) at the
    /// earliest possible moment.
    #[allow(dead_code)]
    fn _stack_assertions() {
        fn assert_send<T: Send>() {}
        assert_send::<LakekeeperStack>();
    }
}

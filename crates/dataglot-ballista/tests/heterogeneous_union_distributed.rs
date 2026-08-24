//! Heterogeneous distributed UNION —  item 3.
//!
//! `multi_source_union.rs` unions four **Postgres** backends (one codec,
//! the federation `VirtualExecutionPlan`); `warehouse_distributed.rs`
//! runs a **warehouse/Iceberg** table alone (the `WarehouseScanExec`
//! codec added by ). Neither pins the mixed case: a *single*
//! distributed plan that carries **both** codecs at once — exactly the
//! path / made work. This test does:
//!
//!   SELECT id FROM pg.public.items          -- federation leg
//!   UNION ALL
//!   SELECT id FROM lakehouse.sales.orders   -- warehouse (Iceberg) leg
//!
//! through one standalone Ballista cluster, so the serialized stage graph
//! must round-trip a federation source *and* a warehouse scan on the same
//! plan. A regression in either codec's registration (or a collision
//! between them) fails here.
//!
//! # Docker requirement
//!
//! `#[ignore = "requires Docker"]` — the Postgres leg uses testcontainers,
//! same shape as `multi_source_union.rs`. The warehouse leg is in-memory
//! (temp-dir Iceberg, no Docker) — copied from `warehouse_distributed.rs`.
//! The `ballista (Phase 2)` CI job runs `--ignored`.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use ballista::datafusion::arrow::array::{Int32Array, Int64Array, RecordBatch};
use ballista::datafusion::arrow::datatypes::{DataType, Field, Schema as ArrowSchema};
use ballista::datafusion::prelude::SessionContext;
use datafusion_federation::sql::SQLExecutor;
use datafusion_proto::logical_plan::LogicalExtensionCodec;
use datafusion_proto::physical_plan::PhysicalExtensionCodec;
use dataglot_ballista::{
    BallistaContextFactory, BallistaPhysicalExtensionCodec, FederationLogicalCodec,
};
use dataglot_core::SessionConfig;
use dataglot_federation::iceberg::{WarehouseConnector, WarehouseRegistry};
use dataglot_federation::postgres::PostgresConnector;
use dataglot_federation::{DynConnectorRegistry, FederationPlanCodec, InMemoryConnectorRegistry};
use iceberg::io::LocalFsStorageFactory;
use iceberg::memory::{MemoryCatalogBuilder, MEMORY_CATALOG_WAREHOUSE};
use iceberg::spec::{NestedField, PrimitiveType, Schema as IcebergSchema, Type};
use iceberg::transaction::{ApplyTransactionAction, Transaction};
use iceberg::writer::base_writer::data_file_writer::DataFileWriterBuilder;
use iceberg::writer::file_writer::location_generator::{
    DefaultFileNameGenerator, DefaultLocationGenerator,
};
use iceberg::writer::file_writer::rolling_writer::RollingFileWriterBuilder;
use iceberg::writer::file_writer::ParquetWriterBuilder;
use iceberg::writer::{IcebergWriter, IcebergWriterBuilder};
use iceberg::{Catalog, CatalogBuilder, NamespaceIdent, TableCreation};
use parquet::arrow::PARQUET_FIELD_ID_META_KEY;
use parquet::file::properties::WriterProperties;
use testcontainers::runners::AsyncRunner;
use testcontainers::ContainerAsync;
use testcontainers_modules::postgres::Postgres;
use tokio_postgres::NoTls;

/// Bring up one Postgres container + seed `public.items(id, source_tag)`
/// with two rows. Returns the DSN + the live container (kept alive by the
/// caller; the DB tears down on `Drop`).
async fn setup_postgres() -> (String, ContainerAsync<Postgres>) {
    let container = Postgres::default()
        .start()
        .await
        .expect("postgres container starts");
    let host = container.get_host().await.expect("postgres host");
    let port = container
        .get_host_port_ipv4(5432)
        .await
        .expect("postgres port");
    let dsn = format!("host={host} port={port} user=postgres password=postgres dbname=postgres");

    let (client, connection) = tokio_postgres::connect(&dsn, NoTls)
        .await
        .expect("connect to postgres for seeding");
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            // tokio-postgres errors are credential-free.
            eprintln!("seed connection error: {e}");
        }
    });
    // Same name on both the DataFusion and Postgres sides so the
    // federation unparser produces self-consistent remote SQL (mirrors
    // `multi_source_union.rs`).
    client
        .batch_execute(
            "CREATE TABLE public.pg_items (id INT PRIMARY KEY, source_tag VARCHAR(16) NOT NULL);
             INSERT INTO public.pg_items (id, source_tag) VALUES (10, 'pg'), (20, 'pg');",
        )
        .await
        .expect("seed pg_items table");
    (dsn, container)
}

/// In-memory Iceberg catalog + `sales.orders` (3 rows) on temp-dir
/// storage — copied from `warehouse_distributed.rs` (the writer is
/// storage-agnostic, so local-fs seeds identically to Lakekeeper).
async fn seed_catalog(dir: &std::path::Path) -> Arc<dyn Catalog> {
    let catalog = MemoryCatalogBuilder::default()
        .with_storage_factory(Arc::new(LocalFsStorageFactory))
        .load(
            "warehouse",
            HashMap::from([(
                MEMORY_CATALOG_WAREHOUSE.to_string(),
                dir.to_str().expect("utf-8 tempdir").to_string(),
            )]),
        )
        .await
        .expect("memory catalog loads");
    let namespace = NamespaceIdent::new("sales".to_string());
    catalog
        .create_namespace(&namespace, HashMap::new())
        .await
        .expect("namespace creates");

    let schema = IcebergSchema::builder()
        .with_schema_id(0)
        .with_fields(vec![
            NestedField::required(1, "id", Type::Primitive(PrimitiveType::Int)).into(),
            NestedField::required(2, "amount", Type::Primitive(PrimitiveType::Long)).into(),
        ])
        .build()
        .expect("iceberg schema builds");
    let table = catalog
        .create_table(
            &namespace,
            TableCreation::builder()
                .name("orders".to_string())
                .schema(schema.clone())
                .build(),
        )
        .await
        .expect("table creates");

    let location_generator =
        DefaultLocationGenerator::new(table.metadata()).expect("location generator");
    let file_name_generator = DefaultFileNameGenerator::new(
        "part".to_string(),
        None,
        iceberg::spec::DataFileFormat::Parquet,
    );
    let parquet_writer_builder = ParquetWriterBuilder::new(
        WriterProperties::default(),
        table.metadata().current_schema().clone(),
    );
    let rolling_writer_builder = RollingFileWriterBuilder::new_with_default_file_size(
        parquet_writer_builder,
        table.file_io().clone(),
        location_generator,
        file_name_generator,
    );
    let data_file_writer_builder = DataFileWriterBuilder::new(rolling_writer_builder);
    let mut writer = data_file_writer_builder
        .build(None)
        .await
        .expect("writer builds");

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
    let files = writer.close().await.expect("close writer");
    let tx = Transaction::new(&table);
    let append = tx.fast_append().add_data_files(files);
    let tx = append.apply(tx).expect("append applies");
    let catalog_arc: Arc<dyn Catalog> = Arc::new(catalog);
    tx.commit(&*catalog_arc).await.expect("commit");
    catalog_arc
}

/// The wedge: one distributed plan carrying a federation (Postgres) leg
/// **and** a warehouse (Iceberg) leg through the same encode/decode path.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires Docker"]
async fn heterogeneous_pg_warehouse_union_distributed() {
    // --- Postgres leg ---
    let (dsn, _pg_container) = setup_postgres().await;
    let pg = Arc::new(
        PostgresConnector::connect(&dsn)
            .await
            .expect("postgres connector connects"),
    );
    let pg_executor: Arc<dyn SQLExecutor> = pg.clone();
    let sql_registry: DynConnectorRegistry = Arc::new(
        [("pg".to_string(), pg_executor)]
            .into_iter()
            .collect::<InMemoryConnectorRegistry>(),
    );

    // --- Warehouse (Iceberg) leg ---
    let dir = tempfile::tempdir().expect("tempdir");
    let catalog = seed_catalog(dir.path()).await;
    let warehouse = Arc::new(WarehouseConnector::__from_catalog_for_tests(
        "lakehouse",
        Arc::clone(&catalog),
    ));
    let warehouses = Arc::new(WarehouseRegistry::new(HashMap::from([(
        "lakehouse".to_string(),
        Arc::clone(&warehouse),
    )])));

    // --- Composed codec: federation SQL + warehouse on one plan ---
    // Mirrors dataglot-server::ballista::build_factory when both a SQL
    // source and a warehouse are configured.
    let logical: Arc<dyn LogicalExtensionCodec> = Arc::new(
        FederationLogicalCodec::with_registry(Arc::clone(&sql_registry))
            .with_warehouse_registry(Arc::clone(&warehouses)),
    );
    let physical: Arc<dyn PhysicalExtensionCodec> = Arc::new(
        FederationPlanCodec::with_logical_codec(Arc::clone(&sql_registry), Arc::clone(&logical))
            .with_warehouse_registry(Arc::clone(&warehouses))
            .with_inner_physical_codec(Arc::new(BallistaPhysicalExtensionCodec::default())),
    );

    let factory = BallistaContextFactory::new(SessionConfig::new())
        .with_logical_codec(logical)
        .with_physical_codec(physical);
    let cluster = factory
        .boot_standalone_cluster()
        .await
        .expect("ballista standalone boots");
    let ctx: SessionContext = cluster.create_session();

    // Register both sources: the Postgres `items` table (bare) and the
    // warehouse catalog (`lakehouse.sales.orders`).
    let pg_items = pg
        .table_provider("public", "pg_items")
        .await
        .expect("pg table provider");
    ctx.register_table("pg_items", pg_items)
        .expect("register pg_items");
    let warehouse_catalog = warehouse
        .as_catalog_provider()
        .await
        .expect("warehouse catalog provider");
    ctx.register_catalog("lakehouse", warehouse_catalog);

    // The heterogeneous UNION — both legs on one distributed plan.
    let batches = tokio::time::timeout(Duration::from_mins(2), async {
        ctx.sql(
            "SELECT id FROM pg_items \
             UNION ALL \
             SELECT id FROM lakehouse.sales.orders \
             ORDER BY id",
        )
        .await
        .expect("plans the mixed-source UNION")
        .collect()
        .await
        .expect("executes distributed (a failure here means a codec didn't round-trip)")
    })
    .await
    .expect("bounded (a hang means the mixed stage graph didn't serialize)");

    let mut ids: Vec<i32> = Vec::new();
    for b in &batches {
        let col = b
            .column(0)
            .as_any()
            .downcast_ref::<Int32Array>()
            .expect("id column is Int32");
        for i in 0..b.num_rows() {
            ids.push(col.value(i));
        }
    }

    // Warehouse ids {1,2,3} + Postgres ids {10,20}, both codecs having
    // round-tripped through the same distributed plan.
    assert_eq!(
        ids,
        vec![1, 2, 3, 10, 20],
        "expected the warehouse rows (1,2,3) and the Postgres rows (10,20) \
         from the heterogeneous UNION; a missing set means that source's \
         codec dropped out of the mixed plan"
    );
}

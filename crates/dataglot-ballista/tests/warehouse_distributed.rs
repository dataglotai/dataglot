//! Distributed lakehouse (Iceberg warehouse) e2e —.
//!
//! Before this, a warehouse table in a distributed plan failed at the
//! encode boundary with the  "not available in distributed
//! mode" guidance. This test runs the whole new path with **no
//! Docker**: an in-memory Iceberg catalog over temp-dir storage,
//! seeded through the iceberg writer, queried through a standalone
//! Ballista cluster:
//!
//!   client encode (identity envelope, catalog-name keyed)
//!   → scheduler decode (`LazyWarehouseTableProvider`, no IO)
//!   → physical plan (`WarehouseScanExec`)
//!   → stage serialization (`KIND_WAREHOUSE_SCAN` payload)
//!   → executor decode + execute (catalog `load_table` happens HERE)
//!   → rows back through the shuffle.
//!
//! The in-process executor shares the registry Arc with the client —
//! exactly the demo's standalone shape. Multi-process parity is the
//! `catalogs-config` `warehouse` entry (unit-tested in
//! `catalogs_config.rs`); a Lakekeeper-backed multi-process e2e stays
//! Docker-gated future work.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use ballista::datafusion::arrow::array::{Int32Array, Int64Array, RecordBatch};
use ballista::datafusion::arrow::datatypes::{DataType, Field, Schema as ArrowSchema};
use ballista::datafusion::prelude::SessionContext;
use datafusion_proto::logical_plan::LogicalExtensionCodec;
use datafusion_proto::physical_plan::PhysicalExtensionCodec;
use dataglot_ballista::{
    BallistaContextFactory, BallistaPhysicalExtensionCodec, FederationLogicalCodec,
};
use dataglot_core::SessionConfig;
use dataglot_federation::iceberg::{WarehouseConnector, WarehouseRegistry};
use dataglot_federation::{DynConnectorRegistry, InMemoryConnectorRegistry};
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

/// In-memory catalog + `sales.orders` (3 rows) on temp-dir storage.
/// Same writer dance as `dataglot-federation`'s Lakekeeper e2e — the
/// writer is storage-agnostic, so it seeds local-fs identically.
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
        .expect("schema builds");
    let creation = TableCreation::builder()
        .name("orders".to_string())
        .schema(schema)
        .properties(HashMap::new())
        .build();
    let table = catalog
        .create_table(&namespace, creation)
        .await
        .expect("orders creates");

    // Write one parquet with 3 rows and commit it.
    let table_schema = table.metadata().current_schema().clone();
    let location_gen = DefaultLocationGenerator::new(table.metadata()).expect("location gen");
    let file_name_gen = DefaultFileNameGenerator::new(
        "oss118-e2e".to_string(),
        None,
        iceberg::spec::DataFileFormat::Parquet,
    );
    let parquet_builder =
        ParquetWriterBuilder::new(WriterProperties::builder().build(), table_schema);
    let rolling = RollingFileWriterBuilder::new_with_default_file_size(
        parquet_builder,
        table.file_io().clone(),
        location_gen,
        file_name_gen,
    );
    let mut writer = DataFileWriterBuilder::new(rolling)
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lakehouse_query_executes_distributed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let catalog = seed_catalog(dir.path()).await;
    let connector = Arc::new(WarehouseConnector::__from_catalog_for_tests(
        "lakehouse",
        Arc::clone(&catalog),
    ));

    // Registries: no SQL sources, one warehouse — the demo's
    // lakehouse-only shape.
    let sql_registry: DynConnectorRegistry =
        Arc::new(InMemoryConnectorRegistry::new(HashMap::default()));
    let warehouses = Arc::new(WarehouseRegistry::new(HashMap::from([(
        "lakehouse".to_string(),
        Arc::clone(&connector),
    )])));

    // Codec wiring — mirrors dataglot-server::ballista::build_factory.
    let logical: Arc<dyn LogicalExtensionCodec> = Arc::new(
        FederationLogicalCodec::with_registry(Arc::clone(&sql_registry))
            .with_warehouse_registry(Arc::clone(&warehouses)),
    );
    let physical: Arc<dyn PhysicalExtensionCodec> = Arc::new(
        dataglot_federation::FederationPlanCodec::with_logical_codec(
            sql_registry,
            Arc::clone(&logical),
        )
        .with_warehouse_registry(Arc::clone(&warehouses))
        .with_inner_physical_codec(Arc::new(BallistaPhysicalExtensionCodec::default())),
    );
    let factory = BallistaContextFactory::new(SessionConfig::new())
        .with_logical_codec(logical)
        .with_physical_codec(physical);
    let state = factory.build_federated_state();

    let boot = dataglot_ballista::monitor::boot_monitored_standalone(&state, None, 3600)
        .await
        .expect("standalone cluster boots");
    let ctx: SessionContext = boot.context;
    let catalog_provider = connector
        .as_catalog_provider()
        .await
        .expect("catalog provider builds");
    ctx.register_catalog("lakehouse", catalog_provider);

    // Row-level correctness through the full codec + shuffle path.
    let batches = tokio::time::timeout(Duration::from_mins(1), async {
        ctx.sql("SELECT id, amount FROM lakehouse.sales.orders ORDER BY id")
            .await
            .expect("plans")
            .collect()
            .await
            .expect("executes distributed")
    })
    .await
    .expect("bounded (a hang here means the scan payload didn't round-trip)");
    let mut rows = Vec::new();
    for b in &batches {
        let ids = b
            .column(0)
            .as_any()
            .downcast_ref::<Int32Array>()
            .expect("id col");
        let amounts = b
            .column(1)
            .as_any()
            .downcast_ref::<Int64Array>()
            .expect("amount col");
        for i in 0..b.num_rows() {
            rows.push((ids.value(i), amounts.value(i)));
        }
    }
    assert_eq!(rows, vec![(1, 100), (2, 200), (3, 300)]);

    // An aggregate forces a shuffle boundary above the warehouse scan.
    let batches = tokio::time::timeout(Duration::from_mins(1), async {
        ctx.sql("SELECT SUM(amount) AS total FROM lakehouse.sales.orders")
            .await
            .expect("plans")
            .collect()
            .await
            .expect("aggregate executes distributed")
    })
    .await
    .expect("bounded");
    let total = batches[0]
        .column(0)
        .as_any()
        .downcast_ref::<Int64Array>()
        .expect("sum col")
        .value(0);
    assert_eq!(total, 600);
}

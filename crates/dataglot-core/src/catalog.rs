//! Typed classification of registered catalogs.
//!
//! `CatalogBinding` is the binding layer between a user-facing
//! catalog name (the key in `dataglot.toml`'s `[catalogs.*]`
//! block) and the concrete `Arc<dyn CatalogProvider>` that
//! resolves it. The variants distinguish whether the catalog is
//! Iceberg-materialized, federation pass-through, or a
//! Peaka-managed semantic overlay — a typed slot the upcoming
//! Peaka Catalog Service (Phase 1 task 08) and in-process
//! cache (task 09) consume for invalidation routing, sharing
//! policy, and lineage event subtype.
//!
//! Architecture Decisions v3.0 §09. Spec:
//! the phase-1 `catalog-binding-enum` plan.
//!
//! # Informational-only in Phase 1
//!
//! The binding is metadata. No optimizer rule, no behavioural
//! change, no API mutation. Shipping the type first lets the
//! downstream catalog-service spec reference a concrete shape
//! instead of waiting on shape agreement.
//!
//! # Credential isolation
//!
//! Per hard rule 12, bindings never carry credentials.
//! `LiveConnectorBinding::endpoint_hint` is what an operator can
//! copy out of the catalog-service UI — a `host:port` or
//! `s3://bucket/...` string — with passwords / access keys /
//! tokens elided. The actual credential resolution still goes
//! through the per-connector resolver at execution time.

use serde::{Deserialize, Serialize};

/// Typed classification of a registered catalog. Three
/// variants per Architecture Decisions v3.0 §09; closed set
/// (no `#[non_exhaustive]`) because adding a fourth variant is
/// a deliberate architectural decision that changes what the
/// catalog service has to route.
///
/// Serde uses the default (externally-tagged) shape so the
/// recursive `SemanticCatalog → underlying` case stays
/// unambiguous when nested.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CatalogBinding {
    /// Iceberg lakehouse table — materialized in the
    /// warehouse, served via `iceberg-datafusion`'s catalog
    /// providers. Per hard rule 7, "Iceberg" never
    /// surfaces in user-facing error messages or API
    /// responses; this variant is for internal classification
    /// (cache invalidation, lineage event subtype) only.
    IcebergCache(IcebergCacheBinding),

    /// Live federated source — Postgres, `MySQL`, Snowflake,
    /// object storage — served via `datafusion-federation`'s
    /// `SQLExecutor` adapters (or the warehouse's direct
    /// providers for object storage).
    LiveConnector(LiveConnectorBinding),

    /// Peaka-managed semantic catalog overlay — virtual
    /// catalog of data products with sharing / attachment
    /// metadata. Recursively binds to a physical store
    /// underneath via `underlying`, capped at one level
    /// (enforced at construction).
    SemanticCatalog(SemanticCatalogBinding),
}

/// Binding for an Iceberg-cached catalog.
///
/// `catalog_url` identifies the Iceberg REST catalog
/// (Lakekeeper in Peaka deployments — never Polaris, per the
/// project's "What NOT to do" rules). `warehouse` is the catalog's
/// warehouse name; `table_path` is the dotted reference
/// inside the warehouse, populated lazily — empty at boot,
/// filled per scan if the operator-facing catalog UI ever
/// needs the resolved name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IcebergCacheBinding {
    /// Base URL of the warehouse REST catalog.
    pub catalog_url: String,
    /// Warehouse identifier within the catalog.
    pub warehouse: String,
    /// Resolved table path inside the warehouse. Empty at
    /// boot — populated per-scan if a consumer needs it.
    #[serde(default)]
    pub table_path: Vec<String>,
}

/// Binding for a live federated source — Postgres, `MySQL`,
/// Snowflake, or object storage. `kind` discriminates which
/// connector `dataglot-federation` instantiates;
/// `endpoint_hint` is the credential-redacted location string
/// the catalog-service UI surfaces.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiveConnectorBinding {
    /// Which connector this binding routes through.
    pub kind: LiveConnectorKind,
    /// Diagnostic string for the catalog-service UI — host +
    /// port for SQL sources, URL prefix for object storage.
    /// **Never** contains credentials.
    pub endpoint_hint: String,
}

/// Connector kinds the `LiveConnector` variant can route to.
///
/// Kept independent of `dataglot-federation`'s internal
/// connector-kind type: the binding is the *abstraction*, the
/// connector is the *implementation*. Independence costs one
/// match arm per connector but keeps the catalog service from
/// becoming a federation-internal API consumer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LiveConnectorKind {
    /// `kind: "postgres"` in `dataglot.toml`.
    Postgres,
    /// `kind: "mysql"` in `dataglot.toml`.
    Mysql,
    /// `kind: "snowflake"` in `dataglot.toml` — Phase 1 task
    /// 05. Present in the binding enum for forward
    /// compatibility; consumed once the connector lands.
    Snowflake,
    /// `kind: "oracle"` in `dataglot.toml` — Phase 3 task 04
    /// (, Exadata displacement). The connector is gated
    /// behind the server's `oracle` feature (Oracle Instant Client
    /// is a C-runtime dep); the binding kind is always present so
    /// lineage / catalog-service surfaces the source regardless of
    /// how the server was built.
    Oracle,
    /// `kind: "object_storage"` in `dataglot.toml`.
    ObjectStorage,
    /// `kind: "odata"` / `kind: "sap_s4hana"` in `dataglot.toml` — Phase 4
    /// task 01. A direct-`TableProvider` REST source (OData v2),
    /// not a SQL connector; the SAP layer is the same kind with SAP request
    /// headers. Pure-Rust, so always compiled into the server.
    Odata,
    /// `kind: "adbc"` in `dataglot.toml` — Phase 3 task 02 (,
    /// generic BYO-driver connector). The connector is gated behind the
    /// server's `adbc` feature; the binding kind is always present so
    /// lineage / catalog-service surfaces the source regardless of how
    /// the server was built.
    Adbc,
    /// `kind: "flightsql"` in `dataglot.toml` — Phase 4 task 05.
    /// An Arrow Flight SQL server reached over gRPC: a `SQLExecutor` source
    /// like [`Self::Adbc`], but speaking a wire protocol rather than loading
    /// a driver, so it needs no native library on the host. The connector is
    /// gated behind the server's `flightsql-source` feature; the binding kind
    /// is always present so lineage / catalog-service surfaces the source
    /// regardless of how the server was built.
    ///
    /// Spelled `flightsql`, not `flight_sql`: one spelling across the config
    /// `kind`, this binding and the governance platform, matching the crate
    /// feature and the published spec.
    #[serde(rename = "flightsql")]
    FlightSql,
    /// `kind: "rest"` in `dataglot.toml` — Phase 4. A generic
    /// REST/JSON source (Salesforce, Athena Health APIs): a direct
    /// `TableProvider` (rule 3), sibling of [`Self::Odata`], with a per-table
    /// declared Arrow schema. Pure-Rust, so always compiled into the server.
    Rest,
    /// `kind: "clickhouse"` in `dataglot.toml` — planned, not accepted yet.
    /// Present in the binding enum ahead of the connector, which will be a
    /// `SQLExecutor` source reached over ClickHouse's HTTP interface, with
    /// results returned as Arrow IPC, gated behind a `clickhouse` feature.
    /// Until the server config for it lands, a `kind = "clickhouse"` catalog
    /// is rejected at boot as an unknown kind.
    ///
    /// Spelled `clickhouse`, not `click_house`: `rename_all = "snake_case"`
    /// would split the name at the capital H, and the config key is one word.
    #[serde(rename = "clickhouse")]
    ClickHouse,
}

impl LiveConnectorKind {
    /// The governance platform this connector kind publishes as.
    ///
    /// Lives here, next to both enums, rather than in the server: the
    /// mapping is a property of the two types, and keeping it beside them
    /// means adding a connector kind is one crate's change with the
    /// exhaustive match right there to force the decision. Held in the
    /// server it made every new kind a cross-crate change that could not be
    /// staged (rule 5) without giving up that compile-time check.
    ///
    /// Backend-neutral by construction: both sides are this crate's own
    /// enums. Vendor vocabulary — `DataHub`'s platform slugs, and whatever
    /// `OpenMetadata` and Informatica use — stays in each backend's adapter,
    /// per the Phase 1 decision that the trait carries a typed enum and the
    /// per-backend adapter does the string mapping.
    #[must_use]
    pub fn product_platform(self) -> crate::governance::ProductPlatform {
        use crate::governance::ProductPlatform;
        match self {
            Self::Postgres => ProductPlatform::Postgres,
            Self::Mysql => ProductPlatform::Mysql,
            Self::Snowflake => ProductPlatform::Snowflake,
            Self::Oracle => ProductPlatform::Oracle,
            Self::ObjectStorage => ProductPlatform::ObjectStorage,
            Self::Odata => ProductPlatform::Odata,
            Self::Adbc => ProductPlatform::Adbc,
            Self::Rest => ProductPlatform::Rest,
            Self::FlightSql => ProductPlatform::FlightSql,
            Self::ClickHouse => ProductPlatform::ClickHouse,
        }
    }
}

/// Binding for a Peaka-managed semantic catalog. `data_product_id`
/// is the stable identifier the Peaka Catalog Service issues;
/// `underlying` recursively binds to whatever physical store
/// backs the product.
///
/// One-level nesting cap: `underlying` is never itself
/// `SemanticCatalog`. Enforced at construction via
/// [`SemanticCatalogBinding::try_new`] so the type system
/// can't represent an over-nested shape. The cap keeps the
/// catalog service's invalidation walk O(1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SemanticCatalogBinding {
    /// Stable identifier issued by the Peaka Catalog Service.
    pub data_product_id: String,
    /// Physical store backing the product. Never itself
    /// `CatalogBinding::SemanticCatalog`.
    pub underlying: Box<CatalogBinding>,
}

impl SemanticCatalogBinding {
    /// Construct a `SemanticCatalogBinding`, rejecting nested
    /// `SemanticCatalog` underlying bindings.
    ///
    /// # Errors
    /// Returns [`SemanticCatalogError::NestedSemantic`] if
    /// `underlying` is itself a `SemanticCatalog` variant.
    pub fn try_new(
        data_product_id: String,
        underlying: CatalogBinding,
    ) -> Result<Self, SemanticCatalogError> {
        if matches!(underlying, CatalogBinding::SemanticCatalog(_)) {
            return Err(SemanticCatalogError::NestedSemantic);
        }
        Ok(Self {
            data_product_id,
            underlying: Box::new(underlying),
        })
    }
}

/// Construction-time error for [`SemanticCatalogBinding`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SemanticCatalogError {
    /// `underlying` was itself a `SemanticCatalog`. Phase 1
    /// caps recursion at one level to keep the catalog
    /// service's invalidation walk O(1).
    #[error("SemanticCatalog cannot recursively bind to another SemanticCatalog (one-level cap)")]
    NestedSemantic,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pg_binding() -> CatalogBinding {
        CatalogBinding::LiveConnector(LiveConnectorBinding {
            kind: LiveConnectorKind::Postgres,
            endpoint_hint: "10.0.0.5:5432".to_string(),
        })
    }

    fn warehouse_binding() -> CatalogBinding {
        CatalogBinding::IcebergCache(IcebergCacheBinding {
            catalog_url: "http://lakekeeper:8181/catalog".to_string(),
            warehouse: "main".to_string(),
            table_path: vec![],
        })
    }

    /// Every connector kind maps to a platform, and the mapping lives in
    /// this crate so that adding a kind is a single-crate change with the
    /// exhaustive match right beside the enum.
    #[test]
    fn every_connector_kind_maps_to_a_governance_platform() {
        use crate::governance::ProductPlatform;
        for (kind, platform) in [
            (LiveConnectorKind::Postgres, ProductPlatform::Postgres),
            (LiveConnectorKind::Mysql, ProductPlatform::Mysql),
            (LiveConnectorKind::Snowflake, ProductPlatform::Snowflake),
            (LiveConnectorKind::Oracle, ProductPlatform::Oracle),
            (
                LiveConnectorKind::ObjectStorage,
                ProductPlatform::ObjectStorage,
            ),
            (LiveConnectorKind::Odata, ProductPlatform::Odata),
            (LiveConnectorKind::Adbc, ProductPlatform::Adbc),
            (LiveConnectorKind::Rest, ProductPlatform::Rest),
            (LiveConnectorKind::FlightSql, ProductPlatform::FlightSql),
            (LiveConnectorKind::ClickHouse, ProductPlatform::ClickHouse),
        ] {
            assert_eq!(kind.product_platform(), platform, "{kind:?}");
        }
    }

    /// One spelling everywhere it is written down: the config `kind`, this
    /// binding, and the governance platform. `rename_all = "snake_case"`
    /// would have made this `flight_sql` and left the `dataglot.toml` key
    /// spelled differently from the wire.
    #[test]
    fn the_flight_sql_kind_is_spelled_the_way_the_config_key_is() {
        assert_eq!(
            serde_json::to_string(&LiveConnectorKind::FlightSql).unwrap(),
            "\"flightsql\""
        );
        assert_eq!(
            serde_json::from_str::<LiveConnectorKind>("\"flightsql\"").unwrap(),
            LiveConnectorKind::FlightSql
        );
    }

    #[test]
    fn binding_serde_roundtrip_all_variants() {
        // Pin the wire shape — the catalog service serdes
        // bindings across IPC. Tag rename / variant rename
        // would break consumers; this test is the regression
        // guard.
        for original in [
            pg_binding(),
            warehouse_binding(),
            CatalogBinding::LiveConnector(LiveConnectorBinding {
                kind: LiveConnectorKind::Mysql,
                endpoint_hint: "10.0.0.6:3306".to_string(),
            }),
            CatalogBinding::LiveConnector(LiveConnectorBinding {
                kind: LiveConnectorKind::Snowflake,
                endpoint_hint: "acme-corp.us-east-1".to_string(),
            }),
            CatalogBinding::LiveConnector(LiveConnectorBinding {
                kind: LiveConnectorKind::ObjectStorage,
                endpoint_hint: "file:///var/parquet".to_string(),
            }),
            CatalogBinding::LiveConnector(LiveConnectorBinding {
                kind: LiveConnectorKind::FlightSql,
                endpoint_hint: "grpc://dremio.internal:32010".to_string(),
            }),
            CatalogBinding::LiveConnector(LiveConnectorBinding {
                kind: LiveConnectorKind::ClickHouse,
                endpoint_hint: "https://clickhouse.internal:8443".to_string(),
            }),
            CatalogBinding::SemanticCatalog(
                SemanticCatalogBinding::try_new("dp_42".to_string(), pg_binding())
                    .expect("one-level nesting OK"),
            ),
        ] {
            let json = serde_json::to_string(&original).expect("serialize");
            let parsed: CatalogBinding = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(parsed, original, "roundtrip mismatch for {original:?}");
        }
    }

    #[test]
    fn semantic_catalog_one_level_nesting_enforced() {
        // The constructor rejects a `SemanticCatalog → SemanticCatalog`
        // shape; the type system can't represent it via the
        // safe API. The catalog service's invalidation walk
        // depends on this cap.
        let inner = SemanticCatalogBinding::try_new("dp_inner".to_string(), pg_binding())
            .expect("inner construction");
        let err = SemanticCatalogBinding::try_new(
            "dp_outer".to_string(),
            CatalogBinding::SemanticCatalog(inner),
        )
        .expect_err("nested SemanticCatalog must be rejected");
        assert_eq!(err, SemanticCatalogError::NestedSemantic);
    }

    #[test]
    fn live_connector_kind_serde_lowercase() {
        // `kind: "postgres"` on the wire, not `kind: "Postgres"`.
        // Operator config files use lowercase across the
        // workspace (matches `CatalogConfig`'s
        // `rename_all = "snake_case"`).
        let cases = [
            (LiveConnectorKind::Postgres, r#""postgres""#),
            (LiveConnectorKind::Mysql, r#""mysql""#),
            (LiveConnectorKind::Snowflake, r#""snowflake""#),
            (LiveConnectorKind::Oracle, r#""oracle""#),
            (LiveConnectorKind::ObjectStorage, r#""object_storage""#),
            (LiveConnectorKind::Odata, r#""odata""#),
            //  (rule 14): Adbc was the one variant with no serde
            // pin — a rename/attr regression would silently break
            // `kind = "adbc"` catalog-service IPC and dataglot.json.
            (LiveConnectorKind::Adbc, r#""adbc""#),
            (LiveConnectorKind::Rest, r#""rest""#),
            (LiveConnectorKind::ClickHouse, r#""clickhouse""#),
        ];
        for (kind, expected) in cases {
            let json = serde_json::to_string(&kind).expect("serialize");
            assert_eq!(json, expected, "tag mismatch for {kind:?}");
            let parsed: LiveConnectorKind = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(parsed, kind);
        }
    }

    #[test]
    fn iceberg_cache_binding_default_table_path_empty() {
        // `table_path` defaults to empty on deserialize — the
        // boot path doesn't yet know the resolved path, and
        // the field is lazily populated.
        let json = r#"{"catalog_url":"http://x","warehouse":"main"}"#;
        let b: IcebergCacheBinding = serde_json::from_str(json).unwrap();
        assert!(b.table_path.is_empty());
    }

    #[test]
    fn semantic_catalog_underlying_is_boxed_in_serde() {
        // Recursive serde: the nested binding is preserved
        // round-trip. Catches accidental flattening.
        let original = SemanticCatalogBinding::try_new("dp".into(), warehouse_binding()).unwrap();
        let json = serde_json::to_string(&original).unwrap();
        let parsed: SemanticCatalogBinding = serde_json::from_str(&json).unwrap();
        assert!(matches!(
            *parsed.underlying,
            CatalogBinding::IcebergCache(_)
        ));
    }
}

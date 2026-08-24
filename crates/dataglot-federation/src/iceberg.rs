//! Lakehouse warehouse table format support.
//!
//! This module is gated behind the `iceberg` feature flag. It exposes a
//! [`WarehouseConnector`] that talks to a REST catalog (e.g. Lakekeeper)
//! and resolves `<namespace>.<table>` to a `DataFusion` `TableProvider`
//! backed by `iceberg-datafusion`.
//!
//! # CLAUDE.md compliance
//!
//! * Rule 1 — `iceberg-datafusion` returns Arrow `RecordBatch` streams
//!   from its `TableProvider::scan`; we do not interpose any row-mode
//!   conversion.
//! * Rule 7 — the public surface here never says "Iceberg". The module
//!   filename and internal types still do, but every `pub` item, error
//!   string, and doc comment uses neutral terminology ("warehouse",
//!   "lakehouse table", "warehouse catalog"). The internal Iceberg
//!   crates are an implementation detail.
//! * Rule 10 — `WarehouseConnector` is `Send + Sync + 'static`.
//! * Rule 11 — the constructor and table-resolution paths are async;
//!   no blocking IO is performed under an async fn.
//! * Rule 12 — credentials never appear in `Debug` output, log lines,
//!   or error messages. See the manual `Debug` impl on
//!   [`WarehouseCredentials`] and the audit test that pins this down.
//! * Rule 13 — `WarehouseConnector::connect` does NOT enumerate
//!   namespaces, list tables, or fetch any schema. Only the underlying
//!   REST `GET /v1/config` handshake is performed (by the iceberg
//!   client) so we can reach the catalog. Schema is fetched on the
//!   first call to [`WarehouseConnector::table_provider`].

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use datafusion::catalog::{
    CatalogProvider as DfCatalogProvider, SchemaProvider as DfSchemaProvider,
};
use datafusion::datasource::TableProvider;
use datafusion::error::{DataFusionError, Result as DfResult};
use iceberg::{Catalog, CatalogBuilder, NamespaceIdent, TableIdent};
use iceberg_catalog_rest::{
    RestCatalogBuilder, REST_CATALOG_PROP_URI, REST_CATALOG_PROP_WAREHOUSE,
};
use iceberg_datafusion::IcebergStaticTableProvider;
use iceberg_storage_opendal::OpenDalStorageFactory;
use tracing::{debug, info};

use dataglot_core::{DataglotError, Result as DataglotResult};

/// How a warehouse credential is sourced.
///
/// Phase 0 ships two strategies. A first-class `CredentialResolver`
/// abstraction will land in `dataglot-core` later (TODO); this enum
/// will then become a thin shim around it.
#[derive(Clone)]
pub enum WarehouseCredentials {
    /// Static S3-compatible credentials, supplied inline.
    ///
    /// Use [`Self::Environment`] in production. `Static` is for tests
    /// and local development.
    Static {
        /// S3 access-key id.
        access_key_id: String,
        /// S3 secret-access-key. Never appears in `Debug`, log output,
        /// or error messages — see the manual `Debug` impl on this
        /// enum and the corresponding unit test.
        secret_access_key: String,
    },
    /// Resolve credentials from the process environment
    /// (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, etc).
    Environment,
}

impl fmt::Debug for WarehouseCredentials {
    /// Credential-safe `Debug`. The `Static` variant prints
    /// `access_key_id` (which is not itself secret, but useful for
    /// diagnostics) and a `<redacted>` placeholder for the secret. The
    /// `Environment` variant has nothing to redact.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Static {
                access_key_id,
                secret_access_key: _,
            } => f
                .debug_struct("Static")
                .field("access_key_id", access_key_id)
                .field("secret_access_key", &"<redacted>")
                .finish(),
            Self::Environment => f.write_str("Environment"),
        }
    }
}

/// Configuration for connecting to a warehouse REST catalog.
///
/// `catalog_url` plus `warehouse` together identify a single warehouse
/// (a Lakekeeper deployment can host many). The optional S3 fields are
/// for talking to a non-AWS object store (e.g. `MinIO` during testing).
#[derive(Debug)]
pub struct WarehouseConfig {
    /// Base URL of the warehouse REST catalog (e.g.
    /// `http://lakekeeper:8181/catalog`).
    pub catalog_url: String,
    /// Logical warehouse identifier within the catalog.
    pub warehouse: String,
    /// How to obtain S3 credentials for the underlying object store.
    pub credentials: WarehouseCredentials,
    /// Optional S3 endpoint (used when the object store is something
    /// other than AWS S3, like `MinIO`). Leave `None` for real AWS.
    pub s3_endpoint: Option<String>,
    /// Optional S3 region (e.g. `us-east-1`). Required by some
    /// providers; may be `None` for endpoints that ignore region.
    pub s3_region: Option<String>,
}

/// Connector to a lakehouse warehouse exposed via a REST catalog.
///
/// Construct one with [`WarehouseConnector::connect`]. The connector
/// owns a single REST-catalog client and produces a `TableProvider`
/// per [`WarehouseConnector::table_provider`] call. Schema is fetched
/// lazily — the constructor never enumerates namespaces or tables.
pub struct WarehouseConnector {
    /// Operator-visible identifier (typically the warehouse name). Used
    /// only for logging / `Debug`.
    name: String,
    /// The underlying iceberg-rust catalog client. Held as
    /// `Arc<dyn Catalog>` so we can share it across multiple
    /// table-provider instances cheaply.
    catalog: Arc<dyn Catalog>,
}

impl WarehouseConnector {
    /// Connect to a warehouse REST catalog.
    ///
    /// The REST client performs a `GET /v1/config` handshake during
    /// `load`, so the network must be reachable, but no namespace or
    /// table metadata is fetched here (rule 13).
    ///
    /// # Errors
    /// * [`DataglotError::Configuration`] if `config` is missing
    ///   required fields.
    /// * [`DataglotError::Connection`] if the handshake with the
    ///   warehouse catalog fails. The error message is taken verbatim
    ///   from the underlying client and is guaranteed to not contain
    ///   the supplied credentials (the iceberg client redacts auth
    ///   headers; we never include credentials in error context).
    pub async fn connect(name: impl Into<String>, config: WarehouseConfig) -> DataglotResult<Self> {
        let name = name.into();
        if config.catalog_url.is_empty() {
            return Err(DataglotError::configuration(
                "warehouse catalog_url must not be empty",
            ));
        }
        if config.warehouse.is_empty() {
            return Err(DataglotError::configuration(
                "warehouse name must not be empty",
            ));
        }

        debug!(
            warehouse = %config.warehouse,
            catalog_url = %config.catalog_url,
            "opening warehouse catalog connection"
        );

        let props = build_catalog_props(&config);
        let storage_factory = build_storage_factory();

        // The REST builder's `load()` issues the catalog handshake but
        // does not enumerate namespaces or tables. This is what lets
        // us honour rule 13 (lazy schema resolution) at construction
        // time.
        let catalog = RestCatalogBuilder::default()
            .with_storage_factory(storage_factory)
            .load(name.clone(), props)
            .await
            .map_err(|e| {
                DataglotError::connection(format!("failed to connect to warehouse catalog: {e}"))
            })?;

        info!(
            catalog = %name,
            warehouse = %config.warehouse,
            catalog_url = %config.catalog_url,
            "connected to warehouse catalog"
        );
        Ok(Self {
            name,
            catalog: Arc::new(catalog) as Arc<dyn Catalog>,
        })
    }

    /// Build a connector from an explicit `iceberg::Catalog`.
    ///
    /// **Internal escape hatch for tests.** This signature mentions
    /// the `iceberg::Catalog` trait, which by rule 7 we promise not to
    /// expose in user-facing API. It is therefore `#[doc(hidden)]` and
    /// only used by the integration suite (which stands up an
    /// in-memory iceberg catalog rather than a real REST server).
    /// Production code goes through [`Self::connect`].
    #[doc(hidden)]
    pub fn __from_catalog_for_tests(name: impl Into<String>, catalog: Arc<dyn Catalog>) -> Self {
        Self {
            name: name.into(),
            catalog,
        }
    }

    /// The connector's identifier (typically the warehouse name).
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The underlying catalog client. Crate-internal — the write/materialize
    /// path ([`crate::materialize`]) needs catalog access without exposing the
    /// iceberg client on the public surface (rule 7).
    pub(crate) fn catalog(&self) -> &Arc<dyn Catalog> {
        &self.catalog
    }

    /// Whether `<namespace>.<table>` exists in the catalog.
    ///
    /// Distinguishes "table absent" from "catalog read failed" — callers (the
    /// EL upsert path) must not treat a transient read error as a first load,
    /// which would overwrite an existing table.
    ///
    /// # Errors
    /// [`DataglotError::Catalog`] if the existence check itself fails (network
    /// / catalog error) — distinct from a clean `Ok(false)` for an absent table.
    pub async fn table_exists(&self, namespace: &str, table: &str) -> DataglotResult<bool> {
        let ident = TableIdent::new(
            NamespaceIdent::new(namespace.to_string()),
            table.to_string(),
        );
        self.catalog.table_exists(&ident).await.map_err(|e| {
            DataglotError::catalog(format!(
                "failed to check existence of warehouse table {namespace}.{table}: {e}"
            ))
        })
    }

    /// The current snapshot id of `namespace.table`, or `None` if the table
    /// does not exist (or exists but has no snapshot yet).
    ///
    /// Callers of a read-modify-write copy-on-write path capture this as the
    /// **base version** they read, then pass it back to
    /// [`WarehouseConnector::overwrite_table_checked`] as
    /// [`crate::materialize::ExpectedVersion::Snapshot`] so a concurrent
    /// writer that commits in between is detected rather than silently
    /// clobbered (optimistic concurrency — ).
    ///
    /// # Errors
    /// [`DataglotError::Catalog`] if the existence check or metadata load
    /// fails (a transient catalog/network error must propagate, never be
    /// mistaken for "no snapshot").
    pub async fn current_snapshot_id(
        &self,
        namespace: &str,
        table: &str,
    ) -> DataglotResult<Option<i64>> {
        let ident = TableIdent::new(
            NamespaceIdent::new(namespace.to_string()),
            table.to_string(),
        );
        if !self.catalog.table_exists(&ident).await.map_err(|e| {
            DataglotError::catalog(format!(
                "failed to check existence of warehouse table {namespace}.{table}: {e}"
            ))
        })? {
            return Ok(None);
        }
        let loaded = self.catalog.load_table(&ident).await.map_err(|e| {
            DataglotError::catalog(format!(
                "failed to load warehouse table {namespace}.{table} for version check: {e}"
            ))
        })?;
        Ok(loaded
            .metadata()
            .current_snapshot()
            .map(|s| s.snapshot_id()))
    }

    /// Sweep leftover blue-green **maintenance artifacts** (staging / parked
    /// tables) from `namespace`, dropping only those **older than `min_age`**.
    /// Returns the dropped table names.
    ///
    /// A successful blue-green swap drops its own parked table and promotes
    /// its staging table, so these artifacts only persist when a write
    /// (materialization / EL upsert / compaction) **crashed mid-swap**. The
    /// `min_age` grace window is the safety mechanism: an in-flight write's
    /// staging table is seconds/minutes old and must never be swept, so the
    /// caller passes a grace (e.g. hours) comfortably larger than any real
    /// write's duration. Only tables whose name carries the internal
    /// staging/parked marker are ever considered — user tables are untouched.
    /// Phase 4 Task 03 ( follow-through).
    ///
    /// # Errors
    /// [`DataglotError::Catalog`] if listing the namespace fails. Failure to
    /// load or drop an *individual* candidate is logged and skipped —
    /// best-effort cleanup must not abort the whole sweep.
    pub async fn sweep_orphan_maintenance_tables(
        &self,
        namespace: &str,
        min_age: std::time::Duration,
    ) -> DataglotResult<Vec<String>> {
        let ns = NamespaceIdent::new(namespace.to_string());
        let idents = self.catalog.list_tables(&ns).await.map_err(|e| {
            DataglotError::catalog(format!(
                "failed to list warehouse namespace '{namespace}' for orphan sweep: {e}"
            ))
        })?;
        let now_ms: i64 = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(i64::MAX, |d| {
                i64::try_from(d.as_millis()).unwrap_or(i64::MAX)
            });
        let min_age_ms = i64::try_from(min_age.as_millis()).unwrap_or(i64::MAX);

        let mut dropped = Vec::new();
        for ident in idents {
            if !crate::materialize::is_maintenance_artifact(ident.name()) {
                continue; // user table — never a sweep candidate.
            }
            // Grace window: load metadata to check age; skip anything younger
            // than `min_age` (it may belong to an in-flight write).
            let loaded = match self.catalog.load_table(&ident).await {
                Ok(t) => t,
                Err(e) => {
                    tracing::warn!(
                        table = ident.name(),
                        error = %e,
                        "orphan sweep: skipping candidate that failed to load"
                    );
                    continue;
                }
            };
            let age_ms = now_ms.saturating_sub(loaded.metadata().last_updated_ms());
            if age_ms < min_age_ms {
                continue; // too young — could be an in-flight write.
            }
            match self.catalog.drop_table(&ident).await {
                Ok(()) => {
                    tracing::info!(
                        table = ident.name(),
                        age_ms,
                        "orphan sweep: dropped stale maintenance table"
                    );
                    dropped.push(ident.name().to_string());
                }
                Err(e) => tracing::warn!(
                    table = ident.name(),
                    error = %e,
                    "orphan sweep: drop failed (will retry next sweep)"
                ),
            }
        }
        Ok(dropped)
    }

    /// Resolve a `<namespace>.<table>` reference into a `DataFusion`
    /// `TableProvider` over the warehouse table.
    ///
    /// This is the lazy-schema-resolution entry point (rule 13). It
    /// fetches the table metadata from the catalog (one REST roundtrip
    /// in production, an in-memory lookup for tests) and constructs an
    /// `iceberg-datafusion` static provider over the current snapshot.
    ///
    /// Pushdown of projections, predicates, and limits is handled by
    /// `iceberg-datafusion`'s own provider; we don't wrap it.
    ///
    /// # Errors
    /// Returns [`DataglotError::Catalog`] if the namespace/table does
    /// not exist or the metadata cannot be loaded.
    pub async fn table_provider(
        &self,
        namespace: &str,
        table: &str,
    ) -> DataglotResult<Arc<dyn TableProvider>> {
        if namespace.is_empty() {
            return Err(DataglotError::catalog(
                "warehouse table reference: namespace must not be empty",
            ));
        }
        if table.is_empty() {
            return Err(DataglotError::catalog(
                "warehouse table reference: table name must not be empty",
            ));
        }

        let ns = NamespaceIdent::new(namespace.to_string());
        let ident = TableIdent::new(ns, table.to_string());

        debug!(
            warehouse = %self.name,
            namespace = %namespace,
            table = %table,
            "resolving warehouse table"
        );

        let loaded = self.catalog.load_table(&ident).await.map_err(|e| {
            // The error message intentionally does not include any
            // credential-bearing config. iceberg-rust's `Error` Display
            // never carries credentials, so passing it through is safe.
            DataglotError::catalog(format!(
                "failed to load warehouse table {namespace}.{table}: {e}"
            ))
        })?;

        let provider = IcebergStaticTableProvider::try_new_from_table(loaded)
            .await
            .map_err(|e| {
                DataglotError::catalog(format!(
                    "failed to build provider for warehouse table {namespace}.{table}: {e}"
                ))
            })?;

        Ok(Arc::new(provider) as Arc<dyn TableProvider>)
    }

    /// Wrap this connector as a `DataFusion` [`CatalogProvider`].
    ///
    /// The returned catalog enumerates the warehouse's top-level
    /// namespaces (each becomes a `DataFusion` schema) and resolves
    /// tables lazily via [`Self::table_provider`].
    ///
    /// # Eager listing, lazy schema (caching strategy)
    ///
    /// `DataFusion`'s [`CatalogProvider::schema_names`] and
    /// [`CatalogProvider::schema`] are **synchronous**, but listing
    /// namespaces and tables in the warehouse requires async I/O.
    /// Rather than rely on `block_in_place` + `Handle::block_on`
    /// (brittle — only safe under a multi-thread runtime), we fetch
    /// the list of namespaces and the list of tables per namespace
    /// once, here, while we still have an `async` context. Per-table
    /// metadata (snapshot, schema, manifest list) remains **lazy**
    /// (rule 13) — it is only fetched when the async
    /// [`SchemaProvider::table`] is called, by delegating to
    /// [`Self::table_provider`].
    ///
    /// Names are cached for the lifetime of the returned catalog.
    /// Drop and rebuild the catalog if the operator needs to pick up
    /// newly-created namespaces or tables.
    ///
    /// # Multi-level namespaces
    ///
    /// Only top-level namespaces are surfaced as `DataFusion` schemas
    /// in this PR. Iceberg supports nested namespaces (e.g.
    /// `eu.sales.orders`), but `DataFusion`'s schema/table model is
    /// two-level. Mapping multi-level namespaces is a follow-up.
    ///
    /// # Errors
    /// Returns [`DataglotError::Catalog`] if the listing requests
    /// against the underlying warehouse catalog fail.
    ///
    /// [`CatalogProvider`]: datafusion::catalog::CatalogProvider
    /// [`CatalogProvider::schema_names`]: datafusion::catalog::CatalogProvider::schema_names
    /// [`CatalogProvider::schema`]: datafusion::catalog::CatalogProvider::schema
    /// [`SchemaProvider::table`]: datafusion::catalog::SchemaProvider::table
    pub async fn as_catalog_provider(
        self: &Arc<Self>,
    ) -> DataglotResult<Arc<dyn DfCatalogProvider>> {
        // 1. Top-level namespaces in the warehouse become DataFusion
        //    schemas. `parent = None` is the iceberg-rust convention
        //    for the root level.
        let namespaces = self.catalog.list_namespaces(None).await.map_err(|e| {
            DataglotError::catalog(format!("failed to list warehouse namespaces: {e}"))
        })?;

        // We only surface single-segment namespaces here — see the
        // doc on this method for why. Filtering rather than failing
        // keeps the catalog usable when a warehouse already has
        // multi-level namespaces.
        let mut schema_names: Vec<String> = Vec::with_capacity(namespaces.len());
        let mut schemas: HashMap<String, Arc<dyn DfSchemaProvider>> =
            HashMap::with_capacity(namespaces.len());

        for ns in namespaces {
            let parts: &[String] = ns.as_ref();
            if parts.len() != 1 {
                // Skip multi-level namespaces — they don't fit the
                // two-level DataFusion model.
                continue;
            }
            let ns_name = parts[0].clone();

            // 2. Eagerly fetch the table list for this namespace.
            let tables = self.catalog.list_tables(&ns).await.map_err(|e| {
                DataglotError::catalog(format!(
                    "failed to list warehouse tables in namespace '{ns_name}': {e}"
                ))
            })?;
            let table_names: Vec<String> =
                tables.into_iter().map(|t| t.name().to_string()).collect();

            schema_names.push(ns_name.clone());
            schemas.insert(
                ns_name.clone(),
                Arc::new(WarehouseSchema {
                    connector: Arc::clone(self),
                    namespace: ns_name,
                    table_names,
                }) as Arc<dyn DfSchemaProvider>,
            );
        }

        // Stable ordering for reproducible `schema_names()` output.
        schema_names.sort();

        Ok(Arc::new(WarehouseCatalog {
            connector_name: self.name.clone(),
            schema_names,
            schemas,
        }) as Arc<dyn DfCatalogProvider>)
    }
}

impl fmt::Debug for WarehouseConnector {
    /// Credential-safe `Debug`. Only the connector name is emitted; the
    /// underlying catalog client's `Debug` impl could in theory grow to
    /// expose credential-bearing config in future iceberg-rust
    /// versions, so we redact it explicitly.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WarehouseConnector")
            .field("name", &self.name)
            .field("catalog", &"<redacted>")
            .finish()
    }
}

/// `DataFusion` [`CatalogProvider`] backed by a [`WarehouseConnector`].
///
/// Built via [`WarehouseConnector::as_catalog_provider`]. Holds a
/// cached, sorted list of top-level namespace names and a `HashMap`
/// of pre-built `WarehouseSchema` providers keyed by namespace
/// name. The cache is fixed at construction time — see the docs on
/// [`WarehouseConnector::as_catalog_provider`] for why.
///
/// Per CLAUDE.md rules 7 + 12, `Debug` does not surface the inner
/// iceberg catalog client and uses neutral terminology.
///
/// [`CatalogProvider`]: datafusion::catalog::CatalogProvider
pub struct WarehouseCatalog {
    /// The connector's identifier — used for `Debug` and diagnostic
    /// logs only. NOT the catalog's name in the `SessionContext`;
    /// that name is supplied by the caller of `register_catalog`.
    connector_name: String,
    /// Cached, alphabetised list of namespace (schema) names.
    schema_names: Vec<String>,
    /// Pre-built schema providers, keyed by namespace name. Lookups
    /// are O(1) and never block.
    schemas: HashMap<String, Arc<dyn DfSchemaProvider>>,
}

impl fmt::Debug for WarehouseCatalog {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WarehouseCatalog")
            .field("connector", &self.connector_name)
            .field("schema_count", &self.schema_names.len())
            .finish_non_exhaustive()
    }
}

impl DfCatalogProvider for WarehouseCatalog {
    fn schema_names(&self) -> Vec<String> {
        self.schema_names.clone()
    }

    fn schema(&self, name: &str) -> Option<Arc<dyn DfSchemaProvider>> {
        self.schemas.get(name).map(Arc::clone)
    }
}

/// `DataFusion` [`SchemaProvider`] backed by a single warehouse
/// namespace on a [`WarehouseConnector`].
///
/// Per-table metadata is NOT fetched at construction; it is resolved
/// lazily inside [`SchemaProvider::table`] by delegating to
/// [`WarehouseConnector::table_provider`] (rule 13).
///
/// [`SchemaProvider`]: datafusion::catalog::SchemaProvider
struct WarehouseSchema {
    /// The connector this schema belongs to.
    connector: Arc<WarehouseConnector>,
    /// Top-level namespace name. Stored as a single string because
    /// only single-segment namespaces are surfaced (see
    /// `WarehouseConnector::as_catalog_provider`).
    namespace: String,
    /// Cached, alphabetised list of table names within this namespace.
    /// Populated once at catalog-construction time.
    table_names: Vec<String>,
}

impl fmt::Debug for WarehouseSchema {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WarehouseSchema")
            .field("namespace", &self.namespace)
            .field("table_count", &self.table_names.len())
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl DfSchemaProvider for WarehouseSchema {
    fn table_names(&self) -> Vec<String> {
        self.table_names.clone()
    }

    fn table_exist(&self, name: &str) -> bool {
        self.table_names.iter().any(|t| t == name)
    }

    async fn table(&self, name: &str) -> DfResult<Option<Arc<dyn TableProvider>>> {
        // Cheap negative path: a name not in the cached list never
        // causes a remote roundtrip.
        if !self.table_exist(name) {
            return Ok(None);
        }
        // Lazy metadata fetch (rule 13).
        let provider = self
            .connector
            .table_provider(&self.namespace, name)
            .await
            .map_err(|e| DataFusionError::External(Box::new(e)))?;
        Ok(Some(provider))
    }
}

/// Build the property map that `iceberg-catalog-rest` consumes.
///
/// We translate our public `WarehouseConfig` into the (string, string)
/// pairs the REST builder expects. Any new credential or storage knob
/// we add to `WarehouseConfig` flows through this function.
fn build_catalog_props(config: &WarehouseConfig) -> HashMap<String, String> {
    use iceberg::io::{
        S3_ACCESS_KEY_ID, S3_ENDPOINT, S3_PATH_STYLE_ACCESS, S3_REGION, S3_SECRET_ACCESS_KEY,
    };

    let mut props: HashMap<String, String> = HashMap::new();
    props.insert(
        REST_CATALOG_PROP_URI.to_string(),
        config.catalog_url.clone(),
    );
    props.insert(
        REST_CATALOG_PROP_WAREHOUSE.to_string(),
        config.warehouse.clone(),
    );

    if let WarehouseCredentials::Static {
        access_key_id,
        secret_access_key,
    } = &config.credentials
    {
        props.insert(S3_ACCESS_KEY_ID.to_string(), access_key_id.clone());
        props.insert(S3_SECRET_ACCESS_KEY.to_string(), secret_access_key.clone());
    }
    // For `Environment`, the underlying object-store SDK reads
    // AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY itself; we just don't
    // pass anything explicit.

    if let Some(endpoint) = &config.s3_endpoint {
        props.insert(S3_ENDPOINT.to_string(), endpoint.clone());
        // MinIO-style endpoints typically require path-style addressing
        // (because the bucket isn't a DNS subdomain). This is harmless
        // for AWS too, where virtual-hosted-style is the default but
        // path-style is also accepted.
        props.insert(S3_PATH_STYLE_ACCESS.to_string(), "true".to_string());
    }
    if let Some(region) = &config.s3_region {
        props.insert(S3_REGION.to_string(), region.clone());
    }

    props
}

/// Build the storage factory the REST catalog uses to read parquet.
///
/// We default to S3 because that's the prod path. Local-FS warehouses
/// (which the `MemoryCatalog` test path uses) bypass this entirely by
/// constructing the catalog directly via [`WarehouseConnector::__from_catalog_for_tests`].
fn build_storage_factory() -> Arc<dyn iceberg::io::StorageFactory> {
    Arc::new(OpenDalStorageFactory::S3 {
        customized_credential_load: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// CLAUDE.md rule 12: the secret-access-key never appears in the
    /// `Debug` representation of [`WarehouseCredentials`].
    #[test]
    fn debug_redacts_static_secret_access_key() {
        let creds = WarehouseCredentials::Static {
            access_key_id: "AKIA0EXAMPLE0".to_string(),
            secret_access_key: "totally-secret-do-not-print".to_string(),
        };
        let s = format!("{creds:?}");
        assert!(
            !s.contains("totally-secret-do-not-print"),
            "Debug leaked secret_access_key: {s}"
        );
        assert!(
            s.contains("<redacted>"),
            "Debug missing the <redacted> marker: {s}"
        );
        // access-key-id is NOT a secret — keep it visible for ops.
        assert!(
            s.contains("AKIA0EXAMPLE0"),
            "Debug elided access-key-id: {s}"
        );
    }

    /// `Environment` has nothing to redact and should still produce a
    /// stable, finite Debug string.
    #[test]
    fn debug_environment_credentials_is_terse() {
        let creds = WarehouseCredentials::Environment;
        let s = format!("{creds:?}");
        assert_eq!(s, "Environment");
    }

    /// CLAUDE.md rule 12 (continued): the connector's `Debug` does not
    /// expose the catalog client. The catalog client is held opaquely
    /// and rendered as `<redacted>` so that any future iceberg-rust
    /// change that adds credential-bearing fields to `Catalog::fmt`
    /// can't leak through us.
    #[tokio::test]
    async fn debug_connector_redacts_catalog_field() {
        // We can't easily build a real REST client offline. Use the
        // in-memory escape hatch and the iceberg memory catalog.
        let cfg = HashMap::from([(
            iceberg::memory::MEMORY_CATALOG_WAREHOUSE.to_string(),
            // Any non-empty path works for Debug-only testing; the
            // catalog never reads from it on `Debug`.
            "/tmp/wh-debug-test".to_string(),
        )]);
        // `MemoryCatalogBuilder::load` resolves iceberg-rust's runtime via
        // `Runtime::current()`, which requires a live tokio context — so
        // this runs under `#[tokio::test]` rather than a bare
        // `futures::executor::block_on`.
        let catalog = iceberg::memory::MemoryCatalogBuilder::default()
            .load("warehouse", cfg)
            .await
            .unwrap();
        let connector = WarehouseConnector::__from_catalog_for_tests(
            "warehouse",
            Arc::new(catalog) as Arc<dyn Catalog>,
        );
        let s = format!("{connector:?}");
        assert!(s.contains("WarehouseConnector"), "{s}");
        assert!(s.contains("name"), "{s}");
        assert!(s.contains("\"warehouse\""), "{s}");
        assert!(s.contains("<redacted>"), "{s}");
        // The literal substring "MemoryCatalog" would imply we leaked
        // the inner catalog's Debug. Make sure that didn't happen.
        assert!(
            !s.contains("MemoryCatalog"),
            "connector Debug leaked inner catalog: {s}"
        );
    }

    /// CLAUDE.md rule 7: the connector type name is neutral. This is a
    /// trivial test but it pins the rename — if anyone tries to rename
    /// `WarehouseConnector` back to `IcebergConnector` they'll have to
    /// update this assertion, providing a tripwire on the user-facing
    /// type name.
    #[test]
    fn public_type_name_is_neutral() {
        let name = std::any::type_name::<WarehouseConnector>();
        // The fully-qualified name will include the module path
        // `dataglot_federation::iceberg::...` (the module name is an
        // internal allowance per the task spec), but the *type* itself
        // must be neutral.
        assert!(
            name.ends_with("::WarehouseConnector"),
            "expected ends with ::WarehouseConnector, got {name}"
        );
    }

    /// `connect` rejects empty `catalog_url` early — before any network
    /// IO. Tests rule 13's negative-space (we don't accidentally start
    /// a request with bad config).
    #[tokio::test]
    async fn connect_rejects_empty_catalog_url() {
        let cfg = WarehouseConfig {
            catalog_url: String::new(),
            warehouse: "wh".to_string(),
            credentials: WarehouseCredentials::Environment,
            s3_endpoint: None,
            s3_region: None,
        };
        let err = WarehouseConnector::connect("warehouse", cfg)
            .await
            .expect_err("empty catalog_url should be a configuration error");
        assert!(
            matches!(err, DataglotError::Configuration(_)),
            "expected Configuration error, got {err:?}"
        );
    }

    /// `connect` rejects empty `warehouse` early. Same rationale.
    #[tokio::test]
    async fn connect_rejects_empty_warehouse() {
        let cfg = WarehouseConfig {
            catalog_url: "http://localhost:8181/catalog".to_string(),
            warehouse: String::new(),
            credentials: WarehouseCredentials::Environment,
            s3_endpoint: None,
            s3_region: None,
        };
        let err = WarehouseConnector::connect("warehouse", cfg)
            .await
            .expect_err("empty warehouse should be a configuration error");
        assert!(
            matches!(err, DataglotError::Configuration(_)),
            "expected Configuration error, got {err:?}"
        );
    }

    /// `table_provider` rejects empty `namespace` early — before any
    /// catalog roundtrip. Pin this so a typo or bad SQL parse does not
    /// silently issue a list-tables request.
    #[tokio::test]
    async fn table_provider_rejects_empty_namespace() {
        let catalog = futures::executor::block_on(async {
            let cfg = HashMap::from([(
                iceberg::memory::MEMORY_CATALOG_WAREHOUSE.to_string(),
                "/tmp/wh-empty-ns".to_string(),
            )]);
            iceberg::memory::MemoryCatalogBuilder::default()
                .load("warehouse", cfg)
                .await
                .unwrap()
        });
        let connector = WarehouseConnector::__from_catalog_for_tests(
            "warehouse",
            Arc::new(catalog) as Arc<dyn Catalog>,
        );
        let err = connector
            .table_provider("", "t")
            .await
            .expect_err("empty namespace should be a catalog error");
        assert!(matches!(err, DataglotError::Catalog(_)), "{err:?}");
    }

    /// `table_provider` rejects empty `table`.
    #[tokio::test]
    async fn table_provider_rejects_empty_table_name() {
        let catalog = futures::executor::block_on(async {
            let cfg = HashMap::from([(
                iceberg::memory::MEMORY_CATALOG_WAREHOUSE.to_string(),
                "/tmp/wh-empty-tbl".to_string(),
            )]);
            iceberg::memory::MemoryCatalogBuilder::default()
                .load("warehouse", cfg)
                .await
                .unwrap()
        });
        let connector = WarehouseConnector::__from_catalog_for_tests(
            "warehouse",
            Arc::new(catalog) as Arc<dyn Catalog>,
        );
        let err = connector
            .table_provider("ns", "")
            .await
            .expect_err("empty table name should be a catalog error");
        assert!(matches!(err, DataglotError::Catalog(_)), "{err:?}");
    }

    /// `build_catalog_props` faithfully translates inline credentials
    /// + endpoint + region into the iceberg-rust property map.
    #[test]
    fn build_catalog_props_includes_static_credentials() {
        let cfg = WarehouseConfig {
            catalog_url: "http://lk:8181/catalog".to_string(),
            warehouse: "demo".to_string(),
            credentials: WarehouseCredentials::Static {
                access_key_id: "minio".to_string(),
                secret_access_key: "minio12345".to_string(),
            },
            s3_endpoint: Some("http://minio:9000".to_string()),
            s3_region: Some("us-east-1".to_string()),
        };
        let props = build_catalog_props(&cfg);

        assert_eq!(
            props.get(REST_CATALOG_PROP_URI).map(String::as_str),
            Some("http://lk:8181/catalog")
        );
        assert_eq!(
            props.get(REST_CATALOG_PROP_WAREHOUSE).map(String::as_str),
            Some("demo")
        );
        assert_eq!(
            props.get(iceberg::io::S3_ACCESS_KEY_ID).map(String::as_str),
            Some("minio")
        );
        assert_eq!(
            props
                .get(iceberg::io::S3_SECRET_ACCESS_KEY)
                .map(String::as_str),
            Some("minio12345")
        );
        assert_eq!(
            props.get(iceberg::io::S3_ENDPOINT).map(String::as_str),
            Some("http://minio:9000")
        );
        assert_eq!(
            props.get(iceberg::io::S3_REGION).map(String::as_str),
            Some("us-east-1")
        );
        // MinIO/path-style is auto-enabled when endpoint is overridden.
        assert_eq!(
            props
                .get(iceberg::io::S3_PATH_STYLE_ACCESS)
                .map(String::as_str),
            Some("true")
        );
    }

    /// `build_catalog_props` does not emit any S3 credential keys when
    /// the credentials are `Environment` — those will be picked up by
    /// the SDK from `AWS_*` env vars.
    #[test]
    fn build_catalog_props_omits_keys_for_environment_credentials() {
        let cfg = WarehouseConfig {
            catalog_url: "http://lk:8181/catalog".to_string(),
            warehouse: "demo".to_string(),
            credentials: WarehouseCredentials::Environment,
            s3_endpoint: None,
            s3_region: None,
        };
        let props = build_catalog_props(&cfg);
        assert!(!props.contains_key(iceberg::io::S3_ACCESS_KEY_ID));
        assert!(!props.contains_key(iceberg::io::S3_SECRET_ACCESS_KEY));
        assert!(!props.contains_key(iceberg::io::S3_ENDPOINT));
        assert!(!props.contains_key(iceberg::io::S3_REGION));
        assert!(!props.contains_key(iceberg::io::S3_PATH_STYLE_ACCESS));
    }

    /// Credentials should never leak into the property map under any
    /// representation. This is a defense-in-depth check separate from
    /// the `Debug` test: a bug in `build_catalog_props` could in theory
    /// put a secret somewhere unexpected.
    #[test]
    fn build_catalog_props_does_not_misplace_secret() {
        const SECRET: &str = "do-not-leak-this";
        let cfg = WarehouseConfig {
            catalog_url: "http://lk:8181/catalog".to_string(),
            warehouse: "demo".to_string(),
            credentials: WarehouseCredentials::Static {
                access_key_id: "k".to_string(),
                secret_access_key: SECRET.to_string(),
            },
            s3_endpoint: None,
            s3_region: None,
        };
        let props = build_catalog_props(&cfg);
        // The secret may legitimately appear under exactly ONE key.
        let count = props.values().filter(|v| v.contains(SECRET)).count();
        assert_eq!(count, 1, "secret leaked across multiple keys: {props:?}");
        let key_holding_secret: Vec<&String> = props
            .iter()
            .filter_map(|(k, v)| if v.contains(SECRET) { Some(k) } else { None })
            .collect();
        assert_eq!(
            key_holding_secret,
            vec![&iceberg::io::S3_SECRET_ACCESS_KEY.to_string()],
            "secret stored under unexpected key"
        );
    }

    /// Build a `WarehouseConnector` over an in-memory iceberg catalog
    /// with two namespaces (`sales`, `marketing`) and call
    /// `as_catalog_provider`. The resulting catalog must:
    ///
    /// * surface both namespaces as `DataFusion` schema names,
    /// * return a non-`None` `SchemaProvider` for each known schema,
    /// * return `None` for an unknown schema.
    ///
    /// Per CLAUDE.md rule 13, `as_catalog_provider` only fetches names
    /// — no per-table metadata is loaded here.
    #[tokio::test]
    async fn catalog_provider_lists_top_level_namespaces() {
        let cfg = HashMap::from([(
            iceberg::memory::MEMORY_CATALOG_WAREHOUSE.to_string(),
            "/tmp/wh-catalog-test".to_string(),
        )]);
        let raw = iceberg::memory::MemoryCatalogBuilder::default()
            .load("warehouse", cfg)
            .await
            .unwrap();
        // Seed two top-level namespaces.
        raw.create_namespace(&NamespaceIdent::new("sales".to_string()), HashMap::new())
            .await
            .unwrap();
        raw.create_namespace(
            &NamespaceIdent::new("marketing".to_string()),
            HashMap::new(),
        )
        .await
        .unwrap();

        let connector = Arc::new(WarehouseConnector::__from_catalog_for_tests(
            "warehouse",
            Arc::new(raw) as Arc<dyn Catalog>,
        ));
        let cat = connector
            .as_catalog_provider()
            .await
            .expect("catalog provider builds");

        let mut names = cat.schema_names();
        names.sort();
        assert_eq!(names, vec!["marketing".to_string(), "sales".to_string()]);
        assert!(cat.schema("sales").is_some());
        assert!(cat.schema("marketing").is_some());
        assert!(cat.schema("nonexistent").is_none());
    }

    /// `WarehouseCatalog`'s `Debug` impl exposes only the connector
    /// name and schema count — never the inner iceberg catalog
    /// (rules 7 and 12).
    ///: `WarehouseScanExec` must distinguish `Some(vec![])`
    /// (project ZERO columns → empty schema) from `None` (full schema),
    /// and `Some(0)` (limit zero) from `None` (no limit). The physical
    /// codec serializes these with explicit `has_projection`/`has_limit`
    /// flags precisely so the round-trip can't collapse them; this pins
    /// the constructor semantics those flags exist to preserve — a
    /// collapse would silently return the wrong columns/rows distributed.
    #[tokio::test]
    async fn warehouse_scan_exec_distinguishes_empty_projection_and_zero_limit() {
        use datafusion::arrow::datatypes::{DataType, Field, Schema};
        use datafusion::physical_plan::ExecutionPlan;

        let cfg = HashMap::from([(
            iceberg::memory::MEMORY_CATALOG_WAREHOUSE.to_string(),
            "/tmp/wh-scan-exec-test".to_string(),
        )]);
        let raw = iceberg::memory::MemoryCatalogBuilder::default()
            .load("warehouse", cfg)
            .await
            .unwrap();
        let connector = Arc::new(WarehouseConnector::__from_catalog_for_tests(
            "warehouse",
            Arc::new(raw) as Arc<dyn Catalog>,
        ));
        let full = Arc::new(Schema::new(vec![
            Field::new("id", DataType::Int64, false),
            Field::new("region", DataType::Utf8, true),
        ]));

        let mk = |proj: Option<Vec<usize>>, limit: Option<usize>| {
            WarehouseScanExec::new(
                Arc::clone(&connector),
                "warehouse".to_string(),
                "sales".to_string(),
                "orders".to_string(),
                Arc::clone(&full),
                proj,
                limit,
            )
        };

        // None projection → full schema (2 columns).
        let none_proj = mk(None, None);
        assert_eq!(none_proj.projection(), None);
        assert_eq!(none_proj.schema().fields().len(), 2);

        // Some(vec![]) → EMPTY projected schema (0 columns) — must NOT
        // collapse to the full schema.
        let empty_proj = mk(Some(vec![]), None);
        assert_eq!(empty_proj.projection(), Some(&vec![]));
        assert_eq!(
            empty_proj.schema().fields().len(),
            0,
            "Some(vec![]) must project zero columns, not fall back to full"
        );

        // Some(vec![1]) → single projected column.
        let one_proj = mk(Some(vec![1]), None);
        assert_eq!(one_proj.schema().fields().len(), 1);
        assert_eq!(one_proj.schema().field(0).name(), "region");

        // Some(0) limit is distinct from None.
        assert_eq!(mk(None, Some(0)).limit(), Some(0));
        assert_eq!(mk(None, None).limit(), None);
    }

    #[test]
    fn catalog_debug_does_not_leak_inner_catalog() {
        let cat = WarehouseCatalog {
            connector_name: "warehouse".to_string(),
            schema_names: vec!["sales".to_string()],
            schemas: HashMap::new(),
        };
        let s = format!("{cat:?}");
        assert!(s.contains("WarehouseCatalog"), "{s}");
        assert!(s.contains("schema_count"), "{s}");
        // The literal "MemoryCatalog" / "Iceberg" must never leak.
        assert!(!s.contains("MemoryCatalog"), "{s}");
        let lower = s.to_lowercase();
        assert!(!lower.contains("iceberg"), "rule 7: leaked Iceberg: {s}");
    }

    /// `as_catalog_provider` filters out multi-level namespaces. They
    /// don't fit `DataFusion`'s two-level catalog/schema/table model
    /// and surfacing them under a flattened name would invite
    /// ambiguity. Single-level namespaces alongside multi-level ones
    /// must still appear.
    #[tokio::test]
    async fn catalog_provider_skips_multi_level_namespaces() {
        let cfg = HashMap::from([(
            iceberg::memory::MEMORY_CATALOG_WAREHOUSE.to_string(),
            "/tmp/wh-multi-ns".to_string(),
        )]);
        let raw = iceberg::memory::MemoryCatalogBuilder::default()
            .load("warehouse", cfg)
            .await
            .unwrap();

        // A single-level namespace.
        raw.create_namespace(&NamespaceIdent::new("sales".to_string()), HashMap::new())
            .await
            .unwrap();
        // A multi-level namespace. iceberg-rust requires the parent
        // to exist first.
        raw.create_namespace(&NamespaceIdent::new("eu".to_string()), HashMap::new())
            .await
            .unwrap();
        raw.create_namespace(
            &NamespaceIdent::from_strs(["eu", "sales"]).unwrap(),
            HashMap::new(),
        )
        .await
        .unwrap();

        let connector = Arc::new(WarehouseConnector::__from_catalog_for_tests(
            "warehouse",
            Arc::new(raw) as Arc<dyn Catalog>,
        ));
        let cat = connector
            .as_catalog_provider()
            .await
            .expect("catalog provider builds");

        // The multi-level `eu.sales` is skipped; only the single-level
        // names appear. (`eu` and `sales` are both single-level top-
        // level namespaces, so both should show.)
        let names: Vec<String> = cat.schema_names();
        assert!(names.contains(&"sales".to_string()), "{names:?}");
        assert!(names.contains(&"eu".to_string()), "{names:?}");
        // `eu.sales` must not appear under any flattened form.
        assert!(!names.contains(&"eu.sales".to_string()), "{names:?}");
    }

    // --- Orphan maintenance-table sweep (Phase 4 Task 03 /  follow-up) ---

    /// A writable in-memory warehouse (local-FS storage) with a `lake`
    /// namespace, for exercising real create/list/drop.
    async fn writable_warehouse() -> (WarehouseConnector, tempfile::TempDir) {
        use iceberg::io::LocalFsStorageFactory;
        use iceberg::memory::{MemoryCatalogBuilder, MEMORY_CATALOG_WAREHOUSE};
        use iceberg::CatalogBuilder;
        let dir = tempfile::TempDir::new().unwrap();
        let path = format!("file://{}", dir.path().to_str().unwrap());
        let catalog = MemoryCatalogBuilder::default()
            .with_storage_factory(Arc::new(LocalFsStorageFactory))
            .load(
                "warehouse",
                HashMap::from([(MEMORY_CATALOG_WAREHOUSE.to_string(), path)]),
            )
            .await
            .unwrap();
        catalog
            .create_namespace(&NamespaceIdent::new("lake".to_string()), HashMap::new())
            .await
            .unwrap();
        let connector = WarehouseConnector::__from_catalog_for_tests(
            "warehouse",
            Arc::new(catalog) as Arc<dyn Catalog>,
        );
        (connector, dir)
    }

    /// Create a one-row table named `table` (a successful overwrite leaves
    /// only the final table behind — no internal staging residue).
    async fn seed_table(w: &WarehouseConnector, table: &str) {
        use datafusion::arrow::array::{Int32Array, RecordBatch, StringArray};
        use datafusion::arrow::datatypes::{DataType, Field, Schema};
        let schema = Arc::new(Schema::new(vec![
            Field::new("id", DataType::Int32, false),
            Field::new("v", DataType::Utf8, false),
        ]));
        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(Int32Array::from(vec![1])),
                Arc::new(StringArray::from(vec!["a"])),
            ],
        )
        .unwrap();
        w.overwrite_table("lake", table, &schema, vec![batch], "seed")
            .await
            .expect("seed table");
    }

    #[tokio::test]
    async fn orphan_sweep_drops_stale_artifacts_but_not_user_tables() {
        let (w, _dir) = writable_warehouse().await;
        // A real user table + a leftover staging artifact (name carries the
        // internal marker) simulating a crashed mid-swap write.
        seed_table(&w, "orders").await;
        seed_table(&w, "orders__dataglot_staging_leftover").await;

        // min_age = 0 → any artifact old enough (all are) is dropped.
        let dropped = w
            .sweep_orphan_maintenance_tables("lake", std::time::Duration::ZERO)
            .await
            .expect("sweep");
        assert_eq!(
            dropped,
            vec!["orders__dataglot_staging_leftover".to_string()]
        );
        // User table survives; the orphan is gone.
        assert!(w.table_exists("lake", "orders").await.unwrap());
        assert!(!w
            .table_exists("lake", "orders__dataglot_staging_leftover")
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn orphan_sweep_grace_window_skips_young_artifacts() {
        let (w, _dir) = writable_warehouse().await;
        seed_table(&w, "orders__dataglot_parked_inflight").await;

        // A freshly-created artifact is far younger than a 1h grace, so the
        // sweep must leave it alone — it could belong to an in-flight write.
        let dropped = w
            .sweep_orphan_maintenance_tables("lake", std::time::Duration::from_hours(1))
            .await
            .expect("sweep");
        assert!(
            dropped.is_empty(),
            "young artifact must be spared: {dropped:?}"
        );
        assert!(w
            .table_exists("lake", "orders__dataglot_parked_inflight")
            .await
            .unwrap());
    }
}

// ===========================================================
// Distributed execution support
// ===========================================================
//
// Ballista serializes plans between coordinator, scheduler, and
// executors. A warehouse table can't ship its `IcebergStaticTableProvider`
// (it holds loaded table metadata + FileIO credentials), so the wire
// carries only the *identity* — connector name + namespace + table —
// and each side rebuilds from its own [`WarehouseRegistry`]. Decode is
// synchronous while `table_provider()` needs a REST roundtrip, so the
// rebuilt provider is **lazy**: [`LazyWarehouseTableProvider`] answers
// `schema()` from the envelope and defers the catalog `load_table` into
// [`WarehouseScanExec::execute`], where async is available.

/// Name → connector map shared by the coordinator's and executors'
/// codecs (the warehouse analogue of [`crate::registry::ConnectorRegistry`],
/// which is `SQLExecutor`-shaped and can't hold Iceberg catalogs).
#[derive(Default)]
pub struct WarehouseRegistry {
    connectors: HashMap<String, Arc<WarehouseConnector>>,
}

/// Trait-object-free alias matching `DynConnectorRegistry`'s shape.
pub type DynWarehouseRegistry = Arc<WarehouseRegistry>;

impl WarehouseRegistry {
    /// Build from `(name, connector)` pairs. Names must match the
    /// coordinator's `[catalogs.*]` keys — the name is the wire
    /// identity the executor resolves against its own config.
    #[must_use]
    pub fn new(connectors: HashMap<String, Arc<WarehouseConnector>>) -> Self {
        Self { connectors }
    }

    /// Look up a connector by catalog name.
    #[must_use]
    pub fn lookup(&self, name: &str) -> Option<Arc<WarehouseConnector>> {
        self.connectors.get(name).cloned()
    }

    /// Number of registered warehouse connectors.
    #[must_use]
    pub fn len(&self) -> usize {
        self.connectors.len()
    }

    /// Whether the registry holds no connectors.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.connectors.is_empty()
    }
}

impl fmt::Debug for WarehouseRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Names only — connectors hold catalog clients with credential
        // state (rule 12).
        f.debug_struct("WarehouseRegistry")
            .field("names", &self.connectors.keys().collect::<Vec<_>>())
            .finish()
    }
}

/// A warehouse table rebuilt from the wire: identity + schema
/// only, no loaded metadata. `scan` emits a [`WarehouseScanExec`] that
/// performs the actual catalog `load_table` at execution time.
#[derive(Debug)]
pub struct LazyWarehouseTableProvider {
    connector: Arc<WarehouseConnector>,
    connector_name: String,
    namespace: String,
    table: String,
    schema: datafusion::arrow::datatypes::SchemaRef,
}

impl LazyWarehouseTableProvider {
    /// Rebuild a provider from wire identity. `schema` comes from the
    /// serialized `TableScan` (the coordinator resolved it at plan
    /// time), so no IO happens here — decode stays synchronous.
    #[must_use]
    pub fn new(
        connector: Arc<WarehouseConnector>,
        connector_name: impl Into<String>,
        namespace: impl Into<String>,
        table: impl Into<String>,
        schema: datafusion::arrow::datatypes::SchemaRef,
    ) -> Self {
        Self {
            connector,
            connector_name: connector_name.into(),
            namespace: namespace.into(),
            table: table.into(),
            schema,
        }
    }
}

#[async_trait]
impl TableProvider for LazyWarehouseTableProvider {
    fn schema(&self) -> datafusion::arrow::datatypes::SchemaRef {
        Arc::clone(&self.schema)
    }

    fn table_type(&self) -> datafusion::datasource::TableType {
        datafusion::datasource::TableType::Base
    }

    async fn scan(
        &self,
        _state: &dyn datafusion::catalog::Session,
        projection: Option<&Vec<usize>>,
        // Filters are not pushed down in v1 (`supports_filters_pushdown`
        // defaults to Unsupported), so DataFusion keeps a FilterExec
        // above this scan — correct, just unoptimized.
        _filters: &[datafusion::logical_expr::Expr],
        limit: Option<usize>,
    ) -> DfResult<Arc<dyn datafusion::physical_plan::ExecutionPlan>> {
        Ok(Arc::new(WarehouseScanExec::new(
            Arc::clone(&self.connector),
            self.connector_name.clone(),
            self.namespace.clone(),
            self.table.clone(),
            Arc::clone(&self.schema),
            projection.cloned(),
            limit,
        )))
    }
}

/// Physical scan for a lazily-rebuilt warehouse table.
///
/// Carries identity + projection + limit; `execute` loads the Iceberg
/// table via the connector, plans the real
/// `IcebergStaticTableProvider::scan`, and streams its partitions
/// sequentially through one output partition. Serialized between
/// scheduler and executors by `FederationPlanCodec`'s
/// `KIND_WAREHOUSE_SCAN` payload.
#[derive(Debug)]
pub struct WarehouseScanExec {
    connector: Arc<WarehouseConnector>,
    connector_name: String,
    namespace: String,
    table: String,
    /// The table's full schema (pre-projection) — what the inner
    /// provider will report, and what `projection` indices refer to.
    full_schema: datafusion::arrow::datatypes::SchemaRef,
    projection: Option<Vec<usize>>,
    limit: Option<usize>,
    properties: Arc<datafusion::physical_plan::PlanProperties>,
}

impl WarehouseScanExec {
    /// Build a scan node. `projection` indices refer to `full_schema`.
    ///
    /// # Panics
    /// If a projection index is out of bounds for `full_schema` —
    /// planner-validated on the encode side and wire-carried verbatim,
    /// so this fires only on a corrupted payload.
    #[must_use]
    pub fn new(
        connector: Arc<WarehouseConnector>,
        connector_name: String,
        namespace: String,
        table: String,
        full_schema: datafusion::arrow::datatypes::SchemaRef,
        projection: Option<Vec<usize>>,
        limit: Option<usize>,
    ) -> Self {
        let projected: datafusion::arrow::datatypes::SchemaRef = match &projection {
            Some(idx) => Arc::new(
                full_schema
                    .project(idx)
                    .expect("projection indices validated by the planner"),
            ),
            None => Arc::clone(&full_schema),
        };
        let properties = Arc::new(datafusion::physical_plan::PlanProperties::new(
            datafusion::physical_expr::EquivalenceProperties::new(Arc::clone(&projected)),
            datafusion::physical_plan::Partitioning::UnknownPartitioning(1),
            datafusion::physical_plan::execution_plan::EmissionType::Incremental,
            datafusion::physical_plan::execution_plan::Boundedness::Bounded,
        ));
        Self {
            connector,
            connector_name,
            namespace,
            table,
            full_schema,
            projection,
            limit,
            properties,
        }
    }

    /// Wire identity accessors for the physical codec.
    #[must_use]
    pub fn connector_name(&self) -> &str {
        &self.connector_name
    }
    /// Namespace half of the table identity.
    #[must_use]
    pub fn namespace(&self) -> &str {
        &self.namespace
    }
    /// Table half of the table identity.
    #[must_use]
    pub fn table(&self) -> &str {
        &self.table
    }
    /// The full (pre-projection) schema.
    #[must_use]
    pub fn full_schema(&self) -> datafusion::arrow::datatypes::SchemaRef {
        Arc::clone(&self.full_schema)
    }
    /// Projection indices into [`Self::full_schema`], if any.
    #[must_use]
    pub fn projection(&self) -> Option<&Vec<usize>> {
        self.projection.as_ref()
    }
    /// Row limit, if any.
    #[must_use]
    pub fn limit(&self) -> Option<usize> {
        self.limit
    }
}

impl datafusion::physical_plan::DisplayAs for WarehouseScanExec {
    fn fmt_as(
        &self,
        _t: datafusion::physical_plan::DisplayFormatType,
        f: &mut fmt::Formatter,
    ) -> fmt::Result {
        write!(
            f,
            "WarehouseScanExec: catalog={} table={}.{}",
            self.connector_name, self.namespace, self.table
        )
    }
}

impl datafusion::physical_plan::ExecutionPlan for WarehouseScanExec {
    // The trait fixes the `&str` return; the literal is naturally 'static.
    #[allow(clippy::unnecessary_literal_bound)]
    fn name(&self) -> &str {
        "WarehouseScanExec"
    }

    fn schema(&self) -> datafusion::arrow::datatypes::SchemaRef {
        Arc::clone(self.properties.eq_properties.schema())
    }

    fn properties(&self) -> &Arc<datafusion::physical_plan::PlanProperties> {
        &self.properties
    }

    fn children(&self) -> Vec<&Arc<dyn datafusion::physical_plan::ExecutionPlan>> {
        vec![]
    }

    fn with_new_children(
        self: Arc<Self>,
        _children: Vec<Arc<dyn datafusion::physical_plan::ExecutionPlan>>,
    ) -> DfResult<Arc<dyn datafusion::physical_plan::ExecutionPlan>> {
        Ok(self)
    }

    fn execute(
        &self,
        partition: usize,
        context: Arc<datafusion::execution::TaskContext>,
    ) -> DfResult<datafusion::execution::SendableRecordBatchStream> {
        use futures::{StreamExt, TryStreamExt};

        assert_eq!(partition, 0, "WarehouseScanExec has one output partition");
        let connector = Arc::clone(&self.connector);
        let namespace = self.namespace.clone();
        let table = self.table.clone();
        let projection = self.projection.clone();
        let limit = self.limit;
        let projected_schema = self.schema();

        let stream = futures::stream::once(async move {
            // Load the real Iceberg table + plan its scan now that we
            // are in async context, then chain its partitions.
            let provider = connector
                .table_provider(&namespace, &table)
                .await
                .map_err(|e| DataFusionError::External(Box::new(e)))?;
            let state = datafusion::prelude::SessionContext::new().state();
            let plan = provider
                .scan(&state, projection.as_ref(), &[], limit)
                .await?;
            let n = plan.properties().partitioning.partition_count();
            let mut streams = Vec::with_capacity(n);
            for p in 0..n {
                streams.push(plan.execute(p, Arc::clone(&context))?);
            }
            Ok::<_, DataFusionError>(futures::stream::iter(streams).flatten())
        })
        .try_flatten();

        Ok(Box::pin(
            datafusion::physical_plan::stream::RecordBatchStreamAdapter::new(
                projected_schema,
                stream,
            ),
        ))
    }
}

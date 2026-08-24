//! Governance integration — outbound + inbound `DataHub` glue.
//!
//! This file (originally `governance.rs`, now `governance/mod.rs`)
//! holds the **outbound** Phase 1 §11 Interface #2 publisher; the
//! [`datahub`] sibling module holds the **inbound** Phase 2 §04
//! Interface #3 adapter that the [`crate::webhook`] dispatcher
//! calls. They share the `governance::` namespace because both
//! ultimately speak `DataHub`-shaped JSON; nothing else in the
//! module structure couples them.
//!
//! # Inbound (Phase 2 spec 04 slice 3)
//!
//! See [`datahub::lower_payload`] — given an envelope `event_type`
//! and the platform-shape `payload` JSON, returns the
//! [`dataglot_policy::RuleChange`] the slice-2 rule store accepts.
//! The webhook handler calls this once per request after HMAC
//! verification.
//!
//! # Outbound (Phase 1 §11 Interface #2)
//!
//! `DataHub` HTTP publisher — slice 2 of the Phase 1 §11
//! Interface #2 (data product registration). Implements
//! [`dataglot_core::DataProductPublisher`] by `POST`-ing
//! `MetadataChangeProposal` JSON bodies to a configured `DataHub`
//! GMS endpoint.
//!
//! Spec: `docs/phases/phase-1/10-data-product-registration.md`.
//!
//! # Failure-isolation contract
//!
//! `publish()` returns `()`. HTTP failures (5xx, 4xx, connection
//! refused, DNS failure, body-write error) are captured, logged at
//! `WARN` with the product URN + endpoint, and dropped. Queries and
//! server boot never fail because a governance backend is down.
//! Pinned by `datahub_publisher_swallows_5xx_errors` /
//! `datahub_publisher_swallows_connection_refused`.
//!
//! # `DataHub` REST contract
//!
//! Per the slice spec, every product is published as a single
//! `UPSERT` `MetadataChangeProposal` against the `schemaMetadata`
//! aspect of a `dataset` entity. The endpoint path is
//! `<gms_endpoint>/aspects?action=ingestProposal`. Bearer-token auth
//! is optional — the operator wires `bearer_token_env` in
//! `governance_publishers[]` config, slice 3 resolves it and passes
//! it here.
//!
//! `DataHub`'s `urn:li:dataset:(...)` LinkedIn-style URN format is
//! synthesised here from the platform-agnostic
//! `dataglot_core::TableName` + `ProductPlatform` pair so callers
//! don't need to know `DataHub`'s identifier shape. The Dataglot-side
//! `urn:dataglot:...` URN is preserved on the `DataProduct` and used
//! for log correlation.

pub mod datahub;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use dataglot_core::governance::{
    ColumnMetadata, DataProduct, DataProductPublisher, DynDataProductPublisher, ProductPlatform,
    TableName,
};
use dataglot_core::{CatalogBinding, LiveConnectorKind};
use reqwest::Url;
use serde_json::{json, Value};

use crate::config::GovernancePublisherConfig;

/// `DataHub` ingest action path appended to the configured GMS
/// endpoint. The Action API has been the recommended write path
/// across `DataHub` 0.10+; the legacy `/entities?action=ingest`
/// route is deprecated.
const DATAHUB_INGEST_PATH: &str = "aspects?action=ingestProposal";

/// `DataHub` fabric / environment tag. Phase 1 publishes everything
/// as `PROD` — the spec doesn't model dev/staging fabrics yet, and
/// `DataHub`'s URN parser rejects empty fabrics. Revisit when
/// multi-tenant scoping lands in Phase 2.
const DATAHUB_FABRIC: &str = "PROD";

/// HTTP-based `DataHub` data-product publisher.
///
/// Holds a `reqwest::Client` (clone is cheap; the client owns a
/// connection pool that the application shares across publish
/// calls) plus the configured GMS endpoint and optional bearer
/// token.
///
/// # Example
///
/// ```no_run
/// use dataglot_server::governance::DataHubPublisher;
/// # fn demo() -> anyhow::Result<()> {
/// let publisher = DataHubPublisher::new("http://datahub-gms:8080", None)?;
/// # let _ = publisher;
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct DataHubPublisher {
    client: reqwest::Client,
    endpoint: Url,
    bearer_token: Option<String>,
}

impl std::fmt::Debug for DataHubPublisher {
    /// Credential-safe `Debug`. The `bearer_token` is replaced with
    /// `<redacted>` so a `{:?}` of this publisher never prints the
    /// token. CLAUDE.md rule 12 — matches the hand-written `Debug` on
    /// the credential configs in `config.rs`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DataHubPublisher")
            .field("client", &self.client)
            .field("endpoint", &self.endpoint)
            .field(
                "bearer_token",
                &if self.bearer_token.is_some() {
                    "<redacted>"
                } else {
                    "<unset>"
                },
            )
            .finish()
    }
}

impl DataHubPublisher {
    /// Construct a publisher targeting the given GMS endpoint.
    ///
    /// The endpoint must parse as a valid URL — no live
    /// reachability check is performed (a backend that is down at
    /// boot may be up by the first publish, and vice versa). The
    /// first publish failure surfaces in the `WARN` log.
    ///
    /// # Errors
    /// Returns an error if `gms_endpoint` is not a valid URL or the
    /// internal `reqwest::Client` cannot be constructed.
    pub fn new(gms_endpoint: &str, bearer_token: Option<String>) -> anyhow::Result<Self> {
        let endpoint = Url::parse(gms_endpoint).map_err(|e| {
            anyhow::anyhow!("invalid DataHub GMS endpoint URL {gms_endpoint:?}: {e}")
        })?;
        let client = reqwest::Client::builder()
            // Same generous timeout as the OpenLineage emitter.
            // Governance publish is observability surface; we
            // don't want it eating boot latency on a slow backend.
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| anyhow::anyhow!("failed to build reqwest client: {e}"))?;
        Ok(Self {
            client,
            endpoint,
            bearer_token,
        })
    }

    /// Construct with a caller-supplied `reqwest::Client`.
    ///
    /// Useful for tests that need a tuned client (short timeouts,
    /// custom roots) or for callers wiring one client across
    /// multiple publishers.
    ///
    /// # Errors
    /// Returns an error if `gms_endpoint` is not a valid URL.
    pub fn with_client(
        gms_endpoint: &str,
        bearer_token: Option<String>,
        client: reqwest::Client,
    ) -> anyhow::Result<Self> {
        let endpoint = Url::parse(gms_endpoint).map_err(|e| {
            anyhow::anyhow!("invalid DataHub GMS endpoint URL {gms_endpoint:?}: {e}")
        })?;
        Ok(Self {
            client,
            endpoint,
            bearer_token,
        })
    }

    /// Configured GMS endpoint.
    #[must_use]
    pub fn endpoint(&self) -> &Url {
        &self.endpoint
    }

    /// Returns the full URL the publisher posts to.
    ///
    /// `DATAHUB_INGEST_PATH` is a static well-formed relative
    /// reference; joining against any valid base `Url` cannot fail,
    /// so we materialise the join unconditionally here.
    fn ingest_url(&self) -> Url {
        self.endpoint
            .join(DATAHUB_INGEST_PATH)
            .expect("DATAHUB_INGEST_PATH joined with a valid base must parse")
    }
}

#[async_trait::async_trait]
impl DataProductPublisher for DataHubPublisher {
    async fn publish(&self, product: &DataProduct) {
        let url = self.ingest_url();
        let body = build_mcp_body(product);
        let mut req = self.client.post(url).json(&body);
        if let Some(token) = &self.bearer_token {
            req = req.bearer_auth(token);
        }
        match req.send().await {
            Ok(resp) => {
                let status = resp.status();
                if !status.is_success() {
                    tracing::warn!(
                        urn = %product.urn,
                        endpoint = %self.endpoint,
                        %status,
                        "DataHub rejected data product MCP"
                    );
                }
            }
            Err(err) => {
                tracing::warn!(
                    urn = %product.urn,
                    endpoint = %self.endpoint,
                    error = %err,
                    "DataHub HTTP POST failed; event dropped"
                );
            }
        }
    }
}

/// Build the `MetadataChangeProposal` body for a single
/// `DataProduct`. Pulled out of the trait impl so the JSON shape is
/// unit-testable without booting an HTTP server.
fn build_mcp_body(product: &DataProduct) -> Value {
    let datahub_urn = build_datahub_urn(product.platform, &product.name);
    let aspect = build_schema_metadata_aspect(&datahub_urn, product.platform, &product.columns);
    let mut proposal = serde_json::Map::new();
    proposal.insert("entityType".into(), json!("dataset"));
    proposal.insert("entityUrn".into(), json!(datahub_urn));
    proposal.insert("changeType".into(), json!("UPSERT"));
    proposal.insert("aspectName".into(), json!("schemaMetadata"));
    proposal.insert(
        "aspect".into(),
        json!({
            "value": aspect.to_string(),
            "contentType": "application/json",
        }),
    );
    if let Some(description) = &product.description {
        proposal.insert("entityDescription".into(), json!(description));
    }
    json!({ "proposal": Value::Object(proposal) })
}

/// Build the `schemaMetadata` aspect value. Encoded as a string in
/// the outer `MetadataChangeProposal` body per `DataHub`'s
/// convention.
fn build_schema_metadata_aspect(
    urn: &str,
    platform: ProductPlatform,
    columns: &[ColumnMetadata],
) -> Value {
    let fields: Vec<Value> = columns.iter().map(column_to_field).collect();
    json!({
        "schemaName": urn,
        "platform": format!("urn:li:dataPlatform:{}", datahub_platform_slug(platform)),
        "version": 0,
        "fields": fields,
        "hash": "",
        "platformSchema": {
            "com.linkedin.schema.OtherSchema": { "rawSchema": "" }
        },
    })
}

fn column_to_field(column: &ColumnMetadata) -> Value {
    json!({
        "fieldPath": column.name,
        "nullable": column.nullable,
        "description": column.definition,
        "nativeDataType": column.arrow_type,
        "type": {
            "type": { "com.linkedin.schema.StringType": {} }
        },
    })
}

/// Map our platform enum to `DataHub`'s `dataPlatform` slug. The
/// slugs match `DataHub`'s built-in platform vocabulary; operators
/// stay clear of the `iceberg`-internals exposure called out in
/// CLAUDE.md rule 7 because the *operator* sees `DataHub`'s native
/// "Iceberg" label, not Dataglot's internal `IcebergCache` naming.
fn datahub_platform_slug(platform: ProductPlatform) -> &'static str {
    match platform {
        ProductPlatform::Postgres => "postgres",
        ProductPlatform::Mysql => "mysql",
        ProductPlatform::Snowflake => "snowflake",
        ProductPlatform::Oracle => "oracle",
        ProductPlatform::ObjectStorage => "s3",
        ProductPlatform::Odata => "odata",
        // DataHub has no vocabulary entry for "some ADBC driver" or a generic
        // REST/JSON API; the generic `external` platform is its designated
        // bucket for sources it can't classify.
        ProductPlatform::Adbc | ProductPlatform::Rest => "external",
        ProductPlatform::Iceberg => "iceberg",
    }
}

/// Build `DataHub`'s LinkedIn-style URN for a dataset. Format:
/// `urn:li:dataset:(urn:li:dataPlatform:<slug>,<catalog>.<schema>.<table>,<fabric>)`.
fn build_datahub_urn(platform: ProductPlatform, name: &TableName) -> String {
    format!(
        "urn:li:dataset:(urn:li:dataPlatform:{},{}.{}.{},{})",
        datahub_platform_slug(platform),
        name.catalog,
        name.schema,
        name.table,
        DATAHUB_FABRIC,
    )
}

/// Alias for the `DataHub`-publisher trait object. Mirrors the
/// `DynLineageEmitter` shape from the `OpenLineage` emitter so the
/// server can hold either via `Arc<dyn ...>`.
pub type DynDataHubPublisher = Arc<DataHubPublisher>;

/// Sentinel value used in `name.schema` / `name.table` for the
/// catalog-level data product emitted at boot before any per-table
/// breakdown is known. Phase 2 work (lineage-driven table
/// enumeration) will replace these with real schema / table names
/// as queries surface them.
///
/// Pinned by `data_product_for_binding_*` tests so any future
/// rename surfaces immediately — downstream consumers
/// (`MetadataChangeProposal` URN parsers in `DataHub`,
/// audit-trail tooling) will key off this string.
pub const CATALOG_LEVEL_SENTINEL: &str = "_catalog";

/// Build a [`DataProduct`] for a catalog binding at boot or on a
/// `BindingChange::Upserted` event.
///
/// Phase 1 publishes one `DataProduct` per *catalog* (not per
/// table). The `name.schema` / `name.table` fields use the
/// [`CATALOG_LEVEL_SENTINEL`] string so the wire shape stays
/// stable across phases — Phase 2 will replace these with real
/// per-table breakdowns as lineage tracing surfaces them.
///
/// CLAUDE.md rule 13 — schema inference is lazy: we do *not* walk
/// `SchemaProvider::table_names()` / `TableProvider::schema()` at
/// boot. The columns vector is empty in Phase 1.
#[must_use]
pub fn data_product_for_binding(catalog_name: &str, binding: &CatalogBinding) -> DataProduct {
    let name = TableName {
        catalog: catalog_name.to_string(),
        schema: CATALOG_LEVEL_SENTINEL.to_string(),
        table: CATALOG_LEVEL_SENTINEL.to_string(),
    };
    let urn = name.to_urn();
    let platform = match binding {
        CatalogBinding::LiveConnector(b) => match b.kind {
            LiveConnectorKind::Postgres => ProductPlatform::Postgres,
            LiveConnectorKind::Mysql => ProductPlatform::Mysql,
            LiveConnectorKind::Snowflake => ProductPlatform::Snowflake,
            LiveConnectorKind::Oracle => ProductPlatform::Oracle,
            LiveConnectorKind::ObjectStorage => ProductPlatform::ObjectStorage,
            LiveConnectorKind::Odata => ProductPlatform::Odata,
            LiveConnectorKind::Adbc => ProductPlatform::Adbc,
            LiveConnectorKind::Rest => ProductPlatform::Rest,
        },
        // `SemanticCatalog` is the cross-source semantic-model
        // binding (Architecture Decisions §09); it has no
        // single source platform of its own. Phase 1 treats it
        // as `iceberg` for governance purposes — the underlying
        // tables it surfaces live in the warehouse and `DataHub`
        // platforms it best. Phase 2 follow-up may add a
        // `SemanticModel` platform once a customer surfaces a
        // governance ask there.
        CatalogBinding::IcebergCache(_) | CatalogBinding::SemanticCatalog(_) => {
            ProductPlatform::Iceberg
        }
    };
    DataProduct {
        urn,
        name,
        platform,
        columns: Vec::new(),
        description: Some(format!("Dataglot catalog binding: {catalog_name}")),
    }
}

/// Resolve a configured [`GovernancePublisherConfig`] into a live
/// [`DynDataProductPublisher`].
///
/// # Errors
/// Returns an error if a configured env var holding a bearer token
/// is unset, or if the resulting endpoint URL / `reqwest::Client`
/// cannot be constructed.
pub fn build_publisher(
    config: &GovernancePublisherConfig,
) -> anyhow::Result<DynDataProductPublisher> {
    match config {
        GovernancePublisherConfig::Datahub {
            gms_endpoint,
            bearer_token_env,
        } => {
            let token = match bearer_token_env {
                Some(env_name) => {
                    let value = std::env::var(env_name).map_err(|_| {
                        anyhow::anyhow!(
                            "DataHub publisher bearer_token_env {env_name:?} is not set"
                        )
                    })?;
                    Some(value)
                }
                None => None,
            };
            let publisher = DataHubPublisher::new(gms_endpoint, token)?;
            Ok(Arc::new(publisher))
        }
    }
}

/// Resolve every configured publisher into a `Vec<DynDataProductPublisher>`.
///
/// # Errors
/// Surfaces the first publisher-construction failure
/// (`build_publisher` is fail-fast at boot — better to refuse to
/// start than to silently drop one of multiple publishers).
pub fn build_publishers(
    configs: &[GovernancePublisherConfig],
) -> anyhow::Result<Vec<DynDataProductPublisher>> {
    configs.iter().map(build_publisher).collect()
}

/// Publish one binding's `DataProduct` to every publisher.
///
/// Used by the boot walk and by the `BindingChange` subscriber so
/// the two trigger paths share one rendering.
pub async fn publish_one_binding(
    publishers: &[DynDataProductPublisher],
    catalog_name: &str,
    binding: &CatalogBinding,
) {
    if publishers.is_empty() {
        return;
    }
    let product = data_product_for_binding(catalog_name, binding);
    for publisher in publishers {
        publisher.publish(&product).await;
    }
}

/// Walk a bindings map and publish a `DataProduct` for every entry
/// to every publisher.
///
/// Failure-isolation contract is per-publisher: a 5xx / refused
/// connection on one publisher does not stop the walk. The
/// failure-isolation lives inside each `publish()` impl (slice 2).
///
/// Concurrency: publishers run sequentially per binding because
/// the `Send` bound on the trait object lets `tokio::join_all`
/// work but the cross-publisher ordering doesn't matter here — and
/// per-binding count in Phase 1 is small enough that serial
/// publish is observable-cost-zero.
#[allow(clippy::implicit_hasher)] // server-side bindings map always uses RandomState
pub async fn publish_all_bindings(
    publishers: &[DynDataProductPublisher],
    bindings: &HashMap<String, CatalogBinding>,
) {
    if publishers.is_empty() || bindings.is_empty() {
        return;
    }
    for (name, binding) in bindings {
        let product = data_product_for_binding(name, binding);
        for publisher in publishers {
            publisher.publish(&product).await;
        }
    }
}

/// Spawn the `BindingChange` subscriber task that re-publishes a
/// `DataProduct` on every `Upserted` event from the catalog
/// service. `Deleted` events log a `WARN` and are dropped (per the
/// spec's "Out of scope: deletion" decision — Phase 1 prefers a
/// stale ghost entry over silently losing the record).
///
/// The task owns its own `BindingChangeStream` (a dedicated
/// Postgres LISTEN connection) so it stays independent of the
/// catalog cache's parallel subscriber. Postgres permits arbitrary
/// LISTEN fan-out — the cost is one extra connection per
/// subscriber, which Phase 1 deployments tolerate cheaply.
///
/// Holding the returned `JoinHandle` keeps the task alive for the
/// server's lifetime; dropping it aborts the task. The catalog
/// service must outlive the task — typically `service` is the
/// `Arc<CatalogService>` already held by `DataglotServer`.
///
/// On `Deleted` events the task logs at `WARN` and does **not**
/// invoke any publisher — see spec "Out of scope: Deletion /
/// unregistration".
///
/// Stream loss / reconnect: the task currently exits cleanly on
/// stream EOF and logs `WARN`. A bounded-backoff reconnect mirroring
/// the cache's `reconnect_subscribe` is a Phase 1 follow-up; in
/// practice the operator restart that the cache loop also depends
/// on covers the gap.
///
/// # Errors
/// Returns an error if the initial subscribe call fails.
#[allow(clippy::implicit_hasher)] // server-side bindings map always uses RandomState
pub async fn spawn_binding_change_publisher(
    service: Arc<dyn dataglot_catalog::MetaStore>,
    catalogs: Arc<HashMap<String, dataglot_core::CatalogBinding>>,
    publishers: Arc<Vec<DynDataProductPublisher>>,
) -> Result<tokio::task::JoinHandle<()>, dataglot_catalog::CatalogServiceError> {
    use futures::StreamExt;

    let mut stream = service.subscribe().await?;
    let handle = tokio::spawn(async move {
        while let Some(change) = stream.next().await {
            match change.kind {
                dataglot_catalog::BindingChangeKind::Upserted => {
                    if let Some(binding) = catalogs.get(&change.name) {
                        publish_one_binding(&publishers, &change.name, binding).await;
                    } else {
                        tracing::warn!(
                            catalog = %change.name,
                            "governance: BindingChange::Upserted for unknown catalog; \
                             configured catalog list is the source of truth in Phase 1, \
                             skipping publish"
                        );
                    }
                }
                dataglot_catalog::BindingChangeKind::Deleted => {
                    tracing::warn!(
                        catalog = %change.name,
                        "governance: BindingChange::Deleted received; Phase 1 leaves \
                         ghost entries on the backend (see spec 'Out of scope: Deletion / \
                         unregistration')"
                    );
                }
            }
        }
        tracing::warn!(
            "governance: BindingChange stream closed; no further data products will be \
             re-published until server restart"
        );
    });
    Ok(handle)
}

#[cfg(test)]
mod tests {
    use super::*;

    use dataglot_core::governance::{placeholder_column, ColumnDefinitionSource, TableName};
    use dataglot_core::{IcebergCacheBinding, LiveConnectorBinding};
    use wiremock::matchers::{body_partial_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn fixed_product() -> DataProduct {
        let name = TableName {
            catalog: "pg".into(),
            schema: "public".into(),
            table: "users".into(),
        };
        DataProduct {
            urn: name.to_urn(),
            name,
            platform: ProductPlatform::Postgres,
            columns: vec![
                placeholder_column("id".to_string(), "Int64".to_string(), false),
                placeholder_column("email".to_string(), "Utf8".to_string(), true),
            ],
            description: None,
        }
    }

    /// CLAUDE.md rule 12 regression guard: a `{:?}` of the publisher
    /// must not print the bearer token ( 1a).
    #[test]
    fn datahub_publisher_debug_redacts_bearer_token() {
        let publisher = DataHubPublisher::new(
            "http://datahub-gms:8080",
            Some("super-secret-bearer-token".to_string()),
        )
        .expect("valid endpoint");
        let s = format!("{publisher:?}");
        assert!(
            !s.contains("super-secret-bearer-token"),
            "Debug leaked bearer_token: {s}"
        );
        assert!(s.contains("<redacted>"), "expected <redacted> marker: {s}");
        assert!(s.contains("datahub-gms"), "endpoint should be visible: {s}");
    }

    /// No token → `<unset>`, never a leak or panic.
    #[test]
    fn datahub_publisher_debug_without_token_is_unset() {
        let publisher =
            DataHubPublisher::new("http://datahub-gms:8080", None).expect("valid endpoint");
        let s = format!("{publisher:?}");
        assert!(s.contains("<unset>"), "expected <unset> marker: {s}");
        assert!(!s.contains("<redacted>"), "{s}");
    }

    #[test]
    fn datahub_urn_uses_linkedin_format() {
        // Pin the LinkedIn-style URN. DataHub's URN parser is
        // strict about parens, comma separation, and the
        // `dataPlatform:` prefix — any drift here means
        // `DataHub` will silently reject the MCP.
        let name = TableName {
            catalog: "pg".into(),
            schema: "public".into(),
            table: "users".into(),
        };
        let urn = build_datahub_urn(ProductPlatform::Postgres, &name);
        assert_eq!(
            urn,
            "urn:li:dataset:(urn:li:dataPlatform:postgres,pg.public.users,PROD)"
        );
    }

    #[test]
    fn datahub_platform_slug_covers_all_variants() {
        // Compile-time exhaustive via the match in
        // `datahub_platform_slug`; this test pins the *string*
        // values so a typo doesn't silently change the wire shape.
        assert_eq!(datahub_platform_slug(ProductPlatform::Postgres), "postgres");
        assert_eq!(datahub_platform_slug(ProductPlatform::Mysql), "mysql");
        assert_eq!(
            datahub_platform_slug(ProductPlatform::Snowflake),
            "snowflake"
        );
        assert_eq!(datahub_platform_slug(ProductPlatform::Oracle), "oracle");
        assert_eq!(datahub_platform_slug(ProductPlatform::ObjectStorage), "s3");
        assert_eq!(datahub_platform_slug(ProductPlatform::Odata), "odata");
        assert_eq!(datahub_platform_slug(ProductPlatform::Iceberg), "iceberg");
    }

    #[test]
    fn mcp_body_has_expected_shape() {
        // Pin the MCP JSON keys DataHub's GMS expects.
        let product = fixed_product();
        let body = build_mcp_body(&product);

        let proposal = &body["proposal"];
        assert_eq!(proposal["entityType"], "dataset");
        assert_eq!(
            proposal["entityUrn"],
            "urn:li:dataset:(urn:li:dataPlatform:postgres,pg.public.users,PROD)"
        );
        assert_eq!(proposal["changeType"], "UPSERT");
        assert_eq!(proposal["aspectName"], "schemaMetadata");
        assert_eq!(proposal["aspect"]["contentType"], "application/json");
        // aspect.value is a stringified JSON blob per DataHub
        // convention. Re-parse to assert on its inner shape.
        let aspect_value: Value =
            serde_json::from_str(proposal["aspect"]["value"].as_str().unwrap()).unwrap();
        assert_eq!(aspect_value["platform"], "urn:li:dataPlatform:postgres");
        assert_eq!(aspect_value["fields"].as_array().unwrap().len(), 2);
        assert_eq!(aspect_value["fields"][0]["fieldPath"], "id");
        assert_eq!(aspect_value["fields"][1]["fieldPath"], "email");
        assert_eq!(aspect_value["fields"][1]["nullable"], true);
    }

    #[test]
    fn mcp_body_includes_placeholder_descriptions() {
        // Phase 1 ships placeholder column descriptions; Phase 2
        // LLM swap flips this. Pin the exact placeholder string
        // so the flag-when-fixed is one test failure.
        let product = fixed_product();
        let body = build_mcp_body(&product);
        let aspect_value: Value =
            serde_json::from_str(body["proposal"]["aspect"]["value"].as_str().unwrap()).unwrap();
        for field in aspect_value["fields"].as_array().unwrap() {
            assert_eq!(field["description"], "Pending Dataglot-side definition");
        }
        // Sanity: the source enum is still `Placeholder` on every
        // column the helper produced.
        for column in &product.columns {
            assert!(matches!(
                column.definition_source,
                ColumnDefinitionSource::Placeholder
            ));
        }
    }

    #[test]
    fn mcp_body_carries_optional_description_when_present() {
        // The Phase 2 LLM pipeline may eventually fill a table-
        // level description. Phase 1 leaves it `None`, but the
        // wire shape must already support it.
        let mut product = fixed_product();
        product.description = Some("Customer accounts".to_string());
        let body = build_mcp_body(&product);
        assert_eq!(body["proposal"]["entityDescription"], "Customer accounts");
    }

    #[test]
    fn new_rejects_invalid_endpoint_url() {
        let err = DataHubPublisher::new("not a url", None).unwrap_err();
        assert!(
            err.to_string().contains("invalid DataHub GMS endpoint URL"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn datahub_publish_posts_mcp_with_expected_shape() {
        // End-to-end against wiremock: the publisher must POST one
        // MCP to /aspects?action=ingestProposal with the expected
        // outer-body shape, and the assertion runs through
        // body_partial_json so we don't pin keys we don't care
        // about (timestamps, future fields).
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/aspects"))
            .and(body_partial_json(json!({
                "proposal": {
                    "entityType": "dataset",
                    "changeType": "UPSERT",
                    "aspectName": "schemaMetadata",
                }
            })))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;

        let publisher = DataHubPublisher::new(&server.uri(), None).unwrap();
        publisher.publish(&fixed_product()).await;
        // Drop runs the .expect(1) assertion at the end of the test.
    }

    #[tokio::test]
    async fn datahub_publish_includes_bearer_token_when_configured() {
        // Bearer token from `governance_publishers[].bearer_token_env`
        // (slice 3) must land on the Authorization header.
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/aspects"))
            .and(wiremock::matchers::header(
                "authorization",
                "Bearer secret-token-xyz",
            ))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;

        let publisher =
            DataHubPublisher::new(&server.uri(), Some("secret-token-xyz".to_string())).unwrap();
        publisher.publish(&fixed_product()).await;
    }

    #[tokio::test]
    async fn datahub_publisher_swallows_5xx_errors() {
        // Backend outage MUST NOT propagate to the caller. The
        // failure-isolation contract — publish() returns ().
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;

        let publisher = DataHubPublisher::new(&server.uri(), None).unwrap();
        publisher.publish(&fixed_product()).await;
        // No panic, no propagation — pinned.
    }

    #[tokio::test]
    async fn datahub_publisher_swallows_connection_refused() {
        // Same as above but the endpoint is a closed port.
        let publisher = DataHubPublisher::with_client(
            // Random unbound port on loopback.
            "http://127.0.0.1:1",
            None,
            reqwest::Client::builder()
                .timeout(std::time::Duration::from_millis(100))
                .build()
                .unwrap(),
        )
        .unwrap();
        publisher.publish(&fixed_product()).await;
        // No panic — pinned.
    }

    fn fixed_postgres_binding() -> CatalogBinding {
        CatalogBinding::LiveConnector(LiveConnectorBinding {
            kind: LiveConnectorKind::Postgres,
            endpoint_hint: "postgres://pg.example.com:5432".to_string(),
        })
    }

    fn fixed_iceberg_binding() -> CatalogBinding {
        CatalogBinding::IcebergCache(IcebergCacheBinding {
            catalog_url: "http://lakekeeper:8181/catalog".to_string(),
            warehouse: "warehouse_a".to_string(),
            table_path: Vec::new(),
        })
    }

    #[test]
    fn data_product_for_binding_uses_catalog_level_sentinel() {
        // Phase 1 publishes one DataProduct per catalog, with
        // schema/table set to the documented sentinel. Phase 2
        // per-table breakdown replaces them; pinning the
        // sentinel here keeps the wire shape stable in the
        // meantime.
        let product = data_product_for_binding("pg", &fixed_postgres_binding());
        assert_eq!(product.name.catalog, "pg");
        assert_eq!(product.name.schema, CATALOG_LEVEL_SENTINEL);
        assert_eq!(product.name.table, CATALOG_LEVEL_SENTINEL);
        assert_eq!(product.urn, "urn:dataglot:pg:_catalog:_catalog");
        assert!(product.columns.is_empty(), "Phase 1: no eager schema fetch");
    }

    #[test]
    fn data_product_for_binding_postgres_uses_postgres_platform() {
        let product = data_product_for_binding("pg", &fixed_postgres_binding());
        assert_eq!(product.platform, ProductPlatform::Postgres);
    }

    #[test]
    fn data_product_for_binding_iceberg_uses_iceberg_platform() {
        let product = data_product_for_binding("wh", &fixed_iceberg_binding());
        assert_eq!(product.platform, ProductPlatform::Iceberg);
    }

    #[test]
    fn data_product_for_binding_records_dataglot_description() {
        // The Phase 1 binding-level entry on DataHub carries a
        // human-readable description so operators can tell at a
        // glance that the entity is Dataglot-side metadata.
        let product = data_product_for_binding("pg", &fixed_postgres_binding());
        assert_eq!(
            product.description.as_deref(),
            Some("Dataglot catalog binding: pg")
        );
    }

    #[test]
    fn build_publishers_empty_returns_empty() {
        let publishers = build_publishers(&[]).unwrap();
        assert!(publishers.is_empty());
    }

    #[test]
    fn build_publishers_datahub_without_token_succeeds() {
        // The bearer_token_env: None path keeps DataHub publishers
        // operable against a local-dev DataHub running without
        // auth.
        let publishers = build_publishers(&[GovernancePublisherConfig::Datahub {
            gms_endpoint: "http://datahub-gms:8080".to_string(),
            bearer_token_env: None,
        }])
        .unwrap();
        assert_eq!(publishers.len(), 1);
    }

    #[test]
    fn build_publishers_datahub_missing_env_var_fails() {
        // An operator who declared bearer_token_env but failed to
        // export the variable should not silently boot without
        // auth — fail fast at boot. The env-var name embeds a
        // freshly-generated unique suffix so the test runs the
        // missing-var branch regardless of the host environment;
        // we cannot `remove_var` it ourselves because the crate
        // forbids `unsafe`.
        let env_name = format!(
            "DATAGLOT_TEST_MISSING_PUBLISHER_TOKEN_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        assert!(
            std::env::var(&env_name).is_err(),
            "test env var name should never be set; got value"
        );
        let err = build_publishers(&[GovernancePublisherConfig::Datahub {
            gms_endpoint: "http://datahub-gms:8080".to_string(),
            bearer_token_env: Some(env_name.clone()),
        }])
        .unwrap_err();
        assert!(
            err.to_string().contains("is not set"),
            "expected env-missing error, got: {err}"
        );
    }

    #[tokio::test]
    async fn publish_all_bindings_fires_one_per_binding_per_publisher() {
        // Two bindings + one publisher = two POSTs. Pin the per-
        // binding fan-out shape, the integration test wires the
        // boot path end-to-end against a real DataglotServer.
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/aspects"))
            .respond_with(ResponseTemplate::new(200))
            .expect(2)
            .mount(&server)
            .await;

        let publishers: Vec<DynDataProductPublisher> = vec![Arc::new(
            DataHubPublisher::new(&server.uri(), None).unwrap(),
        )];
        let mut bindings: HashMap<String, CatalogBinding> = HashMap::new();
        bindings.insert("pg".to_string(), fixed_postgres_binding());
        bindings.insert("wh".to_string(), fixed_iceberg_binding());

        publish_all_bindings(&publishers, &bindings).await;
        // Drop runs the .expect(2) assertion.
    }

    #[tokio::test]
    async fn publish_all_bindings_with_zero_publishers_is_noop() {
        // No publisher configured ⇒ no work. Pinned because the
        // server-boot fast path branches on this — empty
        // governance_publishers must stay bit-identical to
        // pre-slice-3 behaviour.
        let mut bindings: HashMap<String, CatalogBinding> = HashMap::new();
        bindings.insert("pg".to_string(), fixed_postgres_binding());
        publish_all_bindings(&[], &bindings).await;
        // No panic, no I/O — pinned.
    }
}

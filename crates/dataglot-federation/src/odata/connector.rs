//! The OData v2 connector: a [`reqwest`]-backed [`OdataConnector`] that
//! discovers schema from `$metadata` and hands out an `OdataTableProvider`
//! per entity set. The provider is a **direct** DataFusion `TableProvider`
//! (rule 3 — OData is REST, not SQL): its `scan` issues one HTTP `GET` with
//! `$select` / `$filter` / `$top` derived from the query, then decodes the
//! JSON response into Arrow via [`super::decode`].
//!
//! Pushdown ceiling (per the spec): column projection (`$select`), filter
//! predicates (`$filter`, via [`super::filter`]), and `LIMIT` (`$top`).
//! Aggregation / join / `ORDER BY` are not pushed (OData v2 has no
//! `$groupby`); DataFusion evaluates them locally over the scan.
//!
//! Server pagination: a scan follows the OData v2 `__next` link across pages,
//! bounded by `MAX_PAGES` (`$top` bounds most queries; the cap stops an
//! unbounded/looping source, truncating with a `WARN`). MVP limitations
//! (documented follow-ups): auth is Basic or a static Bearer.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use arrow::array::RecordBatch;
use arrow::datatypes::SchemaRef;
use async_trait::async_trait;
use datafusion::catalog::{
    CatalogProvider as DfCatalogProvider, SchemaProvider as DfSchemaProvider, Session,
};
use datafusion::datasource::TableProvider;
use datafusion::error::{DataFusionError, Result as DfResult};
use datafusion::execution::TaskContext;
use datafusion::logical_expr::{Expr, TableProviderFilterPushDown, TableType};
use datafusion::physical_expr::EquivalenceProperties;
use datafusion::physical_plan::execution_plan::{Boundedness, EmissionType};
use datafusion::physical_plan::stream::RecordBatchStreamAdapter;
use datafusion::physical_plan::{
    DisplayAs, DisplayFormatType, ExecutionPlan, Partitioning, PlanProperties,
    SendableRecordBatchStream,
};
use futures::StreamExt;
use reqwest::Client;
use tokio::sync::OnceCell;

use dataglot_core::{DataglotError, Result as DataglotResult};

use super::decode::decode_entity_set_page;
use super::filter::translate_filters;
use super::metadata::{parse_edmx_catalog, parse_edmx_schema};

/// Per-request timeout for the OData HTTP client, so a stalled `$metadata`
/// fetch or entity-set scan fails rather than hanging a query indefinitely.
pub(crate) const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Upper bound on OData server-pagination (`__next`) pages a single scan will
/// follow. `$top` already caps most queries; this bounds an unbounded or
/// misbehaving source (one that keeps returning `__next`) so a scan can't loop
/// forever. On hitting the cap the result is truncated with a `WARN` log.
pub(crate) const MAX_PAGES: usize = 16;

/// How the connector authenticates to the OData service.
///
/// `Debug` is hand-written to never render the password or bearer token
/// (CLAUDE.md rule 12).
#[derive(Clone)]
pub enum OdataAuth {
    /// HTTP Basic auth. The password is resolved from config by the caller
    /// (e.g. `password_env`), never inlined.
    Basic {
        /// The user name.
        user: String,
        /// The password (never logged / rendered).
        password: String,
    },
    /// A pre-obtained OAuth 2.0 bearer token (refresh is the caller's job).
    Bearer {
        /// The token (never logged / rendered).
        token: String,
    },
}

impl fmt::Debug for OdataAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Basic { user, .. } => f
                .debug_struct("Basic")
                .field("user", user)
                .field("password", &"<redacted>")
                .finish(),
            Self::Bearer { .. } => f.write_str("Bearer(<redacted>)"),
        }
    }
}

impl OdataAuth {
    /// Apply the credentials to an outgoing request.
    fn apply(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match self {
            Self::Basic { user, password } => req.basic_auth(user, Some(password)),
            Self::Bearer { token } => req.bearer_auth(token),
        }
    }
}

/// A connection to an OData v2 service. Cheap to construct (no I/O until the
/// first `$metadata` fetch, rule 13); one `reqwest::Client` reused for all
/// requests.
pub struct OdataConnector {
    name: String,
    /// Service root URL, no trailing slash (e.g.
    /// `https://host/sap/opu/odata/sap/API_BUSINESS_PARTNER`).
    service_url: String,
    http: Client,
    auth: OdataAuth,
    /// The `$metadata` document, fetched once on first use.
    metadata: OnceCell<String>,
}

impl fmt::Debug for OdataConnector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // `auth` redacts itself; `service_url` carries no credentials (auth is
        // separate). No secret is rendered.
        f.debug_struct("OdataConnector")
            .field("name", &self.name)
            .field("service_url", &self.service_url)
            .field("auth", &self.auth)
            .finish_non_exhaustive()
    }
}

impl OdataConnector {
    /// Construct a connector. Builds the HTTP client but performs no I/O
    /// (schema is fetched lazily on the first [`Self::table_provider`] call).
    ///
    /// # Errors
    /// [`DataglotError::Connection`] if the HTTP client can't be built.
    pub fn connect(
        name: impl Into<String>,
        service_url: impl Into<String>,
        auth: OdataAuth,
    ) -> DataglotResult<Self> {
        let http = Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .build()
            .map_err(|e| DataglotError::connection(format!("failed to build HTTP client: {e}")))?;
        Ok(Self::with_client(name, service_url, auth, http))
    }

    /// Construct a connector over a caller-supplied [`reqwest::Client`] — used
    /// by the SAP layer to inject default headers (e.g. `sap-client`) on every
    /// request. The caller owns the client's configuration (timeout, headers).
    #[must_use]
    pub fn with_client(
        name: impl Into<String>,
        service_url: impl Into<String>,
        auth: OdataAuth,
        http: Client,
    ) -> Self {
        Self {
            name: name.into(),
            service_url: service_url.into().trim_end_matches('/').to_string(),
            http,
            auth,
            metadata: OnceCell::new(),
        }
    }

    /// Operator-visible identifier (the catalog name).
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Fetch (once) and return the raw `$metadata` EDMX document.
    async fn metadata_doc(&self) -> DataglotResult<&str> {
        self.metadata
            .get_or_try_init(|| async {
                let url = format!("{}/$metadata", self.service_url);
                let resp = self
                    .auth
                    .apply(self.http.get(&url))
                    .send()
                    .await
                    .map_err(|e| DataglotError::connection(format!("fetching $metadata: {e}")))?
                    .error_for_status()
                    .map_err(|e| {
                        DataglotError::catalog(format!("$metadata request failed: {e}"))
                    })?;
                resp.text()
                    .await
                    .map_err(|e| DataglotError::connection(format!("reading $metadata body: {e}")))
            })
            .await
            .map(String::as_str)
    }

    /// Resolve `entity_set` into a DataFusion [`TableProvider`], discovering
    /// its schema from `$metadata` (fetched once per connector).
    ///
    /// # Errors
    /// [`DataglotError`] if `$metadata` can't be fetched or the entity set /
    /// its types aren't found or supported.
    pub async fn table_provider(&self, entity_set: &str) -> DataglotResult<Arc<dyn TableProvider>> {
        let schema = parse_edmx_schema(self.metadata_doc().await?, entity_set)?;
        Ok(Arc::new(OdataTableProvider {
            http: self.http.clone(),
            service_url: self.service_url.clone(),
            auth: self.auth.clone(),
            entity_set: entity_set.to_string(),
            schema,
        }))
    }

    /// Wrap this connector as a `DataFusion` [`CatalogProvider`] so an
    /// operator can register the whole OData service as one catalog: each
    /// entity set becomes a table under a single schema named after the
    /// EDMX `<EntityContainer>` (OData v2's one namespace). Queries then
    /// read `catalog.container.EntitySet`, consistent with the SQL
    /// connectors' three-part naming.
    ///
    /// This fetches `$metadata` **once** (at boot, to enumerate the entity
    /// sets — the same fail-fast-on-unreachable point the SQL connectors
    /// use). Per-entity-set Arrow schemas are still resolved lazily inside
    /// [`SchemaProvider::table`], which delegates to [`Self::table_provider`]
    /// (rule 13).
    ///
    /// # Errors
    /// [`DataglotError`] if `$metadata` can't be fetched or parsed.
    ///
    /// [`CatalogProvider`]: datafusion::catalog::CatalogProvider
    /// [`SchemaProvider::table`]: datafusion::catalog::SchemaProvider::table
    pub async fn as_catalog_provider(
        self: &Arc<Self>,
    ) -> DataglotResult<Arc<dyn DfCatalogProvider>> {
        let (container, entity_sets) = parse_edmx_catalog(self.metadata_doc().await?)?;
        let schema: Arc<dyn DfSchemaProvider> = Arc::new(OdataSchema {
            connector: Arc::clone(self),
            container: container.clone(),
            entity_sets,
        });
        Ok(Arc::new(OdataCatalog { container, schema }))
    }
}

/// `DataFusion` [`CatalogProvider`] over one OData service. OData v2 has a
/// single namespace (the entity container), so the catalog holds exactly
/// one schema.
///
/// [`CatalogProvider`]: datafusion::catalog::CatalogProvider
struct OdataCatalog {
    /// The entity-container name — this catalog's single schema name.
    container: String,
    /// The one schema, holding every entity set as a table.
    schema: Arc<dyn DfSchemaProvider>,
}

impl fmt::Debug for OdataCatalog {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OdataCatalog")
            .field("container", &self.container)
            .finish_non_exhaustive()
    }
}

impl DfCatalogProvider for OdataCatalog {
    fn schema_names(&self) -> Vec<String> {
        vec![self.container.clone()]
    }

    fn schema(&self, name: &str) -> Option<Arc<dyn DfSchemaProvider>> {
        (name == self.container).then(|| Arc::clone(&self.schema))
    }
}

/// `DataFusion` [`SchemaProvider`] over an OData service's entity sets.
/// Entity-set names are enumerated once at construction; each table's Arrow
/// schema is resolved lazily in [`SchemaProvider::table`] (rule 13).
///
/// [`SchemaProvider`]: datafusion::catalog::SchemaProvider
struct OdataSchema {
    connector: Arc<OdataConnector>,
    /// The entity-container name (this schema's name).
    container: String,
    /// Sorted entity-set names — the tables of this schema.
    entity_sets: Vec<String>,
}

impl fmt::Debug for OdataSchema {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OdataSchema")
            .field("container", &self.container)
            .field("table_count", &self.entity_sets.len())
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl DfSchemaProvider for OdataSchema {
    fn table_names(&self) -> Vec<String> {
        self.entity_sets.clone()
    }

    fn table_exist(&self, name: &str) -> bool {
        self.entity_sets.iter().any(|t| t == name)
    }

    async fn table(&self, name: &str) -> DfResult<Option<Arc<dyn TableProvider>>> {
        // Cheap negative path — skip the remote schema fetch for a typo /
        // `SELECT * FROM catalog.container.does_not_exist`.
        if !self.table_exist(name) {
            return Ok(None);
        }
        let provider = self
            .connector
            .table_provider(name)
            .await
            .map_err(|e| DataFusionError::External(Box::new(e)))?;
        Ok(Some(provider))
    }
}

/// A DataFusion `TableProvider` over one OData entity set.
struct OdataTableProvider {
    http: Client,
    service_url: String,
    auth: OdataAuth,
    entity_set: String,
    schema: SchemaRef,
}

impl fmt::Debug for OdataTableProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OdataTableProvider")
            .field("entity_set", &self.entity_set)
            .field("service_url", &self.service_url)
            .field("auth", &self.auth)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl TableProvider for OdataTableProvider {
    fn schema(&self) -> SchemaRef {
        self.schema.clone()
    }

    fn table_type(&self) -> TableType {
        TableType::Base
    }

    fn supports_filters_pushdown(
        &self,
        filters: &[&Expr],
    ) -> DfResult<Vec<TableProviderFilterPushDown>> {
        let owned: Vec<Expr> = filters.iter().map(|f| (*f).clone()).collect();
        let translation = translate_filters(&owned);
        let not_pushed = translation.pushed.iter().filter(|p| !**p).count();
        if not_pushed > 0 {
            // A filter that can't be expressed as OData `$filter` (LIKE, IN,
            // function, cast, …) means the whole entity set is fetched and
            // filtered locally. Surface *why* a query is slow — otherwise the
            // fallback is invisible.
            tracing::debug!(
                not_pushed,
                total = translation.pushed.len(),
                "odata: {not_pushed} filter(s) not pushable to the source; they will be applied locally after a full entity fetch"
            );
        }
        Ok(translation
            .pushed
            .into_iter()
            .map(|pushed| {
                if pushed {
                    TableProviderFilterPushDown::Exact
                } else {
                    TableProviderFilterPushDown::Unsupported
                }
            })
            .collect())
    }

    async fn scan(
        &self,
        _state: &dyn Session,
        projection: Option<&Vec<usize>>,
        filters: &[Expr],
        limit: Option<usize>,
    ) -> DfResult<Arc<dyn ExecutionPlan>> {
        let projected_schema = match projection {
            Some(p) => Arc::new(self.schema.project(p)?),
            None => self.schema.clone(),
        };

        let mut query: Vec<(&'static str, String)> = Vec::new();
        // `$select` — only the projected columns (skip when projecting all).
        if let Some(p) = projection {
            if !p.is_empty() && p.len() != self.schema.fields().len() {
                let cols = p
                    .iter()
                    .map(|&i| self.schema.field(i).name().as_str())
                    .collect::<Vec<_>>()
                    .join(",");
                query.push(("$select", cols));
            }
        }
        // `$filter` — the pushable predicates (DataFusion only passes the ones
        // `supports_filters_pushdown` marked Exact).
        if let Some(filter) = translate_filters(filters).filter {
            query.push(("$filter", filter));
        }
        // `$top` — the row limit.
        if let Some(limit) = limit {
            query.push(("$top", limit.to_string()));
        }
        // Ask for JSON (OData v2 defaults to Atom/XML otherwise).
        query.push(("$format", "json".to_string()));

        Ok(Arc::new(OdataScanExec::new(
            self.http.clone(),
            format!("{}/{}", self.service_url, self.entity_set),
            query,
            self.auth.clone(),
            projected_schema,
        )))
    }
}

/// The physical scan: one HTTP `GET` decoded into a single Arrow batch.
pub(crate) struct OdataScanExec {
    http: Client,
    url: String,
    query: Vec<(&'static str, String)>,
    auth: OdataAuth,
    schema: SchemaRef,
    properties: Arc<PlanProperties>,
}

impl OdataScanExec {
    fn new(
        http: Client,
        url: String,
        query: Vec<(&'static str, String)>,
        auth: OdataAuth,
        schema: SchemaRef,
    ) -> Self {
        let properties = Arc::new(PlanProperties::new(
            EquivalenceProperties::new(schema.clone()),
            Partitioning::UnknownPartitioning(1),
            EmissionType::Incremental,
            Boundedness::Bounded,
        ));
        Self {
            http,
            url,
            query,
            auth,
            schema,
            properties,
        }
    }
}

impl fmt::Debug for OdataScanExec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // No auth rendered (rule 12).
        f.debug_struct("OdataScanExec")
            .field("url", &self.url)
            .field("query", &self.query)
            .finish_non_exhaustive()
    }
}

impl DisplayAs for OdataScanExec {
    fn fmt_as(&self, _t: DisplayFormatType, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let params = self
            .query
            .iter()
            .filter(|(k, _)| *k != "$format")
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join(" ");
        write!(f, "OdataScanExec: {}?{params}", self.url)
    }
}

impl ExecutionPlan for OdataScanExec {
    fn name(&self) -> &'static str {
        "OdataScanExec"
    }

    fn properties(&self) -> &Arc<PlanProperties> {
        &self.properties
    }

    fn children(&self) -> Vec<&Arc<dyn ExecutionPlan>> {
        vec![]
    }

    fn with_new_children(
        self: Arc<Self>,
        _children: Vec<Arc<dyn ExecutionPlan>>,
    ) -> DfResult<Arc<dyn ExecutionPlan>> {
        Ok(self)
    }

    fn execute(
        &self,
        _partition: usize,
        _context: Arc<TaskContext>,
    ) -> DfResult<SendableRecordBatchStream> {
        let http = self.http.clone();
        let base_url = self.url.clone();
        let query = self.query.clone();
        let auth = self.auth.clone();
        let schema = self.schema.clone();
        let decode_schema = self.schema.clone();

        // Fetch the first page (base URL + our pushed `$select`/`$filter`/
        // `$top`), then follow the server's `__next` link — which re-encodes
        // the query plus a skiptoken — up to `MAX_PAGES`. All pages share one
        // schema, so each decodes to a batch and streams out in order.
        let fetch_all = async move {
            let mut batches: Vec<RecordBatch> = Vec::new();
            let mut next: Option<String> = None;
            for _ in 0..MAX_PAGES {
                let req = match &next {
                    Some(u) => auth.apply(http.get(u)),
                    None => auth.apply(http.get(&base_url).query(&query)),
                };
                let resp = req
                    .header("Accept", "application/json")
                    .send()
                    .await
                    .map_err(external)?
                    .error_for_status()
                    .map_err(external)?;
                let body = resp.text().await.map_err(external)?;
                let (batch, link) =
                    decode_entity_set_page(&body, &decode_schema).map_err(external)?;
                batches.push(batch);
                match link {
                    None => return Ok(batches),
                    Some(link) => {
                        // Resolve a possibly-relative `__next` against the URL
                        // of the page we just fetched (RFC 3986 join).
                        let base = next.as_deref().unwrap_or(&base_url);
                        let resolved = reqwest::Url::parse(base)
                            .and_then(|b| b.join(&link))
                            .map_err(external)?;
                        next = Some(resolved.to_string());
                    }
                }
            }
            // Cap reached with a `__next` still pending — the result is
            // truncated. WARN (never the credentials / full URL with a token).
            tracing::warn!(
                max_pages = MAX_PAGES,
                "OData source returned more than MAX_PAGES pages; result truncated at the cap"
            );
            Ok(batches)
        };

        // One future yielding all pages, flattened into a stream of batches.
        let stream = futures::stream::once(fetch_all)
            .map(|res: DfResult<Vec<RecordBatch>>| match res {
                Ok(batches) => {
                    futures::stream::iter(batches.into_iter().map(Ok).collect::<Vec<_>>())
                }
                Err(e) => futures::stream::iter(vec![Err(e)]),
            })
            .flatten();
        Ok(Box::pin(RecordBatchStreamAdapter::new(schema, stream)))
    }
}

/// Wrap any error as a `DataFusionError::External` for the execution stream.
fn external<E: std::error::Error + Send + Sync + 'static>(e: E) -> DataFusionError {
    DataFusionError::External(Box::new(e))
}

#[cfg(test)]
mod tests {
    use super::*;

    use datafusion::prelude::SessionContext;
    use wiremock::matchers::{method, path, query_param, query_param_is_missing};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const EDMX: &str = r#"<Schema xmlns="http://schemas.microsoft.com/ado/2008/09/edm">
      <EntityType Name="BP">
        <Property Name="BusinessPartner" Type="Edm.String" Nullable="false"/>
        <Property Name="Age" Type="Edm.Int32"/>
        <Property Name="City" Type="Edm.String"/>
      </EntityType>
      <EntityContainer><EntitySet Name="A_BusinessPartner" EntityType="X.BP"/></EntityContainer>
    </Schema>"#;

    const RESULTS: &str = r#"{"d":{"results":[
        {"BusinessPartner":"1","Age":30,"City":"Berlin"},
        {"BusinessPartner":"2","Age":41,"City":"Berlin"}
    ]}}"#;

    async fn mock_service() -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/$metadata"))
            .respond_with(ResponseTemplate::new(200).set_body_string(EDMX))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/A_BusinessPartner"))
            .respond_with(ResponseTemplate::new(200).set_body_string(RESULTS))
            .mount(&server)
            .await;
        server
    }

    #[tokio::test]
    async fn discovers_schema_from_metadata() {
        let server = mock_service().await;
        let conn =
            OdataConnector::connect("sap", server.uri(), OdataAuth::Bearer { token: "t".into() })
                .expect("connect");
        assert_eq!(conn.name(), "sap");
        let provider = conn
            .table_provider("A_BusinessPartner")
            .await
            .expect("schema");
        let schema = provider.schema();
        assert_eq!(schema.fields().len(), 3);
        assert_eq!(schema.field(0).name(), "BusinessPartner");
        assert!(!schema.field(0).is_nullable());
    }

    #[tokio::test]
    async fn query_returns_rows_and_pushes_select_filter_top() {
        let server = mock_service().await;
        let conn = OdataConnector::connect(
            "sap",
            server.uri(),
            OdataAuth::Basic {
                user: "u".into(),
                password: "p".into(),
            },
        )
        .expect("connect");
        let provider = conn
            .table_provider("A_BusinessPartner")
            .await
            .expect("schema");

        let ctx = SessionContext::new();
        ctx.register_table("bp", provider).expect("register");
        // OData property names are case-sensitive, so they're quoted (an
        // unquoted identifier would be lowercased by SQL and not match).
        let batches = ctx
            .sql(r#"SELECT "City", "Age" FROM bp WHERE "Age" > 18 LIMIT 5"#)
            .await
            .expect("plan")
            .collect()
            .await
            .expect("run");

        let rows: usize = batches
            .iter()
            .map(arrow::array::RecordBatch::num_rows)
            .sum();
        assert_eq!(rows, 2, "both mock rows returned");

        // The entity-set GET must carry the pushed $select / $filter / $top.
        let requests = server.received_requests().await.unwrap();
        let scan = requests
            .iter()
            .find(|r| r.url.path() == "/A_BusinessPartner")
            .expect("entity-set request was issued");
        let q = scan.url.query().unwrap_or_default();
        assert!(
            q.contains("%24filter") || q.contains("$filter"),
            "has $filter: {q}"
        );
        // The pushed predicate (URL-encoded): Age gt 18.
        let decoded = scan.url.as_str();
        assert!(
            decoded.contains("Age+gt+18")
                || decoded.contains("Age%20gt%2018")
                || decoded.contains("Age gt 18"),
            "filter pushed: {decoded}"
        );
        assert!(
            q.contains("top=5") || q.contains("top%3D5") || decoded.contains("%24top=5"),
            "has $top=5: {decoded}"
        );
        assert!(
            decoded.contains("select=") || decoded.contains("%24select="),
            "has $select: {decoded}"
        );
    }

    #[tokio::test]
    async fn as_catalog_provider_exposes_entity_sets_as_tables() {
        // EDMX with a *named* container — it becomes the schema name, so the
        // entity set is queryable as `catalog.container.entityset`.
        const EDMX_NAMED: &str = r#"<Schema xmlns="http://schemas.microsoft.com/ado/2008/09/edm">
          <EntityType Name="BP">
            <Property Name="BusinessPartner" Type="Edm.String" Nullable="false"/>
            <Property Name="City" Type="Edm.String"/>
          </EntityType>
          <EntityContainer Name="API_BP"><EntitySet Name="A_BusinessPartner" EntityType="X.BP"/></EntityContainer>
        </Schema>"#;
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/$metadata"))
            .respond_with(ResponseTemplate::new(200).set_body_string(EDMX_NAMED))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/A_BusinessPartner"))
            .respond_with(ResponseTemplate::new(200).set_body_string(RESULTS))
            .mount(&server)
            .await;

        let conn = Arc::new(
            OdataConnector::connect("sap", server.uri(), OdataAuth::Bearer { token: "t".into() })
                .expect("connect"),
        );
        let catalog = conn.as_catalog_provider().await.expect("catalog");

        // The container is the one schema; the entity set is its one table.
        assert_eq!(catalog.schema_names(), vec!["API_BP".to_string()]);
        assert!(catalog.schema("nonexistent").is_none());
        let schema = catalog.schema("API_BP").expect("schema present");
        assert_eq!(schema.table_names(), vec!["A_BusinessPartner".to_string()]);
        assert!(schema.table_exist("A_BusinessPartner"));
        // Unknown table takes the cheap negative path (no remote fetch).
        assert!(schema.table("does_not_exist").await.expect("ok").is_none());

        // End-to-end via three-part `catalog.container.entityset` naming.
        // Container / entity-set names are case-sensitive, so they're quoted
        // (an unquoted identifier would be lowercased by SQL and not match).
        let ctx = SessionContext::new();
        ctx.register_catalog("sap", catalog);
        let batches = ctx
            .sql(r#"SELECT "City" FROM sap."API_BP"."A_BusinessPartner""#)
            .await
            .expect("plan")
            .collect()
            .await
            .expect("run");
        let rows: usize = batches
            .iter()
            .map(arrow::array::RecordBatch::num_rows)
            .sum();
        assert_eq!(rows, 2, "both mock rows returned through the catalog");
    }

    #[tokio::test]
    async fn follows_next_link_across_pages() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/$metadata"))
            .respond_with(ResponseTemplate::new(200).set_body_string(EDMX))
            .mount(&server)
            .await;
        // Page 1 (no skiptoken): two rows + a `__next` pointing at page 2.
        let next = format!("{}/A_BusinessPartner?$skiptoken=p2", server.uri());
        let page1 = format!(
            r#"{{"d":{{"results":[
                {{"BusinessPartner":"1","Age":30,"City":"Berlin"}},
                {{"BusinessPartner":"2","Age":41,"City":"Berlin"}}
            ],"__next":"{next}"}}}}"#
        );
        Mock::given(method("GET"))
            .and(path("/A_BusinessPartner"))
            .and(query_param_is_missing("$skiptoken"))
            .respond_with(ResponseTemplate::new(200).set_body_string(page1))
            .mount(&server)
            .await;
        // Page 2 (skiptoken=p2): one row, no `__next` → pagination ends.
        let page2 = r#"{"d":{"results":[{"BusinessPartner":"3","Age":52,"City":"Munich"}]}}"#;
        Mock::given(method("GET"))
            .and(path("/A_BusinessPartner"))
            .and(query_param("$skiptoken", "p2"))
            .respond_with(ResponseTemplate::new(200).set_body_string(page2))
            .mount(&server)
            .await;

        let conn =
            OdataConnector::connect("sap", server.uri(), OdataAuth::Bearer { token: "t".into() })
                .expect("connect");
        let provider = conn
            .table_provider("A_BusinessPartner")
            .await
            .expect("schema");
        let ctx = SessionContext::new();
        ctx.register_table("bp", provider).expect("register");
        let batches = ctx
            .sql("SELECT * FROM bp")
            .await
            .expect("plan")
            .collect()
            .await
            .expect("run");
        let rows: usize = batches
            .iter()
            .map(arrow::array::RecordBatch::num_rows)
            .sum();
        assert_eq!(rows, 3, "both pages' rows are returned (2 + 1)");
    }

    #[tokio::test]
    async fn pagination_stops_at_max_pages() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/$metadata"))
            .respond_with(ResponseTemplate::new(200).set_body_string(EDMX))
            .mount(&server)
            .await;
        // Every page returns one row and a `__next` that never terminates —
        // the connector must stop at MAX_PAGES rather than loop forever.
        let loop_next = format!("{}/A_BusinessPartner?$skiptoken=loop", server.uri());
        let body = format!(
            r#"{{"d":{{"results":[{{"BusinessPartner":"x","Age":1,"City":"C"}}],"__next":"{loop_next}"}}}}"#
        );
        Mock::given(method("GET"))
            .and(path("/A_BusinessPartner"))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .mount(&server)
            .await;

        let conn =
            OdataConnector::connect("sap", server.uri(), OdataAuth::Bearer { token: "t".into() })
                .expect("connect");
        let provider = conn
            .table_provider("A_BusinessPartner")
            .await
            .expect("schema");
        let ctx = SessionContext::new();
        ctx.register_table("bp", provider).expect("register");
        let batches = ctx
            .sql("SELECT * FROM bp")
            .await
            .expect("plan")
            .collect()
            .await
            .expect("run");
        let rows: usize = batches
            .iter()
            .map(arrow::array::RecordBatch::num_rows)
            .sum();
        // One row per page, capped at MAX_PAGES — proves the scan terminates.
        assert_eq!(rows, MAX_PAGES, "capped at MAX_PAGES pages");
    }

    #[tokio::test]
    async fn explain_shows_scan_node_with_pushed_predicates() {
        // DoD point 2: EXPLAIN surfaces the OData scan node and the pushed
        // projection / predicate / limit on it — so an operator can see what
        // was pushed to the source (the role the VirtualExecutionPlan node
        // plays for the SQL connectors).
        let server = mock_service().await;
        let conn =
            OdataConnector::connect("sap", server.uri(), OdataAuth::Bearer { token: "t".into() })
                .expect("connect");
        let provider = conn
            .table_provider("A_BusinessPartner")
            .await
            .expect("schema");
        let ctx = SessionContext::new();
        ctx.register_table("bp", provider).expect("register");
        let physical = ctx
            .sql(r#"SELECT "City" FROM bp WHERE "Age" > 18 LIMIT 5"#)
            .await
            .expect("plan")
            .create_physical_plan()
            .await
            .expect("physical plan");
        let display = datafusion::physical_plan::displayable(physical.as_ref())
            .indent(true)
            .to_string();

        assert!(
            display.contains("OdataScanExec"),
            "scan node named in plan:\n{display}"
        );
        assert!(
            display.contains("$filter=Age gt 18"),
            "pushed predicate on scan node:\n{display}"
        );
        assert!(
            display.contains("$top=5"),
            "pushed limit on scan node:\n{display}"
        );
        assert!(
            display.contains("$select="),
            "pushed projection on scan node:\n{display}"
        );
    }

    #[test]
    fn auth_debug_redacts_secrets() {
        let basic = OdataAuth::Basic {
            user: "svc".into(),
            password: "hunter2".into(),
        };
        let dbg = format!("{basic:?}");
        assert!(dbg.contains("svc"));
        assert!(!dbg.contains("hunter2"), "password must be redacted: {dbg}");

        let bearer = OdataAuth::Bearer {
            token: "secret-token".into(),
        };
        assert!(!format!("{bearer:?}").contains("secret-token"));
    }

    #[test]
    fn connector_debug_redacts_auth() {
        let conn = OdataConnector::connect(
            "sap",
            "https://host/svc",
            OdataAuth::Basic {
                user: "u".into(),
                password: "topsecret".into(),
            },
        )
        .unwrap();
        assert!(!format!("{conn:?}").contains("topsecret"));
    }
}

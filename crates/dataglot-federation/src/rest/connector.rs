//! REST connector: auth, source configuration, and the queryable
//! `TableProvider` / `CatalogProvider` ( slices 1–3).
//!
//! A REST API is queried with an HTTP `GET` and has no remote SQL engine to
//! unparse to, so — per hard rule 3 — this is a **direct
//! [`TableProvider`]**, a sibling of the `OData` connector, not a
//! `datafusion-federation` `SQLExecutor`. Unlike `OData` there is no metadata
//! document, so each table declares its Arrow schema and the row array is
//! located by a configurable dot-path (`records_path`).
//!
//! Slice 2 fetches the endpoint and applies projection + limit locally; slice 3
//! adds pagination (follow a "next page" link until exhausted — e.g.
//! Salesforce's `nextRecordsUrl`). Predicate / `$select` pushdown to the API is
//! slice 4.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use arrow::array::RecordBatch;
use arrow::datatypes::SchemaRef;
use async_trait::async_trait;
use datafusion::catalog::{
    CatalogProvider as DfCatalogProvider, SchemaProvider as DfSchemaProvider, Session,
};
use datafusion::common::{Column, ScalarValue};
use datafusion::datasource::TableProvider;
use datafusion::error::{DataFusionError, Result as DfResult};
use datafusion::execution::TaskContext;
use datafusion::logical_expr::{
    BinaryExpr, Expr, Operator, TableProviderFilterPushDown, TableType,
};
use datafusion::physical_expr::EquivalenceProperties;
use datafusion::physical_plan::execution_plan::{Boundedness, EmissionType};
use datafusion::physical_plan::stream::RecordBatchStreamAdapter;
use datafusion::physical_plan::{
    DisplayAs, DisplayFormatType, ExecutionPlan, Partitioning, PlanProperties,
    SendableRecordBatchStream,
};
use futures::StreamExt;
use reqwest::{Client, Url};

use dataglot_core::{DataglotError, Result as DataglotResult};

use super::decode::decode_json_page;
use super::oauth2::{OAuth2Config, OAuth2TokenCache};

/// How the REST connector authenticates to a source.
///
/// `Debug` is hand-written to never render a password, token, or header value
/// (hard rule 12).
#[derive(Clone)]
pub enum RestAuth {
    /// No authentication (public endpoint).
    None,
    /// HTTP Basic. The password is resolved from config by the caller
    /// (e.g. an env var), never inlined.
    Basic {
        /// The user name.
        user: String,
        /// The password (never logged / rendered).
        password: String,
    },
    /// OAuth 2.0 / static bearer token — e.g. a Salesforce session token
    /// (refresh is the caller's job).
    Bearer {
        /// The token (never logged / rendered).
        token: String,
    },
    /// A custom header carrying an API key (e.g. `x-api-key: …`).
    Header {
        /// Header name (not a secret; logged).
        name: String,
        /// Header value (never logged / rendered).
        value: String,
    },
}

impl fmt::Debug for RestAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => f.write_str("None"),
            Self::Basic { user, .. } => f
                .debug_struct("Basic")
                .field("user", user)
                .field("password", &"<redacted>")
                .finish(),
            Self::Bearer { .. } => f.write_str("Bearer(<redacted>)"),
            Self::Header { name, .. } => f
                .debug_struct("Header")
                .field("name", name)
                .field("value", &"<redacted>")
                .finish(),
        }
    }
}

impl RestAuth {
    /// Apply the credentials to an outgoing request.
    pub fn apply(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match self {
            Self::None => req,
            Self::Basic { user, password } => req.basic_auth(user, Some(password)),
            Self::Bearer { token } => req.bearer_auth(token),
            Self::Header { name, value } => req.header(name.as_str(), value.as_str()),
        }
    }
}

/// How the connector fetches additional pages of a result set.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum RestPagination {
    /// A single request; the whole result set is one response.
    #[default]
    None,
    /// Follow a "next page" URL found at `next_path` (a dot-path into each
    /// response) until it is absent — e.g. Salesforce's `nextRecordsUrl`. The
    /// URL may be absolute or relative to the request URL.
    NextLink {
        /// Dot-path to the next-page URL in the JSON response.
        next_path: String,
    },
}

/// Maps an equality filter on a column to an outgoing query parameter, so a
/// `WHERE <column> = <literal>` predicate is pushed to the API as
/// `?<param>=<literal>` on the `GET` (, slice 4).
///
/// Pushdown is **declared per table** rather than inferred: an arbitrary REST
/// endpoint only accepts the query parameters it documents, so the connector
/// pushes only the columns an operator explicitly maps here. Anything not
/// listed falls back to local filtering (DataFusion applies it after the
/// fetch), so results are always correct regardless of what the API honours.
///
/// Interaction with [`RestPagination::NextLink`]: the mapped parameters are set
/// on the **initial** request only; continuation URLs are followed as the API
/// returns them (our profiles' cursors — e.g. Salesforce's `nextRecordsUrl` —
/// already encode the originating query). The pushdown is reported `Inexact`,
/// so DataFusion re-checks every row locally and the result stays correct even
/// if a page comes back unfiltered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RestPushdownParam {
    /// The table column an equality filter is matched against.
    pub column: String,
    /// The query-parameter name to set on the request (often equal to
    /// `column`, e.g. a `time` column → `?time=…`).
    pub param: String,
}

/// Static description of a REST table source: where to `GET`, where the row
/// array lives in the response, how to authenticate, and how to paginate.
///
/// The Arrow schema is declared separately (a REST API has no universal
/// metadata document like OData's `$metadata`). The `RestTableProvider`
/// consumes this to issue the request(s) and decode via
/// [`super::decode::decode_json_page`].
#[derive(Clone, Debug)]
pub struct RestSourceConfig {
    /// Fully-qualified request URL for the table's collection endpoint.
    pub url: String,
    /// Dot-path to the row array in the JSON response (`""` = the body is
    /// itself the array). E.g. `"records"` for Salesforce.
    pub records_path: String,
    /// Authentication (never logged — see [`RestAuth`]'s redacting `Debug`).
    pub auth: RestAuth,
    /// How to fetch subsequent pages (default: [`RestPagination::None`]).
    pub pagination: RestPagination,
    /// Equality filters to push to the API as query parameters (default: none
    /// — every filter is applied locally by DataFusion).
    pub pushdown: Vec<RestPushdownParam>,
}

/// Reused-client HTTP timeout for REST requests.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Keep idle pooled connections warm for a while so a burst of queries reuses
/// sockets instead of re-dialing (the dominant cost under high concurrency).
const POOL_IDLE_TIMEOUT: Duration = Duration::from_secs(90);
/// TCP keep-alive on pooled connections, so long-lived idle sockets aren't
/// silently reaped by a NAT/firewall between bursts.
const TCP_KEEPALIVE: Duration = Duration::from_mins(1);

/// Tunables for the connector's shared HTTP client.
///
/// The defaults suit ordinary REST APIs (HTTP/1.1 with connection pooling).
/// The high-concurrency, HTTP-bound workload in  — hundreds of queries
/// each parked on a slow response — is where `http2_prior_knowledge` matters:
/// it multiplexes many in-flight requests over a *few* TCP connections instead
/// of one socket per request, which is what keeps a client off the
/// ephemeral-port / file-descriptor wall.
#[derive(Clone, Debug, Default)]
pub struct RestClientOptions {
    /// Speak HTTP/2 with prior knowledge — cleartext `h2c` or `h2` — rather
    /// than HTTP/1.1. Enables request multiplexing (many concurrent streams per
    /// connection). Only for endpoints known to speak HTTP/2; an HTTP/1.1-only
    /// server will reject the h2 preface.
    ///
    /// Note: this setting applies to the connector's whole shared client, so
    /// when OAuth 2.0 is configured ([`RestConnector::with_oauth2_config`]) the
    /// **token endpoint** must also speak HTTP/2 — enable it only when both the
    /// data API and its identity provider support HTTP/2 prior knowledge.
    pub http2_prior_knowledge: bool,
}

/// Build the connector's shared, tuned HTTP client from `opts`.
fn build_client(opts: &RestClientOptions) -> DataglotResult<Client> {
    let mut builder = Client::builder()
        .timeout(REQUEST_TIMEOUT)
        .pool_idle_timeout(POOL_IDLE_TIMEOUT)
        .tcp_keepalive(TCP_KEEPALIVE);
    if opts.http2_prior_knowledge {
        builder = builder.http2_prior_knowledge();
    }
    builder
        .build()
        .map_err(|e| DataglotError::connection(format!("failed to build HTTP client: {e}")))
}

/// A single declared REST table: how to fetch it plus its Arrow schema.
///
/// A REST API has no metadata document, so the schema is declared per table
/// (unlike `OData`, which reads it from `$metadata`).
#[derive(Clone, Debug)]
pub struct RestTable {
    /// Table name as exposed in the catalog.
    pub name: String,
    /// Where to `GET`, where the row array lives, and how to authenticate.
    pub config: RestSourceConfig,
    /// The Arrow schema the JSON rows are decoded into.
    pub schema: SchemaRef,
}

/// A REST/JSON federation source: a reused HTTP client plus the set of
/// declared tables it serves. Produces DataFusion [`TableProvider`]s and a
/// [`CatalogProvider`](DfCatalogProvider) for registration on a
/// `SessionContext`.
#[derive(Debug)]
pub struct RestConnector {
    name: String,
    http: Client,
    tables: Vec<RestTable>,
    /// When set, every table request authenticates with a live OAuth 2.0
    /// bearer from this shared cache instead of the per-table static `auth`.
    oauth: Option<Arc<OAuth2TokenCache>>,
}

impl RestConnector {
    /// Build a connector with its own tuned, timeout-bounded HTTP client
    /// (default [`RestClientOptions`] — HTTP/1.1 with connection pooling).
    ///
    /// # Errors
    /// [`DataglotError::Connection`] if the HTTP client cannot be built or a
    /// table URL is invalid; [`DataglotError::Catalog`] for an invalid pushdown
    /// mapping (see [`Self::with_client`]).
    pub fn new(name: impl Into<String>, tables: Vec<RestTable>) -> DataglotResult<Self> {
        Self::new_with_options(name, tables, &RestClientOptions::default())
    }

    /// Build a connector with a client tuned by `opts` — e.g. to enable HTTP/2
    /// multiplexing for a high-concurrency, HTTP-bound source.
    ///
    /// Each table's URL is validated here so a malformed endpoint fails fast at
    /// registration rather than at query time.
    ///
    /// # Errors
    /// [`DataglotError::Connection`] if a table URL is invalid or the HTTP
    /// client cannot be built; [`DataglotError::Catalog`] for an invalid
    /// pushdown mapping (see [`Self::with_client`]).
    pub fn new_with_options(
        name: impl Into<String>,
        tables: Vec<RestTable>,
        opts: &RestClientOptions,
    ) -> DataglotResult<Self> {
        Self::with_client(name, tables, build_client(opts)?)
    }

    /// Build a connector reusing an existing HTTP client (tests inject one
    /// pointed at a mock server). This is the shared construction sink, so it
    /// runs the same table validation as [`Self::new_with_options`].
    ///
    /// # Errors
    /// [`DataglotError::Connection`] for an unparseable table URL;
    /// [`DataglotError::Catalog`] for a pushdown on an unknown column or a
    /// duplicate pushdown parameter name.
    pub fn with_client(
        name: impl Into<String>,
        tables: Vec<RestTable>,
        http: Client,
    ) -> DataglotResult<Self> {
        Self::validate_tables(&tables)?;
        Ok(Self {
            name: name.into(),
            http,
            tables,
            oauth: None,
        })
    }

    /// Validate declared tables at construction: each URL parses, every pushdown
    /// column exists in the table schema, and no two columns map to the same
    /// query parameter.
    ///
    /// # Errors
    /// [`DataglotError::Connection`] for an unparseable URL (the raw URL is not
    /// echoed — it may carry user-info, rule 12); [`DataglotError::Catalog`] for
    /// an unknown pushdown column or a duplicate pushdown parameter name — the
    /// latter would emit `?q=A&q=B` for a conjunctive predicate, and an API that
    /// honours only one value could omit rows the local `Inexact` recheck can't
    /// restore.
    fn validate_tables(tables: &[RestTable]) -> DataglotResult<()> {
        for table in tables {
            Url::parse(&table.config.url).map_err(|e| {
                DataglotError::connection(format!("table '{}' has an invalid URL: {e}", table.name))
            })?;
            let cap = table.config.pushdown.len();
            let mut seen_params = std::collections::HashSet::with_capacity(cap);
            let mut seen_cols = std::collections::HashSet::with_capacity(cap);
            for p in &table.config.pushdown {
                if table.schema.index_of(&p.column).is_err() {
                    return Err(DataglotError::catalog(format!(
                        "table '{}' configures pushdown for unknown column '{}'",
                        table.name, p.column
                    )));
                }
                // A column mapped twice: `param_for` uses `.find()`, so all but
                // the first mapping would be silently dead config.
                if !seen_cols.insert(p.column.as_str()) {
                    return Err(DataglotError::catalog(format!(
                        "table '{}' configures pushdown for column '{}' more than once",
                        table.name, p.column
                    )));
                }
                if !seen_params.insert(p.param.as_str()) {
                    return Err(DataglotError::catalog(format!(
                        "table '{}' maps multiple pushdown columns to the same query parameter '{}'",
                        table.name, p.param
                    )));
                }
            }
        }
        Ok(())
    }

    /// Authenticate every table request with a live OAuth 2.0 bearer from
    /// `cache` (client-credentials grant, refreshed before expiry) instead of
    /// the per-table static `auth`. Used by the Salesforce profile.
    #[must_use]
    pub fn with_oauth2(mut self, cache: Arc<OAuth2TokenCache>) -> Self {
        self.oauth = Some(cache);
        self
    }

    /// Enable OAuth 2.0 auth from a config, using the connector's own HTTP
    /// client to acquire and cache the token (one client for data + token
    /// requests). Convenience over [`Self::with_oauth2`] for callers that only
    /// have the config (e.g. the server's `kind = "rest"` builder).
    #[must_use]
    pub fn with_oauth2_config(self, config: OAuth2Config) -> Self {
        let cache = Arc::new(OAuth2TokenCache::new(self.http.clone(), config));
        self.with_oauth2(cache)
    }

    /// The connector's name (the catalog it backs).
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Names of the declared tables.
    #[must_use]
    pub fn table_names(&self) -> Vec<String> {
        self.tables.iter().map(|t| t.name.clone()).collect()
    }

    /// Build a [`TableProvider`] for `name`, or `None` if no such table is
    /// declared.
    #[must_use]
    pub fn table_provider(&self, name: &str) -> Option<Arc<dyn TableProvider>> {
        self.tables.iter().find(|t| t.name == name).map(|t| {
            Arc::new(RestTableProvider {
                http: self.http.clone(),
                url: t.config.url.clone(),
                records_path: t.config.records_path.clone(),
                auth: t.config.auth.clone(),
                pagination: t.config.pagination.clone(),
                pushdown: t.config.pushdown.clone(),
                oauth: self.oauth.clone(),
                schema: t.schema.clone(),
            }) as Arc<dyn TableProvider>
        })
    }

    /// Wrap this connector as a DataFusion
    /// [`CatalogProvider`](DfCatalogProvider) exposing the declared tables
    /// under a single schema `schema_name` (e.g. `"public"`).
    #[must_use]
    pub fn as_catalog_provider(
        self: &Arc<Self>,
        schema_name: impl Into<String>,
    ) -> Arc<dyn DfCatalogProvider> {
        let schema: Arc<dyn DfSchemaProvider> = Arc::new(RestSchema {
            connector: Arc::clone(self),
        });
        Arc::new(RestCatalog {
            schema_name: schema_name.into(),
            schema,
        })
    }
}

/// A DataFusion [`TableProvider`] over a single REST/JSON endpoint.
#[derive(Debug)]
struct RestTableProvider {
    http: Client,
    url: String,
    records_path: String,
    auth: RestAuth,
    pagination: RestPagination,
    /// Columns whose equality filters are pushed to the API as query params.
    pushdown: Vec<RestPushdownParam>,
    oauth: Option<Arc<OAuth2TokenCache>>,
    schema: SchemaRef,
}

/// If `expr` is an equality `col = literal` (either operand order), return the
/// column and literal by reference — no allocation. Shared by the cheap
/// planning check and the value-producing scan path.
fn equality_parts(expr: &Expr) -> Option<(&Column, &ScalarValue)> {
    let Expr::BinaryExpr(BinaryExpr { left, op, right }) = expr else {
        return None;
    };
    if *op != Operator::Eq {
        return None;
    }
    match (left.as_ref(), right.as_ref()) {
        (Expr::Column(col), Expr::Literal(lit, ..))
        | (Expr::Literal(lit, ..), Expr::Column(col)) => Some((col, lit)),
        _ => None,
    }
}

impl RestTableProvider {
    /// Cheap, allocation-free pushability check for query planning
    /// (`supports_filters_pushdown`): a `col = literal` whose column is declared
    /// pushable and whose literal is a type we can render as a query param.
    fn is_pushable(&self, expr: &Expr) -> bool {
        let Some((col, lit)) = equality_parts(expr) else {
            return false;
        };
        self.pushdown.iter().any(|p| p.column == col.name) && is_pushable_scalar(lit)
    }

    /// If `expr` is a pushable `col = literal`, return the `(param_name, value)`
    /// to set on the request URL. Otherwise `None` (the filter stays local).
    /// Allocates — used at scan time, not during planning.
    fn pushable(&self, expr: &Expr) -> Option<(String, String)> {
        let (col, lit) = equality_parts(expr)?;
        let param = self.param_for(col)?;
        let value = scalar_to_param(lit)?;
        Some((param, value))
    }

    /// The query-param name mapped to `col`, or `None` if `col` isn't pushable.
    fn param_for(&self, col: &Column) -> Option<String> {
        self.pushdown
            .iter()
            .find(|p| p.column == col.name)
            .map(|p| p.param.clone())
    }

    /// Set every pushable equality filter in `filters` on `base` as a query
    /// parameter, returning the final request URL. A pushed key *replaces* any
    /// same-named param already on the configured URL, so the SQL predicate
    /// wins rather than producing a duplicate `?k=configured&k=pushed` (which an
    /// API might resolve to the wrong value).
    fn url_with_pushdown(&self, base: &str, filters: &[Expr]) -> DfResult<String> {
        let pairs: Vec<(String, String)> =
            filters.iter().filter_map(|f| self.pushable(f)).collect();
        if pairs.is_empty() {
            return Ok(base.to_string());
        }
        let mut url = Url::parse(base).map_err(external)?;
        let pushed_keys: std::collections::HashSet<&str> =
            pairs.iter().map(|(k, _)| k.as_str()).collect();
        // Existing params not being overridden, preserved in order.
        let kept: Vec<(String, String)> = url
            .query_pairs()
            .filter(|(k, _)| !pushed_keys.contains(k.as_ref()))
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        url.set_query(None);
        {
            let mut qp = url.query_pairs_mut();
            for (k, v) in kept.iter().chain(pairs.iter()) {
                qp.append_pair(k, v);
            }
        }
        Ok(url.to_string())
    }
}

/// Whether a scalar literal is a type [`scalar_to_param`] can render — checked
/// without allocating during planning.
fn is_pushable_scalar(v: &ScalarValue) -> bool {
    matches!(
        v,
        ScalarValue::Int8(Some(_))
            | ScalarValue::Int16(Some(_))
            | ScalarValue::Int32(Some(_))
            | ScalarValue::Int64(Some(_))
            | ScalarValue::UInt8(Some(_))
            | ScalarValue::UInt16(Some(_))
            | ScalarValue::UInt32(Some(_))
            | ScalarValue::UInt64(Some(_))
            | ScalarValue::Float32(Some(_))
            | ScalarValue::Float64(Some(_))
            | ScalarValue::Utf8(Some(_))
            | ScalarValue::LargeUtf8(Some(_))
            | ScalarValue::Utf8View(Some(_))
            | ScalarValue::Boolean(Some(_))
    )
}

/// Render a scalar equality literal as a query-parameter value, for the common
/// pushable types. `None` for a null or a type we won't put on a URL.
fn scalar_to_param(v: &ScalarValue) -> Option<String> {
    match v {
        ScalarValue::Int8(Some(x)) => Some(x.to_string()),
        ScalarValue::Int16(Some(x)) => Some(x.to_string()),
        ScalarValue::Int32(Some(x)) => Some(x.to_string()),
        ScalarValue::Int64(Some(x)) => Some(x.to_string()),
        ScalarValue::UInt8(Some(x)) => Some(x.to_string()),
        ScalarValue::UInt16(Some(x)) => Some(x.to_string()),
        ScalarValue::UInt32(Some(x)) => Some(x.to_string()),
        ScalarValue::UInt64(Some(x)) => Some(x.to_string()),
        ScalarValue::Float32(Some(x)) => Some(x.to_string()),
        ScalarValue::Float64(Some(x)) => Some(x.to_string()),
        ScalarValue::Utf8(Some(s))
        | ScalarValue::LargeUtf8(Some(s))
        | ScalarValue::Utf8View(Some(s)) => Some(s.clone()),
        ScalarValue::Boolean(Some(b)) => Some(b.to_string()),
        _ => None,
    }
}

#[async_trait]
impl TableProvider for RestTableProvider {
    fn schema(&self) -> SchemaRef {
        self.schema.clone()
    }

    fn table_type(&self) -> TableType {
        TableType::Base
    }

    /// A declared-pushable equality filter (`col = literal`) is reported
    /// `Inexact`: it is pushed to the API as a query parameter *and* still
    /// re-checked locally by DataFusion, so the result is correct even for an
    /// endpoint that treats the parameter as a hint. Everything else is
    /// `Unsupported` (applied locally, as before).
    fn supports_filters_pushdown(
        &self,
        filters: &[&Expr],
    ) -> DfResult<Vec<TableProviderFilterPushDown>> {
        Ok(filters
            .iter()
            .map(|f| {
                if self.is_pushable(f) {
                    TableProviderFilterPushDown::Inexact
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
        // Declared-pushable equality filters become query params on the request
        // URL; the rest DataFusion applies locally (see
        // `supports_filters_pushdown`).
        filters: &[Expr],
        limit: Option<usize>,
    ) -> DfResult<Arc<dyn ExecutionPlan>> {
        let projected_schema = match projection {
            Some(p) => Arc::new(self.schema.project(p)?),
            None => self.schema.clone(),
        };
        let next_path = match &self.pagination {
            RestPagination::None => None,
            RestPagination::NextLink { next_path } => Some(next_path.clone()),
        };
        let url = self.url_with_pushdown(&self.url, filters)?;
        Ok(Arc::new(RestScanExec::new(
            self.http.clone(),
            url,
            self.records_path.clone(),
            self.auth.clone(),
            self.schema.clone(),
            projection.cloned(),
            limit,
            next_path,
            self.oauth.clone(),
            projected_schema,
        )))
    }
}

/// Safety cap on pages followed, so a source that always returns a next-link
/// can't loop forever. Salesforce pages hold 2000 rows, so this bounds a single
/// scan at ~20M rows before the cap trips (a WARN is logged).
const MAX_PAGES: usize = 10_000;

/// A single-partition scan that GETs the endpoint (following pagination links
/// when configured), decodes the JSON rows into Arrow, then applies projection
/// + limit locally.
pub(crate) struct RestScanExec {
    http: Client,
    url: String,
    records_path: String,
    auth: RestAuth,
    /// Full declared schema — rows are decoded against this.
    decode_schema: SchemaRef,
    /// Column indices to keep, or `None` for all.
    projection: Option<Vec<usize>>,
    /// Row cap, applied across pages.
    limit: Option<usize>,
    /// Dot-path to a next-page URL in each response, or `None` for a single
    /// request.
    next_path: Option<String>,
    /// When set, each request authenticates with a live OAuth 2.0 bearer from
    /// this cache instead of the static `auth`.
    oauth: Option<Arc<OAuth2TokenCache>>,
    /// Output schema (equals `decode_schema` when there is no projection).
    projected_schema: SchemaRef,
    properties: Arc<PlanProperties>,
}

// Hand-written so the request URL is redacted — a pushed equality literal in
// its query string could be a credential, and a derived `Debug` would render
// it in plan/debug logging (hard rule 12). `auth` uses its own redacting
// `Debug`.
impl fmt::Debug for RestScanExec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RestScanExec")
            .field("url", &redacted_url(&self.url))
            .field("records_path", &self.records_path)
            .field("auth", &self.auth)
            .field("projection", &self.projection)
            .field("limit", &self.limit)
            .field("next_path", &self.next_path)
            .finish_non_exhaustive()
    }
}

impl RestScanExec {
    #[allow(clippy::too_many_arguments)]
    fn new(
        http: Client,
        url: String,
        records_path: String,
        auth: RestAuth,
        decode_schema: SchemaRef,
        projection: Option<Vec<usize>>,
        limit: Option<usize>,
        next_path: Option<String>,
        oauth: Option<Arc<OAuth2TokenCache>>,
        projected_schema: SchemaRef,
    ) -> Self {
        let properties = Arc::new(PlanProperties::new(
            EquivalenceProperties::new(projected_schema.clone()),
            Partitioning::UnknownPartitioning(1),
            EmissionType::Incremental,
            Boundedness::Bounded,
        ));
        Self {
            http,
            url,
            records_path,
            auth,
            decode_schema,
            projection,
            limit,
            next_path,
            oauth,
            projected_schema,
            properties,
        }
    }
}

/// Resolve a possibly-relative next-page URL against the current request URL.
fn join_url(base: &str, next: &str) -> DfResult<String> {
    let base = Url::parse(base).map_err(external)?;
    Ok(base.join(next).map_err(external)?.to_string())
}

/// The request URL with its query string (and any embedded user-info password)
/// redacted for plan display. Pushed equality literals are appended to the URL
/// as `?…`, and a filter value — or a `user:pass@host` password — can be a
/// credential, so neither may surface in an `EXPLAIN` / plan representation
/// (hard rule 12). The scheme/host/path are safe.
fn redacted_url(url: &str) -> String {
    if let Ok(mut parsed) = Url::parse(url) {
        // Some APIs carry an API key in the user-info username (e.g.
        // `https://API_KEY@host`), so redact it as well as the password.
        if !parsed.username().is_empty() {
            let _ = parsed.set_username("<redacted>");
        }
        if parsed.password().is_some() {
            let _ = parsed.set_password(Some("<redacted>"));
        }
        if parsed.query().is_some() {
            parsed.set_query(Some("<redacted>"));
        }
        return parsed.to_string();
    }
    // Not a parseable absolute URL — fall back to a lexical query strip.
    match url.split_once('?') {
        Some((base, _)) => format!("{base}?<redacted>"),
        None => url.to_string(),
    }
}

impl DisplayAs for RestScanExec {
    fn fmt_as(&self, _t: DisplayFormatType, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RestScanExec: url={}", redacted_url(&self.url))?;
        if !self.records_path.is_empty() {
            write!(f, " records_path={}", self.records_path)?;
        }
        if let Some(p) = &self.projection {
            write!(f, " projection={p:?}")?;
        }
        if let Some(n) = self.limit {
            write!(f, " limit={n}")?;
        }
        if let Some(np) = &self.next_path {
            write!(f, " paginate_next={np}")?;
        }
        Ok(())
    }
}

impl ExecutionPlan for RestScanExec {
    fn name(&self) -> &'static str {
        "RestScanExec"
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
        let start_url = self.url.clone();
        let records_path = self.records_path.clone();
        let auth = self.auth.clone();
        let oauth = self.oauth.clone();
        let decode_schema = self.decode_schema.clone();
        let projection = self.projection.clone();
        let limit = self.limit;
        let next_path = self.next_path.clone();
        let output_schema = self.projected_schema.clone();

        let fetch = async move {
            let mut out: Vec<RecordBatch> = Vec::new();
            let mut total: usize = 0;
            let mut url = start_url;
            let mut pages = 0;
            loop {
                // OAuth 2.0 (Salesforce): a live, cached bearer overrides the
                // static `auth`. The cache refreshes before expiry, so this is
                // cheap on every page.
                let req = match &oauth {
                    Some(cache) => http
                        .get(&url)
                        .bearer_auth(cache.bearer().await.map_err(external)?),
                    None => auth.apply(http.get(&url)),
                };
                // Strip the URL from reqwest errors before propagating: a
                // pushed equality literal in the query string could be a
                // credential, and reqwest keeps the full URL in its error,
                // which would otherwise surface through the pgwire error path
                // (hard rule 12).
                let resp = req
                    .header("Accept", "application/json")
                    .send()
                    .await
                    .map_err(external_reqwest)?
                    .error_for_status()
                    .map_err(external_reqwest)?;
                let body = resp.text().await.map_err(external_reqwest)?;
                let (batch, next) =
                    decode_json_page(&body, &decode_schema, &records_path, next_path.as_deref())
                        .map_err(external)?;
                let batch = match &projection {
                    Some(p) => batch.project(p)?,
                    None => batch,
                };
                // Honor the limit across pages; stop early once it is satisfied.
                if let Some(lim) = limit {
                    let remaining = lim.saturating_sub(total);
                    if batch.num_rows() >= remaining {
                        out.push(batch.slice(0, remaining));
                        break;
                    }
                }
                total += batch.num_rows();
                out.push(batch);

                pages += 1;
                match next {
                    Some(n) if pages < MAX_PAGES => url = join_url(&url, &n)?,
                    Some(_) => {
                        tracing::warn!(
                            max_pages = MAX_PAGES,
                            "REST pagination hit the page cap; result truncated"
                        );
                        break;
                    }
                    None => break,
                }
            }
            Ok::<_, DataFusionError>(out)
        };

        let stream = futures::stream::once(fetch)
            .map(|res: DfResult<Vec<RecordBatch>>| match res {
                Ok(batches) => {
                    futures::stream::iter(batches.into_iter().map(Ok).collect::<Vec<_>>())
                }
                Err(e) => futures::stream::iter(vec![Err(e)]),
            })
            .flatten();
        Ok(Box::pin(RecordBatchStreamAdapter::new(
            output_schema,
            stream,
        )))
    }
}

/// Adapt any std error into a DataFusion external error.
fn external<E: std::error::Error + Send + Sync + 'static>(e: E) -> DataFusionError {
    DataFusionError::External(Box::new(e))
}

/// Like [`external`] but for a [`reqwest::Error`], first stripping the URL so a
/// pushed equality literal (possible credential) in the query string can't
/// escape through the error path (hard rule 12).
fn external_reqwest(e: reqwest::Error) -> DataFusionError {
    external(e.without_url())
}

/// A single-schema catalog exposing a [`RestConnector`]'s declared tables.
#[derive(Debug)]
struct RestCatalog {
    schema_name: String,
    schema: Arc<dyn DfSchemaProvider>,
}

impl DfCatalogProvider for RestCatalog {
    fn schema_names(&self) -> Vec<String> {
        vec![self.schema_name.clone()]
    }

    fn schema(&self, name: &str) -> Option<Arc<dyn DfSchemaProvider>> {
        (name == self.schema_name).then(|| Arc::clone(&self.schema))
    }
}

/// The schema that resolves declared table names to REST [`TableProvider`]s.
#[derive(Debug)]
struct RestSchema {
    connector: Arc<RestConnector>,
}

#[async_trait]
impl DfSchemaProvider for RestSchema {
    fn table_names(&self) -> Vec<String> {
        self.connector.table_names()
    }

    fn table_exist(&self, name: &str) -> bool {
        self.connector.table_names().iter().any(|t| t == name)
    }

    async fn table(&self, name: &str) -> DfResult<Option<Arc<dyn TableProvider>>> {
        Ok(self.connector.table_provider(name))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_never_leaks_secrets() {
        for auth in [
            RestAuth::Basic {
                user: "svc".into(),
                password: "hunter2".into(),
            },
            RestAuth::Bearer {
                token: "sf-session-tok".into(),
            },
            RestAuth::Header {
                name: "x-api-key".into(),
                value: "ak_live_secret".into(),
            },
        ] {
            let printed = format!("{auth:?}");
            assert!(!printed.contains("hunter2"), "leaked password: {printed}");
            assert!(
                !printed.contains("sf-session-tok"),
                "leaked token: {printed}"
            );
            assert!(
                !printed.contains("ak_live_secret"),
                "leaked api key: {printed}"
            );
        }
        // A RestSourceConfig's derived Debug inherits the redaction.
        let cfg = RestSourceConfig {
            url: "https://api.example.com/records".into(),
            records_path: "records".into(),
            auth: RestAuth::Bearer {
                token: "sf-session-tok".into(),
            },
            pagination: RestPagination::None,
            pushdown: vec![],
        };
        let printed = format!("{cfg:?}");
        assert!(printed.contains("api.example.com"));
        assert!(
            !printed.contains("sf-session-tok"),
            "config leaked token: {printed}"
        );
    }

    #[tokio::test]
    async fn scans_rows_projects_and_limits_via_catalog() {
        use arrow::datatypes::{DataType, Field, Schema};
        use datafusion::prelude::SessionContext;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let body = r#"{"records":[
            {"id":1,"name":"a","active":true},
            {"id":2,"name":"b","active":false}
        ]}"#;
        Mock::given(method("GET"))
            .and(path("/things"))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .mount(&server)
            .await;

        let schema = Arc::new(Schema::new(vec![
            Field::new("id", DataType::Int64, true),
            Field::new("name", DataType::Utf8, true),
            Field::new("active", DataType::Boolean, true),
        ]));
        let table = RestTable {
            name: "things".to_string(),
            config: RestSourceConfig {
                url: format!("{}/things", server.uri()),
                records_path: "records".to_string(),
                auth: RestAuth::None,
                pagination: RestPagination::None,
                pushdown: vec![],
            },
            schema,
        };
        let connector =
            Arc::new(RestConnector::with_client("rest_demo", vec![table], Client::new()).unwrap());

        let ctx = SessionContext::new();
        ctx.register_catalog("rest_demo", connector.as_catalog_provider("public"));

        // Full scan — both rows, projected to two columns.
        let batches = ctx
            .sql("SELECT id, name FROM rest_demo.public.things ORDER BY id")
            .await
            .expect("plan")
            .collect()
            .await
            .expect("run");
        let rows: usize = batches.iter().map(RecordBatch::num_rows).sum();
        assert_eq!(rows, 2);
        assert_eq!(batches[0].num_columns(), 2);

        // Projection + limit flow through scan().
        let one = ctx
            .sql("SELECT name FROM rest_demo.public.things LIMIT 1")
            .await
            .expect("plan")
            .collect()
            .await
            .expect("run");
        let rows: usize = one.iter().map(RecordBatch::num_rows).sum();
        assert_eq!(rows, 1);

        // The mock actually received the GET.
        let reqs = server.received_requests().await.unwrap();
        assert!(reqs.iter().any(|r| r.url.path() == "/things"));
    }

    #[tokio::test]
    async fn follows_pagination_next_link() {
        use arrow::datatypes::{DataType, Field, Schema};
        use datafusion::prelude::SessionContext;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        // Page 1 carries a Salesforce-style `nextRecordsUrl` — a RELATIVE path
        // that must resolve against the request host. Page 2 has none (last page).
        let page1 = r#"{"records":[{"id":1},{"id":2}],"nextRecordsUrl":"/q2"}"#;
        let page2 = r#"{"records":[{"id":3}]}"#;
        Mock::given(method("GET"))
            .and(path("/q"))
            .respond_with(ResponseTemplate::new(200).set_body_string(page1))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/q2"))
            .respond_with(ResponseTemplate::new(200).set_body_string(page2))
            .mount(&server)
            .await;

        let schema = Arc::new(Schema::new(vec![Field::new("id", DataType::Int64, true)]));
        let table = RestTable {
            name: "acct".to_string(),
            config: RestSourceConfig {
                url: format!("{}/q", server.uri()),
                records_path: "records".to_string(),
                auth: RestAuth::None,
                pagination: RestPagination::NextLink {
                    next_path: "nextRecordsUrl".to_string(),
                },
                pushdown: vec![],
            },
            schema,
        };
        let connector =
            Arc::new(RestConnector::with_client("sf", vec![table], Client::new()).unwrap());
        let ctx = SessionContext::new();
        ctx.register_catalog("sf", connector.as_catalog_provider("public"));

        // All three rows arrive across the two pages (ORDER BY forces a full scan).
        let all = ctx
            .sql("SELECT id FROM sf.public.acct ORDER BY id")
            .await
            .expect("plan")
            .collect()
            .await
            .expect("run");
        let rows: usize = all.iter().map(RecordBatch::num_rows).sum();
        assert_eq!(rows, 3);

        // Both pages were actually fetched.
        let reqs = server.received_requests().await.unwrap();
        assert!(reqs.iter().any(|r| r.url.path() == "/q"));
        assert!(reqs.iter().any(|r| r.url.path() == "/q2"));
    }

    #[tokio::test]
    async fn oauth2_fetches_token_then_queries_with_bearer() {
        use arrow::datatypes::{DataType, Field, Schema};
        use datafusion::prelude::SessionContext;
        use wiremock::matchers::{header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        use crate::rest::{OAuth2Config, OAuth2TokenCache};

        let server = MockServer::start().await;
        // Token endpoint (client-credentials grant).
        Mock::given(method("POST"))
            .and(path("/services/oauth2/token"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(r#"{"access_token":"tok-xyz","expires_in":3600}"#),
            )
            .mount(&server)
            .await;
        // Data endpoint responds ONLY when the acquired bearer is present — so a
        // successful query proves the token was fetched and applied.
        Mock::given(method("GET"))
            .and(path("/data"))
            .and(header("authorization", "Bearer tok-xyz"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string(r#"{"records":[{"id":1},{"id":2}]}"#),
            )
            .mount(&server)
            .await;

        let schema = Arc::new(Schema::new(vec![Field::new("id", DataType::Int64, true)]));
        let table = RestTable {
            name: "acct".to_string(),
            config: RestSourceConfig {
                url: format!("{}/data", server.uri()),
                records_path: "records".to_string(),
                auth: RestAuth::None, // overridden by OAuth2
                pagination: RestPagination::None,
                pushdown: vec![],
            },
            schema,
        };
        let cache = Arc::new(OAuth2TokenCache::new(
            Client::new(),
            OAuth2Config {
                token_url: format!("{}/services/oauth2/token", server.uri()),
                client_id: "cid".to_string(),
                client_secret: "csecret".to_string(),
                extra_params: vec![],
            },
        ));
        let connector = Arc::new(
            RestConnector::with_client("sf", vec![table], Client::new())
                .unwrap()
                .with_oauth2(cache),
        );

        let ctx = SessionContext::new();
        ctx.register_catalog("sf", connector.as_catalog_provider("public"));
        let batches = ctx
            .sql("SELECT id FROM sf.public.acct")
            .await
            .expect("plan")
            .collect()
            .await
            .expect("run");
        let rows: usize = batches.iter().map(RecordBatch::num_rows).sum();
        assert_eq!(rows, 2, "query succeeds only if the bearer was applied");

        let reqs = server.received_requests().await.unwrap();
        assert_eq!(
            reqs.iter()
                .filter(|r| r.url.path() == "/services/oauth2/token")
                .count(),
            1,
            "token fetched once and cached"
        );
    }

    #[test]
    fn builds_http2_prior_knowledge_client() {
        // The tuned client (incl. HTTP/2 prior knowledge) builds cleanly.
        assert!(build_client(&RestClientOptions::default()).is_ok());
        assert!(build_client(&RestClientOptions {
            http2_prior_knowledge: true,
        })
        .is_ok());
    }

    #[tokio::test]
    async fn pushes_equality_filter_as_query_param() {
        use arrow::datatypes::{DataType, Field, Schema};
        use datafusion::prelude::SessionContext;
        use wiremock::matchers::{method, path, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        // The endpoint responds ONLY when `?time=15000` is present, so a
        // successful query proves the `WHERE time = 15000` predicate was pushed
        // to the API as a query parameter.
        Mock::given(method("GET"))
            .and(path("/sleep"))
            .and(query_param("time", "15000"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string(r#"{"records":[{"time":15000}]}"#),
            )
            .mount(&server)
            .await;

        let schema = Arc::new(Schema::new(vec![Field::new("time", DataType::Int64, true)]));
        let table = RestTable {
            name: "sleep".to_string(),
            config: RestSourceConfig {
                url: format!("{}/sleep", server.uri()),
                records_path: "records".to_string(),
                auth: RestAuth::None,
                pagination: RestPagination::None,
                pushdown: vec![RestPushdownParam {
                    column: "time".to_string(),
                    param: "time".to_string(),
                }],
            },
            schema,
        };
        let connector =
            Arc::new(RestConnector::with_client("api", vec![table], Client::new()).unwrap());
        let ctx = SessionContext::new();
        ctx.register_catalog("api", connector.as_catalog_provider("public"));

        let batches = ctx
            .sql("SELECT time FROM api.public.sleep WHERE time = 15000")
            .await
            .expect("plan")
            .collect()
            .await
            .expect("run");
        let rows: usize = batches.iter().map(RecordBatch::num_rows).sum();
        assert_eq!(rows, 1, "query succeeds only if ?time=15000 was pushed");

        // The GET actually carried the pushed parameter.
        let reqs = server.received_requests().await.unwrap();
        assert!(reqs
            .iter()
            .any(|r| r.url.path() == "/sleep" && r.url.query() == Some("time=15000")));
    }

    #[tokio::test]
    async fn non_declared_column_is_not_pushed() {
        use arrow::datatypes::{DataType, Field, Schema};
        use datafusion::prelude::SessionContext;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        // No query_param matcher: the request must arrive WITHOUT a pushed
        // param because `other` is not in the table's pushdown map — the filter
        // is applied locally instead.
        Mock::given(method("GET"))
            .and(path("/sleep"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(r#"{"records":[{"time":1,"other":7},{"time":2,"other":9}]}"#),
            )
            .mount(&server)
            .await;

        let schema = Arc::new(Schema::new(vec![
            Field::new("time", DataType::Int64, true),
            Field::new("other", DataType::Int64, true),
        ]));
        let table = RestTable {
            name: "sleep".to_string(),
            config: RestSourceConfig {
                url: format!("{}/sleep", server.uri()),
                records_path: "records".to_string(),
                auth: RestAuth::None,
                pagination: RestPagination::None,
                pushdown: vec![RestPushdownParam {
                    column: "time".to_string(),
                    param: "time".to_string(),
                }],
            },
            schema,
        };
        let connector =
            Arc::new(RestConnector::with_client("api", vec![table], Client::new()).unwrap());
        let ctx = SessionContext::new();
        ctx.register_catalog("api", connector.as_catalog_provider("public"));

        // `other = 9` is not pushable → applied locally; exactly one row matches.
        let batches = ctx
            .sql("SELECT time FROM api.public.sleep WHERE other = 9")
            .await
            .expect("plan")
            .collect()
            .await
            .expect("run");
        let rows: usize = batches.iter().map(RecordBatch::num_rows).sum();
        assert_eq!(rows, 1, "local filter keeps only the matching row");

        let reqs = server.received_requests().await.unwrap();
        assert!(
            reqs.iter()
                .any(|r| r.url.path() == "/sleep" && r.url.query().is_none()),
            "no query parameter should be pushed for an undeclared column"
        );
    }

    #[test]
    fn plan_display_redacts_pushed_literals() {
        // A pushed equality literal can be a credential — it must never surface
        // in a plan representation (rule 12).
        assert_eq!(
            redacted_url("http://api.example.com/sleep"),
            "http://api.example.com/sleep"
        );
        let r = redacted_url("http://api.example.com/sleep?token=s3cr3t&time=5");
        assert!(r.starts_with("http://api.example.com/sleep?"), "{r}");
        assert!(!r.contains("s3cr3t"), "leaked literal: {r}");
        assert!(!r.contains("time=5"), "leaked literal: {r}");
        // A `user:pass@host` password is redacted too.
        let r = redacted_url("https://svc:hunter2@api.example.com/x?q=1");
        assert!(!r.contains("hunter2"), "leaked url password: {r}");
        assert!(!r.contains("q=1"), "leaked literal: {r}");
        // A username-form credential (`https://API_KEY@host`) is redacted.
        let r = redacted_url("https://ak_live_secret@api.example.com/x");
        assert!(!r.contains("ak_live_secret"), "leaked url username: {r}");
    }

    #[test]
    fn new_with_options_rejects_invalid_url() {
        let schema = Arc::new(arrow::datatypes::Schema::new(vec![
            arrow::datatypes::Field::new("id", arrow::datatypes::DataType::Int64, true),
        ]));
        let table = RestTable {
            name: "t".to_string(),
            config: RestSourceConfig {
                url: "not a url".to_string(),
                records_path: String::new(),
                auth: RestAuth::None,
                pagination: RestPagination::None,
                pushdown: vec![],
            },
            schema,
        };
        let err =
            RestConnector::new_with_options("bad", vec![table], &RestClientOptions::default())
                .expect_err("invalid URL rejected at init");
        assert!(format!("{err}").contains('t'));
    }

    #[test]
    fn new_with_options_rejects_duplicate_pushdown_param() {
        let schema = Arc::new(arrow::datatypes::Schema::new(vec![
            arrow::datatypes::Field::new("a", arrow::datatypes::DataType::Int64, true),
            arrow::datatypes::Field::new("b", arrow::datatypes::DataType::Int64, true),
        ]));
        let table = RestTable {
            name: "t".to_string(),
            config: RestSourceConfig {
                url: "http://x/y".to_string(),
                records_path: String::new(),
                auth: RestAuth::None,
                pagination: RestPagination::None,
                pushdown: vec![
                    RestPushdownParam {
                        column: "a".to_string(),
                        param: "q".to_string(),
                    },
                    RestPushdownParam {
                        column: "b".to_string(),
                        param: "q".to_string(),
                    },
                ],
            },
            schema,
        };
        let err =
            RestConnector::new_with_options("dup", vec![table], &RestClientOptions::default())
                .expect_err("duplicate pushdown param rejected");
        assert!(err.to_string().contains("parameter 'q'"), "{err}");
    }

    #[test]
    fn with_client_rejects_pushdown_on_unknown_column() {
        // Validation runs in the shared with_client sink, so even the
        // inject-a-client path rejects a pushdown on a column not in the schema.
        let schema = Arc::new(arrow::datatypes::Schema::new(vec![
            arrow::datatypes::Field::new("time", arrow::datatypes::DataType::Int64, true),
        ]));
        let table = RestTable {
            name: "t".to_string(),
            config: RestSourceConfig {
                url: "http://x/y".to_string(),
                records_path: String::new(),
                auth: RestAuth::None,
                pagination: RestPagination::None,
                pushdown: vec![RestPushdownParam {
                    column: "nope".to_string(),
                    param: "nope".to_string(),
                }],
            },
            schema,
        };
        let err = RestConnector::with_client("t", vec![table], Client::new())
            .expect_err("unknown pushdown column rejected");
        assert!(err.to_string().contains("unknown column 'nope'"), "{err}");
    }

    #[test]
    fn with_client_rejects_column_mapped_twice() {
        // The same column mapped to two params: `param_for` would silently use
        // only the first, so reject it (dead config).
        let schema = Arc::new(arrow::datatypes::Schema::new(vec![
            arrow::datatypes::Field::new("time", arrow::datatypes::DataType::Int64, true),
        ]));
        let table = RestTable {
            name: "t".to_string(),
            config: RestSourceConfig {
                url: "http://x/y".to_string(),
                records_path: String::new(),
                auth: RestAuth::None,
                pagination: RestPagination::None,
                pushdown: vec![
                    RestPushdownParam {
                        column: "time".to_string(),
                        param: "t1".to_string(),
                    },
                    RestPushdownParam {
                        column: "time".to_string(),
                        param: "t2".to_string(),
                    },
                ],
            },
            schema,
        };
        let err = RestConnector::with_client("t", vec![table], Client::new())
            .expect_err("duplicate column rejected");
        assert!(
            err.to_string().contains("column 'time' more than once"),
            "{err}"
        );
    }

    #[test]
    fn pushdown_replaces_configured_query_param() {
        use datafusion::prelude::{col, lit};
        let provider = RestTableProvider {
            http: Client::new(),
            url: "http://x/y?time=1&keep=z".to_string(),
            records_path: String::new(),
            auth: RestAuth::None,
            pagination: RestPagination::None,
            pushdown: vec![RestPushdownParam {
                column: "time".to_string(),
                param: "time".to_string(),
            }],
            oauth: None,
            schema: Arc::new(arrow::datatypes::Schema::new(vec![
                arrow::datatypes::Field::new("time", arrow::datatypes::DataType::Int64, true),
            ])),
        };
        let filter = col("time").eq(lit(15_000_i64));
        let out = provider
            .url_with_pushdown("http://x/y?time=1&keep=z", std::slice::from_ref(&filter))
            .expect("url");
        // The SQL predicate replaces the configured `time=1` (no duplicate key),
        // and the unrelated `keep=z` is preserved.
        assert_eq!(out.matches("time=").count(), 1, "{out}");
        assert!(out.contains("time=15000"), "{out}");
        assert!(out.contains("keep=z"), "{out}");
    }
}

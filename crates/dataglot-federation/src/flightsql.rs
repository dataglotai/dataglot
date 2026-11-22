//! Arrow Flight SQL **ingress** connector — federate any engine that speaks
//! Flight SQL (, spec: the phase-4 `arrow-flight-sql-ingress` plan).
//!
//! The mirror of `dataglot-server`'s `flight_sql` egress listener: that one
//! *serves* Flight SQL, this one *consumes* it. One connector covers Dremio,
//! `InfluxDB` 3, Ballista, ROAPI, `GizmoSQL` / `sqlflite`, Sail — and another
//! Dataglot instance, which is how a central governed node federates to
//! regional ones with policy enforced at both ends. Any other Flight SQL
//! server works too, provided its SQL matches one of the dialects below.
//!
//! It is also the transport the driver-host sidecar will speak: most ADBC
//! vendor drivers are Go shared libraries, two Go runtimes in one process is
//! undefined behaviour, so heavyweight drivers belong in their own process
//! behind Flight SQL (the shape ClickHouse arrived at with its ODBC/JDBC
//! bridges).
//!
//! # Contract
//!
//! - **`dialect` is mandatory.** Flight SQL fixes the wire protocol, not the
//!   SQL dialect — the *serving engine* decides that. A Dataglot peer and
//!   `InfluxDB` 3 want [`FlightSqlDialect::DataFusion`]; `GizmoSQL` over `DuckDB`
//!   wants `duckdb`. Like the ADBC connector, the whitelist is exactly the
//!   dialects DataFusion's unparser ships, with no alias mapping: generating
//!   *almost* right SQL is worse than refusing.
//! - **Reads only.** No `DoPut`, no transactions, no prepared statements: the
//!   federation planner hands us one finished SQL string per scan.
//! - **Endpoint locations are not followed by default.** `GetFlightInfo` may
//!   name *other hosts*; following one sends our credentials wherever the
//!   remote points. Tickets with no location (the common case) and locations
//!   equal to the configured endpoint always work; anything else needs
//!   `follow_endpoint_locations`.
//! - **Credentials never appear in logs, errors, `Debug`, or plans**
//!   (hard rule 12). The password/token is read from the environment at
//!   connect time into a redacting wrapper, and errors leaving this module
//!   are scrubbed of it.
//!
//! # Threading
//!
//! There is no connection pool and no reset SQL. [`Channel`] is cheap to
//! clone and multiplexes concurrent RPCs over HTTP/2, so each operation
//! clones the prepared client and runs independently — unlike `adbc.rs`,
//! whose `ManagedConnection` is not concurrency-safe and therefore needs a
//! pool. Every RPC carries its own headers, so no session state can leak
//! between queries or tenants.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use arrow::array::{Array, ArrayRef, RecordBatch, StringArray};
use arrow::datatypes::SchemaRef;
use arrow_flight::error::FlightError;
use arrow_flight::sql::client::FlightSqlServiceClient;
use arrow_flight::sql::CommandGetTables;
use arrow_flight::FlightEndpoint;
use async_trait::async_trait;
use base64::Engine as _;
use datafusion::catalog::{
    CatalogProvider as DfCatalogProvider, SchemaProvider as DfSchemaProvider,
};
use datafusion::common::TableReference;
use datafusion::datasource::TableProvider;
use datafusion::error::{DataFusionError, Result as DfResult};
use datafusion::execution::SendableRecordBatchStream;
use datafusion::physical_plan::stream::RecordBatchStreamAdapter;
use datafusion::physical_plan::PhysicalExpr;
use datafusion::sql::unparser::dialect::{
    BigQueryDialect, DefaultDialect, Dialect, DuckDBDialect, MySqlDialect, PostgreSqlDialect,
    SqliteDialect,
};
use datafusion_federation::sql::{
    AstAnalyzer, LogicalOptimizer, RemoteTableRef, SQLExecutor, SQLFederationProvider,
    SQLTableSource,
};
use datafusion_federation::FederatedTableProviderAdaptor;
use dataglot_core::{DataglotError, Result as DataglotResult};
use futures::stream::{self, BoxStream, StreamExt, TryStreamExt};
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint};
use tracing::{debug, warn};

// ---------------------------------------------------------------------------
// Dialect
// ---------------------------------------------------------------------------

/// The SQL dialect the *serving engine* behind a Flight SQL endpoint speaks.
///
/// Flight SQL standardises the transport, not the SQL, so this cannot be
/// inferred from the protocol and has no safe default — it is mandatory
/// configuration. The whitelist is exactly the unparser dialects DataFusion
/// ships: an unlisted engine is not usable through this connector, and the
/// contained fix is landing its dialect upstream in DataFusion rather than
/// aliasing it to a near-miss here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlightSqlDialect {
    /// `datafusion` → [`DefaultDialect`]. The right choice for every
    /// `DataFusion`-backed server: another Dataglot instance, `InfluxDB` 3,
    /// Sail, Ballista, ROAPI.
    DataFusion,
    /// `postgresql` → [`PostgreSqlDialect`].
    PostgreSql,
    /// `mysql` → [`MySqlDialect`].
    MySql,
    /// `sqlite` → [`SqliteDialect`]. `GizmoSQL` / `sqlflite` over `SQLite`.
    Sqlite,
    /// `duckdb` → [`DuckDBDialect`]. `GizmoSQL` / `sqlflite` over `DuckDB`.
    DuckDb,
    /// `bigquery` → [`BigQueryDialect`].
    BigQuery,
}

/// The user-facing dialect names, for error messages.
const SUPPORTED_DIALECTS: &str = "datafusion | postgresql | mysql | sqlite | duckdb | bigquery";

impl FlightSqlDialect {
    /// The canonical config string for this dialect.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DataFusion => "datafusion",
            Self::PostgreSql => "postgresql",
            Self::MySql => "mysql",
            Self::Sqlite => "sqlite",
            Self::DuckDb => "duckdb",
            Self::BigQuery => "bigquery",
        }
    }

    /// The DataFusion unparser dialect that turns federated plans back into
    /// SQL the remote can execute.
    #[must_use]
    pub fn unparser_dialect(self) -> Arc<dyn Dialect> {
        match self {
            Self::DataFusion => Arc::new(DefaultDialect {}),
            Self::PostgreSql => Arc::new(PostgreSqlDialect {}),
            Self::MySql => Arc::new(MySqlDialect {}),
            Self::Sqlite => Arc::new(SqliteDialect {}),
            Self::DuckDb => Arc::new(DuckDBDialect::new()),
            Self::BigQuery => Arc::new(BigQueryDialect {}),
        }
    }

    /// Can this dialect address a table by `catalog.schema.table`?
    ///
    /// `DataFusion` (catalogs), `DuckDB` (attached databases) and
    /// `BigQuery` (`project.dataset.table`) can. `PostgreSQL` cannot query
    /// across databases, and `MySQL` and `SQLite` have a two-level namespace
    /// at most — so a catalog is not something a reference can carry there,
    /// and emitting one produces SQL the server rejects.
    #[must_use]
    pub fn supports_catalog_qualification(self) -> bool {
        match self {
            Self::DataFusion | Self::DuckDb | Self::BigQuery => true,
            Self::PostgreSql | Self::MySql | Self::Sqlite => false,
        }
    }

    /// Quote one identifier the way this dialect expects, for the
    /// hand-built metadata probes (everything on the query path is spelled
    /// by the unparser itself).
    fn quote(self, ident: &str) -> String {
        match self.unparser_dialect().identifier_quote_style(ident) {
            // Doubling the quote char is the escape in every dialect here.
            Some(q) => format!("{q}{}{q}", ident.replace(q, &format!("{q}{q}"))),
            None => ident.to_string(),
        }
    }
}

impl fmt::Display for FlightSqlDialect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for FlightSqlDialect {
    type Err = DataglotError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "datafusion" => Ok(Self::DataFusion),
            "postgresql" => Ok(Self::PostgreSql),
            "mysql" => Ok(Self::MySql),
            "sqlite" => Ok(Self::Sqlite),
            "duckdb" => Ok(Self::DuckDb),
            "bigquery" => Ok(Self::BigQuery),
            // Named engines DataFusion ships no dialect for. Point at the
            // closest supported spelling rather than aliasing silently.
            "dremio" => Err(DataglotError::configuration(format!(
                "flightsql dialect 'dremio' is not supported: DataFusion ships no Dremio \
                 unparser dialect. Dremio's SQL is closest to 'postgresql' — set that \
                 explicitly if your queries unparse correctly. Supported: {SUPPORTED_DIALECTS}"
            ))),
            "influxdb" | "influxdb3" | "sail" | "ballista" | "roapi" | "dataglot" => {
                Err(DataglotError::configuration(format!(
                    "flightsql dialect '{s}' names a server, not a dialect: that server is \
                     DataFusion-backed, so use 'datafusion'. Supported: {SUPPORTED_DIALECTS}"
                )))
            }
            "mssql" => Err(DataglotError::configuration(format!(
                "flightsql dialect 'mssql' is not supported yet: DataFusion ships no MS SQL \
                 unparser dialect. Supported: {SUPPORTED_DIALECTS}"
            ))),
            other => Err(DataglotError::configuration(format!(
                "unknown flightsql dialect '{other}'; supported dialects: {SUPPORTED_DIALECTS}"
            ))),
        }
    }
}

// ---------------------------------------------------------------------------
// Credentials
// ---------------------------------------------------------------------------

/// A resolved credential. Exists so a stray `{:?}` on a config or connector
/// can never print one (hard rule 12).
#[derive(Clone)]
struct Secret(String);

impl Secret {
    fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[redacted]")
    }
}

/// How to authenticate to the Flight SQL endpoint.
///
/// The secret itself is never part of the config — only the *name* of the
/// environment variable holding it, which is configuration, not a secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlightSqlAuth {
    /// No credentials. The default; correct for a sidecar on loopback.
    None,
    /// `authorization: Basic base64(username:password)` on every RPC — the
    /// shape Dataglot's own Flight SQL listener parses.
    Basic {
        /// Username sent in the Basic credential.
        username: String,
        /// Environment variable holding the password.
        password_env: String,
    },
    /// `authorization: Bearer <token>` on every RPC.
    Bearer {
        /// Environment variable holding the bearer token.
        token_env: String,
    },
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/// Configuration for one `kind = "flightsql"` catalog entry.
///
/// `Debug` is safe to log: it carries env-var *names*, never their values.
#[derive(Clone)]
pub struct FlightSqlConfig {
    /// Catalog name — the unique `SQLExecutor::name` / federation
    /// compute-context key.
    pub name: String,
    /// Endpoint URI. `grpc://`, `grpc+tcp://` and `http://` are plaintext;
    /// `grpc+tls://` and `https://` enable TLS. Example:
    /// `grpc://dremio.internal:32010`.
    pub endpoint: String,
    /// Mandatory SQL dialect of the serving engine.
    pub dialect: FlightSqlDialect,
    /// How to authenticate.
    pub auth: FlightSqlAuth,
    /// Exchange the Basic credential for a bearer token once at connect
    /// (`FlightSqlServiceClient::handshake`) instead of sending Basic on
    /// every RPC. Only meaningful with [`FlightSqlAuth::Basic`].
    pub handshake: bool,
    /// PEM file with a custom CA to trust. TLS endpoints only.
    pub tls_ca_file: Option<PathBuf>,
    /// Override the SNI / certificate domain name. TLS endpoints only.
    pub tls_domain: Option<String>,
    /// Source-side catalog to scope discovery to. `None` means "server
    /// default".
    pub catalog: Option<String>,
    /// Source-side schema to scope discovery to. `None` lists every schema
    /// the server reports.
    pub schema: Option<String>,
    /// TCP + TLS handshake budget for the initial connect. Default 10s.
    pub connect_timeout_secs: u64,
    /// Per-RPC budget, **and** the inactivity deadline while a result
    /// stream is being consumed — a server that answers and then stalls
    /// mid-stream is caught by the same number. `None` means no
    /// client-side deadline (the server's own limits apply).
    pub request_timeout_secs: Option<u64>,
    /// Follow `GetFlightInfo` endpoint locations that point at a host other
    /// than the configured endpoint. Off by default: following one sends
    /// this catalog's credentials wherever the remote nominates.
    pub follow_endpoint_locations: bool,
}

impl FlightSqlConfig {
    /// A config with the required fields set and defaults for the rest
    /// (no auth, no TLS trust override, 10s connect timeout, locations not
    /// followed).
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        endpoint: impl Into<String>,
        dialect: FlightSqlDialect,
    ) -> Self {
        Self {
            name: name.into(),
            endpoint: endpoint.into(),
            dialect,
            auth: FlightSqlAuth::None,
            handshake: false,
            tls_ca_file: None,
            tls_domain: None,
            catalog: None,
            schema: None,
            connect_timeout_secs: 10,
            request_timeout_secs: None,
            follow_endpoint_locations: false,
        }
    }

    /// Validate the config shape before any network interaction.
    ///
    /// # Errors
    /// [`DataglotError::Configuration`] when the endpoint is empty or carries
    /// an unknown scheme, when TLS-only options are set on a plaintext
    /// endpoint, when `handshake` is set without Basic credentials, or when
    /// the connect timeout is zero.
    pub fn validate(&self) -> DataglotResult<()> {
        let cfg_err = |msg: String| {
            DataglotError::configuration(format!("flightsql catalog '{}': {msg}", self.name))
        };
        if self.endpoint.trim().is_empty() {
            return Err(cfg_err("`endpoint` is required".to_string()));
        }
        // URI userinfo (`grpc+tls://svc:secret@host:443`) would put a
        // credential somewhere this struct promises is safe to log, and
        // somewhere connection errors interpolate. Credentials belong in
        // `auth`, resolved from the environment (rule 12), so refuse the
        // shape outright rather than trying to redact it everywhere.
        // One gate for every dialable URI — the configured endpoint here,
        // and any location a server advertises, in `Transport::parse`.
        self.transport()?;
        let tls = self.uses_tls()?;
        if !tls {
            // `tls_ca_file` still has a job on a plaintext coordinator *if*
            // TLS result locations may be followed — `build_channel` applies
            // it to the foreign transport, and rejecting it here would leave
            // a replica behind a private CA unverifiable.
            if self.tls_ca_file.is_some() && !self.follow_endpoint_locations {
                return Err(cfg_err(
                    "`tls_ca_file` is set but the endpoint is plaintext and \
                     `follow_endpoint_locations` is off, so no TLS connection can be made \
                     with it; use a `grpc+tls://` or `https://` endpoint, or enable \
                     following if the trust root is for an advertised TLS location"
                        .to_string(),
                ));
            }
            if self.tls_domain.is_some() {
                return Err(cfg_err(
                    "`tls_domain` is set but the endpoint is plaintext; use a \
                     `grpc+tls://` or `https://` endpoint"
                        .to_string(),
                ));
            }
        }
        if let FlightSqlAuth::Basic { username, .. } = &self.auth {
            // Basic credentials are `base64(user:password)`, so a colon in
            // the username is indistinguishable from the separator. Every
            // receiver splits on the FIRST colon — Dataglot's own Flight SQL
            // listener included — so such a username would silently
            // authenticate as a truncated identity with a mangled password.
            if username.contains(':') {
                return Err(cfg_err(
                    "`auth.username` contains ':', which HTTP Basic cannot represent: the \
                     credential is `base64(username:password)`, so the receiver would read \
                     a truncated username and the wrong password"
                        .to_string(),
                ));
            }
        }
        if self.catalog.is_some() && !self.dialect.supports_catalog_qualification() {
            return Err(cfg_err(format!(
                "`catalog` is set but the `{}` dialect has no three-part namespace, so a \
                 reference cannot carry one — the server would reject every query. Drop \
                 `catalog`, or use `schema` to scope instead",
                self.dialect
            )));
        }
        if self.handshake && !matches!(self.auth, FlightSqlAuth::Basic { .. }) {
            return Err(cfg_err(
                "`handshake` exchanges a Basic credential for a bearer token, so it \
                 requires `auth = \"basic\"` with a username and password_env"
                    .to_string(),
            ));
        }
        if self.connect_timeout_secs == 0 {
            return Err(cfg_err(
                "`connect_timeout_secs` must be at least 1".to_string(),
            ));
        }
        if self.request_timeout_secs == Some(0) {
            return Err(cfg_err(
                "`request_timeout_secs` must be at least 1 when set".to_string(),
            ));
        }
        Ok(())
    }

    /// Does the configured endpoint speak TLS?
    ///
    /// # Errors
    /// [`DataglotError::Configuration`] for an unknown or missing scheme.
    fn uses_tls(&self) -> DataglotResult<bool> {
        Ok(self.transport()?.tls)
    }

    /// The configured endpoint's [`Transport`].
    ///
    /// # Errors
    /// [`DataglotError::Configuration`] for an unknown or missing scheme.
    fn transport(&self) -> DataglotResult<Transport> {
        Transport::parse(&self.endpoint).map_err(|e| {
            DataglotError::configuration(format!("flightsql catalog '{}': {e}", self.name))
        })
    }
}

impl fmt::Debug for FlightSqlConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FlightSqlConfig")
            .field("name", &self.name)
            // `validate` refuses userinfo, but a struct built by hand never
            // saw it — so redact rather than trust (rule 12).
            .field("endpoint", &safe_endpoint_display(&self.endpoint))
            .field("dialect", &self.dialect)
            // `auth` carries env-var names and a username, never a secret.
            .field("auth", &self.auth)
            .field("handshake", &self.handshake)
            .field("tls_ca_file", &self.tls_ca_file)
            .field("tls_domain", &self.tls_domain)
            .field("catalog", &self.catalog)
            .field("schema", &self.schema)
            .field("connect_timeout_secs", &self.connect_timeout_secs)
            .field("request_timeout_secs", &self.request_timeout_secs)
            .field("follow_endpoint_locations", &self.follow_endpoint_locations)
            .finish()
    }
}

/// `schema → table names`, as discovery reports it.
type Listing = BTreeMap<String, BTreeSet<String>>;

/// `schema → the catalogs its rows came from`, where `None` is a row whose
/// catalog column was null. Tracked per schema so that catalogs seen only in
/// rows the configured scope later drops cannot make a listing look
/// ambiguous.
type Provenance = BTreeMap<String, BTreeSet<Option<String>>>;

/// What one pass over a metadata response accumulates.
#[derive(Default)]
struct ListingSink {
    /// `schema → tables`, the listing itself.
    listing: Listing,
    /// Which catalogs each schema's rows came from, for the ambiguity check.
    provenance: Provenance,
    /// A batch carried rows but no readable catalog column — the response is
    /// malformed, and judging catalogs on it would be guesswork.
    unreadable_catalog: bool,
    /// A batch carried rows but no readable schema or table column, so the
    /// whole batch was dropped. Same hazard: a silently partial catalog.
    /// Batch-level, so no scope can excuse it — nothing in such a batch can
    /// be placed at all.
    unreadable_listing: bool,
    /// The schemas of rows that named no table (`None` when the row named no
    /// schema either). Kept per schema rather than as a flag so the caller
    /// can apply the configured scope first: a malformed row in a schema
    /// this catalog does not expose is not this catalog's problem.
    malformed_rows: BTreeSet<Option<String>>,
    /// Rows that named a table but no schema, which this connector has
    /// nowhere to put.
    schemaless: usize,
}

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

/// How to reach one Flight endpoint: the URI in a scheme `tonic` understands,
/// its authority in canonical form, and whether it is TLS.
///
/// Every URI this connector dials is built here — the configured endpoint and
/// any location a server advertises — which makes this the one place that
/// decides what an endpoint may contain. Parsing is delegated to `url`
/// rather than hand-rolled: bracketed IPv6 hosts, implicit default ports and
/// userinfo detection are exactly the cases a string split keeps getting
/// wrong, and each near-miss here is a credential leak or a wrong-host
/// comparison.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Transport {
    /// `http://host:port` or `https://host:port` — what
    /// `tonic::transport::Endpoint` accepts, with the port always explicit.
    uri: String,
    /// `host:port`, lowercased, default port made explicit. Comparing these
    /// answers "is this the server we already hold a connection to".
    authority: String,
    tls: bool,
}

impl Transport {
    /// Parse a Flight endpoint URI.
    ///
    /// `grpc` / `grpc+tcp` / `http` are plaintext; `grpc+tls` / `https` are
    /// TLS. An endpoint is **a host and port and nothing else**: userinfo,
    /// a path, a query string and a fragment are all refused (a bare
    /// trailing `/` is tolerated, since that is what copy-paste produces).
    /// gRPC carries the method in the request, so none of them is meaningful
    /// here — and each is somewhere a credential can hide.
    ///
    /// # Errors
    /// A message naming the problem, for the caller to prefix with its
    /// catalog name. **No error echoes the input**, because the offending
    /// part may be the secret.
    fn parse(uri: &str) -> Result<Self, String> {
        let uri = uri.trim();
        let Some((scheme, rest)) = uri.split_once("://") else {
            return Err(
                "endpoint has no scheme; use grpc://host:port (plaintext) or \
                        grpc+tls://host:port (TLS)"
                    .to_string(),
            );
        };
        let (mapped, tls) = match scheme.to_ascii_lowercase().as_str() {
            "grpc" | "grpc+tcp" | "http" => ("http", false),
            "grpc+tls" | "https" => ("https", true),
            _ => {
                // The scheme is deliberately *not* echoed. On an advertised
                // location it is remote-supplied text that may be a
                // reflected credential, and the allowed list below is what
                // the operator actually needs.
                return Err(
                    "unsupported endpoint scheme; use grpc:// | grpc+tcp:// | http:// \
                     (plaintext) or grpc+tls:// | https:// (TLS)"
                        .to_string(),
                );
            }
        };
        // Mapping the scheme first is what lets `url` supply the default
        // port: it only knows 80/443 for the HTTP schemes.
        let parsed = url::Url::parse(&format!("{mapped}://{rest}"))
            .map_err(|e| format!("endpoint is not a valid URI: {e}"))?;

        if !parsed.username().is_empty() || parsed.password().is_some() {
            return Err(
                "endpoint carries credentials in the URI (user@host); put them in \
                        `auth` instead, so they are resolved from the environment and \
                        never logged"
                    .to_string(),
            );
        }
        for (component, present) in [
            ("a path", parsed.path() != "/" && !parsed.path().is_empty()),
            ("a query string", parsed.query().is_some()),
            ("a fragment", parsed.fragment().is_some()),
        ] {
            if present {
                return Err(format!(
                    "endpoint carries {component}; a Flight SQL endpoint is a host and port \
                     only (gRPC carries the method in the request), and anything else here \
                     cannot be honoured"
                ));
            }
        }

        let host = parsed
            .host_str()
            .filter(|h| !h.is_empty())
            .ok_or_else(|| "endpoint has no host".to_string())?;
        let port = parsed
            .port_or_known_default()
            .ok_or_else(|| "endpoint has no port and the scheme implies none".to_string())?;
        let authority = format!("{}:{port}", host.to_ascii_lowercase());
        Ok(Self {
            uri: format!("{mapped}://{authority}"),
            authority,
            tls,
        })
    }

    /// Is this the same server, reached the same way, as `other`?
    ///
    /// Transport security is part of the identity: a location advertised as
    /// `grpc+tls://host:443` is **not** satisfied by a plaintext channel to
    /// `host:443`, and redeeming its ticket there would silently downgrade
    /// the connection the server asked for.
    fn same_server(&self, other: &Self) -> bool {
        self.authority == other.authority && self.tls == other.tls
    }
}

/// An endpoint rendered for human eyes with nothing sensitive in it.
///
/// Only the parts [`Transport::parse`] accepts — scheme, host, port — can
/// appear. Anything it refuses might *be* the credential, so an unparsable
/// endpoint renders as a placeholder rather than a best-effort redaction:
/// the `Debug` impl promises safety, and this is the cheapest way to keep
/// that promise even for a config built by hand that never saw `validate`.
fn safe_endpoint_display(endpoint: &str) -> String {
    Transport::parse(endpoint)
        .map_or_else(|_| "[redacted: unparsable endpoint]".to_string(), |t| t.uri)
}

/// Split a rendered SQL reference on the dots **outside** quotes.
///
/// `datafusion-federation` hands `get_table_schema` the reference this
/// connector rendered, with each part quoted for the configured dialect. A
/// plain `splitn` would cut a dotted identifier in half: a schema named
/// `warehouse.prod` renders as `"warehouse.prod"."users"` and would
/// otherwise parse as schema `"warehouse` and table `prod"`.
fn split_quoted_reference(reference: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    let mut chars = reference.chars().peekable();
    while let Some(c) = chars.next() {
        match quote {
            // Inside quotes: a doubled quote char is a literal one.
            Some(q) if c == q => {
                if chars.peek() == Some(&q) {
                    current.push(q);
                    chars.next();
                } else {
                    quote = None;
                }
            }
            Some(_) => current.push(c),
            None => match c {
                '"' | '`' => quote = Some(c),
                '.' => parts.push(std::mem::take(&mut current)),
                _ => current.push(c),
            },
        }
    }
    parts.push(current);
    parts
}

/// The `DoGet` sentinel meaning "redeem this ticket on the connection you
/// already have" (Flight spec). It is not a dialable URI.
const REUSE_CONNECTION_SCHEME: &str = "arrow-flight-reuse-connection";

/// Where one endpoint's ticket should be fetched.
#[derive(Debug, PartialEq, Eq)]
enum TicketRoute {
    /// Redeem on the connection we already hold.
    SameChannel,
    /// Redeem on another server; carries its parsed transport.
    Foreign(Box<Transport>),
}

/// Decide where to redeem a ticket, given the endpoint's advertised
/// locations and the authority of the connection we already hold.
///
/// Order matters and is deliberate: **any** reusable location wins before a
/// foreign one is considered. An endpoint that lists our own server next to
/// a replica must not send this catalog's credentials to the replica, and
/// must not be refused when a perfectly good local route is on offer. Empty
/// location lists, empty URIs and the reuse-connection sentinel all mean
/// "same channel" per the Flight spec.
///
/// # Errors
/// A message when the only routes on offer are foreign *and* unparsable.
/// Does this statement's own result order matter — that is, does it carry a
/// top-level `ORDER BY`?
///
/// The statement is one this connector unparsed itself moments ago, so it
/// parses; anything that does not is treated as order-sensitive, because
/// guessing "no" on text we cannot read is the unsafe direction.
///
/// A subquery's `ORDER BY` does not count: it constrains that subquery, not
/// the rows handed back.
fn statement_orders_rows(sql: &str) -> bool {
    use datafusion::sql::sqlparser::ast::Statement;
    use datafusion::sql::sqlparser::dialect::GenericDialect;
    use datafusion::sql::sqlparser::parser::Parser;

    let Ok(statements) = Parser::parse_sql(&GenericDialect {}, sql) else {
        return true;
    };
    statements.iter().any(|statement| match statement {
        Statement::Query(query) => query.order_by.is_some(),
        _ => false,
    })
}

/// The value to send as `db_schema_filter_pattern`, or `None` to send none.
///
/// The field is a SQL *wildcard* pattern, so a scope like `tenant_1` or
/// `sales%` would also match `tenant-1` / `sales_eu` on a conforming server —
/// a silent widening. A backslash is worse: servers that treat it as the
/// pattern escape read `tenant\east` as `tenanteast`, so the configured
/// schema is never returned at all and the exact retain cannot recover rows
/// that never arrived.
///
/// Withholding the hint only costs a wider listing, because the scope is
/// enforced exactly on the rows that come back. Escaping is not an option:
/// the escape character is server-defined and not portable.
fn schema_filter_hint(schema: Option<&str>) -> Option<String> {
    schema
        .filter(|s| !s.contains(['%', '_', '\\']))
        .map(ToString::to_string)
}

/// Is this the "reuse the connection you already have" sentinel?
///
/// Matched as a *scheme*, not a prefix: URI schemes are case-insensitive, so
/// `Arrow-Flight-Reuse-Connection://?` is the same sentinel and a
/// prefix check both misses it and would accept an unrelated scheme that
/// merely starts with the same letters.
fn is_reuse_sentinel(uri: &str) -> bool {
    uri.split_once("://")
        .is_some_and(|(scheme, _)| scheme.eq_ignore_ascii_case(REUSE_CONNECTION_SCHEME))
}

fn route_for(locations: &[String], ours: Option<&Transport>) -> Result<TicketRoute, String> {
    if locations.is_empty() {
        return Ok(TicketRoute::SameChannel);
    }
    let mut foreign: Option<Transport> = None;
    let mut first_error: Option<String> = None;
    for uri in locations {
        let uri = uri.trim();
        if uri.is_empty() || is_reuse_sentinel(uri) {
            return Ok(TicketRoute::SameChannel);
        }
        match Transport::parse(uri) {
            Ok(transport) => {
                if ours.is_some_and(|ours| ours.same_server(&transport)) {
                    return Ok(TicketRoute::SameChannel);
                }

                if foreign.is_none() {
                    foreign = Some(transport);
                }
            }
            Err(e) => {
                if first_error.is_none() {
                    // Redacted: an unusable location may be unusable
                    // *because* it embeds a credential.
                    // The location itself is not rendered: an unusable
                    // one may be unusable precisely because it embeds a
                    // secret.
                    first_error = Some(format!("a result location was unusable: {e}"));
                }
            }
        }
    }
    match foreign {
        Some(transport) => Ok(TicketRoute::Foreign(Box::new(transport))),
        None => Err(first_error
            .unwrap_or_else(|| "the server returned no usable result location".to_string())),
    }
}

// ---------------------------------------------------------------------------
// Connector
// ---------------------------------------------------------------------------

/// Shared state behind [`FlightSqlConnector`], cloned into the futures the
/// `SQLExecutor` hands back.
struct Inner {
    config: FlightSqlConfig,
    /// The connection to the configured endpoint. `Channel` is a cheap
    /// handle that multiplexes concurrent RPCs over HTTP/2, so cloning it
    /// per operation is how this connector gets concurrency without a pool.
    channel: Channel,
    /// `authorization` header applied to every RPC (the Basic credential).
    auth_header: Option<Secret>,
    /// Bearer token, from `handshake` or from configuration. Takes
    /// precedence over `auth_header` — `set_token` overwrites the
    /// `authorization` metadata the headers set.
    token: Option<Secret>,
    /// Every secret this connector holds, for scrubbing error text.
    secrets: Vec<Secret>,
    /// The configured endpoint's transport, for the ticket-routing policy —
    /// authority AND TLS posture, since both are part of "same server".
    transport: Transport,
}

impl Inner {}

impl Inner {
    /// A client for one operation, with this connector's credentials
    /// applied. Built per call rather than cloned from a prepared one: a
    /// client's channel cannot be swapped while keeping its headers, and a
    /// foreign endpoint location needs exactly that.
    fn client_on(&self, channel: Channel) -> FlightSqlServiceClient<Channel> {
        let mut client = FlightSqlServiceClient::new(channel);
        if let Some(token) = &self.token {
            client.set_token(token.expose().to_string());
        } else if let Some(header) = &self.auth_header {
            client.set_header("authorization", header.expose());
        }
        client
    }

    /// A client on the configured endpoint.
    fn client(&self) -> FlightSqlServiceClient<Channel> {
        self.client_on(self.channel.clone())
    }

    /// Strip any credential this connector holds out of remote-produced
    /// text before it becomes a Dataglot error (rule 12). Servers echo
    /// request metadata into error messages more often than you would like.
    fn scrub(&self, msg: &str) -> String {
        scrub_with(msg, &self.secrets)
    }

    /// Rebuild an error with its message scrubbed, preserving its kind.
    fn scrub_err(&self, e: &DataglotError) -> DataglotError {
        let scrubbed = self.scrub(&e.to_string());
        match e {
            DataglotError::Catalog(_) => DataglotError::catalog(scrubbed),
            _ => DataglotError::federation(scrubbed),
        }
    }

    fn flight_err(&self, what: &str, e: &FlightError) -> DataglotError {
        DataglotError::federation(self.scrub(&format!(
            "flightsql catalog '{}': {what}: {e}",
            self.config.name
        )))
    }

    /// `GetFlightInfo` for a statement — plans it on the remote and returns
    /// the advertised schema plus the tickets, without fetching a row.
    async fn plan_statement(&self, sql: String) -> DataglotResult<arrow_flight::FlightInfo> {
        let mut client = self.client();
        client
            .execute(sql, None)
            .await
            .map_err(|e| self.flight_err("statement planning failed", &e))
    }

    /// The channel to fetch one endpoint's ticket on — `None` meaning "the
    /// one we already hold" ([`route_for`] decides).
    ///
    /// A foreign route is refused by default: following it would send this
    /// catalog's credentials to a host the *remote* nominated. When the
    /// operator opts in, the channel is built from the location's **own**
    /// parsed transport, so a `grpc+tls://` replica gets TLS even if this
    /// catalog's endpoint is plaintext (and vice versa).
    async fn channel_for(&self, endpoint: &FlightEndpoint) -> DataglotResult<Option<Channel>> {
        let locations: Vec<String> = endpoint.location.iter().map(|l| l.uri.clone()).collect();
        // Routing errors are scrubbed too: they describe a *remote-supplied*
        // URI, and while `Transport::parse` echoes none of its input, that is
        // an invariant of another function — rule 12 does not rely on it.
        let route = route_for(&locations, Some(&self.transport)).map_err(|e| {
            DataglotError::federation(
                self.scrub(&format!("flightsql catalog '{}': {e}", self.config.name)),
            )
        })?;
        let TicketRoute::Foreign(transport) = route else {
            return Ok(None);
        };
        // The advertised URI is *remote-supplied text*. `Transport::parse`
        // already refuses userinfo, but a host or port component is still
        // free-form enough to carry a reflected credential (a server that
        // echoes a Basic password back as `grpc://hunter2:443`), so every
        // rendering of it — the refusal, the log line, and any connection
        // error underneath — goes through `scrub` first.
        let location = self.scrub(&transport.uri);
        if !self.config.follow_endpoint_locations {
            return Err(DataglotError::federation(format!(
                "flightsql catalog '{}': the server returned a result location on another \
                 host ('{location}'). Following it would send this catalog's credentials \
                 there, so it is refused by default — set `follow_endpoint_locations = \
                 true` to allow it.",
                self.config.name
            )));
        }
        debug!(
            catalog = %self.config.name,
            location = %location,
            tls = transport.tls,
            "flightsql: following a foreign endpoint location"
        );
        build_channel(&self.config, &transport, false)
            .await
            .map(Some)
            .map_err(|e| DataglotError::federation(self.scrub(&e.to_string())))
    }

    /// Redeem one endpoint's ticket, honouring the routing policy. Shared by
    /// the query path and both discovery paths, so a distributed server that
    /// advertises locations behaves the same everywhere.
    ///
    /// An endpoint with no ticket is a protocol error, not something to skip.
    /// Skipping it is invisible on the discovery paths: the RPC succeeded, so
    /// no fallback runs, and the operator gets a catalog that is missing
    /// whatever that endpoint held while everything reports healthy. Same
    /// reasoning as the schema-less listing — a partial catalog that looks
    /// complete is worse than an error.
    ///
    /// # Errors
    /// [`DataglotError::Federation`] when the endpoint carries no ticket,
    /// when the routing policy refuses its location, or when `DoGet` fails.
    async fn do_get(
        &self,
        endpoint: &FlightEndpoint,
    ) -> DataglotResult<BoxStream<'static, Result<RecordBatch, FlightError>>> {
        let Some(ticket) = endpoint.ticket.clone() else {
            return Err(DataglotError::federation(format!(
                "flightsql catalog '{}': the server returned an endpoint with no ticket, \
                 so the rows behind it cannot be fetched",
                self.config.name
            )));
        };
        let mut client = match self.channel_for(endpoint).await? {
            Some(channel) => self.client_on(channel),
            None => self.client(),
        };
        let stream = client
            .do_get(ticket)
            .await
            .map_err(|e| self.flight_err("fetching a result stream failed", &e))?;

        // `Endpoint::timeout` bounds the future that produces the response
        // *headers*; everything after that — the actual data — is polled
        // without a deadline, so a server that answers promptly and then
        // stalls mid-stream would hang forever. Apply the same budget as an
        // INACTIVITY deadline: it catches the stall without capping a long
        // legitimate transfer, which a whole-stream timeout would.
        let Some(secs) = self.config.request_timeout_secs else {
            return Ok(stream.boxed());
        };
        let idle = Duration::from_secs(secs);
        Ok(tokio_stream::StreamExt::timeout(stream, idle)
            .map(move |item| {
                item.unwrap_or_else(|_| {
                    Err(FlightError::ProtocolError(format!(
                        "the server sent no data for {secs}s \
                         (`request_timeout_secs`); giving up on the stalled stream"
                    )))
                })
            })
            .boxed())
    }

    /// Fetch one endpoint's ticket as a stream of batches aligned to
    /// `target`.
    async fn fetch_endpoint(
        self: Arc<Self>,
        endpoint: FlightEndpoint,
        target: SchemaRef,
    ) -> DataglotResult<BoxStream<'static, DfResult<RecordBatch>>> {
        let stream = self.do_get(&endpoint).await?;
        let me = Arc::clone(&self);
        Ok(stream
            .map(move |batch| match batch {
                Ok(batch) => crate::remote_sql::align_batch(&batch, &target, "flightsql")
                    .map_err(|e| DataFusionError::External(Box::new(e))),
                Err(e) => Err(DataFusionError::External(Box::new(
                    DataglotError::federation(me.scrub(&format!(
                        "flightsql catalog '{}': result stream failed: {e}",
                        me.config.name
                    ))),
                ))),
            })
            .boxed())
    }

    /// Run a statement and drain it into memory — metadata-sized results
    /// only (discovery, health).
    async fn collect_statement(&self, sql: String) -> DataglotResult<Vec<RecordBatch>> {
        let info = self.plan_statement(sql).await?;
        let mut out = Vec::new();
        for endpoint in info.endpoint {
            let stream = self.do_get(&endpoint).await?;
            let batches: Vec<RecordBatch> = stream
                .try_collect()
                .await
                .map_err(|e| self.flight_err("reading a metadata stream failed", &e))?;
            out.extend(batches);
        }
        Ok(out)
    }
}

/// Build a tonic channel for one already-parsed [`Transport`], using this
/// config's timeouts and TLS trust settings.
///
/// TLS is taken from `transport`, **not** from the catalog's own endpoint —
/// a followed result location carries its own posture.
/// The SNI / certificate-name override for one channel.
///
/// `tls_domain` names **this catalog's** endpoint — typically because it is
/// reached by IP. A server-advertised replica has its own name, so applying
/// the coordinator's would validate the replica's certificate against the
/// wrong name and reject a perfectly good one.
fn sni_override(config: &FlightSqlConfig, configured: bool) -> Option<&str> {
    configured.then_some(config.tls_domain.as_deref()).flatten()
}

async fn build_channel(
    config: &FlightSqlConfig,
    transport: &Transport,
    configured: bool,
) -> DataglotResult<Channel> {
    let uri = &transport.uri;
    let conn_err = |e: &dyn fmt::Display| {
        DataglotError::connection(format!(
            "flightsql catalog '{}': connecting to '{uri}' failed: {e}",
            config.name
        ))
    };

    let mut endpoint = Endpoint::from_shared(uri.clone())
        .map_err(|e| {
            DataglotError::configuration(format!(
                "flightsql catalog '{}': '{uri}' is not a valid URI: {e}",
                config.name
            ))
        })?
        .connect_timeout(Duration::from_secs(config.connect_timeout_secs));
    if let Some(secs) = config.request_timeout_secs {
        endpoint = endpoint.timeout(Duration::from_secs(secs));
    }

    if transport.tls {
        // One crypto provider per process — the same ring backend `pg_tls`,
        // `mysql_tls` and the pgwire/Flight listeners install. Ignoring the
        // result is deliberate: a provider installed by another connector
        // first is the expected steady state.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut tls = ClientTlsConfig::new().with_enabled_roots();
        if let Some(path) = &config.tls_ca_file {
            let pem = tokio::fs::read(path).await.map_err(|e| {
                DataglotError::configuration(format!(
                    "flightsql catalog '{}': reading tls_ca_file {}: {e}",
                    config.name,
                    path.display()
                ))
            })?;
            tls = tls.ca_certificate(Certificate::from_pem(pem));
        }
        if let Some(domain) = sni_override(config, configured) {
            tls = tls.domain_name(domain.to_string());
        }

        endpoint = endpoint
            .tls_config(tls)
            .map_err(|e| conn_err(&format!("TLS configuration rejected: {e}")))?;
    }

    endpoint.connect().await.map_err(|e| conn_err(&e))
}

/// Flight SQL ingress connector. One instance per `kind = "flightsql"`
/// catalog entry; hands out federation [`TableProvider`]s with full SQL
/// pushdown to the remote engine.
pub struct FlightSqlConnector {
    inner: Arc<Inner>,
}

impl fmt::Debug for FlightSqlConnector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FlightSqlConnector")
            .field("config", &self.inner.config)
            .finish_non_exhaustive()
    }
}

impl FlightSqlConnector {
    /// Connect to the endpoint, resolve credentials, and (when
    /// `handshake` is set) exchange them for a bearer token.
    ///
    /// The TCP/TLS connect happens here so a bad endpoint or a bad
    /// certificate fails boot rather than the first query.
    ///
    /// # Errors
    /// [`DataglotError::Configuration`] when the config is inconsistent or a
    /// credential environment variable is unset;
    /// [`DataglotError::Connection`] when the endpoint is unreachable or TLS
    /// fails; [`DataglotError::Federation`] when the handshake is rejected.
    /// No message carries a credential.
    pub async fn connect(config: FlightSqlConfig) -> DataglotResult<Self> {
        config.validate()?;

        // Resolve secrets from the environment. The *names* are config; the
        // values live only in the `Secret`s below (rule 12).
        let env = |var: &str| -> DataglotResult<String> {
            std::env::var(var).map_err(|_| {
                DataglotError::configuration(format!(
                    "flightsql catalog '{}': environment variable '{var}' is not set",
                    config.name
                ))
            })
        };
        let (basic, bearer) = match &config.auth {
            FlightSqlAuth::None => (None, None),
            FlightSqlAuth::Basic {
                username,
                password_env,
            } => {
                let password = env(password_env)?;
                let encoded = base64::engine::general_purpose::STANDARD
                    .encode(format!("{username}:{password}"));
                (Some((Secret(password), Secret(encoded))), None)
            }
            FlightSqlAuth::Bearer { token_env } => (None, Some(Secret(env(token_env)?))),
        };

        let transport = config.transport()?;
        let channel = build_channel(&config, &transport, true).await?;

        let mut secrets: Vec<Secret> = Vec::new();
        let mut auth_header: Option<Secret> = None;
        let mut token: Option<Secret> = bearer.clone();
        if let Some(token) = &bearer {
            secrets.push(token.clone());
        }
        if let Some((password, encoded)) = &basic {
            secrets.push(password.clone());
            secrets.push(encoded.clone());
            auth_header = Some(Secret(format!("Basic {}", encoded.expose())));
            if config.handshake {
                // Exchange the Basic credential for whatever bearer token
                // the server issues; `handshake` records it on the client it
                // ran on, so read it back off that client.
                let FlightSqlAuth::Basic { username, .. } = &config.auth else {
                    unreachable!("validate() rejects handshake without Basic credentials");
                };
                let mut client = FlightSqlServiceClient::new(channel.clone());
                client
                    .handshake(username, password.expose())
                    .await
                    .map_err(|e| {
                        DataglotError::federation(format!(
                            "flightsql catalog '{}': handshake failed: {}",
                            config.name,
                            scrub_with(&e.to_string(), &secrets)
                        ))
                    })?;
                if let Some(issued) = client.token() {
                    let issued = Secret(issued.clone());
                    secrets.push(issued.clone());
                    token = Some(issued);
                } else {
                    warn!(
                        catalog = %config.name,
                        "flightsql: handshake returned no bearer token; falling back to the \
                         Basic credential on every request"
                    );
                }
            }
        }

        // Register the shape a URL parser would turn each secret into, so a
        // credential reflected into an advertised *host* is still matched
        // after normalisation.
        secrets.extend(
            secrets
                .clone()
                .iter()
                .filter_map(|s| normalised_host(s.expose())),
        );

        Ok(Self {
            inner: Arc::new(Inner {
                config,
                channel,
                auth_header,
                token,
                secrets,
                transport,
            }),
        })
    }

    /// The connector / federation compute-context name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.inner.config.name
    }

    /// Produce a federation [`TableProvider`] for `<schema>.<table>` with
    /// full pushdown to the remote. The Arrow schema resolves on this call
    /// — lazy per hard rule 13, nothing is fetched at
    /// [`FlightSqlConnector::connect`] time.
    ///
    /// # Errors
    /// [`DataglotError::Catalog`] when the remote can't resolve the table's
    /// schema.
    pub async fn table_provider(
        self: &Arc<Self>,
        schema: &str,
        table: &str,
    ) -> DataglotResult<Arc<dyn TableProvider>> {
        let catalog = self.inner.config.catalog.as_deref();
        let arrow_schema = self.fetch_arrow_schema(catalog, schema, table).await?;
        let executor: Arc<dyn SQLExecutor> = Arc::clone(self) as Arc<dyn SQLExecutor>;
        let provider = Arc::new(SQLFederationProvider::new(executor));
        // Qualify with the configured catalog when there is one: discovery
        // scopes to it, so execution must resolve there too — otherwise the
        // server falls back to its default and can read a same-named table
        // from the wrong catalog. `validate` has already refused a catalog
        // on a dialect that cannot carry one.
        let table_ref = RemoteTableRef::from(match catalog {
            Some(catalog) => {
                TableReference::full(catalog.to_string(), schema.to_string(), table.to_string())
            }
            None => TableReference::partial(schema.to_string(), table.to_string()),
        });
        let source = SQLTableSource::new_with_schema(provider, table_ref, arrow_schema);
        Ok(Arc::new(FederatedTableProviderAdaptor::new(Arc::new(
            source,
        ))))
    }

    /// Resolve `<schema>.<table>`'s Arrow schema by planning a zero-row
    /// probe (`SELECT * FROM … LIMIT 0`) and decoding the schema the server
    /// advertises in its `FlightInfo`.
    ///
    /// This works against every Flight SQL server — any server that can plan
    /// a statement returns its schema — and moves no rows, because the
    /// ticket is never fetched.
    async fn fetch_arrow_schema(
        &self,
        catalog: Option<&str>,
        schema: &str,
        table: &str,
    ) -> DataglotResult<SchemaRef> {
        let sql = format!(
            "SELECT * FROM {} LIMIT 0",
            self.qualified_name(catalog, schema, table)
        );

        let info = self.inner.plan_statement(sql).await.map_err(|e| {
            DataglotError::catalog(format!(
                "flightsql: resolving the schema of '{schema}.{table}' failed: {e}"
            ))
        })?;
        let arrow_schema = info.try_decode_schema().map_err(|e| {
            DataglotError::catalog(format!(
                "flightsql: the server advertised no readable schema for '{schema}.{table}': {e}"
            ))
        })?;
        Ok(Arc::new(arrow_schema))
    }

    /// `[catalog.]schema.table`, quoted for the configured dialect — the
    /// reference the remote sees, matching what `table_provider` registers.
    fn qualified_name(&self, catalog: Option<&str>, schema: &str, table: &str) -> String {
        let dialect = self.inner.config.dialect;
        let mut parts = Vec::with_capacity(3);
        if let Some(catalog) = catalog {
            parts.push(dialect.quote(catalog));
        }

        parts.push(dialect.quote(schema));
        parts.push(dialect.quote(table));
        parts.join(".")
    }

    /// Split the reference `datafusion-federation` renders back into
    /// `(schema, table)`.
    ///
    /// The arity is known rather than guessed: this connector rendered the
    /// reference itself in [`Self::table_provider`], so a catalog is present
    /// exactly when one is configured. That matters because a table name may
    /// itself contain a dot.
    fn split_remote_ref(reference: &str) -> Option<(Option<String>, String, String)> {
        // Quote-aware in both arities: a catalog, schema or table may
        // itself contain a dot, in which case the rendered reference quotes
        // it. The arity is known rather than guessed, since this connector
        // rendered the reference itself.
        // Either arity is accepted rather than keyed off the *current*
        // catalog: a provider built before discovery adopted one still
        // holds a two-part reference, and reading the last two parts is
        // correct for both shapes.
        let parts = split_quoted_reference(reference);
        let (catalog, schema, table) = match parts.as_slice() {
            [schema, table] => (None, schema, table),
            [catalog, schema, table] => (Some(catalog.clone()), schema, table),
            _ => return None,
        };
        (!schema.is_empty() && !table.is_empty()).then(|| (catalog, schema.clone(), table.clone()))
    }

    /// Wrap this connector as a `DataFusion` [`CatalogProvider`].
    ///
    /// Schema and table names are enumerated once, here; per-table column
    /// schemas stay **lazy** (rule 13), resolving on first
    /// [`SchemaProvider::table`] access. Listing prefers the Flight SQL
    /// `GetTables` metadata RPC and falls back to an `information_schema`
    /// query for servers that don't implement it — which includes
    /// Dataglot's own Flight SQL listener today.
    ///
    /// Names are cached for the catalog's lifetime, so drop and rebuild it
    /// to pick up remote DDL — the same caveat as every other connector.
    ///
    /// # Errors
    /// [`DataglotError::Catalog`] when neither listing path works.
    ///
    /// [`CatalogProvider`]: datafusion::catalog::CatalogProvider
    /// [`SchemaProvider::table`]: datafusion::catalog::SchemaProvider::table
    pub async fn as_catalog_provider(
        self: &Arc<Self>,
    ) -> DataglotResult<Arc<dyn DfCatalogProvider>> {
        let listing = self.list_tables().await?;
        let schema_names: Vec<String> = listing.keys().cloned().collect();
        let schemas: HashMap<String, Arc<dyn DfSchemaProvider>> = listing
            .into_iter()
            .map(|(schema_name, tables)| {
                let provider = Arc::new(FlightSqlSchema {
                    connector: Arc::clone(self),
                    schema_name: schema_name.clone(),
                    table_names: tables.into_iter().collect(),
                }) as Arc<dyn DfSchemaProvider>;
                (schema_name, provider)
            })
            .collect();

        Ok(Arc::new(FlightSqlCatalog {
            connector_name: self.inner.config.name.clone(),
            schema_names,
            schemas,
        }) as Arc<dyn DfCatalogProvider>)
    }

    /// Apply the configured schema scope to a listing.
    ///
    /// `db_schema_filter_pattern` is a SQL wildcard, and servers vary in
    /// whether they honour it at all, so the scope is a governance boundary
    /// enforced here rather than a hint left to the remote.
    fn retain_scope(&self, listing: &mut Listing, provenance: &mut Provenance) {
        if let Some(scope) = &self.inner.config.schema {
            listing.retain(|schema, _| schema == scope);
            provenance.retain(|schema, _| schema == scope);
        }
    }

    /// Refuse a listing whose rows came from a catalog this connector will
    /// not qualify with.
    ///
    /// Discovery never *adopts* a catalog — `catalog` is configuration, and
    /// a reference is three-part only when it is set (see the connector
    /// docs). But an omitted `CommandGetTables.catalog` means "do not
    /// narrow", not "the session default", so a compliant multi-catalog
    /// server answers with every catalog it has. Two rows that agree on
    /// `schema.table` and differ only in catalog then collapse into one
    /// entry, and the two-part reference this connector emits resolves
    /// against the server's default — making one of the tables unreachable
    /// and, worse, reading the other one's data under its name.
    ///
    /// So the provenance is checked even though it is never adopted:
    ///
    /// * `catalog` unset — more than one distinct value (two named
    ///   catalogs, or a named one mixed with unqualified rows) is ambiguous.
    ///   A single value, named or not, is the documented "resolves against
    ///   the server default" case and passes.
    /// * `catalog` set — every reference is qualified with it, so any row
    ///   from a *different* named catalog would be listed under a name that
    ///   does not address it. Unqualified rows are fine: they mean the
    ///   server simply does not populate the column.
    ///
    /// # Errors
    /// [`DataglotError::Catalog`] when the rows cannot all be addressed by
    /// the references this connector emits.
    fn refuse_foreign_catalogs(&self, provenance: &Provenance) -> DataglotResult<()> {
        judge_catalogs(
            provenance,
            self.inner.config.catalog.as_deref(),
            &self.inner.config.name,
        )
    }
}

/// The judgement behind [`FlightSqlConnector::refuse_schemaless_listing`], as
/// a free function so it can be exercised without a live server.
///
/// # Errors
/// [`DataglotError::Catalog`] when rows named a table but no schema and no
/// scope is configured to put them outside the boundary.
fn judge_schemaless(
    listing: &Listing,
    schemaless: usize,
    scoped: bool,
    name: &str,
) -> DataglotResult<()> {
    if schemaless == 0 {
        return Ok(());
    }
    // A configured scope names a schema, and a row with no schema is not in
    // it. Servers vary in whether they honour `db_schema_filter_pattern` at
    // all, so a schema-less row arriving alongside the scoped ones is the
    // server ignoring the hint — not a table this catalog was ever going to
    // expose. Dropping it is what the scope means; refusing would let a row
    // outside the boundary fail discovery inside it.
    if scoped {
        debug!(
            catalog = %name,
            dropped = schemaless,
            "flightsql: schema-less rows arrived outside the configured scope; ignoring them"
        );
        return Ok(());
    }
    Err(DataglotError::catalog(format!(
        "flightsql catalog '{name}': the server returned {schemaless} table(s) with no \
         schema name. This connector addresses tables as `schema.table`, so it has \
         nowhere to put them — and because the metadata call succeeded, the \
         `information_schema` fallback never runs. Listing the other {} and dropping \
         these would hand back a catalog that looks complete and is not.",
        listing.values().map(BTreeSet::len).sum::<usize>()
    )))
}

/// The judgement behind [`FlightSqlConnector::refuse_foreign_catalogs`], as a
/// free function so it can be exercised without a live server.
///
/// # Errors
/// [`DataglotError::Catalog`] when the listed rows cannot all be addressed by
/// the references this connector emits.
fn judge_catalogs(
    provenance: &Provenance,
    configured: Option<&str>,
    name: &str,
) -> DataglotResult<()> {
    {
        let seen: BTreeSet<&Option<String>> = provenance.values().flatten().collect();
        let render = |c: &Option<String>| -> String {
            c.clone().unwrap_or_else(|| "<unqualified>".to_string())
        };
        let Some(configured) = configured else {
            if seen.len() < 2 {
                return Ok(());
            }
            let names: Vec<String> = seen.iter().map(|c| render(c)).collect();
            return Err(DataglotError::catalog(format!(
                "flightsql catalog '{}': the server listed tables from {} different \
                 catalogs ({}). This connector addresses tables as `schema.table` \
                 unless a catalog is configured, so a table present in two of them \
                 would resolve against whichever the server defaults to — set \
                 `catalog` to the one this catalog should federate.",
                name,
                seen.len(),
                names.join(", ")
            )));
        };
        let foreign: Vec<String> = seen
            .iter()
            .filter(|c| c.as_deref().is_some_and(|c| c != configured))
            .map(|c| render(c))
            .collect();
        if foreign.is_empty() {
            return Ok(());
        }
        Err(DataglotError::catalog(format!(
            "flightsql catalog '{}': `catalog` is set to '{configured}', so every \
             reference is qualified with it — but the server listed tables from {} \
             ({}) as well, which that qualifier does not address. The server ignored \
             the catalog filter; narrow the listing on the server or point this \
             catalog at one it honours.",
            name,
            if foreign.len() == 1 {
                "another catalog".to_string()
            } else {
                format!("{} other catalogs", foreign.len())
            },
            foreign.join(", ")
        )))
    }
}

impl FlightSqlConnector {
    /// Refuse a listing whose rows carry no schema.
    ///
    /// Unless a schema scope is configured: a scope names a schema, a
    /// schema-less row is not in it, and a server that ignores
    /// `db_schema_filter_pattern` will send rows from outside the boundary.
    /// Those are dropped, as everything else outside the scope is.
    ///
    /// A compliant server for an engine with no schema namespace reports
    /// `db_schema_name = NULL`. Those rows name real tables this connector
    /// cannot address, and because the metadata call itself *succeeded* the
    /// `information_schema` fallback never runs. **Any** such row is an
    /// error, not just an all-schemaless answer: tolerating a mixed one
    /// hands back a catalog that looks complete while some tables are
    /// silently missing from it.
    ///
    /// # Errors
    /// [`DataglotError::Catalog`] when any row lacked a schema.
    /// Refuse a response containing rows that named no table.
    ///
    /// Scoped first, like every other judgement here: a row whose schema the
    /// configured scope excludes is outside this catalog whether it is
    /// malformed or not, and servers that ignore `db_schema_filter_pattern`
    /// send such rows routinely. A row that named *neither* a schema nor a
    /// table cannot be placed at all, so no scope excuses it.
    ///
    /// # Errors
    /// [`DataglotError::Catalog`] when a malformed row is in scope, or
    /// carries no schema to scope it by.
    fn refuse_malformed_rows(&self, malformed: &BTreeSet<Option<String>>) -> DataglotResult<()> {
        judge_malformed_rows(
            malformed,
            self.inner.config.schema.as_deref(),
            &self.inner.config.name,
        )
    }
}

/// The judgement behind [`FlightSqlConnector::refuse_malformed_rows`], as a
/// free function so it can be exercised without a live server.
///
/// # Errors
/// [`DataglotError::Catalog`] when a malformed row is in scope, or carries no
/// schema to scope it by.
fn judge_malformed_rows(
    malformed: &BTreeSet<Option<String>>,
    scope: Option<&str>,
    name: &str,
) -> DataglotResult<()> {
    {
        // Fatal unless the configured scope places it elsewhere. A row that
        // named no schema has nothing to scope it by, so it is always fatal.
        let fatal = malformed
            .iter()
            .filter(|row| match (row.as_deref(), scope) {
                (Some(row), Some(scope)) => row == scope,
                _ => true,
            });
        let count = fatal.count();
        if count == 0 {
            if !malformed.is_empty() {
                debug!(
                    catalog = %name,
                    dropped = malformed.len(),
                    "flightsql: rows naming no table arrived outside the configured scope; \
                     ignoring them"
                );
            }
            return Ok(());
        }
        Err(DataglotError::catalog(format!(
            "flightsql catalog '{name}': the server's metadata response carried {count} row(s) \
             naming no table. The table name is what is being listed, so those rows name \
             nothing this connector can address — and because the metadata call succeeded, \
             the `information_schema` fallback never runs. Listing the rest would hand back \
             a catalog that looks complete and is not."
        )))
    }
}

impl FlightSqlConnector {
    /// The error for a metadata response whose listing columns could not be
    /// read — absent, or not castable to a string.
    fn unreadable_listing(&self, columns: &str) -> DataglotError {
        DataglotError::catalog(format!(
            "flightsql catalog '{}': the server's metadata response carried rows but no \
             readable {columns} column, so those rows name tables this connector cannot \
             address. The metadata call succeeded, so the `information_schema` fallback \
             never runs — listing the rest would hand back a catalog that looks complete \
             and is not.",
            self.inner.config.name
        ))
    }

    /// The error for a metadata response whose catalog column could not be
    /// read — absent, or not castable to a string.
    fn unreadable_provenance(&self, column: &str) -> DataglotError {
        DataglotError::catalog(format!(
            "flightsql catalog '{}': the server's metadata response has no readable \
             `{column}` column. Both discovery shapes define one, and without it this \
             connector cannot tell whether the listing spans several catalogs — two \
             same-named tables would collapse into one entry that resolves against the \
             server's default. Refusing rather than guessing.",
            self.inner.config.name
        ))
    }

    fn refuse_schemaless_listing(
        &self,
        listing: &Listing,
        schemaless: usize,
    ) -> DataglotResult<()> {
        judge_schemaless(
            listing,
            schemaless,
            self.inner.config.schema.is_some(),
            &self.inner.config.name,
        )
    }

    /// `schema → table names`, via `GetTables` or the `information_schema`
    /// fallback.
    async fn list_tables(&self) -> DataglotResult<Listing> {
        match self.list_tables_via_metadata().await {
            Ok(found) => Ok(found),
            Err(e) if is_unimplemented(&e) => {
                debug!(
                    catalog = %self.inner.config.name,
                    "flightsql: server does not implement GetTables; listing via information_schema"
                );
                // Scrubbed like the metadata path's errors, which go
                // through `flight_err`. Discovery errors quote *remote*
                // metadata — `judge_catalogs` names the catalogs it saw —
                // so a server that reflects a credential back as a catalog
                // name would otherwise put it in the operator's error.
                self.list_tables_via_information_schema()
                    .await
                    .map_err(|e| self.inner.scrub_err(&e))
            }
            Err(e) => Err(self.inner.flight_err("listing tables failed", &e)),
        }
    }

    /// Primary listing path: the Flight SQL `GetTables` metadata RPC.
    async fn list_tables_via_metadata(&self) -> Result<Listing, FlightError> {
        let mut client = self.inner.client();
        let info = client
            .get_tables(CommandGetTables {
                catalog: self.inner.config.catalog.clone(),
                // `db_schema_filter_pattern` is a SQL *wildcard* pattern, so
                // a schema like `tenant_1` or `sales%` would also match
                // `tenant-1` / `sales_eu` on a conforming server — a silent
                // widening of the configured scope. A backslash is worse
                // still: servers that treat it as the pattern escape read
                // `tenant\\east` as `tenanteast`, so the real schema is
                // never returned and the exact retain below cannot recover
                // rows that never arrived. Send the hint only when the name
                // contains none of the three; scoping itself is enforced
                // exactly, below, so withholding it only costs a wider
                // listing.
                db_schema_filter_pattern: schema_filter_hint(self.inner.config.schema.as_deref()),
                table_name_filter_pattern: None,
                table_types: Vec::new(),
                include_schema: false,
            })
            .await?;

        let mut sink = ListingSink::default();
        for endpoint in info.endpoint {
            // `Inner::do_get` is the single `DoGet` path: it applies the
            // location-routing policy AND the inactivity deadline. Calling
            // the client directly here would leave discovery able to hang on
            // a server that stalls mid-stream.
            let stream = self
                .inner
                .do_get(&endpoint)
                .await
                .map_err(|e| FlightError::ExternalError(Box::new(e)))?;
            let batches: Vec<RecordBatch> = stream.try_collect().await?;
            for batch in batches {
                collect_listing(
                    &batch,
                    "catalog_name",
                    "db_schema_name",
                    "table_name",
                    &mut sink,
                );
            }
        }
        // Scope first, then judge ambiguity: a server that ignores or widens
        // the schema pattern returns unrelated rows, and catalogs seen only
        // in rows the scope drops must not make the listing look ambiguous.
        if sink.unreadable_listing {
            return Err(FlightError::ExternalError(Box::new(
                self.unreadable_listing("`db_schema_name` / `table_name`"),
            )));
        }
        if sink.unreadable_catalog {
            return Err(FlightError::ExternalError(Box::new(
                self.unreadable_provenance("catalog_name"),
            )));
        }
        self.refuse_malformed_rows(&sink.malformed_rows)
            .map_err(|e| FlightError::ExternalError(Box::new(e)))?;
        self.refuse_schemaless_listing(&sink.listing, sink.schemaless)
            .map_err(|e| FlightError::ExternalError(Box::new(e)))?;
        self.retain_scope(&mut sink.listing, &mut sink.provenance);
        self.refuse_foreign_catalogs(&sink.provenance)
            .map_err(|e| FlightError::ExternalError(Box::new(e)))?;
        Ok(sink.listing)
    }

    /// Fallback listing path for servers without `GetTables` — every
    /// DataFusion-backed one, including Dataglot's own listener.
    async fn list_tables_via_information_schema(&self) -> DataglotResult<Listing> {
        // `table_catalog` is projected even though this connector never
        // adopts a catalog: `refuse_foreign_catalogs` reads the provenance
        // to refuse a listing whose rows span catalogs the emitted
        // references cannot address. Omitting it here would record every row
        // as unqualified and leave that check dead on this path.
        let mut sql = String::from(
            "SELECT table_catalog, table_schema, table_name FROM information_schema.tables \
             WHERE table_schema <> 'information_schema'",
        );

        if let Some(catalog) = &self.inner.config.catalog {
            // `information_schema.tables` spans every catalog in the remote
            // session, and execution qualifies each reference with the
            // configured one — so listing a table that exists only in
            // another catalog would produce a provider whose schema probe
            // then fails. Scope the listing the same way execution resolves.
            use std::fmt::Write as _;
            let _ = write!(
                sql,
                " AND table_catalog = '{}'",
                catalog.replace('\'', "''")
            );
        }
        if let Some(schema) = &self.inner.config.schema {
            // Single-quote escaping: doubling is SQL-standard and holds in
            // every dialect on the whitelist.
            use std::fmt::Write as _;
            let _ = write!(sql, " AND table_schema = '{}'", schema.replace('\'', "''"));
        }
        let batches = self.inner.collect_statement(sql).await.map_err(|e| {
            DataglotError::catalog(format!(
                "flightsql catalog '{}': the server implements neither the GetTables metadata \
                 RPC nor an information_schema.tables view, so its catalog cannot be listed: {e}",
                self.inner.config.name
            ))
        })?;
        let mut sink = ListingSink::default();
        for batch in batches {
            collect_listing(
                &batch,
                "table_catalog",
                "table_schema",
                "table_name",
                &mut sink,
            );
        }
        if sink.unreadable_listing {
            return Err(self.unreadable_listing("`table_schema` / `table_name`"));
        }
        if sink.unreadable_catalog {
            return Err(self.unreadable_provenance("table_catalog"));
        }
        self.refuse_malformed_rows(&sink.malformed_rows)?;
        self.refuse_schemaless_listing(&sink.listing, sink.schemaless)?;
        // Same ordering as the metadata path: scope, then judge.
        self.retain_scope(&mut sink.listing, &mut sink.provenance);
        self.refuse_foreign_catalogs(&sink.provenance)?;
        Ok(sink.listing)
    }
}

/// Fold a metadata batch's `(schema, table)` string pairs into
/// `schema → tables`, recording the catalog each row came from.
///
/// Columns are looked up by name, so the extra columns both `GetTables` and
/// `information_schema` carry are ignored. The three this connector needs —
/// catalog, schema and table — are **required** on any batch that carries
/// rows: a batch that cannot be read is flagged for the caller to refuse,
/// never silently dropped. Dropping it is invisible, because the metadata
/// call succeeded and so the `information_schema` fallback never runs; the
/// operator would get an empty or partial catalog with nothing to explain
/// it. An empty batch is not malformed — there is nothing in it to read.
///
/// The catalog matters even when this connector does not qualify with it:
/// an *omitted* `CommandGetTables.catalog` means "do not narrow", not "the
/// session default", so a multi-catalog server answers with everything. If
/// those rows span more than one catalog, a two-part `schema.table`
/// reference is ambiguous — it may resolve to a same-named table in the
/// server's default catalog instead of the one discovery found. The caller
/// refuses that rather than guessing.
fn collect_listing(
    batch: &RecordBatch,
    catalog_column: &str,
    schema_column: &str,
    table_column: &str,
    sink: &mut ListingSink,
) {
    // Cast rather than downcast: servers answer with `LargeUtf8`,
    // `Utf8View` or dictionary-encoded strings just as readily as `Utf8`,
    // and a bare downcast would turn any of those into a silently empty
    // catalog. (The v0.5.1 audit was full of exactly this bug class.)
    let column = |name: &str| -> Option<ArrayRef> {
        let idx = batch.schema().index_of(name).ok()?;
        arrow::compute::cast(batch.column(idx), &arrow::datatypes::DataType::Utf8).ok()
    };
    // The listing columns are required on the same reasoning as the catalog
    // one below: this response *succeeded*, so no fallback runs, and a batch
    // silently contributing nothing hands the operator an empty or partial
    // catalog with nothing to explain it.
    let (Some(schemas), Some(tables)) = (column(schema_column), column(table_column)) else {
        if batch.num_rows() > 0 {
            sink.unreadable_listing = true;
        }
        return;
    };
    // The catalog column is *required*, not optional. Both discovery shapes
    // define it — `catalog_name` is part of the Flight SQL `GetTables`
    // result schema, and the fallback projects `table_catalog` itself — so a
    // response without a readable one is malformed. Reading it as "every row
    // unqualified" would disable the ambiguity check precisely when
    // provenance cannot be established, which is the case that needs it.
    let catalogs = column(catalog_column);
    let catalogs = catalogs
        .as_ref()
        .and_then(|c| c.as_any().downcast_ref::<StringArray>());
    if catalogs.is_none() && batch.num_rows() > 0 {
        sink.unreadable_catalog = true;
        return;
    }
    let (Some(schemas), Some(tables)) = (
        schemas.as_any().downcast_ref::<StringArray>(),
        tables.as_any().downcast_ref::<StringArray>(),
    ) else {
        if batch.num_rows() > 0 {
            sink.unreadable_listing = true;
        }
        return;
    };
    for row in 0..batch.num_rows() {
        // The table name is what is being listed, so a row without one is
        // malformed — flagged for the caller to refuse, not skipped. The
        // metadata call succeeded, so no fallback runs, and quietly dropping
        // the row hands back a catalog that looks complete and is not.
        if tables.is_null(row) {
            sink.malformed_rows
                .insert((!schemas.is_null(row)).then(|| schemas.value(row).to_string()));
            continue;
        }
        // A row with no *schema* is different: that is a server whose engine
        // has no schema namespace at all. It is counted rather than flagged,
        // because whether it matters depends on the configured scope, which
        // only the caller knows.
        if schemas.is_null(row) {
            sink.schemaless += 1;
            continue;
        }

        let schema = schemas.value(row).to_string();
        sink.provenance.entry(schema.clone()).or_default().insert(
            catalogs
                .filter(|c| !c.is_null(row))
                .map(|c| c.value(row).to_string()),
        );
        sink.listing
            .entry(schema)
            .or_default()
            .insert(tables.value(row).to_string());
    }
}

/// Did the server answer this RPC with gRPC `Unimplemented`?
fn is_unimplemented(e: &FlightError) -> bool {
    match e {
        FlightError::Tonic(status) => status.code() == tonic::Code::Unimplemented,
        FlightError::NotYetImplemented(_) => true,
        _ => false,
    }
}

/// Scrub a set of secrets out of a message (the free function behind
/// [`Inner::scrub`], usable before an `Inner` exists).
///
/// Matching is **ASCII-case-insensitive**, because the text being scrubbed
/// has usually been through a normaliser first. `Transport::parse` hands its
/// input to `url`, which lowercases the host — so a server reflecting the
/// password `Hunter2` back as `grpc://Hunter2:443` produces `hunter2` in the
/// parsed URI, which an exact-match scrub would walk straight past. ASCII
/// lowercasing is what URL host normalisation does, and it preserves byte
/// length, so offsets found in the lowercased copy address the original
/// exactly.
fn scrub_with(msg: &str, secrets: &[Secret]) -> String {
    secrets.iter().fold(msg.to_string(), |acc, s| {
        if s.expose().is_empty() {
            acc
        } else {
            redact(&acc, s.expose())
        }
    })
}

/// The form a URL parser would turn `secret` into if it appeared as a host,
/// when that differs from the secret itself.
///
/// `url` does more to a host than lowercase it: it applies IDNA, so a
/// password `päss` reflected back by a server as `grpc://päss:443` is parsed
/// into the host `xn--pss-qla`. No amount of case folding matches that, and
/// punycode is reversible, so the credential would be readable in the
/// refusal. Registering the converted form as a secret of its own closes
/// every rendering path at once, including connection errors raised beneath
/// us that we never format ourselves.
///
/// Returns `None` when the secret cannot appear in a host at all, or when
/// normalisation leaves it unchanged apart from case (which `redact` already
/// handles).
fn normalised_host(secret: &str) -> Option<Secret> {
    if secret.is_empty() {
        return None;
    }
    let parsed = url::Url::parse(&format!("http://{secret}")).ok()?;
    let host = parsed.host_str()?;
    (!host.eq_ignore_ascii_case(secret)).then(|| Secret(host.to_string()))
}

/// Replace every ASCII-case-insensitive occurrence of `needle` in `haystack`.
fn redact(haystack: &str, needle: &str) -> String {
    let (folded, needle_folded) = (haystack.to_ascii_lowercase(), needle.to_ascii_lowercase());
    let mut out = String::with_capacity(haystack.len());
    let mut cursor = 0usize;
    while let Some(hit) = folded[cursor..].find(&needle_folded) {
        let at = cursor + hit;
        out.push_str(&haystack[cursor..at]);
        out.push_str("[redacted]");
        cursor = at + needle_folded.len();
    }
    out.push_str(&haystack[cursor..]);
    out
}

#[async_trait]
impl SQLExecutor for FlightSqlConnector {
    fn name(&self) -> &str {
        &self.inner.config.name
    }

    fn compute_context(&self) -> Option<String> {
        Some(self.inner.config.name.clone())
    }

    fn dialect(&self) -> Arc<dyn Dialect> {
        self.inner.config.dialect.unparser_dialect()
    }

    fn logical_optimizer(&self) -> Option<LogicalOptimizer> {
        // Isolate governance row filters on OUTER-JOIN preserved legs so the
        // unparser can't fold them into `ON` (RLS bypass) — /291.
        // Unparser-level, so every SQL-pushing connector needs it.
        Some(Box::new(|plan: datafusion::logical_expr::LogicalPlan| {
            crate::rls_isolation::isolate_outer_join_filters(plan)
        }))
    }

    fn ast_analyzer(&self) -> Option<AstAnalyzer> {
        // Requalify the derived-table references the unparser leaves
        // dangling on pushed-down DISTINCT / GROUP BY — /291.
        Some(Box::new(
            |stmt: datafusion::sql::sqlparser::ast::Statement| {
                Ok(crate::derived_requalify::requalify_derived_refs(stmt))
            },
        ))
    }

    fn execute(
        &self,
        query: &str,
        schema: SchemaRef,
        _filters: &[Arc<dyn PhysicalExpr>],
    ) -> DfResult<SendableRecordBatchStream> {
        let inner = Arc::clone(&self.inner);
        let sql = query.to_string();
        let target = Arc::clone(&schema);

        // Lazy: nothing happens until the first `poll_next`, so
        // `instrument_pushdown` times remote execution rather than planning.
        // Batches are streamed straight through from the wire — Flight hands
        // us Arrow already, so there is no decode step and no buffering.
        let fut = async move {
            let info = inner
                .plan_statement(sql.clone())
                .await
                .map_err(|e| DataFusionError::External(Box::new(e)))?;
            // `FlightInfo.ordered` tells us whether the endpoints are in the
            // order the rows should be returned. This connector redeems them
            // sequentially in advertised order, which is the right thing when
            // the server says they are ordered — and meaningless when it does
            // not, because then the split across endpoints is arbitrary.
            //
            // That only threatens *correctness* when the rows' order is part
            // of the answer, and federation pushes `ORDER BY` down to the
            // remote and drops the local `SortExec` when it does. So the SQL
            // is parsed — lazily, only in the one case that can go wrong — and
            // an order-sensitive query over an unordered multi-endpoint result
            // is refused rather than answered in partition order.
            if !info.ordered && info.endpoint.len() > 1 && statement_orders_rows(&sql) {
                return Err(DataFusionError::External(Box::new(
                    DataglotError::federation(format!(
                        "flightsql catalog '{}': the server split this result across {} \
                         endpoints without advertising an order between them \
                         (`FlightInfo.ordered` is false), and the query's `ORDER BY` was \
                         pushed down to it. Returning the endpoints back to back would \
                         order rows by partition, not by the sort key.",
                        inner.config.name,
                        info.endpoint.len()
                    )),
                )));
            }
            let endpoints = info.endpoint;
            let streams = stream::iter(endpoints.into_iter().map(Ok::<_, DataFusionError>))
                .and_then(move |endpoint| {
                    let inner = Arc::clone(&inner);
                    let target = Arc::clone(&target);
                    async move {
                        inner
                            .fetch_endpoint(endpoint, target)
                            .await
                            .map_err(|e| DataFusionError::External(Box::new(e)))
                    }
                })
                .try_flatten();
            Ok::<_, DataFusionError>(streams)
        };

        let stream = Box::pin(RecordBatchStreamAdapter::new(
            schema,
            stream::once(fut).try_flatten(),
        ));
        Ok(crate::instrument_pushdown(
            &self.inner.config.name,
            "flightsql",
            query,
            stream,
        ))
    }

    async fn table_names(&self) -> DfResult<Vec<String>> {
        // Not used by the federation pushdown path — mirroring every other
        // connector; `as_catalog_provider` is the catalog-listing surface.
        Err(DataFusionError::NotImplemented(
            "table_names not implemented".to_string(),
        ))
    }

    async fn get_table_schema(&self, table_name: &str) -> DfResult<SchemaRef> {
        // The catalog comes from the reference itself, which this connector
        // rendered — so there is no shared state to consult and no way for
        // a later listing to change the answer for a provider built earlier.
        let (catalog, schema_part, table_part) =
            Self::split_remote_ref(table_name).ok_or_else(|| {
                DataFusionError::External(Box::new(DataglotError::catalog(format!(
                    "expected a '<schema>.<table>' or '<catalog>.<schema>.<table>' \
                     reference, got: {table_name}"
                ))))
            })?;
        self.fetch_arrow_schema(catalog.as_deref(), &schema_part, &table_part)
            .await
            .map_err(|e| DataFusionError::External(Box::new(e)))
    }
}

/// Liveness probe that reuses the existing authenticated client:
/// `GetFlightInfo` on `SELECT 1` proves the endpoint is reachable, the
/// credentials are still valid and the server can plan — without
/// transferring a row (the ticket is never fetched). The error text is the
/// server's own, scrubbed of credentials (rule 12).
#[async_trait]
impl crate::health::ConnectorHealthCheck for FlightSqlConnector {
    async fn health_check(&self) -> Result<(), String> {
        self.inner
            .plan_statement("SELECT 1".to_string())
            .await
            .map(|_| ())
            .map_err(|e| e.to_string())
    }
}

// ---------------------------------------------------------------------------
// Catalog / schema providers
// ---------------------------------------------------------------------------

/// `DataFusion` [`CatalogProvider`] over a [`FlightSqlConnector`] —
/// pre-built at [`FlightSqlConnector::as_catalog_provider`] time, sync
/// afterwards.
///
/// [`CatalogProvider`]: datafusion::catalog::CatalogProvider
pub struct FlightSqlCatalog {
    /// The underlying connector's identifier — diagnostics only; the
    /// catalog's registered name is supplied by `register_catalog`.
    connector_name: String,
    /// Cached, sorted schema names.
    schema_names: Vec<String>,
    /// Pre-built schema providers, keyed by schema name.
    schemas: HashMap<String, Arc<dyn DfSchemaProvider>>,
}

impl fmt::Debug for FlightSqlCatalog {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FlightSqlCatalog")
            .field("connector", &self.connector_name)
            .field("schema_count", &self.schema_names.len())
            .finish_non_exhaustive()
    }
}

impl DfCatalogProvider for FlightSqlCatalog {
    fn schema_names(&self) -> Vec<String> {
        self.schema_names.clone()
    }

    fn schema(&self, name: &str) -> Option<Arc<dyn DfSchemaProvider>> {
        self.schemas.get(name).map(Arc::clone)
    }
}

/// `DataFusion` [`SchemaProvider`] backed by one remote namespace. Table
/// names are cached at construction; column schemas resolve lazily in
/// [`SchemaProvider::table`] (rule 13).
///
/// [`SchemaProvider`]: datafusion::catalog::SchemaProvider
/// [`SchemaProvider::table`]: datafusion::catalog::SchemaProvider::table
struct FlightSqlSchema {
    connector: Arc<FlightSqlConnector>,

    schema_name: String,
    /// Cached, sorted table names within this namespace.
    table_names: Vec<String>,
}

impl fmt::Debug for FlightSqlSchema {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FlightSqlSchema")
            .field("schema", &self.schema_name)
            .field("table_count", &self.table_names.len())
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl DfSchemaProvider for FlightSqlSchema {
    fn table_names(&self) -> Vec<String> {
        self.table_names.clone()
    }

    fn table_exist(&self, name: &str) -> bool {
        self.table_names.iter().any(|t| t == name)
    }

    async fn table(&self, name: &str) -> DfResult<Option<Arc<dyn TableProvider>>> {
        // Cheap negative path — no round trip for names that weren't listed.
        if !self.table_exist(name) {
            return Ok(None);
        }
        let provider = self
            .connector
            .table_provider(&self.schema_name, name)
            .await
            .map_err(|e| DataFusionError::External(Box::new(e)))?;
        Ok(Some(provider))
    }
}

#[cfg(test)]
mod tests {
    use arrow::array::{Int32Array, StringArray};
    use arrow::datatypes::{DataType, Field, Schema};

    use super::*;

    fn cfg() -> FlightSqlConfig {
        FlightSqlConfig::new(
            "wh",
            "grpc://flight.internal:32010",
            FlightSqlDialect::DataFusion,
        )
    }

    // -----------------------------------------------------------------
    // Dialect
    // -----------------------------------------------------------------

    #[test]
    fn every_supported_dialect_round_trips_through_its_name() {
        for dialect in [
            FlightSqlDialect::DataFusion,
            FlightSqlDialect::PostgreSql,
            FlightSqlDialect::MySql,
            FlightSqlDialect::Sqlite,
            FlightSqlDialect::DuckDb,
            FlightSqlDialect::BigQuery,
        ] {
            let parsed: FlightSqlDialect = dialect.as_str().parse().expect("name parses");
            assert_eq!(parsed, dialect);
            assert_eq!(dialect.to_string(), dialect.as_str());
            // Every listed dialect must be in the user-facing error text.
            assert!(
                SUPPORTED_DIALECTS.contains(dialect.as_str()),
                "{dialect} missing from SUPPORTED_DIALECTS"
            );
        }
    }

    #[test]
    fn dialect_parsing_is_case_and_whitespace_insensitive() {
        assert_eq!(
            "  DataFusion \n".parse::<FlightSqlDialect>().unwrap(),
            FlightSqlDialect::DataFusion
        );
    }

    /// A server name is not a dialect. Naming one points the operator at
    /// `datafusion` instead of silently picking a near-miss.
    #[test]
    fn server_names_are_rejected_with_the_dialect_to_use() {
        for name in ["influxdb3", "sail", "ballista", "roapi", "dataglot"] {
            let err = name.parse::<FlightSqlDialect>().unwrap_err().to_string();
            assert!(
                err.contains("use 'datafusion'"),
                "{name} should point at datafusion, got: {err}"
            );
        }
    }

    #[test]
    fn dialects_datafusion_does_not_ship_are_refused_by_name() {
        let dremio = "dremio"
            .parse::<FlightSqlDialect>()
            .unwrap_err()
            .to_string();
        assert!(dremio.contains("postgresql"), "got: {dremio}");
        let mssql = "mssql".parse::<FlightSqlDialect>().unwrap_err().to_string();
        assert!(mssql.contains("no MS SQL"), "got: {mssql}");
        let unknown = "wat".parse::<FlightSqlDialect>().unwrap_err().to_string();
        assert!(unknown.contains(SUPPORTED_DIALECTS), "got: {unknown}");
    }

    /// The metadata probes are hand-built, so identifiers have to be quoted
    /// the way the configured dialect expects — and an embedded quote must
    /// not break out of the identifier.
    #[test]
    fn identifiers_are_quoted_per_dialect() {
        assert_eq!(FlightSqlDialect::PostgreSql.quote("users"), "\"users\"");
        assert_eq!(FlightSqlDialect::MySql.quote("users"), "`users`");
        assert_eq!(
            FlightSqlDialect::PostgreSql.quote("we\"ird"),
            "\"we\"\"ird\""
        );
    }

    // -----------------------------------------------------------------
    // Config
    // -----------------------------------------------------------------

    #[test]
    fn plaintext_and_tls_schemes_map_onto_tonic_uris() {
        for (endpoint, tls, uri) in [
            ("grpc://h:1", false, "http://h:1"),
            ("grpc+tcp://h:1", false, "http://h:1"),
            ("http://h:1", false, "http://h:1"),
            ("grpc+tls://h:1", true, "https://h:1"),
            ("https://h:1", true, "https://h:1"),
        ] {
            let parsed = Transport::parse(endpoint).expect("scheme parses");
            assert_eq!(parsed.uri, uri, "uri for {endpoint}");
            assert_eq!(parsed.tls, tls, "tls for {endpoint}");

            let mut c = cfg();
            c.endpoint = endpoint.to_string();
            assert_eq!(c.uses_tls().unwrap(), tls, "config tls for {endpoint}");
            c.validate().expect("scheme validates");
        }
    }

    /// The URI and its TLS posture come from **one** parse, so a followed
    /// result location can never inherit the catalog endpoint's posture.
    #[test]
    fn transport_tls_follows_the_uri_it_was_parsed_from() {
        let plaintext_catalog = Transport::parse("grpc://coordinator:1").unwrap();
        assert!(!plaintext_catalog.tls);
        let tls_replica = Transport::parse("grpc+tls://replica:2").unwrap();
        assert!(tls_replica.tls, "the replica's own scheme decides");
        assert_eq!(tls_replica.uri, "https://replica:2");
    }

    /// Flight schemes `tonic` cannot dial are refused here rather than
    /// handed over to produce an opaque transport error — and the refusal
    /// never echoes the scheme back. On an advertised location that is
    /// remote-supplied text, so a server can reflect a credential into it
    /// (`hunter2://host`) and read it back out of the operator's error.
    #[test]
    fn unsupported_flight_schemes_are_refused_without_echoing_the_scheme() {
        for uri in ["grpc+unix:///tmp/f.sock", "ftp://h:1", "hunter2://h:1"] {
            let err = Transport::parse(uri).unwrap_err();
            assert!(err.contains("unsupported endpoint scheme"), "{uri}: {err}");
            assert!(
                err.contains("grpc://"),
                "the allowed schemes are what the operator needs: {err}"
            );
        }
        assert!(
            !Transport::parse("hunter2://h:1")
                .unwrap_err()
                .contains("hunter2"),
            "a reflected credential must not come back in the refusal"
        );
        assert!(Transport::parse("h:1").unwrap_err().contains("no scheme"));
        assert!(
            Transport::parse("grpc://").unwrap_err().contains("host"),
            "an empty host is refused"
        );
        // The scheme is judged before the rest of the URI, so an
        // unsupported scheme reports the useful thing even when the URI
        // also carries a path.
        assert!(Transport::parse("grpc+unix:///tmp/f.sock")
            .unwrap_err()
            .contains("unsupported endpoint scheme"));
    }

    #[test]
    fn an_unknown_or_missing_scheme_is_a_config_error() {
        let mut c = cfg();
        c.endpoint = "ftp://h:1".to_string();
        assert!(c
            .validate()
            .unwrap_err()
            .to_string()
            .contains("unsupported endpoint scheme"));

        let mut c = cfg();
        c.endpoint = "flight.internal:32010".to_string();
        assert!(c.validate().unwrap_err().to_string().contains("no scheme"));

        let mut c = cfg();
        c.endpoint = "   ".to_string();
        assert!(c
            .validate()
            .unwrap_err()
            .to_string()
            .contains("`endpoint` is required"));
    }

    /// TLS-only options on a plaintext endpoint are a mistake that would
    /// otherwise be silently ignored — and silently unencrypted.
    #[test]
    fn tls_options_on_a_plaintext_endpoint_are_refused() {
        let mut c = cfg();
        c.tls_ca_file = Some(PathBuf::from("/etc/ca.pem"));
        assert!(c
            .validate()
            .unwrap_err()
            .to_string()
            .contains("tls_ca_file"));

        // …unless TLS locations may be followed, where the trust root is for
        // the *advertised* endpoint rather than this one.
        let mut c = cfg();
        c.tls_ca_file = Some(PathBuf::from("/etc/ca.pem"));
        c.follow_endpoint_locations = true;
        c.validate()
            .expect("a trust root is meaningful when TLS locations may be followed");

        let mut c = cfg();
        c.tls_domain = Some("flight.internal".to_string());
        assert!(c.validate().unwrap_err().to_string().contains("tls_domain"));

        // Both are fine on a TLS endpoint.
        let mut c = cfg();
        c.endpoint = "grpc+tls://h:1".to_string();
        c.tls_ca_file = Some(PathBuf::from("/etc/ca.pem"));
        c.tls_domain = Some("h".to_string());
        c.validate()
            .expect("TLS options validate on a TLS endpoint");
    }

    #[test]
    fn handshake_requires_basic_credentials() {
        let mut c = cfg();
        c.handshake = true;
        assert!(c.validate().unwrap_err().to_string().contains("handshake"));

        c.auth = FlightSqlAuth::Basic {
            username: "svc".to_string(),
            password_env: "WH_PASSWORD".to_string(),
        };
        c.validate().expect("handshake validates with Basic");
    }

    #[test]
    fn zero_timeouts_are_refused() {
        let mut c = cfg();
        c.connect_timeout_secs = 0;
        assert!(c
            .validate()
            .unwrap_err()
            .to_string()
            .contains("connect_timeout_secs"));

        let mut c = cfg();
        c.request_timeout_secs = Some(0);
        assert!(c
            .validate()
            .unwrap_err()
            .to_string()
            .contains("request_timeout_secs"));
    }

    /// Rule 12: a `Debug` render is safe to log. The config holds only
    /// env-var *names*, and the resolved secret is behind [`Secret`].
    #[test]
    fn debug_output_carries_no_credential() {
        let mut c = cfg();
        c.auth = FlightSqlAuth::Basic {
            username: "svc".to_string(),
            password_env: "WH_PASSWORD".to_string(),
        };
        let rendered = format!("{c:?}");
        assert!(rendered.contains("WH_PASSWORD"), "env var name is config");
        assert!(rendered.contains("svc"), "username is config");

        let secret = Secret("hunter2".to_string());
        assert_eq!(format!("{secret:?}"), "[redacted]");
        assert!(!format!("{:?}", vec![secret]).contains("hunter2"));
    }

    #[test]
    fn secrets_are_scrubbed_out_of_remote_error_text() {
        let secrets = vec![Secret("hunter2".to_string()), Secret(String::new())];
        let scrubbed = scrub_with("server said: token=hunter2 invalid", &secrets);
        assert_eq!(scrubbed, "server said: token=[redacted] invalid");
        // An empty secret must not turn every gap into [redacted].
        assert!(!scrub_with("abc", &secrets).contains("[redacted]"));
    }

    // -----------------------------------------------------------------
    // Endpoint-location policy
    // -----------------------------------------------------------------

    #[test]
    fn authority_is_extracted_scheme_and_path_insensitively() {
        let authority = |uri: &str| Transport::parse(uri).ok().map(|t| t.authority);
        assert_eq!(authority("grpc://Host:32010"), Some("host:32010".into()));
        assert_eq!(
            authority("grpc+tls://host:32010/"),
            Some("host:32010".into()),
            "a trailing slash is tolerated and dropped"
        );
        assert_eq!(authority("host:32010"), None, "no scheme, no authority");
        assert_eq!(
            authority("grpc://host:32010/path"),
            None,
            "a path is refused outright, so there is no transport to ask"
        );
    }

    // -----------------------------------------------------------------
    // Ticket routing
    // -----------------------------------------------------------------

    fn route(locations: &[&str]) -> Result<TicketRoute, String> {
        let owned: Vec<String> = locations.iter().map(|s| (*s).to_string()).collect();
        let ours = Transport::parse("grpc://coordinator:1").expect("ours parses");
        route_for(&owned, Some(&ours))
    }

    #[test]
    fn no_location_or_the_reuse_sentinel_means_the_current_connection() {
        assert_eq!(route(&[]).unwrap(), TicketRoute::SameChannel);
        assert_eq!(route(&[""]).unwrap(), TicketRoute::SameChannel);
        // The Flight spec's "redeem on the connection you already have"
        // sentinel is not a dialable URI and must never be treated as
        // foreign.
        assert_eq!(
            route(&["arrow-flight-reuse-connection://?"]).unwrap(),
            TicketRoute::SameChannel
        );
    }

    #[test]
    fn a_location_naming_the_configured_server_is_the_current_connection() {
        assert_eq!(
            route(&["grpc://Coordinator:1"]).unwrap(),
            TicketRoute::SameChannel,
            "authority comparison is case-insensitive and scheme-agnostic"
        );
        assert_eq!(
            route(&["grpc+tcp://coordinator:1"]).unwrap(),
            TicketRoute::SameChannel
        );
    }

    /// A reusable route always wins. Otherwise an endpoint that offers our
    /// own server *and* a replica would either send credentials to the
    /// replica or be refused outright, both for no reason.
    #[test]
    fn a_reusable_location_is_preferred_over_a_foreign_one() {
        assert_eq!(
            route(&["grpc://replica:2", "grpc://coordinator:1"]).unwrap(),
            TicketRoute::SameChannel
        );
        assert_eq!(
            route(&["grpc://replica:2", "arrow-flight-reuse-connection://?"]).unwrap(),
            TicketRoute::SameChannel
        );
    }

    #[test]
    fn a_purely_foreign_location_is_reported_with_its_own_transport() {
        let TicketRoute::Foreign(transport) = route(&["grpc+tls://replica:2"]).unwrap() else {
            panic!("expected a foreign route");
        };
        assert_eq!(transport.uri, "https://replica:2");
        assert!(transport.tls, "the replica's scheme decides its posture");
    }

    #[test]
    fn unusable_locations_surface_as_an_error_rather_than_a_silent_fallback() {
        let err = route(&["grpc+unix:///tmp/f.sock"]).unwrap_err();
        assert!(err.contains("unsupported endpoint scheme"), "{err}");
        // …but a usable sibling still wins.
        assert!(matches!(
            route(&["grpc+unix:///tmp/f.sock", "grpc://coordinator:1"]).unwrap(),
            TicketRoute::SameChannel
        ));
    }

    // -----------------------------------------------------------------
    // Metadata parsing
    // -----------------------------------------------------------------

    /// Fold one batch, returning everything the callers judge on.
    fn fold(
        batch: &RecordBatch,
        schema_col: &str,
        table_col: &str,
    ) -> (Listing, Provenance, bool, usize) {
        let mut sink = ListingSink::default();
        collect_listing(batch, "table_catalog", schema_col, table_col, &mut sink);
        (
            sink.listing,
            sink.provenance,
            sink.unreadable_catalog,
            sink.schemaless,
        )
    }

    fn listing_batch(schemas: Vec<Option<&str>>, tables: Vec<Option<&str>>) -> RecordBatch {
        let schema = Arc::new(Schema::new(vec![
            Field::new("table_catalog", DataType::Utf8, true),
            Field::new("table_schema", DataType::Utf8, true),
            Field::new("table_name", DataType::Utf8, true),
            Field::new("extra", DataType::Int32, true),
        ]));
        let rows = schemas.len();
        RecordBatch::try_new(
            schema,
            vec![
                Arc::new(StringArray::from(vec![None::<&str>; rows])),
                Arc::new(StringArray::from(schemas)),
                Arc::new(StringArray::from(tables)),
                Arc::new(Int32Array::from(vec![0; rows])),
            ],
        )
        .unwrap()
    }

    #[test]
    fn listing_folds_rows_into_schema_to_tables_and_ignores_extra_columns() {
        let batch = listing_batch(
            vec![Some("public"), Some("public"), Some("ops")],
            vec![Some("users"), Some("orders"), Some("audit")],
        );
        let (listing, _, _, _) = fold(&batch, "table_schema", "table_name");
        assert_eq!(listing.len(), 2);
        assert_eq!(
            listing["public"].iter().cloned().collect::<Vec<_>>(),
            vec!["orders".to_string(), "users".to_string()],
            "tables are de-duplicated and sorted"
        );
        assert_eq!(listing["ops"].len(), 1);
    }

    #[test]
    fn listing_skips_null_rows_and_unknown_shapes() {
        let batch = listing_batch(vec![Some("public"), None], vec![None, Some("orders")]);
        let (listing, _, _, _) = fold(&batch, "table_schema", "table_name");
        assert!(listing.is_empty(), "null rows contribute nothing");

        // A batch without the expected columns lists as empty rather than
        // erroring: the operator sees an empty catalog, not a boot failure.
        let (listing, _, _, _) = fold(&batch, "db_schema_name", "table_name");
        assert!(listing.is_empty());
    }

    #[test]
    fn unimplemented_is_detected_for_the_information_schema_fallback() {
        let unimplemented = FlightError::Tonic(Box::new(tonic::Status::unimplemented("GetTables")));
        assert!(is_unimplemented(&unimplemented));
        assert!(is_unimplemented(&FlightError::NotYetImplemented(
            "GetTables".to_string()
        )));
        // Anything else must propagate — a fallback that swallows a real
        // failure would report an empty catalog for an unhealthy server.
        assert!(!is_unimplemented(&FlightError::Tonic(Box::new(
            tonic::Status::unauthenticated("bad token")
        ))));
        assert!(!is_unimplemented(&FlightError::ProtocolError(
            "bad".to_string()
        )));
    }

    // -----------------------------------------------------------------
    // Metadata parsing — encodings
    // -----------------------------------------------------------------

    /// Servers answer metadata in whatever string encoding they like.
    /// A bare downcast would turn `LargeUtf8` into an empty catalog.
    #[test]
    fn listing_reads_metadata_columns_in_any_string_encoding() {
        use arrow::array::{DictionaryArray, LargeStringArray};
        use arrow::datatypes::Int32Type;

        let schema = Arc::new(Schema::new(vec![
            Field::new("table_catalog", DataType::LargeUtf8, true),
            Field::new("table_schema", DataType::LargeUtf8, true),
            Field::new(
                "table_name",
                DataType::Dictionary(Box::new(DataType::Int32), Box::new(DataType::Utf8)),
                true,
            ),
        ]));
        let names: DictionaryArray<Int32Type> = vec!["users", "orders"].into_iter().collect();
        let batch = RecordBatch::try_new(
            schema,
            vec![
                Arc::new(LargeStringArray::from(vec!["prod", "prod"])),
                Arc::new(LargeStringArray::from(vec!["public", "public"])),
                Arc::new(names),
            ],
        )
        .unwrap();

        let (listing, provenance, _, _) = fold(&batch, "table_schema", "table_name");
        assert_eq!(
            listing["public"].iter().cloned().collect::<Vec<_>>(),
            vec!["orders".to_string(), "users".to_string()]
        );
        assert_eq!(
            provenance["public"].iter().collect::<Vec<_>>(),
            vec![&Some("prod".to_string())],
            "provenance is read through the same encodings as the rest"
        );
    }

    /// The schema and table columns are required on the same reasoning as
    /// the catalog one: the metadata call succeeded, so no fallback runs, and
    /// a batch that silently contributes nothing hands the operator a
    /// catalog that looks complete and is not.
    #[test]
    fn a_metadata_response_with_unreadable_listing_columns_is_refused() {
        // Right column names, wrong shape — a struct cannot be cast to Utf8.
        let schema = Arc::new(Schema::new(vec![
            Field::new("table_catalog", DataType::Utf8, true),
            Field::new("table_schema", DataType::Utf8, true),
            Field::new("table_name", DataType::Int32, true),
        ]));
        let batch = RecordBatch::try_new(
            schema,
            vec![
                Arc::new(StringArray::from(vec![Some("prod")])),
                Arc::new(StringArray::from(vec![Some("public")])),
                Arc::new(Int32Array::from(vec![7])),
            ],
        )
        .unwrap();
        let mut sink = ListingSink::default();
        collect_listing(
            &batch,
            "table_catalog",
            "table_schema",
            "nonexistent_column",
            &mut sink,
        );
        assert!(
            sink.unreadable_listing,
            "a batch whose listing columns cannot be read is malformed, not empty"
        );
        assert!(sink.listing.is_empty());

        // An empty batch is not malformed: there is nothing in it to read.
        let empty = RecordBatch::new_empty(Arc::new(Schema::new(vec![Field::new(
            "other",
            DataType::Utf8,
            true,
        )])));
        let mut sink = ListingSink::default();
        collect_listing(
            &empty,
            "table_catalog",
            "table_schema",
            "table_name",
            &mut sink,
        );
        assert!(!sink.unreadable_listing, "no rows, nothing to read");
    }

    /// The catalog column is required, not optional. Reading a response that
    /// lacks one as "every row unqualified" would disable the ambiguity
    /// check precisely when provenance cannot be established — so a
    /// multi-catalog server missing the column would collapse two tables
    /// into one entry and resolve it against its default.
    #[test]
    fn a_metadata_response_without_a_readable_catalog_column_is_refused() {
        let schema = Arc::new(Schema::new(vec![
            Field::new("table_schema", DataType::Utf8, true),
            Field::new("table_name", DataType::Utf8, true),
        ]));
        let batch = RecordBatch::try_new(
            schema,
            vec![
                Arc::new(StringArray::from(vec![Some("public")])),
                Arc::new(StringArray::from(vec![Some("users")])),
            ],
        )
        .unwrap();
        let (listing, _, unreadable, _) = fold(&batch, "table_schema", "table_name");
        assert!(
            unreadable,
            "the caller must be told it cannot judge catalogs"
        );
        assert!(
            listing.is_empty(),
            "and nothing is listed from a response it cannot judge"
        );

        // An empty batch is not a malformed one: there is nothing to judge.
        let empty = RecordBatch::new_empty(Arc::new(Schema::new(vec![
            Field::new("table_schema", DataType::Utf8, true),
            Field::new("table_name", DataType::Utf8, true),
        ])));
        let (_, _, unreadable, _) = fold(&empty, "table_schema", "table_name");
        assert!(!unreadable, "no rows, nothing to establish provenance for");
    }

    // -----------------------------------------------------------------
    // Row-level listing rules
    // -----------------------------------------------------------------

    /// The table name is what is being listed, so a row without one is
    /// malformed — not an empty row to skip. The metadata call succeeded, so
    /// no fallback runs and the operator would get a partial catalog that
    /// looks complete.
    #[test]
    fn a_row_with_no_table_name_makes_the_response_malformed() {
        let batch = qualified_batch_with_nulls(&[
            (Some("prod"), Some("public"), Some("users")),
            (Some("prod"), Some("public"), None),
        ]);
        // `fold` reports the *catalog* flag; this is the listing one, so
        // the sink is read directly.
        let mut sink = ListingSink::default();
        collect_listing(
            &batch,
            "table_catalog",
            "table_schema",
            "table_name",
            &mut sink,
        );
        assert_eq!(
            sink.malformed_rows.iter().collect::<Vec<_>>(),
            vec![&Some("public".to_string())],
            "the row is recorded under its own schema, so the caller can scope it"
        );
        assert!(
            !sink.unreadable_listing,
            "the columns were readable; it is the row that named nothing"
        );
        assert_eq!(
            sink.schemaless, 0,
            "it is not the schema-less case: that row had a schema"
        );
        assert_eq!(
            sink.listing["public"].len(),
            1,
            "the readable row was still folded, but the caller refuses anyway"
        );
    }

    /// A schema-less row is refused only when there is nowhere it could have
    /// belonged. With a scope configured it is outside the boundary by
    /// definition, and servers that ignore `db_schema_filter_pattern` send
    /// such rows routinely — failing discovery on them would let a table
    /// outside the scope break the catalog inside it.
    #[test]
    fn schemaless_rows_are_refused_unscoped_and_dropped_when_a_scope_is_set() {
        let mut listing = Listing::new();
        listing.insert("public".to_string(), ["users".to_string()].into());

        let err = judge_schemaless(&listing, 2, false, "remote")
            .unwrap_err()
            .to_string();
        assert!(err.contains("2 table(s) with no schema name"), "{err}");
        assert!(
            err.contains("looks complete"),
            "the error says why silence would be worse: {err}"
        );

        judge_schemaless(&listing, 2, true, "remote")
            .expect("outside the configured scope, so outside this catalog");

        // No such rows at all is fine either way.
        judge_schemaless(&listing, 0, false, "remote").expect("nothing to judge");
    }

    // -----------------------------------------------------------------
    // Endpoint ordering
    // -----------------------------------------------------------------

    /// The guard fires only for queries whose answer depends on row order,
    /// so it must read a top-level `ORDER BY` and nothing else.
    #[test]
    fn only_a_top_level_order_by_makes_a_statement_order_sensitive() {
        assert!(statement_orders_rows("SELECT id FROM t ORDER BY id"));
        assert!(statement_orders_rows(
            "SELECT id FROM t ORDER BY id DESC LIMIT 10"
        ));
        assert!(!statement_orders_rows("SELECT id FROM t"));
        assert!(!statement_orders_rows("SELECT id FROM t WHERE id > 1"));

        // A subquery's ordering constrains that subquery, not the rows
        // handed back, so it must not cost the caller a refusal.
        assert!(!statement_orders_rows(
            "SELECT id FROM (SELECT id FROM t ORDER BY id) AS s"
        ));

        // Unreadable text is treated as order-sensitive: guessing "no" on
        // SQL we cannot parse is the unsafe direction.
        assert!(statement_orders_rows("this is not sql at all ))("));
    }

    // -----------------------------------------------------------------
    // Location sentinel
    // -----------------------------------------------------------------

    /// URI schemes are case-insensitive, and a prefix test both misses a
    /// differently-cased sentinel and accepts an unrelated scheme that
    /// merely starts with the same letters.
    #[test]
    fn the_reuse_sentinel_is_matched_as_a_scheme_not_a_prefix() {
        for uri in [
            "arrow-flight-reuse-connection://?",
            "Arrow-Flight-Reuse-Connection://?",
            "ARROW-FLIGHT-REUSE-CONNECTION://",
        ] {
            assert!(is_reuse_sentinel(uri), "{uri}");
            assert!(matches!(
                route_for(&[uri.to_string()], None).unwrap(),
                TicketRoute::SameChannel
            ));
        }
        assert!(
            !is_reuse_sentinel("arrow-flight-reuse-connection-elsewhere://host:1"),
            "an unrelated scheme that starts with the same letters is not the sentinel"
        );
        assert!(
            !is_reuse_sentinel("arrow-flight-reuse-connection"),
            "a bare word with no scheme separator is not a URI"
        );
    }

    // -----------------------------------------------------------------
    // Scrubbing
    // -----------------------------------------------------------------

    /// `url` does more to a host than lowercase it. A password containing a
    /// non-ASCII character, reflected back by a server as a host, is
    /// IDNA-converted — and punycode is reversible, so the credential would
    /// be readable in the refusal. The converted form is registered as a
    /// secret of its own, which closes every rendering path including
    /// connection errors raised beneath us.
    #[test]
    fn a_secret_that_idna_normalises_is_registered_in_its_converted_form() {
        let converted = normalised_host("päss").expect("a host-legal secret converts");
        assert_eq!(converted.expose(), "xn--pss-qla");
        assert_eq!(
            scrub_with("dialling http://xn--pss-qla:443 failed", &[converted]),
            "dialling http://[redacted]:443 failed"
        );

        // Case-only differences are `redact`'s job, not this one — no point
        // registering a second secret that the fold already matches.
        assert!(normalised_host("Hunter2").is_none());
        assert!(normalised_host("hunter2").is_none());

        // Nothing to register for a secret that cannot appear in a host.
        assert!(normalised_host("").is_none());
        assert!(normalised_host("has spaces").is_none());
    }

    /// Text reaching `scrub` has usually been normalised first: `url`
    /// lowercases a host, so a password reflected into one comes back in a
    /// different casing than the one this connector holds.
    #[test]
    fn scrubbing_survives_the_case_folding_a_url_parser_applies() {
        let secrets = vec![Secret("Hunter2".to_string())];
        assert_eq!(
            scrub_with("dialling https://hunter2:443 failed", &secrets),
            "dialling https://[redacted]:443 failed",
            "the host was lowercased on the way in; the secret was not"
        );
        // Every occurrence, not just the first, and in any casing.
        assert_eq!(
            scrub_with("HUNTER2 then hunter2 then Hunter2", &secrets),
            "[redacted] then [redacted] then [redacted]"
        );
        // Text with no secret in it is returned intact.
        assert_eq!(scrub_with("nothing to see", &secrets), "nothing to see");
        // An empty secret must not match everywhere and blank the message.
        assert_eq!(scrub_with("intact", &[Secret(String::new())]), "intact");
        // Multi-byte text keeps its boundaries: ASCII lowercasing preserves
        // byte length, so offsets found in the folded copy address the
        // original exactly.
        assert_eq!(
            scrub_with("héllo HUNTER2 wörld", &secrets),
            "héllo [redacted] wörld"
        );
    }

    // -----------------------------------------------------------------
    // Catalog provenance
    // -----------------------------------------------------------------

    /// A batch carrying the catalog column both metadata paths expose.
    /// Like [`qualified_batch`] but able to put a null in any column.
    fn qualified_batch_with_nulls(
        rows: &[(Option<&str>, Option<&str>, Option<&str>)],
    ) -> RecordBatch {
        let schema = Arc::new(Schema::new(vec![
            Field::new("table_catalog", DataType::Utf8, true),
            Field::new("table_schema", DataType::Utf8, true),
            Field::new("table_name", DataType::Utf8, true),
        ]));
        RecordBatch::try_new(
            schema,
            vec![
                Arc::new(StringArray::from(
                    rows.iter().map(|r| r.0).collect::<Vec<_>>(),
                )),
                Arc::new(StringArray::from(
                    rows.iter().map(|r| r.1).collect::<Vec<_>>(),
                )),
                Arc::new(StringArray::from(
                    rows.iter().map(|r| r.2).collect::<Vec<_>>(),
                )),
            ],
        )
        .unwrap()
    }

    fn qualified_batch(rows: &[(Option<&str>, &str, &str)]) -> RecordBatch {
        let schema = Arc::new(Schema::new(vec![
            Field::new("table_catalog", DataType::Utf8, true),
            Field::new("table_schema", DataType::Utf8, true),
            Field::new("table_name", DataType::Utf8, true),
        ]));
        RecordBatch::try_new(
            schema,
            vec![
                Arc::new(StringArray::from(
                    rows.iter().map(|r| r.0).collect::<Vec<_>>(),
                )),
                Arc::new(StringArray::from(
                    rows.iter().map(|r| Some(r.1)).collect::<Vec<_>>(),
                )),
                Arc::new(StringArray::from(
                    rows.iter().map(|r| Some(r.2)).collect::<Vec<_>>(),
                )),
            ],
        )
        .unwrap()
    }

    /// Discovery never *adopts* a catalog — `catalog` is configuration. But
    /// an omitted `CommandGetTables.catalog` means "do not narrow", so a
    /// multi-catalog server answers with everything, and two rows agreeing
    /// on `schema.table` collapse into one entry that the emitted two-part
    /// reference resolves against the server default. That must be loud.
    #[test]
    fn a_listing_spanning_two_catalogs_is_refused_when_none_is_configured() {
        let batch = qualified_batch(&[
            (Some("prod"), "public", "users"),
            (Some("staging"), "public", "users"),
        ]);
        let (listing, provenance, _, _) = fold(&batch, "table_schema", "table_name");
        assert_eq!(
            listing["public"].len(),
            1,
            "the two rows really do collapse — that is the hazard"
        );

        let err = judge_catalogs(&provenance, None, "remote")
            .unwrap_err()
            .to_string();
        assert!(err.contains("prod") && err.contains("staging"), "{err}");
        assert!(err.contains("set `catalog`"), "the fix is named: {err}");

        // A named catalog mixed with unqualified rows is the same hazard:
        // the unqualified ones may live somewhere else entirely.
        let mixed = qualified_batch(&[
            (Some("prod"), "public", "users"),
            (None, "public", "orders"),
        ]);
        let (_, provenance, _, _) = fold(&mixed, "table_schema", "table_name");
        let err = judge_catalogs(&provenance, None, "remote")
            .unwrap_err()
            .to_string();
        assert!(err.contains("<unqualified>"), "{err}");
    }

    /// One catalog — named or not — is the documented "resolves against the
    /// server default" case, not an error. Refusing it would break every
    /// single-catalog server, which is nearly all of them.
    #[test]
    fn a_listing_from_one_catalog_is_accepted_unqualified() {
        for rows in [
            vec![(Some("datafusion"), "public", "users")],
            vec![(None, "public", "users")],
        ] {
            let (_, provenance, _, _) = fold(&qualified_batch(&rows), "table_schema", "table_name");
            judge_catalogs(&provenance, None, "remote").expect("one catalog is unambiguous");
        }
    }

    /// With `catalog` set, every reference is qualified with it. A row from
    /// a different named catalog would be listed under a name that does not
    /// address it, so the server ignoring the filter has to be loud too.
    #[test]
    fn configured_catalog_refuses_rows_from_another_one_but_tolerates_unqualified() {
        let batch = qualified_batch(&[
            (Some("prod"), "public", "users"),
            (Some("staging"), "public", "orders"),
        ]);
        let (_, provenance, _, _) = fold(&batch, "table_schema", "table_name");
        let err = judge_catalogs(&provenance, Some("prod"), "remote")
            .unwrap_err()
            .to_string();
        assert!(err.contains("staging"), "{err}");
        assert!(
            !err.contains("'prod'\n"),
            "the configured one is not foreign"
        );

        // Rows the server left unqualified are fine: that is a server which
        // simply does not populate the column.
        let batch = qualified_batch(&[
            (Some("prod"), "public", "users"),
            (None, "public", "orders"),
        ]);
        let (_, provenance, _, _) = fold(&batch, "table_schema", "table_name");
        judge_catalogs(&provenance, Some("prod"), "remote")
            .expect("unqualified rows do not contradict the configured catalog");
    }

    /// Scope is applied before the judgement, so a server that ignores or
    /// widens `db_schema_filter_pattern` cannot make a scoped listing look
    /// ambiguous through rows the scope drops.
    #[test]
    fn catalogs_seen_only_outside_the_scope_do_not_make_a_listing_ambiguous() {
        let batch = qualified_batch(&[
            (Some("prod"), "public", "users"),
            (Some("staging"), "other", "users"),
        ]);
        let (_, mut provenance, _, _) = fold(&batch, "table_schema", "table_name");
        assert!(
            judge_catalogs(&provenance, None, "remote").is_err(),
            "unscoped, both catalogs count"
        );
        provenance.retain(|schema, _| schema == "public");
        judge_catalogs(&provenance, None, "remote")
            .expect("the dropped schema's catalog is not this listing's problem");
    }

    // -----------------------------------------------------------------
    // Schema scoping
    // -----------------------------------------------------------------

    /// `db_schema_filter_pattern` is a SQL wildcard pattern. A scope
    /// containing `_` or `%` must not be sent as one, or the server widens
    /// the scope for us (`tenant_1` would also match `tenant-1`).
    #[test]
    fn a_schema_scope_with_wildcards_is_not_sent_as_a_server_side_pattern() {
        // The real function, not a copy of its condition: a test that
        // restated the predicate would have gone on passing when the
        // production one changed.
        let hint = |scope: &str| schema_filter_hint(Some(scope));
        assert_eq!(
            hint("public"),
            Some("public".to_string()),
            "plain name narrows"
        );
        assert_eq!(
            hint("tenant_1"),
            None,
            "underscore is a single-char wildcard"
        );
        assert_eq!(hint("sales%"), None, "percent is a multi-char wildcard");
        assert_eq!(
            hint(r"tenant\east"),
            None,
            "a server treating backslash as the pattern escape would read this as \
             `tenanteast` and never return the real schema — and the exact retain \
             cannot recover rows that never arrived"
        );
        assert_eq!(schema_filter_hint(None), None, "no scope, no hint");
    }

    /// A malformed row is judged against the configured scope, like every
    /// other listing decision — a server that ignores
    /// `db_schema_filter_pattern` sends rows from outside the boundary, and
    /// one of those must not fail discovery inside it.
    #[test]
    fn malformed_rows_are_scoped_unless_they_name_no_schema_at_all() {
        let in_scope: BTreeSet<Option<String>> = [Some("public".to_string())].into();
        let out_of_scope: BTreeSet<Option<String>> = [Some("ops".to_string())].into();
        let unplaceable: BTreeSet<Option<String>> = [None].into();

        // Unscoped, any malformed row is fatal.
        assert!(judge_malformed_rows(&in_scope, None, "remote").is_err());
        assert!(judge_malformed_rows(&out_of_scope, None, "remote").is_err());

        // Scoped, only the ones inside the boundary are.
        let err = judge_malformed_rows(&in_scope, Some("public"), "remote")
            .unwrap_err()
            .to_string();
        assert!(err.contains("1 row(s) naming no table"), "{err}");
        judge_malformed_rows(&out_of_scope, Some("public"), "remote")
            .expect("a malformed row in a schema this catalog does not expose is not its problem");

        // A row naming neither schema nor table cannot be placed at all, so
        // no scope excuses it.
        assert!(judge_malformed_rows(&unplaceable, Some("public"), "remote").is_err());

        // Nothing malformed is fine either way.
        judge_malformed_rows(&BTreeSet::new(), Some("public"), "remote").expect("nothing to judge");
    }

    /// Discovery errors quote *remote* metadata — `judge_catalogs` names the
    /// catalogs it saw — so the fallback path's errors are scrubbed like the
    /// metadata path's, and the error keeps its kind while doing it.
    #[test]
    fn scrubbing_an_error_preserves_its_kind() {
        let secrets = vec![Secret("t0ken".to_string())];
        let scrubbed = scrub_with(
            &DataglotError::catalog("listed catalogs: prod, t0ken").to_string(),
            &secrets,
        );
        assert!(scrubbed.contains("[redacted]"), "{scrubbed}");
        assert!(!scrubbed.contains("t0ken"), "{scrubbed}");
        assert!(
            matches!(DataglotError::catalog(scrubbed), DataglotError::Catalog(_)),
            "a catalog error stays a catalog error"
        );
    }

    // -----------------------------------------------------------------
    // Credentials in the endpoint URI
    // -----------------------------------------------------------------

    /// URI userinfo would put a password somewhere `FlightSqlConfig`
    /// promises is safe to log. Credentials belong in `auth` (rule 12).
    #[test]
    fn credentials_embedded_in_the_endpoint_are_refused() {
        for endpoint in [
            "grpc+tls://svc:secret@host:443",
            "grpc://svc@host:32010",
            "https://user:pw@host/path",
        ] {
            let mut c = cfg();
            c.endpoint = endpoint.to_string();
            let err = c.validate().unwrap_err().to_string();
            assert!(
                err.contains("credentials in the URI"),
                "{endpoint} should be refused, got: {err}"
            );
            assert!(
                !err.contains("secret") && !err.contains("pw"),
                "the refusal must not echo the credential: {err}"
            );
        }

        // An endpoint carrying a path is refused, so `Debug` shows a
        // placeholder rather than guessing which part was sensitive.
        assert_eq!(
            safe_endpoint_display("grpc://host:32010/path@v2"),
            "[redacted: unparsable endpoint]"
        );
    }

    /// Defence in depth: a config built by hand never ran `validate`, so
    /// `Debug` renders only what [`Transport::parse`] accepts, and a
    /// placeholder for anything it refuses — the refused part may be the
    /// secret.
    #[test]
    fn debug_renders_only_provably_safe_endpoints() {
        let mut c = cfg();
        c.endpoint = "grpc+tls://svc:hunter2@host:443".to_string();
        let rendered = format!("{c:?}");
        assert!(!rendered.contains("hunter2"), "got: {rendered}");
        assert!(
            rendered.contains("[redacted: unparsable endpoint]"),
            "got: {rendered}"
        );

        // A clean endpoint renders in canonical form (port made explicit).
        assert_eq!(safe_endpoint_display("grpc://host:1"), "http://host:1");
        // Anything `Transport::parse` refuses renders as a placeholder: the
        // refused component may itself be the secret, so nothing is echoed.
        for hostile in [
            "grpc://svc:hunter2@host:1",
            "grpc+tls://host?token=hunter2",
            "grpc://host#hunter2",
            "svc:hunter2@host",
        ] {
            let rendered = safe_endpoint_display(hostile);
            assert_eq!(rendered, "[redacted: unparsable endpoint]", "for {hostile}");
            assert!(!rendered.contains("hunter2"), "leaked for {hostile}");
        }
    }

    /// Server-advertised locations never pass through
    /// [`FlightSqlConfig::validate`], so userinfo is refused in
    /// [`Transport::parse`] — the one place every dialable URI is built.
    /// Without that, a remote could plant a credential in our error text or
    /// debug log by advertising `grpc+tls://user:secret@host`.
    #[test]
    fn a_remote_cannot_plant_credentials_via_an_advertised_location() {
        let err = Transport::parse("grpc+tls://svc:secret@replica:2").unwrap_err();
        assert!(err.contains("credentials in the URI"), "{err}");
        assert!(
            !err.contains("secret"),
            "the refusal must not echo it: {err}"
        );

        // …and routing surfaces it without echoing the credential either.
        let locations = vec!["grpc+tls://svc:secret@replica:2".to_string()];
        let ours = Transport::parse("grpc://coordinator:1").unwrap();
        let err = route_for(&locations, Some(&ours)).unwrap_err();
        assert!(!err.contains("secret"), "routing error leaked it: {err}");
        assert!(
            !err.contains("replica"),
            "the routing error echoes no part of the location: {err}"
        );
        assert!(err.contains("unusable"), "{err}");
    }

    // -----------------------------------------------------------------
    // An endpoint is scheme + authority, and nothing else
    // -----------------------------------------------------------------

    /// Credentials hid in three different URI components across three
    /// review rounds. Rather than a fourth patch, everything but the
    /// authority is refused — which is also simply correct, since gRPC
    /// carries the method in the request, not the URI.
    #[test]
    fn an_endpoint_is_a_host_and_port_only() {
        for (endpoint, expected) in [
            ("grpc+tls://host?token=secret", "a query string"),
            ("grpc://host:1#frag", "a fragment"),
            ("grpc://host:1/v1/flight", "a path"),
        ] {
            let err = Transport::parse(endpoint).unwrap_err();
            assert!(err.contains(expected), "{endpoint}: {err}");
            assert!(!err.contains("secret"), "must not echo the value: {err}");

            // Both gates agree — config load and every dialable URI.
            let mut c = cfg();
            c.endpoint = endpoint.to_string();
            assert!(c.validate().is_err(), "config must refuse {endpoint}");
            assert!(
                Transport::parse(endpoint).is_err(),
                "an advertised {endpoint} must be refused too"
            );
        }

        // A bare trailing slash is what copy-paste produces; allow it.
        Transport::parse("grpc://host:32010/").expect("a trailing slash is fine");
        let mut c = cfg();
        c.endpoint = "grpc://host:32010/".to_string();
        c.validate().expect("a trailing slash validates");
    }

    // -----------------------------------------------------------------
    // Quoted references
    // -----------------------------------------------------------------

    /// A catalog or schema may itself contain a dot, in which case the
    /// rendered reference quotes it — and a plain `splitn` would cut the
    /// identifier in half and probe the wrong table.
    #[test]
    fn a_rendered_reference_splits_on_dots_outside_quotes_only() {
        assert_eq!(
            split_quoted_reference(r#""warehouse.prod"."public"."users""#),
            vec!["warehouse.prod", "public", "users"]
        );
        assert_eq!(
            split_quoted_reference("`a.b`.`c`"),
            vec!["a.b", "c"],
            "backtick dialects too"
        );
        assert_eq!(
            split_quoted_reference(r#""we""ird"."t""#),
            vec![r#"we"ird"#, "t"],
            "a doubled quote is a literal one"
        );
        assert_eq!(
            split_quoted_reference("plain.parts"),
            vec!["plain", "parts"],
            "unquoted input is unaffected"
        );
    }

    // -----------------------------------------------------------------
    // Round-6 findings
    // -----------------------------------------------------------------

    /// A catalog reached by IP needs `tls_domain` for SNI — but a replica
    /// the server advertises has its own name, and validating the replica's
    /// certificate against the coordinator's would fail a perfectly good
    /// certificate. The override is therefore scoped to the configured
    /// endpoint; this pins the seam that decides it.
    #[test]
    fn the_sni_override_belongs_to_the_configured_endpoint_only() {
        let mut c = cfg();
        c.endpoint = "grpc+tls://10.0.0.7:443".to_string();
        c.tls_domain = Some("coordinator.example".to_string());
        c.validate()
            .expect("an SNI override validates on a TLS endpoint");
        assert_eq!(
            sni_override(&c, true),
            Some("coordinator.example"),
            "the configured endpoint uses the override"
        );
        assert_eq!(
            sni_override(&c, false),
            None,
            "a followed location keeps its own name"
        );
    }

    /// HTTP Basic is `base64(user:password)`, so a colon in the username is
    /// indistinguishable from the separator — and every receiver, ours
    /// included, splits on the first one.
    #[test]
    fn a_basic_username_containing_a_colon_is_refused() {
        let mut c = cfg();
        c.auth = FlightSqlAuth::Basic {
            username: "svc:role".to_string(),
            password_env: "WH_PASSWORD".to_string(),
        };
        let err = c.validate().unwrap_err().to_string();
        assert!(err.contains("HTTP Basic cannot represent"), "{err}");

        c.auth = FlightSqlAuth::Basic {
            username: "svc".to_string(),
            password_env: "WH_PASSWORD".to_string(),
        };
        c.validate().expect("a plain username validates");
    }

    /// `https://host` and `grpc+tls://host:443` are the same server. Without
    /// canonical ports the advertised form would be classified as foreign:
    /// refused by default, or needlessly re-dialled when following is on.
    #[test]
    fn an_implicit_default_port_compares_equal_to_the_explicit_one() {
        let implicit = Transport::parse("https://flight.example").unwrap();
        let explicit = Transport::parse("grpc+tls://flight.example:443").unwrap();
        assert_eq!(implicit.authority, explicit.authority);
        assert_eq!(implicit.authority, "flight.example:443");
        assert!(implicit.same_server(&explicit));

        let plain = Transport::parse("grpc://flight.example").unwrap();
        assert_eq!(plain.authority, "flight.example:80");
        assert_ne!(plain.authority, implicit.authority, "80 is not 443");

        // …and routing agrees, which is the point.
        let locations = vec!["grpc+tls://flight.example:443".to_string()];
        assert_eq!(
            route_for(&locations, Some(&implicit)).unwrap(),
            TicketRoute::SameChannel
        );
    }

    /// IPv6 authorities are full of colons that are not port separators —
    /// the case a hand-rolled splitter kept getting wrong, and the reason
    /// parsing is delegated to `url`.
    #[test]
    fn an_ipv6_authority_is_not_mistaken_for_a_port() {
        assert_eq!(
            Transport::parse("grpc+tls://[::1]").unwrap().authority,
            "[::1]:443"
        );
        assert_eq!(
            Transport::parse("grpc://[::1]:32010").unwrap().authority,
            "[::1]:32010"
        );
        assert!(
            Transport::parse("grpc://host:notaport").is_err(),
            "a non-numeric port is not a port"
        );
    }

    /// The quote-aware parse applies to two-part references too — a schema
    /// may contain a dot even when no catalog is configured.
    #[test]
    fn a_two_part_reference_is_parsed_quote_aware() {
        assert_eq!(
            split_quoted_reference(r#""warehouse.prod"."users""#),
            vec!["warehouse.prod", "users"]
        );
    }

    // -----------------------------------------------------------------
    // Multi-catalog ambiguity
    // -----------------------------------------------------------------

    /// A two-part dialect cannot carry a catalog in a reference, so neither
    /// configuration nor discovery may put one there. `PostgreSQL` reports
    /// its current database in `table_catalog` as a matter of course, so an
    /// unconditional adoption would turn every later probe into
    /// `database.schema.table` — which PostgreSQL rejects outright.
    #[test]
    fn only_three_part_dialects_carry_a_catalog() {
        for (dialect, three_part) in [
            (FlightSqlDialect::DataFusion, true),
            (FlightSqlDialect::DuckDb, true),
            (FlightSqlDialect::BigQuery, true),
            (FlightSqlDialect::PostgreSql, false),
            (FlightSqlDialect::MySql, false),
            (FlightSqlDialect::Sqlite, false),
        ] {
            assert_eq!(
                dialect.supports_catalog_qualification(),
                three_part,
                "{dialect}"
            );

            // Configuring one on a two-part dialect is refused at load, not
            // discovered as a stream of rejected queries.
            let mut c = FlightSqlConfig::new("wh", "grpc://h:1", dialect);
            c.catalog = Some("warehouse".to_string());
            if three_part {
                c.validate().expect("three-part dialects accept a catalog");
            } else {
                let err = c.validate().unwrap_err().to_string();
                assert!(err.contains("three-part namespace"), "{dialect}: {err}");
            }
        }
    }

    /// A provider built before discovery adopted a catalog still holds a
    /// two-part reference, so parsing must read the last two parts rather
    /// than keying off the catalog that happens to be set now.
    #[test]
    fn a_rendered_reference_parses_at_either_arity() {
        assert_eq!(split_quoted_reference("s.t").len(), 2);
        assert_eq!(split_quoted_reference("c.s.t").len(), 3);
        let last_two = |r: &str| {
            let parts = split_quoted_reference(r);
            match parts.as_slice() {
                [.., schema, table] if parts.len() <= 3 => Some((schema.clone(), table.clone())),
                _ => None,
            }
        };
        assert_eq!(last_two("s.t"), Some(("s".into(), "t".into())));
        assert_eq!(last_two("c.s.t"), Some(("s".into(), "t".into())));
        assert_eq!(last_two("t"), None, "one part names no schema");
        assert_eq!(
            last_two("a.b.c.d"),
            None,
            "four parts is not a shape we emit"
        );
    }

    /// A server whose engine has no schema namespace reports
    /// `db_schema_name = NULL`. Those rows name real tables we cannot
    /// address, and `GetTables` succeeded — so the fallback never runs and
    /// the operator would get an empty catalog with no explanation.
    #[test]
    fn a_listing_with_no_schema_names_counts_the_rows_it_had_to_drop() {
        let schema = Arc::new(Schema::new(vec![
            Field::new("table_catalog", DataType::Utf8, true),
            Field::new("db_schema_name", DataType::Utf8, true),
            Field::new("table_name", DataType::Utf8, true),
        ]));
        let batch = RecordBatch::try_new(
            schema,
            vec![
                Arc::new(StringArray::from(vec![None::<&str>, None])),
                Arc::new(StringArray::from(vec![None::<&str>, None])),
                Arc::new(StringArray::from(vec![Some("users"), Some("orders")])),
            ],
        )
        .unwrap();
        let (listing, _, _, schemaless) = fold(&batch, "db_schema_name", "table_name");
        assert!(listing.is_empty());
        assert_eq!(schemaless, 2, "both rows named a table but no schema");
    }

    /// A reference carries its own catalog, so `get_table_schema` needs no
    /// shared state to parse one — which is what makes providers from
    /// different listings independent.
    #[test]
    fn a_reference_carries_the_catalog_it_was_rendered_with() {
        let split = FlightSqlConnector::split_remote_ref;
        assert_eq!(
            split(r#""warehouse"."public"."users""#),
            Some((Some("warehouse".into()), "public".into(), "users".into()))
        );
        assert_eq!(
            split(r#""public"."users""#),
            Some((None, "public".into(), "users".into()))
        );
        assert_eq!(split("users"), None, "one part names no schema");
        assert_eq!(split("a.b.c.d"), None, "four parts is not a shape we emit");
    }
}

//! Snowflake data source connector.
//!
//! Gated behind the `snowflake` feature flag. Provides
//! [`SnowflakeConnector`] which implements `datafusion-federation`'s
//! `SQLExecutor` trait on top of [`snowflake_api::SnowflakeApi`].
//!
//! # Why this connector is smaller than the SQL siblings
//!
//! Snowflake's REST API returns **Arrow IPC natively** for `SELECT`
//! statements (`QueryResult::Arrow(Vec<RecordBatch>)`). That means
//! the executor is mostly pass-through — there are no per-type byte
//! decoders like the `tokio-postgres` and `mysql_async` connectors
//! need, because Snowflake already handed us `RecordBatch`. The work
//! left for this module is:
//!
//! - **Auth + connection lifecycle** ([`SnowflakeConnector::connect`])
//! - **Schema discovery via `INFORMATION_SCHEMA.COLUMNS`**
//!   (private helper called by [`SnowflakeConnector::table_provider`])
//! - **Type mapping** for the supported Snowflake types
//!   ([`snowflake_type_to_arrow`])
//! - **`SQLExecutor` impl** that bridges `exec()` → a
//!   `RecordBatchStream`
//!
//! # Supported types
//!
//! Numeric: `NUMBER(p, s)` family (incl. `DECIMAL`, `NUMERIC`, `INT`,
//! `BIGINT` — Snowflake stores them all as `NUMBER` under the hood)
//! → `Decimal128(p, s)`; `FLOAT` / `DOUBLE` / `REAL` → `Float64`.
//!
//! Logical / string: `BOOLEAN` → `Boolean`; `VARCHAR(n)` / `TEXT` /
//! `STRING` → `Utf8`.
//!
//! Temporal: `DATE` → `Date32`; `TIMESTAMP_NTZ` →
//! `Timestamp(Microsecond, None)`.
//!
//! Semi-structured: `VARIANT` / `OBJECT` / `ARRAY` → `Utf8`
//! (Snowflake sends these as UTF-8 JSON text over Arrow IPC).
//!
//! Binary: `BINARY` / `VARBINARY` → `Binary`.
//!
//! Anything outside this list surfaces as a typed catalog error at
//! `table_provider` time, matching the `MySQL` connector's
//! fail-loud-rather-than-silently-truncate pattern. The still-deferred
//! types (`TIME`, `TIMESTAMP_TZ`, `TIMESTAMP_LTZ`, `GEOGRAPHY`,
//! `GEOMETRY`) use scaled-int / composite Arrow encodings (or a
//! GeoJSON/WKB decision) that need more than a straight mapping —
//! tracked in.
//!
//! # Hard-rule compliance
//!
//! * Rule 1 — data flows as Arrow `RecordBatch` end-to-end. Snowflake
//!   returns Arrow IPC; we forward those batches unchanged.
//! * Rule 10 — the executor is `Send + Sync + 'static`. `SnowflakeApi`
//!   takes `&self` for `exec`, so it's safe to share without a Mutex.
//! * Rule 11 — all I/O is async; no blocking calls under an async fn.
//! * Rule 12 — passwords are stored only inside the `SnowflakeApi`
//!   client's opaque session state. The [`SnowflakeConfig`] struct
//!   carries the password through `connect` and is dropped after.
//!   The connector's `Debug` impl never prints the config.
//! * Rule 13 — schemas are fetched on first `table_provider` call,
//!   not at connector construction.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use arrow::array::{Array, ArrayRef, RecordBatch};
use arrow::compute::cast;
use arrow::datatypes::{DataType, Field, Schema, SchemaRef, TimeUnit};
use async_trait::async_trait;
use datafusion::catalog::{
    CatalogProvider as DfCatalogProvider, SchemaProvider as DfSchemaProvider,
};
use datafusion::datasource::TableProvider;
use datafusion::error::{DataFusionError, Result as DfResult};
use datafusion::execution::SendableRecordBatchStream;
use datafusion::physical_plan::stream::RecordBatchStreamAdapter;
use datafusion::physical_plan::PhysicalExpr;
use datafusion::sql::sqlparser::ast::{self};
use datafusion::sql::unparser::dialect::Dialect;
use datafusion::sql::TableReference;
use datafusion_federation::sql::{
    AstAnalyzer, RemoteTableRef, SQLExecutor, SQLFederationProvider, SQLTableSource,
};
use datafusion_federation::FederatedTableProviderAdaptor;
use futures::stream;
use futures::StreamExt;
use snowflake_api::{QueryResult, SnowflakeApi};
use tracing::debug;

use dataglot_core::{DataglotError, Result as DataglotResult};

// ---------------------------------------------------------------------------
// Config — typed shape that callers fill in before calling `connect`.
// ---------------------------------------------------------------------------

/// Snowflake connection parameters consumed by
/// [`SnowflakeConnector::connect`].
///
/// Snowflake's `SnowflakeApi::with_password_auth` takes seven separate
/// fields rather than a single DSN — this struct is the typed shape
/// the server-config layer (and tests) build from JSON / env vars.
///
/// `password` is consumed (`String`, not `&str`) so the value lives
/// only as long as the call to `connect`; the password never reaches
/// the [`SnowflakeConnector`] struct itself.
///
/// `PartialEq`/`Eq` support the ballista distributed-registry classifier
/// (`dataglot-server`) pinning which catalogs are distributable in a
/// live-DB-free unit test — same role the resolved Postgres DSN plays. The
/// derived equality includes `password`, but the manual [`fmt::Debug`] below
/// still redacts it, so it never surfaces in logs/errors (rule 12).
#[derive(Clone, PartialEq, Eq)]
pub struct SnowflakeConfig {
    /// Account identifier, e.g. `acme-corp.us-east-1`. Required.
    pub account: String,
    /// Compute warehouse, e.g. `COMPUTE_WH`. Required.
    pub warehouse: String,
    /// Default database, e.g. `ANALYTICS`. Required.
    pub database: String,
    /// Service-account username. Required.
    pub user: String,
    /// Password auth. Moved into the underlying client and dropped
    /// from callers' hands immediately. Used only when
    /// [`Self::private_key_pem`] is `None`; may be empty when a
    /// private key is supplied. Snowflake is deprecating password auth
    /// (MFA mandates) — prefer key-pair.
    pub password: String,
    /// Key-pair (RSA JWT) auth: the private key in PEM. When `Some`
    /// (non-empty), the connector authenticates with this via
    /// `with_certificate_auth` and ignores [`Self::password`] — the
    /// non-interactive path that isn't blocked by the account's MFA
    /// requirement (Snowflake error 390197). `None` ⇒ password auth.
    pub private_key_pem: Option<String>,
    /// Optional schema for unqualified table references. The
    /// connector defers to the call-site's qualified name when this
    /// is `None`.
    pub schema: Option<String>,
    /// Optional warehouse role override. Useful when the service
    /// account's default role doesn't match what the catalog needs.
    pub role: Option<String>,
}

impl fmt::Debug for SnowflakeConfig {
    /// Credential-safe `Debug` impl per hard rule 12. Emits
    /// operational targeting fields (account / warehouse / database /
    /// schema) so operators can diagnose "which catalog is this?",
    /// but redacts every auth-adjacent field (`user`, `role`,
    /// `password`). Service-account usernames and role names can
    /// leak organisation structure to log readers, so we treat them
    /// as credentials for redaction purposes — only the
    /// `SnowflakeApi` client carries the raw values, and only inside
    /// its opaque session state.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SnowflakeConfig")
            .field("account", &self.account)
            .field("warehouse", &self.warehouse)
            .field("database", &self.database)
            .field("schema", &self.schema)
            .field("user", &"<redacted>")
            .field("role", &"<redacted>")
            .field("password", &"<redacted>")
            .field(
                "private_key_pem",
                &if self.private_key_pem.is_some() {
                    "<redacted>"
                } else {
                    "<unset>"
                },
            )
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Connector
// ---------------------------------------------------------------------------

/// A Snowflake federation connector.
///
/// Construct via [`SnowflakeConnector::connect`] with a
/// [`SnowflakeConfig`]. The underlying `SnowflakeApi` client is
/// thread-safe (its `exec` method takes `&self`), so we hold it as a
/// plain field without an outer `Mutex`.
///
/// The connector stores enough identity metadata (account, warehouse,
/// database, user, schema, role) to surface a useful redacted
/// `Debug`; the password is never copied out of the client.
pub struct SnowflakeConnector {
    /// Federation compute-context key + display name.
    name: String,
    /// Snowflake REST client. Authentication is lazy — the client is
    /// constructed offline; the first `exec` triggers the login flow.
    ///
    /// Wrapped in `Arc` because `SnowflakeApi` is `!Clone` (its
    /// `exec` takes `&self` so we don't need a `Mutex`, but the
    /// `SQLExecutor::execute` impl needs to move a handle into a
    /// spawned future).
    client: Arc<SnowflakeApi>,
    /// Account identifier — emitted via `Debug` for operator
    /// diagnostics ("which catalog is this?").
    account: String,
    /// Compute warehouse — emitted via `Debug` for operator
    /// diagnostics.
    warehouse: String,
    /// Default database — also the database queried by
    /// `INFORMATION_SCHEMA.COLUMNS` during schema discovery.
    database: String,
    /// Default schema, if configured. Surfaced via `Debug` for
    /// operator diagnostics.
    default_schema: Option<String>,
    /// Per-table Arrow schema cache, keyed by lower-cased
    /// `(schema, table)`. `fetch_arrow_schema` (an `INFORMATION_SCHEMA.COLUMNS`
    /// round-trip) is otherwise re-run on every table resolution — DataFusion
    /// resolves a reference several times per statement (analyze + plan), so a
    /// single query paid two ~1.3s COLUMNS fetches. The boot-built connector is
    /// `Arc`-shared across every pgwire session, so this cache is effectively
    /// process-wide: a table's schema is fetched at most once for the server's
    /// lifetime. Lazy per rule 13 (populated on first `table()`/`DESCRIBE`, not
    /// eagerly); a remote `ALTER TABLE` isn't seen until the connector is
    /// rebuilt — the same lifetime contract the cached table/schema lists
    /// already carry.
    schema_cache: Arc<std::sync::Mutex<HashMap<(String, String), SchemaRef>>>,
}

impl SnowflakeConnector {
    /// Construct a connector for the given config. The `SnowflakeApi`
    /// client is built offline — Snowflake's auth handshake fires on
    /// the first query, not at construction time. This matches
    /// hard rule 13 (lazy schema resolution) and gives us the
    /// same "construction is cheap, first query is where errors
    /// surface" shape the other connectors have.
    ///
    /// # Errors
    /// Returns [`DataglotError::Connection`] if the underlying client
    /// can't be built (e.g. malformed account identifier rejected by
    /// `snowflake-api`'s constructor).
    pub fn connect(name: impl Into<String>, cfg: SnowflakeConfig) -> DataglotResult<Self> {
        let name = name.into();
        // hard rule 12: never emit auth-adjacent identifiers
        // (user, role) at any log level. The non-auth targeting
        // fields tell operators which catalog the line refers to;
        // user/role live inside the opaque `SnowflakeApi` client.
        debug!(
            connector = %name,
            account = %cfg.account,
            warehouse = %cfg.warehouse,
            database = %cfg.database,
            schema = ?cfg.schema,
            "building snowflake client"
        );

        // Key-pair (RSA JWT) auth when a private key is supplied — the
        // non-interactive path unaffected by the account's MFA mandate
        //. Falls back to password auth otherwise. Both
        // constructors take the same targeting fields; only the last
        // credential arg differs.
        let use_key_pair = cfg
            .private_key_pem
            .as_deref()
            .is_some_and(|k| !k.trim().is_empty());
        let client = if use_key_pair {
            SnowflakeApi::with_certificate_auth(
                &cfg.account,
                Some(&cfg.warehouse),
                Some(&cfg.database),
                cfg.schema.as_deref(),
                &cfg.user,
                cfg.role.as_deref(),
                cfg.private_key_pem.as_deref().unwrap_or_default(),
            )
        } else {
            SnowflakeApi::with_password_auth(
                &cfg.account,
                Some(&cfg.warehouse),
                Some(&cfg.database),
                cfg.schema.as_deref(),
                &cfg.user,
                cfg.role.as_deref(),
                &cfg.password,
            )
        }
        .map_err(|e| {
            // `snowflake-api`'s error type doesn't echo the credential
            // back, but we still construct our own message to avoid
            // inadvertently widening any future leak surface.
            DataglotError::connection(format!(
                "snowflake client build failed for account '{}' ({} auth): {e}",
                cfg.account,
                if use_key_pair { "key-pair" } else { "password" },
            ))
        })?;

        Ok(Self {
            name,
            client: Arc::new(client),
            account: cfg.account,
            warehouse: cfg.warehouse,
            database: cfg.database,
            default_schema: cfg.schema,
            schema_cache: Arc::new(std::sync::Mutex::new(HashMap::new())),
            // `cfg.user` / `cfg.role` are intentionally dropped at
            // this point — they live inside the `client`'s session
            // state and are never copied out (hard rule 12).
        })
    }

    /// Federation compute-context name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Produce a [`TableProvider`] for `<schema>.<table>` that pushes
    /// filters / projections / limits down to Snowflake.
    ///
    /// The schema is fetched on demand by querying
    /// `INFORMATION_SCHEMA.COLUMNS` in the configured database
    /// (rule 13: no eager remote query at construction).
    ///
    /// # Errors
    /// Returns [`DataglotError::Catalog`] if the table is not found
    /// or its column types cannot be mapped to Arrow.
    pub async fn table_provider(
        self: &Arc<Self>,
        schema: &str,
        table: &str,
    ) -> DataglotResult<Arc<dyn TableProvider>> {
        let arrow_schema = self.fetch_arrow_schema(schema, table).await?;
        let executor: Arc<dyn SQLExecutor> = Arc::clone(self) as Arc<dyn SQLExecutor>;
        let provider = Arc::new(SQLFederationProvider::new(executor));
        let table_ref = RemoteTableRef::from(TableReference::partial(
            schema.to_string(),
            table.to_string(),
        ));
        let source = SQLTableSource::new_with_schema(provider, table_ref, arrow_schema);
        Ok(Arc::new(FederatedTableProviderAdaptor::new(Arc::new(
            source,
        ))))
    }

    /// Wrap this connector as a `DataFusion` [`CatalogProvider`].
    ///
    /// Enumerates the user-visible schemas of the configured
    /// Snowflake database via `INFORMATION_SCHEMA.SCHEMATA` (excluding
    /// `INFORMATION_SCHEMA` itself — the metadata view we just read
    /// from) and resolves tables lazily via [`Self::table_provider`].
    ///
    /// # Eager listing, lazy table schema (matches Postgres pattern)
    ///
    /// `DataFusion`'s [`CatalogProvider::schema_names`] /
    /// [`CatalogProvider::schema`] are sync, but listing schemas +
    /// tables in Snowflake is async. We eagerly fetch both lists once
    /// here (we're already in async context) and cache them. Per-table
    /// Arrow schemas remain lazy (rule 13) — they're only fetched
    /// when [`SchemaProvider::table`] is called, which delegates to
    /// the existing [`Self::table_provider`].
    ///
    /// Names are cached for the lifetime of the returned catalog. A
    /// `CREATE TABLE` issued through another Snowflake session won't
    /// appear until a fresh `as_catalog_provider()` call — drop and
    /// rebuild if the operator needs to pick up DDL.
    ///
    /// # Errors
    /// Returns [`DataglotError::Catalog`] if the listing queries fail
    /// (typically a permissions problem — the CI service-account role
    /// might lack `USAGE` on a schema it can otherwise see in
    /// `INFORMATION_SCHEMA.SCHEMATA`).
    ///
    /// [`CatalogProvider`]: datafusion::catalog::CatalogProvider
    /// [`CatalogProvider::schema_names`]: datafusion::catalog::CatalogProvider::schema_names
    /// [`CatalogProvider::schema`]: datafusion::catalog::CatalogProvider::schema
    /// [`SchemaProvider::table`]: datafusion::catalog::SchemaProvider::table
    pub async fn as_catalog_provider(
        self: &Arc<Self>,
    ) -> DataglotResult<Arc<dyn DfCatalogProvider>> {
        // Same identifier guard as `fetch_arrow_schema` — `cfg.database`
        // is spliced into SQL below. The other identifier inputs
        // (schema/table names) come from Snowflake's own metadata so
        // they're trusted; only `database` is operator-supplied at
        // this layer.
        validate_identifier_literal(&self.database)?;

        // 1. Decide which schemas to enumerate. A configured `schema`
        //    scopes the catalog to just that one namespace instead of
        //    walking the entire database. On a large source (e.g.
        //    SNOWFLAKE_SAMPLE_DATA, with its huge TPCDS_SF*TCL schemas)
        //    a full walk makes catalog build pathologically slow and
        //    burns warehouse credits enumerating tables nobody queries
        //. With no `schema` set we fall back to listing
        //    every user-visible schema (`INFORMATION_SCHEMA` excluded —
        //    it's the metadata view we read from; Snowflake has no other
        //    system schemas inside a user database).
        let schema_names =
            if let Some(scoped) = self.default_schema.as_deref().filter(|s| !s.is_empty()) {
                validate_identifier_literal(scoped)?;
                vec![scoped.to_string()]
            } else {
                let schema_sql = format!(
                    "SELECT SCHEMA_NAME \
                 FROM {database}.INFORMATION_SCHEMA.SCHEMATA \
                 WHERE SCHEMA_NAME <> 'INFORMATION_SCHEMA' \
                 ORDER BY SCHEMA_NAME",
                    database = self.database,
                );
                let schema_result = self.client.exec(&schema_sql).await.map_err(|e| {
                    DataglotError::catalog(format!(
                        "failed to list snowflake schemas in database '{}': {e}",
                        self.database
                    ))
                })?;
                collect_single_string_column(&schema_result, "SCHEMA_NAME").map_err(|e| {
                    DataglotError::catalog(format!(
                    "failed to read snowflake schema names from INFORMATION_SCHEMA.SCHEMATA: {e}"
                ))
                })?
            };

        // 2. For each schema, eagerly fetch its table list and build a
        //    `SnowflakeSchema`. We filter on `TABLE_TYPE IN
        //    ('BASE TABLE', 'VIEW')` to skip transient / external
        //    tables — the federation pipeline can't read those yet
        //    and surfacing them would just confuse `SHOW TABLES`-style
        //    discovery on the pgwire side.
        let mut schemas: HashMap<String, Arc<dyn DfSchemaProvider>> =
            HashMap::with_capacity(schema_names.len());
        for schema_name in &schema_names {
            // `INFORMATION_SCHEMA.TABLES` reports names as Snowflake
            // stored them. We rely on the schema-name comparison
            // matching exactly — works because we sourced the name
            // from the same metadata view one query ago.
            let table_sql = format!(
                "SELECT TABLE_NAME \
                 FROM {database}.INFORMATION_SCHEMA.TABLES \
                 WHERE UPPER(TABLE_SCHEMA) = UPPER('{schema_name}') \
                   AND TABLE_TYPE IN ('BASE TABLE', 'VIEW') \
                 ORDER BY TABLE_NAME",
                database = self.database,
            );
            let table_result = self.client.exec(&table_sql).await.map_err(|e| {
                DataglotError::catalog(format!(
                    "failed to list snowflake tables for schema '{schema_name}': {e}"
                ))
            })?;
            let table_names =
                collect_single_string_column(&table_result, "TABLE_NAME").map_err(|e| {
                    DataglotError::catalog(format!(
                        "failed to read snowflake table names for schema '{schema_name}': {e}"
                    ))
                })?;
            schemas.insert(
                schema_name.clone(),
                Arc::new(SnowflakeSchema {
                    connector: Arc::clone(self),
                    schema_name: schema_name.clone(),
                    table_names,
                }) as Arc<dyn DfSchemaProvider>,
            );
        }

        Ok(Arc::new(SnowflakeCatalog {
            connector_name: self.name.clone(),
            schema_names,
            schemas,
        }) as Arc<dyn DfCatalogProvider>)
    }

    /// Fetch the Arrow schema for `<schema>.<table>` from
    /// `INFORMATION_SCHEMA.COLUMNS`. The query targets the
    /// configured database — Snowflake's `INFORMATION_SCHEMA` is
    /// database-local, not account-wide, which is why the database
    /// is part of [`SnowflakeConfig`].
    async fn fetch_arrow_schema(
        &self,
        schema_name: &str,
        table_name: &str,
    ) -> DataglotResult<SchemaRef> {
        validate_identifier_literal(schema_name)?;
        validate_identifier_literal(table_name)?;
        // `cfg.database` comes from operator config but still gets
        // spliced into SQL — apply the same guard as the other two
        // identifiers. Belt-and-braces against a malformed config
        // smuggling SQL through the catalog layer.
        validate_identifier_literal(&self.database)?;

        // Cache hit → skip the INFORMATION_SCHEMA.COLUMNS round-trip entirely.
        // Key case-insensitively (Snowflake folds unquoted identifiers), matching
        // how the fetched fields are lower-cased below.
        let key = (schema_name.to_lowercase(), table_name.to_lowercase());
        if let Some(cached) = self
            .schema_cache
            .lock()
            .expect("schema cache mutex poisoned")
            .get(&key)
        {
            return Ok(Arc::clone(cached));
        }

        // Snowflake's catalog stores identifier casing case-
        // sensitively under the hood, but folds unquoted identifiers
        // to upper case at catalog-write time. That means:
        // - `public.users`        → stored as `PUBLIC` / `USERS`
        // - `"Sales"."DailyRollup"` → stored as `Sales` / `DailyRollup`
        //
        // Earlier we unconditionally uppercased both sides of the
        // comparison, which broke case-sensitive quoted identifiers.
        // Use `UPPER(...) = UPPER(...)` on the Snowflake side
        // instead — Snowflake's UPPER applies to the stored value
        // and to our literal, so unquoted callers and quoted-mixed-
        // case callers both match without us guessing which path
        // the catalog took.
        let sql = format!(
            "SELECT column_name, data_type, is_nullable, \
                    numeric_precision, numeric_scale \
             FROM {database}.INFORMATION_SCHEMA.COLUMNS \
             WHERE UPPER(table_schema) = UPPER('{schema_name}') \
               AND UPPER(table_name)   = UPPER('{table_name}') \
             ORDER BY ordinal_position",
            database = self.database,
        );

        let outcome = self.client.exec(&sql).await.map_err(|e| {
            DataglotError::catalog(format!(
                "INFORMATION_SCHEMA query failed for {schema_name}.{table_name}: {e}"
            ))
        })?;

        let batches = match outcome {
            QueryResult::Arrow(b) => b,
            QueryResult::Empty => {
                return Err(DataglotError::catalog(format!(
                    "table not found: {schema_name}.{table_name}"
                )));
            }
            // Snowflake's REST sometimes falls back to JSON for very
            // small results / session-config edge cases. We do not
            // implement the JSON shape — the typed mapper below
            // expects Arrow column dispatch and would silently lose
            // precision/scale otherwise. Surface the fallback as a
            // catalog error so the operator sees it loudly.
            QueryResult::Json(_) => {
                return Err(DataglotError::catalog(format!(
                    "INFORMATION_SCHEMA query for {schema_name}.{table_name} returned JSON \
                     instead of Arrow — Snowflake session configuration drift?"
                )));
            }
        };

        if batches.is_empty() || batches.iter().all(|b| b.num_rows() == 0) {
            return Err(DataglotError::catalog(format!(
                "table not found: {schema_name}.{table_name}"
            )));
        }

        let mut fields = Vec::new();
        for batch in &batches {
            let n = batch.num_rows();
            for r in 0..n {
                let column_name = string_cell(batch, "COLUMN_NAME", r)?;
                let data_type_text = string_cell(batch, "DATA_TYPE", r)?;
                let is_nullable_text = string_cell(batch, "IS_NULLABLE", r)?;
                let precision = opt_u32_cell(batch, "NUMERIC_PRECISION", r);
                let scale = opt_u32_cell(batch, "NUMERIC_SCALE", r);
                let nullable = matches!(is_nullable_text.as_str(), "YES" | "yes");

                let arrow_type = snowflake_type_to_arrow(&data_type_text, precision, scale)
                    .ok_or_else(|| {
                        DataglotError::catalog(format!(
                            "unsupported snowflake type '{data_type_text}' for column \
                             {schema_name}.{table_name}.{column_name}"
                        ))
                    })?;
                // Snowflake stores column names upper-cased (`O_CUSTKEY`), but
                // DataFusion normalises unquoted query references to lower case,
                // so an upper-cased Arrow field never matches `o.o_custkey`.
                // Present the field lower-cased; the un-quoting dialect
                // (`SnowflakeDialect`) lets Snowflake fold it back to its stored
                // upper case in the pushed-down SQL.
                fields.push(Field::new(column_name.to_lowercase(), arrow_type, nullable));
            }
        }

        let schema: SchemaRef = Arc::new(Schema::new(fields));
        // Populate the cache. `or_insert_with` keeps a value another task may
        // have raced in between our miss and now (both fetched the same schema,
        // so either is correct); we never hold the lock across the `exec` await.
        self.schema_cache
            .lock()
            .expect("schema cache mutex poisoned")
            .entry(key)
            .or_insert_with(|| Arc::clone(&schema));
        Ok(schema)
    }
}

impl fmt::Debug for SnowflakeConnector {
    /// Credential-safe `Debug` per hard rule 12. Emits
    /// non-auth targeting fields (name / account / warehouse /
    /// database / `default_schema`) so operators can identify which
    /// connector instance a log line refers to. Auth-adjacent
    /// fields (`user`, `role`) and the password aren't stored on
    /// the connector at all — they live inside the underlying
    /// `client`'s opaque session state, which `finish_non_exhaustive`
    /// hides explicitly.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SnowflakeConnector")
            .field("name", &self.name)
            .field("account", &self.account)
            .field("warehouse", &self.warehouse)
            .field("database", &self.database)
            .field("default_schema", &self.default_schema)
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// SQLExecutor
// ---------------------------------------------------------------------------

#[async_trait]
impl SQLExecutor for SnowflakeConnector {
    fn name(&self) -> &str {
        &self.name
    }

    fn compute_context(&self) -> Option<String> {
        Some(self.name.clone())
    }

    fn dialect(&self) -> Arc<dyn Dialect> {
        // Snowflake's SQL surface is ANSI / Postgres-flavoured —
        // double-quoted identifiers, standard string literals, no
        // backticks. The unparser's `DefaultDialect` already emits
        // that shape. A dedicated `SnowflakeDialect` wrapper exists
        // below as a marker for future Snowflake-specific overrides
        // (e.g. `IFF` for `CASE WHEN`, `:variant` field access)
        // without forcing a churn-y call-site change later.
        Arc::new(SnowflakeDialect)
    }

    fn ast_analyzer(&self) -> Option<AstAnalyzer> {
        // Correct the malformed `ORDER BY` the DataFusion/federation
        // unparse pipeline emits when an aggregate's output alias
        // collides with the (bare) local table name. See
        // `rewrite_statement_for_snowflake` for the full mechanism.
        Some(Box::new(|stmt: ast::Statement| {
            Ok(rewrite_statement_for_snowflake(stmt))
        }))
    }

    fn execute(
        &self,
        query: &str,
        schema: SchemaRef,
        _filters: &[Arc<dyn PhysicalExpr>],
    ) -> DfResult<SendableRecordBatchStream> {
        // `SnowflakeApi::exec` takes `&self`; clone the `Arc` so
        // the spawned future owns a reference. The client is
        // internally `Arc`-shared around its connection state, so
        // the outer `Arc` is the cheap-clone wrapper we add.
        let client = Arc::clone(&self.client);
        let target_schema = Arc::clone(&schema);
        let query_owned = query.to_string();

        let fut = async move {
            let outcome = client.exec(&query_owned).await.map_err(|e| {
                DataFusionError::External(Box::new(DataglotError::federation(format!(
                    "snowflake query failed: {e}"
                ))))
            })?;

            let raw = match outcome {
                QueryResult::Arrow(b) => b,
                QueryResult::Empty => Vec::new(),
                QueryResult::Json(_) => {
                    // Same fail-loud reasoning as the schema query —
                    // we don't decode JSON shape; if Snowflake hands
                    // it back the operator needs to know.
                    return Err(DataFusionError::External(Box::new(
                        DataglotError::federation(
                            "snowflake returned JSON instead of Arrow — session config drift?"
                                .to_string(),
                        ),
                    )));
                }
            };

            // Coerce each result batch to the discovered schema. Snowflake's
            // Arrow IPC does NOT always match our INFORMATION_SCHEMA-derived
            // logical types: a `NUMBER(p,0)` (scale-0) column arrives as a
            // compact integer (Int8/16/32/64, sized to the values) rather than
            // the `Decimal128(p,0)` we declare, so the physical array's type
            // disagrees with the schema and a downstream primitive downcast
            // panics ("primitive array"). Cast each column by position to the
            // declared type and adopt the declared (lower-cased) field names.
            let batches = raw
                .into_iter()
                .map(|b| coerce_batch_to_schema(&b, &target_schema))
                .collect::<Result<Vec<_>, DataFusionError>>()?;

            Ok::<_, DataFusionError>(batches)
        };

        // Flatten the Vec<RecordBatch> future into a per-batch
        // stream. `stream::once(fut)` yields the whole vec at once,
        // then `flat_map` fans it out.
        let batch_stream = stream::once(fut).flat_map(|result| match result {
            Ok(batches) => stream::iter(batches.into_iter().map(Ok)).left_stream(),
            Err(e) => stream::iter(std::iter::once(Err(e))).right_stream(),
        });

        let stream = Box::pin(RecordBatchStreamAdapter::new(schema, batch_stream));
        Ok(crate::instrument_pushdown(
            &self.name,
            "snowflake",
            query,
            stream,
        ))
    }

    async fn table_names(&self) -> DfResult<Vec<String>> {
        // Catalog-listing path is unused by federation pushdown
        // (mirrors the Postgres / MySQL connectors). The future
        // catalog-provider surface uses `fetch_arrow_schema` instead.
        Err(DataFusionError::NotImplemented(
            "table_names not implemented".to_string(),
        ))
    }

    async fn get_table_schema(&self, table_name: &str) -> DfResult<SchemaRef> {
        let (schema, table) = split_qualified(table_name).ok_or_else(|| {
            DataFusionError::External(Box::new(DataglotError::catalog(format!(
                "expected '<schema>.<table>' reference, got: {table_name}"
            ))))
        })?;
        self.fetch_arrow_schema(&schema, &table)
            .await
            .map_err(|e| DataFusionError::External(Box::new(e)))
    }
}

/// Cheap liveness probe that reuses the boot-built, already-authenticated
/// `SnowflakeApi` client. The health poller calls this on a timer
/// instead of rebuilding the connector — which, for Snowflake, means a fresh
/// client, a ~0.87s re-authentication, and an eager `INFORMATION_SCHEMA` walk,
/// all thrown away. `SELECT 1` reuses the existing session and errors iff the
/// account is unreachable or the session has expired. `snowflake-api`'s error
/// doesn't echo credentials, and we wrap it in our own message besides (rule 12).
#[async_trait]
impl crate::health::ConnectorHealthCheck for SnowflakeConnector {
    async fn health_check(&self) -> Result<(), String> {
        self.client
            .exec("SELECT 1")
            .await
            .map(|_| ())
            .map_err(|e| format!("snowflake health check failed: {e}"))
    }
}

// ---------------------------------------------------------------------------
// Dialect marker — see `SQLExecutor::dialect` above
// ---------------------------------------------------------------------------

/// `Dialect` implementation for Snowflake.
///
/// Snowflake's SQL is mostly ANSI with double-quoted identifiers, so
/// the upstream `DefaultDialect`'s behaviour is correct for the
/// common case. This wrapper exists so Snowflake-specific overrides
/// (function name remapping, semi-structured access) can land later
/// without changing every call site that names the dialect.
pub struct SnowflakeDialect;

impl Dialect for SnowflakeDialect {
    fn identifier_quote_style(&self, ident: &str) -> Option<char> {
        // Emit *plain* identifiers UNQUOTED. Dataglot presents Snowflake
        // schemas/tables/columns to the client lower-cased (DataFusion
        // normalises unquoted references to lower case), while Snowflake
        // stores them upper-cased. Unquoted identifiers let Snowflake
        // fold our lower-case names back to their stored upper case, so
        // `snowflake.tpch_sf1.orders` → `... FROM tpch_sf1.orders` →
        // resolves to `TPCH_SF1.ORDERS`. Quoting a plain name (the old
        // unconditional `Some('"')`) would instead demand an exact-case
        // match and break every natural lower-case query.
        //
        // BUT a name that isn't a legal *unquoted* Snowflake identifier —
        // most commonly the auto alias DataFusion gives an un-aliased
        // aggregate, `count(*)`, but also anything with parens / operators /
        // spaces — MUST be quoted. Emitted bare it produces malformed SQL
        // (`... AS count(*)`) that Snowflake answers with **zero rows** rather
        // than an error, so `SELECT count(*) FROM t` silently came back empty
        // through federation while `SELECT count(*) AS c` worked (OSS bug).
        // Quoting is safe for these: an alias is just an output label, so
        // case-sensitivity doesn't matter, and results map back by position.
        //
        // Caveat (unchanged): a plain identifier that is a Snowflake reserved
        // word still isn't quoted here — a case-preserving mapping in the
        // federation layer is the proper long-term fix (tracked separately).
        if ident_needs_quoting(ident) {
            Some('"')
        } else {
            None
        }
    }
}

/// Whether `ident` must be double-quoted to be a legal Snowflake identifier.
///
/// A bare Snowflake identifier is `[A-Za-z_][A-Za-z0-9_$]*`; anything else —
/// an empty string, a leading digit, or any character outside that set (the
/// `(`, `*`, `)` of the `count(*)` auto alias; spaces; operators) — has to be
/// quoted or the pushed SQL is malformed.
fn ident_needs_quoting(ident: &str) -> bool {
    let mut chars = ident.chars();
    match chars.next() {
        None => true,
        Some(first) if !(first.is_ascii_alphabetic() || first == '_') => true,
        Some(_) => ident
            .chars()
            .any(|c| !(c.is_ascii_alphanumeric() || c == '_' || c == '$')),
    }
}

// ---------------------------------------------------------------------------
// AST post-pass — `ORDER BY` table-name collision ( bug 2)
// ---------------------------------------------------------------------------

/// Correct the malformed `ORDER BY` the DataFusion + federation unparse
/// pipeline emits for a Snowflake-pushed aggregate whose output alias
/// collides with the (bare) local table name.
///
/// # The bug
///
/// `datafusion-federation`'s `RewriteTableScanAnalyzer` requalifies a
/// pushed plan's columns to the *remote* table reference. For an
/// unqualified `ORDER BY <alias>` sort key it does this by **substring**
/// replacement (`rewrite_column_name_in_expr`): if the sort-key name
/// equals a local table name in its `known_rewrites` map, the name is
/// swapped for the remote table reference. When an aggregate projects
/// `... AS region` and the local table is itself named `region`, the sort
/// key `region` is rewritten to the remote name `tpch_sf1.region`, so the
/// unparser emits `ORDER BY "tpch_sf1.region"` — ordering by a **table
/// name**. Snowflake answers with 0 rows (no error) instead of the sorted
/// aggregate. The `SnowflakeDialect` alone can't fix this: it's a
/// mis-resolved identifier, not a quoting choice, so it needs an AST
/// post-pass — mirroring the Oracle connector's `ast_analyzer`.
///
/// # The fix (narrow)
///
/// Walk each query's `ORDER BY` list and, for a sort key that is a
/// *single* identifier whose value both (a) names a table in that query's
/// `FROM` clause and (b) whose final dotted segment matches one of the
/// query's output column aliases, replace it with a plain identifier
/// referencing that alias — i.e. the sort key the user originally wrote.
/// A healthy `ORDER BY` never names a whole table, so this cannot fire on
/// a correct query; every other shape is left untouched.
fn rewrite_statement_for_snowflake(mut stmt: ast::Statement) -> ast::Statement {
    if let ast::Statement::Query(query) = &mut stmt {
        rewrite_query_order_by(query);
    }
    stmt
}

fn rewrite_query_order_by(query: &mut ast::Query) {
    // Recurse into the body first so nested pushed queries (set
    // operations, derived subqueries, parenthesized joins) are covered
    // as well.
    rewrite_set_expr_order_by(&mut query.body);

    // The outer `ORDER BY` binds to the query's active `Select` — which is
    // not always `query.body` directly: a parenthesized body (`SetExpr::Query`)
    // or a set operation (`SetExpr::SetOperation`) wraps it, and SQL binds a
    // trailing `ORDER BY` on a set operation to the *left* (first) branch's
    // output columns. Descend to that select for the alias / table extraction
    // so the collision is corrected regardless of body shape.
    let Some(select) = find_active_select(query.body.as_ref()) else {
        return;
    };
    let Some(order_by) = query.order_by.as_mut() else {
        return;
    };
    let ast::OrderByKind::Expressions(exprs) = &mut order_by.kind else {
        return;
    };

    // Output aliases come from the active (left) branch, but the colliding
    // table can be in ANY set-operation branch — a trailing `ORDER BY <table>`
    // is still malformed even when `<table>` is only in the right branch. So
    // collect collision tables across the whole body.
    let from_tables = collect_body_table_names(query.body.as_ref());
    if from_tables.is_empty() {
        return;
    }
    let aliases = collect_output_aliases(&select.projection);

    for order_expr in &mut *exprs {
        if let ast::Expr::Identifier(ident) = &order_expr.expr {
            if let Some(alias) = corrected_sort_alias(&ident.value, &from_tables, &aliases) {
                // Restore the *projection's* alias identifier verbatim,
                // preserving its `quote_style`, so a quoted output alias
                // (`AS "Sales-Region"`) round-trips as `ORDER BY "Sales-Region"`
                // rather than the unquoted `ORDER BY Sales-Region` an
                // `Ident::new` would emit (which Snowflake would parse as
                // subtraction / a case-folded reference).
                order_expr.expr = ast::Expr::Identifier(alias);
            }
        }
    }
}

/// The `Select` a query's outer clauses (`ORDER BY`, `LIMIT`) bind to.
///
/// A query body is not always a `Select`: it may be wrapped in parentheses
/// (`SetExpr::Query`) or be a set operation (`SetExpr::SetOperation`). For a
/// set operation a trailing `ORDER BY` binds to the first (left) branch's
/// output columns, so recurse leftward to find the select whose projection /
/// `FROM` clause define those names.
fn find_active_select(body: &ast::SetExpr) -> Option<&ast::Select> {
    match body {
        ast::SetExpr::Select(select) => Some(select),
        ast::SetExpr::Query(query) => find_active_select(query.body.as_ref()),
        ast::SetExpr::SetOperation { left, .. } => find_active_select(left),
        _ => None,
    }
}

fn rewrite_set_expr_order_by(body: &mut ast::SetExpr) {
    match body {
        ast::SetExpr::Query(query) => rewrite_query_order_by(query),
        ast::SetExpr::SetOperation { left, right, .. } => {
            rewrite_set_expr_order_by(left);
            rewrite_set_expr_order_by(right);
        }
        ast::SetExpr::Select(select) => {
            for twj in &mut select.from {
                rewrite_table_with_joins_order_by(twj);
            }
        }
        _ => {}
    }
}

fn rewrite_table_with_joins_order_by(twj: &mut ast::TableWithJoins) {
    rewrite_table_factor_order_by(&mut twj.relation);
    for join in &mut twj.joins {
        rewrite_table_factor_order_by(&mut join.relation);
    }
}

fn rewrite_table_factor_order_by(table_factor: &mut ast::TableFactor) {
    match table_factor {
        // Derived subqueries carry their own `ORDER BY` that can hit the
        // same collision.
        ast::TableFactor::Derived { subquery, .. } => rewrite_query_order_by(subquery),
        // A parenthesized / bushy join tree nests another `TableWithJoins`;
        // descend so subqueries inside it are still reached.
        ast::TableFactor::NestedJoin {
            table_with_joins, ..
        } => rewrite_table_with_joins_order_by(table_with_joins),
        _ => {}
    }
}

/// Every real table name across a whole query body — recursing through
/// set-operation branches and parenthesized bodies — so a collision is caught
/// even when the colliding table sits in a branch other than the one the
/// trailing `ORDER BY` binds to (e.g. only the right side of a `UNION`).
fn collect_body_table_names(body: &ast::SetExpr) -> Vec<String> {
    match body {
        ast::SetExpr::Select(select) => collect_from_table_names(&select.from),
        ast::SetExpr::Query(query) => collect_body_table_names(query.body.as_ref()),
        ast::SetExpr::SetOperation { left, right, .. } => {
            let mut names = collect_body_table_names(left);
            names.extend(collect_body_table_names(right));
            names
        }
        _ => Vec::new(),
    }
}

/// Dot-joined names of every real table referenced in a `FROM` clause
/// (relations + joins, including parenthesized / bushy `NestedJoin` trees).
/// Derived tables / TVFs are skipped — only a real table name can be the
/// target of the collision.
fn collect_from_table_names(from: &[ast::TableWithJoins]) -> Vec<String> {
    let mut names = Vec::new();
    for twj in from {
        push_table_with_joins_names(twj, &mut names);
    }
    names
}

fn push_table_with_joins_names(twj: &ast::TableWithJoins, out: &mut Vec<String>) {
    push_table_factor_name(&twj.relation, out);
    for join in &twj.joins {
        push_table_factor_name(&join.relation, out);
    }
}

fn push_table_factor_name(table_factor: &ast::TableFactor, out: &mut Vec<String>) {
    match table_factor {
        ast::TableFactor::Table { name, .. } => out.push(object_name_to_dotted(name)),
        // A parenthesized / bushy join nests another `TableWithJoins`; recurse
        // so table names inside it are collected and a collision against them
        // is still corrected.
        ast::TableFactor::NestedJoin {
            table_with_joins, ..
        } => push_table_with_joins_names(table_with_joins, out),
        // A derived table (`FROM (SELECT … FROM region) d`) can hide the
        // colliding real table inside its subquery — recurse so it's collected.
        ast::TableFactor::Derived { subquery, .. } => {
            out.extend(collect_body_table_names(subquery.body.as_ref()));
        }
        _ => {}
    }
}

fn object_name_to_dotted(name: &ast::ObjectName) -> String {
    name.0
        .iter()
        .filter_map(ast::ObjectNamePart::as_ident)
        .map(|ident| ident.value.as_str())
        .collect::<Vec<_>>()
        .join(".")
}

/// Output-column alias identifiers of a projection (the `AS <name>` labels).
///
/// The whole `Ident` is returned — not just its `value` — so the rewrite can
/// restore a quoted alias (`AS "Sales-Region"`) with its `quote_style` intact.
fn collect_output_aliases(projection: &[ast::SelectItem]) -> Vec<ast::Ident> {
    projection
        .iter()
        .filter_map(|item| match item {
            ast::SelectItem::ExprWithAlias { alias, .. } => Some(alias.clone()),
            _ => None,
        })
        .collect()
}

/// If `value` (a single sort-key identifier) is the  collision
/// shape, return the output-alias identifier it should be restored to
/// (quoting preserved); otherwise `None` (leave the sort key untouched).
fn corrected_sort_alias(
    value: &str,
    from_tables: &[String],
    aliases: &[ast::Ident],
) -> Option<ast::Ident> {
    // If the sort key already matches an output alias verbatim, it's a
    // legitimate alias reference — not the mis-resolved collision — even when
    // that alias deliberately equals a table name (e.g. `SELECT … AS
    // "tpch_sf1.region"` then `ORDER BY "tpch_sf1.region"`). Leave it untouched.
    if aliases.iter().any(|a| a.value.eq_ignore_ascii_case(value)) {
        return None;
    }
    // A correct `ORDER BY` key is a column or an output alias — never a
    // whole table name. So only a key that exactly matches a `FROM` table
    // is the mis-resolved shape; this guard is what keeps the pass narrow.
    if !from_tables
        .iter()
        .any(|table| table.eq_ignore_ascii_case(value))
    {
        return None;
    }
    // The clobbered alias is the table name's final dotted segment
    // (`tpch_sf1.region` → `region`); restore it only if it is genuinely
    // an output alias of this query.
    let last_segment = value.rsplit('.').next()?;
    aliases
        .iter()
        .find(|alias| alias.value.eq_ignore_ascii_case(last_segment))
        .cloned()
}

/// Coerce a Snowflake result batch to the connector's discovered `schema`:
/// cast each column (by position) to the declared Arrow type and adopt the
/// declared field names.
///
/// Snowflake's Arrow IPC does not always agree with the logical types we
/// derived from `INFORMATION_SCHEMA` — most notably `NUMBER(p,0)` (scale 0)
/// arrives as a compact integer sized to its values (Int8/16/32/64) rather
/// than the declared `Decimal128(p,0)`. Forwarding such a batch as-is claims
/// a schema the physical arrays don't satisfy, which trips a downstream
/// primitive downcast (`arrow`'s "primitive array" panic). Casting by position
/// reconciles both the type and the (lower-cased) field names.
fn coerce_batch_to_schema(
    batch: &RecordBatch,
    schema: &SchemaRef,
) -> Result<RecordBatch, DataFusionError> {
    let want = schema.fields().len();
    if batch.num_columns() != want {
        return Err(DataFusionError::External(Box::new(
            DataglotError::federation(format!(
                "snowflake result has {} column(s) but the discovered schema declares {want}",
                batch.num_columns()
            )),
        )));
    }
    let mut columns: Vec<ArrayRef> = Vec::with_capacity(want);
    for (i, field) in schema.fields().iter().enumerate() {
        let col = batch.column(i);
        if col.data_type() == field.data_type() {
            columns.push(Arc::clone(col));
        } else {
            let casted = cast(col.as_ref(), field.data_type()).map_err(|e| {
                DataFusionError::External(Box::new(DataglotError::federation(format!(
                    "snowflake column '{}' cast {} -> {} failed: {e}",
                    field.name(),
                    col.data_type(),
                    field.data_type()
                ))))
            })?;
            columns.push(casted);
        }
    }
    RecordBatch::try_new(Arc::clone(schema), columns).map_err(|e| {
        DataFusionError::External(Box::new(DataglotError::federation(format!(
            "snowflake batch did not conform to the discovered schema after coercion: {e}"
        ))))
    })
}

// ---------------------------------------------------------------------------
// Type mapping
// ---------------------------------------------------------------------------

/// Map a Snowflake `DATA_TYPE` text (as reported by
/// `INFORMATION_SCHEMA.COLUMNS`) plus optional numeric precision /
/// scale into an Arrow [`DataType`].
///
/// Returns `None` for any unsupported type; the caller turns that
/// into a typed catalog error so the operator sees the unsupported
/// column name + type rather than a silent schema gap.
#[must_use]
// The string family and the semi-structured family both land on
// `Utf8` (Snowflake sends VARIANT/OBJECT/ARRAY as JSON text), but the
// arms are kept separate on purpose — each documents a distinct
// Snowflake type class and they may diverge later (e.g. structured
// Arrow for semi-structured). Merging them would lose that intent.
#[allow(clippy::match_same_arms)]
pub fn snowflake_type_to_arrow(
    data_type: &str,
    numeric_precision: Option<u32>,
    numeric_scale: Option<u32>,
) -> Option<DataType> {
    match data_type.to_ascii_uppercase().as_str() {
        // The NUMBER family — Snowflake stores every fixed-precision
        // value as NUMBER(p, s) under the hood. INT / BIGINT /
        // DECIMAL / NUMERIC are aliases at the SQL surface that all
        // resolve to NUMBER in INFORMATION_SCHEMA.
        "NUMBER" | "DECIMAL" | "NUMERIC" | "INT" | "INTEGER" | "BIGINT" | "SMALLINT"
        | "TINYINT" | "BYTEINT" => {
            // Snowflake's max precision is 38 — fits inside Arrow's
            // Decimal128(38, 38) ceiling. Reject anything that
            // exceeds Arrow's bounds so a row never produces a
            // value the downstream can't represent.
            let p_u8 = u8::try_from(numeric_precision?).ok()?;
            let s_i8 = i8::try_from(numeric_scale?).ok()?;
            if p_u8 == 0 || p_u8 > 38 {
                return None;
            }
            Some(DataType::Decimal128(p_u8, s_i8))
        }
        "FLOAT" | "FLOAT4" | "FLOAT8" | "DOUBLE" | "DOUBLE PRECISION" | "REAL" => {
            Some(DataType::Float64)
        }
        "BOOLEAN" => Some(DataType::Boolean),
        // The string family is uniform in Snowflake — VARCHAR and
        // TEXT are aliases of STRING (length is metadata, not type).
        "VARCHAR" | "CHAR" | "CHARACTER" | "STRING" | "TEXT" => Some(DataType::Utf8),
        "DATE" => Some(DataType::Date32),
        // Naive wall-clock — no offset, no zone. TIMESTAMP_TZ /
        // TIMESTAMP_LTZ are deferred (different Arrow representation
        // + needs the connector's session offset for round-trip).
        "TIMESTAMP_NTZ" | "TIMESTAMPNTZ" => Some(DataType::Timestamp(TimeUnit::Microsecond, None)),
        // Semi-structured. Snowflake serialises VARIANT /
        // OBJECT / ARRAY as UTF-8 JSON text in its Arrow IPC result,
        // so they land as Utf8 end-to-end with no re-cast (rule 1).
        // Structured Arrow (Struct / List) is a later refinement;
        // JSON text is the lossless MVP and matches exactly what
        // Snowflake sends over the wire.
        "VARIANT" | "OBJECT" | "ARRAY" => Some(DataType::Utf8),
        // Variable-length binary. Snowflake's Arrow IPC
        // returns BINARY / VARBINARY as an Arrow `Binary` column.
        "BINARY" | "VARBINARY" => Some(DataType::Binary),
        // Still rejected → typed catalog error (no silent drop):
        // TIME / TIMESTAMP_TZ / TIMESTAMP_LTZ use scaled-int or
        // composite (epoch + offset) Arrow encodings that need the
        // connector's session offset to round-trip; GEOGRAPHY /
        // GEOMETRY need a GeoJSON/WKB decision. Tracked in.
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Helpers (cell access + identifier guarding)
// ---------------------------------------------------------------------------

/// Read a string cell from a `RecordBatch` by column name. Returns an
/// error if the column is missing or the row index is out of bounds.
fn string_cell(
    batch: &arrow::record_batch::RecordBatch,
    col_name: &str,
    row: usize,
) -> DataglotResult<String> {
    let idx = batch
        .schema()
        .index_of(col_name)
        .map_err(|_| DataglotError::catalog(format!("missing column '{col_name}' in result")))?;
    let array = batch.column(idx);
    let s = array
        .as_any()
        .downcast_ref::<arrow::array::StringArray>()
        .ok_or_else(|| {
            DataglotError::catalog(format!(
                "column '{col_name}' is not a StringArray (got {:?})",
                array.data_type()
            ))
        })?;
    if s.is_null(row) {
        return Err(DataglotError::catalog(format!(
            "unexpected NULL in column '{col_name}' at row {row}"
        )));
    }
    Ok(s.value(row).to_string())
}

/// Read an optional `u32` cell — Snowflake's `INFORMATION_SCHEMA`
/// returns `NUMERIC_PRECISION` / `NUMERIC_SCALE` as nullable numbers.
/// Returns `None` if the column is missing or the cell is null.
fn opt_u32_cell(
    batch: &arrow::record_batch::RecordBatch,
    col_name: &str,
    row: usize,
) -> Option<u32> {
    let idx = batch.schema().index_of(col_name).ok()?;
    let array = batch.column(idx);
    if array.is_null(row) {
        return None;
    }
    // Snowflake reports `NUMERIC_PRECISION` / `NUMERIC_SCALE` as
    // NUMBER, which the Arrow IPC layer most often hands back as a
    // `Decimal128` array — that's the load-bearing downcast for
    // production Snowflake deployments. The integer / string
    // variants below are belt-and-braces for session-config drift
    // and the rare cases where Snowflake's JSON fallback gets
    // round-tripped through Arrow as a stringified number.
    if let Some(a) = array
        .as_any()
        .downcast_ref::<arrow::array::Decimal128Array>()
    {
        // Precision/scale themselves are small positive integers
        // (Snowflake caps NUMBER precision at 38). The raw i128
        // value is the unscaled integer representation; for
        // NUMERIC_PRECISION / NUMERIC_SCALE the scale is zero so
        // the raw value IS the integer we want.
        return u32::try_from(a.value(row)).ok();
    }
    if let Some(a) = array.as_any().downcast_ref::<arrow::array::Int64Array>() {
        return u32::try_from(a.value(row)).ok();
    }
    if let Some(a) = array.as_any().downcast_ref::<arrow::array::Int32Array>() {
        return u32::try_from(a.value(row)).ok();
    }
    if let Some(a) = array.as_any().downcast_ref::<arrow::array::UInt32Array>() {
        return Some(a.value(row));
    }
    if let Some(a) = array.as_any().downcast_ref::<arrow::array::StringArray>() {
        // Defensive: some sessions return Snowflake numbers as
        // strings in Arrow. Parse rather than reject.
        return a.value(row).parse::<u32>().ok();
    }
    None
}

/// Reject identifiers that would break the literal-SQL splice we
/// do in `fetch_arrow_schema`. The names come from the catalog
/// config so this is belt-and-braces, not user-input handling — we
/// fail loudly on anything weird rather than silently producing a
/// malformed SQL.
fn validate_identifier_literal(s: &str) -> DataglotResult<()> {
    if s.is_empty() {
        return Err(DataglotError::catalog("empty identifier".to_string()));
    }
    if s.chars().any(|c| {
        c == '\'' || c == '"' || c == '\\' || c == ';' || c == '\0' || c == '\n' || c == '\r'
    }) {
        return Err(DataglotError::catalog(format!(
            "identifier contains unsupported character: {s:?}"
        )));
    }
    Ok(())
}

/// Split a `<schema>.<table>` (optionally double-quote-wrapped)
/// identifier into parts. Mirrors the helper in the `MySQL` connector.
fn split_qualified(s: &str) -> Option<(String, String)> {
    let parts: Vec<&str> = s.splitn(2, '.').collect();
    if parts.len() != 2 {
        return None;
    }
    let schema = parts[0].trim_matches('"').to_string();
    let table = parts[1].trim_matches('"').to_string();
    Some((schema, table))
}

/// Pull a single string column out of a `QueryResult::Arrow` by
/// column name, collecting non-null values into a `Vec<String>`.
/// Used by `as_catalog_provider` to drain the schema-listing and
/// table-listing queries.
///
/// Returns an error if the result isn't Arrow (rare JSON fallback;
/// same fail-loud policy `fetch_arrow_schema` uses), if the named
/// column doesn't exist, or if the column isn't `Utf8`. NULL cells
/// are silently dropped — `INFORMATION_SCHEMA.SCHEMATA.SCHEMA_NAME`
/// and `INFORMATION_SCHEMA.TABLES.TABLE_NAME` are non-nullable in
/// practice; defensive treatment so a future Snowflake schema
/// change doesn't crash the catalog probe.
fn collect_single_string_column(
    result: &QueryResult,
    col_name: &str,
) -> Result<Vec<String>, String> {
    let batches = match result {
        QueryResult::Arrow(b) => b,
        QueryResult::Empty => return Ok(Vec::new()),
        QueryResult::Json(_) => {
            return Err(
                "snowflake returned JSON instead of Arrow — session-config drift?".to_string(),
            );
        }
    };
    let mut out = Vec::new();
    for batch in batches {
        let idx = batch
            .schema()
            .index_of(col_name)
            .map_err(|_| format!("missing column '{col_name}' in result"))?;
        let col = batch.column(idx);
        let arr = col
            .as_any()
            .downcast_ref::<arrow::array::StringArray>()
            .ok_or_else(|| {
                format!(
                    "column '{col_name}' is not Utf8 (got {:?})",
                    col.data_type()
                )
            })?;
        for r in 0..arr.len() {
            if !arr.is_null(r) {
                out.push(arr.value(r).to_string());
            }
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Catalog + schema providers
// ---------------------------------------------------------------------------

/// `DataFusion` [`CatalogProvider`] backed by a single Snowflake
/// database. Built by [`SnowflakeConnector::as_catalog_provider`].
///
/// The cache (schema names + per-schema `SnowflakeSchema` providers)
/// is fixed at construction time — see the docs on
/// `as_catalog_provider` for the eager-listing rationale.
///
/// [`CatalogProvider`]: datafusion::catalog::CatalogProvider
pub struct SnowflakeCatalog {
    /// The underlying connector's identifier — used for `Debug` and
    /// for diagnostic logs only. NOT used as the catalog's name in
    /// the `SessionContext`; that name comes from the caller of
    /// `register_catalog`.
    connector_name: String,
    /// Cached alphabetised list of schema names. Returned verbatim
    /// from `CatalogProvider::schema_names`.
    schema_names: Vec<String>,
    /// Pre-built `SnowflakeSchema` providers, keyed by schema name.
    /// Lookups are O(1) and never block.
    schemas: HashMap<String, Arc<dyn DfSchemaProvider>>,
}

impl fmt::Debug for SnowflakeCatalog {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SnowflakeCatalog")
            .field("connector", &self.connector_name)
            .field("schema_count", &self.schema_names.len())
            .finish_non_exhaustive()
    }
}

impl DfCatalogProvider for SnowflakeCatalog {
    fn schema_names(&self) -> Vec<String> {
        self.schema_names.clone()
    }

    fn schema(&self, name: &str) -> Option<Arc<dyn DfSchemaProvider>> {
        // Snowflake stores identifiers upper-cased (`TPCH_SF1`), but
        // DataFusion normalises unquoted references to lower case
        // (`snowflake.tpch_sf1.orders` → schema `tpch_sf1`). Match
        // case-insensitively so lower-case pgwire queries resolve
        // against the Snowflake-cased schema names ( follow-on).
        self.schemas.get(name).map(Arc::clone).or_else(|| {
            self.schemas
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(name))
                .map(|(_, v)| Arc::clone(v))
        })
    }
}

/// `DataFusion` [`SchemaProvider`] backed by a single Snowflake
/// schema (namespace) on a [`SnowflakeConnector`].
///
/// Per-table Arrow schemas are NOT fetched at construction; they
/// are resolved lazily inside `SchemaProvider::table` by delegating
/// to [`SnowflakeConnector::table_provider`] (rule 13).
///
/// [`SchemaProvider`]: datafusion::catalog::SchemaProvider
struct SnowflakeSchema {
    /// The connector this schema belongs to.
    connector: Arc<SnowflakeConnector>,
    /// Snowflake schema (namespace) name as stored in
    /// `INFORMATION_SCHEMA.SCHEMATA`.
    schema_name: String,
    /// Cached alphabetised list of table + view names within this
    /// schema. Populated once at catalog-construction time.
    table_names: Vec<String>,
}

impl fmt::Debug for SnowflakeSchema {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SnowflakeSchema")
            .field("schema", &self.schema_name)
            .field("table_count", &self.table_names.len())
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl DfSchemaProvider for SnowflakeSchema {
    fn table_names(&self) -> Vec<String> {
        self.table_names.clone()
    }

    fn table_exist(&self, name: &str) -> bool {
        // Case-insensitive: Snowflake stores `ORDERS`, DataFusion asks
        // for the normalised `orders` (see `SnowflakeCatalog::schema`).
        self.table_names
            .iter()
            .any(|t| t.eq_ignore_ascii_case(name))
    }

    async fn table(&self, name: &str) -> DfResult<Option<Arc<dyn TableProvider>>> {
        // Resolve the Snowflake-cased table name case-insensitively;
        // a miss skips the remote roundtrip (typo / does-not-exist).
        let Some(stored) = self
            .table_names
            .iter()
            .find(|t| t.eq_ignore_ascii_case(name))
        else {
            return Ok(None);
        };
        // Lazy column-schema fetch (rule 13). Pass the stored (correct-
        // case) names so the remote query and `INFORMATION_SCHEMA`
        // lookup target the identifiers as Snowflake holds them.
        let provider = self
            .connector
            .table_provider(&self.schema_name, stored)
            .await
            .map_err(|e| DataFusionError::External(Box::new(e)))?;
        Ok(Some(provider))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_config() -> SnowflakeConfig {
        SnowflakeConfig {
            account: "acme-corp.us-east-1".to_string(),
            warehouse: "COMPUTE_WH".to_string(),
            database: "ANALYTICS".to_string(),
            user: "DATAGLOT_SVC".to_string(),
            password: "super-secret".to_string(),
            private_key_pem: None,
            schema: Some("PUBLIC".to_string()),
            role: Some("READER".to_string()),
        }
    }

    #[test]
    fn snowflake_connector_is_a_connector_health_check() {
        //: the boot path retains the `Arc<SnowflakeConnector>` and hands
        // a clone to the poller as an `Arc<dyn ConnectorHealthCheck>`, so a
        // liveness tick reuses the authenticated client (a `SELECT 1`) instead of
        // rebuilding it — no fresh client, no ~0.87s re-auth, no eager
        // INFORMATION_SCHEMA walk. Construction is offline; a live `SELECT 1`
        // needs a real account (integration suite). Here we pin that the impl
        // exists and the concrete type coerces to the trait object the poller
        // stores.
        fn assert_impl<T: crate::health::ConnectorHealthCheck>() {}
        assert_impl::<SnowflakeConnector>();
        let conn = SnowflakeConnector::connect("sf-hc", sample_config()).expect("offline");
        let _handle: Arc<dyn crate::health::ConnectorHealthCheck> = Arc::new(conn);
    }

    #[test]
    fn config_debug_redacts_credentials() {
        // Pin hard rule 12: passwords AND auth-adjacent
        // identifiers (user, role) never appear in `Debug` output.
        // Service-account usernames and role names can leak
        // organisation structure to log readers, so we treat them
        // as credentials for redaction purposes.
        let cfg = sample_config();
        let dbg = format!("{cfg:?}");
        assert!(!dbg.contains("super-secret"), "password leaked: {dbg}");
        assert!(!dbg.contains("DATAGLOT_SVC"), "user leaked: {dbg}");
        assert!(!dbg.contains("READER"), "role leaked: {dbg}");
        assert!(
            dbg.contains("<redacted>"),
            "redaction marker missing: {dbg}"
        );
        // Operational targeting fields are still visible — operators
        // need them to identify which catalog a log line refers to.
        assert!(dbg.contains("acme-corp.us-east-1"));
        assert!(dbg.contains("COMPUTE_WH"));
        assert!(dbg.contains("ANALYTICS"));
    }

    #[test]
    fn connector_debug_does_not_print_client_state() {
        // `Debug` on the connector struct must not include the
        // `client` field (which holds the password inside its
        // session state via the underlying crate). Asserted by
        // construction: we'd need a valid Snowflake account to
        // build a connector, so we only check the struct's
        // formatter doesn't emit a "client" key by inspecting the
        // Debug derive output of a hand-built skeleton.
        //
        // We can't construct a SnowflakeConnector without
        // SnowflakeApi::with_password_auth succeeding (which it
        // does even without a live network — auth fires on first
        // query), so we use the real `connect` path with a syntactic
        // account. The constructor accepts any string for the
        // account; the redaction guarantee is what's under test
        // here.
        let cfg = sample_config();
        let conn = SnowflakeConnector::connect("sf-test", cfg).expect("client builds offline");
        let dbg = format!("{conn:?}");
        assert!(!dbg.contains("super-secret"), "password leaked: {dbg}");
        assert!(!dbg.contains("client"), "client field exposed: {dbg}");
        // user + role are redacted alongside the password — same
        // hard rule 12 reasoning as the config Debug test.
        assert!(!dbg.contains("DATAGLOT_SVC"), "user leaked: {dbg}");
        assert!(!dbg.contains("READER"), "role leaked: {dbg}");
        // Operational identifiers visible for diagnostics.
        assert!(dbg.contains("sf-test"));
        assert!(dbg.contains("acme-corp.us-east-1"));
    }

    #[tokio::test]
    async fn fetch_arrow_schema_serves_cache_hit_without_network() {
        // A populated cache entry short-circuits the INFORMATION_SCHEMA.COLUMNS
        // round-trip — `fetch_arrow_schema` returns the cached schema and never
        // touches the client (which, offline, would error on the first exec).
        // Also pins case-insensitive keying: inserted lower-case, queried upper.
        use datafusion::arrow::datatypes::{DataType, Field, Schema};

        let conn = SnowflakeConnector::connect("sf-test", sample_config()).expect("offline");
        let cached: SchemaRef = Arc::new(Schema::new(vec![Field::new(
            "c_custkey",
            DataType::Int64,
            true,
        )]));
        conn.schema_cache.lock().unwrap().insert(
            ("tpch_sf1".to_string(), "customer".to_string()),
            Arc::clone(&cached),
        );

        let got = conn
            .fetch_arrow_schema("TPCH_SF1", "CUSTOMER")
            .await
            .expect("cache hit returns without a network round-trip");
        assert!(
            Arc::ptr_eq(&got, &cached),
            "returned the exact cached schema"
        );
        assert_eq!(got.field(0).name(), "c_custkey");
    }

    #[test]
    fn dialect_quotes_only_identifiers_that_require_it() {
        let dialect = SnowflakeDialect;
        // Plain names stay UNQUOTED so Snowflake folds our lower-case names to
        // their stored upper case; quoting would demand an exact-case match and
        // break every natural lower-case federated query.
        assert_eq!(dialect.identifier_quote_style("nation"), None);
        assert_eq!(dialect.identifier_quote_style("n_name"), None);
        assert_eq!(dialect.identifier_quote_style("ANY_TABLE_NAME"), None);
        assert_eq!(dialect.identifier_quote_style("c_acctbal$2"), None);
        // Names that aren't legal *unquoted* identifiers MUST be quoted — most
        // importantly the `count(*)` auto alias DataFusion gives an un-aliased
        // aggregate. Emitted bare (`... AS count(*)`) Snowflake answers with
        // zero rows, so `SELECT count(*) FROM t` silently came back empty.
        assert_eq!(dialect.identifier_quote_style("count(*)"), Some('"'));
        assert_eq!(dialect.identifier_quote_style("SUM(x)"), Some('"'));
        assert_eq!(dialect.identifier_quote_style("has space"), Some('"'));
        assert_eq!(dialect.identifier_quote_style(""), Some('"'));
        assert_eq!(dialect.identifier_quote_style("1leading"), Some('"'));
    }

    /// Parse `sql`, run it through the Snowflake `ast_analyzer` post-pass,
    /// and render the result — the offline mirror of the connector hook,
    /// matching the Oracle connector's `unparse_after_analyzer` helper.
    fn unparse_after_analyzer(sql: &str) -> String {
        use datafusion::sql::sqlparser::dialect::GenericDialect;
        use datafusion::sql::sqlparser::parser::Parser;

        let stmt = Parser::parse_sql(&GenericDialect {}, sql)
            .expect("valid SQL")
            .remove(0);
        rewrite_statement_for_snowflake(stmt).to_string()
    }

    /// End-to-end proof of  bug 2 *and* its fix: push an aggregate
    /// with `ORDER BY <alias>` where the alias (`region`) collides with the
    /// bare local table name (`region`). The federation unparse pipeline
    /// corrupts the sort key into the remote **table** name, and the
    /// connector's `ast_analyzer` must correct it back to the alias.
    ///
    /// The `VirtualExecutionPlan` display exposes both the pre-analyzer
    /// `base_sql` (still malformed — the bug) and the post-analyzer
    /// `rewritten_executor_sql` (corrected — the fix), so a single plan
    /// dump witnesses fail-then-pass with no live Snowflake.
    #[tokio::test]
    async fn ast_analyzer_fixes_orderby_collision_end_to_end() {
        use std::any::Any;

        use datafusion::arrow::datatypes::{DataType, Field, Schema};
        use datafusion::physical_plan::displayable;
        use datafusion::prelude::SessionContext;
        use datafusion_federation::sql::SQLTable;

        #[derive(Debug)]
        struct ReproTable {
            reference: TableReference,
            schema: SchemaRef,
        }
        impl SQLTable for ReproTable {
            fn as_any(&self) -> &dyn Any {
                self
            }
            fn table_reference(&self) -> TableReference {
                self.reference.clone()
            }
            fn schema(&self) -> SchemaRef {
                Arc::clone(&self.schema)
            }
        }

        let schema: SchemaRef = Arc::new(Schema::new(vec![
            Field::new("r_regionkey", DataType::Int64, false),
            Field::new("r_name", DataType::Utf8, false),
        ]));

        // Federated table whose *remote* reference is `tpch_sf1.region`,
        // executed via the real `SnowflakeConnector` (offline client) so its
        // dialect + ast_analyzer are exercised. Registered under the bare
        // local name `region` — the collision precondition.
        let conn = SnowflakeConnector::connect("snowflake", sample_config()).expect("offline");
        let provider = Arc::new(SQLFederationProvider::new(Arc::new(conn)));
        let table = Arc::new(ReproTable {
            reference: TableReference::partial("tpch_sf1", "region"),
            schema,
        });
        let source = Arc::new(SQLTableSource { provider, table });
        let adaptor = Arc::new(FederatedTableProviderAdaptor::new(source));

        let ctx = SessionContext::new_with_state(datafusion_federation::default_session_state());
        ctx.register_table(TableReference::bare("region"), adaptor)
            .unwrap();

        let sql = "SELECT r_name AS region, count(*) AS cnt \
                   FROM region GROUP BY r_name ORDER BY region";
        let df = ctx.sql(sql).await.unwrap();
        let phys = df.create_physical_plan().await.unwrap();
        let displayed = displayable(phys.as_ref()).indent(true).to_string();

        // The bug: before the analyzer the sort key is the remote *table*
        // name, not the alias.
        assert!(
            displayed.contains(r#"ORDER BY "tpch_sf1.region""#),
            "expected the federation unparse to emit the malformed \
             table-name ORDER BY (bug precondition): {displayed}"
        );

        // The fix: the analyzer rewrote the statement, and the corrected
        // SQL orders by the alias, not the table.
        let rewritten = displayed
            .split("rewritten_executor_sql=")
            .nth(1)
            .unwrap_or_else(|| panic!("ast_analyzer did not alter the statement: {displayed}"));
        assert!(
            rewritten.contains("ORDER BY region ASC NULLS LAST"),
            "corrected pushdown must order by the alias `region`: {displayed}"
        );
        assert!(
            !rewritten.contains(r#"ORDER BY "tpch_sf1.region""#),
            "the malformed table-name ORDER BY must be gone after the analyzer: {displayed}"
        );
    }

    #[test]
    fn ast_analyzer_rewrites_orderby_table_collision() {
        // The exact malformed statement the federation unparse pipeline
        // produces for a collided aggregate (see the end-to-end test): the
        // sort key is the remote table name `"tpch_sf1.region"` instead of
        // the output alias `region`.
        let out = unparse_after_analyzer(
            r#"SELECT region.r_name AS region, count(1) AS cnt FROM tpch_sf1.region GROUP BY region.r_name ORDER BY "tpch_sf1.region" ASC NULLS LAST"#,
        );
        assert!(
            out.contains("ORDER BY region ASC NULLS LAST"),
            "sort key must be restored to the alias: {out}"
        );
        assert!(
            !out.contains(r#""tpch_sf1.region""#),
            "the mis-resolved table name must be gone from the sort: {out}"
        );
        // The FROM clause (a legitimate use of the table name) is untouched.
        assert!(
            out.contains("FROM tpch_sf1.region"),
            "FROM clause must be preserved: {out}"
        );
    }

    #[test]
    fn ast_analyzer_rewrites_orderby_collision_desc() {
        // The DESC / NULLS FIRST options ride along unchanged; only the
        // sort expression is corrected.
        let out = unparse_after_analyzer(
            r#"SELECT r.r_name AS region, count(1) AS cnt FROM tpch_sf1.region AS r GROUP BY r.r_name ORDER BY "tpch_sf1.region" DESC NULLS FIRST"#,
        );
        assert!(
            out.contains("ORDER BY region DESC NULLS FIRST"),
            "options must be preserved while the key is fixed: {out}"
        );
    }

    #[test]
    fn ast_analyzer_leaves_healthy_alias_sort_untouched() {
        // The benign shape (a bare alias sort key that does NOT match a
        // table name) must pass through unchanged.
        let sql = "SELECT r.r_name AS region, count(1) AS cnt FROM tpch_sf1.region AS r GROUP BY r.r_name ORDER BY region ASC NULLS LAST";
        assert_eq!(unparse_after_analyzer(sql), sql);
    }

    #[test]
    fn ast_analyzer_leaves_column_sort_untouched() {
        // A real qualified-column sort key (`r.r_name`, a compound
        // identifier — not the collision shape) is never rewritten.
        let sql = "SELECT r.r_name AS x, count(1) AS cnt FROM tpch_sf1.region AS r GROUP BY r.r_name ORDER BY r.r_name ASC NULLS LAST";
        assert_eq!(unparse_after_analyzer(sql), sql);
    }

    #[test]
    fn ast_analyzer_requires_matching_alias() {
        // Safety: a sort key equal to a FROM table name is only rewritten
        // when its final segment is a genuine output alias. Here the only
        // alias is `cnt`, so the malformed key is left alone rather than
        // guessed at.
        let sql = r#"SELECT count(1) AS cnt FROM tpch_sf1.region ORDER BY "tpch_sf1.region" ASC NULLS LAST"#;
        assert_eq!(unparse_after_analyzer(sql), sql);
    }

    #[test]
    fn ast_analyzer_rewrites_orderby_collision_on_set_operation() {
        // A trailing `ORDER BY` on a UNION binds to the first (left) branch's
        // output columns. The query body is a `SetExpr::SetOperation`, not a
        // bare `Select`, so the pre-fix code (which matched `SetExpr::Select`
        // directly) skipped the rewrite entirely. `find_active_select` now
        // descends to the left branch, whose `region` alias collides with the
        // bare table name.
        let out = unparse_after_analyzer(
            r#"SELECT r.r_name AS region, count(1) AS cnt FROM tpch_sf1.region AS r GROUP BY r.r_name UNION SELECT 'x' AS region, 0 AS cnt ORDER BY "tpch_sf1.region" ASC NULLS LAST"#,
        );
        assert!(
            out.contains("ORDER BY region ASC NULLS LAST"),
            "set-op outer ORDER BY must be corrected to the alias: {out}"
        );
        assert!(
            !out.contains(r#""tpch_sf1.region""#),
            "the mis-resolved table name must be gone from the sort: {out}"
        );
    }

    #[test]
    fn ast_analyzer_rewrites_orderby_collision_from_right_union_branch() {
        // The colliding table (`tpch_sf1.region`) appears ONLY in the RIGHT
        // branch, while the `region` output alias comes from the left. Collision
        // tables are now collected across all set-operation branches, so this is
        // corrected; collecting only the active (left) branch's tables (pre-fix)
        // missed it and left the malformed key intact.
        let out = unparse_after_analyzer(
            r#"SELECT n.n_name AS region, count(1) AS cnt FROM tpch_sf1.nation AS n GROUP BY n.n_name UNION SELECT r.r_name AS region, 0 AS cnt FROM tpch_sf1.region AS r GROUP BY r.r_name ORDER BY "tpch_sf1.region" ASC NULLS LAST"#,
        );
        assert!(
            out.contains("ORDER BY region ASC NULLS LAST"),
            "a collision from a non-left UNION branch must be corrected: {out}"
        );
        assert!(
            !out.contains(r#""tpch_sf1.region""#),
            "the mis-resolved table name must be gone from the sort: {out}"
        );
    }

    #[test]
    fn ast_analyzer_preserves_legitimate_full_name_alias() {
        // A query deliberately exposes an alias equal to the remote table name
        // alongside another alias matching its final segment. `ORDER BY
        // "tpch_sf1.region"` legitimately targets the first alias and must NOT
        // be rewritten to `region`.
        let out = unparse_after_analyzer(
            r#"SELECT r.r_name AS "tpch_sf1.region", r.r_regionkey AS region FROM tpch_sf1.region AS r ORDER BY "tpch_sf1.region" ASC NULLS LAST"#,
        );
        assert!(
            out.contains(r#"ORDER BY "tpch_sf1.region" ASC NULLS LAST"#),
            "a legitimate full-name output alias must be left untouched: {out}"
        );
    }

    #[test]
    fn ast_analyzer_collects_collision_table_from_derived_subquery() {
        // The colliding real table sits inside a derived subquery; its name must
        // still be collected so the outer malformed sort key is corrected.
        let out = unparse_after_analyzer(
            r#"SELECT d.region AS region, count(1) AS cnt FROM (SELECT r.r_name AS region FROM tpch_sf1.region AS r) AS d GROUP BY d.region ORDER BY "tpch_sf1.region" ASC NULLS LAST"#,
        );
        assert!(
            out.contains("ORDER BY region ASC NULLS LAST"),
            "a collision table inside a derived subquery must be collected + corrected: {out}"
        );
        assert!(
            !out.contains(r#""tpch_sf1.region""#),
            "the mis-resolved table name must be gone from the sort: {out}"
        );
    }

    #[test]
    fn ast_analyzer_rewrites_orderby_collision_on_parenthesized_body() {
        // A parenthesized query body is a `SetExpr::Query`, again not a bare
        // `Select`; `find_active_select` recurses through it so the outer
        // `ORDER BY` collision is still corrected.
        let out = unparse_after_analyzer(
            r#"(SELECT r.r_name AS region, count(1) AS cnt FROM tpch_sf1.region AS r GROUP BY r.r_name) ORDER BY "tpch_sf1.region" ASC NULLS LAST"#,
        );
        assert!(
            out.contains("ORDER BY region ASC NULLS LAST"),
            "parenthesized-body outer ORDER BY must be corrected: {out}"
        );
        assert!(
            !out.contains(r#""tpch_sf1.region""#),
            "the mis-resolved table name must be gone from the sort: {out}"
        );
    }

    #[test]
    fn ast_analyzer_collects_table_names_from_nested_join() {
        // A parenthesized join tree in `FROM` is a `TableFactor::NestedJoin`.
        // The pre-fix collector only saw top-level `TableFactor::Table`s, so
        // a table nested inside the join was never recorded and the collision
        // guard failed. `push_table_factor_name` now recurses into the nested
        // join, so a collision against `region` is corrected.
        let out = unparse_after_analyzer(
            r#"SELECT reg.r_name AS region, count(1) AS cnt FROM (tpch_sf1.region AS reg JOIN tpch_sf1.nation AS n ON reg.r_regionkey = n.n_regionkey) GROUP BY reg.r_name ORDER BY "tpch_sf1.region" ASC NULLS LAST"#,
        );
        assert!(
            out.contains("ORDER BY region ASC NULLS LAST"),
            "collision against a table inside a nested join must be corrected: {out}"
        );
        assert!(
            !out.contains(r#""tpch_sf1.region""#),
            "the mis-resolved table name must be gone from the sort: {out}"
        );
    }

    #[test]
    fn ast_analyzer_preserves_quoted_alias_quoting() {
        // When the colliding table (and thus its clobbered output alias) is
        // quoted because it contains punctuation, the restored sort key must
        // keep its `quote_style`. Emitting it bare (the old `Ident::new`)
        // would render `ORDER BY Sales-Region`, which Snowflake parses as
        // subtraction rather than the quoted identifier.
        let out = unparse_after_analyzer(
            r#"SELECT reg.c AS "Sales-Region", count(1) AS cnt FROM db."Sales-Region" AS reg GROUP BY reg.c ORDER BY "db.Sales-Region" ASC NULLS LAST"#,
        );
        assert!(
            out.contains(r#"ORDER BY "Sales-Region" ASC NULLS LAST"#),
            "quoted output alias must round-trip with its quoting intact: {out}"
        );
        assert!(
            !out.contains(r#""db.Sales-Region""#),
            "the mis-resolved table name must be gone from the sort: {out}"
        );
    }

    #[test]
    fn number_maps_to_decimal128() {
        // NUMBER(10, 2) → Decimal128(10, 2). Snowflake's NUMBER
        // family aliases INT / BIGINT / DECIMAL / NUMERIC; all
        // resolve to Decimal128 with the precision / scale
        // reported by INFORMATION_SCHEMA.
        assert_eq!(
            snowflake_type_to_arrow("NUMBER", Some(10), Some(2)),
            Some(DataType::Decimal128(10, 2))
        );
        assert_eq!(
            snowflake_type_to_arrow("DECIMAL", Some(38), Some(0)),
            Some(DataType::Decimal128(38, 0))
        );
        assert_eq!(
            snowflake_type_to_arrow("INT", Some(38), Some(0)),
            Some(DataType::Decimal128(38, 0))
        );
    }

    #[test]
    fn float_family_maps_to_float64() {
        // Snowflake folds every floating-point alias to FLOAT
        // internally — pin that all the SQL surface names resolve
        // to Float64 so cross-dialect diff doesn't silently
        // truncate.
        for name in ["FLOAT", "DOUBLE", "REAL", "FLOAT8"] {
            assert_eq!(
                snowflake_type_to_arrow(name, None, None),
                Some(DataType::Float64),
                "expected Float64 for {name}"
            );
        }
    }

    #[test]
    fn boolean_maps_to_boolean() {
        assert_eq!(
            snowflake_type_to_arrow("BOOLEAN", None, None),
            Some(DataType::Boolean)
        );
    }

    #[test]
    fn string_family_maps_to_utf8() {
        for name in ["VARCHAR", "CHAR", "TEXT", "STRING"] {
            assert_eq!(
                snowflake_type_to_arrow(name, None, None),
                Some(DataType::Utf8),
                "expected Utf8 for {name}"
            );
        }
    }

    #[test]
    fn date_maps_to_date32() {
        assert_eq!(
            snowflake_type_to_arrow("DATE", None, None),
            Some(DataType::Date32)
        );
    }

    #[test]
    fn timestamp_ntz_maps_to_microsecond_no_tz() {
        assert_eq!(
            snowflake_type_to_arrow("TIMESTAMP_NTZ", None, None),
            Some(DataType::Timestamp(TimeUnit::Microsecond, None))
        );
    }

    #[test]
    fn semi_structured_maps_to_utf8() {
        //: VARIANT / OBJECT / ARRAY arrive as UTF-8 JSON text
        // over Snowflake's Arrow IPC, so they map to Utf8. Case-
        // insensitive, matching the rest of the mapping.
        for name in ["VARIANT", "OBJECT", "ARRAY", "variant", "Array"] {
            assert_eq!(
                snowflake_type_to_arrow(name, None, None),
                Some(DataType::Utf8),
                "{name} should map to Utf8"
            );
        }
    }

    #[test]
    fn binary_maps_to_binary() {
        //: BINARY / VARBINARY → Arrow Binary.
        for name in ["BINARY", "VARBINARY", "binary"] {
            assert_eq!(
                snowflake_type_to_arrow(name, None, None),
                Some(DataType::Binary),
                "{name} should map to Binary"
            );
        }
    }

    #[test]
    fn unsupported_types_return_none() {
        // Still deferred → None, which surfaces as a typed catalog
        // error at table_provider time (no silent drop). TIME /
        // TIMESTAMP_TZ / TIMESTAMP_LTZ need scaled-int or composite
        // Arrow decoding; GEOGRAPHY / GEOMETRY need a GeoJSON/WKB
        // decision. Tracked in.
        assert_eq!(snowflake_type_to_arrow("GEOGRAPHY", None, None), None);
        assert_eq!(snowflake_type_to_arrow("GEOMETRY", None, None), None);
        assert_eq!(snowflake_type_to_arrow("TIMESTAMP_TZ", None, None), None);
        assert_eq!(snowflake_type_to_arrow("TIMESTAMP_LTZ", None, None), None);
        assert_eq!(snowflake_type_to_arrow("TIME", None, None), None);
    }

    #[test]
    fn number_rejects_precision_zero_or_too_large() {
        // Arrow's Decimal128 caps at precision 38. Snowflake's NUMBER
        // also caps at 38, but the validator here is defensive — if
        // a future Snowflake bump widens it, we want a typed catalog
        // error rather than a panicking Decimal128 builder downstream.
        assert!(snowflake_type_to_arrow("NUMBER", Some(0), Some(0)).is_none());
        assert!(snowflake_type_to_arrow("NUMBER", Some(39), Some(0)).is_none());
    }

    #[test]
    fn number_missing_precision_returns_none() {
        // INFORMATION_SCHEMA can legitimately report NULL precision
        // for some non-numeric type rows that the upstream parser
        // mislabels as NUMBER — surface as a typed error rather
        // than guessing a default.
        assert!(snowflake_type_to_arrow("NUMBER", None, Some(0)).is_none());
        assert!(snowflake_type_to_arrow("NUMBER", Some(10), None).is_none());
    }

    #[test]
    fn validate_identifier_rejects_quotes_and_semicolons() {
        // The literal-SQL splice in fetch_arrow_schema is the reason
        // for the validator. Anything that could close the literal
        // or chain a second statement is rejected loudly.
        assert!(validate_identifier_literal("ok_name").is_ok());
        assert!(validate_identifier_literal("with space").is_ok()); // spaces are fine
        assert!(validate_identifier_literal("").is_err());
        assert!(validate_identifier_literal("has\"quote").is_err());
        assert!(validate_identifier_literal("has'quote").is_err());
        assert!(validate_identifier_literal("has;semi").is_err());
        assert!(validate_identifier_literal("has\\backslash").is_err());
        assert!(validate_identifier_literal("has\nnewline").is_err());
    }

    #[test]
    fn split_qualified_unwraps_quotes() {
        assert_eq!(
            split_qualified("PUBLIC.USERS"),
            Some(("PUBLIC".to_string(), "USERS".to_string()))
        );
        assert_eq!(
            split_qualified("\"PUBLIC\".\"USERS\""),
            Some(("PUBLIC".to_string(), "USERS".to_string()))
        );
        assert!(split_qualified("just_one_part").is_none());
    }

    #[test]
    fn connector_name_round_trips() {
        let cfg = sample_config();
        let conn = SnowflakeConnector::connect("sf-prod", cfg).expect("client builds offline");
        assert_eq!(conn.name(), "sf-prod");
        // Compute-context is name-keyed so identical pushdown
        // origins are grouped — pin that.
        let executor: &dyn SQLExecutor = &conn;
        assert_eq!(executor.compute_context().as_deref(), Some("sf-prod"));
        assert_eq!(executor.name(), "sf-prod");
    }

    #[test]
    fn opt_u32_cell_decodes_decimal128_precision() {
        // Snowflake's `INFORMATION_SCHEMA` returns
        // `NUMERIC_PRECISION` / `NUMERIC_SCALE` as `NUMBER` columns,
        // and the Arrow IPC layer hands them back as `Decimal128`
        // in production. Pin that downcast so a regression in the
        // cell reader can't silently make every NUMBER column fail
        // schema inference.
        use arrow::array::{Decimal128Array, RecordBatch};
        use arrow::datatypes::{DataType, Field, Schema};
        use std::sync::Arc;

        let schema = Arc::new(Schema::new(vec![Field::new(
            "NUMERIC_PRECISION",
            DataType::Decimal128(38, 0),
            true,
        )]));
        let arr: Decimal128Array = vec![Some(10i128), None, Some(38i128)]
            .into_iter()
            .collect::<Decimal128Array>()
            .with_precision_and_scale(38, 0)
            .expect("decimal builder accepts (38,0)");
        let batch = RecordBatch::try_new(schema, vec![Arc::new(arr)]).expect("batch builds");

        assert_eq!(opt_u32_cell(&batch, "NUMERIC_PRECISION", 0), Some(10));
        assert_eq!(opt_u32_cell(&batch, "NUMERIC_PRECISION", 1), None);
        assert_eq!(opt_u32_cell(&batch, "NUMERIC_PRECISION", 2), Some(38));
    }

    #[test]
    fn opt_u32_cell_decodes_int64_and_int32_and_uint32() {
        // The integer downcasts are belt-and-braces for session-
        // config drift. Pin them so a future Arrow IPC shape change
        // doesn't silently regress the fallback path.
        use arrow::array::{Int32Array, Int64Array, RecordBatch, UInt32Array};
        use arrow::datatypes::{DataType, Field, Schema};
        use std::sync::Arc;

        let schema = Arc::new(Schema::new(vec![
            Field::new("p_i64", DataType::Int64, false),
            Field::new("p_i32", DataType::Int32, false),
            Field::new("p_u32", DataType::UInt32, false),
        ]));
        let batch = RecordBatch::try_new(
            schema,
            vec![
                Arc::new(Int64Array::from(vec![10i64])),
                Arc::new(Int32Array::from(vec![20i32])),
                Arc::new(UInt32Array::from(vec![30u32])),
            ],
        )
        .expect("batch builds");

        assert_eq!(opt_u32_cell(&batch, "p_i64", 0), Some(10));
        assert_eq!(opt_u32_cell(&batch, "p_i32", 0), Some(20));
        assert_eq!(opt_u32_cell(&batch, "p_u32", 0), Some(30));
    }

    #[test]
    fn opt_u32_cell_decodes_string_fallback() {
        // The string-fallback path is defensive against the rare
        // Snowflake session config where numbers round-trip through
        // a stringified form in Arrow. A regression would surface
        // as silent NUMBER-column rejection in those deployments.
        use arrow::array::{RecordBatch, StringArray};
        use arrow::datatypes::{DataType, Field, Schema};
        use std::sync::Arc;

        let schema = Arc::new(Schema::new(vec![Field::new("p_str", DataType::Utf8, true)]));
        let batch = RecordBatch::try_new(
            schema,
            vec![Arc::new(StringArray::from(vec![
                Some("18"),
                Some("not-a-number"),
                None,
            ]))],
        )
        .expect("batch builds");

        assert_eq!(opt_u32_cell(&batch, "p_str", 0), Some(18));
        assert_eq!(opt_u32_cell(&batch, "p_str", 1), None);
        assert_eq!(opt_u32_cell(&batch, "p_str", 2), None);
    }

    #[test]
    fn opt_u32_cell_returns_none_for_missing_column() {
        use arrow::array::{Int64Array, RecordBatch};
        use arrow::datatypes::{DataType, Field, Schema};
        use std::sync::Arc;

        let schema = Arc::new(Schema::new(vec![Field::new(
            "present",
            DataType::Int64,
            false,
        )]));
        let batch = RecordBatch::try_new(schema, vec![Arc::new(Int64Array::from(vec![1i64]))])
            .expect("batch builds");

        assert_eq!(opt_u32_cell(&batch, "absent", 0), None);
    }

    #[test]
    fn string_cell_reads_value_and_reports_each_failure() {
        // `string_cell` is the required-column reader behind schema/table
        // discovery. Pin all four outcomes: value, missing column, wrong
        // Arrow type, and an unexpected NULL (each is a distinct, fail-loud
        // catalog error the discovery path relies on).
        use arrow::array::{Int64Array, RecordBatch, StringArray};
        use arrow::datatypes::{DataType, Field, Schema};
        use std::sync::Arc;

        let schema = Arc::new(Schema::new(vec![
            Field::new("name", DataType::Utf8, true),
            Field::new("n", DataType::Int64, false),
        ]));
        let batch = RecordBatch::try_new(
            schema,
            vec![
                Arc::new(StringArray::from(vec![Some("PUBLIC"), None])),
                Arc::new(Int64Array::from(vec![1i64, 2i64])),
            ],
        )
        .expect("batch builds");

        assert_eq!(string_cell(&batch, "name", 0).unwrap(), "PUBLIC");
        assert!(string_cell(&batch, "absent", 0).is_err()); // missing column
        assert!(string_cell(&batch, "n", 0).is_err()); // not a StringArray
        assert!(string_cell(&batch, "name", 1).is_err()); // unexpected NULL
    }

    #[test]
    fn collect_single_string_column_gathers_across_batches_and_skips_nulls() {
        use arrow::array::{RecordBatch, StringArray};
        use arrow::datatypes::{DataType, Field, Schema};
        use std::sync::Arc;

        let schema = Arc::new(Schema::new(vec![Field::new(
            "TABLE_NAME",
            DataType::Utf8,
            true,
        )]));
        let b1 = RecordBatch::try_new(
            Arc::clone(&schema),
            vec![Arc::new(StringArray::from(vec![Some("orders"), None]))],
        )
        .expect("batch builds");
        let b2 = RecordBatch::try_new(
            schema,
            vec![Arc::new(StringArray::from(vec![Some("customers")]))],
        )
        .expect("batch builds");

        let out = collect_single_string_column(&QueryResult::Arrow(vec![b1, b2]), "TABLE_NAME")
            .expect("collects");
        assert_eq!(out, vec!["orders".to_string(), "customers".to_string()]);
    }

    #[test]
    fn collect_single_string_column_handles_empty_and_rejects_bad_shapes() {
        use arrow::array::{Int64Array, RecordBatch, StringArray};
        use arrow::datatypes::{DataType, Field, Schema};
        use snowflake_api::JsonResult;
        use std::sync::Arc;

        // Empty result set -> empty vec, not an error.
        assert_eq!(
            collect_single_string_column(&QueryResult::Empty, "TABLE_NAME").unwrap(),
            Vec::<String>::new()
        );

        // JSON fallback (session-config drift) -> loud error.
        let json = QueryResult::Json(JsonResult {
            value: serde_json::Value::Array(vec![]),
            schema: vec![],
        });
        assert!(collect_single_string_column(&json, "TABLE_NAME").is_err());

        // Missing column and non-Utf8 column both error.
        let missing = RecordBatch::try_new(
            Arc::new(Schema::new(vec![Field::new("other", DataType::Utf8, true)])),
            vec![Arc::new(StringArray::from(vec![Some("x")]))],
        )
        .expect("batch builds");
        assert!(
            collect_single_string_column(&QueryResult::Arrow(vec![missing]), "TABLE_NAME").is_err()
        );

        let wrong_type = RecordBatch::try_new(
            Arc::new(Schema::new(vec![Field::new(
                "TABLE_NAME",
                DataType::Int64,
                false,
            )])),
            vec![Arc::new(Int64Array::from(vec![1i64]))],
        )
        .expect("batch builds");
        assert!(
            collect_single_string_column(&QueryResult::Arrow(vec![wrong_type]), "TABLE_NAME")
                .is_err()
        );
    }

    #[test]
    fn coerce_batch_casts_scale_zero_number_int_to_declared_decimal() {
        use arrow::array::{Int8Array, StringArray};
        use arrow::datatypes::{DataType, Field, Schema};
        use std::sync::Arc;

        // Snowflake sends a scale-0 NUMBER (e.g. n_nationkey) as a compact
        // integer; our discovered schema declares Decimal128(38,0). Coercion
        // must cast the int → decimal (and rename to the declared field) so a
        // downstream primitive downcast doesn't panic ( follow-on).
        let physical = RecordBatch::try_new(
            Arc::new(Schema::new(vec![
                Field::new("N_NATIONKEY", DataType::Int8, false),
                Field::new("N_NAME", DataType::Utf8, true),
            ])),
            vec![
                Arc::new(Int8Array::from(vec![0i8, 1, 24])),
                Arc::new(StringArray::from(vec![
                    Some("ALGERIA"),
                    Some("ARGENTINA"),
                    None,
                ])),
            ],
        )
        .expect("physical batch builds");

        let declared: SchemaRef = Arc::new(Schema::new(vec![
            Field::new("n_nationkey", DataType::Decimal128(38, 0), false),
            Field::new("n_name", DataType::Utf8, true),
        ]));

        let out = coerce_batch_to_schema(&physical, &declared).expect("coerces");
        assert_eq!(out.schema(), declared, "adopts the declared schema + names");
        assert_eq!(
            out.column(0).data_type(),
            &DataType::Decimal128(38, 0),
            "int column cast to the declared decimal"
        );
        let keys = out
            .column(0)
            .as_any()
            .downcast_ref::<arrow::array::Decimal128Array>()
            .expect("now a Decimal128 array — the panic case is gone");
        assert_eq!(keys.value(0), 0);
        assert_eq!(keys.value(2), 24, "value preserved (scale 0, no rescale)");
    }

    #[test]
    fn coerce_batch_passes_matching_columns_through_and_rejects_arity_mismatch() {
        use arrow::array::StringArray;
        use arrow::datatypes::{DataType, Field, Schema};
        use std::sync::Arc;

        let schema: SchemaRef = Arc::new(Schema::new(vec![Field::new(
            "n_name",
            DataType::Utf8,
            true,
        )]));
        let batch = RecordBatch::try_new(
            Arc::new(Schema::new(vec![Field::new(
                "N_NAME",
                DataType::Utf8,
                true,
            )])),
            vec![Arc::new(StringArray::from(vec![Some("BRAZIL")]))],
        )
        .expect("batch builds");
        // Type already matches → only the name is reconciled.
        let out = coerce_batch_to_schema(&batch, &schema).expect("coerces");
        assert_eq!(out.schema(), schema);

        // Column-count disagreement is a loud error, not a silent truncation.
        let two_col = RecordBatch::try_new(
            Arc::new(Schema::new(vec![
                Field::new("A", DataType::Utf8, true),
                Field::new("B", DataType::Utf8, true),
            ])),
            vec![
                Arc::new(StringArray::from(vec![Some("x")])),
                Arc::new(StringArray::from(vec![Some("y")])),
            ],
        )
        .expect("batch builds");
        assert!(coerce_batch_to_schema(&two_col, &schema).is_err());
    }

    #[test]
    fn schema_and_table_lookups_are_case_insensitive() {
        use std::collections::HashMap;
        // The connector registers schema/table names Snowflake-cased (upper);
        // DataFusion resolves references normalised to lower case. Confirm the
        // lookups bridge the two so `snowflake.tpch_sf1.orders` finds
        // `TPCH_SF1` / `ORDERS`.
        let connector = Arc::new(
            SnowflakeConnector::connect("t", sample_config()).expect("client builds offline"),
        );
        let schema: Arc<dyn DfSchemaProvider> = Arc::new(SnowflakeSchema {
            connector: Arc::clone(&connector),
            schema_name: "TPCH_SF1".to_string(),
            table_names: vec!["ORDERS".to_string(), "NATION".to_string()],
        });

        assert!(schema.table_exist("orders"), "lower-case table resolves");
        assert!(schema.table_exist("ORDERS"), "exact case still resolves");
        assert!(schema.table_exist("Nation"), "mixed case resolves");
        assert!(!schema.table_exist("missing"));

        let mut schemas: HashMap<String, Arc<dyn DfSchemaProvider>> = HashMap::new();
        schemas.insert("TPCH_SF1".to_string(), schema);
        let catalog = SnowflakeCatalog {
            connector_name: "t".to_string(),
            schema_names: vec!["TPCH_SF1".to_string()],
            schemas,
        };
        assert!(
            catalog.schema("tpch_sf1").is_some(),
            "lower-case schema resolves"
        );
        assert!(
            catalog.schema("TPCH_SF1").is_some(),
            "exact-case still resolves"
        );
        assert!(catalog.schema("nope").is_none());
    }
}

//! Executor-side catalog configuration for the
//! `dataglot-ballista-executor` binary. Phase 2 slice 5a.2.
//!
//! # Why a parallel config shape
//!
//! The coordinator (`dataglot-server`) reads catalogs from
//! `ServerConfig::catalogs` (TOML, structured by source type).
//! `dataglot-ballista` cannot import `ServerConfig` without breaking
//! the dependency direction in CLAUDE.md rule 4 (sibling crates,
//! coordinator depends on `dataglot-ballista`, not the other way
//! around). For slice 5a.2 we ship a **parallel** JSON-on-disk shape
//! defined in this module — operators maintain a `catalogs.json` for
//! the executor alongside their `dataglot.toml` for the coordinator.
//!
//! This is explicit tech debt: a future refactor will move the
//! catalog-config types to either `dataglot-core` or
//! `dataglot-federation` so both binaries share one shape. The
//! drift risk in the meantime is bounded — registry contents have
//! to match in the two processes (otherwise federation plans decode
//! to a different connector), so any divergence will surface as a
//! Docker-gated integration-test failure.
//!
//! # JSON schema
//!
//! ```json
//! {
//!     "pg_main": {
//!         "type": "postgres",
//!         "dsn": "postgres://user:pass@host:5432/db"
//!     },
//!     "pg_replica": {
//!         "type": "postgres",
//!         "dsn_env": "DG_PG_REPLICA_DSN"
//!     }
//! }
//! ```
//!
//! Exactly one of `dsn` (literal) or `dsn_env` (environment variable
//! name) must be set per Postgres entry — mirrors
//! `PostgresCatalogConfig` on the server side. CLAUDE.md rule 12
//! discourages literal DSNs on disk; `dsn_env` is the production
//! shape.
//!
//! # Supported entry types
//!
//! Mirrors the coordinator's registries: `postgres` SQL sources go
//! into the connector registry, and `warehouse` (Iceberg REST)
//! entries go into the warehouse registry so lakehouse
//! scans decode on the executor. Object-storage sources serialize
//! natively and need no entry. Postgres, MySQL, and Snowflake (pure-Rust
//! SQL sources) plus Warehouse (Iceberg) are always supported.
//!
//! `oracle` and `adbc` entries are supported when the executor
//! is built with the matching `dataglot-ballista` feature
//! (`--features oracle-pure` / `--features adbc`) — Oracle uses the
//! pure-Rust backend, and each executor host must carry the ADBC driver
//! `.so` at the configured `driver_path`. Built without the feature, such
//! an entry fails fast at boot rather than silently downgrading to
//! single-node. The `#[serde(tag = "type")]` enum makes additions
//! non-breaking.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use dataglot_federation::mysql::MysqlConnector;
use dataglot_federation::postgres::PostgresConnector;
use dataglot_federation::{DynConnectorRegistry, InMemoryConnectorRegistry, SQLExecutor};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Parsed catalog config consumed by the executor binary's
/// `--catalogs-config <PATH>` flag.
///
/// Top-level shape is a flat `HashMap<String, CatalogEntry>` — the
/// catalog NAME is the map key, the source SHAPE is in the value.
/// See module doc for the JSON example.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CatalogsConfig {
    /// Catalog name → source configuration.
    pub entries: HashMap<String, CatalogEntry>,
}

/// One catalog source. Tagged by `type` so future SQL sources
/// (`mysql`, `snowflake`, ...) land non-breaking.
///
/// `postgres`, `mysql`, `snowflake`, and `warehouse` are supported on
/// the executor side — matching the coordinator's
/// `build_executor_registry` shape. Adding a new SQL source means (a)
/// the matching `SQLExecutor` impl in `dataglot-federation`, (b) a new
/// variant here, and (c) a dispatch arm in
/// [`CatalogsConfig::into_registries`].
///
/// `Debug` redacts secret material (DSNs may carry passwords); the
/// env-var **name** is shown (not itself secret).
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CatalogEntry {
    /// PostgreSQL via `tokio-postgres`. Mirrors
    /// `dataglot-server::config::PostgresCatalogConfig`.
    Postgres {
        /// Literal libpq DSN. Mutually exclusive with `dsn_env`.
        #[serde(default)]
        dsn: Option<String>,
        /// Environment-variable name carrying the DSN. Resolved at
        /// boot; never logged. Mutually exclusive with `dsn`.
        #[serde(default)]
        dsn_env: Option<String>,
    },
    /// MySQL via `mysql_async`. Mirrors
    /// `dataglot-server::config::MysqlCatalogConfig` so the executor
    /// rebuilds the same connector the coordinator registered under
    /// this name — required for a `mysql_demo` federated plan to decode
    /// on the worker instead of evicting the executor.
    Mysql {
        /// Literal MySQL DSN (`mysql://user:pass@host:port/db`).
        /// Mutually exclusive with `dsn_env`.
        #[serde(default)]
        dsn: Option<String>,
        /// Environment-variable name carrying the DSN. Resolved at
        /// boot; never logged. Mutually exclusive with `dsn`.
        #[serde(default)]
        dsn_env: Option<String>,
    },
    /// Snowflake via `snowflake-api` ( follow-up). Mirrors
    /// `dataglot-server::config::SnowflakeCatalogConfig` so the executor
    /// rebuilds the same connector the coordinator registered under this
    /// name — required for a Snowflake federated plan to decode on the
    /// worker instead of evicting it. Snowflake is pure-Rust and always
    /// compiled, so it distributes like Postgres/MySQL (the coordinator's
    /// `build_executor_registry` already registers it single-process).
    Snowflake {
        /// Account identifier (e.g. `ORG-ACCOUNT`). Appears in the public
        /// Snowsight URL — not a credential.
        account: String,
        /// Compute warehouse.
        warehouse: String,
        /// Default database.
        database: String,
        /// Service-account username.
        user: String,
        /// Literal password. Mutually exclusive with `password_env`; a
        /// dev/test escape hatch (rule 12 discourages literals on disk).
        #[serde(default)]
        password: Option<String>,
        /// Environment-variable name carrying the password. Resolved at
        /// boot; never logged. Mutually exclusive with `password`.
        #[serde(default)]
        password_env: Option<String>,
        /// Optional default schema for unqualified references.
        #[serde(default)]
        schema: Option<String>,
        /// Optional warehouse-role override.
        #[serde(default)]
        role: Option<String>,
    },
    /// Oracle via the pure-Rust backend. Mirrors the
    /// `SQLExecutor` half of `dataglot-server::config::OracleCatalogConfig`
    /// so the executor rebuilds the same connector the coordinator
    /// registered under this name — required for an Oracle federated plan
    /// fragment to decode on the worker instead of evicting it.
    ///
    /// Only the fields `OracleConnector::connect` consumes appear here
    /// (`dsn` / `user` / password); the catalog-provider-only `schema`
    /// and the OCI/`driver` selection do not — a distributed executor
    /// always uses the compiled-in **pure-Rust** backend (the executor
    /// build never links the OCI Instant Client). Building the executor
    /// without `--features oracle-pure` turns an `oracle` entry into a
    /// fail-fast boot error rather than a silent single-node fallback.
    Oracle {
        /// Oracle Easy Connect DSN, e.g. `//db.internal:1521/ORCLPDB1`.
        /// No credentials embedded.
        dsn: String,
        /// Service-account username (Oracle folds unquoted to uppercase).
        user: String,
        /// Literal password. Mutually exclusive with `password_env`; a
        /// dev/test escape hatch (rule 12 discourages literals on disk).
        #[serde(default)]
        password: Option<String>,
        /// Environment-variable name carrying the password. Resolved at
        /// boot; never logged. Mutually exclusive with `password`.
        #[serde(default)]
        password_env: Option<String>,
    },
    /// ADBC BYO-driver source. Mirrors
    /// `dataglot-server::config::AdbcCatalogConfig` so the executor
    /// rebuilds the same connector the coordinator registered under this
    /// name. Unlike the pure-Rust SQL sources, **every executor host must
    /// have the driver `.so` at `driver_path`** — the connector dlopen's
    /// it locally. Building the executor without `--features adbc`, or a
    /// host missing the driver, turns an `adbc` entry into a fail-fast
    /// boot error.
    Adbc {
        /// Path to the ADBC driver shared library on this executor host.
        driver_path: String,
        /// Driver init symbol override (e.g. `duckdb_adbc_init`).
        #[serde(default)]
        driver_entrypoint: Option<String>,
        /// Connection URI (standard ADBC `uri` option).
        #[serde(default)]
        uri: Option<String>,
        /// Username (standard ADBC `username` option).
        #[serde(default)]
        username: Option<String>,
        /// Env-var name holding the password. Resolved by the connector
        /// at connect time; never stored or logged.
        #[serde(default)]
        password_env: Option<String>,
        /// Extra driver options as `key=value;key=value` (secret values).
        #[serde(default)]
        driver_options: Option<String>,
        /// Source-side catalog scope.
        #[serde(default)]
        catalog: Option<String>,
        /// Source-side schema scope.
        #[serde(default)]
        schema: Option<String>,
        /// SQL dialect for federation unparsing (validated at boot).
        dialect: String,
        /// Pool size — max concurrent in-flight queries on this catalog.
        #[serde(default = "default_adbc_pool_size")]
        connection_pool_size: usize,
        /// Connections opened eagerly at boot; the rest open lazily.
        #[serde(default = "default_adbc_pool_min_idle")]
        connection_pool_min_idle: usize,
    },
    /// Iceberg warehouse via a REST catalog. Mirrors
    /// `dataglot-server::config::WarehouseCatalogConfig` so the
    /// executor can rebuild the same connector the coordinator
    /// registered under this name.
    Warehouse {
        /// REST catalog base URL (e.g. `http://lakekeeper:8181/catalog`).
        catalog_url: String,
        /// Warehouse name within the catalog.
        warehouse: String,
        /// Static-credential access key. Omitted ⇒ credentials come
        /// from the standard AWS environment variables.
        #[serde(default)]
        access_key_id: Option<String>,
        /// Literal secret. Mutually exclusive with
        /// `secret_access_key_env`; dev/test escape hatch only.
        #[serde(default)]
        secret_access_key: Option<String>,
        /// Environment-variable name carrying the secret. Resolved at
        /// boot; never logged.
        #[serde(default)]
        secret_access_key_env: Option<String>,
        /// S3-compatible endpoint override (MinIO/RustFS).
        #[serde(default)]
        s3_endpoint: Option<String>,
        /// S3 region.
        #[serde(default)]
        s3_region: Option<String>,
    },
}

/// Spec default: 4 pooled connections per ADBC catalog. Mirrors the
/// server-side `default_adbc_pool_size` so the executor entry defaults
/// identically when omitted.
fn default_adbc_pool_size() -> usize {
    4
}

/// Spec default: 1 eager connection. Mirrors the server-side
/// `default_adbc_pool_min_idle`.
fn default_adbc_pool_min_idle() -> usize {
    1
}

impl std::fmt::Debug for CatalogEntry {
    #[allow(clippy::too_many_lines)] // one redaction arm per catalog kind
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Postgres { dsn, dsn_env } => f
                .debug_struct("CatalogEntry::Postgres")
                .field(
                    "dsn",
                    &if dsn.is_some() {
                        "<redacted>"
                    } else {
                        "<unset>"
                    },
                )
                .field("dsn_env", dsn_env)
                .finish(),
            Self::Mysql { dsn, dsn_env } => f
                .debug_struct("CatalogEntry::Mysql")
                .field(
                    "dsn",
                    &if dsn.is_some() {
                        "<redacted>"
                    } else {
                        "<unset>"
                    },
                )
                .field("dsn_env", dsn_env)
                .finish(),
            Self::Snowflake {
                account,
                warehouse,
                database,
                // Redacted below with literals, so the bindings go unused.
                user: _,
                password,
                password_env,
                schema,
                role: _,
            } => f
                .debug_struct("CatalogEntry::Snowflake")
                .field("account", account)
                .field("warehouse", warehouse)
                .field("database", database)
                .field("schema", schema)
                // Auth-adjacent fields redacted (rule 12), matching the
                // server's SnowflakeCatalogConfig Debug.
                .field("user", &"<redacted>")
                .field("role", &"<redacted>")
                .field(
                    "password",
                    &if password.is_some() {
                        "<redacted>"
                    } else {
                        "<unset>"
                    },
                )
                .field("password_env", password_env)
                .finish(),
            Self::Oracle {
                dsn,
                // Auth fields redacted below with literals; bindings unused.
                user: _,
                password,
                password_env,
            } => f
                .debug_struct("CatalogEntry::Oracle")
                // The Easy Connect DSN carries no credentials (matches the
                // server's OracleCatalogConfig Debug), so it stays visible.
                .field("dsn", dsn)
                .field("user", &"<redacted>")
                .field(
                    "password",
                    &if password.is_some() {
                        "<redacted>"
                    } else {
                        "<unset>"
                    },
                )
                .field("password_env", password_env)
                .finish(),
            Self::Adbc {
                driver_path,
                driver_entrypoint,
                uri,
                // Auth-adjacent / secret-bearing fields redacted below.
                username: _,
                password_env,
                driver_options,
                catalog,
                schema,
                dialect,
                connection_pool_size,
                connection_pool_min_idle,
            } => f
                .debug_struct("CatalogEntry::Adbc")
                .field("driver_path", driver_path)
                .field("driver_entrypoint", driver_entrypoint)
                .field("uri", uri)
                .field("username", &"<redacted>")
                .field("password_env", password_env)
                // driver_options values are treated as secrets (rule 12),
                // matching the server's AdbcCatalogConfig Debug.
                .field(
                    "driver_options",
                    &if driver_options.is_some() {
                        "<redacted>"
                    } else {
                        "<unset>"
                    },
                )
                .field("catalog", catalog)
                .field("schema", schema)
                .field("dialect", dialect)
                .field("connection_pool_size", connection_pool_size)
                .field("connection_pool_min_idle", connection_pool_min_idle)
                .finish(),
            Self::Warehouse {
                catalog_url,
                warehouse,
                access_key_id,
                secret_access_key,
                secret_access_key_env,
                s3_endpoint,
                s3_region,
            } => f
                .debug_struct("CatalogEntry::Warehouse")
                .field("catalog_url", catalog_url)
                .field("warehouse", warehouse)
                .field(
                    "access_key_id",
                    &if access_key_id.is_some() {
                        "<redacted>"
                    } else {
                        "<unset>"
                    },
                )
                .field(
                    "secret_access_key",
                    &if secret_access_key.is_some() {
                        "<redacted>"
                    } else {
                        "<unset>"
                    },
                )
                .field("secret_access_key_env", secret_access_key_env)
                .field("s3_endpoint", s3_endpoint)
                .field("s3_region", s3_region)
                .finish(),
        }
    }
}

/// Errors raised when loading the catalogs config or building a
/// registry from it.
///
/// Surfaces at executor boot via the fail-fast path — the same
/// CLAUDE.md rule 12 redaction principle applies: error variants
/// carry the offending catalog *name* (and env-var *name*) but
/// never the DSN payload.
#[derive(Debug, Error)]
pub enum CatalogsConfigError {
    /// Could not read the config file from disk.
    #[error("could not read catalogs config from `{path}`: {source}")]
    Io {
        /// Path the executor was asked to read.
        path: String,
        /// Underlying IO failure.
        source: std::io::Error,
    },
    /// File contents were not valid JSON or did not match the
    /// expected schema (missing fields, unknown `type` tag).
    #[error("could not parse catalogs config from `{path}`: {source}")]
    Parse {
        /// Path the executor was asked to read.
        path: String,
        /// Underlying serde failure.
        source: serde_json::Error,
    },
    /// Warehouse credential misconfiguration: secret
    /// literal/env conflict, missing env var, or a secret without an
    /// access key.
    #[error("catalog `{name}`: {message}")]
    Credential {
        /// Catalog name.
        name: String,
        /// What was wrong (never contains secret material).
        message: String,
    },
    /// `dsn` and `dsn_env` both set or both unset. Exactly one
    /// must be specified per entry.
    #[error("catalog `{name}`: exactly one of `dsn` or `dsn_env` must be set, got both/neither")]
    DsnConflict {
        /// Catalog name that triggered the conflict.
        name: String,
    },
    /// `dsn_env` named an environment variable that wasn't set
    /// (or wasn't valid UTF-8).
    #[error("catalog `{name}`: env var `{var}` is not set")]
    DsnEnvMissing {
        /// Catalog name.
        name: String,
        /// Env-var name that wasn't set. The name itself is not
        /// sensitive — only its value would be.
        var: String,
    },
    /// Live connection attempt to the SQL source failed at boot.
    /// Carries the catalog name so operators can match up to their
    /// config; the underlying error message is filtered through
    /// `PostgresConnector`'s own redaction (slice 4c.B's
    /// SQLSTATE-surfacing fix).
    #[error("catalog `{name}`: connection failed at boot: {message}")]
    Connect {
        /// Catalog name that failed to connect.
        name: String,
        /// Connector-side error message. Already credential-redacted
        /// per the SQLSTATE-surfacing rule.
        message: String,
    },
}

impl CatalogsConfig {
    /// Load and parse the catalogs config from disk.
    ///
    /// # Errors
    /// - [`CatalogsConfigError::Io`] if the file is unreadable.
    /// - [`CatalogsConfigError::Parse`] on JSON / schema failure.
    pub fn from_json_file(path: impl AsRef<Path>) -> Result<Self, CatalogsConfigError> {
        let path = path.as_ref();
        let bytes = std::fs::read(path).map_err(|source| CatalogsConfigError::Io {
            path: path.display().to_string(),
            source,
        })?;
        serde_json::from_slice(&bytes).map_err(|source| CatalogsConfigError::Parse {
            path: path.display().to_string(),
            source,
        })
    }

    /// Resolve every entry into a live `SQLExecutor` and stuff them
    /// into an `InMemoryConnectorRegistry`.
    ///
    /// Async because each `PostgresConnector::connect(...)` opens a
    /// `tokio-postgres` connection at boot. Matches the coordinator
    /// side's `build_executor_registry` shape so the registry the
    /// executor builds is byte-equivalent to the coordinator's
    /// (same catalog names, same connector kind per name) — that's
    /// what makes federation plans decodable on both sides.
    ///
    /// # Errors
    /// - [`CatalogsConfigError::DsnConflict`] if both `dsn` and
    ///   `dsn_env` are set, or neither.
    /// - [`CatalogsConfigError::DsnEnvMissing`] if `dsn_env` names
    ///   an unset variable.
    /// - [`CatalogsConfigError::Connect`] if the connection
    ///   attempt fails.
    pub async fn into_registry(self) -> Result<DynConnectorRegistry, CatalogsConfigError> {
        Ok(self.into_registries().await?.0)
    }

    /// Resolve every entry into its live connector: SQL sources into
    /// an `InMemoryConnectorRegistry`, warehouse (Iceberg) entries
    /// into a [`WarehouseRegistry`]. Both registries must
    /// mirror the coordinator's `[catalogs.*]` names — that agreement
    /// is what makes plans decodable on both sides.
    ///
    /// [`WarehouseRegistry`]: dataglot_federation::iceberg::WarehouseRegistry
    ///
    /// # Errors
    /// Same surface as [`Self::into_registry`], plus
    /// [`CatalogsConfigError::Credential`] for warehouse secret
    /// misconfiguration.
    #[allow(clippy::too_many_lines)] // one dispatch arm per catalog kind
    pub async fn into_registries(
        self,
    ) -> Result<
        (
            DynConnectorRegistry,
            dataglot_federation::iceberg::DynWarehouseRegistry,
        ),
        CatalogsConfigError,
    > {
        let mut executors: HashMap<String, Arc<dyn SQLExecutor>> =
            HashMap::with_capacity(self.entries.len());
        let mut warehouses = HashMap::new();
        for (name, entry) in self.entries {
            match entry {
                CatalogEntry::Postgres { dsn, dsn_env } => {
                    let resolved_dsn = resolve_dsn(&name, dsn.as_deref(), dsn_env.as_deref())?;
                    let connector = PostgresConnector::connect(&resolved_dsn)
                        .await
                        .map_err(|e| {
                            // PostgresConnector's error is already
                            // credential-redacted (slice 4c.B's
                            // diagnostic fix surfaces SQLSTATE +
                            // severity + message, no DSN).
                            CatalogsConfigError::Connect {
                                name: name.clone(),
                                message: e.to_string(),
                            }
                        })?
                        //: label pushdown telemetry with the catalog
                        // name (executor-side), not the DSN.
                        .with_catalog(name.clone());
                    executors.insert(name, Arc::new(connector));
                }
                CatalogEntry::Mysql { dsn, dsn_env } => {
                    let resolved_dsn = resolve_dsn(&name, dsn.as_deref(), dsn_env.as_deref())?;
                    let connector = MysqlConnector::connect(name.clone(), &resolved_dsn)
                        .await
                        .map_err(|e| CatalogsConfigError::Connect {
                            name: name.clone(),
                            // MysqlConnector redacts credentials from its
                            // error surface (rule 12), same as Postgres.
                            message: e.to_string(),
                        })?;
                    executors.insert(name, Arc::new(connector));
                }
                CatalogEntry::Snowflake {
                    account,
                    warehouse,
                    database,
                    user,
                    password,
                    password_env,
                    schema,
                    role,
                } => {
                    let resolved_password = resolve_password_source(&name, password, password_env)?;
                    let cfg = dataglot_federation::snowflake::SnowflakeConfig {
                        account,
                        warehouse,
                        database,
                        user,
                        password: resolved_password,
                        private_key_pem: None,
                        schema,
                        role,
                    };
                    // `connect` builds the REST client offline (auth fires on
                    // the first query), so this is synchronous — mirrors the
                    // coordinator's `build_executor_registry` Snowflake arm.
                    let connector = dataglot_federation::snowflake::SnowflakeConnector::connect(
                        name.clone(),
                        cfg,
                    )
                    .map_err(|e| CatalogsConfigError::Connect {
                        name: name.clone(),
                        message: e.to_string(),
                    })?;
                    executors.insert(name, Arc::new(connector));
                }
                CatalogEntry::Oracle {
                    dsn,
                    user,
                    password,
                    password_env,
                } => {
                    // Distributed Oracle uses the compiled-in pure-Rust
                    // backend only (the executor never links OCI). Present
                    // but un-compiled ⇒ fail fast rather than silently drop.
                    #[cfg(feature = "oracle-pure")]
                    {
                        let resolved = resolve_password_source(&name, password, password_env)?;
                        let connector = dataglot_federation::oracle::OracleConnector::connect(
                            name.clone(),
                            &dsn,
                            &user,
                            &resolved,
                        )
                        .await
                        .map_err(|e| CatalogsConfigError::Connect {
                            name: name.clone(),
                            // OracleConnector redacts DSN + password from its
                            // error surface (rule 12), like Postgres/MySQL.
                            message: e.to_string(),
                        })?;
                        executors.insert(name, Arc::new(connector));
                    }
                    #[cfg(not(feature = "oracle-pure"))]
                    {
                        let _ = (&dsn, &user, &password, &password_env);
                        return Err(CatalogsConfigError::Credential {
                            name: name.clone(),
                            message: "oracle catalog present but this executor was \
                                      built without `--features oracle-pure`"
                                .to_string(),
                        });
                    }
                }
                CatalogEntry::Adbc {
                    driver_path,
                    driver_entrypoint,
                    uri,
                    username,
                    password_env,
                    driver_options,
                    catalog,
                    schema,
                    dialect,
                    connection_pool_size,
                    connection_pool_min_idle,
                } => {
                    #[cfg(feature = "adbc")]
                    {
                        use dataglot_federation::adbc::{
                            AdbcConfig, AdbcConnector, SupportedDialect,
                        };
                        let parsed_dialect: SupportedDialect =
                            dialect
                                .parse()
                                .map_err(|_| CatalogsConfigError::Credential {
                                    name: name.clone(),
                                    message: format!("invalid adbc dialect `{dialect}`"),
                                })?;
                        let mut cfg = AdbcConfig::new(name.clone(), driver_path, parsed_dialect);
                        cfg.driver_entrypoint = driver_entrypoint;
                        cfg.uri = uri;
                        cfg.username = username;
                        cfg.password_env = password_env;
                        cfg.driver_options = driver_options;
                        cfg.catalog = catalog;
                        cfg.schema = schema;
                        cfg.connection_pool_size = connection_pool_size;
                        cfg.connection_pool_min_idle = connection_pool_min_idle;
                        let connector = AdbcConnector::connect(cfg).await.map_err(|e| {
                            CatalogsConfigError::Connect {
                                name: name.clone(),
                                message: e.to_string(),
                            }
                        })?;
                        executors.insert(name, Arc::new(connector));
                    }
                    #[cfg(not(feature = "adbc"))]
                    {
                        let _ = (
                            &driver_path,
                            &driver_entrypoint,
                            &uri,
                            &username,
                            &password_env,
                            &driver_options,
                            &catalog,
                            &schema,
                            &dialect,
                            &connection_pool_size,
                            &connection_pool_min_idle,
                        );
                        return Err(CatalogsConfigError::Credential {
                            name: name.clone(),
                            message: "adbc catalog present but this executor was \
                                      built without `--features adbc`"
                                .to_string(),
                        });
                    }
                }
                CatalogEntry::Warehouse {
                    catalog_url,
                    warehouse,
                    access_key_id,
                    secret_access_key,
                    secret_access_key_env,
                    s3_endpoint,
                    s3_region,
                } => {
                    let credentials = resolve_warehouse_credentials(
                        &name,
                        access_key_id,
                        secret_access_key,
                        secret_access_key_env,
                    )?;
                    let cfg = dataglot_federation::iceberg::WarehouseConfig {
                        catalog_url,
                        warehouse,
                        credentials,
                        s3_endpoint,
                        s3_region,
                    };
                    let connector =
                        dataglot_federation::iceberg::WarehouseConnector::connect(&name, cfg)
                            .await
                            .map_err(|e| CatalogsConfigError::Connect {
                                name: name.clone(),
                                message: e.to_string(),
                            })?;
                    warehouses.insert(name, Arc::new(connector));
                }
            }
        }
        Ok((
            Arc::new(InMemoryConnectorRegistry::new(executors)),
            Arc::new(dataglot_federation::iceberg::WarehouseRegistry::new(
                warehouses,
            )),
        ))
    }
}

/// Resolve warehouse credentials per the same indirection rule as
/// DSNs: literal XOR env, and `access_key_id` present ⇔ static mode.
/// Resolve a password from a literal or an env-var name — exactly one must be
/// set. Shared by the Snowflake and Oracle arms (identical rule). Rule 12: the
/// error carries only the env-var *name*, never the secret value.
fn resolve_password_source(
    name: &str,
    password: Option<String>,
    password_env: Option<String>,
) -> Result<String, CatalogsConfigError> {
    match (password, password_env) {
        (Some(_), Some(_)) => Err(CatalogsConfigError::Credential {
            name: name.to_string(),
            message: "set exactly one of `password` or `password_env`".to_string(),
        }),
        (Some(p), None) => Ok(p),
        (None, Some(env)) => std::env::var(&env).map_err(|_| CatalogsConfigError::Credential {
            name: name.to_string(),
            message: format!("password_env `{env}` is unset"),
        }),
        (None, None) => Err(CatalogsConfigError::Credential {
            name: name.to_string(),
            message: "set one of `password` or `password_env`".to_string(),
        }),
    }
}

fn resolve_warehouse_credentials(
    name: &str,
    access_key_id: Option<String>,
    secret_access_key: Option<String>,
    secret_access_key_env: Option<String>,
) -> Result<dataglot_federation::iceberg::WarehouseCredentials, CatalogsConfigError> {
    let Some(access_key_id) = access_key_id else {
        if secret_access_key.is_some() || secret_access_key_env.is_some() {
            return Err(CatalogsConfigError::Credential {
                name: name.to_string(),
                message: "secret provided without `access_key_id`".to_string(),
            });
        }
        return Ok(dataglot_federation::iceberg::WarehouseCredentials::Environment);
    };
    let secret = match (secret_access_key, secret_access_key_env) {
        (Some(s), None) => s,
        (None, Some(var)) => std::env::var(&var).map_err(|_| CatalogsConfigError::Credential {
            name: name.to_string(),
            message: format!("env var `{var}` is not set"),
        })?,
        _ => {
            return Err(CatalogsConfigError::Credential {
                name: name.to_string(),
                message: "exactly one of `secret_access_key` or \
                          `secret_access_key_env` must be set"
                    .to_string(),
            })
        }
    };
    Ok(dataglot_federation::iceberg::WarehouseCredentials::Static {
        access_key_id,
        secret_access_key: secret,
    })
}

/// Resolve a Postgres entry's DSN per the `dsn` / `dsn_env`
/// indirection rule.
/// Resolve a SQL source's DSN from the literal-XOR-env indirection.
/// Shared by the Postgres and MySQL arms (the rule is identical).
fn resolve_dsn(
    name: &str,
    dsn: Option<&str>,
    dsn_env: Option<&str>,
) -> Result<String, CatalogsConfigError> {
    match (dsn, dsn_env) {
        (Some(d), None) => Ok(d.to_string()),
        (None, Some(var)) => std::env::var(var).map_err(|_| CatalogsConfigError::DsnEnvMissing {
            name: name.to_string(),
            var: var.to_string(),
        }),
        // Both set, or both missing — same error shape.
        _ => Err(CatalogsConfigError::DsnConflict {
            name: name.to_string(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// JSON round-trip — happy path with a single Postgres entry.
    #[test]
    fn config_parses_single_postgres_entry() {
        let json = r#"{
            "pg_main": {
                "type": "postgres",
                "dsn": "postgres://u:p@h/db"
            }
        }"#;
        let cfg: CatalogsConfig = serde_json::from_str(json).expect("parses");
        assert_eq!(cfg.entries.len(), 1);
        let entry = cfg.entries.get("pg_main").expect("pg_main present");
        match entry {
            CatalogEntry::Postgres { dsn, dsn_env } => {
                assert_eq!(dsn.as_deref(), Some("postgres://u:p@h/db"));
                assert!(dsn_env.is_none());
            }
            other => {
                panic!("expected postgres entry, got {other:?}")
            }
        }
    }

    ///  — warehouse entries parse with the full config shape,
    /// and credential misconfigurations error with the catalog name.
    #[test]
    fn config_parses_warehouse_entry() {
        let json = r#"{
            "lakehouse": {
                "type": "warehouse",
                "catalog_url": "http://lakekeeper:8181/catalog",
                "warehouse": "main",
                "access_key_id": "minioadmin",
                "secret_access_key_env": "DEMO_MINIO_SECRET",
                "s3_endpoint": "http://minio:9000",
                "s3_region": "us-east-1"
            }
        }"#;
        let cfg: CatalogsConfig = serde_json::from_str(json).expect("parses");
        match cfg.entries.get("lakehouse").expect("present") {
            CatalogEntry::Warehouse {
                catalog_url,
                warehouse,
                access_key_id,
                secret_access_key_env,
                ..
            } => {
                assert_eq!(catalog_url, "http://lakekeeper:8181/catalog");
                assert_eq!(warehouse, "main");
                assert_eq!(access_key_id.as_deref(), Some("minioadmin"));
                assert_eq!(secret_access_key_env.as_deref(), Some("DEMO_MINIO_SECRET"));
            }
            other => {
                panic!("expected warehouse entry, got {other:?}")
            }
        }
    }

    #[test]
    fn config_parses_mysql_entry() {
        //: the executor must rebuild a MySQL connector for a
        // `mysql_demo` plan or the scheduler evicts it as "failed".
        let json = r#"{
            "mysql_demo": { "type": "mysql", "dsn_env": "DEMO_MYSQL_DSN" }
        }"#;
        let cfg: CatalogsConfig = serde_json::from_str(json).expect("parses");
        match cfg.entries.get("mysql_demo").expect("present") {
            CatalogEntry::Mysql { dsn, dsn_env } => {
                assert!(dsn.is_none());
                assert_eq!(dsn_env.as_deref(), Some("DEMO_MYSQL_DSN"));
            }
            other => panic!("expected mysql entry, got {other:?}"),
        }
    }

    ///  — warehouse credential rule: access key without any
    /// secret, secret without access key, and both secret forms at
    /// once are all typed errors naming the catalog.
    #[test]
    fn warehouse_credentials_misconfigurations_error() {
        let both = resolve_warehouse_credentials(
            "lh",
            Some("k".into()),
            Some("s".into()),
            Some("VAR".into()),
        );
        assert!(matches!(
            both,
            Err(CatalogsConfigError::Credential { ref name, .. }) if name == "lh"
        ));
        let neither = resolve_warehouse_credentials("lh", Some("k".into()), None, None);
        assert!(matches!(
            neither,
            Err(CatalogsConfigError::Credential { .. })
        ));
        let secret_no_key = resolve_warehouse_credentials("lh", None, Some("s".into()), None);
        assert!(matches!(
            secret_no_key,
            Err(CatalogsConfigError::Credential { .. })
        ));
        // No access key + no secrets = environment credentials.
        let env = resolve_warehouse_credentials("lh", None, None, None).expect("environment mode");
        assert!(matches!(
            env,
            dataglot_federation::iceberg::WarehouseCredentials::Environment
        ));
    }

    /// JSON round-trip — `dsn_env` indirection.
    #[test]
    fn config_parses_dsn_env_indirection() {
        let json = r#"{
            "pg_main": { "type": "postgres", "dsn_env": "PG_MAIN_DSN" }
        }"#;
        let cfg: CatalogsConfig = serde_json::from_str(json).expect("parses");
        let entry = cfg.entries.get("pg_main").expect("pg_main present");
        match entry {
            CatalogEntry::Postgres { dsn, dsn_env } => {
                assert!(dsn.is_none());
                assert_eq!(dsn_env.as_deref(), Some("PG_MAIN_DSN"));
            }
            other => {
                panic!("expected postgres entry, got {other:?}")
            }
        }
    }

    /// Empty top-level object is valid — operator chose to run the
    /// executor with no catalogs (smoke / TPC-H mode). Yields an
    /// empty registry.
    #[tokio::test]
    async fn empty_config_yields_empty_registry() {
        let cfg: CatalogsConfig = serde_json::from_str("{}").expect("parses");
        let registry = cfg
            .into_registry()
            .await
            .expect("empty registry never fails");
        assert_eq!(registry.len(), 0);
    }

    /// Unknown `type` tag must surface as a parse error. Future
    /// SQL-source additions get explicit variants; an unknown tag
    /// in a config file means the executor is older than the
    /// config — fail-fast at parse time.
    #[test]
    fn unknown_entry_type_tag_is_a_parse_error() {
        let json = r#"{
            "cool": { "type": "mysql8", "dsn": "..." }
        }"#;
        let err =
            serde_json::from_str::<CatalogsConfig>(json).expect_err("unknown type tag must error");
        let msg = format!("{err}");
        assert!(
            msg.contains("mysql8"),
            "error should name the unknown variant: {msg}"
        );
    }

    /// `from_json_file` — missing path surfaces an IO error
    /// carrying the offending path.
    #[test]
    fn from_json_file_missing_path_errors() {
        let bogus = "/tmp/never-exists-catalogs-5a2-9999.json";
        let Err(err) = CatalogsConfig::from_json_file(bogus) else {
            panic!("missing file must error")
        };
        match err {
            CatalogsConfigError::Io { path, .. } => assert_eq!(path, bogus),
            CatalogsConfigError::Parse { .. } => panic!("expected Io, got Parse"),
            CatalogsConfigError::DsnConflict { .. }
            | CatalogsConfigError::DsnEnvMissing { .. }
            | CatalogsConfigError::Credential { .. }
            | CatalogsConfigError::Connect { .. } => panic!("expected Io error variant"),
        }
    }

    /// `from_json_file` — malformed JSON surfaces a Parse error
    /// carrying the offending path.
    #[test]
    fn from_json_file_malformed_json_errors() {
        let tmp = std::env::temp_dir().join("dataglot-catalogs-malformed-5a2.json");
        std::fs::write(&tmp, b"{ not valid").expect("write tmp");
        let Err(err) = CatalogsConfig::from_json_file(&tmp) else {
            panic!("malformed JSON must error")
        };
        match err {
            CatalogsConfigError::Parse { path, .. } => {
                assert_eq!(path, tmp.display().to_string());
            }
            CatalogsConfigError::Io { .. } => panic!("expected Parse, got Io"),
            CatalogsConfigError::DsnConflict { .. }
            | CatalogsConfigError::DsnEnvMissing { .. }
            | CatalogsConfigError::Credential { .. }
            | CatalogsConfigError::Connect { .. } => panic!("expected Parse error variant"),
        }
        let _ = std::fs::remove_file(&tmp);
    }

    /// DSN-conflict: both `dsn` and `dsn_env` set. Must error at
    /// registry-build time. The catalog name appears in the error
    /// so operators can match up to their config; the DSN payload
    /// does NOT.
    #[tokio::test]
    async fn dsn_and_dsn_env_both_set_is_an_error() {
        let mut entries = HashMap::new();
        entries.insert(
            "pg_main".to_string(),
            CatalogEntry::Postgres {
                dsn: Some("postgres://u:hunter2@h/db".into()),
                dsn_env: Some("PG_MAIN_DSN".into()),
            },
        );
        let cfg = CatalogsConfig { entries };
        let Err(err) = cfg.into_registry().await else {
            panic!("dsn-conflict must error")
        };
        let msg = format!("{err}");
        assert!(msg.contains("pg_main"), "name should appear: {msg}");
        assert!(
            !msg.contains("hunter2"),
            "DSN payload must not leak through error: {msg}"
        );
    }

    /// Neither `dsn` nor `dsn_env` set — same error variant as the
    /// both-set case. Operators get one diagnostic message shape
    /// regardless of which way they misconfigured.
    #[tokio::test]
    async fn dsn_and_dsn_env_both_unset_is_an_error() {
        let mut entries = HashMap::new();
        entries.insert(
            "pg_main".to_string(),
            CatalogEntry::Postgres {
                dsn: None,
                dsn_env: None,
            },
        );
        let cfg = CatalogsConfig { entries };
        let Err(err) = cfg.into_registry().await else {
            panic!("both-unset must error")
        };
        assert!(matches!(err, CatalogsConfigError::DsnConflict { .. }));
    }

    /// `dsn_env` pointing at an unset env var — surfaces as a
    /// typed error naming the env-var (which is not itself
    /// sensitive).
    #[tokio::test]
    async fn dsn_env_unset_is_an_error() {
        let mut entries = HashMap::new();
        entries.insert(
            "pg_main".to_string(),
            CatalogEntry::Postgres {
                dsn: None,
                dsn_env: Some("DEFINITELY_NOT_SET_DG_5A2_TEST_VAR".into()),
            },
        );
        let cfg = CatalogsConfig { entries };
        let Err(err) = cfg.into_registry().await else {
            panic!("missing env var must error")
        };
        match err {
            CatalogsConfigError::DsnEnvMissing { name, var } => {
                assert_eq!(name, "pg_main");
                assert_eq!(var, "DEFINITELY_NOT_SET_DG_5A2_TEST_VAR");
            }
            other => panic!("expected DsnEnvMissing, got {other:?}"),
        }
    }

    /// Defensive: `CatalogEntry::Debug` must redact the DSN. This
    /// is the second mass-redaction surface (CLAUDE.md rule 12) —
    /// the first lives on `CredentialConfigEntry`.
    #[test]
    fn entry_debug_redacts_dsn() {
        let entry = CatalogEntry::Postgres {
            dsn: Some("postgres://u:hunter2@h/db".into()),
            dsn_env: None,
        };
        let dbg = format!("{entry:?}");
        assert!(!dbg.contains("hunter2"), "DSN leaked: {dbg}");
        assert!(dbg.contains("redacted"));
    }

    /// Rule-12 redaction on the MySQL variant — the DSN carries
    /// the password and must never render.
    #[test]
    fn mysql_entry_debug_redacts_dsn() {
        let entry = CatalogEntry::Mysql {
            dsn: Some("mysql://u:hunter2@h:3306/db".into()),
            dsn_env: None,
        };
        let dbg = format!("{entry:?}");
        assert!(!dbg.contains("hunter2"), "MySQL DSN leaked: {dbg}");
        assert!(dbg.contains("redacted"));
    }

    /// Rule-12 redaction on the Warehouse variant — the literal
    /// `secret_access_key` is the sensitive half; the env-var *name* and
    /// non-secret fields (`catalog_url`, `access_key_id`) may show.
    #[test]
    fn warehouse_entry_debug_redacts_secret_access_key() {
        let entry = CatalogEntry::Warehouse {
            catalog_url: "http://lakekeeper:8181/catalog".into(),
            warehouse: "wh".into(),
            access_key_id: Some("AKIAEXAMPLE".into()),
            secret_access_key: Some("top-secret-material".into()),
            secret_access_key_env: None,
            s3_endpoint: None,
            s3_region: None,
        };
        let dbg = format!("{entry:?}");
        assert!(
            !dbg.contains("top-secret-material"),
            "secret_access_key leaked: {dbg}"
        );
        assert!(dbg.contains("redacted"));
        // Non-secret fields are still visible for diagnostics.
        assert!(dbg.contains("lakekeeper"), "catalog_url should show: {dbg}");
    }

    /// The config derives `Serialize` (public API) as well as `Deserialize`.
    /// A round-trip pins the on-disk shape (serde tags / field names) so a
    /// rename can't silently break the executor↔coordinator contract.
    #[test]
    fn config_serialize_round_trips_all_variants() {
        let json = r#"{
            "pg": {"type": "postgres", "dsn_env": "PG_DSN"},
            "my": {"type": "mysql", "dsn_env": "MY_DSN"},
            "wh": {"type": "warehouse", "catalog_url": "http://c/catalog", "warehouse": "w"}
        }"#;
        let cfg: CatalogsConfig = serde_json::from_str(json).expect("parses");
        let reserialized = serde_json::to_string(&cfg).expect("serializes");
        let round_tripped: CatalogsConfig = serde_json::from_str(&reserialized).expect("re-parses");
        assert_eq!(round_tripped.entries.len(), 3);
        // Each variant survives the round-trip as its own type.
        assert!(matches!(
            round_tripped.entries.get("pg"),
            Some(CatalogEntry::Postgres { .. })
        ));
        assert!(matches!(
            round_tripped.entries.get("my"),
            Some(CatalogEntry::Mysql { .. })
        ));
        assert!(matches!(
            round_tripped.entries.get("wh"),
            Some(CatalogEntry::Warehouse { .. })
        ));
    }

    #[tokio::test]
    async fn snowflake_entry_parses_builds_offline_and_redacts() {
        let json = r#"{"sf":{"type":"snowflake","account":"acme-x1","warehouse":"WH","database":"DB","user":"svc","password":"pw","schema":"PUBLIC","role":"READER"}}"#;
        let cfg: CatalogsConfig = serde_json::from_str(json).expect("parses");
        assert!(matches!(
            cfg.entries.get("sf"),
            Some(CatalogEntry::Snowflake { .. })
        ));
        // Debug redacts user/role/password (rule 12); account stays visible.
        let dbg = format!("{:?}", cfg.entries.get("sf").expect("sf"));
        assert!(!dbg.contains("svc"), "user leaked: {dbg}");
        assert!(!dbg.contains("READER"), "role leaked: {dbg}");
        assert!(!dbg.contains("\"pw\""), "password leaked: {dbg}");
        assert!(
            dbg.contains("acme-x1"),
            "account visible for diagnostics: {dbg}"
        );
        // SnowflakeConnector::connect builds the REST client offline (auth fires
        // on the first query), so the executor registry builds with NO Docker —
        // unlike the postgres/mysql arms. This proves the codec-side wiring.
        cfg.into_registries()
            .await
            .expect("snowflake executor builds offline");
    }

    #[test]
    fn resolve_password_source_requires_exactly_one_source() {
        assert_eq!(
            resolve_password_source("sf", Some("p".into()), None).expect("literal"),
            "p"
        );
        assert!(resolve_password_source("sf", Some("p".into()), Some("E".into())).is_err());
        assert!(resolve_password_source("sf", None, None).is_err());
        // Env unset → error names the variable, never its value (rule 12).
        let err = resolve_password_source("sf", None, Some("DEFINITELY_UNSET_SF_PW".into()))
            .expect_err("unset env");
        assert!(format!("{err}").contains("DEFINITELY_UNSET_SF_PW"));
    }

    ///  — an `oracle` entry parses and its `Debug` redacts the
    /// auth-adjacent fields (user, password) while leaving the
    /// credential-free Easy Connect DSN visible for diagnostics.
    #[test]
    fn oracle_entry_parses_and_redacts() {
        let json = r#"{"exadata":{"type":"oracle","dsn":"//db.internal:1521/ORCLPDB1","user":"SCOTT","password":"tiger","password_env":null}}"#;
        let cfg: CatalogsConfig = serde_json::from_str(json).expect("parses");
        assert!(matches!(
            cfg.entries.get("exadata"),
            Some(CatalogEntry::Oracle { .. })
        ));
        let dbg = format!("{:?}", cfg.entries.get("exadata").expect("exadata"));
        assert!(!dbg.contains("SCOTT"), "user leaked: {dbg}");
        assert!(!dbg.contains("tiger"), "password leaked: {dbg}");
        assert!(
            dbg.contains("//db.internal:1521/ORCLPDB1"),
            "DSN visible for diagnostics: {dbg}"
        );
    }

    ///  — an `adbc` entry parses (pool sizes default when omitted)
    /// and its `Debug` redacts `username` + `driver_options` (rule 12)
    /// while showing the non-secret `driver_path` / `dialect`.
    #[test]
    fn adbc_entry_parses_defaults_and_redacts() {
        let json = r#"{"byoduck":{"type":"adbc","driver_path":"/usr/local/lib/libduckdb.so","driver_entrypoint":"duckdb_adbc_init","username":"scott","driver_options":"token=super-secret","dialect":"duckdb"}}"#;
        let cfg: CatalogsConfig = serde_json::from_str(json).expect("parses");
        match cfg.entries.get("byoduck").expect("present") {
            CatalogEntry::Adbc {
                connection_pool_size,
                connection_pool_min_idle,
                dialect,
                ..
            } => {
                assert_eq!(*connection_pool_size, 4, "pool size defaults to 4");
                assert_eq!(*connection_pool_min_idle, 1, "min idle defaults to 1");
                assert_eq!(dialect, "duckdb");
            }
            other => panic!("expected adbc entry, got {other:?}"),
        }
        let dbg = format!("{:?}", cfg.entries.get("byoduck").expect("byoduck"));
        assert!(!dbg.contains("scott"), "username leaked: {dbg}");
        assert!(
            !dbg.contains("super-secret"),
            "driver_options leaked: {dbg}"
        );
        assert!(dbg.contains("libduckdb.so"), "driver_path visible: {dbg}");
    }

    ///  — built WITHOUT `--features oracle-pure`, an `oracle`
    /// entry must fail fast at registry-build time (naming the catalog),
    /// never silently downgrade to a missing connector.
    #[cfg(not(feature = "oracle-pure"))]
    #[tokio::test]
    async fn oracle_without_feature_fails_fast() {
        let mut entries = HashMap::new();
        entries.insert(
            "exadata".to_string(),
            CatalogEntry::Oracle {
                dsn: "//h:1521/S".into(),
                user: "SCOTT".into(),
                password: Some("tiger".into()),
                password_env: None,
            },
        );
        let cfg = CatalogsConfig { entries };
        let Err(err) = cfg.into_registry().await else {
            panic!("oracle without oracle-pure must error")
        };
        let msg = format!("{err}");
        assert!(msg.contains("exadata"), "names the catalog: {msg}");
        assert!(!msg.contains("tiger"), "password must not leak: {msg}");
    }

    ///  — built WITHOUT `--features adbc`, an `adbc` entry must
    /// fail fast at registry-build time (naming the catalog).
    #[cfg(not(feature = "adbc"))]
    #[tokio::test]
    async fn adbc_without_feature_fails_fast() {
        let mut entries = HashMap::new();
        entries.insert(
            "byoduck".to_string(),
            CatalogEntry::Adbc {
                driver_path: "/usr/local/lib/libduckdb.so".into(),
                driver_entrypoint: None,
                uri: None,
                username: None,
                password_env: None,
                driver_options: None,
                catalog: None,
                schema: None,
                dialect: "duckdb".into(),
                connection_pool_size: 4,
                connection_pool_min_idle: 1,
            },
        );
        let cfg = CatalogsConfig { entries };
        let Err(err) = cfg.into_registry().await else {
            panic!("adbc without the feature must error")
        };
        assert!(format!("{err}").contains("byoduck"), "names the catalog");
    }
}

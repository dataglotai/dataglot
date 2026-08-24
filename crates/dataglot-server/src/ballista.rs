//! Ballista distributed-execution wiring for `DataglotServer`.
//! Phase 2 spec 02 slice 3a + slice 4b.5 (server-side codec wiring).
//!
//! This module is gated on the `ballista` cargo feature; the
//! `[ballista]` config-block struct in `config.rs` compiles regardless
//! so JSON parsing stays uniform across feature configurations. When
//! the feature is OFF and a config has `ballista = Some(...)`,
//! `DataglotServer::new` falls back to `reject_ballista_without_feature`
//! to produce a clear error instead of silently ignoring the config.

#[cfg(feature = "ballista")]
mod enabled {
    use anyhow::{Context, Result};
    use std::collections::HashMap;
    use std::sync::Arc;

    use dataglot_ballista::{
        BallistaCluster, BallistaContextFactory, BallistaPhysicalExtensionCodec,
        FederationLogicalCodec,
    };
    use dataglot_federation::{
        mysql::MysqlConnector,
        postgres::PostgresConnector,
        snowflake::{SnowflakeConfig, SnowflakeConnector},
        DynConnectorRegistry, FederationPlanCodec, InMemoryConnectorRegistry,
    };

    use crate::config::{
        resolve_mysql_dsn, resolve_postgres_dsn, resolve_snowflake_config, BallistaServerConfig,
        CatalogConfig, ServerConfig,
    };

    /// Boot the standalone Ballista cluster from the config block.
    /// Returns the cluster handle wrapped in an `Arc` so multiple
    /// per-session contexts can be minted from it.
    ///
    /// Slice 4b.5 — builds a per-server `ConnectorRegistry` from the
    /// SQL-source catalogs in config and plugs the matching
    /// `FederationLogicalCodec` + `FederationPlanCodec` into the
    /// factory's `with_logical_codec` / `with_physical_codec` slots.
    /// That's what makes federated queries actually round-trip
    /// across the Ballista wire in production; without it, the
    /// factory defaults to slice-3a's pure-delegating codec and
    /// every federation query fails at the encode boundary (PR
    /// #272's repeated failure modes).
    ///
    /// # Errors
    /// Wraps `dataglot-ballista`'s standalone-bring-up error if
    /// Ballista cannot allocate ports or start the in-process
    /// scheduler/executor. Also propagates per-Postgres connect
    /// failures when building the SQL-executor registry.
    ///
    /// # Panics
    /// Panics if `config.ballista.is_none()`. The caller in
    /// `DataglotServer::new` only invokes this function inside an
    /// `if config.ballista.is_some()` branch — preserving the
    /// invariant is the caller's responsibility.
    pub async fn boot_cluster(config: &ServerConfig) -> Result<Arc<BallistaCluster>> {
        let ballista_cfg = config
            .ballista
            .as_ref()
            .expect("boot_cluster called without ballista config");
        // Same tolerance the catalog-provider path honors: when the
        // operator opted into `--tolerate-unreachable-catalogs`, a source
        // that can't be reached for the distributed codec registry is
        // logged-and-skipped (that catalog just won't distribute) rather
        // than aborting boot.
        let tolerate = config.tolerate_unreachable_catalogs;
        let registry = build_executor_registry(config, tolerate).await?;
        let warehouses = build_warehouse_registry(config, tolerate).await?;
        let factory = build_factory(config, ballista_cfg, registry, warehouses);
        // Scheduler observability REST API (jobs / executors / stages /
        // DOT graphs) — loopback-only: the endpoints are unauthenticated
        // and can expose query text. `None` port ⇒ plain (unmonitored)
        // standalone boot, byte-identical to the pre-monitor path.
        let api_bind = ballista_cfg
            .rest_api_port
            .map(|port| std::net::SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, port)));
        // Multi-executor: when `external_executors > 0` the server
        // hosts a scheduler-only cluster (no in-process executor) and expects
        // that many `dataglot-ballista-executor` processes to register on the
        // scheduler's gRPC port. Otherwise: the embedded-standalone shape
        // (scheduler + one in-process executor), byte-identical to before.
        let cluster = if ballista_cfg.external_executors > 0 {
            // Bind on all interfaces so executors on the same host (loopback)
            // or a sibling container can register; the advertised name the
            // executor connects back to is derived from this port.
            let grpc_bind = format!("0.0.0.0:{}", ballista_cfg.scheduler_grpc_port);
            let (cluster, api_addr, grpc_addr) = factory
                .boot_monitored_scheduler_only_cluster(api_bind, &grpc_bind)
                .await
                .context("Failed to boot scheduler-only Ballista cluster")?;
            tracing::info!(
                scheduler_grpc = %grpc_addr,
                external_executors = ballista_cfg.external_executors,
                "ballista multi-executor mode: scheduler-only cluster up; \
                 awaiting external executor registrations"
            );
            if let Some(addr) = api_addr {
                tracing::info!(
                    url = %format!("http://{addr}"),
                    "ballista scheduler observability API serving (jobs/executors/stages)"
                );
            }
            cluster
        } else {
            let (cluster, api_addr) = factory
                .boot_monitored_standalone_cluster(api_bind)
                .await
                .context("Failed to boot standalone Ballista cluster")?;
            if let Some(addr) = api_addr {
                tracing::info!(
                    url = %format!("http://{addr}"),
                    "ballista scheduler observability API serving (jobs/executors/stages)"
                );
            }
            cluster
        };
        Ok(Arc::new(cluster))
    }

    /// Build a `ConnectorRegistry` from the SQL-source catalogs in
    /// config — one `SQLExecutor` per distributable catalog, keyed by
    /// catalog name (the identity the codec writes on the wire and each
    /// executor resolves against its own config). `Postgres`, `Mysql`,
    /// and `Snowflake` catalogs surface here (see [`registry_sql_kind`]
    /// for the full split and why `Oracle`/`Adbc` stay single-node);
    /// `Warehouse` / `ObjectStorage` / `OData` don't go through the SQL
    /// federation codec at all. The registry stays empty for those — the
    /// codec gracefully falls through to Ballista's default for any plan
    /// that doesn't reference a registered connector.
    ///
    /// The connection here is *separate* from the catalog provider's
    /// connection in `build_connectors` — the connector exposes
    /// two distinct trait surfaces (`SQLExecutor` for the codec,
    /// `DfCatalogProvider` for catalog listing) and each lives in
    /// its own `Arc`. A future polish could share the underlying
    /// connector across both surfaces (saving one TCP handshake per
    /// Postgres catalog at boot); deferred for now.
    async fn build_executor_registry(
        config: &ServerConfig,
        tolerate: bool,
    ) -> Result<DynConnectorRegistry> {
        use dataglot_federation::SQLExecutor;

        let mut executors: HashMap<String, Arc<dyn SQLExecutor>> =
            HashMap::with_capacity(config.catalogs.len());
        for (name, cfg) in &config.catalogs {
            let Some(kind) = registry_sql_kind(name, cfg)? else {
                continue;
            };
            let built: Result<Arc<dyn SQLExecutor>> = match kind {
                RegistrySqlKind::Postgres(dsn) => PostgresConnector::connect(&dsn)
                    .await
                    .map(|c| Arc::new(c.with_catalog(name.clone())) as Arc<dyn SQLExecutor>)
                    .with_context(|| {
                        format!("ballista codec registry: postgres '{name}' connect failed")
                    }),
                RegistrySqlKind::Mysql(dsn) => MysqlConnector::connect(name.clone(), &dsn)
                    .await
                    .map(|c| Arc::new(c) as Arc<dyn SQLExecutor>)
                    .with_context(|| {
                        format!("ballista codec registry: mysql '{name}' connect failed")
                    }),
                RegistrySqlKind::Snowflake(cfg) => {
                    // `connect` builds the REST client without a network
                    // round-trip (auth fires on the first query), so this is
                    // synchronous and cheap; each executor resolves its own
                    // credentials locally.
                    SnowflakeConnector::connect(name.clone(), cfg)
                        .map(|c| Arc::new(c) as Arc<dyn SQLExecutor>)
                        .with_context(|| {
                            format!("ballista codec registry: snowflake '{name}' connect failed")
                        })
                }
                #[cfg(any(feature = "oracle", feature = "oracle-pure"))]
                RegistrySqlKind::Oracle {
                    dsn,
                    user,
                    password,
                    driver,
                } => {
                    use dataglot_federation::oracle::{OracleConnector, OracleDriver};
                    let drv = driver.map(|d| match d {
                        crate::config::OracleDriverConfig::Oci => OracleDriver::Oci,
                        crate::config::OracleDriverConfig::Pure => OracleDriver::Pure,
                    });
                    OracleConnector::connect_with_driver(name.clone(), &dsn, &user, &password, drv)
                        .await
                        .map(|c| Arc::new(c) as Arc<dyn SQLExecutor>)
                        .with_context(|| {
                            format!("ballista codec registry: oracle '{name}' connect failed")
                        })
                }
                #[cfg(feature = "adbc")]
                RegistrySqlKind::Adbc(a) => {
                    use dataglot_federation::adbc::{AdbcConfig, AdbcConnector, SupportedDialect};
                    match a.dialect.parse::<SupportedDialect>() {
                        Err(_) => Err(anyhow::anyhow!(
                            "ballista codec registry: adbc '{name}' has an invalid dialect"
                        )),
                        Ok(dialect) => {
                            let mut cfg = AdbcConfig::new(name.clone(), a.driver_path, dialect);
                            cfg.driver_entrypoint = a.driver_entrypoint;
                            cfg.uri = a.uri;
                            cfg.username = a.username;
                            cfg.password_env = a.password_env;
                            cfg.driver_options = a.driver_options;
                            cfg.catalog = a.catalog;
                            cfg.schema = a.schema;
                            cfg.connection_pool_size = a.connection_pool_size;
                            cfg.connection_pool_min_idle = a.connection_pool_min_idle;
                            AdbcConnector::connect(cfg)
                                .await
                                .map(|c| Arc::new(c) as Arc<dyn SQLExecutor>)
                                .with_context(|| {
                                    format!("ballista codec registry: adbc '{name}' connect failed")
                                })
                        }
                    }
                }
            };
            match built {
                Ok(connector) => {
                    executors.insert(name.clone(), connector);
                }
                // Tolerate mode: skip the unreachable source. Queries that
                // touch it can't fan out to executors, but the server boots
                // and every other catalog still distributes. The connector
                // errors never carry credentials (rule 12).
                Err(e) if tolerate => {
                    tracing::warn!(
                        catalog = %name,
                        error = %format!("{e:#}"),
                        "catalog unreachable for the distributed codec registry; skipping \
                         (tolerate_unreachable_catalogs) — queries touching it won't distribute"
                    );
                }
                Err(e) => return Err(e),
            }
        }
        Ok(Arc::new(InMemoryConnectorRegistry::new(executors)))
    }

    /// Build the warehouse (Iceberg) registry for the codec:
    /// one [`WarehouseConnector`] per `kind = "warehouse"` catalog,
    /// keyed by the catalog name — the identity the codec writes on
    /// the wire and executors resolve against their own config.
    ///
    /// The REST handshake here is separate from the catalog provider's
    /// connection in `build_connectors` (same trade-off as the SQL
    /// registry above: one extra cheap handshake per warehouse at
    /// boot, no cross-surface sharing yet).
    ///
    /// [`WarehouseConnector`]: dataglot_federation::iceberg::WarehouseConnector
    async fn build_warehouse_registry(
        config: &ServerConfig,
        tolerate: bool,
    ) -> Result<dataglot_federation::iceberg::DynWarehouseRegistry> {
        let mut connectors = HashMap::new();
        for (name, cfg) in &config.catalogs {
            if let CatalogConfig::Warehouse(wh) = cfg {
                let built = crate::config::build_warehouse_connector(name, wh)
                    .await
                    .with_context(|| {
                        format!("ballista codec registry: warehouse '{name}' connect failed")
                    });
                match built {
                    Ok(connector) => {
                        connectors.insert(name.clone(), connector);
                    }
                    // Tolerate mode: skip an unreachable warehouse (same
                    // rationale as the SQL registry above).
                    Err(e) if tolerate => {
                        tracing::warn!(
                            catalog = %name,
                            error = %format!("{e:#}"),
                            "warehouse catalog unreachable for the distributed codec registry; \
                             skipping (tolerate_unreachable_catalogs)"
                        );
                    }
                    Err(e) => return Err(e),
                }
            }
        }
        Ok(Arc::new(
            dataglot_federation::iceberg::WarehouseRegistry::new(connectors),
        ))
    }

    /// Which catalogs the ballista codec registry must carry, as a
    /// **pure, connection-free classification** — split from
    /// `build_executor_registry` so a unit test pins the kind coverage
    /// without live databases.
    ///
    /// History that motivates the test: MySQL was silently in the skip
    /// arm (its comment cited the missing *catalog-listing* path — a
    /// trait surface the registry never needed, since `MysqlConnector`
    /// implements `SQLExecutor` like Postgres). Every mysql-touching
    /// query then failed in `--distributed` with the plan-serialization
    /// error while working single-node, and nothing caught it because
    /// the only signal was a live distributed stack (the testbench
    /// Examples audit, 2026-07-11). With the classifier split out, a
    /// kind quietly falling back to `None` is a unit-test failure.
    ///
    /// `None` ⇒ intentionally not in the **SQL** registry:
    /// `Warehouse` catalogs distribute through their own registry
    /// (, `build_warehouse_registry`); `ObjectStorage` scans
    /// serialize natively; `OData` / SAP / REST take direct-`TableProvider`
    /// paths; `Oracle` and `Adbc` are still single-node (see below).
    /// `Snowflake` **is** distributable — it's pure-Rust and always
    /// compiled, so it reconstructs on any executor exactly like
    /// Postgres/MySQL (a federated query joining Snowflake with another
    /// source now fans out instead of failing the whole plan).
    fn registry_sql_kind(name: &str, cfg: &CatalogConfig) -> Result<Option<RegistrySqlKind>> {
        Ok(match cfg {
            CatalogConfig::Postgres(pg) => {
                Some(RegistrySqlKind::Postgres(resolve_postgres_dsn(name, pg)?))
            }
            CatalogConfig::Mysql(my) => Some(RegistrySqlKind::Mysql(resolve_mysql_dsn(name, my)?)),
            CatalogConfig::Snowflake(sf) => Some(RegistrySqlKind::Snowflake(
                resolve_snowflake_config(name, sf)?,
            )),
            // Oracle + ADBC distribute when the server is built
            // with their feature — Oracle via the pure-Rust backend, ADBC
            // by dlopen'ing the operator-configured driver `.so` on each
            // executor host (that per-host requirement is why they were
            // single-node before). Built WITHOUT the feature they stay
            // single-node: classified to `None`, hitting the clear 
            // "not available in distributed mode" error at query time.
            CatalogConfig::Oracle(o) => {
                #[cfg(any(feature = "oracle", feature = "oracle-pure"))]
                {
                    Some(RegistrySqlKind::Oracle {
                        dsn: o.dsn.clone(),
                        user: o.user.clone(),
                        password: crate::config::resolve_oracle_password(name, o)?,
                        driver: o.driver,
                    })
                }
                #[cfg(not(any(feature = "oracle", feature = "oracle-pure")))]
                {
                    let _ = o;
                    None
                }
            }
            CatalogConfig::Adbc(a) => {
                #[cfg(feature = "adbc")]
                {
                    Some(RegistrySqlKind::Adbc(a.clone()))
                }
                #[cfg(not(feature = "adbc"))]
                {
                    let _ = a;
                    None
                }
            }
            CatalogConfig::Warehouse(_)
            | CatalogConfig::ObjectStorage(_)
            | CatalogConfig::Odata(_)
            | CatalogConfig::SapS4hana(_)
            // REST is a direct `TableProvider` (rule 3), like OData/SAP — not a
            // SQLExecutor source, so it's not in the distributed SQL registry.
            | CatalogConfig::Rest(_) => None,
        })
    }

    /// SQL-source kinds the registry connects, with the resolved
    /// connection descriptor each executor rebuilds from (Postgres/MySQL
    /// DSN, or the full `SnowflakeConfig`). The descriptor is resolved and
    /// consumed locally per executor — it never crosses the wire, so the
    /// embedded credentials never serialize. `SnowflakeConfig`'s `Debug`
    /// redacts its password, so the derived `Debug` here is safe too.
    #[derive(Debug, PartialEq, Eq)]
    enum RegistrySqlKind {
        Postgres(String),
        Mysql(String),
        Snowflake(SnowflakeConfig),
        /// Oracle via the pure-Rust backend. Present only when
        /// the server is built with `oracle`/`oracle-pure`; otherwise an
        /// Oracle catalog stays single-node (classified to `None`). The
        /// password is resolved eagerly at classify time so the descriptor
        /// each executor rebuilds from carries no env indirection; it never
        /// crosses the wire (`RegistrySqlKind`'s `Debug` is only reached in
        /// tests, and the field is a plain `String` the tests don't print).
        #[cfg(any(feature = "oracle", feature = "oracle-pure"))]
        Oracle {
            dsn: String,
            user: String,
            password: String,
            driver: Option<crate::config::OracleDriverConfig>,
        },
        /// ADBC BYO-driver source. Present only when the server
        /// is built with `adbc`; otherwise single-node. Carries the whole
        /// catalog config (the executor rebuilds `AdbcConfig` from it); the
        /// custom `Debug` on `AdbcCatalogConfig` redacts secrets (rule 12).
        #[cfg(feature = "adbc")]
        Adbc(crate::config::AdbcCatalogConfig),
    }

    fn build_factory(
        config: &ServerConfig,
        ballista_cfg: &BallistaServerConfig,
        registry: DynConnectorRegistry,
        warehouses: dataglot_federation::iceberg::DynWarehouseRegistry,
    ) -> BallistaContextFactory {
        use datafusion_proto::logical_plan::LogicalExtensionCodec;
        use datafusion_proto::physical_plan::PhysicalExtensionCodec;

        let session_config = config.to_session_config();
        let logical_codec: Arc<dyn LogicalExtensionCodec> = Arc::new(
            FederationLogicalCodec::with_registry(Arc::clone(&registry))
                .with_warehouse_registry(Arc::clone(&warehouses)),
        );
        // Thread the same `FederationLogicalCodec` into the
        // physical codec's inner-logical-codec slot (so the
        // `VirtualExecutionPlan.plan()` walk reaches federation's
        // `try_encode_table_provider`) and wrap Ballista's stock
        // physical codec so shuffle nodes still round-trip. Same
        // shape as the Docker-gated e2e in `tests/
        // ballista_federation_codec.rs`.
        let physical_codec: Arc<dyn PhysicalExtensionCodec> = Arc::new(
            FederationPlanCodec::with_logical_codec(registry, Arc::clone(&logical_codec))
                .with_warehouse_registry(warehouses)
                .with_inner_physical_codec(Arc::new(BallistaPhysicalExtensionCodec::default())),
        );
        BallistaContextFactory::new(session_config)
            .with_standalone_parallelism(ballista_cfg.standalone_parallelism)
            .with_executor_timeout_seconds(ballista_cfg.executor_timeout_seconds)
            .with_external_executors(ballista_cfg.external_executors)
            .with_logical_codec(logical_codec)
            .with_physical_codec(physical_codec)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::config::ServerConfig;

        /// **Regression pin for the mysql-in-distributed gap.** Every
        /// SQL-source catalog kind must classify into the codec
        /// registry — a kind quietly landing in the `None` arm means
        /// its queries serialize with no connector envelope and fail
        /// in `--distributed` with the plan-serialization error, while
        /// single-node keeps working (exactly how mysql broke: the
        /// testbench "Segment revenue" / "Tri-source" examples failed
        /// distributed, and no test noticed). Pure classification —
        /// no live databases.
        #[test]
        fn sql_source_kinds_classify_into_the_registry() {
            use crate::config::{MysqlCatalogConfig, PostgresCatalogConfig};

            let pg = CatalogConfig::Postgres(PostgresCatalogConfig {
                dsn: Some("host=localhost user=x dbname=d".into()),
                ..Default::default()
            });
            assert_eq!(
                registry_sql_kind("pg", &pg).unwrap(),
                Some(RegistrySqlKind::Postgres(
                    "host=localhost user=x dbname=d".into()
                )),
                "postgres catalogs must enter the registry"
            );

            let my = CatalogConfig::Mysql(MysqlCatalogConfig {
                dsn: Some("mysql://u:p@localhost/demo".into()),
                ..Default::default()
            });
            assert_eq!(
                registry_sql_kind("mysql_demo", &my).unwrap(),
                Some(RegistrySqlKind::Mysql("mysql://u:p@localhost/demo".into())),
                "mysql catalogs must enter the registry — regressing this \
                 to None breaks every mysql query in distributed mode \
                 (works single-node, so only this test or a live \
                 distributed stack would notice)"
            );

            // Snowflake is distributable (pure-Rust, always compiled): it
            // must classify into the registry so a federated query joining
            // it with another source fans out instead of failing the plan.
            let sf = CatalogConfig::Snowflake(crate::config::SnowflakeCatalogConfig {
                account: "acme-corp.us-east-1".into(),
                warehouse: "WH".into(),
                database: "ANALYTICS".into(),
                user: "svc".into(),
                password: Some("pw".into()),
                password_env: None,
                private_key_env: None,
                schema: Some("PUBLIC".into()),
                role: Some("READER".into()),
            });
            assert_eq!(
                registry_sql_kind("sf", &sf).unwrap(),
                Some(RegistrySqlKind::Snowflake(SnowflakeConfig {
                    account: "acme-corp.us-east-1".into(),
                    warehouse: "WH".into(),
                    database: "ANALYTICS".into(),
                    user: "svc".into(),
                    password: "pw".into(),
                    private_key_pem: None,
                    schema: Some("PUBLIC".into()),
                    role: Some("READER".into()),
                })),
                "snowflake catalogs must enter the registry so distributed \
                 federated queries touching Snowflake fan out"
            );
        }

        /// The distributed registry actually **builds** a Snowflake
        /// connector offline — `SnowflakeConnector::connect` constructs the
        /// REST client without a network round-trip (auth fires on the
        /// first query), so a fake-credential catalog lands a live entry in
        /// the registry with no Snowflake account. Proves the executor-side
        /// wiring, not just the classification.
        #[tokio::test]
        async fn snowflake_catalog_builds_into_the_executor_registry() {
            let mut config = ServerConfig::default();
            config.catalogs.insert(
                "sf".to_string(),
                CatalogConfig::Snowflake(crate::config::SnowflakeCatalogConfig {
                    account: "acme-corp.us-east-1".into(),
                    warehouse: "WH".into(),
                    database: "ANALYTICS".into(),
                    user: "svc".into(),
                    password: Some("pw".into()),
                    password_env: None,
                    private_key_env: None,
                    schema: None,
                    role: None,
                }),
            );
            let registry = build_executor_registry(&config, false)
                .await
                .expect("snowflake registry build is network-free and must succeed");
            assert_eq!(
                registry.len(),
                1,
                "the snowflake catalog must produce one executor-side connector"
            );
        }

        /// The intentionally-skipped kinds stay skipped — with the
        ///  friendly error covering them at query time. If a
        /// new SQL-source kind is added to `CatalogConfig`, the
        /// exhaustive match in `registry_sql_kind` forces a decision
        /// here at compile time; this test documents the current
        /// expected split.
        #[test]
        fn non_sql_kinds_are_intentionally_skipped() {
            use crate::config::ObjectStorageCatalogConfig;

            let lake = CatalogConfig::ObjectStorage(ObjectStorageCatalogConfig {
                s3: None,
                tables: vec![],
            });
            assert_eq!(registry_sql_kind("lake", &lake).unwrap(), None);
            // (OData / SAP / REST are direct-`TableProvider` sources and are
            // likewise never in the distributed SQL registry — covered by
            // the exhaustive match in `registry_sql_kind`.)
        }

        /// Oracle + ADBC: classification is **feature-dependent**.
        /// Built with their feature they enter the registry (distribute);
        /// without it they classify to `None` (single-node, hitting the
        ///  friendly error). This test pins both sides of that split
        /// so a regression in either direction is caught.
        #[test]
        fn oracle_and_adbc_classify_by_feature() {
            let adbc_cfg = crate::config::AdbcCatalogConfig {
                driver_path: "/usr/local/lib/libadbc_driver_postgresql.so".to_string(),
                driver_entrypoint: None,
                uri: Some("postgresql://db.internal/prod".to_string()),
                username: None,
                password_env: None,
                driver_options: None,
                catalog: None,
                schema: None,
                dialect: "postgresql".to_string(),
                connection_pool_size: 4,
                connection_pool_min_idle: 1,
            };
            let adbc = CatalogConfig::Adbc(adbc_cfg.clone());
            #[cfg(feature = "adbc")]
            assert_eq!(
                registry_sql_kind("byoduck", &adbc).unwrap(),
                Some(RegistrySqlKind::Adbc(adbc_cfg)),
                "adbc must enter the registry when built with --features adbc"
            );
            #[cfg(not(feature = "adbc"))]
            assert_eq!(
                registry_sql_kind("byoduck", &adbc).unwrap(),
                None,
                "adbc stays single-node without --features adbc — distributed \
                 queries must hit the friendly error"
            );

            let oracle = CatalogConfig::Oracle(crate::config::OracleCatalogConfig {
                dsn: "//db.internal:1521/ORCLPDB1".to_string(),
                user: "SCOTT".to_string(),
                password: Some("tiger".to_string()),
                password_env: None,
                schema: None,
                driver: None,
            });
            #[cfg(any(feature = "oracle", feature = "oracle-pure"))]
            assert_eq!(
                registry_sql_kind("exadata", &oracle).unwrap(),
                Some(RegistrySqlKind::Oracle {
                    dsn: "//db.internal:1521/ORCLPDB1".to_string(),
                    user: "SCOTT".to_string(),
                    password: "tiger".to_string(),
                    driver: None,
                }),
                "oracle must enter the registry when built with \
                 --features oracle/oracle-pure"
            );
            #[cfg(not(any(feature = "oracle", feature = "oracle-pure")))]
            assert_eq!(
                registry_sql_kind("exadata", &oracle).unwrap(),
                None,
                "oracle stays single-node without an oracle backend feature"
            );
        }

        /// Empty `[catalogs.*]` and a non-Postgres-only catalog set
        /// should still build a valid (empty) registry without
        /// attempting any network connect. Pins the slice-4b.5
        /// invariant that the registry is keyed on SQL-source
        /// catalogs only and gracefully no-ops for the rest.
        ///
        /// We deliberately don't exercise the live Postgres path
        /// here — that requires testcontainers and lives in the
        /// Docker-gated e2e at `crates/dataglot-ballista/tests/
        /// ballista_federation_codec.rs`, which proves the same
        /// codec wiring works end-to-end on the wire.
        #[tokio::test]
        async fn empty_catalogs_yields_empty_registry() {
            let config = ServerConfig::default();
            assert!(
                config.catalogs.is_empty(),
                "ServerConfig::default() should have no catalogs configured"
            );
            let registry = build_executor_registry(&config, false)
                .await
                .expect("empty registry build never fails");
            assert_eq!(
                registry.len(),
                0,
                "expected empty registry from default config, got {} entries",
                registry.len()
            );
        }

        ///: with `tolerate_unreachable_catalogs`, a SQL catalog that
        /// can't be reached for the distributed codec registry is skipped
        /// (the server boots, that source just won't distribute) rather than
        /// aborting boot. Without tolerance, the same failure propagates.
        /// Points the catalog at a just-freed loopback port so the connect is
        /// refused immediately (no wait on the connect timeout).
        #[tokio::test]
        async fn unreachable_sql_catalog_skipped_only_when_tolerating() {
            use crate::config::PostgresCatalogConfig;

            let addr = {
                let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let a = l.local_addr().unwrap();
                drop(l); // free the port ⇒ connect is refused fast
                a
            };
            let mut config = ServerConfig::default();
            config.catalogs.insert(
                "pg".to_string(),
                CatalogConfig::Postgres(PostgresCatalogConfig {
                    dsn: Some(format!(
                        "host=127.0.0.1 port={} user=u dbname=d",
                        addr.port()
                    )),
                    ..Default::default()
                }),
            );

            // tolerate=true ⇒ skipped, empty registry, no error.
            let registry = build_executor_registry(&config, true)
                .await
                .expect("tolerate mode must not error on an unreachable catalog");
            assert_eq!(
                registry.len(),
                0,
                "the unreachable catalog must be skipped in tolerate mode"
            );

            // tolerate=false ⇒ the connect failure aborts the build.
            assert!(
                build_executor_registry(&config, false).await.is_err(),
                "non-tolerate mode must propagate the connect failure"
            );
        }
    }
}

#[cfg(feature = "ballista")]
pub use enabled::boot_cluster;

/// Called from `DataglotServer::new` when the config has
/// `ballista = Some(...)` but the `ballista` feature is not compiled
/// in. Produces a pointed error so misconfigured deployments fail
/// loudly at boot rather than silently running single-node.
#[cfg(not(feature = "ballista"))]
#[must_use]
pub fn reject_ballista_without_feature() -> anyhow::Error {
    anyhow::anyhow!(
        "ServerConfig has `ballista = Some(...)` but this binary was \
         not compiled with `--features ballista`. Rebuild with the \
         feature flag enabled (and `protoc` installed in the build \
         environment), or remove the `ballista` block from the \
         configuration."
    )
}

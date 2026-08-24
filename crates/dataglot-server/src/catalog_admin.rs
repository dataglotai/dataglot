//! Server-side implementation of the pgwire [`CatalogAdmin`] seam — the effecting
//! half of SQL-native catalog DDL ( slice C.2).
//!
//! [`dataglot_pgwire::catalog_ddl`] parses `CREATE / ALTER / DROP CATALOG` into a
//! [`CatalogDdl`]; [`StoreCatalogAdmin`] here turns that into a real change:
//!
//! 1. **validate + build** the source with [`build_one_connector`] (the *same*
//!    builder boot and the slice-B refresh use), so an unreachable or
//!    misconfigured source fails the statement *before* anything is persisted —
//!    no half-registered catalog;
//! 2. **persist** to the control-plane [`MetaStore`] (binding first, since
//!    `set_source_config` is a no-op without a binding, then the credential-free
//!    source config). The write fires the store's change feed, so *other*
//!    sessions pick the catalog up via the live-registry refresh (slice B);
//! 3. **hand the provider back** in the [`CatalogAdminOutcome`] so the *calling*
//!    session can register it immediately (the handler wiring is slice C.3).
//!
//! # Option-bag → `CatalogConfig`
//!
//! `WITH (k='v', …)` is a flat map of values. It's converted to a JSON object and
//! deserialized into [`CatalogConfig`] (whose `kind` tag selects the variant). Most
//! options are scalar strings (a `dsn`, a port, a `kind`), so the flat DSN
//! connectors (`postgres`, `mysql`, `oracle`, `snowflake`) map directly. The
//! nested-config sources — `object_storage` (a `tables` array + optional `s3`
//! block), `warehouse` (a nested `credentials` block), `rest` (a `tables` array) —
//! are also expressible: an option value whose trimmed form starts with `[` or `{`
//! is parsed as JSON (see `options_to_config`), so a `tables='[{…}]'` or
//! `credentials='{…}'` value round-trips. A `kind` the option-bag still can't
//! express, or a malformed JSON value, fails with a clear
//! [`CatalogAdminError::InvalidOptions`].

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use datafusion::catalog::CatalogProvider as DfCatalogProvider;
use dataglot_catalog::MetaStore;
use dataglot_pgwire::catalog_admin::{CatalogAdmin, CatalogAdminError, CatalogAdminOutcome};
use dataglot_pgwire::catalog_ddl::CatalogDdl;
use serde_json::Value;

use crate::config::{build_one_connector, resolve_catalog_secrets, CatalogConfig, SecretResolver};

/// Builds a catalog provider from a validated config. Injected so tests can
/// exercise the persist path offline; production wires [`build_one_connector`].
/// Mirrors [`dataglot_catalog::cache::ProviderBuilder`].
type ProviderBuilder = Arc<
    dyn Fn(
            String,
            CatalogConfig,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<Output = anyhow::Result<Arc<dyn DfCatalogProvider>>>
                    + Send
                    + 'static,
            >,
        > + Send
        + Sync
        + 'static,
>;

/// [`CatalogAdmin`] backed by the control-plane [`MetaStore`].
///
///  M2: one admin serves every org — the target org arrives per
/// [`CatalogAdmin::apply`] call (threaded from the connection's session
/// identity by the pgwire handler) rather than being fixed at construction.
#[derive(Clone)]
pub struct StoreCatalogAdmin {
    store: Arc<dyn MetaStore>,
    build: ProviderBuilder,
    /// Resolves `*_secret` catalog options at build time.
    /// `None` ⇒ a catalog that references a secret is rejected with a clear
    /// error; inline `dsn`/`dsn_env` catalogs are unaffected.
    resolver: Option<Arc<dyn SecretResolver>>,
}

impl StoreCatalogAdmin {
    /// Wrap a meta store. Uses [`build_one_connector`] to build sources; the
    /// target org is supplied per [`CatalogAdmin::apply`] call.
    #[must_use]
    pub fn new(store: Arc<dyn MetaStore>) -> Self {
        let build: ProviderBuilder = Arc::new(|name: String, cfg: CatalogConfig| {
            Box::pin(async move { build_one_connector(&name, &cfg).await })
        });
        Self {
            store,
            build,
            resolver: None,
        }
    }

    /// Attach a secret resolver so `CREATE CATALOG … WITH (… dsn_secret='…')`
    /// resolves the reference at build time.
    #[must_use]
    pub fn with_secret_resolver(mut self, resolver: Arc<dyn SecretResolver>) -> Self {
        self.resolver = Some(resolver);
        self
    }

    /// Does a binding with this name already exist in the store, under `org`?
    async fn exists(&self, org: &str, name: &str) -> Result<bool, CatalogAdminError> {
        let bindings = self
            .store
            .list_bindings(org)
            .await
            .map_err(|e| backend(&e))?;
        Ok(bindings.contains_key(name))
    }

    /// Build the source, then persist it. Build FIRST: a failed build must not
    /// leave a persisted binding behind (the "no half-registered catalog"
    /// invariant), and it gives the client an immediate, source-specific error.
    /// Binding before source-config because `set_source_config` no-ops without a
    /// binding (mirrors the boot-time seed order in `build_catalogs_and_cache`).
    async fn build_and_persist(
        &self,
        org: &str,
        name: &str,
        cfg: &CatalogConfig,
    ) -> Result<Arc<dyn DfCatalogProvider>, CatalogAdminError> {
        // Resolve `*_secret` references into a runtime-only config to BUILD with;
        // the original `cfg` (carrying the reference, never the value) is what we
        // PERSIST, so the store never holds plaintext (rule 12) and a restart can
        // re-resolve. A bad/absent secret fails the statement before any write.
        // Secrets resolve within the same org the catalog persists to.
        let runtime = resolve_catalog_secrets(cfg, org, self.resolver.as_deref())
            .await
            .map_err(|e| CatalogAdminError::InvalidOptions(format!("{e:#}")))?;
        let provider = (self.build)(name.to_string(), runtime)
            .await
            .map_err(|e| CatalogAdminError::Backend(format!("catalog {name:?}: {e:#}")))?;
        let serialized = serde_json::to_value(cfg).map_err(|e| {
            CatalogAdminError::Backend(format!("catalog {name:?}: serialize config: {e}"))
        })?;
        self.store
            .upsert_binding(org, name, &cfg.binding())
            .await
            .map_err(|e| backend(&e))?;
        self.store
            .set_source_config(org, name, &serialized)
            .await
            .map_err(|e| backend(&e))?;
        Ok(provider)
    }
}

/// Map an option-bag into a [`CatalogConfig`]. The bag is a flat `String`→`String`
/// map; it's rendered as a JSON object and deserialized against `CatalogConfig`'s
/// `#[serde(tag = "kind")]` discriminator.
///
/// # Nested-config sources
///
/// Most option values are scalar strings (a `dsn`, a port, a `kind`), and a flat
/// bag expresses them fine. The nested-config sources can't be flattened, though:
/// `object_storage` needs a `tables` **array** (and an optional `s3` **object**),
/// `warehouse` a nested `credentials` **object**, `rest` a `tables` array. So an
/// option value whose trimmed form **starts with `[` or `{`** is parsed as JSON
/// and spliced into the map as the parsed array/object; every other value stays a
/// `Value::String`, byte-for-byte. The `[`/`{` gate is deliberately narrow: it's
/// the exact set of JSON tokens a scalar option can never legitimately begin with,
/// so DSNs, bare numbers (ports), bools, and quoted-looking strings are all left
/// untouched (no surprise coercion) — the change is purely additive. A value that
/// opens `[`/`{` but is malformed JSON is a hard error naming the option, rather
/// than being silently passed through as a string that would then fail to
/// deserialize with an opaque message.
///
/// The raw option value is never logged here (rule 12 — a `credentials` blob may
/// carry a secret); only the option *name* appears in the error.
fn options_to_config(
    options: &HashMap<String, String>,
) -> Result<CatalogConfig, CatalogAdminError> {
    if !options.contains_key("kind") {
        return Err(CatalogAdminError::InvalidOptions(
            "missing required option `kind` (e.g. kind='postgres')".to_string(),
        ));
    }
    let mut map = serde_json::Map::with_capacity(options.len());
    for (k, v) in options {
        // Only `[`/`{`-prefixed values are treated as JSON (the array/object nested
        // cases). Everything else is kept verbatim as a string.
        let value = if matches!(v.trim_start().as_bytes().first(), Some(b'[' | b'{')) {
            serde_json::from_str::<Value>(v).map_err(|e| {
                CatalogAdminError::InvalidOptions(format!(
                    "option `{k}` looks like JSON (starts with `[` or `{{`) but did not parse: {e}"
                ))
            })?
        } else {
            Value::String(v.clone())
        };
        map.insert(k.clone(), value);
    }
    serde_json::from_value::<CatalogConfig>(Value::Object(map))
        .map_err(|e| CatalogAdminError::InvalidOptions(e.to_string()))
}

/// Map a store error into a client-safe [`CatalogAdminError::Backend`]. Store
/// errors are backend IO / serialization failures and never carry credentials.
fn backend(e: &dataglot_catalog::CatalogServiceError) -> CatalogAdminError {
    CatalogAdminError::Backend(format!("catalog store: {e}"))
}

#[async_trait]
impl CatalogAdmin for StoreCatalogAdmin {
    async fn apply(
        &self,
        org: &str,
        ddl: CatalogDdl,
    ) -> Result<CatalogAdminOutcome, CatalogAdminError> {
        match ddl {
            CatalogDdl::Create {
                name,
                options,
                or_replace,
                if_not_exists,
            } => {
                if self.exists(org, &name).await? {
                    // `IF NOT EXISTS` wins over `OR REPLACE` when both are given:
                    // the safest reading of "create only if absent" is to leave
                    // an existing catalog untouched.
                    if if_not_exists {
                        return Ok(CatalogAdminOutcome::NoOp);
                    }
                    if !or_replace {
                        return Err(CatalogAdminError::AlreadyExists(name));
                    }
                }
                let cfg = options_to_config(&options)?;
                let provider = self.build_and_persist(org, &name, &cfg).await?;
                Ok(CatalogAdminOutcome::Registered { name, provider })
            }
            CatalogDdl::Alter { name, options } => {
                if !self.exists(org, &name).await? {
                    return Err(CatalogAdminError::NotFound(name));
                }
                // ALTER replaces the option set wholesale (parser semantics):
                // build a fresh config and re-persist under the same name.
                let cfg = options_to_config(&options)?;
                let provider = self.build_and_persist(org, &name, &cfg).await?;
                Ok(CatalogAdminOutcome::Registered { name, provider })
            }
            CatalogDdl::Drop { name, if_exists } => {
                let removed = self
                    .store
                    .delete_binding(org, &name)
                    .await
                    .map_err(|e| backend(&e))?;
                if removed {
                    Ok(CatalogAdminOutcome::Dropped { name })
                } else if if_exists {
                    Ok(CatalogAdminOutcome::NoOp)
                } else {
                    Err(CatalogAdminError::NotFound(name))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ObjectStorageFormat, WarehouseCredentialsConfig};
    use datafusion::catalog::MemoryCatalogProvider;
    use dataglot_catalog::embedded::EmbeddedMetaStore;

    /// A store over a fresh temp dir.
    async fn store() -> (Arc<dyn MetaStore>, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = EmbeddedMetaStore::open(dir.path().join("meta.json"), "default")
            .await
            .expect("open embedded store");
        (Arc::new(store), dir)
    }

    /// An admin whose builder always succeeds with an empty in-memory catalog —
    /// exercises the persist path offline (no real source).
    fn admin_ok(store: Arc<dyn MetaStore>) -> StoreCatalogAdmin {
        let build: ProviderBuilder = Arc::new(|_name, _cfg| {
            Box::pin(async move {
                Ok(Arc::new(MemoryCatalogProvider::new()) as Arc<dyn DfCatalogProvider>)
            })
        });
        StoreCatalogAdmin {
            store,
            build,
            resolver: None,
        }
    }

    fn pg_options() -> HashMap<String, String> {
        HashMap::from([
            ("kind".to_string(), "postgres".to_string()),
            ("dsn".to_string(), "host=db port=5432 dbname=x".to_string()),
        ])
    }

    fn create(name: &str, or_replace: bool, if_not_exists: bool) -> CatalogDdl {
        CatalogDdl::Create {
            name: name.to_string(),
            options: pg_options(),
            or_replace,
            if_not_exists,
        }
    }

    #[test]
    fn options_to_config_requires_kind() {
        let opts = HashMap::from([("dsn".to_string(), "x".to_string())]);
        let err = options_to_config(&opts).expect_err("missing kind");
        assert!(matches!(err, CatalogAdminError::InvalidOptions(_)), "{err}");
        assert!(err.to_string().contains("kind"), "{err}");
    }

    #[test]
    fn options_to_config_rejects_unknown_kind() {
        let opts = HashMap::from([("kind".to_string(), "nosuchsource".to_string())]);
        let err = options_to_config(&opts).expect_err("unknown kind");
        assert!(matches!(err, CatalogAdminError::InvalidOptions(_)), "{err}");
    }

    #[test]
    fn options_to_config_parses_postgres() {
        let cfg = options_to_config(&pg_options()).expect("valid postgres options");
        assert!(matches!(cfg, CatalogConfig::Postgres(_)), "{cfg:?}");
    }

    #[test]
    fn options_to_config_parses_object_storage_tables_json() {
        //  F1: a `tables` option that is a JSON array is parsed as an
        // array (not kept as an opaque string), yielding the nested config.
        let opts = HashMap::from([
            ("kind".to_string(), "object_storage".to_string()),
            (
                "tables".to_string(),
                r#"[{"name":"lineitem","url":"file:///data/lineitem.parquet","format":"parquet"}]"#
                    .to_string(),
            ),
        ]);
        let cfg = options_to_config(&opts).expect("valid object_storage options");
        match cfg {
            CatalogConfig::ObjectStorage(os) => {
                assert_eq!(os.tables.len(), 1);
                assert_eq!(os.tables[0].name, "lineitem");
                assert_eq!(os.tables[0].url, "file:///data/lineitem.parquet");
                assert!(
                    matches!(os.tables[0].format, ObjectStorageFormat::Parquet),
                    "{:?}",
                    os.tables[0].format
                );
                assert!(os.s3.is_none());
            }
            other => panic!("expected ObjectStorage, got {other:?}"),
        }
    }

    #[test]
    fn options_to_config_parses_warehouse_nested_credentials_json() {
        // A `warehouse` with a nested `credentials` object (rule 12: a blob that
        // may carry a secret). `environment` is the real credential-kind rep.
        let opts = HashMap::from([
            ("kind".to_string(), "warehouse".to_string()),
            (
                "catalog_url".to_string(),
                "http://lakekeeper:8181/catalog".to_string(),
            ),
            ("warehouse".to_string(), "demo".to_string()),
            (
                "credentials".to_string(),
                r#"{"kind":"environment"}"#.to_string(),
            ),
        ]);
        let cfg = options_to_config(&opts).expect("valid warehouse options");
        match cfg {
            CatalogConfig::Warehouse(wh) => {
                assert_eq!(wh.catalog_url, "http://lakekeeper:8181/catalog");
                assert_eq!(wh.warehouse, "demo");
                assert!(
                    matches!(wh.credentials, WarehouseCredentialsConfig::Environment),
                    "{:?}",
                    wh.credentials
                );
            }
            other => panic!("expected Warehouse, got {other:?}"),
        }
    }

    #[test]
    fn options_to_config_keeps_plain_dsn_string() {
        // Regression: a scalar `dsn` (contains no leading `[`/`{`) must stay a
        // string, byte-for-byte — no accidental JSON coercion.
        let cfg = options_to_config(&pg_options()).expect("valid postgres options");
        match cfg {
            CatalogConfig::Postgres(pg) => {
                let json = serde_json::to_value(&pg).expect("serialize");
                assert_eq!(
                    json.get("dsn").and_then(Value::as_str),
                    Some("host=db port=5432 dbname=x"),
                    "dsn preserved verbatim: {json}"
                );
            }
            other => panic!("expected Postgres, got {other:?}"),
        }
    }

    #[test]
    fn options_to_config_malformed_json_array_errors_naming_option() {
        // A value that opens `[` but isn't valid JSON is a hard, named error —
        // not a silent string pass-through.
        let opts = HashMap::from([
            ("kind".to_string(), "object_storage".to_string()),
            ("tables".to_string(), "[bad".to_string()),
        ]);
        let err = options_to_config(&opts).expect_err("malformed tables json");
        assert!(matches!(err, CatalogAdminError::InvalidOptions(_)), "{err}");
        assert!(err.to_string().contains("tables"), "{err}");
    }

    #[test]
    fn options_to_config_bare_number_stays_string() {
        // A bare number is NOT `[`/`{`-prefixed, so it must stay a `Value::String`
        // — never coerced to a JSON number. Proof: a numeric-looking value in a
        // *string* field (`dsn`) still deserializes. Had we parsed bare numbers,
        // `dsn` would arrive as a JSON number and fail the `Option<String>` field.
        let opts = HashMap::from([
            ("kind".to_string(), "postgres".to_string()),
            ("dsn".to_string(), "5432".to_string()),
        ]);
        let cfg = options_to_config(&opts).expect("bare number stays a string");
        match cfg {
            CatalogConfig::Postgres(pg) => {
                let json = serde_json::to_value(&pg).expect("serialize");
                assert_eq!(
                    json.get("dsn").and_then(Value::as_str),
                    Some("5432"),
                    "numeric-looking value kept as string: {json}"
                );
            }
            other => panic!("expected Postgres, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn create_builds_persists_and_returns_provider() {
        let (store, _dir) = store().await;
        let admin = admin_ok(Arc::clone(&store));

        let outcome = admin
            .apply("default", create("pg", false, false))
            .await
            .expect("create");
        match outcome {
            CatalogAdminOutcome::Registered { name, .. } => assert_eq!(name, "pg"),
            other => panic!("expected Registered, got {other:?}"),
        }
        // Persisted: both a binding and a source config now exist in the store.
        assert!(store
            .list_bindings("default")
            .await
            .unwrap()
            .contains_key("pg"));
        assert!(store
            .list_source_configs("default")
            .await
            .unwrap()
            .contains_key("pg"));
    }

    #[tokio::test]
    async fn create_persists_under_the_call_org_only() {
        //  M2: the org is a per-call argument, so a `CREATE` for org
        // "acme" lands under "acme" and is invisible to "default".
        let (store, _dir) = store().await;
        let admin = admin_ok(Arc::clone(&store));

        admin
            .apply("acme", create("pg", false, false))
            .await
            .expect("create under acme");

        assert!(
            store
                .list_bindings("acme")
                .await
                .unwrap()
                .contains_key("pg"),
            "persisted under acme"
        );
        assert!(
            !store
                .list_bindings("default")
                .await
                .unwrap()
                .contains_key("pg"),
            "not visible to the default org"
        );
        assert!(store
            .list_source_configs("acme")
            .await
            .unwrap()
            .contains_key("pg"));
        assert!(!store
            .list_source_configs("default")
            .await
            .unwrap()
            .contains_key("pg"));
    }

    #[tokio::test]
    async fn create_existing_without_or_replace_errors_already_exists() {
        let (store, _dir) = store().await;
        let admin = admin_ok(Arc::clone(&store));
        admin
            .apply("default", create("pg", false, false))
            .await
            .expect("first create");

        let err = admin
            .apply("default", create("pg", false, false))
            .await
            .expect_err("second create");
        assert!(
            matches!(err, CatalogAdminError::AlreadyExists(ref n) if n == "pg"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn create_if_not_exists_on_existing_is_noop() {
        let (store, _dir) = store().await;
        let admin = admin_ok(Arc::clone(&store));
        admin
            .apply("default", create("pg", false, false))
            .await
            .expect("first create");

        let outcome = admin
            .apply("default", create("pg", false, true))
            .await
            .expect("if not exists");
        assert!(matches!(outcome, CatalogAdminOutcome::NoOp), "{outcome:?}");
    }

    #[tokio::test]
    async fn create_or_replace_rebuilds_existing() {
        let (store, _dir) = store().await;
        let admin = admin_ok(Arc::clone(&store));
        admin
            .apply("default", create("pg", false, false))
            .await
            .expect("first create");

        let outcome = admin
            .apply("default", create("pg", true, false))
            .await
            .expect("or replace");
        assert!(
            matches!(outcome, CatalogAdminOutcome::Registered { ref name, .. } if name == "pg"),
            "{outcome:?}"
        );
    }

    #[tokio::test]
    async fn build_failure_persists_nothing() {
        let (store, _dir) = store().await;
        // Real builder + a dsn_env pointing at an unset var: `resolve_postgres_dsn`
        // fails fast (no network) inside `build_one_connector`.
        let admin = StoreCatalogAdmin::new(Arc::clone(&store));
        let ddl = CatalogDdl::Create {
            name: "pg".to_string(),
            options: HashMap::from([
                ("kind".to_string(), "postgres".to_string()),
                (
                    "dsn_env".to_string(),
                    "OSS194_DEFINITELY_UNSET_DSN_VAR".to_string(),
                ),
            ]),
            or_replace: false,
            if_not_exists: false,
        };
        let err = admin
            .apply("default", ddl)
            .await
            .expect_err("build must fail");
        assert!(matches!(err, CatalogAdminError::Backend(_)), "{err}");
        // Invariant: nothing was persisted.
        assert!(!store
            .list_bindings("default")
            .await
            .unwrap()
            .contains_key("pg"));
        assert!(!store
            .list_source_configs("default")
            .await
            .unwrap()
            .contains_key("pg"));
    }

    #[tokio::test]
    async fn alter_missing_errors_not_found() {
        let (store, _dir) = store().await;
        let admin = admin_ok(Arc::clone(&store));
        let ddl = CatalogDdl::Alter {
            name: "ghost".to_string(),
            options: pg_options(),
        };
        let err = admin
            .apply("default", ddl)
            .await
            .expect_err("alter missing");
        assert!(
            matches!(err, CatalogAdminError::NotFound(ref n) if n == "ghost"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn alter_existing_rebuilds() {
        let (store, _dir) = store().await;
        let admin = admin_ok(Arc::clone(&store));
        admin
            .apply("default", create("pg", false, false))
            .await
            .expect("create");

        let ddl = CatalogDdl::Alter {
            name: "pg".to_string(),
            options: HashMap::from([
                ("kind".to_string(), "postgres".to_string()),
                (
                    "dsn".to_string(),
                    "host=other port=5432 dbname=y".to_string(),
                ),
            ]),
        };
        let outcome = admin.apply("default", ddl).await.expect("alter");
        assert!(
            matches!(outcome, CatalogAdminOutcome::Registered { ref name, .. } if name == "pg"),
            "{outcome:?}"
        );
    }

    #[tokio::test]
    async fn drop_existing_removes_and_reports() {
        let (store, _dir) = store().await;
        let admin = admin_ok(Arc::clone(&store));
        admin
            .apply("default", create("pg", false, false))
            .await
            .expect("create");

        let outcome = admin
            .apply(
                "default",
                CatalogDdl::Drop {
                    name: "pg".to_string(),
                    if_exists: false,
                },
            )
            .await
            .expect("drop");
        assert!(
            matches!(outcome, CatalogAdminOutcome::Dropped { ref name } if name == "pg"),
            "{outcome:?}"
        );
        assert!(!store
            .list_bindings("default")
            .await
            .unwrap()
            .contains_key("pg"));
    }

    #[tokio::test]
    async fn drop_missing_without_if_exists_errors() {
        let (store, _dir) = store().await;
        let admin = admin_ok(Arc::clone(&store));
        let err = admin
            .apply(
                "default",
                CatalogDdl::Drop {
                    name: "ghost".to_string(),
                    if_exists: false,
                },
            )
            .await
            .expect_err("drop missing");
        assert!(
            matches!(err, CatalogAdminError::NotFound(ref n) if n == "ghost"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn drop_missing_if_exists_is_noop() {
        let (store, _dir) = store().await;
        let admin = admin_ok(Arc::clone(&store));
        let outcome = admin
            .apply(
                "default",
                CatalogDdl::Drop {
                    name: "ghost".to_string(),
                    if_exists: true,
                },
            )
            .await
            .expect("drop if exists");
        assert!(matches!(outcome, CatalogAdminOutcome::NoOp), "{outcome:?}");
    }
}

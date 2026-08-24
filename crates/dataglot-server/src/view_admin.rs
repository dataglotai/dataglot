//! Server-side implementation of the pgwire [`ViewAdmin`] seam — the effecting
//! half of SQL-native view DDL (a derived product,  slice F9).
//!
//! [`dataglot_pgwire::view_ddl`] parses `CREATE / DROP VIEW` into a [`ViewDdl`];
//! [`StoreViewAdmin`] here turns that into a real change, mirroring
//! [`crate::catalog_admin::StoreCatalogAdmin`]:
//!
//! 1. the **handler** has already validated the `AS <query>` by planning it
//!    against the calling session (the only context that can see a catalog the
//!    same session just created) and built a [`ViewTable`]; a broken query
//!    failed there, before this admin ran;
//! 2. [`StoreViewAdmin::apply`] **persists** the [`DerivedProductRecord`] to the
//!    control-plane [`MetaStore`] under the calling org;
//! 3. it **registers the handler-built provider live** into the per-org
//!    [`LiveViewRegistry`] so a subsequent connection (which rebuilds its session
//!    from that registry) can query it — the same visibility model as
//!    `CREATE CATALOG`.
//!
//! Boot-load (`load_persisted_derived_products`) and config-declared products
//! (`register_config_derived_product_view`) build their providers here via
//! `build_derived_product_view` (the same planner path `build_lineage_graph`
//! uses), because at boot there is no session to build against.
//!
//! # Governance (rule 6)
//!
//! A view is a DataFusion [`ViewTable`] wrapping the planned `LogicalPlan`. At
//! query time the plan is **inlined**, so the underlying source `TableScan`
//! appears in the querying session's plan and the existing plan-time
//! `PolicyOptimizerRule` masks a masked source column *through* the view — the
//! mask cannot be bypassed by querying the view instead of the source.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use async_trait::async_trait;
use datafusion::catalog::{CatalogProvider as DfCatalogProvider, TableProvider};
use datafusion::common::TableReference;
use datafusion::datasource::ViewTable;
use dataglot_catalog::{DerivedProductRecord, MetaStore};
use dataglot_core::SessionContextFactory;
use dataglot_pgwire::view_admin::{ViewAdmin, ViewAdminError, ViewAdminOutcome};
use dataglot_pgwire::view_ddl::ViewDdl;

/// A derived-product view registered live: the reference to register it under
/// (session default when unqualified) plus the built provider.
#[derive(Clone)]
pub struct RegisteredView {
    /// Where to register the view in a session.
    pub reference: TableReference,
    /// The built `ViewTable` provider.
    pub provider: Arc<dyn TableProvider>,
}

/// Per-org live registry of derived-product views: `org -> (name -> view)`.
/// Names are unique per org (the store keys derived products by name), so the
/// inner map is keyed by name. `create_session` reads it to register each org's
/// views; [`StoreViewAdmin`] writes it so a runtime `CREATE / DROP VIEW` is
/// visible to subsequent connections (slice-B visibility model).
pub type LiveViewRegistry = Arc<RwLock<HashMap<String, HashMap<String, RegisteredView>>>>;

/// Build a [`TableReference`] for a derived product from its optional
/// `catalog`/`schema`: full when both are present, partial when only a schema
/// is, bare otherwise. A bare/partial reference resolves against the session's
/// default catalog/schema — standard Postgres semantics.
#[must_use]
pub fn view_reference(record: &DerivedProductRecord) -> TableReference {
    match (record.catalog.clone(), record.schema.clone()) {
        (Some(c), Some(s)) => TableReference::full(c, s, record.name.clone()),
        (_, Some(s)) => TableReference::partial(s, record.name.clone()),
        _ => TableReference::bare(record.name.clone()),
    }
}

/// Plan a derived product's SQL into a DataFusion [`ViewTable`] — the builder
/// shared by boot-load and config derived products (the runtime path plans
/// against the calling session instead). Plans the query against a probe context
/// with every catalog registered (exactly the shape `build_lineage_graph` uses),
/// so a view that references a real federated source resolves, and a broken query
/// fails here.
///
/// # Errors
/// The `AS <query>` failed to plan (unknown table/column, syntax error, an
/// unreachable source at plan time).
pub(crate) async fn build_derived_product_view(
    factory: &SessionContextFactory,
    catalogs: &HashMap<String, Arc<dyn DfCatalogProvider>>,
    needs_federation: bool,
    record: &DerivedProductRecord,
) -> anyhow::Result<Arc<dyn TableProvider>> {
    let ctx = if needs_federation {
        factory.create_federated_context()
    } else {
        factory.create_context()
    };
    for (name, catalog) in catalogs {
        // Replacing the default-catalog placeholder is expected (mirrors
        // `build_lineage_graph`); `catalogs` is a map so no real collision.
        ctx.register_catalog(name, Arc::clone(catalog));
    }
    let plan = ctx
        .state()
        .create_logical_plan(&record.sql)
        .await
        .map_err(|e| anyhow::anyhow!("plan view {:?}: {e}", record.name))?;
    // `ViewTable` inlines this plan on query, so masks on the underlying source
    // still apply through the view (rule 6). Keep the SQL as the definition.
    let view = ViewTable::new(plan, Some(record.sql.clone()));
    Ok(Arc::new(view))
}

/// [`ViewAdmin`] backed by the control-plane [`MetaStore`] + the live view
/// registry. One admin serves every org — the target org arrives
/// per [`ViewAdmin::apply`] call (threaded from the connection's session
/// identity by the pgwire handler). The handler builds + validates the view's
/// provider against the calling session and hands it here; this admin persists
/// the definition and registers that provider live.
#[derive(Clone)]
pub struct StoreViewAdmin {
    store: Arc<dyn MetaStore>,
    registry: LiveViewRegistry,
}

impl StoreViewAdmin {
    /// Wrap a store + the live registry the admin registers into.
    #[must_use]
    pub fn new(store: Arc<dyn MetaStore>, registry: LiveViewRegistry) -> Self {
        Self { store, registry }
    }

    /// Insert a built view into the live registry under `org`, keyed by name.
    fn register_live(
        &self,
        org: &str,
        record: &DerivedProductRecord,
        provider: Arc<dyn TableProvider>,
    ) {
        let view = RegisteredView {
            reference: view_reference(record),
            provider,
        };
        let mut guard = self
            .registry
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard
            .entry(org.to_string())
            .or_default()
            .insert(record.name.clone(), view);
    }

    /// Remove a view from the live registry under `org` by name.
    fn unregister_live(&self, org: &str, name: &str) {
        let mut guard = self
            .registry
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(org_views) = guard.get_mut(org) {
            org_views.remove(name);
        }
    }
}

/// Map a store error into a client-safe [`ViewAdminError::Backend`]. Store errors
/// are backend IO / serialization failures and never carry credentials.
fn backend(e: &dataglot_catalog::CatalogServiceError) -> ViewAdminError {
    ViewAdminError::Backend(format!("view store: {e}"))
}

#[async_trait]
impl ViewAdmin for StoreViewAdmin {
    async fn apply(
        &self,
        org: &str,
        ddl: ViewDdl,
        provider: Option<Arc<dyn TableProvider>>,
    ) -> Result<ViewAdminOutcome, ViewAdminError> {
        match ddl {
            ViewDdl::Create {
                catalog,
                schema,
                name,
                query,
                or_replace,
            } => {
                let exists = self
                    .store
                    .get_derived_product(org, &name)
                    .await
                    .map_err(|e| backend(&e))?
                    .is_some();
                if exists && !or_replace {
                    return Err(ViewAdminError::AlreadyExists(name));
                }
                let record = DerivedProductRecord {
                    name,
                    sql: query,
                    catalog,
                    schema,
                };
                // Persist the definition, then register the handler-built
                // provider live so subsequent connections see it.
                self.store
                    .put_derived_product(org, &record)
                    .await
                    .map_err(|e| backend(&e))?;
                if let Some(provider) = provider {
                    self.register_live(org, &record, provider);
                }
                if exists {
                    Ok(ViewAdminOutcome::Replaced)
                } else {
                    Ok(ViewAdminOutcome::Created)
                }
            }
            ViewDdl::Drop {
                catalog: _,
                schema: _,
                name,
                if_exists,
            } => {
                // Use the STORED qualifiers for the session-deregister reference
                // (what the view was created under), not what the client typed.
                let stored = self
                    .store
                    .get_derived_product(org, &name)
                    .await
                    .map_err(|e| backend(&e))?;
                self.store
                    .delete_derived_product(org, &name)
                    .await
                    .map_err(|e| backend(&e))?;
                self.unregister_live(org, &name);
                if let Some(record) = stored {
                    Ok(ViewAdminOutcome::Dropped {
                        catalog: record.catalog,
                        schema: record.schema,
                        name: record.name,
                    })
                } else if if_exists {
                    Ok(ViewAdminOutcome::NoOp)
                } else {
                    Err(ViewAdminError::NotFound(name))
                }
            }
        }
    }
}

/// Boot-load persisted derived products into the live view registry
/// — analogous to `load_persisted_policies` / the catalog live-registry seed.
/// For every org the store knows, builds each persisted product through
/// [`build_derived_product_view`] and inserts it into `registry` so a fresh
/// session registers it. Best-effort **per product**: one that can't plan
/// (unreachable source, a source dropped since it was created) is logged and
/// skipped — a single bad view never blocks boot.
///
/// # Errors
/// A store read failure (`list_orgs` / `list_derived_products`).
pub(crate) async fn load_persisted_derived_products(
    store: &dyn MetaStore,
    factory: &SessionContextFactory,
    catalogs: &HashMap<String, Arc<dyn DfCatalogProvider>>,
    needs_federation: bool,
    registry: &LiveViewRegistry,
) -> anyhow::Result<()> {
    let orgs = store.list_orgs().await?;
    for org in orgs {
        let products = store.list_derived_products(&org).await?;
        for record in products {
            match build_derived_product_view(factory, catalogs, needs_federation, &record).await {
                Ok(provider) => insert_view(registry, &org, &record, provider),
                Err(e) => tracing::warn!(
                    org = %org, product = %record.name, error = %format!("{e:#}"),
                    "view: persisted derived product failed to plan; skipping (not queryable until its source resolves)"
                ),
            }
        }
    }
    Ok(())
}

/// Register a config-declared **live** derived product as a queryable view in
/// `registry` under `org`, through the shared builder. Best-effort — a product
/// that can't plan is logged + skipped (same posture as `build_lineage_graph`).
/// Materialized products are skipped by the caller (the scheduler writes them to
/// a warehouse table instead of exposing an inlined view).
pub(crate) async fn register_config_derived_product_view(
    factory: &SessionContextFactory,
    catalogs: &HashMap<String, Arc<dyn DfCatalogProvider>>,
    needs_federation: bool,
    registry: &LiveViewRegistry,
    org: &str,
    record: &DerivedProductRecord,
) {
    match build_derived_product_view(factory, catalogs, needs_federation, record).await {
        Ok(provider) => insert_view(registry, org, record, provider),
        Err(e) => tracing::warn!(
            product = %record.name, error = %format!("{e:#}"),
            "view: config derived product failed to plan; skipping (not queryable)"
        ),
    }
}

/// Insert a built view into `registry` under `org`, keyed by name.
fn insert_view(
    registry: &LiveViewRegistry,
    org: &str,
    record: &DerivedProductRecord,
    provider: Arc<dyn TableProvider>,
) {
    let view = RegisteredView {
        reference: view_reference(record),
        provider,
    };
    let mut guard = registry
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    guard
        .entry(org.to_string())
        .or_default()
        .insert(record.name.clone(), view);
}

#[cfg(test)]
mod tests {
    use super::*;
    use datafusion::arrow::array::Int32Array;
    use datafusion::arrow::datatypes::{DataType, Field, Schema};
    use datafusion::arrow::record_batch::RecordBatch;
    use datafusion::datasource::MemTable;
    use dataglot_catalog::embedded::EmbeddedMetaStore;

    /// A store over a fresh temp dir.
    async fn store() -> (Arc<dyn MetaStore>, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = EmbeddedMetaStore::open(dir.path().join("meta.json"), "default")
            .await
            .expect("open embedded store");
        (Arc::new(store), dir)
    }

    fn empty_registry() -> LiveViewRegistry {
        Arc::new(RwLock::new(HashMap::new()))
    }

    /// A one-column `users` `MemTable` so a `SELECT ... FROM users` view plans.
    fn users_provider() -> Arc<dyn TableProvider> {
        let schema = Arc::new(Schema::new(vec![
            Field::new("id", DataType::Int32, false),
            Field::new("email", DataType::Int32, false),
        ]));
        let batch = RecordBatch::try_new(
            Arc::clone(&schema),
            vec![
                Arc::new(Int32Array::from(vec![1])),
                Arc::new(Int32Array::from(vec![42])),
            ],
        )
        .expect("batch");
        Arc::new(MemTable::try_new(schema, vec![vec![batch]]).expect("memtable"))
    }

    /// Build a `ViewTable` provider by planning `sql` against a context with a
    /// `users` table — the offline stand-in for what the handler builds against
    /// the calling session.
    async fn view_provider(sql: &str) -> Arc<dyn TableProvider> {
        let ctx = datafusion::prelude::SessionContext::new();
        ctx.register_table("users", users_provider())
            .expect("register users");
        let plan = ctx
            .state()
            .create_logical_plan(sql)
            .await
            .expect("plan view");
        Arc::new(ViewTable::new(plan, Some(sql.to_string())))
    }

    fn create(name: &str, sql: &str, or_replace: bool) -> ViewDdl {
        ViewDdl::Create {
            catalog: None,
            schema: None,
            name: name.to_string(),
            query: sql.to_string(),
            or_replace,
        }
    }

    #[tokio::test]
    async fn create_persists_and_registers_live() {
        let (store, _dir) = store().await;
        let registry = empty_registry();
        let admin = StoreViewAdmin::new(Arc::clone(&store), Arc::clone(&registry));
        let sql = "SELECT id, email FROM users";

        let outcome = admin
            .apply(
                "acme",
                create("active", sql, false),
                Some(view_provider(sql).await),
            )
            .await
            .expect("create");
        assert!(matches!(outcome, ViewAdminOutcome::Created));
        // Persisted under the call org only.
        assert!(store
            .get_derived_product("acme", "active")
            .await
            .unwrap()
            .is_some());
        assert!(store
            .get_derived_product("default", "active")
            .await
            .unwrap()
            .is_none());
        // Registered live under acme.
        assert!(registry
            .read()
            .unwrap()
            .get("acme")
            .unwrap()
            .contains_key("active"));
    }

    #[tokio::test]
    async fn create_existing_without_or_replace_errors() {
        let (store, _dir) = store().await;
        let registry = empty_registry();
        let admin = StoreViewAdmin::new(Arc::clone(&store), Arc::clone(&registry));
        let sql = "SELECT id FROM users";
        admin
            .apply(
                "acme",
                create("v", sql, false),
                Some(view_provider(sql).await),
            )
            .await
            .expect("first");
        let err = admin
            .apply(
                "acme",
                create("v", sql, false),
                Some(view_provider(sql).await),
            )
            .await
            .expect_err("dup");
        assert!(
            matches!(err, ViewAdminError::AlreadyExists(ref n) if n == "v"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn or_replace_updates_definition() {
        let (store, _dir) = store().await;
        let registry = empty_registry();
        let admin = StoreViewAdmin::new(Arc::clone(&store), Arc::clone(&registry));
        admin
            .apply(
                "acme",
                create("v", "SELECT id FROM users", false),
                Some(view_provider("SELECT id FROM users").await),
            )
            .await
            .expect("first");
        let outcome = admin
            .apply(
                "acme",
                create("v", "SELECT id, email FROM users", true),
                Some(view_provider("SELECT id, email FROM users").await),
            )
            .await
            .expect("replace");
        assert!(matches!(outcome, ViewAdminOutcome::Replaced));
        let rec = store
            .get_derived_product("acme", "v")
            .await
            .unwrap()
            .expect("present");
        assert_eq!(rec.sql, "SELECT id, email FROM users");
    }

    #[tokio::test]
    async fn drop_removes_from_store_and_registry() {
        let (store, _dir) = store().await;
        let registry = empty_registry();
        let admin = StoreViewAdmin::new(Arc::clone(&store), Arc::clone(&registry));
        let sql = "SELECT id FROM users";
        admin
            .apply(
                "acme",
                create("v", sql, false),
                Some(view_provider(sql).await),
            )
            .await
            .expect("create");

        let outcome = admin
            .apply(
                "acme",
                ViewDdl::Drop {
                    catalog: None,
                    schema: None,
                    name: "v".to_string(),
                    if_exists: false,
                },
                None,
            )
            .await
            .expect("drop");
        assert!(matches!(outcome, ViewAdminOutcome::Dropped { ref name, .. } if name == "v"));
        assert!(store
            .get_derived_product("acme", "v")
            .await
            .unwrap()
            .is_none());
        assert!(!registry
            .read()
            .unwrap()
            .get("acme")
            .unwrap()
            .contains_key("v"));
    }

    #[tokio::test]
    async fn drop_missing_if_exists_is_noop_else_not_found() {
        let (store, _dir) = store().await;
        let registry = empty_registry();
        let admin = StoreViewAdmin::new(Arc::clone(&store), Arc::clone(&registry));
        let noop = admin
            .apply(
                "acme",
                ViewDdl::Drop {
                    catalog: None,
                    schema: None,
                    name: "ghost".to_string(),
                    if_exists: true,
                },
                None,
            )
            .await
            .expect("noop");
        assert!(matches!(noop, ViewAdminOutcome::NoOp));
        let err = admin
            .apply(
                "acme",
                ViewDdl::Drop {
                    catalog: None,
                    schema: None,
                    name: "ghost".to_string(),
                    if_exists: false,
                },
                None,
            )
            .await
            .expect_err("not found");
        assert!(
            matches!(err, ViewAdminError::NotFound(ref n) if n == "ghost"),
            "{err}"
        );
    }

    /// Boot-load makes a persisted view queryable: seed the store, then load
    /// into a fresh registry (via the offline builder) and confirm it registers.
    #[tokio::test]
    async fn boot_load_registers_persisted_views() {
        let (store, _dir) = store().await;
        let record = DerivedProductRecord {
            name: "active".to_string(),
            sql: "SELECT id FROM users".to_string(),
            catalog: None,
            schema: None,
        };
        store
            .put_derived_product("acme", &record)
            .await
            .expect("seed");
        let registry = empty_registry();
        for org in store.list_orgs().await.unwrap() {
            for rec in store.list_derived_products(&org).await.unwrap() {
                let provider = view_provider(&rec.sql).await;
                insert_view(&registry, &org, &rec, provider);
            }
        }
        assert!(registry
            .read()
            .unwrap()
            .get("acme")
            .unwrap()
            .contains_key("active"));
    }
}

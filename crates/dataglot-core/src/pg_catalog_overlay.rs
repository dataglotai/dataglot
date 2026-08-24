//! Per-catalog `pg_catalog` schema overlay.
//!
//! # Why this exists
//!
//! `datafusion-pg-catalog::setup_pg_catalog` registers the `pg_catalog`
//! schema (the `pg_class`, `pg_namespace`, `pg_settings`, ... tables
//! every psql/JDBC client introspects on connect) against **one**
//! named catalog. In a single-source DataFusion deployment that's
//! enough.
//!
//! In Dataglot, the production server registers one
//! `Arc<dyn CatalogProvider>` per federated source (`pg`, `pg_orders`,
//! `mysql_demo`, `iceberg`, ...) via `SessionContext::register_catalog`,
//! which **replaces** the target slot in the catalog list. So:
//!
//! 1. [`SessionContextFactory::create_federated_context`] builds a
//!    fresh context, DataFusion auto-creates the default
//!    [`MemoryCatalogProvider`] (named after `SessionConfig::default_catalog`),
//!    `setup_pg_catalog` registers `pg_catalog` schema under it.
//! 2. `dataglot-server` then calls `register_catalog("pg", federated_pg)`
//!    for each configured federated catalog. The federated providers
//!    (`PostgresCatalog`, `MysqlCatalog`, etc.) do NOT implement
//!    [`CatalogProvider::register_schema`] — they use the upstream
//!    default impl, which returns `Err`. So adding `pg_catalog` to
//!    them after construction is impossible via the trait surface.
//! 3. The federated `pg` catalog now sits in the slot the
//!    `pg_catalog`-bearing `MemoryCatalogProvider` used to occupy.
//!    `psql -d pg` resolves `pg_catalog.pg_class` to
//!    `pg.pg_catalog.pg_class` and gets a planning error.
//!
//! [`PgCatalogOverlayProvider`] solves this by **wrapping** each
//! federated catalog with a composite that:
//! - delegates [`schema_names`](CatalogProvider::schema_names) and
//!   [`schema`](CatalogProvider::schema) to the wrapped provider for
//!   every name except `"pg_catalog"`,
//! - returns the overlay [`SchemaProvider`] for `"pg_catalog"`.
//!
//! The wrapped provider's own schema set is preserved (no eager
//! enumeration, no schema fetch — rule 13 stays satisfied).
//!
//! # Scope (, Layer A)
//!
//! This wrapper is the minimum needed for psql introspection
//! (`\dt`, `\d`, `\l`) to **work without errors** against any
//! federated catalog. It does NOT scope the `pg_catalog` contents
//! to the wrapping catalog — the overlay [`SchemaProvider`] passed in
//! is the upstream `PgCatalogSchemaProvider`, which enumerates
//! `pg_class` / `pg_namespace` across **all** registered catalogs.
//!
//! Net effect: `\dt` in `psql -d pg` returns the union of every
//! federated catalog's tables, not just `pg`'s. The true
//! Model-A scoping ("`\dt` shows only the connected catalog's
//! tables") needs a catalog-scoped [`SchemaProvider`] implementation
//! tracked separately as  (Layer B). Layer A is the stepping
//! stone — once a scoped provider exists, just hand it to this
//! wrapper instead.
//!
//! # Identity
//!
//! `EmptyContextProvider` (no role membership / privilege model)
//! today. Identity-aware `pg_roles` / `has_table_privilege` is
//! deferred to a follow-up; see the "Open questions" section of
//! `docs/phases/phase-3/06-pg-catalog-compatibility.md`.
//!
//! [`SessionContextFactory::create_federated_context`]: crate::session::SessionContextFactory::create_federated_context
//! [`MemoryCatalogProvider`]: datafusion::catalog::MemoryCatalogProvider

use std::sync::{Arc, OnceLock};

use async_trait::async_trait;
use datafusion::arrow::array::{
    new_null_array, Array, ArrayRef, Int32Array, RecordBatch, StringArray,
};
use datafusion::arrow::datatypes::SchemaRef;
use datafusion::catalog::{CatalogProvider, CatalogProviderList, SchemaProvider};
use datafusion::datasource::{MemTable, TableProvider};
use datafusion::error::{DataFusionError, Result as DfResult};
use datafusion::physical_plan::collect;
use datafusion::prelude::SessionContext;
use datafusion_pg_catalog::pg_catalog::context::{PgCatalogContextProvider, Role};
use datafusion_pg_catalog::pg_catalog::{PgCatalogSchemaProvider, PgCatalogStaticTables};

/// `pg_catalog` tables that pg semantics treat as **server-wide**,
/// not per-database. When the surrounding [`HybridPgCatalogSchema`]
/// receives a `table(name)` lookup for one of these, it routes to a
/// flat (full-catalog-list) provider instead of the per-catalog
/// scoped one — so e.g. `\l` (which reads `pg_database`) still
/// enumerates every Dataglot catalog as a database.
///
/// Today this list contains only `pg_database`. Other server-wide
/// tables (`pg_settings`, `pg_roles`, `pg_authid`, ...) could be
/// added here if a client's query against them is found to leak
/// per-catalog scoping in a misleading way. Adding a name here is
/// safe: the upstream provider exposes the same table set under
/// both flat and scoped catalog lists; routing one to flat just
/// returns the cross-catalog view.
const SERVER_WIDE_PG_CATALOG_TABLES: &[&str] = &["pg_database"];

/// OID of the `pg_catalog` namespace. `datafusion-pg-catalog` fixes this at
/// **11** (its `PG_CATALOG_NAMESPACE_OID`, mirroring real PostgreSQL), and every
/// built-in row in the static `pg_type` / `pg_proc` tables it ships references
/// `typnamespace = 11`. The synthetic `pg_namespace` row we add **must** use
/// this value so `pg_type.typnamespace = pg_namespace.oid` resolves.
const PG_CATALOG_NAMESPACE_OID: i32 = 11;

/// OID of the `information_schema` namespace as baked into the static catalog
/// tables of the pinned `datafusion-pg-catalog` (0.18.x) — the value its static
/// `pg_type`/`pg_proc` rows for SQL-standard objects reference. Not a fixed
/// upstream constant like `pg_catalog`; mirrored here so those rows also join.
/// The Npgsql base-type loader only needs `pg_catalog` (11); this is for
/// completeness of `information_schema` introspection.
const INFORMATION_SCHEMA_NAMESPACE_OID: i32 = 13283;

/// Build the synthetic `pg_namespace` rows for the system namespaces
/// (`pg_catalog`, `information_schema`), matching `schema` — the upstream
/// `pg_namespace` Arrow schema — so the batch unions cleanly with the
/// upstream rows and preserves the `oid` column's field metadata.
///
/// Columns are filled by name (`oid`, `nspname`, `nspowner`); any other column
/// (`nspacl`, `options`, or a future upstream addition) is filled with NULLs of
/// the field's own type, so this stays correct if the upstream schema grows.
fn system_namespace_rows(schema: &SchemaRef) -> DfResult<RecordBatch> {
    const ROWS: usize = 2;
    let columns: Vec<ArrayRef> = schema
        .fields()
        .iter()
        .map(|field| -> ArrayRef {
            match field.name().as_str() {
                "oid" => Arc::new(Int32Array::from(vec![
                    PG_CATALOG_NAMESPACE_OID,
                    INFORMATION_SCHEMA_NAMESPACE_OID,
                ])),
                "nspname" => Arc::new(StringArray::from(vec!["pg_catalog", "information_schema"])),
                // Upstream fills `nspowner` with a constant 10 (bootstrap superuser).
                "nspowner" => Arc::new(Int32Array::from(vec![10, 10])),
                _ => new_null_array(field.data_type(), ROWS),
            }
        })
        .collect();
    RecordBatch::try_new(Arc::clone(schema), columns).map_err(DataFusionError::from)
}

/// Build `pg_settings` rows for the capability GUCs in
/// [`crate::functions::CAPABILITY_GUCS`] whose name is not already present in
/// `existing` (lowercased), matching `schema` — the upstream `pg_settings`
/// Arrow schema. `name` + `setting` are filled; every other column is NULL,
/// exactly as upstream does for its own rows.
///
/// Upstream ships only `standard_conforming_strings` in `pg_settings`, but
/// clients (and `SHOW`) read it for capability GUCs like `server_version_num`
/// / `client_encoding`. Backed by the same source as `current_setting` so the
/// function and the table can't disagree.
fn capability_settings_rows(
    schema: &SchemaRef,
    existing: &std::collections::HashSet<String>,
) -> DfResult<RecordBatch> {
    let rows: Vec<(&str, &str)> = crate::functions::CAPABILITY_GUCS
        .iter()
        .copied()
        .filter(|(name, _)| !existing.contains(&name.to_ascii_lowercase()))
        .collect();
    let names: Vec<&str> = rows.iter().map(|(n, _)| *n).collect();
    let values: Vec<&str> = rows.iter().map(|(_, v)| *v).collect();
    let n = rows.len();
    let columns: Vec<ArrayRef> = schema
        .fields()
        .iter()
        .map(|field| -> ArrayRef {
            match field.name().as_str() {
                "name" => Arc::new(StringArray::from(names.clone())),
                "setting" => Arc::new(StringArray::from(values.clone())),
                _ => new_null_array(field.data_type(), n),
            }
        })
        .collect();
    RecordBatch::try_new(Arc::clone(schema), columns).map_err(DataFusionError::from)
}

/// Collect the lowercased `name`-column values across `batches` (used to
/// dedupe the `pg_settings` augmentation against upstream's own rows).
fn collect_name_column(batches: &[RecordBatch]) -> std::collections::HashSet<String> {
    let mut names = std::collections::HashSet::new();
    for batch in batches {
        if let Some(col) = batch
            .column_by_name("name")
            .and_then(|c| c.as_any().downcast_ref::<StringArray>())
        {
            for i in 0..col.len() {
                if !col.is_null(i) {
                    names.insert(col.value(i).to_ascii_lowercase());
                }
            }
        }
    }
    names
}

/// A role row for the emulated `pg_roles`. The minimal shape
/// Dataglot can populate from its identity/role config — **attributes only,
/// no grants**: there is no ACL/grant model until enterprise auth, so
/// `has_*_privilege` stays permissive and only role *identity* is surfaced.
#[derive(Debug, Clone)]
pub struct PgRoleSpec {
    /// Role name (`rolname`).
    pub name: String,
    /// Whether the role is a superuser (`rolsuper`).
    pub is_superuser: bool,
    /// Whether the role may log in (`rolcanlogin`) — true for user
    /// identities, false for group roles.
    pub can_login: bool,
}

/// [`PgCatalogContextProvider`] that serves `pg_roles` from a fixed set of
/// Dataglot roles (built from the server's `identities` / `roles` config).
///
/// `pg_roles` is the only table the upstream context provider drives; the
/// privilege/visibility functions don't consult it (they stay permissive
/// pending a grant model — ). An empty role set makes this behave
/// exactly like the upstream `EmptyContextProvider`.
#[derive(Debug, Clone)]
struct DataglotPgContextProvider {
    roles: Arc<[PgRoleSpec]>,
}

#[async_trait]
impl PgCatalogContextProvider for DataglotPgContextProvider {
    async fn roles(&self) -> Vec<String> {
        self.roles.iter().map(|r| r.name.clone()).collect()
    }

    async fn role(&self, name: &str) -> Option<Role> {
        self.roles.iter().find(|r| r.name == name).map(|r| Role {
            name: r.name.clone(),
            is_superuser: r.is_superuser,
            can_login: r.can_login,
            // No grant/role-attribute model yet — report the
            // conservative defaults for everything beyond login/superuser.
            can_create_db: false,
            can_create_role: false,
            can_create_user: false,
            can_replication: false,
            grants: Vec::new(),
            inherited_roles: Vec::new(),
        })
    }
}

/// `CatalogProvider` that overlays a single fixed `pg_catalog`
/// [`SchemaProvider`] on top of a wrapped base catalog.
///
/// All schema lookups for names other than `"pg_catalog"` delegate to
/// the wrapped provider — including delegation to the wrapped
/// provider's [`CatalogProvider::register_schema`] (if it supports
/// modification at all).
#[derive(Debug)]
pub struct PgCatalogOverlayProvider {
    inner: Arc<dyn CatalogProvider>,
    pg_catalog: Arc<dyn SchemaProvider>,
}

impl PgCatalogOverlayProvider {
    /// Wrap `inner` so that `schema("pg_catalog")` returns `pg_catalog`
    /// and all other names fall through to the wrapped provider.
    #[must_use]
    pub fn new(inner: Arc<dyn CatalogProvider>, pg_catalog: Arc<dyn SchemaProvider>) -> Self {
        Self { inner, pg_catalog }
    }
}

impl CatalogProvider for PgCatalogOverlayProvider {
    /// The wrapped provider's schemas plus `"pg_catalog"`.
    ///
    /// Defensive: if the wrapped provider already lists `"pg_catalog"`
    /// (unlikely against a real federated source today, but possible
    /// against a future provider that mirrors pg semantics natively),
    /// no duplicate entry is appended — the overlay still wins on
    /// `schema()`. Comparison is `eq_ignore_ascii_case` to match
    /// PostgreSQL identifier semantics (unquoted identifiers are
    /// case-insensitive; quoted `"PG_CATALOG"` from a client still
    /// routes here).
    fn schema_names(&self) -> Vec<String> {
        let mut names = self.inner.schema_names();
        if !names.iter().any(|n| n.eq_ignore_ascii_case("pg_catalog")) {
            names.push("pg_catalog".to_string());
        }
        names
    }

    fn schema(&self, name: &str) -> Option<Arc<dyn SchemaProvider>> {
        if name.eq_ignore_ascii_case("pg_catalog") {
            Some(Arc::clone(&self.pg_catalog))
        } else {
            self.inner.schema(name)
        }
    }

    fn register_schema(
        &self,
        name: &str,
        schema: Arc<dyn SchemaProvider>,
    ) -> DfResult<Option<Arc<dyn SchemaProvider>>> {
        // Refuse to let callers re-register `pg_catalog` through the
        // overlay — that would shadow what `setup_pg_catalog` already
        // installed and cause silent divergence between the session's
        // pg_catalog state and what psql introspects.
        // Case-insensitive — see `schema_names` comment.
        if name.eq_ignore_ascii_case("pg_catalog") {
            return Err(DataFusionError::Configuration(
                "pg_catalog schema is owned by the overlay; \
                 register against the session's default catalog before wrapping"
                    .to_string(),
            ));
        }
        self.inner.register_schema(name, schema)
    }

    fn deregister_schema(
        &self,
        name: &str,
        cascade: bool,
    ) -> DfResult<Option<Arc<dyn SchemaProvider>>> {
        if name.eq_ignore_ascii_case("pg_catalog") {
            return Err(DataFusionError::Configuration(
                "pg_catalog schema is owned by the overlay; cannot deregister".to_string(),
            ));
        }
        self.inner.deregister_schema(name, cascade)
    }
}

/// A [`CatalogProviderList`] that exposes exactly **one** named
/// catalog. Used to build a catalog-scoped [`PgCatalogSchemaProvider`]
/// (see [`build_scoped_pg_catalog_schema`]).
///
/// # Why this exists
///
/// Upstream `datafusion-pg-catalog`'s `pg_class`, `pg_namespace`,
/// `pg_attribute`, etc. build their row sets by iterating
/// `catalog_list.catalog_names()` (confirmed at
/// `~/.cargo/registry/.../datafusion-pg-catalog-0.17.0/src/pg_catalog/pg_class.rs:120`
/// and equivalent lines in the other table files). If we hand the
/// [`PgCatalogSchemaProvider`] constructor a `CatalogProviderList`
/// that returns just one catalog name, the resulting `pg_class` /
/// `pg_namespace` rows are naturally scoped to that catalog — no
/// per-table reimplementation needed.
///
/// `register_catalog` is a no-op (returns `None`) because the scoped
/// view is read-only; the upstream tables never call it.
#[derive(Debug)]
struct SingleCatalogProviderList {
    name: String,
    catalog: Arc<dyn CatalogProvider>,
}

impl CatalogProviderList for SingleCatalogProviderList {
    fn register_catalog(
        &self,
        _name: String,
        _catalog: Arc<dyn CatalogProvider>,
    ) -> Option<Arc<dyn CatalogProvider>> {
        // Read-only view — upstream `PgCatalogSchemaProvider` never
        // mutates the list it was constructed with. If a future
        // upstream version starts calling `register_catalog`, swap
        // this for a panic so the divergence surfaces loudly.
        None
    }

    fn catalog_names(&self) -> Vec<String> {
        vec![self.name.clone()]
    }

    fn catalog(&self, name: &str) -> Option<Arc<dyn CatalogProvider>> {
        if name == self.name {
            Some(Arc::clone(&self.catalog))
        } else {
            None
        }
    }
}

/// A [`SchemaProvider`] that splits `pg_catalog` table lookups
/// between a **scoped** provider (per-database tables: `pg_class`,
/// `pg_namespace`, ...) and a **flat** provider (server-wide tables
/// per [`SERVER_WIDE_PG_CATALOG_TABLES`]: `pg_database`).
///
/// This mirrors pg's own design: most `pg_catalog` tables hold rows
/// *about the current database*, but a small set (`pg_database`,
/// `pg_roles`, `pg_authid`, `pg_tablespace`, ...) hold rows *about
/// the whole server*. Connecting to one Dataglot catalog must show
/// only that catalog's tables in `\dt` (per-database semantic), but
/// must still show every catalog as a "database" in `\l`
/// (server-wide semantic — the pg-native equivalent of Trino's
/// `SHOW CATALOGS`).
#[derive(Debug)]
struct HybridPgCatalogSchema {
    /// Built with a single-catalog [`SingleCatalogProviderList`].
    /// Used for every table NOT in [`SERVER_WIDE_PG_CATALOG_TABLES`].
    scoped: Arc<dyn SchemaProvider>,
    /// Built with the session's full catalog list. Only consulted
    /// for tables in [`SERVER_WIDE_PG_CATALOG_TABLES`].
    flat: Arc<dyn SchemaProvider>,
}

impl HybridPgCatalogSchema {
    /// Serve a scoped `pg_catalog` table with extra rows appended: collect the
    /// upstream rows, build `extra` from the table's schema (and its existing
    /// rows), and return the union as a [`MemTable`]. Used to fill small static
    /// tables that upstream under-populates for BI-client introspection
    /// (`pg_namespace` —; `pg_settings` — ). Both are tiny and
    /// read infrequently, so materializing per lookup is cheap.
    async fn augment_scoped_table(
        &self,
        name: &str,
        build_extra: impl FnOnce(&SchemaRef, &[RecordBatch]) -> DfResult<RecordBatch>,
    ) -> DfResult<Option<Arc<dyn TableProvider>>> {
        let Some(inner) = self.scoped.table(name).await? else {
            return Ok(None);
        };
        let schema = inner.schema();
        let ctx = SessionContext::new();
        let state = ctx.state();
        let plan = inner.scan(&state, None, &[], None).await?;
        let mut batches = collect(plan, ctx.task_ctx()).await?;
        let extra = build_extra(&schema, &batches)?;
        batches.push(extra);
        let mem = MemTable::try_new(schema, vec![batches])?;
        Ok(Some(Arc::new(mem)))
    }
}

#[async_trait]
impl SchemaProvider for HybridPgCatalogSchema {
    fn table_names(&self) -> Vec<String> {
        // Both providers expose the same upstream table set (one is
        // just constructed against a single-catalog list). The scoped
        // side is the authoritative source for table existence.
        self.scoped.table_names()
    }

    async fn table(&self, name: &str) -> DfResult<Option<Arc<dyn TableProvider>>> {
        // PostgreSQL treats unquoted identifiers case-insensitively, and the
        // rest of `PgCatalogOverlayProvider` already routes with
        // `eq_ignore_ascii_case`. Match that here so e.g.
        // `pg_catalog."PG_DATABASE"` still reaches the server-wide flat half.
        let server_wide = SERVER_WIDE_PG_CATALOG_TABLES
            .iter()
            .any(|t| t.eq_ignore_ascii_case(name));
        if server_wide {
            return self.flat.table(name).await;
        }
        //  — augment `pg_namespace` with the system namespaces.
        // Upstream builds `pg_namespace` from the federated catalog's *user*
        // schemas only, so it omits `pg_catalog` (oid 11) and
        // `information_schema` (13283) — the namespaces the static
        // `pg_type`/`pg_proc` rows reference. Npgsql (Power BI's driver) loads
        // types via `pg_type INNER JOIN pg_namespace ON typnamespace = oid`,
        // which then returns zero built-in types unless those rows exist.
        if name.eq_ignore_ascii_case("pg_namespace") {
            return self
                .augment_scoped_table(name, |schema, _existing| system_namespace_rows(schema))
                .await;
        }
        //  — augment `pg_settings` with the capability GUCs clients read
        // on connect (`server_version_num`, `client_encoding`, …). Upstream
        // ships only `standard_conforming_strings`; add the rest, deduped
        // against whatever upstream already provides.
        if name.eq_ignore_ascii_case("pg_settings") {
            return self
                .augment_scoped_table(name, |schema, existing| {
                    capability_settings_rows(schema, &collect_name_column(existing))
                })
                .await;
        }
        self.scoped.table(name).await
    }

    fn table_exist(&self, name: &str) -> bool {
        self.scoped.table_exist(name)
    }
}

/// Build a `pg_catalog` [`SchemaProvider`] scoped to a single
/// federated catalog for per-database tables (`pg_class`,
/// `pg_namespace`, `pg_attribute`, ...), while preserving a
/// cross-catalog view for the server-wide ones (`pg_database` —
/// what `\l` reads).
///
/// `full_catalog_list` backs the flat half (`pg_database` — what `\l`
/// reads); its `catalog_names()` become the advertised databases. The
/// caller is responsible for passing a list that enumerates *exactly*
/// the databases `\l` should show — i.e. the configured federated
/// catalogs. Do **not** pass the session's live
/// `state().catalog_list()`: at session boot it also holds the
/// placeholder default catalog from `with_default_catalog_and_schema`,
/// which would leak into `pg_database` as a phantom database whenever
/// the configured `default_catalog` isn't itself a federated catalog
/// name. Build the list from the configured catalog set instead (see
/// `dataglot-server`'s `create_session`). This is the pg-native
/// equivalent of Trino's `SHOW CATALOGS`.
///
/// Both halves share a single process-wide [`PgCatalogStaticTables`]
/// (see `shared_pg_catalog_static_tables`) — it holds only immutable
/// embedded Arrow data, so decoding it once and sharing the `Arc` is
/// sound and keeps the connection hot path cheap. OID generation is
/// *not* in the static tables; it lives in each
/// [`PgCatalogSchemaProvider`], which is still built fresh per call.
/// The two halves therefore use different OID caches; cross-half joins
/// (e.g. joining `pg_database.oid` to a per-database table's row)
/// are not a supported query shape — pg's own design treats the
/// server-wide set as orthogonal to per-database OIDs. (OID *stability
/// across connections* is a separate provider-lifecycle concern, out of
/// scope here: each session may wrap a different catalog set.)
///
/// # Errors
/// Returns [`crate::DataglotError::Configuration`] if the one-time
/// `shared_pg_catalog_static_tables` decode or either
/// [`PgCatalogSchemaProvider::try_new`] call fails. All are infallible
/// in practice on a vanilla `datafusion-pg-catalog 0.17` install; an
/// error here would indicate an upstream regression.
///
/// # Example
/// ```rust,ignore
/// // In dataglot-server::create_session — build the flat list from the
/// // configured catalogs (NOT the session's live list, which carries the
/// // placeholder default catalog).
/// let flat_list: Arc<dyn CatalogProviderList> = {
///     let list = MemoryCatalogProviderList::new();
///     for (name, catalog) in &self.catalogs {
///         list.register_catalog(name.clone(), Arc::clone(catalog));
///     }
///     Arc::new(list)
/// };
/// for (name, catalog) in &self.catalogs {
///     let scoped = build_scoped_pg_catalog_schema(
///         name,
///         Arc::clone(catalog),
///         Arc::clone(&flat_list),
///     )?;
///     let wrapped = Arc::new(PgCatalogOverlayProvider::new(
///         Arc::clone(catalog),
///         scoped,
///     ));
///     let _ = ctx.register_catalog(name, wrapped);
/// }
/// ```
pub fn build_scoped_pg_catalog_schema(
    name: &str,
    catalog: Arc<dyn CatalogProvider>,
    full_catalog_list: Arc<dyn CatalogProviderList>,
) -> crate::Result<Arc<dyn SchemaProvider>> {
    build_scoped_pg_catalog_schema_with_roles(name, catalog, full_catalog_list, &[])
}

/// Like [`build_scoped_pg_catalog_schema`], but populates `pg_roles` from
/// `roles` — the Dataglot identities/roles the server knows at
/// session-construction time. An empty slice reproduces the role-less
/// behaviour of [`build_scoped_pg_catalog_schema`].
///
/// The same role set is handed to both the scoped and flat halves; `pg_roles`
/// is cluster-wide in Postgres, so which half serves it is immaterial (both
/// report the same rows). Only role *identity* is surfaced — privileges stay
/// permissive until there's a grant model.
///
/// # Errors
/// Same as [`build_scoped_pg_catalog_schema`].
pub fn build_scoped_pg_catalog_schema_with_roles(
    name: &str,
    catalog: Arc<dyn CatalogProvider>,
    full_catalog_list: Arc<dyn CatalogProviderList>,
    roles: &[PgRoleSpec],
) -> crate::Result<Arc<dyn SchemaProvider>> {
    // Both halves read from the same immutable, process-wide static
    // tables — decoded once, then cheaply Arc-cloned per connection.
    let static_tables = shared_pg_catalog_static_tables()?;
    let context = DataglotPgContextProvider {
        roles: Arc::from(roles.to_vec()),
    };

    // Scoped half: per-database tables (`pg_class`, `pg_namespace`,
    // `pg_attribute`, ...) enumerate only the wrapping catalog.
    let scoped_list: Arc<dyn CatalogProviderList> = Arc::new(SingleCatalogProviderList {
        name: name.to_string(),
        catalog,
    });
    let scoped = Arc::new(
        PgCatalogSchemaProvider::try_new(scoped_list, Arc::clone(&static_tables), context.clone())
            .map_err(|e| {
                crate::DataglotError::Configuration(format!(
                    "failed to build scoped PgCatalogSchemaProvider for catalog '{name}': {e}"
                ))
            })?,
    ) as Arc<dyn SchemaProvider>;

    // Flat half: server-wide tables (`pg_database`) enumerate the
    // full catalog list — preserves `\l` semantics across Model A.
    let flat = Arc::new(
        PgCatalogSchemaProvider::try_new(full_catalog_list, static_tables, context).map_err(
            |e| {
                crate::DataglotError::Configuration(format!(
                    "failed to build flat PgCatalogSchemaProvider for catalog '{name}': {e}"
                ))
            },
        )?,
    ) as Arc<dyn SchemaProvider>;

    Ok(Arc::new(HybridPgCatalogSchema { scoped, flat }))
}

/// Process-wide cached [`PgCatalogStaticTables`], decoded once from the
/// embedded feather exports and shared by every
/// [`build_scoped_pg_catalog_schema`] call.
///
/// `PgCatalogStaticTables` is purely immutable: it holds `Arc<ArrowTable>`
/// handles to read-only embedded data and carries no per-session or OID
/// state (OID generation lives in each [`PgCatalogSchemaProvider`], which
/// is still constructed per call). Decoding its ~60 feather tables on
/// every `create_session` showed up on the connection hot path, so we
/// decode once and hand out `Arc` clones.
///
/// # Errors
/// Surfaces [`crate::DataglotError::Configuration`] if the one-time decode
/// fails — practically unreachable on a vanilla `datafusion-pg-catalog`
/// install. After the first success the cached value is reused and this
/// never errors again.
fn shared_pg_catalog_static_tables() -> crate::Result<Arc<PgCatalogStaticTables>> {
    // The fallible decode runs *inside* `get_or_init`, so it executes exactly
    // once even when many connections race on the first call — decoding the
    // ~60 feather tables outside the closure would let every concurrent caller
    // pay that cost before one wins the store. `OnceLock::get_or_init` can't
    // carry a `Result`, so we cache the `Result` itself; the decode is
    // deterministic (embedded data), so a cached error would recur anyway.
    static STATIC_TABLES: OnceLock<Result<Arc<PgCatalogStaticTables>, String>> = OnceLock::new();

    STATIC_TABLES
        .get_or_init(|| {
            PgCatalogStaticTables::try_new()
                .map(Arc::new)
                .map_err(|e| format!("failed to build PgCatalogStaticTables: {e}"))
        })
        .as_ref()
        .map(Arc::clone)
        .map_err(|e| crate::DataglotError::Configuration(e.clone()))
}

/// Eagerly initialize the process-wide `pg_catalog` static-table cache.
///
/// The cache is decoded lazily on first use (see
/// [`build_scoped_pg_catalog_schema`]), which would otherwise put the
/// one-time decode of the embedded `pg_catalog` tables on the first
/// client connection's async task. Call this **once at server boot**,
/// inside [`tokio::task::spawn_blocking`], so the CPU-bound decode runs
/// off the Tokio connection path and every `create_session` after boot
/// only reads an already-initialized `OnceLock`.
///
/// Idempotent: subsequent calls (and concurrent first uses) reuse the
/// cached value. Safe to skip — omitting it just restores the lazy
/// first-connection behaviour.
///
/// # Errors
/// Returns [`crate::DataglotError::Configuration`] if the one-time
/// decode fails (practically unreachable on a vanilla
/// `datafusion-pg-catalog` install).
pub fn prewarm_pg_catalog_static_tables() -> crate::Result<()> {
    shared_pg_catalog_static_tables().map(|_| ())
}

/// Extract the `pg_catalog` [`SchemaProvider`] that
/// [`crate::session::SessionContextFactory::create_federated_context`]
/// (or `create_context`) registered against `source_catalog`.
///
/// The returned `Arc` can be cheaply cloned into a
/// [`PgCatalogOverlayProvider`] per federated catalog so every catalog
/// the server registers exposes the same `pg_catalog` schema.
///
/// # Errors
/// Returns [`DataglotError::Configuration`](crate::error::DataglotError::Configuration)
/// if `source_catalog` doesn't exist on `ctx`, or if it has no
/// `pg_catalog` schema (which would indicate the factory's setup call
/// regressed — `SessionContextFactory` always registers it).
pub fn extract_pg_catalog_schema(
    ctx: &SessionContext,
    source_catalog: &str,
) -> crate::Result<Arc<dyn SchemaProvider>> {
    let catalog = ctx.catalog(source_catalog).ok_or_else(|| {
        crate::DataglotError::Configuration(format!(
            "cannot extract pg_catalog: catalog '{source_catalog}' is not registered \
             on the session"
        ))
    })?;
    catalog.schema("pg_catalog").ok_or_else(|| {
        crate::DataglotError::Configuration(format!(
            "cannot extract pg_catalog: catalog '{source_catalog}' has no pg_catalog \
             schema — SessionContextFactory should have registered it"
        ))
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use datafusion::arrow::array::Int32Array;
    use datafusion::arrow::datatypes::{DataType, Field, Schema as ArrowSchema};
    use datafusion::arrow::record_batch::RecordBatch;
    use datafusion::catalog::{MemTable, MemoryCatalogProvider, MemorySchemaProvider};

    use std::any::Any;

    use datafusion::arrow::array::Array;

    use super::*;

    /// A schema provider that returns no tables. Used to stand in for
    /// the real `pg_catalog` `SchemaProvider` in tests of the overlay's
    /// delegation behaviour.
    fn dummy_pg_catalog_schema() -> Arc<dyn SchemaProvider> {
        Arc::new(MemorySchemaProvider::new())
    }

    fn one_int_batch() -> RecordBatch {
        let schema = Arc::new(ArrowSchema::new(vec![Field::new(
            "x",
            DataType::Int32,
            false,
        )]));
        RecordBatch::try_new(schema, vec![Arc::new(Int32Array::from(vec![1]))]).unwrap()
    }

    fn base_with_public_users() -> Arc<dyn CatalogProvider> {
        let cat = MemoryCatalogProvider::new();
        let public = MemorySchemaProvider::new();
        let batch = one_int_batch();
        public
            .register_table(
                "users".to_string(),
                Arc::new(MemTable::try_new(batch.schema(), vec![vec![batch]]).unwrap()),
            )
            .unwrap();
        cat.register_schema("public", Arc::new(public)).unwrap();
        Arc::new(cat)
    }

    #[test]
    fn schema_names_includes_pg_catalog_and_inner_schemas() {
        let overlay =
            PgCatalogOverlayProvider::new(base_with_public_users(), dummy_pg_catalog_schema());
        let names = overlay.schema_names();
        assert!(names.contains(&"public".to_string()), "got: {names:?}");
        assert!(names.contains(&"pg_catalog".to_string()), "got: {names:?}");
    }

    #[test]
    fn schema_lookup_routes_pg_catalog_to_overlay_others_to_inner() {
        let overlay =
            PgCatalogOverlayProvider::new(base_with_public_users(), dummy_pg_catalog_schema());
        assert!(
            overlay.schema("pg_catalog").is_some(),
            "pg_catalog must come from the overlay"
        );
        assert!(
            overlay.schema("public").is_some(),
            "non-pg_catalog schemas must fall through to the inner provider"
        );
        assert!(
            overlay.schema("does_not_exist").is_none(),
            "unknown schemas must be None"
        );
    }

    #[test]
    fn schema_names_does_not_duplicate_pg_catalog_when_inner_already_has_it() {
        // Synthetic edge case: an inner provider that already exposes
        // pg_catalog (no real federated source does today). The overlay
        // must not append a duplicate entry.
        let inner = MemoryCatalogProvider::new();
        inner
            .register_schema("pg_catalog", Arc::new(MemorySchemaProvider::new()))
            .unwrap();
        let overlay = PgCatalogOverlayProvider::new(Arc::new(inner), dummy_pg_catalog_schema());
        let pg_cat_count = overlay
            .schema_names()
            .iter()
            .filter(|n| *n == "pg_catalog")
            .count();
        assert_eq!(pg_cat_count, 1, "exactly one pg_catalog entry expected");
    }

    #[test]
    fn register_schema_rejects_pg_catalog_to_prevent_silent_shadowing() {
        let overlay =
            PgCatalogOverlayProvider::new(base_with_public_users(), dummy_pg_catalog_schema());
        let result = overlay.register_schema("pg_catalog", Arc::new(MemorySchemaProvider::new()));
        assert!(result.is_err());
    }

    #[test]
    fn register_schema_delegates_non_pg_catalog_to_inner() {
        // The complement of the reject test: a non-pg_catalog schema falls
        // through to the inner provider and registers normally.
        let overlay =
            PgCatalogOverlayProvider::new(base_with_public_users(), dummy_pg_catalog_schema());
        overlay
            .register_schema("analytics", Arc::new(MemorySchemaProvider::new()))
            .expect("non-pg_catalog registration must delegate and succeed");
        assert!(
            overlay.schema("analytics").is_some(),
            "the delegated schema must now be visible through the overlay"
        );
    }

    #[test]
    fn deregister_schema_rejects_pg_catalog_but_delegates_others() {
        let overlay =
            PgCatalogOverlayProvider::new(base_with_public_users(), dummy_pg_catalog_schema());

        // pg_catalog is overlay-owned — deregistering it is refused
        // (case-insensitively, mirroring register_schema).
        assert!(overlay.deregister_schema("pg_catalog", true).is_err());
        assert!(overlay.deregister_schema("PG_CATALOG", true).is_err());

        // A real inner schema deregisters via delegation and comes back
        // (cascade=true since `public` holds the `users` table).
        let removed = overlay
            .deregister_schema("public", true)
            .expect("delegated deregister must succeed");
        assert!(removed.is_some(), "the removed schema should be returned");
        assert!(
            overlay.schema("public").is_none(),
            "public must be gone after deregistration"
        );
    }

    #[test]
    fn overlay_as_any_downcasts_to_concrete_type() {
        let overlay =
            PgCatalogOverlayProvider::new(base_with_public_users(), dummy_pg_catalog_schema());
        assert!((&overlay as &dyn CatalogProvider as &dyn Any)
            .downcast_ref::<PgCatalogOverlayProvider>()
            .is_some());
    }

    /// Case-insensitive routing of `"pg_catalog"` — pins the
    /// `eq_ignore_ascii_case` behaviour requested in PR #503 review
    /// (Gemini, 2026-06-08). PostgreSQL identifier semantics: unquoted
    /// identifiers are case-folded; quoted `"PG_CATALOG"` from a client
    /// should still resolve to the overlay rather than fall through to
    /// the inner provider.
    #[test]
    fn schema_lookup_matches_pg_catalog_case_insensitively() {
        let overlay =
            PgCatalogOverlayProvider::new(base_with_public_users(), dummy_pg_catalog_schema());
        for variant in ["pg_catalog", "PG_CATALOG", "Pg_Catalog", "pG_cAtAlOg"] {
            assert!(
                overlay.schema(variant).is_some(),
                "schema({variant:?}) must route to the overlay"
            );
        }
    }

    #[test]
    fn register_schema_rejects_pg_catalog_case_insensitively() {
        let overlay =
            PgCatalogOverlayProvider::new(base_with_public_users(), dummy_pg_catalog_schema());
        for variant in ["pg_catalog", "PG_CATALOG", "Pg_Catalog"] {
            let result = overlay.register_schema(variant, Arc::new(MemorySchemaProvider::new()));
            assert!(
                result.is_err(),
                "register_schema({variant:?}) must be rejected"
            );
        }
    }

    // ──  — Layer B (catalog-scoped pg_catalog) ───────────────

    ///  — L1 from the spec's test inventory.
    ///
    /// `SingleCatalogProviderList` MUST expose exactly one catalog
    /// name, and `catalog(name)` MUST resolve only the wrapping name.
    /// This pins the surface upstream `PgCatalogSchemaProvider`
    /// relies on for catalog enumeration.
    #[test]
    fn single_catalog_provider_list_exposes_only_the_wrapping_catalog() {
        let inner = base_with_public_users();
        let list = SingleCatalogProviderList {
            name: "alpha".to_string(),
            catalog: Arc::clone(&inner),
        };
        assert_eq!(list.catalog_names(), vec!["alpha".to_string()]);
        assert!(list.catalog("alpha").is_some());
        assert!(
            list.catalog("beta").is_none(),
            "non-wrapping names must NOT resolve"
        );
        // Register-catalog is a no-op; the scoped view is read-only.
        let result = list.register_catalog("beta".to_string(), inner);
        assert!(result.is_none());
    }

    ///  G1 — `shared_pg_catalog_static_tables` MUST return the
    /// same `Arc` on every call. The `OnceLock` cache is the whole
    /// point: it eliminates the per-connection decode of the embedded
    /// `pg_catalog` feather tables on the hot path (and lets
    /// `prewarm_pg_catalog_static_tables` move that cost off the
    /// first connection's Tokio worker — see `dataglot-server`'s
    /// boot path).
    ///
    /// Pinned via `Arc::ptr_eq`: a future refactor that accidentally
    /// drops the singleton (e.g. "simplifies" the helper to a
    /// non-cached function) would otherwise regress silently —
    /// surfacing only as a per-connection CPU profile change, not a
    /// test failure. This test catches that class of regression.
    #[test]
    fn shared_pg_catalog_static_tables_is_singleton() {
        let a = super::shared_pg_catalog_static_tables()
            .expect("first call must succeed against vanilla datafusion-pg-catalog");
        let b =
            super::shared_pg_catalog_static_tables().expect("second call must succeed (cached)");
        assert!(
            Arc::ptr_eq(&a, &b),
            "shared_pg_catalog_static_tables must return the same Arc on each call \
             (OnceLock singleton invariant)"
        );
    }

    ///  — L2 (the load-bearing "trick verification" from step 4
    /// of the spec).
    ///
    /// Build a `SessionContext` containing two memory catalogs
    /// (`alpha` with table `a_one`, `beta` with table `b_one`).
    /// Construct a scoped `pg_catalog` for `alpha` only. A query
    /// against `pg_catalog.pg_class` through the scoped provider MUST
    /// return rows for `alpha`'s tables and NOT for `beta`'s.
    ///
    /// If this test fails, the single-catalog-list trick doesn't
    /// hold and we'd need a fundamentally different approach
    /// (reimplementing the upstream tables — see the spec's
    /// out-of-scope notes for what that would look like).
    #[tokio::test]
    async fn build_scoped_pg_catalog_schema_scopes_pg_class_to_one_catalog() {
        use datafusion::execution::session_state::SessionStateBuilder;

        // Build two memory catalogs with one table each.
        let alpha = Arc::new(MemoryCatalogProvider::new()) as Arc<dyn CatalogProvider>;
        {
            let public = MemorySchemaProvider::new();
            let batch = one_int_batch();
            public
                .register_table(
                    "a_one".to_string(),
                    Arc::new(MemTable::try_new(batch.schema(), vec![vec![batch]]).unwrap()),
                )
                .unwrap();
            alpha.register_schema("public", Arc::new(public)).unwrap();
        }
        let beta = Arc::new(MemoryCatalogProvider::new()) as Arc<dyn CatalogProvider>;
        {
            let public = MemorySchemaProvider::new();
            let batch = one_int_batch();
            public
                .register_table(
                    "b_one".to_string(),
                    Arc::new(MemTable::try_new(batch.schema(), vec![vec![batch]]).unwrap()),
                )
                .unwrap();
            beta.register_schema("public", Arc::new(public)).unwrap();
        }

        // SessionContext with both catalogs registered AND
        // information_schema enabled (so the scoped pg_class can
        // execute via the standard query path).
        let cfg =
            datafusion::execution::context::SessionConfig::new().with_information_schema(true);
        let state = SessionStateBuilder::new()
            .with_config(cfg)
            .with_default_features()
            .build();
        let ctx = SessionContext::new_with_state(state);
        ctx.register_catalog("alpha", Arc::clone(&alpha));
        ctx.register_catalog("beta", Arc::clone(&beta));

        // Scoped provider for alpha only. The full catalog list is
        // the session's live list — `pg_database` lookups go through
        // the flat half built from this list; everything else routes
        // to the scoped half.
        let ctx_state = ctx.state();
        let full_list = Arc::clone(ctx_state.catalog_list());
        let scoped =
            super::build_scoped_pg_catalog_schema("alpha", Arc::clone(&alpha), full_list).unwrap();

        // Register the scoped pg_catalog under a fresh catalog so the
        // query path can resolve `scope.pg_catalog.pg_class`. Using
        // a synthetic catalog name keeps the test independent of
        // whether `alpha` itself already has a pg_catalog schema.
        let scope_holder = MemoryCatalogProvider::new();
        scope_holder.register_schema("pg_catalog", scoped).unwrap();
        ctx.register_catalog("scope", Arc::new(scope_holder));

        let df = ctx
            .sql(
                "SELECT relname FROM scope.pg_catalog.pg_class \
                 WHERE relkind = 'r' \
                 ORDER BY relname",
            )
            .await
            .expect("scoped pg_class query must plan");
        let batches = df
            .collect()
            .await
            .expect("scoped pg_class query must execute");

        // Collect the relname column into a Vec<String>.
        let mut relnames: Vec<String> = Vec::new();
        for batch in &batches {
            let col = batch
                .column(0)
                .as_any()
                .downcast_ref::<datafusion::arrow::array::StringArray>()
                .expect("relname is a String column");
            for i in 0..col.len() {
                if !col.is_null(i) {
                    relnames.push(col.value(i).to_string());
                }
            }
        }

        // The load-bearing assertion: scoped provider MUST contain
        // `a_one` (alpha's table) AND MUST NOT contain `b_one`
        // (beta's table — beta isn't in the scoped catalog list).
        assert!(
            relnames.contains(&"a_one".to_string()),
            "scoped pg_class missing alpha's table 'a_one'; got: {relnames:?}"
        );
        assert!(
            !relnames.contains(&"b_one".to_string()),
            "scoped pg_class LEAKED beta's table 'b_one' — \
             single-catalog-list trick did NOT scope; got: {relnames:?}"
        );
    }

    ///  — L3 from the spec's test inventory.
    ///
    /// Per-catalog `pg_namespace` scoping: a scoped-for-`alpha` provider
    /// MUST list only `alpha`'s schemas. Both catalogs have a `public`
    /// schema, so the load-bearing assertion is that `public` appears
    /// **exactly once** (alpha's) — not duplicated `public×N` across every
    /// catalog, which is what an unscoped flat `pg_namespace` would show
    /// (and what `\dn` would render as confusing duplicates).
    #[tokio::test]
    async fn build_scoped_pg_catalog_schema_scopes_pg_namespace_to_one_catalog() {
        use datafusion::execution::session_state::SessionStateBuilder;

        let alpha = Arc::new(MemoryCatalogProvider::new()) as Arc<dyn CatalogProvider>;
        alpha
            .register_schema("public", Arc::new(MemorySchemaProvider::new()))
            .unwrap();
        let beta = Arc::new(MemoryCatalogProvider::new()) as Arc<dyn CatalogProvider>;
        beta.register_schema("public", Arc::new(MemorySchemaProvider::new()))
            .unwrap();

        let cfg =
            datafusion::execution::context::SessionConfig::new().with_information_schema(true);
        let state = SessionStateBuilder::new()
            .with_config(cfg)
            .with_default_features()
            .build();
        let ctx = SessionContext::new_with_state(state);
        ctx.register_catalog("alpha", Arc::clone(&alpha));
        ctx.register_catalog("beta", Arc::clone(&beta));

        let full_list = Arc::clone(ctx.state().catalog_list());
        let scoped =
            super::build_scoped_pg_catalog_schema("alpha", Arc::clone(&alpha), full_list).unwrap();
        let scope_holder = MemoryCatalogProvider::new();
        scope_holder.register_schema("pg_catalog", scoped).unwrap();
        ctx.register_catalog("scope", Arc::new(scope_holder));

        let batches = ctx
            .sql("SELECT nspname FROM scope.pg_catalog.pg_namespace ORDER BY nspname")
            .await
            .expect("scoped pg_namespace query must plan")
            .collect()
            .await
            .expect("scoped pg_namespace query must execute");

        let mut nspnames: Vec<String> = Vec::new();
        for batch in &batches {
            let col = batch
                .column(0)
                .as_any()
                .downcast_ref::<datafusion::arrow::array::StringArray>()
                .expect("nspname is a String column");
            for i in 0..col.len() {
                if !col.is_null(i) {
                    nspnames.push(col.value(i).to_string());
                }
            }
        }

        let public_count = nspnames.iter().filter(|n| *n == "public").count();
        assert_eq!(
            public_count, 1,
            "scoped pg_namespace must show alpha's `public` exactly once (no cross-catalog \
             duplication); got: {nspnames:?}"
        );
    }

    ///  — `pg_namespace` must expose the **system** namespaces
    /// (`pg_catalog` at oid 11, `information_schema` at 13283) alongside the
    /// user schemas. Upstream builds the table from user schemas only, so the
    /// built-in types in `pg_type` (all `typnamespace = 11`) had no namespace
    /// row to join to — Npgsql's type-loader then returned zero types. This
    /// pins that (a) both system rows are present with the right oids, and
    /// (b) the user `public` schema still appears (augmentation, not
    /// replacement).
    #[tokio::test]
    async fn scoped_pg_namespace_includes_system_namespaces() {
        use datafusion::execution::session_state::SessionStateBuilder;

        let alpha = Arc::new(MemoryCatalogProvider::new()) as Arc<dyn CatalogProvider>;
        alpha
            .register_schema("public", Arc::new(MemorySchemaProvider::new()))
            .unwrap();

        let cfg =
            datafusion::execution::context::SessionConfig::new().with_information_schema(true);
        let state = SessionStateBuilder::new()
            .with_config(cfg)
            .with_default_features()
            .build();
        let ctx = SessionContext::new_with_state(state);
        ctx.register_catalog("alpha", Arc::clone(&alpha));

        let full_list = Arc::clone(ctx.state().catalog_list());
        let scoped =
            super::build_scoped_pg_catalog_schema("alpha", Arc::clone(&alpha), full_list).unwrap();
        let scope_holder = MemoryCatalogProvider::new();
        scope_holder.register_schema("pg_catalog", scoped).unwrap();
        ctx.register_catalog("scope", Arc::new(scope_holder));

        let batches = ctx
            .sql("SELECT oid, nspname FROM scope.pg_catalog.pg_namespace")
            .await
            .expect("pg_namespace query must plan")
            .collect()
            .await
            .expect("pg_namespace query must execute");

        let mut rows: Vec<(i32, String)> = Vec::new();
        for batch in &batches {
            let oids = batch
                .column(0)
                .as_any()
                .downcast_ref::<Int32Array>()
                .expect("oid is Int32");
            let names = batch
                .column(1)
                .as_any()
                .downcast_ref::<StringArray>()
                .expect("nspname is Utf8");
            for i in 0..batch.num_rows() {
                rows.push((oids.value(i), names.value(i).to_string()));
            }
        }

        assert!(
            rows.contains(&(PG_CATALOG_NAMESPACE_OID, "pg_catalog".to_string())),
            "pg_namespace must include pg_catalog at oid {PG_CATALOG_NAMESPACE_OID}; got {rows:?}"
        );
        assert!(
            rows.contains(&(
                INFORMATION_SCHEMA_NAMESPACE_OID,
                "information_schema".to_string()
            )),
            "pg_namespace must include information_schema at oid \
             {INFORMATION_SCHEMA_NAMESPACE_OID}; got {rows:?}"
        );
        assert!(
            rows.iter().any(|(_, n)| n == "public"),
            "user schema `public` must still appear (augmentation, not replacement); got {rows:?}"
        );
    }

    ///  (the actual client symptom) — the Npgsql/Power BI type-loader
    /// join `pg_type ⨝ pg_namespace ON typnamespace = oid` must return the
    /// built-in types. Before the fix this returned zero rows because no
    /// `pg_namespace` row had `oid = 11`.
    #[tokio::test]
    async fn pg_type_joins_pg_namespace_for_builtin_types() {
        use datafusion::execution::session_state::SessionStateBuilder;

        let alpha = Arc::new(MemoryCatalogProvider::new()) as Arc<dyn CatalogProvider>;
        alpha
            .register_schema("public", Arc::new(MemorySchemaProvider::new()))
            .unwrap();

        let cfg =
            datafusion::execution::context::SessionConfig::new().with_information_schema(true);
        let state = SessionStateBuilder::new()
            .with_config(cfg)
            .with_default_features()
            .build();
        let ctx = SessionContext::new_with_state(state);
        ctx.register_catalog("alpha", Arc::clone(&alpha));

        let full_list = Arc::clone(ctx.state().catalog_list());
        let scoped =
            super::build_scoped_pg_catalog_schema("alpha", Arc::clone(&alpha), full_list).unwrap();
        let scope_holder = MemoryCatalogProvider::new();
        scope_holder.register_schema("pg_catalog", scoped).unwrap();
        ctx.register_catalog("scope", Arc::new(scope_holder));

        let batches = ctx
            .sql(
                "SELECT t.typname FROM scope.pg_catalog.pg_type t \
                 JOIN scope.pg_catalog.pg_namespace n ON n.oid = t.typnamespace \
                 WHERE t.typname IN ('int4','text','bool')",
            )
            .await
            .expect("type-loader join must plan")
            .collect()
            .await
            .expect("type-loader join must execute");

        let mut names: Vec<String> = Vec::new();
        for batch in &batches {
            let col = batch
                .column(0)
                .as_any()
                .downcast_ref::<StringArray>()
                .expect("typname is Utf8");
            for i in 0..col.len() {
                names.push(col.value(i).to_string());
            }
        }
        assert!(
            ["int4", "text", "bool"]
                .iter()
                .all(|t| names.iter().any(|n| n == t)),
            "type-loader join must resolve built-in types via typnamespace=11; got {names:?}"
        );
    }

    ///  — `pg_settings` must expose the capability GUCs that BI clients
    /// read on connect (`server_version_num`, `client_encoding`, …), not just
    /// upstream's lone `standard_conforming_strings`. Pins that (a) an added
    /// GUC resolves with the right value, (b) `standard_conforming_strings`
    /// (which upstream already ships) appears exactly once — no duplicate from
    /// the augmentation, and (c) the value agrees with `current_setting`.
    #[tokio::test]
    async fn scoped_pg_settings_includes_capability_gucs() {
        use datafusion::execution::session_state::SessionStateBuilder;

        let alpha = Arc::new(MemoryCatalogProvider::new()) as Arc<dyn CatalogProvider>;
        alpha
            .register_schema("public", Arc::new(MemorySchemaProvider::new()))
            .unwrap();

        let cfg =
            datafusion::execution::context::SessionConfig::new().with_information_schema(true);
        let state = SessionStateBuilder::new()
            .with_config(cfg)
            .with_default_features()
            .build();
        let ctx = SessionContext::new_with_state(state);
        ctx.register_catalog("alpha", Arc::clone(&alpha));

        let full_list = Arc::clone(ctx.state().catalog_list());
        let scoped =
            super::build_scoped_pg_catalog_schema("alpha", Arc::clone(&alpha), full_list).unwrap();
        let scope_holder = MemoryCatalogProvider::new();
        scope_holder.register_schema("pg_catalog", scoped).unwrap();
        ctx.register_catalog("scope", Arc::new(scope_holder));

        let batches = ctx
            .sql("SELECT name, setting FROM scope.pg_catalog.pg_settings")
            .await
            .expect("pg_settings query must plan")
            .collect()
            .await
            .expect("pg_settings query must execute");

        let mut rows: Vec<(String, String)> = Vec::new();
        for batch in &batches {
            let names = batch
                .column(0)
                .as_any()
                .downcast_ref::<StringArray>()
                .expect("name is Utf8");
            let settings = batch
                .column(1)
                .as_any()
                .downcast_ref::<StringArray>()
                .expect("setting is Utf8");
            for i in 0..batch.num_rows() {
                rows.push((names.value(i).to_string(), settings.value(i).to_string()));
            }
        }

        assert!(
            rows.iter()
                .any(|(n, v)| n == "server_version_num" && v == "160006"),
            "pg_settings must expose server_version_num=160006; got {rows:?}"
        );
        assert!(
            rows.iter().any(|(n, _)| n == "client_encoding"),
            "pg_settings must expose client_encoding; got {rows:?}"
        );
        let scs = rows
            .iter()
            .filter(|(n, _)| n == "standard_conforming_strings")
            .count();
        assert_eq!(
            scs, 1,
            "standard_conforming_strings (shipped by upstream) must not be duplicated by the \
             augmentation; got {rows:?}"
        );
    }

    ///  — `pg_roles` must list the Dataglot roles handed to
    /// `build_scoped_pg_catalog_schema_with_roles` (from the server's
    /// identity/role config), with `rolcanlogin` reflecting user vs. group
    /// roles. Empty config still yields empty `pg_roles` (unchanged default).
    #[tokio::test]
    async fn scoped_pg_roles_lists_configured_roles() {
        use datafusion::arrow::array::BooleanArray;
        use datafusion::execution::session_state::SessionStateBuilder;

        let alpha = Arc::new(MemoryCatalogProvider::new()) as Arc<dyn CatalogProvider>;
        alpha
            .register_schema("public", Arc::new(MemorySchemaProvider::new()))
            .unwrap();

        let cfg =
            datafusion::execution::context::SessionConfig::new().with_information_schema(true);
        let state = SessionStateBuilder::new()
            .with_config(cfg)
            .with_default_features()
            .build();
        let ctx = SessionContext::new_with_state(state);
        ctx.register_catalog("alpha", Arc::clone(&alpha));

        let full_list = Arc::clone(ctx.state().catalog_list());
        let roles = vec![
            super::PgRoleSpec {
                name: "analyst".to_string(),
                is_superuser: false,
                can_login: true,
            },
            super::PgRoleSpec {
                name: "readers".to_string(),
                is_superuser: false,
                can_login: false,
            },
        ];
        let scoped = super::build_scoped_pg_catalog_schema_with_roles(
            "alpha",
            Arc::clone(&alpha),
            full_list,
            &roles,
        )
        .unwrap();
        let scope_holder = MemoryCatalogProvider::new();
        scope_holder.register_schema("pg_catalog", scoped).unwrap();
        ctx.register_catalog("scope", Arc::new(scope_holder));

        let batches = ctx
            .sql("SELECT rolname, rolcanlogin FROM scope.pg_catalog.pg_roles ORDER BY rolname")
            .await
            .expect("pg_roles query must plan")
            .collect()
            .await
            .expect("pg_roles query must execute");

        let mut rows: Vec<(String, bool)> = Vec::new();
        for batch in &batches {
            let names = batch
                .column(0)
                .as_any()
                .downcast_ref::<StringArray>()
                .expect("rolname is Utf8");
            let canlogin = batch
                .column(1)
                .as_any()
                .downcast_ref::<BooleanArray>()
                .expect("rolcanlogin is Boolean");
            for i in 0..batch.num_rows() {
                rows.push((names.value(i).to_string(), canlogin.value(i)));
            }
        }

        assert!(
            rows.contains(&("analyst".to_string(), true)),
            "pg_roles must list the login user `analyst`; got {rows:?}"
        );
        assert!(
            rows.contains(&("readers".to_string(), false)),
            "pg_roles must list the group role `readers` (no login); got {rows:?}"
        );
    }

    ///  — `pg_database` MUST remain cross-catalog ("server-wide"
    /// in pg semantics) even when accessed through a scoped provider.
    /// `\l` reads `pg_database` and must enumerate every Dataglot
    /// catalog as a database — the pg-native equivalent of Trino's
    /// `SHOW CATALOGS`. Without this routing, a connection to
    /// `database=pg` would see only `pg` in `\l`, which is a
    /// regression vs Layer A's behaviour.
    ///
    /// Sets up the same two-catalog session as the scoping test
    /// above. Queries `pg_database` through the scoped-for-alpha
    /// provider; asserts the result contains BOTH `alpha` and `beta`
    /// (because the flat half iterates the session's full catalog
    /// list, not the single-catalog scoped list).
    #[tokio::test]
    async fn build_scoped_pg_catalog_schema_keeps_pg_database_cross_catalog() {
        use datafusion::execution::session_state::SessionStateBuilder;

        let alpha = Arc::new(MemoryCatalogProvider::new()) as Arc<dyn CatalogProvider>;
        let beta = Arc::new(MemoryCatalogProvider::new()) as Arc<dyn CatalogProvider>;

        let cfg =
            datafusion::execution::context::SessionConfig::new().with_information_schema(true);
        let state = SessionStateBuilder::new()
            .with_config(cfg)
            .with_default_features()
            .build();
        let ctx = SessionContext::new_with_state(state);
        ctx.register_catalog("alpha", Arc::clone(&alpha));
        ctx.register_catalog("beta", Arc::clone(&beta));

        let ctx_state = ctx.state();
        let full_list = Arc::clone(ctx_state.catalog_list());
        let scoped =
            super::build_scoped_pg_catalog_schema("alpha", Arc::clone(&alpha), full_list).unwrap();

        let scope_holder = MemoryCatalogProvider::new();
        scope_holder.register_schema("pg_catalog", scoped).unwrap();
        ctx.register_catalog("scope", Arc::new(scope_holder));

        let df = ctx
            .sql("SELECT datname FROM scope.pg_catalog.pg_database ORDER BY datname")
            .await
            .expect("pg_database query must plan");
        let batches = df.collect().await.expect("pg_database query must execute");

        let mut datnames: Vec<String> = Vec::new();
        for batch in &batches {
            let col = batch
                .column(0)
                .as_any()
                .downcast_ref::<datafusion::arrow::array::StringArray>()
                .expect("datname is a String column");
            for i in 0..col.len() {
                if !col.is_null(i) {
                    datnames.push(col.value(i).to_string());
                }
            }
        }

        // Cross-catalog assertion: BOTH alpha and beta must appear
        // because pg_database is server-wide. If only `alpha` is
        // present, the hybrid routing regressed and we're scoping
        // pg_database — `\l` would mislead the user.
        assert!(
            datnames.contains(&"alpha".to_string()),
            "pg_database missing alpha; got: {datnames:?}"
        );
        assert!(
            datnames.contains(&"beta".to_string()),
            "pg_database missing beta — scoped provider INCORRECTLY \
             restricted server-wide pg_database to its single-catalog list. \
             Got: {datnames:?}"
        );
    }

    /// G2 — `HybridPgCatalogSchema::table` must route
    /// server-wide table names case-insensitively. PostgreSQL treats
    /// unquoted identifiers case-insensitively and the rest of the
    /// overlay already uses `eq_ignore_ascii_case`, so a
    /// request for `"PG_DATABASE"` must still reach the flat half.
    ///
    /// Uses marker providers so the assertion sees *which half* served
    /// the request, independent of the upstream tables' own casing.
    #[tokio::test]
    async fn hybrid_routes_server_wide_table_case_insensitively() {
        /// A `SchemaProvider` whose `table()` returns a one-column table
        /// named after `marker`, regardless of the requested name — so a
        /// test can tell which half of the hybrid was consulted.
        #[derive(Debug)]
        struct MarkerSchema {
            marker: &'static str,
        }

        #[async_trait]
        impl SchemaProvider for MarkerSchema {
            fn table_names(&self) -> Vec<String> {
                Vec::new()
            }
            async fn table(&self, _name: &str) -> DfResult<Option<Arc<dyn TableProvider>>> {
                let schema = Arc::new(ArrowSchema::new(vec![Field::new(
                    self.marker,
                    DataType::Int32,
                    false,
                )]));
                let batch =
                    RecordBatch::try_new(schema.clone(), vec![Arc::new(Int32Array::from(vec![1]))])
                        .unwrap();
                Ok(Some(Arc::new(
                    MemTable::try_new(schema, vec![vec![batch]]).unwrap(),
                )))
            }
            fn table_exist(&self, _name: &str) -> bool {
                true
            }
        }

        // Returns the single column name of whichever half served `name`.
        async fn served_by(hybrid: &HybridPgCatalogSchema, name: &str) -> String {
            let table = hybrid
                .table(name)
                .await
                .expect("table lookup must not error")
                .expect("marker provider always returns a table");
            table.schema().field(0).name().clone()
        }

        let hybrid = HybridPgCatalogSchema {
            scoped: Arc::new(MarkerSchema { marker: "scoped" }),
            flat: Arc::new(MarkerSchema { marker: "flat" }),
        };

        // Server-wide table, every casing → flat half.
        assert_eq!(served_by(&hybrid, "pg_database").await, "flat");
        assert_eq!(served_by(&hybrid, "PG_DATABASE").await, "flat");
        assert_eq!(served_by(&hybrid, "Pg_Database").await, "flat");
        // Per-database table → scoped half (the default route).
        assert_eq!(served_by(&hybrid, "pg_class").await, "scoped");
        assert_eq!(served_by(&hybrid, "PG_CLASS").await, "scoped");
    }

    ///  — T5 positive case from the spec's test inventory.
    ///
    /// A factory-built `SessionContext` MUST have `pg_catalog`
    /// registered under the configured default catalog, and
    /// `extract_pg_catalog_schema` MUST return it as
    /// `Arc<dyn SchemaProvider>`. Pins the contract
    /// `dataglot-server::create_session` relies on when it calls
    /// `extract_pg_catalog_schema(&ctx, &self.config.default_catalog)`.
    #[tokio::test]
    async fn extract_pg_catalog_schema_returns_registered_schema_on_factory_context() {
        use crate::session::SessionContextFactory;

        let factory = SessionContextFactory::with_defaults().expect("factory builds");
        let ctx = factory.create_context();
        // Default catalog is "dataglot" per `SessionConfig::default`.
        let schema = super::extract_pg_catalog_schema(&ctx, "dataglot")
            .expect("factory registered pg_catalog");
        assert!(
            schema.table_names().iter().any(|n| n == "pg_class"),
            "pg_catalog schema must expose pg_class; got: {:?}",
            schema.table_names()
        );
    }

    ///  — T5 negative cases. `extract_pg_catalog_schema` MUST
    /// return a `Configuration` error (not panic, not silently
    /// return `None`) when:
    /// - the requested catalog name doesn't exist on the session
    /// - the catalog exists but has no `pg_catalog` schema (e.g. a
    ///   raw `SessionContext::new()` with no factory setup)
    #[test]
    fn extract_pg_catalog_schema_errors_when_catalog_missing() {
        let ctx = SessionContext::new();
        let result = super::extract_pg_catalog_schema(&ctx, "no_such_catalog");
        assert!(result.is_err(), "missing catalog must error, not panic");
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains("no_such_catalog"),
            "error must name the missing catalog: {msg}"
        );
    }

    #[test]
    fn extract_pg_catalog_schema_errors_when_pg_catalog_absent_on_existing_catalog() {
        // Raw `SessionContext::new()` creates a default catalog ("datafusion")
        // with no pg_catalog schema. The factory is what installs it.
        let ctx = SessionContext::new();
        let result = super::extract_pg_catalog_schema(&ctx, "datafusion");
        assert!(
            result.is_err(),
            "absent pg_catalog must error, not panic; got Ok"
        );
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains("pg_catalog") && msg.contains("datafusion"),
            "error must name both pg_catalog and the catalog: {msg}"
        );
    }

    ///  — T6 from the spec's test inventory.
    ///
    /// CLAUDE.md rule 13: schema inference is lazy. Wrapping a
    /// federated `CatalogProvider` with `PgCatalogOverlayProvider`
    /// MUST NOT call into the wrapped provider's schema lookup
    /// machinery just to enumerate `schema_names()` — wrapping is a
    /// pure decoration that defers to the inner provider on demand.
    /// Without this guarantee, every server boot would force a
    /// schema fetch against every federated source (Postgres,
    /// MySQL, Iceberg) at wrap time.
    ///
    /// We pin this by giving the inner provider a `schema()` impl
    /// that increments a counter, then asserting that
    /// `wrapper.schema_names()` calls the counter exactly 0 times
    /// (`schema_names` should NOT trigger `schema` lookups).
    #[test]
    fn wrapping_does_not_trigger_inner_schema_lookups() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        #[derive(Debug)]
        struct CountingCatalog {
            schema_lookups: Arc<AtomicUsize>,
            inner: MemoryCatalogProvider,
        }

        impl CatalogProvider for CountingCatalog {
            fn schema_names(&self) -> Vec<String> {
                // No counter bump — schema_names returns metadata,
                // not schema providers. This is the path the wrapper
                // exercises during register_catalog / startup.
                self.inner.schema_names()
            }
            fn schema(&self, name: &str) -> Option<Arc<dyn SchemaProvider>> {
                self.schema_lookups.fetch_add(1, Ordering::SeqCst);
                self.inner.schema(name)
            }
        }

        let counter = Arc::new(AtomicUsize::new(0));
        let mem = MemoryCatalogProvider::new();
        mem.register_schema("public", Arc::new(MemorySchemaProvider::new()))
            .unwrap();
        let inner = Arc::new(CountingCatalog {
            schema_lookups: Arc::clone(&counter),
            inner: mem,
        });

        let overlay = PgCatalogOverlayProvider::new(inner, dummy_pg_catalog_schema());

        // schema_names() — must not trigger a single inner.schema() call.
        let names = overlay.schema_names();
        assert!(names.contains(&"public".to_string()));
        assert!(names.contains(&"pg_catalog".to_string()));
        assert_eq!(
            counter.load(Ordering::SeqCst),
            0,
            "schema_names() must not call inner.schema()"
        );

        // schema("pg_catalog") — served from the overlay, must NOT delegate.
        let _ = overlay.schema("pg_catalog");
        assert_eq!(
            counter.load(Ordering::SeqCst),
            0,
            "schema(\"pg_catalog\") must be served from the overlay, not the inner"
        );

        // schema("public") — delegates exactly once.
        let _ = overlay.schema("public");
        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "schema(\"public\") must delegate to inner exactly once"
        );

        // schema("does_not_exist") — also delegates (and returns None).
        let _ = overlay.schema("does_not_exist");
        assert_eq!(
            counter.load(Ordering::SeqCst),
            2,
            "schema(\"does_not_exist\") must delegate to inner"
        );
    }
}

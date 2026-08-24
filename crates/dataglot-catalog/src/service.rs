//! `CatalogService` — the Phase 1 in-process catalog control plane.
//!
//! Owns the Postgres pool, the org scope, and the boot-time
//! schema-version guard. Spec:
//! `docs/phases/phase-1/08-catalog-service.md`.

use std::collections::HashMap;
use std::str::FromStr;

use async_trait::async_trait;
use dataglot_core::CatalogBinding;
use deadpool_postgres::{Config as PoolConfig, ManagerConfig, Pool, RecyclingMethod, Runtime};
use futures::future::poll_fn;
use serde_json::Value;
use tokio::sync::mpsc;
use tokio_postgres::{AsyncMessage, Config as PgConfig, NoTls};

use crate::error::{CatalogServiceError, Result};
use crate::migrations::{plan_postgres_migrations, version_rank, PostgresMigration};
use crate::store::{
    DerivedProductRecord, GrantObject, GrantRecord, GranteeKind, MetaStore, PolicyRecord,
    UserRecord,
};
use crate::subscribe::{BindingChange, BindingChangeStream};

/// Schema version this build of `dataglot-catalog` understands — the target
/// the migration runner brings a database up to (the last step of the internal
/// `POSTGRES_MIGRATIONS` chain). Bumping requires landing a new migration step.
///
/// `v2` adds the derived-product (`CREATE VIEW`) definition
/// columns to `data_product`. Those columns can't reach an existing `v1`
/// database by living in the `v1` baseline DDL — that DDL only runs on a fresh
/// database (a database already at `v1` applies nothing) — so they land as a
/// dedicated, additive `v2` migration step that the runner applies to any `v1`
/// database on connect.
pub const SCHEMA_VERSION: &str = "v2";

/// DDL run at `connect` time. All `IF NOT EXISTS` so the
/// service tolerates a partially-initialised database — the
/// only way to leave the DB in a half-set-up state is a crash
/// mid-DDL, which is rare and recoverable. Forward-compat
/// tables (`share`, `attachment`) ship empty in Phase 1; the
/// schema slots exist so Phase 2 doesn't need a migration to
/// turn them on.
const SCHEMA_V1_DDL: &str = "
    CREATE TABLE IF NOT EXISTS schema_version (
        version TEXT PRIMARY KEY,
        applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS org (
        org_id TEXT PRIMARY KEY,
        display_name TEXT NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS catalog_binding (
        org_id TEXT NOT NULL REFERENCES org(org_id),
        name TEXT NOT NULL,
        binding_json JSONB NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        PRIMARY KEY (org_id, name)
    );

    -- Task 12 slice 1: full source config (a serialized, credential-free
    -- CatalogConfig — `*_env` names only, never secret values) so the server
    -- can build live providers FROM the control plane, not just from
    -- dataglot.json. Additive + nullable + IF NOT EXISTS, so it needs no
    -- SCHEMA_VERSION bump: a v1 database gains the column idempotently and an
    -- older binary simply ignores it.
    ALTER TABLE catalog_binding ADD COLUMN IF NOT EXISTS source_config JSONB;

    CREATE TABLE IF NOT EXISTS data_product (
        org_id TEXT NOT NULL REFERENCES org(org_id),
        data_product_id TEXT NOT NULL,
        name TEXT NOT NULL,
        description TEXT,
        llm_generated BOOLEAN NOT NULL DEFAULT FALSE,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        PRIMARY KEY (org_id, data_product_id)
    );

    CREATE TABLE IF NOT EXISTS share (
        share_id UUID PRIMARY KEY,
        source_org TEXT NOT NULL REFERENCES org(org_id),
        target_org TEXT NOT NULL REFERENCES org(org_id),
        data_product_id TEXT NOT NULL,
        granted_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS attachment (
        org_id TEXT NOT NULL REFERENCES org(org_id),
        local_name TEXT NOT NULL,
        share_id UUID NOT NULL REFERENCES share(share_id),
        attached_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        PRIMARY KEY (org_id, local_name)
    );

    -- first-class secrets. `ciphertext` is opaque,
    -- already-encrypted bytes (the envelope key lives in dataglot-server,
    -- never here — rule 12); this table never stores plaintext. Additive
    -- CREATE TABLE IF NOT EXISTS, so no SCHEMA_VERSION bump (same posture as
    -- the source_config column above).
    CREATE TABLE IF NOT EXISTS secret (
        org_id TEXT NOT NULL REFERENCES org(org_id),
        name TEXT NOT NULL,
        ciphertext BYTEA NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        PRIMARY KEY (org_id, name)
    );

    -- user/role surface. `password_hash` is an opaque,
    -- already-hashed string (the plaintext is hashed in dataglot-server, never
    -- here — rule 12); NULL means the user cannot log in with a password. Table
    -- names are `db_user`/`db_role` to avoid the reserved words `user`/`role`.
    -- Additive CREATE TABLE IF NOT EXISTS, so no SCHEMA_VERSION bump (same
    -- posture as the `secret` table + `source_config` column above).
    CREATE TABLE IF NOT EXISTS db_user (
        org_id TEXT NOT NULL REFERENCES org(org_id),
        name TEXT NOT NULL,
        password_hash TEXT,
        is_superuser BOOL NOT NULL DEFAULT false,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        PRIMARY KEY (org_id, name)
    );

    CREATE TABLE IF NOT EXISTS db_role (
        org_id TEXT NOT NULL REFERENCES org(org_id),
        name TEXT NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        PRIMARY KEY (org_id, name)
    );

    -- governance policies (column masks + row filters).
    -- `rule` is the serialized rule body — an opaque JSONB value shaped like
    -- the server's MaskConfig / RowFilterConfig; this crate persists it
    -- verbatim and never interprets it (rule 4), exactly like
    -- catalog_binding.source_config. `kind` is 'mask' or 'row_filter'.
    -- Additive CREATE TABLE IF NOT EXISTS, so no SCHEMA_VERSION bump (same
    -- posture as the `secret`/`db_user`/`db_role` tables above).
    CREATE TABLE IF NOT EXISTS db_policy (
        org_id TEXT NOT NULL REFERENCES org(org_id),
        name TEXT NOT NULL,
        kind TEXT NOT NULL,
        rule JSONB NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        PRIMARY KEY (org_id, name)
    );

    -- privilege grants + role membership. This layer STORES grants
    -- but does not enforce them (enforcement is a later layer), so these tables change no
    -- query behaviour. All columns NOT NULL: for a USAGE grant (object = a
    -- catalog) `obj_schema`/`obj_table` are the empty string, for a SELECT grant
    -- (object = catalog.schema.table) all three are set; the `privilege` column
    -- discriminates. The full tuple is the primary key, giving an idempotent
    -- upsert (ON CONFLICT DO NOTHING) and an exact-match delete. Additive
    -- CREATE TABLE IF NOT EXISTS, so no SCHEMA_VERSION bump (same posture as the
    -- secret/db_user/db_role/db_policy tables above).
    CREATE TABLE IF NOT EXISTS db_grant (
        org_id TEXT NOT NULL REFERENCES org(org_id),
        grantee_kind TEXT NOT NULL,
        grantee TEXT NOT NULL,
        privilege TEXT NOT NULL,
        obj_catalog TEXT NOT NULL,
        obj_schema TEXT NOT NULL,
        obj_table TEXT NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        PRIMARY KEY (org_id, grantee_kind, grantee, privilege, obj_catalog, obj_schema, obj_table)
    );

    CREATE TABLE IF NOT EXISTS db_role_member (
        org_id TEXT NOT NULL REFERENCES org(org_id),
        role TEXT NOT NULL,
        member TEXT NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        PRIMARY KEY (org_id, role, member)
    );

    -- LISTEN/NOTIFY trigger for the Phase 1 task 09 cache.
    -- Emits a JSON payload on every INSERT/UPDATE/DELETE
    -- against `catalog_binding` so the in-process cache can
    -- evict by key. Self-loop on the service's own upsert is
    -- intentional per the spec — the cache rebuilds the same
    -- way it would for an external write.
    --
    -- `CREATE OR REPLACE FUNCTION` makes the trigger DDL
    -- idempotent. The `DROP TRIGGER IF EXISTS` is belt-and-
    -- braces; `CREATE TRIGGER` is not itself `IF NOT EXISTS`-
    -- safe across all Postgres versions.
    CREATE OR REPLACE FUNCTION notify_catalog_binding_change() RETURNS trigger AS $$
    BEGIN
        IF TG_OP = 'DELETE' THEN
            PERFORM pg_notify('catalog_binding_changed', json_build_object(
                'org_id', OLD.org_id,
                'name',   OLD.name,
                'kind',   'deleted'
            )::text);
        ELSE
            PERFORM pg_notify('catalog_binding_changed', json_build_object(
                'org_id', NEW.org_id,
                'name',   NEW.name,
                'kind',   'upserted'
            )::text);
        END IF;
        RETURN NULL;
    END;
    $$ LANGUAGE plpgsql;

    DROP TRIGGER IF EXISTS catalog_binding_change_notify ON catalog_binding;
    CREATE TRIGGER catalog_binding_change_notify
        AFTER INSERT OR UPDATE OR DELETE ON catalog_binding
        FOR EACH ROW EXECUTE FUNCTION notify_catalog_binding_change();
";

/// Bootstrap DDL for the version ledger itself — run before the migration
/// runner reads the current version, so a brand-new database has somewhere to
/// read from (it comes back empty ⇒ "fresh"). Idempotent, and a subset of
/// [`SCHEMA_V1_DDL`] (which re-declares the same table `IF NOT EXISTS`), so the
/// two never conflict.
const SCHEMA_VERSION_TABLE_DDL: &str = "
    CREATE TABLE IF NOT EXISTS schema_version (
        version TEXT PRIMARY KEY,
        applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
";

///  F9 (`v2`): derived-product (`CREATE VIEW`) definition columns on the
/// existing `data_product` table. Additive + nullable + `IF NOT EXISTS`, so it
/// is safe to re-run against a partially-applied database. Wired as its own
/// migration step (not folded into [`SCHEMA_V1_DDL`]) so it reaches a database
/// already recorded at `v1` — which never re-runs the baseline DDL. `sql` holds
/// the verbatim `AS <query>` body; `catalog`/`schema` are the optional resolve
/// location (NULL ⇒ server default). A pre-F9 `data_product` row (none are
/// written today) simply has these NULL and is skipped by the F9 reads.
const SCHEMA_V2_DDL: &str = "
    ALTER TABLE data_product ADD COLUMN IF NOT EXISTS sql TEXT;
    ALTER TABLE data_product ADD COLUMN IF NOT EXISTS catalog TEXT;
    ALTER TABLE data_product ADD COLUMN IF NOT EXISTS schema TEXT;
";

/// Ordered Postgres migration chain. Each step's idempotent DDL
/// brings the database up to the version it records. The baseline step is the
/// additive `v1` schema ([`SCHEMA_V1_DDL`]); the `v2` step ([`SCHEMA_V2_DDL`],
///  F9) adds the derived-product columns and is applied by the runner to
/// any database still at `v1`.
const POSTGRES_MIGRATIONS: &[PostgresMigration] = &[
    PostgresMigration {
        to: "v1",
        ddl: SCHEMA_V1_DDL,
    },
    PostgresMigration {
        to: SCHEMA_VERSION,
        ddl: SCHEMA_V2_DDL,
    },
];

/// Handle for the Phase 1 in-process catalog service. Cloning is
/// cheap (`Arc` inside the pool). Single instance per
/// `DataglotServer`.
#[derive(Debug, Clone)]
pub struct CatalogService {
    pool: Pool,
    org_id: String,
    /// Original DSN — held so [`subscribe`](Self::subscribe)
    /// can open a dedicated long-lived LISTEN connection
    /// separate from the pool. The pool is read/write
    /// short-lived; LISTEN ties up a connection so it can't
    /// share with the pool.
    dsn: String,
}

/// Decompose a [`GrantRecord`] into its `db_grant` column values. A USAGE
/// grant (object = a catalog) leaves `schema`/`table` empty; a SELECT grant
/// (object = `catalog.schema.table`) fills all three.
fn grant_columns(
    grant: &GrantRecord,
) -> (&'static str, String, &'static str, String, String, String) {
    let kind = grant.grantee_kind.as_str();
    let privilege = grant.privilege().as_str();
    let (catalog, schema, table) = match grant.object() {
        GrantObject::Catalog(catalog) => (catalog, String::new(), String::new()),
        GrantObject::Table {
            catalog,
            schema,
            table,
        } => (catalog, schema, table),
    };
    (
        kind,
        grant.grantee.clone(),
        privilege,
        catalog,
        schema,
        table,
    )
}

/// Rebuild a [`GrantRecord`] from its `db_grant` column values. The `privilege`
/// column drives the object shape: `SELECT` → a table (all three parts),
/// `USAGE` → a catalog (schema/table ignored). Unknown tokens surface as
/// [`CatalogServiceError::MalformedGrant`].
fn grant_from_columns(
    kind: &str,
    grantee: String,
    privilege: &str,
    catalog: String,
    schema: String,
    table: String,
) -> Result<GrantRecord> {
    let grantee_kind = GranteeKind::from_token(kind).ok_or_else(|| {
        CatalogServiceError::MalformedGrant(format!("unknown grantee_kind {kind:?}"))
    })?;
    match privilege {
        "SELECT" => Ok(GrantRecord::select(
            grantee_kind,
            grantee,
            catalog,
            schema,
            table,
        )),
        "USAGE" => Ok(GrantRecord::usage(grantee_kind, grantee, catalog)),
        other => Err(CatalogServiceError::MalformedGrant(format!(
            "unknown privilege {other:?}"
        ))),
    }
}

impl CatalogService {
    /// Connect to the catalog-service Postgres database and
    /// ensure schema v1 + the named org are present.
    ///
    /// Idempotent: calling `connect` on a fresh database creates
    /// the schema and the named org; calling again is a no-op.
    /// Returns [`CatalogServiceError::SchemaVersionMismatch`] if
    /// the database already carries a different version (means
    /// either a newer dataglot binary has run against it, or the
    /// database wasn't initialised by this crate).
    ///
    /// # Errors
    /// Returns an error if the DSN can't be parsed, the pool
    /// can't be built, the connection fails, the schema DDL
    /// fails, or the version row indicates a mismatch.
    pub async fn connect(dsn: &str, org_id: &str) -> Result<Self> {
        let pg_config = PgConfig::from_str(dsn).map_err(CatalogServiceError::Connect)?;

        // Map tokio-postgres' Config into deadpool's Config —
        // deadpool's `Config` is a wrapper that exposes the
        // same surface plus pool-knob fields. We only need the
        // connection params here; the rest stays at defaults.
        let mut pool_cfg = PoolConfig::new();
        // `Host::Unix` only exists on Unix targets; using a
        // single `Tcp`-only match is portable across Windows
        // builds (Windows `tokio-postgres` doesn't surface the
        // Unix variant at all). The `if let` reads as irrefutable
        // on Windows (one variant) but is needed on Unix where
        // the enum has both; allow the warning unconditionally.
        pool_cfg.host = pg_config.get_hosts().iter().find_map(|h| {
            #[allow(irrefutable_let_patterns)]
            if let tokio_postgres::config::Host::Tcp(s) = h {
                Some(s.clone())
            } else {
                None
            }
        });
        pool_cfg.port = pg_config.get_ports().first().copied();
        pool_cfg.user = pg_config.get_user().map(str::to_string);
        pool_cfg.password = pg_config
            .get_password()
            .and_then(|p| std::str::from_utf8(p).ok())
            .map(str::to_string);
        pool_cfg.dbname = pg_config.get_dbname().map(str::to_string);
        pool_cfg.manager = Some(ManagerConfig {
            recycling_method: RecyclingMethod::Fast,
        });

        let pool = pool_cfg
            .create_pool(Some(Runtime::Tokio1), NoTls)
            .map_err(|e| CatalogServiceError::Pool(e.to_string()))?;

        let svc = Self {
            pool,
            org_id: org_id.to_string(),
            dsn: dsn.to_string(),
        };

        svc.ensure_schema().await?;
        svc.ensure_org(org_id).await?;
        Ok(svc)
    }

    /// Drive the [`POSTGRES_MIGRATIONS`] runner: bootstrap the version ledger,
    /// read the database's current version, then apply each pending step's
    /// idempotent DDL in order, recording its target as it goes. Rejects a
    /// database at a version newer than this build understands.
    ///
    /// Behavior preserved from the pre-framework guard: a fresh database runs
    /// the baseline DDL and records `v1`; a database already at `v1` is current
    /// and applies nothing new; a database at any other version fails fast with
    /// [`CatalogServiceError::SchemaVersionMismatch`].
    async fn ensure_schema(&self) -> Result<()> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| CatalogServiceError::Pool(e.to_string()))?;

        // Ensure the ledger exists so we can read the current version even on a
        // brand-new database.
        client
            .batch_execute(SCHEMA_VERSION_TABLE_DDL)
            .await
            .map_err(CatalogServiceError::Query)?;

        // Current recorded version = the highest-ranked ledger row (one row per
        // applied step), or `None` on a fresh database.
        let rows = client
            .query("SELECT version FROM schema_version", &[])
            .await
            .map_err(CatalogServiceError::Query)?;
        let current: Option<String> = rows
            .iter()
            .map(|r| r.get::<_, String>(0))
            .max_by_key(|v| version_rank(v));

        // Plan the pending steps (fails fast if the DB is newer/unknown), then
        // apply each in order and stamp its target into the ledger.
        let pending = plan_postgres_migrations(current.as_deref(), POSTGRES_MIGRATIONS)?;
        for step in pending {
            client
                .batch_execute(step.ddl)
                .await
                .map_err(CatalogServiceError::Query)?;
            client
                .execute(
                    "INSERT INTO schema_version (version) VALUES ($1)
                     ON CONFLICT (version) DO NOTHING",
                    &[&step.to],
                )
                .await
                .map_err(CatalogServiceError::Query)?;
        }

        Ok(())
    }

    /// Create the named org if missing. Idempotent — Phase 1
    /// always uses `"default"`; Phase 2 will pass real org IDs.
    async fn ensure_org(&self, org_id: &str) -> Result<()> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| CatalogServiceError::Pool(e.to_string()))?;
        client
            .execute(
                "INSERT INTO org (org_id, display_name) VALUES ($1, $1)
                 ON CONFLICT (org_id) DO NOTHING",
                &[&org_id],
            )
            .await
            .map_err(CatalogServiceError::Query)?;
        Ok(())
    }

    /// Org scope this service was constructed with.
    #[must_use]
    pub fn org_id(&self) -> &str {
        &self.org_id
    }

    /// Snapshot every registered binding for `org`. Called by
    /// `DataglotServer::new` at boot to populate the in-process bindings map.
    ///
    /// # Errors
    /// Returns [`CatalogServiceError::Query`] on Postgres-side
    /// failure and [`CatalogServiceError::MalformedBinding`] if
    /// a row's `binding_json` doesn't deserialize into
    /// `CatalogBinding`.
    pub async fn list_bindings(&self, org: &str) -> Result<HashMap<String, CatalogBinding>> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| CatalogServiceError::Pool(e.to_string()))?;

        let rows = client
            .query(
                "SELECT name, binding_json FROM catalog_binding WHERE org_id = $1",
                &[&org],
            )
            .await
            .map_err(CatalogServiceError::Query)?;

        let mut out = HashMap::with_capacity(rows.len());
        for row in rows {
            let name: String = row.get(0);
            let json: Value = row.get(1);
            let binding: CatalogBinding = serde_json::from_value(json).map_err(|source| {
                CatalogServiceError::MalformedBinding {
                    name: name.clone(),
                    source,
                }
            })?;
            out.insert(name, binding);
        }
        Ok(out)
    }

    /// All persisted source configs (serialized `CatalogConfig` per catalog
    /// name), for rows where one has been stored. This is what makes the
    /// control plane a **source of truth**: the server builds live providers
    /// from these — including catalogs that exist only in the DB, never in
    /// `dataglot.toml` (task 12 slice 1) — not just from the file.
    ///
    /// The value is the raw JSON; the caller deserializes it into its own
    /// `CatalogConfig` (this crate doesn't depend on `dataglot-server`,
    /// CLAUDE.md rule 4). Rows with a NULL `source_config` are omitted.
    ///
    /// # Errors
    /// [`CatalogServiceError::Query`] on Postgres-side failure.
    pub async fn list_source_configs(&self, org: &str) -> Result<HashMap<String, Value>> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| CatalogServiceError::Pool(e.to_string()))?;

        let rows = client
            .query(
                "SELECT name, source_config FROM catalog_binding
                 WHERE org_id = $1 AND source_config IS NOT NULL",
                &[&org],
            )
            .await
            .map_err(CatalogServiceError::Query)?;

        let mut out = HashMap::with_capacity(rows.len());
        for row in rows {
            let name: String = row.get(0);
            let cfg: Value = row.get(1);
            out.insert(name, cfg);
        }
        Ok(out)
    }

    /// Persist the full source config (a serialized, credential-free
    /// `CatalogConfig`) for an existing binding row, so the server can
    /// rebuild the live provider from the control plane. Secrets are never
    /// included — the config names `*_env` vars resolved from the environment
    /// at execution time (rule 12).
    ///
    /// This UPDATEs the row created by [`upsert_binding`](Self::upsert_binding);
    /// it is a no-op (0 rows) if no binding exists under `(org_id, name)`.
    ///
    /// # Errors
    /// [`CatalogServiceError::Query`] on Postgres-side failure.
    pub async fn set_source_config(
        &self,
        org: &str,
        name: &str,
        source_config: &Value,
    ) -> Result<()> {
        // FK safety: `catalog_binding` references `org(org_id)`, and this write
        // may target an org not seen at connect (multi-tenant,  M1).
        self.ensure_org(org).await?;
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| CatalogServiceError::Pool(e.to_string()))?;

        client
            .execute(
                "UPDATE catalog_binding SET source_config = $3, updated_at = now()
                 WHERE org_id = $1 AND name = $2",
                &[&org, &name, &source_config],
            )
            .await
            .map_err(CatalogServiceError::Query)?;
        Ok(())
    }

    /// Upsert a binding under `(org_id, name)`. Returns the
    /// previous binding if one existed.
    ///
    /// Called by `DataglotServer::new` for every entry in
    /// `dataglot.toml`'s `[catalogs.*]` block — Phase 1 syncs
    /// JSON → service at boot. JSON wins on conflict.
    ///
    /// # Errors
    /// Returns [`CatalogServiceError::BindingSerialization`] if
    /// the binding can't be serialized (practically impossible
    /// for current variants), and [`CatalogServiceError::Query`]
    /// for Postgres-side failures.
    pub async fn upsert_binding(
        &self,
        org: &str,
        name: &str,
        binding: &CatalogBinding,
    ) -> Result<Option<CatalogBinding>> {
        let json = serde_json::to_value(binding).map_err(|source| {
            CatalogServiceError::BindingSerialization {
                name: name.to_string(),
                source,
            }
        })?;

        // FK safety: `catalog_binding` references `org(org_id)`, and this write
        // may target an org not seen at connect (multi-tenant,  M1).
        self.ensure_org(org).await?;

        let mut client = self
            .pool
            .get()
            .await
            .map_err(|e| CatalogServiceError::Pool(e.to_string()))?;

        // Read the previous value before the upsert so we can
        // return it. Serialised with the upsert in one txn so
        // a concurrent writer doesn't slip in between.
        let txn = client
            .build_transaction()
            .start()
            .await
            .map_err(CatalogServiceError::Query)?;

        let prev_row = txn
            .query_opt(
                "SELECT binding_json FROM catalog_binding
                 WHERE org_id = $1 AND name = $2",
                &[&org, &name],
            )
            .await
            .map_err(CatalogServiceError::Query)?;

        txn.execute(
            "INSERT INTO catalog_binding (org_id, name, binding_json)
             VALUES ($1, $2, $3)
             ON CONFLICT (org_id, name) DO UPDATE
             SET binding_json = EXCLUDED.binding_json,
                 updated_at = now()",
            &[&org, &name, &json],
        )
        .await
        .map_err(CatalogServiceError::Query)?;

        txn.commit().await.map_err(CatalogServiceError::Query)?;

        let prev = prev_row
            .map(|r| -> Result<CatalogBinding> {
                let v: Value = r.get(0);
                serde_json::from_value(v).map_err(|source| CatalogServiceError::MalformedBinding {
                    name: name.to_string(),
                    source,
                })
            })
            .transpose()?;
        Ok(prev)
    }

    /// Delete a binding (and its `source_config`) by name. Returns
    /// `true` if a row existed, `false` if the name was already absent.
    /// The `AFTER DELETE` trigger fires a `catalog_binding_changed`
    /// NOTIFY (`kind = "deleted"`) so subscribers evict.
    ///
    /// # Errors
    /// [`CatalogServiceError::Pool`] on pool checkout failure,
    /// [`CatalogServiceError::Query`] on the DELETE.
    pub async fn delete_binding(&self, org: &str, name: &str) -> Result<bool> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| CatalogServiceError::Pool(e.to_string()))?;
        let rows = client
            .execute(
                "DELETE FROM catalog_binding WHERE org_id = $1 AND name = $2",
                &[&org, &name],
            )
            .await
            .map_err(CatalogServiceError::Query)?;
        Ok(rows > 0)
    }

    /// Store (or overwrite) a secret's already-encrypted bytes ( slice
    /// D). `ciphertext` is opaque — the server encrypts before calling here, so
    /// plaintext never reaches Postgres (rule 12).
    ///
    /// # Errors
    /// [`CatalogServiceError::Pool`] on checkout, [`CatalogServiceError::Query`]
    /// on the upsert.
    pub async fn put_secret(&self, org: &str, name: &str, ciphertext: &[u8]) -> Result<()> {
        // FK safety: `secret` references `org(org_id)`; the write may target an
        // org not seen at connect (multi-tenant,  M1).
        self.ensure_org(org).await?;
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| CatalogServiceError::Pool(e.to_string()))?;
        client
            .execute(
                "INSERT INTO secret (org_id, name, ciphertext) VALUES ($1, $2, $3)
                 ON CONFLICT (org_id, name)
                 DO UPDATE SET ciphertext = EXCLUDED.ciphertext, updated_at = now()",
                &[&org, &name, &ciphertext],
            )
            .await
            .map_err(CatalogServiceError::Query)?;
        Ok(())
    }

    /// Fetch a secret's ciphertext, or `None` if absent.
    ///
    /// # Errors
    /// [`CatalogServiceError::Pool`] on checkout, [`CatalogServiceError::Query`]
    /// on the select.
    pub async fn get_secret(&self, org: &str, name: &str) -> Result<Option<Vec<u8>>> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| CatalogServiceError::Pool(e.to_string()))?;
        let row = client
            .query_opt(
                "SELECT ciphertext FROM secret WHERE org_id = $1 AND name = $2",
                &[&org, &name],
            )
            .await
            .map_err(CatalogServiceError::Query)?;
        Ok(row.map(|r| r.get::<_, Vec<u8>>(0)))
    }

    /// Remove a secret; returns `true` if one existed.
    ///
    /// # Errors
    /// [`CatalogServiceError::Pool`] on checkout, [`CatalogServiceError::Query`]
    /// on the delete.
    pub async fn delete_secret(&self, org: &str, name: &str) -> Result<bool> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| CatalogServiceError::Pool(e.to_string()))?;
        let rows = client
            .execute(
                "DELETE FROM secret WHERE org_id = $1 AND name = $2",
                &[&org, &name],
            )
            .await
            .map_err(CatalogServiceError::Query)?;
        Ok(rows > 0)
    }

    /// List secret names (never values), sorted.
    ///
    /// # Errors
    /// [`CatalogServiceError::Pool`] on checkout, [`CatalogServiceError::Query`]
    /// on the select.
    pub async fn list_secret_names(&self, org: &str) -> Result<Vec<String>> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| CatalogServiceError::Pool(e.to_string()))?;
        let rows = client
            .query(
                "SELECT name FROM secret WHERE org_id = $1 ORDER BY name",
                &[&org],
            )
            .await
            .map_err(CatalogServiceError::Query)?;
        Ok(rows.iter().map(|r| r.get::<_, String>(0)).collect())
    }

    /// Upsert a user under `(org_id, name)`. `password_hash` is
    /// opaque — hashing happens in the caller (M3b), so plaintext never reaches
    /// Postgres (rule 12). `None` stores SQL NULL (no password).
    ///
    /// # Errors
    /// [`CatalogServiceError::Pool`] on checkout, [`CatalogServiceError::Query`]
    /// on the upsert.
    pub async fn put_user(
        &self,
        org: &str,
        name: &str,
        password_hash: Option<&str>,
        is_superuser: bool,
    ) -> Result<()> {
        // FK safety: `db_user` references `org(org_id)`; the write may target an
        // org not seen at connect (multi-tenant,  M1).
        self.ensure_org(org).await?;
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| CatalogServiceError::Pool(e.to_string()))?;
        client
            .execute(
                "INSERT INTO db_user (org_id, name, password_hash, is_superuser)
                 VALUES ($1, $2, $3, $4)
                 ON CONFLICT (org_id, name) DO UPDATE
                 SET password_hash = EXCLUDED.password_hash,
                     is_superuser = EXCLUDED.is_superuser,
                     updated_at = now()",
                &[&org, &name, &password_hash, &is_superuser],
            )
            .await
            .map_err(CatalogServiceError::Query)?;
        Ok(())
    }

    /// Fetch a user as its [`UserRecord`] plus opaque password hash, or `None`
    /// if absent. The **only** method that returns the hash (for M3b auth); it
    /// never appears in [`list_users`](Self::list_users) (rule 12).
    ///
    /// # Errors
    /// [`CatalogServiceError::Pool`] on checkout, [`CatalogServiceError::Query`]
    /// on the select.
    pub async fn get_user(
        &self,
        org: &str,
        name: &str,
    ) -> Result<Option<(UserRecord, Option<String>)>> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| CatalogServiceError::Pool(e.to_string()))?;
        let row = client
            .query_opt(
                "SELECT name, is_superuser, password_hash FROM db_user
                 WHERE org_id = $1 AND name = $2",
                &[&org, &name],
            )
            .await
            .map_err(CatalogServiceError::Query)?;
        Ok(row.map(|r| {
            let record = UserRecord {
                name: r.get(0),
                is_superuser: r.get(1),
            };
            let hash: Option<String> = r.get(2);
            (record, hash)
        }))
    }

    /// Find a user by name **across all orgs** ( F3, global-unique
    /// usernames), returning `(org, UserRecord, opaque password hash)` for the
    /// first match by `org_id`, or `None`. Like [`get_user`](Self::get_user)
    /// this exposes the hash (for the auth path); it never appears in a listing
    /// (rule 12).
    ///
    /// # Errors
    /// [`CatalogServiceError::Pool`] on checkout, [`CatalogServiceError::Query`]
    /// on the select.
    pub async fn find_user(
        &self,
        name: &str,
    ) -> Result<Option<(String, UserRecord, Option<String>)>> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| CatalogServiceError::Pool(e.to_string()))?;
        // Global-unique names mean at most one row; `ORDER BY org_id LIMIT 1`
        // makes a (defensive) collision resolve deterministically to the lowest
        // org, matching the embedded backend.
        let row = client
            .query_opt(
                "SELECT org_id, name, is_superuser, password_hash FROM db_user
                 WHERE name = $1 ORDER BY org_id LIMIT 1",
                &[&name],
            )
            .await
            .map_err(CatalogServiceError::Query)?;
        Ok(row.map(|r| {
            let org: String = r.get(0);
            let record = UserRecord {
                name: r.get(1),
                is_superuser: r.get(2),
            };
            let hash: Option<String> = r.get(3);
            (org, record, hash)
        }))
    }

    /// Remove a user; returns `true` if one existed.
    ///
    /// # Errors
    /// [`CatalogServiceError::Pool`] on checkout, [`CatalogServiceError::Query`]
    /// on the delete.
    pub async fn delete_user(&self, org: &str, name: &str) -> Result<bool> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| CatalogServiceError::Pool(e.to_string()))?;
        let rows = client
            .execute(
                "DELETE FROM db_user WHERE org_id = $1 AND name = $2",
                &[&org, &name],
            )
            .await
            .map_err(CatalogServiceError::Query)?;
        Ok(rows > 0)
    }

    /// List users (name + superuser flag), sorted by name. Never returns the
    /// password hash (rule 12).
    ///
    /// # Errors
    /// [`CatalogServiceError::Pool`] on checkout, [`CatalogServiceError::Query`]
    /// on the select.
    pub async fn list_users(&self, org: &str) -> Result<Vec<UserRecord>> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| CatalogServiceError::Pool(e.to_string()))?;
        let rows = client
            .query(
                "SELECT name, is_superuser FROM db_user WHERE org_id = $1 ORDER BY name",
                &[&org],
            )
            .await
            .map_err(CatalogServiceError::Query)?;
        Ok(rows
            .iter()
            .map(|r| UserRecord {
                name: r.get(0),
                is_superuser: r.get(1),
            })
            .collect())
    }

    /// Upsert a role under `(org_id, name)`. Idempotent — a role carries no
    /// password.
    ///
    /// # Errors
    /// [`CatalogServiceError::Pool`] on checkout, [`CatalogServiceError::Query`]
    /// on the upsert.
    pub async fn put_role(&self, org: &str, name: &str) -> Result<()> {
        // FK safety: `db_role` references `org(org_id)`.
        self.ensure_org(org).await?;
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| CatalogServiceError::Pool(e.to_string()))?;
        client
            .execute(
                "INSERT INTO db_role (org_id, name) VALUES ($1, $2)
                 ON CONFLICT (org_id, name) DO NOTHING",
                &[&org, &name],
            )
            .await
            .map_err(CatalogServiceError::Query)?;
        Ok(())
    }

    /// Remove a role; returns `true` if one existed.
    ///
    /// # Errors
    /// [`CatalogServiceError::Pool`] on checkout, [`CatalogServiceError::Query`]
    /// on the delete.
    pub async fn delete_role(&self, org: &str, name: &str) -> Result<bool> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| CatalogServiceError::Pool(e.to_string()))?;
        let rows = client
            .execute(
                "DELETE FROM db_role WHERE org_id = $1 AND name = $2",
                &[&org, &name],
            )
            .await
            .map_err(CatalogServiceError::Query)?;
        Ok(rows > 0)
    }

    /// List role names, sorted.
    ///
    /// # Errors
    /// [`CatalogServiceError::Pool`] on checkout, [`CatalogServiceError::Query`]
    /// on the select.
    pub async fn list_roles(&self, org: &str) -> Result<Vec<String>> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| CatalogServiceError::Pool(e.to_string()))?;
        let rows = client
            .query(
                "SELECT name FROM db_role WHERE org_id = $1 ORDER BY name",
                &[&org],
            )
            .await
            .map_err(CatalogServiceError::Query)?;
        Ok(rows.iter().map(|r| r.get::<_, String>(0)).collect())
    }

    /// Upsert a governance policy under `(org_id, name)`. `kind`
    /// is `"mask"` / `"row_filter"`; `rule` is the opaque serialized rule body,
    /// stored verbatim as JSONB (rule 4 — the service never interprets it).
    ///
    /// # Errors
    /// [`CatalogServiceError::Pool`] on checkout, [`CatalogServiceError::Query`]
    /// on the upsert.
    pub async fn put_policy(&self, org: &str, name: &str, kind: &str, rule: &Value) -> Result<()> {
        // FK safety: `db_policy` references `org(org_id)`.
        self.ensure_org(org).await?;
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| CatalogServiceError::Pool(e.to_string()))?;
        client
            .execute(
                "INSERT INTO db_policy (org_id, name, kind, rule)
                 VALUES ($1, $2, $3, $4)
                 ON CONFLICT (org_id, name) DO UPDATE
                 SET kind = EXCLUDED.kind, rule = EXCLUDED.rule, updated_at = now()",
                &[&org, &name, &kind, &rule],
            )
            .await
            .map_err(CatalogServiceError::Query)?;
        Ok(())
    }

    /// Fetch a policy as `(kind, serialized rule)`, or `None` if absent.
    ///
    /// # Errors
    /// [`CatalogServiceError::Pool`] on checkout, [`CatalogServiceError::Query`]
    /// on the select.
    pub async fn get_policy(&self, org: &str, name: &str) -> Result<Option<(String, Value)>> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| CatalogServiceError::Pool(e.to_string()))?;
        let row = client
            .query_opt(
                "SELECT kind, rule FROM db_policy WHERE org_id = $1 AND name = $2",
                &[&org, &name],
            )
            .await
            .map_err(CatalogServiceError::Query)?;
        Ok(row.map(|r| {
            let kind: String = r.get(0);
            let rule: Value = r.get(1);
            (kind, rule)
        }))
    }

    /// Remove a policy; returns `true` if one existed.
    ///
    /// # Errors
    /// [`CatalogServiceError::Pool`] on checkout, [`CatalogServiceError::Query`]
    /// on the delete.
    pub async fn delete_policy(&self, org: &str, name: &str) -> Result<bool> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| CatalogServiceError::Pool(e.to_string()))?;
        let rows = client
            .execute(
                "DELETE FROM db_policy WHERE org_id = $1 AND name = $2",
                &[&org, &name],
            )
            .await
            .map_err(CatalogServiceError::Query)?;
        Ok(rows > 0)
    }

    /// List policies (name + kind), sorted by name. The serialized rule body is
    /// never included — fetch it with [`get_policy`](Self::get_policy).
    ///
    /// # Errors
    /// [`CatalogServiceError::Pool`] on checkout, [`CatalogServiceError::Query`]
    /// on the select.
    pub async fn list_policies(&self, org: &str) -> Result<Vec<PolicyRecord>> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| CatalogServiceError::Pool(e.to_string()))?;
        let rows = client
            .query(
                "SELECT name, kind FROM db_policy WHERE org_id = $1 ORDER BY name",
                &[&org],
            )
            .await
            .map_err(CatalogServiceError::Query)?;
        Ok(rows
            .iter()
            .map(|r| PolicyRecord {
                name: r.get(0),
                kind: r.get(1),
            })
            .collect())
    }

    /// Every org with a persisted policy, sorted. Powers the
    /// boot-time per-org policy replay — `SELECT DISTINCT org_id` over the
    /// policy table so an org contributes exactly once regardless of how
    /// many masks / row filters it owns.
    ///
    /// # Errors
    /// [`CatalogServiceError::Pool`] on checkout, [`CatalogServiceError::Query`]
    /// on the select.
    pub async fn list_orgs(&self) -> Result<Vec<String>> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| CatalogServiceError::Pool(e.to_string()))?;
        let rows = client
            .query(
                // `org_id` is `NOT NULL` in the schema, but guard defensively:
                // a NULL row would make the `String` decode below panic. The
                // filter is a no-op today and cheap insurance against a future
                // schema change (Gemini review).
                "SELECT DISTINCT org_id FROM db_policy WHERE org_id IS NOT NULL ORDER BY org_id",
                &[],
            )
            .await
            .map_err(CatalogServiceError::Query)?;
        Ok(rows.iter().map(|r| r.get(0)).collect())
    }

    /// Upsert a grant under `org`. Idempotent — an identical grant
    /// re-put is a no-op (`ON CONFLICT DO NOTHING` on the full-tuple PK). Stores
    /// only; F5b enforces.
    ///
    /// # Errors
    /// [`CatalogServiceError::Pool`] on checkout, [`CatalogServiceError::Query`]
    /// on the upsert.
    pub async fn put_grant(&self, org: &str, grant: &GrantRecord) -> Result<()> {
        // FK safety: `db_grant` references `org(org_id)`.
        self.ensure_org(org).await?;
        let (kind, grantee, privilege, catalog, schema, table) = grant_columns(grant);
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| CatalogServiceError::Pool(e.to_string()))?;
        client
            .execute(
                "INSERT INTO db_grant
                   (org_id, grantee_kind, grantee, privilege, obj_catalog, obj_schema, obj_table)
                 VALUES ($1, $2, $3, $4, $5, $6, $7)
                 ON CONFLICT DO NOTHING",
                &[&org, &kind, &grantee, &privilege, &catalog, &schema, &table],
            )
            .await
            .map_err(CatalogServiceError::Query)?;
        Ok(())
    }

    /// Delete a grant under `org`; returns `true` if a row existed.
    ///
    /// # Errors
    /// [`CatalogServiceError::Pool`] on checkout, [`CatalogServiceError::Query`]
    /// on the delete.
    pub async fn delete_grant(&self, org: &str, grant: &GrantRecord) -> Result<bool> {
        let (kind, grantee, privilege, catalog, schema, table) = grant_columns(grant);
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| CatalogServiceError::Pool(e.to_string()))?;
        let rows = client
            .execute(
                "DELETE FROM db_grant
                 WHERE org_id = $1 AND grantee_kind = $2 AND grantee = $3 AND privilege = $4
                   AND obj_catalog = $5 AND obj_schema = $6 AND obj_table = $7",
                &[&org, &kind, &grantee, &privilege, &catalog, &schema, &table],
            )
            .await
            .map_err(CatalogServiceError::Query)?;
        Ok(rows > 0)
    }

    /// List every grant under `org`, in a deterministic order.
    ///
    /// # Errors
    /// [`CatalogServiceError::Pool`] on checkout, [`CatalogServiceError::Query`]
    /// on the select, or [`CatalogServiceError::CorruptStore`] if a row carries
    /// an unknown `grantee_kind` / `privilege` token.
    pub async fn list_grants(&self, org: &str) -> Result<Vec<GrantRecord>> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| CatalogServiceError::Pool(e.to_string()))?;
        let rows = client
            .query(
                "SELECT grantee_kind, grantee, privilege, obj_catalog, obj_schema, obj_table
                 FROM db_grant WHERE org_id = $1
                 ORDER BY grantee_kind, grantee, privilege, obj_catalog, obj_schema, obj_table",
                &[&org],
            )
            .await
            .map_err(CatalogServiceError::Query)?;
        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let kind: String = row.get(0);
            let grantee: String = row.get(1);
            let privilege: String = row.get(2);
            let catalog: String = row.get(3);
            let schema: String = row.get(4);
            let table: String = row.get(5);
            out.push(grant_from_columns(
                &kind, grantee, &privilege, catalog, schema, table,
            )?);
        }
        Ok(out)
    }

    /// Upsert a derived product under `org`. Idempotent by name —
    /// used for both `CREATE VIEW` and `CREATE OR REPLACE VIEW`. Stored on the
    /// existing `data_product` table with `data_product_id = name`; the verbatim
    /// `sql` and optional `catalog`/`schema` land in the F9 columns.
    ///
    /// # Errors
    /// [`CatalogServiceError::Pool`] on checkout, [`CatalogServiceError::Query`]
    /// on the upsert.
    pub async fn put_derived_product(
        &self,
        org: &str,
        product: &DerivedProductRecord,
    ) -> Result<()> {
        // FK safety: `data_product` references `org(org_id)`.
        self.ensure_org(org).await?;
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| CatalogServiceError::Pool(e.to_string()))?;
        client
            .execute(
                "INSERT INTO data_product (org_id, data_product_id, name, sql, catalog, schema)
                 VALUES ($1, $2, $2, $3, $4, $5)
                 ON CONFLICT (org_id, data_product_id) DO UPDATE
                 SET name = EXCLUDED.name, sql = EXCLUDED.sql,
                     catalog = EXCLUDED.catalog, schema = EXCLUDED.schema",
                &[
                    &org,
                    &product.name,
                    &product.sql,
                    &product.catalog,
                    &product.schema,
                ],
            )
            .await
            .map_err(CatalogServiceError::Query)?;
        Ok(())
    }

    /// Fetch a derived product under `org` by name, or `None` if absent (
    /// F9). Only rows carrying a `sql` body (F9-created views) are returned.
    ///
    /// # Errors
    /// [`CatalogServiceError::Pool`] on checkout, [`CatalogServiceError::Query`]
    /// on the select.
    pub async fn get_derived_product(
        &self,
        org: &str,
        name: &str,
    ) -> Result<Option<DerivedProductRecord>> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| CatalogServiceError::Pool(e.to_string()))?;
        let row = client
            .query_opt(
                "SELECT sql, catalog, schema FROM data_product
                 WHERE org_id = $1 AND data_product_id = $2 AND sql IS NOT NULL",
                &[&org, &name],
            )
            .await
            .map_err(CatalogServiceError::Query)?;
        Ok(row.map(|r| DerivedProductRecord {
            name: name.to_string(),
            sql: r.get(0),
            catalog: r.get(1),
            schema: r.get(2),
        }))
    }

    /// List every derived product under `org`, sorted by name. Only
    /// rows carrying a `sql` body (F9-created views) are returned.
    ///
    /// # Errors
    /// [`CatalogServiceError::Pool`] on checkout, [`CatalogServiceError::Query`]
    /// on the select.
    pub async fn list_derived_products(&self, org: &str) -> Result<Vec<DerivedProductRecord>> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| CatalogServiceError::Pool(e.to_string()))?;
        let rows = client
            .query(
                "SELECT data_product_id, sql, catalog, schema FROM data_product
                 WHERE org_id = $1 AND sql IS NOT NULL ORDER BY data_product_id",
                &[&org],
            )
            .await
            .map_err(CatalogServiceError::Query)?;
        Ok(rows
            .iter()
            .map(|r| DerivedProductRecord {
                name: r.get(0),
                sql: r.get(1),
                catalog: r.get(2),
                schema: r.get(3),
            })
            .collect())
    }

    /// Remove a derived product under `org`; returns `true` if one existed
    ///
    /// # Errors
    /// [`CatalogServiceError::Pool`] on checkout, [`CatalogServiceError::Query`]
    /// on the delete.
    pub async fn delete_derived_product(&self, org: &str, name: &str) -> Result<bool> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| CatalogServiceError::Pool(e.to_string()))?;
        let rows = client
            .execute(
                "DELETE FROM data_product
                 WHERE org_id = $1 AND data_product_id = $2 AND sql IS NOT NULL",
                &[&org, &name],
            )
            .await
            .map_err(CatalogServiceError::Query)?;
        Ok(rows > 0)
    }

    /// Add a `role → user` membership under `org`. Idempotent
    /// (`ON CONFLICT DO NOTHING`).
    ///
    /// # Errors
    /// [`CatalogServiceError::Pool`] on checkout, [`CatalogServiceError::Query`]
    /// on the upsert.
    pub async fn add_role_member(&self, org: &str, role: &str, user: &str) -> Result<()> {
        // FK safety: `db_role_member` references `org(org_id)`.
        self.ensure_org(org).await?;
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| CatalogServiceError::Pool(e.to_string()))?;
        client
            .execute(
                "INSERT INTO db_role_member (org_id, role, member) VALUES ($1, $2, $3)
                 ON CONFLICT DO NOTHING",
                &[&org, &role, &user],
            )
            .await
            .map_err(CatalogServiceError::Query)?;
        Ok(())
    }

    /// Remove a `role → user` membership under `org`; returns `true` if one
    /// existed.
    ///
    /// # Errors
    /// [`CatalogServiceError::Pool`] on checkout, [`CatalogServiceError::Query`]
    /// on the delete.
    pub async fn remove_role_member(&self, org: &str, role: &str, user: &str) -> Result<bool> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| CatalogServiceError::Pool(e.to_string()))?;
        let rows = client
            .execute(
                "DELETE FROM db_role_member WHERE org_id = $1 AND role = $2 AND member = $3",
                &[&org, &role, &user],
            )
            .await
            .map_err(CatalogServiceError::Query)?;
        Ok(rows > 0)
    }

    /// List the roles a `user` is a member of under `org`, sorted.
    ///
    /// # Errors
    /// [`CatalogServiceError::Pool`] on checkout, [`CatalogServiceError::Query`]
    /// on the select.
    pub async fn list_roles_for_user(&self, org: &str, user: &str) -> Result<Vec<String>> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| CatalogServiceError::Pool(e.to_string()))?;
        let rows = client
            .query(
                "SELECT role FROM db_role_member WHERE org_id = $1 AND member = $2 ORDER BY role",
                &[&org, &user],
            )
            .await
            .map_err(CatalogServiceError::Query)?;
        Ok(rows.iter().map(|r| r.get::<_, String>(0)).collect())
    }

    /// List the users that are members of a `role` under `org`, sorted.
    ///
    /// # Errors
    /// [`CatalogServiceError::Pool`] on checkout, [`CatalogServiceError::Query`]
    /// on the select.
    pub async fn list_role_members(&self, org: &str, role: &str) -> Result<Vec<String>> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| CatalogServiceError::Pool(e.to_string()))?;
        let rows = client
            .query(
                "SELECT member FROM db_role_member WHERE org_id = $1 AND role = $2 ORDER BY member",
                &[&org, &role],
            )
            .await
            .map_err(CatalogServiceError::Query)?;
        Ok(rows.iter().map(|r| r.get::<_, String>(0)).collect())
    }

    /// Subscribe to LISTEN/NOTIFY events on the
    /// `catalog_binding_changed` channel. Returns an async
    /// [`BindingChangeStream`] the Phase 1 task 09 cache
    /// consumes for invalidation routing.
    ///
    /// Implementation notes:
    /// - A dedicated `tokio_postgres::connect` happens here,
    ///   not a pool checkout — LISTEN ties up the connection
    ///   for its lifetime, so it can't share with the pool's
    ///   short-lived workers.
    /// - The connection driver is spawned onto tokio. The
    ///   stream owns the `Client`; dropping the stream
    ///   closes the connection and the pump task exits.
    /// - Notification payloads that can't be parsed are
    ///   logged at WARN and dropped. A malformed payload
    ///   would indicate either an external writer producing
    ///   garbage or a schema regression; either way, dropping
    ///   is better than poisoning the stream.
    ///
    /// # Errors
    /// Returns [`CatalogServiceError::Connect`] on TCP / TLS /
    /// startup failure, [`CatalogServiceError::Query`] if the
    /// `LISTEN` statement fails.
    pub async fn subscribe(&self) -> Result<BindingChangeStream> {
        let (client, mut connection) = tokio_postgres::connect(&self.dsn, NoTls)
            .await
            .map_err(CatalogServiceError::Connect)?;

        let (tx, rx) = mpsc::unbounded_channel::<BindingChange>();

        // Pump task: drive the connection's async-message
        // stream and forward notifications into the channel.
        // tokio-postgres requires the consumer to poll the
        // connection to keep the protocol moving; without
        // this spawn, no messages flow and `LISTEN` itself
        // would deadlock.
        tokio::spawn(async move {
            loop {
                let msg = poll_fn(|cx| connection.poll_message(cx)).await;
                match msg {
                    Some(Ok(AsyncMessage::Notification(notification))) => {
                        match serde_json::from_str::<BindingChange>(notification.payload()) {
                            Ok(change) => {
                                if tx.send(change).is_err() {
                                    // Consumer dropped the stream; exit.
                                    break;
                                }
                            }
                            Err(err) => {
                                tracing::warn!(
                                    payload = %notification.payload(),
                                    error = %err,
                                    "catalog: malformed BindingChange payload; dropping"
                                );
                            }
                        }
                    }
                    Some(Ok(_)) => {
                        // Other async messages (notices, etc.)
                        // are not the catalog cache's concern.
                    }
                    Some(Err(err)) => {
                        tracing::warn!(error = %err, "catalog: subscribe connection error");
                        break;
                    }
                    None => {
                        tracing::debug!("catalog: subscribe connection closed");
                        break;
                    }
                }
            }
        });

        // Issue LISTEN on the same connection. The pump task
        // above is what makes this work — without it, this
        // batch_execute would deadlock waiting for the protocol
        // to advance.
        client
            .batch_execute("LISTEN catalog_binding_changed")
            .await
            .map_err(CatalogServiceError::Query)?;

        // Hand the client to the stream — its drop closes the
        // connection and the pump exits.
        Ok(BindingChangeStream::from_pg(rx, client))
    }
}

/// [`CatalogService`] is the Postgres-backed [`MetaStore`] — the HA /
/// multi-node backend.
///
/// Each method delegates to the inherent method of the same name above.
/// Inherent methods take resolution priority over trait methods, so
/// `self.list_bindings()` here calls the concrete Postgres impl, **not**
/// this trait method recursively.
#[async_trait]
impl MetaStore for CatalogService {
    async fn list_source_configs(&self, org: &str) -> Result<HashMap<String, Value>> {
        self.list_source_configs(org).await
    }

    async fn list_bindings(&self, org: &str) -> Result<HashMap<String, CatalogBinding>> {
        self.list_bindings(org).await
    }

    async fn upsert_binding(
        &self,
        org: &str,
        name: &str,
        binding: &CatalogBinding,
    ) -> Result<Option<CatalogBinding>> {
        self.upsert_binding(org, name, binding).await
    }

    async fn set_source_config(&self, org: &str, name: &str, source_config: &Value) -> Result<()> {
        self.set_source_config(org, name, source_config).await
    }

    async fn delete_binding(&self, org: &str, name: &str) -> Result<bool> {
        self.delete_binding(org, name).await
    }

    async fn put_secret(&self, org: &str, name: &str, ciphertext: &[u8]) -> Result<()> {
        self.put_secret(org, name, ciphertext).await
    }

    async fn get_secret(&self, org: &str, name: &str) -> Result<Option<Vec<u8>>> {
        self.get_secret(org, name).await
    }

    async fn delete_secret(&self, org: &str, name: &str) -> Result<bool> {
        self.delete_secret(org, name).await
    }

    async fn list_secret_names(&self, org: &str) -> Result<Vec<String>> {
        self.list_secret_names(org).await
    }

    async fn put_user(
        &self,
        org: &str,
        name: &str,
        password_hash: Option<&str>,
        is_superuser: bool,
    ) -> Result<()> {
        self.put_user(org, name, password_hash, is_superuser).await
    }

    async fn get_user(
        &self,
        org: &str,
        name: &str,
    ) -> Result<Option<(UserRecord, Option<String>)>> {
        self.get_user(org, name).await
    }

    async fn find_user(&self, name: &str) -> Result<Option<(String, UserRecord, Option<String>)>> {
        self.find_user(name).await
    }

    async fn delete_user(&self, org: &str, name: &str) -> Result<bool> {
        self.delete_user(org, name).await
    }

    async fn list_users(&self, org: &str) -> Result<Vec<UserRecord>> {
        self.list_users(org).await
    }

    async fn put_role(&self, org: &str, name: &str) -> Result<()> {
        self.put_role(org, name).await
    }

    async fn delete_role(&self, org: &str, name: &str) -> Result<bool> {
        self.delete_role(org, name).await
    }

    async fn list_roles(&self, org: &str) -> Result<Vec<String>> {
        self.list_roles(org).await
    }

    async fn put_policy(&self, org: &str, name: &str, kind: &str, rule: &Value) -> Result<()> {
        self.put_policy(org, name, kind, rule).await
    }

    async fn get_policy(&self, org: &str, name: &str) -> Result<Option<(String, Value)>> {
        self.get_policy(org, name).await
    }

    async fn delete_policy(&self, org: &str, name: &str) -> Result<bool> {
        self.delete_policy(org, name).await
    }

    async fn list_policies(&self, org: &str) -> Result<Vec<PolicyRecord>> {
        self.list_policies(org).await
    }

    async fn put_grant(&self, org: &str, grant: &GrantRecord) -> Result<()> {
        self.put_grant(org, grant).await
    }

    async fn delete_grant(&self, org: &str, grant: &GrantRecord) -> Result<bool> {
        self.delete_grant(org, grant).await
    }

    async fn list_grants(&self, org: &str) -> Result<Vec<GrantRecord>> {
        self.list_grants(org).await
    }

    async fn put_derived_product(&self, org: &str, product: &DerivedProductRecord) -> Result<()> {
        self.put_derived_product(org, product).await
    }

    async fn get_derived_product(
        &self,
        org: &str,
        name: &str,
    ) -> Result<Option<DerivedProductRecord>> {
        self.get_derived_product(org, name).await
    }

    async fn list_derived_products(&self, org: &str) -> Result<Vec<DerivedProductRecord>> {
        self.list_derived_products(org).await
    }

    async fn delete_derived_product(&self, org: &str, name: &str) -> Result<bool> {
        self.delete_derived_product(org, name).await
    }

    async fn add_role_member(&self, org: &str, role: &str, user: &str) -> Result<()> {
        self.add_role_member(org, role, user).await
    }

    async fn remove_role_member(&self, org: &str, role: &str, user: &str) -> Result<bool> {
        self.remove_role_member(org, role, user).await
    }

    async fn list_roles_for_user(&self, org: &str, user: &str) -> Result<Vec<String>> {
        self.list_roles_for_user(org, user).await
    }

    async fn list_role_members(&self, org: &str, role: &str) -> Result<Vec<String>> {
        self.list_role_members(org, role).await
    }

    async fn list_orgs(&self) -> Result<Vec<String>> {
        self.list_orgs().await
    }

    async fn subscribe(&self) -> Result<BindingChangeStream> {
        self.subscribe().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // `grant_columns` / `grant_from_columns` are the postgres-backend
    // serialization mirror of the store's `GrantRecord` (store.rs covers the
    // in-memory shape). They're the only DB-free logic in this module — every
    // `CatalogService` method runs SQL against a live pool — so pin the
    // round-trip and the malformed-token errors here ( F5a / ).

    #[test]
    fn grant_columns_round_trips_a_select_grant() {
        let grant = GrantRecord::select(
            GranteeKind::User,
            "alice".to_string(),
            "analytics".to_string(),
            "public".to_string(),
            "orders".to_string(),
        );
        let (kind, grantee, privilege, catalog, schema, table) = grant_columns(&grant);
        assert_eq!(kind, "user");
        assert_eq!(privilege, "SELECT");
        assert_eq!(
            (catalog.as_str(), schema.as_str(), table.as_str()),
            ("analytics", "public", "orders")
        );

        let rebuilt = grant_from_columns(kind, grantee, privilege, catalog, schema, table).unwrap();
        assert_eq!(rebuilt, grant);
    }

    #[test]
    fn grant_columns_round_trips_a_usage_grant_with_empty_schema_and_table() {
        // A USAGE grant is catalog-scoped: schema/table columns are empty and
        // must stay empty through the round-trip (they're ignored on rebuild).
        let grant = GrantRecord::usage(
            GranteeKind::Role,
            "readers".to_string(),
            "analytics".to_string(),
        );
        let (kind, grantee, privilege, catalog, schema, table) = grant_columns(&grant);
        assert_eq!(kind, "role");
        assert_eq!(privilege, "USAGE");
        assert!(
            schema.is_empty() && table.is_empty(),
            "USAGE leaves schema/table empty"
        );

        let rebuilt = grant_from_columns(kind, grantee, privilege, catalog, schema, table).unwrap();
        assert_eq!(rebuilt, grant);
    }

    #[test]
    fn grant_from_columns_rejects_unknown_kind_and_privilege() {
        // Both malformed-token paths surface as MalformedGrant rather than
        // silently coercing — a corrupt db_grant row fails loud.
        let bad_kind = grant_from_columns(
            "group",
            "x".to_string(),
            "SELECT",
            "c".to_string(),
            "s".to_string(),
            "t".to_string(),
        );
        assert!(matches!(
            bad_kind,
            Err(CatalogServiceError::MalformedGrant(_))
        ));

        let bad_priv = grant_from_columns(
            "user",
            "x".to_string(),
            "DELETE",
            "c".to_string(),
            "s".to_string(),
            "t".to_string(),
        );
        assert!(matches!(
            bad_priv,
            Err(CatalogServiceError::MalformedGrant(_))
        ));
    }
}

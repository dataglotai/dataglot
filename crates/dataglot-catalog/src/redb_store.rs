//! [`RedbMetaStore`] — the single-file, pure-Rust embedded meta store
//! ( slice A / ).
//!
//! Backs the control plane's durable state — catalogs, secrets, users, roles,
//! grants, policies, and derived products — on [`redb`], a pure-Rust
//! (hard rule 15 clean) ACID/MVCC embedded KV store. It is the production
//! embedded backend; the whole-file JSON [`crate::EmbeddedMetaStore`] it
//! replaces stays only as a fast in-test [`MetaStore`] double.
//!
//! # Why redb over a whole-file rewrite
//!
//! The JSON store re-serialized the entire document on every mutation — no
//! transactions, single-writer, O(document) per change. redb gives per-key
//! B-tree writes, MVCC snapshots for readers, and crash-atomic commits, in one
//! file. It is the rule-15-compatible analogue of the **SQLite** backend
//! RisingWave uses for its local meta store (SQLite is a C library — excluded
//! here); Postgres [`crate::CatalogService`] remains the HA backend.
//!
//! # Layout
//!
//! One table per object kind, keyed by `(org, name)` (a 3-tuple for role
//! membership). Values are `serde_json` bytes, except `secrets` which stores
//! raw ciphertext. See `docs/meta-store.md`.
//!
//! # Security (rule 12)
//!
//! The store persists only **ciphertext** for secrets (encryption stays in
//! `dataglot-server`'s `SecretCipher`) and **opaque password hashes** for
//! users — never plaintext. The DB file is created `0600` on Unix. [`Debug`]
//! is value-free (path + org only). redb error text is structural, never a
//! stored value.
//!
//! # Async
//!
//! redb is synchronous + memory-mapped; every operation runs under
//! [`tokio::task::spawn_blocking`] so it never blocks the async runtime
//! (rule 11). The `Database` is shared as an `Arc` across those tasks.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock, Weak};

use dataglot_core::CatalogBinding;
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use serde::{de::DeserializeOwned, Serialize};
use serde_json::Value;
use tokio::sync::broadcast;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;

use crate::error::{CatalogServiceError, Result};
use crate::store::{DerivedProductRecord, GrantRecord, MetaStore, PolicyRecord, UserRecord};
use crate::subscribe::{BindingChange, BindingChangeKind, BindingChangeStream};

/// On-disk schema version this build writes/reads. Bump only on a
/// backward-incompatible table-layout change (add a migration first).
const SCHEMA_VERSION: &str = "v1";

/// Broadcast capacity for the binding-change feed. Matches the JSON store; a
/// slow subscriber that lags past this sees a `Lagged` skip, never blocks a
/// writer.
const CHANGE_CHANNEL_CAPACITY: usize = 256;

// One table per object kind. `(org, name)` composite keys keep every object
// org-scoped; values are serde_json bytes unless noted.
//
// `entries`: catalog binding + optional source_config (a `StoredEntry`).
const ENTRIES: TableDefinition<(&str, &str), &[u8]> = TableDefinition::new("entries");
// `secrets`: raw ciphertext (NOT json) — the store never sees plaintext.
const SECRETS: TableDefinition<(&str, &str), &[u8]> = TableDefinition::new("secrets");
// `users`: `(Option<opaque hash>, is_superuser)` as json.
const USERS: TableDefinition<(&str, &str), &[u8]> = TableDefinition::new("users");
// `roles`: presence set (value is an unused marker byte).
const ROLES: TableDefinition<(&str, &str), u8> = TableDefinition::new("roles");
// `role_members`: `(org, role, user)` presence set.
const ROLE_MEMBERS: TableDefinition<(&str, &str, &str), u8> = TableDefinition::new("role_members");
// `policies`: `(kind, rule)` as json.
const POLICIES: TableDefinition<(&str, &str), &[u8]> = TableDefinition::new("policies");
// `grants`: keyed by (org, canonical serialized GrantRecord); value is that json.
const GRANTS: TableDefinition<(&str, &str), &[u8]> = TableDefinition::new("grants");
// `derived_products`: DerivedProductRecord as json.
const PRODUCTS: TableDefinition<(&str, &str), &[u8]> = TableDefinition::new("derived_products");
// `meta`: singleton keys (`schema_version`).
const META: TableDefinition<&str, &str> = TableDefinition::new("meta");

/// Serialized catalog entry — mirrors the JSON store's `Entry`: the binding
/// plus any `source_config` attached to the same catalog name.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
struct StoredEntry {
    binding: CatalogBinding,
    #[serde(default)]
    source_config: Option<Value>,
}

/// The shared, per-file open handle: redb keeps an **exclusive OS lock** on the
/// database file, so a given path can be opened only once per process. The old
/// whole-file JSON store took no lock, and the server's boot path opens the
/// meta store several times (bindings-map build, provider cache, session set).
/// To stay a drop-in, we key one `Inner` per path in a process-global registry
/// and hand every `open()` of that path a clone of the same handle — one lock,
/// one change feed, shared.
struct Inner {
    db: Arc<Database>,
    /// In-process binding-change feed (parity with the Postgres LISTEN/NOTIFY
    /// stream and the JSON store's broadcast).
    tx: broadcast::Sender<BindingChange>,
}

/// Single-file embedded [`MetaStore`] on redb.
pub struct RedbMetaStore {
    inner: Arc<Inner>,
    /// Backing-file path — for `Debug`, the registry key, and error context.
    path: PathBuf,
}

/// Process-global path → open-handle registry (see [`Inner`]). `Weak` so a
/// handle is evicted once its last `RedbMetaStore` drops and redb releases the
/// file lock, letting a later `open()` of the same path start fresh.
fn open_registry() -> &'static Mutex<HashMap<PathBuf, Weak<Inner>>> {
    static REG: OnceLock<Mutex<HashMap<PathBuf, Weak<Inner>>>> = OnceLock::new();
    REG.get_or_init(|| Mutex::new(HashMap::new()))
}

impl std::fmt::Debug for RedbMetaStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Value-free (rule 12): never render stored records.
        f.debug_struct("RedbMetaStore")
            .field("path", &self.path)
            .field("subscribers", &self.inner.tx.receiver_count())
            .finish_non_exhaustive()
    }
}

impl RedbMetaStore {
    /// Open (or create) the embedded meta store at `path`. `org_id` is the
    /// default org scope (kept for signature parity with the JSON store; every
    /// method takes its own `org`).
    ///
    /// Creates every table up front so reads never hit a missing table, checks
    /// the schema version, and tightens the file to `0600` on Unix.
    ///
    /// # Errors
    /// - [`CatalogServiceError::Redb`] if the database can't be opened/created
    ///   or a bootstrap transaction fails.
    /// - [`CatalogServiceError::SchemaVersionMismatch`] if the file was written
    ///   by an incompatible build.
    ///
    /// # Panics
    /// If the process-global open-handle registry mutex is poisoned — i.e. a
    /// prior `open()` panicked while holding it, which never happens in normal
    /// operation.
    pub async fn open(path: impl Into<PathBuf>, _org_id: impl Into<String>) -> Result<Self> {
        let path = path.into();

        // redb holds an exclusive OS lock on the file, so a path can be opened
        // once per process. Reuse a live handle if one exists (the boot path
        // opens the meta store several times) — one lock, one change feed.
        if let Some(inner) = open_registry()
            .lock()
            .expect("meta-store registry mutex poisoned")
            .get(&path)
            .and_then(Weak::upgrade)
        {
            return Ok(Self { inner, path });
        }

        let db_path = path.clone();
        let db = tokio::task::spawn_blocking(move || -> Result<Database> {
            let db = Database::create(&db_path).map_err(rerr)?;
            // Create all tables + version-stamp in one write txn.
            let wtx = db.begin_write().map_err(rerr)?;
            {
                let _ = wtx.open_table(ENTRIES).map_err(rerr)?;
                let _ = wtx.open_table(SECRETS).map_err(rerr)?;
                let _ = wtx.open_table(USERS).map_err(rerr)?;
                let _ = wtx.open_table(ROLES).map_err(rerr)?;
                let _ = wtx.open_table(ROLE_MEMBERS).map_err(rerr)?;
                let _ = wtx.open_table(POLICIES).map_err(rerr)?;
                let _ = wtx.open_table(GRANTS).map_err(rerr)?;
                let _ = wtx.open_table(PRODUCTS).map_err(rerr)?;
                let mut meta = wtx.open_table(META).map_err(rerr)?;
                // Read into an owned value so the access guard drops before the
                // (possible) mutable insert below.
                let found: Option<String> = meta
                    .get("schema_version")
                    .map_err(rerr)?
                    .map(|v| v.value().to_string());
                match found {
                    Some(found) if found != SCHEMA_VERSION => {
                        return Err(CatalogServiceError::SchemaVersionMismatch {
                            expected: SCHEMA_VERSION.to_string(),
                            found,
                        });
                    }
                    Some(_) => {}
                    None => {
                        meta.insert("schema_version", SCHEMA_VERSION)
                            .map_err(rerr)?;
                    }
                }
            }
            wtx.commit().map_err(rerr)?;
            Ok(db)
        })
        .await
        .map_err(jerr)??;

        // Secrets + password hashes live here — restrict to the owner (0600).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(meta) = std::fs::metadata(&path) {
                let mut perms = meta.permissions();
                perms.set_mode(0o600);
                let _ = std::fs::set_permissions(&path, perms);
            }
        }

        let (tx, _rx) = broadcast::channel(CHANGE_CHANNEL_CAPACITY);
        let inner = Arc::new(Inner {
            db: Arc::new(db),
            tx,
        });

        // Publish the live handle so concurrent/later opens of this same path
        // share it (a raced open that already created its own handle simply wins
        // — either handle is correct, both wrap the one locked file).
        open_registry()
            .lock()
            .expect("meta-store registry mutex poisoned")
            .insert(path.clone(), Arc::downgrade(&inner));

        Ok(Self { inner, path })
    }

    /// Clone the shared database handle for a `spawn_blocking` op.
    fn db(&self) -> Arc<Database> {
        Arc::clone(&self.inner.db)
    }

    /// Emit a binding change to the in-process feed (best-effort; no
    /// subscribers ⇒ dropped).
    fn emit(&self, org: &str, name: &str, kind: BindingChangeKind) {
        let _ = self.inner.tx.send(BindingChange {
            org_id: org.to_string(),
            name: name.to_string(),
            kind,
        });
    }

    // ── generic (org, name) → bytes helpers ───────────────────────────────
    // Each runs one redb transaction under spawn_blocking.

    async fn put_bytes(
        &self,
        table: TableDefinition<'static, (&'static str, &'static str), &'static [u8]>,
        org: &str,
        name: &str,
        val: Vec<u8>,
    ) -> Result<()> {
        let (db, org, name) = (self.db(), org.to_string(), name.to_string());
        tokio::task::spawn_blocking(move || -> Result<()> {
            let wtx = db.begin_write().map_err(rerr)?;
            {
                let mut t = wtx.open_table(table).map_err(rerr)?;
                t.insert((org.as_str(), name.as_str()), val.as_slice())
                    .map_err(rerr)?;
            }
            wtx.commit().map_err(rerr)
        })
        .await
        .map_err(jerr)?
    }

    async fn get_bytes(
        &self,
        table: TableDefinition<'static, (&'static str, &'static str), &'static [u8]>,
        org: &str,
        name: &str,
    ) -> Result<Option<Vec<u8>>> {
        let (db, org, name) = (self.db(), org.to_string(), name.to_string());
        tokio::task::spawn_blocking(move || -> Result<Option<Vec<u8>>> {
            let rtx = db.begin_read().map_err(rerr)?;
            let t = rtx.open_table(table).map_err(rerr)?;
            Ok(t.get((org.as_str(), name.as_str()))
                .map_err(rerr)?
                .map(|v| v.value().to_vec()))
        })
        .await
        .map_err(jerr)?
    }

    async fn remove_key(
        &self,
        table: TableDefinition<'static, (&'static str, &'static str), &'static [u8]>,
        org: &str,
        name: &str,
    ) -> Result<bool> {
        let (db, org, name) = (self.db(), org.to_string(), name.to_string());
        tokio::task::spawn_blocking(move || -> Result<bool> {
            let wtx = db.begin_write().map_err(rerr)?;
            let existed = {
                let mut t = wtx.open_table(table).map_err(rerr)?;
                let existed = t
                    .remove((org.as_str(), name.as_str()))
                    .map_err(rerr)?
                    .is_some();
                existed
            };
            wtx.commit().map_err(rerr)?;
            Ok(existed)
        })
        .await
        .map_err(jerr)?
    }

    /// All `(name, value_bytes)` pairs for `org`, sorted by name (redb iterates
    /// keys in order). Control-plane object sets are small, so a filtered scan
    /// is fine.
    async fn list_org(
        &self,
        table: TableDefinition<'static, (&'static str, &'static str), &'static [u8]>,
        org: &str,
    ) -> Result<Vec<(String, Vec<u8>)>> {
        let (db, org) = (self.db(), org.to_string());
        tokio::task::spawn_blocking(move || -> Result<Vec<(String, Vec<u8>)>> {
            let rtx = db.begin_read().map_err(rerr)?;
            let t = rtx.open_table(table).map_err(rerr)?;
            let mut out = Vec::new();
            for item in t.iter().map_err(rerr)? {
                let (k, v) = item.map_err(rerr)?;
                let (k_org, k_name) = k.value();
                if k_org == org {
                    out.push((k_name.to_string(), v.value().to_vec()));
                }
            }
            Ok(out)
        })
        .await
        .map_err(jerr)?
    }
}

/// Map any redb error to the typed [`CatalogServiceError::Redb`] (structural
/// message only — never a stored value, rule 12).
fn rerr<E: std::fmt::Display>(e: E) -> CatalogServiceError {
    CatalogServiceError::Redb(e.to_string())
}

/// Map a `spawn_blocking` join failure. By value to match `.map_err(jerr)` at
/// the call sites (the `JoinError` is owned there).
#[allow(clippy::needless_pass_by_value)]
fn jerr(e: tokio::task::JoinError) -> CatalogServiceError {
    CatalogServiceError::Join(e.to_string())
}

/// Serialize a record to json bytes for storage.
fn ser<T: Serialize>(v: &T) -> Result<Vec<u8>> {
    serde_json::to_vec(v).map_err(CatalogServiceError::StoreSerialization)
}

/// Deserialize a stored json value; a failure means a corrupt / externally
/// edited store.
fn de<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    serde_json::from_slice(bytes)
        .map_err(|e| CatalogServiceError::Redb(format!("corrupt stored value: {e}")))
}

#[async_trait::async_trait]
impl MetaStore for RedbMetaStore {
    async fn list_source_configs(
        &self,
        org: &str,
    ) -> Result<std::collections::HashMap<String, Value>> {
        let mut out = std::collections::HashMap::new();
        for (name, bytes) in self.list_org(ENTRIES, org).await? {
            let entry: StoredEntry = de(&bytes)?;
            if let Some(cfg) = entry.source_config {
                out.insert(name, cfg);
            }
        }
        Ok(out)
    }

    async fn list_bindings(
        &self,
        org: &str,
    ) -> Result<std::collections::HashMap<String, CatalogBinding>> {
        let mut out = std::collections::HashMap::new();
        for (name, bytes) in self.list_org(ENTRIES, org).await? {
            let entry: StoredEntry = de(&bytes)?;
            out.insert(name, entry.binding);
        }
        Ok(out)
    }

    async fn upsert_binding(
        &self,
        org: &str,
        name: &str,
        binding: &CatalogBinding,
    ) -> Result<Option<CatalogBinding>> {
        // Preserve any existing source_config; only the binding moves.
        let prev = self.get_bytes(ENTRIES, org, name).await?;
        let (previous_binding, source_config) = match &prev {
            Some(bytes) => {
                let e: StoredEntry = de(bytes)?;
                (Some(e.binding), e.source_config)
            }
            None => (None, None),
        };
        let entry = StoredEntry {
            binding: binding.clone(),
            source_config,
        };
        self.put_bytes(ENTRIES, org, name, ser(&entry)?).await?;
        self.emit(org, name, BindingChangeKind::Upserted);
        Ok(previous_binding)
    }

    async fn set_source_config(&self, org: &str, name: &str, source_config: &Value) -> Result<()> {
        // Merge onto the existing binding. A source_config with no binding is a
        // no-op returning Ok — the Postgres `UPDATE … WHERE` touches 0 rows and
        // the JSON store no-ops too; matching keeps every backend's contract
        // identical (an unknown catalog is silently ignored, not an error).
        let existing = self.get_bytes(ENTRIES, org, name).await?;
        let Some(bytes) = existing else {
            return Ok(());
        };
        let mut entry: StoredEntry = de(&bytes)?;
        entry.source_config = Some(source_config.clone());
        self.put_bytes(ENTRIES, org, name, ser(&entry)?).await?;
        // Emit like the JSON store: `CREATE CATALOG` persists the binding
        // (`upsert_binding`) then the source_config in two steps, and the live
        // registry-refresh rebuilds from `list_source_configs` — so a session
        // only sees the fully-configured catalog if this second write also
        // fires a change (without it the refresh rebuilds before the config
        // lands and never re-runs).
        self.emit(org, name, BindingChangeKind::Upserted);
        Ok(())
    }

    async fn delete_binding(&self, org: &str, name: &str) -> Result<bool> {
        let removed = self.remove_key(ENTRIES, org, name).await?;
        if removed {
            self.emit(org, name, BindingChangeKind::Deleted);
        }
        Ok(removed)
    }

    async fn put_secret(&self, org: &str, name: &str, ciphertext: &[u8]) -> Result<()> {
        // Raw ciphertext — never serialized/inspected here.
        self.put_bytes(SECRETS, org, name, ciphertext.to_vec())
            .await
    }

    async fn get_secret(&self, org: &str, name: &str) -> Result<Option<Vec<u8>>> {
        self.get_bytes(SECRETS, org, name).await
    }

    async fn delete_secret(&self, org: &str, name: &str) -> Result<bool> {
        self.remove_key(SECRETS, org, name).await
    }

    async fn list_secret_names(&self, org: &str) -> Result<Vec<String>> {
        Ok(self
            .list_org(SECRETS, org)
            .await?
            .into_iter()
            .map(|(name, _)| name)
            .collect())
    }

    async fn put_user(
        &self,
        org: &str,
        name: &str,
        password_hash: Option<&str>,
        is_superuser: bool,
    ) -> Result<()> {
        let val: (Option<String>, bool) = (password_hash.map(str::to_string), is_superuser);
        self.put_bytes(USERS, org, name, ser(&val)?).await
    }

    async fn get_user(
        &self,
        org: &str,
        name: &str,
    ) -> Result<Option<(UserRecord, Option<String>)>> {
        Ok(match self.get_bytes(USERS, org, name).await? {
            Some(bytes) => {
                let (hash, is_superuser): (Option<String>, bool) = de(&bytes)?;
                Some((
                    UserRecord {
                        name: name.to_string(),
                        is_superuser,
                    },
                    hash,
                ))
            }
            None => None,
        })
    }

    async fn find_user(&self, name: &str) -> Result<Option<(String, UserRecord, Option<String>)>> {
        // Scan every org's users table for `name`. Orgs are few; users per org
        // small — acceptable for the auth lookup path.
        let db = self.db();
        let want = name.to_string();
        tokio::task::spawn_blocking(
            move || -> Result<Option<(String, UserRecord, Option<String>)>> {
                let rtx = db.begin_read().map_err(rerr)?;
                let t = rtx.open_table(USERS).map_err(rerr)?;
                for item in t.iter().map_err(rerr)? {
                    let (k, v) = item.map_err(rerr)?;
                    let (k_org, k_name) = k.value();
                    if k_name == want {
                        let (hash, is_superuser): (Option<String>, bool) = de(v.value())?;
                        return Ok(Some((
                            k_org.to_string(),
                            UserRecord {
                                name: want.clone(),
                                is_superuser,
                            },
                            hash,
                        )));
                    }
                }
                Ok(None)
            },
        )
        .await
        .map_err(jerr)?
    }

    async fn delete_user(&self, org: &str, name: &str) -> Result<bool> {
        self.remove_key(USERS, org, name).await
    }

    async fn list_users(&self, org: &str) -> Result<Vec<UserRecord>> {
        let mut out = Vec::new();
        for (name, bytes) in self.list_org(USERS, org).await? {
            // Hash deliberately dropped from the listing (rule 12).
            let (_hash, is_superuser): (Option<String>, bool) = de(&bytes)?;
            out.push(UserRecord { name, is_superuser });
        }
        Ok(out)
    }

    async fn put_role(&self, org: &str, name: &str) -> Result<()> {
        let (db, org, name) = (self.db(), org.to_string(), name.to_string());
        tokio::task::spawn_blocking(move || -> Result<()> {
            let wtx = db.begin_write().map_err(rerr)?;
            {
                let mut t = wtx.open_table(ROLES).map_err(rerr)?;
                t.insert((org.as_str(), name.as_str()), 1u8).map_err(rerr)?;
            }
            wtx.commit().map_err(rerr)
        })
        .await
        .map_err(jerr)?
    }

    async fn delete_role(&self, org: &str, name: &str) -> Result<bool> {
        let (db, org, name) = (self.db(), org.to_string(), name.to_string());
        tokio::task::spawn_blocking(move || -> Result<bool> {
            let wtx = db.begin_write().map_err(rerr)?;
            let existed = {
                let mut t = wtx.open_table(ROLES).map_err(rerr)?;
                let existed = t
                    .remove((org.as_str(), name.as_str()))
                    .map_err(rerr)?
                    .is_some();
                existed
            };
            wtx.commit().map_err(rerr)?;
            Ok(existed)
        })
        .await
        .map_err(jerr)?
    }

    async fn list_roles(&self, org: &str) -> Result<Vec<String>> {
        let (db, org) = (self.db(), org.to_string());
        tokio::task::spawn_blocking(move || -> Result<Vec<String>> {
            let rtx = db.begin_read().map_err(rerr)?;
            let t = rtx.open_table(ROLES).map_err(rerr)?;
            let mut out = Vec::new();
            for item in t.iter().map_err(rerr)? {
                let (k, _v) = item.map_err(rerr)?;
                let (k_org, k_name) = k.value();
                if k_org == org {
                    out.push(k_name.to_string());
                }
            }
            Ok(out)
        })
        .await
        .map_err(jerr)?
    }

    async fn put_policy(&self, org: &str, name: &str, kind: &str, rule: &Value) -> Result<()> {
        let val: (String, Value) = (kind.to_string(), rule.clone());
        self.put_bytes(POLICIES, org, name, ser(&val)?).await
    }

    async fn get_policy(&self, org: &str, name: &str) -> Result<Option<(String, Value)>> {
        Ok(match self.get_bytes(POLICIES, org, name).await? {
            Some(bytes) => Some(de::<(String, Value)>(&bytes)?),
            None => None,
        })
    }

    async fn delete_policy(&self, org: &str, name: &str) -> Result<bool> {
        self.remove_key(POLICIES, org, name).await
    }

    async fn list_policies(&self, org: &str) -> Result<Vec<PolicyRecord>> {
        let mut out = Vec::new();
        for (name, bytes) in self.list_org(POLICIES, org).await? {
            let (kind, _rule): (String, Value) = de(&bytes)?;
            out.push(PolicyRecord { name, kind });
        }
        Ok(out)
    }

    async fn put_grant(&self, org: &str, grant: &GrantRecord) -> Result<()> {
        let key = grant_key(grant)?;
        self.put_bytes(GRANTS, org, &key, ser(grant)?).await
    }

    async fn delete_grant(&self, org: &str, grant: &GrantRecord) -> Result<bool> {
        let key = grant_key(grant)?;
        self.remove_key(GRANTS, org, &key).await
    }

    async fn list_grants(&self, org: &str) -> Result<Vec<GrantRecord>> {
        let mut out = Vec::new();
        for (_key, bytes) in self.list_org(GRANTS, org).await? {
            out.push(de::<GrantRecord>(&bytes)?);
        }
        Ok(out)
    }

    async fn add_role_member(&self, org: &str, role: &str, user: &str) -> Result<()> {
        let (db, org, role, user) = (
            self.db(),
            org.to_string(),
            role.to_string(),
            user.to_string(),
        );
        tokio::task::spawn_blocking(move || -> Result<()> {
            let wtx = db.begin_write().map_err(rerr)?;
            {
                let mut t = wtx.open_table(ROLE_MEMBERS).map_err(rerr)?;
                t.insert((org.as_str(), role.as_str(), user.as_str()), 1u8)
                    .map_err(rerr)?;
            }
            wtx.commit().map_err(rerr)
        })
        .await
        .map_err(jerr)?
    }

    async fn remove_role_member(&self, org: &str, role: &str, user: &str) -> Result<bool> {
        let (db, org, role, user) = (
            self.db(),
            org.to_string(),
            role.to_string(),
            user.to_string(),
        );
        tokio::task::spawn_blocking(move || -> Result<bool> {
            let wtx = db.begin_write().map_err(rerr)?;
            let existed = {
                let mut t = wtx.open_table(ROLE_MEMBERS).map_err(rerr)?;
                let existed = t
                    .remove((org.as_str(), role.as_str(), user.as_str()))
                    .map_err(rerr)?
                    .is_some();
                existed
            };
            wtx.commit().map_err(rerr)?;
            Ok(existed)
        })
        .await
        .map_err(jerr)?
    }

    async fn list_roles_for_user(&self, org: &str, user: &str) -> Result<Vec<String>> {
        let (db, org, user) = (self.db(), org.to_string(), user.to_string());
        tokio::task::spawn_blocking(move || -> Result<Vec<String>> {
            let rtx = db.begin_read().map_err(rerr)?;
            let t = rtx.open_table(ROLE_MEMBERS).map_err(rerr)?;
            let mut out = Vec::new();
            for item in t.iter().map_err(rerr)? {
                let (k, _v) = item.map_err(rerr)?;
                let (k_org, k_role, k_user) = k.value();
                if k_org == org && k_user == user {
                    out.push(k_role.to_string());
                }
            }
            Ok(out)
        })
        .await
        .map_err(jerr)?
    }

    async fn list_role_members(&self, org: &str, role: &str) -> Result<Vec<String>> {
        let (db, org, role) = (self.db(), org.to_string(), role.to_string());
        tokio::task::spawn_blocking(move || -> Result<Vec<String>> {
            let rtx = db.begin_read().map_err(rerr)?;
            let t = rtx.open_table(ROLE_MEMBERS).map_err(rerr)?;
            let mut out = Vec::new();
            for item in t.iter().map_err(rerr)? {
                let (k, _v) = item.map_err(rerr)?;
                let (k_org, k_role, k_user) = k.value();
                if k_org == org && k_role == role {
                    out.push(k_user.to_string());
                }
            }
            Ok(out)
        })
        .await
        .map_err(jerr)?
    }

    async fn put_derived_product(&self, org: &str, product: &DerivedProductRecord) -> Result<()> {
        self.put_bytes(PRODUCTS, org, &product.name, ser(product)?)
            .await
    }

    async fn get_derived_product(
        &self,
        org: &str,
        name: &str,
    ) -> Result<Option<DerivedProductRecord>> {
        Ok(match self.get_bytes(PRODUCTS, org, name).await? {
            Some(bytes) => Some(de::<DerivedProductRecord>(&bytes)?),
            None => None,
        })
    }

    async fn list_derived_products(&self, org: &str) -> Result<Vec<DerivedProductRecord>> {
        let mut out = Vec::new();
        for (_name, bytes) in self.list_org(PRODUCTS, org).await? {
            out.push(de::<DerivedProductRecord>(&bytes)?);
        }
        Ok(out)
    }

    async fn delete_derived_product(&self, org: &str, name: &str) -> Result<bool> {
        self.remove_key(PRODUCTS, org, name).await
    }

    async fn list_orgs(&self) -> Result<Vec<String>> {
        let db = self.db();
        tokio::task::spawn_blocking(move || -> Result<Vec<String>> {
            let rtx = db.begin_read().map_err(rerr)?;
            let mut orgs = std::collections::BTreeSet::new();
            // Every org that owns at least one object of any kind. Union across
            // all `(org, …)`-keyed tables so an org with only, say, a role still
            // shows up (rare — used for boot replay).
            macro_rules! collect2 {
                ($table:expr) => {{
                    let t = rtx.open_table($table).map_err(rerr)?;
                    for item in t.iter().map_err(rerr)? {
                        let (k, _v) = item.map_err(rerr)?;
                        orgs.insert(k.value().0.to_string());
                    }
                }};
            }
            collect2!(ENTRIES);
            collect2!(SECRETS);
            collect2!(USERS);
            collect2!(ROLES);
            collect2!(POLICIES);
            collect2!(GRANTS);
            collect2!(PRODUCTS);
            {
                let t = rtx.open_table(ROLE_MEMBERS).map_err(rerr)?;
                for item in t.iter().map_err(rerr)? {
                    let (k, _v) = item.map_err(rerr)?;
                    orgs.insert(k.value().0.to_string());
                }
            }
            // BTreeSet already yields sorted, deterministic order.
            Ok(orgs.into_iter().collect())
        })
        .await
        .map_err(jerr)?
    }

    async fn subscribe(&self) -> Result<BindingChangeStream> {
        let stream = BroadcastStream::new(self.inner.tx.subscribe())
            // Drop lag errors: a lagging subscriber re-lists rather than
            // blocking a writer (parity with the JSON store).
            .filter_map(std::result::Result::ok);
        Ok(BindingChangeStream::from_stream(stream))
    }
}

/// Deterministic key for a grant: its canonical json (serde serializes fields
/// in declaration order, so identical grants collide → set semantics, matching
/// the Postgres/JSON backends' `BTreeSet<GrantRecord>`).
fn grant_key(grant: &GrantRecord) -> Result<String> {
    serde_json::to_string(grant).map_err(CatalogServiceError::StoreSerialization)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use dataglot_core::catalog::{LiveConnectorBinding, LiveConnectorKind};
    use serde_json::json;
    use tokio_stream::StreamExt;

    use super::*;
    use crate::store::{GrantRecord, GranteeKind};

    fn pg_binding(hint: &str) -> CatalogBinding {
        CatalogBinding::LiveConnector(LiveConnectorBinding {
            kind: LiveConnectorKind::Postgres,
            endpoint_hint: hint.to_string(),
        })
    }

    fn db_path(dir: &tempfile::TempDir) -> PathBuf {
        dir.path().join("meta.redb")
    }

    async fn store(dir: &tempfile::TempDir) -> RedbMetaStore {
        RedbMetaStore::open(db_path(dir), "default")
            .await
            .expect("open redb store")
    }

    #[tokio::test]
    async fn bindings_and_source_config_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(&dir).await;

        // upsert returns the previous binding (None first time).
        assert!(s
            .upsert_binding("default", "pg", &pg_binding("h1"))
            .await
            .unwrap()
            .is_none());
        assert_eq!(
            s.upsert_binding("default", "pg", &pg_binding("h2"))
                .await
                .unwrap(),
            Some(pg_binding("h1")),
            "upsert returns the prior binding"
        );

        // source_config attaches to the same catalog and survives a re-upsert.
        s.set_source_config("default", "pg", &json!({"dsn_env": "PG"}))
            .await
            .unwrap();
        let _ = s
            .upsert_binding("default", "pg", &pg_binding("h3"))
            .await
            .unwrap();
        let cfgs = s.list_source_configs("default").await.unwrap();
        assert_eq!(cfgs.get("pg"), Some(&json!({"dsn_env": "PG"})));

        let bindings = s.list_bindings("default").await.unwrap();
        assert_eq!(bindings.get("pg"), Some(&pg_binding("h3")));

        assert!(s.delete_binding("default", "pg").await.unwrap());
        assert!(s.list_bindings("default").await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn set_source_config_without_binding_is_noop() {
        // Contract parity with Postgres (`UPDATE … WHERE` touches 0 rows) and
        // the JSON store: an unknown catalog is silently ignored, not an error,
        // and nothing is created.
        let dir = tempfile::tempdir().unwrap();
        let s = store(&dir).await;
        s.set_source_config("default", "ghost", &json!({"x": 1}))
            .await
            .expect("set_source_config on a missing binding is a no-op");
        assert!(s.list_source_configs("default").await.unwrap().is_empty());
        assert!(s.list_bindings("default").await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn set_source_config_emits_change() {
        // `CREATE CATALOG` writes the binding then the source_config; the live
        // registry-refresh rebuilds from the source_config, so this second write
        // must fire a change too (regression: it silently didn't).
        let dir = tempfile::tempdir().unwrap();
        let s = store(&dir).await;
        s.upsert_binding("default", "pg", &pg_binding("h"))
            .await
            .unwrap();
        let mut stream = s.subscribe().await.unwrap();
        s.set_source_config("default", "pg", &json!({"dsn_env": "PG"}))
            .await
            .unwrap();
        let ev = tokio::time::timeout(std::time::Duration::from_secs(2), stream.next())
            .await
            .expect("change within 2s")
            .expect("stream item");
        assert_eq!(ev.name, "pg");
        assert_eq!(ev.kind, BindingChangeKind::Upserted);
    }

    #[tokio::test]
    async fn secrets_store_ciphertext_verbatim_and_never_plaintext() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(&dir).await;
        let ciphertext = b"\x00\x01\x02opaque-cipher-bytes\xff";
        s.put_secret("default", "sf", ciphertext).await.unwrap();
        assert_eq!(
            s.get_secret("default", "sf").await.unwrap().as_deref(),
            Some(&ciphertext[..])
        );
        assert_eq!(s.list_secret_names("default").await.unwrap(), vec!["sf"]);
        assert!(s.delete_secret("default", "sf").await.unwrap());
        assert!(s.get_secret("default", "sf").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn users_expose_hash_only_via_get_never_list() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(&dir).await;
        s.put_user("default", "alice", Some("argon2$hash"), true)
            .await
            .unwrap();
        s.put_user("default", "bob", None, false).await.unwrap();

        let (rec, hash) = s.get_user("default", "alice").await.unwrap().unwrap();
        assert!(rec.is_superuser);
        assert_eq!(hash.as_deref(), Some("argon2$hash"));

        // find_user locates across the org and returns the hash.
        let (org, rec, hash) = s.find_user("alice").await.unwrap().unwrap();
        assert_eq!(org, "default");
        assert_eq!(rec.name, "alice");
        assert_eq!(hash.as_deref(), Some("argon2$hash"));

        // list_users must NOT carry the hash (rule 12) — UserRecord has no hash
        // field, so this is a structural guarantee; assert the set is present.
        let mut names: Vec<_> = s
            .list_users("default")
            .await
            .unwrap()
            .into_iter()
            .map(|u| u.name)
            .collect();
        names.sort();
        assert_eq!(names, vec!["alice", "bob"]);

        assert!(s.delete_user("default", "bob").await.unwrap());
        assert!(s.get_user("default", "bob").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn roles_members_policies_grants_products_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(&dir).await;

        // roles + membership
        s.put_role("default", "analyst").await.unwrap();
        s.add_role_member("default", "analyst", "alice")
            .await
            .unwrap();
        s.add_role_member("default", "analyst", "bob")
            .await
            .unwrap();
        assert_eq!(s.list_roles("default").await.unwrap(), vec!["analyst"]);
        let mut members = s.list_role_members("default", "analyst").await.unwrap();
        members.sort();
        assert_eq!(members, vec!["alice", "bob"]);
        assert_eq!(
            s.list_roles_for_user("default", "alice").await.unwrap(),
            vec!["analyst"]
        );
        assert!(s
            .remove_role_member("default", "analyst", "bob")
            .await
            .unwrap());

        // policies
        s.put_policy("default", "mask_email", "mask", &json!({"kind": "hash"}))
            .await
            .unwrap();
        assert_eq!(
            s.get_policy("default", "mask_email").await.unwrap(),
            Some(("mask".to_string(), json!({"kind": "hash"})))
        );
        let pols = s.list_policies("default").await.unwrap();
        assert_eq!(pols.len(), 1);
        assert_eq!(pols[0].kind, "mask");

        // grants — set semantics: same grant twice ⇒ one entry.
        let g = GrantRecord::select(GranteeKind::User, "alice", "pg", "public", "t");
        s.put_grant("default", &g).await.unwrap();
        s.put_grant("default", &g).await.unwrap();
        assert_eq!(s.list_grants("default").await.unwrap(), vec![g.clone()]);
        assert!(s.delete_grant("default", &g).await.unwrap());
        assert!(s.list_grants("default").await.unwrap().is_empty());

        // derived products
        let prod = DerivedProductRecord {
            name: "customer_360".to_string(),
            sql: "SELECT 1".to_string(),
            catalog: Some("main".to_string()),
            schema: Some("public".to_string()),
        };
        s.put_derived_product("default", &prod).await.unwrap();
        assert_eq!(
            s.get_derived_product("default", "customer_360")
                .await
                .unwrap(),
            Some(prod.clone())
        );
        assert_eq!(
            s.list_derived_products("default").await.unwrap(),
            vec![prod]
        );
        assert!(s
            .delete_derived_product("default", "customer_360")
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn org_isolation_and_list_orgs() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(&dir).await;
        s.upsert_binding("orgA", "pg", &pg_binding("a"))
            .await
            .unwrap();
        s.put_role("orgB", "reader").await.unwrap();

        assert!(s.list_bindings("orgB").await.unwrap().is_empty());
        assert!(s.list_roles("orgA").await.unwrap().is_empty());
        assert_eq!(s.list_orgs().await.unwrap(), vec!["orgA", "orgB"]);
    }

    #[tokio::test]
    async fn state_persists_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        {
            let s = store(&dir).await;
            s.upsert_binding("default", "pg", &pg_binding("h"))
                .await
                .unwrap();
            s.put_secret("default", "sf", b"cipher").await.unwrap();
        }
        // Reopen the same file — redb persists.
        let s = store(&dir).await;
        assert_eq!(
            s.list_bindings("default").await.unwrap().get("pg"),
            Some(&pg_binding("h"))
        );
        assert_eq!(
            s.get_secret("default", "sf").await.unwrap().as_deref(),
            Some(&b"cipher"[..])
        );
    }

    /// redb takes an exclusive file lock, so opening the same path twice while
    /// both handles are live would fail with "Database already open" — the boot
    /// path does exactly that. The registry must hand the second `open()` a clone
    /// of the same handle: both succeed and share one DB + change feed.
    #[tokio::test]
    async fn concurrent_opens_of_same_path_share_one_handle() {
        let dir = tempfile::tempdir().unwrap();
        let s1 = store(&dir).await; // first handle stays alive …
        let s2 = store(&dir).await; // … so this second open must not re-lock.

        // A write through one handle is visible through the other (shared DB) …
        s1.upsert_binding("default", "pg", &pg_binding("h"))
            .await
            .unwrap();
        assert_eq!(
            s2.list_bindings("default").await.unwrap().get("pg"),
            Some(&pg_binding("h"))
        );

        // … and they share one change feed: s2's subscriber sees s1's write.
        let mut stream = s2.subscribe().await.unwrap();
        s1.upsert_binding("default", "pg2", &pg_binding("h2"))
            .await
            .unwrap();
        let ev = tokio::time::timeout(std::time::Duration::from_secs(2), stream.next())
            .await
            .expect("change within 2s")
            .expect("stream item");
        assert_eq!(ev.name, "pg2");
    }

    #[tokio::test]
    async fn change_feed_emits_on_upsert_and_delete() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(&dir).await;
        let mut stream = s.subscribe().await.unwrap();

        s.upsert_binding("default", "pg", &pg_binding("h"))
            .await
            .unwrap();
        let ev = tokio::time::timeout(std::time::Duration::from_secs(2), stream.next())
            .await
            .expect("change within 2s")
            .expect("stream item");
        assert_eq!(ev.name, "pg");
        assert_eq!(ev.kind, BindingChangeKind::Upserted);

        s.delete_binding("default", "pg").await.unwrap();
        let ev = tokio::time::timeout(std::time::Duration::from_secs(2), stream.next())
            .await
            .expect("change within 2s")
            .expect("stream item");
        assert_eq!(ev.kind, BindingChangeKind::Deleted);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn backing_file_is_owner_only_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let s = store(&dir).await;
        s.put_secret("default", "sf", b"cipher").await.unwrap();
        let mode = std::fs::metadata(db_path(&dir))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode, 0o600,
            "meta store file must be owner-only (secrets live here)"
        );
    }

    #[tokio::test]
    async fn debug_is_value_free() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(&dir).await;
        s.put_secret("default", "sf", b"top-secret-cipher")
            .await
            .unwrap();
        let dbg = format!("{s:?}");
        assert!(dbg.contains("RedbMetaStore"));
        assert!(
            !dbg.contains("top-secret-cipher"),
            "no stored value in Debug"
        );
    }
}

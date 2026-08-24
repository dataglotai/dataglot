//! [`EmbeddedMetaStore`] — the pure-Rust, zero-external-dependency
//! [`MetaStore`] backend (hard rule 15 clean; no C, no Postgres).
//!
//! Spec: the phase-6 `sql-native-runtime-config` plan (slice A).
//!
//! State lives in memory behind a `tokio::sync::Mutex`; every mutation is
//! flushed to a single JSON file with a **write-temp-then-rename** so a
//! reader (or a crash) sees the whole old document or the whole new one,
//! never a torn write. The change feed is an in-process
//! `tokio::sync::broadcast` adapted into the same [`BindingChangeStream`]
//! the Postgres LISTEN/NOTIFY pump produces.
//!
//! Chosen over an embedded KV (redb/sled) or embedded SQLite because the
//! data is tiny and low-churn (dozens of small catalog/secret records):
//! a whole-file atomic rewrite is simpler, dependency-free, and fully
//! debuggable. RisingWave uses SQLite for this slot; we can't (it's a C
//! dep — rule 15), and our Postgres backend already mirrors RisingWave's
//! HA (Postgres/MySQL) meta store.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;
use std::path::PathBuf;

use async_trait::async_trait;
use dataglot_core::CatalogBinding;
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::{broadcast, Mutex};
use tokio_stream::wrappers::BroadcastStream;

use crate::error::CatalogServiceError;
use crate::migrations::{run_embedded_migrations, EmbeddedMigration};
use crate::store::{DerivedProductRecord, GrantRecord, MetaStore, PolicyRecord, UserRecord};
use crate::subscribe::{BindingChange, BindingChangeKind, BindingChangeStream};
use crate::Result;

/// On-disk **target** version this build writes and loads. `v2` is org-nested
/// ( M1: one store serves every org). An older file is brought up to
/// this version by folding the ordered [`EMBEDDED_MIGRATIONS`] chain on
/// [`open`](EmbeddedMetaStore::open); a newer/unknown version is refused (same
/// fail-fast posture as the Postgres schema-version guard). Bumping the target
/// is a matter of appending one step to that chain.
const STORE_VERSION: &str = "v2";

/// Prior, single-org on-disk version — the input of the first migration step.
const STORE_VERSION_V1: &str = "v1";

/// The org a legacy `v1` (flat, single-org) document's data lands in when
/// migrated to the org-nested `v2` layout. Phase 1 always ran as
/// `"default"`, so this keeps every existing embedded store working.
const MIGRATION_ORG: &str = "default";

/// Ordered embedded-store migration chain. Each step takes the
/// document from version `from` to `to`; the last step's `to` is the build's
/// target ([`STORE_VERSION`]). Today the single registered step is the
/// `v1 -> v2` org-nesting migration (the flat `entries`/`secrets` fold into org
/// [`MIGRATION_ORG`]); the next schema change appends a `v2 -> v3` step here.
const EMBEDDED_MIGRATIONS: &[EmbeddedMigration] = &[EmbeddedMigration {
    from: STORE_VERSION_V1,
    to: STORE_VERSION,
    apply: migrate_v1_to_v2,
}];

/// The `v1 -> v2` org-nesting migration, re-expressed as a registered step
///. Folds a legacy flat, single-org document — top-level
/// `entries` + `secrets` — into the org-nested `v2` shape under org
/// [`MIGRATION_ORG`]. A `v1` file predates users/roles/policies/grants, so
/// those org fields are left absent and default to empty on the subsequent
/// typed load — identical to the hand-written migration this replaces.
///
/// Pure and total: an input that is unexpectedly not a JSON object is returned
/// unchanged, leaving the caller's typed deserialize to reject it as a corrupt
/// store (matching the pre-framework behavior where a bad shape surfaced as
/// [`CatalogServiceError::CorruptStore`]).
fn migrate_v1_to_v2(mut doc: Value) -> Value {
    if let Some(obj) = doc.as_object_mut() {
        let entries = obj
            .remove("entries")
            .unwrap_or_else(|| Value::Object(serde_json::Map::new()));
        let secrets = obj
            .remove("secrets")
            .unwrap_or_else(|| Value::Object(serde_json::Map::new()));
        let mut org = serde_json::Map::new();
        org.insert("entries".to_string(), entries);
        org.insert("secrets".to_string(), secrets);
        let mut orgs = serde_json::Map::new();
        orgs.insert(MIGRATION_ORG.to_string(), Value::Object(org));
        obj.insert("orgs".to_string(), Value::Object(orgs));
        obj.insert(
            "version".to_string(),
            Value::String(STORE_VERSION.to_string()),
        );
    }
    doc
}

/// Change-feed channel depth. Comfortably larger than any realistic burst
/// of catalog mutations; a subscriber that still lags past it receives a
/// `Lagged` (dropped here) and is expected to re-list (the cache does).
const CHANGE_CHANNEL_CAPACITY: usize = 256;

/// One stored catalog: its binding plus the optional credential-free
/// source config (`*_env` names only, rule 12).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Entry {
    binding: CatalogBinding,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    source_config: Option<Value>,
}

/// Per-org state: one org's catalog entries and secrets. Serialized as a
/// nested object under `orgs[<org_id>]` in the `v2` document.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
struct OrgState {
    #[serde(default)]
    entries: HashMap<String, Entry>,
    /// Encrypted secrets by name. Values are opaque
    /// ciphertext — the embedded store never holds plaintext (rule 12).
    /// `BTreeMap` for deterministic on-disk ordering.
    #[serde(default)]
    secrets: BTreeMap<String, Vec<u8>>,
    /// Users by name: `(opaque password hash | None, is_superuser)`.
    /// The hash is opaque — hashed in `dataglot-server` (M3b), never plaintext
    /// here (rule 12) — and is never surfaced by `list_users`. `BTreeMap` for
    /// deterministic on-disk ordering. `#[serde(default)]` so existing v2 files
    /// (written before M3a) still load.
    #[serde(default)]
    users: BTreeMap<String, (Option<String>, bool)>,
    /// Role names. A role carries no password. `BTreeSet` for
    /// deterministic on-disk ordering.
    #[serde(default)]
    roles: BTreeSet<String>,
    /// Governance policies by name: `(kind, serialized rule)`.
    /// `kind` is `"mask"` / `"row_filter"`; the rule is an opaque JSON value
    /// (the embedded store never interprets it — rule 4). `BTreeMap` for
    /// deterministic on-disk ordering. `#[serde(default)]` so existing v2 files
    /// (written before M4a) still load.
    #[serde(default)]
    policies: BTreeMap<String, (String, Value)>,
    /// Privilege grants. A `BTreeSet` gives idempotent upsert
    /// (a re-put of an identical grant collapses) and deterministic on-disk
    /// ordering. `#[serde(default)]` so existing v2 files (written before F5a)
    /// still load. Stored only; not enforced (F5b).
    #[serde(default)]
    grants: BTreeSet<GrantRecord>,
    /// Role→user memberships ( F5a, `GRANT <role> TO <user>`): each role
    /// maps to its member users. A separate user↔role relation from `roles`
    /// (M3a's bare role set). `BTreeMap`/`BTreeSet` for deterministic ordering.
    /// `#[serde(default)]` so existing v2 files still load.
    #[serde(default)]
    role_members: BTreeMap<String, BTreeSet<String>>,
    /// Derived products by name: a runtime `CREATE VIEW` mapped to
    /// Dataglot's derived-product concept. `BTreeMap` for deterministic on-disk
    /// ordering; keyed by name so an upsert (`CREATE` / `CREATE OR REPLACE`)
    /// replaces in place. `#[serde(default)]` so existing v2 files (written
    /// before F9) still load — no store-version bump needed (additive, same
    /// posture as the M3a/M4a/F5a maps above).
    #[serde(default)]
    derived_products: BTreeMap<String, DerivedProductRecord>,
}

/// In-memory state guarded by the store's mutex. Org-nested:
/// one store instance serves every org.
#[derive(Debug, Default)]
struct State {
    orgs: HashMap<String, OrgState>,
}

impl State {
    /// Read-only view of an org's state, or `None` if the org has never
    /// been written (reads on an unknown org return empty results).
    fn org(&self, org: &str) -> Option<&OrgState> {
        self.orgs.get(org)
    }

    /// Mutable view of an org's state, creating it on first write.
    fn org_mut(&mut self, org: &str) -> &mut OrgState {
        self.orgs.entry(org.to_string()).or_default()
    }
}

/// Borrowed serialize view of the whole `v2` document (no clone on write).
#[derive(Serialize)]
struct StoreDocRef<'a> {
    version: &'a str,
    /// Informational label (the store's home/default org). Data scoping is
    /// entirely by the `orgs` map keys, never this field.
    org_id: &'a str,
    orgs: &'a HashMap<String, OrgState>,
}

/// Minimal projection that reads just the on-disk `version` tag before the
/// document is interpreted. A file missing this field is corrupt (the
/// pre-framework typed parse likewise required `version`), so extracting it
/// through a typed deserialize preserves that [`CatalogServiceError::CorruptStore`]
/// behavior. The migration chain is keyed off the value read here.
#[derive(Deserialize)]
struct VersionTag {
    version: String,
}

/// Owned deserialize view of the **target-version** (`v2`) document — the shape
/// every store has after [`EMBEDDED_MIGRATIONS`] has folded it forward.
/// Older on-disk layouts (the flat `v1` `entries`/`secrets`) are handled by the
/// migration steps, not here. `org_id` in the file is informational and ignored
/// on read; unknown fields are tolerated.
#[derive(Deserialize)]
struct StoreDoc {
    /// Org-nested state.
    #[serde(default)]
    orgs: HashMap<String, OrgState>,
}

/// Pure-Rust file-backed [`MetaStore`]. Cheap to share behind an `Arc`.
pub struct EmbeddedMetaStore {
    path: PathBuf,
    org_id: String,
    state: Mutex<State>,
    tx: broadcast::Sender<BindingChange>,
}

impl fmt::Debug for EmbeddedMetaStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Deliberately omits `entries` — no lock grab in Debug, and no
        // reason to dump source configs into a log line.
        f.debug_struct("EmbeddedMetaStore")
            .field("path", &self.path)
            .field("org_id", &self.org_id)
            .finish_non_exhaustive()
    }
}

impl EmbeddedMetaStore {
    /// Open (or create) an embedded meta store backed by `path`, scoped to
    /// `org_id`. A missing file starts empty; the file is created on the
    /// first mutation. An existing file is loaded and its version checked.
    ///
    /// # Errors
    /// [`CatalogServiceError::Io`] if the file exists but can't be read,
    /// [`CatalogServiceError::CorruptStore`] if it can't be parsed, or
    /// [`CatalogServiceError::SchemaVersionMismatch`] on a version other
    /// than the one this build understands.
    pub async fn open(path: impl Into<PathBuf>, org_id: impl Into<String>) -> Result<Self> {
        let path = path.into();
        let org_id = org_id.into();
        let state = match tokio::fs::read(&path).await {
            Ok(bytes) => {
                let corrupt = |source| CatalogServiceError::CorruptStore {
                    path: path.display().to_string(),
                    source,
                };
                // Parse once as an untyped document (the migration chain rewrites
                // it in place) and once for just the `version` tag (a missing
                // version is corrupt, matching the old required-field parse).
                let doc: Value = serde_json::from_slice(&bytes).map_err(corrupt)?;
                let tag: VersionTag = serde_json::from_slice(&bytes).map_err(corrupt)?;
                // Fold the ordered chain from the file's version up to the
                // build's target; a newer/unknown version fails fast here.
                let migrated =
                    run_embedded_migrations(EMBEDDED_MIGRATIONS, STORE_VERSION, tag.version, doc)?;
                // The result is a target-version (`v2`) document; a shape the
                // typed load can't accept surfaces as a corrupt store.
                let doc: StoreDoc = serde_json::from_value(migrated).map_err(corrupt)?;
                State { orgs: doc.orgs }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => State::default(),
            Err(source) => {
                return Err(CatalogServiceError::Io {
                    path: path.display().to_string(),
                    source,
                });
            }
        };
        let (tx, _rx) = broadcast::channel(CHANGE_CHANNEL_CAPACITY);
        Ok(Self {
            path,
            org_id,
            state: Mutex::new(state),
            tx,
        })
    }

    /// `<path>.tmp` sibling used for the atomic write.
    fn tmp_path(&self) -> PathBuf {
        let mut s = self.path.clone().into_os_string();
        s.push(".tmp");
        PathBuf::from(s)
    }

    /// Serialize the whole document (entries + secrets) and atomically
    /// replace the backing file (write temp + rename on the same directory).
    /// Held under the state lock by callers so the file always reflects a
    /// committed state.
    async fn persist(&self, state: &State) -> Result<()> {
        let doc = StoreDocRef {
            version: STORE_VERSION,
            org_id: &self.org_id,
            orgs: &state.orgs,
        };
        let bytes =
            serde_json::to_vec_pretty(&doc).map_err(CatalogServiceError::StoreSerialization)?;
        let tmp = self.tmp_path();
        tokio::fs::write(&tmp, &bytes)
            .await
            .map_err(|source| CatalogServiceError::Io {
                path: tmp.display().to_string(),
                source,
            })?;
        tokio::fs::rename(&tmp, &self.path)
            .await
            .map_err(|source| CatalogServiceError::Io {
                path: self.path.display().to_string(),
                source,
            })?;
        Ok(())
    }

    /// Best-effort change emit — a send error only means no live
    /// subscribers, which is fine. The event carries the mutating `org`
    /// (not a store-wide default), so an org-wide subscriber can filter.
    fn emit(&self, org: &str, name: &str, kind: BindingChangeKind) {
        let _ = self.tx.send(BindingChange {
            org_id: org.to_string(),
            name: name.to_string(),
            kind,
        });
    }
}

#[async_trait]
impl MetaStore for EmbeddedMetaStore {
    async fn list_source_configs(&self, org: &str) -> Result<HashMap<String, Value>> {
        // Single returned expression so the lock guard's scope stays tight
        // (clippy::significant_drop_tightening). Unknown org ⇒ empty map.
        let st = self.state.lock().await;
        Ok(st
            .org(org)
            .map(|o| {
                o.entries
                    .iter()
                    .filter_map(|(name, e)| e.source_config.clone().map(|c| (name.clone(), c)))
                    .collect()
            })
            .unwrap_or_default())
    }

    async fn list_bindings(&self, org: &str) -> Result<HashMap<String, CatalogBinding>> {
        let st = self.state.lock().await;
        Ok(st
            .org(org)
            .map(|o| {
                o.entries
                    .iter()
                    .map(|(name, e)| (name.clone(), e.binding.clone()))
                    .collect()
            })
            .unwrap_or_default())
    }

    async fn upsert_binding(
        &self,
        org: &str,
        name: &str,
        binding: &CatalogBinding,
    ) -> Result<Option<CatalogBinding>> {
        let mut st = self.state.lock().await;
        let o = st.org_mut(org);
        let prev = o.entries.get(name).map(|e| e.binding.clone());
        match o.entries.get_mut(name) {
            // Preserve any existing source_config; only the binding moves.
            Some(e) => e.binding = binding.clone(),
            None => {
                o.entries.insert(
                    name.to_string(),
                    Entry {
                        binding: binding.clone(),
                        source_config: None,
                    },
                );
            }
        }
        self.persist(&st).await?;
        drop(st);
        self.emit(org, name, BindingChangeKind::Upserted);
        Ok(prev)
    }

    async fn set_source_config(&self, org: &str, name: &str, source_config: &Value) -> Result<()> {
        let mut st = self.state.lock().await;
        // No-op if the name has no binding in this org (contract mirrors the
        // Postgres UPDATE, which touches 0 rows). Only a real change emits +
        // persists. Read without creating the org so an unknown org stays absent.
        let touched = st
            .orgs
            .get_mut(org)
            .and_then(|o| o.entries.get_mut(name))
            .map(|e| e.source_config = Some(source_config.clone()))
            .is_some();
        if !touched {
            return Ok(());
        }
        self.persist(&st).await?;
        drop(st);
        self.emit(org, name, BindingChangeKind::Upserted);
        Ok(())
    }

    async fn delete_binding(&self, org: &str, name: &str) -> Result<bool> {
        let mut st = self.state.lock().await;
        let existed = st
            .orgs
            .get_mut(org)
            .is_some_and(|o| o.entries.remove(name).is_some());
        if existed {
            self.persist(&st).await?;
            drop(st);
            self.emit(org, name, BindingChangeKind::Deleted);
        }
        Ok(existed)
    }

    async fn put_secret(&self, org: &str, name: &str, ciphertext: &[u8]) -> Result<()> {
        let mut st = self.state.lock().await;
        st.org_mut(org)
            .secrets
            .insert(name.to_string(), ciphertext.to_vec());
        self.persist(&st).await?;
        drop(st);
        Ok(())
    }

    async fn get_secret(&self, org: &str, name: &str) -> Result<Option<Vec<u8>>> {
        let st = self.state.lock().await;
        Ok(st.org(org).and_then(|o| o.secrets.get(name).cloned()))
    }

    async fn delete_secret(&self, org: &str, name: &str) -> Result<bool> {
        let mut st = self.state.lock().await;
        let existed = st
            .orgs
            .get_mut(org)
            .is_some_and(|o| o.secrets.remove(name).is_some());
        if existed {
            self.persist(&st).await?;
        }
        drop(st);
        Ok(existed)
    }

    async fn list_secret_names(&self, org: &str) -> Result<Vec<String>> {
        let st = self.state.lock().await;
        // `BTreeMap` iterates in sorted key order.
        Ok(st
            .org(org)
            .map(|o| o.secrets.keys().cloned().collect())
            .unwrap_or_default())
    }

    async fn put_user(
        &self,
        org: &str,
        name: &str,
        password_hash: Option<&str>,
        is_superuser: bool,
    ) -> Result<()> {
        let mut st = self.state.lock().await;
        st.org_mut(org).users.insert(
            name.to_string(),
            (password_hash.map(str::to_string), is_superuser),
        );
        self.persist(&st).await?;
        drop(st);
        Ok(())
    }

    async fn get_user(
        &self,
        org: &str,
        name: &str,
    ) -> Result<Option<(UserRecord, Option<String>)>> {
        let st = self.state.lock().await;
        Ok(st.org(org).and_then(|o| {
            o.users.get(name).map(|(hash, is_superuser)| {
                (
                    UserRecord {
                        name: name.to_string(),
                        is_superuser: *is_superuser,
                    },
                    hash.clone(),
                )
            })
        }))
    }

    async fn find_user(&self, name: &str) -> Result<Option<(String, UserRecord, Option<String>)>> {
        let st = self.state.lock().await;
        // Deterministic "first match": scan orgs in sorted name order so a
        // (defensively tolerated) duplicate resolves to the lowest org name.
        let mut orgs: Vec<&String> = st.orgs.keys().collect();
        orgs.sort();
        let found = orgs.into_iter().find_map(|org| {
            st.orgs.get(org).and_then(|o| {
                o.users.get(name).map(|(hash, is_superuser)| {
                    (
                        org.clone(),
                        UserRecord {
                            name: name.to_string(),
                            is_superuser: *is_superuser,
                        },
                        hash.clone(),
                    )
                })
            })
        });
        // Release the guard before returning (clippy::significant_drop_tightening).
        drop(st);
        Ok(found)
    }

    async fn delete_user(&self, org: &str, name: &str) -> Result<bool> {
        let mut st = self.state.lock().await;
        let existed = st
            .orgs
            .get_mut(org)
            .is_some_and(|o| o.users.remove(name).is_some());
        if existed {
            self.persist(&st).await?;
        }
        drop(st);
        Ok(existed)
    }

    async fn list_users(&self, org: &str) -> Result<Vec<UserRecord>> {
        let st = self.state.lock().await;
        // `BTreeMap` iterates in sorted key order; the hash is deliberately
        // dropped here — it never leaves via a listing (rule 12).
        Ok(st
            .org(org)
            .map(|o| {
                o.users
                    .iter()
                    .map(|(name, (_hash, is_superuser))| UserRecord {
                        name: name.clone(),
                        is_superuser: *is_superuser,
                    })
                    .collect()
            })
            .unwrap_or_default())
    }

    async fn put_role(&self, org: &str, name: &str) -> Result<()> {
        let mut st = self.state.lock().await;
        st.org_mut(org).roles.insert(name.to_string());
        self.persist(&st).await?;
        drop(st);
        Ok(())
    }

    async fn delete_role(&self, org: &str, name: &str) -> Result<bool> {
        let mut st = self.state.lock().await;
        let existed = st.orgs.get_mut(org).is_some_and(|o| o.roles.remove(name));
        if existed {
            self.persist(&st).await?;
        }
        drop(st);
        Ok(existed)
    }

    async fn list_roles(&self, org: &str) -> Result<Vec<String>> {
        let st = self.state.lock().await;
        // `BTreeSet` iterates in sorted order.
        Ok(st
            .org(org)
            .map(|o| o.roles.iter().cloned().collect())
            .unwrap_or_default())
    }

    async fn put_policy(&self, org: &str, name: &str, kind: &str, rule: &Value) -> Result<()> {
        let mut st = self.state.lock().await;
        st.org_mut(org)
            .policies
            .insert(name.to_string(), (kind.to_string(), rule.clone()));
        self.persist(&st).await?;
        drop(st);
        Ok(())
    }

    async fn get_policy(&self, org: &str, name: &str) -> Result<Option<(String, Value)>> {
        let st = self.state.lock().await;
        Ok(st.org(org).and_then(|o| o.policies.get(name).cloned()))
    }

    async fn delete_policy(&self, org: &str, name: &str) -> Result<bool> {
        let mut st = self.state.lock().await;
        let existed = st
            .orgs
            .get_mut(org)
            .is_some_and(|o| o.policies.remove(name).is_some());
        if existed {
            self.persist(&st).await?;
        }
        drop(st);
        Ok(existed)
    }

    async fn list_policies(&self, org: &str) -> Result<Vec<PolicyRecord>> {
        let st = self.state.lock().await;
        // `BTreeMap` iterates in sorted key order; the rule body is dropped
        // here — a listing carries name + kind only.
        Ok(st
            .org(org)
            .map(|o| {
                o.policies
                    .iter()
                    .map(|(name, (kind, _rule))| PolicyRecord {
                        name: name.clone(),
                        kind: kind.clone(),
                    })
                    .collect()
            })
            .unwrap_or_default())
    }

    async fn put_grant(&self, org: &str, grant: &GrantRecord) -> Result<()> {
        let mut st = self.state.lock().await;
        // `BTreeSet::insert` on an equal element is a no-op — idempotent upsert.
        st.org_mut(org).grants.insert(grant.clone());
        self.persist(&st).await?;
        drop(st);
        Ok(())
    }

    async fn delete_grant(&self, org: &str, grant: &GrantRecord) -> Result<bool> {
        let mut st = self.state.lock().await;
        let existed = st.orgs.get_mut(org).is_some_and(|o| o.grants.remove(grant));
        if existed {
            self.persist(&st).await?;
        }
        drop(st);
        Ok(existed)
    }

    async fn list_grants(&self, org: &str) -> Result<Vec<GrantRecord>> {
        let st = self.state.lock().await;
        // `BTreeSet` iterates in sorted (deterministic) order.
        Ok(st
            .org(org)
            .map(|o| o.grants.iter().cloned().collect())
            .unwrap_or_default())
    }

    async fn put_derived_product(&self, org: &str, product: &DerivedProductRecord) -> Result<()> {
        let mut st = self.state.lock().await;
        // Keyed by name — an upsert (CREATE / CREATE OR REPLACE) replaces.
        st.org_mut(org)
            .derived_products
            .insert(product.name.clone(), product.clone());
        self.persist(&st).await?;
        drop(st);
        Ok(())
    }

    async fn get_derived_product(
        &self,
        org: &str,
        name: &str,
    ) -> Result<Option<DerivedProductRecord>> {
        let st = self.state.lock().await;
        Ok(st
            .org(org)
            .and_then(|o| o.derived_products.get(name).cloned()))
    }

    async fn list_derived_products(&self, org: &str) -> Result<Vec<DerivedProductRecord>> {
        let st = self.state.lock().await;
        // `BTreeMap` iterates in sorted key (name) order.
        Ok(st
            .org(org)
            .map(|o| o.derived_products.values().cloned().collect())
            .unwrap_or_default())
    }

    async fn delete_derived_product(&self, org: &str, name: &str) -> Result<bool> {
        let mut st = self.state.lock().await;
        let existed = st
            .orgs
            .get_mut(org)
            .is_some_and(|o| o.derived_products.remove(name).is_some());
        if existed {
            self.persist(&st).await?;
        }
        drop(st);
        Ok(existed)
    }

    async fn add_role_member(&self, org: &str, role: &str, user: &str) -> Result<()> {
        let mut st = self.state.lock().await;
        // `BTreeSet::insert` collapses a duplicate pair — idempotent.
        st.org_mut(org)
            .role_members
            .entry(role.to_string())
            .or_default()
            .insert(user.to_string());
        self.persist(&st).await?;
        drop(st);
        Ok(())
    }

    async fn remove_role_member(&self, org: &str, role: &str, user: &str) -> Result<bool> {
        let mut st = self.state.lock().await;
        let existed = st
            .orgs
            .get_mut(org)
            .and_then(|o| o.role_members.get_mut(role))
            .is_some_and(|members| members.remove(user));
        if existed {
            // Drop an emptied role key so it doesn't linger in the document.
            if let Some(o) = st.orgs.get_mut(org) {
                if o.role_members.get(role).is_some_and(BTreeSet::is_empty) {
                    o.role_members.remove(role);
                }
            }
            self.persist(&st).await?;
        }
        drop(st);
        Ok(existed)
    }

    async fn list_roles_for_user(&self, org: &str, user: &str) -> Result<Vec<String>> {
        let st = self.state.lock().await;
        // `BTreeMap` iterates roles in sorted order, so the result is sorted.
        Ok(st
            .org(org)
            .map(|o| {
                o.role_members
                    .iter()
                    .filter(|(_role, members)| members.contains(user))
                    .map(|(role, _members)| role.clone())
                    .collect()
            })
            .unwrap_or_default())
    }

    async fn list_role_members(&self, org: &str, role: &str) -> Result<Vec<String>> {
        let st = self.state.lock().await;
        // `BTreeSet` iterates members in sorted order.
        Ok(st
            .org(org)
            .and_then(|o| o.role_members.get(role))
            .map(|members| members.iter().cloned().collect())
            .unwrap_or_default())
    }

    async fn list_orgs(&self) -> Result<Vec<String>> {
        // Scope the lock to the collect so the guard drops before the sort
        // (clippy::significant_drop_tightening).
        let mut orgs: Vec<String> = {
            let st = self.state.lock().await;
            st.orgs.keys().cloned().collect()
        };
        // Every org the store knows, sorted for a deterministic boot replay.
        orgs.sort();
        Ok(orgs)
    }

    async fn subscribe(&self) -> Result<BindingChangeStream> {
        // Drop `Lagged` errors — a lagging subscriber is expected to
        // re-list; the stream stays a clean `BindingChange` feed.
        let rx = self.tx.subscribe();
        let stream = BroadcastStream::new(rx).filter_map(|r| async move { r.ok() });
        Ok(BindingChangeStream::from_stream(stream))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use dataglot_core::catalog::{LiveConnectorBinding, LiveConnectorKind};
    use futures::StreamExt;
    use tokio::time::{timeout, Duration};

    use super::*;

    fn pg_binding(hint: &str) -> CatalogBinding {
        CatalogBinding::LiveConnector(LiveConnectorBinding {
            kind: LiveConnectorKind::Postgres,
            endpoint_hint: hint.to_string(),
        })
    }

    fn store_path(dir: &tempfile::TempDir) -> PathBuf {
        dir.path().join("meta.json")
    }

    #[tokio::test]
    async fn open_missing_file_is_empty() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = EmbeddedMetaStore::open(store_path(&dir), "default")
            .await
            .expect("open");
        assert!(store
            .list_bindings("default")
            .await
            .expect("list")
            .is_empty());
        assert!(store
            .list_source_configs("default")
            .await
            .expect("list")
            .is_empty());
    }

    #[tokio::test]
    async fn upsert_lists_and_returns_previous() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = EmbeddedMetaStore::open(store_path(&dir), "default")
            .await
            .expect("open");

        // First upsert: no previous.
        let prev = store
            .upsert_binding("default", "pg", &pg_binding("host-a"))
            .await
            .expect("upsert");
        assert!(prev.is_none());

        // Second upsert of the same name returns the prior binding.
        let prev = store
            .upsert_binding("default", "pg", &pg_binding("host-b"))
            .await
            .expect("upsert");
        assert_eq!(prev, Some(pg_binding("host-a")));

        let bindings = store.list_bindings("default").await.expect("list");
        assert_eq!(bindings.len(), 1);
        assert_eq!(bindings.get("pg"), Some(&pg_binding("host-b")));
    }

    #[tokio::test]
    async fn source_config_only_listed_when_set_and_survives_upsert() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = EmbeddedMetaStore::open(store_path(&dir), "default")
            .await
            .expect("open");

        // set_source_config on a missing binding is a no-op.
        store
            .set_source_config("default", "pg", &serde_json::json!({"kind": "postgres"}))
            .await
            .expect("set (noop)");
        assert!(store
            .list_source_configs("default")
            .await
            .expect("list")
            .is_empty());

        // With a binding, it sticks — and survives a later binding upsert.
        store
            .upsert_binding("default", "pg", &pg_binding("host-a"))
            .await
            .expect("upsert");
        store
            .set_source_config(
                "default",
                "pg",
                &serde_json::json!({"kind": "postgres", "dsn_env": "PG"}),
            )
            .await
            .expect("set");
        store
            .upsert_binding("default", "pg", &pg_binding("host-b"))
            .await
            .expect("re-upsert");

        let cfgs = store.list_source_configs("default").await.expect("list");
        assert_eq!(cfgs.len(), 1);
        assert_eq!(cfgs["pg"]["dsn_env"], "PG");
    }

    #[tokio::test]
    async fn delete_removes_and_reports_existence() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = EmbeddedMetaStore::open(store_path(&dir), "default")
            .await
            .expect("open");
        store
            .upsert_binding("default", "pg", &pg_binding("host-a"))
            .await
            .expect("upsert");

        assert!(store.delete_binding("default", "pg").await.expect("delete")); // existed
        assert!(!store.delete_binding("default", "pg").await.expect("delete")); // gone
        assert!(store
            .list_bindings("default")
            .await
            .expect("list")
            .is_empty());
    }

    #[tokio::test]
    async fn state_survives_reopen() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = store_path(&dir);
        {
            let store = EmbeddedMetaStore::open(&path, "default")
                .await
                .expect("open");
            store
                .upsert_binding("default", "pg", &pg_binding("host-a"))
                .await
                .expect("upsert");
            store
                .set_source_config(
                    "default",
                    "pg",
                    &serde_json::json!({"kind": "postgres", "dsn_env": "PG"}),
                )
                .await
                .expect("set");
        }
        // A fresh instance on the same path sees the persisted document.
        let reopened = EmbeddedMetaStore::open(&path, "default")
            .await
            .expect("reopen");
        let bindings = reopened.list_bindings("default").await.expect("list");
        assert_eq!(bindings.get("pg"), Some(&pg_binding("host-a")));
        assert_eq!(
            reopened.list_source_configs("default").await.expect("list")["pg"]["dsn_env"],
            "PG"
        );
    }

    #[tokio::test]
    async fn subscribe_emits_upsert_and_delete() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Arc::new(
            EmbeddedMetaStore::open(store_path(&dir), "default")
                .await
                .expect("open"),
        );
        let mut sub = store.subscribe().await.expect("subscribe");

        store
            .upsert_binding("default", "pg", &pg_binding("host-a"))
            .await
            .expect("upsert");
        let ev = timeout(Duration::from_secs(2), sub.next())
            .await
            .expect("no timeout")
            .expect("event");
        assert_eq!(ev.name, "pg");
        assert_eq!(ev.org_id, "default");
        assert_eq!(ev.kind, BindingChangeKind::Upserted);

        store.delete_binding("default", "pg").await.expect("delete");
        let ev = timeout(Duration::from_secs(2), sub.next())
            .await
            .expect("no timeout")
            .expect("event");
        assert_eq!(ev.name, "pg");
        assert_eq!(ev.kind, BindingChangeKind::Deleted);
    }

    #[tokio::test]
    async fn refuses_wrong_version() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = store_path(&dir);
        tokio::fs::write(&path, br#"{"version": "v0", "entries": {}}"#)
            .await
            .expect("seed file");
        let err = EmbeddedMetaStore::open(&path, "default")
            .await
            .expect_err("must refuse");
        assert!(matches!(
            err,
            CatalogServiceError::SchemaVersionMismatch { .. }
        ));
    }

    #[tokio::test]
    async fn secret_put_get_overwrite_delete() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = EmbeddedMetaStore::open(store_path(&dir), "default")
            .await
            .expect("open");

        // Absent → None; listing empty.
        assert!(store
            .get_secret("default", "pw")
            .await
            .expect("get")
            .is_none());
        assert!(store
            .list_secret_names("default")
            .await
            .expect("list")
            .is_empty());

        // Put + read back the exact ciphertext bytes.
        store
            .put_secret("default", "pw", b"cipher-1")
            .await
            .expect("put");
        assert_eq!(
            store.get_secret("default", "pw").await.expect("get"),
            Some(b"cipher-1".to_vec())
        );

        // Overwrite.
        store
            .put_secret("default", "pw", b"cipher-2")
            .await
            .expect("put");
        assert_eq!(
            store.get_secret("default", "pw").await.expect("get"),
            Some(b"cipher-2".to_vec())
        );

        // A second secret; listing is sorted by name.
        store
            .put_secret("default", "api", b"cipher-3")
            .await
            .expect("put");
        assert_eq!(
            store.list_secret_names("default").await.expect("list"),
            vec!["api".to_string(), "pw".to_string()]
        );

        // Delete reports existence; a second delete is false.
        assert!(store.delete_secret("default", "pw").await.expect("delete"));
        assert!(!store
            .delete_secret("default", "pw")
            .await
            .expect("delete again"));
        assert!(store
            .get_secret("default", "pw")
            .await
            .expect("get")
            .is_none());
    }

    #[tokio::test]
    async fn secrets_persist_across_reopen_and_coexist_with_bindings() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = store_path(&dir);
        {
            let store = EmbeddedMetaStore::open(&path, "default")
                .await
                .expect("open");
            store
                .upsert_binding("default", "pg", &pg_binding("host"))
                .await
                .expect("upsert");
            store
                .put_secret("default", "pw", b"\x00\x01\xffbytes")
                .await
                .expect("put");
        }
        // Reopen: both the binding and the secret survive the round-trip.
        let store = EmbeddedMetaStore::open(&path, "default")
            .await
            .expect("reopen");
        assert_eq!(store.list_bindings("default").await.expect("list").len(), 1);
        assert_eq!(
            store.get_secret("default", "pw").await.expect("get"),
            Some(b"\x00\x01\xffbytes".to_vec())
        );
    }

    /// A legacy `v1` (flat, single-org) document migrates on open into org
    /// `"default"` — existing embedded stores keep working after the bump.
    #[tokio::test]
    async fn v1_file_migrates_into_default_org() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = store_path(&dir);
        // Seed a hand-written v1 document: flat `entries` + `secrets`, no
        // `orgs`. `ciphertext` is a JSON array of bytes (serde's Vec<u8> shape).
        let v1 = serde_json::json!({
            "version": "v1",
            "org_id": "default",
            "entries": {
                "pg": {
                    "binding": pg_binding("host-a"),
                    "source_config": {"kind": "postgres", "dsn_env": "PG"}
                }
            },
            "secrets": { "pw": b"cipher-1".to_vec() }
        });
        tokio::fs::write(&path, serde_json::to_vec(&v1).expect("serialize v1"))
            .await
            .expect("seed v1 file");

        let store = EmbeddedMetaStore::open(&path, "default")
            .await
            .expect("open migrates v1");

        // The flat data now lives under org "default".
        let bindings = store.list_bindings("default").await.expect("list");
        assert_eq!(bindings.get("pg"), Some(&pg_binding("host-a")));
        assert_eq!(
            store.list_source_configs("default").await.expect("list")["pg"]["dsn_env"],
            "PG"
        );
        assert_eq!(
            store.get_secret("default", "pw").await.expect("get"),
            Some(b"cipher-1".to_vec())
        );

        // Re-persist rewrites the file at v2; a reopen loads it as-is (no
        // second migration) and still sees the data.
        store
            .upsert_binding("default", "pg2", &pg_binding("host-b"))
            .await
            .expect("upsert bumps file to v2");
        let reopened = EmbeddedMetaStore::open(&path, "default")
            .await
            .expect("reopen v2");
        assert_eq!(
            reopened.list_bindings("default").await.expect("list").len(),
            2
        );
    }

    #[tokio::test]
    async fn user_put_get_overwrite_delete_and_list_omits_hash() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = EmbeddedMetaStore::open(store_path(&dir), "default")
            .await
            .expect("open");

        // Absent → None; empty listing.
        assert!(store
            .get_user("default", "alice")
            .await
            .expect("get")
            .is_none());
        assert!(store.list_users("default").await.expect("list").is_empty());

        // Put with a hash + superuser; read back the record AND the hash.
        store
            .put_user("default", "alice", Some("hash-1"), true)
            .await
            .expect("put");
        let (record, hash) = store
            .get_user("default", "alice")
            .await
            .expect("get")
            .expect("present");
        assert_eq!(
            record,
            UserRecord {
                name: "alice".to_string(),
                is_superuser: true,
            }
        );
        assert_eq!(hash, Some("hash-1".to_string()));

        // Overwrite: new hash, clear superuser.
        store
            .put_user("default", "alice", Some("hash-2"), false)
            .await
            .expect("overwrite");
        let (record, hash) = store
            .get_user("default", "alice")
            .await
            .expect("get")
            .expect("present");
        assert!(!record.is_superuser);
        assert_eq!(hash, Some("hash-2".to_string()));

        // A passwordless user stores None for the hash.
        store
            .put_user("default", "svc", None, false)
            .await
            .expect("put passwordless");
        let (_, hash) = store
            .get_user("default", "svc")
            .await
            .expect("get")
            .expect("present");
        assert!(hash.is_none());

        // Listing is sorted by name and NEVER carries the hash (rule 12).
        let users = store.list_users("default").await.expect("list");
        assert_eq!(
            users,
            vec![
                UserRecord {
                    name: "alice".to_string(),
                    is_superuser: false,
                },
                UserRecord {
                    name: "svc".to_string(),
                    is_superuser: false,
                },
            ]
        );

        // Delete reports existence; a second delete is false.
        assert!(store.delete_user("default", "alice").await.expect("delete"));
        assert!(!store
            .delete_user("default", "alice")
            .await
            .expect("delete again"));
        assert!(store
            .get_user("default", "alice")
            .await
            .expect("get")
            .is_none());
    }

    #[tokio::test]
    async fn role_crud() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = EmbeddedMetaStore::open(store_path(&dir), "default")
            .await
            .expect("open");

        assert!(store.list_roles("default").await.expect("list").is_empty());

        store.put_role("default", "analyst").await.expect("put");
        // Idempotent upsert.
        store
            .put_role("default", "analyst")
            .await
            .expect("put again");
        store.put_role("default", "admin").await.expect("put");

        // Sorted.
        assert_eq!(
            store.list_roles("default").await.expect("list"),
            vec!["admin".to_string(), "analyst".to_string()]
        );

        assert!(store
            .delete_role("default", "analyst")
            .await
            .expect("delete"));
        assert!(!store
            .delete_role("default", "analyst")
            .await
            .expect("delete again"));
        assert_eq!(
            store.list_roles("default").await.expect("list"),
            vec!["admin".to_string()]
        );
    }

    #[tokio::test]
    async fn users_and_roles_survive_reopen() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = store_path(&dir);
        {
            let store = EmbeddedMetaStore::open(&path, "default")
                .await
                .expect("open");
            store
                .put_user("default", "alice", Some("hash-1"), true)
                .await
                .expect("put user");
            store
                .put_role("default", "analyst")
                .await
                .expect("put role");
        }
        let reopened = EmbeddedMetaStore::open(&path, "default")
            .await
            .expect("reopen");
        let (record, hash) = reopened
            .get_user("default", "alice")
            .await
            .expect("get")
            .expect("present");
        assert!(record.is_superuser);
        assert_eq!(hash, Some("hash-1".to_string()));
        assert_eq!(
            reopened.list_roles("default").await.expect("list"),
            vec!["analyst".to_string()]
        );
    }

    /// Org isolation for users/roles: a user under org "a" is invisible under
    /// org "b" ( M1 multi-tenancy).
    #[tokio::test]
    async fn org_isolation_users_and_roles() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = EmbeddedMetaStore::open(store_path(&dir), "default")
            .await
            .expect("open");

        store
            .put_user("a", "alice", Some("hash-a"), true)
            .await
            .expect("put a");
        store.put_role("a", "analyst").await.expect("role a");

        // Org "a" sees them.
        assert!(store.get_user("a", "alice").await.expect("get a").is_some());
        assert_eq!(store.list_users("a").await.expect("list a").len(), 1);
        assert_eq!(store.list_roles("a").await.expect("roles a").len(), 1);

        // Org "b" sees nothing.
        assert!(store.get_user("b", "alice").await.expect("get b").is_none());
        assert!(store.list_users("b").await.expect("list b").is_empty());
        assert!(store.list_roles("b").await.expect("roles b").is_empty());

        // A same-named user under "b" doesn't disturb "a"'s record/hash.
        store
            .put_user("b", "alice", Some("hash-b"), false)
            .await
            .expect("put b");
        let (_, hash_a) = store
            .get_user("a", "alice")
            .await
            .expect("get a")
            .expect("present");
        assert_eq!(hash_a, Some("hash-a".to_string()));
    }

    /// Cross-org user lookup: a user in a non-default org is found
    /// with the right org + hash; an absent name is `None`; and a defensive
    /// same-name collision across two orgs resolves deterministically to the
    /// lowest org name.
    #[tokio::test]
    async fn find_user_resolves_org_across_orgs() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = EmbeddedMetaStore::open(store_path(&dir), "default")
            .await
            .expect("open");

        // A user created only in a NON-default org is still found, with that
        // org and its opaque hash.
        store
            .put_user("acme", "alice", Some("hash-acme"), true)
            .await
            .expect("put");
        let (org, record, hash) = store
            .find_user("alice")
            .await
            .expect("find")
            .expect("present");
        assert_eq!(org, "acme");
        assert_eq!(
            record,
            UserRecord {
                name: "alice".to_string(),
                is_superuser: true,
            }
        );
        assert_eq!(hash, Some("hash-acme".to_string()));

        // Absent name → None.
        assert!(store.find_user("ghost").await.expect("find").is_none());

        // Defensive: the same name in two orgs resolves to the lowest org
        // name ("acme" < "zeta"), deterministically.
        store
            .put_user("zeta", "alice", Some("hash-zeta"), false)
            .await
            .expect("put zeta");
        let (org, _record, hash) = store
            .find_user("alice")
            .await
            .expect("find")
            .expect("present");
        assert_eq!(org, "acme");
        assert_eq!(hash, Some("hash-acme".to_string()));
    }

    #[tokio::test]
    async fn policy_put_get_overwrite_delete_and_list() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = EmbeddedMetaStore::open(store_path(&dir), "default")
            .await
            .expect("open");

        // Absent → None; empty listing.
        assert!(store
            .get_policy("default", "m")
            .await
            .expect("get")
            .is_none());
        assert!(store
            .list_policies("default")
            .await
            .expect("list")
            .is_empty());

        // Put a mask rule; read back the exact (kind, rule).
        let mask_rule = serde_json::json!({
            "table": "users", "column": "email", "mask_literal": "***"
        });
        store
            .put_policy("default", "email_mask", "mask", &mask_rule)
            .await
            .expect("put");
        assert_eq!(
            store
                .get_policy("default", "email_mask")
                .await
                .expect("get"),
            Some(("mask".to_string(), mask_rule.clone()))
        );

        // Overwrite: new kind + rule body.
        let filter_rule = serde_json::json!({
            "table": "users", "predicate": {"kind": "sql", "sql": "active"}
        });
        store
            .put_policy("default", "email_mask", "row_filter", &filter_rule)
            .await
            .expect("overwrite");
        assert_eq!(
            store
                .get_policy("default", "email_mask")
                .await
                .expect("get"),
            Some(("row_filter".to_string(), filter_rule.clone()))
        );

        // A second policy; listing is sorted by name and carries name + kind
        // only (no rule body).
        store
            .put_policy("default", "acme_rows", "row_filter", &filter_rule)
            .await
            .expect("put second");
        assert_eq!(
            store.list_policies("default").await.expect("list"),
            vec![
                PolicyRecord {
                    name: "acme_rows".to_string(),
                    kind: "row_filter".to_string(),
                },
                PolicyRecord {
                    name: "email_mask".to_string(),
                    kind: "row_filter".to_string(),
                },
            ]
        );

        // Delete reports existence; a second delete is false.
        assert!(store
            .delete_policy("default", "email_mask")
            .await
            .expect("delete"));
        assert!(!store
            .delete_policy("default", "email_mask")
            .await
            .expect("delete again"));
        assert!(store
            .get_policy("default", "email_mask")
            .await
            .expect("get")
            .is_none());
    }

    /// `list_orgs` returns every org the store knows, sorted —
    /// the set the boot path replays per-org policies for.
    #[tokio::test]
    async fn list_orgs_returns_every_org_sorted() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = EmbeddedMetaStore::open(store_path(&dir), "default")
            .await
            .expect("open");

        // A fresh store knows no orgs until something is written.
        assert!(store.list_orgs().await.expect("list").is_empty());

        // Writing a policy under several orgs makes them appear, sorted.
        let rule = serde_json::json!({"table": "t", "column": "c", "mask_literal": "x"});
        store
            .put_policy("beta", "m", "mask", &rule)
            .await
            .expect("put beta");
        store
            .put_policy("acme", "m", "mask", &rule)
            .await
            .expect("put acme");
        assert_eq!(store.list_orgs().await.expect("list"), vec!["acme", "beta"]);
    }

    /// Policies survive a reopen and are org-isolated ( M4a + M1).
    #[tokio::test]
    async fn policies_persist_across_reopen_and_are_org_isolated() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = store_path(&dir);
        let rule = serde_json::json!({"table": "t", "column": "c", "mask_literal": "x"});
        {
            let store = EmbeddedMetaStore::open(&path, "default")
                .await
                .expect("open");
            store
                .put_policy("a", "m", "mask", &rule)
                .await
                .expect("put a");
        }
        let reopened = EmbeddedMetaStore::open(&path, "default")
            .await
            .expect("reopen");
        // Org "a" sees it after the round-trip.
        assert_eq!(
            reopened.get_policy("a", "m").await.expect("get a"),
            Some(("mask".to_string(), rule))
        );
        // Org "b" sees nothing — fully isolated.
        assert!(reopened
            .get_policy("b", "m")
            .await
            .expect("get b")
            .is_none());
        assert!(reopened
            .list_policies("b")
            .await
            .expect("list b")
            .is_empty());
    }

    /// Grant round-trip: put/list/delete, idempotent upsert, and
    /// the typed SELECT-on-table vs USAGE-on-catalog pairing survive.
    #[tokio::test]
    async fn grant_put_list_delete_and_idempotent_upsert() {
        use crate::store::{GrantObject, GranteeKind, Privilege};

        let dir = tempfile::tempdir().expect("tempdir");
        let store = EmbeddedMetaStore::open(store_path(&dir), "default")
            .await
            .expect("open");

        assert!(store.list_grants("default").await.expect("list").is_empty());

        let select = GrantRecord::select(GranteeKind::User, "alice", "pg", "public", "orders");
        let usage = GrantRecord::usage(GranteeKind::Role, "analyst", "pg");
        store
            .put_grant("default", &select)
            .await
            .expect("put select");
        store.put_grant("default", &usage).await.expect("put usage");
        // Idempotent upsert: a re-put of an identical grant does not duplicate.
        store
            .put_grant("default", &select)
            .await
            .expect("re-put select");

        let grants = store.list_grants("default").await.expect("list");
        assert_eq!(grants.len(), 2);
        assert!(grants.contains(&select));
        assert!(grants.contains(&usage));
        // The typed pairing round-trips.
        assert_eq!(select.privilege(), Privilege::Select);
        assert_eq!(
            select.object(),
            GrantObject::Table {
                catalog: "pg".into(),
                schema: "public".into(),
                table: "orders".into(),
            }
        );
        assert_eq!(usage.privilege(), Privilege::Usage);
        assert_eq!(usage.object(), GrantObject::Catalog("pg".into()));

        // Delete reports existence; a second delete is false.
        assert!(store.delete_grant("default", &select).await.expect("del"));
        assert!(!store
            .delete_grant("default", &select)
            .await
            .expect("del again"));
        assert_eq!(store.list_grants("default").await.expect("list").len(), 1);
    }

    /// Role membership round-trip: add/remove/list, idempotent,
    /// and both directions of lookup.
    #[tokio::test]
    async fn role_membership_add_remove_list() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = EmbeddedMetaStore::open(store_path(&dir), "default")
            .await
            .expect("open");

        assert!(store
            .list_roles_for_user("default", "alice")
            .await
            .expect("list")
            .is_empty());

        store
            .add_role_member("default", "analyst", "alice")
            .await
            .expect("add");
        // Idempotent.
        store
            .add_role_member("default", "analyst", "alice")
            .await
            .expect("add again");
        store
            .add_role_member("default", "admin", "alice")
            .await
            .expect("add");
        store
            .add_role_member("default", "analyst", "bob")
            .await
            .expect("add");

        // Sorted roles for alice.
        assert_eq!(
            store
                .list_roles_for_user("default", "alice")
                .await
                .expect("roles"),
            vec!["admin".to_string(), "analyst".to_string()]
        );
        // Sorted members of analyst.
        assert_eq!(
            store
                .list_role_members("default", "analyst")
                .await
                .expect("members"),
            vec!["alice".to_string(), "bob".to_string()]
        );

        // Remove reports existence; a second remove is false.
        assert!(store
            .remove_role_member("default", "analyst", "alice")
            .await
            .expect("remove"));
        assert!(!store
            .remove_role_member("default", "analyst", "alice")
            .await
            .expect("remove again"));
        assert_eq!(
            store
                .list_roles_for_user("default", "alice")
                .await
                .expect("roles"),
            vec!["admin".to_string()]
        );
    }

    /// Grants + memberships survive a reopen and are org-isolated.
    #[tokio::test]
    async fn grants_and_memberships_persist_and_are_org_isolated() {
        use crate::store::GranteeKind;

        let dir = tempfile::tempdir().expect("tempdir");
        let path = store_path(&dir);
        let grant = GrantRecord::select(GranteeKind::User, "alice", "pg", "public", "t");
        {
            let store = EmbeddedMetaStore::open(&path, "default")
                .await
                .expect("open");
            store.put_grant("acme", &grant).await.expect("put");
            store
                .add_role_member("acme", "analyst", "alice")
                .await
                .expect("add");
        }
        let reopened = EmbeddedMetaStore::open(&path, "default")
            .await
            .expect("reopen");
        // Org "acme" sees them after the round-trip.
        assert_eq!(
            reopened.list_grants("acme").await.expect("list"),
            vec![grant]
        );
        assert_eq!(
            reopened
                .list_roles_for_user("acme", "alice")
                .await
                .expect("roles"),
            vec!["analyst".to_string()]
        );
        // Org "beta" sees nothing — fully isolated.
        assert!(reopened.list_grants("beta").await.expect("list").is_empty());
        assert!(reopened
            .list_roles_for_user("beta", "alice")
            .await
            .expect("roles")
            .is_empty());
    }

    /// Derived products round-trip through a reopen, replace
    /// idempotently by name, and are org-isolated.
    #[tokio::test]
    async fn derived_products_round_trip_replace_and_org_isolation() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = store_path(&dir);
        let v = DerivedProductRecord {
            name: "active_users".to_string(),
            sql: "SELECT id, email FROM users WHERE active".to_string(),
            catalog: Some("pg".to_string()),
            schema: Some("public".to_string()),
        };
        {
            let store = EmbeddedMetaStore::open(&path, "default")
                .await
                .expect("open");
            store.put_derived_product("acme", &v).await.expect("put");
            // Idempotent replace by name: a second put with new SQL overwrites,
            // it does not accumulate a second entry.
            let replaced = DerivedProductRecord {
                sql: "SELECT id FROM users".to_string(),
                catalog: None,
                schema: None,
                ..v.clone()
            };
            store
                .put_derived_product("acme", &replaced)
                .await
                .expect("replace");
            assert_eq!(
                store
                    .list_derived_products("acme")
                    .await
                    .expect("list")
                    .len(),
                1,
                "OR REPLACE replaces in place"
            );
        }
        // Survives a reopen.
        let reopened = EmbeddedMetaStore::open(&path, "default")
            .await
            .expect("reopen");
        let got = reopened
            .get_derived_product("acme", "active_users")
            .await
            .expect("get")
            .expect("present");
        assert_eq!(got.sql, "SELECT id FROM users");
        assert_eq!(got.catalog, None);
        // Org "beta" sees nothing — fully isolated.
        assert!(reopened
            .list_derived_products("beta")
            .await
            .expect("list")
            .is_empty());
        assert!(reopened
            .get_derived_product("beta", "active_users")
            .await
            .expect("get")
            .is_none());
        // Delete reports existence; a second delete is false.
        assert!(reopened
            .delete_derived_product("acme", "active_users")
            .await
            .expect("delete"));
        assert!(!reopened
            .delete_derived_product("acme", "active_users")
            .await
            .expect("delete again"));
        assert!(reopened
            .list_derived_products("acme")
            .await
            .expect("list")
            .is_empty());
    }

    /// Org isolation: writes under org "a" are invisible under org "b", for
    /// both bindings and secrets. One store instance, two tenants.
    #[tokio::test]
    async fn org_isolation_bindings_and_secrets() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = EmbeddedMetaStore::open(store_path(&dir), "default")
            .await
            .expect("open");

        // Write a binding + a secret under org "a" only.
        store
            .upsert_binding("a", "pg", &pg_binding("host-a"))
            .await
            .expect("upsert a");
        store
            .put_secret("a", "pw", b"secret-a")
            .await
            .expect("put a");

        // Org "a" sees them.
        assert_eq!(
            store.list_bindings("a").await.expect("list a").get("pg"),
            Some(&pg_binding("host-a"))
        );
        assert_eq!(
            store.get_secret("a", "pw").await.expect("get a"),
            Some(b"secret-a".to_vec())
        );

        // Org "b" sees nothing — fully isolated.
        assert!(store.list_bindings("b").await.expect("list b").is_empty());
        assert!(store.get_secret("b", "pw").await.expect("get b").is_none());
        assert!(store
            .list_secret_names("b")
            .await
            .expect("names b")
            .is_empty());

        // A same-named write under "b" doesn't disturb "a".
        store
            .upsert_binding("b", "pg", &pg_binding("host-b"))
            .await
            .expect("upsert b");
        store
            .put_secret("b", "pw", b"secret-b")
            .await
            .expect("put b");
        assert_eq!(
            store.list_bindings("a").await.expect("list a").get("pg"),
            Some(&pg_binding("host-a"))
        );
        assert_eq!(
            store.get_secret("a", "pw").await.expect("get a"),
            Some(b"secret-a".to_vec())
        );
        assert_eq!(
            store.get_secret("b", "pw").await.expect("get b"),
            Some(b"secret-b".to_vec())
        );

        // Deleting under "b" leaves "a" intact.
        assert!(store.delete_binding("b", "pg").await.expect("del b"));
        assert_eq!(
            store.list_bindings("a").await.expect("list a").get("pg"),
            Some(&pg_binding("host-a"))
        );
    }
}

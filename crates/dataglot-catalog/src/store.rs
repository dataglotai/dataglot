//! The [`MetaStore`] trait — the backend-agnostic control-plane store.
//!
//! Spec: `docs/phases/phase-6/01-sql-native-runtime-config.md` (slice A).
//!
//! The meta store is the source of truth for catalog **bindings** and
//! their credential-free **source configs**, plus a change feed the read
//! cache subscribes to. Two impls:
//!
//! - [`crate::CatalogService`] — Postgres-backed, for HA / multi-node.
//! - [`crate::EmbeddedMetaStore`] — pure-Rust atomic-file store, the
//!   zero-external-dependency single-binary default.
//!
//! Object-safe (via `async_trait`) so the server can hold
//! `Arc<dyn MetaStore>` and pick the backend by config without threading
//! a generic through every boot helper.

use std::collections::HashMap;

use async_trait::async_trait;
use dataglot_core::CatalogBinding;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::subscribe::BindingChangeStream;
use crate::Result;

/// A stored user, **without** its password hash. This is the shape returned by
/// [`MetaStore::list_users`] — the opaque password hash is deliberately absent
/// so it can never leak through a listing (CLAUDE.md rule 12). The hash is
/// retrievable only via [`MetaStore::get_user`], for M3b's auth path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserRecord {
    /// User name (org-scoped; unique within an org).
    pub name: String,
    /// Whether the user is a superuser.
    pub is_superuser: bool,
}

/// A stored governance policy's identity — its name and kind. This is the
/// shape returned by [`MetaStore::list_policies`]; the serialized
/// rule body is deliberately absent from a listing (fetch it with
/// [`MetaStore::get_policy`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyRecord {
    /// Policy name (org-scoped; unique within an org).
    pub name: String,
    /// Policy kind — `"mask"` or `"row_filter"`.
    pub kind: String,
}

/// Who a privilege is granted to. Both a user and a role are just
/// **names** in a given org; which one a name resolves to is decided at
/// enforcement time (F5b), so F5a stores the kind alongside the name without
/// requiring the user/role to pre-exist.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GranteeKind {
    /// The grantee is a user.
    User,
    /// The grantee is a role.
    Role,
}

impl GranteeKind {
    /// Stable lowercase token used in the Postgres backend and DDL.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Role => "role",
        }
    }

    /// Parse the token produced by [`GranteeKind::as_str`], or `None`. Named
    /// `from_token` (not `from_str`) to avoid colliding with
    /// [`std::str::FromStr`].
    #[must_use]
    pub fn from_token(s: &str) -> Option<Self> {
        match s {
            "user" => Some(Self::User),
            "role" => Some(Self::Role),
            _ => None,
        }
    }
}

/// A grantable privilege. v1 ships `SELECT` (on a table) and
/// `USAGE` (on a catalog); the enum has room to grow (`INSERT` / `CREATE` …)
/// without a storage migration. The privilege↔object pairing is enforced by
/// [`GrantRecord`]'s constructors, so an invalid combo (e.g. `USAGE` on a table)
/// can never be built or stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Privilege {
    /// `SELECT` — read a table. Pairs with [`GrantObject::Table`].
    Select,
    /// `USAGE` — reference a catalog. Pairs with [`GrantObject::Catalog`].
    Usage,
}

impl Privilege {
    /// Stable uppercase SQL token (`SELECT` / `USAGE`), used in the Postgres
    /// backend and command tags.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Select => "SELECT",
            Self::Usage => "USAGE",
        }
    }
}

/// The object a privilege is granted on. `USAGE` is granted on a
/// whole [`Catalog`](GrantObject::Catalog); `SELECT` on a fully-qualified
/// [`Table`](GrantObject::Table) (`catalog.schema.table`).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum GrantObject {
    /// A whole catalog — the object of `USAGE`.
    Catalog(String),
    /// A fully-qualified `catalog.schema.table` — the object of `SELECT`.
    Table {
        /// Catalog part.
        catalog: String,
        /// Schema part.
        schema: String,
        /// Table part.
        table: String,
    },
}

/// The privilege + object of a grant, coupled so an invalid pairing is
/// *unrepresentable*. This is the internal, serde-stable shape of
/// a [`GrantRecord`]; construct one only through [`GrantRecord::select`] /
/// [`GrantRecord::usage`] and read it back via [`GrantRecord::privilege`] /
/// [`GrantRecord::object`].
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "privilege", rename_all = "snake_case")]
enum GrantOn {
    /// `SELECT` on a fully-qualified table.
    Select {
        catalog: String,
        schema: String,
        table: String,
    },
    /// `USAGE` on a catalog.
    Usage { catalog: String },
}

/// A stored grant: a `(grantee_kind, grantee, privilege, object)`
/// tuple, org-scoped like every other control-plane record. The
/// privilege↔object pairing is coupled internally so an invalid combination
/// (`USAGE` on a table, `SELECT` on a catalog) can never be constructed or
/// persisted — build one with [`GrantRecord::select`] or [`GrantRecord::usage`].
///
/// F5a **stores** grants but does not enforce them (that is F5b); nothing here
/// changes query behaviour.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct GrantRecord {
    /// Whether the grantee is a user or a role.
    pub grantee_kind: GranteeKind,
    /// The grantee's name (org-scoped; not required to pre-exist in F5a).
    pub grantee: String,
    /// The coupled privilege + object (private so the pairing invariant holds).
    on: GrantOn,
}

impl GrantRecord {
    /// A `SELECT` grant on a fully-qualified `catalog.schema.table`.
    pub fn select(
        grantee_kind: GranteeKind,
        grantee: impl Into<String>,
        catalog: impl Into<String>,
        schema: impl Into<String>,
        table: impl Into<String>,
    ) -> Self {
        Self {
            grantee_kind,
            grantee: grantee.into(),
            on: GrantOn::Select {
                catalog: catalog.into(),
                schema: schema.into(),
                table: table.into(),
            },
        }
    }

    /// A `USAGE` grant on a whole catalog.
    pub fn usage(
        grantee_kind: GranteeKind,
        grantee: impl Into<String>,
        catalog: impl Into<String>,
    ) -> Self {
        Self {
            grantee_kind,
            grantee: grantee.into(),
            on: GrantOn::Usage {
                catalog: catalog.into(),
            },
        }
    }

    /// The privilege this grant confers.
    #[must_use]
    pub fn privilege(&self) -> Privilege {
        match self.on {
            GrantOn::Select { .. } => Privilege::Select,
            GrantOn::Usage { .. } => Privilege::Usage,
        }
    }

    /// The object this grant is scoped to (owned; clones the names).
    #[must_use]
    pub fn object(&self) -> GrantObject {
        match &self.on {
            GrantOn::Select {
                catalog,
                schema,
                table,
            } => GrantObject::Table {
                catalog: catalog.clone(),
                schema: schema.clone(),
                table: table.clone(),
            },
            GrantOn::Usage { catalog } => GrantObject::Catalog(catalog.clone()),
        }
    }
}

/// A stored derived data product — a runtime `CREATE VIEW` mapped
/// to Dataglot's derived-product concept. Org-scoped like every other
/// control-plane record. Holds the view's defining SQL **verbatim** (captured
/// from the statement's `AS <query>` body) plus the optional
/// `catalog`/`schema` the product resolves under; absent parts default to the
/// server's `default_catalog`/`default_schema` when the product is registered.
///
/// The store persists this verbatim and never interprets the `sql` (rule 4 —
/// the crate can't depend on `dataglot-server`'s planner), exactly like
/// `source_config` for catalogs and `rule` for policies. Plain
/// (non-materialized) views only in v1; a materialization backing is a future
/// follow-up and is not represented here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DerivedProductRecord {
    /// Product / view name (org-scoped; unique within an org). This is the name
    /// the view is referenced by at query time.
    pub name: String,
    /// The defining query — the verbatim `AS <query>` body of `CREATE VIEW`.
    pub sql: String,
    /// Catalog the product resolves under; `None` ⇒ the server default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub catalog: Option<String>,
    /// Schema the product resolves under; `None` ⇒ the server default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,
}

/// A durable, subscribable store for catalog bindings + source configs.
///
/// Method contracts mirror the read/write surface the server boot path
/// and (later slices) runtime SQL DDL need. Credential **values** never
/// cross this boundary — `source_config` carries `*_env` names only
/// (CLAUDE.md rule 12); the store persists and returns them verbatim.
///
/// The store is **org-parameterized** (multi-tenant foundation,
/// M1): one instance serves every org, and each data method takes the
/// target `org` as its first argument. Reads on an org with no data
/// return empty; writes implicitly scope to (and, for the Postgres
/// backend, ensure) the named org. [`subscribe`](Self::subscribe) stays
/// org-**wide** — the emitted [`crate::BindingChange`] carries its own
/// `org_id`, so a consumer filters by org itself.
#[async_trait]
pub trait MetaStore: Send + Sync + std::fmt::Debug {
    /// Every stored source config **for `org`**, as `name -> serialized
    /// CatalogConfig` JSON, for the entries that carry one. This is the
    /// boot-time "source of truth" read; the caller deserializes each
    /// `Value` into its own `CatalogConfig` (the store can't depend on
    /// `dataglot-server`, rule 4).
    ///
    /// # Errors
    /// Backend IO / query failure, or a corrupt on-disk document.
    async fn list_source_configs(&self, org: &str) -> Result<HashMap<String, Value>>;

    /// Every binding **for `org`**, as `name -> CatalogBinding`.
    ///
    /// # Errors
    /// Backend IO / query failure, or a binding that fails to decode.
    async fn list_bindings(&self, org: &str) -> Result<HashMap<String, CatalogBinding>>;

    /// Upsert a binding **under `org`**; returns the previous value if the
    /// name existed. Fires a `BindingChange { kind: Upserted }` (carrying
    /// `org`) to subscribers.
    ///
    /// # Errors
    /// Serialization or backend IO / query failure.
    async fn upsert_binding(
        &self,
        org: &str,
        name: &str,
        binding: &CatalogBinding,
    ) -> Result<Option<CatalogBinding>>;

    /// Attach (or overwrite) the credential-free source config for an
    /// existing binding **under `org`**. A no-op if the name has no binding
    /// in that org.
    ///
    /// # Errors
    /// Backend IO / query failure.
    async fn set_source_config(&self, org: &str, name: &str, source_config: &Value) -> Result<()>;

    /// Remove a binding (and its source config) **under `org`**. Returns
    /// `true` if a row existed. Fires a `BindingChange { kind: Deleted }`
    /// (carrying `org`).
    ///
    /// # Errors
    /// Backend IO / query failure.
    async fn delete_binding(&self, org: &str, name: &str) -> Result<bool>;

    /// Store (or overwrite) a secret's **already-encrypted** bytes by name,
    /// **under `org`**. The store never sees plaintext —
    /// encryption happens in the caller (`dataglot-server`, which owns the
    /// envelope key), so this crate stays credential-agnostic (rule 12).
    /// Secrets are a namespace separate from catalog bindings and do not
    /// emit a [`crate::BindingChange`].
    ///
    /// # Errors
    /// Backend IO / query failure.
    async fn put_secret(&self, org: &str, name: &str, ciphertext: &[u8]) -> Result<()>;

    /// Fetch a secret's ciphertext **for `org`**, or `None` if no such
    /// secret exists.
    ///
    /// # Errors
    /// Backend IO / query failure.
    async fn get_secret(&self, org: &str, name: &str) -> Result<Option<Vec<u8>>>;

    /// Remove a secret **under `org`**; returns `true` if one existed.
    ///
    /// # Errors
    /// Backend IO / query failure.
    async fn delete_secret(&self, org: &str, name: &str) -> Result<bool>;

    /// List secret **names** (never values) **for `org`**, sorted.
    ///
    /// # Errors
    /// Backend IO / query failure.
    async fn list_secret_names(&self, org: &str) -> Result<Vec<String>>;

    /// Upsert a user **under `org`**. `password_hash` is an
    /// **opaque, already-hashed** string — hashing happens in the caller
    /// (`dataglot-server`, M3b), so this crate never sees plaintext (rule 12);
    /// `None` means the user has no password and cannot log in with one.
    /// `is_superuser` records the privilege flag. Users are a namespace
    /// separate from catalog bindings and do not emit a [`crate::BindingChange`].
    ///
    /// # Errors
    /// Backend IO / query failure.
    async fn put_user(
        &self,
        org: &str,
        name: &str,
        password_hash: Option<&str>,
        is_superuser: bool,
    ) -> Result<()>;

    /// Fetch a user **for `org`** as its [`UserRecord`] plus its opaque
    /// password hash (the inner `Option` is `None` when the user has no
    /// password). Returns `None` if no such user exists. This is the **only**
    /// method that exposes the hash — for M3b's auth path; it never appears in
    /// [`list_users`](Self::list_users) (rule 12).
    ///
    /// # Errors
    /// Backend IO / query failure.
    async fn get_user(&self, org: &str, name: &str)
        -> Result<Option<(UserRecord, Option<String>)>>;

    /// Find a user by name **across all orgs** ( F3, global-unique
    /// usernames). Scans orgs in deterministic order and returns the **first**
    /// match as `(org, UserRecord, opaque password hash)` — the org that owns
    /// the name (so the md5 auth path resolves a connection's tenant in a
    /// single call) plus the hash, exactly like [`get_user`](Self::get_user)
    /// (the inner `Option` is `None` for a passwordless user). `None` when no
    /// org holds the name.
    ///
    /// Usernames are globally unique by construction — `CREATE USER` rejects a
    /// name already taken in another org — so at most one org matches in
    /// practice. If two ever collide (a defensively tolerated corruption) the
    /// **lowest** org name wins, so the result is deterministic. Like
    /// [`get_user`](Self::get_user) this is one of only two methods that expose
    /// the hash; it never appears in [`list_users`](Self::list_users) (rule 12).
    ///
    /// # Errors
    /// Backend IO / query failure, or a corrupt on-disk document.
    async fn find_user(&self, name: &str) -> Result<Option<(String, UserRecord, Option<String>)>>;

    /// Remove a user **under `org`**; returns `true` if one existed.
    ///
    /// # Errors
    /// Backend IO / query failure.
    async fn delete_user(&self, org: &str, name: &str) -> Result<bool>;

    /// List users **for `org`** as [`UserRecord`]s (name + superuser flag),
    /// sorted by name. The password hash is **never** included (rule 12).
    ///
    /// # Errors
    /// Backend IO / query failure.
    async fn list_users(&self, org: &str) -> Result<Vec<UserRecord>>;

    /// Upsert a role **under `org`**. A role is a bare named
    /// grantable; it carries no password.
    ///
    /// # Errors
    /// Backend IO / query failure.
    async fn put_role(&self, org: &str, name: &str) -> Result<()>;

    /// Remove a role **under `org`**; returns `true` if one existed.
    ///
    /// # Errors
    /// Backend IO / query failure.
    async fn delete_role(&self, org: &str, name: &str) -> Result<bool>;

    /// List role **names** **for `org`**, sorted.
    ///
    /// # Errors
    /// Backend IO / query failure.
    async fn list_roles(&self, org: &str) -> Result<Vec<String>>;

    /// Upsert a governance policy **under `org`**. `kind` is
    /// `"mask"` or `"row_filter"`; `rule` is the serialized rule body — an
    /// opaque `serde_json::Value` shaped like the server's `MaskConfig` /
    /// `RowFilterConfig`. The store persists it verbatim and never interprets
    /// it, so this crate stays free of a `dataglot-server` dependency (rule 4),
    /// exactly like `source_config` for catalogs. Policies are a namespace
    /// separate from catalog bindings and do not emit a [`crate::BindingChange`].
    ///
    /// # Errors
    /// Backend IO / query failure.
    async fn put_policy(&self, org: &str, name: &str, kind: &str, rule: &Value) -> Result<()>;

    /// Fetch a policy **for `org`** as `(kind, serialized rule)`, or `None` if
    /// no such policy exists.
    ///
    /// # Errors
    /// Backend IO / query failure.
    async fn get_policy(&self, org: &str, name: &str) -> Result<Option<(String, Value)>>;

    /// Remove a policy **under `org`**; returns `true` if one existed.
    ///
    /// # Errors
    /// Backend IO / query failure.
    async fn delete_policy(&self, org: &str, name: &str) -> Result<bool>;

    /// List policies **for `org`** as [`PolicyRecord`]s (name + kind), sorted
    /// by name. The serialized rule body is **never** included — fetch it with
    /// [`get_policy`](Self::get_policy).
    ///
    /// # Errors
    /// Backend IO / query failure.
    async fn list_policies(&self, org: &str) -> Result<Vec<PolicyRecord>>;

    /// Upsert a grant **under `org`**. Idempotent — re-putting an
    /// identical `(grantee_kind, grantee, privilege, object)` is a no-op. F5a
    /// **stores** grants only; enforcement is F5b, so this changes no query
    /// behaviour. Grants are a namespace separate from catalog bindings and do
    /// not emit a [`crate::BindingChange`].
    ///
    /// # Errors
    /// Backend IO / query failure.
    async fn put_grant(&self, org: &str, grant: &GrantRecord) -> Result<()>;

    /// Remove a grant **under `org`**; returns `true` if one existed (matched on
    /// the full `(grantee_kind, grantee, privilege, object)` identity).
    ///
    /// # Errors
    /// Backend IO / query failure.
    async fn delete_grant(&self, org: &str, grant: &GrantRecord) -> Result<bool>;

    /// List every grant **for `org`**, in a deterministic order.
    ///
    /// # Errors
    /// Backend IO / query failure, or a corrupt on-disk document.
    async fn list_grants(&self, org: &str) -> Result<Vec<GrantRecord>>;

    /// Add a `role → user` membership **under `org`** ( F5a,
    /// `GRANT <role> TO <user>`). Idempotent — re-adding the same pair is a
    /// no-op. Neither the role nor the user is required to pre-exist (F5a stores
    /// the relation; resolution is F5b). Membership is a separate user↔role
    /// relation from M3a's role table.
    ///
    /// # Errors
    /// Backend IO / query failure.
    async fn add_role_member(&self, org: &str, role: &str, user: &str) -> Result<()>;

    /// Remove a `role → user` membership **under `org`**; returns `true` if one
    /// existed.
    ///
    /// # Errors
    /// Backend IO / query failure.
    async fn remove_role_member(&self, org: &str, role: &str, user: &str) -> Result<bool>;

    /// List the roles a `user` is a member of **for `org`**, sorted.
    ///
    /// # Errors
    /// Backend IO / query failure, or a corrupt on-disk document.
    async fn list_roles_for_user(&self, org: &str, user: &str) -> Result<Vec<String>>;

    /// List the users that are members of a `role` **for `org`**, sorted.
    ///
    /// # Errors
    /// Backend IO / query failure, or a corrupt on-disk document.
    async fn list_role_members(&self, org: &str, role: &str) -> Result<Vec<String>>;

    /// Upsert a derived product **under `org`**. Idempotent by
    /// `name` — used for both `CREATE VIEW` and `CREATE OR REPLACE VIEW`, so a
    /// re-put with the same name replaces the stored definition. The `sql` is
    /// persisted verbatim and never interpreted here (rule 4). Derived products
    /// are a namespace separate from catalog bindings and do not emit a
    /// [`crate::BindingChange`].
    ///
    /// # Errors
    /// Backend IO / query failure.
    async fn put_derived_product(&self, org: &str, product: &DerivedProductRecord) -> Result<()>;

    /// Fetch a derived product **for `org`** by name, or `None` if absent.
    ///
    /// # Errors
    /// Backend IO / query failure, or a corrupt on-disk document.
    async fn get_derived_product(
        &self,
        org: &str,
        name: &str,
    ) -> Result<Option<DerivedProductRecord>>;

    /// List every derived product **for `org`**, sorted by name. Unlike the
    /// policy / user listings this returns the full record (including `sql`),
    /// because the boot loader rebuilds each view from its SQL.
    ///
    /// # Errors
    /// Backend IO / query failure, or a corrupt on-disk document.
    async fn list_derived_products(&self, org: &str) -> Result<Vec<DerivedProductRecord>>;

    /// Remove a derived product **under `org`**; returns `true` if one existed.
    ///
    /// # Errors
    /// Backend IO / query failure.
    async fn delete_derived_product(&self, org: &str, name: &str) -> Result<bool>;

    /// Every org the boot path should replay persisted policies for
    ///, sorted. The server iterates this set to load each
    /// tenant's masks / row filters into the live rule store tagged with
    /// its org, so per-org enforcement is restored after a restart.
    ///
    /// A superset of "orgs with policies" is acceptable — the caller
    /// tolerates an org that turns out to have none (its policy list comes
    /// back empty). The embedded backend returns every org it knows (the
    /// orgs-map keys); the Postgres backend returns the distinct orgs
    /// present in the policy table.
    ///
    /// # Errors
    /// Backend IO / query failure, or a corrupt on-disk document.
    async fn list_orgs(&self) -> Result<Vec<String>>;

    /// Subscribe to the change feed. Every upsert/delete (including the
    /// caller's own) emits a [`crate::BindingChange`].
    ///
    /// # Errors
    /// Backend connect / subscribe failure.
    async fn subscribe(&self) -> Result<BindingChangeStream>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grantee_kind_token_round_trips() {
        assert_eq!(GranteeKind::User.as_str(), "user");
        assert_eq!(GranteeKind::Role.as_str(), "role");
        assert_eq!(GranteeKind::from_token("user"), Some(GranteeKind::User));
        assert_eq!(GranteeKind::from_token("role"), Some(GranteeKind::Role));
        assert_eq!(GranteeKind::from_token("nope"), None);
    }

    #[test]
    fn privilege_tokens_are_sql_uppercase() {
        assert_eq!(Privilege::Select.as_str(), "SELECT");
        assert_eq!(Privilege::Usage.as_str(), "USAGE");
    }

    #[test]
    fn grant_select_couples_privilege_with_table() {
        let g = GrantRecord::select(GranteeKind::User, "analyst", "pg", "public", "users");
        assert_eq!(g.privilege(), Privilege::Select);
        assert_eq!(
            g.object(),
            GrantObject::Table {
                catalog: "pg".into(),
                schema: "public".into(),
                table: "users".into(),
            }
        );
        assert_eq!(g.grantee, "analyst");
        assert_eq!(g.grantee_kind, GranteeKind::User);
    }

    #[test]
    fn grant_usage_couples_privilege_with_catalog() {
        let g = GrantRecord::usage(GranteeKind::Role, "reporting", "pg");
        assert_eq!(g.privilege(), Privilege::Usage);
        assert_eq!(g.object(), GrantObject::Catalog("pg".into()));
        assert_eq!(g.grantee_kind, GranteeKind::Role);
    }

    #[test]
    fn grant_record_serde_round_trips_both_shapes() {
        for g in [
            GrantRecord::select(GranteeKind::User, "analyst", "pg", "public", "users"),
            GrantRecord::usage(GranteeKind::Role, "reporting", "pg"),
        ] {
            let json = serde_json::to_string(&g).unwrap();
            let back: GrantRecord = serde_json::from_str(&json).unwrap();
            assert_eq!(g, back, "grant must survive a serde round-trip");
        }
        // The coupled privilege tag is stable + snake_case.
        let json =
            serde_json::to_string(&GrantRecord::usage(GranteeKind::Role, "r", "pg")).unwrap();
        assert!(json.contains("\"privilege\":\"usage\""), "got: {json}");
    }
}

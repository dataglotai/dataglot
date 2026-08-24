//! GRANT/REVOKE enforcement — deny-unless-granted access control
//!
//! F5a landed the GRANT/REVOKE *model* (typed privileges + a store); this
//! module is the *enforcement*. [`GrantEnforcer`] is a [`PolicyEnforcer`]
//! that, in **grant mode**, rejects a query at plan time unless the session
//! holds every privilege the query's table scans require. Like every other
//! Dataglot policy, enforcement is a plan-time `LogicalPlan` walk — no UDFs,
//! no runtime SQL (hard rule 6).
//!
//! # Semantics (decided,  F5b)
//!
//! - **Mode** ([`AuthzMode`]): `Open` (default) applies **zero**
//!   enforcement — every existing deployment is unchanged. `Grant` is
//!   deny-unless-granted.
//! - To read a table `catalog.schema.table` a grant-mode session must hold
//!   **both** `USAGE` on `catalog` **and** `SELECT` on that table. Missing
//!   either ⇒ the query is rejected with a `permission denied`
//!   [`DataFusionError::Plan`] (same surface as [`crate::access_deny`]).
//! - **Principal**: a grant applies to the session when its grantee name
//!   equals the session [`user`](Identity::user) **or** is one of the
//!   session's [`roles`](Identity::roles). Grants are **org-scoped** — only
//!   a grant whose org matches the session's [`org`](Identity::org) counts
//!   (cross-org isolation, via the crate `org_rule_applies` helper).
//! - **Superuser bypass**: an [`Identity::is_superuser`] session is allowed
//!   everything; the walk is skipped.
//! - **Anonymous / no principal**: no grants match ⇒ every governed scan is
//!   denied (fail-closed, rule 12).
//!
//! # Scan resolution (closing the bare-reference bypass)
//!
//! A governed federated table is always reachable as `catalog.schema.table`,
//! but a client may *write* it bare (`FROM users`) or partially
//! (`FROM public.users`). Because enforcement is deny-unless-granted,
//! **skipping** an unqualified scan would *allow* the read — a bypass. So the
//! enforcer resolves every scan to its full identity using the session
//! `(default_catalog, default_schema)` (`resolve_full`) before checking —
//! bare `users` is governed as `default_catalog.default_schema.users`,
//! exactly as DataFusion planned it. This mirrors
//! [`crate::mask::ColumnMaskingEnforcer`]'s `session_defaults` upgrade.
//!
//! A scan is only left ungoverned when it genuinely can't be resolved to a
//! full triple (no session defaults configured *and* the scan wasn't already
//! 3-part). Scans in the Postgres system schemas (`pg_catalog`,
//! `information_schema`) are exempt so client introspection (`\dt`, JDBC
//! metadata) works without a grant. Everything that resolves to a governed
//! table is fail-closed.

use std::sync::{Arc, RwLock};

use datafusion::common::tree_node::Transformed;
use datafusion::error::DataFusionError;
use datafusion::logical_expr::LogicalPlan;
use datafusion::sql::TableReference;

use crate::{Identity, PolicyEnforcer};

/// Server-configured authorization mode (the `[authz] mode` key).
///
/// `Open` is the default and preserves the pre-F5b behaviour byte-for-byte
/// (no enforcement). `Grant` turns on deny-unless-granted checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AuthzMode {
    /// No authorization enforcement — the historical behaviour.
    #[default]
    Open,
    /// Deny a table read unless the session holds `USAGE` on its catalog
    /// **and** `SELECT` on the table.
    Grant,
}

/// A grantable privilege, mirrored from the catalog's `Privilege`
/// (the policy crate must not depend on `dataglot-catalog`, rule 4 — the
/// server translates one to the other).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantPrivilege {
    /// `SELECT` on a table.
    Select,
    /// `USAGE` on a catalog.
    Usage,
}

/// The object a [`Grant`] confers a privilege on — mirrors the catalog's
/// `GrantObject`. `Usage` pairs with a catalog; `Select` with a
/// fully-qualified table.
#[derive(Debug, Clone, PartialEq, Eq)]
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

/// One resolved grant, policy-crate-local (rule 4). The server lowers a
/// `dataglot_catalog::GrantRecord` (+ the org it is stored under) into this
/// shape via `build_grant`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    /// The grantee's **name** — matched against the session user or one of
    /// its roles at enforcement time (F5a stores every privilege grantee as
    /// nominal `User`; F5b resolves the real principal by name).
    pub grantee: String,
    /// The org the grant is scoped to. `Some(x)` (the only form the server
    /// produces) applies only to a session whose `Identity.org` is `x`;
    /// `None` would be operator-wide (unused today, kept for parity with
    /// the mask/row-filter org model and the crate `org_rule_applies` helper).
    pub org: Option<String>,
    /// The object the privilege is on (its variant also encodes the
    /// privilege: `Catalog` ⇒ `USAGE`, `Table` ⇒ `SELECT`).
    pub object: GrantObject,
}

impl Grant {
    /// A `USAGE`-on-catalog grant.
    #[must_use]
    pub fn usage(
        grantee: impl Into<String>,
        org: Option<String>,
        catalog: impl Into<String>,
    ) -> Self {
        Self {
            grantee: grantee.into(),
            org,
            object: GrantObject::Catalog(catalog.into()),
        }
    }

    /// A `SELECT`-on-table grant.
    #[must_use]
    pub fn select(
        grantee: impl Into<String>,
        org: Option<String>,
        catalog: impl Into<String>,
        schema: impl Into<String>,
        table: impl Into<String>,
    ) -> Self {
        Self {
            grantee: grantee.into(),
            org,
            object: GrantObject::Table {
                catalog: catalog.into(),
                schema: schema.into(),
                table: table.into(),
            },
        }
    }

    /// The privilege this grant confers.
    #[must_use]
    pub fn privilege(&self) -> GrantPrivilege {
        match self.object {
            GrantObject::Catalog(_) => GrantPrivilege::Usage,
            GrantObject::Table { .. } => GrantPrivilege::Select,
        }
    }

    /// Whether this grant applies to `identity`: it is org-scoped to the
    /// session's org **and** its grantee names the session's user or one of
    /// its roles.
    fn applies_to(&self, identity: &Identity) -> bool {
        if !crate::org_rule_applies(self.org.as_deref(), identity) {
            return false;
        }
        let matches_user = identity.user.as_deref() == Some(self.grantee.as_str());
        let matches_role = identity.roles.iter().any(|r| r == &self.grantee);
        matches_user || matches_role
    }
}

/// Postgres system schemas that are exempt from grant enforcement so client
/// introspection works without an explicit `USAGE`/`SELECT` grant.
fn is_system_schema(schema: &str) -> bool {
    schema.eq_ignore_ascii_case("pg_catalog") || schema.eq_ignore_ascii_case("information_schema")
}

fn usage_denied(catalog: &str) -> DataFusionError {
    DataFusionError::Plan(format!(
        "permission denied: no USAGE privilege on catalog \"{catalog}\""
    ))
}

fn select_denied(catalog: &str, schema: &str, table: &str) -> DataFusionError {
    DataFusionError::Plan(format!(
        "permission denied: no SELECT privilege on table \"{catalog}.{schema}.{table}\""
    ))
}

/// A [`PolicyEnforcer`] that denies a table read unless the session holds
/// `USAGE` on its catalog and `SELECT` on the table (grant mode).
///
/// Holds a **live-swappable** grant set: [`Self::publish`] republishes the
/// full set after any `GRANT`/`REVOKE`, so the change is visible to every
/// session's *next* query with no reconnect — the same visibility model as
/// `CREATE`/`DROP MASK`. The set spans every org; `Grant::applies_to`
/// narrows it to the session at rewrite time.
#[derive(Debug)]
pub struct GrantEnforcer {
    mode: AuthzMode,
    grants: RwLock<Arc<Vec<Grant>>>,
    /// The session `(default_catalog, default_schema)` used to resolve a
    /// bare/partial scan to its fully-qualified identity before the grant
    /// check. Without this a `SELECT … FROM users` (relying on
    /// the default catalog/schema) reaches the enforcer as a bare
    /// `TableReference` and would escape a deny-unless-granted check — a
    /// bypass. Mirrors [`crate::mask::ColumnMaskingEnforcer`]'s
    /// `session_defaults`. `None` ⇒ no defaults known, so only already-
    /// fully-qualified scans are governed (the tests' default).
    session_defaults: Option<(String, String)>,
}

impl GrantEnforcer {
    /// A grant enforcer in `mode` with no grants yet. Load grants with
    /// [`Self::publish`].
    #[must_use]
    pub fn new(mode: AuthzMode) -> Self {
        Self {
            mode,
            grants: RwLock::new(Arc::new(Vec::new())),
            session_defaults: None,
        }
    }

    /// A grant enforcer in `mode` pre-loaded with `grants`.
    #[must_use]
    pub fn with_grants(mode: AuthzMode, grants: impl IntoIterator<Item = Grant>) -> Self {
        Self {
            mode,
            grants: RwLock::new(Arc::new(grants.into_iter().collect())),
            session_defaults: None,
        }
    }

    /// Set the session `(default_catalog, default_schema)` used to resolve
    /// bare/partial scans. The server always supplies these
    /// from `ServerConfig`; a bare `FROM t` is then governed as
    /// `default_catalog.default_schema.t`.
    #[must_use]
    pub fn with_session_defaults(mut self, defaults: Option<(String, String)>) -> Self {
        self.session_defaults = defaults;
        self
    }

    /// The configured authorization mode.
    #[must_use]
    pub fn mode(&self) -> AuthzMode {
        self.mode
    }

    /// Replace the live grant set (the runtime-freshness path). Every
    /// subsequent query sees the new set; in-flight rewrites finish against
    /// the snapshot they already loaded.
    pub fn publish(&self, grants: Vec<Grant>) {
        let mut guard = self
            .grants
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *guard = Arc::new(grants);
    }

    /// Clone the current grant-set handle (one atomic refcount bump).
    fn snapshot(&self) -> Arc<Vec<Grant>> {
        let guard = self
            .grants
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Arc::clone(&guard)
    }

    /// Number of live grants (across every org). Diagnostics only.
    #[must_use]
    pub fn grant_count(&self) -> usize {
        self.snapshot().len()
    }

    /// Whether `identity` holds `USAGE` on `catalog` among `grants`.
    fn holds_usage(grants: &[Grant], identity: &Identity, catalog: &str) -> bool {
        grants.iter().any(|g| {
            matches!(&g.object, GrantObject::Catalog(c) if c == catalog) && g.applies_to(identity)
        })
    }

    /// Whether `identity` holds `SELECT` on `catalog.schema.table`.
    fn holds_select(
        grants: &[Grant],
        identity: &Identity,
        catalog: &str,
        schema: &str,
        table: &str,
    ) -> bool {
        grants.iter().any(|g| {
            matches!(
                &g.object,
                GrantObject::Table { catalog: c, schema: s, table: t }
                    if c == catalog && s == schema && t == table
            ) && g.applies_to(identity)
        })
    }

    /// Resolve a scan's `TableReference` to the fully-qualified
    /// `(catalog, schema, table)` identity DataFusion planned it as, applying
    /// the session defaults to a bare/partial reference. `None` only when the
    /// reference can't be resolved to a full triple (no defaults configured
    /// and the scan wasn't already 3-part) — such a scan is not governed.
    ///
    /// This is the security-critical step: a governed federated table is
    /// always reachable as `catalog.schema.table`, but a client may *write*
    /// it bare (`FROM users`) or partially (`FROM public.users`). Without this
    /// upgrade a deny-unless-granted check would skip such scans and allow the
    /// read. Mirrors [`crate::mask::ColumnMaskingEnforcer`]'s `candidate_refs`
    /// upgrade, but resolves to the single planned identity (grants
    /// are always stored fully-qualified, so no downgrade chain is needed).
    fn resolve_full(&self, rel: &TableReference) -> Option<(String, String, String)> {
        let table = rel.table().to_string();
        match (rel.catalog(), rel.schema()) {
            (Some(catalog), Some(schema)) => Some((catalog.to_string(), schema.to_string(), table)),
            // Partial `schema.table` → `default_catalog.schema.table`.
            (None, Some(schema)) => self
                .session_defaults
                .as_ref()
                .map(|(dc, _)| (dc.clone(), schema.to_string(), table)),
            // Bare `table` → `default_catalog.default_schema.table`.
            (None, None) => self
                .session_defaults
                .as_ref()
                .map(|(dc, ds)| (dc.clone(), ds.clone(), table)),
            // A catalog with no schema is not a resolvable table reference.
            (Some(_), None) => None,
        }
    }

    /// The privilege a governed scan is missing (`None` ⇒ allowed).
    /// Shared by `rewrite` (raises the error) and `explain` (reports it).
    fn missing_privilege(
        &self,
        grants: &[Grant],
        identity: &Identity,
        rel: &TableReference,
    ) -> Option<DataFusionError> {
        let (catalog, schema, table) = self.resolve_full(rel)?;
        if is_system_schema(&schema) {
            return None;
        }
        if !Self::holds_usage(grants, identity, &catalog) {
            return Some(usage_denied(&catalog));
        }
        if !Self::holds_select(grants, identity, &catalog, &schema, &table) {
            return Some(select_denied(&catalog, &schema, &table));
        }
        None
    }
}

impl PolicyEnforcer for GrantEnforcer {
    fn rewrite(
        &self,
        plan: LogicalPlan,
        identity: &Identity,
    ) -> Result<Transformed<LogicalPlan>, DataFusionError> {
        // Open mode is inert; a superuser bypasses enforcement entirely.
        if self.mode == AuthzMode::Open || identity.is_superuser {
            return Ok(Transformed::no(plan));
        }
        let grants = self.snapshot();

        // Walk every TableScan — including those nested in expression
        // subqueries (`try_for_each_table_scan`), which `LogicalPlan::apply`
        // skips (: `SELECT (SELECT … FROM secret)` would otherwise
        // bypass the deny-unless-granted check entirely). The first governed
        // scan the session can't read raises the deny, which short-circuits
        // the walk and propagates out as the query failure. The plan is never
        // mutated — a grant check is all-or-nothing.
        crate::try_for_each_table_scan(&plan, &mut |scan| {
            if let Some(err) = self.missing_privilege(&grants, identity, &scan.table_name) {
                crate::audit::record_decision("deny", identity, &scan.table_name.to_string());
                return Err(err);
            }
            Ok(())
        })?;

        Ok(Transformed::no(plan))
    }

    fn explain(&self, plan: &LogicalPlan, identity: &Identity) -> Vec<crate::PolicyDecision> {
        use crate::{PolicyAction, PolicyDecision};
        if self.mode == AuthzMode::Open || identity.is_superuser {
            return Vec::new();
        }
        let grants = self.snapshot();
        let mut out: Vec<PolicyDecision> = Vec::new();
        // Collect decisions across subqueries too (same subquery-aware walk as
        // `rewrite`); the closure never errors, so every governed scan is
        // visited and reported, deduped by resource.
        let _ = crate::try_for_each_table_scan(plan, &mut |scan| {
            if let Some(err) = self.missing_privilege(&grants, identity, &scan.table_name) {
                let resource = scan.table_name.to_string();
                if !out.iter().any(|d| d.resource == resource) {
                    out.push(PolicyDecision::new(
                        PolicyAction::Deny,
                        resource,
                        err.to_string(),
                    ));
                }
            }
            Ok(())
        });
        out
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use datafusion::arrow::datatypes::{DataType, Field, Schema};
    use datafusion::catalog::{
        CatalogProvider, MemoryCatalogProvider, MemorySchemaProvider, SchemaProvider,
    };
    use datafusion::datasource::MemTable;
    use datafusion::prelude::SessionContext;

    use super::*;

    /// A `SessionContext` with a fully-qualified `pg.public.users` table so
    /// a `SELECT … FROM pg.public.users` yields a `TableScan` whose
    /// `table_name` is the full 3-part reference the enforcer governs.
    fn ctx_with_pg_users() -> SessionContext {
        let ctx = SessionContext::new();
        let schema = Arc::new(Schema::new(vec![
            Field::new("id", DataType::Int32, false),
            Field::new("email", DataType::Utf8, false),
        ]));
        let table = Arc::new(MemTable::try_new(schema, vec![vec![]]).expect("memtable"));
        let public = Arc::new(MemorySchemaProvider::new());
        public
            .register_table("users".to_string(), table)
            .expect("register table");
        let catalog = Arc::new(MemoryCatalogProvider::new());
        catalog
            .register_schema("public", public)
            .expect("register schema");
        ctx.register_catalog("pg", catalog);
        ctx
    }

    /// [`ctx_with_pg_users`] plus a bare, **ungoverned** `docs` table for the
    /// outer FROM of an `IN` / `EXISTS` subquery test. With no session
    /// defaults the bare `docs` scan is not governed, so any denial the test
    /// sees comes strictly from the governed `pg.public.users` scan *inside*
    /// the subquery — isolating the expression-subquery traversal.
    fn ctx_with_pg_users_and_docs() -> SessionContext {
        let ctx = ctx_with_pg_users();
        let schema = Arc::new(Schema::new(vec![Field::new("id", DataType::Int32, false)]));
        let table = Arc::new(MemTable::try_new(schema, vec![vec![]]).expect("memtable"));
        ctx.register_table("docs", table).expect("register docs");
        ctx
    }

    /// [`ctx_with_pg_users`] plus a second **governed** `pg.public.orders`
    /// table registered in the same catalog+schema, so a grant covering only
    /// `users` can be shown NOT to authorize `orders`.
    fn ctx_with_pg_users_and_orders() -> SessionContext {
        let ctx = ctx_with_pg_users();
        let schema = Arc::new(Schema::new(vec![Field::new("id", DataType::Int32, false)]));
        let table = Arc::new(MemTable::try_new(schema, vec![vec![]]).expect("memtable"));
        ctx.catalog("pg")
            .expect("pg catalog")
            .schema("public")
            .expect("public schema")
            .register_table("orders".to_string(), table)
            .expect("register orders");
        ctx
    }

    async fn plan_of(ctx: &SessionContext, sql: &str) -> LogicalPlan {
        ctx.state().create_logical_plan(sql).await.expect("plan")
    }

    fn grant_usage_select(grantee: &str, org: &str) -> Vec<Grant> {
        vec![
            Grant::usage(grantee, Some(org.to_string()), "pg"),
            Grant::select(grantee, Some(org.to_string()), "pg", "public", "users"),
        ]
    }

    // ---- open mode: zero enforcement -------------------------------------

    #[tokio::test]
    async fn open_mode_allows_ungranted_read() {
        let ctx = ctx_with_pg_users();
        let plan = plan_of(&ctx, "SELECT id FROM pg.public.users").await;
        // No grants at all, but open mode ⇒ allowed (existing behaviour).
        let enforcer = GrantEnforcer::new(AuthzMode::Open);
        let out = enforcer
            .rewrite(plan, &Identity::user("nobody").with_org("acme"))
            .expect("open mode never denies");
        assert!(!out.transformed);
    }

    // ---- grant mode: deny by default -------------------------------------

    #[tokio::test]
    async fn grant_mode_denies_ungranted_read() {
        let ctx = ctx_with_pg_users();
        let plan = plan_of(&ctx, "SELECT id FROM pg.public.users").await;
        let enforcer = GrantEnforcer::new(AuthzMode::Grant);
        let res = enforcer.rewrite(plan, &Identity::user("alice").with_org("acme"));
        let err = res.expect_err("ungranted read must be denied").to_string();
        assert!(err.contains("permission denied"), "got: {err}");
    }

    // ---- expression-position subquery bypass -------------------
    // `LogicalPlan::apply` does not descend into subqueries embedded in
    // expressions, so before the `try_for_each_table_scan` fix an ungranted
    // read wrapped in one ESCAPED the deny-unless-granted check entirely — a
    // full auth bypass. Each of these must be DENIED.

    #[tokio::test]
    async fn scalar_subquery_in_projection_is_denied() {
        // SELECT (SELECT id FROM pg.public.users LIMIT 1)
        let ctx = ctx_with_pg_users();
        let plan = plan_of(&ctx, "SELECT (SELECT id FROM pg.public.users LIMIT 1)").await;
        let enforcer = GrantEnforcer::new(AuthzMode::Grant);
        let err = enforcer
            .rewrite(plan, &Identity::user("alice").with_org("acme"))
            .expect_err("ungranted scalar-subquery read must be denied")
            .to_string();
        assert!(err.contains("permission denied"), "got: {err}");
    }

    #[tokio::test]
    async fn in_subquery_in_where_is_denied() {
        // SELECT ... WHERE id IN (SELECT id FROM pg.public.users)
        let ctx = ctx_with_pg_users_and_docs();
        let plan = plan_of(
            &ctx,
            "SELECT id FROM docs WHERE id IN (SELECT id FROM pg.public.users)",
        )
        .await;
        let enforcer = GrantEnforcer::new(AuthzMode::Grant);
        let err = enforcer
            .rewrite(plan, &Identity::user("alice").with_org("acme"))
            .expect_err("ungranted IN-subquery read must be denied")
            .to_string();
        assert!(err.contains("permission denied"), "got: {err}");
    }

    #[tokio::test]
    async fn any_subquery_in_where_is_denied() {
        // SELECT ... WHERE id = ANY (SELECT id FROM pg.public.users)
        // The `= ANY (subquery)` form plans to the `SetComparison` Expr
        // variant — the fourth subquery-bearing expression. An ungranted read
        // reached only through it must still be denied (the deny-unless-granted
        // walk descends into it via `try_for_each_table_scan`, ).
        let ctx = ctx_with_pg_users_and_docs();
        let plan = plan_of(
            &ctx,
            "SELECT id FROM docs WHERE id = ANY (SELECT id FROM pg.public.users)",
        )
        .await;
        let enforcer = GrantEnforcer::new(AuthzMode::Grant);
        let err = enforcer
            .rewrite(plan, &Identity::user("alice").with_org("acme"))
            .expect_err("ungranted = ANY-subquery read must be denied")
            .to_string();
        assert!(err.contains("permission denied"), "got: {err}");
    }

    #[tokio::test]
    async fn exists_subquery_in_where_is_denied() {
        // SELECT ... WHERE EXISTS (SELECT 1 FROM pg.public.users)
        let ctx = ctx_with_pg_users_and_docs();
        let plan = plan_of(
            &ctx,
            "SELECT id FROM docs WHERE EXISTS (SELECT 1 FROM pg.public.users)",
        )
        .await;
        let enforcer = GrantEnforcer::new(AuthzMode::Grant);
        let err = enforcer
            .rewrite(plan, &Identity::user("alice").with_org("acme"))
            .expect_err("ungranted EXISTS-subquery read must be denied")
            .to_string();
        assert!(err.contains("permission denied"), "got: {err}");
    }

    #[tokio::test]
    async fn nested_subquery_is_denied() {
        // A subquery within a subquery: the innermost scan of pg.public.users
        // is two expression-subquery levels deep, and the intermediate level
        // scans nothing governed — so only a recursive descent catches it.
        let ctx = ctx_with_pg_users();
        let plan = plan_of(
            &ctx,
            "SELECT (SELECT (SELECT id FROM pg.public.users LIMIT 1) AS inner_id)",
        )
        .await;
        let enforcer = GrantEnforcer::new(AuthzMode::Grant);
        let err = enforcer
            .rewrite(plan, &Identity::user("alice").with_org("acme"))
            .expect_err("ungranted deeply-nested subquery read must be denied")
            .to_string();
        assert!(err.contains("permission denied"), "got: {err}");
    }

    #[tokio::test]
    async fn granted_user_is_allowed_through_a_subquery() {
        // The fix must not over-deny: a user holding USAGE + SELECT reads the
        // governed table through a subquery without a spurious denial.
        let ctx = ctx_with_pg_users();
        let plan = plan_of(&ctx, "SELECT (SELECT id FROM pg.public.users LIMIT 1)").await;
        let enforcer =
            GrantEnforcer::with_grants(AuthzMode::Grant, grant_usage_select("alice", "acme"));
        let out = enforcer
            .rewrite(plan, &Identity::user("alice").with_org("acme"))
            .expect("granted read through a subquery ⇒ allowed");
        assert!(!out.transformed, "allow leaves the plan unchanged");
    }

    // ---- grant mode: USAGE + SELECT allows -------------------------------

    #[tokio::test]
    async fn grant_mode_allows_with_usage_and_select() {
        let ctx = ctx_with_pg_users();
        let plan = plan_of(&ctx, "SELECT id FROM pg.public.users").await;
        let enforcer =
            GrantEnforcer::with_grants(AuthzMode::Grant, grant_usage_select("alice", "acme"));
        let out = enforcer
            .rewrite(plan, &Identity::user("alice").with_org("acme"))
            .expect("USAGE + SELECT ⇒ allowed");
        assert!(!out.transformed, "allow leaves the plan unchanged");
    }

    // ---- grant is table-scoped, not catalog-wide -------------------------

    #[tokio::test]
    async fn grant_on_one_table_does_not_authorize_another() {
        // USAGE on `pg` + SELECT on `pg.public.users` grants exactly `users`;
        // it must NOT authorize a *different* ungranted table in the same
        // catalog/schema. (Previously only proven by the Docker `#[ignore]`
        // e2e — this is the fast plan-time unit equivalent.)
        let ctx = ctx_with_pg_users_and_orders();
        let enforcer =
            GrantEnforcer::with_grants(AuthzMode::Grant, grant_usage_select("alice", "acme"));
        let alice = Identity::user("alice").with_org("acme");

        // The granted table reads fine.
        let plan = plan_of(&ctx, "SELECT id FROM pg.public.users").await;
        assert!(
            enforcer.rewrite(plan, &alice).is_ok(),
            "the granted table must be readable"
        );

        // A sibling table the grant never named is denied for lack of SELECT.
        let plan = plan_of(&ctx, "SELECT id FROM pg.public.orders").await;
        let err = enforcer
            .rewrite(plan, &alice)
            .expect_err("SELECT on users must not authorize orders")
            .to_string();
        assert!(
            err.contains("SELECT") && err.contains("orders"),
            "expected a missing-SELECT-on-orders denial, got: {err}"
        );
    }

    // ---- CTE / alias name collision cannot dodge a grant -----------------
    // adapted from Trino TestRowFilter "SQL injection prevention"

    #[tokio::test]
    async fn cte_named_like_governed_table_does_not_dodge_grant() {
        // A CTE named exactly like the governed table (`WITH users AS …`) must
        // not shield the real `pg.public.users` scan inside the CTE body from
        // the deny-unless-granted check: the outer `FROM users` resolves to the
        // CTE, but the CTE body still scans the governed table, and grant mode
        // (no grants) must deny it.
        let ctx = ctx_with_pg_users();
        let plan = plan_of(
            &ctx,
            "WITH users AS (SELECT id FROM pg.public.users) SELECT id FROM users",
        )
        .await;
        let enforcer = GrantEnforcer::new(AuthzMode::Grant);
        let err = enforcer
            .rewrite(plan, &Identity::user("alice").with_org("acme"))
            .expect_err("a CTE aliasing the governed table must not dodge the grant")
            .to_string();
        assert!(err.contains("permission denied"), "got: {err}");
    }

    // ---- partial: SELECT but no USAGE, and USAGE but no SELECT -----------

    #[tokio::test]
    async fn select_without_usage_is_denied() {
        let ctx = ctx_with_pg_users();
        let plan = plan_of(&ctx, "SELECT id FROM pg.public.users").await;
        let enforcer = GrantEnforcer::with_grants(
            AuthzMode::Grant,
            [Grant::select(
                "alice",
                Some("acme".into()),
                "pg",
                "public",
                "users",
            )],
        );
        let err = enforcer
            .rewrite(plan, &Identity::user("alice").with_org("acme"))
            .expect_err("SELECT without USAGE ⇒ denied")
            .to_string();
        assert!(
            err.contains("USAGE"),
            "missing-USAGE message expected, got: {err}"
        );
    }

    #[tokio::test]
    async fn usage_without_select_is_denied() {
        let ctx = ctx_with_pg_users();
        let plan = plan_of(&ctx, "SELECT id FROM pg.public.users").await;
        let enforcer = GrantEnforcer::with_grants(
            AuthzMode::Grant,
            [Grant::usage("alice", Some("acme".into()), "pg")],
        );
        let err = enforcer
            .rewrite(plan, &Identity::user("alice").with_org("acme"))
            .expect_err("USAGE without SELECT ⇒ denied")
            .to_string();
        assert!(
            err.contains("SELECT"),
            "missing-SELECT message expected, got: {err}"
        );
    }

    // ---- role-inherited grant --------------------------------------------

    #[tokio::test]
    async fn role_inherited_grant_allows_then_revoke_denies() {
        let ctx = ctx_with_pg_users();
        // Grants are held by the *role* `analyst`, not the user directly.
        let enforcer =
            GrantEnforcer::with_grants(AuthzMode::Grant, grant_usage_select("analyst", "acme"));

        // Alice holds the analyst role ⇒ allowed.
        let plan = plan_of(&ctx, "SELECT id FROM pg.public.users").await;
        let member = Identity::user("alice")
            .with_org("acme")
            .with_roles(["analyst"]);
        assert!(
            enforcer.rewrite(plan, &member).is_ok(),
            "a role member inherits the role's grants"
        );

        // Same user without the role (membership revoked) ⇒ denied.
        let plan = plan_of(&ctx, "SELECT id FROM pg.public.users").await;
        let non_member = Identity::user("alice").with_org("acme");
        assert!(
            enforcer.rewrite(plan, &non_member).is_err(),
            "revoking the membership removes the inherited grant"
        );
    }

    // ---- superuser bypass -------------------------------------------------

    #[tokio::test]
    async fn superuser_bypasses_with_no_grants() {
        let ctx = ctx_with_pg_users();
        let plan = plan_of(&ctx, "SELECT id FROM pg.public.users").await;
        let enforcer = GrantEnforcer::new(AuthzMode::Grant);
        let out = enforcer
            .rewrite(
                plan,
                &Identity::user("root").with_org("acme").as_superuser(),
            )
            .expect("superuser is allowed everything");
        assert!(!out.transformed);
    }

    // ---- cross-org isolation ---------------------------------------------

    #[tokio::test]
    async fn grant_in_one_org_does_not_authorize_same_name_in_another() {
        let ctx = ctx_with_pg_users();
        // `analyst` is granted USAGE+SELECT in org `acme`.
        let enforcer =
            GrantEnforcer::with_grants(AuthzMode::Grant, grant_usage_select("analyst", "acme"));

        // A session named `analyst` in `acme` is allowed.
        let plan = plan_of(&ctx, "SELECT id FROM pg.public.users").await;
        assert!(enforcer
            .rewrite(plan, &Identity::user("analyst").with_org("acme"))
            .is_ok());

        // The same name in `beta` is NOT — the grant is org-scoped.
        let plan = plan_of(&ctx, "SELECT id FROM pg.public.users").await;
        assert!(
            enforcer
                .rewrite(plan, &Identity::user("analyst").with_org("beta"))
                .is_err(),
            "a grant in acme must not authorize an analyst in beta"
        );
    }

    // ---- anonymous fail-closed -------------------------------------------

    #[tokio::test]
    async fn anonymous_session_is_denied_in_grant_mode() {
        let ctx = ctx_with_pg_users();
        let plan = plan_of(&ctx, "SELECT id FROM pg.public.users").await;
        let enforcer =
            GrantEnforcer::with_grants(AuthzMode::Grant, grant_usage_select("alice", "acme"));
        assert!(
            enforcer.rewrite(plan, &Identity::anonymous()).is_err(),
            "an anonymous session holds no grants ⇒ fail-closed deny"
        );
    }

    // ---- over-deny audit: system + unqualified scans ---------------------

    #[tokio::test]
    async fn system_schema_scan_is_not_denied() {
        // pg_catalog introspection must run without a grant. Register a
        // `pg.pg_catalog.pg_class` table so the query plans, then confirm the
        // full-3-part scan into a system schema is exempt.
        let ctx = SessionContext::new();
        let schema = Arc::new(Schema::new(vec![Field::new(
            "relname",
            DataType::Utf8,
            false,
        )]));
        let table = Arc::new(MemTable::try_new(schema, vec![vec![]]).expect("memtable"));
        let pg_catalog = Arc::new(MemorySchemaProvider::new());
        pg_catalog
            .register_table("pg_class".to_string(), table)
            .expect("register pg_class");
        let catalog = Arc::new(MemoryCatalogProvider::new());
        catalog
            .register_schema("pg_catalog", pg_catalog)
            .expect("register pg_catalog schema");
        ctx.register_catalog("pg", catalog);

        let plan = plan_of(&ctx, "SELECT relname FROM pg.pg_catalog.pg_class").await;
        let enforcer = GrantEnforcer::new(AuthzMode::Grant);
        assert!(
            enforcer
                .rewrite(plan, &Identity::user("alice").with_org("acme"))
                .is_ok(),
            "system-schema scans are exempt from grant enforcement"
        );
    }

    #[tokio::test]
    async fn scan_without_a_catalog_is_not_governed() {
        // A bare table registered on the session default catalog yields a
        // bare TableScan — no resolvable catalog ⇒ not governed (matches the
        // mask/row-filter resolution behaviour), so it isn't spuriously denied.
        let ctx = SessionContext::new();
        let schema = Arc::new(Schema::new(vec![Field::new("id", DataType::Int32, false)]));
        let table = Arc::new(MemTable::try_new(schema, vec![vec![]]).expect("memtable"));
        ctx.register_table("t", table).expect("register bare table");
        let plan = plan_of(&ctx, "SELECT id FROM t").await;
        let enforcer = GrantEnforcer::new(AuthzMode::Grant);
        assert!(
            enforcer
                .rewrite(plan, &Identity::user("alice").with_org("acme"))
                .is_ok(),
            "a catalog-less scan is not governed and must not be denied"
        );
    }

    // ---- bare/partial scans ARE governed once session defaults are set ---
    // Regression: without this a `FROM users` (bare) or `FROM public.users`
    // (partial) escapes a deny-unless-granted check — a bypass.

    #[tokio::test]
    async fn bare_scan_is_governed_via_session_defaults_and_denied() {
        // A bare `FROM t` yields a bare TableScan; with the session defaults
        // configured it resolves to `pg.public.t` and, ungranted, is DENIED.
        let ctx = SessionContext::new();
        let schema = Arc::new(Schema::new(vec![Field::new("id", DataType::Int32, false)]));
        let table = Arc::new(MemTable::try_new(schema, vec![vec![]]).expect("memtable"));
        ctx.register_table("t", table).expect("register bare table");
        let plan = plan_of(&ctx, "SELECT id FROM t").await;
        let enforcer = GrantEnforcer::new(AuthzMode::Grant)
            .with_session_defaults(Some(("pg".into(), "public".into())));
        let err = enforcer
            .rewrite(plan, &Identity::user("alice").with_org("acme"))
            .expect_err("bare scan resolves to pg.public.t and is ungranted ⇒ denied")
            .to_string();
        assert!(err.contains("permission denied"), "got: {err}");
    }

    #[tokio::test]
    async fn bare_scan_is_allowed_with_a_grant_on_the_resolved_name() {
        // Same bare scan, now with USAGE on pg + SELECT on the resolved
        // pg.public.t ⇒ allowed. Proves the resolution targets the same
        // identity a grant is written against.
        let ctx = SessionContext::new();
        let schema = Arc::new(Schema::new(vec![Field::new("id", DataType::Int32, false)]));
        let table = Arc::new(MemTable::try_new(schema, vec![vec![]]).expect("memtable"));
        ctx.register_table("t", table).expect("register bare table");
        let plan = plan_of(&ctx, "SELECT id FROM t").await;
        let enforcer = GrantEnforcer::with_grants(
            AuthzMode::Grant,
            [
                Grant::usage("alice", Some("acme".into()), "pg"),
                Grant::select("alice", Some("acme".into()), "pg", "public", "t"),
            ],
        )
        .with_session_defaults(Some(("pg".into(), "public".into())));
        let out = enforcer
            .rewrite(plan, &Identity::user("alice").with_org("acme"))
            .expect("granted resolved table ⇒ allowed");
        assert!(!out.transformed, "allow leaves the plan unchanged");
    }

    #[tokio::test]
    async fn partial_scan_is_governed_via_default_catalog_and_denied() {
        // A partial `FROM public.t` yields a partial TableScan (`public.t`,
        // catalog absent); the enforcer's default catalog resolves it to
        // `pg.public.t` and, ungranted, it is DENIED. (The table is registered
        // on the session's own default catalog so the query plans; the
        // enforcer's configured default catalog `pg` is what governance uses.)
        let ctx = SessionContext::new();
        let schema = Arc::new(Schema::new(vec![Field::new("id", DataType::Int32, false)]));
        let table = Arc::new(MemTable::try_new(schema, vec![vec![]]).expect("memtable"));
        ctx.register_table("t", table).expect("register bare table");
        let plan = plan_of(&ctx, "SELECT id FROM public.t").await;
        let enforcer = GrantEnforcer::new(AuthzMode::Grant)
            .with_session_defaults(Some(("pg".into(), "public".into())));
        let err = enforcer
            .rewrite(plan, &Identity::user("alice").with_org("acme"))
            .expect_err("partial scan resolves to pg.public.t and is ungranted ⇒ denied")
            .to_string();
        assert!(err.contains("permission denied"), "got: {err}");
    }

    #[tokio::test]
    async fn no_table_scan_query_is_allowed() {
        let ctx = SessionContext::new();
        let plan = plan_of(&ctx, "SELECT 1").await;
        let enforcer = GrantEnforcer::new(AuthzMode::Grant);
        assert!(enforcer.rewrite(plan, &Identity::anonymous()).is_ok());
    }

    // ---- runtime freshness -----------------------------------------------

    #[tokio::test]
    async fn publish_makes_a_new_grant_visible() {
        let ctx = ctx_with_pg_users();
        let enforcer = GrantEnforcer::new(AuthzMode::Grant);
        let identity = Identity::user("alice").with_org("acme");

        // Before publish: denied.
        let plan = plan_of(&ctx, "SELECT id FROM pg.public.users").await;
        assert!(enforcer.rewrite(plan, &identity).is_err());

        // Publish USAGE+SELECT (a runtime GRANT) → next query allowed.
        enforcer.publish(grant_usage_select("alice", "acme"));
        let plan = plan_of(&ctx, "SELECT id FROM pg.public.users").await;
        assert!(enforcer.rewrite(plan, &identity).is_ok());

        // Publish an empty set (a runtime REVOKE of everything) → denied again.
        enforcer.publish(Vec::new());
        let plan = plan_of(&ctx, "SELECT id FROM pg.public.users").await;
        assert!(enforcer.rewrite(plan, &identity).is_err());
    }

    // ---- explain ---------------------------------------------------------

    #[tokio::test]
    async fn explain_reports_the_denied_table() {
        let ctx = ctx_with_pg_users();
        let plan = plan_of(&ctx, "SELECT id FROM pg.public.users").await;
        let enforcer = GrantEnforcer::new(AuthzMode::Grant);
        let decisions = enforcer.explain(&plan, &Identity::user("alice").with_org("acme"));
        assert_eq!(decisions.len(), 1);
        assert!(decisions[0].detail.contains("permission denied"));
        assert!(decisions[0].resource.contains("users"));
    }

    #[tokio::test]
    async fn explain_is_empty_for_superuser_and_open_mode() {
        let ctx = ctx_with_pg_users();
        let plan = plan_of(&ctx, "SELECT id FROM pg.public.users").await;
        let identity = Identity::user("alice").with_org("acme");
        assert!(GrantEnforcer::new(AuthzMode::Open)
            .explain(&plan, &identity)
            .is_empty());
        assert!(GrantEnforcer::new(AuthzMode::Grant)
            .explain(&plan, &identity.clone().as_superuser())
            .is_empty());
    }

    #[test]
    fn grant_privilege_accessor() {
        assert_eq!(
            Grant::usage("a", None, "pg").privilege(),
            GrantPrivilege::Usage
        );
        assert_eq!(
            Grant::select("a", None, "pg", "public", "t").privilege(),
            GrantPrivilege::Select
        );
    }

    #[test]
    fn debug_does_not_panic() {
        let enforcer =
            GrantEnforcer::with_grants(AuthzMode::Grant, grant_usage_select("a", "acme"));
        assert!(format!("{enforcer:?}").contains("GrantEnforcer"));
        assert_eq!(enforcer.grant_count(), 2);
    }
}

//! Server-side implementation of the pgwire [`GrantAdmin`] seam — the effecting
//! half of `GRANT` / `REVOKE`.
//!
//! [`dataglot_pgwire::grant_ddl`] parses the statement; [`StoreGrantAdmin`] here
//! persists it to the org-scoped [`MetaStore`]:
//!
//! - a **privilege** grant (`GRANT SELECT ON …` / `GRANT USAGE ON CATALOG …`)
//!   becomes a [`GrantRecord`] via [`MetaStore::put_grant`] (idempotent);
//! - a **role membership** grant (`GRANT <role> TO <user>`) becomes a
//!   user↔role relation via [`MetaStore::add_role_member`];
//! - the `REVOKE` forms invert each (delete / remove), reporting whether a row
//!   existed so the handler can distinguish a real revoke from a no-op.
//!
//! # Persistence (F5a) + enforcement freshness (F5b)
//!
//! This admin persists to the store, and — when the server runs in grant mode
//! (`[authz] mode = "grant"`) — republishes the full grant set into the live
//! [`dataglot_policy::GrantEnforcer`] after every mutating
//! statement, so a runtime `GRANT` / `REVOKE` takes effect on every session's
//! **next** query with no reconnect (the same visibility model as
//! `CREATE / DROP MASK`). In `open` mode the enforcer handle is `None`: the
//! admin still persists, but there is no enforcement to refresh, so applying a
//! grant changes no query behaviour.
//!
//! # Grantee kind
//!
//! A privilege grant's grantee is a bare name — the DDL grammar carries no
//! `USER` / `ROLE` qualifier — so F5a records it with the nominal kind
//! [`GranteeKind::User`] and does **not** require the principal to pre-exist
//! (matching how `CREATE MASK` does not pre-check columns). Resolving whether a
//! grantee is actually a user or a role is F5b's job (it resolves by name); the
//! load-bearing stored fact is the `(grantee, privilege, object)` tuple.
//!
//! # Not credentials
//!
//! A grant names a principal, a privilege, and an object — all config-level, no
//! secrets — so this module has no rule-12 redaction obligation (like
//! [`crate::policy_admin`]).

use std::sync::Arc;

use async_trait::async_trait;
use dataglot_catalog::{GrantRecord, GranteeKind, MetaStore};
use dataglot_pgwire::grant_admin::{GrantAdmin, GrantAdminError, GrantOutcome};
use dataglot_pgwire::grant_ddl::GrantDdl;
use dataglot_policy::GrantEnforcer;

/// [`GrantAdmin`] backed by the [`MetaStore`] (org-scoped persistence).
///
///  M2: one admin serves every org — the target org arrives per
/// [`GrantAdmin::apply`] call (threaded from the connection's session identity by
/// the pgwire handler). Persists every statement; in grant mode also
/// republishes the live grant set into the wired `GrantEnforcer` (F5b).
#[derive(Clone)]
pub struct StoreGrantAdmin {
    store: Arc<dyn MetaStore>,
    /// The live GRANT/REVOKE enforcer to keep fresh. `Some` in grant mode,
    /// `None` in open mode (nothing to enforce, so nothing to refresh).
    grant_enforcer: Option<Arc<GrantEnforcer>>,
}

impl StoreGrantAdmin {
    /// Wrap a control-plane store and (in grant mode) the live enforcer to
    /// refresh. The target org is supplied per [`GrantAdmin::apply`] call.
    #[must_use]
    pub fn new(store: Arc<dyn MetaStore>, grant_enforcer: Option<Arc<GrantEnforcer>>) -> Self {
        Self {
            store,
            grant_enforcer,
        }
    }

    /// Reload **every org's** grants and republish them into the live
    /// enforcer, so a mutation is visible to every session's next query. A
    /// no-op in open mode (`grant_enforcer` is `None`). A reload failure is
    /// surfaced as a backend error — the persisted change already succeeded,
    /// but leaving the enforcer stale would silently under-enforce, so the
    /// statement reports failure rather than hiding it.
    async fn refresh(&self, org: &str) -> Result<(), GrantAdminError> {
        let Some(enforcer) = &self.grant_enforcer else {
            return Ok(());
        };
        let grants = crate::server::load_all_grants(self.store.as_ref())
            .await
            .map_err(|e| GrantAdminError::Backend(format!("grant refresh for org {org:?}: {e}")))?;
        enforcer.publish(grants);
        Ok(())
    }
}

/// Map a store error into a client-safe [`GrantAdminError::Backend`]. Store
/// errors are backend IO / serialization failures and never carry credentials.
fn backend(e: &dataglot_catalog::CatalogServiceError) -> GrantAdminError {
    GrantAdminError::Backend(format!("grant store: {e}"))
}

#[async_trait]
impl GrantAdmin for StoreGrantAdmin {
    async fn apply(&self, org: &str, ddl: GrantDdl) -> Result<GrantOutcome, GrantAdminError> {
        let outcome = match ddl {
            GrantDdl::GrantSelect {
                catalog,
                schema,
                table,
                grantee,
            } => {
                // Nominal User kind (see module docs); F5b resolves the real
                // principal by name.
                let grant = GrantRecord::select(GranteeKind::User, grantee, catalog, schema, table);
                self.store
                    .put_grant(org, &grant)
                    .await
                    .map_err(|e| backend(&e))?;
                GrantOutcome::Granted
            }
            GrantDdl::GrantUsage { catalog, grantee } => {
                let grant = GrantRecord::usage(GranteeKind::User, grantee, catalog);
                self.store
                    .put_grant(org, &grant)
                    .await
                    .map_err(|e| backend(&e))?;
                GrantOutcome::Granted
            }
            GrantDdl::RevokeSelect {
                catalog,
                schema,
                table,
                grantee,
            } => {
                let grant = GrantRecord::select(GranteeKind::User, grantee, catalog, schema, table);
                let removed = self
                    .store
                    .delete_grant(org, &grant)
                    .await
                    .map_err(|e| backend(&e))?;
                revoke_outcome(removed)
            }
            GrantDdl::RevokeUsage { catalog, grantee } => {
                let grant = GrantRecord::usage(GranteeKind::User, grantee, catalog);
                let removed = self
                    .store
                    .delete_grant(org, &grant)
                    .await
                    .map_err(|e| backend(&e))?;
                revoke_outcome(removed)
            }
            GrantDdl::GrantRole { role, user } => {
                self.store
                    .add_role_member(org, &role, &user)
                    .await
                    .map_err(|e| backend(&e))?;
                GrantOutcome::Granted
            }
            GrantDdl::RevokeRole { role, user } => {
                let removed = self
                    .store
                    .remove_role_member(org, &role, &user)
                    .await
                    .map_err(|e| backend(&e))?;
                revoke_outcome(removed)
            }
        };
        // Republish the live grant set so a privilege GRANT / REVOKE is
        // enforced on every session's next query (grant mode; no-op in open
        // mode). Role-membership changes reload the same privilege set (they
        // don't alter it) — a session's *roles* are resolved into its
        // Identity at connect time, so a membership change takes effect for
        // connections opened afterward (documented visibility).
        self.refresh(org).await?;
        Ok(outcome)
    }
}

/// A `REVOKE` reports `Revoked` when a row existed, else `NoOp` (revoking an
/// absent grant is not an error — Postgres treats it as a warning).
fn revoke_outcome(removed: bool) -> GrantOutcome {
    if removed {
        GrantOutcome::Revoked
    } else {
        GrantOutcome::NoOp
    }
}

#[cfg(test)]
mod tests {
    use dataglot_catalog::embedded::EmbeddedMetaStore;
    use dataglot_catalog::GrantObject;

    use super::*;

    async fn setup() -> (Arc<dyn MetaStore>, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store: Arc<dyn MetaStore> = Arc::new(
            EmbeddedMetaStore::open(dir.path().join("m.json"), "default")
                .await
                .expect("store"),
        );
        (store, dir)
    }

    #[tokio::test]
    async fn grant_select_persists_under_call_org_then_revoke_removes() {
        let (store, _d) = setup().await;
        let admin = StoreGrantAdmin::new(Arc::clone(&store), None);

        admin
            .apply(
                "acme",
                GrantDdl::GrantSelect {
                    catalog: "pg".into(),
                    schema: "public".into(),
                    table: "orders".into(),
                    grantee: "alice".into(),
                },
            )
            .await
            .expect("grant");

        // Stored under "acme", invisible to "default" (org isolation).
        let grants = store.list_grants("acme").await.unwrap();
        assert_eq!(grants.len(), 1);
        assert_eq!(
            grants[0].object(),
            GrantObject::Table {
                catalog: "pg".into(),
                schema: "public".into(),
                table: "orders".into(),
            }
        );
        assert_eq!(grants[0].grantee_kind, GranteeKind::User);
        assert!(store.list_grants("default").await.unwrap().is_empty());

        // Revoke removes it; revoking again is a NoOp, not an error.
        assert!(matches!(
            admin
                .apply(
                    "acme",
                    GrantDdl::RevokeSelect {
                        catalog: "pg".into(),
                        schema: "public".into(),
                        table: "orders".into(),
                        grantee: "alice".into(),
                    },
                )
                .await
                .unwrap(),
            GrantOutcome::Revoked
        ));
        assert!(matches!(
            admin
                .apply(
                    "acme",
                    GrantDdl::RevokeSelect {
                        catalog: "pg".into(),
                        schema: "public".into(),
                        table: "orders".into(),
                        grantee: "alice".into(),
                    },
                )
                .await
                .unwrap(),
            GrantOutcome::NoOp
        ));
        assert!(store.list_grants("acme").await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn grant_usage_is_idempotent() {
        let (store, _d) = setup().await;
        let admin = StoreGrantAdmin::new(Arc::clone(&store), None);
        let ddl = || GrantDdl::GrantUsage {
            catalog: "pg".into(),
            grantee: "analyst".into(),
        };
        admin.apply("default", ddl()).await.expect("first");
        admin.apply("default", ddl()).await.expect("idempotent");
        assert_eq!(store.list_grants("default").await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn role_membership_grant_and_revoke() {
        let (store, _d) = setup().await;
        let admin = StoreGrantAdmin::new(Arc::clone(&store), None);

        admin
            .apply(
                "default",
                GrantDdl::GrantRole {
                    role: "analyst".into(),
                    user: "alice".into(),
                },
            )
            .await
            .expect("membership grant");
        assert_eq!(
            store.list_roles_for_user("default", "alice").await.unwrap(),
            vec!["analyst".to_string()]
        );

        assert!(matches!(
            admin
                .apply(
                    "default",
                    GrantDdl::RevokeRole {
                        role: "analyst".into(),
                        user: "alice".into(),
                    },
                )
                .await
                .unwrap(),
            GrantOutcome::Revoked
        ));
        // Revoking again → NoOp.
        assert!(matches!(
            admin
                .apply(
                    "default",
                    GrantDdl::RevokeRole {
                        role: "analyst".into(),
                        user: "alice".into(),
                    },
                )
                .await
                .unwrap(),
            GrantOutcome::NoOp
        ));
        assert!(store
            .list_roles_for_user("default", "alice")
            .await
            .unwrap()
            .is_empty());
    }

    /// F5b freshness: a `GRANT` through the admin must republish the live grant
    /// set into the wired `GrantEnforcer`, and a `REVOKE` must remove it — the
    /// mechanism that makes runtime grants take effect with no reconnect.
    #[tokio::test]
    async fn grant_then_revoke_republishes_live_enforcer() {
        use dataglot_policy::{AuthzMode, GrantEnforcer};

        let (store, _d) = setup().await;
        let enforcer = Arc::new(GrantEnforcer::new(AuthzMode::Grant));
        let admin = StoreGrantAdmin::new(Arc::clone(&store), Some(Arc::clone(&enforcer)));
        assert_eq!(enforcer.grant_count(), 0, "no grants at start");

        admin
            .apply(
                "acme",
                GrantDdl::GrantUsage {
                    catalog: "pg".into(),
                    grantee: "alice".into(),
                },
            )
            .await
            .expect("grant usage");
        admin
            .apply(
                "acme",
                GrantDdl::GrantSelect {
                    catalog: "pg".into(),
                    schema: "public".into(),
                    table: "users".into(),
                    grantee: "alice".into(),
                },
            )
            .await
            .expect("grant select");
        assert_eq!(
            enforcer.grant_count(),
            2,
            "both grants republished to the live enforcer"
        );

        admin
            .apply(
                "acme",
                GrantDdl::RevokeSelect {
                    catalog: "pg".into(),
                    schema: "public".into(),
                    table: "users".into(),
                    grantee: "alice".into(),
                },
            )
            .await
            .expect("revoke select");
        assert_eq!(
            enforcer.grant_count(),
            1,
            "revoke republishes the shrunken set"
        );
    }

    /// Cross-org persistence isolation (F4): a grant written under org A is
    /// never listed under org B, and vice-versa — the persistence-layer twin of
    /// the enforcer-level cross-org test (`grant.rs`
    /// `grant_in_one_org_does_not_authorize_same_name_in_another`) and the
    /// mirror of `policy_admin`'s `create_mask_persists_under_org_and_enforces`
    /// isolation assertion.
    #[tokio::test]
    async fn grant_written_under_one_org_is_not_listed_under_another() {
        let (store, _d) = setup().await;
        let admin = StoreGrantAdmin::new(Arc::clone(&store), None);

        // acme grants USAGE on pg to alice.
        admin
            .apply(
                "acme",
                GrantDdl::GrantUsage {
                    catalog: "pg".into(),
                    grantee: "alice".into(),
                },
            )
            .await
            .expect("acme grant");
        // beta grants SELECT on a different object to bob.
        admin
            .apply(
                "beta",
                GrantDdl::GrantSelect {
                    catalog: "pg".into(),
                    schema: "public".into(),
                    table: "orders".into(),
                    grantee: "bob".into(),
                },
            )
            .await
            .expect("beta grant");

        // Each org sees only its own grant.
        let acme = store.list_grants("acme").await.unwrap();
        assert_eq!(acme.len(), 1, "acme sees exactly its own grant");
        assert_eq!(acme[0].object(), GrantObject::Catalog("pg".into()));

        let beta = store.list_grants("beta").await.unwrap();
        assert_eq!(beta.len(), 1, "beta sees exactly its own grant");
        assert_eq!(
            beta[0].object(),
            GrantObject::Table {
                catalog: "pg".into(),
                schema: "public".into(),
                table: "orders".into(),
            }
        );

        // A third, untouched org sees nothing.
        assert!(store.list_grants("default").await.unwrap().is_empty());
    }

    /// Open mode: the admin still persists but has no enforcer to refresh
    /// (`None`) — the refresh path is a clean no-op, no panic.
    #[tokio::test]
    async fn open_mode_admin_persists_without_enforcer() {
        let (store, _d) = setup().await;
        let admin = StoreGrantAdmin::new(Arc::clone(&store), None);
        admin
            .apply(
                "default",
                GrantDdl::GrantUsage {
                    catalog: "pg".into(),
                    grantee: "alice".into(),
                },
            )
            .await
            .expect("persists in open mode");
        assert_eq!(store.list_grants("default").await.unwrap().len(), 1);
    }
}

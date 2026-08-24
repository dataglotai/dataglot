//! Read-only Control Plane view for the operational dashboard.
//!
//! Surfaces the **persisted control-plane state** — what the running server
//! actually knows — from the meta store ([`MetaStore`](dataglot_catalog::MetaStore):
//! embedded `RedbMetaStore` or Postgres `CatalogService`). The dashboard's other
//! governance surfaces show
//! a lineage graph + counts and a DDL runner; none lists the stored objects.
//! `GET /api/control-plane` fills that gap so an operator can answer "what
//! catalogs / users / roles / grants / policies / secrets exist right now?"
//! without opening `psql`.
//!
//! # Read-only + credential-safe (rule 12)
//!
//! Every field is read through the store's `list_*` methods. Secrets are listed
//! by **name only** (`list_secret_names`; the trait has no list-values path).
//! Users carry only `name` + `is_superuser` (`list_users`); the password hash is
//! reachable solely via `get_user` on the auth path and is **never** touched
//! here. No secret value or hash can cross this wire.
//!
//! # Scope
//!
//! Reads the **boot org** ( M1 is single-org; M2 threads the real
//! per-connection org). In distributed mode the meta store is coordinator-only,
//! so this is the one authoritative view (see `docs/meta-store.md`).

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;

use dataglot_catalog::store::{GrantObject, MetaStore};
use dataglot_core::CatalogBinding;

/// Router state: the meta store to read and the org to scope reads to.
#[derive(Clone)]
struct ControlPlaneState {
    store: Arc<dyn MetaStore>,
    org: String,
}

/// One catalog as shown in the panel — name + a rule-7-safe kind/endpoint
/// (never "Iceberg"; `endpoint_hint` is credential-redacted by contract).
#[derive(Serialize)]
struct CatalogView {
    name: String,
    kind: String,
    endpoint: String,
}

/// One user — name + admin flag. Deliberately no hash field.
#[derive(Serialize)]
struct UserView {
    name: String,
    is_superuser: bool,
}

/// One role + its members.
#[derive(Serialize)]
struct RoleView {
    name: String,
    members: Vec<String>,
}

/// One stored grant, flattened to readable tokens.
#[derive(Serialize)]
struct GrantView {
    grantee_kind: String,
    grantee: String,
    privilege: String,
    object: String,
}

/// One governance policy — name + kind (`mask` / `row_filter`).
#[derive(Serialize)]
struct PolicyView {
    name: String,
    kind: String,
}

/// One derived data product — name + where it materializes.
#[derive(Serialize)]
struct ProductView {
    name: String,
    catalog: Option<String>,
    schema: Option<String>,
}

/// The full read-only snapshot returned by `GET /api/control-plane`.
#[derive(Serialize)]
struct ControlPlaneView {
    /// The org these objects are scoped to (the boot org for now).
    org: String,
    catalogs: Vec<CatalogView>,
    /// Secret **names** only — never values.
    secrets: Vec<String>,
    users: Vec<UserView>,
    roles: Vec<RoleView>,
    grants: Vec<GrantView>,
    policies: Vec<PolicyView>,
    derived_products: Vec<ProductView>,
}

/// Rule-7-safe classification of a binding into `(kind, endpoint)` — the
/// `IcebergCache` variant is surfaced as a generic "warehouse", never "Iceberg".
fn classify(binding: &CatalogBinding) -> (String, String) {
    match binding {
        CatalogBinding::LiveConnector(b) => {
            let kind = serde_json::to_value(b.kind)
                .ok()
                .and_then(|v| v.as_str().map(String::from))
                .unwrap_or_else(|| "connector".to_string());
            (kind, b.endpoint_hint.clone())
        }
        CatalogBinding::IcebergCache(b) => ("warehouse".to_string(), b.warehouse.clone()),
        CatalogBinding::SemanticCatalog(_) => ("semantic".to_string(), String::new()),
    }
}

/// Gather the whole snapshot from the store. Any store error aborts with the
/// underlying structural message (never a stored value — rule 12).
async fn gather(store: &dyn MetaStore, org: &str) -> Result<ControlPlaneView, String> {
    let bindings = store.list_bindings(org).await.map_err(|e| e.to_string())?;
    let mut catalogs: Vec<CatalogView> = bindings
        .into_iter()
        .map(|(name, binding)| {
            let (kind, endpoint) = classify(&binding);
            CatalogView {
                name,
                kind,
                endpoint,
            }
        })
        .collect();
    catalogs.sort_by(|a, b| a.name.cmp(&b.name));

    let mut secrets = store
        .list_secret_names(org)
        .await
        .map_err(|e| e.to_string())?;
    secrets.sort();

    let mut users: Vec<UserView> = store
        .list_users(org)
        .await
        .map_err(|e| e.to_string())?
        .into_iter()
        .map(|u| UserView {
            name: u.name,
            is_superuser: u.is_superuser,
        })
        .collect();
    users.sort_by(|a, b| a.name.cmp(&b.name));

    let mut role_names = store.list_roles(org).await.map_err(|e| e.to_string())?;
    role_names.sort();
    let mut roles = Vec::with_capacity(role_names.len());
    for name in role_names {
        let members = store
            .list_role_members(org, &name)
            .await
            .map_err(|e| e.to_string())?;
        roles.push(RoleView { name, members });
    }

    let grants: Vec<GrantView> = store
        .list_grants(org)
        .await
        .map_err(|e| e.to_string())?
        .into_iter()
        .map(|g| {
            let object = match g.object() {
                GrantObject::Catalog(c) => c,
                GrantObject::Table {
                    catalog,
                    schema,
                    table,
                } => format!("{catalog}.{schema}.{table}"),
            };
            let grantee_kind = g.grantee_kind.as_str().to_string();
            let privilege = g.privilege().as_str().to_string();
            GrantView {
                grantee_kind,
                grantee: g.grantee,
                privilege,
                object,
            }
        })
        .collect();

    let mut policies: Vec<PolicyView> = store
        .list_policies(org)
        .await
        .map_err(|e| e.to_string())?
        .into_iter()
        .map(|p| PolicyView {
            name: p.name,
            kind: p.kind,
        })
        .collect();
    policies.sort_by(|a, b| a.name.cmp(&b.name));

    let mut derived_products: Vec<ProductView> = store
        .list_derived_products(org)
        .await
        .map_err(|e| e.to_string())?
        .into_iter()
        .map(|p| ProductView {
            name: p.name,
            catalog: p.catalog,
            schema: p.schema,
        })
        .collect();
    derived_products.sort_by(|a, b| a.name.cmp(&b.name));

    Ok(ControlPlaneView {
        org: org.to_string(),
        catalogs,
        secrets,
        users,
        roles,
        grants,
        policies,
        derived_products,
    })
}

/// `GET /api/control-plane` — the read-only snapshot, or `503` with a structural
/// error if the store read fails.
async fn control_plane_handler(State(state): State<ControlPlaneState>) -> impl IntoResponse {
    match gather(state.store.as_ref(), &state.org).await {
        Ok(view) => Json(view).into_response(),
        Err(msg) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "error": msg })),
        )
            .into_response(),
    }
}

/// Build the `/api/control-plane` router over a live meta store. Merged into the
/// observability router only when a `catalog_service` is configured; without one
/// the route is absent and the dashboard tab renders its "not configured" state.
pub fn router(store: Arc<dyn MetaStore>, org: String) -> Router {
    Router::new()
        .route("/api/control-plane", get(control_plane_handler))
        .with_state(ControlPlaneState { store, org })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use dataglot_catalog::store::{GrantRecord, GranteeKind};
    use dataglot_catalog::EmbeddedMetaStore;
    use dataglot_core::catalog::{CatalogBinding, LiveConnectorBinding, LiveConnectorKind};
    use tower::ServiceExt;

    fn pg(host: &str) -> CatalogBinding {
        CatalogBinding::LiveConnector(LiveConnectorBinding {
            kind: LiveConnectorKind::Postgres,
            endpoint_hint: host.to_string(),
        })
    }

    async fn seeded_store() -> Arc<dyn MetaStore> {
        let dir = tempfile::tempdir().unwrap();
        let store = EmbeddedMetaStore::open(dir.path().join("meta.json"), "default")
            .await
            .unwrap();
        store
            .upsert_binding("default", "pg", &pg("db.internal:5432"))
            .await
            .unwrap();
        store
            .put_secret("default", "pg_dsn", b"ciphertext")
            .await
            .unwrap();
        store
            .put_user("default", "alice", Some("argon2$hash"), true)
            .await
            .unwrap();
        store.put_role("default", "analyst").await.unwrap();
        store
            .add_role_member("default", "analyst", "alice")
            .await
            .unwrap();
        store
            .put_grant(
                "default",
                &GrantRecord::usage(GranteeKind::Role, "analyst", "pg"),
            )
            .await
            .unwrap();
        // Keep the tempdir alive for the store's lifetime by leaking it — the
        // test process is short-lived and this avoids a use-after-free of the
        // backing file across the awaits below.
        std::mem::forget(dir);
        Arc::new(store)
    }

    #[tokio::test]
    async fn snapshot_lists_objects_and_hides_secret_values() {
        let store = seeded_store().await;
        let app = router(store, "default".to_string());
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/control-plane")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

        assert_eq!(v["org"], "default");
        assert_eq!(v["catalogs"][0]["name"], "pg");
        assert_eq!(v["catalogs"][0]["kind"], "postgres");
        assert_eq!(v["catalogs"][0]["endpoint"], "db.internal:5432");
        // Secrets: names only, and the ciphertext value never appears anywhere.
        assert_eq!(v["secrets"][0], "pg_dsn");
        assert_eq!(v["users"][0]["name"], "alice");
        assert_eq!(v["users"][0]["is_superuser"], true);
        assert_eq!(v["roles"][0]["name"], "analyst");
        assert_eq!(v["roles"][0]["members"][0], "alice");
        assert_eq!(v["grants"][0]["grantee"], "analyst");
        assert_eq!(v["grants"][0]["privilege"], "USAGE");
        assert_eq!(v["grants"][0]["object"], "pg");

        // Rule 12: no hash, no plaintext/ciphertext value in the whole payload.
        let raw = String::from_utf8(bytes.to_vec()).unwrap();
        assert!(
            !raw.contains("argon2"),
            "password hash must never be serialized"
        );
        assert!(
            !raw.contains("ciphertext"),
            "secret value must never be serialized"
        );
    }
}

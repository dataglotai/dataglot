//! Policy-explainability HTTP endpoint — Phase 3 "why was this column
//! masked?" surface.
//!
//! A small sibling axum server (same shape as [`crate::webhook`]) exposing
//! `POST /policy/explain`. Given a SQL string and an optional `user`, it
//! resolves the session identity (the same [`resolve_identity_with_roles`]
//! the pgwire startup path uses), plans the SQL, and reports the policy
//! decisions that would apply — **without executing** the query — via
//! [`dataglot_policy::PolicyEnforcer::explain`].
//!
//! # Why an endpoint (not a pgwire `EXPLAIN POLICY` statement)
//!
//! CLAUDE.md rule 4 forbids `dataglot-pgwire` depending on
//! `dataglot-policy` (no lateral deps), so a native `EXPLAIN POLICY`
//! statement can't reach the enforcer from the wire handler. The endpoint
//! lives in `dataglot-server`, which already owns both the `SessionContext`
//! and the enforcer — and it adds a capability the pgwire surface can't:
//! an admin can ask "what would **alice** see for this query?" without
//! connecting as her (`{"sql": "...", "user": "alice"}`).
//!
//! ```text
//! curl -s localhost:9092/policy/explain \
//!   -H 'content-type: application/json' \
//!   -d '{"sql":"SELECT email FROM users","user":"alice"}'
//! ```

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use datafusion::prelude::SessionContext;
use dataglot_policy::PolicyEnforcer;
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tokio::sync::broadcast;

use crate::config::{resolve_identity_with_roles, IdentityProfileConfig, RoleConfig};

/// Configuration for the policy-explain HTTP endpoint. Omitting the block
/// keeps the server identical to before (no endpoint bound).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyExplainConfig {
    /// Address to bind the policy-explain HTTP server to.
    pub addr: SocketAddr,
    /// Name of the environment variable holding a **bearer token** that
    /// callers must present as `Authorization: Bearer <token>`. The
    /// token itself never appears in config (rule 12) — only the env-var
    /// name. `None` ⇒ the endpoint is **unauthenticated** (a boot warning
    /// is logged): it discloses which columns are masked and any user's
    /// group memberships, so leave it unset only on a trusted network.
    #[serde(default)]
    pub token_env: Option<String>,
}

/// Request body for `POST /policy/explain`.
#[derive(Debug, Deserialize)]
pub struct ExplainRequest {
    /// The query to explain (planned, never executed).
    pub sql: String,
    /// Identity to evaluate the policy for; omitted/empty ⇒ anonymous.
    #[serde(default)]
    pub user: Option<String>,
}

/// One decision in the response (JSON projection of
/// [`dataglot_policy::PolicyDecision`]).
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct DecisionJson {
    /// `"mask"` | `"row_filter"` | `"deny"`.
    pub action: String,
    /// Affected resource — `"table"` or `"table.column"`.
    pub resource: String,
    /// Human-readable detail.
    pub detail: String,
}

/// Response body for `POST /policy/explain`.
#[derive(Debug, Serialize)]
pub struct ExplainResponse {
    /// The resolved user (echoed back), `null` for anonymous.
    pub user: Option<String>,
    /// The resolved effective groups (incl. folded roles).
    pub groups: Vec<String>,
    /// Policy decisions that apply to the query under this identity.
    pub decisions: Vec<DecisionJson>,
}

/// Shared state for the endpoint. All fields are cheaply clonable.
#[derive(Clone)]
struct ExplainState {
    ctx: Arc<SessionContext>,
    enforcer: Arc<dyn PolicyEnforcer>,
    identities: Arc<HashMap<String, IdentityProfileConfig>>,
    roles: Arc<HashMap<String, RoleConfig>>,
    /// Expected bearer token (the resolved secret), or `None` when the
    /// endpoint runs unauthenticated. Never rendered — no `Debug`.
    token: Option<Arc<str>>,
}

/// Constant-length credential check: does `Authorization: Bearer <token>`
/// match the expected token? Compares SHA-256 digests so the comparison
/// is fixed-width regardless of token length (no length/content timing
/// leak). `None` expected ⇒ always authorized (unauthenticated endpoint).
fn authorized(expected: Option<&str>, headers: &axum::http::HeaderMap) -> bool {
    use sha2::{Digest, Sha256};
    let Some(expected) = expected else {
        return true;
    };
    // The HTTP auth scheme is case-insensitive (RFC 7235), so accept
    // any casing of "Bearer" (and tolerate extra spaces after it).
    let provided = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split_once(' '))
        .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("Bearer"))
        .map(|(_, token)| token.trim_start());
    let Some(provided) = provided else {
        return false;
    };
    // 32-byte digests — `==` on the fixed-width arrays doesn't leak the
    // token's length or a matching-prefix position.
    Sha256::digest(provided.as_bytes()) == Sha256::digest(expected.as_bytes())
}

/// Handle returned by [`spawn_policy_explain_server`].
#[derive(Debug)]
pub struct PolicyExplainServerHandle {
    /// Background task running `axum::serve`.
    pub join: tokio::task::JoinHandle<()>,
    /// The actual bound address (differs from `cfg.addr` only when the
    /// configured port was `0` — used by tests for ephemeral ports).
    pub bound: SocketAddr,
}

/// Compute the explain response for a request. Split out of the axum
/// handler so it's unit-testable without binding a listener.
///
/// # Errors
/// Returns a human-readable message if the SQL fails to plan.
async fn compute_explain(
    state: &ExplainState,
    req: &ExplainRequest,
) -> Result<ExplainResponse, String> {
    let identity = resolve_identity_with_roles(
        req.user.as_deref().unwrap_or(""),
        &state.identities,
        &state.roles,
    );
    let plan = state
        .ctx
        .state()
        .create_logical_plan(&req.sql)
        .await
        .map_err(|e| format!("could not plan SQL: {e}"))?;
    let decisions = state
        .enforcer
        .explain(&plan, &identity)
        .into_iter()
        .map(|d| DecisionJson {
            action: d.action.as_str().to_string(),
            resource: d.resource,
            detail: d.detail,
        })
        .collect();
    Ok(ExplainResponse {
        user: identity.user,
        groups: identity.org_groups,
        decisions,
    })
}

async fn handle_explain(
    State(state): State<ExplainState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<ExplainRequest>,
) -> Response {
    if !authorized(state.token.as_deref(), &headers) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "missing or invalid bearer token" })),
        )
            .into_response();
    }
    match compute_explain(&state, &req).await {
        Ok(resp) => Json(resp).into_response(),
        Err(msg) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": msg })),
        )
            .into_response(),
    }
}

fn build_router(state: ExplainState) -> Router {
    Router::new()
        .route("/policy/explain", post(handle_explain))
        .with_state(state)
}

/// Spawn the policy-explain HTTP server on a tokio task. Mirrors
/// [`crate::webhook::spawn_webhook_server`].
///
/// # Errors
/// The listener fails to bind `cfg.addr`.
#[allow(clippy::implicit_hasher)] // identities/roles come from config's std HashMap
pub async fn spawn_policy_explain_server(
    cfg: &PolicyExplainConfig,
    ctx: Arc<SessionContext>,
    enforcer: Arc<dyn PolicyEnforcer>,
    identities: Arc<HashMap<String, IdentityProfileConfig>>,
    roles: Arc<HashMap<String, RoleConfig>>,
    mut shutdown: broadcast::Receiver<()>,
) -> Result<PolicyExplainServerHandle> {
    let listener = TcpListener::bind(cfg.addr)
        .await
        .with_context(|| format!("Failed to bind policy-explain server to {}", cfg.addr))?;
    let bound = listener.local_addr().unwrap_or(cfg.addr);

    // Resolve the bearer token (rule 12: only the env-var name is in
    // config). Fail-safe: configuring `token_env` signals intent to
    // authenticate, so an unset/empty variable is a hard boot error —
    // never a silent downgrade to an open endpoint. Only the *absence*
    // of `token_env` runs unauthenticated (with a loud warning).
    let token: Option<Arc<str>> = match cfg.token_env.as_deref() {
        None => {
            tracing::warn!(
                "policy-explain endpoint is UNAUTHENTICATED (no policy_explain.token_env): \
                 it discloses masked columns and user group memberships to anyone who can \
                 reach {bound}. Set token_env, or bind to a trusted network only."
            );
            None
        }
        Some(name) => match std::env::var(name).ok().filter(|v| !v.is_empty()) {
            Some(tok) => Some(Arc::from(tok.as_str())),
            None => anyhow::bail!(
                "policy_explain.token_env {name:?} is set but the environment variable is \
                 unset or empty — refusing to start the endpoint unauthenticated (fail-safe)"
            ),
        },
    };

    let router = build_router(ExplainState {
        ctx,
        enforcer,
        identities,
        roles,
        token,
    });

    tracing::info!(%bound, "Policy-explain endpoint listening");

    let join = tokio::spawn(async move {
        let serve = axum::serve(listener, router).with_graceful_shutdown(async move {
            let _ = shutdown.recv().await;
        });
        if let Err(err) = serve.await {
            tracing::error!(error = %err, "Policy-explain endpoint exited with error");
        } else {
            tracing::info!("Policy-explain endpoint stopped");
        }
    });

    Ok(PolicyExplainServerHandle { join, bound })
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Arc;

    use datafusion::arrow::array::{ArrayRef, Int32Array, RecordBatch, StringArray};
    use datafusion::arrow::datatypes::{DataType, Field, Schema};
    use datafusion::datasource::MemTable;
    use datafusion::logical_expr::lit;
    use datafusion::sql::TableReference;
    use dataglot_policy::{
        AccessDenial, AccessDenyEnforcer, ColumnMask, ColumnMaskingEnforcer, CompositeEnforcer,
    };

    fn state() -> ExplainState {
        let schema = Arc::new(Schema::new(vec![
            Field::new("id", DataType::Int32, false),
            Field::new("email", DataType::Utf8, false),
            Field::new("dept", DataType::Utf8, false),
        ]));
        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(Int32Array::from(vec![1])) as ArrayRef,
                Arc::new(StringArray::from(vec!["a@x.com"])) as ArrayRef,
                Arc::new(StringArray::from(vec!["eng"])) as ArrayRef,
            ],
        )
        .unwrap();
        let ctx = SessionContext::new();
        ctx.register_table(
            "users",
            Arc::new(MemTable::try_new(schema, vec![vec![batch]]).unwrap()),
        )
        .unwrap();

        let masks = ColumnMaskingEnforcer::new([ColumnMask {
            table: TableReference::bare("users"),
            column: "email".into(),
            mask: lit("***"),
            org: None,
            groups: None,
        }])
        .unwrap();
        let denials = AccessDenyEnforcer::new([AccessDenial {
            table: TableReference::bare("users"),
            column: Some("dept".into()),
            groups: vec!["contractor".into()],
        }]);
        let enforcer: Arc<dyn PolicyEnforcer> = Arc::new(CompositeEnforcer::new(vec![
            Arc::new(denials),
            Arc::new(masks),
        ]));

        let mut identities = HashMap::new();
        identities.insert(
            "carol".to_string(),
            IdentityProfileConfig {
                org: None,
                groups: vec!["contractor".into()],
                password_env: None,
            },
        );

        ExplainState {
            ctx: Arc::new(ctx),
            enforcer,
            identities: Arc::new(identities),
            roles: Arc::new(HashMap::new()),
            token: None,
        }
    }

    fn bearer(token: &str) -> axum::http::HeaderMap {
        let mut h = axum::http::HeaderMap::new();
        h.insert(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {token}").parse().unwrap(),
        );
        h
    }

    #[test]
    fn unauthenticated_endpoint_allows_any_request() {
        // token = None ⇒ open (with a boot warning elsewhere).
        assert!(authorized(None, &axum::http::HeaderMap::new()));
    }

    #[test]
    fn bearer_token_is_enforced() {
        let expected = Some("s3cret-token");
        assert!(
            authorized(expected, &bearer("s3cret-token")),
            "correct token"
        );
        assert!(!authorized(expected, &bearer("wrong")), "wrong token");
        assert!(
            !authorized(expected, &axum::http::HeaderMap::new()),
            "missing header"
        );
        // A bare token without the `Bearer ` scheme is rejected.
        let mut h = axum::http::HeaderMap::new();
        h.insert(
            axum::http::header::AUTHORIZATION,
            "s3cret-token".parse().unwrap(),
        );
        assert!(!authorized(expected, &h), "missing Bearer scheme");

        // The scheme is case-insensitive (RFC 7235).
        let mut lower = axum::http::HeaderMap::new();
        lower.insert(
            axum::http::header::AUTHORIZATION,
            "bearer s3cret-token".parse().unwrap(),
        );
        assert!(authorized(expected, &lower), "lowercase bearer scheme");
    }

    #[tokio::test]
    async fn explains_mask_and_group_scoped_deny() {
        let s = state();
        let resp = compute_explain(
            &s,
            &ExplainRequest {
                sql: "SELECT email, dept FROM users".into(),
                user: Some("carol".into()),
            },
        )
        .await
        .expect("plans");
        assert_eq!(resp.user.as_deref(), Some("carol"));
        assert!(resp.groups.iter().any(|g| g == "contractor"));
        assert!(resp
            .decisions
            .iter()
            .any(|d| d.action == "mask" && d.resource == "users.email"));
        assert!(resp
            .decisions
            .iter()
            .any(|d| d.action == "deny" && d.resource == "users.dept"));
    }

    #[tokio::test]
    async fn anonymous_sees_mask_but_not_group_scoped_deny() {
        let s = state();
        let resp = compute_explain(
            &s,
            &ExplainRequest {
                sql: "SELECT email, dept FROM users".into(),
                user: None,
            },
        )
        .await
        .expect("plans");
        assert!(resp.decisions.iter().any(|d| d.action == "mask"));
        assert!(
            !resp.decisions.iter().any(|d| d.action == "deny"),
            "anonymous is not a contractor: {:?}",
            resp.decisions
        );
    }

    #[tokio::test]
    async fn bad_sql_is_an_error() {
        let s = state();
        let err = compute_explain(
            &s,
            &ExplainRequest {
                sql: "SELECT * FROM does_not_exist".into(),
                user: None,
            },
        )
        .await
        .unwrap_err();
        assert!(err.contains("could not plan SQL"), "{err}");
    }
}

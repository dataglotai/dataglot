//! Bearer-token check for the HTTP API (`/api/*`) on the metrics address.
//!
//! Every `/api/*` request goes through [`authorize`], so another scheme (the
//! engine's JWT auth, say) can be added there without touching the handlers.
//! `/metrics`, `/health`, `/lineage` and `/ui` are not checked.
//!
//! - `observability.api_token_env` names the variable holding the full-access
//!   token. `api_read_token_env` optionally adds a read-only one.
//! - GET and HEAD need either token. Anything else (cancel, probe) needs the
//!   full token.
//! - With no token, everything stays open on a loopback address, as before.
//!   On any other address reads stay open (with a boot warning) and writes
//!   get 403.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{bail, Result};
use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};

use crate::observability::ObservabilityConfig;

/// Resolved `/api/*` tokens. Holds the secrets themselves, so no `Debug`.
#[derive(Clone, Default)]
pub struct ApiAuth {
    full: Option<Arc<str>>,
    read: Option<Arc<str>>,
}

impl ApiAuth {
    /// Read the tokens named by `api_token_env` and `api_read_token_env`.
    ///
    /// # Errors
    /// A named variable is unset or empty, or `api_read_token_env` is set
    /// without `api_token_env`.
    pub fn from_config(cfg: &ObservabilityConfig) -> Result<Self> {
        if cfg.api_read_token_env.is_some() && cfg.api_token_env.is_none() {
            bail!(
                "observability.api_read_token_env needs observability.api_token_env as well; \
                 without a full-access token nothing could cancel queries"
            );
        }
        Ok(Self {
            full: token_from_env("api_token_env", cfg.api_token_env.as_deref())?,
            read: token_from_env("api_read_token_env", cfg.api_read_token_env.as_deref())?,
        })
    }
}

// Same rule as `policy_explain.token_env`: naming a variable means a token is
// wanted, so an unset or empty one stops the boot instead of leaving /api open.
fn token_from_env(field: &str, name: Option<&str>) -> Result<Option<Arc<str>>> {
    let Some(name) = name else {
        return Ok(None);
    };
    match std::env::var(name) {
        Ok(v) if !v.is_empty() => Ok(Some(Arc::from(v))),
        _ => bail!(
            "observability.{field} {name:?} is set but the environment variable is unset or \
             empty; refusing to serve /api without it"
        ),
    }
}

#[derive(Clone)]
struct Guard {
    auth: ApiAuth,
    loopback: bool,
}

#[derive(Debug, PartialEq, Eq)]
enum Denied {
    /// Missing or wrong token.
    BadToken,
    /// The read-only token on a write.
    ReadOnly,
    /// A write with no token configured, on a non-loopback address.
    NoTokenConfigured,
}

impl IntoResponse for Denied {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            Self::BadToken => (StatusCode::UNAUTHORIZED, "missing or invalid bearer token"),
            Self::ReadOnly => (
                StatusCode::FORBIDDEN,
                "this token is read-only; cancel and probe need the api_token_env token",
            ),
            Self::NoTokenConfigured => (
                StatusCode::FORBIDDEN,
                "writes to /api are disabled on a non-loopback address without a token; \
                 set observability.api_token_env",
            ),
        };
        let mut resp = (status, Json(serde_json::json!({ "error": message }))).into_response();
        if status == StatusCode::UNAUTHORIZED {
            resp.headers_mut().insert(
                header::WWW_AUTHENTICATE,
                header::HeaderValue::from_static("Bearer"),
            );
        }
        resp
    }
}

/// Put the `/api/*` check in front of `router`. `bound` is the address the
/// listener actually got; without a token it decides whether writes are
/// allowed.
pub fn protect(router: Router, auth: ApiAuth, bound: SocketAddr) -> Router {
    let loopback = bound.ip().is_loopback();
    if auth.full.is_none() && !loopback {
        tracing::warn!(
            "/api on {bound} has no token (observability.api_token_env): anyone who can reach \
             it can list sessions and query text. Cancel and probe are refused until a token \
             is set."
        );
    }
    router.layer(middleware::from_fn_with_state(
        Guard { auth, loopback },
        authorize_api,
    ))
}

async fn authorize_api(State(guard): State<Guard>, req: Request, next: Next) -> Response {
    if !req.uri().path().starts_with("/api/") {
        return next.run(req).await;
    }
    match authorize(&guard, req.method(), req.headers()) {
        Ok(()) => next.run(req).await,
        Err(denied) => denied.into_response(),
    }
}

fn authorize(guard: &Guard, method: &Method, headers: &HeaderMap) -> Result<(), Denied> {
    let write = !matches!(*method, Method::GET | Method::HEAD);
    let Some(full) = guard.auth.full.as_deref() else {
        return if write && !guard.loopback {
            Err(Denied::NoTokenConfigured)
        } else {
            Ok(())
        };
    };
    if bearer_matches(full, headers) {
        return Ok(());
    }
    let read_ok = guard
        .auth
        .read
        .as_deref()
        .is_some_and(|read| bearer_matches(read, headers));
    match (read_ok, write) {
        (true, false) => Ok(()),
        (true, true) => Err(Denied::ReadOnly),
        (false, _) => Err(Denied::BadToken),
    }
}

// The explain endpoint's check: compares SHA-256 digests, so the time taken
// doesn't depend on how much of the token matched.
fn bearer_matches(expected: &str, headers: &HeaderMap) -> bool {
    crate::policy_explain::authorized(Some(expected), headers)
}

#[cfg(test)]
mod tests {
    use super::*;

    use axum::body::Body;
    use axum::routing::{get, post};
    use tower::ServiceExt;

    fn auth(full: Option<&str>, read: Option<&str>) -> ApiAuth {
        ApiAuth {
            full: full.map(Arc::from),
            read: read.map(Arc::from),
        }
    }

    fn router(auth: ApiAuth, bound: &str) -> Router {
        let router = Router::new()
            .route("/metrics", get(|| async { "metrics" }))
            .route("/api/queries", get(|| async { "[]" }))
            .route("/api/queries/{id}/cancel", post(|| async { "cancelled" }))
            .route("/api/connectors/{name}/probe", post(|| async { "probed" }));
        protect(router, auth, bound.parse().unwrap())
    }

    async fn status(router: &Router, method: &str, path: &str, token: Option<&str>) -> StatusCode {
        let mut req = Request::builder().method(method).uri(path);
        if let Some(token) = token {
            req = req.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        router
            .clone()
            .oneshot(req.body(Body::empty()).unwrap())
            .await
            .unwrap()
            .status()
    }

    #[tokio::test]
    async fn no_token_on_loopback_keeps_everything_open() {
        let r = router(ApiAuth::default(), "127.0.0.1:9090");
        assert_eq!(
            status(&r, "GET", "/api/queries", None).await,
            StatusCode::OK
        );
        assert_eq!(
            status(&r, "POST", "/api/queries/q1/cancel", None).await,
            StatusCode::OK
        );
        let r = router(ApiAuth::default(), "[::1]:9090");
        assert_eq!(
            status(&r, "POST", "/api/connectors/pg/probe", None).await,
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn no_token_elsewhere_allows_reads_and_refuses_writes() {
        let r = router(ApiAuth::default(), "0.0.0.0:9090");
        assert_eq!(
            status(&r, "GET", "/api/queries", None).await,
            StatusCode::OK
        );
        assert_eq!(
            status(&r, "HEAD", "/api/queries", None).await,
            StatusCode::OK
        );
        assert_eq!(
            status(&r, "POST", "/api/queries/q1/cancel", None).await,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            status(&r, "POST", "/api/connectors/pg/probe", None).await,
            StatusCode::FORBIDDEN
        );
    }

    #[tokio::test]
    async fn the_403_says_what_to_set() {
        let r = router(ApiAuth::default(), "0.0.0.0:9090");
        let req = Request::post("/api/queries/q1/cancel")
            .body(Body::empty())
            .unwrap();
        let resp = r.oneshot(req).await.unwrap();
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert!(body.contains("observability.api_token_env"), "{body}");
    }

    #[tokio::test]
    async fn full_token_is_needed_for_everything_under_api() {
        let r = router(auth(Some("full-tok"), None), "0.0.0.0:9090");
        assert_eq!(
            status(&r, "GET", "/api/queries", None).await,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            status(&r, "GET", "/api/queries", Some("nope")).await,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            status(&r, "GET", "/api/queries", Some("full-tok")).await,
            StatusCode::OK
        );
        assert_eq!(
            status(&r, "POST", "/api/queries/q1/cancel", Some("full-tok")).await,
            StatusCode::OK
        );
        // On loopback too: a configured token is always required.
        let r = router(auth(Some("full-tok"), None), "127.0.0.1:9090");
        assert_eq!(
            status(&r, "GET", "/api/queries", None).await,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            status(&r, "POST", "/api/queries/q1/cancel", None).await,
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn read_token_reads_but_cannot_cancel_or_probe() {
        let r = router(auth(Some("full-tok"), Some("read-tok")), "0.0.0.0:9090");
        assert_eq!(
            status(&r, "GET", "/api/queries", Some("read-tok")).await,
            StatusCode::OK
        );
        assert_eq!(
            status(&r, "POST", "/api/queries/q1/cancel", Some("read-tok")).await,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            status(&r, "POST", "/api/connectors/pg/probe", Some("read-tok")).await,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            status(&r, "POST", "/api/connectors/pg/probe", Some("full-tok")).await,
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn a_401_asks_for_a_bearer_token() {
        let r = router(auth(Some("full-tok"), None), "0.0.0.0:9090");
        let resp = r
            .oneshot(Request::get("/api/queries").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(resp.headers()[header::WWW_AUTHENTICATE], "Bearer");
    }

    #[tokio::test]
    async fn metrics_stays_open() {
        let r = router(auth(Some("full-tok"), None), "0.0.0.0:9090");
        assert_eq!(status(&r, "GET", "/metrics", None).await, StatusCode::OK);
    }

    #[tokio::test]
    async fn other_spellings_of_the_path_do_not_get_past_the_check() {
        let r = router(auth(Some("full-tok"), None), "0.0.0.0:9090");
        for path in [
            "//api/queries",
            "/API/queries",
            "/%61pi/queries",
            "/metrics/../api/queries",
        ] {
            let got = status(&r, "GET", path, None).await;
            assert_ne!(got, StatusCode::OK, "{path} answered without a token");
        }
    }

    #[test]
    fn read_token_alone_is_a_config_error() {
        let cfg = ObservabilityConfig {
            api_read_token_env: Some("DATAGLOT_TEST_UNUSED_READ_TOKEN".into()),
            ..ObservabilityConfig::default()
        };
        let err = ApiAuth::from_config(&cfg).err().expect("should be refused");
        assert!(err.to_string().contains("api_token_env"), "{err}");
    }

    #[test]
    fn a_named_but_unset_variable_is_a_config_error() {
        let cfg = ObservabilityConfig {
            api_token_env: Some("DATAGLOT_TEST_SURELY_UNSET_API_TOKEN".into()),
            ..ObservabilityConfig::default()
        };
        let err = ApiAuth::from_config(&cfg).err().expect("should be refused");
        assert!(
            err.to_string()
                .contains("DATAGLOT_TEST_SURELY_UNSET_API_TOKEN"),
            "{err}"
        );
    }

    #[test]
    fn no_names_means_no_tokens() {
        let auth = ApiAuth::from_config(&ObservabilityConfig::default()).unwrap();
        assert!(auth.full.is_none() && auth.read.is_none());
    }
}

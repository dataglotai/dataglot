//! OAuth 2.0 client-credentials token acquisition for the REST connector
//!. Turns a client id/secret into a live bearer token, cached and
//! refreshed before expiry — e.g. Salesforce's
//! `https://login.salesforce.com/services/oauth2/token`.
//!
//! This is the connector authenticating to its *source* (not the enterprise
//! ingress auth of ). The secret is resolved from config by the caller
//! (env indirection), and never logged (CLAUDE.md rule 12).

use std::fmt;
use std::time::{Duration, Instant};

use reqwest::Client;
use tokio::sync::Mutex;

use dataglot_core::{DataglotError, Result as DataglotResult};

/// OAuth 2.0 client-credentials configuration: where to get a token and the
/// client credentials to present.
#[derive(Clone)]
pub struct OAuth2Config {
    /// Token endpoint, e.g.
    /// `https://login.salesforce.com/services/oauth2/token`.
    pub token_url: String,
    /// OAuth client id.
    pub client_id: String,
    /// OAuth client secret (never logged / rendered).
    pub client_secret: String,
    /// Extra form params sent with the grant (e.g. `("scope", "api")`).
    pub extra_params: Vec<(String, String)>,
}

impl fmt::Debug for OAuth2Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never render the client secret (rule 12).
        f.debug_struct("OAuth2Config")
            .field("token_url", &self.token_url)
            .field("client_id", &self.client_id)
            .field("client_secret", &"<redacted>")
            .field("extra_params", &self.extra_params)
            .finish()
    }
}

/// A cached bearer token and when it stops being usable.
struct CachedToken {
    token: String,
    expires_at: Instant,
}

/// Acquires and caches an OAuth 2.0 access token via the client-credentials
/// grant, refreshing it before expiry. Shared (behind an `Arc`) across a
/// connector's tables so one token serves the whole source.
pub struct OAuth2TokenCache {
    http: Client,
    config: OAuth2Config,
    cached: Mutex<Option<CachedToken>>,
}

impl fmt::Debug for OAuth2TokenCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The cached token is a live secret — never render it (rule 12).
        f.debug_struct("OAuth2TokenCache")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl OAuth2TokenCache {
    /// Build a cache over an existing HTTP client.
    #[must_use]
    pub fn new(http: Client, config: OAuth2Config) -> Self {
        Self {
            http,
            config,
            cached: Mutex::new(None),
        }
    }

    /// Return a valid bearer token, fetching or refreshing as needed. A 30s
    /// skew margin means a token about to expire is refreshed rather than
    /// presented mid-request.
    ///
    /// # Errors
    /// [`DataglotError`] if the token endpoint is unreachable, returns an error
    /// status, or its response carries no `access_token`.
    pub async fn bearer(&self) -> DataglotResult<String> {
        const SKEW: Duration = Duration::from_secs(30);
        // Fast path: return a still-valid cached token, releasing the lock
        // before any network work.
        {
            let guard = self.cached.lock().await;
            if let Some(t) = guard.as_ref() {
                if t.expires_at > Instant::now() + SKEW {
                    return Ok(t.token.clone());
                }
            }
        }
        // Slow path: fetch a fresh token WITHOUT holding the lock, then store
        // it. A rare concurrent double-fetch on a cold cache is harmless — both
        // callers get a valid token and the last write wins.
        let (token, expires_in) = self.fetch().await?;
        *self.cached.lock().await = Some(CachedToken {
            token: token.clone(),
            expires_at: Instant::now() + Duration::from_secs(expires_in),
        });
        Ok(token)
    }

    /// POST the client-credentials grant and parse `access_token` / `expires_in`.
    async fn fetch(&self) -> DataglotResult<(String, u64)> {
        // Form-encode the grant body via `Url::query_pairs_mut` (dummy base) —
        // proper `application/x-www-form-urlencoded` without an extra crate.
        let mut form = reqwest::Url::parse("http://form.local/")
            .map_err(|e| DataglotError::catalog(format!("OAuth2 form encode failed: {e}")))?;
        {
            let mut pairs = form.query_pairs_mut();
            pairs.append_pair("grant_type", "client_credentials");
            pairs.append_pair("client_id", &self.config.client_id);
            pairs.append_pair("client_secret", &self.config.client_secret);
            for (k, v) in &self.config.extra_params {
                pairs.append_pair(k, v);
            }
        }
        let body = form.query().unwrap_or_default().to_string();
        let resp = self
            .http
            .post(&self.config.token_url)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(body)
            .send()
            .await
            .map_err(|e| DataglotError::connection(format!("OAuth2 token request failed: {e}")))?
            .error_for_status()
            .map_err(|e| {
                DataglotError::catalog(format!("OAuth2 token endpoint returned an error: {e}"))
            })?;
        let body = resp.text().await.map_err(|e| {
            DataglotError::connection(format!("reading OAuth2 token response: {e}"))
        })?;
        let v: serde_json::Value = serde_json::from_str(&body).map_err(|e| {
            DataglotError::catalog(format!("OAuth2 token response is not valid JSON: {e}"))
        })?;
        let token = v
            .get("access_token")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                DataglotError::catalog("OAuth2 token response has no `access_token`".to_string())
            })?
            .to_string();
        // Salesforce includes `expires_in`; default to 1h if a provider omits it.
        let expires_in = v
            .get("expires_in")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(3600);
        Ok((token, expires_in))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn config_debug_never_leaks_secret() {
        let cfg = OAuth2Config {
            token_url: "https://login.example.com/services/oauth2/token".into(),
            client_id: "3MVG9...".into(),
            client_secret: "super-secret-value".into(),
            extra_params: vec![],
        };
        let printed = format!("{cfg:?}");
        assert!(printed.contains("login.example.com"));
        assert!(
            !printed.contains("super-secret-value"),
            "secret leaked: {printed}"
        );
    }

    #[tokio::test]
    async fn fetches_then_caches_the_token() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/services/oauth2/token"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(r#"{"access_token":"tok-123","expires_in":3600}"#),
            )
            .mount(&server)
            .await;

        let cache = OAuth2TokenCache::new(
            Client::new(),
            OAuth2Config {
                token_url: format!("{}/services/oauth2/token", server.uri()),
                client_id: "cid".into(),
                client_secret: "csecret".into(),
                extra_params: vec![],
            },
        );

        assert_eq!(cache.bearer().await.expect("first"), "tok-123");
        // A second call is served from cache — the token endpoint is hit once.
        assert_eq!(cache.bearer().await.expect("second"), "tok-123");
        let hits = server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|r| r.url.path() == "/services/oauth2/token")
            .count();
        assert_eq!(hits, 1, "token should be fetched once and cached");
    }

    #[tokio::test]
    async fn errors_when_response_has_no_access_token() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string(r#"{"error":"invalid_client"}"#),
            )
            .mount(&server)
            .await;
        let cache = OAuth2TokenCache::new(
            Client::new(),
            OAuth2Config {
                token_url: format!("{}/token", server.uri()),
                client_id: "cid".into(),
                client_secret: "csecret".into(),
                extra_params: vec![],
            },
        );
        assert!(cache.bearer().await.is_err());
    }
}

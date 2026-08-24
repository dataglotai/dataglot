//! Inbound governance webhook — Phase 2 spec 04 slice 1.
//!
//! HTTP receiver for the Interface 3 policy-ingestion event stream
//! (defined in the phase-2 `inbound-governance-integration` plan)
//! from a governance platform's Actions Framework (`DataHub` Actions,
//! Informatica IDMC, etc.). Operators wire `[webhook]` in
//! `dataglot.toml`; the server boots a sibling axum task on its own
//! `SocketAddr` so the webhook's auth posture (HMAC) and exposure
//! (governance-platform network) stay independent of the metrics
//! endpoint.
//!
//! # Why a separate axum server (not a `/v1/events` route on /metrics)
//!
//! Mirrors the architectural decision in spec 04 §"Webhook HTTP server
//! placement": the metrics endpoint is unauthenticated and intended
//! for an internal Prometheus scrape; the webhook receives requests
//! from a governance platform that may sit on a different network and
//! must authenticate every call. Sharing the port would force the
//! operator to either expose `/metrics` to the platform (bad) or put
//! auth in front of `/metrics` (overkill). Two ports = two firewall
//! rules.
//!
//! # Slice 1 scope (this module)
//!
//! - Outer JSON envelope deserialization with a versioned `api_version`
//!   field and the six event-type discriminants the spec commits to.
//! - HMAC-SHA256 verification of the raw request body against a shared
//!   secret loaded from the env var named in [`WebhookConfig::secret_env`].
//! - Echo handler that returns `200 {"event_id":"…","status":"accepted"}`
//!   on a verified envelope. No policy mutation, no event dispatching —
//!   slices 2 and 3 layer those on without changing this module's
//!   external shape.
//! - Prometheus counter `dataglot_governance_webhook_events_total`
//!   labelled by `event_type` and `status` so operators can see
//!   accepted / rejected traffic without grepping logs.
//!
//! # Threat model
//!
//! - **Tampered body.** HMAC mismatch → 401, counter increments under
//!   `status="rejected_signature"`.
//! - **Missing signature header.** 401, counter under
//!   `status="missing_signature"`.
//! - **Wrong/missing secret env var.** Boot-time error, server refuses
//!   to start — fail-fast is the only safe shape.
//! - **Replay.** Out of scope for slice 1 (spec §"Open questions" #3).
//!   Idempotency by `event_id` lands in slice 3 or 3.5.

use std::net::SocketAddr;

use anyhow::{Context, Result};
use axum::body::{to_bytes, Body};
use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use dataglot_policy::{InMemoryRuleStore, RuleStore};
use hmac::{Hmac, KeyInit, Mac};
use prometheus::IntCounterVec;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::broadcast;

use crate::governance::datahub::{lower_payload, AdapterError};

/// HTTP header carrying the HMAC-SHA256 signature, formatted as
/// `sha256=<hex>` matching `DataHub`'s default scheme
/// and GitHub's webhook convention (familiar to operators).
const SIGNATURE_HEADER: &str = "X-Dataglot-Signature";

/// Hex prefix the signature header value must carry. Anything else is
/// rejected; future hash variants would extend this constant rather
/// than relax the parser.
const SIGNATURE_PREFIX: &str = "sha256=";

/// Maximum request body size accepted by the handler, in bytes.
///
/// 256 KiB is generous for a tag-event payload (a few hundred bytes
/// typical) but bounds the worst-case allocation a hostile or
/// misconfigured client can force. Above this the handler responds
/// with 413 Payload Too Large; the counter increments under
/// `status="rejected_too_large"`.
const MAX_BODY_BYTES: usize = 256 * 1024;

/// Inbound webhook configuration.
///
/// Operators opt in by setting the `webhook` block in `dataglot.toml`;
/// omitting the block keeps the server bit-identical to pre-slice-1
/// behaviour (no extra port bound, no Prometheus counter registered).
///
/// JSON shape:
///
/// ```json
/// {
///   "webhook": {
///     "addr": "0.0.0.0:8080",
///     "secret_env": "DATAGLOT_WEBHOOK_SECRET"
///   }
/// }
/// ```
///
/// `secret_env` names an environment variable; the shared secret value
/// never appears in the config file. The server resolves it at boot
/// and refuses to start if the variable is unset — fail-fast over
/// silently accepting unsigned requests.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WebhookConfig {
    /// Address to bind the webhook HTTP server to.
    pub addr: SocketAddr,
    /// Name of the environment variable holding the HMAC-SHA256
    /// shared secret. Indirected via env so the secret never lands
    /// in the config file or process listing.
    pub secret_env: String,
}

/// Versioned outer envelope every inbound event carries.
///
/// The envelope is Dataglot-owned and stable; the inner `payload` is
/// platform-shape (`DataHub` Actions JSON, Informatica IDMC, etc.) and
/// is normalised into Dataglot's policy types by the per-platform
/// adapter layer that lands in slice 3. Slice 1 only deserializes the
/// envelope to confirm the request is well-formed enough to log; the
/// `payload` field is captured as a raw `serde_json::Value` so future
/// slices can lower it without bumping `api_version`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventEnvelope {
    /// Envelope schema version. Slice 1 accepts `"v1"` only;
    /// anything else returns 400 with `error: "UNSUPPORTED_API_VERSION"`.
    pub api_version: String,
    /// Stable id for the event from the producer's side. Used by
    /// slice 3's idempotency LRU; slice 1 just echoes it back in the
    /// 200 response.
    pub event_id: String,
    /// Discriminator for the six flows Interface 3 carries.
    pub event_type: EventType,
    /// ISO-8601 producer timestamp. Slice 1 doesn't act on it;
    /// kept on the envelope so log lines and the eventual catalog
    /// persistence layer can recover producer-side ordering.
    pub occurred_at: String,
    /// Platform-shape JSON consumed by the slice-3 adapter. Slice 1
    /// preserves it as opaque `Value` — the parse succeeds for any
    /// JSON object the producer sends, so a malformed payload fails
    /// at the *adapter* layer (with a precise error) rather than at
    /// the envelope (with a vague one).
    #[serde(default)]
    pub payload: serde_json::Value,
}

/// The six event-type discriminants Interface 3 commits to in spec
/// 04 §"Payload schema". 1:1 mapping with the `RuleChange` enum slice
/// 2 introduces in `dataglot-policy`. Adding a new event type is a
/// minor-version envelope bump.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    /// Flow 5 — Classification inbound. The governance platform
    /// attached one or more tags to a column.
    #[serde(rename = "tag.assigned")]
    TagAssigned,
    /// Flow 5 — Classification inbound, inverse. A previously-applied
    /// tag was removed.
    #[serde(rename = "tag.removed")]
    TagRemoved,
    /// Flow 6 — Policy inbound. The platform defined or updated a
    /// policy rule (mask / row-filter) for an existing tag.
    #[serde(rename = "policy.upserted")]
    PolicyUpserted,
    /// Flow 6 — Policy inbound, inverse. A previously-defined policy
    /// rule was removed.
    #[serde(rename = "policy.deleted")]
    PolicyDeleted,
    /// Flow 7 — Certification inbound. A column gained a steward
    /// certification annotation.
    #[serde(rename = "certification.upserted")]
    CertificationUpserted,
    /// Flow 7 — Certification inbound, inverse. A certification
    /// annotation was withdrawn.
    #[serde(rename = "certification.deleted")]
    CertificationDeleted,
}

impl EventType {
    /// Stable string used as the `event_type` label on the Prometheus
    /// counter. Matches the JSON wire format so dashboards
    /// cross-reference one-to-one with producer logs.
    #[must_use]
    pub fn as_metric_label(self) -> &'static str {
        match self {
            Self::TagAssigned => "tag.assigned",
            Self::TagRemoved => "tag.removed",
            Self::PolicyUpserted => "policy.upserted",
            Self::PolicyDeleted => "policy.deleted",
            Self::CertificationUpserted => "certification.upserted",
            Self::CertificationDeleted => "certification.deleted",
        }
    }
}

/// Acknowledgement body returned on a verified envelope (200 OK).
///
/// The producer's Actions Framework uses `status` to decide whether
/// to mark the delivery successful. Slice 1 only ever produces
/// `"accepted"`; slice 3 keeps the same shape and only varies the
/// internal dispatcher outcome.
#[derive(Debug, Clone, Serialize)]
struct AckBody {
    event_id: String,
    status: &'static str,
}

/// Structured error body. Matches the JSON shape spec 04 §"Slice 3"
/// commits to so producers see consistent error contracts even for
/// envelope-level rejections.
#[derive(Debug, Clone, Serialize)]
struct ErrorBody {
    error: &'static str,
    message: String,
}

/// State shared with every handler invocation. Cheap to clone — every
/// field is already `Arc`-shaped or trivially clonable.
#[derive(Clone)]
struct WebhookState {
    /// HMAC shared secret bytes, resolved from `secret_env` at boot.
    secret: Vec<u8>,
    /// Counter incremented per request with `event_type` and `status`
    /// labels. `event_type` is `"unknown"` for envelope-rejection
    /// paths where the envelope didn't deserialize far enough to
    /// identify the type.
    events_total: IntCounterVec,
    /// Slice-2 rule store the handler dispatches `RuleChange` mutations
    /// into after the slice-3 `DataHub` adapter lowers the payload.
    /// `None` keeps the handler in slice-1 echo mode — useful for the
    /// few tests that want to exercise HMAC + envelope plumbing
    /// without standing up a real store. Production boot via
    /// [`spawn_webhook_server`] always populates it.
    rule_store: Option<Arc<InMemoryRuleStore>>,
}

/// Tuple returned by [`spawn_webhook_server`]: the `JoinHandle` for
/// the spawned axum task plus the actual bound `SocketAddr`. Tests
/// pass `cfg.addr = 127.0.0.1:0` to let the OS pick an ephemeral
/// port; without `bound` in the return signature, the discovered
/// port would be lost. Production callers just hold the
/// `JoinHandle` and ignore the addr (config already has it).
#[derive(Debug)]
pub struct WebhookServerHandle {
    /// Background task running `axum::serve`. Joined alongside the
    /// metrics handle in `DataglotServer::run`'s shutdown drain.
    pub join: tokio::task::JoinHandle<()>,
    /// `local_addr()` of the bound listener — the actual addr clients
    /// must reach. Identical to `cfg.addr` when `cfg.addr` was a
    /// fully-specified address; differs only when `cfg.addr.port() == 0`.
    pub bound: SocketAddr,
}

/// Spawn the inbound webhook HTTP server on a tokio task.
///
/// Mirrors [`crate::observability::spawn_metrics_server`]'s shape:
/// bind, build a router, hand it to `axum::serve` with the supplied
/// broadcast receiver wiring graceful shutdown. The returned
/// [`WebhookServerHandle`] carries both the `JoinHandle` (for shutdown
/// drain) and the actual bound `SocketAddr` (for in-process tests
/// that ask the OS for an ephemeral port via `127.0.0.1:0`).
///
/// # Errors
/// - The shared-secret env var named by `cfg.secret_env` is unset or
///   empty — fail-fast over accepting unsigned requests.
/// - The listener fails to bind `cfg.addr` (port collision, etc.).
///
/// # Side effects
/// Registers the `dataglot_governance_webhook_events_total` counter
/// on the supplied Prometheus registry. The counter is shared across
/// every handler invocation for the lifetime of the spawned task.
pub async fn spawn_webhook_server(
    cfg: &WebhookConfig,
    events_total: IntCounterVec,
    rule_store: Arc<InMemoryRuleStore>,
    mut shutdown: broadcast::Receiver<()>,
) -> Result<WebhookServerHandle> {
    let secret = resolve_webhook_secret(&cfg.secret_env)?;

    let listener = TcpListener::bind(cfg.addr)
        .await
        .with_context(|| format!("Failed to bind webhook server to {}", cfg.addr))?;
    let bound = listener.local_addr().unwrap_or(cfg.addr);

    let state = WebhookState {
        secret,
        events_total,
        rule_store: Some(rule_store),
    };
    let router = build_router(state);

    tracing::info!(%bound, "Inbound governance webhook listening");

    let join = tokio::spawn(async move {
        let serve = axum::serve(listener, router).with_graceful_shutdown(async move {
            let _ = shutdown.recv().await;
        });
        if let Err(err) = serve.await {
            tracing::error!(error = %err, "Inbound governance webhook exited with error");
        } else {
            tracing::info!("Inbound governance webhook stopped");
        }
    });

    Ok(WebhookServerHandle { join, bound })
}

/// Resolve the shared-secret bytes from the named environment
/// variable. Split out of `spawn_webhook_server` so the failure
/// modes (env var unset, env var set-but-empty) can be unit-tested
/// in isolation without binding a real listener.
///
/// # Errors
/// - The environment variable is unset.
/// - The variable is set but empty.
fn resolve_webhook_secret(secret_env: &str) -> Result<Vec<u8>> {
    let value = std::env::var(secret_env).with_context(|| {
        format!(
            "Inbound governance webhook is configured but the shared-secret env var \
             `{secret_env}` is unset. Set it before starting the server, or remove the \
             [webhook] block from dataglot.json to disable inbound governance entirely."
        )
    })?;
    if value.is_empty() {
        anyhow::bail!(
            "Inbound governance webhook shared-secret env var `{secret_env}` is set but empty"
        );
    }
    Ok(value.into_bytes())
}

fn build_router(state: WebhookState) -> Router {
    Router::new()
        .route("/v1/events", post(handle_event))
        .with_state(state)
}

async fn handle_event(State(state): State<WebhookState>, request: Request<Body>) -> Response {
    // Pull headers off the request before consuming the body — the
    // signature header must be in scope when we know the raw bytes.
    let (parts, body) = request.into_parts();
    let headers = parts.headers;

    // Bounded body read: anything above MAX_BODY_BYTES gets 413. This
    // is the only allocation the handler makes on the hot path; we
    // verify the signature against `body_bytes` directly so HMAC sees
    // the exact bytes the wire delivered (post-axum content decoding,
    // matching what the producer signs).
    let body_bytes = match to_bytes(body, MAX_BODY_BYTES).await {
        Ok(b) => b,
        Err(err) => {
            tracing::warn!(error = %err, "Rejecting webhook body — too large or read error");
            state
                .events_total
                .with_label_values(&["unknown", "rejected_too_large"])
                .inc();
            return error_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                "PAYLOAD_TOO_LARGE",
                format!("Request body exceeds {MAX_BODY_BYTES} bytes"),
            );
        }
    };

    // Verify the signature first — before any JSON parse — so a
    // crafted body with a malformed payload can't surface
    // deserialization errors that leak the parser's behaviour. HMAC
    // failures look identical regardless of body shape.
    if let Err(reject) = verify_signature(&headers, &body_bytes, &state.secret) {
        state
            .events_total
            .with_label_values(&["unknown", reject.metric_status])
            .inc();
        return error_response(StatusCode::UNAUTHORIZED, reject.code, reject.message);
    }

    // Now parse the envelope. Signature is verified; deserialization
    // failure can return a precise message without giving an attacker
    // a probe channel.
    let envelope: EventEnvelope = match serde_json::from_slice(&body_bytes) {
        Ok(env) => env,
        Err(err) => {
            tracing::warn!(error = %err, "Rejecting webhook body — envelope deserialization failed");
            state
                .events_total
                .with_label_values(&["unknown", "rejected_malformed"])
                .inc();
            return error_response(
                StatusCode::BAD_REQUEST,
                "MALFORMED_ENVELOPE",
                format!("Failed to parse webhook envelope: {err}"),
            );
        }
    };

    // API version gate. Slice 1 accepts v1 only.
    if envelope.api_version != "v1" {
        tracing::warn!(
            api_version = %envelope.api_version,
            event_id = %envelope.event_id,
            "Rejecting webhook event — unsupported api_version"
        );
        state
            .events_total
            .with_label_values(&[
                envelope.event_type.as_metric_label(),
                "rejected_unsupported_version",
            ])
            .inc();
        return error_response(
            StatusCode::BAD_REQUEST,
            "UNSUPPORTED_API_VERSION",
            format!(
                "Envelope api_version `{}` is not supported by this server",
                envelope.api_version
            ),
        );
    }

    // Slice 3 dispatcher. Extracted into a helper so the handler
    // stays under the clippy line budget; same effect.
    dispatch_envelope(&state, envelope)
}

/// Lower the envelope's platform-shape payload through the slice-3
/// `DataHub` adapter and forward the resulting [`RuleChange`] to the
/// slice-2 rule store. Returns the final HTTP response (200 on
/// successful apply, 4xx/5xx on each failure mode).
///
/// The store may be `None` in a few tests that exercise HMAC +
/// envelope plumbing only. Production boot via
/// [`spawn_webhook_server`] always populates it; we treat the
/// store-missing branch as a server-config bug (500) rather than
/// silently echoing.
fn dispatch_envelope(state: &WebhookState, envelope: EventEnvelope) -> Response {
    let Some(rule_store) = state.rule_store.as_ref() else {
        tracing::error!(
            event_id = %envelope.event_id,
            "rule_store unconfigured at webhook handler — server bootstrap is incomplete"
        );
        state
            .events_total
            .with_label_values(&[envelope.event_type.as_metric_label(), "rejected_no_store"])
            .inc();
        return error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "RULE_STORE_UNAVAILABLE",
            "Inbound governance webhook is configured but no rule store was bound to the handler"
                .to_string(),
        );
    };

    let change = match lower_payload(envelope.event_type, &envelope.payload) {
        Ok(change) => change,
        Err(err) => {
            tracing::warn!(
                event_id = %envelope.event_id,
                event_type = %envelope.event_type.as_metric_label(),
                error = %err,
                "DataHub adapter rejected payload"
            );
            state
                .events_total
                .with_label_values(&[
                    envelope.event_type.as_metric_label(),
                    adapter_failure_status_label(&err),
                ])
                .inc();
            return error_response(
                StatusCode::BAD_REQUEST,
                "ADAPTER_VALIDATION_FAILED",
                format!("{err}"),
            );
        }
    };

    if let Err(err) = rule_store.apply(change) {
        tracing::warn!(
            event_id = %envelope.event_id,
            event_type = %envelope.event_type.as_metric_label(),
            error = %err,
            "Rule store apply failed; published enforcer unchanged"
        );
        state
            .events_total
            .with_label_values(&[envelope.event_type.as_metric_label(), "rejected_apply"])
            .inc();
        return error_response(
            StatusCode::BAD_REQUEST,
            "RULE_STORE_APPLY_FAILED",
            format!("{err}"),
        );
    }

    tracing::info!(
        event_id = %envelope.event_id,
        event_type = %envelope.event_type.as_metric_label(),
        occurred_at = %envelope.occurred_at,
        "Applied inbound governance event"
    );
    state
        .events_total
        .with_label_values(&[envelope.event_type.as_metric_label(), "accepted"])
        .inc();

    (
        StatusCode::OK,
        Json(AckBody {
            event_id: envelope.event_id,
            status: "accepted",
        }),
    )
        .into_response()
}

/// Pick the Prometheus `status` label for a given adapter failure.
/// Distinct labels per variant so dashboards distinguish
/// payload-shape errors from URN parse failures from SQL parse
/// failures without grepping logs.
fn adapter_failure_status_label(err: &AdapterError) -> &'static str {
    match err {
        AdapterError::Payload(_) => "rejected_adapter_payload",
        AdapterError::InvalidUrn { .. } => "rejected_adapter_urn",
        AdapterError::InvalidTable { .. } => "rejected_adapter_table",
        AdapterError::PolicyPredicate { .. } => "rejected_adapter_predicate",
    }
}

/// Single rejection reason for the HMAC verification step. Carries
/// both the operator-facing error code/message and the metric label
/// so the handler can increment the counter consistently.
struct SignatureRejection {
    code: &'static str,
    message: String,
    metric_status: &'static str,
}

fn verify_signature(
    headers: &HeaderMap,
    body: &[u8],
    secret: &[u8],
) -> std::result::Result<(), SignatureRejection> {
    let Some(header_value) = headers.get(SIGNATURE_HEADER) else {
        return Err(SignatureRejection {
            code: "MISSING_SIGNATURE",
            message: format!("Missing required `{SIGNATURE_HEADER}` header"),
            metric_status: "missing_signature",
        });
    };

    let header_str = header_value.to_str().map_err(|_| SignatureRejection {
        code: "INVALID_SIGNATURE",
        message: format!("`{SIGNATURE_HEADER}` header contains non-ASCII bytes"),
        metric_status: "rejected_signature",
    })?;

    let Some(hex_signature) = header_str.strip_prefix(SIGNATURE_PREFIX) else {
        return Err(SignatureRejection {
            code: "INVALID_SIGNATURE",
            message: format!(
                "`{SIGNATURE_HEADER}` must start with `{SIGNATURE_PREFIX}` — got `{header_str}`"
            ),
            metric_status: "rejected_signature",
        });
    };

    let provided = decode_hex(hex_signature).map_err(|()| SignatureRejection {
        code: "INVALID_SIGNATURE",
        message: "Signature hex decode failed".to_string(),
        metric_status: "rejected_signature",
    })?;

    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(secret).map_err(|_| {
        // Hmac::new_from_slice can only fail on key length; SHA-256
        // accepts any length so this branch is unreachable in
        // practice. Return rejected_signature to keep the timing
        // shape uniform with a tampered-body rejection.
        SignatureRejection {
            code: "INVALID_SIGNATURE",
            message: "Internal HMAC initialization error".to_string(),
            metric_status: "rejected_signature",
        }
    })?;
    mac.update(body);

    // Constant-time comparison via `verify_slice` so a timing oracle
    // on the secret stays closed even with a hostile attacker who
    // measures handler latency.
    mac.verify_slice(&provided)
        .map_err(|_| SignatureRejection {
            code: "INVALID_SIGNATURE",
            message: "Signature does not match the computed HMAC-SHA256 of the request body"
                .to_string(),
            metric_status: "rejected_signature",
        })?;

    Ok(())
}

/// Lower-case hex decoder. `hex` crate would also work; rolling it
/// here keeps the dep surface tight (the only hex this crate touches
/// is the HMAC signature, ~32 bytes per request).
fn decode_hex(input: &str) -> std::result::Result<Vec<u8>, ()> {
    if !input.len().is_multiple_of(2) {
        return Err(());
    }
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    // `as_chunks` (what the lint suggests) is fine on stable, but keep the
    // idiomatic `chunks_exact` iterator and silence the lint locally — the
    // chunk size is a constant 2 and the length is verified above.
    #[allow(clippy::chunks_exact_to_as_chunks)]
    for chunk in bytes.chunks_exact(2) {
        let hi = hex_nibble(chunk[0])?;
        let lo = hex_nibble(chunk[1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn hex_nibble(b: u8) -> std::result::Result<u8, ()> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(()),
    }
}

fn error_response(status: StatusCode, code: &'static str, message: String) -> Response {
    (
        status,
        [(header::CONTENT_TYPE, "application/json")],
        Json(ErrorBody {
            error: code,
            message,
        }),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes as collect_body;
    use axum::http::Request;
    use prometheus::Opts;
    use tower::ServiceExt;

    const TEST_SECRET: &[u8] = b"super-secret-shared-key";

    fn fresh_counter() -> IntCounterVec {
        IntCounterVec::new(
            Opts::new("dataglot_governance_webhook_events_total", "test counter"),
            &["event_type", "status"],
        )
        .expect("counter builds")
    }

    fn build_state(secret: &[u8]) -> WebhookState {
        WebhookState {
            secret: secret.to_vec(),
            events_total: fresh_counter(),
            rule_store: None,
        }
    }

    /// Variant that binds a fresh empty rule store — for tests that
    /// exercise the slice-3 dispatcher end-to-end (HMAC → adapter →
    /// rule store apply).
    fn build_state_with_store(secret: &[u8]) -> (WebhookState, Arc<InMemoryRuleStore>) {
        let store = InMemoryRuleStore::new(dataglot_policy::InitialRules {
            tags: vec![dataglot_policy::TagDefinition {
                id: dataglot_policy::TagId::new("pii"),
                org: "acme".to_string(),
                name: "PII".to_string(),
            }],
            ..Default::default()
        })
        .expect("rule store builds with the seed PII tag");
        let state = WebhookState {
            secret: secret.to_vec(),
            events_total: fresh_counter(),
            rule_store: Some(Arc::clone(&store)),
        };
        (state, store)
    }

    fn sign(secret: &[u8], body: &[u8]) -> String {
        use std::fmt::Write;
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(secret).expect("init");
        mac.update(body);
        let result = mac.finalize().into_bytes();
        let mut s = String::from(SIGNATURE_PREFIX);
        for b in &result {
            write!(s, "{b:02x}").expect("write to String never fails");
        }
        s
    }

    /// URN used by every dispatcher test below. Refers to
    /// `public.users.email`; the `DataHub` adapter parses the
    /// `(public.users, email)` pair out and the seed `pii` tag in
    /// `build_state_with_store` validates the lookup.
    const TEST_SCHEMA_FIELD_URN: &str =
        "urn:li:schemaField:(urn:li:dataset:(urn:li:dataPlatform:postgres,public.users,PROD),email)";
    const TEST_TAG_URN: &str = "urn:li:tag:pii";

    /// Default envelope shape used by the HMAC-only tests below.
    /// Event type is `tag.assigned` so the payload's structure is
    /// the cheapest legitimate shape to construct.
    fn valid_envelope() -> serde_json::Value {
        envelope_with("tag.assigned", &datahub_tag_payload())
    }

    fn envelope_with(event_type: &str, payload: &serde_json::Value) -> serde_json::Value {
        serde_json::json!({
            "api_version": "v1",
            "event_id": "evt-test-1",
            "event_type": event_type,
            "occurred_at": "2026-05-19T12:00:00Z",
            "payload": payload,
        })
    }

    fn datahub_tag_payload() -> serde_json::Value {
        serde_json::json!({
            "entity_urn": TEST_SCHEMA_FIELD_URN,
            "tag_urn": TEST_TAG_URN,
        })
    }

    /// Validly-signed body with a store-bound state returns 200 with
    /// `status: "accepted"`, echoes the `event_id`, increments the
    /// counter under `(event_type, status="accepted")`, AND the
    /// store's published enforcer pointer advances — confirming the
    /// dispatcher ran the full slice-3 flow (HMAC verify → adapter
    /// lower → `RuleStore::apply`).
    #[tokio::test]
    async fn valid_signature_accepts_and_applies_event() {
        let (state, store) = build_state_with_store(TEST_SECRET);
        let counter = state.events_total.clone();
        let pre_snapshot_ptr = Arc::as_ptr(&store.snapshot()).cast::<()>();
        let router = build_router(state);

        let body_bytes = serde_json::to_vec(&valid_envelope()).expect("serialize");
        let sig = sign(TEST_SECRET, &body_bytes);

        let request = Request::post("/v1/events")
            .header(SIGNATURE_HEADER, sig)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body_bytes))
            .expect("build request");

        let response = router.oneshot(request).await.expect("router responds");
        assert_eq!(response.status(), StatusCode::OK);

        let body = collect_body(response.into_body(), 64 * 1024)
            .await
            .expect("read body");
        let parsed: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(parsed["status"], "accepted");
        assert_eq!(parsed["event_id"], "evt-test-1");

        assert_eq!(
            counter
                .with_label_values(&["tag.assigned", "accepted"])
                .get(),
            1
        );

        // Snapshot advanced ⇒ the rule store applied the change.
        let post_snapshot_ptr = Arc::as_ptr(&store.snapshot()).cast::<()>();
        assert_ne!(
            pre_snapshot_ptr, post_snapshot_ptr,
            "store's published enforcer must advance after a successful dispatch"
        );
    }

    /// Tampered body returns 401 — the signature still corresponds to
    /// the *original* bytes, so HMAC's `verify_slice` fails.
    #[tokio::test]
    async fn tampered_body_rejects() {
        let state = build_state(TEST_SECRET);
        let counter = state.events_total.clone();
        let router = build_router(state);

        let original = serde_json::to_vec(&valid_envelope()).expect("serialize");
        let sig = sign(TEST_SECRET, &original);

        // Mutate one byte of the payload after signing.
        let mut tampered = original;
        let last = tampered.len() - 2;
        tampered[last] ^= 0x01;

        let request = Request::post("/v1/events")
            .header(SIGNATURE_HEADER, sig)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(tampered))
            .expect("build request");

        let response = router.oneshot(request).await.expect("router responds");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        assert_eq!(
            counter
                .with_label_values(&["unknown", "rejected_signature"])
                .get(),
            1
        );
    }

    /// Body signed with the wrong secret returns 401. The handler
    /// can't tell whether the producer used the wrong secret or a
    /// different body — the error code is the same, the metric label
    /// is the same.
    #[tokio::test]
    async fn wrong_secret_rejects() {
        let state = build_state(TEST_SECRET);
        let router = build_router(state);

        let body_bytes = serde_json::to_vec(&valid_envelope()).expect("serialize");
        let wrong_sig = sign(b"a-different-secret", &body_bytes);

        let request = Request::post("/v1/events")
            .header(SIGNATURE_HEADER, wrong_sig)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body_bytes))
            .expect("build request");

        let response = router.oneshot(request).await.expect("router responds");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// Missing header returns 401 with the dedicated `MISSING_SIGNATURE`
    /// code so operators can distinguish "client forgot to sign" from
    /// "client signed with the wrong secret."
    #[tokio::test]
    async fn missing_signature_rejects() {
        let state = build_state(TEST_SECRET);
        let counter = state.events_total.clone();
        let router = build_router(state);

        let body_bytes = serde_json::to_vec(&valid_envelope()).expect("serialize");

        let request = Request::post("/v1/events")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body_bytes))
            .expect("build request");

        let response = router.oneshot(request).await.expect("router responds");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let body = collect_body(response.into_body(), 64 * 1024)
            .await
            .expect("read body");
        let parsed: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(parsed["error"], "MISSING_SIGNATURE");

        assert_eq!(
            counter
                .with_label_values(&["unknown", "missing_signature"])
                .get(),
            1
        );
    }

    /// Unsupported `api_version` returns 400 — the signature is valid
    /// (we trust the producer) but the envelope is from a future
    /// schema this server doesn't know how to consume yet.
    #[tokio::test]
    async fn unsupported_api_version_rejects_with_400() {
        let state = build_state(TEST_SECRET);
        let router = build_router(state);

        let mut env = valid_envelope();
        env["api_version"] = serde_json::Value::String("v99".to_string());
        let body_bytes = serde_json::to_vec(&env).expect("serialize");
        let sig = sign(TEST_SECRET, &body_bytes);

        let request = Request::post("/v1/events")
            .header(SIGNATURE_HEADER, sig)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body_bytes))
            .expect("build request");

        let response = router.oneshot(request).await.expect("router responds");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let body = collect_body(response.into_body(), 64 * 1024)
            .await
            .expect("read body");
        let parsed: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(parsed["error"], "UNSUPPORTED_API_VERSION");
    }

    /// Malformed JSON (after passing the signature check) returns 400
    /// with `MALFORMED_ENVELOPE`. The producer signed bogus bytes;
    /// from the server's standpoint we trust the signature but can't
    /// route the payload.
    #[tokio::test]
    async fn malformed_body_rejects_with_400_after_signature_check() {
        let state = build_state(TEST_SECRET);
        let router = build_router(state);

        let body_bytes = b"this is not json".to_vec();
        let sig = sign(TEST_SECRET, &body_bytes);

        let request = Request::post("/v1/events")
            .header(SIGNATURE_HEADER, sig)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body_bytes))
            .expect("build request");

        let response = router.oneshot(request).await.expect("router responds");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let body = collect_body(response.into_body(), 64 * 1024)
            .await
            .expect("read body");
        let parsed: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(parsed["error"], "MALFORMED_ENVELOPE");
    }

    /// Signature header present but not in `sha256=<hex>` form returns
    /// 401 with `INVALID_SIGNATURE` — distinct from missing because
    /// the producer *tried* to sign but used the wrong shape.
    #[tokio::test]
    async fn malformed_signature_header_rejects() {
        let state = build_state(TEST_SECRET);
        let router = build_router(state);

        let body_bytes = serde_json::to_vec(&valid_envelope()).expect("serialize");

        let request = Request::post("/v1/events")
            .header(SIGNATURE_HEADER, "not-a-proper-signature")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body_bytes))
            .expect("build request");

        let response = router.oneshot(request).await.expect("router responds");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let body = collect_body(response.into_body(), 64 * 1024)
            .await
            .expect("read body");
        let parsed: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(parsed["error"], "INVALID_SIGNATURE");
    }

    /// Pins the JSON wire format of every event type so a downstream
    /// adapter (slice 3) can rely on the discriminant string never
    /// changing without a bump.
    #[test]
    fn event_type_serialization_is_stable() {
        let pairs = [
            (EventType::TagAssigned, "tag.assigned"),
            (EventType::TagRemoved, "tag.removed"),
            (EventType::PolicyUpserted, "policy.upserted"),
            (EventType::PolicyDeleted, "policy.deleted"),
            (EventType::CertificationUpserted, "certification.upserted"),
            (EventType::CertificationDeleted, "certification.deleted"),
        ];
        for (variant, wire) in pairs {
            let s = serde_json::to_string(&variant).expect("serialize");
            assert_eq!(
                s,
                format!("\"{wire}\""),
                "{variant:?} should serialize to {wire}"
            );
            assert_eq!(variant.as_metric_label(), wire);
        }
    }

    /// `WebhookConfig` parses cleanly from the documented JSON shape.
    /// Pins the field names downstream operators read in the spec.
    #[test]
    fn webhook_config_deserializes_from_documented_shape() {
        let cfg: WebhookConfig = serde_json::from_value(serde_json::json!({
            "addr": "127.0.0.1:8080",
            "secret_env": "TEST_WEBHOOK_SECRET"
        }))
        .expect("WebhookConfig deserializes");
        assert_eq!(cfg.addr.port(), 8080);
        assert_eq!(cfg.secret_env, "TEST_WEBHOOK_SECRET");
    }

    /// Test-local RAII guard so the env mutation tests below never
    /// leak state into sibling tests if an assertion panics. Each
    /// test passes a unique name (derived from the test fn name) so
    /// the guards never compete for the same key.
    struct EnvGuard(&'static str);
    impl Drop for EnvGuard {
        fn drop(&mut self) {
            std::env::remove_var(self.0);
        }
    }

    /// Env var unset → fail-fast. Per-test unique name (`module::test`
    /// shape) means we never race with sibling tests touching env.
    #[test]
    fn resolve_secret_errors_when_env_var_missing() {
        const NAME: &str = "__DATAGLOT_TEST_WEBHOOK_SECRET_UNSET__";
        // Belt-and-suspenders: clear in case a previous run leaked.
        std::env::remove_var(NAME);
        let err = resolve_webhook_secret(NAME).expect_err("should fail");
        let msg = format!("{err:#}");
        assert!(
            msg.contains(NAME) && msg.contains("unset"),
            "error message must name the env var and the reason; got: {msg}"
        );
    }

    /// Env var set-but-empty is a distinct failure mode the operator
    /// should hear about explicitly (almost always a templating bug
    /// in the secrets manager). The `EnvGuard` removes the variable
    /// on Drop so the variable can't leak to sibling tests.
    #[test]
    fn resolve_secret_errors_when_env_var_empty() {
        const NAME: &str = "__DATAGLOT_TEST_WEBHOOK_SECRET_EMPTY__";
        std::env::set_var(NAME, "");
        let _guard = EnvGuard(NAME);
        let err = resolve_webhook_secret(NAME).expect_err("should fail");
        let msg = format!("{err:#}");
        assert!(
            msg.contains(NAME) && msg.contains("empty"),
            "error message must name the env var and the reason; got: {msg}"
        );
    }

    /// Happy path — env var present with a non-empty value resolves
    /// to the matching byte slice.
    #[test]
    fn resolve_secret_returns_bytes_for_set_value() {
        const NAME: &str = "__DATAGLOT_TEST_WEBHOOK_SECRET_OK__";
        std::env::set_var(NAME, "super-secret-shared-key");
        let _guard = EnvGuard(NAME);
        let bytes = resolve_webhook_secret(NAME).expect("ok");
        assert_eq!(bytes, b"super-secret-shared-key");
    }

    #[test]
    fn hex_decoder_roundtrips() {
        use std::fmt::Write;
        let bytes = [0x00, 0x10, 0xff, 0xa5];
        let mut hex = String::with_capacity(bytes.len() * 2);
        for b in &bytes {
            write!(hex, "{b:02x}").expect("write to String never fails");
        }
        assert_eq!(decode_hex(&hex).expect("decode"), bytes.to_vec());
        // Mixed case acceptance — match what producers may emit.
        assert_eq!(decode_hex("AbCd").expect("decode"), vec![0xAB, 0xCD]);
        // Odd length and non-hex chars rejected.
        assert!(decode_hex("abc").is_err());
        assert!(decode_hex("zz").is_err());
    }

    // ---------------------------------------------------------------------
    // Slice 3 dispatcher tests — each event_type lands on the rule store.
    // ---------------------------------------------------------------------

    /// Drive one DataHub-shape event through the dispatcher end-to-end
    /// and return the response status + body so each per-variant test
    /// stays small.
    async fn dispatch(
        state: WebhookState,
        event_type: &str,
        payload: serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        let router = build_router(state);
        let body_bytes =
            serde_json::to_vec(&envelope_with(event_type, &payload)).expect("serialize");
        let sig = sign(TEST_SECRET, &body_bytes);
        let request = Request::post("/v1/events")
            .header(SIGNATURE_HEADER, sig)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body_bytes))
            .expect("build request");
        let response = router.oneshot(request).await.expect("router responds");
        let status = response.status();
        let body_bytes = collect_body(response.into_body(), 64 * 1024)
            .await
            .expect("read body");
        let parsed: serde_json::Value =
            serde_json::from_slice(&body_bytes).unwrap_or(serde_json::Value::Null);
        (status, parsed)
    }

    /// Build a store with one initial PII tag AND the mask policy that
    /// later events delete / re-upsert. Mirrors the governance demo
    /// shape from `examples/demo/dataglot-with-governance.toml`.
    fn build_state_with_seeded_policy(secret: &[u8]) -> (WebhookState, Arc<InMemoryRuleStore>) {
        use dataglot_policy::{OrgGroupId, Policy as PolicyDef, RuleType};
        let store = InMemoryRuleStore::new(dataglot_policy::InitialRules {
            tags: vec![dataglot_policy::TagDefinition {
                id: dataglot_policy::TagId::new("pii"),
                org: "acme".to_string(),
                name: "PII".to_string(),
            }],
            policies: vec![PolicyDef {
                id: "mask-pii-analyst".to_string(),
                org: "acme".to_string(),
                tag: dataglot_policy::TagId::new("pii"),
                group: OrgGroupId::new("analyst"),
                rule: RuleType::Mask {
                    expression: datafusion::logical_expr::lit("***@example.com"),
                },
            }],
            ..Default::default()
        })
        .expect("rule store builds with seed tag + policy");
        let state = WebhookState {
            secret: secret.to_vec(),
            events_total: fresh_counter(),
            rule_store: Some(Arc::clone(&store)),
        };
        (state, store)
    }

    #[tokio::test]
    async fn dispatch_tag_assigned_updates_store() {
        let (state, store) = build_state_with_store(TEST_SECRET);
        let pre = Arc::as_ptr(&store.snapshot()).cast::<()>();
        let (status, body) = dispatch(state, "tag.assigned", datahub_tag_payload()).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["status"], "accepted");
        assert_ne!(pre, Arc::as_ptr(&store.snapshot()).cast::<()>());
    }

    #[tokio::test]
    async fn dispatch_tag_removed_updates_store() {
        // Pre-assign the tag so the remove has something to do.
        let (state, store) = build_state_with_store(TEST_SECRET);
        store
            .apply(dataglot_policy::RuleChange::TagAssigned {
                table: datafusion::sql::TableReference::partial("public", "users"),
                column: "email".to_string(),
                tag: dataglot_policy::TagId::new("pii"),
            })
            .expect("seed binding");
        let pre = Arc::as_ptr(&store.snapshot()).cast::<()>();
        let (status, _) = dispatch(state, "tag.removed", datahub_tag_payload()).await;
        assert_eq!(status, StatusCode::OK);
        assert_ne!(pre, Arc::as_ptr(&store.snapshot()).cast::<()>());
    }

    #[tokio::test]
    async fn dispatch_policy_upserted_mask_updates_store() {
        let (state, store) = build_state_with_store(TEST_SECRET);
        let pre = Arc::as_ptr(&store.snapshot()).cast::<()>();
        let payload = serde_json::json!({
            "id": "mask-pii-analyst",
            "org": "acme",
            "tag_urn": TEST_TAG_URN,
            "group": "analyst",
            "rule": {"kind": "mask", "mask_literal": "***@example.com"},
        });
        let (status, _) = dispatch(state, "policy.upserted", payload).await;
        assert_eq!(status, StatusCode::OK);
        assert_ne!(pre, Arc::as_ptr(&store.snapshot()).cast::<()>());
    }

    #[tokio::test]
    async fn dispatch_policy_upserted_row_filter_updates_store() {
        let (state, store) = build_state_with_store(TEST_SECRET);
        let pre = Arc::as_ptr(&store.snapshot()).cast::<()>();
        let payload = serde_json::json!({
            "id": "filter-pii-analyst",
            "org": "acme",
            "tag_urn": TEST_TAG_URN,
            "group": "analyst",
            "rule": {"kind": "row_filter", "sql": "email = 'bob@example.com'"},
        });
        let (status, _) = dispatch(state, "policy.upserted", payload).await;
        assert_eq!(status, StatusCode::OK);
        assert_ne!(pre, Arc::as_ptr(&store.snapshot()).cast::<()>());
    }

    #[tokio::test]
    async fn dispatch_policy_deleted_updates_store() {
        let (state, store) = build_state_with_seeded_policy(TEST_SECRET);
        let pre = Arc::as_ptr(&store.snapshot()).cast::<()>();
        let (status, _) = dispatch(
            state,
            "policy.deleted",
            serde_json::json!({"id": "mask-pii-analyst"}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_ne!(pre, Arc::as_ptr(&store.snapshot()).cast::<()>());
    }

    #[tokio::test]
    async fn dispatch_certification_upserted_updates_store() {
        let (state, store) = build_state_with_store(TEST_SECRET);
        let pre = Arc::as_ptr(&store.snapshot()).cast::<()>();
        let payload = serde_json::json!({
            "entity_urn": TEST_SCHEMA_FIELD_URN,
            "certification": "steward.alice",
        });
        let (status, _) = dispatch(state, "certification.upserted", payload).await;
        assert_eq!(status, StatusCode::OK);
        // Certification is a sidecar — does NOT trigger an enforcer
        // rebuild today (slice 3 stores it but enforcement-side
        // semantics are deferred per spec §"RuleChange variants").
        // So the snapshot pointer is allowed to be stable; we only
        // assert the 200 disposition. Slice 3+ wires this through
        // Interface 5.
        let _ = pre;
        let _ = store;
    }

    #[tokio::test]
    async fn dispatch_certification_deleted_returns_200_even_when_absent() {
        let (state, _store) = build_state_with_store(TEST_SECRET);
        let payload = serde_json::json!({
            "entity_urn": TEST_SCHEMA_FIELD_URN,
            "certification": "steward.alice",
        });
        let (status, body) = dispatch(state, "certification.deleted", payload).await;
        // Deleting an absent certification is a no-op (idempotent
        // per the slice-2 store contract), but the handler still
        // ack's 200.
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["status"], "accepted");
    }

    /// Invalid URN ⇒ adapter rejection ⇒ 400 with
    /// `ADAPTER_VALIDATION_FAILED`. Pins the spec's exit-criterion
    /// "adapter rejects unknown payload with 400."
    #[tokio::test]
    async fn dispatch_invalid_urn_returns_400_with_adapter_failure() {
        let (state, store) = build_state_with_store(TEST_SECRET);
        let counter = state.events_total.clone();
        let pre = Arc::as_ptr(&store.snapshot()).cast::<()>();
        let bad_payload = serde_json::json!({
            "entity_urn": "not-a-urn",
            "tag_urn": TEST_TAG_URN,
        });
        let (status, body) = dispatch(state, "tag.assigned", bad_payload).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "ADAPTER_VALIDATION_FAILED");
        // Store stays at its pre-apply snapshot pointer.
        assert_eq!(pre, Arc::as_ptr(&store.snapshot()).cast::<()>());
        assert_eq!(
            counter
                .with_label_values(&["tag.assigned", "rejected_adapter_urn"])
                .get(),
            1
        );
    }

    /// Missing payload field ⇒ adapter rejection (serde) ⇒ 400.
    #[tokio::test]
    async fn dispatch_missing_payload_field_returns_400() {
        let (state, _store) = build_state_with_store(TEST_SECRET);
        let counter = state.events_total.clone();
        let bad_payload = serde_json::json!({"entity_urn": TEST_SCHEMA_FIELD_URN}); // no tag_urn
        let (status, body) = dispatch(state, "tag.assigned", bad_payload).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "ADAPTER_VALIDATION_FAILED");
        assert_eq!(
            counter
                .with_label_values(&["tag.assigned", "rejected_adapter_payload"])
                .get(),
            1
        );
    }

    /// `rule_store = None` (the test-only state shape) returns 500
    /// with `RULE_STORE_UNAVAILABLE`. Production boot can't reach
    /// this branch — but the test-double `build_state` exposes it,
    /// and that path needs to fail loudly rather than silently echo.
    #[tokio::test]
    async fn dispatch_returns_500_when_rule_store_unconfigured() {
        let state = build_state(TEST_SECRET);
        let counter = state.events_total.clone();
        let (status, body) = dispatch(state, "tag.assigned", datahub_tag_payload()).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body["error"], "RULE_STORE_UNAVAILABLE");
        assert_eq!(
            counter
                .with_label_values(&["tag.assigned", "rejected_no_store"])
                .get(),
            1
        );
    }
}

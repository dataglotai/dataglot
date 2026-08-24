//! Integration tests for the REST/JSON federation connector.
//!
//! The connector's inline `#[cfg(test)]` tests already cover the happy paths
//! end-to-end via a `SessionContext` + wiremock (full scan, projection, limit,
//! `NextLink` pagination, the `OAuth2` bearer flow, and the Salesforce /
//! athenahealth profiles). This file adds the behaviors those don't reach:
//!
//! * outgoing **static auth headers** actually reach the upstream (Bearer /
//!   custom header / Basic), asserted via the mock's received requests, and
//! * **query-time error surfacing** — a non-2xx HTTP status and a malformed
//!   JSON body must both fail the query cleanly rather than hang or panic.
//!
//! Runnable without Docker — wiremock is an in-process mock HTTP server — so
//! these are NOT `#[ignore]`d.

#![cfg(feature = "rest")]

use std::sync::Arc;

use datafusion::arrow::array::RecordBatch;
use datafusion::arrow::datatypes::{DataType, Field, Schema};
use datafusion::error::Result as DfResult;
use datafusion::prelude::SessionContext;
use dataglot_federation::rest::{
    RestAuth, RestConnector, RestPagination, RestSourceConfig, RestTable,
};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// A single-column `things` table pointed at `{server}/things`, with `auth`.
fn things_table(server_uri: &str, auth: RestAuth) -> RestTable {
    RestTable {
        name: "things".to_string(),
        config: RestSourceConfig {
            url: format!("{server_uri}/things"),
            records_path: "records".to_string(),
            auth,
            pagination: RestPagination::None,
            pushdown: vec![],
        },
        schema: Arc::new(Schema::new(vec![Field::new("id", DataType::Int64, true)])),
    }
}

/// Register a `things` table backed by `auth` and run a full scan.
async fn query_things(server_uri: &str, auth: RestAuth) -> DfResult<Vec<RecordBatch>> {
    let connector = Arc::new(
        RestConnector::new("rest_demo", vec![things_table(server_uri, auth)])
            .expect("HTTP client builds"),
    );
    let ctx = SessionContext::new();
    ctx.register_catalog("rest_demo", connector.as_catalog_provider("public"));
    ctx.sql("SELECT id FROM rest_demo.public.things ORDER BY id")
        .await?
        .collect()
        .await
}

/// A static `Bearer` token must be sent on the outgoing request. Prior tests
/// used Bearer auth but never asserted the header actually reached the upstream
/// — a silent regression there would leak requests unauthenticated.
#[tokio::test]
async fn static_bearer_auth_header_reaches_upstream() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/things"))
        .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"records":[{"id":1}]}"#))
        .mount(&server)
        .await;

    let batches = query_things(
        &server.uri(),
        RestAuth::Bearer {
            token: "sekret-tok".into(),
        },
    )
    .await
    .expect("bearer query runs");
    assert_eq!(batches.iter().map(RecordBatch::num_rows).sum::<usize>(), 1);

    let reqs = server.received_requests().await.unwrap();
    assert!(
        reqs.iter().any(|r| {
            r.headers.get("authorization").and_then(|v| v.to_str().ok())
                == Some("Bearer sekret-tok")
        }),
        "the static Bearer token must be sent as an Authorization header"
    );
}

/// A custom header credential (e.g. `X-Api-Key`) and Basic auth must both reach
/// the upstream.
#[tokio::test]
async fn static_custom_header_and_basic_auth_reach_upstream() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/things"))
        .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"records":[{"id":1}]}"#))
        .mount(&server)
        .await;

    query_things(
        &server.uri(),
        RestAuth::Header {
            name: "X-Api-Key".into(),
            value: "abc123".into(),
        },
    )
    .await
    .expect("header-auth query runs");

    query_things(
        &server.uri(),
        RestAuth::Basic {
            user: "svc".into(),
            password: "pw".into(),
        },
    )
    .await
    .expect("basic-auth query runs");

    let reqs = server.received_requests().await.unwrap();
    assert!(
        reqs.iter().any(|r| {
            r.headers.get("x-api-key").and_then(|v| v.to_str().ok()) == Some("abc123")
        }),
        "the custom header credential must be sent verbatim"
    );
    assert!(
        reqs.iter().any(|r| {
            r.headers
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| v.starts_with("Basic "))
        }),
        "Basic auth must be sent as an Authorization: Basic header"
    );
}

/// A non-2xx upstream status must fail the query (the connector calls
/// `error_for_status`), not silently yield an empty result.
#[tokio::test]
async fn http_error_status_surfaces_as_query_error() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/things"))
        .respond_with(ResponseTemplate::new(500).set_body_string("upstream boom"))
        .mount(&server)
        .await;

    let err = query_things(&server.uri(), RestAuth::None)
        .await
        .expect_err("HTTP 500 must fail the query");
    let msg = err.to_string();
    assert!(
        msg.contains("500") || msg.to_lowercase().contains("status"),
        "expected an HTTP-status error, got: {msg}"
    );
}

/// A 200 response whose body is not the expected JSON shape must surface as a
/// clean decode error at query time (the decoder is unit-tested directly, but
/// not its surfacing through `scan`/`execute`).
#[tokio::test]
async fn malformed_json_body_surfaces_as_query_error() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/things"))
        .respond_with(ResponseTemplate::new(200).set_body_string("not json at all"))
        .mount(&server)
        .await;

    let err = query_things(&server.uri(), RestAuth::None)
        .await
        .expect_err("a non-JSON body must fail the query");
    // Just assert it is a real, non-empty error — the exact message is the
    // serde/decode layer's to phrase.
    assert!(!err.to_string().is_empty());
}

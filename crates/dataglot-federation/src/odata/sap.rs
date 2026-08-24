//! SAP S/4HANA thin layer over the generic OData v2 connector (Phase 4,
//!  slice 2).
//!
//! SAP's OData services are ordinary OData v2 — the generic
//! [`OdataConnector`] does the real work (schema discovery, pushdown, JSON
//! decode). This layer adds only the SAP-specific request conventions:
//!
//! - **`sap-client` header** — selects the SAP client (mandant), e.g. `"100"`.
//!   Sent on every request as an HTTP header.
//! - **`sap-language` header** — optional logon language (e.g. `"EN"`).
//! - **URL convention** — SAP services live under
//!   `/sap/opu/odata/sap/<service>/`; the caller passes that full prefix as
//!   the `service_url`, and the entity set is the table-shaped name, so no
//!   special URL handling is needed here.
//! - **`Edm.DateTime` as `/Date(ms)/`** — already handled by the shared
//!   [`super::decode`], so no SAP-specific decoding is required.
//!
//! The headers are applied by building the `reqwest::Client` with
//! `default_headers`, so they ride every request the underlying connector
//! issues (both `$metadata` and entity-set scans).

use std::sync::Arc;

use datafusion::catalog::{CatalogProvider as DfCatalogProvider, TableProvider};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::Client;

use dataglot_core::{DataglotError, Result as DataglotResult};

use super::connector::{OdataAuth, OdataConnector, REQUEST_TIMEOUT};

/// SAP-specific request options layered onto a [`SapConnector`].
#[derive(Debug, Clone, Default)]
pub struct SapOptions {
    /// The SAP client / mandant (`sap-client` header), e.g. `"100"`.
    pub sap_client: Option<String>,
    /// The logon language (`sap-language` header), e.g. `"EN"`.
    pub sap_language: Option<String>,
}

/// A connector to an SAP S/4HANA OData v2 service — a thin wrapper over
/// [`OdataConnector`] that sends the SAP client/language headers.
///
/// The inner connector is held behind an `Arc` so it can be handed to
/// [`OdataConnector::as_catalog_provider`] (which needs `&Arc<Self>`) for
/// server registration.
#[derive(Debug)]
pub struct SapConnector {
    inner: Arc<OdataConnector>,
}

impl SapConnector {
    /// Connect to an SAP OData service at `service_url` (the full
    /// `/sap/opu/odata/sap/<service>` prefix), sending the SAP headers from
    /// `options` on every request.
    ///
    /// # Errors
    /// [`DataglotError::Configuration`] if a header value is invalid, or
    /// [`DataglotError::Connection`] if the HTTP client can't be built.
    pub fn connect(
        name: impl Into<String>,
        service_url: impl Into<String>,
        auth: OdataAuth,
        options: &SapOptions,
    ) -> DataglotResult<Self> {
        let http = Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .default_headers(sap_headers(options)?)
            .build()
            .map_err(|e| {
                DataglotError::connection(format!("failed to build SAP HTTP client: {e}"))
            })?;
        Ok(Self {
            inner: Arc::new(OdataConnector::with_client(name, service_url, auth, http)),
        })
    }

    /// Operator-visible identifier (the catalog name).
    #[must_use]
    pub fn name(&self) -> &str {
        self.inner.name()
    }

    /// Resolve `entity_set` into a DataFusion [`TableProvider`] (delegates to
    /// the underlying OData connector; SAP headers ride every request).
    ///
    /// # Errors
    /// As [`OdataConnector::table_provider`].
    pub async fn table_provider(&self, entity_set: &str) -> DataglotResult<Arc<dyn TableProvider>> {
        self.inner.table_provider(entity_set).await
    }

    /// Wrap this SAP connector as a `DataFusion` [`CatalogProvider`] for
    /// server registration — every entity set of the service becomes a
    /// table, with the SAP headers riding each request. Delegates to
    /// [`OdataConnector::as_catalog_provider`].
    ///
    /// # Errors
    /// As [`OdataConnector::as_catalog_provider`].
    ///
    /// [`CatalogProvider`]: datafusion::catalog::CatalogProvider
    pub async fn as_catalog_provider(&self) -> DataglotResult<Arc<dyn DfCatalogProvider>> {
        self.inner.as_catalog_provider().await
    }
}

/// Build the SAP default-header map from the options. A header name is fixed
/// (static), so only the value can be malformed (e.g. a non-ASCII client).
fn sap_headers(options: &SapOptions) -> DataglotResult<HeaderMap> {
    let mut headers = HeaderMap::new();
    if let Some(client) = &options.sap_client {
        headers.insert(
            HeaderName::from_static("sap-client"),
            header_value("sap-client", client)?,
        );
    }
    if let Some(language) = &options.sap_language {
        headers.insert(
            HeaderName::from_static("sap-language"),
            header_value("sap-language", language)?,
        );
    }
    Ok(headers)
}

/// Parse a header value, mapping an invalid one to a clear config error
/// (no secret is involved — these are client/language codes).
fn header_value(name: &str, value: &str) -> DataglotResult<HeaderValue> {
    HeaderValue::from_str(value).map_err(|_| {
        DataglotError::configuration(format!("invalid '{name}' header value: '{value}'"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use datafusion::prelude::SessionContext;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const EDMX: &str = r#"<Schema xmlns="http://schemas.microsoft.com/ado/2008/09/edm">
      <EntityType Name="BP"><Property Name="BusinessPartner" Type="Edm.String" Nullable="false"/></EntityType>
      <EntityContainer><EntitySet Name="A_BusinessPartner" EntityType="X.BP"/></EntityContainer>
    </Schema>"#;

    const RESULTS: &str = r#"{"d":{"results":[{"BusinessPartner":"1"},{"BusinessPartner":"2"}]}}"#;

    #[test]
    fn header_value_rejects_invalid() {
        assert!(header_value("sap-client", "10\n0").is_err());
        assert!(header_value("sap-client", "100").is_ok());
    }

    #[test]
    fn sap_headers_only_includes_set_options() {
        let none = sap_headers(&SapOptions::default()).unwrap();
        assert!(none.is_empty());
        let both = sap_headers(&SapOptions {
            sap_client: Some("100".into()),
            sap_language: Some("EN".into()),
        })
        .unwrap();
        assert_eq!(both.get("sap-client").unwrap(), "100");
        assert_eq!(both.get("sap-language").unwrap(), "EN");
    }

    #[tokio::test]
    async fn sends_sap_client_header_on_every_request() {
        let server = MockServer::start().await;
        // Both endpoints require the sap-client header to match — if it's
        // missing, wiremock returns no match and the request fails.
        Mock::given(method("GET"))
            .and(path("/$metadata"))
            .and(header("sap-client", "100"))
            .respond_with(ResponseTemplate::new(200).set_body_string(EDMX))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/A_BusinessPartner"))
            .and(header("sap-client", "100"))
            .respond_with(ResponseTemplate::new(200).set_body_string(RESULTS))
            .mount(&server)
            .await;

        let conn = SapConnector::connect(
            "sap",
            server.uri(),
            OdataAuth::Basic {
                user: "u".into(),
                password: "p".into(),
            },
            &SapOptions {
                sap_client: Some("100".into()),
                sap_language: None,
            },
        )
        .expect("connect");

        let provider = conn
            .table_provider("A_BusinessPartner")
            .await
            .expect("schema (with sap-client header)");
        let ctx = SessionContext::new();
        ctx.register_table("bp", provider).unwrap();
        let batches = ctx
            .sql("SELECT * FROM bp")
            .await
            .unwrap()
            .collect()
            .await
            .expect("query (with sap-client header)");
        let rows: usize = batches
            .iter()
            .map(arrow::array::RecordBatch::num_rows)
            .sum();
        assert_eq!(rows, 2);

        // Every received request carried the header (both $metadata + scan).
        let requests = server.received_requests().await.unwrap();
        assert!(requests.len() >= 2);
        for r in &requests {
            assert_eq!(
                r.headers.get("sap-client").map(|v| v.to_str().unwrap()),
                Some("100"),
                "sap-client header on {}",
                r.url.path()
            );
        }
    }
}

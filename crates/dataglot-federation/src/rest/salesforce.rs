//! Salesforce profile for the REST connector.
//!
//! A thin builder — analogous to the `OData` connector's `sap` layer — that
//! maps a Salesforce object to a [`RestTable`] over the generic REST connector:
//! the SOQL `/query` endpoint, rows at `records`, and `nextRecordsUrl`
//! pagination.
//!
//! Auth is a static OAuth 2.0 **session token** (used as a `Bearer`); acquiring
//! and refreshing that token (the OAuth 2.0 flow) is deferred to a later slice —
//! the caller supplies a currently-valid token.

use arrow::datatypes::SchemaRef;
use reqwest::Url;

use dataglot_core::{DataglotError, Result as DataglotResult};

use super::connector::{RestAuth, RestPagination, RestSourceConfig, RestTable};
use super::oauth2::OAuth2Config;

/// Build the OAuth 2.0 client-credentials config for a Salesforce org's token
/// endpoint (`{login_url}/services/oauth2/token`, e.g. `login_url =
/// https://login.salesforce.com` or a My Domain URL).
///
/// Pair it with [`super::oauth2::OAuth2TokenCache`] +
/// [`super::connector::RestConnector::with_oauth2`] so the connector acquires
/// and refreshes the session token itself, instead of the caller supplying a
/// static one to [`salesforce_table`].
#[must_use]
pub fn salesforce_oauth2_config(
    login_url: &str,
    client_id: impl Into<String>,
    client_secret: impl Into<String>,
) -> OAuth2Config {
    OAuth2Config {
        token_url: format!("{}/services/oauth2/token", login_url.trim_end_matches('/')),
        client_id: client_id.into(),
        client_secret: client_secret.into(),
        extra_params: Vec::new(),
    }
}

/// Build a [`RestTable`] for a Salesforce object queried via SOQL.
///
/// The table is served from
/// `{instance_url}/services/data/{api_version}/query?q={soql}`, with the row
/// array at `records` and `nextRecordsUrl` pagination (Salesforce returns up to
/// 2000 rows per page). `schema` declares the Arrow columns the selected SOQL
/// fields decode into (matching the `SELECT` list).
///
/// `session_token` is a Salesforce OAuth 2.0 access token, sent as a bearer;
/// obtaining and refreshing it is the caller's responsibility for now.
///
/// # Errors
/// [`DataglotError::Catalog`] if `instance_url` is not a valid base URL.
pub fn salesforce_table(
    name: impl Into<String>,
    instance_url: &str,
    api_version: &str,
    soql: &str,
    session_token: impl Into<String>,
    schema: SchemaRef,
) -> DataglotResult<RestTable> {
    let base = format!(
        "{}/services/data/{}/query",
        instance_url.trim_end_matches('/'),
        api_version,
    );
    let mut url = Url::parse(&base)
        .map_err(|e| DataglotError::catalog(format!("invalid Salesforce instance_url: {e}")))?;
    url.query_pairs_mut().append_pair("q", soql);

    Ok(RestTable {
        name: name.into(),
        config: RestSourceConfig {
            url: url.to_string(),
            records_path: "records".to_string(),
            auth: RestAuth::Bearer {
                token: session_token.into(),
            },
            pagination: RestPagination::NextLink {
                next_path: "nextRecordsUrl".to_string(),
            },
            pushdown: vec![],
        },
        schema,
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use arrow::array::RecordBatch;
    use arrow::datatypes::{DataType, Field, Schema};
    use datafusion::prelude::SessionContext;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::salesforce_table;
    use crate::rest::RestConnector;

    #[tokio::test]
    async fn soql_query_reads_all_records_across_pages() {
        let server = MockServer::start().await;
        // Salesforce query response shape: totalSize/done + records, with a
        // relative `nextRecordsUrl` on the non-final page.
        let page1 = r#"{"totalSize":3,"done":false,
            "nextRecordsUrl":"/services/data/v58.0/query/01g-2000",
            "records":[{"Id":"a","Name":"Acme"},{"Id":"b","Name":"Beta"}]}"#;
        let page2 = r#"{"totalSize":3,"done":true,
            "records":[{"Id":"c","Name":"Cyan"}]}"#;
        Mock::given(method("GET"))
            .and(path("/services/data/v58.0/query"))
            .respond_with(ResponseTemplate::new(200).set_body_string(page1))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/services/data/v58.0/query/01g-2000"))
            .respond_with(ResponseTemplate::new(200).set_body_string(page2))
            .mount(&server)
            .await;

        let schema = Arc::new(Schema::new(vec![
            Field::new("Id", DataType::Utf8, true),
            Field::new("Name", DataType::Utf8, true),
        ]));
        let table = salesforce_table(
            "account",
            &server.uri(),
            "v58.0",
            "SELECT Id, Name FROM Account",
            "sess-tok",
            schema,
        )
        .expect("build table");
        // The SOQL query is carried as the `q` param on the /query endpoint.
        assert!(table.config.url.contains("/services/data/v58.0/query"));
        assert!(table.config.url.contains("q="));

        let connector = Arc::new(
            RestConnector::with_client("sf", vec![table], reqwest::Client::new()).unwrap(),
        );
        let ctx = SessionContext::new();
        ctx.register_catalog("sf", connector.as_catalog_provider("public"));

        let batches = ctx
            .sql(r#"SELECT "Name" FROM sf.public.account ORDER BY "Name""#)
            .await
            .expect("plan")
            .collect()
            .await
            .expect("run");
        let rows: usize = batches.iter().map(RecordBatch::num_rows).sum();
        assert_eq!(rows, 3, "all records across both SOQL pages");
    }
}

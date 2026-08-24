//! athenahealth profile for the REST connector.
//!
//! A thin builder — analogous to [`super::salesforce`] — for the athenahealth
//! platform API. Collection endpoints live at `{base_url}/v1/{practice_id}/…`,
//! nest the rows under a resource key (e.g. `patients`), and paginate via a
//! `next` link (a relative URL, resolved like Salesforce's `nextRecordsUrl`).
//!
//! Auth is OAuth 2.0 client-credentials — reuse [`athenahealth_oauth2_config`]
//! with [`super::oauth2::OAuth2TokenCache`] +
//! [`super::connector::RestConnector::with_oauth2`] so the connector acquires
//! and refreshes the bearer itself.

use arrow::datatypes::SchemaRef;

use super::connector::{RestAuth, RestPagination, RestSourceConfig, RestTable};
use super::oauth2::OAuth2Config;

/// Build the OAuth 2.0 client-credentials config for an athenahealth token
/// endpoint (`{base_url}/oauth2/v1/token`, e.g. `base_url =
/// https://api.platform.athenahealth.com`). `scope` is required by athenahealth
/// (e.g. `athena/service/Athenanet.MDP.*`).
#[must_use]
pub fn athenahealth_oauth2_config(
    base_url: &str,
    client_id: impl Into<String>,
    client_secret: impl Into<String>,
    scope: impl Into<String>,
) -> OAuth2Config {
    OAuth2Config {
        token_url: format!("{}/oauth2/v1/token", base_url.trim_end_matches('/')),
        client_id: client_id.into(),
        client_secret: client_secret.into(),
        extra_params: vec![("scope".to_string(), scope.into())],
    }
}

/// Build a [`RestTable`] for an athenahealth collection endpoint.
///
/// The table is served from `{base_url}/v1/{practice_id}/{resource}`, with the
/// row array at `records_path` (athenahealth nests the collection under a
/// resource key — usually the same word as `resource`, e.g. `patients`) and
/// `next`-link pagination.
///
/// Auth is left [`RestAuth::None`] here — pair the connector with
/// [`athenahealth_oauth2_config`] + [`super::oauth2::OAuth2TokenCache`] via
/// [`super::connector::RestConnector::with_oauth2`], so every request carries a
/// live bearer.
#[must_use]
pub fn athenahealth_table(
    name: impl Into<String>,
    base_url: &str,
    practice_id: &str,
    resource: &str,
    records_path: impl Into<String>,
    schema: SchemaRef,
) -> RestTable {
    let url = format!(
        "{}/v1/{}/{}",
        base_url.trim_end_matches('/'),
        practice_id,
        resource.trim_start_matches('/'),
    );
    RestTable {
        name: name.into(),
        config: RestSourceConfig {
            url,
            records_path: records_path.into(),
            auth: RestAuth::None,
            pagination: RestPagination::NextLink {
                next_path: "next".to_string(),
            },
            pushdown: vec![],
        },
        schema,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use arrow::array::RecordBatch;
    use arrow::datatypes::{DataType, Field, Schema};
    use datafusion::prelude::SessionContext;
    use wiremock::matchers::{method, path, query_param, query_param_is_missing};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::{athenahealth_oauth2_config, athenahealth_table};
    use crate::rest::RestConnector;

    #[test]
    fn oauth2_config_targets_the_token_endpoint() {
        let cfg = athenahealth_oauth2_config(
            "https://api.platform.athenahealth.com/",
            "cid",
            "csecret",
            "athena/service/Athenanet.MDP.*",
        );
        assert_eq!(
            cfg.token_url,
            "https://api.platform.athenahealth.com/oauth2/v1/token"
        );
        assert_eq!(
            cfg.extra_params,
            vec![(
                "scope".to_string(),
                "athena/service/Athenanet.MDP.*".to_string()
            )]
        );
    }

    #[tokio::test]
    async fn reads_a_collection_across_next_pages() {
        let server = MockServer::start().await;
        // athenahealth collection shape: {totalcount, <resource>: [...], next}.
        // Page 1 carries a relative `next` with an offset; page 2 has none.
        let page1 = r#"{"totalcount":3,
            "patients":[{"patientid":"1","lastname":"Acer"},{"patientid":"2","lastname":"Byrd"}],
            "next":"/v1/195900/patients?offset=2"}"#;
        let page2 = r#"{"totalcount":3,
            "patients":[{"patientid":"3","lastname":"Cole"}]}"#;
        Mock::given(method("GET"))
            .and(path("/v1/195900/patients"))
            .and(query_param_is_missing("offset"))
            .respond_with(ResponseTemplate::new(200).set_body_string(page1))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v1/195900/patients"))
            .and(query_param("offset", "2"))
            .respond_with(ResponseTemplate::new(200).set_body_string(page2))
            .mount(&server)
            .await;

        let schema = Arc::new(Schema::new(vec![
            Field::new("patientid", DataType::Utf8, true),
            Field::new("lastname", DataType::Utf8, true),
        ]));
        let table = athenahealth_table(
            "patients",
            &server.uri(),
            "195900",
            "patients",
            "patients",
            schema,
        );
        assert!(table.config.url.ends_with("/v1/195900/patients"));

        let connector = Arc::new(
            RestConnector::with_client("athena", vec![table], reqwest::Client::new()).unwrap(),
        );
        let ctx = SessionContext::new();
        ctx.register_catalog("athena", connector.as_catalog_provider("public"));

        let batches = ctx
            .sql(r#"SELECT "lastname" FROM athena.public.patients ORDER BY "lastname""#)
            .await
            .expect("plan")
            .collect()
            .await
            .expect("run");
        let rows: usize = batches.iter().map(RecordBatch::num_rows).sum();
        assert_eq!(rows, 3, "all patients across both pages");
    }
}

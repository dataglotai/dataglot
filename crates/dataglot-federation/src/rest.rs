//! Generic REST/JSON federation connector (Phase 4, ).
//!
//! A sibling of the OData connector ([`super::odata`]): a REST API is queried
//! with an HTTP `GET` and has no remote SQL engine to unparse to, so — per
//! CLAUDE.md rule 3 — this is a **direct `TableProvider`**, not a
//! `datafusion-federation` `SQLExecutor`.
//!
//! Unlike OData there is no universal metadata document, so a source declares
//! its Arrow schema, and the location of the row array in the response is a
//! configurable dot-path (`records_path`) — e.g. `"records"` for Salesforce, a
//! nested path, or `""` for a top-level array.
//!
//! # Slices
//!
//! - [`decode`] — turn a REST/JSON response into an Arrow `RecordBatch` for a
//!   declared schema (slice 1).
//! - [`connector`] — [`RestAuth`] + [`RestSourceConfig`] (slice 1), the
//!   queryable [`RestConnector`] / `TableProvider` / scan `ExecutionPlan`
//!   (slice 2), and [`RestPagination`] — follow a next-page link (slice 3).
//! - [`oauth2`] — OAuth 2.0 client-credentials token acquisition + caching, so
//!   the connector authenticates to its source with a live, refreshed bearer.
//! - [`salesforce`] / [`athenahealth`] — per-API profiles over the generic
//!   connector (SOQL `/query` + `nextRecordsUrl`; athenahealth `/v1/…` + `next`
//!   pagination), analogous to [`super::odata`]'s `sap` layer.
//! - Server config wiring (`kind = "rest"`, incl. `auth.kind = "oauth2"`) lives
//!   in `dataglot-server`. Equality-predicate pushdown to API query parameters
//!   ([`RestPushdownParam`]) is implemented; `$select` projection
//!   pushdown is a later slice.

pub mod athenahealth;
pub mod connector;
pub mod decode;
pub mod oauth2;
pub mod salesforce;

pub use athenahealth::{athenahealth_oauth2_config, athenahealth_table};
pub use connector::{
    RestAuth, RestClientOptions, RestConnector, RestPagination, RestPushdownParam,
    RestSourceConfig, RestTable,
};
pub use decode::{decode_json_page, decode_json_rows};
pub use oauth2::{OAuth2Config, OAuth2TokenCache};
pub use salesforce::{salesforce_oauth2_config, salesforce_table};

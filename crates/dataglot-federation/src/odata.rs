//! OData v2 generic federation connector (Phase 4 · Task 01, ).
//!
//! OData is a REST protocol, not SQL: a source is queried with a `GET`
//! against an entity-set URL carrying query-string parameters (`$select`,
//! `$filter`, `$top`, …). There is no remote SQL engine to unparse to, so —
//! per CLAUDE.md rule 3 — this connector is a **direct `TableProvider`**, not
//! a `datafusion-federation` `SQLExecutor`.
//!
//! # Slices
//!
//! Pieces:
//! - [`filter`] translates DataFusion filter [`Expr`](datafusion::logical_expr::Expr)s
//!   into an OData v2 `$filter` string and reports which filters were pushed.
//! - [`metadata`] parses an OData v2 `$metadata` (EDMX) document into an
//!   Arrow schema for a named entity set.
//! - [`decode`] turns an OData v2 JSON entity-set response into an Arrow
//!   `RecordBatch`.
//! - [`connector`] ties them together: [`OdataConnector`] discovers schema
//!   and hands out an `OdataTableProvider` whose scan issues the HTTP `GET`
//!   (with `$select`/`$filter`/`$top`) and decodes the result.
//! - [`sap`] is a thin SAP S/4HANA layer over [`OdataConnector`] adding the
//!   `sap-client` / `sap-language` request headers.
//!
//! See `docs/phases/phase-4/01-odata-sap-s4hana-connector.md`.

pub mod connector;
pub mod decode;
pub mod filter;
pub mod metadata;
pub mod sap;

pub use connector::{OdataAuth, OdataConnector};
pub use decode::decode_entity_set;
pub use filter::{translate_filters, FilterTranslation};
pub use metadata::{parse_edmx_catalog, parse_edmx_schema};
pub use sap::{SapConnector, SapOptions};

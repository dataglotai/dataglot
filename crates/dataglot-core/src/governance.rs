//! Data product registration + column-definition sync —
//! §11 Interfaces #2 and #5 of the governance integration epic.
//!
//! Spec:
//! - the phase-1 `data-product-registration` plan
//! - the phase-1 `column-definition-sync` plan
//!
//! This module plants the **trait + types** for the outbound
//! channel from the Peaka Catalog Service to a governance
//! backend (`DataHub` / `OpenMetadata` / Informatica). The HTTP
//! adapter that implements [`DataProductPublisher`] lives in
//! `dataglot-server::governance` (`reqwest` belongs there per
//! hard rule 4).
//!
//! # Phase 1 scope
//!
//! - Trait surface + value types — this module.
//! - `Placeholder` is the only [`ColumnDefinitionSource`] variant
//!   Phase 1 ever produces. `Llm` and `Steward` are forward-
//!   compat slots: their wire shape is locked in now so Phase 2
//!   (LLM) and Phase 3 (steward inbound via §11 Interface #3)
//!   land without renegotiating the JSON.
//!
//! # Failure isolation
//!
//! The trait's only method returns `()` rather than `Result`,
//! matching the `OpenLineage` emitter contract
//! ([`crate::lineage::LineageEmitter`]). Implementations log +
//! drop on backend failure. A governance-backend outage MUST
//! NOT propagate to the query path or to server boot — same
//! rule as the lineage spec's "Lineage emission MUST NOT
//! propagate failures" exit criterion.

use std::time::SystemTime;

use serde::{Deserialize, Serialize};

/// One column's metadata as it appears on the outbound wire to
/// the governance backend.
///
/// The Arrow type is rendered as a string (e.g. `"Utf8"`,
/// `"Decimal128(10, 2)"`) because every backend in scope —
/// `DataHub`, `OpenMetadata`, Informatica — has its own type
/// taxonomy and the per-backend adapter handles the
/// Arrow→backend mapping at HTTP-build time. Carrying the
/// Arrow type as a typed enum here would force every backend
/// adapter to import the full Arrow type tree for no
/// downstream benefit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ColumnMetadata {
    /// Column name as it appears in the source schema.
    pub name: String,
    /// String rendering of the column's Arrow type. Per-backend
    /// adapter translates to the backend's vocabulary.
    pub arrow_type: String,
    /// Whether the source declared the column nullable.
    pub nullable: bool,
    /// Provenance of [`ColumnMetadata::definition`].
    pub definition_source: ColumnDefinitionSource,
    /// Human-readable description. Phase 1 ships
    /// `"Pending Dataglot-side definition"` for every column;
    /// Phase 2 LLM and Phase 3 steward replace this string via
    /// the producer variant on `definition_source`.
    pub definition: String,
}

/// Three-state provenance of a column definition.
///
/// Closed enum (no `#[non_exhaustive]`) — a fourth variant
/// would be a wire-shape break across Phase versions. Spec'd
/// in the phase-1 `column-definition-sync` plan;
/// implementations are added per phase:
///
/// - **Phase 1** (this PR): only [`Self::Placeholder`] is
///   produced.
/// - **Phase 2**: LLM data dictionary fills in
///   [`Self::Llm`] values.
/// - **Phase 3**: steward inbound (§11 Interface #3) writes
///   [`Self::Steward`] rows from the governance backend.
///
/// The wire shape (`#[serde(tag = "kind", rename_all =
/// "snake_case")]`) is byte-stable across the three phases —
/// only the producer changes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ColumnDefinitionSource {
    /// Phase 1 default. No definition yet; LLM hasn't run and
    /// no steward has certified. The accompanying
    /// [`ColumnMetadata::definition`] string is
    /// `"Pending Dataglot-side definition"` per the spec.
    Placeholder,
    /// Phase 2. The LLM data-dictionary pipeline produced
    /// this definition.
    Llm {
        /// When the LLM ran. Wall-clock; cross-system clock
        /// correlation matters more than nanosecond
        /// resolution.
        generated_at: SystemTime,
        /// Model identifier (e.g. `"claude-opus-4-7"`).
        /// Open-ended string so model bumps don't churn the
        /// wire shape.
        model: String,
    },
    /// Phase 3 inbound (§11 Interface #3). A human steward
    /// certified this definition via the governance backend's
    /// UI; the inbound webhook surfaced it back to Dataglot.
    /// Authoritative — overrides any prior `Placeholder` or
    /// `Llm` value.
    Steward {
        /// Steward identifier from the inbound webhook.
        /// Format is the governance backend's identity-
        /// provider string (e.g. `"jane.doe@acme.com"`,
        /// `"datahub-user:42"`).
        certified_by: String,
        /// When the steward certified. Wall-clock; same
        /// rationale as `Llm::generated_at`.
        certified_at: SystemTime,
    },
}

/// Phase 1 placeholder description text. Pinned as a `const`
/// so a Phase 2 swap to LLM-generated descriptions is a
/// clear find-and-replace signal across the codebase.
pub const PLACEHOLDER_DEFINITION: &str = "Pending Dataglot-side definition";

/// Construct a `Placeholder`-source [`ColumnMetadata`] with
/// the standard placeholder definition string. Helper for the
/// catalog service's outbound publish path — saves repeating
/// the placeholder string at every call site.
#[must_use]
pub fn placeholder_column(name: String, arrow_type: String, nullable: bool) -> ColumnMetadata {
    ColumnMetadata {
        name,
        arrow_type,
        nullable,
        definition_source: ColumnDefinitionSource::Placeholder,
        definition: PLACEHOLDER_DEFINITION.to_string(),
    }
}

/// Connector kind the data product routes through. Maps to
/// the backend's `platform` field — `DataHub` has a pre-baked
/// vocabulary (`postgres`, `mysql`, `iceberg`, etc.) that
/// matches one-for-one; `OpenMetadata` uses the same names.
/// Informatica's vocabulary is custom but the per-backend
/// adapter handles the translation.
///
/// Mirrors [`crate::catalog::LiveConnectorKind`] +
/// [`crate::catalog::IcebergCacheBinding`] but stays
/// independent on purpose — the platform here is the
/// *governance-facing* descriptor, not the connector-side
/// implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProductPlatform {
    /// Live federated Postgres source.
    Postgres,
    /// Live federated `MySQL` source.
    Mysql,
    /// Live federated Snowflake source.
    Snowflake,
    /// Live federated Oracle source (, Exadata displacement).
    Oracle,
    /// Live federated object-storage (Parquet) source.
    ObjectStorage,
    /// Live federated OData v2 / SAP S/4HANA source.
    Odata,
    /// Live federated generic ADBC BYO-driver source. The
    /// platform name is deliberately generic — the actual backing
    /// system is whatever driver the operator supplied, which the
    /// engine cannot classify further.
    Adbc,
    /// Live federated generic REST/JSON source — Salesforce,
    /// Athena Health, and similar `SaaS` APIs.
    Rest,
    /// Iceberg-cached warehouse table (hard rule 7:
    /// the *governance* platform name is `iceberg` because
    /// that's what `DataHub` / `OpenMetadata` expect; the
    /// user-facing surface stays Iceberg-free).
    Iceberg,
}

/// Three-part `(catalog, schema, table)` identifier the
/// outbound publisher renders into a stable URN.
///
/// Same shape as [`crate::lineage::DatasetRef`] but kept
/// independent so the governance and lineage paths can evolve
/// their identifier formats separately. The two happen to
/// match today; that's coincidence, not contract.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TableName {
    /// Catalog name from `dataglot.toml`'s `[catalogs.*]`
    /// block.
    pub catalog: String,
    /// Schema name within the catalog (e.g. `"public"`).
    pub schema: String,
    /// Table name within the schema.
    pub table: String,
}

impl TableName {
    /// Render the URN format §11 Interface #2's outbound
    /// channel uses: `urn:dataglot:<catalog>:<schema>:<table>`.
    /// Stable across phases; the URN is the de-duplication
    /// key on the backend side.
    #[must_use]
    pub fn to_urn(&self) -> String {
        format!(
            "urn:dataglot:{}:{}:{}",
            self.catalog, self.schema, self.table
        )
    }
}

/// One data product as it lands on the outbound wire.
///
/// Backend-agnostic — the per-backend HTTP adapter
/// (`dataglot-server::governance::DataHubPublisher` and
/// future `OpenMetadata` / Informatica adapters) maps this into
/// the backend's body shape (`DataHub` ``MetadataChangeProposal``,
/// `OpenMetadata` `dataAsset`, Informatica v3 catalog).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataProduct {
    /// Stable identifier the backend uses for upsert
    /// dedup. Always [`TableName::to_urn`] today;
    /// Phase 2 multi-tenant adds an `org` segment.
    pub urn: String,
    /// Three-part name.
    pub name: TableName,
    /// Connector kind for the backend's `platform` field.
    pub platform: ProductPlatform,
    /// Per-column metadata. Phase 1 always emits
    /// [`ColumnDefinitionSource::Placeholder`] columns; Phase 2
    /// LLM and Phase 3 steward overrides swap the variant
    /// without changing the rest of the shape.
    pub columns: Vec<ColumnMetadata>,
    /// Optional table-level description. Phase 1: always
    /// `None`. Phase 2 LLM pipeline may fill this in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Outbound publisher trait — §11 Interface #2.
///
/// Implementations:
/// - [`NoopDataProductPublisher`] — default no-op for the
///   `governance_publishers: []` config path.
/// - `dataglot-server::governance::DataHubPublisher` — HTTP
///   adapter targeting `DataHub`'s GMS `ingestProposal`
///   endpoint (lands with the slice-2 PR).
///
/// # Failure isolation
///
/// Returns `()` not `Result`. Implementations log + drop on
/// backend error. The lineage emitter's contract applies here
/// too — governance-backend outage must NOT propagate to query
/// or boot paths.
#[async_trait::async_trait]
pub trait DataProductPublisher: Send + Sync + std::fmt::Debug + 'static {
    /// Register or update one data product on the governance
    /// backend. Phase 1 calls this from:
    ///
    /// 1. `DataglotServer::new` post-boot, once per registered
    ///    catalog.
    /// 2. The catalog cache's `BindingChange` subscriber, once
    ///    per `Upserted` event.
    ///
    /// `BindingChangeKind::Deleted` events log a WARN and do
    /// NOT call this method in Phase 1 — leaving stale
    /// "ghost" entries in `DataHub` is preferable to losing the
    /// record while the retention policy is undecided.
    async fn publish(&self, product: &DataProduct);
}

/// Default publisher — silently drops every product.
///
/// Used by the boot path when `governance_publishers` is
/// empty / missing. Cost is two trait-object indirections per
/// call — effectively free.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoopDataProductPublisher;

#[async_trait::async_trait]
impl DataProductPublisher for NoopDataProductPublisher {
    async fn publish(&self, _product: &DataProduct) {}
}

/// Trait object alias for cross-crate consumers. Matches the
/// shape `dataglot_core::lineage::DynLineageEmitter` uses.
pub type DynDataProductPublisher = std::sync::Arc<dyn DataProductPublisher>;

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_table() -> TableName {
        TableName {
            catalog: "pg".to_string(),
            schema: "public".to_string(),
            table: "users".to_string(),
        }
    }

    #[test]
    fn urn_format_stable() {
        let t = fixture_table();
        assert_eq!(t.to_urn(), "urn:dataglot:pg:public:users");
    }

    #[test]
    fn column_definition_source_serde_lowercase() {
        // Wire shape pinned across phases — the JSON tag is
        // snake_case for all three variants. Spec'd in task 11.
        let cases = vec![
            (
                ColumnDefinitionSource::Placeholder,
                serde_json::json!({"kind": "placeholder"}),
            ),
            (
                ColumnDefinitionSource::Llm {
                    generated_at: SystemTime::UNIX_EPOCH,
                    model: "claude-opus-4-7".to_string(),
                },
                serde_json::json!({
                    "kind": "llm",
                    "generated_at": { "secs_since_epoch": 0, "nanos_since_epoch": 0 },
                    "model": "claude-opus-4-7",
                }),
            ),
            (
                ColumnDefinitionSource::Steward {
                    certified_by: "jane.doe@acme.com".to_string(),
                    certified_at: SystemTime::UNIX_EPOCH,
                },
                serde_json::json!({
                    "kind": "steward",
                    "certified_by": "jane.doe@acme.com",
                    "certified_at": { "secs_since_epoch": 0, "nanos_since_epoch": 0 },
                }),
            ),
        ];
        for (src, expected_json) in cases {
            let actual = serde_json::to_value(&src).unwrap();
            assert_eq!(actual, expected_json, "wire mismatch for {src:?}");
            let parsed: ColumnDefinitionSource = serde_json::from_value(actual).unwrap();
            assert_eq!(parsed, src);
        }
    }

    #[test]
    fn phase_1_binary_can_deserialize_phase_2_and_phase_3_payloads() {
        // Load-bearing forward-compat property from task 11.
        // A Phase 1 binary that crashes on Llm or Steward
        // values it didn't produce itself would break the
        // wire across phases — make sure that doesn't happen.
        let llm_json = serde_json::json!({
            "kind": "llm",
            "generated_at": { "secs_since_epoch": 1_700_000_000, "nanos_since_epoch": 0 },
            "model": "claude-opus-5-0",
        });
        let _: ColumnDefinitionSource =
            serde_json::from_value(llm_json).expect("Phase 1 must accept Llm payloads");

        let steward_json = serde_json::json!({
            "kind": "steward",
            "certified_by": "bob",
            "certified_at": { "secs_since_epoch": 1_700_000_000, "nanos_since_epoch": 0 },
        });
        let _: ColumnDefinitionSource =
            serde_json::from_value(steward_json).expect("Phase 1 must accept Steward payloads");
    }

    #[test]
    fn product_platform_serde_lowercase() {
        // `kind: "iceberg"` on the wire is intentional — that's
        // what `DataHub` / `OpenMetadata` expect for the platform
        // name even though hard rule 7 keeps Iceberg out
        // of user-facing surfaces. Pin this so a future
        // rename to "warehouse" or similar doesn't silently
        // break the governance integration.
        for (variant, expected) in [
            (ProductPlatform::Postgres, "\"postgres\""),
            (ProductPlatform::Mysql, "\"mysql\""),
            (ProductPlatform::Snowflake, "\"snowflake\""),
            (ProductPlatform::Oracle, "\"oracle\""),
            (ProductPlatform::ObjectStorage, "\"object_storage\""),
            (ProductPlatform::Iceberg, "\"iceberg\""),
        ] {
            let json = serde_json::to_string(&variant).unwrap();
            assert_eq!(json, expected, "platform tag mismatch for {variant:?}");
        }
    }

    #[test]
    fn placeholder_column_uses_canonical_string() {
        // Phase 2 LLM swap depends on this string being a
        // single canonical value — pin it.
        let col = placeholder_column("email".to_string(), "Utf8".to_string(), false);
        assert_eq!(col.definition_source, ColumnDefinitionSource::Placeholder);
        assert_eq!(col.definition, "Pending Dataglot-side definition");
        assert_eq!(col.name, "email");
        assert_eq!(col.arrow_type, "Utf8");
        assert!(!col.nullable);
    }

    #[test]
    fn data_product_serde_round_trip() {
        // Pin the full payload shape across the wire.
        let p = DataProduct {
            urn: "urn:dataglot:pg:public:users".to_string(),
            name: fixture_table(),
            platform: ProductPlatform::Postgres,
            columns: vec![
                placeholder_column("id".to_string(), "Int32".to_string(), false),
                placeholder_column("email".to_string(), "Utf8".to_string(), false),
            ],
            description: None,
        };
        let json = serde_json::to_value(&p).unwrap();
        // `description: None` must NOT appear in the JSON
        // (skip_serializing_if). Backend payloads stay clean.
        assert!(
            json.get("description").is_none(),
            "None description must not serialise: {json:?}"
        );
        let parsed: DataProduct = serde_json::from_value(json).unwrap();
        assert_eq!(parsed, p);
    }

    #[tokio::test]
    async fn noop_publisher_silently_drops() {
        // Two calls, no panic, no return value to check. The
        // default impl is what `governance_publishers: []`
        // boots with — must always be safe to call.
        let p = NoopDataProductPublisher;
        let product = DataProduct {
            urn: "urn:dataglot:pg:public:users".to_string(),
            name: fixture_table(),
            platform: ProductPlatform::Postgres,
            columns: vec![],
            description: None,
        };
        p.publish(&product).await;
        p.publish(&product).await;
    }

    #[test]
    fn dyn_publisher_is_send_sync_via_arc() {
        // Cross-crate consumers store `Arc<dyn
        // DataProductPublisher>`. Pin the trait-object shape
        // — a future trait change that broke Send + Sync +
        // 'static would surface here.
        let _p: DynDataProductPublisher = std::sync::Arc::new(NoopDataProductPublisher);
    }
}

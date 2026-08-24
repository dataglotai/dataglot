//! `DataHub` Actions Framework → `RuleChange` adapter.
//!
//! Phase 2 spec 04 slice 3. Translates the platform-shape JSON
//! payload that a `DataHub` Action posts to `POST /v1/events` into
//! the native [`RuleChange`] enum the slice-2 rule store accepts.
//! The webhook handler in [`crate::webhook`] calls
//! [`lower_payload`] once per request after HMAC verification.
//!
//! # Why a separate adapter (and not webhook-handler-inline)
//!
//! `DataHub` is the MVP platform; spec 04 §"Out of scope" defers
//! Informatica IDMC / Collibra / other adapters until a customer
//! pulls. Keeping the lowering logic behind a stable function
//! signature means a second adapter is a sibling file, not a
//! webhook-handler edit. The envelope-level dispatch on
//! `event_type` lives in the handler; the per-platform JSON
//! interpretation lives here.
//!
//! # Payload shape — `DataHub` Actions Framework subset
//!
//! `DataHub` Actions Framework emits structured `EntityChangeEvent`s
//! over a webhook; their inner JSON varies by entity type. Slice 3
//! accepts the subset of fields Dataglot needs to materialize each
//! of the six [`RuleChange`] variants. The shape is intentionally
//! shallow:
//!
//! ## `tag.assigned` / `tag.removed`
//! ```json
//! {
//!   "entity_urn": "urn:li:schemaField:(urn:li:dataset:(urn:li:dataPlatform:postgres,public.users,PROD),email)",
//!   "tag_urn": "urn:li:tag:pii"
//! }
//! ```
//!
//! ## `policy.upserted`
//! ```json
//! {
//!   "id": "mask-pii-analyst",
//!   "org": "acme",
//!   "tag_urn": "urn:li:tag:pii",
//!   "group": "analyst",
//!   "rule": {"kind": "mask", "mask_literal": "***@example.com"}
//! }
//! ```
//! or for row-filter:
//! ```json
//! {
//!   "id": "filter-pii-analyst",
//!   "org": "acme",
//!   "tag_urn": "urn:li:tag:pii",
//!   "group": "analyst",
//!   "rule": {"kind": "row_filter", "sql": "email = 'bob@example.com'"}
//! }
//! ```
//!
//! ## `policy.deleted`
//! ```json
//! { "id": "mask-pii-analyst" }
//! ```
//!
//! ## `certification.upserted` / `certification.deleted`
//! ```json
//! {
//!   "entity_urn": "urn:li:schemaField:(urn:li:dataset:(...,users),email)",
//!   "certification": "steward.alice"
//! }
//! ```
//!
//! # URN parsing
//!
//! `DataHub` identifies entities by URN. The two URN shapes Dataglot
//! consumes:
//!
//! - **schemaField:** `urn:li:schemaField:(urn:li:dataset:(urn:li:dataPlatform:<platform>,<table_path>,<env>),<column>)`
//!   yields `(TableReference, column_name)`. `<table_path>` may be
//!   `schema.table` (Postgres) or `db.schema.table` (Snowflake);
//!   parsed via the same `parse_table_ref` helper the static
//!   `[[masks]]` / `[[row_filters]]` config block uses.
//! - **tag:** `urn:li:tag:<tag_id>` yields a [`TagId`].
//!
//! Anything that doesn't match the URN structure returns
//! [`AdapterError::InvalidUrn`] with the offending URN inline —
//! handler responds with 400 + structured `ADAPTER_VALIDATION_FAILED`.
//!
//! # Slice 3 scope
//!
//! - Per-variant `Deserialize` payload struct.
//! - URN parser pair (schema-field + tag).
//! - SQL predicate parsing for `policy.upserted` row-filter rules.
//! - `lower_payload` entry point covering all six event types.
//! - Unit tests for each variant + the URN-format negative cases.
//!
//! Out of scope: real `DataHub` GMS lookup (we trust the payload),
//! batched events (one event per `POST`), schema-evolution shims for
//! `DataHub` GMS version drift.

use anyhow::Context;
use datafusion::logical_expr::lit;
use datafusion::sql::TableReference;
use serde::Deserialize;
use thiserror::Error;

use dataglot_policy::{OrgGroupId, Policy, RuleChange, RuleType, TagId};

use crate::config::parse_sql_predicate;
use crate::webhook::EventType;

/// Errors the adapter surfaces when a payload can't be lowered.
///
/// Mapped to HTTP 400 by the webhook handler with the
/// `ADAPTER_VALIDATION_FAILED` error code; the `Display` impl
/// shows up in the response `message` field.
#[derive(Debug, Error)]
pub enum AdapterError {
    /// JSON deserialization of the inner `payload` failed for the
    /// given `event_type`. Carries the underlying `serde_json` error
    /// so the operator can fix the platform-side payload shape.
    #[error("payload deserialization failed: {0}")]
    Payload(#[source] serde_json::Error),
    /// A URN didn't match the expected `DataHub` shape. Slice 3
    /// supports two URN families (`schemaField`, `tag`); any other
    /// URN scheme or a malformed instance trips this.
    #[error("invalid {kind} URN `{urn}`: {reason}")]
    InvalidUrn {
        /// Which URN family the parser tried to match — `"schemaField"`
        /// or `"tag"`. Surfaced so the operator's logs make the
        /// failure unambiguous.
        kind: &'static str,
        /// The full URN the producer sent.
        urn: String,
        /// Free-form explanation of the structural mismatch.
        reason: String,
    },
    /// The SQL predicate inside a `policy.upserted` row-filter
    /// payload didn't parse. Surfaces the upstream
    /// `predicate_to_expr_sql` error verbatim.
    #[error("policy `{policy_id}` row-filter SQL parse failed: {source:#}")]
    PolicyPredicate {
        /// The policy id from the payload so the operator can find
        /// the offending rule in their `DataHub` Actions config.
        policy_id: String,
        /// The upstream parse error.
        #[source]
        source: anyhow::Error,
    },
    /// `parse_table_ref` rejected the table path extracted from the
    /// schema-field URN. Distinct from `InvalidUrn` because the URN
    /// itself was structurally fine — the embedded table reference
    /// wasn't.
    #[error("table reference `{table}` (from URN `{urn}`) failed to parse: {source:#}")]
    InvalidTable {
        /// The table path string extracted from the URN.
        table: String,
        /// The full URN it came from, so the error message is
        /// debuggable end-to-end.
        urn: String,
        /// The upstream parse error.
        #[source]
        source: anyhow::Error,
    },
}

/// Lower a single inbound governance event into a [`RuleChange`].
///
/// Dispatches on `event_type` and deserializes the inner JSON into
/// the per-variant payload struct, then translates each field
/// (URN parsing, SQL parsing, etc.) into the
/// `dataglot-policy`-native shape.
///
/// # Errors
/// See [`AdapterError`].
pub fn lower_payload(
    event_type: EventType,
    payload: &serde_json::Value,
) -> Result<RuleChange, AdapterError> {
    match event_type {
        EventType::TagAssigned => {
            let p: TagPayload =
                serde_json::from_value(payload.clone()).map_err(AdapterError::Payload)?;
            let (table, column) = parse_schema_field_urn(&p.entity_urn)?;
            let tag = parse_tag_urn(&p.tag_urn)?;
            Ok(RuleChange::TagAssigned { table, column, tag })
        }
        EventType::TagRemoved => {
            let p: TagPayload =
                serde_json::from_value(payload.clone()).map_err(AdapterError::Payload)?;
            let (table, column) = parse_schema_field_urn(&p.entity_urn)?;
            let tag = parse_tag_urn(&p.tag_urn)?;
            Ok(RuleChange::TagRemoved { table, column, tag })
        }
        EventType::PolicyUpserted => {
            let p: PolicyPayload =
                serde_json::from_value(payload.clone()).map_err(AdapterError::Payload)?;
            let tag = parse_tag_urn(&p.tag_urn)?;
            let rule = lower_policy_rule(&p.id, p.rule)?;
            Ok(RuleChange::PolicyUpserted(Policy {
                id: p.id,
                org: p.org,
                tag,
                group: OrgGroupId::new(&p.group),
                rule,
            }))
        }
        EventType::PolicyDeleted => {
            let p: PolicyDeletePayload =
                serde_json::from_value(payload.clone()).map_err(AdapterError::Payload)?;
            Ok(RuleChange::PolicyDeleted { policy_id: p.id })
        }
        EventType::CertificationUpserted => {
            let p: CertificationPayload =
                serde_json::from_value(payload.clone()).map_err(AdapterError::Payload)?;
            let (table, column) = parse_schema_field_urn(&p.entity_urn)?;
            Ok(RuleChange::CertificationUpserted {
                table,
                column,
                certification: p.certification,
            })
        }
        EventType::CertificationDeleted => {
            let p: CertificationPayload =
                serde_json::from_value(payload.clone()).map_err(AdapterError::Payload)?;
            let (table, column) = parse_schema_field_urn(&p.entity_urn)?;
            Ok(RuleChange::CertificationDeleted {
                table,
                column,
                certification: p.certification,
            })
        }
    }
}

// ---------------------------------------------------------------------------
// Payload structs
// ---------------------------------------------------------------------------

/// `tag.assigned` / `tag.removed` payload. Same shape for both.
#[derive(Debug, Deserialize)]
struct TagPayload {
    /// `urn:li:schemaField:(urn:li:dataset:(...,<table>),<column>)`.
    entity_urn: String,
    /// `urn:li:tag:<tag_id>`.
    tag_urn: String,
}

/// `policy.upserted` payload — full policy definition flowing in.
#[derive(Debug, Deserialize)]
struct PolicyPayload {
    /// Stable policy id used for upsert/delete keying.
    id: String,
    /// Owning organization (mirrors [`Policy::org`]).
    org: String,
    /// `urn:li:tag:<tag_id>`.
    tag_urn: String,
    /// Plain group name (no URN scheme — matches the way the static
    /// `[governance.policies.group]` field in `dataglot.toml` is
    /// written).
    group: String,
    /// Mask / row-filter shape.
    rule: PolicyRulePayload,
}

/// `policy.deleted` payload — just the id.
#[derive(Debug, Deserialize)]
struct PolicyDeletePayload {
    /// Policy id to delete.
    id: String,
}

/// `certification.upserted` / `certification.deleted` payload.
#[derive(Debug, Deserialize)]
struct CertificationPayload {
    /// `urn:li:schemaField:(...)`.
    entity_urn: String,
    /// Free-form certification identifier (steward name, level,
    /// etc.). Opaque to the enforcement path; slice 3 stores it in
    /// the rule store's sidecar map.
    certification: String,
}

/// Policy rule sub-shape. Tagged enum on `kind` so the wire format
/// reads naturally: `{"kind": "mask", "mask_literal": "***"}`.
#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum PolicyRulePayload {
    /// Column-mask rule. Carries the literal that replaces the
    /// column value in projections.
    Mask {
        /// String literal used as the mask `Expr`. Same shape as
        /// the static `[[masks.mask_literal]]` config field.
        mask_literal: String,
    },
    /// Row-filter rule. Predicate is a raw SQL expression (no JSON
    /// shape) so operators can use any boolean DataFusion-supported
    /// expression — same affordance as the static
    /// `[[row_filters.predicate.kind = "sql"]]` config variant.
    RowFilter {
        /// SQL expression returning a `BOOLEAN`. Examples:
        /// `email = 'bob@example.com'`, `tenant_id = 42`.
        sql: String,
    },
}

fn lower_policy_rule(policy_id: &str, rule: PolicyRulePayload) -> Result<RuleType, AdapterError> {
    match rule {
        PolicyRulePayload::Mask { mask_literal } => Ok(RuleType::Mask {
            expression: lit(mask_literal),
        }),
        PolicyRulePayload::RowFilter { sql } => {
            let predicate = parse_sql_predicate(&sql)
                .with_context(|| format!("predicate SQL `{sql}`"))
                .map_err(|e| AdapterError::PolicyPredicate {
                    policy_id: policy_id.to_string(),
                    source: e,
                })?;
            Ok(RuleType::RowFilter { predicate })
        }
    }
}

// ---------------------------------------------------------------------------
// URN parsing
// ---------------------------------------------------------------------------

const SCHEMA_FIELD_PREFIX: &str = "urn:li:schemaField:";
const TAG_PREFIX: &str = "urn:li:tag:";

/// Parse a `urn:li:schemaField:(urn:li:dataset:(...,<table_path>,<env>),<column>)`
/// URN into `(TableReference, column_name)`. Robust to common shape
/// variations (with/without the `urn:li:dataPlatform:...,` prefix
/// inside the dataset URN); strict on the outermost shape.
fn parse_schema_field_urn(urn: &str) -> Result<(TableReference, String), AdapterError> {
    let body = urn
        .strip_prefix(SCHEMA_FIELD_PREFIX)
        .ok_or_else(|| AdapterError::InvalidUrn {
            kind: "schemaField",
            urn: urn.to_string(),
            reason: format!("expected prefix `{SCHEMA_FIELD_PREFIX}`"),
        })?;
    let inner = body
        .strip_prefix('(')
        .and_then(|s| s.strip_suffix(')'))
        .ok_or_else(|| AdapterError::InvalidUrn {
            kind: "schemaField",
            urn: urn.to_string(),
            reason: "expected `(...,<column>)` outer parens".to_string(),
        })?;

    // Split at the LAST top-level comma so the dataset URN's own
    // commas (e.g. `urn:li:dataPlatform:postgres,public.users,PROD`)
    // don't confuse the parse.
    let (dataset_urn, column) =
        split_last_top_level_comma(inner).ok_or_else(|| AdapterError::InvalidUrn {
            kind: "schemaField",
            urn: urn.to_string(),
            reason: "missing column separator (`,<column>`) at the top level".to_string(),
        })?;
    if column.is_empty() {
        return Err(AdapterError::InvalidUrn {
            kind: "schemaField",
            urn: urn.to_string(),
            reason: "column name is empty".to_string(),
        });
    }

    let table_path =
        extract_dataset_table_path(dataset_urn).ok_or_else(|| AdapterError::InvalidUrn {
            kind: "schemaField",
            urn: urn.to_string(),
            reason: format!("inner dataset URN `{dataset_urn}` did not parse"),
        })?;

    let table =
        crate::config::parse_table_ref(table_path).map_err(|e| AdapterError::InvalidTable {
            table: table_path.to_string(),
            urn: urn.to_string(),
            source: e,
        })?;
    Ok((table, column.to_string()))
}

/// Parse `urn:li:tag:<tag_id>` into a [`TagId`].
fn parse_tag_urn(urn: &str) -> Result<TagId, AdapterError> {
    let id = urn
        .strip_prefix(TAG_PREFIX)
        .ok_or_else(|| AdapterError::InvalidUrn {
            kind: "tag",
            urn: urn.to_string(),
            reason: format!("expected prefix `{TAG_PREFIX}`"),
        })?;
    if id.is_empty() {
        return Err(AdapterError::InvalidUrn {
            kind: "tag",
            urn: urn.to_string(),
            reason: "tag id is empty".to_string(),
        });
    }
    Ok(TagId::new(id))
}

/// Extract the `<table_path>` segment out of a
/// `urn:li:dataset:(urn:li:dataPlatform:<platform>,<table_path>,<env>)`
/// URN. Only the canonical 3-part shape (with the explicit
/// `dataPlatform` prefix on the first segment) and the bare 1-part
/// shape are supported; the 2-part shape is ambiguous in `DataHub`'s
/// docs (`(platform, table)` vs `(table, env)`) and rejected here so
/// operators can't accidentally apply rules to the wrong target.
fn extract_dataset_table_path(dataset_urn: &str) -> Option<&str> {
    let body = dataset_urn.strip_prefix("urn:li:dataset:")?;
    let inner = body.strip_prefix('(').and_then(|s| s.strip_suffix(')'))?;
    let parts: Vec<&str> = inner.split(',').collect();
    match parts.as_slice() {
        // Single-part: `<table>`. Used by some non-DataHub producers
        // (Informatica adapter prototypes, etc.) that emit a bare
        // table reference. Safe because there's no ambiguity.
        [table] => Some(table.trim()),
        // Canonical DataHub 3-part:
        // `urn:li:dataPlatform:<platform>,<table>,<env>`. The first
        // segment MUST carry the `urn:li:dataPlatform:` prefix —
        // anything else is rejected so the 2-part-shape ambiguity
        // (see doc above) doesn't sneak in through a producer
        // sending `(table, env, extra)` shaped variants.
        [platform, table, _env] if platform.trim().starts_with("urn:li:dataPlatform:") => {
            Some(table.trim())
        }
        _ => None,
    }
}

/// Find the comma index that splits the *outermost* `(...,...)`
/// wrapping. Walks left-to-right tracking parenthesis depth so
/// nested commas inside the dataset URN don't trigger a split.
///
/// Returns `None` on **unbalanced** parens — depth going negative
/// mid-scan (an unmatched `)`) or ending non-zero (an unmatched `(`).
/// A malformed URN must fail closed at the caller (`InvalidUrn`), never
/// silently split at the wrong comma and bind a tag to a garbage
/// column (: `(...,users,PROD),c),realcol` used to parse as
/// column `"c),realcol"`, so the intended column got no tag).
fn split_last_top_level_comma(s: &str) -> Option<(&str, &str)> {
    let bytes = s.as_bytes();
    let mut depth = 0i32;
    let mut last_top_level_comma: Option<usize> = None;
    for (i, &b) in bytes.iter().enumerate() {
        match b {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                // An unmatched `)` means the URN's parens are
                // malformed — reject rather than trust any split.
                if depth < 0 {
                    return None;
                }
            }
            b',' if depth == 0 => last_top_level_comma = Some(i),
            _ => {}
        }
    }
    // Unmatched `(` (depth still open) is equally malformed.
    if depth != 0 {
        return None;
    }
    let idx = last_top_level_comma?;
    Some((&s[..idx], &s[idx + 1..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SCHEMA_FIELD: &str =
        "urn:li:schemaField:(urn:li:dataset:(urn:li:dataPlatform:postgres,public.users,PROD),email)";
    const TAG_URN: &str = "urn:li:tag:pii";

    fn schema_field_payload() -> serde_json::Value {
        serde_json::json!({
            "entity_urn": SCHEMA_FIELD,
            "tag_urn": TAG_URN,
        })
    }

    // --- URN parser unit tests --------------------------------------------

    #[test]
    fn parse_schema_field_urn_extracts_table_and_column() {
        let (table, column) = parse_schema_field_urn(SCHEMA_FIELD).expect("parse");
        assert_eq!(column, "email");
        // `public.users` parses to a (schema, table) reference.
        assert_eq!(format!("{table}"), "public.users");
    }

    #[test]
    fn parse_schema_field_urn_rejects_missing_prefix() {
        let err = parse_schema_field_urn("not-a-urn").expect_err("err");
        assert!(matches!(
            err,
            AdapterError::InvalidUrn {
                kind: "schemaField",
                ..
            }
        ));
    }

    /// Two-part dataset URN shape is ambiguous (`(platform, table)`
    /// vs `(table, env)`) and is rejected to prevent rules being
    /// applied to the wrong target. The 1-part shape (bare table)
    /// and 3-part shape (with explicit `dataPlatform` prefix on
    /// the first segment) are the only accepted variants.
    #[test]
    fn parse_schema_field_urn_rejects_ambiguous_two_part_dataset() {
        let urn = "urn:li:schemaField:(urn:li:dataset:(public.users,PROD),email)";
        let err = parse_schema_field_urn(urn).expect_err("err");
        assert!(matches!(err, AdapterError::InvalidUrn { .. }));
    }

    /// 3-part shape without the canonical `urn:li:dataPlatform:`
    /// prefix on the first segment is also rejected — the first
    /// segment must be a real `dataPlatform` URN, not a bare
    /// platform name.
    #[test]
    fn parse_schema_field_urn_rejects_missing_data_platform_prefix() {
        let urn = "urn:li:schemaField:(urn:li:dataset:(postgres,public.users,PROD),email)";
        let err = parse_schema_field_urn(urn).expect_err("err");
        assert!(matches!(err, AdapterError::InvalidUrn { .. }));
    }

    #[test]
    fn parse_schema_field_urn_rejects_missing_outer_parens() {
        let err = parse_schema_field_urn("urn:li:schemaField:no_parens_here").expect_err("err");
        assert!(matches!(err, AdapterError::InvalidUrn { .. }));
    }

    /// ** regression pin.** A schemaField URN with UNBALANCED
    /// parens must be rejected, never silently mis-split into a garbage
    /// column. Pre-fix, this parsed to `Ok((pg.public.users,
    /// "c),realcol"))` — binding the inbound tag to a nonexistent
    /// column so the real column silently kept no tag (governance
    /// under-protection).
    #[test]
    fn parse_schema_field_urn_rejects_unbalanced_parens() {
        let urn = "urn:li:schemaField:(urn:li:dataset:(urn:li:dataPlatform:postgres,\
                   pg.public.users,PROD),c),realcol)";
        let err = parse_schema_field_urn(urn).expect_err("unbalanced parens must reject");
        assert!(
            matches!(err, AdapterError::InvalidUrn { .. }),
            "expected InvalidUrn, got {err:?}"
        );
    }

    /// `split_last_top_level_comma` directly: balanced input splits at
    /// the last top-level comma; any unbalanced-paren input is `None`.
    #[test]
    fn split_last_top_level_comma_rejects_unbalanced() {
        assert_eq!(
            split_last_top_level_comma("a(b,c),d"),
            Some(("a(b,c)", "d"))
        );
        assert_eq!(split_last_top_level_comma("(a,b),c),d"), None); // extra ')'
        assert_eq!(split_last_top_level_comma("((a,b),c"), None); // unmatched '('
        assert_eq!(split_last_top_level_comma("no_comma"), None);
    }

    /// ** related (fail-closed pin).** A table name containing a
    /// comma or paren makes `build_datahub_urn` emit an ambiguous
    /// dataset URN; the inbound parser must reject it with a clean
    /// `InvalidUrn` — a robustness limitation, but fail-closed (no
    /// silent mis-bind). Documents the behavior until identifiers are
    /// escaped at build time (follow-up).
    #[test]
    fn schema_field_urn_with_comma_in_table_fails_closed() {
        // Mirror what build_datahub_urn produces for a comma-named table.
        let urn = "urn:li:schemaField:(urn:li:dataset:(urn:li:dataPlatform:postgres,\
                   pg.public.orders,2024,PROD),email)";
        let err = parse_schema_field_urn(urn).expect_err("comma-in-table must fail closed");
        assert!(matches!(err, AdapterError::InvalidUrn { .. }));
    }

    #[test]
    fn parse_schema_field_urn_rejects_empty_column() {
        let urn =
            "urn:li:schemaField:(urn:li:dataset:(urn:li:dataPlatform:postgres,public.users,PROD),)";
        let err = parse_schema_field_urn(urn).expect_err("err");
        assert!(matches!(
            err,
            AdapterError::InvalidUrn { reason, .. } if reason.contains("column name is empty")
        ));
    }

    #[test]
    fn parse_tag_urn_extracts_id() {
        let tag = parse_tag_urn("urn:li:tag:pii").expect("parse");
        assert_eq!(tag.as_str(), "pii");
    }

    #[test]
    fn parse_tag_urn_rejects_missing_prefix() {
        let err = parse_tag_urn("not-a-tag-urn").expect_err("err");
        assert!(matches!(err, AdapterError::InvalidUrn { kind: "tag", .. }));
    }

    #[test]
    fn parse_tag_urn_rejects_empty_id() {
        let err = parse_tag_urn("urn:li:tag:").expect_err("err");
        assert!(matches!(
            err,
            AdapterError::InvalidUrn { reason, .. } if reason.contains("empty")
        ));
    }

    // --- lower_payload round-trip tests (6 event types) -------------------

    #[test]
    fn lower_tag_assigned() {
        let change = lower_payload(EventType::TagAssigned, &schema_field_payload()).expect("lower");
        match change {
            RuleChange::TagAssigned { table, column, tag } => {
                assert_eq!(format!("{table}"), "public.users");
                assert_eq!(column, "email");
                assert_eq!(tag.as_str(), "pii");
            }
            other => panic!("expected TagAssigned, got {other:?}"),
        }
    }

    #[test]
    fn lower_tag_removed() {
        let change = lower_payload(EventType::TagRemoved, &schema_field_payload()).expect("lower");
        assert!(matches!(change, RuleChange::TagRemoved { .. }));
    }

    #[test]
    fn lower_policy_upserted_mask() {
        let payload = serde_json::json!({
            "id": "mask-pii-analyst",
            "org": "acme",
            "tag_urn": "urn:li:tag:pii",
            "group": "analyst",
            "rule": {"kind": "mask", "mask_literal": "***@example.com"},
        });
        let change = lower_payload(EventType::PolicyUpserted, &payload).expect("lower");
        match change {
            RuleChange::PolicyUpserted(p) => {
                assert_eq!(p.id, "mask-pii-analyst");
                assert_eq!(p.org, "acme");
                assert_eq!(p.tag.as_str(), "pii");
                assert_eq!(p.group.as_str(), "analyst");
                assert!(matches!(p.rule, RuleType::Mask { .. }));
            }
            other => panic!("expected PolicyUpserted, got {other:?}"),
        }
    }

    #[test]
    fn lower_policy_upserted_row_filter() {
        let payload = serde_json::json!({
            "id": "filter-pii-analyst",
            "org": "acme",
            "tag_urn": "urn:li:tag:pii",
            "group": "analyst",
            "rule": {"kind": "row_filter", "sql": "email = 'bob@example.com'"},
        });
        let change = lower_payload(EventType::PolicyUpserted, &payload).expect("lower");
        match change {
            RuleChange::PolicyUpserted(p) => {
                assert!(matches!(p.rule, RuleType::RowFilter { .. }));
            }
            other => panic!("expected PolicyUpserted, got {other:?}"),
        }
    }

    #[test]
    fn lower_policy_upserted_rejects_invalid_sql() {
        let payload = serde_json::json!({
            "id": "bad-sql",
            "org": "acme",
            "tag_urn": "urn:li:tag:pii",
            "group": "analyst",
            "rule": {"kind": "row_filter", "sql": "this is not sql ¯\\_(ツ)_/¯"},
        });
        let err = lower_payload(EventType::PolicyUpserted, &payload).expect_err("err");
        assert!(
            matches!(err, AdapterError::PolicyPredicate { ref policy_id, .. } if policy_id == "bad-sql"),
            "expected PolicyPredicate(`bad-sql`), got: {err:?}"
        );
    }

    #[test]
    fn lower_policy_deleted() {
        let payload = serde_json::json!({"id": "mask-pii-analyst"});
        let change = lower_payload(EventType::PolicyDeleted, &payload).expect("lower");
        match change {
            RuleChange::PolicyDeleted { policy_id } => {
                assert_eq!(policy_id, "mask-pii-analyst");
            }
            other => panic!("expected PolicyDeleted, got {other:?}"),
        }
    }

    #[test]
    fn lower_certification_upserted() {
        let payload = serde_json::json!({
            "entity_urn": SCHEMA_FIELD,
            "certification": "steward.alice",
        });
        let change = lower_payload(EventType::CertificationUpserted, &payload).expect("lower");
        match change {
            RuleChange::CertificationUpserted {
                table,
                column,
                certification,
            } => {
                assert_eq!(format!("{table}"), "public.users");
                assert_eq!(column, "email");
                assert_eq!(certification, "steward.alice");
            }
            other => panic!("expected CertificationUpserted, got {other:?}"),
        }
    }

    #[test]
    fn lower_certification_deleted() {
        let payload = serde_json::json!({
            "entity_urn": SCHEMA_FIELD,
            "certification": "steward.alice",
        });
        let change = lower_payload(EventType::CertificationDeleted, &payload).expect("lower");
        assert!(matches!(change, RuleChange::CertificationDeleted { .. }));
    }

    // --- Adapter-failure tests --------------------------------------------

    #[test]
    fn lower_tag_assigned_rejects_missing_field() {
        let payload = serde_json::json!({"entity_urn": SCHEMA_FIELD});
        let err = lower_payload(EventType::TagAssigned, &payload).expect_err("err");
        assert!(
            matches!(err, AdapterError::Payload(_)),
            "expected Payload(serde), got: {err:?}"
        );
    }

    #[test]
    fn lower_tag_assigned_rejects_invalid_entity_urn() {
        let payload = serde_json::json!({
            "entity_urn": "not-a-urn",
            "tag_urn": TAG_URN,
        });
        let err = lower_payload(EventType::TagAssigned, &payload).expect_err("err");
        assert!(matches!(
            err,
            AdapterError::InvalidUrn {
                kind: "schemaField",
                ..
            }
        ));
    }
}

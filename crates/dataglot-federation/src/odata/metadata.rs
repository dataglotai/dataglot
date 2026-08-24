//! Parse an OData v2 `$metadata` (EDMX) XML document into an Arrow
//! [`Schema`] for a named entity set.
//!
//! `$metadata` is the schema document an OData service exposes; for SAP
//! S/4HANA it's `GET <service_url>/$metadata`. It declares `EntityType`s
//! (each a list of typed `Property` elements) and an `EntityContainer` whose
//! `EntitySet`s bind a table-shaped name to an entity type. This module maps
//! the entity set's properties to Arrow fields.
//!
//! # EDM → Arrow type mapping (the 9 MVP types)
//!
//! | EDM type | Arrow `DataType` |
//! |---|---|
//! | `Edm.Int16` / `Int32` / `Int64` | `Int16` / `Int32` / `Int64` |
//! | `Edm.Single` / `Edm.Double` | `Float32` / `Float64` |
//! | `Edm.Decimal` (P, S) | `Decimal128(P, S)` |
//! | `Edm.Boolean` | `Boolean` |
//! | `Edm.String` | `Utf8` |
//! | `Edm.DateTime` | `Timestamp(µs, None)` |
//! | `Edm.DateTimeOffset` | `Timestamp(µs, "+00:00")` |
//!
//! Any other EDM type (`Edm.Binary`, `Edm.Guid`, `Edm.Time`, complex types,
//! …) is rejected — a follow-up per the spec.

use std::collections::HashMap;

use arrow::datatypes::{DataType, Field, Schema, SchemaRef, TimeUnit};
use quick_xml::events::{BytesStart, Event};
use quick_xml::reader::Reader;
use quick_xml::XmlVersion;

use dataglot_core::{DataglotError, Result as DataglotResult};

/// Arrow `Decimal128` caps precision at 38.
const MAX_DECIMAL128_PRECISION: u8 = 38;

/// Parse `edmx` (an OData v2 `$metadata` document) and return the Arrow
/// [`SchemaRef`] for `entity_set`.
///
/// # Errors
/// [`DataglotError::Catalog`] if the XML is malformed, `entity_set` is not
/// declared, its entity type is missing, or a property uses an EDM type not
/// in the supported set.
pub fn parse_edmx_schema(edmx: &str, entity_set: &str) -> DataglotResult<SchemaRef> {
    let parsed = parse_document(edmx)?;

    let entity_type = parsed.entity_sets.get(entity_set).ok_or_else(|| {
        let mut available: Vec<&str> = parsed.entity_sets.keys().map(String::as_str).collect();
        available.sort_unstable();
        DataglotError::catalog(format!(
            "OData entity set '{entity_set}' not found in $metadata; available: [{}]",
            available.join(", ")
        ))
    })?;

    let fields = parsed.entity_types.get(entity_type).ok_or_else(|| {
        DataglotError::catalog(format!(
            "OData entity set '{entity_set}' references entity type '{entity_type}', \
             which is not declared in $metadata"
        ))
    })?;

    Ok(SchemaRef::new(Schema::new(fields.clone())))
}

/// The parts of an EDMX document we care about: entity types (name →
/// fields), the entity-set → entity-type-name binding, and the entity
/// container name (OData's one namespace, used as the catalog schema name).
// EDMX is all "entity"-prefixed vocabulary; the shared prefix is the domain
// term, not noise.
#[allow(clippy::struct_field_names)]
struct ParsedEdmx {
    /// Entity type *local* name → its Arrow fields.
    entity_types: HashMap<String, Vec<Field>>,
    /// Entity set name → entity type *local* name.
    entity_sets: HashMap<String, String>,
    /// `<EntityContainer Name="…">` — the service's single namespace, if
    /// declared. `None` for a fragment with no container.
    entity_container: Option<String>,
}

/// Fallback schema name when an EDMX document declares no
/// `<EntityContainer Name>` (unusual — the attribute is required by the
/// spec, but a hand-trimmed fragment may omit it).
pub const DEFAULT_ENTITY_CONTAINER: &str = "default";

/// List the entity-set names and the entity-container name declared in an
/// OData v2 `$metadata` (EDMX) document. Entity sets become the tables of a
/// catalog whose single schema is the container name; the per-set Arrow
/// schema is still resolved lazily via [`parse_edmx_schema`] (rule 13).
/// Names are returned sorted for stable listing.
///
/// # Errors
/// [`DataglotError::Catalog`] if the EDMX is malformed.
pub fn parse_edmx_catalog(edmx: &str) -> DataglotResult<(String, Vec<String>)> {
    let parsed = parse_document(edmx)?;
    let container = parsed
        .entity_container
        .unwrap_or_else(|| DEFAULT_ENTITY_CONTAINER.to_string());
    let mut names: Vec<String> = parsed.entity_sets.into_keys().collect();
    names.sort_unstable();
    Ok((container, names))
}

/// One streaming pass over the document, collecting entity types and sets.
/// Entity types and the entity container can appear in either order, so both
/// maps are built fully and resolved by the caller.
fn parse_document(edmx: &str) -> DataglotResult<ParsedEdmx> {
    let mut reader = Reader::from_str(edmx);
    reader.config_mut().trim_text(true);

    let mut entity_types: HashMap<String, Vec<Field>> = HashMap::new();
    let mut entity_sets: HashMap<String, String> = HashMap::new();
    let mut entity_container: Option<String> = None;
    // The entity type whose `<Property>` children we're currently collecting.
    let mut current_type: Option<String> = None;

    loop {
        match reader
            .read_event()
            .map_err(|e| DataglotError::catalog(format!("malformed $metadata XML: {e}")))?
        {
            Event::Start(e) if is_elem(&e, b"EntityType") => {
                let name = required_attr(&e, b"Name", "EntityType")?;
                entity_types.entry(name.clone()).or_default();
                current_type = Some(name);
            }
            Event::End(e) if e.local_name().into_inner() == b"EntityType" => {
                current_type = None;
            }
            // A self-closed `<EntityType Name="X"/>` (no properties) is valid
            // XML — register it with an empty field list so an EntitySet
            // referencing it resolves rather than erroring.
            Event::Empty(e) if is_elem(&e, b"EntityType") => {
                let name = required_attr(&e, b"Name", "EntityType")?;
                entity_types.entry(name).or_default();
            }
            // Properties are usually empty elements, but handle Start too.
            Event::Empty(e) | Event::Start(e) if is_elem(&e, b"Property") => {
                if let Some(type_name) = &current_type {
                    let field = property_to_field(&e)?;
                    entity_types
                        .get_mut(type_name)
                        .expect("current_type inserted on EntityType start")
                        .push(field);
                }
            }
            Event::Empty(e) | Event::Start(e) if is_elem(&e, b"EntitySet") => {
                let name = required_attr(&e, b"Name", "EntitySet")?;
                let type_ref = required_attr(&e, b"EntityType", "EntitySet")?;
                entity_sets.insert(name, strip_namespace(&type_ref).to_string());
            }
            // The container's `Name` becomes the catalog's single schema name.
            // First one wins (a well-formed OData v2 service declares one).
            Event::Start(e) | Event::Empty(e)
                if is_elem(&e, b"EntityContainer") && entity_container.is_none() =>
            {
                entity_container = attr(&e, b"Name")?;
            }
            Event::Eof => break,
            _ => {}
        }
    }

    Ok(ParsedEdmx {
        entity_types,
        entity_sets,
        entity_container,
    })
}

/// Build an Arrow [`Field`] from a `<Property>` element.
fn property_to_field(e: &BytesStart<'_>) -> DataglotResult<Field> {
    let name = required_attr(e, b"Name", "Property")?;
    let edm_type = required_attr(e, b"Type", "Property")?;
    // OData `Nullable` defaults to true when absent; the value is
    // case-insensitive ("false"/"False"/"FALSE").
    let nullable = attr(e, b"Nullable")?.is_none_or(|v| !v.eq_ignore_ascii_case("false"));
    let precision = parse_u8_attr(e, b"Precision")?;
    let scale = parse_u8_attr(e, b"Scale")?;

    let data_type = edm_to_arrow(&edm_type, precision, scale).ok_or_else(|| {
        DataglotError::catalog(format!(
            "OData property '{name}' uses EDM type '{edm_type}', which is not yet supported"
        ))
    })?;
    Ok(Field::new(name, data_type, nullable))
}

/// Map an EDM primitive type name to an Arrow [`DataType`], or `None` if it's
/// outside the supported MVP set.
fn edm_to_arrow(edm_type: &str, precision: Option<u8>, scale: Option<u8>) -> Option<DataType> {
    Some(match edm_type {
        "Edm.Int16" => DataType::Int16,
        "Edm.Int32" => DataType::Int32,
        "Edm.Int64" => DataType::Int64,
        "Edm.Single" => DataType::Float32,
        "Edm.Double" => DataType::Float64,
        "Edm.Boolean" => DataType::Boolean,
        "Edm.String" => DataType::Utf8,
        "Edm.Decimal" => {
            // Arrow `Decimal128` requires precision in 1..=38, so clamp (an
            // explicit `Precision="0"` would otherwise yield an invalid type).
            let precision = precision
                .unwrap_or(MAX_DECIMAL128_PRECISION)
                .clamp(1, MAX_DECIMAL128_PRECISION);
            // Clamp scale to precision (Arrow requires scale ≤ precision).
            let scale = scale.unwrap_or(0).min(precision);
            DataType::Decimal128(precision, i8::try_from(scale).ok()?)
        }
        "Edm.DateTime" => DataType::Timestamp(TimeUnit::Microsecond, None),
        "Edm.DateTimeOffset" => DataType::Timestamp(TimeUnit::Microsecond, Some("+00:00".into())),
        _ => return None,
    })
}

/// Whether the element's local name (namespace prefix stripped) equals `name`.
fn is_elem(e: &BytesStart<'_>, name: &[u8]) -> bool {
    e.local_name().into_inner() == name
}

/// Strip an EDM namespace qualifier: `NS.TypeName` → `TypeName`.
fn strip_namespace(qualified: &str) -> &str {
    qualified.rsplit('.').next().unwrap_or(qualified)
}

/// Read an attribute's value by local name, or `None` if absent.
fn attr(e: &BytesStart<'_>, key: &[u8]) -> DataglotResult<Option<String>> {
    for a in e.attributes() {
        let a = a.map_err(|err| DataglotError::catalog(format!("malformed attribute: {err}")))?;
        if a.key.local_name().into_inner() == key {
            // quick-xml 0.40 deprecated `unescape_value()` in favour of
            // `normalized_value(version)`, which applies XML attribute-value
            // normalization. EDMX `$metadata` is XML 1.0; we don't track the
            // document's declared version, so assume 1.0 (`Implicit1_0`).
            let value = a.normalized_value(XmlVersion::Implicit1_0).map_err(|err| {
                DataglotError::catalog(format!("malformed attribute value: {err}"))
            })?;
            return Ok(Some(value.into_owned()));
        }
    }
    Ok(None)
}

/// Read a required attribute, erroring with context if absent.
fn required_attr(e: &BytesStart<'_>, key: &[u8], element: &str) -> DataglotResult<String> {
    attr(e, key)?.ok_or_else(|| {
        DataglotError::catalog(format!(
            "$metadata <{element}> is missing the required '{}' attribute",
            String::from_utf8_lossy(key)
        ))
    })
}

/// Parse a `u8` attribute (EDM `Precision`/`Scale`), or `None` if absent.
///
/// SAP frequently emits `Scale="Variable"` (or `"floating"`) on `Edm.Decimal`
/// properties; those are treated as absent (⇒ default scale) rather than a
/// parse error that would crash schema discovery.
fn parse_u8_attr(e: &BytesStart<'_>, key: &[u8]) -> DataglotResult<Option<u8>> {
    match attr(e, key)? {
        Some(v) => {
            if key == b"Scale"
                && (v.eq_ignore_ascii_case("variable") || v.eq_ignore_ascii_case("floating"))
            {
                return Ok(None);
            }
            v.parse::<u8>().map(Some).map_err(|_| {
                DataglotError::catalog(format!(
                    "$metadata attribute '{}' is not a valid number: '{v}'",
                    String::from_utf8_lossy(key)
                ))
            })
        }
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A compact EDMX v2 document exercising every supported EDM type, a
    /// non-nullable field, a decimal with precision/scale, and a second
    /// entity set (so set→type resolution is real).
    const SAMPLE_EDMX: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<edmx:Edmx Version="1.0" xmlns:edmx="http://schemas.microsoft.com/ado/2007/06/edmx">
  <edmx:DataServices xmlns:m="http://schemas.microsoft.com/ado/2007/08/dataservices/metadata" m:DataServiceVersion="2.0">
    <Schema Namespace="API_TEST" xmlns="http://schemas.microsoft.com/ado/2008/09/edm">
      <EntityType Name="BusinessPartnerType">
        <Key><PropertyRef Name="BusinessPartner"/></Key>
        <Property Name="BusinessPartner" Type="Edm.String" Nullable="false"/>
        <Property Name="Age" Type="Edm.Int32"/>
        <Property Name="Rank" Type="Edm.Int16"/>
        <Property Name="Balance" Type="Edm.Int64"/>
        <Property Name="Ratio" Type="Edm.Double"/>
        <Property Name="Score" Type="Edm.Single"/>
        <Property Name="Active" Type="Edm.Boolean"/>
        <Property Name="Amount" Type="Edm.Decimal" Precision="13" Scale="2"/>
        <Property Name="CreatedAt" Type="Edm.DateTime"/>
        <Property Name="ChangedAt" Type="Edm.DateTimeOffset"/>
      </EntityType>
      <EntityType Name="OtherType">
        <Property Name="Id" Type="Edm.String" Nullable="false"/>
      </EntityType>
      <EntityContainer Name="Container" m:IsDefaultEntityContainer="true">
        <EntitySet Name="A_BusinessPartner" EntityType="API_TEST.BusinessPartnerType"/>
        <EntitySet Name="A_Other" EntityType="API_TEST.OtherType"/>
      </EntityContainer>
    </Schema>
  </edmx:DataServices>
</edmx:Edmx>"#;

    fn schema() -> SchemaRef {
        parse_edmx_schema(SAMPLE_EDMX, "A_BusinessPartner").expect("parses")
    }

    #[test]
    fn catalog_lists_container_and_sorted_entity_sets() {
        let (container, sets) = parse_edmx_catalog(SAMPLE_EDMX).expect("parses");
        assert_eq!(container, "Container");
        // Both entity sets, returned sorted.
        assert_eq!(sets, vec!["A_BusinessPartner", "A_Other"]);
    }

    #[test]
    fn catalog_falls_back_when_container_unnamed() {
        // A fragment whose `<EntityContainer>` has no `Name` attribute.
        let edmx = r#"<Schema xmlns="http://schemas.microsoft.com/ado/2008/09/edm">
          <EntityType Name="T"><Property Name="Id" Type="Edm.String"/></EntityType>
          <EntityContainer><EntitySet Name="Things" EntityType="X.T"/></EntityContainer>
        </Schema>"#;
        let (container, sets) = parse_edmx_catalog(edmx).expect("parses");
        assert_eq!(container, DEFAULT_ENTITY_CONTAINER);
        assert_eq!(sets, vec!["Things"]);
    }

    #[test]
    fn maps_every_supported_edm_type() {
        let s = schema();
        let by_name = |n: &str| s.field_with_name(n).unwrap().data_type().clone();
        assert_eq!(by_name("BusinessPartner"), DataType::Utf8);
        assert_eq!(by_name("Age"), DataType::Int32);
        assert_eq!(by_name("Rank"), DataType::Int16);
        assert_eq!(by_name("Balance"), DataType::Int64);
        assert_eq!(by_name("Ratio"), DataType::Float64);
        assert_eq!(by_name("Score"), DataType::Float32);
        assert_eq!(by_name("Active"), DataType::Boolean);
        assert_eq!(by_name("Amount"), DataType::Decimal128(13, 2));
        assert_eq!(
            by_name("CreatedAt"),
            DataType::Timestamp(TimeUnit::Microsecond, None)
        );
        assert_eq!(
            by_name("ChangedAt"),
            DataType::Timestamp(TimeUnit::Microsecond, Some("+00:00".into()))
        );
    }

    #[test]
    fn field_order_and_count_match_the_entity_type() {
        let s = schema();
        assert_eq!(s.fields().len(), 10);
        assert_eq!(s.field(0).name(), "BusinessPartner");
        assert_eq!(s.field(1).name(), "Age");
    }

    #[test]
    fn nullability_defaults_true_and_honors_false() {
        let s = schema();
        // Nullable="false" ⇒ not nullable.
        assert!(!s.field_with_name("BusinessPartner").unwrap().is_nullable());
        // Absent Nullable ⇒ nullable (OData default).
        assert!(s.field_with_name("Age").unwrap().is_nullable());
    }

    #[test]
    fn resolves_the_second_entity_set_independently() {
        let s = parse_edmx_schema(SAMPLE_EDMX, "A_Other").expect("parses");
        assert_eq!(s.fields().len(), 1);
        assert_eq!(s.field(0).name(), "Id");
    }

    #[test]
    fn unknown_entity_set_lists_the_available_ones() {
        let err = parse_edmx_schema(SAMPLE_EDMX, "A_Missing").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("A_Missing"), "{msg}");
        // The available sets are listed to aid diagnosis.
        assert!(
            msg.contains("A_BusinessPartner") && msg.contains("A_Other"),
            "{msg}"
        );
    }

    #[test]
    fn unsupported_edm_type_is_rejected_with_context() {
        let edmx = r#"<Schema xmlns="http://schemas.microsoft.com/ado/2008/09/edm">
          <EntityType Name="T"><Property Name="Blob" Type="Edm.Binary"/></EntityType>
          <EntityContainer><EntitySet Name="S" EntityType="X.T"/></EntityContainer>
        </Schema>"#;
        let err = parse_edmx_schema(edmx, "S").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("Blob") && msg.contains("Edm.Binary"), "{msg}");
    }

    #[test]
    fn malformed_xml_errors() {
        assert!(parse_edmx_schema("<not-closed", "S").is_err());
    }

    #[test]
    fn decimal_without_precision_defaults_and_clamps() {
        // No Precision/Scale ⇒ default precision 38, scale 0.
        let edmx = r#"<Schema xmlns="http://schemas.microsoft.com/ado/2008/09/edm">
          <EntityType Name="T"><Property Name="D" Type="Edm.Decimal"/></EntityType>
          <EntityContainer><EntitySet Name="S" EntityType="X.T"/></EntityContainer>
        </Schema>"#;
        let s = parse_edmx_schema(edmx, "S").unwrap();
        assert_eq!(s.field(0).data_type().clone(), DataType::Decimal128(38, 0));
    }

    #[test]
    fn decimal_scale_variable_is_treated_as_default() {
        // SAP commonly emits Scale="Variable" — must not crash discovery.
        let edmx = r#"<Schema xmlns="http://schemas.microsoft.com/ado/2008/09/edm">
          <EntityType Name="T"><Property Name="D" Type="Edm.Decimal" Precision="23" Scale="Variable"/></EntityType>
          <EntityContainer><EntitySet Name="S" EntityType="X.T"/></EntityContainer>
        </Schema>"#;
        let s = parse_edmx_schema(edmx, "S").unwrap();
        assert_eq!(s.field(0).data_type().clone(), DataType::Decimal128(23, 0));
    }

    #[test]
    fn decimal_precision_zero_is_clamped_to_valid_range() {
        // Precision="0" is invalid for Arrow Decimal128; clamp to 1.
        let edmx = r#"<Schema xmlns="http://schemas.microsoft.com/ado/2008/09/edm">
          <EntityType Name="T"><Property Name="D" Type="Edm.Decimal" Precision="0"/></EntityType>
          <EntityContainer><EntitySet Name="S" EntityType="X.T"/></EntityContainer>
        </Schema>"#;
        let s = parse_edmx_schema(edmx, "S").unwrap();
        assert_eq!(s.field(0).data_type().clone(), DataType::Decimal128(1, 0));
    }

    #[test]
    fn nullable_is_case_insensitive() {
        let edmx = r#"<Schema xmlns="http://schemas.microsoft.com/ado/2008/09/edm">
          <EntityType Name="T"><Property Name="Id" Type="Edm.String" Nullable="False"/></EntityType>
          <EntityContainer><EntitySet Name="S" EntityType="X.T"/></EntityContainer>
        </Schema>"#;
        let s = parse_edmx_schema(edmx, "S").unwrap();
        assert!(!s.field_with_name("Id").unwrap().is_nullable());
    }

    #[test]
    fn self_closed_entity_type_resolves_to_empty_schema() {
        // A property-less `<EntityType Name="X"/>` is valid XML.
        let edmx = r#"<Schema xmlns="http://schemas.microsoft.com/ado/2008/09/edm">
          <EntityType Name="T"/>
          <EntityContainer><EntitySet Name="S" EntityType="X.T"/></EntityContainer>
        </Schema>"#;
        let s = parse_edmx_schema(edmx, "S").unwrap();
        assert_eq!(s.fields().len(), 0);
    }
}

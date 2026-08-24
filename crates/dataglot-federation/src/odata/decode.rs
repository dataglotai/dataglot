//! Decode an OData v2 JSON entity-set response into an Arrow [`RecordBatch`].
//!
//! OData v2 wraps a collection response as `{"d": {"results": [ {…}, … ]}}`
//! (a single entity is `{"d": {…}}`). Each result object maps property names
//! to JSON values. This module turns those rows into typed Arrow columns for
//! the schema discovered from `$metadata` (see [`super::metadata`]).
//!
//! OData v2's JSON encoding has quirks this handles: 64-bit integers and
//! decimals arrive as **strings** (JS can't hold them losslessly), and SAP
//! serialises `Edm.DateTime` as `"/Date(<ms>)/"`. A missing property or JSON
//! `null` becomes an Arrow null; a present-but-undecodable value is an error
//! (surfacing bad source data rather than silently nulling it).

use std::sync::Arc;

use arrow::array::{
    ArrayRef, BooleanArray, Decimal128Array, Float32Array, Float64Array, Int16Array, Int32Array,
    Int64Array, RecordBatch, StringArray, TimestampMicrosecondArray,
};
use arrow::datatypes::{DataType, Field, SchemaRef, TimeUnit};
use serde_json::Value;

use dataglot_core::{DataglotError, Result as DataglotResult};

/// Decode an OData v2 JSON entity-set `body` into a [`RecordBatch`] with the
/// given `schema` (the columns and order the schema defines).
///
/// # Errors
/// [`DataglotError::Catalog`] if the body isn't valid JSON, the results array
/// can't be located, a cell can't be decoded to its column type, or the
/// batch fails to assemble.
pub fn decode_entity_set(body: &str, schema: &SchemaRef) -> DataglotResult<RecordBatch> {
    Ok(decode_entity_set_page(body, schema)?.0)
}

/// Decode one page of an OData v2 JSON entity-set response: the
/// [`RecordBatch`] plus the server-pagination link (`d.__next`) if the
/// source split the collection across pages. The connector follows that
/// link (up to a bounded page count) to assemble the full result.
///
/// # Errors
/// As [`decode_entity_set`].
pub fn decode_entity_set_page(
    body: &str,
    schema: &SchemaRef,
) -> DataglotResult<(RecordBatch, Option<String>)> {
    let json: Value = serde_json::from_str(body)
        .map_err(|e| DataglotError::catalog(format!("OData response is not valid JSON: {e}")))?;
    let rows = locate_results(&json)?;

    // Every result must be a JSON object; a non-object row would otherwise
    // decode to all-nulls silently (a `.get(name)` on a non-object is `None`).
    if let Some(bad) = rows.iter().find(|r| !r.is_object()) {
        return Err(DataglotError::catalog(format!(
            "OData result row is not a JSON object: {bad}"
        )));
    }

    let columns = schema
        .fields()
        .iter()
        .map(|field| build_column(rows, field))
        .collect::<DataglotResult<Vec<ArrayRef>>>()?;

    let batch = RecordBatch::try_new(schema.clone(), columns).map_err(|e| {
        DataglotError::catalog(format!("failed to assemble OData result batch: {e}"))
    })?;
    Ok((batch, next_link(&json)))
}

/// The OData v2 server-pagination link, if present: `d.__next` (an absolute
/// or service-relative URL to the next page). A bare `__next` and the v4
/// `@odata.nextLink` are accepted as lenient fallbacks. A non-string or
/// absent value yields `None`.
fn next_link(json: &Value) -> Option<String> {
    json.get("d")
        .and_then(|d| d.get("__next"))
        .or_else(|| json.get("__next"))
        .or_else(|| json.get("@odata.nextLink"))
        .and_then(Value::as_str)
        .map(str::to_owned)
}

/// Locate the array of result objects in an OData response. Handles the v2
/// `d.results` and bare-`d`-array shapes, plus the v4 `value` shape as a
/// lenient fallback.
fn locate_results(json: &Value) -> DataglotResult<&[Value]> {
    let candidate = json
        .get("d")
        .and_then(|d| d.get("results").or(Some(d)))
        .or_else(|| json.get("value"));
    match candidate {
        Some(Value::Array(rows)) => Ok(rows),
        // A single-entity `{"d": {…}}` response isn't an entity-set result;
        // the connector only issues collection GETs, so treat non-arrays as
        // an unexpected shape rather than guessing.
        _ => Err(DataglotError::catalog(
            "OData response has no `d.results` (or `value`) array".to_string(),
        )),
    }
}

/// Build one Arrow column from `rows` for `field`, decoding each row's value
/// for `field.name()` according to the column's [`DataType`].
fn build_column(rows: &[Value], field: &Field) -> DataglotResult<ArrayRef> {
    let name = field.name();
    // The value for this field in each row (`None` ⇒ missing or JSON null),
    // collected once so it's iterated per column exactly once.
    let cells: Vec<Option<&Value>> = rows
        .iter()
        .map(|row| match row.get(name) {
            None | Some(Value::Null) => None,
            some => some,
        })
        .collect();

    // A non-nullable column must not receive a null/missing value — that would
    // build an Arrow array that violates its field's contract and can panic a
    // downstream consumer. Fail here with the column name instead.
    if !field.is_nullable() && cells.iter().any(Option::is_none) {
        return Err(DataglotError::catalog(format!(
            "OData column '{name}' is declared non-nullable but a row has no value for it"
        )));
    }
    let cells = || cells.iter().copied();

    Ok(match field.data_type() {
        DataType::Utf8 => Arc::new(
            cells()
                .map(|c| c.map(cell_string).transpose())
                .collect::<DataglotResult<StringArray>>()?,
        ),
        DataType::Boolean => Arc::new(
            cells()
                .map(|c| c.map(|v| cell_bool(v, name)).transpose())
                .collect::<DataglotResult<BooleanArray>>()?,
        ),
        DataType::Int16 => Arc::new(
            cells()
                .map(|c| c.map(|v| cell_int(v, name).map(|i| i as i16)).transpose())
                .collect::<DataglotResult<Int16Array>>()?,
        ),
        DataType::Int32 => Arc::new(
            cells()
                .map(|c| c.map(|v| cell_int(v, name).map(|i| i as i32)).transpose())
                .collect::<DataglotResult<Int32Array>>()?,
        ),
        DataType::Int64 => Arc::new(
            cells()
                .map(|c| c.map(|v| cell_int(v, name)).transpose())
                .collect::<DataglotResult<Int64Array>>()?,
        ),
        DataType::Float32 => Arc::new(
            cells()
                .map(|c| c.map(|v| cell_float(v, name).map(|f| f as f32)).transpose())
                .collect::<DataglotResult<Float32Array>>()?,
        ),
        DataType::Float64 => Arc::new(
            cells()
                .map(|c| c.map(|v| cell_float(v, name)).transpose())
                .collect::<DataglotResult<Float64Array>>()?,
        ),
        DataType::Decimal128(precision, scale) => {
            let values = cells()
                .map(|c| c.map(|v| cell_decimal(v, *scale, name)).transpose())
                .collect::<DataglotResult<Vec<Option<i128>>>>()?;
            Arc::new(
                Decimal128Array::from(values)
                    .with_precision_and_scale(*precision, *scale)
                    .map_err(|e| {
                        DataglotError::catalog(format!("invalid decimal column '{name}': {e}"))
                    })?,
            )
        }
        DataType::Timestamp(TimeUnit::Microsecond, tz) => {
            let values = cells()
                .map(|c| c.map(|v| cell_timestamp_micros(v, name)).transpose())
                .collect::<DataglotResult<Vec<Option<i64>>>>()?;
            let array = TimestampMicrosecondArray::from(values);
            Arc::new(match tz {
                Some(tz) => array.with_timezone(tz.clone()),
                None => array,
            })
        }
        other => {
            return Err(DataglotError::catalog(format!(
                "OData column '{name}' has unsupported Arrow type {other:?}"
            )))
        }
    })
}

/// A JSON value as an OData string cell.
fn cell_string(v: &Value) -> DataglotResult<String> {
    match v {
        Value::String(s) => Ok(s.clone()),
        // Be lenient: render a JSON number/bool that landed in a string column.
        Value::Number(n) => Ok(n.to_string()),
        Value::Bool(b) => Ok(b.to_string()),
        other => Err(type_error("string", other)),
    }
}

/// A JSON value as an integer (OData v2 returns Int64 as a string).
fn cell_int(v: &Value, name: &str) -> DataglotResult<i64> {
    match v {
        Value::Number(n) => n.as_i64().ok_or_else(|| {
            DataglotError::catalog(format!("column '{name}': {n} is not an integer"))
        }),
        Value::String(s) => s.parse::<i64>().map_err(|_| {
            DataglotError::catalog(format!("column '{name}': '{s}' is not an integer"))
        }),
        other => Err(type_error("integer", other)),
    }
}

/// A JSON value as a float (OData v2 may return Double/Single as a string).
fn cell_float(v: &Value, name: &str) -> DataglotResult<f64> {
    match v {
        Value::Number(n) => n
            .as_f64()
            .ok_or_else(|| DataglotError::catalog(format!("column '{name}': {n} is not a number"))),
        Value::String(s) => s
            .parse::<f64>()
            .map_err(|_| DataglotError::catalog(format!("column '{name}': '{s}' is not a number"))),
        other => Err(type_error("number", other)),
    }
}

/// A JSON value as a boolean (OData v2 may return `"true"` / `"false"`).
fn cell_bool(v: &Value, name: &str) -> DataglotResult<bool> {
    match v {
        Value::Bool(b) => Ok(*b),
        Value::String(s) if s.eq_ignore_ascii_case("true") => Ok(true),
        Value::String(s) if s.eq_ignore_ascii_case("false") => Ok(false),
        other => Err(DataglotError::catalog(format!(
            "column '{name}': {other} is not a boolean"
        ))),
    }
}

/// A JSON value as an unscaled `i128` at `scale` (OData v2 returns
/// `Edm.Decimal` as a string like `"123.45"`).
fn cell_decimal(v: &Value, scale: i8, name: &str) -> DataglotResult<i128> {
    let text = match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        other => return Err(type_error("decimal", other)),
    };
    decimal_str_to_i128(&text, scale).ok_or_else(|| {
        DataglotError::catalog(format!("column '{name}': '{text}' is not a decimal"))
    })
}

/// Parse a decimal string (`"-123.45"`, `"123"`, `".5"`) into an unscaled
/// `i128` at `scale` fractional digits. Excess fractional digits are
/// truncated; a shorter fraction is zero-padded. Negative scales shift the
/// integer left. Returns `None` on non-numeric input.
fn decimal_str_to_i128(text: &str, scale: i8) -> Option<i128> {
    let text = text.trim();
    let negative = text.starts_with('-');
    let unsigned = text.strip_prefix(['-', '+']).unwrap_or(text);
    let (int_part, frac_part) = unsigned.split_once('.').unwrap_or((unsigned, ""));
    if int_part.is_empty() && frac_part.is_empty() {
        return None;
    }
    if !int_part.bytes().all(|b| b.is_ascii_digit())
        || !frac_part.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }

    let digits = if scale >= 0 {
        let scale = scale.unsigned_abs() as usize;
        let mut frac = String::from(frac_part);
        if frac.len() < scale {
            frac.push_str(&"0".repeat(scale - frac.len()));
        } else {
            frac.truncate(scale);
        }
        format!("{int_part}{frac}")
    } else {
        // Negative scale: the unscaled value is `value / 10^|scale|`, i.e. drop
        // the last |scale| integer digits (any fraction is below the
        // representable granularity). "1200" @ scale -2 ⇒ unscaled 12.
        let drop = scale.unsigned_abs() as usize;
        int_part
            .get(..int_part.len().saturating_sub(drop))
            .unwrap_or("")
            .to_string()
    };

    let magnitude: i128 = digits
        .trim_start_matches('0')
        .parse()
        .or_else(|_| {
            // All-zero (or empty after trim) ⇒ 0.
            if digits.bytes().all(|b| b == b'0') {
                Ok(0)
            } else {
                Err(())
            }
        })
        .ok()?;
    Some(if negative { -magnitude } else { magnitude })
}

/// A JSON value as microseconds since the Unix epoch. Handles SAP's
/// `"/Date(<ms>)/"` epoch-millis form and a bare integer of milliseconds.
fn cell_timestamp_micros(v: &Value, name: &str) -> DataglotResult<i64> {
    let millis = match v {
        Value::String(s) => parse_sap_date_millis(s),
        Value::Number(n) => n.as_i64(),
        _ => None,
    };
    let millis = millis.ok_or_else(|| {
        DataglotError::catalog(format!(
            "column '{name}': {v} is not an /Date(ms)/ timestamp"
        ))
    })?;
    millis.checked_mul(1000).ok_or_else(|| {
        DataglotError::catalog(format!("column '{name}': timestamp {millis}ms overflows"))
    })
}

/// Parse the epoch-milliseconds out of SAP's `"/Date(1592524800000)/"` (an
/// optional `±HHMM` offset suffix is ignored — the instant is UTC-anchored).
fn parse_sap_date_millis(s: &str) -> Option<i64> {
    let inner = s.strip_prefix("/Date(")?.strip_suffix(")/")?;
    // Take the leading (optionally signed) integer, dropping any `±HHMM`
    // offset. `get(1..)` avoids panicking on an empty `/Date()/`.
    let end = inner
        .get(1..)?
        .find(['+', '-'])
        .map_or(inner.len(), |i| i + 1);
    inner.get(..end)?.parse::<i64>().ok()
}

/// A "column X is not a <expected>" error for an unexpected JSON kind.
fn type_error(expected: &str, got: &Value) -> DataglotError {
    DataglotError::catalog(format!("expected {expected}, got JSON value {got}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    use arrow::array::Array;
    use arrow::datatypes::{Field, Schema};

    fn schema() -> SchemaRef {
        SchemaRef::new(Schema::new(vec![
            Field::new("Name", DataType::Utf8, true),
            Field::new("Age", DataType::Int32, true),
            Field::new("Balance", DataType::Int64, true),
            Field::new("Ratio", DataType::Float64, true),
            Field::new("Active", DataType::Boolean, true),
            Field::new("Amount", DataType::Decimal128(13, 2), true),
            Field::new(
                "CreatedAt",
                DataType::Timestamp(TimeUnit::Microsecond, None),
                true,
            ),
        ]))
    }

    const BODY: &str = r#"{"d":{"results":[
        {"Name":"Alice","Age":30,"Balance":"9000000000","Ratio":1.5,"Active":true,"Amount":"123.45","CreatedAt":"/Date(1592524800000)/"},
        {"Name":"Bob","Age":null,"Balance":"-1","Ratio":"2.5","Active":"false","Amount":"0.05","CreatedAt":null}
    ]}}"#;

    #[test]
    fn page_extracts_next_link_or_none() {
        let s = SchemaRef::new(Schema::new(vec![Field::new("Name", DataType::Utf8, true)]));

        // `d.__next` present → returned as the pagination link.
        let with_next = r#"{"d":{"results":[{"Name":"A"}],"__next":"https://h/E?$skiptoken=k"}}"#;
        let (batch, next) = decode_entity_set_page(with_next, &s).expect("decodes");
        assert_eq!(batch.num_rows(), 1);
        assert_eq!(next.as_deref(), Some("https://h/E?$skiptoken=k"));

        // No `__next` → last page.
        let no_next = r#"{"d":{"results":[{"Name":"A"}]}}"#;
        assert!(decode_entity_set_page(no_next, &s)
            .expect("decodes")
            .1
            .is_none());
    }

    #[test]
    fn decodes_all_column_types_and_nulls() {
        let batch = decode_entity_set(BODY, &schema()).expect("decodes");
        assert_eq!(batch.num_rows(), 2);
        assert_eq!(batch.num_columns(), 7);

        let names = batch
            .column(0)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        assert_eq!(names.value(0), "Alice");
        assert_eq!(names.value(1), "Bob");

        let age = batch
            .column(1)
            .as_any()
            .downcast_ref::<Int32Array>()
            .unwrap();
        assert_eq!(age.value(0), 30);
        assert!(age.is_null(1), "JSON null ⇒ Arrow null");

        // Int64 arrives as a string in OData v2.
        let bal = batch
            .column(2)
            .as_any()
            .downcast_ref::<Int64Array>()
            .unwrap();
        assert_eq!(bal.value(0), 9_000_000_000);
        assert_eq!(bal.value(1), -1);

        // Float from number and from string.
        let ratio = batch
            .column(3)
            .as_any()
            .downcast_ref::<Float64Array>()
            .unwrap();
        assert!((ratio.value(0) - 1.5).abs() < f64::EPSILON);
        assert!((ratio.value(1) - 2.5).abs() < f64::EPSILON);

        // Bool from JSON bool and from string.
        let active = batch
            .column(4)
            .as_any()
            .downcast_ref::<BooleanArray>()
            .unwrap();
        assert!(active.value(0));
        assert!(!active.value(1));

        // Decimal string → unscaled i128 at scale 2.
        let amt = batch
            .column(5)
            .as_any()
            .downcast_ref::<Decimal128Array>()
            .unwrap();
        assert_eq!(amt.value(0), 12_345);
        assert_eq!(amt.value(1), 5);

        // /Date(ms)/ → microseconds; null stays null.
        let ts = batch
            .column(6)
            .as_any()
            .downcast_ref::<TimestampMicrosecondArray>()
            .unwrap();
        assert_eq!(ts.value(0), 1_592_524_800_000 * 1000);
        assert!(ts.is_null(1));
    }

    #[test]
    fn missing_property_becomes_null() {
        // Row omits "Age" entirely ⇒ null (not an error).
        let body = r#"{"d":{"results":[{"Name":"X"}]}}"#;
        let s = SchemaRef::new(Schema::new(vec![
            Field::new("Name", DataType::Utf8, true),
            Field::new("Age", DataType::Int32, true),
        ]));
        let batch = decode_entity_set(body, &s).unwrap();
        assert!(batch.column(1).is_null(0));
    }

    #[test]
    fn empty_results_yields_zero_rows() {
        let batch = decode_entity_set(r#"{"d":{"results":[]}}"#, &schema()).unwrap();
        assert_eq!(batch.num_rows(), 0);
        assert_eq!(batch.num_columns(), 7);
    }

    #[test]
    fn v4_style_value_array_is_accepted() {
        let body = r#"{"value":[{"Name":"Z"}]}"#;
        let s = SchemaRef::new(Schema::new(vec![Field::new("Name", DataType::Utf8, true)]));
        let batch = decode_entity_set(body, &s).unwrap();
        assert_eq!(batch.num_rows(), 1);
    }

    #[test]
    fn undecodable_cell_errors() {
        let body = r#"{"d":{"results":[{"Age":"not-a-number"}]}}"#;
        let s = SchemaRef::new(Schema::new(vec![Field::new("Age", DataType::Int32, true)]));
        assert!(decode_entity_set(body, &s).is_err());
    }

    #[test]
    fn bad_json_and_missing_results_error() {
        assert!(decode_entity_set("{not json", &schema()).is_err());
        assert!(decode_entity_set(r#"{"d":{}}"#, &schema()).is_err());
    }

    #[test]
    fn decimal_parsing_edge_cases() {
        assert_eq!(decimal_str_to_i128("123.45", 2), Some(12_345));
        assert_eq!(decimal_str_to_i128("-123.45", 2), Some(-12_345));
        assert_eq!(decimal_str_to_i128("123", 2), Some(12_300)); // zero-pad
        assert_eq!(decimal_str_to_i128("1.239", 2), Some(123)); // truncate
        assert_eq!(decimal_str_to_i128("0.05", 2), Some(5));
        assert_eq!(decimal_str_to_i128("5", 0), Some(5));
        // Negative scale: unscaled = value / 10^|scale| (drop trailing digits).
        assert_eq!(decimal_str_to_i128("1200", -2), Some(12));
        assert_eq!(decimal_str_to_i128("12", -2), Some(0));
        assert_eq!(decimal_str_to_i128("0", 2), Some(0));
        assert_eq!(decimal_str_to_i128("abc", 2), None);
        assert_eq!(decimal_str_to_i128("", 2), None);
    }

    #[test]
    fn sap_date_offset_suffix_is_ignored() {
        assert_eq!(
            parse_sap_date_millis("/Date(1592524800000)/"),
            Some(1_592_524_800_000)
        );
        assert_eq!(
            parse_sap_date_millis("/Date(1592524800000+0000)/"),
            Some(1_592_524_800_000)
        );
        assert_eq!(parse_sap_date_millis("/Date(-1000)/"), Some(-1000));
        assert_eq!(parse_sap_date_millis("nope"), None);
        // Empty `/Date()/` must not panic.
        assert_eq!(parse_sap_date_millis("/Date()/"), None);
    }

    #[test]
    fn non_object_row_errors() {
        let body = r#"{"d":{"results":["not-an-object"]}}"#;
        let s = SchemaRef::new(Schema::new(vec![Field::new("Name", DataType::Utf8, true)]));
        assert!(decode_entity_set(body, &s).is_err());
    }

    #[test]
    fn non_nullable_column_with_missing_value_errors() {
        // Field is non-nullable but the row omits it ⇒ error, not a silent null.
        let body = r#"{"d":{"results":[{"Other":"x"}]}}"#;
        let s = SchemaRef::new(Schema::new(vec![Field::new("Id", DataType::Utf8, false)]));
        let err = decode_entity_set(body, &s).unwrap_err();
        assert!(err.to_string().contains("non-nullable"), "{err}");
    }
}

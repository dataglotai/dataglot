//! Decode a generic REST/JSON response into an Arrow [`RecordBatch`].
//!
//! Unlike OData (which has a fixed `{"d": {"results": […]}}` envelope and a
//! `$metadata` schema document — see [`super::super::odata`]), a plain REST
//! API's row array can sit anywhere in the response and there is no universal
//! metadata, so:
//!
//! - the **row array** is located by a caller-supplied dot-path
//!   (`records_path`) — e.g. `"records"` (Salesforce), `"data.items"`, or `""`
//!   for a top-level JSON array;
//! - the Arrow **schema** is declared by the caller (per source/table).
//!
//! Each row object maps field names to JSON values. A missing field or JSON
//! `null` becomes an Arrow null; a present-but-undecodable value is an error
//! (surfacing bad source data rather than silently nulling it).

use std::sync::Arc;

use arrow::array::{
    ArrayRef, BooleanArray, Float64Array, Int32Array, Int64Array, RecordBatch, StringArray,
};
use arrow::datatypes::{DataType, Field, SchemaRef};
use serde_json::Value;

use dataglot_core::{DataglotError, Result as DataglotResult};

/// Decode a REST/JSON `body` into a [`RecordBatch`] for `schema`, locating the
/// row array at `records_path` (a `.`-separated object path; `""` = the body
/// is itself the array).
///
/// # Errors
/// [`DataglotError::Catalog`] if the body isn't valid JSON, the row array
/// can't be located at `records_path`, a cell can't be decoded to its column
/// type, or the batch fails to assemble.
pub fn decode_json_rows(
    body: &str,
    schema: &SchemaRef,
    records_path: &str,
) -> DataglotResult<RecordBatch> {
    Ok(decode_json_page(body, schema, records_path, None)?.0)
}

/// Decode one page of a REST/JSON response: the [`RecordBatch`] for `schema`
/// plus, if `next_path` is given, the "next page" URL found at that dot-path
/// (e.g. `nextRecordsUrl` for Salesforce). `None` is returned for the next link
/// when the path is absent or its value is not a JSON string — i.e. the last
/// page.
///
/// # Errors
/// [`DataglotError::Catalog`] if the body isn't valid JSON, the row array
/// can't be located at `records_path`, a cell can't be decoded to its column
/// type, or the batch fails to assemble.
pub fn decode_json_page(
    body: &str,
    schema: &SchemaRef,
    records_path: &str,
    next_path: Option<&str>,
) -> DataglotResult<(RecordBatch, Option<String>)> {
    let json: Value = serde_json::from_str(body)
        .map_err(|e| DataglotError::catalog(format!("REST response is not valid JSON: {e}")))?;
    let rows = locate_rows(&json, records_path)?;

    let columns = schema
        .fields()
        .iter()
        .map(|field| build_column(rows, field))
        .collect::<DataglotResult<Vec<ArrayRef>>>()?;

    let batch = RecordBatch::try_new(schema.clone(), columns).map_err(|e| {
        DataglotError::catalog(format!("REST rows don't fit the declared schema: {e}"))
    })?;
    let next = next_path.and_then(|p| locate_string(&json, p));
    Ok((batch, next))
}

/// Walk a dot-path from the root and return the value there as an owned string,
/// or `None` if any segment is missing or the final value is not a JSON string.
fn locate_string(json: &Value, path: &str) -> Option<String> {
    let mut cur = json;
    for seg in path.split('.') {
        cur = cur.get(seg)?;
    }
    match cur {
        Value::String(s) => Some(s.clone()),
        _ => None,
    }
}

/// Walk `records_path` (dot segments) from the root and return the array found
/// there. An empty path means the body itself must be the array.
fn locate_rows<'a>(json: &'a Value, records_path: &str) -> DataglotResult<&'a [Value]> {
    let mut cur = json;
    if !records_path.is_empty() {
        for seg in records_path.split('.') {
            cur = cur.get(seg).ok_or_else(|| {
                DataglotError::catalog(format!(
                    "REST records_path segment '{seg}' not found in response"
                ))
            })?;
        }
    }
    match cur {
        Value::Array(rows) => Ok(rows),
        _ => Err(DataglotError::catalog(format!(
            "REST records_path '{records_path}' did not resolve to a JSON array"
        ))),
    }
}

/// Build one Arrow column from `rows` for `field`, reading each row's value for
/// `field.name()` per the column's [`DataType`].
fn build_column(rows: &[Value], field: &Field) -> DataglotResult<ArrayRef> {
    let name = field.name();
    let cells: Vec<Option<&Value>> = rows
        .iter()
        .map(|row| match row.get(name) {
            None | Some(Value::Null) => None,
            some => some,
        })
        .collect();

    if !field.is_nullable() && cells.iter().any(Option::is_none) {
        return Err(DataglotError::catalog(format!(
            "REST column '{name}' is declared non-nullable but a row has no value for it"
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
        DataType::Float64 => Arc::new(
            cells()
                .map(|c| c.map(|v| cell_float(v, name)).transpose())
                .collect::<DataglotResult<Float64Array>>()?,
        ),
        other => {
            return Err(DataglotError::catalog(format!(
                "REST column '{name}': unsupported Arrow type {other:?} \
                 (slice 1 supports Utf8/Boolean/Int32/Int64/Float64)"
            )));
        }
    })
}

fn cell_string(v: &Value) -> DataglotResult<String> {
    match v {
        Value::String(s) => Ok(s.clone()),
        // Be lenient: render a JSON number/bool that landed in a string column.
        Value::Number(n) => Ok(n.to_string()),
        Value::Bool(b) => Ok(b.to_string()),
        other => Err(type_error("string", other)),
    }
}

fn cell_int(v: &Value, name: &str) -> DataglotResult<i64> {
    match v {
        Value::Number(n) => n.as_i64().ok_or_else(|| {
            DataglotError::catalog(format!("column '{name}': {n} is not an integer"))
        }),
        // Many REST APIs (like OData) return large integers as strings.
        Value::String(s) => s.parse::<i64>().map_err(|_| {
            DataglotError::catalog(format!("column '{name}': '{s}' is not an integer"))
        }),
        other => Err(type_error("integer", other)),
    }
}

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

fn cell_bool(v: &Value, name: &str) -> DataglotResult<bool> {
    match v {
        Value::Bool(b) => Ok(*b),
        other => Err(type_error(&format!("boolean for column '{name}'"), other)),
    }
}

fn type_error(expected: &str, got: &Value) -> DataglotError {
    DataglotError::catalog(format!("expected {expected}, got JSON value {got}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use arrow::array::Array;
    use arrow::datatypes::Schema;

    fn schema() -> SchemaRef {
        Arc::new(Schema::new(vec![
            Field::new("Name", DataType::Utf8, true),
            Field::new("Age", DataType::Int32, true),
            Field::new("Balance", DataType::Int64, true),
            Field::new("Ratio", DataType::Float64, true),
            Field::new("Active", DataType::Boolean, true),
        ]))
    }

    #[test]
    fn decodes_rows_at_a_records_path() {
        // Salesforce-shaped: rows under "records".
        let body = r#"{"totalSize":2,"records":[
            {"Name":"a","Age":30,"Balance":"9007199254740993","Ratio":1.5,"Active":true},
            {"Name":"b","Age":40,"Balance":"2","Ratio":2.5,"Active":false}
        ]}"#;
        let batch = decode_json_rows(body, &schema(), "records").expect("decode");
        assert_eq!(batch.num_rows(), 2);
        assert_eq!(batch.num_columns(), 5);
        let names = batch
            .column(0)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        assert_eq!(names.value(0), "a");
        // Int64 arriving as a string (JS-lossless) decodes correctly.
        let bal = batch
            .column(2)
            .as_any()
            .downcast_ref::<Int64Array>()
            .unwrap();
        assert_eq!(bal.value(0), 9_007_199_254_740_993);
    }

    #[test]
    fn decodes_a_top_level_array() {
        let body = r#"[{"Name":"x","Age":1,"Balance":1,"Ratio":0.0,"Active":true}]"#;
        let batch = decode_json_rows(body, &schema(), "").expect("decode");
        assert_eq!(batch.num_rows(), 1);
    }

    #[test]
    fn missing_field_and_json_null_become_arrow_nulls() {
        let body = r#"{"records":[
            {"Name":"a","Age":null,"Ratio":1.0,"Active":true},
            {"Age":5,"Balance":7,"Ratio":2.0,"Active":false}
        ]}"#;
        let batch = decode_json_rows(body, &schema(), "records").expect("decode");
        let ages = batch
            .column(1)
            .as_any()
            .downcast_ref::<Int32Array>()
            .unwrap();
        assert!(ages.is_null(0)); // explicit JSON null
        assert_eq!(ages.value(1), 5);
        let names = batch
            .column(0)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        assert!(names.is_null(1)); // missing field
    }

    #[test]
    fn errors_on_bad_path_and_bad_cell() {
        assert!(decode_json_rows(r#"{"x":1}"#, &schema(), "records").is_err());
        assert!(decode_json_rows("not json", &schema(), "").is_err());
        // "Age" declared Int32 but a non-numeric string is present.
        let body = r#"{"records":[{"Age":"not-a-number"}]}"#;
        assert!(decode_json_rows(body, &schema(), "records").is_err());
    }

    #[test]
    fn non_nullable_missing_value_is_rejected() {
        let strict = Arc::new(Schema::new(vec![Field::new("Age", DataType::Int32, false)]));
        let body = r#"{"records":[{"Name":"a"}]}"#;
        assert!(decode_json_rows(body, &strict, "records").is_err());
    }
}

//! Shape helpers shared by the connectors that push **one finished SQL
//! string** to a remote and receive Arrow back — today `adbc.rs` and
//! `flightsql.rs`.
//!
//! Both sit behind the same two seams of `datafusion-federation`'s
//! [`SQLExecutor`](datafusion_federation::sql::SQLExecutor):
//!
//! * `get_table_schema` receives a *rendered* `RemoteTableRef`, so the
//!   `<schema>.<table>` reference has to be split back apart
//!   ([`split_qualified`]);
//! * `execute` must hand back batches whose schema is exactly the one the
//!   federation plan resolved earlier, while a remote is free to answer with
//!   a wider integer or a different nullability ([`align_batch`]).
//!
//! Neither is source-specific, so they live here rather than being copied per
//! connector — the copies drifted apart once already.

use std::sync::Arc;

use arrow::array::RecordBatch;
use arrow::compute::{cast_with_options, CastOptions};
use arrow::datatypes::SchemaRef;
use dataglot_core::{DataglotError, Result as DataglotResult};

/// Align a remote-produced batch with the schema the federation plan
/// expects.
///
/// Remotes commonly agree on layout but differ in field nullability, names,
/// or exact numeric width; identical schemas pass through untouched,
/// same-arity schemas are cast column-by-column. `kind` names the connector
/// in error messages (`"adbc"`, `"flightsql"`).
///
/// # Errors
/// [`DataglotError::Federation`] when the remote returned a different number
/// of columns than the plan expects, when a column the plan calls
/// non-nullable contains nulls, when a column can't be cast to the planned
/// type, or when the rebuilt batch is rejected by Arrow.
pub(crate) fn align_batch(
    batch: &RecordBatch,
    target: &SchemaRef,
    kind: &str,
) -> DataglotResult<RecordBatch> {
    // Arity first: it is O(1), and every check below zips columns against
    // fields, which on a mismatch would silently walk the shorter of the two
    // and report whatever it found there instead of the real problem.
    if batch.num_columns() != target.fields().len() {
        return Err(DataglotError::federation(format!(
            "{kind} result arity mismatch: remote returned {} columns, plan expects {}",
            batch.num_columns(),
            target.fields().len()
        )));
    }
    // Nullability is checked even when the schemas match, and even on the
    // identical-schema fast path. `RecordBatch::try_new` does reject nulls in
    // a non-nullable column, but a batch decoded from Arrow IPC was never
    // put through it — so a remote that declares a column non-nullable and
    // then sends nulls in it would otherwise pass straight through to
    // DataFusion operators that trust the flag.
    //
    // *Logical* nulls, not `null_count()`: that counts only the validity
    // bitmap, so a dictionary whose valid key points at a null value, or a
    // `Null`-typed column, reports zero while every such row is null.
    // Counting logical nulls can build and scan a mask (dictionary,
    // run-end, union), so it is done only for fields that must not hold any.
    for (column, field) in batch.columns().iter().zip(target.fields()) {
        if field.is_nullable() {
            continue;
        }
        let nulls = column.logical_null_count();
        if nulls > 0 {
            return Err(DataglotError::federation(format!(
                "{kind} result column '{}' contains {nulls} null(s) but the plan expects it \
                 to be non-nullable",
                field.name(),
            )));
        }
    }
    if batch.schema().as_ref() == target.as_ref() {
        return Ok(batch.clone());
    }
    let columns = batch
        .columns()
        .iter()
        .zip(target.fields())
        .map(|(column, field)| {
            if column.data_type() == field.data_type() {
                Ok(Arc::clone(column))
            } else {
                // `safe: false`. The default safe cast turns a value it
                // cannot represent — an `Int64` that overflows `Int32`, a
                // string that will not parse as a timestamp — into a null
                // and reports success. Into a *nullable* target that is
                // silent data loss: the row survives with its value quietly
                // replaced, and nothing downstream can tell it apart from a
                // null the remote actually sent. Failing the query is the
                // only honest answer.
                cast_with_options(
                    column,
                    field.data_type(),
                    &CastOptions {
                        safe: false,
                        ..Default::default()
                    },
                )
                .map_err(|e| {
                    DataglotError::federation(format!(
                        "{kind} result column '{}' cast from {:?} to {:?} failed: {e}",
                        field.name(),
                        column.data_type(),
                        field.data_type()
                    ))
                })
            }
        })
        .collect::<DataglotResult<Vec<_>>>()?;
    RecordBatch::try_new(Arc::clone(target), columns)
        .map_err(|e| DataglotError::federation(format!("{kind} result batch rebuild failed: {e}")))
}

/// Split a `<schema>.<table>` reference (bare, double-quoted, or
/// backtick-quoted per the active dialect) into its two parts.
///
/// ADBC-only: the Flight SQL connector parses its references
/// quote-aware (a schema may itself contain a dot), which this cannot do —
/// it splits at the first separator so a dotted *table* name survives, the
/// shape ADBC needs.
///
/// Input comes from `datafusion-federation`'s `RemoteTableRef` rendering of
/// the reference the connector built in its `table_provider`, so the shape is
/// well-known. Returns `None` for anything that isn't two non-empty parts.
#[cfg(feature = "adbc")]
pub(crate) fn split_qualified(s: &str) -> Option<(String, String)> {
    let parts: Vec<&str> = s.splitn(2, '.').collect();
    if parts.len() != 2 {
        return None;
    }
    let unquote = |p: &str| p.trim_matches('"').trim_matches('`').to_string();
    let schema = unquote(parts[0]);
    let table = unquote(parts[1]);
    if schema.is_empty() || table.is_empty() {
        return None;
    }
    Some((schema, table))
}

#[cfg(test)]
mod tests {
    use arrow::array::{Int32Array, Int64Array};
    use arrow::datatypes::{DataType, Field, Schema};

    use super::*;

    #[cfg(feature = "adbc")]
    #[test]
    fn split_qualified_handles_all_quote_styles() {
        assert_eq!(
            split_qualified("main.orders"),
            Some(("main".to_string(), "orders".to_string()))
        );
        assert_eq!(
            split_qualified("\"main\".\"orders\""),
            Some(("main".to_string(), "orders".to_string()))
        );
        assert_eq!(
            split_qualified("`main`.`orders`"),
            Some(("main".to_string(), "orders".to_string()))
        );
        assert_eq!(split_qualified("orders"), None);
        assert_eq!(split_qualified(".orders"), None);
        assert_eq!(split_qualified("main."), None);
    }

    /// A schema-qualified name whose *table* part contains a dot keeps the
    /// remainder intact — `splitn(2, …)` splits on the first separator only.
    #[cfg(feature = "adbc")]
    #[test]
    fn split_qualified_splits_on_the_first_dot_only() {
        assert_eq!(
            split_qualified("main.orders.2024"),
            Some(("main".to_string(), "orders.2024".to_string()))
        );
    }

    #[test]
    fn align_batch_passes_identical_schemas_through_and_casts_widths() {
        let source_schema = Arc::new(Schema::new(vec![Field::new("n", DataType::Int32, false)]));
        let batch = RecordBatch::try_new(
            Arc::clone(&source_schema),
            vec![Arc::new(Int32Array::from(vec![1, 2, 3]))],
        )
        .unwrap();

        // Identical schema — untouched.
        let same = align_batch(&batch, &source_schema, "flightsql").unwrap();
        assert_eq!(same.schema().as_ref(), source_schema.as_ref());

        // Wider target — cast column-by-column.
        let target: SchemaRef =
            Arc::new(Schema::new(vec![Field::new("n", DataType::Int64, false)]));
        let widened = align_batch(&batch, &target, "flightsql").unwrap();
        assert_eq!(widened.schema().as_ref(), target.as_ref());
        let values = widened
            .column(0)
            .as_any()
            .downcast_ref::<Int64Array>()
            .unwrap();
        assert_eq!(values.values(), &[1, 2, 3]);

        // Arity mismatch — a named error, not a panic.
        let two_cols: SchemaRef = Arc::new(Schema::new(vec![
            Field::new("n", DataType::Int64, false),
            Field::new("m", DataType::Int64, false),
        ]));
        let err = align_batch(&batch, &two_cols, "flightsql").unwrap_err();
        assert!(
            err.to_string().contains("arity mismatch"),
            "expected an arity-mismatch error, got: {err}"
        );
    }

    /// The `kind` tag names the connector in the message, so a failure in a
    /// mixed-connector plan says which source produced it.
    #[test]
    fn align_batch_errors_name_the_connector() {
        let schema = Arc::new(Schema::new(vec![Field::new("n", DataType::Int32, false)]));
        let batch = RecordBatch::try_new(
            Arc::clone(&schema),
            vec![Arc::new(Int32Array::from(vec![1]))],
        )
        .unwrap();
        let two_cols: SchemaRef = Arc::new(Schema::new(vec![
            Field::new("n", DataType::Int32, false),
            Field::new("m", DataType::Int32, false),
        ]));
        let msg = align_batch(&batch, &two_cols, "adbc")
            .unwrap_err()
            .to_string();
        assert!(
            msg.contains("adbc result arity mismatch"),
            "the kind tag must name the connector, got: {msg}"
        );
    }

    /// A safe `cast` turns an unrepresentable value into a null rather than
    /// failing, so a cast into a non-nullable target *can* manufacture one.
    /// That path is already fail-closed: `RecordBatch::try_new` validates
    /// nullability unconditionally (arrow-array 58.4.0
    /// `src/record_batch.rs:348`, inside `try_new_impl`, no option gate).
    /// Pinned here as an executable fact rather than an argument, because
    /// review keeps asserting the opposite.
    #[test]
    fn an_unrepresentable_value_fails_the_query_rather_than_becoming_a_null() {
        let source = Arc::new(Schema::new(vec![Field::new("n", DataType::Utf8, false)]));
        let batch = RecordBatch::try_new(
            Arc::clone(&source),
            // "abc" has no Int32 representation; a safe cast yields a null.
            vec![Arc::new(arrow::array::StringArray::from(vec!["1", "abc"]))],
        )
        .unwrap();
        let target: SchemaRef =
            Arc::new(Schema::new(vec![Field::new("n", DataType::Int32, false)]));

        // The input carries no nulls, so the pre-cast guard passes and the
        // cast itself is what has to catch it — `safe: false` turns the
        // unrepresentable value into an error instead of a null.
        let err = align_batch(&batch, &target, "flightsql")
            .unwrap_err()
            .to_string();
        assert!(err.contains("cast from"), "caught at the cast: {err}");

        // …and a *nullable* target is the case that would otherwise be
        // silent: the row survives with its value quietly replaced by a
        // null, indistinguishable from one the remote really sent.
        let nullable: SchemaRef =
            Arc::new(Schema::new(vec![Field::new("n", DataType::Int32, true)]));
        let err = align_batch(&batch, &nullable, "flightsql")
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("cast from"),
            "an unrepresentable value is never silently nulled: {err}"
        );

        // An overflow is the same hazard with no parsing involved.
        let wide = RecordBatch::try_new(
            Arc::new(Schema::new(vec![Field::new("n", DataType::Int64, false)])),
            vec![Arc::new(Int64Array::from(vec![i64::from(i32::MAX) + 1]))],
        )
        .unwrap();
        assert!(
            align_batch(&wide, &nullable, "flightsql")
                .unwrap_err()
                .to_string()
                .contains("cast from"),
            "an Int64 that does not fit Int32 must not become a null"
        );
    }

    /// A batch decoded from Arrow IPC never went through
    /// `RecordBatch::try_new`, so a remote that declares a column
    /// non-nullable and then sends nulls in it would reach DataFusion
    /// operators that trust the flag. Caught here, on both the
    /// identical-schema fast path and the casting one.
    #[test]
    fn nulls_in_a_column_the_plan_calls_non_nullable_are_refused() {
        let nullable = Arc::new(Schema::new(vec![Field::new("n", DataType::Int32, true)]));
        let batch = RecordBatch::try_new(
            Arc::clone(&nullable),
            vec![Arc::new(Int32Array::from(vec![Some(1), None]))],
        )
        .unwrap();

        // Same type, non-nullable target — the fast path must not wave it
        // through just because the data types agree.
        let target: SchemaRef =
            Arc::new(Schema::new(vec![Field::new("n", DataType::Int32, false)]));
        let err = align_batch(&batch, &target, "flightsql")
            .unwrap_err()
            .to_string();
        assert!(err.contains("non-nullable"), "{err}");
        assert!(err.contains("1 null"), "the count helps diagnosis: {err}");

        // Different type, non-nullable target — the casting path too.
        let widened: SchemaRef =
            Arc::new(Schema::new(vec![Field::new("n", DataType::Int64, false)]));
        assert!(align_batch(&batch, &widened, "flightsql")
            .unwrap_err()
            .to_string()
            .contains("non-nullable"));

        // A nullable target accepts them.
        align_batch(&batch, &nullable, "flightsql").expect("nulls are fine when declared");
    }

    /// `null_count()` counts only *physical* nulls. A dictionary array whose
    /// keys are all valid can still point at a null value, and a `Null`-typed
    /// column reports `null_count() == 0` for every row — both are logical
    /// nulls a non-nullable column must not carry. `RecordBatch::try_new`
    /// checks only physical nulls too, so the guard has to look at logical
    /// ones itself.
    #[test]
    fn logical_nulls_in_a_column_the_plan_calls_non_nullable_are_refused() {
        use arrow::array::{Array as _, DictionaryArray, NullArray, StringArray};
        use arrow::datatypes::Int32Type;

        // A valid key (0) pointing at a null dictionary value.
        let dict = DictionaryArray::<Int32Type>::try_new(
            Int32Array::from(vec![0, 0]),
            Arc::new(StringArray::from(vec![None::<&str>])),
        )
        .unwrap();
        assert_eq!(
            dict.null_count(),
            0,
            "no physical nulls: the keys are valid"
        );
        let dict_type = dict.data_type().clone();
        let schema: SchemaRef = Arc::new(Schema::new(vec![Field::new("d", dict_type, false)]));
        // Arrow itself accepts the batch — it checks physical nulls only.
        let batch = RecordBatch::try_new(Arc::clone(&schema), vec![Arc::new(dict)]).unwrap();
        // Identical-schema fast path.
        let err = align_batch(&batch, &schema, "flightsql")
            .unwrap_err()
            .to_string();
        assert!(err.contains("non-nullable"), "{err}");
        assert!(err.contains("2 null"), "{err}");
        // Casting path (dictionary → plain Utf8).
        let plain: SchemaRef = Arc::new(Schema::new(vec![Field::new("d", DataType::Utf8, false)]));
        assert!(align_batch(&batch, &plain, "flightsql")
            .unwrap_err()
            .to_string()
            .contains("non-nullable"));

        // A `Null`-typed column is all logical nulls with `null_count() == 0`.
        let nulls = NullArray::new(3);
        assert_eq!(nulls.null_count(), 0);
        let source = Arc::new(Schema::new(vec![Field::new("z", DataType::Null, true)]));
        let batch = RecordBatch::try_new(source, vec![Arc::new(nulls)]).unwrap();
        let target: SchemaRef =
            Arc::new(Schema::new(vec![Field::new("z", DataType::Int32, false)]));
        assert!(align_batch(&batch, &target, "flightsql")
            .unwrap_err()
            .to_string()
            .contains("non-nullable"));
    }
}

//! Translate DataFusion filter [`Expr`]s into an OData v2 `$filter` string.
//!
//! This is the load-bearing pushdown piece of the OData connector: a filter
//! the OData service can evaluate is rendered into the `$filter` query
//! parameter and advertised `Exact` (DataFusion then removes it from the
//! local plan); anything else is left `Unsupported` and evaluated locally.
//!
//! Scope (OData v2, MVP): the six scalar comparisons (`=`, `!=`, `<`, `<=`,
//! `>`, `>=`) plus `IS NULL` / `IS NOT NULL`, combined with `AND` / `OR` /
//! `NOT`, over the four literal kinds (integer, real/decimal, string,
//! boolean) and `NULL`. Any other expression (functions, `LIKE`, `IN`,
//! casts, date literals, …) is reported as not-pushed and handled by
//! DataFusion. Aggregation/`ORDER BY`/join pushdown are out of scope (OData
//! v2 has no `$groupby`) — see the spec.

use datafusion::logical_expr::{BinaryExpr, Expr, Operator};
use datafusion::scalar::ScalarValue;

/// The result of translating a slice of DataFusion filters.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FilterTranslation {
    /// The combined `$filter` value — the pushed fragments joined with
    /// `and` — or `None` when nothing was pushable.
    pub filter: Option<String>,
    /// Aligned 1:1 with the input `filters`: `true` at index `i` means
    /// `filters[i]` was translated (advertise
    /// [`Exact`](datafusion::logical_expr::TableProviderFilterPushDown::Exact)),
    /// `false` means it was not (advertise `Unsupported`).
    pub pushed: Vec<bool>,
}

/// Translate `filters` into an OData `$filter` string, recording per-filter
/// whether each was pushed. Each top-level filter is independent (DataFusion
/// passes a conjunction as separate slice entries), so a mix of
/// pushable/unpushable filters pushes what it can and leaves the rest local.
#[must_use]
pub fn translate_filters(filters: &[Expr]) -> FilterTranslation {
    let mut fragments = Vec::new();
    let mut pushed = Vec::with_capacity(filters.len());
    for f in filters {
        match translate_expr(f) {
            Some(fragment) => {
                fragments.push(fragment);
                pushed.push(true);
            }
            None => pushed.push(false),
        }
    }
    let filter = (!fragments.is_empty()).then(|| fragments.join(" and "));
    FilterTranslation { filter, pushed }
}

/// Render one predicate to an OData `$filter` fragment, or `None` if it is
/// not pushable (⇒ DataFusion evaluates it locally). Recursive over
/// `AND`/`OR`/`NOT`; a compound expression pushes only if *every* leaf does.
fn translate_expr(expr: &Expr) -> Option<String> {
    match expr {
        Expr::BinaryExpr(BinaryExpr { left, op, right }) => match op {
            Operator::And => Some(format!(
                "({} and {})",
                translate_expr(left)?,
                translate_expr(right)?
            )),
            Operator::Or => Some(format!(
                "({} or {})",
                translate_expr(left)?,
                translate_expr(right)?
            )),
            Operator::Eq
            | Operator::NotEq
            | Operator::Lt
            | Operator::LtEq
            | Operator::Gt
            | Operator::GtEq => translate_comparison(left, *op, right),
            _ => None,
        },
        Expr::Not(inner) => Some(format!("not ({})", translate_expr(inner)?)),
        Expr::IsNull(inner) => Some(format!("{} eq null", as_column(inner)?)),
        Expr::IsNotNull(inner) => Some(format!("{} ne null", as_column(inner)?)),
        _ => None,
    }
}

/// A `column <op> literal` (or `literal <op> column`) comparison. The column
/// must be one side and a literal the other; when the literal is on the left
/// the operator is flipped so the rendered form is always `column op value`.
fn translate_comparison(left: &Expr, op: Operator, right: &Expr) -> Option<String> {
    if let (Some(name), Some(scalar)) = (as_column(left), as_literal(right)) {
        return Some(format!(
            "{name} {} {}",
            odata_op(op)?,
            render_scalar(scalar)?
        ));
    }
    if let (Some(scalar), Some(name)) = (as_literal(left), as_column(right)) {
        return Some(format!(
            "{name} {} {}",
            odata_op(flip_op(op))?,
            render_scalar(scalar)?
        ));
    }
    None
}

/// The OData property name for a bare column reference (ignores any relation
/// qualifier — OData entity sets are flat), or `None` for anything else.
fn as_column(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Column(c) => Some(c.name.clone()),
        _ => None,
    }
}

/// The literal value of a scalar-literal expression, else `None`.
fn as_literal(expr: &Expr) -> Option<&ScalarValue> {
    match expr {
        Expr::Literal(scalar, _) => Some(scalar),
        _ => None,
    }
}

/// DataFusion comparison operator → OData v2 `$filter` operator keyword.
fn odata_op(op: Operator) -> Option<&'static str> {
    match op {
        Operator::Eq => Some("eq"),
        Operator::NotEq => Some("ne"),
        Operator::Lt => Some("lt"),
        Operator::LtEq => Some("le"),
        Operator::Gt => Some("gt"),
        Operator::GtEq => Some("ge"),
        _ => None,
    }
}

/// Flip a comparison operator so `literal op column` becomes an equivalent
/// `column op' literal` (e.g. `5 < x` ⇒ `x > 5`).
fn flip_op(op: Operator) -> Operator {
    match op {
        Operator::Lt => Operator::Gt,
        Operator::LtEq => Operator::GtEq,
        Operator::Gt => Operator::Lt,
        Operator::GtEq => Operator::LtEq,
        // `eq` / `ne` are symmetric.
        other => other,
    }
}

/// Render a scalar literal as an OData v2 `$filter` value literal, or `None`
/// for an unsupported type (⇒ the whole predicate stays local).
///
/// Follows OData v2's URI literal grammar, which SAP enforces strictly:
/// strings are single-quoted with embedded quotes doubled (EDM escaping);
/// `Edm.Int64` carries an `L` suffix, `Edm.Single` an `f`, `Edm.Double` a
/// `d`, `Edm.Decimal` an `M`; floats always carry a decimal point.
///
/// A **null** literal returns `None` — a `col = NULL` comparison has SQL's
/// three-valued semantics (never true), which is *not* the same as OData's
/// `col eq null` null test, so it must not be pushed. Genuine null tests
/// arrive as `IS NULL` / `IS NOT NULL` and are handled in [`translate_expr`].
fn render_scalar(scalar: &ScalarValue) -> Option<String> {
    match scalar {
        ScalarValue::Utf8(Some(s))
        | ScalarValue::LargeUtf8(Some(s))
        | ScalarValue::Utf8View(Some(s)) => Some(format!("'{}'", s.replace('\'', "''"))),
        ScalarValue::Boolean(Some(b)) => Some((*b).to_string()),
        // Int32 and smaller fit `Edm.Int32` (no suffix); `Edm.Int64` takes `L`.
        ScalarValue::Int8(Some(v)) => Some(v.to_string()),
        ScalarValue::Int16(Some(v)) => Some(v.to_string()),
        ScalarValue::Int32(Some(v)) => Some(v.to_string()),
        ScalarValue::Int64(Some(v)) => Some(format!("{v}L")),
        ScalarValue::UInt8(Some(v)) => Some(v.to_string()),
        ScalarValue::UInt16(Some(v)) => Some(v.to_string()),
        // u32/u64 can exceed `Edm.Int32`, so render as Int64 (`L`).
        ScalarValue::UInt32(Some(v)) => Some(format!("{v}L")),
        ScalarValue::UInt64(Some(v)) => Some(format!("{v}L")),
        ScalarValue::Float32(Some(v)) => render_float(f64::from(*v)).map(|s| format!("{s}f")),
        ScalarValue::Float64(Some(v)) => render_float(*v).map(|s| format!("{s}d")),
        ScalarValue::Decimal128(Some(v), _precision, scale) => {
            Some(format!("{}M", render_decimal128(*v, *scale)))
        }
        _ => None,
    }
}

/// Render a float literal (refusing non-finite values — no OData spelling),
/// ensuring a decimal point or exponent is present so the OData grammar's
/// `Edm.Double`/`Edm.Single` production accepts it (`12` → `12.0`).
fn render_float(v: f64) -> Option<String> {
    if !v.is_finite() {
        return None;
    }
    let s = v.to_string();
    if s.contains(['.', 'e', 'E']) {
        Some(s)
    } else {
        Some(format!("{s}.0"))
    }
}

/// Render an i128 unscaled decimal value at `scale` fractional digits as a
/// plain decimal string. A positive scale places a decimal point (value
/// `12345`, scale `2` ⇒ `123.45`); a negative scale (Arrow permits these)
/// appends trailing zeros (value `123`, scale `-2` ⇒ `12300`).
fn render_decimal128(value: i128, scale: i8) -> String {
    if scale == 0 {
        return value.to_string();
    }
    if scale < 0 {
        return format!("{value}{}", "0".repeat(scale.unsigned_abs() as usize));
    }
    // `scale > 0` here, so `unsigned_abs` (u8) → usize is lossless.
    let scale = scale.unsigned_abs() as usize;
    let negative = value < 0;
    // `unsigned_abs` handles i128::MIN without overflow.
    let mut digits = value.unsigned_abs().to_string();
    if digits.len() <= scale {
        // Pad so there's at least one integer digit before the point.
        digits = format!("{digits:0>width$}", width = scale + 1);
    }
    let point = digits.len() - scale;
    let rendered = format!("{}.{}", &digits[..point], &digits[point..]);
    if negative {
        format!("-{rendered}")
    } else {
        rendered
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use datafusion::common::Column;
    use datafusion::prelude::lit;
    use datafusion::scalar::ScalarValue;

    /// An exact-case column reference. (The `col()` helper parses a SQL
    /// identifier and lowercases unquoted names; a real scan receives
    /// schema-resolved columns whose names preserve the EDM property casing,
    /// which is what this builds.)
    fn c(name: &str) -> Expr {
        Expr::Column(Column::new_unqualified(name))
    }

    /// Translate a single expression and return the `$filter` fragment.
    fn frag(expr: &Expr) -> Option<String> {
        translate_expr(expr)
    }

    #[test]
    fn comparisons_map_to_odata_operators() {
        assert_eq!(frag(&c("Age").eq(lit(30))).unwrap(), "Age eq 30");
        assert_eq!(frag(&c("Age").not_eq(lit(30))).unwrap(), "Age ne 30");
        assert_eq!(frag(&c("Age").lt(lit(30))).unwrap(), "Age lt 30");
        assert_eq!(frag(&c("Age").lt_eq(lit(30))).unwrap(), "Age le 30");
        assert_eq!(frag(&c("Age").gt(lit(30))).unwrap(), "Age gt 30");
        assert_eq!(frag(&c("Age").gt_eq(lit(30))).unwrap(), "Age ge 30");
    }

    #[test]
    fn literal_on_the_left_flips_the_operator() {
        // `5 < Age` ⇒ `Age gt 5`
        assert_eq!(frag(&lit(5).lt(c("Age"))).unwrap(), "Age gt 5");
        // `10 = Age` ⇒ `Age eq 10` (symmetric)
        assert_eq!(frag(&lit(10).eq(c("Age"))).unwrap(), "Age eq 10");
    }

    #[test]
    fn string_literals_are_single_quoted_and_escaped() {
        assert_eq!(
            frag(&c("City").eq(lit("Berlin"))).unwrap(),
            "City eq 'Berlin'"
        );
        // Embedded single quotes are doubled per EDM escaping.
        assert_eq!(
            frag(&c("Name").eq(lit("O'Brien"))).unwrap(),
            "Name eq 'O''Brien'"
        );
    }

    #[test]
    fn boolean_and_null_literals() {
        assert_eq!(frag(&c("Active").eq(lit(true))).unwrap(), "Active eq true");
        assert_eq!(frag(&c("Deleted").is_null()).unwrap(), "Deleted eq null");
        assert_eq!(
            frag(&c("Deleted").is_not_null()).unwrap(),
            "Deleted ne null"
        );
    }

    #[test]
    fn decimal_literal_renders_with_scale_and_suffix() {
        let price = ScalarValue::Decimal128(Some(12_345), 10, 2);
        assert_eq!(
            frag(&c("Price").gt(lit(price))).unwrap(),
            "Price gt 123.45M"
        );
        // Fractional-only value pads an integer zero.
        let small = ScalarValue::Decimal128(Some(5), 10, 2);
        assert_eq!(frag(&c("R").eq(lit(small))).unwrap(), "R eq 0.05M");
    }

    #[test]
    fn render_decimal128_handles_scales() {
        assert_eq!(render_decimal128(12_345, 2), "123.45");
        assert_eq!(render_decimal128(5, 2), "0.05");
        assert_eq!(render_decimal128(-12_345, 2), "-123.45");
        assert_eq!(render_decimal128(42, 0), "42");
        // Negative scale appends trailing zeros (123 × 10^2).
        assert_eq!(render_decimal128(123, -2), "12300");
        assert_eq!(render_decimal128(-123, -2), "-12300");
    }

    #[test]
    fn odata_v2_literal_type_suffixes() {
        // Int32 (the default int literal) is bare; Int64 takes `L`.
        assert_eq!(frag(&c("V").eq(lit(30_i32))).unwrap(), "V eq 30");
        assert_eq!(frag(&c("V").eq(lit(30_i64))).unwrap(), "V eq 30L");
        // Double → `d` (with a decimal point); Single → `f`.
        assert_eq!(frag(&c("V").eq(lit(12.3_f64))).unwrap(), "V eq 12.3d");
        assert_eq!(frag(&c("V").eq(lit(12.0_f64))).unwrap(), "V eq 12.0d");
        assert_eq!(frag(&c("V").eq(lit(12.5_f32))).unwrap(), "V eq 12.5f");
    }

    #[test]
    fn null_literal_comparison_is_not_pushed() {
        // `col = NULL` is SQL three-valued (never true) — not OData's null
        // test — so it must NOT be pushed. Only IS NULL / IS NOT NULL are.
        assert!(frag(&c("V").eq(lit(ScalarValue::Null))).is_none());
        assert!(frag(&c("V").eq(lit(ScalarValue::Int32(None)))).is_none());
        assert!(frag(&c("V").not_eq(lit(ScalarValue::Utf8(None)))).is_none());
    }

    #[test]
    fn and_or_not_compose() {
        let e = c("Age").gt(lit(18)).and(c("City").eq(lit("NYC")));
        assert_eq!(frag(&e).unwrap(), "(Age gt 18 and City eq 'NYC')");

        let e = c("A").eq(lit(1)).or(c("B").eq(lit(2)));
        assert_eq!(frag(&e).unwrap(), "(A eq 1 or B eq 2)");

        let e = Expr::Not(Box::new(c("Active").eq(lit(true))));
        assert_eq!(frag(&e).unwrap(), "not (Active eq true)");
    }

    #[test]
    fn unsupported_predicates_are_not_pushed() {
        // A predicate the OData layer can't express pushes nothing.
        let unsupported = c("Name").like(lit("A%"));
        assert!(frag(&unsupported).is_none());
        // AND with an unsupported leaf ⇒ whole thing unpushable.
        assert!(frag(&c("Age").gt(lit(1)).and(unsupported)).is_none());
        // A bare column or literal is not a predicate.
        assert!(frag(&c("Age")).is_none());
    }

    #[test]
    fn translate_filters_reports_per_filter_pushdown() {
        let filters = vec![
            c("Age").gt(lit(18)),        // pushable
            c("Name").like(lit("A%")),   // not pushable
            c("City").eq(lit("Berlin")), // pushable
        ];
        let out = translate_filters(&filters);
        assert_eq!(out.pushed, vec![true, false, true]);
        assert_eq!(
            out.filter.unwrap(),
            "Age gt 18 and City eq 'Berlin'",
            "pushed fragments are combined with `and`"
        );
    }

    #[test]
    fn no_pushable_filters_yields_none() {
        let filters = vec![c("Name").like(lit("A%"))];
        let out = translate_filters(&filters);
        assert_eq!(out.pushed, vec![false]);
        assert!(out.filter.is_none());
    }
}

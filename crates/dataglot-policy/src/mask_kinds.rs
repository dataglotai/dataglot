//! Named column-mask types — Apache Ranger masking parity (OSS / Ranger
//! policy-parity slice 1).
//!
//! [`crate::ColumnMask`] accepts an arbitrary masking `Expr`, which is
//! strictly more expressive than Ranger's fixed mask list — but a
//! customer migrating Ranger policies thinks in Ranger's *named* mask
//! types (`MASK` / redact, `MASK_SHOW_LAST_4`, `MASK_HASH`,
//! `MASK_NULL`, …), not DataFusion `Expr` trees.
//!
//! [`MaskKind`] is that vocabulary: each variant compiles to the
//! equivalent plan-time `Expr` via [`MaskKind::to_expr`], so a config
//! (or a future Ranger policy importer) can say `"hash"` and get the
//! same masking Dataglot already enforces. The produced `Expr`
//! references the source column, so it transforms the real value — the
//! same Projection-substitution path [`crate::ColumnMaskingEnforcer`]
//! uses for literal masks.
//!
//! Mapping to Ranger's built-in mask types:
//!
//! | Ranger | [`MaskKind`] |
//! |---|---|
//! | `MASK` (redact: letters→x, digits→n) | [`MaskKind::Redact`] |
//! | `MASK_SHOW_LAST_N` | [`MaskKind::PartialShowLast`] |
//! | `MASK_SHOW_FIRST_N` | [`MaskKind::PartialShowFirst`] |
//! | `MASK_HASH` | [`MaskKind::Hash`] |
//! | `MASK_NULL` | [`MaskKind::Nullify`] |
//! | `MASK_DATE_SHOW_YEAR` | [`MaskKind::DateYear`] |
//! | `MASK_NONE` / custom constant | [`MaskKind::Constant`] |

use datafusion::arrow::datatypes::DataType;
use datafusion::common::ScalarValue;
use datafusion::functions::expr_fn::{
    character_length, concat, date_trunc, left, md5, nullif, regexp_replace, repeat, right,
};
use datafusion::logical_expr::{col, lit, when, Cast, Expr};

/// A named column-masking strategy that compiles to a DataFusion `Expr`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MaskKind {
    /// Redact: replace every letter with `x` and every digit with `n`,
    /// preserving length and punctuation. Ranger's default `MASK`.
    Redact,
    /// Show the last `n` characters; mask the rest with `X`.
    PartialShowLast(usize),
    /// Show the first `n` characters; mask the rest with `X`.
    PartialShowFirst(usize),
    /// Replace the value with its MD5 hex digest. Ranger `MASK_HASH`.
    Hash,
    /// Replace the value with a type-preserving `NULL`. Ranger `MASK_NULL`.
    Nullify,
    /// Truncate a date/timestamp to the start of its year (year only).
    /// Ranger `MASK_DATE_SHOW_YEAR`.
    DateYear,
    /// Replace the value with a constant Utf8 literal.
    Constant(String),
}

/// Cast the column to Utf8 so the string-manipulation masks operate on a
/// text value regardless of the source column's type.
fn as_text(column: &str) -> Expr {
    Expr::Cast(Cast::new(Box::new(col(column)), DataType::Utf8))
}

/// Wrap a masking expression so a NULL source column stays NULL.
/// `concat` (used by the partial masks) coalesces NULL to `""`, which
/// would turn a NULL into an empty-string value downstream; every other
/// mask kind preserves NULL, so the partials must too.
fn null_safe(source: Expr, masked: Expr) -> Expr {
    when(source.is_null(), lit(ScalarValue::Utf8(None)))
        .otherwise(masked)
        .expect("case builder: when/otherwise are both set")
}

/// Which end of the value a partial mask reveals.
#[derive(Clone, Copy)]
enum Reveal {
    First,
    Last,
}

/// Compile a `PartialShowFirst`/`PartialShowLast` mask.
///
///: a value not strictly longer than `keep` cannot reveal a
/// "first/last `keep`" without exposing the whole value, so it is masked
/// in FULL (all `X`, length preserved). NULL is preserved via
/// [`null_safe`] (the underlying `concat` would otherwise coalesce it
/// to `""`). Char-based `character_length` / `left` / `right` keep the
/// count in code points, never splitting a multi-byte character.
fn partial_mask(column: &str, n: usize, reveal: Reveal) -> Expr {
    let keep = i64::try_from(n).unwrap_or(i64::MAX);
    let s = as_text(column);
    // `character_length` returns Int32 for the Utf8 input `as_text`
    // guarantees, while `keep` is an Int64 literal. Mask expressions are
    // injected by an OptimizerRule, which runs AFTER the TypeCoercion
    // analyzer — nothing coerces a mixed-type operation for us, and the
    // uncoerced `Int32 > Int64` panics at execution when the masked
    // table sits inside a federated join (dataglotai/dataglot#2). Cast
    // the length up front so every use below (`>`, `-`, the `repeat`
    // count) is Int64-vs-Int64 by construction.
    let full_len = Expr::Cast(Cast::new(
        Box::new(character_length(s.clone())),
        DataType::Int64,
    ));
    let longer = full_len.clone().gt(lit(keep));
    let masked_len = when(longer.clone(), full_len.clone() - lit(keep))
        .otherwise(full_len)
        .expect("case builder: when/otherwise are both set");
    let mask = repeat(lit("X"), masked_len);
    let body = match reveal {
        Reveal::Last => {
            let shown = when(longer, right(s.clone(), lit(keep)))
                .otherwise(lit(""))
                .expect("case builder: when/otherwise are both set");
            concat(vec![mask, shown])
        }
        Reveal::First => {
            let shown = when(longer, left(s.clone(), lit(keep)))
                .otherwise(lit(""))
                .expect("case builder: when/otherwise are both set");
            concat(vec![shown, mask])
        }
    };
    null_safe(s, body)
}

impl MaskKind {
    /// Compile this mask into the `Expr` that replaces the column value.
    #[must_use]
    pub fn to_expr(&self, column: &str) -> Expr {
        match self {
            MaskKind::Constant(value) => lit(value.clone()),
            // `nullif(x, x)` is always NULL but carries x's type, so the
            // masked projection column keeps the original column's type
            // (an untyped NULL literal would poison the output schema).
            MaskKind::Nullify => nullif(col(column), col(column)),
            MaskKind::Hash => md5(as_text(column)),
            MaskKind::Redact => {
                let letters =
                    regexp_replace(as_text(column), lit("[A-Za-z]"), lit("x"), Some(lit("g")));
                regexp_replace(letters, lit("[0-9]"), lit("n"), Some(lit("g")))
            }
            MaskKind::PartialShowLast(n) => partial_mask(column, *n, Reveal::Last),
            MaskKind::PartialShowFirst(n) => partial_mask(column, *n, Reveal::First),
            MaskKind::DateYear => date_trunc(lit("year"), col(column)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use datafusion::arrow::array::{Array, ArrayRef, StringArray};
    use datafusion::arrow::record_batch::RecordBatch;
    use datafusion::prelude::SessionContext;
    use std::sync::Arc;

    /// Apply `kind` to a single-column `email` table and return the one
    /// masked string value.
    async fn mask_one(kind: &MaskKind, value: &str) -> Option<String> {
        let batch = RecordBatch::try_from_iter(vec![(
            "email",
            Arc::new(StringArray::from(vec![value])) as ArrayRef,
        )])
        .unwrap();
        let ctx = SessionContext::new();
        let df = ctx
            .read_batch(batch)
            .unwrap()
            .select(vec![kind.to_expr("email").alias("m")])
            .unwrap();
        let batches = df.collect().await.unwrap();
        // Normalize to Utf8 — some string functions (e.g. md5) return
        // Utf8View in DataFusion 53; cast so the assertion is type-agnostic.
        let arr = datafusion::arrow::compute::cast(batches[0].column(0), &DataType::Utf8).unwrap();
        let col = arr.as_any().downcast_ref::<StringArray>().expect("Utf8");
        if col.is_null(0) {
            None
        } else {
            Some(col.value(0).to_string())
        }
    }

    #[tokio::test]
    async fn constant_replaces_value() {
        let m = MaskKind::Constant("***".into());
        assert_eq!(
            mask_one(&m, "alice@example.com").await.as_deref(),
            Some("***")
        );
    }

    #[tokio::test]
    async fn redact_masks_letters_and_digits() {
        let m = MaskKind::Redact;
        // letters -> x, digits -> n, punctuation preserved
        assert_eq!(mask_one(&m, "aB12.c").await.as_deref(), Some("xxnn.x"));
    }

    #[tokio::test]
    async fn hash_is_md5_hex() {
        let m = MaskKind::Hash;
        // MD5 of the input, as 32-char lowercase hex.
        let out = mask_one(&m, "secret").await.unwrap();
        assert_eq!(out.len(), 32);
        assert!(out.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(out, "secret");
    }

    #[tokio::test]
    async fn nullify_returns_null() {
        let m = MaskKind::Nullify;
        assert_eq!(mask_one(&m, "alice@example.com").await, None);
    }

    #[tokio::test]
    async fn show_last_n_masks_prefix() {
        let m = MaskKind::PartialShowLast(4);
        // "1234567" -> mask first 3 with X, show last 4
        assert_eq!(mask_one(&m, "1234567").await.as_deref(), Some("XXX4567"));
    }

    /// Regression for dataglotai/dataglot#2: mask expressions are injected
    /// by an `OptimizerRule`, which runs AFTER the `TypeCoercion` analyzer, so
    /// a mixed-type operation inside a mask is never coerced and panics at
    /// execution (`Invalid comparison operation: Int32 > Int64`) when the
    /// masked table sits inside a federated join. Pin that every binary
    /// operation in the partial masks is type-identical by construction.
    #[test]
    fn partial_masks_are_type_correct_without_coercion() {
        use datafusion::arrow::datatypes::{Field, Schema};
        use datafusion::common::tree_node::{TreeNode, TreeNodeRecursion};
        use datafusion::common::DFSchema;
        use datafusion::logical_expr::{BinaryExpr, ExprSchemable};

        let schema = Schema::new(vec![Field::new("email", DataType::Utf8, true)]);
        let df_schema = DFSchema::try_from(schema).unwrap();
        for kind in [MaskKind::PartialShowLast(4), MaskKind::PartialShowFirst(2)] {
            let expr = kind.to_expr("email");
            expr.apply(|e| {
                if let Expr::BinaryExpr(BinaryExpr { left, op, right }) = e {
                    let lt = left.get_type(&df_schema).unwrap();
                    let rt = right.get_type(&df_schema).unwrap();
                    assert_eq!(
                        lt, rt,
                        "uncoerced `{op}` ({lt} vs {rt}) in {kind:?} — mask exprs \
                         run after the TypeCoercion analyzer and must be \
                         type-correct by construction"
                    );
                }
                Ok(TreeNodeRecursion::Continue)
            })
            .unwrap();
        }
    }

    #[tokio::test]
    async fn show_first_n_masks_suffix() {
        let m = MaskKind::PartialShowFirst(2);
        assert_eq!(mask_one(&m, "abcdef").await.as_deref(), Some("abXXXX"));
    }

    /// Apply `kind` to a single-row `email` column holding NULL, and
    /// return whether the masked output is NULL. Governance masks must
    /// preserve NULL, never emit a placeholder that could be mistaken
    /// for real (or masked-real) data.
    async fn mask_null(kind: &MaskKind) -> bool {
        let batch = RecordBatch::try_from_iter(vec![(
            "email",
            Arc::new(StringArray::from(vec![Option::<&str>::None])) as ArrayRef,
        )])
        .unwrap();
        let ctx = SessionContext::new();
        let df = ctx
            .read_batch(batch)
            .unwrap()
            .select(vec![kind.to_expr("email").alias("m")])
            .unwrap();
        let batches = df.collect().await.unwrap();
        let arr = datafusion::arrow::compute::cast(batches[0].column(0), &DataType::Utf8).unwrap();
        arr.as_any()
            .downcast_ref::<StringArray>()
            .expect("Utf8")
            .is_null(0)
    }

    /// ** regression pin.** A value not longer than the keep
    /// count must be masked in FULL — the pre-fix code returned the
    /// whole value in cleartext (`right("abc", 4)` = `"abc"`), a PII
    /// leak in the headline governance feature.
    #[tokio::test]
    async fn show_last_short_value_is_fully_masked_not_leaked() {
        for (keep, val, expected) in [
            (4, "abc", "XXX"),   // strictly shorter than keep
            (4, "abcd", "XXXX"), // exactly keep — still no hidden prefix
            (4, "ab", "XX"),
            (10, "abcdef", "XXXXXX"),
        ] {
            let out = mask_one(&MaskKind::PartialShowLast(keep), val).await;
            assert_eq!(
                out.as_deref(),
                Some(expected),
                "show_last({keep}) on {val:?} must fully mask, got {out:?}"
            );
            assert!(
                !out.as_deref().unwrap().contains(val) || val.chars().all(|c| c == 'X'),
                "leaked the source value {val:?}: {out:?}"
            );
        }
    }

    /// Mirror of the above for `PartialShowFirst`.
    #[tokio::test]
    async fn show_first_short_value_is_fully_masked_not_leaked() {
        for (keep, val, expected) in [
            (10, "abcdef", "XXXXXX"),
            (4, "abc", "XXX"),
            (4, "abcd", "XXXX"),
        ] {
            let out = mask_one(&MaskKind::PartialShowFirst(keep), val).await;
            assert_eq!(
                out.as_deref(),
                Some(expected),
                "show_first({keep}) on {val:?} must fully mask, got {out:?}"
            );
        }
    }

    /// `keep = 0` is the "mask everything" boundary for both partials.
    #[tokio::test]
    async fn show_partial_keep_zero_masks_everything() {
        assert_eq!(
            mask_one(&MaskKind::PartialShowLast(0), "abcd")
                .await
                .as_deref(),
            Some("XXXX")
        );
        assert_eq!(
            mask_one(&MaskKind::PartialShowFirst(0), "abcd")
                .await
                .as_deref(),
            Some("XXXX")
        );
    }

    /// Empty string through every mask kind: no panic, no leak, sane output.
    #[tokio::test]
    async fn empty_string_masks_cleanly() {
        assert_eq!(
            mask_one(&MaskKind::PartialShowLast(4), "").await.as_deref(),
            Some("")
        );
        assert_eq!(
            mask_one(&MaskKind::PartialShowFirst(4), "")
                .await
                .as_deref(),
            Some("")
        );
        assert_eq!(mask_one(&MaskKind::Redact, "").await.as_deref(), Some(""));
        // md5("") is the well-known constant — a stable, non-empty hash.
        assert_eq!(
            mask_one(&MaskKind::Hash, "").await.as_deref(),
            Some("d41d8cd98f00b204e9800998ecf8427e")
        );
    }

    /// Multi-byte unicode: `character_length` / `left` / `right` are
    /// CHAR-based, so `show_last(2)` keeps 2 code points, never splits
    /// one. A regression to byte-indexing would corrupt or panic here.
    #[tokio::test]
    async fn show_partial_counts_chars_not_bytes() {
        // "héllo" — 5 chars, 6 bytes (é is 2 bytes).
        assert_eq!(
            mask_one(&MaskKind::PartialShowLast(2), "héllo")
                .await
                .as_deref(),
            Some("XXXlo")
        );
        assert_eq!(
            mask_one(&MaskKind::PartialShowFirst(2), "héllo")
                .await
                .as_deref(),
            Some("héXXX")
        );
        // A value shorter (in chars) than keep, but multi-byte: must
        // still fully mask, not leak ( + unicode).
        assert_eq!(
            mask_one(&MaskKind::PartialShowLast(4), "café")
                .await
                .as_deref(),
            Some("XXXX")
        );
    }

    /// Every string mask kind must preserve NULL rather than emit a
    /// placeholder (a masked-NULL that looked like data would corrupt
    /// downstream governance reporting).
    #[tokio::test]
    async fn masks_preserve_null_input() {
        for kind in [
            MaskKind::Redact,
            MaskKind::Hash,
            MaskKind::PartialShowLast(4),
            MaskKind::PartialShowFirst(4),
            MaskKind::Nullify,
        ] {
            assert!(
                mask_null(&kind).await,
                "{kind:?} must return NULL for NULL input"
            );
        }
    }
}

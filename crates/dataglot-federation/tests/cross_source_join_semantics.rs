//! Non-gated characterization tests for the cross-source JOIN correctness
//! invariant ( test-coverage follow-up).
//!
//! The full cross-source suite (`cross_source_joins.rs`) joins a real
//! Postgres source with a real MySQL source and is necessarily
//! `#[ignore = "requires Docker"]`. That leaves the *correctness invariant*
//! it exists to pin — join-key **type coercion across sources** (a Postgres
//! `INT`/Arrow `Int32` key matching a MySQL `BIGINT`/Arrow `Int64` key) and
//! **NULL join semantics** — running only under Docker, never in the default
//! `cargo test` pass.
//!
//! These tests close that gap by exercising the same Arrow-level contract
//! with two in-memory providers of *different* key types. They are
//! characterization tests of the DataFusion join behaviour the federation
//! path relies on: a regression in cross-type key coercion or NULL-join
//! semantics on a DataFusion bump trips here, in default CI, without Docker.
//! (They do not exercise the SQL-unparser pushdown path — that stays covered
//! by the Docker suite; per-connector type mapping is unit-tested in each
//! connector module.)

use std::sync::Arc;

use datafusion::arrow::array::{
    Array, Decimal128Array, Int32Array, Int64Array, LargeStringArray, RecordBatch, StringArray,
};
use datafusion::arrow::datatypes::{DataType, Field, Schema};
use datafusion::datasource::MemTable;
use datafusion::prelude::SessionContext;

/// "users" source: `id` is Arrow `Int32` (a Postgres `INT` shape), nullable,
/// with one NULL-keyed row. Mirrors the left side of the cross-source join.
fn users() -> Arc<MemTable> {
    let schema = Arc::new(Schema::new(vec![
        Field::new("id", DataType::Int32, true),
        Field::new("name", DataType::Utf8, false),
    ]));
    let batch = RecordBatch::try_new(
        schema.clone(),
        vec![
            Arc::new(Int32Array::from(vec![Some(1), Some(2), None])),
            Arc::new(StringArray::from(vec!["alice", "bob", "nokey"])),
        ],
    )
    .unwrap();
    Arc::new(MemTable::try_new(schema, vec![vec![batch]]).unwrap())
}

/// "orders" source: `user_id` is Arrow `Int64` (a MySQL `BIGINT` shape) — a
/// *different* integer width from `users.id`, so the join must coerce.
fn orders() -> Arc<MemTable> {
    let schema = Arc::new(Schema::new(vec![
        Field::new("user_id", DataType::Int64, false),
        Field::new("total", DataType::Int64, false),
    ]));
    let batch = RecordBatch::try_new(
        schema.clone(),
        vec![
            // user 1 has two orders, user 2 has one, user 3 has none in `users`.
            Arc::new(Int64Array::from(vec![1_i64, 1, 2, 3])),
            Arc::new(Int64Array::from(vec![10_i64, 20, 30, 40])),
        ],
    )
    .unwrap();
    Arc::new(MemTable::try_new(schema, vec![vec![batch]]).unwrap())
}

fn ctx() -> SessionContext {
    let ctx = SessionContext::new();
    ctx.register_table("users", users()).unwrap();
    ctx.register_table("orders", orders()).unwrap();
    ctx
}

async fn run(ctx: &SessionContext, sql: &str) -> Vec<RecordBatch> {
    ctx.sql(sql).await.unwrap().collect().await.unwrap()
}

fn total_rows(batches: &[RecordBatch]) -> usize {
    batches.iter().map(RecordBatch::num_rows).sum()
}

#[tokio::test]
async fn inner_join_coerces_int32_and_int64_keys_and_drops_null_key() {
    let ctx = ctx();
    // INT (Int32) `users.id` = BIGINT (Int64) `orders.user_id` — the planner
    // must coerce the two widths to a common type to match at all.
    let batches = run(
        &ctx,
        "SELECT u.name, o.total FROM users u \
         JOIN orders o ON u.id = o.user_id ORDER BY o.total",
    )
    .await;
    // alice(1)×2 + bob(2)×1 = 3 rows. If coercion failed → 0 rows.
    // The NULL-keyed 'nokey' row and the orphan order (user_id=3) never match.
    assert_eq!(
        total_rows(&batches),
        3,
        "Int32↔Int64 key coercion joined rows"
    );
    let names = batches[0]
        .column(0)
        .as_any()
        .downcast_ref::<StringArray>()
        .unwrap();
    let joined: Vec<&str> = (0..names.len()).map(|i| names.value(i)).collect();
    assert!(!joined.contains(&"nokey"), "NULL join key must not match");
    assert!(joined.contains(&"alice") && joined.contains(&"bob"));
}

#[tokio::test]
async fn left_join_preserves_null_key_row_with_null_total() {
    let ctx = ctx();
    // LEFT JOIN: the NULL-keyed 'nokey' user is preserved with a NULL total
    // (NULL never equals anything, incl. another NULL) — the standard
    // three-valued-logic semantics the cross-source suite relies on.
    let batches = run(
        &ctx,
        "SELECT u.name, o.total FROM users u \
         LEFT JOIN orders o ON u.id = o.user_id \
         WHERE o.total IS NULL",
    )
    .await;
    let names = batches[0]
        .column(0)
        .as_any()
        .downcast_ref::<StringArray>()
        .unwrap();
    let unmatched: Vec<&str> = (0..names.len()).map(|i| names.value(i)).collect();
    assert_eq!(
        unmatched,
        vec!["nokey"],
        "NULL-key row kept with NULL total"
    );
}

/// Cross-source join keys are frequently the *same* logical type carried in
/// different Arrow widths. Pin two more coercion shapes beyond Int32↔Int64,
/// since a DataFusion type-coercion regression would silently drop all matches
/// (0 rows) rather than error.
#[tokio::test]
async fn inner_join_coerces_utf8_and_large_utf8_string_keys() {
    // accounts.code is Utf8 (one source's VARCHAR); ledger.acct is LargeUtf8
    // (another source's TEXT/CLOB shape). The join must coerce to match.
    let ctx = SessionContext::new();

    let accounts_schema = Arc::new(Schema::new(vec![Field::new("code", DataType::Utf8, false)]));
    let accounts = RecordBatch::try_new(
        Arc::clone(&accounts_schema),
        vec![Arc::new(StringArray::from(vec!["A1", "B2"]))],
    )
    .unwrap();
    ctx.register_table(
        "accounts",
        Arc::new(MemTable::try_new(accounts_schema, vec![vec![accounts]]).unwrap()),
    )
    .unwrap();

    let ledger_schema = Arc::new(Schema::new(vec![Field::new(
        "acct",
        DataType::LargeUtf8,
        false,
    )]));
    let ledger = RecordBatch::try_new(
        Arc::clone(&ledger_schema),
        vec![Arc::new(LargeStringArray::from(vec!["A1", "A1", "B2"]))],
    )
    .unwrap();
    ctx.register_table(
        "ledger",
        Arc::new(MemTable::try_new(ledger_schema, vec![vec![ledger]]).unwrap()),
    )
    .unwrap();

    let batches = run(
        &ctx,
        "SELECT a.code FROM accounts a JOIN ledger l ON a.code = l.acct",
    )
    .await;
    assert_eq!(
        total_rows(&batches),
        3,
        "Utf8↔LargeUtf8 key coercion joined rows (A1×2 + B2×1)"
    );
}

#[tokio::test]
async fn inner_join_coerces_differing_decimal_widths() {
    // A NUMERIC(10,2) key from one source joined to a NUMERIC(20,4) key from
    // another: same value, different Arrow Decimal128 precision/scale. The
    // planner must coerce to a common decimal type to match.
    let ctx = SessionContext::new();

    let left_schema = Arc::new(Schema::new(vec![Field::new(
        "amt",
        DataType::Decimal128(10, 2),
        false,
    )]));
    // 100.00 and 250.00 at scale 2 → raw 10000, 25000.
    let left_amt = Decimal128Array::from(vec![10_000_i128, 25_000])
        .with_precision_and_scale(10, 2)
        .unwrap();
    let left = RecordBatch::try_new(Arc::clone(&left_schema), vec![Arc::new(left_amt)]).unwrap();
    ctx.register_table(
        "invoices",
        Arc::new(MemTable::try_new(left_schema, vec![vec![left]]).unwrap()),
    )
    .unwrap();

    let right_schema = Arc::new(Schema::new(vec![Field::new(
        "amt",
        DataType::Decimal128(20, 4),
        false,
    )]));
    // 100.0000 and 100.0000 at scale 4 → raw 1_000_000 (matches 100.00 above).
    let right_amt = Decimal128Array::from(vec![1_000_000_i128, 1_000_000])
        .with_precision_and_scale(20, 4)
        .unwrap();
    let right = RecordBatch::try_new(Arc::clone(&right_schema), vec![Arc::new(right_amt)]).unwrap();
    ctx.register_table(
        "payments",
        Arc::new(MemTable::try_new(right_schema, vec![vec![right]]).unwrap()),
    )
    .unwrap();

    let batches = run(
        &ctx,
        "SELECT i.amt FROM invoices i JOIN payments p ON i.amt = p.amt",
    )
    .await;
    assert_eq!(
        total_rows(&batches),
        2,
        "Decimal128(10,2)↔Decimal128(20,4) coercion matched 100.00 twice"
    );
}

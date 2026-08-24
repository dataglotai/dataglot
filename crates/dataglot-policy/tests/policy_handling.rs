//! End-to-end policy-handling integration tests.
//!
//! The per-enforcer unit tests (in `src/`) check each rule in isolation.
//! These tests exercise the **composed** stack the server actually runs:
//! `AccessDenyEnforcer` + `ColumnMaskingEnforcer` + `RowFilterEnforcer`
//! wrapped in a [`CompositeEnforcer`], driven through the real
//! [`PolicyOptimizerRule`] under a session [`Identity`], with the
//! resulting plan **executed** so we assert on actual rows / errors —
//! not just that the plan was rewritten.
//!
//! Scenarios mirror Apache Ranger parity: column masking, row filtering,
//! table- and column-level access denial, and group-scoped enforcement
//! (the shape roles resolve into at the server layer).

use std::sync::Arc;

use datafusion::arrow::array::{ArrayRef, Int32Array, RecordBatch, StringArray};
use datafusion::arrow::datatypes::{DataType, Field, Schema};
use datafusion::arrow::util::display::array_value_to_string;
use datafusion::datasource::MemTable;
use datafusion::error::DataFusionError;
use datafusion::logical_expr::{col, lit};
use datafusion::optimizer::{OptimizerContext, OptimizerRule};
use datafusion::prelude::SessionContext;
use datafusion::sql::TableReference;

use dataglot_policy::{
    AccessDenial, AccessDenyEnforcer, ColumnMask, ColumnMaskingEnforcer, CompositeEnforcer,
    Identity, PolicyAction, PolicyEnforcer, PolicyOptimizerRule, RowFilter, RowFilterEnforcer,
};

/// `users(id, email, dept)` + an empty `secrets(token)` table.
fn ctx() -> SessionContext {
    let ctx = SessionContext::new();

    let users_schema = Arc::new(Schema::new(vec![
        Field::new("id", DataType::Int32, false),
        Field::new("email", DataType::Utf8, false),
        Field::new("dept", DataType::Utf8, false),
    ]));
    let users = RecordBatch::try_new(
        users_schema.clone(),
        vec![
            Arc::new(Int32Array::from(vec![1, 2, 3])) as ArrayRef,
            Arc::new(StringArray::from(vec![
                "alice@x.com",
                "bob@x.com",
                "carol@x.com",
            ])) as ArrayRef,
            Arc::new(StringArray::from(vec!["eng", "sales", "eng"])) as ArrayRef,
        ],
    )
    .unwrap();
    ctx.register_table(
        "users",
        Arc::new(MemTable::try_new(users_schema, vec![vec![users]]).unwrap()),
    )
    .unwrap();

    let secrets_schema = Arc::new(Schema::new(vec![Field::new(
        "token",
        DataType::Utf8,
        false,
    )]));
    ctx.register_table(
        "secrets",
        Arc::new(MemTable::try_new(secrets_schema, vec![vec![]]).unwrap()),
    )
    .unwrap();

    // A table with no policy configured (for the explain-empty case).
    let events_schema = Arc::new(Schema::new(vec![Field::new("note", DataType::Utf8, false)]));
    ctx.register_table(
        "events",
        Arc::new(MemTable::try_new(events_schema, vec![vec![]]).unwrap()),
    )
    .unwrap();

    ctx
}

/// The composed policy the server runs: deny-first, then mask, then filter.
/// - mask `users.email` -> `***`
/// - row-filter `users` to `dept = 'eng'`
/// - deny table `secrets` (everyone)
/// - deny column `users.dept` for group `contractor`
fn enforcer() -> Arc<dyn PolicyEnforcer> {
    let masks = ColumnMaskingEnforcer::new([ColumnMask {
        table: TableReference::bare("users"),
        column: "email".into(),
        mask: lit("***"),
        org: None,
        groups: None,
    }])
    .unwrap();

    let filters = RowFilterEnforcer::new([RowFilter {
        table: TableReference::bare("users"),
        predicate: col("dept").eq(lit("eng")),
        org: None,
        groups: None,
    }])
    .unwrap();

    let denials = AccessDenyEnforcer::new([
        AccessDenial {
            table: TableReference::bare("secrets"),
            column: None,
            groups: vec![],
        },
        AccessDenial {
            table: TableReference::bare("users"),
            column: Some("dept".into()),
            groups: vec!["contractor".into()],
        },
    ]);

    Arc::new(CompositeEnforcer::new(vec![
        Arc::new(denials),
        Arc::new(masks),
        Arc::new(filters),
    ]))
}

/// Plan `sql`, apply the composed enforcer under `identity` via the real
/// optimizer rule, then execute — returning rows as strings, or the
/// policy error (a denial).
async fn run(
    ctx: &SessionContext,
    identity: Identity,
    sql: &str,
) -> Result<Vec<Vec<String>>, DataFusionError> {
    run_with(ctx, enforcer(), identity, sql).await
}

/// Like [`run`] but with an explicit enforcer — used by scenarios that need a
/// bespoke policy set (e.g. complementary org-scoped row filters).
async fn run_with(
    ctx: &SessionContext,
    enforcer: Arc<dyn PolicyEnforcer>,
    identity: Identity,
    sql: &str,
) -> Result<Vec<Vec<String>>, DataFusionError> {
    let plan = ctx.sql(sql).await?.into_unoptimized_plan();
    let rule = PolicyOptimizerRule::with_identity(enforcer, identity);
    let rewritten = rule.rewrite(plan, &OptimizerContext::new())?.data;
    let batches = ctx.execute_logical_plan(rewritten).await?.collect().await?;

    let mut rows = Vec::new();
    for b in &batches {
        for r in 0..b.num_rows() {
            let row = (0..b.num_columns())
                .map(|c| array_value_to_string(b.column(c), r).unwrap())
                .collect();
            rows.push(row);
        }
    }
    Ok(rows)
}

fn analyst() -> Identity {
    Identity::user("alice").with_groups(["analyst"])
}
fn contractor() -> Identity {
    Identity::user("carol").with_groups(["contractor"])
}

#[tokio::test]
async fn masking_applies_for_every_identity() {
    let ctx = ctx();
    let rows = run(&ctx, analyst(), "SELECT email FROM users WHERE id = 1")
        .await
        .unwrap();
    assert_eq!(rows, vec![vec!["***".to_string()]]);
}

#[tokio::test]
async fn row_filter_keeps_only_matching_rows() {
    let ctx = ctx();
    // dept='eng' keeps ids 1 and 3, drops 2 (sales).
    let rows = run(&ctx, analyst(), "SELECT id FROM users ORDER BY id")
        .await
        .unwrap();
    let ids: Vec<&str> = rows.iter().map(|r| r[0].as_str()).collect();
    assert_eq!(ids, vec!["1", "3"]);
}

#[tokio::test]
async fn mask_and_filter_compose() {
    let ctx = ctx();
    // both policies fire: only eng rows survive, and each email is masked.
    let rows = run(&ctx, analyst(), "SELECT email FROM users ORDER BY id")
        .await
        .unwrap();
    assert_eq!(rows, vec![vec!["***".to_string()], vec!["***".to_string()]]);
}

#[tokio::test]
async fn table_level_denial_rejects_query() {
    let ctx = ctx();
    let err = run(&ctx, analyst(), "SELECT token FROM secrets")
        .await
        .unwrap_err();
    assert!(err.to_string().contains("permission denied"), "{err}");
}

#[tokio::test]
async fn column_denial_is_group_scoped() {
    let ctx = ctx();

    // analyst is NOT in `contractor` → may read dept.
    let rows = run(&ctx, analyst(), "SELECT dept FROM users WHERE id = 1")
        .await
        .unwrap();
    assert_eq!(rows, vec![vec!["eng".to_string()]]);

    // contractor IS denied the dept column.
    let err = run(&ctx, contractor(), "SELECT dept FROM users")
        .await
        .unwrap_err();
    assert!(err.to_string().contains("permission denied"), "{err}");
}

#[tokio::test]
async fn denial_does_not_block_unrelated_columns() {
    let ctx = ctx();
    // contractor denied `dept`, but `email` (masked) is still readable.
    let rows = run(&ctx, contractor(), "SELECT email FROM users WHERE id = 1")
        .await
        .unwrap();
    assert_eq!(rows, vec![vec!["***".to_string()]]);
}

#[tokio::test]
async fn explain_reports_decisions_per_identity() {
    let ctx = ctx();
    let plan = ctx
        .sql("SELECT email, dept FROM users")
        .await
        .unwrap()
        .into_unoptimized_plan();

    let has = |ds: &[dataglot_policy::PolicyDecision], a: &PolicyAction, res: &str| {
        ds.iter().any(|d| &d.action == a && d.resource == res)
    };

    // contractor: email masked, users row-filtered, dept denied.
    let c = enforcer().explain(&plan, &contractor());
    assert!(has(&c, &PolicyAction::Mask, "users.email"), "{c:?}");
    assert!(has(&c, &PolicyAction::RowFilter, "users"), "{c:?}");
    assert!(has(&c, &PolicyAction::Deny, "users.dept"), "{c:?}");

    // analyst: same mask + filter, but NOT denied dept (group-scoped).
    let a = enforcer().explain(&plan, &analyst());
    assert!(has(&a, &PolicyAction::Mask, "users.email"), "{a:?}");
    assert!(has(&a, &PolicyAction::RowFilter, "users"), "{a:?}");
    assert!(
        !has(&a, &PolicyAction::Deny, "users.dept"),
        "analyst is not in the denied group: {a:?}"
    );
}

#[tokio::test]
async fn explain_is_empty_when_no_policy_applies() {
    let ctx = ctx();
    // `events` has no mask / filter / denial configured.
    let plan = ctx
        .sql("SELECT note FROM events")
        .await
        .unwrap()
        .into_unoptimized_plan();
    let decisions = enforcer().explain(&plan, &analyst());
    assert!(
        decisions.is_empty(),
        "no policy targets this query: {decisions:?}"
    );
}

/// Mask-in-predicate **option A** (adapted from Trino TestColumnMask): a
/// predicate on a masked column matches the row by its **real** value, while
/// the output projection is masked. The mask is applied only to the projection,
/// never to the `WHERE` — so filtering by the true email finds alice's row and
/// the returned email is `***`. (If the mask leaked into the predicate,
/// `'***' = 'alice@x.com'` would match nothing and the result would be empty.)
#[tokio::test]
async fn mask_matches_real_value_in_predicate_but_masks_projection() {
    let ctx = ctx();
    let rows = run(
        &ctx,
        analyst(),
        "SELECT email FROM users WHERE email = 'alice@x.com'",
    )
    .await
    .unwrap();
    assert_eq!(
        rows,
        vec![vec!["***".to_string()]],
        "predicate matched the real value; projection is masked (option A)"
    );
}

/// Group-scoped complementary row filters (adapted from PostgreSQL
/// rowsecurity.sql `TO group1 USING(even)` / `TO group2 USING(odd)`). Dataglot
/// row filters isolate by **org** rather than group, so the scenario is ported
/// onto the org dimension: an `evens` org sees only even ids, an `odds` org
/// only odd ids, and neither sees the other's rows. `users` has ids 1,2,3.
#[tokio::test]
async fn complementary_org_scoped_row_filters_isolate() {
    let ctx = ctx();
    let filters = RowFilterEnforcer::new([
        RowFilter {
            table: TableReference::bare("users"),
            predicate: (col("id") % lit(2_i32)).eq(lit(0_i32)),
            org: Some("evens".to_string()),
            groups: None,
        },
        RowFilter {
            table: TableReference::bare("users"),
            predicate: (col("id") % lit(2_i32)).eq(lit(1_i32)),
            org: Some("odds".to_string()),
            groups: None,
        },
    ])
    .unwrap();
    let enforcer: Arc<dyn PolicyEnforcer> = Arc::new(filters);

    // evens org → only id=2.
    let evens = Identity::user("e").with_org("evens");
    let rows = run_with(
        &ctx,
        Arc::clone(&enforcer),
        evens,
        "SELECT id FROM users ORDER BY id",
    )
    .await
    .unwrap();
    let ids: Vec<&str> = rows.iter().map(|r| r[0].as_str()).collect();
    assert_eq!(ids, vec!["2"], "evens org sees only even ids");

    // odds org → only ids 1 and 3, cross-org isolated.
    let odds = Identity::user("o").with_org("odds");
    let rows = run_with(
        &ctx,
        Arc::clone(&enforcer),
        odds,
        "SELECT id FROM users ORDER BY id",
    )
    .await
    .unwrap();
    let ids: Vec<&str> = rows.iter().map(|r| r[0].as_str()).collect();
    assert_eq!(ids, vec!["1", "3"], "odds org sees only odd ids");
}

#[tokio::test]
async fn anonymous_identity_still_gets_masking_and_filtering() {
    let ctx = ctx();
    // Unconditional (group-less) policies apply even to anonymous sessions.
    let rows = run(&ctx, Identity::anonymous(), "SELECT email FROM users")
        .await
        .unwrap();
    assert_eq!(rows.len(), 2, "row filter still applies");
    assert!(rows.iter().all(|r| r[0] == "***"), "mask still applies");
}

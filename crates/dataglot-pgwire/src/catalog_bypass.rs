//! Catalog-metadata bypass for the extended-query path.
//!
//! # Why this exists
//!
//! `SELECT … FROM information_schema.tables` (and its siblings —
//! `.columns`, `.schemata`, and the `pg_catalog.*` views from
//! `datafusion-pg-catalog`) hangs indefinitely when issued over the
//! extended-query protocol (`Parse` / `Bind` / `Describe` / `Execute`)
//! against a federated `SessionContext`. The same SQL completes
//! immediately via the simple-query protocol.
//!
//! The hang is structural: it surfaces when
//! `datafusion_federation::FederationOptimizerRule` runs against a
//! plan whose `TableScan` is `InformationSchemaTables`, an upstream
//! `StreamingTable` whose `execute()` enumerates **every** registered
//! catalog and calls `schema.table_type(&t).await` per table. Federated
//! catalogs (Postgres / Iceberg) issue remote I/O from those calls,
//! and the runtime contention against the prepared-statement execution
//! task is what locks the future. The simple-query path runs the
//! optimizer + execution in a different order and never enters the
//! same wait.
//!
//! # What this module does
//!
//! Inspects the [`LogicalPlan`] carried in the extended-query portal
//! (`pgwire::api::portal::Portal::statement`) for any `TableScan` whose
//! `TableReference::schema()` matches a known catalog-metadata schema.
//! When [`plan_references_catalog_metadata`] returns `true`, the
//! pgwire handler bypasses
//! `datafusion_postgres::DfSessionService`'s
//! `ExtendedQueryHandler::do_query` and routes the call through the
//! sibling `SimpleQueryHandler::do_query` instead.
//!
//! Detection is **plan-based**, not SQL-string-based: a user-registered
//! table literally named `information_schema_logs` or `pg_catalog_dump`
//! resolves to a `TableScan` with a *different* schema and does NOT
//! trigger the bypass. The trade-off vs a substring check is the
//! ~unmeasurable cost of one extra tree walk per extended-query
//! execution; the upside is zero false-positives by construction.
//!
//! # Scope of the bypass
//!
//! Only applies when the upstream `Execute` message carried
//! `max_rows == 0` (no pagination — the standard shape for every psql
//! / JDBC introspection query). When a client sets `max_rows > 0`, we
//! cannot honour it through the simple-query path and fall back to
//! the original extended-query handler. This is acceptable in
//! practice: paginated metadata queries are rare, and the original
//! hang only affects clients running these queries without pagination
//! (psql `\d`, asyncpg's introspection, etc.).
//!
//! # Removal path
//!
//! When the upstream interaction between `datafusion-federation` and
//! `information_schema` is fixed, delete this module and remove the
//! bypass branch in `ObservingExtendedHandler::do_query`
//! ([`crate::handler`]). The unit tests below pin the detection
//! contract so a removal that accidentally drops coverage surfaces as
//! a test failure.

use datafusion::common::tree_node::{TreeNode, TreeNodeRecursion};
use datafusion::logical_expr::LogicalPlan;

/// Schemas whose `TableScan` should trigger the simple-query bypass.
///
/// `information_schema` is the SQL-standard catalog-metadata schema
/// DataFusion exposes via `with_information_schema(true)`. `pg_catalog`
/// is the Postgres-compatibility surface from `datafusion-pg-catalog`
/// (the `pg_class`, `pg_namespace`, `pg_settings`, etc. tables every
/// psql client queries during connect), registered against every
/// session by `dataglot_core::SessionContextFactory`.
const CATALOG_METADATA_SCHEMAS: &[&str] = &["information_schema", "pg_catalog"];

/// Returns `true` iff the plan contains a `TableScan` against a
/// catalog-metadata schema (`information_schema` or `pg_catalog`).
///
/// Returns `false` for plans with no `TableScan`s (e.g. `SELECT 1`),
/// plans that reference only user tables, and plans that reference
/// tables whose **name** happens to contain `information_schema` or
/// `pg_catalog` as a substring (e.g. a user-registered table named
/// `information_schema_logs`).
///
/// The walk is single-pass and stops on the first match
/// (`TreeNodeRecursion::Stop`).
#[must_use]
pub fn plan_references_catalog_metadata(plan: &LogicalPlan) -> bool {
    let mut hit = false;
    // `apply` only returns `Err` when a custom plan node's `children()`
    // impl panics. For built-in nodes (which is all we ever see in this
    // crate's wire path), it cannot fail. A `.ok()` here is safe and
    // keeps the helper infallible-by-contract.
    let _ = plan.apply(|node| {
        if let LogicalPlan::TableScan(scan) = node {
            if matches_catalog_metadata_schema(scan.table_name.schema()) {
                hit = true;
                return Ok(TreeNodeRecursion::Stop);
            }
        }
        Ok(TreeNodeRecursion::Continue)
    });
    hit
}

fn matches_catalog_metadata_schema(schema: Option<&str>) -> bool {
    matches!(schema, Some(s) if CATALOG_METADATA_SCHEMAS.contains(&s))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use datafusion::arrow::array::{Int32Array, RecordBatch};
    use datafusion::arrow::datatypes::{DataType, Field, Schema as ArrowSchema};
    use datafusion::datasource::MemTable;
    use datafusion::execution::context::SessionConfig;
    use datafusion::prelude::SessionContext;

    use super::*;

    /// Build a `SessionContext` with `information_schema` enabled and
    /// a user table registered at `public.users`. Mirrors the
    /// production session config so tests exercise the same
    /// `TableReference::schema()` shape the handler sees.
    fn ctx_with_user_table() -> SessionContext {
        let cfg = SessionConfig::new().with_information_schema(true);
        let ctx = SessionContext::new_with_config(cfg);

        let schema = Arc::new(ArrowSchema::new(vec![Field::new(
            "id",
            DataType::Int32,
            false,
        )]));
        let batch = RecordBatch::try_new(schema.clone(), vec![Arc::new(Int32Array::from(vec![1]))])
            .expect("user-table batch builds");
        let mem = MemTable::try_new(schema, vec![vec![batch]]).expect("MemTable builds");
        ctx.register_table("users", Arc::new(mem))
            .expect("register users");
        ctx
    }

    async fn plan_of(ctx: &SessionContext, sql: &str) -> LogicalPlan {
        ctx.sql(sql)
            .await
            .expect("sql parses")
            .into_optimized_plan()
            .expect("plan optimizes")
    }

    #[tokio::test]
    async fn fires_for_information_schema_tables() {
        let ctx = ctx_with_user_table();
        let plan = plan_of(&ctx, "SELECT table_name FROM information_schema.tables").await;
        assert!(plan_references_catalog_metadata(&plan));
    }

    #[tokio::test]
    async fn fires_for_information_schema_columns() {
        let ctx = ctx_with_user_table();
        let plan = plan_of(&ctx, "SELECT column_name FROM information_schema.columns").await;
        assert!(plan_references_catalog_metadata(&plan));
    }

    #[tokio::test]
    async fn does_not_fire_for_user_table() {
        let ctx = ctx_with_user_table();
        let plan = plan_of(&ctx, "SELECT id FROM users").await;
        assert!(!plan_references_catalog_metadata(&plan));
    }

    #[tokio::test]
    async fn does_not_fire_for_select_constant() {
        // No TableScan at all — bypass must not fire.
        let ctx = ctx_with_user_table();
        let plan = plan_of(&ctx, "SELECT 1").await;
        assert!(!plan_references_catalog_metadata(&plan));
    }

    #[tokio::test]
    async fn fires_when_information_schema_is_one_of_many_scans() {
        // A JOIN that touches both a user table and information_schema
        // still triggers the bypass — any catalog-metadata scan is
        // enough to risk the hang.
        let ctx = ctx_with_user_table();
        let plan = plan_of(
            &ctx,
            "SELECT u.id, t.table_name FROM users u, information_schema.tables t",
        )
        .await;
        assert!(plan_references_catalog_metadata(&plan));
    }

    #[tokio::test]
    async fn schema_substring_match_is_negative() {
        // Pin the false-positive guarantee: a TableReference whose
        // *table* name contains "information_schema" must not trigger
        // the bypass. We register a user table at `public.information_schema_logs`
        // and assert the bypass stays off.
        let cfg = SessionConfig::new().with_information_schema(true);
        let ctx = SessionContext::new_with_config(cfg);
        let schema = Arc::new(ArrowSchema::new(vec![Field::new(
            "id",
            DataType::Int32,
            false,
        )]));
        let batch = RecordBatch::try_new(schema.clone(), vec![Arc::new(Int32Array::from(vec![1]))])
            .expect("batch builds");
        let mem = MemTable::try_new(schema, vec![vec![batch]]).expect("MemTable builds");
        ctx.register_table("information_schema_logs", Arc::new(mem))
            .expect("register table");
        let plan = plan_of(&ctx, "SELECT id FROM information_schema_logs").await;
        assert!(!plan_references_catalog_metadata(&plan));
    }
}

//! Phase 2 slice 1 — Ballista localhost smoke test.
//!
//! The audit (the phase-2 `distributed-readiness-audit` plan)
//! explicitly deferred the in-process Ballista probe to this slice. The
//! deliverable is "the smallest viable Ballista cluster that proves the
//! moving parts wire up" — not the federation pushdown story, not the
//! 5× cluster benchmark. Those land in slices 4 and 8 respectively.
//!
//! # What this exercises
//!
//! ```text
//!   ┌─────────────────────────────────────────────────────────┐
//!   │  Ballista standalone (1 coord + 1 exec, in-process)      │
//!   │                                                          │
//!   │   ctx = SessionContext::standalone_with_state(...)       │
//!   │                                                          │
//!   │   1. SELECT 1 + 1            → proves the cluster boots  │
//!   │                                and dispatches a literal  │
//!   │                                                          │
//!   │   2. CSV scan + GROUP BY     → proves a registered       │
//!   │      via register_csv          (wire-serializable)       │
//!   │                                TableProvider survives    │
//!   │                                the standalone scheduler  │
//!   │                                                          │
//!   │   3. JOIN (Phase 0 shape)    → proves the exit-gate      │
//!   │      across two CSVs           query SHAPE plans + runs  │
//!   │                                on the cluster — slice 4  │
//!   │                                will reuse this query     │
//!   │                                against Postgres+iceberg  │
//!   └──────────────────────────────────────────────────────────┘
//! ```
//!
//! # Why CSV files instead of `MemTable`
//!
//! Even in standalone mode Ballista round-trips every logical plan through
//! `datafusion-proto` before dispatching to the executor. The proto layer
//! refuses any `TableProvider` that lacks a `LogicalExtensionCodec` — and
//! `MemTable`'s state is, by definition, not serializable. Trying it
//! surfaces:
//!
//! ```text
//!   failed to serialize logical plan: Context(...)
//!     NotImplemented("LogicalExtensionCodec is not provided")
//! ```
//!
//! On-disk formats (parquet, CSV, JSON) sidestep this because the worker
//! re-reads the file by URI — the path is serializable, the data is read
//! independently on each executor. This is the same constraint that
//! drives spec 01 (`FederationPlanCodec`) for federated `TableProvider`s.
//! Slice 2 picks up registering codecs for non-filesystem providers.
//!
//! # Why CSV instead of parquet
//!
//! Slice 1 wants the lightest possible seed path. Parquet would pull
//! the `parquet` crate as a dev-dep and a few hundred lines of writer
//! boilerplate; `std::fs::write` + `register_csv` is five lines.
//!
//! # Why `MemTable` in `phase0_gate.rs` doesn't have this problem
//!
//! Phase 0's gate runs everything in-process through a plain
//! `SessionContext::new()` — no Ballista, no `datafusion-proto`
//! round-trip. The federation-analyzer rewrites the plan but the
//! resulting physical plan executes in-place. Ballista forces the
//! serialization boundary unconditionally.
//!
//! # Hard-rule notes
//!
//! * Rule 1 — query results collected as `Vec<RecordBatch>`; no row-mode
//!   conversion on the read path.
//! * Rule 5 — this crate is new; the slice does not edit any other crate.
//! * Rule 10 — every async path in the smoke test is `async fn` /
//!   `#[tokio::test]`.

use std::fs;

use ballista::datafusion::arrow::array::RecordBatch;
use ballista::datafusion::arrow::util::pretty::pretty_format_batches;
use ballista::datafusion::prelude::{CsvReadOptions, SessionContext};
use dataglot_ballista::BallistaContextFactory;
use dataglot_core::SessionConfig;
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// Cluster boot helper
// ---------------------------------------------------------------------------

/// Boot a 1-scheduler + 1-executor Ballista cluster in-process via
/// the `BallistaContextFactory` (Phase 2 slice 2). Single-node code
/// paths use `dataglot_core::SessionContextFactory`; this is the
/// sibling factory that produces a Ballista-backed `SessionContext`
/// from the same `SessionConfig` shape.
async fn build_ballista_ctx() -> SessionContext {
    BallistaContextFactory::new(SessionConfig::new())
        .with_standalone_parallelism(2)
        .create_standalone_context()
        .await
        .expect("ballista standalone boots")
}

// ---------------------------------------------------------------------------
// CSV seed — same five rows the Phase 0 exit-gate uses
// ---------------------------------------------------------------------------

/// Seed a tempdir with `customers.csv` (five rows, three EU + two US) and
/// `orders.csv` (matching ids, amounts chosen so the EU-filtered join is
/// exactly `{(1, 100), (2, 200), (4, 300)}`). The Phase 0 gate seeds the
/// identical rows in Postgres + warehouse — keeping them identical here
/// is what lets slice 4 swap CSV for Postgres+iceberg and assert the same
/// fingerprint without touching the query string.
fn seed_csvs() -> TempDir {
    let dir = TempDir::new().expect("seed tempdir");
    fs::write(
        dir.path().join("customers.csv"),
        "id,region,name\n1,EU,Alice\n2,EU,Bob\n3,US,Carol\n4,EU,Dave\n5,US,Eve\n",
    )
    .expect("write customers.csv");
    fs::write(
        dir.path().join("orders.csv"),
        "id,amount\n1,100\n2,200\n3,50\n4,300\n5,75\n",
    )
    .expect("write orders.csv");
    dir
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Bare-minimum: a `SELECT 1 + 1` round-trip through the cluster. If this
/// passes, the standalone scheduler is up, the in-process executor is
/// registered, and the basic dispatch loop works.
#[tokio::test]
async fn smoke_select_literal() {
    let ctx = build_ballista_ctx().await;
    let batches = ctx
        .sql("SELECT 1 + 1 AS two")
        .await
        .expect("plan SELECT 1 + 1")
        .collect()
        .await
        .expect("execute SELECT 1 + 1");
    let printed = pretty_format_batches(&batches).expect("format").to_string();
    assert_eq!(
        batches.iter().map(RecordBatch::num_rows).sum::<usize>(),
        1,
        "expected one row, got:\n{printed}"
    );
    assert!(
        printed.contains('2'),
        "expected the literal `2` in the result, got:\n{printed}"
    );
}

/// CSV scan + GROUP BY — proves a registered filesystem-backed
/// `TableProvider` survives the standalone scheduler's serialization
/// round-trip and aggregates run through the cluster.
#[tokio::test]
async fn smoke_grouped_aggregate() {
    let seed = seed_csvs();
    let ctx = build_ballista_ctx().await;
    ctx.register_csv(
        "customers",
        seed.path()
            .join("customers.csv")
            .to_str()
            .expect("utf-8 path"),
        CsvReadOptions::new().has_header(true),
    )
    .await
    .expect("register customers.csv");

    let batches = ctx
        .sql(
            "SELECT region, COUNT(*) AS n
             FROM customers
             GROUP BY region
             ORDER BY region",
        )
        .await
        .expect("plan grouped aggregate")
        .collect()
        .await
        .expect("execute grouped aggregate");
    let printed = pretty_format_batches(&batches).expect("format").to_string();

    // Two groups (EU, US) with counts 3 + 2 = 5.
    assert_eq!(
        batches.iter().map(RecordBatch::num_rows).sum::<usize>(),
        2,
        "expected 2 region groups, got:\n{printed}"
    );
    assert!(
        printed.contains("EU") && printed.contains("US"),
        "expected both regions in result:\n{printed}"
    );
    assert!(
        printed.contains('3') && printed.contains('2'),
        "expected counts 3 (EU) and 2 (US) in result:\n{printed}"
    );
}

/// The Phase 0 exit-gate query shape (JOIN + WHERE + ORDER BY), served
/// from two CSV files instead of Postgres + warehouse. Same five-row
/// seed, same expected three-row EU result. When slice 4 wires the
/// federation analyzer into the Ballista context, the query string + the
/// expected rows here can be reused verbatim — single-vs-cluster
/// fingerprint match is the slice-4 exit assertion.
#[tokio::test]
async fn smoke_phase0_query_shape() {
    let seed = seed_csvs();
    let ctx = build_ballista_ctx().await;
    ctx.register_csv(
        "customers",
        seed.path()
            .join("customers.csv")
            .to_str()
            .expect("utf-8 path"),
        CsvReadOptions::new().has_header(true),
    )
    .await
    .expect("register customers.csv");
    ctx.register_csv(
        "orders",
        seed.path().join("orders.csv").to_str().expect("utf-8 path"),
        CsvReadOptions::new().has_header(true),
    )
    .await
    .expect("register orders.csv");

    let batches = ctx
        .sql(
            "SELECT p.id, p.region, w.amount
             FROM customers p
             JOIN orders w USING (id)
             WHERE p.region = 'EU'
             ORDER BY p.id",
        )
        .await
        .expect("plan join + filter")
        .collect()
        .await
        .expect("execute join + filter");

    let total: usize = batches.iter().map(RecordBatch::num_rows).sum();
    let printed = pretty_format_batches(&batches).expect("format").to_string();

    assert_eq!(
        total, 3,
        "expected exactly 3 EU rows, got {total}:\n{printed}"
    );
    for amount in ["100", "200", "300"] {
        assert!(
            printed.contains(amount),
            "expected EU amount {amount} in result:\n{printed}"
        );
    }
    assert!(
        !printed.contains(" 50 ") && !printed.contains(" 75 "),
        "US rows leaked through the EU filter:\n{printed}"
    );
    assert_eq!(
        printed.matches("EU").count(),
        3,
        "expected exactly 3 EU markers, got:\n{printed}"
    );
}

//! Version-keyed migration runners for the two [`MetaStore`](crate::store::MetaStore)
//! backends.
//!
//! Both backends keep the `vN` on-store version scheme, but they are
//! structurally different — the embedded store is a single JSON document,
//! the Postgres store is a SQL schema — so this module gives each a **thin,
//! backend-shaped** vocabulary rather than one heavy shared trait:
//!
//! - [`EmbeddedMigration`] + [`run_embedded_migrations`] fold an ordered chain
//!   of pure `Value -> Value` document transforms, starting at the file's
//!   on-disk `version` and walking each registered step until the build's
//!   target version is reached.
//! - [`PostgresMigration`] + [`plan_postgres_migrations`] select the pending
//!   idempotent DDL steps for a database at a given recorded version; the
//!   [`CatalogService`](crate::service::CatalogService) connect path runs them
//!   in order, recording each step's target as it goes.
//!
//! Both share the same posture the pre-framework code had: a store already at
//! the target version applies nothing; an older store has its pending steps
//! applied in order; a store at a **newer / unknown** version fails fast with
//! [`CatalogServiceError::SchemaVersionMismatch`]. Adding the next schema
//! change is a matter of appending one step to the relevant chain — no more
//! hand-edited open/connect branching.

use serde_json::Value;

use crate::error::{CatalogServiceError, Result};

/// One embedded-store schema migration: rewrites the parsed on-disk JSON
/// document from version [`from`](Self::from) to version [`to`](Self::to).
///
/// The transform is a pure, total `Value -> Value` function: it never fails
/// (a shape it can't understand is left for the caller's final typed
/// deserialize to reject as a corrupt store), so the only error the runner
/// itself can raise is the newer/unknown-version fail-fast.
#[derive(Debug)]
pub(crate) struct EmbeddedMigration {
    /// On-disk version this step consumes.
    pub(crate) from: &'static str,
    /// On-disk version this step produces.
    pub(crate) to: &'static str,
    /// The document transform taking a `from`-shaped doc to a `to`-shaped doc.
    pub(crate) apply: fn(Value) -> Value,
}

/// Fold the ordered embedded-store migration `chain` over `doc`, starting at
/// `version` (the document's on-disk `version` tag) until it reaches `target`
/// (the build's current version — the last step's output).
///
/// - A document already at `target` returns unchanged (no step runs), so a
///   re-open of a freshly-written store is a cheap no-op.
/// - An older document has each pending step applied **in registration order**
///   (the chain is walked by matching each step's `from` to the running
///   version), so a `vA -> vB -> vC` upgrade composes deterministically.
/// - A document whose version has no consuming step before reaching `target`
///   — i.e. a **newer or unknown** version — fails fast with
///   [`CatalogServiceError::SchemaVersionMismatch`], preserving the embedded
///   store's original refuse-unknown-version posture exactly.
///
/// # Errors
/// [`CatalogServiceError::SchemaVersionMismatch`] when `version` is newer than,
/// or otherwise not reachable to, `target` through the chain.
pub(crate) fn run_embedded_migrations(
    chain: &[EmbeddedMigration],
    target: &str,
    mut version: String,
    mut doc: Value,
) -> Result<Value> {
    while version != target {
        let step = chain.iter().find(|m| m.from == version).ok_or_else(|| {
            CatalogServiceError::SchemaVersionMismatch {
                expected: target.to_string(),
                found: version.clone(),
            }
        })?;
        doc = (step.apply)(doc);
        version = step.to.to_string();
    }
    Ok(doc)
}

/// One Postgres-store schema migration: an idempotent DDL script that takes the
/// database up to the version it records in [`to`](Self::to).
///
/// The DDL is written to be safe to run against a database that is already at
/// (or partway through) this step — every statement is `IF NOT EXISTS` /
/// `CREATE OR REPLACE` / additive — so a partially-applied step re-runs cleanly.
#[derive(Debug)]
pub(crate) struct PostgresMigration {
    /// Schema version this step brings the database to (recorded in
    /// `schema_version` once its DDL has run).
    pub(crate) to: &'static str,
    /// Idempotent DDL that realises this step's schema.
    pub(crate) ddl: &'static str,
}

/// Select the pending Postgres migration steps for a database whose recorded
/// schema version is `current` (`None` ⇒ a fresh database, pre-baseline), given
/// the build's ordered `chain`.
///
/// Returns the contiguous tail of the chain that still needs to run, in order:
///
/// - `None` (fresh) ⇒ the whole chain.
/// - `current == target` (the last step's version) ⇒ nothing pending; the
///   connect path runs no DDL, matching the pre-framework "already current"
///   no-op.
/// - `current` is a recognised intermediate version ⇒ the steps registered
///   after it.
/// - `current` is **newer than / unknown to** this build ⇒ fail fast with
///   [`CatalogServiceError::SchemaVersionMismatch`], exactly as the original
///   `ensure_schema` version guard did.
///
/// This is a pure function so the ordering / future-fail semantics are unit
/// testable without a live database.
///
/// # Errors
/// [`CatalogServiceError::SchemaVersionMismatch`] when `current` is not a
/// version this build's chain knows how to advance from.
pub(crate) fn plan_postgres_migrations<'a>(
    current: Option<&str>,
    chain: &'a [PostgresMigration],
) -> Result<&'a [PostgresMigration]> {
    let Some(target) = chain.last().map(|m| m.to) else {
        // An empty chain has nothing to apply and nothing to fail against.
        return Ok(&[]);
    };
    match current {
        None => Ok(chain),
        Some(v) if v == target => Ok(&[]),
        Some(v) => match chain.iter().position(|m| m.to == v) {
            Some(i) => Ok(&chain[i + 1..]),
            None => Err(CatalogServiceError::SchemaVersionMismatch {
                expected: target.to_string(),
                found: v.to_string(),
            }),
        },
    }
}

/// Numeric rank of a `vN` version tag (`"v2"` ⇒ `Some(2)`), or `None` if it
/// isn't of that shape. Used to pick the highest recorded version out of the
/// `schema_version` ledger, so a multi-step history (one row per applied step)
/// resolves to the latest without relying on lexicographic ordering (which
/// breaks at `v10`).
pub(crate) fn version_rank(v: &str) -> Option<u32> {
    v.strip_prefix('v').and_then(|n| n.parse().ok())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    // ---- Embedded runner --------------------------------------------------

    /// A synthetic ≥2-step chain proves the runner composes steps in order
    /// (each step asserts its predecessor ran), is a no-op once at the target
    /// (idempotent re-open), and fails fast on a future/unknown version — none
    /// of which the single real `v1 -> v2` migration can exercise alone.
    #[test]
    fn embedded_chain_applies_in_order_is_idempotent_and_rejects_future() {
        // vA -> vB stamps "b"; vB -> vC requires "b" already present, proving
        // ordered composition (not just "both ran").
        fn a_to_b(mut d: Value) -> Value {
            d["trail"] = json!("b");
            d["version"] = json!("vB");
            d
        }
        fn b_to_c(mut d: Value) -> Value {
            assert_eq!(d["trail"], json!("b"), "vB->vC must run after vA->vB");
            d["trail"] = json!("bc");
            d["version"] = json!("vC");
            d
        }
        let chain = [
            EmbeddedMigration {
                from: "vA",
                to: "vB",
                apply: a_to_b,
            },
            EmbeddedMigration {
                from: "vB",
                to: "vC",
                apply: b_to_c,
            },
        ];

        // Full chain: vA folds through vB into vC, in order.
        let out = run_embedded_migrations(&chain, "vC", "vA".to_string(), json!({"version": "vA"}))
            .expect("chain reaches target");
        assert_eq!(out["trail"], json!("bc"));
        assert_eq!(out["version"], json!("vC"));

        // Starting mid-chain applies only the pending tail.
        let mid = run_embedded_migrations(
            &chain,
            "vC",
            "vB".to_string(),
            json!({"version": "vB", "trail": "b"}),
        )
        .expect("mid-chain reaches target");
        assert_eq!(mid["trail"], json!("bc"));

        // Idempotent: a doc already at the target is returned untouched (no
        // step runs), so re-opening a current store never re-migrates.
        let already = json!({"version": "vC", "trail": "bc"});
        let reopened =
            run_embedded_migrations(&chain, "vC", "vC".to_string(), already.clone()).unwrap();
        assert_eq!(reopened, already);

        // A future/unknown version fails fast rather than silently loading.
        let err = run_embedded_migrations(&chain, "vC", "vD".to_string(), json!({"version": "vD"}))
            .expect_err("future version must be refused");
        assert!(matches!(
            err,
            CatalogServiceError::SchemaVersionMismatch { expected, found }
                if expected == "vC" && found == "vD"
        ));
    }

    // ---- Postgres planner -------------------------------------------------

    fn synthetic_pg_chain() -> [PostgresMigration; 2] {
        [
            PostgresMigration {
                to: "v1",
                ddl: "-- baseline",
            },
            PostgresMigration {
                to: "v2",
                ddl: "-- second step",
            },
        ]
    }

    #[test]
    fn plan_postgres_fresh_db_applies_whole_chain() {
        let chain = synthetic_pg_chain();
        let pending = plan_postgres_migrations(None, &chain).expect("fresh plans");
        assert_eq!(pending.len(), 2);
        assert_eq!(pending[0].to, "v1");
        assert_eq!(pending[1].to, "v2");
    }

    #[test]
    fn plan_postgres_intermediate_applies_ordered_tail() {
        let chain = synthetic_pg_chain();
        // A DB at v1 has only the v2 step pending (ordered tail).
        let pending = plan_postgres_migrations(Some("v1"), &chain).expect("v1 plans");
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].to, "v2");
    }

    #[test]
    fn plan_postgres_at_target_is_noop() {
        let chain = synthetic_pg_chain();
        let pending = plan_postgres_migrations(Some("v2"), &chain).expect("target plans");
        assert!(pending.is_empty());
    }

    #[test]
    fn plan_postgres_newer_version_fails_fast() {
        let chain = synthetic_pg_chain();
        let err = plan_postgres_migrations(Some("v999"), &chain)
            .expect_err("newer version must be refused");
        assert!(matches!(
            err,
            CatalogServiceError::SchemaVersionMismatch { expected, found }
                if expected == "v2" && found == "v999"
        ));
    }

    #[test]
    fn plan_postgres_empty_chain_is_noop() {
        let pending = plan_postgres_migrations(None, &[]).expect("empty chain plans");
        assert!(pending.is_empty());
    }

    #[test]
    fn version_rank_parses_vn_and_orders_past_v9() {
        assert_eq!(version_rank("v0"), Some(0));
        assert_eq!(version_rank("v2"), Some(2));
        assert_eq!(version_rank("v10"), Some(10));
        // v10 outranks v2 numerically (lexicographic ordering would not).
        assert!(version_rank("v10") > version_rank("v2"));
        assert_eq!(version_rank("v999"), Some(999));
        assert_eq!(version_rank("nonsense"), None);
        assert_eq!(version_rank("v"), None);
    }
}

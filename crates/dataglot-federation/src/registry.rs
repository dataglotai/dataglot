//! Connector registry — maps stable connector-name strings to
//! `Arc<dyn SQLExecutor>` instances.
//!
//! Spec: the phase-2 `federation-codec-impl` plan
//! (internal phase-plan document).
//!
//! # Why a registry exists
//!
//! The eventual `FederationPlanCodec` (Phase 2 follow-up) serializes
//! federated physical plans across the Ballista wire format so workers
//! can execute cross-source queries instead of collapsing onto the
//! coordinator. Per the audit's Gap 2 recommendation, credentials never
//! cross the wire — workers register their own connector instances at
//! boot and look them up by *name* when decoding a serialized plan.
//!
//! This module ships the trait + a default in-memory implementation.
//! The codec impl that consumes it lands in a separate PR.
//!
//! # Lookup semantics
//!
//! [`ConnectorRegistry::lookup`] returns `Option<Arc<dyn SQLExecutor>>` —
//! `None` means "no executor registered under that name." The codec's
//! decoder surfaces this as a typed `DataFusionError::Plan` so a
//! worker booted with a missing connector fails the query cleanly
//! rather than panicking or hanging.
//!
//! # Thread safety
//!
//! The trait is `Send + Sync + 'static` (no async, sync lookup) so
//! workers can register connectors once at boot and share the
//! registry across executor threads via `Arc`.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use datafusion_federation::sql::{SQLExecutor, SQLFederationPlanner};
use datafusion_federation::FederationPlanner;

// -------- Phase 2 slice 4b.3 hotfix --------
//
// Slice 4b.1 shipped a `find_planner_name(Arc<dyn FederationPlanner>)`
// method that relied on `Arc::ptr_eq` matching the planner Arc inside
// a `FederatedPlanNode` against one our registry stored at registration
// time. The slice's unit tests passed because they round-tripped the
// SAME Arc through the registry, but the real federation construction
// path allocates a fresh `Arc<SQLFederationPlanner>` inside each
// `SQLFederationProvider::new(executor)` call. The provider's Arc is
// what ends up in `FederatedPlanNode.planner`; the registry's Arc is
// a different allocation; `ptr_eq` returns false; codec encode fails.
//
// PR #272 surfaced this on a real Postgres testcontainer run — the
// e2e test failed with:
//
//   FederationLogicalCodec: planner not registered in ConnectorRegistry
//
// The fix routes identity through `compute_context()` instead. Every
// `SQLExecutor` exposes it via the trait method; `SQLFederationProvider`
// proxies it through `FederationProvider::compute_context()` so the
// codec can pull it off the FederatedPlanNode's plan tree without
// downcasting the planner trait object.
//
// `find_name_by_compute_context(context)` is the replacement reverse-
// lookup. `find_planner_name` is left in place — it still works for
// Arcs the registry handed out — but it is NOT the path the codec
// uses anymore; the doc comment on the trait method calls this out
// so a future reader doesn't reach for it again.

/// Maps stable connector-name strings to live [`SQLExecutor`] instances.
///
/// One registry instance is typically constructed per worker process
/// at boot, populated from the same `[catalogs.*]` config block as
/// the coordinator, and held inside the worker's session state for
/// the lifetime of the process.
pub trait ConnectorRegistry: Send + Sync + 'static {
    /// Resolve `name` to a registered executor.
    ///
    /// Returns `None` if no executor was registered under `name`.
    /// Callers (notably the federation plan codec) translate `None`
    /// into a typed planner error rather than panicking.
    fn lookup(&self, name: &str) -> Option<Arc<dyn SQLExecutor>>;

    /// Resolve `name` to the registered executor's paired
    /// [`FederationPlanner`]. Phase 2 slice 4b — the
    /// `FederationLogicalCodec` decoder uses this to reconstruct
    /// the `FederatedPlanNode.planner` field after a proto
    /// round-trip across the Ballista wire.
    ///
    /// Returns `None` for the same shape as [`Self::lookup`]: the
    /// codec decoder surfaces it as a typed `DataFusionError::Plan`
    /// so a worker missing the named connector fails the query
    /// cleanly rather than panicking.
    ///
    /// **Invariant**: a registry that returns `Some(executor)` from
    /// `lookup(name)` MUST return `Some(planner)` from
    /// `lookup_planner(name)`. The default in-memory implementation
    /// guarantees this by constructing both at the same time. Custom
    /// implementations should preserve the invariant.
    fn lookup_planner(&self, name: &str) -> Option<Arc<dyn FederationPlanner>>;

    /// Reverse lookup — given the `Arc<dyn FederationPlanner>`
    /// stored in a `FederatedPlanNode`, return the connector name
    /// it was registered under.
    ///
    /// **Do not use for codec encoding.** This method matches by
    /// [`Arc::ptr_eq`], and the assumption it relies on — that
    /// `FederatedPlanNode.planner` is the same `Arc` allocation the
    /// registry stored — does not hold in production. The real
    /// federation construction path goes through
    /// `SQLFederationProvider::new(executor)`, which allocates a
    /// fresh `Arc<SQLFederationPlanner>` per provider. The codec
    /// uses [`Self::find_name_by_compute_context`] instead.
    ///
    /// Kept on the trait for backward compatibility with slice 4b.1
    /// callers and because the round-trip-the-same-Arc case (visible
    /// to the unit tests below) still works. Returns `None` for any
    /// independently-allocated planner — including all real
    /// federation analyzer output, which is why slice 4b.3 had to
    /// route encode-time identity through `compute_context()`.
    fn find_planner_name(&self, planner: &Arc<dyn FederationPlanner>) -> Option<&str>;

    /// Reverse lookup keyed on
    /// [`FederationProvider::compute_context()`](datafusion_federation::FederationProvider::compute_context).
    ///
    /// Phase 2 slice 4b.3 — the `FederationLogicalCodec` encoder uses
    /// this to recover a connector name from a `FederatedPlanNode`
    /// without depending on `Arc::ptr_eq` of the planner trait object.
    /// The codec walks the federated plan tree, finds a `TableScan`
    /// backed by a `FederatedTableProviderAdaptor`, asks the
    /// `FederationProvider` for its `compute_context()` string, then
    /// calls this method to translate that string into the registered
    /// connector name.
    ///
    /// Returns `None` when no registered executor reports the given
    /// `compute_context`. Typically that means the federation source
    /// was plumbed in by something other than the connector registry
    /// (test harness, ad-hoc registration); the codec encoder surfaces
    /// it as a typed `DataFusionError::Internal`.
    ///
    /// **Invariant:** for any registered name `n`,
    /// `find_name_by_compute_context(executor.compute_context().unwrap())
    /// == Some(n)` provided `executor.compute_context()` is `Some`.
    /// Executors that return `None` from `compute_context()` cannot
    /// be reverse-resolved through this method — the default
    /// in-memory implementation simply omits them from its lookup
    /// index. In production every Dataglot connector returns `Some`
    /// (see `PostgresConnector::compute_context`).
    fn find_name_by_compute_context(&self, context: &str) -> Option<&str>;

    /// Number of registered connectors. Useful for diagnostics
    /// (`metrics`, health checks).
    fn len(&self) -> usize;

    /// True when no connectors are registered.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Default in-memory implementation of [`ConnectorRegistry`].
///
/// Wraps two parallel `HashMap`s behind the trait:
///
/// - `executors: HashMap<String, Arc<dyn SQLExecutor>>` — the
///   original (Phase 2 slice 1) lookup-by-name map used by the
///   physical-side `FederationPlanCodec`.
/// - `planners: HashMap<String, Arc<dyn FederationPlanner>>` —
///   the Phase 2 slice 4b parallel map. Built at construction
///   time by wrapping each executor in `SQLFederationPlanner::new`
///   so that the `Arc` identity we hold here matches the one
///   federation's analyzer stuffs into every `FederatedPlanNode`
///   for that source.
///
/// The two maps share keys by construction (every executor gets a
/// planner). The "frozen after construction" shape matches the
/// Phase 1 catalog-provider cache's invariant (`build_connectors`
/// runs once at boot) and keeps lookups lock-free.
///
/// # Pointer-identity invariant
///
/// `lookup_planner(name)` and `find_planner_name(planner)` cooperate
/// as inverse functions on `Arc::ptr_eq`-identity. Specifically:
/// for every registered `name`, `find_planner_name(&lookup_planner(name).unwrap()) == Some(name)`.
/// The `pointer_identity_round_trips` test pins this contract.
pub struct InMemoryConnectorRegistry {
    executors: HashMap<String, Arc<dyn SQLExecutor>>,
    planners: HashMap<String, Arc<dyn FederationPlanner>>,
    /// `compute_context → name` index for slice 4b.3's reverse-lookup
    /// path. Populated at construction by calling
    /// `executor.compute_context()` on every registered executor and
    /// indexing the resulting `Some(...)` value. Executors that
    /// return `None` are intentionally omitted — the codec then
    /// surfaces them as "no registered connector" errors at encode
    /// time, which is the same shape we'd get from a missing name.
    ///
    /// In the (unusual) case that two executors share a
    /// `compute_context` string, a deterministic `BTreeMap` keyed
    /// resolution wins this reverse index; the forward
    /// `lookup`/`lookup_planner` maps are unaffected. We pin this
    /// behaviour in `duplicate_compute_context_last_write_wins`.
    ///
    /// `BTreeMap`, not `HashMap`: the index is read at codec encode
    /// time and the result rides the wire. `HashMap` iteration
    /// order is non-deterministic across processes (`HashDoS`-
    /// resistant seeding), so the surviving connector name for
    /// duplicate contexts would vary per run. `CodeRabbit` flagged
    /// this on PR #272.
    compute_contexts: BTreeMap<String, String>,
}

impl InMemoryConnectorRegistry {
    /// Construct from a `HashMap` of `name → executor` entries.
    /// Each executor is wrapped in `SQLFederationPlanner::new` at
    /// construction time; the resulting planner Arcs are stored
    /// alongside for slice 4b's reverse-lookup.
    ///
    /// Names are case-sensitive and should match the connector keys
    /// in the operator's `dataglot.toml` `[catalogs.*]` block so the
    /// coordinator-side encoder and worker-side decoder agree on
    /// identity.
    #[must_use]
    pub fn new(executors: HashMap<String, Arc<dyn SQLExecutor>>) -> Self {
        let planners = build_planners(&executors);
        let compute_contexts = build_compute_contexts(&executors);
        Self {
            executors,
            planners,
            compute_contexts,
        }
    }

    /// Empty registry. Useful for tests and for worker bootstraps
    /// that intend to register connectors via `from_iter` shortly
    /// after.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            executors: HashMap::new(),
            planners: HashMap::new(),
            compute_contexts: BTreeMap::new(),
        }
    }
}

/// Wrap each `SQLExecutor` in an `SQLFederationPlanner` so the
/// returned `Arc<dyn FederationPlanner>` identities are stable for
/// the lifetime of the registry. Federation's analyzer always
/// `.clone()`s the same Arc into every `FederatedPlanNode` it
/// produces for a given source, so the data-pointer matches the
/// one stored here.
fn build_planners(
    executors: &HashMap<String, Arc<dyn SQLExecutor>>,
) -> HashMap<String, Arc<dyn FederationPlanner>> {
    executors
        .iter()
        .map(|(name, executor)| {
            let planner: Arc<dyn FederationPlanner> =
                Arc::new(SQLFederationPlanner::new(Arc::clone(executor)));
            (name.clone(), planner)
        })
        .collect()
}

/// Build the slice-4b.3 `compute_context → name` reverse-lookup index.
/// Executors that return `None` from `compute_context()` are simply
/// omitted; they're invisible to codec encode-time identity matching
/// but still resolvable by name through `lookup`/`lookup_planner`.
fn build_compute_contexts(
    executors: &HashMap<String, Arc<dyn SQLExecutor>>,
) -> BTreeMap<String, String> {
    executors
        .iter()
        .filter_map(|(name, executor)| {
            executor
                .compute_context()
                .map(|context| (context, name.clone()))
        })
        .collect()
}

impl Default for InMemoryConnectorRegistry {
    fn default() -> Self {
        Self::empty()
    }
}

// Deliberate `missing_fields_in_debug` allow: per hard rule 12,
// executor / planner objects can carry references to credential
// handles and must never appear in `Debug` output. Just expose the
// registered names. The two parallel maps share keys by construction,
// so showing one is enough.
#[allow(clippy::missing_fields_in_debug)]
impl std::fmt::Debug for InMemoryConnectorRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let names: Vec<&str> = self.executors.keys().map(String::as_str).collect();
        f.debug_struct("InMemoryConnectorRegistry")
            .field("names", &names)
            .finish()
    }
}

impl ConnectorRegistry for InMemoryConnectorRegistry {
    fn lookup(&self, name: &str) -> Option<Arc<dyn SQLExecutor>> {
        self.executors.get(name).map(Arc::clone)
    }

    fn lookup_planner(&self, name: &str) -> Option<Arc<dyn FederationPlanner>> {
        self.planners.get(name).map(Arc::clone)
    }

    fn find_planner_name(&self, planner: &Arc<dyn FederationPlanner>) -> Option<&str> {
        // O(N) linear scan with Arc::ptr_eq. N ≈ number of catalogs
        // (1–10 realistically). The slice-4b.3 hotfix documents why
        // this method is *not* what the codec calls — see the
        // trait-method doc comment. Kept as a working backward-compat
        // surface for callers that did round-trip the same Arc.
        self.planners
            .iter()
            .find(|(_, stored)| Arc::ptr_eq(stored, planner))
            .map(|(name, _)| name.as_str())
    }

    fn find_name_by_compute_context(&self, context: &str) -> Option<&str> {
        self.compute_contexts.get(context).map(String::as_str)
    }

    fn len(&self) -> usize {
        self.executors.len()
    }
}

impl FromIterator<(String, Arc<dyn SQLExecutor>)> for InMemoryConnectorRegistry {
    fn from_iter<T: IntoIterator<Item = (String, Arc<dyn SQLExecutor>)>>(iter: T) -> Self {
        let executors: HashMap<String, Arc<dyn SQLExecutor>> = iter.into_iter().collect();
        let planners = build_planners(&executors);
        let compute_contexts = build_compute_contexts(&executors);
        Self {
            executors,
            planners,
            compute_contexts,
        }
    }
}

/// Alias mirroring the [`crate`]'s convention for trait-object Arcs.
pub type DynConnectorRegistry = Arc<dyn ConnectorRegistry>;

#[cfg(test)]
mod tests {
    use super::*;

    use async_trait::async_trait;
    use datafusion::arrow::datatypes::SchemaRef;
    use datafusion::error::Result as DfResult;
    use datafusion::physical_plan::{PhysicalExpr, SendableRecordBatchStream};
    use datafusion::sql::unparser::dialect::{DefaultDialect, Dialect};
    use datafusion_federation::sql::SQLExecutor;

    /// Minimal `SQLExecutor` impl that just records its name —
    /// enough to verify the registry surface without standing up a
    /// real connector.
    #[derive(Debug)]
    struct FakeExecutor {
        name: String,
        compute_context: Option<String>,
    }

    #[async_trait]
    impl SQLExecutor for FakeExecutor {
        fn name(&self) -> &str {
            &self.name
        }

        fn compute_context(&self) -> Option<String> {
            self.compute_context.clone()
        }

        fn dialect(&self) -> Arc<dyn Dialect> {
            Arc::new(DefaultDialect {})
        }

        fn execute(
            &self,
            _query: &str,
            _schema: SchemaRef,
            _filters: &[Arc<dyn PhysicalExpr>],
        ) -> DfResult<SendableRecordBatchStream> {
            unimplemented!("tests don't exercise the execute path")
        }

        async fn table_names(&self) -> DfResult<Vec<String>> {
            Ok(Vec::new())
        }

        async fn get_table_schema(&self, _table: &str) -> DfResult<SchemaRef> {
            unimplemented!("tests don't exercise schema discovery")
        }
    }

    fn fake(name: &str) -> Arc<dyn SQLExecutor> {
        // Default fake executor: reports its own name as the
        // compute_context so slice 4b.3's reverse-lookup index has
        // something to key on. Tests that need a `None`-context
        // executor use `fake_without_context` below.
        Arc::new(FakeExecutor {
            name: name.to_string(),
            compute_context: Some(format!("ctx::{name}")),
        })
    }

    fn fake_without_context(name: &str) -> Arc<dyn SQLExecutor> {
        Arc::new(FakeExecutor {
            name: name.to_string(),
            compute_context: None,
        })
    }

    #[test]
    fn empty_registry_has_zero_entries() {
        let reg = InMemoryConnectorRegistry::empty();
        assert_eq!(reg.len(), 0);
        assert!(reg.is_empty());
        assert!(reg.lookup("pg").is_none());
    }

    #[test]
    fn lookup_returns_registered_executor_by_name() {
        let mut map: HashMap<String, Arc<dyn SQLExecutor>> = HashMap::new();
        map.insert("pg_demo".to_string(), fake("pg_demo"));
        map.insert("mysql_demo".to_string(), fake("mysql_demo"));
        let reg = InMemoryConnectorRegistry::new(map);

        let pg = reg.lookup("pg_demo").expect("pg_demo registered");
        assert_eq!(pg.name(), "pg_demo");

        let my = reg.lookup("mysql_demo").expect("mysql_demo registered");
        assert_eq!(my.name(), "mysql_demo");

        assert_eq!(reg.len(), 2);
        assert!(!reg.is_empty());
    }

    #[test]
    fn lookup_unknown_name_returns_none() {
        // Per the trait contract, missing connectors surface as
        // `None` (which the codec translates to a typed planner
        // error); they never panic.
        let reg = InMemoryConnectorRegistry::from_iter([("pg".to_string(), fake("pg"))]);
        assert!(reg.lookup("snowflake").is_none());
        assert!(reg.lookup("PG").is_none(), "lookup is case-sensitive");
    }

    #[test]
    fn registry_is_send_sync_via_arc() {
        // The codec stores the registry as `Arc<dyn ConnectorRegistry>`
        // and ships it across executor threads. Pin the trait-object
        // bound at compile time.
        fn assert_send_sync<T: Send + Sync + 'static>() {}
        assert_send_sync::<Arc<dyn ConnectorRegistry>>();
    }

    #[test]
    fn debug_redacts_executor_internals() {
        // Connector executors may carry references to credential
        // handles (hard rule 12). The registry's `Debug` impl
        // must only print names, never the executor objects.
        let reg = InMemoryConnectorRegistry::from_iter([("pg_demo".to_string(), fake("pg_demo"))]);
        let rendered = format!("{reg:?}");
        assert!(
            rendered.contains("pg_demo"),
            "name should appear in Debug: {rendered}"
        );
        assert!(
            !rendered.contains("FakeExecutor"),
            "executor object must not appear in Debug: {rendered}"
        );
    }

    #[test]
    fn default_is_empty() {
        let reg = InMemoryConnectorRegistry::default();
        assert!(reg.is_empty());
    }

    #[test]
    fn from_iter_constructs_registry_from_pairs() {
        let reg: InMemoryConnectorRegistry = [
            ("pg".to_string(), fake("pg")),
            ("mysql".to_string(), fake("mysql")),
        ]
        .into_iter()
        .collect();
        assert_eq!(reg.len(), 2);
        assert!(reg.lookup("pg").is_some());
        assert!(reg.lookup("mysql").is_some());
    }

    // ----- Phase 2 slice 4b — planner reverse-lookup tests --------

    #[test]
    fn lookup_planner_returns_some_for_registered_name() {
        let reg = InMemoryConnectorRegistry::from_iter([("pg".to_string(), fake("pg"))]);
        assert!(reg.lookup_planner("pg").is_some());
        // Invariant: lookup and lookup_planner agree on key set.
        assert!(reg.lookup("pg").is_some());
    }

    #[test]
    fn lookup_planner_returns_none_for_unknown_name() {
        let reg = InMemoryConnectorRegistry::from_iter([("pg".to_string(), fake("pg"))]);
        assert!(reg.lookup_planner("snowflake").is_none());
    }

    #[test]
    fn find_planner_name_resolves_registered_planner() {
        let reg = InMemoryConnectorRegistry::from_iter([
            ("pg_demo".to_string(), fake("pg_demo")),
            ("mysql_demo".to_string(), fake("mysql_demo")),
        ]);

        let pg_planner = reg.lookup_planner("pg_demo").expect("pg_demo registered");
        let my_planner = reg
            .lookup_planner("mysql_demo")
            .expect("mysql_demo registered");

        assert_eq!(reg.find_planner_name(&pg_planner), Some("pg_demo"));
        assert_eq!(reg.find_planner_name(&my_planner), Some("mysql_demo"));
    }

    #[test]
    fn find_planner_name_returns_none_for_unregistered_planner() {
        let reg = InMemoryConnectorRegistry::from_iter([("pg".to_string(), fake("pg"))]);

        // Construct a planner that was NEVER registered with this
        // registry. It wraps an SQLExecutor but no `Arc::ptr_eq`
        // match against any stored entry, so reverse-lookup returns
        // None — the codec encoder translates this into a clean
        // "unknown federation source" error.
        let stranger: Arc<dyn FederationPlanner> =
            Arc::new(SQLFederationPlanner::new(fake("stranger")));
        assert!(reg.find_planner_name(&stranger).is_none());
    }

    /// **Critical defensive test** — pins the pointer-identity gamble
    /// the whole slice 4b codec design rests on. Phase 2 spec PR #268
    /// called this out as the design risk:
    ///
    /// > The whole approach assumes `Arc::ptr_eq` on fat-pointer-coerced
    /// > `Arc<dyn FederationPlanner>` reliably compares data pointers.
    ///
    /// If this test ever fails, the codec's reverse-lookup is broken
    /// and slice 4b.2's `try_encode` path won't work — we'd need a
    /// different planner-identity story.
    #[test]
    fn pointer_identity_round_trips_through_trait_object() {
        let reg = InMemoryConnectorRegistry::from_iter([("pg".to_string(), fake("pg"))]);

        // First fetch — the Arc the registry hands back.
        let p1 = reg.lookup_planner("pg").expect("registered");
        // Second fetch — should be a clone of the same Arc.
        let p2 = reg.lookup_planner("pg").expect("registered");
        assert!(
            Arc::ptr_eq(&p1, &p2),
            "two lookups of the same name must return the same Arc data pointer"
        );

        // Reverse-lookup uses `Arc::ptr_eq`. If the fat-pointer
        // coercion ever scrambled the data pointer (which it
        // shouldn't per Rust std), this assertion would fire.
        assert_eq!(
            reg.find_planner_name(&p1),
            Some("pg"),
            "find_planner_name must recognize an Arc obtained from \
             lookup_planner — pointer-identity round-trip"
        );

        // A semantically-equivalent but freshly-constructed planner
        // (same executor name) must NOT match — proves we're doing
        // pointer-identity, not structural equality (which the trait
        // wouldn't expose anyway).
        let lookalike: Arc<dyn FederationPlanner> = Arc::new(SQLFederationPlanner::new(fake("pg")));
        assert!(
            reg.find_planner_name(&lookalike).is_none(),
            "find_planner_name must NOT match a structurally-equivalent \
             but freshly-allocated planner — pointer identity only"
        );
    }

    #[test]
    fn debug_redacts_planner_internals_too() {
        // The planner Arc wraps the executor; the same redaction
        // contract from the existing debug test applies to the
        // expanded registry shape.
        let reg = InMemoryConnectorRegistry::from_iter([("pg_demo".to_string(), fake("pg_demo"))]);
        let rendered = format!("{reg:?}");
        assert!(rendered.contains("pg_demo"), "name visible: {rendered}");
        assert!(
            !rendered.contains("SQLFederationPlanner"),
            "planner type must not appear in Debug: {rendered}"
        );
        assert!(
            !rendered.contains("FakeExecutor"),
            "executor must not appear in Debug: {rendered}"
        );
    }

    // ----- Phase 2 slice 4b.3 — compute_context reverse-lookup -----
    //
    // These tests pin the replacement for `find_planner_name`.
    // The slice-4b.1 pointer-identity gamble failed on the real
    // federation construction path (see PR #272 / the header
    // comment block above). The new index is keyed on
    // `SQLExecutor::compute_context()` — a stable string the
    // codec can pull off the FederatedPlanNode's plan tree without
    // any Arc-identity assumption.

    #[test]
    fn find_name_by_compute_context_resolves_registered_executor() {
        let reg = InMemoryConnectorRegistry::from_iter([
            ("pg_demo".to_string(), fake("pg_demo")),
            ("mysql_demo".to_string(), fake("mysql_demo")),
        ]);

        // `fake()` reports compute_context as `ctx::<name>`.
        assert_eq!(
            reg.find_name_by_compute_context("ctx::pg_demo"),
            Some("pg_demo")
        );
        assert_eq!(
            reg.find_name_by_compute_context("ctx::mysql_demo"),
            Some("mysql_demo")
        );
    }

    #[test]
    fn find_name_by_compute_context_returns_none_for_unknown_context() {
        let reg = InMemoryConnectorRegistry::from_iter([("pg".to_string(), fake("pg"))]);

        // Different compute_context — must not match. The codec
        // surfaces this as a typed `DataFusionError::Internal`,
        // not a panic.
        assert!(reg.find_name_by_compute_context("ctx::snowflake").is_none());
        // Empty string must not silently match anything either.
        assert!(reg.find_name_by_compute_context("").is_none());
    }

    #[test]
    fn executor_without_compute_context_is_omitted_from_reverse_index() {
        // An executor whose `compute_context()` returns `None` can
        // still be resolved by name — but it can't be reverse-resolved
        // by context (because there's no context to key on). The
        // codec encoder will surface this as "no registered connector"
        // at encode time, which is the same shape as a missing name.
        let reg = InMemoryConnectorRegistry::from_iter([
            ("legacy".to_string(), fake_without_context("legacy")),
            ("pg".to_string(), fake("pg")),
        ]);

        assert!(reg.lookup("legacy").is_some(), "forward lookup still works");
        assert_eq!(
            reg.find_name_by_compute_context("ctx::pg"),
            Some("pg"),
            "executor WITH a context is still resolvable"
        );

        // No way to round-trip the contextless executor through the
        // reverse index — by design. There is no string to key on.
        // The test below also pins that the index size matches the
        // count of context-bearing executors, not the total.
        assert_eq!(reg.len(), 2, "forward index counts every executor");
    }

    #[test]
    fn duplicate_compute_context_last_write_wins() {
        // Two executors claim the same compute_context. The forward
        // index keeps both (they have distinct names); the reverse
        // index can only return one. The behaviour here is "the
        // map's iteration / insertion order decides" — we pin only
        // that *some* registered name comes back and that it is one
        // of the two duplicates, NOT a stale/missing entry.
        //
        // This is acceptable because in production two registrations
        // pointing at the same compute_context (same host/port/db/user)
        // are misconfiguration — but we still want the codec to
        // produce a deterministic error path rather than panicking.
        let dup_ctx = "ctx::shared";
        let mut a = HashMap::new();
        a.insert(
            "alpha".to_string(),
            Arc::new(FakeExecutor {
                name: "alpha".to_string(),
                compute_context: Some(dup_ctx.to_string()),
            }) as Arc<dyn SQLExecutor>,
        );
        a.insert(
            "beta".to_string(),
            Arc::new(FakeExecutor {
                name: "beta".to_string(),
                compute_context: Some(dup_ctx.to_string()),
            }) as Arc<dyn SQLExecutor>,
        );
        let reg = InMemoryConnectorRegistry::new(a);

        let resolved = reg
            .find_name_by_compute_context(dup_ctx)
            .expect("one of the two duplicates wins the reverse index");
        assert!(
            resolved == "alpha" || resolved == "beta",
            "reverse-lookup must return one of the registered duplicates, got {resolved}"
        );
        // Forward index unaffected: both are still resolvable by name.
        assert!(reg.lookup("alpha").is_some());
        assert!(reg.lookup("beta").is_some());
    }
}

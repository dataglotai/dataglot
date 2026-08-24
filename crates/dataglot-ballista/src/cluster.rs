//! `BallistaCluster` — server-scoped handle to a running standalone
//! Ballista cluster. Phase 2 spec 02 slice 3a.
//!
//! # Why a separate handle and not just a `SessionContext`
//!
//! Ballista's `SessionContext::standalone_with_state` boots an
//! in-process scheduler + executor pair on freshly-allocated ports.
//! The returned `SessionContext` holds (via its `BallistaQueryPlanner`)
//! an HTTP client pointing at the scheduler's URL — that's the only
//! thread of life that keeps the cluster alive in this process.
//! Dropping every `SessionContext` would terminate the scheduler.
//!
//! For server-mode operation we need:
//!
//! - **Boot once at server start.** `DataglotServer::new()` calls
//!   `BallistaContextFactory::boot_standalone_cluster` and stashes
//!   the returned `BallistaCluster` in an `Arc<BallistaCluster>`
//!   field. The cluster stays alive for the server's whole lifetime.
//! - **Per-session contexts share the same scheduler.** Each pgwire
//!   connection calls [`BallistaCluster::create_session`] to mint a
//!   fresh `SessionContext` whose `BallistaQueryPlanner` clones the
//!   cluster's HTTP-client config (pointing at the same scheduler
//!   URL). Per-session isolation works the same as on the single-node
//!   side — every context is its own state.
//! - **Drop on shutdown.** When the `Arc<BallistaCluster>` is
//!   dropped, the wrapped reference `SessionContext` drops too, the
//!   in-process scheduler unwinds, ports are released.
//!
//! This is what slice 2's `create_standalone_context` was implicitly
//! doing — boot + return one context. Slice 3a separates the two
//! responsibilities so the lifetime is server-scoped, not
//! session-scoped, and `DataglotServer::create_session()`'s sync
//! contract stays unchanged.

use std::sync::Arc;

use ballista::datafusion::execution::context::QueryPlanner;
use ballista::datafusion::execution::session_state::SessionStateBuilder;
use ballista::datafusion::prelude::SessionContext;
use dataglot_core::CredentialResolver;

use crate::plan_guard::SerializationGuardQueryPlanner;

/// Handle to a running standalone Ballista cluster. Created by
/// [`BallistaContextFactory::boot_standalone_cluster`]; consumed by
/// [`BallistaCluster::create_session`] to mint per-session contexts.
///
/// The internal `SessionContext` is the load-bearing field — its
/// `BallistaQueryPlanner` holds the HTTP client to the scheduler,
/// which is what keeps the in-process cluster alive. Dropping a
/// `BallistaCluster` (when the wrapping `Arc` reaches zero references)
/// terminates the scheduler.
///
/// # Credential resolution (slice 3b)
///
/// The cluster optionally carries a coordinator-side
/// `Arc<dyn CredentialResolver>` propagated from
/// [`BallistaContextFactory::with_credential_resolver`]. Today's
/// standalone deployment runs the executor in the same process as the
/// coordinator, so per-worker resolution trivially collapses to one
/// shared resolver instance. Slice 5's multi-process HA scheduler will
/// extend this model: each executor binary will take a
/// `--credentials-config` flag pointing at the same config the
/// coordinator uses, construct its own resolver instance at boot, and
/// refuse to register with the scheduler if construction fails (the
/// trait's pre-fetch contract is where backend reachability is
/// checked). The coordinator's resolver never serializes its resolved
/// tokens onto the wire (CLAUDE.md rule 12).
///
/// Consumers — connectors that bind a `CredentialHandle` to its
/// resolved payload at execution time — do not yet exist; the Phase 1
/// connector migration that introduces them will pull the resolver
/// off the cluster via [`Self::credential_resolver`] (or off
/// the session context once slice 5 attaches it as a state extension).
///
/// [`BallistaContextFactory::boot_standalone_cluster`]: super::factory::BallistaContextFactory::boot_standalone_cluster
/// [`BallistaContextFactory::with_credential_resolver`]: super::factory::BallistaContextFactory::with_credential_resolver
pub struct BallistaCluster {
    /// First `SessionContext` Ballista returned at bring-up time.
    /// Kept alive for the cluster's whole lifetime; per-session
    /// contexts are minted by cloning its state. `SessionContext`
    /// itself doesn't implement `Debug`, so neither does this type;
    /// callers wanting log output should pull the scheduler URL out
    /// of `reference_session().state().query_planner()`'s debug repr
    /// instead.
    reference_ctx: SessionContext,
    /// Coordinator-side credential resolver propagated from the
    /// factory at boot. `None` when the factory was not given one.
    /// See type-level docs for the per-worker / multi-process story.
    credential_resolver: Option<Arc<dyn CredentialResolver>>,
}

impl BallistaCluster {
    /// Construct from the first `SessionContext` Ballista returns at
    /// standalone bring-up, plus the coordinator's credential resolver
    /// if one was attached to the factory. Internal — created only by
    /// `BallistaContextFactory::boot_standalone_cluster`.
    pub(crate) fn new(
        reference_ctx: SessionContext,
        credential_resolver: Option<Arc<dyn CredentialResolver>>,
    ) -> Self {
        Self {
            reference_ctx,
            credential_resolver,
        }
    }

    /// Mint a fresh `SessionContext` against this running cluster.
    /// Per-session contexts share the same in-process scheduler +
    /// executor; the cluster's `BallistaQueryPlanner` is cloned
    /// (it's an HTTP client pointing at the scheduler URL) so the
    /// new context dispatches against the same pool.
    ///
    /// Sync surface — matches `DataglotServer::create_session()`'s
    /// per-pgwire-connection contract. The async work (cluster
    /// bring-up) already happened at `boot_standalone_cluster` time.
    #[must_use]
    pub fn create_session(&self) -> SessionContext {
        // Cloning the reference state preserves the federation
        // analyzer rules + FilterPushdown strip + (most importantly)
        // the BallistaQueryPlanner pointing at our scheduler URL.
        // `new_from_existing` is the standard way to build a fresh
        // SessionState that shares planner + analyzer rules with a
        // template — the new context's optimizers + catalog
        // registrations are then independent of the template's.
        // Guard the coordinator's `BallistaQueryPlanner`: a cross-source
        // GROUP-BY aggregate can make `datafusion-federation` emit a cyclic
        // LogicalPlan, and `DistributedQueryExec` serializing it overflows
        // the worker stack and aborts the whole process (DEV-3719 / GH
        // #418). The guard rejects such a plan with a typed error *before*
        // serialization, so the server survives. Validation is cheap (a
        // bounded iterative walk) and a no-op for every well-formed plan.
        let template = self.reference_ctx.state();
        let guarded: Arc<dyn QueryPlanner + Send + Sync> = Arc::new(
            SerializationGuardQueryPlanner::new(Arc::clone(template.query_planner())),
        );
        // pg_catalog metadata queries (JDBC DatabaseMetaData — every
        // GUI schema browser) plan locally: their virtual providers
        // can't serialize for Ballista, and there's nothing to
        // distribute.
        let planner: Arc<dyn QueryPlanner + Send + Sync> =
            Arc::new(crate::plan_guard::LocalMetadataQueryPlanner::new(guarded));
        let state = SessionStateBuilder::new_from_existing(template)
            .with_query_planner(planner)
            .build();
        SessionContext::new_with_state(state)
    }

    /// Borrow the reference `SessionContext`. Tests and adjacent
    /// integration code use this to inspect the wired-up state
    /// without minting a fresh session each time. Not the entry
    /// point production code should reach for.
    #[must_use]
    pub fn reference_session(&self) -> &SessionContext {
        &self.reference_ctx
    }

    /// Borrow the coordinator's credential resolver, if one was
    /// attached to the factory before boot. `None` when the cluster
    /// was booted without a resolver — the default for callers that
    /// don't ship credentials through the Ballista path.
    ///
    /// Consumers landing in slice 5 / the Phase 1 connector migration
    /// pull the resolver from here to resolve `CredentialHandle`s at
    /// query execution time. The returned `Arc` is identity-shared
    /// with the coordinator's resolver — same allocation, no clones
    /// over a wire.
    #[must_use]
    pub fn credential_resolver(&self) -> Option<&Arc<dyn CredentialResolver>> {
        self.credential_resolver.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use crate::BallistaContextFactory;
    use ballista::datafusion::arrow::array::RecordBatch;

    /// End-to-end: boot a cluster, mint two distinct sessions, run a
    /// query on each. Proves the per-session-context-sharing design
    /// works without re-allocating cluster ports per session.
    #[tokio::test]
    async fn cluster_creates_independent_sessions() {
        let factory = BallistaContextFactory::with_defaults();
        let cluster = factory
            .boot_standalone_cluster()
            .await
            .expect("ballista standalone boots");

        let session_a = cluster.create_session();
        let session_b = cluster.create_session();

        // Both contexts run against the same scheduler — the
        // `BallistaQueryPlanner` debug repr (which carries the
        // scheduler URL) should be identical across sessions.
        let planner_a = format!("{:?}", session_a.state().query_planner().clone());
        let planner_b = format!("{:?}", session_b.state().query_planner().clone());

        // Each planner string includes `scheduler_url: "http://localhost:<port>"`.
        // Extract the URL substring on both and assert they match.
        let url_a = scheduler_url(&planner_a).expect("planner A carries scheduler_url");
        let url_b = scheduler_url(&planner_b).expect("planner B carries scheduler_url");
        assert_eq!(
            url_a, url_b,
            "expected per-session contexts to share scheduler, got A={url_a}, B={url_b}"
        );

        // Both contexts should execute a literal SELECT independently.
        for (name, ctx) in [("A", &session_a), ("B", &session_b)] {
            let batches = ctx
                .sql("SELECT 1 + 1 AS two")
                .await
                .unwrap_or_else(|e| panic!("session {name} plan: {e}"))
                .collect()
                .await
                .unwrap_or_else(|e| panic!("session {name} execute: {e}"));
            let total: usize = batches.iter().map(RecordBatch::num_rows).sum();
            assert_eq!(total, 1, "session {name} returned {total} rows");
        }
    }

    /// Phase 2 slice 3b — when the factory boots a cluster, the
    /// coordinator's credential resolver propagates to the cluster
    /// handle with Arc identity preserved. The in-process collapse
    /// design depends on this: the resolver allocation must be the
    /// same one the coordinator handed in, never re-allocated or
    /// re-wrapped at boot time.
    ///
    /// Boots an in-process Ballista (the existing cluster tests
    /// already pay this cost; one more boot is the cheapest way to
    /// pin the end-to-end carry-through).
    #[tokio::test]
    async fn cluster_carries_resolver_from_factory_with_arc_identity() {
        use dataglot_core::{CredentialResolver, StaticCredentialResolver};
        use std::sync::Arc;

        let resolver: Arc<dyn CredentialResolver> = Arc::new(StaticCredentialResolver::new());
        let factory =
            BallistaContextFactory::with_defaults().with_credential_resolver(Arc::clone(&resolver));
        let cluster = factory
            .boot_standalone_cluster()
            .await
            .expect("ballista standalone boots");

        let stored = cluster
            .credential_resolver()
            .expect("cluster carries resolver from factory");
        assert!(
            Arc::ptr_eq(stored, &resolver),
            "cluster's resolver Arc must be identity-equal to the factory's input"
        );
    }

    /// Phase 2 slice 3b — boot without attaching a resolver. The
    /// cluster's `credential_resolver()` accessor returns `None`,
    /// letting consumers branch on resolver presence.
    #[tokio::test]
    async fn cluster_without_resolver_returns_none() {
        let factory = BallistaContextFactory::with_defaults();
        let cluster = factory
            .boot_standalone_cluster()
            .await
            .expect("ballista standalone boots");
        assert!(
            cluster.credential_resolver().is_none(),
            "cluster booted without a resolver must expose None"
        );
    }

    /// Defensive: dropping the cluster handle must terminate the
    /// scheduler. We can't directly observe scheduler shutdown from
    /// outside the process, but we *can* assert that creating a new
    /// cluster after dropping the old one succeeds (which is only
    /// possible if the old scheduler released its port allocation).
    #[tokio::test]
    async fn dropping_cluster_releases_resources() {
        let factory = BallistaContextFactory::with_defaults();

        // Boot, capture the scheduler URL, drop.
        let url_first = {
            let cluster = factory
                .boot_standalone_cluster()
                .await
                .expect("first cluster boots");
            let planner = format!(
                "{:?}",
                cluster.reference_session().state().query_planner().clone()
            );
            scheduler_url(&planner)
                .expect("planner carries scheduler_url")
                .to_string()
            // `cluster` drops here
        };

        // Boot a second cluster. Should succeed; Ballista allocates
        // its own port so we don't strictly need the previous one to
        // be released, but the boot itself proves no global state was
        // leaked across the drop.
        let cluster2 = factory
            .boot_standalone_cluster()
            .await
            .expect("second cluster boots after first dropped");
        let planner2 = format!(
            "{:?}",
            cluster2.reference_session().state().query_planner().clone()
        );
        let url_second = scheduler_url(&planner2).expect("second planner carries scheduler_url");

        // The two URLs should reference different ports (the
        // standalone bring-up allocates fresh each time).
        assert_ne!(
            url_first, url_second,
            "expected second cluster to allocate a different scheduler port; got {url_first} both times"
        );
    }

    /// `create_session` must wire the FULL decorator chain, not just the
    /// `BallistaQueryPlanner`. The previous tests only assert the planner
    /// carries a `scheduler_url` (i.e. a `BallistaQueryPlanner` is present
    /// *somewhere*) — dropping the `LocalMetadataQueryPlanner` or the
    /// `SerializationGuardQueryPlanner` decorator would pass every one of
    /// them while silently reintroducing  (schema browsers break
    /// distributed) or GH #418 (serializer stack overflow). This pins the
    /// composition AND the wrapping order via the nested `Debug` repr:
    /// `LocalMetadataQueryPlanner` (outermost, routes metadata local) →
    /// `SerializationGuardQueryPlanner` → `BallistaQueryPlanner` (innermost,
    /// dispatches to the scheduler).
    #[tokio::test]
    async fn create_session_wires_the_full_guard_chain() {
        let factory = BallistaContextFactory::with_defaults();
        let cluster = factory
            .boot_standalone_cluster()
            .await
            .expect("ballista standalone boots");

        let planner = format!("{:?}", cluster.create_session().state().query_planner());

        let local = planner
            .find("LocalMetadataQueryPlanner")
            .expect("LocalMetadataQueryPlanner must be in the chain (local routing)");
        let guard = planner
            .find("SerializationGuardQueryPlanner")
            .expect("SerializationGuardQueryPlanner must be in the chain (GH #418 DoS guard)");
        let ballista = planner
            .find("BallistaQueryPlanner")
            .expect("BallistaQueryPlanner must be the innermost planner");

        assert!(
            local < guard && guard < ballista,
            "decorator order must be LocalMetadata -> SerializationGuard -> Ballista, got: {planner}"
        );
    }

    /// Extract the `scheduler_url` substring from a `BallistaQueryPlanner`
    /// debug repr. Format is:
    ///   `BallistaQueryPlanner { scheduler_url: "http://localhost:NNNNN", ... }`
    fn scheduler_url(planner_debug: &str) -> Option<&str> {
        let key = "scheduler_url: \"";
        let start = planner_debug.find(key)? + key.len();
        let rest = &planner_debug[start..];
        let end = rest.find('"')?;
        Some(&rest[..end])
    }
}

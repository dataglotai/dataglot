//! In-process `CatalogProvider` cache — Phase 1 task 09.
//!
//! Spec: the phase-1 `catalog-provider-cache` plan.
//!
//! Sits in front of [`crate::CatalogService`] and gives the
//! query plane sub-millisecond catalog lookups. Cache hits
//! are a `DashMap` probe + `Arc::clone`; cold misses dispatch
//! to a caller-supplied closure (the server crate captures
//! its `build_connectors` helper there). The cache evicts on
//! every [`crate::BindingChange`] event from the service's
//! `subscribe` stream — task 09's failure-isolation contract
//! is that subscribe-stream loss logs WARN and serves
//! warm entries until the next reconnect.
//!
//! # First-access collapse
//!
//! N concurrent `get(name)` calls on a cold key invoke the
//! builder exactly once. The first call to land starts a
//! per-key [`tokio::sync::OnceCell`]; subsequent calls
//! `get_or_init` onto the same cell and receive the same
//! `Arc<dyn CatalogProvider>`. Critical correctness invariant
//! pinned by `tests::concurrent_cold_misses_collapse_to_one_resolve`
//! (in this module's `#[cfg(test)]` block).
//!
//! # Why `DashMap` over `RwLock<HashMap>`
//!
//! Reader-mostly workload — warm hits don't write. `DashMap`'s
//! shard-by-hash keeps per-key contention bounded without
//! the read-write coordination cost a single
//! `RwLock<HashMap>` would impose.

use std::sync::Arc;

use dashmap::DashMap;
use datafusion::catalog::CatalogProvider;
use futures::StreamExt;
use tokio::sync::OnceCell;

use crate::error::Result;
use crate::store::MetaStore;
use crate::subscribe::{BindingChange, BindingChangeKind};

/// Closure that builds a fresh `Arc<dyn CatalogProvider>` for
/// a given catalog name. The server crate captures
/// `build_connectors` (its existing connector-construction
/// helper) into this closure; keeping it generic in the cache
/// crate avoids a reverse dep on `dataglot-server` /
/// `dataglot-federation` per hard rule 4.
///
/// The closure is called on every cold miss and on every
/// re-resolve following a `BindingChange`.
pub type ProviderBuilder = Arc<
    dyn Fn(
            String,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<Output = Result<Arc<dyn CatalogProvider>>> + Send + 'static,
            >,
        > + Send
        + Sync
        + 'static,
>;

/// Shorthand for the warm-cache value type. Cache hits clone
/// this `Arc` and hand it to consumers.
type CachedProvider = Arc<dyn CatalogProvider>;

/// Shorthand for the in-flight `OnceCell` shape. Per-key
/// rendezvous for concurrent first-access callers; the first
/// one runs the builder, the rest wait on the cell.
type InFlightCell = Arc<OnceCell<CachedProvider>>;

/// In-process cache fronting the catalog service. Reads hit a
/// `DashMap` probe; misses resolve through the configured
/// `ProviderBuilder`. Evictions are driven by
/// [`Self::start_invalidation`] — the LISTEN/NOTIFY consumer.
#[derive(Clone)]
pub struct CatalogProviderCache {
    /// Warm entries — `Arc::clone` per hit.
    inner: Arc<DashMap<String, CachedProvider>>,
    /// Per-key `OnceCell` so N concurrent first-access calls
    /// collapse to one build. Entries here are cleared once
    /// the value lands in `inner`.
    in_flight: Arc<DashMap<String, InFlightCell>>,
    build: ProviderBuilder,
}

impl std::fmt::Debug for CatalogProviderCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CatalogProviderCache")
            .field("warm_entries", &self.inner.len())
            .field("in_flight_keys", &self.in_flight.len())
            .finish_non_exhaustive()
    }
}

impl CatalogProviderCache {
    /// Construct a cache with the given builder closure.
    /// `start_invalidation` is a separate call so unit tests
    /// can exercise the cache surface without a real catalog
    /// service.
    #[must_use]
    pub fn new(build: ProviderBuilder) -> Self {
        Self {
            inner: Arc::new(DashMap::new()),
            in_flight: Arc::new(DashMap::new()),
            build,
        }
    }

    /// Get the `Arc<dyn CatalogProvider>` for `name`,
    /// resolving + caching on first access. Concurrent first
    /// accesses on the same key collapse to one builder call
    /// via the per-key `OnceCell`.
    ///
    /// # Errors
    /// Propagates whatever the builder closure returns. The
    /// failed key is *not* cached; the next call retries.
    pub async fn get(&self, name: &str) -> Result<Arc<dyn CatalogProvider>> {
        // Warm-path probe.
        if let Some(entry) = self.inner.get(name) {
            return Ok(Arc::clone(entry.value()));
        }

        // Cold path: get-or-insert a per-key OnceCell. All
        // racing callers see the same cell; the first to
        // call `get_or_try_init` runs the builder, others
        // wait on the cell.
        let cell = self
            .in_flight
            .entry(name.to_string())
            .or_insert_with(|| Arc::new(OnceCell::new()))
            .clone();

        let build = Arc::clone(&self.build);
        let name_owned = name.to_string();
        let provider = cell
            .get_or_try_init(|| async move {
                let fut = (build)(name_owned);
                fut.await
            })
            .await?
            .clone();

        // Hoist the freshly-built provider into the warm map.
        // The OnceCell remains keyed for the lifetime of any
        // racing caller; the next eviction cycle would clear
        // it, or it eventually evicts on its own when no one
        // holds a reference.
        self.inner.insert(name.to_string(), Arc::clone(&provider));
        // Drop the in-flight entry now that the warm path
        // has it. A subsequent eviction + re-resolve will
        // create a fresh OnceCell.
        self.in_flight.remove(name);

        Ok(provider)
    }

    /// Evict `name` from the warm cache. The next `get(name)`
    /// re-resolves through the builder.
    ///
    /// Exposed for tests and for the Phase 2 runtime-mutation
    /// path (task 12) that will need to evict before
    /// re-upserting.
    pub fn evict(&self, name: &str) {
        self.inner.remove(name);
        self.in_flight.remove(name);
    }

    /// Number of warm entries — useful for tests and
    /// diagnostics.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// True when no warm entries are cached.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Spawn the LISTEN/NOTIFY-driven invalidation task that
    /// consumes the service's `subscribe` stream and evicts
    /// the warm map on every `BindingChange`. Returns the
    /// task's `JoinHandle` for tests; production callers can
    /// drop it.
    ///
    /// Per the spec, subscribe-stream loss is `stale-but-up`:
    /// the cache keeps serving warm entries while the
    /// reconnect loop tries to re-establish the stream. Phase 1
    /// implements a simple bounded-backoff reconnect; the
    /// caller's `evict` API is always available as a manual
    /// escape hatch.
    ///
    /// # Errors
    /// Returns an error if the initial subscribe call fails.
    /// Subsequent disconnections are absorbed by the
    /// reconnect loop and don't propagate.
    pub async fn start_invalidation(
        self: &Arc<Self>,
        service: Arc<dyn MetaStore>,
    ) -> Result<tokio::task::JoinHandle<()>> {
        let initial_stream = service.subscribe().await?;
        let cache = Arc::clone(self);
        let handle = tokio::spawn(async move {
            let mut stream = initial_stream;
            loop {
                if let Some(change) = stream.next().await {
                    Self::apply_change(&cache, &change);
                } else {
                    tracing::warn!("catalog cache: subscribe stream closed; reconnecting");
                    // Bounded-backoff reconnect. Keep serving
                    // warm entries while we retry
                    // (stale-but-up). The current reconnect
                    // loop returns `Some` on success and runs
                    // forever otherwise — `None` is reserved
                    // for a future bounded-retry policy.
                    if let Some(new_stream) = Self::reconnect_subscribe(&service).await {
                        stream = new_stream;
                    } else {
                        tracing::error!("catalog cache: reconnect gave up; cache serves stale");
                        break;
                    }
                }
            }
        });
        Ok(handle)
    }

    fn apply_change(cache: &Arc<Self>, change: &BindingChange) {
        // Phase 1 is single-tenant; we evict regardless of
        // change.org_id. Phase 2 multi-tenant will scope on
        // the org match.
        match change.kind {
            BindingChangeKind::Upserted | BindingChangeKind::Deleted => {
                cache.evict(&change.name);
                tracing::debug!(?change, "catalog cache: evicted on BindingChange");
            }
        }
    }

    /// Best-effort reconnect with bounded exponential backoff
    /// (base 100ms, cap 30s). Returns `Some(stream)` on
    /// success, `None` when we've decided to give up.
    ///
    /// Phase 1 retries forever (no cap on attempt count) but
    /// caps the delay; an operator restart is the explicit
    /// signal that intervention is needed. This matches the
    /// spec's "stale-but-up over fail-closed" decision.
    async fn reconnect_subscribe(
        service: &Arc<dyn MetaStore>,
    ) -> Option<crate::subscribe::BindingChangeStream> {
        let mut delay = std::time::Duration::from_millis(100);
        let cap = std::time::Duration::from_secs(30);
        loop {
            match service.subscribe().await {
                Ok(s) => {
                    tracing::info!("catalog cache: subscribe reconnected");
                    return Some(s);
                }
                Err(err) => {
                    tracing::warn!(
                        error = %err,
                        ?delay,
                        "catalog cache: subscribe reconnect failed; backing off"
                    );
                    tokio::time::sleep(delay).await;
                    delay = (delay * 2).min(cap);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use datafusion::catalog::{MemoryCatalogProvider, SchemaProvider};
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn empty_provider() -> Arc<dyn CatalogProvider> {
        Arc::new(MemoryCatalogProvider::new())
    }

    /// Build a closure that records the number of times the
    /// builder fired, plus the names it was called with.
    /// Returns the closure, the call-count, and the
    /// observed-names vector.
    fn counting_builder() -> (ProviderBuilder, Arc<AtomicUsize>, Arc<DashMap<String, ()>>) {
        let count = Arc::new(AtomicUsize::new(0));
        let names = Arc::new(DashMap::new());
        let count_c = Arc::clone(&count);
        let names_c = Arc::clone(&names);
        let build: ProviderBuilder = Arc::new(move |name: String| {
            let count = Arc::clone(&count_c);
            let names = Arc::clone(&names_c);
            Box::pin(async move {
                count.fetch_add(1, Ordering::Relaxed);
                names.insert(name, ());
                Ok::<_, crate::error::CatalogServiceError>(empty_provider())
            })
        });
        (build, count, names)
    }

    #[tokio::test]
    async fn cold_miss_invokes_builder_warm_hit_does_not() {
        let (build, count, names) = counting_builder();
        let cache = CatalogProviderCache::new(build);

        let _ = cache.get("pg_demo").await.unwrap();
        assert_eq!(count.load(Ordering::Relaxed), 1);
        assert!(names.contains_key("pg_demo"));
        assert_eq!(cache.len(), 1);

        // Warm hit — must not invoke the builder again.
        let _ = cache.get("pg_demo").await.unwrap();
        assert_eq!(count.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn evict_drops_warm_entry_so_next_get_re_resolves() {
        let (build, count, _) = counting_builder();
        let cache = CatalogProviderCache::new(build);

        let _ = cache.get("pg_demo").await.unwrap();
        assert_eq!(count.load(Ordering::Relaxed), 1);

        cache.evict("pg_demo");
        assert!(cache.is_empty());

        let _ = cache.get("pg_demo").await.unwrap();
        assert_eq!(count.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn concurrent_cold_misses_collapse_to_one_resolve() {
        // Critical correctness invariant from the spec:
        // 100 concurrent get() calls on a cold key invoke
        // the builder exactly once. The first-access OnceCell
        // serialises the cold path.
        let (build, count, _) = counting_builder();
        let cache = Arc::new(CatalogProviderCache::new(build));

        let mut handles = Vec::with_capacity(100);
        for _ in 0..100 {
            let cache = Arc::clone(&cache);
            handles.push(tokio::spawn(
                async move { cache.get("pg_demo").await.unwrap() },
            ));
        }
        for h in handles {
            let _ = h.await.unwrap();
        }
        assert_eq!(
            count.load(Ordering::Relaxed),
            1,
            "expected exactly one builder call across 100 concurrent get()s"
        );
    }

    #[tokio::test]
    async fn separate_keys_resolve_independently() {
        // Concurrent cold misses on DIFFERENT keys should NOT
        // serialise — each key has its own OnceCell.
        let (build, count, names) = counting_builder();
        let cache = Arc::new(CatalogProviderCache::new(build));

        let cache1 = Arc::clone(&cache);
        let cache2 = Arc::clone(&cache);
        let cache3 = Arc::clone(&cache);
        let h1 = tokio::spawn(async move { cache1.get("a").await.unwrap() });
        let h2 = tokio::spawn(async move { cache2.get("b").await.unwrap() });
        let h3 = tokio::spawn(async move { cache3.get("c").await.unwrap() });
        let _ = h1.await.unwrap();
        let _ = h2.await.unwrap();
        let _ = h3.await.unwrap();

        assert_eq!(count.load(Ordering::Relaxed), 3);
        assert_eq!(names.len(), 3);
    }

    #[tokio::test]
    async fn builder_error_is_not_cached_next_get_retries() {
        // Failed first-access doesn't poison the cell — the
        // second call retries from scratch. Production: a
        // transient connect error shouldn't make a catalog
        // permanently unreachable.
        let fail_first = Arc::new(AtomicUsize::new(0));
        let fail_first_c = Arc::clone(&fail_first);
        let build: ProviderBuilder = Arc::new(move |_name: String| {
            let counter = Arc::clone(&fail_first_c);
            Box::pin(async move {
                let n = counter.fetch_add(1, Ordering::Relaxed);
                if n == 0 {
                    Err(crate::error::CatalogServiceError::Pool(
                        "transient connect failure".into(),
                    ))
                } else {
                    Ok(empty_provider())
                }
            })
        });
        let cache = CatalogProviderCache::new(build);

        let first = cache.get("pg_demo").await;
        assert!(first.is_err(), "first call must surface the error");

        let second = cache.get("pg_demo").await;
        assert!(second.is_ok(), "second call must retry (not poisoned)");
    }

    #[test]
    fn debug_does_not_panic_and_shows_sizes() {
        // Smoke for the Debug impl — operators inspect cache
        // state via tracing log lines.
        let (build, _, _) = counting_builder();
        let cache = CatalogProviderCache::new(build);
        let s = format!("{cache:?}");
        assert!(s.contains("CatalogProviderCache"));
        assert!(s.contains("warm_entries"));
    }

    #[test]
    fn provider_returned_is_dyn_catalog_provider() {
        // Compile-time pin on the public type. If the cache
        // ever started returning something other than
        // `Arc<dyn CatalogProvider>`, downstream consumers
        // (`SessionContext::register_catalog`) would break.
        let p: Arc<dyn CatalogProvider> = empty_provider();
        let _schemas: Vec<String> = p.schema_names();
        let _maybe: Option<Arc<dyn SchemaProvider>> = p.schema("public");
    }

    /// `apply_change` is the invalidation reaction: an Upserted or Deleted
    /// `BindingChange` evicts exactly the named warm entry and leaves the
    /// rest intact. Previously exercised only via the Docker-gated
    /// catalog-service integration tests, so it was invisible to the
    /// coverage lane; pin it directly here.
    #[tokio::test]
    async fn apply_change_evicts_only_the_named_entry() {
        use crate::subscribe::{BindingChange, BindingChangeKind};

        let (build, count, _) = counting_builder();
        let cache = Arc::new(CatalogProviderCache::new(build));

        cache.get("pg").await.unwrap();
        cache.get("mysql").await.unwrap();
        assert_eq!(cache.len(), 2);
        assert_eq!(count.load(Ordering::Relaxed), 2);

        // Upserted on "pg" evicts only "pg".
        CatalogProviderCache::apply_change(
            &cache,
            &BindingChange {
                org_id: "default".into(),
                name: "pg".into(),
                kind: BindingChangeKind::Upserted,
            },
        );
        assert_eq!(cache.len(), 1, "only the changed entry is evicted");

        // "pg" re-resolves (builder fires again); "mysql" stayed warm.
        cache.get("pg").await.unwrap();
        assert_eq!(count.load(Ordering::Relaxed), 3, "pg was re-resolved");
        cache.get("mysql").await.unwrap();
        assert_eq!(count.load(Ordering::Relaxed), 3, "mysql stayed warm");

        // Deleted evicts too.
        CatalogProviderCache::apply_change(
            &cache,
            &BindingChange {
                org_id: "default".into(),
                name: "mysql".into(),
                kind: BindingChangeKind::Deleted,
            },
        );
        assert_eq!(cache.len(), 1, "a Deleted change evicts as well");
    }

    /// End-to-end (no Docker): `start_invalidation` wires the store's
    /// `subscribe()` feed into the cache, so an upstream binding change
    /// evicts the warm entry. Driven through the in-memory
    /// `EmbeddedMetaStore` (its `upsert_binding` emits a `BindingChange`
    /// over a broadcast the invalidation task consumes). Covers the
    /// spawn→consume→evict loop that only the Postgres integration tests
    /// touched before.
    #[tokio::test]
    async fn start_invalidation_evicts_cache_on_upstream_binding_change() {
        use crate::embedded::EmbeddedMetaStore;
        use crate::store::MetaStore;
        use dataglot_core::catalog::{LiveConnectorBinding, LiveConnectorKind};
        use dataglot_core::CatalogBinding;

        let dir = tempfile::tempdir().expect("tempdir");
        let store: Arc<dyn MetaStore> = Arc::new(
            EmbeddedMetaStore::open(dir.path().join("meta.json"), "default")
                .await
                .expect("open embedded store"),
        );

        let (build, count, _) = counting_builder();
        let cache = Arc::new(CatalogProviderCache::new(build));
        cache.get("pg").await.unwrap();
        assert_eq!(cache.len(), 1);
        assert_eq!(count.load(Ordering::Relaxed), 1);

        // subscribe() is awaited inside start_invalidation before it returns,
        // so the receiver is registered before we emit below.
        let _handle = cache
            .start_invalidation(Arc::clone(&store))
            .await
            .expect("start invalidation");

        // An upstream binding upsert fires a BindingChange on the store's feed.
        let binding = CatalogBinding::LiveConnector(LiveConnectorBinding {
            kind: LiveConnectorKind::Postgres,
            endpoint_hint: "db.internal:5432".into(),
        });
        store
            .upsert_binding("default", "pg", &binding)
            .await
            .expect("upsert binding");

        // Eviction runs on the spawned task; poll for it with a bounded wait.
        let mut evicted = false;
        for _ in 0..200 {
            if cache.is_empty() {
                evicted = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        assert!(
            evicted,
            "cache must evict the warm entry after an upstream BindingChange"
        );
    }
}

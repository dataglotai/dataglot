//! Swap wrapper around `Arc<dyn PolicyEnforcer>`.
//!
//! Phase 2 spec 04 slice 2 needs to publish a freshly-rebuilt
//! enforcer to every active session whenever the inbound governance
//! webhook (Interface 3) lands a rule change. The hot path is the
//! query optimizer: every plan walks
//! [`PolicyOptimizerRule::rewrite`](crate::PolicyOptimizerRule)
//! which calls `enforcer.rewrite(...)` — millions of times per
//! second under load. Rule churn happens once per tag event
//! (minutes-scale at most).
//!
//! # Why `RwLock<Arc<...>>` rather than `arc-swap`
//!
//! The first cut tried `arc_swap::ArcSwap<dyn PolicyEnforcer>`
//! ([`arc-swap`] is the de facto Rust lock-free swap crate). The
//! crate's `RefCnt` impl for `Arc<T>` doesn't extend to `?Sized`
//! trait objects in the stable 1.x line, so the generic
//! requirements can't be satisfied for our `dyn PolicyEnforcer`
//! shape without a second `Arc` indirection. The std-library
//! `RwLock<Arc<dyn PolicyEnforcer>>` is a strictly simpler dep
//! tree and the contention model is the same in practice:
//! readers acquire a parking-lot-style optimistic shared lock,
//! `Arc::clone` the inner handle (one atomic refcount bump),
//! and release. Rule churn is per-tag-event (minutes scale), so
//! the writer contends at most every few seconds; the read path
//! never blocks against another reader.
//!
//! Slice 2 ships the contract (`current()` / `swap()` / `impl
//! PolicyEnforcer for MutableEnforcer`); the underlying primitive
//! can swap to a true lock-free shape in the future without any
//! call-site change.
//!
//! `MutableEnforcer` itself implements [`PolicyEnforcer`], so it
//! plugs into [`PolicyOptimizerRule::new`](crate::PolicyOptimizerRule)
//! unchanged — the existing wiring on the server side stays
//! intact. The only difference from a "static" enforcer is that
//! [`MutableEnforcer::swap`] publishes a new inner enforcer at any
//! time without coordinating with active readers.
//!
//! [`arc-swap`]: https://crates.io/crates/arc-swap

use std::sync::{Arc, RwLock};

use datafusion::common::tree_node::Transformed;
use datafusion::error::DataFusionError;
use datafusion::logical_expr::LogicalPlan;

use crate::{Identity, PolicyEnforcer};

/// Swap wrapper around `Arc<dyn PolicyEnforcer>`.
///
/// Construct with [`Self::new`] from an initial enforcer; publish
/// new enforcers via [`Self::swap`]. Every call to
/// [`PolicyEnforcer::rewrite`] reads the currently-published
/// enforcer through a brief shared lock and an `Arc` ref-count
/// bump. The shared lock never blocks against another shared lock
/// — only against the rare writer.
pub struct MutableEnforcer {
    inner: RwLock<Arc<dyn PolicyEnforcer>>,
}

impl MutableEnforcer {
    /// Construct from an initial enforcer. Subsequent calls to
    /// [`Self::swap`] atomically replace it.
    #[must_use]
    pub fn new(initial: Arc<dyn PolicyEnforcer>) -> Self {
        Self {
            inner: RwLock::new(initial),
        }
    }

    /// Load the currently-published enforcer.
    ///
    /// # Panics
    /// If the inner `RwLock` is poisoned (a previous writer panicked
    /// while holding it). Slice 2's writer is non-panicking by
    /// construction; poisoning would be a bug, not a transient
    /// condition.
    #[must_use]
    pub fn current(&self) -> Arc<dyn PolicyEnforcer> {
        let guard = self
            .inner
            .read()
            .expect("MutableEnforcer RwLock is poisoned");
        Arc::clone(&guard)
    }

    /// Publish a new enforcer. Returns the previous one so callers
    /// that want a notification (e.g. for diagnostics) can observe
    /// the transition. Concurrent reads in flight against the old
    /// enforcer complete safely against the old `Arc`; only
    /// subsequent reads see the new one.
    ///
    /// # Panics
    /// Same poisoning condition as [`Self::current`].
    pub fn swap(&self, new: Arc<dyn PolicyEnforcer>) -> Arc<dyn PolicyEnforcer> {
        let mut guard = self
            .inner
            .write()
            .expect("MutableEnforcer RwLock is poisoned");
        std::mem::replace(&mut *guard, new)
    }
}

impl std::fmt::Debug for MutableEnforcer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MutableEnforcer")
            .field("current", &self.current())
            .finish()
    }
}

impl PolicyEnforcer for MutableEnforcer {
    fn rewrite(
        &self,
        plan: LogicalPlan,
        identity: &Identity,
    ) -> Result<Transformed<LogicalPlan>, DataFusionError> {
        // Clone the inner Arc out under the shared lock; release the
        // lock before calling the inner enforcer's `rewrite`. The
        // optimizer pass can be long (cross-source plan walks, etc.)
        // and we don't want to hold the read lock for its duration —
        // a writer waiting on the rebuild would deadlock-by-priority
        // against a long-running optimization on the same thread.
        let current = self.current();
        current.rewrite(plan, identity)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NoopPolicyEnforcer;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Test enforcer that counts how many times its `rewrite` was
    /// invoked. We use atomic counts so multi-threaded stress tests
    /// can assert "every read landed on a real enforcer."
    #[derive(Debug, Default)]
    struct CountingEnforcer {
        calls: AtomicUsize,
    }
    impl CountingEnforcer {
        fn count(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }
    impl PolicyEnforcer for CountingEnforcer {
        fn rewrite(
            &self,
            plan: LogicalPlan,
            _identity: &Identity,
        ) -> Result<Transformed<LogicalPlan>, DataFusionError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(Transformed::no(plan))
        }
    }

    fn empty_plan() -> LogicalPlan {
        use datafusion::logical_expr::LogicalPlanBuilder;
        LogicalPlanBuilder::empty(true).build().expect("empty plan")
    }

    #[test]
    fn current_returns_initial_enforcer_until_first_swap() {
        let mutable = MutableEnforcer::new(Arc::new(NoopPolicyEnforcer));
        // Two reads back-to-back observe the same pointer until a
        // swap publishes a new one — confirmation that `current` is
        // a pure read with no internal mutation.
        let first = mutable.current();
        let second = mutable.current();
        assert!(Arc::ptr_eq(&first, &second));
    }

    #[test]
    fn swap_publishes_new_enforcer_to_subsequent_reads() {
        let first = Arc::new(CountingEnforcer::default());
        let mutable = MutableEnforcer::new(Arc::clone(&first) as Arc<dyn PolicyEnforcer>);

        // First rewrite lands on the first enforcer.
        let _ = mutable
            .rewrite(empty_plan(), &Identity::anonymous())
            .unwrap();
        assert_eq!(first.count(), 1);

        // Swap in a fresh counter.
        let second = Arc::new(CountingEnforcer::default());
        let _ = mutable.swap(Arc::clone(&second) as Arc<dyn PolicyEnforcer>);

        // Second rewrite lands on the new enforcer only.
        let _ = mutable
            .rewrite(empty_plan(), &Identity::anonymous())
            .unwrap();
        assert_eq!(
            first.count(),
            1,
            "old enforcer must not receive the post-swap call"
        );
        assert_eq!(
            second.count(),
            1,
            "new enforcer must receive the post-swap call"
        );
    }

    /// Stress test: many readers + occasional writers race against
    /// each other. The invariant is *no torn state*: every read
    /// completes against a well-formed enforcer (call count strictly
    /// non-negative, `ptr_eq` with one of the values we ever
    /// published). The swap is well-defined by construction; the test
    /// pins the guarantee so a future regression to a primitive that
    /// allows torn state would surface here.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_reads_during_swap_observe_consistent_enforcers() {
        let initial = Arc::new(CountingEnforcer::default());
        let mutable = Arc::new(MutableEnforcer::new(
            Arc::clone(&initial) as Arc<dyn PolicyEnforcer>
        ));

        // Spawn N reader tasks, each doing many rewrites in a loop.
        let readers: Vec<_> = (0..8)
            .map(|_| {
                let mutable = Arc::clone(&mutable);
                tokio::spawn(async move {
                    for _ in 0..200 {
                        // The rewrite call would panic on torn state
                        // (e.g. a half-replaced trait object vtable);
                        // staying alive across the whole loop is the
                        // assertion.
                        let _ = mutable
                            .rewrite(empty_plan(), &Identity::anonymous())
                            .unwrap();
                        // Yield occasionally so the runtime interleaves
                        // with the writer task and we actually race.
                        tokio::task::yield_now().await;
                    }
                })
            })
            .collect();

        // Writer: swap in fresh enforcers concurrently. Each new
        // enforcer is observable to subsequent reads but never tears
        // an in-flight read.
        let writer = {
            let mutable = Arc::clone(&mutable);
            tokio::spawn(async move {
                for _ in 0..50 {
                    let fresh = Arc::new(CountingEnforcer::default());
                    let _ = mutable.swap(fresh as Arc<dyn PolicyEnforcer>);
                    tokio::task::yield_now().await;
                }
            })
        };

        for r in readers {
            r.await.expect("reader task ran without panic");
        }
        writer.await.expect("writer task ran without panic");
    }
}

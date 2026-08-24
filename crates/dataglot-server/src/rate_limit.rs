//! Connection-level rate limiting for the pgwire listener (, ).
//!
//! Two accept-path controls, both part of the Phase 3 security-audit
//! remainder and composing with the auth + ingress-TLS slices (admission is
//! gated *before* the handshake — the cheapest possible rejection point):
//!
//! - **Concurrency ceilings** — a global and a per-source-IP cap on
//!   the number of *live* connections, so one client (or a burst) cannot
//!   exhaust the server's connection/task budget.
//! - **New-connection rate** — a per-source-IP token bucket bounding
//!   the *rate* of new connections, the brute-force / churn defense the
//!   concurrency ceilings don't cover (a client that opens and closes fast).
//!
//! Enforcement is a single [`ConnectionLimiter::try_admit`] call on the
//! accept path; the returned [`ConnectionPermit`] releases the reserved
//! concurrency slot(s) on drop — including on panic or early return anywhere
//! in the connection handler. (The rate check consumes a token but holds no
//! releasable slot — tokens refill over time.)

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use dataglot_pgwire::{IdentityAdmission, IdentityLimited, IdentityPermit};
use prometheus::IntCounterVec;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::config::RateLimitConfig;

/// Shared live-connection counts keyed by source IP.
type PerIpCounts = Arc<Mutex<HashMap<IpAddr, usize>>>;

/// Shared per-source-IP token buckets for the new-connection *rate* limit.
type PerIpBuckets = Arc<Mutex<HashMap<IpAddr, TokenBucket>>>;

/// Token-bucket parameters for the per-IP connection-rate limit.
#[derive(Debug, Clone, Copy)]
struct RateParams {
    /// Maximum tokens the bucket holds (the allowed burst).
    capacity: f64,
    /// Tokens added per second (the steady-state rate).
    refill_per_sec: f64,
}

/// A per-IP token bucket: `tokens` available now, last refilled at `last`.
#[derive(Debug)]
struct TokenBucket {
    tokens: f64,
    last: Instant,
}

/// Why a connection was refused admission — the label on the rejection
/// metric and audit event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectReason {
    /// The global concurrent-connection ceiling was reached.
    Global,
    /// The per-source-IP concurrent-connection ceiling was reached.
    PerIp,
    /// The per-source-IP new-connection *rate* (token bucket) was exceeded.
    RateIp,
}

impl RejectReason {
    /// Stable, low-cardinality string for the metric label / audit field.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            RejectReason::Global => "global",
            RejectReason::PerIp => "per_ip",
            RejectReason::RateIp => "rate_ip",
        }
    }
}

/// Enforces the pgwire accept-path limits: global + per-IP concurrency
/// ceilings and a per-IP new-connection rate (token bucket).
///
/// Cheap to [`Clone`] (all state is shared by `Arc`), so the server holds
/// one and each connection borrows it. A limiter with no limits set admits
/// unconditionally — but the server only constructs one when a
/// `[rate_limit]` block is present, so the no-limit path is defensive.
#[derive(Clone)]
pub struct ConnectionLimiter {
    /// `Some` when a global ceiling is configured; its permits meter the
    /// total number of live connections.
    global: Option<Arc<Semaphore>>,
    /// The per-IP ceiling, if configured.
    per_ip_max: Option<usize>,
    /// Live connection count per source IP. Entries are removed when their
    /// count returns to zero, so churned IPs do not accumulate.
    per_ip: PerIpCounts,
    /// Token-bucket parameters for the per-IP new-connection rate limit, if
    /// configured.
    per_ip_rate: Option<RateParams>,
    /// Per-IP token buckets backing the rate limit.
    buckets: PerIpBuckets,
}

impl ConnectionLimiter {
    /// Build a limiter from the `[rate_limit]` config.
    #[must_use]
    pub fn new(cfg: &RateLimitConfig) -> Self {
        Self {
            global: cfg.max_connections.map(|n| Arc::new(Semaphore::new(n))),
            per_ip_max: cfg.max_connections_per_ip,
            per_ip: Arc::new(Mutex::new(HashMap::new())),
            per_ip_rate: cfg.max_new_connections_per_ip_per_minute.map(|n| {
                // Capacity = the per-minute allowance (the burst); refill at
                // that many tokens spread across 60s. `max(1.0)` keeps a
                // configured `0` from wedging the limiter shut in a way the
                // operator likely didn't intend (it still throttles hard).
                let per_min = f64::from(n).max(1.0);
                RateParams {
                    capacity: per_min,
                    refill_per_sec: per_min / 60.0,
                }
            }),
            buckets: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Try to admit a connection from `ip`.
    ///
    /// Checks the per-IP rate first, then the global slot, then the per-IP
    /// slot; if the per-IP ceiling is hit the already-acquired global permit
    /// is released before returning. On success the returned
    /// [`ConnectionPermit`] holds both concurrency reservations until dropped.
    ///
    /// # Errors
    /// Returns the [`RejectReason`] for the first exhausted ceiling.
    ///
    /// # Panics
    /// Panics only if an internal lock is poisoned — i.e. a previous holder
    /// panicked mid-update, which cannot happen in the tiny non-panicking
    /// critical sections here.
    pub fn try_admit(&self, ip: IpAddr) -> Result<ConnectionPermit, RejectReason> {
        self.admit_at(ip, Instant::now())
    }

    /// [`Self::try_admit`] with an injected clock, so the token-bucket rate
    /// limit is unit-testable without sleeping.
    fn admit_at(&self, ip: IpAddr, now: Instant) -> Result<ConnectionPermit, RejectReason> {
        // Rate limit first — it's the brute-force / churn gate and holds no
        // permit, so a rejection here costs nothing downstream. Because it
        // runs before the concurrency checks, it counts every *attempt* from
        // an IP (including ones the concurrency ceilings then reject), which
        // is the behavior a brute-force defense wants.
        if let Some(params) = self.per_ip_rate {
            let mut buckets = self.buckets.lock().expect("rate-bucket lock poisoned");
            let bucket = buckets.entry(ip).or_insert(TokenBucket {
                tokens: params.capacity,
                last: now,
            });
            // Refill for elapsed time (saturating so a non-monotonic clock or
            // out-of-order call can't underflow), capped at capacity.
            let elapsed = now.saturating_duration_since(bucket.last).as_secs_f64();
            bucket.tokens = (bucket.tokens + elapsed * params.refill_per_sec).min(params.capacity);
            bucket.last = now;
            if bucket.tokens < 1.0 {
                return Err(RejectReason::RateIp);
            }
            bucket.tokens -= 1.0;
        }

        // Global next. `try_acquire_owned` never blocks; it errors when no
        // permit is available (or the semaphore was closed, which we never do).
        let global_permit = match &self.global {
            Some(sem) => Some(
                Arc::clone(sem)
                    .try_acquire_owned()
                    .map_err(|_| RejectReason::Global)?,
            ),
            None => None,
        };

        // Then per-IP. The lock is held only for this increment — no `.await`
        // is taken while holding it (rule 11).
        if let Some(max) = self.per_ip_max {
            let mut map = self.per_ip.lock().expect("per-IP lock poisoned");
            let count = map.entry(ip).or_insert(0);
            if *count >= max {
                // `global_permit` drops here, releasing the global slot.
                return Err(RejectReason::PerIp);
            }
            *count += 1;
        }

        Ok(ConnectionPermit {
            _global: global_permit,
            per_ip: self.per_ip_max.map(|_| (Arc::clone(&self.per_ip), ip)),
        })
    }
}

/// RAII reservation of one connection's rate-limit slot(s). Dropping it
/// releases the global semaphore permit and decrements the per-IP count.
pub struct ConnectionPermit {
    /// Held to keep the global semaphore slot reserved; released on drop.
    _global: Option<OwnedSemaphorePermit>,
    /// `Some((map, ip))` when a per-IP ceiling is active — drop decrements
    /// `map[ip]` and removes the entry at zero.
    per_ip: Option<(PerIpCounts, IpAddr)>,
}

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        if let Some((map, ip)) = &self.per_ip {
            let mut m = map.lock().expect("per-IP lock poisoned");
            if let Some(count) = m.get_mut(ip) {
                *count -= 1;
                if *count == 0 {
                    m.remove(ip);
                }
            }
        }
        // `_global` releases its permit on drop automatically.
    }
}

/// Bounds concurrent connections **per authenticated identity** (username),
/// implementing the pgwire [`IdentityAdmission`] hook. Unlike the
/// [`ConnectionLimiter`] (which keys on source IP at the TCP accept path),
/// this keys on the username asserted in the pgwire startup message, so it
/// caps how many connections one role holds at once regardless of origin.
///
/// `admit(user)` increments a per-username counter and returns a guard that
/// decrements it on drop (the pgwire handler holds the guard for the
/// connection's lifetime); over the cap it refuses with [`IdentityLimited`],
/// which pgwire maps to a `53300` fatal — and here bumps
/// `dataglot_pgwire_connections_rejected_total{reason="identity"}` and emits
/// a `dataglot::audit` event.
#[derive(Clone)]
pub struct IdentityLimiter {
    max: usize,
    counts: Arc<Mutex<HashMap<String, usize>>>,
    /// `dataglot_pgwire_connections_rejected_total`, bumped on refusal.
    rejected: IntCounterVec,
}

impl IdentityLimiter {
    /// Build a limiter capping each identity at `max` concurrent connections,
    /// bumping `rejected{reason="identity"}` on refusal.
    #[must_use]
    pub fn new(max: usize, rejected: IntCounterVec) -> Self {
        Self {
            max,
            counts: Arc::new(Mutex::new(HashMap::new())),
            rejected,
        }
    }
}

impl IdentityAdmission for IdentityLimiter {
    fn admit(&self, user: &str) -> Result<IdentityPermit, IdentityLimited> {
        let mut counts = self.counts.lock().expect("identity-count lock poisoned");
        let n = counts.entry(user.to_owned()).or_insert(0);
        if *n >= self.max {
            drop(counts);
            self.rejected.with_label_values(&["identity"]).inc();
            // Audit-visible (same target as auth failures); user only — no
            // credential is in scope here (rule 12).
            tracing::warn!(
                target: "dataglot::audit",
                action = "connection_rejected",
                user = user,
                reason = "identity",
                "connection refused: identity connection limit reached"
            );
            return Err(IdentityLimited);
        }
        *n += 1;
        Ok(Box::new(IdentityGuard {
            counts: Arc::clone(&self.counts),
            user: user.to_owned(),
        }))
    }
}

/// RAII guard decrementing an identity's live-connection count on drop (and
/// removing the entry at zero, so churned identities don't accumulate).
struct IdentityGuard {
    counts: Arc<Mutex<HashMap<String, usize>>>,
    user: String,
}

impl Drop for IdentityGuard {
    fn drop(&mut self) {
        let mut counts = self.counts.lock().expect("identity-count lock poisoned");
        if let Some(n) = counts.get_mut(&self.user) {
            *n -= 1;
            if *n == 0 {
                counts.remove(&self.user);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("valid IP")
    }

    /// A throwaway rejection counter for the identity-limiter tests.
    fn rejected_counter() -> IntCounterVec {
        IntCounterVec::new(
            prometheus::Opts::new("test_rejected_total", "test"),
            &["reason"],
        )
        .expect("counter builds")
    }

    fn cfg(global: Option<usize>, per_ip: Option<usize>) -> RateLimitConfig {
        RateLimitConfig {
            max_connections: global,
            max_connections_per_ip: per_ip,
            max_new_connections_per_ip_per_minute: None,
            max_connections_per_identity: None,
        }
    }

    /// A config with only the per-IP new-connection rate limit set.
    fn rate_cfg(per_min: u32) -> RateLimitConfig {
        RateLimitConfig {
            max_connections: None,
            max_connections_per_ip: None,
            max_new_connections_per_ip_per_minute: Some(per_min),
            max_connections_per_identity: None,
        }
    }

    #[test]
    fn no_caps_admits_unconditionally() {
        let limiter = ConnectionLimiter::new(&cfg(None, None));
        // Hold many permits at once; all admit.
        let permits: Vec<_> = (0..100)
            .map(|_| limiter.try_admit(ip("10.0.0.1")).expect("admitted"))
            .collect();
        assert_eq!(permits.len(), 100);
        drop(permits);
    }

    #[test]
    fn global_cap_rejects_beyond_ceiling() {
        let limiter = ConnectionLimiter::new(&cfg(Some(1), None));
        let _p1 = limiter.try_admit(ip("10.0.0.1")).expect("first admitted");
        // Second, even from a different IP, hits the global ceiling.
        assert!(matches!(
            limiter.try_admit(ip("10.0.0.2")),
            Err(RejectReason::Global)
        ));
    }

    #[test]
    fn global_slot_freed_on_drop() {
        let limiter = ConnectionLimiter::new(&cfg(Some(1), None));
        {
            let _p = limiter.try_admit(ip("10.0.0.1")).expect("first admitted");
            assert!(matches!(
                limiter.try_admit(ip("10.0.0.1")),
                Err(RejectReason::Global)
            ));
        }
        // The first permit dropped at the end of the block → slot is free.
        limiter
            .try_admit(ip("10.0.0.1"))
            .expect("admitted after release");
    }

    #[test]
    fn per_ip_cap_rejects_same_ip_but_not_others() {
        let limiter = ConnectionLimiter::new(&cfg(None, Some(2)));
        let a = ip("10.0.0.1");
        let _p1 = limiter.try_admit(a).expect("1st from a");
        let _p2 = limiter.try_admit(a).expect("2nd from a");
        assert!(matches!(limiter.try_admit(a), Err(RejectReason::PerIp)));
        // A different IP is unaffected by a's saturation.
        limiter
            .try_admit(ip("10.0.0.2"))
            .expect("other IP admitted");
    }

    #[test]
    fn per_ip_slot_freed_on_drop_and_entry_removed() {
        let limiter = ConnectionLimiter::new(&cfg(None, Some(1)));
        let a = ip("10.0.0.1");
        {
            let _p = limiter.try_admit(a).expect("admitted");
            assert!(matches!(limiter.try_admit(a), Err(RejectReason::PerIp)));
        }
        // Count returned to zero → entry removed → fresh admit succeeds.
        assert!(limiter.per_ip.lock().unwrap().is_empty());
        limiter.try_admit(a).expect("admitted after release");
    }

    #[test]
    fn per_ip_rejection_does_not_consume_global_slot() {
        // Global has room for 2; per-IP allows 1. A second connection from
        // the same IP must be rejected on PerIp *and* leave the global slot
        // available for a different IP.
        let limiter = ConnectionLimiter::new(&cfg(Some(2), Some(1)));
        let a = ip("10.0.0.1");
        let _p1 = limiter.try_admit(a).expect("1st from a");
        assert!(matches!(limiter.try_admit(a), Err(RejectReason::PerIp)));
        // If the PerIp rejection had leaked a global permit, only 1 global
        // slot would remain and this could still pass; but a third distinct
        // IP proves 2 global slots are usable in total.
        let _p2 = limiter
            .try_admit(ip("10.0.0.2"))
            .expect("2nd global slot free");
        assert!(
            matches!(limiter.try_admit(ip("10.0.0.3")), Err(RejectReason::Global)),
            "global ceiling of 2 now reached"
        );
    }

    #[test]
    fn per_ip_rate_allows_burst_then_throttles() {
        // 60/min ⇒ capacity 60, refill 1/sec. A fresh bucket starts full, so
        // 60 connections at the same instant are admitted, the 61st is not.
        let limiter = ConnectionLimiter::new(&rate_cfg(60));
        let a = ip("10.0.0.1");
        let t0 = Instant::now();
        for i in 0..60 {
            limiter
                .admit_at(a, t0)
                .unwrap_or_else(|_| panic!("burst conn {i} within capacity"));
        }
        assert!(
            matches!(limiter.admit_at(a, t0), Err(RejectReason::RateIp)),
            "61st connection in the same instant is throttled"
        );
    }

    #[test]
    fn per_ip_rate_refills_over_time() {
        let limiter = ConnectionLimiter::new(&rate_cfg(60)); // 1 token/sec
        let a = ip("10.0.0.1");
        let t0 = Instant::now();
        // Drain the full burst.
        for _ in 0..60 {
            limiter.admit_at(a, t0).expect("burst");
        }
        assert!(matches!(limiter.admit_at(a, t0), Err(RejectReason::RateIp)));
        // One second later ≈ one token refilled: exactly one more admits.
        let t1 = t0 + std::time::Duration::from_secs(1);
        limiter
            .admit_at(a, t1)
            .expect("one token refilled after 1s");
        assert!(
            matches!(limiter.admit_at(a, t1), Err(RejectReason::RateIp)),
            "only one token had refilled"
        );
    }

    #[test]
    fn per_ip_rate_is_independent_across_ips() {
        let limiter = ConnectionLimiter::new(&rate_cfg(1)); // capacity 1
        let t0 = Instant::now();
        limiter.admit_at(ip("10.0.0.1"), t0).expect("a's one token");
        assert!(matches!(
            limiter.admit_at(ip("10.0.0.1"), t0),
            Err(RejectReason::RateIp)
        ));
        // A different IP has its own full bucket.
        limiter
            .admit_at(ip("10.0.0.2"), t0)
            .expect("b's own bucket");
    }

    #[test]
    fn rate_counts_attempts_including_concurrency_rejections() {
        // Rate 2/min (capacity 2) + per-IP concurrency 1. Because the rate
        // gate is checked first, an attempt that is subsequently rejected by
        // the concurrency ceiling still spends a rate token — the rate limit
        // bounds connection *attempts* per IP, which is the correct behavior
        // for a brute-force / churn defense.
        let cfg = RateLimitConfig {
            max_connections: None,
            max_connections_per_ip: Some(1),
            max_new_connections_per_ip_per_minute: Some(2),
            max_connections_per_identity: None,
        };
        let limiter = ConnectionLimiter::new(&cfg);
        let a = ip("10.0.0.1");
        let t0 = Instant::now();

        let p1 = limiter.admit_at(a, t0).expect("first admits"); // rate 2→1, conc 0→1
                                                                 // Second attempt: rate 1→0 is spent, then concurrency (held by p1)
                                                                 // rejects it.
        assert!(matches!(limiter.admit_at(a, t0), Err(RejectReason::PerIp)));

        // Free the concurrency slot. The rate bucket is nonetheless empty —
        // the rejected attempt above counted — so the next attempt is
        // throttled on rate, not admitted.
        drop(p1);
        assert!(
            matches!(limiter.admit_at(a, t0), Err(RejectReason::RateIp)),
            "the concurrency-rejected attempt still consumed a rate token"
        );
    }

    #[test]
    fn identity_limiter_caps_per_user_and_frees_on_drop() {
        let limiter = IdentityLimiter::new(1, rejected_counter());
        let g1 = limiter.admit("alice").expect("alice's first connection");
        // alice is at her cap of 1.
        assert!(limiter.admit("alice").is_err(), "alice over cap");
        // A different identity is unaffected.
        let _g_bob = limiter.admit("bob").expect("bob has his own budget");
        // Freeing alice's connection lets her reconnect.
        drop(g1);
        let _g2 = limiter.admit("alice").expect("readmitted after release");
    }

    #[test]
    fn identity_limiter_removes_entry_at_zero() {
        let limiter = IdentityLimiter::new(2, rejected_counter());
        {
            let _g1 = limiter.admit("carol").expect("1st");
            let _g2 = limiter.admit("carol").expect("2nd");
            assert!(limiter.admit("carol").is_err(), "carol over cap of 2");
        }
        // Both guards dropped → count zero → entry removed.
        assert!(limiter.counts.lock().unwrap().is_empty());
        // Rejection was counted on the metric.
        assert_eq!(limiter.rejected.with_label_values(&["identity"]).get(), 1);
    }
}

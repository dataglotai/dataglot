//! Phase 2 slice 5b — object-store ETag scheduler HA.
//!
//! Architecture §12's "no etcd, no ZooKeeper, no Redis" commitment.
//! Two scheduler replicas coordinate exclusively through S3 / ADLS /
//! GCS conditional writes (`If-None-Match` for first claim,
//! `If-Match` on the ETag for heartbeat updates). The pattern is
//! identical to Kubernetes' coordination-API lease primitive, but
//! backed by object storage instead of etcd.
//!
//! # State machine
//!
//! Each scheduler instance picks a `holder_id` (UUIDv4) at startup
//! and runs the following loop:
//!
//! 1. **Try claim.** `PutMode::Create` on the lease path. On success,
//!    we're the leader; the returned `ETag` is our heartbeat token.
//! 2. **On `AlreadyExists`:** read the current lease. If
//!    `expires_at` is in the past, try to steal it via
//!    `PutMode::Update(stale_etag)`. On success, we're the leader.
//!    On `Precondition`, somebody else stole it first — back to step 1
//!    after a sleep.
//! 3. **Heartbeat (leader only).** Every `heartbeat_interval`,
//!    refresh the lease with `PutMode::Update(current_etag)`, extending
//!    `expires_at`. On success, the returned ETag becomes the new
//!    heartbeat token. On `Precondition`, we lost leadership — abort
//!    the scheduler service and return to step 1.
//!
//! # What this module proves
//!
//! - ✅ One claimer succeeds; concurrent claimer is rejected
//!   (`PutMode::Create` semantics).
//! - ✅ Lease expiry → second claimer takes over via
//!   `PutMode::Update(stale_etag)`.
//! - ✅ Holder loses ETag race → next heartbeat fails with
//!   `Precondition`, surfacing the lost-leadership signal to the
//!   caller.
//!
//! # What this module doesn't cover
//!
//! - **Job state persistence across leader failover.** The Ballista
//!   `JobState` impl is in-memory per-scheduler today; in-flight
//!   jobs at the moment of a leader crash are lost. Clients
//!   re-submit. Persistent job state is a deeper upstream
//!   change and out of scope for slice 5b.
//! - **Graceful scheduler shutdown on lease loss.** This module
//!   surfaces "leadership lost"; the binary that consumes the
//!   stream is expected to `abort()` its scheduler task. Brief
//!   port-rebind races during rapid failover may produce
//!   "address already in use" — production fix is a graceful-
//!   shutdown signal threaded through Ballista's `start_server`.
//!   Tracked as a Phase 2 follow-up.

use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use object_store::path::Path as ObjectPath;
use object_store::{
    Error as OsError, ObjectStore, ObjectStoreExt, PutMode, PutOptions, UpdateVersion,
};
use serde::{Deserialize, Serialize};

/// On-disk lease payload — serialized as JSON inside the lease object.
///
/// `expires_at` is RFC 3339 UTC. Followers check it against their
/// local clock to decide whether the lease is stealable; the
/// `e_tag` returned by `object_store` is the canonical concurrency
/// token, but `expires_at` lets a follower decide *whether* to even
/// attempt a steal before they pay the round-trip.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeasePayload {
    /// Random per-instance ID picked at startup. Lets a holder
    /// distinguish "still mine" from "leader changed."
    pub holder_id: String,
    /// When the lease expires. The holder is expected to heartbeat
    /// before this point or lose leadership.
    pub expires_at: DateTime<Utc>,
}

/// Outcome of a claim attempt.
#[derive(Debug)]
pub enum ClaimOutcome {
    /// We won the lease. `etag` is the heartbeat token to use on
    /// the next refresh.
    Acquired {
        /// Concurrency token for the next `heartbeat` call. Pass
        /// it back unchanged; each successful heartbeat returns
        /// a fresh ETag superseding this one.
        etag: String,
        /// Lease payload we wrote — copy of what's now persisted.
        payload: LeasePayload,
    },
    /// Someone else holds the lease. The payload reflects the
    /// current state at the time of read.
    HeldByOther {
        /// Current lease payload (holder ID + expiry) as read
        /// from object-store.
        payload: LeasePayload,
    },
}

/// Errors raised by the lease state machine.
///
/// Distinct from `object_store::Error` so callers can branch on
/// "I lost leadership" vs "the backend is unreachable" without
/// pattern-matching `object_store`'s deeper error surface.
#[derive(Debug, thiserror::Error)]
pub enum LeaseError {
    /// Our last heartbeat raced with a competing writer and lost.
    /// Caller should drop scheduler state and re-enter the claim
    /// loop.
    #[error("leadership lost — another holder wrote to the lease since our last refresh")]
    LeadershipLost,
    /// Object-store backend failure (network, permissions, etc.).
    #[error("object-store backend error: {0}")]
    Backend(String),
    /// On-disk lease payload didn't parse. Most likely indicates
    /// schema drift between scheduler versions; surfaces here so
    /// operators can investigate rather than silently treating
    /// the lease as expired.
    #[error("lease payload at `{path}` is malformed: {source}")]
    Malformed {
        /// Object-store path the malformed payload was read from.
        path: String,
        /// Underlying serde failure.
        source: serde_json::Error,
    },
}

impl From<OsError> for LeaseError {
    fn from(value: OsError) -> Self {
        Self::Backend(value.to_string())
    }
}

/// Coordination handle. Carries the object store + lease path +
/// this instance's `holder_id` + the lease duration. Cheap clone
/// (`Arc<dyn ObjectStore>`); single instance per scheduler process.
#[derive(Clone)]
pub struct ObjectStoreLease {
    store: Arc<dyn ObjectStore>,
    path: ObjectPath,
    holder_id: String,
    lease_duration: Duration,
}

/// Extract the ETag an object store returned for a write/read, or fail with
/// [`LeaseError::Backend`]. The whole HA scheme rests on `PutMode::Update(etag)`
/// conditional writes; a backend that omits `ETag`s (some S3-compatible / GCS
/// setups) can't provide that, and silently proceeding would let two schedulers
/// both believe they hold the lease (split-brain). So a missing ETag is a hard
/// backend error, never ignored. `op` names the operation for the message
/// (`Create` / `Update` / `Get`).
fn require_etag(e_tag: Option<String>, op: &str) -> Result<String, LeaseError> {
    e_tag.ok_or_else(|| {
        LeaseError::Backend(format!(
            "object store didn't return an ETag on {op} — conditional-update \
             semantics unavailable on this backend"
        ))
    })
}

impl ObjectStoreLease {
    /// Build a lease handle.
    ///
    /// `holder_id` should be unique per scheduler instance — a
    /// UUIDv4 is the canonical choice. `lease_duration` is how long
    /// each granted lease holds before becoming stealable; tune in
    /// concert with `heartbeat_interval` (heartbeat should fire at
    /// least 2-3× per lease window to absorb clock drift +
    /// transient backend latency).
    pub fn new(
        store: Arc<dyn ObjectStore>,
        path: ObjectPath,
        holder_id: String,
        lease_duration: Duration,
    ) -> Self {
        Self {
            store,
            path,
            holder_id,
            lease_duration,
        }
    }

    /// Borrow this instance's holder ID — useful for logging +
    /// follower-side "is this our lease?" checks.
    #[must_use]
    pub fn holder_id(&self) -> &str {
        &self.holder_id
    }

    /// Try to claim the lease.
    ///
    /// Returns `Acquired` if we won (no existing lease or the
    /// existing one was stealable due to expiry). Returns
    /// `HeldByOther` if a live lease is still in force.
    ///
    /// # Errors
    /// - [`LeaseError::Backend`] on object-store network / permission
    ///   failures.
    /// - [`LeaseError::Malformed`] if an existing payload can't be
    ///   parsed.
    ///
    /// # Panics
    /// Panics if the lease payload cannot be serialised to JSON —
    /// `LeasePayload` is a fixed shape with always-serialisable
    /// fields (String + RFC 3339 timestamp), so this is a "should
    /// never happen" guard for an in-process invariant.
    pub async fn try_claim(&self) -> Result<ClaimOutcome, LeaseError> {
        let payload = self.fresh_payload();
        let bytes = serde_json::to_vec(&payload).expect("serialise lease payload");

        // Step 1: optimistic Create.
        match self
            .store
            .put_opts(
                &self.path,
                bytes.clone().into(),
                PutOptions::from(PutMode::Create),
            )
            .await
        {
            Ok(result) => {
                let etag = require_etag(result.e_tag, "Create")?;
                return Ok(ClaimOutcome::Acquired { etag, payload });
            }
            Err(OsError::AlreadyExists { .. }) => {
                // Fall through to step 2 — read + maybe steal.
            }
            Err(e) => return Err(LeaseError::from(e)),
        }

        // Step 2: read the existing lease + decide whether to steal.
        let (existing_payload, stale_etag) = self.read_payload().await?;
        if existing_payload.expires_at > Utc::now() {
            return Ok(ClaimOutcome::HeldByOther {
                payload: existing_payload,
            });
        }

        // Lease is stale — try to steal via conditional update.
        let new_payload = self.fresh_payload();
        let new_bytes = serde_json::to_vec(&new_payload).expect("serialise lease payload");
        match self
            .store
            .put_opts(
                &self.path,
                new_bytes.into(),
                PutOptions::from(PutMode::Update(UpdateVersion {
                    e_tag: Some(stale_etag),
                    version: None,
                })),
            )
            .await
        {
            Ok(result) => {
                let etag = require_etag(result.e_tag, "Update")?;
                Ok(ClaimOutcome::Acquired {
                    etag,
                    payload: new_payload,
                })
            }
            Err(OsError::Precondition { .. }) => {
                // Lost the race — another follower stole it.
                // Re-read to surface the new holder's payload.
                let (now_held, _) = self.read_payload().await?;
                Ok(ClaimOutcome::HeldByOther { payload: now_held })
            }
            Err(e) => Err(LeaseError::from(e)),
        }
    }

    /// Refresh the lease, extending `expires_at` by another
    /// `lease_duration` from now.
    ///
    /// Returns the new ETag — pass it back on the next heartbeat.
    ///
    /// # Errors
    /// - [`LeaseError::LeadershipLost`] if the stored ETag no longer
    ///   matches `current_etag`. Caller should abort scheduler
    ///   state and re-enter the claim loop.
    /// - [`LeaseError::Backend`] on object-store failure.
    ///
    /// # Panics
    /// Panics if the lease payload cannot be serialised to JSON —
    /// see [`Self::try_claim`] for the same invariant rationale.
    pub async fn heartbeat(&self, current_etag: &str) -> Result<String, LeaseError> {
        let payload = self.fresh_payload();
        let bytes = serde_json::to_vec(&payload).expect("serialise lease payload");
        match self
            .store
            .put_opts(
                &self.path,
                bytes.into(),
                PutOptions::from(PutMode::Update(UpdateVersion {
                    e_tag: Some(current_etag.to_string()),
                    version: None,
                })),
            )
            .await
        {
            Ok(result) => require_etag(result.e_tag, "Update"),
            Err(OsError::Precondition { .. }) => Err(LeaseError::LeadershipLost),
            Err(e) => Err(LeaseError::from(e)),
        }
    }

    /// Read the current lease payload + its ETag.
    async fn read_payload(&self) -> Result<(LeasePayload, String), LeaseError> {
        let result = self.store.get(&self.path).await?;
        let etag = require_etag(result.meta.e_tag.clone(), "Get")?;
        let bytes = result.bytes().await?;
        let payload: LeasePayload =
            serde_json::from_slice(&bytes).map_err(|source| LeaseError::Malformed {
                path: self.path.to_string(),
                source,
            })?;
        Ok((payload, etag))
    }

    /// Build a fresh `LeasePayload` with `expires_at = now +
    /// lease_duration`.
    fn fresh_payload(&self) -> LeasePayload {
        LeasePayload {
            holder_id: self.holder_id.clone(),
            expires_at: Utc::now() + self.lease_duration,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use object_store::memory::InMemory;

    /// Convenience constructor — `InMemory` backend with a fresh
    /// lease path. Each test gets its own backend so they don't
    /// race each other.
    fn build_test_lease(holder: &str, lease_secs: u64) -> (Arc<dyn ObjectStore>, ObjectStoreLease) {
        let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let lease = ObjectStoreLease::new(
            Arc::clone(&store),
            ObjectPath::from("scheduler-lease.json"),
            holder.to_string(),
            Duration::from_secs(lease_secs),
        );
        (store, lease)
    }

    /// Build a second lease handle pointing at the same object
    /// store as the first — both racing for the same path. This
    /// is the two-scheduler simulation.
    fn second_claimer(
        store: Arc<dyn ObjectStore>,
        holder: &str,
        lease_secs: u64,
    ) -> ObjectStoreLease {
        ObjectStoreLease::new(
            store,
            ObjectPath::from("scheduler-lease.json"),
            holder.to_string(),
            Duration::from_secs(lease_secs),
        )
    }

    /// Single claimer succeeds and the returned payload reflects
    /// our `holder_id` + a sensible `expires_at`.
    #[tokio::test]
    async fn single_claim_succeeds() {
        let (_store, lease) = build_test_lease("scheduler-a", 30);
        match lease.try_claim().await.expect("claim succeeds") {
            ClaimOutcome::Acquired { etag, payload } => {
                assert!(!etag.is_empty(), "Acquired must carry a non-empty ETag");
                assert_eq!(payload.holder_id, "scheduler-a");
                assert!(
                    payload.expires_at > Utc::now(),
                    "expires_at must be in the future, got {}",
                    payload.expires_at
                );
            }
            ClaimOutcome::HeldByOther { .. } => panic!("expected Acquired, got HeldByOther"),
        }
    }

    /// Concurrent claimer against a live lease is rejected.
    #[tokio::test]
    async fn second_claimer_rejected_while_live() {
        let (store, first) = build_test_lease("scheduler-a", 30);
        let second = second_claimer(Arc::clone(&store), "scheduler-b", 30);

        // First wins.
        let ClaimOutcome::Acquired { .. } = first.try_claim().await.expect("first claim") else {
            panic!("first should win");
        };

        // Second is rejected; payload reports scheduler-a holds it.
        match second.try_claim().await.expect("second sees holder") {
            ClaimOutcome::HeldByOther { payload } => {
                assert_eq!(payload.holder_id, "scheduler-a");
            }
            ClaimOutcome::Acquired { .. } => {
                panic!("expected HeldByOther, got Acquired")
            }
        }
    }

    /// Holder can refresh — the heartbeat returns a fresh ETag.
    /// Each successful heartbeat produces a NEW ETag, so chained
    /// heartbeats need to thread the ETag through.
    #[tokio::test]
    async fn holder_can_heartbeat() {
        let (_store, lease) = build_test_lease("scheduler-a", 30);
        let ClaimOutcome::Acquired { etag: etag1, .. } = lease.try_claim().await.expect("claim")
        else {
            panic!("should win");
        };
        let etag2 = lease.heartbeat(&etag1).await.expect("heartbeat succeeds");
        assert_ne!(
            etag1, etag2,
            "successive heartbeats must produce distinct ETags"
        );
        // And a chained heartbeat with the NEW etag also works.
        let etag3 = lease.heartbeat(&etag2).await.expect("second heartbeat");
        assert_ne!(etag2, etag3);
    }

    /// Holder's heartbeat fails after a competing writer stole the
    /// lease (simulated by directly overwriting with `Overwrite`).
    /// This is the load-bearing leadership-lost signal — the binary
    /// reacts by aborting the scheduler service.
    #[tokio::test]
    async fn heartbeat_fails_after_external_overwrite() {
        let (store, lease) = build_test_lease("scheduler-a", 30);
        let ClaimOutcome::Acquired { etag, .. } = lease.try_claim().await.expect("claim") else {
            panic!("should win");
        };

        // Simulate scheduler-b stealing by writing a new payload
        // with `Overwrite` semantics. The ETag changes on the
        // backend; our stored `etag` is now stale.
        let stolen = LeasePayload {
            holder_id: "scheduler-b".to_string(),
            expires_at: Utc::now() + Duration::from_secs(30),
        };
        let bytes = serde_json::to_vec(&stolen).expect("serialise");
        store
            .put_opts(
                &ObjectPath::from("scheduler-lease.json"),
                bytes.into(),
                PutOptions::default(),
            )
            .await
            .expect("external overwrite");

        // Next heartbeat with the stale ETag must surface
        // LeadershipLost.
        let err = lease
            .heartbeat(&etag)
            .await
            .expect_err("heartbeat must fail after external overwrite");
        assert!(
            matches!(err, LeaseError::LeadershipLost),
            "expected LeadershipLost, got {err:?}"
        );
    }

    /// Lease expiry: scheduler-b can take over once scheduler-a's
    /// lease window has passed.
    #[tokio::test]
    async fn second_claimer_takes_over_after_expiry() {
        // 1-second lease so the test runs quickly.
        let (store, first) = build_test_lease("scheduler-a", 1);
        let second = second_claimer(Arc::clone(&store), "scheduler-b", 1);

        let ClaimOutcome::Acquired { .. } = first.try_claim().await.expect("first claim") else {
            panic!("first should win");
        };

        // Wait past the lease window.
        tokio::time::sleep(Duration::from_millis(1_100)).await;

        // Second should now win via PutMode::Update(stale_etag).
        match second.try_claim().await.expect("second claim") {
            ClaimOutcome::Acquired { payload, .. } => {
                assert_eq!(payload.holder_id, "scheduler-b");
            }
            ClaimOutcome::HeldByOther { .. } => {
                panic!("expected Acquired after expiry, got HeldByOther")
            }
        }
    }

    /// Two claimers race against a stale lease — exactly one wins.
    /// The other should see `HeldByOther` with the winner's holder
    /// id, NOT silently accept the stolen state.
    #[tokio::test]
    async fn only_one_winner_in_concurrent_steal_race() {
        let (store, first) = build_test_lease("scheduler-a", 1);
        let second = second_claimer(Arc::clone(&store), "scheduler-b", 1);
        let third = second_claimer(Arc::clone(&store), "scheduler-c", 1);

        let ClaimOutcome::Acquired { .. } = first.try_claim().await.expect("first claim") else {
            panic!("first should win");
        };
        tokio::time::sleep(Duration::from_millis(1_100)).await;

        // Both race to steal. InMemory is sequential here, but the
        // state-machine pattern still surfaces exactly-one-winner
        // semantics via PutMode::Update's Precondition error.
        let r_second = second.try_claim().await.expect("second");
        let r_third = third.try_claim().await.expect("third");

        let (acquired_count, holder) = match (&r_second, &r_third) {
            (ClaimOutcome::Acquired { payload, .. }, ClaimOutcome::HeldByOther { .. })
            | (ClaimOutcome::HeldByOther { .. }, ClaimOutcome::Acquired { payload, .. }) => {
                (1, payload.holder_id.clone())
            }
            (ClaimOutcome::Acquired { .. }, ClaimOutcome::Acquired { .. }) => {
                panic!("BOTH followers acquired — concurrency invariant broken")
            }
            (ClaimOutcome::HeldByOther { .. }, ClaimOutcome::HeldByOther { .. }) => {
                (0, String::new())
            }
        };

        assert_eq!(acquired_count, 1, "exactly one follower should win");
        assert!(
            holder == "scheduler-b" || holder == "scheduler-c",
            "winner should be one of the two contenders, got {holder}"
        );
    }

    /// Malformed payload on disk surfaces as a typed error so
    /// operators can investigate instead of silently treating the
    /// lease as missing.
    #[tokio::test]
    async fn malformed_payload_surfaces_typed_error() {
        let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let path = ObjectPath::from("scheduler-lease.json");
        // Write garbage at the lease path.
        store
            .put_opts(
                &path,
                b"\x00\x01garbage".to_vec().into(),
                PutOptions::default(),
            )
            .await
            .expect("seed garbage");

        let lease = ObjectStoreLease::new(
            store,
            path,
            "scheduler-a".to_string(),
            Duration::from_secs(30),
        );

        // Create fails because something exists; the fallback read
        // hits the garbage; surfaces as Malformed.
        let err = lease
            .try_claim()
            .await
            .expect_err("malformed lease must error");
        assert!(
            matches!(err, LeaseError::Malformed { .. }),
            "expected Malformed, got {err:?}"
        );
    }

    // --- missing-ETag Backend guards ------------------------------
    // A backend that doesn't return ETags can't support the conditional writes
    // the lease relies on; silently proceeding risks split-brain. `require_etag`
    // turns that into a hard error; these lock in both the helper and the
    // wiring at the Create + heartbeat call sites.

    use futures::stream::BoxStream;
    use object_store::{
        CopyOptions, GetOptions, GetResult, ListResult, MultipartUpload, ObjectMeta,
        PutMultipartOptions, PutPayload, PutResult,
    };

    #[test]
    fn require_etag_passes_present_value() {
        assert_eq!(require_etag(Some("v1".into()), "Create").unwrap(), "v1");
    }

    #[test]
    fn require_etag_missing_is_backend_error_naming_op() {
        let err = require_etag(None, "Create").expect_err("None must fail");
        assert!(matches!(err, LeaseError::Backend(_)));
        let msg = err.to_string();
        assert!(msg.contains("Create"), "names the op: {msg}");
        assert!(msg.contains("ETag"), "explains the cause: {msg}");
    }

    /// A backend whose writes report a caller-chosen ETag (or none). Only
    /// `put_opts` behaves — the lease's Create + heartbeat paths never touch
    /// the other methods, so they're stubs.
    #[derive(Debug)]
    struct PutEtagStore {
        etag: Option<String>,
    }
    impl std::fmt::Display for PutEtagStore {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "PutEtagStore")
        }
    }
    #[async_trait::async_trait]
    impl ObjectStore for PutEtagStore {
        async fn put_opts(
            &self,
            _: &ObjectPath,
            _: PutPayload,
            _: PutOptions,
        ) -> object_store::Result<PutResult> {
            Ok(PutResult {
                e_tag: self.etag.clone(),
                version: None,
                extensions: object_store::Extensions::default(),
            })
        }
        async fn put_multipart_opts(
            &self,
            _: &ObjectPath,
            _: PutMultipartOptions,
        ) -> object_store::Result<Box<dyn MultipartUpload>> {
            unimplemented!("mock store: put_multipart_opts unused")
        }
        async fn get_opts(&self, _: &ObjectPath, _: GetOptions) -> object_store::Result<GetResult> {
            unimplemented!("mock store: get_opts unused")
        }
        fn delete_stream(
            &self,
            _: BoxStream<'static, object_store::Result<ObjectPath>>,
        ) -> BoxStream<'static, object_store::Result<ObjectPath>> {
            unimplemented!("mock store: delete_stream unused")
        }
        fn list(
            &self,
            _: Option<&ObjectPath>,
        ) -> BoxStream<'static, object_store::Result<ObjectMeta>> {
            unimplemented!("mock store: list unused")
        }
        async fn list_with_delimiter(
            &self,
            _: Option<&ObjectPath>,
        ) -> object_store::Result<ListResult> {
            unimplemented!("mock store: list_with_delimiter unused")
        }
        async fn copy_opts(
            &self,
            _: &ObjectPath,
            _: &ObjectPath,
            _: CopyOptions,
        ) -> object_store::Result<()> {
            unimplemented!("mock store: copy_opts unused")
        }
    }

    fn lease_over(store: Arc<dyn ObjectStore>) -> ObjectStoreLease {
        ObjectStoreLease::new(
            store,
            ObjectPath::from("scheduler-lease.json"),
            "h".to_string(),
            Duration::from_secs(30),
        )
    }

    #[tokio::test]
    async fn try_claim_errors_backend_when_create_omits_etag() {
        // Empty store → Create branch; a None ETag means no conditional-update
        // support, so we refuse rather than falsely "win" the lease.
        let store: Arc<dyn ObjectStore> = Arc::new(PutEtagStore { etag: None });
        let err = lease_over(store)
            .try_claim()
            .await
            .expect_err("no-ETag Create must fail");
        assert!(matches!(err, LeaseError::Backend(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn try_claim_acquires_when_create_returns_etag() {
        // Same path with an ETag present acquires cleanly — the guard rejects
        // only the missing-ETag case.
        let store: Arc<dyn ObjectStore> = Arc::new(PutEtagStore {
            etag: Some("v1".into()),
        });
        let outcome = lease_over(store).try_claim().await.expect("claim ok");
        assert!(matches!(outcome, ClaimOutcome::Acquired { .. }));
    }

    #[tokio::test]
    async fn heartbeat_errors_backend_when_update_omits_etag() {
        let store: Arc<dyn ObjectStore> = Arc::new(PutEtagStore { etag: None });
        let err = lease_over(store)
            .heartbeat("prev-etag")
            .await
            .expect_err("no-ETag heartbeat must fail");
        assert!(matches!(err, LeaseError::Backend(_)), "got {err:?}");
    }

    // --- read (Get) site guard + error mapping + payload serde -----

    use futures::StreamExt as _;
    use object_store::{Attributes, GetResultPayload};

    /// A backend whose `get` reports a caller-chosen ETag (or none). Only
    /// `get_opts` behaves — `read_payload`'s missing-ETag guard fires before the
    /// body is read, so the payload stream is left empty and never consumed.
    #[derive(Debug)]
    struct GetEtagStore {
        etag: Option<String>,
    }
    impl std::fmt::Display for GetEtagStore {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "GetEtagStore")
        }
    }
    #[async_trait::async_trait]
    impl ObjectStore for GetEtagStore {
        async fn put_opts(
            &self,
            _: &ObjectPath,
            _: PutPayload,
            _: PutOptions,
        ) -> object_store::Result<PutResult> {
            unimplemented!("mock store: put_opts unused")
        }
        async fn put_multipart_opts(
            &self,
            _: &ObjectPath,
            _: PutMultipartOptions,
        ) -> object_store::Result<Box<dyn MultipartUpload>> {
            unimplemented!("mock store: put_multipart_opts unused")
        }
        async fn get_opts(&self, _: &ObjectPath, _: GetOptions) -> object_store::Result<GetResult> {
            let meta = ObjectMeta {
                location: ObjectPath::from("scheduler-lease.json"),
                last_modified: Utc::now(),
                size: 0,
                e_tag: self.etag.clone(),
                version: None,
            };
            Ok(GetResult {
                payload: GetResultPayload::Stream(futures::stream::empty().boxed()),
                meta,
                range: 0..0,
                attributes: Attributes::default(),
                extensions: object_store::Extensions::default(),
            })
        }
        fn delete_stream(
            &self,
            _: BoxStream<'static, object_store::Result<ObjectPath>>,
        ) -> BoxStream<'static, object_store::Result<ObjectPath>> {
            unimplemented!("mock store: delete_stream unused")
        }
        fn list(
            &self,
            _: Option<&ObjectPath>,
        ) -> BoxStream<'static, object_store::Result<ObjectMeta>> {
            unimplemented!("mock store: list unused")
        }
        async fn list_with_delimiter(
            &self,
            _: Option<&ObjectPath>,
        ) -> object_store::Result<ListResult> {
            unimplemented!("mock store: list_with_delimiter unused")
        }
        async fn copy_opts(
            &self,
            _: &ObjectPath,
            _: &ObjectPath,
            _: CopyOptions,
        ) -> object_store::Result<()> {
            unimplemented!("mock store: copy_opts unused")
        }
    }

    /// The fourth conditional-write site: `read_payload` (used by the steal
    /// path). A `get` with no ETag means the backend can't give us the
    /// concurrency token a steal's `Update` would need, so we refuse rather
    /// than proceed toward a split-brain steal.
    #[tokio::test]
    async fn read_payload_errors_backend_when_get_omits_etag() {
        let store: Arc<dyn ObjectStore> = Arc::new(GetEtagStore { etag: None });
        let err = lease_over(store)
            .read_payload()
            .await
            .expect_err("no-ETag get must fail");
        assert!(matches!(err, LeaseError::Backend(_)), "got {err:?}");
    }

    /// Non-`Precondition` object-store errors map to `Backend` (`Precondition`
    /// is special-cased at the call sites as `LeadershipLost` / lost-steal,
    /// never here), and the underlying cause is preserved in the message.
    #[test]
    fn from_os_error_non_precondition_maps_to_backend() {
        let os = OsError::Generic {
            store: "mock",
            source: "disk on fire".into(),
        };
        match LeaseError::from(os) {
            LeaseError::Backend(msg) => {
                assert!(msg.contains("disk on fire"), "preserves cause: {msg}");
            }
            other => panic!("expected Backend, got {other:?}"),
        }
    }

    /// The on-disk lease payload survives a JSON round-trip unchanged — it's the
    /// cross-scheduler-version wire format, so a follower reading a holder's
    /// write must recover the exact `holder_id` + `expires_at`.
    #[test]
    fn lease_payload_json_round_trips() {
        let expires_at: DateTime<Utc> = "2027-01-15T08:30:00Z".parse().expect("rfc3339");
        let payload = LeasePayload {
            holder_id: "scheduler-7".to_string(),
            expires_at,
        };
        let json = serde_json::to_vec(&payload).expect("serialise");
        let back: LeasePayload = serde_json::from_slice(&json).expect("deserialise");
        assert_eq!(back.holder_id, payload.holder_id);
        assert_eq!(back.expires_at, payload.expires_at);
    }
}

//! Live registry of connected pgwire sessions — the data plane behind the
//! operational dashboard's "who is connected" view.
//!
//! Today the dashboard exposes only an aggregate active-connection COUNT
//! (the `dataglot_pgwire_connections_active` gauge). This registry adds the
//! per-connection detail an operator of a multi-tenant deployment needs:
//! **user · org · client address · connected-since**. It is the sessions
//! analogue of the [`crate::query_registry`] "what's running" list — a
//! thread-safe, cheaply-cloneable, in-memory map, snapshotted point-in-time
//! to back `GET /api/sessions` (see [`crate::observability`]).
//!
//! # Lifecycle (rule 4: pgwire stays independent — the server owns this)
//!
//! pgwire never learns about the registry. The server drives it from its own
//! connection handler: [`register`](SessionRegistry::register) when a
//! connection is admitted (peer + connect time known), then
//! [`set_identity`](SessionRegistry::set_identity) from the `StartupObserver`
//! once the username + resolved org are available, and
//! [`deregister`](SessionRegistry::deregister) via an RAII guard on drop —
//! the same seam as the active-connection gauge's `.dec()`.
//!
//! # Rule 12
//!
//! Only the peer socket address, the startup username, and the resolved org
//! (a tenant name) are retained — all safe to surface. No password or other
//! credential ever reaches this layer.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

/// Opaque per-connection session identifier, monotonically allocated by
/// [`SessionRegistry::next_id`]. Stable across a connection's lifetime
/// (`register` → `set_identity` → `deregister`).
pub type SessionId = u64;

/// One connected session, as tracked internally. `user`/`org` start `None`
/// at connect and are filled in once the startup handshake resolves them.
#[derive(Debug, Clone)]
struct Session {
    /// pgwire startup username, once resolved. `None` in the brief window
    /// before the `StartupObserver` fires, or in trust mode with no user.
    user: Option<String>,
    /// Resolved tenant/org for this session, once known. `None` before the
    /// startup handshake resolves it.
    org: Option<String>,
    /// Client socket address (`ip:port`), captured at connect.
    peer: String,
    /// When the connection was admitted — the "connected-since" instant.
    connected_at: SystemTime,
}

/// One connected session as exposed by `GET /api/sessions`.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SessionInfoView {
    /// Stable per-connection id (stringified for the JSON wire shape, matching
    /// the `run_id` string convention of `/api/queries`).
    pub session_id: String,
    /// pgwire startup username. `None` when the connection reported none
    /// (e.g. trust mode) or before the handshake resolved it.
    pub user: Option<String>,
    /// Resolved tenant/org — the governance-relevant column. `None` before
    /// the handshake resolves it.
    pub org: Option<String>,
    /// Client socket address (`ip:port`).
    pub peer: String,
    /// Connect time as Unix epoch milliseconds — the client renders both a
    /// relative ("3m ago") and an absolute timestamp from this.
    pub connected_at_ms: u64,
}

/// Shared, cheaply-cloneable registry of currently-connected sessions.
///
/// Cloning shares the same underlying map (an `Arc`), so the copy handed to
/// the axum router and the copy wired into the connection handler see the
/// same live state — the same pattern as [`crate::query_registry::QueryRegistry`].
#[derive(Clone, Default)]
pub struct SessionRegistry {
    inner: Arc<RwLock<HashMap<SessionId, Session>>>,
    /// Monotonic id source. Shared via the `Arc` so every clone allocates
    /// from the same sequence.
    next: Arc<AtomicU64>,
}

impl std::fmt::Debug for SessionRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the sessions themselves — just the count.
        let live = self.inner.read().map_or(0, |m| m.len());
        f.debug_struct("SessionRegistry")
            .field("live", &live)
            .finish_non_exhaustive()
    }
}

impl SessionRegistry {
    /// Create an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Allocate a fresh, process-unique [`SessionId`]. The caller pairs it
    /// with [`register`](Self::register) and holds it for the connection's
    /// lifetime so [`set_identity`](Self::set_identity) and
    /// [`deregister`](Self::deregister) target the same entry.
    #[must_use]
    pub fn next_id(&self) -> SessionId {
        self.next.fetch_add(1, Ordering::Relaxed)
    }

    /// Record a session as connected. `user`/`org` are unknown at this point
    /// (the startup handshake hasn't resolved them); fill them in later with
    /// [`set_identity`](Self::set_identity). A poisoned lock is swallowed —
    /// losing an observability entry must never break the connection path.
    pub fn register(&self, session_id: SessionId, peer: impl Into<String>) {
        let session = Session {
            user: None,
            org: None,
            peer: peer.into(),
            connected_at: SystemTime::now(),
        };
        if let Ok(mut map) = self.inner.write() {
            map.insert(session_id, session);
        }
    }

    /// Attach the resolved username + org to an already-registered session
    /// (fired from the `StartupObserver`, which follows `register`). A no-op
    /// if the session is gone (already deregistered).
    pub fn set_identity(&self, session_id: SessionId, user: Option<String>, org: Option<String>) {
        if let Ok(mut map) = self.inner.write() {
            if let Some(s) = map.get_mut(&session_id) {
                s.user = user;
                s.org = org;
            }
        }
    }

    /// Remove a session — called on connection drop (the RAII guard).
    pub fn deregister(&self, session_id: SessionId) {
        if let Ok(mut map) = self.inner.write() {
            map.remove(&session_id);
        }
    }

    /// Point-in-time snapshot of connected sessions, **longest-connected
    /// first** (oldest connection at the front) — mirroring `/api/queries`'
    /// longest-running-first ordering.
    #[must_use]
    pub fn list(&self) -> Vec<SessionInfoView> {
        let Ok(map) = self.inner.read() else {
            return Vec::new();
        };
        let mut out: Vec<SessionInfoView> = map
            .iter()
            .map(|(id, s)| SessionInfoView {
                session_id: id.to_string(),
                user: s.user.clone(),
                org: s.org.clone(),
                peer: s.peer.clone(),
                connected_at_ms: epoch_ms(s.connected_at),
            })
            .collect();
        // Oldest (smallest epoch-ms) first; ties broken by id for stability.
        out.sort_by(|a, b| {
            a.connected_at_ms
                .cmp(&b.connected_at_ms)
                .then_with(|| a.session_id.cmp(&b.session_id))
        });
        out
    }

    /// Number of currently-connected sessions.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.read().map_or(0, |m| m.len())
    }

    /// Whether no sessions are currently connected.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Unix epoch milliseconds for a [`SystemTime`], saturating at 0 for the
/// (impossible in practice) pre-epoch case.
fn epoch_ms(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_list_deregister_roundtrip() {
        let reg = SessionRegistry::new();
        assert!(reg.is_empty());
        assert_eq!(reg.len(), 0);

        let id = reg.next_id();
        reg.register(id, "10.0.0.1:5010");
        assert_eq!(reg.len(), 1);

        let list = reg.list();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].session_id, id.to_string());
        assert_eq!(list[0].peer, "10.0.0.1:5010");
        // Identity unknown until set_identity fires.
        assert_eq!(list[0].user, None);
        assert_eq!(list[0].org, None);
        assert!(list[0].connected_at_ms > 0);

        reg.deregister(id);
        assert!(reg.is_empty());
        assert!(reg.list().is_empty());
    }

    #[test]
    fn set_identity_surfaces_user_and_org() {
        let reg = SessionRegistry::new();
        let id = reg.next_id();
        reg.register(id, "127.0.0.1:6000");
        reg.set_identity(id, Some("alice".to_string()), Some("acme".to_string()));

        let list = reg.list();
        assert_eq!(list[0].user.as_deref(), Some("alice"));
        assert_eq!(list[0].org.as_deref(), Some("acme"));
    }

    #[test]
    fn set_identity_on_missing_session_is_a_noop() {
        let reg = SessionRegistry::new();
        // No panic, no insert — just ignored.
        reg.set_identity(999, Some("ghost".to_string()), None);
        assert!(reg.is_empty());
    }

    #[test]
    fn ids_are_unique_and_count_reflects_live_sessions() {
        let reg = SessionRegistry::new();
        let a = reg.next_id();
        let b = reg.next_id();
        let c = reg.next_id();
        assert_ne!(a, b);
        assert_ne!(b, c);

        reg.register(a, "1.1.1.1:1");
        reg.register(b, "2.2.2.2:2");
        reg.register(c, "3.3.3.3:3");
        assert_eq!(reg.len(), 3);
        assert_eq!(reg.list().len(), 3);

        reg.deregister(b);
        assert_eq!(reg.len(), 2);
        let peers: Vec<_> = reg.list().into_iter().map(|s| s.peer).collect();
        assert!(peers.contains(&"1.1.1.1:1".to_string()));
        assert!(!peers.contains(&"2.2.2.2:2".to_string()));
        assert!(peers.contains(&"3.3.3.3:3".to_string()));
    }

    #[test]
    fn list_is_longest_connected_first() {
        let reg = SessionRegistry::new();
        let older = reg.next_id();
        let newer = reg.next_id();
        // Force a strictly-greater connect timestamp on the second entry by
        // inserting sessions with hand-set times (register uses `now()`,
        // which can collide at ms resolution on fast machines).
        {
            let mut map = reg.inner.write().unwrap();
            map.insert(
                older,
                Session {
                    user: None,
                    org: None,
                    peer: "old:1".to_string(),
                    connected_at: UNIX_EPOCH + std::time::Duration::from_secs(1),
                },
            );
            map.insert(
                newer,
                Session {
                    user: None,
                    org: None,
                    peer: "new:2".to_string(),
                    connected_at: UNIX_EPOCH + std::time::Duration::from_secs(2),
                },
            );
        }
        let list = reg.list();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].peer, "old:1", "oldest connection first");
        assert_eq!(list[1].peer, "new:2");
        assert!(list[0].connected_at_ms <= list[1].connected_at_ms);
    }

    #[test]
    fn debug_does_not_leak_session_detail() {
        let reg = SessionRegistry::new();
        let id = reg.next_id();
        reg.register(id, "secret-peer:9999");
        reg.set_identity(id, Some("secret-user".to_string()), None);
        let dbg = format!("{reg:?}");
        assert!(dbg.contains("live"));
        assert!(!dbg.contains("secret-peer"));
        assert!(!dbg.contains("secret-user"));
    }
}

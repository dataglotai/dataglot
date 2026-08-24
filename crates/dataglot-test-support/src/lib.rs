//! Shared test-only helpers for the Dataglot workspace.
//!
//! Dev tooling (`publish = false`): pulled in as a `[dev-dependencies]`
//! entry by the crates whose tests need it. Depends on nothing but `std`
//! so it stays a leaf and never risks a dependency cycle.

use std::collections::HashSet;
use std::net::TcpListener;
use std::sync::{Mutex, OnceLock};

/// Process-wide set of ports already handed out by [`reserve_loopback_port`].
/// `OnceLock` (not a `const` initializer) because `HashSet::new()` isn't
/// `const` on stable — keeps the crate MSRV-friendly.
fn handed_out() -> &'static Mutex<HashSet<u16>> {
    static PORTS: OnceLock<Mutex<HashSet<u16>>> = OnceLock::new();
    PORTS.get_or_init(|| Mutex::new(HashSet::new()))
}

/// Reserve a loopback TCP port for a test server to bind.
///
/// Race-hardened replacement for the ~18 copy-pasted
/// `bind(":0"); read port; drop; return port` helpers. Those all shared a
/// TOCTOU window between dropping the probe listener and the server
/// re-binding — but the dominant CI flake was **intra-process**: two tests
/// running concurrently in the same test binary received the *same*
/// ephemeral port from the OS (each probe binds `:0`, reads the port, then
/// frees it, so the allocator can hand the same number to the next probe),
/// and the second server then failed to bind with
/// `Address already in use`.
///
/// This helper records every port it returns in a process-wide set and
/// only returns one not already handed to a concurrent caller in this
/// process, eliminating that intra-process collision. The cross-*process*
/// window (separate test binaries) is unchanged, but it is far rarer than
/// the in-binary collision this removes.
///
/// # Panics
/// Panics if an ephemeral port cannot be bound, or if 1000 consecutive
/// probes all collided with already-handed-out ports (never observed in
/// practice — it would mean the process reserved ~1000 live ports).
#[must_use]
pub fn reserve_loopback_port() -> u16 {
    for _ in 0..1000 {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind an ephemeral loopback port");
        let port = listener
            .local_addr()
            .expect("resolve the bound local address")
            .port();
        // Free the probe listener so the caller's server can bind the port.
        drop(listener);
        if handed_out()
            .lock()
            .expect("port registry mutex is not poisoned")
            .insert(port)
        {
            return port;
        }
        // Port was already handed to another caller this process — retry.
    }
    panic!("could not reserve a unique loopback port after 1000 attempts");
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every reserved port is unique within the process — the core
    /// guarantee that removes the intra-binary collision flake.
    #[test]
    fn reserved_ports_are_unique_within_the_process() {
        let mut seen = HashSet::new();
        for _ in 0..200 {
            let port = reserve_loopback_port();
            assert_ne!(port, 0, "reserved port must be non-zero");
            assert!(seen.insert(port), "port {port} was handed out twice");
        }
    }

    /// A reserved port is actually bindable right after it's returned
    /// (the probe listener was dropped, so the caller can claim it).
    #[test]
    fn reserved_port_is_bindable() {
        let port = reserve_loopback_port();
        let _listener = TcpListener::bind(("127.0.0.1", port))
            .expect("a freshly reserved port must be bindable");
    }
}

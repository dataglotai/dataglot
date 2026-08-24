//! Policy-decision audit — Apache Ranger audit parity (Ranger
//! policy-parity slice 5).
//!
//! Ranger writes an audit record for every access decision. Dataglot
//! emits a structured `tracing` event on the `dataglot::audit` target
//! when a policy fires, carrying the session identity and the resource.
//! Routing the `dataglot::audit` target to a file/collector (the server
//! already logs structured JSON, surfaced in the testbench Logs tab)
//! gives the audit trail enterprise security reviews expect.
//!
//! Coverage: **access-deny** (slice 5 — "who was refused which
//! resource"), plus **mask** and **row-filter** decisions (the
//! completeness follow-up) — every policy decision the engine makes at
//! planning time now emits an audit event, whichever enforcer path
//! produced it (static config, tag-based dispatch, or the composed
//! stack — `TagBasedEnforcer` delegates to the same mask/filter
//! enforcers, so their events fire on that path too).

use crate::Identity;

/// Audit target for policy decisions. Operators filter/route on this
/// (e.g. `RUST_LOG=dataglot::audit=info`).
pub(crate) const AUDIT_TARGET: &str = "dataglot::audit";

/// Record a policy decision to the audit log.
///
/// `action` is the decision verb (e.g. `"deny"`); `resource` is the
/// affected object (`"table"` or `"table.column"`).
pub(crate) fn record_decision(action: &str, identity: &Identity, resource: &str) {
    tracing::info!(
        target: AUDIT_TARGET,
        action,
        user = identity.user.as_deref().unwrap_or("anonymous"),
        groups = ?identity.org_groups,
        resource,
        "policy decision"
    );
}

/// Test-only capture harness for audit events, shared by the audit /
/// mask / filter test modules: runs `f` and returns everything it logged
/// as a `String`.
///
/// # Why one persistent global subscriber, not per-call `with_default`
///
/// An earlier version installed a fresh capturing subscriber per call via
/// `tracing::subscriber::with_default` (thread-local). That flaked under
/// parallel test execution — `tracing`'s max-level hint is a **process-
/// global atomic**, recomputed whenever a thread-local default is set *or
/// dropped*. When one test's `with_default` guard dropped (recomputing the
/// global max toward `OFF`, since nothing else held a global default), a
/// *concurrent* test's `info!` could be short-circuited at the macro before
/// reaching its still-installed thread-local subscriber — an empty capture,
/// order/timing-dependent, worse under coverage instrumentation.
///
/// The fix: install **one** global default subscriber **once** with max
/// level `TRACE` (so the global hint is permanently permissive and never
/// races toward `OFF`) that routes every event to the **calling thread's**
/// sink. Per-test isolation comes from the thread-local sink, not from
/// swapping subscribers, so parallel captures can't interfere.
#[cfg(test)]
pub(crate) mod test_capture {
    use std::cell::RefCell;
    use std::io::Write;
    use std::sync::{Arc, Mutex, Once};

    use tracing_subscriber::fmt::MakeWriter;

    thread_local! {
        /// The current thread's capture buffer, set for the duration of a
        /// `capture_logs` call. `None` outside one (events are dropped).
        static SINK: RefCell<Option<Arc<Mutex<Vec<u8>>>>> = const { RefCell::new(None) };
    }

    /// A `MakeWriter` that appends emitted bytes to the calling thread's
    /// `SINK` (if one is installed); otherwise discards them.
    #[derive(Clone, Default)]
    struct ThreadLocalWriter;

    impl Write for ThreadLocalWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            SINK.with(|s| {
                if let Some(sink) = s.borrow().as_ref() {
                    sink.lock().unwrap().extend_from_slice(buf);
                }
            });
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for ThreadLocalWriter {
        type Writer = ThreadLocalWriter;
        fn make_writer(&'a self) -> ThreadLocalWriter {
            ThreadLocalWriter
        }
    }

    static INIT: Once = Once::new();

    /// Run `f` with audit-event capture active on this thread and return the
    /// captured log text.
    pub(crate) fn capture_logs(f: impl FnOnce()) -> String {
        INIT.call_once(|| {
            let subscriber = tracing_subscriber::fmt()
                .with_writer(ThreadLocalWriter)
                .with_target(true)
                // Deterministic output for `contains` assertions: no ANSI
                // color escapes, no timestamps (both vary by environment).
                .with_ansi(false)
                .without_time()
                // Keep the process-global max-level hint permissive so no
                // event is filtered at the macro (the  flake).
                .with_max_level(tracing::Level::TRACE)
                .finish();
            // Ignore an `Err` — some other test may have set a global
            // default first (none do in this crate today); either way the
            // capture then simply routes through whatever is installed.
            let _ = tracing::subscriber::set_global_default(subscriber);
        });

        let buf = Arc::new(Mutex::new(Vec::new()));
        SINK.with(|s| *s.borrow_mut() = Some(Arc::clone(&buf)));
        f();
        SINK.with(|s| *s.borrow_mut() = None);
        let bytes = buf.lock().unwrap().clone();
        String::from_utf8(bytes).expect("log output is utf8")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_decision_emits_structured_audit_event() {
        let logged = crate::audit::test_capture::capture_logs(|| {
            let id = Identity::user("alice").with_groups(["analyst"]);
            record_decision("deny", &id, "categories.name");
        });

        assert!(logged.contains("dataglot::audit"), "audit target: {logged}");
        assert!(logged.contains("deny"), "action: {logged}");
        assert!(logged.contains("categories.name"), "resource: {logged}");
        assert!(logged.contains("alice"), "user: {logged}");
        assert!(logged.contains("analyst"), "groups: {logged}");
    }
}

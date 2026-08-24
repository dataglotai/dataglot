//! Per-connection **session org** task-local.
//!
//! A connection's org (tenant) is resolved from its authenticated identity by
//! `dataglot-server` — which owns the identity/role config — *after* the pgwire
//! `SessionContext` (and this handler) were already built at connect time. So,
//! exactly like `dataglot_policy`'s session-identity task-local, the org is
//! stashed in a tokio task-local scoped to the connection's task: the server
//! wraps the connection future in [`with_session_org`] and sets the resolved
//! value from its `StartupObserver` via [`try_set_session_org`]; the handler
//! reads it back with [`current_session_org`] when it effects catalog / secret
//! DDL, so a `CREATE CATALOG` persists under the *issuing connection's* org.
//!
//! Why a task-local here rather than reading
//! `dataglot_policy::current_session_identity()` directly: CLAUDE.md rule 4
//! forbids a lateral `dataglot-pgwire -> dataglot-policy` dependency. The org
//! is a plain `String` (a tenant name, never a credential — rule 12), so the
//! server mirrors the resolved identity's `org` into this pgwire-owned
//! task-local instead of pgwire reaching across the crate boundary.
//!
//! Same-task semantics (tokio task-locals migrate with the future across
//! worker threads but do **not** cross `tokio::spawn`) match the policy
//! identity's; query handling on a connection runs sequentially in that task,
//! so the value set at startup is visible to every later query on the
//! connection.

use std::cell::RefCell;

tokio::task_local! {
    static CURRENT_SESSION_ORG: RefCell<Option<String>>;
}

/// Run `future` with `initial` bound as the current task's session org.
/// The server wraps a connection's whole lifetime in this scope so the org
/// set from the startup observer is visible to every query on the connection.
pub async fn with_session_org<F: std::future::Future>(
    initial: Option<String>,
    future: F,
) -> F::Output {
    CURRENT_SESSION_ORG
        .scope(RefCell::new(initial), future)
        .await
}

/// Replace the current task's session org.
///
/// # Panics
/// Panics if called outside a [`with_session_org`] scope. Prefer
/// [`try_set_session_org`] where a scope can't be statically guaranteed.
pub fn set_session_org(org: Option<String>) {
    CURRENT_SESSION_ORG.with(|cell| *cell.borrow_mut() = org);
}

/// Best-effort variant of [`set_session_org`] — a no-op outside a
/// [`with_session_org`] scope (e.g. unit tests that don't establish one).
pub fn try_set_session_org(org: Option<String>) {
    let _ = CURRENT_SESSION_ORG.try_with(|cell| *cell.borrow_mut() = org);
}

/// The current task's session org, if any.
///
/// `None` ⇒ no [`with_session_org`] scope is active, or the scope holds no
/// org (a single-tenant / default connection). Catalog-DDL callers treat that
/// as the `"default"` org.
#[must_use]
pub fn current_session_org() -> Option<String> {
    CURRENT_SESSION_ORG
        .try_with(|cell| cell.borrow().clone())
        .ok()
        .flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_session_org_is_none_outside_scope() {
        assert!(current_session_org().is_none());
    }

    #[test]
    fn try_set_outside_scope_is_no_op() {
        try_set_session_org(Some("acme".into()));
        assert!(current_session_org().is_none());
    }

    #[tokio::test]
    async fn with_scope_exposes_initial_and_set() {
        let observed = with_session_org(Some("acme".into()), async {
            let initial = current_session_org();
            set_session_org(Some("globex".into()));
            (initial, current_session_org())
        })
        .await;
        assert_eq!(observed.0.as_deref(), Some("acme"));
        assert_eq!(observed.1.as_deref(), Some("globex"));
    }

    #[tokio::test]
    async fn none_scope_reads_none() {
        let observed = with_session_org(None, async { current_session_org() }).await;
        assert!(observed.is_none());
    }
}

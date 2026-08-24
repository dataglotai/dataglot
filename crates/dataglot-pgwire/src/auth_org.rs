//! Per-connection **auth-resolved org** task-local.
//!
//! Global-unique usernames (a `CREATE USER` name is unique across every org)
//! mean a store-backed user's org is discovered during the **async** md5 auth
//! exchange — the server's `PasswordSource` scans the meta store for the
//! username and learns which org owns it — *before* the sync
//! [`StartupObserver`](crate::StartupObserver) runs. The observer needs that
//! org to scope the session (per-org catalog swap + session identity), but it
//! is **sync**: Hard rule 11 forbids blocking on async inside it, so it
//! must not re-query the store.
//!
//! So, exactly like [`crate::session_org`], the value is bridged through a
//! tokio task-local scoped to the connection's task: the server wraps the
//! connection future in [`with_auth_org`], its async `PasswordSource` records
//! the org it resolved via [`try_set_auth_org`] during auth, and its sync
//! observer reads it back with [`current_auth_org`] to pick the session's org
//! (config-identity org → this auth-resolved org → boot org).
//!
//! Why a pgwire-owned task-local rather than the server reaching into
//! `dataglot_policy` / writing across crates: Hard rule 4 forbids a
//! lateral `dataglot-pgwire -> dataglot-policy`/`-server` dependency, so the
//! server (which depends on both) mirrors the resolved value into this
//! pgwire-owned seam instead. The org is a plain tenant name, never a
//! credential (rule 12).
//!
//! Same-task semantics match [`crate::session_org`]: auth runs before the
//! observer in the same connection task, and tokio task-locals migrate with
//! the future across worker threads but do **not** cross `tokio::spawn`, so
//! the value set during auth is visible to the observer that follows.

use std::cell::RefCell;

tokio::task_local! {
    static CURRENT_AUTH_ORG: RefCell<Option<String>>;
}

/// Run `future` with `initial` bound as the current task's auth-resolved org.
/// The server wraps a connection's whole lifetime in this scope so an org
/// resolved during that connection's md5 auth is visible to the startup
/// observer that runs afterwards.
pub async fn with_auth_org<F: std::future::Future>(
    initial: Option<String>,
    future: F,
) -> F::Output {
    CURRENT_AUTH_ORG.scope(RefCell::new(initial), future).await
}

/// Replace the current task's auth-resolved org.
///
/// # Panics
/// Panics if called outside a [`with_auth_org`] scope. Prefer
/// [`try_set_auth_org`] where a scope can't be statically guaranteed (e.g. the
/// server's `PasswordSource`, which also runs in unit tests without a scope).
pub fn set_auth_org(org: Option<String>) {
    CURRENT_AUTH_ORG.with(|cell| *cell.borrow_mut() = org);
}

/// Best-effort variant of [`set_auth_org`] — a no-op outside a
/// [`with_auth_org`] scope (e.g. unit tests that don't establish one).
pub fn try_set_auth_org(org: Option<String>) {
    let _ = CURRENT_AUTH_ORG.try_with(|cell| *cell.borrow_mut() = org);
}

/// The org resolved for this connection during md5 auth, if any.
///
/// `None` ⇒ no [`with_auth_org`] scope is active, or auth resolved no org
/// (a trust-mode / config-defined connection, or an unknown user). The
/// startup observer treats that as "fall through to the config-identity org
/// or the boot org".
#[must_use]
pub fn current_auth_org() -> Option<String> {
    CURRENT_AUTH_ORG
        .try_with(|cell| cell.borrow().clone())
        .ok()
        .flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_auth_org_is_none_outside_scope() {
        assert!(current_auth_org().is_none());
    }

    #[test]
    fn try_set_outside_scope_is_no_op() {
        try_set_auth_org(Some("acme".into()));
        assert!(current_auth_org().is_none());
    }

    #[tokio::test]
    async fn with_scope_exposes_initial_and_set() {
        let observed = with_auth_org(Some("acme".into()), async {
            let initial = current_auth_org();
            set_auth_org(Some("globex".into()));
            (initial, current_auth_org())
        })
        .await;
        assert_eq!(observed.0.as_deref(), Some("acme"));
        assert_eq!(observed.1.as_deref(), Some("globex"));
    }

    #[tokio::test]
    async fn none_scope_reads_none() {
        let observed = with_auth_org(None, async { current_auth_org() }).await;
        assert!(observed.is_none());
    }

    #[tokio::test]
    async fn try_set_within_scope_updates_value() {
        // Mirrors the server's PasswordSource → observer bridge: a best-effort
        // set during auth is visible to a later read in the same task/scope.
        let observed = with_auth_org(None, async {
            try_set_auth_org(Some("acme".into()));
            current_auth_org()
        })
        .await;
        assert_eq!(observed.as_deref(), Some("acme"));
    }
}

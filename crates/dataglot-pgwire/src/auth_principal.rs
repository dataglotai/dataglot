//! Per-connection **auth-resolved principal** task-local.
//!
//! A companion to [`crate::auth_org`]. GRANT/REVOKE enforcement needs two more
//! facts about a store-backed user, both discoverable only during the
//! **async** md5 auth exchange (the server's `PasswordSource` reads the meta
//! store): the user's **superuser** flag and its **RBAC role** memberships.
//! The sync [`StartupObserver`](crate::StartupObserver) builds the session
//! identity but is sync — CLAUDE.md rule 11 forbids blocking on async inside
//! it, so it must not re-query the store.
//!
//! So, exactly like [`crate::auth_org`], the value is bridged through a tokio
//! task-local scoped to the connection's task: the server wraps the connection
//! future in [`with_auth_principal`], its async `PasswordSource` records the
//! roles + superuser flag it resolved via [`try_set_auth_principal`] during
//! auth, and its sync observer reads them back with [`current_auth_principal`]
//! to populate the session [`Identity`](dataglot-policy). The values are plain
//! data (role names, a bool) — never credentials (rule 12) — and this
//! pgwire-owned seam keeps the lateral `dataglot-pgwire -> dataglot-policy`
//! dependency the direct approach would need off the graph (rule 4): the
//! server, which depends on both, mirrors the value across.
//!
//! Same-task semantics match [`crate::auth_org`]: auth runs before the
//! observer in the same connection task, and tokio task-locals migrate with
//! the future across worker threads but do **not** cross `tokio::spawn`.

use std::cell::RefCell;

/// The auth-resolved principal facts a connection carries from its md5 auth
/// exchange to its startup observer. Plain data — no credentials.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuthPrincipal {
    /// RBAC role names the user is a member of (from the store's
    /// `role → user` memberships). Empty for a config-defined / trust user.
    pub roles: Vec<String>,
    /// Whether the store marks the user a superuser. Drives grant-enforcement
    /// bypass (folded into the session `Identity`); see the server's startup
    /// observer.
    pub is_superuser: bool,
    /// Whether this session may run control-plane DDL (`CREATE CATALOG/USER/…`,
    /// `GRANT`, `CREATE MASK/POLICY`, …) —. Set by the server's startup
    /// observer to `trust-mode OR a config-defined identity OR a store
    /// superuser`. Deliberately **separate** from [`Self::is_superuser`]: it
    /// authorizes the admin surface without also bypassing read-time grant /
    /// column-whitelist enforcement, so a config-defined analyst stays
    /// grant-enforced on reads.
    pub can_admin: bool,
}

tokio::task_local! {
    static CURRENT_AUTH_PRINCIPAL: RefCell<AuthPrincipal>;
}

/// Run `future` with `initial` bound as the current task's auth-resolved
/// principal. The server wraps a connection's whole lifetime in this scope so
/// facts resolved during that connection's md5 auth are visible to the startup
/// observer that runs afterwards.
pub async fn with_auth_principal<F: std::future::Future>(
    initial: AuthPrincipal,
    future: F,
) -> F::Output {
    CURRENT_AUTH_PRINCIPAL
        .scope(RefCell::new(initial), future)
        .await
}

/// Best-effort setter — a no-op outside a [`with_auth_principal`] scope (e.g.
/// unit tests, or the server's `PasswordSource` running without a scope).
pub fn try_set_auth_principal(principal: AuthPrincipal) {
    let _ = CURRENT_AUTH_PRINCIPAL.try_with(|cell| *cell.borrow_mut() = principal);
}

/// The principal resolved for this connection during md5 auth, if any.
///
/// `None` ⇒ no [`with_auth_principal`] scope is active (a trust-mode /
/// config-defined connection, or an unknown user); the startup observer then
/// leaves roles empty and superuser `false`.
#[must_use]
pub fn current_auth_principal() -> Option<AuthPrincipal> {
    CURRENT_AUTH_PRINCIPAL
        .try_with(|cell| cell.borrow().clone())
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_is_none_outside_scope() {
        assert!(current_auth_principal().is_none());
    }

    #[test]
    fn try_set_outside_scope_is_no_op() {
        try_set_auth_principal(AuthPrincipal {
            roles: vec!["analyst".into()],
            is_superuser: true,
            can_admin: true,
        });
        assert!(current_auth_principal().is_none());
    }

    #[tokio::test]
    async fn scope_exposes_initial_and_set() {
        let observed = with_auth_principal(AuthPrincipal::default(), async {
            let initial = current_auth_principal();
            try_set_auth_principal(AuthPrincipal {
                roles: vec!["analyst".into(), "oncall".into()],
                is_superuser: true,
                can_admin: true,
            });
            (initial, current_auth_principal())
        })
        .await;
        assert_eq!(observed.0, Some(AuthPrincipal::default()));
        let set = observed.1.expect("set within scope");
        assert_eq!(set.roles, vec!["analyst".to_string(), "oncall".to_string()]);
        assert!(set.is_superuser);
    }
}

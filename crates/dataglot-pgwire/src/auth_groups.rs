//! Per-connection **auth-resolved directory groups** task-local.
//!
//! A companion to [`crate::auth_org`] and [`crate::auth_principal`]. In the
//! `jwt` / `ldap` auth modes the session's org-group memberships are
//! discovered during the **async** startup exchange — the JWT is verified and
//! its `groups` claim read, or the LDAP bind succeeds and the directory is
//! searched. The sync [`StartupObserver`](crate::StartupObserver) that builds
//! the session identity runs afterwards and, per hard rule 11, must not
//! block on async IO to re-query the directory.
//!
//! So, exactly like [`crate::auth_org`], the resolved groups are bridged
//! through a tokio task-local scoped to the connection's task: the server
//! wraps the connection future in [`with_auth_groups`], the JWT / LDAP startup
//! handler records what it resolved via [`try_set_auth_groups`] once auth
//! succeeds, and the sync observer reads it back with [`current_auth_groups`]
//! to populate [`Identity::org_groups`](dataglot-policy). Group **names** are
//! plain data — never credentials (rule 12); the token and bind password stay
//! inside the startup handler and never reach this seam. Keeping the mapping
//! to policy types in the server (which depends on both crates) is what keeps
//! the lateral `dataglot-pgwire -> dataglot-policy` dependency off the graph
//! (rule 4).
//!
//! Same-task semantics match [`crate::auth_org`]: auth runs before the
//! observer in the same connection task, and tokio task-locals migrate with
//! the future across worker threads but do **not** cross `tokio::spawn`.

use std::cell::RefCell;

/// The directory groups a connection resolved during its `jwt` / `ldap`
/// startup exchange, carried from that async auth to the sync startup
/// observer. Plain data — no credentials.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuthGroups {
    /// Resolved group names (JWT `groups` claim, or LDAP group search). Empty
    /// ⇒ authenticated with no memberships.
    pub groups: Vec<String>,
    /// `true` when group resolution **failed after successful authentication**
    /// (e.g. the LDAP bind succeeded but the group search errored). The
    /// observer treats this as least-privilege: no groups are granted, and it
    /// is logged at WARN. Never set when authentication itself failed — that
    /// path rejects the connection outright.
    pub unavailable: bool,
}

impl AuthGroups {
    /// Authenticated with the given resolved group names.
    #[must_use]
    pub fn resolved(groups: Vec<String>) -> Self {
        Self {
            groups,
            unavailable: false,
        }
    }

    /// Authenticated, but group resolution failed — least privilege.
    #[must_use]
    pub fn unavailable() -> Self {
        Self {
            groups: Vec::new(),
            unavailable: true,
        }
    }
}

tokio::task_local! {
    static CURRENT_AUTH_GROUPS: RefCell<Option<AuthGroups>>;
}

/// Run `future` with `initial` bound as the current task's auth-resolved
/// groups. The server wraps a connection's whole lifetime in this scope so
/// groups resolved during that connection's `jwt` / `ldap` auth are visible to
/// the startup observer that runs afterwards.
pub async fn with_auth_groups<F: std::future::Future>(
    initial: Option<AuthGroups>,
    future: F,
) -> F::Output {
    CURRENT_AUTH_GROUPS
        .scope(RefCell::new(initial), future)
        .await
}

/// Best-effort setter — a no-op outside a [`with_auth_groups`] scope (e.g.
/// unit tests, or a startup handler running without a scope).
pub fn try_set_auth_groups(groups: AuthGroups) {
    let _ = CURRENT_AUTH_GROUPS.try_with(|cell| *cell.borrow_mut() = Some(groups));
}

/// The groups resolved for this connection during `jwt` / `ldap` auth, if any.
///
/// `None` ⇒ no [`with_auth_groups`] scope is active, or auth resolved no
/// groups (a trust / md5 / scram connection); the startup observer then falls
/// back to the config-map group resolver, preserving existing behaviour.
#[must_use]
pub fn current_auth_groups() -> Option<AuthGroups> {
    CURRENT_AUTH_GROUPS
        .try_with(|cell| cell.borrow().clone())
        .ok()
        .flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_is_none_outside_scope() {
        assert!(current_auth_groups().is_none());
    }

    #[test]
    fn try_set_outside_scope_is_no_op() {
        try_set_auth_groups(AuthGroups::resolved(vec!["analyst".into()]));
        assert!(current_auth_groups().is_none());
    }

    #[tokio::test]
    async fn scope_exposes_initial_and_set() {
        let observed = with_auth_groups(None, async {
            let initial = current_auth_groups();
            try_set_auth_groups(AuthGroups::resolved(vec![
                "QC-Finance".into(),
                "QC-Ops".into(),
            ]));
            (initial, current_auth_groups())
        })
        .await;
        assert_eq!(observed.0, None);
        let set = observed.1.expect("set within scope");
        assert_eq!(
            set.groups,
            vec!["QC-Finance".to_string(), "QC-Ops".to_string()]
        );
        assert!(!set.unavailable);
    }

    #[tokio::test]
    async fn unavailable_is_carried() {
        let observed = with_auth_groups(None, async {
            try_set_auth_groups(AuthGroups::unavailable());
            current_auth_groups()
        })
        .await;
        let set = observed.expect("set within scope");
        assert!(set.groups.is_empty());
        assert!(set.unavailable);
    }
}

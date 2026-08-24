//! The control-plane admin seam for grant DDL.
//!
//! [`crate::grant_ddl`] parses `GRANT` / `REVOKE`; this trait *effects* it. As
//! with [`crate::catalog_admin`], [`crate::secret_admin`],
//! [`crate::user_admin`], and [`crate::policy_admin`], the implementation lives
//! in `dataglot-server` (which owns the meta store), so the *seam* lives here
//! and the server depends on this crate — never the reverse (rule 4).
//!
//! **Scope (F5a): store only, no enforcement.** Applying a grant persists a
//! `(grantee, privilege, object)` tuple (or a role membership) to the org-scoped
//! store; it touches no `SessionContext`, no planner, and no policy enforcer, so
//! **no query behaviour changes**. Denying un-granted reads is a separate
//! follow-up (F5b). The handler just applies the change and returns a `GRANT` /
//! `REVOKE` command tag.
//!
//! # Not credentials
//!
//! A grant names a principal, a privilege, and an object — all config-level, no
//! secrets (the parser's [`crate::grant_ddl::GrantDdl`] derives a plain `Debug`
//! for the same reason). So this module has no rule-12 redaction obligation;
//! [`GrantOutcome`] and [`GrantAdminError`] carry only object/principal names.

use async_trait::async_trait;

use crate::grant_ddl::GrantDdl;

/// Outcome of a grant-DDL statement (no session-visible effect in F5a).
#[derive(Debug)]
pub enum GrantOutcome {
    /// A privilege or role membership was recorded (`GRANT …`).
    Granted,
    /// A privilege or role membership was removed (`REVOKE …`).
    Revoked,
    /// Nothing changed — a `REVOKE` of a grant/membership that did not exist.
    /// The statement still succeeds (Postgres `REVOKE` of an absent grant is a
    /// warning, not an error).
    NoOp,
}

/// Why a grant-DDL statement could not be applied. Every variant's `Display` is
/// client-safe and names only objects/principals (never a session's data).
#[derive(Debug)]
pub enum GrantAdminError {
    /// Grant DDL is unavailable on this server: no control-plane store.
    NotConfigured,
    /// A meta-store read/write failed. The reason is value-free.
    Backend(String),
}

impl std::fmt::Display for GrantAdminError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotConfigured => write!(
                f,
                "grant management is unavailable: this needs a configured \
                 catalog_service"
            ),
            Self::Backend(reason) => write!(f, "{reason}"),
        }
    }
}

impl std::error::Error for GrantAdminError {}

/// Server-side seam that effects grant DDL: persist the grant / role membership
/// to the org-scoped store. **F5a persists only — it does not enforce.**
///
/// Implemented in `dataglot-server`. The pgwire handler holds one behind an
/// `Arc<dyn GrantAdmin>` and calls [`Self::apply`] on a parsed statement.
#[async_trait]
pub trait GrantAdmin: Send + Sync {
    /// Apply a parsed grant-DDL statement **scoped to `org`**. `org` is the
    /// connection's resolved org, threaded from the session
    /// identity by the handler so the grant persists under the issuing
    /// connection's tenant.
    ///
    /// # Errors
    /// [`GrantAdminError`] on missing configuration or a store failure.
    async fn apply(&self, org: &str, ddl: GrantDdl) -> Result<GrantOutcome, GrantAdminError>;
}

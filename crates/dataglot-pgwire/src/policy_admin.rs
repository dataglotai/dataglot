//! The control-plane admin seam for policy DDL.
//!
//! [`crate::policy_ddl`] parses `CREATE / DROP MASK` and
//! `CREATE / DROP ROW FILTER`; this trait *effects* it. As with
//! [`crate::catalog_admin`], [`crate::secret_admin`], and
//! [`crate::user_admin`], the implementation lives in `dataglot-server`
//! (which owns the meta store *and* the live policy enforcer), so the
//! *seam* lives here and the server depends on this crate — never the
//! reverse (rule 4).
//!
//! Unlike catalog DDL, a policy change touches **no** `SessionContext`:
//! the rule is applied to the process-wide governance enforcer (so every
//! active session sees it on its next query, via the published
//! `MutableEnforcer`) and persisted to the org-scoped store (so it
//! survives restart). The handler just applies the change and returns a
//! command tag.
//!
//! # Not credentials
//!
//! A mask literal / row-filter predicate is config-level governance, not
//! a secret (the parser's [`crate::policy_ddl::PolicyDdl`] derives a plain
//! `Debug` for the same reason). So — unlike the secret/user seams — this
//! module has no rule-12 redaction obligation; [`PolicyOutcome`] and
//! [`PolicyAdminError`] carry only the policy name.

use async_trait::async_trait;

use crate::policy_ddl::PolicyDdl;

/// Outcome of a policy-DDL statement (no session-visible effect). Carries
/// only the affected policy name.
#[derive(Debug)]
pub enum PolicyOutcome {
    /// A mask or row filter was created — both applied to the live
    /// enforcer and persisted.
    Created {
        /// Policy name.
        name: String,
    },
    /// A mask or row filter was dropped — removed from the live enforcer
    /// and the store.
    Dropped {
        /// Policy name.
        name: String,
    },
    /// Nothing changed (`IF NOT EXISTS` on an existing name, `IF EXISTS`
    /// on a missing one). The statement still succeeds.
    NoOp,
}

/// Why a policy-DDL statement could not be applied. Every variant's
/// `Display` is client-safe and names only the policy (never a session's
/// data).
#[derive(Debug)]
pub enum PolicyAdminError {
    /// `CREATE MASK`/`CREATE ROW FILTER <name>` without `IF NOT EXISTS`,
    /// but the name already exists.
    AlreadyExists(String),
    /// `DROP …` (without `IF EXISTS`) on a name that does not exist.
    NotFound(String),
    /// Policy DDL is unavailable on this server: no control-plane store,
    /// or no live rule store to enforce against.
    NotConfigured,
    /// The rule could not be assembled or the enforcer rejected it, or a
    /// meta-store read/write failed. The reason is value-free.
    Backend(String),
}

impl std::fmt::Display for PolicyAdminError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AlreadyExists(name) => write!(f, "policy {name:?} already exists"),
            Self::NotFound(name) => write!(f, "policy {name:?} does not exist"),
            Self::NotConfigured => write!(
                f,
                "policy management is unavailable: this needs a configured \
                 catalog_service and a live policy rule store"
            ),
            Self::Backend(reason) => write!(f, "{reason}"),
        }
    }
}

impl std::error::Error for PolicyAdminError {}

/// Server-side seam that effects policy DDL: apply the rule to the live
/// governance enforcer and persist it to the store.
///
/// Implemented in `dataglot-server`. The pgwire handler holds one behind
/// an `Arc<dyn PolicyAdmin>` and calls [`Self::apply`] on a parsed
/// statement.
#[async_trait]
pub trait PolicyAdmin: Send + Sync {
    /// Apply a parsed policy-DDL statement **scoped to `org`**. `org` is
    /// the connection's resolved org, threaded from the
    /// session identity by the handler so the policy persists under the
    /// issuing connection's tenant.
    ///
    /// # Errors
    /// [`PolicyAdminError`] on a name precondition, missing configuration,
    /// a rule the enforcer refuses, or a store failure.
    async fn apply(&self, org: &str, ddl: PolicyDdl) -> Result<PolicyOutcome, PolicyAdminError>;
}

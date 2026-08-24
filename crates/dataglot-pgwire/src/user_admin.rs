//! The control-plane admin seam for user/role DDL.
//!
//! [`crate::user_ddl`] parses `CREATE / ALTER / DROP USER` and
//! `CREATE / DROP ROLE`; this trait effects it. As with [`crate::catalog_admin`]
//! and [`crate::secret_admin`], the implementation lives in `dataglot-server`
//! (which owns the meta store + the envelope key used to protect the password),
//! so the *seam* lives here and the server depends on this crate — never the
//! reverse (rule 4).
//!
//! Like a secret, a user change touches **no** `SessionContext`: the password is
//! only ever read later, on the *next* connection's auth exchange (the
//! store-backed [`crate::PasswordSource`] the server layers into
//! [`crate::AuthMode::Md5`]). So the handler just applies the change and returns
//! a command tag.
//!
//! # Rule 12 (credential isolation)
//!
//! The password never crosses this seam in the clear once applied: the impl
//! hashes/encrypts it before it reaches the store, and neither [`UserOutcome`]
//! nor [`UserAdminError`] carries a password — their `Display`/`Debug` are
//! value-free (they name only the user/role and the problem).

use async_trait::async_trait;

use crate::user_ddl::UserDdl;

/// Outcome of a user/role-DDL statement (no session-visible effect). Carries
/// only the affected name — never a password (rule 12).
#[derive(Debug)]
pub enum UserOutcome {
    /// A user or role was created.
    Created {
        /// User/role name.
        name: String,
    },
    /// An existing user's password was changed (`ALTER USER … PASSWORD`).
    Altered {
        /// User name.
        name: String,
    },
    /// A user or role was dropped.
    Dropped {
        /// User/role name.
        name: String,
    },
    /// Nothing changed (`IF NOT EXISTS` on an existing name, `IF EXISTS` on a
    /// missing one). The statement still succeeds.
    NoOp,
}

/// Why a user/role-DDL statement could not be applied. Every variant's
/// `Display` is client-safe and **never** echoes the password (rule 12).
#[derive(Debug)]
pub enum UserAdminError {
    /// `CREATE USER`/`CREATE ROLE <name>` without `IF NOT EXISTS`, but the name
    /// already exists.
    AlreadyExists(String),
    /// `ALTER`/`DROP` on a name that does not exist (without `IF EXISTS`).
    NotFound(String),
    /// User/role DDL is unavailable on this server: no control-plane store, or —
    /// for a statement that sets a password — no `DATAGLOT_SECRET_KEY` envelope
    /// key to protect it with.
    NotConfigured,
    /// A password-protection or meta-store write failed. The reason is
    /// value-free (rule 12).
    Backend(String),
}

impl std::fmt::Display for UserAdminError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AlreadyExists(name) => write!(f, "role {name:?} already exists"),
            Self::NotFound(name) => write!(f, "role {name:?} does not exist"),
            Self::NotConfigured => write!(
                f,
                "user management is unavailable: this needs a configured \
                 catalog_service, and setting a password additionally needs a \
                 DATAGLOT_SECRET_KEY envelope key"
            ),
            Self::Backend(reason) => write!(f, "{reason}"),
        }
    }
}

impl std::error::Error for UserAdminError {}

/// Server-side seam that effects user/role DDL: protect the password + persist
/// to the store.
///
/// Implemented in `dataglot-server`. The pgwire handler holds one behind an
/// `Arc<dyn UserAdmin>` and calls [`Self::apply`] on a parsed statement.
#[async_trait]
pub trait UserAdmin: Send + Sync {
    /// Apply a parsed user/role-DDL statement **scoped to `org`**. `org` is the
    /// connection's resolved org, threaded from the session
    /// identity by the handler so a user/role persists under the issuing
    /// connection's tenant.
    ///
    /// # Errors
    /// [`UserAdminError`] on a name precondition, missing configuration, or a
    /// protection / store failure.
    async fn apply(&self, org: &str, ddl: UserDdl) -> Result<UserOutcome, UserAdminError>;
}

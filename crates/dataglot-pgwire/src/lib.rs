//! `PostgreSQL` wire protocol interface via `pgwire` and `datafusion-postgres`.
//!
//! This crate provides the pg wire protocol layer for Dataglot,
//! allowing `PostgreSQL` clients (psql, JDBC, etc.) to connect and execute
//! queries against `DataFusion`.
//!
//! # Architecture
//!
//! ```text
//! psql/JDBC client
//!       │
//!       ▼ TCP
//! ┌─────────────────────┐
//! │   dataglot-pgwire    │
//! │  (this crate)       │
//! │                     │
//! │  ┌───────────────┐  │
//! │  │ pgwire crate  │  │  ← Protocol parsing
//! │  └───────┬───────┘  │
//! │          │          │
//! │  ┌───────▼───────┐  │
//! │  │ datafusion-   │  │  ← Query execution
//! │  │ postgres      │  │
//! │  └───────────────┘  │
//! └─────────────────────┘
//!       │
//!       ▼
//!   DataFusion SessionContext
//! ```
//!
//! # Example
//!
//! ```ignore
//! use std::sync::Arc;
//! use datafusion::prelude::SessionContext;
//! use dataglot_pgwire::handle_connection;
//!
//! async fn handle(stream: TcpStream, peer: SocketAddr) {
//!     let ctx = Arc::new(SessionContext::new());
//!     handle_connection(stream, peer, ctx).await.unwrap();
//! }
//! ```

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used))]
// bare .unwrap() panics without context on a live server; use .expect("why") or return an error. Tests exempt.
#![warn(missing_docs)]
#![cfg_attr(not(test), deny(clippy::print_stdout, clippy::print_stderr))]

pub mod auth;
pub mod auth_groups;
pub mod auth_org;
pub mod auth_principal;
pub mod catalog_admin;
pub mod catalog_bypass;
pub mod catalog_ddl;
pub mod copy;
pub mod error;
pub mod explain;
pub mod grant_admin;
pub mod grant_ddl;
pub mod handler;
mod identifier_guard;
mod identity_registers;
pub mod jwt;
pub mod ldap;
pub mod observer;
pub mod pg_compat;
pub mod policy_admin;
pub mod policy_ddl;
pub mod secret_admin;
pub mod secret_ddl;
pub mod server_tls;
pub mod session_org;
pub mod show_schemas;
pub mod show_variable;
mod sql_split;
pub mod user_admin;
pub mod user_ddl;
pub mod view_admin;
pub mod view_ddl;

pub use auth::{AuthMode, PasswordSource};
pub use auth_groups::{current_auth_groups, try_set_auth_groups, with_auth_groups, AuthGroups};
pub use auth_org::{current_auth_org, set_auth_org, try_set_auth_org, with_auth_org};
pub use auth_principal::{
    current_auth_principal, try_set_auth_principal, with_auth_principal, AuthPrincipal,
};
pub use error::{PgWireError, Result};
pub use handler::{
    handle_connection, handle_connection_with_observer, handle_connection_with_observers,
    handle_connection_with_observers_and_auth, handle_connection_with_security, CancelRegistry,
    ConnectionSecurity, DataglotHandlerFactory, IdentityAdmission, IdentityLimited, IdentityPermit,
    IngressTls, QueryHandle, StartupInfo, StartupObserver, StartupRejection,
};

pub use jwt::{JwtAlgorithm, JwtError, JwtVerifier, VerifiedJwt};
pub use ldap::{
    GroupLookup, Ldap3Connection, LdapAuthenticator, LdapConfig, LdapConnection, LdapError,
    LdapOutcome,
};
pub use observer::{CompositeQueryObserver, NoopObserver, QueryObserver, QueryOutcome};
/// The rustls-backed TLS acceptor type for pgwire ingress (re-exported
/// from `pgwire::tokio`) so the server can hold one without a direct
/// `pgwire` / `tokio-rustls` dependency.
pub use pgwire::tokio::TlsAcceptor;
pub use server_tls::build_tls_acceptor;
pub use session_org::{
    current_session_org, set_session_org, try_set_session_org, with_session_org,
};

#[cfg(test)]
mod tests {
    #[test]
    fn test_crate_compiles() {
        // Verify crate compiles correctly with all modules
    }
}

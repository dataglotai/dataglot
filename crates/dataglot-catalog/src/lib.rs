//! Peaka Catalog Service — the Phase 1 control plane for
//! `CatalogBinding` registration.
//!
//! Spec: `docs/phases/phase-1/08-catalog-service.md`.
//!
//! The service owns the binding map persistently (across server
//! restarts) and exposes it via a typed in-process API. The
//! upcoming in-process cache (Phase 1 task 09) sits in front of
//! it as the read-path optimisation.
//!
//! # Scope (Phase 1)
//!
//! - Single-tenant — `default` org hardcoded; the schema carries
//!   `org_id` from day one so Phase 2 multi-tenant just flips
//!   the routing on.
//! - In-process — no remote protocol yet; callers `await`
//!   directly on the service's `async fn` methods. Phase 2
//!   picks the protocol.
//! - JSON authoritative — operators still declare catalogs in
//!   `dataglot.toml`; the service is the propagation +
//!   persistence layer. Phase 2 inverts this once runtime
//!   mutation lands.
//!
//! # Crate dependency direction
//!
//! Extends CLAUDE.md rule 4:
//!
//! ```text
//! dataglot-server → dataglot-catalog → dataglot-core
//! ```
//!
//! The pgwire / federation / policy crates do NOT depend on
//! `dataglot-catalog`; the catalog service is a server-binary
//! concern only.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![cfg_attr(not(test), deny(clippy::print_stdout, clippy::print_stderr))]

pub mod cache;
pub mod embedded;
pub mod error;
/// Version-keyed migration runners shared by the two `MetaStore` backends
///. Internal to the crate — the backends register their own
/// ordered chains and drive them from their open/connect paths.
mod migrations;
pub mod redb_store;
pub mod service;
pub mod store;
pub mod subscribe;

pub use cache::CatalogProviderCache;
pub use embedded::EmbeddedMetaStore;
pub use error::{CatalogServiceError, Result};
pub use redb_store::RedbMetaStore;
pub use service::CatalogService;
pub use store::{
    DerivedProductRecord, GrantObject, GrantRecord, GranteeKind, MetaStore, PolicyRecord,
    Privilege, UserRecord,
};
pub use subscribe::{BindingChange, BindingChangeKind, BindingChangeStream};

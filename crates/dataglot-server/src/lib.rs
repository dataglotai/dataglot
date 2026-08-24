//! `dataglot-server` library surface.
//!
//! The binary at `src/main.rs` is the production entrypoint; this lib
//! exists so integration tests (and any future in-process embedder)
//! can drive [`server::DataglotServer`] directly without spawning the
//! binary as a subprocess.
//!
//! Public surface is intentionally thin — the modules are exposed,
//! and a few selected symbols are re-exported for ergonomics. Keep
//! the surface small; tests prefer `dataglot_server::module::Type`
//! over re-exports so the source of each symbol stays obvious.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used))]
// bare .unwrap() panics without context on a live server; use .expect("why") or return an error. Tests exempt.
#![warn(missing_docs)]
#![cfg_attr(not(test), deny(clippy::print_stdout, clippy::print_stderr))]

pub mod ballista;
pub mod catalog_admin;
pub mod cli;
pub mod cluster;
pub mod config;
pub mod connectors;
/// Read-only Control Plane view (`GET /api/control-plane`) for the dashboard —
/// lists the meta store's persisted objects.
pub mod control_plane;
/// Embedded operational-dashboard SPA served at `/ui`.
/// Behind the `dashboard` feature so default builds carry no UI.
#[cfg(feature = "dashboard")]
pub mod embed;
pub mod first_run;
// SQL-native grants: the GRANT/REVOKE admin. Stores
// privileges + role memberships in the meta store; no enforcement (that is
// F5b). Sibling of `policy_admin` / `user_admin`.
pub mod grant_admin;
// SQL-native secrets: the CREATE/DROP SECRET admin + the
// envelope cipher, siblings of `catalog_admin`.
pub mod secret_admin;
pub mod secret_crypto;
pub mod user_admin;
// SQL-native derived products: the CREATE/DROP VIEW admin.
// Plans + persists a view as a derived product and registers it live so
// subsequent connections can query it. Sibling of `catalog_admin`.
pub mod view_admin;
// Arrow Flight SQL egress — off by default; enabled by the
// `flight_sql` feature. Internal: it reaches into `DataglotServer`'s
// session/shutdown internals, so it stays crate-private.
#[cfg(feature = "flight_sql")]
pub(crate) mod flight_sql;
pub mod governance;
// Directory-group resolution: the pluggable `GroupResolver` seam
// (config / JWT / LDAP) that populates `Identity::org_groups` from an external
// identity provider.
pub mod group_resolver;
// Internal — the EL upsert merge core is a server internal (touches warehouse
// write internals); its REST-endpoint consumer lands in a follow-up. The two
// symbols below are re-exported (module stays private) so the Trino-retirement
// slice-5 dual-run parity gate can drive the EL mechanic against a
// Trino `MERGE` reference; production wiring still goes through the server.
pub(crate) mod ingest;
pub use ingest::{upsert_into_table, UpsertOutcome};
pub mod lineage;
pub mod lineage_snapshot;
// Internal — the refresh orchestration/scheduler are server internals (they
// touch warehouse write internals); only the server's own boot path calls them.
pub(crate) mod materialization;
pub mod materialization_registry;
// Internal — warehouse table compaction (OPTIMIZE replacement); its
// maintenance-trigger consumer lands in a follow-up. The two symbols below are
// re-exported (module stays private) so the slice-5 dual-run parity gate
// can drive compaction against a Trino `OPTIMIZE` reference.
pub(crate) mod maintenance;
pub mod maintenance_registry;
pub use maintenance::{
    build_compaction_jobs, build_orphan_sweep_jobs, compact_table, CompactOutcome,
};
pub mod observability;
pub mod policy_admin;
pub mod policy_explain;
pub mod propagation;
pub mod query;
pub mod query_registry;
pub mod rate_limit;
pub mod server;
pub mod session_registry;
pub mod shell;
pub mod webhook;

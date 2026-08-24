//! Distributed-execution wiring for Dataglot, built on Apache Ballista.
//!
//! Sibling crate to `dataglot-server` rather than a feature flag on it —
//! Ballista's dep tree (gRPC scheduler, in-process executor, Arrow
//! Flight shuffle) is heavy enough to dominate the default workspace
//! build, and operators on the single-node path should never pay for it.
//!
//! # Phase 2 status
//!
//! - **Slice 1** (this commit) — localhost smoke test only. Boots a
//!   standalone (1-coordinator + 1-executor, in-process) Ballista
//!   cluster and proves a SQL query round-trips. The exported surface
//!   is intentionally empty; the test binary at
//!   `tests/smoke_localhost.rs` is the deliverable.
//! - **Slice 2** — `BallistaContextFactory` lands in `dataglot-core` as
//!   a sibling of `SessionContextFactory`, with this crate wiring it
//!   through to the standalone-cluster shape used here.
//! - **Slices 3 – 8** — credentials per-worker, split-level parallelism,
//!   object-store `ETag` scheduler HA, governance parity, mTLS, and the
//!   four-worker exit-criterion benchmark. See
//!   `docs/phases/phase-2/02-ballista-distributed-execution.md`.
//!
//! Slice 2 (this drop) ships the [`BallistaContextFactory`] —
//! the sibling of `dataglot-core::SessionContextFactory` that
//! single-node code paths consume. See the type doc and
//! `docs/phases/phase-2/02-ballista-distributed-execution.md`
//! slice 2 for the design rationale.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used))]
// bare .unwrap() panics without context on a live server; use .expect("why") or return an error. Tests exempt.
#![warn(missing_docs)]
#![cfg_attr(not(test), deny(clippy::print_stdout, clippy::print_stderr))]

pub mod cancel_on_drop;
pub mod catalogs_config;
pub mod cluster;
pub mod codec;
pub mod executor;
pub mod factory;
pub mod ha;
pub mod monitor;
pub mod plan_guard;
pub mod scheduler;
pub mod server;
pub mod tls;

pub use catalogs_config::{CatalogEntry, CatalogsConfig, CatalogsConfigError};
pub use cluster::BallistaCluster;
pub use codec::FederationLogicalCodec;
pub use executor::{
    build_executor_process_config, run_executor, CredentialResolverExtension, ExecutorArgs,
};
pub use factory::BallistaContextFactory;
pub use ha::{ClaimOutcome, LeaseError, LeasePayload, ObjectStoreLease};
pub use plan_guard::{validate_serializable_plan, SerializationGuardQueryPlanner};
pub use scheduler::{run_scheduler, SchedulerArgs};
pub use server::{run_executor_tls, run_scheduler_tls};
pub use tls::{install_default_crypto_provider, BallistaTlsConfig, TlsArgs, TlsConfigError};

// Re-export of Ballista's stock physical codec — the production
// wrap target for `FederationPlanCodec::with_inner_physical_codec`.
// Re-exported here so `dataglot-server`'s ballista wiring doesn't
// have to take a direct `ballista-core` dep just to construct the
// default wrapper (CLAUDE.md rule 4: every cross-crate touchpoint
// goes through a known re-export, not a transitive symbol).
pub use ballista_core::serde::BallistaPhysicalExtensionCodec;

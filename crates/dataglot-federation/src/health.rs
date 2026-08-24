//! Cheap liveness probing for a *already-built* connector.
//!
//! The connector health poller (`dataglot-server`'s `ConnectorMonitor`) used to
//! re-probe liveness by **rebuilding** the connector from config on every tick
//! — a full re-authentication plus an eager `INFORMATION_SCHEMA` walk for SQL
//! sources, then the freshly-built provider was thrown away. On a 30s timer
//! (and on the dashboard "Check now" path) that is pure waste: the query path
//! already reuses the boot-built provider.
//!
//! Every SQL connector's `as_catalog_provider(self: &Arc<Self>)` takes
//! `&Arc<Self>`, so the boot path can retain the `Arc<Connector>` after the
//! provider is built and keep it as a health-check handle. [`ConnectorHealthCheck`]
//! is that handle's contract: a single cheap round-trip on the **existing,
//! already-authenticated** client — no rebuild, no re-auth.

/// A cheap liveness probe over an already-built, already-authenticated
/// connector.
///
/// The boot path keeps the `Arc<Connector>` it used to build the catalog
/// provider and hands a clone back as an `Arc<dyn ConnectorHealthCheck>`; the
/// health poller then calls [`Self::health_check`] on a timer instead of
/// rebuilding the connector.
///
/// Implementors run the cheapest reachability query the source supports (a
/// `SELECT 1`) on their existing client. The point is only to learn whether the
/// source is still reachable and the credentials still valid — the result rows
/// are discarded.
///
/// # CLAUDE.md compliance
/// * Rule 10 — `Send + Sync + 'static`, async.
/// * Rule 11 — implementors do all I/O asynchronously (blocking clients hop
///   through `spawn_blocking` exactly as their `SQLExecutor` impl does).
/// * Rule 12 — the returned error string must be credential-safe: it may name
///   the failure ("`SELECT 1` failed") but must never carry a DSN, password, or
///   other secret.
#[async_trait::async_trait]
pub trait ConnectorHealthCheck: Send + Sync + 'static {
    /// Cheap liveness probe that REUSES the existing authenticated client — a
    /// single round-trip that errors iff the source is unreachable or creds are
    /// invalid. Must NOT rebuild the client or re-authenticate. The returned
    /// error string must be credential-safe (CLAUDE.md rule 12).
    async fn health_check(&self) -> Result<(), String>;
}

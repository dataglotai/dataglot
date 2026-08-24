//! `PostgreSQL` wire protocol handler using `datafusion-postgres`.
//!
//! This module provides the connection handling logic that bridges
//! pgwire to `DataFusion` via the `datafusion-postgres` crate.

use std::fmt::Debug;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use datafusion::catalog::MemoryCatalogProvider;
use datafusion::common::TableReference;
use datafusion::datasource::ViewTable;
use datafusion::logical_expr::LogicalPlan;
use datafusion::prelude::SessionContext;
use datafusion_postgres::{DfSessionService, QueryHook};
use futures::Sink;
use pgwire::api::auth::md5pass::Md5PasswordAuthStartupHandler;
use pgwire::api::auth::noop::NoopStartupHandler;
use pgwire::api::auth::sasl::{scram, SASLAuthStartupHandler};
use pgwire::api::auth::{DefaultServerParameterProvider, StartupHandler};
use pgwire::api::cancel::CancelHandler;
use pgwire::api::portal::{Format, Portal};
use pgwire::api::query::{ExtendedQueryHandler, SimpleQueryHandler};
use pgwire::api::results::{
    DescribePortalResponse, DescribeStatementResponse, FieldInfo, Response, Tag,
};
use pgwire::api::stmt::{QueryParser, StoredStatement};
use pgwire::api::store::PortalStore;
use pgwire::api::PgWireConnectionState;
use pgwire::api::{
    ClientInfo, ClientPortalStore, ConnectionManager, ErrorHandler, PgWireServerHandlers,
    PidSecretKeyGenerator, RandomPidSecretKeyGenerator, Type,
};
use pgwire::error::{PgWireError, PgWireError as PgWireLibError, PgWireResult};
use pgwire::messages::{PgWireBackendMessage, PgWireFrontendMessage};
use pgwire::tokio::{process_socket, TlsAcceptor};
use tokio::net::TcpStream;

use dataglot_core::lineage::RunId;

use crate::auth::{AuthMode, DataglotAuthSource, ScramAuthSource};
use crate::catalog_admin::{CatalogAdmin, CatalogAdminError, CatalogAdminOutcome};
use crate::catalog_bypass::plan_references_catalog_metadata;
use crate::catalog_ddl::{parse_catalog_ddl, CatalogDdl};
use crate::copy::{build_copy_out_response, detect_copy_to_stdout};
use crate::error::Result;
use crate::explain::rewrite_explain_federation;
use crate::grant_admin::{GrantAdmin, GrantAdminError};
use crate::grant_ddl::{parse_grant_ddl, GrantDdl};
use crate::identifier_guard::reject_deep_compound_identifier;
use crate::identity_registers::rewrite_identity_registers;
use crate::observer::{NoopObserver, QueryObserver, QueryOutcome};
use crate::pg_compat::{noop_command_tag, rewrite_table};
use crate::policy_admin::{PolicyAdmin, PolicyAdminError};
use crate::policy_ddl::{parse_policy_ddl, PolicyDdl};
use crate::secret_admin::{SecretAdmin, SecretAdminError};
use crate::secret_ddl::{parse_secret_ddl, SecretDdl};
use crate::show_schemas::rewrite_show_schemas;
use crate::show_variable::rewrite_show_variable;
use crate::sql_split::split_sql_statements;
use crate::user_admin::{UserAdmin, UserAdminError};
use crate::user_ddl::{parse_user_ddl, UserDdl};
use crate::view_admin::{ViewAdmin, ViewAdminError, ViewAdminOutcome};
use crate::view_ddl::{parse_view_ddl, ViewDdl};

/// Startup parameters extracted from the pgwire `StartupMessage`,
/// handed to the [`StartupObserver`] once per connection.
///
/// Borrows from the connection's metadata map; valid only for the
/// duration of the callback.
#[derive(Debug, Clone, Copy)]
pub struct StartupInfo<'a> {
    /// The `user` startup parameter (empty string when absent).
    pub user: &'a str,
    /// The `database` startup parameter, if the client provided a
    /// non-empty one. The server crate maps this to the session's
    /// default catalog (Postgres `\c <db>` semantics) when it names a
    /// registered catalog.
    pub database: Option<&'a str>,
}

/// Callback invoked once per connection, after the pgwire startup
/// handshake has stored `StartupMessage` parameters in
/// [`ClientInfo::metadata`]. Receives the parsed [`StartupInfo`]
/// (username + optional database).
///
/// The server crate uses this to (a) swap the per-task session
/// identity — see `dataglot_policy::with_session_identity` /
/// `dataglot_policy::set_session_identity` — and (b) set the
/// connection's default catalog from the `database` parameter. The
/// callback runs on the connection's task, before any query is
/// handled, so writes to a tokio task-local or to the connection's
/// `SessionContext` from inside the closure are visible to subsequent
/// query handling on that same connection.
///
/// Defaults to a no-op when not provided; the no-op path matches the
/// pre-#150 behaviour where every session ran with
/// `Identity::anonymous()` and the server's configured default catalog.
///
/// Returning `Err(StartupRejection)` **refuses** the connection with a
/// FATAL pgwire error carrying the given SQLSTATE — e.g. an unknown
/// `database` startup parameter maps to `3D000 invalid_catalog_name`,
/// matching Postgres, instead of silently falling back to the
/// server default catalog.
pub type StartupObserver = Arc<
    dyn for<'a> Fn(&StartupInfo<'a>) -> std::result::Result<(), StartupRejection> + Send + Sync,
>;

/// A startup observer's decision to refuse a connection. Mapped to a
/// pgwire FATAL `ErrorResponse` (`ErrorInfo` with severity `FATAL` and
/// the given `sqlstate`) by the crate-internal startup dispatch.
#[derive(Debug, Clone)]
pub struct StartupRejection {
    /// SQLSTATE code, e.g. `"3D000"` (`invalid_catalog_name`).
    pub sqlstate: String,
    /// Human-readable message, e.g. `database "foo" does not exist`.
    pub message: String,
}

fn noop_startup_observer() -> StartupObserver {
    Arc::new(|_: &StartupInfo<'_>| Ok(()))
}

/// Opaque per-connection guard returned by [`IdentityAdmission::admit`].
/// Held for the connection's lifetime and released on drop — the server's
/// implementation uses the drop to decrement its per-identity counter.
pub type IdentityPermit = Box<dyn Send + Sync>;

/// Returned by [`IdentityAdmission::admit`] when the identity has reached
/// its connection limit; the pgwire layer maps it to a `53300`
/// (`too_many_connections`) fatal error.
#[derive(Debug, Clone, Copy)]
pub struct IdentityLimited;

/// Per-identity admission control, consulted once per connection with the
/// asserted username from the startup message (**before** authentication),
/// so the server can bound concurrent connections per identity. The pgwire
/// layer only *invokes* it; the policy + counters live in `dataglot-server`
/// (rule 4 keeps this crate free of server dependencies).
///
/// Admission runs on the initial `Startup` message, before the auth
/// exchange and before `ReadyForQuery` — so a refusal fails the client's
/// connect cleanly rather than surfacing on the first query. Because it
/// keys on the *asserted* (not yet verified) username, it also throttles
/// per-username brute-force before the password check.
pub trait IdentityAdmission: Send + Sync {
    /// Admit a connection for `user`. Returns a guard held for the
    /// connection's lifetime, or [`IdentityLimited`] to refuse it.
    ///
    /// # Errors
    /// Returns [`IdentityLimited`] when `user` is at its connection limit.
    fn admit(&self, user: &str) -> std::result::Result<IdentityPermit, IdentityLimited>;
}

/// Handler factory that creates pgwire handlers backed by `DataFusion`.
///
/// This implements `PgWireServerHandlers` to provide the necessary
/// handlers for the pgwire protocol. The optional `QueryObserver`
/// receives a callback once per query handled — the server crate uses
/// this to bump Prometheus counters (see Phase 0.5 Task 03). The
/// optional [`StartupObserver`] receives the username extracted from
/// the `StartupMessage` once per connection — the server crate uses
/// this to swap the per-task session identity.
pub struct DataglotHandlerFactory {
    session_service: Arc<DfSessionService>,
    /// The session context, kept so the simple-query handler can capture
    /// the unoptimized `LogicalPlan` before execution for plan-wanting
    /// observers.
    session_context: Arc<SessionContext>,
    observer: Arc<dyn QueryObserver>,
    startup_observer: StartupObserver,
    auth: AuthMode,
    /// When true, a connection that did not negotiate TLS is rejected at
    /// startup (`require` mode). The TLS acceptor itself is supplied to
    /// `process_socket`, not held here — this only drives the
    /// plaintext-rejection check in the startup handler.
    tls_required: bool,
    /// Optional per-identity admission control (bounds connections per
    /// username). Consulted on the startup message, before auth.
    admission: Option<Arc<dyn IdentityAdmission>>,
    /// Per-connection slot holding the admission guard for this connection's
    /// lifetime. The factory is owned by `process_socket` for the whole
    /// connection, so keeping the guard here releases it (drops the server's
    /// per-identity count) exactly when the connection ends.
    identity_permit: Arc<Mutex<Option<IdentityPermit>>>,
    /// Registry of live connections' backend keys + cancel state.
    /// The startup handlers register each connection here, and the
    /// cancel handler resolves incoming `CancelRequest`s against it —
    /// without this, pgwire's `cancel_handler()` defaults to a no-op
    /// and a client's cancel is silently dropped while the query runs
    /// to completion ( finding: `Ctrl-C` in psql did nothing).
    cancel_registry: Arc<CancelRegistry>,
    /// SQL-native catalog-DDL executor. `Some` when the
    /// server has a control-plane store; the simple-query handler routes
    /// `CREATE / ALTER / DROP CATALOG` here. `None` ⇒ catalog DDL is rejected
    /// with a clear "requires a configured `catalog_service`" error.
    catalog_admin: Option<Arc<dyn CatalogAdmin>>,
    /// SQL-native secret-DDL executor. `Some` when the server
    /// has a control-plane store *and* an envelope key; the simple-query handler
    /// routes `CREATE / DROP SECRET` here. `None` ⇒ secret DDL is rejected.
    secret_admin: Option<Arc<dyn SecretAdmin>>,
    /// SQL-native user/role-DDL executor. `Some` when the
    /// server has a control-plane store; the simple-query handler routes
    /// `CREATE / ALTER / DROP USER` and `CREATE / DROP ROLE` here. `None` ⇒
    /// user DDL is rejected with a clear error.
    user_admin: Option<Arc<dyn UserAdmin>>,
    /// SQL-native policy-DDL executor. `Some` when the
    /// server has both a control-plane store and a live rule store; the
    /// simple-query handler routes `CREATE / DROP MASK` and
    /// `CREATE / DROP ROW FILTER` here. `None` ⇒ policy DDL is rejected.
    policy_admin: Option<Arc<dyn PolicyAdmin>>,
    /// SQL-native grant-DDL executor. `Some` when the
    /// server has a control-plane store; the simple-query handler routes
    /// `GRANT / REVOKE` here. F5a **persists only** — no enforcement. `None` ⇒
    /// grant DDL is rejected with a clear error.
    grant_admin: Option<Arc<dyn GrantAdmin>>,
    /// SQL-native view-DDL executor. `Some` when the server
    /// has a control-plane store; the simple-query handler routes
    /// `CREATE / DROP VIEW` (derived products) here. `None` ⇒ view DDL is
    /// rejected with a clear error.
    view_admin: Option<Arc<dyn ViewAdmin>>,
}

/// One connection's cancellation slot: the flag for the query that is
/// *currently* streaming. Replaced at the start of every query, so a
/// late cancel for a finished query is a harmless no-op on a stale
/// flag (standard Postgres best-effort cancel semantics).
pub struct CancelSlot {
    current: std::sync::Mutex<Arc<CancelFlag>>,
}

impl CancelSlot {
    fn new() -> Self {
        Self {
            current: std::sync::Mutex::new(Arc::new(CancelFlag::default())),
        }
    }

    /// Install a fresh flag for a starting query and return it.
    fn begin_query(&self) -> Arc<CancelFlag> {
        let flag = Arc::new(CancelFlag::default());
        *self.current.lock().expect("cancel-slot lock") = Arc::clone(&flag);
        flag
    }

    fn cancel_current(&self) {
        self.current.lock().expect("cancel-slot lock").cancel();
    }
}

/// A set-once async flag (`AtomicBool` + `Notify`): cheap to poll from
/// the row-stream wrapper, wakeable from the cancel handler.
#[derive(Default)]
struct CancelFlag {
    cancelled: std::sync::atomic::AtomicBool,
    notify: tokio::sync::Notify,
}

impl CancelFlag {
    fn cancel(&self) {
        self.cancelled
            .store(true, std::sync::atomic::Ordering::SeqCst);
        self.notify.notify_waiters();
    }

    async fn cancelled(&self) {
        // Create the `Notified` future *before* re-checking the flag so
        // a cancel between check and await can't be missed.
        loop {
            let notified = self.notify.notified();
            if self.cancelled.load(std::sync::atomic::Ordering::SeqCst) {
                return;
            }
            notified.await;
        }
    }
}

/// A cancel trigger for one in-flight query. Handed to observers via
/// [`QueryObserver::on_query_cancellable`] so an out-of-band caller —
/// the dashboard's `POST /api/queries/{id}/cancel` —
/// can abort a running
/// query it only knows by [`RunId`]. Cheap to clone (an `Arc`); firing
/// it triggers the same best-effort cancel path a pg `CancelRequest`
/// does, aborting the wrapped row stream.
#[derive(Clone)]
pub struct QueryHandle {
    flag: Arc<CancelFlag>,
}

impl QueryHandle {
    fn new(flag: Arc<CancelFlag>) -> Self {
        Self { flag }
    }

    /// A handle attached to no live query — its [`cancel`](Self::cancel)
    /// fires a flag nothing is listening to. For tests that exercise
    /// registry/endpoint wiring without a real connection.
    #[doc(hidden)]
    #[must_use]
    pub fn detached() -> Self {
        Self {
            flag: Arc::new(CancelFlag::default()),
        }
    }

    /// Signal the query to abort. Best-effort: a no-op if the query has
    /// already finished (the flag is then stale).
    pub fn cancel(&self) {
        self.flag.cancel();
    }
}

impl std::fmt::Debug for QueryHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QueryHandle").finish_non_exhaustive()
    }
}

/// A connection's backend key as the registry stores it: `(pid, secret)`.
type BackendKey = (i32, Vec<u8>);

/// Server-wide cancellation registry. Two layers, both keyed
/// by the connection's backend key `(pid, secret)`:
///
/// - pgwire's own [`ConnectionManager`], which arms the library's
///   `do_query`-vs-cancel race — that covers the **planning** phase;
/// - our [`CancelSlot`]s, which the observing handlers' row-stream
///   wrappers watch — that covers the **streaming** phase, where a
///   long query actually spends its life (`datafusion-postgres`
///   executes lazily via `execute_stream`, so `do_query` returns in
///   milliseconds and pgwire's built-in race alone never fires).
///
/// A Postgres `CancelRequest` arrives on a *new* TCP connection, so
/// one registry must be shared across every connection of the server —
/// see [`ConnectionSecurity::cancel_registry`].
pub struct CancelRegistry {
    manager: Arc<ConnectionManager>,
    slots: std::sync::RwLock<std::collections::HashMap<BackendKey, Arc<CancelSlot>>>,
}

impl CancelRegistry {
    /// A fresh, empty registry. The server creates exactly one and
    /// shares it into every connection's [`ConnectionSecurity`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            manager: Arc::new(ConnectionManager::new()),
            slots: std::sync::RwLock::new(std::collections::HashMap::new()),
        }
    }

    /// Register the (already startup-completed) connection's cancel
    /// slot and stash it in the client's session extensions for the
    /// query handlers. Idempotent per connection.
    fn register_slot<C: ClientInfo>(self: &Arc<Self>, client: &C) {
        let (pid, secret_key) = client.pid_and_secret_key();
        let key = (pid, secret_key.to_bytes().to_vec());
        let slot = Arc::new(CancelSlot::new());
        self.slots
            .write()
            .expect("cancel-registry lock")
            .insert(key.clone(), Arc::clone(&slot));
        client.session_extensions().insert::<Arc<CancelSlot>>(slot);
        client.session_extensions().insert::<SlotGuard>(SlotGuard {
            key,
            registry: Arc::clone(self),
        });
    }

    async fn cancel(&self, pid: i32, secret_key: &pgwire::messages::startup::SecretKey) -> bool {
        // Planning phase (pgwire's own race)…
        let known = self.manager.cancel(pid, secret_key).await;
        // …and streaming phase (our row-stream wrappers).
        let slot = self
            .slots
            .read()
            .expect("cancel-registry lock")
            .get(&(pid, secret_key.to_bytes().to_vec()))
            .cloned();
        if let Some(slot) = &slot {
            slot.cancel_current();
        }
        known || slot.is_some()
    }
}

impl Default for CancelRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Removes the connection's slot from the registry when the connection
/// ends (session extensions drop with the client).
struct SlotGuard {
    key: BackendKey,
    registry: Arc<CancelRegistry>,
}

impl Drop for SlotGuard {
    fn drop(&mut self) {
        self.registry
            .slots
            .write()
            .expect("cancel-registry lock")
            .remove(&self.key);
    }
}

/// Wrap a query's row stream so a fired [`CancelFlag`] aborts it with
/// [`PgWireError::QueryCanceled`] — even while the stream is pending on
/// a slow upstream batch. An abort surfaces as an `ErrorResponse`, never
/// as a silently truncated result set.
fn cancel_aware_rows(
    rows: pgwire::api::results::SendableRowStream,
    flag: Arc<CancelFlag>,
) -> pgwire::api::results::SendableRowStream {
    use futures::StreamExt;
    Box::pin(futures::stream::unfold(
        (rows, flag, false),
        |(mut rows, flag, done)| async move {
            if done {
                return None;
            }
            tokio::select! {
                () = flag.cancelled() => {
                    Some((Err(PgWireError::QueryCanceled), (rows, flag, true)))
                }
                next = rows.next() => next.map(|item| (item, (rows, flag, false))),
            }
        },
    ))
}

/// Emit the connection's pg wire startup username to observers right after
/// `on_query_start`, so the query registry can attribute a running query to
/// who submitted it ( per-query `user` column). The username is
/// startup metadata, never a credential (rule 12); no-op when the client
/// reported none.
fn emit_query_identity<C: ClientInfo>(observer: &dyn QueryObserver, run_id: RunId, client: &C) {
    if let Some(user) = client.metadata().get(pgwire::api::METADATA_USER) {
        observer.on_query_identity(run_id, user);
    }
}

/// Apply [`cancel_aware_rows`] to every `Query` response in place.
fn make_responses_cancel_aware(responses: &mut [Response], flag: &Arc<CancelFlag>) {
    for resp in responses {
        if let Response::Query(qr) = resp {
            let rows = std::mem::replace(&mut qr.data_rows, Box::pin(futures::stream::empty()));
            qr.data_rows = cancel_aware_rows(rows, Arc::clone(flag));
        }
    }
}

/// Fires [`QueryObserver::on_query_complete`] when the query's result
/// stream is fully drained (or dropped) — **not** when `do_query`
/// returns.
///
/// `do_query` returns a *lazy* row stream: the query's real execution
/// happens during streaming, after `do_query` returns. Bracketing
/// completion at `do_query`'s return therefore measures only planning and
/// removes the query from the live registry before it actually runs. This
/// guard defers completion to the true end: an `Arc<QueryCompletion>` is
/// cloned into every `Query` response's row stream; the inner value drops
/// — and `on_query_complete` fires exactly once — when the last stream is
/// consumed or the client disconnects.
struct QueryCompletion {
    observer: Arc<dyn QueryObserver>,
    run_id: RunId,
    query: String,
    plan: Option<Arc<LogicalPlan>>,
    start: Instant,
    /// 0 = success, 1 = error. Set to error when `do_query` failed or any
    /// row-stream item is an error (including a fired cancel).
    outcome: std::sync::atomic::AtomicU8,
    /// The first (root-cause) error message seen, for the History error
    /// detail. Set alongside the error flag; `None` on success.
    /// This is the same text the client received (rule 12: already scrubbed).
    error: std::sync::Mutex<Option<String>>,
}

impl QueryCompletion {
    fn new(
        observer: Arc<dyn QueryObserver>,
        run_id: RunId,
        query: String,
        plan: Option<Arc<LogicalPlan>>,
        start: Instant,
    ) -> Arc<Self> {
        Arc::new(Self {
            observer,
            run_id,
            query,
            plan,
            start,
            outcome: std::sync::atomic::AtomicU8::new(0),
            error: std::sync::Mutex::new(None),
        })
    }

    /// Flag an error outcome and retain `message` as the root cause (the
    /// first message wins — later stream errors are usually fallout).
    fn set_error(&self, message: String) {
        self.outcome.store(1, std::sync::atomic::Ordering::SeqCst);
        let mut slot = self
            .error
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if slot.is_none() {
            *slot = Some(message);
        }
    }
}

impl Drop for QueryCompletion {
    fn drop(&mut self) {
        let errored = self.outcome.load(std::sync::atomic::Ordering::SeqCst) == 1;
        // Surface the error detail before the completion so an observer that
        // moves the query to history on `on_query_complete` already has it.
        if errored {
            if let Some(message) = self
                .error
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take()
            {
                self.observer.on_query_error(self.run_id, &message);
            }
        }
        let outcome = if errored {
            QueryOutcome::Error
        } else {
            QueryOutcome::Success
        };
        self.observer.on_query_complete(
            self.run_id,
            &self.query,
            self.plan.take(),
            outcome,
            self.start.elapsed(),
        );
    }
}

/// Wrap a row stream so it holds an `Arc<QueryCompletion>` for its whole
/// lifetime and flags an error outcome on any error item. When the stream
/// ends or is dropped, its `Arc` clone drops with it.
fn completion_aware_rows(
    rows: pgwire::api::results::SendableRowStream,
    completion: Arc<QueryCompletion>,
) -> pgwire::api::results::SendableRowStream {
    use futures::StreamExt;
    Box::pin(futures::stream::unfold(
        (rows, completion),
        |(mut rows, completion)| async move {
            match rows.next().await {
                Some(item) => {
                    if let Err(e) = &item {
                        completion.set_error(format!("{e}"));
                    }
                    Some((item, (rows, completion)))
                }
                None => None,
            }
        },
    ))
}

/// Attach `completion` to every `Query` response's row stream so the guard
/// outlives the query's streaming phase.
fn attach_completion(responses: &mut [Response], completion: &Arc<QueryCompletion>) {
    for resp in responses {
        if let Response::Query(qr) = resp {
            let rows = std::mem::replace(&mut qr.data_rows, Box::pin(futures::stream::empty()));
            qr.data_rows = completion_aware_rows(rows, Arc::clone(completion));
        }
    }
}

/// A datafusion-postgres [`QueryHook`] that applies a caller-supplied logical
/// plan rewrite at the **extended-parse** phase, so the prepared statement's
/// `RowDescription` (derived from the parsed plan) matches execution when a
/// governance rule changes the output schema ( column whitelist).
///
/// The rewrite closure — a [`dataglot_core::PlanRewriteFn`] provided by the
/// server via a `SessionConfig` extension — is a plain `Fn(LogicalPlan)`; it
/// reads the session identity from the policy task-local itself, so this hook
/// (in `dataglot-pgwire`) needs no dependency on `dataglot-policy` (rule 4).
struct PlanRewriteHook {
    rewriter: dataglot_core::PlanRewriteFn,
}

#[async_trait::async_trait]
impl QueryHook for PlanRewriteHook {
    async fn handle_simple_query(
        &self,
        _statement: &datafusion::sql::sqlparser::ast::Statement,
        _session_context: &SessionContext,
        _client: &mut dyn datafusion_postgres::hooks::HookClient,
    ) -> Option<pgwire::error::PgWireResult<pgwire::api::results::Response>> {
        // Simple-query describe + execute come from the same executed plan, so
        // the session analyzer rule already keeps them consistent — nothing to
        // do here.
        None
    }

    async fn handle_extended_parse_query(
        &self,
        sql: &datafusion::sql::sqlparser::ast::Statement,
        session_context: &SessionContext,
        _client: &(dyn ClientInfo + Send + Sync),
    ) -> Option<pgwire::error::PgWireResult<datafusion::logical_expr::LogicalPlan>> {
        // Let the default parser surface any planning error.
        let Ok(plan) = session_context
            .state()
            .statement_to_plan(datafusion::sql::parser::Statement::Statement(Box::new(
                sql.clone(),
            )))
            .await
        else {
            return None;
        };
        Some((self.rewriter)(plan).map_err(|e| pgwire::error::PgWireError::ApiError(Box::new(e))))
    }

    async fn handle_extended_query(
        &self,
        _statement: &datafusion::sql::sqlparser::ast::Statement,
        _logical_plan: &datafusion::logical_expr::LogicalPlan,
        _params: &datafusion::common::ParamValues,
        _session_context: &SessionContext,
        _client: &mut dyn datafusion_postgres::hooks::HookClient,
    ) -> Option<pgwire::error::PgWireResult<pgwire::api::results::Response>> {
        None
    }
}

/// Build the `DfSessionService`, installing the [`PlanRewriteHook`] when the
/// session carries a [`dataglot_core::SessionPlanRewriter`] extension.
fn build_session_service(session_context: &Arc<SessionContext>) -> Arc<DfSessionService> {
    if let Some(rw) = session_context
        .state()
        .config()
        .get_extension::<dataglot_core::SessionPlanRewriter>()
    {
        Arc::new(DfSessionService::new_with_hooks(
            Arc::clone(session_context),
            vec![Arc::new(PlanRewriteHook {
                rewriter: Arc::clone(&rw.0),
            })],
        ))
    } else {
        Arc::new(DfSessionService::new(Arc::clone(session_context)))
    }
}

impl DataglotHandlerFactory {
    /// Create a new handler factory with the given session context.
    ///
    /// Each connection will share this session context for query
    /// execution. No-op `QueryObserver` and no-op `StartupObserver`
    /// are installed; use [`Self::with_observer`] for query metrics
    /// or [`Self::with_observers`] for both query metrics and
    /// per-session identity wiring.
    #[must_use]
    pub fn new(session_context: Arc<SessionContext>) -> Self {
        Self::with_observers(
            session_context,
            Arc::new(NoopObserver),
            noop_startup_observer(),
        )
    }

    /// Create a new handler factory with a custom `QueryObserver`.
    ///
    /// Equivalent to [`Self::with_observers`] with a no-op
    /// `StartupObserver`. Use [`Self::with_observers`] when wiring
    /// per-session identity from the pgwire `StartupMessage`.
    #[must_use]
    pub fn with_observer(
        session_context: Arc<SessionContext>,
        observer: Arc<dyn QueryObserver>,
    ) -> Self {
        Self::with_observers(session_context, observer, noop_startup_observer())
    }

    /// Create a new handler factory with both a `QueryObserver` and
    /// a [`StartupObserver`].
    #[must_use]
    pub fn with_observers(
        session_context: Arc<SessionContext>,
        observer: Arc<dyn QueryObserver>,
        startup_observer: StartupObserver,
    ) -> Self {
        // Keep the SessionContext alongside the service: the simple-query
        // handler uses it to capture the pre-execution `LogicalPlan` for
        // observers that want it, separate from `DfSessionService`'s
        // own internal planning (which it doesn't expose).
        let session_service = build_session_service(&session_context);
        Self {
            session_context,
            session_service,
            observer,
            startup_observer,
            auth: AuthMode::Trust,
            tls_required: false,
            admission: None,
            identity_permit: Arc::new(Mutex::new(None)),
            cancel_registry: Arc::new(CancelRegistry::new()),
            catalog_admin: None,
            secret_admin: None,
            user_admin: None,
            policy_admin: None,
            grant_admin: None,
            view_admin: None,
        }
    }

    /// Set the connection authentication mode (default [`AuthMode::Trust`]).
    ///
    /// In [`AuthMode::Md5`] the startup handler runs a Postgres MD5
    /// password exchange before the [`StartupObserver`] fires; in trust
    /// mode the behavior is unchanged.
    #[must_use]
    pub fn with_auth(mut self, auth: AuthMode) -> Self {
        self.auth = auth;
        self
    }

    /// Require TLS: reject any connection that did not negotiate TLS at
    /// startup (`[pgwire_tls] mode = "require"`). Default `false`.
    #[must_use]
    pub fn with_tls_required(mut self, tls_required: bool) -> Self {
        self.tls_required = tls_required;
        self
    }

    /// Install per-identity admission control (bounds connections per
    /// username; see [`IdentityAdmission`]). Default: none.
    #[must_use]
    pub fn with_identity_admission(mut self, admission: Arc<dyn IdentityAdmission>) -> Self {
        self.admission = Some(admission);
        self
    }

    /// Share a **server-wide** [`CancelRegistry`] so cancel requests
    /// (which arrive on their own TCP connection) can resolve the
    /// backend key of a query running on a *different* connection. The
    /// default per-factory registry only ever sees this one connection
    #[must_use]
    pub fn with_cancel_registry(mut self, registry: Arc<CancelRegistry>) -> Self {
        self.cancel_registry = registry;
        self
    }

    /// Install the SQL-native catalog-DDL executor. With it,
    /// `CREATE / ALTER / DROP CATALOG` is effected against the control-plane
    /// store and reflected into the issuing session. Without it (the default),
    /// catalog DDL is rejected with a clear error.
    #[must_use]
    pub fn with_catalog_admin(mut self, admin: Arc<dyn CatalogAdmin>) -> Self {
        self.catalog_admin = Some(admin);
        self
    }

    /// Install the SQL-native secret-DDL executor. With it,
    /// `CREATE / DROP SECRET` encrypts + persists to the control-plane store.
    /// Without it (the default), secret DDL is rejected with a clear error.
    #[must_use]
    pub fn with_secret_admin(mut self, admin: Arc<dyn SecretAdmin>) -> Self {
        self.secret_admin = Some(admin);
        self
    }

    /// Install the SQL-native user/role-DDL executor. With
    /// it, `CREATE / ALTER / DROP USER` and `CREATE / DROP ROLE` persist to the
    /// control-plane store (a created user with a password can then authenticate
    /// via md5). Without it (the default), user DDL is rejected with a clear
    /// error.
    #[must_use]
    pub fn with_user_admin(mut self, admin: Arc<dyn UserAdmin>) -> Self {
        self.user_admin = Some(admin);
        self
    }

    /// Install the SQL-native policy-DDL executor. With
    /// it, `CREATE / DROP MASK` and `CREATE / DROP ROW FILTER` apply to the
    /// live policy enforcer and persist to the control-plane store. Without
    /// it (the default), policy DDL is rejected with a clear error.
    #[must_use]
    pub fn with_policy_admin(mut self, admin: Arc<dyn PolicyAdmin>) -> Self {
        self.policy_admin = Some(admin);
        self
    }

    /// Install the SQL-native grant-DDL executor. With it,
    /// `GRANT / REVOKE` persists privileges + role memberships to the
    /// control-plane store. F5a **stores only** — no query behaviour changes.
    /// Without it (the default), grant DDL is rejected with a clear error.
    #[must_use]
    pub fn with_grant_admin(mut self, admin: Arc<dyn GrantAdmin>) -> Self {
        self.grant_admin = Some(admin);
        self
    }

    /// Install the SQL-native view-DDL executor. With it,
    /// `CREATE / DROP VIEW` is effected against the control-plane store as a
    /// derived product and reflected into the issuing session. Without it (the
    /// default), view DDL is rejected with a clear error.
    #[must_use]
    pub fn with_view_admin(mut self, admin: Arc<dyn ViewAdmin>) -> Self {
        self.view_admin = Some(admin);
        self
    }
}

impl PgWireServerHandlers for DataglotHandlerFactory {
    fn simple_query_handler(&self) -> Arc<impl SimpleQueryHandler> {
        Arc::new(ObservingSimpleHandler {
            inner: Arc::clone(&self.session_service),
            session_context: Arc::clone(&self.session_context),
            observer: Arc::clone(&self.observer),
            catalog_admin: self.catalog_admin.clone(),
            secret_admin: self.secret_admin.clone(),
            user_admin: self.user_admin.clone(),
            policy_admin: self.policy_admin.clone(),
            grant_admin: self.grant_admin.clone(),
            view_admin: self.view_admin.clone(),
        })
    }

    fn extended_query_handler(&self) -> Arc<impl ExtendedQueryHandler> {
        Arc::new(ObservingExtendedHandler {
            inner: Arc::clone(&self.session_service),
            observer: Arc::clone(&self.observer),
        })
    }

    fn startup_handler(&self) -> Arc<impl StartupHandler> {
        let observer = Arc::clone(&self.startup_observer);
        // Both modes register the connection with the shared
        // `ConnectionManager`, which is what arms pgwire's
        // do_query-vs-cancel race for this connection.
        let mode = match &self.auth {
            AuthMode::Trust => StartupMode::Trust(DataglotStartupHandler {
                observer,
                cancel_registry: Arc::clone(&self.cancel_registry),
            }),
            AuthMode::Md5(source) => {
                let auth_source = Arc::new(DataglotAuthSource::new(Arc::clone(source)));
                let params = Arc::new(DefaultServerParameterProvider::default());
                StartupMode::Md5(Md5StartupHandler {
                    inner: Md5PasswordAuthStartupHandler::new(auth_source, params)
                        .with_connection_manager(Arc::clone(&self.cancel_registry.manager)),
                    observer,
                    cancel_registry: Arc::clone(&self.cancel_registry),
                })
            }
            AuthMode::ScramSha256(source) => {
                let auth_source = Arc::new(ScramAuthSource::new(Arc::clone(source)));
                let mut scram_auth = scram::ScramAuth::new(auth_source);
                // The SASL handler tells the client which iteration count to
                // hash with; it MUST equal the count `ScramAuthSource` bakes
                // into `gen_salted_password`. Both are `scram::SCRAM_ITERATIONS`.
                scram_auth.set_iterations(scram::SCRAM_ITERATIONS);
                let params = Arc::new(DefaultServerParameterProvider::default());
                let inner = SASLAuthStartupHandler::new(params)
                    .with_scram(scram_auth)
                    .with_connection_manager(Arc::clone(&self.cancel_registry.manager));
                StartupMode::Scram(ScramStartupHandler {
                    inner,
                    observer,
                    cancel_registry: Arc::clone(&self.cancel_registry),
                })
            }
            //: JWT / LDAP both use the cleartext-password exchange —
            // the client presents the token (jwt) or password (ldap), which
            // the backend verifies/binds and turns into resolved groups.
            AuthMode::Jwt(verifier) => StartupMode::Credential(CredentialStartupHandler {
                backend: CredentialBackend::Jwt(Arc::clone(verifier)),
                parameter_provider: Arc::new(DefaultServerParameterProvider::default()),
                observer,
                cancel_registry: Arc::clone(&self.cancel_registry),
            }),
            AuthMode::Ldap(authenticator) => StartupMode::Credential(CredentialStartupHandler {
                backend: CredentialBackend::Ldap(Arc::clone(authenticator)),
                parameter_provider: Arc::new(DefaultServerParameterProvider::default()),
                observer,
                cancel_registry: Arc::clone(&self.cancel_registry),
            }),
        };
        Arc::new(DataglotStartup {
            mode,
            tls_required: self.tls_required,
            admission: self.admission.clone(),
            identity_permit: Arc::clone(&self.identity_permit),
        })
    }

    fn error_handler(&self) -> Arc<impl ErrorHandler> {
        Arc::new(DataglotErrorHandler)
    }

    fn cancel_handler(&self) -> Arc<impl CancelHandler> {
        // Resolves a CancelRequest's (pid, secret key) against the
        // connections the startup handlers registered, firing the
        // matching connection's cancel sender — pgwire then aborts
        // that connection's in-flight `do_query` future (the dropped
        // stream tears down execution). Without this override the
        // trait default is a no-op and cancels vanish.
        Arc::new(AuditedCancelHandler {
            registry: Arc::clone(&self.cancel_registry),
        })
    }
}

/// [`DefaultCancelHandler`] semantics plus an audit line — cancellation
/// is an operator-visible action worth a trace in the server log, and
/// `resolved = false` (unknown backend key) is the signature of a
/// mis-shared registry.
struct AuditedCancelHandler {
    registry: Arc<CancelRegistry>,
}

#[async_trait::async_trait]
impl CancelHandler for AuditedCancelHandler {
    async fn on_cancel_request(&self, cancel_request: pgwire::messages::cancel::CancelRequest) {
        let resolved = self
            .registry
            .cancel(cancel_request.pid, &cancel_request.secret_key)
            .await;
        tracing::info!(
            pid = cancel_request.pid,
            resolved,
            "pgwire cancel request received"
        );
    }
}

/// Wrapper that times each Simple-Query `do_query` call and reports
/// the outcome to the observer.
struct ObservingSimpleHandler {
    inner: Arc<DfSessionService>,
    session_context: Arc<SessionContext>,
    observer: Arc<dyn QueryObserver>,
    /// SQL-native catalog-DDL executor. `Some` when the
    /// server has a control-plane store. `None` ⇒ catalog DDL is rejected.
    catalog_admin: Option<Arc<dyn CatalogAdmin>>,
    /// SQL-native secret-DDL executor. `Some` when the server
    /// has a control-plane store *and* an envelope key. `None` ⇒ secret DDL is
    /// rejected with a clear error.
    secret_admin: Option<Arc<dyn SecretAdmin>>,
    /// SQL-native user/role-DDL executor. `Some` when the
    /// server has a control-plane store. `None` ⇒ user DDL is rejected.
    user_admin: Option<Arc<dyn UserAdmin>>,
    /// SQL-native policy-DDL executor. `Some` when the
    /// server has both a control-plane store and a live rule store. `None` ⇒
    /// policy DDL is rejected.
    policy_admin: Option<Arc<dyn PolicyAdmin>>,
    /// SQL-native grant-DDL executor. `Some` when the
    /// server has a control-plane store. F5a persists grants only (no
    /// enforcement). `None` ⇒ grant DDL is rejected.
    grant_admin: Option<Arc<dyn GrantAdmin>>,
    /// SQL-native view-DDL executor. `Some` when the server
    /// has a control-plane store. `None` ⇒ view DDL is rejected.
    view_admin: Option<Arc<dyn ViewAdmin>>,
}

/// Map a [`CatalogAdminError`] to a pg wire error with a fitting SQLSTATE, so a
/// psql/JDBC client sees a standard error class rather than an opaque failure.
fn catalog_ddl_error(e: &CatalogAdminError) -> PgWireError {
    let sqlstate = match e {
        CatalogAdminError::AlreadyExists(_) => "42710", // duplicate_object
        CatalogAdminError::NotFound(_) => "42704",      // undefined_object
        CatalogAdminError::InvalidOptions(_) => "42601", // syntax_error
        CatalogAdminError::Backend(_) => "58000",       // system_error
    };
    PgWireError::UserError(Box::new(pgwire::error::ErrorInfo::new(
        "ERROR".to_owned(),
        sqlstate.to_owned(),
        e.to_string(),
    )))
}

/// Map a [`ViewAdminError`] to a pg wire error with a fitting SQLSTATE, so a
/// psql/JDBC client sees a standard error class rather than an opaque failure.
fn view_ddl_error(e: &ViewAdminError) -> PgWireError {
    let sqlstate = match e {
        ViewAdminError::AlreadyExists(_) => "42710", // duplicate_object
        ViewAdminError::NotFound(_) => "42704",      // undefined_object
        ViewAdminError::InvalidQuery(_) => "42601",  // syntax_error
        ViewAdminError::Backend(_) => "58000",       // system_error
    };
    PgWireError::UserError(Box::new(pgwire::error::ErrorInfo::new(
        "ERROR".to_owned(),
        sqlstate.to_owned(),
        e.to_string(),
    )))
}

/// Map a [`SecretAdminError`] to a pg wire error with a fitting SQLSTATE. The
/// message is value-free (rule 12).
fn secret_ddl_error(e: &SecretAdminError) -> PgWireError {
    let sqlstate = match e {
        SecretAdminError::AlreadyExists(_) => "42710", // duplicate_object
        SecretAdminError::NotFound(_) => "42704",      // undefined_object
        SecretAdminError::NotConfigured => "0A000",    // feature_not_supported
        SecretAdminError::Backend(_) => "58000",       // system_error
    };
    PgWireError::UserError(Box::new(pgwire::error::ErrorInfo::new(
        "ERROR".to_owned(),
        sqlstate.to_owned(),
        e.to_string(),
    )))
}

/// Map a [`UserAdminError`] to a pg wire error with a fitting SQLSTATE. The
/// message is value-free (rule 12).
fn user_ddl_error(e: &UserAdminError) -> PgWireError {
    let sqlstate = match e {
        UserAdminError::AlreadyExists(_) => "42710", // duplicate_object
        UserAdminError::NotFound(_) => "42704",      // undefined_object
        UserAdminError::NotConfigured => "0A000",    // feature_not_supported
        UserAdminError::Backend(_) => "58000",       // system_error
    };
    PgWireError::UserError(Box::new(pgwire::error::ErrorInfo::new(
        "ERROR".to_owned(),
        sqlstate.to_owned(),
        e.to_string(),
    )))
}

/// Map a [`PolicyAdminError`] to a pg wire error with a fitting SQLSTATE.
fn policy_ddl_error(e: &PolicyAdminError) -> PgWireError {
    let sqlstate = match e {
        PolicyAdminError::AlreadyExists(_) => "42710", // duplicate_object
        PolicyAdminError::NotFound(_) => "42704",      // undefined_object
        PolicyAdminError::NotConfigured => "0A000",    // feature_not_supported
        PolicyAdminError::Backend(_) => "58000",       // system_error
    };
    PgWireError::UserError(Box::new(pgwire::error::ErrorInfo::new(
        "ERROR".to_owned(),
        sqlstate.to_owned(),
        e.to_string(),
    )))
}

/// Map a [`GrantAdminError`] to a pg wire error with a fitting SQLSTATE
///. Grants are not credentials, so the message is plain.
fn grant_ddl_error(e: &GrantAdminError) -> PgWireError {
    let sqlstate = match e {
        GrantAdminError::NotConfigured => "0A000", // feature_not_supported
        GrantAdminError::Backend(_) => "58000",    // system_error
    };
    PgWireError::UserError(Box::new(pgwire::error::ErrorInfo::new(
        "ERROR".to_owned(),
        sqlstate.to_owned(),
        e.to_string(),
    )))
}

/// Does `stmt` parse as one of the five control-plane DDL surfaces
/// (`CATALOG` / `SECRET` / `USER`|`ROLE` / `MASK`|`ROW FILTER` /
/// `GRANT`|`REVOKE`)? Used by the multi-statement dispatch to decide whether a
/// bundled message carries any DDL that the inner planner cannot handle. Cheap
/// re-parse; the actual routing re-parses once more to obtain the typed value
/// (see [`ObservingSimpleHandler::try_apply_control_plane_ddl`]).
fn is_control_plane_ddl(stmt: &str) -> bool {
    parse_catalog_ddl(stmt).is_some()
        || parse_secret_ddl(stmt).is_some()
        || parse_user_ddl(stmt).is_some()
        || parse_policy_ddl(stmt).is_some()
        || parse_grant_ddl(stmt).is_some()
        || parse_view_ddl(stmt).is_some()
}

impl ObservingSimpleHandler {
    /// If `stmt` is control-plane DDL, effect it through the matching admin seam
    /// and return `Some(result)`; otherwise return `None` so the caller routes
    /// it as an ordinary query. The parse order mirrors the single-statement
    /// short-circuits in [`SimpleQueryHandler::do_query`] (catalog → secret →
    /// user → policy); the surfaces are mutually exclusive on their leading
    /// keywords, so order is not load-bearing.
    async fn try_apply_control_plane_ddl(&self, stmt: &str) -> Option<PgWireResult<Tag>> {
        // Recognize the statement as one of the control-plane DDL surfaces
        // first; only THEN authorize. Ordinary queries fall through to
        // `None` untouched — the authz gate never sees them. Every recognized
        // DDL is admin-only: a non-admin session is denied with SQLSTATE 42501.
        if let Some(ddl) = parse_catalog_ddl(stmt) {
            return Some(match Self::admin_denial() {
                Some(denied) => Err(denied),
                None => self.apply_catalog_ddl(ddl).await,
            });
        }
        if let Some(ddl) = parse_secret_ddl(stmt) {
            return Some(match Self::admin_denial() {
                Some(denied) => Err(denied),
                None => self.apply_secret_ddl(ddl).await,
            });
        }
        if let Some(ddl) = parse_user_ddl(stmt) {
            return Some(match Self::admin_denial() {
                Some(denied) => Err(denied),
                None => self.apply_user_ddl(ddl).await,
            });
        }
        if let Some(ddl) = parse_policy_ddl(stmt) {
            return Some(match Self::admin_denial() {
                Some(denied) => Err(denied),
                None => self.apply_policy_ddl(ddl).await,
            });
        }
        if let Some(ddl) = parse_grant_ddl(stmt) {
            return Some(match Self::admin_denial() {
                Some(denied) => Err(denied),
                None => self.apply_grant_ddl(ddl).await,
            });
        }
        if let Some(ddl) = parse_view_ddl(stmt) {
            return Some(match Self::admin_denial() {
                Some(denied) => Err(denied),
                None => self.apply_view_ddl(ddl).await,
            });
        }
        None
    }

    /// Authorize the control-plane admin surface. Returns `Some(err)`
    /// (SQLSTATE `42501`, `insufficient_privilege`) when the session may NOT run
    /// DDL, or `None` when it may.
    ///
    /// A session may run DDL when [`AuthPrincipal::can_admin`] is set — trust
    /// mode, a config-defined identity, or a store superuser, as resolved by the
    /// server's startup observer. When no auth principal is bound at all (outside
    /// a server connection scope — e.g. pgwire-library unit tests) it is allowed;
    /// in production the server always binds one, so the gate is live for every
    /// real session.
    fn admin_denial() -> Option<PgWireError> {
        match crate::current_auth_principal() {
            Some(principal) if !principal.can_admin => Some(PgWireError::UserError(Box::new(
                pgwire::error::ErrorInfo::new(
                    "ERROR".to_owned(),
                    // 42501 — insufficient_privilege.
                    "42501".to_owned(),
                    "permission denied: control-plane DDL (CREATE/ALTER/DROP \
                     CATALOG/SECRET/USER/ROLE, GRANT/REVOKE, CREATE/DROP \
                     MASK/POLICY/VIEW) requires an administrator; this session \
                     is not authorized"
                        .to_owned(),
                ),
            ))),
            _ => None,
        }
    }

    /// Complete a wire-boundary control-plane statement (the DDL short-circuits
    /// below, and the multi-statement path) through the observer.
    ///
    /// Forwards the redacted error message via [`QueryObserver::on_query_error`]
    /// *before* the terminal `on_query_complete` when the statement failed —
    /// the same error-then-complete order the streaming path's
    /// [`QueryCompletion`] drop uses — so the dashboard query profile / history
    /// shows *why* a `CREATE VIEW` (etc.) failed instead of a bare `ERROR`.
    /// `error` is `None` on success. The message is `format!("{e}")` on the
    /// `PgWireError`, already scrubbed of credentials at source (rule 12).
    fn complete_control_plane(
        &self,
        run_id: RunId,
        query: &str,
        error: Option<&PgWireError>,
        start: Instant,
    ) {
        if let Some(e) = error {
            self.observer.on_query_error(run_id, &format!("{e}"));
        }
        let outcome = if error.is_some() {
            QueryOutcome::Error
        } else {
            QueryOutcome::Success
        };
        self.observer
            .on_query_complete(run_id, query, None, outcome, start.elapsed());
    }

    /// Effect a parsed `CREATE / ALTER / DROP CATALOG` through the control-plane
    /// admin seam and reflect it into *this* session's `SessionContext`.
    ///
    /// The store write (inside `apply`) fires the change feed, so *other*
    /// sessions pick the change up via the live-registry refresh (slice B) on
    /// their next connection. Here we mutate only this session:
    /// - `Registered` → register (replacing) the freshly-built provider so a
    ///   follow-on `SELECT` in the same session resolves the new catalog. The
    ///   provider is raw — full `pg_catalog` introspection parity (`\d`, `\l`)
    ///   for the new catalog arrives on the next connection, which rebuilds
    ///   every catalog with its overlay.
    /// - `Dropped` → `SessionContext` exposes no deregister, so shadow the name
    ///   with an empty catalog: in-session queries against it stop resolving.
    ///   Full removal happens on reconnect via the slice-B refresh.
    /// - `NoOp` → nothing to reflect.
    async fn apply_catalog_ddl(&self, ddl: CatalogDdl) -> PgWireResult<Tag> {
        let Some(admin) = self.catalog_admin.as_ref() else {
            return Err(PgWireError::UserError(Box::new(
                pgwire::error::ErrorInfo::new(
                    "ERROR".to_owned(),
                    // 0A000 — feature_not_supported.
                    "0A000".to_owned(),
                    "catalog DDL requires a configured catalog_service; this server \
                     has none, so CREATE/ALTER/DROP CATALOG is unavailable"
                        .to_owned(),
                ),
            )));
        };
        let verb = match &ddl {
            CatalogDdl::Create { .. } => "CREATE CATALOG",
            CatalogDdl::Alter { .. } => "ALTER CATALOG",
            CatalogDdl::Drop { .. } => "DROP CATALOG",
        };
        // Scope the change to this connection's org. The server
        // mirrors the resolved identity's org into the pgwire session-org
        // task-local at startup; absent one (single-tenant / no control plane)
        // this is `"default"` — identical to the pre-M2 boot-org behavior.
        let org = crate::current_session_org().unwrap_or_else(|| "default".to_string());
        match admin
            .apply(&org, ddl)
            .await
            .map_err(|e| catalog_ddl_error(&e))?
        {
            CatalogAdminOutcome::Registered { name, provider } => {
                self.session_context.register_catalog(name, provider);
            }
            CatalogAdminOutcome::Dropped { name } => {
                self.session_context
                    .register_catalog(name, Arc::new(MemoryCatalogProvider::new()));
            }
            CatalogAdminOutcome::NoOp => {}
        }
        Ok(Tag::new(verb))
    }

    /// Effect a parsed `CREATE / DROP SECRET` through the secret-admin seam.
    /// Unlike catalog DDL, this touches no `SessionContext` — a secret is only
    /// read later when a catalog resolves a `*_secret` reference — so we just
    /// encrypt+persist (inside `apply`) and return a command tag.
    async fn apply_secret_ddl(&self, ddl: SecretDdl) -> PgWireResult<Tag> {
        let Some(admin) = self.secret_admin.as_ref() else {
            return Err(secret_ddl_error(&SecretAdminError::NotConfigured));
        };
        let verb = match &ddl {
            SecretDdl::Create { .. } => "CREATE SECRET",
            SecretDdl::Drop { .. } => "DROP SECRET",
        };
        // Scope the secret to this connection's org; see
        // `apply_catalog_ddl` for how the org is resolved.
        let org = crate::current_session_org().unwrap_or_else(|| "default".to_string());
        admin
            .apply(&org, ddl)
            .await
            .map_err(|e| secret_ddl_error(&e))?;
        Ok(Tag::new(verb))
    }

    /// Effect a parsed `CREATE / ALTER / DROP USER` or `CREATE / DROP ROLE`
    /// through the user-admin seam. Like secret DDL this touches no
    /// `SessionContext` — a created user's password is only read later, by the
    /// *next* connection's md5 auth exchange (the store-backed `PasswordSource`
    /// the server layers into `AuthMode::Md5`) — so we just persist (inside
    /// `apply`) and return a command tag. The password is never in scope here
    /// (the parsed `UserDdl` redacts it; the impl protects it before the store).
    async fn apply_user_ddl(&self, ddl: UserDdl) -> PgWireResult<Tag> {
        let Some(admin) = self.user_admin.as_ref() else {
            return Err(user_ddl_error(&UserAdminError::NotConfigured));
        };
        let verb = match &ddl {
            UserDdl::CreateUser { .. } => "CREATE USER",
            UserDdl::AlterUserPassword { .. } => "ALTER USER",
            UserDdl::DropUser { .. } => "DROP USER",
            UserDdl::CreateRole { .. } => "CREATE ROLE",
            UserDdl::DropRole { .. } => "DROP ROLE",
        };
        // Scope the user/role to this connection's org; see
        // `apply_catalog_ddl` for how the org is resolved.
        let org = crate::current_session_org().unwrap_or_else(|| "default".to_string());
        admin
            .apply(&org, ddl)
            .await
            .map_err(|e| user_ddl_error(&e))?;
        Ok(Tag::new(verb))
    }

    /// Effect a parsed `CREATE / DROP MASK` or `CREATE / DROP ROW FILTER`
    /// through the policy-admin seam. The rule is applied to the live
    /// process-wide policy enforcer (so a follow-on `SELECT` in *any*
    /// session sees the mask/filter on its next query) and persisted to the
    /// control-plane store, so it survives restart — no `SessionContext`
    /// mutation is needed because masking/filtering is a plan-time
    /// `OptimizerRule`, not session state (rule 6).
    async fn apply_policy_ddl(&self, ddl: PolicyDdl) -> PgWireResult<Tag> {
        let Some(admin) = self.policy_admin.as_ref() else {
            return Err(policy_ddl_error(&PolicyAdminError::NotConfigured));
        };
        let verb = match &ddl {
            PolicyDdl::CreateMask { .. } => "CREATE MASK",
            PolicyDdl::CreateRowFilter { .. } => "CREATE ROW FILTER",
            PolicyDdl::DropMask { .. } => "DROP MASK",
            PolicyDdl::DropRowFilter { .. } => "DROP ROW FILTER",
        };
        // Scope the policy to this connection's org; see
        // `apply_catalog_ddl` for how the org is resolved.
        let org = crate::current_session_org().unwrap_or_else(|| "default".to_string());
        admin
            .apply(&org, ddl)
            .await
            .map_err(|e| policy_ddl_error(&e))?;
        Ok(Tag::new(verb))
    }

    /// Effect a parsed `GRANT` / `REVOKE` through the grant-admin seam
    ///. Like secret/user DDL this touches no
    /// `SessionContext`; unlike policy DDL it touches no enforcer either —
    /// **F5a persists the grant only, it does not enforce it** (enforcement is
    /// F5b). So we just persist (inside `apply`) and return a `GRANT` / `REVOKE`
    /// command tag. No query behaviour changes.
    async fn apply_grant_ddl(&self, ddl: GrantDdl) -> PgWireResult<Tag> {
        let Some(admin) = self.grant_admin.as_ref() else {
            return Err(grant_ddl_error(&GrantAdminError::NotConfigured));
        };
        // The command tag reflects the verb; Postgres reports both privilege
        // grants and role-membership grants as `GRANT` / `REVOKE`.
        let verb = match &ddl {
            GrantDdl::GrantSelect { .. }
            | GrantDdl::GrantUsage { .. }
            | GrantDdl::GrantRole { .. } => "GRANT",
            GrantDdl::RevokeSelect { .. }
            | GrantDdl::RevokeUsage { .. }
            | GrantDdl::RevokeRole { .. } => "REVOKE",
        };
        // Scope the grant to this connection's org; see
        // `apply_catalog_ddl` for how the org is resolved.
        let org = crate::current_session_org().unwrap_or_else(|| "default".to_string());
        admin
            .apply(&org, ddl)
            .await
            .map_err(|e| grant_ddl_error(&e))?;
        Ok(Tag::new(verb))
    }

    /// Effect a parsed `CREATE / DROP VIEW` (a derived product,  slice
    /// F9) through the control-plane admin seam and reflect it into *this*
    /// session's `SessionContext`.
    ///
    /// For `CREATE`, the query is **planned + validated against this session**
    /// (the only context that can see a catalog this same session just created)
    /// and wrapped in a [`ViewTable`]; a query that can't plan fails here, before
    /// any persist. The built provider is handed to the admin, which persists the
    /// derived product and registers it into the live per-org registry so *other*
    /// sessions pick it up (the same visibility model as `CREATE CATALOG`). The
    /// provider is then registered into *this* session so a follow-on `SELECT`
    /// resolves it. A masked source column stays masked through the view: the
    /// plan is inlined at query time, so the plan-time policy rule rewrites the
    /// underlying scan (rule 6). `DROP` deregisters the view from the session.
    async fn apply_view_ddl(&self, ddl: ViewDdl) -> PgWireResult<Tag> {
        let Some(admin) = self.view_admin.as_ref() else {
            return Err(PgWireError::UserError(Box::new(
                pgwire::error::ErrorInfo::new(
                    "ERROR".to_owned(),
                    // 0A000 — feature_not_supported.
                    "0A000".to_owned(),
                    "view DDL requires a configured catalog_service; this server \
                     has none, so CREATE/DROP VIEW is unavailable"
                        .to_owned(),
                ),
            )));
        };
        // Scope the change to this connection's org; see
        // `apply_catalog_ddl` for how the org is resolved.
        let org = crate::current_session_org().unwrap_or_else(|| "default".to_string());
        match ddl {
            ViewDdl::Create {
                catalog,
                schema,
                name,
                query,
                or_replace,
            } => {
                // Validate + build against THIS session (sees runtime catalogs).
                let plan = self
                    .session_context
                    .state()
                    .create_logical_plan(&query)
                    .await
                    .map_err(|e| view_ddl_error(&ViewAdminError::InvalidQuery(format!("{e}"))))?;
                let provider: Arc<dyn datafusion::catalog::TableProvider> =
                    Arc::new(ViewTable::new(plan, Some(query.clone())));
                let reference = view_table_reference(catalog.clone(), schema.clone(), name.clone());
                // Rollback coordinates for atomicity — see below.
                let (rb_catalog, rb_schema, rb_name) =
                    (catalog.clone(), schema.clone(), name.clone());
                let ddl = ViewDdl::Create {
                    catalog,
                    schema,
                    name,
                    query,
                    or_replace,
                };
                match admin
                    .apply(&org, ddl, Some(Arc::clone(&provider)))
                    .await
                    .map_err(|e| view_ddl_error(&e))?
                {
                    ViewAdminOutcome::Created | ViewAdminOutcome::Replaced => {
                        if let Err(e) = self.session_context.register_table(reference, provider) {
                            //  — `CREATE VIEW` is atomic. The view persisted
                            // but can't register in this session (e.g. its target
                            // schema is a read-only federated source, or an absent
                            // schema). Roll the persist back so a poison view isn't
                            // re-registered — and warned — on every future
                            // connection, then surface the original error. Views
                            // created into the reserved writable catalog
                            // (`dataglot.public`) register fine and never hit this.
                            let _ = admin
                                .apply(
                                    &org,
                                    ViewDdl::Drop {
                                        catalog: rb_catalog,
                                        schema: rb_schema,
                                        name: rb_name,
                                        if_exists: true,
                                    },
                                    None,
                                )
                                .await;
                            return Err(view_ddl_error(&ViewAdminError::Backend(format!(
                                "register view in session: {e}"
                            ))));
                        }
                    }
                    ViewAdminOutcome::Dropped { .. } | ViewAdminOutcome::NoOp => {}
                }
                Ok(Tag::new("CREATE VIEW"))
            }
            ViewDdl::Drop { .. } => {
                match admin
                    .apply(&org, ddl, None)
                    .await
                    .map_err(|e| view_ddl_error(&e))?
                {
                    ViewAdminOutcome::Dropped {
                        catalog,
                        schema,
                        name,
                    } => {
                        let reference = view_table_reference(catalog, schema, name);
                        // Best-effort in-session deregister: the store + live
                        // registry are already updated inside `apply`; a
                        // deregister of a name this session never registered is a
                        // harmless `Ok(None)`.
                        self.session_context
                            .deregister_table(reference)
                            .map_err(|e| {
                                view_ddl_error(&ViewAdminError::Backend(format!(
                                    "deregister view in session: {e}"
                                )))
                            })?;
                    }
                    ViewAdminOutcome::Created
                    | ViewAdminOutcome::Replaced
                    | ViewAdminOutcome::NoOp => {}
                }
                Ok(Tag::new("DROP VIEW"))
            }
        }
    }
}

/// Build a [`TableReference`] for a view from its optional `catalog`/`schema`
/// qualifiers: full when both are present, partial when only a schema is, bare
/// otherwise. A bare/partial reference resolves against the session's default
/// catalog/schema at registration + query time — standard Postgres semantics.
fn view_table_reference(
    catalog: Option<String>,
    schema: Option<String>,
    name: String,
) -> TableReference {
    match (catalog, schema) {
        (Some(c), Some(s)) => TableReference::full(c, s, name),
        (_, Some(s)) => TableReference::partial(s, name),
        _ => TableReference::bare(name),
    }
}

#[async_trait::async_trait]
impl SimpleQueryHandler for ObservingSimpleHandler {
    // A wire-boundary dispatcher: it fans a simple-query string across the
    // no-op / catalog-DDL / secret-DDL / COPY / rewrite-hook / planned-query
    // paths, each a short guarded block. Splitting it would scatter the shared
    // observer bookkeeping; the length is inherent to the dispatch.
    #[allow(clippy::too_many_lines)]
    async fn do_query<C>(&self, client: &mut C, query: &str) -> PgWireResult<Vec<Response>>
    where
        C: ClientInfo + ClientPortalStore + Sink<PgWireBackendMessage> + Unpin + Send + Sync,
        C::Error: Debug,
        C::PortalStore: PortalStore,
        PgWireError: From<<C as Sink<PgWireBackendMessage>>::Error>,
    {
        // Multi-statement control-plane DDL. A single simple-query
        // message may bundle control-plane DDL with following statements, e.g.
        // `CREATE CATALOG c WITH (…); SELECT … FROM c…` (psql -c, JDBC
        // executeUpdate). The DDL parsers decline anything after their single
        // statement, so the whole message would otherwise fall through to
        // DataFusion — which cannot parse `CREATE CATALOG` and errors. Split
        // the message on top-level `;` (quote-aware, matching the parsers'
        // quoting) and take this path ONLY when it carries ≥2 statements AND
        // ≥1 is control-plane DDL; then dispatch each statement in order — DDL
        // through the admin seam, everything else through the inner handler —
        // preserving order. A single statement (the common case) or a DDL-free
        // multi-statement message (e.g. `SELECT 1; SELECT 2`, which
        // datafusion-postgres splits itself) falls through unchanged, so
        // existing behaviour is byte-for-byte preserved. Stop-on-first-error
        // (psql `ON_ERROR_STOP`-on semantics). Observer bookkeeping brackets
        // the whole message once (mirroring the single-DDL short-circuits); the
        // observer only ever sees the original `query`, so rule-12 redaction
        // posture is unchanged (no new logging of raw statement text).
        let statements = split_sql_statements(query);
        if statements.len() >= 2 && statements.iter().any(|s| is_control_plane_ddl(s)) {
            let run_id = RunId::new();
            self.observer.on_query_start(run_id, query);
            emit_query_identity(&*self.observer, run_id, client);
            let start = Instant::now();
            let mut responses: Vec<Response> = Vec::new();
            let mut failure: Option<PgWireError> = None;
            for stmt in statements {
                if let Some(result) = self.try_apply_control_plane_ddl(stmt).await {
                    match result {
                        Ok(tag) => responses.push(Response::Execution(tag)),
                        Err(e) => {
                            failure = Some(e);
                            break;
                        }
                    }
                } else {
                    match SimpleQueryHandler::do_query(&*self.inner, client, stmt).await {
                        Ok(mut inner) => responses.append(&mut inner),
                        Err(e) => {
                            failure = Some(e);
                            break;
                        }
                    }
                }
            }
            self.complete_control_plane(run_id, query, failure.as_ref(), start);
            if let Some(e) = failure {
                return Err(e);
            }
            return Ok(responses);
        }

        // Session/txn-control statements a read-only engine can safely
        // treat as successful no-ops: `DISCARD`, `RESET`,
        // `SAVEPOINT`/`RELEASE`/`ROLLBACK TO`. Connection poolers
        // (pgbouncer) issue `DISCARD ALL`/`RESET` on every reset, so
        // erroring here breaks pooled deployments. Short-circuit with a
        // success tag without touching DataFusion. See `crate::pg_compat`.
        if let Some(tag) = noop_command_tag(query) {
            let run_id = RunId::new();
            self.observer.on_query_start(run_id, query);
            emit_query_identity(&*self.observer, run_id, client);
            // No plan for session/txn-control no-ops.
            self.observer.on_query_complete(
                run_id,
                query,
                None,
                QueryOutcome::Success,
                Duration::ZERO,
            );
            return Ok(vec![Response::Execution(Tag::new(tag))]);
        }

        //  — authorize the control-plane admin surface for the
        // single-statement DDL short-circuits below (the multi-statement path
        // gates inside `try_apply_control_plane_ddl`). A recognized DDL from a
        // non-admin session is refused with SQLSTATE 42501 before any admin seam
        // runs; the observer brackets the denied query like any other error.
        if is_control_plane_ddl(query) {
            if let Some(denied) = Self::admin_denial() {
                let run_id = RunId::new();
                self.observer.on_query_start(run_id, query);
                emit_query_identity(&*self.observer, run_id, client);
                let start = Instant::now();
                self.complete_control_plane(run_id, query, Some(&denied), start);
                return Err(denied);
            }
        }

        // CREATE / ALTER / DROP CATALOG — SQL-native control-plane DDL (
        // slice C). DataFusion's planner has no such statement, so intercept it
        // at the wire boundary (like COPY / SHOW SCHEMAS), effect it through the
        // control-plane admin seam, and reflect the change into *this* session
        // so a `CREATE CATALOG …; SELECT …` sees its own catalog immediately.
        if let Some(ddl) = parse_catalog_ddl(query) {
            let run_id = RunId::new();
            self.observer.on_query_start(run_id, query);
            emit_query_identity(&*self.observer, run_id, client);
            let start = Instant::now();
            let result = self.apply_catalog_ddl(ddl).await;
            self.complete_control_plane(run_id, query, result.as_ref().err(), start);
            return Ok(vec![Response::Execution(result?)]);
        }

        // CREATE / DROP SECRET — SQL-native secrets. Same
        // wire-boundary interception as catalog DDL; the value is encrypted and
        // persisted by the admin seam and never touches the planner or a plan.
        if let Some(ddl) = parse_secret_ddl(query) {
            let run_id = RunId::new();
            self.observer.on_query_start(run_id, query);
            emit_query_identity(&*self.observer, run_id, client);
            let start = Instant::now();
            let result = self.apply_secret_ddl(ddl).await;
            self.complete_control_plane(run_id, query, result.as_ref().err(), start);
            return Ok(vec![Response::Execution(result?)]);
        }

        // CREATE / ALTER / DROP USER and CREATE / DROP ROLE — SQL-native
        // user/role DDL. Same wire-boundary interception as
        // catalog / secret DDL; the password is protected and persisted by the
        // admin seam and never touches the planner or a plan. A user created
        // here (with a password) can then authenticate via md5 on a fresh
        // connection — no config file entry required.
        if let Some(ddl) = parse_user_ddl(query) {
            let run_id = RunId::new();
            self.observer.on_query_start(run_id, query);
            emit_query_identity(&*self.observer, run_id, client);
            let start = Instant::now();
            let result = self.apply_user_ddl(ddl).await;
            self.complete_control_plane(run_id, query, result.as_ref().err(), start);
            return Ok(vec![Response::Execution(result?)]);
        }

        // CREATE / DROP MASK and CREATE / DROP ROW FILTER — SQL-native policy
        // DDL. Same wire-boundary interception as catalog /
        // secret / user DDL; the admin seam applies the rule to the live policy
        // enforcer and persists it. A mask created here masks the column for a
        // follow-on SELECT in the same deployment — no config file required.
        if let Some(ddl) = parse_policy_ddl(query) {
            let run_id = RunId::new();
            self.observer.on_query_start(run_id, query);
            emit_query_identity(&*self.observer, run_id, client);
            let start = Instant::now();
            let result = self.apply_policy_ddl(ddl).await;
            self.complete_control_plane(run_id, query, result.as_ref().err(), start);
            return Ok(vec![Response::Execution(result?)]);
        }

        // GRANT / REVOKE — SQL-native privilege + role-membership DDL (
        // slice F5a). Same wire-boundary interception as the other control-plane
        // DDL; the admin seam persists the grant to the org-scoped store.
        // **F5a stores only — no enforcement**, so nothing about query planning
        // or results changes here.
        if let Some(ddl) = parse_grant_ddl(query) {
            let run_id = RunId::new();
            self.observer.on_query_start(run_id, query);
            emit_query_identity(&*self.observer, run_id, client);
            let start = Instant::now();
            let result = self.apply_grant_ddl(ddl).await;
            self.complete_control_plane(run_id, query, result.as_ref().err(), start);
            return Ok(vec![Response::Execution(result?)]);
        }

        // CREATE / DROP VIEW — SQL-native derived products.
        // DataFusion's `CREATE VIEW` is session-local + ephemeral; Dataglot's
        // are org-scoped + store-backed, so intercept at the wire boundary like
        // catalog DDL: the admin seam validates the query, persists the derived
        // product, and registers it live so subsequent connections can query it,
        // and we reflect it into *this* session immediately.
        if let Some(ddl) = parse_view_ddl(query) {
            let run_id = RunId::new();
            self.observer.on_query_start(run_id, query);
            emit_query_identity(&*self.observer, run_id, client);
            let start = Instant::now();
            let result = self.apply_view_ddl(ddl).await;
            self.complete_control_plane(run_id, query, result.as_ref().err(), start);
            return Ok(vec![Response::Execution(result?)]);
        }

        // COPY (query) TO STDOUT — bulk text egress. Neither the
        // DataFusion parser nor datafusion-postgres accepts `STDOUT`, so
        // intercept it here, run the inner query, and stream the result as
        // COPY text via `Response::CopyOut` (the pgwire server drives the
        // CopyOutResponse → CopyData* → CopyDone → CommandComplete sequence).
        if let Some(inner) = detect_copy_to_stdout(query) {
            let run_id = RunId::new();
            self.observer.on_query_start(run_id, query);
            emit_query_identity(&*self.observer, run_id, client);
            let start = Instant::now();
            let resp = build_copy_out_response(&self.session_context, &inner).await;
            self.complete_control_plane(run_id, query, resp.as_ref().err(), start);
            return Ok(vec![resp?]);
        }

        // Pre-parse rewrite hooks applied at the pg wire boundary — see
        // `apply_preparse_rewrites` for the surfaces and their order. The
        // extended-query path applies the same chain in
        // `GuardingQueryParser::parse_sql`.
        let rewritten = apply_preparse_rewrites(query);
        let effective_query = rewritten.as_deref().unwrap_or(query);

        // Reject statements that would panic the planner before any
        // observer or planning runs. The extended-query path
        // is guarded separately in `GuardingQueryParser`.
        if let Some(err) = reject_deep_compound_identifier(effective_query) {
            return Err(err);
        }

        // Allocate the per-query run id once, before any observers
        // see the query — the lineage emitter needs the same value on
        // both `START` and `COMPLETE` to correlate them. See
        // dataglot-server::lineage and the slice-3 trait extension on
        // QueryObserver.
        let run_id = RunId::new();
        self.observer.on_query_start(run_id, effective_query);
        emit_query_identity(&*self.observer, run_id, client);

        // Capture the unoptimized `LogicalPlan` *before* execution, but only
        // if an observer wants it (lineage) — otherwise a metrics-only
        // deployment would pay an extra plan per query. Capturing pre-
        // execution is what makes `CREATE TABLE t AS …` lineage work:
        // re-planning after the table exists fails. Planning failures are
        // swallowed (`.ok()`) — the query still runs; lineage just falls
        // back to empty. `DfSessionService` re-plans internally for
        // execution (its plan isn't exposed), so this is additive.
        let plan: Option<Arc<LogicalPlan>> = if self.observer.wants_plan() {
            self.session_context
                .state()
                .create_logical_plan(effective_query)
                .await
                .ok()
                .map(Arc::new)
        } else {
            None
        };
        // Hand the pre-execution plan to observers that want it (the
        // dashboard's federated-source extraction —  slice 5b).
        if let Some(plan) = &plan {
            self.observer.on_query_plan(run_id, Arc::clone(plan));
        }

        let start = Instant::now();
        // `DfSessionService` implements both `SimpleQueryHandler` and
        // `ExtendedQueryHandler`, so the call needs an explicit trait
        // path to pick the right `do_query`.
        //
        // Results are lazy (`execute_stream`), so a long query spends
        // its life in the *streaming* phase after `do_query` returns —
        // wrap every row stream so a CancelRequest aborts it.
        let flag = client
            .session_extensions()
            .get::<Arc<CancelSlot>>()
            .map(|slot| slot.begin_query());
        // Hand the per-query cancel flag to observers keyed by run_id so
        // an out-of-band caller (the dashboard kill button) can abort it
        //. Fires after on_query_start so the registry
        // entry already exists.
        if let Some(flag) = &flag {
            self.observer
                .on_query_cancellable(run_id, QueryHandle::new(Arc::clone(flag)));
        }
        let mut result = SimpleQueryHandler::do_query(&*self.inner, client, effective_query).await;
        // Completion fires when the result stream drains, not here:
        // `do_query` hands back a lazy stream, so the query's real
        // lifetime is the streaming phase after this point.
        let completion = QueryCompletion::new(
            Arc::clone(&self.observer),
            run_id,
            effective_query.to_string(),
            plan,
            start,
        );
        match &mut result {
            Ok(responses) => {
                if let Some(flag) = &flag {
                    make_responses_cancel_aware(responses, flag);
                }
                attach_completion(responses, &completion);
            }
            // Planning/binding failed — there is no stream to drain, so
            // flag the error and let the guard fire when it drops below.
            Err(e) => completion.set_error(format!("{e}")),
        }
        // Release the local owner. If `Query` responses took clones the
        // guard lives until they drain; otherwise (DDL / empty / error)
        // this is the last owner and completion fires now.
        drop(completion);
        result
    }
}

/// The pgwire-boundary pre-parse rewrite chain.
///
/// Applied on **both** the simple-query path (`ObservingSimpleHandler::do_query`)
/// and the extended/prepared-statement parse path (`GuardingQueryParser::parse_sql`)
/// so SQL surfaces DataFusion's planner cannot handle behave identically
/// regardless of wire protocol. Before this was shared, only the simple
/// path rewrote, so BI tools / JDBC drivers (which use prepared statements)
/// saw `SHOW SCHEMAS` etc. fail with "Unsupported SQL statement".
///
/// The surfaces are mutually exclusive, tried in order:
///   - `EXPLAIN FEDERATION <sql>`      (; `crate::explain`)
///   - `SHOW SCHEMAS [FROM <catalog>]` (; `crate::show_schemas`)
///   - `SHOW <var>`                    (`crate::pg_compat`)
///   - `TABLE <name>`                  (; `crate::pg_compat`)
///   - bare identity registers         (; `crate::identity_registers`)
///
/// Returns `Some(rewritten)` when a surface matched, else `None` (the
/// caller passes the original query through unchanged).
fn apply_preparse_rewrites(query: &str) -> Option<String> {
    rewrite_explain_federation(query)
        .or_else(|| rewrite_show_schemas(query))
        .or_else(|| rewrite_show_variable(query))
        .or_else(|| rewrite_table(query))
        .or_else(|| rewrite_identity_registers(query))
}

/// Wraps the inner `QueryParser` to reject pathological compound
/// identifiers on the extended-query (prepared-statement) path — the
/// panic happens during Parse, before `do_query`, so this is the only
/// point that can intercept it. The simple-query path is guarded inline
/// in `ObservingSimpleHandler::do_query`. See [`crate::identifier_guard`]
struct GuardingQueryParser {
    inner: Arc<<DfSessionService as ExtendedQueryHandler>::QueryParser>,
}

#[async_trait::async_trait]
impl QueryParser for GuardingQueryParser {
    type Statement =
        <<DfSessionService as ExtendedQueryHandler>::QueryParser as QueryParser>::Statement;

    async fn parse_sql<C>(
        &self,
        client: &C,
        sql: &str,
        types: &[Option<Type>],
    ) -> PgWireResult<Self::Statement>
    where
        C: ClientInfo + Unpin + Send + Sync,
    {
        // Apply the full pgwire-boundary rewrite chain before the inner
        // parser runs, so SHOW SCHEMAS / EXPLAIN FEDERATION / SHOW <var> /
        // TABLE / identity registers behave the same over the extended
        // (prepared-statement) protocol as over simple query.
        // Previously only identity registers were rewritten here, so the
        // DataFusion-unsupported surfaces failed to parse on this path.
        let rewritten = apply_preparse_rewrites(sql);
        let effective_sql = rewritten.as_deref().unwrap_or(sql);
        if let Some(err) = reject_deep_compound_identifier(effective_sql) {
            return Err(err);
        }
        self.inner.parse_sql(client, effective_sql, types).await
    }

    fn get_parameter_types(&self, stmt: &Self::Statement) -> PgWireResult<Vec<Type>> {
        self.inner.get_parameter_types(stmt)
    }

    fn get_result_schema(
        &self,
        stmt: &Self::Statement,
        column_format: Option<&Format>,
    ) -> PgWireResult<Vec<FieldInfo>> {
        self.inner.get_result_schema(stmt, column_format)
    }
}

/// Wrapper that times each Extended-Query `do_query` call and reports
/// the outcome to the observer. `do_describe_*` paths fall through to
/// the trait's default impls (which only need `query_parser`) — only
/// real query execution is observed.
struct ObservingExtendedHandler {
    inner: Arc<DfSessionService>,
    observer: Arc<dyn QueryObserver>,
}

#[async_trait::async_trait]
impl ExtendedQueryHandler for ObservingExtendedHandler {
    type Statement = <DfSessionService as ExtendedQueryHandler>::Statement;
    type QueryParser = GuardingQueryParser;

    fn query_parser(&self) -> Arc<Self::QueryParser> {
        Arc::new(GuardingQueryParser {
            inner: self.inner.query_parser(),
        })
    }

    async fn do_query<C>(
        &self,
        client: &mut C,
        portal: &Portal<Self::Statement>,
        max_rows: usize,
    ) -> PgWireResult<Response>
    where
        C: ClientInfo + ClientPortalStore + Sink<PgWireBackendMessage> + Unpin + Send + Sync,
        C::PortalStore: PortalStore<Statement = Self::Statement>,
        C::Error: Debug,
        PgWireError: From<<C as Sink<PgWireBackendMessage>>::Error>,
    {
        // Lift the raw SQL out of the portal's stored statement so
        // observers see the same shape on the extended-query path as
        // on the simple-query path. `datafusion-postgres` defines
        // `type Statement = (String, Option<(datafusion::sql::sqlparser::ast::Statement, LogicalPlan)>)`
        // — the `.0` is the SQL string the client submitted. The
        // optional pair carries the parsed AST + plan, which both
        // slice 4's LineageObserver and the catalog-metadata bypass
        // below consume directly to avoid re-planning.
        let query: &str = portal.statement.statement.0.as_str();

        // Allocate run_id once; see the sibling SimpleQueryHandler
        // impl for the rationale.
        let run_id = RunId::new();
        self.observer.on_query_start(run_id, query);
        emit_query_identity(&*self.observer, run_id, client);

        // The extended path already carries the parsed plan
        // (`statement.1` = `(ast, LogicalPlan)`), so — unlike the
        // simple path — we reuse it directly, no re-planning at all
        //. Only cloned when an observer wants it.
        let plan: Option<Arc<LogicalPlan>> = if self.observer.wants_plan() {
            portal
                .statement
                .statement
                .1
                .as_ref()
                .map(|(_, p)| Arc::new(p.clone()))
        } else {
            None
        };
        // See the simple-query path: deliver the plan for federated-
        // source extraction.
        if let Some(plan) = &plan {
            self.observer.on_query_plan(run_id, Arc::clone(plan));
        }

        let start = Instant::now();

        // `information_schema.*` / `pg_catalog.*` queries hang on the
        // upstream extended-query path against a federated session
        // context. Detect that case from the parsed plan and route
        // through the simple-query handler instead. Only applies when
        // the Execute message carried no row limit; otherwise the
        // simple-query path would silently drop pagination semantics.
        // See `crate::catalog_bypass` for the full background.
        if max_rows == 0
            && portal
                .statement
                .statement
                .1
                .as_ref()
                .is_some_and(|(_, plan)| plan_references_catalog_metadata(plan))
        {
            let result = SimpleQueryHandler::do_query(&*self.inner, client, query).await;
            let outcome = match &result {
                Ok(responses) if !responses.is_empty() => QueryOutcome::Success,
                _ => QueryOutcome::Error,
            };
            self.observer
                .on_query_complete(run_id, query, plan, outcome, start.elapsed());
            return match result {
                // Metadata queries are single-statement by construction;
                // the simple-query handler returns one response. Pop it
                // (vs `responses[0]` clone) since `Response` is not
                // Clone.
                Ok(mut responses) if responses.len() == 1 => Ok(responses.remove(0)),
                Ok(responses) => Err(PgWireError::ApiError(
                    format!(
                        "catalog-metadata bypass: simple-query handler returned \
                         {} responses for a single statement",
                        responses.len()
                    )
                    .into(),
                )),
                Err(e) => Err(e),
            };
        }

        // Disambiguate against `SimpleQueryHandler::do_query` — see the
        // sibling impl above. As on the simple path, results stream
        // lazily, so wrap the row stream for cancellation.
        let flag = client
            .session_extensions()
            .get::<Arc<CancelSlot>>()
            .map(|slot| slot.begin_query());
        // See the simple-query path: expose the cancel flag by run_id so
        // the dashboard can kill this query out-of-band.
        if let Some(flag) = &flag {
            self.observer
                .on_query_cancellable(run_id, QueryHandle::new(Arc::clone(flag)));
        }
        let mut result =
            ExtendedQueryHandler::do_query(&*self.inner, client, portal, max_rows).await;
        // As on the simple path, defer completion to stream drain — the
        // result streams lazily after `do_query` returns.
        let completion = QueryCompletion::new(
            Arc::clone(&self.observer),
            run_id,
            query.to_string(),
            plan,
            start,
        );
        match &mut result {
            Ok(response) => {
                if let Some(flag) = &flag {
                    make_responses_cancel_aware(std::slice::from_mut(response), flag);
                }
                attach_completion(std::slice::from_mut(response), &completion);
            }
            Err(e) => completion.set_error(format!("{e}")),
        }
        drop(completion);
        result
    }

    async fn do_describe_statement<C>(
        &self,
        client: &mut C,
        target: &StoredStatement<Self::Statement>,
    ) -> PgWireResult<DescribeStatementResponse>
    where
        C: ClientInfo + ClientPortalStore + Sink<PgWireBackendMessage> + Unpin + Send + Sync,
        C::PortalStore: PortalStore<Statement = Self::Statement>,
        C::Error: Debug,
        PgWireError: From<<C as Sink<PgWireBackendMessage>>::Error>,
    {
        // Describe is a metadata-shape query, not an execution; we
        // don't bump the query counter here. Forward to inner so the
        // schema returned matches what `DfSessionService` would have
        // emitted unwrapped.
        ExtendedQueryHandler::do_describe_statement(&*self.inner, client, target).await
    }

    async fn do_describe_portal<C>(
        &self,
        client: &mut C,
        target: &Portal<Self::Statement>,
    ) -> PgWireResult<DescribePortalResponse>
    where
        C: ClientInfo + ClientPortalStore + Sink<PgWireBackendMessage> + Unpin + Send + Sync,
        C::PortalStore: PortalStore<Statement = Self::Statement>,
        C::Error: Debug,
        PgWireError: From<<C as Sink<PgWireBackendMessage>>::Error>,
    {
        ExtendedQueryHandler::do_describe_portal(&*self.inner, client, target).await
    }
}

/// Startup handler with no authentication (trust mode), augmented
/// with a `post_startup` callback that surfaces the username from
/// the `StartupMessage` to the [`StartupObserver`].
///
/// `NoopStartupHandler::on_startup` (the default) calls
/// `save_startup_parameters_to_metadata` before invoking
/// `post_startup`, so by the time we read `client.metadata()` here
/// the `user` / `database` keys are populated. We use the constant
/// from pgwire's API surface (`pgwire::api::METADATA_USER`) rather
/// than a stringly-typed key so a future rename in the upstream
/// crate surfaces as a build failure.
struct DataglotStartupHandler {
    observer: StartupObserver,
    /// Registers each connection for cancel resolution: the
    /// inner pgwire `ConnectionManager` via the
    /// `NoopStartupHandler::connection_manager` hook, and our
    /// streaming-phase [`CancelSlot`] in `post_startup`.
    cancel_registry: Arc<CancelRegistry>,
}

#[async_trait::async_trait]
impl NoopStartupHandler for DataglotStartupHandler {
    fn connection_manager(&self) -> Option<Arc<ConnectionManager>> {
        Some(Arc::clone(&self.cancel_registry.manager))
    }

    async fn post_startup<C>(
        &self,
        client: &mut C,
        _message: PgWireFrontendMessage,
    ) -> PgWireResult<()>
    where
        C: ClientInfo + Sink<PgWireBackendMessage> + Unpin + Send,
        C::Error: Debug,
        PgWireError: From<<C as Sink<PgWireBackendMessage>>::Error>,
    {
        // Run the observer first: if it refuses the connection (e.g.
        // unknown database → 3D000), propagate the FATAL before we send
        // ReadyForQuery (the base handler's post_startup sends it after
        // this returns), so the client sees a clean startup rejection.
        invoke_startup_observer(&self.observer, client.metadata())?;
        self.cancel_registry.register_slot(client);
        audit_connection_established(client.metadata(), client.socket_addr());
        Ok(())
    }
}

/// MD5 password startup handler.
///
/// Delegates the wire exchange to the `pgwire` crate's
/// [`Md5PasswordAuthStartupHandler`], then — once auth has *succeeded*
/// (the connection reaches [`PgWireConnectionState::ReadyForQuery`]) —
/// fires the [`StartupObserver`] from the now-*verified* username.
///
/// The crate's MD5 handler bundles the `AuthenticationOk` +
/// `ReadyForQuery` into its own `on_startup` with no post-auth hook, so
/// we detect completion by inspecting `client.state()` after delegating:
/// the startup-message call leaves the connection in
/// `AuthenticationInProgress` (challenge sent), and only the subsequent
/// password-message call advances it to `ReadyForQuery`. The observer
/// therefore fires exactly once, after a verified login and before the
/// first query is processed.
struct Md5StartupHandler {
    inner: Md5PasswordAuthStartupHandler<DataglotAuthSource, DefaultServerParameterProvider>,
    observer: StartupObserver,
    cancel_registry: Arc<CancelRegistry>,
}

#[async_trait::async_trait]
impl StartupHandler for Md5StartupHandler {
    async fn on_startup<C>(
        &self,
        client: &mut C,
        message: PgWireFrontendMessage,
    ) -> PgWireResult<()>
    where
        C: ClientInfo + Sink<PgWireBackendMessage> + Unpin + Send + Sync,
        C::Error: Debug,
        PgWireError: From<<C as Sink<PgWireBackendMessage>>::Error>,
    {
        let result = self.inner.on_startup(client, message).await;
        match &result {
            Ok(()) => {
                if matches!(client.state(), PgWireConnectionState::ReadyForQuery) {
                    // The crate's md5 handler already sent ReadyForQuery
                    // inside `finish_authentication`, so a refusal here
                    // (unknown database → 3D000) lands as a FATAL right
                    // after it — the connection is still refused before
                    // any query runs. Propagate it.
                    invoke_startup_observer(&self.observer, client.metadata())?;
                    self.cancel_registry.register_slot(client);
                    audit_connection_established(client.metadata(), client.socket_addr());
                }
            }
            // The crate's MD5 handler returns `InvalidPassword(user)` on a
            // bad password / unknown user. Audit it (brute-force detection)
            // before propagating — no lockout here; that's a follow-up.
            Err(PgWireError::InvalidPassword(user)) => {
                audit_auth_failure(user, client.socket_addr());
            }
            // Any other startup failure (TLS handshake, protocol violation,
            // IO error mid-handshake) is neither a credential nor one of our
            // deliberate refusals. Trace it at debug so a "can't connect"
            // report isn't a total blank, without flooding warn on benign
            // mid-handshake client disconnects. No credential is in scope.
            Err(e) => {
                tracing::debug!(
                    peer = %client.socket_addr(),
                    error = %e,
                    "startup failed before authentication"
                );
            }
        }
        result
    }
}

/// SCRAM-SHA-256 (SASL) password startup handler (F7).
///
/// Delegates the SASL wire exchange to the `pgwire` crate's
/// [`SASLAuthStartupHandler`] (configured with a
/// [`scram::ScramAuth`] over [`ScramAuthSource`]), then — once auth has
/// *succeeded* (the connection reaches
/// [`PgWireConnectionState::ReadyForQuery`]) — fires the
/// [`StartupObserver`] from the now-*verified* username. Structurally
/// identical to [`Md5StartupHandler`]: the SASL handler likewise bundles
/// `AuthenticationOk` + `ReadyForQuery` into its own `on_startup` with no
/// post-auth hook, and only the final client message advances the state
/// to `ReadyForQuery`, so inspecting `client.state()` after delegating
/// fires the observer exactly once, after a verified login.
struct ScramStartupHandler {
    inner: SASLAuthStartupHandler<DefaultServerParameterProvider>,
    observer: StartupObserver,
    cancel_registry: Arc<CancelRegistry>,
}

#[async_trait::async_trait]
impl StartupHandler for ScramStartupHandler {
    async fn on_startup<C>(
        &self,
        client: &mut C,
        message: PgWireFrontendMessage,
    ) -> PgWireResult<()>
    where
        C: ClientInfo + Sink<PgWireBackendMessage> + Unpin + Send + Sync,
        C::Error: Debug,
        PgWireError: From<<C as Sink<PgWireBackendMessage>>::Error>,
    {
        let result = self.inner.on_startup(client, message).await;
        match &result {
            Ok(()) => {
                if matches!(client.state(), PgWireConnectionState::ReadyForQuery) {
                    // Auth succeeded and the SASL handler already sent
                    // ReadyForQuery inside `finish_authentication`; a refusal
                    // here (unknown database → 3D000) lands as a FATAL right
                    // after it, still refusing before any query runs.
                    invoke_startup_observer(&self.observer, client.metadata())?;
                    self.cancel_registry.register_slot(client);
                    audit_connection_established(client.metadata(), client.socket_addr());
                }
            }
            // The SCRAM verifier returns `InvalidPassword(user)` on a bad
            // password / unknown user. Audit it (brute-force detection)
            // before propagating; no credential is ever in scope (rule 12).
            Err(PgWireError::InvalidPassword(user)) => {
                audit_auth_failure(user, client.socket_addr());
            }
            // Any other startup failure (TLS handshake, protocol violation,
            // IO mid-handshake, an unsupported SASL mechanism) is neither a
            // credential nor one of our deliberate refusals.
            Err(e) => {
                tracing::debug!(
                    peer = %client.socket_addr(),
                    error = %e,
                    "startup failed before authentication"
                );
            }
        }
        result
    }
}

/// Credential-based auth backends that authenticate a connection
/// from the **cleartext password** the client presents and, in the same step,
/// resolve the session's directory groups: a verified JWT (the token is the
/// password) or an LDAP bind (the password binds to the directory).
///
/// Both are gated behind a Postgres cleartext-password request. Neither the
/// token nor the bind password is ever logged (rule 12) — only the resolved
/// group *names* (plain data) leave this handler, via the
/// [`crate::auth_groups`] task-local.
enum CredentialBackend {
    Jwt(Arc<crate::jwt::JwtVerifier>),
    Ldap(Arc<crate::ldap::LdapAuthenticator>),
}

impl CredentialBackend {
    /// Authenticate `user` with the presented `credential` and resolve groups.
    ///
    /// `Some(groups)` ⇒ authenticated (with resolved-or-unavailable groups);
    /// `None` ⇒ authentication failed — the caller rejects the connection
    /// (fail-closed).
    async fn authenticate(
        &self,
        user: &str,
        credential: &str,
    ) -> Option<crate::auth_groups::AuthGroups> {
        use crate::auth_groups::AuthGroups;
        match self {
            // JWT: verifying the token IS the authentication. A verified token
            // yields its `groups` claim; any failure rejects the connection.
            CredentialBackend::Jwt(verifier) => match verifier.verify(credential) {
                Ok(claims) => Some(AuthGroups::resolved(claims.groups)),
                Err(_) => None,
            },
            // LDAP: binding as the user IS the authentication. A failed bind
            // rejects; a good bind whose group search failed authenticates
            // with no groups (least privilege).
            CredentialBackend::Ldap(authenticator) => {
                use crate::ldap::{GroupLookup, LdapOutcome};
                match authenticator.authenticate(user, credential).await {
                    LdapOutcome::AuthFailed => None,
                    LdapOutcome::Authenticated { groups } => Some(match groups {
                        GroupLookup::Resolved(names) => AuthGroups::resolved(names),
                        GroupLookup::Unavailable => AuthGroups::unavailable(),
                    }),
                }
            }
        }
    }
}

/// Cleartext-password startup handler for the `jwt` / `ldap` auth modes
///
/// Requests a Postgres cleartext password, then hands it to a
/// [`CredentialBackend`] which both authenticates the connection and resolves
/// its directory groups. On success the resolved groups are stashed in the
/// [`crate::auth_groups`] task-local (read back by the server's startup
/// observer), the startup observer fires (so an unknown-database refusal still
/// lands before `ReadyForQuery`), and authentication is finished. On failure
/// the connection is rejected with `InvalidPassword` (fail-closed) — the
/// reason is audited but the credential is never logged (rule 12).
struct CredentialStartupHandler {
    backend: CredentialBackend,
    parameter_provider: Arc<DefaultServerParameterProvider>,
    observer: StartupObserver,
    cancel_registry: Arc<CancelRegistry>,
}

/// Replicate pgwire's own (crate-private) `register_connection`: stash the
/// connection's cancel handle + unregister guard in its session extensions so
/// a `CancelRequest` resolves against it during the planning phase (the
/// streaming phase is covered separately by [`CancelRegistry::register_slot`]).
fn register_pgwire_connection<C: ClientInfo>(client: &C, manager: &Arc<ConnectionManager>) {
    let (pid, secret_key) = client.pid_and_secret_key();
    let (handle, guard) = manager.register(pid, secret_key);
    client
        .session_extensions()
        .insert::<Arc<pgwire::api::ConnectionHandle>>(handle);
    client
        .session_extensions()
        .insert::<pgwire::api::ConnectionGuard>(guard);
}

#[async_trait::async_trait]
impl StartupHandler for CredentialStartupHandler {
    async fn on_startup<C>(
        &self,
        client: &mut C,
        message: PgWireFrontendMessage,
    ) -> PgWireResult<()>
    where
        C: ClientInfo + Sink<PgWireBackendMessage> + Unpin + Send + Sync,
        C::Error: Debug,
        PgWireError: From<<C as Sink<PgWireBackendMessage>>::Error>,
    {
        use futures::SinkExt;
        use pgwire::api::auth::{
            finish_authentication, protocol_negotiation, save_startup_parameters_to_metadata,
        };
        use pgwire::messages::startup::Authentication;

        match message {
            PgWireFrontendMessage::Startup(ref startup) => {
                // Negotiate protocol + persist the startup params (user /
                // database), then request a cleartext password from the client.
                protocol_negotiation(client, startup).await?;
                save_startup_parameters_to_metadata(client, startup);
                client.set_state(PgWireConnectionState::AuthenticationInProgress);
                client
                    .send(PgWireBackendMessage::Authentication(
                        Authentication::CleartextPassword,
                    ))
                    .await?;
            }
            PgWireFrontendMessage::PasswordMessageFamily(pwd) => {
                let pwd = pwd.into_password()?;
                let user = client
                    .metadata()
                    .get(pgwire::api::METADATA_USER)
                    .cloned()
                    .unwrap_or_default();

                let Some(groups) = self.backend.authenticate(&user, &pwd.password).await else {
                    // Fail-closed: bad JWT / failed LDAP bind ⇒ reject. Audit
                    // the attempt (brute-force detection); never the token /
                    // password (rule 12).
                    audit_auth_failure(&user, client.socket_addr());
                    return Err(PgWireError::InvalidPassword(user));
                };

                // Bridge the resolved groups to the sync startup observer
                // (rule 4/11): plain group names only, never the credential.
                crate::auth_groups::try_set_auth_groups(groups);

                // Mint the backend key BEFORE finishing auth (it is sent in
                // BackendKeyData) and before cancel registration.
                let (pid, secret_key) = RandomPidSecretKeyGenerator::default().generate(client);
                client.set_pid_and_secret_key(pid, secret_key);

                // Observer first: a refusal (e.g. unknown database → 3D000)
                // propagates as FATAL before AuthenticationOk / ReadyForQuery,
                // so the client sees a clean startup rejection and no query
                // ever runs.
                invoke_startup_observer(&self.observer, client.metadata())?;

                register_pgwire_connection(client, &self.cancel_registry.manager);
                finish_authentication(client, self.parameter_provider.as_ref()).await?;
                self.cancel_registry.register_slot(client);
                audit_connection_established(client.metadata(), client.socket_addr());
            }
            _ => {}
        }
        Ok(())
    }
}

/// Emit a structured audit event for a failed authentication attempt on
/// the `dataglot::audit` target (the same target `dataglot-policy` uses
/// for policy decisions), so a collector routing that target sees auth
/// failures — the signal an enterprise security review needs to detect
/// brute-force attempts. Carries the attempted username + peer address
/// only; no credential is ever in scope here (rule 12).
fn audit_auth_failure(user: &str, peer: std::net::SocketAddr) {
    tracing::warn!(
        target: "dataglot::audit",
        action = "auth_failed",
        user = user,
        peer = %peer,
        "authentication failed"
    );
}

/// Emit a structured audit event for a successful connection on the
/// `dataglot::audit` target — the success counterpart to
/// [`audit_auth_failure`], so an operator/security review sees who
/// connected, from where, and to which database (previously only
/// failures were logged, leaving half the auth audit trail missing).
/// Identifiers only; no credential is ever in scope here (rule 12).
fn audit_connection_established(
    metadata: &std::collections::HashMap<String, String>,
    peer: std::net::SocketAddr,
) {
    tracing::info!(
        target: "dataglot::audit",
        action = "connected",
        user = metadata
            .get(pgwire::api::METADATA_USER)
            .map_or("", String::as_str),
        database = metadata
            .get(pgwire::api::METADATA_DATABASE)
            .map_or("", String::as_str),
        peer = %peer,
        "client connection established"
    );
}

/// Auth-mode dispatch: a single concrete type carrying the trust, MD5, or
/// SCRAM startup path (a `fn -> impl Trait` must name one type).
enum StartupMode {
    Trust(DataglotStartupHandler),
    Md5(Md5StartupHandler),
    Scram(ScramStartupHandler),
    /// The `jwt` / `ldap` credential modes, both driven by the
    /// cleartext-password [`CredentialStartupHandler`].
    Credential(CredentialStartupHandler),
}

/// Startup handler returned by
/// [`DataglotHandlerFactory::startup_handler`]: enforces the require-TLS
/// posture, then dispatches to the configured auth mode.
struct DataglotStartup {
    mode: StartupMode,
    tls_required: bool,
    /// Optional per-identity admission control, consulted on the initial
    /// `Startup` message before auth.
    admission: Option<Arc<dyn IdentityAdmission>>,
    /// Shared slot (owned by the factory) where the admission guard lives for
    /// the connection's lifetime.
    identity_permit: Arc<Mutex<Option<IdentityPermit>>>,
}

#[async_trait::async_trait]
impl StartupHandler for DataglotStartup {
    async fn on_startup<C>(
        &self,
        client: &mut C,
        message: PgWireFrontendMessage,
    ) -> PgWireResult<()>
    where
        C: ClientInfo + Sink<PgWireBackendMessage> + Unpin + Send + Sync,
        C::Error: Debug,
        PgWireError: From<<C as Sink<PgWireBackendMessage>>::Error>,
    {
        // `require` mode: TLS negotiation already happened in
        // `process_socket` before this handler runs, so `is_secure()` is
        // authoritative. Reject a plaintext connection before any auth.
        if self.tls_required && !client.is_secure() {
            tracing::warn!(
                target: "dataglot::audit",
                action = "connection_refused",
                sqlstate = "28000",
                peer = %client.socket_addr(),
                "plaintext connection refused: TLS required"
            );
            return Err(PgWireError::UserError(Box::new(
                pgwire::error::ErrorInfo::new(
                    "FATAL".to_owned(),
                    // 28000 — invalid_authorization_specification.
                    "28000".to_owned(),
                    "TLS required: reconnect with TLS (e.g. sslmode=require)".to_owned(),
                ),
            )));
        }

        // Per-identity admission runs on the initial `Startup` message —
        // before auth, before `ReadyForQuery` — so a refusal fails the
        // client's connect cleanly. The username is the *asserted* one from
        // the startup parameters (a later auth failure ends the connection,
        // dropping the guard). Subsequent messages on this connection (e.g.
        // the MD5 password) are not `Startup`, so admission fires once.
        if let (Some(admission), PgWireFrontendMessage::Startup(startup)) =
            (&self.admission, &message)
        {
            let user = startup
                .parameters
                .get(pgwire::api::METADATA_USER)
                .map_or("", String::as_str);
            if let Ok(permit) = admission.admit(user) {
                *self.identity_permit.lock().expect("identity-permit lock") = Some(permit);
            } else {
                // Err(IdentityLimited) — the only error variant.
                tracing::warn!(
                    target: "dataglot::audit",
                    action = "connection_refused",
                    sqlstate = "53300",
                    user = user,
                    peer = %client.socket_addr(),
                    "connection refused: too many connections for role"
                );
                return Err(PgWireError::UserError(Box::new(
                    pgwire::error::ErrorInfo::new(
                        "FATAL".to_owned(),
                        // 53300 — too_many_connections.
                        "53300".to_owned(),
                        format!("too many connections for role \"{user}\""),
                    ),
                )));
            }
        }

        match &self.mode {
            StartupMode::Trust(h) => h.on_startup(client, message).await,
            StartupMode::Md5(h) => h.on_startup(client, message).await,
            StartupMode::Scram(h) => h.on_startup(client, message).await,
            StartupMode::Credential(h) => h.on_startup(client, message).await,
        }
    }
}

// NOTE: `C: ... + Sync` on the two impls above matches the upstream
// `StartupHandler::on_startup` bound exactly (the trait requires `Sync`).

/// Pure helper that parses the username + database from a metadata
/// map into a [`StartupInfo`] and invokes the [`StartupObserver`].
/// Factored out from `DataglotStartupHandler::post_startup` so the
/// metadata→observer hop can be unit-tested without mocking pgwire's
/// full `ClientInfo` trait surface (12+ required methods, several of
/// them feature-gated by TLS). The actual `post_startup` path is
/// exercised end-to-end by the pgwire e2e suite under `dataglot-tests`.
///
/// Treats a missing `user` key as the empty string — the same value
/// the server crate maps to `Identity::anonymous()`. A missing or
/// empty `database` becomes `None` (keep the server's default catalog).
fn invoke_startup_observer(
    observer: &StartupObserver,
    metadata: &std::collections::HashMap<String, String>,
) -> PgWireResult<()> {
    let info = StartupInfo {
        user: metadata
            .get(pgwire::api::METADATA_USER)
            .map_or("", String::as_str),
        database: metadata
            .get(pgwire::api::METADATA_DATABASE)
            .map(String::as_str)
            .filter(|s| !s.is_empty()),
    };
    observer(&info).map_err(|r| {
        // A refused connection surfaces as a FATAL ErrorResponse with the
        // observer's SQLSTATE (e.g. 3D000 for an unknown database), which
        // pgwire sends before the connection closes. Log it on the audit
        // target so a "client can't connect" report has a server-side
        // trace (user + requested database + sqlstate); no credential is
        // in scope here (rule 12).
        tracing::warn!(
            target: "dataglot::audit",
            action = "connection_refused",
            sqlstate = %r.sqlstate,
            user = info.user,
            database = info.database.unwrap_or(""),
            "startup rejected: {}",
            r.message
        );
        PgWireError::UserError(Box::new(pgwire::error::ErrorInfo::new(
            "FATAL".to_string(),
            r.sqlstate,
            r.message,
        )))
    })
}

/// Error handler that logs errors via tracing.
struct DataglotErrorHandler;

impl ErrorHandler for DataglotErrorHandler {
    fn on_error<C>(&self, _client: &C, error: &mut PgWireLibError)
    where
        C: pgwire::api::ClientInfo,
    {
        // A `UserError` is a query/SQL error surfaced back to the client
        // (syntax error, unknown column, type mismatch, …) — routine
        // client-caused noise. Log it at debug so it doesn't drown genuine
        // operational warnings. Everything else (transport, protocol,
        // internal) stays at warn.
        if let PgWireLibError::UserError(_) = error {
            tracing::debug!(error = %error, "sending error to client");
        } else {
            tracing::warn!(error = %error, "sending error to client");
        }
    }
}

/// Handle a single client connection using the pg wire protocol.
///
/// This function takes ownership of the TCP stream and processes
/// `PostgreSQL` protocol messages until the connection is closed.
/// No per-query observation is performed — call
/// [`handle_connection_with_observer`] to plug in metrics.
///
/// # Arguments
/// * `stream` - The TCP stream for the client connection
/// * `peer_addr` - The peer address for logging
/// * `session_context` - The `DataFusion` session context for query execution
///
/// # Errors
/// Returns an error if the connection cannot be processed.
pub async fn handle_connection(
    stream: TcpStream,
    peer_addr: SocketAddr,
    session_context: Arc<SessionContext>,
) -> Result<()> {
    handle_connection_with_observer(stream, peer_addr, session_context, Arc::new(NoopObserver))
        .await
}

/// Handle a single client connection using the pg wire protocol, with
/// a `QueryObserver` invoked once per query.
///
/// Equivalent to [`handle_connection_with_observers`] with a no-op
/// [`StartupObserver`]. Use [`handle_connection_with_observers`] when
/// the caller needs to react to the username from the
/// `StartupMessage` — e.g., to swap the per-task session identity
/// for `dataglot_policy`.
///
/// # Errors
/// Returns an error if the connection cannot be processed.
pub async fn handle_connection_with_observer(
    stream: TcpStream,
    peer_addr: SocketAddr,
    session_context: Arc<SessionContext>,
    observer: Arc<dyn QueryObserver>,
) -> Result<()> {
    handle_connection_with_observers(
        stream,
        peer_addr,
        session_context,
        observer,
        noop_startup_observer(),
    )
    .await
}

/// Handle a single client connection with both a `QueryObserver`
/// (invoked once per query) and a [`StartupObserver`] (invoked once
/// per connection, after the `StartupMessage` is processed and
/// before the first query).
///
/// The `StartupObserver` runs on the connection's task, so writes
/// it makes to a tokio task-local are visible to subsequent query
/// processing on the same task. This is the mechanism the server
/// crate uses to wire pgwire's username into
/// `dataglot_policy::set_session_identity`.
///
/// # Errors
/// Returns an error if the connection cannot be processed.
pub async fn handle_connection_with_observers(
    stream: TcpStream,
    peer_addr: SocketAddr,
    session_context: Arc<SessionContext>,
    observer: Arc<dyn QueryObserver>,
    startup_observer: StartupObserver,
) -> Result<()> {
    handle_connection_with_observers_and_auth(
        stream,
        peer_addr,
        session_context,
        observer,
        startup_observer,
        AuthMode::Trust,
        None,
    )
    .await
}

/// Ingress-TLS configuration for a connection: the built acceptor plus
/// whether TLS is mandatory. `Some(IngressTls { required: false })` is
/// *prefer* (offer TLS, accept plaintext too); `required: true` rejects
/// a client that connects without TLS. `None` (at the call site) ⇒ a
/// plaintext listener. Cheap to clone (`TlsAcceptor` is `Arc`-backed) —
/// the server holds one and clones it per connection.
#[derive(Clone)]
pub struct IngressTls {
    /// The rustls acceptor (from [`crate::build_tls_acceptor`]).
    pub acceptor: TlsAcceptor,
    /// Reject connections that don't negotiate TLS (`require` mode).
    pub required: bool,
}

/// As [`handle_connection_with_observers`], but with an explicit
/// [`AuthMode`] gating the startup handshake plus optional **ingress
/// TLS**. In [`AuthMode::Md5`] the connection must complete a Postgres
/// MD5 password exchange before the `StartupObserver` fires. When `tls`
/// is `Some`, the socket can negotiate TLS (build the acceptor with
/// [`crate::build_tls_acceptor`]); `tls_required` additionally rejects
/// any client that connects without TLS (`require` mode).
///
/// # Errors
/// Returns an error if the connection cannot be processed.
pub async fn handle_connection_with_observers_and_auth(
    stream: TcpStream,
    peer_addr: SocketAddr,
    session_context: Arc<SessionContext>,
    observer: Arc<dyn QueryObserver>,
    startup_observer: StartupObserver,
    auth: AuthMode,
    tls: Option<IngressTls>,
) -> Result<()> {
    handle_connection_with_security(
        stream,
        peer_addr,
        session_context,
        observer,
        startup_observer,
        ConnectionSecurity {
            auth,
            tls,
            admission: None,
            cancel_registry: None,
            catalog_admin: None,
            secret_admin: None,
            user_admin: None,
            policy_admin: None,
            grant_admin: None,
            view_admin: None,
        },
    )
    .await
}

/// Per-connection security configuration for the pgwire handler: the auth
/// mode, optional ingress TLS, and optional per-identity admission control.
/// Bundled into one value so the handler entry point stays under the
/// argument-count limit as these knobs accumulate.
#[derive(Clone, Default)]
pub struct ConnectionSecurity {
    /// Startup authentication mode (default [`AuthMode::Trust`]).
    pub auth: AuthMode,
    /// Optional ingress TLS (`prefer`/`require`); `None` ⇒ plaintext.
    pub tls: Option<IngressTls>,
    /// Optional per-identity admission control (see [`IdentityAdmission`]).
    pub admission: Option<Arc<dyn IdentityAdmission>>,
    /// **Server-wide** connection registry for query cancellation. A
    /// Postgres `CancelRequest` arrives on a *new* TCP connection, so
    /// the registry that resolves its (pid, secret key) must be shared
    /// across all connections — the server creates one and passes it
    /// here. `None` (tests, simple entry points) keeps a per-connection
    /// registry: same-connection behavior is identical, but cross-
    /// connection cancel resolution will miss.
    pub cancel_registry: Option<Arc<CancelRegistry>>,
    /// SQL-native catalog-DDL executor. `Some` when the
    /// server has a control-plane store; enables `CREATE / ALTER / DROP
    /// CATALOG`. `None` (tests, no control plane) ⇒ catalog DDL is rejected
    /// with a clear error.
    pub catalog_admin: Option<Arc<dyn CatalogAdmin>>,
    /// SQL-native secret-DDL executor. `Some` when the server
    /// has a store *and* an envelope key; enables `CREATE / DROP SECRET`. `None`
    /// ⇒ secret DDL is rejected with a clear error.
    pub secret_admin: Option<Arc<dyn SecretAdmin>>,
    /// SQL-native user/role-DDL executor. `Some` when the
    /// server has a control-plane store; enables `CREATE / ALTER / DROP USER`
    /// and `CREATE / DROP ROLE`. `None` ⇒ user DDL is rejected with a clear
    /// error.
    pub user_admin: Option<Arc<dyn UserAdmin>>,
    /// SQL-native policy-DDL executor. `Some` when the
    /// server has both a control-plane store and a live rule store; enables
    /// `CREATE / DROP MASK` and `CREATE / DROP ROW FILTER`. `None` ⇒ policy
    /// DDL is rejected with a clear error.
    pub policy_admin: Option<Arc<dyn PolicyAdmin>>,
    /// SQL-native grant-DDL executor. `Some` when the
    /// server has a control-plane store; enables `GRANT / REVOKE` (persist
    /// only, no enforcement). `None` ⇒ grant DDL is rejected with a clear error.
    pub grant_admin: Option<Arc<dyn GrantAdmin>>,
    /// SQL-native view-DDL executor. `Some` when the server
    /// has a control-plane store; enables `CREATE / DROP VIEW` (derived
    /// products). `None` ⇒ view DDL is rejected with a clear error.
    pub view_admin: Option<Arc<dyn ViewAdmin>>,
}

/// As [`handle_connection_with_observers`], with the full
/// [`ConnectionSecurity`] bundle — auth mode, ingress TLS, and per-identity
/// admission control. This is the entry point the server uses.
///
/// # Errors
/// Returns an error if the connection cannot be processed.
pub async fn handle_connection_with_security(
    stream: TcpStream,
    peer_addr: SocketAddr,
    session_context: Arc<SessionContext>,
    observer: Arc<dyn QueryObserver>,
    startup_observer: StartupObserver,
    security: ConnectionSecurity,
) -> Result<()> {
    tracing::debug!(%peer_addr, "Starting pg wire protocol handler");

    let ConnectionSecurity {
        auth,
        tls,
        admission,
        cancel_registry,
        catalog_admin,
        secret_admin,
        user_admin,
        policy_admin,
        grant_admin,
        view_admin,
    } = security;
    let (acceptor, tls_required) = match tls {
        Some(t) => (Some(t.acceptor), t.required),
        None => (None, false),
    };
    let mut factory =
        DataglotHandlerFactory::with_observers(session_context, observer, startup_observer)
            .with_auth(auth)
            .with_tls_required(tls_required);
    if let Some(admission) = admission {
        factory = factory.with_identity_admission(admission);
    }
    if let Some(registry) = cancel_registry {
        factory = factory.with_cancel_registry(registry);
    }
    if let Some(admin) = catalog_admin {
        factory = factory.with_catalog_admin(admin);
    }
    if let Some(admin) = secret_admin {
        factory = factory.with_secret_admin(admin);
    }
    if let Some(admin) = user_admin {
        factory = factory.with_user_admin(admin);
    }
    if let Some(admin) = policy_admin {
        factory = factory.with_policy_admin(admin);
    }
    if let Some(admin) = grant_admin {
        factory = factory.with_grant_admin(admin);
    }
    if let Some(admin) = view_admin {
        factory = factory.with_view_admin(admin);
    }

    process_socket(stream, acceptor, Arc::new(factory)).await?;

    tracing::debug!(%peer_addr, "Connection closed");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handler_factory_creation() {
        let ctx = Arc::new(SessionContext::new());
        let _factory = DataglotHandlerFactory::new(ctx);
        // Factory created successfully
    }

    #[test]
    fn test_handler_factory_provides_simple_query_handler() {
        let ctx = Arc::new(SessionContext::new());
        let factory = DataglotHandlerFactory::new(ctx);
        let _ = factory.simple_query_handler();
        // Handler obtained successfully
    }

    #[test]
    fn test_handler_factory_provides_extended_query_handler() {
        let ctx = Arc::new(SessionContext::new());
        let factory = DataglotHandlerFactory::new(ctx);
        let _ = factory.extended_query_handler();
        // Handler obtained successfully
    }

    //: the shared pre-parse rewrite chain must recognise every
    // compat surface, so both the simple-query and extended/prepared
    // paths (which both call this helper) rewrite identically.
    #[test]
    fn preparse_rewrites_show_schemas_bare_and_scoped() {
        // `SHOW SCHEMAS` is rejected by DataFusion's planner natively, so
        // the shim must turn it into an information_schema query.
        let bare = apply_preparse_rewrites("SHOW SCHEMAS").expect("bare SHOW SCHEMAS rewrites");
        assert!(
            bare.to_ascii_lowercase()
                .contains("information_schema.schemata"),
            "unexpected rewrite: {bare}"
        );
        let scoped =
            apply_preparse_rewrites("SHOW SCHEMAS FROM pg").expect("scoped SHOW SCHEMAS rewrites");
        assert!(
            scoped.contains("catalog_name = 'pg'"),
            "unexpected rewrite: {scoped}"
        );
    }

    #[test]
    fn preparse_rewrites_explain_federation() {
        let rw = apply_preparse_rewrites("EXPLAIN FEDERATION SELECT 1")
            .expect("EXPLAIN FEDERATION rewrites");
        assert!(
            rw.to_ascii_uppercase().starts_with("EXPLAIN"),
            "unexpected rewrite: {rw}"
        );
    }

    #[test]
    fn preparse_rewrites_table_shorthand() {
        let rw = apply_preparse_rewrites("TABLE foo").expect("TABLE <name> rewrites");
        let up = rw.to_ascii_uppercase();
        assert!(
            up.contains("SELECT") && up.contains("FROM"),
            "unexpected rewrite: {rw}"
        );
    }

    #[test]
    fn preparse_rewrites_pass_through_plain_select() {
        // A statement DataFusion handles natively must not be rewritten,
        // so the caller runs it verbatim.
        assert_eq!(apply_preparse_rewrites("SELECT 1"), None);
        assert_eq!(
            apply_preparse_rewrites("SELECT * FROM information_schema.schemata"),
            None
        );
    }

    #[test]
    fn test_handler_factory_provides_startup_handler() {
        let ctx = Arc::new(SessionContext::new());
        let factory = DataglotHandlerFactory::new(ctx);
        let _ = factory.startup_handler();
        // Handler obtained successfully
    }

    #[test]
    fn test_handler_factory_provides_error_handler() {
        let ctx = Arc::new(SessionContext::new());
        let factory = DataglotHandlerFactory::new(ctx);
        let _ = factory.error_handler();
        // Handler obtained successfully
    }

    #[test]
    fn test_handler_factory_session_service_shared() {
        let ctx = Arc::new(SessionContext::new());
        let factory = DataglotHandlerFactory::new(ctx);

        // Both handlers should share the same session service
        let simple = factory.simple_query_handler();
        let extended = factory.extended_query_handler();

        // If we can get both handlers, they're properly created
        drop(simple);
        drop(extended);
    }

    #[test]
    fn test_multiple_factories_independent() {
        let ctx1 = Arc::new(SessionContext::new());
        let ctx2 = Arc::new(SessionContext::new());

        let factory1 = DataglotHandlerFactory::new(ctx1);
        let factory2 = DataglotHandlerFactory::new(ctx2);

        // Both factories should work independently
        let _ = factory1.simple_query_handler();
        let _ = factory2.simple_query_handler();
    }

    #[test]
    fn invoke_startup_observer_extracts_user_and_database_from_metadata() {
        // Pin: the observer fires with the `user` verbatim and the
        // `database` parameter surfaced as `Some(db)`.
        use std::sync::Mutex;
        let user: Arc<Mutex<String>> = Arc::new(Mutex::new(String::new()));
        let db: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
        let user_c = Arc::clone(&user);
        let db_c = Arc::clone(&db);
        let observer: StartupObserver = Arc::new(move |info: &StartupInfo<'_>| {
            *user_c.lock().unwrap() = info.user.to_string();
            *db_c.lock().unwrap() = info.database.map(str::to_string);
            Ok(())
        });

        let mut metadata = std::collections::HashMap::new();
        metadata.insert(pgwire::api::METADATA_USER.to_string(), "alice".to_string());
        metadata.insert(pgwire::api::METADATA_DATABASE.to_string(), "pg".to_string());
        invoke_startup_observer(&observer, &metadata).expect("observer does not reject");

        assert_eq!(*user.lock().unwrap(), "alice");
        assert_eq!(db.lock().unwrap().clone(), Some("pg".to_string()));
    }

    #[test]
    fn invoke_startup_observer_treats_missing_or_empty_database_as_none() {
        use std::sync::Mutex;
        let db: Arc<Mutex<Option<Option<String>>>> = Arc::new(Mutex::new(None));
        let db_clone = Arc::clone(&db);
        let observer: StartupObserver = Arc::new(move |info: &StartupInfo<'_>| {
            *db_clone.lock().unwrap() = Some(info.database.map(str::to_string));
            Ok(())
        });

        // Missing database key → None.
        let mut metadata = std::collections::HashMap::new();
        metadata.insert(pgwire::api::METADATA_USER.to_string(), "bob".to_string());
        invoke_startup_observer(&observer, &metadata).expect("observer does not reject");
        assert_eq!(db.lock().unwrap().clone(), Some(None));

        // Empty database value → None (not Some("")).
        metadata.insert(pgwire::api::METADATA_DATABASE.to_string(), String::new());
        invoke_startup_observer(&observer, &metadata).expect("observer does not reject");
        assert_eq!(db.lock().unwrap().clone(), Some(None));
    }

    #[test]
    fn invoke_startup_observer_passes_empty_string_when_user_absent() {
        // Pin: defensive empty-string fallback when the
        // StartupMessage didn't include a `user` key. Maps to
        // `Identity::anonymous()` on the server side.
        use std::sync::Mutex;
        let captured: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
        let captured_clone = Arc::clone(&captured);
        let observer: StartupObserver = Arc::new(move |info: &StartupInfo<'_>| {
            *captured_clone.lock().unwrap() = Some(info.user.to_string());
            Ok(())
        });

        let metadata = std::collections::HashMap::new();
        invoke_startup_observer(&observer, &metadata).expect("observer does not reject");

        assert_eq!(captured.lock().unwrap().clone(), Some(String::new()));
    }

    #[test]
    fn audit_auth_failure_emits_structured_event() {
        use std::io::Write;
        use std::sync::Mutex;
        use tracing_subscriber::fmt::MakeWriter;

        #[derive(Clone)]
        struct Buf(Arc<Mutex<Vec<u8>>>);
        impl Write for Buf {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(b);
                Ok(b.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        impl<'a> MakeWriter<'a> for Buf {
            type Writer = Buf;
            fn make_writer(&'a self) -> Buf {
                self.clone()
            }
        }

        let buf = Arc::new(Mutex::new(Vec::new()));
        let sub = tracing_subscriber::fmt()
            .with_writer(Buf(buf.clone()))
            .with_target(true)
            .with_ansi(false)
            .without_time()
            .finish();
        tracing::subscriber::with_default(sub, || {
            audit_auth_failure("mallory", "10.0.0.9:5432".parse().unwrap());
        });

        let logged = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
        assert!(logged.contains("dataglot::audit"), "target: {logged}");
        assert!(logged.contains("auth_failed"), "action: {logged}");
        assert!(logged.contains("mallory"), "user: {logged}");
        assert!(logged.contains("10.0.0.9"), "peer: {logged}");
    }

    #[test]
    fn factory_with_observers_accepts_startup_observer() {
        // Pin: the new constructor accepts a `StartupObserver` and
        // produces a working factory. The observer's actual
        // invocation path (post_startup → metadata → callback) is
        // exercised end-to-end by the pgwire e2e tests once a real
        // connection drives the StartupMessage; mocking the rich
        // pgwire 0.38 `ClientInfo` trait surface (including TLS
        // feature-gated methods) at unit level is more code than
        // the one-line metadata lookup it would test. This test
        // pins the construction surface so a future signature change
        // surfaces here.
        use std::sync::atomic::{AtomicBool, Ordering};
        let fired = Arc::new(AtomicBool::new(false));
        let fired_clone = Arc::clone(&fired);
        let startup_observer: StartupObserver = Arc::new(move |_user| {
            fired_clone.store(true, Ordering::Relaxed);
            Ok(())
        });
        let ctx = Arc::new(SessionContext::new());
        let factory =
            DataglotHandlerFactory::with_observers(ctx, Arc::new(NoopObserver), startup_observer);
        // Basic shape: startup handler still produced.
        let _ = factory.startup_handler();
        // Observer hasn't fired — only construction happened.
        assert!(!fired.load(Ordering::Relaxed));
    }

    #[test]
    fn with_observer_constructor_produces_working_factory() {
        // The single-observer convenience constructor (no StartupObserver)
        // still wires a complete handler set.
        let ctx = Arc::new(SessionContext::new());
        let factory = DataglotHandlerFactory::with_observer(ctx, Arc::new(NoopObserver));
        let _ = factory.simple_query_handler();
        let _ = factory.extended_query_handler();
        let _ = factory.startup_handler();
        let _ = factory.error_handler();
    }

    #[test]
    fn noop_startup_observer_is_invocable() {
        // The default observer must accept an invocation and do nothing —
        // covers the no-op closure body installed by `new`/`with_observer`.
        let observer = noop_startup_observer();
        observer(&StartupInfo {
            user: "alice",
            database: Some("analytics"),
        })
        .expect("observer does not reject");
        observer(&StartupInfo {
            user: "",
            database: None,
        })
        .expect("observer does not reject");
    }

    /// Minimal `PasswordSource` so we can build an `AuthMode::Md5` and
    /// exercise the Md5 branch of `startup_handler()`.
    #[derive(Debug)]
    struct StaticPassword;

    #[async_trait::async_trait]
    impl crate::auth::PasswordSource for StaticPassword {
        async fn password(&self, _user: &str) -> Option<String> {
            Some("secret".to_string())
        }
    }

    #[test]
    fn builder_chain_md5_tls_and_admission_builds_full_handler_set() {
        // Drives every builder (`with_auth`, `with_tls_required`,
        // `with_identity_admission`) and the Md5 arm of `startup_handler`
        // (the Trust arm is covered by the other factory tests).
        let ctx = Arc::new(SessionContext::new());
        let auth = AuthMode::Md5(Arc::new(StaticPassword));
        let factory = DataglotHandlerFactory::new(ctx)
            .with_auth(auth)
            .with_tls_required(true)
            .with_identity_admission(Arc::new(AllowAllAdmission));

        // All four handler accessors must still produce; startup_handler
        // here takes the Md5 construction path.
        let _ = factory.simple_query_handler();
        let _ = factory.extended_query_handler();
        let _ = factory.startup_handler();
        let _ = factory.error_handler();
    }

    /// `IdentityAdmission` double that always admits — its permit is a
    /// unit box, released on drop like the real server counter guard.
    #[derive(Debug)]
    struct AllowAllAdmission;
    impl IdentityAdmission for AllowAllAdmission {
        fn admit(&self, _user: &str) -> std::result::Result<IdentityPermit, IdentityLimited> {
            Ok(Box::new(()))
        }
    }

    /// `IdentityAdmission` double that always refuses.
    #[derive(Debug)]
    struct DenyAllAdmission;
    impl IdentityAdmission for DenyAllAdmission {
        fn admit(&self, _user: &str) -> std::result::Result<IdentityPermit, IdentityLimited> {
            Err(IdentityLimited)
        }
    }

    #[test]
    fn identity_admission_contract_admits_and_refuses() {
        // Pin the admission seam the server implements: admit → permit,
        // or IdentityLimited when at the cap.
        assert!(AllowAllAdmission.admit("alice").is_ok());
        assert!(DenyAllAdmission.admit("alice").is_err());
    }

    // ----: completion fires at stream drain, not `do_query` return.

    /// Records the outcome and count of `on_query_complete` calls so tests
    /// can pin *when* completion fires relative to the row stream.
    #[derive(Default)]
    struct RecordingObserver {
        completes: std::sync::atomic::AtomicUsize,
        last_outcome: std::sync::Mutex<Option<QueryOutcome>>,
        last_error: std::sync::Mutex<Option<String>>,
    }

    impl QueryObserver for RecordingObserver {
        fn on_query_error(&self, _run_id: RunId, message: &str) {
            *self.last_error.lock().unwrap() = Some(message.to_string());
        }

        fn on_query_complete(
            &self,
            _run_id: RunId,
            _query: &str,
            _plan: Option<Arc<LogicalPlan>>,
            outcome: QueryOutcome,
            _duration: Duration,
        ) {
            self.completes
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            *self.last_outcome.lock().unwrap() = Some(outcome);
        }
    }

    impl RecordingObserver {
        fn count(&self) -> usize {
            self.completes.load(std::sync::atomic::Ordering::SeqCst)
        }
        fn outcome(&self) -> Option<QueryOutcome> {
            *self.last_outcome.lock().unwrap()
        }
        fn error(&self) -> Option<String> {
            self.last_error.lock().unwrap().clone()
        }
    }

    fn completion_guard(obs: Arc<RecordingObserver>) -> Arc<QueryCompletion> {
        QueryCompletion::new(
            obs as Arc<dyn QueryObserver>,
            RunId::new(),
            "select 1".to_string(),
            None,
            Instant::now(),
        )
    }

    #[test]
    fn completion_fires_success_exactly_once_on_drop() {
        let obs = Arc::new(RecordingObserver::default());
        let guard = completion_guard(Arc::clone(&obs));
        assert_eq!(obs.count(), 0, "must not fire while the guard is alive");
        drop(guard);
        assert_eq!(obs.count(), 1);
        assert_eq!(obs.outcome(), Some(QueryOutcome::Success));
    }

    #[test]
    fn completion_reports_error_and_message_after_set_error() {
        let obs = Arc::new(RecordingObserver::default());
        let guard = completion_guard(Arc::clone(&obs));
        guard.set_error("table \"missing\" not found".to_string());
        drop(guard);
        assert_eq!(obs.outcome(), Some(QueryOutcome::Error));
        // The message is surfaced via on_query_error, before completion.
        assert_eq!(obs.error().as_deref(), Some("table \"missing\" not found"));
    }

    #[test]
    fn set_error_keeps_the_first_root_cause_message() {
        let obs = Arc::new(RecordingObserver::default());
        let guard = completion_guard(Arc::clone(&obs));
        guard.set_error("root cause".to_string());
        guard.set_error("downstream fallout".to_string());
        drop(guard);
        assert_eq!(obs.error().as_deref(), Some("root cause"));
    }

    #[test]
    fn successful_completion_fires_no_error() {
        let obs = Arc::new(RecordingObserver::default());
        let guard = completion_guard(Arc::clone(&obs));
        drop(guard);
        assert_eq!(obs.outcome(), Some(QueryOutcome::Success));
        assert_eq!(obs.error(), None, "success must not fire on_query_error");
    }

    /// Build a handler wired to a `RecordingObserver` (no admin seams) so a
    /// direct `complete_control_plane` call can be inspected.
    fn recording_handler(obs: Arc<RecordingObserver>) -> ObservingSimpleHandler {
        let ctx = Arc::new(SessionContext::new());
        ObservingSimpleHandler {
            inner: Arc::new(DfSessionService::new(Arc::clone(&ctx))),
            session_context: ctx,
            observer: obs as Arc<dyn QueryObserver>,
            catalog_admin: None,
            secret_admin: None,
            user_admin: None,
            policy_admin: None,
            grant_admin: None,
            view_admin: None,
        }
    }

    #[test]
    fn control_plane_error_forwards_message_before_completion() {
        // Regression: a failed control-plane DDL (e.g. CREATE VIEW) used to
        // report a bare `error` outcome with NO message, so the dashboard query
        // profile showed "ERROR" and nothing else. It must now forward the
        // failure detail via on_query_error before completion.
        let obs = Arc::new(RecordingObserver::default());
        let h = recording_handler(Arc::clone(&obs));
        let err = PgWireError::UserError(Box::new(pgwire::error::ErrorInfo::new(
            "ERROR".to_owned(),
            "0A000".to_owned(),
            "schema provider does not support registering tables".to_owned(),
        )));
        h.complete_control_plane(
            RunId::new(),
            "CREATE VIEW v AS SELECT 1",
            Some(&err),
            Instant::now(),
        );
        assert_eq!(obs.outcome(), Some(QueryOutcome::Error));
        assert!(
            obs.error()
                .as_deref()
                .is_some_and(|m| m.contains("schema provider does not support registering tables")),
            "profile must carry the DDL failure detail, got {:?}",
            obs.error()
        );
    }

    #[test]
    fn control_plane_success_fires_no_error() {
        let obs = Arc::new(RecordingObserver::default());
        let h = recording_handler(Arc::clone(&obs));
        h.complete_control_plane(
            RunId::new(),
            "CREATE VIEW v AS SELECT 1",
            None,
            Instant::now(),
        );
        assert_eq!(obs.outcome(), Some(QueryOutcome::Success));
        assert_eq!(obs.error(), None, "success must not fire on_query_error");
    }

    #[tokio::test]
    async fn completion_deferred_until_wrapped_stream_is_drained() {
        use futures::StreamExt;
        let obs = Arc::new(RecordingObserver::default());
        let guard = completion_guard(Arc::clone(&obs));
        let rows: pgwire::api::results::SendableRowStream = Box::pin(futures::stream::empty());
        let mut wrapped = completion_aware_rows(rows, Arc::clone(&guard));
        // Release the local owner: the wrapped stream now holds the only
        // clone, so completion must NOT have fired yet.
        drop(guard);
        assert_eq!(obs.count(), 0, "streaming still in flight => no completion");
        // Draining to the end drops the stream state (and its Arc clone),
        // which fires completion exactly once.
        assert!(wrapped.next().await.is_none());
        assert_eq!(obs.count(), 1);
        assert_eq!(obs.outcome(), Some(QueryOutcome::Success));
        drop(wrapped);
        assert_eq!(obs.count(), 1, "fires exactly once, not again on drop");
    }

    #[tokio::test]
    async fn completion_fires_on_early_stream_drop() {
        // A client that disconnects mid-result: the wrapped stream is
        // dropped before it drains, and completion must still fire.
        let obs = Arc::new(RecordingObserver::default());
        let guard = completion_guard(Arc::clone(&obs));
        let rows: pgwire::api::results::SendableRowStream =
            Box::pin(futures::stream::iter(vec![Err(PgWireError::ApiError(
                "would-be-row".into(),
            ))]));
        let wrapped = completion_aware_rows(rows, Arc::clone(&guard));
        drop(guard);
        assert_eq!(obs.count(), 0);
        drop(wrapped);
        assert_eq!(obs.count(), 1, "early drop still fires completion");
    }

    #[tokio::test]
    async fn completion_flags_error_on_error_row() {
        use futures::StreamExt;
        let obs = Arc::new(RecordingObserver::default());
        let guard = completion_guard(Arc::clone(&obs));
        let rows: pgwire::api::results::SendableRowStream =
            Box::pin(futures::stream::iter(vec![Err(PgWireError::ApiError(
                "boom".into(),
            ))]));
        let mut wrapped = completion_aware_rows(rows, Arc::clone(&guard));
        drop(guard);
        assert!(wrapped.next().await.unwrap().is_err());
        assert!(wrapped.next().await.is_none());
        assert_eq!(obs.count(), 1);
        assert_eq!(
            obs.outcome(),
            Some(QueryOutcome::Error),
            "an error row must taint the outcome even though do_query returned Ok"
        );
        // The row's error text is captured for the History error detail.
        assert!(
            obs.error().is_some_and(|m| m.contains("boom")),
            "the error-row message must be surfaced via on_query_error"
        );
    }

    #[test]
    fn attach_completion_leaves_non_query_responses_untouched() {
        // Only `Response::Query` carries a row stream; a bare guard with
        // no stream attached fires as soon as it drops.
        let obs = Arc::new(RecordingObserver::default());
        let guard = completion_guard(Arc::clone(&obs));
        let mut responses: Vec<Response> = Vec::new();
        attach_completion(&mut responses, &guard);
        assert_eq!(obs.count(), 0);
        drop(guard);
        assert_eq!(obs.count(), 1, "no stream to defer to => fires on drop");
    }
}

/// Catalog-DDL wire path ( slice C.3): the `ObservingSimpleHandler`
/// short-circuit that effects `CREATE / ALTER / DROP CATALOG` through the
/// admin seam and reflects it into the issuing session.
#[cfg(test)]
mod catalog_ddl_tests {
    use std::collections::HashMap;

    use datafusion::catalog::{CatalogProvider, MemoryCatalogProvider, MemorySchemaProvider};

    use super::*;

    /// A mock admin: `Create`/`Alter` → `Registered` with a one-schema catalog
    /// (so a test can see it land); `Drop` → `Dropped`; the name `"boom"` →
    /// `NotFound` (to exercise the error → SQLSTATE mapping).
    struct MockAdmin;

    #[async_trait::async_trait]
    impl CatalogAdmin for MockAdmin {
        async fn apply(
            &self,
            _org: &str,
            ddl: CatalogDdl,
        ) -> std::result::Result<CatalogAdminOutcome, CatalogAdminError> {
            let name = match &ddl {
                CatalogDdl::Create { name, .. }
                | CatalogDdl::Alter { name, .. }
                | CatalogDdl::Drop { name, .. } => name.clone(),
            };
            if name == "boom" {
                return Err(CatalogAdminError::NotFound(name));
            }
            match ddl {
                CatalogDdl::Create { .. } | CatalogDdl::Alter { .. } => {
                    let cat = MemoryCatalogProvider::new();
                    cat.register_schema("s", Arc::new(MemorySchemaProvider::new()))
                        .expect("register schema");
                    Ok(CatalogAdminOutcome::Registered {
                        name,
                        provider: Arc::new(cat),
                    })
                }
                CatalogDdl::Drop { .. } => Ok(CatalogAdminOutcome::Dropped { name }),
            }
        }
    }

    fn handler(admin: Option<Arc<dyn CatalogAdmin>>) -> ObservingSimpleHandler {
        let ctx = Arc::new(SessionContext::new());
        ObservingSimpleHandler {
            inner: Arc::new(DfSessionService::new(Arc::clone(&ctx))),
            session_context: ctx,
            observer: Arc::new(NoopObserver),
            catalog_admin: admin,
            secret_admin: None,
            user_admin: None,
            policy_admin: None,
            grant_admin: None,
            view_admin: None,
        }
    }

    fn create(name: &str) -> CatalogDdl {
        CatalogDdl::Create {
            name: name.to_owned(),
            options: HashMap::new(),
            or_replace: false,
            if_not_exists: false,
        }
    }

    #[tokio::test]
    async fn create_registers_catalog_into_session() {
        let h = handler(Some(Arc::new(MockAdmin)));
        h.apply_catalog_ddl(create("c")).await.expect("create ok");
        let cat = h
            .session_context
            .catalog("c")
            .expect("catalog registered in session");
        assert_eq!(cat.schema_names(), vec!["s".to_owned()]);
    }

    #[tokio::test]
    async fn drop_shadows_catalog_with_empty() {
        let h = handler(Some(Arc::new(MockAdmin)));
        h.apply_catalog_ddl(create("c")).await.expect("create ok");
        assert!(!h
            .session_context
            .catalog("c")
            .unwrap()
            .schema_names()
            .is_empty());

        h.apply_catalog_ddl(CatalogDdl::Drop {
            name: "c".to_owned(),
            if_exists: false,
        })
        .await
        .expect("drop ok");

        // No public deregister — the name is shadowed with an empty catalog.
        let cat = h.session_context.catalog("c").expect("shadow present");
        assert!(
            cat.schema_names().is_empty(),
            "dropped catalog should be shadowed empty in-session"
        );
    }

    #[tokio::test]
    async fn no_admin_rejects_with_feature_not_supported() {
        let h = handler(None);
        let err = h
            .apply_catalog_ddl(create("c"))
            .await
            .expect_err("no admin => reject");
        match err {
            PgWireError::UserError(info) => assert_eq!(info.code, "0A000"),
            other => panic!("expected UserError, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn admin_error_maps_to_sqlstate() {
        let h = handler(Some(Arc::new(MockAdmin)));
        let err = h
            .apply_catalog_ddl(create("boom"))
            .await
            .expect_err("boom => error");
        match err {
            // NotFound → undefined_object.
            PgWireError::UserError(info) => assert_eq!(info.code, "42704"),
            other => panic!("expected UserError, got {other:?}"),
        }
    }

    #[test]
    fn error_sqlstate_mapping_is_stable() {
        let code = |e: &CatalogAdminError| match catalog_ddl_error(e) {
            PgWireError::UserError(info) => info.code,
            other => panic!("expected UserError, got {other:?}"),
        };
        assert_eq!(code(&CatalogAdminError::AlreadyExists("x".into())), "42710");
        assert_eq!(code(&CatalogAdminError::NotFound("x".into())), "42704");
        assert_eq!(
            code(&CatalogAdminError::InvalidOptions("x".into())),
            "42601"
        );
        assert_eq!(code(&CatalogAdminError::Backend("x".into())), "58000");
    }

    /// A mock admin that records the `org` it was called with.
    struct OrgRecordingAdmin(Arc<Mutex<Option<String>>>);

    #[async_trait::async_trait]
    impl CatalogAdmin for OrgRecordingAdmin {
        async fn apply(
            &self,
            org: &str,
            ddl: CatalogDdl,
        ) -> std::result::Result<CatalogAdminOutcome, CatalogAdminError> {
            *self.0.lock().unwrap() = Some(org.to_owned());
            let name = match ddl {
                CatalogDdl::Create { name, .. }
                | CatalogDdl::Alter { name, .. }
                | CatalogDdl::Drop { name, .. } => name,
            };
            Ok(CatalogAdminOutcome::Registered {
                name,
                provider: Arc::new(MemoryCatalogProvider::new()),
            })
        }
    }

    ///  M2: the handler threads the connection's session org (from the
    /// pgwire session-org task-local) into `CatalogAdmin::apply`.
    #[tokio::test]
    async fn apply_catalog_ddl_passes_session_org() {
        let seen = Arc::new(Mutex::new(None));
        let h = handler(Some(Arc::new(OrgRecordingAdmin(Arc::clone(&seen)))));
        crate::with_session_org(Some("acme".to_owned()), async {
            h.apply_catalog_ddl(create("c")).await.expect("create ok");
        })
        .await;
        assert_eq!(seen.lock().unwrap().as_deref(), Some("acme"));
    }

    /// Without a session org (single-tenant / no control plane) the handler
    /// falls back to `"default"` — the pre-M2 boot-org behavior.
    #[tokio::test]
    async fn apply_catalog_ddl_defaults_org_when_unset() {
        let seen = Arc::new(Mutex::new(None));
        let h = handler(Some(Arc::new(OrgRecordingAdmin(Arc::clone(&seen)))));
        crate::with_session_org(None, async {
            h.apply_catalog_ddl(create("c")).await.expect("create ok");
        })
        .await;
        assert_eq!(seen.lock().unwrap().as_deref(), Some("default"));
    }

    // ----: multi-statement dispatch routing.
    //
    // Driving the full `do_query` here would require a mock pgwire client
    // implementing `ClientInfo + ClientPortalStore + Sink<…> + …` — the same
    // rich trait surface the existing tests deliberately avoid (see
    // `factory_with_observers_accepts_startup_observer`, exercised e2e instead).
    // So the routing decision the multi-statement path makes per statement is
    // pinned directly on `try_apply_control_plane_ddl`: control-plane DDL is
    // applied (here, a CREATE CATALOG that lands in this session's context),
    // while an ordinary statement declines (`None`) so `do_query` would hand it
    // to the inner handler. The quote-aware split feeding this loop is covered
    // in `crate::sql_split`; the create-then-select over one wire message is
    // covered by the Docker e2e `create_then_select_same_message`.

    #[tokio::test]
    async fn multi_statement_routes_ddl_to_admin_and_declines_plain_sql() {
        let h = handler(Some(Arc::new(MockAdmin)));
        // The two statements a `CREATE CATALOG c WITH (…); SELECT 1` message
        // splits into (see `crate::sql_split`).
        let stmts = crate::sql_split::split_sql_statements(
            "CREATE CATALOG c WITH (kind = 'postgres', dsn = 'host=db;port=5432'); SELECT 1",
        );
        assert_eq!(
            stmts,
            vec![
                "CREATE CATALOG c WITH (kind = 'postgres', dsn = 'host=db;port=5432')",
                "SELECT 1"
            ]
        );

        // First statement is control-plane DDL: applied through the admin seam,
        // registering the catalog into this session.
        let ddl_result = h
            .try_apply_control_plane_ddl(stmts[0])
            .await
            .expect("first statement is control-plane DDL");
        ddl_result.expect("CREATE CATALOG applies");
        let cat = h
            .session_context
            .catalog("c")
            .expect("catalog registered into session by the DDL statement");
        assert_eq!(cat.schema_names(), vec!["s".to_owned()]);

        // Second statement is an ordinary query: declines, so `do_query` routes
        // it to the inner handler rather than the admin seam.
        assert!(
            h.try_apply_control_plane_ddl(stmts[1]).await.is_none(),
            "SELECT must not be treated as control-plane DDL"
        );
    }

    #[test]
    fn is_control_plane_ddl_matches_each_surface_and_declines_queries() {
        assert!(is_control_plane_ddl(
            "CREATE CATALOG c WITH (kind='postgres')"
        ));
        assert!(is_control_plane_ddl("DROP CATALOG c"));
        assert!(!is_control_plane_ddl("SELECT 1"));
        assert!(!is_control_plane_ddl("CREATE TABLE t (a int)"));
    }
}

/// Secret-DDL wire path: the `ObservingSimpleHandler`
/// short-circuit that routes `CREATE / DROP SECRET` to the admin seam.
#[cfg(test)]
mod secret_ddl_tests {
    use datafusion::prelude::SessionContext;

    use super::*;

    /// A mock secret admin: succeeds unless the name is `"boom"` (→ Backend).
    struct MockSecretAdmin;

    #[async_trait::async_trait]
    impl SecretAdmin for MockSecretAdmin {
        async fn apply(
            &self,
            _org: &str,
            ddl: SecretDdl,
        ) -> std::result::Result<crate::secret_admin::SecretOutcome, SecretAdminError> {
            match ddl {
                SecretDdl::Create { name, .. } if name == "boom" => {
                    Err(SecretAdminError::Backend("boom".into()))
                }
                SecretDdl::Create { name, .. } => {
                    Ok(crate::secret_admin::SecretOutcome::Created { name })
                }
                SecretDdl::Drop { name, .. } => {
                    Ok(crate::secret_admin::SecretOutcome::Dropped { name })
                }
            }
        }
    }

    fn handler(secret_admin: Option<Arc<dyn SecretAdmin>>) -> ObservingSimpleHandler {
        let ctx = Arc::new(SessionContext::new());
        ObservingSimpleHandler {
            inner: Arc::new(DfSessionService::new(Arc::clone(&ctx))),
            session_context: ctx,
            observer: Arc::new(NoopObserver),
            catalog_admin: None,
            secret_admin,
            user_admin: None,
            policy_admin: None,
            grant_admin: None,
            view_admin: None,
        }
    }

    fn create(name: &str) -> SecretDdl {
        SecretDdl::Create {
            name: name.to_owned(),
            value: "v".to_owned(),
            or_replace: false,
            if_not_exists: false,
        }
    }

    #[tokio::test]
    async fn create_and_drop_return_tags() {
        let h = handler(Some(Arc::new(MockSecretAdmin)));
        h.apply_secret_ddl(create("pw")).await.expect("create ok");
        h.apply_secret_ddl(SecretDdl::Drop {
            name: "pw".to_owned(),
            if_exists: false,
        })
        .await
        .expect("drop ok");
    }

    #[tokio::test]
    async fn no_admin_rejects_with_feature_not_supported() {
        let h = handler(None);
        let err = h
            .apply_secret_ddl(create("pw"))
            .await
            .expect_err("no admin => reject");
        match err {
            PgWireError::UserError(info) => assert_eq!(info.code, "0A000"),
            other => panic!("expected UserError, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn backend_error_maps_to_sqlstate() {
        let h = handler(Some(Arc::new(MockSecretAdmin)));
        let err = h
            .apply_secret_ddl(create("boom"))
            .await
            .expect_err("boom => error");
        match err {
            PgWireError::UserError(info) => assert_eq!(info.code, "58000"),
            other => panic!("expected UserError, got {other:?}"),
        }
    }

    #[test]
    fn error_sqlstate_mapping_is_stable() {
        let code = |e: &SecretAdminError| match secret_ddl_error(e) {
            PgWireError::UserError(info) => info.code,
            other => panic!("expected UserError, got {other:?}"),
        };
        assert_eq!(code(&SecretAdminError::AlreadyExists("x".into())), "42710");
        assert_eq!(code(&SecretAdminError::NotFound("x".into())), "42704");
        assert_eq!(code(&SecretAdminError::NotConfigured), "0A000");
        assert_eq!(code(&SecretAdminError::Backend("x".into())), "58000");
    }
}

/// User/role-DDL wire path: the `ObservingSimpleHandler`
/// short-circuit that routes `CREATE / ALTER / DROP USER` + `CREATE / DROP ROLE`
/// to the admin seam.
#[cfg(test)]
mod user_ddl_tests {
    use datafusion::prelude::SessionContext;

    use super::*;
    use crate::user_admin::{UserAdmin, UserOutcome};

    /// A mock user admin: succeeds unless the name is `"boom"` (→ Backend).
    struct MockUserAdmin;

    #[async_trait::async_trait]
    impl UserAdmin for MockUserAdmin {
        async fn apply(
            &self,
            _org: &str,
            ddl: UserDdl,
        ) -> std::result::Result<UserOutcome, UserAdminError> {
            let name = match ddl {
                UserDdl::CreateUser { name, .. }
                | UserDdl::AlterUserPassword { name, .. }
                | UserDdl::DropUser { name, .. }
                | UserDdl::CreateRole { name, .. }
                | UserDdl::DropRole { name, .. } => name,
            };
            if name == "boom" {
                return Err(UserAdminError::Backend("boom".into()));
            }
            Ok(UserOutcome::Created { name })
        }
    }

    fn handler(user_admin: Option<Arc<dyn UserAdmin>>) -> ObservingSimpleHandler {
        let ctx = Arc::new(SessionContext::new());
        ObservingSimpleHandler {
            inner: Arc::new(DfSessionService::new(Arc::clone(&ctx))),
            session_context: ctx,
            observer: Arc::new(NoopObserver),
            catalog_admin: None,
            secret_admin: None,
            user_admin,
            policy_admin: None,
            grant_admin: None,
            view_admin: None,
        }
    }

    fn create_user(name: &str) -> UserDdl {
        UserDdl::CreateUser {
            name: name.to_owned(),
            password: Some("pw".to_owned()),
            superuser: false,
            if_not_exists: false,
        }
    }

    #[tokio::test]
    async fn create_and_drop_return_tags() {
        let h = handler(Some(Arc::new(MockUserAdmin)));
        h.apply_user_ddl(create_user("alice"))
            .await
            .expect("create ok");
        h.apply_user_ddl(UserDdl::DropUser {
            name: "alice".to_owned(),
            if_exists: false,
        })
        .await
        .expect("drop ok");
        h.apply_user_ddl(UserDdl::CreateRole {
            name: "analyst".to_owned(),
            if_not_exists: false,
        })
        .await
        .expect("create role ok");
    }

    #[tokio::test]
    async fn no_admin_rejects_with_feature_not_supported() {
        let h = handler(None);
        let err = h
            .apply_user_ddl(create_user("alice"))
            .await
            .expect_err("no admin => reject");
        match err {
            PgWireError::UserError(info) => assert_eq!(info.code, "0A000"),
            other => panic!("expected UserError, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn backend_error_maps_to_sqlstate() {
        let h = handler(Some(Arc::new(MockUserAdmin)));
        let err = h
            .apply_user_ddl(create_user("boom"))
            .await
            .expect_err("boom => error");
        match err {
            PgWireError::UserError(info) => assert_eq!(info.code, "58000"),
            other => panic!("expected UserError, got {other:?}"),
        }
    }

    #[test]
    fn error_sqlstate_mapping_is_stable() {
        let code = |e: &UserAdminError| match user_ddl_error(e) {
            PgWireError::UserError(info) => info.code,
            other => panic!("expected UserError, got {other:?}"),
        };
        assert_eq!(code(&UserAdminError::AlreadyExists("x".into())), "42710");
        assert_eq!(code(&UserAdminError::NotFound("x".into())), "42704");
        assert_eq!(code(&UserAdminError::NotConfigured), "0A000");
        assert_eq!(code(&UserAdminError::Backend("x".into())), "58000");
    }
}

/// Policy-DDL wire path: the `ObservingSimpleHandler`
/// short-circuit that routes `CREATE / DROP MASK` + `CREATE / DROP ROW FILTER`
/// to the admin seam.
#[cfg(test)]
mod policy_ddl_tests {
    use datafusion::prelude::SessionContext;

    use super::*;
    use crate::policy_admin::{PolicyAdmin, PolicyOutcome};
    use crate::policy_ddl::PolicyMask;

    /// A mock policy admin: succeeds unless the name is `"boom"` (→ Backend).
    struct MockPolicyAdmin;

    #[async_trait::async_trait]
    impl PolicyAdmin for MockPolicyAdmin {
        async fn apply(
            &self,
            _org: &str,
            ddl: PolicyDdl,
        ) -> std::result::Result<PolicyOutcome, PolicyAdminError> {
            let name = match ddl {
                PolicyDdl::CreateMask { name, .. }
                | PolicyDdl::CreateRowFilter { name, .. }
                | PolicyDdl::DropMask { name, .. }
                | PolicyDdl::DropRowFilter { name, .. } => name,
            };
            if name == "boom" {
                return Err(PolicyAdminError::Backend("boom".into()));
            }
            Ok(PolicyOutcome::Created { name })
        }
    }

    fn handler(policy_admin: Option<Arc<dyn PolicyAdmin>>) -> ObservingSimpleHandler {
        let ctx = Arc::new(SessionContext::new());
        ObservingSimpleHandler {
            inner: Arc::new(DfSessionService::new(Arc::clone(&ctx))),
            session_context: ctx,
            observer: Arc::new(NoopObserver),
            catalog_admin: None,
            secret_admin: None,
            user_admin: None,
            policy_admin,
            grant_admin: None,
            view_admin: None,
        }
    }

    fn create_mask(name: &str) -> PolicyDdl {
        PolicyDdl::CreateMask {
            name: name.to_owned(),
            table: "users".to_owned(),
            column: "email".to_owned(),
            mask: PolicyMask::Literal("***@example.com".to_owned()),
            if_not_exists: false,
        }
    }

    #[tokio::test]
    async fn create_and_drop_return_tags() {
        let h = handler(Some(Arc::new(MockPolicyAdmin)));
        h.apply_policy_ddl(create_mask("email_mask"))
            .await
            .expect("create mask ok");
        h.apply_policy_ddl(PolicyDdl::DropMask {
            name: "email_mask".to_owned(),
            if_exists: false,
        })
        .await
        .expect("drop mask ok");
        h.apply_policy_ddl(PolicyDdl::CreateRowFilter {
            name: "tenant".to_owned(),
            table: "orders".to_owned(),
            predicate: "tenant_id = 'acme'".to_owned(),
            if_not_exists: false,
        })
        .await
        .expect("create row filter ok");
    }

    #[tokio::test]
    async fn no_admin_rejects_with_feature_not_supported() {
        let h = handler(None);
        let err = h
            .apply_policy_ddl(create_mask("email_mask"))
            .await
            .expect_err("no admin => reject");
        match err {
            PgWireError::UserError(info) => assert_eq!(info.code, "0A000"),
            other => panic!("expected UserError, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn backend_error_maps_to_sqlstate() {
        let h = handler(Some(Arc::new(MockPolicyAdmin)));
        let err = h
            .apply_policy_ddl(create_mask("boom"))
            .await
            .expect_err("boom => error");
        match err {
            PgWireError::UserError(info) => assert_eq!(info.code, "58000"),
            other => panic!("expected UserError, got {other:?}"),
        }
    }

    #[test]
    fn error_sqlstate_mapping_is_stable() {
        let code = |e: &PolicyAdminError| match policy_ddl_error(e) {
            PgWireError::UserError(info) => info.code,
            other => panic!("expected UserError, got {other:?}"),
        };
        assert_eq!(code(&PolicyAdminError::AlreadyExists("x".into())), "42710");
        assert_eq!(code(&PolicyAdminError::NotFound("x".into())), "42704");
        assert_eq!(code(&PolicyAdminError::NotConfigured), "0A000");
        assert_eq!(code(&PolicyAdminError::Backend("x".into())), "58000");
    }
}

/// Grant-DDL wire path: the `ObservingSimpleHandler`
/// short-circuit that routes `GRANT / REVOKE` to the admin seam. F5a persists
/// only — these tests assert the wire tags + error mapping, not enforcement.
#[cfg(test)]
mod grant_ddl_tests {
    use datafusion::prelude::SessionContext;

    use super::*;
    use crate::grant_admin::{GrantAdmin, GrantOutcome};

    /// A mock grant admin: succeeds unless the grantee/user is `"boom"`
    /// (→ Backend), so the SQLSTATE mapping can be exercised.
    struct MockGrantAdmin;

    #[async_trait::async_trait]
    impl GrantAdmin for MockGrantAdmin {
        async fn apply(
            &self,
            _org: &str,
            ddl: GrantDdl,
        ) -> std::result::Result<GrantOutcome, GrantAdminError> {
            let boom = matches!(&ddl,
                GrantDdl::GrantSelect { grantee, .. }
                | GrantDdl::GrantUsage { grantee, .. }
                | GrantDdl::RevokeSelect { grantee, .. }
                | GrantDdl::RevokeUsage { grantee, .. } if grantee == "boom")
                || matches!(&ddl,
                GrantDdl::GrantRole { user, .. } | GrantDdl::RevokeRole { user, .. }
                    if user == "boom");
            if boom {
                return Err(GrantAdminError::Backend("boom".into()));
            }
            match ddl {
                GrantDdl::GrantSelect { .. }
                | GrantDdl::GrantUsage { .. }
                | GrantDdl::GrantRole { .. } => Ok(GrantOutcome::Granted),
                GrantDdl::RevokeSelect { .. }
                | GrantDdl::RevokeUsage { .. }
                | GrantDdl::RevokeRole { .. } => Ok(GrantOutcome::Revoked),
            }
        }
    }

    fn handler(grant_admin: Option<Arc<dyn GrantAdmin>>) -> ObservingSimpleHandler {
        let ctx = Arc::new(SessionContext::new());
        ObservingSimpleHandler {
            inner: Arc::new(DfSessionService::new(Arc::clone(&ctx))),
            session_context: ctx,
            observer: Arc::new(NoopObserver),
            catalog_admin: None,
            secret_admin: None,
            user_admin: None,
            policy_admin: None,
            grant_admin,
            view_admin: None,
        }
    }

    fn select(grantee: &str) -> GrantDdl {
        GrantDdl::GrantSelect {
            catalog: "pg".into(),
            schema: "public".into(),
            table: "orders".into(),
            grantee: grantee.into(),
        }
    }

    #[tokio::test]
    async fn grant_and_revoke_return_tags() {
        let h = handler(Some(Arc::new(MockGrantAdmin)));
        h.apply_grant_ddl(select("alice")).await.expect("grant ok");
        h.apply_grant_ddl(GrantDdl::RevokeUsage {
            catalog: "pg".into(),
            grantee: "analyst".into(),
        })
        .await
        .expect("revoke ok");
        h.apply_grant_ddl(GrantDdl::GrantRole {
            role: "analyst".into(),
            user: "alice".into(),
        })
        .await
        .expect("membership ok");
    }

    #[tokio::test]
    async fn no_admin_rejects_with_feature_not_supported() {
        let h = handler(None);
        let err = h
            .apply_grant_ddl(select("alice"))
            .await
            .expect_err("no admin => reject");
        match err {
            PgWireError::UserError(info) => assert_eq!(info.code, "0A000"),
            other => panic!("expected UserError, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn backend_error_maps_to_sqlstate() {
        let h = handler(Some(Arc::new(MockGrantAdmin)));
        let err = h
            .apply_grant_ddl(select("boom"))
            .await
            .expect_err("boom => error");
        match err {
            PgWireError::UserError(info) => assert_eq!(info.code, "58000"),
            other => panic!("expected UserError, got {other:?}"),
        }
    }

    #[test]
    fn error_sqlstate_mapping_is_stable() {
        let code = |e: &GrantAdminError| match grant_ddl_error(e) {
            PgWireError::UserError(info) => info.code,
            other => panic!("expected UserError, got {other:?}"),
        };
        assert_eq!(code(&GrantAdminError::NotConfigured), "0A000");
        assert_eq!(code(&GrantAdminError::Backend("x".into())), "58000");
    }
}

/// View-DDL wire path: the `ObservingSimpleHandler`
/// short-circuit that effects `CREATE / DROP VIEW` (derived products) through
/// the admin seam and reflects it into the issuing session.
#[cfg(test)]
mod view_ddl_tests {
    use super::*;

    /// A mock admin: `Create` → `Created` (the handler already built the
    /// provider); the name `"boom"` → `AlreadyExists` (to exercise the error →
    /// SQLSTATE mapping); `Drop` → `Dropped` with the given qualifiers.
    struct MockViewAdmin;

    #[async_trait::async_trait]
    impl ViewAdmin for MockViewAdmin {
        async fn apply(
            &self,
            _org: &str,
            ddl: ViewDdl,
            _provider: Option<Arc<dyn datafusion::catalog::TableProvider>>,
        ) -> std::result::Result<ViewAdminOutcome, ViewAdminError> {
            match ddl {
                ViewDdl::Create { name, .. } => {
                    if name == "boom" {
                        return Err(ViewAdminError::AlreadyExists(name));
                    }
                    Ok(ViewAdminOutcome::Created)
                }
                ViewDdl::Drop {
                    catalog,
                    schema,
                    name,
                    ..
                } => Ok(ViewAdminOutcome::Dropped {
                    catalog,
                    schema,
                    name,
                }),
            }
        }
    }

    fn handler(admin: Option<Arc<dyn ViewAdmin>>) -> ObservingSimpleHandler {
        let ctx = Arc::new(SessionContext::new());
        ObservingSimpleHandler {
            inner: Arc::new(DfSessionService::new(Arc::clone(&ctx))),
            session_context: ctx,
            observer: Arc::new(NoopObserver),
            catalog_admin: None,
            secret_admin: None,
            user_admin: None,
            policy_admin: None,
            grant_admin: None,
            view_admin: admin,
        }
    }

    fn create(name: &str) -> ViewDdl {
        ViewDdl::Create {
            catalog: None,
            schema: None,
            name: name.to_owned(),
            query: "SELECT 1".to_owned(),
            or_replace: false,
        }
    }

    #[tokio::test]
    async fn create_registers_view_into_session() {
        let h = handler(Some(Arc::new(MockViewAdmin)));
        h.apply_view_ddl(create("v")).await.expect("create ok");
        assert!(
            h.session_context
                .table_exist(TableReference::bare("v"))
                .expect("table_exist"),
            "view must be registered as a queryable table in the session"
        );
    }

    #[tokio::test]
    async fn drop_deregisters_view_from_session() {
        let h = handler(Some(Arc::new(MockViewAdmin)));
        h.apply_view_ddl(create("v")).await.expect("create ok");
        h.apply_view_ddl(ViewDdl::Drop {
            catalog: None,
            schema: None,
            name: "v".to_owned(),
            if_exists: false,
        })
        .await
        .expect("drop ok");
        assert!(
            !h.session_context
                .table_exist(TableReference::bare("v"))
                .expect("table_exist"),
            "dropped view must no longer resolve in-session"
        );
    }

    #[tokio::test]
    async fn missing_admin_rejects_with_feature_not_supported() {
        let h = handler(None);
        let err = h.apply_view_ddl(create("v")).await.expect_err("no admin");
        match err {
            PgWireError::UserError(info) => assert_eq!(info.code, "0A000"),
            other => panic!("expected UserError, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn unplannable_query_maps_to_syntax_error_sqlstate() {
        // The handler plans the AS body against its session; an unknown table
        // fails to plan → InvalidQuery (42601), before the admin is consulted.
        let h = handler(Some(Arc::new(MockViewAdmin)));
        let ddl = ViewDdl::Create {
            catalog: None,
            schema: None,
            name: "v".to_owned(),
            query: "SELECT * FROM no_such_table".to_owned(),
            or_replace: false,
        };
        let err = h.apply_view_ddl(ddl).await.expect_err("unplannable");
        match err {
            PgWireError::UserError(info) => assert_eq!(info.code, "42601"),
            other => panic!("expected UserError, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn already_exists_maps_to_duplicate_object_sqlstate() {
        // A plannable query whose admin reports AlreadyExists → 42710.
        let h = handler(Some(Arc::new(MockViewAdmin)));
        let err = h
            .apply_view_ddl(create("boom"))
            .await
            .expect_err("boom => already exists");
        match err {
            PgWireError::UserError(info) => assert_eq!(info.code, "42710"),
            other => panic!("expected UserError, got {other:?}"),
        }
    }

    #[test]
    fn error_sqlstate_mapping_is_stable() {
        let code = |e: &ViewAdminError| match view_ddl_error(e) {
            PgWireError::UserError(info) => info.code,
            other => panic!("expected UserError, got {other:?}"),
        };
        assert_eq!(code(&ViewAdminError::AlreadyExists("v".into())), "42710");
        assert_eq!(code(&ViewAdminError::NotFound("v".into())), "42704");
        assert_eq!(code(&ViewAdminError::InvalidQuery("v".into())), "42601");
        assert_eq!(code(&ViewAdminError::Backend("x".into())), "58000");
    }
}

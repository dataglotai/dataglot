//! Integration tests for the Arrow Flight SQL **ingress** connector
//! (, spec: the phase-4 `arrow-flight-sql-ingress` plan).
//!
//! Unlike the Postgres / MySQL / ADBC suites these need **no Docker**: the
//! remote is an in-process Flight SQL server built on DataFusion, served over
//! a loopback gRPC listener. That is deliberate — it keeps the mandatory
//! SQL-connector parity test (the mandatory-tests rule) in the
//! normal CI lane, and it is a faithful stand-in for the servers this
//! connector targets, which are DataFusion-backed themselves (a Dataglot
//! peer, `InfluxDB` 3, Sail, Ballista, ROAPI).
//!
//! What is covered:
//!
//! 1. **Pushdown parity** — a complex single-source query compiles to one SQL
//!    string sent over Flight, with the negative-space assertion that nothing
//!    re-executes locally.
//! 2. **Discovery on both paths** — the `GetTables` metadata RPC, and the
//!    `information_schema` fallback for servers that answer `Unimplemented`
//!    (which is what Dataglot's own Flight SQL listener does today).
//! 3. **Correctness** — values and row counts, plus a cross-source join with
//!    a local table.
//! 4. **Credentials** — the Basic header reaches the server, and a wrong
//!    environment variable fails at connect with no secret in the message.
//! 5. **The endpoint-location policy** — a server that points results at
//!    another host is refused unless the operator opts in.

#![cfg(feature = "flightsql")]

use std::sync::{Arc, Mutex};

/// Serialises every test that writes to the process environment.
///
/// Unique variable names are not enough. `setenv` mutates a process-wide
/// table that other threads may be reading at the same moment — `getenv`
/// during another test's `connect`, or anything inside tokio or tonic — and
/// that race is a data race whatever the key is. It is the reason edition
/// 2024 makes `set_var` unsafe; edition 2021, which this workspace uses,
/// merely leaves the hazard unmarked.
///
/// A *reader/writer* lock, because the hazard is a writer racing any
/// concurrent reader, not two writers racing each other. `set_var` mutates
/// the process-wide table while `getenv` may be walking it on another
/// thread — inside another test's `connect`, or anywhere in tokio, tonic or
/// rustls — so a writer has to exclude every other test, and readers only
/// have to exclude writers. Tests that touch the environment take
/// [`env_write`]; every other test takes [`env_read`].
///
/// A `tokio` lock rather than a `std` one: guards are deliberately held
/// across `.await` points, since the variable must stay set for a whole
/// connect-and-query sequence. It also does not poison, so one failing test
/// cannot cascade into the rest.
static ENV_LOCK: tokio::sync::RwLock<()> = tokio::sync::RwLock::const_new(());

/// Take the environment lock for writing — for a test that sets or removes a
/// variable.
async fn env_write() -> tokio::sync::RwLockWriteGuard<'static, ()> {
    ENV_LOCK.write().await
}

/// Take the environment lock for reading — for every other test, so a writer
/// cannot run while this one is reading the environment underneath.
async fn env_read() -> tokio::sync::RwLockReadGuard<'static, ()> {
    ENV_LOCK.read().await
}

/// Sets an environment variable and removes it again on drop, so a panicking
/// test cannot leave it set for whatever runs next.
struct EnvVar(&'static str);

impl EnvVar {
    fn set(name: &'static str, value: &str) -> Self {
        // Edition 2021: `set_var` is safe. The caller holds the write half
        // of `ENV_LOCK`, which is what makes it *sound* rather than merely
        // legal.
        std::env::set_var(name, value);
        Self(name)
    }
}

impl Drop for EnvVar {
    fn drop(&mut self) {
        std::env::remove_var(self.0);
    }
}

use arrow_flight::encode::FlightDataEncoderBuilder;
use arrow_flight::error::FlightError;
use arrow_flight::flight_service_server::{FlightService, FlightServiceServer};
use arrow_flight::sql::server::FlightSqlService;
use arrow_flight::sql::{
    Any, CommandGetTables, CommandStatementQuery, SqlInfo, TicketStatementQuery,
};
use arrow_flight::{FlightDescriptor, FlightEndpoint, FlightInfo, Ticket};
use datafusion::arrow::array::{Int32Array, RecordBatch, StringArray};
use datafusion::arrow::datatypes::{DataType, Field, Schema};
use datafusion::arrow::util::pretty::pretty_format_batches;
use datafusion::catalog::SchemaProvider as _;
use datafusion::datasource::MemTable;
use datafusion::execution::session_state::SessionStateBuilder;
use datafusion::prelude::{SessionConfig as DfSessionConfig, SessionContext};
use dataglot_federation::flightsql::{
    FlightSqlAuth, FlightSqlConfig, FlightSqlConnector, FlightSqlDialect,
};
use futures::TryStreamExt;
use prost::Message;
use tonic::{Request, Response, Status};

// ---------------------------------------------------------------------------
// An in-process Flight SQL server over DataFusion
// ---------------------------------------------------------------------------

/// How the fixture server answers `GetTables`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Metadata {
    /// Implements the metadata RPC — the Dremio-style server.
    GetTables,
    /// Answers `Unimplemented`, forcing the `information_schema` fallback —
    /// what Dataglot's own Flight SQL listener does today.
    Unimplemented,
}

#[derive(Clone)]
struct TestServer {
    ctx: Arc<SessionContext>,
    metadata: Metadata,
    /// Advertised on every endpoint when set, to exercise the
    /// foreign-location policy.
    advertise_location: Option<String>,
    /// Answer every `GetFlightInfo` with a ticket-less endpoint.
    drop_tickets: bool,
    /// Advertise the result across this many endpoints (all redeeming the
    /// same ticket), the shape a distributed server returns.
    endpoints: usize,
    /// What to put in `FlightInfo.ordered`.
    ordered: bool,
    /// The `authorization` header of the most recent request.
    seen_auth: Arc<Mutex<Option<String>>>,
    /// Every statement the server was asked to plan, in order — the wire
    /// truth about what pushdown actually sent.
    seen_sql: Arc<Mutex<Vec<String>>>,
    /// How many tickets this server has served. Planning and serving are
    /// separate RPCs and can land on different servers, which is exactly
    /// what the endpoint-location tests need to tell apart.
    served_tickets: Arc<std::sync::atomic::AtomicUsize>,
}

impl TestServer {
    fn new(metadata: Metadata) -> Self {
        // `information_schema` is what the fallback discovery path reads.
        let config = DfSessionConfig::new().with_information_schema(true);
        let ctx = SessionContext::new_with_config(config);

        let schema = Arc::new(Schema::new(vec![
            Field::new("id", DataType::Int32, false),
            Field::new("name", DataType::Utf8, false),
            Field::new("age", DataType::Int32, false),
        ]));
        let batch = RecordBatch::try_new(
            Arc::clone(&schema),
            vec![
                Arc::new(Int32Array::from(vec![1, 2, 3, 4])),
                Arc::new(StringArray::from(vec!["alice", "bob", "carol", "dave"])),
                Arc::new(Int32Array::from(vec![30, 25, 35, 20])),
            ],
        )
        .expect("build the users fixture batch");
        ctx.register_table(
            "users",
            Arc::new(MemTable::try_new(schema, vec![vec![batch]]).expect("memtable")),
        )
        .expect("register users");

        // A second schema, so "the configured scope is honoured exactly" has
        // something to exclude. This fixture's GetTables deliberately ignores
        // the filter pattern — which is what a server that widens a wildcard
        // pattern looks like from the client's side.
        let ops = Arc::new(datafusion::catalog::MemorySchemaProvider::new());
        let secrets_schema = Arc::new(Schema::new(vec![Field::new(
            "token",
            DataType::Utf8,
            false,
        )]));
        let secrets = RecordBatch::try_new(
            Arc::clone(&secrets_schema),
            vec![Arc::new(StringArray::from(vec!["s3cret"]))],
        )
        .expect("build the secrets fixture batch");
        ops.register_table(
            "secrets".to_string(),
            Arc::new(MemTable::try_new(secrets_schema, vec![vec![secrets]]).expect("memtable")),
        )
        .expect("register secrets");
        ctx.catalog("datafusion")
            .expect("default catalog")
            .register_schema("ops", ops)
            .expect("register the ops schema");

        Self {
            ctx: Arc::new(ctx),
            metadata,
            advertise_location: None,
            drop_tickets: false,
            endpoints: 1,
            ordered: false,
            seen_auth: Arc::new(Mutex::new(None)),
            seen_sql: Arc::new(Mutex::new(Vec::new())),
            served_tickets: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        }
    }

    fn record_auth<T>(&self, request: &Request<T>) {
        let header = request
            .metadata()
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        *self.seen_auth.lock().expect("auth lock") = header;
    }

    fn endpoint(&self, ticket: Ticket) -> FlightEndpoint {
        // A malformed server: the endpoint names no ticket, so nothing can
        // be fetched from it.
        if self.drop_tickets {
            return FlightEndpoint::new();
        }
        let endpoint = FlightEndpoint::new().with_ticket(ticket);
        match &self.advertise_location {
            Some(uri) => endpoint.with_location(uri.clone()),
            None => endpoint,
        }
    }

    /// Plan `sql` and answer with its schema plus a ticket carrying the SQL.
    async fn info_for_sql(
        &self,
        sql: String,
        descriptor: FlightDescriptor,
    ) -> Result<Response<FlightInfo>, Status> {
        let df = self
            .ctx
            .sql(&sql)
            .await
            .map_err(|e| Status::invalid_argument(format!("planning failed: {e}")))?;
        let schema = df.schema().as_arrow().clone();
        let ticket = Ticket::new(
            Any::pack(&TicketStatementQuery {
                statement_handle: sql.into_bytes().into(),
            })
            .map_err(|e| Status::internal(format!("ticket encode: {e}")))?
            .encode_to_vec(),
        );
        let mut info = FlightInfo::new()
            .try_with_schema(&schema)
            .map_err(|e| Status::internal(format!("schema encode: {e}")))?
            .with_descriptor(descriptor)
            .with_ordered(self.ordered);
        for _ in 0..self.endpoints.max(1) {
            info = info.with_endpoint(self.endpoint(ticket.clone()));
        }
        Ok(Response::new(info))
    }

    async fn stream_sql(
        &self,
        sql: &str,
    ) -> Result<Response<<Self as FlightService>::DoGetStream>, Status> {
        let df = self
            .ctx
            .sql(sql)
            .await
            .map_err(|e| Status::invalid_argument(format!("planning failed: {e}")))?;
        let batches = df
            .execute_stream()
            .await
            .map_err(|e| Status::internal(format!("execution failed: {e}")))?;
        let stream = FlightDataEncoderBuilder::new()
            .build(batches.map_err(|e| FlightError::ExternalError(Box::new(e))))
            .map_err(Status::from);
        Ok(Response::new(Box::pin(stream)))
    }
}

#[tonic::async_trait]
impl FlightSqlService for TestServer {
    type FlightService = TestServer;

    async fn get_flight_info_statement(
        &self,
        query: CommandStatementQuery,
        request: Request<FlightDescriptor>,
    ) -> Result<Response<FlightInfo>, Status> {
        self.record_auth(&request);
        self.seen_sql
            .lock()
            .expect("sql lock")
            .push(query.query.clone());
        self.info_for_sql(query.query, request.into_inner()).await
    }

    async fn do_get_statement(
        &self,
        ticket: TicketStatementQuery,
        request: Request<Ticket>,
    ) -> Result<Response<<Self as FlightService>::DoGetStream>, Status> {
        self.record_auth(&request);
        self.served_tickets
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let sql = String::from_utf8(ticket.statement_handle.to_vec())
            .map_err(|_| Status::invalid_argument("ticket is not UTF-8 SQL"))?;
        self.stream_sql(&sql).await
    }

    async fn get_flight_info_tables(
        &self,
        _query: CommandGetTables,
        request: Request<FlightDescriptor>,
    ) -> Result<Response<FlightInfo>, Status> {
        self.record_auth(&request);
        if self.metadata == Metadata::Unimplemented {
            return Err(Status::unimplemented("GetTables"));
        }
        // The metadata RPC is answered from the same catalog the fallback
        // would read, spelled in the Flight SQL column names.
        self.info_for_sql(
            "SELECT table_catalog AS catalog_name, table_schema AS db_schema_name, \
             table_name, table_type FROM information_schema.tables \
             WHERE table_schema <> 'information_schema'"
                .to_string(),
            request.into_inner(),
        )
        .await
    }

    async fn register_sql_info(&self, _id: i32, _result: &SqlInfo) {}
}

/// A running fixture server: its `grpc://` URI, a handle for inspecting what
/// it saw, and a graceful-shutdown trigger.
///
/// Shutdown is explicit rather than `JoinHandle::abort` so that
/// [`Fixture::stop`] is *deterministic*: it returns only once tonic has
/// closed the listener and every connection, which is what makes "the health
/// probe fails against a stopped server" a reliable assertion instead of a
/// race.
struct Fixture {
    uri: String,
    server: TestServer,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    /// `Option` so `stop` can await it while `Drop` can still abort it.
    task: Option<tokio::task::JoinHandle<()>>,
}

impl Fixture {
    /// Start a server on a loopback port.
    ///
    /// The listener is bound *before* `build` runs so a fixture can advertise
    /// the very address it is about to listen on — the self-referential
    /// endpoint location Dremio-style servers emit.
    async fn start(build: impl FnOnce(&str) -> TestServer) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind a loopback port");
        let addr = listener.local_addr().expect("resolve the bound address");
        let uri = format!("grpc://{addr}");
        let server = build(&uri);
        let inspect = server.clone();
        let (shutdown, rx) = tokio::sync::oneshot::channel();
        let svc = FlightServiceServer::new(server);
        let task = tokio::spawn(async move {
            let _ = tonic::transport::Server::builder()
                .add_service(svc)
                .serve_with_incoming_shutdown(
                    tokio_stream::wrappers::TcpListenerStream::new(listener),
                    async move {
                        let _ = rx.await;
                    },
                )
                .await;
        });
        Self {
            uri,
            server: inspect,
            shutdown: Some(shutdown),
            task: Some(task),
        }
    }

    /// Start a server with the default fixture data.
    async fn with(metadata: Metadata) -> Self {
        Self::start(|_| TestServer::new(metadata)).await
    }

    /// Stop the server and wait until it is really gone.
    async fn stop(mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
    }
}

impl Drop for Fixture {
    /// A test that panics never reaches `stop`, and its server would then
    /// hold its port for the rest of the run — enough to make the *next*
    /// failure look unrelated. Signalling shutdown here cannot await the
    /// task, so `stop` is still the way to be sure it is gone; this is the
    /// safety net for the panicking path.
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

async fn connect(endpoint: &str) -> Arc<FlightSqlConnector> {
    Arc::new(
        FlightSqlConnector::connect(FlightSqlConfig::new(
            "flight",
            endpoint,
            FlightSqlDialect::DataFusion,
        ))
        .await
        .expect("connector connects"),
    )
}

/// A federation-enabled context with the remote `public.users` registered.
async fn federated_ctx(connector: &Arc<FlightSqlConnector>) -> SessionContext {
    let provider = connector
        .table_provider("public", "users")
        .await
        .expect("schema resolves for public.users");
    let base = SessionContext::new();
    let state = SessionStateBuilder::new_from_existing(base.state())
        .with_optimizer_rules(datafusion_federation::default_optimizer_rules())
        .with_query_planner(Arc::new(datafusion_federation::FederatedQueryPlanner::new()))
        .build();
    let ctx = SessionContext::new_with_state(state);
    ctx.register_table("users", provider)
        .expect("register the remote users table");
    ctx
}

// ---------------------------------------------------------------------------
// Correctness
// ---------------------------------------------------------------------------

#[tokio::test]
async fn select_over_flight_sql_returns_remote_rows() {
    let _env = env_read().await;
    let fx = Fixture::with(Metadata::GetTables).await;
    let connector = connect(&fx.uri).await;
    let ctx = federated_ctx(&connector).await;

    let batches = ctx
        .sql("SELECT name FROM users WHERE age >= 25 ORDER BY name")
        .await
        .expect("plans")
        .collect()
        .await
        .expect("executes");
    let rendered = pretty_format_batches(&batches).unwrap().to_string();
    assert!(rendered.contains("alice"), "got:\n{rendered}");
    assert!(rendered.contains("bob"), "got:\n{rendered}");
    assert!(rendered.contains("carol"), "got:\n{rendered}");
    assert!(
        !rendered.contains("dave"),
        "age 20 is filtered out on the remote:\n{rendered}"
    );
}

/// A join between the Flight source and a local table: the Flight side is
/// still pushed, the join happens locally. This is the shape every
/// cross-source query takes.
#[tokio::test]
async fn flight_sql_joins_against_a_local_table() {
    let _env = env_read().await;
    let fx = Fixture::with(Metadata::GetTables).await;
    let connector = connect(&fx.uri).await;
    let ctx = federated_ctx(&connector).await;

    let schema = Arc::new(Schema::new(vec![
        Field::new("id", DataType::Int32, false),
        Field::new("city", DataType::Utf8, false),
    ]));
    let batch = RecordBatch::try_new(
        Arc::clone(&schema),
        vec![
            Arc::new(Int32Array::from(vec![1, 2])),
            Arc::new(StringArray::from(vec!["ankara", "izmir"])),
        ],
    )
    .unwrap();
    ctx.register_table(
        "cities",
        Arc::new(MemTable::try_new(schema, vec![vec![batch]]).unwrap()),
    )
    .unwrap();

    let batches = ctx
        .sql("SELECT u.name, c.city FROM users u JOIN cities c ON u.id = c.id ORDER BY u.name")
        .await
        .expect("plans")
        .collect()
        .await
        .expect("executes");
    let rendered = pretty_format_batches(&batches).unwrap().to_string();
    assert!(
        rendered.contains("ankara") && rendered.contains("izmir"),
        "got:\n{rendered}"
    );
    assert_eq!(
        batches.iter().map(RecordBatch::num_rows).sum::<usize>(),
        2,
        "two ids match:\n{rendered}"
    );
}

// ---------------------------------------------------------------------------
// The mandatory SQL-connector parity test
// ---------------------------------------------------------------------------

/// Native-query passthrough verification — the SQL-connector parity rule:
/// a complex single-source query must reach the remote as one statement.
///
/// A complex single-source query (predicate + `GROUP BY` + aggregate +
/// `ORDER BY` + `LIMIT`) must compile into **one** SQL statement sent over
/// Flight. The negative half is the load-bearing one: a test that only
/// asserts the federation node appears still passes when the predicate
/// pushes and DataFusion re-does the aggregation locally — exactly the
/// regression a `datafusion-federation` bump could introduce.
#[tokio::test]
async fn single_source_complex_query_pushed_through_natively() {
    let _env = env_read().await;
    let fx = Fixture::with(Metadata::GetTables).await;
    let connector = connect(&fx.uri).await;
    let ctx = federated_ctx(&connector).await;

    let complex_sql = "
        SELECT age, COUNT(*) AS n
        FROM users
        WHERE age >= 25
        GROUP BY age
        ORDER BY age
        LIMIT 10
    ";

    // ---- 1. Correctness sanity check ---------------------------
    let batches = ctx
        .sql(complex_sql)
        .await
        .expect("complex SQL plans")
        .collect()
        .await
        .expect("complex SQL executes");
    let total_rows: usize = batches.iter().map(RecordBatch::num_rows).sum();
    assert_eq!(
        total_rows,
        3,
        "ages 25, 30, 35 each form one group:\n{}",
        pretty_format_batches(&batches).unwrap()
    );

    // ---- 2. Passthrough — positive assertion -------------------
    let explain_batches = ctx
        .sql(&format!("EXPLAIN {complex_sql}"))
        .await
        .expect("EXPLAIN plans")
        .collect()
        .await
        .expect("EXPLAIN runs");
    let explain_str = pretty_format_batches(&explain_batches).unwrap().to_string();
    let explain_upper = explain_str.to_uppercase();

    assert!(
        explain_upper.contains("VIRTUALEXECUTIONPLAN")
            || explain_str.contains("sql_federation_exec"),
        "expected a federation virtual exec node:\n{explain_str}"
    );
    for needle in ["GROUP BY", "ORDER BY", "LIMIT"] {
        assert!(
            explain_upper.contains(needle),
            "expected {needle:?} in the pushed SQL inside EXPLAIN:\n{explain_str}"
        );
    }
    assert!(
        explain_str.contains("age") && explain_str.contains("25"),
        "expected `age` and `25` (the predicate) in the pushed SQL:\n{explain_str}"
    );

    // ---- 3. Passthrough — what actually crossed the wire -------
    // EXPLAIN proves the plan; this proves execution. The server records
    // every statement it was asked to plan, so a regression that pushed a
    // bare scan and aggregated locally would show a `SELECT` without the
    // aggregate here even if the plan text looked right.
    let pushed = fx.server.seen_sql.lock().unwrap().clone();
    let aggregate_pushed = pushed
        .iter()
        .any(|sql| sql.to_uppercase().contains("GROUP BY") && sql.to_uppercase().contains("COUNT"));
    assert!(
        aggregate_pushed,
        "the aggregate must be in the SQL sent over Flight; the server saw: {pushed:#?}"
    );

    // ---- 4. Passthrough — negative assertion -------------------
    // No local-execution operator above the federation node. `ProjectionExec`
    // is deliberately absent from this list: DataFusion routinely wraps the
    // virtual exec in a projection that only renames or re-orders columns.
    let forbidden_locally_executed = [
        "AggregateExec",
        "SortExec",
        "FilterExec",
        "GlobalLimitExec",
        "LocalLimitExec",
        "HashAggregateExec",
        "PartialAggregateExec",
    ];
    let leaks: Vec<&str> = forbidden_locally_executed
        .into_iter()
        .filter(|op| explain_str.contains(op))
        .collect();
    assert!(
        leaks.is_empty(),
        "single-source complex query leaked local-execution operator(s) above the federation node: {leaks:?}\n\
         GROUP BY / ORDER BY / LIMIT did not fully push and native passthrough regressed.\n\nfull EXPLAIN:\n{explain_str}"
    );
}

// ---------------------------------------------------------------------------
// Discovery — both paths
// ---------------------------------------------------------------------------

#[tokio::test]
async fn catalog_discovery_uses_the_get_tables_metadata_rpc() {
    let _env = env_read().await;
    let fx = Fixture::with(Metadata::GetTables).await;
    let connector = connect(&fx.uri).await;

    let catalog = connector
        .as_catalog_provider()
        .await
        .expect("catalog lists via GetTables");
    assert!(
        catalog.schema_names().contains(&"public".to_string()),
        "expected the public schema, got: {:?}",
        catalog.schema_names()
    );
    let schema = catalog.schema("public").expect("public schema resolves");
    assert!(schema.table_names().contains(&"users".to_string()));
    assert!(schema.table_exist("users"));
    assert!(!schema.table_exist("absent"));

    // Column schemas stay lazy until the table is asked for (rule 13).
    let table = schema
        .table("users")
        .await
        .expect("table resolves")
        .unwrap();
    let fields: Vec<String> = table
        .schema()
        .fields()
        .iter()
        .map(|f| f.name().clone())
        .collect();
    assert_eq!(fields, vec!["id", "name", "age"]);
    assert!(
        schema
            .table("absent")
            .await
            .expect("negative lookup")
            .is_none(),
        "an unlisted name resolves to None without a round trip"
    );
}

/// `FlightInfo.ordered` says whether the endpoints are in the order the rows
/// should come back in. When it is false the split is arbitrary, so a query
/// whose `ORDER BY` was pushed to the remote cannot be answered by reading
/// the endpoints back to back — that orders rows by partition.
#[tokio::test]
async fn an_ordered_query_over_an_unordered_multi_endpoint_result_is_refused() {
    let _env = env_read().await;
    let fx = Fixture::start(|_| {
        let mut fixture = TestServer::new(Metadata::GetTables);
        fixture.endpoints = 2;
        fixture.ordered = false;
        fixture
    })
    .await;
    let connector = connect(&fx.uri).await;
    let ctx = federated_ctx(&connector).await;

    let err = ctx
        .sql("SELECT id FROM users ORDER BY id")
        .await
        .expect("plans")
        .collect()
        .await
        .expect_err("partition order is not sort order");
    let msg = err.to_string();
    assert!(msg.contains("ordered"), "names the flag: {msg}");
    assert!(msg.contains("ORDER BY"), "names what is at stake: {msg}");

    // The same server answers an unordered query perfectly well: the guard
    // must not cost every distributed result, only the ones whose
    // correctness depends on the order.
    ctx.sql("SELECT id FROM users")
        .await
        .expect("plans")
        .collect()
        .await
        .expect("an unordered query does not care how the split fell");
}

/// …and a server that *does* advertise an order is taken at its word: the
/// endpoints are redeemed in the order it listed them.
#[tokio::test]
async fn an_ordered_query_is_served_when_the_server_advertises_an_order() {
    let _env = env_read().await;
    let fx = Fixture::start(|_| {
        let mut fixture = TestServer::new(Metadata::GetTables);
        fixture.endpoints = 2;
        fixture.ordered = true;
        fixture
    })
    .await;
    let connector = connect(&fx.uri).await;
    let ctx = federated_ctx(&connector).await;

    ctx.sql("SELECT id FROM users ORDER BY id")
        .await
        .expect("plans")
        .collect()
        .await
        .expect("an advertised order is honoured, not second-guessed");
}

/// An endpoint with no ticket names rows that cannot be fetched. Skipping it
/// is invisible on the discovery paths — the RPC succeeded, so no fallback
/// runs — and the operator would get a catalog missing whatever that
/// endpoint held, with everything reporting healthy.
#[tokio::test]
async fn an_endpoint_without_a_ticket_is_a_protocol_error_on_every_path() {
    let _env = env_read().await;
    for metadata in [Metadata::GetTables, Metadata::Unimplemented] {
        let fx = Fixture::start(move |_| {
            let mut fixture = TestServer::new(metadata);
            fixture.drop_tickets = true;
            fixture
        })
        .await;
        let connector = connect(&fx.uri).await;

        let err = connector
            .as_catalog_provider()
            .await
            .expect_err("a ticket-less endpoint must not list as an empty catalog");
        assert!(err.to_string().contains("no ticket"), "{metadata:?}: {err}");
    }
}

/// A server that answers `Unimplemented` — Dataglot's own Flight SQL
/// listener today — must still be listable, via `information_schema`.
#[tokio::test]
async fn catalog_discovery_falls_back_to_information_schema() {
    let _env = env_read().await;
    let fx = Fixture::with(Metadata::Unimplemented).await;
    let connector = connect(&fx.uri).await;

    let catalog = connector
        .as_catalog_provider()
        .await
        .expect("catalog lists via the information_schema fallback");
    let schema = catalog.schema("public").expect("public schema resolves");
    assert!(
        schema.table_names().contains(&"users".to_string()),
        "got: {:?}",
        schema.table_names()
    );
    assert!(
        !catalog
            .schema_names()
            .contains(&"information_schema".to_string()),
        "the server's own metadata views are not part of the federated catalog"
    );

    // The fallback projects `table_catalog` as well. It is never adopted —
    // `catalog` is configuration — but the ambiguity check reads it, and a
    // projection without it would record every row as unqualified and leave
    // that check silently dead on this path.
    let listed = fx.server.seen_sql.lock().unwrap().clone();
    assert!(
        listed
            .iter()
            .any(|sql| sql.contains("table_catalog") && sql.contains("information_schema.tables")),
        "the fallback must carry catalog provenance: {listed:?}"
    );
}

/// Scoping to one source-side schema keeps everything else out of the
/// catalog — the multi-tenant case.
#[tokio::test]
async fn discovery_honours_the_configured_schema_scope() {
    let _env = env_read().await;
    let fx = Fixture::with(Metadata::Unimplemented).await;
    let mut config = FlightSqlConfig::new("flight", &fx.uri, FlightSqlDialect::DataFusion);
    config.schema = Some("nope".to_string());
    let connector = Arc::new(
        FlightSqlConnector::connect(config)
            .await
            .expect("connector connects"),
    );
    let catalog = connector.as_catalog_provider().await.expect("lists");
    assert!(
        catalog.schema_names().is_empty(),
        "a schema filter that matches nothing yields an empty catalog, got: {:?}",
        catalog.schema_names()
    );
}

// ---------------------------------------------------------------------------
// Health, credentials, endpoint policy
// ---------------------------------------------------------------------------

#[tokio::test]
async fn health_check_probes_without_moving_rows() {
    use dataglot_federation::health::ConnectorHealthCheck;
    let _env = env_read().await;

    let fx = Fixture::with(Metadata::GetTables).await;
    let connector = connect(&fx.uri).await;
    connector.health_check().await.expect("healthy endpoint");

    // A stopped endpoint reports unhealthy rather than hanging or panicking.
    // `stop` returns only once the listener and every connection are closed,
    // so this is a fact about the probe, not a timing race.
    fx.stop().await;
    let err = connector
        .health_check()
        .await
        .expect_err("a stopped server must fail the probe");
    assert!(
        err.contains("flightsql catalog 'flight'"),
        "the probe error names the catalog: {err}"
    );
}

#[tokio::test]
async fn an_unreachable_endpoint_fails_at_connect() {
    let _env = env_read().await;
    // Bind and immediately drop, so the port is almost certainly closed.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let err = FlightSqlConnector::connect(FlightSqlConfig::new(
        "flight",
        format!("grpc://{addr}"),
        FlightSqlDialect::DataFusion,
    ))
    .await
    .expect_err("an unreachable endpoint must fail boot");
    assert!(
        err.to_string().contains("flightsql catalog 'flight'"),
        "the error names the catalog: {err}"
    );
}

#[tokio::test]
async fn basic_credentials_reach_the_server_and_never_leak() {
    const PASSWORD_VAR: &str = "DATAGLOT_TEST_FLIGHTSQL_PASSWORD";
    let _env = env_write().await;
    let _var = EnvVar::set(PASSWORD_VAR, "hunter2");

    let fx = Fixture::with(Metadata::GetTables).await;
    let mut config = FlightSqlConfig::new("flight", &fx.uri, FlightSqlDialect::DataFusion);
    config.auth = FlightSqlAuth::Basic {
        username: "svc".to_string(),
        password_env: PASSWORD_VAR.to_string(),
    };
    let connector = Arc::new(
        FlightSqlConnector::connect(config)
            .await
            .expect("connector connects"),
    );
    let ctx = federated_ctx(&connector).await;
    ctx.sql("SELECT id FROM users")
        .await
        .expect("plans")
        .collect()
        .await
        .expect("executes");

    let seen = fx.server.seen_auth.lock().unwrap().clone();
    let seen = seen.expect("the server saw an authorization header");
    assert!(seen.starts_with("Basic "), "got: {seen}");
    // base64("svc:hunter2")
    assert_eq!(seen, "Basic c3ZjOmh1bnRlcjI=");
    // Rule 12: the credential is nowhere in the connector's Debug output.
    let rendered = format!("{connector:?}");
    assert!(!rendered.contains("hunter2"), "got: {rendered}");
    assert!(!rendered.contains("c3ZjOmh1bnRlcjI="), "got: {rendered}");
}

#[tokio::test]
async fn a_missing_credential_variable_fails_before_connecting() {
    let _env = env_read().await;
    let fx = Fixture::with(Metadata::GetTables).await;
    let mut config = FlightSqlConfig::new("flight", &fx.uri, FlightSqlDialect::DataFusion);
    config.auth = FlightSqlAuth::Basic {
        username: "svc".to_string(),
        password_env: "DATAGLOT_TEST_FLIGHTSQL_DEFINITELY_UNSET".to_string(),
    };
    let err = FlightSqlConnector::connect(config)
        .await
        .expect_err("an unset credential variable must fail");
    assert!(
        err.to_string()
            .contains("DATAGLOT_TEST_FLIGHTSQL_DEFINITELY_UNSET"),
        "the error names the variable so the operator can fix it: {err}"
    );
}

/// The advertised location is remote-supplied text. A server that reflects
/// a credential back inside an otherwise valid host component would, without
/// scrubbing, get it interpolated straight into the refusal the operator
/// reads. Rule 12: credentials never appear in an error message.
#[tokio::test]
async fn a_credential_reflected_into_an_advertised_location_is_redacted() {
    const PASSWORD_VAR: &str = "DATAGLOT_TEST_FLIGHTSQL_REFLECTED";
    let _env = env_write().await;
    // Deliberately mixed case: `Transport::parse` hands the advertised URI
    // to `url`, which lowercases the host. An exact-match scrub would walk
    // straight past the normalised copy, so this pins the case-insensitive
    // matching rather than the easy already-lowercase path.
    let _var = EnvVar::set(PASSWORD_VAR, "Hunter2");

    let fx = Fixture::start(|_| {
        let mut fixture = TestServer::new(Metadata::GetTables);
        // The password, echoed back as the host of the result location.
        fixture.advertise_location = Some("grpc://Hunter2:32010".to_string());
        fixture
    })
    .await;
    let mut config = FlightSqlConfig::new("flight", &fx.uri, FlightSqlDialect::DataFusion);
    config.auth = FlightSqlAuth::Basic {
        username: "svc".to_string(),
        password_env: PASSWORD_VAR.to_string(),
    };
    let connector = Arc::new(
        FlightSqlConnector::connect(config)
            .await
            .expect("connector connects"),
    );
    let ctx = federated_ctx(&connector).await;

    let err = ctx
        .sql("SELECT id FROM users")
        .await
        .expect("plans")
        .collect()
        .await
        .expect_err("a foreign result location must be refused");
    let msg = err.to_string();
    assert!(
        !msg.to_ascii_lowercase().contains("hunter2"),
        "the reflected credential must not reach the operator, in any casing: {msg}"
    );
    assert!(msg.contains("[redacted]"), "it is redacted in place: {msg}");
    assert!(
        msg.contains("follow_endpoint_locations"),
        "the refusal is still actionable: {msg}"
    );
}

/// A server that points results at another host would have this catalog's
/// credentials sent there. Refused by default; the error names the opt-in.
#[tokio::test]
async fn a_foreign_endpoint_location_is_refused_by_default() {
    let _env = env_read().await;
    let fx = Fixture::start(|_| {
        let mut fixture = TestServer::new(Metadata::GetTables);
        fixture.advertise_location = Some("grpc://elsewhere.invalid:32010".to_string());
        fixture
    })
    .await;
    let connector = connect(&fx.uri).await;
    let ctx = federated_ctx(&connector).await;

    let err = ctx
        .sql("SELECT id FROM users")
        .await
        .expect("plans")
        .collect()
        .await
        .expect_err("a foreign result location must be refused");
    let msg = err.to_string();
    assert!(
        msg.contains("elsewhere.invalid"),
        "names the location: {msg}"
    );
    assert!(
        msg.contains("follow_endpoint_locations"),
        "names the opt-in so the operator can allow it: {msg}"
    );
}

/// The same server advertising *its own* address is the common Dremio shape
/// and must work untouched — the policy is about foreign hosts only.
#[tokio::test]
async fn an_endpoint_location_naming_the_configured_server_is_followed() {
    let _env = env_read().await;
    let fx = Fixture::start(|uri| {
        let mut fixture = TestServer::new(Metadata::GetTables);
        // The address this server is about to listen on.
        fixture.advertise_location = Some(uri.to_string());
        fixture
    })
    .await;

    let connector = connect(&fx.uri).await;
    let ctx = federated_ctx(&connector).await;
    let batches = ctx
        .sql("SELECT id FROM users")
        .await
        .expect("plans")
        .collect()
        .await
        .expect("a self-referential location is not foreign");
    assert_eq!(batches.iter().map(RecordBatch::num_rows).sum::<usize>(), 4);
}

// ---------------------------------------------------------------------------
// Remote catalog qualification and exact schema scoping
// ---------------------------------------------------------------------------

/// With a remote catalog configured, discovery scopes to it — so execution
/// has to resolve there too. A two-part reference would let the server fall
/// back to its default catalog and read a same-named table from the wrong
/// one.
#[tokio::test]
async fn a_configured_catalog_qualifies_every_remote_reference() {
    let _env = env_read().await;
    let fx = Fixture::with(Metadata::GetTables).await;
    let mut config = FlightSqlConfig::new("flight", &fx.uri, FlightSqlDialect::DataFusion);
    config.catalog = Some("datafusion".to_string());
    let connector = Arc::new(
        FlightSqlConnector::connect(config)
            .await
            .expect("connector connects"),
    );

    // The zero-row schema probe is three-part…
    let provider = connector
        .table_provider("public", "users")
        .await
        .expect("schema resolves");
    let probes = fx.server.seen_sql.lock().unwrap().clone();
    assert!(
        probes.iter().any(|sql| sql.contains("datafusion")
            && sql.contains("public")
            && sql.contains("users")
            && sql.contains("LIMIT 0")),
        "the schema probe must name the configured catalog; server saw: {probes:#?}"
    );

    // …and so is the SQL the pushdown sends.
    let base = SessionContext::new();
    let state = SessionStateBuilder::new_from_existing(base.state())
        .with_optimizer_rules(datafusion_federation::default_optimizer_rules())
        .with_query_planner(Arc::new(datafusion_federation::FederatedQueryPlanner::new()))
        .build();
    let ctx = SessionContext::new_with_state(state);
    ctx.register_table("users", provider).expect("register");
    let batches = ctx
        .sql("SELECT id FROM users WHERE age >= 30")
        .await
        .expect("plans")
        .collect()
        .await
        .expect("executes against the catalog-qualified reference");
    assert_eq!(batches.iter().map(RecordBatch::num_rows).sum::<usize>(), 2);

    let pushed = fx.server.seen_sql.lock().unwrap().clone();
    assert!(
        pushed
            .iter()
            .any(|sql| sql.contains("datafusion") && sql.contains("WHERE")),
        "the pushed query must name the catalog too; server saw: {pushed:#?}"
    );
}

/// `db_schema_filter_pattern` is a SQL wildcard pattern, so a server may
/// return more schemas than the configured scope. The scope is enforced
/// exactly on our side, whatever the server matched — otherwise a catalog
/// scoped to one tenant quietly gains another's schemas.
#[tokio::test]
async fn a_server_that_widens_the_schema_filter_does_not_widen_the_catalog() {
    let _env = env_read().await;
    for metadata in [Metadata::GetTables, Metadata::Unimplemented] {
        let fx = Fixture::with(metadata).await;

        // Unscoped: the fixture has two schemas, and both show up.
        let unscoped = connect(&fx.uri).await;
        let all = unscoped.as_catalog_provider().await.expect("lists");
        assert!(
            all.schema_names().contains(&"ops".to_string())
                && all.schema_names().contains(&"public".to_string()),
            "precondition: the fixture serves two schemas, got {:?}",
            all.schema_names()
        );

        // Scoped: only the configured one, even though this fixture's
        // GetTables ignores the filter pattern entirely.
        let mut config = FlightSqlConfig::new("flight", &fx.uri, FlightSqlDialect::DataFusion);
        config.schema = Some("public".to_string());
        let scoped = Arc::new(
            FlightSqlConnector::connect(config)
                .await
                .expect("connector connects"),
        );
        let catalog = scoped.as_catalog_provider().await.expect("lists");
        assert_eq!(
            catalog.schema_names(),
            vec!["public".to_string()],
            "the configured scope is exact ({metadata:?} path)"
        );
    }
}

/// `FlightSqlAuth::Bearer` is a public configuration option, so it carries
/// the same obligations as Basic: the header must actually reach the server,
/// and the token must not be renderable (rule 12 / rule 14).
#[tokio::test]
async fn bearer_credentials_reach_the_server_and_never_leak() {
    const TOKEN_VAR: &str = "DATAGLOT_TEST_FLIGHTSQL_TOKEN";
    let _env = env_write().await;
    let _var = EnvVar::set(TOKEN_VAR, "t0ken-abc");

    let fx = Fixture::with(Metadata::GetTables).await;
    let mut config = FlightSqlConfig::new("flight", &fx.uri, FlightSqlDialect::DataFusion);
    config.auth = FlightSqlAuth::Bearer {
        token_env: TOKEN_VAR.to_string(),
    };
    let connector = Arc::new(
        FlightSqlConnector::connect(config)
            .await
            .expect("connector connects"),
    );
    let ctx = federated_ctx(&connector).await;
    ctx.sql("SELECT id FROM users")
        .await
        .expect("plans")
        .collect()
        .await
        .expect("executes");

    let seen = fx.server.seen_auth.lock().unwrap().clone();
    let seen = seen.expect("the server saw an authorization header");
    assert_eq!(seen, "Bearer t0ken-abc");
    let rendered = format!("{connector:?}");
    assert!(!rendered.contains("t0ken-abc"), "got: {rendered}");
}

/// An unset token variable is named at connect, before any RPC — the same
/// contract as the Basic path.
#[tokio::test]
async fn a_missing_bearer_token_variable_fails_before_connecting() {
    let _env = env_read().await;
    let fx = Fixture::with(Metadata::GetTables).await;
    let mut config = FlightSqlConfig::new("flight", &fx.uri, FlightSqlDialect::DataFusion);
    config.auth = FlightSqlAuth::Bearer {
        token_env: "DATAGLOT_TEST_FLIGHTSQL_TOKEN_DEFINITELY_UNSET".to_string(),
    };
    let err = FlightSqlConnector::connect(config)
        .await
        .expect_err("an unset token variable must fail");
    assert!(
        err.to_string()
            .contains("DATAGLOT_TEST_FLIGHTSQL_TOKEN_DEFINITELY_UNSET"),
        "the error names the variable: {err}"
    );
}

/// The `follow_endpoint_locations` opt-in had no test at all: the suite
/// covered refusal and same-channel routing only, so the whole opted-in
/// path — dialling a second server, applying *its* transport, carrying the
/// credentials over, redeeming its ticket — could have regressed silently.
///
/// Two servers: the **planner** advertises the **holder**'s address on every
/// endpoint, so the planner sees `GetFlightInfo` and the holder serves the
/// `DoGet`. Asserting which server saw which RPC is what proves the hop
/// actually happened rather than being quietly served locally.
#[tokio::test]
async fn an_opted_in_foreign_location_is_dialled_and_its_ticket_redeemed() {
    let _env = env_read().await;
    let holder = Fixture::with(Metadata::GetTables).await;
    let planner = Fixture::start({
        let holder_uri = holder.uri.clone();
        move |_| {
            let mut fixture = TestServer::new(Metadata::GetTables);
            fixture.advertise_location = Some(holder_uri);
            fixture
        }
    })
    .await;

    let mut config = FlightSqlConfig::new("flight", &planner.uri, FlightSqlDialect::DataFusion);
    config.follow_endpoint_locations = true;
    let connector = Arc::new(
        FlightSqlConnector::connect(config)
            .await
            .expect("connector connects"),
    );
    let ctx = federated_ctx(&connector).await;
    let batches = ctx
        .sql("SELECT id FROM users")
        .await
        .expect("plans")
        .collect()
        .await
        .expect("the foreign location is followed and its ticket redeemed");
    assert_eq!(batches.iter().map(RecordBatch::num_rows).sum::<usize>(), 4);

    // The planner was asked to plan…
    let statements = planner.server.seen_sql.lock().unwrap().clone();
    assert!(
        statements.iter().any(|sql| sql.contains("users")),
        "the planner should have seen the statement: {statements:#?}"
    );
    // …and the holder served the data, which is the hop.
    let tickets = |f: &Fixture| {
        f.server
            .served_tickets
            .load(std::sync::atomic::Ordering::SeqCst)
    };
    assert!(
        tickets(&holder) > 0,
        "the holder must have served the ticket — that is the hop"
    );
    assert_eq!(
        tickets(&planner),
        0,
        "the planner must NOT have served it; if it did, the location was ignored"
    );
}

/// The same topology with the opt-in **off** is refused rather than quietly
/// served — the default that makes the flag safe to have.
#[tokio::test]
async fn the_same_topology_is_refused_without_the_opt_in() {
    let _env = env_read().await;
    let holder = Fixture::with(Metadata::GetTables).await;
    let planner = Fixture::start({
        let holder_uri = holder.uri.clone();
        move |_| {
            let mut fixture = TestServer::new(Metadata::GetTables);
            fixture.advertise_location = Some(holder_uri);
            fixture
        }
    })
    .await;

    let connector = connect(&planner.uri).await;
    let ctx = federated_ctx(&connector).await;
    let err = ctx
        .sql("SELECT id FROM users")
        .await
        .expect("plans")
        .collect()
        .await
        .expect_err("a foreign location must be refused by default");
    assert!(
        err.to_string().contains("follow_endpoint_locations"),
        "the refusal names the opt-in: {err}"
    );
}

/// Without a configured catalog, references stay **two-part** and the
/// server resolves them against its own default. That is a deliberate
/// limitation, not an oversight: nothing on the wire identifies the default
/// catalog, and an earlier attempt to infer it from discovery produced five
/// rounds of silent wrong-catalog hazards. An operator whose tables are not
/// in the default catalog sets `catalog`, and gets a clear remote error
/// until they do.
#[tokio::test]
async fn references_stay_two_part_until_a_catalog_is_configured() {
    let _env = env_read().await;
    let fx = Fixture::with(Metadata::GetTables).await;
    let connector = connect(&fx.uri).await;

    let catalog = connector.as_catalog_provider().await.expect("lists");
    let schema = catalog.schema("public").expect("public schema resolves");
    schema
        .table("users")
        .await
        .expect("table resolves")
        .expect("users is listed");

    let probes = fx.server.seen_sql.lock().unwrap().clone();
    let probe = probes
        .iter()
        .find(|sql| sql.contains("LIMIT 0"))
        .expect("a schema probe was sent");
    assert!(
        !probe.contains("datafusion"),
        "an unconfigured catalog stays out of the reference: {probe}"
    );
    assert!(probe.contains("users"), "{probe}");
}

//! Arrow Flight SQL egress ( · Phase 4 · `flight_sql` feature).
//!
//! A second query surface alongside pg-wire, on `[flight_sql] addr`
//! (default `:32010`), for native-Arrow clients (Python/R/Go/Rust ADBC).
//! Arrow in the engine, Arrow on the wire — no serialization boundary
//! (rule 1). Every query runs through [`DataglotServer::create_session`],
//! so the same catalogs and plan-time policy enforcement apply as on
//! pg-wire (rule 6); parity is by construction, not by duplicated logic.
//!
//! Slice 1: `get_flight_info_statement` + `do_get_statement`, i.e. plan →
//! advertise schema → execute → stream.
//!
//! Slice 2: identity → policy parity + TLS. Each RPC resolves an
//! [`Identity`](dataglot_policy::Identity) from its `authorization: Basic`
//! metadata via [`DataglotServer::authenticate_flight`] and runs the
//! plan+execute inside [`dataglot_policy::with_session_identity`], so the same
//! masks/row-filters the identity sees on pg-wire apply here — and under md5
//! auth the Basic password is verified against the same credential source, so
//! Flight is never a weaker door. TLS terminates on the listener when
//! `[flight_sql].tls` is set (see [`serve`]). A missing/anonymous identity is
//! the behaviour-neutral default, exactly as an unauthenticated pg-wire session.

use std::sync::Arc;

use arrow_flight::encode::FlightDataEncoderBuilder;
use arrow_flight::error::FlightError;
use arrow_flight::flight_service_server::{FlightService, FlightServiceServer};
use arrow_flight::sql::server::FlightSqlService;
use arrow_flight::sql::{Any, CommandStatementQuery, SqlInfo, TicketStatementQuery};
use arrow_flight::{FlightDescriptor, FlightEndpoint, FlightInfo, Ticket};
use datafusion::error::DataFusionError;
use datafusion::prelude::SessionContext;
use futures::TryStreamExt;
use prost::Message as _;
use tonic::{Request, Response, Status};

use crate::server::{DataglotServer, FlightAuth};

/// Flight SQL service backed by the shared [`DataglotServer`]. Holds only
/// an `Arc` to the server, so each RPC builds a fresh governed session via
/// `create_session()` — the identical path the pg-wire handler uses.
pub(crate) struct DataglotFlightSqlService {
    server: Arc<DataglotServer>,
}

impl DataglotFlightSqlService {
    fn new(server: Arc<DataglotServer>) -> Self {
        Self { server }
    }

    /// A governed session for one request: installs the policy optimizer
    /// rule and registers catalogs, exactly like the pg-wire path.
    fn session(&self) -> SessionContext {
        self.server.create_session()
    }

    /// Resolve the governed [`Identity`](dataglot_policy::Identity) for a
    /// request from its `authorization` metadata (slice 2). Extracted per RPC
    /// — the ticket carries only SQL, so `do_get_statement` re-derives identity
    /// from its own metadata, exactly like `get_flight_info_statement`. Delegates
    /// to [`DataglotServer::authenticate_flight`] so auth policy (trust vs md5)
    /// lives in one place shared with pg-wire. Auth failures map to gRPC
    /// `UNAUTHENTICATED`.
    async fn identity_for<T>(
        &self,
        request: &Request<T>,
    ) -> Result<dataglot_policy::Identity, Status> {
        let header = request
            .metadata()
            .get("authorization")
            .and_then(|v| v.to_str().ok());
        match self.server.authenticate_flight(header).await {
            FlightAuth::Ok(identity) => Ok(identity),
            FlightAuth::Unauthenticated(msg) | FlightAuth::BadHeader(msg) => {
                Err(Status::unauthenticated(msg))
            }
        }
    }
}

/// Map a planning/execution error to a gRPC status.
///
/// Rule 12: DataFusion planning errors carry table/column identifiers but
/// never credentials or DSNs (federation surfaces sources by catalog name,
/// not connection string), so the message is safe to return verbatim.
fn planning_status(e: &DataFusionError) -> Status {
    Status::invalid_argument(format!("query planning failed: {e}"))
}

#[tonic::async_trait]
impl FlightSqlService for DataglotFlightSqlService {
    // Per the trait's own guidance ("you can always set FlightService to
    // Self"): the `FlightServiceServer` wrapper provides the transport impl.
    type FlightService = DataglotFlightSqlService;

    async fn get_flight_info_statement(
        &self,
        query: CommandStatementQuery,
        request: Request<FlightDescriptor>,
    ) -> Result<Response<FlightInfo>, Status> {
        // Identity → policy parity (slice 2): resolve the request's identity and
        // plan under it, so the advertised schema reflects the SAME masks the
        // same identity sees on pg-wire.
        let identity = self.identity_for(&request).await?;
        let sql = query.query;
        // Plan (not execute) to resolve the result schema. The policy
        // rewrite runs here, so the advertised schema already reflects any
        // projection the masks/row-filters imply.
        let schema = dataglot_policy::with_session_identity(identity, async {
            let df = self
                .session()
                .sql(&sql)
                .await
                .map_err(|e| planning_status(&e))?;
            Ok::<_, Status>(df.schema().as_arrow().clone())
        })
        .await?;

        // Embed the SQL in the ticket — `do_get_statement` re-plans and
        // executes it. Simple and stateless; a server-side handle (to skip
        // the re-plan) is a documented follow-up if re-plan cost matters.
        let ticket_cmd = TicketStatementQuery {
            statement_handle: sql.into_bytes().into(),
        };
        let ticket = Ticket::new(
            Any::pack(&ticket_cmd)
                .map_err(|e| Status::internal(format!("ticket encode failed: {e}")))?
                .encode_to_vec(),
        );

        let endpoint = FlightEndpoint::new().with_ticket(ticket);
        let info = FlightInfo::new()
            .try_with_schema(&schema)
            .map_err(|e| Status::internal(format!("schema encode failed: {e}")))?
            .with_endpoint(endpoint)
            .with_descriptor(request.into_inner());
        Ok(Response::new(info))
    }

    async fn do_get_statement(
        &self,
        ticket: TicketStatementQuery,
        request: Request<Ticket>,
    ) -> Result<Response<<Self as FlightService>::DoGetStream>, Status> {
        // Re-derive identity from THIS request's metadata (the ticket carries
        // only SQL) and plan+execute under it — same governed result the same
        // identity gets on pg-wire.
        let identity = self.identity_for(&request).await?;
        let sql = String::from_utf8(ticket.statement_handle.to_vec())
            .map_err(|_| Status::invalid_argument("statement_handle is not valid UTF-8 SQL"))?;
        let batches = dataglot_policy::with_session_identity(identity, async {
            let df = self
                .session()
                .sql(&sql)
                .await
                .map_err(|e| planning_status(&e))?;
            df.execute_stream().await.map_err(|e| planning_status(&e))
        })
        .await?;

        // Arrow-native egress: encode `RecordBatch`es straight to
        // `FlightData` — no intermediate row conversion (rule 1).
        let stream = FlightDataEncoderBuilder::new()
            .build(batches.map_err(|e| FlightError::ExternalError(Box::new(e))))
            .map_err(Status::from);
        let boxed: <Self as FlightService>::DoGetStream = Box::pin(stream);
        Ok(Response::new(boxed))
    }

    // Required by the trait. We advertise no SQL-info metadata yet; ADBC
    // connects without it. Metadata RPCs are a client-pull follow-up.
    async fn register_sql_info(&self, _id: i32, _result: &SqlInfo) {}
}

/// The tonic gRPC service for the Flight SQL listener, ready to hand to
/// `Server::builder().add_service(..)`.
fn flight_sql_service(
    server: Arc<DataglotServer>,
) -> FlightServiceServer<DataglotFlightSqlService> {
    FlightServiceServer::new(DataglotFlightSqlService::new(server))
}

/// Spawn the Flight SQL gRPC server on an already-bound listener, draining
/// on the shared `shutdown_tx` broadcast (mirrors the metrics/webhook
/// sibling tasks). The listener is bound up front in `run()` so an
/// addr-in-use error fails fast before any task is spawned.
///
/// When `[flight_sql].tls` is set, terminates TLS on the listener via
/// `tonic::transport::ServerTlsConfig` on the ring provider (the same crypto
/// backend `[pgwire_tls]` /  uses) — so the native-Arrow egress is
/// encrypted end to end just like the pg-wire one. The cert/key are read here
/// so a bad path/PEM fails boot (this returns `Err`) rather than a listener
/// that dies on first connect.
///
/// # Errors
/// Returns an error if `[flight_sql].tls` names an unreadable cert/key file or
/// tonic rejects the TLS configuration.
pub(crate) fn serve(
    server: Arc<DataglotServer>,
    listener: tokio::net::TcpListener,
) -> anyhow::Result<tokio::task::JoinHandle<()>> {
    let mut shutdown = server.shutdown_receiver();

    let mut builder = tonic::transport::Server::builder();
    if let Some(tls) = server.flight_sql_tls() {
        let cert = std::fs::read(&tls.cert_file).map_err(|e| {
            anyhow::anyhow!(
                "reading [flight_sql].tls cert_file {}: {e}",
                tls.cert_file.display()
            )
        })?;
        let key = std::fs::read(&tls.key_file).map_err(|e| {
            anyhow::anyhow!(
                "reading [flight_sql].tls key_file {}: {e}",
                tls.key_file.display()
            )
        })?;
        let tls_config = tonic::transport::ServerTlsConfig::new()
            .identity(tonic::transport::Identity::from_pem(cert, key));
        builder = builder
            .tls_config(tls_config)
            .map_err(|e| anyhow::anyhow!("[flight_sql].tls configuration failed: {e}"))?;
        tracing::info!("Flight SQL listener: TLS enabled");
    }

    let svc = flight_sql_service(server);
    let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
    Ok(tokio::spawn(async move {
        let result = builder
            .add_service(svc)
            .serve_with_incoming_shutdown(incoming, async move {
                let _ = shutdown.recv().await;
            })
            .await;
        if let Err(e) = result {
            tracing::error!(error = %e, "Flight SQL server terminated with error");
        }
    }))
}

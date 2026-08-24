//! `OpenLineage` HTTP emitter — slice 2 of the Phase 1 lineage MVP.
//!
//! Implements [`dataglot_core::LineageEmitter`] by `POST`-ing
//! `OpenLineage` `RunEvent` JSON to a configured HTTP endpoint
//! (Marquez, `DataHub`, `OpenMetadata`, Informatica — all four
//! accept the standard schema as an intake).
//!
//! Spec: `docs/phases/phase-1/06-openlineage-emitter.md`.
//!
//! # Failure-isolation contract
//!
//! Every public method here returns `()`. HTTP failures (5xx,
//! 4xx, connection refused, DNS failure, body-write error) are
//! captured, logged at `WARN` with the `run_id` + endpoint, and
//! dropped. Queries never fail because lineage emission failed.
//! See the spec's "Lineage emission MUST NOT propagate failures"
//! exit criterion.
//!
//! # Pinned `OpenLineage` schema version
//!
//! Events carry `schemaURL = "https://openlineage.io/spec/2-0-2/OpenLineage.json"`.
//! Older Marquez / `DataHub` deployments may reject this version — surface
//! the pin in the operator-facing connector doc when this slice ships
//! to customers.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use chrono::{DateTime, SecondsFormat, Utc};
use datafusion::common::TableReference;
use datafusion::logical_expr::LogicalPlan;
use datafusion::prelude::SessionContext;
use dataglot_core::lineage::{
    column_lineage, extract_inputs, ColumnLineage, DatasetRef, DynLineageEmitter, FieldRef,
    Identity, LineageEmitter, QueryFinishContext, QueryOutcome, QueryStartContext, RunId,
    TransformationType,
};
use reqwest::Url;
use serde_json::{json, Value};

/// `OpenLineage` `schemaURL` value baked into every emitted event.
const OPENLINEAGE_SCHEMA_URL: &str = "https://openlineage.io/spec/2-0-2/OpenLineage.json";

/// `OpenLineage` `producer` URI — identifies Dataglot as the
/// source of the event. Matches the workspace `repository`
/// field on `Cargo.toml`.
const OPENLINEAGE_PRODUCER: &str = "https://github.com/dataglotai/dataglot";

/// Maximum length of the truncated SQL string used as the
/// `OpenLineage` `job.name`. Per the spec's "Open questions"
/// section, we ship the (a) variant — truncated SQL — for the
/// MVP and revisit if operators report job-cardinality issues.
const JOB_NAME_MAX_LEN: usize = 128;

/// HTTP-based `OpenLineage` emitter.
///
/// Holds a `reqwest::Client` (which itself owns a connection
/// pool — clone is cheap and the client should be shared
/// across queries) plus the configured endpoint and namespace.
///
/// # Example
///
/// ```no_run
/// use dataglot_server::lineage::OpenLineageHttpEmitter;
/// # async fn demo() -> anyhow::Result<()> {
/// let emitter = OpenLineageHttpEmitter::new(
///     "http://marquez:5000/api/v1/lineage",
///     "dataglot.acme".to_string(),
/// )?;
/// # let _ = emitter;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct OpenLineageHttpEmitter {
    client: reqwest::Client,
    endpoint: Url,
    namespace: String,
}

impl OpenLineageHttpEmitter {
    /// Construct an emitter targeting the given endpoint.
    ///
    /// The endpoint must parse as a valid URL — no live
    /// reachability check is performed (a backend that's down
    /// at boot can be up by the first emit, and vice versa).
    /// The first emit failure surfaces in the WARN log.
    ///
    /// # Errors
    /// Returns an error if `endpoint` is not a valid URL.
    pub fn new(endpoint: &str, namespace: String) -> anyhow::Result<Self> {
        let endpoint = Url::parse(endpoint)
            .map_err(|e| anyhow::anyhow!("invalid lineage endpoint URL {endpoint:?}: {e}"))?;
        let client = reqwest::Client::builder()
            // Generous default. The emitter is observability
            // surface; we don't want it eating query latency
            // on a slow backend, but we also don't want it
            // timing out during a normal slow event ingest.
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|e| anyhow::anyhow!("failed to build reqwest client: {e}"))?;
        Ok(Self {
            client,
            endpoint,
            namespace,
        })
    }

    /// Construct with a caller-supplied `reqwest::Client`.
    ///
    /// Useful for tests that need a tuned client (short
    /// timeouts, custom roots) and for callers that want to
    /// share one client across multiple emitters.
    ///
    /// # Errors
    /// Returns an error if `endpoint` is not a valid URL.
    pub fn with_client(
        endpoint: &str,
        namespace: String,
        client: reqwest::Client,
    ) -> anyhow::Result<Self> {
        let endpoint = Url::parse(endpoint)
            .map_err(|e| anyhow::anyhow!("invalid lineage endpoint URL {endpoint:?}: {e}"))?;
        Ok(Self {
            client,
            endpoint,
            namespace,
        })
    }

    /// Configured `OpenLineage` `job.namespace` value.
    #[must_use]
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// Configured HTTP endpoint.
    #[must_use]
    pub fn endpoint(&self) -> &Url {
        &self.endpoint
    }

    async fn post(&self, run_id: dataglot_core::RunId, body: &Value) {
        match self
            .client
            .post(self.endpoint.clone())
            .json(body)
            .send()
            .await
        {
            Ok(resp) => {
                let status = resp.status();
                if !status.is_success() {
                    tracing::warn!(
                        %run_id,
                        endpoint = %self.endpoint,
                        %status,
                        "OpenLineage backend rejected event"
                    );
                }
            }
            Err(err) => {
                tracing::warn!(
                    %run_id,
                    endpoint = %self.endpoint,
                    error = %err,
                    "OpenLineage HTTP POST failed; event dropped"
                );
            }
        }
    }
}

#[async_trait::async_trait]
impl LineageEmitter for OpenLineageHttpEmitter {
    async fn on_query_start(&self, ctx: &QueryStartContext<'_>) {
        let body = build_start_event(&self.namespace, ctx);
        self.post(ctx.run_id, &body).await;
    }

    async fn on_query_finish(&self, ctx: &QueryFinishContext<'_>) {
        let body = build_finish_event(&self.namespace, ctx);
        self.post(ctx.run_id, &body).await;
    }
}

/// Build the `OpenLineage` `START` event payload. Pulled
/// out of the trait impl so the JSON shape is unit-testable
/// without booting an HTTP server.
fn build_start_event(namespace: &str, ctx: &QueryStartContext<'_>) -> Value {
    let event_time = system_time_to_rfc3339(ctx.started_at);
    let job_name = truncate_sql_for_job_name(ctx.sql);

    let mut run_facets = serde_json::Map::new();
    run_facets.insert(
        "nominalTime".into(),
        json!({
            "_producer": OPENLINEAGE_PRODUCER,
            "_schemaURL": OPENLINEAGE_SCHEMA_URL,
            "nominalStartTime": event_time,
        }),
    );
    if let Some(facet) = identity_facet(ctx.identity) {
        run_facets.insert("dataglot_identity".into(), facet);
    }

    json!({
        "eventType": "START",
        "eventTime": event_time,
        "producer": OPENLINEAGE_PRODUCER,
        "schemaURL": OPENLINEAGE_SCHEMA_URL,
        "run": {
            "runId": ctx.run_id.to_string(),
            "facets": Value::Object(run_facets),
        },
        "job": {
            "namespace": namespace,
            "name": job_name,
        },
        "inputs": [],
        "outputs": [],
    })
}

/// Build the `OpenLineage` `COMPLETE` (success) or `FAIL`
/// (error) event payload.
fn build_finish_event(namespace: &str, ctx: &QueryFinishContext<'_>) -> Value {
    let event_time = system_time_to_rfc3339(ctx.finished_at);
    let event_type = match ctx.outcome {
        QueryOutcome::Success => "COMPLETE",
        QueryOutcome::Error => "FAIL",
    };

    let mut run_facets = serde_json::Map::new();
    if matches!(ctx.outcome, QueryOutcome::Error) {
        let message = ctx.error_message.unwrap_or("query failed").to_string();
        run_facets.insert(
            "errorMessage".into(),
            json!({
                "_producer": OPENLINEAGE_PRODUCER,
                "_schemaURL": OPENLINEAGE_SCHEMA_URL,
                "message": message,
                "programmingLanguage": "rust",
            }),
        );
    }

    let inputs: Vec<Value> = ctx
        .input_datasets
        .iter()
        .map(|d| {
            json!({
                "namespace": namespace,
                "name": format!("{}.{}.{}", d.catalog, d.schema, d.table),
            })
        })
        .collect();

    // Column-level lineage rides on an *output* dataset facet
    // (OpenLineage attaches `columnLineage` to the output). For an
    // ad-hoc query the output is the result set — modelled as a
    // synthetic dataset named by run id. Only emitted on success,
    // and only when at least one output column has known
    // provenance (skip pure-literal / no-input queries).
    let outputs: Vec<Value> = match ctx.column_lineage {
        Some(cl)
            if matches!(ctx.outcome, QueryOutcome::Success) && column_lineage_has_inputs(cl) =>
        {
            vec![json!({
                "namespace": namespace,
                "name": format!("run:{}", ctx.run_id),
                "facets": { "columnLineage": column_lineage_facet(namespace, cl) },
            })]
        }
        _ => Vec::new(),
    };

    // job.name on the finish event must match the start
    // event's so consumers correlate; for the MVP that means
    // we can't reproduce the truncated SQL here (we don't
    // carry it on QueryFinishContext). Operators correlate
    // by run.runId instead — the canonical OpenLineage
    // contract. We still emit a job block because the schema
    // requires it; use a stable placeholder.
    json!({
        "eventType": event_type,
        "eventTime": event_time,
        "producer": OPENLINEAGE_PRODUCER,
        "schemaURL": OPENLINEAGE_SCHEMA_URL,
        "run": {
            "runId": ctx.run_id.to_string(),
            "facets": Value::Object(run_facets),
        },
        "job": {
            "namespace": namespace,
            "name": format!("run:{}", ctx.run_id),
        },
        "inputs": inputs,
        "outputs": outputs,
    })
}

/// True if any output column has at least one source contribution
/// — i.e. there is genuine column lineage worth emitting. Skips
/// pure-literal projections (`SELECT 1`) whose facet would be empty.
fn column_lineage_has_inputs(cl: &ColumnLineage) -> bool {
    cl.fields.iter().any(|f| !f.inputs.is_empty())
}

/// Render a [`ColumnLineage`] as an `OpenLineage` `columnLineage`
/// dataset facet. Each output column maps to its contributing
/// input fields, each carrying a `transformations` entry with the
/// `type`/`subtype` and the `masking` flag the emitter overlaid.
///
/// Mapping: every transformation is `DIRECT` (the value derives
/// from the input field); the subtype is `IDENTITY` /
/// `TRANSFORMATION` / `AGGREGATION` per
/// [`TransformationType`].
fn column_lineage_facet(namespace: &str, cl: &ColumnLineage) -> Value {
    let mut fields = serde_json::Map::new();
    for ofl in &cl.fields {
        if ofl.inputs.is_empty() {
            continue;
        }
        let input_fields: Vec<Value> = ofl
            .inputs
            .iter()
            .map(|c| {
                let subtype = match c.transform {
                    TransformationType::Identity => "IDENTITY",
                    TransformationType::Transformation => "TRANSFORMATION",
                    TransformationType::Aggregation => "AGGREGATION",
                };
                json!({
                    "namespace": namespace,
                    "name": format!(
                        "{}.{}.{}",
                        c.field.dataset.catalog, c.field.dataset.schema, c.field.dataset.table
                    ),
                    "field": c.field.field,
                    "transformations": [{
                        "type": "DIRECT",
                        "subtype": subtype,
                        "masking": c.masking,
                    }],
                })
            })
            .collect();
        fields.insert(
            ofl.output_field.clone(),
            json!({ "inputFields": input_fields }),
        );
    }
    json!({
        "_producer": OPENLINEAGE_PRODUCER,
        "_schemaURL": OPENLINEAGE_SCHEMA_URL,
        "fields": Value::Object(fields),
    })
}

/// Render the Dataglot identity as a custom run facet.
/// Returns `None` if every field is empty so the facet doesn't
/// pollute payloads on unauthenticated sessions.
fn identity_facet(identity: &Identity) -> Option<Value> {
    if identity.user.is_none() && identity.org.is_none() && identity.org_groups.is_empty() {
        return None;
    }
    Some(json!({
        "_producer": OPENLINEAGE_PRODUCER,
        "_schemaURL": OPENLINEAGE_SCHEMA_URL,
        "user": identity.user,
        "org": identity.org,
        "orgGroups": identity.org_groups,
    }))
}

fn system_time_to_rfc3339(t: SystemTime) -> String {
    let dt: DateTime<Utc> = t.into();
    dt.to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn truncate_sql_for_job_name(sql: &str) -> String {
    let trimmed = sql.trim();
    if trimmed.len() <= JOB_NAME_MAX_LEN {
        return trimmed.to_string();
    }
    // Truncate on a char boundary, not a byte boundary, so
    // multi-byte UTF-8 (e.g. column comments in Cyrillic /
    // CJK SQL strings) doesn't panic.
    let mut end = JOB_NAME_MAX_LEN;
    while !trimmed.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &trimmed[..end])
}

/// The set of configured column masks, used to overlay the
/// `masking` flag onto computed column lineage.
///
/// The structural analyzer in `dataglot-core` is policy-blind
/// (rule 4) — it sees a masked column as an ordinary lineage
/// edge. This type carries the policy knowledge the analyzer
/// lacks: given the configured `(table, column)` masks, it marks
/// the matching source-field contributions as `masking: true`
/// (and bumps their transform to at least `Transformation`, since
/// a mask *is* a value transformation).
///
/// Matching mirrors the policy enforcer
/// ([`dataglot_policy::ColumnMaskingEnforcer`]) so the emitted
/// `masking` flag never disagrees with what enforcement actually
/// did:
/// - **Qualifier leniency** — a mask whose table reference omits
///   the schema/catalog matches any field with that table +
///   column name (a bare `users` mask matches `pg.public.users`),
///   exactly like the enforcer's `match_candidates` chain.
/// - **Case-sensitive** — the enforcer keys a `HashMap` on the
///   raw `(table, column)` config strings, and `DataFusion` folds
///   unquoted identifiers to lowercase, so a mis-cased mask
///   (`"EMAIL"`) does **not** enforce. Matching case-insensitively
///   here would flag `masking: true` on a column the enforcer left
///   untouched — the facet would lie. Case-sensitivity keeps the
///   flag honest.
#[derive(Debug, Default)]
pub struct MaskedColumns {
    /// Parsed `(table reference, column name)` pairs.
    entries: Vec<(TableReference, String)>,
}

impl MaskedColumns {
    /// Build from `(table, column)` string pairs — typically the
    /// server's `config.masks`. The table string is parsed as a
    /// `TableReference` (bare / partial / full).
    #[must_use]
    pub fn new<'a>(masks: impl IntoIterator<Item = (&'a str, &'a str)>) -> Self {
        let entries = masks
            .into_iter()
            .map(|(table, column)| (TableReference::parse_str(table), column.to_string()))
            .collect();
        Self { entries }
    }

    /// Whether `field` is targeted by any configured mask.
    #[must_use]
    pub fn is_masked(&self, field: &FieldRef) -> bool {
        self.entries.iter().any(|(tr, col)| {
            *col == field.field
                && tr.table() == field.dataset.table
                && tr.schema().is_none_or(|s| s == field.dataset.schema)
                && tr.catalog().is_none_or(|c| c == field.dataset.catalog)
        })
    }

    /// Overlay the `masking` flag onto every contribution whose
    /// source field is masked, bumping its transform to at least
    /// `Transformation`.
    fn overlay(&self, cl: &mut ColumnLineage) {
        if self.entries.is_empty() {
            return;
        }
        for ofl in &mut cl.fields {
            for c in &mut ofl.inputs {
                if self.is_masked(&c.field) {
                    c.masking = true;
                    c.transform = c.transform.combine(TransformationType::Transformation);
                }
            }
        }
    }
}

/// Bridges the synchronous pgwire [`dataglot_pgwire::QueryObserver`]
/// trait to the async [`LineageEmitter`] trait.
///
/// One `LineageObserver` instance lives per pgwire connection and
/// holds:
/// - an `Arc<dyn LineageEmitter>` (typically the
///   [`OpenLineageHttpEmitter`]) shared across all connections — the
///   emitter itself is `Send + Sync + 'static`;
/// - an `Arc<SessionContext>` scoped to *this* connection, used to
///   plan the SQL on `on_query_complete` and extract input datasets
///   via [`extract_inputs`].
///
/// Lineage emission fires on tokio tasks the observer spawns. The
/// trait is sync because pgwire calls it inline on the connection
/// task; if we blocked there for an HTTP POST, the wire would
/// back-pressure. Spawning a task means the emission cost is paid
/// off the connection's hot path — at the cost of one
/// `tokio::spawn` per query. The failure-isolation contract on
/// `LineageEmitter` (everything returns `()`, errors are logged +
/// dropped) means a panic in the spawned task is bounded to that
/// task; the connection survives.
///
/// # Identity propagation
///
/// `dataglot_policy::current_session_identity()` reads the
/// connection's task-local identity. That call has to happen on
/// the connection task, not on the spawned emission task — tokio
/// task-locals don't propagate across `spawn`. We snapshot the
/// identity in `on_query_start` / `on_query_complete` and move the
/// cloned value into the spawned future.
#[derive(Clone)]
pub struct LineageObserver {
    emitter: DynLineageEmitter,
    session_ctx: Arc<SessionContext>,
    /// Configured column masks, used to overlay the `masking`
    /// flag onto computed column lineage. Shared across
    /// connections (built once at server boot).
    masked_columns: Arc<MaskedColumns>,
}

impl std::fmt::Debug for LineageObserver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LineageObserver")
            .field("emitter", &"<dyn LineageEmitter>")
            .field("session_ctx", &"<SessionContext>")
            .finish()
    }
}

impl LineageObserver {
    /// Build a new observer wrapping the given emitter and binding
    /// to the connection's session context for input-dataset and
    /// column-lineage extraction. `masked_columns` is the set of
    /// configured column masks used to overlay the `masking` flag
    /// on emitted column lineage (empty ⇒ no masking overlaid).
    #[must_use]
    pub fn new(
        emitter: DynLineageEmitter,
        session_ctx: Arc<SessionContext>,
        masked_columns: Arc<MaskedColumns>,
    ) -> Self {
        Self {
            emitter,
            session_ctx,
            masked_columns,
        }
    }

    /// Snapshot the current task-local identity from
    /// `dataglot_policy` and convert into the `dataglot_core`
    /// representation. Identity types are duplicated across crates
    /// because `dataglot-core` cannot depend on `dataglot-policy`
    /// (CLAUDE.md rule 4); this is the conversion seam.
    fn snapshot_identity() -> Identity {
        let policy_id = dataglot_policy::current_session_identity().unwrap_or_default();
        Identity {
            user: policy_id.user,
            org: policy_id.org,
            org_groups: policy_id.org_groups,
        }
    }
}

impl dataglot_pgwire::QueryObserver for LineageObserver {
    fn on_query_start(&self, run_id: RunId, query: &str) {
        let emitter = Arc::clone(&self.emitter);
        let sql = query.to_string();
        let identity = Self::snapshot_identity();
        let started_at = SystemTime::now();
        // Spawn off-thread so the HTTP POST doesn't block the
        // connection's read loop. The emitter's failure-isolation
        // contract keeps any backend outage off the query path.
        tokio::spawn(async move {
            let ctx = QueryStartContext {
                run_id,
                sql: &sql,
                identity: &identity,
                started_at,
            };
            emitter.on_query_start(&ctx).await;
        });
    }

    // Wants the executed plan so it can extract lineage without
    // re-planning — the handler captures it pre-execution.
    fn wants_plan(&self) -> bool {
        true
    }

    fn on_query_complete(
        &self,
        run_id: RunId,
        query: &str,
        plan: Option<Arc<LogicalPlan>>,
        outcome: dataglot_pgwire::QueryOutcome,
        _duration: Duration,
    ) {
        let emitter = Arc::clone(&self.emitter);
        let session_ctx = Arc::clone(&self.session_ctx);
        let masked = Arc::clone(&self.masked_columns);
        let sql = query.to_string();
        let _identity = Self::snapshot_identity();
        let finished_at = SystemTime::now();
        let core_outcome = match outcome {
            dataglot_pgwire::QueryOutcome::Success => QueryOutcome::Success,
            dataglot_pgwire::QueryOutcome::Error => QueryOutcome::Error,
        };

        tokio::spawn(async move {
            // Extract input datasets + column-level lineage from the plan.
            //
            //: prefer the **executed** plan captured pre-execution
            // by the pgwire handler — this is correct for `CREATE TABLE t
            // AS …`, where re-planning the SQL here would fail because `t`
            // now exists (silently emptying lineage for the very case where
            // output-dataset lineage matters most). Only when the handler
            // couldn't supply a plan (e.g. the extended path had no parsed
            // plan) do we fall back to re-planning the SQL string.
            //
            // Lineage is computed on the *unoptimized* plan so a
            // column-masking rewrite (which can replace a column with a
            // literal, erasing its source reference) doesn't sever the
            // lineage edge; masking is then overlaid from the configured
            // masks (`masked`), tracing back to the true source column.
            // The handler captures `create_logical_plan` output, which is
            // unoptimized — the property this relies on.
            let extract = |plan: &LogicalPlan| -> (Vec<DatasetRef>, Option<ColumnLineage>) {
                let inputs = extract_inputs(plan).unwrap_or_default();
                let mut cl = column_lineage(plan).unwrap_or_default();
                masked.overlay(&mut cl);
                (inputs, Some(cl))
            };
            let (inputs, col_lineage): (Vec<DatasetRef>, Option<ColumnLineage>) = match plan {
                Some(plan) => extract(&plan),
                None => match session_ctx.state().create_logical_plan(&sql).await {
                    Ok(plan) => extract(&plan),
                    Err(err) => {
                        tracing::debug!(
                            %run_id,
                            sql = %sql,
                            error = %err,
                            "lineage: no executed plan supplied and SQL re-plan failed; \
                             emitting COMPLETE with empty inputs"
                        );
                        (Vec::new(), None)
                    }
                },
            };

            // pgwire's QueryOutcome doesn't carry the diagnostic
            // (the error path returns it to the client and drops
            // it). Pass a placeholder; OpenLineage only requires
            // `errorMessage.message` to be non-empty on FAIL.
            let error_message = if matches!(core_outcome, QueryOutcome::Error) {
                Some("query failed at pgwire boundary")
            } else {
                None
            };

            let ctx = QueryFinishContext {
                run_id,
                outcome: core_outcome,
                finished_at,
                error_message,
                input_datasets: &inputs,
                column_lineage: col_lineage.as_ref(),
            };
            emitter.on_query_finish(&ctx).await;
        });
    }
}

/// Build a [`DynLineageEmitter`] from the server config's
/// `lineage` block. `None` ⇒ `NoopLineageEmitter`. Any future
/// variants on `LineageConfig` (`Kafka`, `File`, …) land here.
///
/// # Errors
/// Surfaces parse / construction errors from the concrete emitter
/// (e.g. invalid endpoint URL for the HTTP variant).
pub fn build_lineage_emitter(
    config: Option<&crate::config::LineageConfig>,
) -> anyhow::Result<DynLineageEmitter> {
    match config {
        None => Ok(Arc::new(dataglot_core::NoopLineageEmitter)),
        Some(crate::config::LineageConfig::OpenlineageHttp {
            endpoint,
            namespace,
        }) => {
            let emitter = OpenLineageHttpEmitter::new(endpoint, namespace.clone())?;
            Ok(Arc::new(emitter))
        }
    }
}

#[cfg(test)]
// Tests (and the RecordingEmitter test double) hold a lock guard to the
// end of the body to assert on its contents — harmless.
// `significant_drop_tightening` exists to prevent the over-held guards
// that cause production deadlocks, so relax it here.
#[allow(clippy::significant_drop_tightening)]
mod tests {
    use super::*;

    use dataglot_core::{DatasetRef, RunId};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn fixed_identity() -> Identity {
        Identity {
            user: Some("alice".to_string()),
            org: Some("acme".to_string()),
            org_groups: vec!["analysts".to_string()],
        }
    }

    fn fixed_start_ctx<'a>(sql: &'a str, id: &'a Identity) -> QueryStartContext<'a> {
        QueryStartContext {
            run_id: RunId::new(),
            sql,
            identity: id,
            started_at: SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000),
        }
    }

    fn fixed_finish_ctx<'a>(
        run_id: RunId,
        outcome: QueryOutcome,
        err: Option<&'a str>,
        inputs: &'a [DatasetRef],
    ) -> QueryFinishContext<'a> {
        QueryFinishContext {
            run_id,
            outcome,
            finished_at: SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_001),
            error_message: err,
            input_datasets: inputs,
            column_lineage: None,
        }
    }

    #[test]
    fn start_event_has_expected_shape() {
        // Pin the JSON keys the backend expects. Drift in
        // OpenLineage spec versions surfaces here first.
        let id = fixed_identity();
        let ctx = fixed_start_ctx("SELECT 1", &id);
        let event = build_start_event("dataglot.test", &ctx);

        assert_eq!(event["eventType"], "START");
        assert_eq!(event["producer"], OPENLINEAGE_PRODUCER);
        assert_eq!(event["schemaURL"], OPENLINEAGE_SCHEMA_URL);
        assert_eq!(event["job"]["namespace"], "dataglot.test");
        assert_eq!(event["job"]["name"], "SELECT 1");
        assert_eq!(event["run"]["runId"], ctx.run_id.to_string());
        assert!(event["run"]["facets"]["nominalTime"].is_object());
        assert!(event["inputs"].is_array());
        assert!(event["outputs"].is_array());
    }

    #[test]
    fn start_event_includes_identity_facet_when_user_set() {
        // The dataglot_identity custom facet must carry the
        // connecting user so governance backends can attribute
        // the query to the right actor.
        let id = fixed_identity();
        let ctx = fixed_start_ctx("SELECT 1", &id);
        let event = build_start_event("dataglot.test", &ctx);

        let facet = &event["run"]["facets"]["dataglot_identity"];
        assert!(facet.is_object(), "expected identity facet, got {facet:?}");
        assert_eq!(facet["user"], "alice");
        assert_eq!(facet["org"], "acme");
        assert_eq!(facet["orgGroups"][0], "analysts");
    }

    #[test]
    fn start_event_omits_identity_facet_for_anonymous_session() {
        // Unauthenticated session ⇒ no facet, no noisy null
        // fields on the payload.
        let id = Identity::default();
        let ctx = fixed_start_ctx("SELECT 1", &id);
        let event = build_start_event("dataglot.test", &ctx);

        assert!(
            event["run"]["facets"].get("dataglot_identity").is_none(),
            "anonymous session should not produce an identity facet"
        );
    }

    #[test]
    fn finish_event_complete_renders_inputs() {
        // The COMPLETE event carries inputs[] with the
        // <catalog>.<schema>.<table> shape downstream
        // consumers expect.
        let id = fixed_identity();
        let start = fixed_start_ctx("SELECT * FROM users", &id);
        let inputs = vec![DatasetRef {
            catalog: "pg".into(),
            schema: "public".into(),
            table: "users".into(),
        }];
        let finish = fixed_finish_ctx(start.run_id, QueryOutcome::Success, None, &inputs);
        let event = build_finish_event("dataglot.test", &finish);

        assert_eq!(event["eventType"], "COMPLETE");
        let arr = event["inputs"].as_array().expect("inputs is array");
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["namespace"], "dataglot.test");
        assert_eq!(arr[0]["name"], "pg.public.users");
        assert!(
            event["run"]["facets"]
                .as_object()
                .is_none_or(|m| !m.contains_key("errorMessage")),
            "COMPLETE must not carry errorMessage facet"
        );
    }

    #[test]
    fn finish_event_fail_includes_error_message_facet() {
        // The FAIL event carries the diagnostic on the
        // errorMessage facet — backends use this to surface
        // failure reason in the run history UI.
        let id = fixed_identity();
        let start = fixed_start_ctx("SELECT bad", &id);
        let finish = fixed_finish_ctx(
            start.run_id,
            QueryOutcome::Error,
            Some("column \"bad\" not found"),
            &[],
        );
        let event = build_finish_event("dataglot.test", &finish);

        assert_eq!(event["eventType"], "FAIL");
        let err = &event["run"]["facets"]["errorMessage"];
        assert_eq!(err["message"], "column \"bad\" not found");
        assert_eq!(err["programmingLanguage"], "rust");
        assert_eq!(err["_producer"], OPENLINEAGE_PRODUCER);
    }

    // -------- column lineage facet --------

    fn dataset(table: &str) -> DatasetRef {
        DatasetRef {
            catalog: "pg".into(),
            schema: "public".into(),
            table: table.into(),
        }
    }

    /// A two-column lineage: a masked IDENTITY column from
    /// `users.email`, and an AGGREGATION column from `orders.id`.
    fn sample_lineage() -> ColumnLineage {
        use dataglot_core::lineage::{InputFieldContribution, OutputFieldLineage};
        ColumnLineage {
            fields: vec![
                OutputFieldLineage {
                    output_field: "email".into(),
                    inputs: vec![InputFieldContribution {
                        field: FieldRef {
                            dataset: dataset("users"),
                            field: "email".into(),
                        },
                        transform: TransformationType::Identity,
                        masking: true,
                    }],
                },
                OutputFieldLineage {
                    output_field: "n".into(),
                    inputs: vec![InputFieldContribution {
                        field: FieldRef {
                            dataset: dataset("orders"),
                            field: "id".into(),
                        },
                        transform: TransformationType::Aggregation,
                        masking: false,
                    }],
                },
            ],
        }
    }

    fn finish_with_lineage<'a>(
        run_id: RunId,
        outcome: QueryOutcome,
        cl: Option<&'a ColumnLineage>,
        inputs: &'a [DatasetRef],
    ) -> QueryFinishContext<'a> {
        QueryFinishContext {
            run_id,
            outcome,
            finished_at: SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_002),
            error_message: None,
            input_datasets: inputs,
            column_lineage: cl,
        }
    }

    #[test]
    fn finish_event_renders_column_lineage_facet() {
        // The COMPLETE event carries a synthetic output dataset
        // whose columnLineage facet maps each output column to its
        // source fields, with type/subtype/masking per contribution.
        let cl = sample_lineage();
        let finish = finish_with_lineage(RunId::new(), QueryOutcome::Success, Some(&cl), &[]);
        let event = build_finish_event("dataglot.test", &finish);

        let outputs = event["outputs"].as_array().expect("outputs array");
        assert_eq!(outputs.len(), 1, "one synthetic output dataset");
        assert_eq!(outputs[0]["namespace"], "dataglot.test");
        let facet = &outputs[0]["facets"]["columnLineage"];
        assert_eq!(facet["_producer"], OPENLINEAGE_PRODUCER);

        // Masked IDENTITY column → users.email, masking: true.
        let email = &facet["fields"]["email"]["inputFields"][0];
        assert_eq!(email["namespace"], "dataglot.test");
        assert_eq!(email["name"], "pg.public.users");
        assert_eq!(email["field"], "email");
        let t = &email["transformations"][0];
        assert_eq!(t["type"], "DIRECT");
        assert_eq!(t["subtype"], "IDENTITY");
        assert_eq!(t["masking"], true);

        // AGGREGATION column → orders.id, masking: false.
        let n = &facet["fields"]["n"]["inputFields"][0]["transformations"][0];
        assert_eq!(n["subtype"], "AGGREGATION");
        assert_eq!(n["masking"], false);
    }

    #[test]
    fn finish_event_omits_outputs_without_column_lineage() {
        // No column lineage carried ⇒ no synthetic output dataset.
        let finish = finish_with_lineage(RunId::new(), QueryOutcome::Success, None, &[]);
        let event = build_finish_event("dataglot.test", &finish);
        assert!(event["outputs"].as_array().expect("array").is_empty());
    }

    #[test]
    fn finish_event_omits_outputs_for_input_free_lineage() {
        // A lineage with only literal columns (no inputs) carries
        // no provenance — skip the facet rather than emit an empty one.
        use dataglot_core::lineage::OutputFieldLineage;
        let cl = ColumnLineage {
            fields: vec![OutputFieldLineage {
                output_field: "one".into(),
                inputs: vec![],
            }],
        };
        let finish = finish_with_lineage(RunId::new(), QueryOutcome::Success, Some(&cl), &[]);
        let event = build_finish_event("dataglot.test", &finish);
        assert!(event["outputs"].as_array().expect("array").is_empty());
    }

    #[test]
    fn finish_event_omits_column_lineage_on_failure() {
        // FAIL events don't carry column lineage even if computed —
        // the query didn't produce a result set.
        let cl = sample_lineage();
        let finish = finish_with_lineage(RunId::new(), QueryOutcome::Error, Some(&cl), &[]);
        let event = build_finish_event("dataglot.test", &finish);
        assert_eq!(event["eventType"], "FAIL");
        assert!(event["outputs"].as_array().expect("array").is_empty());
    }

    // -------- masking overlay (MaskedColumns) --------

    #[test]
    fn masked_columns_overlay_marks_and_bumps_transform() {
        // An IDENTITY contribution to a masked column gets
        // masking: true AND its transform bumped to Transformation
        // (a mask is a value transformation).
        use dataglot_core::lineage::{InputFieldContribution, OutputFieldLineage};
        let masks = MaskedColumns::new([("users", "email")]);
        let mut cl = ColumnLineage {
            fields: vec![OutputFieldLineage {
                output_field: "email".into(),
                inputs: vec![InputFieldContribution {
                    field: FieldRef {
                        dataset: dataset("users"),
                        field: "email".into(),
                    },
                    transform: TransformationType::Identity,
                    masking: false,
                }],
            }],
        };
        masks.overlay(&mut cl);
        let c = &cl.fields[0].inputs[0];
        assert!(c.masking, "masked column must be flagged");
        assert_eq!(c.transform, TransformationType::Transformation);
    }

    #[test]
    fn masked_columns_overlay_leaves_unmasked_untouched() {
        use dataglot_core::lineage::{InputFieldContribution, OutputFieldLineage};
        let masks = MaskedColumns::new([("users", "email")]);
        let mut cl = ColumnLineage {
            fields: vec![OutputFieldLineage {
                output_field: "name".into(),
                inputs: vec![InputFieldContribution {
                    field: FieldRef {
                        dataset: dataset("users"),
                        field: "name".into(),
                    },
                    transform: TransformationType::Identity,
                    masking: false,
                }],
            }],
        };
        masks.overlay(&mut cl);
        let c = &cl.fields[0].inputs[0];
        assert!(!c.masking);
        assert_eq!(c.transform, TransformationType::Identity);
    }

    #[test]
    fn masked_columns_is_masked_respects_schema_qualifier() {
        // A schema-qualified mask only matches that schema; a bare
        // mask matches regardless of resolved schema/catalog.
        let qualified = MaskedColumns::new([("analytics.users", "email")]);
        let in_public = FieldRef {
            dataset: dataset("users"), // schema = public
            field: "email".into(),
        };
        assert!(
            !qualified.is_masked(&in_public),
            "analytics.users mask must not match public.users"
        );

        let bare = MaskedColumns::new([("users", "email")]);
        assert!(bare.is_masked(&in_public), "bare mask matches any schema");
        assert!(
            !bare.is_masked(&FieldRef {
                dataset: dataset("users"),
                field: "name".into(),
            }),
            "different column must not match"
        );
    }

    #[test]
    fn finish_event_fail_supplies_default_message_when_none_given() {
        // Defensive: the FAIL path must always carry *some*
        // message so backends don't reject the payload for a
        // missing required facet field.
        let id = Identity::default();
        let start = fixed_start_ctx("SELECT 1", &id);
        let finish = fixed_finish_ctx(start.run_id, QueryOutcome::Error, None, &[]);
        let event = build_finish_event("dataglot.test", &finish);

        assert_eq!(
            event["run"]["facets"]["errorMessage"]["message"],
            "query failed"
        );
    }

    #[test]
    fn truncate_sql_keeps_short_queries_intact() {
        assert_eq!(truncate_sql_for_job_name("SELECT 1"), "SELECT 1");
    }

    #[test]
    fn truncate_sql_truncates_long_queries_with_ellipsis() {
        let sql = "SELECT ".to_string() + &"a, ".repeat(100);
        let job_name = truncate_sql_for_job_name(&sql);
        assert!(job_name.ends_with('…'));
        assert!(job_name.chars().count() <= JOB_NAME_MAX_LEN + 1);
    }

    #[test]
    fn truncate_sql_handles_multibyte_at_boundary() {
        // 4-byte UTF-8 char straddling the boundary used to
        // panic on a byte-slice; pin the char-boundary fix.
        let mut sql = "x".repeat(JOB_NAME_MAX_LEN - 1);
        sql.push('𝕏'); // 4-byte UTF-8
        let job_name = truncate_sql_for_job_name(&sql);
        // Don't panic, produce *something* — the exact slice
        // depends on where the char boundary falls.
        assert!(!job_name.is_empty());
    }

    #[test]
    fn rfc3339_format_is_utc_with_milliseconds() {
        // OpenLineage prefers RFC3339 with millisecond
        // precision; the suffix is `Z` for UTC, not `+00:00`.
        let t = SystemTime::UNIX_EPOCH + std::time::Duration::from_millis(1_700_000_000_123);
        let s = system_time_to_rfc3339(t);
        assert!(s.ends_with('Z'), "expected Z suffix, got {s}");
        assert!(s.contains(".123"), "expected ms precision, got {s}");
    }

    #[tokio::test]
    async fn http_emitter_posts_start_then_complete() {
        // Drive the real reqwest client against a wiremock
        // backend; both POSTs must land with the expected
        // eventType.
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/lineage"))
            .respond_with(ResponseTemplate::new(200))
            .expect(2)
            .mount(&server)
            .await;

        let endpoint = format!("{}/api/v1/lineage", server.uri());
        let emitter = OpenLineageHttpEmitter::new(&endpoint, "dataglot.test".to_string()).unwrap();

        let id = fixed_identity();
        let start = fixed_start_ctx("SELECT 1", &id);
        emitter.on_query_start(&start).await;

        let finish = fixed_finish_ctx(start.run_id, QueryOutcome::Success, None, &[]);
        emitter.on_query_finish(&finish).await;

        // Drop the server; .expect(2) asserts at drop time.
    }

    #[tokio::test]
    async fn http_emitter_swallows_5xx_errors() {
        // Lineage outage MUST NOT propagate to the query
        // path. Wiremock returns 503; emitter must return
        // cleanly without panicking.
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;

        let endpoint = format!("{}/api/v1/lineage", server.uri());
        let emitter = OpenLineageHttpEmitter::new(&endpoint, "dataglot.test".to_string()).unwrap();

        let id = Identity::default();
        let start = fixed_start_ctx("SELECT 1", &id);
        emitter.on_query_start(&start).await;
        // No panic, no propagation — pinned.
    }

    #[tokio::test]
    async fn http_emitter_swallows_connection_refused() {
        // Endpoint that never responds (closed port) — also
        // must not propagate.
        let emitter = OpenLineageHttpEmitter::with_client(
            // Random unbound port on loopback.
            "http://127.0.0.1:1/api/v1/lineage",
            "dataglot.test".to_string(),
            reqwest::Client::builder()
                .timeout(std::time::Duration::from_millis(100))
                .build()
                .unwrap(),
        )
        .unwrap();

        let id = Identity::default();
        let start = fixed_start_ctx("SELECT 1", &id);
        emitter.on_query_start(&start).await;
        // No panic — pinned.
    }

    #[tokio::test]
    async fn http_emitter_posts_fail_event_on_error_outcome() {
        // The FAIL path must hit the same endpoint with
        // eventType=FAIL and an errorMessage facet. Pin the
        // body shape via body_partial_json so any drift in
        // the JSON keys the emitter produces surfaces here.
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/lineage"))
            .and(wiremock::matchers::body_partial_json(json!({
                "eventType": "FAIL",
                "run": {
                    "facets": {
                        "errorMessage": {
                            "message": "boom",
                            "programmingLanguage": "rust",
                        }
                    }
                }
            })))
            .respond_with(ResponseTemplate::new(201))
            .expect(1)
            .mount(&server)
            .await;

        let endpoint = format!("{}/api/v1/lineage", server.uri());
        let emitter = OpenLineageHttpEmitter::new(&endpoint, "dataglot.test".to_string()).unwrap();

        let id = Identity::default();
        let start = fixed_start_ctx("SELECT 1", &id);
        let finish = fixed_finish_ctx(start.run_id, QueryOutcome::Error, Some("boom"), &[]);
        emitter.on_query_finish(&finish).await;
    }

    #[test]
    fn new_rejects_invalid_endpoint_url() {
        let err =
            OpenLineageHttpEmitter::new("not a url", "dataglot.test".to_string()).unwrap_err();
        assert!(
            err.to_string().contains("invalid lineage endpoint URL"),
            "unexpected error: {err}"
        );
    }

    // ----- LineageObserver tests ----------------------------------

    /// One recorded finish: run id, outcome, input-dataset count,
    /// and the column lineage carried on the context (if any).
    type RecordedFinish = (RunId, QueryOutcome, usize, Option<ColumnLineage>);

    /// Test double for `LineageEmitter` that records calls to a
    /// `Mutex<Vec<...>>` so tests can assert on call shape without
    /// HTTP. Each entry carries (`run_id`, sql, outcome) — enough to
    /// pin the bridge logic in `LineageObserver`.
    #[derive(Debug, Default)]
    struct RecordingEmitter {
        starts: tokio::sync::Mutex<Vec<(RunId, String)>>,
        finishes: tokio::sync::Mutex<Vec<RecordedFinish>>,
    }

    #[async_trait::async_trait]
    impl LineageEmitter for RecordingEmitter {
        async fn on_query_start(&self, ctx: &QueryStartContext<'_>) {
            self.starts
                .lock()
                .await
                .push((ctx.run_id, ctx.sql.to_string()));
        }
        async fn on_query_finish(&self, ctx: &QueryFinishContext<'_>) {
            self.finishes.lock().await.push((
                ctx.run_id,
                ctx.outcome,
                ctx.input_datasets.len(),
                ctx.column_lineage.cloned(),
            ));
        }
    }

    /// Drain pending tokio tasks the observer spawned. The observer
    /// fires the emitter via `tokio::spawn`, so synchronous test
    /// asserts after `on_query_*` would race. A small yield + sleep
    /// lets the spawned task run.
    async fn drain_spawned_tasks() {
        // Yield twice to step past both the spawn and the await on
        // the Mutex; a 10ms sleep is generous belt-and-braces.
        tokio::task::yield_now().await;
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    #[tokio::test]
    async fn lineage_observer_fires_emitter_on_query_start() {
        use dataglot_pgwire::QueryObserver as _;

        let rec: Arc<RecordingEmitter> = Arc::new(RecordingEmitter::default());
        let ctx = Arc::new(SessionContext::new());
        let obs = LineageObserver::new(rec.clone(), ctx, Arc::new(MaskedColumns::default()));

        let run_id = RunId::new();
        obs.on_query_start(run_id, "SELECT 1");
        drain_spawned_tasks().await;

        let starts = rec.starts.lock().await;
        assert_eq!(starts.len(), 1);
        assert_eq!(starts[0].0, run_id);
        assert_eq!(starts[0].1, "SELECT 1");
    }

    #[tokio::test]
    async fn lineage_observer_extracts_inputs_on_complete() {
        // Register a MemTable so `SELECT * FROM users` plans
        // cleanly and extract_inputs surfaces `users` as a
        // DatasetRef. Pins the per-query plan extraction in
        // `on_query_complete`.
        use datafusion::arrow::array::{Int32Array, RecordBatch};
        use datafusion::arrow::datatypes::{DataType, Field, Schema};
        use datafusion::datasource::MemTable;
        use dataglot_pgwire::QueryObserver as _;

        let rec: Arc<RecordingEmitter> = Arc::new(RecordingEmitter::default());
        let ctx = Arc::new(SessionContext::new());

        let schema = Arc::new(Schema::new(vec![Field::new("id", DataType::Int32, false)]));
        let batch = RecordBatch::try_new(schema.clone(), vec![Arc::new(Int32Array::from(vec![1]))])
            .expect("batch");
        let table = MemTable::try_new(schema, vec![vec![batch]]).expect("memtable");
        ctx.register_table("users", Arc::new(table)).unwrap();

        let obs = LineageObserver::new(rec.clone(), ctx, Arc::new(MaskedColumns::default()));

        let run_id = RunId::new();
        obs.on_query_complete(
            run_id,
            "SELECT id FROM users",
            None,
            dataglot_pgwire::QueryOutcome::Success,
            Duration::from_millis(7),
        );
        drain_spawned_tasks().await;

        let finishes = rec.finishes.lock().await;
        assert_eq!(finishes.len(), 1);
        assert_eq!(finishes[0].0, run_id);
        assert_eq!(finishes[0].1, QueryOutcome::Success);
        assert_eq!(
            finishes[0].2, 1,
            "expected exactly one input dataset for `SELECT id FROM users`"
        );
    }

    #[tokio::test]
    async fn threaded_plan_is_used_instead_of_replanning() {
        //: `on_query_complete` must extract lineage from the
        // **executed** plan captured pre-execution, not re-plan the SQL on
        // the completion path. The motivating case is `CREATE TABLE t AS
        // SELECT …` (re-planning after t exists is unreliable), but the
        // guarantee is general: the threaded plan is authoritative and a
        // re-plan can diverge or fail (session state / search_path drift).
        //
        // Proof, version-robustly: the observer's own session context does
        // NOT contain `users`, so a *re-plan* of `SELECT id FROM users`
        // there fails (table not found) → empty inputs. The threaded plan
        // (built against a context that DID have `users`) still yields the
        // `users` input — showing the plan is used, not re-planned.
        use datafusion::arrow::array::{Int32Array, RecordBatch};
        use datafusion::arrow::datatypes::{DataType, Field, Schema};
        use datafusion::datasource::MemTable;
        use dataglot_pgwire::QueryObserver as _;

        let sql = "SELECT id FROM users";
        let schema = Arc::new(Schema::new(vec![Field::new("id", DataType::Int32, false)]));
        let batch = RecordBatch::try_new(schema.clone(), vec![Arc::new(Int32Array::from(vec![1]))])
            .expect("batch");

        // A context that HAS `users` — used only to build the plan the
        // handler would capture at execution time.
        let plan_ctx = SessionContext::new();
        plan_ctx
            .register_table(
                "users",
                Arc::new(MemTable::try_new(schema, vec![vec![batch]]).expect("memtable")),
            )
            .unwrap();
        let plan = Arc::new(
            plan_ctx
                .state()
                .create_logical_plan(sql)
                .await
                .expect("plan built where users exists"),
        );

        // The observer's session context does NOT have `users`, so a
        // re-plan there fails.
        let obs_ctx = Arc::new(SessionContext::new());
        assert!(
            obs_ctx.state().create_logical_plan(sql).await.is_err(),
            "precondition: re-plan must fail in a context without `users`",
        );

        // Threaded plan → lineage surfaces `users` despite the re-plan
        // being impossible here.
        let rec: Arc<RecordingEmitter> = Arc::new(RecordingEmitter::default());
        let obs = LineageObserver::new(
            rec.clone(),
            Arc::clone(&obs_ctx),
            Arc::new(MaskedColumns::default()),
        );
        obs.on_query_complete(
            RunId::new(),
            sql,
            Some(plan),
            dataglot_pgwire::QueryOutcome::Success,
            Duration::from_millis(1),
        );
        drain_spawned_tasks().await;
        assert_eq!(
            rec.finishes.lock().await[0].2,
            1,
            "lineage must come from the threaded plan (`users`), not a re-plan",
        );

        // No plan → the re-plan fallback fails → empty inputs (the pre-fix
        // behaviour the threaded plan avoids).
        let rec2: Arc<RecordingEmitter> = Arc::new(RecordingEmitter::default());
        let obs2 = LineageObserver::new(rec2.clone(), obs_ctx, Arc::new(MaskedColumns::default()));
        obs2.on_query_complete(
            RunId::new(),
            sql,
            None,
            dataglot_pgwire::QueryOutcome::Success,
            Duration::from_millis(1),
        );
        drain_spawned_tasks().await;
        assert_eq!(
            rec2.finishes.lock().await[0].2,
            0,
            "without a threaded plan the re-plan fails here → empty inputs",
        );
    }

    #[tokio::test]
    async fn lineage_observer_computes_column_lineage_and_overlays_masking() {
        // End-to-end through the observer: plan `SELECT email FROM
        // users`, compute column lineage on the raw plan, and overlay
        // the configured mask on `users.email`. Proves the wiring
        // from on_query_complete → analyzer → masking overlay →
        // QueryFinishContext.column_lineage.
        use datafusion::arrow::array::{RecordBatch, StringArray};
        use datafusion::arrow::datatypes::{DataType, Field, Schema};
        use datafusion::datasource::MemTable;
        use dataglot_pgwire::QueryObserver as _;

        let rec: Arc<RecordingEmitter> = Arc::new(RecordingEmitter::default());
        let ctx = Arc::new(SessionContext::new());
        let schema = Arc::new(Schema::new(vec![Field::new(
            "email",
            DataType::Utf8,
            false,
        )]));
        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![Arc::new(StringArray::from(vec!["a@x.com"]))],
        )
        .expect("batch");
        let table = MemTable::try_new(schema, vec![vec![batch]]).expect("memtable");
        ctx.register_table("users", Arc::new(table)).unwrap();

        let masks = Arc::new(MaskedColumns::new([("users", "email")]));
        let obs = LineageObserver::new(rec.clone(), ctx, masks);

        obs.on_query_complete(
            RunId::new(),
            "SELECT email FROM users",
            None,
            dataglot_pgwire::QueryOutcome::Success,
            Duration::from_millis(3),
        );
        drain_spawned_tasks().await;

        let finishes = rec.finishes.lock().await;
        let cl = finishes[0].3.as_ref().expect("column lineage present");
        let email = cl
            .fields
            .iter()
            .find(|f| f.output_field == "email")
            .expect("email column");
        let c = &email.inputs[0];
        assert_eq!(c.field.dataset.table, "users");
        assert_eq!(c.field.field, "email");
        assert!(c.masking, "configured mask on users.email must be overlaid");
        assert_eq!(c.transform, TransformationType::Transformation);
    }

    #[tokio::test]
    async fn lineage_observer_emits_complete_with_no_inputs_on_unplannable_sql() {
        // SQL that can't plan against an empty SessionContext —
        // the observer must still fire on_query_finish, just with
        // empty inputs. Pins the best-effort behaviour.
        use dataglot_pgwire::QueryObserver as _;

        let rec: Arc<RecordingEmitter> = Arc::new(RecordingEmitter::default());
        let ctx = Arc::new(SessionContext::new());
        let obs = LineageObserver::new(rec.clone(), ctx, Arc::new(MaskedColumns::default()));

        let run_id = RunId::new();
        obs.on_query_complete(
            run_id,
            "SELECT * FROM nonexistent_table",
            None,
            dataglot_pgwire::QueryOutcome::Error,
            Duration::from_millis(2),
        );
        drain_spawned_tasks().await;

        let finishes = rec.finishes.lock().await;
        assert_eq!(finishes.len(), 1);
        assert_eq!(finishes[0].1, QueryOutcome::Error);
        assert_eq!(finishes[0].2, 0);
    }

    #[test]
    fn build_lineage_emitter_returns_noop_for_no_config() {
        let emitter = build_lineage_emitter(None).expect("noop builds");
        // Smoke: it's a `dyn LineageEmitter`. We can't pattern-
        // match into a private type, but we can call into it
        // without crashing.
        drop(emitter);
    }

    #[test]
    fn build_lineage_emitter_returns_http_for_openlineage_config() {
        let cfg = crate::config::LineageConfig::OpenlineageHttp {
            endpoint: "http://localhost:5000/api/v1/lineage".into(),
            namespace: "dataglot.test".into(),
        };
        let _emitter = build_lineage_emitter(Some(&cfg)).expect("http emitter builds");
    }

    #[test]
    fn build_lineage_emitter_surfaces_invalid_endpoint() {
        let cfg = crate::config::LineageConfig::OpenlineageHttp {
            endpoint: "not a url".into(),
            namespace: "dataglot.test".into(),
        };
        let err = build_lineage_emitter(Some(&cfg)).unwrap_err();
        assert!(
            err.to_string().contains("invalid lineage endpoint URL"),
            "unexpected error: {err}"
        );
    }
}

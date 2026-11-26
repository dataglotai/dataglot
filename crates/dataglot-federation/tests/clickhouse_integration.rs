//! Integration tests for the ClickHouse federation connector.
//!
//! Most tests run against wiremock, an in-process HTTP server that answers
//! with Arrow IPC streams built here — shaped the way ClickHouse shapes them
//! (`Date` as `UInt16` days, `DateTime` as `UInt32` seconds). They need no
//! Docker and are not ignored.
//!
//! `against_a_real_server` runs the same paths against a real ClickHouse in
//! Docker and is `#[ignore]`d. Set `DATAGLOT_CLICKHOUSE_URL` to point it at a
//! server that is already running instead. That server needs a user
//! `dataglot` with the password in `CLICKHOUSE_PASSWORD` below, and an
//! `https://` URL unless it is on loopback, since the connector refuses to
//! send a password over plain HTTP. The test creates its own uniquely named
//! database and drops only that one.

#![cfg(feature = "clickhouse")]

use std::sync::Arc;

use datafusion::arrow::array::{
    ArrayRef, RecordBatch, StringArray, UInt16Array, UInt32Array, UInt64Array,
};
use datafusion::arrow::datatypes::{DataType, Field, Schema, TimeUnit};
use datafusion::arrow::ipc::writer::StreamWriter;
use datafusion::arrow::util::pretty::pretty_format_batches;
use datafusion::execution::session_state::SessionStateBuilder;
use datafusion::prelude::SessionContext;
use dataglot_federation::clickhouse::{ClickHouseConfig, ClickHouseConnector};
use dataglot_federation::health::ConnectorHealthCheck;
use wiremock::matchers::{body_string_contains, header, method, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

// ---------------------------------------------------------------------------
// Environment lock (same reasoning as the Flight SQL tests)
// ---------------------------------------------------------------------------

/// Serialises every test that writes to the process environment.
///
/// `set_var` mutates a process-wide table that other threads may be reading
/// at the same moment — `getenv` in another test's `connect`, or reqwest
/// reading proxy variables while it builds a client. A writer must exclude
/// every other test, readers only writers, so every test takes this lock:
/// [`env_write`] to set a variable, [`env_read`] otherwise.
static ENV_LOCK: tokio::sync::RwLock<()> = tokio::sync::RwLock::const_new(());

async fn env_write() -> tokio::sync::RwLockWriteGuard<'static, ()> {
    ENV_LOCK.write().await
}

async fn env_read() -> tokio::sync::RwLockReadGuard<'static, ()> {
    ENV_LOCK.read().await
}

/// Sets an environment variable and removes it again on drop.
struct EnvVar(&'static str);

impl EnvVar {
    fn set(name: &'static str, value: &str) -> Self {
        // Edition 2021: `set_var` is safe; holding the write half of
        // `ENV_LOCK` is what makes it sound.
        std::env::set_var(name, value);
        Self(name)
    }
}

impl Drop for EnvVar {
    fn drop(&mut self) {
        std::env::remove_var(self.0);
    }
}

// ---------------------------------------------------------------------------
// Fake server
// ---------------------------------------------------------------------------

/// Encode batches the way ClickHouse answers `FORMAT ArrowStream`.
fn arrow_stream(schema: &Arc<Schema>, batches: &[RecordBatch]) -> Vec<u8> {
    let mut body = Vec::new();
    let mut writer = StreamWriter::try_new(&mut body, schema).unwrap();
    for batch in batches {
        writer.write(batch).unwrap();
    }
    writer.finish().unwrap();
    drop(writer);
    body
}

/// A 200 response carrying one batch of string columns.
fn strings_response(columns: &[(&str, Vec<&str>)]) -> ResponseTemplate {
    let schema = Arc::new(Schema::new(
        columns
            .iter()
            .map(|(name, _)| Field::new(*name, DataType::Utf8, false))
            .collect::<Vec<_>>(),
    ));
    let arrays = columns
        .iter()
        .map(|(_, values)| Arc::new(StringArray::from(values.clone())) as ArrayRef)
        .collect();
    let batch = RecordBatch::try_new(Arc::clone(&schema), arrays).unwrap();
    ResponseTemplate::new(200).set_body_bytes(arrow_stream(&schema, &[batch]))
}

/// Answer the `system.columns` lookup for `analytics.events`.
async fn mount_columns(server: &MockServer, columns: &[(&str, &str)]) {
    let names = columns.iter().map(|(name, _)| *name).collect();
    let types = columns.iter().map(|(_, ty)| *ty).collect();
    let zones = vec!["UTC"; columns.len()];
    Mock::given(method("POST"))
        .and(body_string_contains("system.columns"))
        .and(query_param("param_database", "analytics"))
        .and(query_param("param_table", "events"))
        .respond_with(strings_response(&[
            ("name", names),
            ("type", types),
            ("timezone()", zones),
        ]))
        .mount(server)
        .await;
}

fn connect(config: ClickHouseConfig) -> Arc<ClickHouseConnector> {
    Arc::new(ClickHouseConnector::connect(config).expect("connector builds"))
}

/// A federation-enabled context with `analytics.events` registered as
/// `events`.
async fn federated_ctx(connector: &Arc<ClickHouseConnector>) -> SessionContext {
    let provider = connector
        .table_provider("analytics", "events")
        .await
        .expect("schema resolves for analytics.events");
    let base = SessionContext::new();
    let state = SessionStateBuilder::new_from_existing(base.state())
        .with_optimizer_rules(datafusion_federation::default_optimizer_rules())
        .with_query_planner(Arc::new(datafusion_federation::FederatedQueryPlanner::new()))
        .build();
    let ctx = SessionContext::new_with_state(state);
    ctx.register_table("events", provider)
        .expect("register analytics.events");
    ctx
}

/// The SQL text of every request the fake server received.
async fn received_sql(server: &MockServer) -> Vec<String> {
    server
        .received_requests()
        .await
        .unwrap_or_default()
        .iter()
        .map(|request| String::from_utf8_lossy(&request.body).into_owned())
        .collect()
}

// ---------------------------------------------------------------------------
// Discovery and schemas
// ---------------------------------------------------------------------------

#[tokio::test]
async fn databases_become_schemas_and_tables_are_listed() {
    let _env = env_read().await;
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(body_string_contains("system.tables"))
        // Every request pins the output format and the SQL behaviour.
        .and(query_param("default_format", "ArrowStream"))
        .and(query_param("wait_end_of_query", "1"))
        .and(query_param(
            "output_format_arrow_compression_method",
            "none",
        ))
        .and(query_param("join_use_nulls", "1"))
        .respond_with(strings_response(&[
            ("database", vec!["analytics", "analytics", "logs"]),
            ("name", vec!["events", "users", "raw"]),
        ]))
        .mount(&server)
        .await;

    let connector = connect(ClickHouseConfig::new("ch", server.uri()));
    let catalog = connector.as_catalog_provider().await.expect("listing");

    assert_eq!(catalog.schema_names(), vec!["analytics", "logs"]);
    let analytics = catalog.schema("analytics").expect("analytics schema");
    assert_eq!(analytics.table_names(), vec!["events", "users"]);
    assert!(catalog.schema("system").is_none());
    // Discovery fetched names only: no column schema yet (rule 13).
    assert_eq!(received_sql(&server).await.len(), 1);
}

#[tokio::test]
async fn a_configured_database_is_sent_as_a_query_parameter() {
    let _env = env_read().await;
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(body_string_contains("database = {database:String}"))
        .and(query_param("param_database", "analytics"))
        .respond_with(strings_response(&[
            ("database", vec!["analytics"]),
            ("name", vec!["events"]),
        ]))
        .mount(&server)
        .await;

    let mut config = ClickHouseConfig::new("ch", server.uri());
    config.database = Some("analytics".into());
    let catalog = connect(config)
        .as_catalog_provider()
        .await
        .expect("listing");
    assert_eq!(catalog.schema_names(), vec!["analytics"]);
}

#[tokio::test]
async fn a_listing_row_without_a_name_fails_closed() {
    let _env = env_read().await;
    let schema = Arc::new(Schema::new(vec![
        Field::new("database", DataType::Utf8, true),
        Field::new("name", DataType::Utf8, true),
    ]));
    // A null and an empty name, each beside a valid row.
    for (databases, tables) in [
        (
            vec![Some("analytics"), None],
            vec![Some("events"), Some("users")],
        ),
        (
            vec![Some("analytics"), Some("analytics")],
            vec![Some("events"), Some("")],
        ),
    ] {
        let server = MockServer::start().await;
        let batch = RecordBatch::try_new(
            Arc::clone(&schema),
            vec![
                Arc::new(StringArray::from(databases)),
                Arc::new(StringArray::from(tables)),
            ],
        )
        .unwrap();
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200).set_body_bytes(arrow_stream(&schema, &[batch])),
            )
            .mount(&server)
            .await;

        let err = connect(ClickHouseConfig::new("ch", server.uri()))
            .as_catalog_provider()
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("without a database or table name"), "{err}");
    }
}

#[tokio::test]
async fn column_types_resolve_to_arrow_on_first_use() {
    let _env = env_read().await;
    let server = MockServer::start().await;
    mount_columns(
        &server,
        &[
            ("id", "UInt64"),
            ("day", "Date"),
            ("at", "DateTime"),
            ("price", "Decimal(18, 4)"),
            ("country", "LowCardinality(String)"),
            ("note", "Nullable(String)"),
        ],
    )
    .await;

    let provider = connect(ClickHouseConfig::new("ch", server.uri()))
        .table_provider("analytics", "events")
        .await
        .expect("schema resolves");
    let expected = Schema::new(vec![
        Field::new("id", DataType::UInt64, false),
        Field::new("day", DataType::Date32, false),
        Field::new(
            "at",
            DataType::Timestamp(TimeUnit::Second, Some("UTC".into())),
            false,
        ),
        Field::new("price", DataType::Decimal128(18, 4), false),
        Field::new("country", DataType::Utf8, false),
        Field::new("note", DataType::Utf8, true),
    ]);
    assert_eq!(provider.schema().as_ref(), &expected);
}

#[tokio::test]
async fn an_unreadable_column_type_fails_the_table_naming_the_column() {
    let _env = env_read().await;
    let server = MockServer::start().await;
    mount_columns(
        &server,
        &[("id", "UInt64"), ("status", "Enum8('new' = 1, 'done' = 2)")],
    )
    .await;

    let err = connect(ClickHouseConfig::new("ch", server.uri()))
        .table_provider("analytics", "events")
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("analytics.events.status"), "{err}");
    assert!(err.contains("Enum8"), "{err}");
}

#[tokio::test]
async fn a_missing_table_is_an_error() {
    let _env = env_read().await;
    let server = MockServer::start().await;
    mount_columns(&server, &[]).await;

    let err = connect(ClickHouseConfig::new("ch", server.uri()))
        .table_provider("analytics", "events")
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("does not exist or is not visible"), "{err}");
}

// ---------------------------------------------------------------------------
// Queries
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_query_is_pushed_down_and_dates_come_back_as_dates() {
    let _env = env_read().await;
    let server = MockServer::start().await;
    mount_columns(
        &server,
        &[("id", "UInt64"), ("day", "Date"), ("at", "DateTime")],
    )
    .await;
    // What ClickHouse sends for these columns: Date as UInt16 days,
    // DateTime as UInt32 seconds.
    let wire = Arc::new(Schema::new(vec![
        Field::new("id", DataType::UInt64, false),
        Field::new("day", DataType::UInt16, false),
        Field::new("at", DataType::UInt32, false),
    ]));
    let rows = RecordBatch::try_new(
        Arc::clone(&wire),
        vec![
            Arc::new(UInt64Array::from(vec![2, 3])),
            Arc::new(UInt16Array::from(vec![19_724, 19_725])),
            Arc::new(UInt32Array::from(vec![1_704_161_045, 1_704_247_445])),
        ],
    )
    .unwrap();
    Mock::given(method("POST"))
        .and(body_string_contains(r#""analytics"."events""#))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(arrow_stream(&wire, &[rows])))
        .mount(&server)
        .await;

    let connector = connect(ClickHouseConfig::new("ch", server.uri()));
    let ctx = federated_ctx(&connector).await;
    let batches = ctx
        .sql("SELECT id, day, at FROM events WHERE id > 1 ORDER BY id")
        .await
        .expect("plans")
        .collect()
        .await
        .expect("executes");
    let rendered = pretty_format_batches(&batches).unwrap().to_string();
    assert!(
        rendered.contains("| 2  | 2024-01-02 | 2024-01-02T02:04:05Z |"),
        "{rendered}"
    );
    assert!(
        rendered.contains("| 3  | 2024-01-03 | 2024-01-03T02:04:05Z |"),
        "{rendered}"
    );

    // The filter and the ordering ran on the server, against the quoted
    // database-qualified table.
    let sql = received_sql(&server).await;
    let pushed = sql
        .iter()
        .find(|q| q.contains(r#""analytics"."events""#))
        .expect("the query reached the server");
    assert!(pushed.contains("WHERE"), "{pushed}");
    assert!(pushed.contains("ORDER BY"), "{pushed}");
}

#[tokio::test]
async fn a_server_error_fails_the_query_with_the_servers_message() {
    let _env = env_read().await;
    let server = MockServer::start().await;
    mount_columns(&server, &[("id", "UInt64")]).await;
    Mock::given(method("POST"))
        .and(body_string_contains(r#""analytics"."events""#))
        .respond_with(
            ResponseTemplate::new(500)
                .insert_header("X-ClickHouse-Exception-Code", "241")
                .set_body_string("Code: 241. DB::Exception: Memory limit exceeded"),
        )
        .mount(&server)
        .await;

    let ctx = federated_ctx(&connect(ClickHouseConfig::new("ch", server.uri()))).await;
    let err = ctx
        .sql("SELECT id FROM events")
        .await
        .expect("plans")
        .collect()
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("Memory limit exceeded"), "{err}");
    assert!(err.contains("500"), "{err}");
}

// ---------------------------------------------------------------------------
// Credentials and health
// ---------------------------------------------------------------------------

#[tokio::test]
async fn credentials_go_in_headers_and_never_into_errors() {
    let _env = env_write().await;
    let _password = EnvVar::set("DATAGLOT_TEST_CH_PASSWORD", "Sw0rdfish-42");
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(header("x-clickhouse-user", "reader"))
        .and(header("x-clickhouse-key", "Sw0rdfish-42"))
        // A server reflecting the credential back, in another case.
        .respond_with(ResponseTemplate::new(516).set_body_string(
            "Code: 516. DB::Exception: reader: Authentication failed (key sw0rdfish-42)",
        ))
        .mount(&server)
        .await;

    let mut config = ClickHouseConfig::new("ch", server.uri());
    config.user = Some("reader".into());
    config.password_env = Some("DATAGLOT_TEST_CH_PASSWORD".into());
    let connector = connect(config);

    let err = connector.health_check().await.unwrap_err();
    assert!(err.contains("Authentication failed"), "{err}");
    assert!(err.contains("[redacted]"), "{err}");
    assert!(!err.to_ascii_lowercase().contains("sw0rdfish-42"), "{err}");
    assert!(!format!("{connector:?}").contains("Sw0rdfish"));
    // The mock only matched with both headers present.
    assert_eq!(
        received_sql(&server).await,
        vec!["SELECT 1 WHERE 0".to_string()]
    );
}

#[tokio::test]
async fn a_password_reflected_in_a_column_type_is_scrubbed() {
    let _env = env_write().await;
    let _password = EnvVar::set("DATAGLOT_TEST_CH_PASSWORD", "Sw0rdfish-42");
    let server = MockServer::start().await;
    mount_columns(&server, &[("status", "Enum8('Sw0rdfish-42' = 1)")]).await;

    let mut config = ClickHouseConfig::new("ch", server.uri());
    config.password_env = Some("DATAGLOT_TEST_CH_PASSWORD".into());
    let err = connect(config)
        .table_provider("analytics", "events")
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("analytics.events.status"), "{err}");
    assert!(err.contains("Enum8('[redacted]' = 1)"), "{err}");
    assert!(!err.contains("Sw0rdfish"), "{err}");
}

#[tokio::test]
async fn an_unset_password_variable_fails_at_connect() {
    let _env = env_read().await;
    let mut config = ClickHouseConfig::new("ch", "https://ch.example.com:8443");
    config.password_env = Some("DATAGLOT_TEST_CH_PASSWORD_UNSET".into());
    let err = ClickHouseConnector::connect(config)
        .unwrap_err()
        .to_string();
    assert!(err.contains("DATAGLOT_TEST_CH_PASSWORD_UNSET"), "{err}");
}

#[tokio::test]
async fn the_health_check_runs_a_query_that_returns_no_rows() {
    let _env = env_read().await;
    let server = MockServer::start().await;
    let schema = Arc::new(Schema::new(vec![Field::new("1", DataType::UInt8, false)]));
    Mock::given(method("POST"))
        .and(body_string_contains("SELECT 1 WHERE 0"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(arrow_stream(&schema, &[])))
        .mount(&server)
        .await;

    connect(ClickHouseConfig::new("ch", server.uri()))
        .health_check()
        .await
        .expect("healthy");
}

// ---------------------------------------------------------------------------
// Real server
// ---------------------------------------------------------------------------

/// Password of the `dataglot` user on the real server.
const CLICKHOUSE_PASSWORD: &str = "dataglot-test";

/// Run SQL on the real server directly, for setup.
async fn admin(url: &str, sql: &str) {
    let response = reqwest::Client::new()
        .post(url)
        .header("X-ClickHouse-User", "dataglot")
        .header("X-ClickHouse-Key", CLICKHOUSE_PASSWORD)
        .body(sql.to_string())
        .send()
        .await
        .expect("setup request");
    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    assert!(
        status.is_success(),
        "setup failed for `{sql}`: {status} {body}"
    );
}

/// A running ClickHouse: the one at `DATAGLOT_CLICKHOUSE_URL`, or a new
/// container. Returns its URL and the container, which must outlive the test.
async fn real_server() -> (
    String,
    Option<testcontainers::ContainerAsync<testcontainers::GenericImage>>,
) {
    use testcontainers::runners::AsyncRunner;
    use testcontainers::{GenericImage, ImageExt};

    let (url, container) = if let Ok(url) = std::env::var("DATAGLOT_CLICKHOUSE_URL") {
        (url, None)
    } else {
        let container = GenericImage::new("clickhouse/clickhouse-server", "25.8")
            .with_exposed_port(8123.into())
            .with_env_var("CLICKHOUSE_USER", "dataglot")
            .with_env_var("CLICKHOUSE_PASSWORD", CLICKHOUSE_PASSWORD)
            .with_env_var("CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT", "1")
            .start()
            .await
            .expect("start clickhouse");
        let port = container.get_host_port_ipv4(8123).await.expect("port");
        (format!("http://127.0.0.1:{port}"), Some(container))
    };
    // Wait until the HTTP interface answers.
    let ping = format!("{url}/ping");
    for _ in 0..60 {
        if reqwest::get(&ping)
            .await
            .is_ok_and(|r| r.status().is_success())
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    (url, container)
}

/// A database name no earlier run or other user is using.
fn unique_database() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock after 1970")
        .as_nanos();
    format!("dataglot_it_{}_{nanos}", std::process::id())
}

/// Create `database` and the tables the real-server test reads. No
/// `DROP ... IF EXISTS` first: `CREATE DATABASE` fails on a name that is
/// already taken rather than replacing someone's data.
async fn seed(url: &str, database: &str) {
    for sql in [
        format!("CREATE DATABASE {database}"),
        format!(
            "CREATE TABLE {database}.events (id UInt64, day Date, at DateTime('UTC'), \
             price Decimal(18, 4), country LowCardinality(String), note Nullable(String)) \
             ENGINE = MergeTree ORDER BY id"
        ),
        format!(
            "INSERT INTO {database}.events VALUES \
             (1, '2024-01-01', '2024-01-01 10:00:00', 1.5, 'DE', NULL), \
             (2, '2024-01-02', '2024-01-02 11:30:00', 2.25, 'TR', 'second'), \
             (3, '2024-01-03', '2024-01-03 12:45:00', 3.125, 'DE', 'third')"
        ),
        format!(
            "CREATE TABLE {database}.countries (code String, name String) \
             ENGINE = MergeTree ORDER BY code"
        ),
        format!("INSERT INTO {database}.countries VALUES ('DE', 'Germany')"),
        format!(
            "CREATE TABLE {database}.tagged (id UInt64, tag Enum8('a' = 1, 'b' = 2)) \
             ENGINE = MergeTree ORDER BY id"
        ),
    ] {
        admin(url, &sql).await;
    }
}

/// End to end against a real ClickHouse: discovery, types, pushdown, the
/// standard-SQL settings, and an unreadable column.
#[tokio::test]
#[ignore = "requires Docker (or DATAGLOT_CLICKHOUSE_URL)"]
async fn against_a_real_server() {
    use futures::FutureExt;

    let _env = env_write().await;
    let (url, _container) = real_server().await;
    let database = unique_database();

    // Build the connector before touching the server, so a config it refuses
    // (plain http:// to a remote host) fails before anything is created.
    let _password = EnvVar::set("DATAGLOT_TEST_CH_IT_PASSWORD", CLICKHOUSE_PASSWORD);
    let mut config = ClickHouseConfig::new("ch", url.clone());
    config.user = Some("dataglot".into());
    config.password_env = Some("DATAGLOT_TEST_CH_IT_PASSWORD".into());
    config.database = Some(database.clone());
    let connector = connect(config);

    seed(&url, &database).await;
    // Drop the database this run created even when an assertion fails.
    let outcome = std::panic::AssertUnwindSafe(check_real_server(&connector, &database))
        .catch_unwind()
        .await;
    admin(&url, &format!("DROP DATABASE {database}")).await;
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
}

/// The assertions of [`against_a_real_server`], against a seeded `database`.
async fn check_real_server(connector: &Arc<ClickHouseConnector>, database: &str) {
    connector.health_check().await.expect("healthy");

    let catalog = connector.as_catalog_provider().await.expect("listing");
    assert_eq!(catalog.schema_names(), vec![database.to_string()]);
    let base = SessionContext::new();
    let state = SessionStateBuilder::new_from_existing(base.state())
        .with_optimizer_rules(datafusion_federation::default_optimizer_rules())
        .with_query_planner(Arc::new(datafusion_federation::FederatedQueryPlanner::new()))
        .build();
    let ctx = SessionContext::new_with_state(state);
    ctx.register_catalog("ch", catalog);

    let run = |sql: String| {
        let ctx = ctx.clone();
        async move { ctx.sql(&sql).await?.collect().await }
    };

    // Types and a pushed-down filter.
    let batches = run(format!(
        "SELECT id, day, at, price, country, note FROM ch.{database}.events \
         WHERE country = 'DE' ORDER BY id"
    ))
    .await
    .expect("filtered select");
    datafusion::assert_batches_eq!(
        [
            "+----+------------+----------------------+--------+---------+-------+",
            "| id | day        | at                   | price  | country | note  |",
            "+----+------------+----------------------+--------+---------+-------+",
            "| 1  | 2024-01-01 | 2024-01-01T10:00:00Z | 1.5000 | DE      |       |",
            "| 3  | 2024-01-03 | 2024-01-03T12:45:00Z | 3.1250 | DE      | third |",
            "+----+------------+----------------------+--------+---------+-------+",
        ],
        &batches
    );

    // An unmatched outer-join row is NULL (`join_use_nulls`), not ''. A
    // printed table shows both as blank, so ask the server which it is.
    let batches = run(format!(
        "SELECT e.id, c.name IS NULL AS no_country FROM ch.{database}.events e \
         LEFT JOIN ch.{database}.countries c ON e.country = c.code ORDER BY e.id"
    ))
    .await
    .expect("left join");
    datafusion::assert_batches_eq!(
        [
            "+----+------------+",
            "| id | no_country |",
            "+----+------------+",
            "| 1  | false      |",
            "| 2  | true       |",
            "| 3  | false      |",
            "+----+------------+",
        ],
        &batches
    );

    // An aggregate over no rows is NULL (`aggregate_functions_null_for_empty`),
    // not 0.
    let batches = run(format!(
        "SELECT sum(id) IS NULL AS no_total FROM ch.{database}.events WHERE id > 100"
    ))
    .await
    .expect("empty aggregate");
    datafusion::assert_batches_eq!(
        [
            "+----------+",
            "| no_total |",
            "+----------+",
            "| true     |",
            "+----------+",
        ],
        &batches
    );

    // An unreadable column type fails the table, naming the column.
    let err = run(format!("SELECT id FROM ch.{database}.tagged"))
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains(&format!("{database}.tagged.tag")), "{err}");
}

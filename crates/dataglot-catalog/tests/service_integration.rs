//! Docker-gated integration tests for `CatalogService`.
//!
//! Boot a real Postgres via `testcontainers`, run the
//! `CatalogService::connect` → upsert → list round-trip, assert
//! both bindings come back with the same shape they went in
//! with.
//!
//! Marked `#[ignore = "requires Docker"]` so these only run
//! under `make test-integration` / the Docker-gated CI job. The
//! unit-level shape (serde roundtrip) is already pinned in
//! `dataglot-core::catalog::tests`; these tests pin the
//! Postgres-side wiring.

#![cfg(test)]

use dataglot_catalog::{
    BindingChangeKind, CatalogService, CatalogServiceError, GrantRecord, GranteeKind,
};
use dataglot_core::{CatalogBinding, IcebergCacheBinding, LiveConnectorBinding, LiveConnectorKind};
use futures::StreamExt;
use testcontainers::runners::AsyncRunner;
use testcontainers_modules::postgres::Postgres;

/// Boot a fresh Postgres container, return the DSN string and
/// hold the container alive for the duration of the test.
async fn boot_postgres() -> (String, testcontainers::ContainerAsync<Postgres>) {
    let container = Postgres::default().start().await.expect("postgres starts");
    let host = container.get_host().await.unwrap();
    let port = container.get_host_port_ipv4(5432).await.unwrap();
    let dsn = format!("host={host} port={port} user=postgres password=postgres dbname=postgres");
    (dsn, container)
}

#[tokio::test]
#[ignore = "requires Docker"]
async fn connect_creates_schema_v1_idempotently() {
    let (dsn, _container) = boot_postgres().await;

    // First connect: creates everything.
    let _svc1 = CatalogService::connect(&dsn, "default")
        .await
        .expect("first connect creates schema");

    // Second connect: must be a no-op, not a schema rebuild.
    let _svc2 = CatalogService::connect(&dsn, "default")
        .await
        .expect("second connect succeeds idempotently");
}

#[tokio::test]
#[ignore = "requires Docker"]
async fn migration_runner_records_baseline_and_reconnect_is_noop() {
    //  F8: the migration runner takes a fresh DB up to the target
    // version and records exactly that one baseline row; a re-connect finds the
    // DB already current and applies nothing new (no extra ledger rows).
    let (dsn, _container) = boot_postgres().await;

    let _svc = CatalogService::connect(&dsn, "default")
        .await
        .expect("fresh connect runs the baseline step");

    let (client, conn) = tokio_postgres::connect(&dsn, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });

    // Exactly one ledger row, at the build's target version.
    let rows = client
        .query("SELECT version FROM schema_version", &[])
        .await
        .unwrap();
    assert_eq!(rows.len(), 1, "baseline records a single version row");
    assert_eq!(rows[0].get::<_, String>(0), "v1");

    // Re-connect: DB is already current, so the runner is a no-op — still one
    // row, unchanged.
    let _svc2 = CatalogService::connect(&dsn, "default")
        .await
        .expect("reconnect is idempotent");
    let count: i64 = client
        .query_one("SELECT count(*) FROM schema_version", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(count, 1, "reconnect adds no new ledger rows");
}

#[tokio::test]
#[ignore = "requires Docker"]
async fn migration_runner_rejects_newer_version() {
    //  F8: a database stamped with a version newer than this build knows
    // fails fast — the runner refuses to touch a schema it can't advance from.
    let (dsn, _container) = boot_postgres().await;
    let _svc = CatalogService::connect(&dsn, "default").await.unwrap();

    let (client, conn) = tokio_postgres::connect(&dsn, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    client
        .execute("UPDATE schema_version SET version = 'v999'", &[])
        .await
        .unwrap();

    let err = CatalogService::connect(&dsn, "default")
        .await
        .expect_err("must reject a newer schema version");
    match err {
        CatalogServiceError::SchemaVersionMismatch { expected, found } => {
            assert_eq!(expected, "v1");
            assert_eq!(found, "v999");
        }
        other => panic!("expected SchemaVersionMismatch, got {other:?}"),
    }
}

#[tokio::test]
#[ignore = "requires Docker"]
async fn list_bindings_empty_for_fresh_org() {
    // A freshly-connected service with no upserts returns an
    // empty map — not an error, not None.
    let (dsn, _container) = boot_postgres().await;
    let svc = CatalogService::connect(&dsn, "default").await.unwrap();
    let bindings = svc.list_bindings("default").await.expect("list succeeds");
    assert!(bindings.is_empty());
}

#[tokio::test]
#[ignore = "requires Docker"]
async fn upsert_then_list_round_trips_each_variant() {
    // Two bindings, two upserts, then list — the order and shape
    // must roundtrip through the JSONB column intact. Pins the
    // serde wire-shape against the Postgres-side storage.
    let (dsn, _container) = boot_postgres().await;
    let svc = CatalogService::connect(&dsn, "default").await.unwrap();

    let pg = CatalogBinding::LiveConnector(LiveConnectorBinding {
        kind: LiveConnectorKind::Postgres,
        endpoint_hint: "10.0.0.5:5432".into(),
    });
    let warehouse = CatalogBinding::IcebergCache(IcebergCacheBinding {
        catalog_url: "http://lakekeeper:8181/catalog".into(),
        warehouse: "main".into(),
        table_path: vec![],
    });

    let prev1 = svc.upsert_binding("default", "pg_demo", &pg).await.unwrap();
    let prev2 = svc
        .upsert_binding("default", "warehouse", &warehouse)
        .await
        .unwrap();
    assert!(prev1.is_none(), "first upsert has no previous value");
    assert!(prev2.is_none(), "first upsert has no previous value");

    let bindings = svc.list_bindings("default").await.unwrap();
    assert_eq!(bindings.len(), 2);
    assert_eq!(bindings.get("pg_demo"), Some(&pg));
    assert_eq!(bindings.get("warehouse"), Some(&warehouse));
}

#[tokio::test]
#[ignore = "requires Docker"]
async fn upsert_overwrites_returns_previous_value() {
    // Second upsert on the same key replaces the binding and
    // returns the prior value. Pin the contract — Phase 2's
    // runtime-mutation API will surface the previous value to
    // callers (e.g. to log diffs).
    let (dsn, _container) = boot_postgres().await;
    let svc = CatalogService::connect(&dsn, "default").await.unwrap();

    let v1 = CatalogBinding::LiveConnector(LiveConnectorBinding {
        kind: LiveConnectorKind::Postgres,
        endpoint_hint: "old:5432".into(),
    });
    let v2 = CatalogBinding::LiveConnector(LiveConnectorBinding {
        kind: LiveConnectorKind::Postgres,
        endpoint_hint: "new:5432".into(),
    });

    let prev1 = svc.upsert_binding("default", "pg", &v1).await.unwrap();
    let prev2 = svc.upsert_binding("default", "pg", &v2).await.unwrap();
    assert!(prev1.is_none());
    assert_eq!(prev2, Some(v1));

    let bindings = svc.list_bindings("default").await.unwrap();
    assert_eq!(bindings.get("pg"), Some(&v2));
}

#[tokio::test]
#[ignore = "requires Docker"]
async fn connect_rejects_schema_version_mismatch() {
    // Simulate an "older binary against newer DB" by manually
    // bumping the schema_version row to v999, then re-connecting.
    let (dsn, _container) = boot_postgres().await;
    let _svc = CatalogService::connect(&dsn, "default").await.unwrap();

    let (client, conn) = tokio_postgres::connect(&dsn, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    client
        .execute("UPDATE schema_version SET version = 'v999'", &[])
        .await
        .unwrap();

    let err = CatalogService::connect(&dsn, "default")
        .await
        .expect_err("must reject mismatched schema version");
    match err {
        CatalogServiceError::SchemaVersionMismatch { expected, found } => {
            assert_eq!(expected, "v1");
            assert_eq!(found, "v999");
        }
        other => panic!("expected SchemaVersionMismatch, got {other:?}"),
    }
}

#[tokio::test]
#[ignore = "requires Docker"]
async fn malformed_binding_in_db_surfaces_as_typed_error() {
    // An external writer (raw SQL) inserts garbage JSON into
    // the binding column. `list_bindings` must surface a typed
    // MalformedBinding error, not panic.
    let (dsn, _container) = boot_postgres().await;
    let svc = CatalogService::connect(&dsn, "default").await.unwrap();

    let (client, conn) = tokio_postgres::connect(&dsn, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let garbage: serde_json::Value = serde_json::json!({"not": "a CatalogBinding"});
    client
        .execute(
            "INSERT INTO catalog_binding (org_id, name, binding_json)
             VALUES ('default', 'garbage', $1)",
            &[&garbage],
        )
        .await
        .unwrap();

    let err = svc
        .list_bindings("default")
        .await
        .expect_err("must surface error");
    match err {
        CatalogServiceError::MalformedBinding { name, .. } => {
            assert_eq!(name, "garbage");
        }
        other => panic!("expected MalformedBinding, got {other:?}"),
    }
}

#[tokio::test]
#[ignore = "requires Docker"]
async fn subscribe_emits_upserted_event_on_own_upsert() {
    // Self-loop semantics from the spec: the service's own
    // upsert fires the trigger, so a single caller's upsert
    // produces a NOTIFY. Pin this — task 09's cache rebuild
    // path depends on it being symmetric with external writes.
    let (dsn, _container) = boot_postgres().await;
    let svc = CatalogService::connect(&dsn, "default").await.unwrap();

    let mut stream = svc.subscribe().await.expect("subscribe succeeds");

    let binding = CatalogBinding::LiveConnector(LiveConnectorBinding {
        kind: LiveConnectorKind::Postgres,
        endpoint_hint: "10.0.0.5:5432".into(),
    });
    svc.upsert_binding("default", "pg_demo", &binding)
        .await
        .unwrap();

    // Wait at most 5s for the NOTIFY to land — Postgres
    // triggers are fast, but the pump task + channel may add
    // tens of ms.
    let change = tokio::time::timeout(std::time::Duration::from_secs(5), stream.next())
        .await
        .expect("timed out waiting for BindingChange")
        .expect("stream yielded a value");

    assert_eq!(change.org_id, "default");
    assert_eq!(change.name, "pg_demo");
    assert_eq!(change.kind, BindingChangeKind::Upserted);
}

#[tokio::test]
#[ignore = "requires Docker"]
async fn subscribe_emits_deleted_event_on_external_delete() {
    // External DELETE (via raw SQL) fires the trigger too. Pin
    // the DELETE → kind: Deleted mapping — task 09's cache
    // uses the kind to decide whether to also evict downstream
    // dependents (deletes propagate further than upserts).
    let (dsn, _container) = boot_postgres().await;
    let svc = CatalogService::connect(&dsn, "default").await.unwrap();

    // Seed a row first, then subscribe (so the upsert's own
    // NOTIFY doesn't show up in the stream we're testing).
    let binding = CatalogBinding::LiveConnector(LiveConnectorBinding {
        kind: LiveConnectorKind::Postgres,
        endpoint_hint: "x:5432".into(),
    });
    svc.upsert_binding("default", "doomed", &binding)
        .await
        .unwrap();

    let mut stream = svc.subscribe().await.expect("subscribe succeeds");

    // External DELETE.
    let (client, conn) = tokio_postgres::connect(&dsn, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    client
        .execute(
            "DELETE FROM catalog_binding WHERE org_id = 'default' AND name = 'doomed'",
            &[],
        )
        .await
        .unwrap();

    let change = tokio::time::timeout(std::time::Duration::from_secs(5), stream.next())
        .await
        .expect("timed out waiting for BindingChange")
        .expect("stream yielded a value");

    assert_eq!(change.name, "doomed");
    assert_eq!(change.kind, BindingChangeKind::Deleted);
}

#[tokio::test]
#[ignore = "requires Docker"]
async fn subscribe_stream_closes_when_dropped() {
    // Dropping the stream must close the underlying Postgres
    // connection. We can't directly observe that from the
    // test, but we can confirm the stream surface itself
    // becomes non-functional. Smoke-level coverage of the
    // drop-closes-connection invariant.
    let (dsn, _container) = boot_postgres().await;
    let svc = CatalogService::connect(&dsn, "default").await.unwrap();

    let stream = svc.subscribe().await.expect("subscribe succeeds");
    drop(stream);

    // Nothing to assert beyond "no panic" — the test passes
    // simply by completing. The cancellation behaviour is
    // structural (Drop on Client closes the connection).
}

#[tokio::test]
#[ignore = "requires Docker"]
async fn source_config_round_trips_and_lists_only_when_set() {
    // Task 12 slice 1: the control plane stores a full source config so the
    // server can build a live provider FROM the DB (not just dataglot.json).
    // Persist one, read it back via `list_source_configs`, and confirm a
    // binding WITHOUT a stored config is omitted (NULL column, not empty).
    let (dsn, _container) = boot_postgres().await;
    let svc = CatalogService::connect(&dsn, "default").await.unwrap();

    let binding = CatalogBinding::LiveConnector(LiveConnectorBinding {
        kind: LiveConnectorKind::Postgres,
        endpoint_hint: "10.0.0.5:5432".into(),
    });
    // Row WITH a source config.
    svc.upsert_binding("default", "pg", &binding).await.unwrap();
    let cfg = serde_json::json!({"kind": "postgres", "dsn_env": "PG_DSN"});
    svc.set_source_config("default", "pg", &cfg).await.unwrap();
    // Row with NO source config (binding only).
    svc.upsert_binding("default", "bare", &binding)
        .await
        .unwrap();

    let configs = svc
        .list_source_configs("default")
        .await
        .expect("list source configs");
    assert_eq!(
        configs.len(),
        1,
        "only rows with a source config are listed"
    );
    assert_eq!(
        configs.get("pg"),
        Some(&cfg),
        "source config round-trips through JSONB"
    );
    assert!(
        !configs.contains_key("bare"),
        "a binding without a source config is omitted"
    );

    // Setting again overwrites.
    let cfg2 = serde_json::json!({"kind": "postgres", "dsn_env": "OTHER_DSN"});
    svc.set_source_config("default", "pg", &cfg2).await.unwrap();
    let configs = svc.list_source_configs("default").await.unwrap();
    assert_eq!(
        configs.get("pg"),
        Some(&cfg2),
        "set_source_config overwrites the stored value"
    );
}

#[tokio::test]
#[ignore = "requires Docker"]
async fn grant_round_trips_put_list_delete_and_is_idempotent() {
    //  F5a: grants persist through the additive `db_grant` table. Put a
    // SELECT-on-table and a USAGE-on-catalog grant, list them back with the same
    // typed shape, confirm an identical re-put is idempotent, then delete.
    let (dsn, _container) = boot_postgres().await;
    let svc = CatalogService::connect(&dsn, "default").await.unwrap();

    assert!(svc.list_grants("default").await.unwrap().is_empty());

    let select = GrantRecord::select(GranteeKind::User, "alice", "pg", "public", "orders");
    let usage = GrantRecord::usage(GranteeKind::Role, "analyst", "pg");
    svc.put_grant("default", &select).await.unwrap();
    svc.put_grant("default", &usage).await.unwrap();
    // Idempotent upsert — the full-tuple PK + ON CONFLICT DO NOTHING collapses it.
    svc.put_grant("default", &select).await.unwrap();

    let grants = svc.list_grants("default").await.unwrap();
    assert_eq!(grants.len(), 2, "duplicate put did not add a row");
    assert!(grants.contains(&select));
    assert!(grants.contains(&usage));

    // Delete reports existence; a second delete is false.
    assert!(svc.delete_grant("default", &select).await.unwrap());
    assert!(!svc.delete_grant("default", &select).await.unwrap());
    let grants = svc.list_grants("default").await.unwrap();
    assert_eq!(grants, vec![usage]);
}

#[tokio::test]
#[ignore = "requires Docker"]
async fn role_membership_round_trips_on_postgres() {
    //  F5a: `GRANT <role> TO <user>` persists in the additive
    // `db_role_member` table; add/remove/list both directions.
    let (dsn, _container) = boot_postgres().await;
    let svc = CatalogService::connect(&dsn, "default").await.unwrap();

    svc.add_role_member("default", "analyst", "alice")
        .await
        .unwrap();
    // Idempotent.
    svc.add_role_member("default", "analyst", "alice")
        .await
        .unwrap();
    svc.add_role_member("default", "admin", "alice")
        .await
        .unwrap();
    svc.add_role_member("default", "analyst", "bob")
        .await
        .unwrap();

    assert_eq!(
        svc.list_roles_for_user("default", "alice").await.unwrap(),
        vec!["admin".to_string(), "analyst".to_string()]
    );
    assert_eq!(
        svc.list_role_members("default", "analyst").await.unwrap(),
        vec!["alice".to_string(), "bob".to_string()]
    );

    assert!(svc
        .remove_role_member("default", "analyst", "alice")
        .await
        .unwrap());
    assert!(!svc
        .remove_role_member("default", "analyst", "alice")
        .await
        .unwrap());
    assert_eq!(
        svc.list_roles_for_user("default", "alice").await.unwrap(),
        vec!["admin".to_string()]
    );
}

#[tokio::test]
#[ignore = "requires Docker"]
async fn grants_are_org_isolated_on_postgres() {
    //  F5a + M1: a grant under `acme` is invisible under `beta`.
    let (dsn, _container) = boot_postgres().await;
    let svc = CatalogService::connect(&dsn, "default").await.unwrap();

    let grant = GrantRecord::select(GranteeKind::User, "alice", "pg", "public", "t");
    svc.put_grant("acme", &grant).await.unwrap();
    svc.add_role_member("acme", "analyst", "alice")
        .await
        .unwrap();

    assert_eq!(svc.list_grants("acme").await.unwrap(), vec![grant]);
    assert!(svc.list_grants("beta").await.unwrap().is_empty());
    assert_eq!(
        svc.list_roles_for_user("acme", "alice").await.unwrap(),
        vec!["analyst".to_string()]
    );
    assert!(svc
        .list_roles_for_user("beta", "alice")
        .await
        .unwrap()
        .is_empty());
}

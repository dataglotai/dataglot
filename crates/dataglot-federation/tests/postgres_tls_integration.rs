//! Docker-gated integration test for the Postgres source-connection TLS
//! path (`pg_tls`, PRs #546/#547). Verification tail of the Phase 3
//! source-database-TLS exit item.
//!
//! Builds a throwaway `postgres:16-alpine`-based image at test time that
//! bakes in a self-signed CA→leaf chain (chowned to the `postgres` user
//! so the server can read the key — a bind-mounted/copied key would be
//! root-owned and unreadable by the unprivileged server), then drives
//! [`PostgresConnector::connect_with_tls`] three ways:
//!
//! 1. **CA-file full verification** — trust the test CA → handshake +
//!    query succeed.
//! 2. **accept-invalid bypass** — dev/test escape hatch → succeeds.
//! 3. **secure default rejects** — `sslmode=require` with the OS trust
//!    store (which doesn't contain the test CA) → connection fails.
//!
//! `#[ignore]`: requires Docker. Run via the integration workflow's
//! `--ignored` lane (`cargo test -p dataglot-federation --features all
//! --tests -- --ignored`).

#![cfg(feature = "postgres")]

use std::path::Path;
use std::process::Command;
use std::str::FromStr;

use dataglot_federation::pg_tls::{PgTls, TlsRoots};
use dataglot_federation::postgres::PostgresConnector;
use testcontainers::core::WaitFor;
use testcontainers::runners::AsyncRunner;
use testcontainers::{GenericImage, ImageExt};
use tokio_postgres::Config;

/// Locally-built image tag. testcontainers 0.27 only pulls on a 404
/// (image absent locally), so a `docker build`-produced tag is used
/// directly — no registry, no pull.
const IMAGE: &str = "dataglot-source-tls-it";
const TAG: &str = "latest";

/// Generate a CA + a `localhost` server cert (SAN localhost/127.0.0.1)
/// signed by it into `dir` via the `openssl` CLI, then `docker build` a
/// postgres image that bakes them in — chowned to the `postgres` user so
/// the unprivileged server can read the key. Returns the CA cert path
/// (for `TlsRoots::CaFile` on the client side).
fn build_ssl_postgres_image(dir: &Path) -> std::path::PathBuf {
    let p = |n: &str| dir.join(n);
    let run = |bin: &str, args: &[&str]| {
        let status = Command::new(bin)
            .args(args)
            .status()
            .unwrap_or_else(|e| panic!("run {bin}: {e}"));
        assert!(status.success(), "{bin} {args:?} failed");
    };
    let s = |pb: &std::path::PathBuf| pb.to_str().unwrap().to_string();
    let (ca_key, ca_crt) = (p("ca.key"), p("ca.crt"));
    let (srv_key, srv_csr, srv_crt) = (p("server.key"), p("server.csr"), p("server.crt"));

    // Self-signed CA → server cert with a SAN covering localhost + 127.0.0.1.
    run(
        "openssl",
        &[
            "req",
            "-new",
            "-x509",
            "-days",
            "2",
            "-nodes",
            "-keyout",
            &s(&ca_key),
            "-out",
            &s(&ca_crt),
            "-subj",
            "/CN=Dataglot Test CA",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
        ],
    );
    run(
        "openssl",
        &[
            "req",
            "-new",
            "-nodes",
            "-keyout",
            &s(&srv_key),
            "-out",
            &s(&srv_csr),
            "-subj",
            "/CN=localhost",
        ],
    );
    let ext = p("ext.cnf");
    std::fs::write(&ext, "subjectAltName=DNS:localhost,IP:127.0.0.1\n").unwrap();
    run(
        "openssl",
        &[
            "x509",
            "-req",
            "-in",
            &s(&srv_csr),
            "-CA",
            &s(&ca_crt),
            "-CAkey",
            &s(&ca_key),
            "-CAcreateserial",
            "-days",
            "2",
            "-out",
            &s(&srv_crt),
            "-extfile",
            &s(&ext),
        ],
    );

    // Bake certs into an image, fixing ownership so `postgres` can read
    // the key (a copied/mounted key is root-owned → unreadable → the
    // server's temp init instance refuses to start).
    std::fs::write(
        p("Dockerfile"),
        "FROM postgres:16-alpine\n\
         COPY server.crt /etc/pg/server.crt\n\
         COPY server.key /etc/pg/server.key\n\
         RUN chown postgres:postgres /etc/pg/server.crt /etc/pg/server.key \
             && chmod 600 /etc/pg/server.key\n",
    )
    .unwrap();
    let ctx = dir.to_str().expect("utf8 build-context path");
    run("docker", &["build", "-t", &format!("{IMAGE}:{TAG}"), ctx]);

    ca_crt
}

fn dsn(port: u16, extra: &str) -> String {
    format!("host=127.0.0.1 port={port} user=postgres password=pw dbname=demo {extra}")
}

/// A successful `connect_with_tls` already proved the TLS handshake
/// completed; sanity-check the connector is usable.
fn assert_connector_ok(connector: &PostgresConnector) {
    assert!(!connector.name().is_empty());
}

#[tokio::test]
#[ignore = "requires Docker"]
async fn postgres_tls_handshake_end_to_end() {
    let dir = tempfile::tempdir().expect("tempdir");
    // `build_ssl_postgres_image` shells out to openssl + `docker build`
    // (several seconds of blocking work) — keep it off the async
    // executor (rule 11). `dir` (the TempDir guard) stays alive here so
    // the build context isn't cleaned up mid-build.
    let dir_path = dir.path().to_path_buf();
    let ca_path = tokio::task::spawn_blocking(move || build_ssl_postgres_image(&dir_path))
        .await
        .expect("cert generation + image build task");

    let container = GenericImage::new(IMAGE, TAG)
        .with_wait_for(WaitFor::message_on_stderr(
            "database system is ready to accept connections",
        ))
        .with_env_var("POSTGRES_PASSWORD", "pw")
        .with_env_var("POSTGRES_DB", "demo")
        .with_cmd([
            "postgres",
            "-c",
            "ssl=on",
            "-c",
            "ssl_cert_file=/etc/pg/server.crt",
            "-c",
            "ssl_key_file=/etc/pg/server.key",
        ])
        .start()
        .await
        .expect("start ssl postgres");

    let port = container
        .get_host_port_ipv4(5432)
        .await
        .expect("mapped port");

    // 1. CA-file full verification (the production shape).
    let tls_ca = PgTls {
        roots: TlsRoots::CaFile(ca_path.clone()),
        accept_invalid_certs: false,
    };
    let cfg = Config::from_str(&dsn(port, "")).expect("dsn parses");
    let conn = PostgresConnector::connect_with_tls(cfg, &tls_ca)
        .await
        .expect("CA-file-verified TLS connect");
    assert_connector_ok(&conn);

    // 2. accept-invalid bypass (dev/test).
    let tls_bypass = PgTls {
        roots: TlsRoots::Webpki,
        accept_invalid_certs: true,
    };
    let cfg = Config::from_str(&dsn(port, "")).expect("dsn parses");
    PostgresConnector::connect_with_tls(cfg, &tls_bypass)
        .await
        .expect("accept-invalid TLS connect");

    // 3. Secure default (`sslmode=require` → native trust store, which
    //    doesn't contain the test CA) must REJECT the self-signed server.
    let rejected = PostgresConnector::connect(&dsn(port, "sslmode=require")).await;
    assert!(
        rejected.is_err(),
        "sslmode=require against a self-signed server must fail with native roots"
    );
}

//! Docker-gated integration test for the MySQL source-connection TLS
//! path (`mysql_tls`, PR #548). The MySQL counterpart of
//! `postgres_tls_integration.rs`, completing source-TLS verification for
//! both SQL connectors.
//!
//! Builds a throwaway `mysql:8.4`-based image at test time baking a
//! self-signed CA→leaf chain (chowned to the `mysql` user so the server
//! can read the key), then drives
//! [`MysqlConnector::connect_with_tls`] three ways:
//!
//! 1. **CA-file full verification** — trust the test CA → handshake +
//!    query succeed.
//! 2. **accept-invalid bypass** — dev/test escape hatch → succeeds.
//! 3. **built-in roots reject** — verify against the bundled Mozilla
//!    roots (which don't contain the test CA) → connection fails.
//!
//! `#[ignore]`: requires Docker. Runs in the integration workflow's
//! federation `--ignored` lane (`--features all` → mysql on).

#![cfg(feature = "mysql")]

use std::path::Path;
use std::process::Command;

use dataglot_federation::mysql::MysqlConnector;
use dataglot_federation::mysql_tls::MysqlTls;
use testcontainers::core::WaitFor;
use testcontainers::runners::AsyncRunner;
use testcontainers::{GenericImage, ImageExt};

const IMAGE: &str = "dataglot-source-tls-mysql-it";
const TAG: &str = "latest";

/// Generate a CA + `localhost` server cert (SAN localhost/127.0.0.1)
/// via `openssl`, then `docker build` a mysql image baking them in —
/// chowned to the `mysql` user so the server can read the key. Returns
/// the CA cert path (for `MysqlTls::ca_file`).
fn build_ssl_mysql_image(dir: &Path) -> std::path::PathBuf {
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

    std::fs::write(
        p("Dockerfile"),
        "FROM mysql:8.4\n\
         COPY server.crt /etc/mysql/certs/server.crt\n\
         COPY server.key /etc/mysql/certs/server.key\n\
         RUN chown -R mysql:mysql /etc/mysql/certs \
             && chmod 600 /etc/mysql/certs/server.key\n",
    )
    .unwrap();
    let ctx = dir.to_str().expect("utf8 build-context path");
    run("docker", &["build", "-t", &format!("{IMAGE}:{TAG}"), ctx]);

    ca_crt
}

fn dsn(port: u16) -> String {
    format!("mysql://root:pw@127.0.0.1:{port}/demo")
}

#[tokio::test]
#[ignore = "requires Docker"]
async fn mysql_tls_handshake_end_to_end() {
    let dir = tempfile::tempdir().expect("tempdir");
    // openssl + `docker build` are multi-second blocking work — keep them
    // off the async executor (rule 11). `dir` stays alive for the build.
    let dir_path = dir.path().to_path_buf();
    let ca_path = tokio::task::spawn_blocking(move || build_ssl_mysql_image(&dir_path))
        .await
        .expect("cert generation + image build task");

    let container = GenericImage::new(IMAGE, TAG)
        .with_wait_for(WaitFor::message_on_stderr("ready for connections"))
        .with_env_var("MYSQL_ROOT_PASSWORD", "pw")
        .with_env_var("MYSQL_DATABASE", "demo")
        .with_cmd([
            "mysqld",
            "--ssl-cert=/etc/mysql/certs/server.crt",
            "--ssl-key=/etc/mysql/certs/server.key",
        ])
        .start()
        .await
        .expect("start ssl mysql");

    let port = container
        .get_host_port_ipv4(3306)
        .await
        .expect("mapped port");

    // MySQL's "ready for connections" fires first for the socket-only
    // init server; retry until the networked server accepts TLS.
    let tls_ca = MysqlTls {
        ca_file: Some(ca_path.clone()),
        accept_invalid_certs: false,
    };
    let mut last_err = None;
    let mut connected = false;
    for _ in 0..30 {
        match MysqlConnector::connect_with_tls("mysql_tls", &dsn(port), &tls_ca).await {
            Ok(conn) => {
                assert!(!conn.name().is_empty());
                connected = true;
                break;
            }
            Err(e) => {
                last_err = Some(e);
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            }
        }
    }
    assert!(connected, "CA-file-verified TLS connect: {last_err:?}");

    // 2. accept-invalid bypass.
    let tls_bypass = MysqlTls {
        ca_file: None,
        accept_invalid_certs: true,
    };
    MysqlConnector::connect_with_tls("mysql_tls_bypass", &dsn(port), &tls_bypass)
        .await
        .expect("accept-invalid TLS connect");

    // 3. Built-in (Mozilla) roots, which don't contain the test CA →
    //    verification must REJECT the self-signed server.
    let tls_builtin = MysqlTls {
        ca_file: None,
        accept_invalid_certs: false,
    };
    let rejected =
        MysqlConnector::connect_with_tls("mysql_tls_reject", &dsn(port), &tls_builtin).await;
    assert!(
        rejected.is_err(),
        "built-in roots must reject a self-signed server cert"
    );
}

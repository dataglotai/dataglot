//! Client mode TLS and password handling against a real `DataglotServer`.
//!
//! One server requires TLS on pg-wire, so a plaintext client can't get in.
//! Another uses `scram-sha-256` auth for the password cases.

use std::collections::HashMap;
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

use dataglot_server::cli::OutputFormat;
use dataglot_server::client::{self, RemoteSession};
use dataglot_server::config::{
    AuthConfig, AuthMode, IdentityProfileConfig, PgwireTlsConfig, PgwireTlsMode, ServerConfig,
};
use dataglot_server::observability::ObservabilityConfig;
use dataglot_server::server::DataglotServer;
use tempfile::TempDir;

// Self-signed P-256 cert (CN=scheduler.local), shared with dataglot-ballista's
// TLS tests; its key is allowlisted in .gitleaks.toml. It's a CA certificate,
// which rustls never accepts as a server certificate, so every verifying mode
// has to reject it. `prefer` and `require` don't check it and connect fine.
const CERT_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIBiDCCAS+gAwIBAgIUb98gUuOUxnAhMfepW6NntDu7VZYwCgYIKoZIzj0EAwIw
GjEYMBYGA1UEAwwPc2NoZWR1bGVyLmxvY2FsMB4XDTI2MDcyNjEyMDAyNVoXDTM2
MDcyMzEyMDAyNVowGjEYMBYGA1UEAwwPc2NoZWR1bGVyLmxvY2FsMFkwEwYHKoZI
zj0CAQYIKoZIzj0DAQcDQgAETzUXqYk4eMz44cNunQlm7aThDOPr2ndG7Rb9qeEC
xMBm6J+Asof4pj0OylI2atId/rEQqrKQLcilncVtPmgkrKNTMFEwHQYDVR0OBBYE
FIxfUshEjRv4FhU87aYS6QYBDn4hMB8GA1UdIwQYMBaAFIxfUshEjRv4FhU87aYS
6QYBDn4hMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDRwAwRAIgKHi1cNac
966q2qODy0xn8Pap2NHo8xJURe37PdrfChECIBasPNSDlU7Ze5Bj2wpdAH5Hb4E3
ad3f4PDq8AK0DZyR
-----END CERTIFICATE-----
";

const KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg39O4wyy9L1tFEkod
yvaloMCgN5HGjXQ95KMlDfK/8E+hRANCAARPNRepiTh4zPjhw26dCWbtpOEM4+va
d0btFv2p4QLEwGbon4Cyh/imPQ7KUjZq0h3+sRCqspAtyKWdxW0+aCSs
-----END PRIVATE KEY-----
";

fn base_config(port: u16) -> ServerConfig {
    ServerConfig {
        host: "127.0.0.1".to_string(),
        port,
        observability: ObservabilityConfig {
            metrics_addr: None,
            ..ObservabilityConfig::default()
        },
        ..ServerConfig::default()
    }
}

/// Start `config` and wait until `ready_url` can connect.
async fn start(config: ServerConfig, ready_url: &str) {
    // Boxed so `start`'s own future stays small (`clippy::large_futures`).
    let server = Box::pin(DataglotServer::new(config))
        .await
        .expect("server boots");
    tokio::spawn(async move {
        server.run().await.expect("server runs");
    });
    for _ in 0..50 {
        if RemoteSession::connect(ready_url).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("server did not become ready for {ready_url}");
}

/// A server that only accepts TLS connections. Returns its base URL and
/// the path of its certificate.
async fn boot_tls_only() -> (String, String, TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let cert = dir.path().join("cert.pem");
    let key = dir.path().join("key.pem");
    std::fs::write(&cert, CERT_PEM).expect("write cert");
    std::fs::write(&key, KEY_PEM).expect("write key");
    let port = dataglot_test_support::reserve_loopback_port();
    let config = ServerConfig {
        pgwire_tls: Some(PgwireTlsConfig {
            cert_file: cert.clone(),
            key_file: key,
            mode: PgwireTlsMode::Require,
        }),
        ..base_config(port)
    };
    let url = format!("postgres://dataglot@127.0.0.1:{port}");
    start(config, &format!("{url}?sslmode=require")).await;
    (url, path_for_url(&cert), dir)
}

/// Forward slashes, so the path can go into a URL on Windows too.
fn path_for_url(path: &Path) -> String {
    path.display().to_string().replace('\\', "/")
}

async fn query(server: &str) -> (ExitCode, String, String) {
    let mut out = Vec::new();
    let mut err = Vec::new();
    let code = client::run_query(
        server,
        "SELECT 1 AS n",
        OutputFormat::Csv,
        &mut out,
        &mut err,
    )
    .await;
    (
        code,
        String::from_utf8(out).expect("utf-8 stdout"),
        String::from_utf8(err).expect("utf-8 stderr"),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn require_and_prefer_connect_over_tls() {
    let (url, _cert, _dir) = boot_tls_only().await;
    // The server refuses plaintext, so getting a result proves TLS was used.
    for server in [format!("{url}?sslmode=require"), url.clone()] {
        let (code, out, err) = query(&server).await;
        assert_eq!(code, ExitCode::SUCCESS, "{server}: {err}");
        assert_eq!(out, "n\n1\n", "{server}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn disable_is_plaintext_and_gets_refused() {
    let (url, _cert, _dir) = boot_tls_only().await;
    let (code, out, err) = query(&format!("{url}?sslmode=disable")).await;
    assert_eq!(code, ExitCode::from(2), "{err}");
    assert_eq!(out, "");
    assert!(
        err.starts_with("error: could not connect to 127.0.0.1:"),
        "{err}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn verifying_modes_reject_an_untrusted_certificate() {
    let (url, cert, _dir) = boot_tls_only().await;
    for server in [
        // Not signed by anything in the OS trust store.
        format!("{url}?sslmode=verify-full"),
        format!("{url}?sslmode=verify-ca"),
        // Trusted as a root, but still not usable as a server certificate.
        format!("{url}?sslmode=verify-full&sslrootcert={cert}"),
        // A root certificate makes `require` verify too, as in libpq.
        format!("{url}?sslmode=require&sslrootcert={cert}"),
    ] {
        let (code, _, err) = query(&server).await;
        assert_eq!(code, ExitCode::from(2), "expected connection failure");
        assert!(err.contains("certificate"), "expected certificate-related error");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_missing_root_certificate_file_is_reported() {
    let (url, _cert, _dir) = boot_tls_only().await;
    let (code, _, err) = query(&format!(
        "{url}?sslmode=verify-full&sslrootcert=/no/such/dir/ca.pem"
    ))
    .await;
    assert_eq!(code, ExitCode::from(2), "{err}");
    assert!(err.contains("/no/such/dir/ca.pem"), "{err}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn password_auth() {
    // Unique per run, so nothing else in the process reads or writes it.
    let password_env = format!(
        "DATAGLOT_CLIENT_TLS_E2E_PW_{}",
        dataglot_test_support::reserve_loopback_port()
    );
    std::env::set_var(&password_env, "s3cret");
    let port = dataglot_test_support::reserve_loopback_port();
    let config = ServerConfig {
        auth: AuthConfig {
            mode: AuthMode::ScramSha256,
            ..AuthConfig::default()
        },
        identities: HashMap::from([(
            "alice".to_string(),
            IdentityProfileConfig {
                password_env: Some(password_env),
                ..IdentityProfileConfig::default()
            },
        )]),
        ..base_config(port)
    };
    let base = format!("127.0.0.1:{port}");
    start(config, &format!("postgres://alice:s3cret@{base}")).await;

    let (code, out, err) = query(&format!("postgres://alice:s3cret@{base}")).await;
    assert_eq!(code, ExitCode::SUCCESS, "{err}");
    assert_eq!(out, "n\n1\n");

    let (code, _, err) = query(&format!("postgres://alice@{base}")).await;
    assert_eq!(code, ExitCode::from(2), "{err}");
    assert!(
        err.contains("the server asked for a password; put it in the URL or set PGPASSWORD"),
        "{err}"
    );

    let (code, _, err) = query(&format!("postgres://alice:wrong@{base}")).await;
    assert_eq!(code, ExitCode::from(2), "{err}");
    assert!(
        !err.contains("wrong"),
        "the password must not be echoed: {err}"
    );
}

//! Client mode TLS and password handling against a real `DataglotServer`.
//!
//! One server requires TLS on pg-wire, so a plaintext client can't get in.
//! Its certificates come from a CA generated per test with rcgen.
//! Another uses `scram-sha-256` auth for the password cases, including a
//! connection profile that reads its password from `password_env`.

use std::collections::HashMap;
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

use dataglot_server::cli::OutputFormat;
use dataglot_server::client::{self, Endpoint, RemoteSession};
use dataglot_server::config::{
    AuthConfig, AuthMode, IdentityProfileConfig, PgwireTlsConfig, PgwireTlsMode, ServerConfig,
};
use dataglot_server::observability::ObservabilityConfig;
use dataglot_server::server::DataglotServer;
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, KeyUsagePurpose};
use tempfile::TempDir;

/// A CA, and a server certificate it signed, all as PEM. Generated on every
/// run, so no private key lives in the repository.
struct Pki {
    ca: String,
    cert: String,
    key: String,
}

/// A fresh CA and a server certificate from it, valid for `names`.
fn issue(names: &[&str]) -> Pki {
    let ca_key = KeyPair::generate().expect("CA key");
    let mut ca = CertificateParams::new(Vec::<String>::new()).expect("CA params");
    ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca.distinguished_name
        .push(DnType::CommonName, "dataglot test CA");
    ca.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca_cert = ca.self_signed(&ca_key).expect("self-sign CA");
    let issuer = Issuer::new(ca, ca_key);

    let key = KeyPair::generate().expect("server key");
    let names: Vec<String> = names.iter().map(ToString::to_string).collect();
    let cert = CertificateParams::new(names)
        .expect("server params")
        .signed_by(&key, &issuer)
        .expect("sign server certificate");
    Pki {
        ca: ca_cert.pem(),
        cert: cert.pem(),
        key: key.serialize_pem(),
    }
}

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

/// A server that only accepts TLS connections.
struct TlsServer {
    /// `postgres://dataglot@127.0.0.1:<port>`
    url: String,
    /// Path of the CA that signed the server's certificate, ready for
    /// `sslrootcert=`.
    ca: String,
    _dir: TempDir,
}

/// Boot a TLS-only server whose certificate is valid for `names`.
async fn boot_tls_only(names: &[&str]) -> TlsServer {
    let pki = issue(names);
    let dir = tempfile::tempdir().expect("tempdir");
    let ca = dir.path().join("ca.pem");
    let cert = dir.path().join("cert.pem");
    let key = dir.path().join("key.pem");
    std::fs::write(&ca, &pki.ca).expect("write CA");
    std::fs::write(&cert, &pki.cert).expect("write cert");
    std::fs::write(&key, &pki.key).expect("write key");
    let port = dataglot_test_support::reserve_loopback_port();
    let config = ServerConfig {
        pgwire_tls: Some(PgwireTlsConfig {
            cert_file: cert,
            key_file: key,
            mode: PgwireTlsMode::Require,
        }),
        ..base_config(port)
    };
    let url = format!("postgres://dataglot@127.0.0.1:{port}");
    start(config, &format!("{url}?sslmode=require")).await;
    TlsServer {
        url,
        ca: path_for_url(&ca),
        _dir: dir,
    }
}

/// Write `pem` to a file in `dir` and return its path for `sslrootcert=`.
fn root_file(dir: &TempDir, pem: &str) -> String {
    let path = dir.path().join("other-ca.pem");
    std::fs::write(&path, pem).expect("write root");
    path_for_url(&path)
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

/// The names the test server's certificate is valid for.
const SERVER_NAMES: &[&str] = &["127.0.0.1", "localhost"];

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn require_and_prefer_connect_over_tls() {
    let server = boot_tls_only(SERVER_NAMES).await;
    let url = &server.url;
    // The server refuses plaintext, so getting a result proves TLS was used.
    for target in [format!("{url}?sslmode=require"), url.clone()] {
        let (code, out, err) = query(&target).await;
        assert_eq!(code, ExitCode::SUCCESS, "{target}: {err}");
        assert_eq!(out, "n\n1\n", "{target}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn disable_is_plaintext_and_gets_refused() {
    let server = boot_tls_only(SERVER_NAMES).await;
    let (code, out, err) = query(&format!("{}?sslmode=disable", server.url)).await;
    assert_eq!(code, ExitCode::from(2), "{err}");
    assert_eq!(out, "");
    assert!(
        err.starts_with("error: could not connect to 127.0.0.1:"),
        "{err}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn verifying_modes_accept_a_certificate_from_the_given_root() {
    let server = boot_tls_only(SERVER_NAMES).await;
    let (url, ca) = (&server.url, &server.ca);
    for target in [
        format!("{url}?sslmode=verify-full&sslrootcert={ca}"),
        format!("{url}?sslmode=verify-ca&sslrootcert={ca}"),
        // A root certificate makes `require` verify too, as in libpq.
        format!("{url}?sslmode=require&sslrootcert={ca}"),
    ] {
        let (code, out, err) = query(&target).await;
        assert_eq!(code, ExitCode::SUCCESS, "{target}: {err}");
        assert_eq!(out, "n\n1\n", "{target}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn verifying_modes_reject_an_untrusted_certificate() {
    let server = boot_tls_only(SERVER_NAMES).await;
    let url = &server.url;
    let dir = tempfile::tempdir().expect("tempdir");
    let other_ca = root_file(&dir, &issue(SERVER_NAMES).ca);
    for target in [
        // Not signed by anything in the OS trust store.
        format!("{url}?sslmode=verify-full"),
        format!("{url}?sslmode=verify-ca"),
        // Signed, but not by the root we were told to trust.
        format!("{url}?sslmode=verify-full&sslrootcert={other_ca}"),
        format!("{url}?sslmode=require&sslrootcert={other_ca}"),
    ] {
        let (code, _, err) = query(&target).await;
        assert_eq!(code, ExitCode::from(2), "{target}: expected a failure");
        assert!(err.contains("invalid peer certificate"), "{target}: {err}");
    }
}

/// Unlike libpq, `verify-ca` checks the host name too (see
/// `docs/quick-reference.md`), so both verifying modes refuse a certificate
/// issued for another host.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn verifying_modes_reject_a_certificate_for_another_host() {
    let server = boot_tls_only(&["db.example.com"]).await;
    let (url, ca) = (&server.url, &server.ca);
    for mode in ["verify-full", "verify-ca"] {
        let target = format!("{url}?sslmode={mode}&sslrootcert={ca}");
        let (code, _, err) = query(&target).await;
        assert_eq!(code, ExitCode::from(2), "{target}: expected a failure");
        assert!(err.contains("not valid for name"), "{target}: {err}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_missing_root_certificate_file_is_reported() {
    let server = boot_tls_only(SERVER_NAMES).await;
    let (code, _, err) = query(&format!(
        "{}?sslmode=verify-full&sslrootcert=/no/such/dir/ca.pem",
        server.url
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
                password_env: Some(password_env.clone()),
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

    // A profile supplies the password through password_env.
    let dir = tempfile::tempdir().expect("tempdir");
    let profiles = dir.path().join("cli.toml");
    std::fs::write(
        &profiles,
        format!(
            "[profiles.test]\nurl = \"postgres://alice@{base}\"\npassword_env = \"{password_env}\"\n"
        ),
    )
    .expect("write profiles");
    let endpoint = Endpoint::from_profile_file(&profiles, "test").expect("profile");
    let mut out = Vec::new();
    let mut err = Vec::new();
    let code = client::run_query(
        endpoint,
        "SELECT 1 AS n",
        OutputFormat::Csv,
        &mut out,
        &mut err,
    )
    .await;
    assert_eq!(code, ExitCode::SUCCESS, "{}", String::from_utf8_lossy(&err));
    assert_eq!(String::from_utf8(out).expect("utf-8"), "n\n1\n");
}

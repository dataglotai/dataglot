//! Client-side mTLS plumbing for Phase 2 slice 7a.
//!
//! Architecture Decisions §12 commits to "mTLS with port separation —
//! control plane vs. data plane on separate ports." Ballista already
//! ships port-separated listeners (executor: gRPC control on
//! `grpc_port` 50052, Arrow Flight data on `port` 50051; scheduler:
//! one combined gRPC port 50050). What it does not ship is server-
//! side TLS in its `start_server` / `start_executor_process` entry
//! points — both serve plaintext, with a documented escape hatch
//! (`tonic::transport::Server::builder().tls_config(...)`) only
//! reachable by bypassing those entries.
//!
//! Slice 7 is therefore split:
//!
//! - **Slice 7a (this module + binary CLI flags)** — *client-side
//!   only*. Wires `tonic::transport::ClientTlsConfig` through Ballista's
//!   `override_create_grpc_client_endpoint` hook on both the scheduler
//!   and executor binaries, plus through `BallistaContextFactory`. The
//!   plumbing is complete; the actual connections still negotiate
//!   plaintext because the server sides remain on Ballista's stock
//!   `start_server` / `start_executor_process` (no TLS listeners). A
//!   binary started with `--tls-*` flags loads and validates its certs
//!   at boot (fail-fast on missing / malformed PEM, slice 3b shape),
//!   installs the rustls crypto provider, and constructs the override.
//!   Any actual outbound connection still fails the TLS handshake when
//!   pointed at a plaintext peer — by design; the next slice (7b)
//!   lights up the server side.
//! - **Slice 7b (next)** — *server-side TLS via the
//!   `tonic::transport::Server::builder().tls_config(...)` escape
//!   hatch*. Inlines the bodies of `start_server` and
//!   `start_executor_process` enough to attach TLS to both ports,
//!   plus the Docker-gated handshake test that proves the full
//!   round-trip works.
//!
//! Why a "non-load-bearing-yet" 7a: the cert-loading + config-parsing
//! surface is the largest non-controversial chunk of the slice, and
//! shipping it ahead of the server-side wrapper lets the wrapper PR
//! focus on the gnarly Ballista-internals inlining without dragging
//! the config layer with it.
//!
//! # Why not use Ballista's `use_tls` flag
//!
//! `SchedulerConfig.use_tls` (`config.rs:250`) only controls the
//! embedded flight-proxy *client* — it does not enable TLS on the
//! scheduler's own gRPC server, nor does it accept cert paths. The
//! actual TLS wiring is delegated entirely to
//! `override_create_grpc_client_endpoint`. We set both: `use_tls = true`
//! so Ballista picks `https://` URLs internally, and the override
//! closure for the actual `ClientTlsConfig`. The Apache `mtls-cluster.rs`
//! example does the same.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use ballista_core::extension::EndpointOverrideFn;
use thiserror::Error;
use tonic::transport::{Certificate, ClientTlsConfig, Identity, ServerTlsConfig};

/// Clap-derive bag of TLS-related CLI arguments. Flatten into the
/// scheduler and executor binaries' `Args` structs via
/// `#[command(flatten)]` so both surfaces stay symmetric.
///
/// All four cert paths are required together (an error surfaces if
/// some are set but not all); the all-or-nothing rule keeps the
/// fail-fast contract simple. The `--insecure` flag is reserved for
/// slice 7b's default-deny enforcement — accepted in 7a as a no-op
/// (with a startup log line) so existing scripts can opt in early
/// without a future breaking change.
#[derive(clap::Args, Debug, Clone, Default)]
pub struct TlsArgs {
    /// PEM-encoded CA bundle used to verify the peer's certificate.
    /// For mutual TLS, this CA signs both scheduler and executor certs.
    #[arg(long, value_name = "PATH")]
    pub tls_ca: Option<PathBuf>,

    /// PEM-encoded certificate chain presented by this process to its
    /// peer for mutual authentication.
    #[arg(long, value_name = "PATH")]
    pub tls_cert: Option<PathBuf>,

    /// PEM-encoded private key matching `--tls-cert`.
    #[arg(long, value_name = "PATH")]
    pub tls_key: Option<PathBuf>,

    /// SNI / server-name expected from the peer's certificate. For
    /// executor → scheduler, this is the scheduler's hostname as it
    /// appears in the cert's Subject Alternative Names list.
    #[arg(long, value_name = "HOSTNAME")]
    pub tls_domain: Option<String>,

    /// Opt out of TLS for local development. Slice 7a accepts but
    /// does not enforce; slice 7b makes plaintext default-deny so
    /// this flag is required if `--tls-*` flags are absent. Either
    /// way the boot log carries a loud `INSECURE` warning.
    #[arg(long)]
    pub insecure: bool,
}

impl TlsArgs {
    /// Load the TLS config from the flags, or return `Ok(None)` if no
    /// TLS flags were supplied (slice 7a's backward-compatible
    /// behavior — plaintext on the wire).
    ///
    /// # Errors
    /// - [`TlsConfigError::Pem`] with a synthesized "mixed config"
    ///   message when some `--tls-*` flags are set and others are
    ///   missing — fail-fast rather than silently dropping into
    ///   plaintext when the operator clearly intended TLS.
    /// - Bubble-up from [`BallistaTlsConfig::from_paths`] (file IO
    ///   or PEM parse failures).
    pub fn load(&self) -> Result<Option<BallistaTlsConfig>, TlsConfigError> {
        match (
            &self.tls_ca,
            &self.tls_cert,
            &self.tls_key,
            &self.tls_domain,
        ) {
            (None, None, None, None) => Ok(None),
            (Some(ca), Some(cert), Some(key), Some(domain)) => {
                BallistaTlsConfig::from_paths(ca, cert, key, domain).map(Some)
            }
            _ => Err(TlsConfigError::Pem {
                path: PathBuf::new(),
                reason: "--tls-ca, --tls-cert, --tls-key, and --tls-domain must all be \
                         supplied together (or all omitted for plaintext)"
                    .to_string(),
            }),
        }
    }
}

/// PEM-encoded TLS material loaded from disk, paired with the SNI /
/// server-name expected from the peer's certificate.
///
/// Constructed via [`BallistaTlsConfig::from_paths`]; stored as raw
/// PEM bytes rather than parsed `Certificate` / `PrivateKey` types so
/// downstream callers can mint as many `ClientTlsConfig` /
/// `ServerTlsConfig` instances as they need without re-IO and without
/// exposing tonic types in the cross-module surface.
///
/// `Debug` redacts the cert / key payloads per hard rule 12 —
/// the key is sensitive; the cert is at-rest fine but the audit trail
/// should not have to distinguish.
#[derive(Clone)]
pub struct BallistaTlsConfig {
    ca_pem: Vec<u8>,
    cert_pem: Vec<u8>,
    key_pem: Vec<u8>,
    domain: String,
}

impl std::fmt::Debug for BallistaTlsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BallistaTlsConfig")
            .field(
                "ca_pem",
                &format_args!("<{} bytes redacted>", self.ca_pem.len()),
            )
            .field(
                "cert_pem",
                &format_args!("<{} bytes redacted>", self.cert_pem.len()),
            )
            .field(
                "key_pem",
                &format_args!("<{} bytes redacted>", self.key_pem.len()),
            )
            .field("domain", &self.domain)
            .finish()
    }
}

/// Typed errors from [`BallistaTlsConfig::from_paths`].
///
/// Fail-fast contract matches slices 3b / 5a.2: loading failure
/// exits the binary at `main` entry before any RPC. Error variants
/// carry the offending path so operator diagnostics have a fix-it
/// target; payloads are never included.
#[derive(Debug, Error)]
pub enum TlsConfigError {
    /// CA, cert, or key file could not be read.
    #[error("TLS file `{path}` could not be read: {source}")]
    Io {
        /// The file path that failed.
        path: PathBuf,
        #[source]
        /// Underlying IO error.
        source: std::io::Error,
    },
    /// CA, cert, or key file parsed but contained no PEM blocks of
    /// the expected type, or contained more than one private key.
    #[error("TLS file `{path}` did not parse as expected PEM ({reason})")]
    Pem {
        /// The file path that failed.
        path: PathBuf,
        /// Human-readable parse-failure reason.
        reason: String,
    },
}

impl BallistaTlsConfig {
    /// Load CA bundle, identity cert chain, and private key from
    /// PEM-encoded files. Validates that each file contains at least
    /// one PEM block of the expected type, and that the key file
    /// contains exactly one private key.
    ///
    /// `domain` is the SNI / server-name expected to appear in the
    /// peer's certificate Subject Alternative Names list. For
    /// `executor → scheduler`, this is the scheduler's hostname. For
    /// `scheduler → executor` (flight-proxy client), the wildcard
    /// `*.executor.local` shape works if the cluster mints per-node
    /// certs from a shared SAN template.
    ///
    /// # Errors
    /// - [`TlsConfigError::Io`] if any file is unreadable.
    /// - [`TlsConfigError::Pem`] if any file contains no usable PEM
    ///   blocks, contains the wrong block type, or contains more than
    ///   one private key.
    pub fn from_paths(
        ca: &Path,
        cert: &Path,
        key: &Path,
        domain: impl Into<String>,
    ) -> Result<Self, TlsConfigError> {
        let ca_pem = load_pem_certificates(ca)?;
        let cert_pem = load_pem_certificates(cert)?;
        let key_pem = load_pem_private_key(key)?;
        Ok(Self {
            ca_pem,
            cert_pem,
            key_pem,
            domain: domain.into(),
        })
    }

    /// SNI / server-name this config expects on the peer's cert.
    #[must_use]
    pub fn domain(&self) -> &str {
        &self.domain
    }

    /// Build a [`tonic::transport::ClientTlsConfig`] for outbound
    /// connections — executor → scheduler, scheduler → flight-proxy,
    /// or `dataglot-server` → remote Ballista.
    ///
    /// The CA bundle is installed as the trust root; the identity is
    /// presented for mutual authentication; the domain anchors SNI.
    /// Borrowed-clone construction is cheap (each call mints a fresh
    /// `ClientTlsConfig`); call as many times as needed.
    #[must_use]
    pub fn client_tls_config(&self) -> ClientTlsConfig {
        ClientTlsConfig::new()
            .ca_certificate(Certificate::from_pem(self.ca_pem.clone()))
            .domain_name(self.domain.clone())
            .identity(Identity::from_pem(
                self.cert_pem.clone(),
                self.key_pem.clone(),
            ))
    }

    /// Build a [`tonic::transport::ServerTlsConfig`] for inbound
    /// listeners — used by slice 7b when the scheduler / executor
    /// servers light up TLS-aware listeners. Slice 7a stores this
    /// for forward compatibility but does not yet wire it into a
    /// listener.
    ///
    /// The identity is presented to peers; `client_ca_root` enforces
    /// mutual TLS by rejecting any client that doesn't present a
    /// cert signed by our CA.
    #[must_use]
    pub fn server_tls_config(&self) -> ServerTlsConfig {
        ServerTlsConfig::new()
            .identity(Identity::from_pem(
                self.cert_pem.clone(),
                self.key_pem.clone(),
            ))
            .client_ca_root(Certificate::from_pem(self.ca_pem.clone()))
    }

    /// Wrap this config into the closure shape Ballista's
    /// `override_create_grpc_client_endpoint` accepts. Every gRPC
    /// client endpoint Ballista constructs (executor → scheduler,
    /// scheduler → flight-proxy, shuffle reader, executor heartbeat,
    /// etc.) will route through `endpoint.tls_config(...)` and pick up
    /// our identity + CA + SNI.
    #[must_use]
    pub fn into_endpoint_override(self: Arc<Self>) -> EndpointOverrideFn {
        Arc::new(move |endpoint| {
            let cfg = self.client_tls_config();
            endpoint
                .tls_config(cfg)
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
        })
    }
}

/// Install rustls's `ring` crypto provider as the process default,
/// idempotently.
///
/// rustls 0.23 requires a `CryptoProvider` to be installed before any
/// TLS connection (client or server) can negotiate; `install_default`
/// is a one-shot operation that panics on a second call. We always
/// call it from the binary's `main` and silently absorb the
/// already-installed signal so the function is safe to call from
/// tests too.
pub fn install_default_crypto_provider() {
    // Returns `Result<(), Arc<CryptoProvider>>`; the Err branch is
    // "another provider was already installed," which is fine — we
    // only care that *some* provider is live.
    let _ = rustls::crypto::ring::default_provider().install_default();
}

fn load_pem_certificates(path: &Path) -> Result<Vec<u8>, TlsConfigError> {
    let raw = std::fs::read(path).map_err(|e| TlsConfigError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
    // rustls_pemfile parses the byte stream; we validate at least one
    // certificate is present so a file holding only a private key (or
    // empty / garbled) fails loud rather than silently disabling auth.
    let mut cursor = std::io::Cursor::new(&raw);
    let certs: Vec<_> = rustls_pemfile::certs(&mut cursor)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| TlsConfigError::Pem {
            path: path.to_path_buf(),
            reason: format!("rustls-pemfile parse error: {e}"),
        })?;
    if certs.is_empty() {
        return Err(TlsConfigError::Pem {
            path: path.to_path_buf(),
            reason: "no CERTIFICATE PEM blocks found".to_string(),
        });
    }
    // Return the original bytes — tonic re-parses them anyway via
    // `Certificate::from_pem`, and we want to preserve any
    // intermediate CA certs in a chain file verbatim.
    Ok(raw)
}

fn load_pem_private_key(path: &Path) -> Result<Vec<u8>, TlsConfigError> {
    let raw = std::fs::read(path).map_err(|e| TlsConfigError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
    // Count private-key blocks across the whole file rather than
    // taking the first match `rustls_pemfile::private_key` would
    // return — a file with two keys is ambiguous, and silently
    // picking the first lets a misconfigured deployment carry a
    // surprise identity. Reject > 1 explicitly.
    let mut cursor = std::io::Cursor::new(&raw);
    let key_count = rustls_pemfile::read_all(&mut cursor)
        .filter_map(|item| match item {
            Ok(
                rustls_pemfile::Item::Pkcs1Key(_)
                | rustls_pemfile::Item::Pkcs8Key(_)
                | rustls_pemfile::Item::Sec1Key(_),
            ) => Some(Ok(())),
            Ok(_) => None,
            Err(e) => Some(Err(e)),
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| TlsConfigError::Pem {
            path: path.to_path_buf(),
            reason: format!("rustls-pemfile parse error: {e}"),
        })?
        .len();
    if key_count > 1 {
        return Err(TlsConfigError::Pem {
            path: path.to_path_buf(),
            reason: format!("found {key_count} PRIVATE KEY PEM blocks — exactly one expected"),
        });
    }
    if key_count == 0 {
        return Err(TlsConfigError::Pem {
            path: path.to_path_buf(),
            reason: "no PRIVATE KEY PEM block found (expected one of PKCS8 / RSA / SEC1)"
                .to_string(),
        });
    }
    Ok(raw)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    // Minimal valid PEM blocks generated via openssl. These are NOT
    // signed certificates — they're syntactically valid PEM that
    // rustls-pemfile decodes successfully. tonic does its own real
    // parsing later when an endpoint is constructed; at the
    // `from_paths` layer we only verify the file structure.
    //
    // Generated locally via:
    //   openssl req -x509 -newkey rsa:2048 -keyout key.pem \
    //     -out cert.pem -days 1 -nodes -subj '/CN=test'
    // Then copied as string constants here so the test is hermetic.

    const TEST_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIBkTCCATegAwIBAgIUMQQjjxBmYJEFGyN9yT/V6XJ6jK4wCgYIKoZIzj0EAwIw
GjEYMBYGA1UEAwwPdGVzdC5leGFtcGxlLmNvbTAeFw0yNjA1MjYxMDAwMDBaFw0y
NzA1MjYxMDAwMDBaMBoxGDAWBgNVBAMMD3Rlc3QuZXhhbXBsZS5jb20wWTATBgcq
hkjOPQIBBggqhkjOPQMBBwNCAATDQs9DBmf01EXLDp4Jv6Tw8jr4HHF9ZVL5JFvW
hG7ND6ny5tDh8X8Khv5wG7JLqTfL3rZW1eOk/uTGiqYf28Zlo1MwUTAdBgNVHQ4E
FgQUE3WX9hLZHa4Bf6E6Hb/v1c0CTaIwHwYDVR0jBBgwFoAUE3WX9hLZHa4Bf6E6
Hb/v1c0CTaIwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNHADBEAiAJxFqU
KKnEYsJYBxNyXqV7G9CqVHsDpWOcv0vYx3VqaQIgQYnpa6jHnNxX/CXEoFn4HJEN
F4XBgGOd2WuKsIQNQwM=
-----END CERTIFICATE-----
";

    const TEST_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgXcGqzKZ+G7Wq+TUz
EeHL2tD6jJyD6Z9q5j5p5BJqfgmhRANCAATDQs9DBmf01EXLDp4Jv6Tw8jr4HHF9
ZVL5JFvWhG7ND6ny5tDh8X8Khv5wG7JLqTfL3rZW1eOk/uTGiqYf28Zl
-----END PRIVATE KEY-----
";

    fn write_temp(dir: &Path, name: &str, body: &str) -> PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, body).expect("temp write");
        p
    }

    #[test]
    fn loads_well_formed_pem_files() {
        let dir = TempDir::new().unwrap();
        let ca = write_temp(dir.path(), "ca.pem", TEST_CERT_PEM);
        let cert = write_temp(dir.path(), "cert.pem", TEST_CERT_PEM);
        let key = write_temp(dir.path(), "key.pem", TEST_KEY_PEM);

        let cfg =
            BallistaTlsConfig::from_paths(&ca, &cert, &key, "scheduler.local").expect("loads");
        assert_eq!(cfg.domain(), "scheduler.local");
    }

    #[test]
    fn rejects_missing_ca() {
        let dir = TempDir::new().unwrap();
        let cert = write_temp(dir.path(), "cert.pem", TEST_CERT_PEM);
        let key = write_temp(dir.path(), "key.pem", TEST_KEY_PEM);
        let missing = dir.path().join("does-not-exist.pem");

        let err = BallistaTlsConfig::from_paths(&missing, &cert, &key, "x")
            .expect_err("missing CA should reject");
        assert!(matches!(err, TlsConfigError::Io { .. }));
        assert!(err.to_string().contains("does-not-exist.pem"));
    }

    #[test]
    fn rejects_missing_cert() {
        let dir = TempDir::new().unwrap();
        let ca = write_temp(dir.path(), "ca.pem", TEST_CERT_PEM);
        let key = write_temp(dir.path(), "key.pem", TEST_KEY_PEM);
        let missing = dir.path().join("does-not-exist.pem");

        let err = BallistaTlsConfig::from_paths(&ca, &missing, &key, "x")
            .expect_err("missing cert should reject");
        assert!(matches!(err, TlsConfigError::Io { .. }));
    }

    #[test]
    fn rejects_missing_key() {
        let dir = TempDir::new().unwrap();
        let ca = write_temp(dir.path(), "ca.pem", TEST_CERT_PEM);
        let cert = write_temp(dir.path(), "cert.pem", TEST_CERT_PEM);
        let missing = dir.path().join("does-not-exist.pem");

        let err = BallistaTlsConfig::from_paths(&ca, &cert, &missing, "x")
            .expect_err("missing key should reject");
        assert!(matches!(err, TlsConfigError::Io { .. }));
    }

    #[test]
    fn rejects_cert_file_without_certificate_block() {
        let dir = TempDir::new().unwrap();
        let ca = write_temp(dir.path(), "ca.pem", TEST_CERT_PEM);
        // Pass the key file (only contains a PRIVATE KEY block) where
        // a cert chain is expected — must error.
        let key = write_temp(dir.path(), "key.pem", TEST_KEY_PEM);

        let err = BallistaTlsConfig::from_paths(&ca, &key, &key, "x")
            .expect_err("key-only file should not parse as cert chain");
        assert!(matches!(err, TlsConfigError::Pem { .. }));
        let TlsConfigError::Pem { reason, .. } = err else {
            unreachable!()
        };
        assert!(
            reason.contains("CERTIFICATE"),
            "reason should mention CERTIFICATE: {reason}"
        );
    }

    #[test]
    fn rejects_key_file_with_multiple_private_keys() {
        let dir = TempDir::new().unwrap();
        let ca = write_temp(dir.path(), "ca.pem", TEST_CERT_PEM);
        let cert = write_temp(dir.path(), "cert.pem", TEST_CERT_PEM);
        // Concatenate the same key twice — two valid PKCS8 PEM blocks
        // in one file. The loader must reject rather than silently
        // pick the first.
        let two_keys = format!("{TEST_KEY_PEM}\n{TEST_KEY_PEM}");
        let key = write_temp(dir.path(), "key.pem", &two_keys);

        let err = BallistaTlsConfig::from_paths(&ca, &cert, &key, "x")
            .expect_err("multiple keys must reject");
        let TlsConfigError::Pem { reason, .. } = err else {
            panic!("expected Pem variant for multi-key file")
        };
        assert!(reason.contains("exactly one expected"), "got: {reason}");
    }

    #[test]
    fn rejects_key_file_without_private_key_block() {
        let dir = TempDir::new().unwrap();
        let ca = write_temp(dir.path(), "ca.pem", TEST_CERT_PEM);
        let cert = write_temp(dir.path(), "cert.pem", TEST_CERT_PEM);
        // Pass the cert file (no PRIVATE KEY block) where the key is
        // expected.
        let err = BallistaTlsConfig::from_paths(&ca, &cert, &cert, "x").expect_err("no key block");
        assert!(matches!(err, TlsConfigError::Pem { .. }));
        let TlsConfigError::Pem { reason, .. } = err else {
            unreachable!()
        };
        assert!(reason.contains("PRIVATE KEY"), "got: {reason}");
    }

    #[test]
    fn debug_redacts_cert_and_key_bytes() {
        let dir = TempDir::new().unwrap();
        let ca = write_temp(dir.path(), "ca.pem", TEST_CERT_PEM);
        let cert = write_temp(dir.path(), "cert.pem", TEST_CERT_PEM);
        let key = write_temp(dir.path(), "key.pem", TEST_KEY_PEM);

        let cfg = BallistaTlsConfig::from_paths(&ca, &cert, &key, "scheduler.local").unwrap();
        let printed = format!("{cfg:?}");
        // The PEM strings include "BEGIN CERTIFICATE" / "PRIVATE KEY"
        // markers; redacted Debug must not leak them.
        assert!(!printed.contains("BEGIN"), "Debug leaked PEM: {printed}");
        assert!(!printed.contains("PRIVATE"), "Debug leaked PEM: {printed}");
        // The domain is fine to show.
        assert!(printed.contains("scheduler.local"));
        assert!(printed.contains("redacted"));
    }

    #[test]
    fn install_crypto_provider_is_idempotent() {
        // Two back-to-back calls must not panic. The function silently
        // absorbs "already installed" so tests sharing process state
        // are safe.
        install_default_crypto_provider();
        install_default_crypto_provider();
    }

    #[test]
    fn tls_args_load_returns_none_when_all_flags_absent() {
        let args = TlsArgs::default();
        let loaded = args.load().expect("backward-compat plaintext path");
        assert!(loaded.is_none());
    }

    #[test]
    fn tls_args_load_succeeds_when_all_flags_present() {
        let dir = TempDir::new().unwrap();
        let ca = write_temp(dir.path(), "ca.pem", TEST_CERT_PEM);
        let cert = write_temp(dir.path(), "cert.pem", TEST_CERT_PEM);
        let key = write_temp(dir.path(), "key.pem", TEST_KEY_PEM);
        let args = TlsArgs {
            tls_ca: Some(ca),
            tls_cert: Some(cert),
            tls_key: Some(key),
            tls_domain: Some("scheduler.local".to_string()),
            insecure: false,
        };
        let loaded = args.load().expect("all flags supplied");
        assert_eq!(loaded.unwrap().domain(), "scheduler.local");
    }

    #[test]
    fn tls_args_load_rejects_partial_config() {
        let dir = TempDir::new().unwrap();
        let ca = write_temp(dir.path(), "ca.pem", TEST_CERT_PEM);
        // Only --tls-ca set, others missing → mixed config error.
        let args = TlsArgs {
            tls_ca: Some(ca),
            tls_cert: None,
            tls_key: None,
            tls_domain: None,
            insecure: false,
        };
        let err = args.load().expect_err("partial config should reject");
        let TlsConfigError::Pem { reason, .. } = err else {
            panic!("expected Pem variant for partial config")
        };
        assert!(reason.contains("all be supplied together"), "got: {reason}");
    }

    #[test]
    fn client_tls_config_constructs_from_loaded_pem() {
        // Smoke test that the parsed bytes survive into a
        // `ClientTlsConfig`. tonic does the heavy validation lazily
        // when an endpoint actually dials, so at this layer we just
        // confirm no panic during construction.
        let dir = TempDir::new().unwrap();
        let ca = write_temp(dir.path(), "ca.pem", TEST_CERT_PEM);
        let cert = write_temp(dir.path(), "cert.pem", TEST_CERT_PEM);
        let key = write_temp(dir.path(), "key.pem", TEST_KEY_PEM);

        let cfg = BallistaTlsConfig::from_paths(&ca, &cert, &key, "scheduler.local").unwrap();
        let _client = cfg.client_tls_config();
        let _server = cfg.server_tls_config();
    }

    // A *real* self-signed EC (prime256v1) cert + matching PKCS8 key
    // (CN=scheduler.local), generated via
    //   openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    //     -keyout key.pem -out cert.pem -days 3650 -nodes -subj '/CN=scheduler.local'
    // Unlike TEST_CERT_PEM / TEST_KEY_PEM above (which only pass
    // rustls-pemfile's *structural* check), these survive tonic's real
    // rustls parse — required to exercise `into_endpoint_override`, which
    // forces the client `ClientConfig` to be built. Self-signed, so the
    // one cert serves as both the trust-root CA and the client identity.
    const REAL_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----
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

    const REAL_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg39O4wyy9L1tFEkod
yvaloMCgN5HGjXQ95KMlDfK/8E+hRANCAARPNRepiTh4zPjhw26dCWbtpOEM4+va
d0btFv2p4QLEwGbon4Cyh/imPQ7KUjZq0h3+sRCqspAtyKWdxW0+aCSs
-----END PRIVATE KEY-----
";

    /// `into_endpoint_override` is the only fn that actually attaches TLS to
    /// Ballista's gRPC client endpoints (executor→scheduler, heartbeat,
    /// shuffle reader, …). Applying the returned closure to a real tonic
    /// `Endpoint` forces the rustls `ClientConfig` to be built from our
    /// identity + CA + SNI — the step `client_tls_config()` alone defers.
    #[test]
    fn into_endpoint_override_attaches_tls_to_a_grpc_endpoint() {
        // rustls 0.23 needs a crypto provider before a ClientConfig builds.
        install_default_crypto_provider();

        let dir = TempDir::new().unwrap();
        let ca = write_temp(dir.path(), "ca.pem", REAL_CERT_PEM);
        let cert = write_temp(dir.path(), "cert.pem", REAL_CERT_PEM);
        let key = write_temp(dir.path(), "key.pem", REAL_KEY_PEM);
        let cfg =
            Arc::new(BallistaTlsConfig::from_paths(&ca, &cert, &key, "scheduler.local").unwrap());

        let override_fn = cfg.into_endpoint_override();

        let endpoint = tonic::transport::Endpoint::from_static("http://scheduler.local:50050");
        let overridden = override_fn(endpoint);
        assert!(
            overridden.is_ok(),
            "into_endpoint_override must attach TLS without error: {:?}",
            overridden.err()
        );
    }
}

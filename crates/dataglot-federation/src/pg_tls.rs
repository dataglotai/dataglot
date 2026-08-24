//! TLS for the Postgres federation connector.
//!
//! Phase 3 security-audit-readiness: source-database connections were
//! plaintext (`NoTls`) — a flagged blocker for a regulated-bank ICP.
//! This module builds a rustls-backed [`MakeRustlsConnect`] so the
//! Postgres connector can negotiate encrypted connections.
//!
//! # Provider
//!
//! rustls's **ring** provider, matching `dataglot-ballista`'s
//! `install_default_crypto_provider` — installed once, idempotently, so
//! `ClientConfig::builder()` resolves a process-default provider. `ring`
//! is transitive under rustls (not a direct production dep), so the
//! native-dependency-hygiene gate (rule 15) is unaffected.
//!
//! # Trust roots
//!
//! [`TlsRoots`] selects where server-certificate trust anchors come from:
//! the OS/corporate store ([`TlsRoots::Native`]), the bundled Mozilla set
//! ([`TlsRoots::Webpki`]), or a specific PEM CA bundle
//! ([`TlsRoots::CaFile`]) for private CAs / self-signed dev servers.
//! [`PgTls::accept_invalid_certs`] disables verification entirely — a
//! **dev/test-only** escape hatch, never a production default.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use tokio_postgres_rustls::MakeRustlsConnect;

use dataglot_core::{DataglotError, Result as DataglotResult};

/// Source of trust anchors for verifying the Postgres server certificate.
#[derive(Debug, Clone)]
pub enum TlsRoots {
    /// The host OS / corporate trust store (`rustls-native-certs`).
    /// The right default for servers behind a corporate or public CA.
    Native,
    /// The bundled Mozilla root set (`webpki-roots`). Hermetic — no
    /// dependence on the host trust store.
    Webpki,
    /// A specific PEM CA bundle on disk. For private CAs / self-signed
    /// server certs (the common regulated-deployment shape).
    CaFile(PathBuf),
}

/// TLS settings for a Postgres source connection.
#[derive(Debug, Clone)]
pub struct PgTls {
    /// Where to load trust anchors from.
    pub roots: TlsRoots,
    /// **DANGER** — skip server-certificate verification entirely.
    /// Dev/test only (e.g. a throwaway self-signed server). Never set
    /// this in production: it defeats the point of TLS (MITM-open).
    pub accept_invalid_certs: bool,
}

impl Default for PgTls {
    fn default() -> Self {
        // Native store + full verification: the secure default. Servers
        // with a private CA opt into `CaFile`; dev uses `accept_invalid_certs`.
        Self {
            roots: TlsRoots::Native,
            accept_invalid_certs: false,
        }
    }
}

/// Install rustls's `ring` crypto provider as the process default,
/// idempotently. Mirrors `dataglot_ballista::tls::install_default_crypto_provider`.
fn install_default_crypto_provider() {
    // Err == "already installed" — we only need *some* provider live.
    let _ = rustls::crypto::ring::default_provider().install_default();
}

impl PgTls {
    /// Build a [`MakeRustlsConnect`] for `tokio_postgres::Config::connect`.
    ///
    /// # Errors
    /// Returns [`DataglotError::Configuration`] if the native trust store
    /// or a CA file can't be loaded / contains no usable certificates.
    pub(crate) fn make_connector(&self) -> DataglotResult<MakeRustlsConnect> {
        install_default_crypto_provider();

        let config = if self.accept_invalid_certs {
            let provider = rustls::crypto::ring::default_provider();
            ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoCertVerification(Arc::new(provider))))
                .with_no_client_auth()
        } else {
            let roots = self.load_roots()?;
            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth()
        };

        Ok(MakeRustlsConnect::new(config))
    }

    /// Assemble the [`RootCertStore`] from the configured [`TlsRoots`].
    fn load_roots(&self) -> DataglotResult<RootCertStore> {
        let mut store = RootCertStore::empty();
        match &self.roots {
            TlsRoots::Native => {
                let result = rustls_native_certs::load_native_certs();
                // `load_native_certs` is best-effort: it returns whatever
                // it could parse plus a list of per-cert errors. We accept
                // the certs and only fail if the store ends up empty.
                let (added, _ignored) = store.add_parsable_certificates(result.certs);
                if added == 0 {
                    return Err(DataglotError::configuration(
                        "postgres TLS: no usable certificates in the OS trust store",
                    ));
                }
            }
            TlsRoots::Webpki => {
                store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            }
            TlsRoots::CaFile(path) => {
                let certs = load_ca_file(path)?;
                let (added, _ignored) = store.add_parsable_certificates(certs);
                if added == 0 {
                    return Err(DataglotError::configuration(format!(
                        "postgres TLS: no certificates parsed from CA file {}",
                        path.display()
                    )));
                }
            }
        }
        Ok(store)
    }
}

/// Load DER certificates from a PEM CA-bundle file.
fn load_ca_file(path: &Path) -> DataglotResult<Vec<CertificateDer<'static>>> {
    let raw = std::fs::read(path).map_err(|e| {
        DataglotError::configuration(format!(
            "postgres TLS: cannot read CA file {}: {e}",
            path.display()
        ))
    })?;
    let mut cursor = std::io::Cursor::new(raw);
    rustls_pemfile::certs(&mut cursor)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| {
            DataglotError::configuration(format!(
                "postgres TLS: malformed PEM in CA file {}: {e}",
                path.display()
            ))
        })
}

/// Certificate verifier that accepts every server certificate.
///
/// Backs [`PgTls::accept_invalid_certs`] — **dev/test only**. Signature
/// checks still run against the crypto provider (so the handshake is
/// well-formed); only the certificate *trust-chain / hostname* check is
/// skipped.
#[derive(Debug)]
struct NoCertVerification(Arc<CryptoProvider>);

impl ServerCertVerifier for NoCertVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn webpki_roots_build_a_connector() {
        let tls = PgTls {
            roots: TlsRoots::Webpki,
            accept_invalid_certs: false,
        };
        // Bundled Mozilla roots are always present and non-empty.
        assert!(tls.make_connector().is_ok());
    }

    #[test]
    fn accept_invalid_certs_builds_without_roots() {
        let tls = PgTls {
            // Roots are irrelevant when verification is disabled.
            roots: TlsRoots::CaFile(PathBuf::from("/nonexistent")),
            accept_invalid_certs: true,
        };
        assert!(tls.make_connector().is_ok());
    }

    #[test]
    fn native_roots_build_a_connector() {
        // The CI/dev host has an OS trust store; assert it loads.
        let tls = PgTls {
            roots: TlsRoots::Native,
            accept_invalid_certs: false,
        };
        assert!(tls.make_connector().is_ok());
    }

    #[test]
    fn missing_ca_file_is_a_clear_error() {
        let tls = PgTls {
            roots: TlsRoots::CaFile(PathBuf::from("/definitely/not/here.pem")),
            accept_invalid_certs: false,
        };
        // `.map(|_| ())` discards the non-`Debug` `MakeRustlsConnect` so
        // `unwrap_err` has a `Debug` Ok type to format on the (unexpected)
        // success path.
        let err = tls.make_connector().map(|_| ()).unwrap_err().to_string();
        assert!(err.contains("CA file"), "{err}");
    }

    #[test]
    fn empty_ca_file_is_rejected() {
        use std::io::Write;
        // NamedTempFile auto-deletes on drop — survives a test panic.
        let mut file = tempfile::NamedTempFile::new().unwrap();
        writeln!(file, "not a certificate").unwrap();
        let tls = PgTls {
            roots: TlsRoots::CaFile(file.path().to_path_buf()),
            accept_invalid_certs: false,
        };
        let err = tls.make_connector().map(|_| ()).unwrap_err().to_string();
        assert!(err.contains("no certificates parsed"), "{err}");
    }
}

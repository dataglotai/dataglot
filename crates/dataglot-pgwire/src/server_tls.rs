//! TLS for the pgwire **ingress** socket (client↔server),.
//!
//! Builds a [`TlsAcceptor`] from an operator-supplied PEM cert chain +
//! private key so `process_socket` can terminate TLS on the listening
//! socket — encrypting the MD5 handshake and all query results, which
//! otherwise cross the client link in plaintext.
//!
//! Uses rustls's **ring** provider, matching the rest of the workspace
//! (`pg_tls` / `mysql_tls` / `dataglot-ballista`). This is the
//! *server*-side counterpart to the connectors' *client*-side TLS.

use std::io;
use std::path::Path;
use std::sync::Arc;

use pgwire::tokio::TlsAcceptor;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;

use crate::error::{PgWireError, Result};

/// Install rustls's `ring` crypto provider as the process default,
/// idempotently (shared workspace idiom).
fn install_default_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

fn cfg_err(msg: impl Into<String>) -> PgWireError {
    PgWireError::Io(io::Error::new(io::ErrorKind::InvalidInput, msg.into()))
}

/// Load the PEM certificate chain at `path`.
fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let data = std::fs::read(path).map_err(|e| {
        cfg_err(format!(
            "pgwire TLS: cannot read cert file {}: {e}",
            path.display()
        ))
    })?;
    let certs = rustls_pemfile::certs(&mut io::Cursor::new(data))
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| {
            cfg_err(format!(
                "pgwire TLS: malformed cert PEM {}: {e}",
                path.display()
            ))
        })?;
    if certs.is_empty() {
        return Err(cfg_err(format!(
            "pgwire TLS: no certificates in {}",
            path.display()
        )));
    }
    Ok(certs)
}

/// Load a single PEM private key at `path`.
fn load_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let data = std::fs::read(path).map_err(|e| {
        cfg_err(format!(
            "pgwire TLS: cannot read key file {}: {e}",
            path.display()
        ))
    })?;
    rustls_pemfile::private_key(&mut io::Cursor::new(data))
        .map_err(|e| {
            cfg_err(format!(
                "pgwire TLS: malformed key PEM {}: {e}",
                path.display()
            ))
        })?
        .ok_or_else(|| cfg_err(format!("pgwire TLS: no private key in {}", path.display())))
}

/// Build a [`TlsAcceptor`] from a PEM cert chain + private key on disk.
///
/// Blocking (reads + parses files) — call it off the async executor
/// (`spawn_blocking`) at boot, not per connection (hard rule 11).
///
/// # Errors
/// Returns a [`PgWireError::Io`] if a file can't be read, the PEM is
/// malformed, no cert / key is present, or the cert/key don't form a
/// valid keypair.
pub fn build_tls_acceptor(cert_path: &Path, key_path: &Path) -> Result<TlsAcceptor> {
    install_default_crypto_provider();
    let certs = load_certs(cert_path)?;
    let key = load_key(key_path)?;
    let config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|e| cfg_err(format!("pgwire TLS: protocol versions: {e}")))?
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| cfg_err(format!("pgwire TLS: invalid cert/key pair: {e}")))?;
    Ok(TlsAcceptor::from(Arc::new(config)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_cert_file_is_a_clear_error() {
        let err = build_tls_acceptor(
            Path::new("/definitely/nope.crt"),
            Path::new("/definitely/nope.key"),
        )
        .map(|_| ())
        .unwrap_err()
        .to_string();
        assert!(err.contains("cert file"), "{err}");
    }

    #[test]
    fn empty_cert_file_is_rejected() {
        use std::io::Write;
        let mut cert = tempfile::NamedTempFile::new().unwrap();
        writeln!(cert, "not a certificate").unwrap();
        let mut key = tempfile::NamedTempFile::new().unwrap();
        writeln!(key, "not a key").unwrap();
        let err = build_tls_acceptor(cert.path(), key.path())
            .map(|_| ())
            .unwrap_err()
            .to_string();
        assert!(err.contains("no certificates"), "{err}");
    }
}

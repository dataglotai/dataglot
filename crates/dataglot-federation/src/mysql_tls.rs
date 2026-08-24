//! TLS for the MySQL federation connector.
//!
//! Sibling of [`crate::pg_tls`]. Where the Postgres connector builds a
//! rustls `ClientConfig` by hand, `mysql_async` owns the whole TLS
//! handshake — we only translate our config into its [`SslOpts`]. The
//! `rustls-tls` + `ring` features on `mysql_async` (see the crate
//! `Cargo.toml`) provide the same ring-backed rustls stack the Postgres
//! path uses.
//!
//! # Trust roots
//!
//! `mysql_async`'s built-in roots are the bundled Mozilla set
//! (`webpki-roots`). A private-CA / self-signed source sets
//! [`MysqlTls::ca_file`], which replaces the built-in roots with that CA
//! bundle. [`MysqlTls::accept_invalid_certs`] disables verification —
//! **dev/test only**.

use std::path::PathBuf;

use mysql_async::SslOpts;

/// TLS settings for a MySQL source connection.
#[derive(Debug, Clone, Default)]
pub struct MysqlTls {
    /// PEM CA-bundle file for a private CA / self-signed server. `None`
    /// ⇒ the bundled Mozilla (`webpki-roots`) trust set.
    pub ca_file: Option<PathBuf>,
    /// **DANGER** — accept any server certificate and skip hostname
    /// validation. Dev/test only; never in production (MITM-open).
    pub accept_invalid_certs: bool,
}

/// Install rustls's `ring` crypto provider as the process default,
/// idempotently. `mysql_async` builds its rustls `ClientConfig` from the
/// process-default provider; without one installed, the first TLS
/// connection panics (no process-level `CryptoProvider`). The Postgres
/// connector installs the same provider via `pg_tls`; a MySQL-only
/// deployment must install it here rather than relying on that.
fn install_default_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

impl MysqlTls {
    /// Translate into `mysql_async`'s [`SslOpts`], ensuring the ring
    /// crypto provider is installed for the rustls handshake.
    pub(crate) fn to_ssl_opts(&self) -> SslOpts {
        install_default_crypto_provider();
        let mut ssl = SslOpts::default();
        if let Some(ca) = &self.ca_file {
            // Replace the bundled roots with the operator's CA bundle.
            ssl = ssl
                .with_root_certs(vec![ca.clone().into()])
                .with_disable_built_in_roots(true);
        }
        if self.accept_invalid_certs {
            ssl = ssl
                .with_danger_accept_invalid_certs(true)
                .with_danger_skip_domain_validation(true);
        }
        ssl
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_uses_built_in_roots_and_verifies() {
        let ssl = MysqlTls::default().to_ssl_opts();
        assert!(ssl.root_certs().is_empty(), "no explicit CA");
        assert!(!ssl.disable_built_in_roots(), "built-in roots kept");
        assert!(!ssl.accept_invalid_certs());
        assert!(!ssl.skip_domain_validation());
    }

    #[test]
    fn ca_file_replaces_built_in_roots() {
        let ssl = MysqlTls {
            ca_file: Some(PathBuf::from("/certs/ca.pem")),
            accept_invalid_certs: false,
        }
        .to_ssl_opts();
        assert_eq!(ssl.root_certs().len(), 1, "the CA bundle is used");
        assert!(ssl.disable_built_in_roots(), "built-in roots disabled");
        assert!(!ssl.accept_invalid_certs());
    }

    #[test]
    fn accept_invalid_disables_verification() {
        let ssl = MysqlTls {
            ca_file: None,
            accept_invalid_certs: true,
        }
        .to_ssl_opts();
        assert!(ssl.accept_invalid_certs());
        assert!(ssl.skip_domain_validation());
    }
}

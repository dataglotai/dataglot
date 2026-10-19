//! Turns `--server` plus the `PG*` environment variables into a
//! tokio-postgres `Config` and a TLS setting.
//!
//! tokio-postgres parses most of a libpq connection string, but it rejects
//! `sslmode=verify-ca` / `verify-full` and doesn't know `sslrootcert`. Those
//! two options are taken out of the string first and handled here, so a
//! connection string that works with psql works with `--server` too.

use std::path::PathBuf;

use dataglot_federation::pg_tls::{PgTls, TlsRoots};
use tokio_postgres::Config;

/// User name sent when neither the URL nor `PGUSER` has one. Matches the
/// embedded `--user` default.
const DEFAULT_USER: &str = "dataglot";

/// libpq's `sslmode` values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SslMode {
    Disable,
    Prefer,
    Require,
    VerifyCa,
    VerifyFull,
}

impl SslMode {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "disable" => Ok(Self::Disable),
            // libpq's `allow` tries plaintext first and TLS second.
            // tokio-postgres can't do that order; `prefer` connects in the
            // same cases, just encrypted when it can be.
            "allow" | "prefer" => Ok(Self::Prefer),
            "require" => Ok(Self::Require),
            "verify-ca" => Ok(Self::VerifyCa),
            "verify-full" => Ok(Self::VerifyFull),
            other => Err(format!("invalid sslmode \"{other}\"")),
        }
    }
}

/// Everything needed to open the connection.
#[derive(Debug)]
pub(super) struct Settings {
    pub config: Config,
    pub ssl_mode: SslMode,
    /// `sslrootcert`; `None` means the OS trust store.
    pub root_cert: Option<PathBuf>,
}

impl Settings {
    /// The TLS setup for this connection, or `None` for plaintext.
    ///
    /// Same rules as libpq: `prefer` and `require` encrypt without checking
    /// the server certificate, unless `require` comes with an `sslrootcert`.
    /// `verify-ca` and `verify-full` check it. rustls always checks the host
    /// name too, so `verify-ca` is as strict as `verify-full` here.
    pub fn tls(&self) -> Option<PgTls> {
        let verify = match self.ssl_mode {
            SslMode::Disable => return None,
            SslMode::Prefer => false,
            SslMode::Require => self.root_cert.is_some(),
            SslMode::VerifyCa | SslMode::VerifyFull => true,
        };
        let roots = self
            .root_cert
            .clone()
            .map_or(TlsRoots::Native, TlsRoots::CaFile);
        Some(PgTls {
            roots,
            accept_invalid_certs: !verify,
        })
    }
}

/// Build the connection settings from `server` and, for anything it leaves
/// out, the `PG*` variables `env` returns.
///
/// The environment only fills gaps: a value in `server` always wins.
pub(super) fn resolve(
    server: &str,
    env: &dyn Fn(&str) -> Option<String>,
) -> Result<Settings, String> {
    let (mut rest, options) = take_libpq_options(server)?;
    let env_port: Option<u16> = env("PGPORT")
        .map(|port| {
            port.parse()
                .map_err(|_| format!("PGPORT is not a valid port: \"{port}\""))
        })
        .transpose()?;
    if let Some(port) = env_port {
        // tokio-postgres gives every URL host an explicit 5432, so a missing
        // port has to be filled in before parsing.
        rest = fill_url_ports(&rest, port);
    }
    let mut config: Config = rest
        .parse()
        .map_err(|e: tokio_postgres::Error| super::describe(&e))?;

    if config.get_user().is_none() {
        config.user(env("PGUSER").as_deref().unwrap_or(DEFAULT_USER));
    }
    if config.get_hosts().is_empty() && config.get_hostaddrs().is_empty() {
        config.host(env("PGHOST").as_deref().unwrap_or("localhost"));
    }
    if config.get_ports().is_empty() {
        if let Some(port) = env_port {
            config.port(port);
        }
    }
    if config.get_password().is_none() {
        if let Some(password) = env("PGPASSWORD") {
            config.password(password);
        }
    }
    if config.get_dbname().is_none() {
        if let Some(dbname) = env("PGDATABASE") {
            config.dbname(dbname);
        }
    }

    let ssl_mode = match options.ssl_mode.or_else(|| env("PGSSLMODE")) {
        Some(value) => SslMode::parse(&value)?,
        None => SslMode::Prefer,
    };
    config.ssl_mode(match ssl_mode {
        SslMode::Disable => tokio_postgres::config::SslMode::Disable,
        SslMode::Prefer => tokio_postgres::config::SslMode::Prefer,
        SslMode::Require | SslMode::VerifyCa | SslMode::VerifyFull => {
            tokio_postgres::config::SslMode::Require
        }
    });

    // libpq's `sslrootcert=system` means the OS store, which is the default.
    let root_cert = options
        .root_cert
        .or_else(|| env("PGSSLROOTCERT"))
        .filter(|path| path != "system")
        .map(PathBuf::from);

    Ok(Settings {
        config,
        ssl_mode,
        root_cert,
    })
}

/// The options tokio-postgres can't take, removed from the string.
#[derive(Debug, Default, PartialEq, Eq)]
struct LibpqOptions {
    ssl_mode: Option<String>,
    root_cert: Option<String>,
}

impl LibpqOptions {
    /// Record `key=value` if it's one of ours. Returns whether it was.
    fn take(&mut self, key: &str, value: String) -> bool {
        match key {
            "sslmode" => self.ssl_mode = Some(value),
            "sslrootcert" => self.root_cert = Some(value),
            _ => return false,
        }
        true
    }
}

/// Split `sslmode` and `sslrootcert` off a URL or `key=value` string.
///
/// A `key=value` string this can't tokenize is returned unchanged, so
/// tokio-postgres reports the problem in its own words.
fn take_libpq_options(server: &str) -> Result<(String, LibpqOptions), String> {
    if server.starts_with("postgres://") || server.starts_with("postgresql://") {
        take_from_url(server)
    } else {
        Ok(take_from_key_value(server)
            .unwrap_or_else(|| (server.to_string(), LibpqOptions::default())))
    }
}

fn take_from_url(url: &str) -> Result<(String, LibpqOptions), String> {
    let mut options = LibpqOptions::default();
    let Some((base, query)) = url.split_once('?') else {
        return Ok((url.to_string(), options));
    };
    let mut kept = Vec::new();
    for pair in query.split('&') {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        if !options.take(&percent_decode(key)?, percent_decode(value)?) {
            kept.push(pair);
        }
    }
    if kept.is_empty() {
        Ok((base.to_string(), options))
    } else {
        Ok((format!("{base}?{}", kept.join("&")), options))
    }
}

/// libpq `key=value` tokenizer: whitespace between pairs, optional
/// whitespace around `=`, values either bare or single-quoted, `\` escapes
/// the next character. Pairs we don't take are copied through as written.
fn take_from_key_value(s: &str) -> Option<(String, LibpqOptions)> {
    let mut options = LibpqOptions::default();
    let mut kept: Vec<&str> = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    loop {
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i == bytes.len() {
            break;
        }
        let start = i;
        while i < bytes.len() && bytes[i] != b'=' && !bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        let key = &s[start..i];
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if key.is_empty() || bytes.get(i) != Some(&b'=') {
            return None;
        }
        i += 1;
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        let quoted = bytes.get(i) == Some(&b'\'');
        if quoted {
            i += 1;
        }
        let mut value = String::new();
        let mut closed = !quoted;
        while i < bytes.len() {
            let c = bytes[i];
            if quoted && c == b'\'' {
                i += 1;
                closed = true;
                break;
            }
            if !quoted && c.is_ascii_whitespace() {
                break;
            }
            if c == b'\\' {
                i += 1;
            }
            // Only ASCII bytes are special, so copying whole UTF-8
            // characters keeps multi-byte values intact.
            let ch = s.get(i..)?.chars().next()?;
            value.push(ch);
            i += ch.len_utf8();
        }
        if !closed {
            return None;
        }
        if !options.take(key, value) {
            kept.push(&s[start..i]);
        }
    }
    Some((kept.join(" "), options))
}

/// Give each host in a URL that has no port `:{port}`. Leaves the URL alone
/// if it isn't one, has no host, or sets `port=` in its query.
fn fill_url_ports(url: &str, port: u16) -> String {
    let Some(scheme_end) = url.find("://").map(|i| i + 3) else {
        return url.to_string();
    };
    let (head, tail) = url.split_at(scheme_end);
    let authority_end = tail.find(['/', '?']).unwrap_or(tail.len());
    let (authority, path) = tail.split_at(authority_end);
    let query = path.split_once('?').map_or("", |(_, q)| q);
    if query
        .split('&')
        .any(|pair| pair.split('=').next() == Some("port"))
    {
        return url.to_string();
    }
    let (userinfo, hosts) = match authority.rfind('@') {
        Some(at) => authority.split_at(at + 1),
        None => ("", authority),
    };
    if hosts.is_empty() {
        return url.to_string();
    }
    let hosts: Vec<String> = hosts
        .split(',')
        .map(|chunk| {
            let has_port = match chunk.rfind(']') {
                // [ipv6] or [ipv6]:port
                Some(close) => chunk[close + 1..].starts_with(':'),
                None => chunk.contains(':'),
            };
            if has_port || chunk.is_empty() {
                chunk.to_string()
            } else {
                format!("{chunk}:{port}")
            }
        })
        .collect();
    format!("{head}{userinfo}{}{path}", hosts.join(","))
}

fn percent_decode(s: &str) -> Result<String, String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = s
                .get(i + 1..i + 3)
                .and_then(|h| u8::from_str_radix(h, 16).ok())
                .ok_or_else(|| "invalid percent-encoding in --server".to_string())?;
            out.push(hex);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| "invalid percent-encoding in --server".to_string())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn resolve_with(server: &str, vars: &[(&str, &str)]) -> Result<Settings, String> {
        let vars: HashMap<String, String> = vars
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
        resolve(server, &|key| vars.get(key).cloned())
    }

    #[test]
    fn url_options_are_taken_out_and_the_rest_kept() {
        let (rest, options) = take_libpq_options(
            "postgres://u@h/db?sslmode=verify-full&application_name=cli&sslrootcert=%2Ftmp%2Fca.pem",
        )
        .expect("parse");
        assert_eq!(rest, "postgres://u@h/db?application_name=cli");
        assert_eq!(options.ssl_mode.as_deref(), Some("verify-full"));
        assert_eq!(options.root_cert.as_deref(), Some("/tmp/ca.pem"));

        let (rest, _) = take_libpq_options("postgres://u@h/db?sslmode=require").expect("parse");
        assert_eq!(rest, "postgres://u@h/db");
    }

    #[test]
    fn key_value_options_are_taken_out_and_the_rest_kept() {
        let (rest, options) = take_libpq_options(
            "host=h  sslmode = verify-ca user='a b' sslrootcert='/path/with space/ca.pem'",
        )
        .expect("parse");
        assert_eq!(rest, "host=h user='a b'");
        assert_eq!(options.ssl_mode.as_deref(), Some("verify-ca"));
        assert_eq!(
            options.root_cert.as_deref(),
            Some("/path/with space/ca.pem")
        );
    }

    #[test]
    fn key_value_escapes_and_unicode_survive() {
        let (rest, options) =
            take_libpq_options(r"password='it\'s' sslrootcert=/tmp/zertifikat-ä.pem dbname=x")
                .expect("parse");
        assert_eq!(rest, r"password='it\'s' dbname=x");
        assert_eq!(options.root_cert.as_deref(), Some("/tmp/zertifikat-ä.pem"));
    }

    #[test]
    fn malformed_key_value_is_left_for_tokio_postgres() {
        let (rest, options) = take_libpq_options("host=h user='unterminated").expect("parse");
        assert_eq!(rest, "host=h user='unterminated");
        assert_eq!(options, LibpqOptions::default());
        assert!(resolve_with("host=h user='unterminated", &[]).is_err());
    }

    #[test]
    fn defaults_without_url_or_env() {
        let s = resolve_with("postgres://", &[]).expect("resolve");
        assert_eq!(s.config.get_user(), Some("dataglot"));
        assert_eq!(super::super::target(&s.config), "localhost:5432");
        assert_eq!(s.ssl_mode, SslMode::Prefer);
        assert!(s.root_cert.is_none());
    }

    #[test]
    fn env_fills_only_what_the_url_leaves_out() {
        let env = [
            ("PGUSER", "envuser"),
            ("PGHOST", "envhost"),
            ("PGPORT", "6000"),
            ("PGPASSWORD", "envpw"),
            ("PGDATABASE", "envdb"),
            ("PGSSLMODE", "require"),
            ("PGSSLROOTCERT", "/env/ca.pem"),
        ];
        let s = resolve_with("postgres://", &env).expect("resolve");
        assert_eq!(s.config.get_user(), Some("envuser"));
        assert_eq!(super::super::target(&s.config), "envhost:6000");
        assert_eq!(s.config.get_password(), Some(&b"envpw"[..]));
        assert_eq!(s.config.get_dbname(), Some("envdb"));
        assert_eq!(s.ssl_mode, SslMode::Require);
        assert_eq!(s.root_cert, Some(PathBuf::from("/env/ca.pem")));

        let s = resolve_with(
            "postgres://u:pw@h:7000/db?sslmode=disable&sslrootcert=/url/ca.pem",
            &env,
        )
        .expect("resolve");
        assert_eq!(s.config.get_user(), Some("u"));
        assert_eq!(super::super::target(&s.config), "h:7000");
        assert_eq!(s.config.get_password(), Some(&b"pw"[..]));
        assert_eq!(s.config.get_dbname(), Some("db"));
        assert_eq!(s.ssl_mode, SslMode::Disable);
        assert_eq!(s.root_cert, Some(PathBuf::from("/url/ca.pem")));
    }

    #[test]
    fn pgport_fills_url_hosts_without_a_port() {
        let port = [("PGPORT", "6000")];
        let target =
            |url: &str| super::super::target(&resolve_with(url, &port).expect("resolve").config);
        assert_eq!(target("postgres://h/db"), "h:6000");
        assert_eq!(target("postgres://u:p@h"), "h:6000");
        assert_eq!(target("postgres://[::1]/db"), "[::1]:6000");
        assert_eq!(target("postgres://h:7000/db"), "h:7000");
        assert_eq!(target("host=h"), "h:6000");
        assert_eq!(target("host=h port=7000"), "h:7000");
        assert_eq!(
            fill_url_ports("postgres://a,b:7000/db", 6000),
            "postgres://a:6000,b:7000/db"
        );
    }

    #[test]
    fn bad_values_are_errors() {
        let err = resolve_with("postgres://h?sslmode=sometimes", &[]).expect_err("sslmode");
        assert_eq!(err, "invalid sslmode \"sometimes\"");
        let err = resolve_with("postgres://h", &[("PGPORT", "nope")]).expect_err("port");
        assert_eq!(err, "PGPORT is not a valid port: \"nope\"");
        assert!(resolve_with("postgres://h?sslrootcert=%zz", &[]).is_err());
    }

    #[test]
    fn tls_follows_libpq() {
        let tls = |url: &str| resolve_with(url, &[]).expect("resolve").tls();

        assert!(tls("postgres://h?sslmode=disable").is_none());

        // prefer and require encrypt but don't check the certificate...
        for mode in ["prefer", "allow", "require"] {
            let t = tls(&format!("postgres://h?sslmode={mode}")).expect("tls");
            assert!(t.accept_invalid_certs, "{mode}");
        }
        // ...unless require comes with a root certificate.
        let t = tls("postgres://h?sslmode=require&sslrootcert=/ca.pem").expect("tls");
        assert!(!t.accept_invalid_certs);
        assert!(matches!(t.roots, TlsRoots::CaFile(ref p) if p == &PathBuf::from("/ca.pem")));

        for mode in ["verify-ca", "verify-full"] {
            let t = tls(&format!("postgres://h?sslmode={mode}")).expect("tls");
            assert!(!t.accept_invalid_certs, "{mode}");
            assert!(matches!(t.roots, TlsRoots::Native), "{mode}");
        }
        let t = tls("postgres://h?sslmode=verify-full&sslrootcert=system").expect("tls");
        assert!(matches!(t.roots, TlsRoots::Native));
    }
}

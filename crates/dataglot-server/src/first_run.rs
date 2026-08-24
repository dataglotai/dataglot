//! First-run ergonomics: a copy-pasteable starter config and a
//! no-catalogs boot banner.
//!
//! A developer who grabs the binary or `docker run`s the image should
//! never hit a silent dead end. Two touch-points live here:
//!
//! - [`EXAMPLE_CONFIG_TOML`] / [`print_example_config`] — `dataglot
//!   --print-example-config` emits a commented, immediately-loadable
//!   starter `dataglot.toml`.
//! - [`no_catalogs_banner`] — when the server boots with zero catalogs,
//!   `main` logs this so the operator sees *what's running* and *the one
//!   command to fix it*, not silence.
//!
//! The config format is TOML, so the example is commented with
//! real `#` comments; JSON configs still load via extension dispatch in
//! `ServerConfig::load_from_file`, but TOML is the canonical/emitted form.

/// A minimal, immediately-loadable starter config (TOML).
///
/// One Postgres catalog wired through `dsn_env` (rule 12 — no inline
/// secrets) plus one column-mask example. Redirect it to a file to get
/// going:
///
/// ```text
/// dataglot --print-example-config > dataglot.toml
/// ```
pub const EXAMPLE_CONFIG_TOML: &str = r#"# Dataglot starter config. Full reference: docs/configuration.md
# Secrets are NEVER written here: every credential has an *_env twin naming an
# environment variable the server reads at boot.

host = "127.0.0.1"
port = 5432
batch_size = 8192
default_catalog = "pg"
default_schema = "public"

# How clients authenticate to the pgwire port. `trust` (the default) accepts any
# username with no password — dev only. `md5` requires each connecting user to
# complete a Postgres MD5 password exchange against an identity below. For
# production also add a [pgwire_tls] block so the hash isn't sent in the clear.
[auth]
mode = "md5"

# Login identities for `md5` mode. The password itself is NEVER written here —
# `password_env` names an environment variable the server reads at boot. `org`
# and `groups` are optional. Runtime `CREATE USER ... WITH PASSWORD '...'` adds
# more identities without a restart (meta store) — see docs/authentication.md.
#   export DATAGLOT_ADMIN_PW='choose-a-strong-secret'   # before boot; never logged
[identities.admin]
password_env = "DATAGLOT_ADMIN_PW"

# Each key under [catalogs] is a catalog you query as
#   SELECT ... FROM <name>.<schema>.<table>
#   export DATAGLOT_PG_DSN='host=localhost port=5432 user=me password=... dbname=mydb'
[catalogs.pg]
kind = "postgres"
dsn_env = "DATAGLOT_PG_DSN"

# Optional plan-time column masking — delete this block if you don't need
# governance yet. Every query selecting users.email sees the literal instead.
[[masks]]
table = "users"
column = "email"
mask_literal = "***@example.com"
"#;

/// Print the starter config to stdout (for `--print-example-config`).
///
/// stdout only — so `dataglot --print-example-config > dataglot.toml`
/// captures exactly the file with nothing else mixed in. Writes through
/// a `stdout` handle rather than `print!` (the workspace denies
/// `clippy::print_stdout`); a broken pipe (`… | head`) is ignored.
///
/// # Errors
/// Propagates a write error other than a broken pipe.
pub fn print_example_config() -> std::io::Result<()> {
    use std::io::Write;
    match std::io::stdout().write_all(EXAMPLE_CONFIG_TOML.as_bytes()) {
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
        other => other,
    }
}

/// Write the starter config to `path` (for `dataglot init`).
///
/// Refuses to clobber an existing file unless `force` — a fresh
/// `dataglot init` should never silently overwrite an operator's tuned
/// config. Returns the same bytes `--print-example-config` streams, so
/// the two entry points can't drift.
///
/// # Errors
/// - [`std::io::ErrorKind::AlreadyExists`] if `path` exists and `force`
///   is false (the caller turns this into an actionable message).
/// - any underlying write error.
pub fn write_starter_config(path: &std::path::Path, force: bool) -> std::io::Result<()> {
    if path.exists() && !force {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            format!(
                "{} already exists — pass `--force` to overwrite it",
                path.display()
            ),
        ));
    }
    std::fs::write(path, EXAMPLE_CONFIG_TOML)
}

/// The banner logged when the server boots with no catalogs configured.
///
/// Returned as a `String` (rather than logged inline) so it can be
/// unit-tested and so `main` controls the log level. Names the pgwire
/// endpoint that *is* up, states plainly that there are no catalogs, and
/// gives the exact two commands to fix it.
#[must_use]
pub fn no_catalogs_banner(host: &str, port: u16) -> String {
    format!(
        "Dataglot is running on {host}:{port} (pgwire) with 0 catalogs configured — \
         it will accept connections but has nothing to query yet.\n\
         To connect a data source:\n\
         \x20 1. dataglot --print-example-config > dataglot.toml\n\
         \x20 2. edit dataglot.toml (set your catalog's DSN env var), then export it\n\
         \x20 3. restart with:  dataglot --config dataglot.toml\n\
         Full reference: docs/configuration.md"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ServerConfig;

    #[test]
    fn example_config_is_valid_toml() {
        // Must parse as TOML at all — a broken example is worse than none.
        let v: toml::Value =
            toml::from_str(EXAMPLE_CONFIG_TOML).expect("example config must be valid TOML");
        assert!(v.is_table());
    }

    #[test]
    fn example_config_loads_as_server_config() {
        // The whole point: a file produced by `--print-example-config` must
        // load cleanly. Every real field must match the config shape. If this
        // breaks, the starter we hand users is a dead end on their first
        // `--config`.
        let cfg: ServerConfig = toml::from_str(EXAMPLE_CONFIG_TOML)
            .expect("example config must deserialize into ServerConfig");
        assert_eq!(cfg.default_catalog, "pg");
        assert!(
            cfg.catalogs.contains_key("pg"),
            "starter must define the `pg` catalog"
        );
        assert_eq!(cfg.masks.len(), 1, "starter has one example mask");
        // The starter demonstrates md5 auth + one env-backed identity, so a new
        // user sees the authentication surface (not just trust mode).
        assert_eq!(
            cfg.auth.mode,
            crate::config::AuthMode::Md5,
            "starter must demonstrate md5 auth"
        );
        let admin = cfg
            .identities
            .get("admin")
            .expect("starter must define the `admin` identity");
        assert_eq!(
            admin.password_env.as_deref(),
            Some("DATAGLOT_ADMIN_PW"),
            "admin identity must read its password from an env var, never inline (rule 12)"
        );
    }

    #[test]
    fn write_starter_config_writes_then_refuses_without_force() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dataglot.toml");

        // First write succeeds and produces the exact starter bytes.
        write_starter_config(&path, false).expect("first write");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), EXAMPLE_CONFIG_TOML);

        // Second write refuses (AlreadyExists) rather than clobbering.
        let err = write_starter_config(&path, false).expect_err("must refuse to overwrite");
        assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);

        // …unless forced.
        write_starter_config(&path, true).expect("force overwrites");
    }

    #[test]
    fn banner_names_endpoint_and_the_fix_command() {
        let banner = no_catalogs_banner("127.0.0.1", 5432);
        assert!(banner.contains("127.0.0.1:5432"));
        assert!(banner.contains("0 catalogs"));
        // The actionable fix must be present verbatim.
        assert!(banner.contains("--print-example-config"));
        assert!(banner.contains("--config dataglot.toml"));
    }
}

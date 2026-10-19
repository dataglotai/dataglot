//! Named connection profiles for client mode, read from a small TOML file:
//!
//! ```toml
//! [profiles.prod]
//! url = "postgres://alice@db.example.com/files?sslmode=verify-full"
//! password_env = "DATAGLOT_PROD_PASSWORD"
//! ```
//!
//! `url` takes the same values as `--server`. Passwords never go in the
//! file: `password_env` names the environment variable that holds one, and a
//! url with a password in it is refused.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use super::{ClientError, Endpoint};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CliConfig {
    #[serde(default)]
    profiles: BTreeMap<String, Profile>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Profile {
    url: String,
    password_env: Option<String>,
}

/// Where the profiles file is: `DATAGLOT_CLI_CONFIG` if set, otherwise
/// `%APPDATA%\dataglot\cli.toml` on Windows and
/// `$XDG_CONFIG_HOME/dataglot/cli.toml` or `~/.config/dataglot/cli.toml`
/// everywhere else.
fn config_path(env: &dyn Fn(&str) -> Option<String>, windows: bool) -> Option<PathBuf> {
    let set = |key: &str| env(key).filter(|value| !value.is_empty());
    if let Some(path) = set("DATAGLOT_CLI_CONFIG") {
        return Some(PathBuf::from(path));
    }
    let base = if windows {
        PathBuf::from(set("APPDATA")?)
    } else if let Some(xdg) = set("XDG_CONFIG_HOME") {
        PathBuf::from(xdg)
    } else {
        PathBuf::from(set("HOME")?).join(".config")
    };
    Some(base.join("dataglot").join("cli.toml"))
}

/// Look up profile `name` in the default profiles file.
pub(super) fn load(name: &str) -> Result<Endpoint, ClientError> {
    let env = |key: &str| std::env::var(key).ok();
    let path = config_path(&env, cfg!(windows)).ok_or_else(|| {
        ClientError::Profile(
            "can't tell where the profiles file is; set DATAGLOT_CLI_CONFIG to its path"
                .to_string(),
        )
    })?;
    load_from(&path, name, &env)
}

/// Look up profile `name` in the file at `path`. `env` supplies the
/// variable that `password_env` names.
pub(super) fn load_from(
    path: &Path,
    name: &str,
    env: &dyn Fn(&str) -> Option<String>,
) -> Result<Endpoint, ClientError> {
    let fail = |message: String| ClientError::Profile(message);
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(fail(format!(
                "no profiles file at {} (set DATAGLOT_CLI_CONFIG to use another one)",
                path.display()
            )));
        }
        Err(e) => return Err(fail(format!("can't read {}: {e}", path.display()))),
    };
    let config: CliConfig =
        toml::from_str(&text).map_err(|e| fail(parse_error(path, &text, &e)))?;

    let Some(profile) = config.profiles.get(name) else {
        let known: Vec<&str> = config.profiles.keys().map(String::as_str).collect();
        return Err(fail(if known.is_empty() {
            format!("no profiles in {}", path.display())
        } else {
            format!(
                "no profile \"{name}\" in {} (profiles there: {})",
                path.display(),
                known.join(", ")
            )
        }));
    };

    // Parse with an empty environment so only the url itself counts.
    let parsed = super::settings::resolve(&profile.url, &|_| None)
        .map_err(|e| fail(format!("profile \"{name}\": invalid url: {e}")))?;
    if parsed.config.get_password().is_some() {
        return Err(fail(format!(
            "profile \"{name}\" has a password in its url; keep it in an environment \
             variable and name that variable with password_env"
        )));
    }

    let password = match &profile.password_env {
        None => None,
        Some(var) => match env(var).filter(|value| !value.is_empty()) {
            Some(password) => Some(password),
            None => {
                return Err(fail(format!(
                    "profile \"{name}\" reads its password from {var}, which isn't set"
                )));
            }
        },
    };
    Ok(Endpoint {
        server: profile.url.clone(),
        password,
    })
}

/// toml's own `Display` quotes the line it choked on, and that line may be
/// a password someone put in the file by mistake. Say which line instead.
fn parse_error(path: &Path, text: &str, e: &toml::de::Error) -> String {
    let message = without_value(e.message());
    match e.span() {
        Some(span) => {
            let before = text.get(..span.start).unwrap_or(text);
            let line = before.matches('\n').count() + 1;
            format!("{}, line {line}: {message}", path.display())
        }
        None => format!("{}: {message}", path.display()),
    }
}

/// serde puts the value it got into type errors (`invalid type: string
/// "...", expected a map`). Keep what kind of value it was, drop the value.
fn without_value(message: &str) -> String {
    for prefix in ["invalid type: ", "invalid value: "] {
        if let Some(rest) = message.strip_prefix(prefix) {
            // The expected part comes from our own types, so split at the
            // last one in case the value contains ", expected " itself.
            let (found, expected) = rest.rsplit_once(", expected ").unwrap_or((rest, ""));
            let kind = found
                .split(['"', '`'])
                .next()
                .unwrap_or_default()
                .trim_end();
            return if expected.is_empty() {
                format!("{prefix}{kind}")
            } else {
                format!("{prefix}{kind}, expected {expected}")
            };
        }
    }
    message.to_string()
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn env_of(vars: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let vars: HashMap<String, String> = vars
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
        move |key| vars.get(key).cloned()
    }

    fn write(dir: &tempfile::TempDir, text: &str) -> PathBuf {
        let path = dir.path().join("cli.toml");
        std::fs::write(&path, text).expect("write profiles file");
        path
    }

    fn message(result: Result<Endpoint, ClientError>) -> String {
        match result {
            Ok(_) => panic!("expected an error"),
            Err(e) => {
                assert!(matches!(e, ClientError::Profile(_)), "{e:?}");
                e.to_string()
            }
        }
    }

    #[test]
    fn config_path_prefers_the_override_then_the_platform_default() {
        let path = |vars: &[(&str, &str)], windows| config_path(&env_of(vars), windows);
        assert_eq!(
            path(
                &[("DATAGLOT_CLI_CONFIG", "/x/cli.toml"), ("HOME", "/h")],
                false
            ),
            Some(PathBuf::from("/x/cli.toml"))
        );
        assert_eq!(
            path(&[("HOME", "/h")], false),
            Some(PathBuf::from("/h/.config/dataglot/cli.toml"))
        );
        assert_eq!(
            path(&[("HOME", "/h"), ("XDG_CONFIG_HOME", "/xdg")], false),
            Some(PathBuf::from("/xdg/dataglot/cli.toml"))
        );
        assert_eq!(
            path(&[("APPDATA", "C:/Users/a/AppData/Roaming")], true),
            Some(PathBuf::from(
                "C:/Users/a/AppData/Roaming/dataglot/cli.toml"
            ))
        );
        // An empty variable counts as unset.
        assert_eq!(
            path(&[("DATAGLOT_CLI_CONFIG", ""), ("HOME", "")], false),
            None
        );
        assert_eq!(path(&[], true), None);
    }

    #[test]
    fn a_profile_resolves_with_its_password() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = write(
            &dir,
            r#"
            [profiles.prod]
            url = "postgres://alice@db.example.com/files?sslmode=verify-full"
            password_env = "PROD_PW"

            [profiles.local]
            url = "host=localhost user=admin"
            "#,
        );
        let env = env_of(&[("PROD_PW", "s3cret")]);

        let prod = load_from(&path, "prod", &env).expect("prod");
        assert_eq!(
            prod.server,
            "postgres://alice@db.example.com/files?sslmode=verify-full"
        );
        assert_eq!(prod.password.as_deref(), Some("s3cret"));

        let local = load_from(&path, "local", &env).expect("local");
        assert_eq!(local.server, "host=localhost user=admin");
        assert!(local.password.is_none());
    }

    #[test]
    fn unknown_profile_lists_the_known_ones() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = write(
            &dir,
            "[profiles.b]\nurl = \"postgres://h\"\n[profiles.a]\nurl = \"postgres://h\"\n",
        );
        let err = message(load_from(&path, "c", &env_of(&[])));
        assert!(err.contains("no profile \"c\""), "{err}");
        assert!(err.ends_with("(profiles there: a, b)"), "{err}");

        let empty = write(&dir, "");
        let err = message(load_from(&empty, "c", &env_of(&[])));
        assert!(err.starts_with("no profiles in "), "{err}");
    }

    #[test]
    fn a_missing_file_says_where_it_looked() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("nope.toml");
        let err = message(load_from(&path, "prod", &env_of(&[])));
        assert!(err.contains(&path.display().to_string()), "{err}");
        assert!(err.contains("DATAGLOT_CLI_CONFIG"), "{err}");
    }

    #[test]
    fn passwords_in_the_file_are_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        for url in ["postgres://alice:s3cret@h/db", "host=h password=s3cret"] {
            let path = write(&dir, &format!("[profiles.p]\nurl = \"{url}\"\n"));
            let err = message(load_from(&path, "p", &env_of(&[])));
            assert!(err.contains("has a password in its url"), "{url}: {err}");
            assert!(
                !err.contains("s3cret"),
                "the password must not be echoed: {err}"
            );
        }
    }

    /// A broken file must not put its contents on stderr: the line toml
    /// stopped at may be a password.
    #[test]
    fn parse_errors_say_which_line_without_echoing_it() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cases = [
            (
                "[profiles.p]\nurl = \"postgres://h\"\npassword = \"s3cret-PROD-pw\"\n",
                "line 3: unknown field `password`, expected `url` or `password_env`",
            ),
            (
                "[profiles.p]\nurl = \"postgres://h\"\npassword = s3cret-PROD-pw\n",
                "line 3: string values must be quoted",
            ),
            (
                "profiles = \"s3cret-PROD-pw\"\n",
                "line 1: invalid type: string, expected a map",
            ),
            (
                "[profiles.p]\nurl = \"postgres://h\"\npassword_env = 20481024\n",
                "line 3: invalid type: integer, expected a string",
            ),
        ];
        for (text, expected) in cases {
            let path = write(&dir, text);
            let err = message(load_from(&path, "p", &env_of(&[])));
            assert!(err.contains(expected), "{text:?}: {err}");
            assert!(
                !err.contains("s3cret") && !err.contains("20481024"),
                "the value must not be echoed: {err}"
            );
        }
    }

    #[test]
    fn without_value_keeps_the_kind_and_drops_the_value() {
        assert_eq!(
            without_value("invalid type: string \"a, expected b\", expected a map"),
            "invalid type: string, expected a map"
        );
        assert_eq!(
            without_value("invalid type: floating point `1.5`, expected a string"),
            "invalid type: floating point, expected a string"
        );
        assert_eq!(
            without_value("unknown field `x`, expected `url`"),
            "unknown field `x`, expected `url`"
        );
    }

    #[test]
    fn an_unset_password_env_is_an_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = write(
            &dir,
            "[profiles.p]\nurl = \"postgres://h\"\npassword_env = \"P_PW\"\n",
        );
        let err = message(load_from(&path, "p", &env_of(&[])));
        assert_eq!(
            err,
            "profile \"p\" reads its password from P_PW, which isn't set"
        );
        let err = message(load_from(&path, "p", &env_of(&[("P_PW", "")])));
        assert!(err.contains("which isn't set"), "{err}");
    }

    #[test]
    fn typos_and_bad_urls_are_reported() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = write(
            &dir,
            "[profiles.p]\nurl = \"postgres://h\"\npasword_env = \"X\"\n",
        );
        let err = message(load_from(&path, "p", &env_of(&[])));
        assert!(err.contains("pasword_env"), "{err}");

        let path = write(&dir, "[profiles.p]\nurl = \"postgres://h?sslmode=never\"\n");
        let err = message(load_from(&path, "p", &env_of(&[])));
        assert!(err.contains("invalid sslmode"), "{err}");
    }
}

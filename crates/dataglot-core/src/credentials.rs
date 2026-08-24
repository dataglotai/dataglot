//! Credential resolution abstraction.
//!
//! Phase 1 prep. Today every connector takes its credentials inline in
//! the config file (a raw DSN string for Postgres, a static
//! access-key/secret pair for warehouses). That works for a single-
//! tenant deployment; it stops working the moment Phase 1 introduces
//! per-tenant catalogs or vault-backed secrets.
//!
//! This module defines the abstraction Phase 1 will plug in to:
//!
//! - [`CredentialHandle`] — an opaque, named reference to a credential.
//!   Configs hold handles, not raw secrets, so that credentials never
//!   appear in `Debug`, in plan trees, in logs, or in error chains
//!   (hard rule 12).
//! - [`CredentialResolver`] — the trait every backend (env vars,
//!   Vault, AWS Secrets Manager, ...) implements. Resolution happens
//!   at execution time, not at config load.
//! - [`Credentials`] — the resolved payload typed by shape (DSN
//!   string for SQL sources, key+secret pair for object stores, an
//!   opaque token for everything else).
//! - [`StaticCredentialResolver`] — the only resolver shipped today,
//!   serving statically-loaded credentials from an in-memory map. It
//!   exists so the abstraction is exercised end-to-end by tests; the
//!   binary still uses the inline config formats from PR #50.
//!
//! The connector configs in `dataglot-server::config` and the
//! `PostgresConnector` / `WarehouseConnector` constructors deliberately
//! do NOT consume `CredentialHandle` yet — that migration is a
//! Phase 1 PR. Today the abstraction sits in core unused so Phase 1
//! has a stable shape to bind to.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Opaque, named reference to a credential.
///
/// Configs and connectors carry handles in place of the secret itself.
/// The handle's `Debug` and `Display` impls intentionally surface only
/// the name — never the resolved bytes — so accidental log statements
/// or panic messages cannot leak credentials.
///
/// Cloning a `CredentialHandle` is cheap (`Arc<str>` inside).
#[derive(Clone)]
pub struct CredentialHandle {
    name: Arc<str>,
}

impl CredentialHandle {
    /// Build a handle from a stable, human-readable name.
    ///
    /// The name is what the resolver looks up. It is the only piece of
    /// the handle that surfaces in logs.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: Arc::from(name.into()),
        }
    }

    /// Borrow the credential's lookup name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
}

impl std::fmt::Debug for CredentialHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Surface only the name, never the resolved value (which we
        // don't hold here, but the principle is what makes this safe
        // when handles flow through error chains).
        f.debug_struct("CredentialHandle")
            .field("name", &self.name)
            .finish()
    }
}

impl std::fmt::Display for CredentialHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "credential:{}", self.name)
    }
}

/// Resolved credential payload.
///
/// Typed by *shape*, not by backend. A SQL connector wants a DSN
/// string regardless of where it came from (env var, vault, k8s
/// secret); an S3-compatible connector wants `(access_key_id,
/// secret_access_key)`. Backends translate from whatever they store
/// internally into one of these variants.
///
/// `Credentials` does NOT implement `Debug` or `Serialize` — that's
/// deliberate. Anything that needs to log a credential must redact it
/// at the call site (the connectors already do this — see
/// `PostgresConnector::redacted_dsn`).
#[derive(Clone)]
pub enum Credentials {
    /// libpq-style connection string. Typical for SQL connectors.
    Dsn(String),
    /// S3 / object-store style access pair.
    AccessKey {
        /// Access key ID (typically not sensitive on its own).
        access_key_id: String,
        /// Secret access key (the sensitive half).
        secret_access_key: String,
    },
    /// Bearer token (OAuth, JWT, etc.).
    Token(String),
}

impl std::fmt::Debug for Credentials {
    /// Redacted `Debug` impl. Surfaces the variant tag and any
    /// non-sensitive identifier (e.g. `access_key_id`) but never the
    /// secret material.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Dsn(_) => f
                .debug_struct("Credentials::Dsn")
                .field("value", &"<redacted>")
                .finish(),
            Self::AccessKey { access_key_id, .. } => f
                .debug_struct("Credentials::AccessKey")
                .field("access_key_id", access_key_id)
                .field("secret_access_key", &"<redacted>")
                .finish(),
            Self::Token(_) => f
                .debug_struct("Credentials::Token")
                .field("value", &"<redacted>")
                .finish(),
        }
    }
}

/// Errors returned by `CredentialResolver` implementations.
///
/// Distinct from [`crate::DataglotError`] so resolvers can surface
/// fine-grained reasons (not found vs. backend unreachable vs. wrong
/// shape) without leaking the resolver's backend-specific details
/// into the broader error surface.
#[derive(Debug, Error)]
pub enum CredentialError {
    /// No credential is registered under that handle's name.
    #[error("credential `{0}` not found")]
    NotFound(String),
    /// The credential is registered but its resolved payload doesn't
    /// match the shape the caller asked for (e.g. asked for a DSN,
    /// got an `AccessKey`).
    #[error("credential `{name}` resolved to a different shape than requested")]
    ShapeMismatch {
        /// Handle name that was looked up.
        name: String,
    },
    /// Resolver-specific backend failure (vault unreachable, env var
    /// set to invalid UTF-8, etc.). The caller should surface this as
    /// an opaque internal error and not leak the backend's message.
    #[error("credential resolver backend error: {0}")]
    Backend(String),
}

/// Trait implemented by every credential backend.
///
/// Resolution is intentionally synchronous and infallible-on-fast-path:
/// the trait owns its source of truth (typically a small in-memory
/// map populated at boot), not a network round-trip. Backends that
/// need IO should pre-fetch at startup and refresh lazily — the
/// trait does NOT define a refresh API because that's Phase 1 design
/// space.
///
/// All implementations must be `Send + Sync + 'static` so a single
/// `Arc<dyn CredentialResolver>` can be shared across pgwire sessions
/// (hard rule 10).
pub trait CredentialResolver: Send + Sync + 'static {
    /// Look up the credential named by `handle` and return its
    /// resolved payload.
    ///
    /// # Errors
    /// Returns [`CredentialError::NotFound`] if no credential is
    /// registered, or [`CredentialError::Backend`] for resolver-
    /// specific failures.
    fn resolve(&self, handle: &CredentialHandle) -> Result<Credentials, CredentialError>;
}

/// In-memory `CredentialResolver` populated at construction time.
///
/// Used by tests today. Phase 1 will likely keep this as the default
/// resolver for single-tenant deployments and add `EnvVarResolver`
/// (env-only) and a vault-backed resolver as siblings.
#[derive(Default)]
pub struct StaticCredentialResolver {
    entries: HashMap<String, Credentials>,
}

impl StaticCredentialResolver {
    /// Build an empty resolver.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a credential under `name`. Returns the previous
    /// payload registered under that name, if any.
    pub fn insert(&mut self, name: impl Into<String>, value: Credentials) -> Option<Credentials> {
        self.entries.insert(name.into(), value)
    }

    /// Number of registered credentials.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// `true` when no credentials are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl CredentialResolver for StaticCredentialResolver {
    fn resolve(&self, handle: &CredentialHandle) -> Result<Credentials, CredentialError> {
        self.entries
            .get(handle.name())
            .cloned()
            .ok_or_else(|| CredentialError::NotFound(handle.name().to_string()))
    }
}

/// JSON-driven blueprint for an `Arc<dyn CredentialResolver>`.
///
/// Phase 2 slice 5a — the standalone executor binary takes a
/// `--credentials-config` flag pointing at a JSON file deserialised
/// into this enum. `into_resolver()` builds the resolver instance the
/// executor will share with every per-task `SessionContext`.
///
/// The fail-fast contract slice 3b architected (executor refuses to
/// register if resolver construction fails) is enforced by this
/// method's `Result` return — the binary calls it before any Ballista
/// RPC startup, so a missing config file / malformed JSON / unknown
/// variant tag exits the process non-zero before the executor ever
/// touches the scheduler.
///
/// Today only the [`CredentialResolverConfig::Static`] variant ships,
/// matching the only `CredentialResolver` impl in the crate
/// ([`StaticCredentialResolver`]). The enum is `#[serde(tag = "kind")]`
/// so future backends (`Vault`, `Env`, `Iam`, ...) can be added
/// without breaking the existing config file format.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CredentialResolverConfig {
    /// In-memory resolver. Maps handle name → credential payload.
    ///
    /// Mirrors [`StaticCredentialResolver`]. JSON example:
    ///
    /// ```json
    /// {
    ///   "kind": "static",
    ///   "entries": {
    ///     "pg_main": { "type": "dsn", "value": "postgres://user:pass@host/db" },
    ///     "warehouse_aws": {
    ///       "type": "access_key",
    ///       "access_key_id": "AKIA...",
    ///       "secret_access_key": "..."
    ///     }
    ///   }
    /// }
    /// ```
    Static {
        /// Handle name → credential payload.
        entries: HashMap<String, CredentialConfigEntry>,
    },
}

/// Wire-format credential payload, tagged by shape. Mirrors the
/// [`Credentials`] variants 1:1 with named fields so the JSON is
/// self-documenting; round-trip via [`Self::into_credentials`].
///
/// `Debug` is redacted manually so accidental log statements don't
/// leak secret material (matches [`Credentials`]'s redacted impl).
/// `Serialize` is intentionally implemented — these structs *are* the
/// JSON-on-disk shape — but should never be logged or surfaced through
/// error chains.
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CredentialConfigEntry {
    /// libpq-style DSN. Maps to [`Credentials::Dsn`].
    Dsn {
        /// Connection string. Treated as a secret in `Debug`.
        value: String,
    },
    /// S3 / object-store access key pair. Maps to
    /// [`Credentials::AccessKey`].
    AccessKey {
        /// Access key ID (typically not sensitive on its own).
        access_key_id: String,
        /// Secret access key (the sensitive half).
        secret_access_key: String,
    },
    /// Bearer token. Maps to [`Credentials::Token`].
    Token {
        /// The token value. Treated as a secret in `Debug`.
        value: String,
    },
}

impl CredentialConfigEntry {
    /// Convert this wire-format entry into the runtime [`Credentials`]
    /// shape the resolver hands back to consumers.
    #[must_use]
    pub fn into_credentials(self) -> Credentials {
        match self {
            Self::Dsn { value } => Credentials::Dsn(value),
            Self::AccessKey {
                access_key_id,
                secret_access_key,
            } => Credentials::AccessKey {
                access_key_id,
                secret_access_key,
            },
            Self::Token { value } => Credentials::Token(value),
        }
    }
}

impl std::fmt::Debug for CredentialConfigEntry {
    /// Redacted `Debug` impl — matches [`Credentials`]'s impl shape so
    /// a config entry surfaced through an error chain (e.g. parse
    /// failure) cannot leak its secret payload.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Dsn { .. } => f
                .debug_struct("CredentialConfigEntry::Dsn")
                .field("value", &"<redacted>")
                .finish(),
            Self::AccessKey { access_key_id, .. } => f
                .debug_struct("CredentialConfigEntry::AccessKey")
                .field("access_key_id", access_key_id)
                .field("secret_access_key", &"<redacted>")
                .finish(),
            Self::Token { .. } => f
                .debug_struct("CredentialConfigEntry::Token")
                .field("value", &"<redacted>")
                .finish(),
        }
    }
}

/// Errors raised when loading or materialising a
/// [`CredentialResolverConfig`].
///
/// Distinct from [`CredentialError`] (which is the resolver's *runtime*
/// error type for `resolve()` calls) — these are config-load failures
/// at executor boot time. They are what fail-fasts the executor binary
/// per slice 3b's contract: if any of these surface, the process exits
/// non-zero before the Ballista RPC handshake.
#[derive(Debug, Error)]
pub enum CredentialConfigError {
    /// Could not read the config file from disk.
    #[error("could not read credentials config from `{path}`: {source}")]
    Io {
        /// Path the executor was asked to read.
        path: String,
        /// Underlying IO failure.
        source: std::io::Error,
    },
    /// The file's bytes were not valid JSON, or did not match the
    /// expected schema (missing fields, unknown variant tags, etc.).
    #[error("could not parse credentials config from `{path}`: {source}")]
    Parse {
        /// Path the executor was asked to read.
        path: String,
        /// Underlying serde failure.
        source: serde_json::Error,
    },
}

impl CredentialResolverConfig {
    /// Load and parse the config from disk. Returns
    /// [`CredentialConfigError`] on IO or parse failure.
    ///
    /// # Errors
    /// - [`CredentialConfigError::Io`] if the file is unreadable
    ///   (missing, permission denied, ...).
    /// - [`CredentialConfigError::Parse`] if the JSON does not match
    ///   the expected schema.
    pub fn from_json_file(path: impl AsRef<Path>) -> Result<Self, CredentialConfigError> {
        let path = path.as_ref();
        let bytes = std::fs::read(path).map_err(|source| CredentialConfigError::Io {
            path: path.display().to_string(),
            source,
        })?;
        serde_json::from_slice(&bytes).map_err(|source| CredentialConfigError::Parse {
            path: path.display().to_string(),
            source,
        })
    }

    /// Materialise the config into an `Arc<dyn CredentialResolver>`.
    ///
    /// In slice 5a's minimal cut this is infallible — the only backend
    /// is `Static`, which is in-memory only. The `Result` return is
    /// forward-looking: future backends (`Vault`, `Iam`, ...) will
    /// pre-fetch their source of truth at construction time (per the
    /// [`CredentialResolver`] trait's contract), and their `new()` may
    /// fail with backend-specific errors. Returning `Result` here keeps
    /// the executor binary's fail-fast call site uniform across all
    /// future variants.
    ///
    /// # Errors
    /// Infallible today; returns `Result` for forward compatibility.
    pub fn into_resolver(self) -> Result<Arc<dyn CredentialResolver>, CredentialConfigError> {
        match self {
            Self::Static { entries } => {
                let mut resolver = StaticCredentialResolver::new();
                for (name, entry) in entries {
                    resolver.insert(name, entry.into_credentials());
                }
                Ok(Arc::new(resolver))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handle_debug_does_not_leak_resolved_value() {
        // The handle itself never holds the resolved bytes, but its
        // Debug must surface only the name to keep error chains safe.
        let h = CredentialHandle::new("pg_main");
        let debug = format!("{h:?}");
        assert!(debug.contains("pg_main"));
        // Sanity: no secret has been associated with this handle yet.
        assert_eq!(h.name(), "pg_main");
    }

    #[test]
    fn handle_display_is_name_prefixed() {
        let h = CredentialHandle::new("warehouse_aws");
        assert_eq!(h.to_string(), "credential:warehouse_aws");
    }

    #[test]
    fn credentials_debug_redacts_secret_material() {
        let dsn = Credentials::Dsn("postgres://user:hunter2@host:5432/db".into());
        let dbg = format!("{dsn:?}");
        assert!(
            !dbg.contains("hunter2"),
            "DSN secret leaked through Debug:\n{dbg}"
        );
        assert!(dbg.contains("redacted"));

        let key = Credentials::AccessKey {
            access_key_id: "AKIA1234".into(),
            secret_access_key: "very-secret".into(),
        };
        let dbg = format!("{key:?}");
        assert!(
            !dbg.contains("very-secret"),
            "secret_access_key leaked:\n{dbg}"
        );
        // access_key_id is not sensitive — should still appear
        assert!(dbg.contains("AKIA1234"), "access_key_id missing:\n{dbg}");

        let tok = Credentials::Token("eyJhbGciOiJIUzI1NiJ9.payload.sig".into());
        let dbg = format!("{tok:?}");
        assert!(!dbg.contains("eyJ"), "token leaked through Debug:\n{dbg}");
    }

    #[test]
    fn static_resolver_resolves_registered_handle() {
        let mut r = StaticCredentialResolver::new();
        r.insert(
            "pg_main",
            Credentials::Dsn("postgres://user:secret@host/db".into()),
        );
        let resolved = r
            .resolve(&CredentialHandle::new("pg_main"))
            .expect("registered handle resolves");
        assert!(matches!(resolved, Credentials::Dsn(s) if s.starts_with("postgres://")));
    }

    #[test]
    fn static_resolver_returns_not_found_for_unknown_handle() {
        let r = StaticCredentialResolver::new();
        let err = r
            .resolve(&CredentialHandle::new("missing"))
            .expect_err("unknown handle must error");
        match err {
            CredentialError::NotFound(name) => assert_eq!(name, "missing"),
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[test]
    fn static_resolver_replaces_on_re_insert() {
        let mut r = StaticCredentialResolver::new();
        r.insert("k", Credentials::Token("first".into()));
        let prev = r.insert("k", Credentials::Token("second".into()));
        assert!(matches!(prev, Some(Credentials::Token(_))));
        let now = r.resolve(&CredentialHandle::new("k")).unwrap();
        match now {
            Credentials::Token(s) => assert_eq!(s, "second"),
            other => panic!("expected Token, got {other:?}"),
        }
    }

    #[test]
    fn resolver_can_be_used_via_dyn_trait() {
        // The Phase 1 wiring will hold `Arc<dyn CredentialResolver>`,
        // so the trait must be object-safe.
        let mut r = StaticCredentialResolver::new();
        r.insert(
            "warehouse",
            Credentials::AccessKey {
                access_key_id: "AKIA".into(),
                secret_access_key: "secret".into(),
            },
        );
        let dyn_r: Arc<dyn CredentialResolver> = Arc::new(r);
        let _ = dyn_r.resolve(&CredentialHandle::new("warehouse")).unwrap();
    }

    #[test]
    fn resolver_isnt_empty_check() {
        let mut r = StaticCredentialResolver::new();
        assert!(r.is_empty());
        assert_eq!(r.len(), 0);
        r.insert("a", Credentials::Token("t".into()));
        assert!(!r.is_empty());
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn credential_error_is_debug_and_display() {
        let e = CredentialError::NotFound("k".into());
        assert!(format!("{e}").contains("not found"));
        assert!(format!("{e:?}").contains("NotFound"));

        let e = CredentialError::ShapeMismatch { name: "k".into() };
        assert!(format!("{e}").contains("different shape"));

        let e = CredentialError::Backend("vault unreachable".into());
        assert!(format!("{e}").contains("vault unreachable"));
    }

    // ---------------------------------------------------------------
    // CredentialResolverConfig — slice 5a
    // ---------------------------------------------------------------

    /// Round-trip from the JSON shape the executor binary consumes
    /// into a working resolver. Covers all three credential shapes.
    #[test]
    fn config_into_resolver_round_trips_all_shapes() {
        let json = r#"{
            "kind": "static",
            "entries": {
                "pg_main": { "type": "dsn", "value": "postgres://user:pass@host/db" },
                "warehouse": {
                    "type": "access_key",
                    "access_key_id": "AKIA",
                    "secret_access_key": "shh"
                },
                "api": { "type": "token", "value": "tok-xyz" }
            }
        }"#;

        let cfg: CredentialResolverConfig = serde_json::from_str(json).expect("config parses");
        let resolver = cfg.into_resolver().expect("infallible today");

        // Each handle resolves to its expected shape — `Credentials`
        // doesn't implement Eq so we match by variant + interior field.
        match resolver
            .resolve(&CredentialHandle::new("pg_main"))
            .expect("pg_main resolves")
        {
            Credentials::Dsn(s) => assert_eq!(s, "postgres://user:pass@host/db"),
            other => panic!("expected Dsn, got {other:?}"),
        }
        match resolver
            .resolve(&CredentialHandle::new("warehouse"))
            .expect("warehouse resolves")
        {
            Credentials::AccessKey {
                access_key_id,
                secret_access_key,
            } => {
                assert_eq!(access_key_id, "AKIA");
                assert_eq!(secret_access_key, "shh");
            }
            other => panic!("expected AccessKey, got {other:?}"),
        }
        match resolver
            .resolve(&CredentialHandle::new("api"))
            .expect("api resolves")
        {
            Credentials::Token(t) => assert_eq!(t, "tok-xyz"),
            other => panic!("expected Token, got {other:?}"),
        }
    }

    /// Unknown `kind` tag must surface as a parse error, not an
    /// `Ok(...)` with a silently-defaulted variant. Future backends
    /// (`vault`, `iam`, ...) get added explicitly to the enum; an
    /// unknown tag in a config file means the executor is older than
    /// the config — fail-fast.
    #[test]
    fn config_unknown_kind_tag_is_a_parse_error() {
        let json = r#"{ "kind": "vault_v2", "address": "https://vault.example" }"#;
        let err = serde_json::from_str::<CredentialResolverConfig>(json)
            .expect_err("unknown kind must error");
        let msg = format!("{err}");
        assert!(
            msg.contains("vault_v2"),
            "error message should name the unknown variant tag: {msg}"
        );
    }

    /// Unknown credential `type` tag inside a static entry must error
    /// rather than silently dropping the entry. Same fail-fast
    /// motivation as the unknown `kind`.
    #[test]
    fn config_unknown_entry_type_tag_is_a_parse_error() {
        let json = r#"{
            "kind": "static",
            "entries": {
                "weird": { "type": "x509", "value": "..." }
            }
        }"#;
        let err = serde_json::from_str::<CredentialResolverConfig>(json)
            .expect_err("unknown entry type must error");
        let msg = format!("{err}");
        assert!(
            msg.contains("x509"),
            "error message should name the unknown variant tag: {msg}"
        );
    }

    /// Empty `entries` map is valid (operator chose not to ship any
    /// credentials). `into_resolver()` returns a working empty
    /// resolver, not an error.
    #[test]
    fn config_with_empty_entries_yields_empty_resolver() {
        let json = r#"{ "kind": "static", "entries": {} }"#;
        let cfg: CredentialResolverConfig = serde_json::from_str(json).expect("config parses");
        let resolver = cfg.into_resolver().expect("infallible today");
        let err = resolver
            .resolve(&CredentialHandle::new("any"))
            .expect_err("empty resolver returns NotFound");
        assert!(matches!(err, CredentialError::NotFound(_)));
    }

    /// `from_json_file` surfaces an IO error (with the offending path)
    /// when the config file doesn't exist. This is the most common
    /// fail-fast path at executor boot.
    #[test]
    fn from_json_file_io_error_includes_path() {
        let bogus = "/tmp/definitely-not-a-real-credentials-config-12345.json";
        let err =
            CredentialResolverConfig::from_json_file(bogus).expect_err("missing file must error");
        match err {
            CredentialConfigError::Io { path, .. } => assert_eq!(path, bogus),
            CredentialConfigError::Parse { .. } => panic!("expected Io error, got Parse"),
        }
    }

    /// `from_json_file` surfaces a parse error (with the offending
    /// path) when the file exists but is malformed.
    #[test]
    fn from_json_file_parse_error_includes_path() {
        let tmp = std::env::temp_dir().join("dataglot-credentials-malformed.json");
        std::fs::write(&tmp, b"{ not valid json ").expect("write tmp file");
        let err =
            CredentialResolverConfig::from_json_file(&tmp).expect_err("malformed JSON must error");
        match err {
            CredentialConfigError::Parse { path, .. } => {
                assert_eq!(path, tmp.display().to_string());
            }
            CredentialConfigError::Io { .. } => panic!("expected Parse error, got Io"),
        }
        let _ = std::fs::remove_file(&tmp);
    }

    /// Defensive: `CredentialConfigEntry`'s `Debug` impl must redact
    /// secret material, matching `Credentials`'s impl. A malformed
    /// config file may surface entries through `Parse` error chains,
    /// so this is the spot where leakage would otherwise happen.
    #[test]
    fn config_entry_debug_redacts_secrets() {
        let dsn = CredentialConfigEntry::Dsn {
            value: "postgres://u:hunter2@h/d".into(),
        };
        let dbg = format!("{dsn:?}");
        assert!(!dbg.contains("hunter2"), "DSN secret leaked: {dbg}");

        let key = CredentialConfigEntry::AccessKey {
            access_key_id: "AKIA".into(),
            secret_access_key: "shh".into(),
        };
        let dbg = format!("{key:?}");
        assert!(!dbg.contains("shh"), "secret_access_key leaked: {dbg}");
        assert!(dbg.contains("AKIA"), "access_key_id should appear: {dbg}");

        let tok = CredentialConfigEntry::Token {
            value: "eyJ.payload.sig".into(),
        };
        let dbg = format!("{tok:?}");
        assert!(!dbg.contains("eyJ"), "token leaked: {dbg}");
    }
}

#[cfg(test)]
mod redaction_proptests {
    //! Property: the redacted `Debug` impls on [`Credentials`] and
    //! [`CredentialConfigEntry`] never emit secret material, for *any*
    //! secret value — not just the hand-picked examples in `tests`.
    //! This is the proptest backstop for hard rule 12 ("credentials
    //! never appear in logs, error messages, or plan representations").
    //!
    //! Generated-secret hygiene: secret bodies are 12+ char lowercase
    //! alphanumeric so they can never be a substring of the `Debug`
    //! scaffolding (the variant tags / field names / `<redacted>`
    //! placeholder are all shorter or mixed-case), which keeps a passing
    //! redaction from ever spuriously tripping `!contains`. The
    //! intentionally-surfaced `access_key_id` is generated uppercase so
    //! it can't collide with the lowercase secret either.

    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn dsn_credentials_debug_never_leaks(secret in "[a-z0-9]{12,64}") {
            let dbg = format!("{:?}", Credentials::Dsn(secret.clone()));
            prop_assert!(!dbg.contains(&secret), "DSN secret leaked: {dbg}");
            prop_assert!(dbg.contains("redacted"), "missing redaction marker: {dbg}");
        }

        #[test]
        fn token_credentials_debug_never_leaks(secret in "[a-z0-9]{12,64}") {
            let dbg = format!("{:?}", Credentials::Token(secret.clone()));
            prop_assert!(!dbg.contains(&secret), "token leaked: {dbg}");
            prop_assert!(dbg.contains("redacted"), "missing redaction marker: {dbg}");
        }

        #[test]
        fn access_key_credentials_debug_redacts_secret_keeps_id(
            access_key_id in "[A-Z0-9]{8,20}",
            secret in "[a-z0-9]{12,64}",
        ) {
            let dbg = format!(
                "{:?}",
                Credentials::AccessKey {
                    access_key_id: access_key_id.clone(),
                    secret_access_key: secret.clone(),
                }
            );
            prop_assert!(!dbg.contains(&secret), "secret_access_key leaked: {dbg}");
            // access_key_id is intentionally non-sensitive and surfaced.
            prop_assert!(dbg.contains(&access_key_id), "access_key_id missing: {dbg}");
        }

        #[test]
        fn config_entry_dsn_debug_never_leaks(secret in "[a-z0-9]{12,64}") {
            let dbg = format!("{:?}", CredentialConfigEntry::Dsn { value: secret.clone() });
            prop_assert!(!dbg.contains(&secret), "config DSN secret leaked: {dbg}");
            prop_assert!(dbg.contains("redacted"), "missing redaction marker: {dbg}");
        }

        #[test]
        fn config_entry_token_debug_never_leaks(secret in "[a-z0-9]{12,64}") {
            let dbg = format!("{:?}", CredentialConfigEntry::Token { value: secret.clone() });
            prop_assert!(!dbg.contains(&secret), "config token leaked: {dbg}");
            prop_assert!(dbg.contains("redacted"), "missing redaction marker: {dbg}");
        }

        #[test]
        fn config_entry_access_key_debug_redacts_secret_keeps_id(
            access_key_id in "[A-Z0-9]{8,20}",
            secret in "[a-z0-9]{12,64}",
        ) {
            let dbg = format!(
                "{:?}",
                CredentialConfigEntry::AccessKey {
                    access_key_id: access_key_id.clone(),
                    secret_access_key: secret.clone(),
                }
            );
            prop_assert!(!dbg.contains(&secret), "config secret_access_key leaked: {dbg}");
            prop_assert!(dbg.contains(&access_key_id), "access_key_id missing: {dbg}");
        }
    }
}

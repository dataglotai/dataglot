//! CLI argument parsing for the Dataglot server.

use std::net::SocketAddr;

use clap::{Parser, Subcommand};

use crate::observability::LogFormat;

/// Dataglot server — federated SQL engine with `PostgreSQL` wire protocol.
// A CLI arg struct is a flat bag of independent flags; several are
// naturally bool toggles (`--verbose`, `--disable-health-check`,
// `--healthcheck`, `--tolerate-unreachable-catalogs`). A state machine
// would not model command-line flags more clearly.
#[allow(clippy::struct_excessive_bools)]
#[derive(Parser, Debug)]
#[command(name = "dataglot")]
#[command(version, about, long_about = None)]
pub struct Args {
    /// Host address to bind to.
    ///
    /// When omitted, the value from the loaded config file (if any) is
    /// kept; otherwise falls back to `"127.0.0.1"` via
    /// `ServerConfig::default()`. Same precedence as `default_catalog`
    /// (CLI > env > config file > struct `Default`). Earlier this field
    /// carried a clap `default_value = "127.0.0.1"` that silently
    /// overrode a `host` set in the JSON config at every boot.
    #[arg(short = 'H', long, env = "DATAGLOT_HOST")]
    pub host: Option<String>,

    /// Port to listen on.
    ///
    /// When omitted, the config file's `port` (or the `5432`
    /// `ServerConfig::default()` fallback) is kept. Earlier a clap
    /// `default_value_t = 5432` silently clobbered a `port` set in the
    /// JSON config — a `"port": 15499` bound 5432 until `--port` was
    /// passed. Same precedence rules as `host` above.
    #[arg(short, long, env = "DATAGLOT_PORT")]
    pub port: Option<u16>,

    /// Path to configuration file. Global: also accepted after a
    /// subcommand, e.g. `dataglot query -c dataglot.toml "SELECT 1"`.
    #[arg(short, long, env = "DATAGLOT_CONFIG", global = true)]
    pub config: Option<std::path::PathBuf>,

    /// Batch size for query execution.
    ///
    /// When omitted, the config file's `batch_size` (or the `8192`
    /// `ServerConfig::default()` fallback) is kept. Earlier a clap
    /// `default_value_t = 8192` silently clobbered a `batch_size` set in
    /// the JSON config. Same precedence rules as `host`/`port`.
    #[arg(long, env = "DATAGLOT_BATCH_SIZE")]
    pub batch_size: Option<usize>,

    /// Number of partitions for parallel execution
    #[arg(long, env = "DATAGLOT_PARTITIONS")]
    pub partitions: Option<usize>,

    /// Default catalog name.
    ///
    /// When omitted, the value from the loaded config file (if any) is
    /// kept; otherwise falls back to `"dataglot"` in
    /// `ServerConfig::load`. Earlier this field carried a clap
    /// `default_value = "dataglot"` that silently overrode the config
    /// file's value at every boot — bit us during  diagnosis
    /// when a `default_catalog: "pg"` in JSON had no effect.
    #[arg(long, env = "DATAGLOT_DEFAULT_CATALOG")]
    pub default_catalog: Option<String>,

    /// Default schema name. Same precedence rules as `default_catalog`
    /// above (CLI > env > config file > `"public"` fallback in `load`).
    #[arg(long, env = "DATAGLOT_DEFAULT_SCHEMA")]
    pub default_schema: Option<String>,

    /// Enable verbose logging
    #[arg(short, long)]
    pub verbose: bool,

    /// Tolerate unreachable catalogs at boot: log a WARN and skip a
    /// catalog that fails to connect instead of aborting startup. Off
    /// by default (fail-fast). Useful for demo / auto-detected sources
    /// (e.g. the testbench's Snowflake auto-on) where stale credentials
    /// shouldn't take the whole server down.
    #[arg(long, env = "DATAGLOT_TOLERATE_UNREACHABLE_CATALOGS")]
    pub tolerate_unreachable_catalogs: bool,

    /// Log output format. Overrides the value loaded from a config file.
    /// `DATAGLOT_LOG_FORMAT=json` (read at process start) takes final precedence.
    #[arg(long, value_enum, env = "DATAGLOT_LOG_FORMAT")]
    pub log_format: Option<LogFormat>,

    /// `tracing-subscriber::EnvFilter` directive used when `RUST_LOG` is unset.
    #[arg(long, env = "DATAGLOT_LOG_FILTER")]
    pub log_filter: Option<String>,

    /// Address (host:port) for the Prometheus `/metrics` HTTP endpoint.
    /// Pass `disabled` to turn the metrics listener off entirely.
    #[arg(long, env = "DATAGLOT_METRICS_ADDR", value_parser = parse_metrics_addr)]
    pub metrics_addr: Option<MetricsAddr>,

    /// Disable the `/health` endpoint exposed alongside `/metrics`.
    #[arg(long, env = "DATAGLOT_DISABLE_HEALTH_CHECK")]
    pub disable_health_check: bool,

    /// Print a commented starter `dataglot.toml` to stdout and exit.
    ///
    /// Redirect it to a file to get going in one step:
    /// `dataglot --print-example-config > dataglot.toml`. The output is
    /// valid, immediately-loadable TOML (with `#` comments), one Postgres
    /// catalog and a mask example.
    ///
    /// Runs before config loading and tracing init — nothing else on the
    /// command line matters on this path.
    #[arg(long)]
    pub print_example_config: bool,

    /// Run as a one-shot health probe instead of starting the server.
    ///
    /// When set, the process attempts a short TCP connect to
    /// `127.0.0.1:<port>` (defaulting to the server's pg-wire port)
    /// and exits 0 on success or 1 on failure — same contract as
    /// `nc -z localhost 5432`. Designed for the distroless runtime
    /// image's `HEALTHCHECK` directive and for `docker-compose`
    /// healthcheck definitions on shell-less base images.
    ///
    /// `--port` still applies; everything else (`--config`,
    /// `--host`, observability settings) is ignored on this path so
    /// the probe stays fast and free of side effects (no config
    /// parsing, no tracing init, no metrics listener).
    #[arg(long, env = "DATAGLOT_HEALTHCHECK")]
    pub healthcheck: bool,

    /// Optional subcommand. When omitted, the flags above run the server.
    #[command(subcommand)]
    pub command: Option<Command>,
}

/// Subcommands. The server-run path is the default (no subcommand); these
/// are one-shot utilities that short-circuit before boot.
#[derive(Subcommand, Debug)]
pub enum Command {
    /// Write a starter `dataglot.toml` to disk and exit.
    ///
    /// The friendly, file-writing sibling of `--print-example-config`
    /// (which streams the same content to stdout). Refuses to overwrite an
    /// existing file unless `--force`.
    Init(InitArgs),

    /// Run one SQL statement against the configured catalogs and exit.
    ///
    /// Runs the engine in-process (no server, no pg-wire listener) using the
    /// same federation + plan-time governance the server applies, then prints
    /// the result. The "try it in one command" path — no `psql` required:
    ///
    ///   dataglot query -c dataglot.toml "SELECT * FROM pg.public.users LIMIT 5"
    ///   dataglot query -c dataglot.toml -f report.sql
    ///   echo "SELECT 1" | dataglot query -c dataglot.toml -
    Query(QueryArgs),

    /// Interactive SQL shell over the embedded engine — a lightweight REPL for
    /// the configured catalogs, no server or `psql` needed. Type SQL and press
    /// Enter; `\q` or Ctrl-D to quit. Results go to stdout, prompts to stderr.
    Shell(ShellArgs),

    /// Print a shell completion script to stdout and exit.
    ///
    /// Install it where your shell looks for completions, e.g.:
    ///
    /// ```text
    /// dataglot completions bash > /etc/bash_completion.d/dataglot
    /// dataglot completions zsh  > "${fpath[1]}/_dataglot"
    /// dataglot completions fish > ~/.config/fish/completions/dataglot.fish
    /// ```
    Completions(CompletionsArgs),
}

/// Arguments for `dataglot shell`.
#[derive(clap::Args, Debug)]
pub struct ShellArgs {
    /// Output format for result sets.
    #[arg(long, value_enum, default_value_t = OutputFormat::Table)]
    pub format: OutputFormat,

    /// Identity to run as — sets what `current_user` / `session_user` return.
    #[arg(long, default_value = "dataglot")]
    pub user: String,
}

/// Arguments for `dataglot completions`.
#[derive(clap::Args, Debug)]
pub struct CompletionsArgs {
    /// Shell to generate a completion script for.
    #[arg(value_enum)]
    pub shell: clap_complete::Shell,
}

/// Write a shell completion script for `dataglot` to stdout.
pub fn print_completions(shell: clap_complete::Shell) {
    write_completions(shell, &mut std::io::stdout());
}

/// Generate the completion script into `out`. Split out from
/// [`print_completions`] so it's testable without capturing stdout.
fn write_completions<W: std::io::Write>(shell: clap_complete::Shell, out: &mut W) {
    let mut cmd = <Args as clap::CommandFactory>::command();
    clap_complete::generate(shell, &mut cmd, "dataglot", out);
}

/// Arguments for `dataglot query`.
#[derive(clap::Args, Debug)]
pub struct QueryArgs {
    /// SQL to run. Use `-`, or omit and pipe, to read the statement from stdin.
    #[arg(value_name = "SQL")]
    pub sql: Option<String>,

    /// Read the SQL from a file instead of the positional argument.
    #[arg(short = 'f', long, value_name = "FILE", conflicts_with = "sql")]
    pub file: Option<std::path::PathBuf>,

    /// Output format for the result set.
    #[arg(long, value_enum, default_value_t = OutputFormat::Table)]
    pub format: OutputFormat,

    /// Identity to run as — sets what `current_user` / `session_user` return.
    /// Governance (masking / row filters) is static today, so this is currently
    /// only reflected by those functions; it becomes policy-relevant when
    /// identity-aware rules land.
    #[arg(long, default_value = "dataglot")]
    pub user: String,
}

/// Result-set rendering for `dataglot query`.
#[derive(clap::ValueEnum, Clone, Copy, Debug, Default)]
pub enum OutputFormat {
    /// Aligned ASCII table (the default; what `psql` shows).
    #[default]
    Table,
    /// Comma-separated values with a header row.
    Csv,
    /// One JSON object per row (newline-delimited).
    Json,
}

/// Arguments for `dataglot init`.
#[derive(clap::Args, Debug)]
pub struct InitArgs {
    /// Path to write the starter config to.
    #[arg(default_value = "dataglot.toml")]
    pub path: std::path::PathBuf,

    /// Overwrite the file if it already exists.
    #[arg(long)]
    pub force: bool,
}

/// Wrapper that distinguishes "not configured on the CLI" from
/// "configured to be off" without conflating them with `Option<SocketAddr>`.
#[derive(Debug, Clone, Copy)]
pub enum MetricsAddr {
    /// Listen on the given socket.
    Bind(SocketAddr),
    /// Explicitly disabled by the user.
    Disabled,
}

fn parse_metrics_addr(s: &str) -> Result<MetricsAddr, String> {
    if s.eq_ignore_ascii_case("disabled") || s.eq_ignore_ascii_case("off") || s.is_empty() {
        return Ok(MetricsAddr::Disabled);
    }
    s.parse::<SocketAddr>()
        .map(MetricsAddr::Bind)
        .map_err(|e| format!("invalid metrics address '{s}': {e}"))
}

impl Args {
    /// Parse command-line arguments.
    #[must_use]
    pub fn parse_args() -> Self {
        Self::parse()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn completions_generate_for_each_shell() {
        for shell in [
            clap_complete::Shell::Bash,
            clap_complete::Shell::Zsh,
            clap_complete::Shell::Fish,
        ] {
            let mut out = Vec::new();
            write_completions(shell, &mut out);
            let script = String::from_utf8(out).expect("utf-8 completion script");
            assert!(
                script.contains("dataglot"),
                "{shell:?} script must name the binary"
            );
            assert!(
                script.contains("completions"),
                "{shell:?} script must include the subcommands"
            );
        }
    }

    #[test]
    fn test_args_defaults() {
        let args = Args::parse_from(["dataglot"]);
        //: `host` / `port` / `batch_size` are now `Option` with
        // NO clap `default_value`, so an unset flag stays `None` and does
        // NOT silently clobber the config-file value. The `127.0.0.1` /
        // `5432` / `8192` fallbacks now live in `ServerConfig::default()`.
        assert!(args.host.is_none());
        assert!(args.port.is_none());
        assert!(args.batch_size.is_none());
        //: `default_catalog` / `default_schema` are now
        // `Option<String>` so an unset flag does NOT silently clobber
        // the config-file value. See `cli::Args` doc comments.
        assert!(args.default_catalog.is_none());
        assert!(args.default_schema.is_none());
        assert!(args.log_format.is_none());
        assert!(args.log_filter.is_none());
        assert!(args.metrics_addr.is_none());
        assert!(!args.disable_health_check);
        assert!(!args.print_example_config);
        assert!(args.command.is_none(), "bare invocation runs the server");
    }

    #[test]
    fn test_init_subcommand() {
        // Default path + no force.
        let args = Args::parse_from(["dataglot", "init"]);
        match args.command {
            Some(Command::Init(ref i)) => {
                assert_eq!(i.path.to_str(), Some("dataglot.toml"));
                assert!(!i.force);
            }
            other => panic!("expected Init, got {other:?}"),
        }

        // Custom path + --force.
        let args = Args::parse_from(["dataglot", "init", "custom.json", "--force"]);
        match args.command {
            Some(Command::Init(ref i)) => {
                assert_eq!(i.path.to_str(), Some("custom.json"));
                assert!(i.force);
            }
            other => panic!("expected Init, got {other:?}"),
        }
    }

    #[test]
    fn test_print_example_config_flag() {
        let args = Args::parse_from(["dataglot", "--print-example-config"]);
        assert!(args.print_example_config);
        // Default off — a normal boot must never take the print path.
        let args = Args::parse_from(["dataglot"]);
        assert!(!args.print_example_config);
    }

    #[test]
    fn test_args_custom() {
        let args = Args::parse_from([
            "dataglot",
            "-H",
            "0.0.0.0",
            "-p",
            "15432",
            "--batch-size",
            "4096",
        ]);
        assert_eq!(args.host.as_deref(), Some("0.0.0.0"));
        assert_eq!(args.port, Some(15432));
        assert_eq!(args.batch_size, Some(4096));
    }

    #[test]
    fn test_metrics_addr_parsing() {
        let args = Args::parse_from(["dataglot", "--metrics-addr", "0.0.0.0:9100"]);
        match args.metrics_addr {
            Some(MetricsAddr::Bind(s)) => assert_eq!(s.port(), 9100),
            other => panic!("expected Bind, got {other:?}"),
        }
    }

    #[test]
    fn test_metrics_addr_disabled() {
        let args = Args::parse_from(["dataglot", "--metrics-addr", "disabled"]);
        assert!(matches!(args.metrics_addr, Some(MetricsAddr::Disabled)));
    }

    #[test]
    fn test_metrics_addr_invalid_returns_error() {
        let result = Args::try_parse_from(["dataglot", "--metrics-addr", "not-an-addr"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_log_format_flag() {
        let args = Args::parse_from(["dataglot", "--log-format", "json"]);
        assert_eq!(args.log_format, Some(LogFormat::Json));
    }

    #[test]
    fn test_log_filter_flag() {
        let args = Args::parse_from(["dataglot", "--log-filter", "dataglot=trace,datafusion=info"]);
        assert_eq!(
            args.log_filter,
            Some("dataglot=trace,datafusion=info".to_string())
        );
    }

    #[test]
    fn test_disable_health_check_flag() {
        let args = Args::parse_from(["dataglot", "--disable-health-check"]);
        assert!(args.disable_health_check);
    }

    #[test]
    fn test_healthcheck_flag_defaults_off() {
        // Default must be `false` — a missing flag should never trigger
        // the one-shot probe path. Pinned because turning this on by
        // accident would break the binary's normal startup.
        let args = Args::parse_from(["dataglot"]);
        assert!(!args.healthcheck);
    }

    #[test]
    fn test_healthcheck_flag_set() {
        let args = Args::parse_from(["dataglot", "--healthcheck"]);
        assert!(args.healthcheck);
    }

    #[test]
    fn test_healthcheck_flag_with_port_override() {
        // The probe respects `--port` so operators can probe a
        // non-default pg-wire port without an env-var dance.
        let args = Args::parse_from(["dataglot", "--healthcheck", "--port", "15432"]);
        assert!(args.healthcheck);
        assert_eq!(args.port, Some(15432));
    }
}

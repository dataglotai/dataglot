# Dataglot

Rust-native federated SQL query engine with governance enforced in the
query plan. One PostgreSQL endpoint for all your databases.

Dataglot speaks the PostgreSQL wire protocol, so `psql`, DBeaver,
Metabase, Tableau, dbt, and every Postgres driver connect with no
special client. Point it at the databases you already run — PostgreSQL,
MySQL, Oracle, Snowflake, S3/Parquet/CSV, Apache Iceberg — and query
across all of them in one SQL statement, with column masks and row
filters compiled into the plan, not bolted on after it.

Website & docs: [dataglot.ai](https://dataglot.ai)

> **Status:** pre-1.0 and evolving. Dataglot is a read-path federation
> and governance engine, not a general-purpose PostgreSQL replacement.
> See [known limitations](docs/compatibility.md).

## Install

Prebuilt everywhere — no toolchain, no compiling (full menu, including
tarballs and `cargo binstall`, in [docs/install.md](docs/install.md)).
Pick **one** channel:

Homebrew (macOS / Linux):

```bash
brew install dataglotai/tap/dataglot
```

Container image (published on loopback only — the default auth mode
trusts any local user):

```bash
docker run --rm -p 127.0.0.1:5432:5432 ghcr.io/dataglotai/dataglot:latest
```

## Quick start

**[QUICKSTART.md](QUICKSTART.md)** takes you from install to a governed,
federated query in about five minutes — sources, credentials, and
policies are all administered over `psql` with plain SQL
([docs/runtime-config.md](docs/runtime-config.md)).

You don't need a server to try it — the binary runs a query in-process
using the same federation and plan-time governance the server applies:

```bash
dataglot query "SELECT 1 AS n, 'hello' AS greeting"
dataglot query -c dataglot.toml "SELECT * FROM pg.public.users LIMIT 5"
dataglot shell -c dataglot.toml      # interactive REPL; \q to quit
```

To build from source instead:

```bash
# Prerequisites: Rust 1.94+ (workspace MSRV), nightly toolchain, cargo-deny + taplo
rustup toolchain install nightly
cargo install cargo-deny taplo-cli

# Build and test
make ci
```

## Crates

| Crate | Purpose |
|---|---|
| `dataglot-core` | Shared types, `SessionContextFactory`, error types |
| `dataglot-federation` | Postgres, MySQL, warehouse, and lakehouse connectors via `datafusion-federation` and `iceberg-datafusion` |
| `dataglot-pgwire` | PostgreSQL wire protocol via `pgwire` + `datafusion-postgres` |
| `dataglot-policy` | Policy enforcement — column masking, row filtering, tag-based governance |
| `dataglot-catalog` | Catalog metadata and the embedded meta-store |
| `dataglot-server` | Binary entrypoint, config, CLI, dashboard |
| `dataglot-ballista` | Optional distributed execution on Apache Ballista |
| `dataglot-test-support` | Shared test helpers for the workspace's unit tests |

## Docs map

| Doc | What it gives you |
|---|---|
| [QUICKSTART.md](QUICKSTART.md) | Install → first governed federated query in ~5 minutes |
| [docs/getting-started.md](docs/getting-started.md) | The same journey, in more depth |
| [docs/install.md](docs/install.md) | Every install channel: Homebrew, Docker, tarballs, `cargo binstall`, from source |
| [docs/quick-reference.md](docs/quick-reference.md) | One-page cheat-sheet: build commands, features, runtime flags, dashboard URLs, auth modes |
| [docs/configuration.md](docs/configuration.md) | Full `dataglot.toml` reference: catalogs, policies, TLS, auth, rate limits |
| [docs/runtime-config.md](docs/runtime-config.md) | SQL-native administration: `CREATE CATALOG`, `CREATE MASK`, secrets |
| [docs/access-control.md](docs/access-control.md) | Governance model: masks, row filters, tags, identities |
| [docs/authentication.md](docs/authentication.md) | Auth modes and hardening before exposing a port |
| [docs/compatibility.md](docs/compatibility.md) | What works, what doesn't, and how far Postgres compatibility goes |
| [CONTRIBUTING.md](CONTRIBUTING.md) | PR workflow, branch/commit conventions, crate boundaries |
| [SECURITY.md](SECURITY.md) | Vulnerability reporting policy |

## License

Apache-2.0

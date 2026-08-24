# Dataglot — Quick Reference

A one-page reference for building and running Dataglot: compile-time and runtime
options, the dashboard, and auth modes.

Dataglot is a Rust-native federated SQL engine (Apache Arrow + DataFusion) that
queries across Postgres, MySQL, Oracle, Snowflake, Iceberg/lakehouse, object
storage, and OData/REST — over the **PostgreSQL wire protocol**, with plan-time
governance (column masks, row filters). No JVM.

## Build

Prereqs: stable Rust (workspace **MSRV 1.94**); `protoc` only if you build the
`ballista` (distributed) feature. See [install.md](install.md) for the full
toolchain list (prebuilt binaries need none of it).

```bash
# Server binary (default features) → target/release/dataglot
cargo build --release -p dataglot-server

# Fast iterative build (optimized, no fat-LTO)
cargo build --profile release-fast -p dataglot-server

# Dev gates
make check     # fmt + clippy + taplo
make test      # workspace tests (non-Docker)
make ci        # full pre-PR gate (check + test + doc + deny)

# One-command local server (builds + runs on port 15432)
./scripts/run-single.sh                    # single-node
./scripts/run-distributed.sh               # 1 server + 2 external executors
EXECUTORS=3 ./scripts/run-distributed.sh   # 1 server + N executors
```

Build profiles: `dev` (fastest) · `release-fast` (optimized, no LTO — dev
default) · `release` (fat-LTO, the shipped container).

## Compile-time options (Cargo features)

Connectors and subsystems are feature-gated — build only what you need.

**`dataglot-server`:** `dashboard` (embedded ops UI at `/ui`; a Cargo
feature that is off for a bare `cargo build`, but **stock release binaries
and the container image ship with it**, so `/ui` is served out of the box —
enable it for a local build with `--features dashboard`) ·
`ballista` (distributed execution, needs `protoc`) · `oracle` (Oracle
via OCI/ODPI-C, native C client at runtime) · `oracle-pure` (Oracle, pure-Rust,
no C).

**`dataglot-federation` connectors:** `postgres` · `mysql` · `iceberg` · `odata`
· `rest` · `snowflake` · `adbc` (bring-your-own ADBC driver) · `oracle` /
`oracle-pure`. Shortcut: `all = postgres,mysql,iceberg,odata,rest`.

```bash
cargo build --release -p dataglot-server \
  --features "dashboard,ballista,dataglot-federation/all"

# Everything on (distributed + dashboard + oracle/adbc/flight_sql + all
# connectors) — shortest form. Needs protoc (ballista) and a C compiler
# (the OCI `oracle` feature builds ODPI-C).
cargo build --release -p dataglot-server --all-features

# Distributed needs the executor/scheduler binaries too — the server's
# `ballista` feature only links the ballista *library*, not its bins.
# Build the server AND the ballista package (its bins) with all features:
cargo build --release -p dataglot-server -p dataglot-ballista --all-features
#   → target/release/dataglot                      (server + in-process scheduler)
#     target/release/dataglot-ballista-executor    (external worker)
#     target/release/dataglot-ballista-scheduler   (standalone scheduler; optional
#                                                    — the server hosts one in-process)
```

The 3 workspace binaries: `dataglot` (`dataglot-server`) · `dataglot-ballista-executor`
and `dataglot-ballista-scheduler` (`dataglot-ballista`). Building everything
with `--all-features` pulls the heaviest toolchain set: `protoc` (ballista), a
**C** compiler (OCI `oracle`/ODPI-C), and **Node 20** (the dashboard frontend
build — skipped when the `dashboard` feature is off).

Default build (`-p dataglot-server`, no `--features`) always compiles the
pure-Rust connectors — `postgres`, `mysql`, `iceberg`, `snowflake`, `odata`,
`rest` — and leaves `ballista`, `dashboard`, `oracle`, `oracle-pure`, `adbc`,
and `flight_sql` off.

## Binaries & topology

How the binaries interact in **distributed** mode (single-node = the same
server with the scheduler + one *in-process* executor, no external workers):

```text
   psql / JDBC / BI tool
   (any pg client)
           │
           │  pgwire (SQL, :5432)
           ▼
        ┌───────────────────────────────────────────┐
        │  dataglot            (dataglot-server bin)  │
        │  pgwire · DataFusion planner · policy       │
        │  Ballista scheduler  (in-process)           │
        └───────┬───────────────────────────┬─────────┘
        dispatch│ register  gRPC :50060      │ status  REST :50050
                ▼                            ▼
    ┌───────────────────────┐   ┌───────────────────────┐
    │ dataglot-ballista-    │◄─►│ dataglot-ballista-    │
    │ executor  (worker 1)  │   │ executor  (worker N)  │
    └───────────┬───────────┘   └───────────┬───────────┘
       Arrow Flight shuffle between workers (:50061/50071 …)
                │                            │
                │  federated scans (each worker connects to sources)
                ▼                            ▼
        ┌─────────────────────────────────────────────┐
        │ Sources: Postgres · MySQL · Oracle ·         │
        │ Snowflake · Iceberg/lakehouse · object store │
        │ · OData/REST                                 │
        └─────────────────────────────────────────────┘
```

- **`dataglot`** — the only user-facing binary: pgwire ingress, planning, policy
  enforcement, and (with `--features ballista` + a `[ballista]` config) the
  in-process scheduler. Single-node builds do the source scans themselves.
- **`dataglot-ballista-executor`** — external worker; registers with the
  scheduler (gRPC), runs plan stages, connects to the federated **sources**
  directly (hence its own catalogs config), and shuffles intermediate data to
  peer executors over **Arrow Flight**.
- **`dataglot-ballista-scheduler`** — standalone scheduler binary, **optional**:
  the server already hosts one in-process, so it's only for a fully-external
  cluster deployment.

## Runtime options

Every flag has a `DATAGLOT_*` env-var equivalent. Precedence: CLI > env > config
file > default.

| Flag / env | Meaning |
| --- | --- |
| `-H/--host`, `DATAGLOT_HOST` | bind host (default `127.0.0.1`) |
| `-p/--port`, `DATAGLOT_PORT` | pgwire port (default `5432`) |
| `-c/--config`, `DATAGLOT_CONFIG` | config file path |
| `--default-catalog` / `--default-schema` | default namespace |
| `--partitions`, `--batch-size` | parallelism / batch tuning |
| `--tolerate-unreachable-catalogs` | skip sources that are down at boot |
| `--metrics-addr` (default `127.0.0.1:9090`) | Prometheus + dashboard bind addr |
| `--log-format` (`json`\|…), `--log-filter` | logging |
| `--healthcheck` | one-shot TCP probe, exits 0/1 (container HEALTHCHECK) |

Subcommands: `dataglot init` (write a starter config) · `dataglot query "<SQL>"`
(one-shot, in-process, no server) · `dataglot shell` (REPL) ·
`dataglot completions`.

## Dashboard

- **Operational dashboard (served by the engine):** <http://127.0.0.1:9090/ui>
  — cluster, running queries, sessions, governance/security posture, connector
  health, query history. **Served out of the box** by stock release binaries
  and the container image. A bare `cargo build` omits it — add
  `--features dashboard` for a local build; the `scripts/run-*.sh` launchers
  already do. Bound at `--metrics-addr` (default `:9090`); Prometheus metrics
  at `:9090/metrics`.

## Auth modes

Selected by the `[auth] mode` config key (full detail:
[authentication.md](authentication.md)).

| Mode | Behaviour | Use for |
| --- | --- | --- |
| `trust` (default) | any username, **no password** | local dev only |
| `md5` | Postgres MD5 password exchange | legacy clients |
| `scram-sha-256` | SASL salted challenge–response (RFC 5802) | production (preferred) |
| `jwt` | client presents a signed JWT as its password; verified `groups` claim drives policy (`[auth.jwt]`) | IdP / token auth |
| `ldap` | bind to the directory as the user; group search drives policy (`[auth.ldap]`) | LDAP / AD |

Options:
- **Identities** (md5/scram): declared under `identities` in config; the password
  is never in the file — `password_env` names an env var read at boot. Optional
  `org` and `groups`.
- **Runtime users:** `CREATE USER … WITH PASSWORD '…'` adds identities live (no
  restart; stored encrypted in the meta store — needs `DATAGLOT_SECRET_KEY`).
- **Multi-org:** identities carry an `org`; usernames are globally unique;
  sessions are org-scoped.
- **TLS:** add a `[pgwire_tls]` block with `mode = "require"` to encrypt the
  session. The server warns if a password mode runs without ingress TLS.
- **Groups / LDAP:** `groups` drive group-conditional masks/row-filters and can
  be populated from LDAP/IdP.

> Authorization (what an authenticated user may *see* — masks, row filters,
> GRANT/REVOKE) is separate; see [access-control.md](access-control.md) and
> [runtime-config.md](runtime-config.md).

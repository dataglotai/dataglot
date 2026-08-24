# Client-tool compatibility

> Verified with `scripts/client-compat.sh` — a scripted smoke matrix
> that runs **connect / introspect / federated query / extended
> protocol (parameterized) / cancel** through each driver stack against
> a live server. Run it against your own deployment:
>
> ```bash
>./scripts/run-testbench.sh          # or any running dataglot-server
> PGPORT=5432./scripts/client-compat.sh
> ```

Dataglot speaks the PostgreSQL wire protocol (both simple and extended
flavors), so anything built on a Postgres driver connects. GUI tools
are grouped under the driver they embed — a tool's schema browser and
query runner exercise exactly the driver behaviors the matrix scripts.

> **Last verified: 2026-07-29** against the `--distributed` testbench —
> all stacks pass (psql, node-postgres, pgJDBC, psycopg). An earlier
> psycopg connect-time `SELECT 1` hang was fixed
> (: input-less plans now
> run locally instead of being dispatched to Ballista); psycopg federated
> queries were then re-verified at **30/30** (≈6ms). The only distributed
> caveat is **not client-specific**: under heavy concurrent load the shared
> Ballista scheduler (N executor slots) can saturate, so queries *queue*
> and can look slow/stuck until slots free — a load characteristic, not a
> protocol bug ().

## Matrix

| Tool / stack | Driver | Connect | Introspect | Federated query | Extended protocol | Cancel | Verified |
|---|---|---|---|---|---|---|---|
| **psql** | libpq | ✅ | ✅ (`\dt`, `\d`, information_schema) | ✅ | ✅ (`\bind`) | ✅ Ctrl-C | scripted |
| **pgcli** | psycopg | ✅ | ✅ | ✅ | ✅ | ✅ | via psycopg (scripted); single-node + `--distributed` |
| **Python** (psycopg 3) | psycopg | ✅ | ✅ | ✅ | ✅ | ✅ `Connection.cancel()` | scripted; `--distributed` re-verified 30/30 |
| **dbt-postgres** | psycopg2 | ✅ | ✅ | ✅ | ✅ | ✅ | via psycopg (scripted); no DDL → see limits |
| **Node.js** (`pg`) | node-postgres | ✅ | ✅ | ✅ | ✅ | n/a (driver exposes no cancel API) | scripted |
| **DBeaver** | pgJDBC | ✅ | ✅ (`DatabaseMetaData`) | ✅ | ✅ | ✅ `Statement.cancel()` | via pgJDBC (scripted) |
| **DataGrip** | pgJDBC | ✅ | ✅ | ✅ | ✅ | ✅ | via pgJDBC (scripted) |
| **Metabase** | pgJDBC | ✅ | ✅ | ✅ | ✅ | ✅ | via pgJDBC (scripted) |
| **Grafana** (postgres datasource) | lib/pq (Go) | ✅ | ✅ | ✅ | ✅ | — | expected (wire-identical checks pass on 4 other stacks) |
| **Rust** (tokio-postgres) | tokio-postgres | ✅ | ✅ | ✅ | ✅ | ✅ | CI e2e (`ballista_e2e.rs`, pgwire tests) |

Query cancellation (the wire `CancelRequest`) is handled server-side
for both the planning and streaming phases, including distributed
(Ballista) queries — a cancelled distributed job is also cancelled on
the cluster, not orphaned.

## Warts the matrix found (and their fixes)

Running the matrix against a live distributed server surfaced two real
bugs, both fixed in the same change that added the script:

- **psql v16+ `\dt` failed** with `Invalid function
  'pg_table_is_visible'` — psql's table listing filters on it. A shim
  UDF (always `true`; every listed table is already scoped to the
  connection's catalog) is registered per session.
- **JDBC `DatabaseMetaData.getTables` failed on distributed servers**
  ("failed to serialize logical plan") — `pg_catalog` queries scan
  in-process virtual tables that can't ship to Ballista. Metadata
  queries now plan **locally** (`LocalMetadataQueryPlanner`): there is
  nothing to distribute in an introspection call. This is what makes
  DBeaver/DataGrip/Metabase schema browsing work against `--distributed`
  servers.

A third finding (2026-07-28), now **fixed**:

- **psycopg connect-time `SELECT 1` hung in `--distributed`** — a no-table
  extended-protocol query planned as `PlaceholderRowExec` was dispatched to
  Ballista instead of running in-process. **Fixed** in
: input-less plans now plan
  locally (same bypass as `pg_catalog`/metadata). The residual "federated hang"
  reported afterward was transient scheduler saturation under load, not a
  protocol bug () — see the
  verification banner above.

One non-bug worth knowing: `\dt other_catalog.schema.*` errors with
"cross-database references are not implemented" — identical to real
Postgres, because each Dataglot catalog is a *database* in psql's
model. Use `\c`-equivalent (reconnect with `dbname=<catalog>`) or
`information_schema` with a `table_catalog` predicate.

## Known limitations (by design)

Dataglot is a **read-path federation and governance engine**, not a
Postgres replacement. Tools that assume full Postgres will hit these:

- **No data-plane DML** — `INSERT` / `UPDATE` / `DELETE` and model
  materialization (`CREATE TABLE AS`) are not supported; Dataglot is a
  read/federation + governance engine. dbt works for `SELECT`-shaped workflows
  (sources, tests, compiled queries) but cannot materialize models.
  *Control-plane* DDL — `CREATE CATALOG` / `SECRET` / `USER` / `ROLE` / `MASK` /
  `ROW FILTER` / `VIEW` / `GRANT` — **is** supported at runtime (see
  [`runtime-config.md`](runtime-config.md)); a session `CREATE TABLE` also works
  single-node.
- **No COPY protocol** — bulk load belongs to the sources, not the
  federation layer. Tools that hard-require `COPY` for export will
  fall back to row-by-row fetch or fail on that feature only.
- **No transactions** — `BEGIN`/`COMMIT` are accepted as no-ops (the
  pgbouncer/pooler compatibility shims from Phase 3), which is correct
  for a read-only engine but means tools cannot rely on isolation
  semantics.
- **Session-control no-ops** — `DISCARD`, `RESET`, `SAVEPOINT` return
  success without effect (pooler compatibility).

## Wire behaviors tools rely on (implemented)

- `information_schema.tables` / `columns` and the `pg_catalog` subset
  that psql's `\d*` commands and JDBC's `DatabaseMetaData` issue
  (catalog-metadata queries are routed through a dedicated bypass to
  keep them fast against federated sessions).
- `version()`, `current_database()`, `current_schema()` and the
  startup parameters GUIs read.
- Extended-protocol prepare/bind/execute with typed parameters.
- `BackendKeyData` + `CancelRequest` — wire-level cancel from a second
  connection, the mechanism every tool's "stop query" button uses.

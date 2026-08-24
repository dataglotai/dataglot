# Quickstart — first federated query

Five minutes, no compiling, no cluster: install a prebuilt Dataglot,
start it, and administer everything — sources, credentials, policies —
over `psql` with plain SQL. All you need is a database you already run
(Postgres in the examples below) and any PostgreSQL client.

## 1. Install and start

Pick whichever channel you prefer (all of them ship the same prebuilt
`dataglot` binary — see [docs/install.md](docs/install.md) for tarballs
and `cargo binstall` too).

First, a two-line config. It turns on the SQL-native control plane: the
catalogs, secrets, and policies you create over `psql` are persisted in
an embedded file-backed meta store (without it, the server still runs
queries but rejects `CREATE CATALOG` with "catalog DDL requires a
configured catalog_service"):

```bash
cat > dataglot.toml <<'EOF'
[catalog_service]
path = "dataglot-meta.json"
EOF
```

Homebrew (macOS / Linux):

```bash
brew install dataglotai/tap/dataglot && dataglot -c dataglot.toml
```

Or the container image — published on loopback only (the default auth
mode trusts any local user; keep the port off other interfaces), with
your working directory mounted so the config is readable and the meta
store survives container restarts:

```bash
docker run --rm -p 127.0.0.1:5432:5432 \
  -v "$PWD:/data" -w /data --user "$(id -u)" \
  ghcr.io/dataglotai/dataglot:latest -c /data/dataglot.toml
```

Started fresh, the server boots with **no catalogs** and prints a banner
saying so. That's expected — you create everything at runtime with SQL.

## 2. Connect

Dataglot speaks the PostgreSQL wire protocol, so connect with `psql` (or
DBeaver, Metabase, any Postgres driver). Before any catalog exists, use
the built-in bootstrap database `dataglot`:

```bash
psql -h 127.0.0.1 -p 5432 -U admin -d dataglot
```

(Out of the box the username is a policy *identity*, not a credential —
the default auth mode is `trust`, meant for local use. See
[docs/authentication.md](docs/authentication.md) before exposing a
port.)

## 3. Add your first source — with SQL

No config-file edit per source: a catalog is a federated data source, created against
the running server and persisted across restarts.

```sql
CREATE CATALOG pg WITH (
  kind = 'postgres',
  dsn  = 'host=localhost port=5433 user=me password=secret dbname=app'
);
```

(Running Dataglot in Docker? A source on your host machine is not
`localhost` from inside the container — use `host.docker.internal` in
the DSN; on Linux, add `--add-host=host.docker.internal:host-gateway`
to the `docker run` command.)

The source is validated before anything is persisted — an unreachable
DSN fails the statement instead of leaving a half-registered catalog.
Query it immediately, in the same session:

```sql
SELECT * FROM pg.public.users LIMIT 10;
```

Prefer not to inline credentials? Store them encrypted and reference by
name (requires a `DATAGLOT_SECRET_KEY` env var on the server):

```sql
CREATE SECRET app_pg_dsn AS 'host=localhost port=5433 user=me password=secret dbname=app';
CREATE CATALOG pg WITH (kind = 'postgres', dsn_secret = 'app_pg_dsn');
```

Add a second source the same way — MySQL, Snowflake, Iceberg, or even a
bare CSV/Parquet file — and JOIN across them in one statement. (Oracle
works too, but isn't in the prebuilt binaries: it needs a from-source
build with `--features oracle` or the pure-Rust `oracle-pure` — see
[docs/install.md](docs/install.md#building-from-source).)

For the CSV example, first drop a file into the working directory you
started the server from:

```bash
cat > segments.csv <<'EOF'
user_id,segment
7,enterprise
42,self-serve
EOF
```

```sql
CREATE CATALOG files WITH (
  kind = 'object_storage',
  tables = '[{"name":"segments","url":"file:///data/segments.csv","format":"csv"}]'
);

SELECT u.email, s.segment
FROM   pg.public.users u
JOIN   files.public.segments s ON u.id = s.user_id;
```

(The `file:///data/…` URL matches the Docker mount from step 1; running
the Homebrew binary instead, use the file's absolute path on your
machine — e.g. `file:///Users/you/segments.csv`.)

## 4. Govern it — also with SQL

Masks and row filters are compiled into the query plan itself: a masked
column is never fetched from storage, and there is no code path around
the filter.

```sql
CREATE MASK email_mask ON pg.public.users (email) AS '***@example.com';
CREATE ROW FILTER active_only ON pg.public.users USING (active = true);
```

Every session now sees the governed view:

```sql
SELECT id, email FROM pg.public.users ORDER BY id;
```

```text
 id |      email
----+-----------------
  2 | ***@example.com
(1 row)
```

## 5. See the pushdown

`EXPLAIN FEDERATION` shows what Dataglot ships to each source instead
of computing locally:

```sql
EXPLAIN FEDERATION
SELECT user_id, SUM(amount) AS total_amount, COUNT(*)
FROM pg.public.orders
GROUP BY user_id
ORDER BY total_amount DESC;
```

Look for the `VirtualExecutionPlan` node — the **entire aggregation**
went to the source as SQL, not just the scan. The plan trace also shows
the `DataglotPolicyEnforcer` pass — the masks/filters you saw in step 4
are baked into the plan, not applied after the fact.

## Where next

- **SQL-native administration** —
  [docs/runtime-config.md](docs/runtime-config.md) covers catalogs,
  secrets, masks, row filters, and how they persist across restarts.
- **Configure via file instead** —
  [docs/configuration.md](docs/configuration.md) is the full
  `dataglot.toml` reference (all connector kinds, policies, TLS, auth);
  ready-made examples live in [examples/demo/](examples/demo/).
- **Governance in depth** —
  [docs/access-control.md](docs/access-control.md): masks, row filters,
  tag-based policies, identities.
- **Build and contribute** — [docs/install.md](docs/install.md)
  ("Building from source") then [CONTRIBUTING.md](CONTRIBUTING.md).

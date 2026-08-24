# Getting started with Dataglot

Dataglot is a federated SQL engine that speaks the **PostgreSQL wire
protocol**. You point it at your existing data sources (Postgres, MySQL,
Snowflake, Oracle, object storage, SAP/OData, a lakehouse) with one JSON
config file, then query across all of them with any Postgres client —
`psql`, a BI tool, or your app's Postgres driver — while column masks and
row filters are enforced at plan time.

This guide takes you from a downloaded binary to your first query in about
five minutes. For the exhaustive field-by-field reference, see
[`configuration.md`](configuration.md). To manage catalogs, secrets, users, and
governance **at runtime with SQL DDL** — no `dataglot.toml` — see
[`runtime-config.md`](runtime-config.md).

---

## 1. Run the server

You need the `dataglot` binary (from a release, `cargo build --release`, or
the container image). Verify it runs:

```bash
dataglot --version
```

Started with no configuration, Dataglot boots but has **no catalogs** — it
will print a banner telling you exactly that and what to do next. So let's
give it a config.

---

## 2. Create a starter config

Generate a commented starter file:

```bash
dataglot init                       # writes ./dataglot.toml (won't overwrite; use --force)
# — or stream it to stdout / a custom path —
dataglot --print-example-config > my-config.json
```

You get a ready-to-edit `dataglot.toml`:

```toml
# Dataglot starter config. Full reference: docs/configuration.md
host = "127.0.0.1"
port = 5432
default_catalog = "pg"
default_schema = "public"

[catalogs.pg]
kind = "postgres"
dsn_env = "DATAGLOT_PG_DSN"

[[masks]]
table = "users"
column = "email"
mask_literal = "***@example.com"
```

> Lines starting with `#` are TOML comments — delete them, and the
> `[[masks]]` block, freely; every block is optional. (A `.json` config
> still loads too, for back-compat.)

---

## 3. Point it at your data

Each entry under `catalogs` is a data source. Its **key is the catalog
name** you'll use in SQL as `<catalog>.<schema>.<table>`. Edit the starter
to describe your source(s). A few common shapes:

**PostgreSQL / MySQL** — a connection string via an env var:

```toml
[catalogs.pg]
kind = "postgres"
dsn_env = "DATAGLOT_PG_DSN"

[catalogs.sales]
kind = "mysql"
dsn_env = "SALES_MYSQL_DSN"
```

**Your files (object storage)** — Parquet, CSV, or JSON, local or on S3:

```toml
[catalogs.files]
kind = "object_storage"

[catalogs.files.s3]
endpoint = "http://minio:9000"
access_key_id = "minioadmin"
secret_access_key_env = "S3_SECRET"

[[catalogs.files.tables]]
name = "events"
url = "s3://lake/events/*.parquet"
format = "parquet"

[[catalogs.files.tables]]
name = "signups"
url = "file:///data/signups.csv"
format = "csv"
```

Other kinds — `snowflake`, `oracle`, `warehouse` (lakehouse), `odata` /
`sap_s4hana` — are documented in
[`configuration.md` → `catalogs`](configuration.md).

---

## 4. Provide credentials (never in the file)

Secrets are **never** written in `dataglot.toml`. Every credential field
has an `*_env` twin naming an environment variable that Dataglot reads once
at boot. Set the ones your config references:

```bash
export DATAGLOT_PG_DSN='host=localhost port=5432 user=me password=secret dbname=app'
export SALES_MYSQL_DSN='mysql://svc:secret@10.0.0.6:3306/sales'
export S3_SECRET='…'
```

If a referenced variable is missing, the server tells you exactly which one
and how to set it — it won't start with half its sources unreachable
(unless you pass `--tolerate-unreachable-catalogs`).

---

## 5. Start the server

```bash
dataglot --config dataglot.toml
```

On a healthy boot you'll see it bind the pgwire port and connect each
catalog:

```
INFO Starting Dataglot version="…" host=127.0.0.1 port=5432
INFO registering federated catalog catalog=pg kind="postgres"
INFO Listening for connections addr=127.0.0.1:5432
```

Useful flags (all also settable via `DATAGLOT_*` env vars):

| Flag | Purpose |
|---|---|
| `--config <path>` | Path to `dataglot.toml` (or `DATAGLOT_CONFIG`) |
| `--port <n>` | pgwire port (default 5432) |
| `--host <addr>` | bind address (default `127.0.0.1`; use `0.0.0.0` in containers) |
| `--log-format json` | structured logs |
| `--tolerate-unreachable-catalogs` | boot even if a source is down (skips it with a WARN) |

---

## 6. Connect and run a query

Dataglot is a Postgres server, so connect with anything that speaks
Postgres. Auth defaults to **trust** (no password) — fine for local dev;
turn on MD5 + TLS for anything shared (see `auth` / `pgwire_tls` in the
reference).

```bash
psql -h 127.0.0.1 -p 5432 -U dev -d pg
```

Query with **three-part names** — `catalog.schema.table` — which is how you
reach across sources:

```sql
-- one source
SELECT id, email FROM pg.public.users LIMIT 5;

-- join across two different databases in one query
SELECT u.email, o.total
FROM   pg.public.users u
JOIN   sales.public.orders o ON o.user_id = u.id;

-- your files, joined to a database
SELECT * FROM files.public.events e JOIN pg.public.users u ON u.id = e.user_id;
```

psql introspection works too — `\dt`, `\d pg.public.users`, `\l`.

If a `masks` or `row_filters` rule matches, it's applied automatically and
transparently — e.g. `users.email` above comes back masked for every
client, with no way to opt out from the query side.

---

## 7. Add governance (optional)

Column masks and row filters live in the same config, enforced at plan
time (not as a view you can bypass):

```toml
[[masks]]
table = "pg.public.users"
column = "ssn"
mask_type = { kind = "show_last", keep = 4 }

[[row_filters]]
table = "pg.public.orders"
predicate = { kind = "sql", sql = "region = 'EU'" }
```

Tag-based policies, per-identity roles, and access-deny rules are covered in
[`configuration.md` → Governance](configuration.md). For the whole picture —
how authentication, GRANT authorization, and governance fit together — read the
[access-control overview](access-control.md).

---

## Troubleshooting the first 30 minutes

| You see… | Cause | Fix |
|---|---|---|
| `config file not found: …` | wrong `--config` path | run `dataglot init` to create one, or fix the path |
| `catalogs.pg.dsn_env: environment variable 'X' is not set` | a referenced `*_env` var is missing | `export X='…'` and restart |
| `…is running on … with 0 catalogs configured` | started without `--config` (or an empty one) | add a catalog and pass `--config` |
| `port 5432 is already in use` | another Postgres (or Dataglot) is on that port | `--port 5433`, or stop the other process |
| query returns 0 rows from a file table | glob matched nothing / wrong extension | check the `url` and that files end `.parquet`/`.csv`/`.json` |
| `table 'x' not found` | unqualified name, or wrong catalog/schema | use `catalog.schema.table`; check `\dt` |

Every boot/first-run error is written to say **what's wrong and what to
do** — if one doesn't, that's a bug worth filing.

---

## Where to go next

- **[`runtime-config.md`](runtime-config.md)** — manage catalogs, secrets,
  users, and governance at runtime with SQL DDL, with no `dataglot.toml`.
- **[`reference-comparison.md`](reference-comparison.md)** — how Dataglot's
  control plane compares to RisingWave, Snowflake, Trino, and others.
- **[`configuration.md`](configuration.md)** — every field, every catalog
  kind, governance, TLS, auth, rate limiting, observability.
- **`examples/demo/`** — worked configs exercised by the demo and tests
  (Postgres + MySQL, governance, lakehouse, DataHub publisher).
- **Security for shared deployments** — set `auth.mode = "md5"` and
  `pgwire_tls.mode = "require"`; see the `auth` / `pgwire_tls` sections.

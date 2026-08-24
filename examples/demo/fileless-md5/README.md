# Fileless + md5 demo

Boots Dataglot with **no state in the config file** — no `catalogs`, no
`identities` state, no `masks`. The config is just *bootstrap* (bind address,
auth mode, meta-store location); everything else is created at runtime over SQL
DDL and lives in the meta store. Connections authenticate with **md5**.

This mirrors what the testbench/demo does, but the RisingWave-style way: state
via DDL, not JSON. (`tpch`/`lakehouse` still need file config until
`object_storage`/`warehouse` DDL lands — see the note at the bottom.)

## Prerequisites

The demo source databases — `make demo-sources` in the private dev repo
brings up postgres :5433, postgres-orders :5434, and mysql :3306; any
Postgres/MySQL you already run works too (adjust the DSNs in
[`seed.sql`](seed.sql)).

## 1. Boot (bootstrap-only config)

[`bootstrap.json`](bootstrap.json) has one bootstrap admin (`admin`, password
from `DG_ADMIN_PW`) and an embedded meta store — nothing else.

```bash
export DG_ADMIN_PW='admin-pw'
export DATAGLOT_SECRET_KEY="$(openssl rand -base64 32)"   # envelope key for CREATE SECRET
dataglot --config examples/demo/fileless-md5/bootstrap.json --port 15432 --metrics-addr disabled
```

The server logs a warning that md5 without ingress TLS sends the hash in the
clear — for production add `[pgwire_tls] mode = "require"`.

## 2. Seed the control plane over SQL (as `admin`)

Connect to the `dataglot` bootstrap database (there are no catalogs yet) and run
[`seed.sql`](seed.sql) — encrypted secrets, catalogs that reference them, a
derived-product view, and a runtime user:

```bash
PGPASSWORD="$DG_ADMIN_PW" \
  psql "host=127.0.0.1 port=15432 user=admin dbname=dataglot" \
  -f examples/demo/fileless-md5/seed.sql
# CREATE SECRET  ×2
# CREATE CATALOG ×3
# CREATE VIEW
# CREATE USER
```

## 3. Log in as the runtime user and query across sources

`analyst` was created at runtime with **no config entry** — it authenticates
via md5 and can query the federated catalogs:

```bash
PGPASSWORD='analyst-pw' \
  psql "host=127.0.0.1 port=15432 user=analyst dbname=pg" -c "
SELECT s.segment, COUNT(*) AS orders, SUM(o.amount) AS revenue
FROM pg_orders.public.orders o
JOIN mysql_demo.demo.customer_segments s ON s.user_id = o.user_id
GROUP BY s.segment ORDER BY revenue DESC, s.segment;"
```

```
 segment  | orders | revenue
----------+--------+---------
 standard |      3 |  298.45
 beta     |      2 |  218.50
 premium  |      1 |   49.99
```

The `order_segments` **derived product** created in `seed.sql` is queryable like
any table — no `dataglot.toml` `[[derived_products]]` entry:

```bash
PGPASSWORD='analyst-pw' \
  psql "host=127.0.0.1 port=15432 user=analyst dbname=pg" -c "
SELECT segment, COUNT(*) AS orders, SUM(amount) AS revenue
FROM order_segments GROUP BY segment ORDER BY revenue DESC, segment;"
```

Everything — the secrets, catalogs, the view, the user — survives a restart; it
lives in the meta store (`/tmp/dataglot-fileless-meta.json` here), not in a
config file.

See [`docs/runtime-config.md`](../../../docs/runtime-config.md) for the full DDL
reference.

## Known gap

The `tpch` (parquet / `object_storage`) and `lakehouse` (Iceberg / `warehouse`)
catalogs used by the full benchmark can't be created via DDL yet — their nested
config doesn't fit the flat `WITH (key = value)` option bag. They stay
file-configured until an `object_storage`/`warehouse` DDL form lands; the SQL
sources (postgres, mysql) go fully fileless as shown above.

Derived products no longer need file config: `CREATE VIEW` (above) persists a
plain derived product to the meta store, so the `[[derived_products]]` block is
fileless too. Materialized derived products still need file config until a
materialization DDL form lands.

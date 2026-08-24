# Configuration reference — `dataglot.toml`

> **New to Dataglot?** Start with the step-by-step
> [Getting started guide](getting-started.md) (install → config → first
> query). This page is the exhaustive field reference.

The Dataglot server takes a **bootstrap** TOML config — bind address, TLS,
auth, and any initial catalogs/policies — passed via `--config <path>` (or the
`DATAGLOT_CONFIG` env var). Every block is optional; an empty file boots a bare
server. Catalogs, secrets, users, roles, and policies can also be created **at
runtime over SQL DDL** and persisted in the meta store — see
[`runtime-config.md`](runtime-config.md). This page is the exhaustive
file-config reference; the authoritative source is
`crates/dataglot-server/src/config.rs`.

> **Format:** TOML is the canonical config format. A `.json` config
> still loads — the loader dispatches on file extension — so existing
> `dataglot.json` files keep working; new configs should use `.toml`.

**Fastest start** — scaffold a commented starter, then point the server
at it:

```bash
dataglot init                       # writes./dataglot.toml (refuses to clobber; --force to overwrite)
# edit dataglot.toml, export the DSN env var it names, then:
dataglot --config dataglot.toml
```

`dataglot --print-example-config` streams the same content to stdout
instead (`… > custom.toml`, or pipe it elsewhere). The generated file uses
real `#` comments, so it stays valid TOML you can trim down. Booting with
no catalogs prints a banner telling you exactly this.

Worked example configs (exercised by the demo and integration tests):

- [`examples/demo/dataglot.toml`](../examples/demo/dataglot.toml) — postgres + mysql catalogs, static masks + row filters
- [`examples/demo/dataglot-with-governance.toml`](../examples/demo/dataglot-with-governance.toml) — tag-based governance, identities
- [`examples/demo/dataglot-with-lakehouse.toml`](../examples/demo/dataglot-with-lakehouse.toml) — warehouse catalog (REST catalog + S3)
- [`examples/demo/dataglot-with-datahub.toml`](../examples/demo/dataglot-with-datahub.toml) — governance publisher

**Credential rule (applies everywhere):** secrets are never written in
the config file. Every credential field has an `*_env` twin naming an
environment variable; the server resolves it once at boot and fails
fast if it's missing. Literal-secret fields (`password`, `token`,
`secret_access_key`, `dsn` with inline password) exist as dev-only
escape hatches. Secrets never appear in logs, errors, or plans.

## Top-level fields

| Key | Type | Default | Meaning |
|---|---|---|---|
| `host` | string | `"127.0.0.1"` | Bind address for the pgwire listener |
| `port` | integer | `5432` | pgwire port |
| `batch_size` | integer | `8192` | Row batch size for query execution |
| `partitions` | integer | CPU count | Target partitions for parallel execution |
| `default_catalog` | string | `"dataglot"` | Catalog for unqualified table references |
| `default_schema` | string | `"public"` | Schema for unqualified references |
| `memory_limit_bytes` | integer | unset | Cap on query-execution memory. When set, heavy operators (joins, sorts, aggregations) spill to disk or fail with a "resources exhausted" error instead of growing until the OS kills the server. Unset = unbounded. Recommended alongside `[ballista]` distributed execution |
| `spill_dir` | string | OS temp dir | Directory for operator spill files; only used when spilling occurs (pair with `memory_limit_bytes`) |
| `tolerate_unreachable_catalogs` | bool | `false` | `true`: skip catalogs that fail to connect at boot (WARN); `false`: fail fast |

Plus the nested blocks documented below: `observability`, `catalogs`,
`masks`, `row_filters`, `access_denials`, `identities`, `roles`,
`governance`, `derived_products`, `maintenance`, `auth`, `pgwire_tls`,
`rate_limit`, `policy_explain`, `lineage`, `governance_publishers`,
`webhook`, `catalog_service`, `ballista`.

## `observability`

| Key | Type | Default | Meaning |
|---|---|---|---|
| `log_format` | `"plain"` \| `"json"` | `"plain"` | Log output format |
| `log_filter` | string | `"dataglot=info"` | `EnvFilter` directive used when `RUST_LOG` is unset |
| `metrics_addr` | `"host:port"` or `null` | `"127.0.0.1:9090"` | Prometheus `/metrics` bind address; `null` disables |
| `health_check_enabled` | bool | `true` | Expose `/health` alongside `/metrics` |
| `capture_query_sources` | bool | `false` | Plan each query once up front to record the source catalogs it federates across (dashboard federation breakdown), and — when execution is single-partition single-node — capture the per-source pushdown profile shown in the dashboard query treeview. Does **not** change parallelism. The pushdown→query correlation runs on the connection task, which DataFusion's parallel execution spawns past, so the treeview populates only with `partitions = 1` (an explicit profiling choice — it serializes local execution). In distributed mode pushdowns run in the executor processes and aren't captured by the scheduler dashboard. |
| `connector_health_interval_secs` | int (seconds) | `30` | Background source-health probe interval feeding the dashboard's live connector status and the `dataglot_connector_up` gauge; `0` disables the poller (sources then carry zero monitoring load, liveness only via an on-demand "Check now") |

The same listener serves `GET /lineage`: the boot-time column-lineage
graph across declared `derived_products`, as JSON
(`{products, nodes, edges}`), with each column annotated
`configured` / `propagated` when a mask covers it. This is the
inspection surface for lineage-propagated governance (a mask on
`users.email` extends to every derived column that descends from it) —
the testbench's Lineage tab renders it. Loopback-only, like
`/metrics`: it exposes table/column names and product SQL.

## `catalogs` — data sources

A map of catalog name → source config. The name becomes the SQL
catalog: `SELECT * FROM <name>.<schema>.<table>`. Each entry is
discriminated by `kind`.

#### Declaring catalogs without a file (env vars)

For containerized / 12-factor deploys you can declare catalogs entirely
via the environment — no `dataglot.json` needed. Each
`DATAGLOT_CATALOG_<NAME>` variable holds a single catalog object as JSON;
the `<NAME>` suffix is lowercased to form the catalog name:

```bash
export DATAGLOT_CATALOG_PG='{"kind":"postgres","dsn_env":"PG_DSN"}'
export DATAGLOT_CATALOG_MYSQL_DEMO='{"kind":"mysql","dsn_env":"MYSQL_DSN"}'
export PG_DSN='host=db port=5432 user=me password=... dbname=app'
export MYSQL_DSN='mysql://me:...@db:3306/app'
dataglot            # boots with catalogs `pg` and `mysql_demo`, no file
```

Env catalogs are merged **after** any `--config` file and **override** a
file-declared catalog of the same name. Secrets still never live in the
value directly — use the `*_env` twins (`dsn_env`, …) exactly as in the
file. (Governance, identities, and other structural blocks remain
file-only for now; see the roadmap for moving those to the control plane.)

### `kind: "postgres"` / `kind: "mysql"`

```toml
[catalogs.pg]
kind = "postgres"
dsn_env = "DEMO_PG_DSN"
tls = "require"
tls_ca_file = "/etc/ssl/private-ca.pem"
```

| Key | Type | Default | Meaning |
|---|---|---|---|
| `dsn` / `dsn_env` | string | — | Connection DSN, literal or env-var name — **exactly one required** |
| `tls` | `"disable"` \| `"require"` | `"disable"` | Source-connection TLS (rustls; verifies the server certificate) |
| `tls_ca_file` | path | OS/Mozilla trust store | PEM CA bundle for private/self-signed CAs |
| `tls_accept_invalid_certs` | bool | `false` | **Dev/test only** — skips certificate verification |

### `kind: "snowflake"`

```toml
[catalogs.sf]
kind = "snowflake"
account = "acme-prod1"
warehouse = "COMPUTE_WH"
database = "ANALYTICS"
user = "DATAGLOT_SVC"
password_env = "SNOWFLAKE_PASSWORD"
schema = "PUBLIC"
role = "ANALYST_ROLE"
```

`account`, `warehouse`, `database`, `user` are required; exactly one of
`password` / `password_env` is required; `schema` and `role` are
optional. Transport is HTTPS by nature of the Snowflake API.

### `kind: "oracle"` *(feature-gated: build with `oracle` and/or `oracle-pure`)*

```toml
[catalogs.ora]
kind = "oracle"
dsn = "//db.internal:1521/ORCLPDB1"
user = "DATAGLOT"
password_env = "ORACLE_PASSWORD"
driver = "pure"
```

| Key | Type | Default | Meaning |
|---|---|---|---|
| `dsn` | string | — | Oracle Easy Connect string (no credentials in it) — required |
| `user` | string | — | Required (Oracle folds unquoted identifiers to uppercase) |
| `password` / `password_env` | string | — | Exactly one required |
| `schema` | string | connection user | Default owner/schema |
| `driver` | `"oci"` \| `"pure"` | build default | Wire backend: `oci` needs the Oracle Instant Client C runtime; `pure` is pure Rust. Selecting an uncompiled driver fails at boot. |

### `kind: "warehouse"` — lakehouse tables (REST catalog + S3)

```toml
[catalogs.lakehouse]
kind = "warehouse"
catalog_url = "http://lakekeeper:8181/catalog"
warehouse = "demo"
s3_endpoint = "http://minio:9000"
s3_region = "us-east-1"
credentials = { kind = "static", access_key_id = "minio", secret_access_key_env = "LAKEHOUSE_S3_SECRET" }
```

`catalog_url`, `warehouse`, `credentials` are required. `credentials.kind`
is `"environment"` (standard AWS env vars) or `"static"`
(`access_key_id` + exactly one of `secret_access_key` /
`secret_access_key_env`). `s3_endpoint` targets S3-compatible stores
(MinIO, RustFS); omit for AWS S3.

### `kind: "object_storage"` — query files directly

```toml
[catalogs.files]
kind = "object_storage"

[catalogs.files.s3]
endpoint = "http://minio:9000"
region = "us-east-1"
access_key_id = "minioadmin"
secret_access_key_env = "S3_SECRET"
path_style_access = true

[[catalogs.files.tables]]
name = "events"
url = "s3://lake/events/*.parquet"
format = "parquet"

[[catalogs.files.tables]]
name = "signups"
url = "file:///data/signups.csv"
format = "csv"
schema = "raw"

[[catalogs.files.tables]]
name = "logs"
url = "file:///data/logs.json"
format = "json"
```

Each table becomes `<catalog>.<schema>.<name>` (schema defaults to `public`).

- **Formats:** `parquet`, `csv` (a header row is assumed), and `json`
  (newline-delimited — one JSON object per line). Schema is inferred at boot.
- **Schemes:** `file://` always; `s3://` when the `[s3]` block is present.
  Globs work (`s3://lake/events/*.parquet`, `file:///data/part-*.parquet`).
- **`[s3]` block:** omit `endpoint` for real AWS; set it for S3-compatibles
  (MinIO, Cloudflare R2, …). `secret_access_key_env` names an env var holding
  the secret (preferred over inline `secret_access_key`, rule 12). Omit both to
  fall back to the ambient AWS credential chain (for public buckets, that's
  fine). `path_style_access` defaults to `true` (MinIO / self-hosted); set
  `false` for virtual-hosted AWS buckets. `region` defaults to `us-east-1`.
- `gs://` and `abfs://` are not yet supported.

### `kind: "odata"` / `kind: "sap_s4hana"` — REST sources

```toml
[catalogs.sap]
kind = "sap_s4hana"
service_url = "https://host/sap/opu/odata/sap/API_BUSINESS_PARTNER"
sap_client = "100"
sap_language = "EN"
auth = { kind = "basic", user = "svc", password_env = "SAP_PASSWORD" }
```

`service_url` and `auth` are required. `auth.kind` is `"basic"` (`user`
+ one of `password`/`password_env`) or `"bearer"` (one of
`token`/`token_env`). The `sap_s4hana` kind adds the optional
`sap_client` / `sap_language` request headers.

### `kind: "rest"` — generic REST/JSON sources (Salesforce, HTTP APIs)

For JSON APIs that aren't OData (Salesforce, Athena Health, and similar). Unlike
OData there's no metadata document, so each table declares its **URL**, where
the row array lives (`records_path`), its **columns**, and how to **paginate**.

```toml
[catalogs.salesforce]
kind = "rest"
schema = "public"
auth = { kind = "bearer", token_env = "SF_TOKEN" }

[[catalogs.salesforce.tables]]
name = "account"
url = "https://acme.my.salesforce.com/services/data/v58.0/query?q=SELECT+Id,Name,AnnualRevenue+FROM+Account"
records_path = "records"
pagination = { kind = "next_link", next_path = "nextRecordsUrl" }
columns = [
  { name = "Id", type = "utf8" },
  { name = "Name", type = "utf8" },
  { name = "AnnualRevenue", type = "float64", nullable = true },
]
```

Each table becomes `<catalog>.<schema>.<name>` (schema defaults to `public`).
REST/JSON field names are case-sensitive, so quote them in SQL.

To try it without a real SaaS tenant, the testbench ships a **mock SaaS
service** (`mock-saas`, a wiremock container serving a Salesforce-shaped
collection with `nextRecordsUrl` pagination) wired as the `saas` catalog —
`SELECT * FROM saas.public.accounts` returns 3 rows across two mock pages. See
`examples/demo/dataglot-with-rest.toml` and `examples/demo/mock-saas/mappings/`.
Like other direct-`TableProvider` sources (ADBC), REST is **single-node only**:
under `--distributed` a query against `saas` is refused with a "run single-node"
message (no distributed plan codec — ), so run the testbench without
`--distributed` to query it.

- **`url`** — the request endpoint (may carry a query string, e.g. a SOQL query).
- **`records_path`** — dot-path to the row array in the response (`""` = the body
  is itself the array; `"records"` for Salesforce).
- **`columns`** — one per selected field: `name` + `type` (`utf8`, `boolean`,
  `int32`, `int64`, `float64`) + optional `nullable` (default `true`).
- **`pagination`** — `{ "kind": "none" }` (default) or
  `{ "kind": "next_link", "next_path": "<dot-path to next URL>" }` to follow a
  next-page link (absolute or relative) until absent — e.g. Salesforce's
  `nextRecordsUrl`.
- **`auth`** — `"none"` (default), `"basic"` (`user` + `password`/`password_env`),
  `"bearer"` (`token`/`token_env`), `"header"` (`name` + `value`/`value_env`
  for an API-key header), or `"oauth2"` (see below). Secrets prefer the `*_env`
  form (rule 12).

For **Salesforce and other OAuth 2.0 client-credentials sources**, the connector
acquires and refreshes its own bearer token — no static token to rotate:

```toml
[catalogs.salesforce.auth]
kind = "oauth2"
token_url = "https://login.salesforce.com/services/oauth2/token"
client_id_env = "SF_CLIENT_ID"
client_secret_env = "SF_CLIENT_SECRET"
scope = "api"
```

`token_url` is required; `client_id` and `client_secret` each take exactly one
of the literal or `*_env` form; `scope` is optional. OAuth2 is connector-level
(one refreshed token serves every table), and the token is fetched lazily on
first query, cached, and refreshed before expiry.

Like OData, REST is a direct `TableProvider` (rule 3) — it federates and is
governed (masks / row-filters apply) exactly like a SQL source.

## Governance and policy

> Governance (masks, row filters, access-deny) is the third access-control
> layer, after authentication and GRANT authorization. For how the three
> compose — and why a superuser bypasses grants but never masks — see
> [`access-control.md`](access-control.md).

### `masks` — column masking

```toml
[[masks]]
table = "users"
column = "email"
mask_literal = "***@example.com"

[[masks]]
table = "pg.public.users"
column = "ssn"
mask_type = { kind = "show_last", keep = 4 }
priority = 10
```

| Key | Type | Default | Meaning |
|---|---|---|---|
| `table` | string | — | Bare, partial, or fully-qualified table reference — required |
| `column` | string | — | Required |
| `mask_literal` | string | `""` | Replacement Utf8 literal (used when `mask_type` absent) |
| `mask_type` | object | — | Named mask: `redact`, `show_last`/`show_first` (+`keep`), `hash` (MD5), `nullify`, `date_year`, `constant` (+`value`) |
| `priority` | integer | `0` | Highest wins when rules collide; a tie at the top is a boot error |

### `row_filters` — row-level filtering

```toml
[[row_filters]]
table = "users"
predicate = { kind = "eq_string", column = "email", value = "bob@example.com" }

[[row_filters]]
table = "orders"
predicate = { kind = "sql", sql = "region = 'EU' AND status IS NOT NULL" }
```

Predicate kinds: `eq_string`, `eq_int`, `gt_int` (declarative, typed),
or `sql` (arbitrary boolean expression, parsed at boot — for non-Utf8
columns prefer the typed variants or explicit `CAST`s). Filters
evaluate on **unmasked** values and wrap the table scan — no bypass.

### `access_denials` — table/column deny

```toml
[[access_denials]]
table = "salaries"
groups = ["analyst"]

[[access_denials]]
table = "users"
column = "ssn"
groups = []
```

Enforced plan-time *before* masking; a denied query fails with
`permission denied`. Empty `groups` denies everyone.

### `identities` and `roles`

```toml
[identities.alice]
org = "acme"
groups = ["analyst"]
password_env = "ALICE_PASSWORD"

[roles.pii_reader]
users = ["alice"]
groups = ["auditor"]
```

`identities` maps the pgwire username to org + group memberships (the
policy identity; unknown usernames get empty groups). `password_env` is
consulted only under `auth.mode = "md5"`. A `roles` entry folds into
the session's effective groups when its user or any group matches.

### `governance` — tag-based policies

```toml
[governance]
tags = [ { id = "pii", org = "acme", name = "PII" } ]
policies = [ { id = "mask-pii", org = "acme", tag = "pii", group = "analyst", rule = { kind = "mask", mask_literal = "***" } } ]
columns = [ { table = "users", column = "email", tags = ["pii"] } ]
```

Tag → policy → column indirection: tag a column and every policy
attached to that tag fires for sessions in the policy's group. Rule
kinds mirror the static blocks: `mask` (+`mask_literal`) and
`row_filter` (+`predicate`). The inbound governance webhook (below)
mutates this registry at runtime.

### `derived_products` — data products with lineage

```toml
[[derived_products]]
name = "eu_revenue"
sql = "SELECT... FROM orders..."
backing = "materialized"
materialization = { warehouse = "lakehouse", namespace = "products", refresh_every = "15m" }
```

Planned once at boot to extract column lineage, so masks on *source*
columns propagate to derived columns. `backing` is `"live"` (default;
planned per read) or `"materialized"` (refreshed into a warehouse
table on the `refresh_every` cadence — durations like `"30s"`, `"15m"`,
`"1h"`, `"2d"`).

A **materialized** product whose `sql` federates across sources is the
no-`dblink` migration pattern: a query that on a legacy stack would be an
Oracle `dblink` + `CREATE TABLE` job becomes a governed federated read
persisted to the lakehouse on a schedule — no per-source link, no
data-movement script. See `examples/demo/dataglot-with-lakehouse.toml`
(`customer_360_mart`, federating `pg` + `pg_orders` into an Iceberg
table).

Refresh status for every materialized product is observable at
`GET /api/materialization` (and the dashboard's **Materialization** tab):
per product — state (`pending`/`running`/`success`/`error`), last row
count and duration, when it last ran, the approximate next run, and a
run/failure tally. A failed refresh is non-fatal (the prior snapshot is
retained and the scheduler retries next tick); its redacted error is
surfaced there. Loopback-only, same posture as the rest of `/api`.

## Security

### `auth`

| Key | Type | Default | Meaning |
|---|---|---|---|
| `mode` | `"trust"` \| `"md5"` \| `"scram-sha-256"` \| `"jwt"` \| `"ldap"` | `"trust"` | `trust`: the asserted username is believed (a boot warning fires if policies are configured); `md5` / `scram-sha-256`: password exchange against each identity's `password_env` (SCRAM preferred); `jwt`: a signed JWT as the password, its `groups` claim drives policy (needs `[auth.jwt]`); `ldap`: directory bind + group search (needs `[auth.ldap]`) |

`jwt` mode reads an `[auth.jwt]` block (algorithm `hs256`/`rs256`/`es256`, `secret_env` or `public_key_file`, `groups_claim`, `issuer`, `audience`, `leeway_secs`); `ldap` reads `[auth.ldap]`. See [`authentication.md`](authentication.md) for the mode details.

### `authz` — object authorization (GRANT)

| Key | Type | Default | Meaning |
|---|---|---|---|
| `mode` | `"open"` \| `"grant"` | `"open"` | `open`: no enforcement — any authenticated session may read any table; `grant`: **deny-unless-granted** — a read needs `USAGE` on the catalog **and** `SELECT` on the table, missing either is rejected at plan time |

Grants are written with the `GRANT` / `REVOKE`
[DDL](runtime-config.md#grant--revoke-access-control), apply per role or user,
and are org-scoped. Superuser sessions bypass grant enforcement (but never
column masks or row filters). See [`authentication.md` →
Authorization](authentication.md#authorization-grantrevoke), and
[`access-control.md`](access-control.md) for how authentication, GRANT, and
governance compose.

### `pgwire_tls` — client↔server encryption

```toml
[pgwire_tls]
cert_file = "/etc/tls/server.pem"
key_file = "/etc/tls/server.key"
mode = "require"
```

`mode` is `"prefer"` (default — accept TLS and plaintext) or
`"require"` (reject plaintext). Omitting the block leaves the listener
plaintext (and md5 auth then warns at boot).

### `rate_limit` — connection admission

| Key | Meaning |
|---|---|
| `max_connections` | Global concurrent-connection ceiling |
| `max_connections_per_ip` | Per-source-IP concurrent ceiling |
| `max_new_connections_per_ip_per_minute` | Per-IP token bucket on new connections (brute-force/churn defense) |
| `max_connections_per_identity` | Per-username concurrent ceiling (enforced on the startup message) |

All optional; omitted = unlimited. Rejections emit `dataglot::audit`
events and bump `dataglot_pgwire_connections_rejected_total{reason}`.

These ceilings (plus `memory_limit_bytes`) and the live usage against
them — active connections, the busiest IP / identity bucket, and
cumulative rejections by reason — are served at `GET /api/limits` and
rendered as the dashboard's **Resource limits** panel (Sessions tab), so
an operator can see headroom at a glance. Loopback-only, same posture as
the rest of `/api`.

### `policy_explain` — explainability endpoint

```toml
[policy_explain]
addr = "127.0.0.1:8085"
token_env = "POLICY_EXPLAIN_TOKEN"
```

Enables `POST /policy/explain`: plans a SQL string (never executes)
and reports the mask / row-filter / deny decisions for a given
identity. `token_env` names a bearer token; unset ⇒ open endpoint +
boot warning.

## Integrations

### `lineage` — OpenLineage emitter

```toml
[lineage]
kind = "openlineage_http"
endpoint = "http://marquez:5000/api/v1/lineage"
namespace = "dataglot.acme"
```

Emits an OpenLineage `RunEvent` (with column-level `columnLineage`
facets) per query. Compatible with DataHub, Marquez, OpenMetadata,
Gravitino, Informatica. Omit for no emission.

### `governance_publishers` — outbound metadata

```toml
[[governance_publishers]]
kind = "datahub"
gms_endpoint = "http://datahub-gms:8080"
bearer_token_env = "DATAHUB_TOKEN"
```

Publishes data products / column metadata to the platform at boot and
on binding changes. `bearer_token_env` optional (local DataHub dev
deployments run unauthenticated).

### `webhook` — inbound governance (policy ingestion)

```toml
[webhook]
addr = "0.0.0.0:8084"
secret_env = "DATAGLOT_WEBHOOK_SECRET"
```

HMAC-SHA256-authenticated endpoint receiving tag/policy/certification
events from a governance platform's actions framework; propagates into
enforcement in under 60 seconds. Both fields required to enable.

### `catalog_service`

The meta store that persists runtime control-plane DDL (`CREATE CATALOG` /
`SECRET` / `USER` / `ROLE` / `MASK` …). Two backends — pick by the keys you set:

```toml
# embedded (default, zero-dependency):
[catalog_service]
path = "/var/lib/dataglot/meta.json"
org_id = "default"

# — or — Postgres-backed (HA / multi-node): set `dsn` instead of `path`:
# [catalog_service]
# dsn = "postgres://user:pass@host/catalog"
# org_id = "default"
```

Omitted = catalogs come only from `catalogs` (file/env) and no runtime DDL is
available. When configured, the store is also a **source of truth for
catalogs**: at boot the server unions the file/env config with the source
configs stored in the meta store; for a name the file also declares, the file
wins. Stored source configs are credential-free — they name `*_env` vars or
`dsn_secret` references, never secret values; encrypting secrets at rest needs
`DATAGLOT_SECRET_KEY`. See [`runtime-config.md`](runtime-config.md) for the
runtime DDL + secrets detail.

### `maintenance` — scheduled compaction

```toml
[[maintenance.compaction]]
warehouse = "lakehouse"
namespace = "products"
table = "eu_revenue"
compact_every = "6h"

[[maintenance.orphan_cleanup]]
warehouse = "lakehouse"
namespace = "products"
sweep_every = "1h"
min_age = "6h"
```

`compaction` rewrites a table into fewer, larger files (Trino
`OPTIMIZE`); `orphan_cleanup` sweeps stale staging/parked tables left by
interrupted writes. Both run on the in-process scheduler. Their live
status — per job: state, last run, files affected / tables swept,
next run, and any redacted error — is served at `GET /api/maintenance`
and rendered as the **Warehouse maintenance** panel on the dashboard's
Materialization tab. Loopback-only, same posture as the rest of `/api`.

### `ballista` — distributed execution *(feature-gated: `ballista`)*

```toml
[ballista]
standalone_parallelism = 4
rest_api_port = 50050
```

Spins up an in-process standalone Ballista cluster (1 scheduler +
executors with the given task slots). Present-but-uncompiled is a boot
error.

Distributed-capable catalogs: federated SQL sources (`postgres`,
`mysql`), **Iceberg warehouses** (`warehouse` — lazily rebuilt on
executors, the catalog `load_table` happens at execution time), and
`object_storage` files. Other kinds fail with a clear "not available
in distributed mode" error and should be queried single-node.

`rest_api_port` serves the scheduler's observability REST API on
loopback (`/api/state`, `/api/executors`, `/api/jobs`,
`/api/job/{id}/stages`, `/api/job/{id}/dot` and `/dot_svg` execution
graphs — SVG requires graphviz `dot` on the host) — the data source
for live cluster monitoring. Default `50050`; `null` disables.
Loopback-only by design: the endpoints are unauthenticated and can
expose query text.

The same listener serves **cluster metrics in Prometheus format** at
`/api/metrics` — job/task/executor counters from the Ballista
scheduler. This is a second scrape target alongside the server's own
`metrics_addr` (`:9090/metrics`, pgwire/session metrics):

```yaml
# prometheus.yml
scrape_configs:
  - job_name: dataglot-server
    metrics_path: /metrics
    static_configs: [{ targets: ["localhost:9090"] }]
  - job_name: dataglot-cluster          # only when ballista is enabled
    metrics_path: /api/metrics
    static_configs: [{ targets: ["localhost:50050"] }]
```

Since both listeners are loopback-only, run the Prometheus scraper on
the same host (or bridge with a local agent).

## CLI flags and environment variables

Every flag has an env-var twin; precedence is **CLI > env > config
file > built-in default**.

| Flag | Env var | Meaning |
|---|---|---|
| `-c, --config <path>` | `DATAGLOT_CONFIG` | Config file path |
| `-H, --host` | `DATAGLOT_HOST` | Bind address |
| `-p, --port` | `DATAGLOT_PORT` | pgwire port |
| `--batch-size` | `DATAGLOT_BATCH_SIZE` | Execution batch size |
| `--partitions` | `DATAGLOT_PARTITIONS` | Parallelism |
| `--default-catalog` | `DATAGLOT_DEFAULT_CATALOG` | Default catalog |
| `--default-schema` | `DATAGLOT_DEFAULT_SCHEMA` | Default schema |
| `--tolerate-unreachable-catalogs` | `DATAGLOT_TOLERATE_UNREACHABLE_CATALOGS` | Skip unreachable catalogs at boot |
| `--log-format` | `DATAGLOT_LOG_FORMAT` | `plain` \| `json` |
| `--log-filter` | `DATAGLOT_LOG_FILTER` | Filter when `RUST_LOG` unset (`RUST_LOG` wins) |
| `--metrics-addr` | `DATAGLOT_METRICS_ADDR` | `/metrics` address, or `disabled` |
| `--disable-health-check` | `DATAGLOT_DISABLE_HEALTH_CHECK` | Turn off `/health` |
| `--healthcheck` | `DATAGLOT_HEALTHCHECK` | One-shot TCP health probe (exit 0/1) — used by the Docker HEALTHCHECK |
| `-v, --verbose` | — | Verbose logging |

Secret-bearing env vars are whatever names your config's `*_env` fields
declare — the server reads each once at boot and refuses to start if
one is missing.

## Feature gates

The stock `dataglot-server` binary compiles the common connectors in
**unconditionally** — `kind` values `postgres` / `mysql` / `warehouse` /
`snowflake` / `odata` / `rest` all work out of the box. (Feature gates apply at
the `dataglot-federation` **library** level, where `all = postgres, mysql,
iceberg, odata, rest`; `iceberg` backs the user-facing `kind: "warehouse"`.)
The connectors the *server* leaves opt-in:

| Server Cargo feature | Unlocks |
|---|---|
| `adbc` | `kind: "adbc"` (bring-your-own ADBC driver) |
| `oracle` / `oracle-pure` | `kind: "oracle"` catalogs (OCI / pure-Rust backend) |
| `ballista` | the `ballista` config block (distributed execution) |
| `dashboard` | the operational dashboard at `/ui` (shipped in stock release binaries + the container image; off for a bare `cargo build` — add `--features dashboard` locally — ) |

A server built without a needed feature rejects the corresponding config at
boot with a clear, credential-free error.

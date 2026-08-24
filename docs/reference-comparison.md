# Reference comparison: runtime configuration and multi-tenancy

How Dataglot's SQL-native control plane ( — see
[`runtime-config.md`](runtime-config.md)) compares to the engines we drew from
or measure against. The short version: we mirror **RisingWave's** pluggable SQL
meta store and its "DDL is the front door" posture, and we deliberately diverge
on **one** axis — we put multi-tenancy *inside* the store (the Snowflake/Dremio
shape) rather than at the deployment level.

---

## The RisingWave lineage

RisingWave keeps its catalog and secrets in a **pluggable SQL meta store**
(Postgres, MySQL, or SQLite) and mutates it entirely through **runtime SQL DDL**
against a live cluster — no config file is the source of truth. Dataglot adopts
both:

- **Pluggable SQL meta store.** RisingWave's PG/MySQL/SQLite maps onto our
  **Postgres** backend (HA / multi-node) plus a **pure-Rust atomic-file** backend
  (the zero-dependency single-node default). We use an atomic-file store where
  RisingWave uses SQLite because SQLite is a C dependency we avoid on principle
  (Rust-only production runtime); the file store gives the same
  single-binary-no-external-service experience without the native dep.
- **DDL is the front door.** `CREATE / ALTER / DROP CATALOG`, `CREATE / DROP
  SECRET`, `CREATE / ALTER / DROP USER`, and the governance DDL all run against a
  running server and take effect immediately — the meta store is the single
  source of truth, and there is no `dataglot.toml`.

---

## The deliberate divergence: tenancy in the store

This is the one place we consciously do **not** follow RisingWave, and it is a
data-mesh product choice we make with eyes open.

**RisingWave does tenancy at the deployment level:** one cluster per tenant. There
is no `org` column in the catalog, and no notion of sharing an object across
tenants — isolation is achieved by running separate clusters.

**Dataglot puts tenancy in the store.** Every object — catalog, secret, user,
role, governance rule — carries an `org_id`, and the model is built to support
cross-org **`share` / `attachment`** primitives so one org can expose a curated
object to another. This is the **Snowflake / Dremio** shape (accounts / projects
with managed cross-tenant sharing), not the RisingWave shape.

We choose it because the product is a **data-mesh governance layer** for
regulated enterprises: multiple orgs sharing one control plane, with governed
cross-org sharing, is the point — not an accident. The honest tradeoff is that
per-tenant blast-radius isolation is weaker than cluster-per-tenant: one process
serves every org, so a control-plane bug is shared surface in a way that
cluster-per-tenant avoids. The seams themselves are multi-tenant — auth resolves
the connecting user's org at login (global-unique usernames), and masks, row
filters, and grants all enforce per-org (see [Gaps and roadmap](#gaps-and-roadmap)
for the remaining edges).

---

## The field

| Engine | Control-plane store | Runtime DDL |
| --- | --- | --- |
| **Dataglot** | Pluggable: Postgres **or** pure-Rust atomic file | Yes — `CREATE/ALTER/DROP CATALOG · SECRET · USER · MASK · ROW FILTER` · `GRANT/REVOKE` |
| **RisingWave** | Pluggable SQL: Postgres / MySQL / SQLite | Yes — DDL is the front door |
| **ClickHouse** | On-disk metadata + ClickHouse Keeper (Raft) for replicated DDL | Yes — runtime DDL, `ON CLUSTER` |
| **Dremio** | KV control-plane store; projects | Mostly — sources/spaces via API/UI + some SQL |
| **Snowflake** | Fully managed cloud service; accounts | Yes — SQL for everything (managed) |
| **Trino** | Static catalog `.properties` files on disk | No — catalog files, restart/refresh |
| **Postgres FDW** | The system catalog itself | Yes — `CREATE SERVER` / `CREATE USER MAPPING` |
| **DuckDB** | Embedded in the process / database file | Yes — `ATTACH` at runtime |

| Engine | Secrets | Users / auth |
| --- | --- | --- |
| **Dataglot** | `CREATE SECRET`, encrypted at rest (XChaCha20-Poly1305) | md5 **or** SCRAM-SHA-256 store-backed users + bootstrap identities; `GRANT`-based authorization (roles, org-scoped, superuser) |
| **RisingWave** | `CREATE SECRET` | trust / md5 / oauth / ldap |
| **ClickHouse** | Named collections; disk/KMS encryption | Native + SQL users, many methods |
| **Dremio** | Source-credential store | Local + LDAP/SSO |
| **Snowflake** | Managed secrets / secure integrations | Rich RBAC, MFA, SSO, key-pair |
| **Trino** | File/env secrets in catalog properties | File / LDAP / OAuth via config |
| **Postgres FDW** | User mappings in the catalog | Postgres roles (md5 / scram) |
| **DuckDB** | `CREATE SECRET` (session/persistent) | None (embedded) |

| Engine | Multi-tenancy | HA | Zero-dep single node | Cross-tenant sharing |
| --- | --- | --- | --- | --- |
| **Dataglot** | `org_id` **in the store** | Postgres store | Yes (atomic-file store, no C deps) | Designed for (`share` / `attachment`) |
| **RisingWave** | **Deployment-level** (cluster per tenant) | Yes (meta store) | Via SQLite (C dep) | No |
| **ClickHouse** | Deployment / RBAC | Yes (Keeper) | Yes | No first-class org sharing |
| **Dremio** | Projects | Yes | No (JVM) | Within-instance spaces |
| **Snowflake** | **Accounts** | Managed | N/A (cloud) | **Secure Data Sharing** |
| **Trino** | Deployment-level | Coordinator/worker | No (JVM) | No |
| **Postgres FDW** | Databases / schemas | Via Postgres | Yes | Via grants |
| **DuckDB** | None (embedded) | No | Yes | No |

---

## Gaps and roadmap

The SQL-native control plane is real and shipping, but several edges are
deliberately deferred:

- **Views are non-materialized.** `CREATE VIEW` defines a derived product that
  inlines its query at plan time; materialized views with a refresh schedule are
  future work.
- **`GRANT` is table-level; column visibility is a separate whitelist.**
  `GRANT SELECT` / `USAGE` cover tables and catalogs. Column-level authorization
  ships as `[[column_grants]]`: a positive per-role whitelist where
  only listed columns are visible and unlisted columns are projected away
  (`SELECT *` returns the visible subset, not an error), org + group scoped.
  `WITH GRANT OPTION` delegation is still not implemented.
- **Access-deny is group-scoped, not org-scoped.** Column/table denials scope by
  org-group; unlike masks, row filters, and grants they are not yet per-tenant
  (org) scoped.
- **SCRAM is SCRAM-SHA-256 (no channel binding).** The `-PLUS` channel-binding
  variant is not offered; use ingress TLS for transport protection.

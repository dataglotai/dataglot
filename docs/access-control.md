# Access control

The single entry point for how Dataglot decides **who may connect**, **which
objects they may read**, and **what they see when they read them**. If you are
new to the engine, start here, then follow the links into the reference pages.

Access control is three distinct layers, applied in order:

1. **Authentication** — *who you are*. The pgwire login (`trust` / `md5` /
   `scram-sha-256` / `jwt` / `ldap`).
2. **Authorization (GRANT)** — *which objects you may read*. Deny-unless-granted
   privileges on catalogs and tables (`authz.mode = grant`).
3. **Governance** — *what you see in the rows you are allowed to read*. Column
   masks, row filters, and access-deny rules.

Two properties hold across all three, and they are the whole design:

- **Plan-time enforcement.** Every layer is enforced on the DataFusion
  `LogicalPlan` before execution — masks and filters are typed `Expr`
  predicates baked into the plan, not UDFs or post-hoc SQL rewriting
  (hard architecture rule 6). There is no execution path that skips them.
- **Fail-closed.** A missing credential, a missing grant, or any store/decrypt
  error denies rather than allows (hard architecture rule 12). You opt *out* of
  enforcement (the `open`/`trust` defaults), never *into* a leak.

Each layer is enforced at its own point, so they compose without special-casing
each other. The rest of this page walks the layers, then shows them working
together end to end.

---

## 1. Authentication — who you are

The `[auth] mode` bootstrap key selects how a connection proves its username:

- **`trust`** (default) — no password check; the asserted username is believed.
  Local dev only; never on a reachable network.
- **`md5`** — Postgres MD5 password exchange.
- **`scram-sha-256`** — Postgres SCRAM-SHA-256 (SASL) salted challenge–response.
  It authenticates against the *same* credentials as md5, so switching is a
  one-line config change; prefer it on any shared deployment because nothing
  replayable crosses the wire.
- **`jwt`** — the client presents a signed JWT as its password; its verified
  `groups` claim drives directory-group policy (`[auth.jwt]`).
- **`ldap`** — the connection binds to the directory as the user; a group search
  drives directory-group policy (`[auth.ldap]`).

Authentication is fail-closed: an unknown user, a passwordless user, and a wrong
password all fail identically, and the reason is never logged. Full details —
config vs runtime `CREATE USER`, multi-org username resolution, TLS — are in
[`authentication.md`](authentication.md).

---

## 2. Authorization — which objects you may read

Authentication proves *who* you are; authorization decides *what you may read*.
It is governed by one bootstrap key:

```toml
[authz]
mode = "grant"   # "open" (default) | "grant"
```

- **`open`** (default) — no enforcement. Any authenticated (or trusted) session
  may read any table. Existing deployments are unchanged.
- **`grant`** — **deny-unless-granted**. To read `catalog.schema.table`, a
  session must hold **both** `USAGE` on the catalog **and** `SELECT` on the
  table. Missing either, the query is rejected at plan time with `permission
  denied` — nothing about whether the object exists is revealed.

```sql
GRANT USAGE  ON CATALOG pg      TO analyst;
GRANT SELECT ON pg.public.users TO analyst;
```

Key rules (all verified in `crates/dataglot-policy/src/grant.rs`):

- **Principal** — a grant applies when its grantee name equals the session
  **user** or one of the session's **roles**. `GRANT <role> TO <user>`
  establishes membership.
- **Org-scoped** — a grant made in org `acme` never authorizes a same-named
  principal in another org. Cross-org isolation is enforced, not conventional.
- **Superuser bypass** — a `WITH … SUPERUSER` session skips grant enforcement
  entirely. (It does **not** skip masks or row filters — see below.)
- **Anonymous / no grants** — fail-closed: a session with no matching grant is
  denied.
- **Introspection exempt** — the Postgres system schemas (`pg_catalog`,
  `information_schema`) are always readable, so `\dt`, JDBC metadata, and BI
  catalog browsing work without an explicit grant. Enforcement targets the
  fully-qualified `catalog.schema.table` references used to reach federated
  data; a bare or partial reference (`FROM users`) is resolved to its full
  identity *before* the check, so qualifying (or not qualifying) a name can
  never dodge enforcement.

A privilege `GRANT`/`REVOKE` applies to a session's **next** query (no
reconnect); role membership resolves at connect time. Full DDL:
[`runtime-config.md` → GRANT/REVOKE](runtime-config.md#grant--revoke-access-control).

---

## 3. Governance — what you see

Once a read is authorized, governance decides what the rows actually contain.
Three enforcers, all plan-time, all in `crates/dataglot-policy/`:

- **Column masks** (`mask.rs`) — a matching column is replaced by its mask
  expression **only in the output projection**. Predicates, joins, sorts, and
  aggregates see the *unmasked* value (industry-standard "option A" semantics,
  matching Snowflake / BigQuery / Databricks). So `WHERE email = 'alice@…'`
  still finds Alice's row even though `email` comes back masked in the result.
- **Row filters** (`filter.rs`) — a mandatory boolean predicate is baked into
  every scan of the target table. Predicate pushdown collapses it into the
  source scan where possible; where not, it is evaluated locally. Either way it
  is not optional and there is no caller-side path around it.
- **Access-deny** (`access_deny.rs`) — reject the query outright. Table-level
  denies any scan of the table; column-level denies any *reference* to the
  column (projection, predicate, `SELECT *`). Both are **group-scoped**: an
  empty group list applies to everyone, otherwise it applies when the session's
  org-groups intersect the list.

**Deny vs grant.** They answer different questions and both must pass. Grant is
*deny-unless-granted* (you need a positive privilege to read at all); access-deny
is a *negative* rule that subtracts a specific table/column from a group even
where a broader read would otherwise be allowed. A read must satisfy grant
authorization **and** survive access-deny.

**Superuser and governance.** A superuser bypasses **grants** but **not** masks,
row filters, or access-deny. Governance controls are *guarantees about the data*,
not access privileges — a masked SSN stays masked for everyone, including the
superuser. This is the tag-becomes-a-guarantee thesis: the mask is a property of
the column, not of the caller.

---

## 4. How the layers compose

Walk a single `SELECT email FROM pg.public.users` through the stack, in order:

| Session | Authentication | Authorization (`grant`) | Governance | Result |
|---|---|---|---|---|
| Unauthenticated | fails login | — | — | **connection refused** |
| Authenticated, no grant | ok | no `USAGE`+`SELECT` | — | **`permission denied`** |
| Authenticated, granted | ok | `USAGE`+`SELECT` held | mask on `email` | **rows returned, `email` masked** |
| Superuser | ok | skipped | mask on `email` | **rows returned, `email` still masked** |

The precedence is always the same: authenticate, then authorize, then govern.
A later layer never re-opens an earlier one — a grant does not un-mask, and
superuser does not un-mask.

---

## 5. The no-bypass guarantee

Grants, masks, row filters, and denials are not surface-level checks on the
top-level query — they hold **wherever a governed table is reached in the plan**.
Two paths that naive engines leak through are closed here:

- **Through subqueries.** A governed scan reached only inside a scalar subquery,
  an `IN` / `EXISTS` test, a `= ANY` comparison, or a nested subquery is
  governed exactly as a top-level scan. The enforcers descend into the four
  subquery-bearing expression variants explicitly (the shared
  `embedded_subquery` / `map_subquery_plans` helpers in
  `crates/dataglot-policy/src/lib.rs`), because DataFusion's default plan walk
  does *not* — skipping them would have been a silent read-around.
- **Through views.** `CREATE VIEW` stores a derived product whose defining plan
  is **inlined** at query time (it is not a rewrite you can peer around).
  Governance re-applies to the inlined plan, so a mask, filter, or grant on an
  underlying source column holds when you query the view instead of the source.

The upshot: you cannot escape a control by wrapping the read in a subquery or a
view. This is enforced by construction and regression-tested (see the
subquery-nesting tests in `grant.rs` and `access_deny.rs`).

---

## 6. End-to-end example

A complete session showing all three layers. It is org-scoped throughout and
modeled on [`examples/demo/fileless-md5/`](../examples/demo/fileless-md5/).

**1. Boot** with md5 auth and grant-mode authorization (`bootstrap.json`):

```toml
host = "127.0.0.1"
port = 5432

[catalog_service]
path = "/var/lib/dataglot/meta.json"

[auth]
mode = "md5"

[authz]
mode = "grant"

[identities.admin]
password_env = "DATAGLOT_PW_ADMIN"
```

```bash
export DATAGLOT_PW_ADMIN='admin-bootstrap-pw'
export DATAGLOT_SECRET_KEY="$(openssl rand -base64 32)"
dataglot --config bootstrap.toml
```

**2. As `admin`**, wire up a source, a role, and a runtime user:

```sql
CREATE SECRET  app_pg_dsn AS 'host=db port=5432 dbname=app user=svc password=hunter2';
CREATE CATALOG pg WITH (kind = 'postgres', dsn_secret = 'app_pg_dsn');

CREATE ROLE reporting;
CREATE USER analyst WITH PASSWORD 'correct horse battery staple';
GRANT reporting TO analyst;
```

**3. As `analyst`** (reconnect — role membership resolves at connect time),
the read is denied because no privilege has been granted yet:

```sql
SELECT email FROM pg.public.users LIMIT 3;
-- ERROR:  permission denied
```

**4. Back as `admin`**, grant the two privileges a read requires:

```sql
GRANT USAGE  ON CATALOG pg      TO reporting;   -- reach the catalog
GRANT SELECT ON pg.public.users TO reporting;   -- read the table
```

**5. As `analyst`**, the same query now returns rows (grants apply on the next
query, no reconnect needed):

```sql
SELECT email FROM pg.public.users LIMIT 3;
--        email
-- ---------------------
--  alice@example.com
--  bob@corp.example
--  carol@example.org
```

**6. As `admin`, add a mask** — the authorized read now returns masked:

```sql
CREATE MASK email_mask ON pg.public.users ( email ) AS '***@example.com';
```

```sql
-- as analyst, the same authorized query:
SELECT email FROM pg.public.users LIMIT 3;
--       email
-- -------------------
--  ***@example.com
--  ***@example.com
--  ***@example.com
```

Authorization decided *whether* `analyst` could read; governance decided *what*
the rows contained. A superuser at step 5 would have skipped the grant checks —
but at step 6 would still see the masked value.

---

## 7. Config vs runtime-DDL equivalence

Every control can be declared in the bootstrap config **or** created at runtime
over SQL DDL (persisted to the meta store, org-scoped). Both routes reach the
same plan-time enforcers.

| Control | Config | Runtime DDL |
|---|---|---|
| Authentication mode | `auth.mode = "trust" \| "md5" \| "scram-sha-256" \| "jwt" \| "ldap"` | — (bootstrap only) |
| Login identity | `identities.<user>` (`password_env`) | `CREATE / ALTER / DROP USER … PASSWORD` |
| Authorization mode | `authz.mode = "open" \| "grant"` | — (bootstrap only) |
| Privilege grant | — | `GRANT USAGE ON CATALOG … / GRANT SELECT ON … / REVOKE` |
| Role & membership | `identities.<user>.groups` (tag policies) | `CREATE ROLE …` / `GRANT <role> TO <user>` |
| Column mask | `masks[]` | `CREATE / DROP MASK` |
| Row filter | `row_filters[]` | `CREATE / DROP ROW FILTER` |
| Access-deny / tag policy | `governance` | (tag-driven; managed via config + webhook) |

**Fail-closed summary.** Authentication denies on any credential error;
authorization (`grant` mode) denies any un-granted read; governance masks,
filters, or denies before any row leaves the plan. The defaults (`trust`,
`open`, no masks) are permissive by design so existing deployments are
unchanged — but every enforcement path, once on, denies rather than leaks.

---

## See also

- [`authentication.md`](authentication.md) — auth modes, identities, multi-org,
  the Authorization key in depth.
- [`runtime-config.md`](runtime-config.md) — the full runtime DDL surface
  (`CREATE USER`, `GRANT`, `CREATE MASK`, …).
- [`configuration.md`](configuration.md) — the bootstrap-config reference
  (`auth`, `authz`, `masks`, `row_filters`, `governance`).
- [`examples/demo/fileless-md5/`](../examples/demo/fileless-md5/) — a runnable
  fileless + md5 walk-through.

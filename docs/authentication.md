# Authentication

How clients prove who they are to Dataglot's pgwire port, and how login
identities are defined — both in config and at runtime over SQL.

> Authorization (what an authenticated user may *see* — column masks, row
> filters, per-org policy) is covered in
> [`runtime-config.md`](runtime-config.md). This page is only about **who you
> are**.

## Modes

The `[auth] mode` key selects the method:

| Mode | Behaviour | Use for |
| --- | --- | --- |
| `trust` (default) | The asserted username is trusted with **no password**. | Local dev only. |
| `md5` | Each connection completes a Postgres MD5 password exchange. | Legacy clients. |
| `scram-sha-256` | Each connection completes a Postgres SCRAM-SHA-256 (SASL) challenge–response. | Everything else. |
| `jwt` | The client presents a signed JWT as its password; its verified `groups` claim drives directory-group policy. Requires `[auth.jwt]`. | IdP / token auth. |
| `ldap` | The connection binds to the directory as the user; a group search drives directory-group policy. Requires `[auth.ldap]`. | LDAP / Active Directory. |

```toml
[auth]
mode = "scram-sha-256"
```

`trust` preserves the zero-friction local-dev experience: `psql "host=127.0.0.1
user=anyone"` connects. Never run `trust` on a reachable network.

**`scram-sha-256` vs `md5`.** Both authenticate against the *same* credentials
(the sections below apply unchanged to either), so switching is a one-line
config change with no re-provisioning. SCRAM-SHA-256 is the stronger choice and
should be preferred: it is a **salted challenge–response** (RFC 5802) — the
server sends a random challenge, the client proves knowledge of the password
without ever transmitting it, and nothing that crosses the wire is a replayable
password-equivalent. md5's salted hash, by contrast, *is* a bearer secret an
eavesdropper can capture and replay. Any modern Postgres client (`psql`,
`libpq`, JDBC, `tokio-postgres`, …) negotiates SCRAM automatically when the
server offers SASL, so no client change is needed.

Neither mode removes the need for TLS. Both still require a
cleartext-equivalent credential **at rest** (the server has to verify the
password without the client's cooperation — inherent to md5 and SCRAM alike;
SCRAM stores a salted derivation, not the raw password, but it is still
credential-equivalent). And SCRAM's non-replayable handshake still leaves your
**query results** crossing the network in the clear. For production add a
[`[pgwire_tls]`](runtime-config.md) block with `mode = "require"` so the whole
session is encrypted. The server logs a warning if you enable either password
mode without ingress TLS.

## Identities from config

Under `md5`, each login name is an **identity**. The password itself is never
written to the config file — `password_env` names an environment variable the
server reads once at boot (credentials never live in config or logs):

```toml
[auth]
mode = "md5"

[identities.admin]
password_env = "DATAGLOT_ADMIN_PW"

[identities.analyst]
password_env = "DATAGLOT_ANALYST_PW"
org = "acme"
groups = ["analyst"]
```

```bash
export DATAGLOT_ADMIN_PW='choose-a-strong-secret'
export DATAGLOT_ANALYST_PW='another-secret'
dataglot --config dataglot.toml
```

- `org` — the tenant the identity belongs to (see **Multi-org** below). Omit
  for the default org.
- `groups` — org-group memberships that activate tag-based governance policies.
- An identity with no `password_env` cannot log in under md5 (no credential),
  though its profile still resolves for authorization if it authenticates some
  other way.

## Identities at runtime (no restart)

You don't have to redeploy to add a user. Connected as an existing user, issue
SQL DDL — the identity is stored in the meta store and survives restart:

```sql
CREATE USER analyst WITH PASSWORD 'a-secret';
ALTER USER analyst WITH PASSWORD 'rotated';
DROP USER analyst;
```

Runtime identities and config identities coexist; on a name collision the store
wins. The full DDL surface (secrets, catalogs, masks, row filters, users,
roles) is in [`runtime-config.md`](runtime-config.md). For a end-to-end
walk-through see [`examples/demo/fileless-md5/`](../examples/demo/fileless-md5/).

## Multi-org (global-unique usernames)

Dataglot is multi-tenant: identities, catalogs, and policies are scoped to an
**org**. Because md5 auth happens before any per-connection org is known,
**usernames are unique across all orgs**. At login the meta store is scanned
for the username, and the match determines the org your session runs in — so a
user created while scoped to org `acme` authenticates and is governed as
`acme`, with no change to the connection string:

```bash
PGPASSWORD='a-secret' psql "host=127.0.0.1 user=analyst dbname=pg"
# -> resolves `analyst` to org `acme`; the session sees acme's catalogs + policies
```

`CREATE USER` rejects a name already taken in another org (the name must be
globally unique). Re-creating the same user in the same org stays idempotent.

## Failure semantics

Authentication is **fail-closed**. An unknown user, a passwordless user, a
wrong password, or any store/decrypt error all fail the login identically —
there is no distinction a client could use to probe which usernames exist, and
the reason is never logged.

## Authorization (what you may read)

Authentication proves *who* you are; **authorization** decides *what you may
see*. It's a separate layer, off by default (`authz.mode = "open"`; set
`"grant"` for deny-unless-granted `USAGE`+`SELECT`), and it also covers column
masks and row filters (which even a superuser can't bypass). See
[`access-control.md`](access-control.md) for the model and
[`runtime-config.md`](runtime-config.md#grant--revoke-access-control) for the
`GRANT`/`REVOKE` DDL.

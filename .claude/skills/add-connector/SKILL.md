---
name: add-connector
description: >
  Add a new federated data source to Dataglot — the full path from connector
  crate to a `kind = "..."` catalog an operator can configure. Use when
  wiring up a new database, API, or protocol as a queryable source. Covers
  the crate ordering that keeps each PR independently buildable.
---

# Add a connector

A connector lands in four places. The order matters, because each crate has
to compile on its own.

## Decide the shape first

Two kinds of source, and the choice drives everything after it:

- **SQL source** — the remote speaks SQL and can execute pushed-down
  queries. Implement `SQLExecutor`; `datafusion-federation` plans it as a
  `VirtualExecutionPlan`. Postgres, MySQL, Oracle, ADBC, Flight SQL.
- **Direct provider** — the remote has no SQL engine, so Dataglot filters
  and joins locally. Implement `TableProvider`. OData, REST, object storage.

Getting this wrong is not subtle: a SQL source that is not classified as
federated never has its `FederatedTableProviderAdaptor` rewritten, and every
scan fails with "cannot scan".

## 1. The connector itself — `crates/dataglot-federation`

Behind a Cargo feature, off by default. A module with:

- A config struct whose `Debug` is hand-written and redacts credentials.
  Credentials come from environment variables named in config
  (`password_env`), never from literals, and are resolved at connect.
- A `connect()` that validates everything cheap before any I/O, so a typo
  fails at boot naming the field, not on the first query.
- `as_catalog_provider()` for discovery, and `SQLExecutor` or
  `TableProvider` for execution.
- A health check that probes without moving rows.

Test against an in-process fake rather than a container where you can — a
suite with no Docker dependency runs in CI unconditionally, which is the
difference between a connector that is tested and one that is only tested
when someone remembers.

### Things that bite

- **Schema inference is lazy.** Do not fetch schemas at boot; resolve on
  first query or explicit `DESCRIBE`.
- **Cast metadata columns, do not downcast them.** Servers answer with
  `LargeUtf8`, `Utf8View`, or dictionary-encoded strings as readily as
  `Utf8`. A bare downcast turns any of those into a silently empty catalog.
- **Align result batches strictly.** Check arity first, then nullability on
  every path including the identical-schema fast path, and cast with
  `safe: false`. A safe cast turns an unrepresentable value into a null and
  reports success, which against a nullable column is silent data loss.
- **Fail closed on partial metadata.** If discovery succeeds but returns
  rows you cannot address, error. A successful call means no fallback runs,
  so a partial catalog looks complete and nothing reports a problem.
- **Respect result ordering.** If the protocol can split a result across
  endpoints or partitions, check whether it guarantees an order between
  them. Federation pushes `ORDER BY` to the remote and drops the local sort,
  so concatenating unordered parts returns rows in partition order.
- **Never render a credential.** Not in errors, not in logs, not in a
  binding. Remote-supplied text can carry a reflected credential, and it
  reaches you *after* normalisation — scrub case-insensitively, and register
  the form a URL parser would produce if the value can appear in a host.

## 2. The enums — `crates/dataglot-core`

`LiveConnectorKind` for the catalog binding, `ProductPlatform` for
governance. Both are needed before the server can accept the config.

Note the ordering constraint: adding a variant breaks every exhaustive
`match` on it. Those matches live in core precisely so that adding a kind
stays a single-crate change. Keep it that way — if you find yourself needing
to edit another crate in the same commit, the match has escaped and should
move back rather than the rule being bent.

## 3. The config surface — `crates/dataglot-server`

- A `<Name>CatalogConfig` struct and a `CatalogConfig` variant tagged with
  the `kind` string an operator writes.
- A `build_<name>_catalog` behind the server's feature, plus a
  `#[cfg(not(feature = ...))]` stub that rejects the config at boot with a
  message naming the feature. The config surface always compiles; only the
  connector is optional.
- Add it to `requires_federation()` if it is a SQL source.
- Ballista registry parity, or the catalog silently falls back to
  single-node in distributed mode.

Name the server feature for the *direction* if there is any chance of
confusion with an existing one. A feature that reads from a source and a
feature that serves the same protocol are opposite things and must not be
one underscore apart.

## 4. Docs

`docs/configuration.md` gets a `kind:` section with a real TOML example and
the feature-gate table row. `docs/quick-reference.md` lists the feature.

Keep comments in shipped crates free of private doc paths — name a plan
rather than linking a file that the public repo does not contain.

## Staging the PRs

Each PR must build on its own, so the order follows the dependency graph:
**core → federation → server**. `dataglot-federation` and `dataglot-server`
both depend on `dataglot-core`, so anything the later crates reference —
a new `LiveConnectorKind`, a new `ProductPlatform` — has to land first or the
intermediate state does not compile.

A change that spans crates in one commit is a change that cannot be reviewed
or reverted independently.

## Done means

An operator can write the `kind` block, boot, and query it; a server built
without the feature rejects that config with a message naming the feature;
the connector has a CI lane in the feature matrix; and the docs describe it.

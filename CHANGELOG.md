# Changelog

All notable changes to this project are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the
project is pre-1.0, so minor versions may contain breaking changes.
Release history before this file existed is reconstructed from the
annotated git tags (`git show v0.1.0`, `git show v0.3.0`) and the phase
closure records under `docs/phases/`.

## [Unreleased]

_Nothing yet._

## [0.5.0] — 2026-08-08

The SQL-native control plane cycle: a running Dataglot server can now be
administered entirely over the pg wire with SQL DDL — catalogs, secrets,
users, roles, grants, and governance policies — with multi-tenant
(per-org) isolation, stronger authentication, and a full operational
dashboard. A large cycle since 0.4.0 (117 features, 63 fixes); highlights
below, full list via the compare link.

### Added

- **SQL-native control plane.** Runtime DDL over the pg wire:
  `CREATE`/`DROP CATALOG` (including nested JSON-valued options),
  `CREATE`/`DROP SECRET` with encrypted at-rest storage and `dsn_secret`
  references, `CREATE`/`DROP USER`/`ROLE`, and a `GRANT`/`REVOKE` privilege
  model — all persisted in a version-keyed meta store with a migration
  framework. No config-file edit or reboot required.
- **Runtime governance DDL.** `CREATE MASK` / `CREATE ROW FILTER` parsed,
  persisted, and enforced at plan time; column-level positive authorization
  (whitelist, ); per-org enforcement of masks and row filters.
- **Multi-org / multi-tenant.** Global-unique-username auth routing, org-scoped
  sessions, and per-connection DDL-admin scope.
- **Authentication.** SCRAM-SHA-256 alongside md5; store-backed runtime users
  authenticate via md5; optional read-only LDAP service-account bind for group
  search.
- **Operational dashboard.** Governance + security posture, live source health
  (`connector_up` gauge), materialization/refresh status, resource limits vs
  usage, query history with error/cancel detail, and a live Sessions view.
- **`CREATE VIEW`** for derived data products.
- **Testbench.** Control-plane pane for runtime DDL, run-as-identity +
  governance diff, pg wire TLS, seeded md5 identities in `--fileless`, and an
  "Ops ↗" link to the operational dashboard.

### Fixed

- **Federation robustness.** Bounded pushed-down query execution + TCP
  keepalive so a black-holed source fails fast instead of hanging forever
, complementing the bounded connect from 0.4's line.
- **Distributed mode.** No-table queries (`SELECT 1`) no longer hang under
  `--distributed`; `pg_catalog` introspection registered on executors
  (/188); spill-pool and `target_partitions` sized to the actual cluster
  (/169); orphaned executors reaped before spawn.
- **Policy.** Masks and row filters now apply inside expression subqueries, and
  the grant/access-deny subquery bypass is closed.
- Multi-statement DDL messages (`CREATE...; SELECT...`) over the pg wire.

### Changed

- `run-testbench.sh` builds with a fast `release-fast` profile by default and
  re-verifies source health before boot (/215); Docker images build with
  reduced LTO to fit memory-constrained hosts.

## [0.4.0] — 2026-07-06

The Phase 3 cycle: closed-loop governance, security hardening, the
Trino-retirement write path — plus the external-contributor
documentation set and this changelog/release pipeline itself.

### Added

- Native plan-time policy engine at Apache Ranger model parity:
  named mask types (redact / hash / show-first/last-N / nullify /
  date-year / constant), table- and column-level access-deny, role
  resolution, mask precedence, and a structured `dataglot::audit`
  decision trail covering mask, row-filter, deny, failed-auth, and
  connection-rejection events.
- Lineage closure: column-level lineage analysis, OpenLineage
  `columnLineage` facet emission, and lineage-propagated mask
  enforcement — a mask on a source column automatically covers every
  derived column that descends from it.
- Policy explainability: `POST /policy/explain` plans a query without
  executing it and reports the mask / row-filter / deny decisions for
  any identity (optional bearer-token auth).
- pgwire authentication (`trust` / `md5`), pgwire ingress TLS
  (prefer/require), and connection admission control: global, per-IP,
  per-IP-rate (token bucket), and per-identity ceilings.
- Source-database TLS for the Postgres and MySQL connectors
  (per-catalog `tls = "require"`, custom CA support).
- Oracle federation connector with dual wire backends: OCI/ODPI-C
  (default) and pure-Rust (`oracle-rs`), selectable per catalog.
- Trino-retirement write path: detached-table materialization with
  refresh scheduler, EL copy-on-write upsert, compaction/maintenance —
  with optimistic concurrency and bounded-memory streaming writes.
- Inbound governance webhook hardening and `pg_catalog` compatibility
  (psql/JDBC introspection, catalog-scoped `\dt`/`\dn`).
- External-contributor documentation: SETUP.md, QUICKSTART, SECURITY.md,
  `docs/configuration.md` reference, README docs map.

## [0.3.0] — 2026-06-02

Phase 1 (Federation + Governance, closed 2026-05-12) and Phase 2
(Distributed Execution, closed 2026-05-30) in one release.

### Added

- **Federation connectors:** MySQL (full 14-type Arrow matrix), object
  storage (local parquet), and Snowflake (`SQLExecutor` via a Peaka
  `arrow-58` fork of `snowflake-rs`) alongside the existing Postgres +
  warehouse connectors; native single-source query passthrough;
  cross-source JOIN correctness suite.
- **Plan-time governance:** column masking + row filters + typed tag
  layer + per-session identity (Architecture Decisions §10).
- **Governance integration:** OpenLineage emitter (table-level),
  DataHub data-product registration (Interfaces #1/#2/#5), and the
  inbound policy-ingestion webhook with `<60 s` enforcement propagation.
- **Catalog layer:** `CatalogBinding` enum, in-process catalog service,
  provider cache.
- **Distributed execution:** Ballista integration (18 slice-units) —
  federation plan codec, resolver-per-worker credential distribution,
  object-store scheduler HA, cluster mTLS (Architecture §12),
  governance parity across workers; near-linear 4-worker scaling
  (2.83× @ SF1 → 3.17× @ SF10 vs a single-worker Ballista baseline).
- **Benchmarks/testbench:** TPC-H SF1 baseline, multi-engine testbench
  (Dataglot vs Trino vs DuckDB) with differential mode and scaling
  curves.
- First properly semver-tagged container images on
  `ghcr.io/dataglotai/dataglot`.

## [0.1.0] — 2026-05-05

Phase 0 (Foundations, closed 2026-04-30) + Phase 0.5 (hardening).

### Added

- Cross-source SELECT from a single SQL endpoint (PostgreSQL +
  lakehouse warehouse via Lakekeeper REST catalog), with plan-time
  predicate pushdown via `datafusion-federation`.
- pgwire frontend with `EXPLAIN FEDERATION`, Prometheus query
  observability, and the sub-500 MB container budget (production image
  measured at 271 MB).
- Browser-based multi-engine SQL comparator (`dataglot-testbench`).
- Nightly differential SQL harness vs Trino (first clean run: 6/10
  queries match; the 4 divergences became Phase 1 input).

[Unreleased]: https://github.com/dataglotai/dataglot/compare/v0.5.0...HEAD
[0.5.0]: https://github.com/dataglotai/dataglot/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/dataglotai/dataglot/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/dataglotai/dataglot/compare/v0.1.0...v0.3.0
[0.1.0]: https://github.com/dataglotai/dataglot/releases/tag/v0.1.0

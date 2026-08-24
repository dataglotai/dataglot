# Code coverage

How Dataglot's coverage is measured in this repository, how to run it locally,
and — importantly — **what the number does and does not include**. Coverage is a
**signal, not a gate**: it points at under-exercised code; it does not block PRs.

## At a glance

| | |
|---|---|
| **Tool** | [`cargo-llvm-cov`](https://github.com/taiki-e/cargo-llvm-cov) (LLVM source-based instrumentation) |
| **Scope** | workspace **unit tests** (`--lib`) + `dataglot-ballista` non-Docker integration tests |
| **Local** | `make coverage` (HTML) · `make coverage-json` (JSON summary) |
| **CI** | [`.github/workflows/coverage.yml`](../.github/workflows/coverage.yml) (push to `main` + manual) |

```sh
rustup component add llvm-tools-preview
cargo install cargo-llvm-cov --locked
make coverage        # → target/llvm-cov/html/index.html
make coverage-open   # open the report
```

## What the number measures — and what it doesn't

This repository ships and measures **unit tests** (in-crate `#[cfg(test)]`
modules). **Integration and end-to-end tests are not part of this repository's
coverage number**, so per-file coverage of code that is exercised primarily by
those suites will look low here even though the code is well tested. In
particular:

- **Data-source connectors** (`postgres`, `mysql`, `iceberg`, `snowflake`, and
  the TLS paths) require a **live database or broker**. They are covered by
  Docker-gated integration tests, not by unit tests — so their unit-coverage
  line is low by construction.
- **The Postgres-backed catalog service** (`dataglot-catalog::service`) runs SQL
  against a live pool; it is covered by integration tests. Its only
  database-free logic (grant column (de)serialization) *is* unit-tested. The
  **embedded** meta-store backend (`embedded`, `redb_store`, `store`, `cache`,
  `migrations`) is in-process and sits at ~95–100% unit coverage.
- **Server boot / wire-protocol handling** (`dataglot-server`,
  `dataglot-pgwire::handler`) are covered by end-to-end tests.

Where the logic is genuinely in-process — the engine core, policy/governance
enforcement, the embedded meta-store, plan codecs — unit coverage is high
(≈90–100%). Treat the headline percentage as a **floor**: real coverage,
counting the integration/e2e tiers, is higher.

## Interpreting a low file

Before "adding tests to raise coverage", check *why* a file is low:

1. **Does it need a live external service** (DB, broker, TLS peer, full server)?
   Then it belongs in an integration/e2e test, not a unit test — raising its
   unit number would mean mocking the world for little value.
2. **Is it genuinely in-process logic** (parsing, encoding, a pure state
   machine)? Then a unit test is the right tool and welcome.

Contributions that add unit tests to in-process logic are very welcome; PRs that
mock a database purely to move a percentage are not the goal.

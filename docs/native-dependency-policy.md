# Native dependency policy (Rust-only production runtime)

**Rule:** hard architecture rule 15 — the Dataglot engine, all connectors, the
catalog service, and the EL pipeline are **Rust**. No JVM in the production
runtime, and no other non-Rust / native dependency in a production crate
without an explicit, documented exception.

This note records *what counts as a production crate*, *the sanctioned
exceptions*, and *how the policy is enforced*.

## What is enforced

[`scripts/check-native-deps.py`](../scripts/check-native-deps.py) (run by the
**Native Dependency Hygiene** CI workflow on any `Cargo.toml` change) fails when
a **production crate** declares a **direct** non-Rust dependency that isn't
allow-listed:

- **JVM** — `jni`, `j4rs`, `jni-sys`, …
- **Python** — `pyo3`, `cpython`, `rustpython`, …
- **C / C++** — any `*-sys` crate (links a native library), native build tools
  used as `build-dependencies` (`cc`, `cmake`, `bindgen`, `cxx`), and known
  native-bundling client crates.

Only `[dependencies]` and `[build-dependencies]` are scanned — `[dev-dependencies]`
are test-only and never linked into the shipped binary. Transitive native crates
(e.g. `ring`, `zstd-sys` pulled via rustls/parquet) are *not* direct dependencies
of our production crates, so scanning direct deps avoids false positives on the
unavoidable crypto/compression tree.

## Production vs dev tooling

A crate is **production** if it is in the shipped **`dataglot-server`** binary's
workspace dependency closure (normal + build deps) — that is exactly what ships,
so exactly what rule 15 governs. `scripts/check-native-deps.py` computes the
closure from the manifests and scans those crates; if it ever resolves to fewer
than two crates it *fails* rather than pass a no-op guard (fail-secure).

| Production (Rust-only) | Dev tooling (outside the closure, exempt) |
| --- | --- |
| `dataglot-core`, `dataglot-federation`, `dataglot-pgwire`, `dataglot-policy`, `dataglot-catalog`, `dataglot-server`, `dataglot-ballista` | `dataglot-testbench`, `dataglot-tests`, `dataglot-{trino,dremio,clickhouse,spice}-client` |

The differential-comparator clients and the testbench (incl. its TypeScript/React
frontend and the DuckDB comparator) are dev tooling — nothing shipped depends on
them, so they fall outside `dataglot-server`'s closure automatically (no
`publish`-flag heuristic; this replaced the  gap where every crate's
`publish = false` made the guard scan nothing).

## Sanctioned exceptions

Both are **feature-gated, off by default**, and isolated.

### 1. Oracle OCI connector — C (production, allow-listed)

- **Crate:** `oracle` (kubo/rust-oracle) in `dataglot-federation`, behind
  `--features oracle`.
- **Native surface:** wraps **ODPI-C**; needs a C compiler at build and
  `dlopen`s the **Oracle Instant Client** (`libclntsh`) at runtime.
- **Why allowed:** the OCI client is Oracle's blessed, maximum-compatibility
  path for federating an Oracle/Exadata estate. It is the **default**
  Oracle backend.
- **No longer unavoidable.** A **pure-Rust** Oracle backend ships alongside it —
  `oracle-rs` behind `--features oracle-pure`, which reimplements the
  Oracle TTC/TNS protocol in Rust (no ODPI-C, no Instant Client, no C compiler).
  So an operator can run Oracle federation with **zero native code**; the OCI
  backend is the default for compatibility but is one of two. The guard scans
  crate dependencies, not Cargo features: the `oracle-rs` crate (pulled in by
  the `oracle-pure` feature) is pure Rust and needs **no** allow-list entry.
- **Containment:** the `oracle` (OCI) feature is off by default, excluded from
  the `all` feature; a default `cargo build` pulls none of it. Allow-listed as
  `("dataglot-federation", "oracle")` in the guard. (`oracle-rs` — the pure
  backend's crate — is *not* allow-listed, by design: it's pure Rust.)

### 2. DuckDB comparator — C++ (dev tooling, not allow-listed)

- **Crate:** `duckdb` (`bundled`) in `dataglot-testbench`, behind
  `--features duckdb`.
- **Native surface:** compiles `libduckdb` (C++) via `cc`.
- **Why not in the allow-list:** the testbench is `publish = false` dev tooling,
  so the guard never scans it. DuckDB is a browser-testbench differential
  comparator, never part of the runtime.

## Adding a new exception

Only if the dependency is genuinely required **and** has no pure-Rust
alternative:

1. **Feature-gate it, off by default** (and keep it out of any `all`/default
   feature).
2. Add the `(crate, dep)` pair to `ALLOW` in `scripts/check-native-deps.py`,
   with a comment explaining why no Rust alternative exists.
3. Document it here.

If the crate is dev tooling rather than runtime, set `publish = false` instead —
it's then exempt by construction.

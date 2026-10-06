---
name: verify
description: >
  Run every gate a change has to pass before it is pushed, in the order that
  catches problems cheapest first. Use before opening or updating a PR, or
  whenever "is this green?" needs a real answer. Covers the gates that are
  NOT in `make ci` and are therefore the ones that fail in CI after you
  thought you were done.
---

# Verify a change

`make ci` is `check test doc deny`. That is most of it, and it is not all of
it. Several gates run only in CI, so a clean `make ci` is not the same as a
green pipeline. Run them here instead of finding out from a red PR.

## 1. Read the result line, never the exit code

This is the single most common way a change gets pushed broken.

```bash
set -o pipefail
log=$(mktemp "${TMPDIR:-/tmp}/dataglot-ci.XXXXXX")
make ci 2>&1 | tee "$log"; ci_status=$?
grep -E "^(test result|error)" "$log" || true   # no match is not a failure
test "$ci_status" -eq 0
```

Note what `set -o pipefail` and `ci_status` are doing there. Without them the
pipeline's status is `tee`'s, which is almost always 0 — so this very snippet
would demonstrate the bug it is warning about. It did, until review caught
it.

Backgrounding `make ci > log` and then checking `$?` reports the exit status
of the *last* thing in the pipeline, not of the test run. A suite can fail
and the shell still hands you 0. Gate on the `test result:` line of **every**
suite, and on the absence of `^error`.

The same trap applies to piping through `head`: `cargo test | head -20` makes
the exit code the one from `head`, which is always 0.

## 2. Formatting, including TOML

```bash
cargo +nightly fmt --all
taplo fmt
```

`rustfmt` runs on nightly here. The pre-commit hook checks both and will
reject a commit that touches a `Cargo.toml` without `taplo fmt`.

## 3. Clippy, across the feature combinations you touched

```bash
cargo clippy --workspace --exclude dataglot-ballista --all-targets -- -D warnings
```

That is the exact gate, not an approximation of it. Two details matter:
`dataglot-ballista` is excluded because it needs `protoc`, and it has its own
lane (`cargo clippy -p dataglot-ballista --all-targets -- -D warnings`) — run
that too if you touched it. And `-- -D warnings` is what turns configured
warning-level lints into failures, so without it a clean local run can still
lose to the gate.

Two things make this more than a formality:

- **Lints are errors.** `-D warnings` plus `clippy::pedantic`. A warning that
  looks cosmetic (`doc_markdown`, `needless_pass_by_value`,
  `items_after_statements`, `too_many_lines`) fails the build.
  `-- -D warnings` belongs on **every** clippy command you run, including the
  per-feature ones below — a few lints are configured at `warn` rather than
  `deny` (`large_futures` is the one that bites), so without it they print
  and the command still exits 0.
- **CI uses the latest stable toolchain.** If your local stable is older, a
  newly-stabilised lint passes here and fails there. `rustup update stable`
  before trusting a clean run.

Feature-gated code is only linted when its feature is on. If you touched
anything behind a feature, lint that combination explicitly — and lint the
*absence* too, since `#[cfg(not(feature = ...))]` stubs are real code:

```bash
cargo clippy -p dataglot-server --features ballista,adbc --all-targets -- -D warnings
cargo clippy -p dataglot-federation --all-features --all-targets -- -D warnings
```

## 4. The gates that are not in `make ci`

These run in CI and will fail a PR that passed `make ci` locally.

**Workspace dependency hygiene** — a dependency used by a second crate must
be declared in `[workspace.dependencies]`, not inline:

```bash
python3 scripts/check-workspace-deps.py
```

**Native dependency policy** — the runtime is Rust-only. A new native, JVM
or Python dependency in a production crate must be feature-gated off by
default, allow-listed in the script below, and documented in
`docs/native-dependency-policy.md`:

```bash
python3 scripts/check-native-deps.py
```

## 5. Tests, per feature combination

A default `cargo test` does not compile feature-gated code at all, so a
connector behind a feature can be entirely untested while the suite is green.
Run the combinations your change reaches:

```bash
cargo test -p dataglot-federation --features oracle-pure
cargo test -p dataglot-server --lib --features flight_sql
cargo test -p dataglot-server --lib --features ballista,adbc
```

Check `[features]` in the crate's `Cargo.toml` for the name — a feature that
does not exist fails with `does not contain this feature`, not with a test
failure, so it is easy to read as "nothing to run here".

Watch for pairs whose names differ only in punctuation and which mean
opposite things. `flight_sql` on the server *serves* Flight SQL to clients;
the federation crate's Flight SQL feature *reads from* a remote server.
Testing one proves nothing about the other, and the names are one underscore
apart.

If you added a feature, add it to the CI feature matrix in the same change.
A feature with no CI lane means every later "all checks green" is silent
about it — which is exactly how a connector can sit untested while the
pipeline stays green.

## 6. Enum changes reach further than they look

Adding a variant to a public enum breaks every exhaustive `match` on it,
including ones in other crates and in test code. Before assuming a change is
contained:

```bash
cargo check --workspace --all-features
```

**This one needs `protoc`,** and `--exclude dataglot-ballista` will not save
you: `dataglot-server`'s `ballista` feature depends on the `dataglot-ballista`
crate, so `--all-features` pulls it back in through the dependency graph even
when the package itself is excluded. Excluding works for the clippy gate
because that command does not enable the feature that drags it in.

Without `protoc`, check the combinations you actually touched instead:

```bash
cargo check -p dataglot-federation --all-features
cargo check -p dataglot-server --features adbc,oracle-pure
```

## What "green" means

Every suite's `test result:` line says `ok`, clippy is silent on the feature
combinations you touched, both hygiene scripts pass, and nothing in the log
matches `^error`. Anything less is a guess.

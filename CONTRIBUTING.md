# Contributing to Dataglot

## Workflow

1. Create a branch from `main`
2. Make your change (one logical change per PR)
3. Run `make ci` locally (first-time prerequisites — nightly toolchain for
   `rustfmt`, `taplo`, `cargo-deny` — are listed in
   [docs/install.md](docs/install.md#building-from-source))
4. Push and open a PR
5. CI must pass, arch-reviewer must approve, one human must approve
6. Squash merge to `main`

## Branch naming

```
feat/<short-description>     # new functionality
fix/<short-description>      # bug fix
refactor/<short-description> # restructuring without behavior change
chore/<short-description>    # CI, config, deps, docs
```

## Commit messages

Imperative mood, prefixed with the crate name:

```
dataglot-core: add CatalogProvider trait
dataglot-pgwire: implement simple query protocol
dataglot-federation: fix LEFT JOIN pushdown
chore: update datafusion to 47
```

## Crate boundaries

Each PR should touch only one crate when possible. If a change requires
modifications across crates:

1. Start with the lowest crate in the dependency chain (`dataglot-core`)
2. Open that PR first, get it merged
3. Then open the dependent PR

This keeps reviews focused and avoids merge conflicts.

## AI-authored PRs

PRs created by Claude Code (from Slack or VS Code) follow the same rules:

- Same branch naming and commit conventions
- Must pass CI
- Must be reviewed and approved by a human
- AI never merges its own PRs

When reviewing an AI-authored PR, pay special attention to:

- Crate boundary violations (check dependency direction)
- Unnecessary dependencies added to `Cargo.toml`
- Generated code that compiles but doesn't match the architecture intent

## Testing

- Every public function should have at least one test
- Use `#[tokio::test]` for async tests
- Integration tests go in `tests/` at the crate root
- Use `assert_cmd` for end-to-end server tests in `dataglot-server`

## Adding dependencies

- Always use workspace dependencies: add to `[workspace.dependencies]` in the
  root `Cargo.toml`, then reference with `.workspace = true` in the crate
- Run `cargo deny check` after adding a dependency to verify license compliance
- Prefer Apache-2.0 or MIT licensed crates

## CI for external contributors

Everything the PR gate needs runs on public infrastructure with no
secrets: format, clippy, tests, docs, `cargo deny`, and the in-process
e2e suite all execute on any fork's PR.

> **Note on fork CI:** the workflows target this project's runners, which
> your fork doesn't have — so Actions on your *own fork* may sit
> "Waiting for a runner". That's expected. Open the PR against `main` and
> the gate runs here automatically; you don't need CI to run on your fork.

Two integration suites are the exception — **Snowflake** and
**Oracle** nightly jobs connect to real external services using
repository secrets. They are schedule-only, internal to Peaka, and
**never block a PR**. If your change touches those connectors, the
unit tests plus the Docker-gated integration tests (`make
test-integration`, against local testcontainers) are the expected
validation; a maintainer can trigger the nightly suites after merge.

# Installing Dataglot

Four channels, by decreasing convenience. All binaries are the
`dataglot` server (release profile, default features:
postgres + mysql + iceberg + snowflake + odata + rest).

## 1. Homebrew (macOS / Linux)

```bash
brew install dataglotai/tap/dataglot
```

Every GitHub Release ships a rendered formula (`dataglot.rb` in the
release assets) covering macOS arm64/x86_64 and Linux arm64/x86_64.

> **Status:** the `dataglotai/homebrew-tap` repository is created at OSS
> launch (releases are also unreachable to `brew` while this
> repository is private). Until then, use the release tarballs or
> `cargo binstall` below. Publishing a release to the tap = copying
> the rendered `dataglot.rb` from the release assets to
> `homebrew-tap/Formula/dataglot.rb`.

## 2. cargo-binstall

Resolves prebuilt binaries straight from GitHub Releases — no
compilation, no crates.io required:

```bash
cargo binstall --git https://github.com/dataglotai/dataglot dataglot-server
```

(The crate is `dataglot-server`; the installed binary is `dataglot`.)

## 3. Release tarballs

From [GitHub Releases](https://github.com/dataglotai/dataglot/releases):
`dataglot-<version>-<target>.tar.gz` + `.sha256` for

- `aarch64-apple-darwin` (Apple Silicon)
- `x86_64-apple-darwin` (Intel Mac)
- `aarch64-unknown-linux-gnu`
- `x86_64-unknown-linux-gnu`

```bash
tar xzf dataglot-<version>-<target>.tar.gz
./dataglot-<version>-<target>/dataglot --help
```

## 4. Container image

```bash
docker run --rm -p 5432:5432 ghcr.io/dataglotai/dataglot:latest
```

[QUICKSTART.md](../QUICKSTART.md) is the fastest path from any of these
channels to a first governed, federated query.

## Why not `cargo install` / crates.io?

Publishing to crates.io is deliberately deferred: the workspace uses
path dependencies plus a git-forked `snowflake-rs`, so publishing
means flattening/vendoring that graph. Binaries + Homebrew +
binstall cover the install story without it; the decision gets
revisited if users ask for `cargo install dataglot` specifically.
( records this decision.)

## Building from source

```bash
git clone https://github.com/dataglotai/dataglot.git
cd dataglot
cargo build --release -p dataglot-server
./target/release/dataglot --help
```

Rust stable; no C toolchain needed for the default feature set
(rule 15: the production runtime is Rust-only).

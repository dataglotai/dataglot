# ============================================================================
# Dataglot Dockerfile (open-source repo)
#
# Multi-stage build for optimized image size and build caching. This is the
# public-repo variant of the private development repo's Dockerfile: the
# workspace here contains only the shipped crates, so the dependency-caching
# COPY/stub blocks below list exactly this repo's workspace members. When a
# crate is added to `[workspace] members`, add it to BOTH the COPY block and
# the stub-source RUN below in the same PR — cargo refuses to resolve a
# workspace where any declared member is missing on disk, and a missing stub
# turns the cache layer into a silent 60-minute cold build.
# ============================================================================

# ============================================================================
# Stage 0: Frontend — build the operational dashboard bundle
#
# The `/ui` dashboard is embedded into `dataglot-server` via rust-embed
# (`#[folder = "frontend/dist"]`). We build that bundle here, in a dedicated
# Node stage, rather than installing Node in the Rust builder: it keeps the
# Rust builder Node-free, pins the toolchain vite 6 needs (Node 20), and makes
# the result deterministic. The built dist (~216 KB) is copied into the Rust
# builder below; Node never reaches the runtime image. `npm ci` reinstalls
# from the lockfile, so a stray local `node_modules` (already excluded via
# .dockerignore) can't influence the result.
# ============================================================================
FROM node:20-bookworm AS frontend
WORKDIR /fe
COPY crates/dataglot-server/frontend/ ./
RUN npm ci && npm run build

# Stage 1: Build environment
#
# Pinned to `rust:1.94-bookworm` (the workspace MSRV). The builder image never
# ships to production; only the binary it produces moves into the runtime
# stage below.
FROM rust:1.94-bookworm AS builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake \
    protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

# Build the image with THIN LTO instead of the workspace default
# `lto = "fat"` (Cargo.toml [profile.release]). Fat LTO merges the whole
# program's LLVM bitcode into a single module and optimizes it as one unit at
# link time, which spikes peak RSS well past what a memory-constrained Docker
# VM allocates. Thin LTO is parallel + per-module: a fraction of the peak
# memory for near-identical runtime performance, so the image builds on
# constrained hosts. This overrides ONLY the in-container build; the
# workspace profile and the `release.yml` binary keep fat LTO.
ENV CARGO_PROFILE_RELEASE_LTO=thin

# ----------------------------------------------------------------------
# Dependency-caching layer
#
# The pattern: copy ONLY the workspace + per-crate `Cargo.toml` files
# first, populate each crate's `src/` with the minimum stub that
# satisfies its manifest, then run `cargo build --release --package
# dataglot-server`. Cargo compiles every dep in `dataglot-server`'s
# transitive closure once. The result lives in `target/release/deps/`
# and survives the subsequent `rm -rf crates/*/src` + `COPY crates
# crates` because Docker treats the build artefacts as part of THIS
# layer's filesystem state. On subsequent builds where only source
# files changed (not `Cargo.toml` or `Cargo.lock`), Docker reuses this
# layer wholesale → real build takes ~30s instead of ~60min.
#
# `dataglot-ballista`'s Cargo.toml is copied even though the runtime image
# doesn't build the ballista feature: it is in `[workspace] members`, and
# cargo requires every member's manifest at workspace-load time. The stub
# `src/lib.rs` satisfies cargo's "every member has source" requirement; no
# actual Ballista compilation happens during the image build. Cargo also
# validates declared `[[test]]`/`[[bench]]` target paths at manifest-parse
# time — keep the bench stubs below in lock-step with the manifests.
# ----------------------------------------------------------------------
COPY Cargo.toml Cargo.lock ./
COPY crates/dataglot-ballista/Cargo.toml crates/dataglot-ballista/
COPY crates/dataglot-catalog/Cargo.toml crates/dataglot-catalog/
COPY crates/dataglot-core/Cargo.toml crates/dataglot-core/
COPY crates/dataglot-federation/Cargo.toml crates/dataglot-federation/
COPY crates/dataglot-pgwire/Cargo.toml crates/dataglot-pgwire/
COPY crates/dataglot-policy/Cargo.toml crates/dataglot-policy/
COPY crates/dataglot-server/Cargo.toml crates/dataglot-server/
COPY crates/dataglot-test-support/Cargo.toml crates/dataglot-test-support/

# Stub source files — one per workspace member (lib.rs for library crates,
# plus main.rs for crates with a `[[bin]]` target and bench stubs for
# declared `[[bench]]` paths). A stub-build failure below means these have
# drifted from manifest reality — fix the drift, never `|| true` it away.
RUN mkdir -p crates/dataglot-ballista/src     && echo "pub fn stub() {}" > crates/dataglot-ballista/src/lib.rs     \
    && mkdir -p crates/dataglot-ballista/benches \
    && echo "fn main() {}" > crates/dataglot-ballista/benches/four_worker_throughput.rs \
    && echo "fn main() {}" > crates/dataglot-ballista/benches/four_worker_multiprocess.rs \
    && mkdir -p crates/dataglot-catalog/src       && echo "pub fn stub() {}" > crates/dataglot-catalog/src/lib.rs       \
    && mkdir -p crates/dataglot-core/src          && echo "pub fn stub() {}" > crates/dataglot-core/src/lib.rs          \
    && mkdir -p crates/dataglot-federation/src    && echo "pub fn stub() {}" > crates/dataglot-federation/src/lib.rs    \
    && mkdir -p crates/dataglot-pgwire/src        && echo "pub fn stub() {}" > crates/dataglot-pgwire/src/lib.rs        \
    && mkdir -p crates/dataglot-policy/src        && echo "pub fn stub() {}" > crates/dataglot-policy/src/lib.rs        \
    && mkdir -p crates/dataglot-server/src        && echo "pub fn stub() {}" > crates/dataglot-server/src/lib.rs        \
    && echo "fn main() {}"   > crates/dataglot-server/src/main.rs    \
    && mkdir -p crates/dataglot-test-support/src  && echo "pub fn stub() {}" > crates/dataglot-test-support/src/lib.rs

# Build dependencies only (this layer is the cache target).
#
# `--features dashboard` here caches the dashboard's extra deps (rust-embed)
# in this layer too; `DATAGLOT_SKIP_FRONTEND_BUILD=1` makes build.rs emit a
# throwaway stub dist for the cache build (no Node in this stage) — the real
# bundle is copied in and embedded by the real build below.
RUN DATAGLOT_SKIP_FRONTEND_BUILD=1 cargo build --release --package dataglot-server --features dashboard

# Replace the stub sources with the real ones. The dep artefacts
# under `target/release/deps/` survive because they're outside the
# directories we just removed.
RUN rm -rf crates/*/src
COPY crates crates

# Touch real source files so cargo invalidates only the workspace
# crates' own .rlibs — not their transitive deps' artefacts in
# `target/release/deps/`. Without the touch, cargo's incremental
# tracker can decide the unchanged Cargo.toml means nothing to
# rebuild and skip the workspace crates entirely.
RUN touch crates/*/src/*.rs

# Bring in the dashboard bundle built in the `frontend` stage so
# rust-embed bakes the real `/ui` into the binary. It lands after the
# real sources are copied so nothing overwrites it, and `.dockerignore`
# keeps any local dist out of the context, so this is the only source
# of the embedded bundle.
COPY --from=frontend /fe/dist crates/dataglot-server/frontend/dist

# Build the real binary. Cargo finds every dep already compiled
# under `target/release/deps/` and only links the workspace crates
# fresh on top. Cold-cache: ~30s. Layer-cache hit: instant.
# `DATAGLOT_SKIP_FRONTEND_BUILD=1` tells build.rs to embed the dist we
# just copied instead of invoking vite (no Node in this stage).
RUN DATAGLOT_SKIP_FRONTEND_BUILD=1 cargo build --release --package dataglot-server --features dashboard \
    && strip /build/target/release/dataglot

# ============================================================================
# Stage 2: Runtime image — distroless
#
# `gcr.io/distroless/cc-debian12:nonroot` ships only the runtime libraries a
# glibc-linked Rust binary needs (libc, libgcc, libssl, ca-certificates) — no
# package manager, no shell, no `nc`. That eliminates the entire class of
# transitive CVEs a general-purpose base image carries: they aren't in the
# image at all rather than being patched.
#
# The shell-less runtime relies on `dataglot --healthcheck` — a one-shot TCP
# probe to `127.0.0.1:<port>` baked into the binary — and on the `nonroot`
# user (uid 65532) built into the distroless image.
#
# Why not pin by digest: this image is rebuilt on every push to main; we want
# Debian / glibc security patches to flow through automatically rather than
# blocking on a manual digest-bump PR. The Trivy gate on every Docker build is
# the safety net for "upstream retag changes CVE profile silently".
#
# The :cc variant has glibc and the openssl libs Rust crates pull
# (rustls + native-tls fallback path). The :base variant lacks
# libgcc/libstdc++ and is too thin for arbitrary Rust binaries.
# ============================================================================
FROM gcr.io/distroless/cc-debian12:nonroot AS runtime

WORKDIR /app

# Copy binary from builder. The builder produced a statically-
# stripped release binary in the previous stage; distroless's
# glibc 2.36 is ABI-compatible with the bookworm builder's glibc
# (both Debian 12 stream).
COPY --from=builder /build/target/release/dataglot /app/dataglot

# Apache-2.0 § 4(d): binary distributions must include the LICENSE,
# propagate downstream NOTICE attributions, and (per common Rust-
# ecosystem practice) ship a per-crate attribution report. All
# three land under /app/ so operators inspecting the container can
# read them with `docker run --rm dataglot:latest cat /app/NOTICE`
# (or LICENSE, or THIRD_PARTY_LICENSES.md).
COPY LICENSE /app/LICENSE
COPY NOTICE /app/NOTICE
COPY THIRD_PARTY_LICENSES.md /app/THIRD_PARTY_LICENSES.md

# Expose PostgreSQL wire protocol port
EXPOSE 5432

# Health check via the binary itself. Distroless has no shell or `nc`,
# so we lean on the `--healthcheck` flag — it does a TCP connect to
# 127.0.0.1:<port> with a 2-second timeout and exits 0/1.
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD ["/app/dataglot", "--healthcheck"]

# Environment variables with sensible defaults
ENV DATAGLOT_HOST=0.0.0.0 \
    DATAGLOT_PORT=5432 \
    DATAGLOT_BATCH_SIZE=8192 \
    DATAGLOT_DEFAULT_CATALOG=dataglot \
    DATAGLOT_DEFAULT_SCHEMA=public \
    RUST_LOG=info

# distroless `:nonroot` already runs as uid 65532; no explicit USER
# directive needed.
ENTRYPOINT ["/app/dataglot"]

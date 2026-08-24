# Dataglot (open-source) — developer Makefile.
#
# Scoped to the crates shipped in the public repo. Targets that need held-back
# crates (the differential testbench / comparators), Docker images, or internal
# tooling live in the private development repo and are intentionally absent here.
.PHONY: fmt toml-fmt toml-check check build-check build install-hooks \
        test test-unit test-pr doc deny ballista-ci ci clean \
        deps-check coverage coverage-open coverage-json

# ── formatting ─────────────────────────────────────────────
fmt:
	cargo +nightly fmt --all

toml-fmt:
	taplo fmt

toml-check:
	taplo fmt --check

# ── checks ─────────────────────────────────────────────────
# Excludes dataglot-ballista (needs protoc + a long compile); use `make
# ballista-ci` for that crate.
check:
	cargo +nightly fmt --all -- --check
	taplo fmt --check
	cargo clippy --workspace --exclude dataglot-ballista --all-targets -- -D warnings

# Fast compile-only gate — type-check without clippy/tests.
build-check:
	cargo check --workspace --all-targets --exclude dataglot-ballista
	@echo "✓ Workspace type-checks."

# Compile libs + binaries only (no test harnesses). For optimized binaries:
# cargo build --release --workspace --exclude dataglot-ballista
build:
	cargo build --workspace --exclude dataglot-ballista
	@echo "✓ Workspace built (libs + binaries)."

# ── git hooks ──────────────────────────────────────────────
# Install the repo-tracked pre-commit hook (taplo + rustfmt). Run once after clone.
install-hooks:
	git config core.hooksPath scripts/git-hooks
	@echo "✓ Pre-commit hook active (taplo fmt --check + cargo +nightly fmt --check)."

# ── tests ──────────────────────────────────────────────────
# All non-ballista tests (unit + any in-crate integration).
test:
	cargo test --workspace --exclude dataglot-ballista

# Unit tests only (fast, no external deps).
test-unit:
	cargo test --workspace --exclude dataglot-ballista --lib
	@echo "✓ Unit tests passed."

# The fast pre-PR gate.
test-pr: test-unit
	@echo "✓ PR tests passed."

# ── docs / licenses ────────────────────────────────────────
doc:
	RUSTDOCFLAGS="-D warnings" cargo doc --workspace --exclude dataglot-ballista --no-deps

deny:
	cargo deny check

# ── dependency hygiene ─────────────────────────────────────
# Native-dependency policy (rule 15) + workspace-dependency hygiene. Same guards
# the CI workflows run; handy to run locally before a dependency change.
deps-check:
	python3 scripts/check-native-deps.py
	python3 scripts/check-workspace-deps.py
	@echo "✓ Dependency hygiene checks passed."

# ── code coverage (cargo-llvm-cov) ─────────────────────────
# Line/region/function coverage over the workspace unit tests (--lib) plus
# dataglot-ballista's non-Docker integration tests. Requires:
#   rustup component add llvm-tools-preview
#   cargo install cargo-llvm-cov --locked
# (and protoc for ballista). See docs/coverage.md.
COVERAGE_SCOPE := --workspace --lib
COVERAGE_FEATURES := --features dataglot-federation/all
COVERAGE_BALLISTA_TESTS := -p dataglot-ballista --tests

coverage:
	@command -v cargo-llvm-cov >/dev/null 2>&1 || { \
	  echo "cargo-llvm-cov not found. Install:"; \
	  echo "  rustup component add llvm-tools-preview"; \
	  echo "  cargo install cargo-llvm-cov --locked"; exit 1; }
	cargo llvm-cov clean --workspace
	cargo llvm-cov $(COVERAGE_SCOPE) $(COVERAGE_FEATURES) --no-report
	cargo llvm-cov $(COVERAGE_BALLISTA_TESTS) --no-report
	cargo llvm-cov report --html
	@echo "✓ HTML report: target/llvm-cov/html/index.html  (open with: make coverage-open)"

coverage-open:
	@open target/llvm-cov/html/index.html 2>/dev/null || xdg-open target/llvm-cov/html/index.html 2>/dev/null || \
	  echo "Open target/llvm-cov/html/index.html manually."

# JSON coverage summary (for CI / badges). COVERAGE_JSON_OUT sets the destination.
coverage-json:
	@command -v cargo-llvm-cov >/dev/null 2>&1 || { echo "cargo-llvm-cov not found (see 'make coverage')."; exit 1; }
	cargo llvm-cov clean --workspace
	cargo llvm-cov $(COVERAGE_SCOPE) $(COVERAGE_FEATURES) --no-report
	cargo llvm-cov $(COVERAGE_BALLISTA_TESTS) --no-report
	cargo llvm-cov report --json > target/llvm-cov-export.json
	COVERAGE_JSON_OUT=$${COVERAGE_JSON_OUT:-target/coverage-summary.json} \
	  python3 scripts/coverage-summary.py target/llvm-cov-export.json
	@echo "✓ Coverage summary written (COVERAGE_JSON_OUT, default target/coverage-summary.json)."

# ── full local CI ──────────────────────────────────────────
ci: check test doc deny
	@echo ""
	@echo "✓ All CI checks passed."

# ── distributed execution (Apache Ballista) ────────────────
# Separate target: dataglot-ballista pulls Ballista's gRPC stack and needs
# `protoc` on PATH (macOS: brew install protobuf; Linux: apt-get install
# protobuf-compiler) plus a longer compile.
ballista-ci:
	cargo +nightly fmt -p dataglot-ballista -- --check
	cargo clippy -p dataglot-ballista --all-targets -- -D warnings
	cargo test -p dataglot-ballista
	RUSTDOCFLAGS="-D warnings" cargo doc -p dataglot-ballista --no-deps
	@echo ""
	@echo "✓ dataglot-ballista CI checks passed."

clean:
	cargo clean

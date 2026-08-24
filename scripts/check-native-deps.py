#!/usr/bin/env python3
"""Keep the production runtime Rust-only (hard rule 15).

The engine, connectors, catalog service, and EL pipeline are Rust. This
guard fails when a **production crate** gains a **direct** non-Rust /
native dependency that isn't on the sanctioned-exceptions allow-list:

  * JVM bindings    — `jni`, `j4rs`, `jni-sys`, …
  * Python bindings — `pyo3`, `cpython`, `rustpython`, …
  * C / C++         — any `*-sys` crate (links a native lib), native
                      build tools used as build-dependencies
                      (`cc`, `cmake`, `bindgen`, `cxx`), and known
                      native-bundling client crates.

A "production crate" is any workspace crate in the shipped **`dataglot-server`**
binary's dependency closure (normal + build deps). That's exactly what ships, so
it's exactly what rule 15 governs. Dev/tooling crates nothing shipped depends on
— the testbench (its TS frontend + DuckDB-C++ comparator), the `dataglot-tests`
harness, and the differential-comparator clients — fall outside the closure and
are exempt by construction.

(Earlier this used `publish = false` as the prod/dev signal — but every crate
sets `publish = false` to stay off crates.io, so the guard classified them all
as dev and scanned 0 crates, enforcing nothing.)

Only `[dependencies]` + `[build-dependencies]` are scanned (those ship /
affect the build); `[dev-dependencies]` are test-only and don't ship.
Transitive native crates (ring, zstd-sys, …) are *not* direct deps of our
production crates, so scanning direct deps only avoids false positives on
the unavoidable crypto/compression transitive tree.

Pairs with check-workspace-deps.py — stable toolchain, no build, safe for
the PR critical path. See docs/native-dependency-policy.md.
"""

from __future__ import annotations

import sys

try:
    import tomllib  # Python 3.11+ (the CI runner ships ≥3.12)
except ModuleNotFoundError:  # older local interpreters
    import tomli as tomllib  # type: ignore[no-redef]  # `pip install tomli`

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Dep tables that ship / affect the build. dev-dependencies are excluded
# (test-only, never linked into the shipped binary).
SHIPPING_TABLES = ("dependencies", "build-dependencies")

# Exact crate names that are non-Rust language bindings / runtimes.
NATIVE_DEP_NAMES: set[str] = {
    # JVM
    "jni",
    "jni-sys",
    "j4rs",
    "jbang",
    # Python
    "pyo3",
    "cpython",
    "python3-sys",
    "rustpython",
    "inline-python",
    # native-bundling clients we know wrap C / C++
    "duckdb",
    "oracle",
}

# Native build tooling — flagged only when used as a *build-dependency*
# (i.e. the crate compiles C/C++ at build time).
NATIVE_BUILD_TOOLS: set[str] = {"cc", "cmake", "bindgen", "cxx", "cxx-build"}

# (crate, dep) pairs that are DELIBERATELY allowed despite being native.
# Each MUST be feature-gated + documented in
# docs/native-dependency-policy.md. Keep this list short and commented.
ALLOW: set[tuple[str, str]] = {
    # Oracle federation connector (, Exadata displacement): the
    # `oracle` crate wraps ODPI-C and dlopen's Oracle Instant Client.
    # There is NO pure-Rust Oracle driver (proprietary wire protocol).
    # Feature-gated (`--features oracle`), off by default, excluded from
    # the `all` feature. See docs/native-dependency-policy.md.
    ("dataglot-federation", "oracle"),
}


def is_native(name: str, table: str) -> bool:
    """True if a direct dependency `name` in `table` is non-Rust/native."""
    if name in NATIVE_DEP_NAMES:
        return True
    if name.endswith("-sys") or name.endswith("_sys"):
        return True
    if table == "build-dependencies" and name in NATIVE_BUILD_TOOLS:
        return True
    return False


def internal_deps(data: dict, member_names: set[str], workspace_deps: dict) -> set[str]:
    """Workspace crates this manifest depends on via `[dependencies]` /
    `[build-dependencies]` (incl. platform-specific and optional deps).
    `[dev-dependencies]` are excluded — a test-only edge doesn't ship."""
    deps: set[str] = set()
    scopes = [data, *data.get("target", {}).values()]
    for scope in scopes:
        for table in SHIPPING_TABLES:
            for name, spec in scope.get(table, {}).items():
                real = actual_dep_name(name, spec, workspace_deps)
                if real in member_names:
                    deps.add(real)
    return deps


def production_crates(
    members: dict[str, dict], workspace_deps: dict, root_bin: str = "dataglot-server"
) -> set[str]:
    """The production set = the shipped `dataglot-server` binary's workspace
    dependency closure.

    Rule 15 governs *what ships*. We BFS from `dataglot-server` over internal
    (normal + build) dependency edges and treat every reachable workspace crate
    as production. Dev/tooling crates nothing shipped depends on — the testbench,
    the `dataglot-tests` harness, and the differential-comparator clients — are
    excluded by construction, no per-crate opt-out needed.

    (This replaces the old `publish = false` discriminator, which classified
    *every* crate as dev — all of them set `publish = false` to stay off
    crates.io — so the guard scanned 0 crates and enforced nothing.)"""
    member_names = set(members)
    if root_bin not in member_names:
        raise SystemExit(
            f"check-native-deps: shipped crate `{root_bin}` not found among "
            f"workspace members {sorted(member_names)}"
        )
    adjacency = {
        name: internal_deps(data, member_names, workspace_deps)
        for name, data in members.items()
    }
    seen: set[str] = set()
    stack = [root_bin]
    while stack:
        crate = stack.pop()
        if crate in seen:
            continue
        seen.add(crate)
        stack.extend(adjacency.get(crate, ()))
    return seen


def actual_dep_name(name: str, spec, workspace_deps: dict) -> str:
    """The real crate name a dependency resolves to.

    Closes two rename bypasses:
    - a local `package` rename (`alias = { package = "jni" }`), and
    - a **workspace-inherited** rename (`alias = { workspace = true }` where
      the root `[workspace.dependencies]` defines `alias = { package = "jni" }`)
      — resolved by consulting `workspace_deps`."""
    if isinstance(spec, dict):
        if spec.get("workspace") is True:
            return actual_dep_name(name, workspace_deps.get(name), workspace_deps)
        renamed = spec.get("package")
        if isinstance(renamed, str):
            return renamed
    return name


def main() -> int:
    offenders: list[str] = []

    # Root `[workspace.dependencies]` — needed to resolve workspace-inherited
    # renamed deps (`alias = { workspace = true }`).
    root = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))
    workspace_deps = root.get("workspace", {}).get("dependencies", {})

    # Every workspace crate, keyed by package name. rglob (not glob) so nested
    # crates can't slip past the scan; skip cargo build artifacts and virtual
    # (no-`[package]`) manifests.
    members: dict[str, dict] = {}
    for manifest_path in sorted((ROOT / "crates").rglob("Cargo.toml")):
        if "target" in manifest_path.parts:
            continue
        data = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
        package = data.get("package")
        if not isinstance(package, dict) or "name" not in package:
            continue
        members[package["name"]] = data

    # Production = the shipped `dataglot-server` binary's dependency closure.
    production = production_crates(members, workspace_deps)

    # Fail-secure: the closure must be non-trivial. A near-empty result means
    # the discriminator broke (the  regression scanned 0 crates and
    # passed silently) — refuse rather than pass a no-op guard.
    if len(production) < 2:
        print(
            "check-native-deps: production set is suspiciously small "
            f"({sorted(production)}) — the dataglot-server dependency closure "
            "did not resolve; refusing to pass a no-op guard.",
            file=sys.stderr,
        )
        return 2

    checked = sorted(production)
    for crate in checked:
        data = members[crate]

        # A crate that links a native library directly (the `links`
        # manifest key) is non-Rust even with no native dependency crate.
        links = data.get("package", {}).get("links")
        if links and (crate, f"links:{links}") not in ALLOW:
            offenders.append(f"  {crate}: links native library `{links}` (package.links)")

        # Top-level tables plus platform-specific
        # `[target.<cfg>.(build-)dependencies]`.
        scopes = [data, *data.get("target", {}).values()]
        for scope in scopes:
            for table in SHIPPING_TABLES:
                for name, spec in scope.get(table, {}).items():
                    real = actual_dep_name(name, spec, workspace_deps)
                    if not is_native(real, table):
                        continue
                    if (crate, real) in ALLOW:
                        continue
                    offenders.append(f"  {crate}: `{real}` ({table})")

    if offenders:
        print("Non-Rust dependency in a production crate (hard rule 15):\n")
        print("\n".join(sorted(set(offenders))))
        print(
            "\nThe production runtime is Rust-only. If this dependency is "
            "genuinely required and has no pure-Rust alternative:\n"
            "  1. feature-gate it (off by default),\n"
            "  2. add the (crate, dep) pair to ALLOW in "
            "scripts/check-native-deps.py, and\n"
            "  3. document the exception in docs/native-dependency-policy.md.\n"
            "If the crate is dev tooling, it must simply not be in "
            "`dataglot-server`'s dependency tree (that is what marks a crate "
            "non-production now)."
        )
        return 1

    print(
        f"Native-dependency check passed: {len(checked)} production crate(s) "
        "are Rust-only (sanctioned exceptions aside)."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

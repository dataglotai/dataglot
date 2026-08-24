#!/usr/bin/env python3
"""Enforce single-source-of-truth dependency versions across the workspace.

Rust workspace inheritance (`dep = { workspace = true }` against the root
`[workspace.dependencies]`) is how we keep one version per dependency. A
dep version pinned *inline* in two different crates is a drift hazard:
bump one, forget the other, and the resolver pulls two copies (bigger
build, bigger image — the 500 MB budget cares).

This check fails when:

  1. a dependency is declared with an inline version/git source in **two
     or more** workspace crates (it should live in
     `[workspace.dependencies]` and the crates should use
     `{ workspace = true }`); or
  2. a dependency is declared inline in a crate even though a
     `[workspace.dependencies]` entry of the same name already exists
     (the crate should inherit it).

Local `path` deps (intra-workspace crates) and single-crate inline deps
are fine — only one consumer, so no drift.

Stable toolchain, no build — safe for the PR critical path. Pairs with
the unused-dependency checks (cargo-machete PR + cargo-udeps nightly).
"""

from __future__ import annotations

import sys

try:
    import tomllib  # Python 3.11+ (the CI runner ships ≥3.12)
except ModuleNotFoundError:  # older local interpreters
    import tomli as tomllib  # type: ignore[no-redef]  # `pip install tomli`

from collections import defaultdict
from pathlib import Path

DEP_TABLES = ("dependencies", "dev-dependencies", "build-dependencies")
ROOT = Path(__file__).resolve().parent.parent

# (crate, dep) pairs intentionally exempt — each is a *deliberate* divergence,
# not accidental drift. Keep this list short and commented.
EXEMPT: set[tuple[str, str]] = {
    # The federation connector pins the arrow-58 snowflake-rs fork; the
    # testbench comparator pins a different rev of the same fork. Unifying
    # the revs is a separate, build-verified change — not safe to force here.
    ("dataglot-federation", "snowflake-api"),
    ("dataglot-testbench", "snowflake-api"),
    # federation deliberately uses a leaner chrono (default-features = false,
    # only `clock`, no `serde`) than the workspace entry — same version, so
    # no version drift; inheriting would pull features it doesn't want.
    ("dataglot-federation", "chrono"),
    # object_store versions are pinned to each crate's engine: dataglot-server
    # must match DataFusion 53.1's `object_store` 0.13 exactly (its
    # `AmazonS3` store is registered on DataFusion's RuntimeEnv, so the trait
    # types must line up), while dataglot-ballista tracks Apache Ballista's
    # 0.14. A single workspace pin can't serve both; unifying is a separate,
    # build-verified change (mirrors the snowflake-api divergence above).
    ("dataglot-server", "object_store"),
}


def is_inline(spec) -> bool:
    """True if the spec pins its own version/git (i.e. NOT workspace-inherited
    and NOT a pure intra-workspace `path` dep)."""
    if isinstance(spec, str):  # `dep = "1.2"`
        return True
    if not isinstance(spec, dict):
        return False
    if spec.get("workspace") is True:
        return False  # inherits the workspace version — good
    # A pure path dep (intra-workspace crate) has no version drift.
    if "path" in spec and "version" not in spec and "git" not in spec:
        return False
    return "version" in spec or "git" in spec


def main() -> int:
    root_manifest = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))
    workspace_deps = set(
        root_manifest.get("workspace", {}).get("dependencies", {}).keys()
    )

    # dep name -> list of crates that declare it inline
    inline: dict[str, list[str]] = defaultdict(list)
    # (crate, dep) pairs that pin inline despite a workspace entry existing
    shadows: list[tuple[str, str]] = []

    for manifest in sorted((ROOT / "crates").glob("*/Cargo.toml")):
        crate = manifest.parent.name
        data = tomllib.loads(manifest.read_text(encoding="utf-8"))
        # Top-level dep tables plus any platform-specific
        # `[target.<cfg>.dependencies]` tables (those can drift too).
        scopes = [data, *data.get("target", {}).values()]
        for scope in scopes:
            for table in DEP_TABLES:
                for name, spec in scope.get(table, {}).items():
                    if not is_inline(spec):
                        continue
                    if (crate, name) in EXEMPT:
                        continue
                    inline[name].append(crate)
                    if name in workspace_deps:
                        shadows.append((crate, name))

    errors: list[str] = []

    for crate, name in sorted(set(shadows)):
        errors.append(
            f"  {crate}: `{name}` is pinned inline but `[workspace.dependencies]` "
            f"already defines it — use `{name} = {{ workspace = true }}`."
        )

    for name, crates in sorted(inline.items()):
        distinct = sorted(set(crates))
        if len(distinct) >= 2 and name not in workspace_deps:
            errors.append(
                f"  `{name}` is pinned inline in {len(distinct)} crates "
                f"({', '.join(distinct)}) — hoist it to "
                f"`[workspace.dependencies]` and use `{{ workspace = true }}`."
            )

    if errors:
        print("Workspace dependency drift detected:\n")
        print("\n".join(errors))
        print(
            "\nFix: add the dependency to the root `[workspace.dependencies]` "
            "(single version source of truth) and declare it in each crate as "
            "`<dep> = { workspace = true }` (adding crate-specific `features` / "
            "`optional` as needed)."
        )
        return 1

    print("Workspace dependency check passed: no inline version drift.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

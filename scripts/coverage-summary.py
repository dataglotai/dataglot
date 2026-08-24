#!/usr/bin/env python3
"""Turn `cargo llvm-cov --json` export into the dashboard coverage summary.

Single source of truth for both `make coverage-json` (local) and the nightly
`coverage.yml` workflow. Reads llvm-cov's JSON on stdin (or a file arg) and
writes a JSON summary (destination via `COVERAGE_JSON_OUT`, default
`target/coverage-summary.json`) with:

  - overall line / region / function totals (count, covered, percent)
  - a per-crate breakdown (grouped by `crates/<name>/`)
  - generated_at + commit for the dashboard's "as of" line

llvm-cov's export shape (v0.8): `.data[0].totals` and `.data[0].files[]`, each
carrying `lines`, `regions`, `functions`, `branches`, ... with count/covered/
percent. We surface line (headline), region (llvm's finer-grained primary),
and function — the three metrics Rust coverage tooling conventionally reports;
branch/MCDC stay off by default (they need `--branch`) so we don't publish
misleading zeros.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import datetime, timezone

METRICS = ("lines", "regions", "functions")

# Crates excluded from the coverage report. `dataglot-testbench` is dev
# tooling (the differential testbench SPA + harness), not shipped engine
# code — same rationale as excluding it from `--lib` coverage at the cargo
# level. Kept here too so a stray export (or a local run without the
# `--exclude` flag) still produces the intended report.
EXCLUDE_CRATES = {"dataglot-testbench"}


def metric(summary: dict, name: str) -> dict:
    m = summary.get(name, {})
    return {
        "count": m.get("count", 0),
        "covered": m.get("covered", 0),
        "percent": round(m.get("percent", 0.0), 2),
    }


def totals_block(summary: dict) -> dict:
    return {name: metric(summary, name) for name in METRICS}


def crate_of(path: str) -> str | None:
    """`.../crates/<name>/src/foo.rs` -> `<name>`; None for non-crate paths."""
    parts = path.replace("\\", "/").split("/")
    if "crates" in parts:
        i = parts.index("crates")
        if i + 1 < len(parts):
            return parts[i + 1]
    return None


def merge(into: dict, summary: dict) -> None:
    for name in METRICS:
        src = summary.get(name, {})
        dst = into.setdefault(name, {"count": 0, "covered": 0})
        dst["count"] += src.get("count", 0)
        dst["covered"] += src.get("covered", 0)


def pct(block: dict) -> dict:
    out = {}
    for name in METRICS:
        c = block.get(name, {"count": 0, "covered": 0})
        cnt, cov = c["count"], c["covered"]
        out[name] = {
            "count": cnt,
            "covered": cov,
            "percent": round((cov / cnt * 100) if cnt else 0.0, 2),
        }
    return out


def git_commit() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"], text=True
        ).strip()
    except Exception:
        return os.environ.get("GITHUB_SHA", "")[:7]


def main() -> int:
    raw = open(sys.argv[1]).read() if len(sys.argv) > 1 and sys.argv[1] != "-" else sys.stdin.read()
    data = json.loads(raw)
    export = data["data"][0]

    per_crate: dict[str, dict] = {}
    for f in export.get("files", []):
        name = crate_of(f["filename"])
        if name is None or name in EXCLUDE_CRATES:
            continue
        merge(per_crate.setdefault(name, {}), f["summary"])

    crates = [
        {"crate": name, **pct(block)}
        for name, block in sorted(per_crate.items())
    ]

    # Overall is the sum of the crates we actually report, so the headline
    # always equals what the per-crate table shows (and excludes anything in
    # EXCLUDE_CRATES — llvm-cov's own `totals` would still count it).
    overall_acc: dict = {}
    for block in per_crate.values():
        merge(overall_acc, {m: block.get(m, {}) for m in METRICS})
    overall = pct(overall_acc)

    out = {
        "generated_at": os.environ.get("COVERAGE_GENERATED_AT")
        or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "commit": git_commit(),
        "scope": "workspace unit tests (--lib) + dataglot-ballista non-Docker distributed integration tests; excludes dataglot-testbench; ballista's Docker-gated --ignored tier not measured",
        "overall": overall,
        "crates": crates,
    }

    dest = os.environ.get("COVERAGE_JSON_OUT", "target/coverage-summary.json")
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    with open(dest, "w") as fh:
        json.dump(out, fh, indent=2)
        fh.write("\n")
    print(f"wrote {dest}: {out['overall']['lines']['percent']}% lines, "
          f"{len(crates)} crates")
    return 0


if __name__ == "__main__":
    sys.exit(main())

# TPC-H query templates

Canonical TPC-H 3.0 queries used by the
`crates/dataglot-tests/benches/tpch_baseline.rs` harness. Phase 2 task 03
ships an initial set (q1, q3, q5, q6, q9 — the spec's "headline three"
plus two single-table queries for harness validation); the remaining 17
land in a follow-up.

## Provenance

The reference parameter values are from the TPC-H 3.0 specification
(`DATE`, `INTERVAL`, and string literal substitutions baked in
verbatim, no runtime parameterization). The SQL syntax matches what
DataFusion 53.1's SQL planner accepts:

- `EXTRACT(year FROM …)` rather than the SQL-92
  `EXTRACT(YEAR FROM …)` (DataFusion lowercases part names internally
  but the parser accepts both).
- `INTERVAL '90' DAY` rather than vendor-specific `INTERVAL 90 DAY`.
- No vendor-specific `LIMIT` placement — `ORDER BY` then `LIMIT n` is
  ANSI-standard and DataFusion handles it.

## Why not pull at build time

Three reasons:

1. **Build determinism.** No network at compile time; the workspace
   builds in air-gapped CI runners.
2. **Spec drift visibility.** A change to a query is a real change to
   what we measure; it should show up in `git log` against this dir,
   not be silent.
3. **License + provenance clarity.** TPC-H queries themselves are
   covered by the TPC fair-use clause; we redistribute them in the
   identical canonical form, which is the standard practice across
   open-source benchmark harnesses.

## See also

- the phase-2 `tpch-baseline` plan — the spec (maintainers' private
  development repo, along with the `tpch_baseline.rs` bench runner and
  the nightly-published baseline JSON).

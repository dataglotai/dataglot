# Security Policy

## Reporting a vulnerability

**Do not open a public issue for security problems.** Use one of:

1. **GitHub private vulnerability reporting** (preferred) — the
   *Security* tab of this repository → *Report a vulnerability*.
2. **Email** — `security@peaka.com`, with a description, reproduction
   steps, and the impact you believe it has.

We acknowledge reports within **48 hours** and aim to share a triage
verdict and remediation timeline within **7 days**. Please give us a
reasonable window to ship a fix before public disclosure; we credit
reporters in the release notes unless you ask otherwise.

## Supported versions

Dataglot is pre-1.0. Security fixes land on `main` and in the **latest
tagged release** only; older tags are not patched. Container images are
published at `ghcr.io/dataglotai/dataglot`.

## Scope

In scope: the production crates (`dataglot-core`, `dataglot-federation`,
`dataglot-pgwire`, `dataglot-policy`, `dataglot-server`,
`dataglot-ballista`, `dataglot-catalog`) — in particular anything that
lets a client **bypass plan-time governance** (column masks, row
filters, access-deny), leak credentials, or evade authentication /
connection admission. Governance bypasses are treated as
highest-severity: enforcement being a guarantee is the product thesis.

Out of scope: the demo stack (`examples/demo/` — its hardcoded
credentials like `postgres:postgres` and `demo` identities are
intentional test fixtures, never production defaults), the dev-only
testbench and comparator client crates (`publish = false`), and
vulnerabilities requiring an already-compromised host.

## Security posture (summary)

- **Credential isolation** — credentials are referenced by env-var name
  or file path, resolved at boot, and never appear in logs, errors,
  `Debug` output, or plan representations — a hard architectural rule.
- **Transport encryption** — pgwire ingress TLS (`[pgwire_tls]`,
  prefer/require), source-database TLS for Postgres/MySQL (per-catalog
  `tls = "require"`), and cluster mTLS for distributed execution.
- **Authentication & admission** — trust or MD5 password auth
  (`[auth]`), plus global / per-IP / per-IP-rate / per-identity
  connection ceilings (`[rate_limit]`). Insecure postures (trust +
  policies, md5 without TLS) emit boot warnings.
- **Audit trail** — every policy decision (mask, row-filter, deny),
  failed authentication, and connection rejection emits a structured
  event on the `dataglot::audit` tracing target.
- **Supply chain** — dependencies are license- and advisory-checked in
  CI via `cargo deny`; native dependencies are allow-listed and
  CI-enforced (Native Dependency Hygiene workflow).

The full control inventory and audit-readiness scorecard is maintained
in the project's internal audit-readiness review
(`docs/phases/phase-3/security-audit-readiness.md` in the private
development repository).

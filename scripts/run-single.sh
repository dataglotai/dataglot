#!/usr/bin/env bash
# run-single.sh — start Dataglot in single-node mode with sensible defaults.
#
#   ./scripts/run-single.sh
#
# No arguments needed. Builds and runs one server on port 15432 with a single
# `demo` catalog. It boots even if the catalog's Postgres source is unreachable
# (--tolerate-unreachable-catalogs), so you can connect right away:
#
#   psql "host=127.0.0.1 port=15432 user=postgres dbname=demo"
#
# Point it at your own Postgres for real data:
#
#   DGLOT_DSN="host=… port=… user=… password=… dbname=…" ./scripts/run-single.sh
#
# Env overrides (all optional): PORT (15432), PROFILE (release|debug), DGLOT_DSN.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PORT="${PORT:-15432}"
HOST="${HOST:-127.0.0.1}"   # loopback by default (the generated config has no auth)
PROFILE="${PROFILE:-release}"
DASHBOARD="${DASHBOARD:-1}"  # operational UI at http://127.0.0.1:9090/ui (DASHBOARD=0 to skip)
DGLOT_DSN="${DGLOT_DSN:-host=127.0.0.1 port=5432 user=postgres password=postgres dbname=demo}"
export DGLOT_DSN
FEATURES=()
DASH_LABEL=""
[[ "$DASHBOARD" == "1" ]] && { FEATURES=(--features dashboard); DASH_LABEL=", dashboard"; }

uint() { [[ "$1" =~ ^[1-9][0-9]*$ ]] || { echo "$2 must be a positive integer (got '$1')" >&2; exit 2; }; }
uint "$PORT" PORT
[[ "$PORT" -le 65535 ]] || { echo "PORT must be <= 65535 (got $PORT)" >&2; exit 2; }
case "$PROFILE" in
  release) PROFILE_DIR=release; CARGO_PROFILE=(--release) ;;
  debug)   PROFILE_DIR=debug;   CARGO_PROFILE=() ;;
  *) echo "PROFILE must be release or debug (got '$PROFILE')" >&2; exit 1 ;;
esac

CFG="$(mktemp "${TMPDIR:-/tmp}/dataglot-single.XXXXXX")"
trap 'rm -f "$CFG"' EXIT
cat > "$CFG" <<TOML
host = "${HOST}"
port = ${PORT}
default_catalog = "demo"
default_schema = "public"

[catalogs.demo]
kind = "postgres"
dsn_env = "DGLOT_DSN"
TOML

echo "→ building dataglot-server (${PROFILE}${DASH_LABEL})…"
[[ "$DASHBOARD" == "1" ]] && ! command -v npm >/dev/null 2>&1 && \
  echo "  ! npm not found — the dashboard will be an empty stub; install Node.js to build the real UI"
cargo build "${CARGO_PROFILE[@]+"${CARGO_PROFILE[@]}"}" ${FEATURES[@]+"${FEATURES[@]}"} -p dataglot-server
echo "→ single-node on ${HOST}:${PORT}   (Ctrl-C to stop)"
echo "   connect: psql \"host=127.0.0.1 port=${PORT} user=postgres dbname=demo\""
[[ "$DASHBOARD" == "1" ]] && echo "   dashboard: http://127.0.0.1:9090/ui"
# Not `exec` — so the EXIT trap runs and removes the temp config on shutdown.
"$ROOT/target/$PROFILE_DIR/dataglot" \
  --config "$CFG" --port "$PORT" --tolerate-unreachable-catalogs

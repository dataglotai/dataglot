#!/usr/bin/env bash
# run-distributed.sh — start a Dataglot distributed cluster with sensible defaults.
#
#   ./scripts/run-distributed.sh
#
# No arguments needed. Builds the server (--features ballista) and the Ballista
# executor, then starts a scheduler-hosting server plus 2 executors × 8 task
# slots (16 slots total) on port 15432 with a single `demo` catalog. Requires
# `protoc` on PATH (Apache Ballista): brew install protobuf / apt-get install
# protobuf-compiler.
#
#   psql "host=127.0.0.1 port=15432 user=postgres dbname=demo"
#
# The server boots even if the catalog source is unreachable, but distributed
# introspection (\dt / \dn) and federated queries need DGLOT_DSN pointing at a
# reachable Postgres:
#
#   DGLOT_DSN="host=… port=… user=… password=… dbname=…" ./scripts/run-distributed.sh
#
# Env overrides (all optional): PORT (15432), PROFILE (release|debug),
# EXECUTORS (2), SLOTS (8), DGLOT_DSN, REST_API_PORT (50050, scheduler REST API).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PORT="${PORT:-15432}"
HOST="${HOST:-127.0.0.1}"   # loopback by default (the generated config has no auth)
PROFILE="${PROFILE:-release}"
DASHBOARD="${DASHBOARD:-1}"  # operational UI at http://127.0.0.1:9090/ui (DASHBOARD=0 to skip)
EXECUTORS="${EXECUTORS:-2}"
SLOTS="${SLOTS:-8}"
SCHEDULER_GRPC_PORT="${SCHEDULER_GRPC_PORT:-50060}"
REST_API_PORT="${REST_API_PORT:-50050}"  # scheduler observability REST API (backs the dashboard Cluster view + the registration wait below)
DGLOT_DSN="${DGLOT_DSN:-host=127.0.0.1 port=5432 user=postgres password=postgres dbname=demo}"
export DGLOT_DSN

uint() { [[ "$1" =~ ^[1-9][0-9]*$ ]] || { echo "$2 must be a positive integer (got '$1')" >&2; exit 2; }; }
uint "$PORT" PORT; uint "$EXECUTORS" EXECUTORS; uint "$SLOTS" SLOTS; uint "$SCHEDULER_GRPC_PORT" SCHEDULER_GRPC_PORT; uint "$REST_API_PORT" REST_API_PORT
{ [[ "$PORT" -le 65535 && "$SCHEDULER_GRPC_PORT" -le 65535 && "$REST_API_PORT" -le 65535 ]]; } || { echo "ports must be <= 65535" >&2; exit 2; }
case "$PROFILE" in
  release) PROFILE_DIR=release; CARGO_PROFILE=(--release) ;;
  debug)   PROFILE_DIR=debug;   CARGO_PROFILE=() ;;
  *) echo "PROFILE must be release or debug (got '$PROFILE')" >&2; exit 1 ;;
esac
command -v protoc >/dev/null 2>&1 || {
  echo "distributed mode needs protoc on PATH (brew install protobuf / apt-get install protobuf-compiler)" >&2
  exit 1
}

WORK="$(mktemp -d "${TMPDIR:-/tmp}/dataglot-dist.XXXXXX")"
chmod 700 "$WORK"
PIDS=()
EXEC_PIDS=()
cleanup() {
  echo; echo "→ shutting down cluster…"
  # Only kill the processes we started (tracked in PIDS) — no broad pkill, which
  # would take down another user's executors on a shared host.
  for p in ${PIDS[@]+"${PIDS[@]}"}; do kill "$p" 2>/dev/null || true; done
  rm -rf "$WORK" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

cat > "$WORK/dataglot.toml" <<TOML
host = "${HOST}"
port = ${PORT}
default_catalog = "demo"
default_schema = "public"

[catalogs.demo]
kind = "postgres"
dsn_env = "DGLOT_DSN"

# external_executors > 0 => the server hosts the scheduler only; the executor
# processes below carry every task.
[ballista]
standalone_parallelism = ${SLOTS}
external_executors = ${EXECUTORS}
scheduler_grpc_port = ${SCHEDULER_GRPC_PORT}
rest_api_port = ${REST_API_PORT}
TOML

SERVER_FEATURES="ballista"; [[ "$DASHBOARD" == "1" ]] && SERVER_FEATURES="ballista,dashboard"
[[ "$DASHBOARD" == "1" ]] && ! command -v npm >/dev/null 2>&1 && \
  echo "  ! npm not found — the dashboard will be an empty stub; install Node.js to build the real UI"
echo "→ building server (--features ${SERVER_FEATURES}) + executor (${PROFILE})…"
cargo build "${CARGO_PROFILE[@]+"${CARGO_PROFILE[@]}"}" --features "$SERVER_FEATURES" -p dataglot-server
cargo build "${CARGO_PROFILE[@]+"${CARGO_PROFILE[@]}"}" -p dataglot-ballista --bin dataglot-ballista-executor
SERVER="$ROOT/target/$PROFILE_DIR/dataglot"
EXEC="$ROOT/target/$PROFILE_DIR/dataglot-ballista-executor"

SERVER_PID=""
SLOG="$WORK/server.log"
echo "→ starting scheduler-hosting server on 127.0.0.1:${PORT} (log: $SLOG)…"
"$SERVER" --config "$WORK/dataglot.toml" --port "$PORT" --tolerate-unreachable-catalogs >"$SLOG" 2>&1 &
SERVER_PID=$!; PIDS+=("$SERVER_PID")
SERVER_UP=0
for _ in $(seq 1 180); do
  if grep -q "Listening for connections" "$SLOG" 2>/dev/null; then SERVER_UP=1; echo "  ✓ server listening"; break; fi
  kill -0 "$SERVER_PID" 2>/dev/null || break   # server died during startup
  sleep 1
done
if [[ "$SERVER_UP" -ne 1 ]]; then
  echo "✗ server did not come up — log tail:" >&2; tail -20 "$SLOG" >&2; exit 1
fi

# Did OUR scheduler actually bind the REST API? If REST_API_PORT was already
# taken, the server logs the failure and continues — and a poll of that port
# would then reach whatever else owns it (e.g. another cluster), whose executor
# count is not ours. Only trust the registration count (and only abort on a
# shortfall) once the server's own log confirms it is serving that REST port.
# Two greps, not one regex: under JSON logging the structured port field can
# serialize before the message text on the line, so a single `phrase.*port`
# pattern would miss it. Match the phrase and the port independently on the
# same line — order-agnostic across plain and JSON log formats.
REST_MINE=0
if grep -E "(scheduler REST API serving|observability API serving)" "$SLOG" 2>/dev/null \
     | grep -Eq "[:/]${REST_API_PORT}([^0-9]|$)"; then
  REST_MINE=1
else
  echo "  ! scheduler REST API not serving on 127.0.0.1:${REST_API_PORT} (port in use?) — registration check + dashboard Cluster view disabled; set REST_API_PORT to a free port"
fi

# Is the demo source reachable? Executors' --catalogs-config connects eagerly and
# treats a failed connection as fatal (no coordinator-style tolerate flag), so
# pass it only when the source is up. Without it the executors still boot and
# register (empty registry) — the cluster has workers, and federated queries
# start working as soon as you point DGLOT_DSN at a reachable Postgres.
DSN_HOST="$(sed -n 's/.*[^a-z]host=\([^ ]*\).*/\1/p' <<<" $DGLOT_DSN")"; DSN_HOST="${DSN_HOST:-127.0.0.1}"
DSN_PORT="$(sed -n 's/.*[^a-z]port=\([^ ]*\).*/\1/p' <<<" $DGLOT_DSN")"; DSN_PORT="${DSN_PORT:-5432}"
CATALOG_ARGS=()
if (exec 3<>"/dev/tcp/${DSN_HOST}/${DSN_PORT}") 2>/dev/null; then
  exec 3>&- 2>/dev/null || true
  # Build the JSON with python so a DSN containing quotes is escaped safely.
  DGLOT_DSN="$DGLOT_DSN" python3 -c 'import json,os; print(json.dumps({"demo":{"type":"postgres","dsn":os.environ["DGLOT_DSN"]}}))' > "$WORK/catalogs.json"
  CATALOG_ARGS=(--catalogs-config "$WORK/catalogs.json")
  echo "  ✓ source reachable at ${DSN_HOST}:${DSN_PORT} — executors get the demo catalog"
else
  echo "  ! no source at ${DSN_HOST}:${DSN_PORT} — executors boot without it; set DGLOT_DSN to a reachable Postgres for federated distributed queries"
fi
printf '{"kind":"static","entries":{}}' > "$WORK/creds.json"

echo "→ spawning ${EXECUTORS} executor(s) × ${SLOTS} slots → scheduler :${SCHEDULER_GRPC_PORT}…"
EXPECT_PORTS=""            # the Flight bind ports of the executors WE spawn
for i in $(seq 0 $((EXECUTORS - 1))); do
  bport=$((50061 + i * 10))
  "$EXEC" \
    --scheduler-host 127.0.0.1 --scheduler-port "$SCHEDULER_GRPC_PORT" \
    --bind-host 127.0.0.1 --external-host 127.0.0.1 \
    --bind-port "$bport" --bind-grpc-port $((50062 + i * 10)) \
    --concurrent-tasks "$SLOTS" \
    --credentials-config "$WORK/creds.json" \
    ${CATALOG_ARGS[@]+"${CATALOG_ARGS[@]}"} \
    --insecure >"$WORK/executor-$i.log" 2>&1 &
  epid=$!
  PIDS+=("$epid")           # for cleanup (plain PIDs)
  EXEC_PIDS+=("$epid:$i")   # for the liveness check below
  EXPECT_PORTS+="$bport "   # so the registration count matches OUR executors, not any stranger's
done

# A live process (kill -0) is not a registered worker: executors take a few
# seconds to register with the scheduler (longer on a cold first run), and the
# dashboard Cluster view stays empty until they do. So wait for both — each
# executor survived startup AND the scheduler reports the full count — before
# announcing the cluster as up. Registration is read from the scheduler's REST
# API; if curl/python3 are missing we fall back to a fixed grace period.
check_alive() {  # abort if any executor exited during startup (bad port/config/source)
  for entry in "${EXEC_PIDS[@]}"; do
    epid="${entry%%:*}"; eidx="${entry##*:}"
    if ! kill -0 "$epid" 2>/dev/null; then
      echo "✗ executor $eidx exited during startup — log tail:" >&2
      tail -20 "$WORK/executor-$eidx.log" >&2; exit 1
    fi
  done
}
reg_count() {  # echo how many of OUR executors have registered; return non-zero (no output) if the REST API can't be read
  local body
  body="$(curl -fs --max-time 3 "http://127.0.0.1:${REST_API_PORT}/api/executors" 2>/dev/null)" || return 1  # -f: fail on HTTP errors instead of parsing an error page
  # The REST API is loopback-only by engine design (unauthenticated), so we poll
  # 127.0.0.1 regardless of the pgwire HOST. Require a JSON *list* (a stray
  # object/string would also have a length), then count the number of DISTINCT
  # endpoints we spawned — each executor advertises (host=127.0.0.1, port=P) for
  # a P we chose. Matching distinct loopback (host,port) pairs — not a raw port
  # tally — means a foreign executor (the scheduler binds 0.0.0.0) advertising a
  # duplicate port from another host can't stand in for one that hasn't
  # registered yet.
  printf '%s' "$body" | EXPECT_PORTS="$EXPECT_PORTS" python3 -c 'import json,os,sys
want = {int(p) for p in os.environ.get("EXPECT_PORTS", "").split()}
try:
    x = json.load(sys.stdin)
except Exception:
    sys.exit(1)
if not isinstance(x, list):
    sys.exit(1)
if not want:
    print(len(x)); sys.exit(0)
seen = {e.get("port") for e in x
        if isinstance(e, dict) and e.get("host") == "127.0.0.1" and e.get("port") in want}
print(len(seen))' 2>/dev/null
}
HAVE_POLL=0
command -v curl >/dev/null 2>&1 && command -v python3 >/dev/null 2>&1 && HAVE_POLL=1
if [[ "$HAVE_POLL" -ne 1 || "$REST_MINE" -ne 1 ]]; then
  # Can't verify registration (no curl/python3, or the REST API isn't ours):
  # keep the old best-effort grace period + liveness check, don't abort.
  sleep 3; check_alive
  [[ "$HAVE_POLL" -ne 1 ]] && echo "  (install curl + python3 to have the launcher confirm executor registration)"
else
  REGISTERED=0 OBSERVED=0 LAST=0
  # Wall-clock deadline (bash `SECONDS`), not an iteration count: `curl
  # --max-time` bounds each request, so a hung-but-accepting REST port could
  # stretch a fixed 40-iteration loop to minutes. This keeps the real ~40s bound.
  SECONDS=0
  while [[ "$SECONDS" -lt 40 ]]; do
    check_alive                      # fail fast if one crashed while we wait
    if n="$(reg_count)"; then        # scheduler REST API answered with a count
      OBSERVED=1; LAST="$n"
      if [[ "$n" -ge "$EXECUTORS" ]]; then
        REGISTERED=1; echo "  ✓ ${n}/${EXECUTORS} executor(s) registered with the scheduler"; break
      fi
    fi
    sleep 1
  done
  if [[ "$REGISTERED" -ne 1 ]]; then
    if [[ "$OBSERVED" -eq 1 ]]; then
      # The scheduler answered but is short of workers — a real registration
      # failure, not a slow start. Abort rather than announce a false-ready
      # cluster that would run queries against too few (or zero) executors.
      echo "✗ only ${LAST}/${EXECUTORS} executor(s) registered after 40s — aborting so queries don't run on an under-provisioned cluster." >&2
      echo "  server log tail:" >&2; tail -15 "$SLOG" >&2
      for entry in "${EXEC_PIDS[@]}"; do
        eidx="${entry##*:}"; echo "  executor $eidx log tail:" >&2; tail -8 "$WORK/executor-$eidx.log" >&2
      done
      exit 1
    fi
    # Couldn't reach the REST API at all (e.g. :${REST_API_PORT} was taken, so
    # the scheduler skipped the bind). The executors passed their liveness
    # checks, so the cluster itself is likely fine — we just can't confirm.
    echo "  ! couldn't reach the scheduler REST API on 127.0.0.1:${REST_API_PORT} to confirm registration; executors are alive, continuing (set REST_API_PORT to a free port to enable the check + dashboard Cluster view)"
  fi
fi

echo "→ distributed cluster up: ${EXECUTORS}×${SLOTS} = $((EXECUTORS * SLOTS)) task slots on ${HOST}:${PORT}   (Ctrl-C to stop)"
echo "   connect: psql \"host=127.0.0.1 port=${PORT} user=postgres dbname=demo\"   (\\dt / queries need DGLOT_DSN reachable)"
[[ "$DASHBOARD" == "1" ]] && echo "   dashboard: http://127.0.0.1:9090/ui"
wait

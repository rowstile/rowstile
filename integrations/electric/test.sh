#!/bin/bash
# test.sh: the conformance suite for Electric (a preview), the sync engine, behind the app's own server: Postgres
# (wal_level logical), Electric in manual publication mode on a role of its own, a small Express app whose shape
# routes are @rowstile/client's electricShape, nginx as a cache in front of it, and the checks on Vitest with
# Electric's own client (@electric-sql/client).
#   integrations/electric/test.sh            # PG_MAJOR=17 or 18 for another version; KEEP=1 keeps the containers
#   POOLER=pgbouncer integrations/electric/test.sh   # the app through PgBouncer in transaction mode (Electric direct)
#   integrations/electric/test.sh -t "E2"    # some of the checks: what follows is Vitest's
#   SYNC_MODE=keyed integrations/electric/test.sh    # the whole suite in another of the index's modes:
#     copied   the default: each file's readers copied in from every folder above it, in the writer's transaction
#     keyed    keyed by folder (`by folder` on the files' and the folders' sync lines; the notes' can't take it)
#     after    after commit (`sync after commit`): a worker beside the app runs authz.sync_work() in a loop
# Check 11 first: a fresh database, migrated (the app's SQL migrations, the policy's ones rowstile migrate wrote, and
# Electric's publication; in another mode, then the migration rowstile migrate writes from the lock file to that
# mode's policy, as an app changing its sync lines would), then the policy's tests, then the lock files. Then
# Electric starts on the migrated database, the app is built and started twice (a pool of five connections, and a
# pool of one), and the other checks run.
set -u
cd "$(dirname "$0")"
MODE=${SYNC_MODE:-copied}
case $MODE in copied|keyed|after) ;; *) echo "SYNC_MODE=$MODE: copied, keyed or after"; exit 2 ;; esac
PG=${PG_MAJOR:-16}
NAME=rowstile-conformance-electric
PORT=${CONFORMANCE_PORT:-25570}    # Postgres; then Electric, nginx, PgBouncer and the app, on the next four
ROOT=$(cd ../.. && pwd)
BIN=$ROOT/node_modules/.bin
# Electric's and nginx's images, pinned in images/Dockerfile beside this folder
ELECTRIC_IMAGE=$(sed -n 's/^FROM \([^ ]*\) AS electric$/\1/p' ../images/Dockerfile)
NGINX_IMAGE=$(sed -n 's/^FROM \([^ ]*\) AS nginx$/\1/p' ../images/Dockerfile)
export PYTHON=${PYTHON:-python3}
[ -d "$ROOT/node_modules" ] || (cd "$ROOT" && npm ci --no-audit --no-fund) || exit 1
LOG=$(mktemp -d)
servers=()
cleanup() {
  for p in "${servers[@]}"; do kill "$p" 2>/dev/null; done
  [ -n "${KEEP:-}" ] && return
  [ "${POOLER:-}" = pgbouncer ] && pooler_stop "$NAME"
  docker rm -f -v "$NAME-electric" "$NAME-nginx" "$NAME" >/dev/null 2>&1
  docker network rm "$NAME-net" >/dev/null 2>&1
}
trap cleanup EXIT
docker build -q -t "rowstile:$PG" --build-arg "PG_MAJOR=$PG" -f ../../core/Dockerfile ../.. >/dev/null || exit 1
for image in "$ELECTRIC_IMAGE" "$NGINX_IMAGE"; do
  docker image inspect "$image" >/dev/null 2>&1 || docker pull -q "$image" >/dev/null || exit 1
done
docker rm -f -v "$NAME-electric" "$NAME-nginx" "$NAME" >/dev/null 2>&1
docker network create "$NAME-net" >/dev/null 2>&1
docker run -d --name "$NAME" --network "$NAME-net" --network-alias=pg -e POSTGRES_PASSWORD=postgres -p "$PORT:5432" \
  "rowstile:$PG" -c wal_level=logical >/dev/null || exit 1
for _ in $(seq 60); do docker exec "$NAME" pg_isready -q -U postgres 2>/dev/null && break; sleep 1; done
sleep 2
# the migration role owns the database, not a superuser, as on managed Postgres; Electric's role is made by whoever
# runs the database (a role that may make roles may give neither REPLICATION nor BYPASSRLS without holding them)
docker exec "$NAME" psql -q -U postgres -v ON_ERROR_STOP=1 -c "CREATE ROLE conf_owner LOGIN PASSWORD 'owner' CREATEROLE CREATEDB" \
  -c "ALTER ROLE conf_owner SET createrole_self_grant = 'set, inherit'" \
  -c "CREATE ROLE conf_electric LOGIN PASSWORD 'electric' REPLICATION BYPASSRLS" \
  -c "CREATE DATABASE conf OWNER conf_owner" >/dev/null || exit 1
OWNER_AT="postgresql://conf_owner:owner@localhost:$PORT"
export ROWSTILE_OWNER_DSN="$OWNER_AT/conf"
# whoever runs the database (Electric's role, which the checks break and mend for lint)
export ROWSTILE_ADMIN_DSN="postgresql://postgres:postgres@localhost:$PORT/conf"
APP_PORT=$PORT
if [ "${POOLER:-}" = pgbouncer ]; then          # the app through PgBouncer in transaction mode (../pooler.sh)
  source ../pooler.sh
  APP_PORT=$((PORT + 3))
  pooler_start "$NAME" "$APP_PORT" conf_app:app || exit 1
fi
export ROWSTILE_APP_URL="postgresql://conf_app:app@localhost:$APP_PORT/conf"
rc=0
# The mode's policy: db/policy.authz, or it with its sync lines changed, beside a copy of its lock file, from which
# rowstile migrate writes the mode's migration (the checks apply it by this path: SYNC_POLICY)
migrations=(migrations/*.sql)
POLICY=$PWD/db/policy.authz
if [ "$MODE" != copied ]; then
  POLICY=$LOG/mode/policy.authz
  mkdir -p "$LOG/mode"
  case $MODE in
    keyed) sed -e 's/^sync app\.files : view$/& by folder/' -e 's/^sync app\.folders$/& by folder/' db/policy.authz ;;
    after) cat db/policy.authz && echo "sync after commit" ;;
  esac >"$POLICY"
  [ "$(diff db/policy.authz "$POLICY" | grep -c '^>')" = "$([ "$MODE" = keyed ] && echo 2 || echo 1)" ] ||
    { diff db/policy.authz "$POLICY"; echo "FAIL  the $MODE policy: its sync lines aren't the ones it changes"; exit 1; }
  cp db/policy.lock "$LOG/mode/policy.lock"
  $PYTHON ../../core/cli/rowstile_cli.py migrate "$POLICY" --dir "$LOG/mode/migrations" --name "sync_$MODE" \
    >"$LOG/mode/migrate.log" 2>&1 || { cat "$LOG/mode/migrate.log"; echo "FAIL  rowstile migrate to the $MODE policy"; exit 1; }
  migrations+=("$LOG"/mode/migrations/*.sql)
fi
export SYNC_MODE=$MODE SYNC_POLICY=$POLICY
# 11: the migrations in order, each in a transaction, as a runner of plain SQL files does
for f in "${migrations[@]}"; do
  docker exec -i "$NAME" psql -q -X -U conf_owner -d conf -v ON_ERROR_STOP=1 -1 -f - <"$f" >"$LOG/migrate.log" 2>&1 ||
    { cat "$LOG/migrate.log"; echo "FAIL  11: $f"; exit 1; }
done
$PYTHON ../../core/cli/rowstile_cli.py test >"$LOG/policy-tests.log" 2>&1 &&
  echo "ok    11: a fresh database, migrated, passes the policy's tests ($MODE)" || { cat "$LOG/policy-tests.log"; echo "FAIL  11: policy tests"; rc=1; }
$PYTHON ../../core/cli/rowstile_cli.py migrate --check >/dev/null &&
  echo "ok    11: ... and the policy's lock file is up to date" || { echo "FAIL  rowstile migrate --check"; rc=1; }
if [ "$MODE" != copied ]; then
  $PYTHON ../../core/cli/rowstile_cli.py migrate --check "$POLICY" >/dev/null &&
    echo "ok    11: ... and so is the $MODE policy's, after its migration" || { echo "FAIL  rowstile migrate --check, $MODE"; rc=1; }
fi
# Electric, in manual publication mode: the publication is the app's migration's, and its role owns no table
export ELECTRIC_SECRET=conformance-secret
docker run -d --name "$NAME-electric" --network "$NAME-net" -p "$((PORT + 1)):3000" \
  -e DATABASE_URL="postgresql://conf_electric:electric@pg:5432/conf?sslmode=disable" \
  -e ELECTRIC_MANUAL_TABLE_PUBLISHING=true -e ELECTRIC_SECRET="$ELECTRIC_SECRET" "$ELECTRIC_IMAGE" >/dev/null || exit 1
export ELECTRIC_URL="http://localhost:$((PORT + 1))/v1/shape"
for _ in $(seq 90); do [ "$(curl -s "http://localhost:$((PORT + 1))/v1/health")" = '{"status":"active"}' ] && break; sleep 1; done
[ "$(curl -s "http://localhost:$((PORT + 1))/v1/health")" = '{"status":"active"}' ] ||
  { docker logs "$NAME-electric" 2>&1 | tail -20; echo "FAIL  Electric doesn't start"; exit 1; }
# with source maps: what the checks run of the built files is reported on the SDK's sources (vitest.config.ts)
(cd "$ROOT" && $BIN/tsc -b sdk/typescript --sourceMap) || { echo "FAIL  the SDK doesn't build"; exit 1; }
$PYTHON ../../core/cli/rowstile_cli.py client >/dev/null || exit 1
git diff --quiet -- src/authz.gen.ts src/shapes.gen.ts 2>/dev/null ||
  { echo "FAIL  src/authz.gen.ts or src/shapes.gen.ts is out of date: rowstile client"; rc=1; }
# ... and the shapes are the same in every mode: the filter is the same one join
$PYTHON ../../core/cli/rowstile_cli.py client electric "$POLICY" | diff - src/shapes.gen.ts >"$LOG/shapes.diff" ||
  { cat "$LOG/shapes.diff"; echo "FAIL  the $MODE policy's shapes aren't src/shapes.gen.ts"; rc=1; }
rm -rf build && $BIN/tsc -p . >"$LOG/build.log" 2>&1 || { cat "$LOG/build.log"; echo "FAIL  the app doesn't type-check"; exit 1; }
PG_POOL_MAX=1 PORT=0 node build/src/server.js >"$LOG/server-one.log" 2>&1 & servers+=($!)
# 13: the app refuses to start on a connection that skips row-level security (here, the owner's)
ROWSTILE_APP_URL=$ROWSTILE_OWNER_DSN PORT=0 timeout 60 node build/src/server.js >"$LOG/server-owner.log" 2>&1
if [ $? = 1 ] && grep -q "an owner skips row-level security" "$LOG/server-owner.log"; then
  echo "ok    13: the app refuses to start on the owner's connection"
else cat "$LOG/server-owner.log"; echo "FAIL  13: the app started on the owner's connection"; rc=1; fi
# where each server listens, as it says once it does
listening() { sed -n 's/^listening on \([0-9]*\)$/\1/p' "$1"; }
for _ in $(seq 60); do [ -n "$(listening "$LOG/server-one.log")" ] && break; sleep 1; done
[ -n "$(listening "$LOG/server-one.log")" ] || { cat "$LOG/server-one.log"; echo "FAIL  the app doesn't start"; exit 1; }
export CONFORMANCE_SERVER_ONE="http://localhost:$(listening "$LOG/server-one.log")"
# the app with a pool of five runs inside the checks' own process (tests/shapes.test.ts starts it), so that what they
# run of the SDK in it is measured, on this port
export CONFORMANCE_APP_PORT=$((PORT + 4))
export CONFORMANCE_SERVER="http://localhost:$CONFORMANCE_APP_PORT"
# E10: a cache in front of the app, as a CDN would be (nginx's proxy_cache keeps a copy for each value of the
# headers a response varies on); on the host's network, where the app listens
sed -e "s/@PORT@/$((PORT + 2))/" -e "s/@APP@/$CONFORMANCE_APP_PORT/" nginx.conf >"$LOG/nginx.conf"
chmod 644 "$LOG/nginx.conf" && chmod 755 "$LOG"
docker run -d --name "$NAME-nginx" --network host -v "$LOG/nginx.conf:/etc/nginx/nginx.conf:ro" "$NGINX_IMAGE" >/dev/null || exit 1
export CONFORMANCE_CACHE="http://localhost:$((PORT + 2))"
for _ in $(seq 30); do curl -s -o /dev/null "$CONFORMANCE_CACHE/" && break; sleep 1; done
# What the checks run of Electric's proxy in the SDK, lines, branches and functions: the report is printed, and kept
# in CONFORMANCE_COVERAGE (a folder of its own if not given) with the details of each file
export CONFORMANCE_COVERAGE=${CONFORMANCE_COVERAGE:-$(mktemp -d)}
$BIN/vitest run --coverage "$@" || { rc=1; echo "(logs: $LOG; Electric's: docker logs $NAME-electric, with KEEP=1)"; }
if [ $# -gt 0 ]; then
  echo "(some of the checks ran: the SDK's coverage isn't judged)"
elif node -e 'const t = require(process.argv[1]).total;
  process.exit(["lines", "statements", "branches", "functions"].every((k) => t[k].pct === 100) ? 0 : 1)' \
  "$CONFORMANCE_COVERAGE/coverage-summary.json"; then
  echo "ok    the checks run every line, branch and function of Electric's proxy (@rowstile/client's electricShape)"
else
  echo "FAIL  lines, branches or functions of Electric's proxy no check runs (the report above: $CONFORMANCE_COVERAGE/report.txt)"; rc=1
fi
exit $rc

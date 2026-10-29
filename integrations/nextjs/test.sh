#!/bin/bash
# test.sh: the TypeScript SDK's conformance suite, against a fresh Postgres in Docker.
#   integrations/nextjs/test.sh             # PG_MAJOR=17 or 18 for another version; KEEP=1 keeps the database
#   POOLER=pgbouncer integrations/nextjs/test.sh      # the app through PgBouncer in transaction mode
# (to look at: check 14 migrates it once more, so the tests run again only on a new one, which this script makes)
# Check 11 first: a fresh database, migrated with Prisma Migrate (rowstile's policy is one of the migrations),
# then the policy's tests, then Prisma's own diff, which must show no change. Then the app is built and started
# twice (a pool of five connections, and a pool of one), and the other checks run (Vitest). Beside Postgres: Neon's
# wsproxy, through which Neon's serverless driver reaches it over WebSockets (on Neon, Neon's own proxy does), and
# Redis, for the BullMQ queue (check 10); both preview.
set -u
cd "$(dirname "$0")"
PG=${PG_MAJOR:-16}
NAME=rowstile-conformance-ts
PORT=${CONFORMANCE_PORT:-25441}
WEB=${CONFORMANCE_WEB_PORT:-3401}
WSPORT=$((PORT + 3))                                   # the WebSocket proxy
REDIS_PORT=${CONFORMANCE_REDIS_PORT:-26380}
ROOT=$(cd ../.. && pwd)
BIN=$ROOT/node_modules/.bin
export PYTHON=${PYTHON:-python3}
[ -d "$ROOT/node_modules" ] || (cd "$ROOT" && npm ci --no-audit --no-fund) || exit 1
docker build -q -t "rowstile:$PG" --build-arg "PG_MAJOR=$PG" -f ../../core/Dockerfile ../.. >/dev/null || exit 1
source ../pooler.sh
# the services beside Postgres, a stage each in images/Dockerfile, pinned by digest
WSPROXY_IMAGE=$(sed -n 's/^FROM \([^ ]*\) AS wsproxy$/\1/p' ../images/Dockerfile)
REDIS_IMAGE=$(sed -n 's/^FROM \([^ ]*\) AS redis$/\1/p' ../images/Dockerfile)
servers=()
stop() { for p in "${servers[@]}"; do kill "$p" 2>/dev/null; done; }
# whatever ends the run: the servers, then the containers (the database stays with KEEP=1)
cleanup() {
  stop
  docker rm -f -v "$NAME-wsproxy" "$NAME-redis" >/dev/null 2>&1
  [ -n "${KEEP:-}" ] && return
  [ "${POOLER:-}" = pgbouncer ] && pooler_stop "$NAME"
  docker rm -f -v "$NAME" >/dev/null 2>&1
  docker network rm "$NAME-net" >/dev/null 2>&1
}
trap cleanup EXIT
docker rm -f -v "$NAME" "$NAME-wsproxy" "$NAME-redis" >/dev/null 2>&1
docker run -d --name "$NAME" -e POSTGRES_PASSWORD=postgres -p "$PORT:5432" "rowstile:$PG" >/dev/null || exit 1
for _ in $(seq 60); do docker exec "$NAME" pg_isready -q -U postgres 2>/dev/null && break; sleep 1; done
sleep 2
# the migration role owns the databases: not a superuser, as on managed Postgres (CREATEDB: a test database per worker)
docker exec "$NAME" psql -q -U postgres -c "CREATE ROLE conf_owner LOGIN PASSWORD 'owner' CREATEROLE CREATEDB" \
  -c "ALTER ROLE conf_owner SET createrole_self_grant = 'set, inherit'" -c "CREATE DATABASE conf OWNER conf_owner" \
  -c "CREATE DATABASE conf_tests OWNER conf_owner" >/dev/null || exit 1
export ROWSTILE_OWNER_DSN="postgresql://conf_owner:owner@localhost:$PORT/conf"
export ROWSTILE_TESTS_DSN="postgresql://conf_owner:owner@localhost:$PORT/conf_tests"
APP_PORT=$PORT
if [ "${POOLER:-}" = pgbouncer ]; then          # the app through PgBouncer in transaction mode (../pooler.sh)
  APP_PORT=$((PORT + 2))
  pooler_start "$NAME" "$APP_PORT" conf_app:app || exit 1
fi
export ROWSTILE_APP_URL="postgresql://conf_app:app@localhost:$APP_PORT/conf"
# Neon's serverless driver: the proxy dials the database from the containers' network, straight to Postgres or,
# with POOLER=pgbouncer, through PgBouncer (as Neon's pooled URL does); it lets the driver reach nothing else
NEON_DB=pg:5432
[ "${POOLER:-}" = pgbouncer ] && NEON_DB=$NAME-pgbouncer:6432
docker network create "$NAME-net" >/dev/null 2>&1
docker network connect --alias pg "$NAME-net" "$NAME" 2>/dev/null
for image in "$WSPROXY_IMAGE" "$REDIS_IMAGE"; do
  docker image inspect "$image" >/dev/null 2>&1 || docker pull -q "$image" >/dev/null || exit 1
done
docker run -d --name "$NAME-wsproxy" --network "$NAME-net" -e "ALLOW_ADDR_REGEX=^${NEON_DB//./\\.}\$" -e LOG_CONN_INFO=false \
  -p "$WSPORT:80" "$WSPROXY_IMAGE" >/dev/null || exit 1
docker run -d --name "$NAME-redis" -p "$REDIS_PORT:6379" "$REDIS_IMAGE" >/dev/null || exit 1
for _ in $(seq 30); do
  [ "$(curl -s -o /dev/null -w '%{http_code}' "http://localhost:$WSPORT/v1")" != 000 ] &&
    docker exec "$NAME-redis" redis-cli ping >/dev/null 2>&1 && break
  sleep 1
done
export ROWSTILE_WSPROXY="localhost:$WSPORT" ROWSTILE_NEON_URL="postgresql://conf_app:app@$NEON_DB/conf"
export REDIS_URL="redis://localhost:$REDIS_PORT"
# the change feed LISTENs: its own connection, straight to Postgres (a pooler in transaction mode hears nothing)
export ROWSTILE_FEED_URL="postgresql://conf_app:app@localhost:$PORT/conf"
export CONFORMANCE_SERVER="http://localhost:$WEB" CONFORMANCE_SERVER_ONE="http://localhost:$((WEB + 1))"
export CONFORMANCE_SERVER_EDGE="http://localhost:$((WEB + 3))"   # edge/: the edge runtime's routes (preview)
LOG=$(mktemp -d)
export CONFORMANCE_SERVER_LOG="$LOG/server.log"   # what the first server logs: why a page failed (check 15)
rc=0
$BIN/prisma migrate deploy >"$LOG/migrate.log" 2>&1 || { cat "$LOG/migrate.log"; echo "FAIL  11: prisma migrate deploy"; exit 1; }
$PYTHON ../../core/cli/rowstile_cli.py test >"$LOG/policy-tests.log" 2>&1 &&
  echo "ok    11: a fresh database, migrated, passes the policy's tests" || { cat "$LOG/policy-tests.log"; echo "FAIL  11: policy tests"; rc=1; }
$BIN/prisma migrate diff --from-config-datasource --to-schema prisma/schema.prisma --exit-code >"$LOG/diff.log" 2>&1 &&
  echo "ok    11: ... and Prisma's own diff shows no change" || { cat "$LOG/diff.log"; echo "FAIL  11: prisma migrate diff"; rc=1; }
$PYTHON ../../core/cli/rowstile_cli.py migrate --check >/dev/null &&
  echo "ok    the policy's lock file is up to date" || { echo "FAIL  rowstile migrate --check"; rc=1; }
# 12: the framework's test database, migrated the same way (the tests copy it for each worker)
ROWSTILE_OWNER_DSN=$ROWSTILE_TESTS_DSN $BIN/prisma migrate deploy >"$LOG/migrate-tests.log" 2>&1 || { cat "$LOG/migrate-tests.log"; exit 1; }
# with source maps: what the checks run of the built files is reported on the SDK's sources (vitest.config.ts)
(cd "$ROOT" && $BIN/tsc -b sdk/typescript --sourceMap) || { echo "FAIL  the SDK doesn't build"; exit 1; }
$BIN/prisma generate >/dev/null 2>&1 || { echo "FAIL  prisma generate"; exit 1; }
# the second app's client: Prisma's defaults, no schemas (prisma/plain/schema.prisma), for the SDK's checks
$BIN/prisma generate --schema prisma/plain/schema.prisma >/dev/null 2>&1 || { echo "FAIL  prisma generate (prisma/plain)"; exit 1; }
$PYTHON ../../core/cli/rowstile_cli.py client >/dev/null || exit 1
git diff --quiet -- src/authz.gen.ts 2>/dev/null || { echo "FAIL  src/authz.gen.ts is out of date: rowstile client"; rc=1; }
node ../../node_modules/next/dist/bin/next build >"$LOG/build.log" 2>&1 || { cat "$LOG/build.log"; echo "FAIL  next build"; exit 1; }
# the edge runtime's routes are an app of their own (edge/next.config.ts says why); a build that warns of a Node.js
# API in the SDK fails
node ../../node_modules/next/dist/bin/next build edge >"$LOG/build-edge.log" 2>&1 || { cat "$LOG/build-edge.log"; echo "FAIL  next build edge"; exit 1; }
if grep -q "Node.js API is used" "$LOG/build.log" "$LOG/build-edge.log"; then
  cat "$LOG/build-edge.log"; echo "FAIL  the SDK uses a Node.js API the edge runtime lacks"; rc=1
fi
NEXT="node ../../node_modules/next/dist/bin/next"
$NEXT start -p "$WEB" >"$LOG/server.log" 2>&1 & servers+=($!)
PG_POOL_MAX=1 $NEXT start -p "$((WEB + 1))" >"$LOG/server-one.log" 2>&1 & servers+=($!)
$NEXT start edge -p "$((WEB + 3))" >"$LOG/server-edge.log" 2>&1 & servers+=($!)
# 13: the app refuses to start on a connection that skips row-level security (here, the owner's)
ROWSTILE_APP_URL=$ROWSTILE_OWNER_DSN timeout 60 $NEXT start -p "$((WEB + 2))" >"$LOG/server-owner.log" 2>&1
if [ $? = 1 ] && grep -q "an owner skips row-level security" "$LOG/server-owner.log"; then
  echo "ok    13: the app refuses to start on the owner's connection"
else cat "$LOG/server-owner.log"; echo "FAIL  13: the app started on the owner's connection"; rc=1; fi
for _ in $(seq 60); do curl -sf "$CONFORMANCE_SERVER/api/projects" >/dev/null && curl -sf "$CONFORMANCE_SERVER_ONE/api/projects" >/dev/null &&
  curl -sf "$CONFORMANCE_SERVER_EDGE/api/check" >/dev/null && break; sleep 1; done
# What the checks run of the SDK (sdk/typescript/*/src), lines, branches and functions: the report is printed, and
# kept in CONFORMANCE_COVERAGE (a folder of its own if not given) with the details of each file
export CONFORMANCE_COVERAGE=${CONFORMANCE_COVERAGE:-$(mktemp -d)}
$BIN/vitest run --coverage "$@" || { rc=1; echo "(server logs: $LOG)"; }
if [ $# -gt 0 ]; then
  echo "(some of the checks ran: the SDK's coverage isn't judged)"
elif node -e 'const t = require(process.argv[1]).total;
  process.exit(["lines", "statements", "branches", "functions"].every((k) => t[k].pct === 100) ? 0 : 1)' \
  "$CONFORMANCE_COVERAGE/coverage-summary.json"; then
  echo "ok    the checks run every line, branch and function of the TypeScript SDK"
else
  echo "FAIL  lines, branches or functions of the TypeScript SDK no check runs (the report above: $CONFORMANCE_COVERAGE/report.txt)"; rc=1
fi
exit $rc

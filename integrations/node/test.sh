#!/bin/bash
# test.sh: the conformance suite for a plain Node server (Express 5, node-postgres, Drizzle, postgres.js), with its
# tests on Jest (@rowstile/jest), against a fresh Postgres in Docker.
#   integrations/node/test.sh               # PG_MAJOR=17 or 18 for another version; KEEP=1 keeps the database
#   POOLER=pgbouncer integrations/node/test.sh        # the app through PgBouncer in transaction mode
#   integrations/node/test.sh -t "16"       # some of the checks: what follows is Jest's
# Check 11 first: a fresh database, migrated with Drizzle Kit (rowstile's policy is one of its migrations), then the
# policy's tests, then Drizzle Kit's own diff, which must show no change, and what drizzle-kit push would do to the
# database. Then the app is built and started twice (a pool of five connections, and a pool of one), and the other
# checks run (Jest, two workers, a test database each).
set -u
cd "$(dirname "$0")"
PG=${PG_MAJOR:-16}
NAME=rowstile-conformance-node
PORT=${CONFORMANCE_PORT:-25460}
# the servers' ports: free ones, as the system gives them (CONFORMANCE_WEB_PORT: that one and the next)
WEB=${CONFORMANCE_WEB_PORT:-0}
ROOT=$(cd ../.. && pwd)
BIN=$ROOT/node_modules/.bin
export PYTHON=${PYTHON:-python3}
[ -d "$ROOT/node_modules" ] || (cd "$ROOT" && npm ci --no-audit --no-fund) || exit 1
LOG=$(mktemp -d)
servers=()
cleanup() {
  for p in "${servers[@]}"; do kill "$p" 2>/dev/null; done
  rm -rf .work
  [ -n "${KEEP:-}" ] && return
  [ "${POOLER:-}" = pgbouncer ] && pooler_stop "$NAME"
  docker rm -f -v "$NAME" >/dev/null 2>&1
}
trap cleanup EXIT
docker build -q -t "rowstile:$PG" --build-arg "PG_MAJOR=$PG" -f ../../core/Dockerfile ../.. >/dev/null || exit 1
docker rm -f -v "$NAME" >/dev/null 2>&1
docker run -d --name "$NAME" -e POSTGRES_PASSWORD=postgres -p "$PORT:5432" "rowstile:$PG" >/dev/null || exit 1
for _ in $(seq 60); do docker exec "$NAME" pg_isready -q -U postgres 2>/dev/null && break; sleep 1; done
sleep 2
# the migration role owns the databases: not a superuser, as on managed Postgres (CREATEDB: a test database per worker)
docker exec "$NAME" psql -q -U postgres -c "CREATE ROLE conf_owner LOGIN PASSWORD 'owner' CREATEROLE CREATEDB" \
  -c "ALTER ROLE conf_owner SET createrole_self_grant = 'set, inherit'" -c "CREATE DATABASE conf OWNER conf_owner" \
  -c "CREATE DATABASE conf_tests OWNER conf_owner" >/dev/null || exit 1
OWNER_AT="postgresql://conf_owner:owner@localhost:$PORT"
export ROWSTILE_OWNER_DSN="$OWNER_AT/conf"
export ROWSTILE_TESTS_DSN="$OWNER_AT/conf_tests"
APP_PORT=$PORT
if [ "${POOLER:-}" = pgbouncer ]; then          # the app through PgBouncer in transaction mode (../pooler.sh)
  source ../pooler.sh
  APP_PORT=$((PORT + 2))
  pooler_start "$NAME" "$APP_PORT" conf_app:app || exit 1
fi
export ROWSTILE_APP_URL="postgresql://conf_app:app@localhost:$APP_PORT/conf"
rc=0
KIT="$BIN/drizzle-kit"
$KIT migrate >"$LOG/migrate.log" 2>&1 || { cat "$LOG/migrate.log"; echo "FAIL  11: drizzle-kit migrate"; exit 1; }
$PYTHON ../../core/cli/rowstile_cli.py test >"$LOG/policy-tests.log" 2>&1 &&
  echo "ok    11: a fresh database, migrated, passes the policy's tests" || { cat "$LOG/policy-tests.log"; echo "FAIL  11: policy tests"; rc=1; }
# Drizzle Kit's own diff: src/schema.ts against the migrations' snapshots (rowstile's copy the one before), in a copy
# of the folder, where a migration it would write lands
mkdir -p .work/diff && cp -r drizzle drizzle.config.ts .work/diff/ && mkdir .work/diff/src && cp src/schema.ts .work/diff/src/
(cd .work/diff && $KIT generate) >"$LOG/diff.log" 2>&1
if grep -q "No schema changes, nothing to migrate" "$LOG/diff.log" && diff -r drizzle .work/diff/drizzle >/dev/null; then
  echo "ok    11: ... and Drizzle Kit's own diff shows no change"
else cat "$LOG/diff.log"; echo "FAIL  11: drizzle-kit generate would write a migration"; rc=1; fi
# ... and the database against src/schema.ts, as drizzle-kit push compares them (on a copy: push may change it).
# Drizzle Kit models row-level security, and the schema declares none: push would turn rowstile's off (the stack
# page says never to push), and must find nothing else to change
docker exec "$NAME" psql -q -U conf_owner -d postgres -c "CREATE DATABASE conf_push TEMPLATE conf" >/dev/null || exit 1
ROWSTILE_OWNER_DSN="$OWNER_AT/conf_push" timeout 120 $KIT push --verbose --strict </dev/null >"$LOG/push.log" 2>&1
docker exec "$NAME" psql -q -U conf_owner -d postgres -c "DROP DATABASE conf_push" >/dev/null
statements=$(grep -E ';$' "$LOG/push.log")
others=$(grep -v -E '^(ALTER TABLE "app"\."[a-z_]+" DISABLE ROW LEVEL SECURITY|DROP POLICY "authz_[a-z_]+" ON "app"\."[a-z_]+" CASCADE);$' <<<"$statements")
if grep -q "Pulling schema from database" "$LOG/push.log" && [ -n "$statements" ] && [ -z "$others" ]; then
  echo "ok    11: ... and drizzle-kit push would change nothing but rowstile's row-level security, which it would turn off"
else cat "$LOG/push.log"; echo "FAIL  11: drizzle-kit push would change the database's tables"; rc=1; fi
rm -rf .work/diff
$PYTHON ../../core/cli/rowstile_cli.py migrate --check >/dev/null &&
  echo "ok    the policy's lock file is up to date" || { echo "FAIL  rowstile migrate --check"; rc=1; }
# 12: the framework's test database, migrated the same way (the tests copy it for each Jest worker)
ROWSTILE_OWNER_DSN=$ROWSTILE_TESTS_DSN $KIT migrate >"$LOG/migrate-tests.log" 2>&1 || { cat "$LOG/migrate-tests.log"; exit 1; }
# with source maps: what the checks run of the built files is reported on the SDK's sources (jest.config.js)
(cd "$ROOT" && $BIN/tsc -b sdk/typescript --sourceMap) || { echo "FAIL  the SDK doesn't build"; exit 1; }
$PYTHON ../../core/cli/rowstile_cli.py client >/dev/null || exit 1
git diff --quiet -- src/authz.gen.ts 2>/dev/null || { echo "FAIL  src/authz.gen.ts is out of date: rowstile client"; rc=1; }
rm -rf build && $BIN/tsc -p . >"$LOG/build.log" 2>&1 || { cat "$LOG/build.log"; echo "FAIL  the app doesn't type-check"; exit 1; }
PORT=$WEB node build/src/server.js >"$LOG/server.log" 2>&1 & servers+=($!)
PG_POOL_MAX=1 PORT=$((WEB ? WEB + 1 : 0)) node build/src/server.js >"$LOG/server-one.log" 2>&1 & servers+=($!)
# 13: the app refuses to start on a connection that skips row-level security (here, the owner's)
ROWSTILE_APP_URL=$ROWSTILE_OWNER_DSN PORT=0 timeout 60 node build/src/server.js >"$LOG/server-owner.log" 2>&1
if [ $? = 1 ] && grep -q "an owner skips row-level security" "$LOG/server-owner.log"; then
  echo "ok    13: the app refuses to start on the owner's connection"
else cat "$LOG/server-owner.log"; echo "FAIL  13: the app started on the owner's connection"; rc=1; fi
# where each server listens, as it says once it does
listening() { sed -n 's/^listening on \([0-9]*\)$/\1/p' "$1"; }
for _ in $(seq 60); do [ -n "$(listening "$LOG/server.log")" ] && [ -n "$(listening "$LOG/server-one.log")" ] && break; sleep 1; done
[ -n "$(listening "$LOG/server.log")" ] && [ -n "$(listening "$LOG/server-one.log")" ] ||
  { cat "$LOG/server.log" "$LOG/server-one.log"; echo "FAIL  the app doesn't start"; exit 1; }
export CONFORMANCE_SERVER="http://localhost:$(listening "$LOG/server.log")"
export CONFORMANCE_SERVER_ONE="http://localhost:$(listening "$LOG/server-one.log")"
# @rowstile/jest as npm installs it: packed, with the packages it depends on, in a folder of its own, and loaded
pack=$(mktemp -d)
for p in client vitest jest; do (cd "$ROOT/sdk/typescript/$p" && npm pack --silent --pack-destination "$pack" >/dev/null) || exit 1; done
(cd "$pack" && echo '{"private": true}' >package.json && npm install --no-audit --no-fund --legacy-peer-deps ./*.tgz >/dev/null 2>&1 &&
  node --input-type=module -e 'const j = await import("@rowstile/jest");
    process.exit(typeof j.matchers.toBeRefused === "function" && typeof j.databasePerWorker === "function" ? 0 : 1)') &&
  echo "ok    @rowstile/jest installs from its packed files, and loads" || { echo "FAIL  @rowstile/jest from its packed files"; rc=1; }
rm -rf "$pack"
# What the checks run of the SDK's packages (their sources), lines, branches and functions: the report is printed,
# and kept in CONFORMANCE_COVERAGE (a folder of its own if not given) with the details of each file
export CONFORMANCE_COVERAGE=${CONFORMANCE_COVERAGE:-$(mktemp -d)}
NODE_OPTIONS="--experimental-vm-modules --no-warnings=ExperimentalWarning" node "$ROOT/node_modules/jest/bin/jest.js" --coverage "$@" ||
  { rc=1; echo "(server logs: $LOG)"; }
# 12: the checks ran on two Jest workers, each in a copy of the test database of its own
workers=$(docker exec "$NAME" psql -tA -U postgres -c "SELECT count(*) FROM pg_database WHERE datname ~ '^conf_tests_w[0-9]+$'")
if [ $# -gt 0 ]; then :
elif [ "$workers" -ge 2 ]; then echo "ok    12: each Jest worker had a test database of its own ($workers)"
else echo "FAIL  12: the workers' test databases: $workers"; rc=1; fi
if [ $# -gt 0 ]; then
  echo "(some of the checks ran: the SDK's coverage isn't judged)"
elif node -e 'const s = require(process.argv[1]);
  const all = (f) => ["lines", "statements", "branches", "functions"].every((k) => s[f][k].pct === 100);
  const judged = Object.keys(s).filter((f) => /sdk\/typescript\/(jest\/src\/|vitest\/src\/core)/.test(f));
  process.exit(judged.length === 2 && judged.every(all) ? 0 : 1)' "$CONFORMANCE_COVERAGE/coverage-summary.json"; then
  echo "ok    the checks run every line, branch and function of @rowstile/jest (and the core it shares with /vitest)"
else
  echo "FAIL  lines, branches or functions of @rowstile/jest no check runs (the report above: $CONFORMANCE_COVERAGE/report.txt)"; rc=1
fi
exit $rc

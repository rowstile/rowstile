#!/bin/bash
# test.sh: the helpdesk's checks, from an empty database in Docker.
#   examples/helpdesk/test.sh          # PG_MAJOR=17 or 18 for another version; KEEP=1 keeps the database
# The database is migrated with Prisma Migrate, rowstile's policy among the migrations; then the policy's tests and
# its invariants in many small worlds (rowstile prove), Prisma's own diff (no change), the lock file, and the
# public-surface check.
set -u
cd "$(dirname "$0")"
PG=${PG_MAJOR:-16}
NAME=rowstile-example-helpdesk
PORT=${HELPDESK_DB_PORT:-25434}
ROOT=$(cd ../.. && pwd)
BIN=$ROOT/node_modules/.bin
PYTHON=${PYTHON:-python3}
ROWSTILE="$PYTHON $ROOT/core/cli/rowstile_cli.py"
# the workspace's packages, installed again when the lock file is newer than the install (a pull that changed it)
[ "$ROOT/node_modules/.package-lock.json" -nt "$ROOT/package-lock.json" ] || (cd "$ROOT" && npm ci --no-audit --no-fund) || exit 1
docker build -q -t "rowstile:$PG" --build-arg "PG_MAJOR=$PG" -f ../../core/Dockerfile ../.. >/dev/null || exit 1
cleanup() {
  docker rm -f -v "$NAME-electric" >/dev/null 2>&1
  [ -n "${KEEP:-}" ] && return
  docker rm -f -v "$NAME" >/dev/null 2>&1
  docker network rm "$NAME-net" >/dev/null 2>&1
}
trap cleanup EXIT
docker rm -f -v "$NAME-electric" "$NAME" >/dev/null 2>&1
ELECTRIC_IMAGE=$(sed -n 's/^FROM \([^ ]*\) AS electric$/\1/p' ../../integrations/images/Dockerfile)
docker image inspect "$ELECTRIC_IMAGE" >/dev/null 2>&1 || docker pull -q "$ELECTRIC_IMAGE" >/dev/null || exit 1
docker network create "$NAME-net" >/dev/null 2>&1
docker run -d --name "$NAME" --network "$NAME-net" --network-alias=pg -e POSTGRES_PASSWORD=postgres -p "$PORT:5432" \
  "rowstile:$PG" -c wal_level=logical >/dev/null || exit 1
for _ in $(seq 60); do docker exec "$NAME" pg_isready -q -h 127.0.0.1 -U postgres 2>/dev/null && break; sleep 1; done
# the tables' owner migrates: not a superuser, as on managed Postgres; Electric's role is the administrator's
docker exec -i "$NAME" psql -q -U postgres -v ON_ERROR_STOP=1 >/dev/null <<'EOF' || exit 1
CREATE ROLE hd_owner LOGIN PASSWORD 'hd_owner' CREATEROLE;
ALTER ROLE hd_owner SET createrole_self_grant = 'set, inherit';
CREATE DATABASE helpdesk OWNER hd_owner;
EOF
docker exec -i "$NAME" psql -q -U postgres -d helpdesk -v ON_ERROR_STOP=1 < db/electric.sql >/dev/null || exit 1
export DATABASE_URL="postgresql://hd_owner:hd_owner@localhost:$PORT/helpdesk"
LOG=$(mktemp -d)
rc=0
ok() { echo "ok    $1"; }
bad() { echo "FAIL  $1"; rc=1; }
$BIN/prisma migrate deploy >"$LOG/migrate.log" 2>&1 || { cat "$LOG/migrate.log"; echo "FAIL  prisma migrate deploy"; exit 1; }
ok "an empty database, migrated with Prisma Migrate"
if $ROWSTILE test >"$LOG/tests.log" 2>&1; then ok "the policy's tests pass ($(grep -o '[0-9]* checks' "$LOG/tests.log"))"
else cat "$LOG/tests.log"; bad "the policy's tests"; fi
if $ROWSTILE prove >"$LOG/prove.log" 2>&1 && ! grep -q "^  no " "$LOG/prove.log"; then
  ok "rowstile prove: the $(grep -c '^line ' "$LOG/prove.log") invariants hold in every world it tries"
else cat "$LOG/prove.log"; bad "rowstile prove"; fi
$BIN/prisma migrate diff --from-config-datasource --to-schema prisma/schema.prisma --exit-code >"$LOG/diff.log" 2>&1 &&
  ok "Prisma's own diff shows no change" || { cat "$LOG/diff.log"; bad "prisma migrate diff"; }
$ROWSTILE migrate --check >"$LOG/check.log" 2>&1 && ok "the policy's lock file is up to date" || { cat "$LOG/check.log"; bad "rowstile migrate --check"; }
lint=$(docker exec "$NAME" psql -qXAt -U postgres -d helpdesk -c "SELECT count(*) FROM authz.lint() WHERE severity <> 'info'")
[ "$lint" = 0 ] && ok "authz.lint() finds nothing but notes" ||
  { docker exec "$NAME" psql -qX -U postgres -d helpdesk -c "SELECT * FROM authz.lint() WHERE severity <> 'info'"; bad "authz.lint()"; }
$PYTHON check_public_surface.py && ok "only rowstile's public surface" || bad "the public surface"

# the app: the demo's data, the clients (Prisma's, and rowstile's, which must match the policy), a build, the server
docker exec -i "$NAME" psql -q -U hd_owner -d helpdesk -v ON_ERROR_STOP=1 < db/seed.sql >/dev/null || { echo "FAIL  db/seed.sql"; exit 1; }
(cd "$ROOT" && $BIN/tsc -b sdk/typescript) || { echo "FAIL  the SDK doesn't build"; exit 1; }
$BIN/prisma generate >/dev/null 2>&1 || { echo "FAIL  prisma generate"; exit 1; }
# (compared with the files as they were, in a git checkout or not)
cp src/authz_client.ts src/shapes.gen.ts "$LOG/"
$ROWSTILE client >/dev/null || exit 1
cmp -s src/authz_client.ts "$LOG/authz_client.ts" && cmp -s src/shapes.gen.ts "$LOG/shapes.gen.ts" &&
  ok "the clients (src/authz_client.ts, src/shapes.gen.ts) are the policy's" ||
  bad "src/authz_client.ts or src/shapes.gen.ts is out of date: rowstile client"
export HD_APP_URL="postgresql://hd_app:hd_app@localhost:$PORT/helpdesk"
export HD_SESSION_SECRET=${HD_SESSION_SECRET:-test-only-secret-of-thirty-two-characters}
WEB=${HELPDESK_WEB_PORT:-8002}
export HELPDESK_SERVER="http://localhost:$WEB"
# Electric, in manual publication mode (the publication is a migration), as its own role
export ELECTRIC_SECRET=${ELECTRIC_SECRET:-test-only-electric-secret}
docker run -d --name "$NAME-electric" --network "$NAME-net" -p "$((PORT + 1)):3000" \
  -e DATABASE_URL="postgresql://hd_electric:hd_electric@pg:5432/helpdesk?sslmode=disable" \
  -e ELECTRIC_MANUAL_TABLE_PUBLISHING=true -e ELECTRIC_SECRET="$ELECTRIC_SECRET" "$ELECTRIC_IMAGE" >/dev/null || exit 1
export ELECTRIC_URL="http://localhost:$((PORT + 1))/v1/shape"
for _ in $(seq 90); do [ "$(curl -s "http://localhost:$((PORT + 1))/v1/health")" = '{"status":"active"}' ] && break; sleep 1; done
[ "$(curl -s "http://localhost:$((PORT + 1))/v1/health")" = '{"status":"active"}' ] && ok "Electric is up, as hd_electric" ||
  { docker logs "$NAME-electric" 2>&1 | tail -20; echo "FAIL  Electric doesn't start"; exit 1; }
NEXT="node $ROOT/node_modules/next/dist/bin/next"
$NEXT build >"$LOG/build.log" 2>&1 || { cat "$LOG/build.log"; echo "FAIL  next build"; exit 1; }
ok "next build"
# the server refuses to start on a connection that skips row-level security (here, the tables' owner's)
HD_APP_URL=$DATABASE_URL timeout 60 $NEXT start -p "$((WEB + 1))" >"$LOG/server-owner.log" 2>&1
if [ $? = 1 ] && grep -q "an owner skips row-level security" "$LOG/server-owner.log"; then ok "the app refuses to start on the owner's connection"
else cat "$LOG/server-owner.log"; bad "the app started on the owner's connection"; fi
$NEXT start -p "$WEB" >"$LOG/server.log" 2>&1 &
server=$!
# the sync index's clock (jobs/sync-tick.ts), as the tables' owner: every second here, so that a break glass that
# ends leaves the live shapes while the tests wait
HD_TICK_SECONDS=1 node jobs/sync-tick.ts >"$LOG/tick.log" 2>&1 &
ticker=$!
trap 'kill $server $ticker 2>/dev/null; cleanup' EXIT
for _ in $(seq 60); do curl -sf -o /dev/null "$HELPDESK_SERVER/" && break; sleep 1; done
$BIN/vitest run || { rc=1; echo "(the server's log: $LOG/server.log; the sync tick's: $LOG/tick.log)"; }
exit $rc

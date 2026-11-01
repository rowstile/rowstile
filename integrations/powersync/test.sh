#!/bin/bash
# test.sh: the conformance suite for PowerSync (a preview), the sync engine: Postgres (wal_level logical), the PowerSync
# service on a role of its own (no superuser) with its bucket storage in a database of its own, the publication
# powersync (the policy's mirrors and the keys), the streams rowstile client powersync writes, a small Express app that
# gives the clients their tokens (HS256, the key the service checks) and takes their writes, and the checks on Vitest
# with PowerSync's own client, in Node (@powersync/node on better-sqlite3).
#   integrations/powersync/test.sh            # PG_MAJOR=17 or 18 for another version; KEEP=1 keeps the containers
#   POOLER=pgbouncer integrations/powersync/test.sh   # the app through PgBouncer in transaction mode (the service direct)
#   integrations/powersync/test.sh -t "P2"    # some of the checks: what follows is Vitest's
#   SYNC_MODE=after integrations/powersync/test.sh    # the whole suite in another of the index's modes:
#     copied   the default: each file's readers copied in from every folder above it, in the writer's transaction
#     after    after commit (`sync after commit`): a worker beside the app runs authz.sync_work() in a loop
#   (a mirrored line can't be keyed by folder: AZ811)
# Check 11 first: a fresh database, migrated (the app's SQL migrations, the policy's, and the publication; after commit,
# then the migration rowstile migrate writes from the lock file to that mode's policy), then the policy's tests, then the
# lock files, and the clients rowstile client writes. Then the app and the service start, and the other checks run.
set -u
cd "$(dirname "$0")"
MODE=${SYNC_MODE:-copied}
case $MODE in copied|after) ;; *) echo "SYNC_MODE=$MODE: copied or after"; exit 2 ;; esac
PG=${PG_MAJOR:-16}
NAME=rowstile-conformance-powersync
PORT=${CONFORMANCE_PORT:-25590}    # Postgres; then the service, PgBouncer and the app, on the next three
ROOT=$(cd ../.. && pwd)
BIN=$ROOT/node_modules/.bin
# the service's image, pinned in images/Dockerfile beside this folder
SERVICE_IMAGE=$(sed -n 's/^FROM \([^ ]*\) AS powersync$/\1/p' ../images/Dockerfile)
export PYTHON=${PYTHON:-python3}
[ -d "$ROOT/node_modules" ] || (cd "$ROOT" && npm ci --no-audit --no-fund) || exit 1
LOG=$(mktemp -d)
servers=()
cleanup() {
  for p in "${servers[@]}"; do kill "$p" 2>/dev/null; done
  [ -n "${KEEP:-}" ] && return
  [ "${POOLER:-}" = pgbouncer ] && pooler_stop "$NAME"
  docker rm -f -v "$NAME-service" "$NAME" >/dev/null 2>&1
  docker network rm "$NAME-net" >/dev/null 2>&1
  rm -rf "$LOG"
}
trap cleanup EXIT
docker build -q -t "rowstile:$PG" --build-arg "PG_MAJOR=$PG" -f ../../core/Dockerfile ../.. >/dev/null || exit 1
docker image inspect "$SERVICE_IMAGE" >/dev/null 2>&1 || docker pull -q "$SERVICE_IMAGE" >/dev/null || exit 1
docker rm -f -v "$NAME-service" "$NAME" >/dev/null 2>&1
docker network create "$NAME-net" >/dev/null 2>&1
docker run -d --name "$NAME" --network "$NAME-net" --network-alias=pg -e POSTGRES_PASSWORD=postgres -p "$PORT:5432" \
  "rowstile:$PG" -c wal_level=logical >/dev/null || exit 1
for _ in $(seq 60); do docker exec "$NAME" pg_isready -q -U postgres 2>/dev/null && break; sleep 1; done
sleep 2
# the migration role owns the database, not a superuser, as on managed Postgres; PowerSync's role is made by whoever
# runs the database (a role that may make roles may give neither REPLICATION nor BYPASSRLS without holding them), and
# so is its bucket storage's database, which it owns
docker exec "$NAME" psql -q -U postgres -v ON_ERROR_STOP=1 -c "CREATE ROLE conf_owner LOGIN PASSWORD 'owner' CREATEROLE CREATEDB" \
  -c "ALTER ROLE conf_owner SET createrole_self_grant = 'set, inherit'" \
  -c "CREATE ROLE conf_ps LOGIN PASSWORD 'ps' REPLICATION BYPASSRLS" \
  -c "CREATE DATABASE conf OWNER conf_owner" -c "CREATE DATABASE conf_ps_storage OWNER conf_ps" >/dev/null || exit 1
OWNER_AT="postgresql://conf_owner:owner@localhost:$PORT"
export ROWSTILE_OWNER_DSN="$OWNER_AT/conf"
# whoever runs the database (PowerSync's role, which the checks break and mend for lint)
export ROWSTILE_ADMIN_DSN="postgresql://postgres:postgres@localhost:$PORT/conf"
APP_PORT=$PORT
if [ "${POOLER:-}" = pgbouncer ]; then          # the app through PgBouncer in transaction mode (../pooler.sh)
  source ../pooler.sh
  APP_PORT=$((PORT + 2))
  pooler_start "$NAME" "$APP_PORT" conf_app:app || exit 1
fi
export ROWSTILE_APP_URL="postgresql://conf_app:app@localhost:$APP_PORT/conf"
rc=0
# The mode's policy: db/policy.authz, or it with `sync after commit`, beside a copy of its lock file, from which
# rowstile migrate writes the mode's migration (the checks apply it by this path: SYNC_POLICY)
migrations=(migrations/*.sql)
POLICY=$PWD/db/policy.authz
if [ "$MODE" = after ]; then
  POLICY=$LOG/mode/policy.authz
  mkdir -p "$LOG/mode"
  { cat db/policy.authz && echo "sync after commit"; } >"$POLICY"
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
# the clients rowstile.toml names, written from the migrated database (the streams list each mirror's columns, which
# the database has): the committed ones are current
(cd "$ROOT" && $BIN/tsc -b sdk/typescript) || { echo "FAIL  the SDK doesn't build"; exit 1; }
$PYTHON ../../core/cli/rowstile_cli.py client >"$LOG/client.log" 2>&1 || { cat "$LOG/client.log"; exit 1; }
git diff --quiet -- src/authz.gen.ts powersync/sync-config.yaml 2>/dev/null &&
  echo "ok    rowstile client writes the streams of the mirrored tables, as committed" ||
  { git diff -- src/authz.gen.ts powersync/sync-config.yaml | head -30; echo "FAIL  src/authz.gen.ts or powersync/sync-config.yaml is out of date: rowstile client"; rc=1; }
rm -rf build && $BIN/tsc -p . >"$LOG/build.log" 2>&1 || { cat "$LOG/build.log"; echo "FAIL  the app doesn't type-check"; exit 1; }
# 13: the app refuses to start on a connection that skips row-level security (here, the owner's)
ROWSTILE_APP_URL=$ROWSTILE_OWNER_DSN PORT=0 timeout 60 node build/src/server.js >"$LOG/server-owner.log" 2>&1
if [ $? = 1 ] && grep -q "an owner skips row-level security" "$LOG/server-owner.log"; then
  echo "ok    13: the app refuses to start on the owner's connection"
else cat "$LOG/server-owner.log"; echo "FAIL  13: the app started on the owner's connection"; rc=1; fi
# the key the app signs tokens with and the service checks them with (HS256): one for each run
export POWERSYNC_TOKEN_SECRET=$(head -c 32 /dev/urandom | base64 | tr -d '\n')
K=$(printf '%s' "$POWERSYNC_TOKEN_SECRET" | base64 -w0 | tr '+/' '-_' | tr -d '=')
APP=$((PORT + 3))
PORT=$APP node build/src/server.js >"$LOG/server.log" 2>&1 & servers+=($!)
for _ in $(seq 60); do grep -q "^listening on $APP$" "$LOG/server.log" && break; sleep 1; done
grep -q "^listening on $APP$" "$LOG/server.log" || { cat "$LOG/server.log"; echo "FAIL  the app doesn't start"; exit 1; }
export CONFORMANCE_SERVER="http://localhost:$APP"
# the service: its role, the publication powersync, its storage, the streams, and the app's key
mkdir -p "$LOG/config"
cp powersync/sync-config.yaml "$LOG/config/sync-config.yaml"
cat >"$LOG/config/service.yaml" <<EOF
replication:
  connections:
    - type: postgresql
      uri: postgresql://conf_ps:ps@pg:5432/conf
      sslmode: disable
storage:
  type: postgresql
  uri: postgresql://conf_ps:ps@pg:5432/conf_ps_storage
  sslmode: disable
port: 8080
sync_config:
  path: sync-config.yaml
client_auth:
  jwks:
    keys:
      - kty: oct
        alg: HS256
        kid: rowstile-conformance
        k: $K
  audience: ['powersync']
telemetry:
  disable_telemetry_sharing: true
system:
  logging:
    level: info
    format: text
EOF
chmod 755 "$LOG" "$LOG/config" && chmod 644 "$LOG"/config/*
docker run -d --name "$NAME-service" --network "$NAME-net" -p "$((PORT + 1)):8080" -v "$LOG/config:/config:ro" \
  -e POWERSYNC_CONFIG_PATH=/config/service.yaml "$SERVICE_IMAGE" start -r unified >/dev/null || exit 1
export POWERSYNC_URL="http://localhost:$((PORT + 1))"
for _ in $(seq 120); do [ "$(curl -s -o /dev/null -w '%{http_code}' "$POWERSYNC_URL/probes/liveness")" = 200 ] && break; sleep 1; done
[ "$(curl -s -o /dev/null -w '%{http_code}' "$POWERSYNC_URL/probes/liveness")" = 200 ] ||
  { docker logs "$NAME-service" 2>&1 | tail -20; echo "FAIL  the PowerSync service doesn't start"; exit 1; }
$BIN/vitest run "$@" || { rc=1; echo "(the service's logs: docker logs $NAME-service, with KEEP=1)"; }
exit $rc

#!/bin/bash
# test.sh: the Elixir SDK's conformance suite (a preview: Phoenix on Bandit, Ecto on Postgrex), against a fresh
# Postgres in Docker.
#   integrations/phoenix/test.sh            # PG_MAJOR=17 or 18 for another version; KEEP=1 keeps the database
#   POOLER=pgbouncer integrations/phoenix/test.sh     # the app through PgBouncer in transaction mode
#   integrations/phoenix/test.sh test/conformance_test.exs   # some of the checks (mix test's arguments)
# Elixir runs in a container (elixir.Dockerfile, on the Elixir image ../images/Dockerfile pins), on the host's
# network, as the caller, Hex's packages and the builds outside the checkout (ROWSTILE_PHOENIX_CACHE,
# ~/.cache/rowstile/phoenix by default).
# First the SDK: its package built and unpacked, the app compiled on it, and what Elixir checks of the SDK and the
# app (mix format, the compiler's warnings, Credo --strict, Dialyzer). Then check 11: a fresh database, migrated by
# Ecto (rowstile's policy is one of the migrations), the policy's tests, and Ecto's own status, which must show
# nothing left to run. Then the server's half of check 13, and the other checks: mix test in two partitions side
# by side, each on its own copy of the migrated test database (check 12), measuring what they run of the SDK.
set -u
cd "$(dirname "$0")"
PG=${PG_MAJOR:-16}
NAME=rowstile-conformance-phoenix
PORT=${CONFORMANCE_PORT:-25550}
WEB=${CONFORMANCE_WEB_PORT:-$((PORT + 3))}
ROOT=$(cd ../.. && pwd)
HERE=$PWD
ELIXIR_IMAGE=$(sed -n 's/^FROM \([^ ]*\) AS elixir$/\1/p' ../images/Dockerfile)
IMAGE=rowstile-phoenix
CACHE=${ROWSTILE_PHOENIX_CACHE:-$HOME/.cache/rowstile/phoenix}
LOG=$(mktemp -d)
server=
cleanup() {
  [ -n "$server" ] && kill "$server" 2>/dev/null
  rm -rf "$LOG"
  [ -n "${KEEP:-}" ] && return
  [ "${POOLER:-}" = pgbouncer ] && pooler_stop "$NAME"
  docker rm -f -v "$NAME" >/dev/null 2>&1
}
# the containers the suite runs in the background, by name: a docker client stopped can leave its container running
cleanup_runs() { docker rm -f "$NAME-server" "$NAME-test-1" "$NAME-test-2" >/dev/null 2>&1; }
trap 'cleanup_runs; cleanup' EXIT
docker build -q -t "rowstile:$PG" --build-arg "PG_MAJOR=$PG" -f ../../core/Dockerfile ../.. >/dev/null || exit 1
docker build -q -t "$IMAGE" --build-arg "ELIXIR_IMAGE=$ELIXIR_IMAGE" -f elixir.Dockerfile . >/dev/null || exit 1
# What the checks run of the SDK (test/support/cover.ex): each partition's, kept in CONFORMANCE_COVERAGE (a folder of
# its own if not given), where the report is kept
export CONFORMANCE_COVERAGE=${CONFORMANCE_COVERAGE:-$LOG/coverage}
mkdir -p "$CACHE" "$CONFORMANCE_COVERAGE" && find "$CONFORMANCE_COVERAGE" -mindepth 1 -delete
# Elixir, in a folder of the repository, with the suite's environment (its databases, and what a step sets); the
# Mix and Hex homes, the packages and the builds in the cache, a build for each folder and environment; RUN_NAME
# names its container
elixir_run() {
  local dir=$1 passed=() named=() name; shift
  [ -n "${RUN_NAME:-}" ] && named=(--name "$RUN_NAME")
  for name in $(compgen -e | grep -E '^(ROWSTILE_[A-Z_]+|CONFORMANCE_[A-Z_]+|DATABASE_URL|PORT|MIX_ENV|MIX_TEST_PARTITION)$'); do
    passed+=(-e "$name")
  done
  docker run --rm "${named[@]}" --network host --user "$(id -u):$(id -g)" -e HOME=/tmp -e MIX_HOME="$CACHE/mix" \
    -e HEX_HOME="$CACHE/hex" -e MIX_DEPS_PATH="$CACHE/deps/$(basename "$dir")" \
    -e MIX_BUILD_ROOT="$CACHE/build/$(basename "$dir")" -e ROWSTILE_CLI="$ROOT/core/cli/rowstile_cli.py" \
    -e PYTHONDONTWRITEBYTECODE=1 -e ERL_AFLAGS="+S 4" "${passed[@]}" \
    -v "$ROOT:$ROOT" -v "$CACHE:$CACHE" -v "$LOG:$LOG" -v "$CONFORMANCE_COVERAGE:$CONFORMANCE_COVERAGE" \
    -w "$dir" "$IMAGE" "$@"
}
SDK=$ROOT/sdk/elixir
elixir_run "$SDK" sh -c 'mix local.hex --force --if-missing && mix local.rebar --force --if-missing && mix deps.get' \
  >"$LOG/deps.log" 2>&1 || { cat "$LOG/deps.log"; echo "FAIL  mix deps.get (sdk/elixir)"; exit 1; }
# the SDK, as Hex would publish it: its package built and unpacked, its version the repository's, and the app
# compiled on it, with the compiler's warnings as errors
VERSION=$(sed -n 's/^  @version "\(.*\)"$/\1/p' "$SDK/mix.exs")
export ROWSTILE_SDK=$LOG/rowstile-$VERSION
elixir_run "$SDK" sh -c "mix hex.build --unpack -o $ROWSTILE_SDK" >"$LOG/build.log" 2>&1 &&
  [ -f "$ROWSTILE_SDK/lib/rowstile.ex" ] && grep -q "@version \"$VERSION\"" "$ROWSTILE_SDK/mix.exs" &&
  elixir_run "$HERE" sh -c 'mix deps.get && MIX_ENV=test mix compile --warnings-as-errors --force' >>"$LOG/build.log" 2>&1 &&
  echo "ok    the SDK's package builds, unpacks, and the app compiles on it (rowstile $VERSION)" ||
  { cat "$LOG/build.log"; echo "FAIL  the SDK's package doesn't build, or the app doesn't compile on it"; exit 1; }
# what Elixir checks: the layout (mix format), the compiler's warnings (its types too), Credo --strict and Dialyzer,
# in the SDK and the app (the generated names and migrations too)
for dir in "$SDK" "$HERE"; do
  elixir_run "$dir" sh -c 'mix format --check-formatted && MIX_ENV=test mix compile --warnings-as-errors &&
    MIX_ENV=test mix credo --strict && MIX_ENV=test mix dialyzer --format short' >"$LOG/lint.log" 2>&1 ||
    { cat "$LOG/lint.log"; echo "FAIL  mix format, the compiler, Credo or Dialyzer: ${dir#"$ROOT"/}"; exit 1; }
done
echo "ok    mix format, the compiler's warnings, Credo --strict and Dialyzer find nothing in the SDK and the app"
docker rm -f -v "$NAME" >/dev/null 2>&1
docker run -d --name "$NAME" -e POSTGRES_PASSWORD=postgres -p "$PORT:5432" "rowstile:$PG" >/dev/null || exit 1
for _ in $(seq 60); do docker exec "$NAME" pg_isready -q -U postgres 2>/dev/null && break; sleep 1; done
sleep 2
# the migration role owns the databases: not a superuser, as on managed Postgres (CREATEDB: a test database per
# partition)
docker exec "$NAME" psql -q -U postgres -c "CREATE ROLE conf_owner LOGIN PASSWORD 'owner' CREATEROLE CREATEDB" \
  -c "ALTER ROLE conf_owner SET createrole_self_grant = 'set, inherit'" -c "CREATE DATABASE conf OWNER conf_owner" \
  -c "CREATE DATABASE conf_tests OWNER conf_owner" >/dev/null || exit 1
export ROWSTILE_OWNER_URL="postgres://conf_owner:owner@localhost:$PORT/conf"
export ROWSTILE_TESTS_URL="postgres://conf_owner:owner@localhost:$PORT/conf_tests"
APP_PORT=$PORT
if [ "${POOLER:-}" = pgbouncer ]; then          # the app through PgBouncer in transaction mode (../pooler.sh)
  source ../pooler.sh
  APP_PORT=$((PORT + 2))
  pooler_start "$NAME" "$APP_PORT" conf_app:app || exit 1
fi
export ROWSTILE_APP_TESTS_URL="postgres://conf_app:app@localhost:$APP_PORT/conf_tests"
rc=0
# 11: migrated by Ecto as the owner, then the policy's tests, then Ecto's status: every migration up
DATABASE_URL=$ROWSTILE_OWNER_URL elixir_run "$HERE" mix ecto.migrate >"$LOG/migrate.log" 2>&1 ||
  { cat "$LOG/migrate.log"; echo "FAIL  11: mix ecto.migrate"; exit 1; }
python3 ../../core/cli/rowstile_cli.py test >"$LOG/policy-tests.log" 2>&1 &&
  echo "ok    11: a fresh database, migrated, passes the policy's tests" || { cat "$LOG/policy-tests.log"; echo "FAIL  11: policy tests"; rc=1; }
DATABASE_URL=$ROWSTILE_OWNER_URL elixir_run "$HERE" mix ecto.migrations >"$LOG/status.log" 2>&1 &&
  grep -q "  up  " "$LOG/status.log" && ! grep -q "  down  " "$LOG/status.log" &&
  echo "ok    11: ... and Ecto's status shows nothing left to run (mix ecto.migrations: every migration up)" ||
  { cat "$LOG/status.log"; echo "FAIL  11: mix ecto.migrations"; rc=1; }
python3 ../../core/cli/rowstile_cli.py migrate --check >/dev/null &&
  echo "ok    the policy's lock file is up to date" || { echo "FAIL  rowstile migrate --check"; rc=1; }
# 12: the test database, migrated the same way (each partition copies it)
DATABASE_URL=$ROWSTILE_TESTS_URL elixir_run "$HERE" mix ecto.migrate >"$LOG/migrate-tests.log" 2>&1 ||
  { cat "$LOG/migrate-tests.log"; echo "FAIL  12: mix ecto.migrate, on the test database"; exit 1; }
# 13: the app refuses to start on a connection that skips row-level security (here, the owner's), and starts on
# the app role's
DATABASE_URL=$ROWSTILE_OWNER_URL PORT=$WEB elixir_run "$HERE" timeout 120 mix run --no-halt >"$LOG/server-owner.log" 2>&1
if [ $? = 1 ] && grep -q "an owner skips row-level security" "$LOG/server-owner.log"; then
  echo "ok    13: the app refuses to start on the owner's connection"
else cat "$LOG/server-owner.log"; echo "FAIL  13: the app started on the owner's connection"; rc=1; fi
RUN_NAME=$NAME-server DATABASE_URL="postgres://conf_app:app@localhost:$APP_PORT/conf" PORT=$WEB elixir_run "$HERE" mix run --no-halt \
  >"$LOG/server.log" 2>&1 & server=$!
for _ in $(seq 60); do curl -sf "http://localhost:$WEB/projects" >"$LOG/projects.json" 2>/dev/null && break; sleep 1; done
[ "$(cat "$LOG/projects.json" 2>/dev/null)" = "[]" ] &&
  echo "ok    13: ... and starts on the app role's" || { cat "$LOG/server.log"; echo "FAIL  13: the app didn't start on the app role's connection"; rc=1; }
kill "$server" 2>/dev/null; wait "$server" 2>/dev/null; server=
# the checks: two partitions side by side (mix test --partitions 2), each on its own copy of the test database
for p in 1 2; do
  RUN_NAME=$NAME-test-$p MIX_ENV=test MIX_TEST_PARTITION=$p elixir_run "$HERE" mix test --partitions 2 --cover "$@" >"$LOG/test-$p.log" 2>&1 &
  eval "tests_$p=\$!"
done
tested=0
for p in 1 2; do eval "wait \$tests_$p" || tested=1; done
for p in 1 2; do grep -E '^(ok    |FAIL  )' "$LOG/test-$p.log"; done
[ $tested = 0 ] || { cat "$LOG/test-1.log" "$LOG/test-2.log"; echo "FAIL  mix test"; rc=1; }
# 12: ... and the migrated test database is left as it was
users=$(docker exec "$NAME" psql -U conf_owner -d conf_tests -Atc "SELECT count(*) FROM app.users")
[ "$users" = 0 ] && echo "ok    12: ... the migrated test database is left as it was" || { echo "FAIL  12: conf_tests has $users users"; rc=1; }
MIX_ENV=test elixir_run "$HERE" mix run --no-start -e "Conformance.Cover.report()" >"$LOG/report.txt" 2>&1
covered=$?
cp "$LOG/report.txt" "$CONFORMANCE_COVERAGE/report.txt"
cat "$CONFORMANCE_COVERAGE/report.txt"
if [ $# -gt 0 ]; then
  echo "(some of the checks ran: the SDK's coverage isn't judged)"
elif [ $tested = 0 ] && [ $covered = 0 ]; then
  echo "ok    the checks run every line of the Elixir SDK (Erlang's cover counts lines: Elixir has no branch coverage)"
else
  echo "FAIL  lines of the Elixir SDK no check runs (the report above: $CONFORMANCE_COVERAGE/report.txt)"; rc=1
fi
exit $rc

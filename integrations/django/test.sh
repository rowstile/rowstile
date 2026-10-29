#!/bin/bash
# test.sh: the Django integration's conformance suite (a preview), against a fresh Postgres in Docker.
#   integrations/django/test.sh            # PG_MAJOR=17 or 18 for another version; KEEP=1 keeps the database
#   POOLER=pgbouncer integrations/django/test.sh     # the app through PgBouncer in transaction mode
#   RESOLUTION=lowest-direct integrations/django/test.sh     # the oldest versions the bounds allow, not uv.lock's
# Check 11 first: a fresh database, migrated with Django's migrate (rowstile's policy is one of the app's
# migrations), then the policy's tests, then Django's own diff (makemigrations --check), which must show no change.
# Then the other checks (pytest, pytest-django).
set -u
cd "$(dirname "$0")"
PG=${PG_MAJOR:-16}
NAME=rowstile-conformance-django
PORT=${CONFORMANCE_PORT:-25450}
docker build -q -t "rowstile:$PG" --build-arg "PG_MAJOR=$PG" -f ../../core/Dockerfile ../.. >/dev/null || exit 1
docker rm -f -v "$NAME" >/dev/null 2>&1
POOLED=
stop() {
  [ -n "${KEEP:-}" ] && return
  [ -n "$POOLED" ] && pooler_stop "$NAME"
  docker rm -f -v "$NAME" >/dev/null 2>&1
}
trap stop EXIT
docker run -d --name "$NAME" -e POSTGRES_PASSWORD=postgres -p "$PORT:5432" "rowstile:$PG" >/dev/null || exit 1
for _ in $(seq 60); do docker exec "$NAME" pg_isready -q -U postgres 2>/dev/null && break; sleep 1; done
sleep 2
# the migration role owns the databases: not a superuser, as on managed Postgres (CREATEDB: a test database per worker)
docker exec "$NAME" psql -q -U postgres -c "CREATE ROLE conf_owner LOGIN PASSWORD 'owner' CREATEROLE CREATEDB" \
  -c "ALTER ROLE conf_owner SET createrole_self_grant = 'set, inherit'" -c "CREATE DATABASE conf OWNER conf_owner" \
  -c "CREATE DATABASE conf_tests OWNER conf_owner" >/dev/null || exit 1
OWNER="postgresql://conf_owner:owner@localhost:$PORT"
export ROWSTILE_OWNER_DSN="$OWNER/conf" ROWSTILE_TESTS_URL="$OWNER/conf_tests"
APP_PORT=$PORT
if [ "${POOLER:-}" = pgbouncer ]; then          # the app through PgBouncer in transaction mode (../pooler.sh)
  source ../pooler.sh
  APP_PORT=$((PORT + 2))
  POOLED=1
  pooler_start "$NAME" "$APP_PORT" conf_app:app || exit 1
fi
# the app's connection: the app role, which row-level security applies to (manage.py migrate is given the owner's)
export DATABASE_URL="postgresql://conf_app:app@localhost:$APP_PORT/conf"
if [ -n "${RESOLUTION:-}" ]; then
  # the lowest version of each dependency pyproject.toml names (Django, psycopg: the same floors as the SDK's
  # extra), on the oldest Python the SDK supports, in an environment of its own; uv.lock and .venv stay as they are
  export UV_PROJECT_ENVIRONMENT="$(mktemp -d)/venv" UV_NO_SYNC=1
  uv venv -q --python 3.11 "$UV_PROJECT_ENVIRONMENT" &&
    uv pip install -q --python "$UV_PROJECT_ENVIRONMENT" --resolution "$RESOLUTION" -r pyproject.toml \
      -e ../../sdk/python || exit 1
  uv pip list -q --python "$UV_PROJECT_ENVIRONMENT" | grep -iE '^(django|psycopg|psycopg-pool|pytest-django) '
fi
# What the checks run of the SDK's Django module (sdk/python/rowstile/django), lines and branches (pyproject.toml's
# [tool.coverage]): every Python process from here on, the tests' own subprocesses too, measures itself into
# CONFORMANCE_COVERAGE (a folder of its own if not given), where the report is kept; it is printed at the end
COVERAGE=${CONFORMANCE_COVERAGE:-$(mktemp -d)}
mkdir -p "$COVERAGE" && rm -f "$COVERAGE"/.coverage* "$COVERAGE/report.txt"
export COVERAGE_PROCESS_START="$PWD/pyproject.toml" COVERAGE_FILE="$COVERAGE/.coverage"
LOG=$(mktemp -d)
rc=0
DATABASE_URL=$ROWSTILE_OWNER_DSN uv run --quiet python manage.py migrate --verbosity 0 ||
  { echo "FAIL  11: manage.py migrate"; rc=1; }
uv run --quiet rowstile test >"$LOG/policy-tests.log" 2>&1 &&
  echo "ok    11: a fresh database, migrated, passes the policy's tests" || { cat "$LOG/policy-tests.log"; echo "FAIL  11: policy tests"; rc=1; }
DATABASE_URL=$ROWSTILE_OWNER_DSN uv run --quiet python manage.py makemigrations --check --dry-run >"$LOG/makemigrations.log" 2>&1 &&
  echo "ok    11: ... and Django's own diff shows no change" || { cat "$LOG/makemigrations.log"; echo "FAIL  11: makemigrations --check"; rc=1; }
uv run --quiet rowstile migrate --check >/dev/null &&
  echo "ok    the policy's lock file is up to date" || { echo "FAIL  rowstile migrate --check"; rc=1; }
# 12: the framework's test database, migrated the same way (the tests copy it for each worker)
DATABASE_URL=$ROWSTILE_TESTS_URL uv run --quiet python manage.py migrate --verbosity 0 ||
  { echo "FAIL  12: manage.py migrate, on the test database"; rc=1; }
# two of pytest-xdist's workers, each on a copy of its own (tests/conftest.py)
uv run --quiet pytest -q -p no:cacheprovider -n 2 "$@" || rc=1
copies=$(docker exec "$NAME" psql -qAt -U postgres -c "SELECT string_agg(datname, ', ' ORDER BY datname) FROM pg_database WHERE datname ~ '^conf_tests_w[0-9]+$'")
[ "$copies" = "conf_tests_w0, conf_tests_w1" ] &&
  echo "ok    12: a copy of the migrated test database for each of pytest-xdist's workers ($copies)" || { echo "FAIL  12: the workers' copies: $copies"; rc=1; }
[ "$(docker exec "$NAME" psql -qAt -U postgres -d conf_tests -c "SELECT count(*) FROM users")" = 0 ] &&
  echo "ok    12: ... and the migrated one is left as it was" || { echo "FAIL  12: the migrated test database was written to"; rc=1; }
unset COVERAGE_PROCESS_START
uv run --quiet coverage combine --quiet && uv run --quiet coverage report >"$COVERAGE/report.txt"
covered=$?
cat "$COVERAGE/report.txt"
rm -rf "$LOG"
if [ $# -gt 0 ]; then
  echo "(some of the checks ran: the SDK's coverage isn't judged)"
elif [ -n "${RESOLUTION:-}" ]; then
  echo "(the oldest versions: the SDK's coverage isn't judged, as some of its lines are for newer ones)"
elif [ $covered = 0 ]; then
  echo "ok    the checks run every line and branch of the Python SDK's Django module"
else
  echo "FAIL  lines or branches of the Python SDK's Django module no check runs (the report above: $COVERAGE/report.txt)"; rc=1
fi
exit $rc

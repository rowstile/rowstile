#!/bin/bash
# test.sh: the Python SDK's conformance suite, against a fresh Postgres in Docker.
#   integrations/fastapi/test.sh            # PG_MAJOR=17 or 18 for another version; KEEP=1 keeps the database
#   POOLER=pgbouncer integrations/fastapi/test.sh     # the app through PgBouncer in transaction mode
#   RESOLUTION=lowest-direct integrations/fastapi/test.sh     # the oldest versions the bounds allow, not uv.lock's
# (to look at: check 14 migrates it once more, so the tests run again only on a new one, which this script makes)
# Check 11 first: a fresh database, migrated with Alembic (rowstile's policy is one of the revisions), then
# the policy's tests, then Alembic's own diff, which must show no change. Then the other checks (pytest).
set -u
cd "$(dirname "$0")"
PG=${PG_MAJOR:-16}
NAME=rowstile-conformance-py
PORT=${CONFORMANCE_PORT:-25440}
docker build -q -t "rowstile:$PG" --build-arg "PG_MAJOR=$PG" -f ../../core/Dockerfile ../.. >/dev/null || exit 1
docker rm -f "$NAME" >/dev/null 2>&1
docker run -d --name "$NAME" -e POSTGRES_PASSWORD=postgres -p "$PORT:5432" "rowstile:$PG" >/dev/null || exit 1
for _ in $(seq 60); do docker exec "$NAME" pg_isready -q -U postgres 2>/dev/null && break; sleep 1; done
sleep 2
# the migration role owns the databases: not a superuser, as on managed Postgres (CREATEDB: a test database per worker)
docker exec "$NAME" psql -q -U postgres -c "CREATE ROLE conf_owner LOGIN PASSWORD 'owner' CREATEROLE CREATEDB" \
  -c "ALTER ROLE conf_owner SET createrole_self_grant = 'set, inherit'" -c "CREATE DATABASE conf OWNER conf_owner" \
  -c "CREATE DATABASE conf_tests OWNER conf_owner" >/dev/null || exit 1
export ROWSTILE_OWNER_URL="postgresql+psycopg://conf_owner:owner@localhost:$PORT/conf"
export ROWSTILE_TESTS_URL="postgresql+psycopg://conf_owner:owner@localhost:$PORT/conf_tests"
export ROWSTILE_OWNER_DSN="postgresql://conf_owner:owner@localhost:$PORT/conf"
APP_PORT=$PORT
if [ "${POOLER:-}" = pgbouncer ]; then          # the app through PgBouncer in transaction mode (../pooler.sh)
  source ../pooler.sh
  APP_PORT=$((PORT + 2))
  pooler_start "$NAME" "$APP_PORT" conf_app:app || exit 1
fi
export ROWSTILE_APP_URL="postgresql+asyncpg://conf_app:app@localhost:$APP_PORT/conf"
if [ -n "${RESOLUTION:-}" ]; then
  # the lowest version of each dependency pyproject.toml names (FastAPI, SQLAlchemy, psycopg, asyncpg, Alembic: the
  # same floors as the SDK's extras), on the oldest Python the SDK supports (the oldest of them build on no newer
  # one), in an environment of its own; uv.lock and .venv stay as they are
  export UV_PROJECT_ENVIRONMENT="$(mktemp -d)/venv" UV_NO_SYNC=1
  uv venv -q --python 3.11 "$UV_PROJECT_ENVIRONMENT" &&
    uv pip install -q --python "$UV_PROJECT_ENVIRONMENT" --resolution "$RESOLUTION" -r pyproject.toml || exit 1
  uv pip list -q --python "$UV_PROJECT_ENVIRONMENT" | grep -iE '^(fastapi|starlette|sqlalchemy|psycopg|asyncpg|alembic) '
fi
# What the checks run of the SDK (sdk/python/rowstile), lines and branches (pyproject.toml's [tool.coverage]): every
# Python process from here on, the tests' own subprocesses too, measures itself into CONFORMANCE_COVERAGE (a folder
# of its own if not given), where the report is kept; it is printed at the end
COVERAGE=${CONFORMANCE_COVERAGE:-$(mktemp -d)}
mkdir -p "$COVERAGE" && rm -f "$COVERAGE"/.coverage* "$COVERAGE/report.txt"
export COVERAGE_PROCESS_START="$PWD/pyproject.toml" COVERAGE_FILE="$COVERAGE/.coverage"
rc=0
uv run --quiet alembic upgrade head || { echo "FAIL  11: alembic upgrade head"; rc=1; }
uv run --quiet rowstile test >/tmp/conformance-policy-tests.log 2>&1 &&
  echo "ok    11: a fresh database, migrated, passes the policy's tests" || { cat /tmp/conformance-policy-tests.log; echo "FAIL  11: policy tests"; rc=1; }
uv run --quiet alembic check >/tmp/conformance-alembic-check.log 2>&1 &&
  echo "ok    11: ... and Alembic's own diff shows no change" || { cat /tmp/conformance-alembic-check.log; echo "FAIL  11: alembic check"; rc=1; }
uv run --quiet rowstile migrate --check >/dev/null &&
  echo "ok    the policy's lock file is up to date" || { echo "FAIL  rowstile migrate --check"; rc=1; }
# 12: the framework's test database, migrated the same way (the tests copy it for each worker)
ROWSTILE_OWNER_URL=$ROWSTILE_TESTS_URL uv run --quiet alembic upgrade head || { echo "FAIL  12: alembic upgrade head, on the test database"; rc=1; }
uv run --quiet pytest -q -p no:cacheprovider "$@" || rc=1
unset COVERAGE_PROCESS_START
uv run --quiet coverage combine --quiet && uv run --quiet coverage report >"$COVERAGE/report.txt"
covered=$?
cat "$COVERAGE/report.txt"
if [ $# -gt 0 ]; then
  echo "(some of the checks ran: the SDK's coverage isn't judged)"
elif [ -n "${RESOLUTION:-}" ]; then
  echo "(the oldest versions: the SDK's coverage isn't judged, as some of its lines are for newer ones)"
elif [ $covered = 0 ]; then
  echo "ok    the checks run every line and branch of the Python SDK"
else
  echo "FAIL  lines or branches of the Python SDK no check runs (the report above: $COVERAGE/report.txt)"; rc=1
fi
[ -n "${KEEP:-}" ] || { [ "${POOLER:-}" = pgbouncer ] && pooler_stop "$NAME"; docker rm -f "$NAME" >/dev/null; }
exit $rc

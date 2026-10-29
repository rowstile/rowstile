#!/bin/bash
# test.sh: the Ruby SDK's conformance suite (Rails 8, Active Record on pg, Puma), against a fresh Postgres in Docker.
#   integrations/rails/test.sh              # PG_MAJOR=17 or 18 for another version; KEEP=1 keeps the database
#   POOLER=pgbouncer integrations/rails/test.sh       # the app through PgBouncer in transaction mode
#   integrations/rails/test.sh -i /test_7/            # some of the checks (Minitest's options)
# Ruby runs in a container (ruby.Dockerfile, on the Ruby image ../images/Dockerfile pins), on the host's network,
# as the caller, the gems outside the checkout (ROWSTILE_RAILS_BUNDLE, ~/.cache/rowstile/rails-bundle by default).
# First the gem: built and installed from the build, and its signatures checked with Steep. Then check 11: a fresh
# database, migrated by Rails (rowstile's policy is one of the migrations), the policy's tests, and Rails' own diff:
# the schema it dumps after migrating is db/structure.sql.
# Then the other checks (Minitest, two workers, each on its own copy of the migrated test database).
set -u
cd "$(dirname "$0")"
PG=${PG_MAJOR:-16}
NAME=rowstile-conformance-rails
PORT=${CONFORMANCE_PORT:-25500}
ROOT=$(cd ../.. && pwd)
HERE=$PWD
RUBY_IMAGE=$(sed -n 's/^FROM \([^ ]*\) AS ruby$/\1/p' ../images/Dockerfile)
IMAGE=rowstile-rails
docker build -q -t "rowstile:$PG" --build-arg "PG_MAJOR=$PG" -f ../../core/Dockerfile ../.. >/dev/null || exit 1
docker build -q -t "$IMAGE" --build-arg "RUBY_IMAGE=$RUBY_IMAGE" -f ruby.Dockerfile . >/dev/null || exit 1
LOG=$(mktemp -d)
BUNDLE=${ROWSTILE_RAILS_BUNDLE:-$HOME/.cache/rowstile/rails-bundle}
# What the checks run of the gem (sdk/ruby/lib), lines and branches (test/coverage.rb): every Ruby process the tests
# start measures itself into CONFORMANCE_COVERAGE (a folder of its own if not given), where the report is kept
export CONFORMANCE_COVERAGE=${CONFORMANCE_COVERAGE:-$LOG/coverage}
mkdir -p "$BUNDLE" "$CONFORMANCE_COVERAGE" && find "$CONFORMANCE_COVERAGE" -mindepth 1 -delete
# Ruby, in this folder, with the suite's environment (its databases, and what a step sets)
ruby_run() {
  local passed=() name
  for name in $(compgen -e | grep -E '^(ROWSTILE_[A-Z_]+|CONFORMANCE_[A-Z_]+|DATABASE_URL|RAILS_ENV|SCHEMA|RUBYOPT)$'); do
    passed+=(-e "$name")
  done
  docker run --rm --network host --user "$(id -u):$(id -g)" -e HOME=/tmp -e BUNDLE_PATH="$BUNDLE" \
    -e BUNDLE_GEMFILE="$HERE/Gemfile" -e PYTHONDONTWRITEBYTECODE=1 "${passed[@]}" \
    -v "$ROOT:$ROOT" -v "$LOG:$LOG" -v "$BUNDLE:$BUNDLE" -v "$CONFORMANCE_COVERAGE:$CONFORMANCE_COVERAGE" -w "$HERE" \
    "$IMAGE" "$@"
}
ruby_run bundle install --quiet >"$LOG/bundle.log" 2>&1 || { cat "$LOG/bundle.log"; echo "FAIL  bundle install"; exit 1; }
# the gem, as it is published: built, installed from the build, and loaded from where it was installed
ruby_run bash test/gem.sh "$LOG" >"$LOG/gem.log" 2>&1 &&
  echo "ok    the gem builds, installs from the build and loads ($(tail -1 "$LOG/gem.log"))" ||
  { cat "$LOG/gem.log"; echo "FAIL  the gem doesn't build, install or load"; exit 1; }
# the gem's signatures, against its code (Steep, its strict diagnostics: sdk/ruby/Steepfile)
ruby_run bash -c 'cd ../../sdk/ruby && bundle exec steep check' >"$LOG/steep.log" 2>&1 &&
  echo "ok    the gem type-checks (Steep)" || { cat "$LOG/steep.log"; echo "FAIL  steep check (sdk/ruby)"; exit 1; }
docker rm -f -v "$NAME" >/dev/null 2>&1
docker run -d --name "$NAME" -e POSTGRES_PASSWORD=postgres -p "$PORT:5432" "rowstile:$PG" >/dev/null || exit 1
cleanup() {
  [ -n "${KEEP:-}" ] && return
  [ "${POOLER:-}" = pgbouncer ] && pooler_stop "$NAME"
  docker rm -f -v "$NAME" >/dev/null 2>&1
}
trap cleanup EXIT
for _ in $(seq 60); do docker exec "$NAME" pg_isready -q -U postgres 2>/dev/null && break; sleep 1; done
sleep 2
# the migration role owns the databases: not a superuser, as on managed Postgres (CREATEDB: a test database per worker)
docker exec "$NAME" psql -q -U postgres -c "CREATE ROLE conf_owner LOGIN PASSWORD 'owner' CREATEROLE CREATEDB" \
  -c "ALTER ROLE conf_owner SET createrole_self_grant = 'set, inherit'" -c "CREATE DATABASE conf OWNER conf_owner" \
  -c "CREATE DATABASE conf_tests OWNER conf_owner" >/dev/null || exit 1
export ROWSTILE_OWNER_URL="postgresql://conf_owner:owner@localhost:$PORT/conf"
export ROWSTILE_TESTS_URL="postgresql://conf_owner:owner@localhost:$PORT/conf_tests"
APP_PORT=$PORT
if [ "${POOLER:-}" = pgbouncer ]; then          # the app through PgBouncer in transaction mode (../pooler.sh)
  source ../pooler.sh
  APP_PORT=$((PORT + 2))
  pooler_start "$NAME" "$APP_PORT" conf_app:app || exit 1
fi
export ROWSTILE_APP_TESTS_URL="postgresql://conf_app:app@localhost:$APP_PORT/conf_tests"
rc=0
# 11: migrated by Rails as the owner. Rails reads the schema it dumped (db/structure.sql) before migrating an empty
# database, and dumps it again after: a copy of the committed one, where SCHEMA says, so the run leaves it alone
cp db/structure.sql "$LOG/structure.sql"
DATABASE_URL=$ROWSTILE_OWNER_URL SCHEMA=$LOG/structure.sql ruby_run bin/rails db:migrate >"$LOG/migrate.log" 2>&1 ||
  { cat "$LOG/migrate.log"; echo "FAIL  11: bin/rails db:migrate"; rc=1; }
python3 ../../core/cli/rowstile_cli.py test >"$LOG/policy-tests.log" 2>&1 &&
  echo "ok    11: a fresh database, migrated, passes the policy's tests" || { cat "$LOG/policy-tests.log"; echo "FAIL  11: policy tests"; rc=1; }
diff -u db/structure.sql "$LOG/structure.sql" >"$LOG/structure.diff" 2>&1 &&
  echo "ok    11: ... and Rails' own diff shows no change (the schema it dumps after migrating is db/structure.sql)" ||
  { cat "$LOG/structure.diff"; echo "FAIL  11: db/structure.sql isn't what Rails dumps after migrating"; rc=1; }
python3 ../../core/cli/rowstile_cli.py migrate --check >/dev/null &&
  echo "ok    the policy's lock file is up to date" || { echo "FAIL  rowstile migrate --check"; rc=1; }
# 12: the framework's test database, migrated the same way (the tests copy it for each worker)
cp db/structure.sql "$LOG/structure-tests.sql"
DATABASE_URL=$ROWSTILE_TESTS_URL RAILS_ENV=test SCHEMA=$LOG/structure-tests.sql ruby_run bin/rails db:migrate \
  >"$LOG/migrate-tests.log" 2>&1 || { cat "$LOG/migrate-tests.log"; echo "FAIL  12: bin/rails db:migrate, on the test database"; rc=1; }
DATABASE_URL=$ROWSTILE_APP_TESTS_URL RAILS_ENV=test RUBYOPT="-r$PWD/test/coverage.rb" ruby_run bin/rails test "$@" || rc=1
ruby_run bundle exec ruby test/coverage.rb --report "$CONFORMANCE_COVERAGE" >"$LOG/report.txt" 2>&1
covered=$?
cp "$LOG/report.txt" "$CONFORMANCE_COVERAGE/report.txt"
cat "$CONFORMANCE_COVERAGE/report.txt"
if [ $# -gt 0 ]; then
  echo "(some of the checks ran: the gem's coverage isn't judged)"
elif [ $covered = 0 ]; then
  echo "ok    the checks run every line and branch of the Ruby SDK"
else
  echo "FAIL  lines or branches of the Ruby SDK no check runs (the report above: $CONFORMANCE_COVERAGE)"; rc=1
fi
exit $rc

#!/bin/bash
# test.sh: the PHP SDK's conformance suite (a preview: Laravel, Eloquent on pdo_pgsql, the queue's worker, PHPUnit
# with paratest), against a fresh Postgres in Docker.
#   integrations/laravel/test.sh            # PG_MAJOR=17 or 18 for another version; KEEP=1 keeps the database
#   POOLER=pgbouncer integrations/laravel/test.sh     # the app through PgBouncer in transaction mode
#   integrations/laravel/test.sh --filter test_7      # some of the checks (PHPUnit's options)
# PHP runs in a container (php.Dockerfile, on the PHP and Composer images ../images/Dockerfile pins), on the host's
# network, as the caller; Composer's cache is outside the checkout (ROWSTILE_COMPOSER_CACHE,
# ~/.cache/rowstile/composer by default), vendor/ in this folder (git ignores it).
# First the package: archived, installed from the archive and loaded (tests/package.sh); then PHPStan over the SDK
# and the app. Then check 11: a fresh database, migrated by Laravel (rowstile's policy is one of the migrations), the
# policy's tests, and Laravel's own migrate --pretend, which must find nothing left to run.
# Then the other checks (paratest, two workers, each on its own copy of the migrated test database), with what they
# run of the SDK measured by Xdebug, lines and branches (tests/coverage.php).
set -u
cd "$(dirname "$0")"
PG=${PG_MAJOR:-16}
NAME=rowstile-conformance-laravel
PORT=${CONFORMANCE_PORT:-25530}
ROOT=$(cd ../.. && pwd)
HERE=$PWD
PHP_IMAGE=$(sed -n 's/^FROM \([^ ]*\) AS php$/\1/p' ../images/Dockerfile)
COMPOSER_IMAGE=$(sed -n 's/^FROM \([^ ]*\) AS composer$/\1/p' ../images/Dockerfile)
IMAGE=rowstile-laravel
docker build -q -t "rowstile:$PG" --build-arg "PG_MAJOR=$PG" -f ../../core/Dockerfile ../.. >/dev/null || exit 1
docker build -q -t "$IMAGE" --build-arg "PHP_IMAGE=$PHP_IMAGE" --build-arg "COMPOSER_IMAGE=$COMPOSER_IMAGE" -f php.Dockerfile . >/dev/null || exit 1
LOG=$(mktemp -d)
CACHE=${ROWSTILE_COMPOSER_CACHE:-$HOME/.cache/rowstile/composer}
# what the checks run of the SDK, kept where CONFORMANCE_COVERAGE says (a folder of its own if not given)
export CONFORMANCE_COVERAGE=${CONFORMANCE_COVERAGE:-$LOG/coverage}
mkdir -p "$CACHE" "$CONFORMANCE_COVERAGE" && find "$CONFORMANCE_COVERAGE" -mindepth 1 -delete
# PHP, in this folder, with the suite's environment (its databases, and what a step sets)
php_run() {
  local passed=() name
  for name in $(compgen -e | grep -E '^(ROWSTILE_[A-Z_]+|DB_URL|XDEBUG_MODE)$'); do
    passed+=(-e "$name")
  done
  docker run --rm --network host --user "$(id -u):$(id -g)" -e HOME=/tmp -e COMPOSER_CACHE_DIR="$CACHE" \
    -e DB_CONNECTION=pgsql -e APP_ENV=testing -e APP_KEY=base64:cm93c3RpbGUtY29uZm9ybWFuY2UtbGFyYXZlbC1rZXk= \
    "${passed[@]}" -v "$ROOT:$ROOT" -v "$LOG:$LOG" -v "$CACHE:$CACHE" -v "$CONFORMANCE_COVERAGE:$CONFORMANCE_COVERAGE" \
    -w "$HERE" "$IMAGE" "$@"
}
php_run composer install --no-interaction --no-progress >"$LOG/composer.log" 2>&1 ||
  { cat "$LOG/composer.log"; echo "FAIL  composer install"; exit 1; }
# the package, as it is published: archived, installed from the archive, and loaded from where it was installed
php_run bash tests/package.sh "$LOG/package" >"$LOG/package.log" 2>&1 &&
  echo "ok    the package builds, installs from its archive and loads ($(tail -1 "$LOG/package.log"))" ||
  { cat "$LOG/package.log"; echo "FAIL  the package doesn't build, install or load"; exit 1; }
# the SDK and the app, the policy's names and the migrations, at PHPStan's strictest (phpstan.neon)
php_run vendor/bin/phpstan analyse --no-progress --memory-limit=1G >"$LOG/phpstan.log" 2>&1 &&
  echo "ok    the SDK and the app type-check (PHPStan, level max, its strict rules, Larastan)" ||
  { cat "$LOG/phpstan.log"; echo "FAIL  phpstan analyse"; exit 1; }
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
# 11: migrated by Laravel as the owner, then the policy's tests, then Laravel's own look: nothing left to run
DB_URL=$ROWSTILE_OWNER_URL php_run php artisan migrate --force >"$LOG/migrate.log" 2>&1 ||
  { cat "$LOG/migrate.log"; echo "FAIL  11: php artisan migrate"; rc=1; }
python3 ../../core/cli/rowstile_cli.py test >"$LOG/policy-tests.log" 2>&1 &&
  echo "ok    11: a fresh database, migrated, passes the policy's tests" || { cat "$LOG/policy-tests.log"; echo "FAIL  11: policy tests"; rc=1; }
DB_URL=$ROWSTILE_OWNER_URL php_run php artisan migrate --pretend --force >"$LOG/pretend.log" 2>&1 && grep -q "Nothing to migrate" "$LOG/pretend.log" &&
  echo "ok    11: ... and Laravel's migrate --pretend finds nothing left to run" ||
  { cat "$LOG/pretend.log"; echo "FAIL  11: php artisan migrate --pretend"; rc=1; }
python3 ../../core/cli/rowstile_cli.py migrate --check >/dev/null &&
  echo "ok    the policy's lock file is up to date" || { echo "FAIL  rowstile migrate --check"; rc=1; }
# 12: the framework's test database, migrated the same way (each worker copies it)
DB_URL=$ROWSTILE_TESTS_URL php_run php artisan migrate --force >"$LOG/migrate-tests.log" 2>&1 ||
  { cat "$LOG/migrate-tests.log"; echo "FAIL  12: php artisan migrate, on the test database"; rc=1; }
# the checks: each prints its line (tests/checks.php reads PHPUnit's report of them)
DB_URL=$ROWSTILE_APP_TESTS_URL XDEBUG_MODE=coverage php_run vendor/bin/paratest -p 2 --no-progress \
  --log-junit "$LOG/checks.xml" --coverage-php "$CONFORMANCE_COVERAGE/coverage.php" "$@" >"$LOG/checks.log" 2>&1 || rc=1
php_run php tests/checks.php "$LOG/checks.xml" || { cat "$LOG/checks.log"; rc=1; }
php_run php -d memory_limit=1G tests/coverage.php "$CONFORMANCE_COVERAGE/coverage.php" >"$CONFORMANCE_COVERAGE/report.txt" 2>&1
covered=$?
cat "$CONFORMANCE_COVERAGE/report.txt"
if [ $# -gt 0 ]; then
  echo "(some of the checks ran: the SDK's coverage isn't judged)"
elif [ $covered = 0 ]; then
  echo "ok    the checks run every line and branch of the PHP SDK"
else
  echo "FAIL  lines or branches of the PHP SDK no check runs (the report above: $CONFORMANCE_COVERAGE)"; rc=1
fi
exit $rc

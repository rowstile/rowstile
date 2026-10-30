#!/bin/bash
# test.sh: the Kotlin SDK's conformance suite (preview), against a fresh Postgres in Docker.
#   integrations/ktor/test.sh             # PG_MAJOR=17 or 18 for another version; KEEP=1 keeps the database
#   POOLER=pgbouncer integrations/ktor/test.sh      # the app through PgBouncer in transaction mode
#   integrations/ktor/test.sh -Dtest=ConformanceTest    # some of the checks (Maven's arguments)
# Maven runs through sdk/java's wrapper (Java 21 or newer on the PATH); MAVEN_ARGS, Maven's own, may name another
# local repository (-Dmaven.repo.local=...). The SDK is built and installed first (sdk/java: the Java SDK and the
# Kotlin module), as an app's build gets it. Then check 11: a fresh database, migrated with Flyway (rowstile's policy
# is one of the migrations), then the policy's tests, then Flyway's own validate, which must find nothing pending and
# nothing changed. Then the other checks run (JUnit, in two JVMs: check 12), each printing its line. Their coverage
# of the Kotlin module is reported last.
set -u
cd "$(dirname "$0")"
PG=${PG_MAJOR:-16}
NAME=rowstile-conformance-ktor
PORT=${CONFORMANCE_PORT:-25560}
MVN="../../sdk/java/mvnw -B -q"
export PYTHON=${PYTHON:-python3}
CLI="$PYTHON ../../core/cli/rowstile_cli.py"
docker build -q -t "rowstile:$PG" --build-arg "PG_MAJOR=$PG" -f ../../core/Dockerfile ../.. >/dev/null || exit 1
docker rm -f -v "$NAME" >/dev/null 2>&1
source ../pooler.sh
stop() { [ -n "${KEEP:-}" ] || { pooler_stop "$NAME"; docker rm -f -v "$NAME" >/dev/null 2>&1; }; }
trap stop EXIT
docker run -d --name "$NAME" -e POSTGRES_PASSWORD=postgres -p "$PORT:5432" "rowstile:$PG" >/dev/null || exit 1
for _ in $(seq 60); do docker exec "$NAME" pg_isready -q -U postgres 2>/dev/null && break; sleep 1; done
sleep 2
# the migration role owns the databases: not a superuser, as on managed Postgres (CREATEDB: a test database per JVM)
docker exec "$NAME" psql -q -U postgres -c "CREATE ROLE conf_owner LOGIN PASSWORD 'owner' CREATEROLE CREATEDB" \
  -c "ALTER ROLE conf_owner SET createrole_self_grant = 'set, inherit'" -c "CREATE DATABASE conf OWNER conf_owner" \
  -c "CREATE DATABASE conf_tests OWNER conf_owner" >/dev/null || exit 1
export ROWSTILE_OWNER_DSN="postgresql://conf_owner:owner@localhost:$PORT/conf"
export ROWSTILE_OWNER_URL="jdbc:postgresql://localhost:$PORT/conf?user=conf_owner&password=owner"
export ROWSTILE_TESTS_URL="jdbc:postgresql://localhost:$PORT/conf_tests?user=conf_owner&password=owner"
APP_PORT=$PORT
if [ "${POOLER:-}" = pgbouncer ]; then          # the app through PgBouncer in transaction mode (../pooler.sh)
  APP_PORT=$((PORT + 2))
  pooler_start "$NAME" "$APP_PORT" conf_app:app || exit 1
fi
export ROWSTILE_APP_URL="jdbc:postgresql://localhost:$APP_PORT/conf?user=conf_app&password=app"
export ROWSTILE_CLI="$PYTHON $PWD/../../core/cli/rowstile_cli.py"   # the command, for checks 9 and 14
LOG=$(mktemp -d)
rc=0
# the SDK first (the Kotlin module, and the Java one under it), built and installed in the local repository, where the
# app's build finds it: Maven resolves the app's dependencies for Flyway's goals too (a clean local repository, as on
# CI's runners, has no other copy of it)
$MVN -f ../../sdk/java/pom.xml -pl rowstile-kotlin -am install >"$LOG/sdk.log" 2>&1 ||
  { cat "$LOG/sdk.log"; echo "FAIL  the SDK doesn't build"; exit 1; }
$MVN flyway:migrate >"$LOG/migrate.log" 2>&1 || { cat "$LOG/migrate.log"; echo "FAIL  11: flyway:migrate"; exit 1; }
$CLI test >"$LOG/policy-tests.log" 2>&1 &&
  echo "ok    11: a fresh database, migrated, passes the policy's tests" || { cat "$LOG/policy-tests.log"; echo "FAIL  11: policy tests"; rc=1; }
$MVN flyway:validate >"$LOG/validate.log" 2>&1 &&
  echo "ok    11: ... and Flyway's own validate finds nothing pending and nothing changed" || { cat "$LOG/validate.log"; echo "FAIL  11: flyway:validate"; rc=1; }
$CLI migrate --check >/dev/null &&
  echo "ok    the policy's lock file is up to date" || { echo "FAIL  rowstile migrate --check"; rc=1; }
# 12: the framework's test database, migrated the same way (each test JVM copies it)
ROWSTILE_OWNER_URL=$ROWSTILE_TESTS_URL $MVN flyway:migrate >"$LOG/migrate-tests.log" 2>&1 || { cat "$LOG/migrate-tests.log"; exit 1; }
# What the checks run of the Kotlin module (sdk/java/rowstile-kotlin), lines and branches, measured by JaCoCo in the
# tests' JVMs: the report is printed, and kept in CONFORMANCE_COVERAGE (a folder of its own if not given) with its pages
COVERAGE=${CONFORMANCE_COVERAGE:-$(mktemp -d)}
mkdir -p "$COVERAGE" && rm -rf "$COVERAGE"/jacoco.exec "$COVERAGE"/report.txt "$COVERAGE"/rowstile-kotlin
../../sdk/java/mvnw -B verify -Djacoco.destFile="$COVERAGE/jacoco.exec" "$@" >"$LOG/verify.log" 2>&1
verified=$?
grep -E '^(ok|FAIL)  ' "$LOG/verify.log"
[ $verified = 0 ] || { grep -E '^\[ERROR\]|^e: ' "$LOG/verify.log" | head -40; echo "(Maven's log: $LOG/verify.log)"; rc=1; }
$MVN -f ../../sdk/java/pom.xml -pl rowstile-kotlin org.jacoco:jacoco-maven-plugin:0.8.16:report \
  -Djacoco.dataFile="$COVERAGE/jacoco.exec" >"$LOG/report.log" 2>&1 || { cat "$LOG/report.log"; rc=1; }
cp -r ../../sdk/java/rowstile-kotlin/target/site/jacoco "$COVERAGE/rowstile-kotlin" 2>/dev/null
# each class: lines and branches missed, then the total (jacoco.csv: a row per class)
awk -F, '$1 != "GROUP" {
    lm += $8; lc += $9; bm += $6; bc += $7
    if ($8 + $6 > 0) printf "%-60s %3d lines, %3d branches missed\n", $2 "." $3, $8, $6
  } END { printf "TOTAL  %d of %d lines, %d of %d branches run\n", lc, lm + lc, bc, bm + bc; exit (lm + bm > 0) }' \
  "$COVERAGE/rowstile-kotlin/jacoco.csv" >"$COVERAGE/report.txt" 2>/dev/null
covered=$?
cat "$COVERAGE/report.txt"
if [ $# -gt 0 ]; then
  echo "(some of the checks ran: the SDK's coverage isn't judged)"
elif [ $covered = 0 ] && [ -s "$COVERAGE/report.txt" ]; then
  echo "ok    the checks run every line and branch of the Kotlin SDK"
else
  echo "FAIL  lines or branches of the Kotlin SDK no check runs (the report above: $COVERAGE/report.txt)"; rc=1
fi
exit $rc

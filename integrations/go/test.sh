#!/bin/bash
# test.sh: the Go SDK's conformance suite (a preview), against a fresh Postgres in Docker.
#   integrations/go/test.sh                 # PG_MAJOR=17 or 18 for another version; KEEP=1 keeps the database
#   POOLER=pgbouncer integrations/go/test.sh          # the app through PgBouncer in transaction mode
# Needs go (1.25 or newer: the SDK's go.mod), git, curl, python3 and docker. goose is its release's Linux x86-64
# binary, checked against its hash (core/tests/migration_tools.sh's version); sqlc is its image, pinned in
# ../images/Dockerfile.
# Check 11 first: a fresh database, migrated with goose (rowstile's policy is one of the migrations), then the
# policy's tests, then goose's status, which must show nothing left to run (goose has no diff of its own). Then
# sqlc's code, the checks Go itself makes (go vet, gofmt, staticcheck), the SDK installed from its tag, the server's
# half of check 13, and the other checks (go test, its two packages side by side, each on its own database).
set -u
cd "$(dirname "$0")"
PG=${PG_MAJOR:-16}
NAME=rowstile-conformance-go
PORT=${CONFORMANCE_PORT:-25480}
WEB=${CONFORMANCE_WEB_PORT:-$((PORT + 3))}
ROOT=$(cd ../.. && pwd)
export ROWSTILE_CLI=$ROOT/core/cli/rowstile_cli.py
GOOSE_VERSION=$(sed -n 's/^GOOSE=\(v[0-9.]*\) GOOSE_SHA=.*/\1/p' ../../core/tests/migration_tools.sh)
GOOSE_SHA=$(sed -n 's/^GOOSE=v[0-9.]* GOOSE_SHA=\([0-9a-f]*\)$/\1/p' ../../core/tests/migration_tools.sh)
SQLC=$(sed -n 's/^FROM \([^ ]*\) AS sqlc$/\1/p' ../images/Dockerfile)
STATICCHECK=honnef.co/go/tools/cmd/staticcheck@v0.8.1
T=$(mktemp -d)
server=
stop() {
  [ -n "$server" ] && kill "$server" 2>/dev/null
  [ -n "${KEEP:-}" ] || { [ "${POOLER:-}" = pgbouncer ] && pooler_stop "$NAME"; docker rm -f -v "$NAME" >/dev/null 2>&1; }
  rm -rf "$T"
}
trap stop EXIT
command -v go >/dev/null || { echo "FAIL  go is not installed"; exit 1; }
# goose, kept between runs
TOOLS=${XDG_CACHE_HOME:-$HOME/.cache}/rowstile-conformance-go
export GOOSE=$TOOLS/goose-$GOOSE_VERSION
if ! echo "$GOOSE_SHA  $GOOSE" | sha256sum -c --quiet - 2>/dev/null; then
  mkdir -p "$TOOLS" && curl -fsSL -o "$GOOSE" "https://github.com/pressly/goose/releases/download/$GOOSE_VERSION/goose_linux_x86_64" &&
    echo "$GOOSE_SHA  $GOOSE" | sha256sum -c --quiet - && chmod +x "$GOOSE" ||
    { echo "FAIL  goose $GOOSE_VERSION: not downloaded, or not the bytes its release published"; exit 1; }
fi
docker build -q -t "rowstile:$PG" --build-arg "PG_MAJOR=$PG" -f ../../core/Dockerfile ../.. >/dev/null || exit 1
docker rm -f -v "$NAME" >/dev/null 2>&1
docker run -d --name "$NAME" -e POSTGRES_PASSWORD=postgres -p "$PORT:5432" "rowstile:$PG" >/dev/null || exit 1
for _ in $(seq 60); do docker exec "$NAME" pg_isready -q -U postgres 2>/dev/null && break; sleep 1; done
sleep 2
# the migration role owns the databases: not a superuser, as on managed Postgres (CREATEDB: a test database per package)
docker exec "$NAME" psql -q -U postgres -c "CREATE ROLE conf_owner LOGIN PASSWORD 'owner' CREATEROLE CREATEDB" \
  -c "ALTER ROLE conf_owner SET createrole_self_grant = 'set, inherit'" -c "CREATE DATABASE conf OWNER conf_owner" \
  -c "CREATE DATABASE conf_tests OWNER conf_owner" >/dev/null || exit 1
export ROWSTILE_OWNER_DSN="postgres://conf_owner:owner@localhost:$PORT/conf"
export ROWSTILE_TESTS_URL="postgres://conf_owner:owner@localhost:$PORT/conf_tests"
APP_PORT=$PORT
if [ "${POOLER:-}" = pgbouncer ]; then          # the app through PgBouncer in transaction mode (../pooler.sh)
  source ../pooler.sh
  APP_PORT=$((PORT + 2))
  pooler_start "$NAME" "$APP_PORT" conf_app:app || exit 1
fi
APP="postgres://conf_app:app@localhost:$APP_PORT"
rc=0
"$GOOSE" -dir migrations postgres "$ROWSTILE_OWNER_DSN" up >"$T/migrate.log" 2>&1 || { cat "$T/migrate.log"; echo "FAIL  11: goose up"; exit 1; }
python3 "$ROWSTILE_CLI" test >"$T/policy-tests.log" 2>&1 &&
  echo "ok    11: a fresh database, migrated, passes the policy's tests" || { cat "$T/policy-tests.log"; echo "FAIL  11: policy tests"; rc=1; }
"$GOOSE" -dir migrations postgres "$ROWSTILE_OWNER_DSN" status >"$T/status.log" 2>&1 && ! grep -q Pending "$T/status.log" &&
  echo "ok    11: ... and goose's status shows nothing left to run" || { cat "$T/status.log"; echo "FAIL  11: goose status"; rc=1; }
python3 "$ROWSTILE_CLI" migrate --check >/dev/null &&
  echo "ok    the policy's lock file is up to date" || { echo "FAIL  rowstile migrate --check"; rc=1; }
# 12: the test database, migrated the same way (each test package copies it)
"$GOOSE" -dir migrations postgres "$ROWSTILE_TESTS_URL" up >"$T/migrate-tests.log" 2>&1 || { cat "$T/migrate-tests.log"; echo "FAIL  12: goose up, on the test database"; exit 1; }
# sqlc's code is what sqlc writes from the queries and the tables, in a copy of what it reads
mkdir -p "$T/sqlc/db" "$T/sqlc/migrations" && cp sqlc.yaml "$T/sqlc/" && cp db/queries.sql "$T/sqlc/db/" &&
  cp migrations/00001_schema.sql "$T/sqlc/migrations/" || exit 1
docker image inspect "$SQLC" >/dev/null 2>&1 || docker pull -q "$SQLC" >/dev/null || exit 1
docker run --rm -u "$(id -u):$(id -g)" -v "$T/sqlc:/src" -w /src "$SQLC" generate >"$T/sqlc.log" 2>&1 &&
  diff -r "$T/sqlc/internal/db" internal/db >"$T/sqlc.diff" &&
  echo "ok    sqlc's code is what sqlc writes from the queries" || { cat "$T/sqlc.log" "$T/sqlc.diff"; echo "FAIL  internal/db is out of date: sqlc generate"; rc=1; }
# what Go itself checks, in the SDK and the app (the generated code too)
for module in ../../sdk/go .; do
  (cd "$module" && go vet ./... && test -z "$(gofmt -l .)" && go run "$STATICCHECK" ./...) >"$T/vet.log" 2>&1 ||
    { cat "$T/vet.log"; gofmt -l "$module"; echo "FAIL  go vet, gofmt or staticcheck: $module"; rc=1; }
done
[ $rc = 0 ] && echo "ok    go vet, gofmt and staticcheck find nothing in the SDK and the app"
# the SDK from its tag, as the repository would publish it: a commit of its folder, tagged sdk/go/v<its version> in a
# repository go fetches as github.com/rowstile/rowstile (git's insteadOf), and the app built on that module. In a
# module cache of its own (the tag's version is the same from one run to the next, the code isn't), which takes the
# other modules from the usual one
VERSION=v$(sed -n 's/^const Version = "\(.*\)"$/\1/p' ../../sdk/go/version.go)
(mkdir -p "$T/repo/sdk" && cp -r ../../sdk/go "$T/repo/sdk/go" && cd "$T/repo" && git init -q && git add . &&
  git -c user.name=t -c user.email=t@t commit -q -m sdk && git tag "sdk/go/$VERSION") || exit 1
cp -r . "$T/app" || exit 1
(cd "$T/app" && export GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0="url.file://$T/repo.insteadOf" \
  GIT_CONFIG_VALUE_0=https://github.com/rowstile/rowstile GOPRIVATE=github.com/rowstile/rowstile \
  GOFLAGS="-mod=mod -modcacherw" GOMODCACHE="$T/modcache" GOPROXY="file://$(go env GOMODCACHE)/cache/download,$(go env GOPROXY)" &&
  go mod edit -dropreplace github.com/rowstile/rowstile/sdk/go -require "github.com/rowstile/rowstile/sdk/go@$VERSION" &&
  go build -o "$T/conformance" ./cmd/conformance && go list -m github.com/rowstile/rowstile/sdk/go) >"$T/tag.log" 2>&1 &&
  grep -qx "github.com/rowstile/rowstile/sdk/go $VERSION" "$T/tag.log" &&
  echo "ok    the SDK installs from its tag, sdk/go/$VERSION, and the app builds on it" || { cat "$T/tag.log"; echo "FAIL  the SDK from its tag"; rc=1; }
# 13: the app refuses to start on a connection that skips row-level security (here, the owner's), and starts on
# the app role's
ROWSTILE_APP_URL=$ROWSTILE_OWNER_DSN ADDR="localhost:$WEB" timeout 60 "$T/conformance" >"$T/server-owner.log" 2>&1
if [ $? = 1 ] && grep -q "an owner skips row-level security" "$T/server-owner.log"; then
  echo "ok    13: the app refuses to start on the owner's connection"
else cat "$T/server-owner.log"; echo "FAIL  13: the app started on the owner's connection"; rc=1; fi
ROWSTILE_APP_URL="$APP/conf" ADDR="localhost:$WEB" "$T/conformance" >"$T/server.log" 2>&1 & server=$!
for _ in $(seq 30); do curl -sf "http://localhost:$WEB/projects" >"$T/projects.json" && break; sleep 1; done
[ "$(cat "$T/projects.json" 2>/dev/null)" = "[]" ] &&
  echo "ok    13: ... and starts on the app role's" || { cat "$T/server.log"; echo "FAIL  13: the app didn't start on the app role's connection"; rc=1; }
kill "$server" 2>/dev/null; server=
# What the checks run of the SDK (sdk/go and its rowstiletest), statements: Go measures no branches. The report is
# printed, and kept in CONFORMANCE_COVERAGE (a folder of its own if not given) with the profile
COVERAGE=${CONFORMANCE_COVERAGE:-$(mktemp -d)}
mkdir -p "$COVERAGE" && rm -f "$COVERAGE/cover.out" "$COVERAGE/report.txt"
ROWSTILE_APP_URL="$APP/conf_tests" go test -count=1 -v -coverpkg=github.com/rowstile/rowstile/sdk/go/... \
  -coverprofile="$COVERAGE/cover.out" ./... "$@" >"$T/test.log" 2>&1
tested=$?
grep -E '^(ok    |FAIL  )' "$T/test.log"
[ $tested = 0 ] || { cat "$T/test.log"; echo "FAIL  go test"; rc=1; }
# 12: ... and the migrated test database is left as it was
users=$(docker exec "$NAME" psql -U conf_owner -d conf_tests -Atc "SELECT count(*) FROM app.users")
[ "$users" = 0 ] && echo "ok    12: ... the migrated test database is left as it was" || { echo "FAIL  12: conf_tests has $users users"; rc=1; }
go tool cover -func="$COVERAGE/cover.out" >"$COVERAGE/report.txt" 2>&1
cat "$COVERAGE/report.txt"
if [ $# -gt 0 ]; then
  echo "(some of the checks ran: the SDK's coverage isn't judged)"
elif [ $tested = 0 ] && grep -qE '^total:\s+\(statements\)\s+100.0%$' "$COVERAGE/report.txt"; then
  echo "ok    the checks run every statement of the Go SDK (Go's coverage counts statements, not branches)"
else
  echo "FAIL  statements of the Go SDK no check runs (the report above: $COVERAGE/report.txt)"; rc=1
fi
exit $rc

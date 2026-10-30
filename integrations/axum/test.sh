#!/bin/bash
# test.sh: the Rust SDK's conformance suite (a preview): an Axum app on sqlx, against a fresh Postgres in Docker.
#   integrations/axum/test.sh               # PG_MAJOR=17 or 18 for another version; KEEP=1 keeps the database
#   POOLER=pgbouncer integrations/axum/test.sh        # the app through PgBouncer in transaction mode
#   integrations/axum/test.sh check_07                # some of the checks (cargo test's filter)
# Rust runs in a container (rust.Dockerfile, on the Rust image ../images/Dockerfile pins), on the host's network, as
# the caller; cargo's registry and the builds are outside the checkout (ROWSTILE_AXUM_CACHE,
# ~/.cache/rowstile/axum by default). Needs docker, python3 and curl.
# First the SDK: rustfmt, Clippy (every warning an error, on each set of its features), its examples, and its
# package (cargo package builds it as crates.io would), installed from the package: the app builds on it. Then
# check 11: a fresh database, migrated by sqlx's migrator (rowstile's policy is one of the migrations), the
# policy's tests, then sqlx's own list of migrations, which must show each one installed, as its file is. The
# server's half of check 13. Then the other checks (cargo test, its two test binaries one after the other, each on
# its own copy of the migrated test database), measured by cargo-llvm-cov, and checks 9 and 14, which compile Rust
# (tests/compile.sh).
set -u
cd "$(dirname "$0")"
PG=${PG_MAJOR:-16}
NAME=rowstile-conformance-axum
PORT=${CONFORMANCE_PORT:-25540}
WEB=${CONFORMANCE_WEB_PORT:-$((PORT + 3))}
ROOT=$(cd ../.. && pwd)
HERE=$PWD
RUST_IMAGE=$(sed -n 's/^FROM \([^ ]*\) AS rust$/\1/p' ../images/Dockerfile)
IMAGE=rowstile-axum
CACHE=${ROWSTILE_AXUM_CACHE:-$HOME/.cache/rowstile/axum}
T=$(mktemp -d)
# What the checks run of the SDK (sdk/rust), lines and regions (cargo-llvm-cov, on stable Rust: branches need a
# nightly compiler). The report is printed, and kept in CONFORMANCE_COVERAGE (a folder of its own if not given)
export CONFORMANCE_COVERAGE=${CONFORMANCE_COVERAGE:-$T/coverage}
mkdir -p "$CACHE" "$CONFORMANCE_COVERAGE" && rm -f "$CONFORMANCE_COVERAGE/report.txt"
stop() {
  [ -n "${KEEP:-}" ] || { [ "${POOLER:-}" = pgbouncer ] && pooler_stop "$NAME"; docker rm -f -v "$NAME" >/dev/null 2>&1; }
  docker rm -f "$NAME-server" >/dev/null 2>&1
  rm -rf "$T"
}
trap stop EXIT
docker build -q -t "rowstile:$PG" --build-arg "PG_MAJOR=$PG" -f ../../core/Dockerfile ../.. >/dev/null || exit 1
docker build -q -t "$IMAGE" --build-arg "RUST_IMAGE=$RUST_IMAGE" -f rust.Dockerfile . >/dev/null || exit 1
# Rust, in a folder (this one if none is given), with the suite's environment (its databases, and what a step sets)
rust_run() {
  local passed=() name dir=$HERE
  [ "${1:-}" = -C ] && { dir=$2; shift 2; }
  for name in $(compgen -e | grep -E '^(ROWSTILE_[A-Z_]+|CONFORMANCE_[A-Z_]+)$'); do passed+=(-e "$name"); done
  docker run --rm --network host --user "$(id -u):$(id -g)" -e HOME=/tmp -e CARGO_HOME="$CACHE/cargo" \
    -e CARGO_TARGET_DIR="$CACHE/target" -e CARGO_TERM_COLOR=never -e PYTHONDONTWRITEBYTECODE=1 "${passed[@]}" \
    -v "$ROOT:$ROOT" -v "$T:$T" -v "$CACHE:$CACHE" -v "$CONFORMANCE_COVERAGE:$CONFORMANCE_COVERAGE" -w "$dir" \
    "$IMAGE" "$@"
}
SDK=$ROOT/sdk/rust
rc=0
# the SDK's own checks: its layout, Clippy on each set of its features (pedantic, every warning an error), the
# examples in its documentation; the app's layout and Clippy
rust_run -C "$SDK" bash -c 'cargo fmt --check && cargo clippy --locked --all-targets --all-features -- -D warnings &&
  cargo clippy --locked --no-default-features -- -D warnings &&
  cargo clippy --locked --no-default-features --features sqlx -- -D warnings &&
  cargo test --locked --doc --all-features && cd "$0" && cargo fmt --check &&
  cargo clippy --locked --all-targets -- -D warnings' "$HERE" >"$T/lint.log" 2>&1 &&
  echo "ok    rustfmt and Clippy find nothing in the SDK and the app, and the SDK's examples compile" ||
  { cat "$T/lint.log"; echo "FAIL  rustfmt, Clippy or the SDK's examples"; rc=1; }
# the SDK as crates.io would have it: its package (cargo package builds what it holds), unpacked, and the app built
# on it, the server among its programs (check 13's)
VERSION=$(sed -n 's/^version = "\(.*\)"$/\1/p' "$SDK/Cargo.toml" | head -1)
rust_run -C "$SDK" cargo package --locked --allow-dirty >"$T/package.log" 2>&1 &&
  mkdir -p "$T/crate" && tar -xzf "$CACHE/target/package/rowstile-$VERSION.crate" -C "$T/crate" &&
  cp -r . "$T/app" && sed -i "s|path = \"../../sdk/rust\"|path = \"$T/crate/rowstile-$VERSION\"|" "$T/app/Cargo.toml" &&
  rust_run -C "$T/app" cargo build --locked --bins >>"$T/package.log" 2>&1 &&
  echo "ok    the SDK's package, rowstile $VERSION, builds, and the app builds on it" ||
  { cat "$T/package.log"; echo "FAIL  the SDK's package"; exit 1; }
docker rm -f -v "$NAME" >/dev/null 2>&1
docker run -d --name "$NAME" -e POSTGRES_PASSWORD=postgres -p "$PORT:5432" "rowstile:$PG" >/dev/null || exit 1
for _ in $(seq 60); do docker exec "$NAME" pg_isready -q -U postgres 2>/dev/null && break; sleep 1; done
sleep 2
# the migration role owns the databases: not a superuser, as on managed Postgres (CREATEDB: a test database per binary)
docker exec "$NAME" psql -q -U postgres -c "CREATE ROLE conf_owner LOGIN PASSWORD 'owner' CREATEROLE CREATEDB" \
  -c "ALTER ROLE conf_owner SET createrole_self_grant = 'set, inherit'" -c "CREATE DATABASE conf OWNER conf_owner" \
  -c "CREATE DATABASE conf_tests OWNER conf_owner" >/dev/null || exit 1
export ROWSTILE_OWNER_DSN="postgres://conf_owner:owner@localhost:$PORT/conf"
export ROWSTILE_TESTS_URL="postgres://conf_owner:owner@localhost:$PORT/conf_tests"
export ROWSTILE_CLI=$ROOT/core/cli/rowstile_cli.py
APP_PORT=$PORT
if [ "${POOLER:-}" = pgbouncer ]; then          # the app through PgBouncer in transaction mode (../pooler.sh)
  source ../pooler.sh
  APP_PORT=$((PORT + 2))
  pooler_start "$NAME" "$APP_PORT" conf_app:app || exit 1
fi
APP="postgres://conf_app:app@localhost:$APP_PORT"
BIN=$CACHE/target/debug
# 11: migrated by sqlx's migrator as the owner (the migrate program: sqlx-cli's library), then the policy's tests,
# then sqlx's list of migrations: each installed, as its file is (sqlx keeps each one's checksum)
rust_run "$BIN/migrate" "$ROWSTILE_OWNER_DSN" >"$T/migrate.log" 2>&1 || { cat "$T/migrate.log"; echo "FAIL  11: sqlx migrate"; exit 1; }
python3 "$ROWSTILE_CLI" test >"$T/policy-tests.log" 2>&1 &&
  echo "ok    11: a fresh database, migrated, passes the policy's tests" || { cat "$T/policy-tests.log"; echo "FAIL  11: policy tests"; rc=1; }
rust_run "$BIN/migrate" --info "$ROWSTILE_OWNER_DSN" >"$T/info.log" 2>&1 &&
  [ "$(grep -c ': installed$' "$T/info.log")" = "$(ls migrations/*.sql | wc -l)" ] && [ "$(wc -l <"$T/info.log")" = "$(ls migrations/*.sql | wc -l)" ] &&
  echo "ok    11: ... and sqlx's list of migrations shows each one installed, as its file is" || { cat "$T/info.log"; echo "FAIL  11: sqlx migrate info"; rc=1; }
python3 "$ROWSTILE_CLI" migrate --check >/dev/null &&
  echo "ok    the policy's lock file is up to date" || { echo "FAIL  rowstile migrate --check"; rc=1; }
# 12: the test database, migrated the same way (each test binary copies it)
rust_run "$BIN/migrate" "$ROWSTILE_TESTS_URL" >"$T/migrate-tests.log" 2>&1 || { cat "$T/migrate-tests.log"; echo "FAIL  12: sqlx migrate, on the test database"; exit 1; }
# 13: the app refuses to start on a connection that skips row-level security (here, the owner's), and starts on
# the app role's
ROWSTILE_APP_URL=$ROWSTILE_OWNER_DSN timeout 60 docker run --rm --network host -e ROWSTILE_APP_URL -e ADDR="localhost:$WEB" \
  -v "$CACHE:$CACHE" "$IMAGE" "$BIN/server" >"$T/server-owner.log" 2>&1
if [ $? = 1 ] && grep -q "an owner skips row-level security" "$T/server-owner.log"; then
  echo "ok    13: the app refuses to start on the owner's connection"
else cat "$T/server-owner.log"; echo "FAIL  13: the app started on the owner's connection"; rc=1; fi
docker run -d --name "$NAME-server" --network host -e ROWSTILE_APP_URL="$APP/conf" -e ADDR="localhost:$WEB" \
  -v "$CACHE:$CACHE" "$IMAGE" "$BIN/server" >/dev/null
for _ in $(seq 30); do curl -sf "http://localhost:$WEB/projects" >"$T/projects.json" && break; sleep 1; done
[ "$(cat "$T/projects.json" 2>/dev/null)" = "[]" ] &&
  echo "ok    13: ... and starts on the app role's" || { docker logs "$NAME-server"; echo "FAIL  13: the app didn't start on the app role's connection"; rc=1; }
docker rm -f "$NAME-server" >/dev/null 2>&1
# the other checks, each test binary on its own copy of the test database, one test at a time; what they run of
# the SDK measured (cargo-llvm-cov, its builds beside the others'), and reported for the SDK's files alone
rust_run cargo llvm-cov clean --workspace >/dev/null 2>&1  # what an earlier run measured
ROWSTILE_APP_URL="$APP/conf_tests" rust_run cargo llvm-cov --locked --no-report --dep-coverage rowstile test --tests -- \
  --test-threads=1 --nocapture "$@" \
  >"$T/test.log" 2>&1
tested=$?
grep -E '^(ok    |FAIL  )' "$T/test.log"
[ $tested = 0 ] || { cat "$T/test.log"; echo "FAIL  cargo test"; rc=1; }
# 12: ... and the migrated test database is left as it was
users=$(docker exec "$NAME" psql -U conf_owner -d conf_tests -Atc "SELECT count(*) FROM app.users")
[ "$users" = 0 ] && echo "ok    12: ... the migrated test database is left as it was" || { echo "FAIL  12: conf_tests has $users users"; rc=1; }
# 9 and 14 compile Rust: the names rowstile client writes, a wrong one, and a policy change shipped as the next
# migration (on a copy of the migrated test database of its own)
docker exec "$NAME" psql -q -U conf_owner -d postgres -c "CREATE DATABASE conf_change TEMPLATE conf_tests" &&
  docker exec "$NAME" psql -q -U conf_owner -d conf_change -c "INSERT INTO app.users VALUES (1, 'ann'), (2, 'bo')" \
    -c "INSERT INTO app.inbox (id, sender_id, recipient_id, body) VALUES (1, 1, 2, 'hi')" >/dev/null || exit 1
ROWSTILE_CHANGE_URL="postgres://conf_owner:owner@localhost:$PORT/conf_change" ROWSTILE_CHANGE_APP_URL="$APP/conf_change" \
  rust_run bash tests/compile.sh "$T" || rc=1
# (--dep-coverage measures the SDK, a dependency of the app; the report leaves out the app's own files)
rust_run cargo llvm-cov report --ignore-filename-regex '/integrations/axum/' >"$CONFORMANCE_COVERAGE/report.txt" 2>&1
cat "$CONFORMANCE_COVERAGE/report.txt"
if [ $# -gt 0 ]; then
  echo "(some of the checks ran: the SDK's coverage isn't judged)"
elif [ $tested = 0 ] && grep -qE '^TOTAL( +[0-9]+){2} +100\.00%( +[0-9]+){2} +100\.00%( +[0-9]+){2} +100\.00%' "$CONFORMANCE_COVERAGE/report.txt"; then
  echo "ok    the checks run every line and region of the Rust SDK (and every function; branches need a nightly Rust)"
else
  echo "FAIL  lines or regions of the Rust SDK no check runs (the report above: $CONFORMANCE_COVERAGE/report.txt)"; rc=1
fi
exit $rc

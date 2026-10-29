#!/bin/bash
# migration_tools.sh: the migrations rowstile migrate writes for goose, dbmate and Flyway, run by each tool itself
# (tests/migrations.sh checks their files' names and markers; only the tools can say they run them): the docs app's
# policy, then a change, written in an empty folder (versions by the time) and in one the app numbers by hand (the
# next numbers), applied by the tool as the tables' owner; then the app's next migration, numbered after rowstile's,
# runs too (goose, dbmate --strict and Flyway refuse one below a version applied already; Django's depends on it).
# On the machine, beside a Postgres of its own (the image core/Dockerfile names, on a port Docker picks, removed
# after): docker, python3, curl and sha256sum. goose and dbmate are their releases' Linux x86-64 binaries, checked
# against their hashes, run in the Postgres container; Flyway is its image; Django runs in Python's image beside it,
# its release and psycopg's installed by version. Nightly (nightly.yml's tools job).
#   bash core/tests/migration_tools.sh
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
CORE=$(dirname "$HERE")
GOOSE=v3.29.0 GOOSE_SHA=cc56e2f75532a4dd52f5ef2d31db0121e91079a9c2617bc0ad4e04e2d41c228b
DBMATE=v2.37.0 DBMATE_SHA=f855e99a0f0a81322014bf686b1cb820d2b4d8074e4eadafd64b851b80ecb15a
FLYWAY=flyway/flyway:13.10.3-alpine@sha256:f6358224a41866888c3341b9c1e286fa2be8e1ccc18270b219dc0e8ea26e789f
PYTHON=python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1
DJANGO="django==6.1.2 psycopg[binary]==3.3.6"
PG=$(sed -n 's/^FROM \(postgres:16@sha256:[0-9a-f]*\) AS pg16$/\1/p' "$CORE/Dockerfile")
NAME="rowstile-migration-tools-$$"
T=$(mktemp -d)
trap 'docker rm -f -v "$NAME" "$NAME-python" >/dev/null 2>&1; rm -rf "$T"' EXIT
fails=0 passed=0
ok() { echo "ok    $1"; passed=$((passed + 1)); }
bad() { echo "FAIL  $1${2:+: $2}"; fails=$((fails + 1)); }

fetch() {  # fetch <url> <sha256> <file>
  curl -fsSL -o "$3" "$1" && echo "$2  $3" | sha256sum -c --quiet - && chmod +x "$3"
}
fetch "https://github.com/pressly/goose/releases/download/$GOOSE/goose_linux_x86_64" "$GOOSE_SHA" "$T/goose" &&
  fetch "https://github.com/amacneil/dbmate/releases/download/$DBMATE/dbmate-linux-amd64" "$DBMATE_SHA" "$T/dbmate" ||
  { echo "FAIL  the tools' binaries: not downloaded, or not the bytes their releases published"; exit 1; }
docker image inspect "$FLYWAY" >/dev/null 2>&1 || docker pull -q "$FLYWAY" >/dev/null || exit 1
docker run -d --name "$NAME" -e POSTGRES_HOST_AUTH_METHOD=trust -v "$CORE:/core:ro" "$PG" >/dev/null || exit 1
for _ in $(seq 60); do  # past the image's first start (initdb, then a restart)
  docker exec "$NAME" pg_isready -q -h 127.0.0.1 -U postgres 2>/dev/null && break
  sleep 1
done
docker exec -e PGHOST=/var/run/postgresql -e PGUSER=postgres "$NAME" bash /core/tests/make_owner.sh || exit 1
docker cp -q "$T/goose" "$NAME:/usr/local/bin/goose" && docker cp -q "$T/dbmate" "$NAME:/usr/local/bin/dbmate" || exit 1
PSQL() { docker exec -i -e PGUSER=authz_owner "$NAME" psql -X -q -At -v ON_ERROR_STOP=1 "$@"; }
URL="postgres://authz_owner@localhost:5432"

# run <tool> <folder> <database>: the tool applies what the folder holds that the database hasn't
run() {
  local tool=$1 dir=$2 db=$3
  docker exec "$NAME" rm -rf /w && docker cp -q "$dir" "$NAME:/w" || return 1
  case $tool in
    goose) docker exec "$NAME" goose -dir /w postgres "$URL/$db?sslmode=disable" up;;
    dbmate) docker exec "$NAME" dbmate --url "$URL/$db?sslmode=disable" --migrations-dir /w --no-dump-schema up --strict;;
    flyway) docker run --rm --network "container:$NAME" -v "$dir:/flyway/sql:ro" "$FLYWAY" \
      "-url=jdbc:postgresql://localhost:5432/$db" -user=authz_owner -locations=filesystem:/flyway/sql migrate;;
  esac
}
# a migration of the app's own, as the tool's own command would write it
by_hand() {
  local tool=$1 file=$2 table=$3
  case $tool in
    goose) printf -- '-- +goose Up\nCREATE TABLE %s (id int);\n' "$table" > "$file";;
    dbmate) printf -- '-- migrate:up\nCREATE TABLE %s (id int);\n\n-- migrate:down\n' "$table" > "$file";;
    flyway) printf 'CREATE TABLE %s (id int);\n' "$table" > "$file";;
  esac
}

for tool in goose dbmate flyway; do
  for folder in empty numbered; do
    W="$T/$tool-$folder" db="tools_${tool}_$folder"
    mkdir -p "$W/m"
    sed '/^test$/,$d' "$CORE/example/docs.authz" > "$W/policy.authz"
    PSQL -d postgres -c "CREATE DATABASE $db" && PSQL -d "$db" < "$CORE/example/app_schema.sql" > /dev/null ||
      { bad "$tool, $folder folder: the database"; continue; }
    p=; [ $tool = flyway ] && p=V
    s=_; [ $tool = flyway ] && s=__
    want="$p[0-9]{14}${s}authz_first\.sql $p[0-9]{14}${s}authz_print\.sql"  # by the time
    if [ $folder = numbered ]; then
      case $tool in goose) n=(00001 00002 00003 00004);; dbmate) n=(001 002 003 004);; flyway) n=(1 2 3 4);; esac
      first=$p${n[0]}${s}app.sql next=$p${n[3]}${s}app_next.sql
      want="$first $p${n[1]}${s}authz_first\.sql $p${n[2]}${s}authz_print\.sql"
      by_hand $tool "$W/m/$first" app_first
    fi
    out=$( cd "$W" && python3 "$CORE/cli/rowstile_cli.py" migrate policy.authz --tool $tool --dir m --name first 2>&1 ) &&
      sed -i 's/^  can view  = edit or viewer$/&\n  can print = edit/' "$W/policy.authz" &&
      out=$( cd "$W" && python3 "$CORE/cli/rowstile_cli.py" migrate policy.authz --tool $tool --dir m --name print 2>&1 ) ||
      { bad "$tool, $folder folder: rowstile migrate" "$out"; continue; }
    files=$(ls "$W/m" | grep -v '\.conf$' | tr '\n' ' ') files=${files% }
    [[ $files =~ ^$want$ ]] && ok "$tool, a$([ $folder = empty ] && echo "n") $folder folder: $files" ||
      bad "$tool, $folder folder: the files' names" "$files"
    out=$(run $tool "$W/m" "$db" 2>&1)
    got=$(PSQL -d "$db" -c "SELECT authz.verify(), count(*) FROM authz.policy_versions" 2>&1)
    [ "$got" = "t|2" ] && ok "... which $tool runs, both" ||
      { bad "$tool, $folder folder: the tool's run" "$got
$out"; continue; }
    [ $folder = numbered ] || continue
    by_hand $tool "$W/m/$next" app_next
    out=$(run $tool "$W/m" "$db" 2>&1)
    [ "$(PSQL -d "$db" -c "SELECT to_regclass('app_next') IS NOT NULL")" = t ] &&
      ok "... and then the app's next migration, $next, numbered after them" || bad "$tool: the app's next migration" "$out"
  done
done
# Django: the app's migrations folder (a package), its migrations run by Django's migrate, in Python's image on the
# Postgres container's network
docker run -d --name "$NAME-python" --network "container:$NAME" "$PYTHON" sleep infinity >/dev/null &&
  docker exec "$NAME-python" pip install -q --root-user-action=ignore --disable-pip-version-check $DJANGO ||
  { echo "FAIL  django: $DJANGO, in $PYTHON"; exit 1; }
for folder in empty numbered; do
  W="$T/django-$folder" db="tools_django_$folder" M="$T/django-$folder/app/migrations"
  mkdir -p "$M" && : > "$W/app/__init__.py" && : > "$M/__init__.py"
  printf '%s\n' 'import os' 'SECRET_KEY = "migration tools"' 'USE_TZ = True' 'INSTALLED_APPS = ["app"]' \
    'DATABASES = {"default": {"ENGINE": "django.db.backends.postgresql", "NAME": os.environ["DB"], "USER": "authz_owner", "HOST": "localhost"}}' \
    > "$W/settings.py"
  sed '/^test$/,$d' "$CORE/example/docs.authz" > "$W/policy.authz"
  PSQL -d postgres -c "CREATE DATABASE $db" && PSQL -d "$db" < "$CORE/example/app_schema.sql" > /dev/null ||
    { bad "django, $folder folder: the database"; continue; }
  want="0001_authz_first.py 0002_authz_print.py"
  # a migration of the app's own, as makemigrations would write one: before rowstile's, and after them
  django_migration() {  # django_migration <file> <dependency> <table>
    printf '%s\n' 'from django.db import migrations' '' '' 'class Migration(migrations.Migration):' \
      "    dependencies = [$2]" "    operations = [migrations.RunSQL(\"CREATE TABLE $3 (id int)\")]" > "$1"
  }
  if [ $folder = numbered ]; then
    want="0001_app.py 0002_authz_first.py 0003_authz_print.py"
    django_migration "$M/0001_app.py" "" app_first
  fi
  out=$( cd "$W" && python3 "$CORE/cli/rowstile_cli.py" migrate policy.authz --tool django --dir app/migrations --name first 2>&1 ) &&
    sed -i 's/^  can view  = edit or viewer$/&\n  can print = edit/' "$W/policy.authz" &&
    out=$( cd "$W" && python3 "$CORE/cli/rowstile_cli.py" migrate policy.authz --tool django --dir app/migrations --name print 2>&1 ) ||
    { bad "django, $folder folder: rowstile migrate" "$out"; continue; }
  files=$(ls "$M" | grep '\.py$' | grep -v '^__init__' | tr '\n' ' ') files=${files% }
  [ "$files" = "$want" ] && ok "django, a$([ $folder = empty ] && echo "n") $folder folder: $files" ||
    bad "django, $folder folder: the files' names" "$files"
  run_django() {
    docker exec "$NAME-python" rm -rf /w && docker cp -q "$W" "$NAME-python:/w" &&
      docker exec -e DB="$db" -e PYTHONPATH=/w -w /w "$NAME-python" python -m django migrate --settings settings --verbosity 0
  }
  out=$(run_django 2>&1)
  got=$(PSQL -d "$db" -c "SELECT authz.verify(), count(*) FROM authz.policy_versions" 2>&1)
  [ "$got" = "t|2" ] && ok "... which django runs, both" || { bad "django, $folder folder: the tool's run" "$got
$out"; continue; }
  [ $folder = numbered ] || continue
  django_migration "$M/0004_app_next.py" '("app", "0003_authz_print")' app_next
  out=$(run_django 2>&1)
  [ "$(PSQL -d "$db" -c "SELECT to_regclass('app_next') IS NOT NULL")" = t ] &&
    ok "... and then the app's next migration, 0004_app_next.py, after them" || bad "django: the app's next migration" "$out"
done
echo "--- passed: $passed, failed: $fails"
[ $fails -eq 0 ]

#!/bin/bash
# test.sh: the .NET SDK's conformance suite (a preview), against a fresh Postgres in Docker.
#   integrations/aspnetcore/test.sh            # PG_MAJOR=17 or 18 for another version; KEEP=1 keeps the database
#   POOLER=pgbouncer integrations/aspnetcore/test.sh     # the app through PgBouncer in transaction mode
#   integrations/aspnetcore/test.sh --filter-method '*Check_7*'   # some of the checks (xUnit's options)
# Needs the .NET 10 SDK (dotnet), python3 and Docker. The SDK's packages are packed from sdk/dotnet into .feed, which
# NuGet.config makes the only source of Rowstile*: the app runs this checkout's SDK, as a package.
# Check 11 first: a fresh database, migrated with EF Core's migrations (rowstile's policy is one of them), then the
# policy's tests, then EF Core's own diff, which must show no change. Then the app is started on the owner's
# connection, which it must refuse (13), and the other checks run (xUnit, each test collection on a copy of its own
# of the migrated test database: 12), measured by coverlet.
set -u
cd "$(dirname "$0")"
PG=${PG_MAJOR:-16}
NAME=rowstile-conformance-aspnetcore
PORT=${CONFORMANCE_PORT:-25510}
export PYTHON=${PYTHON:-python3}
export CONFORMANCE_HERE=$PWD DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1
command -v dotnet >/dev/null || { echo "FAIL  no dotnet: this suite needs the .NET 10 SDK"; exit 1; }
docker build -q -t "rowstile:$PG" --build-arg "PG_MAJOR=$PG" -f ../../core/Dockerfile ../.. >/dev/null || exit 1
docker rm -f -v "$NAME" >/dev/null 2>&1
docker run -d --name "$NAME" -e POSTGRES_PASSWORD=postgres -p "$PORT:5432" "rowstile:$PG" >/dev/null || exit 1
LOG=$(mktemp -d)
done_() {
  [ -n "${KEEP:-}" ] || { [ "${POOLER:-}" = pgbouncer ] && pooler_stop "$NAME"; docker rm -f -v "$NAME" >/dev/null 2>&1; }
  rm -rf "$LOG"
}
trap done_ EXIT
for _ in $(seq 60); do docker exec "$NAME" pg_isready -q -U postgres 2>/dev/null && break; sleep 1; done
sleep 2
# the migration role owns the databases: not a superuser, as on managed Postgres (CREATEDB: a test database per collection)
docker exec "$NAME" psql -q -U postgres -c "CREATE ROLE conf_owner LOGIN PASSWORD 'owner' CREATEROLE CREATEDB" \
  -c "ALTER ROLE conf_owner SET createrole_self_grant = 'set, inherit'" -c "CREATE DATABASE conf OWNER conf_owner" \
  -c "CREATE DATABASE conf_tests OWNER conf_owner" >/dev/null || exit 1
# the command's (a URL), and Npgsql's (key=value), for the same owner; Npgsql hides the database's DETAIL, which says
# why a write was refused, unless it is asked to include it
export ROWSTILE_OWNER_DSN="postgresql://conf_owner:owner@localhost:$PORT/conf"
NPGSQL="Host=localhost;Include Error Detail=true"
export ROWSTILE_OWNER_CONN="$NPGSQL;Port=$PORT;Username=conf_owner;Password=owner;Database=conf"
export ROWSTILE_TESTS_CONN="$NPGSQL;Port=$PORT;Username=conf_owner;Password=owner;Database=conf_tests"
APP_PORT=$PORT
if [ "${POOLER:-}" = pgbouncer ]; then          # the app through PgBouncer in transaction mode (../pooler.sh)
  source ../pooler.sh
  APP_PORT=$((PORT + 2))
  pooler_start "$NAME" "$APP_PORT" conf_app:app || exit 1
fi
export ROWSTILE_APP_CONN="$NPGSQL;Port=$APP_PORT;Username=conf_app;Password=app;Database=conf"
# the SDK, packed from this checkout (its version is the repository's: a package of the same version a restore
# took earlier is left out of NuGet's cache, so this one is taken)
VERSION=$(sed -n 's:.*<RowstileVersion>\(.*\)</RowstileVersion>.*:\1:p' ../../sdk/dotnet/Version.props)
PACKAGES=$(dotnet nuget locals global-packages --list | sed 's/^global-packages: //')
for p in rowstile rowstile.entityframeworkcore rowstile.aspnetcore; do rm -rf "${PACKAGES:?}/$p/$VERSION"; done
rm -rf .feed
dotnet pack ../../sdk/dotnet/Rowstile.slnx -o .feed >"$LOG/pack.log" 2>&1 || { cat "$LOG/pack.log"; echo "FAIL  the SDK doesn't build"; exit 1; }
dotnet tool restore >"$LOG/tool.log" 2>&1 || { cat "$LOG/tool.log"; exit 1; }
dotnet build Tests >"$LOG/build.log" 2>&1 || { cat "$LOG/build.log"; echo "FAIL  the app or its tests don't build"; exit 1; }
EF="dotnet ef --project App --no-build"
rc=0
$EF database update >"$LOG/migrate.log" 2>&1 || { cat "$LOG/migrate.log"; echo "FAIL  11: dotnet ef database update"; exit 1; }
$PYTHON ../../core/cli/rowstile_cli.py test >"$LOG/policy-tests.log" 2>&1 &&
  echo "ok    11: a fresh database, migrated, passes the policy's tests" || { cat "$LOG/policy-tests.log"; echo "FAIL  11: policy tests"; rc=1; }
$EF migrations has-pending-model-changes >"$LOG/diff.log" 2>&1 &&
  echo "ok    11: ... and EF Core's own diff shows no change" || { cat "$LOG/diff.log"; echo "FAIL  11: dotnet ef migrations has-pending-model-changes"; rc=1; }
$PYTHON ../../core/cli/rowstile_cli.py migrate --check >/dev/null &&
  echo "ok    the policy's lock file is up to date" || { echo "FAIL  rowstile migrate --check"; rc=1; }
# 12: the framework's test database, migrated the same way (each test collection copies it)
ROWSTILE_OWNER_CONN=$ROWSTILE_TESTS_CONN $EF database update >"$LOG/migrate-tests.log" 2>&1 || { cat "$LOG/migrate-tests.log"; exit 1; }
# 13: the app refuses to start on a connection that skips row-level security (here, the owner's)
# (it stops on the error it can't start with, which .NET ends with an abort: the shell's word for that, too, goes to
# the log)
{ ROWSTILE_APP_CONN=$ROWSTILE_OWNER_CONN timeout 60 dotnet App/bin/Debug/net10.0/App.dll --urls http://127.0.0.1:0 >"$LOG/owner.log" 2>&1; } 2>>"$LOG/owner.log"
started=$?
if [ $started != 0 ] && [ $started != 124 ] && grep -q "an owner skips row-level security" "$LOG/owner.log"; then
  echo "ok    13: the app refuses to start on the owner's connection"
else cat "$LOG/owner.log"; echo "FAIL  13: the app started on the owner's connection"; rc=1; fi
# What the checks run of the SDK (sdk/dotnet, its three packages), lines and branches (coverlet): the report is kept in
# CONFORMANCE_COVERAGE (a folder of its own if not given), and printed
COVERAGE=${CONFORMANCE_COVERAGE:-$(mktemp -d)}
mkdir -p "$COVERAGE" && rm -f "$COVERAGE"/coverage*.xml "$COVERAGE/report.txt"
# (Tests/testconfig.json names the packages: coverlet leaves a package out unless it is named)
dotnet Tests/bin/Debug/net10.0/Tests.dll --results-directory "$COVERAGE" --coverlet --output Detailed "$@" >"$LOG/tests.log" 2>&1
tests=$?
# a line for each test, as the other suites print theirs: Check_7_hidden_is_404 is "ok    7: hidden is 404", the SDK's
# own by their words, sorted by number; the whole log when one failed
sed -nE 's/^\s*(passed|failed) Conformance\.Tests\.[A-Za-z0-9]+\.([A-Za-z0-9_]+) \(.*$/\1 \2/p' "$LOG/tests.log" |
  sed -E 's/^passed /ok    /; s/^failed /FAIL  /; s/Check_([0-9]+)_([0-9]+)_/\1, \2: /; s/Check_([0-9]+)_/\1: /; s/_/ /g' |
  awk '{ print ($2 ~ /^[0-9]/ ? $2 + 0 : 99) "\t" $0 }' | sort -s -n -k1,1 | cut -f2-
[ $tests = 0 ] || { cat "$LOG/tests.log"; rc=1; }
$PYTHON - "$COVERAGE" >"$COVERAGE/report.txt" <<'PY'
import glob, os, sys
import xml.etree.ElementTree as ET
# every line and branch of the SDK's sources (sdk/dotnet), as coverlet measured them: each file, and what no check ran
found = sorted(glob.glob(os.path.join(sys.argv[1], "coverage*.xml")), key=os.path.getmtime)
if not found:
    print("no coverage report"); sys.exit(1)
import re
lines: dict[str, dict[int, tuple[int, int, int]]] = {}  # file: {line: (hits, branches taken, branches)}
for cls in ET.parse(found[-1]).getroot().iter("class"):
    name = cls.get("filename", "")
    if not name.startswith("sdk/dotnet/"):
        continue  # the conformance app's own
    for line in cls.iter("line"):
        n, hits = int(line.get("number", 0)), int(line.get("hits", 0))
        m = re.search(r"\((\d+)/(\d+)\)", line.get("condition-coverage", ""))
        taken, of = (int(m.group(1)), int(m.group(2))) if m else (0, 0)
        was = lines.setdefault(name, {}).get(n, (0, 0, 0))
        lines[name][n] = (max(was[0], hits), max(was[1], taken), max(was[2], of))
bad = 0
for name, ls in sorted(lines.items()):
    missed = [n for n, (h, _, _) in sorted(ls.items()) if h == 0]
    partial = [f"{n} ({t}/{o})" for n, (h, t, o) in sorted(ls.items()) if h and t < o]
    bad += len(missed) + len(partial)
    short = name.removeprefix("sdk/dotnet/")
    print(f"{short:52} {len(ls) - len(missed):4}/{len(ls):<4} lines"
          + (f"  not run: {missed}" if missed else "") + (f"  branches not taken: {partial}" if partial else ""))
sys.exit(1 if bad else 0)
PY
covered=$?
cat "$COVERAGE/report.txt"
if [ $# -gt 0 ]; then
  echo "(some of the checks ran: the SDK's coverage isn't judged)"
elif [ $covered = 0 ]; then
  echo "ok    the checks run every line and branch of the .NET SDK"
else
  echo "FAIL  lines or branches of the .NET SDK no check runs (the report above: $COVERAGE/report.txt)"; rc=1
fi
exit $rc

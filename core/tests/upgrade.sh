#!/bin/bash
# upgrade.sh: databases the release before this one made, upgraded by this checkout's command. The release before
# (the newest on PyPI older than this version: tests/previous_release.py installs it) makes the docs app's database
# the ways an app keeps one: a development database it pushes to, as rowstile dev does; databases it applies the
# policy to, for an app without migrations (two: one for each way docs/operations.md upgrades them); and one the
# migrations and lock file its rowstile migrate writes set up. Under it the app shares, makes an API key and asks
# for access. Then this checkout's command upgrades each as the app would: push; apply, or reapply (the policy the
# database holds); and the next migration from the old lock file. Each database then holds what applying this
# version on a new one leaves, the policy's tests and the docs scenario pass, and what the app made before is still
# there and still in force. Where PyPI can't be reached, it says so and skips.
# Right after a release this version makes just what the release before made (a new version alone is no
# migration): then migrate has nothing to write, and that database stays as the release before's migrations left
# it, which must still be what this version leaves on a new one. The checks are as many either way.
#   PGHOST=... PGUSER=... tests/upgrade.sh
set -u
cd "$(dirname "$0")/.."
CORE=$PWD
DB=authz_upgrade
WAYS="push apply reapply migrate"
fails=0
ok() { echo "ok    $1"; }
bad() { echo "FAIL  $1${2:+: $2}"; fails=$((fails + 1)); }
T=$(mktemp -d)
P="$T/app"   # the app's folder: its policy, its tests, rowstile.toml, the migrations and the lock file
mkdir -p "$P"
cleanup() { rm -rf "$T"; for w in $WAYS fresh; do dropdb --if-exists "${DB}_$w" 2>/dev/null; done; }
trap cleanup EXIT

echo "-- the release before this one, from PyPI"
out=$(python3 tests/previous_release.py "$T/old" 2>&1); rc=$?
if [ $rc -eq 2 ]; then echo "skip  $out"; echo "upgrade: skipped"; exit 0; fi
[ $rc -eq 0 ] || { bad "the release before, from PyPI" "$out"; echo "upgrade: 1 failed"; exit 1; }
OLD_VERSION=$out
NEW_VERSION=$(python3 -c 'import authzlib; print(authzlib.__version__)')
BUILD=$(python3 -c 'import authzlib; print(authzlib.BUILD)')
# each command runs in the app's folder; the old one with nothing of this checkout's on its path (-P)
OLD() { ( cd "$P" && "$T/old/bin/python" -P -m rowstile "$@" ); }
NEW() { ( cd "$P" && python3 "$CORE/cli/rowstile_cli.py" "$@" ); }
case "$(OLD --version 2>&1)" in *" $OLD_VERSION "*)
  ok "the release before $NEW_VERSION, $OLD_VERSION, installed from PyPI in a virtual environment of its own";;
  *) bad "the release before's command" "$(OLD --version 2>&1)";; esac

cp example/docs.authz "$P/policy.authz"
cp example/docs.test.authz "$P/tests.authz"
printf 'policy = "policy.authz"\ndatabase = "dbname=%s"\n[migrations]\ntool = "sql"\ndir = "migrations"\n' "${DB}_migrate" > "$P/rowstile.toml"
python3 compile_policy.py example/docs.authz --tests > "$T/docs_tests.sql" || exit 1
fresh() { dropdb --if-exists "$1" 2>/dev/null; createdb "$1" || exit 1
  PGOPTIONS="-c client_min_messages=error" psql -X -q -v ON_ERROR_STOP=1 -d "$1" -f example/app_schema.sql >/dev/null || exit 1; }
# every migration in the folder the database hasn't taken yet, in order, each in one transaction (as the tools do)
migrate_db() {
  local f out
  touch "$T/applied"
  for f in $(ls "$P"/migrations/*.sql | sort); do
    grep -qx "$f" "$T/applied" && continue
    out=$(PGOPTIONS="-c client_min_messages=error" psql -X -q -1 -v ON_ERROR_STOP=1 -d "$1" -f "$f" 2>&1) || { echo "$f: $out"; return 1; }
    echo "$f" >> "$T/applied"
  done
}
PSQL() { psql -X -q -At -v ON_ERROR_STOP=1 -d "$1" "${@:2}"; }
# a statement as the app role, signed in as a user (the owner's session may set authz.user_id); the last line
as() { psql -X -q -At -d "$1" -c "SET ROLE app_user" -c "SET authz.user_id = $2" -c "$3" 2>&1 | tail -n 1; }
FILES="SELECT coalesce(string_agg(name, ', ' ORDER BY name), '-') FROM app.files"
# the audit trail's rows up to an id, each as the columns every release has written
AUDIT="SELECT string_agg(concat_ws(' ', id, at, action, object_type, object_id, relation, subject_type, subject_id, user_id), E'\n' ORDER BY id) FROM authz.audit"
# what the release before recorded, and the app's own state under it, per way
declare -A KEY REQ TRAIL LAST

echo "-- the databases the release before made"
fresh "${DB}_push"
out=$(OLD --db "dbname=${DB}_push" push 2>&1) || bad "push: the release before pushes to a new database" "$out"
for w in apply reapply; do
  fresh "${DB}_$w"
  out=$(OLD --db "dbname=${DB}_$w" apply 2>&1) || bad "$w: the release before applies the policy" "$out"
done
fresh "${DB}_migrate"
out=$(OLD migrate 2>&1) && [ -f "$P/policy.lock" ] && [ "$(ls "$P/migrations" | wc -l)" = 1 ] &&
  out=$(migrate_db "${DB}_migrate") ||
  bad "migrate: the release before writes the first migration and the lock file, and the migration applies" "$out"
head -n 1 "$P/policy.lock" | grep -qF " $OLD_VERSION" && cp "$P/policy.lock" "$T/old.lock" &&
  ok "migrate: the lock file names the release before, which wrote it" || bad "the old lock file" "$(head -n 1 "$P/policy.lock")"
for w in $WAYS; do
  db="${DB}_$w"
  [ "$(PSQL "$db" -c "SELECT version FROM authz.policy_versions ORDER BY id DESC LIMIT 1")" = "$OLD_VERSION" ] &&
    [ "$(PSQL "$db" -c "SELECT authz.verify()")" = t ] &&
    ok "$w: the release before made the database: it records its version, and its inheritance tables match a rebuild" ||
    bad "$w: what the release before made" "$(PSQL "$db" -c "SELECT version FROM authz.policy_versions ORDER BY id DESC LIMIT 1" 2>&1)"
  # what the app does under it: erin shares Company with Acme's members and offer-letter.pdf with dave (the two
  # shares the policy's tests count on), dave makes an API key and asks frank for a look at Globex
  out=$(psql -X -q -At -v ON_ERROR_STOP=1 -d "$db" -c "SET ROLE app_user" -c "SET authz.user_id = 5" \
          -c "SELECT authz.share('folder', 1, 'viewer', 'org', 1, 'member')" \
          -c "SELECT authz.share('file', 13, 'viewer', 'user', 4, '', now() + interval '1 day')" 2>&1) || bad "$w: erin's shares" "$out"
  REQ[$w]=$(as "$db" 4 "SELECT authz.request_access('folder', 20, 'viewer', 'asked before the upgrade', '7 days')")
  KEY[$w]=$(as "$db" 4 "SELECT authz.create_api_key('made before the upgrade', 'read')")
  LAST[$w]=$(PSQL "$db" -c "SELECT max(id) FROM authz.audit")
  TRAIL[$w]=$(PSQL "$db" -c "$AUDIT")
  made=$(PSQL "$db" -c "SELECT count(*) FROM authz.audit")
  [ "${KEY[$w]:0:3}" = ak_ ] && [ "${REQ[$w]}" -gt 0 ] 2>/dev/null && [ "$made" -ge 4 ] &&
    ok "$w: under the release before, the app shares, makes an API key and asks for access, and the audit trail has it" ||
    bad "$w: the app's state under the release before" "key ${KEY[$w]:0:12}..., request ${REQ[$w]}, $made audit rows"
done

echo "-- this version, on a new database (what each upgraded one must hold)"
fresh "${DB}_fresh"
out=$(NEW --db "dbname=${DB}_fresh" apply 2>&1) || bad "this version applies on a new database" "$out"

echo "-- this version's command upgrades each the way the app keeps it"
out=$(NEW --db "dbname=${DB}_push" push 2>&1)
[ "$out" = "$P/policy.authz: applied (the whole policy)" ] &&
  ok "push: a development database the release before pushed to takes the whole policy, another version having made it" ||
  bad "push over the release before's database" "$out"
out=$(NEW --db "dbname=${DB}_apply" apply 2>&1)
[ "$out" = "$P/policy.authz: applied" ] &&
  ok "apply: a database the release before applied is applied again, not taken as up to date" ||
  bad "apply over the release before's database" "$out"
out=$(NEW --db "dbname=${DB}_reapply" reapply 2>&1)
[ "$out" = "applied again" ] && ok "reapply: the policy a database the release before applied holds, applied again by this version" ||
  bad "reapply over the release before's database" "$out"
out=$(NEW migrate --check 2>&1); rc=$?
SAME=   # set when this version makes nothing differently: no migration to write
case "$out" in *"policy.authz has changes no migration has"*"rowstile $OLD_VERSION -> $NEW_VERSION: what the new version makes differently"*)
  [ $rc -eq 1 ] && ok "migrate --check, on the lock file the release before wrote: exit 1, the new version makes something differently" ||
    bad "migrate --check after the upgrade: exit" "$rc";;
  "nothing to migrate: "*) SAME=1
  [ $rc -eq 0 ] && ok "migrate --check, on the lock file the release before wrote: exit 0, the new version makes nothing differently" ||
    bad "migrate --check after the upgrade: exit" "$rc";;
  *) bad "migrate --check after the upgrade" "$out";; esac
before=$(ls "$P/migrations" | wc -l)
out=$(NEW migrate 2>&1); rc=$?
if [ -n "$SAME" ]; then
  [ $rc -eq 0 ] && [ "$(ls "$P/migrations" | wc -l)" = "$before" ] && cmp -s "$P/policy.lock" "$T/old.lock" &&
    ok "migrate writes no migration, a new version alone being none, and leaves the lock file the release before wrote" ||
    bad "migrate after the upgrade" "$out"
else
  [ $rc -eq 0 ] && [ "$(ls "$P/migrations" | wc -l)" -gt "$before" ] && ! cmp -s "$P/policy.lock" "$T/old.lock" &&
    ok "migrate writes the migration from the old lock file to this version, and the lock file after it" || bad "migrate after the upgrade" "$out"
fi
out=$(migrate_db "${DB}_migrate") &&
  ok "the migration applies on the database the release before's migrations set up" || bad "the upgrade's migration" "$out"
out=$(NEW migrate --check 2>&1); [ $? -eq 0 ] && ok "... and migrate --check passes again" || bad "migrate --check after migrating" "$out"

echo "-- each upgraded database"
# what differs from the new database: what tests/migrate_test.py compares a migration with applying whole by
# (functions and their privileges, views, triggers, row-level security policies, rowstile's tables and their rows),
# and the tables kept across applies (schema authz), which only an upgrade finds as an older version left them:
# their columns in order (a new one goes last in its CREATE TABLE, where its ADD COLUMN IF NOT EXISTS puts it on a
# database made before), with their types and defaults, and their constraints. The first line: how many objects
differs() {
  python3 - "$1" "$2" <<'PY'
import sys
sys.path.insert(0, "tests")
from migrate_test import objects, psql, snapshot
KEPT = r"""
SELECT 'column ' || c.oid::regclass::text || ' #' || row_number() OVER (PARTITION BY c.oid ORDER BY a.attnum) || ' '
       || a.attname || ' ' || format_type(a.atttypid, a.atttypmod) || CASE WHEN a.attnotnull THEN ' not null' ELSE '' END
       || coalesce(' default ' || pg_get_expr(d.adbin, d.adrelid), '')
FROM pg_class c JOIN pg_attribute a ON a.attrelid = c.oid LEFT JOIN pg_attrdef d ON d.adrelid = c.oid AND d.adnum = a.attnum
WHERE c.relnamespace = 'authz'::regnamespace AND c.relkind IN ('r', 'p') AND a.attnum > 0 AND NOT a.attisdropped
UNION ALL
SELECT 'table ' || conrelid::regclass::text || ' constraint ' || conname || ' ' || pg_get_constraintdef(oid)
FROM pg_constraint WHERE connamespace = 'authz'::regnamespace
ORDER BY 1;
"""
upgraded, new = (objects(snapshot(db) + "\n" + psql(db, KEPT)) for db in sys.argv[1:3])
print(len(new))
for k in sorted(set(upgraded) | set(new)):
    if k not in new:
        print(f"  only in the upgraded database: {k}")
    elif k not in upgraded:
        print(f"  only in the new one: {k}")
    elif upgraded[k] != new[k]:
        a, b = upgraded[k].split("\n"), new[k].split("\n")
        i = next((i for i, (x, y) in enumerate(zip(a, b)) if x != y), min(len(a), len(b)))
        print(f"  differs: {k}\n    upgraded: {a[i] if i < len(a) else '(end)'}\n    new:      {b[i] if i < len(b) else '(end)'}")
PY
}
for w in $WAYS; do
  db="${DB}_$w"
  # with no migration to run, the database the migrations set up still records the release before
  recorded=$BUILD whose="this version's"
  [ "$w" = migrate ] && [ -n "$SAME" ] && recorded=$OLD_VERSION whose="the release before's, which this version makes the same"
  [ "$(PSQL "$db" -c "SELECT version FROM authz.policy_versions ORDER BY id DESC LIMIT 1")" = "$recorded" ] &&
    [ "$(PSQL "$db" -c "SELECT authz.verify()")" = t ] &&
    ok "$w: the policy in force is $whose, and the inheritance tables match a rebuild" ||
    bad "$w: the policy in force after" "$(PSQL "$db" -c "SELECT version FROM authz.policy_versions ORDER BY id DESC LIMIT 1" -c "SELECT authz.verify()" 2>&1)"
  out=$(differs "$db" "${DB}_fresh" 2>&1)
  n=$(echo "$out" | head -n 1)
  [ "$(echo "$out" | wc -l)" = 1 ] && [ "$n" -gt 100 ] 2>/dev/null &&
    ok "$w: it holds what applying this version on a new database leaves ($n objects)" ||
    bad "$w: what applying this version on a new database leaves" "$(echo "$out" | head -n 24)"
  [ "$(PSQL "$db" -c "$AUDIT WHERE id <= ${LAST[$w]}")" = "${TRAIL[$w]}" ] &&
    ok "$w: the audit trail's rows from before are all there, as they were" ||
    bad "$w: the audit trail from before" "$(PSQL "$db" -c "$AUDIT WHERE id <= ${LAST[$w]}" 2>&1 | head -n 6)"
  [ "$(as "$db" 4 "$FILES")|$(as "$db" 3 "$FILES")" = "offer-letter.pdf|architecture.md, handbook.pdf, joint-plan.md" ] &&
    ok "$w: the shares made before still grant: dave reads offer-letter.pdf, and carol, of Acme, what is in Company" ||
    bad "$w: the shares made before" "$(as "$db" 4 "$FILES")|$(as "$db" 3 "$FILES")"
  out=$(psql -X -q -At -d "$db" -c "SET ROLE app_user" -c "BEGIN" -c "SELECT authz.login_key('${KEY[$w]}')" \
          -c "SELECT authz.uid() || ': ' || ($FILES) || ', may edit: ' || authz.can('file', 13, 'edit')" -c "COMMIT" 2>&1 | grep ': ')
  [ "$out" = "4: offer-letter.pdf, may edit: false" ] &&
    ok "$w: the API key made before still signs dave in, with its read-only scope" || bad "$w: the API key made before" "$out"
  out=$(as "$db" 6 "SELECT requester || ' ' || reason FROM authz.pending_requests() WHERE id = ${REQ[$w]}")
  [ "$out" = "4 asked before the upgrade" ] && ok "$w: the request made before is still pending, for frank to decide" ||
    bad "$w: the request made before" "$out"
  out=$(NEW --db "dbname=$db" test tests.authz 2>&1); rc=$?
  [ $rc -eq 0 ] && echo "$out" | grep -q "^policy tests passed" &&
    ok "$w: the policy's tests pass, those that count on the shares made before among them" || bad "$w: rowstile test" "$out"
done

echo "-- the docs scenario, on each upgraded database"
for w in $WAYS; do
  db="${DB}_$w"
  out=$(psql -X -q -v ON_ERROR_STOP=1 -v docs_tests="$T/docs_tests.sql" -d "$db" -f tests/scenario.sql 2>&1); rc=$?
  n=$(echo "$out" | grep -c 'ok  ')
  [ $rc -eq 0 ] && [ "$n" -gt 0 ] && ok "$w: the docs scenario passes ($n checks)" || bad "$w: the docs scenario" "$(echo "$out" | grep "FAIL\|ERROR" | head -n 5)"
  # the request made before, decided with this version's functions: dave gets what he asked for
  was=$(as "$db" 4 "SELECT authz.can('file', 15, 'view')")
  out=$(as "$db" 6 "SELECT authz.decide_request(${REQ[$w]}, true, 'approved after the upgrade')")
  [ "$was|$(as "$db" 4 "SELECT authz.can('file', 15, 'view')")" = "f|t" ] &&
    ok "$w: frank approves the request made before, and dave reads globex-plan.md" || bad "$w: approving the request made before" "$out"
done

[ $fails -eq 0 ] && echo "upgrade: all passed" || { echo "upgrade: $fails failed"; exit 1; }

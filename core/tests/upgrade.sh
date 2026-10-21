#!/bin/bash
# upgrade.sh: databases the release before this one made, upgraded by this checkout's command. The release before
# (the newest on PyPI older than this version, from 0.1.0-beta.1 on: tests/previous_release.py installs it; the beta
# started afresh, and a database an alpha before it made is applied from scratch) makes the docs app's database
# the ways an app keeps one: a development database it pushes to, as rowstile dev does; databases it applies the
# policy to, for an app without migrations (two: one for each way docs/operations.md upgrades them); and one the
# migrations and lock file its rowstile migrate writes set up. Under it the app shares, makes an API key and asks
# for access. Then this checkout's command upgrades each as the app would: push; apply, or reapply (the policy the
# database holds); and the next migration from the old lock file. Each database then holds what applying this
# version on a new one leaves, the policy's tests and the docs scenario pass, and what the app made before is still
# there and still in force. Where PyPI can't be reached, it says so and skips; where PyPI has no release from the
# beta on that is older than this version (until 0.1.0-beta.1 is out, and on the beta's own commit), it says so too,
# and skips with a last line of its own, which run_tests.sh records under a name of its own: no checks to count.
# Right after a release this version makes just what the release before made (a new version alone is no
# migration): then migrate has nothing to write, and that database stays as the release before's migrations left
# it, which must still be what this version leaves on a new one. The checks are as many either way.
# The docs app is the one the older release was released with (tests/docs_app.py: its copy in tests/docs_apps/ where
# it differs from core/example's, which an older release may not compile), on every database here, the new one too.
# --from VERSION: from that release in place of the one before. --world: also a world of data (tests/upgrade_world.py,
# as difftest makes the docs app's: shares in every state, links, moves, through the older release's own triggers
# and authz.share), in a database it applied and in one its migration set up; this version upgrades them by reapply
# and by the next migration, and each then answers every user, object and permission as the reference evaluator
# does and as a new database does, with this version applied whole on the same rows, and holds what that one holds.
# --every: from each release PyPI has that is older than this version (--from V --world for each, oldest first);
# each upgrades with as many checks, and the last line says so. Nightly; it needs PyPI too, and skips without it, or
# without a release from the beta on before this version.
#   PGHOST=... PGUSER=... tests/upgrade.sh [--from VERSION] [--world] | --every
set -u
cd "$(dirname "$0")/.."
FROM="" WORLD=""
while [ $# -gt 0 ]; do
  case "$1" in
    --from) FROM=$2; shift 2;;
    --world) WORLD=1; shift;;
    --every) EVERY=1; shift;;
    *) echo "usage: tests/upgrade.sh [--from VERSION] [--world] | --every"; exit 2;;
  esac
done
if [ -n "${EVERY:-}" ]; then
  out=$(python3 tests/previous_release.py --list 2>&1); rc=$?
  if [ $rc -eq 2 ]; then echo "skip  $out"; echo "upgrade: skipped"; exit 0; fi
  if [ $rc -eq 3 ]; then echo "skip  $out"; echo "upgrade: skipped, nothing to upgrade from"; exit 0; fi
  [ $rc -eq 0 ] || { echo "FAIL  the releases on PyPI: $out"; echo "upgrade: 1 failed"; exit 1; }
  failed=() counts=()
  for v in $out; do
    echo "=== from $v"
    started=$SECONDS
    log=$(bash tests/upgrade.sh --from "$v" --world 2>&1); rc=$?
    echo "$log"
    n=$(echo "$log" | grep -c '^ok')
    echo "--- from $v: $n checks passed ($((SECONDS - started))s)"
    [ $rc -eq 0 ] || failed+=("$v")
    counts+=("$n")
  done
  if [ ${#failed[@]} -gt 0 ]; then echo "upgrade: failed from ${failed[*]}"; exit 1; fi
  if [ "$(printf '%s\n' "${counts[@]}" | sort -u | wc -l)" != 1 ]; then
    echo "FAIL  each release upgrades with as many checks: $(paste -sd' ' <<< "$out") passed ${counts[*]}"; exit 1; fi
  echo "ok    every release before this one upgrades, each with the same ${counts[0]} checks: $(paste -sd' ' <<< "$out")"
  echo "upgrade: all passed"; exit 0
fi
CORE=$PWD
DB=authz_upgrade
WAYS="push apply reapply migrate"
fails=0
ok() { echo "ok    $1"; }
bad() { echo "FAIL  $1${2:+: $2}"; fails=$((fails + 1)); }
T=$(mktemp -d)
P="$T/app"   # the app's folder: its policy, its tests, rowstile.toml, the migrations and the lock file
mkdir -p "$P"
cleanup() { rm -rf "$T"; for w in $WAYS fresh world_reapply world_migrate world_fresh; do dropdb --if-exists "${DB}_$w" 2>/dev/null; done; }
trap cleanup EXIT

if [ -n "$FROM" ]; then BEFORE="the older release"; else BEFORE="the release before"; fi
echo "-- ${FROM:-the release before this one}, from PyPI"
out=$(python3 tests/previous_release.py "$T/old" $FROM 2>&1); rc=$?
if [ $rc -eq 2 ]; then echo "skip  $out"; echo "upgrade: skipped"; exit 0; fi
if [ $rc -eq 3 ]; then echo "skip  $out"; echo "upgrade: skipped, nothing to upgrade from"; exit 0; fi
[ $rc -eq 0 ] || { bad "$BEFORE, from PyPI" "$out"; echo "upgrade: 1 failed"; exit 1; }
OLD_VERSION=$out
NEW_VERSION=$(python3 -c 'import authzlib; print(authzlib.__version__)')
BUILD=$(python3 -c 'import authzlib; print(authzlib.BUILD)')
# each command runs in the app's folder; the old one with nothing of this checkout's on its path (-P)
OLD() { ( cd "$P" && "$T/old/bin/python" -P -m rowstile "$@" ); }
NEW() { ( cd "$P" && python3 "$CORE/cli/rowstile_cli.py" "$@" ); }
case "$(OLD --version 2>&1)" in *" $OLD_VERSION "*)
  ok "$BEFORE, $OLD_VERSION, older than this $NEW_VERSION, installed from PyPI in a virtual environment of its own";;
  *) bad "${BEFORE}'s command" "$(OLD --version 2>&1)";; esac

# the docs app as the older release was released with it: its policy, its tests, its schema
APP=() said=$(python3 tests/docs_app.py "$OLD_VERSION" 2>&1 >/dev/null)
mapfile -t APP < <(python3 tests/docs_app.py "$OLD_VERSION" 2>/dev/null)
where="its copy, core/${APP[0]%/*}/"; [ "${APP[0]}" = example/docs.authz ] && where="core/example's, this checkout's"
[ ${#APP[@]} -eq 3 ] && ok "the docs app $OLD_VERSION was released with: $where${said:+ ($said)}" ||
  { bad "the docs app $OLD_VERSION was released with" "${APP[*]} $said"; echo "upgrade: 1 failed"; exit 1; }
export UPGRADE_DOCS_POLICY=${APP[0]} UPGRADE_DOCS_SCHEMA=${APP[2]}   # (tests/upgrade_world.py's)
cp "${APP[0]}" "$P/policy.authz"
cp "${APP[1]}" "$P/tests.authz"
printf 'policy = "policy.authz"\ndatabase = "dbname=%s"\n[migrations]\ntool = "sql"\ndir = "migrations"\n' "${DB}_migrate" > "$P/rowstile.toml"
python3 compile_policy.py "$P/policy.authz" --tests > "$T/docs_tests.sql" || exit 1
fresh() { dropdb --if-exists "$1" 2>/dev/null; createdb "$1" || exit 1
  PGOPTIONS="-c client_min_messages=error" psql -X -q -v ON_ERROR_STOP=1 -d "$1" -f "${APP[2]}" >/dev/null || exit 1; }
# every migration in the folder the database hasn't taken yet, in order, each in one transaction (as the tools do)
migrate_db() {
  local f out
  touch "$T/applied.$1"
  for f in $(ls "$P"/migrations/*.sql | sort); do
    grep -qx "$f" "$T/applied.$1" && continue
    out=$(PGOPTIONS="-c client_min_messages=error" psql -X -q -1 -v ON_ERROR_STOP=1 -d "$1" -f "$f" 2>&1) || { echo "$f: $out"; return 1; }
    echo "$f" >> "$T/applied.$1"
  done
}
PSQL() { psql -X -q -At -v ON_ERROR_STOP=1 -d "$1" "${@:2}"; }
# a statement as the app role, signed in as a user (the owner's session may set authz.user_id); the last line
as() { psql -X -q -At -d "$1" -c "SET ROLE app_user" -c "SET authz.user_id = $2" -c "$3" 2>&1 | tail -n 1; }
FILES="SELECT coalesce(string_agg(name, ', ' ORDER BY name), '-') FROM app.files"
# the audit trail's rows up to an id, each as the columns every release has written
AUDIT="SELECT string_agg(concat_ws(' ', id, at, action, object_type, object_id, relation, subject_type, subject_id, user_id), E'\n' ORDER BY id) FROM authz.audit"
# what the older release recorded, and the app's own state under it, per way
declare -A KEY REQ TRAIL LAST

echo "-- the databases $BEFORE made"
fresh "${DB}_push"
out=$(OLD --db "dbname=${DB}_push" push 2>&1) || bad "push: $BEFORE pushes to a new database" "$out"
for w in apply reapply; do
  fresh "${DB}_$w"
  out=$(OLD --db "dbname=${DB}_$w" apply 2>&1) || bad "$w: $BEFORE applies the policy" "$out"
done
fresh "${DB}_migrate"
out=$(OLD migrate 2>&1) && [ -f "$P/policy.lock" ] && [ "$(ls "$P/migrations" | wc -l)" = 1 ] &&
  out=$(migrate_db "${DB}_migrate") ||
  bad "migrate: $BEFORE writes the first migration and the lock file, and the migration applies" "$out"
head -n 1 "$P/policy.lock" | grep -qF " $OLD_VERSION" && cp "$P/policy.lock" "$T/old.lock" &&
  ok "migrate: the lock file names $BEFORE, which wrote it" || bad "the old lock file" "$(head -n 1 "$P/policy.lock")"
for w in $WAYS; do
  db="${DB}_$w"
  [ "$(PSQL "$db" -c "SELECT version FROM authz.policy_versions ORDER BY id DESC LIMIT 1")" = "$OLD_VERSION" ] &&
    [ "$(PSQL "$db" -c "SELECT authz.verify()")" = t ] &&
    ok "$w: $BEFORE made the database: it records its version, and its inheritance tables match a rebuild" ||
    bad "$w: what $BEFORE made" "$(PSQL "$db" -c "SELECT version FROM authz.policy_versions ORDER BY id DESC LIMIT 1" 2>&1)"
  # what the app does under it: erin shares Company with Acme's members and offer-letter.pdf with dave, dave
  # makes an API key and asks frank for a look at Globex
  out=$(psql -X -q -At -v ON_ERROR_STOP=1 -d "$db" -c "SET ROLE app_user" -c "SET authz.user_id = 5" \
          -c "SELECT authz.share('folder', 1, 'viewer', 'org', 1, 'member')" \
          -c "SELECT authz.share('file', 13, 'viewer', 'user', 4, '', now() + interval '1 day')" 2>&1) || bad "$w: erin's shares" "$out"
  REQ[$w]=$(as "$db" 4 "SELECT authz.request_access('folder', 20, 'viewer', 'asked before the upgrade', '7 days')")
  KEY[$w]=$(as "$db" 4 "SELECT authz.create_api_key('made before the upgrade', 'read')")
  LAST[$w]=$(PSQL "$db" -c "SELECT max(id) FROM authz.audit")
  TRAIL[$w]=$(PSQL "$db" -c "$AUDIT")
  made=$(PSQL "$db" -c "SELECT count(*) FROM authz.audit")
  [ "${KEY[$w]:0:3}" = ak_ ] && [ "${REQ[$w]}" -gt 0 ] 2>/dev/null && [ "$made" -ge 4 ] &&
    ok "$w: under $BEFORE, the app shares, makes an API key and asks for access, and the audit trail has it" ||
    bad "$w: the app's state under $BEFORE" "key ${KEY[$w]:0:12}..., request ${REQ[$w]}, $made audit rows"
done

if [ -n "$WORLD" ]; then
  echo "-- a world of data under $BEFORE: one database it applied, one its first migration set up"
  fresh "${DB}_world_reapply"
  out=$(OLD --db "dbname=${DB}_world_reapply" apply 2>&1) || bad "world, reapply: $BEFORE applies the policy" "$out"
  fresh "${DB}_world_migrate"
  out=$(migrate_db "${DB}_world_migrate") || bad "world, migrate: ${BEFORE}'s first migration applies" "$out"
  # (shares: live, live until tomorrow, expired, not started; to groups; made by authz.share, which records who)
  STATES="SELECT count(*) FILTER (WHERE expires_at IS NULL AND starts_at IS NULL) || ' ' ||
    count(*) FILTER (WHERE expires_at > now() AND starts_at IS NULL) || ' ' || count(*) FILTER (WHERE expires_at < now())
    || ' ' || count(*) FILTER (WHERE starts_at > now()) || ' ' || count(*) FILTER (WHERE subject_relation <> '')
    || ' ' || count(*) FILTER (WHERE created_by IS NOT NULL) FROM authz.shares"
  # the world's rows and shares, each share with the columns every release has: the upgrade keeps them all, as they
  # were (a share that doesn't count now, not started yet or expired, changes no answer, but is the app's)
  KEPT_ROWS="SELECT md5(string_agg(x, ',' ORDER BY x)) FROM (SELECT concat_ws(' ', 'share', object_type, object_id,
    relation, subject_type, subject_id, subject_relation, expires_at, starts_at, caveat, caveat_args, created_by, created_at)
    FROM authz.shares UNION ALL SELECT f::text FROM app.folders f UNION ALL SELECT f::text FROM app.files f
    UNION ALL SELECT l::text FROM app.folder_links l UNION ALL SELECT m::text FROM app.team_members m
    UNION ALL SELECT t::text FROM app.teams t UNION ALL SELECT a::text FROM app.folder_team_access a) r(x)"
  declare -A WORLD_ROWS
  for w in reapply migrate; do
    db="${DB}_world_$w"
    out=$(python3 tests/upgrade_world.py fill "$db" 1 2>&1); rc=$?
    WORLD_ROWS[$w]=$(PSQL "$db" -c "$KEPT_ROWS")
    states=$(PSQL "$db" -c "$STATES")
    [ $rc -eq 0 ] && [ -z "$out" ] && [ "$(PSQL "$db" -c "SELECT authz.verify()")" = t ] && ! echo " $states" | grep -q " 0" &&
      ok "world, $w: under $BEFORE, the world's rows, shares in every state, some made by authz.share, and 40 changes; the inheritance tables match a rebuild" ||
      bad "world, $w: the world under $BEFORE" "exit $rc, $out (shares live, until tomorrow, expired, not started, to groups, by authz.share: $states)"
  done
fi

echo "-- this version, on a new database (what each upgraded one must hold)"
fresh "${DB}_fresh"
out=$(NEW --db "dbname=${DB}_fresh" apply 2>&1) || bad "this version applies on a new database" "$out"

echo "-- this version's command upgrades each the way the app keeps it"
out=$(NEW --db "dbname=${DB}_push" push 2>&1)
[ "$out" = "$P/policy.authz: applied (the whole policy)" ] &&
  ok "push: a development database $BEFORE pushed to takes the whole policy, another version having made it" ||
  bad "push over ${BEFORE}'s database" "$out"
out=$(NEW --db "dbname=${DB}_apply" apply 2>&1)
[ "$out" = "$P/policy.authz: applied" ] &&
  ok "apply: a database $BEFORE applied is applied again, not taken as up to date" ||
  bad "apply over ${BEFORE}'s database" "$out"
out=$(NEW --db "dbname=${DB}_reapply" reapply 2>&1)
[ "$out" = "applied again" ] && ok "reapply: the policy a database $BEFORE applied holds, applied again by this version" ||
  bad "reapply over ${BEFORE}'s database" "$out"
out=$(NEW migrate --check 2>&1); rc=$?
SAME=   # set when this version makes nothing differently: no migration to write
case "$out" in *"policy.authz has changes no migration has"*"rowstile $OLD_VERSION -> $NEW_VERSION: what the new version makes differently"*)
  [ $rc -eq 1 ] && ok "migrate --check, on the lock file $BEFORE wrote: exit 1, the new version makes something differently" ||
    bad "migrate --check after the upgrade: exit" "$rc";;
  "nothing to migrate: "*) SAME=1
  [ $rc -eq 0 ] && ok "migrate --check, on the lock file $BEFORE wrote: exit 0, the new version makes nothing differently" ||
    bad "migrate --check after the upgrade: exit" "$rc";;
  *) bad "migrate --check after the upgrade" "$out";; esac
before=$(ls "$P/migrations" | wc -l)
out=$(NEW migrate 2>&1); rc=$?
if [ -n "$SAME" ]; then
  [ $rc -eq 0 ] && [ "$(ls "$P/migrations" | wc -l)" = "$before" ] && cmp -s "$P/policy.lock" "$T/old.lock" &&
    ok "migrate writes no migration, a new version alone being none, and leaves the lock file $BEFORE wrote" ||
    bad "migrate after the upgrade" "$out"
else
  [ $rc -eq 0 ] && [ "$(ls "$P/migrations" | wc -l)" -gt "$before" ] && ! cmp -s "$P/policy.lock" "$T/old.lock" &&
    ok "migrate writes the migration from the old lock file to this version, and the lock file after it" || bad "migrate after the upgrade" "$out"
fi
out=$(migrate_db "${DB}_migrate") &&
  ok "the migration applies on the database ${BEFORE}'s migrations set up" || bad "the upgrade's migration" "$out"
out=$(NEW migrate --check 2>&1); [ $? -eq 0 ] && ok "... and migrate --check passes again" || bad "migrate --check after migrating" "$out"
if [ -n "$WORLD" ]; then
  out=$(NEW --db "dbname=${DB}_world_reapply" reapply 2>&1)
  [ "$out" = "applied again" ] && ok "world, reapply: this version applies again the policy the world's database holds" ||
    bad "world, reapply over ${BEFORE}'s database" "$out"
  out=$(migrate_db "${DB}_world_migrate") && ok "world, migrate: the migration applies on the world's database" ||
    bad "world, migrate: the upgrade's migration" "$out"
  for w in reapply migrate; do
    [ "$(PSQL "${DB}_world_$w" -c "$KEPT_ROWS")" = "${WORLD_ROWS[$w]}" ] &&
      ok "world, $w: every share and row made before is there after the upgrade, as it was" ||
      bad "world, $w: the shares and rows made before" "$(PSQL "${DB}_world_$w" -c "SELECT count(*) FROM authz.shares")"
  done
fi

echo "-- each upgraded database"
# what differs from the new database: what tests/migrate_test.py compares a migration with applying whole by
# (functions and their privileges, views, triggers, row-level security policies, rowstile's tables and their rows),
# and the tables kept across applies (schema authz), which only an upgrade finds as an older version left them:
# their columns in order (a new one goes last in its CREATE TABLE, where its ADD COLUMN IF NOT EXISTS puts it on a
# database made before), with their types and defaults, and their constraints. The first line: how many objects
differs() { python3 tests/upgrade_world.py differs "$1" "$2"; }
for w in $WAYS; do
  db="${DB}_$w"
  # with no migration to run, the database the migrations set up still records the older release
  recorded=$BUILD whose="this version's"
  [ "$w" = migrate ] && [ -n "$SAME" ] && recorded=$OLD_VERSION whose="${BEFORE}'s, which this version makes the same"
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

if [ -n "$WORLD" ]; then
  echo "-- the world, upgraded, against a new database with the same rows"
  out=$(python3 tests/upgrade_world.py fresh "${DB}_world_reapply" "${DB}_world_fresh" "$P/policy.authz" 2>&1) &&
    ok "the world's rows on a new database, this version applied whole, then the same shares" || bad "the world on a new database" "$out"
  ROWS="SELECT md5(string_agg(t::text, ',' ORDER BY t::text)) FROM (SELECT f::text FROM app.folders f UNION ALL
    SELECT f::text FROM app.files f UNION ALL SELECT l::text FROM app.folder_links l UNION ALL SELECT m::text FROM app.team_members m
    UNION ALL SELECT concat_ws(' ', object_type, object_id, relation, subject_type, subject_id, subject_relation, expires_at IS NULL,
    starts_at IS NULL, created_by) FROM authz.shares) t(t)"
  [ "$(PSQL "${DB}_world_migrate" -c "$ROWS")" = "$(PSQL "${DB}_world_reapply" -c "$ROWS")" ] &&
    ok "world: its two databases hold the same rows and shares" || bad "world: the two databases' rows differ"
  # judged by its exit status as well as by its lines: one that dies after some `ok` lines fails here
  out=$(python3 tests/upgrade_world.py compare "${DB}_world_fresh" "${DB}_world_reapply" "${DB}_world_migrate" 2>&1); rc=$?
  echo "$out" | grep -v '^ok'
  echo "$out" | grep '^ok'
  failed=$(echo "$out" | grep -c '^FAIL')
  fails=$((fails + failed))
  echo "$out" | grep -q '^ok' || bad "world: the answers" "$out"
  [ $rc -eq 0 ] || [ "$failed" -gt 0 ] || bad "world: the answers: tests/upgrade_world.py compare stopped, exit $rc" "$(echo "$out" | tail -n 5)"
  for w in reapply migrate; do
    out=$(differs "${DB}_world_$w" "${DB}_world_fresh" 2>&1)
    n=$(echo "$out" | head -n 1)
    [ "$(echo "$out" | wc -l)" = 1 ] && [ "$n" -gt 100 ] 2>/dev/null &&
      ok "world, $w: it holds what applying this version on a new database with its rows leaves ($n objects, the inheritance tables' rows among them)" ||
      bad "world, $w: what this version applied on a new database with its rows leaves" "$(echo "$out" | head -n 24)"
  done
fi

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

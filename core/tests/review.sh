#!/bin/bash
# review.sh: rowstile review in a git repository, with a database at the base branch's state, as CI
# runs it: what the pull request changes in meaning, access, risk, tests and deploy; the comment, the JSON and
# the annotations; the database left as it was. And rowstile fmt.
#   PGHOST=... PGUSER=... tests/review.sh
set -u
cd "$(dirname "$0")/.."
DB=authz_review
fails=0
ok() { echo "ok    $1"; }
bad() { echo "FAIL  $1${2:+: $2}"; fails=$((fails + 1)); }
PSQL() { psql -X -q -At -v ON_ERROR_STOP=1 -d "$DB" "$@"; }
command -v git >/dev/null || { echo "skip  git is not installed"; exit 0; }
T=$(mktemp -d)
P="$T/p"
mkdir -p "$P/db/tests"
sed '/^test$/,$d' example/docs.authz > "$P/db/policy.authz"
cp example/docs.test.authz "$P/db/tests/docs.authz"
printf 'policy = "db/policy.authz"\ntests = ["db/tests/*.authz"]\n[migrations]\ntool = "sql"\ndir = "db/migrations"\n' > "$P/rowstile.toml"
CLI() { ( cd "$P" && python3 "$OLDPWD/cli/rowstile_cli.py" "$@" ); }
G() { git -C "$P" "$@"; }
# the project in a folder of the repository, as the file manager is in this one
git -C "$T" init -q -b main && G config user.email t@example.com && G config user.name t
CLI migrate >/dev/null && G add -A && G commit -q -m base || { bad "setting up the repository"; exit 1; }

# the review database: the base branch's migrations, then the review data
dropdb --if-exists "$DB" 2>/dev/null; createdb "$DB" || exit 1
PGOPTIONS="-c client_min_messages=error" psql -X -q -v ON_ERROR_STOP=1 -d "$DB" -f example/app_schema.sql >/dev/null || exit 1
for f in "$P"/db/migrations/*.sql; do
  PGOPTIONS="-c client_min_messages=error" psql -X -q -1 -v ON_ERROR_STOP=1 -d "$DB" -f "$f" >/dev/null || { bad "base migration"; exit 1; }
done
PSQL -c "SET ROLE app_user" -c "SET authz.user_id = 5" -c "SELECT authz.share('folder', 1, 'viewer', 'org', 1, 'member')" >/dev/null
before=$(PSQL -c "SELECT count(*) || '/' || max(lock) FROM authz.policy_versions")

echo "-- a pull request that changes inheritance"
sed -i 's/can view  = edit or viewer or (parent.view and {inherit})/can view  = edit or viewer or parent.view/' "$P/db/policy.authz"
sed -i 's/user $bo cannot view file $f/user $bo can view file $f/' "$P/db/tests/docs.authz"
CLI migrate >/dev/null
out=$(CLI --db "dbname=$DB" review --base main 2>&1); rc=$?
[ $rc -eq 0 ] && ok "rowstile review runs, and exits 0 whatever it found (it reports, the tests gate)" || bad "review" "$out"
case "$out" in *"Meaning  1 permission changed, 3 permissions and rules change through it"*) ok "Meaning: what changed, and what changes through it";; *) bad "meaning" "$out";; esac
case "$out" in *"Access   "*"users gain \`view\` on"*"Nobody loses access."*) ok "Access: who gains what, on the review data";; *) bad "access" "$out";; esac
case "$out" in *"not a refactor: "*" differs for user "*" on "[a-z]*" "*) ok "... and the difference that makes it no refactor names who and what, in words";; *) bad "the counterexample's wording" "$out";; esac
case "$out" in *"folder.view\` allows more than before"*) ok "Risk: the permission widened, with an example";; *) bad "risk" "$out";; esac
case "$out" in *"Tests    "*"checks pass, "*" fail. 1 check changed what it expects."*) ok "Tests: the tests of the pull request ran, and the flipped check is named";;
  *) bad "tests" "$out";; esac
case "$out" in *"Deploy   2 migrations."*"Builds folder__linked_into_parent__tree beside the tables in use, then swaps in."*"Applied on the review database in"*)
  ok "Deploy: two migrations, the tree built beside, applied on the review data";; *) bad "deploy" "$out";; esac
[ "$(PSQL -c "SELECT count(*) || '/' || max(lock) FROM authz.policy_versions")" = "$before" ] &&
  ok "the review database is left as it was" || bad "review left changes"
md=$(CLI --db "dbname=$DB" review --base main --markdown)
case "$md" in "<!-- rowstile review -->"*"<details><summary>Meaning</summary>"*"| \`folder.view\` (changed) |"*"<details><summary>Access</summary>"*"<details><summary>Deploy</summary>"*)
  ok "--markdown: the comment, with its marker and details";; *) bad "markdown" "$md";; esac
CLI review --base main --json | python3 -c "import json,sys; d=json.load(sys.stdin); assert d['meaning']['changed'][0]['what'] == 'folder.view'" &&
  ok "--json" || bad "json"
case "$(CLI review --base main --annotations)" in "::warning file=p/db/policy.authz,line="*"a permission widened"*)
  ok "--annotations: on the policy line, its path from the repository's top folder";;
  *) bad "annotations" "$(CLI review --base main --annotations)";; esac

echo "-- a base git doesn't know, a policy with a mistake"
out=$(CLI review --base no-such-branch 2>&1); rc=$?
case "$out" in *"git doesn't know the commit to compare with, no-such-branch"*) [ $rc -eq 2 ] && ok "a base git doesn't know: said, exit 2 (not the whole policy as new)" || bad "unknown base exit" "$rc";;
  *) bad "unknown base" "$out";; esac
# a base whose lock file a merge left its conflict markers in (main's, in a commit of its own): Deploy says why it
# isn't computed, and the rest of the review goes on
blob=$(G show main:p/db/policy.lock | sed '3i<<<<<<< HEAD' | G hash-object -w --stdin)
GIT_INDEX_FILE="$T/merged.index" G read-tree main &&
  GIT_INDEX_FILE="$T/merged.index" G update-index --cacheinfo "100644,$blob,p/db/policy.lock" &&
  G branch merged "$(G commit-tree "$(GIT_INDEX_FILE="$T/merged.index" G write-tree)" -p main -m merged)" || bad "a base with a merged lock: setting it up"
out=$(CLI review --base merged 2>&1); rc=$?
case "$out" in *"Meaning  "*"Deploy   not computed: line 3 of the lock file isn't one rowstile migrate writes (<<<<<<< HEAD), at the base [AZ619]"*)
  [ $rc -eq 0 ] && ok "a base whose lock file holds a merge's conflict markers: Deploy says why it isn't computed, the review goes on" ||
  bad "a base with a merged lock: exit" "$rc";;
  *) bad "a base with a merged lock" "$out";; esac
G branch -D merged >/dev/null
cp "$P/db/policy.authz" "$T/keep.authz"
sed -i 's/can view  = edit or viewer or parent.view/can view  = edit or viewer or nosuch.view/' "$P/db/policy.authz"
out=$(CLI review --base main 2>&1); rc=$?
case "$out" in *"Traceback"*) bad "a mistake in the policy gives a traceback" "$out";;
  "db/policy.authz: line "*"has no relation or permission 'nosuch'"*"[AZ203]"*) [ $rc -eq 1 ] && ok "a mistake in the pull request's policy: check's message, exit 1" || bad "mistake exit" "$rc";;
  *) bad "a mistake in the policy" "$out";; esac
cp "$T/keep.authz" "$P/db/policy.authz"
out=$(CLI review --base main db/nosuch.authz 2>&1); rc=$?
[ $rc -eq 2 ] && [ "$out" = "db/nosuch.authz: No such file or directory" ] && ok "a policy file that isn't there: said, exit 2" || bad "review of a missing policy" "$rc $out"
{ cat "$P/db/policy.authz"; printf -- '-- caf\351\n'; } > "$P/db/latin.authz"
out=$(CLI review --base main db/latin.authz 2>&1); rc=$?
case "$out" in "db/latin.authz: not UTF-8 (the byte at "*"): save it as UTF-8") [ $rc -eq 2 ] && ok "... nor one that isn't UTF-8" || bad "review of a policy not UTF-8: exit" "$rc";;
  *) bad "review of a policy not UTF-8" "$out";; esac
rm "$P/db/latin.authz"
printf 'test "caf\351"\n  user 3 can view file 11\n' > "$P/db/tests/latin.authz"
out=$(CLI review --base main 2>&1); rc=$?
case "$out" in "db/tests/latin.authz: not UTF-8 (the byte at 9): save it as UTF-8") [ $rc -eq 2 ] && ok "a test file that isn't UTF-8: said, exit 2" || bad "review of a test file not UTF-8: exit" "$rc";;
  *) bad "review of a test file not UTF-8" "$out";; esac
rm "$P/db/tests/latin.authz"
out=$(CLI --db "dbname=authz_review_no_such_db" review --base main 2>&1); rc=$?
case "$out" in "can't connect: "*'database "authz_review_no_such_db" does not exist') [ $rc -eq 2 ] && ok "a review database that isn't there: can't connect, exit 2" || bad "review --db unreachable: exit" "$rc";;
  *) bad "review --db unreachable" "$out";; esac
dropdb --if-exists "${DB}_bare" 2>/dev/null; createdb "${DB}_bare"
out=$(CLI --db "dbname=${DB}_bare" review --base main 2>&1); rc=$?
case "$out" in *Traceback*) bad "a review database without the app's tables gives a traceback" "${out: -300}";;
  *"Access   not computed: the policy does not match this database:"*"table app.users not found [AZ601]"*)
    [ $rc -eq 0 ] && ok "a review database without the app's tables: Access says why it isn't computed, exit 0" || bad "review on a bare database: exit" "$rc";;
  *) bad "review on a bare database" "$out";; esac
dropdb --if-exists "${DB}_bare"
# the server ends the review's session while it works (here while it waits on a table another session holds)
( PSQL -c "BEGIN" -c "LOCK TABLE app.folders IN ACCESS EXCLUSIVE MODE" -c "SELECT pg_sleep(6)" -c "COMMIT" >/dev/null 2>&1 ) &
locker=$!
for _ in $(seq 40); do [ "$(PSQL -c "SELECT count(*) FROM pg_locks WHERE relation = 'app.folders'::regclass AND mode = 'AccessExclusiveLock' AND granted")" = 1 ] && break; sleep 0.25; done
( CLI --db "dbname=$DB" review --base main > "$T/review.out" 2>&1; echo $? > "$T/review.rc" ) &
reviewer=$!
for _ in $(seq 40); do w=$(PSQL -c "SELECT pid FROM pg_stat_activity WHERE datname = '$DB' AND application_name = 'rowstile' AND wait_event_type = 'Lock' LIMIT 1"); [ -n "$w" ] && break; sleep 0.25; done
[ -n "$w" ] && PSQL -c "SELECT pg_terminate_backend($w)" >/dev/null
wait "$reviewer"
PSQL -c "SELECT pg_cancel_backend(pid) FROM pg_stat_activity WHERE datname = '$DB' AND query = 'SELECT pg_sleep(6)'" >/dev/null
wait "$locker"
case "$(cat "$T/review.out")" in "lost the database: "*) [ "$(cat "$T/review.rc")" = 2 ] && ok "the server ending the review's session: lost the database, exit 2" ||
  bad "review losing its database: exit" "$(cat "$T/review.rc")";; *) bad "review losing its database" "$(cat "$T/review.out")";; esac

echo "-- a pull request whose policy doesn't run on the review data"
G checkout -q -- db && rm -f "$P"/db/migrations/*_authz_build_policy.sql && G clean -q -fd db
sed -i 's/not {confidential}/not {confidentail}/' "$P/db/policy.authz"
CLI migrate >/dev/null
out=$(CLI --db "dbname=$DB" review --base main 2>&1); rc=$?
said="policy line 63: the condition {confidentail} doesn't run: column \"confidentail\" does not exist [AZ613]"
case "$out" in *Traceback*) bad "a condition Postgres refuses gives a traceback" "$out";;
  *"Access   not computed: $said"*"Tests    not run: the migration fails: $said"*"It fails on the review database: $said"*)
    [ $rc -eq 0 ] && [ "$(PSQL -c "SELECT count(*) || '/' || max(lock) FROM authz.policy_versions")" = "$before" ] &&
    ok "a condition Postgres refuses: Access, Tests and Deploy say which and why; the review database is left as it was" ||
    bad "a condition Postgres refuses: exit or the database" "$rc";;
  *) bad "a condition Postgres refuses" "$out";; esac
G checkout -q -- db && G clean -q -fd db
sed -i 's/not {confidential}/not {confidential or name::int > 0}/' "$P/db/policy.authz"
CLI migrate >/dev/null
out=$(CLI --db "dbname=$DB" review --base main 2>&1); rc=$?
case "$out" in *Traceback*) bad "a condition that fails on a row gives a traceback" "$out";;
  *"Access   not computed: invalid input syntax for type integer: "*) [ $rc -eq 0 ] &&
    ok "... one that fails on a row of the review data: Access says why, and the review goes on" || bad "a condition that fails on a row: exit" "$rc";;
  *) bad "a condition that fails on a row" "$out";; esac
G checkout -q -- db && G clean -q -fd db

echo "-- a refactor"
G checkout -q -- db && rm -f "$P"/db/migrations/*_authz_build_policy.sql && G clean -q -fd db
sed -i 's/can edit  = share or editor or (parent.edit and {inherit})/can edit  = editor or share or ({inherit} and parent.edit)/' "$P/db/policy.authz"
out=$(CLI review --base main 2>&1)
case "$out" in "Meaning  unchanged: every permission and rule grants the same in"*) ok "a refactor: meaning unchanged, checked in small worlds";; *) bad "refactor" "$out";; esac

echo "-- a pull request whose policy reads a column its own migration of the app adds"
G checkout -q -- db && G clean -q -fd db
sed -i 's/^  owner  : user   = owner_id$/  owner  : user   = author_id/' "$P/db/policy.authz"
CLI migrate >/dev/null
out=$(CLI --db "dbname=$DB" review --base main 2>&1); rc=$?
case "$out" in *"Traceback"*) bad "a column the review database doesn't have yet: a traceback" "$out";;
  *"Access   not computed: the policy does not match this database:"*"column author_id not found in app.files [AZ601]"*"Tests    not run: the migration fails: "*"**It fails on the review database: "*)
  [ $rc -eq 0 ] && ok "a column the review database doesn't have yet: Access not computed, and why; the review goes on, exit 0" ||
    bad "a column the review database doesn't have yet: exit" "$rc";;
  *) bad "a column the review database doesn't have yet" "$out";; esac
[ "$(PSQL -c "SELECT count(*) || '/' || max(lock) FROM authz.policy_versions")" = "$before" ] &&
  ok "... and the review database is left as it was" || bad "review left changes after a failed diff"
G checkout -q -- db && G clean -q -fd db

echo "-- a pull request that lets a service in (a bot that signs in, which the app's own migration adds)"
PSQL -c "CREATE TABLE app.bots (id bigint PRIMARY KEY)" -c "CREATE TABLE app.folder_bots (folder_id bigint, bot_id bigint)" \
  -c "INSERT INTO app.bots VALUES (7)" -c "INSERT INTO app.folder_bots VALUES (2, 7)"
sed -i -e 's/^type org = app.orgs$/type bot = app.bots principal\n\ntype org = app.orgs/' \
  -e 's/^  editor      : team#member = app.folder_team_access(folder_id -> team_id) where {access = .edit.}$/&\n  bot_viewer  : bot         = app.folder_bots(folder_id -> bot_id)/' \
  -e 's/^           or linked_into.view  -- links pass on view, not edit$/           or linked_into.view or bot_viewer  -- links pass on view, not edit/' "$P/db/policy.authz"
CLI migrate >/dev/null
out=$(CLI --db "dbname=$DB" review --base main --markdown 2>&1)
case "$out" in *"**Access**: 1 bot gains \`view\` on 1 file; 1 bot gains \`view\` on 1 folder. Nobody loses access."*)
  ok "Access says who gains: a bot, not a user";; *) bad "Access of a service" "$out";; esac
case "$out" in *"| gains | \`folder\` view | 1 bot | 1 | bot 7, folder 2: bot_viewer, bot_viewer: a row in app.folder_bots names you |"*)
  ok "... and how it gains, asked as the bot, from what grants it alone";; *) bad "how a service gains" "$out";; esac
G checkout -q -- db && G clean -q -fd db
PSQL -c "DROP TABLE app.folder_bots, app.bots"

echo "-- rowstile fmt"
G checkout -q -- db
out=$(CLI fmt --check 2>&1); rc=$?
case "$out" in *"db/policy.authz: not formatted"*) [ $rc -eq 1 ] && ok "fmt --check: exit 1, and which file" || bad "fmt --check exit" "$rc";; *) bad "fmt --check" "$out";; esac
out=$(CLI fmt 2>&1); out2=$(CLI fmt --check 2>&1); rc=$?
case "$out" in *"formatted db/policy.authz"*) [ $rc -eq 0 ] && ok "fmt writes it; then --check passes" || bad "fmt then check" "$out2";; *) bad "fmt" "$out";; esac
out=$(CLI review --base main 2>&1)
case "$out" in "Meaning  unchanged (only comments, spacing or order)"*"Deploy   no migration"*) ok "... and review says formatting changed nothing";; *) bad "review after fmt" "$out";; esac
# a Windows checkout: the file's lines end with CRLF, and stay so
sed -i 's/$/\r/' "$P/db/policy.authz"
out=$(CLI fmt --check 2>&1); rc=$?
[ $rc -eq 0 ] && ok "a CRLF file in fmt's layout passes --check" || bad "fmt --check on CRLF" "$out"
printf '\r\n\r\n' >> "$P/db/policy.authz"
out=$(CLI fmt 2>&1)
lines=$(wc -l < "$P/db/policy.authz"); crlf=$(grep -c $'\r$' "$P/db/policy.authz")
case "$out" in *"formatted db/policy.authz"*) [ "$lines" = "$crlf" ] && ok "... and fmt writes it back with CRLF" || bad "fmt on CRLF: endings" "$crlf of $lines";; *) bad "fmt on CRLF" "$out";; esac

echo "-- a base whose policy has a mistake"
G checkout -q -- db && G clean -q -fd db
{ G checkout -q -b broken && sed -i 's/can edit  = share or editor or/can edit  = share or edtor or/' "$P/db/policy.authz" &&
  G commit -q -am broken && G checkout -q main; } || bad "setting up the branch broken"
# the pull request that fixes the mistake is reviewed: as one that adds the policy, the mistake said first
out=$(CLI review --base broken 2>&1); rc=$?
case "$out" in "Base     The policy at the base has a mistake (line "*" there: folder has no relation or permission 'edtor'"*"[AZ203]), so the review reads this one as new."$'\n'"Meaning  "*"added    app role"*"added    type folder"*)
  [ $rc -eq 0 ] && ok "a base whose policy has a mistake: said first, with its line there and its code, and the policy reviewed as new, exit 0" || bad "a base with a mistake: exit" "$rc";;
  *) bad "a base with a mistake" "$out";; esac
out=$(CLI review --base broken --json 2>&1)
printf '%s' "$out" | python3 -c "
import json, sys
d = json.load(sys.stdin)
m = d['base_mistake']
assert (m['code'], m['message'][:44]) == ('AZ203', \"folder has no relation or permission 'edtor'\"), m
assert m['line'].startswith('line ') and all(c['kind'] == 'added' for c in d['meaning']['changed']), d
" && ok "... --json: base_mistake, its line, message and code" || bad "a base with a mistake, --json" "$out"
case "$(CLI review --base broken --markdown)" in *"### rowstile: what this pull request changes"$'\n\n'"The policy at the base has a mistake (line "*"[AZ203]), so the review reads this one as new."$'\n\n'"**Meaning**"*)
  ok "... --markdown: said at the top of the comment";; *) bad "a base with a mistake, --markdown" "$(CLI review --base broken --markdown)";; esac
case "$(CLI review --base broken --annotations)" in "::warning file=p/db/policy.authz,title=rowstile review::The policy at the base has a mistake (line "*"[AZ203]), so the review reads this one as new."*)
  ok "... --annotations: on the policy file, first";; *) bad "a base with a mistake, --annotations" "$(CLI review --base broken --annotations)";; esac

echo "-- the review database"
G checkout -q -- db && G clean -q -fd db
# the tests alone change: nothing to migrate, and they run on the review data
sed -i 's/user $bo cannot view file $f/user $bo can view file $f/' "$P/db/tests/docs.authz"
out=$(CLI --db "dbname=$DB" review --base main 2>&1)
case "$out" in *"Tests    "*" checks pass, 1 fail. 1 check changed what it expects."*"Deploy   no migration: nothing the database holds changes."*)
  ok "a pull request that changes the tests alone: nothing to migrate, and they run on the review data";; *) bad "the tests alone" "$out";; esac
# test files rowstile test would refuse (a permission the policy doesn't have, a line that doesn't parse): each is
# named under Tests, the others still run on the review data, and the review goes on (exit 0)
printf 'test "broken"\n  user 3 can nosuch file 11\n' > "$P/db/tests/nosuch.authz"
printf 'test "unread"\n  user 3 frobs file 11\n' > "$P/db/tests/frobs.authz"
out=$(CLI --db "dbname=$DB" review --base main 2>&1); rc=$?
case "$out" in *"Tests    9 checks pass, 1 fail. 1 check changed what it expects. 2 test files can't be read, so their checks aren't compared."*"Deploy   no migration"*"can't read: db/tests/frobs.authz line 2: a test's lines are: "*" [AZ106]"*"can't read: db/tests/nosuch.authz line 2: file has no permission 'nosuch' (it has: share, edit, view) [AZ203]"*)
  [ $rc -eq 0 ] && ok "test files rowstile test would refuse: each named with its mistake under Tests, the others run, the review goes on (exit 0)" ||
    bad "test files it would refuse: exit" "$rc";; *) bad "test files it would refuse" "$out";; esac
rm "$P/db/tests/nosuch.authz" "$P/db/tests/frobs.authz"
G checkout -q -- db
# a project that keeps no migrations (rowstile apply): the pull request's policy is applied whole on the review data
N="$T/nolock"; mkdir -p "$N/db/tests"
sed '/^test$/,$d' example/docs.authz > "$N/db/policy.authz"; cp example/docs.test.authz "$N/db/tests/docs.authz"
printf 'policy = "db/policy.authz"\ntests = ["db/tests/*.authz"]\n' > "$N/rowstile.toml"
{ git -C "$N" init -q -b main && git -C "$N" config user.email t@example.com && git -C "$N" config user.name t &&
  git -C "$N" add -A && git -C "$N" commit -q -m base; } || bad "setting up a repository without migrations"
sed -i 's/can view  = edit or viewer or (parent.view and {inherit})/can view  = edit or viewer or parent.view/' "$N/db/policy.authz"
out=$( (cd "$N" && python3 "$OLDPWD/cli/rowstile_cli.py" --db "dbname=$DB" review --base main) 2>&1)
case "$out" in *"Tests    9 checks pass, 1 fail."*"Deploy   no lock file, so no migrations"*)
  [ "$(PSQL -c "SELECT count(*) || '/' || max(lock) FROM authz.policy_versions")" = "$before" ] &&
  ok "a project without migrations: the policy applied whole on the review data, its tests run there, all undone" ||
  bad "a project without migrations: the database changed";; *) bad "a project without migrations" "$out";; esac
# a review database a policy was pushed to since: the migrations from the base's lock refuse to run there
sed -e '/^test$/,$d' -e 's/^  can share = owner or folder.share$/  can share = owner or folder.share\n  can print = view/' \
  example/docs.authz > "$T/pushed.authz"
CLI --db "dbname=$DB" push --development "$T/pushed.authz" >/dev/null 2>&1 || bad "a push to the review database"
sed -i 's/can view  = edit or viewer or (parent.view and {inherit})/can view  = edit or viewer or parent.view/' "$P/db/policy.authz"
CLI migrate >/dev/null
out=$(CLI --db "dbname=$DB" review --base main 2>&1)
case "$out" in *"Tests    not run: the migration fails: rowstile: this migration changes the policy the migration before it left"*"It fails on the review database: rowstile: this migration changes"*"[AZ607]"*)
  ok "a review database not where the base's lock says: the migrations refuse it, and Tests and Deploy say so";;
  *) bad "a review database not where the base's lock says" "$out";; esac
G checkout -q -- db && G clean -q -fd db

echo "-- the pull request that adds the policy: none at the base"
F="$T/first"; mkdir -p "$F/db"
{ git -C "$F" init -q -b main && git -C "$F" config user.email t@example.com && git -C "$F" config user.name t &&
  echo "# app" > "$F/README.md" && git -C "$F" add -A && git -C "$F" commit -q -m base; } || bad "setting up the new repository"
printf 'app role web\ntype user = public.users\ntype doc = public.docs\n  owner : user = owner_id\n  can view = owner\n' > "$F/db/policy.authz"
out=$( (cd "$F" && python3 "$OLDPWD/cli/rowstile_cli.py" review --base main db/policy.authz) 2>&1); rc=$?
if printf '%s\n' "$out" | grep -q '^ *changed '; then bad "a new policy: a declaration said to change from one nobody wrote" "$out"
else case "$out" in *"added    app role"*"after:  app role web"*"added    type user"*"after:  type user = public.users"*)
  [ $rc -eq 0 ] && ok "the pull request that adds the policy: each declaration added, its own app role and user type too" || bad "a new policy: exit" "$rc";;
  *) bad "a new policy" "$out";; esac; fi
# without --base: main, also from a branch (HEAD isn't main: the policy is committed on the branch)
{ git -C "$F" checkout -q -b feature && git -C "$F" add -A && git -C "$F" commit -q -m policy; } || bad "setting up the branch feature"
out=$( (cd "$F" && python3 "$OLDPWD/cli/rowstile_cli.py" review db/policy.authz) 2>&1); rc=$?
case "$out" in *"added    app role"*"after:  app role web"*) [ $rc -eq 0 ] && ok "without --base, the review compares with main" || bad "review without --base: exit" "$rc";;
  *) bad "review without --base" "$out";; esac
git -C "$F" branch -q -m main trunk
out=$( (cd "$F" && python3 "$OLDPWD/cli/rowstile_cli.py" review db/policy.authz) 2>&1); rc=$?
[ $rc -eq 2 ] && [ "$out" = "rowstile review: which commit to compare with? --base main (or a commit)" ] &&
  ok "... and where there is no main or master, asks which commit" || bad "review without --base, no main" "$rc $out"

echo "-- a policy in several files, at the base and in the pull request"
I="$T/inc"; mkdir -p "$I/db/parts"
printf 'include "parts/types.authz"\n' > "$I/db/policy.authz"
printf 'app role web\ntype user = public.users\ntype doc = public.docs\n  owner : user = owner_id\n  can view = owner\n' > "$I/db/parts/types.authz"
{ git -C "$I" init -q -b main && git -C "$I" config user.email t@example.com && git -C "$I" config user.name t &&
  git -C "$I" add -A && git -C "$I" commit -q -m base; } || bad "setting up the repository with includes"
printf '  can edit = owner\n' >> "$I/db/parts/types.authz"
out=$( (cd "$I" && python3 "$OLDPWD/cli/rowstile_cli.py" review --base main db/policy.authz) 2>&1); rc=$?
case "$out" in "Meaning  1 permission added"*) [ $rc -eq 0 ] && ok "a policy that includes files: the base's are read from git too" || bad "includes at the base: exit" "$rc";;
  *) bad "includes at the base" "$out";; esac

echo "-- a base git can't read all of (a repository missing objects: a partial clone that can't fetch them)"
L="$T/lost"; mkdir -p "$L/db/parts" "$L/db/tests/old" "$L/db/more"
printf 'include "parts/types.authz"\n' > "$L/db/policy.authz"
printf 'app role web\ntype user = public.users\ntype doc = public.docs\n  owner : user = owner_id\n  can view = owner\n' > "$L/db/parts/types.authz"
printf 'test "the owner reads"\n  user 1 can view doc 1\n' > "$L/db/tests/a.authz"
# test files the globs don't find, at the base as in the pull request: below a glob's folder, a name that starts
# with a dot, above a glob's last folder
printf 'test "legacy"\n  user 2 cannot view doc 1\n' > "$L/db/tests/old/legacy.authz"
printf 'test "draft"\n  user 3 cannot view doc 1\n' > "$L/db/tests/.draft.authz"
printf 'test "stray"\n  user 4 cannot view doc 1\n' > "$L/db/more/stray.authz"
printf 'policy = "db/policy.authz"\ntests = ["db/tests/*.authz", "db/more/*/*.authz"]\n[migrations]\ntool = "sql"\ndir = "db/migrations"\n' > "$L/rowstile.toml"
LCLI() { ( cd "$L" && python3 "$OLDPWD/cli/rowstile_cli.py" "$@" ); }
{ git -C "$L" init -q -b main && git -C "$L" config user.email t@example.com && git -C "$L" config user.name t &&
  LCLI migrate >/dev/null && git -C "$L" add -A && git -C "$L" commit -q -m base; } || bad "setting up the repository whose base loses objects"
# the pull request: a permission, and a test file the base doesn't have
printf '  can edit = owner\n' >> "$L/db/parts/types.authz"
printf 'test "the owner edits"\n  user 1 can edit doc 1\n' > "$L/db/tests/b.authz"
LCLI migrate >/dev/null
out=$(LCLI review --base main --json 2>&1); rc=$?
[ $rc -eq 0 ] && printf '%s' "$out" | python3 -c "import json,sys; t=json.load(sys.stdin)['tests']
assert [(a['test'], a['check']) for a in t['added']] == [('the owner edits', 'user 1 can edit doc 1')], t" &&
  ok "a test file the base doesn't have: its checks are added, and the review goes on" || bad "a test file added since the base" "$rc $out"
printf '%s' "$out" | python3 -c "import json,sys; t=json.load(sys.stdin)['tests']; assert t['removed'] == [], t['removed']" &&
  ok "the base's test files are found as the pull request's: not one below a glob's folder, above its last, or whose name starts with a dot (no check removed)" ||
  bad "the base's test files found otherwise than the pull request's" "$out"
cp "$L/db/parts/types.authz" "$T/outside.authz"
out=$(LCLI review --base main "$T/outside.authz" 2>&1); rc=$?
case "$out" in *"added    app role"*) [ $rc -eq 0 ] && ok "a policy outside the repository: none at the base, reviewed as new, as before" || bad "a policy outside the repository: exit" "$rc";;
  *) bad "a policy outside the repository" "$out";; esac
cp "$L/db/parts/types.authz" "$L/db/policy[2].authz"
out=$(LCLI review --base main "db/policy[2].authz" 2>&1); rc=$?
case "$out" in *"added    app role"*) [ $rc -eq 0 ] && ok "a new policy whose name has a [ in it: reviewed as new (git doesn't read the name as a pattern)" || bad "a new policy named with a [: exit" "$rc";;
  *) bad "a new policy named with a [" "$out";; esac
mv "$L/db/policy[2].authz" "$L/:!policy.authz"
out=$(LCLI review --base main ':!policy.authz' 2>&1); rc=$?
case "$out" in *"added    app role"*) [ $rc -eq 0 ] && ok "... nor one at the top whose name starts with :! (git doesn't read it as a pathspec's magic)" || bad "a new policy named :!...: exit" "$rc";;
  *) bad "a new policy named :!..." "$out";; esac
rm "$L/:!policy.authz"
cp -a "$L" "$T/lost.kept"
fetch=": this repository is missing objects of that commit (a partial clone that can't fetch them? fetch the base's history: fetch-depth: 0 with actions/checkout, and no filter)"
lost() {  # the review in a copy of the repository missing one object of the base: the one at path $1 there
  rc=""
  rm -rf "$L" && cp -a "$T/lost.kept" "$L" && sha=$(git -C "$L" rev-parse "main:$1") &&
    rm -f "$L/.git/objects/${sha:0:2}/${sha:2}" || { out="the object at $1 not taken out"; return; }
  out=$(LCLI review --base main 2>&1); rc=$?
}
lost db/policy.authz
[ "$rc" = 2 ] && [ "$out" = "rowstile review: git can't read db/policy.authz at main$fetch" ] &&
  ok "a policy git lists at the base and can't read: the review stops, exit 2, and says how to fetch it (not the policy as new)" ||
  bad "a policy git can't read at the base" "$rc $out"
lost db/parts/types.authz
[ "$rc" = 2 ] && [ "$out" = "rowstile review: git can't read db/parts/types.authz at main$fetch" ] &&
  ok "... a file it includes (not a mistake of the base's)" || bad "an included file git can't read at the base" "$rc $out"
lost db/policy.lock
[ "$rc" = 2 ] && [ "$out" = "rowstile review: git can't read db/policy.lock at main$fetch" ] &&
  ok "... its lock file (not Deploy as if the base had none)" || bad "a lock file git can't read at the base" "$rc $out"
lost db/tests/a.authz
[ "$rc" = 2 ] && [ "$out" = "rowstile review: git can't read db/tests/a.authz at main$fetch" ] &&
  ok "... a test file (not the base's tests without it)" || bad "a test file git can't read at the base" "$rc $out"
lost db/tests
[ "$rc" = 2 ] && [ "$out" = "rowstile review: git can't list the files at main$fetch" ] &&
  ok "... a folder git can't list (which test files it holds is unknown)" || bad "a folder git can't list at the base" "$rc $out"
lost db
[ "$rc" = 2 ] && [ "$out" = "rowstile review: git can't read db/policy.authz at main$fetch" ] &&
  ok "... the folder the policy is in (whether the policy is there is unknown)" || bad "the policy's folder git can't list at the base" "$rc $out"

echo "-- a review database whose owner may not switch to the app role"
# since PostgreSQL 16 a role that makes another gets ADMIN on it, not SET (the suites' owner has
# createrole_self_grant, which would hide it); the tests run as the app role
N=authz_review_plain
R=authz_review_plain_app
dropdb --if-exists "$N" 2>/dev/null; psql -X -q -d postgres -c "DROP ROLE IF EXISTS $R" >/dev/null 2>&1
createdb "$N" || exit 1
PGOPTIONS="-c createrole_self_grant= -c client_min_messages=error" psql -X -q -v ON_ERROR_STOP=1 -d "$N" \
  -c "CREATE ROLE $R" -c "CREATE SCHEMA app" -c "CREATE TABLE app.users (id bigint PRIMARY KEY)" \
  -c "CREATE TABLE app.notes (id bigint PRIMARY KEY, owner_id bigint NOT NULL REFERENCES app.users, body text)" \
  -c "GRANT USAGE ON SCHEMA app TO $R" -c "GRANT SELECT ON app.users TO $R" -c "GRANT SELECT, UPDATE ON app.notes TO $R" >/dev/null || exit 1
Q="$T/plain"; mkdir -p "$Q/db/tests"
printf 'app role %s\ntype user = app.users\ntype note = app.notes\n  owner : user = owner_id\n  can edit = owner\nrules app.notes\n  select : edit\n  update : edit\n' "$R" > "$Q/db/policy.authz"
printf 'test "the owner reads its note"\n  as user 1 sees 1 {SELECT FROM app.notes}\n' > "$Q/db/tests/t.authz"
printf 'policy = "db/policy.authz"\ntests = ["db/tests/*.authz"]\n[migrations]\ntool = "sql"\ndir = "db/migrations"\n' > "$Q/rowstile.toml"
QCLI() { ( cd "$Q" && python3 "$OLDPWD/cli/rowstile_cli.py" "$@" ); }
{ git -C "$Q" init -q -b main && git -C "$Q" config user.email t@example.com && git -C "$Q" config user.name t &&
  QCLI migrate >/dev/null && git -C "$Q" add -A && git -C "$Q" commit -q -m base; } || bad "setting up the plain owner's repository"
for f in "$Q"/db/migrations/*.sql; do
  PGOPTIONS="-c client_min_messages=error" psql -X -q -1 -v ON_ERROR_STOP=1 -d "$N" -f "$f" >/dev/null || bad "the plain owner's base migration"
done
sed -i 's/^  can edit = owner$/&\n  can view = edit/' "$Q/db/policy.authz"
out=$(QCLI --db "dbname=$N" review --base main 2>&1); rc=$?
case "$out" in *"may not switch to the app role $R (SET ROLE), and this looks at the data as the app does [AZ618]"*"HINT: "*"GRANT \"$R\" TO \"$PGUSER\""*)
  [ $rc -eq 1 ] && ok "the review says what to grant, exit 1" || bad "review as a plain owner: exit" "$rc";;
  *) bad "review as a plain owner" "$out";; esac
dropdb --if-exists "$N"; psql -X -q -d postgres -c "DROP ROLE IF EXISTS $R" >/dev/null 2>&1

rm -rf "$T"
dropdb --if-exists "$DB" 2>/dev/null
[ $fails -eq 0 ] && echo "review: all passed" || { echo "review: $fails failed"; exit 1; }

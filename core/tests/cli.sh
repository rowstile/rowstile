#!/bin/bash
# cli.sh: the rowstile command: apply (with included files read from disk), check, diff, test,
# graph, client, reapply, remove, and its exit codes.
#   PGHOST=... PGUSER=postgres tests/cli.sh
set -u
cd "$(dirname "$0")/.."
DB=authz_cli
fails=0
PSQL() { psql -X -q -At -v ON_ERROR_STOP=1 -d "$DB" "$@"; }
ok() { echo "ok    $1"; }
bad() { echo "FAIL  $1${2:+: $2}"; fails=$((fails + 1)); }
# (with --db, except where the command reads no database and refuses it: check, prove, fmt, migrate, and a graph
# or a client of a file)
CLI() {
  case "$1:$#" in
    check:* | prove:* | fmt:* | migrate:* | graph:2 | client:3) python3 cli/rowstile_cli.py "$@" ;;
    *) python3 cli/rowstile_cli.py --db "dbname=$DB" "$@" ;;
  esac
}
# runs the command; sets $out (stdout and stderr) and $rc
run() { out=$(CLI "$@" 2>&1); rc=$?; }

dropdb --if-exists "$DB" 2>/dev/null; createdb "$DB" || exit 1
PGOPTIONS="-c client_min_messages=error" psql -X -q -v ON_ERROR_STOP=1 -d "$DB" -f example/app_schema.sql >/dev/null || exit 1
T=$(mktemp -d)
mkdir -p "$T/parts"
printf 'include "parts/all.authz"   -- the whole example policy\n' > "$T/main.authz"
cp example/docs.authz "$T/parts/all.authz"

echo "-- apply and check"
run apply "$T/main.authz"
[ $rc -eq 0 ] && [ "$out" = "$T/main.authz: applied" ] && ok "apply reads the included files from disk" || bad "apply" "$out"
[ "$(PSQL -c "SELECT authz.verify()")" = t ] && ok "... and the policy is in force" || bad "verify"
[ "$(PSQL -c "SELECT count(*) FROM jsonb_object_keys((SELECT files FROM authz.policy_versions ORDER BY id DESC LIMIT 1))")" = 1 ] &&
  ok "... and the included file is stored with it" || bad "stored files"
run check "$T/main.authz"; [ $rc -eq 0 ] && [ "$out" = "$T/main.authz: ok" ] && ok "check: ok, exit 0" || bad "check good" "$rc $out"
printf 'app role app_user\ntype user = app.users\n  can view = nosuch\n' > "$T/parts/bad.authz"
printf 'include "parts/bad.authz"\n' > "$T/bad.authz"
run check "$T/bad.authz"
case "$out" in "$T/bad.authz: parts/bad.authz line 3: "*) [ $rc -eq 1 ] && ok "check names the included file and line, exit 1" || bad "check exit" "$rc";;
  *) bad "check bad" "$out";; esac
run apply "$T/bad.authz"
case "$out" in *"parts/bad.authz line 3"*) [ $rc -eq 1 ] && ok "apply refuses it, exit 1" || bad "apply bad exit" "$rc";; *) bad "apply bad" "$out";; esac
printf 'include "parts/missing.authz"\n' > "$T/missing.authz"
run check "$T/missing.authz"; [ "$out" = "$T/missing.authz: line 1: can't find parts/missing.authz in the policy's folder [AZ108]" ] && ok "a missing include is reported with its line, in the command's words" || bad "missing" "$out"

echo "-- diff"
sed -e '/or linked_into.view/d' -e '/^  linked_into : folder/d' example/docs.authz > "$T/parts/all.authz"
run diff "$T/main.authz"
case "$out" in *" changes"*"folder"*"loses"*) [ $rc -eq 0 ] && ok "diff lists who loses what ($(echo "$out" | head -n 1 | sed 's/.*: //'))" || bad "diff exit" "$rc";; *) bad "diff" "$out";; esac
run diff "$T/main.authz" --users 3
[ $rc -eq 0 ] && ! echo "$out" | awk 'NR > 1 && $1 ~ /^(gains|loses)$/ && $2 != "3"' | grep -q . && ok "diff --users 3 lists only user 3" || bad "diff --users" "$out"
run diff "$T/main.authz" --limit 1; n=$(echo "$out" | head -n 1 | sed 's/.*: \([0-9]*\) changes.*/\1/')
[ $rc -eq 0 ] && [ "$n" -gt 1 ] && [ "$(echo "$out" | tail -n 1)" = "... and $((n - 1)) more (--limit)" ] && ok "diff --limit 1 lists one change, and says how many more" || bad "diff --limit" "$out"
[ "$(PSQL -c "SELECT authz.verify()")" = t ] && [ "$(PSQL -c "SELECT count(*) FROM authz.policy_versions")" = 1 ] && ok "diff changed nothing" || bad "diff changed something"
cp example/docs.authz "$T/parts/all.authz"
run diff "$T/main.authz"; case "$out" in *"0 changes (nobody gains"*) ok "diff of the policy in force: nothing";; *) bad "diff same" "$out";; esac
# each diff makes the new policies and undoes them, which leaves dead rows in pg_policy: with many of them the
# planner reads the catalog another way round. A table's name read back as a table is refused there for one of
# pg_toast's ("permission denied for schema pg_toast") to an owner who is no superuser: diff finds each policy's
# table by its oid
PSQL -c "BEGIN" -c "CREATE TABLE public.undone (id int)" \
  -c "DO \$\$ BEGIN FOR i IN 1..500 LOOP EXECUTE format('CREATE POLICY p%s ON public.undone USING (id = %s)', i, i); END LOOP; END \$\$" \
  -c "ROLLBACK" >/dev/null
run diff "$T/main.authz"; case "$out" in *"0 changes (nobody gains"*) ok "... and after many diffs undone, their policies dead in the catalog";; *) bad "diff after many undone" "$out";; esac

echo "-- test"
# the policy's tests expect the two shares the example scenario makes first
PSQL -c "SET ROLE app_user" -c "SET authz.user_id = 5" -c "SELECT authz.share('folder', 1, 'viewer', 'org', 1, 'member')" \
     -c "SELECT authz.share('file', 13, 'viewer', 'user', 4, '', now() + interval '1 day')" >/dev/null
run test; [ $rc -eq 0 ] && echo "$out" | grep -q "policy tests passed" && ok "test passes and shows each check ($(echo "$out" | grep -c 'ok '))" || bad "test" "$out"
sed 's/user 3 can view file 11/user 3 cannot view file 11/' example/docs.authz > "$T/parts/all.authz"
CLI apply "$T/main.authz" >/dev/null 2>&1
run test; case "$out" in *"FAIL  parts/all.authz line 90: user 3 cannot view file 11"*"1 policy test(s) failed"*) [ $rc -eq 1 ] && ok "a failing test fails the command, exit 1" || bad "test exit" "$rc";; *) bad "failing test" "$out";; esac
cp example/docs.authz "$T/parts/all.authz"; CLI apply "$T/main.authz" >/dev/null 2>&1

echo "-- graph and client"
run graph; case "$out" in "%% Generated by rowstile graph"*) ok "graph of the current policy";; *) bad "graph" "${out:0:200}";; esac
run graph "$T/missing.authz"; [ $rc -eq 1 ] && ok "graph of a broken file fails" || bad "graph broken" "$rc $out"
run client py
if [ $rc -eq 0 ] && echo "$out" | python3 -c "import ast, sys; ast.parse(sys.stdin.read())" 2>/dev/null; then ok "client py is valid Python"; else bad "client py" "${out:0:200}"; fi
run client ts; case "$out" in *"export const permissions"*) ok "client ts";; *) bad "client ts" "${out:0:200}";; esac
run client java; [ $rc -eq 2 ] && ok "client with an unknown language: exit 2" || bad "client java" "$rc $out"

echo "-- reapply and remove"
run reapply; [ $rc -eq 0 ] && ok "reapply" || bad "reapply" "$out"
run remove; [ $rc -eq 2 ] && case "$out" in *"--yes"*) true;; *) false;; esac && ok "remove asks for --yes" || bad "remove without --yes" "$rc $out"
[ "$(PSQL -c "SELECT count(*) FROM pg_namespace WHERE nspname = 'authz_int'")" = 1 ] && ok "... and removes nothing without it" || bad "removed without --yes"
run remove --yes; [ $rc -eq 0 ] && [ "$(PSQL -c "SELECT count(*) FROM pg_namespace WHERE nspname = 'authz_int'")" = 0 ] && ok "remove --yes" || bad "remove" "$out"
run test; case "$out" in *"no policy is applied"*) [ $rc -eq 1 ] && ok "errors come back as the database's message, exit 1" || bad "error exit" "$rc";; *) bad "error message" "$out";; esac

echo "-- the command line: options anywhere, arguments counted"
run who folder 1 view; case "$out" in *"no policy is applied"*"AZ609"*) [ $rc -eq 1 ] && ok "who with no policy applied: the same message as the other commands" || bad "who exit" "$rc";; *) bad "who without a policy" "$out";; esac
CLI apply "$T/main.authz" >/dev/null 2>&1
dropdb --if-exists "${DB}_other" 2>/dev/null; createdb "${DB}_other"
out=$(PGDATABASE="${DB}_other" python3 cli/rowstile_cli.py lint --db "dbname=$DB" 2>&1); rc=$?
case "$out" in *"no policy is applied"*) bad "--db after the command is not read: the default database was used" "$out";; *) ok "--db after the command names the database";; esac
out=$(PGDATABASE="${DB}_other" python3 cli/rowstile_cli.py apply "$T/main.authz" --db "dbname=$DB" 2>&1); rc=$?
[ $rc -eq 0 ] && [ "$out" = "$T/main.authz: unchanged" ] && ok "... and after the policy file too" || bad "--db last" "$rc $out"
out=$(PGDATABASE="$DB" python3 cli/rowstile_cli.py remove --yes --db "dbname=${DB}_other" 2>&1); rc=$?
[ "$(PSQL -c "SELECT count(*) FROM pg_namespace WHERE nspname = 'authz_int'")" = 1 ] && case "$out" in *"no policy is applied"*) true;; *) false;; esac &&
  ok "remove --yes --db X leaves the default database alone" || bad "remove --db removed the wrong database's policy" "$out"
dropdb --if-exists "${DB}_other" 2>/dev/null
run check "$T/bad.authz" "$T/main.authz"; [ $rc -eq 2 ] && case "$out" in *"takes 1 argument"*) true;; *) false;; esac && ok "an argument too many is refused, exit 2" || bad "extra argument" "$rc $out"
run diff "$T/main.authz" --limit 5 --limit 7; [ $rc -eq 2 ] && case "$out" in *"--limit is given twice"*) true;; *) false;; esac && ok "an option given twice is refused" || bad "option twice" "$rc $out"
run lint --colour; [ $rc -eq 2 ] && case "$out" in *"--colour is not an option"*) true;; *) false;; esac && ok "an unknown option is refused" || bad "unknown option" "$rc $out"
# another command's option is refused too, where it would do nothing and say nothing (a CI step that doesn't do what
# its author meant), and so is a single dash: not taken for the policy file
run check --force "$T/main.authz"
[ "$rc $out" = "2 rowstile check: --force is not an option it has (rowstile check --help)" ] && ok "an option of another command is refused, exit 2" || bad "check --force" "$rc $out"
run apply --check "$T/main.authz"; [ "$rc $out" = "2 rowstile apply: --check is not an option it has (rowstile apply --help)" ] && ok "... apply --check too" || bad "apply --check" "$rc $out"
run migrate --development "$T/main.authz"; [ "$rc $out" = "2 rowstile migrate: --development is not an option it has (rowstile migrate --help)" ] && ok "... and migrate --development" || bad "migrate --development" "$rc $out"
run check -x "$T/main.authz"; [ "$rc $out" = "2 rowstile check: -x is not an option it has (rowstile check --help)" ] && ok "... and -x is named as an option, not blamed on the policy file" || bad "check -x" "$rc $out"
run lint -d "dbname=$DB"; [ "$rc $out" = "2 rowstile lint: -d is not an option it has (rowstile lint --help)" ] && ok "... and -d: --db only" || bad "lint -d" "$rc $out"
run perms --as user:5 folder -1; [ "$rc $out" = "0 (none)" ] && ok "a negative number is an argument, not an option" || bad "an id of -1" "$rc $out"
out=$(python3 cli/rowstile_cli.py --db "dbname=$DB" check "$T/main.authz" 2>&1); rc=$?
[ "$rc $out" = "2 rowstile check: --db is not an option it has: it reads no database" ] && ok "--db on a command that reads no database is refused, saying so" || bad "check --db" "$rc $out"
out=$(python3 cli/rowstile_cli.py --db "dbname=$DB" graph "$T/main.authz" 2>&1); rc=$?
[ "$rc $out" = "2 rowstile graph: --db or a policy file, not both: a file is read without a database" ] && ok "... and on a graph of a file" || bad "graph --db FILE" "$rc $out"
out=$(python3 cli/rowstile_cli.py --db "dbname=$DB" client py "$T/main.authz" 2>&1); rc=$?
[ "$rc $out" = "2 rowstile client: --db or a policy file, not both: a file is read without a database" ] && ok "... and a client of a file" || bad "client --db FILE" "$rc $out"
# a script's --db "$DATABASE_URL" with the variable unset: said, not a traceback
out=$(python3 cli/rowstile_cli.py --db "" lint 2>&1); rc=$?
[ "$rc $out" = "2 --db is empty" ] && ok "an empty --db is refused, exit 2" || bad "--db ''" "$rc $out"
run perms --as "" folder 1; [ "$rc $out" = "2 --as is empty" ] && ok "... and an empty --as" || bad "--as ''" "$rc $out"
run perms --as nobody folder 1; [ "$rc $out" = "2 --as nobody: write it as user:42, bot:7 or anyone" ] && ok "--as nobody is refused: anyone" || bad "--as nobody" "$rc $out"
out=$(python3 cli/rowstile_cli.py --db "dbname=authz_no_such_db" bogus 2>&1); rc=$?
case "$out" in "unknown command 'bogus'"*) [ $rc -eq 2 ] && ok "an unknown command is said before connecting" || bad "unknown command exit" "$rc";; *) bad "unknown command" "${out:0:120}";; esac
run sql --as user:5 "SELECT count(*) FROM app.files -- --limit 3"; [ $rc -eq 0 ] && ok "sql's statement is left as it is" || bad "sql" "$rc $out"
# Ctrl-C while sql waits on a statement: it stops at once, and the statement ends on the server too (started with job
# control on, as a terminal starts it: a background job otherwise ignores Ctrl-C)
sleeping() { PSQL -c "SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND query LIKE '%pg_sleep(30)%' AND state = 'active' AND pid <> pg_backend_pid()"; }
set -m
python3 cli/rowstile_cli.py --db "dbname=$DB" sql --as user:5 "SELECT pg_sleep(30)" > "$T/sleep.out" 2>&1 &
sleeper=$!
set +m
for _ in $(seq 60); do [ "$(sleeping)" = 1 ] && break; sleep 0.5; done
began=$(date +%s); kill -INT "$sleeper"; wait "$sleeper"; rc=$?; took=$(( $(date +%s) - began ))
for _ in $(seq 20); do [ "$(sleeping)" = 0 ] && break; sleep 0.5; done
[ $rc -eq 130 ] && [ "$(cat "$T/sleep.out")" = "stopped: nothing was kept" ] && [ $took -lt 10 ] && [ "$(sleeping)" = 0 ] &&
  ok "Ctrl-C while sql waits on a statement: stopped at once (exit 130), and the statement ended on the server" ||
  bad "Ctrl-C during sql" "exit $rc after ${took}s, still running on the server: $(sleeping), said: $(cat "$T/sleep.out")"
# ... and while apply waits for a lock another session holds (inside the savepoint it runs the policy in): the same
sed 's/^  delete                            : edit$/  delete                            : share/' example/docs.authz > "$T/parts/changed.authz"
printf 'include "parts/changed.authz"\n' > "$T/changed.authz"
versions=$(PSQL -c "SELECT count(*) FROM authz.policy_versions")
waiting() { PSQL -c "SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock' AND pid <> pg_backend_pid()"; }
PSQL -c "BEGIN" -c "LOCK TABLE app.files IN ACCESS EXCLUSIVE MODE" -c "SELECT pg_sleep(31)" > /dev/null 2>&1 &
holder=$!
for _ in $(seq 60); do [ "$(PSQL -c "SELECT count(*) FROM pg_locks l JOIN pg_class c ON c.oid = l.relation WHERE c.relname = 'files' AND l.mode = 'AccessExclusiveLock' AND l.granted")" = 1 ] && break; sleep 0.2; done
set -m
python3 cli/rowstile_cli.py --db "dbname=$DB" apply "$T/changed.authz" > "$T/apply.out" 2>&1 &
applier=$!
set +m
for _ in $(seq 60); do [ "$(waiting)" = 1 ] && break; sleep 0.5; done
before=$(waiting)
began=$(date +%s); kill -INT "$applier"; wait "$applier"; rc=$?; took=$(( $(date +%s) - began ))
for _ in $(seq 20); do [ "$(waiting)" = 0 ] && break; sleep 0.5; done
after=$(waiting)
PSQL -c "SELECT pg_cancel_backend(pid) FROM pg_stat_activity WHERE datname = current_database() AND query = 'SELECT pg_sleep(31)' AND pid <> pg_backend_pid()" > /dev/null
wait "$holder"
[ "$before" = 1 ] && [ $rc -eq 130 ] && [ "$(cat "$T/apply.out")" = "stopped: nothing was kept" ] && [ $took -lt 10 ] && [ "$after" = 0 ] &&
  [ "$(PSQL -c "SELECT count(*) FROM authz.policy_versions")" = "$versions" ] && [ "$(PSQL -c "SELECT authz.verify()")" = t ] &&
  ok "Ctrl-C while apply waits for a lock: stopped at once (exit 130), its statement ended on the server, nothing kept" ||
  bad "Ctrl-C during apply" "waiting $before, exit $rc after ${took}s, still waiting on the server: $after, said: $(cat "$T/apply.out")"
run explain-rule --as user:3 app.files insert --row '{folder_id: 6}'; [ $rc -eq 2 ] && case "$out" in *"--row: not JSON: {folder_id: 6}"*"The shell took the double quotes"*) true;; *) false;; esac && ok "explain-rule shows a row a Windows shell took the quotes out of, and how to write it there" || bad "explain-rule --row without quotes" "$out"
run explain-rule --as user:3 app.files insert --row '[1]'; [ $rc -eq 2 ] && case "$out" in *"JSON object"*) true;; *) false;; esac && ok "explain-rule --row wants an object" || bad "--row" "$rc $out"
run diff "$T/main.authz" --limit; [ $rc -eq 2 ] && [ "$out" = "--limit needs a value" ] && ok "an option without its value is refused" || bad "option without value" "$rc $out"
run studio --port 70000; [ $rc -eq 2 ] && [ "$out" = "--port needs a port, a whole number from 1 to 65535, not '70000'" ] &&
  ok "a port above 65535 is refused" || bad "studio --port 70000" "$rc ${out: -200}"
run dev --once --studio-port 99999 "$T/main.authz"; [ $rc -eq 2 ] && [ "$out" = "--studio-port needs a port, a whole number from 1 to 65535, not '99999'" ] &&
  ok "... and one for Studio beside dev" || bad "dev --studio-port 99999" "$rc ${out: -200}"
run client rb "$T/main.authz"; [ $rc -eq 2 ] && [ "$out" = "rowstile client: which language, py or ts?" ] && ok "client in a language it doesn't write is refused" || bad "client rb" "$rc $out"
run client py; fromdb=$out
run client py "$T/main.authz"; [ $rc -eq 0 ] && [ -n "$out" ] && [ "$out" = "$fromdb" ] && ok "client py from the file alone is the one the applied policy gives" || bad "client py from a file" "$rc ${out:0:120}"
which='which policy file? (or name it in rowstile.toml: policy = "db/policy.authz")'
run check; [ $rc -eq 2 ] && [ "$out" = "rowstile check: $which" ] && ok "a command without its policy file, and no rowstile.toml, asks which" || bad "check without a file" "$rc $out"
run dev; [ $rc -eq 2 ] && [ "$out" = "rowstile dev: $which" ] && ok "... dev too" || bad "dev without a file" "$rc $out"
run review; [ $rc -eq 2 ] && [ "$out" = "rowstile review: $which" ] && ok "... and review" || bad "review without a file" "$rc $out"
run fmt; [ $rc -eq 2 ] && [ "$out" = "rowstile fmt: which files? (or name the policy in rowstile.toml)" ] && ok "... and fmt asks which files" || bad "fmt without files" "$rc $out"
run fmt "$T/nosuch.authz"; [ $rc -eq 2 ] && [ "$out" = "$T/nosuch.authz: No such file or directory" ] && ok "fmt on a file that isn't there says so, exit 2" || bad "fmt on a missing file" "$rc $out"
printf 'app role app_user\ntype user = app.users\n  can view = (\n' > "$T/broken.authz"; cp "$T/broken.authz" "$T/broken.before"
run fmt "$T/broken.authz"
case "$out" in *"broken.authz: can't format a policy that doesn't parse: "*) [ $rc -eq 1 ] && cmp -s "$T/broken.authz" "$T/broken.before" && ok "fmt on a policy that doesn't parse says so, exit 1, and leaves the file" || bad "fmt on a broken file: exit or file" "$rc";; *) bad "fmt on a broken file" "$rc $out";; esac
run migrate "$T/main.authz" --tool bogus; [ $rc -eq 2 ] && case "$out" in "rowstile migrate: unknown tool 'bogus' (use one of "*) true;; *) false;; esac && ok "migrate for a tool it doesn't know says which it does" || bad "migrate --tool" "$rc $out"
printf 'app role app_user\ntype user = app.users\n' > "$T/plain.authz"
run prove "$T/plain.authz"; [ $rc -eq 0 ] && case "$out" in *"no invariants to prove"*) true;; *) false;; esac && ok "prove on a policy without invariants says there is nothing to prove" || bad "prove without invariants" "$rc $out"
# a policy without rules names no role for row-level security: sql --as has none to take
CLI apply "$T/plain.authz" >/dev/null 2>&1
run sql --as user:1 "SELECT 1"
[ $rc -eq 1 ] && [ "$out" = "no policy with rules is applied, so there is no app role to run as" ] && ok "sql --as on a policy without rules says there is no app role to run as, exit 1" || bad "sql --as without rules" "$rc $out"
CLI apply "$T/main.authz" >/dev/null 2>&1

echo "-- the command's own pages: help, version, an error code's page"
out=$(python3 cli/rowstile_cli.py --version 2>&1); rc=$?
case "$out" in "rowstile "*" (Python "*")") [ $rc -eq 0 ] && ok "--version says the version, and the Python it runs on" || bad "--version exit" "$rc";; *) bad "--version" "$out";; esac
out=$(python3 cli/rowstile_cli.py version 2>&1); rc=$?
[ $rc -eq 2 ] && case "$out" in "unknown command 'version'"*) true;; *) false;; esac && ok "... and version is no command: --version" || bad "version" "$rc ${out:0:80}"
for asked in --help -h help; do
  out=$(python3 cli/rowstile_cli.py $asked 2>"$T/help.err"); rc=$?
  [ $rc -eq 0 ] && [ ! -s "$T/help.err" ] && case "$out" in "rowstile: compile policies"*"rowstile dev"*) true;; *) false;; esac &&
    ok "$asked prints the usage on stdout (for a pager or grep), exit 0" || bad "$asked" "$rc ${out:0:80} $(cat "$T/help.err")"
done
out=$(python3 cli/rowstile_cli.py check --help 2>"$T/help.err"); rc=$?
[ $rc -eq 0 ] && [ ! -s "$T/help.err" ] && case "$out" in "rowstile check   [POLICY.authz]"*) true;; *) false;; esac &&
  ok "... and a command's --help, its own lines" || bad "check --help" "$rc ${out:0:80}"
out=$(python3 cli/rowstile_cli.py bogus --help 2>&1); rc=$?
[ $rc -eq 2 ] && case "$out" in "unknown command 'bogus'"*) true;; *) false;; esac && ok "--help of a command that doesn't exist: unknown command, exit 2" || bad "bogus --help" "$rc ${out:0:80}"
out=$(python3 cli/rowstile_cli.py 2>&1); rc=$?
[ $rc -eq 2 ] && case "$out" in "rowstile: compile policies"*) true;; *) false;; esac && ok "no command at all: the usage, exit 2" || bad "no command" "$rc ${out:0:80}"
out=$(python3 cli/rowstile_cli.py help az201 2>&1); rc=$?
[ $rc -eq 0 ] && case "$out" in *AZ201*) true;; *) false;; esac && ok "help AZ201 shows that error's page, written in either case" || bad "help AZ201" "$rc ${out:0:80}"
out=$(python3 cli/rowstile_cli.py help errors 2>&1); rc=$?
[ $rc -eq 0 ] && case "$out" in *AZ201*AZ709*) true;; *) false;; esac && ok "help errors lists the codes" || bad "help errors" "$rc ${out:0:80}"
out=$(python3 cli/rowstile_cli.py help AZ999 2>&1); rc=$?
[ $rc -eq 2 ] && [ "$out" = "rowstile help: no code AZ999 (rowstile help errors lists them)" ] && ok "help with a code that doesn't exist says so, exit 2" || bad "help AZ999" "$rc $out"
out=$(python3 cli/rowstile_cli.py help codes 2>&1); rc=$?
[ "$rc $out" = "2 rowstile help: no code codes (rowstile help errors lists them)" ] && ok "... help codes too: help errors" || bad "help codes" "$rc $out"
out=$(python3 cli/rowstile_cli.py help AZ201 AZ202 2>&1); rc=$?
[ "$rc $out" = "2 rowstile help takes one code: rowstile help AZ201 (rowstile help errors lists them)" ] && ok "... and help with two codes" || bad "help with two codes" "$rc $out"
# with its output closed (started by a service, or by pythonw on Windows, where there is no console): it answers by
# its exit code all the same, and its errors still go to stderr
python3 cli/rowstile_cli.py check example/docs.authz >&-; rc=$?
out=$(python3 cli/rowstile_cli.py check "$T/bad.authz" 2>&1 >&-); rc2=$?
[ $rc -eq 0 ] && [ $rc2 -eq 1 ] && case "$out" in "$T/bad.authz: parts/bad.authz line 3: "*) true;; *) false;; esac &&
  ok "with its output closed: the same exit codes, and the mistake said on stderr" || bad "output closed" "$rc $rc2 $out"

echo "-- questions to the database, as someone"
want=$(PSQL -c "SET authz.user_id = '5'" -c "SELECT array_to_string(authz.perms('folder', 1), E'\n')")
run perms --as user:5 folder 1; [ $rc -eq 0 ] && [ "$out" = "${want:-(none)}" ] && ok "perms: what someone holds on an object, as authz.perms says" || bad "perms" "$rc $out (wanted $want)"
run perms --as user:5 folder 999999; [ $rc -eq 0 ] && [ "$out" = "(none)" ] && ok "... and (none) where they hold nothing" || bad "perms none" "$rc $out"
want=$(PSQL -c "SELECT array_to_string(authz.perms('folder', 1), E'\n')")  # nobody signed in
run perms --as anyone folder 1; [ $rc -eq 0 ] && [ "$out" = "${want:-(none)}" ] && ok "--as anyone asks as nobody signed in" || bad "--as anyone" "$rc $out (wanted $want)"
run perms --as 5 folder 1; [ $rc -eq 2 ] && [ "$out" = "--as 5: write it as user:42, bot:7 or anyone" ] && ok "--as without a type is refused, with how to write it" || bad "--as 5" "$rc $out"
run can folder 1 view; [ $rc -eq 2 ] && [ "$out" = "rowstile can: as whom? --as user:42 (or bot:7, or anyone)" ] && ok "a question without --as asks as whom" || bad "can without --as" "$rc $out"
run can --as user:5 folder 1
[ "$rc $out" = "2 rowstile can takes 3 arguments, not 2:
rowstile can     --as WHO TYPE ID PERM         yes or no" ] && ok "a question an argument short is refused, with its usage" || bad "can short" "$rc $out"
run explain-rule --as user:3 app.files
[ $rc -eq 2 ] && case "$out" in "rowstile explain-rule takes 2 or 3 arguments, not 1:
rowstile explain-rule --as WHO TABLE"*) true;; *) false;; esac && ok "explain-rule without a command shows how to ask" || bad "explain-rule short" "$rc $out"
run why folder 1 view; [ $rc -eq 2 ] && [ "$out" = "rowstile why --as user:42 TYPE ID PERM" ] && ok "why without --as shows how to ask" || bad "why without --as" "$rc $out"
run why --as anyone folder 1 view
[ $rc -eq 2 ] && [ "$out" = "rowstile why: as whom? someone signed in (user:42, bot:7): nobody can be given access" ] &&
  ok "... and why --as anyone asks as whom too, exit 2" || bad "why --as anyone" "$rc $out"
run sql --as user:5 "UPDATE app.files SET name = name WHERE false"; [ $rc -eq 0 ] && [ "$out" = "UPDATE 0, as user:5; rolled back" ] && ok "sql says what a statement without rows did, in the server's words" || bad "sql's tag" "$rc $out"
run sql --as user:5 "SELECT true AS yes, ARRAY['x','y z',NULL] AS words, '{\"k\": 1}'::jsonb AS doc"
[ $rc -eq 0 ] && [ "$(echo "$out" | sed -n 3p)" = 't    {x,"y z",NULL}  {"k": 1}' ] &&
  ok "... and writes values as Postgres does, as psql shows them: t, {x,\"y z\",NULL}, JSON" || bad "sql's values" "$out"
# COPY ... FROM STDIN waits for rows the command has none of: the copy is failed at once, in the server's words
# (it waited for good, the transaction open), on a table without row-level security the app role may write
PSQL -c "CREATE TABLE app.cli_inbox (x int); GRANT INSERT ON app.cli_inbox TO app_user"
out=$(timeout 20 python3 cli/rowstile_cli.py --db "dbname=$DB" sql --as user:5 "COPY app.cli_inbox FROM STDIN" 2>&1); rc=$?
[ "$rc $out" = "1 COPY from stdin failed: the rowstile command sends no rows to COPY FROM STDIN (psql's \\copy does)" ] &&
  ok "sql with a COPY FROM STDIN says the command sends no rows, at once" || bad "sql COPY FROM STDIN" "$rc $out"
PSQL -c "DROP TABLE app.cli_inbox"

echo "-- files that can't be read as they should"
{ cat example/docs.authz; printf -- '-- caf\351\n'; } > "$T/latin.authz"
run check "$T/latin.authz"; case "$out" in *Traceback*) bad "a file that isn't UTF-8 gives a traceback" "$out";;
  *"not UTF-8"*) [ $rc -eq 2 ] && ok "a policy that isn't UTF-8: said, exit 2" || bad "not UTF-8 exit" "$rc";; *) bad "not UTF-8" "$out";; esac
printf 'test "caf\351"\n  user 3 can view file 11\n' > "$T/latin_test.authz"
run test "$T/latin_test.authz"; case "$out" in *"latin_test.authz: not UTF-8"*) [ $rc -eq 2 ] && ok "a test file that isn't UTF-8" || bad "test not UTF-8 exit" "$rc";; *) bad "test not UTF-8" "$out";; esac
printf 'include "parts/latin.authz"\n' > "$T/inc_latin.authz"; cp "$T/latin.authz" "$T/parts/latin.authz"
run check "$T/inc_latin.authz"; case "$out" in *"parts/latin.authz, is not UTF-8"*) ok "an included file that isn't UTF-8 is named";; *) bad "include not UTF-8" "$out";; esac
python3 -c "open('$T/deep.authz', 'w').write('app role app_user\ntype user = app.users\ntype d = app.d\n  o : user = owner_id\n  can view = ' + '(' * 3000 + 'o' + ')' * 3000 + '\n')"
run check "$T/deep.authz"; case "$out" in *Traceback*) bad "deep nesting gives a traceback" "${out: -200}";; *"nested too deep"*) ok "an expression nested too deep is said";; *) bad "deep" "${out:0:200}";; esac
run apply "$T/deep.authz"
[ $rc -eq 1 ] && [ "$out" = "rowstile apply: an expression in the policy is nested too deep to read" ] && [ "$(PSQL -c "SELECT authz.verify()")" = t ] &&
  ok "... by apply too, which leaves the policy in force" || bad "apply deep" "$rc ${out: -200}"

echo "-- rowstile.toml"
P="$T/proj"; mkdir -p "$P/db/tests" "$P/out"; cp example/docs.authz "$P/db/policy.authz"
TOML() {
  case "$1" in
    check | prove | fmt | migrate) ( cd "$P" && python3 "$OLDPWD/cli/rowstile_cli.py" "$@" ) ;;
    *) ( cd "$P" && python3 "$OLDPWD/cli/rowstile_cli.py" --db "dbname=$DB" "$@" ) ;;
  esac
}
toml() { printf "$1" > "$P/rowstile.toml"; out=$(TOML "${@:2}" 2>&1); rc=$?; }
toml 'policy = "db/policy.authz"\ntests = "db/tests/*.authz"\n' test
[ $rc -eq 2 ] && case "$out" in *"tests is a list of patterns"*) true;; *) false;; esac && ok "tests = \"...\" (not a list) is refused: it ran no named test" || bad "tests as text" "$rc ${out:0:200}"
toml 'policy = "db/policy.authz"\ntest = ["db/tests/*.authz"]\n' check
[ $rc -eq 2 ] && case "$out" in *"test is not a setting rowstile knows"*) true;; *) false;; esac && ok "a misspelt setting is named" || bad "misspelt setting" "$rc $out"
toml 'policy = "db/policy.authz"\n[migrations]\ntests = ["x"]\n' check
[ $rc -eq 2 ] && ok "a setting in the wrong table is refused" || bad "wrong table" "$rc $out"
toml '\357\273\277policy = "db/policy.authz"\n' check; [ $rc -eq 0 ] && ok "a byte order mark is skipped" || bad "BOM" "$rc $out"
toml 'policy = "db/policy.authz\n' check
[ $rc -eq 2 ] && case "$out" in "$P/rowstile.toml: "*) true;; *) false;; esac && ok "a rowstile.toml that isn't TOML is named, with what is wrong, exit 2" || bad "toml syntax" "$rc $out"
toml 'policy = "db/policy.authz"\nmigrations = "db/migrations"\n' check
[ $rc -eq 2 ] && [ "$out" = "$P/rowstile.toml: [migrations] is a table of settings" ] && ok "a table written as one setting is refused" || bad "table as setting" "$rc $out"
toml 'policy = "db/policy.authz"\ntests = ["db/nothere/*.authz"]\n' test
case "$out" in *"matches no file"*) ok "a tests pattern that matches no file is said";; *) bad "no test file" "${out:0:200}";; esac
toml 'policy = "/etc/passwd"\n' check
[ $rc -eq 2 ] && case "$out" in *"outside the folder"*) true;; *root:*) false;; *) false;; esac && ok "a policy outside rowstile.toml's folder is not read" || bad "policy outside" "$rc $out"
ln -s /etc/passwd "$P/db/link.authz"
toml 'policy = "db/link.authz"\n' check
[ $rc -eq 2 ] && case "$out" in *"outside the folder"*) true;; *) false;; esac && ok "... nor through a link out of it" || bad "policy link" "$rc $out"
toml 'policy = "db/policy.authz"\ntests = ["/etc/pass*"]\n' test
[ $rc -eq 2 ] && case "$out" in *"outside the folder"*) true;; *) false;; esac && ok "... nor test files" || bad "tests outside" "$rc ${out:0:200}"

echo "-- .env beside rowstile.toml"
# where a Next.js or Prisma app keeps its database's URL: read for what the environment doesn't set, .env.local first
E="$T/envproj"; mkdir -p "$E/db" "$E/sub"; cp example/docs.authz "$E/db/policy.authz"
printf 'policy = "db/policy.authz"\n' > "$E/rowstile.toml"
CLI_PY="$PWD/cli/rowstile_cli.py"
# runs the command in the project (or the folder named first with -C), with no DATABASE_URL of the suite's own
envrun() { local d="$E"; [ "$1" = -C ] && { d=$2; shift 2; }; out=$(cd "$d" && env -u DATABASE_URL -u OWNER_DSN python3 "$CLI_PY" "$@" 2>&1); rc=$?; }
envrun sql --as user:1 "SELECT 1"
[ $rc -eq 2 ] && case "$out" in "can't connect: "*) true;; *) false;; esac && ok "without a .env, nothing names the database" || bad "no .env" "$rc $out"
printf '# the owner\nexport DATABASE_URL="dbname=%s"   # development\nGIT_SSH_COMMAND=false\n' "$DB" > "$E/.env"
envrun sql --as user:1 "SELECT 1"
[ $rc -eq 0 ] && case "$out" in *"as user:1; rolled back"*) true;; *) false;; esac && ok "DATABASE_URL in .env names it" || bad ".env" "$rc $out"
envrun -C "$E/sub" sql --as user:1 "SELECT 1"; [ $rc -eq 0 ] && ok "... from a folder below too: the .env beside rowstile.toml" || bad ".env from below" "$rc $out"
envrun dev --once --no-studio
case "$out" in "rowstile dev: "*" -> $DB on "*" (from .env)"*) ok "rowstile dev says the database came from .env";; *) bad "dev and .env" "$out";; esac
printf "DATABASE_URL='dbname=authz_no_such_db'\n" > "$E/.env.local"
envrun sql --as user:1 "SELECT 1"
[ $rc -eq 2 ] && case "$out" in "can't connect: "*"(the database is the one .env.local names)"*) true;; *) false;; esac &&
  ok ".env.local comes before .env, and a failed connection says which file named the database" || bad ".env.local" "$rc $out"
envrun dev --once --no-studio
[ $rc -eq 1 ] && case "$out" in *"  x    can't connect: "*"(the database is the one .env.local names)"*) true;; *) false;; esac &&
  ok "... and so does rowstile dev, exit 1" || bad "dev that can't connect" "$rc $out"
out=$(cd "$E" && DATABASE_URL="dbname=$DB" python3 "$CLI_PY" sql --as user:1 "SELECT 1" 2>&1); rc=$?
[ $rc -eq 0 ] && ok "the environment comes before both" || bad "the environment first" "$rc $out"
if [ -z "${PGPORT:-}" ]; then  # (a port of the suite's own would come first)
  printf 'PGPORT=1\n' > "$E/.env.local"
  envrun sql --as user:1 "SELECT 1"; [ $rc -eq 2 ] && ok "a PG* variable in a file completes the URL (here a port nothing listens on)" || bad "PGPORT from a file" "$rc $out"
  envrun --db "dbname=$DB" sql --as user:1 "SELECT 1"
  [ $rc -eq 0 ] && ok "... but not what --db names: the files aren't read then" || bad "--db and .env" "$rc $out"
fi
rm "$E/.env.local"
printf 'policy = "db/policy.authz"\ndatabase = "env:OWNER_DSN"\n' > "$E/rowstile.toml"
envrun sql --as user:1 "SELECT 1"
[ $rc -eq 2 ] && case "$out" in *'database = "env:OWNER_DSN", but OWNER_DSN is not set: not in the environment, and not in .env.local or .env beside rowstile.toml'*) true;; *) false;; esac &&
  ok "a variable rowstile.toml names that is nowhere: said, with where it was looked for" || bad "env: missing" "$rc $out"
printf 'OWNER_DSN=dbname=%s\n' "$DB" >> "$E/.env"
envrun sql --as user:1 "SELECT 1"; [ $rc -eq 0 ] && ok "... and found in .env once it is there" || bad "env: from .env" "$rc $out"
printf 'DATABASE_URL="dbname=%s"\n' "$DB" > "$T/outside.env"; rm "$E/.env"; ln -s "$T/outside.env" "$E/.env"
printf 'policy = "db/policy.authz"\n' > "$E/rowstile.toml"
envrun sql --as user:1 "SELECT 1"
[ $rc -eq 2 ] && case "$out" in *".env is a link out of its folder: it isn't read"*) true;; *) false;; esac &&
  ok "a .env that is a link out of the folder isn't read, and the failure says so" || bad "a link out" "$rc $out"

echo "-- the clients rowstile.toml names"
# (from its policy file: without --db, which would name the database's policy)
OWN() { ( cd "$P" && python3 "$OLDPWD/cli/rowstile_cli.py" "$@" ); }
printf 'policy = "db/policy.authz"\n[clients]\npy = "out/c.py"\n' > "$P/rowstile.toml"
out=$(OWN client 2>&1); rc=$?
[ $rc -eq 0 ] && [ -s "$P/out/c.py" ] && ok "rowstile client writes them" || bad "client files" "$rc $out"
size=$(wc -c < "$P/out/c.py")
printf 'type zz = app.nothere\n  can nosuch = bogus\n' >> "$P/db/policy.authz"
out=$(OWN client 2>&1); rc=$?
[ $rc -eq 1 ] && [ "$(wc -c < "$P/out/c.py")" = "$size" ] && ok "a mistake in the policy leaves the client file as it was" || bad "client file emptied" "$rc $(wc -c < "$P/out/c.py") $out"
cp example/docs.authz "$P/db/policy.authz"
cp "$P/out/c.py" "$T/c.before"
sed -i 's/^  can share = owner or folder.share$/&\n  can comment = view/' "$P/db/policy.authz"
out=$(OWN client 2>&1); rc=$?
[ $rc -eq 0 ] && ! cmp -s "$P/out/c.py" "$T/c.before" && grep -q "comment" "$P/out/c.py" && ok "... and a change to the policy writes it again" || bad "client file not written again" "$rc $out"
cp example/docs.authz "$P/db/policy.authz"
toml '[clients]\npy = "out/db.py"\n' client
[ $rc -eq 0 ] && [ "$out" = "wrote out/db.py" ] && [ "$(cat "$P/out/db.py")" = "$(CLI client py)" ] &&
  ok "... and without a policy in rowstile.toml, the policy in force's" || bad "clients from the database" "$rc $out"
# with --db, graph and client read the database's policy, not the file rowstile.toml names (here one that differs)
sed -i 's/^  can share = owner or folder.share$/&\n  can comment = view/' "$P/db/policy.authz"
toml 'policy = "db/policy.authz"\n' graph
[ $rc -eq 0 ] && [ "$out" = "$(CLI graph)" ] && ! grep -q comment <<< "$out" &&
  ok "graph --db reads the policy in force, though rowstile.toml names a file" || bad "graph --db with rowstile.toml" "$rc ${out:0:200}"
toml 'policy = "db/policy.authz"\n[clients]\npy = "out/db.py"\n' client
[ $rc -eq 0 ] && [ "$out" = "wrote out/db.py" ] && [ "$(cat "$P/out/db.py")" = "$(CLI client py)" ] &&
  ok "... and client --db" || bad "client --db with rowstile.toml" "$rc $out"
cp example/docs.authz "$P/db/policy.authz"

echo "-- snapshot: where it writes"
toml 'policy = "db/policy.authz"\n' snapshot
[ $rc -eq 0 ] && case "$out" in "wrote db/access.snapshot ("*" lines)") true;; *) false;; esac && [ -s "$P/db/access.snapshot" ] &&
  ok "snapshot writes access.snapshot beside the policy" || bad "snapshot beside the policy" "$rc $out"
toml 'policy = "db/policy.authz"\n[review]\nsnapshot = "review/access.txt"\n' snapshot
[ $rc -eq 0 ] && case "$out" in "wrote review/access.txt ("*" lines)") true;; *) false;; esac && [ -s "$P/review/access.txt" ] &&
  ok "... or where [review] snapshot says, making its folder" || bad "snapshot where rowstile.toml says" "$rc $out"
out=$(TOML snapshot --out db 2>&1); rc=$?
[ $rc -eq 2 ] && [ "$out" = "db: Is a directory" ] && ok "a file it can't write (here a folder) is named, with why, exit 2: not a lost database" || bad "snapshot into a folder" "$rc $out"

echo "-- a server that goes away, two applies at once"
( sleep 2; psql -X -q -At -d postgres -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '$DB' AND query LIKE '%pg_sleep(7)%' AND pid <> pg_backend_pid()" >/dev/null ) &
run sql --as user:5 "SELECT pg_sleep(7)"; wait
case "$out" in *Traceback*) bad "a lost connection gives a traceback" "${out: -300}";;
  "lost the database: "*"terminating connection"*) [ $rc -eq 2 ] && ok "a server that ends the connection: its message, exit 2" || bad "lost exit" "$rc";; *) bad "lost the database" "$out";; esac
# ... and one that ends it while the command waits inside a savepoint (diff, on a table another session holds):
# going back to the savepoint finds the connection gone
( PSQL -c "BEGIN" -c "LOCK TABLE app.folders IN ACCESS EXCLUSIVE MODE" -c "SELECT pg_sleep(6)" -c "COMMIT" >/dev/null 2>&1 ) &
locker=$!
for _ in $(seq 40); do [ "$(PSQL -c "SELECT count(*) FROM pg_locks WHERE relation = 'app.folders'::regclass AND mode = 'AccessExclusiveLock' AND granted")" = 1 ] && break; sleep 0.25; done
( CLI diff "$T/main.authz" > "$T/diff.out" 2>&1; echo $? > "$T/diff.rc" ) &
differ=$!
for _ in $(seq 40); do w=$(PSQL -c "SELECT pid FROM pg_stat_activity WHERE datname = '$DB' AND application_name = 'rowstile' AND wait_event_type = 'Lock' LIMIT 1"); [ -n "$w" ] && break; sleep 0.25; done
[ -n "$w" ] && PSQL -c "SELECT pg_terminate_backend($w)" >/dev/null
wait "$differ"
PSQL -c "SELECT pg_cancel_backend(pid) FROM pg_stat_activity WHERE datname = '$DB' AND query = 'SELECT pg_sleep(6)'" >/dev/null
wait "$locker"; out=$(cat "$T/diff.out")
case "$out" in *Traceback*) bad "a connection lost inside a savepoint gives a traceback" "${out: -300}";;
  "lost the database: "*) [ "$(cat "$T/diff.rc")" = 2 ] && ok "... and while the command waits inside a savepoint: lost the database, exit 2" || bad "lost in a savepoint: exit" "$(cat "$T/diff.rc")";;
  *) bad "lost in a savepoint" "$out";; esac
( CLI apply --force "$T/main.authz" > "$T/a1.out" 2>&1; echo $? > "$T/a1.rc" ) &
( CLI apply --force "$T/main.authz" > "$T/a2.out" 2>&1; echo $? > "$T/a2.rc" ) &
wait
[ "$(cat "$T/a1.rc")$(cat "$T/a2.rc")" = "00" ] && ok "two applies at once: the second waits for the first" || bad "two applies" "$(cat "$T/a1.out" "$T/a2.out")"
CLI remove --yes >/dev/null 2>&1

echo "-- connecting"
out=$(python3 cli/rowstile_cli.py --db "dbname=authz_no_such_db" test 2>&1); rc=$?
case "$out" in "can't connect"*) [ $rc -eq 2 ] && ok "a database that doesn't exist: exit 2" || bad "connect exit" "$rc";; *) bad "connect" "$out";; esac
out=$(python3 cli/rowstile_cli.py --db "colour=blue" test 2>&1); case "$out" in *"unknown connection setting 'colour'"*) ok "unknown connection settings are named";; *) bad "dsn" "$out";; esac
out=$(python3 cli/rowstile_cli.py --db "colour=blue" dev --once --no-studio "$T/main.authz" 2>&1); rc=$?
[ $rc -eq 2 ] && case "$out" in "can't connect: "*"unknown connection setting 'colour'"*) true;; *) false;; esac &&
  ok "... by dev too, before its loop starts, exit 2" || bad "dev with a setting it doesn't know" "$rc ${out: -300}"
out=$(PGDATABASE=$DB python3 cli/rowstile_cli.py test 2>&1); case "$out" in *"no policy is applied"*) ok "PGDATABASE is used when --db is left out";; *) bad "env" "${out:0:200}";; esac
# what the server says as the session starts (here a setting of the database's it can't take; after a system
# upgrade, a collation version that doesn't match), on stderr as psql shows it; and by dev, as it shows a warning
PSQL -c "ALTER DATABASE $DB SET default_text_search_config = 'public.nosuch'" 2>/dev/null
starting='WARNING: invalid value for parameter "default_text_search_config": "public.nosuch"'
out=$(CLI test 2>&1 >/dev/null); rc=$?
[ "$rc $out" = "1 $starting"$'\nno policy is applied [AZ609]\nHINT: rowstile apply db/policy.authz' ] &&
  ok "a warning the server sends as the session starts is said, on stderr" || bad "a warning as the session starts" "$rc $out"
run dev --once --no-studio "$T/main.authz"
case "$out" in *$'\n  ok   compiles\n  !    '"${starting#WARNING: }"$'\n'*) ok "... and by dev";; *) bad "dev, a warning as the session starts" "$out";; esac
PSQL -c "ALTER DATABASE $DB RESET default_text_search_config" 2>/dev/null
CLI remove --yes >/dev/null 2>&1  # what dev applied: none again, as before
out=$(PGHOST=/nowhere python3 cli/rowstile_cli.py graph "$T/main.authz" 2>&1); case "$out" in "%% Generated"*) ok "check, graph and client of a file need no database";; *) bad "no database" "${out:0:200}";; esac

# a named database that doesn't answer is said as that, with where it tried (unit_test.py has the case where nothing
# names one)
out=$(python3 cli/rowstile_cli.py --db "host=127.0.0.1 port=1 dbname=x connect_timeout=2" lint 2>&1); rc=$?
[ "$rc $out" = "2 can't connect to 127.0.0.1 port 1: connection refused" ] &&
  ok "... and a named one that doesn't answer is only that, with the host and port it tried" || bad "a named database that doesn't answer" "$rc $out"
out=$(python3 cli/rowstile_cli.py --db "host=/nowhere port=5433 dbname=x" lint 2>&1); rc=$?
[ "$rc $out" = "2 can't connect to the socket /nowhere/.s.PGSQL.5433: no such file or directory" ] &&
  ok "... and a socket that isn't there, with its path" || bad "a socket that isn't there" "$rc $out"

echo "-- lint where it finds nothing"
# an app role of its own (JIT off) that reads only the table the rules govern, and may change only its body
N=authz_cli_lint
R=authz_cli_lint_app
dropdb --if-exists "$N" 2>/dev/null; psql -X -q -d postgres -c "DROP ROLE IF EXISTS $R" >/dev/null 2>&1
createdb "$N" || exit 1
PGOPTIONS="-c client_min_messages=error" psql -X -q -v ON_ERROR_STOP=1 -d "$N" \
  -c "CREATE ROLE $R" -c "ALTER ROLE $R SET jit = off" -c "CREATE SCHEMA app" -c "CREATE TABLE app.users (id bigint PRIMARY KEY)" \
  -c "CREATE TABLE app.notes (id bigint PRIMARY KEY, owner_id bigint NOT NULL REFERENCES app.users, body text)" \
  -c "CREATE INDEX ON app.notes (owner_id)" -c "GRANT USAGE ON SCHEMA app TO $R" -c "GRANT SELECT, UPDATE (body) ON app.notes TO $R" >/dev/null || exit 1
printf 'app role %s\ntype user = app.users\ntype note = app.notes\n  owner : user = owner_id\n  can edit = owner\nrules app.notes\n  select : edit\n  update : edit\n' "$R" > "$T/clean.authz"
python3 cli/rowstile_cli.py --db "dbname=$N" apply "$T/clean.authz" >/dev/null 2>&1
out=$(python3 cli/rowstile_cli.py --db "dbname=$N" lint 2>&1); rc=$?
[ $rc -eq 0 ] && [ "$out" = "authz.lint(): nothing found" ] && ok "lint where it finds nothing says so, exit 0" || bad "lint, nothing found" "$rc $out"
# a warning fails it too: an update rule the app role has no privilege for
psql -X -q -d "$N" -c "REVOKE UPDATE (body) ON app.notes FROM $R" >/dev/null
out=$(python3 cli/rowstile_cli.py --db "dbname=$N" lint 2>&1); rc=$?
case "$out" in *"warning"*"app.notes"*"the policy has a rule for update"*) [ $rc -eq 1 ] && ok "... and where it finds a warning, exit 1" || bad "lint on a warning: exit" "$rc";;
  *) bad "lint on a warning" "$out";; esac
dropdb "$N"; psql -X -q -d postgres -c "DROP ROLE IF EXISTS $R" >/dev/null 2>&1

echo "-- an owner that only administers the app role"
# since PostgreSQL 16 a role that makes another gets ADMIN on it, not SET: what an owner on managed Postgres has
# until it grants itself the role (the suites' owner has createrole_self_grant, which would hide it)
N=authz_cli_plain
R=authz_cli_plain_app
dropdb --if-exists "$N" 2>/dev/null; psql -X -q -d postgres -c "DROP ROLE IF EXISTS $R" >/dev/null 2>&1
createdb "$N" || exit 1
PGOPTIONS="-c createrole_self_grant= -c client_min_messages=error" psql -X -q -v ON_ERROR_STOP=1 -d "$N" \
  -c "CREATE ROLE $R" -c "CREATE SCHEMA app" -c "CREATE TABLE app.users (id bigint PRIMARY KEY)" \
  -c "CREATE TABLE app.notes (id bigint PRIMARY KEY, owner_id bigint NOT NULL REFERENCES app.users, body text)" \
  -c "GRANT USAGE ON SCHEMA app TO $R" -c "GRANT SELECT ON app.users TO $R" -c "GRANT SELECT, UPDATE ON app.notes TO $R" \
  -c "INSERT INTO app.users VALUES (1), (2)" -c "INSERT INTO app.notes VALUES (1, 1, 'mine')" >/dev/null || exit 1
printf 'app role %s\ntype user = app.users\ntype note = app.notes\n  owner : user = owner_id\n  can edit = owner\nrules app.notes\n  select : edit\n  update : edit\n' "$R" > "$T/plain.authz"
printf 'test "the owner reads and changes its note"\n  as user 1 sees 1 {SELECT FROM app.notes}\n  as user 2 refused {UPDATE app.notes SET body = %s WHERE id = 1}\n' "'x'" > "$T/plain.test.authz"
PLAIN() { out=$(python3 cli/rowstile_cli.py --db "dbname=$N" "$@" 2>&1); rc=$?; }
PLAIN apply "$T/plain.authz"; [ $rc -eq 0 ] && ok "apply needs no more than making the role" || bad "apply as a plain owner" "$out"
said="may not switch to the app role $R (SET ROLE), and this looks at the data as the app does [AZ618]"
PLAIN test "$T/plain.test.authz"
case "$out" in *"$said"*"GRANT \"$R\" TO \"$PGUSER\""*) [ $rc -eq 1 ] && ok "test says what to grant, and no check passes on the refused switch" || bad "test exit" "$rc";;
  *) bad "test as a plain owner" "$out";; esac
PLAIN sql --as user:1 "SELECT count(*) FROM app.notes"; case "$out" in *"$said"*) ok "... and sql --as";; *) bad "sql --as as a plain owner" "$out";; esac
PLAIN plans --as user:1; case "$out" in *"$said"*) ok "... and plans";; *) bad "plans as a plain owner" "$out";; esac
PLAIN bench --people 1 --rounds 1; case "$out" in *"$said"*) ok "... and bench";; *) bad "bench as a plain owner" "$out";; esac
PLAIN explain-rule --as user:2 app.notes update 1; case "$out" in *"$said"*) ok "... and explain-rule";; *) bad "explain-rule as a plain owner" "$out";; esac
PLAIN can --as user:1 note 1 edit; [ "$out" = yes ] && ok "the questions that don't switch role are answered" || bad "can as a plain owner" "$out"
# the dev loop there: the policy goes in, then the tests' switch is refused. Its last line says what is left,
# and names who else may run the grant
mkdir -p "$T/plainp"; cp "$T/plain.authz" "$T/plainp/policy.authz"; cp "$T/plain.test.authz" "$T/plainp/t.authz"
printf 'policy = "policy.authz"\ntests = ["t.authz"]\ndatabase = "dbname=%s"\n' "$N" > "$T/plainp/rowstile.toml"
PLAIN push --development "$T/plain.authz"
out=$(cd "$T/plainp" && python3 "$OLDPWD/cli/rowstile_cli.py" dev --once 2>&1); rc=$?
case "$out" in *"nothing applied"*) bad "dev as a plain owner says nothing was applied" "$out";;
  *"$said"*"if it made $R, else as the role that did or a superuser: GRANT"*"the policy is applied; its tests didn't run"*)
    [ $rc -eq 1 ] && ok "dev says the policy is applied and its tests did not run, and who may grant" || bad "dev exit" "$rc";;
  *) bad "dev as a plain owner" "$out";; esac
psql -X -q -d "$N" -c "GRANT $R TO $PGUSER" >/dev/null
PLAIN test "$T/plain.test.authz"; [ $rc -eq 0 ] && ok "after the grant, the tests pass" || bad "test after the grant" "$out"
PLAIN sql --as user:2 "SELECT count(*) FROM app.notes"; case "$out" in *"0"*"as user:2; rolled back"*) ok "... and sql --as reads as the app does";; *) bad "sql --as after the grant" "$out";; esac
PLAIN sql --as user:2 "UPDATE app.notes SET body = 'theirs' WHERE id = 1"
[ "$out" = "UPDATE 0, as user:2; rolled back" ] && ok "... and says a write changed no row, in the server's words" || bad "sql --as, a write of no row" "$out"
PLAIN sql --as user:1 "UPDATE app.notes SET body = 'still mine' WHERE id = 1"
[ "$out" = "UPDATE 1, as user:1; rolled back" ] && ok "... or one" || bad "sql --as, a write" "$out"
dropdb "$N"; psql -X -q -d postgres -c "DROP ROLE IF EXISTS $R" >/dev/null 2>&1

rm -rf "$T"
[ -z "${KEEP:-}" ] && dropdb "$DB"
if [ $fails -eq 0 ]; then echo "cli: all passed"; else echo "cli: $fails failed"; exit 1; fi

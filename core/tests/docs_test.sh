#!/bin/bash
# docs_test.sh: docs/getting-started.md runs as written and does what the guide says, and the blog post's
# experiment.sql runs as its header says.
#   PGHOST=... PGUSER=postgres tests/docs_test.sh
# Walks the guide's blocks in order, in a fresh database and an empty folder: ```sql blocks run in psql,
# ```authz <file> blocks are written to that file, ```sh blocks run (with rowstile on the PATH, and
# DATABASE_URL naming the database). Then checks what the guide's comments promise.
set -u
cd "$(dirname "$0")/.."
DB=authz_docs
GUIDE=../docs/getting-started.md
fails=0
check() { if [ "$2" = "$3" ]; then echo "ok    $1"; else echo "FAIL  $1: expected '$3', got '$2'"; fails=$((fails + 1)); fi; }

dropdb --if-exists "$DB" 2>/dev/null; createdb "$DB" || exit 1
drop_roles() {
  for r in app_backend docs_other; do
    psql -X -q -d postgres -c "DROP ROLE IF EXISTS $r" >/dev/null 2>&1
  done
}
drop_roles
DIR=$(mktemp -d)
# the folder step 1 puts on the PATH (an indented line, from the repository's root): the command is there
CLI=$(sed -n 's/^ *export PATH="\$PWD\/\([^:"]*\):\$PATH".*/\1/p' "$GUIDE" | head -n 1)
[ -n "$CLI" ] && [ -x "../$CLI/rowstile" ] && echo "ok    the guide's PATH line names the command's folder ($CLI)" ||
  { echo "FAIL  the guide's PATH line: '$CLI' doesn't hold the rowstile command"; fails=$((fails + 1)); CLI=core/cli; }
out=$(DATABASE_URL="dbname=$DB" PATH="$PWD/../$CLI:$PATH" python3 - "$GUIDE" "$DIR" "$DB" <<'PY'
import os, re, subprocess, sys
guide, folder, db = sys.argv[1:]
text = open(guide, encoding="utf-8").read()
for kind, name, body in re.findall(r"```(sql|authz|sh)[ \t]*([^\n]*)\n(.*?)```", text, re.S):
    if kind == "sql":
        p = subprocess.run(["psql", "-X", "-At", "-v", "ON_ERROR_STOP=1", "-d", db], input=body, text=True,
                           capture_output=True, env={**os.environ, "PGOPTIONS": "-c client_min_messages=warning"})
    elif kind == "authz":
        if not name:
            continue                               # an example, not a file
        path = os.path.join(folder, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(body)
        continue
    else:
        p = subprocess.run(["bash", "-e", "-c", body], cwd=folder, text=True, capture_output=True)
    print(f"--- {kind} {name}".rstrip())
    print(p.stdout + p.stderr)
    if p.returncode:
        print(f"BLOCK FAILED ({kind}, exit {p.returncode}):\n{body}")
        sys.exit(1)
PY
)
rc=$?
check "every block of the guide runs" "$rc" "0"
[ $rc -ne 0 ] && echo "$out" | tail -n 25
case "$out" in *"ok   compiles"*"applied in"*"check(s) pass"*) echo "ok    rowstile dev applies the policy and its tests pass";;
  *) echo "FAIL  rowstile dev: $(echo "$out" | grep -A 12 'sh$' | head -30)"; fails=$((fails + 1));; esac
case "$out" in *"no   insert : project.edit and author"*) echo "ok    explain-rule says which rule and what is missing";;
  *) echo "FAIL  explain-rule"; fails=$((fails + 1));; esac
[ -f "$DIR/db/policy.lock" ] && ls "$DIR"/migrations/*_authz_policy.sql >/dev/null 2>&1 && grep -q "linguist-generated" "$DIR/.gitattributes" &&
  ( cd "$DIR" && PATH="$OLDPWD/cli:$PATH" rowstile migrate --check >/dev/null ) &&
  echo "ok    rowstile migrate writes the first migration, the lock file and .gitattributes" ||
  { echo "FAIL  rowstile migrate: $(ls -R "$DIR" | head -20)"; fails=$((fails + 1)); }
# what the guide's comments say the last blocks return
notes_cy=$(psql -X -At -d "$DB" -c "SET ROLE app_backend" -c "SET authz.user_id = '3'" -c "SELECT count(*) FROM app.notes" | tail -n 1)
check "cy sees no notes" "$notes_cy" "0"
body=$(psql -X -At -d "$DB" -c "SET ROLE app_backend" -c "SET authz.user_id = '2'" -c "SELECT body FROM app.notes" | tail -n 1)
check "bo, a writer, sees the note he edited" "$body" "Chapter one, again"
share=$(psql -X -At -d "$DB" -c "SET ROLE app_backend" -c "SET authz.user_id = '2'" -c "SELECT authz.can('project', 1, 'share')" | tail -n 1)
check "bo may not share the project" "$share" "f"
refused=$(psql -X -At -d "$DB" -c "SET ROLE app_backend" -c "SET authz.user_id = '3'" \
          -c "INSERT INTO app.notes (project_id, author_id, body) VALUES (1, 3, 'hi')" 2>&1)
case "$refused" in *"permission denied: user 3 may not insert this row into app.notes"*"no   project.edit"*) echo "ok    a refused insert reads as the guide shows";;
  *) echo "FAIL  refused insert: $refused"; fails=$((fails + 1));; esac
lint=$(psql -X -At -d "$DB" -c "SELECT count(*) FROM authz.lint() WHERE severity = 'warning'")
check "authz.lint() finds no warnings in the guide's setup" "$lint" "0"
refused=$(psql -X -At -d "$DB" -c "CREATE ROLE docs_other" -c "SET ROLE docs_other" -c "SELECT authz.act_as('user', '1')" 2>&1 | grep ERROR)
case "$refused" in *"permission denied"*) echo "ok    another role can't say who is signed in";;
  *) echo "FAIL  another role signed someone in: $refused"; fails=$((fails + 1));; esac

rm -r "$DIR"
dropdb "$DB"
drop_roles

# the blog post's experiment runs as its header says, small, as a role that isn't a superuser: with the setting
# a stock server has (the suites' owner has createrole_self_grant, which would hide a missing grant)
BLOG=authz_docs_blog
dropdb --if-exists "$BLOG" 2>/dev/null; createdb "$BLOG" || exit 1
out=$(cd ../docs/blog/recursive-row-level-security &&
      PGOPTIONS="-c createrole_self_grant=" psql -X -d "$BLOG" -v folders=200 -f experiment.sql 2>&1)
rc=$?
check "the blog post's experiment.sql runs to its end as a role that isn't a superuser" "$rc" "0"
[ $rc -ne 0 ] && echo "$out" | grep ERROR | head -n 3
check "it times each query three times through each of the four policies" "$(echo "$out" | grep -c 'Execution Time')" "36"
dropdb "$BLOG"
psql -X -q -d postgres -c "DROP ROLE IF EXISTS demo_app" >/dev/null
[ $fails -eq 0 ] && echo "docs: all passed" || { echo "docs: $fails failed"; exit 1; }

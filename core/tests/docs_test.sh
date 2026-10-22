#!/bin/bash
# docs_test.sh: docs/getting-started.md runs as written and does what the guide says (its Python too, against the
# client it writes: tests/guide_app.py), the blog post's experiment.sql runs as its header says, and the code of the
# landing pages (README.md, site/index.md) runs and does what its comments say.
#   PGHOST=... PGUSER=authz_owner tests/docs_test.sh
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

# step 7, the guide's Python: the client written as the guide says, then the block run (tests/guide_app.py) for a
# request by a user who can't see the note, one who sees it and may not edit it, and one who may
client=$(grep -o '`rowstile client py > [A-Za-z_]*\.py`' "$GUIDE" | head -n 1 | tr -d '`')
written=$(cd "$DIR" && DATABASE_URL="dbname=$DB" PATH="$OLDPWD/../$CLI:$PATH" bash -e -c "$client" 2>&1) &&
  [ -s "$DIR/authz_client.py" ] && echo "ok    the guide's line writes the Python client ($client)" ||
  { echo "FAIL  the guide's line doesn't write authz_client.py: '$client' $written"; fails=$((fails + 1)); }
app() { python3 tests/guide_app.py "$GUIDE" "$DIR" "$DB" \
          "{\"current_user_id\": $1, \"project_id\": 1, \"note_id\": 1, \"body\": \"Chapter two\"}" 2>&1; }
out=$(app 3)
check "the guide's Python, for cy, who can't see the note: its handler answers 404" \
  "$(echo "$out" | sed -n 1p)" '[404, {"detail": "not found"}]'
check "... and makes the database's refusal of cy's note a 403 that says why" "$(echo "$out" | sed -n 2p)" \
  '[403, {"detail": "you may not do that", "why": ["no   insert : project.edit and author  (line 33)", "  no   project.edit", "    no   you have no access to project 1", "  yes  author"]}]'
psql -X -q -d "$DB" -c "SET ROLE app_backend" \
  -c "BEGIN; SELECT authz.act_as('user', '1'); SELECT authz.share('project', 1, 'viewer', 'user', 3); COMMIT" >/dev/null
out=$(app 3)
check "for cy, once ada shares the project with her to view: 403, and why she may not edit the note" \
  "$(echo "$out" | sed -n 1p)" '[403, {"detail": "you may not do that", "why": ["no   update : edit  (line 34)", "  no   edit", "    no   user 3 does not hold edit on note 1", "      note.edit = author or project.edit", "      no   author", "      no   project.edit", "        no   project is project 1, without edit", "          project.edit = share or editor", "          no   share", "          no   editor"]}]'
out=$(app 2)
check "for bo, a writer: no error, and the note is changed" \
  "$(echo "$out" | sed -n 1p) $(psql -X -At -d "$DB" -c "SELECT body FROM app.notes WHERE id = 1")" "null Chapter two"
check "... and the database lets him add a note" "$(echo "$out" | sed -n 2p)" "null"

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

# the landing pages, README.md and site/index.md: the policy each shows applies to the tables it reads
# (tests/fixtures/landing.sql: user 42 owns folder 8 and folder 12 inside it, and edits folder 10), and its SQL runs
# as the app role and does what its comments say, before and after 42 is made an editor of folder 7. authz.lint()
# warns of nothing, 42 moves folder 8 only under a folder they may edit, and gives away only a folder they own. A
# fenced block of another kind says why it isn't run, in a comment right before it (<!-- not run: why -->). (The
# README's install lines are DocPages': the same as docs/installing.md's, for the version being released.)
LAND=authz_docs_landing
landing() {   # page, the SQL's output before, after
  local page=$1 B out
  B=$(mktemp -d)
  out=$(python3 - "../$page" "$B" <<'PY'
import os, re, sys
page, out = sys.argv[1:]
text = open(page, encoding="utf-8").read()
n = {"authz": 0, "sql": 0}
bad = []
for m in re.finditer(r"^```(\w*)[^\n]*\n.*?^```", text, re.S | re.M):
    kind, before = m.group(1), text[: m.start()].rstrip().split("\n")[-1].strip()
    if kind in n:
        n[kind] += 1
        with open(os.path.join(out, f"{n[kind]}.{kind}"), "w", encoding="utf-8") as fh:
            fh.write(m.group(0).split("\n", 1)[1][:-3])
    elif not re.fullmatch(r"<!-- not run: .+ -->", before):
        bad.append(f"line {text[: m.start()].count(chr(10)) + 1}: a {kind or 'plain'} block, not run, and no comment says why")
if n["authz"] != 1:
    bad.append(f"{n['authz']} policies (one is applied)")
if not n["sql"]:
    bad.append("no SQL")
print("; ".join(bad))
PY
)
  [ -z "$out" ] && echo "ok    $page: one policy, its SQL, and no other block" || { echo "FAIL  $page: $out"; fails=$((fails + 1)); }
  dropdb --if-exists "$LAND" 2>/dev/null; createdb "$LAND" || exit 1
  psql -X -q -v ON_ERROR_STOP=1 -d "$LAND" -f tests/fixtures/landing.sql >/dev/null
  out=$(python3 cli/rowstile_cli.py --db "dbname=$LAND" apply "$B/1.authz" 2>&1)
  case "$out" in *": applied") echo "ok    $page: its policy applies";; *) echo "FAIL  $page: its policy: $out"; fails=$((fails + 1));; esac
  ran() { for f in "$B"/*.sql; do
            PGOPTIONS="-c client_min_messages=warning" psql -X -At -v ON_ERROR_STOP=1 -d "$LAND" -c "SET ROLE app_user" -f "$f" 2>&1
          done; }
  check "$page: its SQL, as user 42" "$(ran)" "$2"
  check "$page: authz.lint() has no warning" \
    "$(psql -X -At -d "$LAND" -c "SELECT object || ': ' || problem FROM authz.lint() WHERE severity = 'warning'")" ""
  as42() { PGOPTIONS="-c client_min_messages=warning" psql -X -At -d "$LAND" -c "SET ROLE app_user" \
             -c "BEGIN; SELECT authz.act_as('user', '42'); $1; ROLLBACK" 2>&1 | grep -E '^(UPDATE|ERROR)'; }
  check "$page: 42 can't move folder 8 under folder 7, which they may not edit" \
    "$(as42 "UPDATE app.folders SET parent_id = 7 WHERE id = 8")" "ERROR:  changing parent_id of app.folders 8 needs: parent.edit"
  check "$page: ... and moves it under folder 10, which they edit" \
    "$(as42 "UPDATE app.folders SET parent_id = 10 WHERE id = 8")" "UPDATE 1"
  check "$page: 42 edits folder 10 and can't give it away" \
    "$(as42 "UPDATE app.folders SET owner_id = 42 WHERE id = 10")" "ERROR:  changing owner_id of app.folders 10 needs: owner"
  check "$page: ... and gives away folder 12, which they own (and still edit, through folder 8)" \
    "$(as42 "UPDATE app.folders SET owner_id = 1 WHERE id = 12")" "UPDATE 1"
  psql -X -q -d "$LAND" -c "INSERT INTO app.folder_editors VALUES (7, 42)"
  check "$page: its SQL, once 42 may edit folder 7" "$(ran)" "$3"
  rm -r "$B"
  dropdb "$LAND"
}
FOLDERS=$'8|Home|42|\n9|Photos|1|8\n10|Drafts|1|7\n11|Old|1|10\n12|Trips|42|8'
landing README.md $'SET\nBEGIN\n\n'"$FOLDERS"$'\nf\n7|{}\n8|{edit,view}\nCOMMIT' \
  $'SET\nBEGIN\n\n7|Notes|1|\n'"$FOLDERS"$'\nt\n7|{edit,view}\n8|{edit,view}\nCOMMIT'
landing site/index.md $'SET\nBEGIN\n\n'"$FOLDERS"$'\nUPDATE 0\nCOMMIT' $'SET\nBEGIN\n\n7|Notes|1|\n'"$FOLDERS"$'\nUPDATE 1\nCOMMIT'
[ $fails -eq 0 ] && echo "docs: all passed" || { echo "docs: $fails failed"; exit 1; }

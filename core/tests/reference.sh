#!/bin/bash
# reference.sh: the reference runs as written. Each code block of docs/reference/*.md is run as what it is: a
# policy (```authz) compiles, with its tests, what it includes taken from tests/fixtures/, and is applied to the
# tables tests/fixtures/<page>.sql makes, where its tests run on their rows; SQL (```sql) runs on the docs app;
# the refusal app-code.md shows is the docs app's, word for word; a rowstile.toml (```toml) is a project's,
# whose commands read it; the settings that start the MCP server (```json) start it, in that project;
# and the lines of a block indented four spaces, a `rowstile` command each, run there in the pages' order, each
# doing what its comment says. A block that can't run says why in a comment right before it
# (<!-- not run: why -->); a block that does neither fails. And what the pages' tables say of the compiler
# without a database, which no other suite asks.
#   PGHOST=... PGUSER=postgres tests/reference.sh
set -u
cd "$(dirname "$0")/.."
CORE=$PWD
REF=$(cd ../docs/reference && pwd)
DB=authz_reference                 # the docs app: SQL blocks, the refusal
DEV=authz_reference_dev            # the project's development database: push, diff, test
REVIEW=authz_reference_review      # the review database, at the base branch's state
POLICY=authz_reference_policy      # a page's policy, applied to the tables tests/fixtures/ gives that page
fails=0
ok() { echo "ok    $1"; }
bad() { echo "FAIL  $1${2:+: $2}"; fails=$((fails + 1)); }
quiet() { PGOPTIONS="-c client_min_messages=error" psql -X -q -v ON_ERROR_STOP=1 "$@"; }
T=$(mktemp -d)
P=$T/project
# the command on the PATH as an install puts it there: this checkout's
export PATH="$CORE/cli:$PATH"

# the blocks: one file each, and a list (id, page, kind, line, the reason a comment gives for not running it).
# kind: the fence's language, text for a fence without one, lines for a block indented four spaces
mkdir -p "$T/blocks"
python3 - "$REF" "$T/blocks" <<'PY' || { bad "reading the reference's blocks"; exit 1; }
import os, re, sys
ref, out = sys.argv[1:]
rows = []
for page in sorted(f for f in os.listdir(ref) if f.endswith(".md")):
    with open(os.path.join(ref, page), encoding="utf-8") as fh:
        lines = fh.read().split("\n")
    i = 0
    while i < len(lines):
        line = lines[i]
        prev = next((x for x in reversed(lines[:i]) if x.strip()), "")
        fence = re.match(r"( *)(```+)\s*(\S*)", line)
        if fence:
            indent, end = len(fence.group(1)), fence.group(2)
            kind = fence.group(3) or "text"
            j = i + 1
            while j < len(lines) and not lines[j].strip().startswith(end):
                j += 1
            body = [x[indent:] if not x[:indent].strip() else x.lstrip() for x in lines[i + 1 : j]]
            start, i = i + 1, j + 1
        elif line.startswith("    ") and line.strip() and not lines[i - 1].strip() and not re.match(r"( *)([-*+] |\d+[.)] )|  ", prev):
            j = i
            while j < len(lines) and (lines[j].startswith("    ") or not lines[j].strip()):
                j += 1
            body = [x[4:] for x in lines[i:j]]
            while body and not body[-1].strip():
                body.pop()
            kind, start, i = "lines", i + 1, j
        else:
            i += 1
            continue
        why = re.fullmatch(r"\s*<!-- not run: (.+?) -->\s*", prev)
        name = f"{len(rows) + 1}.{kind}"
        with open(os.path.join(out, name), "w", encoding="utf-8") as fh:
            fh.write("\n".join(body) + "\n")
        rows.append("\t".join([name, page, kind, str(start), why.group(1) if why else ""]))
with open(os.path.join(out, "list"), "w", encoding="utf-8") as fh:
    fh.write("".join(r + "\n" for r in rows))
PY
handled() { echo "$1" >> "$T/handled"; }
touch "$T/handled"
blocks() { awk -F'\t' -v k="$1" '$3 == k' "$T/blocks/list"; }   # the blocks of one kind: id page kind line why

# the docs app, with its policy applied
dropdb --if-exists "$DB" 2>/dev/null; createdb "$DB" || exit 1
quiet -d "$DB" -f example/app_schema.sql >/dev/null || exit 1
python3 cli/rowstile_cli.py --db "dbname=$DB" apply example/docs.authz >/dev/null 2>&1 || { bad "applying the docs app's policy"; exit 1; }

echo "-- blocks that can't run, and say why"
while IFS=$'\t' read -r id page kind line why; do
  [ -n "$why" ] || continue
  ok "$page, the $kind block on line $line: not run, and says why"
  handled "$id"
done < "$T/blocks/list"

echo "-- policies compile, with their tests, and run"
applied=0
while IFS=$'\t' read -r id page kind line why; do
  [ -z "$why" ] || continue
  d="$T/authz/$id"; mkdir -p "$d"; cp "$T/blocks/$id" "$d/policy.authz"
  missing=""
  for inc in $(sed -n 's/^include "\([^"]*\)".*/\1/p' "$d/policy.authz"); do
    cp "tests/fixtures/$inc" "$d/$inc" 2>/dev/null || missing="$missing $inc"
  done
  if [ -n "$missing" ]; then bad "$page, line $line: what it includes is in no file of tests/fixtures/:$missing"; continue; fi
  out=$(rowstile check "$d/policy.authz" 2>&1) && out=$(python3 compile_policy.py "$d/policy.authz" --tests 2>&1 >/dev/null) &&
    ok "$page, the policy on line $line compiles, with its tests" || bad "$page, the policy on line $line" "$out"
  handled "$id"
  # applied to the tables tests/fixtures/ gives its page, and its tests run on their rows
  schema="tests/fixtures/${page%.md}.sql"
  if [ -f "$schema" ]; then
    dropdb --if-exists "$POLICY" 2>/dev/null; createdb "$POLICY" || exit 1
    quiet -d "$POLICY" -f "$schema" >/dev/null || { bad "$schema"; continue; }
    out=$(rowstile --db "dbname=$POLICY" apply "$d/policy.authz" 2>&1) && [ "$out" = "$d/policy.authz: applied" ] &&
      ok "$page, the policy on line $line applies to the tables of $schema" || bad "$page, applying the policy on line $line" "$out"
    out=$(cd "$d" && rowstile --db "dbname=$POLICY" test 2>&1); rc=$?
    case "$out" in *"policy tests passed"*) [ $rc -eq 0 ] && ok "$page, the policy on line $line: its tests and invariants pass on the rows of $schema" ||
        bad "$page, the tests of the policy on line $line" "exit $rc";;
      *) bad "$page, the tests of the policy on line $line" "$out";; esac
    dropdb "$POLICY"
    applied=$((applied + 1))
  fi
done < <(blocks authz)
[ "$applied" -ge 1 ] || bad "no policy of the reference was applied: tests/fixtures/ has the tables of none"

echo "-- SQL runs on the docs app"
while IFS=$'\t' read -r id page kind line why; do
  [ -z "$why" ] || continue
  out=$(quiet -At -d "$DB" -f "$T/blocks/$id" 2>&1) && ok "$page, the SQL on line $line runs on the docs app" || bad "$page, the SQL on line $line" "$out"
  handled "$id"
  # the settings identity.md says JWT login reads: a token signed with the secret it sets, from its issuer
  if grep -q "'jwt_secret'" "$T/blocks/$id"; then
    secret=$(sed -n "s/.*('jwt_secret', '\([^']*\)').*/\1/p" "$T/blocks/$id")
    issuer=$(sed -n "s/.*('jwt_issuer', '\([^']*\)').*/\1/p" "$T/blocks/$id")
    token=$(python3 - "$secret" "$issuer" <<'PY'
import base64, hashlib, hmac, json, sys, time
secret, issuer = sys.argv[1:]
part = lambda d: base64.urlsafe_b64encode(json.dumps(d, separators=(",", ":")).encode()).rstrip(b"=").decode()
msg = part({"alg": "HS256", "typ": "JWT"}) + "." + part({"sub": "1", "iss": issuer, "exp": int(time.time()) + 300})
print(msg + "." + base64.urlsafe_b64encode(hmac.new(secret.encode(), msg.encode(), hashlib.sha256).digest()).rstrip(b"=").decode())
PY
)
    got=$(psql -X -q -At -d "$DB" -c "BEGIN" -c "SET LOCAL ROLE app_user" -c "SELECT authz.login_jwt('$token')" -c "SELECT authz.uid()" -c "COMMIT" 2>&1 | tail -n 1)
    [ -n "$secret" ] && [ "$got" = 1 ] && ok "the settings identity.md sets: a token signed with that secret, from that issuer, signs in" ||
      bad "a token for the settings identity.md sets" "$got"
  fi
done < <(blocks sql)

echo "-- output the pages show"
while IFS=$'\t' read -r id page kind line why; do
  [ -z "$why" ] || continue
  shown=$(cat "$T/blocks/$id")
  case "$shown" in
    "ERROR:  permission denied: user 1 may not insert this row into app.files"*)
      # alice (user 1) may edit Design docs (folder 4), and names bob as the new file's owner
      got=$(psql -X -q -At -d "$DB" -c "BEGIN" -c "SET LOCAL ROLE app_user" -c "SELECT authz.act_as('user', '1')" \
              -c "INSERT INTO app.files (folder_id, owner_id, name) VALUES (4, 2, 'x')" 2>&1)
      case "$got" in *"$shown"*) ok "the refusal app-code.md shows is the docs app's, word for word";;
        *) bad "the refusal app-code.md shows" "$got";; esac
      handled "$id";;
  esac
done < <(blocks text)

echo "-- a project: the rowstile.toml tools.md shows"
mkdir -p "$P/db/tests" "$P/alembic/versions" "$P/backend/app"
sed '/^test$/,$d' example/docs.authz > "$P/db/policy.authz"
cp example/docs.test.authz "$P/db/tests/docs.authz"
dropdb --if-exists "$DEV" 2>/dev/null; createdb "$DEV" || exit 1
quiet -d "$DEV" -f example/app_schema.sql >/dev/null || exit 1
# runs a command in the project, its database the development one (DATABASE_URL, as rowstile.toml says)
project() { (cd "$P" && DATABASE_URL="dbname=$DEV" bash -c "$1" 2>&1); }
toml=$(blocks toml | head -n 1 | cut -f1)
if [ -z "$toml" ]; then bad "no rowstile.toml in the reference to make a project of"; else
  cp "$T/blocks/$toml" "$P/rowstile.toml"
  out=$(project "rowstile check"); [ "$out" = "$P/db/policy.authz: ok" ] && ok "its policy is the one rowstile.toml names" || bad "rowstile check in the project" "$out"
  out=$(project "rowstile client") && python3 -m py_compile "$P/backend/app/authz_client.py" 2>/dev/null &&
    ok "rowstile client writes the client it names, which is Python" || bad "rowstile client in the project" "$out"
  handled "$toml"
fi

echo "-- the lines of the pages' indented blocks, run in the project"
# the base of the pull request review.md's lines review: the project on main, its first migration applied to the
# review database with the review data; then a branch that widens folder.view (inheritance no longer stopped)
review_ready=""
prepare_review() {
  [ -n "$review_ready" ] && return 0
  review_ready=1
  command -v git >/dev/null || { bad "git, which rowstile review needs, is not installed"; return 1; }
  git -C "$P" init -q -b main && git -C "$P" config user.email t@example.com && git -C "$P" config user.name t &&
    git -C "$P" add -A && git -C "$P" commit -q -m base || { bad "the project's repository"; return 1; }
  dropdb --if-exists "$REVIEW" 2>/dev/null; createdb "$REVIEW" || return 1
  quiet -d "$REVIEW" -f example/app_schema.sql >/dev/null || return 1
  for f in "$P"/alembic/versions/*.sql; do quiet -1 -d "$REVIEW" -f "$f" >/dev/null || { bad "the base's migration on the review database"; return 1; }; done
  psql -X -q -d "$REVIEW" -c "SET ROLE app_user" -c "SET authz.user_id = 5" -c "SELECT authz.share('folder', 1, 'viewer', 'org', 1, 'member')" >/dev/null
  git -C "$P" checkout -q -b change &&
    sed -i 's/can view  = edit or viewer or (parent.view and {inherit})/can view  = edit or viewer or parent.view/' "$P/db/policy.authz" &&
    grep -q "or parent.view$" "$P/db/policy.authz" && project "rowstile migrate" >/dev/null &&
    git -C "$P" add -A && git -C "$P" commit -q -m change || { bad "the pull request's change"; return 1; }
}
lines_run=0
while IFS=$'\t' read -r id page kind line why; do
  [ -z "$why" ] || continue
  n=$line
  while IFS= read -r text; do
    cmd=$(echo "${text%%#*}" | sed 's/[[:space:]]*$//')
    [ -n "$cmd" ] || { n=$((n + 1)); continue; }
    lines_run=$((lines_run + 1))
    where="$page, line $n: $cmd"
    case "$cmd" in
      "rowstile migrate")
        # (no database needed: the URL it names leads nowhere)
        out=$(cd "$P" && DATABASE_URL="postgresql://nobody@127.0.0.1:1/nowhere" rowstile migrate 2>&1); rc=$?
        [ $rc -eq 0 ] && ls "$P"/alembic/versions/*_authz_*.py "$P"/alembic/versions/*_authz_*.sql >/dev/null 2>&1 && [ -f "$P/db/policy.lock" ] &&
          ok "$where: the next migration, and db/policy.lock, with no database" || bad "$where" "$out";;
      "rowstile migrate --check")
        out=$(project "$cmd"); rc=$?
        [ $rc -eq 0 ] && ok "$where: nothing left without a migration, exit 0" || bad "$where" "$rc $out";;
      "rowstile push")
        out=$(project "$cmd"); rc=$?
        case "$out" in *"policy.authz: applied (the whole policy)") [ $rc -eq 0 ] && ok "$where: the development database, brought to the policy" || bad "$where" "$rc";;
          *) bad "$where" "$out";; esac
        [ "$(psql -X -At -d "$DEV" -c "SELECT value FROM authz.settings WHERE key = 'development'")" = true ] &&
          ok "the first push to a database that never had a policy marks it as a development one" || bad "the development mark after the first push";;
      "rowstile diff")
        before=$(psql -X -At -d "$DEV" -c "SELECT count(*) || '/' || max(id) FROM authz.policy_versions")
        out=$(project "$cmd"); rc=$?
        [ $rc -eq 0 ] && [ "$(psql -X -At -d "$DEV" -c "SELECT count(*) || '/' || max(id) FROM authz.policy_versions")" = "$before" ] &&
          ok "$where: who gains and loses what, and nothing changed" || bad "$where" "$rc $out";;
      "rowstile test")
        out=$(project "$cmd"); rc=$?
        case "$out" in *"policy tests passed"*) [ $rc -eq 0 ] && ok "$where: the tests and invariants pass" || bad "$where" "$rc";; *) bad "$where" "$out";; esac;;
      "rowstile review --base main")
        prepare_review || { n=$((n + 1)); continue; }
        out=$(cd "$P" && rowstile review --base main 2>&1); rc=$?
        case "$out" in *"Meaning"*"folder.view"*) [ $rc -eq 0 ] && ok "$where: what the change does, exit 0" || bad "$where" "$rc";; *) bad "$where" "$out";; esac;;
      'rowstile review --base main --markdown --db "$URL"')
        prepare_review || { n=$((n + 1)); continue; }
        out=$(cd "$P" && URL="dbname=$REVIEW" bash -c "$cmd" 2>&1); rc=$?
        case "$out" in "<!-- rowstile review -->"*"Access"*) [ $rc -eq 0 ] && ok "$where: the comment, with who gains what on the review data" || bad "$where" "$rc";;
          *) bad "$where" "$out";; esac;;
      *) bad "$where: a line this suite doesn't know what to expect of";;
    esac
    n=$((n + 1))
  done < "$T/blocks/$id"
  handled "$id"
done < <(blocks lines)
[ "$lines_run" -ge 7 ] || bad "only $lines_run lines of indented blocks were found"

echo "-- the MCP server, started as tools.md's settings say"
while IFS=$'\t' read -r id page kind line why; do
  [ -z "$why" ] || continue
  out=$(cd "$P" && DATABASE_URL="dbname=$DEV" python3 - "$T/blocks/$id" "$REF/$page" <<'PY' 2>&1
import json, re, subprocess, sys
settings = json.load(open(sys.argv[1], encoding="utf-8"))
page = open(sys.argv[2], encoding="utf-8").read()
said = re.search(r"with the command's own tools: (.*?) to a development database", page, re.S)
named = set(re.findall(r"`(\w+)`", said.group(1))) if said else set()
asks = [
    {"jsonrpc": "2.0", "id": 1, "method": "initialize",
     "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "reference", "version": "1"}}},
    {"jsonrpc": "2.0", "method": "notifications/initialized"},
    {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
]
p = subprocess.run([settings["command"], *settings["args"]], input="".join(json.dumps(a) + "\n" for a in asks),
                   capture_output=True, text=True, timeout=60)
answers = {a.get("id"): a for a in map(json.loads, filter(None, p.stdout.split("\n")))}
tools = {t["name"] for t in answers[2]["result"]["tools"]}
print("tools: " + " ".join(sorted(tools)))
sys.exit(0 if named and tools == named else 1)
PY
)
  rc=$?
  [ $rc -eq 0 ] && ok "the MCP server tools.md's settings start lists the tools the page names" || bad "$page, the settings on line $line" "$out"
  handled "$id"
done < <(blocks json)

echo "-- every block"
total=$(wc -l < "$T/blocks/list")
left=$(cut -f1 "$T/blocks/list" | grep -vxF -f "$T/handled")
if [ -z "$left" ] && [ "$total" -ge 8 ]; then ok "every block of the reference runs, or says why not ($total blocks)"; else
  for id in $left; do bad "$(awk -F'\t' -v i="$id" '$1 == i {print $2 ", line " $4 ": a " $3 " block no check runs, and no comment says why"}' "$T/blocks/list")"; done
  [ "$total" -ge 8 ] || bad "only $total blocks were found in the reference"
fi

[ -n "${KEEP:-}" ] || { dropdb "$DB"; dropdb "$DEV"; dropdb --if-exists "$REVIEW" 2>/dev/null; dropdb --if-exists "$POLICY" 2>/dev/null; rm -rf "$T"; }
if [ $fails -eq 0 ]; then echo "reference: all passed"; else echo "reference: $fails failed"; exit 1; fi

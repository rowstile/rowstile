#!/bin/bash
# cookbook.sh: the cookbook is tested. Each recipe is a page, docs/cookbook/<name>.md, beside a folder,
# docs/cookbook/<name>/: schema.sql (its tables), rows.sql (a few rows, for the playground), policy.authz,
# tests.authz and rowstile.toml (naming those two). For each: the tables and the rows load, the policy applies
# without a warning, its tests pass (with the rows there, as in the playground), and every line of policy and
# tests the page shows is in those files, so the page can't drift. The SQL the page shows runs, and the commands
# it shows print what it shows. Its invariants, if it states any, are proved, and ask.sql, if it has one (what
# the playground asks first), runs as the app role. Then the steps docs/cookbook.md gives: `rowstile dev` in a
# copy of the folder, on a database with only the tables and the rows, applies it and passes its tests. A page
# without its folder, or a folder without its page, fails.
#   PGHOST=... PGUSER=postgres tests/cookbook.sh
set -u
cd "$(dirname "$0")/.."
BOOK=../docs/cookbook
fails=0
ok() { echo "ok    $1"; }
bad() { echo "FAIL  $1${2:+: $2}"; fails=$((fails + 1)); }

recipe() {
  local name=$1 dir=$BOOK/$1 page=$BOOK/$1.md
  local db="authz_cookbook_${name//-/_}" out rc missing f
  for f in schema.sql rows.sql tests.authz rowstile.toml; do [ -f "$dir/$f" ] || { bad "$name: no $f"; return; }; done
  [ -f "$page" ] || { bad "$name: no page (docs/cookbook/$name.md)"; return; }
  CLI() { python3 cli/rowstile_cli.py --db "dbname=$db" "$@"; }
  dropdb --if-exists "$db" 2>/dev/null
  createdb "$db" || { bad "$name: createdb"; return; }
  if ! PGOPTIONS="-c client_min_messages=warning" psql -X -q -v ON_ERROR_STOP=1 -d "$db" -f "$dir/schema.sql" -f "$dir/rows.sql" >/dev/null; then
    bad "$name: its tables and rows"; dropdb "$db"; return
  fi
  out=$(CLI apply "$dir/policy.authz" 2>&1); case "$out" in *": applied") ok "$name: the policy applies";; *) bad "$name: apply" "$out";; esac
  case "$out" in *WARNING*) bad "$name: applying warns" "$out";; *) ok "$name: ... without warnings (authz.lint included)";; esac
  out=$(CLI test "$dir/tests.authz" 2>&1); rc=$?
  [ $rc -eq 0 ] && ok "$name: its tests pass ($(echo "$out" | tail -n 1))" || bad "$name: tests" "$(echo "$out" | grep -A 8 FAIL | head -40)"
  missing=$(python3 - "$page" "$dir/policy.authz" "$dir/tests.authz" <<'PY'
import re, sys
page = open(sys.argv[1], encoding="utf-8").read()
norm = lambda s: " ".join(s.split("--")[0].split())
have = set()
for f in sys.argv[2:]:
    have |= {norm(line) for line in open(f, encoding="utf-8")}
blocks = re.findall(r"```authz\n(.*?)```", page, re.S)
if not blocks:
    print("(the page shows no policy)")
for block in blocks:
    for line in block.splitlines():
        if norm(line) and norm(line) not in have:
            print(line.strip())
PY
)
  [ -z "$missing" ] && ok "$name: every line of policy and tests its page shows is in its files" || bad "$name: lines not in the policy or tests" "$missing"
  # the SQL the page shows runs as the app role, signed in as the first user of rows.sql, and each command it
  # shows (an indented `$ rowstile ...` and what it prints) prints that, run in the recipe's folder; a block
  # with <!-- not run: why --> right before it is left out
  out=$(python3 - "$page" "$db" "$dir" <<'PY'
import os, re, subprocess, sys
page, db, folder = sys.argv[1], sys.argv[2], sys.argv[3]
lines = open(page, encoding="utf-8").read().splitlines()
cli = os.path.abspath("cli/rowstile_cli.py")
sql, shown, problems = 0, 0, []
def before(i):
    j = i - 1
    while j >= 0 and not lines[j].strip():
        j -= 1
    return lines[j] if j >= 0 else ""
i = 0
while i < len(lines):
    line, start = lines[i], i
    if line == "```sql":
        j = lines.index("```", i + 1)
        body, i = "\n".join(lines[i + 1 : j]), j + 1
        if re.fullmatch(r"<!-- not run: .+ -->", before(start).strip()):
            continue
        sql += 1
        script = f"BEGIN;\nSET LOCAL ROLE app_user;\nSELECT authz.act_as('user', '1');\n{body}\n;\nROLLBACK;\n"
        run = subprocess.run(["psql", "-X", "-q", "-At", "-v", "ON_ERROR_STOP=1", "-d", db], input=script, capture_output=True, text=True)
        if run.returncode:
            problems.append(f"the SQL on line {start + 1}: {run.stderr.strip()}")
    elif line.startswith("    $ rowstile "):
        j = i + 1
        while j < len(lines) and lines[j].startswith("    "):
            j += 1
        want = "\n".join(x[4:].rstrip() for x in lines[i + 1 : j])
        args, i = line[len("    $ rowstile ") :].split(), j
        shown += 1
        env = dict(os.environ, DATABASE_URL=f"dbname={db}")
        run = subprocess.run([sys.executable, cli, *args], cwd=folder, env=env, capture_output=True, text=True)
        got = "\n".join(x.rstrip() for x in (run.stdout + run.stderr).strip("\n").splitlines())
        if got != want:
            problems.append(f"rowstile {' '.join(args)} (line {start + 1}) printed:\n{got}")
    else:
        i += 1
print(f"{sql} {shown}")
print("\n".join(problems))
PY
)
  read -r sql shown <<<"$(echo "$out" | head -n 1)"
  out=$(echo "$out" | tail -n +2)
  if [ "${sql:-0}" -gt 0 ] || [ "${shown:-0}" -gt 0 ]; then
    [ -z "$out" ] && ok "$name: the SQL its page shows runs, as its first user, and its commands print what it shows" || bad "$name: what its page shows" "$out"
  fi
  # a recipe that states invariants shows them proved: rowstile prove finds no small world that breaks one
  if grep -q '^invariants' "$dir/policy.authz"; then
    out=$(python3 cli/rowstile_cli.py prove "$dir/policy.authz" 2>&1)
    if echo "$out" | grep -q '^  ok   holds' && ! echo "$out" | grep -q '^  no  '; then ok "$name: its invariants are proved"; else bad "$name: prove" "$out"; fi
  fi
  # the question the playground asks first, as its first user, runs
  if [ -f "$dir/ask.sql" ]; then
    out=$({ echo "BEGIN; SET LOCAL ROLE app_user; SELECT authz.act_as('user', '1');"; cat "$dir/ask.sql"; echo "; ROLLBACK;"; } |
      psql -X -q -At -v ON_ERROR_STOP=1 -d "$db" 2>&1) &&
      ok "$name: the playground's question runs as the app role" || bad "$name: ask.sql" "$out"
  fi
  [ -z "${KEEP:-}" ] && dropdb "$db"
  # the steps docs/cookbook.md gives for trying a recipe on a database of your own: its tables and rows, then
  # `rowstile dev` in a copy of the folder, which its rowstile.toml points at the policy and the tests
  local copy here=$PWD
  copy=$(mktemp -d "/tmp/authz_cookbook_${name//-/_}.XXXXXX")
  cp -r "$dir/." "$copy/"
  dropdb --if-exists "${db}_dev" 2>/dev/null
  createdb "${db}_dev" || { bad "$name: createdb"; rm -rf "$copy"; return; }
  out=$(cd "$copy" && PGOPTIONS="-c client_min_messages=warning" psql -X -q -v ON_ERROR_STOP=1 -d "${db}_dev" -f schema.sql -f rows.sql >/dev/null &&
    DATABASE_URL="dbname=${db}_dev" python3 "$here/cli/rowstile_cli.py" dev --once --no-studio 2>&1); rc=$?
  if [ $rc -eq 0 ] && echo "$out" | grep -q '^  ok   applied' && echo "$out" | grep -q '^  ok   [0-9]* check(s) pass'; then
    ok "$name: rowstile dev in a copy of its folder applies it and passes its tests"
  else
    bad "$name: rowstile dev in a copy of its folder" "$out"
  fi
  dropdb "${db}_dev"
  rm -rf "$copy"
}

recipes=0
for dir in "$BOOK"/*/; do
  [ -f "$dir/policy.authz" ] || continue
  recipes=$((recipes + 1))
  recipe "$(basename "$dir")"
done
# a page without its folder shows lines nothing tests
for page in "$BOOK"/*.md; do
  [ -e "$page" ] || continue
  name=$(basename "$page" .md)
  [ -f "$BOOK/$name/policy.authz" ] || bad "$name: a page without docs/cookbook/$name/policy.authz"
done
# the index names every recipe
for dir in "$BOOK"/*/; do
  name=$(basename "$dir")
  [ -f "$dir/policy.authz" ] || continue
  grep -qF "(cookbook/$name.md)" "$BOOK.md" || bad "$name: docs/cookbook.md doesn't link to it"
done
[ "$recipes" -ge 18 ] && ok "$recipes recipes" || bad "only $recipes recipes were found"

if [ $fails -eq 0 ]; then echo "cookbook: all passed"; else echo "cookbook: $fails failed"; exit 1; fi

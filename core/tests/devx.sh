#!/bin/bash
# devx.sh: what developers use day to day. Named tests that bring their own data, refusals that say why
# (the error, authz.explain_rule), authz.who_among, applying only when changed, the warning for rule
# conditions that read governed tables, drafting a policy, and the rowstile command: dev, test, init, --as.
#   PGHOST=... PGUSER=postgres tests/devx.sh [database]
set -u
cd "$(dirname "$0")/.."
DB=${1:-authz_devx}
fails=0
PSQL() { psql -X -q -At -v ON_ERROR_STOP=1 -d "$DB" "$@"; }
ok() { echo "ok    $1"; }
bad() { echo "FAIL  $1${2:+: $2}"; fails=$((fails + 1)); }
CLI() { python3 cli/rowstile_cli.py --db "dbname=$DB" "$@"; }
run() { out=$(CLI "$@" 2>&1); rc=$?; }
# a statement as the app role, signed in as user $1: its error (message and detail), or 'ok'
as() { psql -X -q -At -d "$DB" -v VERBOSITY=verbose -c "SET ROLE app_user" -c "SET authz.user_id = '$1'" -c "$2" 2>&1; }
# the rows of a test run of these named test files (tab-separated: test, line, ok, detail), without the
# policy's own test section (it needs the example scenario's shares)
rows() { python3 tests/test_rows.py "dbname=$DB" "$@" | awk -F'\t' '$1 != "test section"'; }

dropdb --if-exists "$DB" 2>/dev/null; createdb "$DB" || exit 1
PGOPTIONS="-c client_min_messages=error" psql -X -q -v ON_ERROR_STOP=1 -d "$DB" -f example/app_schema.sql >/dev/null || exit 1
run apply example/docs.authz; [ "$out" = "example/docs.authz: applied" ] || { bad "apply" "$out"; exit 1; }
T=$(mktemp -d)

echo "-- named tests: their own data, rolled back"
before=$(PSQL -c "SELECT (SELECT count(*) FROM app.users) || '/' || (SELECT count(*) FROM app.files)")
cp example/docs.test.authz "$T/docs.test.authz"
out=$(rows "$T/docs.test.authz" | awk -F'\t' '{n++; if ($3 == "t") y++} END {print y+0 "/" n+0}')
case "$out" in "0/"*) bad "named tests" "$out";; *) [ "${out%/*}" = "${out#*/}" ] && ok "the example's named tests pass ($out)" || bad "named tests" "$out";; esac
[ "$(PSQL -c "SELECT (SELECT count(*) FROM app.users) || '/' || (SELECT count(*) FROM app.files)")" = "$before" ] &&
  ok "... and leave no rows behind" || bad "named tests left rows"
sed 's/user $bo cannot view file $f/user $bo can view file $f/' example/docs.test.authz > "$T/t.authz"
out=$(rows "$T/t.authz" | awk -F'\t' '$3 == "f" {print $2 ": " $4}')
case "$out" in "t.authz line 13: user \$bo can view file \$f"*"does not hold view on file"*) ok "a failing check names its file and line, and explains itself";;
  *) bad "failing check" "$out";; esac
sed 's/as user $bo refused {INSERT/as user $bo allowed {INSERT/' example/docs.test.authz > "$T/t.authz"
out=$(rows "$T/t.authz" | awk -F'\t' '$3 == "f" {print $4}')
case "$out" in *"refused: permission denied: user 9002 may not insert this row into app.files"*"no   folder.edit"*) ok "an 'allowed' that is refused shows the refusal and why";;
  *) bad "allowed but refused" "$out";; esac
printf '%s\n' 'test "ids of several columns"' '  given m = {SELECT 7 AS org_id, 42 AS id}' "  as anyone sees 1 {SELECT WHERE \$m = '(7,42)'}" > "$T/c.authz"
out=$(rows "$T/c.authz" | awk -F'\t' '$1 == "ids of several columns" {print $3}' | tr '\n' ' ')
[ "$out" = "t " ] && ok "given binds several returned columns as one id, as Postgres writes the row" || bad "composite given" "$out"
cat > "$T/w.authz" <<'EOF'
test "a write, however it starts"
  given ann  = {INSERT INTO app.users (id, name) VALUES (9001, 'Ann') RETURNING id;}
  given bo   = {INSERT INTO app.users (id, name) VALUES (9002, 'Bo') RETURNING id}
  given acme = {INSERT INTO app.orgs (id, name) VALUES (9001, 'Acme') RETURNING id}
  given top  = {INSERT INTO app.folders (org_id, owner_id, name) VALUES ($acme, $ann, 'Top') RETURNING id}
  as user $bo refused {WITH x AS (SELECT 1) UPDATE app.folders SET name = 'x' WHERE id = $top}
  as user $bo refused {/* hidden from Bo */ UPDATE app.folders SET name = 'x' WHERE id = $top}
  as user $ann allowed {WITH x AS (SELECT 1) UPDATE app.folders SET name = 'x' WHERE id = $top}
  as user $bo allowed {WITH x AS (SELECT 1) SELECT FROM app.folders WHERE id = $top}
  as user $ann sees 1 {SELECT FROM app.folders WHERE id = $top;}
  as user $ann refused {DELETE FROM app.users WHERE id = $ann}
  given f    = {INSERT INTO app.files (folder_id, owner_id, name) VALUES ($top, $ann, 'a') RETURNING id}
  as user $ann refused {INSERT INTO app.files (id, folder_id, owner_id, name) VALUES ($f, $top, $ann, 'twice')}
EOF
out=$(rows "$T/w.authz" | awk -F'\t' '$1 != "invariants" {print $3}' | tr -d '\n')
[ "$out" = ttttttf ] && ok "a write after WITH or a comment that changes no row is refused, and one the app role has no privilege for; a read of no row is allowed; sees takes a final ;" || bad "writes however they start" "$(rows "$T/w.authz")"
out=$(rows "$T/w.authz" | awk -F'\t' '$3 == "f" {print $4}')
case "$out" in *"error: "*) ok "... and an error that isn't a refusal fails 'refused' too";; *) bad "refused by another error" "$out";; esac
# with scope: a line checked as a key or a token limited to those scopes would be (the docs app: read is
# select and view; files is select and update on app.files, and view and edit on a file)
cat > "$T/s.authz" <<'EOF'
test "a key limited to a scope"
  given ann  = {INSERT INTO app.users (id, name) VALUES (9001, 'Ann') RETURNING id}
  given acme = {INSERT INTO app.orgs (id, name) VALUES (9001, 'Acme') RETURNING id}
  given top  = {INSERT INTO app.folders (org_id, owner_id, name) VALUES ($acme, $ann, 'Top') RETURNING id}
  given f    = {INSERT INTO app.files (folder_id, owner_id, name) VALUES ($top, $ann, 'a') RETURNING id}
  user $ann can edit file $f
  user $ann with scope read can view file $f
  user $ann with scope read cannot edit file $f
  as user $ann with scope read sees 1 {SELECT FROM app.files WHERE id = $f}
  as user $ann with scope read refused {UPDATE app.files SET name = 'b' WHERE id = $f}
  as user $ann with scope files allowed {UPDATE app.files SET name = 'b' WHERE id = $f}
  as user $ann with scope files refused {UPDATE app.folders SET name = 'x' WHERE id = $top}
  as user $ann with scope read, files allowed {UPDATE app.files SET name = 'c' WHERE id = $f}
  as user $ann allowed {UPDATE app.folders SET name = 'x' WHERE id = $top}
  user $ann can edit file $f
EOF
out=$(rows "$T/s.authz" | awk -F'\t' '$1 != "invariants" {print $3}' | tr -d '\n')
[ "$out" = tttttttttt ] && ok "with scope: a line is checked as a key limited to those scopes, and the next line is not" || bad "with scope" "$(rows "$T/s.authz")"
sed 's/with scope read cannot edit/with scope read can edit/' "$T/s.authz" > "$T/t.authz"
out=$(rows "$T/t.authz" | awk -F'\t' '$3 == "f" {print $4}')
case "$out" in *"with scope read can edit file"*) ok "... and a check that fails under a scope says so";; *) bad "with scope, failing" "$out";; esac
[ -z "$(PSQL -c "SELECT current_setting('authz.scopes', true)")" ] && ok "... and nothing of it stays in the session" || bad "with scope left a setting"
sed 's/as user $bo refused {WITH/as user $bo allowed {WITH/' "$T/w.authz" > "$T/t.authz"
out=$(rows "$T/t.authz" | awk -F'\t' '$3 == "f" {print $4}')
case "$out" in *"refused: it changed no rows"*) ok "... 'allowed' on one fails, and says it changed no rows";; *) bad "allowed, no rows" "$out";; esac
printf '%s\n' 'test "x"' '  given a = {SELECT 1 WHERE false}' '  anyone cannot view file 1' > "$T/x.authz"
out=$(rows "$T/x.authz" | awk -F'\t' '$1 == "x" {print $4}')
case "$out" in *"returned 0 rows: it must return one"*) ok "a given that returns no row is an error, named";; *) bad "given no row" "$out";; esac

echo "-- refusals that say why"
out=$(as 1 "INSERT INTO app.files (folder_id, owner_id, name) VALUES (6, 2, 'x')")
case "$out" in *"42501"*"permission denied: user 1 may not insert this row into app.files"*"insert : folder.edit and owner"*"no   owner"*)
  ok "a refused insert says which rule, and which part of it";; *) bad "refused insert" "$out";; esac
case "$out" in *"CONSTRAINT NAME:  authz_insert"*"TABLE NAME:  files"*|*"TABLE NAME:  files"*"CONSTRAINT NAME:  authz_insert"*) ok "... with the table and the policy in the error's fields";;
  *) bad "error fields" "$out";; esac
out=$(as 6 "INSERT INTO app.files (folder_id, owner_id, name) VALUES (6, 6, 'x')")
case "$out" in *"no   you have no access to folder 6"*) ok "... and says nothing about a folder the user can't see";; *) bad "no leak" "$out";; esac
out=$(as 5 "UPDATE app.folders SET inherit = false WHERE id = 1 RETURNING id")
[ "$out" = 1 ] && ok "an allowed update is not refused" || bad "allowed update" "$out"
# as user $1, in a transaction rolled back after it: rows put in as the owner ($2), then statements ($3, $4)
then_as() { psql -X -q -At -d "$DB" -v VERBOSITY=verbose -c "BEGIN" -c "$2" -c "SET LOCAL ROLE app_user" \
  -c "SET LOCAL authz.user_id = '$1'" -c "$3" ${4:+-c "$4"} -c "ROLLBACK" 2>&1; }
# alice may share a folder below Engineering through Engineering alone: once she turns its inheritance off, she
# may no longer edit it, so the update rule doesn't hold after the change
out=$(then_as 1 "INSERT INTO app.folders (id, org_id, parent_id, owner_id, name) VALUES (90, 1, 3, 3, 'Below')" \
  "UPDATE app.folders SET inherit = false WHERE id = 90")
case "$out" in *"42501: permission denied: user 1 may not update this row of app.folders to these values"*"DETAIL:  no   update : edit  (line "*"  no   edit"*"HINT:  the update rule must hold on the row after the change too (Postgres checks both) (rowstile help AZ709)"*)
  ok "an update the rule refuses on the row after it says so, and that the rule holds on both sides";; *) bad "refused after the change" "$out";; esac
# bob may edit Design docs (his team edits Engineering above it), not share it, and not edit Handbook: moving it
# there fails both items of `update parent_id after`, and the second (an and) says which of its parts failed
out=$(then_as 2 "SELECT 1" "UPDATE app.folders SET parent_id = 2 WHERE id = 4")
want="DETAIL:  no   update parent_id after : parent.edit or ({parent_id is null} and share)  (line "*$'\n'"  no   parent.edit"$'\n'"    no   you have no access to folder 2"$'\n'"  no   ({parent_id is null} and share)"$'\n'"    no   {parent_id is null}"$'\n'"    no   share"$'\n'"HINT:  "
case "$out" in *"42501: changing parent_id of app.folders 4 needs: parent.edit or ({parent_id is null} and share)"$'\n'$want*)
  ok "a refused move says which part of an and failed, each on its own line below it";; *) bad "the parts of an and" "$out";; esac

echo "-- authz.explain_rule"
out=$(as 1 "SELECT array_to_string(authz.explain_rule('app.files', 'update', '11'), '|')")
case "$out" in "yes  update : edit"*) ok "an update that would be allowed: yes";; *) bad "explain update yes" "$out";; esac
out=$(as 1 "SELECT authz.explain_rule('app.files', 'delete', '999999') IS NULL")
[ "$out" = t ] && ok "a row that isn't there: NULL (404, not 403)" || bad "explain missing" "$out"
out=$(as 2 "SELECT array_to_string(authz.explain_rule('app.files', 'delete', '13'), '|')")
case "$out" in "no   delete : edit  (line "*"|  no   edit|    no   user 2 does not hold edit on file 13|"*)
  ok "a delete the user may not make: no, and why";; *) bad "explain delete" "$out";; esac
out=$(as 1 "SELECT authz.explain_rule('app.files', 'update')")
case "$out" in *"22023: which row? authz.explain_rule(app.files, update, id)"*) ok "an update is explained for a row: which one?";;
  *) bad "explain without a row" "$out";; esac
out=$(as 1 "SELECT authz.explain_rule('app.files', 'select', '11')")
case "$out" in *"22023: explain_rule explains insert, update or delete, not select"*) ok "... and writes only";;
  *) bad "explain a select" "$out";; esac
out=$(as 1 "SELECT authz.can('file', '11', 'fly')")
case "$out" in *"P0001: no permission file.fly in the policy"*) ok "a permission the policy doesn't have is a mistake, not a no";;
  *) bad "can, an unknown permission" "$out";; esac
out=$(as 1 "SELECT * FROM authz.who('file', '11', 'fly')")
case "$out" in *"P0001: no permission file.fly in the policy"*) ok "... asking who holds it too";; *) bad "who, an unknown permission" "$out";; esac
# a type without permissions (team) is still a type: no such permission, and none held
out=$(as 1 "SELECT authz.can('team', '10', 'view')")
case "$out" in *"P0001: no permission team.view in the policy"*) ok "... on a type that has no permissions too";;
  *) bad "can, a type without permissions" "$out";; esac
out=$(psql -X -q -At -d "$DB" -v VERBOSITY=verbose -c "SELECT * FROM authz.who('team', '10', 'view')" 2>&1)  # as one who may ask
case "$out" in *"P0001: no permission team.view in the policy"*) ok "... asking who holds it on such a type";;
  *) bad "who, a type without permissions" "$out";; esac
out=$(as 1 "SELECT cardinality(authz.perms('team', '10'))")
[ "$out" = 0 ] && ok "... and the permissions held on it: none" || bad "perms, a type without permissions" "$out"
# each call that takes a type or a permission says so itself (its own guard, which the error's context names)
nope() {   # $1 label, $2 SQL, $3 the error's words, $4 the function that raises it; as user 1, or as $AS_SQL says
  local out; out=$(psql -X -q -At -d "$DB" -v VERBOSITY=verbose -c "SET ROLE app_user" -c "SET authz.user_id = '1'" \
    ${AS_SQL:+-c "$AS_SQL"} -c "$2" 2>&1)
  case "$out" in "ERROR:  P0001: $3"$'\n'"HINT:  rowstile help AZ707"$'\n'"CONTEXT:  PL/pgSQL function $4 line "*" at RAISE"*) ok "$1";;
    *) bad "$1" "$out";; esac
}
nope "... listing what holds it" "SELECT * FROM authz.list('file', 'fly')" "no permission file.fly in the policy" \
  "authz.list(text,text,text,integer)"
nope "a type the policy doesn't have is a mistake too: the permissions held on it" "SELECT authz.perms('boat', '1')" \
  "no type boat in the policy" "authz.perms(text,text)"
nope "... asking can() about it" "SELECT authz.can('boat', '1', 'view')" "no type boat in the policy" "authz.can(text,text,text)"
nope "... sharing it" "SELECT authz.share('boat', '1', 'viewer', 'user', '2')" "no type boat in the policy" \
  "authz.share(text,text,text,text,text,text,timestamp with time zone,timestamp with time zone,text,jsonb)"
AS_SQL="RESET ROLE" nope "... asking who holds a permission on it (as one who may ask: others may not see who)" \
  "SELECT * FROM authz.who('boat', '1', 'view')" "no type boat in the policy" "authz.who(text,text,text)"
# with a key's scopes, can() answers no for a permission they leave out, before it looks at the type or the
# permission: explaining it still says the mistake
AS_SQL="SET authz.scopes = 'read'" nope "with scopes, explain says a permission the policy doesn't have is a mistake" \
  "SELECT * FROM authz.explain('file', '11', 'fly')" "no permission file.fly in the policy" "authz.explain(text,text,text,text)"
AS_SQL="SET authz.scopes = 'read'" nope "... on a type that has no permissions" \
  "SELECT * FROM authz.explain('team', '10', 'fly', '1')" "no permission team.fly in the policy" "authz.explain(text,text,text,text)"
AS_SQL="SET authz.scopes = 'read'" nope "... and on a type the policy doesn't have" \
  "SELECT * FROM authz.explain('boat', '1', 'fly', '1')" "no type boat in the policy" "authz.explain(text,text,text,text)"
out=$(as 6 "SELECT authz.explain_rule('app.files', 'update', '11') IS NULL")
[ "$out" = t ] && ok "... and one the user can't see: NULL too" || bad "explain invisible" "$out"
out=$(as 2 "SELECT array_to_string(authz.explain_rule('app.files', 'update', '12', '{\"name\": \"x\"}'), '|')")
case "$out" in "no   update : edit"*"after the change:"*) ok "an update the user may not make: no, before and after the change";; *) bad "explain update" "$out";; esac
out=$(as 1 "SELECT authz.explain_rule('app.nothing', 'insert')")
case "$out" in *"no rules for table app.nothing"*) ok "a table without rules is named";; *) bad "no rules" "$out";; esac

echo "-- an update after rule: what the row after the change answers to"
# (applying makes rowstile's functions anew, and Postgres's counts of their calls go with the old ones: while the
# run measures what the suites run, they are kept first, here and before the next apply; tests/coverage_functions.sh)
bash tests/coverage_functions.sh "$DB"
# a file's sharers update it, and after the change they must still edit it (not share it)
sed 's/^  update                            : edit$/  update                            : share\n  update after                      : edit/' \
  example/docs.authz > "$T/after.authz"
[ "$(grep -c '^  update after  *: edit$' "$T/after.authz")" = 1 ] || bad "could not make the policy with an update after rule"
run apply "$T/after.authz"; case "$out" in *": applied") ;; *) bad "the policy with an update after rule applies" "$out";; esac
# carol gives away her file in Secrets, where she edits nothing
out=$(then_as 3 "INSERT INTO app.files (id, folder_id, owner_id, name) VALUES (90, 5, 3, 'mine')" \
  "UPDATE app.files SET owner_id = 4 WHERE id = 90")
case "$out" in *"42501: permission denied: user 3 may not update this row of app.files to these values"*"DETAIL:  no   update after : edit  (line "*"  no   edit"*"HINT:  rowstile help AZ709"*)
  ok "an update the after rule refuses says it is that rule, on the row after the change";; *) bad "refused by the after rule" "$out";; esac
case "$out" in *"holds edit on file 90"*) bad "the after rule's reasons read the row as stored" "$out";;
  *) ok "... and gives no reasons read from the row as stored, which the change alters";; esac
# bob gives away his file in Design docs, which he edits: the update rule (share) wouldn't hold after it
out=$(then_as 2 "INSERT INTO app.files (id, folder_id, owner_id, name) VALUES (91, 4, 2, 'his')" \
  "SELECT array_to_string(authz.explain_rule('app.files', 'update', '91', '{\"owner_id\": 7}'), '|')" \
  "UPDATE app.files SET owner_id = 7 WHERE id = 91 RETURNING owner_id")
[ "${out##*$'\n'}" = 7 ] && ok "... and one it allows goes through, though the update rule wouldn't hold after it" ||
  bad "allowed by the after rule" "$out"
case "$out" in "yes  update : share  (line "*"|after the change:|  yes  update after : edit  (line "*) ok "... which explain_rule says: after the change, the after rule";;
  *) bad "explain_rule with an update after rule" "$out";; esac
bash tests/coverage_functions.sh "$DB"
CLI apply example/docs.authz >/dev/null 2>&1

echo "-- authz.who_among"
out=$(as '' "SELECT string_agg(x, ',' ORDER BY x) FROM authz.who_among('file', 11, 'view', ARRAY['1','2','3','4','5','6','7']) x")
[ -n "$out" ] && ok "who of these may view file 11: $out" || bad "who_among" "$out"
want=$(for u in 1 2 3 4 5 6 7; do [ "$(as $u "SELECT authz.can('file', 11, 'view')")" = t ] && printf '%s,' $u; done)
[ "$out," = "$want" ] && ok "... the same as asking authz.can as each of them" || bad "who_among vs can" "$out vs $want"
out=$(as 4 "SELECT count(*) FROM authz.who_among('file', 11, 'view', ARRAY['1']); SELECT current_setting('authz.user_id')" | tail -n 1)
[ "$out" = 4 ] && ok "... and whoever was signed in stays signed in" || bad "who_among restores" "$out"
PSQL -c "DROP ROLE IF EXISTS authz_devx_other" -c "CREATE ROLE authz_devx_other" -c "GRANT USAGE ON SCHEMA authz TO authz_devx_other" \
     -c "GRANT EXECUTE ON FUNCTION authz.who_among(text, text, text, text[], text) TO authz_devx_other" >/dev/null
out=$(PSQL -c "SET ROLE authz_devx_other" -c "SELECT authz.who_among('file', '11', 'view', ARRAY['1'])" 2>&1)
case "$out" in *"permission denied"*) ok "a role that may not sign people in may not use it";; *) bad "who_among needs SET" "$out";; esac

echo "-- applying, and what it warns about"
{ cat example/docs.authz; printf '%s\n' 'rules app.teams' '  select : {exists (select 1 from app.files f where f.owner_id = authz.uid())}'; } > "$T/trap.authz"
run apply "$T/trap.authz"
qual=$(PSQL -c "SELECT qual FROM pg_policies WHERE schemaname = 'app' AND tablename = 'teams' AND policyname = 'authz_select'")
case "$out $qual" in *"row-level security"*) bad "a rule condition that reads a governed table is warned about" "$out";;
  *"authz_gen.team__check_"*) ok "a rule condition that reads a governed table runs with the policy's rights, as a function";;
  *) bad "the rule condition" "$qual";; esac
CLI apply example/docs.authz >/dev/null 2>&1

echo "-- drafting a policy (rowstile init)"
mkdir -p "$T/i" && ( cd "$T/i" && python3 "$OLDPWD/cli/rowstile_cli.py" --db "dbname=$DB" init --schema app ) > "$T/init.log" 2>&1
out=$(cat "$T/i/db/policy.authz" 2>/dev/null)
case "$out" in *"type folder = app.folders"*"parent : folder = parent_id"*"member : user = app.org_members(org_id -> user_id)"*"update parent_id after : parent.edit"*)
  ok "a draft: types, relations from columns and link tables, rules";; *) bad "draft" "${out:0:400} $(cat "$T/init.log")";; esac
run apply "$T/i/db/policy.authz"; case "$out" in *": applied") ok "... which applies";; *) bad "draft applies" "$out";; esac
CLI apply example/docs.authz >/dev/null 2>&1
# --out: the draft, its first test and the lock file's folder somewhere else than db/, and rowstile.toml says where
out=$(mkdir -p "$T/o" && cd "$T/o" && python3 "$OLDPWD/cli/rowstile_cli.py" --db "dbname=$DB" init --schema app --out auth/policy 2>&1)
[ -f "$T/o/auth/policy/policy.authz" ] && [ -f "$T/o/auth/policy/tests/first.authz" ] && [ ! -e "$T/o/db" ] &&
  grep -q '^policy   = "auth/policy/policy.authz"$' "$T/o/rowstile.toml" && grep -q '^tests    = \["auth/policy/tests/\*.authz"\]$' "$T/o/rowstile.toml" &&
  ok "init --out writes the draft and its first test there, and rowstile.toml names them" || bad "init --out" "$out $(ls -R "$T/o")"
out=$(mkdir -p "$T/j" && cd "$T/j" && python3 "$OLDPWD/cli/rowstile_cli.py" --db "dbname=$DB" init --schema nosuch 2>&1)
case "$out" in *"no tables to draft a policy from in nosuch"*) ok "a schema with no tables is named";; *) bad "draft empty" "$out";; esac
out=$(mkdir -p "$T/u" && cd "$T/u" && python3 "$OLDPWD/cli/rowstile_cli.py" --db "dbname=$DB" init --schema app --users app.nosuch 2>&1)
[ "$out" = "app.nosuch: no such table with a primary key in app" ] && [ -z "$(ls -A "$T/u")" ] &&
  ok "... and a --users table that isn't there, with nothing written" || bad "init --users of a table that isn't there" "$out $(ls -A "$T/u")"
# in a Next.js app on Prisma: the tool, the generated names, the SDK packages and the setup line
mkdir -p "$T/k/prisma" "$T/k/src"
printf '{\n    "name": "shop",\n    "dependencies": {"next": "16", "@prisma/client": "7", "react": "19"}\n}\n' > "$T/k/package.json"
printf 'datasource db {\n  provider = "postgresql"\n}\n' > "$T/k/prisma/schema.prisma"
printf 'export const db = new PrismaClient({ adapter });\n' > "$T/k/src/db.ts"
out=$(cd "$T/k" && python3 "$OLDPWD/cli/rowstile_cli.py" --db "dbname=$DB" init --schema app 2>&1)
case "$out" in *"found   Next.js, Prisma (prisma/schema.prisma)"*"added   @rowstile/prisma, @rowstile/next, @rowstile/react, rowstile"*"in src/db.ts"*"signedIn("*)
  ok "init finds Next.js and Prisma, adds the SDK, says which line to change";; *) bad "init stack" "$out";; esac
grep -q 'tool = "prisma"' "$T/k/rowstile.toml" && grep -q 'dir  = "prisma/migrations"' "$T/k/rowstile.toml" && grep -q 'ts = "src/authz.gen.ts"' "$T/k/rowstile.toml" &&
  grep -q '"@rowstile/prisma": "^' "$T/k/package.json" && grep -q '^    "name": "shop"' "$T/k/package.json" && grep -q 'linguist-generated' "$T/k/.gitattributes" &&
  ok "... in rowstile.toml, package.json (its layout kept) and .gitattributes" || bad "init stack files" "$(cat "$T/k/rowstile.toml" "$T/k/package.json")"
# ...and that the app's client takes a URL of its own, not Prisma's, which is the owner's
case "$out" in *"process.env.ROWSTILE_APP_URL"*"never the one this command uses"*) ok "... and that the app connects with its own URL, as the app role";;
  *) bad "init: the app's connection" "$out";; esac
# init again there: rowstile.toml is kept, and package.json, which has the packages now, is left as it is
before=$(cksum < "$T/k/package.json")
out=$(cd "$T/k" && python3 "$OLDPWD/cli/rowstile_cli.py" --db "dbname=$DB" init --schema app 2>&1)
case "$out" in *"added "*) bad "init again adds packages the app has" "$out";;
  *"using rowstile.toml (it is there already)"*) [ "$(cksum < "$T/k/package.json")" = "$before" ] &&
    ok "... init again keeps rowstile.toml, and package.json as it is" || bad "init again changed package.json" "$(cat "$T/k/package.json")";;
  *) bad "init again in the Next.js app" "$out";; esac
# ...and with rowstile.toml gone: written again, and .gitattributes, which marks the generated files already, as it is
before=$(cksum < "$T/k/.gitattributes"); rm "$T/k/rowstile.toml"
out=$(cd "$T/k" && python3 "$OLDPWD/cli/rowstile_cli.py" --db "dbname=$DB" init --schema app 2>&1)
case "$out" in *".gitattributes"*) bad "init marks the generated files again" "$out";;
  *"wrote rowstile.toml"*) [ "$(cksum < "$T/k/.gitattributes")" = "$before" ] &&
    ok "... with rowstile.toml gone, writes it, and leaves .gitattributes as it is" || bad "init changed .gitattributes" "$(cat "$T/k/.gitattributes")";;
  *) bad "init without rowstile.toml" "$out";; esac
# in a FastAPI app that got FastAPI through rowstile's extras, with a role of its own name: the stack is found, the
# role named is the policy's, and rowstile isn't asked for again
mkdir -p "$T/f"
printf '[project]\nname = "tracker"\ndependencies = [\n    "rowstile[asyncpg,fastapi,sqlalchemy]>=0.1.0a4",\n]\n' > "$T/f/pyproject.toml"
printf 'script_location = migrations\n' > "$T/f/alembic.ini"
out=$(cd "$T/f" && python3 "$OLDPWD/cli/rowstile_cli.py" --db "dbname=$DB" init --schema app --role tracker_app 2>&1)
case "$out" in *"to your Python dependencies"*|*"(app_user)"*) bad "init in a FastAPI app asks again, or names another role" "$out";;
  *"found   FastAPI, SQLAlchemy, Alembic"*"Rowstile(app, engine"*"connects as (tracker_app)"*) ok "init finds FastAPI through rowstile's extras, and names the policy's role";;
  *) bad "init in a FastAPI app" "$out";; esac
grep -q "(tracker_app)" "$T/f/db/tests/first.authz" && ok "... in the first test file too" || bad "init: the role in the test file" "$(cat "$T/f/db/tests/first.authz")"
# a FastAPI app that doesn't depend on rowstile yet: what to add to its dependencies, with the extras it uses
mkdir -p "$T/fa"
printf 'fastapi>=0.110\nsqlalchemy\n' > "$T/fa/requirements.txt"
out=$(cd "$T/fa" && python3 "$OLDPWD/cli/rowstile_cli.py" --db "dbname=$DB" init --schema app 2>&1)
case "$out" in *"found   FastAPI, SQLAlchemy, Postgres"*"add     rowstile[fastapi,sqlalchemy]"*" to your Python dependencies (pip install 'rowstile[fastapi,sqlalchemy]"*"', or uv add 'rowstile[fastapi,sqlalchemy]"*)
  ok "init in a FastAPI app without rowstile says what to add to its dependencies";; *) bad "init: what to add to a Python app" "$out";; esac
# a schema as Prisma names it (capitals), a column named like an SQL word, a link table named like a permission,
# one through a unique column, a name with a space, and the migration tool's own table: the draft compiles and applies
dropdb --if-exists "${DB}_names" 2>/dev/null; createdb "${DB}_names"
psql -X -q -v ON_ERROR_STOP=1 -d "${DB}_names" >/dev/null <<'SQL'
CREATE SCHEMA pr;
CREATE TABLE pr."User" (id serial PRIMARY KEY, email text UNIQUE);
CREATE TABLE pr."Post" (id serial PRIMARY KEY, "authorId" int REFERENCES pr."User", "order" int REFERENCES pr."User");
CREATE TABLE pr."Comment" (id serial PRIMARY KEY, "postId" int REFERENCES pr."Post", "authorId" int REFERENCES pr."User");
CREATE TABLE pr.post_views (post_id int REFERENCES pr."Post", user_id int REFERENCES pr."User", PRIMARY KEY (post_id, user_id));
CREATE TABLE pr.teams (id serial PRIMARY KEY, slug text UNIQUE);
CREATE TABLE pr.team_members (team_slug text REFERENCES pr.teams (slug), user_id int REFERENCES pr."User", PRIMARY KEY (team_slug, user_id));
CREATE TABLE pr."_prisma_migrations" (id varchar(36) PRIMARY KEY);
CREATE TABLE pr."owner list" (id serial PRIMARY KEY, "owner id" int REFERENCES pr."User");
SQL
mkdir -p "$T/n"
out=$(cd "$T/n" && python3 "$OLDPWD/cli/rowstile_cli.py" --db "dbname=${DB}_names" init --schema pr 2>&1)
draft=$(cat "$T/n/db/policy.authz" 2>/dev/null)
case "$draft" in *'type user = pr.User'*'author : user = authorId'*'viewer : user = pr.post_views(post_id -> user_id)'*'insert : author'*'pr._prisma_migrations: the migration tool'*'pr.owner list: a name the policy language'*)
  ok "a draft of a schema with capitals and awkward names: quoted where SQL reads it, the rest left out and said";; *) bad "draft names" "$out $draft";; esac
out=$(cd "$T/n" && python3 "$OLDPWD/cli/rowstile_cli.py" check 2>&1); rc=$?
[ $rc -eq 0 ] && ok "... which compiles" || bad "draft names compile" "$out"
out=$(cd "$T/n" && python3 "$OLDPWD/cli/rowstile_cli.py" --db "dbname=${DB}_names" apply 2>&1); rc=$?
case "$out" in *": applied") ok "... and applies";; *) bad "draft names apply" "$out";; esac
dropdb --if-exists "${DB}_names" 2>/dev/null
# shapes real apps have (Chatwoot, GitLab, Documenso, Plausible): accounts beside users, a foreign key declared
# twice, a loop of foreign keys where only orgs have owners, a membership with an id of its own: the draft takes
# users, one relation, a loop that compiles, a link; it applies, and lint finds no view written out too often
dropdb --if-exists "${DB}_apps" 2>/dev/null; createdb "${DB}_apps"
psql -X -q -v ON_ERROR_STOP=1 -d "${DB}_apps" >/dev/null <<'SQL'
CREATE SCHEMA lo;
CREATE TABLE lo.accounts (id bigserial PRIMARY KEY, name text);
CREATE TABLE lo.users (id bigserial PRIMARY KEY, account_id bigint REFERENCES lo.accounts);
CREATE TABLE lo.orgs (id bigserial PRIMARY KEY, owner_id bigint REFERENCES lo.users, settings_id bigint);
CREATE TABLE lo.settings (id bigserial PRIMARY KEY, email_id bigint);
CREATE TABLE lo.emails (id bigserial PRIMARY KEY, domain_id bigint);
CREATE TABLE lo.domains (id bigserial PRIMARY KEY, org_id bigint REFERENCES lo.orgs);
ALTER TABLE lo.orgs ADD FOREIGN KEY (settings_id) REFERENCES lo.settings;
ALTER TABLE lo.settings ADD FOREIGN KEY (email_id) REFERENCES lo.emails;
ALTER TABLE lo.emails ADD FOREIGN KEY (domain_id) REFERENCES lo.domains;
ALTER TABLE lo.emails ADD CONSTRAINT fk_again FOREIGN KEY (domain_id) REFERENCES lo.domains NOT VALID;
CREATE TABLE lo.org_memberships (id bigserial PRIMARY KEY, org_id bigint NOT NULL REFERENCES lo.orgs,
                                 user_id bigint NOT NULL REFERENCES lo.users, note text, UNIQUE (org_id, user_id));
CREATE TABLE lo.projects (id bigserial PRIMARY KEY, org_id bigint REFERENCES lo.orgs, lead_id bigint REFERENCES lo.users);
CREATE TABLE lo.tasks (id bigserial PRIMARY KEY, project_id bigint REFERENCES lo.projects, author_id bigint REFERENCES lo.users);
SQL
mkdir -p "$T/a"
out=$(cd "$T/a" && python3 "$OLDPWD/cli/rowstile_cli.py" --db "dbname=${DB}_apps" init --schema lo 2>&1)
draft=$(cat "$T/a/db/policy.authz" 2>/dev/null)
case "$draft" in *'type user = lo.users'*'type domain = lo.domains'*'membership : user = lo.org_memberships(org_id -> user_id)'*'can view = author or project.view'*)
  ok "a draft of real apps' shapes: users, not accounts; a membership with an id; each parent named once";; *) bad "draft apps" "$out $draft";; esac
[ "$(grep -c 'update domain_id after' <<<"$draft")" = 1 ] && ok "... a foreign key declared twice is one relation" || bad "draft apps: the key twice" "$draft"
out=$(cd "$T/a" && python3 "$OLDPWD/cli/rowstile_cli.py" check 2>&1); rc=$?
[ $rc -eq 0 ] && ok "... which compiles (the loop of foreign keys too)" || bad "draft apps compile" "$out"
out=$(cd "$T/a" && python3 "$OLDPWD/cli/rowstile_cli.py" --db "dbname=${DB}_apps" apply 2>&1); rc=$?
case "$out" in *": applied") ok "... and applies";; *) bad "draft apps apply" "$out";; esac
out=$(cd "$T/a" && python3 "$OLDPWD/cli/rowstile_cli.py" --db "dbname=${DB}_apps" lint 2>&1)
case "$out" in *"name others more than once"*) bad "draft apps: lint warns of views written out again" "$out";;
  *) ok "... and lint finds no permission named again and again";; esac
# round the loop as the org's owner: the domain, its address, the settings that use it, and the org
psql -X -q -d "${DB}_apps" -c "INSERT INTO lo.users (id) VALUES (1), (2);
  INSERT INTO lo.orgs (id, owner_id) VALUES (1, 1); INSERT INTO lo.domains (id, org_id) VALUES (1, 1);
  INSERT INTO lo.emails (id, domain_id) VALUES (1, 1); INSERT INTO lo.settings (id, email_id) VALUES (1, 1);
  INSERT INTO lo.orgs (id, owner_id, settings_id) VALUES (2, 2, 1)" >/dev/null
out=$(psql -X -q -At -d "${DB}_apps" -c "SET authz.user_id = '1'" -c "SELECT authz.can('domain', '1', 'edit'), authz.can('email', '1', 'edit'),
  authz.can('setting', '1', 'edit'), authz.can('org', '2', 'edit')" -c "SET authz.user_id = '2'" -c "SELECT authz.can('domain', '1', 'edit')" 2>&1 | tr '\n' ' ')
[ "$out" = "t|t|t|t f " ] && ok "... and round the loop the org's owner edits each in turn, the other owner none of them" || bad "draft apps: the loop" "$out"
dropdb --if-exists "${DB}_apps" 2>/dev/null

echo "-- the rowstile command"
mkdir -p "$T/p/tests"
sed '/^test$/,$d' example/docs.authz > "$T/p/policy.authz"     # its old test section needs the scenario's shares
cp example/docs.test.authz "$T/p/tests/docs.authz"
printf 'policy = "policy.authz"\ntests = ["tests/*.authz"]\ndatabase = "dbname=%s"\n[clients]\npy = "out/authz_client.py"\n' "$DB" > "$T/p/rowstile.toml"
( cd "$T/p" && python3 "$OLDPWD/cli/rowstile_cli.py" dev --once ) > "$T/dev.log" 2>&1; rc=$?
case "$(cat "$T/dev.log")" in *"isn't marked as a development database"*"[AZ610]"*"nothing applied"*) [ $rc -eq 1 ] &&
  ok "dev won't push to a database with a policy that isn't marked as a development database" || bad "dev unmarked exit" "$rc";;
  *) bad "dev on an unmarked database" "$(cat "$T/dev.log")";; esac
CLI push --development example/docs.authz >/dev/null 2>&1 || bad "push --development"
( cd "$T/p" && python3 "$OLDPWD/cli/rowstile_cli.py" dev --once ) > "$T/dev.log" 2>&1; rc=$?
case "$(cat "$T/dev.log")" in *"ok   compiles"*"applied in"*"check(s) pass"*"wrote out/authz_client.py"*) [ $rc -eq 0 ] &&
  ok "dev --once: compiles, applies, tests, writes the client" || bad "dev exit" "$rc";; *) bad "dev --once" "$(cat "$T/dev.log")";; esac
# a lookup the policy makes that no index serves: named once the pass is through, with the line to add
PSQL -c "DROP INDEX app.team_members_user_id_idx"
( cd "$T/p" && python3 "$OLDPWD/cli/rowstile_cli.py" dev --once ) > "$T/dev.log" 2>&1; rc=$?
case "$(cat "$T/dev.log")" in *"check(s) pass"*"  !    app.team_members has no index on (user_id): finding the teams by their team.member"*'         add: CREATE INDEX CONCURRENTLY "team_members_user_id_idx" ON "app"."team_members" ("user_id");')
  [ $rc -eq 0 ] && ok "... and names a lookup no index serves, with the index to add" || bad "dev index exit" "$rc";;
  *) bad "dev and a missing index" "$(cat "$T/dev.log")";; esac
PSQL -c "CREATE INDEX team_members_user_id_idx ON app.team_members (user_id)"
sed -i 's/can edit  = share or editor or/can edit  = share or edtor or/' "$T/p/policy.authz"
( cd "$T/p" && python3 "$OLDPWD/cli/rowstile_cli.py" dev --once ) > "$T/dev.log" 2>&1; rc=$?
case "$(cat "$T/dev.log")" in *"policy.authz: line "*"edtor"*"nothing applied"*) [ $rc -eq 1 ] && ok "... a mistake stops it before applying, exit 1" || bad "dev mistake exit" "$rc";;
  *) bad "dev mistake" "$(cat "$T/dev.log")";; esac
sed -i 's/edtor/editor/' "$T/p/policy.authz"
# what it says of a test that fails, a test file it can't read, and a table the database doesn't have
devonce() { ( cd "$T/p" && python3 "$OLDPWD/cli/rowstile_cli.py" dev --once ) > "$T/dev.log" 2>&1; rc=$?; }
cp "$T/p/tests/docs.authz" "$T/docs.keep"
sed -i 's/user $bo cannot view file $f/user $bo can view file $f/' "$T/p/tests/docs.authz"
devonce
case "$(cat "$T/dev.log")" in *"         ok    "*) bad "dev lists the checks that pass with the one that fails" "$(cat "$T/dev.log")";;
  *"  x    1 of "*" checks fail"*"FAIL  tests/docs.authz line 13: user \$bo can view file \$f"*"does not hold view on file"*)
    [ $rc -eq 1 ] && ok "dev on a failing test: which check, its line and why, not the ones that pass; exit 1" || bad "dev on a failing test: exit" "$rc";;
  *) bad "dev on a failing test" "$(cat "$T/dev.log")";; esac
cp "$T/docs.keep" "$T/p/tests/docs.authz"
printf 'test "caf\351"\n  anyone cannot view file 11\n' > "$T/p/tests/latin.authz"
devonce
case "$(cat "$T/dev.log")" in *"  x    tests/latin.authz: not UTF-8 (the byte at "*"): save it as UTF-8"*)
  [ $rc -eq 1 ] && ok "... on a test file that isn't UTF-8: said, exit 1" || bad "dev on a test file not UTF-8: exit" "$rc";;
  *) bad "dev on a test file not UTF-8" "$(cat "$T/dev.log")";; esac
rm "$T/p/tests/latin.authz"
sed -i 's/^type team = app.teams$/type team = app.teamz/' "$T/p/policy.authz"
devonce
case "$(cat "$T/dev.log")" in *"  x    the policy does not match this database:"*"table app.teamz not found [AZ601]"*"nothing applied"*)
  [ $rc -eq 1 ] && ok "... on a table the database doesn't have: the database's words, nothing applied, exit 1" || bad "dev on a missing table: exit" "$rc";;
  *) bad "dev on a missing table" "$(cat "$T/dev.log")";; esac
sed -i 's/^type team = app.teamz$/type team = app.teams/' "$T/p/policy.authz"
# a policy with neither tests nor invariants
dropdb --if-exists "${DB}_plain" 2>/dev/null; createdb "${DB}_plain"
PGOPTIONS="-c client_min_messages=error" psql -X -q -v ON_ERROR_STOP=1 -d "${DB}_plain" -f example/app_schema.sql >/dev/null
printf 'app role app_user\ntype user = app.users\n' > "$T/plain.authz"
out=$(python3 cli/rowstile_cli.py --db "dbname=${DB}_plain" dev --once --no-studio "$T/plain.authz" 2>&1); rc=$?
case "$out" in *'  ok   no tests yet (rowstile.toml: tests = ["db/tests/*.authz"])'*) [ $rc -eq 0 ] && ok "... on a policy with neither tests nor invariants: no tests yet, exit 0" || bad "dev without tests: exit" "$rc";;
  *) bad "dev without tests" "$out";; esac
dropdb --if-exists "${DB}_plain"
# who gains and loses what, said before each push: permissions on objects, and rows by table
cp "$T/p/policy.authz" "$T/policy.keep"
sed -i 's/^           or (folder.view and not {confidential})$//' "$T/p/policy.authz"
devonce
[ $rc -eq 0 ] && grep -q "^  ~    access:$" "$T/dev.log" &&
  grep -qE "^       [1-9][0-9]* user\(s\) lose rows readable in app\.files \([1-9][0-9]* rows?\)$" "$T/dev.log" &&
  grep -qE "^       [1-9][0-9]* user\(s\) lose permission view on [1-9][0-9]* files?$" "$T/dev.log" &&
  ok "... says before each push who gains and loses what: rows by table, permissions by type" || bad "dev's access" "$rc $(cat "$T/dev.log")"
cp "$T/policy.keep" "$T/p/policy.authz"; devonce
# a client it can't write (its path a folder): which file and why, not a lost database
rm "$T/p/out/authz_client.py"; mkdir "$T/p/out/authz_client.py"
devonce
case "$(cat "$T/dev.log")" in *"lost the database"*) bad "dev says it lost the database for a client it can't write" "$(cat "$T/dev.log")";;
  *"  x    out/authz_client.py: Is a directory"*) [ $rc -eq 1 ] && ok "... of a client file it can't write: which file and why, exit 1" || bad "dev on a client it can't write: exit" "$rc";;
  *) bad "dev on a client it can't write" "$(cat "$T/dev.log")";; esac
rmdir "$T/p/out/authz_client.py"
python3 -c "open('$T/deep.authz', 'w').write('app role app_user\ntype user = app.users\ntype d = app.d\n  o : user = owner_id\n  can view = ' + '(' * 3000 + 'o' + ')' * 3000 + '\n')"
run dev --once --no-studio "$T/deep.authz"
case "$out" in *Traceback*) bad "dev on an expression nested too deep gives a traceback" "${out: -300}";;
  *"  x    "*"deep.authz: an expression in the policy is nested too deep to read"*"nothing applied"*)
    [ $rc -eq 1 ] && ok "... of an expression nested too deep to read: said, nothing applied, exit 1" || bad "dev on deep nesting: exit" "$rc";;
  *) bad "dev on deep nesting" "$out";; esac
# the loop itself, left running: each save of the policy or of a test file runs it again, a mistake stops it
# before applying, the migration is written once the saves stop, and Ctrl-C ends it, exit 0 (with job control
# on: a background job otherwise ignores Ctrl-C)
printf '[migrations]\ntool = "sql"\ndir = "migrations"\nwrite_after = 1\n' >> "$T/p/rowstile.toml"
set -m
( cd "$T/p" && exec python3 "$OLDPWD/cli/rowstile_cli.py" dev --no-studio ) > "$T/watch.log" 2>&1 &
watcher=$!
set +m
# waits (a minute at most) until the loop has said something, or said it n times
seen() { for _ in $(seq 120); do [ "$(grep -c -- "$1" "$T/watch.log")" -ge "${2:-1}" ] && return 0; sleep 0.5; done; return 1; }
passes() { grep -c "check(s) pass" "$T/watch.log"; }
# saves a mistake: the loop drops the migration it was about to write, so once it says it applied nothing, none is
# being written, and a check may change the files one writes
mistake() {
  local k; k=$(grep -c "nothing applied" "$T/watch.log")
  sed -i 's/can edit  = share or editor or/can edit  = share or edtor or/' "$T/p/policy.authz"; seen "nothing applied" $((k + 1))
}
if seen "watching 2 file(s)" && seen "check(s) pass"; then
  printf -- '-- saved again\n' >> "$T/p/tests/docs.authz"
  seen "tests/docs.authz saved" && seen "check(s) pass" 2 && ok "dev runs again when a test file is saved" || bad "dev on a test file" "$(cat "$T/watch.log")"
  sed -i 's/can edit  = share or editor or/can edit  = share or edtor or/' "$T/p/policy.authz"
  seen "policy.authz saved" && seen "nothing applied" && ok "... stops before applying a policy saved with a mistake" || bad "dev on a mistake" "$(cat "$T/watch.log")"
  sed -i 's/edtor/editor/' "$T/p/policy.authz"
  seen "check(s) pass" 3 && ok "... and applies it again once it is fixed" || bad "dev after the fix" "$(cat "$T/watch.log")"
  # (the lock file is written last: before it, Ctrl-C could stop the migration half written)
  seen "stopped editing" && seen "wrote policy.lock" && ls "$T/p/migrations/"*.sql >/dev/null 2>&1 &&
    ok "... and writes the migration once the saves stop ([migrations] write_after)" || bad "dev's migration" "$(cat "$T/watch.log")"
  # a warning applying gives is shown once, then counted while it stays
  n=$(passes); sed -i 's/^  can view  = edit or viewer or (parent.view and {inherit})$/& or {exists (select 1 from app.files f where f.folder_id = id)}/' "$T/p/policy.authz"
  seen "check(s) pass" $((n + 1)) && grep -q "^  !    line [0-9]*: the condition {exists (select 1 from app.files f where f.folder_id = id)} names id" "$T/watch.log" &&
    ok "... shows a warning applying gives" || bad "dev's warning" "$(cat "$T/watch.log")"
  n=$(passes); sed -i 's/^  can share = owner or folder.share$/&\n  can comment = view/' "$T/p/policy.authz"
  seen "check(s) pass" $((n + 1)) && grep -q "^  !    and 1 warning(s) shown before" "$T/watch.log" && [ "$(grep -c "names id, a column of" "$T/watch.log")" = 1 ] &&
    ok "... once: the next change says it was shown before" || bad "dev's warning, shown again" "$(cat "$T/watch.log")"
  n=$(passes); mv "$T/p/policy.authz" "$T/policy.away"
  seen "  x    policy.authz: No such file or directory" && mv "$T/policy.away" "$T/p/policy.authz" && seen "check(s) pass" $((n + 1)) &&
    ok "... says when the policy file is gone, and runs again once it is back" || bad "dev without its policy file" "$(cat "$T/watch.log")"
  # a migration it can't write (its folder is a file): which file and why, and the loop goes on
  mistake; rm -r "$T/p/migrations"; : > "$T/p/migrations"
  n=$(passes); sed -i -e 's/edtor/editor/' -e 's/^  can share = owner or folder.share$/&\n  can annotate = view/' "$T/p/policy.authz"
  seen "check(s) pass" $((n + 1)) && seen "^migrations: File exists" &&
    printf -- '-- saved after it\n' >> "$T/p/tests/docs.authz" && seen "check(s) pass" $((n + 2)) &&
    ok "... says which file stops the migration it writes, and goes on" || bad "dev's migration it can't write" "$(cat "$T/watch.log")"
  rm "$T/p/migrations"; mkdir "$T/p/migrations"
  # a migration it may not write (a lock file a newer rowstile wrote) is said, and the loop goes on
  mistake; sed -i '1s/^# rowstile [^:]*:/# rowstile 99.0.0:/' "$T/p/policy.lock"
  n=$(passes); sed -i -e 's/edtor/editor/' -e '/^  can comment = view$/d' "$T/p/policy.authz"
  seen "check(s) pass" $((n + 1)) && seen "the lock file was last written by rowstile 99.0.0, which is newer than this command" &&
    printf -- '-- saved after it\n' >> "$T/p/tests/docs.authz" && seen "check(s) pass" $((n + 2)) &&
    ok "... says why it writes no migration (a lock file a newer rowstile wrote), and goes on" || bad "dev's migration refused" "$(cat "$T/watch.log")"
  # the server ends dev's session between two saves
  pid=$(PSQL -c "SELECT pid FROM pg_stat_activity WHERE datname = '$DB' AND application_name = 'rowstile' AND pid <> pg_backend_pid() LIMIT 1")
  PSQL -c "SELECT pg_terminate_backend($pid)" >/dev/null
  for _ in $(seq 20); do [ "$(PSQL -c "SELECT count(*) FROM pg_stat_activity WHERE pid = $pid")" = 0 ] && break; sleep 0.25; done
  n=$(passes); printf -- '-- saved once more\n' >> "$T/p/tests/docs.authz"
  seen "  x    lost the database: " && printf -- '-- and again\n' >> "$T/p/tests/docs.authz" && seen "check(s) pass" $((n + 1)) &&
    ok "... says it lost the database when the server ends its session, and connects again on the next save" || bad "dev losing the database" "$(cat "$T/watch.log")"
  # ... and when it ends it in the middle of a push (here while it waits on another apply, which holds the lock
  # apply and push take)
  ( PSQL -c "SELECT pg_advisory_lock(1919905638, 0)" -c "SELECT pg_sleep(4)" >/dev/null 2>&1 ) &
  locker=$!
  for _ in $(seq 40); do [ "$(PSQL -c "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND classid = 1919905638 AND objid = 0 AND granted AND database = (SELECT oid FROM pg_database WHERE datname = current_database())")" = 1 ] && break; sleep 0.25; done
  n=$(passes); sed -i 's/^  can share = owner or folder.share$/&\n  can comment = view/' "$T/p/policy.authz"
  for _ in $(seq 40); do pid=$(PSQL -c "SELECT pid FROM pg_stat_activity WHERE datname = '$DB' AND application_name = 'rowstile' AND wait_event_type = 'Lock' LIMIT 1"); [ -n "$pid" ] && break; sleep 0.25; done
  [ -n "$pid" ] && PSQL -c "SELECT pg_terminate_backend($pid)" >/dev/null
  wait "$locker"
  seen "  x    lost the database: terminating connection" && printf -- '-- saved after it\n' >> "$T/p/tests/docs.authz" && seen "check(s) pass" $((n + 1)) &&
    ok "... and in the middle of a push: lost the database, and connects again on the next save" || bad "dev losing the database in a push" "$(cat "$T/watch.log")"
else
  bad "dev didn't start watching" "$(cat "$T/watch.log")"
fi
kill -INT "$watcher" 2>/dev/null; wait "$watcher"; rc=$?
[ $rc -eq 0 ] && ok "... and Ctrl-C ends it, exit 0" || bad "dev Ctrl-C" "$rc $(tail -n 3 "$T/watch.log")"
# Studio beside the loop (without --no-studio): on the port given, able to write (this is a development database);
# on a port another program holds it doesn't start, and the loop goes on without it
mkdir -p "$T/s"; cp "$T/p/policy.authz" "$T/s/policy.authz"
printf 'policy = "policy.authz"\ndatabase = "dbname=%s"\n' "$DB" > "$T/s/rowstile.toml"
# starts the loop with Studio on port $1, and waits (a minute at most) until it watches
looping() {
  set -m
  ( cd "$T/s" && exec python3 "$OLDPWD/cli/rowstile_cli.py" dev --studio-port "$1" ) > "$T/s.log" 2>&1 &
  watcher=$!
  set +m
  for _ in $(seq 120); do grep -q "^watching" "$T/s.log" && break; sleep 0.5; done
}
port=$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')
looping "$port"
token=$(sed -n "s|^Studio on http://127.0.0.1:$port/?token=\([A-Za-z0-9_-]*\)$|\1|p" "$T/s.log")
writes=$(python3 -c "import json, sys, urllib.request
r = urllib.request.Request('http://127.0.0.1:$port/api/overview', headers={'X-Studio-Token': sys.argv[1]})
print(json.load(urllib.request.urlopen(r, timeout=60))['writable'])" "$token" 2>&1)
kill -INT "$watcher"; wait "$watcher"; rc=$?
[ -n "$token" ] && [ "$writes" = True ] && [ $rc -eq 0 ] &&
  ok "dev starts Studio beside the loop, on the port given, able to write" || bad "dev's Studio" "$rc $writes $(cat "$T/s.log")"
python3 -c 'import socket, sys, time
s = socket.socket(); s.bind(("127.0.0.1", 0)); s.listen()
with open(sys.argv[1], "w") as fh: fh.write(str(s.getsockname()[1]))
time.sleep(120)' "$T/held" &
holder=$!
for _ in $(seq 40); do [ -s "$T/held" ] && break; sleep 0.25; done
port=$(cat "$T/held")
looping "$port"
kill -INT "$watcher"; wait "$watcher"; rc=$?
kill "$holder"; wait "$holder" 2>/dev/null
case "$(cat "$T/s.log")" in *"Studio didn't start ("*"): rowstile dev --studio-port N for another port"*"watching 1 file(s)"*)
  [ $rc -eq 0 ] && ok "... on a port another program holds: says so and how to pick another, and the loop goes on" || bad "dev with Studio's port held: exit" "$rc";;
  *) bad "dev with Studio's port held" "$(cat "$T/s.log")";; esac
# with its output closed (a service, or pythonw on Windows, where there is no console): the pass all the same
( cd "$T/s" && python3 "$OLDPWD/cli/rowstile_cli.py" dev --once --no-studio >&- ) 2> "$T/s.log"; rc=$?
[ $rc -eq 0 ] && [ ! -s "$T/s.log" ] && ok "dev --once with its output closed: exit 0, nothing on stderr" || bad "dev with its output closed" "$rc $(cat "$T/s.log")"
# the database lost once the pass is through, as dev looks for the lookups no index serves: here a session waits to
# lock rowstile's table of policies while a slow test runs, dev's look waits behind it, and is ended there
printf 'test "slow"\n  given s = {SELECT 1 FROM pg_sleep(2)}\n  anyone cannot view file 11\n' > "$T/s/slow.authz"
printf 'tests = ["slow.authz"]\n' >> "$T/s/rowstile.toml"
# starts dev in $T/s with these arguments (dev's pid: $pass), and once its look waits behind the lock, runs $1 with
# its session's pid ($pid)
behind() {
  local then=$1; shift
  set -m
  ( cd "$T/s" && exec python3 "$OLDPWD/cli/rowstile_cli.py" dev --no-studio "$@" ) > "$T/s.log" 2>&1 &
  pass=$!
  set +m
  pid=
  for _ in $(seq 80); do pid=$(PSQL -c "SELECT pid FROM pg_stat_activity WHERE datname = '$DB' AND application_name = 'rowstile' AND wait_event = 'PgSleep'"); [ -n "$pid" ] && break; sleep 0.25; done
  ( PSQL -c "BEGIN" -c "LOCK TABLE authz.policy_versions" -c "SELECT pg_sleep(3)" -c "COMMIT" >/dev/null 2>&1 ) &
  locker=$!
  for _ in $(seq 80); do [ -n "$pid" ] && [ "$(PSQL -c "SELECT wait_event_type FROM pg_stat_activity WHERE pid = $pid")" = Lock ] && break; sleep 0.25; done
  [ -n "$pid" ] && $then
  wait "$locker"
}
grows() { for _ in $(seq 120); do [ "$(grep -c -- "$1" "$T/s.log")" -ge "${2:-1}" ] && return 0; sleep 0.5; done; return 1; }
# the server ends the session there (with --once): said, the pass stands (exit 0), and no traceback
terminate() { PSQL -c "SELECT pg_terminate_backend($pid)" >/dev/null; }
behind terminate --once
wait "$pass"; rc=$?
case "$(cat "$T/s.log")" in *Traceback*) bad "dev on a database lost as it looks for missing indexes gives a traceback" "$(cat "$T/s.log")";;
  *"check(s) pass"*"  x    lost the database: terminating connection due to administrator command"*) [ $rc -eq 0 ] && [ -n "$pid" ] &&
    ok "... and the database lost after the pass, as it looks for missing indexes: said, the pass stands, exit 0" ||
    bad "dev losing the database as it looks for missing indexes: exit" "$rc ($pid)";;
  *) bad "dev losing the database as it looks for missing indexes" "$(cat "$T/s.log")";; esac
# ... and left watching: the next save connects again and runs the pass, without saying it lost the database again
behind terminate
grows "lost the database: terminating connection" && grows "^watching" && printf -- '-- saved\n' >> "$T/s/slow.authz" && grows "check(s) pass" 2 &&
  [ "$(grep -c "lost the database" "$T/s.log")" = 1 ] &&
  ok "... and watching: it goes on watching, and the next save connects again and passes" || bad "dev watching, losing the database as it looks for missing indexes" "$(cat "$T/s.log")"
kill -INT "$pass"; wait "$pass"
# ... the connection closed under it without a word from the server (here by a go-between dev connects through,
# which then closes the connections it holds, as a server that goes away or a network that drops does): the same
python3 -c 'import os, signal, socket, sys, threading
host, port = os.environ.get("PGHOST") or "/var/run/postgresql", int(os.environ.get("PGPORT") or 5432)
held = []
lis = socket.socket(); lis.bind(("127.0.0.1", 0)); lis.listen()
with open(sys.argv[1], "w") as fh: fh.write(str(lis.getsockname()[1]))
def pump(a, b):
    try:
        while data := a.recv(65536): b.sendall(data)
    except OSError: pass
def close(*_):
    for s in held:
        try: s.shutdown(socket.SHUT_RDWR)
        except OSError: pass
        s.close()
    held.clear()
signal.signal(signal.SIGUSR1, close)
while True:
    c, _ = lis.accept()
    u = socket.socket(socket.AF_UNIX) if host.startswith("/") else socket.socket()
    u.connect(f"{host}/.s.PGSQL.{port}" if host.startswith("/") else (host, port))
    held += [c, u]
    for a, b in ((c, u), (u, c)): threading.Thread(target=pump, args=(a, b), daemon=True).start()' "$T/between" &
between=$!
for _ in $(seq 40); do [ -s "$T/between" ] && break; sleep 0.25; done
hang_up() { kill -USR1 "$between"; }
behind hang_up --db "host=127.0.0.1 port=$(cat "$T/between") dbname=$DB"
grows "lost the database: the server closed the connection" && grows "^watching" && printf -- '-- saved again\n' >> "$T/s/slow.authz" && grows "check(s) pass" 2 &&
  [ "$(grep -c "lost the database" "$T/s.log")" = 1 ] &&
  ok "... and when the connection closes without a word from the server: said, and the next save connects again" || bad "dev on a connection closed as it looks for missing indexes" "$(cat "$T/s.log")"
kill -INT "$pass"; wait "$pass"
kill "$between"; wait "$between" 2>/dev/null
# a look that doesn't go through, its session still there (its statement cancelled): nothing said, the pass stands
cancel() { PSQL -c "SELECT pg_cancel_backend($pid)" >/dev/null; }
behind cancel --once
wait "$pass"; rc=$?
case "$(cat "$T/s.log")" in *Traceback*|*"  x    "*) bad "dev on a look for missing indexes cancelled" "$(cat "$T/s.log")";;
  *"check(s) pass"*) [ $rc -eq 0 ] && [ -n "$pid" ] && ok "... and a look cancelled, the session still there: nothing said, exit 0" ||
    bad "dev on a look for missing indexes cancelled: exit" "$rc ($pid)";;
  *) bad "dev on a look for missing indexes cancelled" "$(cat "$T/s.log")";; esac
run test example/docs.test.authz
case "$out" in *"ok    user \$ann can edit file \$f"*"policy tests passed"*) [ $rc -eq 0 ] && ok "test runs named test files, exit 0" || bad "test exit" "$rc";;
  *) bad "test" "$out";; esac
printf 'test "fails"\n  anyone can view file 11\n' > "$T/p/broken.authz"
run test "$T/p/broken.authz"
case "$out" in *"broken.authz line 2: anyone can view file 11"*) echo "$out" | grep -q "1 policy test(s) failed" && [ $rc -eq 1 ] &&
  ok "... and a failing one fails it, exit 1" || bad "test fail exit" "$rc";; *) bad "test fail" "$out";; esac
run can --as user:1 file 11 edit; [ "$out" = yes ] && ok "can --as user:1" || bad "can" "$out"
run explain --as user:6 file 11 view; case "$out" in "no   user 6 does not hold view on file 11"*) ok "explain --as";; *) bad "explain" "$out";; esac
run sql --as user:2 "SELECT count(*) AS n FROM app.folders"; case "$out" in *"(1 row, as user:2; rolled back)"*) ok "sql --as runs as the app role";; *) bad "sql" "$out";; esac
run sql --as user:2 "DELETE FROM app.users"; [ "$(PSQL -c "SELECT count(*) > 0 FROM app.users")" = t ] && ok "... and rolls back" || bad "sql rollback" "$out"
run explain-rule --as user:1 app.files insert --row '{"folder_id": 6, "owner_id": 2}'
case "$out" in "no   insert"*"no   owner"*) ok "explain-rule --as";; *) bad "explain-rule" "$out";; esac
[ -f "$T/i/db/policy.authz" ] && [ -f "$T/i/rowstile.toml" ] && [ -f "$T/i/db/tests/first.authz" ] && grep -q "authz.act_as" "$T/init.log" &&
  ok "init writes a policy, a test file and rowstile.toml, and says what's next" || bad "init" "$(cat "$T/init.log")"
# the note for coding agents: written with the paths init wrote; a second init leaves it as it is, and one
# in a project that has an AGENTS.md adds its section at the end
grep -q "^wrote AGENTS.md" "$T/init.log" && grep -q '^- The policy is `db/policy.authz`, its tests `db/tests/\*.authz`' "$T/i/AGENTS.md" &&
  ok "init writes AGENTS.md: where the policy is, and the loop" || bad "init AGENTS.md" "$(cat "$T/init.log" "$T/i/AGENTS.md" 2>&1)"
before=$(cksum < "$T/i/AGENTS.md")
out=$(cd "$T/i" && python3 "$OLDPWD/cli/rowstile_cli.py" --db "dbname=$DB" init --schema app 2>&1)
case "$out" in *"kept AGENTS.md (it has rowstile's section already)"*) [ "$(cksum < "$T/i/AGENTS.md")" = "$before" ] &&
  ok "... a second init changes nothing in it" || bad "init AGENTS.md twice" "$out";; *) bad "init AGENTS.md twice" "$out";; esac
mkdir -p "$T/ag" && printf '# The app\n\nRun the tests with make.\n' > "$T/ag/AGENTS.md"
out=$(cd "$T/ag" && python3 "$OLDPWD/cli/rowstile_cli.py" --db "dbname=$DB" init --schema app 2>&1)
case "$out" in *"added   rowstile's section to AGENTS.md"*) [ "$(head -1 "$T/ag/AGENTS.md")" = "# The app" ] && [ "$(grep -c "rowstile:begin" "$T/ag/AGENTS.md")" = 1 ] &&
  ok "... and an AGENTS.md that is there keeps its text, with the section added" || bad "init AGENTS.md added" "$(cat "$T/ag/AGENTS.md")";;
  *) bad "init AGENTS.md added" "$out";; esac

rm -r "$T"
[ -z "${KEEP:-}" ] && { dropdb "$DB"; psql -X -q -d postgres -c "DROP ROLE IF EXISTS authz_devx_other" >/dev/null 2>&1; }
if [ $fails -eq 0 ]; then echo "devx: all passed"; else echo "devx: $fails failed"; exit 1; fi

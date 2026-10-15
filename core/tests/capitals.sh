#!/bin/bash
# capitals.sh: the command over tables named as Prisma names them (tests/prisma_schema.sql, tests/prisma.authz):
# capital letters in the tables' names and the columns', in public. Wherever a table is looked up by its name,
# the name has to be quoted, or Postgres reads "Folder" as folder and finds nothing.
#   PGHOST=... PGUSER=postgres tests/capitals.sh
set -u
cd "$(dirname "$0")/.."
ROOT=$PWD
DB=authz_capitals
DB2=authz_capitals_2
fails=0
PSQL() { psql -X -q -At -v ON_ERROR_STOP=1 -d "$DB" "$@"; }
ok() { echo "ok    $1"; }
bad() { echo "FAIL  $1${2:+: $2}"; fails=$((fails + 1)); }
schema() { PGOPTIONS="-c client_min_messages=error" psql -X -q -v ON_ERROR_STOP=1 -d "$1" -f tests/prisma_schema.sql >/dev/null; }
T=$(mktemp -d)
# runs the command in the project; sets $out (stdout and stderr) and $rc
run() { out=$(cd "$T" && python3 "$ROOT/cli/rowstile_cli.py" "$@" 2>&1); rc=$?; }
as() { PSQL -c "SET authz.user_id = $1" -c "$2"; }
# whether the command's last line says this of the policy ("…policy.authz: unchanged")
is() { case "$out" in *"policy.authz: $1") return 0;; *) return 1;; esac; }

for d in "$DB" "$DB2"; do dropdb --if-exists "$d" 2>/dev/null; createdb "$d" || exit 1; schema "$d" || exit 1; done
mkdir -p "$T/db"
cp tests/prisma.authz "$T/db/policy.authz"
printf 'policy   = "db/policy.authz"\ndatabase = "dbname=%s"\n[migrations]\ntool = "sql"\ndir  = "db/migrations"\n' "$DB" > "$T/rowstile.toml"

echo "-- apply, and what it made is found again"
run apply; [ $rc -eq 0 ] && is applied && ok "apply" || bad "apply" "$out"
run apply; is unchanged && ok "... again: unchanged (its policies and triggers are found by their quoted names)" || bad "apply again" "$out"
run push --development; is unchanged && ok "push: unchanged too" || bad "push" "$out"
[ "$(PSQL -c "SELECT authz.verify()")" = t ] && ok "the inheritance tables are right" || bad "verify"
run test; case "$out" in *"policy tests passed (12 checks)") ok "the policy's tests pass, a named test that writes to the tables among them";; *) bad "test" "$out";; esac

sed 's/^type user = public.User (id int)$/type user = public.User/' tests/prisma.authz > "$T/nokey.authz"
run apply "$T/nokey.authz"
case "$out" in *"public.User.id is integer, not bigint: write its type after the key, (id integer) [AZ602]"*) ok "a key Prisma made an Int: applying says what to write after the key";; *) bad "AZ602" "$out";; esac
[ "$(PSQL -c "SELECT problem FROM authz.lint() WHERE object = 'public.\"TeamMember\"'")" = "app_user may read every row, and the policy reads it for team.member: who is linked to what is readable. Fine where that is no secret, otherwise give it a type and rules" ] &&
  ok "lint says of the link table that the app role reads it in full, and for which relation" || bad "lint, the link table" "$(PSQL -c "SELECT object, problem FROM authz.lint()")"

echo "-- lint and indexes"
[ "$(PSQL -c "SELECT count(*) FROM authz.lint() WHERE severity IN ('error', 'warning')")" = 0 ] && ok "lint: no error, no warning" || bad "lint" "$(PSQL -c "SELECT * FROM authz.lint()")"
[ "$(PSQL -c "SELECT string_agg(object, ' ' ORDER BY object) FROM authz.lint() WHERE problem LIKE '%may read every row%'")" = 'public."Team" public."TeamMember" public."User"' ] &&
  ok "lint names the tables read in full as Postgres writes them (the link table too), and not Prisma's own" || bad "lint, tables read in full" "$(PSQL -c "SELECT object, problem FROM authz.lint()")"
run indexes; [ "$out" = "every lookup the policy makes into the app's tables has an index" ] && ok "indexes: Prisma's indexes are found" || bad "indexes" "$out"
PSQL -c 'DROP INDEX "Note_folderId_idx"'
run indexes --check; case "$out" in *'public.Note'*'folderId'*) [ $rc -eq 1 ] && ok "... and one that is missing is named" || bad "indexes --check exit" "$rc";; *) bad "a missing index" "$out";; esac
PSQL -c 'CREATE INDEX "Note_folderId_idx" ON "Note" ("folderId")'

echo "-- asking, reading and writing as someone"
run who folder 3 view; [ "$out" = 1 ] && ok "who" || bad "who" "$out"
run list --as user:2 folder view; [ "$out" = 4 ] && ok "list" || bad "list" "$out"
run why --as user:2 folder 3 edit; case "$out" in *"would be granted by:"*"share editor on folder 3 with user 2"*"set ownerId of folder 3 to 2"*) ok "why: the shares and the column that would grant it";; *) bad "why" "$out";; esac
as 1 "SELECT authz.share('folder', 1, 'viewer', 'user', 2)" >/dev/null
[ "$(as 2 'SET ROLE app_user; SELECT id FROM "Folder" ORDER BY id' | tr '\n' ' ')" = "1 2 3 4 " ] && ok "a share on the top folder shows what is under it" || bad "rows after a share"
[ "$(as 2 'SET ROLE app_user; SELECT count(*), count(body) FROM "NoteShown" WHERE id IN (1, 2)')" = "2|0" ] && ok "the masked view shows a viewer the notes without their text" || bad "the masked view"
[ "$(PSQL -c "SELECT has_column_privilege('app_user', 'public.\"Note\"', 'body', 'SELECT'), has_column_privilege('app_user', 'public.\"Note\"', 'title', 'SELECT')")" = "f|t" ] &&
  ok "... and the table doesn't give the masked column" || bad "column privileges"
run explain-rule --as user:2 public.Note update 2; case "$out" in *"no   update"*": edit"*) ok "explain-rule: why a viewer may not update";; *) bad "explain-rule" "$out";; esac
run sql --as user:1 'UPDATE "Note" SET "authorId" = 2 WHERE id = 2'
case "$out" in "changing authorId of public.Note 2 needs: nobody"*) ok "a column's rule refuses, naming the column";; *) bad "a column rule" "$out";; esac
out=$(as 2 'SET ROLE app_user; INSERT INTO "Note" (title, "folderId", "authorId") VALUES ($$n$$, 3, 2)' 2>&1)
case "$out" in *"permission denied: user 2 may not insert this row into public.Note"*) ok "a refused insert says who and where";; *) bad "a refused insert" "$out";; esac
out=$(PSQL -c "SELECT added || '|' || removed FROM authz.sync_members('team', '1', 'member', ARRAY['3', '4'])" \
           -c 'SELECT string_agg("userId"::text, $$,$$ ORDER BY "userId") FROM "TeamMember"' \
           -c "SELECT added || '|' || removed FROM authz.sync_members('team', '1', 'member', ARRAY['3'])" 2>&1 | paste -sd' ')
[ "$out" = "1|0 3,4 0|1" ] && ok "group sync writes the link table by its quoted name" || bad "sync_members on TeamMember" "$out"

echo "-- moves"
PSQL -c 'UPDATE "Folder" SET "parentId" = 4 WHERE id = 3'
run who folder 3 view; [ "$(echo "$out" | sort | tr '\n' ' ')" = "1 2 " ] && [ "$(PSQL -c "SELECT authz.verify()")" = t ] && ok "a folder moved under another's: its owner sees it" || bad "after a move" "$out"
run who note 2 view; [ "$(echo "$out" | sort | tr '\n' ' ')" = "1 2 " ] && ok "... and the note in it" || bad "the note after a move" "$out"

echo "-- push and diff"
printf '\n-- a comment\n' >> "$T/db/policy.authz"
run push; is pushed && ok "a comment: pushed, nothing applied whole" || bad "push a comment" "$out"
sed -i 's/^  can view = folder.view$/  can view = folder.view\n  can comment = view/' "$T/db/policy.authz"
run diff; case "$out" in *"note  permission comment  gains"*) ok "diff: who gains the new permission";; *) bad "diff" "$out";; esac
run push; is pushed && [ "$(as 2 "SELECT authz.can('note', 3, 'comment')")" = t ] && ok "a new permission: pushed, and held" || bad "push a permission" "$out"
run apply; is unchanged && ok "apply after it: unchanged" || bad "apply after push" "$out"

echo "-- migrations: a second database takes them, and holds what this one holds"
cp tests/prisma.authz "$T/db/policy.authz"
run push >/dev/null
run migrate; case "$out" in *"the whole policy"*"wrote db/migrations/"*) ok "migrate: the whole policy first";; *) bad "migrate" "$out";; esac
sed -i 's/^  can view = folder.view$/  can view = folder.view\n  can comment = view/' "$T/db/policy.authz"
run migrate --name note_comment; case "$out" in *"+ type note: can comment = view"*"_authz_note_comment.sql"*) ok "... then only the new permission";; *) bad "migrate a permission" "$out";; esac
sed -i "s/^  can view   = edit or viewer or parent.view$/  can view   = edit or viewer or (parent.view and {name <> 'sealed'})/" "$T/db/policy.authz"
run migrate --name sealed; case "$out" in *"_authz_sealed"*) ok "... then a change to what a folder inherits";; *) bad "migrate a tree" "$out";; esac
run push; is pushed || bad "push the last policy" "$out"
PSQL -c "UPDATE \"Folder\" SET name = 'sealed' WHERE id = 2"
applied=0
for f in "$T"/db/migrations/*.sql; do
  psql -X -q -1 -v ON_ERROR_STOP=1 -d "$DB2" -f "$f" >/dev/null 2>"$T/err" || { bad "$(basename "$f")" "$(cat "$T/err")"; break; }
  applied=$((applied + 1))
done
[ "$applied" -ge 3 ] && ok "$applied migration files apply in order" || bad "migrations applied" "$applied"
psql -X -q -At -d "$DB2" -c "SET authz.user_id = 1" -c "SELECT authz.share('folder', 1, 'viewer', 'user', 2)" >/dev/null
psql -X -q -d "$DB2" -c 'UPDATE "Folder" SET "parentId" = 4 WHERE id = 3' -c "UPDATE \"Folder\" SET name = 'sealed' WHERE id = 2"
run snapshot --out "$T/a.snapshot"; a=$rc
run --db "dbname=$DB2" snapshot --out "$T/b.snapshot"
[ $a -eq 0 ] && [ $rc -eq 0 ] && cmp -s "$T/a.snapshot" "$T/b.snapshot" && [ "$(psql -X -q -At -d "$DB2" -c "SELECT authz.verify()")" = t ] &&
  ok "the database that took the migrations answers as the one that was pushed to" || bad "the two databases differ" "$(diff "$T/a.snapshot" "$T/b.snapshot" | head -n 10)"
run who folder 2 view; [ "$out" = 1 ] && ok "... and the sealed folder stops what comes from above" || bad "sealed" "$out"

echo "-- a column the app adds to a masked table"
PSQL -c 'ALTER TABLE "Note" ADD COLUMN "dueAt" date'
run reapply
[ $rc -eq 0 ] && [ "$(PSQL -c "SELECT has_column_privilege('app_user', 'public.\"Note\"', 'dueAt', 'SELECT'), has_column_privilege('app_user', 'public.\"Note\"', 'body', 'SELECT')")" = "t|f" ] &&
  ok "reapply gives the app role the new column, and still not the masked one" || bad "a new column of a masked table" "$out"

echo "-- without the mask, then removed"
sed -i '/^  mask body/d; s/^rules public.Note view public.NoteShown$/rules public.Note/' "$T/db/policy.authz"
run push; is pushed || run apply
[ "$(PSQL -c "SELECT has_column_privilege('app_user', 'public.\"Note\"', 'body', 'SELECT'), to_regclass('public.\"NoteShown\"') IS NULL, (SELECT count(*) FROM authz.masked_tables)")" = "t|t|0" ] &&
  ok "the mask taken out: the column is the app role's again, the view is gone" || bad "without the mask" "$out $(PSQL -c "SELECT * FROM authz.masked_tables")"
run remove --yes
case "$out" in *'"Folder" was governed by the removed policy, and row-level security is still on'*'"Note" was governed'*removed)
  ok "remove says which tables keep row-level security on, as Postgres writes their names";; *) bad "remove" "$out";; esac
[ "$(PSQL -c "SELECT to_regnamespace('authz_gen') IS NULL, (SELECT count(*) FROM pg_policy), (SELECT count(*) FROM pg_trigger WHERE NOT tgisinternal AND tgrelid IN ('public.\"Folder\"'::regclass, 'public.\"Note\"'::regclass, 'public.\"TeamMember\"'::regclass))")" = "t|0|0" ] &&
  ok "... and leaves no policy and no trigger on them" || bad "after remove"

echo "-- a tree across two types, through a link table named with capitals"
# a folder may be filed inside a note (a row of "FolderInNote"), a note sits in a folder: view goes down through
# both types at once, one closure table for the two, kept by triggers on the link table too
DB3=authz_capitals_link
L() { psql -X -q -At -v ON_ERROR_STOP=1 -d "$DB3" "$@"; }
dropdb --if-exists "$DB3" 2>/dev/null; createdb "$DB3" || exit 1
L >/dev/null <<'SQL' || exit 1
CREATE TABLE "User" (id serial PRIMARY KEY);
CREATE TABLE "Folder" (id serial PRIMARY KEY, "ownerId" integer NOT NULL REFERENCES "User");
CREATE TABLE "Note" (id serial PRIMARY KEY, "folderId" integer NOT NULL REFERENCES "Folder");
CREATE TABLE "FolderInNote" (
  "folderId" integer NOT NULL REFERENCES "Folder", "noteId" integer NOT NULL REFERENCES "Note",
  PRIMARY KEY ("folderId", "noteId"));
CREATE INDEX "FolderInNote_noteId_idx" ON "FolderInNote" ("noteId");
CREATE INDEX "Note_folderId_idx" ON "Note" ("folderId");
GRANT SELECT ON "User", "Folder", "Note", "FolderInNote" TO app_user;
INSERT INTO "User" (id) VALUES (1), (2);
INSERT INTO "Folder" (id, "ownerId") VALUES (1, 1), (2, 2);
INSERT INTO "Note" (id, "folderId") VALUES (1, 1), (2, 2);
SQL
cat > "$T/link.authz" <<'EOF'
app role app_user

type user = public.User (id int)

type folder = public.Folder (id int)
  owner : user = ownerId
  in    : note = public.FolderInNote(folderId -> noteId)   -- a folder filed inside a note
  can view = owner or in.view

type note = public.Note (id int)
  folder : folder = folderId
  can view = folder.view
EOF
run --db "dbname=$DB3" apply "$T/link.authz"
case "$out" in *"link.authz: applied") [ "$(L -c "SELECT count(*) FROM pg_trigger WHERE NOT tgisinternal AND tgrelid = 'public.\"FolderInNote\"'::regclass AND tgname LIKE '%tree%'")" -ge 2 ] &&
  ok "apply: the closure table's triggers are on the link table, by its quoted name" || bad "triggers on the link table";; *) bad "apply, a link table named with capitals" "$out";; esac
can_1() { L -c "SET authz.user_id = 1" -c "SELECT authz.can('note', '2', 'view')"; }
[ "$(can_1)" = f ] && ok "ann may not view bo's note" || bad "before the link" "$(can_1)"
L -c 'INSERT INTO "FolderInNote" ("folderId", "noteId") VALUES (2, 1)'
[ "$(can_1)" = t ] && [ "$(L -c "SELECT authz.verify()")" = t ] &&
  ok "... until bo's folder is filed in her note: through her folder, her note, his folder" || bad "a link row added" "$(can_1)"
[ "$(L -c "SELECT count(*) FROM authz.lint() WHERE severity IN ('error', 'warning')")" = 0 ] && ok "... lint: no error, no warning" ||
  bad "lint, the two-type tree" "$(L -c "SELECT * FROM authz.lint() WHERE severity IN ('error', 'warning')")"
L -c 'DELETE FROM "FolderInNote"'
[ "$(can_1)" = f ] && [ "$(L -c "SELECT authz.verify()")" = t ] && ok "... and the link row deleted, the access is gone" || bad "a link row deleted" "$(can_1)"
[ -z "${KEEP:-}" ] && dropdb "$DB3"

rm -rf "$T"
[ -z "${KEEP:-}" ] && dropdb "$DB" && dropdb "$DB2"
if [ $fails -eq 0 ]; then echo "capitals: all passed"; else echo "capitals: $fails failed"; exit 1; fi

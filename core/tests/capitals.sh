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
# a table beside the policy's that it doesn't name, and a view of Folder that runs with its owner's rights: lint finds
# both from the policy's tables, by their quoted names
PSQL -c 'CREATE TABLE "Lookup" (id int)' -c 'CREATE VIEW "FolderView" AS SELECT id FROM "Folder"' \
     -c 'GRANT SELECT ON "Lookup", "FolderView" TO app_user'
got=$(PSQL -c "SELECT string_agg(object || ' ' || severity, ', ' ORDER BY object) FROM authz.lint() WHERE object LIKE '%Lookup%' OR object LIKE '%FolderView%'")
[ "$got" = 'public."FolderView" error, public."Lookup" info' ] &&
  ok "lint: a table beside Folder that no rule names, and a view of Folder that skips its rules" || bad "lint, beside and views" "$got"
PSQL -c 'DROP VIEW "FolderView"' -c 'DROP TABLE "Lookup"'
# the app's own check of its connection finds the tables by their quoted names too
PSQL -c 'ALTER TABLE "Folder" DISABLE ROW LEVEL SECURITY'
got=$(PSQL -c "SET ROLE app_user" -c "SELECT problem FROM authz.connection_check() WHERE problem LIKE 'row-level security%'")
PSQL -c 'ALTER TABLE "Folder" ENABLE ROW LEVEL SECURITY'
[ "$got" = "row-level security is off on public.\"Folder\": the policy's rules don't apply to it" ] &&
  ok "connection_check: a table with rules and row-level security off, named as Postgres writes it" || bad "connection_check" "$got"
run indexes; [ "$out" = "every lookup the policy makes into the app's tables has an index" ] && ok "indexes: Prisma's indexes are found" || bad "indexes" "$out"
PSQL -c 'DROP INDEX "Note_folderId_idx"'
run indexes --check; case "$out" in *'public.Note'*'folderId'*) [ $rc -eq 1 ] && ok "... and one that is missing is named" || bad "indexes --check exit" "$rc";; *) bad "a missing index" "$out";; esac
[ "$(PSQL -c "SELECT count(*) FROM authz.lint() WHERE severity = 'performance' AND object = 'public.\"Note\".folderId'")" = 1 ] &&
  ok "... and lint names it too, its table found by its quoted name" || bad "lint, a missing index" "$(PSQL -c "SELECT object, problem FROM authz.lint() WHERE severity = 'performance'")"
PSQL -c 'CREATE INDEX "Note_folderId_idx" ON "Note" ("folderId")'

echo "-- conditions on a table named with a word SQL reserves (User)"
# a select rule's condition that doesn't run: Postgres gives no position there, so the condition is tried alone on
# its table, named as Postgres writes it ("public"."User" AS "User")
{ cat tests/prisma.authz; printf '\nrules public.User\n  select : {nme is not null}\n'; } > "$T/user_rule.authz"
run apply "$T/user_rule.authz"
case "$out" in "policy line $(grep -c '' "$T/user_rule.authz"): the condition {nme is not null} doesn't run: column \"nme\" does not exist [AZ613]"*)
  [ $rc -eq 1 ] && ok "a select rule's condition on User that doesn't run: refused with its line" || bad "a select rule on User: exit" "$rc";;
  *) bad "a select rule's condition on User that doesn't run" "$out";; esac
# a bare column name a subquery's table takes: Postgres is asked which columns the condition reads from User's rows
sed 's/^type user = public.User (id int)$/type user = public.User (id int)\n  can see = {exists (select 1 from public."Folder" f where f."ownerId" = id)}/' tests/prisma.authz > "$T/user_captured.authz"
run apply "$T/user_captured.authz"
case "$out" in *'the condition {exists (select 1 from public."Folder" f where f."ownerId" = id)} names id, a column of public.User'"'"'s rows, but reads it from another table the condition names'*"for the row's, write this.id"*)
  [ $rc -eq 0 ] && ok "... and one with a bare id that Folder takes: applied, with the warning" || bad "the captured id on User: exit" "$rc";;
  *) bad "the captured id on User" "$out";; esac
run apply; is applied || bad "applying the policy again" "$out"

echo "-- asking, reading and writing as someone"
run who folder 3 view; [ "$out" = 1 ] && ok "who" || bad "who" "$out"
run list --as user:2 folder view; [ "$out" = 4 ] && ok "list" || bad "list" "$out"
run why --as user:2 folder 3 edit; case "$out" in *"would be granted by:"*"share editor on folder 3 with user 2"*"set ownerId of folder 3 to 2"*) ok "why: the shares and the column that would grant it";; *) bad "why" "$out";; esac
run plans --as user:1
case "$out" in *failed*) bad "plans" "$out";; "as user:1:"$'\n'"  public.Folder: "[0-9]*" ms"*$'\n'"  public.Note: "[0-9]*" ms"*) ok "plans: each table read as the app, by its quoted name";; *) bad "plans" "$out";; esac
as 1 "SELECT authz.share('folder', 1, 'viewer', 'user', 2)" >/dev/null
[ "$(as 2 'SET ROLE app_user; SELECT id FROM "Folder" ORDER BY id' | tr '\n' ' ')" = "1 2 3 4 " ] && ok "a share on the top folder shows what is under it" || bad "rows after a share"
[ "$(as 2 'SET ROLE app_user; SELECT count(*), count(body) FROM "NoteShown" WHERE id IN (1, 2)')" = "2|0" ] && ok "the masked view shows a viewer the notes without their text" || bad "the masked view"
[ "$(PSQL -c "SELECT has_column_privilege('app_user', 'public.\"Note\"', 'body', 'SELECT'), has_column_privilege('app_user', 'public.\"Note\"', 'title', 'SELECT')")" = "f|t" ] &&
  ok "... and the table doesn't give the masked column" || bad "column privileges"
run explain-rule --as user:2 public.Note update 2; case "$out" in *"no   update"*": edit"*) ok "explain-rule: why a viewer may not update";; *) bad "explain-rule" "$out";; esac
run explain-rule --as user:2 public.Note insert --row '{"folderId": 3, "authorId": 2}'
case "$out" in *"no   insert : folder.edit and author"*) ok "... and why one may not insert this row: the row read as a Note";; *) bad "explain-rule insert" "$out";; esac
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
# a table made since that inherits from a table with rules (named with capitals): apply sees it, so applies again
PSQL -c 'CREATE TABLE "FolderArchive" () INHERITS ("Folder")'
run apply; is applied && [ "$(PSQL -c "SELECT relrowsecurity FROM pg_class WHERE oid = '\"FolderArchive\"'::regclass")" = t ] &&
  ok "... until a table inherits from Folder: applied again, its rows under row-level security" || bad "apply after a child table" "$out"
PSQL -c 'DROP TABLE "FolderArchive"'

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
PSQL -c 'ALTER TABLE "Note" RENAME COLUMN "dueAt" TO "dueOn"'
run reapply
[ $rc -eq 0 ] && [ "$(PSQL -c "SELECT string_agg(attname, ',') FROM pg_attribute WHERE attrelid = 'public.\"NoteShown\"'::regclass AND attname LIKE 'due%'")" = dueOn ] &&
  ok "... and a column renamed: the masked view, which can't rename one in place, is made anew" || bad "a column renamed under a masked view" "$out"
# something of the app's built on the masked view: it can't be made anew, and applying says so, naming it
PSQL -c 'CREATE VIEW "NoteTitles" AS SELECT id, title FROM "NoteShown"' -c 'ALTER TABLE "Note" RENAME COLUMN "dueOn" TO "dueBy"'
run reapply
case "$out" in *'the masked view public.NoteShown can'"'"'t be replaced in place'*'[AZ617]'*'NoteTitles'*) [ $rc -ne 0 ] &&
  ok "... unless something is built on it: refused, naming what" || bad "AZ617 on NoteShown: rc" "$rc";;
  *) bad "a column renamed under a masked view something is built on" "$out";; esac
PSQL -c 'DROP VIEW "NoteTitles"'
run reapply; [ $rc -eq 0 ] || bad "reapply after the view built on it is gone" "$out"

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
# a note moved by its column ("folderId"): the trigger that sees the move names the column quoted
L -c 'UPDATE "Note" SET "folderId" = 1 WHERE id = 2' >/dev/null
[ "$(can_1)" = t ] && [ "$(L -c "SELECT authz.verify()")" = t ] && ok "... and bo's note moved into her folder by its column: hers to view" ||
  bad "a note moved by its column" "$(can_1)"
L -c 'UPDATE "Note" SET "folderId" = 2 WHERE id = 2' >/dev/null
# a condition on the tree's links that reads another table (User): what watches that table is found by its quoted name
sed 's/^  can view = owner or in.view$/  can view = owner or (in.view and {exists (select 1 from public."User" u where u.id = this."ownerId")})/' \
  "$T/link.authz" > "$T/link_reads.authz"
run --db "dbname=$DB3" apply "$T/link_reads.authz"
case "$out" in *"link_reads.authz: applied") [ "$(L -c "SELECT authz.verify()")" = t ] &&
  ok "a condition on the links that reads another table: applied, the tree right" || bad "verify, a condition that reads User";;
  *) bad "apply, a condition on the links that reads User" "$out";; esac
# what those conditions gave is kept beside the tree, and verify() compares it too: a row of it missing is found
cache=$(L -c "SELECT relname FROM pg_class WHERE relnamespace = 'authz_int'::regnamespace AND relname LIKE '%\_cond\_cache'")
[ "$(L -c "BEGIN" -c "DELETE FROM authz_int.\"$cache\" WHERE ctid = (SELECT ctid FROM authz_int.\"$cache\" LIMIT 1)" \
  -c "SELECT authz.verify()" -c "ROLLBACK")" = f ] && ok "... and verify() finds a condition's kept answer missing ($cache)" ||
  bad "verify, the kept conditions" "$cache"

echo "-- types named with capitals: explain finds their views by their quoted names"
cat > "$T/types.authz" <<'EOF'
app role app_user

type user = public.User (id int)

type Folder = public.Folder (id int)
  owner : user = ownerId
  can view = owner

type Note = public.Note (id int)
  folder : Folder       = folderId
  keeper : Folder#owner = folderId   -- a column naming a group: the owners of the note's folder
  can view = folder.view
  can keep = keeper
EOF
run --db "dbname=$DB3" apply "$T/types.authz"
case "$out" in *"types.authz: applied") ok "apply: types named with capitals";; *) bad "apply, types named with capitals" "$out";; esac
got=$(L -c "SELECT string_agg(e, '|' ORDER BY n) FROM authz.explain('Note', '1', 'view', '1') WITH ORDINALITY x(e, n)")
[ "$got" = "yes  user 1 holds view on Note 1|  Note.view = folder.view|  yes  folder.view|    yes  folder is Folder 1, which has view|      Folder.view = owner|      yes  owner|        yes  owner: ownerId is you" ] &&
  ok "explain follows a relation to a type named with capitals" || bad "explain through folder.view" "$got"
got=$(L -c "SELECT string_agg(e, '|' ORDER BY n) FROM authz.explain('Note', '1', 'keep', '1') WITH ORDINALITY x(e, n)")
[ "$got" = "yes  user 1 holds keep on Note 1|  Note.keep = keeper|  yes  keeper|    yes  keeper: folderId is Folder 1, and you are owner there|      yes  owner: ownerId is you" ] &&
  ok "... and a column naming the group of one" || bad "explain through Folder#owner" "$got"
[ -z "${KEEP:-}" ] && dropdb "$DB3"

echo "-- custom roles of the org a folder is in, by a column or a link table; a type named with a capital"
# whose roles count on a folder is read from the folder's table and from the link table, by their quoted names; a
# folder filed inside another through a link table checks the one above with the type's own function, by its name
DB4=authz_capitals_roles
R() { psql -X -q -At -v ON_ERROR_STOP=1 -d "$DB4" "$@"; }
dropdb --if-exists "$DB4" 2>/dev/null; createdb "$DB4" || exit 1
R >/dev/null <<'SQL' || exit 1
CREATE TABLE "User" (id serial PRIMARY KEY);
CREATE TABLE "Org" (id serial PRIMARY KEY, "adminId" integer NOT NULL REFERENCES "User");
CREATE TABLE "Folder" (id serial PRIMARY KEY, "ownerId" integer NOT NULL REFERENCES "User", "orgId" integer REFERENCES "Org");
CREATE TABLE "FolderOrg" (
  "folderId" integer NOT NULL REFERENCES "Folder", "orgId" integer NOT NULL REFERENCES "Org",
  PRIMARY KEY ("folderId", "orgId"));
CREATE TABLE "FolderIn" (
  "folderId" integer NOT NULL REFERENCES "Folder", "parentId" integer NOT NULL REFERENCES "Folder",
  PRIMARY KEY ("folderId", "parentId"));
GRANT SELECT ON "User", "Org", "Folder", "FolderOrg", "FolderIn" TO app_user;
INSERT INTO "User" (id) VALUES (1), (2), (3), (4);
INSERT INTO "Org" (id, "adminId") VALUES (1, 1), (2, 1);
INSERT INTO "Folder" (id, "ownerId", "orgId") VALUES (1, 4, 1), (2, 4, NULL), (3, 4, NULL);
INSERT INTO "FolderIn" VALUES (2, 1);
INSERT INTO "FolderOrg" VALUES (3, 2);
SQL
cat > "$T/roles.authz" <<'EOF'
app role app_user

type user = public.User (id int)

type org = public.Org (id int)
  admin : user = adminId
  can manage_roles = admin

type Folder = public.Folder (id int)
  owner  : user   = ownerId
  org    : org    = orgId
  org    : org    = public.FolderOrg(folderId -> orgId)
  parent : Folder = public.FolderIn(folderId -> parentId)
  roles  : user from org
  can share = owner or org.admin
  can view  = owner or org.admin or roles or parent.view
EOF
run --db "dbname=$DB4" apply "$T/roles.authz"
case "$out" in *"roles.authz: applied") ok "apply: roles from an org named by a column and by a link table";; *) bad "apply, roles from a column and a link table" "$out";; esac
R -c "SET authz.user_id = 1" -c "SELECT authz.create_role('org', 1, 'Folder', 'reader', ARRAY['view'])" \
  -c "SELECT authz.create_role('org', 2, 'Folder', 'reader', ARRAY['view'])" >/dev/null || bad "create the roles"
R -c "SET authz.user_id = 1" \
  -c "SELECT authz.share('Folder', 1, 'role:' || (SELECT id FROM authz.roles WHERE owner_id = '1'), 'user', 2)" \
  -c "SELECT authz.share('Folder', 3, 'role:' || (SELECT id FROM authz.roles WHERE owner_id = '2'), 'user', 3)" >/dev/null ||
  bad "give the roles"
views() { R -c "SET authz.user_id = $1" -c "SELECT string_agg(f::text || ':' || authz.can('Folder', f, 'view'), ' ' ORDER BY f) FROM generate_series(1, 3) f"; }
[ "$(views 2)" = "1:true 2:true 3:false" ] &&
  ok "a role of the org in the folder's column counts there, and in the folder filed inside it" || bad "a role through the column" "$(views 2)"
[ "$(views 3)" = "1:false 2:false 3:true" ] &&
  ok "a role of the org the link table puts a folder in counts there" || bad "a role through the link table" "$(views 3)"
# what reads the tree of folders filed in folders, Folder__parent__tree, by its quoted name
run --db "dbname=$DB4" who Folder 2 view
[ "$(echo "$out" | sort | tr '\n' ' ')" = "1 2 4 " ] && ok "who: through the tree of a type named with a capital" || bad "who on Folder" "$out"
tree() { R -c "SELECT 'authz_int.\"Folder__parent__tree\"'::regclass::oid"; }
before=$(tree)
sed 's/^  can share = owner or org.admin$/  can share = owner or org.admin\n  can look  = owner/' "$T/roles.authz" > "$T/roles_look.authz"
run --db "dbname=$DB4" apply "$T/roles_look.authz"
case "$out" in *"roles_look.authz: applied") [ "$(tree)" = "$before" ] && ok "a permission added: the tree is kept, the same table" ||
  bad "the tree kept" "$before then $(tree)";; *) bad "apply, a permission added" "$out";; esac
# the link table made anew between applies: the tree is built again, even with the same definition
R >/dev/null <<'SQL'
SET client_min_messages = warning;
ALTER TABLE "FolderIn" RENAME TO "FolderInOld";
CREATE TABLE "FolderIn" (LIKE "FolderInOld" INCLUDING ALL);
INSERT INTO "FolderIn" SELECT * FROM "FolderInOld";
DROP TABLE "FolderInOld" CASCADE;
GRANT SELECT ON "FolderIn" TO app_user;
SQL
before=$(tree)
run --db "dbname=$DB4" apply "$T/roles_look.authz" --force
[ "$(tree)" != "$before" ] && [ "$(R -c "SELECT authz.verify()")" = t ] && ok "... and the link table made anew: the tree is built again" ||
  bad "the tree after its table was made anew" "$out"
run --db "dbname=$DB4" reapply --force
[ $rc -eq 0 ] && [ "$(views 2)" = "1:true 2:true 3:false" ] && [ "$(R -c "SELECT authz.verify()")" = t ] &&
  ok "reapply --force computes the tree again, by its quoted name" || bad "reapply --force" "$out"
# teams in teams, named with a capital: explain says which sub-team a member is in
R >/dev/null <<'SQL' || bad "the teams"
CREATE TABLE "Team" (id serial PRIMARY KEY, "parentId" integer REFERENCES "Team");
CREATE TABLE "TeamMember" ("teamId" integer REFERENCES "Team", "userId" integer REFERENCES "User", PRIMARY KEY ("teamId", "userId"));
GRANT SELECT ON "Team", "TeamMember" TO app_user;
INSERT INTO "Team" (id, "parentId") VALUES (1, NULL), (2, 1);
INSERT INTO "TeamMember" VALUES (2, 2);
CREATE TABLE "FolderBacking" ("folderId" integer REFERENCES "Folder", "backerType" text, "backerId" integer);
GRANT SELECT ON "FolderBacking" TO app_user;
SQL
{ sed 's/^  can view  = owner or org.admin or roles or parent.view$/  viewer : Team#member shared by share\n  can see   = owner or viewer or backer\n  can view  = owner or org.admin or roles or viewer or parent.view/' "$T/roles_look.authz"
  printf '\ntype Team = public.Team (id int)\n  member : user        = public.TeamMember(teamId -> userId)\n  member : Team#member = public.Team(parentId -> id)\n'
} | sed 's/^  viewer : Team#member shared by share$/&\n  backer : user, Team  = public.FolderBacking(folderId -> (backerType, backerId))/' > "$T/teams.authz"
run --db "dbname=$DB4" apply "$T/teams.authz"; case "$out" in *"teams.authz: applied") ;; *) bad "apply, teams" "$out";; esac
R -c "SET authz.user_id = 4" -c "SELECT authz.share('Folder', 3, 'viewer', 'Team', 1, 'member')" >/dev/null || bad "share with a team"
got=$(R -c "SELECT string_agg(btrim(e), '|') FROM authz.explain('Folder', '3', 'see', '2') e WHERE e LIKE '%through Team%'")
[ "$got" = "yes  through Team 2, whose member count here too" ] && ok "explain: a member of a sub-team, through Team 2" || bad "explain through a sub-team" "$got"
# a link table naming users or teams by a pair of columns: each row is in the audit trail, its subject read by its column
# (one naming a type the policy hasn't too: it gives nothing, and the trail still says what it names)
R -c "INSERT INTO \"FolderBacking\" VALUES (3, 'user', 2), (3, 'Team', 1), (3, 'robot', 9)" >/dev/null || bad "rows of a link table with a type column"
[ "$(R -c "SELECT string_agg(subject_type || ':' || coalesce(subject_id, '?'), ' ' ORDER BY subject_type COLLATE \"C\") FROM authz.audit WHERE action = 'relate' AND relation = 'backer'")" = "Team:1 robot:9 user:2" ] &&
  ok "... the audit trail names who each row of a link table with a type column names" || bad "the audit of a link table with a type column"
# two types whose names differ only in case, each a tree: each has functions of its own
{ cat "$T/teams.authz"
  printf '\ntype folder = public.Team (id int)\n  member : user   = public.TeamMember(teamId -> userId)\n  parent : folder = parentId\n  can view = member or parent.view\n'
} > "$T/cases.authz"
run --db "dbname=$DB4" apply "$T/cases.authz"
case "$out" in *"cases.authz: applied")
  run --db "dbname=$DB4" who folder 2 view; a=$out; run --db "dbname=$DB4" who Folder 2 view
  [ "$a" = 2 ] && [ "$(echo "$out" | sort | tr '\n' ' ')" = "1 2 4 " ] && ok "folder and Folder, each its own tree: who asks each" ||
    bad "who on folder and Folder" "$a / $out";;
  *) bad "apply, folder and Folder" "$out";; esac
# invariants, a principal type and a team linked through a table, each named with a capital: who, explain, the
# invariants' list of everyone, the principal signed in and the benchmark's people find them by their quoted names
R >/dev/null <<'SQL' || bad "the bots and the folders' teams"
CREATE TABLE "Bot" (id serial PRIMARY KEY);
CREATE TABLE "FolderTeam" ("folderId" integer REFERENCES "Folder", "teamId" integer REFERENCES "Team");
GRANT SELECT ON "Bot", "FolderTeam" TO app_user;
INSERT INTO "Bot" (id) VALUES (1);
INSERT INTO "FolderTeam" VALUES (3, 1);
CREATE TABLE "Log" (id integer PRIMARY KEY, "ownerId" integer REFERENCES "User") PARTITION BY RANGE (id);
CREATE TABLE "LogOld" PARTITION OF "Log" FOR VALUES FROM (0) TO (100);
GRANT SELECT ON "Log", "LogOld" TO app_user;
SQL
{ sed 's/^  backer : user, Team .*$/&\n  crew   : Team#member  = public.FolderTeam(folderId -> teamId)\n  can muster = crew/' "$T/teams.authz"
  printf '\ntype Bot = public.Bot (id int) principal\n\ntype Log = public.Log (id int)\n  owner : user = ownerId\n  can view = owner\n'
  printf '\nrules public.Log\n  select : view\n\ninvariants\n  never Folder: look and not share\n'
} > "$T/more.authz"
run --db "dbname=$DB4" apply "$T/more.authz"
case "$out" in *"more.authz: applied")
  run --db "dbname=$DB4" who Folder 3 muster
  [ "$out" = 2 ] && ok "who: through a team a link table names, and the teams in it" || bad "who through FolderTeam" "$out"
  got=$(R -c "SELECT string_agg(btrim(e), '|') FROM authz.explain('Folder', '3', 'muster', '2') e WHERE e LIKE '%through Team%'")
  [ "$got" = "yes  through Team 2, whose member count here too" ] && ok "explain: through the team the link table names, and the team in it" ||
    bad "explain through FolderTeam" "$got"
  [ "$(R -c "SELECT count(*) FROM authz.check_invariants()")" = 0 ] && ok "the invariants, asked as every user and bot: kept" ||
    bad "check_invariants" "$(R -c "SELECT * FROM authz.check_invariants()" 2>&1)"
  got=$(R -c "SELECT authz.act_as('Bot', '1'); SELECT principal_type || ':' || principal_id FROM authz.principal()" 2>&1 | tail -n 1)
  [ "$got" = "Bot:1" ] && ok "a Bot signed in is who authz.principal() says" || bad "authz.principal(), a Bot" "$got"
  run --db "dbname=$DB4" bench --people 1 --rounds 1
  [ $rc -eq 0 ] && ok "bench: its people read from tables named with capitals" || bad "bench" "$out"
  # a partition made since, of a table with rules named with a capital: apply finds it without row-level security
  R -c 'CREATE TABLE "LogNew" PARTITION OF "Log" FOR VALUES FROM (100) TO (200)' -c 'GRANT SELECT ON "LogNew" TO app_user' >/dev/null
  run --db "dbname=$DB4" apply "$T/more.authz"
  case "$out" in *"more.authz: applied") [ "$(R -c "SELECT relrowsecurity FROM pg_class WHERE oid = '\"LogNew\"'::regclass")" = t ] &&
    ok "a partition of Log made since: applied again, its rows under row-level security" || bad "the new partition's row-level security";;
    *) bad "apply after a partition of Log was made" "$out";; esac;;
  *) bad "apply, the policy with invariants and bots" "$out";; esac
[ -z "${KEEP:-}" ] && dropdb "$DB4"

rm -rf "$T"
[ -z "${KEEP:-}" ] && dropdb "$DB" && dropdb "$DB2"
if [ $fails -eq 0 ]; then echo "capitals: all passed"; else echo "capitals: $fails failed"; exit 1; fi

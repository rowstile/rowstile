#!/bin/bash
# masks.sh: masked columns stay masked: at apply time, in lint (later GRANTs), and in --diff.
#   PGHOST=... PGPORT=... PGUSER=authz_owner tests/masks.sh [database]
set -u
cd "$(dirname "$0")/.."
DB=${1:-authz_masks}
fails=0
PSQL() { psql -X -q -At -v ON_ERROR_STOP=1 -d "$DB" "$@"; }
ok() { echo "ok    $1"; }
bad() { echo "FAIL  $1${2:+: $2}"; fails=$((fails + 1)); }
T=$(mktemp -d)
# whatever way the suite ends: its database, its role, its files
cleanup() {
  [ -n "${KEEP:-}" ] || dropdb --force --if-exists "$DB" 2>/dev/null
  psql -X -q -d postgres -c "DROP ROLE IF EXISTS authz_masks_reader" >/dev/null 2>&1
  rm -rf "$T"
}
trap cleanup EXIT
apply() { PGOPTIONS="-c client_min_messages=error" psql -X -q -v ON_ERROR_STOP=1 -d "$DB" -f "$1" 2>&1 >/dev/null; }
fresh() {
  dropdb --if-exists "$DB" 2>/dev/null; createdb "$DB" || exit 1
  PGOPTIONS="-c client_min_messages=error" psql -X -q -v ON_ERROR_STOP=1 -d "$DB" -f tests/multi_schema.sql >/dev/null || exit 1
  PSQL -c "INSERT INTO mt.users VALUES ('00000000-0000-4000-8000-000000000001'), ('00000000-0000-4000-8000-000000000002')" \
       -c "INSERT INTO mt.orgs VALUES (1)" \
       -c "INSERT INTO mt.projects (id, org_id, lead_id) VALUES (1, 1, '00000000-0000-4000-8000-000000000001')" \
       -c "INSERT INTO mt.docs VALUES ('10000000-0000-4000-8000-000000000001', 'project', 1, NULL, 'secret text')" >/dev/null
}
python3 compile_policy.py tests/multi.authz > $T/masks.sql || exit 1
sed '/mask body/d; s/ view mt.docs_visible//' tests/multi.authz > $T/nomask.authz
python3 compile_policy.py $T/nomask.authz > $T/nomask.sql || exit 1

echo "-- applying"
fresh
PSQL -c "GRANT SELECT ON mt.docs TO PUBLIC" >/dev/null
out=$(apply $T/masks.sql)
case "$out" in *"could still read masked columns of mt.docs"*) ok "a mask PUBLIC could read around is refused";;
  *) bad "apply with PUBLIC access" "$out";; esac
PSQL -c "REVOKE SELECT ON mt.docs FROM PUBLIC" >/dev/null
out=$(apply $T/masks.sql); [ -z "$out" ] && ok "... and applies once that is revoked" || bad "apply" "$out"
# a view of the app's own, with a comment of its own: applying again leaves it (only the masked views it made are made again)
PSQL -c "CREATE VIEW mt.org_ids AS SELECT id FROM mt.orgs" -c "COMMENT ON VIEW mt.org_ids IS 'the app''s own view'" >/dev/null
out=$(apply $T/masks.sql)
[ -z "$out" ] && [ "$(PSQL -c "SELECT count(*) FROM mt.org_ids")" = 1 ] && ok "... and applied again, it leaves the app's own commented view as it was" ||
  bad "the app's own view after apply" "$out"
PSQL -c "DROP VIEW mt.org_ids" >/dev/null
got=$(PSQL -c "SELECT string_agg(attname, ',' ORDER BY attnum) FROM pg_attribute WHERE attrelid = 'mt.docs_visible'::regclass")
[ "$got" = "id,container_type,container_id,author_id,body" ] && ok "the masked view has the table's columns, in their order, and no others" ||
  bad "the masked view's columns" "$got"
[ "$(PSQL -c "SELECT has_column_privilege('app_user', 'mt.docs', 'body', 'SELECT')")" = "f" ] &&
  ok "the app role cannot read the masked column from the table" || bad "column privilege"
[ "$(PSQL -c "SELECT has_column_privilege('app_user', 'mt.docs', 'ctid', 'SELECT') OR has_column_privilege('app_user', 'mt.docs', 'xmin', 'SELECT')")" = "f" ] &&
  ok "... nor Postgres's own columns of it (only the table's own columns are given back)" || bad "system columns given"

echo "-- later grants: lint reports them, and applying again takes them back (no event triggers)"
[ "$(PSQL -c "SELECT count(*) FROM authz.lint() WHERE object = 'mt.docs.body'")" = "0" ] && ok "lint: nothing to report on the mask" || bad "lint on a clean mask"
for g in "GRANT SELECT ON mt.docs TO app_user" "GRANT SELECT ON ALL TABLES IN SCHEMA mt TO app_user"; do
  PSQL -c "$g" >/dev/null
  [ "$(PSQL -c "SELECT severity FROM authz.lint() WHERE object = 'mt.docs.body'")" = "error" ] &&
    ok "lint reports: $g" || bad "lint misses: $g"
  apply $T/masks.sql >/dev/null
  [ "$(PSQL -c "SELECT has_column_privilege('app_user', 'mt.docs', 'body', 'SELECT')")" = "f" ] &&
    ok "... and applying again takes it back" || bad "re-apply did not revoke: $g"
done
PSQL -c "GRANT SELECT (body) ON mt.docs TO PUBLIC" >/dev/null
[ "$(PSQL -c "SELECT severity FROM authz.lint() WHERE object = 'mt.docs.body'")" = "error" ] &&
  ok "lint reports: GRANT SELECT (body) ON mt.docs TO PUBLIC" || bad "lint misses the PUBLIC grant"
out=$(apply $T/masks.sql)
case "$out" in *"could still read masked columns of mt.docs"*) ok "... and applying refuses until it is revoked";; *) bad "apply with PUBLIC column grant" "$out";; esac
PSQL -c "REVOKE SELECT (body) ON mt.docs FROM PUBLIC" >/dev/null
out=$(PSQL -c "GRANT SELECT (id, author_id) ON mt.docs TO app_user" 2>&1); [ -z "$out" ] && ok "granting other columns is fine" || bad "grant other columns" "$out"
[ "$(PSQL -c "SELECT count(*) FROM authz.lint() WHERE object = 'mt.docs.body'")" = "0" ] && ok "... and lint has nothing to say about it" || bad "lint after other columns"
PSQL -c "CREATE ROLE authz_masks_reader" >/dev/null 2>&1
PSQL -c "GRANT SELECT ON mt.docs TO authz_masks_reader" -c "GRANT authz_masks_reader TO app_user" >/dev/null
[ "$(PSQL -c "SELECT severity FROM authz.lint() WHERE object = 'mt.docs.body'")" = "error" ] &&
  ok "lint reports a column readable through a role membership" || bad "lint misses the membership"
out=$(apply $T/masks.sql)
case "$out" in *"could still read masked columns of mt.docs"*) ok "... and applying refuses it, as for PUBLIC";; *) bad "apply with the column readable through a role" "$out";; esac
PSQL -c "REVOKE authz_masks_reader FROM app_user" -c "DROP OWNED BY authz_masks_reader" -c "DROP ROLE authz_masks_reader" >/dev/null
PSQL -c "ALTER TABLE mt.docs RENAME COLUMN body TO body2" >/dev/null 2>&1
out=$(PSQL -c "SELECT count(*) FROM authz.lint()" 2>&1); case "$out" in [0-9]*) ok "a renamed masked column doesn't break lint";; *) bad "lint after rename" "$out";; esac
PSQL -c "ALTER TABLE mt.docs RENAME COLUMN body2 TO body" >/dev/null

echo "-- previewing mask changes"
out=$(python3 compile_policy.py $T/nomask.authz --diff | PGOPTIONS="-c client_min_messages=error" psql -X -q -d "$DB" 2>&1)
case "$out" in *"gains  | 00000000-0000-4000-8000-000000000001 | mt.docs | column body readable"*) bad "the lead could already read the body" "$out";;
  *"== Details (first "*) ok "the project lead (who could read the text) gains nothing";;
  *) bad "the preview without the mask" "$out";; esac
PSQL -c "INSERT INTO authz.shares (object_type, object_id, relation, subject_type, subject_id) VALUES ('project', '1', 'viewer', 'user', '00000000-0000-4000-8000-000000000002')" >/dev/null
out=$(python3 compile_policy.py $T/nomask.authz --diff | PGOPTIONS="-c client_min_messages=error" psql -X -q -d "$DB" 2>&1)
case "$out" in *"gains  | 00000000-0000-4000-8000-000000000002 | mt.docs | column body readable"*) ok "removing the mask: a viewer gains the text";;
  *) bad "diff without the mask" "$out";; esac
# a mask of a column the table doesn't have (a typo): the preview names the policy's line, as applying does
sed 's/^  mask body : edit /  mask bodyx : edit /' tests/multi.authz > $T/masks_typo.authz
out=$(python3 cli/rowstile_cli.py --db "dbname=$DB" diff $T/masks_typo.authz 2>&1); rc=$?
case "$out" in *"line "*": column bodyx not found in mt.docs [AZ601]"*) [ $rc -eq 1 ] && ok "previewing a mask of a column the table doesn't have names its line" || bad "diff of a typo'd mask: exit" "$rc";;
  *) bad "diff of a typo'd mask" "$out";; esac

echo "-- why a write is refused, on a table whose column the app role can't read"
DOC=10000000-0000-4000-8000-000000000001
why() { PSQL -c "SET ROLE app_user" -c "SET authz.user_id = '00000000-0000-4000-8000-00000000000$1'" -c "$2" 2>&1 | tail -n 1; }
PSQL -c "INSERT INTO mt.users VALUES ('00000000-0000-4000-8000-000000000003')" >/dev/null
out=$(why 1 "SELECT (authz.explain_rule('mt.docs', 'update', '$DOC', '{\"body\": \"x\"}'))[1]")
case "$out" in "yes  update : edit"*) ok "explain_rule answers the lead, who may edit";; *) bad "explain_rule on a masked table, as the lead" "$out";; esac
out=$(why 2 "SELECT (authz.explain_rule('mt.docs', 'update', '$DOC', '{\"body\": \"x\"}'))[1]")
case "$out" in "no   update : edit"*) ok "... a viewer, who may not, with the rule";; *) bad "explain_rule on a masked table, as a viewer" "$out";; esac
out=$(why 3 "SELECT authz.explain_rule('mt.docs', 'update', '$DOC') IS NULL")
[ "$out" = "t" ] && ok "... and someone who can't see the row gets NULL" || bad "explain_rule on a masked table, a hidden row" "$out"
out=$(why 2 "SELECT (authz.explain_rule('mt.docs', 'delete', '$DOC'))[1]")
case "$out" in "no   there is no delete rule"*) ok "... a delete too";; *) bad "explain_rule delete on a masked table" "$out";; esac
out=$(why 2 "SELECT r_old.body IS NULL FROM (SELECT (jsonb_populate_record(NULL::mt.docs, to_jsonb(x))).* FROM mt.docs_visible x WHERE x.id = '$DOC') r_old")
[ "$out" = "t" ] && ok "... judged on the row as the viewer may read it: the masked column is NULL" || bad "the row explain_rule reads" "$out"

out=$(apply $T/nomask.sql); [ -z "$out" ] && ok "the version without masks applies" || bad "apply without masks" "$out"
[ "$(PSQL -c "SELECT has_table_privilege('app_user', 'mt.docs', 'SELECT')")|$(PSQL -c "SELECT to_regclass('mt.docs_visible') IS NULL")" = "t|t" ] &&
  ok "... gives back table-wide SELECT and drops the view" || bad "unmasking"
out=$(python3 compile_policy.py tests/multi.authz --diff | PGOPTIONS="-c client_min_messages=error" psql -X -q -d "$DB" 2>&1)
case "$out" in *"loses  | 00000000-0000-4000-8000-000000000002 | mt.docs | column body readable"*) ok "adding the mask back: the viewer would lose the text";;
  *) bad "diff adding the mask" "$out";; esac
case "$out" in *"00000000-0000-4000-8000-000000000001 | mt.docs | column body"*) bad "the lead should keep the text" "$out";;
  *) ok "... and the lead keeps it";; esac

echo "-- two masked columns, two masked tables"
# either masked column readable around the view is refused, not only both
sed 's/^  mask body : edit /  mask author_id : edit\n  mask body : edit /' tests/multi.authz > $T/masks_two.authz
grep -q "mask author_id" $T/masks_two.authz || bad "the variant with two masked columns"
python3 compile_policy.py $T/masks_two.authz > $T/masks_two.sql || exit 1
fresh
PSQL -c "GRANT SELECT (author_id) ON mt.docs TO PUBLIC" >/dev/null
out=$(apply $T/masks_two.sql)
case "$out" in *"could still read masked columns of mt.docs"*) ok "one of two masked columns readable by PUBLIC: refused";; *) bad "one of two masked columns readable" "$out";; esac
PSQL -c "REVOKE SELECT (author_id) ON mt.docs FROM PUBLIC" >/dev/null
# the projects masked too, then not: they get back the SELECT they had, and the docs stay masked
{ cat tests/multi.authz; printf '\nrules mt.projects view mt.projects_visible\n  select : view\n  mask lead_id : edit\n'; } > $T/masks_projects.authz
python3 compile_policy.py $T/masks_projects.authz > $T/masks_projects.sql || exit 1
out=$(apply $T/masks_projects.sql); [ -z "$out" ] || bad "apply, two masked tables" "$out"
[ "$(PSQL -c "SELECT has_table_privilege('app_user', 'mt.projects', 'SELECT'), has_table_privilege('app_user', 'mt.docs', 'SELECT')")" = "f|f" ] ||
  bad "two masked tables: table-wide SELECT left"
out=$(apply $T/masks.sql); [ -z "$out" ] || bad "apply, the projects no longer masked" "$out"
[ "$(PSQL -c "SELECT has_table_privilege('app_user', 'mt.projects', 'SELECT'), has_table_privilege('app_user', 'mt.docs', 'SELECT')")" = "t|f" ] &&
  ok "a table no longer masked gets its SELECT back; the one still masked doesn't" || bad "unmasking one of two tables"

echo "-- a mask that goes leaves the app role's privileges as they were"
# the app role reads mt.docs column by column (body among them): the masks take body's SELECT of its own away, and
# give it back when they go, by applying, by a migration and by rowstile remove
acl() { PSQL -c "SELECT (SELECT relacl::text FROM pg_class WHERE oid = 'mt.docs'::regclass) || ' ' || string_agg(attname || '=' || coalesce(attacl::text, ''), ' ' ORDER BY attnum)
  FROM pg_attribute WHERE attrelid = 'mt.docs'::regclass AND attnum > 0 AND NOT attisdropped"; }
CLI() { python3 cli/rowstile_cli.py --db "dbname=$DB" "$@"; }
columns() { fresh; PSQL -c "REVOKE SELECT ON mt.docs FROM app_user" -c "GRANT SELECT (id, author_id, body) ON mt.docs TO app_user" >/dev/null; start=$(acl); }
columns
out=$(apply $T/masks.sql); [ -z "$out" ] || bad "apply, the app role reading columns" "$out"
[ "$(PSQL -c "SELECT has_column_privilege('app_user', 'mt.docs', 'body', 'SELECT'), has_column_privilege('app_user', 'mt.docs', 'id', 'SELECT'), has_table_privilege('app_user', 'mt.docs', 'SELECT')")" = "f|t|f" ] &&
  ok "a masked column the app role could read with a grant of its own: the grant is taken away, the others kept" || bad "masking a column granted on its own" "$(acl)"
apply $T/masks_two.sql >/dev/null; apply $T/masks.sql >/dev/null
[ "$(PSQL -c "SELECT has_column_privilege('app_user', 'mt.docs', 'author_id', 'SELECT'), has_column_privilege('app_user', 'mt.docs', 'body', 'SELECT'), (SELECT cols FROM authz.masked_tables)")" = "t|f|{body}" ] &&
  ok "... a second column masked, then no longer: its grant is given back, the first stays masked" || bad "a column no longer masked" "$(acl)"
apply $T/nomask.sql >/dev/null
[ "$(acl)" = "$start" ] && ok "... and the policy without the mask applied: every grant is as it was" || bad "the grants after unmasking" "$(acl), not $start"
CLI apply tests/multi.authz --force >/dev/null 2>&1 || bad "apply with the command"
out=$(CLI remove --yes 2>&1) || bad "remove" "$out"
[ "$(acl)" = "$start" ] && ok "... and rowstile remove gives the column's grant back" || bad "the grants after remove" "$(acl), not $start"
columns
M=$T/migrations
mkdir -p "$M/db"; cp tests/multi.authz "$M/db/policy.authz"
printf 'policy = "db/policy.authz"\ndatabase = "dbname=%s"\n[migrations]\ntool = "sql"\ndir = "db/migrations"\n' "$DB" > "$M/rowstile.toml"
migrate() {
  ( cd "$M" && python3 "$OLDPWD/cli/rowstile_cli.py" migrate --name "$1" ) >/dev/null 2>&1 || bad "migrate $1"
  PGOPTIONS="-c client_min_messages=error" psql -X -q -1 -v ON_ERROR_STOP=1 -d "$DB" -f "$(ls "$M"/db/migrations/*.sql | sort | tail -n 1)" 2>&1 >/dev/null
}
out=$(migrate masked); [ -z "$out" ] || bad "the first migration" "$out"
cp $T/nomask.authz "$M/db/policy.authz"
out=$(migrate unmasked)
[ -z "$out" ] && [ "$(acl)" = "$start" ] && ok "... and so does a migration to the policy without the mask" || bad "the grants after a migration" "$out $(acl), not $start"
# the table-wide SELECT a mask replaced: given back alone, the column grants the mask gave instead taken back
fresh; apply $T/masks.sql >/dev/null; apply $T/masks_two.sql >/dev/null; apply $T/nomask.sql >/dev/null
[ "$(acl)" = "$(PSQL -c "SELECT relacl FROM pg_class WHERE oid = 'mt.docs'::regclass") id= container_type= container_id= author_id= body=" ] &&
  ok "the table-wide SELECT a mask replaced, given back by applying once the masks changed and went: no column grant they gave is left" || bad "column grants left by unmasking" "$(acl)"

if [ $fails -eq 0 ]; then echo "masks: all passed"; else echo "masks: $fails failed"; exit 1; fi

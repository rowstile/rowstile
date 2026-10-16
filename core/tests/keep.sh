#!/bin/bash
# keep.sh: applying keeps inheritance tables whose definition didn't change (and whose tables
# weren't recreated) instead of rebuilding them under lock; what did change is rebuilt.
#   PGHOST=... PGUSER=postgres tests/keep.sh [database]
set -u
cd "$(dirname "$0")/.."
DB=${1:-authz_keep}
fails=0
PSQL() { psql -X -q -At -v ON_ERROR_STOP=1 -d "$DB" "$@"; }
ok() { echo "ok    $1"; }
bad() { echo "FAIL  $1${2:+: $2}"; fails=$((fails + 1)); }
T=$(mktemp -d)
# applies the policy text $1 with the rowstile command
apply() { printf '%s\n' "$1" > "$T/p.authz"
          out=$(python3 cli/rowstile_cli.py --db "dbname=$DB" apply "$T/p.authz" --force 2>&1) || { bad "apply" "$out"; exit 1; }; }
# the inheritance tables, by oid: the same oid after an apply means the table (and its rows) was kept
trees() { PSQL -c "SELECT string_agg(c.relname || '=' || c.oid, ' ' ORDER BY c.relname) FROM pg_class c
                   WHERE c.relnamespace = 'authz_int'::regnamespace AND c.relkind = 'r' AND c.relname LIKE '%\_\_tree%'"; }
verify() { [ "$(PSQL -c 'SELECT authz.verify()')" = "t" ]; }

dropdb --if-exists "$DB" 2>/dev/null; createdb "$DB" || exit 1
PGOPTIONS="-c client_min_messages=error" psql -X -q -v ON_ERROR_STOP=1 -d "$DB" -f example/app_schema.sql >/dev/null || exit 1
DOCS=$(cat example/docs.authz)
apply "$DOCS"
BEFORE=$(trees)
[ -n "$BEFORE" ] && ok "the example has inheritance tables: $(echo "$BEFORE" | wc -w)" || bad "no trees"

# a permission added, nothing about inheritance changed
MORE=$(echo "$DOCS" | sed 's/^  can break_glass = org.member$/  can break_glass = org.member\n  can peek = view/')
[ "$MORE" != "$DOCS" ] || bad "the policy change did not apply"
apply "$MORE"
[ "$(trees)" = "$BEFORE" ] && ok "a new permission keeps every inheritance table" || bad "kept" "$(trees)"
verify && ok "...and they match a rebuild" || bad "verify after keeping"

# rows written between applies: the kept tables were kept current by their triggers
PSQL -c "UPDATE app.folders SET parent_id = NULL WHERE id = (SELECT max(id) FROM app.folders WHERE parent_id IS NOT NULL)" >/dev/null
apply "$DOCS"
[ "$(trees)" = "$BEFORE" ] && verify && ok "a move between applies is in the kept tables" || bad "after a move" "$(trees)"

# inheritance changed: the tree that changed is rebuilt, the others kept
NOINH=$(echo "$DOCS" | sed 's/(parent.edit and {inherit})/parent.edit/')
[ "$NOINH" != "$DOCS" ] || bad "the inheritance change did not apply"
apply "$NOINH"
AFTER=$(trees)
kept=$(comm -12 <(echo "$BEFORE" | tr ' ' '\n' | sort) <(echo "$AFTER" | tr ' ' '\n' | sort) | wc -l)
total=$(echo "$AFTER" | wc -w)
[ "$AFTER" != "$BEFORE" ] && [ "$kept" -gt 0 ] && ok "changed inheritance is rebuilt ($((total - kept)) of $total), the rest kept" \
  || bad "partial rebuild" "kept $kept of $total"
verify && ok "...and everything matches a rebuild" || bad "verify after a partial rebuild"

# a table recreated between applies: its trees are rebuilt, even with the same definition
apply "$DOCS"
BEFORE=$(trees)
PGOPTIONS="-c client_min_messages=warning" PSQL <<'SQL' >/dev/null
ALTER TABLE app.folder_links RENAME TO folder_links_old;
CREATE TABLE app.folder_links (LIKE app.folder_links_old INCLUDING ALL);
INSERT INTO app.folder_links SELECT * FROM app.folder_links_old;
INSERT INTO app.folder_links SELECT f.id, 1 FROM app.folders f WHERE f.id > 1 AND NOT EXISTS
  (SELECT 1 FROM app.folder_links l WHERE l.folder_id = f.id) LIMIT 1;
DROP TABLE app.folder_links_old CASCADE;
GRANT SELECT ON app.folder_links TO app_user;
SQL
apply "$DOCS"
[ "$(trees)" != "$BEFORE" ] && verify && ok "a recreated link table rebuilds the trees that read it" || bad "recreated table" "$(trees)"

# an index on share ids for a type the policy no longer has (made for a type gone since): applying drops it, so a
# share of another type of that name, with ids of another kind, isn't refused by its cast
PSQL -c "CREATE INDEX shares_obj_ghost_bigint ON authz.shares ((object_id::bigint), relation) WHERE object_type = 'ghost'" >/dev/null
apply "$DOCS"
[ "$(PSQL -c "SELECT to_regclass('authz.shares_obj_ghost_bigint') IS NULL, to_regclass('authz.shares_obj_folder_bigint') IS NOT NULL")" = "t|t" ] &&
  ok "applying drops an index on share ids no type of the policy has, and keeps the policy's own" || bad "share indexes after apply"

rm -r "$T"
dropdb "$DB"
echo "keep: $fails failure(s)"
exit $((fails > 0))

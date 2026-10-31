#!/bin/bash
# children.sh: tables under a governed table (tests/children_schema.sql, tests/children.authz): the partitions
# of a partitioned table, and a table that inherits from one. Postgres runs a table's row triggers on its
# partitions (it copies them there) but not for rows stored in a table that inherits from it; and an update that
# puts a row in another partition is a delete there and an insert here, with no AFTER UPDATE row trigger.
# What rowstile keeps with row triggers has to hold for those rows too: a rule on a column, forgetting a row's
# shares when its key changes, the audit line of a changed relationship column.
#   PGHOST=... PGUSER=authz_owner tests/children.sh
set -u
cd "$(dirname "$0")/.."
ROOT=$PWD
DB=authz_children
DB2=authz_children_2
fails=0
PSQL() { psql -X -q -At -v ON_ERROR_STOP=1 -v VERBOSITY=terse -d "${D:-$DB}" "$@"; }
ok() { echo "ok    $1"; }
bad() { echo "FAIL  $1${2:+: $2}"; fails=$((fails + 1)); }
# $1 label, $2 what was got, $3 what is expected
same() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "expected '$3', got '$2'"; fi; }
schema() { PGOPTIONS="-c client_min_messages=error" psql -X -q -v ON_ERROR_STOP=1 -d "$1" -f tests/children_schema.sql >/dev/null; }
T=$(mktemp -d)
# whatever way the suite ends: its databases, its files
cleanup() { [ -n "${KEEP:-}" ] || for d in "$DB" "$DB2" "${DB}_sync"; do dropdb --force --if-exists "$d" 2>/dev/null; done; rm -rf "$T"; }
trap cleanup EXIT
# runs the command in the project; sets $out (stdout and stderr) and $rc
run() { out=$(cd "$T" && python3 "$ROOT/cli/rowstile_cli.py" "$@" 2>&1); rc=$?; }
# whether the command's last line says this of the policy ("…policy.authz: unchanged")
is() { case "$out" in *"policy.authz: $1") return 0;; *) return 1;; esac; }
# as user $1, as the app role: the last line of what the statements print, or the error
as() { local u=$1; shift; PSQL -c "SET authz.user_id = $u" -c "SET ROLE app_user" "$@" 2>&1 | tail -n 1; }
# as user $1, as the tables' owner (no rule applies; the triggers run): for what the rules would refuse
owner() { local u=$1; shift; PSQL -c "SET authz.user_id = $u" "$@" 2>&1 | tail -n 1; }
changed() { echo "WITH u AS ($1 RETURNING 1) SELECT count(*) FROM u"; }
shares() { PSQL -c "SELECT count(*) FROM authz.shares WHERE object_type = '$1' AND object_id = '$2'"; }
relates() { PSQL -c "SELECT string_agg(user_id || ' set ' || subject_id || ', was ' || (detail->>'was'), '; ' ORDER BY id) FROM authz.audit WHERE action = 'relate' AND object_type = '$1' AND object_id = '$2'"; }
triggers() { PSQL -c "SELECT coalesce(string_agg(tgname, ' ' ORDER BY tgname), '') FROM pg_trigger WHERE tgrelid = '$1'::regclass AND NOT tgisinternal"; }

for d in "$DB" "$DB2"; do dropdb --if-exists "$d" 2>/dev/null; createdb "$d" || exit 1; schema "$d" || exit 1; done
mkdir -p "$T/db"
cp tests/children.authz "$T/db/policy.authz"
printf 'policy   = "db/policy.authz"\ndatabase = "dbname=%s"\n[migrations]\ntool = "sql"\ndir  = "db/migrations"\n' "$DB" > "$T/rowstile.toml"

echo "-- apply"
run apply; [ $rc -eq 0 ] && is applied && ok "apply" || bad "apply" "$out"
run apply; is unchanged && ok "... again: unchanged (a trigger made for partitioned tables alone is looked for there alone)" || bad "apply again" "$out"
same "the inheritance tables are right" "$(PSQL -c "SELECT authz.verify()")" t
same "the partitioned tables have the trigger that forgets a row gone to another partition, the others don't" \
  "$(PSQL -c "SELECT string_agg(tgrelid::regclass::text, ' ' ORDER BY tgrelid::regclass::text) FROM pg_trigger g JOIN pg_class c ON c.oid = g.tgrelid WHERE tgname LIKE 'authz\_%\_forget\_moved' AND NOT c.relispartition")" "ch.notes ch.tasks ch.topics"
rowtriggers=$(triggers ch.docs_old)
# (not the ones for TRUNCATE alone: emptying the table that inherits is not emptying the table)
same "the table that inherits has its table's row and statement triggers" "$rowtriggers" \
  "authz_doc_col_audit_del authz_doc_col_audit_ins authz_doc_col_audit_row authz_doc_col_audit_upd authz_doc_forget_del authz_doc_forget_id authz_update owner_id"

echo "-- a table that inherits: its rows, read and written through the table above"
as 1 -c "SELECT authz.share('doc', 1, 'editor', 'user', 2)" -c "SELECT authz.share('doc', 11, 'editor', 'user', 2)" >/dev/null
same "a row stored there is written through the table above" "$(as 2 -c "$(changed "UPDATE ch.docs SET title = 'bob was here' WHERE id = 11")")" 1
same "the rule on a column, on a row of the table itself" "$(as 2 -c "UPDATE ch.docs SET owner_id = 2 WHERE id = 1")" "ERROR:  changing owner_id of ch.docs 1 needs: own"
same "... and on a row stored in the table that inherits" "$(as 2 -c "UPDATE ch.docs SET owner_id = 2 WHERE id = 11")" "ERROR:  changing owner_id of ch.docs 11 needs: own"
same "... which its owner may change" "$(as 1 -c "$(changed "UPDATE ch.docs SET owner_id = 1 WHERE id = 11")")" 1
owner 1 -c "UPDATE ch.docs SET owner_id = 3 WHERE id = 12" >/dev/null
same "the audit has the line of a relationship column changed there" "$(relates doc 12)" "1 set 3, was 1"
same "a key that changes there" "$(as 1 -c "$(changed "UPDATE ch.docs SET id = 111 WHERE id = 11")")" 1
same "... takes the row's shares away" "$(shares doc 11) $(shares doc 111)" "0 0"
PSQL -c "INSERT INTO ch.docs_old VALUES (11, 1, 'another doc 11')"
same "... so a row that has the key later starts with none" "$(as 2 -c "SELECT count(*) FROM ch.docs WHERE id = 11")" 0
# the table's primary key doesn't cover the rows of a table that inherits: two rows may hold one key, each
# with its own owner. A permission holds on the key where it holds on either row, as the views say
PSQL -c "INSERT INTO ch.docs_old VALUES (2, 3, 'another doc 2')"
same "a key two rows hold: authz.can answers for either (owner of one, of the other, of neither)" \
  "$(as 1 -c "SELECT authz.can('doc', 2, 'own')")|$(as 3 -c "SELECT authz.can('doc', 2, 'own')")|$(as 2 -c "SELECT authz.can('doc', 2, 'own')")" "t|t|f"
same "... and so do perms, explain and who" \
  "$(as 3 -c "SELECT authz.perms('doc', 2)")|$(as 3 -c "SELECT left(e, 3) FROM authz.explain('doc', 2, 'own') e LIMIT 1")|$(owner 1 -c "SELECT string_agg(w, ' ' ORDER BY w) FROM authz.who('doc', 2, 'own') w")" \
  "{own,edit}|yes|1 3"
same "... as list does" "$(as 3 -c "SELECT count(*) FROM authz.list('doc', 'own') l WHERE l = '2'")" 1
PSQL -c "DELETE FROM ch.docs_old WHERE id = 2"
PSQL -c "DELETE FROM ch.docs WHERE id = 1"
same "a row deleted through the table above: its shares go" "$(shares doc 1)" 0

echo "-- a table that inherits, made after the policy was applied"
PSQL -c "CREATE TABLE ch.docs_older () INHERITS (ch.docs)" -c "CREATE TABLE ch.docs_oldest () INHERITS (ch.docs_old)" \
     -c "INSERT INTO ch.docs_older VALUES (21, 1, 'ancient')"
same "lint names each, and the triggers it lacks" \
  "$(PSQL -c "SELECT string_agg(object || ': ' || split_part(problem, ',', 1), '; ' ORDER BY object) FROM authz.lint() WHERE severity = 'error' AND problem LIKE 'inherits from %, and was made since the policy was last applied: Postgres runs a table''s row triggers for its own rows only, and its statement triggers for statements on it only, so a rule on a column is not checked on the rows stored here, their shares stay when their key changes, and a statement on this table doesn''t keep inheritance, shares and the audit current (missing here: authz_doc_col_audit_del, authz_doc_col_audit_ins, authz_doc_col_audit_row, authz_doc_col_audit_upd, authz_doc_forget_del, authz_doc_forget_id, authz_update owner_id). Apply the policy again (it makes them)'")" \
  "ch.docs_older: inherits from ch.docs; ch.docs_oldest: inherits from ch.docs_old"
run apply; is applied && ok "apply is not 'unchanged' then: it applies" || bad "apply after a table was made" "$out"
same "... and lint has nothing more to say of them" "$(PSQL -c "SELECT count(*) FROM authz.lint() WHERE object LIKE 'ch.docs_old%'")" 0
same "... each has the row triggers, once (the one that inherits from a table that inherits too)" "$(triggers ch.docs_older)|$(triggers ch.docs_oldest)" "$rowtriggers|$rowtriggers"
same "... and row-level security on, as partitions have" "$(PSQL -c "SELECT bool_and(relrowsecurity) FROM pg_class WHERE oid IN ('ch.docs_older'::regclass, 'ch.docs_oldest'::regclass)")" t
as 1 -c "SELECT authz.share('doc', 21, 'editor', 'user', 2)" >/dev/null
same "the rule on a column holds on its rows" "$(as 2 -c "UPDATE ch.docs SET owner_id = 2 WHERE id = 21")" "ERROR:  changing owner_id of ch.docs 21 needs: own"
run apply; is unchanged && ok "apply again: unchanged" || bad "apply once more" "$out"
PSQL -c "ALTER TABLE ch.docs_older NO INHERIT ch.docs"
run apply; is unchanged && ok "a table that inherits no more keeps its triggers until the next apply, and that is no reason to apply" || bad "apply after NO INHERIT" "$out"
PSQL -c "ALTER TABLE ch.docs_older INHERIT ch.docs"
PSQL -c "DROP TRIGGER \"authz_update owner_id\" ON ch.docs_old"
run apply; is applied && ok "a row trigger dropped from a table that inherits: apply applies" || bad "apply after a dropped copy" "$out"
same "... and it is back" "$(triggers ch.docs_old)" "$rowtriggers"
# the other way round: dropped from the table, while the tables that inherit keep their copies (the same name)
PSQL -c "DROP TRIGGER \"authz_update owner_id\" ON ch.docs"
run apply; is applied && ok "a row trigger dropped from the table, its copies left below: apply applies" || bad "apply after a dropped trigger above its copies" "$out"
same "... and it is back there" "$(PSQL -c "SELECT count(*) FROM pg_trigger WHERE tgrelid = 'ch.docs'::regclass AND tgname = 'authz_update owner_id'")" 1
# what lacks a copy is read from the catalog, whatever the search path of the session asking: a table of the
# catalog's name in a schema before pg_catalog changes nothing
PSQL -c "CREATE TABLE ch.docs_older_still () INHERITS (ch.docs)"
same "a table made since lacks its copies, whatever the search path says first" \
  "$(PSQL -c "CREATE SCHEMA shadow" -c "CREATE TABLE shadow.pg_inherits (LIKE pg_catalog.pg_inherits)" -c "SET client_min_messages = warning" -c "SET search_path = shadow, pg_catalog" \
     -c "SELECT string_agg(child::text || ' ' || name, ', ' ORDER BY name) FROM authz_int.child_triggers()" -c "RESET search_path" -c "DROP SCHEMA shadow CASCADE")" \
  "ch.docs_older_still authz_doc_col_audit_del, ch.docs_older_still authz_doc_col_audit_ins, ch.docs_older_still authz_doc_col_audit_row, ch.docs_older_still authz_doc_col_audit_upd, ch.docs_older_still authz_doc_forget_del, ch.docs_older_still authz_doc_forget_id, ch.docs_older_still authz_update owner_id"
PSQL -c "DROP TABLE ch.docs_older_still"

echo "-- a partitioned table: a row that stays in its partition, and one an update puts in another"
as 1 -c "SELECT authz.share('note', 1, 'viewer', 'user', 2)" -c "SELECT authz.share('note', 3, 'viewer', 'user', 2)" \
     -c "SELECT authz.share('note', 4, 'viewer', 'user', 2)" >/dev/null
same "the rule on a column, on a row of a partition" "$(as 2 -c "UPDATE ch.notes SET owner_id = 2 WHERE id = 3")" "ERROR:  changing owner_id of ch.notes 3 needs: manage"
same "... and on one the same update puts in another partition" "$(as 2 -c "UPDATE ch.notes SET owner_id = 2, id = 503 WHERE id = 3")" "ERROR:  changing owner_id of ch.notes 3 needs: manage"
same "a key that changes inside a partition" "$(as 1 -c "$(changed "UPDATE ch.notes SET id = 33 WHERE id = 3")")|$(PSQL -c "SELECT tableoid::regclass FROM ch.notes WHERE id = 33")" "1|ch.notes_low"
same "... takes the row's shares away" "$(shares note 3)" 0
same "a key that changes and puts the row in another partition" "$(as 1 -c "$(changed "UPDATE ch.notes SET id = 504 WHERE id = 4")")|$(PSQL -c "SELECT tableoid::regclass FROM ch.notes WHERE id = 504")" "1|ch.notes_high"
same "... takes them away too" "$(shares note 4) $(shares note 504)" "0 0"
as 1 -c "INSERT INTO ch.notes VALUES (4, 1, NULL, 'another note 4')" >/dev/null
same "... so a row that has the key later starts with none" "$(as 2 -c "SELECT count(*) FROM ch.notes WHERE id = 4")" 0
same "a note under a shared one, put in another partition, is still under it" \
  "$(as 1 -c "$(changed "UPDATE ch.notes SET id = 502 WHERE id = 2")")|$(as 2 -c "SELECT count(*) FROM ch.notes WHERE id = 502")|$(PSQL -c "SELECT authz.verify()")" "1|1|t"

echo "-- a table partitioned by a column that is not its key: a row changes partition and keeps its key"
as 1 -c "SELECT authz.share('task', 1, 'viewer', 'user', 2)" >/dev/null
same "the row goes to the other partition" "$(as 1 -c "$(changed "UPDATE ch.tasks SET state = 'done' WHERE id = 1")")|$(PSQL -c "SELECT tableoid::regclass FROM ch.tasks WHERE id = 1")" "1|ch.tasks_done"
same "... and keeps its shares: its key did not change" "$(shares task 1)|$(as 2 -c "SELECT count(*) FROM ch.tasks WHERE id = 1")" "1|1"
owner 1 -c "UPDATE ch.tasks SET owner_id = 3, state = 'done' WHERE id = 2" >/dev/null
same "the audit has the line of a relationship column changed by the update that moved the row" "$(relates task 2)" "1 set 3, was 1"
owner 1 -c "UPDATE ch.tasks SET owner_id = 2 WHERE id = 3" >/dev/null
same "... and one line, not two, for a row that stayed where it was" "$(relates task 3)" "1 set 2, was 1"
owner 1 -c "UPDATE ch.tasks SET owner_id = 1 WHERE id = 3" -c "UPDATE ch.tasks SET owner_id = 2, state = 'open' WHERE id = 3" >/dev/null
same "... a line for each change after that, moved or not" "$(relates task 3)" "1 set 2, was 1; 1 set 1, was 2; 1 set 2, was 1"

echo "-- the API keys of principals stored in partitions, and in a table that inherits"
# (bot 4 and person 13, stored in the table that inherits, are only renamed: their keys stay)
PSQL -c "INSERT INTO ch.bots VALUES (4, 'd')" -c "INSERT INTO ch.people_old VALUES (13, 'kept')" >/dev/null
PSQL -c "INSERT INTO authz.api_keys (user_id, principal_type, name, prefix, hash) VALUES
  ('1', 'bot', 'a', 'ak_', 'h1'), ('2', 'bot', 'b', 'ak_', 'h2'), ('3', 'bot', 'c', 'ak_', 'h3'), ('4', 'bot', 'f', 'ak_', 'h6'),
  ('11', 'person', 'd', 'ak_', 'h4'), ('12', 'person', 'e', 'ak_', 'h5'), ('13', 'person', 'g', 'ak_', 'h7')"
keys() { PSQL -c "SELECT coalesce(string_agg(user_id, ' ' ORDER BY user_id), '') FROM authz.api_keys WHERE principal_type = '$1'"; }
PSQL -c "UPDATE ch.bots SET id = 33 WHERE id = 3" -c "UPDATE ch.bots SET id = 502 WHERE id = 2" -c "DELETE FROM ch.bots WHERE id = 1" \
     -c "UPDATE ch.bots SET name = 'dd' WHERE id = 4"
same "a bot's keys go when its id changes, inside its partition or to another, and with its row; a bot renamed keeps its own" "$(keys bot)" "4"
same "the table that inherits from the people's has the row trigger that deletes the keys of an id that changes" \
  "$(PSQL -c "SELECT count(*) FROM pg_trigger WHERE tgrelid = 'ch.people_old'::regclass AND tgname = 'authz_person_keys_gone_id'")" 1
PSQL -c "UPDATE ch.people SET id = 111 WHERE id = 11" -c "DELETE FROM ch.people WHERE id = 12" -c "UPDATE ch.people SET name = 'still' WHERE id = 13"
same "... so a person stored there loses their keys with a new id, and one above with their row; one renamed there keeps them" "$(keys person)" "13"

echo "-- trees whose tables have no rules, written directly through what is under them (posts read them)"
# Postgres runs a table's statement triggers only for statements on it, and those keep the trees, the shares and
# the audit current: each partition, and each table that inherits, has them too. The app role is given these tables
# as an app gives them (GRANT ... ON ALL TABLES IN SCHEMA): they have no rules, so they are not closed to it
seen() { as "$1" -c "SELECT coalesce(string_agg(id::text, ' ' ORDER BY id), '') FROM ch.posts"; }
same "user 1 sees the posts in the topics and shelves under theirs" "$(seen 1)" "5 6 7 8"
same "the app role reads a partition of a table without rules directly, as it reads the table" \
  "$(as 1 -c "SELECT count(*) FROM ch.topics_high")|$(as 1 -c "SELECT count(*) FROM ch.shelves_old")" "3|3"
same "the partitions have their table's statement triggers (Postgres gave them the row triggers)" "$(triggers ch.topics_high)|$(triggers ch.topic_links_see)|$(triggers ch.frozen_hold)" \
  "authz_topic__linked_parent__tree_del authz_topic__linked_parent__tree_ins authz_topic__linked_parent__tree_upd authz_topic_col_audit_del authz_topic_col_audit_ins authz_topic_col_audit_row authz_topic_col_audit_upd authz_topic_forget_del authz_topic_forget_id authz_topic_forget_moved|authz_rel_audit_2_del authz_rel_audit_2_ins authz_rel_audit_2_upd authz_topic__linked_parent__tree_on_links1_del authz_topic__linked_parent__tree_on_links1_ins authz_topic__linked_parent__tree_on_links1_upd|authz_topic__linked_parent__tree_dep"
same "... and so have the tables that inherit" "$(triggers ch.shelves_old)|$(triggers ch.shelf_links_old)|$(triggers ch.holds_old)" \
  "authz_shelf__linked_parent__tree_del authz_shelf__linked_parent__tree_ins authz_shelf__linked_parent__tree_upd authz_shelf_col_audit_del authz_shelf_col_audit_ins authz_shelf_col_audit_row authz_shelf_col_audit_upd authz_shelf_forget_del authz_shelf_forget_id|authz_rel_audit_1_del authz_rel_audit_1_ins authz_rel_audit_1_upd authz_shelf__linked_parent__tree_on_links1_del authz_shelf__linked_parent__tree_on_links1_ins authz_shelf__linked_parent__tree_on_links1_upd|authz_shelf__linked_parent__tree_dep"
as 2 -c "SELECT authz.share('topic', 152, 'viewer', 'user', 3)" -c "SELECT authz.share('shelf', 52, 'viewer', 'user', 3)" >/dev/null
for kind in topic shelf; do
  if [ $kind = topic ]; then
    rows=ch.topics_high links=ch.topic_links_see held=ch.frozen_hold lone=150 other=151 under=3 gone=152
  else
    rows=ch.shelves_old links=ch.shelf_links_old held=ch.holds_old lone=50 other=51 under=3 gone=52
  fi
  where=$([ $kind = topic ] && echo "a partition" || echo "a table that inherits")
  same "the app role moves a $kind under another through $where of its table" "$(as 1 -c "$(changed "UPDATE $rows SET parent_id = 2 WHERE id = $lone")")" 1
  same "... and links one in through $where of the link table" "$(as 1 -c "$(changed "INSERT INTO $links VALUES ($other, 1)")")" 1
  same "... and holds one through $where of the table the condition reads" "$(as 1 -c "$(changed "INSERT INTO $held VALUES ($under)")")" 1
  same "... so user 1 sees the posts in the one moved and the one linked, not in the one held" \
    "$(as 1 -c "SELECT string_agg(id::text, ' ' ORDER BY id) FROM ch.posts WHERE ${kind}_id IN ($lone, $other, $under)")" \
    "$([ $kind = topic ] && echo "1 2" || echo "3 4")"
  same "the app role deletes a $kind through $where of its table" "$(as 1 -c "$(changed "DELETE FROM $rows WHERE id = $gone")")" 1
  same "... and its shares go" "$(shares $kind $gone)" 0
done
same "the inheritance tables are right" "$(PSQL -c "SELECT authz.verify()")" t
same "... user 1 sees the posts in the ones moved under theirs and linked in" "$(seen 1)" "1 2 3 4 7 8"
same "the tables' owner moving them out again, through the partition and the table that inherits: user 1 no longer sees their posts" \
  "$(owner 1 -c "UPDATE ch.topics_high SET parent_id = NULL WHERE id = 150" -c "UPDATE ch.shelves_old SET parent_id = NULL WHERE id = 50" -c "SELECT authz.verify()")|$(seen 1)" \
  "t|2 4 7 8"

echo "-- a partition made after the policy was applied"
PSQL -c "CREATE TABLE ch.notes_top PARTITION OF ch.notes FOR VALUES FROM (1000) TO (2000)" \
     -c "GRANT SELECT, INSERT, UPDATE, DELETE ON ch.notes_top TO app_user" -c "INSERT INTO ch.notes VALUES (1001, 3, NULL, 'carol''s')"
directly="SELECT count(*) FROM authz.lint() WHERE severity = 'error' AND object = 'ch.notes_top' AND problem LIKE '%may use it directly%'"
same "lint says the app role may use it directly" "$(PSQL -c "$directly")" 1
# ... with any one of those privileges (reading too: its table has rules)
for p in SELECT INSERT UPDATE DELETE; do
  PSQL -c "REVOKE ALL ON ch.notes_top FROM app_user" -c "GRANT $p ON ch.notes_top TO app_user" >/dev/null
  same "... with $p alone on it too" "$(PSQL -c "$directly")" 1
done
PSQL -c "GRANT SELECT, INSERT, UPDATE, DELETE ON ch.notes_top TO app_user" >/dev/null
# its rows are written through the table from the day it is made (a job that makes next month's partition
# doesn't apply the policy): the rule on a column has to hold there before the next apply
as 3 -c "SELECT authz.share('note', 1001, 'viewer', 'user', 2)" >/dev/null
same "the rule on a column holds on its rows already" "$(as 2 -c "UPDATE ch.notes SET owner_id = 2 WHERE id = 1001")" "ERROR:  changing owner_id of ch.notes 1001 needs: manage"
same "... and their owner still writes them" "$(as 3 -c "$(changed "UPDATE ch.notes SET owner_id = 3, title = 'still carol''s' WHERE id = 1001")")" 1
run apply; is applied && ok "apply is not 'unchanged' then: it applies" || bad "apply after a partition was made" "$out"
same "... and the partition is closed: the app role reads it through its table" "$(as 2 -c "SELECT count(*) FROM ch.notes_top")|$(as 3 -c "SELECT count(*) FROM ch.notes WHERE id = 1001")" "0|1"
same "... lint has nothing more to say of it" "$(PSQL -c "SELECT count(*) FROM authz.lint() WHERE object = 'ch.notes_top'")" 0
same "... Postgres gave it the row triggers itself, and apply the statement triggers" "$(triggers ch.notes_top)" \
  "authz_note__parent__tree_del authz_note__parent__tree_ins authz_note__parent__tree_upd authz_note_col_audit_del authz_note_col_audit_ins authz_note_col_audit_row authz_note_col_audit_upd authz_note_forget_del authz_note_forget_id authz_note_forget_moved authz_update owner_id"
run apply; is unchanged && ok "apply again: unchanged" || bad "apply once more after a partition was made" "$out"
# a partition of a table without rules, made since: given nothing, its rows are written through its table; but a
# statement on it alone (the owner's, or the app role's once given it) runs none of the table's statement triggers
PSQL -c "CREATE TABLE ch.topics_top PARTITION OF ch.topics FOR VALUES FROM (1000) TO (2000)"
same "lint names a partition made since of a table without rules, and the statement triggers it lacks" \
  "$(PSQL -c "SELECT severity || ': ' || problem FROM authz.lint() WHERE object = 'ch.topics_top'")" \
  "error: is a partition of ch.topics, and was made since the policy was last applied: Postgres runs a table's statement triggers for statements on it only, so a statement on this partition doesn't keep inheritance, shares and the audit current (missing here: authz_topic__linked_parent__tree_del, authz_topic__linked_parent__tree_ins, authz_topic__linked_parent__tree_upd, authz_topic_col_audit_del, authz_topic_col_audit_ins, authz_topic_col_audit_upd, authz_topic_forget_del, authz_topic_forget_moved). Apply the policy again (it makes them)"
PSQL -c "GRANT TRUNCATE ON ch.frozen_hold TO app_user"
same "lint says the app role may empty a partition of the table a condition reads, which skips its triggers" \
  "$(PSQL -c "SELECT count(*) FROM authz.lint() WHERE severity = 'error' AND object = 'ch.frozen_hold' AND problem LIKE 'is a partition of ch.frozen (or inherits from it), and app_user may TRUNCATE it, %'")" 1
PSQL -c "REVOKE TRUNCATE ON ch.frozen_hold FROM app_user"
# (a governed table has triggers of rowstile's too: it is still one table above, said once)
PSQL -c "GRANT TRUNCATE ON ch.notes_top TO app_user"
same "... and once a partition of a governed table" \
  "$(PSQL -c "SELECT count(*) FROM authz.lint() WHERE severity = 'error' AND object = 'ch.notes_top' AND problem LIKE 'is a partition of ch.notes (or inherits from it), and app_user may TRUNCATE it, %'")" 1
PSQL -c "REVOKE TRUNCATE ON ch.notes_top FROM app_user"
run apply; is applied && ok "apply is not 'unchanged' then: it applies" || bad "apply after a partition of a table without rules was made" "$out"
same "... lint has nothing more to say of them" "$(PSQL -c "SELECT count(*) FROM authz.lint() WHERE object IN ('ch.topics_top', 'ch.frozen_hold')")" 0
# (not the triggers for TRUNCATE alone: emptying a partition is not emptying its table, which is what they do)
as 1 -c "SELECT authz.share('topic', 1, 'viewer', 'user', 3)" >/dev/null
PSQL -c "TRUNCATE ch.topics_top"
same "... and emptying the partition keeps the shares of the rows stored in the others" "$(shares topic 1)" 1

echo "-- migrations: a rule on a column changes, where a table that inherits has its trigger"
cp tests/children.authz "$T/db/policy.authz"
run migrate; case "$out" in *"the whole policy"*"wrote db/migrations/"*) ok "migrate: the whole policy first";; *) bad "migrate" "$out";; esac
sed -i 's/^  update owner_id : own$/  update owner_id, title : own/' "$T/db/policy.authz"
run migrate --name doc_title; case "$out" in *"_authz_doc_title.sql"*) ok "... then the rule that now covers the title too";; *) bad "migrate the rule" "$out";; esac
applied=0
for f in "$T"/db/migrations/*.sql; do
  psql -X -q -1 -v ON_ERROR_STOP=1 -d "$DB2" -f "$f" >/dev/null 2>"$T/err" || { bad "$(basename "$f")" "$(cat "$T/err")"; break; }
  applied=$((applied + 1))
done
same "both migration files apply in order (the second drops a function the copied trigger calls)" "$applied" 2
# (the rule's trigger is named after its head: the old one goes, on the tables that inherit too)
retitled=${rowtriggers/authz_update owner_id/authz_update owner_id, title}
same "the table that inherits has the row triggers after them" "$(D=$DB2 triggers ch.docs_old)" "$retitled"
same "... and the partitions of a link table their table's statement triggers" "$(D=$DB2 triggers ch.topic_links_see)" \
  "authz_rel_audit_2_del authz_rel_audit_2_ins authz_rel_audit_2_upd authz_topic__linked_parent__tree_on_links1_del authz_topic__linked_parent__tree_on_links1_ins authz_topic__linked_parent__tree_on_links1_upd"
D=$DB2 as 1 -c "SELECT authz.share('doc', 12, 'editor', 'user', 2)" >/dev/null
same "... and the changed rule holds on its rows" "$(D=$DB2 as 2 -c "UPDATE ch.docs SET title = 'mine' WHERE id = 12")" "ERROR:  changing owner_id, title of ch.docs 12 needs: own"
run push --development; is pushed && ok "push: the same change on the first database" || bad "push" "$out"
same "... where the tables that inherit have the row triggers too" "$(triggers ch.docs_old)|$(triggers ch.docs_older)|$(triggers ch.docs_oldest)" "$retitled|$retitled|$retitled"
same "... and the changed rule holds" "$(as 2 -c "UPDATE ch.docs SET title = 'mine' WHERE id = 21")" "ERROR:  changing owner_id, title of ch.docs 21 needs: own"

echo "-- a column an app's migration adds or drops, after apply"
# Postgres keeps a policy, a view and a BEGIN ATOMIC body as parsed, with a dependency on each column they name: the
# rules pass the whole row and name only the columns they read, or no column of the table could be dropped
reads() {
  PSQL -c "SELECT string_agg(DISTINCT a.attname, ' ' ORDER BY a.attname) FROM pg_depend d
    JOIN pg_attribute a ON a.attrelid = d.refobjid AND a.attnum = d.refobjsubid
    WHERE d.refobjid = '$1'::regclass AND d.classid IN ('pg_proc'::regclass, 'pg_policy'::regclass, 'pg_rewrite'::regclass)"
}
PSQL -c "ALTER TABLE ch.notes ADD COLUMN body text" -c "ALTER TABLE ch.docs ADD COLUMN body text" \
     -c "ALTER TABLE ch.topics ADD COLUMN body text" -c "ALTER TABLE ch.posts ADD COLUMN body text"
# (and a rule whose condition reads other rows: the app role checks it through a function given the row)
echo '  insert : view and {not exists (select 1 from ch.holds h where h.shelf_id = this.shelf_id)}' >> "$T/db/policy.authz"
run push; is pushed || bad "push after columns were added" "$out"
same "the rules' functions, policies and views depend on the columns the rules read, not on the others" \
  "$(reads ch.notes)|$(reads ch.docs)|$(reads ch.topics)|$(reads ch.posts)" "id owner_id parent_id|id owner_id|id owner_id parent_id|id shelf_id topic_id"
same "a column no rule reads is dropped, from a table that has rules on inserts, updates and a column" \
  "$(PSQL -c "ALTER TABLE ch.notes DROP COLUMN title" -c "ALTER TABLE ch.notes DROP COLUMN body" 2>&1)" ""
same "... from one whose rows are in part stored in a table that inherits" "$(PSQL -c "ALTER TABLE ch.docs DROP COLUMN body" 2>&1)" ""
same "... from one whose type has a condition that reads other rows" "$(PSQL -c "ALTER TABLE ch.topics DROP COLUMN body" 2>&1)" ""
same "... and from one with a rule that does" "$(PSQL -c "ALTER TABLE ch.posts DROP COLUMN body" 2>&1)" ""
same "... the rules still hold, and a refused insert still says why" \
  "$(PSQL -v VERBOSITY=default -c "SET authz.user_id = 2" -c "SET ROLE app_user" -c "INSERT INTO ch.notes (id, owner_id) VALUES (5, 1)" 2>&1 | head -n 4 | tr '\n' '|')" \
  "ERROR:  permission denied: user 2 may not insert this row into ch.notes|DETAIL:  no   insert : owner  (line 36)|  no   owner|HINT:  rowstile help AZ709|"
same "... and an allowed one is made, there and where the rule reads other rows" \
  "$(as 2 -c "$(changed "INSERT INTO ch.notes (id, owner_id) VALUES (5, 2)")")|$(as 1 -c "$(changed "INSERT INTO ch.posts (id, topic_id) VALUES (99, 1)")")" "1|1"
same "a column a rule reads can't be dropped: Postgres names what reads it" \
  "$(PSQL -v VERBOSITY=default -c "ALTER TABLE ch.docs DROP COLUMN title" 2>&1 | head -n 2 | tr '\n' '|')" \
  "ERROR:  cannot drop desired object(s) because other objects depend on them|DETAIL:  trigger authz_update owner_id, title on table ch.docs depends on column title of table ch.docs|"

echo "-- the sync index (a preview): what is written through a partition, or a table that inherits, reaches it"
DB3=${DB}_sync
dropdb --if-exists "$DB3" 2>/dev/null; createdb "$DB3" && schema "$DB3" || exit 1
psql -X -q -d postgres -c "DO \$r\$ BEGIN CREATE ROLE authz_sync_engine; EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL; END \$r\$;" >/dev/null
{ cat tests/children.authz; printf '\nsync role authz_sync_engine\nsync ch.notes : view\nsync ch.docs : edit\nsync ch.topics : view\n'; } > "$T/synced.authz"
python3 cli/rowstile_cli.py --db "dbname=$DB3" apply "$T/synced.authz" --force >/dev/null 2>&1 || bad "the policy with sync lines applies"
# whether user $1 reads $2 $3 through the index (as the tables' owner)
synced() { D=$DB3 PSQL -c "SELECT EXISTS (SELECT 1 FROM authz_sync.${2}__readers r WHERE r.id = $3 AND r.key IN
                      (SELECT k.key FROM authz_sync.keys k WHERE k.principal_type = 'user' AND k.principal_id = '$1'))"; }
D=$DB3 PSQL -c "UPDATE ch.notes SET owner_id = 2 WHERE id = 1" >/dev/null
same "a note moved under another, through the partition it is stored in: its new parent's owner reads it" \
  "$(synced 2 note 101)|$(D=$DB3 PSQL -c "UPDATE ch.notes_high SET parent_id = 1 WHERE id = 101" && synced 2 note 101)" "f|t"
same "a row of the table that inherits, its owner changed there: its readers follow" \
  "$(synced 2 doc 12)|$(D=$DB3 PSQL -c "UPDATE ch.docs_old SET owner_id = 2 WHERE id = 12" && synced 2 doc 12)" "f|t"
same "a topic frozen through a partition of the table its inheritance condition reads: its readers follow" \
  "$(synced 1 topic 2)|$(D=$DB3 PSQL -c "INSERT INTO ch.frozen_hold (topic_id) VALUES (2)" && synced 1 topic 2)" "t|f"
same "... and the index matches a rebuild" "$(D=$DB3 PSQL -c "SELECT authz.sync_verify()")" t
dropdb --force --if-exists "$DB3" 2>/dev/null

echo "-- removed"
run remove --yes
same "remove leaves no trigger on the tables, nor on those under them" \
  "$(PSQL -c "SELECT count(*) FROM pg_trigger g JOIN pg_class c ON c.oid = g.tgrelid WHERE NOT g.tgisinternal AND c.relnamespace = 'ch'::regnamespace")" 0

if [ $fails -eq 0 ]; then echo "children: all passed"; else echo "children: $fails failed"; exit 1; fi

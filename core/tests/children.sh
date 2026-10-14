#!/bin/bash
# children.sh: tables under a governed table (tests/children_schema.sql, tests/children.authz): the partitions
# of a partitioned table, and a table that inherits from one. Postgres runs a table's row triggers on its
# partitions (it copies them there) but not for rows stored in a table that inherits from it; and an update that
# puts a row in another partition is a delete there and an insert here, with no AFTER UPDATE row trigger.
# What rowstile keeps with row triggers has to hold for those rows too: a rule on a column, forgetting a row's
# shares when its key changes, the audit line of a changed relationship column.
#   PGHOST=... PGUSER=postgres tests/children.sh
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
  "$(PSQL -c "SELECT string_agg(tgrelid::regclass::text, ' ' ORDER BY tgrelid::regclass::text) FROM pg_trigger WHERE tgname LIKE 'authz\_%\_forget\_moved'")" "ch.notes ch.tasks"
rowtriggers=$(triggers ch.docs_old)
same "the table that inherits has its table's row triggers" "$rowtriggers" "authz_doc_col_audit_row authz_doc_forget_id authz_update_3"

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
  "$(PSQL -c "SELECT string_agg(object, ' ' ORDER BY object) FROM authz.lint() WHERE severity = 'error' AND problem LIKE 'inherits from a table the policy has rules or a type for, and was made since the policy was last applied:%(missing here: authz_doc_col_audit_row, authz_doc_forget_id, authz_update_3). Apply the policy again (it makes them)'")" \
  "ch.docs_older ch.docs_oldest"
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
PSQL -c "DROP TRIGGER authz_update_3 ON ch.docs_old"
run apply; is applied && ok "a row trigger dropped from a table that inherits: apply applies" || bad "apply after a dropped copy" "$out"
same "... and it is back" "$(triggers ch.docs_old)" "$rowtriggers"

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
PSQL -c "INSERT INTO authz.api_keys (user_id, principal_type, name, prefix, hash) VALUES
  ('1', 'bot', 'a', 'ak_', 'h1'), ('2', 'bot', 'b', 'ak_', 'h2'), ('3', 'bot', 'c', 'ak_', 'h3'),
  ('11', 'person', 'd', 'ak_', 'h4'), ('12', 'person', 'e', 'ak_', 'h5')"
keys() { PSQL -c "SELECT coalesce(string_agg(user_id, ' ' ORDER BY user_id), '') FROM authz.api_keys WHERE principal_type = '$1'"; }
PSQL -c "UPDATE ch.bots SET id = 33 WHERE id = 3" -c "UPDATE ch.bots SET id = 502 WHERE id = 2" -c "DELETE FROM ch.bots WHERE id = 1"
same "a bot's keys go when its id changes, inside its partition or to another, and with its row" "$(keys bot)" ""
same "the table that inherits from the people's has the row trigger that deletes the keys of an id that changes" \
  "$(PSQL -c "SELECT count(*) FROM pg_trigger WHERE tgrelid = 'ch.people_old'::regclass AND tgname = 'authz_person_keys_gone_id'")" 1
PSQL -c "UPDATE ch.people SET id = 111 WHERE id = 11" -c "DELETE FROM ch.people WHERE id = 12"
same "... so a person stored there loses their keys with a new id, and one above with their row" "$(keys person)" ""

echo "-- a partition made after the policy was applied"
PSQL -c "CREATE TABLE ch.notes_top PARTITION OF ch.notes FOR VALUES FROM (1000) TO (2000)" \
     -c "GRANT SELECT, INSERT, UPDATE, DELETE ON ch.notes_top TO app_user" -c "INSERT INTO ch.notes VALUES (1001, 3, NULL, 'carol''s')"
same "lint says the app role may use it directly" "$(PSQL -c "SELECT count(*) FROM authz.lint() WHERE severity = 'error' AND object = 'ch.notes_top'")" 1
# its rows are written through the table from the day it is made (a job that makes next month's partition
# doesn't apply the policy): the rule on a column has to hold there before the next apply
as 3 -c "SELECT authz.share('note', 1001, 'viewer', 'user', 2)" >/dev/null
same "the rule on a column holds on its rows already" "$(as 2 -c "UPDATE ch.notes SET owner_id = 2 WHERE id = 1001")" "ERROR:  changing owner_id of ch.notes 1001 needs: manage"
same "... and their owner still writes them" "$(as 3 -c "$(changed "UPDATE ch.notes SET owner_id = 3, title = 'still carol''s' WHERE id = 1001")")" 1
run apply; is applied && ok "apply is not 'unchanged' then: it applies" || bad "apply after a partition was made" "$out"
same "... and the partition is closed: the app role reads it through its table" "$(as 2 -c "SELECT count(*) FROM ch.notes_top")|$(as 3 -c "SELECT count(*) FROM ch.notes WHERE id = 1001")" "0|1"
same "... lint has nothing more to say of it" "$(PSQL -c "SELECT count(*) FROM authz.lint() WHERE object = 'ch.notes_top'")" 0
same "... Postgres gave it the row triggers itself" "$(triggers ch.notes_top)" "authz_note_col_audit_row authz_note_forget_id authz_update_1"

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
same "the table that inherits has the row triggers after them" "$(D=$DB2 triggers ch.docs_old)" "$rowtriggers"
D=$DB2 as 1 -c "SELECT authz.share('doc', 12, 'editor', 'user', 2)" >/dev/null
same "... and the changed rule holds on its rows" "$(D=$DB2 as 2 -c "UPDATE ch.docs SET title = 'mine' WHERE id = 12")" "ERROR:  changing owner_id, title of ch.docs 12 needs: own"
run push --development; is pushed && ok "push: the same change on the first database" || bad "push" "$out"
same "... where the tables that inherit have the row triggers too" "$(triggers ch.docs_old)|$(triggers ch.docs_older)|$(triggers ch.docs_oldest)" "$rowtriggers|$rowtriggers|$rowtriggers"
same "... and the changed rule holds" "$(as 2 -c "UPDATE ch.docs SET title = 'mine' WHERE id = 21")" "ERROR:  changing owner_id, title of ch.docs 21 needs: own"

echo "-- removed"
run remove --yes
same "remove leaves no trigger on the tables, nor on those under them" \
  "$(PSQL -c "SELECT count(*) FROM pg_trigger g JOIN pg_class c ON c.oid = g.tgrelid WHERE NOT g.tgisinternal AND c.relnamespace = 'ch'::regnamespace")" 0

rm -rf "$T"
[ -z "${KEEP:-}" ] && dropdb "$DB" && dropdb "$DB2"
if [ $fails -eq 0 ]; then echo "children: all passed"; else echo "children: $fails failed"; exit 1; fi

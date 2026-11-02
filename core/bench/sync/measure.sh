#!/usr/bin/env bash
# The sync index's costs on the bench database (setup.sh), in one mode: copied, keyed, after or afterkeyed. From the
# core folder whose command applies it. $2 = big adds the move of half the tree, and the share above it
set -u
MODE=$1
DB=${DB:-authz_sync_bench}
PSQL() { PGOPTIONS="-c client_min_messages=warning" psql -X -q -At -v ON_ERROR_STOP=1 -d "$DB" "$@"; }
now() { date +%s.%N; }
since() { python3 -c "print(f'{($(now) - $1):.2f}')"; }
T='authz_int."folder__linked_into_parent__tree"'
case "$MODE" in
  copied) LINES='sync app.files : view\nsync app.folders\n' ;;
  keyed) LINES='sync app.files : view by folder\nsync app.folders by folder\n' ;;
  after) LINES='sync app.files : view\nsync app.folders\nsync after commit\n' ;;
  afterkeyed) LINES='sync app.files : view by folder\nsync app.folders by folder\nsync after commit\n' ;;
esac
P=/tmp/authz_sync_kb_$MODE.authz
{ cat example/docs.authz; printf "\nsync role authz_sync_engine\n$LINES"; } > "$P"
echo "== $MODE, from $(pwd), load $(cut -d' ' -f1-3 /proc/loadavg)"
# from no index: the policy without sync lines first
python3 cli/rowstile_cli.py --db "dbname=$DB" apply example/docs.authz --force >/dev/null 2>&1 || { echo "apply without sync failed"; exit 1; }
PSQL -c "DROP SCHEMA IF EXISTS proto CASCADE"
a=$(now); out=$(python3 cli/rowstile_cli.py --db "dbname=$DB" apply "$P" 2>&1) || { echo "apply failed: $out"; exit 1; }
echo "applied (the index worked out whole) in $(since "$a") s"
PSQL -c "VACUUM ANALYZE" >/dev/null 2>&1
INH=$(PSQL -c "SELECT to_regclass('authz_sync.inherits') IS NOT NULL")
own=""
[ "$(PSQL -c "SELECT to_regclass('authz_sync.given_own') IS NOT NULL")" = t ] && own="UNION ALL SELECT 'given_own', count(*) FROM authz_sync.given_own"
more=""
[ "$INH" = t ] && more="UNION ALL SELECT 'given', count(*) FROM authz_sync.given $own UNION ALL SELECT 'inherits', count(*) FROM authz_sync.inherits"
PSQL -F ' ' -c "SELECT 'file readers', count(*) FROM authz_sync.file__readers UNION ALL SELECT 'folder readers', count(*) FROM authz_sync.folder__readers
  UNION ALL SELECT 'groups', count(*) FROM authz_sync.groups UNION ALL SELECT 'keys', count(*) FROM authz_sync.keys $more
  UNION ALL SELECT 'keys, the most a user holds', max(n) FROM (SELECT count(*) AS n FROM authz_sync.keys GROUP BY principal_id) k
  UNION ALL SELECT 'keys, the median', percentile_disc(0.5) WITHIN GROUP (ORDER BY n) FROM (SELECT count(*) AS n FROM authz_sync.keys GROUP BY principal_id) k"
PSQL -c "SELECT 'the index on disk: ' || pg_size_pretty(sum(pg_total_relation_size(c.oid))) FROM pg_class c WHERE c.relnamespace = 'authz_sync'::regnamespace AND c.relkind = 'r'"
# the engines' filter, for a user, for the one who reads the most (an org admin)
held="SELECT k.key FROM authz_sync.keys k WHERE k.principal_type = 'user' AND k.principal_id = \$1"
filter="r.key IN ($held)"
[ "$INH" = t ] && filter="$filter OR r.key IN (SELECT i.key FROM authz_sync.inherits i WHERE i.source IN (SELECT g.source FROM authz_sync.given g WHERE g.key IN ($held)))"
for u in 500 1; do
  a=$(now); n=$(PSQL -c "PREPARE f(text) AS SELECT count(*) FROM app.files WHERE id IN (SELECT r.id FROM authz_sync.file__readers r WHERE $filter)" -c "EXECUTE f('$u')")
  echo "the files' filter for user $u: $n files in $(since "$a") s"
  if [ "$INH" = t ]; then
    PSQL -F ' ' -c "SELECT '   ... rows it reads: given', count(*) FROM authz_sync.given WHERE key IN (SELECT key FROM authz_sync.keys WHERE principal_id = '$u')
      UNION ALL SELECT '   ... inherits', count(*) FROM authz_sync.inherits WHERE source IN (SELECT source FROM authz_sync.given WHERE key IN (SELECT key FROM authz_sync.keys WHERE principal_id = '$u'))"
  fi
done
work() { case "$MODE" in after*) wb=$(now); n=$(PSQL -c "SELECT authz.sync_work()"); echo "   ... the worker: $n objects in $(since "$wb") s";; esac; }
pick() {
  read -r F P BELOW <<< "$(PSQL -F ' ' -c "SELECT f.id, f.parent_id, b.n FROM app.folders f JOIN (SELECT ancestor, count(*) AS n FROM $T GROUP BY ancestor) b ON b.ancestor = f.id WHERE f.parent_id IS NOT NULL AND b.n <= $1 ORDER BY b.n DESC LIMIT 1")"
  TARGET=$(PSQL -c "SELECT t.id FROM app.folders t WHERE t.id NOT IN (SELECT descendant FROM $T WHERE ancestor = $F) AND t.id <> $P ORDER BY t.id LIMIT 1")
  FILES=$(PSQL -c "SELECT count(*) FROM app.files WHERE folder_id IN (SELECT descendant FROM $T WHERE ancestor = $F)")
}
written() { PSQL -c "SELECT coalesce(sum(n_tup_ins + n_tup_del), 0) FROM pg_stat_user_tables WHERE schemaname = 'authz_sync' AND relname <> 'pending'"; }
sizes="100 1000"
[ "${2:-}" = big ] && sizes="100 1000 10000"
for size in $sizes; do
  pick "$size"
  w0=$(written); a=$(now); PSQL -c "UPDATE app.folders SET parent_id = $TARGET WHERE id = $F"; a=$(since "$a"); work
  w1=$(written); b=$(now); PSQL -c "UPDATE app.folders SET parent_id = $P WHERE id = $F"; b=$(since "$b"); work
  sleep 1; w2=$(written)
  echo "move of folder $F ($BELOW folders below, $FILES files) and back: $a s, $b s; index rows written $((w1 - w0)), $((w2 - w1))"
done
w0=$(written); a=$(now); PSQL -c "INSERT INTO app.team_members VALUES (5, 999) ON CONFLICT DO NOTHING"; a=$(since "$a"); work
b=$(now); PSQL -c "DELETE FROM app.team_members WHERE team_id = 5 AND user_id = 999"; b=$(since "$b"); work; sleep 1; w1=$(written)
echo "a member joining a team, and leaving: $a s, $b s; index rows written $((w1 - w0))"
for size in $sizes; do
  [ "$size" = 100 ] && continue
  pick "$size"
  w0=$(written); a=$(now); PSQL -c "INSERT INTO authz.shares (object_type, object_id, relation, subject_type, subject_id) VALUES ('folder', '$F', 'viewer', 'user', '999')"; a=$(since "$a"); work
  b=$(now); PSQL -c "DELETE FROM authz.shares WHERE object_type = 'folder' AND object_id = '$F' AND subject_id = '999'"; b=$(since "$b"); work; sleep 1; w1=$(written)
  echo "a share on folder $F ($BELOW folders below, $FILES files), and its revoke: $a s, $b s; index rows written $((w1 - w0))"
done
# a share to someone high up, one to them again below it, then the one above revoked (the one below then counts)
pick 10000
PSQL -c "INSERT INTO authz.shares (object_type, object_id, relation, subject_type, subject_id) VALUES ('folder', '$F', 'viewer', 'user', '998')"; work
LOW=$(PSQL -c "SELECT max(descendant) FROM $T WHERE ancestor = $F")
a=$(now); PSQL -c "INSERT INTO authz.shares (object_type, object_id, relation, subject_type, subject_id) VALUES ('folder', '$LOW', 'viewer', 'user', '998')"; a=$(since "$a"); work
w0=$(written); b=$(now); PSQL -c "DELETE FROM authz.shares WHERE object_type = 'folder' AND object_id = '$F' AND subject_id = '998'"; b=$(since "$b"); work; sleep 1; w1=$(written)
PSQL -c "DELETE FROM authz.shares WHERE subject_id = '998'"; work
echo "a share below one to the same user on folder $F ($BELOW folders below): $a s; the one above revoked: $b s; index rows written $((w1 - w0))"
a=$(now); PSQL -c "UPDATE app.files SET name = name || '.' WHERE id = 12345"; echo "a file's name changed (nothing the index reads): $(since "$a") s"; work
a=$(now); PSQL -c "INSERT INTO app.files (folder_id, owner_id, name) VALUES ($F, 5, 'new')"; echo "a file made: $(since "$a") s"; work
a=$(now); PSQL -c "INSERT INTO app.folders (org_id, parent_id, owner_id, name) VALUES (1, $F, 5, 'new')"; echo "a folder made: $(since "$a") s"; work
a=$(now); echo "authz.sync_verify(): $(PSQL -c 'SELECT authz.sync_verify()') in $(since "$a") s"

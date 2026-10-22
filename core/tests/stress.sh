#!/bin/bash
# stress.sh: 16 clients writing a folder tree at once (create, move, link, unlink, delete, at random places)
# for SECONDS seconds at each isolation level, retrying 40001/40P01 as an app would; afterwards the
# inheritance tables must match a rebuild (authz.verify()). Moves that would make a loop, and deletes of
# folders that still hold something, are refused and count as done.
# Every tree write takes the type-wide lock, so the writes go one at a time and each waits for the queue
# ahead of it: as the random moves make the tree deep, a write can wait tens of seconds on a slow machine
# (a move of a big subtree alone takes about a second). So the limit on a statement, 600 s, is there for a
# write that never ends; how fast a write is, is checked alone afterwards, on the tree the run leaves: the
# biggest moves and links must each take under MOVE_LIMIT seconds (10). The slowest write is said either way.
#   PGHOST=... PGUSER=postgres tests/stress.sh [SECONDS]   (default 60 per isolation level)
set -u
cd "$(dirname "$0")/.."
DB=authz_stress
SECONDS_EACH=${1:-60}
MOVE_LIMIT=${MOVE_LIMIT:-10}
fails=0
W=$(mktemp -d)
# whatever way the suite ends: its database, its files
cleanup() { [ -n "${KEEP:-}" ] || dropdb --force --if-exists "$DB" 2>/dev/null; rm -rf "$W"; }
trap cleanup EXIT
dropdb --if-exists "$DB" 2>/dev/null; createdb "$DB" || exit 1
PGOPTIONS="-c client_min_messages=error" psql -X -q -v ON_ERROR_STOP=1 -d "$DB" -f example/app_schema.sql >/dev/null || exit 1
python3 compile_policy.py example/docs.authz > "$W/docs.sql" || exit 1
PGOPTIONS="-c client_min_messages=error" psql -X -q -v ON_ERROR_STOP=1 -d "$DB" -f "$W/docs.sql" >/dev/null || exit 1
psql -X -q -v ON_ERROR_STOP=1 -d "$DB" >/dev/null <<'SQL' || exit 1
SET client_min_messages = warning;
-- 2,000 more folders under the example's, each under a random earlier one; 100 of them also linked elsewhere
INSERT INTO app.folders (id, org_id, parent_id, owner_id, name)
SELECT i, 1, CASE WHEN i = 100 THEN 1 ELSE 100 + floor(random() * (i - 100))::int END, 1, 'f' || i
FROM generate_series(100, 2099) i;
INSERT INTO app.folder_links SELECT DISTINCT 100 + floor(random() * 2000)::int, 100 + floor(random() * 2000)::int
FROM generate_series(1, 100) ON CONFLICT DO NOTHING;
DELETE FROM app.folder_links WHERE folder_id = parent_id;
SELECT setval(pg_get_serial_sequence('app.folders', 'id'), 1000000);
CREATE SCHEMA stress;
-- runs a write; refusals that are part of the game (a loop, a folder that isn't empty, a duplicate) are fine,
-- while 40001 and 40P01 go back to pgbench, which retries the transaction
CREATE FUNCTION stress.try(stmt text) RETURNS void LANGUAGE plpgsql AS $$
BEGIN
  EXECUTE stmt;
EXCEPTION WHEN check_violation OR foreign_key_violation OR unique_violation THEN NULL;
END $$;
-- runs a write alone, undoes it, and says how long it took (seconds)
CREATE FUNCTION stress.timed(stmt text) RETURNS numeric LANGUAGE plpgsql AS $$
DECLARE
  t0 timestamptz := clock_timestamp();
  took numeric;
BEGIN
  BEGIN
    EXECUTE stmt;
    took := extract(epoch FROM clock_timestamp() - t0);
    RAISE EXCEPTION USING ERRCODE = 'AZS01', MESSAGE = 'undone';
  EXCEPTION WHEN SQLSTATE 'AZS01' THEN NULL;
  END;
  RETURN round(took, 2);
END $$;
-- the three folders with the most below them (not a top one), each moved, then linked, under the deepest folder
-- outside what is below it: [write, seconds]
CREATE FUNCTION stress.biggest_moves() RETURNS TABLE (stmt text, took numeric) LANGUAGE plpgsql AS $$
DECLARE m record;
BEGIN
  FOR m IN
    SELECT f.id, f.parent_id, (
      SELECT t.id FROM app.folders t
      WHERE t.id NOT IN (SELECT c.descendant FROM authz_int."folder__linked_into_parent__tree" c WHERE c.ancestor = f.id)
        AND t.id IS DISTINCT FROM f.parent_id
      ORDER BY (SELECT count(*) FROM authz_int."folder__linked_into_parent__tree" a WHERE a.descendant = t.id) DESC, t.id
      LIMIT 1) AS target
    FROM app.folders f
    JOIN (SELECT ancestor, count(*) AS below FROM authz_int."folder__linked_into_parent__tree" GROUP BY ancestor) b
      ON b.ancestor = f.id
    WHERE f.parent_id IS NOT NULL
    ORDER BY b.below DESC, f.id
    LIMIT 3
  LOOP
    CONTINUE WHEN m.target IS NULL;
    stmt := format('UPDATE app.folders SET parent_id = %s WHERE id = %s', m.target, m.id);
    took := stress.timed(stmt);
    RETURN NEXT;
    stmt := format('INSERT INTO app.folder_links VALUES (%s, %s) ON CONFLICT DO NOTHING', m.id, m.target);
    took := stress.timed(stmt);
    RETURN NEXT;
  END LOOP;
END $$;
SQL
cat > "$W/create.sql" <<'EOF'
\set p random(100, 2099)
SELECT stress.try(format('INSERT INTO app.folders (org_id, parent_id, owner_id, name) VALUES (1, %s, 1, %L)', :p, 'new'));
EOF
cat > "$W/move.sql" <<'EOF'
\set m random(101, 2099)
\set t random(100, 2099)
SELECT stress.try(format('UPDATE app.folders SET parent_id = %s WHERE id = %s', :t, :m));
EOF
cat > "$W/link.sql" <<'EOF'
\set m random(101, 2099)
\set t random(100, 2099)
SELECT stress.try(format('INSERT INTO app.folder_links VALUES (%s, %s) ON CONFLICT DO NOTHING', :m, :t));
EOF
cat > "$W/unlink.sql" <<'EOF'
\set m random(101, 2099)
DELETE FROM app.folder_links WHERE folder_id = :m;
EOF
cat > "$W/delete.sql" <<'EOF'
\set m random(101, 2099)
SELECT stress.try(format('DELETE FROM app.folders WHERE id = %s', :m));
EOF
cat > "$W/pair.sql" <<'EOF'
-- two writes in one transaction, so locks are taken across statements (the deadlock case)
\set m random(101, 2099)
\set t random(100, 2099)
\set p random(100, 2099)
BEGIN;
SELECT stress.try(format('UPDATE app.folders SET parent_id = %s WHERE id = %s', :t, :m));
SELECT stress.try(format('INSERT INTO app.folders (org_id, parent_id, owner_id, name) VALUES (1, %s, 1, %L)', :p, 'new'));
COMMIT;
EOF

for level in "read committed" "repeatable read" "serializable"; do
  # (PGOPTIONS splits on spaces: "read committed" needs its space escaped)
  rm -f "$W"/tx*
  PGOPTIONS="-c default_transaction_isolation=${level// /\\ } -c statement_timeout=600s" pgbench -n -d "$DB" -c 16 -j 4 \
    -T "$SECONDS_EACH" --max-tries=50 -l --log-prefix="$W/tx" -f "$W/create.sql@4" -f "$W/move.sql@2" -f "$W/link.sql@1" \
    -f "$W/unlink.sql@1" -f "$W/delete.sql@1" -f "$W/pair.sql@1" > "$W/out" 2>&1
  tps=$(sed -n 's/^tps = \([0-9.]*\) .*/\1/p' "$W/out")
  retried=$(sed -n 's/^number of transactions retried: \([0-9]*\).*/\1/p' "$W/out")
  failed=$(sed -n 's/^number of failed transactions: \([0-9]*\).*/\1/p' "$W/out")
  aborted=$(grep -c "aborted in command" "$W/out")
  if [ -z "$tps" ]; then
    echo "FAIL  $level: pgbench didn't run: $(head -c 300 "$W/out" | tr '\n' ' ')"; fails=$((fails + 1)); continue
  fi
  # each transaction's time, in microseconds, is the third column of pgbench's log (a word for one that failed)
  slowest=$(cat "$W"/tx* 2>/dev/null | awk '$3 ~ /^[0-9]+$/ && $3 + 0 > m + 0 { m = $3 } END { printf "%.1f", m / 1000000 }')
  echo "info  $level: $tps writes/s for ${SECONDS_EACH}s, ${retried:-0} retried, ${failed:-0} failed after 50 tries, $aborted clients stopped; the slowest took ${slowest}s"
  [ "$aborted" = 0 ] || { echo "FAIL  $level: a client stopped on an error: $(grep -m1 "aborted in command" -A2 "$W/out" | tr '\n' ' ')"; fails=$((fails + 1)); }
  if [ "$(psql -X -At -d "$DB" -c "SELECT authz.verify()")" = t ]; then
    echo "ok    $level: the inheritance tables match a rebuild"
  else
    echo "FAIL  $level: the inheritance tables don't match a rebuild"; fails=$((fails + 1))
  fi
  # the biggest moves on the tree as it is now, each alone
  if ! moves=$(psql -X -At -F ' ' -v ON_ERROR_STOP=1 -d "$DB" -c "SELECT took, stmt FROM stress.biggest_moves()" 2>&1) || [ -z "$moves" ]; then
    echo "FAIL  $level: the biggest moves couldn't be timed: $(echo "$moves" | head -c 300 | tr '\n' ' ')"; fails=$((fails + 1))
  else
    tree=$(psql -X -At -d "$DB" -c "SELECT count(*) || ' folders, ' || (SELECT count(*) FROM authz_int.\"folder__linked_into_parent__tree\") || ' rows in the tree' FROM app.folders")
    worst=$(echo "$moves" | sort -n -r | head -1)
    if awk -v w="${worst%% *}" -v l="$MOVE_LIMIT" 'BEGIN { exit !(w < l) }'; then
      echo "ok    $level: the biggest moves and links, each alone, take under ${MOVE_LIMIT}s ($tree; the slowest: ${worst%% *}s)"
    else
      echo "FAIL  $level: a move or link alone took ${worst%% *}s (the limit is ${MOVE_LIMIT}s; $tree): ${worst#* }"
      fails=$((fails + 1))
    fi
  fi
done

if [ $fails -eq 0 ]; then echo "stress: all passed"; else echo "stress: $fails failed"; exit 1; fi

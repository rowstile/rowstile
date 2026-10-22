#!/bin/bash
# run.sh: the scale benchmark, run inside a rowstile container (bench/scale.sh starts one). Loads the
# example app at scale, applies docs.authz with the rowstile command, then measures
# (the gate's workload: tree writes are 90% folder creates, 9% moves of small folders, 1% links):
#   1. reads through RLS, alone
#   2. tree writes as clients go from 1 to 50: how far does throughput go?
#   3. the gate: 20 tree writes/s arriving steadily, with 400 reads/s at the same time (READ_RATE: another rate)
#   4. one big move (a top folder) during steady writes: how long it takes, and how long others wait
# Settings (environment, all set by scale.sh, which holds the sizes): FILES FOLDERS LEVELS USERS TEAMS DURATION
# GATE_DURATION READ_RATE OUT
# Exits 1 when a gate fails, when authz.verify() doesn't say true after the writes, or when a listing fails.
set -u
cd "$(dirname "$0")/.."
for v in FILES FOLDERS LEVELS USERS TEAMS DURATION GATE_DURATION READ_RATE OUT; do
  [ -n "${!v:-}" ] || { echo "run.sh: $v is not set: start the benchmark with core/bench/scale.sh" >&2; exit 2; }
done
DB=authz_bench
W=bench/workload
LOGS=${LOGS:-/tmp/bench_logs}   # the per-transaction logs (a test sets another place)
PSQL() { psql -X -q -At -v ON_ERROR_STOP=1 -d "$DB" "$@"; }
say() { echo "$*" | tee -a "$OUT"; }
now() { date +%s.%N; }
since() { python3 -c "print(f'{($(now) - $1):.2f}')"; }
wrong=0
: > "$OUT"; rm -rf "$LOGS"; mkdir -p "$LOGS"

say "# rowstile scale benchmark ($(date -u +%Y-%m-%d), $(psql -X -At -d postgres -c 'SHOW server_version' | cut -d' ' -f1), rowstile $(sed -n 's/^__version__ = "\([^"]*\)".*/\1/p' authzlib/__init__.py))"
say "# $FILES files, $FOLDERS folders $LEVELS levels deep, $USERS users, $TEAMS nested teams; $(nproc) CPUs shared by server and pgbench"
say "# $(psql -X -At -d postgres -c "SELECT string_agg(name || '=' || current_setting(name), ', ' ORDER BY name) FROM pg_settings WHERE name IN ('shared_buffers', 'work_mem', 'max_connections', 'jit', 'synchronous_commit')")"
say

dropdb --if-exists "$DB" >/dev/null 2>&1; createdb "$DB" || exit 1
PGOPTIONS="-c client_min_messages=error" psql -X -q -v ON_ERROR_STOP=1 -d "$DB" -f example/app_schema.sql >/dev/null || exit 1

say "== Loading and applying (seconds)"
t=$(now)
psql -X -q -v ON_ERROR_STOP=1 -d "$DB" -v files="$FILES" -v folders="$FOLDERS" -v levels="$LEVELS" \
     -v users="$USERS" -v teams="$TEAMS" -f bench/load.sql >/dev/null || exit 1
PSQL -c "VACUUM ANALYZE" >/dev/null
say "load the app data                       $(since "$t")"
t=$(now)
if ! python3 cli/rowstile_cli.py --db "dbname=$DB" apply example/docs.authz >/dev/null 2>"$LOGS/apply.err"; then
  say "apply docs.authz failed:"; tee -a "$OUT" < "$LOGS/apply.err"; exit 1
fi
say "apply docs.authz, with backfill         $(since "$t")"
t=$(now)
psql -X -q -v ON_ERROR_STOP=1 -d "$DB" -v files="$FILES" -v folders="$FOLDERS" -v users="$USERS" -v teams="$TEAMS" \
     -f bench/shares.sql >/dev/null || exit 1
PSQL -c "VACUUM ANALYZE" >/dev/null
say "load shares, vacuum                     $(since "$t")"
say
say "== Sizes"
PSQL -c "SELECT format('%-40s %s', 'database', pg_size_pretty(pg_database_size(current_database())))" | tee -a "$OUT"
PSQL -c "SELECT format('%-40s %s rows, %s', c.relname, to_char(c.reltuples, 'FM999,999,999'), pg_size_pretty(pg_total_relation_size(c.oid)))
         FROM pg_class c WHERE c.relnamespace = 'authz_int'::regnamespace AND c.relkind = 'r' AND c.reltuples > 1000
         ORDER BY c.reltuples DESC" | tee -a "$OUT"
PSQL -c "SELECT format('%-40s %s rows', 'authz.shares', to_char(count(*), 'FM999,999,999')) FROM authz.shares" | tee -a "$OUT"
# small folders: from 60% of the depth down (at 20 levels, level 12: about 100 folders below each)
SMALL_FIRST=$(PSQL -c "SELECT first_id FROM bench.levels WHERE level = greatest(2, ($LEVELS * 3 + 4) / 5)")
say "$(PSQL -c "SELECT format('folders per level: %s', string_agg((last_id - first_id + 1)::text, ' ' ORDER BY level)) FROM bench.levels")"
say

# A pgbench statement running longer than four measuring periods is cut off (its client stops), as a
# guard against a run that hangs; "timed out" counts those clients, and "aborted" the clients pgbench stopped on
# any other error (a write the rules refuse, a broken script): a broken write path, not a slow one.
PGB=(env PGOPTIONS="-c statement_timeout=$((DURATION * 4))s" pgbench -n -M prepared -d "$DB" -D nusers="$USERS" -D nfiles="$FILES" -D nfolders="$FOLDERS"
     -D small_first="$SMALL_FIRST")
# members three times as often as org admins, who reach every folder (the slowest single-object checks)
READS=(-f "$W/read_file.sql@3" -f "$W/read_folder.sql@3" -f "$W/read_can.sql@3"
       -f "$W/read_file_admin.sql@1" -f "$W/read_folder_admin.sql@1" -f "$W/read_can_admin.sql@1")
READ_NAMES=(open_file open_folder can_edit open_file_adm open_folder_adm can_edit_adm)
WRITES=(-f "$W/write_create.sql@90" -f "$W/write_move.sql@9" -f "$W/write_link.sql@1")
tps() { sed -n 's/^tps = \([0-9.]*\) .*/\1/p' "$1" | head -n 1; }
failed() { sed -n 's/^number of failed transactions: \([0-9]*\).*/\1/p' "$1" | head -n 1; }
TIMEOUT="canceling statement due to statement timeout"
timedout() { grep "aborted in command" "$1" | grep -c "$TIMEOUT"; }
aborted() { grep "aborted in command" "$1" | grep -vc "$TIMEOUT"; }
# share of connected clients waiting on a lock, sampled every half second while pgbench runs
lockwait() {
  local n=0 sum=0
  while kill -0 "$1" 2>/dev/null; do
    v=$(PSQL -c "SELECT coalesce(round(100.0 * count(*) FILTER (WHERE wait_event_type = 'Lock') / nullif(count(*), 0)), 0)
                 FROM pg_stat_activity WHERE datname = current_database() AND backend_type = 'client backend'
                 AND pid <> pg_backend_pid() AND state = 'active'")
    sum=$((sum + v)); n=$((n + 1)); sleep 0.5
  done
  [ $n -gt 0 ] && echo $((sum / n)) || echo 0
}

say "== 1. Reads through RLS, alone ($READ_RATE/s arriving steadily, 16 clients, $DURATION s)"
"${PGB[@]}" -c 16 -j 4 -T "$DURATION" --rate "$READ_RATE" "${READS[@]}" -l --log-prefix="$LOGS/reads" > "$LOGS/reads.out" 2>&1
say "$(tps "$LOGS/reads.out") transactions/s done"
python3 bench/latency.py "$LOGS/reads" "${READ_NAMES[@]}" | tee -a "$OUT"
say

say "== 2. Tree writes as clients grow ($DURATION s each; create 90%, move 9% (small folders), link 1%)"
say "$(printf '%-9s%10s%8s%9s%11s%11s%11s%11s' clients writes/s failed aborted 'timed out' 'p50 ms' 'p95 ms' 'waiting %')"
for c in 1 10 50; do
  "${PGB[@]}" -c "$c" -j "$((c < 8 ? c : 8))" -T "$DURATION" "${WRITES[@]}" -l --log-prefix="$LOGS/w$c" > "$LOGS/w$c.out" 2>&1 &
  pid=$!; wait_pct=$(lockwait $pid); wait $pid
  read -r p50 p95 < <(python3 bench/latency.py "$LOGS/w$c" create move link | awk '$1 == "all" {print $4, $5}')
  say "$(printf '%-9s%10.1f%8s%9s%11s%11s%11s%11s' "$c" "$(tps "$LOGS/w$c.out")" "$(failed "$LOGS/w$c.out")" "$(aborted "$LOGS/w$c.out")" "$(timedout "$LOGS/w$c.out")" "$p50" "$p95" "$wait_pct")"
done
say "per kind of write, 50 clients:"
python3 bench/latency.py "$LOGS/w50" create move link | tee -a "$OUT"
say

say "== 3. The gate: 20 tree writes/s arriving steadily (20 clients) + $READ_RATE reads/s (16 clients), $GATE_DURATION s"
"${PGB[@]}" -c 20 -j 4 -T "$GATE_DURATION" --rate 20 "${WRITES[@]}" -l --log-prefix="$LOGS/gw" > "$LOGS/gw.out" 2>&1 &
wpid=$!
"${PGB[@]}" -c 16 -j 4 -T "$GATE_DURATION" --rate "$READ_RATE" "${READS[@]}" -l --log-prefix="$LOGS/gr" > "$LOGS/gr.out" 2>&1 &
rpid=$!
wait $wpid; wait $rpid
say "writes: $(tps "$LOGS/gw.out")/s done, $(failed "$LOGS/gw.out") failed, $(aborted "$LOGS/gw.out") clients aborted, $(timedout "$LOGS/gw.out") timed out"
python3 bench/latency.py "$LOGS/gw" create move link | tee -a "$OUT"
say "reads: $(tps "$LOGS/gr.out")/s done"
python3 bench/latency.py "$LOGS/gr" "${READ_NAMES[@]}" | tee -a "$OUT"
wp95=$(python3 bench/latency.py "$LOGS/gw" create move link | awk '$1 == "all" {print $NF}')
rp95=$(python3 bench/latency.py "$LOGS/gr" "${READ_NAMES[@]}" | awk '$1 == "all" {print $NF}')
bad=$(( $(failed "$LOGS/gw.out") + $(aborted "$LOGS/gw.out") + $(timedout "$LOGS/gw.out") ))
verdict() { python3 -c "print('pass' if $1 else 'FAIL')"; }
gate() {
  local v; v=$(verdict "$2")
  if [ "$v" != pass ] && ! { [ "${3:-}" = speed ] && [ "${SPEED_GATES:-1}" = 0 ]; }; then wrong=1; fi
  say "$1 -> $v"
}
# the speed limits are the scale gate's, for its size on a machine of its own: SPEED_GATES=0 (regress.sh, a small
# run on a shared CI machine) shows them without failing on them
gate "gate: tree writes p95 < 50 ms (end to end):   $wp95 ms" "float('${wp95:-nan}') < 50" speed
gate "gate: reads p95 < 5 ms (end to end):          $rp95 ms" "float('${rp95:-nan}') < 5" speed
gate "gate: no failed, aborted or timed-out writes: $bad" "$bad == 0"
say

say "== 4. One big move during steady writes (20/s, $GATE_DURATION s): the folder with most below it, into another root"
# the folder (not a root) with the most folders below it by now: earlier writes have reshaped the tree
BIG=$(PSQL -c "SELECT c.ancestor FROM authz_int.\"folder__linked_into_parent__tree\" c JOIN app.folders f ON f.id = c.ancestor WHERE f.parent_id IS NOT NULL GROUP BY 1 ORDER BY count(*) DESC LIMIT 1")
TO=$(PSQL -c "SELECT id FROM app.folders WHERE parent_id IS NULL AND id <> (SELECT parent_id FROM app.folders WHERE id = $BIG) ORDER BY id LIMIT 1")
below=$(PSQL -c "SELECT count(*) - 1 FROM authz_int.\"folder__linked_into_parent__tree\" WHERE ancestor = $BIG")
"${PGB[@]}" -c 20 -j 4 -T "$GATE_DURATION" --rate 20 "${WRITES[@]}" -l --log-prefix="$LOGS/bw" > "$LOGS/bw.out" 2>&1 &
wpid=$!
sleep $((GATE_DURATION / 3))
t=$(now); PSQL -c "UPDATE app.folders SET parent_id = $TO WHERE id = $BIG" >/dev/null; took=$(since "$t")
wait $wpid
say "the big move: folder $BIG with $below folders below it, into folder $TO: $took s"
say "writes meanwhile: $(tps "$LOGS/bw.out")/s done, $(failed "$LOGS/bw.out") failed, $(aborted "$LOGS/bw.out") clients aborted, $(timedout "$LOGS/bw.out") timed out"
python3 bench/latency.py "$LOGS/bw" create move link | tee -a "$OUT"
t=$(now); ok=$(PSQL -c "SELECT authz.verify()")
say "authz.verify() after all the writes: ${ok:-no answer} ($(since "$t") s)"
[ "$ok" = t ] || wrong=1
say

say "== 5. Listing everything a user can see: authz.list('file', 'view'), all of it and one page of 1,000"
for who in "3 org admin" "500 member"; do
  set -- $who; u=$1; shift
  for q in "SELECT count(*) FROM authz.list('file', 'view')" "SELECT count(*) FROM authz.list('file', 'view', NULL, 1000)" \
           "SELECT count(*) FROM authz.list('file', 'view', '$((FILES / 2))', 1000)"; do
    t=$(now); n=$(PSQL -c "SET ROLE app_user" -c "SET authz.user_id = '$u'" -c "$q" | tail -n 1)
    [ -n "$n" ] || wrong=1
    say "$(printf '%-10s %-66s %9s rows %8s s' "$*" "${q#SELECT count(*) FROM }" "$n" "$(since "$t")")"
  done
done
say
exit $wrong

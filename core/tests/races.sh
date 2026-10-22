# races.sh: two sessions put in order by asking the server, not by sleeping, so that a session that starts late on
# a busy server changes nothing (sourced by apply.sh, concurrency.sh, governance.sh, identity.sh, migrations.sh and
# principals.sh; not a suite).
# The first session stops where the race needs it, in $HOLD: a statement that waits until the suite says go. The
# suite waits until it is there (held NAME), has the second session do its part (and, where that one must wait
# behind the first, waits until it does: blocked NAME), then says go, and the first goes on. Each session is named
# by PGAPPNAME=NAME; RACE_DB is the database (else DB).

# makes the go of the next race, not said yet (a sequence: what nextval does, every snapshot sees at once)
race() {
  psql -X -q -v ON_ERROR_STOP=1 -d "${RACE_DB:-$DB}" -c "CREATE SEQUENCE IF NOT EXISTS public.race_go" \
    -c "ALTER SEQUENCE public.race_go RESTART" -c "GRANT SELECT ON public.race_go TO PUBLIC" >/dev/null
}
# waits until the suite says go (a minute at most)
HOLD="DO \$hold\$ BEGIN FOR i IN 1..1200 LOOP EXIT WHEN pg_sequence_last_value('public.race_go') IS NOT NULL;
  PERFORM pg_sleep(0.05); END LOOP; END \$hold\$"
go() { psql -X -q -d "${RACE_DB:-$DB}" -c "SELECT nextval('public.race_go')" >/dev/null; }
# $1 the session's name, $2 what it waits on (a wait_event or a wait_event_type): until it does, a minute at most;
# else a failure of the suite's (its count of fails), which says what it waited for
waits_on() {
  local _
  for _ in $(seq 240); do
    [ "$(psql -X -q -At -d "${RACE_DB:-$DB}" -c "SELECT count(*) FROM pg_stat_activity WHERE datname = current_database()
          AND application_name = '$1' AND '$2' IN (wait_event, wait_event_type)")" -ge 1 ] 2>/dev/null && return 0
    sleep 0.25
  done
  echo "FAIL  the session $1 didn't wait on $2 within a minute"
  fails=$((fails + 1))
  return 1
}
# for a suite's cleanup: what it started in the background and left running (it stopped early) stopped, and
# waited for. Only the last process of each chain is signalled (a psql, a python3, never a server process): the
# shells between it and the suite end as it does, and reap it. One left to end after the suite would be the
# container's first process's to reap, and where that is Postgres, a child it doesn't know that ends on a signal
# or with an error makes it restart.
stop_sessions() {
  local j p sig
  for sig in TERM KILL; do
    [ -n "$(jobs -pr)" ] || break
    for j in $(jobs -pr); do for p in $(race_leaves "$j"); do kill -"$sig" "$p" 2>/dev/null; done; done
    for _ in $(seq 20); do [ -n "$(jobs -pr)" ] || break; sleep 0.25; done
  done
  wait 2>/dev/null
}
# the processes below $1 with none below them (or $1 itself)
race_leaves() {
  local c found=
  for c in $(cat /proc/"$1"/task/*/children 2>/dev/null); do found=1; race_leaves "$c"; done
  [ -n "$found" ] || echo "$1"
}
# the first session is in $HOLD
held() { waits_on "$1" PgSleep; }
# the second session waits on a lock (the first one's)
blocked() { waits_on "$1" Lock; }

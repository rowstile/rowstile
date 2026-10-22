#!/bin/bash
# pooler.sh: PgBouncer in transaction mode in front of a conformance suite's Postgres (POOLER=pgbouncer test.sh).
#   source ../pooler.sh; pooler_start <postgres container> <host port> <user:password>...
# Only the app's URL goes through it (the userlist holds the users given: the suites give the app role alone).
# The owner's (migrations, the command, rowstile test) and the change feed's stay direct, as the operations page
# asks (docs/operations.md, Behind a pooler, which says what this runs). It keeps prepared statements per client
# (max_prepared_statements, PgBouncer 1.21 and newer): a pooler that keeps none, and the drivers' settings for
# it, aren't run here. pooler_stop removes it.
POOLER_IMAGE=edoburu/pgbouncer:v1.26.0-p0

pooler_start() {
  local pg=$1 port=$2; shift 2
  local name="$pg-pgbouncer" dir
  dir=$(mktemp -d)
  docker network create "$pg-net" >/dev/null 2>&1
  docker network connect --alias pg "$pg-net" "$pg" 2>/dev/null
  docker rm -f "$name" >/dev/null 2>&1
  docker image inspect "$POOLER_IMAGE" >/dev/null 2>&1 || docker pull -q "$POOLER_IMAGE" >/dev/null || return 1
  : >"$dir/userlist.txt"
  for up in "$@"; do echo "\"${up%%:*}\" \"${up#*:}\"" >>"$dir/userlist.txt"; done
  cat >"$dir/pgbouncer.ini" <<EOF
[databases]
* = host=pg port=5432
[pgbouncer]
listen_addr = 0.0.0.0
listen_port = 6432
auth_type = scram-sha-256
auth_file = /etc/pgbouncer/userlist.txt
pool_mode = transaction
default_pool_size = 4
max_client_conn = 200
max_prepared_statements = 200
ignore_startup_parameters = extra_float_digits,options
EOF
  # PgBouncer runs as its image's own user (postgres, uid 70): mktemp's folder is the caller's alone
  chmod 755 "$dir" && chmod 644 "$dir"/*
  docker run -d --name "$name" --network "$pg-net" -p "$port:6432" -v "$dir:/etc/pgbouncer:ro" "$POOLER_IMAGE" >/dev/null || return 1
  # ready when PgBouncer itself answers (from the database's container, on their network): Docker's published
  # port accepts a connection even when nothing listens behind it
  for _ in $(seq 30); do
    docker exec "$pg" pg_isready -q -h "$name" -p 6432 2>/dev/null &&
      { echo "PgBouncer in front of $pg on port $port (transaction mode)"; return 0; }
    sleep 1
  done
  echo "PgBouncer didn't start:"
  docker logs "$name" 2>&1 | tail -5
  return 1
}

pooler_stop() {
  docker rm -f "$1-pgbouncer" >/dev/null 2>&1
  docker network disconnect "$1-net" "$1" >/dev/null 2>&1
  docker network rm "$1-net" >/dev/null 2>&1
}

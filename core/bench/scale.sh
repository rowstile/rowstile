#!/bin/bash
# scale.sh: the scale benchmark in a fresh Postgres container; see bench/run.sh.
#   core/bench/scale.sh              # 400k files, 20k folders, 20 levels: the dev size, a few minutes
#   core/bench/scale.sh --large      # 1M files, 50k folders: the gate's size on the laptop of 2026-10 (out of use)
#   core/bench/scale.sh --medium     # 5M files, 250k folders (long)
#   core/bench/scale.sh --full       # 20M files, 1M folders: the scale gate's size; needs 16 GB for Docker
# (--large, --medium and --full have 25 folders for each user and for each team, so one user holds the same at each)
# Environment: KEEP=1 leaves the container running; PG (default 16), SHARED_BUFFERS, FILES FOLDERS LEVELS USERS TEAMS
# DURATION GATE_DURATION (seconds per step, default 20 and 30), OUT. Results go to
# core/bench/results/. Needs Docker and bash.
set -u
cd "$(dirname "$0")/../.."
REPO=$(pwd)
PG=${PG:-16}
case "${1:-}" in
  --full)   FILES=${FILES:-20000000} FOLDERS=${FOLDERS:-1000000} USERS=${USERS:-40000} TEAMS=${TEAMS:-4000}
            SHARED_BUFFERS=${SHARED_BUFFERS:-8GB};;
  --medium) FILES=${FILES:-5000000} FOLDERS=${FOLDERS:-250000} USERS=${USERS:-10000} TEAMS=${TEAMS:-1000};;
  --large)  FILES=${FILES:-1000000} FOLDERS=${FOLDERS:-50000} USERS=${USERS:-2000} TEAMS=${TEAMS:-200};;
  "")       FILES=${FILES:-400000} FOLDERS=${FOLDERS:-20000} USERS=${USERS:-1000} TEAMS=${TEAMS:-100};;
  *)        echo "usage: $0 [--large|--medium|--full]" >&2; exit 2;;
esac
LEVELS=${LEVELS:-20} DURATION=${DURATION:-20} GATE_DURATION=${GATE_DURATION:-30}
# memory for Postgres: 4 GB of shared buffers holds what the sizes up to --medium read; --full's database is 6 GB:
# 8 GB, in a Docker VM of 16 GB (with less the reads fetch pages from the system on every query, and in a VM of
# 6 GB it swaps, which makes every number meaningless)
SETTINGS="-c shared_buffers=${SHARED_BUFFERS:-4GB} -c effective_cache_size=10GB -c work_mem=32MB -c maintenance_work_mem=1GB"
NAME=rowstile-bench-$PG
OUT=${OUT:-core/bench/results/$(date -u +%Y-%m-%d)-${FILES}-files-pg$PG.txt}
mkdir -p core/bench/results
echo "benchmark: $FILES files, $FOLDERS folders, PostgreSQL $PG -> $OUT"

docker build -q -t "rowstile:$PG" --build-arg "PG_MAJOR=$PG" -f core/Dockerfile . >/dev/null || exit 1
docker rm -f "$NAME" >/dev/null 2>&1
# shellcheck disable=SC2086
docker run -d --name "$NAME" --shm-size=1g -e POSTGRES_HOST_AUTH_METHOD=trust -v "$REPO:/src" "rowstile:$PG" \
  $SETTINGS -c max_connections=300 -c max_wal_size=8GB -c checkpoint_timeout=30min -c jit=off >/dev/null || exit 1
for _ in $(seq 60); do docker exec "$NAME" pg_isready -q -h /var/run/postgresql 2>/dev/null && break; sleep 1; done
sleep 3
docker exec -e PGHOST=/var/run/postgresql -e PGUSER=postgres -e FILES="$FILES" -e FOLDERS="$FOLDERS" \
  -e LEVELS="$LEVELS" -e USERS="$USERS" -e TEAMS="$TEAMS" -e DURATION="$DURATION" -e GATE_DURATION="$GATE_DURATION" \
  -e SPEED_GATES="${SPEED_GATES:-1}" -e READ_RATE="${READ_RATE:-400}" \
  -e OUT="/src/$OUT" -w /src/core "$NAME" bash bench/run.sh
rc=$?
if [ -n "${KEEP:-}" ]; then echo "kept container $NAME (database authz_bench)"; else docker rm -f "$NAME" >/dev/null; fi
echo "results: $OUT"
exit $rc

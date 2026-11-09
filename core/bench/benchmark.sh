#!/bin/bash
# benchmark.sh: benchmark.sql (the docs app, bigger) in a fresh Postgres container, as the tables' owner, not a
# superuser (tests/make_owner.sh), with Postgres's own memory settings (128 MB of shared buffers) and JIT off.
#   core/bench/benchmark.sh           # writes core/bench/results/benchmark-latest.txt: the figures of
#                                     # docs/reference/limits.md's speed table, with what ran them in its first lines
# Environment: PG (default 16), OUT. Needs Docker and bash; a few minutes. On GitHub's runners:
# `gh workflow run nightly.yml -f only=speed` (its file is the run's `speed` artifact).
set -u
cd "$(dirname "$0")/../.."
REPO=$(pwd)
PG=${PG:-16}
NAME=rowstile-benchmark-$PG
OUT=${OUT:-core/bench/results/benchmark-latest.txt}
mkdir -p core/bench/results

docker build -q -t "rowstile:$PG" --build-arg "PG_MAJOR=$PG" -f core/Dockerfile . >/dev/null || exit 1
docker rm -f -v "$NAME" >/dev/null 2>&1
trap 'docker rm -f -v "$NAME" >/dev/null 2>&1' EXIT
docker run -d --name "$NAME" --shm-size=1g -e POSTGRES_HOST_AUTH_METHOD=trust -v "$REPO:/src" "rowstile:$PG" \
  -c jit=off >/dev/null || exit 1
for _ in $(seq 60); do docker exec "$NAME" pg_isready -q -h 127.0.0.1 2>/dev/null && break; sleep 1; done
docker exec -e PGHOST=/var/run/postgresql -e PGUSER=postgres -w /src/core "$NAME" bash tests/make_owner.sh || exit 1
owner() { docker exec -e PGHOST=/var/run/postgresql -e PGUSER=authz_owner -w /src/core "$NAME" "$@"; }
owner createdb authz_benchmark || exit 1
owner psql -X -q -v ON_ERROR_STOP=1 -d authz_benchmark -f example/app_schema.sql >/dev/null || exit 1
owner bash -c "python3 compile_policy.py example/docs.authz > /tmp/docs.sql" || exit 1
{
  echo "# bench/benchmark.sql on PostgreSQL $(owner psql -X -At -d postgres -c 'SHOW server_version'), $(date -u +%Y-%m-%d),"
  echo "# commit $(git rev-parse --short=8 HEAD) ($(python3 -c 'import sys; sys.path.insert(0, "core"); import authzlib; print(authzlib.__version__)')),"
  echo "# $(nproc) CPUs ($(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | sed 's/^ *//')), $(owner psql -X -At -d postgres -c 'SHOW shared_buffers') of shared buffers"
  echo
  owner psql -X -v ON_ERROR_STOP=1 -v docs_sql=/tmp/docs.sql -d authz_benchmark -f bench/benchmark.sql
} > "$OUT.part" || { cat "$OUT.part"; rm -f "$OUT.part"; exit 1; }
mv "$OUT.part" "$OUT"
cat "$OUT"

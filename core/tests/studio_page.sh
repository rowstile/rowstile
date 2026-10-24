#!/bin/bash
# studio_page.sh: Studio's page in a browser (tests/studio_page.mjs), on a Postgres of its own: a container of
# rowstile:16 (core/Dockerfile), on a port Docker picks, removed after. Studio and the browser run here, beside it:
# python3, node and Chrome (CI's studio-page job; GitHub's runners have Chrome).
#   docker build -t rowstile:16 --build-arg PG_MAJOR=16 -f core/Dockerfile . && bash core/tests/studio_page.sh [chrome]
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
NAME="rowstile-studio-page-$$"
trap 'docker rm -f -v "$NAME" >/dev/null 2>&1 || true' EXIT
docker run -d --name "$NAME" -p 127.0.0.1::5432 -e POSTGRES_HOST_AUTH_METHOD=trust \
  -v "$(dirname "$(dirname "$HERE")"):/src" rowstile:16 >/dev/null
# ready when the server answers on its socket, past the image's first start (initdb, then a restart)
for _ in $(seq 60); do
  docker exec "$NAME" pg_isready -q -h 127.0.0.1 -U postgres 2>/dev/null && break
  sleep 1
done
docker exec -e PGHOST=/var/run/postgresql -e PGUSER=postgres -w /src/core "$NAME" bash tests/make_owner.sh
PORT=$(docker port "$NAME" 5432/tcp | head -1 | sed 's/.*://')
PGHOST=127.0.0.1 PGPORT=$PORT PGUSER=authz_owner node "$HERE/studio_page.mjs" "$@"

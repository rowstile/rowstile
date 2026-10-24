#!/bin/bash
# The messenger's tests: the database (rowstile from this repository) in Docker, the API tests on the host.
#   examples/messenger/test.sh [pytest args]     KEEP=1 leaves the database running
set -u
cd "$(dirname "$0")"
export MS_ADMIN_URL=postgresql://ms_owner:ms_owner@localhost:25433/messenger MS_APP_PASSWORD=ms_app
export MS_DATABASE_URL=postgresql://ms_app:ms_app@localhost:25433/messenger
python3 check_public_surface.py || exit 1
# every change to db/policy.authz has its migration (rowstile migrate writes it)
python3 ../../core/cli/rowstile_cli.py migrate --check || exit 1
docker compose down -v >/dev/null 2>&1        # a new database each time: migrations run from the start
here=$(pwd)
trap '[ -n "${KEEP:-}" ] || (cd "$here" && docker compose down -v)' EXIT    # however the run ends
docker compose up -d --build --wait db || exit 1
cd backend
rc=0
uv run python ../db/migrate.py --client || exit 1
if ! git diff --quiet -- app/authz_client.py; then
  echo "app/authz_client.py was out of date with db/policy.authz (now rewritten: commit it)"; rc=1
fi
# the policy's own tests (db/tests/*.authz, named in rowstile.toml), as many as the README says, then the API
out=$(uv run python ../../../core/cli/rowstile_cli.py test) || rc=1
echo "$out"
n=$(echo "$out" | sed -n 's/^policy tests passed (\([0-9]*\) checks)$/\1/p')
if ! grep -q "runs them: $n checks" ../README.md; then
  echo "README.md says another number of checks than rowstile test ran ($n)"; rc=1
fi
uv run pytest -q "$@" || rc=1
exit $rc

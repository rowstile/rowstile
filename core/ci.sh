#!/bin/bash
# ci.sh: every test, on every supported PostgreSQL version, each in its own container.
#   core/ci.sh                 # PostgreSQL 16, 17 and 18, run_tests.sh --quick in each
#   core/ci.sh --full 16       # the full run_tests.sh, on 16 only
#   core/ci.sh --proofs 16     # the race and stress tests (short), on 16 only
#   core/ci.sh --short 17 18   # what depends on the version (run_tests.sh --short), on 17 and 18
#   SOAK_SEED=N core/ci.sh --soak 16   # the random checks, long, with a new seed (run_tests.sh --soak; SMALL_SLICE too)
#   ROWSTILE_PART=command core/ci.sh 16   # one part of a run (run_tests.sh names them): CI runs the parts side by side
#   ROWSTILE_LANES=1 core/ci.sh 16      # each step after the other (run_tests.sh runs a part's steps in lanes)
#   ROWSTILE_UPGRADES=every core/ci.sh 16   # upgrades from every release on PyPI, not only the one before (nightly)
#   core/ci.sh --coverage 16   # (before the others) and measure what the suites run, in the image built with
#                              # COVERAGE=1: .ci/coverage-16 holds the data, and the report (tests/coverage_report.py)
#   core/ci.sh --statements 16 # --coverage, and each statement and branch of rowstile's PL/pgSQL the suites run
#                              # (plpgsql_check's profiler, preloaded: tests/coverage_plpgsql.py; nightly)
# Needs Docker and bash (Git Bash works on Windows). Builds rowstile:<version> from Dockerfile,
# mounts the repository, runs the tests in it and removes the container. Exit status: 0 only if
# every version passed.
set -u
cd "$(dirname "$0")/.."
export MSYS_NO_PATHCONV=1           # Git Bash: don't rewrite /src into a Windows path
REPO=$(pwd -W 2>/dev/null || pwd)
COVERAGE=""; if [ "${1:-}" = --coverage ]; then COVERAGE=1; shift; fi
STATEMENTS=""; if [ "${1:-}" = --statements ]; then COVERAGE=1; STATEMENTS=1; shift; fi
MODE=--quick
case "${1:-}" in --full) MODE=""; shift;; --proofs) MODE=--proofs; shift;; --short) MODE=--short; shift;; --soak) MODE=--soak; shift;; esac
VERSIONS=${*:-16 17 18}
# how long one version's suites may take, on the clock: two hours; the soak three and a half (its random
# policies alone may take one, and it shares the machine with the night's other jobs)
LIMIT=7200; [ "$MODE" = --soak ] && LIMIT=12600
failed=()
# where the logs go: /tmp, or ROWSTILE_CI_LOGS (CI gives each job its own: self-hosted runners may share a machine)
LOGS=${ROWSTILE_CI_LOGS:-/tmp}
name=""
# with Docker Desktop, each docker command in WSL crosses to the engine over a link that drops connections held
# long under load: the suites run detached, and write their log and exit code into the mounted checkout (.ci/)
mkdir -p .ci
# a docker command, again when the link to the engine fails (up to 5 tries)
retry() { local n; for n in 1 2 3 4 5; do "$@" && return 0; sleep $((n * 2)); done; return 1; }
# a run stopped half way (Ctrl-C, a cancelled CI job) removes its container too, and the database's volume
trap '[ -z "$name" ] || docker rm -f -v "$name" >/dev/null 2>&1' EXIT
trap 'exit 130' INT TERM
for v in $VERSIONS; do
  echo "=== PostgreSQL $v"
  image="rowstile:$v${COVERAGE:+-coverage}"
  if ! docker build -q -t "$image" --build-arg "PG_MAJOR=$v" ${COVERAGE:+--build-arg COVERAGE=1} -f core/Dockerfile . >/dev/null; then
    echo "--- FAILED: building the image"; failed+=("$v (build)"); continue
  fi
  name="rowstile-ci-$v-$$"
  # labelled with the job (ROWSTILE_CI_JOB in CI), whose cleanup removes only its own
  # The server doesn't wait for the disk: the databases last as long as the container, and no suite stops the
  # server to see what it kept. What the suites check is the same, sooner (they make and drop many databases).
  # (measuring, Postgres also counts the calls of every function: track_functions; with --statements, plpgsql_check's
  # profiler the statements of each PL/pgSQL one, in shared memory, tests/coverage_plpgsql.py, its warnings about
  # cursors left open off, so the suites see what they see without it). wal_level = logical: a database can publish
  # to another of the same server (tests/governance.sh copies the audit trail by a subscription)
  retry docker run -d --name "$name" --label "rowstile.ci=${ROWSTILE_CI_JOB:-local}" -e POSTGRES_HOST_AUTH_METHOD=trust -v "$REPO:/src" "$image" \
    -c fsync=off -c synchronous_commit=off -c full_page_writes=off -c wal_level=logical \
    ${COVERAGE:+-c track_functions=all} ${STATEMENTS:+-c shared_preload_libraries=plpgsql_check -c plpgsql_check.profiler=on} \
    ${STATEMENTS:+-c plpgsql_check.cursors_leaks=off -c plpgsql_check.max_stats_size=204800} >/dev/null || { failed+=("$v (start)"); continue; }
  for _ in $(seq 60); do docker exec "$name" pg_isready -q -h /var/run/postgresql 2>/dev/null && break; sleep 1; done
  sleep 2                              # the image's entrypoint restarts the server once after initdb
  out=".ci/$name"; rm -f "$out.log" "$out.rc"
  # with --coverage, where the suites measure: .ci/coverage-<version> in the checkout, emptied first (from inside:
  # on Linux the container's files are root's)
  cov=${COVERAGE:+/src/.ci/coverage-$v}
  # Python keeps the code it compiles, in the container (never the mounted checkout): each of the suites' hundreds
  # of Python processes starts sooner. The image keeps it off: anything that rewrites authzlib's files (a mutation
  # tried on them) must run without it, as Python knows a stale file by its size and its time to the second
  retry docker exec -d -e PYTHONPYCACHEPREFIX=/tmp/pycache -e PYTHONDONTWRITEBYTECODE= -e SOAK_SEED="${SOAK_SEED:-}" -e SMALL_SLICE="${SMALL_SLICE:-}" -e ROWSTILE_PART="${ROWSTILE_PART:-}" -e ROWSTILE_UPGRADES="${ROWSTILE_UPGRADES:-}" -e ROWSTILE_COVERAGE="$cov" -e ROWSTILE_COVERAGE_STATEMENTS="$STATEMENTS" -e PGHOST=/var/run/postgresql -e PGUSER=postgres -w /src/core "$name" \
    bash -c "${cov:+rm -rf $cov; }ROWSTILE_LANES='${ROWSTILE_LANES:-}' bash run_tests.sh $MODE > /src/$out.log 2>&1; echo \$? > /src/$out.rc" || { failed+=("$v (start)"); continue; }
  # the exit code appears when the suites end; a container that stopped or went first ends the wait too, and so
  # does the limit
  started=$SECONDS; why=""
  while [ ! -f "$out.rc" ]; do
    sleep 5; waited=$((SECONDS - started))
    [ -f "$out.rc" ] && break
    state=$(retry docker inspect -f '{{.State.Running}}' "$name" 2>/dev/null) || state="not there"
    if [ "$state" != true ]; then why="the container stopped before the suites ended (running: $state, after ${waited}s)"
    elif [ "$waited" -ge "$LIMIT" ]; then why="the suites were still running after ${waited}s (the limit is ${LIMIT}s): stopped there"
    else continue; fi
    [ -f "$out.rc" ] && { why=""; break; }
    echo 1 > "$out.rc"
  done
  rc=$(cat "$out.rc")
  # each suite passed as many checks as tests/check_counts.txt says (tests/check_counts.py, on the log, in the
  # container: its python3)
  counts=$(docker exec -w /src/core "$name" python3 tests/check_counts.py "/src/$out.log" 2>&1) ||
    { [ "$rc" -ne 0 ] || rc=1; }
  cp "$out.log" "$LOGS/rowstile-ci-$v.log"; rm -f "$out.log" "$out.rc"
  # said in the copy: the log itself was made inside the container (by root, on Linux), and this user can't add to it
  printf '%s\n' "$counts" >> "$LOGS/rowstile-ci-$v.log"
  [ -z "$why" ] || echo "FAILED: $why" >> "$LOGS/rowstile-ci-$v.log"
  grep -E "^(--- |ALL PASSED|FAILED|check counts: )" "$LOGS/rowstile-ci-$v.log"
  [ $rc -eq 0 ] || failed+=("$v")
  # what the suites ran: the totals here, each file's beside the log, what nothing runs in .ci/coverage-<version>
  if [ -n "$COVERAGE" ]; then
    if docker exec -w /src/core "$name" python3 tests/coverage_report.py "$cov" > "$LOGS/rowstile-coverage-$v.txt" 2>&1; then
      grep "^run: " "$LOGS/rowstile-coverage-$v.txt" | sed "s/^/coverage, PostgreSQL $v: /"
    else
      cat "$LOGS/rowstile-coverage-$v.txt"; echo "--- FAILED: the coverage report"; failed+=("$v (coverage)")
    fi
  fi
  retry docker rm -f -v "$name" >/dev/null 2>&1; name=""
done
echo
if [ ${#failed[@]} -eq 0 ]; then echo "CI PASSED on PostgreSQL $VERSIONS"; else
  echo "CI FAILED on PostgreSQL ${failed[*]} (logs: $LOGS/rowstile-ci-<version>.log)"; exit 1; fi

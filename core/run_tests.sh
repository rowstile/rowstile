#!/bin/bash
# run_tests.sh: every test, from scratch, against the Postgres the PG* variables point at.
#   PGHOST=... PGPORT=... PGUSER=postgres ./run_tests.sh           # the full run (long)
#   ./run_tests.sh --quick                                         # meant to stay under 10 minutes
#   ./run_tests.sh --proofs                                        # every order of two tree writes, and the stress test (short)
#   ./run_tests.sh --short                                         # what depends on the Postgres version: --quick
#                         without the checks that need no database, one random-change run, no migrate vs apply
#   SOAK_SEED=N ./run_tests.sh --soak                              # the random checks (random policies too), long, with a new seed
#                         (about 110 minutes; a random seed if SOAK_SEED is empty; the log says which)
#   ROWSTILE_PART=command ./run_tests.sh --quick                   # one part of a run (below: the parts of each)
#   ROWSTILE_LANES=1 ./run_tests.sh --quick                        # each step after the other (below: lanes)
#   ROWSTILE_COVERAGE=/abs/dir ./run_tests.sh --quick              # also measure what the suites run (below)
#   ROWSTILE_UPGRADES=every ./run_tests.sh --quick                 # upgrades from every release, not only the one before
# Needs psql, createdb, dropdb and python3. Creates and drops databases named authz_*, as a non-superuser.
# Each step's result line says how long it took.
set -u
cd "$(dirname "$0")"
# Every suite runs as a non-superuser owner, as on managed Postgres. Started as a superuser, this
# makes one (authz_owner: LOGIN, CREATEDB, CREATEROLE, and SET on the roles it creates) and runs again as it;
# PGSUPERUSER names the superuser for the few checks that a superuser's connection is refused.
if [ "$(psql -X -At -d postgres -c "SELECT rolsuper FROM pg_roles WHERE rolname = current_user")" = t ]; then
  PGSUPERUSER=$(psql -X -At -d postgres -c "SELECT current_user")
  bash tests/make_owner.sh || exit 1
  echo "running as authz_owner, not the superuser $PGSUPERUSER"
  exec env PGSUPERUSER="$PGSUPERUSER" PGUSER=authz_owner bash "$PWD/run_tests.sh" "$@"
fi
MODE=full; case "${1:-}" in --quick) MODE=quick;; --proofs) MODE=proofs;; --short) MODE=short;; --soak) MODE=soak;; esac
STEPS=100; [ "$MODE" = quick ] || [ "$MODE" = short ] && STEPS=15
# --short leaves out what reads no database (the same on every version) and the longest cross-checks
every_version() { [ "$MODE" != short ]; }
DB=authz_tests
failed=()
# The parts of a run: CI runs them side by side, each on a runner and in a container of its own, and the run
# is as long as its longest part. ROWSTILE_PART names the one to run (none: the whole run, one part after the
# other). The workflows list them, and tests/unit_test.py checks they leave none out.
# (unit: the checks without a database, alone, so that the longest part doesn't wait for them; --short has none)
PARTS_SUITES="unit policy command random"                 # --quick, --short and the full run
PARTS_SOAK="changes-1 changes-2 policies around races"    # --soak
case "$MODE" in
  soak) PARTS=$PARTS_SOAK;; proofs) PARTS=races;; full) PARTS="$PARTS_SUITES races";;
  short) PARTS=${PARTS_SUITES#unit };; *) PARTS=$PARTS_SUITES;;
esac
PART=${ROWSTILE_PART:-}
case " $PARTS " in *" ${PART:-${PARTS%% *}} "*) ;; *) echo "no part '$PART' in this run: its parts are $PARTS"; exit 2;; esac
[ -z "$PART" ] || echo "part $PART (of: $PARTS)"
part() { [ -z "$PART" ] || [ "$PART" = "$1" ]; }
# ROWSTILE_COVERAGE=DIR: each Python process the suites start measures which lines and branches of authzlib and
# cli it runs, into DIR, each one marked with the step that ran it (tests/coverage.ini). It needs coverage.py: the
# image core/Dockerfile builds with COVERAGE=1 has it, and core/ci.sh --coverage uses that image. Each database is
# also asked, before it is dropped, which of rowstile's functions were called in it (tests/coverage-bin wraps
# createdb and dropdb; Postgres counts them with track_functions = all, which ci.sh --coverage sets).
# python3 tests/coverage_report.py DIR then says what nothing runs.
if [ -n "${ROWSTILE_COVERAGE:-}" ]; then
  mkdir -p "$ROWSTILE_COVERAGE/data" && ROWSTILE_COVERAGE=$(cd "$ROWSTILE_COVERAGE" && pwd) || exit 1
  export ROWSTILE_COVERAGE COVERAGE_PROCESS_START="$PWD/tests/coverage.ini" ROWSTILE_COVERAGE_CODE="$PWD"
  export ROWSTILE_COVERAGE_CONTEXT="" PATH="$PWD/tests/coverage-bin:$PATH"
  echo "measuring what the suites run, into $ROWSTILE_COVERAGE"
fi
STEPS_RUN=0
step() { echo; echo "=== $1"; STEP_START=$SECONDS; STEPS_RUN=$((STEPS_RUN + 1)); ROWSTILE_COVERAGE_CONTEXT=$1; }
record() {
  local took="($((SECONDS - STEP_START))s)"
  if [ "$1" -eq 0 ]; then echo "--- passed: $2 $took"; else echo "--- FAILED: $2 $took"; failed+=("$2"); fi
  [ -z "${LANE_OUT:-}" ] || lane_next "$1" "$2"
}
# the steps of a part run in lanes side by side (tests/lanes.sh: ROWSTILE_LANES, 3 unless it says; 1: each step
# after the other, as written here)
. tests/lanes.sh
# app_user: the suites' schemas make it when it isn't there, and two doing so at once collide. tests/make_owner.sh
# makes it; here too when started as the owner
[ "$LANES" -eq 1 ] || psql -X -q -v ON_ERROR_STOP=1 -d postgres -c "DO \$o\$ BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'app_user') THEN CREATE ROLE app_user NOLOGIN; END IF;
  END \$o\$" >/dev/null || exit 1
apply() { PGOPTIONS="-c client_min_messages=error" psql -X -q -v ON_ERROR_STOP=1 -d "$DB" -f "$1"; }
# a suite's output without a line for each check it passed, but how many it passed: the log stays short, and
# tests/check_counts.py (which core/ci.sh runs on the log) still sees how many each suite passed
quiet_ok() { awk '/^ok/ {n++; next} {print} END {print n + 0 " checks passed"}'; }

# --soak: the parser fuzzer and every random-change run, longer and with a seed of their own, then the race
# and stress tests below, longer too. Nightly runs it with the run's id, so each night tries new cases.
if [ "$MODE" = soak ]; then
  SEED=${SOAK_SEED:-$RANDOM}
  echo "seed $SEED (again: SOAK_SEED=$SEED ./run_tests.sh --soak)"
  if part policies; then
  step "broken policies are refused with a line number, never a crash (200000 cases, seed $SEED)"
  python3 tests/fuzz_parser.py --cases 200000 --seed "$SEED"
  record $? "fuzz parser"
  step "simple conditions read as Postgres reads them (50000 made up, seed $SEED)"
  python3 tests/conditions_test.py --cases 50000 --seed "$SEED"
  record $? "conditions"
  fi
  for gen in docs alt multi composite loop cross; do
    # two parts, about as long as each other
    case "$gen" in docs|multi) part changes-1;; *) part changes-2;; esac || continue
    step "random changes, compared with the reference evaluator ($gen, 500 changes, seed $SEED)"
    python3 tests/difftest.py --gen "$gen" --steps 500 --seed "$SEED" --quiet --db "authz_diff_$gen" --decisions
    record $? "difftest $gen"
    dropdb --if-exists "authz_diff_$gen" >/dev/null 2>&1
  done
  if part policies; then
  step "random policies, compared with the reference evaluator (100 policies, seeds from $((SEED * 1000)))"
  python3 tests/genpolicy.py --policies 100 --steps 10 --seed "$((SEED * 1000))" --db authz_genpolicy --decisions
  record $? "genpolicy"
  dropdb --if-exists authz_genpolicy >/dev/null 2>&1
  step "random policies rewritten: the review's \"grants the same\" against the database's answers (40 policies, seeds from $((SEED * 1000)))"
  python3 tests/rewrites.py --policies 40 --seed "$((SEED * 1000))" --db authz_rewrites
  record $? "rewrites"
  step "random policies written another way and their data renumbered: the same SQL and answers (20 policies, seeds from $((SEED * 1000)))"
  python3 tests/invariance.py --policies 20 --seed "$((SEED * 1000))" --db authz_invariance
  record $? "invariance"
  fi
  if part around; then
  step "random policies in random worlds: the catalog, the session and the role around them (60, seeds from $((SEED * 1000)))"
  python3 tests/around.py --policies 60 --steps 8 --seed "$((SEED * 1000))" --db authz_around
  record $? "around"
  fi
fi

if [ "$MODE" != proofs ] && [ "$MODE" != soak ]; then
# Each unit below is a function, then `unit PART SECONDS FUNCTION`: its seconds, one unit after the other with
# coverage on (as CI runs), only balance the lanes
if every_version && part unit; then
unit_tests() {
step "fast checks without a database: golden SQL, included files, the command's SQL, rowstile command"
python3 tests/unit_test.py 2>&1 | tail -n 3
record "${PIPESTATUS[0]}" "unit"
}
unit unit 80 unit_tests
# (in this part, the shortest, though it needs a database: in the command part it made that part the longest)
interrupt() {
step "the command and a migration cut half way: a sample of the statements of each"
python3 tests/interrupt.py
record $? "cuts half way"
}
unit unit 90 interrupt
invariance_sql() {
step "the fixed policies written another way (reordered, in included files, laid out and formatted): the same SQL"
python3 tests/invariance.py --fixed
record $? "invariance of the fixed policies"
}
unit unit 10 invariance_sql
fi
if part policy; then
if every_version; then
fuzz_parser() {
step "broken policies are refused with a line number, never a crash (mutated example policies)"
FUZZ=5000; [ "$MODE" = quick ] && FUZZ=1500
python3 tests/fuzz_parser.py --cases "$FUZZ"
record $? "fuzz parser"
}
unit policy 11 fuzz_parser
fi

# one unit: they share the database authz_tests and the files /tmp/authz_docs*.sql
scenarios() {
step "compile the example policy"
python3 compile_policy.py example/docs.authz > /tmp/authz_docs.sql &&
python3 compile_policy.py example/docs.authz --tests > /tmp/authz_docs_tests.sql
record $? "compile"

step "end-to-end scenario through RLS (tests/scenario.sql + the tests in docs.authz)"
dropdb --if-exists "$DB" >/dev/null 2>&1; createdb "$DB"
apply example/app_schema.sql && apply /tmp/authz_docs.sql &&
psql -X -q -v ON_ERROR_STOP=1 -v docs_tests=/tmp/authz_docs_tests.sql -d "$DB" -f tests/scenario.sql > /tmp/authz_scenario.log 2>&1
rc=$?; echo "$(grep -c 'ok  ' /tmp/authz_scenario.log) checks passed"; grep "FAIL\|ERROR" /tmp/authz_scenario.log
record $rc "scenario"

step "re-applying the policy keeps shares and stays consistent"
psql -X -q -d "$DB" -c "SELECT count(*) FROM authz.shares" -At > /tmp/authz_shares_before
apply /tmp/authz_docs.sql && apply /tmp/authz_docs.sql &&
[ "$(psql -X -q -d "$DB" -At -c 'SELECT count(*) FROM authz.shares')" = "$(cat /tmp/authz_shares_before)" ] &&
[ "$(psql -X -q -d "$DB" -At -c 'SELECT authz.verify()')" = "t" ]
record $? "re-apply"
tests/keep.sh >/tmp/authz_keep.log 2>&1; rc=$?; echo "$(grep -c '^ok' /tmp/authz_keep.log) checks passed"
grep "FAIL" /tmp/authz_keep.log
record $rc "keep unchanged trees"
dropdb "$DB"

step "the share API and newer features (tests/multi_scenario.sql on tests/multi.authz)"
dropdb --if-exists "$DB" >/dev/null 2>&1; createdb "$DB"
python3 compile_policy.py tests/multi.authz > /tmp/authz_multi.sql &&
apply tests/multi_schema.sql && apply /tmp/authz_multi.sql &&
psql -X -q -v ON_ERROR_STOP=1 -d "$DB" -f tests/multi_scenario.sql > /tmp/authz_multi_scenario.log 2>&1
rc=$?; echo "$(grep -c 'ok  ' /tmp/authz_multi_scenario.log) checks passed"; grep "FAIL\|ERROR" /tmp/authz_multi_scenario.log
record $rc "multi scenario"
dropdb "$DB"
}
unit policy 9 scenarios

if every_version; then
policy_errors() {
step "policy mistakes are reported with line numbers"
python3 tests/policy_errors.py | tail -n 1
record "${PIPESTATUS[0]}" "policy errors"
}
unit policy 7 policy_errors
fi

identities() {
step "identities: scopes, API keys, JWT, view as, group sync, signed sessions"
tests/identity.sh
record $? "identity"
tests/principals.sh
record $? "principals"
tests/sessions.sh
record $? "signed sessions"
}
unit policy 32 identities

governance() {
step "governance: audit trail, change feed, requests, break glass, reviews, invariants, policy diff"
tests/governance.sh
record $? "governance"
}
unit policy 22 governance

masks() {
step "masked columns: applying, lint, --diff"
tests/masks.sh
record $? "masks"
}
unit policy 7 masks

tools() {
step "developer tools: diagram, Python and TypeScript clients, editor grammar"
python3 tests/tools_test.py
record $? "tools"
if every_version; then
  python3 tests/lsp_test.py | quiet_ok
  record "${PIPESTATUS[0]}" "language server"
fi
}
unit policy 13 tools

fi
if part command; then
apply_() {
step "applying with the rowstile command: no extension, no superuser, includes, diff, backup and restore, remove"
tests/apply.sh
record $? "apply"
}
unit command 76 apply_
cli() {
step "the rowstile command"
tests/cli.sh
record $? "cli"
}
unit command 48 cli
capitals() {
step "the command over tables named as Prisma names them: capital letters, in public"
tests/capitals.sh
record $? "capitals"
}
unit command 14 capitals
children() {
step "tables under a governed one: partitions, and tables that inherit"
tests/children.sh
record $? "children"
}
unit command 8 children
migrations() {
step "policy changes as migrations: each tool's files, in order, out of order, push, trees built beside"
tests/migrations.sh
record $? "migrations"
}
unit command 47 migrations
# ROWSTILE_UPGRADES=every (nightly): from every release on PyPI older than this version, each with a world of data
# that this version's answers on it are judged by; else from the release before
if [ "${ROWSTILE_UPGRADES:-}" = every ]; then
upgrade() {
step "upgrading from every release (from PyPI): the docs app's databases and a world of data, upgraded by this version"
tests/upgrade.sh --every
record $? "upgrade from every release"
}
unit command 540 upgrade
else
upgrade() {
step "upgrading: databases the release before made (from PyPI), pushed to, applied and migrated by this version"
tests/upgrade.sh
record $? "upgrade"
}
unit command 16 upgrade
fi
review() {
step "rowstile review and fmt: a pull request in a git repository, with a review database"
tests/review.sh
record $? "review"
}
unit command 48 review
if every_version; then
migrate_vs_apply() {
step "a migration leaves what applying the new policy whole leaves (each kind of change, both ways)"
python3 tests/migrate_test.py | quiet_ok
record "${PIPESTATUS[0]}" "migrate vs apply"
}
unit command 95 migrate_vs_apply
fi
fi
if part policy; then
confidence() {
step "prove, coverage, snapshots, indexes, plans and bench"
python3 tests/confidence_test.py | quiet_ok
record "${PIPESTATUS[0]}" "confidence"
}
unit policy 12 confidence
studio() {
step "why, and how to grant; Studio (read-only, and able to write)"
python3 tests/studio_test.py | quiet_ok
record "${PIPESTATUS[0]}" "studio"
}
unit policy 52 studio
mcp() {
step "the MCP server, for coding agents: check, prove, push, test, why, lint"
python3 tests/mcp_test.py | quiet_ok
record "${PIPESTATUS[0]}" "mcp"
}
unit policy 8 mcp
devx() {
step "day to day: named tests, refusals that say why, who_among, init, dev, --as"
tests/devx.sh
record $? "devx"
}
unit policy 108 devx

concurrency() {
step "concurrent changes to the tree"
tests/concurrency.sh
record $? "concurrency"
}
unit policy 10 concurrency
# every order of two tree writes in READ COMMITTED (the full run has every level, in the races part below)
if [ "$MODE" != full ]; then
interleavings_rc() {
step "every order of two tree writes, in READ COMMITTED"
python3 tests/interleave.py --levels "read committed" --db authz_interleave_rc | quiet_ok
record "${PIPESTATUS[0]}" "interleavings (read committed)"
}
unit policy 45 interleavings_rc
fi

moves() {
step "moves and links of folders with many below them"
tests/moves.sh
record $? "moves"
}
unit policy 8 moves

adversarial() {
step "the app role trying every way around the policy"
tests/adversarial.sh
record $? "adversarial"
}
unit policy 11 adversarial

docs() {
step "docs/getting-started.md runs as written"
tests/docs_test.sh
record $? "docs"
}
unit policy 2 docs
cookbook() {
step "the cookbook's recipes: each one's policy applies, its tests pass, and its page shows only what is tested"
tests/cookbook.sh
record $? "cookbook"
}
unit policy 23 cookbook
reference() {
step "the reference runs as written: its policies compile, its SQL and its commands run, each block or why not"
tests/reference.sh
record $? "reference"
}
unit policy 12 reference
hand_answers() {
step "answers worked out by hand from the language's reference, held against the database (tests/hand/)"
tests/hand_answers.sh | quiet_ok
record "${PIPESTATUS[0]}" "hand answers"
}
unit policy 45 hand_answers

fi
difftest() {
  step "random changes, compared with the reference evaluator ($1, $STEPS changes)"
  python3 tests/difftest.py --gen "$1" --steps "$STEPS" --seed 7 --quiet --db "authz_diff_$1" --decisions
  record $? "difftest $1"
  dropdb --if-exists "authz_diff_$1" >/dev/null 2>&1
}
GENS="docs alt multi composite loop cross"; every_version || GENS=docs
for gen in $GENS; do
  # six policies: four in the random part, one with each of the two others, which are shorter, so that the
  # three parts are about as long as each other. --decisions says too which parts of the policy never decided an
  # answer there (tests/decisions.py: whose SQL the run never judged), a report that fails nothing
  case "$gen" in composite) part policy;; multi) part command;; *) part random;; esac || continue
  # the part it runs in, and how long it takes with 15 changes
  case "$gen" in composite) p=policy secs=81;; multi) p=command secs=125;; docs) p=random secs=200;;
    alt) p=random secs=130;; loop) p=random secs=25;; cross) p=random secs=45;; esac
  unit "$p" $((secs*STEPS/15)) difftest "$gen"
done
# what is around the policy depends on the version of Postgres more than the policy does: a few on every run
# (the full run: the worlds in which every two of their features meet, twenty of a thousand seeds). In shares, each
# with databases and login roles of its own: on the full run three lanes of the random part; else two, one with
# each of the other parts, which are shorter (as difftest's composite and multi are)
around() {
if [ "$MODE" = full ]; then
  step "random policies in random worlds: the catalog, the session and the role around them (every two features of the worlds together, of 1000 seeds: share $1 of 3)"
  python3 tests/around.py --pairs 1000 --share "$1/3" --steps 4 --db "authz_around_$1"
else
  step "random policies in random worlds: the catalog, the session and the role around them (4 policies: share $1 of 2)"
  python3 tests/around.py --policies 4 --share "$1/2" --steps 6 --seed 1 --db "authz_around_$1"
fi
record $? "around $1"
}
AROUND="1 2"; [ "$MODE" = full ] && AROUND="1 2 3"
for share in $AROUND; do
  # the part it runs in, and how long it takes: the full run's on pgdev (2026-10-12; two of its worlds have
  # policies slow to plan, both in the second share), the others' on CI
  case "$MODE $share" in "full 1") p=random secs=250;; "full 2") p=random secs=650;; "full 3") p=random secs=365;;
    *" 1") p=command secs=140;; *) p=policy secs=215;; esac
  part "$p" || continue
  unit "$p" "$secs" around "$share"
done
if part random; then
if [ "$MODE" = full ]; then
  genpolicy() {
  step "random policies, compared with the reference evaluator (every two features together, of 1000 seeds)"
  python3 tests/genpolicy.py --pairs 1000 --steps 8 --db authz_genpolicy --decisions
  record $? "genpolicy"
  dropdb --if-exists authz_genpolicy >/dev/null 2>&1
  }
  unit random 430 genpolicy   # 7 minutes on pgdev, 2026-10-11
fi
# the review reads no database for its "grants the same"; the diff it is held against is the database's own
REWRITES=4; [ "$MODE" = full ] && REWRITES=12
rewrites() {
step "random policies rewritten: the review's \"grants the same\" against the database's answers ($REWRITES policies)"
python3 tests/rewrites.py --policies "$REWRITES" --seed 1 --db authz_rewrites
record $? "rewrites"
}
unit random $((33*REWRITES)) rewrites
# changes to a policy and its data that must change nothing: the same SQL, the same answers (renumbered: mapped)
# (each run seed 2: keys of two columns, awkward names)
INVARIANCE=1; INVARIANCE_SEED=2; [ "$MODE" = full ] && INVARIANCE=8 INVARIANCE_SEED=1
invariance() {
step "random policies written another way and their data renumbered: the same SQL and answers ($INVARIANCE, seeds from $INVARIANCE_SEED)"
python3 tests/invariance.py --policies "$INVARIANCE" --seed "$INVARIANCE_SEED" --db authz_invariance
record $? "invariance"
}
if every_version; then
unit random $((40*INVARIANCE)) invariance
fi
if [ "$MODE" = full ]; then
  invariance_fixed() {
  step "the fixed policies written another way: the same answers on difftest's data"
  python3 tests/invariance.py --fixed --steps 5 --db authz_invariance_fixed
  record $? "invariance of the fixed policies, answered"
  }
  unit random 490 invariance_fixed
fi
conditions() {
step "simple conditions read as Postgres reads them (3000 made up)"
python3 tests/conditions_test.py --cases 3000 --seed 1
record $? "conditions"
}
unit random 14 conditions
fi
# with more than one lane, the units run now: each part's in its lanes, one part after the other
for p in $PARTS; do run_lanes "$p"; done
fi

# Tree writes under concurrency: every order of two of them at each isolation level, and a concurrent stress run;
# the inheritance tables must stay exact throughout.
# --proofs runs a short version on its own (--quick leaves it out, so each stays under 10 minutes).
if { [ "$MODE" = full ] || [ "$MODE" = proofs ] || [ "$MODE" = soak ]; } && part races; then
  STRESS=100; [ "$MODE" = proofs ] && STRESS=15; [ "$MODE" = soak ] && STRESS=300
  step "every order of two tree writes, at each isolation level"
  python3 tests/interleave.py | quiet_ok
  record "${PIPESTATUS[0]}" "interleavings"
  step "tree writes under stress (${STRESS}s per isolation level)"
  tests/stress.sh $STRESS
  record $? "stress"
fi

# The command and a migration cut after every statement of each on the docs app (--soak: other policies' first
# apply, cut where the seed says)
if { [ "$MODE" = full ] || [ "$MODE" = proofs ] || [ "$MODE" = soak ]; } && part races; then
  if [ "$MODE" = soak ]; then
    step "other policies' first apply cut half way (seed $SEED)"
    python3 tests/interrupt.py --others --seed "$SEED" --policies 20
    record $? "cuts half way, other policies"
  else
    step "the command and a migration cut half way, after every statement of each"
    python3 tests/interrupt.py --every
    record $? "cuts half way, every statement"
  fi
fi

# measuring: the function calls of the databases still here (each one dropped earlier was asked then)
[ -z "${ROWSTILE_COVERAGE:-}" ] ||
  bash tests/coverage_functions.sh $(psql -X -At -d postgres -c "SELECT datname FROM pg_database WHERE datname LIKE 'authz%'")

echo
[ "$STEPS_RUN" -gt 0 ] || failed+=("no step ran")
if [ ${#failed[@]} -eq 0 ]; then echo "ALL PASSED"; else echo "FAILED: ${failed[*]}"; exit 1; fi

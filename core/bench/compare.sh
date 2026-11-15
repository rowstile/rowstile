#!/bin/bash
# compare.sh: the scale benchmark on two builds in turn on this machine: another commit (base) and this tree (here).
# One machine is up to three times another, and one hour differs from the next: two builds are compared only when
# one machine ran both, in turn, more than once. A tenth of a difference can't be read from two results of two days.
#   core/bench/compare.sh main              # this tree against main: the dev size, two rounds (base, here, here, base)
#   core/bench/compare.sh v0.1.0 --large    # against a tag, at another of scale.sh's sizes
# Environment: ROUNDS (default 2), and scale.sh's own (PG, DURATION, ...). The gate's speed limits are shown, not
# judged (SPEED_GATES=0). The other commit is checked out beside this tree (a git worktree, .ci/bench-base, removed
# at the end) and runs its own benchmark: its scale.sh, its workload, its policy. This tree runs as it is, with
# what isn't committed.
# Results: core/bench/results/compare/ (not in git): base-N.txt and here-N.txt, and compare.txt, the table
# compare.py makes of them. On GitHub's runners: `gh workflow run nightly.yml --ref <branch> -f only=scale -f
# size=dev -f against=main` (the run's `scale-compare` artifact).
# Exits with the code of the first run that went wrong (the lines above say why), and 0 otherwise: the table is to
# be read, nothing in it is judged.
set -u
cd "$(dirname "$0")/../.."
BASE=${1:-} SIZE=${2:---dev}
case "$SIZE" in
  --dev|--large|--medium|--full) ;;
  *) BASE=;;
esac
[ -n "$BASE" ] || { echo "usage: $0 <commit> [--dev|--large|--medium|--full]" >&2; exit 2; }
ROUNDS=${ROUNDS:-2}
DIR=core/bench/results/compare
WT=.ci/bench-base
# a branch of the remote alone (a CI checkout has no local main) is found there
commit=$(git rev-parse --verify --quiet "$BASE^{commit}" || git rev-parse --verify --quiet "origin/$BASE^{commit}") || {
  echo "compare.sh: no commit $BASE here (a shallow clone has only its own: fetch it first)" >&2; exit 2; }
export SPEED_GATES=${SPEED_GATES:-0}
mkdir -p "$DIR" .ci
rm -f "$DIR"/base-*.txt "$DIR"/here-*.txt "$DIR/compare.txt"
git worktree remove --force "$WT" >/dev/null 2>&1
git worktree add --detach --force "$WT" "$commit" >/dev/null || exit 1
trap 'git worktree remove --force "$WT" >/dev/null 2>&1' EXIT
for n in $(seq "$ROUNDS"); do
  # which build goes first changes each round: a machine that warms up or slows down favours neither
  if [ $((n % 2)) = 1 ]; then order="base here"; else order="here base"; fi
  for which in $order; do
    echo "== round $n of $ROUNDS: $which"
    if [ "$which" = base ]; then root=$WT; else root=.; fi
    OUT=core/bench/results/scale-latest.txt bash "$root/core/bench/scale.sh" "$SIZE"; rc=$?
    cp "$root/core/bench/results/scale-latest.txt" "$DIR/$which-$n.txt" 2>/dev/null
    [ $rc = 0 ] || { echo "== the run went wrong (the lines above say why): the comparison stops"; exit $rc; }
  done
done
python3 core/bench/compare.py "$DIR" | tee "$DIR/compare.txt"

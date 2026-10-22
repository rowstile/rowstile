#!/bin/bash
# regress.sh: a small run of the scale benchmark, compared with this machine's baseline (see regress.py).
#   core/bench/regress.sh             # fails when something got more than twice as slow, or the run went wrong
#   core/bench/regress.sh --record    # make this machine's run the baseline (after an intended change)
# 10k folders and 200k files, short steps: a few minutes. A baseline belongs to the machine that recorded it, so
# none is committed: the first run on a machine records one (core/bench/baseline.txt, not in git; CI keeps its own
# in the Actions cache). The scale gate's speed limits are shown, not judged (SPEED_GATES=0): they are for the
# gate's size on a machine of its own; here speed is judged against the baseline.
# A run that goes wrong (a write failed or was aborted, authz.verify() didn't say true, a listing failed) fails at
# once, not run again. A run that is slower is run once more, and only a second slower run counts: the machine
# may be busy with something else for a while (a CI runner is a shared machine), and a slower commit is slower
# both times.
set -u
cd "$(dirname "$0")/../.."
export FILES=${FILES:-200000} FOLDERS=${FOLDERS:-10000} USERS=${USERS:-500} TEAMS=${TEAMS:-50}
export SPEED_GATES=${SPEED_GATES:-0}
# reads arrive at 25/s per CPU, at most the gate's 400 (16 CPUs): on GitHub's runners (2 CPUs, 4 for a public
# repository) 400 reads/s keep both busy, and their p95 measures the wait for a CPU (126 ms there)
cpus=$(nproc 2>/dev/null || echo 16)
export READ_RATE=${READ_RATE:-$(( cpus * 25 < 400 ? cpus * 25 : 400 ))}
export DURATION=${DURATION:-15} GATE_DURATION=${GATE_DURATION:-20}
export OUT=core/bench/results/regress-latest.txt
BASELINE=${BASELINE:-core/bench/baseline.txt}
run() {
  bash core/bench/scale.sh && return
  echo "== the run went wrong (the lines above say why): not run again"
  exit 1
}
run
if [ "${1:-}" = --record ] || [ ! -f "$BASELINE" ]; then
  python3 core/bench/regress.py "$OUT" "$BASELINE" --record
  exit
fi
python3 core/bench/regress.py "$OUT" "$BASELINE" && exit 0
echo "== slower than the baseline: running once more; only a second slower run counts"
run
python3 core/bench/regress.py "$OUT" "$BASELINE"

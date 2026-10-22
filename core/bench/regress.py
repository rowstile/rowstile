#!/usr/bin/env python3
"""regress.py: compare a benchmark result (run.sh output) with a recorded baseline.

    python3 bench/regress.py RESULT bench/baseline.txt            # exit 1 on a regression
    python3 bench/regress.py RESULT bench/baseline.txt --record   # write RESULT's numbers as the baseline

Compared: the p95 of each script when reads run alone (step 1) and in the gate (step 3: the writes' table and the
reads' table, each with its own "all" row, keyed 3.writes.* and 3.reads.*), and how long the big move took (step 4).
A number counts as slower when it is more than FACTOR times its baseline and more than its floor above it (FLOOR_MS
milliseconds; FLOOR_S seconds for the big move, which takes about half a second: a floor of seconds would let it
get four times slower), so noise on small numbers doesn't fail the check; scripts with fewer than MIN_TXNS
transactions are left out. Only speed is judged here: whether the run was right (no failed or aborted writes,
authz.verify() true after the writes, the listings answered) is run.sh's exit code, and regress.sh stops on it.
The gate's speed limits (reads and writes p95) are the scale gate's, for its size on a machine of its own
(scale.sh --large, --full); this small run on a shared CI machine is judged against its own baseline.
Step 2 (throughput as clients grow) is left out: at 50 clients the machine is saturated and its
latencies say more about the machine than about the code.
"""

import re
import sys

FACTOR, FLOOR_MS, FLOOR_S = 2.0, 2.0, 0.5
MIN_TXNS = 50


def numbers(path: str) -> tuple[dict[str, float], set[str]]:
    out: dict[str, float] = {}
    rare: set[str] = set()  # scripts that ran, too few times to judge
    section: str | None = None
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            m = re.match(r"== (\d+)\.", line)
            if m:
                section = m.group(1)
                continue
            # step 3 prints the writes' table, then the reads': both end with an "all" row
            m = re.match(r"(writes|reads): ", line)
            if m and section is not None and section.startswith("3"):
                section = f"3.{m.group(1)}"
                continue
            m = re.match(r"the big move: .*: ([0-9.]+) s", line)
            if m:
                out["4.big_move_s"] = float(m.group(1))
                continue
            f = line.split()
            # scripts that ran rarely (links: 1% of writes) have too few samples for a stable p95
            if section is not None and section[0] in "13" and len(f) >= 7 and f[1].isdigit():
                if int(f[1]) < MIN_TXNS:
                    rare.add(f"{section}.{f[0]}")
                    continue
                out[f"{section}.{f[0]}"] = float(f[4])
    return out, rare


def main() -> int:
    result, baseline = sys.argv[1], sys.argv[2]
    now, rare = numbers(result)
    if "--record" in sys.argv:
        with open(baseline, "w", newline="\n", encoding="utf-8") as fh:
            fh.write("# bench/regress.py baseline: p95 ms per script (1 = reads alone, 3 = the gate), big move s\n")
            for k in sorted(now):
                fh.write(f"{k} {now[k]}\n")
        print(f"recorded {len(now)} numbers in {baseline}")
        return 0
    base: dict[str, float] = {}
    with open(baseline, encoding="utf-8") as fh:
        for line in fh:
            if line.strip() and not line.startswith("#"):
                k, v = line.split()
                base[k] = float(v)
    slower: list[str] = []
    print(f"{'measure':28}{'baseline':>10}{'now':>10}")
    for k in sorted(base):
        if k in rare:  # the run's rate (READ_RATE) leaves few of a rare script: not judged this time
            print(f"{k:28}{base[k]:10.2f}{'too few':>10}")
            continue
        if k not in now:
            slower.append(f"{k}: missing from the result")
            continue
        floor = FLOOR_S if k.endswith("_s") else FLOOR_MS
        flag = now[k] > base[k] * FACTOR and now[k] - base[k] > floor
        print(f"{k:28}{base[k]:10.2f}{now[k]:10.2f}{'  SLOWER' if flag else ''}")
        if flag:
            slower.append(f"{k}: {now[k]:.2f} against {base[k]:.2f}")
    for problem in slower:
        print("regression:", problem)
    if slower:
        return 1
    print("no regression")
    return 0


if __name__ == "__main__":
    sys.exit(main())

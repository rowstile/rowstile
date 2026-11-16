#!/usr/bin/env python3
"""compare.py: the results of two builds the scale benchmark ran in turn on one machine, side by side.

    python3 bench/compare.py DIR      # DIR holds base-1.txt, here-1.txt, base-2.txt, ... (compare.sh writes them)

One row per measure both builds have: each round's figure, and the mean of `here` over the mean of `base`. Read:
the times of loading and applying, each read's p50 alone (step 1) and in the gate (step 3), the tree writes a
second as clients grow (step 2), the gate's writes' p50, the big move and the longest a write beside it took (the
pause it makes), each listing (step 5), each reader's p50 by what they hold (step 6) and the tree writes a second
by where the writers are (step 7). A p50, not a p95: the question is what the code costs, and a p95 on a shared
machine says more of the machine. The reads' "all" rows are left out: members and admins together have two speeds, and
the middle of the two moves with how many of each a run drew.
A difference is called (faster, slower) only when every round of one build is beyond every round of the other
and the means differ by more than one build's own runs do on a runner (FLOOR; the same build against itself on
2026-11-15: a read's p50 by up to 2%, tree writes a second by up to 7%). Otherwise nothing is said. Nothing is
judged: the exit code is 0 whatever the table says, and 2 when a build's results are missing.
"""

import glob
import os
import re
import sys

MORE_IS_BETTER = "writes/s"
# a difference of the means that is called: over 3% for a time, over 10% for writes a second
FLOOR, FLOOR_WRITES = 0.03, 0.10


def numbers(path: str) -> tuple[str, dict[str, float]]:
    """A result's build (its first line's commit, or its version) and its measures, in the file's order."""
    out: dict[str, float] = {}
    build = "a build its result doesn't name"
    section, table = "", ""
    with open(path, encoding="utf-8") as fh:
        for n, line in enumerate(fh):
            if n == 0:
                m = re.search(r"(commit [^)]+)\)", line) or re.search(r"(rowstile [^,)]+)", line)
                build = m.group(1) if m else build
            if line.startswith("== "):
                m = re.match(r"== (\d+)\.", line)
                section, table = (m.group(1) if m else "load" if line.startswith("== Loading") else ""), ""
                continue
            f = line.split()
            if not f:
                continue
            if section == "load" and len(f) > 1 and re.fullmatch(r"[0-9.]+", f[-1]):
                out[f"{' '.join(f[:-1])}, s"] = float(f[-1])
            elif section == "2" and f[0].isdigit() and len(f) >= 8:
                out[f"2. {f[0]} clients, {MORE_IS_BETTER}"] = float(f[1])
            elif section == "3" and f[0] in ("writes:", "reads:"):
                table = f[0][:-1]
            elif section in ("1", "3") and len(f) >= 7 and f[1].isdigit() and f[2].isdigit():
                if f[0] == "all" and table != "writes":
                    continue
                if section == "1":
                    out[f"1. {f[0]}, p50 ms"] = float(f[3])
                elif table == "writes" and f[0] == "all":
                    out["3. the gate's writes, p50 ms"] = float(f[3])
                elif table == "reads":
                    out[f"3. {f[0]} in the gate, p50 ms"] = float(f[3])
            elif section == "4":
                m = re.match(r"the big move: .*: ([0-9.]+) s", line)
                if m:
                    out["4. the big move, s"] = float(m.group(1))
                elif f[0] == "all" and len(f) >= 7 and f[1].isdigit():
                    out["4. the longest write beside the big move, ms"] = float(f[6])
            elif section == "5":
                m = re.match(r"(.+?)\s+(authz\.list\(.*\))\s+(\d+) rows\s+([0-9.]+) s$", line.rstrip())
                if m:
                    out[f"5. {m.group(1)}: {m.group(2)}, s"] = float(m.group(4))
            elif section == "6":
                m = re.match(r"(.+ folders)\s+(\d+)\s+(\d+)\s+([0-9.]+)\s", line)
                if m:
                    out[f"6. {m.group(1)}, p50 ms"] = float(m.group(4))
            elif section == "7":
                m = re.match(r"(each in a part of its own|all in one part)\s+(\d+)\s+([0-9.]+)\s", line)
                if m:
                    out[f"7. {m.group(1)}, {m.group(2)} clients, {MORE_IS_BETTER}"] = float(m.group(3))
    return build, out


def round_of(path: str) -> int:
    m = re.search(r"-(\d+)\.txt$", path)
    return int(m.group(1)) if m else 0


def called(base: list[float], here: list[float], more_is_better: bool) -> str:
    """faster or slower when every round of one build is beyond every round of the other, two rounds or more of
    each say so, and the means differ by more than a build's own runs do (FLOOR); nothing otherwise."""
    if min(len(base), len(here)) < 2:
        return ""
    b, h = sum(base) / len(base), sum(here) / len(here)
    # (figures are written to a hundredth: two of them apart or less is how they are rounded)
    if abs(h / b - 1) <= (FLOOR_WRITES if more_is_better else FLOOR) or abs(h - b) <= 0.02:
        return ""
    if max(here) < min(base):
        return "slower" if more_is_better else "faster"
    if min(here) > max(base):
        return "faster" if more_is_better else "slower"
    return ""


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: compare.py DIR  (base-N.txt and here-N.txt, as compare.sh writes them)", file=sys.stderr)
        return 2
    folder = sys.argv[1]
    builds: dict[str, str] = {}
    results: dict[str, list[dict[str, float]]] = {}
    for which in ("base", "here"):
        read = [numbers(p) for p in sorted(glob.glob(os.path.join(folder, f"{which}-*.txt")), key=round_of)]
        if not read:
            print(f"compare.py: no {which}-N.txt in {folder}", file=sys.stderr)
            return 2
        builds[which], results[which] = read[0][0], [r[1] for r in read]
    base, here = results["base"], results["here"]
    ran = {which: f"{builds[which]}, {len(r)} round{'s' if len(r) > 1 else ''}" for which, r in results.items()}
    print(f"# the scale benchmark on two builds in turn on one machine: base ({ran['base']}) and here ({ran['here']})")
    wide = 9 * max(len(base), len(here))
    print(f"{'measure':<58}{'base':>{wide}}  {'here':>{wide}}{'here/base':>11}")
    for key in base[0]:
        b = [r[key] for r in base if key in r]
        h = [r[key] for r in here if key in r]
        if not h or not sum(b):
            continue
        ratio = (sum(h) / len(h)) / (sum(b) / len(b))
        said = called(b, h, key.endswith(MORE_IS_BETTER))
        cells = "  ".join(f"{''.join(f'{x:9.2f}' for x in xs):>{wide}}" for xs in (b, h))
        print(f"{key:<58}{cells}{ratio:11.2f}{'  ' + said if said else ''}")
    print(
        "# faster, slower: every round of one build is beyond every round of the other, and the means differ by more "
        f"than {FLOOR:.0%} ({FLOOR_WRITES:.0%} for writes a second); nothing said otherwise"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

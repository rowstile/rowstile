#!/usr/bin/env python3
"""check_counts: how many checks each suite passes is written down, and changes only on purpose.

    python3 tests/check_counts.py LOG [LOG ...]      # core/ci.sh runs it on run_tests.sh's log
    python3 tests/check_counts.py --write LOG [...]  # after adding or taking away checks on purpose
    python3 tests/check_counts.py --mode quick --part command LOG   # and each suite that run must have, ran

A suite that stops checking something can stay green: a glob that matches nothing, a loop over an empty list, a
suite cut short, a test that skips. run_tests.sh's log says how many checks each one passed (a line `ok ...` each,
`N checks passed`, `Ran N tests` less the `skipped=K` after it, `N of N cases`) before the step's `--- passed: NAME`
line, and check_counts.txt says how many each one passes: no fewer and no more, so that a count that changes is in
the diff, like the golden SQL. The unit tests' count is what they pass where ci.sh runs them, in its container:
there git can't be asked of the checkout, and the tests that need it skip (as do those for Windows alone, and the
install lines' on main between releases).

A suite that never ran is not in the log at all. So with --mode (and --part and --upgrades, as core/ci.sh knows them
from run_tests.sh's) each suite check_counts.txt names that this mode and part run (PLACES says where each runs) must
have a result in the log: one put under another part or mode by mistake, a unit that ends before its record, a name
changed, all fail the run. Without --mode, a suite a log doesn't have isn't asked. A unit test checks that each
suite check_counts.txt names is a step run_tests.sh runs, and has its place in PLACES.

The random ones (difftest, genpolicy, around, the invariance, the conditions, the parser fuzzer, the rewrites, the
stress test) check as many things as their seeds draw: they aren't counted (the invariance of the fixed policies is,
but not the full run's answers to them). Nor are the upgrades from every release (nightly), as many as PyPI has
releases: that suite checks each passes as many.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from collections.abc import Sequence

HERE = os.path.dirname(os.path.abspath(__file__))
EXPECTED = os.path.join(HERE, "check_counts.txt")
# the suites that check as many things on every run: not the random ones
FIXED = re.compile(
    r"^(?!difftest|genpolicy|around|invariance(?! of the fixed policies$)|conditions|fuzz parser|rewrites|stress|"
    r"upgrade from every release)"
)
# Where each suite check_counts.txt names runs: its part of run_tests.sh's run, and the modes that run it there
# (--short leaves out what is the same on every version, the full run has every isolation level's interleavings in
# its races part in place of READ COMMITTED's in the policy part, the soak its own small part)
EVERY = frozenset({"quick", "short", "full"})
BUT_SHORT = frozenset({"quick", "full"})
PLACES: dict[tuple[str, frozenset[str]], tuple[str, ...]] = {
    ("unit", BUT_SHORT): ("unit", "cuts half way", "invariance of the fixed policies"),
    ("policy", BUT_SHORT): ("policy errors", "language server"),
    ("policy", EVERY): (
        "scenario",
        "keep unchanged trees",
        "multi scenario",
        "identity",
        "principals",
        "signed sessions",
        "governance",
        "masks",
        "tools",
        "confidence",
        "studio",
        "mcp",
        "devx",
        "concurrency",
        "moves",
        "sync index",
        "adversarial",
        "docs",
        "cookbook",
        "reference",
        "hand answers",
    ),
    ("policy", frozenset({"quick", "short"})): (
        "interleavings (read committed, docs)",
        "interleavings (read committed, cross)",
        "interleavings (read committed, parts)",
        "interleavings (read committed, boxes)",
        "interleavings (read committed, docs keyed by folder)",
        "interleavings (read committed, docs after commit)",
    ),
    ("command", EVERY): ("apply", "cli", "capitals", "children", "migrations", "upgrade", "review"),
    ("command", BUT_SHORT): ("migrate vs apply",),
    ("random", EVERY): ("small policies",),
    ("small", frozenset({"soak"})): ("small policies",),
    ("races", frozenset({"full", "proofs", "soak"})): ("interleavings",),
    ("races", frozenset({"full", "proofs"})): ("cuts half way, every statement",),
    ("races", frozenset({"soak"})): ("cuts half way, other policies",),
}
STEP = re.compile(r"^--- (?:passed|FAILED): (.+?) \(\d+s\)$", re.M)
# a line that says how many checks passed: a scenario's, a filtered suite's (run_tests.sh's quiet_ok), the unit
# tests', the policy errors'
COUNT = re.compile(r"^\s*(\d+) checks passed$|^Ran (\d+) tests? in |^policy errors: (\d+) of \d+ cases")
# what the unit tests skipped, after their `Ran N tests`: not passed
SKIPPED = re.compile(r"^(?:OK|FAILED) \((?:.*, )?skipped=(\d+)")


def counted(log: str) -> dict[str, int]:
    """How many checks each suite of a log passed, by the name its `--- passed:` line gives."""
    out: dict[str, int] = {}
    n = 0
    for line in log.splitlines():
        if line.startswith("ok"):
            n += 1
        elif c := COUNT.match(line):
            n += int(next(g for g in c.groups() if g is not None))
        elif k := SKIPPED.match(line):
            n -= int(k.group(1))
        elif m := STEP.match(line):
            if FIXED.match(m.group(1)):
                out[m.group(1)] = n
            n = 0
    return out


def wanted(mode: str, part: str = "", upgrades: str = "") -> set[str]:
    """The suites a run of run_tests.sh in this mode must have, in this part of it (empty: every part). With
    ROWSTILE_UPGRADES=every the upgrade is the one from every release, which isn't counted but must run too."""
    out = {name for (p, modes), names in PLACES.items() if mode in modes and part in ("", p) for name in names}
    if upgrades == "every" and "upgrade" in out:
        out = (out - {"upgrade"}) | {"upgrade from every release"}
    return out


def not_run(log: str, want: set[str]) -> list[str]:
    """Each suite the run should have had that the log has no result of."""
    ran = set(STEP.findall(log))
    return [f"{k} didn't run, though this run's mode and part have it" for k in sorted(want - ran)]


def expected(path: str = EXPECTED) -> dict[str, int]:
    """What check_counts.txt says: a line `NAME COUNT` per suite."""
    out: dict[str, int] = {}
    if os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                if line.strip() and not line.startswith("#"):
                    name, count = line.rstrip("\n").rsplit(" ", 1)
                    out[name] = int(count)
    return out


def differences(got: dict[str, int], want: dict[str, int]) -> list[str]:
    """Each suite of a log that passed another number of checks than check_counts.txt says."""
    return [
        f"{k} passed {got[k]} checks, check_counts.txt says {want[k]}"
        if k in want
        else f"{k} passed {got[k]} checks, check_counts.txt doesn't name it"
        for k in sorted(got)
        if got[k] != want.get(k, 0)
    ]


def together(logs: Sequence[dict[str, int]]) -> tuple[dict[str, int], list[str]]:
    """The counts of several logs as one, and each suite whose count isn't the same in all of them."""
    out: dict[str, int] = {}
    unfixed: list[str] = []
    for got in logs:
        for k, v in got.items():
            if out.setdefault(k, v) != v:
                unfixed.append(f"{k} passed {out[k]} checks in one log and {v} in another: its count isn't fixed")
    return out, unfixed


def write(path: str, counts: dict[str, int]) -> None:
    """check_counts.txt anew: its comments as they were, then a line for each suite that passes any check."""
    head: list[str] = []
    if os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            head = [line for line in fh if line.startswith("#")]
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.writelines(head)
        fh.writelines(f"{k} {v}\n" for k, v in sorted(counts.items()) if v)


def main(argv: Sequence[str]) -> int:
    ap = argparse.ArgumentParser(description="How many checks each suite passes, as check_counts.txt says.")
    ap.add_argument("logs", nargs="+", metavar="LOG")
    ap.add_argument("--write", action="store_true", help="write the logs' counts into check_counts.txt")
    ap.add_argument("--mode", choices=["quick", "short", "full", "proofs", "soak"], help="run_tests.sh's mode")
    ap.add_argument("--part", default="", help="the part of the run (ROWSTILE_PART; none: every part)")
    ap.add_argument("--upgrades", default="", help="ROWSTILE_UPGRADES")
    a = ap.parse_args(argv)
    logs: list[dict[str, int]] = []
    text: list[str] = []
    for path in a.logs:
        with open(path, encoding="utf-8", errors="replace") as fh:
            text.append(fh.read())
        logs.append(counted(text[-1]))
    got, unfixed = together(logs)
    for line in unfixed:
        print(f"check counts: {line}")
    if a.write:
        if unfixed:
            print("check counts: nothing written")
            return 1
        write(EXPECTED, {**expected(), **got})
        print(f"check counts: {len(got)} suites written to tests/check_counts.txt")
        return 0
    wrong = differences(got, expected())
    for line in wrong:
        print(f"check counts: {line}")
    # each suite the mode and part have, in one of the logs
    missing = not_run("\n".join(text), wanted(a.mode, a.part, a.upgrades)) if a.mode else []
    for line in missing:
        print(f"check counts: {line}")
    if wrong or unfixed:
        print(
            f"check counts: {len(wrong)} of {len(got)} suites not as tests/check_counts.txt says; after adding or "
            "taking away checks on purpose, write the new counts there (python3 tests/check_counts.py --write LOG)"
        )
    if missing:
        print(f"check counts: {len(missing)} suites didn't run (tests/check_counts.py's PLACES says where each runs)")
    if wrong or unfixed or missing:
        return 1
    print(f"check counts: {len(got)} suites, each with as many checks as tests/check_counts.txt says")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

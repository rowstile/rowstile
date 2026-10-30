#!/usr/bin/env python3
"""coverage_report: what the suites run of authzlib and cli, and what nothing runs.

    python3 tests/coverage_report.py [--out DIR] [--diff REF] [--floor FILE] DIR [DIR ...]

Each DIR is one that run_tests.sh measured into (ROWSTILE_COVERAGE=DIR; core/ci.sh --coverage makes
.ci/coverage-<version>), whose data/ holds a file per Python process the suites started, or such a data folder
itself (CI's parts). Run it where coverage.py is (the image core/Dockerfile builds with COVERAGE=1). It combines
them into --out (the first DIR if not given): .coverage, coverage.json (coverage.py's report) and report.txt:

  - for each file, its lines and branches, and how many of them the suites run (this part is printed too);
  - the lines and branches nothing runs, with their text, the files with the most first;
  - compiled, never judged: what runs of the code that writes the SQL deciding who may do what (DECIDES), but only
    in steps that don't compare the database's answers with the reference evaluator (ORACLE): its SQL was made,
    and difftest, genpolicy and around never judged it;
  - what the database runs: the kinds of rowstile's functions (authz_gen."<table>:update:refuse", a tree's
    refresh, authz.share) no suite ever called, and those whose every call raised, from the counts
    tests/coverage_functions.sh kept (functions.tsv beside each DIR or data file);
  - and statement by statement, where plpgsql_check's profiler counted them (plpgsql.jsonl beside each DIR or data
    file; tests/coverage_plpgsql.py): the RAISEs, other statements and branches of rowstile's PL/pgSQL no suite ran.

With --diff REF it also prints the lines changed since REF (git diff REF...HEAD) that nothing runs, and exits 1 if
there are any. With --floor FILE (tests/plpgsql_floor.txt) it exits 1 unless the PL/pgSQL never run in the schemas
the floor holds is what FILE says: more is a change whose PL/pgSQL no suite runs, fewer a floor to write anew.
"""

from __future__ import annotations

import argparse
import ast
import bisect
import contextlib
import json
import os
import re
import sqlite3
import subprocess
import sys
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any

import coverage_plpgsql

HERE = os.path.dirname(os.path.abspath(__file__))
CODE = os.path.dirname(HERE)  # core/: where the measured code is
SETTINGS = os.path.join(HERE, "coverage.ini")
# the steps of run_tests.sh that compare the database's answers with the reference evaluator's, by their names
# (CoverageReport in unit_test.py checks it against the steps that run difftest, genpolicy and around)
ORACLE = re.compile(r"compared with the reference evaluator|in random worlds")
# the code that writes the SQL deciding who may do what: the checks and lists, the trees, and what every check
# calls of identity.py (who is signed in: authz_int.session_ok(); the scopes: scope_cmd, scope_perm, writable).
# Not refusals.py: its functions run once a check has said no, to say why
DECIDES = (
    "authzlib/compiler.py",
    "authzlib/identity.py",
    "authzlib/insight.py",
    "authzlib/output.py",
    "authzlib/sqlutil.py",
    "authzlib/trees.py",
)

Answer = Any  # coverage.py's JSON report, as read


@dataclass
class Function:
    name: str  # Class.method, as coverage.py names it
    lines: list[int]  # its statements


@dataclass
class File:
    """What the suites ran of one file."""

    name: str  # relative to core/: authzlib/compiler.py
    statements: list[int]
    missing: list[int]  # the statements no step ran
    never: dict[int, list[int]]  # a line that ran -> where its branches never went (negative: out of the function)
    branches: int
    branches_run: int
    functions: list[Function] = field(default_factory=list)
    steps: dict[int, set[str]] = field(default_factory=dict)  # a line -> the steps that ran it


@dataclass
class Called:
    """One of rowstile's functions in a database the suites made, and how often they called it."""

    step: str  # the step that made the database
    db: str
    schema: str
    name: str
    args: str
    calls: int
    how: str  # its language, then definer and set when it has them: "plpgsql definer set", "sql"
    entered: bool  # called at all: Postgres has a count for it, which a call that raised leaves at 0

    def counted(self) -> bool:
        """Whether Postgres counts its calls: not a plain SQL function, which it may inline into the query."""
        return self.how != "sql"


def functions_measured(paths: Sequence[str]) -> list[Called]:
    """What tests/coverage_functions.sh wrote (functions.tsv) beside each measured DIR or data file."""
    out: list[Called] = []
    for p in paths:
        path = os.path.join(p if os.path.isdir(p) else os.path.dirname(p), "functions.tsv")
        if not os.path.isfile(path):
            continue
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                parts = line.rstrip("\n").split("\t")
                if len(parts) == 8 and parts[5].isdigit():
                    step, db, schema, name, args, calls, how, entered = parts
                    out.append(Called(step, db, schema, name, args, int(calls), how, entered == "t"))
    return out


def kind(schema: str, name: str, args: str) -> str:
    """What made a function: its name with the policy's own names taken out (authz_gen.<table>:update:refuse,
    authz_int.<type>__<name>__why, a tree's <tree>_refresh); rowstile's own functions as they are, and the API's
    with their arguments (authz.share has three)."""
    if ":" in name and "__" not in name.split(":", 1)[0]:
        return f"{schema}.<table>:" + re.sub(r"column_\d+", "column_<n>", name.split(":", 1)[1])
    name = re.sub(r"__roles:[^_]+(?:_[^_]+)*__", "__roles:<name>__", name)  # a custom role's: doc__roles:view__who
    if re.fullmatch(r".+__t_[0-9a-f]{8,}", name):  # a tree whose name was too long, shortened to a hash
        return f"{schema}.<tree>_<hash>"
    name = re.sub(r"_[0-9a-f]{8,}$", "_<hash>", name)  # a condition's function, named by its text: folder__check_...
    tree = re.fullmatch(r".+__tree\d*_(.+)", name)
    if tree:
        return f"{schema}.<tree>_" + re.sub(r"^rows_.+$", "rows_<type>", re.sub(r"\d+$", "<n>", tree.group(1)))
    if "__" in name:
        parts = name.split("__")
        return f"{schema}." + "__".join(["<type>", *["<name>"] * (len(parts) - 2), re.sub(r"_\d+$", "_<n>", parts[-1])])
    if schema == "authz":
        return f"authz.{name}({args})"
    return f"{schema}." + re.sub(r"_\d+_", "_<n>_", name)


@dataclass
class Kind:
    """What the suites did with one kind of function."""

    made: int = 0  # in how many databases
    called: int = 0  # how many of those called it
    raised: int = 0  # how many of the others called it, every call raising (a guard that refuses)
    steps: set[str] = field(default_factory=set)  # the steps that made a database where it was called
    counted: bool = False  # whether Postgres counts its calls (Called.counted)


def by_kind(called: Sequence[Called]) -> dict[str, Kind]:
    """What the suites did with each kind of function. A database measured twice (before applying a policy again,
    and when it is dropped) is one database, which called a function if either measure says so."""
    databases: dict[tuple[str, str, str], list[Called]] = {}
    for c in called:
        databases.setdefault((kind(c.schema, c.name, c.args), c.step, c.db), []).append(c)
    out: dict[str, Kind] = {}
    for (name, step, _), cs in databases.items():
        k = out.setdefault(name, Kind())
        k.made += 1
        k.counted = k.counted or any(c.counted() for c in cs)
        if any(c.calls for c in cs):
            k.called += 1
            k.steps.add(step)
        elif any(c.entered for c in cs):
            k.raised += 1
    return out


def calls_summary(kinds: dict[str, Kind]) -> str:
    counted = [k for k in kinds.values() if k.counted]
    raised = sum(1 for k in counted if not k.called and k.raised)
    return f"{sum(1 for k in counted if k.called)} of {len(counted)} kinds of function called" + (
        f", and {raised} more whose every call raised" if raised else ""
    )


def functions_report(called: Sequence[Called]) -> list[str]:
    kinds = by_kind(called)
    raised = sorted(name for name, k in kinds.items() if k.counted and not k.called and k.raised)
    never = sorted(name for name, k in kinds.items() if k.counted and not k.called and not k.raised)
    uncounted = sorted(name for name, k in kinds.items() if not k.counted)
    out = [
        "What the database runs: rowstile's functions in the suites' databases, by what made them (Postgres's counts,",
        f"track_functions): {calls_summary(kinds)}.",
        "",
        "Called, but every call raised (Postgres counts only the calls that return: a guard's that refuses, not):",
    ]
    out += [
        f"  {name}  (made in {kinds[name].made} database(s), called in {kinds[name].raised})" for name in raised
    ] or ["  (none)"]
    out += [
        "",
        "Never called, or called only before the database's last apply (Postgres counts each function apart, and",
        "applying a policy makes its functions anew: a suite that applies again measures first, or it is counted for",
        "what it did after its last apply):",
    ]
    out += [f"  {name}  (made in {kinds[name].made} database(s))" for name in never] or ["  (none)"]
    out += ["", "Not counted: plain SQL functions, which Postgres may inline into the query that calls them:"]
    out += [f"  {name}" for name in uncounted] or ["  (none)"]
    return out


def lost(called: Sequence[Called], m: coverage_plpgsql.Measured) -> list[str]:
    """The PL/pgSQL functions Postgres counts as called in a database whose statements the profiler read none of
    there: its counts went with the function's catalog row, made anew after the calls (applying again, a GRANT or a
    REVOKE on it) and before they were read. Postgres's own count is by the function's oid, which a GRANT keeps."""
    read = {(r.step, r.db, r.schema, r.name, r.args) for r in m.runs}
    ran = {(r.step, r.db, r.schema, r.name, r.args) for r in m.runs if any(r.ran.values())}
    keys = {
        (c.step, c.db, c.schema, c.name, c.args)
        for c in called
        if c.how.startswith("plpgsql") and (c.entered or c.calls > 0)
    }
    return [f"  {s}.{n}({a}) in {db} ({step})" for step, db, s, n, a in sorted(keys & read - ran)]


def relative(path: str) -> str:
    """A measured file's name as the report gives it: relative to core/, with forward slashes."""
    return (os.path.relpath(path, CODE) if os.path.isabs(path) else path).replace(os.sep, "/")


def combine(dirs: Sequence[str], out: str) -> tuple[str, str]:
    """Every DIR's data in one file, and coverage.py's report of it: (data file, JSON report), in `out`."""
    os.makedirs(out, exist_ok=True)
    data, report = os.path.join(out, ".coverage"), os.path.join(out, "coverage.json")
    parts = [os.path.join(d, "data") if os.path.isdir(os.path.join(d, "data")) else d for d in dirs]
    env = dict(os.environ, ROWSTILE_COVERAGE=out, ROWSTILE_COVERAGE_CODE=CODE, ROWSTILE_COVERAGE_CONTEXT="")
    env.pop("COVERAGE_PROCESS_START", None)  # coverage.py's own commands measure nothing
    for command, *args in (["combine", "--keep", *parts], ["json", "-o", report]):
        p = subprocess.run(
            [sys.executable, "-m", "coverage", command, f"--rcfile={SETTINGS}", f"--data-file={data}", *args],
            cwd=CODE,
            env=env,
            capture_output=True,
            text=True,
        )
        if p.returncode:
            raise SystemExit(f"coverage {command} failed:\n{p.stdout}{p.stderr}")
    return data, report


def steps_by_line(data: str) -> dict[str, dict[int, set[str]]]:
    """For each file, the steps that ran each of its lines: coverage.py's data file is SQLite, and with branches
    measured it holds each step's jumps from line to line (a negative line: into or out of a function)."""
    out: dict[str, dict[int, set[str]]] = {}
    with contextlib.closing(sqlite3.connect(data)) as db:
        rows = db.execute(
            "SELECT f.path, c.context, a.fromno, a.tono FROM arc a JOIN file f ON f.id = a.file_id "
            "JOIN context c ON c.id = a.context_id"
        )
        for path, step, a, b in rows:
            lines = out.setdefault(relative(path), {})
            for n in (a, b):
                if n > 0:
                    lines.setdefault(n, set()).add(step)
    return out


def read(report: str, steps: dict[str, dict[int, set[str]]]) -> list[File]:
    """coverage.py's JSON report, with the steps that ran each line."""
    with open(report, encoding="utf-8") as fh:
        doc: Answer = json.load(fh)
    files = []
    for path, f in sorted(doc["files"].items()):
        name = relative(path)
        missing = set(f["missing_lines"])
        never: dict[int, list[int]] = {}
        for a, b in f["missing_branches"]:
            if a not in missing:  # a line that never ran is listed as such, not by its branches
                never.setdefault(a, []).append(b)
        files.append(
            File(
                name=name,
                statements=sorted(set(f["executed_lines"]) | missing),
                missing=sorted(missing),
                never={k: sorted(v) for k, v in never.items()},
                branches=f["summary"]["num_branches"],
                branches_run=f["summary"]["covered_branches"],
                functions=[
                    Function(n, sorted(set(g["executed_lines"]) | set(g["missing_lines"])))
                    for n, g in f.get("functions", {}).items()
                    if n  # "": the module's own lines
                ],
                steps=steps.get(name, {}),
            )
        )
    return files


def ranges(lines: Iterable[int], statements: Iterable[int]) -> list[tuple[int, int]]:
    """Lines as runs: a run goes on until a statement that isn't among the lines (it ran) comes between."""
    missing = sorted(set(lines))
    ran = sorted(set(statements) - set(missing))
    out: list[tuple[int, int]] = []
    for n in missing:
        if out and bisect.bisect_right(ran, out[-1][1]) == bisect.bisect_left(ran, n):
            out[-1] = (out[-1][0], n)
        else:
            out.append((n, n))
    return out


def judged(f: File) -> set[int]:
    """The lines of f that ran in a step comparing answers with the reference evaluator."""
    return {n for n, steps in f.steps.items() if any(ORACLE.search(s) for s in steps)}


def fails(node: ast.stmt) -> bool:
    """Whether a statement always reports a mistake: fail(...) or raise."""
    return isinstance(node, ast.Raise) or (
        isinstance(node, ast.Expr)
        and isinstance(node.value, ast.Call)
        and isinstance(node.value.func, ast.Name)
        and node.value.func.id == "fail"
    )


def reports(node: ast.stmt) -> bool:
    """Whether a statement only looks for a mistake: fail(...), raise or assert; an if without an else whose body
    only looks, or ends in a failure (what comes before it there makes the message); a loop whose body only
    looks."""
    match node:
        case ast.Assert():
            return True
        case ast.If(body=body, orelse=[]):
            return fails(body[-1]) or all(reports(s) for s in body)
        case ast.For(body=body, orelse=[]) | ast.While(body=body, orelse=[]):
            return all(reports(s) for s in body)
    return fails(node)


def leading_to_report(block: list[ast.stmt]) -> list[ast.stmt]:
    """The statements at the end of a block that only lead to a failure: it, and the straight-line ones before it
    (they make its message: nothing between them goes elsewhere)."""
    if not block or not fails(block[-1]):
        return []
    n = len(block) - 1
    while n > 0 and isinstance(block[n - 1], ast.Assign | ast.AnnAssign | ast.AugAssign | ast.Expr | ast.Assert):
        n -= 1
    return block[n:]


def mistakes(code: str) -> set[int]:
    """The lines of code that report a mistake or handle one: each fail(...) call, raise and except clause, each
    check that only looks for one (`reports`) and what only leads on to a failure (`leading_to_report`), whole: no
    policy that compiles reaches them, or they only look."""
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return set()
    out: set[int] = set()
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Raise | ast.ExceptHandler)
            or (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "fail")
            or (isinstance(node, ast.stmt) and reports(node))
        ):
            out.update(range(node.lineno, (node.end_lineno or node.lineno) + 1))
        for name in ("body", "orelse", "finalbody"):
            block = getattr(node, name, None)
            if not isinstance(block, list):
                continue  # an if expression's body, say
            stmts = [s for s in block if isinstance(s, ast.stmt)]
            if len(stmts) == len(block):
                for s in leading_to_report(stmts):
                    out.update(range(s.lineno, (s.end_lineno or s.lineno) + 1))
    return out


def never_judged(f: File, code: str | None = None) -> tuple[list[int], list[str]]:
    """What ran of f, but never in a step that compares answers with the reference evaluator: the lines (but those
    that report a mistake in the policy, which no policy that compiles reaches), and the functions none of whose
    lines ever did."""
    seen = judged(f)
    skip = mistakes("\n".join(source(f.name)) if code is None else code)
    lines = sorted(n for n in f.steps if n not in seen and n not in skip)
    functions = [
        fn.name for fn in f.functions if any(n in f.steps for n in fn.lines) and not any(n in seen for n in fn.lines)
    ]
    return lines, functions


def changed(diff: str) -> dict[str, set[int]]:
    """The lines of core/'s files a diff (git diff -U0) adds or changes, on its new side, by name under core/."""
    out: dict[str, set[int]] = {}
    name: str | None = None
    for line in diff.splitlines():
        if line.startswith("+++ "):
            path = line[4:]
            name = path[len("b/core/") :] if path.startswith("b/core/") else None
        elif name and line.startswith("@@ "):
            m = re.match(r"@@ -\S+ \+(\d+)(?:,(\d+))? @@", line)
            if m:
                start, count = int(m.group(1)), int(m.group(2) or 1)
                out.setdefault(name, set()).update(range(start, start + count))
    return out


def source(name: str) -> list[str]:
    try:
        with open(os.path.join(CODE, name), encoding="utf-8") as fh:
            return fh.read().splitlines()
    except OSError:
        return []


def text(lines: list[str], n: int) -> str:
    s = lines[n - 1].strip() if 0 < n <= len(lines) else ""
    return s if len(s) <= 90 else s[:87] + "..."


def share(part: int, whole: int) -> str:
    return f"{100 * part / whole:6.1f}" if whole else "     -"


def where(target: int) -> str:
    return "the function's end" if target < 0 else f"line {target}"


def table(files: Sequence[File]) -> list[str]:
    """Each file's lines and branches, and how many of them ran."""
    out = [f"{'':34}{'lines':>22}{'branches':>23}", f"{'':34}{'run':>8}{'of':>7}{'%':>7}{'run':>9}{'of':>7}{'%':>7}"]
    total = [0, 0, 0, 0]
    for f in files:
        run = len(f.statements) - len(f.missing)
        out.append(
            f"{f.name:34}{run:>8}{len(f.statements):>7}{share(run, len(f.statements)):>7}"
            f"{f.branches_run:>9}{f.branches:>7}{share(f.branches_run, f.branches):>7}"
        )
        total = [total[0] + run, total[1] + len(f.statements), total[2] + f.branches_run, total[3] + f.branches]
    out.append(
        f"{'total':34}{total[0]:>8}{total[1]:>7}{share(total[0], total[1]):>7}"
        f"{total[2]:>9}{total[3]:>7}{share(total[2], total[3]):>7}"
    )
    return out


def summary(files: Sequence[File]) -> str:
    """The totals, in a line."""
    lines = sum(len(f.statements) for f in files)
    run = lines - sum(len(f.missing) for f in files)
    branches, taken = sum(f.branches for f in files), sum(f.branches_run for f in files)
    return (
        f"run: {run} of {lines} lines ({share(run, lines).strip()}%), "
        f"{taken} of {branches} branches ({share(taken, branches).strip()}%)"
    )


def stops(code: str) -> set[int]:
    """The lines a statement that never goes on starts on: fail(...) and raise. Coverage counts the way on from
    such a statement (back to its loop, say) as a branch, which no run can take."""
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return set()
    return {node.lineno for node in ast.walk(tree) if isinstance(node, ast.stmt) and fails(node)}


def not_run(f: File, only: set[int] | None = None, code: str | None = None) -> list[str]:
    """The lines of f nothing runs, as runs of lines, and the branches never taken from lines that ran (but the
    way on from a failure, `stops`); with `only`, those among these lines. code: f's text, if not read from it."""
    lines = source(f.name) if code is None else code.split("\n")
    never_on = stops("\n".join(lines))
    missing = [n for n in f.missing if only is None or n in only]
    entries = [(a, f"{a if a == b else f'{a}-{b}':>11}  {text(lines, a)}") for a, b in ranges(missing, f.statements)]
    entries += [
        (n, f"{n:>11}  never to {', '.join(where(t) for t in targets)}: {text(lines, n)}")
        for n, targets in f.never.items()
        if (only is None or n in only) and n not in never_on
    ]
    return [entry for _, entry in sorted(entries)]


def report(files: Sequence[File]) -> list[str]:
    out = ["What the suites run of authzlib and cli (core/tests/coverage_report.py)", "", *table(files), ""]
    missed = sorted((f for f in files if f.missing or f.never), key=lambda f: (-len(f.missing), f.name))
    out.append("Not run: each run of lines nothing runs, and each branch never taken (the files with most first)")
    for f in missed:
        branches = sum(len(t) for t in f.never.values())
        out += ["", f"{f.name}: {len(f.missing)} lines, and {branches} branches from lines that ran", *not_run(f)]
    out += [
        "",
        "Compiled, never judged: lines of the code that writes the SQL deciding who may do what, run only in steps",
        "that compare no answers with the reference evaluator (difftest, genpolicy and around never met them)",
    ]
    for f in files:
        if f.name not in DECIDES:
            continue
        code = source(f.name)
        lines, functions = never_judged(f, "\n".join(code))
        if not lines:
            continue
        out += ["", f"{f.name}: {len(lines)} lines; functions none of whose lines they met: {len(functions)}"]
        out += [f"  {name}" for name in functions]
        out += [f"{a if a == b else f'{a}-{b}':>11}  {text(code, a)}" for a, b in ranges(lines, f.statements)]
    return out


def main(argv: Sequence[str]) -> int:
    ap = argparse.ArgumentParser(description="What the suites run of authzlib and cli, and what nothing runs.")
    ap.add_argument("dirs", nargs="+", metavar="DIR", help="where run_tests.sh measured (ROWSTILE_COVERAGE)")
    ap.add_argument("--out", metavar="DIR", help="where the combined data and the report go (the first DIR)")
    ap.add_argument("--diff", metavar="REF", help="also the lines changed since REF that nothing runs (exit 1 if any)")
    ap.add_argument("--floor", metavar="FILE", help="the PL/pgSQL never run, by schema (exit 1 unless it is FILE's)")
    a = ap.parse_args(argv)
    out = a.out or a.dirs[0]
    data, json_report = combine(a.dirs, out)
    files = read(json_report, steps_by_line(data))
    called = functions_measured(a.dirs)
    statements = coverage_plpgsql.measured(a.dirs)
    each = coverage_plpgsql.totals(statements, kind)
    database = [""] + functions_report(called) if called else []
    if statements.runs:
        database += ["", *coverage_plpgsql.report(statements, each, a.dirs)]
        gone = lost(called, statements)
        if gone:
            database += [
                "",
                "Called (Postgres counts them) but none of their statements counted: the profiler's counts went with",
                "the function's catalog row, made anew after the calls (an apply, a GRANT or REVOKE on it). A suite",
                "that does so measures first (tests/coverage_functions.sh), or what it ran is reported as never run:",
                *gone,
            ]
    with open(os.path.join(out, "report.txt"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(report(files) + database) + "\n")
    print("\n".join(table(files)))
    kinds = by_kind(called)
    calls = f"; {calls_summary(kinds)}" if kinds else ""
    if statements.runs:
        calls += f"; {coverage_plpgsql.summary(each)}"
        print(*coverage_plpgsql.memory(a.dirs), sep="\n")
    print(f"\n{summary(files)}{calls}; what nothing runs, line by line: {os.path.join(out, 'report.txt')}")
    floor_failed = False
    if a.floor:
        if not statements.runs:
            print(f"\nThe floor ({a.floor}): nothing was counted statement by statement (core/ci.sh --statements)")
            floor_failed = True
        else:
            said, floor_failed = coverage_plpgsql.judge(
                coverage_plpgsql.never_run(each), coverage_plpgsql.read_floor(a.floor), a.floor
            )
            print("", *said, sep="\n")
    if not a.diff:
        return 1 if floor_failed else 0
    # (in a container the checkout is someone else's, which git refuses unless told: this only reads)
    diff = subprocess.run(
        ["git", "-c", "safe.directory=*", "diff", "-U0", "--no-color", "--no-ext-diff", f"{a.diff}...HEAD", "--"]
        + ["authzlib", "cli"],
        cwd=CODE,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    new = changed(diff)
    found = [line for f in files if f.name in new for line in not_run(f, new[f.name])]
    print(f"\nChanged since {a.diff} and not run: {len(found)} (each a run of lines, or a branch never taken)")
    for f in files:
        if f.name in new and (lines := not_run(f, new[f.name])):
            print(f.name, *lines, sep="\n")
    return 1 if found or floor_failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

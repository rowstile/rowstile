"""What runs for a mutant, and in which order: the suites, the data that selects them, and the cheap phase.

The cheap phase, per mutant, without Postgres: the policies are compiled before and after the mutation (helper.py,
a child process each time) and the SQL is compared object by object (authzlib/statements.py reads it back). Its
kind says what comes of it:
- `sql`: the SQL of one of the fixed policies (POLICIES) changes. The suites whose run_tests.sh step called a
  changed function are selected (the call data: CI's coverage run, `functions.tsv`); a changed view, trigger or
  policy counts by the functions it names; a suite whose calls the data misses, by the policy it applies
  (POLICY_APPLIED).
- `other`: only another output changes: the cookbook's policies and tests, the four apps', docs.test.authz, the
  docs app's diagram, clients and diffs, or a migration tests/migrate_test.py checks. The suites that use it and
  those that ran its lines are selected.
- `python`: no compile runs it (the command's own code); the suites whose Python ran its lines are selected
  (coverage.py's contexts, one per step).
- `same`: the compiler runs it and no output of any policy in the repository changes: equivalent for all of them
  (it may still matter for a policy no file has). Not run.
- `unreached`: no compile and no suite ran its lines. Not run: a gap in what the suites run, not a mutant.
- `compiler fails` / `compiler hangs`: a policy that compiled no longer does (or the compile takes over a minute):
  caught without a suite.
The selected suites run first, then every other one, each group most catches per second first (Stats)."""

from __future__ import annotations

import concurrent.futures
import importlib.util
import json
import os
import re
import resource
import shutil
import sqlite3
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from types import ModuleType
from typing import Any

import mutants

HERE = os.path.dirname(os.path.abspath(__file__))
HELPER = os.path.join(HERE, "helper.py")
COMPILE_TIMEOUT = 60  # seconds: a mutant whose compile takes longer hangs (a loop that no longer ends)
COMPILE_MEMORY = 4 << 30  # bytes a compile may take: one that wants more is a mutant gone wrong

PG = "PGOPTIONS='-c client_min_messages=error'"
SCEN = (
    f"dropdb --if-exists authz_m 2>/dev/null; createdb authz_m && {PG} psql -X -q -v ON_ERROR_STOP=1 -d authz_m "
    "-f example/app_schema.sql >/dev/null && python3 compile_policy.py example/docs.authz > /tmp/m_docs.sql "
    f"&& python3 compile_policy.py example/docs.authz --tests > /tmp/m_tests.sql && {PG} psql -X -q "
    "-v ON_ERROR_STOP=1 -d authz_m -f /tmp/m_docs.sql >/dev/null && psql -X -q -v ON_ERROR_STOP=1 "
    "-v docs_tests=/tmp/m_tests.sql -d authz_m -f tests/scenario.sql"
)
MSCEN = (
    f"dropdb --if-exists authz_m 2>/dev/null; createdb authz_m && {PG} psql -X -q -v ON_ERROR_STOP=1 -d authz_m "
    "-f tests/multi_schema.sql >/dev/null && python3 compile_policy.py tests/multi.authz > /tmp/m_multi.sql "
    f"&& {PG} psql -X -q -v ON_ERROR_STOP=1 -d authz_m -f /tmp/m_multi.sql >/dev/null "
    "&& psql -X -q -v ON_ERROR_STOP=1 -d authz_m -f tests/multi_scenario.sql"
)
# unit_test.py without the change detectors: Golden (it fails on any change to the generated SQL, not a check of
# what the SQL means) and Survivors (it fails when a listed survivor's line changes, as each mutant there does).
# Nor Encodings and Editors, which ask the repository's git. The other checks that ask it (in Layout and Executable)
# skip themselves: git refuses a checkout another user owns, and the container runs them as root.
UNIT = (
    "python3 -c \"import sys, unittest; sys.argv = ['unit_test']; sys.path.insert(0, 'tests'); import unit_test as u; "
    "c = [v for k, v in vars(u).items() if isinstance(v, type) and issubclass(v, unittest.TestCase) "
    "and k not in ('Golden', 'Survivors', 'Encodings', 'Editors')]; "
    "s = unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromTestCase(x) for x in c); "
    'sys.exit(not unittest.TextTestRunner(verbosity=0).run(s).wasSuccessful())"'
)
# Each suite and how it runs, from core/ (shorter than run_tests.sh's where a suite takes a size: a mutant runs
# many of them)
SUITES: list[tuple[str, str]] = (
    [
        ("difftest " + g, f"python3 tests/difftest.py --gen {g} --steps 12 --seed 7 --quiet --db authz_m_{g}")
        for g in ("docs", "alt", "multi", "composite", "loop", "cross")
    ]
    + [("scenario", SCEN), ("multi scenario", MSCEN)]
    + [
        (s, f"bash tests/{s}.sh")
        for s in (
            "sessions",
            "identity",
            "principals",
            "governance",
            "adversarial",
            "masks",
            "apply",
            "keep",
            "moves",
            "devx",
            "cli",
            "concurrency",
            "migrations",
            "capitals",
            "children",
            "cookbook",
        )
    ]
    + [(s, f"python3 tests/{s}_test.py") for s in ("confidence", "studio", "tools")]
    + [
        ("around", "python3 tests/around.py --policies 8 --steps 4 --no-shrink --db authz_m_around"),
        ("genpolicy", "python3 tests/genpolicy.py --policies 6 --steps 6 --no-shrink --db authz_m_gen"),
        ("interleavings", 'python3 tests/interleave.py --levels "read committed" --db authz_m_interleave'),
        ("stress", "bash tests/stress.sh 15"),
        ("policy errors", "python3 tests/policy_errors.py"),
        ("fuzz parser", "python3 tests/fuzz_parser.py --cases 1500"),
        ("review", "bash tests/review.sh"),
        ("migrate vs apply", "python3 tests/migrate_test.py"),
        ("mcp", "python3 tests/mcp_test.py"),
        ("lsp", "python3 tests/lsp_test.py"),
        ("docs", "bash tests/docs_test.sh"),
        ("reference", "bash tests/reference.sh"),
        ("rewrites", "python3 tests/rewrites.py --policies 4 --seed 1 --db authz_m_rewrites"),
        ("conditions", "python3 tests/conditions_test.py --cases 3000 --seed 1"),
        ("hand answers", "bash tests/hand_answers.sh"),
        ("cuts", "python3 tests/interrupt.py"),
        ("invariance", "python3 tests/invariance.py --policies 1 --seed 2 --db authz_m_invariance"),
        ("invariance fixed", "python3 tests/invariance.py --fixed"),
        ("small", "python3 tests/small.py --size 3 --db authz_m_small"),
        ("unit", UNIT),
    ]
)

# The fixed policies, compiled before and after each mutation: (label, path from the checkout's root, its tests)
POLICIES: list[tuple[str, str, bool]] = [
    ("docs", "core/example/docs.authz", False),
    ("docs tests", "core/example/docs.authz", True),
    ("alt", "core/tests/alt.authz", False),
    ("multi", "core/tests/multi.authz", False),
    ("composite", "core/tests/composite.authz", False),
    ("loop", "core/tests/loop.authz", False),
    ("cross", "core/tests/cross.authz", False),
    ("children", "core/tests/children.authz", False),
    ("prisma", "core/tests/prisma.authz", False),
    ("patterns", "core/tests/patterns.authz", False),
]
# a policy that no longer compiles: the suites that compile it go first (docs or multi: the compiler fails)
POLICY_SUITES: dict[str, list[str]] = {
    "docs tests": ["scenario", "devx"],
    "alt": ["difftest alt", "adversarial"],
    "composite": ["difftest composite", "adversarial"],
    "loop": ["difftest loop"],
    "cross": ["difftest cross", "adversarial"],
    "children": ["children"],
    "prisma": ["capitals"],
    "patterns": ["adversarial"],
}
# Suites the call data misses: the scenario's database is measured only after the next step has applied the docs
# policy to it again (each function made anew, its count gone), and the multi scenario's in part; most databases
# of the suites that apply fixed policies with the command (adversarial.sh: five of them; children.sh, capitals.sh:
# their own) too. They are selected whenever the policy they apply compiles to other SQL.
POLICY_APPLIED: dict[str, list[str]] = {
    "docs": ["scenario", "keep"],
    "multi": ["multi scenario", "adversarial"],
    "alt": ["adversarial"],
    "composite": ["adversarial"],
    "cross": ["adversarial"],
    "patterns": ["adversarial"],
    "children": ["children"],
    "prisma": ["capitals"],
}
# run_tests.sh's steps (what coverage names a context, by how it starts) and the suites each one runs
STEP_SUITES: list[tuple[str, list[str]]] = [
    ("end-to-end scenario through RLS", ["scenario"]),
    ("re-applying the policy keeps shares", ["keep"]),
    ("the share API and newer features", ["multi scenario"]),
    ("identities: ", ["identity", "principals", "sessions"]),
    ("governance: ", ["governance"]),
    ("masked columns", ["masks"]),
    ("developer tools", ["tools", "lsp"]),
    ("applying with the rowstile command", ["apply"]),
    ("the rowstile command", ["cli"]),
    ("the command over tables named as Prisma", ["capitals"]),
    ("tables under a governed one", ["children"]),
    ("policy changes as migrations", ["migrations"]),
    ("prove, coverage", ["confidence"]),
    ("why, and how to grant", ["studio"]),
    ("day to day", ["devx"]),
    ("concurrent changes to the tree", ["concurrency"]),
    ("moves and links", ["moves"]),
    ("the app role trying", ["adversarial"]),
    ("the cookbook's recipes", ["cookbook"]),
    ("random policies in random worlds", ["around"]),
    ("random policies, compared with", ["genpolicy"]),
    ("every order of two tree writes", ["interleavings"]),
    ("tree writes under stress", ["stress"]),
    ("policy mistakes are reported", ["policy errors"]),
    ("broken policies are refused", ["fuzz parser"]),
    ("rowstile review and fmt", ["review"]),
    ("a migration leaves what applying", ["migrate vs apply"]),
    ("the MCP server", ["mcp"]),
    ("docs/getting-started.md runs", ["docs"]),
    ("the reference runs as written", ["reference"]),
    ("random policies rewritten", ["rewrites"]),
    ("simple conditions read as Postgres", ["conditions"]),
    ("answers worked out by hand", ["hand answers"]),
    ("the command and a migration cut half way", ["cuts"]),
    ("other policies' first apply cut half way", ["cuts"]),
    ("the fixed policies written another way", ["invariance fixed"]),
    ("random policies written another way", ["invariance"]),
    ("every small policy", ["small"]),
    ("compile the example policy", ["scenario"]),
    ("fast checks without a database", ["unit"]),
]
# steps no suite of the sweep stands for: what they'd catch, another catches sooner (or they need the network)
NOT_SWEPT = ("upgrading",)
DIFFTEST_STEP = re.compile(r"random changes, compared with the reference evaluator \((\w+),")
PRIOR = 0.5  # catches a suite is credited with before any: those with none go cheapest first
DEFAULT_SECONDS = 60.0  # a suite the stats don't have yet
NO_STATS = f"no run (every suite counted at {DEFAULT_SECONDS:.0f} s with no catch, until this one learns)"


def suites_of_step(step: str) -> list[str]:
    m = DIFFTEST_STEP.match(step)
    if m:
        return ["difftest " + m.group(1)]
    for prefix, suites in STEP_SUITES:
        if step == prefix or (step.startswith(prefix) and prefix != "the rowstile command"):
            return suites
    return []


def to_ranges(lines: set[int]) -> list[list[int]]:
    out: list[list[int]] = []
    for n in sorted(lines):
        if out and n == out[-1][1] + 1:
            out[-1][1] = n
        else:
            out.append([n, n])
    return out


# ---------------------------------------------------------------------------------------------------------------
# The call data and the stats


@dataclass
class Calls:
    """Which suites called each of rowstile's functions, and ran each line of authzlib and cli."""

    functions: dict[str, set[str]]
    lines: dict[str, dict[str, list[list[int]]]]
    source: str

    @staticmethod
    def load(path: str | None) -> Calls:
        if not path or not os.path.exists(path):
            return Calls({}, {}, "none: every suite in the order of the stats")
        with open(path, encoding="utf-8") as fh:
            d = json.load(fh)
        # a step no suite stands for (NOT_SWEPT, or one the data's run had and this checkout doesn't) selects nothing
        known = {s for s, _ in SUITES}
        functions = {k: set(v) & known for k, v in d["functions"].items()}
        lines = {f: {s: r for s, r in per.items() if s in known} for f, per in d["lines"].items()}
        return Calls(functions, lines, d["source"])

    def ran(self, fname: str, line: int) -> set[str]:
        out = set()
        for suite, ranges in self.lines.get(fname, {}).items():
            if any(a <= line <= b for a, b in ranges):
                out.add(suite)
        return out


def refresh_calls(dirs: list[str], source: str, dest: str) -> list[str]:
    """The call data from a run measured with coverage (core/ci.sh --coverage, or CI's coverage-pg16-<part>
    artifacts, a directory each): functions.tsv (each step's calls of rowstile's functions) and .coverage
    (coverage.py's data, one context per step). Says which steps it couldn't map to a suite."""
    functions: dict[str, set[str]] = {}
    lines: dict[str, dict[str, set[int]]] = {}
    unmapped: set[str] = set()
    for d in dirs:
        tsv = os.path.join(d, "functions.tsv")
        with open(tsv if os.path.exists(tsv) else os.devnull, encoding="utf-8") as fh:  # the unit part has none
            for row in fh:
                p = row.rstrip("\n").split("\t")
                if len(p) < 8 or p[7] != "t":
                    continue
                suites = suites_of_step(p[0])
                if not suites:
                    unmapped.add(p[0])
                functions.setdefault(f"{p[2]}.{p[3]}", set()).update(suites)
        db = sqlite3.connect(f"file:{os.path.join(d, '.coverage')}?mode=ro", uri=True)
        files = {}
        for fid, path in db.execute("SELECT id, path FROM file"):
            m = re.search(r"/core/((?:authzlib|cli)/[^/]+\.py)$", path)
            if m:
                files[fid] = m.group(1)
        contexts = {
            cid: suites_of_step(name) or ["(" + name + ")"]
            for cid, name in db.execute("SELECT id, context FROM context")
        }
        for fid, cid, a, b in db.execute("SELECT file_id, context_id, fromno, tono FROM arc"):
            f = files.get(fid)
            if f is None:
                continue
            for suite in contexts.get(cid, []):
                s = lines.setdefault(f, {}).setdefault(suite, set())
                if a > 0:
                    s.add(a)
                if b > 0:
                    s.add(b)
        db.close()
    out = {
        "source": source,
        "functions": {k: sorted(v) for k, v in sorted(functions.items())},
        "lines": {f: {s: to_ranges(v) for s, v in sorted(per.items())} for f, per in sorted(lines.items())},
    }
    with open(dest, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=0, sort_keys=True)
    return sorted(unmapped)


@dataclass
class Stats:
    """Each suite's catches and its seconds (a running mean of its green runs): the order learns from both. No file
    in the repository holds them: each run starts from the newest run's (mutants.yml), and source names the run
    that learned them last."""

    suites: dict[str, dict[str, float]]
    source: str
    lock: threading.Lock = field(default_factory=threading.Lock)

    @staticmethod
    def load(path: str | None) -> Stats:
        """A run's stats.json; without one, every suite at DEFAULT_SECONDS with no catch."""
        d: dict[str, Any] = {"suites": {}, "source": NO_STATS}
        if path:
            with open(path, encoding="utf-8") as fh:
                d = json.load(fh)
        for s, _ in SUITES:
            d["suites"].setdefault(s, {"catches": 0, "seconds": DEFAULT_SECONDS, "runs": 0})
        return Stats(d["suites"], d.get("source") or f"{path}, which names no run")

    def save(self, path: str) -> None:
        with self.lock, open(path + ".tmp", "w", encoding="utf-8") as fh:
            json.dump({"source": self.source, "suites": self.suites}, fh, indent=1, sort_keys=True)
            fh.write("\n")
        os.replace(path + ".tmp", path)

    def seconds(self, s: str) -> float:
        return float(self.suites[s]["seconds"])

    def score(self, s: str) -> float:
        return (float(self.suites[s]["catches"]) + PRIOR) / max(self.seconds(s), 0.5)

    def ran_green(self, s: str, secs: float) -> None:
        with self.lock:
            st = self.suites[s]
            n = min(int(st["runs"]), 19)  # a running mean of the last twenty or so: the machines change
            st["seconds"] = round((float(st["seconds"]) * n + secs) / (n + 1), 1)
            st["runs"] = int(st["runs"]) + 1

    def caught(self, s: str) -> None:
        with self.lock:
            if s in self.suites:
                self.suites[s]["catches"] = int(self.suites[s]["catches"]) + 1

    def order(self, selected: set[str] | list[str]) -> list[str]:
        """Every suite: those selected first, then the others; each group most catches per second first."""
        return sorted((s for s, _ in SUITES), key=lambda s: (s not in selected, -self.score(s), self.seconds(s)))


# ---------------------------------------------------------------------------------------------------------------
# Compiling (helper.py, in a child process) and comparing


def no_bytecode_env() -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPYCACHEPREFIX"}
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return env


def limits() -> None:
    resource.setrlimit(resource.RLIMIT_AS, (COMPILE_MEMORY, COMPILE_MEMORY))


def compile_outputs(core: str, root: str, spec: str, trace: bool = False, timeout: int = COMPILE_TIMEOUT * 3) -> dict[str, Any]:  # fmt: skip
    """What each output of the spec file is with core's authzlib (subprocess.TimeoutExpired past `timeout`)."""
    args = [sys.executable, "-B", "-I", HELPER, core, root, spec] + (["--trace"] if trace else [])
    p = subprocess.run(args, cwd=core, env=no_bytecode_env(), capture_output=True, text=True, timeout=timeout,
                       preexec_fn=limits)  # fmt: skip
    if p.returncode != 0:
        if trace:  # unmutated: the outputs can't be measured
            raise RuntimeError(f"the compile helper: {p.stderr[-500:]}")
        with open(spec, encoding="utf-8") as fh:  # a mutant that breaks authzlib's import: every output fails
            return {label: f"FAILED: the helper: {p.stderr[-300:]}" for label, *_ in json.load(fh)}
    return json.loads(p.stdout)


def load_statements(core: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location("mutants_statements", os.path.join(core, "authzlib", "statements.py"))
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.dont_write_bytecode = True
    spec.loader.exec_module(mod)
    return mod


def objects(st: ModuleType, sql: str) -> dict[str, str]:
    """The compiled SQL by the object each statement makes ('function authz_int.canon(p_type text, ...)'); a
    statement that makes nothing goes with the one before it."""
    out: dict[str, str] = {}
    cur = "(start)"
    for comments, stmt in st.split(sql):
        m = st.made(stmt, comments)
        if m:
            cur = f"{m[0]} {m[1]}"
        out[cur] = out.get(cur, "") + stmt + ";\n"
    return out


def fixed_outputs() -> list[tuple[str, str, str | None, str]]:
    return [(label, path, None, "tests" if tests else "sql") for label, path, tests in POLICIES]


def other_outputs(root: str) -> list[tuple[str, str, str | None, str]]:
    """Every other output of the repository's policies: (label, policy, a tests file or None, what)."""
    out: list[tuple[str, str, str | None, str]] = [
        ("docs + docs.test.authz", "core/example/docs.authz", "core/example/docs.test.authz", "tests"),
        ("docs graph", "core/example/docs.authz", None, "graph"),
        ("docs diff", "core/example/docs.authz", None, "diff"),
        ("docs diff users", "core/example/docs.authz", None, "diff users"),
        ("docs client ts", "core/example/docs.authz", None, "ts"),
        ("docs client py", "core/example/docs.authz", None, "py"),
        ("multi client ts", "core/tests/multi.authz", None, "ts"),
    ]
    cb = os.path.join(root, "docs", "cookbook")
    for name in sorted(os.listdir(cb)):
        p = f"docs/cookbook/{name}/policy.authz"
        if os.path.isfile(os.path.join(root, p)):
            out.append((f"cookbook {name}", p, None, "sql"))
            t = f"docs/cookbook/{name}/tests.authz"
            if os.path.isfile(os.path.join(root, t)):
                out.append((f"cookbook {name} tests", p, t, "tests"))
    for app in ("examples/filemanager", "examples/messenger", "integrations/fastapi", "integrations/nextjs"):
        p = f"{app}/db/policy.authz"
        if os.path.isfile(os.path.join(root, p)):
            out.append((app, p, None, "sql"))
            tdir = os.path.join(root, app, "db", "tests")
            for t in sorted(os.listdir(tdir)) if os.path.isdir(tdir) else []:
                out.append((f"{app} tests", p, f"{app}/db/tests/{t}", "tests"))
    return out


def migration_outputs(root: str) -> list[tuple[str, str, str | None, str]]:
    """Each migration tests/migrate_test.py checks, both ways."""
    sys.path.insert(0, os.path.join(root, "core", "tests"))
    try:
        import migrate_test  # ty: ignore[unresolved-import] - the checkout's
    finally:
        sys.path.pop(0)
    out: list[tuple[str, str, str | None, str]] = []
    for i, (name, _schema, old, new) in enumerate(migrate_test.CASES):
        for way in (0, 1) if old != new else (0,):
            out.append((f"migration {i} ({name[:50]}){' back' if way else ''}", "", None, f"migration {i} {way}"))
    sys.modules.pop("migrate_test", None)
    return out


def suites_of_output(label: str) -> list[str]:
    if label.startswith("migration "):
        return ["migrate vs apply", "migrations"]
    if " diff" in label:
        return ["governance", "masks", "devx"]
    if label.startswith("cookbook"):
        return ["cookbook"]
    if label.startswith("docs + docs.test"):
        return ["devx", "cli"]
    if " client " in label or label.endswith("graph"):
        return ["tools"]
    return []


@dataclass
class Group:
    """Outputs compiled together: their spec file, what they are unmutated, the lines of authzlib that made them."""

    spec: str
    base: dict[str, str]
    executed: dict[str, set[int]]


@dataclass
class Base:
    """The outputs unmutated, measured once: the fixed policies (spec, SQL and lines run), then the other groups."""

    root: str
    fixed: Group
    groups: list[Group]


def measure(root: str, work: str) -> Base:
    """Compiles every output unmutated, tracing the lines each group runs; writes the spec files to work."""
    work = os.path.abspath(work)  # the helper runs in core/
    os.makedirs(work, exist_ok=True)
    core = os.path.join(root, "core")
    groups: list[Group] = []
    for name, outputs in (("fixed", fixed_outputs()), ("other-outputs", other_outputs(root)),
                          ("migrations", migration_outputs(root))):  # fmt: skip
        spec = os.path.join(work, name + ".json")
        with open(spec, "w", encoding="utf-8") as fh:
            json.dump(outputs, fh)
        base = compile_outputs(core, root, spec, trace=True, timeout=COMPILE_TIMEOUT * 20)  # tracing is slow
        executed = {f: set(v) for f, v in base.pop("(executed)").items()}
        bad = [k for k, v in base.items() if v.startswith("FAILED")]
        if bad:
            print(f"note: unmutated, these don't compile and are left out: {bad}", flush=True)
        groups.append(Group(spec, {k: v for k, v in base.items() if k not in bad}, executed))
    return Base(root, groups[0], groups[1:])


@dataclass
class Plan:
    kind: str  # sql, other, python, same, unreached, compiler fails, compiler hangs, error
    selected: list[str]  # the suites the mutation's changes chose
    changed: list[str]  # objects, or outputs that changed or fail
    note: str = ""


RUNNABLE = ("sql", "other", "python")


class Planner:
    """Classifies a mutant (the cheap phase) on a copy of core: before and after, every output it can change."""

    def __init__(self, base: Base, calls: Calls) -> None:
        self.base, self.calls = base, calls
        self.st = load_statements(os.path.join(base.root, "core"))
        self.base_objects = {k: objects(self.st, v) for k, v in base.fixed.base.items()}
        self.sources: dict[str, mutants.Source] = {}
        self._rev: dict[str, set[str]] | None = None

    def rev(self) -> dict[str, set[str]]:
        """What names what, in the unmutated SQL: {name: the functions that name it} (made once)."""
        if self._rev is None:
            rev: dict[str, set[str]] = {}
            for objs in self.base_objects.values():
                for k, body in objs.items():
                    if k.startswith("function "):
                        me = self.st.unquoted(k[len("function ") :])
                        for r in self.st.references(body):
                            if r != me:
                                rev.setdefault(r, set()).add(me)
            self._rev = rev
        return self._rev

    def ran_lines(self, fname: str, lines: set[int]) -> set[str]:
        out: set[str] = set()
        for ln in lines:
            out |= self.calls.ran("authzlib/" + fname, ln)
        return out

    def source(self, fname: str, text: str) -> mutants.Source:
        got = self.sources.get(fname)
        if got is None or got.text != text:
            got = self.sources[fname] = mutants.Source(fname, text)
        return got

    def differs(self, label: str, before: str, after: str | None) -> bool:
        """SQL compared statement by statement, its comments aside (as the fixed policies are)."""
        if after is None or after == before:
            return after is None
        if after.startswith("FAILED") or any(x in label for x in (" graph", " client ", "migration ")):
            return True
        return [x for _, x in self.st.split(before)] != [x for _, x in self.st.split(after)]

    def fixed(self, mutated_core: str, ran: set[str]) -> Plan | None:
        """The fixed policies' SQL after the mutation: a plan if it changed or a policy no longer compiles."""
        fx = self.base.fixed
        after = compile_outputs(mutated_core, self.base.root, fx.spec, timeout=COMPILE_TIMEOUT)
        failed = [k for k in self.base_objects if after.get(k, "FAILED").startswith("FAILED")]
        if any(k in ("docs", "multi") for k in failed):
            return Plan("compiler fails", [], failed)
        changed: dict[str, tuple[str, str]] = {}  # object -> (before, after) texts
        tests_changed = False
        policies: set[str] = set()  # the policies whose SQL changed
        for label, before_objs in self.base_objects.items():
            if label in failed or after[label] == fx.base[label]:
                continue
            after_objs = objects(self.st, after[label])
            for k in set(before_objs) | set(after_objs):
                if before_objs.get(k) != after_objs.get(k):
                    tests_changed |= label == "docs tests"
                    policies.add(label)
                    b, a = changed.get(k, ("", ""))
                    changed[k] = (b + before_objs.get(k, ""), a + after_objs.get(k, ""))
        if not changed and not failed:
            return None
        selected: set[str] = set()
        for k in failed:
            selected.update(POLICY_SUITES.get(k, []))
        rev = self.rev()
        names: set[str] = set()
        for k, (b, a) in changed.items():
            kind, _, key = k.partition(" ")
            if kind == "function":
                names.add(self.st.unquoted(key))
            else:
                names |= self.st.references(b + a)
                if kind in ("view", "table"):
                    names |= rev.get(self.st.unquoted(key), set())
        for n in names:
            got = self.calls.functions.get(n, set())
            if not got:  # never seen called (an inlined SQL function, a trigger nothing fired): its callers
                for caller in rev.get(n, set()):
                    got = got | self.calls.functions.get(caller, set())
            selected |= got
        for label in policies:  # suites whose calls the data misses, by the policy they apply
            selected.update(POLICY_APPLIED.get(label, []))
        if tests_changed:
            selected |= {"scenario"} | ran
        if not selected:  # SQL changed that no step was seen running: whoever ran the statement
            selected = set(ran)
        return Plan("sql", sorted(selected), sorted(changed) + [f"(fails) {k}" for k in failed])

    def classify(self, m: mutants.Mutant, text: str, mutated_core: str) -> Plan:
        """text: the file unmutated; mutated_core: a copy of core where it is mutated."""
        lines = self.source(m.file, text).header_lines(m.line, m.end)
        ran = self.ran_lines(m.file, lines)
        in_fixed = bool(lines & self.base.fixed.executed.get(m.file, set()))
        in_groups = [g for g in self.base.groups if lines & g.executed.get(m.file, set())]
        if not in_fixed and not in_groups:
            if ran:
                return Plan("python", sorted(ran), [])
            return Plan("unreached", [], [], "no policy's compile and no suite ran its lines")
        if in_fixed:
            p = self.fixed(mutated_core, ran)
            if p is not None:
                return p
        for g in in_groups:
            after = compile_outputs(mutated_core, self.base.root, g.spec)
            changed = [k for k, v in g.base.items() if self.differs(k, v, after.get(k))]
            failed = [k for k in changed if str(after.get(k, "FAILED")).startswith("FAILED")]
            if failed:
                return Plan("compiler fails", [], failed)
            if changed:
                sel = set(ran)
                for k in changed:
                    sel.update(suites_of_output(k))
                return Plan("other", sorted(sel), changed)
        if m.func == "<module>" and ran:
            # its lines run on import, which any compile does: an unchanged output says nothing of the code that
            # reads the name later (database.py's REMOVE_SQL, run by `rowstile remove`)
            return Plan("python", sorted(ran), [], "no output of any policy changed; run on import")
        return Plan("same", sorted(ran), [], "no output of any policy changed")


# ---------------------------------------------------------------------------------------------------------------
# The cheap phase, on processes side by side: each its own copy of core, mutated in turn


_planner: Planner | None = None
_copy = ""


def _init(base: Base, calls: Calls, work: str) -> None:
    global _planner, _copy
    _copy = os.path.join(work, f"copy-{os.getpid()}")
    shutil.rmtree(_copy, ignore_errors=True)
    os.makedirs(_copy)
    skip = shutil.ignore_patterns("__pycache__", "golden", "fixtures")
    for sub in ("authzlib", "example", "tests"):
        shutil.copytree(os.path.join(base.root, "core", sub), os.path.join(_copy, sub), ignore=skip)
    _planner = Planner(base, calls)


def _one(m: mutants.Mutant) -> dict[str, Any]:
    assert _planner is not None
    path = os.path.join(_copy, "authzlib", m.file)
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    t = time.time()
    if text.count(m.old) != 1:
        return {"id": m.id, "kind": "error", "selected": [], "changed": [], "note": "its text isn't found once"}
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text.replace(m.old, m.new, 1))
    try:
        p = _planner.classify(m, text, _copy)
    except subprocess.TimeoutExpired:
        p = Plan("compiler hangs", [], [])
    except Exception as e:
        p = Plan("error", [], [], f"{type(e).__name__}: {e}")
    finally:
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
    return {"id": m.id, "kind": p.kind, "selected": p.selected, "changed": p.changed[:3],
            "n_changed": len(p.changed), "note": p.note, "seconds": round(time.time() - t, 2)}  # fmt: skip


def cheap(base: Base, calls: Calls, work: str, candidates: list[mutants.Mutant], procs: int, runnable: int | None) -> list[dict[str, Any]]:  # fmt: skip
    """Classifies the candidates in their order, `procs` at a time, until `runnable` of them need suites (None:
    all). Each row: the mutant's id, its kind, the suites selected, the first objects it changes."""
    out: list[dict[str, Any]] = []
    found = 0
    t0 = time.time()
    batch = max(procs * 4, 8)
    with concurrent.futures.ProcessPoolExecutor(procs, initializer=_init, initargs=(base, calls, work)) as ex:
        for i in range(0, len(candidates), batch):
            for row in ex.map(_one, candidates[i : i + batch]):
                out.append(row)
                found += row["kind"] in RUNNABLE
            print(
                f"  classified {len(out)} of {len(candidates)}, {found} to run ({time.time() - t0:.0f} s)", flush=True
            )
            if runnable is not None and found >= runnable:
                break
    for d in os.listdir(work):
        if d.startswith("copy-"):
            shutil.rmtree(os.path.join(work, d), ignore_errors=True)
    if runnable is not None:  # the last batch may have gone past it: those are left for the next run
        keep, n = [], 0
        for row in out:
            if row["kind"] in RUNNABLE:
                if n >= runnable:
                    continue
                n += 1
            keep.append(row)
        out = keep
    return out

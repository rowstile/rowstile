"""Compiles policies with a copy of authzlib, in a child process of its own, and writes what each gave as JSON.

    python3 -B -I helper.py CORE ROOT SPEC [--trace]

CORE is the copy (its authzlib/ and tests/, maybe mutated), ROOT the checkout the policies are read from, SPEC a JSON
list of [label, policy, tests or null, what], paths from ROOT. What is `sql` (compile), `tests` (compile_tests, with
the tests file if one is named), `graph`, `diff`, `diff users`, `ts`, `py` (the clients), or `migration <case>
<0|1>` (tests/migrate_test.py's case, old to new or back). A compile that raises gives `FAILED: ...`. With --trace,
`(executed)` also holds the lines of authzlib each file ran. A fresh process each time: nothing of another
mutant's authzlib stays imported, and -B -I keep bytecode and the caller's environment out. It imports nothing
of the folder it is in (-I leaves that off the path)."""

from __future__ import annotations

import json
import os
import sys
from collections.abc import Callable
from types import FrameType
from typing import Any

TraceFunction = Callable[[FrameType, str, object], object]


def migration(core: str, what: str) -> str:
    """The migrations of one of tests/migrate_test.py's cases (`migration <i> <0: old to new | 1: back>`)."""
    sys.path.insert(0, os.path.join(core, "tests"))
    import migrate_test  # ty: ignore[unresolved-import] - the copy's, as the suite runs it
    from authzlib import database, migrate

    _, i, way = what.split()
    name, _schema, old, new = migrate_test.CASES[int(i)]
    a, b = (old, new) if way == "0" else (new, old)
    lock = migrate.lock_of(database.migratable(a, {})[1])
    # (the build a migration records hashes authzlib's files, so it differs for every mutant these cases run: each
    # is `other` and goes to the suites, kept so on purpose, as the suites' own policies may show what these don't)
    return "\n-- next\n".join(m.sql for m in database.migrations(b, {}, lock, name))


def main() -> None:
    core, root, spec = sys.argv[1:4]
    trace = "--trace" in sys.argv[4:]
    sys.dont_write_bytecode = True
    sys.path.insert(0, core)
    os.chdir(core)
    executed: dict[str, set[int]] = {}
    lib = os.path.join(core, "authzlib") + os.sep

    def local(frame: FrameType, event: str, arg: object) -> TraceFunction:
        if event == "line":
            executed.setdefault(os.path.basename(frame.f_code.co_filename), set()).add(frame.f_lineno)
        return local

    def tracer(frame: FrameType, event: str, arg: object) -> TraceFunction | None:
        if frame.f_code.co_filename.startswith(lib):
            executed.setdefault(os.path.basename(frame.f_code.co_filename), set()).add(frame.f_lineno)
            return local
        return None

    with open(spec, encoding="utf-8") as fh:
        outputs = json.load(fh)
    if trace:
        sys.settrace(tracer)
    from authzlib import Compiler, parse_policy

    out: dict[str, Any] = {}
    for label, policy, tests, what in outputs:
        try:
            if what.startswith("migration "):
                out[label] = migration(core, what)
                continue
            with open(os.path.join(root, policy), encoding="utf-8") as fh:
                c = Compiler(parse_policy(fh.read(), policy))
            if what == "tests":
                extra: dict[str, str] = {}
                if tests:
                    with open(os.path.join(root, tests), encoding="utf-8") as fh:
                        extra[tests] = fh.read()
                c.add_test_files(extra)
                out[label] = c.compile_tests(policy)
            elif what == "graph":
                c.compile(policy)
                out[label] = c.graph()
            elif what.startswith("diff"):
                out[label] = c.compile_diff(policy, ["1", "2"] if what == "diff users" else None)
            elif what in ("ts", "py"):
                c.compile(policy)
                out[label] = c.client(what, os.path.basename(policy))
            else:
                out[label] = c.compile(policy)
        except Exception as e:
            out[label] = f"FAILED: {type(e).__name__}: {e}"
    sys.settrace(None)
    if trace:
        out["(executed)"] = {f: sorted(v) for f, v in executed.items()}
    json.dump(out, sys.stdout)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""fuzz_coverage: fuzz_parser's rule, with a coverage-guided search over the parser and the compiler.

    python3 -m pip install --require-hashes -r tests/fuzz-requirements.txt    (Atheris; Linux x86_64)
    python3 tests/fuzz_coverage.py [corpus_dir] [-max_total_time=600] [-artifact_prefix=dir/] [libFuzzer's flags]

fuzz_parser.py mutates the example policies at random. This one runs them through Atheris (libFuzzer for Python),
which watches which branches of authzlib each input reaches, keeps the inputs that reach new ones and mutates
those: it follows what the code does with a policy. The rule is the same (fuzz_parser.check): a policy is
accepted, or refused with a line it has and words inside its text; never another exception, never seconds.

It starts from every .authz file in the repository (copied into the corpus folder, a temporary one unless named).
A problem stops it: the input is saved as crash-<hash> (in -artifact_prefix), and running the script with that
file as its argument runs it again. Every night (nightly.yml, the job fuzz), for twenty minutes.
"""

import os
import shutil
import sys
import tempfile
import time

import atheris  # ty: ignore[unresolved-import] - installed only where it runs (fuzz-requirements.txt)

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.dirname(HERE))

with atheris.instrument_imports(include=["authzlib"]):
    import fuzz_parser


def seeds() -> list[str]:
    """The repository's policies, recipes and tests included."""
    found = []
    for root, dirs, files in os.walk(REPO):
        dirs[:] = [d for d in dirs if d not in {".git", "node_modules", ".venv", ".ci", "dist", "out"}]
        found += [os.path.join(root, f) for f in files if f.endswith(".authz")]
    return sorted(found)


def test_one_input(data: bytes) -> None:
    text = data.decode("utf-8", errors="replace")
    started = time.perf_counter()
    what, _ = fuzz_parser.check(text)
    took = time.perf_counter() - started
    if took > 5:
        what = what or f"took {took:.1f} s"
    if what:
        raise AssertionError(what)


def main() -> None:
    args = sys.argv[1:]
    dirs = [a for a in args if not a.startswith("-") and os.path.isdir(a)]
    if not dirs and not [a for a in args if not a.startswith("-")]:
        # no corpus folder and no input to run again: a temporary corpus
        dirs = [tempfile.mkdtemp(prefix="fuzz_coverage_")]
        args.insert(0, dirs[0])
    for i, path in enumerate(seeds()) if dirs else ():
        shutil.copy(path, os.path.join(dirs[0], f"seed-{i:03d}.authz"))
    if not any(a.startswith("-timeout=") for a in args):
        args.append("-timeout=30")  # a case that hangs is a problem too (fuzz_parser's limit is 5 s)
    atheris.Setup([sys.argv[0], *args], test_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""compile_policy: the compiler without a database, for the suites and for development: the SQL for psql.

    python3 compile_policy.py docs.authz > docs.sql                                # views, triggers, RLS, API
    python3 compile_policy.py docs.authz --check                                   # only report mistakes
    python3 compile_policy.py docs.authz --tests [tests/*.authz] > docs_tests.sql  # the policy's tests, and more
    python3 compile_policy.py docs.authz --diff [--users 1,2] | psql               # who gains/loses access
                                                                                   # if applied (rolled back)

Apply the output with psql as the owner of the tables. It runs in one transaction, so a policy change applies
fully or not at all, and re-applying replaces the previous version while keeping people's shares. Installs
don't carry this script: the rowstile command does the same against a database (rowstile --help).
"""

import argparse
import io
import os
import sys
from typing import Literal, NamedTuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from authzlib import Compiler, PolicyError, parse_policy

Mode = Literal["compile", "check", "tests", "diff"]


class Options(NamedTuple):
    policy: str
    mode: Mode
    test_files: list[str]  # with --tests: the named tests' files
    users: list[str] | None  # with --diff: only these users


class Unreadable(Exception):
    """A file that can't be read or isn't UTF-8; the message names it."""


def options(argv: list[str]) -> Options:
    """The command line, read; a mistake in it exits 2 with the usage."""
    parser = argparse.ArgumentParser(
        prog="compile_policy.py",
        description="The compiler without a database: the SQL for psql.",
        allow_abbrev=False,  # --test is a mistake, not --tests
    )
    parser.add_argument("policy", help="the policy file")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="only report mistakes")
    mode.add_argument(
        "--tests", nargs="*", metavar="TESTS.authz", help="the policy's tests, these named tests and the invariants"
    )
    mode.add_argument("--diff", action="store_true", help="who gains and loses what if it is applied (rolled back)")
    parser.add_argument("--users", metavar="1,2", help="with --diff: only these users")
    ns = parser.parse_args(argv)
    if ns.users is not None and not ns.diff:
        parser.error("--users only goes with --diff")
    tests: list[str] | None = ns.tests
    chosen: Mode = "check" if ns.check else "tests" if tests is not None else "diff" if ns.diff else "compile"
    users = None if ns.users is None else [u for u in str(ns.users).split(",") if u]
    return Options(str(ns.policy), chosen, tests or [], users)


def read(path: str) -> str:
    try:
        with open(path, encoding="utf-8") as fh:
            return fh.read()
    except OSError as e:
        raise Unreadable(f"{path}: {e.strerror}") from e
    except UnicodeDecodeError as e:
        raise Unreadable(f"{path}: not UTF-8: {e}") from e


def load(path: str) -> Compiler:
    return Compiler(parse_policy(read(path), path))


def main(argv: list[str] | None = None) -> int:
    opts = options(sys.argv[1:] if argv is None else argv)
    if isinstance(sys.stdout, io.TextIOWrapper):  # the SQL is UTF-8 everywhere
        sys.stdout.reconfigure(encoding="utf-8")
    path = opts.policy
    try:
        compiler = load(path)
        if opts.mode == "tests":
            compiler.add_test_files({name: read(name) for name in opts.test_files})
            out = compiler.compile_tests(path)
        elif opts.mode == "diff":
            out = compiler.compile_diff(path, opts.users)
        else:
            out = compiler.compile(path)
    except PolicyError as e:
        print(f"{path}: {e}", file=sys.stderr)
        return 1
    except Unreadable as e:
        print(e, file=sys.stderr)
        return 2
    if opts.mode == "check":
        print(f"{path}: ok")
    else:
        sys.stdout.write(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())

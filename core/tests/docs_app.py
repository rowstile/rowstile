#!/usr/bin/env python3
"""docs_app: each release's own docs app, for tests/upgrade.sh to upgrade it with.

    python3 tests/docs_app.py VERSION     # the files (from core/) of the docs app VERSION was released with
    python3 tests/docs_app.py --sync      # from the tags (git tag v*): record each release's, copy those that differ;
                                          # and the release being made (this checkout's version, not a -dev one)

The docs app is core/example's docs.authz, docs.test.authz and app_schema.sql (FILES). upgrade.sh makes databases
with an older release and upgrades them with this checkout's command: the policy has to be one the older release can
compile. So each release is upgraded with the docs app as its tag has it: where it is this checkout's, core/example;
where it differs, a copy in tests/docs_apps/VERSION/, each file named with `.txt` after it (a release's policy is in
its release's language: the checks that read every policy in the repository leave it alone).
tests/docs_apps/releases.txt records each release's (its SHA-256, digest()), from FIRST on (previous_release.py's:
the beta started afresh, and nothing upgrades from an alpha before it). tests/unit_test.py holds the copies to it
(one for each release whose docs app differs from this checkout's, none for the others), and it to the tags where
the checkout has them. CI's checkouts may have no tags: the copies are committed. When core/example changes, or
after a release, --sync writes them again from the tags. A release's own commit records itself (its version isn't a
-dev one: --sync records it from this checkout, as no tag has it yet), so that the release run, on its tag, finds
its tag recorded. A version not recorded is upgraded with core/example's (and upgrade.sh says so).
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
import sys
from collections.abc import Callable

HERE = os.path.dirname(os.path.abspath(__file__))
CORE = os.path.dirname(HERE)
sys.path.insert(0, HERE)
from previous_release import FIRST, key  # noqa: E402

FILES = ("docs.authz", "docs.test.authz", "app_schema.sql")
MAIN = "example"  # this checkout's docs app, from core/
COPIES = os.path.join("tests", "docs_apps")  # the releases' copies, from core/
COPIED = ".txt"  # what a copy's file name has after the file's own
RECORD = os.path.join(CORE, COPIES, "releases.txt")
HEADER = """\
# Each release's docs app (core/example: docs.authz, docs.test.authz, app_schema.sql) as its tag has it: the version,
# then the SHA-256 of the three files (tests/docs_app.py digest()). Written by python3 tests/docs_app.py --sync.
"""


def digest(read: Callable[[str], bytes]) -> str:
    """The docs app's SHA-256: each file's name and bytes (read(name)), in FILES' order."""
    h = hashlib.sha256()
    for name in FILES:
        h.update(name.encode() + b"\0" + read(name) + b"\0")
    return h.hexdigest()


def files(version: str | None = None) -> list[str]:
    """The paths (from core/) of the docs app a release was released with, in FILES' order: its copy, or core/example's
    (None: this checkout's)."""
    copy = os.path.join(COPIES, version) if version else ""
    if copy and os.path.isdir(os.path.join(CORE, copy)):
        return [os.path.join(copy, name + COPIED) for name in FILES]
    return [os.path.join(MAIN, name) for name in FILES]


def digest_of(paths: list[str]) -> str:
    """The SHA-256 of the docs app whose files (from core/, in FILES' order) are these."""
    by_name = dict(zip(FILES, paths, strict=True))

    def read(name: str) -> bytes:
        with open(os.path.join(CORE, by_name[name]), "rb") as fh:
            return fh.read()

    return digest(read)


def recorded(path: str = RECORD) -> dict[str, str]:
    """releases.txt: {version: its docs app's SHA-256}."""
    out: dict[str, str] = {}
    if os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                if line.strip() and not line.startswith("#"):
                    version, sha = line.split()
                    out[version] = sha
    return out


def git(*args: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(["git", "-C", CORE, *args], capture_output=True)


def tags() -> list[str] | None:
    """The releases from FIRST on that this checkout has tags of (v0.1.0-beta.1: 0.1.0-beta.1), oldest first; None
    where git or the tags aren't there at all (CI's suites' checkouts)."""
    try:
        p = git("tag", "--list", "v*")
    except OSError:
        return None
    if p.returncode != 0 or not p.stdout.split():
        return None
    first = key(FIRST)
    assert first is not None
    out: list[tuple[tuple[int, ...], str]] = []
    for tag in p.stdout.decode().split():
        k = key(tag[1:])
        if k is not None and k >= first:
            out.append((k, tag[1:]))
    return [v for _, v in sorted(out)]


def releasing() -> str | None:
    """The version this checkout is the release of (core/authzlib's, when it isn't a -dev one), or None."""
    with open(os.path.join(CORE, "authzlib", "__init__.py"), encoding="utf-8") as fh:
        m = re.search(r'^__version__ = "([^"]+)"', fh.read(), re.M)
    version = m.group(1) if m else ""
    return version if version and not version.endswith("-dev") else None


def expected() -> list[str]:
    """What releases.txt must record where the checkout has the tags: the tagged releases, and the release this
    checkout is, when its tag isn't there yet (FIRST's own release too, when only older tags are there)."""
    out = tags()
    if out is None:
        return []
    if (version := releasing()) and version not in out:
        out.append(version)
    return out


def tagged(version: str) -> Callable[[str], bytes]:
    """A release's docs app's files, as its tag has them."""

    def read(name: str) -> bytes:
        p = git("show", f"v{version}:core/{MAIN}/{name}")
        if p.returncode != 0:
            raise RuntimeError(f"v{version}: {p.stderr.decode().strip()}")
        return p.stdout

    return read


def _read_main(name: str) -> bytes:
    with open(os.path.join(CORE, MAIN, name), "rb") as fh:
        return fh.read()


def sync() -> list[str]:
    """releases.txt and the copies, written again from the tags: what changed."""
    versions = tags()
    if versions is None:
        raise RuntimeError("no tags here (git fetch --tags)")
    main = digest_of(files())
    said: list[str] = []
    lines = [HEADER]
    this = releasing()
    for version in versions + ([this] if this and this not in versions else []):
        read = tagged(version) if version in versions else _read_main
        sha = digest(read)
        lines.append(f"{version} {sha}\n")
        folder = os.path.join(CORE, COPIES, version)
        if sha == main:
            if os.path.isdir(folder):
                shutil.rmtree(folder)
                said.append(f"{version}: the same as core/{MAIN} now, its copy removed")
        elif not os.path.isdir(folder) or digest_of(files(version)) != sha:
            os.makedirs(folder, exist_ok=True)
            for name in FILES:
                with open(os.path.join(folder, name + COPIED), "wb") as fh:
                    fh.write(read(name))
            said.append(f"{version}: differs from core/{MAIN}, copied from its tag")
    with open(RECORD, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("".join(lines))
    return said or ["nothing changed"]


def main(argv: list[str]) -> int:
    match argv:
        case ["--sync"]:
            print("\n".join(sync()))
        case [version] if not version.startswith("-"):
            print("\n".join(files(version)))
            if version not in recorded():
                print(f"{version} is not in {os.path.relpath(RECORD, CORE)}: core/{MAIN}'s", file=sys.stderr)
        case _:
            print((__doc__ or "").split("\n\n")[1], file=sys.stderr)
            return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

#!/usr/bin/env python3
"""previous_release: the release of rowstile before this checkout's version, installed from PyPI into a virtual
environment of its own, for tests/upgrade.sh to make a database with.

    python3 tests/previous_release.py DIR            # prints the version it installed, as the command writes it
    python3 tests/previous_release.py DIR VERSION    # that release (0.1.0-beta.1, or as PyPI writes it: 0.1.0b1)
    python3 tests/previous_release.py --list         # every release older than this version, oldest first

The release before is the newest version PyPI has that is older than this checkout's (authzlib.__version__), from
FIRST on: the beta started afresh, and a database an alpha before it made is applied from scratch, never upgraded,
so those alphas are never the release before. A version's alphas come before its betas, its betas before its
candidates, and those before the version itself (authzlib/versions.py); a build of main (X.Y.Z-dev) is on its way
to X.Y.Z, after each alpha, beta and candidate of it that is out. Its wheel is checked against the SHA-256 PyPI's
index gives, and its files are put in DIR, a virtual environment made without pip: a wheel of pure Python is its
files, and the image the suites run in has no pip. `DIR/bin/python -m rowstile` is then that release's command.

Exit 0: installed, and its version printed (--list: the versions, one a line). Exit 2: PyPI can't be reached from
here, and why: the suite says so and skips. Exit 3: PyPI has no release from FIRST on that is older than this
version: there is nothing to upgrade from, which the suite says and skips. Exit 1: anything else (PyPI answered
something this doesn't read, a wheel that isn't the one the index names, a release asked for by name that is older
than FIRST).
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
import zipfile
from collections.abc import Iterable
from typing import Any

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from authzlib import __version__
from authzlib.versions import PYPI, STAGES, VERSION, stage
from authzlib.versions import spelled as ours

# the first release anything upgrades from: the beta started afresh (a database the alphas before it made is
# applied from scratch); tests/docs_app.py records each release's docs app from it on
FIRST = "0.1.0-beta.1"
# PyPI's index of the package, as JSON (PEP 691): each file with its hashes
INDEX = "https://pypi.org/simple/rowstile/"
INDEX_JSON = "application/vnd.pypi.simple.v1+json"
# where in a version's life: its stages (alphas, betas, candidates), a build of main on its way to it, the version
DEV, RELEASED = len(STAGES), len(STAGES) + 1
Answer = Any  # the index's JSON
Key = tuple[int, int, int, int, int]


class Unreachable(Exception):
    """PyPI didn't answer: no network, a name that doesn't resolve, a certificate that can't be checked, a server
    that is down."""


class Wrong(Exception):
    """PyPI answered, with something that isn't what this reads or expects."""


def key(version: str) -> Key | None:
    """Where a version comes, written either way; None for one that is neither (a post-release, a dev build)."""
    m = VERSION.fullmatch(version)
    if m:
        at = DEV if m.group(6) else stage(m.group(4)) if m.group(4) else RELEASED
    else:
        m = PYPI.fullmatch(version)
        if not m:
            return None
        at = stage(m.group(4)) if m.group(4) else RELEASED
    return int(m.group(1)), int(m.group(2)), int(m.group(3)), at, int(m.group(5) or 0)


def spelled(version: str) -> str:
    """A version PyPI writes, as the command writes it: 0.1.0a6 is 0.1.0-alpha.6, 0.1.0b1 0.1.0-beta.1, 0.1.0rc1
    0.1.0-rc.1."""
    return ours(version) or version


def before(mine: str, released: Iterable[str]) -> str | None:
    """The newest of the released versions that is older than mine; None if none is."""
    here = key(mine)
    if here is None:
        raise ValueError(f"{mine} is not a version rowstile has")
    older = [(k, v) for v in released if (k := key(v)) is not None and k < here]
    return max(older)[1] if older else None


def fetch(url: str, accept: str | None = None) -> bytes:
    """The answer at url, asked up to three times while the network or the server fails: a moment's outage in a
    run that downloads every release (upgrade.sh --every) would otherwise fail the run."""
    for wait in (2, 5):
        try:
            return fetch_once(url, accept)
        except Unreachable:
            time.sleep(wait)
    return fetch_once(url, accept)


def fetch_once(url: str, accept: str | None) -> bytes:
    request = urllib.request.Request(url, headers={"Accept": accept} if accept else {})
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            return response.read()
    except urllib.error.HTTPError as e:  # it answered: a server that is down is no answer, anything else is wrong
        if e.code >= 500 or e.code == 429:
            raise Unreachable(f"{url} answered {e.code} {e.reason}") from e
        raise Wrong(f"{url} answered {e.code} {e.reason}") from e
    except (urllib.error.URLError, OSError) as e:
        raise Unreachable(f"{url}: {getattr(e, 'reason', None) or e}") from e


def wheels(index: Answer) -> dict[str, tuple[str, str]]:
    """{version: (url, sha256)} of each wheel the index lists, but those taken back (yanked)."""
    out: dict[str, tuple[str, str]] = {}
    files = index.get("files") if isinstance(index, dict) else None
    if not isinstance(files, list):
        raise Wrong(f"{INDEX} has no list of files")
    for f in files:
        m = re.fullmatch(r"rowstile-([^-]+)-py3-none-any\.whl", str(f.get("filename", "")))
        if m and not f.get("yanked") and f.get("hashes", {}).get("sha256"):
            out[m.group(1)] = (str(f["url"]), str(f["hashes"]["sha256"]))
    return out


def install(target: str, url: str, sha256: str) -> None:
    """The wheel at url, checked against its hash, in a new virtual environment at target."""
    data = fetch(url)
    if hashlib.sha256(data).hexdigest() != sha256:
        raise Wrong(f"{url}: its SHA-256 is not the one PyPI's index gives")
    subprocess.run([sys.executable, "-m", "venv", "--without-pip", target], check=True)
    where = subprocess.run(
        [os.path.join(target, "bin", "python"), "-c", "import sysconfig; print(sysconfig.get_paths()['purelib'])"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    with zipfile.ZipFile(io.BytesIO(data)) as wheel:
        wheel.extractall(where)


def older(mine: str, released: Iterable[str]) -> list[str]:
    """Every released version older than mine, oldest first."""
    here = key(mine)
    if here is None:
        raise ValueError(f"{mine} is not a version rowstile has")
    keyed = [(k, v) for v in released if (k := key(v)) is not None and k < here]
    return [v for _, v in sorted(keyed)]


def named(version: str, released: Iterable[str]) -> str:
    """The released version a name means, written either way (0.1.0-beta.1 or 0.1.0b1)."""
    want = key(version)
    match = [v for v in released if want is not None and key(v) == want]
    if not match:
        raise Wrong(f"PyPI's index has no wheel of rowstile {version}")
    return match[0]


def from_first(version: str) -> bool:
    """Whether a released version is one this upgrades from: FIRST or a later one, never an alpha before it."""
    k, first = key(version), key(FIRST)
    return k is not None and first is not None and k >= first


def nothing_before(mine: str) -> str:
    """What the suite says when no release from FIRST on is older than mine."""
    return (
        f"PyPI has no release of rowstile from {FIRST} on that is older than {mine}: there is nothing to upgrade "
        f"from (a database an alpha before {FIRST} made is applied from scratch, never upgraded)"
    )


def main(argv: list[str]) -> int:
    if len(argv) not in (1, 2) or (argv[0] == "--list" and len(argv) != 1):
        print("usage: python3 tests/previous_release.py DIR [VERSION] | --list", file=sys.stderr)
        return 1
    try:
        if len(argv) == 2 and key(argv[1]) is not None and not from_first(argv[1]):
            raise Wrong(f"{argv[1]} is older than {FIRST}, the first release anything upgrades from")
        found = {v: f for v, f in wheels(json.loads(fetch(INDEX, INDEX_JSON))).items() if from_first(v)}
        if argv[0] == "--list":
            every = older(__version__, found)
            if not every:
                print(nothing_before(__version__))
                return 3
            print("\n".join(spelled(v) for v in every))
            return 0
        old = named(argv[1], found) if len(argv) == 2 else before(__version__, found)
        if old is None:
            print(nothing_before(__version__))
            return 3
        install(argv[0], *found[old])
    except Unreachable as e:
        print(f"PyPI can't be reached from here ({e}): there is nothing to upgrade from")
        return 2
    except (Wrong, ValueError, subprocess.CalledProcessError, zipfile.BadZipFile) as e:
        print(f"previous_release: {e}", file=sys.stderr)
        return 1
    print(spelled(old))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

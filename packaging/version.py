#!/usr/bin/env python3
"""The version, everywhere it is written.

    python3 packaging/version.py              # prints it; fails if two places disagree
    python3 packaging/version.py 0.2.0-rc.1   # sets it everywhere
    python3 packaging/version.py --dist-tag   # the tag its release is published under: latest, next, release-X.Y

A version is X.Y.Z; X.Y.Z-alpha.N, X.Y.Z-beta.N or X.Y.Z-rc.N before it (npm's form; PyPI reads 0.2.0-alpha.1 as
0.2.0a1, 0.2.0-beta.1 as 0.2.0b1 and 0.2.0-rc.1 as 0.2.0rc1); or X.Y.Z-dev: main between releases, on its way to
X.Y.Z, never published (PyPI: 0.2.0.dev0). The grammar is the compiler's (core/authzlib/versions.py), the one the
command orders versions by: a version's alphas, then its betas, its candidates, then the version itself.
The compiler's version (core/authzlib/__init__.py) is the one the command and the Python package read. The others
copy it: the TypeScript SDK's packages and their dependencies on each other, the workspace's lock file, and
the review for CI, which installs the release its tag names. The editor extension keeps its own version (the
Marketplace takes no versions that aren't final). Standard library only.
"""

from __future__ import annotations

import glob
import os
import re
import subprocess
import sys
from collections.abc import Iterator

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path.insert(0, os.path.join(ROOT, "core"))
from authzlib.versions import STAGES, VERSION  # noqa: E402

# (files, pattern): each pattern's one group is the version. Each must match in each file, but for the
# packages' dependencies on each other (@rowstile/client has none)
PLACES = [
    (["core/authzlib/__init__.py"], r'^__version__ = "([^"]+)"'),
    (["sdk/typescript/*/package.json"], r'^  "version": "([^"]+)"'),
    (["sdk/typescript/*/package.json", "package-lock.json"], r'"@rowstile/[a-z-]+": "(\d[^"]*)"'),  # optional
    (["package-lock.json"], r'"name": "@rowstile/[a-z-]+",\n\s+"version": "([^"]+)"'),
    (["server.json"], r'^ +"version": "([^"]+)"'),  # the MCP registry's entry: its own version, and the package's
    (["review-ci/github/action.yml"], r'^    default: "(\d[^"]*)"'),
    (["review-ci/github/action.yml", "docs/reference/review.md"], r"review-ci/github@v(\S+)"),
    (["review-ci/gitlab/rowstile-review.gitlab-ci.yml"], r'ROWSTILE_VERSION: "([^"]+)"'),
    (["review-ci/gitlab/rowstile-review.gitlab-ci.yml"], r"/rowstile/rowstile/v([^/]+)/"),
]


def places() -> Iterator[tuple[str, re.Pattern[str]]]:
    """(path relative to the root, compiled pattern) for each place, in order."""
    for patterns, rx in PLACES:
        for pattern in patterns:
            paths = sorted(glob.glob(os.path.join(ROOT, pattern)))
            if not paths:
                raise SystemExit(f"version.py: nothing matches {pattern}")
            for path in paths:
                yield os.path.relpath(path, ROOT).replace(os.sep, "/"), re.compile(rx, re.M)


def read(path: str) -> str:
    with open(os.path.join(ROOT, path), encoding="utf-8", newline="") as fh:
        return fh.read()


def found() -> dict[str, list[str]]:
    """{version: [where it is written, ...]}"""
    out: dict[str, list[str]] = {}
    for path, rx in places():
        hits = rx.findall(read(path))
        if not hits and not rx.pattern.startswith('"@rowstile/'):
            raise SystemExit(f"version.py: {path} has no match for {rx.pattern}")
        for v in hits:
            out.setdefault(v, []).append(path)
    return out


def set_version(new: str) -> None:
    if not VERSION.fullmatch(new):
        forms = ", ".join(f"X.Y.Z-{stage}.N" for stage in STAGES)
        raise SystemExit(f"version.py: {new} is not X.Y.Z, {forms} or X.Y.Z-dev")
    texts: dict[str, str] = {}
    for path, rx in places():
        text = texts.get(path, read(path))
        texts[path] = rx.sub(lambda m: m.string[m.start(0) : m.start(1)] + new + m.string[m.end(1) : m.end(0)], text)
    for path, text in texts.items():
        with open(os.path.join(ROOT, path), "w", encoding="utf-8", newline="") as fh:
            fh.write(text)


def dist_tag(version: str, tags: list[str]) -> str:
    """The tag a release is published under (npm's dist-tag; the image is `latest` when this is): `next` for an
    alpha, a beta or a candidate, `latest` for the highest release, and `release-X.Y` for a patch to an older line
    once a higher release is out (a patch from `release/0.1` after 0.2.0 must not become what `npm i rowstile` installs).
    `tags` are the repository's (`v0.2.0`, `v0.2.0-rc.1`, ...)."""
    if "-" in version:
        return "next"

    def key(v: str) -> tuple[int, ...]:
        return tuple(int(n) for n in v.split("."))

    released = [t[1:] for t in tags if re.fullmatch(r"v\d+\.\d+\.\d+", t)]
    if any(key(v) > key(version) for v in released):
        return "release-" + version.rsplit(".", 1)[0]
    return "latest"


def main(argv: list[str]) -> None:
    if argv == ["--dist-tag"]:
        tags = subprocess.run(["git", "tag", "-l", "v*"], cwd=ROOT, capture_output=True, text=True, check=True).stdout
        print(dist_tag(next(iter(found())), tags.split()))
        return
    if argv:
        set_version(argv[0])
    versions = found()
    if len(versions) > 1:
        for v, paths in sorted(versions.items()):
            print(f"{v}: {', '.join(sorted(set(paths)))}", file=sys.stderr)
        raise SystemExit("version.py: the version differs between files")
    print(next(iter(versions)))


if __name__ == "__main__":
    main(sys.argv[1:])

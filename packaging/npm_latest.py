#!/usr/bin/env python3
"""npm's `latest` while no final release is published: it follows `next`.

    python3 packaging/npm_latest.py          # says what it would move, package by package
    python3 packaging/npm_latest.py --move   # moves it (the release workflow, by npm's trusted publishing)
    python3 packaging/npm_latest.py --move --published 0.1.0-alpha.7   # a release's own run: once the registry
                                                                       # shows that version under next

A release publishes an alpha, a beta or a candidate under `next`. `latest` is what a plain `npm i rowstile` gets and what
a package's page on npmjs.com shows, and npm gave it to the first version ever published: left alone it stays
there. So, until a final release exists, each release moves `latest` to where `next` is, on every package. From
the first final release on, this moves nothing: that release is published as `latest`, and later alphas stay
under `next`.

Moving a tag by trusted publishing needs npm 11.21.0 or newer, and **Allow npm dist-tag** ticked in each
package's trusted publisher on npmjs.com (off by default). Without it npm refuses, this says which packages,
and nothing else is touched: what was published stays published.

The registry shows a publish some minutes late, package by package. Read sooner, `next` is still the release
before and `latest` looks as if it were there already: so the run that just published says which version
(`--published`), and each package is waited for, twenty minutes in all. A package the registry still doesn't
show is said, and the by-hand run moves it later. Standard library only.
"""

from __future__ import annotations

import glob
import json
import os
import re
import shutil
import subprocess
import sys
import time
from collections.abc import Callable

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FINAL = re.compile(r"\d+\.\d+\.\d+")
NEEDS = (11, 21, 0)
# how long a release waits for the registry to show what it published, and how often it looks
WAIT = 20 * 60
EVERY = 15


def names() -> list[str]:
    """Every package a release publishes: the launcher, one per platform, the TypeScript SDK's."""
    with open(os.path.join(ROOT, "packaging", "npm", "build.mjs"), encoding="utf-8") as fh:
        platforms = re.findall(r'^  "([a-z0-9-]+)": \{ triple:', fh.read(), re.M)
    sdk = []
    for path in sorted(glob.glob(os.path.join(ROOT, "sdk", "typescript", "*", "package.json"))):
        with open(path, encoding="utf-8") as fh:
            sdk.append(str(json.load(fh)["name"]))
    return ["rowstile", *(f"@rowstile/cli-{p}" for p in platforms), *sdk]


def target(dist_tags: dict[str, str], versions: list[str]) -> tuple[str | None, str]:
    """The version `latest` moves to (None: it stays), and why, from a package's tags and published versions."""
    final = sorted(v for v in versions if FINAL.fullmatch(v))
    if final:
        return None, f"{final[-1]} is released: latest is a release's from now on"
    following = dist_tags.get("next")
    if not following:
        return None, "nothing is published under next"
    if dist_tags.get("latest") == following:
        return None, f"latest is {following} already"
    return following, f"latest {dist_tags.get('latest', 'nothing')} -> {following}"


def npm(*args: str) -> subprocess.CompletedProcess[str]:
    command = shutil.which("npm")
    if not command:
        raise SystemExit("npm_latest.py: npm isn't on the PATH")
    return subprocess.run([command, *args], capture_output=True, text=True, encoding="utf-8", check=False)


def published(name: str) -> tuple[dict[str, str], list[str]]:
    """A package's tags and versions, as the registry has them."""
    out = npm("view", name, "dist-tags", "versions", "--json")
    if out.returncode != 0:
        raise SystemExit(f"npm_latest.py: npm view {name}: {out.stderr.strip() or out.stdout.strip()}")
    said = json.loads(out.stdout)
    versions = said.get("versions", [])
    return dict(said.get("dist-tags", {})), [versions] if isinstance(versions, str) else list(versions)


def shown(
    name: str,
    expect: str,
    until: float,
    read: Callable[[str], tuple[dict[str, str], list[str]]] = published,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> tuple[dict[str, str], list[str]] | None:
    """A package's tags and versions once the registry shows `expect` under `next`; None if it doesn't by `until`."""
    while True:
        tags, versions = read(name)
        if tags.get("next") == expect:
            return tags, versions
        if clock() >= until:
            return None
        sleep(EVERY)


def new_enough(version: str) -> bool:
    """Whether this npm moves a tag by trusted publishing: 11.21.0 or newer, and on 12 from 12.2.0."""
    found = tuple(int(n) for n in re.findall(r"\d+", version)[:3])
    return found >= (12, 2, 0) or (12, 0, 0) > found >= NEEDS


def main(argv: list[str]) -> None:
    expect = argv[2] if len(argv) == 3 and argv[:2] == ["--move", "--published"] else None
    if argv not in ([], ["--move"]) and expect is None:
        raise SystemExit(__doc__)
    move = argv[:1] == ["--move"]
    if expect is not None and FINAL.fullmatch(expect):
        # a release is published as `latest` itself: nothing follows `next`, and a registry read too soon would
        # put `latest` back on the candidate before it
        print(f"{expect} is a release: it is published as latest, nothing to move")
        return
    if move and not new_enough(npm("--version").stdout.strip()):
        raise SystemExit(
            f"npm_latest.py: moving a tag by trusted publishing needs npm 11.21.0 or newer (12.2.0 on 12), this is "
            f"{npm('--version').stdout.strip()}"
        )
    refused = []
    late = []
    until = time.monotonic() + WAIT
    for name in names():
        found = published(name) if expect is None else shown(name, expect, until)
        if found is None:
            late.append(name)
            print(f"{name}: not moved, the registry doesn't show {expect} under next yet")
            continue
        version, why = target(*found)
        if version is None or not move:
            print(f"{name}: {why}" + ("" if version is None else " (not moved: run with --move)"))
            continue
        out = npm("dist-tag", "add", f"{name}@{version}", "latest")
        if out.returncode == 0:
            print(f"{name}: {why}")
        else:
            lines = (out.stderr.strip() or out.stdout.strip()).splitlines()
            refused.append(name)
            print(f"{name}: not moved, npm refused: {' '.join(lines[-3:])}")
    unmoved = []
    if refused:
        unmoved.append(
            f"npm's latest was not moved on {len(refused)} package(s): {', '.join(refused)}. Everything published "
            "stays published. If npm says the trusted publisher cannot manage dist-tags, tick Allow npm dist-tag in "
            "each package's settings on npmjs.com (Trusted publisher), then: gh workflow run release.yml -f latest=true"
        )
    if late:
        unmoved.append(
            f"npm's latest was not moved on {len(late)} package(s): {', '.join(late)}. The registry didn't show "
            f"{expect} under next within {WAIT // 60} minutes. Everything published stays published. Once "
            "`python3 packaging/npm_latest.py` shows it there: gh workflow run release.yml -f latest=true"
        )
    for said in unmoved:
        if os.environ.get("GITHUB_ACTIONS"):
            print(f"::warning::{said}")
    if unmoved:
        raise SystemExit("npm_latest.py: " + " ".join(unmoved))


if __name__ == "__main__":
    main(sys.argv[1:])

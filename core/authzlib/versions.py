"""rowstile's versions: how one is written, the order of a version's stages, and how PyPI writes each. The one
grammar everything that reads a version shares: the downgrade guard (database.py), the requirement `rowstile init`
gives a Python app (cli/stack.py), packaging/version.py, which sets the version, and tests/previous_release.py,
which reads PyPI's. Standard library only.

A version is X.Y.Z; X.Y.Z-alpha.N, X.Y.Z-beta.N or X.Y.Z-rc.N before it (npm's form, which the command and the
packages write); or X.Y.Z-dev, `main` between releases, on its way to X.Y.Z, never published. A build of `main`
adds a hash of the compiler's sources (0.2.0-dev+3f2a9c1e8b7d, authzlib.BUILD).
"""

from __future__ import annotations

import re

# a version's stages before its release, in their order, each with how PyPI writes it (0.2.0-beta.1 is 0.2.0b1)
STAGES = {"alpha": "a", "beta": "b", "rc": "rc"}
# as the command writes one; groups: X, Y and Z, the stage and its number, or "dev"
VERSION = re.compile(rf"(\d+)\.(\d+)\.(\d+)(?:-({'|'.join(STAGES)})\.(\d+)|-(dev))?")
# as PyPI writes a published one (0.2.0, 0.2.0a1, 0.2.0b1, 0.2.0rc1); groups: X, Y and Z, the stage and its number
PYPI = re.compile(rf"(\d+)\.(\d+)\.(\d+)(?:({'|'.join(STAGES.values())})(\d+))?")


def stage(name: str) -> int:
    """Where a stage comes among a version's, by either spelling (alpha or a, beta or b, rc): 0, 1, 2. The version
    itself comes after them all, len(STAGES)."""
    for i, (ours, pypi) in enumerate(STAGES.items()):
        if name in (ours, pypi):
            return i
    raise ValueError(f"{name} is not a stage of a version (alpha, beta, rc)")


def pypi(version: str) -> str | None:
    """How PyPI writes a version: 0.2.0-alpha.1 is 0.2.0a1, 0.2.0-beta.1 0.2.0b1, 0.2.0-rc.1 0.2.0rc1, 0.2.0-dev
    0.2.0.dev0, and 0.2.0 is 0.2.0. None for what isn't a version."""
    m = VERSION.fullmatch(version)
    if not m:
        return None
    base = ".".join(m.group(1, 2, 3))
    if m.group(6):
        return base + ".dev0"
    return base + (f"{STAGES[m.group(4)]}{m.group(5)}" if m.group(4) else "")


def spelled(published: str) -> str | None:
    """A version PyPI writes, as the command writes it: 0.2.0a1 is 0.2.0-alpha.1, 0.2.0b1 0.2.0-beta.1, 0.2.0rc1
    0.2.0-rc.1. None for what isn't one."""
    m = PYPI.fullmatch(published)
    if not m:
        return None
    base = ".".join(m.group(1, 2, 3))
    return f"{base}-{list(STAGES)[stage(m.group(4))]}.{m.group(5)}" if m.group(4) else base

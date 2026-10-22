#!/usr/bin/env python3
"""A release's notes, from CHANGELOG.md.

    python3 packaging/changelog.py 0.2.0-rc.1   # prints the section of 0.2.0; fails if there is none
    python3 packaging/changelog.py --tagged 0.2.0-rc.1   # ... and fails if Unreleased still has lines (a tag's check)
    python3 packaging/changelog.py 0.3.0-dev    # main between releases (the release workflow's dry run): Unreleased

Each release has a section, `## X.Y.Z (YYYY-MM-DD)`; while its alphas, its betas or its release candidates are
out, `## X.Y.Z (alpha)`, `## X.Y.Z (beta)` or `## X.Y.Z (release candidate)`, and the notes of each of them are
that section as it stands. A final release's heading must have its date. A -dev version is no release: its notes
are what **Unreleased** holds so far, perhaps nothing. Standard library only.
"""

from __future__ import annotations

import os
import re
import sys

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))


def read() -> str:
    with open(os.path.join(ROOT, "CHANGELOG.md"), encoding="utf-8") as fh:
        return fh.read()


def heading(version: str, text: str) -> str | None:
    """The heading line of the release a version belongs to (0.2.0-alpha.1, 0.2.0-beta.1 and 0.2.0-rc.1 belong to
    0.2.0), or None."""
    base = version.split("-", 1)[0]
    m = re.search(rf"^## {re.escape(base)}(?: \([^)\n]*\))?$", text, re.M)
    return m.group(0) if m else None


def section(version: str, text: str) -> str:
    """What the release's section says, headings of its parts included; empty if it has none."""
    line = heading(version, text)
    if not line:
        return ""
    body = text[text.index(line) + len(line) :]
    end = re.search(r"^## ", body, re.M)
    return (body[: end.start()] if end else body).strip() + "\n"


def upcoming(text: str) -> str:
    """What **Unreleased** says, headings of its parts included; empty if nothing."""
    m = re.search(r"^## Unreleased$", text, re.M)
    body = text[m.end() :] if m else ""
    end = re.search(r"^## ", body, re.M)
    said = (body[: end.start()] if end else body).strip()
    return said + "\n" if said else ""


def unreleased(text: str) -> list[str]:
    """The lines still under **Unreleased**: what a release's notes would leave out."""
    return [line for line in upcoming(text).splitlines() if line.startswith("- ")]


def main(argv: list[str]) -> None:
    tagged = argv[:1] == ["--tagged"]
    if len(argv) != 1 + tagged:
        raise SystemExit("usage: changelog.py [--tagged] VERSION")
    version, text = argv[-1], read()
    if tagged and unreleased(text):
        raise SystemExit(
            f"changelog.py: {version} is being released with {len(unreleased(text))} lines still under "
            "Unreleased: move them into its section (RELEASING.md)"
        )
    if version.endswith("-dev"):
        sys.stdout.write(upcoming(text))
        return
    notes = section(version, text)
    if not notes.strip():
        raise SystemExit(f"changelog.py: CHANGELOG.md has no section for {version.split('-', 1)[0]}")
    if "-" not in version and not re.search(r"\(\d{4}-\d{2}-\d{2}\)$", heading(version, text) or ""):
        raise SystemExit(f"changelog.py: {version} is a release: its heading needs the date, ## {version} (YYYY-MM-DD)")
    sys.stdout.write(notes)


if __name__ == "__main__":
    main(sys.argv[1:])

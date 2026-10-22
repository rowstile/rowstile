#!/usr/bin/env python3
"""A release's notes, from CHANGELOG.md.

    python3 packaging/changelog.py 0.2.0-rc.1   # prints the section of 0.2.0-rc.1; fails if there is none
    python3 packaging/changelog.py --tagged 0.2.0-rc.1   # ... and fails if Unreleased still has lines (a tag's check)
    python3 packaging/changelog.py 0.3.0-dev    # main between releases (the release workflow's dry run): Unreleased

Each release has a section of its own, an alpha, a beta and a candidate as much as a final release:
`## 0.2.0-alpha.1 (YYYY-MM-DD)`, `## 0.2.0-rc.1 (YYYY-MM-DD)`, `## 0.2.0 (YYYY-MM-DD)`. Its notes are that section,
under its heading's exact version. A -dev version is no release: its notes are what **Unreleased** holds so far,
perhaps nothing. A relative link in the notes becomes a link to its file at the release's tag (at `main` for a -dev
version). `layout()` says where the file strays from RELEASING.md's layout. Standard library only.
"""

from __future__ import annotations

import os
import re
import sys

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

# the parts of a release's section, in this order, each once at most (RELEASING.md)
PARTS = ("Added", "Changed", "Removed", "Fixed", "Upgrading")
# the section after the releases', which no release reads
HISTORY = "Before the beta"
RELEASE = re.compile(r"(\d+)\.(\d+)\.(\d+)(?:-(alpha|beta|rc)\.(\d+))? \(\d{4}-\d{2}-\d{2}\)")
STAGES = ("alpha", "beta", "rc", None)  # a version's alphas come before its betas, its candidates, then itself
REPOSITORY = "https://github.com/rowstile/rowstile"
# code (inline or fenced), which is left as it is, or a link's target: [text](target)
LINK = re.compile(r"(`+)[\s\S]*?\1|\]\(([^)\s]+)\)")


def read() -> str:
    with open(os.path.join(ROOT, "CHANGELOG.md"), encoding="utf-8") as fh:
        return fh.read()


def heading(version: str, text: str) -> str | None:
    """The heading line of this version's own section (`## 0.2.0-beta.1 (2026-11-02)`, with or without its date),
    or None. Another version's, `## 0.2.0` for 0.2.0-beta.1, is not it."""
    m = re.search(rf"^## {re.escape(version)}(?: \([^)\n]*\))?$", text, re.M)
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


def linked(notes: str, ref: str) -> str:
    """The notes with each relative link made a link to its file at ref (the release's tag): CHANGELOG.md's links
    are written from the repository's root, as GitHub reads the file, but a release's page reads them from its
    own address, where `[Installing](docs/installing.md)` leads nowhere. A link with a scheme (`https:`), one to
    an anchor of the page, and code are left as they are."""

    def absolute(m: re.Match[str]) -> str:
        target = m.group(2)
        if target is None or re.match(r"[a-z][a-z0-9+.-]*:|#", target, re.I):
            return m.group(0)
        return f"]({REPOSITORY}/blob/{ref}/{target.removeprefix('./').lstrip('/')})"

    return LINK.sub(absolute, notes)


def unreleased(text: str) -> list[str]:
    """The lines still under **Unreleased**: what a release's notes would leave out."""
    return [line for line in upcoming(text).splitlines() if line.startswith("- ")]


def layout(text: str) -> list[str]:
    """Where CHANGELOG.md strays from its layout, each said with its line: Unreleased first, then a section per
    release, newest first, then the history before the beta; in a section its parts in the order of PARTS, each
    once, and no blank line inside a part's list."""
    problems: list[str] = []
    sections: list[str] = []
    newer: tuple[int, ...] | None = None  # the release of the section above
    parts: list[str] = []
    listing = False  # inside a part's list, past its first line
    gap = 0  # the line of a blank line seen inside that list, or 0
    for n, line in enumerate(text.splitlines(), 1):
        if line.startswith("## "):
            name, release = line[3:], RELEASE.fullmatch(line[3:])
            if not (name in ("Unreleased", HISTORY) or release):
                problems.append(f"line {n}: {line} is no release's heading: ## X.Y.Z[-beta.N] (YYYY-MM-DD)")
            elif name in sections or (sections[-1:] == [HISTORY]):
                problems.append(f"line {n}: {line} comes after the history, or twice")
            elif release:
                x, y, z, stage, count = release.groups()
                version = (int(x), int(y), int(z), STAGES.index(stage), int(count or 0))
                if newer and version >= newer:
                    problems.append(f"line {n}: {line} is below an older release's section: newest first")
                newer = version
            sections.append(name)
            parts, listing, gap = [], False, 0
        elif line.startswith("### "):
            name = line[4:]
            if sections[-1:] == [HISTORY] or not sections:
                problems.append(f"line {n}: {line} is outside a release's section")
            elif name not in PARTS:
                problems.append(f"line {n}: {line} is no part of a section: {', '.join(PARTS)}")
            elif name in parts or any(PARTS.index(p) > PARTS.index(name) for p in parts):
                problems.append(f"line {n}: {line} is out of order, or twice: {', '.join(PARTS)}, each once")
            parts.append(name)
            listing, gap = False, 0
        elif parts and line.startswith(("- ", "  ")):
            if gap:
                problems.append(f"line {gap}: a blank line inside the list of {sections[-1]}'s {parts[-1]}")
            listing, gap = True, 0
        elif not line.strip():
            gap = n if listing else 0
        elif parts:
            problems.append(f"line {n}: a part's lines are a list: - ...")
            listing, gap = False, 0
    if sections[:1] != ["Unreleased"]:
        problems.append("## Unreleased is the first section")
    return problems


def main(argv: list[str]) -> None:
    tagged = argv[:1] == ["--tagged"]
    if len(argv) != 1 + tagged:
        raise SystemExit("usage: changelog.py [--tagged] VERSION")
    version, text = argv[-1], read()
    if tagged and unreleased(text):
        raise SystemExit(
            f"changelog.py: {version} is being released with {len(unreleased(text))} lines still under "
            f"Unreleased: they become its section, ## {version} (YYYY-MM-DD) (RELEASING.md)"
        )
    if version.endswith("-dev"):
        sys.stdout.write(linked(upcoming(text), "main"))
        return
    notes = section(version, text)
    if not notes.strip():
        raise SystemExit(
            f"changelog.py: CHANGELOG.md has no section for {version}: its heading is ## {version} (YYYY-MM-DD), "
            "above its lines (RELEASING.md)"
        )
    if not re.search(r"\(\d{4}-\d{2}-\d{2}\)$", heading(version, text) or ""):
        raise SystemExit(f"changelog.py: {version}'s heading needs the date: ## {version} (YYYY-MM-DD)")
    sys.stdout.write(linked(notes, f"v{version}"))


if __name__ == "__main__":
    main(sys.argv[1:])

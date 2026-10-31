#!/usr/bin/env python3
"""llms-full.txt: llms.txt, then every file it links (all but its Optional section's), then every error page, in one
file for agents that can't follow links. Built when the docs are published, not committed.

    python3 docs/llms_full.py [OUT]          (default: llms-full.txt at the repository's root)
"""

import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LINK = re.compile(r"^- \[[^\]]+\]\(([^)]+)\)", re.M)
# the notes the repository's checks read (a promise's `<!-- checked: ... -->`, ...), which the pages don't show:
# left out, as the site's Markdown copies leave them out (site/pages.mjs, withoutNotes)
NOTE_KINDS = "checked|unchecked|answer|tested|not run|features"
NOTE = re.compile(rf"<!-- (?:{NOTE_KINDS}):")
NOTE_LINE = re.compile(rf"^<!-- (?:{NOTE_KINDS}):[^>]*-->\n", re.M)
NOTE_AFTER = re.compile(rf" ?<!-- (?:{NOTE_KINDS}):[^>]*-->")


def read(rel: str) -> str:
    with open(os.path.join(REPO, *rel.split("/")), encoding="utf-8") as fh:
        return without_notes(fh.read())


def without_notes(text: str) -> str:
    """A file without the notes for the repository's checks: a line that is a note, and a note after a sentence
    with the space before it."""
    return NOTE_AFTER.sub("", NOTE_LINE.sub("", text))


def links(text: str) -> list[str]:
    """The paths llms.txt links, in order."""
    return LINK.findall(text)


def build() -> str:
    text = read("llms.txt")
    parts = [text.rstrip("\n")]
    for link in links(text.split("\n## Optional")[0]):
        if os.path.isfile(os.path.join(REPO, *link.split("/"))):
            parts.append(f"<!-- {link} -->\n\n{read(link).rstrip()}")
    for name in sorted(os.listdir(os.path.join(REPO, "docs", "errors"))):
        if name != "README.md":
            parts.append(f"<!-- docs/errors/{name} -->\n\n{read('docs/errors/' + name).rstrip()}")
    return "\n\n".join(parts) + "\n"


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else os.path.join(REPO, "llms-full.txt")
    with open(out, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(build())
    print(f"wrote {out}")

#!/usr/bin/env python3
"""The day each comparison page read the other projects' documentation, and when it is due to be read again.

What those pages say of another project is quoted from its documentation, with the day it was read ("read on
YYYY-MM-DD and linked"), and wants reading again each quarter. This lists each page's reading and fails once one
is more than a quarter old, or a page has none, or more than one. The nightly runs it (its readings job): a
calendar date alone never turns a push's checks red, and `ComparePages` (core/tests/unit_test.py) checks the rest
on every push.

    python3 docs/compare_readings.py [--today YYYY-MM-DD] [--github]

--github writes each problem as an annotation on the page's line too, as a workflow's run shows them.
"""

import argparse
import calendar
import datetime
import os
import re
import sys
from typing import NamedTuple

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# the pages that quote another project's documentation
PAGES = ("docs/comparison.md", "docs/compare/openfga.md", "docs/compare/spicedb.md", "docs/compare/zenstack.md")
READ = re.compile(r"read\s+on\s+(\d{4}-\d{2}-\d{2})\s+and\s+linked")


class Reading(NamedTuple):
    page: str
    line: int
    day: datetime.date


def due(day: datetime.date) -> datetime.date:
    """A quarter after `day`: the same day three months later, or that month's last."""
    month = day.month + 2
    year, month = day.year + month // 12, month % 12 + 1
    return datetime.date(year, month, min(day.day, calendar.monthrange(year, month)[1]))


def readings(page: str, text: str) -> list[Reading]:
    """Each "read on YYYY-MM-DD and linked" in a page's text, with its line."""
    return [
        Reading(page, text.count("\n", 0, m.start(1)) + 1, datetime.date.fromisoformat(m.group(1)))
        for m in READ.finditer(text)
    ]


def check(texts: dict[str, str], today: datetime.date) -> tuple[list[str], list[tuple[str, int, str]]]:
    """(a line for each page's reading, the problems: (page, line, what)), for the pages' texts on `today`."""
    said: list[str] = []
    problems: list[tuple[str, int, str]] = []
    for page, text in texts.items():
        found = readings(page, text)
        if len(found) != 1:
            lines = ", ".join(str(r.line) for r in found)
            what = "none" if not found else f"{len(found)}, on lines {lines}"
            problems.append(
                (page, 1, f'one "read on YYYY-MM-DD and linked" wanted, the day the docs were read: {what}')
            )
            continue
        page, line, day = found[0]
        said.append(f"{page}:{line}: read on {day}, due again on {due(day)}")
        if today > due(day):
            problems.append(
                (
                    page,
                    line,
                    f"read on {day}, more than a quarter ago (due on {due(day)}): read the documentation it quotes "
                    "again, from its sources, correct what changed, and write the day of that reading",
                )
            )
    return said, problems


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="When the comparison pages want reading again.")
    parser.add_argument("--today", type=datetime.date.fromisoformat, default=datetime.date.today())
    parser.add_argument("--github", action="store_true", help="annotations for a workflow's run")
    args = parser.parse_args(argv)
    texts: dict[str, str] = {}
    for page in PAGES:
        with open(os.path.join(REPO, *page.split("/")), encoding="utf-8") as fh:
            texts[page] = fh.read()
    said, problems = check(texts, args.today)
    for line in said:
        print(line)
    for page, line, what in problems:
        print(f"{page}:{line}: {what}", file=sys.stderr)
        if args.github:
            print(f"::error file={page},line={line}::{what}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

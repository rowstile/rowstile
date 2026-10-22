#!/usr/bin/env python3
"""fuzz_parser: broken policies are refused with a PolicyError, never a crash.

    python3 tests/fuzz_parser.py [--cases 3000] [--seed 1]

Starts from the suites' policies (seeds()) and mutates them at random (drop, repeat, swap or replace tokens and
lines, insert odd characters and the language's words, cut the text short), then parses and compiles each. A policy may be
accepted or refused; what must never happen is any other exception (an IndexError, a KeyError, a
RecursionError...), a refusal without a line number or at a line the policy doesn't have (rowstile dev shows
that line), the words a refusal is about (its span, which an editor underlines) outside the policy's text or
before its line, or a case taking seconds. Policy authors are trusted (see docs/threat-model.md), so this is about
robustness and clear errors, not an attack surface.
"""

import argparse
import os
import random
import re
import sys
import time
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
from authzlib import Compiler, parse  # noqa: E402
from authzlib.parse import PolicyError, Span, parse_policy  # noqa: E402

# the policies mutated: every fixed policy of the suites, the docs app with its named tests, the hand-answered
# policies (tests/hand/: tests, principals, caveats, masks, column rules, a link table's where with this., ...) and
# the example apps' (cascade from, services)
FIXED = "tests"
HAND = "tests/hand"
DOCS = ("example/docs.authz", "example/docs.test.authz")  # one policy: the second is the first's named tests
APPS = ("../examples/filemanager/db/policy.authz", "../examples/messenger/db/policy.authz")


def seeds(root: str) -> list[str]:
    """The texts the fuzzer starts from."""

    def read(path: str) -> str:
        with open(os.path.join(root, path), encoding="utf-8") as fh:
            return fh.read()

    found = [f"{FIXED}/{f}" for f in os.listdir(os.path.join(root, FIXED)) if f.endswith(".authz")]
    found += [f"{HAND}/{f}" for f in os.listdir(os.path.join(root, HAND)) if f.endswith(".authz")]
    return ["\n".join(read(p) for p in DOCS), *(read(p) for p in [*sorted(found), *APPS])]


# the odd tokens put in: marks, odd characters, and every word of the language, as the parser names them (its lists,
# and the words it looks for: read from its source, so that a new one is in here as soon as the parser knows it)
MARKS = ["(", ")", "[", "]", "{", "}", "#", ".", ":", "=", ",", "->", "--", "'", '"', "\\", "\t", "é", "\u200b"]
MORE = [
    "$",
    "$$",
    "$f$",
    "E'",
    "/*",
    "*",
    "user:*",
    "shared",
    "link",
    "mask",
    "before",
    "after",
    "this.",
    "user",
    "include",
]


def words() -> list[str]:
    """The language's words: parse.py's lists, and each word it asks a line for (`w.name("given", "as")`)."""
    with open(parse.__file__, encoding="utf-8") as fh:
        source = fh.read()
    named = [w for call in re.findall(r'\.name\(((?:"[A-Za-z_]+",?\s*)+)', source) for w in re.findall(r"\w+", call)]
    listed = [*parse.TOP_WORDS, *parse.COMMANDS, *parse.KEYWORDS, *parse.RESERVED, parse.ROLES]
    return sorted({*listed, *named})


ODD = list(dict.fromkeys(MARKS + MORE + words()))


def tokens(text: str) -> list[str]:
    return re.findall(r"\s+|[A-Za-z_][A-Za-z0-9_]*|\{[^{}\n]*\}|->|--[^\n]*|.", text)


def mutate(rnd: random.Random, text: str) -> str:
    kind = rnd.randrange(8)
    lines = text.split("\n")
    if kind == 0:  # drop a line
        del lines[rnd.randrange(len(lines))]
        return "\n".join(lines)
    if kind == 1:  # repeat a line elsewhere
        lines.insert(rnd.randrange(len(lines)), rnd.choice(lines))
        return "\n".join(lines)
    if kind == 2:  # cut the text short
        return text[: rnd.randrange(len(text))]
    toks = tokens(text)
    i = rnd.randrange(len(toks))
    if kind == 3:  # drop a token
        del toks[i]
    elif kind == 4:  # replace a token with an odd one
        toks[i] = rnd.choice(ODD)
    elif kind == 5:  # replace a token with another from the policy
        toks[i] = rnd.choice(toks)
    elif kind == 6:  # swap two tokens
        j = rnd.randrange(len(toks))
        toks[i], toks[j] = toks[j], toks[i]
    else:  # insert an odd token
        toks.insert(i, " " + rnd.choice(ODD) + " ")
    return "".join(toks)


def within(span: Span, lines: list[str], line: int) -> bool:
    """Whether a refusal's span is words of the policy: on its line or one it goes on to, not empty."""
    start, col, end, end_col = span
    return (
        line <= start <= end <= len(lines)
        and col >= 0
        and end_col <= len(lines[end - 1])
        and (start, col) < (end, end_col)
    )


def check(text: str) -> tuple[str, bool]:
    """Parse and compile a policy: what is wrong with how it went ("" when nothing), and whether it was refused.
    fuzz_coverage.py holds its inputs to this rule too."""
    try:
        Compiler(parse_policy(text, files={})).compile("fuzz")
        return "", False
    except PolicyError as e:
        if not re.match(r"(line )?\d+|[^:]+:\d+", str(e)):
            return f"refused without a line number: {e}", True
        line = re.match(r"line (\d+):", str(e))
        if line and not 0 < int(line.group(1)) <= len(text.split("\n")):  # rowstile dev shows that line
            return f"refused at a line the policy doesn't have: {e}", True
        if e.span and not within(e.span, text.removeprefix("\ufeff").split("\n"), int(line.group(1)) if line else 1):
            return f"refused about words that aren't in its text, {e.span}: {e}", True
        return "", True
    except Exception:
        return traceback.format_exc(limit=3), False


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cases", type=int, default=3000)
    ap.add_argument("--seed", type=int, default=1)
    args = ap.parse_args()
    rnd = random.Random(args.seed)
    texts = seeds(os.path.dirname(HERE))
    accepted = refused = 0
    problems: list[tuple[int, str, str]] = []
    slowest = 0.0
    for n in range(args.cases):
        text = rnd.choice(texts)
        for _ in range(rnd.choice([1, 1, 2, 3, 5])):
            if text:
                text = mutate(rnd, text)
        started = time.perf_counter()
        what, was_refused = check(text)
        refused += was_refused
        accepted += not was_refused and not what
        if what:
            problems.append((n, what, text))
        took = time.perf_counter() - started
        slowest = max(slowest, took)
        if took > 5:
            problems.append((n, f"took {took:.1f} s", text))
    for n, what, text in problems[:5]:
        print(f"--- case {n}: {what.strip()}\n{text[:1500]}\n")
    print(
        f"fuzz_parser: {args.cases} mutated policies (from {len(texts)}), {accepted} accepted, {refused} refused, "
        f"{len(problems)} problems; slowest {slowest * 1000:.0f} ms"
    )
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())

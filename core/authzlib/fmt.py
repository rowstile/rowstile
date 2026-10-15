"""rowstile fmt: one way to write a policy, so a text diff holds only real changes.

- top-level lines (app role, type, rules, scope, caveat, include, invariants, test) start the line; the lines
  of a block are indented by two spaces; a continuation (or, and, where, if) lines up under the
  expression it continues
- one blank line between blocks, none at the start or the end, never two in a row
- in a run of relations, the ':' and the '=' line up; in a run of permissions, the '='; in a run of rules,
  the ':'; trailing comments line up two spaces after the longest line of their run
- words are separated by one space, except inside {conditions}, quotes and comments, which stay as written

format() refuses (raises FormatError) rather than change what the policy says: the result must parse
to the same declarations.
"""

from __future__ import annotations

import re
from typing import NamedTuple, TypeAlias

from .parse import Scanner, meaning_lines

TOP = re.compile(r"^(type|rules|scope|caveat|app\s+role|include|invariants|test)\b")
CONT = re.compile(r"^(or|and|where|if)\b")


class FormatError(Exception):
    pass


class Line(NamedTuple):
    kind: str  # 'blank', 'comment', 'top', 'scope', 'cont', or a body kind (kind_of)
    code: str
    comment: str
    indent: int


# a line of an aligned run: (left of the ':' or '=', right of it, and for a relation the source after its '=')
Head: TypeAlias = "tuple[str, str, str | None]"
# a rendered line, and the column its continuations hang from
Rendered: TypeAlias = "tuple[str, int]"


def scan(text: str) -> list[tuple[str, bool, int]]:
    """Each character of text with whether it is quoted, and how many {braces} are open around it, as the parser
    reads them (parse.Scanner)."""
    return [(c, m.quoted, m.depth) for c, m in zip(text, Scanner().marks(text), strict=True)]


def squeeze(code: str) -> str:
    """One space between words, outside {conditions} and quotes."""
    out: list[str] = []
    space = False
    for c, quoted, depth in scan(code.strip()):
        if c in " \t" and not quoted and depth == 0:
            space = True
            continue
        if space and out:
            out.append(" ")
        space = False
        out.append(c)
    return "".join(out)


def top_split(code: str, sep: str) -> tuple[str, str] | None:
    """code split at the first `sep` outside {} and quotes: (before, after) or None."""
    for i, (_, quoted, depth) in enumerate(scan(code)):
        if not quoted and depth == 0 and code.startswith(sep, i):
            return code[:i], code[i + len(sep) :]
    return None


def split_at(code: str, sep: str) -> tuple[str, str]:
    """top_split for a line whose kind says `sep` is there."""
    parts = top_split(code, sep)
    assert parts is not None, f"no {sep!r} in {code!r}"
    return parts


def kind_of(code: str, block: str | None) -> str:
    if block == "type":
        if re.match(r"can\s", code) and top_split(code, "="):
            return "can"
        if re.match(r"\w+\s*:", code):
            return "relation"
    if block == "rules" and top_split(code, ":"):
        return "rule"
    return "other"


def format_policy(text: str) -> str:
    lines = text.replace("\r\n", "\n").split("\n")
    items: list[Line] = []
    block: str | None = None
    reading = Scanner()  # the lines as the parser reads them: what is a comment, which braces are open
    code_before = False  # a line of code before this one (not a blank line, nor a comment)
    for raw in lines:
        if not raw.strip():
            items.append(Line("blank", "", "", 0))
            continue
        stripped = raw.strip()
        if stripped.startswith("--"):
            items.append(Line("comment", "", stripped, 0 if not raw[:1].isspace() else 2))
            continue
        open_braces = reading.depth
        marks = reading.marks(raw)
        # a trailing comment outside {}; one in a condition is SQL's, kept with it
        at = next((i for i, m in enumerate(marks) if m.comment and not m.depth), len(raw))
        code, comment = raw[:at].rstrip(), raw[at:].rstrip()
        indent = len(raw) - len(raw.lstrip())
        s = squeeze(code) if open_braces == 0 else code.strip()
        # a line that starts with or, and, ... continues the one before it, however it is indented (as the parser reads it)
        if open_braces > 0 or (CONT.match(code.strip()) and code_before):
            items.append(Line("cont", code.strip() if open_braces else squeeze(code), comment, indent))
        elif indent == 0:  # an indented line is never a top-level one: `role : user = ...` is a relation
            m = TOP.match(stripped)
            block = m.group(1) if m else None
            items.append(Line("scope" if block == "scope" and top_split(s, "=") else "top", s, comment, 0))
        else:
            items.append(Line(kind_of(s, block), s, comment, 2))
        code_before = True

    # blank lines: one before each block that follows another (with its comments), none doubled, none at the ends
    # (a blank line is kept only after another line)
    out_items: list[Line] = []
    for it in items:
        if it[0] == "blank":
            if out_items and out_items[-1][0] != "blank":
                out_items.append(it)
            continue
        out_items.append(it)
    while out_items and out_items[-1][0] == "blank":
        out_items.pop()
    final: list[Line] = []
    for i, it in enumerate(out_items):
        if it[0] in ("top", "scope") and final and final[-1][0] not in ("blank", "comment"):
            if not (final[-1][0] in ("top", "scope") and _single(final[-1][1]) and _single(it[1])):
                final.append(Line("blank", "", "", 0))
        elif (
            it[0] == "comment"
            and it[3] == 0
            and final
            and final[-1][0] not in ("blank", "comment")
            and i + 1 < len(out_items)
            and out_items[i + 1][0] in ("top", "comment")
        ):
            final.append(Line("blank", "", "", 0))
        final.append(it)

    # align runs of relations, permissions and rules; continuations under their expression
    rendered: list[Rendered | None] = [None] * len(final)
    i = 0
    while i < len(final):
        kind = final[i][0]
        if kind not in ("relation", "can", "rule", "scope", "other"):
            i += 1
            continue
        j = i
        run: list[int] = []
        while j < len(final) and final[j][0] in (kind, "cont"):
            run.append(j)
            j += 1
        _align(final, run, kind, rendered)
        i = j
    out: list[str] = []
    last_expr_col = 2
    for k, it in enumerate(final):
        kind, code, comment, indent = it
        done = rendered[k]
        if done is not None:
            text_line, last_expr_col = done
        elif kind == "blank":
            text_line = ""
        elif kind == "comment":
            text_line = " " * (2 if indent else 0) + comment
            comment = ""
        elif kind == "cont":
            text_line = hang(last_expr_col, code)
        else:  # a top-level line: the lines of a block are in a run, aligned above
            assert kind == "top", kind
            text_line = code
            last_expr_col = _expr_col(code, 0)
        if comment and rendered[k] is None:
            text_line = (text_line + "  " + comment) if text_line else comment
        out.append(text_line.rstrip())
    result = "\n".join(out) + "\n"
    return result


def hang(col: int, code: str) -> str:
    """A continuation: 'or', 'and', 'where', 'if' hang left of the column, so what follows them lines up
    under the expression they continue; anything else (a condition's SQL) starts at the column."""
    m = CONT.match(code)
    return " " * (max(2, col - len(m.group(1)) - 1) if m else col) + code


def _single(code: str) -> bool:
    return code.startswith(("scope ", "caveat ", "app role ", "include "))


def _expr_col(code: str, indent: int) -> int:
    """Where the expression of a line starts (continuations line up under it)."""
    m = top_split(code, "= ") or top_split(code, ": ")
    return indent + (len(code) - len(m[1]) if m else 2)


def _align(final: list[Line], run: list[int], kind: str, rendered: list[Rendered | None]) -> None:
    heads: list[Head | None] = []
    for k in run:
        it = final[k]
        if it[0] == "cont":
            heads.append(None)
            continue
        code = it[1]
        if kind == "other":
            heads.append((code, "", None))
        elif kind == "relation":
            name, rest = split_at(code, ":")
            eq = top_split(rest, "=")
            heads.append((name.strip(), eq[0].strip() if eq else rest.strip(), eq[1].strip() if eq else None))
        elif kind in ("can", "scope"):
            left, right = split_at(code, "=")
            heads.append((" ".join(left.split()), right.strip(), None))
        else:
            left, right = split_at(code, ":")
            heads.append((" ".join(left.split()), right.strip(), None))
    w1 = max((len(h[0]) for h in heads if h), default=0)
    w2 = max((len(h[1]) for h in heads if h and kind == "relation" and h[2] is not None), default=0)
    lines: list[tuple[int, str, str]] = []
    col = 2
    for k, h in zip(run, heads, strict=True):
        it = final[k]
        if h is None:
            lines.append((k, hang(col, it[1]), it[2]))
            continue
        if kind == "relation":
            if h[2] is not None:
                line = f"  {h[0].ljust(w1)} : {h[1].ljust(w2)} = {h[2]}"
                col = len(f"  {h[0].ljust(w1)} : {h[1].ljust(w2)} = ")
            else:
                line = f"  {h[0].ljust(w1)} : {h[1]}"
                col = len(f"  {h[0].ljust(w1)} : ")
        elif kind == "can":
            line = f"  {h[0].ljust(w1)} = {h[1]}"
            col = len(f"  {h[0].ljust(w1)} = ")
        elif kind == "scope":
            line = f"{h[0].ljust(w1)} = {h[1]}"
            col = len(f"{h[0].ljust(w1)} = ")
        elif kind == "other":
            line = f"  {h[0]}"
            col = _expr_col(h[0], 2)
        else:
            line = f"  {h[0].ljust(w1)} : {h[1]}"
            col = len(f"  {h[0].ljust(w1)} : ")
        lines.append((k, line, it[2]))
    # trailing comments line up after the longest line that has one
    width = max((len(line) for _, line, comment in lines if comment), default=0)
    for (k, line, comment), h in zip(lines, heads, strict=True):
        rendered[k] = (
            (line.ljust(width) + "  " + comment) if comment else line,
            col if h is None else _col_after(line, kind, h),
        )


def _col_after(line: str, kind: str, h: Head) -> int:
    if kind == "other":
        return _expr_col(h[0], 2)
    if kind == "relation" and h[2] is None:
        return len(line) - len(h[1])
    return len(line) - len((h[2] if kind == "relation" else h[1]) or "")


def tight(line: str) -> str:
    """A line with no spaces around punctuation, outside {conditions} and quotes: what it says, not its spacing."""
    marked = "".join("\0" if c == " " and not quoted and depth == 0 else c for c, quoted, depth in scan(squeeze(line)))
    return re.sub(r"\0*([:=,()])\0*", r"\1", marked).replace("\0", " ")


def tests_of(text: str, files: dict[str, str]) -> list[object]:
    """What the tests of a policy or test file say: each check and each named test's lines, as the parser reads
    them. meaning_lines leaves the tests out (they make nothing in the database); formatting must not change them."""
    from .parse import parse_policy

    pol = parse_policy(text, None, files=files)
    return [
        *[(t.ptype, t.who, t.expect, t.perm, t.type, t.obj, t.scopes) for t in pol.tests],
        *[
            (
                sc.name,
                [(st.kind, st.var, st.sql, st.who, st.expect, st.perm, st.type, st.obj, st.scopes) for st in sc.steps],
            )
            for sc in pol.scenarios
        ],
    ]


def format(text: str, files: dict[str, str] | None = None) -> str:
    """The policy as rowstile fmt writes it; FormatError if that would change what it says."""
    out = format_policy(text)
    try:
        same = [tight(x) for x in meaning_lines(text, files or {})] == [
            tight(x) for x in meaning_lines(out, files or {})
        ] and tests_of(text, files or {}) == tests_of(out, files or {})
    except Exception as e:
        raise FormatError(f"can't format a policy that doesn't parse: {e}") from None
    if not same:
        raise FormatError("formatting would change what the policy says (a bug in rowstile fmt: please report it)")
    return out

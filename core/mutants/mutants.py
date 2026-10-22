"""The mutants: small mistakes put into authzlib by rule, one at a time, to see whether a suite notices.

What it makes, in core/authzlib/*.py (errors.py aside: its pages are prose):
- In the SQL inside the compiler's strings (a string with an SQL keyword in capitals, or an f-string; never a
  docstring, a message for fail()/raise/print, or a regular expression): AND for OR and OR for AND, = for <>
  and back, < for <= (and >, >=) and back, IS NULL for IS NOT NULL and back, IS DISTINCT FROM for IS NOT DISTINCT
  FROM and back, EXISTS for NOT EXISTS and back, true for false in a coalesce and back, each term of a WHERE
  (a conjunction) put as true, a PERFORM statement put as NULL, a SET search_path dropped, SECURITY DEFINER
  dropped. Only text outside an f-string's {fields}, and never in an SQL comment.
- In the Python: each comparison's operator (== and !=, < and <=, > and >=, in and not in, is and is not), a
  `not` dropped, a `not` added to an if's test (and a conditional expression's, a comprehension's filter), each
  if's test forced True and False, each item dropped from a list or tuple written one item to a line (REMOVE_SQL,
  GENERATED_FUNCTIONS, compile()'s parts), each q(), qt() and lit() call dropped (its argument left).
- A mutant that doesn't parse is left out; two that make the same file are one.

The id: `g` and ten hex digits of the file, the function (Class.method), the operator, the text of the line it is
on (stripped) with where on that line, and which of identical such keys it is (in file order). Unrelated edits
(lines added above, another function changed) leave it the same, so a mutant's result holds until its own line
changes. Standard library only."""

from __future__ import annotations

import ast
import hashlib
import io
import os
import random
import re
import subprocess
import tokenize
from collections import Counter
from dataclasses import dataclass

SKIP_FILES = {"errors.py"}  # the error pages: prose and examples, not what the compiler writes
# files whose f-strings are mostly text, not SQL: there only a string with an SQL keyword counts as SQL
PROSE_FILES = {"review.py", "fmt.py", "parse.py", "evaluate.py", "conditions.py", "prove.py", "coverage.py",
               "statements.py", "draft.py", "devtools.py", "testing.py", "insight.py"}  # fmt: skip


@dataclass
class Mutant:
    """One mutant: where it is, and the text it replaces (`old`, unique in its file) with `new`."""

    id: str
    file: str  # in authzlib/
    func: str
    op: str
    line: int  # its first and last line (the mutated text, not the context added to make `old` unique)
    end: int
    old: str
    new: str
    what: str


# ---------------------------------------------------------------------------------------------------------------
# The source: offsets, functions, strings


class Source:
    """A file of authzlib: its text, its lines' offsets, its syntax tree and the functions in it."""

    def __init__(self, fname: str, text: str) -> None:
        self.fname, self.text = fname, text
        self.lines = text.split("\n")
        self.starts = [0]
        for ln in self.lines:
            self.starts.append(self.starts[-1] + len(ln) + 1)
        self.tree = ast.parse(text)
        self.defs: list[tuple[int, int, str]] = []  # (first line, last line, qualified name), outer first

        def walk(node: ast.AST, prefix: str) -> None:
            for ch in ast.iter_child_nodes(node):
                if isinstance(ch, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    name = prefix + ch.name
                    self.defs.append((ch.lineno, ch.end_lineno or ch.lineno, name))
                    walk(ch, name + ".")
                else:
                    walk(ch, prefix)

        walk(self.tree, "")
        self.stmts = [n for n in ast.walk(self.tree) if isinstance(n, ast.stmt)]

    def at(self, lineno: int, col: int) -> int:
        """The offset in text of tokenize's (line, column), columns in characters."""
        return self.starts[lineno - 1] + col

    def at_bytes(self, lineno: int, col: int) -> int:
        """The offset of ast's (line, column), columns in UTF-8 bytes."""
        return self.starts[lineno - 1] + len(self.lines[lineno - 1].encode("utf-8")[:col].decode("utf-8", "replace"))

    def span(self, node: ast.expr | ast.stmt) -> tuple[int, int]:
        a = self.at_bytes(node.lineno, node.col_offset)
        b = self.at_bytes(node.end_lineno or node.lineno, node.end_col_offset or 0)
        return a, b

    def line_of(self, off: int) -> int:
        lo, hi = 0, len(self.starts) - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if self.starts[mid] <= off:
                lo = mid
            else:
                hi = mid - 1
        return lo + 1

    def func(self, lineno: int) -> str:
        best = "<module>"
        for a, b, name in self.defs:
            if a <= lineno <= b:
                best = name  # outer first, so the last one holding it is the innermost
        return best

    def header_lines(self, first: int, last: int) -> set[int]:
        """The lines of the statements the mutated lines are in (a compound statement: its header only): if the
        compiler ran none of them, the mutant can't change what it writes."""
        out: set[int] = set()
        for ln in range(first, last + 1):
            best: ast.stmt | None = None
            for n in self.stmts:
                end = n.end_lineno or n.lineno
                body = getattr(n, "body", None)
                if isinstance(body, list) and body and isinstance(body[0], ast.stmt):
                    end = body[0].lineno - 1  # a compound statement's header: its body is statements of their own
                    if ln > end:
                        continue
                if n.lineno <= ln <= max(end, n.lineno) and (best is None or n.lineno >= best.lineno):
                    best = n
            if best is not None:
                hb = best.end_lineno or best.lineno
                body = getattr(best, "body", None)
                if isinstance(body, list) and body and isinstance(body[0], ast.stmt):
                    hb = max(best.lineno, body[0].lineno - 1)
                out.update(range(best.lineno, hb + 1))
            out.add(ln)
        return out


def string_spans(src: Source) -> list[tuple[int, int, bool]]:
    """Each string literal: (start, end, f-string), offsets in the text; an f-string is one span."""
    out: list[tuple[int, int, bool]] = []
    depth = 0
    fstart = 0
    for tok in tokenize.generate_tokens(io.StringIO(src.text).readline):
        name = tokenize.tok_name[tok.type]
        if name == "FSTRING_START":
            if depth == 0:
                fstart = src.at(*tok.start)
            depth += 1
        elif name == "FSTRING_END":
            depth -= 1
            if depth == 0:
                out.append((fstart, src.at(*tok.end), True))
        elif tok.type == tokenize.STRING:  # inside an f-string's field too: `{' AND '.join(...)}` is one of its own
            a = src.at(*tok.start)
            prefix = re.match(r"[A-Za-z]*", tok.string)
            out.append((a, src.at(*tok.end), bool(prefix and "f" in prefix.group(0).lower())))
    return out


def masked(text: str, fstring: bool) -> tuple[str, int, int]:
    """The literal's body with what isn't SQL text blanked: an f-string's fields as NUL, escapes (\\n) as spaces;
    the same length as the body; and the body's start and end in `text`."""
    m = re.match(r"([A-Za-z]*)('''|\"\"\"|'|\")", text)
    assert m
    prefix, quote = m.group(1).lower(), m.group(2)
    a, b = m.end(), len(text) - len(quote)
    body = text[a:b]
    out = list(body)
    raw = "r" in prefix
    i, n = 0, len(body)
    while i < n:
        c = body[i]
        if c == "\\" and not raw and i + 1 < n:
            out[i], out[i + 1] = (
                " ",
                "\n" if body[i + 1] == "n" else " ",
            )  # \n stays a line break: SQL comments end there
            i += 2
            continue
        if fstring and c in "{}" and body[i + 1 : i + 2] == c:
            i += 2
            continue
        if fstring and c == "{":
            j, depth = i + 1, 1
            while j < n and depth:
                ch = body[j]
                if ch in "{[(":
                    depth += 1
                elif ch in "}])":
                    depth -= 1
                elif ch in "'\"":
                    k = body.find(ch, j + 1)
                    j = k if k >= 0 else n
                j += 1
            for k in range(i, min(j, n)):
                out[k] = "\0"
            i = j
            continue
        i += 1
    return "".join(out), a, b


# the clients' code (TypeScript generics, Python assignments) is in strings with SQL in them: not SQL comparisons
CLIENT_FILES = {"devtools.py"}
SYMBOL_OPS = {"sql =-><>", "sql <>->=", "sql <-><=", "sql <=-><", "sql >->=", "sql >=->"}
SQL_WORD = re.compile(
    r"\b(SELECT|WHERE|THEN|RETURN|RETURNS|PERFORM|EXISTS|CREATE|LANGUAGE|INSERT|UPDATE|DELETE|AND|OR|NOT|IS|CASE|"
    r"WHEN|FROM|JOIN|BEGIN|END|IF|ON|SET|GRANT|REVOKE|ALTER|DROP|USING|NULL|LOOP|DEFINER|VALUES)\b|coalesce\("
)
MESSAGE_CALLS = {"fail", "PolicyError", "warn", "print", "note", "ValueError", "RuntimeError", "SystemExit",
                 "AssertionError", "TypeError", "KeyError", "error", "say"}  # fmt: skip


def excluded_ranges(src: Source) -> list[tuple[int, int]]:
    """Docstrings, the arguments of message calls (fail, raise, print) and of the re module's functions."""
    out: list[tuple[int, int]] = []
    for node in ast.walk(src.tree):
        if isinstance(node, ast.Expr) and isinstance(node.value, (ast.Constant, ast.JoinedStr)):
            out.append(src.span(node))
        elif isinstance(node, ast.Call):
            f = node.func
            name = f.id if isinstance(f, ast.Name) else f.attr if isinstance(f, ast.Attribute) else ""
            is_re = isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name) and f.value.id == "re"
            if name in MESSAGE_CALLS or is_re:
                for a in [*node.args, *(k.value for k in node.keywords)]:
                    out.append(src.span(a))
        elif isinstance(node, ast.Raise) and node.exc is not None:
            out.append(src.span(node.exc))
    return out


# ---------------------------------------------------------------------------------------------------------------
# The operators: each gives (start, end, replacement, operator) in the text


Edit = tuple[int, int, str, str]

# a regular expression on the masked body, and what replaces the match
SQL_OPS: list[tuple[str, re.Pattern[str], str]] = [
    ("sql AND->OR", re.compile(r"\bAND\b"), "OR"),
    ("sql OR->AND", re.compile(r"(?<!INSERT )(?<!UPDATE )(?<!DELETE )(?<!TRUNCATE )\bOR\b(?! REPLACE)"), "AND"),
    ("sql =-><>", re.compile(r"(?<![<>:=!~^@|&#*+/%-])=(?![=>~])"), "<>"),
    ("sql <>->=", re.compile(r"<>|!="), "="),
    ("sql <-><=", re.compile(r"(?<![<-])<(?![=>@<])"), "<="),
    ("sql <=-><", re.compile(r"(?<![<])<=(?!>)"), "<"),
    ("sql >->=", re.compile(r"(?<![-#=<>@])>(?![=>])"), ">="),
    ("sql >=->", re.compile(r"(?<![>])>="), ">"),
    ("sql IS NULL->IS NOT NULL", re.compile(r"\bIS NULL\b"), "IS NOT NULL"),
    ("sql IS NOT NULL->IS NULL", re.compile(r"\bIS NOT NULL\b"), "IS NULL"),
    ("sql IS DISTINCT->IS NOT DISTINCT", re.compile(r"\bIS DISTINCT FROM\b"), "IS NOT DISTINCT FROM"),
    ("sql IS NOT DISTINCT->IS DISTINCT", re.compile(r"\bIS NOT DISTINCT FROM\b"), "IS DISTINCT FROM"),
    ("sql EXISTS->NOT EXISTS", re.compile(r"(?<!IF )(?<!NOT )\bEXISTS\b"), "NOT EXISTS"),
    ("sql NOT EXISTS->EXISTS", re.compile(r"(?<!IF )\bNOT EXISTS\b"), "EXISTS"),
    ("sql PERFORM dropped", re.compile(r"(?<![\w.])PERFORM\b[^;]*;"), "NULL;"),
    ("sql search_path dropped", re.compile(r" ?\bSET search_path (?:FROM CURRENT|= pg_catalog, pg_temp)\b"), ""),
    ("sql SECURITY DEFINER dropped", re.compile(r" ?\bSECURITY DEFINER\b"), ""),
]
# = that sets rather than compares: SET x = ..., an UPDATE's SET list, RAISE ... USING ERRCODE = ..., a := default
SETTING = re.compile(
    r"(?:\bSET\s+[\w.\"]+|\b(?:ERRCODE|MESSAGE|HINT|DETAIL|COLUMN|CONSTRAINT|SCHEMA|TABLE)|,\s*[\w\"]+)\s*$"
)
COALESCE_BOOL = re.compile(r",\s*(true|false)\)")
WHERE_END = re.compile(
    r"\b(GROUP BY|ORDER BY|LIMIT|RETURNING|UNION|THEN|LOOP|ON CONFLICT|FOR UPDATE|FOR SHARE|INTO|EXCEPT|INTERSECT|"
    r"HAVING|WINDOW|OFFSET|DO)\b"
)
CONTINUED = re.compile(r"(=|<|>|\(|,|\|\||\b(AND|OR|NOT|IS|IN|LIKE|ILIKE|ANY|ALL|BETWEEN|AS))\s*$")


def where_terms(body: str) -> list[tuple[int, int]]:
    """Each term of each WHERE that is a conjunction (no OR at its level), as (start, end) in the masked body."""
    out: list[tuple[int, int]] = []
    for m in re.finditer(r"\bWHERE\b", body):
        i = m.end()
        n = len(body)
        depth = 0
        terms: list[tuple[int, int]] = []
        start = i
        ok = True
        while i < n:
            c = body[i]
            if c == "'":
                k = body.find("'", i + 1)
                if k < 0:  # the quote closes in another literal (or this WHERE is inside one: format('... WHERE ...'))
                    ok = False
                    break
                i = k + 1
                continue
            if c == "$" or (c == "-" and body.startswith("--", i)):
                break  # a dollar quote or a comment: not a term to drop
            if c == "(":
                depth += 1
            elif c == ")":
                if depth == 0:
                    break
                depth -= 1
            elif c == ";" and depth == 0:
                break
            elif depth == 0 and body[i].isalpha() and (i == 0 or not (body[i - 1].isalnum() or body[i - 1] == "_")):
                if body.startswith("AND", i) and not body[i + 3 : i + 4].isalnum():
                    terms.append((start, i))
                    start = i + 3
                    i += 3
                    continue
                if body.startswith("OR", i) and not body[i + 2 : i + 3].isalnum():
                    ok = False
                    break
                if WHERE_END.match(body, i):
                    break
            i += 1
        terms.append((start, i))
        if not ok or re.search(r"\bCASE\b", body[m.end() : i]):
            continue
        if i >= n and CONTINUED.search(body[start:i]):
            terms.pop()  # the last term may go on in the next literal: `WHERE a = ` "{b}"
        for a, b in terms:
            seg = body[a:b]
            lead = len(seg) - len(seg.lstrip())
            trail = len(seg) - len(seg.rstrip())
            a2, b2 = a + lead, b - trail
            if b2 > a2 and body[a2:b2].strip("\0 ") and body[a2:b2] != "true":
                out.append((a2, b2))
    return out


def in_comment(body: str, at: int, client: bool = False) -> bool:
    """After `--` on its line of SQL: a comment (what it says changes nothing; the comparison skips them). In the
    clients' code (CLIENT_FILES), after `//` too: their TypeScript's comments, which name SQL words in prose."""
    before = body[body.rfind("\n", 0, at) + 1 : at]
    return "--" in before or (client and "//" in before)


def sql_edits(src: Source) -> list[Edit]:
    out: list[Edit] = []
    skip = excluded_ranges(src)
    for a, b, fstring in string_spans(src):
        if any(x <= a and b <= y for x, y in skip):
            continue
        text = src.text[a:b]
        body, ba, _ = masked(text, fstring)
        if not (SQL_WORD.search(body) or (fstring and src.fname not in PROSE_FILES)):
            continue
        base = a + ba
        client = src.fname in CLIENT_FILES
        for op, rx, rep in SQL_OPS:
            if src.fname in CLIENT_FILES and op in SYMBOL_OPS:
                continue
            for m in rx.finditer(body):
                if "\0" in m.group(0) or in_comment(body, m.start(), client):
                    continue
                if op == "sql =-><>" and SETTING.search(body[: m.start()].split("\n")[-1]):
                    continue
                out.append((base + m.start(), base + m.end(), rep, op))
        if "coalesce(" in text.lower():
            for m in COALESCE_BOOL.finditer(body):
                if in_comment(body, m.start(), client):
                    continue
                flip = "false" if m.group(1) == "true" else "true"
                out.append((base + m.start(1), base + m.end(1), flip, f"sql coalesce {m.group(1)}->{flip}"))
        for x, y in where_terms(body):
            if in_comment(body, x, client):
                continue
            out.append((base + x, base + y, "true", "sql WHERE term dropped"))
    return out


CMP_TEXT: dict[type, tuple[str, str]] = {
    ast.Eq: ("==", "!="),
    ast.NotEq: ("!=", "=="),
    ast.Lt: ("<", "<="),
    ast.LtE: ("<=", "<"),
    ast.Gt: (">", ">="),
    ast.GtE: (">=", ">"),
    ast.In: ("in", "not in"),
    ast.NotIn: ("not in", "in"),
    ast.Is: ("is", "is not"),
    ast.IsNot: ("is not", "is"),
}
CALLS_DROPPED = {"q", "qt", "lit"}


def guarded(test: ast.expr) -> bool:
    """An if that isn't the program's logic: `if __name__ == "__main__"`, `if TYPE_CHECKING`."""
    s = ast.unparse(test)
    return "__name__" in s or "TYPE_CHECKING" in s


def python_edits(src: Source) -> list[Edit]:
    out: list[Edit] = []
    t = src.text
    for node in ast.walk(src.tree):
        if isinstance(node, ast.Compare):
            left = node.left
            for op, right in zip(node.ops, node.comparators, strict=True):
                _, la = src.span(left)
                rb, _ = src.span(right)
                have, want = CMP_TEXT[type(op)]
                gap = t[la:rb]
                pat = (
                    r"\bnot\s+in\b|\bis\s+not\b"
                    if " " in have
                    else (r"\b" + have + r"\b" if have.isalpha() else re.escape(have))
                )
                found = list(re.finditer(pat, gap))
                if len(found) == 1 and not (have in ("in", "is") and re.search(r"\bnot\s+in\b|\bis\s+not\b", gap)):
                    m = found[0]
                    out.append((la + m.start(), la + m.end(), want, f"py {have}->{want}"))
                left = right
        elif isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            a, b = src.span(node)
            oa, ob = src.span(node.operand)
            inner = t[oa:ob]
            # parentheses around the operand stay with it: `not (a or b)` -> `(a or b)`
            pre = t[a:oa]
            k = pre.find("(")
            if k >= 0:
                oa = a + k
                close = t.find(")", ob)
                ob = close + 1 if close >= 0 and t[ob:close].strip() == "" else ob
                inner = t[oa:ob]
            out.append((a, b, inner, "py not dropped"))
        if isinstance(node, (ast.If, ast.IfExp)) and not guarded(node.test):
            a, b = src.span(node.test)
            if not isinstance(node.test, ast.Constant):
                out.append((a, b, "True", "py if forced True"))
                out.append((a, b, "False", "py if forced False"))
            if not (isinstance(node.test, ast.UnaryOp) and isinstance(node.test.op, ast.Not)):
                out.append((a, b, f"not ({t[a:b]})", "py not added"))
        if isinstance(node, ast.comprehension):
            for cond in node.ifs:
                a, b = src.span(cond)
                if not (isinstance(cond, ast.UnaryOp) and isinstance(cond.op, ast.Not)):
                    out.append((a, b, f"not ({t[a:b]})", "py not added"))
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in CALLS_DROPPED
            and len(node.args) == 1
            and not node.keywords
            and not isinstance(node.args[0], ast.Starred)
        ):
            a, b = src.span(node)
            xa, xb = src.span(node.args[0])
            out.append((a, b, t[xa:xb], f"py {node.func.id}() dropped"))
        if isinstance(node, (ast.List, ast.Tuple)) and len(node.elts) >= 2:
            elts = node.elts
            for i, el in enumerate(elts):
                first, last = el.lineno, el.end_lineno or el.lineno
                if i > 0 and (elts[i - 1].end_lineno or 0) >= first:
                    continue
                if i + 1 < len(elts) and elts[i + 1].lineno <= last:
                    continue
                a, b = src.span(el)
                la = src.starts[first - 1]
                lb = src.starts[last] - 1  # the end of the element's last line
                if t[la:a].strip() or not re.fullmatch(r"\s*,?\s*(#.*)?", t[b:lb]):
                    continue
                out.append((la, lb + 1, "", "py item dropped"))
    return out


# ---------------------------------------------------------------------------------------------------------------
# Making the mutants


def unique_context(src: Source, a: int, b: int) -> tuple[int, int]:
    """Whole lines around [a, b) that occur once in the text."""
    text, starts = src.text, src.starts
    la, lb = src.line_of(a), src.line_of(max(a, b - 1))
    n = len(starts) - 1
    for k in range(40):
        ca = starts[max(la - 1 - (k + 1) // 2, 0)]
        cb = starts[min(lb + k // 2, n)]
        cb = min(cb, len(text))
        if text.count(text[ca:cb]) == 1:
            return ca, cb
    return 0, len(text)


def short(s: str, n: int = 60) -> str:
    s = " ".join(s.split())
    return s if len(s) <= n else s[: n - 3] + "..."


def of_file(fname: str, text: str, dropped: Counter[str] | None = None) -> list[Mutant]:
    """Every mutant of one file, in file order; `dropped` counts what was left out (doesn't parse, a duplicate)."""
    dropped = Counter() if dropped is None else dropped
    out: list[Mutant] = []
    src = Source(fname, text)
    edits = sorted(set(sql_edits(src) + python_edits(src)))
    keys: Counter[str] = Counter()
    seen: set[str] = set()
    for a, b, rep, op in edits:
        new_text = text[:a] + rep + text[b:]
        if new_text == text:
            dropped["no change"] += 1
            continue
        digest = hashlib.sha1(new_text.encode()).hexdigest()
        if digest in seen:
            dropped["duplicate"] += 1
            continue
        # these two remove a range; the others can't break the syntax (text in a literal, an operator)
        if op in ("py item dropped", "sql WHERE term dropped"):
            try:
                ast.parse(new_text)
            except SyntaxError:
                dropped["does not parse"] += 1
                continue
        seen.add(digest)
        first, last = src.line_of(a), src.line_of(max(a, b - 1))
        ln = src.lines[first - 1]
        col = a - src.starts[first - 1] - (len(ln) - len(ln.lstrip()))
        func = src.func(first)
        key = f"{fname}|{func}|{op}|{ln.strip()}|{col}|{' '.join(text[a:b].split())}"
        keys[key] += 1
        mid = "g" + hashlib.sha1(f"{key}|{keys[key]}".encode()).hexdigest()[:10]
        ca, cb = unique_context(src, a, b)
        old = text[ca:cb]
        new = text[ca:a] + rep + text[b:cb]
        ls, le = src.starts[first - 1], src.starts[min(last, len(src.lines))] - 1
        before, after = text[max(ls, a - 30) : a].lstrip(), text[b : min(le, b + 30)].rstrip()
        change = f"[{short(text[a:b], 40)} => {short(rep, 40)}]"
        what = f"{fname}:{first} {func}: {op}: {short(before, 30)}{change}{short(after, 30)}"
        out.append(Mutant(mid, fname, func, op, first, last, old, new, what))
    return out


def generate(core: str, dropped: Counter[str] | None = None) -> list[Mutant]:
    """Every mutant of core/authzlib, file by file in name order."""
    out: list[Mutant] = []
    lib = os.path.join(core, "authzlib")
    for fname in sorted(os.listdir(lib)):
        if not fname.endswith(".py") or fname in SKIP_FILES:
            continue
        with open(os.path.join(lib, fname), encoding="utf-8") as fh:
            out += of_file(fname, fh.read(), dropped)
    ids = Counter(m.id for m in out)
    assert max(ids.values(), default=1) == 1, f"ids not unique: {[k for k, v in ids.items() if v > 1][:5]}"
    return out


def changed_lines(root: str, since: str) -> dict[str, set[int]]:
    """The lines of authzlib's files added or changed since a commit, by file."""
    p = subprocess.run(["git", "-C", root, "diff", "-U0", since, "--", "core/authzlib"], capture_output=True,
                       text=True, check=True)  # fmt: skip
    out: dict[str, set[int]] = {}
    cur = ""
    for ln in p.stdout.split("\n"):
        if ln.startswith("+++ "):
            cur = os.path.basename(ln[4:].strip())
        m = re.match(r"@@ -\S+ \+(\d+)(?:,(\d+))? @@", ln)
        if m and cur:
            a, n = int(m.group(1)), int(m.group(2) or 1)
            out.setdefault(cur, set()).update(range(a, a + n))
    return out


def in_lines(mutants: list[Mutant], lines: dict[str, set[int]]) -> list[Mutant]:
    """The mutants in these lines (changed_lines')."""
    return [m for m in mutants if any(ln in lines.get(m.file, set()) for ln in range(m.line, m.end + 1))]


def spread(mutants: list[Mutant], seed: int) -> list[Mutant]:
    """The mutants in an order spread over operators and files: one of each (operator, file) group in turn, the
    groups and each group's mutants shuffled with the seed. A run that takes the first N gets a sample of every
    kind; the next run, which leaves out those it has results for, the next N."""
    rng = random.Random(seed)
    groups: dict[tuple[str, str], list[Mutant]] = {}
    for m in mutants:
        groups.setdefault((m.op, m.file), []).append(m)
    keys = sorted(groups)
    rng.shuffle(keys)
    for k in keys:
        rng.shuffle(groups[k])
    out: list[Mutant] = []
    depth = 0
    while len(out) < len(mutants):
        for k in keys:
            if depth < len(groups[k]):
                out.append(groups[k][depth])
        depth += 1
    return out

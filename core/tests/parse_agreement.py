#!/usr/bin/env python3
"""parse_agreement: the Tree-sitter grammar (editor/tree-sitter-authz) reads each policy as authzlib/parse.py does.

The compiler and the reference evaluator both read policies through parse.py, so a policy it misread would fool
them both: their answers would agree, and be wrong. The grammar was written apart from it, for editors; where
the two read a policy alike, that reading has two witnesses.

    python3 tests/parse_agreement.py --write DIR N       # N of genpolicy's random policies, as DIR/gen_<seed>.authz
    python3 tests/parse_agreement.py --write DIR 0 --small 4 [--slice K/N]   # and/or small.py's set up to size 4
    npx tree-sitter parse --xml --paths LIST > all.xml   # in editor/tree-sitter-authz: every file LIST names
    python3 tests/parse_agreement.py all.xml [more.xml]  # each policy parse.py accepts, read alike? (exit 1 if not)

small.py's set (tests/small.py: every policy of the core language up to a size, and those of the next with a deny)
is written twice: each policy as the set lists it (DIR/small_<k>.authz), and written another way, as small.py's
second reading has it (DIR/small_<k>_other.authz: its names swapped, every `or` and `and` the other way round).
--slice K/N: only the policies whose number is K modulo N. Many files are parsed in several XMLs, each compared.

Alike: the app role; the types (table, key, whether they sign in, where); each relation's sources in order, with
their subjects; the permissions, as expressions (or, and, not, grouped as parentheses say, a run of ors or of ands
flat); rules and masks, and the view of a table's rules; invariants; scopes; caveats; the tests and their steps.
The grammar reads more than the parser takes, as an editor must (`a or b and c`, which the parser refuses): a
policy the parser refuses is not compared. Both read a condition's text without its -- comments.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
import xml.etree.ElementTree as ET
from collections.abc import Sequence
from typing import Any

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)
from authzlib import parse  # noqa: E402
from authzlib.parse import And, Arrow, ArrowOn, Cond, Expr, Not, Or, Policy, PolicyError, Ref, Source  # noqa: E402

Shape = Any  # a reading of a policy, as lists, tuples and dicts that compare with ==


# ----------------------------------------------------------------------
# what both readings are made into
# ----------------------------------------------------------------------
def condition(text: str) -> str:
    """A condition's text as both readings give it: its -- comments out (outside quotes), white space single."""
    out = "\n".join(parse.strip_comment(line) for line in text.split("\n"))
    return " ".join(out.split())


def flat(op: str, items: list[Shape]) -> list[Shape]:
    """a or (b or c) is a or b or c: a run of one operator, flat."""
    out: list[Shape] = []
    for x in items:
        out += x[1:] if x[0] == op else [x]
    return out


def cols(c: str | tuple[str, ...] | None) -> tuple[str, ...] | None:
    return None if c is None else (c,) if isinstance(c, str) else tuple(c)


# ----------------------------------------------------------------------
# parse.py's reading
# ----------------------------------------------------------------------
def expr_py(e: Expr) -> Shape:
    match e:
        case Or(items=items):
            return ["or", *flat("or", [expr_py(x) for x in items])]
        case And(items=items):
            return ["and", *flat("and", [expr_py(x) for x in items])]
        case Not(item=item):
            return ["not", expr_py(item)]
        case Cond(sql=sql):
            return ["cond", condition(sql)]
        case Ref(name=name):
            return ["ref", name]
        case Arrow(rel=rel, perm=perm) | ArrowOn(rel=rel, perm=perm):
            return ["arrow", rel, perm]


def source_py(s: Source) -> Shape:
    subjects = [(st, sr) for st, sr in s.subjects]
    if s.kind == "column":
        return ("column", subjects, cols(s.column), s.type_col)
    if s.kind == "table":
        where = condition(s.where) if s.where else None
        return ("table", subjects, s.table, cols(s.obj_col), cols(s.subj_col), s.type_col, where)
    return ("shared", subjects, s.shared_by, condition(s.shared_if) if s.shared_if else None)


def reading_py(pol: Policy) -> Shape:
    """parse.py's reading of the policy's own lines (not those of a file it includes)."""
    own = lambda loc: loc is None or loc.file is None
    types = {}
    for t in pol.types.values():
        if not own(t.loc):
            continue
        types[t.name] = {
            "table": t.table,
            "key": [(c, k) for c, k in t.key],
            "principal": t.principal and t.name != "user",
            "where": condition(t.where) if t.where else None,
            "relations": {
                r.name: [source_py(s) for s in r.sources if s.kind != "roles"]
                for r in t.relations.values()
                if not r.synthetic and any(s.kind != "roles" for s in r.sources)
            },
            "perms": {p.name: expr_py(p.expr) for p in t.perms.values() if not p.hidden},
            "roles": ([(st, sr) for st, sr in t.roles[0]], t.roles_from) if t.roles else None,
        }
    rules = [(r.table, r.command, tuple(r.columns), expr_py(r.expr)) for r in pol.rules if own(r.loc)]
    tests = [(None, [s.kind for s in pol.tests])] if pol.tests else []
    tests += [(sc.name, [s.kind for s in sc.steps]) for sc in pol.scenarios if sc.loc is not None and own(sc.loc)]
    return {
        "role": pol.role,
        "types": types,
        "rules": rules,
        "views": dict(pol.views),
        "invariants": [(i.type, expr_py(i.expr)) for i in pol.invariants if own(i.loc)],
        # (what the parser makes of each item, a command or a permission, is its reading alone: the words compared)
        "scopes": {s.name: [".".join(x for x in item[1:] if x) for item in s.items] for s in pol.scopes.values()},
        "caveats": {c.name: condition(c.sql) for c in pol.caveats.values()},
        "tests": tests,
    }


# ----------------------------------------------------------------------
# the grammar's reading, from `tree-sitter parse --xml`
# ----------------------------------------------------------------------
class Tree:
    """One file's tree from the XML, and the file's bytes, to take a condition's text from where it is."""

    def __init__(self, root: ET.Element, source: bytes) -> None:
        self.root, self.lines = root, source.split(b"\n")

    def text(self, e: ET.Element) -> str:
        """The source text an element covers."""
        sr, sc, er, ec = (int(e.get(k, "0")) for k in ("srow", "scol", "erow", "ecol"))
        if sr == er:
            return self.lines[sr][sc:ec].decode("utf-8")
        parts = [self.lines[sr][sc:], *self.lines[sr + 1 : er], self.lines[er][:ec]]
        return b"\n".join(parts).decode("utf-8")


def kids(e: ET.Element) -> list[ET.Element]:
    return list(e)


def field(e: ET.Element, name: str) -> ET.Element | None:
    return next((k for k in e if k.get("field") == name), None)


def need(e: ET.Element, name: str) -> ET.Element:
    """A field the grammar always gives (an element with no children is false: never `field(...) or ...`)."""
    found = field(e, name)
    if found is None:
        raise ValueError(f"{e.tag} without its {name}")
    return found


def name_of(e: ET.Element | None) -> str | None:
    """A name's text: an identifier, or schema.table (the XML puts each part, and the dot, on a line)."""
    return None if e is None else "".join("".join(e.itertext()).split())


def tokens(e: ET.Element) -> list[str]:
    """The words the grammar matched as tokens of its own (in the XML, the text between an element's children)."""
    texts: list[str] = [e.text or "", *(k.tail or "" for k in e)]
    return [word for text in texts for word in text.split()]


def sql_of(tree: Tree, e: ET.Element) -> str:
    """A {condition}'s text, without its braces."""
    text = tree.text(e).strip()
    return condition(text[1:-1] if text.startswith("{") and text.endswith("}") else text)


def expr_ts(tree: Tree, e: ET.Element) -> Shape:
    match e.tag:
        case "parenthesized":
            return expr_ts(tree, kids(e)[0])
        case "or" | "and":
            a, b = kids(e)
            return [e.tag, *flat(e.tag, [expr_ts(tree, a), expr_ts(tree, b)])]
        case "not":
            return ["not", expr_ts(tree, kids(e)[0])]
        case "sql":
            return ["cond", sql_of(tree, e)]
        case "ref":
            # signed_in, anyone and nobody are words of the language: the parser makes them conditions
            name = name_of(e) or ""
            return ["cond", parse.KEYWORDS[name]] if name in parse.KEYWORDS else ["ref", name]
        case "arrow":
            return ["arrow", name_of(field(e, "relation")), name_of(field(e, "permission"))]
    raise ValueError(f"not an expression: {e.tag}")


def subject_ts(e: ET.Element) -> tuple[str, str | None]:
    if not kids(e):  # anyone, link
        return (tokens(e)[0] if tokens(e) else (e.text or "").strip(), None)
    first = kids(e)[0]
    if first.tag in ("anyone", "link"):
        return (first.tag, None)
    if "*" in tokens(e):
        return (name_of(field(e, "type")) or "", "*")
    return (name_of(field(e, "type")) or "", name_of(field(e, "relation")))


def columns_ts(e: ET.Element) -> tuple[tuple[str, ...] | None, str | None]:
    """(the columns, the type column) of a source's column part: column, [a, b] or (type_col, ...)."""
    if e.tag == "column":
        return (name_of(e) or "",), None
    if e.tag == "columns":
        return tuple(name_of(c) or "" for c in kids(e)), None
    if e.tag == "typed_columns":
        type_col, rest = kids(e)[0], kids(e)[1]
        return columns_ts(rest)[0], name_of(type_col)
    raise ValueError(f"not columns: {e.tag}")


def source_ts(tree: Tree, rel: ET.Element) -> Shape:
    subjects = [subject_ts(k) for k in kids(rel) if k.tag == "subject"]
    last = kids(rel)[-1]
    if last.tag == "shared":
        when = next((k for k in kids(last) if k.tag == "sql"), None)
        return (
            "shared",
            subjects,
            name_of(field(last, "permission")),
            sql_of(tree, when) if when is not None else None,
        )
    if last.tag in ("column", "columns", "typed_columns"):
        c, type_col = columns_ts(last)
        return ("column", subjects, c, type_col)
    if last.tag == "table_source":
        table = name_of(field(last, "table"))
        parts = [k for k in kids(last) if k.tag in ("column", "columns", "typed_columns", "side")]
        if parts and parts[0].tag == "side":
            sides = {tokens(s)[0]: kids(s)[0] for s in parts}
            obj, (subj, type_col) = columns_ts(sides["object"])[0], columns_ts(sides["subject"])
        else:
            obj, (subj, type_col) = columns_ts(parts[0])[0], columns_ts(parts[1])
        where = next((k for k in kids(last) if k.tag == "sql"), None)
        return ("table", subjects, table, obj, subj, type_col, sql_of(tree, where) if where is not None else None)
    raise ValueError(f"not a source: {last.tag}")


def reading_ts(tree: Tree) -> Shape:
    out: Shape = {"role": None, "types": {}, "rules": [], "views": {}, "invariants": [], "scopes": {}, "caveats": {}}
    tests: list[Shape] = []
    unnamed: list[str] = []
    for top in kids(tree.root):
        match top.tag:
            case "app_role":
                out["role"] = name_of(field(top, "name"))
            case "type":
                key = next((k for k in kids(top) if k.tag == "key"), None)
                where = next((k for k in kids(top) if k.tag == "sql"), None)
                relations: dict[str, list[Shape]] = {}
                perms: dict[str, Shape] = {}
                roles = None
                for k in kids(top):
                    if k.tag == "relation":
                        relations.setdefault(name_of(field(k, "name")) or "", []).append(source_ts(tree, k))
                    elif k.tag == "permission":
                        perms[name_of(field(k, "name")) or ""] = expr_ts(tree, need(k, "expression"))
                    elif k.tag == "roles":
                        roles = ([subject_ts(s) for s in kids(k) if s.tag == "subject"], name_of(field(k, "owner")))
                out["types"][name_of(field(top, "name")) or ""] = {
                    "table": name_of(field(top, "table")),
                    "key": [(name_of(field(c, "name")) or "", name_of(field(c, "type")) or "bigint") for c in kids(key)]
                    if key is not None
                    else [("id", "bigint")],
                    "principal": any(k.tag == "principal" for k in kids(top)),
                    "where": sql_of(tree, where) if where is not None else None,
                    "relations": relations,
                    "perms": perms,
                    "roles": roles,
                }
            case "rules":
                table = name_of(field(top, "table")) or ""
                view = field(top, "view")
                if view is not None:
                    out["views"][table] = name_of(view)
                for r in (k for k in kids(top) if k.tag in ("rule", "mask")):
                    expression = expr_ts(tree, need(r, "expression"))
                    columns = tuple(name_of(c) or "" for c in kids(r) if c.tag == "column")
                    if r.tag == "mask":
                        out["rules"].append((table, "mask", columns, expression))
                    elif r.tag == "rule":
                        command = name_of(field(r, "command")) or ""
                        if "after" in tokens(r):
                            command = "update check"
                        out["rules"].append((table, command, columns, expression))
            case "invariants":
                for n in (k for k in kids(top) if k.tag == "never"):
                    out["invariants"].append((name_of(field(n, "type")), expr_ts(tree, need(n, "expression"))))
            case "scope":
                out["scopes"][name_of(field(top, "name")) or ""] = [
                    name_of(i) for i in kids(top) if i.tag == "scope_item"
                ]
            case "caveat":
                out["caveats"][name_of(field(top, "name")) or ""] = sql_of(tree, kids(top)[-1])
            case "test":
                steps = [s.tag for s in kids(top) if s.tag in ("check", "given", "as")]
                name = field(top, "name")
                if name is None:
                    unnamed += steps
                else:
                    tests.append((tree.text(name).strip().strip('"'), steps))
    out["tests"] = ([(None, unnamed)] if unnamed else []) + tests
    return out


def broken(e: ET.Element) -> bool:
    """Whether the grammar could not read some of the file (an ERROR or MISSING node)."""
    return any(x.tag in ("ERROR", "MISSING") or x.get("missing") is not None for x in e.iter())


# ----------------------------------------------------------------------
# the comparison
# ----------------------------------------------------------------------
def differences(a: Shape, b: Shape, where: str = "") -> list[str]:
    """Where two readings differ, as paths into them."""
    if isinstance(a, dict) and isinstance(b, dict):
        out = []
        for k in sorted(set(a) | set(b), key=str):
            if k not in a or k not in b:
                out.append(f"{where}/{k}: only the {'grammar' if k in b else 'parser'} has it")
            else:
                out += differences(a[k], b[k], f"{where}/{k}")
        return out
    if isinstance(a, (list, tuple)) and isinstance(b, (list, tuple)) and len(a) == len(b):
        return [d for i, (x, y) in enumerate(zip(a, b, strict=True)) for d in differences(x, y, f"{where}[{i}]")]
    return [] if a == b else [f"{where}: the parser reads {a!r}, the grammar {b!r}"]


def includes(path: str, text: str) -> dict[str, str]:
    """The files a policy includes (and they include), read from beside it."""
    files: dict[str, str] = {}
    todo = re.findall(r'^include "([^"]+)"', text, re.M)
    while todo:
        name = todo.pop()
        if name not in files and os.path.isfile(os.path.join(os.path.dirname(path), name)):
            with open(os.path.join(os.path.dirname(path), name), encoding="utf-8") as fh:
                files[name] = fh.read()
            todo += re.findall(r'^include "([^"]+)"', files[name], re.M)
    return files


def compare(xml_path: str) -> tuple[int, int, list[str]]:
    """(policies compared, policies parse.py refuses, the disagreements)."""
    compared, refused, problems = 0, 0, []
    for src in ET.parse(xml_path).getroot().iter("source"):
        path = src.get("name") or ""
        with open(path, "rb") as fh:
            data = fh.read()
        text = data.decode("utf-8")
        try:
            pol = parse.parse_policy(text, os.path.basename(path), files=includes(path, text))
        except PolicyError:
            refused += 1
            continue
        root = src.find("source_file")
        if root is None or broken(root):
            problems.append(f"{path}: the parser reads it, the grammar can't")
            continue
        compared += 1
        problems += [f"{path}{d}" for d in differences(reading_py(pol), reading_ts(Tree(root, data)))]
    return compared, refused, problems


def write(folder: str, n: int, small: int = 0, part: tuple[int, int] = (0, 1)) -> None:
    """n of genpolicy's random policies, seeds 1 to n, as folder/gen_<seed>.authz; and small.py's set up to size
    small (those whose number is part[0] modulo part[1]), each as listed and written another way."""
    import genpolicy

    os.makedirs(folder, exist_ok=True)
    texts = {f"gen_{seed}": genpolicy.policy_text(genpolicy.make(seed)) for seed in range(1, n + 1)}
    if small:
        import small as smallset

        for k, spec in enumerate(smallset.the_set(small)):
            if k % part[1] == part[0]:
                texts[f"small_{k}"] = smallset.policy_text(spec)
                texts[f"small_{k}_other"] = smallset.policy_text(smallset.respelled(spec)[0])
    for name, text in texts.items():
        with open(os.path.join(folder, f"{name}.authz"), "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)


def main(argv: Sequence[str]) -> int:
    ap = argparse.ArgumentParser(description="The grammar reads each policy as parse.py does.")
    ap.add_argument("xml", nargs="*", help="what `tree-sitter parse --xml` wrote (several: each, the counts together)")
    ap.add_argument("--write", nargs=2, metavar=("DIR", "N"), help="write N of genpolicy's policies into DIR")
    ap.add_argument("--small", type=int, default=0, metavar="SIZE", help="--write: and small.py's set up to SIZE")
    ap.add_argument("--slice", default="0/1", metavar="K/N", help="--small: those whose number is K modulo N")
    a = ap.parse_args(argv)
    if a.write:
        k, n = (int(x) for x in a.slice.split("/"))
        write(a.write[0], int(a.write[1]), a.small, (k, n))
        return 0
    if not a.xml:
        ap.error("name the XML, or --write")
    compared, refused, problems = 0, 0, []
    for xml in a.xml:
        c, r, p = compare(xml)
        compared, refused, problems = compared + c, refused + r, problems + p
    for p in problems:
        print(p)
    print(
        f"parse agreement: {compared} policies read alike by the grammar and the parser"
        f"{f', {len(problems)} differences' if problems else ''} ({refused} the parser refuses, not compared)"
    )
    return 1 if problems or not compared else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

"""Coverage: which branch of which permission no test made true.

A branch is one item of a permission's definition, as authz.explain lists them (`can edit = share or editor or
(parent.edit and {inherit})` has three). Each check that someone can do something, when it passes, brings
authz.explain's answer (testing.py, coverage=True): the items marked yes, in the permission checked and in the
ones it reached (the first yes of each is explained in depth). A branch no answer marks yes is one no test
reaches: a way to access that nothing checks.

A permission with a deny inside inheritance (`(owner or parent.view) and not hidden`) is compiled as a hidden
permission, its `or` part, and the deny on it (split_denies). Its branches are that part's (`owner`,
`parent.view`), which explain lists under the hidden permission.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from typing import TYPE_CHECKING, TypedDict

from .insight import expr_text
from .parse import Expr

if TYPE_CHECKING:
    from . import Compiler

HEADER = re.compile(r"^( *)(\w+)\.(\w+) = ")
ITEM = re.compile(r"^( *)(yes|no) +(.*)$")


class Report(TypedDict):
    total: int  # branches of the public permissions
    covered: int  # of those, the ones a passing check made true
    missing: list[tuple[str, str, str]]  # the others: (line, "type.perm", item)


def item_text(node: Expr) -> str:
    """An item as authz.explain writes it."""
    return expr_text(node).replace("__base", " (before the deny)")


def shown(text: str) -> str:
    """An item as the policy writes it."""
    return text.replace(" (before the deny)", "")


def branches(c: Compiler) -> list[tuple[str, str, str, str, str]]:
    """[(type, permission, item text, line, the permission explain lists it under)] for every public permission
    of the compiled policy."""
    out = []
    for t in c.types.values():
        for name in c.public_perms(t):
            p = t.perms[name]
            listed = t.perms[p.base] if p.base else p
            for item in c.top_items(listed):
                out.append((t.name, name, item_text(item), str(p.loc), listed.name))
    return out


def covered(explanations: Iterable[str | None]) -> set[tuple[str, str, str]]:
    """The (type, permission, item text) marked yes in authz.explain's answers."""
    out: set[tuple[str, str, str]] = set()
    for text in explanations:
        headers: dict[int, tuple[str, str]] = {}
        for line in (text or "").split("\n"):
            m = HEADER.match(line)
            if m:
                indent = len(m.group(1))
                headers = {k: v for k, v in headers.items() if k < indent}
                headers[indent] = (m.group(2), m.group(3))
                continue
            m = ITEM.match(line)
            if m and m.group(2) == "yes" and len(m.group(1)) in headers:
                out.add(headers[len(m.group(1))] + (m.group(3).strip(),))
    return out


def report(c: Compiler, explanations: Iterable[str | None]) -> Report:
    """How many branches the checks made true, and the ones they didn't."""
    all_ = branches(c)
    hit = covered(explanations)
    missing = [(line, f"{t}.{p}", shown(item)) for t, p, item, line, listed in all_ if (t, listed, item) not in hit]
    return {"total": len(all_), "covered": len(all_) - len(missing), "missing": missing}


def describe(r: Report) -> str:
    if not r["total"]:
        return "coverage: no permissions"
    head = f"coverage: {r['covered']} of {r['total']} branches made true by a test"
    if not r["missing"]:
        return head + " (all of them)"
    return (
        head
        + '; no "can" check reaches:\n'
        + "\n".join(f"  {line}: {name}: {item}" for line, name, item in r["missing"])
    )


def summary(r: Report, limit: int = 2) -> str:
    """For rowstile dev's line: '2 branches no "can" check reaches (line 18: org.admin, line 40: {not locked})'.
    It names the checks that count: a statement run `as` someone passes and covers nothing."""
    if not r["missing"]:
        return ""
    short: Callable[[str], str] = lambda item: (
        item if len(item) <= 32 else item[:29] + "..." + ("}" if item.startswith("{") else "")
    )
    shown = ", ".join(f"{line}: {short(item)}" for line, _, item in r["missing"][:limit])
    n = len(r["missing"])
    return f'{n} branch{"es" if n != 1 else ""} no "can" check reaches ({shown}{", ..." if n > limit else ""})'

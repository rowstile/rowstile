"""rowstile review: what a policy change does, for the pull request.

A reviewer who has never read the policy should understand the change from the review alone:

- Meaning: what the rules say now, entity by entity, and every permission that changes through something it
  uses. A change of text only (a refactor) is checked in many small worlds (evaluate.py) and then says
  "Meaning unchanged" and nothing else.
- Access: who gains and who loses what on the review data (a database the caller prepared: the base
  branch's migrations and review data), with an example and how it is granted.
- Risk: what to look at twice, each on its policy line (also as annotations).
- Tests: what the author claims: checks whose expectation flipped, checks removed (a test that only changed
  its name is said so, and its checks compared under the new one), new permissions no test names; with a
  database, the tests of the pull request run on it.
- Deploy: the migrations the change needs, their statements, the tables they lock, the trees they rebuild.

Everything is computed from the two policies (and a database for Access and the tests' results); review()
returns a Review, and markdown(), text() and annotations() write it out.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from typing import NotRequired, TypeAlias, TypedDict

from . import Compiler, PolicyError, migrate, parse_policy
from .conditions import simple
from .connection import Db
from .evaluate import FOLLOWS, Difference, Listing, Reference, compare, worlds_to_try
from .parse import KEYWORDS, Expr, Loc, Perm, Policy, Rule, Type, read_lines
from .statements import split

MARK = "<!-- rowstile review -->"


WIDE = ("anyone", "link")
# who an example is about when nobody is signed in (as the comparison's examples say it too)
NOBODY = "(nobody signed in)"


# --- what review() returns (as JSON too: rowstile review --json) ------------------------------------
class Changed(TypedDict):
    what: str  # the entity's key: 'folder.edit', 'rule app.folders update', ...
    before: str | None
    after: str | None
    line: str | None
    kind: str  # added | removed | changed
    entity: str  # type | relation | permission | rule | scope | caveat | invariant | declaration


class Through(TypedDict):
    what: str
    via: list[str]  # the changed entities it uses
    line: str


class Meaning(TypedDict):
    changed: list[Changed]
    through: list[Through]
    equivalent: str | None  # 'text', or 'N small worlds and M listed: ...' for a refactor that grants the same
    counterexample: NotRequired[Difference]
    # what changed only in conditions the review can't read (a subquery, a function): it can't tell more or less
    unreadable: NotRequired[list[str]]


class Flag(TypedDict):
    flag: str
    line: str | None
    what: str
    why: str


class Flipped(TypedDict):
    test: str
    before: str
    after: str
    line: str


class Removed(TypedDict):
    test: str
    check: str


class Added(TypedDict):
    test: str
    check: str
    line: str


class Renamed(TypedDict):
    before: str
    after: str


class Untested(TypedDict):
    what: str
    line: str


class Unread(TypedDict):
    file: str
    error: str


class Failed(TypedDict):
    test: str
    line: str | None
    detail: str | None


class TestRun(TypedDict):
    error: NotRequired[str]  # the migration failed, so nothing ran
    checks: NotRequired[int]
    failed: NotRequired[list[Failed]]


class Tests(TypedDict):
    flipped: list[Flipped]
    removed: list[Removed]
    added: list[Added]
    renamed: list[Renamed]
    untested: list[Untested]
    unread: list[Unread]
    invariants_removed: list[str]
    count: int
    run: NotRequired[TestRun]


class Lock(TypedDict):
    mode: str
    why: str


class DeployMigration(TypedDict):
    statements: int
    bytes: int
    locks: dict[str, Lock]
    rebuilds: list[str]
    builds_beside: list[str]
    swaps_in: list[str]


class OnReviewData(TypedDict):
    seconds: float | None
    error: str | None


class Deploy(TypedDict):
    migrations: list[DeployMigration]
    lock_current: bool | None
    error: NotRequired[str]
    no_lock: NotRequired[bool]  # no lock file on either side: the project applies the policy, it keeps no migrations
    on_review_data: NotRequired[OnReviewData]


class Example(TypedDict):
    user: str  # as the review data writes it: a user's id, type:id for another principal, or NOBODY
    who: str  # in words: 'user 3', 'bot 7', 'nobody signed in'
    id: str
    how: NotRequired[str]


class Group(TypedDict):
    change: str  # gains | loses
    type: str
    what: str
    users: int  # how many: users, other principals and someone not signed in
    who: str  # who they are, in words: '2 users and 1 bot'
    objects: int
    examples: list[Example]


class Access(TypedDict):
    groups: list[Group]
    users_in_data: int | None
    error: NotRequired[str]


class BaseMistake(TypedDict):
    """The base's policy has a mistake, so the head was reviewed as new: where (the base's line), what, its code."""

    line: str | None  # 'line 12', 'roles.authz line 3' (as the base has it); None: the whole policy's
    message: str
    code: str | None


class Review(TypedDict):
    meaning: Meaning
    risk: list[Flag]
    tests: Tests
    deploy: Deploy
    access: Access | None
    # the base is in the language before this one: each old form it was read with, where, and what it is now
    base_previous: NotRequired[list[str]]
    # the base's policy has a mistake: the head is reviewed as new, as where the base has no policy
    base_mistake: NotRequired[BaseMistake]


# (policy text, included files, named tests {name: text}) of one side of the change
Given: TypeAlias = "tuple[str, dict[str, str] | None, dict[str, str] | None]"


# --- the policy's entities -------------------------------------------------------------------------
def squeeze(s: str) -> str:
    """One space for each run of spaces, outside quotes ('...', "..." and $$...$$, the dollar quote a condition may
    use): 'a  b' in a condition is another text than 'a b'."""
    out: list[str] = []
    quote = ""
    s = s.strip()
    i = 0
    while i < len(s):
        ch = "$$" if s.startswith("$$", i) else s[i]
        i += len(ch)
        if quote:
            if ch == quote:
                quote = ""
        elif ch in ("'", '"', "$$"):
            quote = ch
        elif ch.isspace():
            if out[-1] != " ":  # (never the first: s is stripped)
                out.append(" ")
            continue
        out.append(ch)
    return "".join(out)


def entities(policy: str, files: dict[str, str] | None, pol: Policy) -> dict[str, tuple[str, Loc]]:
    """{key: (text, line)}: each declaration of the policy (pol: as parsed), its text normalized, and where it is
    written. Keys: 'type folder', 'folder.editor' (a relation: its sources joined), 'folder.edit' (a permission),
    'rule app.folders update', 'scope read', 'caveat x', 'app role', 'invariant <text>'. Tests are left out."""
    # a rule by its head as read (rule_head): `update a,b before` is `update a, b`, as the rest of the review names it
    heads = {r.loc: rule_head(r) for r in pol.rules}
    out: dict[str, tuple[str, Loc]] = {}
    block: tuple[str, str | None] | None = None
    skip = False
    for loc, indent, s in read_lines(None, policy, files=files or {}):
        s = squeeze(s)
        if indent == 0:
            skip = s == "test" or s.startswith("test ")
            if skip:
                continue
            m = re.match(r"type\s+(\w+)", s)
            if m:
                block = ("type", m.group(1))
                out[f"type {m.group(1)}"] = (s, loc)
                continue
            m = re.match(r"rules\s+(\S+)", s)
            if m:
                block = ("rules", m.group(1))
                if " view " in f" {s} ":
                    out[f"view {m.group(1)}"] = (s, loc)
                continue
            if s == "invariants":
                block = ("invariants", None)
                continue
            block = None
            m = re.match(r"(scope|caveat)\s+([\w:-]+)", s)
            if m:
                out[f"{m.group(1)} {m.group(2)}"] = (s, loc)
            else:  # the parser takes no other line here (`role x`: how a policy said it before `app role`)
                assert s.startswith(("app role ", "role ")), s
                out["app role"] = ("app role " + s.split()[-1], loc)
            continue
        if skip or block is None:
            continue
        kind, name = block
        if kind == "type":
            m = re.match(r"can\s+(\w+)\s*=\s*(.*)$", s)
            if m:
                out[f"{name}.{m.group(1)}"] = (m.group(2), loc)
                continue
            m = re.match(r"(\w+)\s*:\s*(.*)$", s)
            assert m, s  # (the parser reads every other line of a type as a relation, roles too: name : ...)
            key, said = f"{name}.{m.group(1)}", m.group(2)
            if m.group(1) == "roles":  # (`roles : user grant view, edit`: before `roles` in the permissions)
                said = re.sub(r"\s+grant\s+.*?(?=\s+from\s+\w+$|$)", "", said)
            prev = out.get(key)
            out[key] = ((prev[0] + "; " if prev else "") + said, prev[1] if prev else loc)
        elif kind == "rules":
            out[f"rule {name} {heads[loc]}"] = (s.partition(":")[2].strip(), loc)
        else:  # invariants
            out[f"invariant {s}"] = (s, loc)
    return out


def uses(pol: Policy) -> dict[tuple[str, str], set[tuple[str, str]]]:
    """{(type, name): {(type, name) it reads}}: what each relation and permission is computed from."""
    graph: dict[tuple[str, str], set[tuple[str, str]]] = {}
    for t in pol.types.values():
        for name in list(t.relations) + list(t.perms):
            graph[(t.name, name)] = set()

    def walk(t: Type, node: Expr, out: set[tuple[str, str]]) -> None:
        match node:
            case ("ref", name):
                out.add((t.name, name))
            case ("arrow", rel, perm):
                out.add((t.name, rel))
                for st, sr in t.relations[rel].subjects():
                    assert sr is None and st in pol.types, FOLLOWS
                    out.add((st, perm))
            case ("not", item):
                walk(t, item, out)
            case ("and", items) | ("or", items):
                for x in items:
                    walk(t, x, out)

    for t in pol.types.values():
        for p in t.perms.values():
            walk(t, p.expr, graph[(t.name, p.name)])
        for r in t.relations.values():
            for src in r.sources:
                for st, sr in src.subjects:
                    if sr and sr != "*" and st in pol.types:
                        graph[(t.name, r.name)].add((st, sr))
    return graph


def closure(graph: dict[tuple[str, str], set[tuple[str, str]]], start: tuple[str, str]) -> set[tuple[str, str]]:
    seen: set[tuple[str, str]] = set()
    todo = [start]
    while todo:
        x = todo.pop()
        for y in graph.get(x, ()):
            if y not in seen:
                seen.add(y)
                todo.append(y)
    return seen


# --- the review --------------------------------------------------------------------------------------
def mistake_of(e: PolicyError) -> BaseMistake:
    """A policy's mistake as the review reports it: 'line 12: message [AZ203]' -> its line, message and code."""
    code = e.code
    text = str(e).removesuffix(f" [{code}]")
    m = re.match(r"((?:\S+ )?line \d+): (.*)$", text, re.S)
    return {"line": m.group(1) if m else None, "message": m.group(2) if m else text, "code": code}


def written_before(policy: str, files: dict[str, str] | None) -> bool:
    """Whether a policy is written in the language before this one: read that way, it has old forms."""
    try:
        return bool(parse_policy(policy, None, files=files or {}, previous=True).previous)
    except PolicyError:
        return False


class Side:
    def __init__(
        self, policy: str, files: dict[str, str] | None, tests: dict[str, str] | None, previous: bool = False
    ) -> None:
        """previous: read in the language before this one (parse_policy), for a base this one refuses."""
        self.policy, self.files, self.tests, self.previous = policy, files or {}, tests or {}, previous
        self.pol = parse_policy(policy, None, files=self.files, previous=previous)
        # what `rowstile check` refuses is refused here, with its message: the rest reads a policy that compiles, as
        # written (a copy is compiled: compiling changes the policy it is given, and adds permissions of its own)
        copy = parse_policy(policy, None, files=self.files, previous=previous)
        Compiler(copy).compile("the policy", transaction=False)
        self.pol.previous = copy.previous  # (with what compiling read the old way too)
        self.entities = entities(policy, self.files, self.pol)


def review(
    base: Given | None,
    head: Given,
    base_lock: str | None = None,
    head_lock: str | None = None,
    db: Db | None = None,
    worlds: int = 200,
) -> Review:
    """base, head: (policy text, files, tests {name: text}); base None: there is no policy at the base, the pull
    request adds it. base_lock/head_lock: the lock files' text (for Deploy). db: a database at the base branch's
    state with the review data (for Access and Tests). A base this language refuses is read in the one before (a
    pull request that upgrades rowstile, and rewrites the policy for it): Meaning then says whether the rewrite says
    the same. A base neither reads has a mistake: the head is reviewed as new, and base_mistake says so (the pull
    request that fixes the mistake is reviewed all the same)."""
    mistake: BaseMistake | None = None
    b: Side | None = None
    if base is not None:
        try:
            b = Side(*base)
        except PolicyError as e:
            try:
                b = Side(*base, previous=True)
            except PolicyError as old:
                # the mistake as the language it is written in says it: this one would only name its old forms
                mistake = mistake_of(old if written_before(base[0], base[1]) else e)
    h = Side(*head)
    if b is None:
        # a new policy: compared with one that allows nothing, in the head's own app role and user type (made up
        # ones would read as changed), and each of its declarations listed as added
        b = Side("\n".join(h.entities[k][0] for k in ("app role", "type user") if k in h.entities) + "\n", None, None)
        b.entities = {}
    unread = unread_tests(h)
    said = meaning(b, h, worlds)
    flags = risk(b, h, worlds, said.get("counterexample"))
    if said["equivalent"] not in (None, "text") and any(f["why"] in ALLOWS_MORE for f in flags):
        said = meaning(b, h, worlds, refactor=False)  # Risk found an example the comparison's worlds didn't
    out: Review = {
        "meaning": said,
        "risk": flags,
        "tests": tests(b, h, unread),
        "deploy": deploy(b, h, base_lock, head_lock),
        "access": access(db, h) if db is not None else None,
    }
    if b.pol.previous is not None:
        out["base_previous"] = b.pol.previous
    if mistake is not None:
        out["base_mistake"] = mistake
    if db is not None:
        from . import database

        wanted = [
            (as_given(e["user"], h.pol), g["type"], e["id"], g["what"][11:])
            for g in (out["access"] or {}).get("groups", [])
            if g["change"] == "gains" and g["what"].startswith("permission ")
            for e in g["examples"][:2]
        ]
        # the test files it can't read are named under Tests, not run: one would stop them all
        named = {f["file"] for f in unread}
        runnable = {name: body for name, body in h.tests.items() if name not in named}
        ran = database.review_run(db, h.policy, h.files, runnable, base_lock, wanted)
        for g in (out["access"] or {}).get("groups", []):
            for e in g["examples"]:
                how = ran["how"].get((as_given(e["user"], h.pol), g["type"], e["id"], g["what"][11:]))
                if how:
                    e["how"] = ", ".join(x.removeprefix("yes").strip() for x in how)
        out["deploy"]["on_review_data"] = {"seconds": ran["deployed"], "error": ran["error"]}
        run: TestRun = (
            # without a lock file the policy is applied whole, as the project does (database.review_run)
            {"error": f"{'the migration fails' if base_lock else 'applying the policy fails'}: {ran['error']}"}
            if ran["error"]
            else {
                "checks": len(ran["tests"]),
                "failed": [{"test": t, "line": ln, "detail": d} for t, ln, ok, d in ran["tests"] if not ok],
            }
        )
        out["tests"]["run"] = run
    return out


def changes(b: Side, h: Side) -> list[Changed]:
    """Each declaration whose text differs between the two sides, in the head's order."""
    changed: list[Changed] = []
    for key in sorted(set(b.entities) | set(h.entities), key=lambda k: ((h.entities.get(k) or b.entities[k])[1], k)):
        before = b.entities.get(key, (None, None))[0]
        after, loc = h.entities.get(key, (None, b.entities.get(key, (None, None))[1]))
        if before != after:
            changed.append(
                {
                    "what": key,
                    "before": before,
                    "after": after,
                    "line": str(loc) if key in h.entities else None,
                    "kind": "added" if before is None else "removed" if after is None else "changed",
                    "entity": entity_kind(key, b.pol, h.pol),
                }
            )
    return changed


def declared(pol: Policy, what: str) -> Perm | Rule | None:
    """A permission ('type.perm') or a rule ('rule table command [columns]') of a policy, by its key."""
    if what.startswith("rule "):
        return {f"rule {r.table} {rule_head(r)}": r for r in pol.rules}.get(what)
    m = re.match(r"^(\w+)\.(\w+)$", what)
    if m and m.group(1) in pol.types and m.group(2) in pol.types[m.group(1)].perms:
        return pol.types[m.group(1)].perms[m.group(2)]
    return None


def expr_of(side: Side, what: str) -> Expr | None:
    """The expression of a permission ('type.perm') or a rule ('rule table command [columns]') on one side."""
    found = declared(side.pol, what)
    return found.expr if found is not None else None


def unreadable_pairs(b: Expr, h: Expr) -> list[tuple[str, str]] | None:
    """When two expressions have one shape and differ only in conditions the review can't read (a subquery, a
    function: conditions.simple reads neither; signed_in, anyone and nobody it reads), those conditions, before
    and after. The small worlds hold such a condition as rows of its own, chosen per world, so two texts are two
    unrelated sets there: the worlds can't say whether the change gives more or less. None when they differ in
    anything else."""

    def unread(sql: str) -> bool:
        return simple(sql) is None and sql not in KEYWORDS.values()

    match b, h:
        case (("cond", sb), ("cond", sh)):
            if squeeze(sb) == squeeze(sh):
                return []
            return [(sb, sh)] if unread(sb) and unread(sh) else None
        case (("not", ib), ("not", ih)):
            return unreadable_pairs(ib, ih)
        case (("and", ib), ("and", ih)) | (("or", ib), ("or", ih)):
            if len(ib) != len(ih):
                return None
            out: list[tuple[str, str]] = []
            for x, y in zip(ib, ih, strict=True):
                pairs = unreadable_pairs(x, y)
                if pairs is None:
                    return None
                out += pairs
            return out
    return [] if b == h else None


def unreadable_changes(b: Side, h: Side, changed: list[Changed]) -> dict[str, list[tuple[str, str]]]:
    """The permissions and rules that changed only in conditions the review can't read, with those conditions."""
    out: dict[str, list[tuple[str, str]]] = {}
    for c in changed:
        eb, eh = (expr_of(b, c["what"]), expr_of(h, c["what"])) if c["kind"] == "changed" else (None, None)
        pairs = unreadable_pairs(eb, eh) if eb is not None and eh is not None else None
        if pairs:
            out[c["what"]] = pairs
    return out


def as_read(b: Side, h: Side, unreadable: dict[str, list[tuple[str, str]]]) -> Policy:
    """The head's policy as the small worlds compare it with the base's: what changed only in conditions the review
    can't read (unreadable) is as the base wrote it. A world draws the rows such a condition holds for by its text,
    so a reworded one holds for other rows there whatever it says, and what reads it differs there too: a difference
    the review would make up. Those changes are said to be beyond it; everything else is compared."""
    if not unreadable:
        return h.pol
    pol = parse_policy(h.policy, None, files=h.files)
    for what in unreadable:
        mine, theirs = declared(pol, what), declared(b.pol, what)
        assert mine is not None and theirs is not None, what  # unreadable_changes compared the two
        mine.expr = theirs.expr
    return pol


def meaning(b: Side, h: Side, worlds: int, refactor: bool = True) -> Meaning:
    changed = changes(b, h)
    out: Meaning = {"changed": changed, "through": [], "equivalent": None}
    if not changed:
        out["equivalent"] = "text"  # comments, spacing, order: the declarations are the same
        return out
    # a refactor: only permissions and rules changed, and they grant the same in every small world tried
    refactor = (
        refactor
        and all(
            re.match(r"^(\w+)\.(\w+)$", c["what"])
            and c["kind"] == "changed"
            and c["what"].split(".")[1] in b.pol.types[c["what"].split(".")[0]].perms
            if c["what"].split(".")[0] in b.pol.types
            else False
            for c in changed
            if not c["what"].startswith("rule ")
        )
        and all(
            c["kind"] == "changed" and " mask " not in f" {c['what']} "
            for c in changed
            if c["what"].startswith("rule ")
        )
    )
    unreadable = unreadable_changes(b, h, changed)
    if unreadable:
        out["unreadable"] = sorted(unreadable)
    if refactor:
        head = as_read(b, h, unreadable)
        listing = Listing((b.pol, head))
        found = compare(b.pol, head, worlds=worlds, listing=listing)
        if found is None and not unreadable:
            out["equivalent"] = f"{worlds} small worlds and {listing.said()}"
            return out
        if found is not None:
            # a rule named as the policy writes it (compare says `update check` for `after`)
            names = {
                f"rule {r.table} {r.command}" + (f" {', '.join(r.columns)}" if r.columns else ""): (
                    f"rule {r.table} {rule_head(r)}"
                )
                for r in h.pol.rules
            }
            found["what"] = names.get(found["what"], found["what"])
            out["counterexample"] = found
    # what changes through something it uses
    graph = uses(h.pol)
    direct = {tuple(c["what"].split(".")) for c in changed if re.match(r"^\w+\.\w+$", c["what"])}
    for t in h.pol.types.values():
        for p in t.perms.values():
            if (t.name, p.name) in direct:
                continue
            via = sorted(f"{a}.{n}" for a, n in closure(graph, (t.name, p.name)) & direct)
            if via:
                out["through"].append({"what": f"{t.name}.{p.name}", "via": via, "line": str(p.loc)})
    governing: dict[str, Type] = {}  # a rule's table, its type's (AZ401: one type governs it)
    for t in h.pol.types.values():
        governing.setdefault(t.table, t)
    for r in h.pol.rules:
        if r.command == "mask":
            continue
        key = f"rule {r.table} {rule_head(r)}"
        if any(c["what"] == key for c in changed):
            continue
        t = governing[r.table]
        reads: set[tuple[str, str]] = set()
        _walk_rule(t, r.expr, reads, h.pol)
        hit: set[tuple[str, str]] = set()
        for x in reads:
            hit |= ({x} | closure(graph, x)) & direct
        if hit:
            out["through"].append({"what": key, "via": sorted(f"{a}.{n}" for a, n in hit), "line": str(r.loc)})
    return out


def entity_kind(key: str, *pols: Policy) -> str:
    m = re.match(r"^(\w+)\.(\w+)$", key)
    if m:
        return (
            "permission"
            if any(m.group(2) in pol.types[m.group(1)].perms for pol in pols if m.group(1) in pol.types)
            else "relation"
        )
    word = key.split()[0]
    return word if word in ("type", "rule", "scope", "caveat", "invariant") else "declaration"


def rule_head(r: Rule) -> str:
    cmd = "update" if r.command == "update check" else r.command
    cols = (" " + ", ".join(r.columns)) if r.columns else ""
    return f"{cmd}{cols}{' after' if r.command == 'update check' else ''}"


def _walk_rule(t: Type, node: Expr, out: set[tuple[str, str]], pol: Policy) -> None:
    match node:
        case ("ref", name):
            out.add((t.name, name))
        case ("arrow", rel, perm):
            for st, sr in t.relations[rel].subjects():
                assert sr is None and st in pol.types, FOLLOWS
                out.add((st, perm))
        case ("not", item):
            _walk_rule(t, item, out, pol)
        case ("and", items) | ("or", items):
            for x in items:
                _walk_rule(t, x, out, pol)


# --- risk --------------------------------------------------------------------------------------------
def subjects_of(pol: Policy) -> dict[tuple[str, str], set[tuple[str, str | None, str, str | None]]]:
    """{(type, relation): {(subject type, subject relation, source kind, the permission sharing needs)}}."""
    out: dict[tuple[str, str], set[tuple[str, str | None, str, str | None]]] = {}
    for t in pol.types.values():
        for r in t.relations.values():
            for src in r.sources:
                for st, sr in src.subjects:
                    out.setdefault((t.name, r.name), set()).add(
                        (st, sr, src.kind, src.shared_by or ("share" if src.kind == "shared" else None))
                    )
    return out


def nots(node: Expr) -> list[Expr]:
    match node:
        case ("not", _):
            return [node]
        case ("and", items) | ("or", items):
            return [n for x in items for n in nots(x)]
    return []


def arrows(node: Expr) -> set[tuple[str, str]]:
    match node:
        case ("arrow", rel, perm):
            return {(rel, perm)}
        case ("not", item):
            return arrows(item)
        case ("and", items) | ("or", items):
            return {a for x in items for a in arrows(x)}
    return set()


# the flags that say the head grants something the base didn't, with an example
ALLOWS_MORE = (
    "a permission widened",
    "a write rule loosened",
    "a select rule loosened",
    "break_glass given to more people",
    "a rule added",
    "a permission widened through what it uses",
    "a rule loosened through what it uses",
    "a type's where loosened",
)


def grants_more(base: Policy, head: Policy, whats: list[str], worlds: int) -> dict[str, tuple[str, str]]:
    """For each of whats ('type.perm', or 'rule table command [columns]': a rule of the head) where, in some small
    world, the head grants something the base didn't: (who, the object). A rule the base doesn't have allowed
    nobody."""
    ref_b, ref_h = Reference(base), Reference(head)
    rules_b = {f"rule {r.table} {rule_head(r)}": r for r in base.rules}
    rules_h = {f"rule {r.table} {rule_head(r)}": r for r in head.rules}
    left = list(whats)
    found: dict[str, tuple[str, str]] = {}
    for w in worlds_to_try((base, head), worlds, "risk"):
        if not left:
            break
        db_, dh = w.data(base), w.data(head)
        for user in w.principals((base, head)):
            sb, sh = ref_b.evaluate(db_, user, ("tok1",)), ref_h.evaluate(dh, user, ("tok1",))
            for what in list(left):
                if what.startswith("rule "):
                    rh, rb = rules_h[what], rules_b.get(what)
                    more = ref_h.rule(sh, rh) - (ref_b.rule(sb, rb) if rb else set())
                    tname = ref_h.type_of_table(rh.table).name
                else:
                    tname, p = what.split(".")
                    more = set(sh.get((tname, p), ())) - set(sb.get((tname, p), ()))
                if more:
                    found[what] = (named(user), f"{tname} {sorted(more)[0]}")
                    left.remove(what)
    return found


def named(user: str) -> str:
    """Who an example is about, in words: user 1, service 3, nobody signed in ('' or, as an example and the
    comparison write it, '(nobody signed in)')."""
    if user in ("", NOBODY):
        return "nobody signed in"
    return user.replace(":", " ") if ":" in user else f"user {user}"


def principal(user: str, pol: Policy) -> tuple[str, str] | None:
    """Who an id of the review data is: (type, id), None for someone not signed in. The data writes a user by
    their id alone, which may hold a ':' too, and another principal as type:id (a type of pol that signs in)."""
    if user in ("", NOBODY):
        return None
    kind, sep, pid = user.partition(":")
    other = pol.types.get(kind)
    return (kind, pid) if sep and other is not None and other.principal and kind != "user" else ("user", user)


def words(user: str, pol: Policy) -> str:
    """An id of the review data in words: 'user 3', 'bot 7', 'nobody signed in'."""
    p = principal(user, pol)
    return " ".join(p) if p else "nobody signed in"


def as_given(user: str, pol: Policy) -> str:
    """An id of the review data as --as writes it, for database.review_run: 'user:3', 'bot:7', '' for nobody."""
    p = principal(user, pol)
    return ":".join(p) if p else ""


def who_of(ids: Iterable[str], pol: Policy) -> str:
    """Who a group of Access is about, in words: '2 users', '1 user and 1 bot', 'someone not signed in' (ids: as
    the review data writes them, principal())."""
    kinds: dict[str, int] = {}
    for i in ids:
        p = principal(i, pol)
        kind = p[0] if p else ""
        kinds[kind] = kinds.get(kind, 0) + 1
    said = [plural(n, k) for k, n in sorted(kinds.items(), key=lambda kn: (kn[0] != "user", kn[0])) if k]
    said += ["someone not signed in"] if "" in kinds else []
    return ", ".join(said[:-1]) + " and " + said[-1] if len(said) > 1 else said[0]


def risk(b: Side, h: Side, worlds: int, seen: Difference | None = None) -> list[Flag]:
    """seen: Meaning's example of a difference (evaluate.compare's), from worlds of its own: one where the head
    grants what the base didn't is one more widening found."""
    flags: list[Flag] = []

    def line(key: str) -> str | None:
        return str(h.entities[key][1]) if key in h.entities else None

    def flag(text: str, key: str, why: str) -> None:
        flags.append({"flag": text, "line": line(key), "what": key, "why": why})

    sb, sh = subjects_of(b.pol), subjects_of(h.pol)
    for key, subs in sorted(sh.items()):
        old = sb.get(key, set())
        name = f"{key[0]}.{key[1]}"
        for st, sr, kind, _ in sorted(subs - old, key=repr):
            if st in WIDE or sr == "*":
                who = st if st in WIDE else f"{st}:*"
                flag(f"`{name}` now reaches {who}" + (" (shared)" if kind == "shared" else ""), name, "access widened")
        old_by = {k_by for _, _, k, k_by in old if k == "shared"}
        new_by = {k_by for _, _, k, k_by in subs if k == "shared"}
        if not old_by:  # once, however many kinds of subjects it may be shared with
            for by in sorted(new_by, key=repr):
                flag(f"`{name}` is newly shared (by whoever holds `{by}`)", name, "a relation newly shared")
        if old_by and new_by and old_by != new_by:
            flag(
                f"`{name}` is now shared by `{', '.join(sorted(new_by))}` (was `{', '.join(sorted(old_by))}`)",
                name,
                "sharing needs another permission",
            )
        if not old and key[0] in b.pol.types:
            targets = {st for st, sr, _, _ in subs if st in h.pol.types and sr is None}
            reached = {st for (tn, _), s in sb.items() if tn == key[0] for st, sr, _, _ in s if sr is None}
            for st in sorted(targets - reached):
                flag(f"`{name}` is a new way from {key[0]} to {st}", name, "a new way to reach a type")
    for t in h.pol.types.values():
        bt = b.pol.types.get(t.name)
        for p in t.perms.values():
            key = f"{t.name}.{p.name}"
            bp = bt.perms.get(p.name) if bt else None
            if bt is None or bp is None:
                continue
            before, after = nots(bp.expr), nots(p.expr)
            if len(after) < len(before):
                flag(f"`{key}` has a deny fewer (`not` {len(before)} -> {len(after)})", key, "a deny removed")
            new_paths = arrows(p.expr) - arrows(bp.expr)
            for rel, perm in sorted(new_paths):
                flag(f"`{key}` now follows `{rel}.{perm}`", key, "a new inheritance path")
    # what allows more than before, with an example from a small world: permissions and rules whose own text
    # changed, rules that are new, what changes through a relation that changed, and everything when a type's
    # where changed (the rows that count are more)
    changed = changes(b, h)
    own: list[str] = []
    for c in changed:
        what = c["what"]
        is_rule = what.startswith("rule ") and " mask " not in f" {what} "
        if c["kind"] == "removed":
            if what.startswith("rule ") and (not is_rule or re.search(r"rule \S+ update \w", what)):
                flag(
                    f"{'the mask' if not is_rule else 'the column rule'} `{what[5:]}` is removed",
                    what,
                    "a mask or column rule removed",
                )
            if what.startswith("invariant "):
                flag(f"the invariant `{what[10:]}` is removed", what, "an invariant removed")
            continue
        is_perm = (
            bool(re.match(r"^(\w+)\.(\w+)$", what))
            and what.split(".")[0] in h.pol.types
            and what.split(".")[1] in h.pol.types[what.split(".")[0]].perms
        )
        if c["kind"] == "changed" and (is_perm or is_rule):
            own.append(what)
        # a new rule on a table that had rules: nobody could, now some can (a new column rule only narrows)
        if (
            c["kind"] == "added"
            and is_rule
            and len(what.split()) == 3
            and any(r.table == what.split()[1] and r.command != "mask" for r in b.pol.rules)
        ):
            own.append(what)
        if c["kind"] == "changed" and what.startswith("scope "):
            flag(f"`{what}` changed: `{c['before']}` -> `{c['after']}`", what, "a scope changed")
        if c["kind"] == "changed" and what.startswith("rule ") and not is_rule:
            flag(f"the mask `{what[5:]}` changed", what, "a mask changed")
    through = {t["what"]: t["via"] for t in meaning(b, h, 0, refactor=False)["through"]} if changed else {}
    wheres = [
        t.name
        for t in h.pol.types.values()
        if t.name in b.pol.types and b.pol.types[t.name].where and b.pol.types[t.name].where != t.where
    ]
    everything = (
        [
            f"{t.name}.{p.name}"
            for t in h.pol.types.values()
            for p in t.perms.values()
            if t.name in b.pol.types and p.name in b.pol.types[t.name].perms
        ]
        + [f"rule {r.table} {rule_head(r)}" for r in h.pol.rules if r.command != "mask" and not r.columns]
        if wheres
        else []
    )
    unreadable = unreadable_changes(b, h, changed)
    for what, pairs in unreadable.items():
        flag(
            f"`{what[5:] if what.startswith('rule ') else what}`: a condition the review can't read changed "
            + ", ".join(f"(`{{{x}}}` -> `{{{y}}}`)" for x, y in pairs)
            + ": read both, it can't tell more from less",
            what,
            "a condition it can't read changed",
        )
    own = [w for w in own if w not in unreadable]
    through = {w: via for w, via in through.items() if not all(v in unreadable for v in via)}
    more = grants_more(b.pol, as_read(b, h, unreadable), list(dict.fromkeys([*own, *through, *everything])), worlds)
    if seen is not None and seen["after"] and not seen["before"]:
        types = {t.table: t.name for t in h.pol.types.values()}  # a rule's row is one of its table's type
        tname = types[seen["what"].split()[1]] if seen["what"].startswith("rule ") else seen["what"].split(".")[0]
        more.setdefault(seen["what"], (named(seen["user"]), f"{tname} {seen['object']}"))
    kinds = {c["what"]: c["kind"] for c in changed}
    for what in own:
        if what not in more:
            continue
        who, where = more[what]
        if kinds[what] == "added":
            flag(f"`{what[5:]}` is new: nobody could, now some can (e.g. {who} on {where})", what, "a rule added")
            continue
        kind = (
            ("a select rule loosened" if what.split()[2] == "select" else "a write rule loosened")
            if what.startswith("rule ")
            else "break_glass given to more people"
            if what.endswith(".break_glass")
            else "a permission widened"
        )
        flag(
            f"`{what[5:] if what.startswith('rule ') else what}` allows more than before (e.g. {who} on {where})",
            what,
            kind,
        )
    for what, via in through.items():
        if what in more and what not in own:
            who, where = more[what]
            flag(
                f"`{what[5:] if what.startswith('rule ') else what}` allows more than before through "
                f"{', '.join(f'`{v}`' for v in via)} (e.g. {who} on {where})",
                what,
                "a rule loosened through what it uses"
                if what.startswith("rule ")
                else "a permission widened through what it uses",
            )
    for tname in wheres:
        # one flag for the type: the first permission or rule that shows it
        shown = next((w for w in everything if w in more and w not in own and w not in through), None)
        if shown:
            who, where = more[shown]
            flag(
                f"`type {tname}`: its where changed, and more rows count: `{shown[5:] if shown.startswith('rule ') else shown}` "
                f"allows more than before (e.g. {who} on {where})",
                f"type {tname}",
                "a type's where loosened",
            )
    return flags


# --- tests -------------------------------------------------------------------------------------------
EXPECT = re.compile(r"\b(can|cannot|allowed|refused|sees\s+\d+)\b")


def unread_tests(side: Side) -> list[Unread]:
    """The test files `rowstile test` would refuse with this side's policy: one that doesn't parse, or names what
    the policy doesn't have (a permission, a type) or a test another file names too. Each is named with its
    mistake, as `rowstile test` names it; the files are added one at a time, in order, so a name two files give is
    the second's mistake."""
    out: list[Unread] = []
    good: dict[str, str] = {}
    for name, body in sorted(side.tests.items()):
        try:
            c = Compiler(parse_policy(side.policy, None, files=side.files, previous=side.previous))
            c.add_test_files({**good, name: body})
            c.tests_function_sql()
        except PolicyError as e:
            out.append({"file": name, "error": f"{name} {e}" if str(e).startswith("line ") else str(e)})
        else:
            good[name] = body
    return out


def checks(side: Side, unread: Iterable[str] = ()) -> dict[tuple[str, str], tuple[str, str, str]]:
    """{(test, check without its expectation): (expectation, text, line)}, from the policy's own tests and the
    test files. A test file in unread, or one that doesn't parse, gives no checks."""
    out: dict[tuple[str, str], tuple[str, str, str]] = {}
    for t in side.pol.tests:
        text = t.text.strip()
        out[("test section", EXPECT.sub("…", text, count=1))] = ("can" if t.expect else "cannot", text, str(t.loc))
    scenarios = [(sc, None) for sc in side.pol.scenarios]
    for name, body in sorted(side.tests.items()):
        if name in unread:
            continue
        try:
            scenarios += [(sc, name) for sc in parse_policy(body, name, files={}, previous=side.previous).scenarios]
        except PolicyError:
            pass  # (the base's own: the pull request's are in unread)
    for sc, file in scenarios:
        for st in sc.steps:
            if st.kind in ("check", "as"):
                text = " ".join(st.text.split())
                m = EXPECT.search(text)
                line = f"{file} line {st.loc.line}" if file else str(st.loc)
                out[(sc.name, EXPECT.sub("…", text, count=1))] = (m.group(1) if m else "", text, line)
    return out


def renames(before: Iterable[tuple[str, str]], after: Iterable[tuple[str, str]]) -> list[Renamed]:
    """The tests that only changed their name: one that went away, whose every check (whatever it expects) is
    in one that appeared. Their checks are then compared under the new name, so a new name doesn't read as
    checks removed. When the checks don't all turn up in one new test, or turn up in two, nothing is said of
    a name: "removed" is then the honest word."""

    def by_test(side: Iterable[tuple[str, str]]) -> dict[str, set[str]]:
        out: dict[str, set[str]] = {}
        for test, check in side:
            if test != "test section":
                out.setdefault(test, set()).add(check)
        return out

    old, new = by_test(before), by_test(after)
    out: list[Renamed] = []
    for gone in sorted(set(old) - set(new)):
        holds = [came for came in sorted(set(new) - set(old)) if old[gone] <= new[came]]
        if len(holds) == 1:
            out.append({"before": gone, "after": holds[0]})
    return out


def tests(b: Side, h: Side, unread: list[Unread]) -> Tests:
    # the pull request's test files that `rowstile test` would refuse are said (unread_tests): their checks are
    # missing from the comparison, which would otherwise read as "no change" (the base's are the base's business)
    cb, ch = checks(b), checks(h, [f["file"] for f in unread])
    renamed = renames(cb, ch)
    now = {r["before"]: r["after"] for r in renamed}
    cb = {(now.get(test, test), check): v for (test, check), v in cb.items()}
    flipped: list[Flipped] = [
        {"test": k[0], "before": cb[k][1], "after": ch[k][1], "line": ch[k][2]}
        for k in sorted(set(cb) & set(ch))
        if cb[k][0] != ch[k][0]
    ]
    removed: list[Removed] = [{"test": k[0], "check": cb[k][1]} for k in sorted(set(cb) - set(ch))]
    added: list[Added] = [{"test": k[0], "check": ch[k][1], "line": ch[k][2]} for k in sorted(set(ch) - set(cb))]
    named = " ".join(v[1] for v in ch.values())
    untested: list[Untested] = []
    for t in h.pol.types.values():
        bt_ = b.pol.types.get(t.name)
        for p in t.perms.values():
            if bt_ and p.name in bt_.perms:
                continue
            if not re.search(rf"\b{re.escape(p.name)}\s+{re.escape(t.name)}\b", named):
                untested.append({"what": f"{t.name}.{p.name}", "line": str(p.loc)})
    inv_b = {" ".join(i.src.split()) for i in b.pol.invariants}
    inv_h = {" ".join(i.src.split()) for i in h.pol.invariants}
    return {
        "flipped": flipped,
        "removed": removed,
        "added": added,
        "renamed": renamed,
        "untested": untested,
        "unread": unread,
        "invariants_removed": sorted(inv_b - inv_h),
        "count": len(ch),
    }


# --- deploy ------------------------------------------------------------------------------------------
LOCKS = [
    (
        re.compile(r"^(CREATE|DROP)\s+POLICY\s+(?:IF\s+EXISTS\s+)?\S+\s+ON\s+(\S+)", re.I),
        "ACCESS EXCLUSIVE",
        "its row-level security policies",
    ),
    (
        re.compile(r"^DROP\s+TRIGGER\s+(?:IF\s+EXISTS\s+)?\S+\s+ON\s+(\S+)", re.I),
        "ACCESS EXCLUSIVE",
        "a trigger dropped",
    ),
    (re.compile(r"^CREATE\s+TRIGGER\s+\S+\s+.*?\bON\s+(\S+)", re.I | re.S), "SHARE ROW EXCLUSIVE", "a trigger made"),
    (
        re.compile(r"^ALTER\s+TABLE\s+(\S+)\s+ENABLE\s+ROW\s+LEVEL\s+SECURITY", re.I),
        "ACCESS EXCLUSIVE",
        "row-level security turned on",
    ),
]
STRENGTH = {"ACCESS SHARE": 1, "SHARE ROW EXCLUSIVE": 2, "ACCESS EXCLUSIVE": 3}


def table_locks(sql: str) -> dict[str, tuple[str, str]]:
    """{app table: (lock mode, why)}: what the migration's statements lock, strongest first."""
    out: dict[str, tuple[str, str]] = {}
    for _, stmt in split(sql):
        s = stmt.lstrip()
        for rx, mode, why in LOCKS:
            mm = rx.match(s)
            if mm:
                tbl = mm.groups()[-1]
                if tbl.strip('"').startswith(("authz", '"authz')) or tbl.startswith(("authz", '"authz')):
                    break
                if STRENGTH[mode] > STRENGTH.get(out.get(tbl, ("", ""))[0], 0):
                    out[tbl] = (mode, why)
                break
    return out


def deploy(b: Side, h: Side, base_lock: str | None, head_lock: str | None) -> Deploy:
    out: Deploy = {"migrations": [], "lock_current": None}
    if base_lock is None and head_lock is None:
        # no lock file at the base or here: the project keeps no migrations (rowstile apply). Reading the change as
        # the first migration would call every change a whole policy that locks every table and rebuilds every tree.
        return {"migrations": [], "lock_current": None, "no_lock": True}
    try:
        ms = migrate_list(h, base_lock)  # (the head's policy compiles: Side compiled it)
    except migrate.LockError as e:  # a merge's conflict markers in the base branch's lock file, say
        return {"migrations": [], "lock_current": None, "error": f"{e}, at the base [AZ619]"}
    for i, m in enumerate(ms):
        if m.empty:
            continue
        stmts = split(m.sql)
        out["migrations"].append(
            {
                "statements": len(stmts),
                "bytes": len(m.sql),
                "locks": {t: {"mode": mode, "why": why} for t, (mode, why) in sorted(table_locks(m.sql).items())},
                "rebuilds": m.rebuilt if (len(ms) == 1 or i == len(ms) - 1) and not (len(ms) == 2 and i == 1) else [],
                "builds_beside": m.rebuilt if len(ms) == 2 and i == 0 else [],
                "swaps_in": ms[0].rebuilt if len(ms) == 2 and i == 1 else [],
            }
        )
    if len(ms) == 2:
        out["migrations"][-1]["rebuilds"] = [t for t in ms[1].rebuilt if t not in ms[0].rebuilt]
    if head_lock is not None:
        out["lock_current"] = head_lock == ms[-1].lock or all(m.empty for m in ms)
    return out


def migrate_list(h: Side, base_lock: str | None) -> list[migrate.Migration]:
    c = Compiler(parse_policy(h.policy, None, files=h.files))
    sql = c.compile("the policy", transaction=False)
    comp = migrate.read(c, h.policy, h.files)
    return migrate.migrations(sql, comp, migrate.parse_lock(base_lock or ""), "review")


# --- with a database ---------------------------------------------------------------------------------
def access(db: Db, h: Side, examples: int = 3) -> Access:
    """Who gains and loses what if the pull request's policy were in force on the review data."""
    from . import database

    try:
        rows = database.diff(db, h.policy, h.files)
    except (database.Error, db.errors) as e:  # db.errors: a condition that fails on a row of the review data
        return {"groups": [], "users_in_data": None, "error": getattr(e, "message", str(e))}
    users: dict[tuple[str, str, str], set[str]] = {}
    objects: dict[tuple[str, str, str], set[str]] = {}
    shown: dict[tuple[str, str, str], list[database.DiffRow]] = {}
    for r in rows:
        key = (r["change"], r["type"], r["what"])
        users.setdefault(key, set()).add(r["user_id"] or "")
        objects.setdefault(key, set()).add(r["id"])
        if len(shown.setdefault(key, [])) < examples:
            shown[key].append(r)
    out: list[Group] = []
    for key in sorted(users):
        change, type_, what = key
        out.append(
            {
                "change": change,
                "type": type_,
                "what": what,
                "users": len(users[key]),
                "who": who_of(users[key], h.pol),
                "objects": len(objects[key]),
                "examples": [
                    {"user": r["user_id"] or NOBODY, "who": words(r["user_id"] or "", h.pol), "id": r["id"]}
                    for r in shown[key]
                ],
            }
        )
    return {"groups": out, "users_in_data": None}


# --- writing it out ----------------------------------------------------------------------------------
def plural(n: int, word: str, many: str | None = None) -> str:
    return f"{n} {word if n == 1 else (many or word + 's')}"


def summary(r: Review) -> dict[str, str]:
    m = r["meaning"]
    lines: dict[str, str] = {}
    if m["equivalent"] == "text":
        lines["Meaning"] = "unchanged (only comments, spacing or order)"
    elif m["equivalent"]:
        lines["Meaning"] = f"unchanged: every permission and rule grants the same in {m['equivalent']}"
    else:
        counts: dict[tuple[str, str], int] = {}
        for c in m["changed"]:
            key = (c["entity"], c["kind"])
            counts[key] = counts.get(key, 0) + 1
        order = ["type", "relation", "permission", "rule", "scope", "caveat", "invariant", "declaration"]
        parts = [
            f"{plural(n, e)} {k}" for (e, k), n in sorted(counts.items(), key=lambda x: (order.index(x[0][0]), x[0][1]))
        ]
        if m["through"]:
            n = len(m["through"])
            parts.append(
                f"{n} {'permission or rule changes' if n == 1 else 'permissions and rules change'} through "
                f"{'it' if len(m['changed']) == 1 else 'them'}"
            )
        if m.get("unreadable"):
            parts.append(
                f"{plural(len(m.get('unreadable', [])), 'change')} it can't compare (a condition it can't read)"
            )
        lines["Meaning"] = ", ".join(parts)
    a = r["access"]
    if a is None:
        lines["Access"] = "not computed (no review database: rowstile review --db)"
    elif a.get("error"):
        lines["Access"] = f"not computed: {a['error']}"
    else:
        gains = [g for g in a["groups"] if g["change"] == "gains"]
        loses = [g for g in a["groups"] if g["change"] == "loses"]
        gains = [g for g in gains if g["what"].startswith("permission ")] or gains
        loses = [g for g in loses if g["what"].startswith("permission ")] or loses

        def say(gs: list[Group], verb: str) -> str:
            # "1 user gains", "2 users gain"
            does = lambda g: verb + ("s" if g["users"] == 1 else "")
            return "; ".join(
                f"{g['who']} {does(g)} `{g['what'].replace('permission ', '')}` on {plural(g['objects'], g['type'])}"
                if g["what"].startswith("permission ")
                else f"{g['who']} {does(g)} {g['what']} in `{g['type']}` ({plural(g['objects'], 'row')})"
                for g in gs[:3]
            ) + (f"; and {len(gs) - 3} more" if len(gs) > 3 else "")

        lines["Access"] = (
            (say(gains, "gain") if gains else "Nobody gains access")
            + ". "
            + (say(loses, "lose") if loses else "Nobody loses access")
            + "."
        )
    lines["Risk"] = (
        (
            plural(len(r["risk"]), "flag")
            + ": "
            + "; ".join(f["flag"] for f in r["risk"][:3])
            + ("; ..." if len(r["risk"]) > 3 else "")
        )
        if r["risk"]
        else "nothing flagged"
    )
    t = r["tests"]
    parts: list[str] = []
    run = t.get("run")
    if run:
        failed = run.get("failed", [])
        parts.append(
            f"not run: {run['error']}"
            if run.get("error")
            else (
                f"{plural(run.get('checks', 0) - len(failed), 'check')} pass"
                + (f", {len(failed)} fail" if failed else "")
            )
        )
    if t["flipped"]:
        expects = "it expects" if len(t["flipped"]) == 1 else "they expect"
        parts.append(f"{plural(len(t['flipped']), 'check')} changed what {expects}")
    if t["removed"]:
        parts.append(f"{plural(len(t['removed']), 'check')} removed")
    if t["renamed"]:
        parts.append(f"{plural(len(t['renamed']), 'test')} renamed")
    if t["untested"]:
        parts.append(f"{plural(len(t['untested']), 'new permission')} no test names")
    if t["unread"]:
        n = len(t["unread"])
        parts.append(
            f"{plural(n, 'test file')} can't be read, so {'its' if n == 1 else 'their'} checks aren't compared"
        )
    lines["Tests"] = ". ".join(parts) + "." if parts else "no change to what the tests claim."
    d = r["deploy"]
    ran = d.get("on_review_data")
    # what bringing the policy in (its migrations, or applying it when there are none) did on the review data
    on_data = (
        ""
        if not ran
        else f" **It fails on the review database: {ran['error']}**"
        if ran["error"]
        else f" Applied on the review database in {ran['seconds']} s."
    )
    if d.get("error"):
        lines["Deploy"] = f"not computed: {d['error']}"
    elif d.get("no_lock"):
        lines["Deploy"] = (
            "no lock file, so no migrations: `rowstile apply` applies the policy, and keeps the "
            "inheritance tables whose definition didn't change." + on_data
        )
    elif not d["migrations"]:
        lines["Deploy"] = "no migration: nothing the database holds changes."
    else:
        locks = sorted({t for m in d["migrations"] for t in m["locks"]})
        rebuilds = [x for m in d["migrations"] for x in m["rebuilds"]]
        beside = [x for m in d["migrations"] for x in m["builds_beside"]]
        text = plural(len(d["migrations"]), "migration") + ". "
        text += f"Locks {', '.join(f'`{x}`' for x in locks)} while it runs. " if locks else "No table locks. "
        text += f"Builds {', '.join(beside)} beside the tables in use, then swaps in. " if beside else ""
        text += (
            f"Rebuilds {', '.join(rebuilds)} under lock."
            if rebuilds
            else ""
            if beside
            else "No inheritance table rebuilt."
        )
        text += on_data
        if d["lock_current"] is False:
            text += " **The lock file is behind the policy: run `rowstile migrate` and commit what it writes.**"
        lines["Deploy"] = text.strip()
    return lines


def previous_note(r: Review) -> str | None:
    """A base read in the language before this one: a sentence saying so, with its first old forms."""
    old = r.get("base_previous")
    if old is None:
        return None
    shown = "; ".join(old[:4]) + (f"; and {len(old) - 4} more" if len(old) > 4 else "")
    return (
        "The policy at the base is written in the language before this version of rowstile, and was read as "
        "that version meant it" + (f": {shown}." if shown else ".")
    )


def mistake_note(r: Review) -> str | None:
    """A base whose policy has a mistake: a sentence saying so, with the mistake, its line there and its code."""
    m = r.get("base_mistake")
    if m is None:
        return None
    said = (f"{m['line']} there: " if m["line"] else "") + m["message"] + (f" [{m['code']}]" if m["code"] else "")
    return f"The policy at the base has a mistake ({said}), so the review reads this one as new."


def markdown(r: Review, title: str = "rowstile: what this pull request changes") -> str:
    s = summary(r)
    out = [MARK, f"### {title}", ""]
    for note in (mistake_note(r), previous_note(r)):
        if note:
            out += [note, ""]
    for k in ("Meaning", "Access", "Risk", "Tests", "Deploy"):
        out.append(f"**{k}**: {s[k]}  ")
    m = r["meaning"]
    if m["equivalent"]:
        # the meaning is the same: what the summary counts without naming is still listed
        return "\n".join(out + risk_details(r) + tests_details(r)) + "\n"

    def cell(x: str | None) -> str:
        return "" if x is None else "`" + x.replace("|", "\\|").replace("`", "'") + "`"

    out += ["", "<details><summary>Meaning</summary>", "", "| | before | after | line |", "|---|---|---|---|"]
    for c in m["changed"]:
        out.append(f"| `{c['what']}` ({c['kind']}) | {cell(c['before'])} | {cell(c['after'])} | {c['line'] or ''} |")
    for t in m["through"]:
        out.append(f"| `{t['what']}` | | changes through {', '.join(f'`{v}`' for v in t['via'])} | {t['line'] or ''} |")
    out += ["", "</details>"]
    a = r["access"]
    if a and not a.get("error") and a["groups"]:
        out += [
            "",
            "<details><summary>Access</summary>",
            "",
            "| change | what | who | objects | examples |",
            "|---|---|---|---|---|",
        ]
        for g in a["groups"]:
            ex = "; ".join(
                f"{e['who']}, {g['type']} {e['id']}" + (f": {e['how']}" if e.get("how") else "")
                for e in g["examples"][:2]
            )
            out.append(
                f"| {g['change']} | `{g['type']}` {g['what'].replace('permission ', '')} | {g['who']} | "
                f"{g['objects']} | {ex.replace('|', '/')} |"
            )
        out += ["", "</details>"]
    out += risk_details(r) + tests_details(r)
    d = r["deploy"]
    if d.get("migrations"):
        out += ["", "<details><summary>Deploy</summary>", ""]
        for i, mg in enumerate(d["migrations"], 1):
            out.append(f"- migration {i}: {mg['statements']} statements ({mg['bytes'] // 1024} KB)")
            for tbl, lk in mg["locks"].items():
                out.append(f"  - `{tbl}`: {lk['mode']} ({lk['why']})")
            for x in mg["builds_beside"]:
                out.append(f"  - builds `{x}` beside the one in use; the app keeps reading and writing")
            for x in mg["swaps_in"]:
                out.append(f"  - swaps `{x}` in, and does again what changed since")
            for x in mg["rebuilds"]:
                out.append(f"  - rebuilds `{x}`, its tables locked meanwhile")
        out.append("- rolling back: change the policy back and write the next migration")
        out += ["", "</details>"]
    return "\n".join(out) + "\n"


def risk_details(r: Review) -> list[str]:
    """The Markdown comment's Risk section: each flag, why, and its line."""
    if not r["risk"]:
        return []
    return [
        "",
        "<details><summary>Risk</summary>",
        "",
        *[f"- {f['flag']} ({f['why']}{', ' + f['line'] if f['line'] else ''})" for f in r["risk"]],
        "",
        "</details>",
    ]


def tests_details(r: Review) -> list[str]:
    """The Markdown comment's Tests section: the checks that flipped, went away, are missing or fail."""
    t = r["tests"]
    said = t["flipped"] or t["removed"] or t["renamed"] or t["untested"] or t["unread"]
    if not (said or (t.get("run") or {}).get("failed")):
        return []
    out = ["", "<details><summary>Tests</summary>", ""]
    out += [f"- can't read: {x['error']}" for x in t["unread"]]
    out += [f"- {x['test']}: `{x['before']}` -> `{x['after']}` ({x['line']})" for x in t["flipped"]]
    out += [f"- removed from {x['test']}: `{x['check']}`" for x in t["removed"]]
    out += [f'- renamed: "{n["before"]}" is now "{n["after"]}"' for n in t["renamed"]]
    out += [f"- no test names `{x['what']}` ({x['line']})" for x in t["untested"]]
    out += [
        f"- fails: {x['test']} {x['line'] or ''}: `{(x['detail'] or '').splitlines()[0] if x['detail'] else ''}`"
        for x in (t.get("run") or {}).get("failed", [])
    ]
    return [*out, "", "</details>"]


def text(r: Review) -> str:
    s = summary(r)
    out = [f"{'Base':<8} {note}" for note in (mistake_note(r), previous_note(r)) if note] + [
        f"{k:<8} {s[k]}" for k in ("Meaning", "Access", "Risk", "Tests", "Deploy")
    ]
    m = r["meaning"]
    if not m["equivalent"]:
        out.append("")
        for c in m["changed"]:
            out.append(f"  {c['kind']:<8} {c['what']}" + (f"  ({c['line']})" if c["line"] else ""))
            if c["before"] is not None:
                out.append(f"             before: {c['before']}")
            if c["after"] is not None:
                out.append(f"             after:  {c['after']}")
        for t in m["through"]:
            out.append(f"  through  {t['what']}: uses {', '.join(t['via'])}")
        ce = m.get("counterexample")
        if ce:
            # as the risks name their examples: user 1 on note 1 (a rule's object is a row of its table)
            kind = ce["what"].split(".")[0] if re.fullmatch(r"\w+\.\w+", ce["what"]) else "row"
            out.append(f"  not a refactor: {ce['what']} differs for {named(ce['user'])} on {kind} {ce['object']}")
        if m.get("unreadable"):
            out.append(
                f"  can't tell: {', '.join(m.get('unreadable', []))} changed only in conditions the review "
                f"can't read (a subquery, a function)"
            )
    for f in r["risk"]:
        out.append(f"  risk     {f['flag']} ({f['why']}" + (f", {f['line']})" if f["line"] else ")"))
    t = r["tests"]
    for u in t["unread"]:
        out.append(f"  test     can't read: {u['error']}")
    for x in t["flipped"]:
        out.append(f"  test     {x['test']}: {x['before']} -> {x['after']} ({x['line']})")
    for y in t["removed"]:
        out.append(f"  test     removed from {y['test']}: {y['check']}")
    for n in t["renamed"]:
        out.append(f'  test     renamed: "{n["before"]}" is now "{n["after"]}"')
    for z in t["untested"]:
        out.append(f"  test     no test names {z['what']} ({z['line']})")
    for failed in (t.get("run") or {}).get("failed", []):
        out.append(f"  test     fails: {failed['test']} {failed['line'] or ''}".rstrip())
    return "\n".join(out) + "\n"


def annotations(r: Review, path: str) -> str:
    """GitHub workflow commands: each flag on its policy line, in the pull request's files view."""
    out = []
    note = mistake_note(r)
    if note:  # on the file, not a line: the line is the base's
        out.append(f"::warning file={path},title=rowstile review::{escape_command(note)}")
    folder = path.rsplit("/", 1)[0] + "/" if "/" in path else ""
    for f in r["risk"]:
        # 'line 12' is the policy file's; 'roles.authz line 3' an included file's, beside the policy
        m = re.fullmatch(r"(?:(\S+) )?line (\d+)", f["line"] or "")
        file = folder + m.group(1) if m and m.group(1) else path
        where = f"file={file},line={m.group(2)}" if m else f"file={path}"
        out.append(f"::warning {where},title=rowstile review::{escape_command(f['why'] + ': ' + f['flag'])}")
    return "\n".join(out) + ("\n" if out else "")


def escape_command(msg: str) -> str:
    """A workflow command's message: % and line breaks escaped, without the backticks GitHub would show."""
    return msg.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A").replace("`", "")


def as_json(r: Review) -> str:
    return json.dumps(r, indent=2) + "\n"

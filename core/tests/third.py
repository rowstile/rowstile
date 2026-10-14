"""third: a third evaluator of policies, written from docs/reference/language.md alone, sharing no code with authzlib.

The compiler and the reference evaluator (authzlib/evaluate.py) read a policy through one parser, and the
evaluator's reading of the page is its author's: a misreading in either would be in both. This one reads the
policy through the editors' Tree-sitter grammar (editor/tree-sitter-authz: `tree-sitter parse --xml`), writes what
the page says as Datalog rules (tests/datalog.py runs them), and reads a world given as plain facts: each table's
rows, the shares, the custom roles, who is signed in. It imports nothing from authzlib, difftest or genpolicy.
tests/third_compare.py holds it to evaluate.py.

What the page says, as rules (T a type, O an object's id, S a session, X a subject's id):

    obj(T, O)            a row of T's table, with key O, that passes T's `where`: "a row that fails it holds nothing
                         and passes nothing on"; every relation, permission and rule needs obj(T, O)
    principal(S, U, X)   S is signed in as X of type U (the user type or a `principal` type), a row that counts:
                         "an id the type's table doesn't have is nobody ... as for a row that fails the type's where"
    link:T:r(O, U, R, X) a source of relation r links O to subject X of the kind (U, R): R '' for an object or a user
                         (U a type), a relation for a group (team#member), '*' for U:*, U 'anyone' or 'link'
    has:T:n(O, S)        S holds relation or permission n on O:
                           relation: obj(T, O), link:T:r(O, U, R, X), and S is X (principal), holds R on group X,
                           is signed in as any U (U:*), anyone, or holds the link's token
                           permission: obj(T, O) and its expression, where `rel.perm` is link:T:rel(O, U, '', X),
                           has:U:perm(X, S); `{c}` the condition on O's row; `signed_in` principal(S, user, _);
                           `anyone` every session; `nobody` none; `roles` a custom role that includes the
                           permission, assigned to S on O (and, with `from rel`, owned by what rel links O to)
    rule:k(O, S)         a rule's expression on a row of its table that counts
    inv:k(O, S)          an invariant's expression holds: someone breaks it on O

The least model of the rules, stratum by stratum, is the answer: inheritance is recursion, a deny a `not` of a
lower stratum (the language refuses a permission that depends on itself other than through `or rel.perm`, AZ302,
and `roles` under a `not`, AZ210, so a valid policy is stratified; datalog.py refuses one that isn't).

The world's conditions are the one input it shares with the harness: it can't run SQL, so the world says on which
rows each condition holds (and for whom, where the condition reads who is signed in). Left out: scopes, the
masked views, `shared if` and `shared by` (who may share, not who holds), before and after a write (a rule is
asked of the rows there), named tests.
"""

from __future__ import annotations

import os
import xml.etree.ElementTree as ET
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import NamedTuple, TypeAlias

import datalog
from datalog import Atom, Lit, Rule, Var


# ----------------------------------------------------------------------
# The policy, as the grammar reads it
# ----------------------------------------------------------------------
class Or(NamedTuple):
    items: tuple[Expr, ...]


class And(NamedTuple):
    items: tuple[Expr, ...]


class Not(NamedTuple):
    item: Expr


class Name(NamedTuple):
    name: str  # a relation or permission of the type, or `roles`


class Follow(NamedTuple):
    rel: str
    perm: str


class Cond(NamedTuple):
    text: str  # normalized: norm()


class Word(NamedTuple):
    word: str  # signed_in | anyone | nobody


Expr: TypeAlias = "Or | And | Not | Name | Follow | Cond | Word"
WORDS = ("signed_in", "anyone", "nobody")


class Subject(NamedTuple):
    type: str  # a type's name, or 'anyone' or 'link'
    rel: str  # '' (the object, or the user), a relation or permission (a group: team#member), '*' (type:*)


@dataclass
class Source:
    kind: str  # column | pair | table | shared
    subjects: list[Subject]
    ids: tuple[str, ...] = ()  # the columns holding the subject's key
    type_col: str = ""  # a pair's column naming the subject's type
    table: str = ""  # a link table
    objs: tuple[str, ...] = ()  # the link table's columns holding the object's key
    where: str | None = None


@dataclass
class TypeDecl:
    name: str
    table: str
    key: tuple[str, ...]
    principal: bool
    where: str | None
    relations: dict[str, list[Source]] = field(default_factory=dict)
    perms: dict[str, Expr] = field(default_factory=dict)
    roles: list[Subject] | None = None
    roles_from: str = ""


class RuleDecl(NamedTuple):
    table: str
    command: str  # select | insert | update | delete | mask
    columns: tuple[str, ...]
    when: str  # '' | before | after
    expr: Expr


class Invariant(NamedTuple):
    type: str
    expr: Expr


@dataclass
class Policy:
    types: dict[str, TypeDecl] = field(default_factory=dict)
    rules: list[RuleDecl] = field(default_factory=list)
    invariants: list[Invariant] = field(default_factory=list)


class Unreadable(Exception):
    """A tree the grammar couldn't read whole, or a name the policy doesn't declare."""


def norm(sql: str) -> str:
    """A condition's text as the world names it: its -- comments out (outside quotes), white space single."""
    out: list[str] = []
    for line in sql.split("\n"):
        quote = ""
        cut = len(line)
        i = 0
        while i < len(line):
            ch = line[i]
            if quote:
                if ch == quote:
                    quote = ""
            elif ch in "'\"":
                quote = ch
            elif line.startswith("--", i):
                cut = i
                break
            i += 1
        out.append(line[:cut])
    return " ".join("\n".join(out).split())


class Tree:
    """One file: its element from the XML, and its bytes (a condition's text is taken from where it is)."""

    def __init__(self, root: ET.Element, source: bytes) -> None:
        self.root, self.lines = root, source.split(b"\n")

    def text(self, e: ET.Element) -> str:
        sr, sc, er, ec = (int(e.get(k, "0")) for k in ("srow", "scol", "erow", "ecol"))
        if sr == er:
            return self.lines[sr][sc:ec].decode("utf-8")
        return b"\n".join([self.lines[sr][sc:], *self.lines[sr + 1 : er], self.lines[er][:ec]]).decode("utf-8")


def trees(xml_path: str) -> dict[str, Tree]:
    """Each file `tree-sitter parse --xml` read, by its path."""
    out: dict[str, Tree] = {}
    for src in ET.parse(xml_path).getroot().iter("source"):
        path = src.get("name") or ""
        root = src.find("source_file")
        if root is None:
            continue
        with open(path, "rb") as fh:
            out[os.path.normpath(path)] = Tree(root, fh.read())
    return out


def children(e: ET.Element, *tags: str) -> list[ET.Element]:
    return [k for k in e if not tags or k.tag in tags]


def named(e: ET.Element, fieldname: str) -> ET.Element | None:
    return next((k for k in e if k.get("field") == fieldname), None)


def word(e: ET.Element | None) -> str:
    """An identifier's or table name's text (the XML lays a name's parts out on lines)."""
    return "" if e is None else "".join("".join(e.itertext()).split())


def bare(e: ET.Element) -> list[str]:
    """The grammar's own words in an element (anonymous tokens: the text between its children)."""
    return [w for t in [e.text or "", *(k.tail or "" for k in e)] for w in t.split()]


def sql(tree: Tree, e: ET.Element) -> str:
    text = tree.text(e).strip()
    if text.startswith("{") and text.endswith("}"):
        text = text[1:-1]
    return norm(text)


def expression(tree: Tree, e: ET.Element) -> Expr:
    tag = e.tag
    if tag == "parenthesized":
        return expression(tree, children(e)[0])
    if tag in ("or", "and"):
        items: list[Expr] = []
        for k in children(e):
            x = expression(tree, k)
            # a run of one operator, flat: (a or b) or c is a or b or c
            if (tag == "or" and isinstance(x, Or)) or (tag == "and" and isinstance(x, And)):
                items += x.items
            else:
                items.append(x)
        return Or(tuple(items)) if tag == "or" else And(tuple(items))
    if tag == "not":
        return Not(expression(tree, children(e)[0]))
    if tag == "sql":
        return Cond(sql(tree, e))
    if tag == "ref":
        n = word(e)
        return Word(n) if n in WORDS else Name(n)
    if tag == "arrow":
        return Follow(word(named(e, "relation")), word(named(e, "permission")))
    raise Unreadable(f"not an expression: {tag}")


def subject(e: ET.Element) -> Subject:
    first = children(e)[0] if children(e) else None
    if first is not None and first.tag in ("anyone", "link"):
        return Subject(first.tag, "")
    t = word(named(e, "type"))
    if "*" in "".join(bare(e)):
        return Subject(t, "*")
    return Subject(t, word(named(e, "relation")))


def columns(e: ET.Element) -> tuple[tuple[str, ...], str]:
    """(the key's columns, the column naming a type) of `c`, `[a, b]`, `(type_col, c)`."""
    if e.tag == "column":
        return (word(e),), ""
    if e.tag == "columns":
        return tuple(word(c) for c in children(e, "column")), ""
    if e.tag == "typed_columns":
        type_col, rest = children(e)[0], children(e)[1]
        return columns(rest)[0], word(type_col)
    raise Unreadable(f"not columns: {e.tag}")


def source(tree: Tree, rel: ET.Element) -> Source:
    subjects = [subject(k) for k in children(rel, "subject")]
    last = children(rel)[-1]
    if last.tag == "shared":
        return Source("shared", subjects)
    if last.tag in ("column", "columns", "typed_columns"):
        ids, type_col = columns(last)
        return Source("pair" if type_col else "column", subjects, ids=ids, type_col=type_col)
    if last.tag == "table_source":
        parts = children(last, "column", "columns", "typed_columns", "side")
        if parts and parts[0].tag == "side":
            sides = {bare(s)[0]: children(s)[0] for s in parts}
            objs = columns(sides["object"])[0]
            ids, type_col = columns(sides["subject"])
        else:
            objs = columns(parts[0])[0]
            ids, type_col = columns(parts[1])
        where = next((k for k in children(last, "sql")), None)
        return Source(
            "table",
            subjects,
            ids=ids,
            type_col=type_col,
            table=word(named(last, "table")),
            objs=objs,
            where=sql(tree, where) if where is not None else None,
        )
    raise Unreadable(f"not a source: {last.tag}")


def read(files: Mapping[str, Tree], path: str) -> Policy:
    """The policy whose first file is path, with the files it includes (from files, beside it)."""
    pol = Policy()
    seen: set[str] = set()

    def visit(p: str) -> None:
        p = os.path.normpath(p)
        if p in seen:
            return
        seen.add(p)
        tree = files.get(p)
        if tree is None:
            raise Unreadable(f"{p}: not in the trees read")
        if any(x.tag in ("ERROR", "MISSING") or x.get("missing") is not None for x in tree.root.iter()):
            raise Unreadable(f"{p}: the grammar can't read it")
        for top in children(tree.root):
            if top.tag == "include":
                visit(os.path.join(os.path.dirname(p), tree.text(children(top)[0]).strip().strip('"')))
            elif top.tag == "type":
                key = next(iter(children(top, "key")), None)
                where = next(iter(children(top, "sql")), None)
                t = TypeDecl(
                    name=word(named(top, "name")),
                    table=word(named(top, "table")),
                    key=tuple(word(named(c, "name")) for c in children(key, "key_column"))
                    if key is not None
                    else ("id",),
                    principal=bool(children(top, "principal")),
                    where=sql(tree, where) if where is not None else None,
                )
                for k in children(top):
                    if k.tag == "relation":
                        t.relations.setdefault(word(named(k, "name")), []).append(source(tree, k))
                    elif k.tag == "permission":
                        t.perms[word(named(k, "name"))] = expression(tree, named_or_fail(k, "expression"))
                    elif k.tag == "roles":
                        t.roles = [subject(s) for s in children(k, "subject")]
                        t.roles_from = word(named(k, "owner"))
                pol.types[t.name] = t
            elif top.tag == "rules":
                table = word(named(top, "table"))
                for r in children(top, "rule", "mask"):
                    cols = tuple(word(c) for c in children(r, "column"))
                    expr = expression(tree, named_or_fail(r, "expression"))
                    if r.tag == "mask":
                        pol.rules.append(RuleDecl(table, "mask", cols, "", expr))
                    else:
                        when = next((w for w in bare(r) if w in ("before", "after")), "")
                        pol.rules.append(RuleDecl(table, word(named(r, "command")), cols, when, expr))
            elif top.tag == "invariants":
                for n in children(top, "never"):
                    pol.invariants.append(
                        Invariant(word(named(n, "type")), expression(tree, named_or_fail(n, "expression")))
                    )

    visit(path)
    return pol


def named_or_fail(e: ET.Element, fieldname: str) -> ET.Element:
    found = named(e, fieldname)
    if found is None:
        raise Unreadable(f"{e.tag} without its {fieldname}")
    return found


# ----------------------------------------------------------------------
# The world, as plain facts
# ----------------------------------------------------------------------
class Share(NamedTuple):
    """A row of authz.shares, as authz.share() makes it: to user:* and anyone the subject's id is '*', to a link the
    token. Whether it is in force now: it may have ended, or not started yet, and its caveat may not hold."""

    object_type: str
    object_id: str
    relation: str  # a relation, or 'role:<id>' for a custom role
    subject_type: str
    subject_id: str
    subject_relation: str = ""
    ended: bool = False
    starts_later: bool = False
    caveat: str = ""
    caveat_holds: bool = True


class Role(NamedTuple):
    """A custom role: its id, its owner (authz.create_role's first two arguments), the type it is for, what it
    includes."""

    id: str
    owner_type: str
    owner_id: str
    object_type: str
    perms: tuple[str, ...]


class Session(NamedTuple):
    id: str
    principal_type: str | None  # None: nobody signed in
    principal_id: str | None
    links: tuple[str, ...] = ()  # the share links' tokens it holds


Row: TypeAlias = "dict[str, str | None]"


@dataclass
class World:
    tables: dict[str, list[Row]] = field(default_factory=dict)  # 'schema.table' -> rows (a row: its index)
    conds: set[tuple[str, str, int]] = field(default_factory=set)  # (table, condition, row): it holds there
    conds_as: set[tuple[str, str, int, str]] = field(default_factory=set)  # ...for that session only
    shares: list[Share] = field(default_factory=list)
    roles: list[Role] = field(default_factory=list)
    sessions: list[Session] = field(default_factory=list)


def record(values: Sequence[str]) -> str:
    """A key of several columns as Postgres writes the row: (1,"a b")."""
    out = []
    for v in values:
        if v == "" or any(c in v for c in '"\\(),') or any(c.isspace() for c in v):
            out.append('"' + v.replace("\\", "\\\\").replace('"', '""') + '"')
        else:
            out.append(v)
    return "(" + ",".join(out) + ")"


def key_text(row: Row, cols: Sequence[str]) -> str | None:
    """The key the columns hold (None if one is NULL)."""
    values = [row.get(c) for c in cols]
    if any(v is None for v in values):
        return None
    texts = [v for v in values if v is not None]
    return texts[0] if len(texts) == 1 else record(texts)


# ----------------------------------------------------------------------
# The rules
# ----------------------------------------------------------------------
OBJ, SES, SUB, TYP, ROW, ANY, ROLE, OWNER_T, OWNER_I = (
    Var(n) for n in ("O", "S", "X", "U", "ROW", "ANY", "ROLE", "OWNER_TYPE", "OWNER_ID")
)


def lit(pred: str, *args: str | Var, negated: bool = False) -> Lit:
    return Lit(Atom(pred, tuple(args)), negated)


def has(t: str, n: str) -> str:
    return f"has:{t}:{n}"


def links(t: str, r: str) -> str:
    return f"link:{t}:{r}"


class Program:
    """A policy's rules, and the column groups and conditions its world must give as facts."""

    def __init__(self, pol: Policy) -> None:
        self.pol = pol
        self.rules: list[Rule] = []
        self.groups: set[tuple[str, tuple[str, ...]]] = set()  # (table, columns) whose values the rules read
        self.counter = 0
        self.of_table: dict[str, TypeDecl] = {}
        for t in pol.types.values():
            self.of_table.setdefault(t.table, t)
        for t in pol.types.values():
            self.type_rules(t)
        for t in pol.types.values():
            for r, srcs in t.relations.items():
                for src in srcs:
                    self.source_rules(t, r, src)
                self.holder_rules(t, r, has(t.name, r), links(t.name, r), [s for src in srcs for s in src.subjects])
            if t.roles is not None:
                self.holder_rules(t, "", f"roleheld:{t.name}", f"rolelink:{t.name}", t.roles, role=True)
            for p, e in t.perms.items():
                self.add(Atom(has(t.name, p), (OBJ, SES)), lit(f"obj:{t.name}", OBJ), lit(self.expr(t, e, p), OBJ, SES))
        for k, rule in enumerate(pol.rules):
            t = self.of_table.get(rule.table)
            if t is None:
                raise Unreadable(f"rules {rule.table}: no type has that table")
            self.add(
                Atom(f"rule:{k}", (OBJ, SES)), lit(f"obj:{t.name}", OBJ), lit(self.expr(t, rule.expr, None), OBJ, SES)
            )
        for k, inv in enumerate(pol.invariants):
            t = self.type(inv.type)
            self.add(
                Atom(f"inv:{k}", (OBJ, SES)), lit(f"obj:{t.name}", OBJ), lit(self.expr(t, inv.expr, None), OBJ, SES)
            )
        # who is someone: a session signed in as a row of its type that counts
        self.add(Atom("principal", (SES, TYP, SUB)), lit("signs_in", SES, TYP, SUB), lit("obj", TYP, SUB))
        for t in pol.types.values():
            self.add(Atom("obj", (t.name, OBJ)), lit(f"obj:{t.name}", OBJ))
        datalog.strata(self.rules)  # refused here if a `not` reads its own stratum

    def add(self, head: Atom, *body: Lit) -> None:
        self.rules.append(Rule(head, tuple(body)))

    def type(self, name: str) -> TypeDecl:
        t = self.pol.types.get(name)
        if t is None:
            raise Unreadable(f"no type {name}")
        return t

    def group(self, table: str, cols: tuple[str, ...]) -> str:
        self.groups.add((table, cols))
        return ",".join(cols)

    def type_rules(self, t: TypeDecl) -> None:
        """obj:T(O): its rows that count; row:T(O, ROW): which row of the table has key O."""
        self.add(Atom(f"row:{t.name}", (OBJ, ROW)), lit("val", t.table, ROW, self.group(t.table, t.key), OBJ))
        if t.where is None:
            self.add(Atom(f"obj:{t.name}", (OBJ,)), lit(f"row:{t.name}", OBJ, ROW))
        else:
            self.add(Atom(f"obj:{t.name}", (OBJ,)), lit(f"row:{t.name}", OBJ, ROW), lit("cond", t.table, t.where, ROW))

    def source_rules(self, t: TypeDecl, r: str, src: Source) -> None:
        head = links(t.name, r)
        if src.kind == "column":
            (st,) = src.subjects  # one kind of subject in a column (AZ205)
            g = self.group(t.table, src.ids)
            self.add(
                Atom(head, (OBJ, st.type, st.rel, SUB)),
                lit(f"row:{t.name}", OBJ, ROW),
                lit("val", t.table, ROW, g, SUB),
            )
        elif src.kind == "pair":
            g, tc = self.group(t.table, src.ids), self.group(t.table, (src.type_col,))
            for st in src.subjects:
                self.add(
                    Atom(head, (OBJ, st.type, st.rel, SUB)),
                    lit(f"row:{t.name}", OBJ, ROW),
                    lit("val", t.table, ROW, tc, st.type),
                    lit("val", t.table, ROW, g, SUB),
                )
        elif src.kind == "table":
            og, sg = self.group(src.table, src.objs), self.group(src.table, src.ids)
            extra = [lit("cond", src.table, src.where, ROW)] if src.where is not None else []
            if src.type_col:
                tc = self.group(src.table, (src.type_col,))
                for st in src.subjects:
                    self.add(
                        Atom(head, (OBJ, st.type, st.rel, SUB)),
                        lit("val", src.table, ROW, og, OBJ),
                        lit("val", src.table, ROW, tc, st.type),
                        lit("val", src.table, ROW, sg, SUB),
                        *extra,
                    )
            else:
                (st,) = src.subjects
                self.add(
                    Atom(head, (OBJ, st.type, st.rel, SUB)),
                    lit("val", src.table, ROW, og, OBJ),
                    lit("val", src.table, ROW, sg, SUB),
                    *extra,
                )
        else:
            # a share names its subject as authz.shares does: (type, id, relation); '*' the id of user:* and anyone
            for st in src.subjects:
                if st.rel == "*" or st.type == "anyone":
                    self.add(Atom(head, (OBJ, st.type, st.rel, "*")), lit("share", t.name, OBJ, r, st.type, "*", ""))
                else:
                    self.add(
                        Atom(head, (OBJ, st.type, st.rel, SUB)), lit("share", t.name, OBJ, r, st.type, SUB, st.rel)
                    )

    def holder_rules(
        self, t: TypeDecl, r: str, head: str, linked: str, subjects: Iterable[Subject], role: bool = False
    ) -> None:
        """Who holds what links name: X itself, its group's members, anyone signed in as its type, anyone, a
        link's holders. For custom roles (role), the role's id rides along: roleheld:T(O, ROLE, S)."""
        lead: tuple[str | Var, ...] = (OBJ, ROLE) if role else (OBJ,)
        for st in dict.fromkeys(subjects):
            link = lit(linked, *lead, st.type, st.rel, SUB)
            out = Atom(head, (*lead, SES))
            if st.type == "anyone":
                self.add(out, lit(f"obj:{t.name}", OBJ), link, lit("session", SES))
            elif st.type == "link":
                self.add(out, lit(f"obj:{t.name}", OBJ), link, lit("token", SES, SUB))
            elif st.rel == "*":
                self.add(out, lit(f"obj:{t.name}", OBJ), link, lit("principal", SES, st.type, ANY))
            elif st.rel:
                self.add(out, lit(f"obj:{t.name}", OBJ), link, lit(has(st.type, st.rel), SUB, SES))
            else:
                self.add(out, lit(f"obj:{t.name}", OBJ), link, lit("principal", SES, st.type, SUB))
        if role:
            # an assignment of a custom role: a share of the relation role:<id>, to a subject the roles line lists
            for st in dict.fromkeys(subjects):
                if st.rel == "*" or st.type == "anyone":
                    self.add(
                        Atom(linked, (OBJ, ROLE, st.type, st.rel, "*")),
                        lit("roleshare", t.name, OBJ, ROLE, st.type, "*", ""),
                    )
                else:
                    self.add(
                        Atom(linked, (OBJ, ROLE, st.type, st.rel, SUB)),
                        lit("roleshare", t.name, OBJ, ROLE, st.type, SUB, st.rel),
                    )

    def fresh(self) -> str:
        self.counter += 1
        return f"e:{self.counter}"

    def expr(self, t: TypeDecl, e: Expr, defining: str | None) -> str:
        """A predicate p(O, S): the expression holds on t's object O for session S. defining: the permission it
        defines (what `roles` gives)."""
        p = self.fresh()
        match e:
            case Or(items=items):
                for x in items:
                    self.add(Atom(p, (OBJ, SES)), lit(self.expr(t, x, defining), OBJ, SES))
            case And(items=items):
                self.add(Atom(p, (OBJ, SES)), *(lit(self.expr(t, x, defining), OBJ, SES) for x in items))
            case Not(item=item):
                inner = self.expr(t, item, defining)
                self.add(
                    Atom(p, (OBJ, SES)),
                    lit(f"obj:{t.name}", OBJ),
                    lit("session", SES),
                    lit(inner, OBJ, SES, negated=True),
                )
            case Name(name=n) if n == "roles" and t.roles is not None and n not in t.relations and n not in t.perms:
                if defining is None:
                    raise Unreadable(f"{t.name}: roles outside a permission")
                body = [
                    lit(f"roleheld:{t.name}", OBJ, ROLE, SES),
                    lit("role", ROLE, OWNER_T, OWNER_I, t.name, defining),
                ]
                if t.roles_from:
                    body.append(lit(links(t.name, t.roles_from), OBJ, OWNER_T, "", OWNER_I))
                self.add(Atom(p, (OBJ, SES)), *body)
            case Name(name=n):
                if n not in t.relations and n not in t.perms:
                    raise Unreadable(f"{t.name} has no relation or permission {n}")
                self.add(Atom(p, (OBJ, SES)), lit(has(t.name, n), OBJ, SES))
            case Follow(rel=rel, perm=perm):
                if rel not in t.relations:
                    raise Unreadable(f"{t.name} has no relation {rel}")
                for st in dict.fromkeys(s for src in t.relations[rel] for s in src.subjects):
                    target = self.pol.types.get(st.type)
                    if st.rel or target is None or (perm not in target.perms and perm not in target.relations):
                        continue  # only relations to objects are followed (AZ301), to what has the name
                    self.add(
                        Atom(p, (OBJ, SES)),
                        lit(links(t.name, rel), OBJ, st.type, "", SUB),
                        lit(has(st.type, perm), SUB, SES),
                    )
            case Cond(text=c):
                self.add(Atom(p, (OBJ, SES)), lit(f"row:{t.name}", OBJ, ROW), lit("cond_as", t.table, c, ROW, SES))
            case Word(word="signed_in"):
                self.add(Atom(p, (OBJ, SES)), lit(f"obj:{t.name}", OBJ), lit("principal", SES, "user", ANY))
            case Word(word="anyone"):
                self.add(Atom(p, (OBJ, SES)), lit(f"obj:{t.name}", OBJ), lit("session", SES))
            case Word():
                pass  # nobody: no rule
        return p

    # ------------------------------------------------------------------
    def facts(self, world: World) -> dict[str, set[datalog.Fact]]:
        """The world as the facts the rules read."""
        out: dict[str, set[datalog.Fact]] = {
            k: set() for k in ("val", "cond", "cond_as", "share", "roleshare", "role", "session", "signs_in", "token")
        }
        for table, cols in self.groups:
            for i, row in enumerate(world.tables.get(table, [])):
                v = key_text(row, cols)
                if v is not None:
                    out["val"].add((table, str(i), ",".join(cols), v))
        sessions = [s.id for s in world.sessions]
        for table, c, i in world.conds:
            out["cond"].add((table, c, str(i)))
            for s in sessions:
                out["cond_as"].add((table, c, str(i), s))
        for table, c, i, s in world.conds_as:
            out["cond_as"].add((table, c, str(i), s))
        for sh in world.shares:
            if sh.ended or sh.starts_later or (sh.caveat and not sh.caveat_holds):
                continue  # a share in force now: not ended, started, its caveat holding
            if sh.relation.startswith("role:"):
                out["roleshare"].add(
                    (
                        sh.object_type,
                        sh.object_id,
                        sh.relation[5:],
                        sh.subject_type,
                        sh.subject_id,
                        sh.subject_relation,
                    )
                )
            else:
                out["share"].add(
                    (
                        sh.object_type,
                        sh.object_id,
                        sh.relation,
                        sh.subject_type,
                        sh.subject_id,
                        sh.subject_relation,
                    )
                )
        for role in world.roles:
            for perm in role.perms:
                out["role"].add((role.id, role.owner_type, role.owner_id, role.object_type, perm))
        for s in world.sessions:
            out["session"].add((s.id,))
            if s.principal_type is not None and s.principal_id is not None:
                out["signs_in"].add((s.id, s.principal_type, s.principal_id))
            for k in s.links:
                out["token"].add((s.id, k))
        return out


class Answers(NamedTuple):
    held: dict[tuple[str, str, str], frozenset[str]]  # (session, type, relation or permission) -> objects
    rules: list[dict[str, frozenset[str]]]  # each rule, in the policy's order: session -> rows (their keys)
    broken: list[frozenset[tuple[str, str]]]  # each invariant: (session, object) where it is broken


def evaluate(prog: Program, world: World) -> Answers:
    model = datalog.run(prog.rules, prog.facts(world))
    held: dict[tuple[str, str, str], frozenset[str]] = {}
    for t in prog.pol.types.values():
        for n in [*t.relations, *t.perms]:
            got: dict[str, set[str]] = {s.id: set() for s in world.sessions}
            for o, s in model.get(has(t.name, n), set()):
                got[s].add(o)
            for s, objs in got.items():
                held[(s, t.name, n)] = frozenset(objs)
    rules: list[dict[str, frozenset[str]]] = []
    for k in range(len(prog.pol.rules)):
        by: dict[str, set[str]] = {s.id: set() for s in world.sessions}
        for o, s in model.get(f"rule:{k}", set()):
            by[s].add(o)
        rules.append({s: frozenset(v) for s, v in by.items()})
    broken = [frozenset((s, o) for o, s in model.get(f"inv:{k}", set())) for k in range(len(prog.pol.invariants))]
    return Answers(held, rules, broken)

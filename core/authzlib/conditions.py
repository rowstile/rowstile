"""Simple conditions: the ones the reference evaluator reads as facts about a row's columns.

A condition such as `{not archived}`, `{role = 'admin'}`, `{kind in ('a', 'b')}`, `{parent_id is null}`,
`{size > 10}` or `{owner_id = authz.uid()}` says something about the row's own columns (and who is signed in).
Read that way, `{archived}` and `{not archived}` are each other's opposite (but for NULL), `{x = 'a'}` and
`{x in ('a')}` are the same, and `{owner_id = authz.uid()}` holds for one user and not another, as in the
database. Any other condition (a subquery, a function, arithmetic) is a set of rows of its own: the data says
which (evaluate.Data.cond).

The grammar: or < and < not < a comparison (`=`, `<>`, `!=`, `<`, `<=`, `>`, `>=`), `is [not] null`,
`[not] in (...)`, of a column (`col`, `this.col`) with a constant (`'text'`, a number, `true`, `false`, `null`)
or `authz.uid()`; a column alone is a boolean. Values follow SQL's three-valued logic: NULL compares to nothing.

A column is named as Postgres reads it: a bare name with its ASCII letters in lower case (`Archived` is `archived`,
`ARCHIVÉ` is `archivÉ`), a quoted one as written (`"Archived"`, `"order"`, `"a""b"` for a"b). A number is read
exactly, as Postgres reads it (numeric: `1.10` is `1.1`, a Decimal).

Only what means the same whatever the column's type and collation, which a condition doesn't say: no text in
order (`{name < 'b'}` follows the database's collation), no text Postgres would read as the column's number or
boolean (`{size = '10'}`, `{done = 't'}`), no number a numeric, a double precision and a real column don't all
hold as written (read: 0.5, 0.25, 1.5, 100; not 0.1, which a real column holds as 0.100000001, so
`0.1::real = 0.1` is false; not 1.00000000000000001, which is 1 in a double precision column; not 16777217,
which a real column rounds, nor 16777216, one more than which it rounds: the made-up rows hold the values around a
number too), no order against authz.uid() (the user key's type decides it). Those are left to the
database too. A column a relation reads holds the linked ids' text: compared with a number, as a number
(tests/conditions_test.py asks Postgres the same questions).
"""

from __future__ import annotations

import re
import struct
from collections.abc import Mapping
from decimal import Decimal
from functools import cache
from typing import NamedTuple, TypeAlias

from .sqlutil import NAME, fold

# a column's value in a made-up row (a number with a decimal point: a Decimal, exact, as Postgres's numeric)
Scalar: TypeAlias = "str | int | Decimal | bool | None"

# the most digits a number may be written with for the evaluator to read it: what a double precision column keeps
# (15); the made-up rows' numbers around it (one less, one more) are then exact in Decimal's 28 digits
DIGITS = 15
# the values the worlds draw for a column around a number it is compared with (evaluate.domains): one less, the
# number, one more, two past the largest; each must be one every numeric column holds as it is
AROUND = (-1, 0, 1, 2)


class Col(NamedTuple):
    name: str


class Const(NamedTuple):
    value: Scalar


class Uid(NamedTuple):
    """authz.uid(): the signed-in user's id, NULL for anyone else."""


class Cmp(NamedTuple):
    op: str
    left: Node
    right: Node


class IsNull(NamedTuple):
    item: Node
    negated: bool


class In(NamedTuple):
    item: Node
    values: tuple[Scalar, ...]
    negated: bool


class Bool(NamedTuple):
    op: str  # and | or | not
    items: tuple[Node, ...]


Node: TypeAlias = "Col | Const | Uid | Cmp | IsNull | In | Bool"

TOKEN = re.compile(
    r"\s*(?:(?P<str>'(?:[^']|'')*')|(?P<num>\d+(?:\.\d+)?)(?![\w.])|"
    r'(?P<uid>authz\s*\.\s*uid\s*\(\s*\))|(?P<quoted>(?:this\s*\.\s*)?"(?:[^"]|"")+")|'
    rf"(?P<name>(?:this\s*\.\s*)?{NAME})|"
    r"(?P<op><>|!=|<=|>=|=|<|>)|(?P<p>[(),]))",
    re.IGNORECASE,
)
WORDS = ("and", "or", "not", "is", "null", "in", "true", "false")


class NotSimple(Exception):
    pass


def tokens(sql: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    i = 0
    while i < len(sql):
        if sql[i:].strip() == "":
            break
        m = TOKEN.match(sql, i)
        if not m or m.end() == i:
            raise NotSimple(sql[i:])
        kind = m.lastgroup or ""
        text = m.group(kind)
        if kind == "name":
            name = re.sub(r"^this\s*\.\s*", "", text, flags=re.IGNORECASE)
            kind, text = ("word", fold(name)) if fold(name) in WORDS and name == text else ("name", fold(name))
        elif kind == "quoted":  # a quoted name: as written, its case kept ("B1", "order", "a""b")
            name = re.sub(r"^this\s*\.\s*", "", text, flags=re.IGNORECASE)
            kind, text = "name", name[1:-1].replace('""', '"')
        out.append((kind, text))
        i = m.end()
    return out


class Parser:
    def __init__(self, sql: str) -> None:
        self.toks, self.i = tokens(sql), 0

    def peek(self, kind: str, text: str | None = None) -> bool:
        if self.i >= len(self.toks):
            return False
        k, t = self.toks[self.i]
        return k == kind and (text is None or t == text)

    def take(self, kind: str, text: str | None = None) -> str:
        if not self.peek(kind, text):
            raise NotSimple(str(self.toks[self.i :]))
        self.i += 1
        return self.toks[self.i - 1][1]

    def parse(self) -> Node:
        node = self.or_()
        if self.i != len(self.toks):
            raise NotSimple(str(self.toks[self.i :]))
        return node

    def or_(self) -> Node:
        items = [self.and_()]
        while self.peek("word", "or"):
            self.take("word")
            items.append(self.and_())
        return items[0] if len(items) == 1 else Bool("or", tuple(items))

    def and_(self) -> Node:
        items = [self.not_()]
        while self.peek("word", "and"):
            self.take("word")
            items.append(self.not_())
        return items[0] if len(items) == 1 else Bool("and", tuple(items))

    def not_(self) -> Node:
        if self.peek("word", "not"):
            self.take("word")
            return Bool("not", (self.not_(),))
        return self.test()

    def test(self) -> Node:
        left = self.operand()
        if self.peek("op"):
            return Cmp(self.take("op").replace("!=", "<>"), left, self.operand())
        if self.peek("word", "is"):
            self.take("word")
            negated = self.peek("word", "not")
            if negated:
                self.take("word")
            self.take("word", "null")
            return IsNull(left, negated)
        negated = self.peek("word", "not") and self.i + 1 < len(self.toks) and self.toks[self.i + 1] == ("word", "in")
        if negated:
            self.take("word")
        if self.peek("word", "in"):
            self.take("word")
            self.take("p", "(")
            values = [self.constant()]
            while self.peek("p", ","):
                self.take("p")
                values.append(self.constant())
            self.take("p", ")")
            return In(left, tuple(values), negated)
        return left  # (`not` was taken only before an `in`)

    def operand(self) -> Node:
        if self.peek("p", "("):
            self.take("p")
            node = self.or_()
            self.take("p", ")")
            return node
        if self.peek("name"):
            return Col(self.take("name"))
        if self.peek("uid"):
            self.take("uid")
            return Uid()
        return Const(self.constant())

    def constant(self) -> Scalar:
        if self.peek("str"):
            return self.take("str")[1:-1].replace("''", "'")
        if self.peek("num"):
            text = self.take("num")
            exact = Decimal(text)
            # a column of some type holds it, or a value the worlds draw around it, otherwise: the database's
            if written(exact) > DIGITS or not all(held(exact + k) for k in AROUND):
                raise NotSimple(text[:40])
            return exact if "." in text else int(text)
        if self.peek("word", "true") or self.peek("word", "false"):
            return self.take("word") == "true"
        if self.peek("word", "null"):
            self.take("word")
            return None
        raise NotSimple(str(self.toks[self.i :]))


# text Postgres reads as a number when the column is one ('10', ' 1.5e3', '0x1A', 'NaN'), or as a boolean: these
# words, any start of them ('t', 'of'), whatever the case
CASTS = re.compile(
    r"\s*[+-]?(?:\d[\d_]*(?:\.[\d_]*)?(?:e[+-]?\d+)?|\.\d[\d_]*(?:e[+-]?\d+)?|0[xob][\da-f_]+|nan|inf|infinity)\s*",
    re.IGNORECASE,
)
BOOLEANS = ("true", "false", "yes", "no", "on", "off", "1", "0")


def plain(v: Scalar) -> bool:
    """Whether a constant means the same whatever the column's type: not text Postgres could read as a number or
    a boolean."""
    if not isinstance(v, str):
        return True
    word = v.strip().lower()
    return not (CASTS.fullmatch(v) or (word and any(b.startswith(word) for b in BOOLEANS)))


def written(d: Decimal) -> int:
    """How many digits d takes written out, without its sign, leading zeros or zeros after its last digit:
    1.50 -> 2, 0.001 -> 4 (0.001), 1000 -> 4."""
    d = abs(d).normalize()
    exponent = d.as_tuple().exponent
    assert isinstance(exponent, int)  # (a number the parser read: not NaN or infinity)
    return max(d.adjusted(), 0) - min(exponent, 0) + 1


def held(d: Decimal) -> bool:
    """Whether a numeric, a double precision and a real column all hold d as it is: its value is the same as a
    float8 and as a float4 (0.5, 0.25, 16777216; not 0.1, nor 16777217, which a real column rounds)."""
    x = float(d)
    return Decimal(x) == d and struct.unpack("f", struct.pack("f", x))[0] == x


def number(v: Scalar) -> Decimal | None:
    """A number as one, and so a linked id's text that is one ('10': owner_id holds the id of its user)."""
    if isinstance(v, bool) or v is None:
        return None
    if isinstance(v, Decimal):
        return v
    # (Decimal reads every int as text, and every run of digits, whatever the script)
    return Decimal(str(v)) if isinstance(v, int) or re.fullmatch(r"-?\d+", v) else None


@cache
def simple(sql: str) -> Node | None:
    """The condition as facts about its row's columns, or None when it is more than that."""
    try:
        node = Parser(sql).parse()
    except NotSimple:
        return None

    # a column compared with a column, or a constant on its own, is not one the evaluator reads
    def fine(n: Node) -> bool:
        match n:
            case Cmp(op=op, left=a, right=b):
                ordered = op not in ("=", "<>")
                return (
                    sum(isinstance(x, Col) for x in (a, b)) == 1
                    and all(isinstance(x, (Col, Const, Uid)) for x in (a, b))
                    and all(
                        plain(x.value) and not (ordered and isinstance(x.value, str))
                        for x in (a, b)
                        if isinstance(x, Const)
                    )
                    and not (ordered and any(isinstance(x, Uid) for x in (a, b)))
                )
            case In(item=x, values=values):
                return isinstance(x, Col) and all(plain(v) for v in values)
            case IsNull(item=x):
                return isinstance(x, Col)
            case Bool(items=items):
                return all(fine(x) for x in items)
            case Col():
                return True
        return False

    return node if fine(node) else None


def columns_of(node: Node) -> dict[str, list[tuple[str, Scalar]]]:
    """Each column the condition reads, with how: ('bool', None) used alone, ('=', 'a') compared with a constant,
    ('uid', None) compared with authz.uid(), ('in', 'a') listed, ('null', None) tested for NULL."""
    out: dict[str, list[tuple[str, Scalar]]] = {}

    def add(col: str, how: str, value: Scalar = None) -> None:
        out.setdefault(col, []).append((how, value))

    def walk(n: Node) -> None:
        match n:
            case Col(name=c):
                add(c, "bool")
            case Cmp(op=op, left=a, right=b):
                col, other = (a, b) if isinstance(a, Col) else (b, a)
                assert isinstance(col, Col)
                if isinstance(other, Uid):
                    add(col.name, "uid")
                else:
                    assert isinstance(other, Const)  # (simple() compares a column with a constant or authz.uid())
                    add(col.name, op, other.value)
            case IsNull(item=Col(name=c)):
                add(c, "null")
            case In(item=Col(name=c), values=values):
                for v in values:
                    add(c, "in", v)
            case _:
                assert isinstance(n, Bool), f"not a condition: {n!r}"  # (simple() gives nothing else)
                for x in n.items:
                    walk(x)

    walk(node)
    return out


def order(op: str, sign: int) -> bool:
    """op on two values whose comparison gives sign (-1, 0, 1)."""
    return {"=": sign == 0, "<>": sign != 0, "<": sign < 0, "<=": sign <= 0, ">": sign > 0, ">=": sign >= 0}[op]


def compare(op: str, a: Scalar, b: Scalar) -> bool | None:
    """a op b as SQL compares them: NULL with anything is NULL; a number with a number (or an id's text that is
    one) as numbers, the rest as their text."""
    if a is None or b is None:
        return None
    x, y = number(a), number(b)
    if x is not None and y is not None and not (isinstance(a, str) and isinstance(b, str)):
        return order(op, (x > y) - (x < y))
    s, t = str(a).lower() if isinstance(a, bool) else str(a), str(b).lower() if isinstance(b, bool) else str(b)
    return order(op, (s > t) - (s < t))


def value(n: Node, row: Mapping[str, Scalar], uid: str | None) -> Scalar:
    """An operand's value: a column's, a constant, or the user's id (simple() compares nothing else)."""
    match n:
        case Col(name=c):
            return row.get(c)
        case Const(value=v):
            return v
        case _:
            assert isinstance(n, Uid), f"not an operand: {n!r}"
            return uid


def truth(n: Node, row: Mapping[str, Scalar], uid: str | None) -> bool | None:
    """The condition on one row, as SQL says it: True, False or NULL (None)."""
    match n:
        case Col(name=c):
            v = row.get(c)
            return v if isinstance(v, bool) or v is None else None
        case Cmp(op=op, left=a, right=b):
            return compare(op, value(a, row, uid), value(b, row, uid))
        case IsNull(item=x, negated=neg):
            return (value(x, row, uid) is not None) if neg else (value(x, row, uid) is None)
        case In(item=x, values=values, negated=neg):
            v = value(x, row, uid)
            if v is None:
                return None
            hit = any(compare("=", v, w) for w in values if w is not None)
            if hit:
                return not neg
            return None if any(w is None for w in values) else neg
        case Bool(op="not", items=(x,)):
            t = truth(x, row, uid)
            return None if t is None else not t
        case Bool(op="and", items=items):
            got = [truth(x, row, uid) for x in items]
            return False if False in got else (None if None in got else True)
        case _:
            assert isinstance(n, Bool) and n.op == "or", f"not a condition: {n!r}"  # (simple() gives nothing else)
            got = [truth(x, row, uid) for x in n.items]
            return True if True in got else (None if None in got else False)


def uses_uid(node: Node) -> bool:
    return any(how == "uid" for hows in columns_of(node).values() for how, _ in hows)

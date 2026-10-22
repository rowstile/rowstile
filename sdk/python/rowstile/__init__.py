"""rowstile for Python apps.

Every transaction signs in as whoever the request (or the job) acts for, with `authz.act_as()`; the database's
refusals become `Refused` (a 403 with the reason), rows the user can't see become `NotFound` (a 404). The
package holds no rowstile logic: it calls the `authz.*` functions the policy made, and translates their answers.

    import rowstile
    with rowstile.acting_as(42):                  # or ("service", 3), or None for nobody
        ...                                       # every transaction in here signs in as user 42

The integrations: `rowstile.fastapi` (one line: Rowstile(app, engine, user=...)), `rowstile.sqlalchemy` (sync
and async engines, SQLModel too), `rowstile.psycopg`, `rowstile.asyncpg`, `rowstile.alembic` (autogenerate
leaves rowstile's objects alone) and `rowstile.testing` (pytest fixtures).
"""

from __future__ import annotations

import contextlib
import contextvars
import enum
import re
from collections.abc import Callable, Iterable, Iterator, Sequence
from dataclasses import dataclass
from typing import LiteralString, ParamSpec, TypeAlias, TypeVar, cast

from ._version import __version__

Id: TypeAlias = "int | str"
# who a transaction acts for: 42, '42' (a user, whatever the id holds), ('service', 3), a Principal, or None (nobody)
Who: TypeAlias = "Principal | Id | tuple[str, Id | None] | None"
Problem: TypeAlias = "dict[str, str | int | list[str] | None]"  # an RFC 9457 problem body
P = ParamSpec("P")
R = TypeVar("R")


@dataclass(frozen=True)
class Principal:
    """Who a transaction acts for: a user (type 'user'), another principal type the policy declares
    (a service, a bot), or nobody (id None: only what `anyone` may see)."""

    type: str = "user"
    id: str | None = None

    @classmethod
    def of(cls, who: Who) -> Principal:
        """42, '42', ('service', 3), a Principal, or None (nobody). A plain id is a user's, whatever it holds:
        'service:3' is the user whose id that is (ids often come from outside: a username, an identity
        provider's subject), never service 3. Another principal type is named: ('service', 3)."""
        if isinstance(who, Principal):
            return who
        if who is None:
            return NOBODY
        if isinstance(who, tuple):
            kind, pid = who
            return cls(str(kind), None if pid is None else str(pid))
        return cls("user", str(who))

    @classmethod
    def parse(cls, text: str) -> Principal:
        """What str() wrote, read back: 'service:3' is service 3, '42' and 'user:42' user 42, 'nobody' nobody.
        For text your own code wrote (a job's argument) and for who acted in the audit trail (its user_id, a
        share's created_by), which the database writes the same way; not for an id that came from outside."""
        if text == "nobody":
            return NOBODY
        if ":" in text and not text.startswith("("):
            kind, pid = text.split(":", 1)
            return cls(kind, pid)
        return cls("user", text)

    def __str__(self) -> str:
        """'42', 'service:3' or 'nobody'. A user whose id holds ':' or is 'nobody' is 'user:<id>' ('user:a:b'),
        so that parse() reads every principal back as itself."""
        if self.id is None:
            return "nobody"
        if self.type != "user":
            return f"{self.type}:{self.id}"
        return f"user:{self.id}" if ":" in self.id or self.id == "nobody" else self.id


NOBODY = Principal("user", None)
_current: contextvars.ContextVar[Principal | None] = contextvars.ContextVar("rowstile_principal", default=None)


class _Unset(enum.Enum):
    UNSET = "unset"  # an argument left out: whoever the code acts for now


_UNSET = _Unset.UNSET


def current() -> Principal | None:
    """Who the code running now acts for (set by acting_as, the web integration or a job), or None if unset."""
    return _current.get()


@contextlib.contextmanager
def acting_as(who: Who) -> Iterator[Principal | None]:
    """Everything in the block (every transaction the integrations begin) acts for `who`."""
    token = _current.set(Principal.of(who))
    try:
        yield _current.get()
    finally:
        _current.reset(token)


def job(who: Who) -> Callable[[Callable[P, R]], Callable[P, R]]:
    """A decorator for background jobs (Celery, RQ, FastAPI's BackgroundTasks): the job acts for `who`, e.g.
    @rowstile.job(("service", 3)). Async functions work too."""
    import functools
    import inspect

    def wrap(fn: Callable[P, R]) -> Callable[P, R]:
        if inspect.iscoroutinefunction(fn):
            coroutine = fn

            @functools.wraps(fn)
            async def run_async(*a: P.args, **kw: P.kwargs) -> object:
                with acting_as(who):
                    return await coroutine(*a, **kw)

            return cast("Callable[P, R]", run_async)  # R is the coroutine run_async returns too

        @functools.wraps(fn)
        def run(*a: P.args, **kw: P.kwargs) -> R:
            with acting_as(who):
                return fn(*a, **kw)

        return run

    return wrap


def literal(value: object) -> str:
    """A SQL string literal that means the same whatever standard_conforming_strings says (a role, a database or
    a session may turn it off): quotes doubled, and a value holding a backslash written E'...' with its
    backslashes doubled, so that no backslash can end the string early."""
    if value is None:
        return "NULL"
    text = str(value).replace("'", "''")
    return "E'" + text.replace("\\", "\\\\") + "'" if "\\" in text else "'" + text + "'"


def act_as_args(who: Who | _Unset = _UNSET) -> tuple[str | None, str | None]:
    """authz.act_as's arguments, (type, id): ('user', '42'), or (None, None) for nobody (who is None). With
    no argument, as whoever the code acts for now (nobody if unset)."""
    p = (current() or NOBODY) if isinstance(who, _Unset) else Principal.of(who)
    return (None, None) if p.id is None else (p.type, p.id)


def act_as_sql(who: Who | _Unset = _UNSET) -> str:
    """The statement that signs a transaction in: SELECT authz.act_as('user', '42'); None is nobody. With no
    argument, as whoever the code acts for now (nobody if unset). The values are written into the statement:
    where the driver takes parameters, pass act_as_args() instead (psycopg reads % in a statement)."""
    kind, pid = act_as_args(who)
    return f"SELECT authz.act_as({literal(kind)}, {literal(pid)})"


# --- errors -------------------------------------------------------------------------------------------
class Refused(Exception):
    """The database refused a write, and said why: the rule (table and command), and the explanation."""

    code = "AZ709"  # rowstile help AZ709: a rule's refusal; the database's own for another (AZ705: a share)

    def __init__(
        self,
        message: str,
        table: str | None = None,
        command: str | None = None,
        why: Sequence[str] = (),
        code: str | None = None,
    ) -> None:
        super().__init__(message)
        self.message, self.table, self.command, self.why = message, table, command, list(why)
        if code:
            self.code = code

    def problem(self) -> Problem:
        """An RFC 9457 problem body for a 403."""
        return {
            "type": "https://rowstile.dev/problems/refused",
            "title": "Forbidden",
            "status": 403,
            "detail": self.message,
            "table": self.table,
            "command": self.command,
            "why": self.why,
            "code": self.code,
        }


class NotFound(Exception):
    """The row isn't there, or whoever the transaction acts for can't see it."""

    def __init__(self, table: str | None = None, id_: object = None) -> None:
        self.table, self.id = table, key_shown(id_)
        # 'app.notes 7 not found', 'app.notes not found', 'row 7 not found', or 'not found'
        named = [table or "row", self.id] if self.id is not None else [table] if table else []
        super().__init__(" ".join([*named, "not found"]))

    def problem(self) -> Problem:
        return {
            "type": "https://rowstile.dev/problems/not-found",
            "title": "Not Found",
            "status": 404,
            "detail": str(self),
        }


class NotSignedIn(Exception):
    """A query that needs to know who is asking ran in a transaction nobody signed in to (strict sign-in)."""

    code = "AZ701"  # rowstile help AZ701


class ConnectionProblem(RuntimeError):
    """authz.connection_check() found that the app's connection skips row-level security (or worse)."""

    def __init__(self, problems: Iterable[str]) -> None:
        self.problems = list(problems)
        super().__init__("the app's database connection can't be used with rowstile: " + "; ".join(self.problems))


def _db_error(exc: BaseException) -> list[BaseException]:
    """The error and the driver's errors inside it: SQLAlchemy keeps the driver's in .orig, and its asyncpg
    adapter keeps asyncpg's own as the cause of that."""
    out: list[BaseException] = []
    seen: set[int] = set()
    todo: list[BaseException | None] = [exc]
    while todo:
        e = todo.pop(0)
        if e is None or id(e) in seen:
            continue
        seen.add(id(e))
        out.append(e)
        todo += [getattr(e, "orig", None), e.__cause__]
    return out


def _field(errs: list[BaseException], *names: str) -> str | None:
    for err in errs:
        for n in names:
            v = getattr(err, n, None)
            if v and isinstance(v, str):
                return v
            diag = getattr(err, "diag", None)
            v = getattr(diag, n, None) if diag is not None else None
            if v:
                return str(v)
    return None


def error_code(exc: BaseException) -> str | None:
    """rowstile's code for a database error (AZ709; `rowstile help AZ709` says what it means): from its HINT,
    where the runtime puts it, or its message. None for an error rowstile didn't raise."""
    import re

    errs = _db_error(exc)
    for text in (_field(errs, "message_hint", "hint"), _field(errs, "message_primary", "message") or str(errs[-1])):
        m = re.search(r"rowstile help (AZ\d{3})", text or "")
        if m:
            return m.group(1)
    return None


# rowstile's codes for a call the database turned down that is no refusal, and what their pages say to answer
# (rowstile help AZ703: a login refused; AZ708: what the call names isn't there; AZ710: a missing or wrong
# argument; AZ713: moved inside itself; AZ714: sign in first)
_CALL_PROBLEMS: dict[str, tuple[str, str, int]] = {
    "AZ703": ("https://rowstile.dev/problems/not-signed-in", "Unauthorized", 401),
    "AZ708": ("https://rowstile.dev/problems/not-found", "Not Found", 404),
    "AZ710": ("https://rowstile.dev/problems/bad-argument", "Bad Request", 400),
    "AZ713": ("https://rowstile.dev/problems/conflict", "Conflict", 409),
    "AZ714": ("https://rowstile.dev/problems/not-signed-in", "Unauthorized", 401),
}


def call_problem(exc: BaseException) -> Problem | None:
    """The problem body for a database error that is no refusal and answers as its code's page says: a login
    refused or a call that needs someone signed in (AZ703, AZ714: 401), something the call names isn't there
    (AZ708: a share with someone who doesn't exist, 404), an argument missing or wrong (AZ710: a negative page
    size, 400), a move inside itself (AZ713: 409); with the database's words. None for any other error."""
    code = error_code(exc)
    if code is None or code not in _CALL_PROBLEMS:
        return None
    kind, title, status = _CALL_PROBLEMS[code]
    errs = _db_error(exc)
    detail = _field(errs, "message_primary", "message") or str(errs[-1]).split("\n")[0]
    return {"type": kind, "title": title, "status": status, "detail": detail, "code": code}


def sqlstate(exc: BaseException) -> str | None:
    err = _db_error(exc)
    return _field(err, "sqlstate", "pgcode")


_UNSEEN = (
    "this user may not see the row as written (the select rule). An insert that reads it back (RETURNING), "
    "an upsert, and an update with a WHERE need to see it."
)


def refusal(exc: BaseException) -> Refused | None:
    """A Refused for an error that is the database refusing a write (SQLSTATE 42501, raised by rowstile's
    policies with the rule and why), else None. psycopg, psycopg2 and asyncpg, bare or in SQLAlchemy's.
    Another 42501 (a table the app role was never granted) is the app's mistake, not a refusal: None."""
    err = _db_error(exc)
    if _field(err, "sqlstate", "pgcode") != "42501":
        return None
    message = _field(err, "message_primary", "message") or str(err[-1]).split("\n")[0]
    code = error_code(exc)
    # Postgres's own words, not rowstile's: a check of a row no rule's own refusal covers. Postgres names the table
    # without its schema, and sets no field for it
    generic = re.match(
        r'(new|target) row violates row-level security policy (\(USING expression\) )?for table "([^"]+)"', message
    )
    if code is None and not generic:
        return None
    if code in _CALL_PROBLEMS:  # sign in first (AZ714) is a 42501 too, but no refusal: a 401
        return None
    if generic:
        row, existing, name = generic.groups()
        if row == "target":
            # MERGE matched a row the update or the delete rule hides; Postgres doesn't say which
            return Refused(
                f"{message}: MERGE matched a row the update or delete rule doesn't let this user change", name
            )
        if existing:
            # an upsert (INSERT ... ON CONFLICT DO UPDATE) whose existing row this user may not update, or not see
            return Refused(
                f"{message}: the row is there already, and the update rule (or the select rule) doesn't let this "
                "user change it (ON CONFLICT DO UPDATE)",
                name,
                "update",
            )
        # the select rule, on the row as written: an insert that reads it back (RETURNING, or an ORM that reads the
        # new row), an upsert, or an update after which the row would be out of this user's sight
        return Refused(f"{message}: {_UNSEEN}", name, "select")
    detail = _field(err, "message_detail", "detail") or ""
    schema, table = _field(err, "schema_name"), _field(err, "table_name")
    constraint = _field(err, "constraint_name") or ""
    return Refused(
        message,
        f"{schema}.{table}" if schema and table else table,
        constraint[6:] if constraint.startswith("authz_") else None,
        detail.split("\n") if detail else [],
        code,
    )


def not_signed_in(exc: BaseException) -> bool:
    """Whether exc is strict sign-in's error (rowstile help AZ701): a query that needs to know who is asking ran in
    a transaction nobody signed in to. A login refused (AZ703) and settings changed by hand (AZ702) share its
    SQLSTATE, 28000, but are no such thing."""
    return sqlstate(exc) == "28000" and error_code(exc) in (None, "AZ701")


def check_problems(rows: Iterable[tuple[str, str]]) -> list[str]:
    """The errors among authz.connection_check()'s rows (severity, problem)."""
    return [problem for severity, problem in rows if severity == "error"]


def _field_text(value: object) -> str:
    """One field of a row as Postgres writes it, quoted: a comma, a quote or a space in it stays in its field."""
    if value is None:
        return ""
    return '"' + str(value).replace("\\", "\\\\").replace('"', '\\"') + '"'


def key_text(key: object) -> str | None:
    """A row's key as the database compares it: one value, or a composite key as Postgres writes a row."""
    if isinstance(key, (tuple, list)):
        if len(key) != 1:
            return "(" + ",".join(_field_text(v) for v in key) + ")"
        key = key[0]
    return None if key is None else str(key)


def key_shown(key: object) -> str | None:
    """A row's key as the database writes it, for a message: 7, or (1,2) for a composite key (a field is
    quoted only where Postgres would: when it is empty or holds a comma, a quote, a parenthesis or a space)."""
    if isinstance(key, (tuple, list)):
        if len(key) != 1:
            return "(" + ",".join(_field_shown(v) for v in key) + ")"
        key = key[0]
    return None if key is None else str(key)


def _field_shown(value: object) -> str:
    if value is None:
        return ""
    text = str(value)
    if text == "" or any(ch in text for ch in '",\\()') or any(ch.isspace() for ch in text):
        return '"' + text.replace("\\", "\\\\").replace('"', '""') + '"'
    return text


def explain_rule_args(table: str, command: str, key: object) -> tuple[str, str, str | None]:
    """authz.explain_rule's arguments for a row's key: one value, or several (a composite key's row text)."""
    return table, command, key_text(key)


def explain_rule_sql(table: LiteralString, command: LiteralString, key: LiteralString) -> LiteralString:
    """SELECT authz.explain_rule($1, $2, $3, NULL) with the driver's placeholders for the table, the command and
    the key (':t', '%(t)s', '$1'), in a second column who is signed in, in the words the database's own
    refusals use ('user 2', 'service 3', 'someone not signed in'), and in a third the table as the policy names
    it. The policy names tables with their schema; a table named without one (a model that names no schema) is
    looked up on the search_path."""
    found = (
        "SELECT n.nspname || '.' || c.relname FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n "
        f"ON n.oid = c.relnamespace WHERE position('.' in {table}) = 0 "
        f"AND c.oid = pg_catalog.to_regclass(pg_catalog.quote_ident({table}))"
    )
    who = (
        "coalesce((SELECT p.principal_type || ' ' || p.principal_id FROM authz.principal() p), 'someone not signed in')"
    )
    return (
        f"SELECT authz.explain_rule(t.tbl, {command}, {key}, NULL), {who}, t.tbl "
        f"FROM (SELECT coalesce(({found}), {table}) AS tbl) t"
    )


def answer(row: Sequence[object] | None) -> tuple[Sequence[str] | None, str | None, str | None]:
    """A row of explain_rule_sql's statement: authz.explain_rule's lines (None: the row isn't there for this
    user), who is signed in, and the table as the policy names it."""
    if row is None:
        return None, None, None
    lines, who, named = row[0], row[1] if len(row) > 1 else None, row[2] if len(row) > 2 else None
    return (
        None if lines is None else [str(x) for x in cast("Iterable[object]", lines)],
        None if who is None else str(who),
        None if named is None else str(named),
    )


def verdict(
    table: str,
    command: str,
    key: object,
    lines: Sequence[str] | None,
    who: str | None = None,
    named: str | None = None,
) -> NotFound | Refused:
    """What an UPDATE or DELETE that changed nothing was: NotFound when the row isn't there for this user
    (authz.explain_rule answered NULL), or when the rule allows the write (its first line says yes: the
    statement matched nothing for another reason, such as a WHERE with more than the key); Refused, with
    why, otherwise. Worded as the database words a refused insert: 'permission denied: user 2 may not update
    row 7 of app.notes'. who: as answer() read it; left out, whoever the code acts for now. named: the table
    as the policy names it, as answer() read it ('public.notes' for a model that says 'notes'), so an update's
    refusal names the table as an insert's does."""
    table = named or table
    if lines is None or (lines and lines[0].lstrip().startswith("yes")):
        return NotFound(table, key)
    if who is None:
        p = current() or NOBODY
        who = "someone not signed in" if p.id is None else f"{p.type} {p.id}"
    message = f"permission denied: {who} may not {command} row {key_shown(key)} of {table}"
    return Refused(message, table, command, lines)


__all__ = [
    "NOBODY",
    "ConnectionProblem",
    "Id",
    "NotFound",
    "NotSignedIn",
    "Principal",
    "Problem",
    "Refused",
    "Who",
    "__version__",
    "act_as_args",
    "act_as_sql",
    "acting_as",
    "current",
    "error_code",
    "job",
    "not_signed_in",
    "refusal",
    "sqlstate",
    "verdict",
]

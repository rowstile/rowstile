"""What the rowstile command does to a database: apply a policy, preview it, test it, draft one, remove it.

The compiler runs here, outside the database; the database only runs the SQL it writes.
Every function takes `db`, a connection.Db:

    db.rows(sql, args=())    one statement with $1..$n parameters; a list of dicts
    db.script(sql)           many statements, no parameters (the compiled policy)
    db.warn(message, detail=None, hint=None)
    db.errors                the exception class the server's errors are raised as

and runs in the caller's transaction, so an error anywhere undoes everything the call did.
"""

from __future__ import annotations

import contextlib
import json
import re
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from typing import TYPE_CHECKING, TypeAlias, TypedDict, TypeVar

from . import __version__
from .connection import Db, Value, flag, number, text, text_or_none
from .parse import KEYWORDS, And, Cond, Expr, Loc, Not, Or, PolicyError, braced, parse_policy, read_lines
from .sqlutil import (
    CAVEAT_ARG,
    DROP_MASKED_VIEWS,
    DROP_OLD_POLICIES,
    IF_PARTITIONED,
    LOST_RULES,
    POLICY_MARKS,
    lit,
    q,
    qt,
    row_cond,
    sql_code,
    this_spans,
    with_uid,
)
from .versions import STAGES, VERSION, stage

# The compiler, migrate.py and statements.py are imported in the functions that use them, and so is BUILD
# (authzlib.__getattr__): a command that only asks the database (can, lint) or only reads the policy doesn't load them.
if TYPE_CHECKING:
    from . import migrate
    from .assembled import Compiler
    from .coverage import Report
    from .grant import Answer

T = TypeVar("T")
# included files: name -> text
Files: TypeAlias = "dict[str, str]"
# a policy test's check: (test, line, ok, detail)
TestRow: TypeAlias = "tuple[str, str | None, bool, str | None]"


class LintRow(TypedDict):
    severity: str
    object: str
    problem: str


class DiffRow(TypedDict):
    change: str  # gains | loses
    user_id: str | None  # None: someone not signed in
    type: str
    what: str
    id: str


class ReviewRun(TypedDict):
    deployed: float | None  # seconds the deploy took; None: it failed
    error: str | None
    tests: list[TestRow]
    how: dict[
        tuple[str, str, str, str], list[str]
    ]  # (user, type, id, perm) -> the lines of authz.explain that grant it


class Error(Exception):
    """A mistake the caller has to fix, with the SQLSTATE the old SQL functions raised."""

    def __init__(self, message: str, sqlstate: str = "P0001", hint: str | None = None) -> None:
        super().__init__(message)
        self.sqlstate, self.hint = sqlstate, hint


def older_than(mine: str, theirs: str | None) -> bool:
    """Whether the build `mine` is surely older than `theirs`: an earlier X.Y.Z, or the same one at an earlier
    stage (its alphas, then its betas, then its release candidates, then the release; versions.STAGES). A -dev
    build is somewhere before its X.Y.Z and can't be placed among that version's stages, so it is never called
    older than one of them."""
    a, b = VERSION.fullmatch(mine.split("+", 1)[0]), VERSION.fullmatch((theirs or "").split("+", 1)[0])
    if not a or not b:
        return False
    core_a, core_b = [int(x) for x in a.group(1, 2, 3)], [int(x) for x in b.group(1, 2, 3)]
    if core_a != core_b:
        return core_a < core_b
    if a.group(6) or b.group(6):
        return False
    stage_a = (stage(a.group(4)), int(a.group(5))) if a.group(4) else (len(STAGES), 0)
    stage_b = (stage(b.group(4)), int(b.group(5))) if b.group(4) else (len(STAGES), 0)
    return stage_a < stage_b


def refuse_older(theirs: str | None, what: str) -> None:
    """An older command would put its own, older work in place of a newer version's, as if it were an upgrade."""
    from . import BUILD

    if older_than(BUILD, theirs):
        raise Error(
            f"{what} was last written by rowstile {theirs}, which is newer than this command "
            f"({__version__}): going on would put this older version's work back [AZ616]",
            "55000",
            hint="upgrade the rowstile command; to go back to this version on purpose, add --downgrade",
        )


def files_map(files: Mapping[str, object] | str | None) -> Files:
    if files is None:
        return {}
    given: object = json.loads(files) if isinstance(files, str) else files
    if not isinstance(given, Mapping) or not all(isinstance(v, str) for v in given.values()):
        raise PolicyError('files must be a map of file name -> policy text, e.g. {"roles.authz": "..."}', "AZ108")
    return {str(k): str(v) for k, v in given.items()}


def build(policy: str, files: Mapping[str, object] | str | None, make: Callable[[Compiler], T]) -> T:
    """make(compiler) with the policy parsed. Raises PolicyError, naming the file and line."""
    from . import Compiler

    return make(Compiler(parse_policy(policy, None, files=files_map(files))))


def compiled(policy: str, files: Mapping[str, object] | str | None, make: Callable[[Compiler], T]) -> T:
    """build(), with policy mistakes turned into an Error."""
    try:
        return build(policy, files, make)
    except PolicyError as e:
        raise Error(f"policy {e}", "42P17") from None


def check(policy: str, files: Mapping[str, object] | str | None = None) -> str | None:
    """The first mistake in the policy (None if none), its own tests included. Only what can be checked without a
    database: tables and columns that don't exist are reported by apply() and diff()."""

    def make(c: Compiler) -> None:
        c.compile("the policy", transaction=False)
        c.tests_function_sql()

    try:
        build(policy, files, make)
    except PolicyError as e:
        return f"policy {e}"
    return None


@contextlib.contextmanager
def savepoint(db: Db, name: str = "authz_sp") -> Iterator[None]:
    """A subtransaction: undone if the block raises, kept otherwise. When undoing it fails too (the server ended the
    session, and the block's error says why), the block's error is raised; for Undo, which asks for the undoing, the
    failure to undo. Not on Ctrl-C (KeyboardInterrupt), which may come in the middle of a statement: the command's
    transaction is ended then (its statement cancelled on the server), where a ROLLBACK TO sent behind the statement
    would wait for it to run its course."""
    db.script(f"SAVEPOINT {name}")
    try:
        yield
    except Exception as e:
        try:
            db.script(f"ROLLBACK TO SAVEPOINT {name}; RELEASE SAVEPOINT {name}")
        except Exception:
            if isinstance(e, Undo):
                raise
            raise e from None
        raise
    db.script(f"RELEASE SAVEPOINT {name}")


def may_take(db: Db, role: str | None) -> None:
    """Refuses, saying what to run, when this connection may not switch to the app role (SET ROLE), which the
    commands that look at the data as the app does need. Since PostgreSQL 16 a role only administers the roles
    it makes, so an owner that isn't a superuser gives itself the app role once."""
    if role is None:
        return
    rows = db.rows(
        "SELECT current_user::text AS me, pg_catalog.pg_has_role(current_user, r.oid, 'SET') AS ok "
        "FROM pg_catalog.pg_roles r WHERE r.rolname = $1",
        [role],
    )
    if rows and not flag(rows[0], "ok"):
        me = text(rows[0], "me")
        raise Error(
            f"{me} may not switch to the app role {role} (SET ROLE), and this looks at the data as the app "
            f"does [AZ618]",
            "42501",
            hint=f"once, as {me} if it made {role}, else as the role that did or a superuser: "
            f"GRANT {q(role)} TO {q(me)}",
        )


class Undo(Exception):
    """Raised inside a savepoint to roll back what it did."""


def run(db: Db, sql: str) -> None:
    """Runs generated SQL, then gives back the settings it changes for the rest of the transaction."""
    before = db.rows(
        "SELECT pg_catalog.current_setting('search_path') AS sp, "
        "pg_catalog.current_setting('check_function_bodies') AS cfb, "
        "pg_catalog.current_setting('lock_timeout') AS lt"
    )[0]
    db.script(sql)
    db.rows(
        "SELECT pg_catalog.set_config('search_path', $1, true), "
        "pg_catalog.set_config('check_function_bodies', $2, true), "
        "pg_catalog.set_config('lock_timeout', $3, true)",
        [text(before, "sp"), text(before, "cfb"), text(before, "lt")],
    )


def lock_room(db: Db, sql: str) -> None:
    """A warning before running SQL that makes more objects in one transaction than Postgres's lock table holds:
    it takes a lock on each, and stops with 'out of shared memory' when the table is full (GitLab's thousand
    tables: after two and a half minutes). The table holds max_locks_per_transaction for each connection."""
    from . import statements

    made = sum(1 for _, st in statements.split(sql) if re.match(r"\s*(CREATE|ALTER|DROP)\b", st, re.I))
    room = db.rows(
        "SELECT pg_catalog.current_setting('max_locks_per_transaction')::int AS per, "
        "pg_catalog.current_setting('max_connections')::int "
        "+ pg_catalog.current_setting('max_prepared_transactions')::int AS slots"
    )[0]
    per, slots = number(room, "per"), number(room, "slots")
    if made > per * slots * 0.8:
        need = 1 << max(0, -(-made * 5 // (4 * slots)) - 1).bit_length()  # a power of two, with room to spare
        db.warn(
            f"this makes about {made} objects in one transaction, and Postgres's lock table holds about "
            f"{per * slots} locks (max_locks_per_transaction {per} for each of {slots} connections): it may stop "
            f"with 'out of shared memory'",
            hint=f"raise max_locks_per_transaction to {need} (a restart; on managed Postgres, a parameter)",
        )


def run_policy(db: Db, sql: str, policy: str, files: Files) -> None:
    """run() for the policy's SQL (whole, or a migration): a condition Postgres refuses is named with its line. In
    a savepoint, so that after an error that says no position the policy's conditions can still be tried."""
    lock_room(db, sql)
    try:
        with savepoint(db, "authz_policy"):
            run(db, sql)
    except db.errors as e:
        if ended(e):  # the server ended the session: nothing more can be asked of it, and its words say why
            raise
        found = condition_error(e, sql, policy, files) or failing_condition(db, e, policy, files)
        if found is None:
            raise
        raise found from e


def ended(err: Exception) -> bool:
    """Whether a database error is the server ending the session (FATAL, PANIC: ended by an administrator, the
    server shutting down)."""
    fields = getattr(err, "fields", None)
    return isinstance(fields, dict) and fields.get("S") in ("FATAL", "PANIC")


def failing_condition(db: Db, err: Exception, policy: str, files: Files) -> Error | None:
    """An error not placed in a condition by its position (Postgres says none for a row-level security policy's own
    expression, or a trigger's): the policy's condition that fails with the same message tried alone on its table,
    if one does. Tried after the policy's SQL is undone, so a condition that only runs once the policy is in place
    (authz.uid() on a first apply) fails another way here, and is never named for an error it doesn't make."""
    from . import Compiler

    fields = getattr(err, "fields", None)
    said, code = (str(fields.get("M", "")), str(fields.get("C", "42P17"))) if isinstance(fields, dict) else ("", "")
    c = Compiler(parse_policy(policy, None, files=files))  # it compiled a moment ago
    return next(
        (
            Error(f"policy {loc}: the condition {{{cond}}} doesn't run: {said} [AZ613]", code)
            for table, cond, loc in row_conditions(c)
            if said and fails_alike(db, table, cond, said, code)
        ),
        None,
    )


SYNTAX_ERROR = "42601"


def fails_alike(db: Db, table: str, cond: str, said: str, code: str = "") -> bool:
    """Whether a condition, tried alone on its table's rows, fails with the message said. A syntax error with any
    message: its words name what follows the condition (an unclosed parenthesis reads on into the SQL around it),
    which is another text there."""
    alias = q(table.split(".")[1])
    try:
        with savepoint(db, "authz_probe"):
            db.rows(f"SELECT ({row_cond(cond, alias)}) AS x FROM {qt(table)} AS {alias} LIMIT 0")
    except db.errors as e:
        got = getattr(e, "fields", None)
        return isinstance(got, dict) and (
            str(got.get("M", "")) == said or code == SYNTAX_ERROR == str(got.get("C", ""))
        )
    return False


def condition_error(err: Exception, sql: str, policy: str, files: Files) -> Error | None:
    """When a statement of the compiled policy failed on one of the policy's {conditions} (SQL Postgres
    refuses: a column that isn't there, a syntax error), that condition and its line; None otherwise. The
    failing text is the statement at the error's position in sql, or the query inside a function that failed."""
    fields = getattr(err, "fields", None)  # what the server said, field by field (pgwire.PgError)
    got: dict[str, str] = {str(k): str(v) for k, v in fields.items()} if isinstance(fields, dict) else {}
    if got.get("q"):
        where, at = got["q"], int(got["p"]) - 1 if got.get("p", "").isdigit() else None
    elif got.get("P", "").isdigit():
        pos = int(got["P"]) - 1
        start = sql.rfind(";\n", 0, pos) + 1
        end = sql.find(";\n", pos)
        where, at = sql[start : end if end >= 0 else len(sql)], pos - start
    else:
        return None
    found: list[tuple[int, int, Loc, str]] = []  # each condition's occurrences in the failing text: where, how long
    for loc, _, line in read_lines(None, policy, files=files):
        for cond in braced(line):
            cond = cond.strip()
            # as the policy writes it, and as the compiled SQL does (authz.uid() is asked once per query, `this.`
            # is the row's alias where the condition is placed)
            for written in dict.fromkeys([cond, with_uid(cond)]):
                if not written:
                    continue
                for m in as_compiled(written).finditer(where):
                    found.append((m.start(), len(m.group(0)), loc, cond))
    # a condition whose text is part of another's ({inherit} in {inherit =}) matches inside it too: only whole ones
    found = [f for f in found if not any(g[0] <= f[0] and f[0] + f[1] <= g[0] + g[1] and g[1] > f[1] for g in found)]
    # the one the error points into (or just after), or the only one there: never a guess among several
    inside = [f for f in found if at is not None and f[0] <= at <= f[0] + f[1] + 2]
    if inside:
        _, _, loc, cond = max(inside, key=lambda f: f[0])
    elif len({(str(f[2]), f[3]) for f in found}) == 1:
        _, _, loc, cond = found[0]
    else:
        return None
    hint = got.get("H")
    table = re.search(r'missing FROM-clause entry for table "([^"]+)"', got.get("M", ""))
    named = re.search(rf"\b{re.escape(table.group(1))}\s*\.\s*([A-Za-z_][A-Za-z0-9_]*)", cond) if table else None
    if table and named:
        hint = (
            f"{table.group(1)}.{named.group(1)} names a table only where the query reads one by that name: for "
            f"the row the condition is about, write this.{named.group(1)}"
        )
    return Error(
        f"policy {loc}: the condition {{{cond}}} doesn't run: {got.get('M', str(err))} [AZ613]",
        got.get("C", "42P17"),
        hint=hint,
    )


def as_compiled(cond: str) -> re.Pattern[str]:
    """The condition as the compiled SQL writes it: each `this.` as the alias of wherever it is placed, and a
    caveat's arg('ip') as what the share it goes with was made with, (<alias>.caveat_args ->> 'ip')
    (Compiler.caveat_sql), or as written (where it is a function's call)."""
    alias = r'(?:"(?:[^"]|"")+"|[A-Za-z_][A-Za-z0-9_]*)'
    spans = [(start, end, alias + r"\.") for start, end in this_spans(cond)] + [
        (m.start(), m.end(), rf"(?:{re.escape(m.group(0))}|\({alias}\.caveat_args ->> '{re.escape(m.group(1))}'\))")
        for m in CAVEAT_ARG.finditer(cond)
    ]
    parts, last = [], 0
    for start, end, pattern in sorted(spans):
        parts += [re.escape(cond[last:start]), pattern]
        last = end
    return re.compile("".join(parts) + re.escape(cond[last:]))


def record(
    db: Db, action: str, policy: str | None = None, files: Mapping[str, object] | None = None, lock: str | None = None
) -> None:
    from . import BUILD

    db.rows(
        "INSERT INTO authz.policy_versions (action, policy, files, version, lock) VALUES ($1, $2, $3::jsonb, $4, $5)",
        [action, policy, json.dumps(files_map(files)), BUILD, lock],
    )


def migratable(policy: str, files: Mapping[str, object] | str | None) -> tuple[str, migrate.Compiled, Compiler]:
    """(the whole compiled policy, the policy as migrate.py reads it, the compiler): what migrations start from."""
    from . import migrate

    def make(c: Compiler) -> tuple[str, Compiler]:
        return c.compile("the policy", transaction=False), c  # compiling finds mistakes too: inside compiled()

    sql, c = compiled(policy, files, make)
    return sql, migrate.read(c, policy, files_map(files)), c


def lock_file(lock_text: str | None) -> migrate.Lock:
    """The lock file's text read: one with a line rowstile migrate doesn't write is an Error that says what to do."""
    from . import migrate

    try:
        return migrate.parse_lock(lock_text)
    except migrate.LockError as e:
        raise Error(
            f"{e}: a merge left both branches' lines in it? Keep the lock file and the migrations of the branch merged "
            "into, then run rowstile migrate again [AZ619]",
            "22023",
        ) from None


def migration(
    policy: str, files: Mapping[str, object] | str | None, lock_text: str | None, name: str = "policy"
) -> migrate.Migration:
    """The migration from the lock file's text (None or '': the first) to this policy (migrate.Migration)."""
    from . import migrate

    sql, comp, _ = migratable(policy, files)
    return migrate.migration(sql, comp, lock_file(lock_text), name)


def migrations(
    policy: str,
    files: Mapping[str, object] | str | None,
    lock_text: str | None,
    name: str = "policy",
    two_phase: bool = True,
    downgrade: bool = False,
) -> list[migrate.Migration]:
    """The migrations from the lock file's text to this policy: one, or two when inheritance trees are
    built beside the ones in use first (migrate.migrations). Refused when a newer version wrote the lock."""
    from . import migrate

    lock = lock_file(lock_text)
    if not downgrade:
        refuse_older(lock.version, "the lock file")
    sql, comp, _ = migratable(policy, files)
    return migrate.migrations(sql, comp, lock, name, two_phase)


def lock_hash(comp: migrate.Compiled) -> str:
    from . import migrate

    return migrate.digest(migrate.lock_of(comp), 16)


def there(db: Db, relation: str) -> bool:
    """Whether a table (or view) of that name exists."""
    return flag(db.rows("SELECT to_regclass($1) IS NOT NULL AS there", [relation])[0], "there")


def applied(db: Db) -> tuple[str, Files]:
    """The policy in force: the last one applied, unless it was removed since."""
    rows: list[dict[str, Value]] = []
    if there(db, "authz.policy_versions"):
        rows = db.rows(
            "SELECT action, policy, files::text AS files FROM authz.policy_versions ORDER BY id DESC LIMIT 1"
        )
    if not rows or rows[0]["action"] != "apply":
        raise Error("no policy is applied [AZ609]", "55000", hint="rowstile apply db/policy.authz")
    return text(rows[0], "policy"), files_map(text_or_none(rows[0], "files") or "{}")


def one_at_a_time(db: Db) -> None:
    """Two commands changing the policy at once: the second waits for the first, where they would meet in the
    middle and one stop with Postgres's "deadlock detected". The lock goes with the transaction."""
    db.rows("SELECT pg_catalog.pg_advisory_xact_lock(1919905638, 0)")


def apply(
    db: Db,
    policy: str,
    files: Mapping[str, object] | str | None = None,
    only_if_changed: bool = False,
    downgrade: bool = False,
    rebuild: bool = False,
) -> str:
    """'applied', or 'unchanged' (only_if_changed, and this policy is in force with everything it made).
    The whole compiled policy: everything it makes is made again (trees that didn't change keep their rows,
    unless rebuild: then each is computed again from the app's tables, which is what brings back a tree that
    writes made with the triggers off left behind).
    Refused when a newer version of rowstile last changed the database, unless downgrade."""
    files = files_map(files)
    one_at_a_time(db)
    if only_if_changed and unchanged(db, policy, files):
        return "unchanged"
    if not downgrade and there(db, "authz.policy_versions"):
        last = db.rows("SELECT version FROM authz.policy_versions ORDER BY id DESC LIMIT 1")
        refuse_older(text_or_none(last[0], "version") if last else None, "this database's policy")
    sql, comp, c = migratable(policy, files)
    run_policy(db, sql, policy, files)
    if rebuild:
        rebuild_trees(db)
    record(db, "apply", policy, files, lock_hash(comp))
    warn_captured_names(db, c)
    warn_lint(db)
    return "applied"


def rebuild_trees(db: Db) -> None:
    """Every inheritance table computed again from the app's tables, under its lock: the kept ones too."""
    for r in db.rows("SELECT name FROM authz_int.trees ORDER BY name"):
        db.rows(f"SELECT authz_int.{q(text(r, 'name') + '_rebuild')}()")


def development(db: Db) -> bool:
    """Whether this database is marked as a development database, which push may change."""
    return bool(
        there(db, "authz.settings")
        and db.rows("SELECT 1 FROM authz.settings WHERE key = 'development' AND value = 'true'")
    )


def push(
    db: Db, policy: str, files: Mapping[str, object] | str | None = None, mark: bool = False, downgrade: bool = False
) -> str:
    """Brings a development database to this policy with the migration from the policy in force, as the next
    migration file would: 'pushed', 'unchanged', or 'applied' (the whole policy, when the one in
    force was applied by another version of rowstile, or isn't as its record says).

    Only a development database: one marked as one (authz.settings), which the first push to a database that
    never had a policy does, and mark=True (rowstile push --development, a person's say-so) does for any other.
    A database with a policy and no mark takes migrations; removing the policy doesn't make it a development
    database (the record of what it took stays)."""
    files = files_map(files)
    one_at_a_time(db)
    had_policy = there(db, "authz.policy_versions") and bool(db.rows("SELECT 1 FROM authz.policy_versions LIMIT 1"))
    if had_policy and not mark and not development(db):
        try:
            applied(db)
            what = "has a policy"
        except Error:
            what = "had a policy (removed since)"
        raise Error(
            f"this database {what} and isn't marked as a development database, so push won't change "
            "it: production takes migrations (rowstile migrate) [AZ610]",
            "55000",
            hint="if it is a development database, mark it once: rowstile push --development",
        )
    state = _push(db, policy, files, downgrade)
    db.rows("INSERT INTO authz.settings VALUES ('development', 'true') ON CONFLICT (key) DO UPDATE SET value = 'true'")
    return state


def _push(db: Db, policy: str, files: Files, downgrade: bool = False) -> str:
    from . import BUILD, migrate

    last = None
    if there(db, "authz.policy_versions"):
        rows = db.rows(
            "SELECT action, policy, files::text AS files, version, lock FROM authz.policy_versions "
            "ORDER BY id DESC LIMIT 1"
        )
        last = rows[0] if rows else None
    lock = text_or_none(last, "lock") if last else None
    if last and last["action"] == "apply" and last["version"] == BUILD and lock:
        last_policy, last_files = text(last, "policy"), files_map(text_or_none(last, "files") or "{}")
        # the policy in force with what it made (unchanged() compiles it: a record this command can't compile isn't
        # one), as the migrations so far left it
        before = migratable(last_policy, last_files)[1] if unchanged(db, last_policy, last_files) else None
        if before is not None and lock_hash(before) == lock:
            sql, comp, c = migratable(policy, files)
            m = migrate.migration(sql, comp, migrate.parse_lock(migrate.lock_of(before)), "push", lines=True)
            if m.empty and (last_policy, last_files) == (policy, files):
                return "unchanged"
            if m.empty:  # the same objects (comments, tests): the new text is the one in force
                record(db, "apply", policy, files, lock)
                return "pushed"
            run_policy(db, m.sql, policy, files)
            warn_captured_names(db, c)
            warn_lint(db)
            return "pushed"
    apply(db, policy, files, downgrade=downgrade)
    return "applied"


def unchanged(db: Db, policy: str, files: Files) -> bool:
    """The policy in force is this one (text and files), applied by this version of rowstile, and what it
    made is still there: its schemas, each row-level security policy its rules make, row-level security on
    each table with rules and on what is under it (partitions, tables that inherit), each trigger it makes
    (enabled; on the tables that inherit too), no privilege on its schemas that the policy doesn't give, and each
    condition only a PL/pgSQL function holds still runs (a signing-in type's where on a column the app dropped
    since: applying again refuses it, AZ613, where the app's every query fails)."""
    from . import BUILD, Compiler, statements

    if not there(db, "authz.policy_versions"):
        return False
    rows = db.rows(
        "SELECT action, policy, files::text AS files, version FROM authz.policy_versions ORDER BY id DESC LIMIT 1"
    )
    if not rows or rows[0]["action"] != "apply" or rows[0]["version"] != BUILD or rows[0]["policy"] != policy:
        return False
    if files_map(text_or_none(rows[0], "files") or "{}") != files:
        return False
    try:
        rules = parse_policy(policy, None, files=files).rules
        # each rule on a whole row is a policy named authz_<command> (output.compile)
        made = sorted(
            {
                (qt(r.table), "authz_" + r.command)
                for r in rules
                if r.command not in ("mask", "update after") and not r.columns
            }
        )
        compiler = Compiler(parse_policy(policy, None, files=files))
        sql = compiler.compile("the policy", transaction=False)
    except PolicyError:
        return False
    if not all(reads(db, rows) for rows, _, _ in compiler.late_conditions()):
        return False
    # (table, name, only where the table is partitioned)
    triggers = [
        (m[1].split(" ON ", 1)[1], statements.unquoted(m[1]), IF_PARTITIONED in c)
        for c, st in statements.split(sql)
        if (m := statements.made(st, c)) and m[0] == "trigger"
    ]
    kept = flag(
        db.rows(
            "SELECT to_regnamespace('authz_int') IS NOT NULL AND to_regnamespace('authz_gen') IS NOT NULL "
            "AND NOT EXISTS (SELECT 1 FROM unnest($1::text[], $2::text[]) m(tbl, name) WHERE NOT EXISTS ("
            "  SELECT 1 FROM pg_catalog.pg_policy p JOIN pg_catalog.pg_description d ON d.objoid = p.oid "
            f"  AND d.classoid = 'pg_catalog.pg_policy'::regclass AND d.description IN {POLICY_MARKS} "
            "  WHERE p.polrelid = to_regclass(m.tbl) AND p.polname = m.name)) "
            "AND NOT EXISTS (SELECT 1 FROM unnest($3::text[]) g(tbl) WHERE NOT coalesce("
            "  (SELECT c.relrowsecurity FROM pg_catalog.pg_class c WHERE c.oid = to_regclass(g.tbl)), false)) "
            "AND NOT EXISTS (SELECT 1 FROM unnest($4::text[], $5::text[], $6::boolean[]) t(tbl, name, part) "
            "  WHERE (NOT t.part OR (SELECT c.relkind FROM pg_catalog.pg_class c WHERE c.oid = to_regclass(t.tbl)) = 'p') "
            "  AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_trigger g WHERE g.tgrelid = to_regclass(t.tbl) "
            "  AND g.tgname = t.name AND g.tgenabled <> 'D')) AS there",
            [
                text_array([t for t, _ in made]),
                text_array([n for _, n in made]),
                text_array(sorted({qt(r.table) for r in rules})),
                text_array([t for t, _, _ in triggers]),
                text_array([n for _, n, _ in triggers]),
                text_array(["true" if p else "false" for _, _, p in triggers]),
            ],
        )[0],
        "there",
    )
    # ... and nothing was made or given since that applying again puts right: a partition of a table with rules,
    # or a table that inherits from it, has row-level security on, each table under one rowstile watches has
    # the triggers of the table above (its statement triggers; the row triggers too, where it inherits), and
    # nobody holds a privilege on rowstile's own schemas that the policy doesn't give
    return kept and flag(
        db.rows(
            "WITH RECURSIVE below(oid) AS ("
            "  SELECT i.inhrelid FROM pg_catalog.pg_inherits i WHERE i.inhparent = ANY (ARRAY("
            "    SELECT to_regclass(g.tbl) FROM unnest($1::text[]) g(tbl))::oid[]) "
            "  UNION SELECT i.inhrelid FROM pg_catalog.pg_inherits i JOIN below b ON i.inhparent = b.oid) "
            "SELECT NOT EXISTS (SELECT 1 FROM below b JOIN pg_catalog.pg_class c ON c.oid = b.oid "
            "  WHERE NOT c.relrowsecurity) AND NOT EXISTS (SELECT 1 FROM authz_int.child_triggers()) "
            f"AND NOT EXISTS ({compiler.extra_grants_sql()}) AS closed",
            [text_array(sorted({qt(r.table) for r in rules}))],
        )[0],
        "closed",
    )


def reads(db: Db, rows: str) -> bool:
    """Whether Postgres reads `SELECT 1 FROM <rows>` (read_now's query: nothing runs), in a savepoint."""
    try:
        with savepoint(db, "authz_probe"):
            db.rows(f"SELECT 1 FROM {rows} LIMIT 0")
    except db.errors:
        return False
    return True


def text_array(items: Iterable[str]) -> str:
    """A Postgres text[] literal: {"a","b"}, with quotes and backslashes escaped."""
    return "{" + ",".join('"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"' for s in items) + "}"


# words a condition writes that are SQL's, not columns
SQL_WORDS = frozenset(
    {
        "all",
        "and",
        "any",
        "array",
        "as",
        "asc",
        "between",
        "both",
        "by",
        "case",
        "cast",
        "coalesce",
        "collate",
        "cross",
        "current_date",
        "current_time",
        "current_timestamp",
        "current_user",
        "date",
        "desc",
        "distinct",
        "do",
        "else",
        "end",
        "except",
        "exists",
        "extract",
        "false",
        "filter",
        "from",
        "full",
        "greatest",
        "group",
        "having",
        "ilike",
        "in",
        "inner",
        "interval",
        "intersect",
        "is",
        "isnull",
        "join",
        "lateral",
        "leading",
        "least",
        "left",
        "like",
        "limit",
        "localtime",
        "localtimestamp",
        "not",
        "notnull",
        "null",
        "nullif",
        "offset",
        "on",
        "only",
        "or",
        "order",
        "outer",
        "over",
        "overlaps",
        "partition",
        "position",
        "row",
        "select",
        "session_user",
        "similar",
        "some",
        "substring",
        "symmetric",
        "table",
        "then",
        "time",
        "timestamp",
        "to",
        "trailing",
        "trim",
        "true",
        "union",
        "user",
        "using",
        "values",
        "when",
        "where",
        "window",
        "with",
        "within",
    }
)
# a bare word in a condition: not after a dot or ::, not a qualifier or a function name
BARE = re.compile(r"(?<![\w.$\"])(?<!::)([A-Za-z_][A-Za-z0-9_]*)\b(?!\s*[.(])")


def row_conditions(c: Compiler) -> list[tuple[str, str, Loc]]:
    """(table, condition, line) for each {condition} written about a row: in permissions, rules and invariants
    (the type's row), a type's where, a link table's where (the link's row). Words that stand for conditions
    (signed_in, anyone, nobody) are left out."""
    words = set(KEYWORDS.values())
    out: list[tuple[str, str, Loc]] = []

    def walk(table: str, node: Expr, loc: Loc) -> None:
        match node:
            case Cond(sql) if sql not in words:
                out.append((table, sql, loc))
            case Not(item):
                walk(table, item, loc)
            case And(items) | Or(items):
                for x in items:
                    walk(table, x, loc)

    for t in c.types.values():
        if t.where:
            out.append((t.table, t.where, t.loc))
        for p in t.perms.values():
            walk(t.table, p.expr, p.loc)
        for r in t.relations.values():
            for src in r.sources:
                if src.kind == "table" and src.where and src.table:
                    out.append((src.table, src.where, src.loc))
    for rule in c.rules:
        walk(rule.table, rule.expr, rule.loc)
    for inv in c.pol.invariants:
        walk(c.T(inv.type).table, inv.expr, inv.loc)
    return list(dict.fromkeys(out))


def warn_captured_names(db: Db, compiler: Compiler) -> None:
    """A condition's bare column name means the row's column only where nothing else in the condition has one by
    that name: inside `exists (select 1 from app.memberships m where m.project_id = id)`, `id` is the membership's,
    when it has one. Postgres says which columns a condition reads: a bare word naming a column of the row that the
    condition doesn't read from the row is read from another table."""
    for table, cond, loc in row_conditions(compiler):
        if not BARE.search(cond):
            continue
        alias = q(table.split(".")[1])
        words = {m.group(1).lower() for code, part in sql_code(cond) if code for m in BARE.finditer(part)} - SQL_WORDS
        try:
            with savepoint(db, "authz_probe"):
                db.script(
                    f"CREATE TEMP VIEW authz_probe AS SELECT ({row_cond(cond, alias)}) AS x FROM {qt(table)} AS {alias}"
                )
                rows = db.rows(
                    "SELECT a.attname::text AS col, EXISTS (SELECT 1 FROM pg_catalog.pg_depend d "
                    "JOIN pg_catalog.pg_rewrite w ON w.oid = d.objid AND d.classid = 'pg_catalog.pg_rewrite'::regclass "
                    "WHERE w.ev_class = 'pg_temp.authz_probe'::regclass AND d.refobjid = a.attrelid "
                    "AND d.refobjsubid = a.attnum) AS read FROM pg_catalog.pg_attribute a "
                    f"WHERE a.attrelid = {lit(qt(table))}::regclass AND a.attnum > 0 AND NOT a.attisdropped"
                )
                db.script("DROP VIEW pg_temp.authz_probe")
        except db.errors:  # a condition Postgres can't plan on its own: applying says why
            continue
        for r in rows:
            col = text(r, "col")
            if col in words and not flag(r, "read"):
                db.warn(
                    f"{loc}: the condition {{{cond}}} names {col}, a column of {table}'s rows, but reads it from "
                    f"another table the condition names (which has a column of that name too)",
                    hint=f"for the row's, write this.{col}",
                )


def warn_lint(db: Db) -> None:
    """What authz.lint() finds that needs fixing (not its notes), as warnings."""
    for r in db.rows("SELECT object, problem, severity FROM authz.lint() WHERE severity IN ('error', 'warning')"):
        db.warn(f"authz.lint(): {r['object']}: {r['problem']}")


LINT_ORDER = {"error": 0, "warning": 1, "performance": 2, "info": 3}


def lint(db: Db) -> list[LintRow]:
    """Everything authz.lint() finds, the worst first."""
    applied(db)
    rows: list[LintRow] = [
        {"severity": text(r, "severity"), "object": text(r, "object"), "problem": text(r, "problem")}
        for r in db.rows("SELECT severity, object, problem FROM authz.lint()")
    ]
    return sorted(rows, key=lambda r: (LINT_ORDER.get(r["severity"], 9), r["object"], r["problem"]))


def draft(db: Db, schemas: Sequence[str] | None = None, users: str | None = None, role: str | None = None) -> str:
    """A first policy from the tables in these schemas (all of the app's, if None) and their foreign keys."""
    from .draft import CATALOG_SQL, DraftError, table_of
    from .draft import draft as make_draft

    rows = db.rows(CATALOG_SQL, [text_array(schemas) if schemas else None])
    tables = [table_of(r) for r in rows]
    if not tables:
        raise Error("no tables to draft a policy from" + (f" in {', '.join(schemas)}" if schemas else ""), "22023")
    try:
        return make_draft(
            tables, users, role or "app_user", schemas or sorted({t["name"].split(".")[0] for t in tables})
        )
    except DraftError as e:
        raise Error(str(e), "22023") from None


def reapply(db: Db, rebuild: bool = False) -> str:
    policy, files = applied(db)
    return apply(db, policy, files, rebuild=rebuild)


def diff(
    db: Db, policy: str, files: Mapping[str, object] | str | None = None, users: list[str] | None = None
) -> list[DiffRow]:
    """Who would gain and lose what if the policy were applied: rows of change, user_id, type, what, id.
    Runs the new policy in a savepoint and undoes it (a condition Postgres refuses is named, as applying names it)."""
    from .governance import DIFF_ROWS

    files = files_map(files)
    parts = compiled(policy, files, lambda c: c.diff_parts("the policy", users or None))
    rows: list[DiffRow] = []
    try:
        with savepoint(db, "authz_diff"):
            db.script(parts["setup"])
            db.script(parts["before"])
            run_policy(db, parts["body"], policy, files)
            db.script(parts["after"])
            rows = [
                {
                    "change": text(r, "change"),
                    "user_id": text_or_none(r, "user_id"),
                    "type": text(r, "type"),
                    "what": text(r, "what"),
                    "id": text(r, "id"),
                }
                for r in db.rows(
                    f"SELECT change, nullif(user_id, '') AS user_id, type, what, id FROM ({DIFF_ROWS}) d "
                    f"ORDER BY type, what, id, user_id, change"
                )
            ]
            raise Undo
    except Undo:
        pass
    return rows


def policy_compiler(policy: str, files: Mapping[str, object] | str | None = None) -> Compiler:
    """The policy compiled (a Compiler with every view and helper made), for what reads its structure."""

    def make(c: Compiler) -> Compiler:
        c.compile("the policy", transaction=False)
        return c

    return compiled(policy, files, make)


def why(
    db: Db,
    ptype: str,
    pid: str,
    type_name: str,
    oid: str,
    perm: str,
    compiler: Compiler | None = None,
    tried: bool = True,
) -> Answer:
    """Whether someone holds a permission, why, and if not the smallest changes that would grant it
    (grant.Answer). Each change is tried in a savepoint and undone: nothing stays. tried=False (a read-only
    transaction): the changes that might grant it, none tried."""
    from . import grant

    assert pid, "the command and Studio ask for someone signed in first: nobody can be given access"
    # JIT off until the caller's transaction ends: counting what someone holds lists every object of a type, which
    # Postgres may estimate at millions of rows and compile for most of a second, though the table holds a few
    db.rows("SELECT pg_catalog.set_config('jit', 'off', true)")
    c = compiler or policy_compiler(*applied(db))
    return grant.how_to_grant(c, db, ptype, pid, type_name, oid, perm, tried)


def graph(policy: str, files: Mapping[str, object] | str | None = None) -> str:
    def make(c: Compiler) -> str:
        c.compile("the policy", transaction=False)  # reports the same mistakes applying would
        return c.graph()

    return compiled(policy, files, make)


def client(lang: str, policy: str, files: Mapping[str, object] | str | None = None) -> str:
    """The client in a language the command takes: py or ts, and python, typescript or ts-sdk in rowstile.toml."""

    def make(c: Compiler) -> str:
        c.compile("the policy", transaction=False)
        return c.client(lang, "the policy")

    return compiled(policy, files, make)


def test_files(tests: Mapping[str, str] | None) -> Files:
    """Named tests' files: name -> text."""
    return dict(tests or {})


def test_row(r: dict[str, Value]) -> TestRow:
    return text(r, "test"), text_or_none(r, "line"), flag(r, "ok"), text_or_none(r, "detail")


def takes_app_role(db: Db, tests_sql: str, role: str) -> None:
    """Checks that write or read as someone run as the app role (the policy's, which a policy without rules makes
    no row-level security policy for): asked before they run, since a refused SET ROLE would read as the policy
    refusing the check."""
    if "SET LOCAL ROLE" in tests_sql:
        may_take(db, role)


def test(db: Db, tests: Mapping[str, str] | None = None) -> list[TestRow]:
    """The current policy's tests, the named tests in `tests` (file name -> text) and the invariants:
    a row per check, as (test, line, ok, detail). Named tests roll back what they did."""
    from .testing import FN as TESTS_FN

    policy, files = applied(db)
    named = test_files(tests)

    def make(c: Compiler) -> tuple[str, str]:
        c.add_test_files(named)
        return c.tests_function_sql(), c.role

    sql, role = compiled(policy, files, make)
    takes_app_role(db, sql, role)
    db.script(sql)
    rows = db.rows(f"SELECT * FROM {TESTS_FN}()")
    db.script(f"DROP FUNCTION {TESTS_FN}()")
    return [test_row(r) for r in rows]


def coverage(db: Db, tests: Mapping[str, str] | None = None) -> tuple[list[TestRow], Report]:
    """test(), and the coverage of the permissions' branches by its passing checks: (rows, coverage.report)."""
    from . import coverage as cov
    from .testing import COVERAGE
    from .testing import FN as TESTS_FN

    policy, files = applied(db)
    named = test_files(tests)

    def make(c: Compiler) -> tuple[str, str]:
        c.add_test_files(named)
        return c.tests_function_sql(coverage=True), c.role

    sql, role = compiled(policy, files, make)
    takes_app_role(db, sql, role)
    db.script(sql)
    rows = db.rows(f"SELECT * FROM {TESTS_FN}()")
    db.script(f"DROP FUNCTION {TESTS_FN}()")
    # the branches, as the policy in force writes them (compiled: a deny's hidden permission stays hidden)
    report = cov.report(
        policy_compiler(policy, files), [text_or_none(r, "detail") for r in rows if r["test"] == COVERAGE]
    )
    return [test_row(r) for r in rows if r["test"] != COVERAGE], report


SNAPSHOT_HEAD = (
    "# rowstile snapshot: who holds what on this database's data (rowstile snapshot writes it).\n"
    "# Commit it with the review data: a pull request that changes access changes these lines.\n"
)


def snapshot(db: Db, limit: int = 500) -> list[str]:
    """Who holds each permission on each object, as sorted lines 'type id perm: who, who' (users by id, other
    principals as type:id, 'anyone' for someone not signed in). Asks authz.list as each principal in the data
    (at most `limit` of them, else an Error: snapshots are for small review data)."""
    c = policy_compiler(*applied(db))
    principals: list[tuple[str | None, str | None]] = []
    for t in c.types.values():
        if t.principal:
            ids = [
                text(r, "id") for r in db.rows(f"SELECT ({c.key(t, 'r')})::text AS id FROM {qt(t.table)} r ORDER BY 1")
            ]
            principals += [(t.name, i) for i in ids]
    if len(principals) > limit:
        raise Error(
            f"{len(principals)} people and principals: a snapshot is for small review data (at most {limit})", "54000"
        )
    held: dict[tuple[str, str, str], list[str]] = {}
    perms = [(t.name, p) for t in c.types.values() for p in c.public_perms(t)]
    for ptype, pid in principals + [(None, None)]:
        db.rows("SELECT authz.act_as($1, $2)", [ptype, pid])
        who = "anyone" if pid is None else pid if ptype == "user" else f"{ptype}:{pid}"
        for tname, perm in perms:
            for r in db.rows("SELECT x FROM authz.list($1, $2) x", [tname, perm]):
                held.setdefault((tname, text(r, "x"), perm), []).append(who)
    db.rows("SELECT authz.act_as(NULL, NULL)")

    def order(key: tuple[str, str, str]) -> tuple[str, tuple[int, int, str], str]:
        tname, oid, perm = key
        return (tname, (0, int(oid), "") if oid.isdigit() else (1, 0, oid), perm)

    return [f"{t} {o} {p}: {', '.join(held[(t, o, p)])}" for t, o, p in sorted(held, key=order)]


def granting(lines: list[str]) -> list[str]:
    """The lines of authz.explain's answer that say why it holds: each `yes` with nothing but `yes` above it (a
    `yes` under a `no`, as `{inherit}` in a `(parent.view and {inherit})` that doesn't hold, grants nothing)."""
    out: list[str] = []
    above: list[tuple[int, bool]] = []  # the yes and no lines this one is under: (indent, yes)
    for line in lines:
        said = line.strip()
        if not said.startswith(("yes ", "no ")):
            continue  # what a permission is, or a note
        indent = len(line) - len(line.lstrip())
        above = [a for a in above if a[0] < indent]
        yes = said.startswith("yes ")
        if yes and all(y for _, y in above):
            out.append(said)
        above.append((indent, yes))
    return out


def review_run(
    db: Db,
    policy: str,
    files: Mapping[str, object] | str | None,
    tests: Mapping[str, str] | None,
    lock_text: str | None,
    explain: Iterable[tuple[str, str, str, str]] = (),
) -> ReviewRun:
    """For rowstile review, on a database at the base branch's state (its migrations and review data): the
    pull request's policy brought in the way it will be deployed (the migrations from the base branch's
    lock, or the whole policy without one), then its tests, all undone afterwards: how long the deploy took
    (or why it failed), the tests' rows, and for each (who, type, id, perm) in explain, the lines of
    authz.explain that grant it (who as --as writes it: user:3, bot:7, '' for someone not signed in). An example
    explain refuses is left without them: they say how, the review goes on without."""
    import time

    out: ReviewRun = {"deployed": None, "error": None, "tests": [], "how": {}}
    try:
        with savepoint(db, "authz_review"):
            started = time.monotonic()
            try:
                with savepoint(db, "authz_review_deploy"):
                    if lock_text:
                        for m in migrations(policy, files, lock_text, "review"):
                            if not m.empty:
                                run_policy(db, m.sql, policy, files_map(files))
                    else:
                        apply(db, policy, files)
                out["deployed"] = round(time.monotonic() - started, 2)
            except (db.errors, Error) as e:
                out["error"] = getattr(e, "message", str(e))
                raise Undo from e
            for who, type_, id_, perm in explain:
                kind, _, pid = who.partition(":")
                lines: list[str] = []
                try:
                    with savepoint(db, "authz_review_explain"):
                        if kind not in ("", "user"):  # another principal: asked signed in as it, signed out after
                            db.rows("SELECT authz.act_as($1, $2)", [kind, pid])
                        lines = [
                            text(r, "l")
                            for r in db.rows(
                                "SELECT l FROM authz.explain($1, $2, $3, $4) l",
                                [type_, id_, perm, pid if kind == "user" else None],
                            )
                        ]
                        raise Undo
                except Undo:
                    pass
                except db.errors:
                    continue
                out["how"][(who, type_, id_, perm)] = granting(lines)[1:4]
            out["tests"] = test(db, tests)
            raise Undo
    except Undo:
        pass
    return out


# Everything apply() made, in an order that works: policies and masked views, then the schemas (their
# CASCADE takes the triggers on app tables and the event triggers along), then the table-wide SELECT
# that masks replaced, then the functions and indexes it put into authz.
REMOVE_SQL = "\n\n".join(
    [
        "DROP TABLE IF EXISTS pg_temp.authz_old_tables;",
        DROP_OLD_POLICIES,
        DROP_MASKED_VIEWS,
        "DROP SCHEMA IF EXISTS authz_gen, authz_int CASCADE;",
        """DO $mr$
DECLARE r record;
BEGIN
  FOR r IN SELECT * FROM authz.masked_tables LOOP
    IF to_regclass(r.tbl) IS NOT NULL AND EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r.role) THEN
      -- (taking the table's SELECT back takes the SELECT on its other columns the mask gave instead)
      EXECUTE format('REVOKE SELECT ON %s FROM %I', r.tbl, r.role);
      EXECUTE format('GRANT SELECT ON %s TO %I', r.tbl, r.role);
    END IF;
    DELETE FROM authz.masked_tables WHERE tbl = r.tbl AND role = r.role;
  END LOOP;
END $mr$;""",
        """DO $rf$
DECLARE f regprocedure; i regclass;
BEGIN
  FOR f IN SELECT p.oid::regprocedure FROM pg_proc p WHERE p.pronamespace = 'authz'::regnamespace
             AND p.proname NOT IN ('ctx', 'link_hashes') LOOP        -- the base functions, with the base tables
    EXECUTE format('DROP FUNCTION %s', f);
  END LOOP;
  FOR i IN SELECT x.indexrelid::regclass FROM pg_index x JOIN pg_class c ON c.oid = x.indexrelid
           WHERE x.indrelid = 'authz.shares'::regclass AND c.relname LIKE 'shares\\_obj\\_%' LOOP
    EXECUTE format('DROP INDEX %s', i);
  END LOOP;
END $rf$;""",
        LOST_RULES.replace("has no rules any more", "was governed by the removed policy"),
    ]
)


def remove(db: Db) -> None:
    one_at_a_time(db)
    applied(db)
    run(db, REMOVE_SQL)
    record(db, "remove")

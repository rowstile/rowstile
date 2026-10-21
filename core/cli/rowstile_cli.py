#!/usr/bin/env python3
"""rowstile: compile policies and apply them to a database, from a terminal, CI or a migration.

    rowstile dev     [POLICY.authz] [--once] [--no-studio] [--studio-port N]
                                                   on each save: check, diff, push, test, write the clients;
                                                   Studio on http://127.0.0.1:4983 beside it
    rowstile studio  [--port N] [--write]          Studio: the tables as anyone, why and how to grant, the graph,
                                                   the access diff, shares and requests (read-only unless --write)
    rowstile migrate [POLICY.authz] [--name NAME] [--check] [--tool T] [--dir D] [--one-phase]
                                                   write the policy's changes since the lock file as a migration
                                                   for the app's migration tool (no database needed); two when
                                                   inheritance trees are built beside the ones in use first
                                                   (--one-phase: one); --check: exit 1 if there are changes no
                                                   migration has (for CI)
    rowstile review  [POLICY.authz] [--base REF] [--markdown|--json|--annotations] [--out FILE] [--db DSN]
                                                   what the change since REF (default main) does: meaning,
                                                   access (with --db: a database at REF with review data),
                                                   risk, tests, deploy; the pull request comment with --markdown,
                                                   or in FILE with --out, beside what it prints (one review for both)
                                                   (exit 0 whatever it finds: test and migrate --check gate)
    rowstile fmt     [--check] [FILE.authz ...]    write policies and test files one way (--check: exit 1 if
                                                   one isn't; for CI); line endings stay the file's own
    rowstile push    [POLICY.authz] [--development]
                                                   bring a development database to the policy with the same
                                                   migration (never production: that takes migrations); a
                                                   database with a policy must be marked as one first, once:
                                                   --development (the first push to one with none marks it)
    rowstile apply   [POLICY.authz] [--force]      apply it whole (and the files it includes), unless it is in force;
                                                   --force: in any case, and every inheritance table computed again
                                                   (after authz.verify() said false)
                                                   (apply, push, migrate and remove refuse a database or lock file
                                                   a newer rowstile wrote; --downgrade goes back on purpose)
    rowstile check   [POLICY.authz]                report its first mistake, as 'file: line N: message'
    rowstile prove   [POLICY.authz] [--worlds N]   every invariant in many small worlds (no database): the
                                                   smallest counterexample, or that none was found
    rowstile diff    [POLICY.authz] [--users 1,2] [--limit N]
                                                   who would gain and lose what; changes nothing
    rowstile test    [TESTS.authz ...] [--coverage]
                                                   the policy's tests, these named tests, and the invariants;
                                                   --coverage: the branches of each permission no test makes true
    rowstile graph   [POLICY.authz]                Mermaid diagram of the file, else of the policy rowstile.toml
                                                   names, else (and with --db) of the policy in force
    rowstile lint                                  the ways around row-level security the database leaves open
                                                   (authz.lint()); exit 1 if there are errors or warnings
    rowstile indexes [--check]                     the lookups the policy makes into the app's tables that no
                                                   index serves, and the line to add for the migration tool
    rowstile plans   [--as WHO]                    each governed table read as someone (EXPLAIN ANALYZE): the
                                                   time, and full scans or per-row subplans that would be slow
    rowstile bench   [--people N] [--rounds N]     p50 and p95 of reads, lists, checks and updates (undone), as
                                                   people in the data
    rowstile snapshot [--check] [--out FILE]       who holds what on this database's data, one sorted line per
                                                   object and permission (for review data: commit it, and a
                                                   pull request that changes access changes it); --check: exit 1
                                                   if it is out of date
    rowstile client  [py|ts] [POLICY.authz]        typed helpers for app code; with neither, writes the
                                                   clients rowstile.toml names
    rowstile init    [--schema app,...] [--users app.users] [--role app_user] [--out db]
                                                   a first policy from the database's tables (every schema of
                                                   the app's, or those --schema names), and rowstile.toml
    rowstile lsp                                   the language server, for editors (stdin and stdout)
    rowstile mcp                                   the MCP server, for coding agents (stdin and stdout): check,
                                                   prove, review, test, why, lint, and push to a development database
    rowstile --version                             the version, and the Python it runs on
    rowstile help AZ201                            what a mistake's code means, and how to fix it (help errors: all)

  asking the database as someone (--as user:42, bot:7, or anyone):
    rowstile can     --as WHO TYPE ID PERM         yes or no
    rowstile explain --as WHO TYPE ID PERM         why, or what is missing
    rowstile perms   --as WHO TYPE ID              every permission WHO holds on it
    rowstile list    --as WHO TYPE PERM            every id WHO holds PERM on
    rowstile who     [--as WHO] TYPE ID PERM       everyone who holds PERM on it
    rowstile why     --as WHO TYPE ID PERM         yes and why; or no, why not, and the smallest changes that
                                                   would grant it (each tried and undone)
    rowstile explain-rule --as WHO TABLE insert|update|delete [ID] [--row JSON]
                                                   why a write is (or would be) refused
    rowstile sql     --as WHO "SELECT ..."         a statement as the app role signed in as WHO; rolled back

    rowstile reapply [--force]                     apply the policy in force again (after upgrading rowstile);
                                                   --force: and compute every inheritance table again
    rowstile remove  --yes                         remove everything the current policy made

The database is --db DSN (host=... port=... user=... password=... dbname=..., or a postgresql:// URL), else
rowstile.toml's `database` (in this folder or a folder above it), else DATABASE_URL, else the PG* environment variables.
Without --db, those variables may be in .env.local or .env beside rowstile.toml: the environment first, then the files.
rowstile.toml:

    policy   = "db/policy.authz"
    tests    = ["db/tests/*.authz"]
    database = "env:DATABASE_URL"          # a DSN or URL, or env:NAME for an environment variable holding one
    [clients]
    py = "backend/app/authz_client.py"
    ts = "frontend/src/authz.ts"
    [migrations]
    tool = "alembic"                       # alembic, prisma, drizzle, sql, goose, dbmate or flyway
    dir  = "alembic/versions"              # where the tool keeps them (each tool has a default)
    lock = "db/policy.lock"                # what the migrations made so far (default: next to the policy)
    write_after = 300                      # rowstile dev writes the migration this long after the last save
                                           # (seconds; 0: never, run rowstile migrate yourself)
    [review]
    snapshot = "db/access.snapshot"        # rowstile snapshot's file (default: access.snapshot next to the policy)

The compiler runs here: the database only runs the SQL it writes, and the authz.* functions
apps call. Applying, previewing and testing each run in one transaction on the database.
"""

from __future__ import annotations

import contextlib
import glob
import io
import json
import os
import posixpath
import re
import sys
import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from typing import NamedTuple, NoReturn, TypeVar

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(1, os.path.dirname(HERE))
import pgwire  # noqa: E402
from authzlib import database  # noqa: E402
from authzlib.connection import Row, Value  # noqa: E402
from authzlib.parse import collect_includes, disk_reader, within  # noqa: E402
from authzlib.sqlutil import POLICY_MARKS  # noqa: E402
from authzlib.sqlutil import q as quote_ident  # noqa: E402

T = TypeVar("T")

CONFIG = "rowstile.toml"
EXPLAIN_SHOWN = 12  # lines of a failing check's explanation shown


def read_text(path: str) -> str:
    """A policy or test file's text. A file that isn't UTF-8 is an OSError that says so (callers print strerror)."""
    try:
        with open(path, encoding="utf-8") as fh:
            return fh.read()
    except UnicodeDecodeError as e:
        raise OSError(0, f"not UTF-8 (the byte at {e.start}): save it as UTF-8") from None


def read_policy(path: str) -> tuple[str, dict[str, str]]:
    """The policy's text, and every file it includes (by name relative to the policy's folder, never outside it)."""
    text = read_text(path)
    folder = os.path.dirname(os.path.abspath(path))
    disk = disk_reader(folder)

    def read(name: str) -> str | None:
        got = disk(name)
        full = os.path.join(folder, *name.split("/"))
        if got is None and os.path.isfile(full):
            try:
                read_text(full)  # there, and not read: not UTF-8 (or a link out of the folder: the compiler says)
            except OSError as e:
                raise OSError(0, f"the file it includes, {name}, is {e.strerror}") from None
        return got

    return text, collect_includes(text, read)


ENV_FILES = (".env.local", ".env")  # read after the environment, in this order: the first that has a name wins
# What the files may set: where the database is, and nothing else. The review in CI reads a pull request's
# files, and a GIT_SSH_COMMAND or a PATH taken from its .env would run the pull request's code there.
PG_NAMES = (
    "PGHOST",
    "PGPORT",
    "PGUSER",
    "PGPASSWORD",
    "PGDATABASE",
    "PGOPTIONS",
    "PGSSLMODE",
    "PGSSLROOTCERT",
    "PGCHANNELBINDING",
)
ENV_NAMES = frozenset({"DATABASE_URL", *PG_NAMES})


def parse_env(text: str) -> dict[str, str]:
    """A .env file's variables. NAME=value lines, `export` in front allowed, # comments; a value in single quotes
    is taken as written, one in double quotes with its backslashes read (a new line, a quote), and ${NAME} in a
    value that isn't in single quotes is filled in from the environment or the lines above. Any other line is
    skipped: the file is the app's, and holds more than rowstile reads."""
    out: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("export "):
            line = line[7:].lstrip()
        name, sep, value = line.partition("=")
        name, value = name.strip(), value.strip()
        if not sep or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
            continue
        if value.startswith("'"):
            end = value.find("'", 1)
            out[name] = value[1 : end if end > 0 else len(value)]
            continue
        if value.startswith('"'):
            body, i = [], 1
            while i < len(value) and value[i] != '"':
                if value[i] == "\\" and i + 1 < len(value):
                    i += 1
                    body.append({"n": "\n", "r": "\r", "t": "\t"}.get(value[i], value[i]))
                else:
                    body.append(value[i])
                i += 1
            value = "".join(body)
        else:
            value = re.split(r"\s#", value, maxsplit=1)[0].rstrip()
        out[name] = re.sub(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}", lambda m: os.environ.get(m[1], out.get(m[1], "")), value)
    return out


class EnvFiles:
    """What .env.local and .env beside rowstile.toml say of where the database is, for what the environment
    doesn't set. They stay in that folder, as the policy does: one that is a link out of it isn't read."""

    def __init__(self) -> None:
        self.values: dict[str, str] = {}  # every name the files set
        self.source: dict[str, str] = {}  # ... and the file each is from
        self.taken: set[str] = set()  # the names whose value in use is a file's
        self.skipped: list[str] = []  # files that weren't read, and why
        self.where = ""  # the files that named the database this command uses (".env"), once that is known
        self.read: set[str] = set()  # the folders whose files were read

    def load(self, folder: str) -> None:
        self.peek(folder)
        # what the command and its connection read from the environment: put there, unless it is there already
        for key in sorted(ENV_NAMES & self.values.keys()):
            if key not in os.environ:
                os.environ[key] = self.values[key]
                self.taken.add(key)

    def peek(self, folder: str) -> None:
        """Reads the files, and leaves the environment as it is."""
        self.read.add(folder)
        top = os.path.realpath(folder)
        for name in ENV_FILES:
            path = os.path.join(folder, name)
            if not os.path.isfile(path):
                continue
            if not within(top, os.path.realpath(path)):
                self.skipped.append(f"{name} is a link out of its folder: it isn't read")
                continue
            try:
                with open(path, encoding="utf-8-sig") as fh:  # a byte order mark is skipped
                    found = parse_env(fh.read())
            except (OSError, UnicodeDecodeError) as e:
                self.skipped.append(f"{name} can't be read ({e})")
                continue
            for key, value in found.items():
                if key not in self.values:
                    self.values[key], self.source[key] = value, name

    def get(self, name: str) -> str | None:
        """A variable rowstile.toml names (database = "env:NAME"): the environment's, else the files'."""
        if name not in os.environ and name in self.values:
            self.taken.add(name)
            return self.values[name]
        return os.environ.get(name)

    def files(self, names: Iterable[str]) -> str:
        """The files these variables' values in use came from: '.env', '.env and .env.local', or ''."""
        return " and ".join(sorted({self.source[n] for n in names if n in self.taken}))

    def note(self) -> str:
        return "".join(f"\n{line}" for line in self.skipped)


ENV = EnvFiles()


def cant_connect(e: BaseException, dsn: str | None) -> str:
    """What to say when the connection failed. When nothing named a database, libpq's defaults were tried (the
    system's user, on a local socket, or localhost on Windows): the message says that, and how to name one. A
    database a .env file named: which file."""
    if dsn or any(os.environ.get(v) for v in ("PGHOST", "PGPORT", "PGDATABASE", "PGUSER", "PGSERVICE")):
        named = f"\n(the database is the one {ENV.where} names)" if ENV.where else ""
        said = f"can't connect to {e.where}: {e.why}" if isinstance(e, pgwire.Unreachable) else f"can't connect: {e}"
        return f"{said}{named}{ENV.note()}"
    return (
        f"can't connect: no database was named, and the default failed ({e})\n"
        f"name it with --db DSN, `database` in {CONFIG}, or DATABASE_URL (in the environment, .env.local or .env)"
        + ENV.note()
    )


def fail(msg: str | None, code: int = 1) -> NoReturn:
    print(msg, file=sys.stderr)
    sys.exit(code)


def print_notice(f: pgwire.Fields) -> None:
    """A WARNING or NOTICE the server sent, on stderr, as psql prints it."""
    print(
        f"{f.get('V', f.get('S', 'NOTICE'))}: {f.get('M', '')}"
        + (f"\nDETAIL: {f['D']}" if f.get("D") else "")
        + (f"\nHINT: {f['H']}" if f.get("H") else ""),
        file=sys.stderr,
    )


class Db:
    """The connection authzlib.database works with (authzlib.connection.Db)."""

    errors = pgwire.PgError

    def __init__(self, conn: pgwire.Connection) -> None:
        self.conn = conn

    def rows(self, sql: str, args: Sequence[Value] = ()) -> list[Row]:
        rows, cols = self.conn.query_described(sql, list(args))
        return [dict(zip(cols, r, strict=True)) for r in rows]

    def script(self, sql: str) -> None:
        self.conn.script(sql)

    def warn(self, message: str, detail: str | None = None, hint: str | None = None) -> None:
        if self.conn.on_notice:
            self.conn.on_notice(
                {
                    "S": "WARNING",
                    "V": "WARNING",
                    "M": message,
                    **({"D": detail} if detail else {}),
                    **({"H": hint} if hint else {}),
                }
            )


def abandon(conn: pgwire.Connection) -> None:
    """Ends a transaction left without a commit: rolled back; or, stopped in the middle of a statement (Ctrl-C),
    that statement ended on the server too, at once, instead of after it has run its course. On a connection that
    is lost already, nothing more: the error that ended the command is the one it reports."""
    with contextlib.suppress(pgwire.PgError, pgwire.ProtocolError, OSError):
        if conn.busy:
            conn.cancel()
        else:
            conn.execute("ROLLBACK")


def transaction(conn: pgwire.Connection, work: Callable[[Db], T], keep: bool = True) -> T:
    """work(Db) in one transaction: committed if keep, else rolled back."""
    conn.execute("BEGIN")
    try:
        out = work(Db(conn))
    except BaseException:
        abandon(conn)
        raise
    conn.execute("COMMIT" if keep else "ROLLBACK")
    return out


def in_force(db: Db) -> bool:
    """Whether a policy is applied (so there is something to compare with)."""
    try:
        database.applied(db)
    except database.Error:
        return False
    return True


def table(rows: Sequence[Sequence[object]], cols: list[str]) -> str:
    cells = [["" if v is None else str(v) for v in r] for r in rows]
    width = [max([len(c)] + [len(r[i]) for r in cells]) for i, c in enumerate(cols)]
    line: Callable[[list[str]], str] = lambda r: "  ".join(v.ljust(w) for v, w in zip(r, width, strict=True)).rstrip()
    return "\n".join([line(cols), line(["-" * w for w in width])] + [line(r) for r in cells])


# --- rowstile.toml -----------------------------------------------------------------------------
class Config:
    """rowstile.toml, read with a typed accessor per setting."""

    def __init__(self, path: str | None = None, data: Mapping[str, object] | None = None) -> None:
        self.path = path
        self.data: dict[str, object] = dict(data or {})
        self.dir = os.path.dirname(path) if path else os.getcwd()

    def file(self, name: str) -> str:
        return os.path.normpath(os.path.join(self.dir, name))

    def inside(self, name: str, what: str) -> str:
        """A file rowstile.toml names to be read (the policy, the tests, the lock): in rowstile.toml's folder, also
        through links. The file may be a pull request's, read by CI: it must not name the runner's own files."""
        path = self.file(name)
        top = os.path.realpath(self.dir)
        if os.path.isabs(name) or not within(top, os.path.realpath(path)):
            fail(
                f'{self.path}: {what} = "{name}" is outside the folder {CONFIG} is in (or a link out of it): '
                f"the files it names stay in that folder",
                2,
            )
        return path

    def below(self, path: str) -> str | None:
        """A path from rowstile.toml's folder, with /, as a .gitattributes there names it. None for one outside
        the folder (another drive, on Windows, or ..): no pattern there matches it."""
        try:
            rel = os.path.relpath(path, self.dir).replace(os.sep, "/")
        except ValueError:
            return None
        return None if rel == ".." or rel.startswith("../") else rel

    def section(self, name: str) -> dict[str, object]:
        """A [table] of the file (empty if it isn't there, or isn't a table)."""
        value = self.data.get(name)
        return {str(k): v for k, v in value.items()} if isinstance(value, dict) else {}

    def setting(self, section: str | None, key: str) -> str | None:
        """A text setting, top-level or in a [section]; None if it isn't text."""
        value = (self.section(section) if section else self.data).get(key)
        return value if isinstance(value, str) and value else None

    @property
    def policy(self) -> str | None:
        p = self.setting(None, "policy")
        return self.inside(p, "policy") if p else None

    def test_globs(self) -> list[str]:
        value = self.data.get("tests", [])
        return [x for x in value if isinstance(x, str)] if isinstance(value, list) else []

    def tests(self) -> list[str]:
        """The test files its globs name, sorted."""
        out: list[str] = []
        for pattern in self.test_globs():
            self.inside(pattern.split("*")[0].split("?")[0].split("[")[0] or ".", "tests")
            out += sorted(
                f for f in glob.glob(self.file(pattern)) if self.inside(os.path.relpath(f, self.dir), "tests")
            )
        return list(dict.fromkeys(out))

    @property
    def clients(self) -> dict[str, str]:
        """{language: path}; the TypeScript one is only the policy's names when the app uses the SDK
        (a dependency on @rowstile/* in its package.json): the SDK has the rest."""
        out: dict[str, str] = {}
        for lang, p in self.section("clients").items():
            assert isinstance(p, str), "check_settings refuses a client that isn't a path"
            out["ts-sdk" if lang == "ts" and self.uses_ts_sdk() else lang] = self.file(p)
        return out

    @property
    def tool(self) -> str | None:
        """[migrations] tool: the app's migration tool."""
        return self.setting("migrations", "tool")

    @property
    def write_after(self) -> float:
        """[migrations] write_after: seconds after the last save that rowstile dev writes the migration (0: never)."""
        if "migrations" not in self.data:
            return 0
        value = self.section("migrations").get("write_after", 300)
        return float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else 300

    def uses_ts_sdk(self) -> bool:
        d = self.dir
        while True:
            try:
                with open(os.path.join(d, "package.json"), encoding="utf-8") as fh:
                    import stack

                    deps = stack.dependencies(json.load(fh))
                return any(name.startswith("@rowstile/") for name in deps)
            except (OSError, ValueError):
                pass
            parent = os.path.dirname(d)
            if parent == d:
                return False
            d = parent

    @property
    def database(self) -> str | None:
        db = self.setting(None, "database")
        if db and db.startswith("env:"):
            value = ENV.get(db[4:])
            if value is None:
                fail(
                    f'{self.path}: database = "{db}", but {db[4:]} is not set: not in the environment, and not in '
                    f".env.local or .env beside {CONFIG}" + ENV.note(),
                    2,
                )
            return value
        return db

    def database_from(self, given: str | None) -> str:
        """The .env files that named the database this command uses ('' when none did): --db is the command
        line's, a literal `database` is rowstile.toml's own."""
        if given is not None:
            return ""
        db = self.setting(None, "database")
        if db:
            return ENV.files([db[4:]]) if db.startswith("env:") else ""
        return ENV.files(["DATABASE_URL"] if os.environ.get("DATABASE_URL") else PG_NAMES)


# what rowstile.toml may hold: {setting: its type in words}, top-level and per [table]
SETTINGS: dict[str, dict[str, str]] = {
    "": {"policy": "text", "tests": "a list of patterns", "database": "text"},
    "clients": {"py": "text", "ts": "text"},
    "migrations": {"tool": "text", "dir": "text", "lock": "text", "write_after": "a number"},
    "review": {"snapshot": "text"},
}


def check_settings(path: str, data: Mapping[str, object]) -> None:
    """Refuses a setting rowstile doesn't know, or one of the wrong type: left alone, `tests = "..."` runs no test."""

    def right(value: object, kind: str) -> bool:
        if kind == "text":
            return isinstance(value, str)
        if kind == "a number":
            return isinstance(value, (int, float)) and not isinstance(value, bool)
        return isinstance(value, list) and all(isinstance(x, str) for x in value)

    def check(table: str, values: Mapping[str, object]) -> None:
        for key, value in values.items():
            name = f"[{table}] {key}" if table else key
            if table == "" and key in SETTINGS and key != "":
                if not isinstance(value, dict):
                    fail(f"{path}: [{key}] is a table of settings", 2)
                check(key, {str(k): v for k, v in value.items()})
            elif key not in SETTINGS[table]:
                known = ", ".join(SETTINGS[table]) + (
                    ", and the tables [clients], [migrations], [review]" if not table else ""
                )
                fail(f"{path}: {name} is not a setting rowstile knows ({known})", 2)
            elif not right(value, SETTINGS[table][key]):
                example = 'tests = ["db/tests/*.authz"]' if key == "tests" else f"{key} = ..."
                fail(f"{path}: {name} is {SETTINGS[table][key]}: {example}", 2)

    check("", data)


def load_config() -> Config:
    d = os.getcwd()
    while True:
        path = os.path.join(d, CONFIG)
        if os.path.exists(path):
            import tomllib

            try:
                with open(path, "rb") as fh:
                    data = tomllib.loads(fh.read().decode("utf-8-sig"))  # a byte order mark is skipped
            except (OSError, ValueError) as e:
                fail(f"{path}: {e}", 2)
            check_settings(path, data)
            return Config(path, data)
        parent = os.path.dirname(d)
        if parent == d:
            return Config()
        d = parent


def lsp_settings() -> Config:
    """rowstile.toml as it is now, for the language server, which reads it again at each change in the editor (a
    mistake fixed, a database named), and the .env files beside it, read once. A mistake stops this as it stops
    the command (SystemExit, after saying it on stderr)."""
    cfg = load_config()
    if cfg.dir not in ENV.read:
        ENV.load(cfg.dir)
    return cfg


def relative(path: str) -> str:
    try:
        return os.path.relpath(path)
    except ValueError:
        return path


def file_problem(e: OSError) -> str | None:
    """'path: why' for a file the command couldn't read or write (a folder where it writes a file, say); None for
    an error that names no file, as a connection's does."""
    return None if e.filename is None else f"{relative(str(e.filename))}: {e.strerror}"


def database_stopped(
    e: pgwire.PgError | pgwire.ProtocolError | OSError, conn: pgwire.Connection | None = None
) -> NoReturn:
    """Says what stopped a command on its database: the server's words, with their detail and hint (exit 1); or,
    when the server ended the session or the connection broke, that the database was lost (exit 2). An error that
    names a file is that file's. A missing authz.* function is asked about on conn (its transaction rolled back
    already): no policy, or one another version of rowstile applied, is said as the other commands say it."""
    if isinstance(e, pgwire.PgError):
        if e.code == "3F000" and 'schema "authz"' in e.message:
            none = database.no_policy()
            fail(f"{none}\nHINT: {none.hint}")  # as the other commands say it
        if e.code == "42883" and "function authz." in e.message and conn is not None:
            missing = None
            with contextlib.suppress(pgwire.PgError, pgwire.ProtocolError, OSError):  # then the server's words
                missing = transaction(conn, lambda db: database.missing_function(db, e.message), keep=False)
            if missing is not None:
                fail(f"{missing}\nHINT: {missing.hint}")
        if e.fields.get("S") in ("FATAL", "PANIC"):
            fail(f"lost the database: {e.message}", 2)
        detail, hint = e.fields.get("D"), e.fields.get("H")
        fail(e.message + (f"\nDETAIL: {detail}" if detail else "") + (f"\nHINT: {hint}" if hint else ""))
    said = file_problem(e) if isinstance(e, OSError) else None
    fail(said or f"lost the database: {e}", 2)


# --- asking as someone ---------------------------------------------------------------------------
def principal(who: str) -> tuple[str, str]:
    """'user:42' -> ('user', '42'); 'anyone' -> ('user', '')."""
    if who == "anyone":
        return "user", ""
    kind, sep, ident = who.partition(":")
    if not sep or not ident:
        fail(f"--as {who}: write it as user:42, bot:7 or anyone", 2)
    return kind, ident


Query = Callable[..., list[tuple[Value, ...]]]


def sign_in(q: Query, who: str) -> None:
    kind, ident = principal(who)
    q("SELECT authz.act_as($1, $2)", [kind, ident or None])


def app_role(q: Query) -> str:
    rows = q(
        "SELECT DISTINCT r.rolname FROM pg_catalog.pg_policy p JOIN pg_catalog.pg_description d ON d.objoid = p.oid "
        f"AND d.classoid = 'pg_catalog.pg_policy'::regclass AND d.description IN {POLICY_MARKS} "
        "CROSS JOIN unnest(p.polroles) ro JOIN pg_catalog.pg_roles r ON r.oid = ro"
    )
    if not rows:
        fail("no policy with rules is applied, so there is no app role to run as", 1)
    return str(rows[0][0])


# --- tests ---------------------------------------------------------------------------------------
def read_tests(paths: list[str]) -> dict[str, str]:
    tests: dict[str, str] = {}
    for path in paths:
        try:
            tests[relative(path).replace(os.sep, "/")] = read_text(path)
        except OSError as e:
            raise Unreadable(f"{relative(path)}: {e.strerror}") from None
    return tests


class Unreadable(Exception):
    """A file that is missing or can't be read: 'path: why'."""


def write_clients(cfg: Config, text: str, files: dict[str, str]) -> list[str]:
    """Writes the clients rowstile.toml names; returns the files that changed. Every client is made before any
    file is opened: a mistake in the policy, or a language rowstile doesn't know, leaves the files as they were."""
    made = {path: database.client(lang, text, files) for lang, path in cfg.clients.items()}
    written: list[str] = []
    for path, code in made.items():
        try:
            if read_text(path) == code:
                continue
        except OSError:
            pass
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(code)
        written.append(path)
    return written


def report_tests(rows: list[database.TestRow], out: Callable[[str], None] = print, verbose: bool = True) -> int:
    """Prints the results by test; returns the number that failed."""
    failed = 0
    current: str | None = None
    for test, line, ok, detail in rows:
        first, *rest = (detail or "").split("\n")
        if not ok:
            failed += 1
        if not verbose and ok:
            continue
        if test != current:
            out(test)
            current = test
        if ok:
            out(f"  ok    {first}")
        else:
            out(f"  FAIL  {line + ': ' if line else ''}{first}")
            for r in rest[:EXPLAIN_SHOWN]:
                out(f"          {r}")
            if len(rest) > EXPLAIN_SHOWN:
                out(f"          ... {len(rest) - EXPLAIN_SHOWN} more lines (rowstile explain --as ... shows them all)")
    return failed


# --- dev: the edit loop --------------------------------------------------------------------------
def watched(cfg: Config, policy_path: str) -> list[str]:
    files = [policy_path]
    try:
        _, inc = read_policy(policy_path)
        base = os.path.dirname(os.path.abspath(policy_path))
        files += [os.path.join(base, *k.split("/")) for k in inc]
    except OSError:
        pass
    return files + cfg.tests()


def stamp(files: list[str]) -> dict[str, int | None]:
    out: dict[str, int | None] = {}
    for f in files:
        try:
            out[f] = os.stat(f).st_mtime_ns
        except OSError:
            out[f] = None
    return out


def notice_text(n: pgwire.Fields) -> str:
    """A warning the server sent, as rowstile dev shows it: its message, then its detail and hint."""
    return n.get("M", "") + (f"\n{n['D']}" if n.get("D") else "") + (f"\n{n['H']}" if n.get("H") else "")


class Dev:
    def __init__(self, cfg: Config, dsn: str | None, policy_path: str) -> None:
        self.cfg, self.dsn, self.policy = cfg, dsn, policy_path
        self.conn: pgwire.Connection | None = None
        self.notices: list[pgwire.Fields] = []
        self.lint: set[str] | None = None
        self.studio_port: int | None = None  # rowstile dev starts Studio on it (None: not)
        self.read: tuple[str, dict[str, str]] | None = None  # the policy and its files, as the last pass read them

    def connect(self) -> pgwire.Connection:
        if self.conn is None:
            self.notices.clear()
            conn = pgwire.connect(**pgwire.parse_dsn(self.dsn), on_notice=self.notices.append)
            for n in self.notices:  # what the server said as the session started, said once
                self.say("!", notice_text(n))
            self.notices.clear()
            conn.query("SELECT set_config('client_min_messages', 'warning', false)")
            self.conn = conn
        return self.conn

    def index_warnings(self) -> None:
        """The lookups the policy makes into the app's tables that no index serves (rowstile indexes), once."""
        from authzlib import perf

        try:
            missing = transaction(
                self.connect(),
                lambda db: perf.missing_indexes(db, database.policy_compiler(*database.applied(db))),
                keep=False,
            )
        except (database.Error, pgwire.PgError, pgwire.ProtocolError, OSError) as e:
            if isinstance(e, database.Error) or (
                isinstance(e, pgwire.PgError) and e.fields.get("S") not in ("FATAL", "PANIC")
            ):
                return  # the look didn't go through (a statement cancelled, say), and the session goes on
            # the session is gone: said as a pass says it, and the next save connects again
            self.say("x", f"lost the database: {e.message if isinstance(e, pgwire.PgError) else e}")
            self.conn = None
            return
        if missing:
            self.say("!", perf.describe_missing(missing, self.cfg.tool or "sql"))

    def say(self, mark: str, text: str) -> None:
        lines = text.split("\n")
        print(f"  {mark:<4} {lines[0]}")
        for line in lines[1:]:
            print(f"       {line}")

    @staticmethod
    def left(pushed: bool) -> str:
        """What an error in a pass leaves in the database."""
        return "the policy is applied; its tests didn't run" if pushed else "nothing applied"

    def cycle(self, why: str) -> bool:
        """One pass; True if everything passed."""
        print(f"{time.strftime('%H:%M:%S')} {why}")
        try:
            text, files = read_policy(self.policy)
        except OSError as e:
            self.say("x", f"{relative(self.policy)}: {e.strerror}")
            return False
        self.read = (text, files)
        try:
            msg = database.check(text, files)
        except RecursionError:
            msg = "an expression in the policy is nested too deep to read"
        if msg:
            where = msg.removeprefix("policy ")
            line = re.match(r"(?:(\S+) )?line (\d+):", where)
            source = ""
            if line:
                name = line.group(1)
                body = files.get(name, text) if name else text
                lines = body.split("\n")
                n = int(line.group(2))
                assert 0 < n <= len(lines), where  # a line of the file it read (tests/fuzz_parser.py checks)
                source = "\n  " + lines[n - 1].strip()
            self.say(
                "x",
                f"{relative(self.policy)}: {where}{source}\nnothing applied: the database keeps the policy in force",
            )
            return False
        self.say("ok", "compiles")
        try:
            conn = self.connect()
        except (ValueError, OSError, pgwire.PgError, pgwire.ProtocolError) as e:
            self.say("x", cant_connect(e, self.dsn))
            self.conn = None
            return False
        pushed = False  # an error after the push leaves the policy in force: only the tests didn't run
        try:
            self.diff(conn, text, files)
            self.notices.clear()
            started = time.monotonic()
            state = transaction(conn, lambda db: database.push(db, text, files))
            pushed = True
            took = time.monotonic() - started
            self.say(
                "ok",
                "unchanged: already in force"
                if state == "unchanged"
                else f"applied in {took:.2f} s" + (" (the whole policy)" if state == "applied" else ""),
            )
            warnings = [notice_text(n) for n in self.notices]
            for w in warnings:
                if w not in (self.lint or ()):
                    self.say("!", w)
            old = sum(1 for w in warnings if w in (self.lint or ()))
            if old:
                self.say("!", f"and {old} warning(s) shown before")
            if state != "unchanged":
                self.lint = set(warnings)
            passed = self.tests(conn)
            for path in write_clients(self.cfg, text, files):
                self.say("ok", f"wrote {relative(path)}")
            return passed
        except Unreadable as e:
            self.say("x", str(e))
            return False
        except database.Error as e:
            self.say("x", str(e) + (f"\n{e.hint}" if e.hint else "") + "\n" + self.left(pushed))
            return False
        except pgwire.PgError as e:
            if e.fields.get("S") in ("FATAL", "PANIC"):  # the server ended the session: the next pass connects again
                self.say("x", f"lost the database: {e.message}")
                self.conn = None
                return False
            detail = e.fields.get("D")
            self.say("x", e.message + (f"\n{detail}" if detail else "") + "\n" + self.left(pushed))
            return False
        except (OSError, pgwire.ProtocolError) as e:
            said = file_problem(e) if isinstance(e, OSError) else None
            if said:  # a client file it couldn't write: the database is still there
                self.say("x", said)
                return False
            self.say("x", f"lost the database: {e}")
            self.conn = None
            return False

    def diff(self, conn: pgwire.Connection, text: str, files: dict[str, str]) -> None:
        def changes(db: Db) -> list[database.DiffRow] | None:
            return database.diff(db, text, files) if in_force(db) else None

        found = transaction(conn, changes, keep=False)
        if found is None:
            return
        groups: dict[tuple[str, str, str], tuple[set[str | None], set[str]]] = {}
        for r in found:
            users, objs = groups.setdefault((r["change"], r["type"], r["what"]), (set(), set()))
            users.add(r["user_id"])
            objs.add(r["id"])
        rows = [(c, t, w, len(u), len(o)) for (c, t, w), (u, o) in sorted(groups.items())]
        if not rows:
            self.say("~", "access: nobody gains or loses anything")
            return
        parts = [
            f"{users} user(s) {change.rstrip('s')} {what} on {objs} {type_}{'' if objs == 1 else 's'}"
            if what.startswith("permission ")
            else f"{users} user(s) {change.rstrip('s')} {what} in {type_} ({objs} row{'' if objs == 1 else 's'})"
            for change, type_, what, users, objs in rows[:8]
        ]
        more = f"\n... and {len(rows) - 8} more (rowstile diff)" if len(rows) > 8 else ""
        self.say("~", "access:\n" + "\n".join(parts) + more)

    def tests(self, conn: pgwire.Connection) -> bool:
        from authzlib import coverage

        tests = read_tests(self.cfg.tests())
        rows, report = transaction(conn, lambda db: database.coverage(db, tests), keep=False)
        failed = report_tests(rows, out=lambda s: None)
        if not rows:
            self.say("ok", 'no tests yet (rowstile.toml: tests = ["db/tests/*.authz"])')
            return True
        if not failed:
            missing = coverage.summary(report)
            self.say("ok", f"{len(rows)} check(s) pass" + (f"; {missing}" if missing else ""))
            return True
        out: list[str] = []
        report_tests(rows, out=out.append, verbose=False)
        self.say("x", f"{failed} of {len(rows)} checks fail\n" + "\n".join(out))
        return False

    def run(self, once: bool) -> bool:
        reconfigure = getattr(sys.stdout, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(line_buffering=True)  # a line as it happens, even into a pipe or a log
        target = pgwire.parse_dsn(self.dsn)
        print(
            f"rowstile dev: {relative(self.policy)} -> {target['database']} on {target['host']}:{target['port']}"
            + (f" (from {ENV.where})" if ENV.where else "")
        )
        passed = self.cycle("start")
        if passed:
            self.index_warnings()
        if once:
            return passed
        if self.studio_port is not None:
            # Studio beside the loop, able to write: this is a development database
            import studio

            try:
                url = studio.Studio(
                    self.dsn, self.cfg, self.policy, writable=True, port=self.studio_port, read_policy=read_policy
                ).start()
                print(f"Studio on {url}")
            except OSError as e:
                print(f"Studio didn't start ({e}): rowstile dev --studio-port N for another port")
        files = watched(self.cfg, self.policy)
        seen = stamp(files)
        # with [migrations] in rowstile.toml, the migration is written once you stop editing (write_after
        # seconds after the last save that passed; 0: never, run rowstile migrate yourself)
        after = self.cfg.write_after
        pending: float | None = None
        print(f"watching {len(files)} file(s); Ctrl-C to stop")
        try:
            while True:
                time.sleep(0.4)
                files = watched(self.cfg, self.policy)
                now = stamp(files)
                if now != seen:
                    changed = [relative(f) for f in files if now.get(f) != seen.get(f)]
                    time.sleep(0.1)  # editors write in steps
                    seen = stamp(files)
                    pending = time.monotonic() if self.cycle(", ".join(changed[:3]) + " saved") and after else None
                if pending is not None and time.monotonic() - pending >= after:
                    pending = None
                    self.write_migration()
        except KeyboardInterrupt:
            return True

    def write_migration(self) -> None:
        """'stopped editing': the migration for what changed, if the lock file is behind the policy: the policy
        the last pass read, checked and pushed (a file changed since is the next pass's, not the migration's)."""
        assert self.read is not None  # the timer is set by a pass that went through
        text, files = self.read
        print(f"{time.strftime('%H:%M:%S')} stopped editing")
        try:
            migrate_cmd(self.cfg, self.policy, text, files, {}, False)
        except SystemExit:
            pass
        except OSError as e:  # a file it couldn't write: said, as migrate says it, and the loop goes on
            print(file_problem(e) or str(e), file=sys.stderr)


# --- main ----------------------------------------------------------------------------------------
class Takes(NamedTuple):
    """What a command takes: how many arguments (fewest, most; None: any number), and its options besides --help.
    Any other option is refused: one it would ignore (`check --db URL`, `apply --check`) would say nothing."""

    fewest: int
    most: int | None
    options: str = ""  # the options, one space between


# each command, and what it takes
ARGUMENTS: dict[str, Takes] = {
    "dev": Takes(0, 1, "--db --once --no-studio --studio-port"),
    "studio": Takes(0, 0, "--db --port --write"),
    "migrate": Takes(0, 1, "--name --check --tool --dir --one-phase --downgrade"),
    "review": Takes(0, 1, "--db --base --markdown --json --annotations --out"),
    "fmt": Takes(0, None, "--check"),
    "push": Takes(0, 1, "--db --development --downgrade"),
    "apply": Takes(0, 1, "--db --force --downgrade"),
    "check": Takes(0, 1),
    "prove": Takes(0, 1, "--worlds"),
    "diff": Takes(0, 1, "--db --users --limit"),
    "test": Takes(0, None, "--db --coverage"),
    "graph": Takes(0, 1, "--db"),
    "lint": Takes(0, 0, "--db"),
    "indexes": Takes(0, 0, "--db --check"),
    "plans": Takes(0, 0, "--db --as"),
    "bench": Takes(0, 0, "--db --people --rounds"),
    "snapshot": Takes(0, 0, "--db --check --out"),
    "client": Takes(0, 2, "--db"),
    "init": Takes(0, 0, "--db --schema --users --role --out"),
    "lsp": Takes(0, 0),
    "mcp": Takes(0, 0, "--db"),
    "can": Takes(3, 3, "--db --as"),
    "explain": Takes(3, 3, "--db --as"),
    "perms": Takes(2, 2, "--db --as"),
    "list": Takes(2, 2, "--db --as"),
    "who": Takes(3, 3, "--db --as"),
    "why": Takes(3, 3, "--db --as"),
    "explain-rule": Takes(2, 3, "--db --as --row"),
    "sql": Takes(1, 1, "--db --as"),
    "reapply": Takes(0, 0, "--db --force"),
    "remove": Takes(0, 0, "--db --yes --downgrade"),
}
# the options that take a value (the others are flags)
VALUED = (
    "--db",
    "--users",
    "--limit",
    "--as",
    "--row",
    "--schema",
    "--role",
    "--out",
    "--name",
    "--tool",
    "--dir",
    "--base",
    "--port",
    "--studio-port",
    "--worlds",
    "--people",
    "--rounds",
)


def command_help(cmd: str) -> str:
    """What `rowstile CMD --help` prints: that command's lines of the usage, and where the database comes from."""
    assert __doc__ is not None
    where = __doc__[__doc__.index("\nThe database is ") + 1 :].splitlines()[:3]  # ... and that .env may hold them
    return "\n".join([*usage_lines(cmd), "", *where, "rowstile --help: every command, and rowstile.toml"])


def usage_lines(cmd: str) -> list[str]:
    """A command's lines of the usage: its line and the lines indented under it (each command has one:
    tests/unit_test.py asks)."""
    assert __doc__ is not None
    own = re.search(rf"^    rowstile {re.escape(cmd)}(?: .*)?\n(?:     .*\n)*", __doc__, re.M)
    assert own is not None, cmd
    return [line[4:] for line in own[0].splitlines()]


def check_row(text: str) -> None:
    """--row is a JSON object. What isn't is shown as it arrived: Windows PowerShell 5 and cmd take the double
    quotes out of '{"column": 1}' before the command sees it, and JSON's own message doesn't say so."""
    try:
        row = json.loads(text)
    except ValueError as e:
        taken = '"' not in text and re.match(r"\s*\{\s*\w+\s*:", text)
        fail(
            f"--row: not JSON: {text}\n  {e}"
            + (
                "\n  The shell took the double quotes: in Windows PowerShell write '{\\\"column\\\": 1}', "
                'in cmd "{\\"column\\": 1}"'
                if taken
                else ""
            ),
            2,
        )
    if not isinstance(row, dict):
        fail('--row: the row as a JSON object, {"column": value}', 2)


def utf8_output() -> None:
    """What the command prints is UTF-8 wherever it goes. On Windows, Python writes into a pipe or a file in the
    system's code page: a character it lacks (an arrow, a name in another script) stopped the command, and the
    files written this way (the review's comment, a graph) were not UTF-8."""
    for stream in (sys.stdout, sys.stderr):
        if isinstance(stream, io.TextIOWrapper):
            stream.reconfigure(encoding="utf-8", errors="backslashreplace")


def is_option(word: str) -> bool:
    """Whether a word of the command line is an option: it starts with -, and isn't a negative number (an id)."""
    return word.startswith("-") and word != "-" and not re.fullmatch(r"-\d+(\.\d+)?", word)


def main(argv: list[str]) -> None:
    utf8_output()
    dsn: str | None = None
    opts: dict[str, str] = {}

    # options are read wherever they are on the line: `rowstile --db URL lint` and `rowstile lint --db URL`
    # (for `sql`, not in its last argument: that is the statement, which may hold anything)
    def options() -> list[str]:
        return argv[:-1] if "sql" in argv else argv

    written: list[str] = []  # the options on the line, in its order
    for i, word in enumerate(options()):
        if is_option(word) and word not in ("--help", "-h") and (i == 0 or argv[i - 1] not in VALUED):
            written.append(word)
    for flag in VALUED:
        if flag in options():
            i = argv.index(flag)
            if i + 1 >= len(argv):
                fail(f"{flag} needs a value", 2)
            if not argv[i + 1]:  # a script's --db "$DATABASE_URL", with the variable unset
                fail(f"{flag} is empty", 2)
            opts[flag] = argv[i + 1]
            del argv[i : i + 2]
            if flag in options():
                fail(f"{flag} is given twice", 2)
    if "--db" in opts:
        dsn = opts.pop("--db")
    for flag in ("--limit", "--port", "--studio-port", "--worlds", "--people", "--rounds"):
        if flag in opts and not (opts[flag].isdigit() and int(opts[flag]) > 0):
            fail(f"{flag} needs a whole number above 0, not {opts[flag]!r}", 2)
    for flag in ("--port", "--studio-port"):
        if flag in opts and int(opts[flag]) > 65535:
            fail(f"{flag} needs a port, a whole number from 1 to 65535, not {opts[flag]!r}", 2)
    if argv == ["--version"]:
        from authzlib import __version__

        print(f"rowstile {__version__} (Python {sys.version.split()[0]})")
        return
    asked = "--help" in argv or "-h" in argv
    flags = {a for a in options() if is_option(a) and a not in ("--help", "-h")}
    argv = [a for a in argv if a not in flags and a not in ("--help", "-h")]
    if argv[:1] == ["help"] and argv[1:]:
        from authzlib import errors

        if argv[2:]:
            fail("rowstile help takes one code: rowstile help AZ201 (rowstile help errors lists them)", 2)
        code = argv[1].upper()
        if code in errors.CODES:
            print(errors.page(code))
        elif code == "ERRORS":
            sys.stdout.write(errors.index())
        else:
            fail(f"rowstile help: no code {argv[1]} (rowstile help errors lists them)", 2)
        return
    if argv and argv[0] in ARGUMENTS and asked:
        print(command_help(argv[0]))
        return
    if argv[:1] == ["help"] or (asked and not argv):
        print(__doc__)  # asked for: on stdout, for a pager or grep
        return
    if not argv:
        fail(__doc__, 2)
    cmd, args = argv[0], argv[1:]
    if cmd not in ARGUMENTS:
        fail(f"unknown command '{cmd}'\n\n{__doc__}", 2)
    takes = ARGUMENTS[cmd]
    for option in written:
        if option in takes.options.split():
            continue
        if option == "--db" and cmd == "lsp":  # the editor's folder says where its database is
            fail("rowstile lsp: --db is not an option it has: it reads the database rowstile.toml names", 2)
        if option == "--db":
            fail(f"rowstile {cmd}: --db is not an option it has: it reads no database", 2)
        fail(f"rowstile {cmd}: {option} is not an option it has (rowstile {cmd} --help)", 2)
    if takes.most is not None and len(args) > takes.most:
        fail(
            f"rowstile {cmd} takes {takes.most or 'no'} argument{'' if takes.most == 1 else 's'}: what is "
            f"{' '.join(args[takes.most :])}? (rowstile {cmd} --help)",
            2,
        )
    if len(args) < takes.fewest:
        counts = f"{takes.fewest}" if takes.most == takes.fewest else f"{takes.fewest} or {takes.most}"
        fail(f"rowstile {cmd} takes {counts} arguments, not {len(args)}:\n" + "\n".join(usage_lines(cmd)), 2)
    if cmd == "lsp":
        from lsp import serve

        serve(lsp_settings)  # it reads rowstile.toml itself: a mistake in it is the editor's to show
        return
    cfg = load_config()
    if dsn is None:  # --db names the database: no file then adds a host or a port to what the command line said
        ENV.load(cfg.dir)
    if cmd == "mcp":
        import mcp

        mcp.serve(dsn)
        return

    def policy_arg() -> tuple[str, str, dict[str, str]]:
        path = args[-1] if args else cfg.policy
        if not path:
            fail(f'rowstile {cmd}: which policy file? (or name it in {CONFIG}: policy = "db/policy.authz")', 2)
        try:
            text, files = read_policy(path)
        except OSError as e:
            fail(f"{path}: {e.strerror}", 2)
        return path, text, files

    # without a database: the compiler alone (graph and client read the policy file, or with --db the database's)
    if cmd in ("graph", "client") and dsn is not None and len(args) > (cmd == "client"):
        fail(f"rowstile {cmd}: --db or a policy file, not both: a file is read without a database", 2)
    try:
        if cmd == "check":
            path, text, files = policy_arg()
            msg = database.check(text, files)
            if msg:
                fail(f"{path}: {msg.removeprefix('policy ')}")
            print(f"{path}: ok")
            return
        if cmd == "graph" and (args or (cfg.policy and dsn is None)):
            _, text, files = policy_arg()
            sys.stdout.write(database.graph(text, files))
            return
        if cmd == "client" and args[1:]:
            if args[0] not in ("py", "ts"):
                fail("rowstile client: which language, py or ts?", 2)
            _, text, files = policy_arg()
            sys.stdout.write(database.client(args[0], text, files))
            return
        if cmd == "prove":
            from authzlib import parse_policy, prove

            path, text, files = policy_arg()
            # the policy as `rowstile check` sees it: one the compiler refuses has nothing to prove
            msg = database.check(text, files)
            if msg:
                fail(f"{relative(path)}: {msg.removeprefix('policy ')}")
            pol = parse_policy(text, None, files=files)  # read as check read it: no mistake now
            if not pol.invariants:
                print(f"{relative(path)}: no invariants to prove (write them under 'invariants': never TYPE: ...)")
                return
            results = prove.prove(pol, worlds=int(opts.get("--worlds", prove.WORLDS)))
            print(prove.describe(results))
            holds = all(r["holds"] for r in results)
            sys.exit(0 if holds else 1)
        if cmd == "fmt":
            sys.exit(fmt_cmd(cfg, args, "--check" in flags))
        if cmd == "review":
            sys.exit(review_cmd(cfg, args, opts, flags, dsn))
        if cmd == "migrate":
            path, text, files = policy_arg()
            sys.exit(
                migrate_cmd(
                    cfg, path, text, files, opts, "--check" in flags, "--one-phase" in flags, "--downgrade" in flags
                )
            )
        if cmd == "client" and not args and cfg.clients and cfg.policy and dsn is None:
            _, text, files = policy_arg()
            write_clients(cfg, text, files)
            for path in cfg.clients.values():
                print(f"wrote {relative(path)}")
            return
    except database.Error as e:
        fail(str(e) + (f"\nHINT: {e.hint}" if e.hint else ""))
    except Unreadable as e:
        fail(str(e), 2)
    except OSError as e:
        fail(file_problem(e) or str(e), 2)
    except RecursionError:
        fail(f"rowstile {cmd}: an expression in the policy is nested too deep to read", 1)

    if cmd == "init":
        from init import out_problem

        problem = out_problem(opts.get("--out", "db"))
        if problem:
            fail(problem, 2)
    given = dsn
    dsn = dsn if dsn is not None else (cfg.database or os.environ.get("DATABASE_URL"))
    ENV.where = cfg.database_from(given)
    if cmd == "dev":
        path = args[0] if args else cfg.policy
        if not path:
            fail(f'rowstile dev: which policy file? (or name it in {CONFIG}: policy = "db/policy.authz")', 2)
        try:
            pgwire.parse_dsn(dsn)  # one it can't read is said before the loop starts, as the other commands say it
        except ValueError as e:
            fail(cant_connect(e, dsn), 2)
        dev = Dev(cfg, dsn, path)
        dev.studio_port = None if "--no-studio" in flags else int(opts.get("--studio-port", "4983"))
        sys.exit(0 if dev.run("--once" in flags) else 1)
    if cmd == "studio":
        import studio

        studio.serve(dsn or "", cfg, cfg.policy, "--write" in flags, int(opts.get("--port", "4983")), read_policy)
        return

    try:
        conn = pgwire.connect(**pgwire.parse_dsn(dsn), on_notice=print_notice)  # those it sends as it starts too
    except (ValueError, OSError, pgwire.PgError, pgwire.ProtocolError) as e:
        fail(cant_connect(e, dsn), 2)
    q = conn.query
    try:
        q("SELECT set_config('client_min_messages', 'warning', false)")  # a session lost already is said as below
        if cmd == "apply":
            path, text, files = policy_arg()
            state = transaction(
                conn,
                lambda db: database.apply(
                    db, text, files, "--force" not in flags, "--downgrade" in flags, rebuild="--force" in flags
                ),
            )
            print(f"{path}: {state}")
        elif cmd == "push":
            path, text, files = policy_arg()
            state = transaction(
                conn,
                lambda db: database.push(
                    db, text, files, mark="--development" in flags, downgrade="--downgrade" in flags
                ),
            )
            print(f"{path}: {state}" + (" (the whole policy)" if state == "applied" else ""))
        elif cmd == "diff":
            path, text, files = policy_arg()
            users = [u for u in opts.get("--users", "").split(",") if u] or None
            cols = ["change", "user_id", "type", "what", "id"]
            rows = [
                (
                    r["change"],
                    r["user_id"] if r["user_id"] is not None else "(nobody signed in)",
                    r["type"],
                    r["what"],
                    r["id"],
                )
                for r in transaction(conn, lambda db: database.diff(db, text, files, users), keep=False)
            ]
            counts: dict[tuple[str, str, str], int] = {}
            for change, _, type_, what, _ in rows:
                counts[(type_, what, change)] = counts.get((type_, what, change), 0) + 1
            print(f"{path}: {len(rows)} changes" + ("" if rows else " (nobody gains or loses anything)"))
            if rows:
                print(
                    table(
                        [(t, w, c, n) for (t, w, c), n in sorted(counts.items())], ["type", "what", "change", "pairs"]
                    )
                )
                limit = int(opts.get("--limit", 200))
                print()
                print(table(rows[:limit], cols))
                if len(rows) > limit:
                    print(f"... and {len(rows) - limit} more (--limit)")
        elif cmd == "test":
            from authzlib import coverage

            if not args and cfg.test_globs() and not cfg.tests():
                print(f"{cfg.path}: tests = {cfg.test_globs()} matches no file", file=sys.stderr)
            tests = read_tests(args or cfg.tests())
            report: coverage.Report | None = None
            if "--coverage" in flags:
                rows, report = transaction(conn, lambda db: database.coverage(db, tests), keep=False)
            else:
                rows = transaction(conn, lambda db: database.test(db, tests), keep=False)
            failed = report_tests(rows)
            if failed:
                print(f"{failed} policy test(s) failed")  # after the results, on the same stream
                sys.exit(1)
            print(f"policy tests passed ({len(rows)} checks)")
            if report is not None:
                print(coverage.describe(report))
        elif cmd == "snapshot":
            snapshot_cmd(conn, cfg, opts, "--check" in flags)
        elif cmd == "lint":
            found = transaction(conn, database.lint, keep=False)
            if not found:
                print("authz.lint(): nothing found")
            else:
                print(
                    table(
                        [(r["severity"], r["object"], r["problem"]) for r in found], ["severity", "object", "problem"]
                    )
                )
            if any(r["severity"] in ("error", "warning") for r in found):
                sys.exit(1)
        elif cmd in ("indexes", "plans", "bench"):
            from authzlib import perf

            def compiled(db: Db) -> database.Compiler:
                return database.policy_compiler(*database.applied(db))

            if cmd == "indexes":
                out = transaction(conn, lambda db: perf.missing_indexes(db, compiled(db)), keep=False)
                if out:
                    print(perf.describe_missing(out, cfg.tool or "sql"))
                else:
                    print("every lookup the policy makes into the app's tables has an index")
                if out and "--check" in flags:
                    sys.exit(1)
            elif cmd == "plans":
                who = principal(opts["--as"]) if opts.get("--as") else None
                print(perf.describe_plans(transaction(conn, lambda db: perf.plans(db, compiled(db), who), keep=False)))
            else:
                people, rounds = int(opts.get("--people", "10")), int(opts.get("--rounds", "20"))
                print(
                    perf.describe_bench(
                        transaction(
                            conn, lambda db: perf.bench(db, compiled(db), people=people, rounds=rounds), keep=False
                        )
                    )
                )
        elif cmd == "graph":
            text, files = transaction(conn, database.applied, keep=False)
            sys.stdout.write(database.graph(text, files))
        elif cmd == "client":
            text, files = transaction(conn, database.applied, keep=False)
            if not args and cfg.clients:
                write_clients(cfg, text, files)
                for path in cfg.clients.values():
                    print(f"wrote {relative(path)}")
                return
            if not args or args[0] not in ("py", "ts"):
                fail("rowstile client: which language, py or ts?", 2)
            sys.stdout.write(database.client(args[0], text, files))
        elif cmd == "why":
            if not opts.get("--as"):
                fail("rowstile why --as user:42 TYPE ID PERM", 2)
            from authzlib import grant

            kind, ident = principal(opts["--as"])
            if not ident:  # as its other usage errors
                fail("rowstile why: as whom? someone signed in (user:42, bot:7): nobody can be given access", 2)
            type_name, oid, perm = args
            answer = transaction(conn, lambda db: database.why(db, kind, ident, type_name, oid, perm), keep=False)
            print(grant.describe(answer, opts["--as"], type_name, oid, perm))
        elif cmd in ("can", "explain", "perms", "list", "who", "explain-rule", "sql"):
            ask(conn, cmd, args, opts)
        elif cmd == "init":
            from init import init

            # DATABASE_URL, which the next command reads, and where it is: with --db, the files weren't read above
            app_url: tuple[str, str] | None = None
            if os.environ.get("DATABASE_URL"):
                app_url = (os.environ["DATABASE_URL"], "")
            elif given is not None:
                env_files = EnvFiles()
                env_files.peek(cfg.dir)
                if env_files.values.get("DATABASE_URL"):
                    app_url = (env_files.values["DATABASE_URL"], env_files.source["DATABASE_URL"])
            schemas = [s for s in opts.get("--schema", "").split(",") if s] or None
            policy = transaction(
                conn,
                lambda db: database.draft(db, schemas, opts.get("--users"), opts.get("--role", "app_user")),
                keep=False,
            )
            init(policy, opts, cfg, ENV.where, given, app_url)
        elif cmd == "reapply":
            transaction(conn, lambda db: database.reapply(db, rebuild="--force" in flags))
            print("applied again")
        else:
            assert cmd == "remove", cmd  # every other command of ARGUMENTS is answered above
            if "--yes" not in flags:
                fail(
                    "rowstile remove drops every view, trigger and row-level security policy the current policy made "
                    "(shares and history stay). Run it again with --yes.",
                    2,
                )
            transaction(conn, lambda db: database.remove(db, downgrade="--downgrade" in flags))
            print("removed")
    except database.Error as e:
        fail(str(e) + (f"\nHINT: {e.hint}" if e.hint else ""))
    except (pgwire.PgError, pgwire.ProtocolError, OSError) as e:
        database_stopped(e, conn)
    except Unreadable as e:
        fail(str(e), 2)
    except RecursionError:
        fail(f"rowstile {cmd}: an expression in the policy is nested too deep to read", 1)
    except KeyboardInterrupt:
        fail("stopped: nothing was kept", 130)
    finally:
        conn.close()


# --- review and fmt ------------------------------------------------------------------------------
def git(*args: str) -> str | None:
    """What a git command prints, None if it fails. A file at the base that isn't UTF-8 is read all the same,
    its other bytes replaced: the review goes on, as it does for any base that doesn't compile."""
    import subprocess

    try:
        p = subprocess.run(["git", *args], capture_output=True, text=True, encoding="utf-8", errors="replace")
    except FileNotFoundError:
        fail("rowstile: git is not installed (the review reads the base branch with it)", 2)
    return p.stdout if p.returncode == 0 else None


def base_unreadable(what: str, ref: str) -> NoReturn:
    """The review stops where git can't read the base: read as missing, the policy there would be reviewed as new,
    and its tests left out."""
    fail(
        f"rowstile review: git can't {what} at {ref}: this repository is missing objects of that commit (a partial "
        "clone that can't fetch them? fetch the base's history: fetch-depth: 0 with actions/checkout, and no filter)",
        2,
    )


def at_base(ref: str, path: str) -> str | None:
    """A file's text at a commit (None if it isn't there), for a path relative to here. One git lists there and
    can't read, or one in a folder git can't list (a repository missing objects: a partial clone that can't fetch
    them), stops the review."""
    try:
        rel = os.path.relpath(path).replace(os.sep, "/")
    except ValueError:
        return None  # on another drive (Windows): not a file of the repository this folder is in
    # --: a file of the commit, never a pattern (a name with [ or * that isn't there showed nothing, and no error)
    text = git("show", f"{ref}:./{rel}" if not rel.startswith("..") else f"{ref}:{rel}", "--")
    if text is None:  # not there, or there and unreadable: the folders it is in, alone, tell which
        name = in_repository(path)
        if name == ".." or name.startswith("../"):
            return None  # above the repository's top folder: not one of its files
        entry = git("--literal-pathspecs", "ls-tree", "-z", "--full-tree", ref, "--", name)
        if entry != "":  # listed (its text can't be read), or a folder on its way git can't list (None)
            base_unreadable(f"read {relative(path)}", ref)
    return text


def in_repository(path: str) -> str:
    """A path as git names it: from the repository's top folder, with /. Worked out from this folder (git says
    where it is in the repository), never from the top folder's own path: git gives that one resolved, and on
    Windows this folder may be reached through a subst drive or a junction, so the two don't start alike. A path
    on another drive stays as it is."""
    try:
        rel = os.path.relpath(path).replace(os.sep, "/")
    except ValueError:
        return path.replace(os.sep, "/")
    return posixpath.normpath(posixpath.join((git("rev-parse", "--show-prefix") or "").strip(), rel))


def base_policy(ref: str, path: str) -> tuple[str | None, dict[str, str]]:
    """The policy at a commit, and the files it includes (read from git, as read_policy reads the disk)."""
    text = at_base(ref, path)
    if text is None:
        return None, {}
    base = os.path.dirname(os.path.abspath(path))
    return text, collect_includes(text, lambda key: at_base(ref, os.path.join(base, *key.split("/"))))


def found_by_glob(name: str, pattern: str) -> bool:
    """Whether glob.glob finds a file for a pattern (both from the same folder, with /), as Config.tests finds the
    pull request's test files: folder by folder (fnmatch alone lets a * cross a /), and a name that starts with a
    dot only for a part of the pattern that does."""
    import fnmatch

    names, parts = name.split("/"), pattern.split("/")
    return len(names) == len(parts) and all(
        fnmatch.fnmatch(n, p) and (p.startswith(".") or not n.startswith("."))
        for n, p in zip(names, parts, strict=True)
    )


def base_tests(cfg: Config, ref: str) -> dict[str, str]:
    """The test files rowstile.toml names, as they were at a commit. One git lists there and can't read, or a
    folder of the commit git can't list (a repository missing objects: a partial clone that can't fetch them),
    stops the review: the base's tests would be read without it."""
    here = git("rev-parse", "--show-prefix")  # this folder, from the top one
    # review_cmd found the commit with git here: git answers this too, even inside .git or a bare repository
    assert here is not None
    # from the top folder, wherever this runs; -z: names as they are (git quotes one with an accent otherwise)
    listed = git("ls-tree", "-r", "-z", "--name-only", "--full-tree", ref)
    if listed is None:  # which test files the commit holds can't be known
        base_unreadable("list the files", ref)
    out: dict[str, str] = {}
    for pattern in cfg.test_globs():
        rel_pattern = in_repository(cfg.file(pattern))
        for name in listed.split("\0"):
            if name and found_by_glob(name, rel_pattern):
                shown = posixpath.relpath(name, here.strip() or ".")  # named as read_tests names it
                text = git("show", f"{ref}:{name}")
                if text is None:  # listed, and its text can't be read
                    base_unreadable(f"read {shown}", ref)
                out[shown] = text
    return out


def default_base() -> str:
    for ref in ("origin/main", "main", "origin/master", "master"):
        if git("rev-parse", "--verify", "--quiet", ref) is not None:
            return ref
    fail("rowstile review: which commit to compare with? --base main (or a commit)", 2)


def review_cmd(cfg: Config, args: list[str], opts: dict[str, str], flags: set[str], dsn: str | None) -> int:
    """What the change since --base does, as text, --markdown (the pull request comment), --json
    or --annotations (GitHub workflow commands); with --out FILE, the comment in FILE too. Access and the tests'
    results need --db: a database at the base's state (its migrations, then the review data), which the review
    changes nothing in."""
    from authzlib import review

    path = args[-1] if args else cfg.policy
    if not path:
        fail(f'rowstile review: which policy file? (or name it in {CONFIG}: policy = "db/policy.authz")', 2)
    ref = opts.get("--base") or default_base()
    # a commit git doesn't know would read as "no policy there": the whole policy reviewed as new
    if ref.startswith("-") or git("rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}") is None:
        fail(
            f"rowstile review: git doesn't know the commit to compare with, {ref} (a shallow checkout? fetch the "
            "base branch: fetch-depth: 0 with actions/checkout)",
            2,
        )
    try:
        head_text, head_files = read_policy(path)
    except OSError as e:
        fail(f"{relative(path)}: {e.strerror}", 2)
    base_text, base_files = base_policy(ref, path)
    lock = lock_path(cfg, path)
    base_lock = at_base(ref, lock)
    try:
        with open(lock, encoding="utf-8") as fh:
            head_lock = fh.read()
    except FileNotFoundError:
        head_lock = None
    head_tests = read_tests(cfg.tests())
    conn: pgwire.Connection | None = None
    db: Db | None = None
    if dsn is not None:
        try:
            # what the server says as the session starts is said (a collation version that doesn't match), what
            # the review's statements make it say isn't
            conn = pgwire.connect(**pgwire.parse_dsn(dsn), on_notice=print_notice)
        except (ValueError, OSError, pgwire.PgError, pgwire.ProtocolError) as e:
            fail(cant_connect(e, dsn), 2)
        conn.on_notice = lambda f: None
    try:
        if conn is not None:
            conn.execute("BEGIN")  # a session lost already is said as below
            db = Db(conn)
        base = None if base_text is None else (base_text, base_files, base_tests(cfg, ref))  # None: the policy is new
        r = review.review(base, (head_text, head_files, head_tests), base_lock, head_lock, db)
    except database.Error as e:
        fail(str(e) + (f"\nHINT: {e.hint}" if e.hint else ""))
    except review.PolicyError as e:
        fail(f"{relative(path)}: {e}")
    except (pgwire.PgError, pgwire.ProtocolError, OSError) as e:  # the review database's (--db)
        database_stopped(e)
    finally:
        if conn is not None:
            abandon(conn)
            conn.close()
    if opts.get("--out"):  # the comment to a file, and the annotations (say) to the log: one review for both
        with open(opts["--out"], "w", encoding="utf-8", newline="\n") as fh:
            fh.write(review.markdown(r))
    if "--json" in flags:
        sys.stdout.write(review.as_json(r))
    elif "--markdown" in flags:
        sys.stdout.write(review.markdown(r))
    elif "--annotations" in flags:
        # GitHub finds the file from the repository's top folder, wherever in it the review runs
        sys.stdout.write(review.annotations(r, in_repository(path)))
    else:
        sys.stdout.write(review.text(r))
    return 0


def line_ending(path: str) -> str:
    """How the file's lines end: as its first line does (a Windows checkout's CRLF stays CRLF)."""
    with open(path, "rb") as fh:
        return "\r\n" if fh.readline().endswith(b"\r\n") else "\n"


def fmt_cmd(cfg: Config, args: list[str], check: bool) -> int:
    """Formats the policy and its test files (or the files named) one way; --check: only says which aren't.
    Line endings are the file's own: read either way, written back as found."""
    from authzlib.fmt import FormatError, format

    paths = args or ([cfg.policy] if cfg.policy else []) + cfg.tests()
    if not paths:
        fail(f"rowstile fmt: which files? (or name the policy in {CONFIG})", 2)
    bad = 0
    for path in paths:
        try:
            text, files = read_policy(path)  # with the files it includes: the format must say the same
        except OSError as e:
            fail(f"{path}: {e.strerror}", 2)
        try:
            done = format(text, files)
        except FormatError as e:
            print(f"{relative(path)}: {e}", file=sys.stderr)
            bad += 1
            continue
        if done == text:
            continue
        if check:
            print(f"{relative(path)}: not formatted (rowstile fmt)")
            bad += 1
        else:
            with open(path, "w", encoding="utf-8", newline=line_ending(path)) as fh:
                fh.write(done)
            print(f"formatted {relative(path)}")
    return 1 if bad else 0


# --- migrations ----------------------------------------------------------------------------------
def lock_path(cfg: Config, policy_path: str) -> str:
    lock = cfg.setting("migrations", "lock")
    return cfg.inside(lock, "[migrations] lock") if lock else os.path.splitext(policy_path)[0] + ".lock"


def print_changes(summary: list[str]) -> None:
    """A migration's changes: the first twenty, and how many more."""
    for line in summary[:20]:
        print(f"  {line}")
    if len(summary) > 20:
        print(f"  ... and {len(summary) - 20} more")


def migration_name(summary: list[str]) -> str:
    """A name from what changed: the one line that changed, else 'policy'."""
    if len(summary) == 1 and summary[0][:2] in ("+ ", "- "):
        words = re.sub(r"[^A-Za-z0-9]+", " ", summary[0][2:]).split()
        drop = {"type", "can", "rules", "user", "shared", "and", "or", "not"}
        return "_".join([w for w in words if w.lower() not in drop][:5]).lower() or "policy"
    return "policy"


def migrate_cmd(
    cfg: Config,
    path: str,
    text: str,
    files: dict[str, str],
    opts: dict[str, str],
    check: bool,
    one_phase: bool = False,
    downgrade: bool = False,
) -> int:
    """Writes the migration from the lock file to this policy, for the tool rowstile.toml names (two, when
    inheritance trees are built beside the ones in use first); with --check, only says whether there is one
    to write (exit 1 if so). Needs no database."""
    import migrations

    tool = opts.get("--tool") or cfg.tool or "sql"
    if tool not in migrations.TOOLS:
        fail(f"rowstile migrate: unknown tool '{tool}' (use one of {', '.join(migrations.TOOLS)})", 2)
    folder = cfg.file(opts.get("--dir") or cfg.setting("migrations", "dir") or migrations.DEFAULT_DIRS[tool])
    lock = lock_path(cfg, path)
    try:
        with open(lock, encoding="utf-8") as fh:
            old = fh.read()
    except FileNotFoundError:
        old = ""
    try:
        ms = database.migrations(text, files, old, opts.get("--name") or migration_name, not one_phase, downgrade)
    except database.Error as e:
        fail(f"{path}: {str(e).removeprefix('policy ')}" + (f"\nHINT: {e.hint}" if e.hint else ""))
    if all(m.empty for m in ms):
        print(f"nothing to migrate: {relative(lock)} is up to date with {relative(path)}")
        return 0
    summary = ms[-1].summary
    if check:
        print(f"{relative(path)} has changes no migration has: run rowstile migrate")
        print_changes(summary)
        return 1
    name = opts.get("--name") or migration_name(summary)
    written: list[str] = []
    now = time.time()
    try:
        for i, m in enumerate(ms):
            written += migrations.write_migration(
                tool, folder, f"build_{name}" if i < len(ms) - 1 else name, m.sql, now=now + i
            )
    except migrations.Error as e:
        fail(f"rowstile migrate: {e}", 2)
    os.makedirs(os.path.dirname(lock) or ".", exist_ok=True)
    with open(lock, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(ms[-1].lock)
    print_changes(summary)
    if len(ms) == 2:
        print(
            f"builds {', '.join(ms[0].rebuilt)} beside the ones in use (the app keeps working), then swaps "
            f"{'them' if len(ms[0].rebuilt) > 1 else 'it'} in: two migrations"
        )
    rebuilt = [t for t in ms[-1].rebuilt if len(ms) == 1 or t not in ms[0].rebuilt]
    if rebuilt:
        print(f"rebuilds {', '.join(rebuilt)} (the app's tables they follow are locked while it runs)")
    for f in written:
        print(f"wrote {relative(f)}")
    print(f"wrote {relative(lock)}")
    marked = (
        migrations.mark_generated(cfg.dir, migrations.generated_patterns(tool, cfg.below(folder), cfg.below(lock)))
        if cfg.path
        else None
    )
    if marked:
        print(f"wrote {relative(marked)} (reviews show the generated files collapsed)")
    return 0


def take_app_role(conn: pgwire.Connection) -> None:
    """The rest of the transaction as the app role; if this connection may not switch to it, what to grant."""
    role = app_role(conn.query)
    try:
        database.may_take(Db(conn), role)
    except database.Error as e:
        fail(str(e) + (f"\nHINT: {e.hint}" if e.hint else ""))
    conn.query(f"SET LOCAL ROLE {quote_ident(role)}")


def ask(conn: pgwire.Connection, cmd: str, args: list[str], opts: dict[str, str]) -> None:
    """One question to the database, as someone, in a transaction that is rolled back."""
    q = conn.query
    who = opts.get("--as")
    if who is None and cmd not in ("who",):
        fail(f"rowstile {cmd}: as whom? --as user:42 (or bot:7, or anyone)", 2)
    q("BEGIN")
    try:
        if who is not None:
            sign_in(q, who)
        if cmd == "can":
            ((ok,),) = q("SELECT authz.can($1, $2, $3)", args)
            print("yes" if ok else "no")
        elif cmd == "explain":
            for (line,) in q("SELECT l FROM authz.explain($1, $2, $3) l", args):
                print(line)
        elif cmd == "perms":
            ((perms,),) = q("SELECT authz.perms($1, $2)", args)
            print("\n".join(str(p) for p in perms) if isinstance(perms, list) and perms else "(none)")
        elif cmd == "list":
            for (x,) in q("SELECT x FROM authz.list($1, $2) x", args):
                print(x)
        elif cmd == "who":
            for (x,) in q("SELECT x FROM authz.who($1, $2, $3) x", args):
                print(x)
        elif cmd == "explain-rule":
            row = opts.get("--row")
            if row is not None:
                check_row(row)
            take_app_role(conn)
            ((lines,),) = q(
                "SELECT authz.explain_rule($1, $2, $3, $4::jsonb)",
                [args[0], args[1], args[2] if len(args) > 2 else None, row],
            )
            print(
                "\n".join(str(x) for x in lines)
                if isinstance(lines, list)
                else f"not found: {args[0]} {args[2] if len(args) > 2 else ''} isn't there, or {who} can't see it"
            )
        else:
            assert cmd == "sql", cmd  # main asks only the questions above
            take_app_role(conn)
            rows, cols = conn.query_described(args[0], text=True)  # values as Postgres writes them, as psql shows them
            if cols:
                print(table(rows, cols))
                print(f"({len(rows)} row{'s' if len(rows) != 1 else ''}, as {who}; rolled back)")
            else:
                # the server's own words for what the statement did: "DELETE 0" is a delete the rules let
                # through for no row, which "done" would hide
                print(f"{conn.tag or 'done'}, as {who}; rolled back")
    finally:
        abandon(conn)


def snapshot_path(cfg: Config, opts: dict[str, str]) -> str:
    """--out, else [review] snapshot in rowstile.toml, else access.snapshot next to the policy."""
    if opts.get("--out"):
        return opts["--out"]
    snapshot = cfg.setting("review", "snapshot")
    if snapshot:
        return cfg.file(snapshot)
    base = os.path.dirname(cfg.policy) if cfg.policy else "."
    return os.path.join(base, "access.snapshot")


def snapshot_cmd(conn: pgwire.Connection, cfg: Config, opts: dict[str, str], check: bool) -> None:
    path = snapshot_path(cfg, opts)
    lines = transaction(conn, database.snapshot, keep=False)
    text = database.SNAPSHOT_HEAD + "".join(x + "\n" for x in lines)
    try:
        with open(path, encoding="utf-8") as fh:
            old = fh.read()
    except OSError:
        old = None
    if check:
        if old == text:
            print(f"{relative(path)} is up to date ({len(lines)} lines)")
            return
        before = {x for x in (old or "").split("\n") if x and not x.startswith("#")}
        after = set(lines)
        print(
            f"{relative(path)} is out of date: rowstile snapshot writes it"
            if old is not None
            else f"{relative(path)} is missing: rowstile snapshot writes it"
        )
        for x in sorted(after - before)[:20]:
            print(f"  + {x}")
        for x in sorted(before - after)[:20]:
            print(f"  - {x}")
        sys.exit(1)
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)
    print(f"wrote {relative(path)} ({len(lines)} lines)")


if __name__ == "__main__":
    # run as a script (npm, Docker), this module is __main__: what imports rowstile_cli by name at run time (Studio)
    # gets this one, with the .env files it read, not a second copy without them
    sys.modules.setdefault("rowstile_cli", sys.modules[__name__])
    main(sys.argv[1:])

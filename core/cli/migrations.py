"""Writing a migration where the app's own migration tool expects it.

    [migrations]                    in rowstile.toml
    tool = "alembic"                alembic | prisma | drizzle | sql | goose | dbmate | flyway | django
    dir  = "alembic/versions"       where the tool keeps its migrations (each tool has a default; Django: the app's)
    lock = "db/policy.lock"         the lock file (default: next to the policy, <policy>.lock)
    write_after = 300               rowstile dev writes the migration this long after the last save (0: never)

Each writer gets the migration's SQL and a name, and returns the files it wrote, named so that they come after
the folder's others: Alembic chains a revision after the head, Django a migration after the app's latest; Drizzle Kit takes the journal's next number; sql,
goose, dbmate and Flyway take the number after the folder's last when it is a number (0005 after 0004, V3 after
V2), else the time (UTC), as Prisma always does.
"""

from __future__ import annotations

import calendar
import hashlib
import json
import os
import re
import time
import uuid
from typing import TypedDict

from authzlib.statements import split

TOOLS = ("alembic", "prisma", "drizzle", "sql", "goose", "dbmate", "flyway", "django")
DEFAULT_DIRS = {
    "alembic": "alembic/versions",
    "prisma": "prisma/migrations",
    "drizzle": "drizzle",
    "sql": "migrations",
    "goose": "migrations",
    "dbmate": "db/migrations",
    "flyway": "sql",
    "django": "migrations",  # an app's own: [migrations] dir = "<app>/migrations"
}


class Error(Exception):
    pass


class JournalEntry(TypedDict):
    idx: int
    version: str
    when: int  # milliseconds
    tag: str
    breakpoints: bool


class Journal(TypedDict):
    """Drizzle Kit's meta/_journal.json."""

    version: str
    dialect: str
    entries: list[JournalEntry]


def journal_of(value: object) -> Journal:
    """A journal as read from JSON, checked."""
    data: dict[str, object] = {str(k): v for k, v in value.items()} if isinstance(value, dict) else {}
    raw = data.get("entries")
    if not isinstance(raw, list):
        raise Error("drizzle's meta/_journal.json isn't a journal (no entries)")
    entries: list[JournalEntry] = []
    for item in raw:
        if not isinstance(item, dict):
            raise Error(f"drizzle's journal has an entry that isn't one: {item!r}")
        e: dict[str, object] = {str(k): v for k, v in item.items()}
        entries.append(
            {
                "idx": int(str(e["idx"])),
                "version": str(e.get("version", "7")),
                "when": int(str(e.get("when", 0))),
                "tag": str(e["tag"]),
                "breakpoints": bool(e.get("breakpoints", True)),
            }
        )
    return {
        "version": str(data.get("version", "7")),
        "dialect": str(data.get("dialect", "postgresql")),
        "entries": entries,
    }


def slug(name: str) -> str:
    """The migration's name: authz_ first, so its files are easy to tell (and to mark as generated)."""
    s = re.sub(r"[^A-Za-z0-9]+", "_", name).strip("_").lower() or "policy"
    return s if s.startswith("authz_") or s == "authz" else f"authz_{s}"


def generated_patterns(tool: str, folder_rel: str | None, lock_rel: str | None) -> list[str]:
    """The .gitattributes lines that mark what rowstile migrate writes as generated: the lock file and the
    migrations folder, each named from the .gitattributes file's folder (None: outside it, so no line)."""
    # the .gitattributes file's own folder: /*_authz_*, as git takes no pattern starting with ./
    top = "" if folder_rel == "." else folder_rel
    pat = f"{top}/*_authz_*/**" if tool == "prisma" else f"{top}/*_authz_*"
    paths = ([lock_rel] if lock_rel else []) + ([pat] if folder_rel else [])
    return [f"{path} linguist-generated=true" for path in paths]


def mark_generated(root: str, lines: list[str]) -> str | None:
    """Adds the lines to root/.gitattributes (made if missing), so GitHub and GitLab collapse generated
    files in reviews. Returns the path if it changed it."""
    path = os.path.join(root, ".gitattributes")
    try:
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
    except FileNotFoundError:
        text = ""
    missing = [x for x in lines if x not in text.split("\n")]
    if not missing:
        return None
    head = "" if "# rowstile" in text else "# rowstile writes these: reviews show them collapsed\n"
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text + ("\n" if text and not text.endswith("\n") else "") + head + "\n".join(missing) + "\n")
    return path


def stamp(now: float | None = None) -> str:
    return time.strftime("%Y%m%d%H%M%S", time.gmtime(now))


def write(path: str, text: str) -> str:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)
    return path


def write_migration(tool: str, folder: str, name: str, sql: str, now: float | None = None) -> list[str]:
    """Writes the migration for `tool` in `folder`; returns the paths written."""
    if tool not in TOOLS:
        raise Error(f"unknown migration tool '{tool}' (use one of {', '.join(TOOLS)})")
    name = slug(name)
    ts = stamp(now)
    names = os.listdir(folder) if os.path.isdir(folder) else []
    # after every migration already there, even ones written the same second
    existing = [m.group(1) for f in names for m in [re.match(r"^V?(\d{14})", f)] if m]
    if existing and max(existing) >= ts:
        ts = stamp(calendar.timegm(time.strptime(max(existing), "%Y%m%d%H%M%S")) + 1)
    version = (next_version(names, VERSIONS[tool]) if tool in VERSIONS else None) or ts
    if tool == "sql":
        return [write(os.path.join(folder, f"{version}_{name}.sql"), sql)]
    if tool == "flyway":
        # the SQL holds ${ (a dollar quote before a JSON object), which Flyway would read as a placeholder: its
        # script config file, beside the migration, turns that off for this script
        path = os.path.join(folder, f"V{version}__{name}.sql")
        return [write(path, sql), write(path + ".conf", "placeholderReplacement=false\n")]
    if tool == "dbmate":
        return [write(os.path.join(folder, f"{version}_{name}.sql"), f"-- migrate:up\n{sql}\n-- migrate:down\n")]
    if tool == "goose":
        return [
            write(
                os.path.join(folder, f"{version}_{name}.sql"),
                f"-- +goose Up\n-- +goose StatementBegin\n{sql}-- +goose StatementEnd\n",
            )
        ]
    if tool == "prisma":
        return [write(os.path.join(folder, f"{ts}_{name}", "migration.sql"), sql)]
    if tool == "drizzle":
        return drizzle(folder, name, sql, now)
    if tool == "django":
        return django(folder, name, sql)
    return alembic(folder, name, sql, now)


# a migration's version in its file's name, as each tool reads it: goose's from .sql and .go files; Flyway's may
# have parts (V1.2__, V1_2__), compared as numbers
VERSIONS = {
    "sql": r"(\d+)_.*\.sql",
    "goose": r"(\d+)_.*\.(?:sql|go)",
    "dbmate": r"(\d+).*\.sql",
    "flyway": r"V(\d+(?:[._]\d+)*)__.*\.sql",
}


def next_version(names: list[str], pattern: str) -> str | None:
    """The version after the last of the folder's when that one is a number (0005 after 0004, 1.3 after 1.2: its
    last part, as wide), so that the app's next migration, numbered after it, comes after it too: goose, Flyway
    and dbmate --strict refuse one below a migration applied already. None when the last is a time (14 digits or
    more) or there is none: the migration's version is then the time."""
    versions = [m.group(1) for n in names for m in [re.fullmatch(pattern, n)] if m]
    if not versions:
        return None
    last = max(versions, key=lambda v: [int(p) for p in re.findall(r"\d+", v)])
    if len(re.findall(r"\d+", last)[0]) >= 14:
        return None
    return re.sub(r"\d+$", lambda m: f"{int(m.group()) + 1:0{len(m.group())}d}", last)


# --- Drizzle Kit: numbered files, a journal, and a snapshot per migration ------------------------------
def drizzle(folder: str, name: str, sql: str, now: float | None) -> list[str]:
    """drizzle-kit migrate runs the journal's entries in order, splitting each file at its statement
    breakpoints. A snapshot per migration keeps drizzle-kit generate working: ours copies the one before
    (rowstile changes nothing drizzle-kit models), as drizzle-kit generate --custom does."""
    meta = os.path.join(folder, "meta")
    journal_path = os.path.join(meta, "_journal.json")
    journal: Journal = {"version": "7", "dialect": "postgresql", "entries": []}
    if os.path.exists(journal_path):
        with open(journal_path, encoding="utf-8") as fh:
            journal = journal_of(json.load(fh))
    idx = max((e["idx"] for e in journal["entries"]), default=-1) + 1
    tag = f"{idx:04d}_{name}"
    body = "\n--> statement-breakpoint\n".join((f"{c}\n" if c else "") + s + ";" for c, s in split(sql))
    written = [write(os.path.join(folder, f"{tag}.sql"), body + "\n")]
    prev: dict[str, object] | None = None
    if journal["entries"]:
        last = max(journal["entries"], key=lambda e: e["idx"])
        p = os.path.join(meta, f"{last['idx']:04d}_snapshot.json")
        if os.path.exists(p):
            with open(p, encoding="utf-8") as fh:
                got = json.load(fh)
            prev = {str(k): v for k, v in got.items()} if isinstance(got, dict) else None
    snap: dict[str, object] = (
        dict(prev)
        if prev
        else {
            "version": "7",
            "dialect": "postgresql",
            "tables": {},
            "enums": {},
            "schemas": {},
            "sequences": {},
            "roles": {},
            "policies": {},
            "views": {},
            "_meta": {"columns": {}, "schemas": {}, "tables": {}},
        }
    )
    prev_id = str(prev["id"]) if prev else "00000000-0000-0000-0000-000000000000"
    snap["prevId"] = prev_id
    snap["id"] = str(uuid.UUID(hashlib.sha256((prev_id + sql).encode()).hexdigest()[:32]))
    written.append(write(os.path.join(meta, f"{idx:04d}_snapshot.json"), json.dumps(snap, indent=2) + "\n"))
    journal["entries"].append(
        {
            "idx": idx,
            "version": journal["version"],
            "when": int((now if now is not None else time.time()) * 1000),
            "tag": tag,
            "breakpoints": True,
        }
    )
    written.append(write(journal_path, json.dumps(journal, indent=2) + "\n"))
    return written


# --- Alembic: a revision after the current head, with its SQL beside it --------------------------------
REVISION = re.compile(r"^revision\s*(?::\s*str\s*)?=\s*['\"]([^'\"]+)['\"]", re.M)
# its value: a merge's tuple of revisions may go on over lines, as black and Ruff lay out a long one
DOWN = re.compile(r"^down_revision\s*(?::[^=]*)?=\s*(\([^)]*\)|.+)$", re.M)


def alembic_heads(folder: str) -> list[str]:
    revs: set[str] = set()
    downs: set[str] = set()
    for f in os.listdir(folder) if os.path.isdir(folder) else []:
        if not f.endswith(".py"):
            continue
        with open(os.path.join(folder, f), encoding="utf-8") as fh:
            text = fh.read()
        m = REVISION.search(text)
        if not m:
            continue
        revs.add(m.group(1))
        d = DOWN.search(text)
        if d:
            downs.update(re.findall(r"['\"]([^'\"]+)['\"]", d.group(1)))
    return sorted(revs - downs)


def alembic(folder: str, name: str, sql: str, now: float | None) -> list[str]:
    heads = alembic_heads(folder)
    if len(heads) > 1:
        raise Error(f"{folder} has several heads ({', '.join(heads)}): merge them first (alembic merge heads)")
    down = heads[0] if heads else None
    rev = hashlib.sha256(((down or "") + sql).encode()).hexdigest()[:12]
    base = f"{rev}_{name}"
    when = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(now))
    py = f'''"""rowstile: {name.replace("_", " ")}

Revision ID: {rev}
Revises: {down or ""}
Create Date: {when}

Generated by rowstile migrate from the policy: the SQL is in {base}.sql, beside this file. Don't edit
either; change the policy and run rowstile migrate again.
"""
from pathlib import Path

from alembic import op

revision = "{rev}"
down_revision: str | None = {down!r}
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.driver == "asyncpg":
        # asyncpg prepares each statement, and a prepared statement is one command: said here, in a line, rather
        # than by the driver with the whole script in its message
        raise RuntimeError(
            "rowstile: Alembic is connected with asyncpg, which takes one statement at a time, and this revision "
            "is one script. Give Alembic a sync driver (postgresql+psycopg://); the app keeps asyncpg"
        )
    sql = Path(__file__).with_suffix(".sql").read_text(encoding="utf-8")
    # as one script, straight to the driver: the SQL has % signs and colons, which are not parameters
    bind.exec_driver_sql(sql, execution_options={{"no_parameters": True}})


def downgrade() -> None:
    raise NotImplementedError("a rowstile migration isn't undone: change the policy back and write a new one")
'''
    return [write(os.path.join(folder, f"{base}.py"), py), write(os.path.join(folder, f"{base}.sql"), sql)]


# --- Django: a migration after the app's latest, with its SQL beside it ---------------------------------
def _pairs(node: object) -> list[tuple[str, str]]:
    """The pairs of strings written in a migration's list: ("app", "0001_initial")."""
    import ast

    out: list[tuple[str, str]] = []
    for t in ast.walk(node) if isinstance(node, ast.AST) else []:
        if isinstance(t, ast.Tuple) and len(t.elts) == 2:
            a, b = t.elts
            if isinstance(a, ast.Constant) and isinstance(b, ast.Constant) and isinstance(a.value, str):
                out.append((a.value, str(b.value)))
    return out


def django_graph(folder: str) -> tuple[str, list[str], int]:
    """The app's label, its latest migrations (those no other of the folder depends on, nor replaces: one, but for
    a branch to merge) and the highest number among them all. The label is what the folder's migrations name the
    app by in their dependencies, else the app's folder name (Django's label, unless its AppConfig gives another)."""
    import ast

    names: list[str] = []
    deps: list[tuple[str, str, str]] = []  # (the migration, the app it depends on, that app's migration)
    replaced: dict[str, list[tuple[str, str]]] = {}
    for f in sorted(os.listdir(folder)):
        if not f.endswith(".py") or f.startswith("_"):
            continue
        with open(os.path.join(folder, f), encoding="utf-8") as fh:
            tree = ast.parse(fh.read(), f)
        names.append(f[:-3])
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and any(isinstance(x, ast.Name) for x in node.targets):
                target = next(x.id for x in node.targets if isinstance(x, ast.Name))
                if target == "dependencies":
                    deps += [(f[:-3], lbl, name) for lbl, name in _pairs(node.value)]
                elif target == "replaces":
                    replaced[f[:-3]] = _pairs(node.value)
    own = os.path.basename(os.path.dirname(os.path.abspath(folder)))
    labels = [lbl for _, lbl, name in deps if name in names]
    label = own if own in labels or not labels else max(set(labels), key=labels.count)
    # a squashed migration stands for those it replaces: what depends on one of them depends on it
    stands = {name: squash for squash, pairs in replaced.items() for lbl, name in pairs if lbl == label}
    needed = {stands.get(name, name) for src, lbl, name in deps if lbl == label and src not in stands}
    latest = sorted(n for n in names if n not in needed and n not in stands)
    numbers = [int(m.group(1)) for n in names for m in [re.match(r"(\d+)_", n)] if m]
    return label, latest, max(numbers, default=0)


def django(folder: str, name: str, sql: str) -> list[str]:
    """A migration the app's own makemigrations would number next, depending on the latest: RunSQL with the SQL
    beside it, read when it runs. Undoing it is refused, in a line: rowstile's migrations go forward only."""
    if not os.path.isfile(os.path.join(folder, "__init__.py")):
        raise Error(
            f"{folder} is no Django app's migrations folder (it has no __init__.py): name the app's, "
            '[migrations] dir = "<app>/migrations" in rowstile.toml (or --dir)'
        )
    label, latest, number = django_graph(folder)
    if len(latest) > 1:
        raise Error(
            f"{folder} has several latest migrations ({', '.join(latest)}): merge them first "
            "(python manage.py makemigrations --merge)"
        )
    base = f"{number + 1:04d}_{name}"
    depends = f"({json.dumps(label)}, {json.dumps(latest[0])})" if latest else ""
    py = f'''"""rowstile: {name.replace("_", " ")}

Generated by rowstile migrate from the policy: the SQL is in {base}.sql, beside this file. Don't edit either;
change the policy and run rowstile migrate again.
"""

from pathlib import Path

from django.db import migrations

# one script, sent as it is: in a list, so Django doesn't split it, and with no parameters, so its % signs stay
SQL = Path(__file__).with_suffix(".sql").read_text(encoding="utf-8")


def forward_only(apps: object, schema_editor: object) -> None:
    raise RuntimeError("a rowstile migration isn't undone: change the policy back and write a new one")


class Migration(migrations.Migration):
    dependencies = [{depends}]

    operations = [
        migrations.RunSQL([SQL], reverse_sql=migrations.RunSQL.noop),
        # undone, this runs first, and refuses: the database would keep the policy and lose its record of it
        migrations.RunPython(migrations.RunPython.noop, forward_only),
    ]
'''
    return [write(os.path.join(folder, f"{base}.py"), py), write(os.path.join(folder, f"{base}.sql"), sql)]

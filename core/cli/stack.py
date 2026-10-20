"""The app's stack, as `rowstile init` finds it: the web framework, the ORM and the migration tool, from the files
in the project folder (package.json, pyproject.toml, requirements*.txt, prisma/, drizzle.config.*, alembic.ini).
What init does with it: rowstile.toml's [migrations] and [clients], the SDK packages to add, and the one line of
setup to change. Reads files only; changes nothing."""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field

from authzlib.versions import pypi

SKIP = {"node_modules", ".git", ".venv", "venv", ".next", "dist", "build", "__pycache__", ".tox"}


@dataclass
class Stack:
    found: list[str] = field(
        default_factory=list
    )  # what was found, in words: "Next.js", "Prisma (prisma/schema.prisma)"
    tool: str = ""  # the migration tool: prisma, drizzle, alembic, sql, or "" (unknown)
    migrations_dir: str = ""
    clients: dict[str, str] = field(default_factory=dict)  # {"ts": "src/authz.gen.ts"} or {"py": "app/authz_types.py"}
    npm: list[str] = field(default_factory=list)  # @rowstile/* packages to add
    npm_maybe: list[str] = field(default_factory=list)  # ... and those the app may want, named, not added
    pip: str = ""  # the pip requirement to add: rowstile[fastapi]
    pip_there: bool = False  # the project depends on rowstile already: nothing to add
    setup: list[str] = field(default_factory=list)  # the change to make, in lines to print
    setup_file: str = ""  # where to make it, if found


def _read(root: str, name: str) -> str | None:
    try:
        with open(os.path.join(root, name), encoding="utf-8-sig") as fh:  # a byte order mark is skipped
            return fh.read()
    except (OSError, UnicodeDecodeError):
        return None


def _files(root: str, exts: tuple[str, ...], limit: int = 2000) -> list[str]:
    """The project's source files with these extensions (not dependencies or builds), relative to root."""
    out: list[str] = []
    for d, dirs, names in os.walk(root):
        dirs[:] = sorted(x for x in dirs if x not in SKIP and not x.startswith("."))
        for n in sorted(names):
            if n.endswith(exts):
                out.append(os.path.relpath(os.path.join(d, n), root).replace(os.sep, "/"))
                if len(out) >= limit:
                    return out
    return out


def _find(root: str, exts: tuple[str, ...], pattern: str) -> str:
    """The first source file with a line matching pattern."""
    rx = re.compile(pattern)
    for rel in _files(root, exts):
        text = _read(root, rel) or ""
        if rx.search(text):
            return rel
    return ""


def _python_names(root: str) -> set[str]:
    """The Python packages the project depends on: names from pyproject.toml and requirements*.txt, and what
    rowstile's own extras bring (`rowstile[fastapi,asyncpg]` is how the stack pages install FastAPI's part)."""
    text = (_read(root, "pyproject.toml") or "") + "\n"
    try:
        for n in sorted(os.listdir(root)):
            if n.startswith("requirements") and n.endswith(".txt"):
                text += (_read(root, n) or "") + "\n"
    except OSError:
        pass
    extras = {
        x.strip().lower()
        for m in re.finditer(r"(?i)\browstile\s*\[([^\]]*)\]", text)
        for x in m.group(1).split(",")
        if x.strip()
    }
    return (
        {m.group(1).lower().replace("_", "-") for m in re.finditer(r'(?m)^\s*"?([A-Za-z][A-Za-z0-9_.-]*)', text)}
        | {  # each one of a list on one line: "fastapi>=0.110", "sqlalchemy (>=2.0)" (Poetry's), "x @ git+https://..."
            m.group(1).lower().replace("_", "-")
            for m in re.finditer(r'"([A-Za-z][A-Za-z0-9_.-]*)\s*(?:\[[^\]]*\])?\s*(?:[(<>=!~;@][^"]*)?"', text)
        }
        | extras
    )


def _object(value: object) -> dict[str, object]:
    """A JSON object (anything else: empty)."""
    return {str(k): v for k, v in value.items()} if isinstance(value, dict) else {}


def dependencies(package_json: object) -> dict[str, str]:
    """package.json's dependencies and devDependencies: name -> version range."""
    data = _object(package_json)
    return {k: str(v) for section in ("dependencies", "devDependencies") for k, v in _object(data.get(section)).items()}


def detect(root: str = ".") -> Stack:
    s = Stack()
    pkg = _read(root, "package.json")
    js: dict[str, str] = {}
    package: dict[str, object] = {}
    if pkg:
        try:
            package = _object(json.loads(pkg))
            js = dependencies(package)
        except ValueError:
            pass
    py = _python_names(root)
    ts_dir = "src" if os.path.isdir(os.path.join(root, "src")) else "."

    # the migration tool first: it decides where rowstile migrate writes
    # where Prisma's schema is: its config file or package.json say, else the two places Prisma looks
    cfg = _read(root, "prisma.config.ts") or ""
    named = re.search(r"\bschema\s*:\s*[\"']([^\"']+)[\"']", cfg)
    said = [named.group(1)] if named else []
    in_package = _object(package.get("prisma")).get("schema")
    if isinstance(in_package, str):
        said.append(in_package)
    prisma_schema = next(
        (p.removeprefix("./") for p in (*said, "prisma/schema.prisma", "schema.prisma") if _read(root, p) is not None),
        "",
    )
    if "prisma" in js or "@prisma/client" in js or prisma_schema:
        s.found.append(f"Prisma ({prisma_schema})" if prisma_schema else "Prisma")
        s.tool = "prisma"
        m = re.search(r"migrations\s*:\s*\{[^}]*path\s*:\s*[\"']([^\"']+)[\"']", cfg)
        s.migrations_dir = (m.group(1) if m else os.path.dirname(prisma_schema or "prisma/x") + "/migrations").lstrip(
            "./"
        ) or "prisma/migrations"
    elif "drizzle-orm" in js or "drizzle-kit" in js:
        config = next(
            (c for c in ("drizzle.config.ts", "drizzle.config.js", "drizzle.config.mjs") if _read(root, c) is not None),
            "",
        )
        s.found.append(f"Drizzle ({config})" if config else "Drizzle")
        s.tool = "drizzle"
        m = re.search(r"out\s*:\s*[\"']([^\"']+)[\"']", _read(root, config) or "") if config else None
        s.migrations_dir = (m.group(1) if m else "drizzle").lstrip("./") or "drizzle"
    elif _read(root, "alembic.ini") is not None or "alembic" in py:
        ini = _read(root, "alembic.ini") or ""
        m = re.search(r"(?m)^script_location\s*=\s*(\S+)", ini)
        loc = (m.group(1) if m else "alembic").replace("%(here)s/", "").strip("/")
        s.found.append("Alembic")
        s.tool, s.migrations_dir = "alembic", f"{loc}/versions"
    else:
        for d in ("db/migrations", "migrations", "sql/migrations"):
            if os.path.isdir(os.path.join(root, d)) and any(
                f.endswith(".sql") for f in os.listdir(os.path.join(root, d))
            ):
                s.found.append(f"SQL migrations ({d})")
                s.tool, s.migrations_dir = "sql", d
                break

    user_ts = "async () => (await auth())?.user.id"  # the app's own session: next-auth's auth(), or yours
    if js:
        if "next" in js:
            s.found.insert(0, "Next.js")
            s.npm.append("@rowstile/next")
        if s.tool == "prisma":
            s.npm.insert(0, "@rowstile/prisma")
            s.setup_file = _find(root, (".ts", ".tsx", ".js", ".mjs"), r"new PrismaClient\(")
            s.setup = [
                'import { PrismaPg } from "@prisma/adapter-pg";',
                'import { authz, signedIn } from "@rowstile/prisma";',
                # the app's own connection, as the app role: DATABASE_URL is Prisma's, the owner's, for migrations
                "const adapter = signedIn(new PrismaPg({ connectionString: process.env.ROWSTILE_APP_URL }),",
                f"                         {{ user: {user_ts} }});",
                "export const db = new PrismaClient({ adapter }).$extends(authz());",
            ]
        elif s.tool == "drizzle":
            s.npm.insert(0, "@rowstile/drizzle")
            s.setup_file = _find(root, (".ts", ".js", ".mjs"), r"drizzle\(")
            s.setup = [
                'import { withAuthz } from "@rowstile/drizzle";',
                f"export const authz = withAuthz(db, {{ user: {user_ts} }});   // authz.transaction(tx => ...)",
            ]
        elif "postgres" in js:
            s.npm.insert(0, "@rowstile/postgres")
            s.setup = [
                'import { authz } from "@rowstile/postgres";',
                f"export const db = authz(sql, {{ user: {user_ts} }});",
            ]
        elif "pg" in js:
            s.npm.insert(0, "@rowstile/pg")
            s.setup = [
                'import { authz } from "@rowstile/pg";',
                f"export const db = authz(pool, {{ user: {user_ts} }});",
            ]
        if "react" in js and "@rowstile/react" not in js:
            s.npm_maybe.append("@rowstile/react")
        if "vitest" in js and "@rowstile/vitest" not in js:
            s.npm_maybe.append("@rowstile/vitest")
        if s.npm:
            s.clients["ts"] = f"{ts_dir}/authz.gen.ts".lstrip("./")
            if "next" in js and s.setup:
                s.setup.insert(0, 'import "@rowstile/next";               // signed-in reads stay out of caches')
    if py and not s.npm:
        extras = [
            x
            for x in ("fastapi", "sqlalchemy", "psycopg", "asyncpg")
            if x in py or (x == "sqlalchemy" and "sqlmodel" in py)
        ]
        if "fastapi" in py:
            s.found.insert(0, "FastAPI")
        if "sqlalchemy" in py or "sqlmodel" in py:
            s.found.insert(1 if "fastapi" in py else 0, "SQLModel" if "sqlmodel" in py else "SQLAlchemy")
        s.pip = "rowstile" + (f"[{','.join(extras)}]" if extras else "")
        s.pip_there = "rowstile" in py
        pkg_dir = next((d for d in ("app", "src", "backend/app") if os.path.isdir(os.path.join(root, d))), ".")
        s.clients["py"] = f"{pkg_dir}/authz_types.py".lstrip("./")
        if "fastapi" in py:
            s.setup_file = _find(root, (".py",), r"=\s*FastAPI\(")
            s.setup = [
                "from rowstile.fastapi import Rowstile",
                "Rowstile(app, engine, user=current_user)   # before adding routes; current_user(request): the",
                "                                            # user's id from its session or token, None for nobody",
            ]
        elif "sqlalchemy" in py or "sqlmodel" in py:
            s.setup = [
                "import rowstile.sqlalchemy",
                "rowstile.sqlalchemy.install(engine)   # with rowstile.acting_as(user_id): ...",
            ]
        if s.tool == "alembic":
            s.setup += [
                "# alembic env.py: context.configure(..., include_name=include_name, include_object=include_object)",
                "from rowstile.alembic import include_name, include_object",
            ]
    return s


def config_lines(s: Stack) -> list[str]:
    """rowstile.toml's [clients] and [migrations] for the stack."""
    out: list[str] = []
    if s.clients:
        out += ["[clients]                    # written on each change by rowstile dev"] + [
            f'{lang} = "{path}"' for lang, path in s.clients.items()
        ]
    if s.tool:
        out += [
            "[migrations]                 # rowstile migrate writes the policy's changes for this tool",
            f'tool = "{s.tool}"',
            f'dir  = "{s.migrations_dir}"',
        ]
    return out


def pip_requirement(name: str, version: str) -> str:
    """The requirement init tells a Python app to add: the bare name for a release; for an alpha, a beta, a candidate
    or a build of main, at least this version in PyPI's spelling (0.1.0-beta.1 is 0.1.0b1), which also lets pip and
    uv take a pre-release, as `^0.1.0-beta.1` does for npm."""
    published = pypi(version)
    return name if published is None or published == version else f"{name}>={published}"


# why init adds each package (or names it): what it says, so that nothing lands in package.json unexplained
NPM_WHY = {
    "@rowstile/prisma": "signs each transaction in, through Prisma's adapter",
    "@rowstile/drizzle": "signs each transaction in",
    "@rowstile/postgres": "signs each transaction in",
    "@rowstile/pg": "signs each transaction in",
    "@rowstile/next": "keeps signed-in reads out of Next.js's caches",
    "@rowstile/react": "hooks for a sharing dialog",
    "@rowstile/vitest": "test matchers for refusals",
    "rowstile": "the command, a dev dependency",
}


def add_npm(root: str, names: list[str], version: str) -> list[str]:
    """Adds the packages to package.json's dependencies (and the command to devDependencies), keeping its layout;
    returns what it added."""
    path = os.path.join(root, "package.json")
    text = _read(root, "package.json")
    if text is None:
        return []
    data = _object(json.loads(text))
    indent = re.search(r'\n([ \t]+)"', text)
    added: list[str] = []
    for section, pkgs in (("dependencies", names), ("devDependencies", ["rowstile"])):
        have = dependencies(data)
        for n in pkgs:
            if n not in have:
                deps = _object(data.get(section))
                deps[n] = f"^{version}"
                data[section] = deps
                added.append(n)
    if added:
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(json.dumps(data, indent=indent.group(1) if indent else 2, ensure_ascii=False) + "\n")
    return added

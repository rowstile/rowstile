"""public_surface.py: an example app uses only rowstile's public surface. Each app's check_public_surface.py runs it
on the app's folder (exit 1 and a list of places otherwise):

    python3 examples/filemanager/check_public_surface.py
    python3 examples/messenger/check_public_surface.py

Public: the rowstile command, and the authz.* functions the reference documents (docs/reference/). Not public:
the schemas authz_gen and authz_int; rowstile's tables (authz.shares, authz.audit, ...), which only its functions
read or write; a search_path naming a schema of rowstile's; and setting authz.user_id, authz.principal_type,
authz.scopes, authz.acting_user or authz.session, which only authz.act_as() and the logins do (the generated
client calls them).

Every text file is read, whatever its name, comments too (a name in a comment is cheap to reword), and names
are matched as Postgres reads them: in any case, quoted or not, with spaces around the dot. What rowstile
migrate writes is rowstile's own SQL, not the app's: the files each app's .gitattributes marks as generated.
"""

import fnmatch
import re
from pathlib import Path

REFERENCE = Path(__file__).resolve().parent.parent / "docs" / "reference"
# what rowstile migrate writes, as the apps' .gitattributes name it
GENERATED = ("db/migrations/*_authz_*", "db/policy.lock")
# what the app doesn't write: its packages, builds and caches
SKIP = {".git", "node_modules", ".venv", "dist", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache"}
# a word: what may come before or after a name for it to be the whole name
WORD = r"[\w$]"
PRIVATE = re.compile(rf"(?<!{WORD})authz_(gen|int)(?!{WORD})", re.I)
# authz.name, "authz"."name", authz . name; group 2: called
NAME = re.compile(rf'(?<!{WORD})"?authz"?\s*\.\s*"?([a-z_]{WORD}*)"?(\s*\()?', re.I)
# rowstile's own tables (some share a name with a function: called, it is the function)
TABLES = (
    "shares",
    "audit",
    "changes",
    "roles",
    "role_permissions",
    "api_keys",
    "settings",
    "requests",
    "reviews",
    "review_items",
    "masked_tables",
    "policy_versions",
)
# the settings that say who is signed in: named in prose, never set by the app
SETTINGS = ("user_id", "principal_type", "scopes", "acting_user")
# SET [LOCAL] authz.x, set_config('authz.x', ...), -c authz.x=... in a connection's options
SETS = re.compile(rf"(?:(?<!{WORD})(?:re)?set\s+(?:local\s+|session\s+)?|set_config\s*\(\s*'|-c\s*)\"?authz\.", re.I)
# SET search_path TO authz, set_config('search_path', 'app, authz', ...), options=-csearch_path%3Dauthz
SEARCH_PATH = re.compile(
    rf'search_path\b[^;\n]*?(?:(?<!{WORD})|(?<=%3d))"?authz(?:_gen|_int)?"?(?!{WORD})(?!"?\s*\.)', re.I
)


def documented() -> frozenset[str]:
    """The authz.* functions the reference documents: authz.name( on any of its pages."""
    names: set[str] = set()
    for page in sorted(REFERENCE.glob("*.md")):
        names.update(n.lower() for n in re.findall(r"\bauthz\.([a-z_][a-z0-9_]*)\(", page.read_text(encoding="utf-8")))
    return frozenset(names)


def generated(rel: str) -> bool:
    """Whether a file (its path from the app's folder) is one rowstile migrate writes: each part of its path
    matches the pattern's."""
    parts = rel.split("/")
    for pattern in GENERATED:
        want = pattern.split("/")
        if len(want) == len(parts) and all(fnmatch.fnmatchcase(p, w) for p, w in zip(parts, want, strict=True)):
            return True
    return False


def texts(root: Path) -> list[tuple[str, str]]:
    """Every text file in the app's folder but what rowstile writes and what isn't the app's: (its path from the
    folder, its text). A file that isn't UTF-8 text (an image) has no names to read."""
    found: list[tuple[str, str]] = []
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root).as_posix()
        if not path.is_file() or SKIP & set(rel.split("/")) or generated(rel):
            continue
        data = path.read_bytes()
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if "\0" not in text:
            found.append((rel, text))
    return found


def places(text: str, public: frozenset[str]) -> list[tuple[int, str]]:
    """Where a file's text goes past the public surface (each place's offset in it), and how."""
    found: list[tuple[int, str]] = []
    for m in PRIVATE.finditer(text):
        found.append((m.start(), "uses rowstile's private schemas"))
    for m in SEARCH_PATH.finditer(text):
        found.append((m.start(), "puts a schema of rowstile's in the search_path"))
    for m in SETS.finditer(text):
        found.append((m.start(), "sets a setting of rowstile's (only authz.act_as() and the logins do)"))
    for m in NAME.finditer(text):
        name, called = m.group(1).lower(), m.group(2) is not None
        if name in TABLES and not called:
            found.append((m.start(), f"reads or writes authz.{name} directly (call an authz.* function instead)"))
        elif name == "session":
            found.append((m.start(), "names the setting rowstile signs sessions with"))
        elif text[m.start() - 1 : m.start()] == ".":
            continue  # an attribute (tx.authz.expect: the generated client), not a schema's name
        elif name not in public and (called or name not in SETTINGS):
            found.append(
                (
                    m.start(),
                    f"authz.{name} is not public (docs/reference/ documents no function or setting by that name)",
                )
            )
    return found


def check(root: Path) -> tuple[int, list[str]]:
    """The files checked, and each place that goes past the public surface, by file and line."""
    public = documented()
    files = texts(root)
    problems: list[tuple[str, int, str]] = []
    for rel, text in files:
        lines = text.split("\n")
        for at, what in places(text, public):
            n = text.count("\n", 0, at)
            problems.append((rel, n + 1, f"{rel}:{n + 1}: {what}: {lines[n].strip()}"))
    return len(files), [p[2] for p in sorted(problems, key=lambda p: p[:2])]


def main(root: Path) -> int:
    n, problems = check(root)
    for p in problems:
        print(p)
    print(f"public surface: {n} files checked, {len(problems)} problems")
    return 1 if problems else 0

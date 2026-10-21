"""check_public_surface.py: the file manager uses only rowstile's public surface.

    python3 filemanager/check_public_surface.py      # exit 1 and a list of places otherwise

Public: the authz.* functions (called: `authz.name(`), the settings authz.user_id, authz.principal_type,
authz.scopes and authz.acting_user, and the rowstile command. Not public: the schemas authz_gen and authz_int, and
the authz tables (shares, audit, changes, ...), which only rowstile's functions may read or write.
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
FILES = [
    p
    for p in ROOT.rglob("*")
    if p.suffix in (".py", ".sql", ".ts", ".tsx", ".authz")
    and not {"node_modules", ".venv", "dist"} & set(p.parts)
    and p.name != Path(__file__).name
    # the migrations rowstile migrate writes are rowstile's own SQL, not the app's (those written before the
    # rename say rowfence: they go when the app's rowstile migrations are made again as one)
    and not p.read_text(encoding="utf-8").startswith(("-- rowstile ", "-- rowfence "))
]
PRIVATE = re.compile(r"\bauthz_(gen|int)\b")
# rowstile's own tables; its functions (named in comments too) are the public API
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
TABLE = re.compile(r"\bauthz\.(" + "|".join(TABLES) + r")\b(?!\s*\()")
# the signature of a session: only authz.act_as() and the logins write it
SIGNED = re.compile(r"\bauthz\.session\b(?!_)")


def main() -> int:
    problems: list[str] = []
    for path in FILES:
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            code = line.split("--")[0] if path.suffix in (".sql", ".authz") else line
            if PRIVATE.search(code):
                problems.append(f"{path.relative_to(ROOT)}:{n}: uses rowstile's private schemas: {line.strip()}")
            for m in TABLE.finditer(code):
                problems.append(
                    f"{path.relative_to(ROOT)}:{n}: reads or writes authz.{m.group(1)} directly "
                    f"(call an authz.* function instead): {line.strip()}"
                )
            if SIGNED.search(code):
                problems.append(
                    f"{path.relative_to(ROOT)}:{n}: writes the setting rowstile signs sessions with: {line.strip()}"
                )
    for p in problems:
        print(p)
    print(f"public surface: {len(FILES)} files checked, {len(problems)} problems")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())

"""rowstile init: a first policy drafted from the database's catalog, a test file, rowstile.toml, and a note for
the coding agents that work in the app (AGENTS.md)."""

from __future__ import annotations

import os
import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from rowstile_cli import Config

CONFIG = "rowstile.toml"
AGENTS = "AGENTS.md"  # the file coding agents read in a repository
BEGIN, END = "<!-- rowstile:begin -->", "<!-- rowstile:end -->"


def write_new(path: str, text: str, written: list[str]) -> None:
    if os.path.exists(path):
        print(f"kept {path} (it is there already)")
        return
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)
    written.append(path)


def agents_note(policy_path: str, tests: str, role: str) -> str:
    """What a coding agent working in the app needs to know of rowstile (llms.txt's list, with this app's paths),
    between two markers."""
    return f"""{BEGIN}
## Access rules (rowstile)

Who may see or change a row is decided in Postgres, by row-level security that the `rowstile` command makes
from a policy file. For coding agents working in this repository:

- The policy is `{policy_path}`, its tests `{tests}`; `{CONFIG}` names both.
  Everything that grants access is written in the policy: no permission checks in app code, no
  `CREATE POLICY` by hand.
- After editing it: `rowstile check` (the first mistake, with its line and a code such as `[AZ201]`), then
  `rowstile push` (the development database only) and `rowstile test`. `rowstile dev` does all three on each
  save. `rowstile help AZ201` explains a code and shows the mistake fixed.
- Production takes migrations: `rowstile migrate` writes the next one. Never `rowstile push` there.
- The app connects as `{role}`, never as the tables' owner, and each transaction signs in first:
  `SELECT authz.act_as('user', '42')` (the SDKs do it). Then plain queries are filtered, a refused insert
  raises SQLSTATE 42501 with the reason, and an UPDATE or DELETE the rules don't allow changes no row.
- Why someone holds a permission or not: `rowstile why --as user:42 TYPE ID PERMISSION`.
- `rowstile mcp` is an MCP server with the command's tools. The language and the rest:
  https://rowstile.dev/llms.txt
{END}
"""


def write_agents_note(note: str, folder: str = ".") -> str | None:
    """Puts the note in the app's AGENTS.md: the file is written if there is none, the note is added at the end
    of one that doesn't have it, and one that has it (the markers) is left as it is. Returns what was done
    ("wrote", "added"), or None."""
    path = os.path.join(folder, AGENTS)
    if not os.path.exists(path):
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(note)
        return "wrote"
    with open(path, encoding="utf-8", newline="") as fh:
        text = fh.read()
    if BEGIN in text:
        return None
    eol = "\r\n" if "\r\n" in text else "\n"
    gap = "" if not text.strip() else eol if text.endswith(("\n", "\r")) else eol * 2
    with open(path, "w", encoding="utf-8", newline="") as fh:
        fh.write(text + gap + note.replace("\n", eol))
    return "added"


def init(policy: str, opts: dict[str, str], cfg: Config, where: str = "", given: str | None = None) -> None:
    """Writes the drafted policy, a first test file, rowstile.toml and the note for coding agents, keeping any
    that exist. where: the .env file that named the database, if one did; given: --db, if it named it."""
    out = opts.get("--out", "db")
    written: list[str] = []
    policy_path = os.path.join(out, "policy.authz")
    write_new(policy_path, policy, written)
    m = re.search(r"^app role (\S+)", policy, re.M)
    role = m.group(1) if m else "app_user"  # a draft always has one
    first = re.search(r"^type (?!user\b)(\w+) = (\S+)", policy, re.M)
    example = first.group(1) if first else "user"
    write_new(
        os.path.join(out, "tests", "first.authz"),
        f"""-- Named tests: each brings its own data and rolls it back. rowstile test (or rowstile dev) runs them.
-- A test's lines:
--   given name = {{INSERT ... RETURNING id}}      rows it needs; $name is what RETURNING gave
--   user $name can|cannot PERM TYPE $id           a permission, as someone
--   as user $name allowed|refused {{SQL}}           a statement as the app role ({role}), signed in as someone
--   as user $name sees N {{SELECT ...}}             how many rows they see

test "nobody signed in sees a {example}"
  anyone cannot view {example} 1
""",
        written,
    )
    import stack

    found = stack.detect(os.getcwd())
    if found.found:
        via = (" from DATABASE_URL" + (f" in {where}" if where else "")) if os.environ.get("DATABASE_URL") else ""
        print(f"found   {', '.join(found.found)}, Postgres{via}")
    if cfg.path is None:
        database, why = "env:DATABASE_URL", "a DSN or URL, or env:NAME for an environment variable holding one"
        app_url = os.environ.get("DATABASE_URL")
        if given and app_url and app_url != given:
            # DATABASE_URL is another connection than the one --db named (often the app's, as its role): rowstile
            # applies as the tables' owner, so it reads the owner's from a name of its own
            database, why = "env:ROWSTILE_DATABASE_URL", "the tables' owner's connection: DATABASE_URL is another"
            print(
                "note    DATABASE_URL is another connection than --db's (the app's, as its role?): rowstile.toml reads\n"
                "        the tables' owner's from ROWSTILE_DATABASE_URL. Set it, in the environment or .env.local, to what\n"
                "        --db named"
            )
        extra = stack.config_lines(found) or [
            "# [clients]                    # generated on each change by rowstile dev",
            '# py = "app/authz_client.py"',
            '# ts = "src/authz.ts"',
        ]
        write_new(
            CONFIG,
            f'''policy   = "{policy_path.replace(os.sep, "/")}"
tests    = ["{os.path.join(out, "tests").replace(os.sep, "/")}/*.authz"]
database = "{database}"     # {why}
'''
            + "\n".join(extra)
            + "\n",
            written,
        )
    else:
        print(f"using {os.path.relpath(cfg.path)} (it is there already)")
    for path in written:
        print(f"wrote {path}")
    tests = os.path.join(out, "tests").replace(os.sep, "/") + "/*.authz"
    noted = write_agents_note(agents_note(policy_path.replace(os.sep, "/"), tests, role))
    if noted == "wrote":
        print(f"wrote {AGENTS} (for coding agents: where the policy is, and the loop)")
    elif noted == "added":
        print(f"added   rowstile's section to {AGENTS} (for coding agents: where the policy is, and the loop)")
    else:
        print(f"kept {AGENTS} (it has rowstile's section already)")
    if found.tool and CONFIG in written:
        import migrations

        lock = os.path.join(out, "policy.lock").replace(os.sep, "/")
        marked = migrations.mark_generated(
            os.getcwd(), migrations.generated_patterns(found.tool, found.migrations_dir, lock)
        )
        if marked:
            print("wrote   .gitattributes (reviews show the generated files collapsed)")
    from authzlib import __version__

    if found.npm:
        added = stack.add_npm(os.getcwd(), found.npm, __version__)
        if added:
            print("added   to package.json (then: npm install):")
            for name in added:
                print(f"          {name}: {stack.NPM_WHY[name]}")
    if found.npm_maybe:
        print("maybe   " + ", ".join(f"{n} ({stack.NPM_WHY[n]})" for n in found.npm_maybe) + ": not added")
    if found.pip and not found.pip_there:
        req = stack.pip_requirement(found.pip, __version__)
        print(f"add     {req} to your Python dependencies (pip install '{req}', or uv add '{req}')")
    setup = ""
    if found.setup:
        where = f"in {found.setup_file}" if found.setup_file else "where the app makes its database client"
        lines = "\n".join("       " + line for line in found.setup)
        setup = f"""
  2. Sign every transaction in, {where}:
{lines}
     The role your app connects as ({role}) must not bypass row-level security:
       CREATE ROLE {role} LOGIN PASSWORD '...' NOSUPERUSER NOBYPASSRLS;
     The app connects as {role}, with a URL of its own: never the one this command uses, the
     tables' owner's, which row-level security doesn't apply to."""
    else:
        setup = f"""
  2. The role your app connects as ({role}) must not bypass row-level security:
       CREATE ROLE {role} LOGIN PASSWORD '...' NOSUPERUSER NOBYPASSRLS;
     It says who is signed in first in each transaction: SELECT authz.act_as('user', '42')
     (the generated clients' sign_in does it)."""
    print(f"""
Next:
  1. Read {policy_path}: every '-- decide:' is a choice only you can make.{setup}
  3. rowstile dev      applies the policy on each save, runs the tests, writes the clients
                       (DATABASE_URL, in the environment or in .env, or database in {CONFIG}: a development database)""")

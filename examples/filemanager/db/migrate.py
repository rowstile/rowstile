"""migrate.py: bring the database up to date, as its owner.

    python db/migrate.py                 # the migrations not applied yet, in order
    python db/migrate.py --client        # ...and rewrite backend/app/authz_client.py from db/policy.authz

Environment: FM_ADMIN_URL (the owner of the app's tables, or a superuser), FM_APP_PASSWORD (the
app role's password; the role is created if missing). The migrations run in one transaction.

The policy ships as migrations too: after a change to db/policy.authz, `rowstile migrate`
writes the next one into db/migrations (and db/policy.lock). The app uses only rowstile's public
surface: the rowstile command writes its migrations and its client, and the app calls
authz.* functions.
"""

import os
import subprocess
import sys
from pathlib import Path

import psycopg
from psycopg import sql

HERE = Path(__file__).resolve().parent
CLIENT = HERE.parent / "backend" / "app" / "authz_client.py"


def rowstile(*args: str) -> str:
    """Runs the rowstile command; its output, or exits with its status. In this repository the command is its own
    (the nearest folder above with core/cli), so the client is of the same commit; elsewhere, the one installed."""
    repo = next((p for p in HERE.parents if (p / "core" / "cli").is_dir()), None)
    command = [sys.executable, str(repo / "core" / "cli" / "rowstile_cli.py")] if repo else ["rowstile"]
    p = subprocess.run([*command, *args], capture_output=True, text=True)
    sys.stderr.write(p.stderr)
    if p.returncode:
        sys.exit(p.returncode)
    return p.stdout


def main() -> None:
    url = os.environ["FM_ADMIN_URL"]
    password = os.environ["FM_APP_PASSWORD"]
    with psycopg.connect(url, autocommit=False) as conn, conn.transaction():
        cur = conn.cursor()
        # the app role logs in; row-level security applies to it
        cur.execute("SELECT 1 FROM pg_roles WHERE rolname = 'fm_app'")
        if cur.fetchone() is None:
            cur.execute("CREATE ROLE fm_app LOGIN NOSUPERUSER NOBYPASSRLS")
        cur.execute(sql.SQL("ALTER ROLE fm_app PASSWORD {}").format(sql.Literal(password)))
        cur.execute(
            "CREATE TABLE IF NOT EXISTS public.fm_migrations (name text PRIMARY KEY, at timestamptz DEFAULT now())"
        )
        cur.execute("SELECT name FROM public.fm_migrations")
        done = {r[0] for r in cur.fetchall()}
        for path in sorted((HERE / "migrations").glob("*.sql")):
            if path.name in done:
                continue
            print(f"migration {path.name}")
            cur.execute(path.read_bytes())  # a file's SQL, not a literal of this code
            cur.execute("INSERT INTO public.fm_migrations (name) VALUES (%s)", (path.name,))
    if "--client" in sys.argv:
        CLIENT.write_text(rowstile("client", "py", str(HERE / "policy.authz")), encoding="utf-8", newline="\n")
        print(f"wrote {CLIENT.relative_to(HERE.parent)}")


if __name__ == "__main__":
    main()

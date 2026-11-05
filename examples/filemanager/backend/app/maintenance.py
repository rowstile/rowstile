"""Maintenance jobs, run on a schedule (cron, a Kubernetes CronJob) as the database owner.

    FM_ADMIN_URL=postgresql://... python -m app.maintenance            # every job
    python -m app.maintenance --uploads-older-than "1 day"

- Uploads that never finished (a row made, the bytes never arrived or never confirmed): their objects
  and rows are removed. They span every user, so this runs as the owner, not as the app role.
- What is left in the uploads' place in storage after a day, and sessions that ended.
- rowstile's retention: the change feed, with authz.trim_changes(). The audit trail is kept; trim it with
  authz.trim_audit(...) once you have decided how long to keep it.
"""

import argparse
import os
from datetime import timedelta

import psycopg
from psycopg.rows import TupleRow

from .config import load
from .storage import Storage


def abandoned_uploads(conn: psycopg.Connection[TupleRow], storage: Storage, older_than: str) -> int:
    """New files and new versions whose bytes never arrived (or were never confirmed). A file never confirmed goes
    with every version it has: one left would hold the file's row, hidden for good, with its name taken."""
    rows = conn.execute(
        "SELECT v.id, v.object_key, v.file_id, f.ready AS file_ready FROM fm.file_versions v "
        "JOIN fm.files f ON f.id = v.file_id WHERE NOT v.ready AND v.created_at < now() - %s::interval "
        "OR NOT f.ready AND f.created_at < now() - %s::interval",
        (older_than, older_than),
    ).fetchall()
    files: set[int] = set()
    for version_id, key, file_id, file_ready in rows:
        storage.discard(str(key))  # the objects first: a row left behind is retried next time
        conn.execute("DELETE FROM fm.file_versions WHERE id = %s", (version_id,))
        if not file_ready:  # a new file that never arrived goes too, once its versions have
            files.add(file_id)
    for file_id in sorted(files):
        conn.execute("DELETE FROM fm.files WHERE id = %s AND NOT ready", (file_id,))
    return len(rows)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--uploads-older-than", default="1 day")
    args = ap.parse_args()
    storage = Storage(load())
    with psycopg.connect(os.environ["FM_ADMIN_URL"], autocommit=True) as conn:
        n = abandoned_uploads(conn, storage, args.uploads_older_than)
        print(f"removed {n} unfinished uploads")
        print(f"removed {storage.sweep_uploads(timedelta(days=1))} leftover uploaded objects")
        ended = conn.execute("DELETE FROM fm.sessions WHERE expires_at < now()").rowcount
        print(f"removed {ended} sessions that ended")
        row = conn.execute("SELECT authz.trim_changes()").fetchone()
        trimmed = row[0] if row else 0
        print(f"trimmed {trimmed} change feed entries")


if __name__ == "__main__":
    main()

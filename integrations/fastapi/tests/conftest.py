import os
from collections.abc import Iterator

import psycopg
import pytest
from rowstile.testing import WorkerDatabase, database_per_worker

OWNER = os.environ.get("ROWSTILE_OWNER_URL", "")


def libpq(url: str) -> str:
    """A SQLAlchemy URL as libpq takes it."""
    return url.replace("postgresql+psycopg://", "postgresql://").replace("postgresql+asyncpg://", "postgresql://")


@pytest.fixture(scope="session")
def anyio_backend() -> tuple[str, dict[str, object]]:
    return "asyncio", {}


@pytest.fixture(scope="session")
def worker_database() -> WorkerDatabase:
    """This worker's own copy of the migrated test database (check 12): tests that write don't meet each other."""
    return database_per_worker(os.environ["ROWSTILE_TESTS_URL"], app_url=os.environ["ROWSTILE_APP_URL"])


@pytest.fixture(scope="session", autouse=True)
def data() -> Iterator[None]:
    """The same few rows for every test: ann (1) owns project 1 (cy is a member, service 1 reads it) and the
    public project 3; bo (2) owns project 2. Ann's folder 1 has folder 2 inside it."""
    if not OWNER:
        pytest.skip("ROWSTILE_OWNER_URL is not set (test.sh sets it)")
    with psycopg.connect(libpq(OWNER), autocommit=True) as conn:
        conn.execute(
            "TRUNCATE app.folders, app.inbox, app.notes, app.members, app.project_services, app.projects, "
            "app.services, app.users CASCADE"
        )
        conn.execute("INSERT INTO app.users VALUES (1, 'ann'), (2, 'bo'), (3, 'cy')")
        conn.execute("INSERT INTO app.services VALUES (1, 'digest')")
        conn.execute(
            "INSERT INTO app.projects VALUES (1, 1, 'Plans', false), (2, 2, 'Bo''s', false), (3, 1, 'Open', true)"
        )
        conn.execute("INSERT INTO app.members VALUES (1, 3)")
        conn.execute("INSERT INTO app.project_services VALUES (1, 1)")
        conn.execute(
            "INSERT INTO app.notes (id, project_id, author_id, body) VALUES "
            "(1, 1, 1, 'plan'), (2, 2, 2, 'mine'), (3, 3, 1, 'hello'), (4, 1, 3, 'idea')"
        )
        conn.execute("SELECT setval(pg_get_serial_sequence('app.notes', 'id'), 100)")
        conn.execute("INSERT INTO app.folders VALUES (1, NULL, 1, 'top'), (2, 1, 1, 'inside')")
    yield

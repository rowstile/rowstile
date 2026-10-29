import os
from collections.abc import Iterator

import psycopg
import pytest
from pytest_django.plugin import DjangoDbBlocker
from rowstile.django.testing import WorkerDatabase, database_per_worker


@pytest.fixture(scope="session")
def django_db_setup() -> WorkerDatabase:
    """The test database has the policy (check 12): this worker's own copy of the migrated one, which Django's
    connection then uses, as the app role. Tests that write don't meet each other."""
    return database_per_worker(os.environ["ROWSTILE_TESTS_URL"])


@pytest.fixture(scope="session", autouse=True)
def data(django_db_setup: WorkerDatabase) -> Iterator[str]:
    """The same few rows for every test, written by the owner: ann (1) owns project 1 (cy is a member, service 1
    reads it) and the public project 3; bo (2) owns project 2. Ann's folder 1 has folder 2 inside it. Gives the
    owner's URL to this worker's database."""
    with psycopg.connect(django_db_setup.url, autocommit=True) as conn:
        conn.execute("TRUNCATE folders, inbox, notes, members, project_services, projects, services, users CASCADE")
        conn.execute("INSERT INTO users VALUES (1, 'ann'), (2, 'bo'), (3, 'cy')")
        conn.execute("INSERT INTO services VALUES (1, 'digest')")
        conn.execute(
            "INSERT INTO projects (id, owner_id, name, public) VALUES "
            "(1, 1, 'Plans', false), (2, 2, 'Bo''s', false), (3, 1, 'Open', true)"
        )
        conn.execute("INSERT INTO members (project_id, user_id) VALUES (1, 3)")
        conn.execute("INSERT INTO project_services (project_id, service_id) VALUES (1, 1)")
        conn.execute(
            "INSERT INTO notes (id, project_id, author_id, body) VALUES "
            "(1, 1, 1, 'plan'), (2, 2, 2, 'mine'), (3, 3, 1, 'hello'), (4, 1, 3, 'idea')"
        )
        conn.execute("SELECT setval(pg_get_serial_sequence('notes', 'id'), 100)")
        conn.execute(
            "INSERT INTO folders (id, parent_id, owner_id, name) VALUES (1, NULL, 1, 'top'), (2, 1, 1, 'inside')"
        )
    yield django_db_setup.url


@pytest.fixture(autouse=True)
def database(django_db_blocker: DjangoDbBlocker) -> Iterator[None]:
    """Every check may reach the database, and commits as the app does (a check that wants pytest-django's
    transaction around it, rolled back after, asks for `db`)."""
    with django_db_blocker.unblock():
        yield

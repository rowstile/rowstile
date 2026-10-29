"""pytest-django and rowstile: the test database has the policy, a copy of the migrated one for each pytest-xdist
worker (rowstile.testing.database_per_worker), which Django's connection then uses. In conftest.py:

    @pytest.fixture(scope="session")
    def django_db_setup() -> WorkerDatabase:
        return database_per_worker(os.environ["ROWSTILE_TESTS_URL"])

ROWSTILE_TESTS_URL: the tables' owner's URL to the test database, migrated (manage.py migrate, as the owner) before
the tests run. Django connects to the copy as settings say (the app role), so the tests see what the app sees.
"""

from __future__ import annotations

import urllib.parse

from django.db import DEFAULT_DB_ALIAS, connections

from ..testing import WorkerDatabase
from ..testing import database_per_worker as _copy


def database_per_worker(url: str, using: str = DEFAULT_DB_ALIAS, fresh: bool = True) -> WorkerDatabase:
    """This worker's copy of the migrated test database at `url` (made again unless fresh=False), and Django's
    `using` connection pointed at it, with the user and password settings give. Returns the copy (its URL is the
    owner's, for test data)."""
    copy = _copy(url, fresh=fresh)
    connection = connections[using]
    connection.close()
    connection.settings_dict["NAME"] = urllib.parse.unquote(urllib.parse.urlsplit(copy.url).path.lstrip("/"))
    return copy


__all__ = ["WorkerDatabase", "database_per_worker"]

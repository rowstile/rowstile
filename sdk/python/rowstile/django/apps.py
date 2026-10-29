"""The Django app "rowstile.django": once it is in INSTALLED_APPS, every transaction on Django's Postgres
connections signs in as whoever the code acts for (rowstile.django's execute wrapper, on each new connection)."""

from __future__ import annotations

from django.apps import AppConfig
from django.db.backends.signals import connection_created


class RowstileConfig(AppConfig):
    name = "rowstile.django"
    label = "rowstile"
    verbose_name = "rowstile"

    def ready(self) -> None:
        from . import _install

        connection_created.connect(_install, dispatch_uid="rowstile.django")

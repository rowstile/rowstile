"""The conformance app's settings: one database, whose URL says who connects. The app connects as the app role
(row-level security applies to it); manage.py migrate runs with the tables' owner's URL."""

import os
import urllib.parse


def database(url: str) -> dict[str, object]:
    """Django's settings for a postgresql:// URL."""
    u = urllib.parse.urlsplit(url)
    return {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": urllib.parse.unquote(u.path.lstrip("/")),
        "USER": urllib.parse.unquote(u.username or ""),
        "PASSWORD": urllib.parse.unquote(u.password or ""),
        "HOST": u.hostname or "",
        "PORT": str(u.port or ""),
    }


SECRET_KEY = "conformance"  # no secret: the app runs in tests only
DEBUG = os.environ.get("DJANGO_DEBUG") == "1"
ALLOWED_HOSTS = ["*"]
USE_TZ = True
TIME_ZONE = "UTC"
ROOT_URLCONF = "conformance.urls"
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

INSTALLED_APPS = ["rowstile.django", "app"]
MIDDLEWARE = ["rowstile.django.Middleware"]
# who a request is: the app's own sign-in (a real app's reads its session; Django's request.user is the default)
ROWSTILE_USER = "app.auth.session_user"

DATABASES = {"default": database(os.environ.get("DATABASE_URL", "postgresql://conf_app@localhost/conf"))}

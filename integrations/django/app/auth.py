"""Who a request is. A real app reads its session or token here (Django's request.user, the default when
ROWSTILE_USER isn't set). The conformance app has no sign-in: its checks name the user in a header, which a real
app must never believe. So docs/stacks/django.md shows the settings naming session_user, and never this file."""

from django.http import HttpRequest


def session_user(request: HttpRequest) -> str | tuple[str, str] | None:
    """The request's signed-in user (None: nobody), or a service (x-service: a service's own API calls)."""
    service = request.headers.get("x-service")
    if service is not None:
        return ("service", service)
    return request.headers.get("x-user")

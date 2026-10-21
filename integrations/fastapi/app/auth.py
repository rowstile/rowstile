"""Who a request is. A real app reads its session or token here: a cookie, a bearer token, an API key. The
conformance app has no sign-in: its checks name the user in a header, which a real app must never believe. So
docs/stacks/fastapi.md shows main.py importing session_user, and never this file."""

from fastapi import Request


def session_user(request: Request) -> str | None:
    """The request's signed-in user (None: nobody)."""
    return request.headers.get("x-user")

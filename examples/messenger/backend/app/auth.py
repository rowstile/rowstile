"""Accounts and sessions. The backend is trusted to say who is signed in: it checks the password or the
session cookie, then tells the database (authz.user_id). Bots bring their own API keys instead."""

import hashlib
import hmac
import secrets

from fastapi import Cookie, Header, HTTPException
from psycopg.rows import DictRow

from . import db

COOKIE = "ms_session"


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
    return f"scrypt${salt.hex()}${digest.hex()}"


def password_ok(password: str, stored: str) -> bool:
    try:
        _, salt, digest = stored.split("$")
    except ValueError:
        return False
    got = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=2**14, r=8, p=1)
    return hmac.compare_digest(got.hex(), digest)


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def new_session(tx: db.Tx, user_id: object, days: int) -> str:
    token = secrets.token_urlsafe(32)
    tx.run("DELETE FROM ms.sessions WHERE expires_at < now()")  # the ones that ended: nothing else removes them
    tx.run(
        "INSERT INTO ms.sessions VALUES (%s, %s, now() + make_interval(days => %s))", (token_hash(token), user_id, days)
    )
    return token


def user_of(session: str | None) -> DictRow | None:
    if not session:
        return None
    with db.as_user(None) as tx:
        user_id = tx.one("SELECT ms.session_user(%s) AS id", (token_hash(session),))["id"]
    if user_id is None:
        return None
    return profile(user_id)


def profile(user_id: str) -> DictRow | None:
    """A person's profile, read as them (ms.people: a phone number shows to whoever may see it, them included)."""
    with db.as_user(user_id) as tx:
        return tx.row("SELECT id, phone, name, about FROM ms.people WHERE id = %s", (user_id,))


def current_user(ms_session: str | None = Cookie(default=None)) -> DictRow:
    """The signed-in person (FastAPI dependency); 401 without a valid session."""
    user = user_of(ms_session)
    if user is None:
        raise HTTPException(401, "sign in first")
    return user


def bot_key(authorization: str | None = Header(default=None)) -> str:
    """A bot's API key, from `Authorization: Bearer ak_...` (checked by the database when used)."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "send the bot's API key: Authorization: Bearer ak_...")
    return authorization.removeprefix("Bearer ").strip()

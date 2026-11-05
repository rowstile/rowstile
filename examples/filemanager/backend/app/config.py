"""Settings, from the environment."""

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    database_url: str  # as fm_app: row-level security applies
    s3_endpoint: str  # where the backend reaches RustFS
    s3_public_endpoint: str  # where browsers reach it (signed download links point here)
    s3_bucket: str
    s3_access_key: str
    s3_secret_key: str
    s3_region: str
    session_days: int
    cookie_secure: bool
    open_signup: bool  # anyone may create an account (development, demos)
    max_upload_bytes: int
    link_minutes: int  # how long a signed download or upload link works
    web_origins: tuple[str, ...]  # where the web app runs: browsers there may upload straight to RustFS


def flag(name: str, default: str) -> bool:
    """A setting that is true or false: those words, or 1 and 0, in any case. Anything else stops the app at start:
    a spelling must not send a cookie meant for HTTPS alone over plain HTTP."""
    word = os.environ.get(name, default).strip().lower()
    if word not in ("true", "false", "1", "0"):
        raise ValueError(f"{name} is {os.environ.get(name)!r}: say true or false")
    return word in ("true", "1")


def load() -> Settings:
    env = os.environ.get
    endpoint = env("FM_S3_ENDPOINT", "http://localhost:9000")
    return Settings(
        database_url=env("FM_DATABASE_URL", "postgresql://fm_app:fm_app@localhost:5432/filemanager"),
        s3_endpoint=endpoint,
        s3_public_endpoint=env("FM_S3_PUBLIC_ENDPOINT", endpoint),
        s3_bucket=env("FM_S3_BUCKET", "files"),
        s3_access_key=env("FM_S3_ACCESS_KEY", "rustfsadmin"),
        s3_secret_key=env("FM_S3_SECRET_KEY", "rustfsadmin"),
        s3_region=env("FM_S3_REGION", "us-east-1"),
        session_days=int(env("FM_SESSION_DAYS", "14")),
        cookie_secure=flag("FM_COOKIE_SECURE", "false"),
        open_signup=flag("FM_OPEN_SIGNUP", "true"),
        max_upload_bytes=int(env("FM_MAX_UPLOAD_BYTES", str(1 << 30))),
        link_minutes=int(env("FM_LINK_MINUTES", "10")),
        web_origins=tuple(
            o.strip()
            for o in env("FM_WEB_ORIGINS", "http://localhost:8000,http://localhost:5173").split(",")
            if o.strip()
        ),
    )

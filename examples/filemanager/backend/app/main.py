"""The file manager's HTTP API.

Every route that touches folders, files or shares runs in a transaction signed in as the user
(db.as_user), so what it may see and change is decided by row-level security and the authz.*
functions of the policy in db/policy.authz; the backend adds no permission checks of its own.
Something a user may not see answers 404, as if it didn't exist.
"""

from collections.abc import AsyncIterator, Mapping, Sequence
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Literal, LiteralString
from uuid import UUID

import psycopg
from fastapi import Depends, FastAPI, HTTPException, Request, Response, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from psycopg import errors
from psycopg.rows import DictRow
from pydantic import BaseModel, Field

from . import auth, db
from .authz_client import NotFound, Refused, refusal
from .config import load
from .storage import Storage

settings = load()
storage = Storage(settings)
Kind = Literal["folder", "file"]
TABLES: dict[Kind, LiteralString] = {"folder": "fm.folders", "file": "fm.files"}
Answer = dict[str, Any]  # a JSON object the web app reads, as FastAPI types it


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    db.open_pool(settings.database_url)
    # the app must connect as a role row-level security applies to: with the owner's URL here by mistake,
    # every request would see everything
    with db.as_user(None) as tx:
        problems = [str(r["problem"]) for r in tx.authz.connection_check() if r["severity"] == "error"]
    if problems:
        db.close_pool()
        raise RuntimeError("FM_DATABASE_URL can't be used with rowstile: " + "; ".join(problems))
    storage.ensure_bucket()
    yield
    db.close_pool()


app = FastAPI(title="File manager", lifespan=lifespan)


# --- errors: what the database refused, as HTTP ------------------------------------------------
# a refusal: 403 with the database's reason (the rule, and what is missing) in "why"
@app.exception_handler(Refused)
async def refused(_request: Request, e: Refused) -> JSONResponse:
    return JSONResponse({"detail": "you may not do that here", "why": e.why}, 403)


@app.exception_handler(NotFound)
async def not_found(_request: Request, e: NotFound) -> JSONResponse:
    return JSONResponse({"detail": "not found"}, 404)


# a unique or foreign key the database refused, by the constraint's name (db/migrations): the answer
NOT_EMPTY = (
    "the folder isn't empty: empty it first (it may hold things you can't see, which only their owners can remove)"
)
CONSTRAINTS: dict[str, tuple[int, str]] = {
    "users_email_key": (409, "an account with that email exists already"),
    "folders_parent_id_name_key": (409, "something with that name is already there"),
    "files_folder_id_name_key": (409, "something with that name is already there"),
    # what it still holds may be something this person can't see (a folder someone made inside and stopped
    # inheritance on): the database keeps it, and says no more than that it is there
    "folders_parent_id_fkey": (409, NOT_EMPTY),
    "files_folder_id_fkey": (409, NOT_EMPTY),
    "groups_parent_id_fkey": (409, "the group has sub-groups: delete them first"),
    "group_members_user_id_fkey": (404, "no such person"),
}


@app.exception_handler(psycopg.Error)
async def database_error(request: Request, e: psycopg.Error) -> JSONResponse:
    diag = getattr(e, "diag", None)
    message = (diag.message_primary if diag and diag.message_primary else str(e)).split("\n")[0]
    r = refusal(e)
    if r:
        return await refused(request, r)
    known = CONSTRAINTS.get(diag.constraint_name or "") if diag else None
    if known and isinstance(e, (errors.UniqueViolation, errors.ForeignKeyViolation)):
        return JSONResponse({"detail": known[1]}, known[0])
    if isinstance(e, errors.ProgramLimitExceeded):  # the storage quota (db migration 0004)
        return JSONResponse({"detail": message}, 413)
    if isinstance(
        e,
        (
            errors.CheckViolation,
            errors.RaiseException,
            errors.InvalidParameterValue,
            errors.InvalidTextRepresentation,
            errors.InvalidDatetimeFormat,
        ),
    ):
        return JSONResponse({"detail": message}, 400)
    raise e


def found(row: DictRow | None, what: str = "not found") -> DictRow:
    if row is None:
        raise HTTPException(404, what)
    return row


# --- accounts ----------------------------------------------------------------------------------
class SignUp(BaseModel):
    email: str = Field(min_length=3, max_length=200)
    name: str = Field(min_length=1, max_length=200)
    password: str = Field(min_length=8, max_length=200)


class LogIn(BaseModel):
    email: str
    password: str


def set_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        auth.COOKIE,
        token,
        httponly=True,
        samesite="lax",
        secure=settings.cookie_secure,
        max_age=settings.session_days * 86400,
    )


@app.post("/api/signup")
def sign_up(body: SignUp, response: Response) -> DictRow:
    if not settings.open_signup:
        raise HTTPException(403, "accounts are created by an administrator")
    with db.as_user(None) as tx:
        # accounts aren't governed by the policy; the app role creates them only through fm.sign_up
        user = tx.one(
            "SELECT * FROM fm.sign_up(%s, %s, %s)", (body.email.lower(), body.name, auth.hash_password(body.password))
        )
        token = auth.new_session(tx, user["id"], settings.session_days)
    set_cookie(response, token)
    return user


@app.post("/api/login")
def log_in(body: LogIn, response: Response) -> DictRow:
    with db.as_user(None) as tx:
        row = tx.row(
            "SELECT u.id, u.email, u.name, u.is_support, c.password_hash FROM fm.users u "
            "JOIN fm.credentials c ON c.user_id = u.id WHERE u.email = %s",
            (body.email.lower(),),
        )
        if row is None or not auth.password_ok(body.password, row.pop("password_hash")):
            raise HTTPException(401, "wrong email or password")
        token = auth.new_session(tx, row["id"], settings.session_days)
    set_cookie(response, token)
    return row


@app.post("/api/logout")
def log_out(response: Response, request: Request) -> dict[str, bool]:
    token = request.cookies.get(auth.COOKIE)
    if token:
        with db.as_user(None) as tx:
            tx.run("DELETE FROM fm.sessions WHERE token_hash = %s", (auth.token_hash(token),))
    response.delete_cookie(auth.COOKIE)
    return {"ok": True}


@app.get("/api/me")
def me(user: DictRow = Depends(auth.current_user)) -> Answer:
    """The signed-in user, and how much of their storage quota they use (every version counts)."""
    with db.as_user(user["id"]) as tx:
        usage = tx.row("SELECT used, quota FROM fm.my_usage()")
    return dict(user, **(usage or {"used": 0, "quota": 0}))


@app.get("/api/users")
def find_users(q: str = "", user: DictRow = Depends(auth.current_user)) -> list[DictRow]:
    """People to share with, by the start of their email or name (two characters at least: not a list of
    everyone)."""
    if len(q) < 2:
        return []
    start = q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
    with db.as_user(user["id"]) as tx:
        return tx.rows(
            "SELECT id, email, name FROM fm.users WHERE email LIKE %s OR name ILIKE %s ORDER BY email LIMIT 20",
            (start.lower(), start),
        )


@app.get("/api/groups")
def groups(user: DictRow = Depends(auth.current_user)) -> list[DictRow]:
    with db.as_user(user["id"]) as tx:
        manage = set(tx.authz.list("group", "manage"))
        rows = tx.rows(
            "SELECT g.id, g.name, g.parent_id, EXISTS (SELECT 1 FROM fm.group_members m "
            "WHERE m.group_id = g.id AND m.user_id = %s) AS member FROM fm.groups g ORDER BY g.name",
            (user["id"],),
        )
    return [dict(r, manage=str(r["id"]) in manage) for r in rows]


# --- folders and files -------------------------------------------------------------------------
FOLDER_COLS = "f.id, f.parent_id, f.name, f.owner_id, f.inherit, f.created_at"
# in a listing: whether the user may share the folder, which moving and deleting it need too (the web app shows
# those actions only then); one check per folder listed
CAN_SHARE = "authz.can('folder', f.id::text, 'share') AS can_share"
FILE_COLS = "f.id, f.folder_id, f.name, f.owner_id, f.size, f.content_type, f.created_at, f.updated_at"


@app.get("/api/home")
def home(user: DictRow = Depends(auth.current_user)) -> Answer:
    """Top folders: the user's own, and those shared with them (visible, inside a folder they can't see);
    and files shared with them on their own."""
    with db.as_user(user["id"]) as tx:
        folders = tx.rows(
            f"SELECT {FOLDER_COLS}, {CAN_SHARE}, f.owner_id = %s AS mine FROM fm.folders f WHERE f.parent_id IS NULL "
            f"OR NOT EXISTS (SELECT 1 FROM fm.folders p WHERE p.id = f.parent_id) ORDER BY f.name",
            (user["id"],),
        )
        files = tx.rows(
            f"SELECT {FILE_COLS} FROM fm.files f "
            f"WHERE f.ready AND NOT EXISTS (SELECT 1 FROM fm.folders p WHERE p.id = f.folder_id) ORDER BY f.name"
        )
    return {"folders": folders, "files": files}


@app.get("/api/folders/{folder_id}")
def folder(folder_id: int, user: DictRow = Depends(auth.current_user)) -> Answer:
    with db.as_user(user["id"]) as tx:
        this = found(tx.row(f"SELECT {FOLDER_COLS} FROM fm.folders f WHERE f.id = %s", (folder_id,)))
        # the way up, as far as the user can see
        path = tx.rows(
            "WITH RECURSIVE up AS (SELECT id, parent_id, name, 0 AS d FROM fm.folders WHERE id = %s "
            "UNION ALL SELECT f.id, f.parent_id, f.name, up.d + 1 FROM fm.folders f JOIN up ON f.id = up.parent_id) "
            "SELECT id, name FROM up ORDER BY d DESC",
            (folder_id,),
        )
        folders = tx.rows(
            f"SELECT {FOLDER_COLS}, {CAN_SHARE} FROM fm.folders f WHERE f.parent_id = %s ORDER BY f.name",
            (folder_id,),
        )
        files = tx.rows(
            f"SELECT {FILE_COLS} FROM fm.files f WHERE f.folder_id = %s AND f.ready ORDER BY f.name", (folder_id,)
        )
        perms = tx.authz.perms("folder", folder_id)
    return {"folder": this, "path": path, "folders": folders, "files": files, "perms": perms}


class NewFolder(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    parent_id: int | None = None


@app.post("/api/folders", status_code=201)
def create_folder(body: NewFolder, user: DictRow = Depends(auth.current_user)) -> DictRow:
    with db.as_user(user["id"]) as tx:
        return tx.one(
            f"INSERT INTO fm.folders AS f (parent_id, owner_id, name) VALUES (%s, %s, %s) RETURNING {FOLDER_COLS}",
            (body.parent_id, user["id"], body.name),
        )


class FolderChange(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    parent_id: int | None = None
    to_top: bool = False  # move out of every folder (parent_id NULL)
    inherit: bool | None = None


def changed(
    tx: db.Tx, table: LiteralString, id_: int, sets: list[LiteralString], args: list[object], cols: LiteralString
) -> DictRow | None:
    """UPDATE through row-level security: nothing changed means 404 (you can't see it) or 403 (you may not, and why)."""
    if not sets:
        return found(tx.row(f"SELECT {cols} FROM {table} f WHERE f.id = %s", (id_,)))
    row = tx.row(f"UPDATE {table} AS f SET {', '.join(sets)} WHERE f.id = %s RETURNING {cols}", (*args, id_))
    return tx.authz.expect(row, table, "update", id_)


@app.patch("/api/folders/{folder_id}")
def change_folder(folder_id: int, body: FolderChange, user: DictRow = Depends(auth.current_user)) -> DictRow | None:
    sets, args = [], []
    if body.name is not None:
        sets.append("name = %s")
        args.append(body.name)
    if body.parent_id is not None or body.to_top:
        sets.append("parent_id = %s")
        args.append(None if body.to_top else body.parent_id)
    if body.inherit is not None:
        sets.append("inherit = %s")
        args.append(body.inherit)
    with db.as_user(user["id"]) as tx:
        return changed(tx, "fm.folders", folder_id, sets, args, FOLDER_COLS)


@app.delete("/api/folders/{folder_id}", status_code=204)
def delete_folder(folder_id: int, user: DictRow = Depends(auth.current_user)) -> None:
    with db.as_user(user["id"]) as tx:
        tx.authz.expect(tx.run("DELETE FROM fm.folders WHERE id = %s", (folder_id,)), "fm.folders", "delete", folder_id)


@app.post("/api/folders/{folder_id}/files", status_code=201)
def upload(folder_id: int, file: UploadFile, user: DictRow = Depends(auth.current_user)) -> DictRow:
    """Through the backend (small files, scripts); the web app uploads straight to RustFS instead."""
    if file.size is not None and file.size > settings.max_upload_bytes:
        raise HTTPException(413, "the file is too large")
    with db.as_user(user["id"]) as tx:
        # the rows first (row-level security checks folder.edit, the quota trigger the size), then the bytes;
        # if storing fails, the rows go too
        row = new_file(
            tx,
            folder_id,
            user,
            Path(file.filename or "file").name,
            file.size or 0,
            file.content_type or "application/octet-stream",
            ready=True,
        )
        storage.put(str(row.pop("object_key")), file.file, row["content_type"])
    return row


def new_file(tx: db.Tx, folder_id: int, user: DictRow, name: str, size: int, content_type: str, ready: bool) -> DictRow:
    """A file and its first version (the object its row points at)."""
    row = tx.one(
        f"INSERT INTO fm.files AS f (folder_id, owner_id, name, size, content_type, ready) "
        f"VALUES (%s, %s, %s, %s, %s, %s) RETURNING {FILE_COLS}, f.object_key",
        (folder_id, user["id"], name, size, content_type, ready),
    )
    tx.run(
        "INSERT INTO fm.file_versions (file_id, object_key, size, content_type, ready, created_by) "
        "VALUES (%s, %s, %s, %s, %s, %s)",
        (row["id"], row["object_key"], size, content_type, ready, user["id"]),
    )
    return row


@app.get("/api/files/{file_id}")
def file_info(file_id: int, user: DictRow = Depends(auth.current_user)) -> DictRow:
    with db.as_user(user["id"]) as tx:
        row = found(tx.row(f"SELECT {FILE_COLS} FROM fm.files f WHERE f.id = %s", (file_id,)))
        row["perms"] = tx.authz.perms("file", file_id)
    return row


@app.get("/api/files/{file_id}/download")
def download(file_id: int, preview: bool = False, user: DictRow = Depends(auth.current_user)) -> dict[str, str]:
    """A short-lived signed link, made only after the file's row was read through row-level security.
    preview=true: shown in the browser (images, PDF, text, audio, video) instead of saved."""
    with db.as_user(user["id"]) as tx:
        row = found(tx.row("SELECT object_key, name, content_type FROM fm.files WHERE id = %s AND ready", (file_id,)))
    return link(row, preview)


def link(row: DictRow, preview: bool) -> dict[str, str]:
    if preview:
        return {
            "url": storage.preview_link(str(row["object_key"]), row["content_type"]),
            "content_type": row["content_type"],
        }
    return {"url": storage.download_link(str(row["object_key"]), row["name"])}


class FileChange(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    folder_id: int | None = None


@app.patch("/api/files/{file_id}")
def change_file(file_id: int, body: FileChange, user: DictRow = Depends(auth.current_user)) -> DictRow | None:
    sets: list[LiteralString] = ["updated_at = now()"]
    args: list[object] = []
    if body.name is not None:
        sets.append("name = %s")
        args.append(body.name)
    if body.folder_id is not None:
        sets.append("folder_id = %s")
        args.append(body.folder_id)
    with db.as_user(user["id"]) as tx:
        return changed(tx, "fm.files", file_id, sets if len(sets) > 1 else [], args, FILE_COLS)


@app.delete("/api/files/{file_id}", status_code=204)
def delete_file(file_id: int, user: DictRow = Depends(auth.current_user)) -> None:
    with db.as_user(user["id"]) as tx:
        found(tx.row("SELECT 1 FROM fm.files WHERE id = %s", (file_id,)))
        keys = [
            r["object_key"]
            for r in tx.rows("DELETE FROM fm.file_versions WHERE file_id = %s RETURNING object_key", (file_id,))
        ]
        tx.authz.expect(tx.run("DELETE FROM fm.files WHERE id = %s", (file_id,)), "fm.files", "delete", file_id)
    for key in keys:  # after the commit: a failure leaves an orphan object, not a lost file
        storage.delete(str(key))


class NewUpload(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    size: int = Field(ge=0)
    content_type: str = "application/octet-stream"


@app.post("/api/folders/{folder_id}/uploads", status_code=201)
def start_upload(folder_id: int, body: NewUpload, user: DictRow = Depends(auth.current_user)) -> Answer:
    """Straight to RustFS: the rows first (row-level security checks folder.edit), not ready yet, and a signed
    link the browser PUTs the bytes to; then /api/files/{id}/ready."""
    if body.size > settings.max_upload_bytes:
        raise HTTPException(413, "the file is too large")
    with db.as_user(user["id"]) as tx:
        row = new_file(tx, folder_id, user, Path(body.name).name, body.size, body.content_type, ready=False)
    return {
        "file": {k: v for k, v in row.items() if k != "object_key"},
        "url": storage.upload_link(str(row["object_key"]), row["content_type"]),
    }


def too_large(stored: int, key: str) -> None:
    """The size claimed when an upload starts is the browser's word, and the signed link takes any length: what
    arrived is checked too. Too large, it is thrown away (the rows wait for the maintenance job, or another try)."""
    if stored > settings.max_upload_bytes:
        storage.discard(key)
        raise HTTPException(413, "the file is too large")


@app.post("/api/files/{file_id}/ready")
def finish_upload(file_id: int, user: DictRow = Depends(auth.current_user)) -> DictRow | None:
    with db.as_user(user["id"]) as tx:
        row = found(tx.row("SELECT object_key FROM fm.files WHERE id = %s AND NOT ready", (file_id,)))
        stored = storage.accept(str(row["object_key"]))  # the bytes move to the file's object: the link is spent
        if stored is None:
            raise HTTPException(409, "the file's bytes haven't arrived")
        too_large(stored, str(row["object_key"]))
        tx.run("UPDATE fm.file_versions SET ready = true, size = %s WHERE object_key = %s", (stored, row["object_key"]))
        return changed(
            tx, "fm.files", file_id, ["ready = true", "size = %s", "updated_at = now()"], [stored], FILE_COLS
        )


# --- versions: every upload over a file is kept, and any can be made current again ---------------
VERSION_COLS = "v.id, v.file_id, v.size, v.content_type, v.created_at, v.created_by"


@app.get("/api/files/{file_id}/versions")
def versions(file_id: int, user: DictRow = Depends(auth.current_user)) -> list[DictRow]:
    with db.as_user(user["id"]) as tx:
        current = found(tx.row("SELECT object_key FROM fm.files WHERE id = %s", (file_id,)))["object_key"]
        rows = tx.rows(
            f"SELECT {VERSION_COLS}, v.object_key = %s AS current, u.name AS created_by_name "
            f"FROM fm.file_versions v JOIN fm.users u ON u.id = v.created_by "
            f"WHERE v.file_id = %s AND v.ready ORDER BY v.created_at DESC, v.id DESC",
            (current, file_id),
        )
    return rows


@app.post("/api/files/{file_id}/versions", status_code=201)
def start_version(file_id: int, body: NewUpload, user: DictRow = Depends(auth.current_user)) -> Answer:
    """A new version of a file (row-level security checks file.edit); the browser PUTs the bytes, then
    /api/versions/{id}/ready makes it current."""
    if body.size > settings.max_upload_bytes:
        raise HTTPException(413, "the file is too large")
    with db.as_user(user["id"]) as tx:
        found(tx.row("SELECT 1 FROM fm.files WHERE id = %s", (file_id,)))
        row = tx.one(
            f"INSERT INTO fm.file_versions AS v (file_id, size, content_type, created_by) VALUES (%s, %s, %s, %s) "
            f"RETURNING {VERSION_COLS}, v.object_key",
            (file_id, body.size, body.content_type, user["id"]),
        )
    return {
        "version": {k: v for k, v in row.items() if k != "object_key"},
        "url": storage.upload_link(str(row["object_key"]), row["content_type"]),
    }


def make_current(tx: db.Tx, version: DictRow) -> DictRow | None:
    """The file shows this version (the policy checks it is one of the file's own, and that the user may edit)."""
    return changed(
        tx,
        "fm.files",
        version["file_id"],
        ["object_key = %s", "size = %s", "content_type = %s", "updated_at = now()"],
        [version["object_key"], version["size"], version["content_type"]],
        FILE_COLS,
    )


@app.post("/api/versions/{version_id}/ready")
def finish_version(version_id: int, user: DictRow = Depends(auth.current_user)) -> DictRow | None:
    with db.as_user(user["id"]) as tx:
        v = found(tx.row("SELECT * FROM fm.file_versions WHERE id = %s AND NOT ready", (version_id,)))
        stored = storage.accept(str(v["object_key"]))
        if stored is None:
            raise HTTPException(409, "the version's bytes haven't arrived")
        too_large(stored, str(v["object_key"]))
        tx.run("UPDATE fm.file_versions SET ready = true, size = %s WHERE id = %s", (stored, version_id))
        return make_current(tx, dict(v, size=stored))


@app.post("/api/versions/{version_id}/restore")
def restore_version(version_id: int, user: DictRow = Depends(auth.current_user)) -> DictRow | None:
    with db.as_user(user["id"]) as tx:
        v = found(tx.row("SELECT * FROM fm.file_versions WHERE id = %s AND ready", (version_id,)))
        return make_current(tx, v)


@app.get("/api/versions/{version_id}/download")
def download_version(
    version_id: int, preview: bool = False, user: DictRow = Depends(auth.current_user)
) -> dict[str, str]:
    with db.as_user(user["id"]) as tx:
        row = found(
            tx.row(
                "SELECT v.object_key, f.name, v.content_type FROM fm.file_versions v JOIN fm.files f ON f.id = v.file_id "
                "WHERE v.id = %s AND v.ready",
                (version_id,),
            )
        )
    return link(row, preview)


SEARCH_PAGE = 50


def search_page(tx: db.Tx, kind: Kind, pattern: str, after: tuple[str, int] | None) -> tuple[list[DictRow], str | None]:
    """A page of one list, by name then id (names repeat across folders), after the row `after` names; and where
    the next page starts, if there is one."""
    query: LiteralString = (
        f"SELECT {FOLDER_COLS} FROM fm.folders f WHERE f.name ILIKE %s "
        if kind == "folder"
        else f"SELECT {FILE_COLS} FROM fm.files f WHERE f.ready AND f.name ILIKE %s "
    )
    if after:
        query += "AND (f.name, f.id) > (%s, %s) "
    rows = tx.rows(query + "ORDER BY f.name, f.id LIMIT %s", (pattern, *(after or ()), SEARCH_PAGE + 1))
    if len(rows) <= SEARCH_PAGE:
        return rows, None
    last = rows[SEARCH_PAGE - 1]
    return rows[:SEARCH_PAGE], f"{last['id']}:{last['name']}"


@app.get("/api/search")
def search(q: str, kind: Kind | None = None, after: str = "", user: DictRow = Depends(auth.current_user)) -> Answer:
    """Folders and files whose name contains q, among those the user can see: 50 of each at a time, by name.
    `next` says where each list's next page starts (null: none); ask for it with kind and after."""
    if len(q) < 2:
        raise HTTPException(400, "type at least two characters")
    start = None
    if after:
        if kind is None:
            raise HTTPException(400, "say which list the cursor is of (kind)")
        id_, colon, name = after.partition(":")
        if not (colon and id_.isascii() and id_.isdigit() and len(id_) < 19):  # an id: a bigint
            raise HTTPException(400, "that isn't where a page of this search ends")
        start = (name, int(id_))
    pattern = "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
    kinds: list[Kind] = [kind] if kind else ["folder", "file"]
    lists: dict[Kind, list[DictRow]] = {"folder": [], "file": []}
    following: dict[Kind, str | None] = {"folder": None, "file": None}
    with db.as_user(user["id"]) as tx:
        for k in kinds:
            lists[k], following[k] = search_page(tx, k, pattern, start)
    return {"folders": lists["folder"], "files": lists["file"], "next": following}


# --- groups: made and run by the people in them ------------------------------------------------
class NewGroup(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    parent_id: UUID | None = None


@app.post("/api/groups", status_code=201)
def create_group(body: NewGroup, user: DictRow = Depends(auth.current_user)) -> DictRow:
    with db.as_user(user["id"]) as tx:
        return tx.one(
            "INSERT INTO fm.groups (name, parent_id, owner_id) VALUES (%s, %s, %s) RETURNING id, name, parent_id, owner_id",
            (body.name, body.parent_id, user["id"]),
        )


class GroupChange(BaseModel):
    name: str = Field(min_length=1, max_length=200)


@app.patch("/api/groups/{group_id}")
def rename_group(group_id: UUID, body: GroupChange, user: DictRow = Depends(auth.current_user)) -> dict[str, bool]:
    with db.as_user(user["id"]) as tx:
        n = tx.run("UPDATE fm.groups SET name = %s WHERE id = %s", (body.name, group_id))
        tx.authz.expect(n, "fm.groups", "update", group_id)
    return {"ok": True}


@app.delete("/api/groups/{group_id}", status_code=204)
def delete_group(group_id: UUID, user: DictRow = Depends(auth.current_user)) -> None:
    with db.as_user(user["id"]) as tx:
        tx.run("DELETE FROM fm.group_members WHERE group_id = %s", (group_id,))
        tx.authz.expect(tx.run("DELETE FROM fm.groups WHERE id = %s", (group_id,)), "fm.groups", "delete", group_id)


@app.get("/api/groups/{group_id}/members")
def members(group_id: UUID, user: DictRow = Depends(auth.current_user)) -> Answer:
    with db.as_user(user["id"]) as tx:
        found(tx.row("SELECT 1 FROM fm.groups WHERE id = %s", (group_id,)))
        rows = tx.rows(
            "SELECT u.id, u.email, u.name, m.is_admin FROM fm.group_members m JOIN fm.users u ON u.id = m.user_id "
            "WHERE m.group_id = %s ORDER BY u.name",
            (group_id,),
        )
        return {"members": rows, "manage": tx.authz.can("group", str(group_id), "manage")}


class Member(BaseModel):
    user_id: UUID
    is_admin: bool = False


@app.post("/api/groups/{group_id}/members", status_code=201)
def add_member(group_id: UUID, body: Member, user: DictRow = Depends(auth.current_user)) -> dict[str, bool]:
    with db.as_user(user["id"]) as tx:
        tx.run(
            "INSERT INTO fm.group_members (group_id, user_id, is_admin) VALUES (%s, %s, %s) "
            "ON CONFLICT (group_id, user_id) DO UPDATE SET is_admin = EXCLUDED.is_admin",
            (group_id, body.user_id, body.is_admin),
        )
    return {"ok": True}


@app.delete("/api/groups/{group_id}/members/{user_id}", status_code=204)
def remove_member(group_id: UUID, user_id: UUID, user: DictRow = Depends(auth.current_user)) -> None:
    """Managers remove anyone; anyone may leave."""
    with db.as_user(user["id"]) as tx:
        member = found(
            tx.row("SELECT id FROM fm.group_members WHERE group_id = %s AND user_id = %s", (group_id, user_id))
        )
        n = tx.run("DELETE FROM fm.group_members WHERE id = %s", (member["id"],))
        tx.authz.expect(n, "fm.group_members", "delete", member["id"])


# --- sharing: who has access, and why ----------------------------------------------------------
class Share(BaseModel):
    relation: Literal["viewer", "editor"]
    subject_type: Literal["user", "group"]
    subject_id: UUID
    expires_at: datetime | None = None


def subject(body: Share) -> tuple[str, str]:
    return str(body.subject_id), "member" if body.subject_type == "group" else ""


def named(tx: db.Tx, rows: Sequence[Mapping[str, object]], key: str, into: str) -> list[DictRow]:
    """rows with the name of the user or group whose id is in rows[key]."""
    names = {
        str(r["id"]): r["name"]
        for r in tx.rows(
            "SELECT id, name FROM fm.users WHERE id::text = ANY (%(ids)s) UNION ALL "
            "SELECT id, name FROM fm.groups WHERE id::text = ANY (%(ids)s)",
            {"ids": [r[key] for r in rows]},
        )
    }
    return [dict(r, **{into: names.get(r[key])}) for r in rows]


@app.get("/api/{kind}s/{id_}/shares")
def shares(kind: Kind, id_: int, user: DictRow = Depends(auth.current_user)) -> list[DictRow]:
    with db.as_user(user["id"]) as tx:
        found(tx.row(f"SELECT 1 FROM {TABLES[kind]} WHERE id = %s", (id_,)))
        return named(tx, tx.authz.list_shares(kind, id_), "subject_id", "subject_name")


@app.post("/api/{kind}s/{id_}/shares", status_code=201)
def share(kind: Kind, id_: int, body: Share, user: DictRow = Depends(auth.current_user)) -> dict[str, bool]:
    sid, srel = subject(body)
    with db.as_user(user["id"]) as tx:
        found(tx.row(f"SELECT 1 FROM {TABLES[kind]} WHERE id = %s", (id_,)))
        tx.authz.share(kind, id_, body.relation, body.subject_type, sid, srel, body.expires_at)
    return {"ok": True}


@app.delete("/api/{kind}s/{id_}/shares", status_code=204)
def unshare(kind: Kind, id_: int, body: Share, user: DictRow = Depends(auth.current_user)) -> None:
    sid, srel = subject(body)
    with db.as_user(user["id"]) as tx:
        found(tx.row(f"SELECT 1 FROM {TABLES[kind]} WHERE id = %s", (id_,)))
        tx.authz.unshare(kind, id_, body.relation, body.subject_type, sid, srel)


@app.get("/api/{kind}s/{id_}/access")
def access(
    kind: Kind, id_: int, perm: Literal["view", "edit", "share"] = "view", user: DictRow = Depends(auth.current_user)
) -> list[DictRow]:
    """Everyone who holds perm on it (for people who may share it)."""
    with db.as_user(user["id"]) as tx:
        found(tx.row(f"SELECT 1 FROM {TABLES[kind]} WHERE id = %s", (id_,)))
        ids = tx.authz.who(kind, id_, perm)
        return tx.rows("SELECT id, email, name FROM fm.users WHERE id::text = ANY (%s) ORDER BY name", (list(ids),))


@app.get("/api/{kind}s/{id_}/why")
def why(
    kind: Kind, id_: int, perm: Literal["view", "edit", "share"] = "view", user: DictRow = Depends(auth.current_user)
) -> dict[str, Sequence[str]]:
    """Why the user holds perm, or what is missing."""
    with db.as_user(user["id"]) as tx:
        return {"lines": tx.authz.explain(kind, id_, perm)}


# --- share links: anyone holding the link may view, until it expires or is revoked --------------
class NewLink(BaseModel):
    expires_at: datetime | None = None


@app.post("/api/{kind}s/{id_}/links", status_code=201)
def create_link(kind: Kind, id_: int, body: NewLink, user: DictRow = Depends(auth.current_user)) -> DictRow:
    """The token is returned once: rowstile keeps only its hash."""
    with db.as_user(user["id"]) as tx:
        found(tx.row(f"SELECT 1 FROM {TABLES[kind]} WHERE id = %s", (id_,)))
        token = tx.authz.create_link(kind, id_, "viewer", body.expires_at)
    return {"token": token, "path": f"#/link/{kind}/{id_}/{token}"}


@app.get("/api/{kind}s/{id_}/links")
def links(kind: Kind, id_: int, user: DictRow = Depends(auth.current_user)) -> list[DictRow]:
    """Its links, for people who may share it (authz.list_links): each has an id, which is not its token."""
    with db.as_user(user["id"]) as tx:
        found(tx.row(f"SELECT 1 FROM {TABLES[kind]} WHERE id = %s", (id_,)))
        return named(tx, tx.authz.list_links(kind, id_), "created_by", "created_by")


@app.delete("/api/{kind}s/{id_}/links/{link_id}", status_code=204)
def revoke_link(kind: Kind, id_: int, link_id: str, user: DictRow = Depends(auth.current_user)) -> None:
    with db.as_user(user["id"]) as tx:
        found(tx.row(f"SELECT 1 FROM {TABLES[kind]} WHERE id = %s", (id_,)))
        found(next((x for x in tx.authz.list_links(kind, id_) if x["id"] == link_id), None))
        tx.authz.revoke_link(kind, id_, link_id)


def link_token(request: Request) -> str:
    token = request.headers.get("X-Link-Token", "")
    if not token:
        raise HTTPException(404, "not found")
    return token


@app.get("/api/public/folders/{folder_id}")
def public_folder(folder_id: int, request: Request) -> Answer:
    """A folder opened with a share link (X-Link-Token), signed in or not; what's inside comes along."""
    with db.as_user(None, [link_token(request)]) as tx:
        this = found(tx.row(f"SELECT {FOLDER_COLS} FROM fm.folders f WHERE f.id = %s", (folder_id,)))
        path = tx.rows(
            "WITH RECURSIVE up AS (SELECT id, parent_id, name, 0 AS d FROM fm.folders WHERE id = %s "
            "UNION ALL SELECT f.id, f.parent_id, f.name, up.d + 1 FROM fm.folders f JOIN up ON f.id = up.parent_id) "
            "SELECT id, name FROM up ORDER BY d DESC",
            (folder_id,),
        )
        folders = tx.rows(
            f"SELECT {FOLDER_COLS} FROM fm.folders f WHERE f.parent_id = %s ORDER BY f.name", (folder_id,)
        )
        files = tx.rows(
            f"SELECT {FILE_COLS} FROM fm.files f WHERE f.folder_id = %s AND f.ready ORDER BY f.name", (folder_id,)
        )
    return {"folder": this, "path": path, "folders": folders, "files": files}


@app.get("/api/public/files/{file_id}")
def public_file(file_id: int, request: Request) -> DictRow:
    with db.as_user(None, [link_token(request)]) as tx:
        return found(tx.row(f"SELECT {FILE_COLS} FROM fm.files f WHERE f.id = %s AND f.ready", (file_id,)))


@app.get("/api/public/files/{file_id}/download")
def public_download(file_id: int, request: Request, preview: bool = False) -> dict[str, str]:
    with db.as_user(None, [link_token(request)]) as tx:
        row = found(tx.row("SELECT object_key, name, content_type FROM fm.files WHERE id = %s AND ready", (file_id,)))
    return link(row, preview)


# --- access requests, reviews, break glass -----------------------------------------------------
class AccessRequest(BaseModel):
    relation: Literal["viewer", "editor"]
    reason: str = Field(min_length=1, max_length=1000)
    duration: str | None = "7 days"


@app.post("/api/{kind}s/{id_}/requests", status_code=201)
def request_access(
    kind: Kind, id_: int, body: AccessRequest, user: DictRow = Depends(auth.current_user)
) -> dict[str, int]:
    """Anyone may ask; asking doesn't reveal whether a hidden object exists."""
    with db.as_user(user["id"]) as tx:
        return {"id": tx.authz.request_access(kind, id_, body.relation, body.reason, body.duration)}


@app.get("/api/requests")
def requests(user: DictRow = Depends(auth.current_user)) -> list[DictRow]:
    with db.as_user(user["id"]) as tx:
        return named(tx, tx.authz.pending_requests(), "requester", "requester_name")


class Decision(BaseModel):
    approve: bool
    note: str | None = None


@app.post("/api/requests/{request_id}/decision")
def decide(request_id: int, body: Decision, user: DictRow = Depends(auth.current_user)) -> dict[str, bool]:
    with db.as_user(user["id"]) as tx:
        tx.authz.decide_request(request_id, body.approve, body.note)
    return {"ok": True}


@app.delete("/api/requests/{request_id}", status_code=204)
def cancel(request_id: int, user: DictRow = Depends(auth.current_user)) -> None:
    with db.as_user(user["id"]) as tx:
        tx.authz.cancel_request(request_id)


@app.post("/api/{kind}s/{id_}/reviews", status_code=201)
def start_review(kind: Kind, id_: int, user: DictRow = Depends(auth.current_user)) -> dict[str, int]:
    with db.as_user(user["id"]) as tx:
        found(tx.row(f"SELECT 1 FROM {TABLES[kind]} WHERE id = %s", (id_,)))
        return {"id": tx.authz.start_review(kind, id_)}


@app.get("/api/reviews/{review_id}")
def review(review_id: int, user: DictRow = Depends(auth.current_user)) -> list[DictRow]:
    with db.as_user(user["id"]) as tx:
        return named(tx, tx.authz.review_items(review_id), "subject_id", "subject_name")


class Keep(BaseModel):
    keep: bool


@app.post("/api/reviews/{review_id}/items/{item}")
def review_decide(review_id: int, item: int, body: Keep, user: DictRow = Depends(auth.current_user)) -> dict[str, bool]:
    with db.as_user(user["id"]) as tx:
        tx.authz.review_decide(review_id, item, body.keep)
    return {"ok": True}


class Close(BaseModel):
    revoke_undecided: bool = False


@app.post("/api/reviews/{review_id}/close")
def close_review(review_id: int, body: Close, user: DictRow = Depends(auth.current_user)) -> dict[str, int]:
    with db.as_user(user["id"]) as tx:
        return {"revoked": tx.authz.close_review(review_id, body.revoke_undecided)}


class BreakGlass(BaseModel):
    reason: str = Field(min_length=1, max_length=1000)
    duration: str = "1 hour"


@app.post("/api/folders/{folder_id}/break-glass")
def break_glass(folder_id: int, body: BreakGlass, user: DictRow = Depends(auth.current_user)) -> dict[str, bool]:
    """Support staff give themselves view access for a short time; audited and announced."""
    with db.as_user(user["id"]) as tx:
        tx.authz.break_glass("folder", folder_id, "viewer", body.reason, body.duration)
    return {"ok": True}


# --- the web app ---------------------------------------------------------------------------------
WEB = Path(__file__).resolve().parents[2] / "frontend" / "dist"
if WEB.is_dir():
    app.mount("/assets", StaticFiles(directory=WEB / "assets"), name="assets")

    @app.get("/{path:path}", include_in_schema=False)
    def web(path: str) -> FileResponse:
        if path == "api" or path.startswith("api/"):  # not the web app's: an API path that doesn't exist
            raise HTTPException(404, "not found")
        return FileResponse(WEB / "index.html")

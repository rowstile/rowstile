"""The messenger's HTTP API.

Every route runs in a transaction signed in as the person (db.as_user) or the bot (db.as_bot) asking.
Who may read a chat, post in it, add people, edit or delete a message, join with a link or write to
someone who blocked them is decided by row-level security from db/policy.authz: there is not one
permission check in this file. Something you may not see answers 404, as if it didn't exist; something
you see but may not do answers 403, with the database's own explanation of why: a refused write raises it
(the rule, and what is missing), and an update or delete that changed nothing asks for it (authz.expect).
"""

import asyncio
import threading
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated, Literal, LiteralString
from uuid import UUID

import psycopg
from fastapi import (
    Depends,
    FastAPI,
    HTTPException,
    Query,
    Request,
    Response,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from psycopg import errors
from psycopg.abc import Params
from psycopg.rows import DictRow
from pydantic import BaseModel, Field

from . import auth, db, events
from .authz_client import NotFound, Refused, refusal
from .config import load

settings = load()


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    db.open_pool(settings.database_url)
    # the app must connect as a role row-level security applies to: with the owner's URL here by mistake,
    # every request would see everything
    with db.as_user(None) as tx:
        problems = [str(r["problem"]) for r in tx.authz.connection_check() if r["severity"] == "error"]
    if problems:
        db.close_pool()
        raise RuntimeError("MS_DATABASE_URL can't be used with rowstile: " + "; ".join(problems))
    stop = threading.Event()
    threading.Thread(
        target=events.listen, args=(settings.database_url, asyncio.get_running_loop(), stop), daemon=True
    ).start()
    yield
    stop.set()
    db.close_pool()


app = FastAPI(title="Messenger", lifespan=lifespan)


# --- errors: what the database refused, as HTTP ------------------------------------------------
# What to say when the database refuses a write, by table and command: words for people. Why comes from the
# database (the rule, and what is missing), shown behind "why?".
WORDS: dict[tuple[str | None, str | None], str] = {
    ("ms.messages", "insert"): "you can't send messages here",
    ("ms.messages", "update"): "you may edit your own messages for 15 minutes, and delete them (admins: anyone's)",
    ("ms.members", "insert"): "you can't add this person here",
    ("ms.members", "update"): "only admins change roles, and nobody the owner's",
    ("ms.members", "delete"): "you can't remove this person (the owner stays: they delete the group instead)",
    ("ms.chats", "update"): "only the group's admins may change it",
    ("ms.chats", "delete"): "only the group's owner may delete it",
    ("ms.chat_bots", "insert"): "admins add their own bots to groups",
    ("ms.chat_bots", "delete"): "you can't remove this bot",
    (None, None): "you may not do that here",
}


@app.exception_handler(Refused)
async def refused(_request: Request, e: Refused) -> JSONResponse:
    return JSONResponse({"detail": WORDS.get((e.table, e.command), WORDS[None, None]), "why": e.why}, 403)


@app.exception_handler(NotFound)
async def not_found(_request: Request, e: NotFound) -> JSONResponse:
    return JSONResponse({"detail": "not found"}, 404)


@app.exception_handler(psycopg.Error)
async def database_error(request: Request, e: psycopg.Error) -> JSONResponse:
    diag = getattr(e, "diag", None)
    message = (diag.message_primary if diag and diag.message_primary else str(e)).split("\n")[0]
    r = refusal(e)
    if r:
        return await refused(request, r)
    if isinstance(e, errors.UniqueViolation):
        return JSONResponse({"detail": "that is already there"}, 409)
    if isinstance(e, errors.ForeignKeyViolation):
        return JSONResponse({"detail": "no such person or chat"}, 404)
    if isinstance(e, errors.InvalidAuthorizationSpecification):  # a bot's key that doesn't work
        return JSONResponse({"detail": "invalid API key"}, 401)
    # a value the database can't take (a number past bigint's range, text that isn't one) is the request's fault
    if isinstance(e, (errors.CheckViolation, errors.RaiseException, psycopg.DataError)):
        return JSONResponse({"detail": message}, 400)
    raise e


# a message's number, as the API takes it: what a bigint column holds, so a bad one is the request's fault (422)
Seq = Annotated[int, Field(ge=0, le=2**63 - 1)]


def found(row: DictRow | None, what: str = "not found") -> DictRow:
    if row is None:
        raise HTTPException(404, what)
    return row


# --- accounts ----------------------------------------------------------------------------------
class SignUp(BaseModel):
    phone: str = Field(min_length=3, max_length=30)
    name: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=8, max_length=200)


class LogIn(BaseModel):
    phone: str
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


def phone_of(text: str) -> str:
    return "".join(c for c in text if c.isdigit() or c == "+")


@app.post("/api/signup")
def sign_up(body: SignUp, response: Response) -> DictRow:
    with db.as_user(None) as tx:
        user = tx.one(
            "SELECT id, phone, name, about FROM ms.sign_up(%s, %s, %s)",
            (phone_of(body.phone), body.name, auth.hash_password(body.password)),
        )
        token = auth.new_session(tx, user["id"], settings.session_days)
    set_cookie(response, token)
    return user


@app.post("/api/login")
def log_in(body: LogIn, response: Response) -> DictRow | None:
    with db.as_user(None) as tx:
        row = tx.row("SELECT * FROM ms.credentials_for(%s)", (phone_of(body.phone),))
        if row is None or not auth.password_ok(body.password, row["password_hash"]):
            raise HTTPException(401, "wrong phone number or password")
        token = auth.new_session(tx, row["user_id"], settings.session_days)
    set_cookie(response, token)
    return auth.profile(row["user_id"])


@app.post("/api/logout")
def log_out(response: Response, request: Request) -> dict[str, bool]:
    token = request.cookies.get(auth.COOKIE)
    if token:
        with db.as_user(None) as tx:
            tx.run("DELETE FROM ms.sessions WHERE token_hash = %s", (auth.token_hash(token),))
    response.delete_cookie(auth.COOKIE)
    return {"ok": True}


@app.get("/api/me")
def me(user: DictRow = Depends(auth.current_user)) -> DictRow:
    return user


class Profile(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=100)
    about: str | None = Field(default=None, max_length=200)


@app.patch("/api/me")
def edit_profile(body: Profile, user: DictRow = Depends(auth.current_user)) -> DictRow | None:
    with db.as_user(user["id"]) as tx:
        return tx.row(
            "UPDATE ms.users SET name = coalesce(%s, name), about = coalesce(%s, about) WHERE id = %s "
            "RETURNING id, phone, name, about",
            (body.name, body.about, user["id"]),
        )


@app.get("/api/people")
def find_people(phone: str, user: DictRow = Depends(auth.current_user)) -> list[DictRow]:
    """Someone by their phone number (to start a chat or add them to a group)."""
    with db.as_user(user["id"]) as tx:
        return tx.rows("SELECT id, phone, name, about FROM ms.users WHERE phone = %s", (phone_of(phone),))


# --- chats -------------------------------------------------------------------------------------
CHAT_LIST = """
SELECT c.id, c.kind, c.admins_only, m.role, m.last_read_seq,
       CASE WHEN c.kind = 'group' THEN c.title ELSE p.name END AS name, p.id AS peer_id,
       l.seq AS last_seq, l.body AS last_body, l.deleted AS last_deleted, l.created_at AS last_at,
       coalesce(ls.name, lb.name) AS last_sender, l.sender_id AS last_sender_id,
       greatest(c.last_seq - greatest(m.last_read_seq, m.joined_seq), 0) AS unread
FROM ms.chats c
JOIN ms.members m ON m.chat_id = c.id AND m.user_id = %(me)s
LEFT JOIN LATERAL (SELECT u.id, u.name FROM ms.members o JOIN ms.users u ON u.id = o.user_id
                   WHERE c.kind = 'direct' AND o.chat_id = c.id AND o.user_id <> %(me)s LIMIT 1) p ON true
LEFT JOIN LATERAL (SELECT x.seq, x.body, x.deleted, x.created_at, x.sender_id, x.bot_id FROM ms.messages x
                   WHERE x.chat_id = c.id ORDER BY x.seq DESC LIMIT 1) l ON true
LEFT JOIN ms.users ls ON ls.id = l.sender_id
LEFT JOIN ms.bots lb ON lb.id = l.bot_id
ORDER BY coalesce(l.created_at, c.created_at) DESC, c.id DESC"""


@app.get("/api/chats")
def chats(user: DictRow = Depends(auth.current_user)) -> list[DictRow]:
    """Your chats, the latest first: what row-level security lets you read (the join on ms.members only
    picks your own row, for your role and how far you have read). Unread is a difference of numbers: messages are
    numbered one by one in each chat, and your mark moves past what you post, so no unread message is read to count
    it (each would be checked against the read rule, which costs a function call a message)."""
    with db.as_user(user["id"]) as tx:
        return tx.rows(CHAT_LIST, {"me": user["id"]})


class NewChat(BaseModel):
    kind: Literal["direct", "group"]
    user_id: UUID | None = None  # direct: the other person
    title: str | None = Field(default=None, min_length=1, max_length=100)  # group
    about: str = Field(default="", max_length=500)
    member_ids: list[UUID] = []  # group: who else is in it


@app.post("/api/chats", status_code=201)
def new_chat(body: NewChat, user: DictRow = Depends(auth.current_user)) -> DictRow:
    me_id = user["id"]

    def make(tx: db.Tx) -> DictRow:
        if body.kind == "direct":
            if body.user_id is None or str(body.user_id) == str(me_id):
                raise HTTPException(400, "say who to chat with")
            old = tx.row(
                "SELECT c.id FROM ms.chats c JOIN ms.members a ON a.chat_id = c.id AND a.user_id = %s "
                "JOIN ms.members b ON b.chat_id = c.id AND b.user_id = %s WHERE c.kind = 'direct'",
                (me_id, body.user_id),
            )
            if old:
                return old
            chat = tx.one("INSERT INTO ms.chats (kind, created_by) VALUES ('direct', %s) RETURNING id", (me_id,))
            tx.run("INSERT INTO ms.members (chat_id, user_id) VALUES (%s, %s)", (chat["id"], me_id))
            tx.run("INSERT INTO ms.members (chat_id, user_id) VALUES (%s, %s)", (chat["id"], body.user_id))
            return chat
        if not body.title:
            raise HTTPException(400, "a group needs a name")
        chat = tx.one(
            "INSERT INTO ms.chats (kind, title, about, created_by) VALUES ('group', %s, %s, %s) RETURNING id",
            (body.title, body.about, me_id),
        )
        tx.run("INSERT INTO ms.members (chat_id, user_id, role) VALUES (%s, %s, 'owner')", (chat["id"], me_id))
        for other in dict.fromkeys(body.member_ids):
            if str(other) != str(me_id):
                tx.run("INSERT INTO ms.members (chat_id, user_id) VALUES (%s, %s)", (chat["id"], other))
        return chat

    try:
        with db.as_user(me_id) as tx:  # the one refusal here: adding someone who blocked you
            return make(tx)
    except errors.UniqueViolation:
        # the other person made the pair's chat at the same moment (ms.direct_pairs): theirs is the one
        with db.as_user(me_id) as tx:
            return make(tx)


@app.get("/api/chats/{chat_id}")
def chat(chat_id: int, user: DictRow = Depends(auth.current_user)) -> DictRow:
    """A chat, its members and bots, and what you may do in it (authz.perms: the web app shows or hides
    buttons by it, and the database enforces the same thing when you press them)."""
    with db.as_user(user["id"]) as tx:
        c = found(
            tx.row(
                "SELECT id, kind, title, about, admins_only, created_at, last_seq FROM ms.chats WHERE id = %s",
                (chat_id,),
            )
        )
        c["members"] = tx.rows(
            "SELECT m.user_id, m.role, m.last_read_seq, u.name, u.phone, u.about "
            "FROM ms.members m JOIN ms.users u ON u.id = m.user_id WHERE m.chat_id = %s "
            "ORDER BY array_position(ARRAY['owner', 'admin', 'member'], m.role), u.name",
            (chat_id,),
        )
        c["bots"] = tx.rows(
            "SELECT b.id, b.name FROM ms.chat_bots cb JOIN ms.bots b ON b.id = cb.bot_id "
            "WHERE cb.chat_id = %s ORDER BY b.name",
            (chat_id,),
        )
        c["perms"] = list(tx.authz.perms("chat", chat_id))
        peer = next((m for m in c["members"] if str(m["user_id"]) != str(user["id"])), None)
        if c["kind"] == "direct" and peer:
            c["title"], c["peer_id"] = peer["name"], peer["user_id"]
            c["i_blocked"] = (
                tx.row(
                    "SELECT 1 FROM ms.blocks WHERE blocker_id = %s AND blocked_id = %s", (user["id"], peer["user_id"])
                )
                is not None
            )
    return c


@app.get("/api/chats/{chat_id}/why/{perm}")
def why(
    chat_id: int,
    perm: Literal["read", "post", "manage", "invite", "add_members"],
    user: DictRow = Depends(auth.current_user),
) -> list[str]:
    """Why you hold perm on the chat, or what is missing: the database's own explanation (authz.explain)."""
    with db.as_user(user["id"]) as tx:
        found(tx.row("SELECT 1 FROM ms.chats WHERE id = %s", (chat_id,)))
        return list(tx.authz.explain("chat", chat_id, perm))


class ChatChange(BaseModel):
    title: str | None = Field(default=None, min_length=1, max_length=100)
    about: str | None = Field(default=None, max_length=500)
    admins_only: bool | None = None


@app.patch("/api/chats/{chat_id}")
def change_chat(chat_id: int, body: ChatChange, user: DictRow = Depends(auth.current_user)) -> DictRow | None:
    with db.as_user(user["id"]) as tx:
        row = tx.row(
            "UPDATE ms.chats SET title = coalesce(%s, title), about = coalesce(%s, about), "
            "admins_only = coalesce(%s, admins_only) WHERE id = %s RETURNING id, title, about, admins_only",
            (body.title, body.about, body.admins_only, chat_id),
        )
        return tx.authz.expect(row, "ms.chats", "update", chat_id)


@app.delete("/api/chats/{chat_id}", status_code=204)
def delete_chat(chat_id: int, user: DictRow = Depends(auth.current_user)) -> None:
    with db.as_user(user["id"]) as tx:
        tx.authz.expect(tx.run("DELETE FROM ms.chats WHERE id = %s", (chat_id,)), "ms.chats", "delete", chat_id)


# --- messages ----------------------------------------------------------------------------------
MESSAGE_COLS = """x.seq, x.sender_id, x.bot_id, x.body, x.deleted, x.created_at, x.edited_at,
       u.name AS sender_name, b.name AS bot_name"""
MESSAGES = f"""
SELECT {MESSAGE_COLS},
       authz.can('message', ROW(x.chat_id, x.seq)::text, 'edit') AS can_edit,
       authz.can('message', ROW(x.chat_id, x.seq)::text, 'remove') AS can_remove
FROM ms.messages x LEFT JOIN ms.users u ON u.id = x.sender_id LEFT JOIN ms.bots b ON b.id = x.bot_id
WHERE x.chat_id = %s AND (%s::bigint IS NULL OR x.seq < %s) AND (%s::bigint IS NULL OR x.seq > %s)
ORDER BY x.seq DESC LIMIT %s"""


@app.get("/api/chats/{chat_id}/messages")
def messages(
    chat_id: int,
    before: Annotated[Seq | None, Query()] = None,
    after: Annotated[Seq | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    user: DictRow = Depends(auth.current_user),
) -> list[DictRow]:
    """The latest messages (or those before or after a number), oldest first. Messages from before you
    joined are not there: the policy's message.read says so. Each says whether you may edit or delete it:
    authz.can on the message, whose id is (chat_id, seq)."""
    with db.as_user(user["id"]) as tx:
        found(tx.row("SELECT 1 FROM ms.chats WHERE id = %s", (chat_id,)))
        rows = tx.rows(MESSAGES, (chat_id, before, before, after, after, limit))
    return rows[::-1]


class NewMessage(BaseModel):
    body: str = Field(min_length=1, max_length=4000)


@app.post("/api/chats/{chat_id}/messages", status_code=201)
def post(chat_id: int, body: NewMessage, user: DictRow = Depends(auth.current_user)) -> DictRow:
    with db.as_user(user["id"]) as tx:
        found(tx.row("SELECT 1 FROM ms.chats WHERE id = %s", (chat_id,)))  # a chat you can't see: 404
        row = tx.one(
            "INSERT INTO ms.messages AS x (chat_id, sender_id, body) VALUES (%s, %s, %s) RETURNING x.seq, x.created_at",
            (chat_id, user["id"], body.body),
        )
        tx.run(
            # only a mark that moves: an update of the row tells every member's open chat (ms.announce)
            "UPDATE ms.members SET last_read_seq = %s WHERE chat_id = %s AND user_id = %s AND last_read_seq < %s",
            (row["seq"], chat_id, user["id"], row["seq"]),
        )
        return row


def change_message(
    user: DictRow, chat_id: int, seq: int, sql: LiteralString, args: Params, values: dict[str, object]
) -> DictRow | None:
    with db.as_user(user["id"]) as tx:
        return tx.authz.expect(tx.row(sql, args), "ms.messages", "update", (chat_id, seq), values)


class Edit(BaseModel):
    body: str = Field(min_length=1, max_length=4000)


@app.patch("/api/chats/{chat_id}/messages/{seq}")
def edit(chat_id: int, seq: int, body: Edit, user: DictRow = Depends(auth.current_user)) -> DictRow | None:
    return change_message(
        user,
        chat_id,
        seq,
        "UPDATE ms.messages SET body = %s, edited_at = now() WHERE chat_id = %s AND seq = %s "
        "RETURNING seq, body, edited_at",
        (body.body, chat_id, seq),
        {"body": body.body},
    )


@app.delete("/api/chats/{chat_id}/messages/{seq}")
def delete_for_everyone(chat_id: int, seq: int, user: DictRow = Depends(auth.current_user)) -> DictRow | None:
    return change_message(
        user,
        chat_id,
        seq,
        "UPDATE ms.messages SET deleted = true, body = '' WHERE chat_id = %s AND seq = %s RETURNING seq, deleted",
        (chat_id, seq),
        {"deleted": True, "body": ""},
    )


class Read(BaseModel):
    seq: Seq


@app.post("/api/chats/{chat_id}/read")
def mark_read(chat_id: int, body: Read, user: DictRow = Depends(auth.current_user)) -> dict[str, bool]:
    with db.as_user(user["id"]) as tx:
        tx.run(  # a mark that wouldn't move changes no row, so nobody is told of it
            "UPDATE ms.members SET last_read_seq = %s WHERE chat_id = %s AND user_id = %s AND last_read_seq < %s",
            (body.seq, chat_id, user["id"], body.seq),
        )
    return {"ok": True}


# --- members -----------------------------------------------------------------------------------
class NewMember(BaseModel):
    user_id: UUID


@app.post("/api/chats/{chat_id}/members", status_code=201)
def add_member(chat_id: int, body: NewMember, user: DictRow = Depends(auth.current_user)) -> dict[str, bool]:
    with db.as_user(user["id"]) as tx:
        found(tx.row("SELECT 1 FROM ms.chats WHERE id = %s", (chat_id,)))
        tx.run("INSERT INTO ms.members (chat_id, user_id) VALUES (%s, %s)", (chat_id, body.user_id))
    return {"ok": True}


class Role(BaseModel):
    role: Literal["admin", "member"]


@app.patch("/api/chats/{chat_id}/members/{user_id}")
def set_role(chat_id: int, user_id: UUID, body: Role, user: DictRow = Depends(auth.current_user)) -> dict[str, bool]:
    with db.as_user(user["id"]) as tx:
        n = tx.run("UPDATE ms.members SET role = %s WHERE chat_id = %s AND user_id = %s", (body.role, chat_id, user_id))
        tx.authz.expect(n, "ms.members", "update", (chat_id, user_id), {"role": body.role})
    return {"ok": True}


@app.delete("/api/chats/{chat_id}/members/{user_id}", status_code=204)
def remove_member(chat_id: int, user_id: UUID, user: DictRow = Depends(auth.current_user)) -> None:
    """Leave (yourself), or remove someone (admins; never the owner)."""
    with db.as_user(user["id"]) as tx:
        n = tx.run("DELETE FROM ms.members WHERE chat_id = %s AND user_id = %s", (chat_id, user_id))
        tx.authz.expect(n, "ms.members", "delete", (chat_id, user_id))


# --- invite links: rowstile share links ----------------------------------------------------------
@app.post("/api/chats/{chat_id}/invite", status_code=201)
def invite(chat_id: int, user: DictRow = Depends(auth.current_user)) -> dict[str, str | datetime]:
    """A link anyone may use to join, for a week (authz.create_link: only its hash is stored)."""
    expires = datetime.now(UTC) + timedelta(days=settings.invite_days)

    with db.as_user(user["id"]) as tx:
        found(tx.row("SELECT 1 FROM ms.chats WHERE id = %s", (chat_id,)))
        return {"token": tx.authz.create_link("chat", chat_id, "invitee", expires), "expires_at": expires}


@app.get("/api/chats/{chat_id}/invites")
def invites(chat_id: int, user: DictRow = Depends(auth.current_user)) -> list[DictRow]:
    """The chat's invite links, for those who may make them (authz.list_links): each has an id, never its token."""
    with db.as_user(user["id"]) as tx:
        found(tx.row("SELECT 1 FROM ms.chats WHERE id = %s", (chat_id,)))
        links = tx.authz.list_links("chat", chat_id)
        names = {
            str(u["id"]): u["name"]
            for u in tx.rows(
                "SELECT id, name FROM ms.users WHERE id::text = ANY (%s)", ([x["created_by"] for x in links],)
            )
        }
        return [
            {
                "id": x["id"],
                "created_by": names.get(x["created_by"]),
                "created_at": x["created_at"],
                "expires_at": x["expires_at"],
            }
            for x in links
        ]


@app.delete("/api/chats/{chat_id}/invites/{link_id}", status_code=204)
def turn_off_invite(chat_id: int, link_id: str, user: DictRow = Depends(auth.current_user)) -> None:
    """Nobody joins with that link any more (authz.revoke_link); those who did stay."""
    with db.as_user(user["id"]) as tx:
        found(tx.row("SELECT 1 FROM ms.chats WHERE id = %s", (chat_id,)))
        found(next((x for x in tx.authz.list_links("chat", chat_id) if x["id"] == link_id), None))
        tx.authz.revoke_link("chat", chat_id, link_id)


def linked_chat(user_id: str, token: str, chat_id: int | None) -> DictRow:
    """The group the link lets you join: the chats you may join holding it, less those you may without it. Admins
    may join their groups without a link (they may make one), so for them that leaves nothing: the chat the link's
    address names (`?chat=`, as the web app writes it) answers, when it is one of theirs."""
    with db.as_user(user_id) as tx:
        without = set(tx.authz.list("chat", "join"))
    with db.as_user(user_id, links=[token]) as tx:
        given = [c for c in tx.authz.list("chat", "join") if c not in without]
        if not given and str(chat_id) in without:
            given = [str(chat_id)]
        if not given:
            raise HTTPException(404, "this invite link doesn't work (any more)")
        return found(
            tx.row(
                "SELECT c.id, c.title, c.about, EXISTS (SELECT 1 FROM ms.members m WHERE m.chat_id = c.id "
                "AND m.user_id = %s) AS member FROM ms.chats c WHERE c.id = %s",
                (user_id, int(given[0])),
            )
        )


@app.get("/api/join/{token}")
def join_preview(token: str, chat: int | None = None, user: DictRow = Depends(auth.current_user)) -> DictRow:
    return linked_chat(user["id"], token, chat)


@app.post("/api/join/{token}")
def join(token: str, chat: int | None = None, user: DictRow = Depends(auth.current_user)) -> dict[str, int]:
    linked = linked_chat(user["id"], token, chat)
    if not linked["member"]:
        with db.as_user(user["id"], links=[token]) as tx:
            tx.run("INSERT INTO ms.members (chat_id, user_id) VALUES (%s, %s)", (linked["id"], user["id"]))
    return {"id": linked["id"]}


# --- blocking ----------------------------------------------------------------------------------
@app.get("/api/blocks")
def blocks(user: DictRow = Depends(auth.current_user)) -> list[DictRow]:
    with db.as_user(user["id"]) as tx:
        return tx.rows(
            "SELECT u.id, u.name, u.phone FROM ms.blocks b JOIN ms.users u ON u.id = b.blocked_id ORDER BY u.name"
        )


class Block(BaseModel):
    user_id: UUID


@app.post("/api/blocks", status_code=201)
def block(body: Block, user: DictRow = Depends(auth.current_user)) -> dict[str, bool]:
    with db.as_user(user["id"]) as tx:
        tx.run(
            "INSERT INTO ms.blocks (blocker_id, blocked_id) VALUES (%s, %s) ON CONFLICT DO NOTHING",
            (user["id"], body.user_id),
        )
    return {"ok": True}


@app.delete("/api/blocks/{user_id}", status_code=204)
def unblock(user_id: UUID, user: DictRow = Depends(auth.current_user)) -> None:
    with db.as_user(user["id"]) as tx:
        tx.run("DELETE FROM ms.blocks WHERE blocker_id = %s AND blocked_id = %s", (user["id"], user_id))


# --- bots: principals with their own API keys ----------------------------------------------------
class NewBot(BaseModel):
    name: str = Field(min_length=1, max_length=100)


@app.get("/api/bots")
def my_bots(user: DictRow = Depends(auth.current_user)) -> list[DictRow]:
    with db.as_user(user["id"]) as tx:
        return tx.rows(
            "SELECT id, name, active, created_at FROM ms.bots WHERE owner_id = %s ORDER BY id", (user["id"],)
        )


@app.post("/api/bots", status_code=201)
def new_bot(body: NewBot, user: DictRow = Depends(auth.current_user)) -> DictRow:
    """A bot, and its API key (shown once). Making the key needs manage_keys on the bot: its owner."""
    with db.as_user(user["id"]) as tx:
        bot = tx.one("INSERT INTO ms.bots (name, owner_id) VALUES (%s, %s) RETURNING id, name", (body.name, user["id"]))
        bot["key"] = tx.authz.create_api_key(body.name, principal_type="bot", principal_id=bot["id"])
    return bot


class ChatBot(BaseModel):
    bot_id: int


@app.post("/api/chats/{chat_id}/bots", status_code=201)
def add_bot(chat_id: int, body: ChatBot, user: DictRow = Depends(auth.current_user)) -> dict[str, bool]:
    with db.as_user(user["id"]) as tx:
        found(tx.row("SELECT 1 FROM ms.chats WHERE id = %s", (chat_id,)))
        tx.run(
            "INSERT INTO ms.chat_bots (chat_id, bot_id, added_by) VALUES (%s, %s, %s)",
            (chat_id, body.bot_id, user["id"]),
        )
    return {"ok": True}


@app.delete("/api/chats/{chat_id}/bots/{bot_id}", status_code=204)
def remove_bot(chat_id: int, bot_id: int, user: DictRow = Depends(auth.current_user)) -> None:
    with db.as_user(user["id"]) as tx:
        n = tx.run("DELETE FROM ms.chat_bots WHERE chat_id = %s AND bot_id = %s", (chat_id, bot_id))
        tx.authz.expect(n, "ms.chat_bots", "delete", (chat_id, bot_id))


# the bots' own API: signed in with their key; they see and post in the chats they were added to
@app.get("/api/bot/chats")
def bot_chats(key: str = Depends(auth.bot_key)) -> list[DictRow]:
    with db.as_bot(key) as tx:
        return tx.rows("SELECT id, kind, title, last_seq FROM ms.chats ORDER BY id")


@app.get("/api/bot/chats/{chat_id}/messages")
def bot_messages(chat_id: int, after: Annotated[Seq, Query()] = 0, key: str = Depends(auth.bot_key)) -> list[DictRow]:
    with db.as_bot(key) as tx:
        found(tx.row("SELECT 1 FROM ms.chats WHERE id = %s", (chat_id,)))
        return tx.rows(
            f"SELECT {MESSAGE_COLS} FROM ms.messages x LEFT JOIN ms.users u ON u.id = x.sender_id "
            f"LEFT JOIN ms.bots b ON b.id = x.bot_id WHERE x.chat_id = %s AND x.seq > %s ORDER BY x.seq LIMIT 200",
            (chat_id, after),
        )


@app.post("/api/bot/chats/{chat_id}/messages", status_code=201)
def bot_post(chat_id: int, body: NewMessage, key: str = Depends(auth.bot_key)) -> DictRow:
    with db.as_bot(key) as tx:
        found(tx.row("SELECT 1 FROM ms.chats WHERE id = %s", (chat_id,)))
        who = tx.authz.principal()  # ('bot', '3'): the database knows who the key is
        if who is None:
            raise HTTPException(401, "invalid API key")
        return tx.one(
            "INSERT INTO ms.messages AS x (chat_id, bot_id, body) VALUES (%s, %s, %s) RETURNING x.seq",
            (chat_id, int(who[1]), body.body),
        )


# --- live updates ------------------------------------------------------------------------------
@app.websocket("/api/events")
async def live(ws: WebSocket) -> None:
    """Sends {"chat": N} when chat N changes and you may read it (events.py); the web app refetches."""
    user = await asyncio.to_thread(auth.user_of, ws.cookies.get(auth.COOKIE))
    if user is None:
        await ws.close(code=4401)
        return
    await ws.accept()
    events.hub.add(ws, str(user["id"]))
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        events.hub.remove(ws)


# --- the web app ---------------------------------------------------------------------------------
WEB = Path(__file__).resolve().parents[2] / "frontend" / "dist"
if WEB.is_dir():
    app.mount("/assets", StaticFiles(directory=WEB / "assets"), name="assets")

    @app.get("/{path:path}", include_in_schema=False)
    def web(path: str) -> FileResponse:
        return FileResponse(WEB / "index.html")

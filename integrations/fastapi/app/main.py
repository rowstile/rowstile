"""The conformance app: no permission checks anywhere. rowstile signs each request's transactions in, the
database filters reads and refuses writes, and the SDK turns refusals into 403 and hidden rows into 404."""

import asyncio
import os

import rowstile
from fastapi import FastAPI, Request
from pydantic import BaseModel
from rowstile import NotFound, Principal
from rowstile import sqlalchemy as authz_sa
from rowstile.fastapi import Rowstile
from sqlalchemy import delete, func, select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from . import jobs, worker
from .auth import session_user
from .authz_client import ObjectType, Permission
from .models import Folder, Message, Note, Project

# the queries by permission, taking only the policy's names: a misspelled one doesn't type-check
queries = authz_sa.Queries[ObjectType, Permission]()


def signed_in() -> int:
    """The user the request acts for (Rowstile set it from session_user), as the tables' key."""
    who = rowstile.current()
    return int(who.id) if who is not None and who.id is not None else 0


def make_app(url: str | None = None, check_connection: bool = True, pool_size: int = 5) -> FastAPI:
    engine = create_async_engine(url or os.environ["ROWSTILE_APP_URL"], pool_size=pool_size, max_overflow=0)
    Session = async_sessionmaker(engine, expire_on_commit=False)
    app = FastAPI()
    app.state.engine, app.state.Session = engine, Session
    authz = Rowstile(app, engine, user=session_user, check_connection=check_connection)
    app.state.authz = authz

    @app.get("/projects")
    async def projects() -> list[int]:
        async with Session() as s:
            return sorted((await s.scalars(select(Project.id))).all())

    @app.get("/projects/editable")
    async def editable() -> list[int]:
        async with Session() as s:
            return sorted(
                (await s.scalars(select(Project.id).where(Project.id.in_(queries.ids("project", "edit"))))).all()
            )

    @app.get("/projects/buttons")
    async def buttons() -> dict[str, list[Permission]]:
        async with Session() as s:
            ids = (await s.scalars(select(Project.id))).all()
            return await queries.perms_of(s, "project", ids)

    @app.get("/projects/page")
    async def page(limit: int, after: str | None = None) -> list[str]:
        # the projects the user may see, a page at a time: the database says when the size or the cursor is wrong
        async with Session() as s:
            listed = text("SELECT x FROM authz.list('project', 'view', :after, :limit) x")
            return list((await s.scalars(listed, {"after": after, "limit": limit})).all())

    @app.delete("/keys/{key_id}", status_code=204)
    async def revoke_key(key_id: int) -> None:
        # one of the user's API keys: someone else's, or one that isn't there, is 404
        async with Session.begin() as s:
            await s.execute(text("SELECT 1 FROM authz.revoke_api_key(:id)"), {"id": key_id})

    class NewKey(BaseModel):
        name: str
        principal_type: str | None = None
        principal_id: str | None = None

    @app.post("/keys", status_code=201)
    async def create_key(k: NewKey, request: Request) -> dict[str, str]:
        # an API key, for the user or a principal whose keys they manage; a request that brings a key (x-api-key)
        # signs in with it first, in the same transaction: the database says who may make which
        async with Session.begin() as s:
            key = request.headers.get("x-api-key")
            if key is not None:
                await s.execute(text("SELECT authz.login_key(:key)"), {"key": key})
            made = text("SELECT authz.create_api_key(:name, '', NULL, CAST(:type AS text), CAST(:id AS text))")
            return {"key": str(await s.scalar(made, {"name": k.name, "type": k.principal_type, "id": k.principal_id}))}

    @app.get("/projects/{project_id}/shares")
    async def shares(project_id: int) -> list[str]:
        async with Session() as s:
            listed = text("SELECT subject_id FROM authz.list_shares('project', CAST(:id AS text))")
            return list((await s.scalars(listed, {"id": str(project_id)})).all())

    class Ask(BaseModel):
        relation: str
        reason: str

    @app.post("/projects/{project_id}/requests", status_code=201)
    async def ask(project_id: int, a: Ask) -> dict[str, int]:
        # access asked for: the policy shares no relation of a project, so this is the app's mistake (a 500), once
        # the database knows who asks
        async with Session.begin() as s:
            asked = text("SELECT authz.request_access('project', CAST(:p AS text), :relation, :reason)")
            params = {"p": str(project_id), "relation": a.relation, "reason": a.reason}
            return {"id": int((await s.execute(asked, params)).scalar_one())}

    @app.get("/notes/as/{user_id}")
    async def notes_as(user_id: int) -> list[int]:
        # who is signed in, changed by hand: the database doesn't believe it (the app's bug, a 500)
        async with Session() as s:
            await s.execute(text("SELECT set_config('authz.user_id', CAST(:u AS text), true)"), {"u": str(user_id)})
            return sorted((await s.scalars(select(Note.id))).all())

    class Move(BaseModel):
        parent_id: int | None

    @app.patch("/folders/{folder_id}")
    async def move_folder(folder_id: int, m: Move) -> dict[str, int]:
        async with Session.begin() as s:
            folder = await s.get(Folder, folder_id)
            if folder is None:
                raise NotFound("app.folders", folder_id)
            folder.parent_id = m.parent_id  # inside one of its own subfolders: 409, the database's words
        return {"id": folder_id}

    @app.get("/notes")
    async def notes() -> list[int]:
        async with Session() as s:
            return sorted((await s.scalars(select(Note.id))).all())

    class NewNote(BaseModel):
        project_id: int
        body: str

    @app.post("/notes", status_code=201)
    async def add_note(n: NewNote) -> dict[str, int]:
        async with Session.begin() as s:
            note = Note(project_id=n.project_id, author_id=signed_in(), body=n.body)
            s.add(note)
            await s.flush()
            return {"id": note.id}

    class Body(BaseModel):
        body: str

    @app.patch("/notes/{note_id}")
    async def edit_note(note_id: int, b: Body) -> dict[str, int]:
        async with Session.begin() as s:
            note = await s.get(Note, note_id)
            if note is None:
                raise NotFound("app.notes", note_id)
            note.body = b.body  # an update the rules may refuse: StaleDataError -> 403 with the reason
        return {"id": note_id}

    @app.delete("/notes/{note_id}", status_code=204)
    async def remove_note(note_id: int) -> None:
        async with Session.begin() as s:
            result = await s.execute(delete(Note).where(Note.id == note_id))
            await authz_sa.expect(s, result, "app.notes", "delete", note_id)

    class NewMessage(BaseModel):
        recipient_id: int
        body: str

    @app.post("/inbox", status_code=201)
    async def send(m: NewMessage) -> dict[str, int]:
        async with Session.begin() as s:
            msg = Message(sender_id=signed_in(), recipient_id=m.recipient_id, body=m.body)
            s.add(msg)
            await s.flush()  # reads the id back (RETURNING): only the recipient may read it
            return {"id": msg.id}

    @app.post("/inbox/quietly", status_code=202)
    async def send_quietly(m: NewMessage) -> dict[str, int]:
        # without reading the row back (SQLAlchemy's insert() would, with RETURNING, to learn the new id)
        async with Session.begin() as s:
            await s.execute(
                text("INSERT INTO app.inbox (sender_id, recipient_id, body) VALUES (:s, :r, :b)"),
                {"s": signed_in(), "r": m.recipient_id, "b": m.body},
            )
        return {}

    # background jobs, on Celery's queue and RQ's: the ids of the two, which a worker process runs
    @app.post("/jobs/digest", status_code=202)
    async def start_digest() -> dict[str, str]:
        started = [worker.digest.delay(), worker.digest_async.delay()]
        queued = [worker.queue.enqueue(jobs.digest), worker.queue.enqueue(jobs.digest_async)]
        return {"celery": started[0].id, "celery_async": started[1].id, "rq": queued[0].id, "rq_async": queued[1].id}

    @app.post("/jobs/notes", status_code=202)
    async def add_note_later(n: NewNote) -> dict[str, str]:
        # who asked goes with the job, as text: the job acts for them
        asked_by = str(rowstile.current())
        task = worker.add_note.delay(asked_by, n.project_id, n.body)
        job = worker.queue.enqueue(jobs.add_note, asked_by, n.project_id, n.body)
        return {"celery": task.id, "rq": job.id}

    @app.patch("/jobs/notes/{note_id}", status_code=202)
    async def edit_note_later(note_id: int, b: Body) -> dict[str, str]:
        asked_by = str(rowstile.current())
        task = worker.edit_note.delay(asked_by, note_id, b.body)
        return {"celery": task.id, "rq": worker.queue.enqueue(jobs.edit_note, asked_by, note_id, b.body).id}

    @app.delete("/jobs/notes/{note_id}", status_code=202)
    async def remove_note_later(note_id: int) -> dict[str, str]:
        asked_by = str(rowstile.current())
        task = worker.remove_note.delay(asked_by, note_id)
        return {"celery": task.id, "rq": worker.queue.enqueue(jobs.remove_note, asked_by, note_id).id}

    @app.get("/jobs/celery/{task_id}")
    async def celery_result(task_id: str) -> dict[str, int | None]:
        # what the job returned; one the database refused raises its Refused or NotFound here: 403 or 404
        done = worker.celery.AsyncResult(task_id)
        return {"result": await asyncio.to_thread(done.get, timeout=60)}

    return app


@rowstile.job(("service", 1))
async def digest(Session: async_sessionmaker[AsyncSession]) -> tuple[int, Principal | None]:
    """A background job: it signs in as service 1, whatever request started it."""
    async with Session() as s:
        return (await s.scalar(select(func.count()).select_from(Project))) or 0, rowstile.current()

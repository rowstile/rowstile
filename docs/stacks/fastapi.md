# FastAPI, SQLAlchemy and Alembic

<!-- tested: every line of code below is in integrations/fastapi (tests/unit_test.py checks it) -->

A FastAPI app on SQLAlchemy (async, asyncpg) whose migrations are Alembic's. The routes check nothing: each
request's transactions sign in as its user, the database filters what they read and refuses what they may
not write, and the SDK answers a refusal with 403 and a hidden row with 404.

Everything here comes from [`integrations/fastapi`](../../integrations/fastapi), the conformance suite: a small app and the checks every
supported stack passes ([`integrations/fastapi/test.sh`](../../integrations/fastapi/test.sh)).

To start from an app that runs instead of from this page: the
[FastAPI starter](https://github.com/rowstile/starter-fastapi), a template repository. `docker compose up`, and
documents are shared with people and teams, with the policy, its tests and the review in CI already there.

## Install

```sh
# while only pre-releases are published: `>=0.1.0a0` lets uv take rowstile's, and no other package's pre-release
uv add "rowstile[fastapi,sqlalchemy,asyncpg,psycopg]>=0.1.0a0"
uv run rowstile init        # once your migrations made the tables: a first policy from them, a test file, rowstile.toml
```

asyncpg is the app's driver and psycopg is Alembic's ([Migrations](#migrations) says why). `init` reads the
tables, so it needs the database: `DATABASE_URL`, or `--db`. The command reads the variable from the
environment, or from a `.env` in the project's folder.

`init` finds FastAPI and Alembic, and writes `rowstile.toml` for them. The conformance app's, with its own
name for the variable that holds the owner's connection and for the client:

```toml
policy   = "db/policy.authz"
tests    = ["db/tests/*.authz"]
database = "env:ROWSTILE_OWNER_DSN"
[clients]
py = "app/authz_client.py"
[migrations]
tool = "alembic"
dir  = "migrations/versions"
```

Two roles connect. The owner of the tables runs the migrations (`ROWSTILE_OWNER_DSN` for the command, and
the same as an SQLAlchemy URL, `ROWSTILE_OWNER_URL`, for Alembic), and the app connects
as the role the policy names (`app role conf_app`), which row-level security applies to (`ROWSTILE_APP_URL`).
The owner must be able to switch to the app role, since the command looks at the data as the app does when it
runs the policy's tests: `GRANT conf_app TO conf_owner`, once, by whoever made the app role.

## The policy

```authz
app role conf_app

type user = app.users

type service = app.services principal

type project = app.projects
  owner   : user    = owner_id
  member  : user    = app.members(project_id -> user_id)
  service : service = app.project_services(project_id -> service_id)

  can edit = owner or member
  can view = edit or service or {public}

type note = app.notes
  project : project = project_id
  author  : user    = author_id

  can edit = author or project.owner
  can view = project.view

rules app.notes
  select : view
  insert : project.edit and author
  update : edit
  delete : edit
```

## The app

`Rowstile` signs in every transaction the engine begins, as whoever `user` returns for the request (`None`:
nobody, who sees only what `anyone` may). It also refuses to start on a connection that skips row-level
security, whether or not the app has a `lifespan` of its own.

`user(request)` runs in a middleware that `Rowstile(...)` adds: read the session or the token from the request
itself. What a middleware of yours puts on `request.state` is there only if that middleware was added after
`Rowstile(...)` (Starlette runs the one added last first). It may raise an `HTTPException` (a 401 for a bad
token). WebSockets are not signed in: use `rowstile.acting_as()` in the endpoint.

Here `user` is `session_user`, from the app's own `auth.py`: yours reads your session cookie or token. The
conformance app has no sign-in, so its `auth.py` stands in for one: it takes the user from a header its checks
set, which a real app must never believe. That is why this page doesn't show it.

```python
# app/main.py
import os

import rowstile
from fastapi import FastAPI, Request
from rowstile import NotFound, Principal
from rowstile import sqlalchemy as authz_sa
from rowstile.fastapi import Rowstile
from sqlalchemy import delete, func, select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from .auth import session_user


def make_app(url: str | None = None, check_connection: bool = True, pool_size: int = 5) -> FastAPI:
    engine = create_async_engine(url or os.environ["ROWSTILE_APP_URL"], pool_size=pool_size, max_overflow=0)
    Session = async_sessionmaker(engine, expire_on_commit=False)
    app = FastAPI()
    authz = Rowstile(app, engine, user=session_user, check_connection=check_connection)
```

Then routes are plain SQLAlchemy. A list shows only the user's rows:

```python
    @app.get("/notes")
    async def notes() -> list[int]:
        async with Session() as s:
            return sorted((await s.scalars(select(Note.id))).all())
```

An update the rules refuse makes SQLAlchemy raise `StaleDataError` (0 rows changed). The SDK asks the
database why and answers 403 with the rule and the reason, or 404 when the user can't see the row:

```python
    @app.patch("/notes/{note_id}")
    async def edit_note(note_id: int, b: Body) -> dict[str, int]:
        async with Session.begin() as s:
            note = await s.get(Note, note_id)
            if note is None:
                raise NotFound("app.notes", note_id)
            note.body = b.body          # an update the rules may refuse: StaleDataError -> 403 with the reason
        return {"id": note_id}
```

The SDK asks before the flush's transaction is rolled back, in it and as the same user, so it sees the rows that
transaction wrote, and needs no other connection from the pool. A flush of several rows is asked about in one
statement: the answer is about the first one the database says no for. When the rules allow every row, the row
changed since it was read (a version counter, `version_id_col`), and the answer is 409. A Core `delete()` or
`update()` reports 0 rows without an error; `expect` turns that into the same
answers (404 too when the user may change the row and the statement matched nothing for another reason, such
as a `where` with more than the key):

```python
            result = await s.execute(delete(Note).where(Note.id == note_id))
            await authz_sa.expect(s, result, "app.notes", "delete", note_id)
```

An ORM delete (`await s.delete(note)`) the rules refuse is not an error in SQLAlchemy, unless the model has a
version column: it only warns, `SAWarning: DELETE statement on table 'notes' expected to delete 1 row(s); 0
were matched`. The row stays, and the request answers as if it was deleted. Delete with `delete()` and
`expect`, as above. To see such a delete in your tests, make the warning an error: in pytest's settings,
`filterwarnings = ["error::sqlalchemy.exc.SAWarning"]`.

An insert that reads the new row back (`flush()` uses `RETURNING`) also needs the select rule: if the user may
insert but not read the row, the 403 names the select rule.

A call the database says names something that isn't there answers 404 (an API key of the user's that isn't
there, a share with someone who doesn't exist), and one it says lacks an argument or has a wrong one 400, each
with the database's words (a negative page size: "the page size must not be negative (got -1)"):

```python
    @app.get("/projects/page")
    async def page(limit: int, after: str | None = None) -> list[str]:
        # the projects the user may see, a page at a time: the database says when the size or the cursor is wrong
        async with Session() as s:
            listed = text("SELECT x FROM authz.list('project', 'view', :after, :limit) x")
            return list((await s.scalars(listed, {"after": after, "limit": limit})).all())
```

A call that needs someone signed in, from a visitor who isn't (an access request, an API key), answers 401, and
so does a login with a key or a token the database refuses; a folder moved into one of its own subfolders
answers 409. Each code's page says what its answer is (`rowstile help AZ714`).

## Lists by permission

`ids(type, perm)` filters a query to the objects the user holds a permission on; `perms_of` answers a list's
buttons in one call. `Queries` has them taking only the policy's names, from the generated client, so a
misspelled type or permission doesn't type-check:

```python
from rowstile import sqlalchemy as authz_sa
from .authz_client import ObjectType, Permission
queries = authz_sa.Queries[ObjectType, Permission]()

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
```

The same functions are in the module itself (`authz_sa.ids`, `authz_sa.perms_of`, `authz_sa.can`), taking any
string.

## Background jobs

A job acts for a principal of its own, whatever request started it (`type service = app.services principal`
in the policy):

```python
@rowstile.job(("service", 1))
async def digest(Session: async_sessionmaker[AsyncSession]) -> tuple[int, Principal | None]:
    """A background job: it signs in as service 1, whatever request started it."""
```

Anywhere else, `with rowstile.acting_as(2):` signs in the transactions begun inside it. A transaction is one
principal's: inside one begun for someone else, its statements raise a `RuntimeError` before they are sent ([Who a
transaction acts for](python.md#who-a-transaction-acts-for)). Jobs in Celery's worker or RQ's, and a job for the
user who asked: [Background jobs](python.md#background-jobs-celery-and-rq-preview) (preview).

## Migrations

The policy ships as Alembic revisions. `rowstile migrate` writes the next one (only what changed since
`db/policy.lock`); `alembic upgrade head` applies it with the others. Tell autogenerate to leave rowstile's
objects alone, so `alembic check` shows no change:

```python
from rowstile.alembic import include_name, include_object

    context.configure(
        connection=connection,
        target_metadata=Base.metadata,
        include_schemas=True,
        include_name=include_name,
        include_object=include_object,
    )
```

A model of a masked view (the view a `mask` reads through) says so with `info={"rowstile": True}` on its table
(`__table_args__`). Otherwise autogenerate sees no table for it, and adds one.

Alembic connects as the owner, with a sync driver: `ROWSTILE_OWNER_URL` is a `postgresql+psycopg://` URL.
A policy's revision is one script of many statements, and asyncpg takes one statement at a time ("cannot
insert multiple commands into a prepared statement"); the revision checks, and says so in a line. The app
itself stays on asyncpg.

```python
engine = create_engine(os.environ["ROWSTILE_OWNER_URL"])
```

```sh
uv run rowstile migrate            # after changing the policy
uv run alembic upgrade head
uv run rowstile migrate --check    # in CI: exit 1 if a policy change has no migration
```

While you edit, `rowstile dev` checks, pushes to the development database, runs the tests and rewrites
`app/authz_client.py` on every save (and writes the migration once you stop editing).

The development database then holds what `dev` pushed, not what its migrations left. The first migration,
the whole policy, applies over that; a later one stops there with AZ607, "this database already holds what
this migration brings" (`alembic upgrade head` prints it far above the bottom of its output). Production
and CI only ever take migrations. On the development database, `alembic stamp head` then brings Alembic's
history level, as the message asks; or rebuild it from the migrations.

## Tests

The policy's own tests run with `rowstile test`. In pytest, sign in the way the app does:

```python
        with rowstile.acting_as(2), Session(engine) as s:
            assert sorted(s.scalars(select(Note.id)).all()) == [2, 3]
```

`database_per_worker(owner_url)` copies the migrated test database once for each pytest-xdist worker, so tests
that write don't meet each other (a run without workers has one copy):

```python
# tests/conftest.py
import os

import pytest
from rowstile.testing import WorkerDatabase, database_per_worker

@pytest.fixture(scope="session")
def worker_database() -> WorkerDatabase:
    return database_per_worker(os.environ["ROWSTILE_TESTS_URL"], app_url=os.environ["ROWSTILE_APP_URL"])
```

It returns the copy's URL, and the app role's for it. The copy needs nobody connected to the original; where the
service keeps a connection (Neon does, for minutes after one), it says so and what to use instead ([Managed
Postgres](../managed-postgres.md)).

## Users and groups from an identity provider (SCIM)

An identity provider (Okta, Microsoft Entra ID) can write its directory's users and groups to the app. It sends
SCIM requests, and the database answers them
([Identity](../reference/identity.md#users-and-groups-from-an-identity-provider-scim) has all of it). The app
mounts the route, on the object `Rowstile(...)` gave:

```python
    # an identity provider's users and groups (SCIM: Okta, Microsoft Entra ID): the database answers each request
    authz.mount_scim("/scim/v2")
```

The route passes each request on and answers what the database says. The bearer token alone says who asks:
`user(request)` isn't asked about a request under the mount, and its transaction signs nobody in, whatever
session the request also carries. An error (settings that no longer hold, your function failing) is answered 500
in SCIM's words and logged by the `rowstile` logger. The route reads a request's whole body before the database
looks at the key, as any route that reads JSON does: how large a body may be is the server in front's to cap.

Users are rows of your table, with columns rowstile doesn't know, so a function of yours makes and changes them.
Here the users' table has three columns for what a provider says: an email, whether the user is active, and the
user as the provider wrote it, which the endpoint answers when the provider reads the user back.

```python
# app/models.py
class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    name: Mapped[str] = mapped_column(Text)
    # what an identity provider says of a user (SCIM): app.scim_user writes them
    email: Mapped[str | None] = mapped_column(Text)
    active: Mapped[bool] = mapped_column(Boolean, server_default=true())
    scim: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
```

The function is a migration of the app's, which the owner runs: the database calls it with the owner's rights, so
it must be the owner's own. It never gets a password. A request may say less of a user than the app has (a PUT
without an email, a PATCH of a user the provider never wrote), so it keeps what the request says nothing of:

```python
# migrations/versions/0002_scim_user.py
def upgrade() -> None:
    # p_id NULL: a user to make; p_resource NULL: one to delete; else one to change. It answers the user's key.
    # rowstile calls it as the tables' owner, whose own it is: the app role has no right to write app.users
    op.execute("""CREATE FUNCTION app.scim_user(p_id text, p_resource jsonb) RETURNS text LANGUAGE plpgsql AS $f$
    DECLARE v_id text;
    BEGIN
      IF p_resource IS NULL THEN
        DELETE FROM app.users WHERE id = p_id::bigint;
        RETURN p_id;
      ELSIF p_id IS NULL THEN
        INSERT INTO app.users (name, email, active, scim)
        VALUES (p_resource->>'userName', p_resource#>>'{emails,0,value}',
                coalesce((p_resource->>'active')::boolean, true), p_resource)
        RETURNING id::text INTO v_id;
      ELSE
        -- a user changed: what the provider says nothing of stays as the app had it
        UPDATE app.users SET name = p_resource->>'userName', scim = p_resource,
          email = coalesce(p_resource#>>'{emails,0,value}', email),
          active = coalesce((p_resource->>'active')::boolean, active)
        WHERE id = p_id::bigint RETURNING id::text INTO v_id;
      END IF;
      RETURN v_id;
    END $f$""")
```

Then the owner says what the endpoint reads, once, in psql or in a migration after the policy's own
(`authz.set_scim` comes with the policy). The call replaces the stored settings, and each is checked as it is
set:

```sql
SELECT authz.set_scim('{
  "principal": "user:9",
  "group": "project.member", "group_name": "name",
  "user_name": "name", "user_active": "active", "user_resource": "scim",
  "user_function": "app.scim_user"
}');
```

- `principal` is whose API key signs the provider in. Here it is user 9, a user the app holds for the provider
  and nobody signs in as; a row of a type that signs in (this app's `service`) does as well. The row is there
  before the settings name it.
- `group` is what the provider's groups are in the policy: here a project's members, so a group's PATCH writes
  `app.members` as `authz.sync_members` would, with its line in the audit trail, and the policy follows at once.
  With no `group_function` the provider finds the projects the app has by their name, and can't make one.
- The `user_` settings name the users' columns and the function above.

The provider's bearer token is an API key of that principal, made once:

```sql
BEGIN;
SELECT authz.act_as('user', '9');
SELECT authz.create_api_key('the identity provider');   -- shown this once: the provider's bearer token
COMMIT;
```

Give the provider the route's address (`https://app.example/scim/v2`) and that key. A user the provider
deactivates stays, with `active` false: what such a user may do is the policy's to say, and
`type user = app.users where {active}` makes one nobody. `rowstile lint` says when a setting no longer holds (a
column renamed, the function gone): a request that meets it is an error, the 500 above.

## Other drivers

The sync engine (and SQLModel, built on it) takes `install(engine)`. psycopg and asyncpg without SQLAlchemy:
[Python apps](python.md). With FastAPI, such an app passes no engine, `Rowstile(app, None, user=...)`, and its
drivers' errors get the same answers: 403 for a refused write, and each code's own. There is no engine to check
at start-up: `rowstile.psycopg.problems(conn)` or `rowstile.asyncpg.problems(conn)` does it. Such an app needs no
SQLAlchemy: install `fastapi` and `rowstile[psycopg]` (or `[asyncpg]`), as the `fastapi` extra brings SQLAlchemy's
async engine.

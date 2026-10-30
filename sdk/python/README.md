# rowstile for Python

`pip install --pre rowstile` (`--pre`: the newest pre-release) installs the `rowstile` command (`rowstile init`, `dev`, `migrate`, `review`; also
`python -m rowstile`) and the SDK for Python apps. Extras bring the integrations' dependencies:
`rowstile[fastapi]`, `[sqlalchemy]`, `[psycopg]`, `[asyncpg]`, `[django]` (a preview: it may change in any
release). Python 3.11 or newer.

The SDK for Python apps on a rowstile policy: every transaction signs in as whoever the request or
the job acts for, refused writes become a 403 with the database's reason, rows the user can't see a 404,
and the app refuses to start on a connection that skips row-level security. It holds no rowstile logic: it
calls the `authz.*` functions the policy made, and translates their answers.

```python
from fastapi import FastAPI
from sqlalchemy.ext.asyncio import create_async_engine
from rowstile.fastapi import Rowstile

engine = create_async_engine("postgresql+asyncpg://app@db/app")
app = FastAPI()
Rowstile(app, engine, user=current_user)     # current_user(request): its user's id, or None; before adding routes
```

| module | what |
|---|---|
| `rowstile` | `acting_as(who)`, `job(who)` (a decorator, or a `with` block for the user a job's argument names; inside it the database's refusals are raised as `Refused` and `NotFound`, which pickle and Celery's results give back whole: preview, for Celery's and RQ's workers), `Principal`, `Refused`, `NotFound`, `refusal(exc)`, `error_code(exc)` (rowstile's code for any database error: `AZ709`), `not_signed_in(exc)` (whether it is the not-signed-in error, AZ701: a query in a transaction nobody signed in to; a login refused, AZ703, and settings changed by hand, AZ702, have its SQLSTATE, 28000, but are not it), `verdict(table, command, key, lines, who, named)` (what each driver's `expect()` raises for an update or delete that changed nothing, from `authz.explain_rule`'s answer; `named` is the table as the policy names it, `public.notes` for a model that says `notes`, so the refusal names it as a refused insert does), `act_as_sql()` |
| `rowstile.fastapi` | `Rowstile(app, engine, user=...)`: the request's principal, 403/404 problem bodies (and 404 for what a call names that isn't there, 400 for a missing or wrong argument, 401 for a call that needs someone signed in or a login refused, 409 for a move inside itself, and for an ORM update the rules allow of a row that changed since it was read), the start-up check; on psycopg or asyncpg without SQLAlchemy, `Rowstile(app, None, user=...)` |
| `rowstile.sqlalchemy` | `install(engine)` (sync or async; SQLModel too; one principal a transaction: a statement in it while the code acts for anyone else is a `RuntimeError`), `ids(type, perm)` for `where`, `perms_of()` for a list's buttons, `can()` (`Queries[ObjectType, Permission]()` has the three taking only the generated client's names, so a misspelled one doesn't type-check), `expect()` for Core updates and deletes, `why_stale()` for the ORM's StaleDataError |
| `rowstile.psycopg` | `transaction(conn, who)`, `atransaction(aconn, who)` (one principal a transaction: inside a block, one for the same principal is a savepoint, one for anyone else a `RuntimeError`), `expect()`, `aexpect()` |
| `rowstile.asyncpg` | `transaction(conn, who)` (as psycopg's), `expect()` |
| `rowstile.django` | a preview: it may change in any release. `"rowstile.django"` in `INSTALLED_APPS` (every transaction on Django's Postgres connections signs in as whoever the code acts for: an atomic block when it begins, a query outside one in a transaction of its own; psycopg 3), `Middleware` (each request acts for `ROWSTILE_USER(request)`, else `request.user`; 403/404 problem bodies and each code's answer, as `rowstile.fastapi`'s; the start-up check of `ROWSTILE_CHECK_DATABASES`), `save(instance)` (an update, never Django's insert after a refused one: `NotFound` or `Refused`), `expect()` for a queryset's `update()` and `delete()`, `ids()`, `can()`, `perms_of()`, `Queries[ObjectType, Permission]()`, `check()`; `rowstile.django.testing.database_per_worker(url)` for pytest-django's `django_db_setup` |
| `rowstile.alembic` | `include_name`, `include_object`: autogenerate leaves rowstile's objects alone, and a model of a masked view that says so (`info={"rowstile": True}` on its table) |
| `rowstile.testing` | pytest fixtures, loaded once the package is installed: `as_user`, `assert_refused`, `assert_not_found` (awaited, with an async function: a test that never awaits it fails), `authz_owner_url`, `authz_app_url`; `database_per_worker(url)`: a copy of the migrated test database for each pytest-xdist worker |

Who a transaction acts for: `42` or `"42"` (a user), `("service", 3)` (another principal type of the policy),
or `None` (nobody: only what `anyone` may see; `None` given to a call is nobody too, whoever the code around
it acts for). A plain id is always a user's, whatever it holds: `"service:3"` is the user with that id, so an
id from outside (a username, an identity provider's subject) can't name a service. `Principal.parse(text)`
reads back what `str()` wrote, for text your own code wrote (a job's argument): `str()` writes a user
whose id holds `:` or is `nobody` as `user:<id>` (`user:service:3`), so every principal reads back as itself.
The audit trail and `created_by` name who acted the same way, so `Principal.parse` reads them too. Every transaction signs in, even when nobody is signed in, and nothing
uses a session-level `SET`, so pools and poolers in transaction mode are safe; behind one that keeps no prepared
statements, turn the driver's off ([Behind a pooler](../../docs/operations.md#behind-a-pooler)).

With FastAPI: `user(request)` runs in a middleware that `Rowstile(...)` adds, so give it the session or the
token to read from the request itself. What a middleware of yours puts on `request.state` is there only if
that middleware was added after `Rowstile(...)` (Starlette runs the one added last first); added before, it
hasn't run yet. `user` may raise an `HTTPException`. The start-up check runs whether or not the app has a `lifespan`. WebSockets
are not signed in: use `rowstile.acting_as()` in the endpoint. An engine in `AUTOCOMMIT` can't be signed in
(the sign-in lasts a transaction): its queries fail with `NotSignedIn`.

Policy changes ship as migrations for your tool (`rowstile migrate`, with `tool = "alembic"` in
`rowstile.toml`). The types and permissions of your policy are generated names (`rowstile client py`), so a
misspelled permission doesn't type-check.

`integrations/fastapi/` is the conformance suite: a small FastAPI app on SQLAlchemy (async, asyncpg) and
Alembic, and the checks every supported stack passes (`integrations/fastapi/test.sh`). `integrations/django/` is
the Django module's: a small Django app on psycopg 3, Django's migrations and pytest-django
([Django](../../docs/stacks/django.md)).

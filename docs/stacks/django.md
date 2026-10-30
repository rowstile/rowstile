# Django

<!-- tested: every line of code below is in integrations/django (tests/unit_test.py checks it) -->

**Preview.** The Django integration may change in any release, and is not part of what 1.0 will promise. It
passes the same checks as the other stacks; tell us what doesn't fit your app.

A Django app (5.2 or newer) on psycopg 3, whose migrations are Django's. The views check nothing: every
transaction signs in as the request's user, the database filters what it reads and refuses what it may not
write, and the SDK answers a refusal with 403 and a hidden row with 404.

Everything here comes from `integrations/django`, the conformance suite: a small app and the checks every
supported stack passes (`integrations/django/test.sh`).

## Install

```sh
# while only pre-releases are published: `>=0.1.0a0` lets uv take rowstile's, and no other package's pre-release
uv add "rowstile[django]>=0.1.0a0"
```

The `django` extra brings Django and psycopg 3 (Django's pool, `OPTIONS["pool"]`, also wants `psycopg-pool`).
`rowstile init` doesn't know Django's folders yet: write `rowstile.toml` yourself. The conformance app's:

```toml
policy   = "db/policy.authz"
tests    = ["db/tests/*.authz"]
database = "env:ROWSTILE_OWNER_DSN"
[clients]
py = "app/authz_client.py"
[migrations]
tool = "django"
dir  = "app/migrations"
```

`dir` is the migrations folder of the app that owns the tables (`<app>/migrations`). Two roles connect. The
owner of the tables runs `manage.py migrate` and the command (`ROWSTILE_OWNER_DSN`), and the app connects as the
role the policy names (`app role conf_app`), which row-level security applies to. The conformance app reads one
URL, `DATABASE_URL`, and is given the owner's when it migrates. The owner must be able to switch to the app role,
since the command looks at the data as the app does when it runs the policy's tests: `GRANT conf_app TO
conf_owner`, once, by whoever made the app role.

## The policy

Django keeps its tables in `public`, so the policy names them there:

```authz
app role conf_app

type user = public.users

type service = public.services principal

type project = public.projects
  owner   : user    = owner_id
  member  : user    = public.members(project_id -> user_id)
  service : service = public.project_services(project_id -> service_id)

  can edit = owner or member
  can view = edit or service or {public}

type note = public.notes
  project : project = project_id
  author  : user    = author_id

  can edit = author or project.owner
  can view = project.view

rules public.notes
  select : view
  insert : project.edit and author
  update : edit
  delete : edit
```

## Settings

`rowstile.django` in `INSTALLED_APPS` signs in every transaction on Django's Postgres connections, as whoever
the code acts for; the middleware says who that is for each request. `ROWSTILE_USER` is a function of the request
(or its dotted path) that gives its user's id, `("service", 3)`, or `None` for nobody. Left out, it is
`request.user`: the user's key when signed in, nobody when not (put the middleware after Django's
`AuthenticationMiddleware`). Here it is the app's own `session_user`, which a real app writes over its session or
token; the conformance app's stands in for a sign-in, so this page doesn't show it.

```python
INSTALLED_APPS = ["rowstile.django", "app"]
MIDDLEWARE = ["rowstile.django.Middleware"]
# who a request is: the app's own sign-in (a real app's reads its session; Django's request.user is the default)
ROWSTILE_USER = "app.auth.session_user"
```

An atomic block signs in when its transaction begins, whether `ATOMIC_REQUESTS` is on or not, and a query
outside one, which Django runs as a transaction of its own, signs in too. The sign-in lasts the transaction, so a
persistent connection (`CONN_MAX_AGE`) or one from Django's pool (`OPTIONS["pool"]`) carries no one into the next
request. Async views and the async ORM sign in the same way.

A transaction is one principal's. One that no one has signed in to yet signs in at its first statement while the
code acts for someone, and is theirs from then on: inside it, a statement while the code acts for someone else, or
for no one, raises a `RuntimeError` before it is sent, and the transaction goes on as its principal's. Run that
work after the transaction, or in one of its own on another connection.

Code that acts for no one signs nothing in: `manage.py migrate` as the owner, a management command, the shell. A
query on a table with rules then fails with AZ701, saying how (`with rowstile.acting_as(...)`, or a job). A
streaming response, made as it is sent after the view has returned, acts for the request's user all the same.

The middleware also refuses to start on a connection that skips row-level security (the owner, a superuser,
`BYPASSRLS`): a WSGI or ASGI worker on one doesn't load. `ROWSTILE_CHECK_DATABASES` names the aliases it checks
(`["default"]` if left out).

## The views

Views are plain Django. A list shows only the user's rows:

```python
def notes(request: HttpRequest) -> JsonResponse:
    if request.method == "POST":
        return add_note(request)
    return JsonResponse(sorted(Note.objects.values_list("id", flat=True)), safe=False)
```

An update the rules refuse changes 0 rows, and Django's own `save()` then tries an INSERT, which a refused
update must not become. `rowstile.django.save()` updates and never inserts: it asks the database why nothing
changed, in the same transaction, and answers 403 with the rule and the reason, or 404 when the user can't see
the row:

```python
from rowstile import NotFound, Principal
from rowstile import django as authz_dj

def edit_note(request: HttpRequest, note_id: int) -> JsonResponse:
    note = Note.objects.filter(pk=note_id).first()
    if note is None:
        raise NotFound("public.notes", note_id)
    note.body = str(body(request)["body"])
    authz_dj.save(note, update_fields=["body"])  # an update the rules may refuse: 403 with the reason
    return JsonResponse({"id": note_id})
```

A queryset's `update()` and `delete()` report 0 rows without an error; `expect` turns that into the same answers
(404 too when the user may change the row and the statement matched nothing for another reason, such as a filter
with more than the key):

```python
    authz_dj.expect(Note.objects.filter(pk=note_id).delete(), Note, "delete", note_id)
```

An insert that reads the new row back (`create()` uses `RETURNING`) also needs the select rule: if the user may
insert but not read the row, the 403 names the select rule.

A call the database says names something that isn't there answers 404 (an API key of the user's that isn't
there), one it says lacks an argument or has a wrong one 400, one that needs someone signed in or a login it
refuses 401, and a folder moved into one of its own subfolders 409, each with the database's words. Each code's
page says what its answer is (`rowstile help AZ714`).

```python
def page(request: HttpRequest) -> JsonResponse:
    # the projects the user may see, a page at a time: the database says when the size or the cursor is wrong
    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT x FROM authz.list('project', 'view', %s, %s) x",
            [request.GET.get("after"), int(request.GET["limit"])],
        )
        return JsonResponse([r[0] for r in cursor.fetchall()], safe=False)
```

## Lists by permission

`ids(type, perm)` filters a queryset to the objects the user holds a permission on; `perms_of` answers a list's
buttons in one call. `Queries` has them taking only the policy's names, from the generated client, so a
misspelled type or permission doesn't type-check:

```python
from .authz_client import ObjectType, Permission
queries = authz_dj.Queries[ObjectType, Permission]()

def editable(request: HttpRequest) -> JsonResponse:
    return JsonResponse(
        sorted(Project.objects.filter(id__in=queries.ids("project", "edit")).values_list("id", flat=True)),
        safe=False,
    )

def buttons(request: HttpRequest) -> JsonResponse:
    return JsonResponse(queries.perms_of("project", Project.objects.values_list("id", flat=True)))
```

The same functions are in the module itself (`authz_dj.ids`, `authz_dj.perms_of`, `authz_dj.can`), taking any
string.

## Background jobs

A job acts for a principal of its own, whatever request started it (`type service = public.services principal`
in the policy). With Celery or RQ, put it under the task's decorator:

```python
import rowstile

@rowstile.job(("service", 1))
def digest() -> tuple[int, Principal | None]:
    """A background job: it signs in as service 1, whatever request started it."""
    return Project.objects.count(), rowstile.current()
```

Anywhere else, `with rowstile.acting_as(2):` signs in the transactions inside it. A thread the request starts
doesn't carry its user: name who it acts for there too.

## Migrations

The policy ships as one of the app's migrations. `rowstile migrate` writes the next one after the app's latest
(only what changed since `db/policy.lock`): a `RunSQL` whose SQL is in the file beside it. `manage.py migrate`
applies it with the others, as the owner. Django's own diff shows no change after it (`makemigrations --check`).
Undoing it is refused, in a line: rowstile's migrations go forward only, so change the policy back and write the
next one.

```sh
uv run rowstile migrate                                  # after changing the policy
DATABASE_URL=$OWNER_URL uv run python manage.py migrate  # as the tables' owner
uv run rowstile migrate --check                          # in CI: exit 1 if a policy change has no migration
```

While you edit, `rowstile dev` checks, pushes to the development database, runs the tests and rewrites
`app/authz_client.py` on every save (and writes the migration once you stop editing). The development database
then holds what `dev` pushed: a later migration stops there with AZ607, "this database already holds what this
migration brings"; `manage.py migrate app --fake` then brings Django's record level, or rebuild the database from
the migrations.

## Tests

The policy's own tests run with `rowstile test`. With pytest-django, the test database has the policy: migrate it
once as the owner, and each pytest-xdist worker gets a copy of its own, which Django's connection then uses as
the app role. Tests sign in as the app does:

```python
# tests/conftest.py
import os

import pytest
from rowstile.django.testing import WorkerDatabase, database_per_worker

@pytest.fixture(scope="session")
def django_db_setup() -> WorkerDatabase:
    return database_per_worker(os.environ["ROWSTILE_TESTS_URL"])
```

`ROWSTILE_TESTS_URL` is the owner's URL to the migrated test database. `@pytest.mark.django_db` works as usual
(each test in a transaction rolled back after), and so do the SDK's fixtures: `as_user`, `assert_refused`,
`assert_not_found` ([Python apps](python.md)). Inside the test's transaction, what the app runs goes as it would
without it: each statement signs in as whoever the code acts for then, so a test may act for one user, then for
another, by requests or with `rowstile.acting_as`. An atomic block the app begins there is one principal's, as a
transaction is outside tests: another's statement inside it raises the `RuntimeError`, and once the block ends, the
next statement signs in as whoever the code acts for again.

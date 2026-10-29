"""The conformance app: no permission checks anywhere. rowstile signs each request's transactions in, the
database filters reads and refuses writes, and the SDK turns refusals into 403 and hidden rows into 404."""

import json
from collections.abc import AsyncIterator, Iterator

import rowstile
from django.db import connection, transaction
from django.http import HttpRequest, HttpResponse, JsonResponse, StreamingHttpResponse
from django.urls import path
from rowstile import NotFound, Principal
from rowstile import django as authz_dj

from .authz_client import ObjectType, Permission
from .models import Folder, Message, Note, Project

# the queries by permission, taking only the policy's names: a misspelled one doesn't type-check
queries = authz_dj.Queries[ObjectType, Permission]()


def signed_in() -> int:
    """The user the request acts for (the middleware set it from session_user), as the tables' key."""
    who = rowstile.current()
    return int(who.id) if who is not None and who.id is not None else 0


def body(request: HttpRequest) -> dict[str, object]:
    sent = json.loads(request.body or b"{}")
    return sent if isinstance(sent, dict) else {}


def number(value: object) -> int:
    if isinstance(value, int):
        return value
    raise ValueError(f"expected a number, got {value!r}")


def text(value: object) -> str | None:
    return None if value is None else str(value)


def projects(request: HttpRequest) -> JsonResponse:
    return JsonResponse(sorted(Project.objects.values_list("id", flat=True)), safe=False)


def editable(request: HttpRequest) -> JsonResponse:
    return JsonResponse(
        sorted(Project.objects.filter(id__in=queries.ids("project", "edit")).values_list("id", flat=True)),
        safe=False,
    )


def buttons(request: HttpRequest) -> JsonResponse:
    return JsonResponse(queries.perms_of("project", Project.objects.values_list("id", flat=True)))


def page(request: HttpRequest) -> JsonResponse:
    # the projects the user may see, a page at a time: the database says when the size or the cursor is wrong
    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT x FROM authz.list('project', 'view', %s, %s) x",
            [request.GET.get("after"), int(request.GET["limit"])],
        )
        return JsonResponse([r[0] for r in cursor.fetchall()], safe=False)


def keys(request: HttpRequest) -> JsonResponse:
    # an API key, for the user or a principal whose keys they manage; a request that brings a key (x-api-key) signs
    # in with it first, in the same transaction: the database says who may make which
    k = body(request)
    with transaction.atomic(), connection.cursor() as cursor:
        key = request.headers.get("x-api-key")
        if key is not None:
            cursor.execute("SELECT authz.login_key(%s)", [key])
        cursor.execute(
            "SELECT authz.create_api_key(%s, '', NULL, CAST(%s AS text), CAST(%s AS text))",
            [str(k["name"]), text(k.get("principal_type")), text(k.get("principal_id"))],
        )
        made = cursor.fetchone()
    return JsonResponse({"key": str(made[0] if made else "")}, status=201)


def revoke_key(request: HttpRequest, key_id: int) -> HttpResponse:
    # one of the user's API keys: someone else's, or one that isn't there, is 404
    with connection.cursor() as cursor:
        cursor.execute("SELECT 1 FROM authz.revoke_api_key(%s)", [key_id])
    return HttpResponse(status=204)


def shares(request: HttpRequest, project_id: int) -> JsonResponse:
    with connection.cursor() as cursor:
        cursor.execute("SELECT subject_id FROM authz.list_shares('project', CAST(%s AS text))", [str(project_id)])
        return JsonResponse([r[0] for r in cursor.fetchall()], safe=False)


def ask(request: HttpRequest, project_id: int) -> JsonResponse:
    # access asked for: the policy shares no relation of a project, so this is the app's mistake (a 500), once the
    # database knows who asks
    a = body(request)
    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT authz.request_access('project', CAST(%s AS text), %s, %s)",
            [str(project_id), str(a["relation"]), str(a["reason"])],
        )
        asked = cursor.fetchone()
    return JsonResponse({"id": int(asked[0]) if asked else 0}, status=201)


def notes_as(request: HttpRequest, user_id: int) -> JsonResponse:
    # who is signed in, changed by hand: the database doesn't believe it (the app's bug, a 500)
    with transaction.atomic(), connection.cursor() as cursor:
        cursor.execute("SELECT set_config('authz.user_id', %s, true)", [str(user_id)])
        return JsonResponse(sorted(Note.objects.values_list("id", flat=True)), safe=False)


def move_folder(request: HttpRequest, folder_id: int) -> JsonResponse:
    folder = Folder.objects.filter(pk=folder_id).first()
    if folder is None:
        raise NotFound("public.folders", folder_id)
    parent = body(request)["parent_id"]
    folder.parent = None if parent is None else Folder(pk=number(parent))
    authz_dj.save(folder, update_fields=["parent"])  # inside one of its own subfolders: 409, the database's words
    return JsonResponse({"id": folder_id})


def notes(request: HttpRequest) -> JsonResponse:
    if request.method == "POST":
        return add_note(request)
    return JsonResponse(sorted(Note.objects.values_list("id", flat=True)), safe=False)


async def notes_async(request: HttpRequest) -> JsonResponse:
    # Django's async ORM: each query runs in a thread, as the request's user all the same
    return JsonResponse(sorted([n async for n in Note.objects.values_list("id", flat=True)]), safe=False)


def notes_streamed(request: HttpRequest) -> StreamingHttpResponse:
    # made as it is sent, after the view has returned: as the request's user all the same
    def chunks() -> Iterator[str]:
        yield json.dumps(sorted(Note.objects.values_list("id", flat=True)))

    return StreamingHttpResponse(chunks(), content_type="application/json")


async def notes_streamed_async(request: HttpRequest) -> StreamingHttpResponse:
    async def chunks() -> AsyncIterator[str]:
        yield json.dumps(sorted([n async for n in Note.objects.values_list("id", flat=True)]))

    return StreamingHttpResponse(chunks(), content_type="application/json")


def add_note(request: HttpRequest) -> JsonResponse:
    n = body(request)
    note = Note.objects.create(project_id=number(n["project_id"]), author_id=signed_in(), body=str(n["body"]))
    return JsonResponse({"id": note.id}, status=201)


def note(request: HttpRequest, note_id: int) -> HttpResponse:
    if request.method == "DELETE":
        return remove_note(request, note_id)
    return edit_note(request, note_id)


def edit_note(request: HttpRequest, note_id: int) -> JsonResponse:
    note = Note.objects.filter(pk=note_id).first()
    if note is None:
        raise NotFound("public.notes", note_id)
    note.body = str(body(request)["body"])
    authz_dj.save(note, update_fields=["body"])  # an update the rules may refuse: 403 with the reason
    return JsonResponse({"id": note_id})


def remove_note(request: HttpRequest, note_id: int) -> HttpResponse:
    authz_dj.expect(Note.objects.filter(pk=note_id).delete(), Note, "delete", note_id)
    return HttpResponse(status=204)


def send(request: HttpRequest) -> JsonResponse:
    m = body(request)
    # Django reads the id back (RETURNING): only the recipient may read it
    msg = Message.objects.create(sender_id=signed_in(), recipient_id=number(m["recipient_id"]), body=str(m["body"]))
    return JsonResponse({"id": msg.id}, status=201)


def send_quietly(request: HttpRequest) -> JsonResponse:
    # without reading the row back (Django's create() would, with RETURNING, to learn the new id)
    m = body(request)
    with connection.cursor() as cursor:
        cursor.execute(
            "INSERT INTO public.inbox (sender_id, recipient_id, body) VALUES (%s, %s, %s)",
            [signed_in(), number(m["recipient_id"]), str(m["body"])],
        )
    return JsonResponse({}, status=202)


@rowstile.job(("service", 1))
def digest() -> tuple[int, Principal | None]:
    """A background job: it signs in as service 1, whatever request started it."""
    return Project.objects.count(), rowstile.current()


urlpatterns = [
    path("projects", projects),
    path("projects/editable", editable),
    path("projects/buttons", buttons),
    path("projects/page", page),
    path("projects/<int:project_id>/shares", shares),
    path("projects/<int:project_id>/requests", ask),
    path("keys", keys),
    path("keys/<int:key_id>", revoke_key),
    path("notes", notes),
    path("notes/async", notes_async),
    path("notes/streamed", notes_streamed),
    path("notes/streamed/async", notes_streamed_async),
    path("notes/as/<int:user_id>", notes_as),
    path("notes/<int:note_id>", note),
    path("folders/<int:folder_id>", move_folder),
    path("inbox", send),
    path("inbox/quietly", send_quietly),
]

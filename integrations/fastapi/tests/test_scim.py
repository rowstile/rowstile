"""An identity provider's SCIM requests through the app's route (`authz.mount_scim("/scim/v2")` in app/main.py), as
Microsoft Entra ID and Okta send them. The database answers each one (authz.scim; core's tests/scim.sh checks what it
answers): these check what the route passes on and what it sends back. The provider is user 9, whose API key is
the bearer token; its groups are the projects' members, and the app's function (app.scim_user) makes its users."""

import json
import logging
import os
from collections.abc import AsyncIterator, Iterator
from typing import Any

import httpx
import psycopg
import pytest
import rowstile
from app.main import make_app
from fastapi import FastAPI, HTTPException
from rowstile import sqlalchemy as authz_sa
from rowstile.fastapi import Rowstile
from sqlalchemy import create_engine
from sqlalchemy.ext.asyncio import create_async_engine
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.routing import Mount

from .conftest import OWNER, libpq

pytestmark = pytest.mark.anyio
APP = os.environ.get("ROWSTILE_APP_URL", "")
Answer = Any
SETTINGS = {
    "principal": "user:9",
    "group": "project.member",
    "group_name": "name",
    "user_name": "name",
    "user_function": "app.scim_user",
}
ERROR = "urn:ietf:params:scim:api:messages:2.0:Error"
PATCH = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
USER = "urn:ietf:params:scim:schemas:core:2.0:User"
NOT_THE_PROVIDER: Answer = {
    "schemas": [ERROR],
    "status": "401",
    "detail": "the bearer token is not an API key of the principal the SCIM settings name (rowstile help AZ721)",
}
# one PATCH that adds a member and removes another: bo joins the group, cy leaves it
BO_FOR_CY: Answer = {
    "schemas": [PATCH],
    "Operations": [
        {"op": "add", "path": "members", "value": [{"value": "2"}]},
        {"op": "remove", "path": 'members[value eq "3"]'},
    ],
}
# a user as Okta writes one in a create: a password comes as a placeholder in each
DEE: Answer = {
    "schemas": [USER],
    "userName": "dee",
    "name": {"givenName": "Dee", "familyName": "User"},
    "emails": [{"primary": True, "value": "dee@example.com", "type": "work"}],
    "displayName": "Dee User",
    "password": "1mz050nq",
    "active": True,
}


def client(app: FastAPI | Starlette) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://conformance")


def bearer(key: str) -> dict[str, str]:
    return {"authorization": f"Bearer {key}"}


def members() -> list[int]:
    """Project 1's members, as the table has them."""
    with psycopg.connect(libpq(OWNER), autocommit=True) as owner:
        return [r[0] for r in owner.execute("SELECT user_id FROM app.members WHERE project_id = 1 ORDER BY 1")]


@pytest.fixture
async def app() -> AsyncIterator[FastAPI]:
    a = make_app(APP, check_connection=False)
    yield a
    await a.state.engine.dispose()


@pytest.fixture
def provider() -> Iterator[str]:
    """The provider's API key. While a test runs, the settings name user 9 as the provider; after it, the endpoint is
    off again, and the users and the members are the ones every other test counts on."""
    with psycopg.connect(libpq(OWNER), autocommit=True) as owner:
        owner.execute("INSERT INTO app.users VALUES (9, 'provisioning')")
        with owner.transaction():
            owner.execute("SELECT authz.act_as('user', '9')")
            key = owner.execute("SELECT authz.create_api_key('the identity provider')").fetchone()
        assert key is not None
        owner.execute("SELECT setval(pg_get_serial_sequence('app.users', 'id'), 100)")
        owner.execute("SELECT authz.set_scim(%s::jsonb)", [json.dumps(SETTINGS)])
        try:
            yield key[0]
        finally:
            owner.execute("SELECT authz.set_scim('{}')")
            owner.execute("DELETE FROM app.members")
            owner.execute("INSERT INTO app.members VALUES (1, 3)")
            owner.execute("DELETE FROM app.users WHERE id > 3")


async def test_scim_only_the_providers_key_is_answered(app: FastAPI, provider: str) -> None:
    with psycopg.connect(libpq(OWNER)) as owner:  # a key of ann's own: a key, but not the provider's
        owner.execute("SELECT authz.act_as('user', '1')")
        anns = owner.execute("SELECT authz.create_api_key('ann''s own')").fetchone()
    assert anns is not None
    async with client(app) as c:
        refused = [
            await c.get("/scim/v2/Groups/1"),
            await c.get("/scim/v2/Groups/1", headers={"x-user": "1"}),  # signed in to the app: no provider
            await c.get("/scim/v2/Groups/1", headers={"x-user": "9"}),
            await c.get("/scim/v2/Groups/1", headers=bearer("ak_00000000000000000000000000000000")),
            await c.get("/scim/v2/Groups/1", headers=bearer(anns[0])),
            await c.get("/scim/v2/Groups/1", headers={"authorization": f"Basic {provider}"}),
            await c.patch("/scim/v2/Groups/1", json=BO_FOR_CY, headers=bearer(anns[0])),
        ]
        answered = await c.get("/scim/v2/Groups/1", headers={"authorization": f"bearer {provider}"})
    for r in refused:
        assert r.status_code == 401 and r.json() == NOT_THE_PROVIDER, r.text
        assert r.headers["content-type"] == "application/scim+json", r.headers
        assert r.headers["www-authenticate"] == "Bearer", r.headers
    assert members() == [3]
    assert answered.status_code == 200 and answered.json()["displayName"] == "Plans", answered.text
    assert "www-authenticate" not in answered.headers


async def test_scim_what_a_provider_asks_before_it_starts(app: FastAPI, provider: str) -> None:
    async with client(app) as c:
        config = await c.get("/scim/v2/ServiceProviderConfig", headers=bearer(provider))
        schemas = await c.get("/scim/v2/Schemas", headers=bearer(provider))
        types = await c.get("/scim/v2/ResourceTypes", headers=bearer(provider))
        # the query string goes to the database as it was sent: Entra ID's filter on a group's name, Okta's on a
        # user's, a space as %20 or as a plus sign
        plans = await c.get(
            "/scim/v2/Groups?excludedAttributes=members&filter=displayName%20eq%20%22Plans%22",
            headers=bearer(provider),
        )
        bo = await c.get("/scim/v2/Users?filter=userName+eq+%22bo%22&startIndex=1&count=100", headers=bearer(provider))
        nobody = await c.get("/scim/v2/Users?filter=userName%20eq%20%22nobody%22", headers=bearer(provider))
        bad = await c.get("/scim/v2/Users?filter=userName%20co%20%22b%22", headers=bearer(provider))
        nowhere = await c.get("/scim/v2/Nothing", headers=bearer(provider))
        bare = await c.get("/scim/v2/", headers=bearer(provider))
    for r in (config, schemas, types, plans, bo, nobody):
        assert r.status_code == 200 and r.headers["content-type"] == "application/scim+json", r.text
    assert config.json()["patch"] == {"supported": True} and config.json()["bulk"]["supported"] is False, config.text
    assert {s["id"] for s in schemas.json()["Resources"]} >= {USER}, schemas.text
    assert sorted(t["endpoint"] for t in types.json()["Resources"]) == ["/Groups", "/Users"], types.text
    assert [(g["id"], g["displayName"], "members" in g) for g in plans.json()["Resources"]] == [("1", "Plans", False)]
    assert [(u["id"], u["userName"]) for u in bo.json()["Resources"]] == [("2", "bo")], bo.text
    assert nobody.json()["totalResults"] == 0 and nobody.json()["Resources"] == [], nobody.text
    assert bad.status_code == 400 and bad.json()["scimType"] == "invalidFilter", bad.text
    for r in (nowhere, bare):
        assert r.status_code == 404 and r.json()["schemas"] == [ERROR] and r.json()["status"] == "404", r.text
        assert r.headers["content-type"] == "application/scim+json", r.headers


async def test_scim_a_patch_changes_the_members_and_the_policy_follows(app: FastAPI, provider: str) -> None:
    async with client(app) as c:
        before = [(await c.get("/notes", headers={"x-user": u})).json() for u in ("2", "3")]
        patched = await c.patch(
            "/scim/v2/Groups/1",
            content=json.dumps(BO_FOR_CY),
            headers={**bearer(provider), "content-type": "application/scim+json"},
        )
        after = [(await c.get("/notes", headers={"x-user": u})).json() for u in ("2", "3")]
        group = await c.get("/scim/v2/Groups/1", headers=bearer(provider))
    # note 1 is the project's, so a member reads it (other checks leave notes of their own: the lists aren't compared)
    assert [1 in notes for notes in before] == [False, True], before
    # Entra ID and Okta both take 204 for a group's PATCH: no body, and so no type for one
    assert patched.status_code == 204 and patched.content == b"", patched.text
    assert "content-type" not in patched.headers and "location" not in patched.headers, patched.headers
    assert members() == [2]
    # bo reads the project's notes now, and cy, a member no longer, does not
    assert [1 in notes for notes in after] == [True, False], after
    assert group.json()["members"] == [{"value": "2"}] and group.json()["displayName"] == "Plans", group.text
    # as authz.sync_members writes it, in one line of the audit trail, which says the provider did it
    with psycopg.connect(libpq(OWNER), autocommit=True) as owner:
        line = owner.execute(
            "SELECT user_id, object_type, object_id, relation, detail->>'added', detail->>'removed', detail->'members' "
            "FROM authz.audit WHERE action = 'sync_members' ORDER BY id DESC LIMIT 1"
        ).fetchone()
    assert line == ("9", "project", "1", "member", "1", "1", ["2"]), line


async def test_scim_a_user_made_is_answered_with_where_it_is(app: FastAPI, provider: str) -> None:
    async with client(app) as c:
        made = await c.post("/scim/v2/Users", json=DEE, headers=bearer(provider))
        where = made.headers.get("location", "")
        read = await c.get(where, headers=bearer(provider))
        again = await c.post("/scim/v2/Users", json=DEE, headers=bearer(provider))
        # Entra ID changes one attribute (op Replace, a path)
        renamed = await c.patch(
            "/scim/v2/Users/101",
            json={"schemas": [PATCH], "Operations": [{"op": "Replace", "path": "userName", "value": "dee.user"}]},
            headers=bearer(provider),
        )
        with psycopg.connect(libpq(OWNER), autocommit=True) as owner:
            row = owner.execute("SELECT name FROM app.users WHERE id = 101").fetchone()
        deleted = await c.delete("/scim/v2/Users/101", headers=bearer(provider))
        gone = await c.get("/scim/v2/Users/101", headers=bearer(provider))
    # 201, the user, and where it is: the mount's own address, then what the database said
    assert made.status_code == 201 and where == "http://conformance/scim/v2/Users/101", (made.text, made.headers)
    assert made.headers["content-type"] == "application/scim+json"
    assert (made.json()["id"], made.json()["userName"], "password" in made.json()) == ("101", "dee", False), made.text
    assert read.status_code == 200 and read.json()["id"] == "101", read.text
    assert again.status_code == 409 and again.json()["scimType"] == "uniqueness", again.text
    assert "location" not in again.headers
    assert renamed.status_code == 200 and renamed.json()["userName"] == "dee.user", renamed.text
    assert row == ("dee.user",)
    assert deleted.status_code == 204 and deleted.content == b"" and "content-type" not in deleted.headers
    assert gone.status_code == 404 and gone.json()["schemas"] == [ERROR], gone.text


async def test_scim_a_body_goes_on_unread_and_nothing_sent_is_an_error(
    app: FastAPI, provider: str, caplog: pytest.LogCaptureFixture
) -> None:
    # The route passes the body on as it was sent, and the database says when it is no JSON, to the provider alone.
    # So what one JSON reader takes and another doesn't is no matter here: no such body fails, with or without the key
    bodies = [
        b'{"userName": ',
        b"dee",
        b'{"userName": "dee", "weight": NaN}',  # Python's reader takes it; JSON has no NaN
        b'{"userName": "dee\\u0000"}',  # JSON, with a text no text of the database holds
        b"[" * 100_000,  # nested deeper than the server reads
    ]
    with caplog.at_level(logging.ERROR, logger="rowstile"):
        async with client(app) as c:
            refused = [await c.post("/scim/v2/Users", content=b, headers=bearer(provider)) for b in bodies]
            strangers = [await c.post("/scim/v2/Users", content=b) for b in bodies]
            # what is no text can't be passed on at all: the route's own answer, whoever asks
            no_text = [
                await c.post("/scim/v2/Users", content=b"\xff\xfe", headers=bearer(provider)),
                await c.post("/scim/v2/Users", content=b'{"userName": "d\x00e"}', headers=bearer(provider)),
                await c.get("/scim/v2/Users/%00", headers=bearer(provider)),
                await c.get("/scim/v2/Users/%00"),
            ]
            listed = await c.get("/scim/v2/Users?filter=userName%20eq%20%22dee%22", headers=bearer(provider))
    for r in refused:
        assert r.status_code == 400 and r.headers["content-type"] == "application/scim+json", r.text
        assert r.json() == {
            "schemas": [ERROR],
            "status": "400",
            "scimType": "invalidSyntax",
            "detail": "the request's body is no JSON, or is nested too deep to read (rowstile help AZ721)",
        }, r.text
    for r in strangers:  # the key is refused, the body not read
        assert r.status_code == 401 and r.json() == NOT_THE_PROVIDER, r.text
    for r in no_text:
        assert r.status_code == 400 and r.headers["content-type"] == "application/scim+json", r.text
        assert r.json() == {
            "schemas": [ERROR],
            "status": "400",
            "scimType": "invalidSyntax",
            "detail": "the request is no text: bytes that are no UTF-8, or a NUL",
        }, r.text
    assert caplog.records == [], caplog.text
    assert listed.json()["totalResults"] == 0, listed.text


async def test_scim_an_error_is_500_and_the_apps_to_see(
    app: FastAPI, provider: str, caplog: pytest.LogCaptureFixture
) -> None:
    # settings that no longer hold (the function they name is gone) are the app's mistake, not the provider's: the
    # database raises, the route answers 500 in SCIM's words and the app's log has the database's
    with psycopg.connect(libpq(OWNER), autocommit=True) as owner:
        owner.execute("ALTER FUNCTION app.scim_user(text, jsonb) RENAME TO scim_user_gone")
        try:
            with caplog.at_level(logging.ERROR, logger="rowstile"):
                async with client(app) as c:
                    failed = await c.post("/scim/v2/Users", json=DEE, headers=bearer(provider))
                    read = await c.get("/scim/v2/Users/2", headers=bearer(provider))
        finally:
            owner.execute("ALTER FUNCTION app.scim_user_gone(text, jsonb) RENAME TO scim_user")
    assert failed.status_code == 500 and failed.headers["content-type"] == "application/scim+json", failed.text
    assert failed.json() == {
        "schemas": [ERROR],
        "status": "500",
        "detail": "the request failed: the app's log says why",
    }, failed.text
    logged = [r for r in caplog.records if r.name == "rowstile" and r.exc_info is not None]
    assert len(logged) == 1 and logged[0].levelno == logging.ERROR, caplog.text
    assert logged[0].getMessage() == "authz.scim failed (POST 'Users')", logged[0].getMessage()
    error = logged[0].exc_info[1] if logged[0].exc_info else None
    assert error is not None and rowstile.error_code(error) == "AZ722", error  # rowstile help AZ722
    assert read.status_code == 200, read.text  # a request that reads no such setting is answered


async def test_scim_requests_are_not_user_requests(provider: str) -> None:
    def who(request: Request) -> str | None:
        """An app that takes a bearer token for a session's, and refuses one it doesn't know."""
        if "authorization" in request.headers:
            raise HTTPException(401, "bad token")
        return request.headers.get("x-user")

    engine = create_async_engine(APP)
    a = FastAPI()
    Rowstile(a, engine, user=who, check_connection=False).mount_scim("/provisioning/")

    @a.get("/me")
    async def me() -> str:
        return str(rowstile.current())

    outer = Starlette(routes=[Mount("/api", app=a)])
    try:
        async with client(a) as c:
            # user(request) isn't asked about a provider's request, whose token is no session's
            group = await c.get("/provisioning/Groups/1", headers=bearer(provider))
            # ... nor believed for one: what else a request says signs nobody in
            with_user = await c.get("/provisioning/Groups/1", headers={**bearer(provider), "x-user": "1"})
            made = await c.post("/provisioning/Users", json=DEE, headers=bearer(provider))
            # every other route is user(request)'s, a path that only begins like the mount too
            mine = await c.get("/me", headers={"x-user": "2"})
            bad = await c.get("/me", headers=bearer(provider))
            beside = await c.get("/provisioningGroups/1", headers=bearer(provider))
        async with client(outer) as c:  # the app mounted in another: the same, and a new user's address says so
            under = await c.get("/api/provisioning/Groups/1", headers=bearer(provider))
            other = await c.post("/api/provisioning/Users", json={**DEE, "userName": "eli"}, headers=bearer(provider))
    finally:
        await engine.dispose()
    assert group.status_code == 200 and group.json()["members"] == [{"value": "3"}], group.text
    assert with_user.status_code == 200, with_user.text
    assert made.status_code == 201 and made.headers["location"] == "http://conformance/provisioning/Users/101"
    assert mine.json() == "2"
    assert bad.status_code == 401 and bad.json() == {"detail": "bad token"}, bad.text
    assert beside.status_code == 401 and beside.json() == {"detail": "bad token"}, beside.text
    assert under.status_code == 200, under.text
    assert other.status_code == 201, other.text
    assert other.headers["location"] == "http://conformance/api/provisioning/Users/102", other.headers


async def test_scim_on_a_sync_engine(provider: str) -> None:
    # an engine whose user() says someone is signed in: a provider's request is still nobody's but its key's
    engine = authz_sa.install(create_engine(APP.replace("+asyncpg", "+psycopg")), user=lambda: 1)
    a = FastAPI()
    Rowstile(a, engine, check_connection=False).mount_scim()
    try:
        async with client(a) as c:
            group = await c.get("/scim/v2/Groups/1", headers=bearer(provider))
            patched = await c.patch("/scim/v2/Groups/1", json=BO_FOR_CY, headers=bearer(provider))
            made = await c.post("/scim/v2/Users", json=DEE, headers=bearer(provider))
            refused = await c.get("/scim/v2/Groups/1")
    finally:
        engine.dispose()
    assert group.status_code == 200 and group.json()["members"] == [{"value": "3"}], group.text
    assert patched.status_code == 204 and members() == [2], patched.text
    assert made.status_code == 201 and made.headers["location"] == "http://conformance/scim/v2/Users/101"
    assert made.json()["userName"] == "dee", made.text
    assert refused.status_code == 401 and refused.json() == NOT_THE_PROVIDER, refused.text


def test_scim_needs_an_engine_and_an_address() -> None:
    # an app on psycopg or asyncpg alone gave Rowstile no engine to ask the database on
    with pytest.raises(ValueError, match=r"Rowstile\(app, None\) has no engine to ask the database on"):
        Rowstile(FastAPI(), None).mount_scim()
    # ... and at the app's root every request would be a provider's
    engine = create_engine(APP.replace("+asyncpg", "+psycopg"))
    for prefix in ("", "/", "scim/v2"):
        with pytest.raises(ValueError, match="give the address a provider's requests come in under"):
            Rowstile(FastAPI(), engine, check_connection=False).mount_scim(prefix)
    engine.dispose()

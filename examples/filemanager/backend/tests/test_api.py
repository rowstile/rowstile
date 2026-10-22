"""The API against real Postgres (with rowstile and db/policy.authz applied) and RustFS: run test.sh.

Every check goes through HTTP as a signed-in person, so what it proves is what row-level security and
the authz.* functions decide, end to end.
"""

import dataclasses
import os
import re
import shutil
import subprocess
import sys
import uuid
from collections.abc import Iterator
from datetime import timedelta
from pathlib import Path
from typing import Any, LiteralString, TypedDict

import httpx
import psycopg
import pytest
from app.main import app, in_words
from fastapi.testclient import TestClient
from psycopg import errors
from psycopg.abc import Params

ADMIN = os.environ["FM_ADMIN_URL"]
# an answer from the API: its shape is what the checks check
Answer = Any


class Person(TestClient):
    """A client signed in as someone, and who they are (the API's answer at sign-up)."""

    me: Answer


class World(TypedDict):
    """Four people; alice's folder, a folder in it, and a file in that."""

    alice: Person
    bob: Person
    carol: Person
    dave: Person
    top: Answer
    sub: Answer
    file: Answer


@pytest.fixture(scope="session", autouse=True)
def running() -> Iterator[None]:
    """The app's startup and shutdown (the connection pool, the bucket), once for every test."""
    with TestClient(app):
        yield


def person(name: str) -> Person:
    """A new account, signed in: a TestClient carrying its session cookie."""
    c = Person(app)
    r = c.post(
        "/api/signup",
        json={"email": f"{name}-{uuid.uuid4().hex[:8]}@example.com", "name": name, "password": "correct horse"},
    )
    assert r.status_code == 200, r.text
    c.me = r.json()
    return c


def admin(sql: LiteralString, args: Params = ()) -> list[tuple[Answer, ...]]:
    with psycopg.connect(ADMIN, autocommit=True) as conn:
        cur = conn.execute(sql, args)
        return cur.fetchall() if cur.description else []  # the rows, if it returns any


@pytest.fixture(scope="module")
def world() -> Iterator[World]:
    alice, bob, carol, dave = (person(n) for n in ("alice", "bob", "carol", "dave"))
    top = alice.post("/api/folders", json={"name": f"Projects {uuid.uuid4().hex[:6]}"}).json()
    sub = alice.post("/api/folders", json={"name": "Plans", "parent_id": top["id"]}).json()
    f = alice.post(f"/api/folders/{sub['id']}/files", files={"file": ("plan.txt", b"the plan", "text/plain")})
    assert f.status_code == 201, f.text
    yield {"alice": alice, "bob": bob, "carol": carol, "dave": dave, "top": top, "sub": sub, "file": f.json()}


def download(client: TestClient, file_id: int) -> bytes | int:
    r = client.get(f"/api/files/{file_id}/download")
    if r.status_code != 200:
        return r.status_code
    return httpx.get(r.json()["url"]).content


# --- accounts ------------------------------------------------------------------------------------
def test_accounts() -> None:
    accounts(TestClient(app))


def accounts(c: TestClient) -> None:
    email = f"eve-{uuid.uuid4().hex[:8]}@example.com"
    assert c.post("/api/signup", json={"email": email, "name": "Eve", "password": "long enough"}).status_code == 200
    assert c.get("/api/me").json()["email"] == email
    assert c.post("/api/logout").status_code == 200
    assert c.get("/api/me").status_code == 401
    assert c.post("/api/login", json={"email": email, "password": "wrong password"}).status_code == 401
    assert c.post("/api/login", json={"email": email.upper(), "password": "long enough"}).status_code == 200
    assert c.get("/api/me").status_code == 200
    again = TestClient(app).post(
        "/api/signup", json={"email": email.upper(), "name": "Eve 2", "password": "long enough"}
    )
    assert (again.status_code, again.json()) == (409, {"detail": "an account with that email exists already"})


def test_sign_up_can_be_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    import dataclasses

    from app import main

    monkeypatch.setattr(main, "settings", dataclasses.replace(main.settings, open_signup=False))
    email = f"closed-{uuid.uuid4().hex[:8]}@example.com"
    r = TestClient(app).post("/api/signup", json={"email": email, "name": "Shut", "password": "long enough"})
    assert (r.status_code, r.json()) == (403, {"detail": "accounts are created by an administrator"})
    assert admin("SELECT count(*) FROM fm.users WHERE email = %s", (email,)) == [(0,)]


def test_signed_out_sees_nothing() -> None:
    assert TestClient(app).get("/api/home").status_code == 401


# --- owning, and not seeing what isn't yours ---------------------------------------------------
def test_owner_works_in_their_folders(world: World) -> None:
    alice, top, sub, f = world["alice"], world["top"], world["sub"], world["file"]
    home = alice.get("/api/home").json()
    assert top["id"] in [x["id"] for x in home["folders"]]
    assert sub["id"] not in [x["id"] for x in home["folders"]]  # inside a folder she sees: not on top
    page = alice.get(f"/api/folders/{sub['id']}").json()
    assert [p["id"] for p in page["path"]] == [top["id"], sub["id"]]
    assert [x["name"] for x in page["files"]] == ["plan.txt"]
    assert set(page["perms"]) >= {"view", "edit", "share"}
    assert download(alice, f["id"]) == b"the plan"


def test_others_see_nothing(world: World) -> None:
    bob, sub, f = world["bob"], world["sub"], world["file"]
    assert bob.get(f"/api/folders/{sub['id']}").status_code == 404
    assert bob.get(f"/api/files/{f['id']}").status_code == 404
    assert download(bob, f["id"]) == 404  # no signed link without reading the row
    assert bob.post(f"/api/folders/{sub['id']}/files", files={"file": ("x.txt", b"x")}).status_code == 403
    assert bob.patch(f"/api/folders/{sub['id']}", json={"name": "Mine"}).status_code == 404
    assert bob.delete(f"/api/files/{f['id']}").status_code == 404
    assert bob.get(f"/api/folders/{sub['id']}/shares").status_code == 404
    assert sub["id"] not in [x["id"] for x in bob.get("/api/home").json()["folders"]]


def test_moving_a_folder_needs_share() -> None:
    """An editor may rename a folder, not move it: moving takes it from everyone who reached it from above."""
    olga, ed = person("olga"), person("ed")
    shared = olga.post("/api/folders", json={"name": f"Shared {uuid.uuid4().hex[:6]}"}).json()
    inner = olga.post("/api/folders", json={"name": "Inner", "parent_id": shared["id"]}).json()
    other = olga.post("/api/folders", json={"name": f"Other {uuid.uuid4().hex[:6]}"}).json()
    his = ed.post("/api/folders", json={"name": "His"}).json()
    r = olga.post(
        f"/api/folders/{shared['id']}/shares",
        json={"relation": "editor", "subject_type": "user", "subject_id": ed.me["id"]},
    )
    assert r.status_code == 201, r.text
    for change in ({"parent_id": his["id"]}, {"to_top": True}):
        r = ed.patch(f"/api/folders/{inner['id']}", json=change)
        assert (r.status_code, r.json()["detail"]) == (403, "you may not do that here"), r.text
        assert any("share" in line for line in r.json()["why"]), r.json()
    assert [p["id"] for p in olga.get(f"/api/folders/{inner['id']}").json()["path"]] == [shared["id"], inner["id"]]
    assert ed.patch(f"/api/folders/{inner['id']}", json={"name": "Renamed"}).status_code == 200
    assert olga.patch(f"/api/folders/{inner['id']}", json={"parent_id": other["id"]}).status_code == 200
    assert [p["id"] for p in olga.get(f"/api/folders/{inner['id']}").json()["path"]] == [other["id"], inner["id"]]
    # the web app shows moving (and sharing, deleting) only where the user may share
    assert [f["can_share"] for f in ed.get(f"/api/folders/{shared['id']}").json()["folders"]] == []
    assert olga.patch(f"/api/folders/{inner['id']}", json={"parent_id": shared["id"]}).status_code == 200
    assert [f["can_share"] for f in ed.get(f"/api/folders/{shared['id']}").json()["folders"]] == [False]
    assert [f["can_share"] for f in olga.get(f"/api/folders/{shared['id']}").json()["folders"]] == [True]
    on_top = {f["id"]: f["can_share"] for f in ed.get("/api/home").json()["folders"]}
    assert (on_top[shared["id"]], on_top[his["id"]]) == (False, True)


def test_listings_say_what_the_user_may_do_with_each_row() -> None:
    """The web app shows a row's buttons from these: renaming, moving, deleting and new versions need edit."""
    olga, vic, ed = person("olga"), person("vic"), person("ed")
    top = olga.post("/api/folders", json={"name": f"Rows {uuid.uuid4().hex[:6]}"}).json()
    olga.post("/api/folders", json={"name": "Inner", "parent_id": top["id"]})
    f = olga.post(f"/api/folders/{top['id']}/files", files={"file": ("a.txt", b"a", "text/plain")}).json()
    for who, relation, path in ((vic, "viewer", f"folders/{top['id']}"), (ed, "editor", f"files/{f['id']}")):
        r = olga.post(
            f"/api/{path}/shares", json={"relation": relation, "subject_type": "user", "subject_id": who.me["id"]}
        )
        assert r.status_code == 201, r.text

    def rows(c: TestClient, path: str) -> dict[str, tuple[bool, bool]]:
        page = c.get(path).json()
        return {x["name"]: (x["can_edit"], x["can_share"]) for x in page["folders"] + page["files"]}

    assert rows(olga, f"/api/folders/{top['id']}") == {"Inner": (True, True), "a.txt": (True, True)}
    assert rows(vic, f"/api/folders/{top['id']}") == {"Inner": (False, False), "a.txt": (False, False)}
    assert rows(vic, "/api/home")[top["name"]] == (False, False)
    assert rows(ed, "/api/home") == {"a.txt": (True, False)}  # the file on its own: its folder isn't shared with him


def test_a_folder_cannot_go_inside_itself(world: World) -> None:
    alice, top, sub = world["alice"], world["top"], world["sub"]
    assert alice.patch(f"/api/folders/{top['id']}", json={"parent_id": sub["id"]}).status_code == 400


NOT_EMPTY = {
    "detail": "the folder isn't empty: empty it first (it may hold things you can't see, which only their owners "
    "can remove)"
}


def test_a_folder_with_contents_cannot_be_deleted(world: World) -> None:
    alice, top = world["alice"], world["top"]
    r = alice.delete(f"/api/folders/{world['sub']['id']}")  # it holds a file
    assert (r.status_code, r.json()) == (409, NOT_EMPTY)
    r = alice.delete(f"/api/folders/{top['id']}")  # it holds a folder
    assert (r.status_code, r.json()) == (409, NOT_EMPTY)


def test_names_are_unique_in_a_folder(world: World) -> None:
    alice, top, sub = world["alice"], world["top"], world["sub"]
    r = alice.post(f"/api/folders/{sub['id']}/files", files={"file": ("plan.txt", b"again")})
    assert (r.status_code, r.json()) == (409, {"detail": "something with that name is already there"})
    r = alice.post("/api/folders", json={"name": "Plans", "parent_id": top["id"]})
    assert (r.status_code, r.json()) == (409, {"detail": "something with that name is already there"})


# --- sharing -----------------------------------------------------------------------------------
def test_sharing_a_folder_with_a_person(world: World) -> None:
    alice, bob, top, sub, f = world["alice"], world["bob"], world["top"], world["sub"], world["file"]
    r = alice.post(
        f"/api/folders/{top['id']}/shares",
        json={"relation": "viewer", "subject_type": "user", "subject_id": bob.me["id"]},
    )
    assert r.status_code == 201, r.text
    assert top["id"] in [x["id"] for x in bob.get("/api/home").json()["folders"]]  # shared with him: on his top
    assert download(bob, f["id"]) == b"the plan"  # ...and everything inside
    assert bob.post(f"/api/folders/{sub['id']}/files", files={"file": ("x.txt", b"x")}).status_code == 403
    assert bob.patch(f"/api/files/{f['id']}", json={"name": "mine.txt"}).status_code == 403
    assert (
        bob.post(
            f"/api/folders/{sub['id']}/shares",
            json={"relation": "viewer", "subject_type": "user", "subject_id": world["dave"].me["id"]},
        ).status_code
        == 403
    )
    shares = alice.get(f"/api/folders/{top['id']}/shares").json()
    assert [(s["relation"], s["subject_name"]) for s in shares] == [("viewer", "bob")]
    assert "bob" in [u["name"] for u in alice.get(f"/api/folders/{sub['id']}/access?perm=view").json()]
    assert any("viewer" in line for line in bob.get(f"/api/folders/{sub['id']}/why?perm=view").json()["lines"])


def test_why_says_nothing_of_what_you_cannot_see(world: World) -> None:
    stranger, sub = person("stranger"), world["sub"]
    hidden = stranger.get(f"/api/folders/{sub['id']}/why?perm=view")
    missing = stranger.get("/api/folders/999999999/why?perm=view")
    assert (hidden.status_code, hidden.json()) == (200, {"lines": [f"no   you have no access to folder {sub['id']}"]})
    assert (missing.status_code, missing.json()) == (200, {"lines": ["no   you have no access to folder 999999999"]})


def test_editors_may_add_files(world: World) -> None:
    alice, carol, sub = world["alice"], world["carol"], world["sub"]
    r = alice.post(
        f"/api/folders/{sub['id']}/shares",
        json={"relation": "editor", "subject_type": "user", "subject_id": carol.me["id"]},
    )
    assert r.status_code == 201, r.text
    r = carol.post(f"/api/folders/{sub['id']}/files", files={"file": ("notes.txt", b"carol's notes")})
    assert r.status_code == 201, r.text
    assert download(world["alice"], r.json()["id"]) == b"carol's notes"
    assert carol.delete(f"/api/files/{r.json()['id']}").status_code == 204
    assert world["alice"].get(f"/api/files/{r.json()['id']}").status_code == 404


def test_sharing_with_a_group(world: World) -> None:
    alice, dave, top = world["alice"], world["dave"], world["top"]
    group, sub_group = uuid.uuid4(), uuid.uuid4()
    admin("INSERT INTO fm.groups (id, name) VALUES (%s, 'Design'), (%s, 'Design / UX')", (group, sub_group))
    admin("UPDATE fm.groups SET parent_id = %s WHERE id = %s", (group, sub_group))
    admin("INSERT INTO fm.group_members VALUES (%s, %s)", (sub_group, dave.me["id"]))
    assert dave.get(f"/api/folders/{top['id']}").status_code == 404
    r = alice.post(
        f"/api/folders/{top['id']}/shares",
        json={"relation": "viewer", "subject_type": "group", "subject_id": str(group)},
    )
    assert r.status_code == 201, r.text
    assert dave.get(f"/api/folders/{top['id']}").status_code == 200  # a member of a sub-group
    r = alice.request(
        "DELETE",
        f"/api/folders/{top['id']}/shares",
        json={"relation": "viewer", "subject_type": "group", "subject_id": str(group)},
    )
    assert r.status_code == 204, r.text
    assert dave.get(f"/api/folders/{top['id']}").status_code == 404


def test_a_folder_can_stop_inheritance(world: World) -> None:
    alice, bob, top = world["alice"], world["bob"], world["top"]
    private = alice.post("/api/folders", json={"name": "Private", "parent_id": top["id"]}).json()
    assert bob.get(f"/api/folders/{private['id']}").status_code == 200  # bob views top (shared above)
    assert alice.patch(f"/api/folders/{private['id']}", json={"inherit": False}).status_code == 200
    assert bob.get(f"/api/folders/{private['id']}").status_code == 404
    assert bob.patch(f"/api/folders/{private['id']}", json={"inherit": True}).status_code == 404


def test_expired_shares_count_for_nothing(world: World) -> None:
    alice, dave, sub = world["alice"], world["dave"], world["sub"]
    alice.post(
        f"/api/folders/{sub['id']}/shares",
        json={
            "relation": "viewer",
            "subject_type": "user",
            "subject_id": dave.me["id"],
            "expires_at": "2000-01-01T00:00:00Z",
        },
    )
    assert dave.get(f"/api/folders/{sub['id']}").status_code == 404


# --- requests, reviews, break glass --------------------------------------------------------------
def test_asking_for_access(world: World) -> None:
    alice, dave, sub = world["alice"], world["dave"], world["sub"]
    rid = dave.post(
        f"/api/folders/{sub['id']}/requests", json={"relation": "viewer", "reason": "for the review"}
    ).json()["id"]
    mine = [r for r in dave.get("/api/requests").json() if r["id"] == rid]
    assert mine and mine[0]["mine"]
    assert mine[0]["duration"] == "7 days"  # as it was asked for, not as JSON writes a timedelta ("P7D")
    assert [r["id"] for r in alice.get("/api/requests").json() if not r["mine"]] == [rid]
    assert dave.post(f"/api/requests/{rid}/decision", json={"approve": True}).status_code == 403  # not his to decide
    assert alice.post(f"/api/requests/{rid}/decision", json={"approve": True, "note": "ok"}).status_code == 200
    assert dave.get(f"/api/folders/{sub['id']}").status_code == 200


def test_a_duration_in_words() -> None:
    assert in_words(timedelta(days=1)) == "1 day"
    assert in_words(timedelta(days=30, hours=2, minutes=1, seconds=5)) == "30 days 2 hours 1 minute 5 seconds"
    assert in_words(timedelta(microseconds=5)) == "under a second"
    assert in_words(None) is None


def test_asking_about_a_folder_that_does_not_exist_looks_the_same(world: World) -> None:
    r = world["dave"].post("/api/folders/999999999/requests", json={"relation": "viewer", "reason": "?"})
    assert r.status_code == 201


def test_reviewing_who_has_access(world: World) -> None:
    alice, bob, top = world["alice"], world["bob"], world["top"]
    rid = alice.post(f"/api/folders/{top['id']}/reviews").json()["id"]
    items = alice.get(f"/api/reviews/{rid}").json()
    bob_item = next(i for i in items if i["subject_id"] == bob.me["id"])
    assert alice.post(f"/api/reviews/{rid}/items/{bob_item['item']}", json={"keep": False}).status_code == 200
    assert alice.post(f"/api/reviews/{rid}/close", json={}).json()["revoked"] >= 1
    assert bob.get(f"/api/folders/{top['id']}").status_code == 404


def test_break_glass_is_for_support_only(world: World) -> None:
    carol, top = world["carol"], world["top"]
    r = carol.post(f"/api/folders/{top['id']}/break-glass", json={"reason": "INC-1: customer can't open plans"})
    assert r.status_code == 403
    admin("UPDATE fm.users SET is_support = true WHERE id = %s", (carol.me["id"],))
    r = carol.post(
        f"/api/folders/{top['id']}/break-glass",
        json={"reason": "INC-1: customer can't open plans", "duration": "30 minutes"},
    )
    assert r.status_code == 200, r.text
    assert carol.get(f"/api/folders/{top['id']}").status_code == 200


# --- groups run in the app ---------------------------------------------------------------------
def test_groups_are_run_by_their_owners_and_admins() -> None:
    ann, ben, cat, dan = (person(n) for n in ("ann", "ben", "cat", "dan"))
    g = ann.post("/api/groups", json={"name": f"Research {uuid.uuid4().hex[:6]}"}).json()
    assert ann.post(f"/api/groups/{g['id']}/members", json={"user_id": ben.me["id"]}).status_code == 201
    assert (
        ben.post(f"/api/groups/{g['id']}/members", json={"user_id": cat.me["id"]}).status_code == 403
    )  # a member, not an admin
    assert (
        ann.post(f"/api/groups/{g['id']}/members", json={"user_id": ben.me["id"], "is_admin": True}).status_code == 201
    )
    assert ben.post(f"/api/groups/{g['id']}/members", json={"user_id": cat.me["id"]}).status_code == 201  # now he may
    sub = ben.post("/api/groups", json={"name": "Research / lab", "parent_id": g["id"]})
    assert sub.status_code == 201, sub.text  # admins make sub-groups
    assert dan.post("/api/groups", json={"name": "not mine", "parent_id": g["id"]}).status_code == 403
    assert dan.patch(f"/api/groups/{g['id']}", json={"name": "taken over"}).status_code == 403
    assert dan.delete(f"/api/groups/{g['id']}/members/{cat.me['id']}").status_code == 403
    assert {m["name"] for m in dan.get(f"/api/groups/{g['id']}/members").json()["members"]} == {
        "ben",
        "cat",
    }  # a directory
    assert cat.delete(f"/api/groups/{g['id']}/members/{cat.me['id']}").status_code == 204  # anyone may leave
    assert [x["manage"] for x in ann.get("/api/groups").json() if x["id"] == g["id"]] == [True]
    # sharing with a group made in the app
    folder = dan.post("/api/folders", json={"name": "For research"}).json()
    r = dan.post(
        f"/api/folders/{folder['id']}/shares",
        json={"relation": "viewer", "subject_type": "group", "subject_id": g["id"]},
    )
    assert r.status_code == 201, r.text
    assert ben.get(f"/api/folders/{folder['id']}").status_code == 200
    assert cat.get(f"/api/folders/{folder['id']}").status_code == 404  # she left
    assert dan.delete(f"/api/groups/{g['id']}").status_code == 403
    # someone who has no account isn't added
    r = ann.post(f"/api/groups/{g['id']}/members", json={"user_id": str(uuid.uuid4())})
    assert (r.status_code, r.json()) == (404, {"detail": "no such person"})
    # its managers rename it (an admin here)
    assert ben.patch(f"/api/groups/{g['id']}", json={"name": "Research, renamed"}).status_code == 200
    assert [x["name"] for x in dan.get("/api/groups").json() if x["id"] == g["id"]] == ["Research, renamed"]
    # a group with sub-groups stays until they go
    r = ann.delete(f"/api/groups/{g['id']}")
    assert (r.status_code, r.json()) == (409, {"detail": "the group has sub-groups: delete them first"})
    assert ann.get(f"/api/groups/{g['id']}/members").status_code == 200
    assert ann.delete(f"/api/groups/{sub.json()['id']}").status_code == 204
    # its owner deletes a group with members: the app removes them first, through the rules (no cascade does)
    assert ann.delete(f"/api/groups/{g['id']}").status_code == 204
    assert ann.get(f"/api/groups/{g['id']}/members").status_code == 404


# --- search, and uploads straight to RustFS -----------------------------------------------------
def test_search_finds_only_what_you_may_see(world: World) -> None:
    alice = world["alice"]
    word = f"zebra{uuid.uuid4().hex[:6]}"
    alice.post(f"/api/folders/{world['top']['id']}/files", files={"file": (f"{word}_notes.txt", b"z")})
    found = alice.get(f"/api/search?q={word}").json()
    assert [f["name"] for f in found["files"]] == [f"{word}_notes.txt"]
    assert found["next"] == {"folder": None, "file": None}  # one page of each
    eve = person("eve")
    assert eve.get(f"/api/search?q={word}").json() == {
        "folders": [],
        "files": [],
        "next": {"folder": None, "file": None},
    }
    assert alice.get("/api/search?q=%25").status_code == 400  # too short


def test_search_pages_through_names_that_repeat() -> None:
    """Names repeat across folders: a page that ends inside a run of equal names goes on with the rest of it."""
    fay = person("fay")
    word = f"report{uuid.uuid4().hex[:6]}"
    made, parent = [], None
    for _ in range(55):  # each inside the one before, all with the same name
        r = fay.post("/api/folders", json={"name": word, "parent_id": parent})
        assert r.status_code == 201, r.text
        made.append(r.json()["id"])
        parent = made[-1]
    for name in ("a", "b"):
        assert (
            fay.post(f"/api/folders/{made[0]}/files", files={"file": (f"{word}-{name}.txt", b"x")}).status_code == 201
        )
    first = fay.get("/api/search", params={"q": word}).json()
    assert (len(first["folders"]), [f["name"] for f in first["files"]]) == (50, [f"{word}-a.txt", f"{word}-b.txt"])
    assert first["next"]["file"] is None and first["next"]["folder"]
    rest = fay.get("/api/search", params={"q": word, "kind": "folder", "after": first["next"]["folder"]}).json()
    assert (len(rest["folders"]), rest["files"], rest["next"]) == (5, [], {"folder": None, "file": None})
    assert sorted(f["id"] for f in first["folders"] + rest["folders"]) == made  # each once, none missed
    files = fay.get("/api/search", params={"q": word, "kind": "file"}).json()
    assert (files["folders"], len(files["files"]), files["next"]) == ([], 2, {"folder": None, "file": None})
    for params, said in (
        ({"after": first["next"]["folder"]}, "say which list the cursor is of (kind)"),
        ({"kind": "folder", "after": "nothing"}, "that isn't where a page of this search ends"),
        ({"kind": "folder", "after": "9" * 19 + ":x"}, "that isn't where a page of this search ends"),
    ):
        r = fay.get("/api/search", params={"q": word, **params})
        assert (r.status_code, r.json()) == (400, {"detail": said})


def test_uploading_straight_to_storage(world: World) -> None:
    alice, dave, sub = world["alice"], world["dave"], world["sub"]
    r = alice.post(
        f"/api/folders/{sub['id']}/uploads",
        json={"name": "direct.bin", "size": 5, "content_type": "application/x-test"},
    )
    assert r.status_code == 201, r.text
    started = r.json()
    fid = started["file"]["id"]
    assert fid not in [f["id"] for f in alice.get(f"/api/folders/{sub['id']}").json()["files"]]  # not ready yet
    assert alice.post(f"/api/files/{fid}/ready").status_code == 409  # no bytes yet
    put = httpx.put(started["url"], content=b"hello", headers={"Content-Type": "application/x-test"})
    assert put.status_code == 200, put.text
    ready = alice.post(f"/api/files/{fid}/ready")
    assert ready.status_code == 200 and ready.json()["size"] == 5
    assert download(alice, fid) == b"hello"
    assert dave.post(f"/api/folders/{world['top']['id']}/uploads", json={"name": "x", "size": 1}).status_code == 403


def test_the_upload_size_limit_holds_for_what_arrives(world: World, monkeypatch: pytest.MonkeyPatch) -> None:
    """FM_MAX_UPLOAD_BYTES: the size claimed when an upload starts, and the size of what the browser sent."""
    import dataclasses

    from app import main

    alice, sub = world["alice"], world["sub"]
    monkeypatch.setattr(main, "settings", dataclasses.replace(main.settings, max_upload_bytes=10))
    too_large = (413, {"detail": "the file is too large"})
    r = alice.post(f"/api/folders/{sub['id']}/files", files={"file": ("big.txt", b"x" * 11)})
    assert (r.status_code, r.json()) == too_large
    r = alice.post(f"/api/folders/{sub['id']}/uploads", json={"name": "big.bin", "size": 11})
    assert (r.status_code, r.json()) == too_large
    # claimed small, sent large: refused when confirmed, and what arrived is thrown away
    started = alice.post(f"/api/folders/{sub['id']}/uploads", json={"name": "claimed.bin", "size": 1}).json()
    put(started["url"], b"x" * 11, "application/octet-stream")
    r = alice.post(f"/api/files/{started['file']['id']}/ready")
    assert (r.status_code, r.json()) == too_large
    r = alice.post(f"/api/files/{started['file']['id']}/ready")
    assert (r.status_code, r.json()) == (409, {"detail": "the file's bytes haven't arrived"})
    assert "claimed.bin" not in [f["name"] for f in alice.get(f"/api/folders/{sub['id']}").json()["files"]]
    # the same for a new version
    f = alice.post(f"/api/folders/{sub['id']}/files", files={"file": ("small.txt", b"small")}).json()
    r = alice.post(f"/api/files/{f['id']}/versions", json={"name": "small.txt", "size": 11})
    assert (r.status_code, r.json()) == too_large
    v = alice.post(f"/api/files/{f['id']}/versions", json={"name": "small.txt", "size": 1}).json()
    put(v["url"], b"y" * 11, "application/octet-stream")
    r = alice.post(f"/api/versions/{v['version']['id']}/ready")
    assert (r.status_code, r.json()) == too_large
    assert download(alice, f["id"]) == b"small"
    assert alice.get(f"/api/files/{f['id']}").json()["size"] == 5


# --- share links ---------------------------------------------------------------------------------
def test_share_links(world: World) -> None:
    alice, top, sub, f = world["alice"], world["top"], world["sub"], world["file"]
    r = alice.post(f"/api/folders/{sub['id']}/links", json={})
    assert r.status_code == 201, r.text
    link = r.json()
    anon = TestClient(app)
    hdr = {"X-Link-Token": link["token"]}
    page = anon.get(f"/api/public/folders/{sub['id']}", headers=hdr)
    assert page.status_code == 200 and "plan.txt" in [x["name"] for x in page.json()["files"]]
    got = anon.get(f"/api/public/files/{f['id']}/download", headers=hdr).json()["url"]
    assert httpx.get(got).content == b"the plan"  # files inside come along
    assert anon.get(f"/api/public/folders/{top['id']}", headers=hdr).status_code == 404  # the folder above doesn't
    assert anon.get(f"/api/public/folders/{sub['id']}").status_code == 404  # no token
    assert anon.get(f"/api/public/folders/{sub['id']}", headers={"X-Link-Token": "guess"}).status_code == 404
    assert anon.get("/api/home").status_code == 401  # a link is not a sign-in
    listed = alice.get(f"/api/folders/{sub['id']}/links").json()  # from authz.list_links
    assert [(x["created_by"], x["expires_at"]) for x in listed] == [("alice", None)]
    link_id = listed[0]["id"]
    assert link_id not in link["token"]  # an id opens nothing
    assert anon.get(f"/api/public/folders/{sub['id']}", headers={"X-Link-Token": link_id}).status_code == 404
    viewer, stranger = person("viewer"), person("stranger")
    r = alice.post(
        f"/api/folders/{sub['id']}/shares",
        json={"relation": "viewer", "subject_type": "user", "subject_id": viewer.me["id"]},
    )
    assert r.status_code == 201, r.text
    assert viewer.get(f"/api/folders/{sub['id']}/links").status_code == 403  # he sees it, and can't share it
    assert viewer.delete(f"/api/folders/{sub['id']}/links/{link_id}").status_code == 403
    assert stranger.get(f"/api/folders/{sub['id']}/links").status_code == 404  # she doesn't see it
    assert stranger.delete(f"/api/folders/{sub['id']}/links/{link_id}").status_code == 404
    assert alice.delete(f"/api/folders/{sub['id']}/links/nothing").status_code == 404
    assert alice.delete(f"/api/folders/{top['id']}/links/{link_id}").status_code == 404  # it is the folder below's
    # the dialog's people: a link is not among them (it has its own list, above, and its own Turn off)
    shares = alice.get(f"/api/folders/{sub['id']}/shares").json()
    assert viewer.me["id"] in [s["subject_id"] for s in shares]
    assert [s for s in shares if s["subject_type"] == "link"] == []
    assert alice.delete(f"/api/folders/{sub['id']}/links/{link_id}").status_code == 204
    assert alice.get(f"/api/folders/{sub['id']}/links").json() == []
    assert anon.get(f"/api/public/folders/{sub['id']}", headers=hdr).status_code == 404  # revoked
    old = alice.post(f"/api/folders/{sub['id']}/links", json={"expires_at": "2000-01-01T00:00:00Z"}).json()
    assert anon.get(f"/api/public/folders/{sub['id']}", headers={"X-Link-Token": old["token"]}).status_code == 404
    # a link on a file opens that file, and nothing beside it
    r = alice.post(f"/api/files/{f['id']}/links", json={})
    assert r.status_code == 201, r.text
    hdr = {"X-Link-Token": r.json()["token"]}
    opened = anon.get(f"/api/public/files/{f['id']}", headers=hdr)
    assert (opened.status_code, opened.json()["name"]) == (200, "plan.txt")
    assert (
        httpx.get(anon.get(f"/api/public/files/{f['id']}/download", headers=hdr).json()["url"]).content == b"the plan"
    )
    assert anon.get(f"/api/public/files/{f['id']}").status_code == 404  # no token
    assert anon.get(f"/api/public/folders/{sub['id']}", headers=hdr).status_code == 404  # its folder isn't shared


def test_unfinished_uploads_are_cleaned_up(world: World) -> None:
    from app.main import storage
    from app.maintenance import abandoned_uploads

    alice, sub = world["alice"], world["sub"]
    started = alice.post(f"/api/folders/{sub['id']}/uploads", json={"name": "never.bin", "size": 3}).json()
    admin(
        "UPDATE fm.file_versions SET created_at = now() - interval '2 days' WHERE file_id = %s",
        (started["file"]["id"],),
    )
    with psycopg.connect(ADMIN, autocommit=True) as conn:
        assert abandoned_uploads(conn, storage, "1 day") >= 1
    assert admin("SELECT count(*) FROM fm.files WHERE id = %s", (started["file"]["id"],)) == [(0,)]


def test_the_maintenance_jobs(
    world: World, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """python -m app.maintenance: every job, and what each removed."""
    from app import maintenance

    alice = world["alice"]
    admin(
        "INSERT INTO fm.sessions (token_hash, user_id, expires_at) VALUES (%s, %s, now() - interval '1 minute')",
        (f"ended-{uuid.uuid4().hex}", alice.me["id"]),
    )
    monkeypatch.setattr(sys, "argv", ["maintenance", "--uploads-older-than", "1 hour"])
    maintenance.main()
    said = capsys.readouterr().out.splitlines()
    assert [line.split(" ", 2)[0::2] for line in said] == [
        ["removed", "unfinished uploads"],
        ["removed", "leftover uploaded objects"],
        ["removed", "sessions that ended"],
        ["trimmed", "change feed entries"],
    ], said
    assert int(said[2].split()[1]) >= 1
    assert admin("SELECT count(*) FROM fm.sessions WHERE expires_at < now()") == [(0,)]
    assert alice.get("/api/me").status_code == 200  # a session that goes on stays


# --- versions, quotas, previews ------------------------------------------------------------------
def put(url: str, body: bytes, content_type: str = "text/plain") -> None:
    r = httpx.put(url, content=body, headers={"Content-Type": content_type})
    assert r.status_code == 200, r.text


def test_versions(world: World) -> None:
    alice, carol, sub = world["alice"], world["carol"], world["sub"]
    started = alice.post(
        f"/api/folders/{sub['id']}/uploads", json={"name": "report.txt", "size": 2, "content_type": "text/plain"}
    ).json()
    fid = started["file"]["id"]
    put(started["url"], b"v1")
    alice.post(f"/api/files/{fid}/ready")
    v = carol.post(f"/api/files/{fid}/versions", json={"name": "report.txt", "size": 2, "content_type": "text/plain"})
    assert v.status_code == 201, v.text  # carol may edit here (shared above)
    put(v.json()["url"], b"v2")
    assert carol.post(f"/api/versions/{v.json()['version']['id']}/ready").status_code == 200
    assert download(alice, fid) == b"v2"
    history = alice.get(f"/api/files/{fid}/versions").json()
    assert [(h["current"], h["created_by_name"]) for h in history] == [(True, "carol"), (False, "alice")]
    assert alice.post(f"/api/versions/{history[1]['id']}/restore").status_code == 200
    assert download(alice, fid) == b"v1"
    old = alice.get(f"/api/versions/{history[0]['id']}/download").json()["url"]
    assert httpx.get(old).content == b"v2"  # older versions stay downloadable
    # someone the file is shared with to view sees its history, and changes nothing
    viewer, stranger = person("viewer"), person("stranger")
    r = alice.post(
        f"/api/files/{fid}/shares", json={"relation": "viewer", "subject_type": "user", "subject_id": viewer.me["id"]}
    )
    assert r.status_code == 201, r.text
    assert [h["id"] for h in viewer.get(f"/api/files/{fid}/versions").json()] == [h["id"] for h in history]
    assert viewer.post(f"/api/files/{fid}/versions", json={"name": "x", "size": 1}).status_code == 403
    assert viewer.post(f"/api/versions/{history[0]['id']}/restore").status_code == 403
    # someone who can't see the file: as if it weren't there
    assert stranger.get(f"/api/files/{fid}/versions").status_code == 404
    assert stranger.post(f"/api/files/{fid}/versions", json={"name": "x", "size": 1}).status_code == 404
    assert stranger.post(f"/api/versions/{history[0]['id']}/restore").status_code == 404
    assert download(alice, fid) == b"v1"


def test_a_file_cannot_point_at_another_files_object(world: World) -> None:
    from app import db

    alice, sub = world["alice"], world["sub"]
    mine = alice.post(f"/api/folders/{sub['id']}/files", files={"file": ("mine.txt", b"mine")}).json()
    # another file's older version: an object no file points at, so no unique index stands in the way
    other = alice.post(f"/api/folders/{sub['id']}/files", files={"file": ("other.txt", b"one")}).json()
    v = alice.post(f"/api/files/{other['id']}/versions", json={"name": "other.txt", "size": 3}).json()
    put(v["url"], b"two", "application/octet-stream")
    assert alice.post(f"/api/versions/{v['version']['id']}/ready").status_code == 200
    older = admin(
        "SELECT v.object_key FROM fm.file_versions v JOIN fm.files f ON f.id = v.file_id "
        "WHERE v.file_id = %s AND v.object_key <> f.object_key",
        (other["id"],),
    )
    assert len(older) == 1
    other_key = older[0][0]
    with pytest.raises(errors.InsufficientPrivilege), db.as_user(alice.me["id"]) as tx:  # even the owner, in SQL
        tx.run("UPDATE fm.files SET object_key = %s WHERE id = %s", (other_key, mine["id"]))
    with pytest.raises(errors.InsufficientPrivilege), db.as_user(alice.me["id"]) as tx:
        tx.run(
            "INSERT INTO fm.files (folder_id, owner_id, name, object_key) VALUES (%s, %s, 'copy', %s)",
            (sub["id"], alice.me["id"], other_key),
        )


def test_quotas() -> None:
    ivy = person("ivy")
    folder = ivy.post("/api/folders", json={"name": "Ivy"}).json()
    admin("UPDATE fm.users SET quota_bytes = 10 WHERE id = %s", (ivy.me["id"],))
    assert ivy.post(f"/api/folders/{folder['id']}/files", files={"file": ("a.txt", b"12345678")}).status_code == 201
    r = ivy.post(f"/api/folders/{folder['id']}/uploads", json={"name": "b.txt", "size": 5})
    assert r.status_code == 413 and "quota" in r.json()["detail"]
    me = ivy.get("/api/me").json()
    assert (me["used"], me["quota"]) == (8, 10)


def test_two_uploads_at_once_stay_within_the_quota() -> None:
    """Two uploads committing at the same time: the second waits for the first, then counts it."""
    import threading
    import time

    from app import db

    jo = person("jo")
    folder = jo.post("/api/folders", json={"name": "Jo"}).json()
    f = jo.post(f"/api/folders/{folder['id']}/files", files={"file": ("a.txt", b"")}).json()
    admin("UPDATE fm.users SET quota_bytes = 10 WHERE id = %s", (jo.me["id"],))
    version: LiteralString = "INSERT INTO fm.file_versions (file_id, size, created_by) VALUES (%s, 6, %s)"
    inserted, failed = threading.Event(), []

    def first() -> None:
        with db.as_user(jo.me["id"]) as tx:
            tx.run(version, (f["id"], jo.me["id"]))
            inserted.set()
            time.sleep(1)  # the second runs meanwhile; it may not pass without seeing this one

    t = threading.Thread(target=first)
    t.start()
    assert inserted.wait(10)
    try:
        with db.as_user(jo.me["id"]) as tx:
            tx.run(version, (f["id"], jo.me["id"]))
    except errors.ProgramLimitExceeded as e:
        failed.append(e.diag.message_primary)
    t.join()
    assert failed == ["storage quota exceeded: 12 of 10 bytes"]
    assert jo.get("/api/me").json()["used"] == 6


def test_previews(world: World) -> None:
    alice, sub = world["alice"], world["sub"]
    f = alice.post(f"/api/folders/{sub['id']}/files", files={"file": ("look.txt", b"hello", "text/plain")}).json()
    r = httpx.get(alice.get(f"/api/files/{f['id']}/download?preview=true").json()["url"])
    assert r.content == b"hello" and r.headers["content-disposition"] == "inline"
    page = alice.post(f"/api/folders/{sub['id']}/files", files={"file": ("page.html", b"<script>", "text/html")}).json()
    r = httpx.get(alice.get(f"/api/files/{page['id']}/download?preview=true").json()["url"])
    assert r.headers["content-disposition"] == "attachment"  # never rendered from the storage's origin


# --- what the app does around the policy ---------------------------------------------------------
def test_the_upload_link_is_spent_once_the_upload_is_confirmed(world: World) -> None:
    """The signed link goes on working for a few minutes: what it writes afterwards never reaches the file."""
    alice, sub = world["alice"], world["sub"]
    used = alice.get("/api/me").json()["used"]
    started = alice.post(
        f"/api/folders/{sub['id']}/uploads", json={"name": "once.txt", "size": 5, "content_type": "text/plain"}
    ).json()
    fid = started["file"]["id"]
    put(started["url"], b"hello")
    assert alice.post(f"/api/files/{fid}/ready").json()["size"] == 5
    put(started["url"], b"x" * 5000)  # the same link again, with more
    assert download(alice, fid) == b"hello"
    assert alice.get(f"/api/files/{fid}").json()["size"] == 5
    assert alice.get("/api/me").json()["used"] == used + 5
    assert alice.post(f"/api/files/{fid}/ready").status_code == 404  # confirmed already: nothing to confirm
    # the same for a new version of the file
    v = alice.post(
        f"/api/files/{fid}/versions", json={"name": "once.txt", "size": 3, "content_type": "text/plain"}
    ).json()
    put(v["url"], b"two")
    assert alice.post(f"/api/versions/{v['version']['id']}/ready").json()["size"] == 3
    put(v["url"], b"y" * 4000)
    assert download(alice, fid) == b"two"
    # and what was sent after is swept away later
    from datetime import timedelta

    from app.main import storage

    assert storage.sweep_uploads(timedelta(days=-1)) >= 2  # (everything there, whatever the clocks say)


def test_looking_people_up(world: World) -> None:
    bob = world["bob"]
    assert bob.get("/api/users", params={"q": ""}).json() == []  # not a list of everyone
    assert bob.get("/api/users", params={"q": "%"}).json() == []
    assert bob.get("/api/users", params={"q": "%%"}).json() == []  # % is a character, not "anything"
    assert world["alice"].me["email"] in [u["email"] for u in bob.get("/api/users", params={"q": "alice-"}).json()]


def test_lint_has_nothing_new_to_say() -> None:
    """authz.lint() on the app's database: no warning but the ones listed here, each with its reason."""
    known = {
        # they run as the owner on purpose: accounts and quotas are the app's, outside the policy
        "fm.sign_up(text,text,text)",
        "fm.my_usage()",
        "fm.check_quota()",
        "fm.key_is_new(uuid)",
    }
    found = admin("SELECT severity, object, problem FROM authz.lint() WHERE severity NOT IN ('info')")
    assert {o for _, o, _ in found} <= known, found


def test_an_unknown_api_path_is_not_the_web_page() -> None:
    r = person("zed").get("/api/no-such-thing")
    assert r.status_code == 404, r.text


def test_migrate_runs_outside_this_repository(tmp_path: Path) -> None:
    """db/migrate.py copied into an app of its own: no rowstile checkout above it, the command the one installed."""
    db_dir = Path(__file__).resolve().parents[2] / "db"
    shutil.copytree(db_dir, tmp_path / "db")
    (tmp_path / "backend" / "app").mkdir(parents=True)
    (tmp_path / "bin").mkdir()
    installed = tmp_path / "bin" / "rowstile"
    installed.write_text('#!/bin/sh\necho "# written by rowstile $*"\n', encoding="utf-8")
    installed.chmod(0o755)
    env = {**os.environ, "PATH": f"{tmp_path / 'bin'}{os.pathsep}{os.environ['PATH']}"}
    # each migration was applied already: there is nothing to run, and with --client only the client to write
    for args, said in (([], ""), (["--client"], "wrote backend/app/authz_client.py\n")):
        p = subprocess.run(
            [sys.executable, str(tmp_path / "db" / "migrate.py"), *args], env=env, capture_output=True, text=True
        )
        assert (p.returncode, p.stderr, p.stdout) == (0, "", said)
    client = (tmp_path / "backend" / "app" / "authz_client.py").read_text(encoding="utf-8")
    assert client == f"# written by rowstile client py {tmp_path / 'db' / 'policy.authz'}\n"


# --- what the README and docs/signed-urls.md say -------------------------------------------------
EXAMPLE = Path(__file__).resolve().parents[2]


def readme_rows() -> dict[str, str]:
    """The README's tables: each row's first cell (in backticks), and the rest of the row."""
    readme = (EXAMPLE / "README.md").read_text(encoding="utf-8")
    return {m[1]: m[2] for m in re.finditer(r"^\| `([^`]+)` \|(.*)\|$", readme, re.M)}


def test_the_readme_gives_each_setting_and_its_default(monkeypatch: pytest.MonkeyPatch) -> None:
    """The settings table: every FM_ variable the backend and db/migrate.py read, each with the default it has."""
    from app import config

    sources = [*(EXAMPLE / "backend" / "app").glob("*.py"), EXAMPLE / "db" / "migrate.py"]
    read = {name for p in sources for name in re.findall(r"\"(FM_[A-Z0-9_]+)\"", p.read_text(encoding="utf-8"))}
    defaults = {k: re.fullmatch(r" `([^`]*)` | (none) ", v.split("|")[0]) for k, v in readme_rows().items()}
    shown = {k: m[1] or m[2] for k, m in defaults.items() if k.startswith("FM_") and m}
    assert sorted(shown) == sorted(read)
    for name in read:
        monkeypatch.delenv(name, raising=False)
    settings = config.load()
    fields = dataclasses.fields(settings)
    for field in fields:
        name, value = f"FM_{field.name.upper()}", getattr(settings, field.name)
        default = shown[shown[name]] if shown[name] in shown else shown[name]  # or another setting's value
        if isinstance(value, bool):
            value = str(value).lower()
        assert default == (",".join(value) if isinstance(value, tuple) else str(value)), name
    # the two the backend doesn't read at start: db/migrate.py and the maintenance jobs need them
    rest = {k: v for k, v in shown.items() if k not in {f"FM_{f.name.upper()}" for f in fields}}
    assert rest == {"FM_ADMIN_URL": "none", "FM_APP_PASSWORD": "none"}


def test_the_readme_names_each_part_of_the_backend() -> None:
    """The table of how it fits together: each module of backend/app, and only paths that are there."""
    paths = [k for k in readme_rows() if "/" in k or "." in k]
    assert [p for p in paths if not (EXAMPLE / p).exists()] == []
    modules = sorted(p.name for p in (EXAMPLE / "backend" / "app").glob("*.py") if p.name != "__init__.py")
    assert [m for m in modules if f"backend/app/{m}" not in paths] == []


def test_the_signed_url_page_uploads_where_the_example_does() -> None:
    """docs/signed-urls.md: the upload link points at the upload's own place, which confirming moves from."""
    from app.storage import Storage

    page = (EXAMPLE.parents[1] / "docs" / "signed-urls.md").read_text(encoding="utf-8")
    assert f"presigned `PUT` URL for `{Storage.UPLOADS}<object_key>`, not for the object's own key" in page
    assert f'CopySource={{"Bucket": BUCKET, "Key": "{Storage.UPLOADS}" + key}}' in page


def test_the_app_does_not_start_as_the_tables_owner(monkeypatch: pytest.MonkeyPatch) -> None:
    """Last: it opens and closes the pool. With the owner's URL, row-level security would be skipped."""
    import dataclasses

    from app import db, main

    monkeypatch.setattr(main, "settings", dataclasses.replace(main.settings, database_url=ADMIN))
    try:
        with pytest.raises(RuntimeError, match="can't be used with rowstile"), TestClient(app):
            pass
    finally:
        monkeypatch.undo()
        db.open_pool(main.settings.database_url)  # for the session's own shutdown

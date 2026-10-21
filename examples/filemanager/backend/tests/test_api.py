"""The API against real Postgres (with rowstile and db/policy.authz applied) and RustFS: run test.sh.

Every check goes through HTTP as a signed-in person, so what it proves is what row-level security and
the authz.* functions decide, end to end.
"""

import os
import shutil
import subprocess
import sys
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any, LiteralString, TypedDict

import httpx
import psycopg
import pytest
from app.main import app
from fastapi.testclient import TestClient
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


def test_a_folder_cannot_go_inside_itself(world: World) -> None:
    alice, top, sub = world["alice"], world["top"], world["sub"]
    assert alice.patch(f"/api/folders/{top['id']}", json={"parent_id": sub["id"]}).status_code == 400


def test_a_folder_with_contents_cannot_be_deleted(world: World) -> None:
    assert world["alice"].delete(f"/api/folders/{world['sub']['id']}").status_code == 409


def test_names_are_unique_in_a_folder(world: World) -> None:
    alice, sub = world["alice"], world["sub"]
    r = alice.post(f"/api/folders/{sub['id']}/files", files={"file": ("plan.txt", b"again")})
    assert r.status_code == 409


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


def test_editors_may_add_files(world: World) -> None:
    alice, carol, sub = world["alice"], world["carol"], world["sub"]
    alice.post(
        f"/api/folders/{sub['id']}/shares",
        json={"relation": "editor", "subject_type": "user", "subject_id": carol.me["id"]},
    )
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
    alice.post(
        f"/api/folders/{top['id']}/shares",
        json={"relation": "viewer", "subject_type": "group", "subject_id": str(group)},
    )
    assert dave.get(f"/api/folders/{top['id']}").status_code == 200  # a member of a sub-group
    alice.request(
        "DELETE",
        f"/api/folders/{top['id']}/shares",
        json={"relation": "viewer", "subject_type": "group", "subject_id": str(group)},
    )
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
    assert [r["id"] for r in alice.get("/api/requests").json() if not r["mine"]] == [rid]
    assert dave.post(f"/api/requests/{rid}/decision", json={"approve": True}).status_code >= 400  # not his to decide
    assert alice.post(f"/api/requests/{rid}/decision", json={"approve": True, "note": "ok"}).status_code == 200
    assert dave.get(f"/api/folders/{sub['id']}").status_code == 200


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
    dan.post(
        f"/api/folders/{folder['id']}/shares",
        json={"relation": "viewer", "subject_type": "group", "subject_id": g["id"]},
    )
    assert ben.get(f"/api/folders/{folder['id']}").status_code == 200
    assert cat.get(f"/api/folders/{folder['id']}").status_code == 404  # she left
    assert dan.delete(f"/api/groups/{g['id']}").status_code == 403
    # its owner deletes a group with members: the app removes them first, through the rules (no cascade does)
    gone = ann.post("/api/groups", json={"name": f"Gone {uuid.uuid4().hex[:6]}"}).json()
    assert ann.post(f"/api/groups/{gone['id']}/members", json={"user_id": ben.me["id"]}).status_code == 201
    assert ann.delete(f"/api/groups/{gone['id']}").status_code == 204
    assert ann.get(f"/api/groups/{gone['id']}/members").status_code == 404


# --- search, and uploads straight to RustFS -----------------------------------------------------
def test_search_finds_only_what_you_may_see(world: World) -> None:
    alice = world["alice"]
    word = f"zebra{uuid.uuid4().hex[:6]}"
    alice.post(f"/api/folders/{world['top']['id']}/files", files={"file": (f"{word}_notes.txt", b"z")})
    assert [f["name"] for f in alice.get(f"/api/search?q={word}").json()["files"]] == [f"{word}_notes.txt"]
    eve = person("eve")
    assert eve.get(f"/api/search?q={word}").json() == {"folders": [], "files": []}
    assert alice.get("/api/search?q=%25").status_code == 400  # too short


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


# --- share links ---------------------------------------------------------------------------------
def test_share_links(world: World) -> None:
    alice, dave, top, sub, f = world["alice"], world["dave"], world["top"], world["sub"], world["file"]
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
    assert dave.get(f"/api/folders/{sub['id']}/links").status_code in (403, 404)  # he can't share it
    assert dave.delete(f"/api/folders/{sub['id']}/links/{link_id}").status_code in (403, 404)
    assert alice.delete(f"/api/folders/{sub['id']}/links/nothing").status_code == 404
    assert alice.delete(f"/api/folders/{top['id']}/links/{link_id}").status_code == 404  # it is the folder below's
    assert alice.delete(f"/api/folders/{sub['id']}/links/{link_id}").status_code == 204
    assert alice.get(f"/api/folders/{sub['id']}/links").json() == []
    assert anon.get(f"/api/public/folders/{sub['id']}", headers=hdr).status_code == 404  # revoked
    old = alice.post(f"/api/folders/{sub['id']}/links", json={"expires_at": "2000-01-01T00:00:00Z"}).json()
    assert anon.get(f"/api/public/folders/{sub['id']}", headers={"X-Link-Token": old["token"]}).status_code == 404


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


# --- versions, quotas, previews ------------------------------------------------------------------
def put(url: str, body: bytes, content_type: str = "text/plain") -> None:
    r = httpx.put(url, content=body, headers={"Content-Type": content_type})
    assert r.status_code == 200, r.text


def test_versions(world: World) -> None:
    alice, carol, dave, sub = world["alice"], world["carol"], world["dave"], world["sub"]
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
    assert dave.post(f"/api/files/{fid}/versions", json={"name": "x", "size": 1}).status_code in (403, 404)
    assert dave.get(f"/api/files/{fid}/versions").status_code in (200, 404)
    assert dave.post(f"/api/versions/{history[0]['id']}/restore").status_code in (403, 404)


def test_a_file_cannot_point_at_another_files_object(world: World) -> None:
    from app import db

    alice, sub = world["alice"], world["sub"]
    mine = alice.post(f"/api/folders/{sub['id']}/files", files={"file": ("mine.txt", b"mine")}).json()
    other_key = admin("SELECT object_key FROM fm.files WHERE id = %s", (world["file"]["id"],))[0][0]
    with pytest.raises(psycopg.Error), db.as_user(alice.me["id"]) as tx:  # even the owner, straight through SQL
        tx.run("UPDATE fm.files SET object_key = %s WHERE id = %s", (other_key, mine["id"]))
    with pytest.raises(psycopg.Error), db.as_user(alice.me["id"]) as tx:
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

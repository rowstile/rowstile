"""The API against real Postgres with rowstile and db/policy.authz applied: run test.sh.

Every check goes through HTTP as a signed-in person (or a bot with its key), so what it proves is what
row-level security decides: the backend has no permission checks of its own.
"""

import json
import os
import random
import shutil
import subprocess
import sys
import threading
from collections.abc import Iterator
from pathlib import Path
from typing import Any, LiteralString

import psycopg
import pytest
from app.main import app
from fastapi.testclient import TestClient
from psycopg.abc import Params

ADMIN = os.environ["MS_ADMIN_URL"]
# an answer from the API: its shape is what the checks check
Answer = Any


class Person(TestClient):
    """A client signed in as someone, and who they are (the API's answer at sign-up)."""

    me: Answer


@pytest.fixture(scope="session", autouse=True)
def running() -> Iterator[None]:
    """The app's startup and shutdown (the connection pool, the event listener), once for every test."""
    with TestClient(app):
        yield


def person(name: str) -> Person:
    """A new account, signed in: a TestClient carrying its session cookie."""
    c = Person(app)
    phone = f"+1555{random.randrange(10**7):07d}"
    r = c.post("/api/signup", json={"phone": phone, "name": name, "password": "correct horse"})
    assert r.status_code == 200, r.text
    c.me = r.json()
    return c


def admin(sql: LiteralString, args: Params = ()) -> list[tuple[Answer, ...]]:
    with psycopg.connect(ADMIN, autocommit=True) as conn:
        cur = conn.execute(sql, args)
        return cur.fetchall() if cur.description else []  # the rows, if it returns any


def direct(a: Person, b: Person) -> int:
    r = a.post("/api/chats", json={"kind": "direct", "user_id": b.me["id"]})
    assert r.status_code == 201, r.text
    return r.json()["id"]


def group(owner: Person, *others: Person, title: str = "Weekend") -> int:
    r = owner.post("/api/chats", json={"kind": "group", "title": title, "member_ids": [o.me["id"] for o in others]})
    assert r.status_code == 201, r.text
    return r.json()["id"]


def say(c: TestClient, chat_id: int, text: str) -> Answer:
    return c.post(f"/api/chats/{chat_id}/messages", json={"body": text})


def bodies(c: TestClient, chat_id: int) -> list[str] | int:
    r = c.get(f"/api/chats/{chat_id}/messages")
    return [m["body"] for m in r.json()] if r.status_code == 200 else r.status_code


# --- accounts ------------------------------------------------------------------------------------
def test_accounts() -> None:
    c = TestClient(app)
    phone = f"+44 7700 {random.randrange(10**6):06d}"
    assert c.post("/api/signup", json={"phone": phone, "name": "Eve", "password": "long enough"}).status_code == 200
    assert c.get("/api/me").json()["name"] == "Eve"
    assert c.post("/api/logout").status_code == 200
    assert c.get("/api/me").status_code == 401
    assert c.post("/api/login", json={"phone": phone, "password": "wrong password"}).status_code == 401
    # a session that ended is removed when someone next signs in
    admin("INSERT INTO ms.sessions VALUES ('ended', (SELECT id FROM ms.users LIMIT 1), now() - interval '1 day')")
    assert c.post("/api/login", json={"phone": phone.replace(" ", ""), "password": "long enough"}).status_code == 200
    assert admin("SELECT count(*) FROM ms.sessions WHERE expires_at < now()")[0][0] == 0


def test_people_are_found_by_phone() -> None:
    a, b = person("Ann"), person("Ben")
    assert [p["name"] for p in a.get("/api/people", params={"phone": b.me["phone"]}).json()] == ["Ben"]


# --- direct chats ----------------------------------------------------------------------------------
def test_direct_chat() -> None:
    ann, ben, cat = person("Ann"), person("Ben"), person("Cat")
    chat = direct(ann, ben)
    assert direct(ben, ann) == chat  # one chat per pair
    assert say(ann, chat, "hi Ben").status_code == 201
    assert say(ben, chat, "hi Ann").status_code == 201
    assert bodies(ben, chat) == ["hi Ben", "hi Ann"]
    assert bodies(cat, chat) == 404  # not in it: it doesn't exist
    assert say(cat, chat, "hello?").status_code == 404
    assert [c["name"] for c in ann.get("/api/chats").json()] == ["Ben"]
    assert ann.get("/api/chats").json()[0]["unread"] == 1  # Ben's message
    # a direct chat stays two people
    r = ann.post(f"/api/chats/{chat}/members", json={"user_id": cat.me["id"]})
    assert r.status_code == 403 and r.json()["why"], r.text


def test_one_direct_chat_for_two_people() -> None:
    ann, ben, cat = person("Ann"), person("Ben"), person("Cat")
    direct(ann, ben)
    # the database keeps it so, whoever writes: a second chat for the same two is refused as its second member joins
    other = admin("INSERT INTO ms.chats (kind, created_by) VALUES ('direct', %s) RETURNING id", (ann.me["id"],))[0][0]
    admin("INSERT INTO ms.members (chat_id, user_id) VALUES (%s, %s)", (other, ann.me["id"]))
    with pytest.raises(psycopg.errors.UniqueViolation):
        admin("INSERT INTO ms.members (chat_id, user_id) VALUES (%s, %s)", (other, ben.me["id"]))
    # two requests at the same moment get the one chat
    got: list[int] = []
    asking = [threading.Thread(target=lambda a=a, b=b: got.append(direct(a, b))) for a, b in ((ann, cat), (cat, ann))]
    for t in asking:
        t.start()
    for t in asking:
        t.join()
    assert len(got) == 2 and got[0] == got[1], got


def test_blocking() -> None:
    ann, ben = person("Ann"), person("Ben")
    chat = direct(ann, ben)
    assert ann.post("/api/blocks", json={"user_id": ben.me["id"]}).status_code == 201
    r = say(ben, chat, "are you there?")
    assert r.status_code == 403
    assert any("blocked" in line for line in r.json()["why"]), r.json()  # authz.explain says why
    assert say(ann, chat, "no").status_code == 403  # nor the other way, while blocked
    assert "post" not in ann.get(f"/api/chats/{chat}").json()["perms"]
    assert ann.delete(f"/api/blocks/{ben.me['id']}").status_code == 204
    r = say(ben, chat, "hello again")
    assert r.status_code == 201, r.text  # with the reason, should it be refused
    # someone who blocked you can't be put in a chat with you
    cat = person("Cat")
    cat.post("/api/blocks", json={"user_id": ann.me["id"]})
    assert ann.post("/api/chats", json={"kind": "direct", "user_id": cat.me["id"]}).status_code == 403
    g = group(ann, ben)
    assert ann.post(f"/api/chats/{g}/members", json={"user_id": cat.me["id"]}).status_code == 403


# --- groups ------------------------------------------------------------------------------------------
def test_group_roles() -> None:
    ann, ben, cat, dan = person("Ann"), person("Ben"), person("Cat"), person("Dan")
    g = group(ann, ben, cat)
    info = ann.get(f"/api/chats/{g}").json()
    assert [(m["name"], m["role"]) for m in info["members"]] == [("Ann", "owner"), ("Ben", "member"), ("Cat", "member")]
    assert "manage" in info["perms"] and "manage" not in ben.get(f"/api/chats/{g}").json()["perms"]
    # members can't add people, rename the group, or make themselves admin
    assert ben.post(f"/api/chats/{g}/members", json={"user_id": dan.me["id"]}).status_code == 403
    assert ben.patch(f"/api/chats/{g}", json={"title": "Mine now"}).status_code == 403
    assert ben.patch(f"/api/chats/{g}/members/{ben.me['id']}", json={"role": "admin"}).status_code == 403
    # the owner makes Ben an admin; Ben adds Dan and renames the group
    assert ann.patch(f"/api/chats/{g}/members/{ben.me['id']}", json={"role": "admin"}).status_code == 200
    assert ben.post(f"/api/chats/{g}/members", json={"user_id": dan.me["id"]}).status_code == 201
    assert ben.patch(f"/api/chats/{g}", json={"title": "Weekend trip"}).json()["title"] == "Weekend trip"
    # nobody touches the owner: not their role, not their membership
    assert ben.patch(f"/api/chats/{g}/members/{ann.me['id']}", json={"role": "member"}).status_code == 403
    assert ben.delete(f"/api/chats/{g}/members/{ann.me['id']}").status_code == 403
    # admins remove members; anyone may leave
    assert ben.delete(f"/api/chats/{g}/members/{cat.me['id']}").status_code == 204
    assert bodies(cat, g) == 404
    assert dan.delete(f"/api/chats/{g}/members/{dan.me['id']}").status_code == 204
    # the owner doesn't leave either: a group without one could never be deleted. They delete it instead
    r = ann.delete(f"/api/chats/{g}/members/{ann.me['id']}")
    assert r.status_code == 403 and "the owner stays" in r.json()["detail"] and r.json()["why"], r.text
    # only the owner deletes the group
    assert ben.delete(f"/api/chats/{g}").status_code == 403
    assert ann.delete(f"/api/chats/{g}").status_code == 204


def test_new_members_read_from_when_they_joined() -> None:
    ann, ben, cat = person("Ann"), person("Ben"), person("Cat")
    g = group(ann, ben)
    say(ann, g, "before Cat")
    ann.post(f"/api/chats/{g}/members", json={"user_id": cat.me["id"]})
    say(ben, g, "welcome Cat")
    assert bodies(cat, g) == ["welcome Cat"]
    assert bodies(ben, g) == ["before Cat", "welcome Cat"]
    # what was said before she joined is not unread for her either
    assert [c["unread"] for c in cat.get("/api/chats").json()] == [1]


def test_a_clock_that_steps_back_refuses_nothing() -> None:
    """What was said since you joined goes by the message's number: a joined_at ahead of now (what a clock that
    stepped back leaves) changes nothing."""
    ann, ben = person("Ann"), person("Ben")
    chat = direct(ann, ben)
    admin("UPDATE ms.members SET joined_at = now() + interval '1 hour' WHERE chat_id = %s", (chat,))
    r = say(ben, chat, "hello")
    assert r.status_code == 201, r.text
    assert bodies(ann, chat) == ["hello"] and bodies(ben, chat) == ["hello"]


def test_only_setting_a_group_up_makes_its_owner() -> None:
    """The API never sends a role when adding someone: the policy alone must refuse an admin adding an owner."""
    from app import db

    ann, ben, cat, dan = person("Ann"), person("Ben"), person("Cat"), person("Dan")
    g = group(ann, ben)
    assert ann.patch(f"/api/chats/{g}/members/{ben.me['id']}", json={"role": "admin"}).status_code == 200
    with pytest.raises(psycopg.errors.InsufficientPrivilege), db.as_user(ben.me["id"]) as tx:
        tx.run("INSERT INTO ms.members (chat_id, user_id, role) VALUES (%s, %s, 'owner')", (g, cat.me["id"]))
    with db.as_user(ben.me["id"]) as tx:  # an admin may add an admin
        tx.run("INSERT INTO ms.members (chat_id, user_id, role) VALUES (%s, %s, 'admin')", (g, dan.me["id"]))
    say(ann, g, "before Cat")
    with db.as_user(ann.me["id"]) as tx:  # joined_seq is the database's to say
        tx.run("INSERT INTO ms.members (chat_id, user_id, joined_seq) VALUES (%s, %s, 0)", (g, cat.me["id"]))
    assert bodies(cat, g) == []


def test_several_rows_at_once_keep_the_counts() -> None:
    """A rule checks each row against the tables as the statement found them: one INSERT of several rows passes a
    count that each row passes alone. The API adds one row a statement; the schema holds the counts for any writer."""
    from app import db

    ann, ben, cat = person("Ann"), person("Ben"), person("Cat")
    three = "INSERT INTO ms.members (chat_id, user_id) VALUES (%s, %s), (%s, %s), (%s, %s)"
    with db.as_user(ann.me["id"]) as tx:
        d = tx.one("INSERT INTO ms.chats (kind, created_by) VALUES ('direct', %s) RETURNING id", (ann.me["id"],))["id"]
    with (
        pytest.raises(psycopg.errors.CheckViolation, match="a direct chat is two people"),
        db.as_user(ann.me["id"]) as tx,
    ):
        tx.run(three, (d, ann.me["id"], d, ben.me["id"], d, cat.me["id"]))
    # ... nor after one of the two left
    chat = direct(ann, ben)
    assert ben.delete(f"/api/chats/{chat}/members/{ben.me['id']}").status_code == 204
    with (
        pytest.raises(psycopg.errors.CheckViolation, match="a direct chat is two people"),
        db.as_user(ann.me["id"]) as tx,
    ):
        tx.run(
            "INSERT INTO ms.members (chat_id, user_id) VALUES (%s, %s), (%s, %s)",
            (chat, ben.me["id"], chat, cat.me["id"]),
        )
    # one owner, also when the group is set up by one statement
    with db.as_user(ann.me["id"]) as tx:
        g = tx.one(
            "INSERT INTO ms.chats (kind, title, created_by) VALUES ('group', 'Two owners', %s) RETURNING id",
            (ann.me["id"],),
        )["id"]
    with pytest.raises(psycopg.errors.UniqueViolation, match="members_one_owner"), db.as_user(ann.me["id"]) as tx:
        tx.run(
            "INSERT INTO ms.members (chat_id, user_id, role) VALUES (%s, %s, 'owner'), (%s, %s, 'owner')",
            (g, ann.me["id"], g, ben.me["id"]),
        )


def test_lint_has_nothing_new_to_say() -> None:
    """authz.lint() on the app's database: no warning but the ones listed here, each with its reason."""
    known = {"ms.credentials_for(text)", "ms.sign_up(text,text,text)"}  # accounts are the app's, outside the policy
    found = admin("SELECT severity, object, problem FROM authz.lint() WHERE severity NOT IN ('info')")
    assert {o for _, o, _ in found} <= known, found
    # the app role doesn't read password hashes: signing in goes through the two functions above
    with psycopg.connect(os.environ["MS_DATABASE_URL"]) as conn, pytest.raises(psycopg.errors.InsufficientPrivilege):
        conn.execute("SELECT count(*) FROM ms.credentials")


def test_announcements() -> None:
    ann, ben = person("Ann"), person("Ben")
    g = group(ann, ben, title="News")
    assert ann.patch(f"/api/chats/{g}", json={"admins_only": True}).status_code == 200
    r = say(ben, g, "can I say something?")
    assert r.status_code == 403 and r.json()["detail"] == "you can't send messages here"
    assert say(ann, g, "Only admins post here").status_code == 201
    assert bodies(ben, g) == ["Only admins post here"]


def test_editing_and_deleting() -> None:
    ann, ben = person("Ann"), person("Ben")
    g = group(ann, ben)
    seq = say(ben, g, "teh plan").json()["seq"]
    mine = ben.get(f"/api/chats/{g}/messages").json()[-1]
    assert mine["can_edit"] and mine["can_remove"]
    assert not ann.get(f"/api/chats/{g}/messages").json()[-1]["can_edit"]  # not Ann's message...
    assert ann.get(f"/api/chats/{g}/messages").json()[-1]["can_remove"]  # ...but she is an admin
    assert ben.patch(f"/api/chats/{g}/messages/{seq}", json={"body": "the plan"}).status_code == 200
    assert ann.patch(f"/api/chats/{g}/messages/{seq}", json={"body": "my plan"}).status_code == 403
    assert bodies(ann, g) == ["the plan"]
    # after 15 minutes, no more editing
    admin("UPDATE ms.messages SET created_at = now() - interval '1 hour' WHERE chat_id = %s AND seq = %s", (g, seq))
    r = ben.patch(f"/api/chats/{g}/messages/{seq}", json={"body": "the real plan"})
    assert r.status_code == 403 and r.json()["why"]
    # deleting for everyone: the author, or an admin
    seq2 = say(ann, g, "oops").json()["seq"]
    assert ben.delete(f"/api/chats/{g}/messages/{seq2}").status_code == 403
    assert ben.delete(f"/api/chats/{g}/messages/{seq}").status_code == 200
    assert ann.delete(f"/api/chats/{g}/messages/{seq2}").status_code == 200
    assert [m["deleted"] for m in ann.get(f"/api/chats/{g}/messages").json()] == [True, True]


def test_invite_links() -> None:
    ann, ben, cat = person("Ann"), person("Ben"), person("Cat")
    g = group(ann, ben, title="Book club")
    assert ben.post(f"/api/chats/{g}/invite").status_code == 403  # not an admin
    token = ann.post(f"/api/chats/{g}/invite").json()["token"]
    # its maker, an admin, may join without it: the chat the link names (?chat=, as the web app writes it) answers
    assert ann.get(f"/api/join/{token}").status_code == 404
    mine = ann.get(f"/api/join/{token}", params={"chat": g}).json()
    assert (mine["id"], mine["title"], mine["member"]) == (g, "Book club", True)
    assert ann.post(f"/api/join/{token}", params={"chat": g}).json() == {"id": g}
    assert ben.get(f"/api/join/{token}").json()["member"] is True  # a member who isn't an admin needs no name
    assert cat.get("/api/join/not-a-token", params={"chat": g}).status_code == 404  # it names a chat, nothing more
    assert cat.get(f"/api/join/{token}").json()["title"] == "Book club"  # the link shows the group...
    assert bodies(cat, g) == 404  # ...not its messages
    assert cat.get("/api/join/not-a-token").status_code == 404
    assert cat.post(f"/api/join/{token}").json()["id"] == g
    assert say(cat, g, "hello book club").status_code == 201
    assert [m["role"] for m in ann.get(f"/api/chats/{g}").json()["members"] if m["name"] == "Cat"] == ["member"]
    # the links are listed and turned off by those who may make them (authz.list_links, authz.revoke_link)
    listed = ann.get(f"/api/chats/{g}/invites").json()
    assert [x["created_by"] for x in listed] == ["Ann"] and listed[0]["expires_at"]
    link_id = listed[0]["id"]
    assert link_id not in token and cat.get(f"/api/join/{link_id}").status_code == 404  # an id opens nothing
    assert ben.get(f"/api/chats/{g}/invites").status_code == 403  # not an admin
    assert ben.delete(f"/api/chats/{g}/invites/{link_id}").status_code == 403
    assert ann.delete(f"/api/chats/{g}/invites/nothing").status_code == 404
    assert ann.delete(f"/api/chats/{g}/invites/{link_id}").status_code == 204
    assert ann.get(f"/api/chats/{g}/invites").json() == []
    dan = person("Dan")
    assert dan.get(f"/api/join/{token}").status_code == 404 and dan.post(f"/api/join/{token}").status_code == 404
    assert say(cat, g, "still here").status_code == 201  # who joined with it stays


def test_read_receipts() -> None:
    ann, ben = person("Ann"), person("Ben")
    chat = direct(ann, ben)
    seq = say(ann, chat, "read this").json()["seq"]
    assert ben.get("/api/chats").json()[0]["unread"] == 1
    ben.post(f"/api/chats/{chat}/read", json={"seq": seq})
    assert ben.get("/api/chats").json()[0]["unread"] == 0
    seen = {m["name"]: m["last_read_seq"] for m in ann.get(f"/api/chats/{chat}").json()["members"]}
    assert seen["Ben"] == seq


def test_the_chat_list_counts_unread_without_reading_them() -> None:
    """Unread is a difference of numbers: the chat list reads one message a chat (the last), not every unread one,
    each of which the read rule would check with a call of its own."""
    from app import db
    from app.main import CHAT_LIST

    ann, ben = person("Ann"), person("Ben")
    g = group(ann, ben)
    for i in range(30):
        say(ann, g, f"news {i}")
    assert [c["unread"] for c in ben.get("/api/chats").json()] == [30]
    assert [c["unread"] for c in ann.get("/api/chats").json()] == [0]  # what you post is read: your mark moves past it
    with db.as_user(ben.me["id"]) as tx:
        plan = tx.rows("EXPLAIN (ANALYZE, FORMAT JSON) " + CHAT_LIST, {"me": ben.me["id"]})[0]["QUERY PLAN"]

    def read(node: Answer) -> int:
        """The rows of ms.messages a plan node and those under it read."""
        own = node.get("Actual Rows", 0) * node.get("Actual Loops", 1) if node.get("Relation Name") == "messages" else 0
        return own + sum(read(n) for n in node.get("Plans", []))

    assert read(plan[0]["Plan"]) == 1
    say(ben, g, "mine")
    say(ann, g, "more news")
    assert [c["unread"] for c in ben.get("/api/chats").json()] == [1]


def test_numbers_out_of_range_are_the_requests_fault() -> None:
    """A number the database can't take answers 422 (the API's bounds) or 400 (the database's words), never 500."""
    ann, ben = person("Ann"), person("Ben")
    g = group(ann, ben)
    for params in ({"limit": -1}, {"limit": 0}, {"limit": 201}, {"before": 2**63}, {"after": -1}):
        assert ann.get(f"/api/chats/{g}/messages", params=params).status_code == 422, params
    assert ann.post(f"/api/chats/{g}/read", json={"seq": 2**63}).status_code == 422
    assert ann.post(f"/api/chats/{g}/read", json={"seq": -1}).status_code == 422
    r = ann.post(f"/api/chats/{g}/bots", json={"bot_id": 2**63})
    assert (r.status_code, r.json()) == (400, {"detail": "bigint out of range"})


def test_message_pages() -> None:
    ann, ben = person("Ann"), person("Ben")
    chat = direct(ann, ben)
    seqs = [say(ann, chat, f"m{i}").json()["seq"] for i in range(4)]
    page = ben.get(f"/api/chats/{chat}/messages", params={"limit": 2}).json()
    assert [m["body"] for m in page] == ["m2", "m3"]  # the latest, oldest first
    page = ben.get(f"/api/chats/{chat}/messages", params={"before": seqs[2]}).json()
    assert [m["body"] for m in page] == ["m0", "m1"]
    page = ben.get(f"/api/chats/{chat}/messages", params={"after": seqs[1]}).json()
    assert [m["body"] for m in page] == ["m2", "m3"]


def test_why_says_what_is_missing() -> None:
    """What the web app's "why?" under a closed composer asks: the database's explanation (authz.explain)."""
    ann, ben, cat = person("Ann"), person("Ben"), person("Cat")
    g = group(ann, ben, title="News")
    assert ann.patch(f"/api/chats/{g}", json={"admins_only": True}).status_code == 200
    why = ben.get(f"/api/chats/{g}/why/post").json()
    assert why[0].startswith("no ") and any("admins_only" in line for line in why), why
    assert ann.get(f"/api/chats/{g}/why/post").json()[0].startswith("yes "), "the admin posts"
    assert cat.get(f"/api/chats/{g}/why/post").status_code == 404  # not in it: it doesn't exist
    assert ben.get(f"/api/chats/{g}/why/delete").status_code == 422  # not a permission the API explains


def test_profile_and_blocked_people() -> None:
    ann, ben = person("Ann"), person("Ben")
    r = ann.patch("/api/me", json={"about": "on holiday"})
    assert (r.status_code, r.json()["name"], r.json()["about"]) == (200, "Ann", "on holiday")
    assert ann.patch("/api/me", json={"name": "Annie"}).json()["about"] == "on holiday"  # what isn't sent stays
    assert ann.get("/api/me").json()["name"] == "Annie"
    assert ann.patch("/api/me", json={"name": ""}).status_code == 422
    assert ann.get("/api/blocks").json() == []
    ann.post("/api/blocks", json={"user_id": ben.me["id"]})
    assert [u["name"] for u in ann.get("/api/blocks").json()] == ["Ben"]
    assert ben.get("/api/blocks").json() == []  # only your own: Ben doesn't learn that Ann blocked him
    assert ann.delete(f"/api/blocks/{ben.me['id']}").status_code == 204
    assert ann.get("/api/blocks").json() == []


def test_marking_read_what_was_read_tells_nobody() -> None:
    """Every member's open chat reloads on "chat N changed": a mark-read that moves nothing must not say it."""
    ann, ben = person("Ann"), person("Ben")
    chat = direct(ann, ben)
    first = say(ann, chat, "one").json()["seq"]
    second = say(ann, chat, "two").json()["seq"]
    with psycopg.connect(ADMIN, autocommit=True) as conn:
        conn.execute("LISTEN ms_events")
        conn.execute("LISTEN ms_test_done")
        ben.post(f"/api/chats/{chat}/read", json={"seq": second})  # moves Ben's mark: his chats hear of it
        ben.post(f"/api/chats/{chat}/read", json={"seq": second})  # read already
        ben.post(f"/api/chats/{chat}/read", json={"seq": first})  # before it
        ann.post(f"/api/chats/{chat}/read", json={"seq": second})  # Ann's own message, read when she sent it
        say(ben, chat, "three")  # a new message: Ben's mark follows it, the message is news
        admin("SELECT pg_notify('ms_test_done', '')")
        heard: list[str] = []
        for n in conn.notifies(timeout=10):
            if n.channel == "ms_test_done":
                break
            heard.append(n.payload)
    assert heard == [f"{chat}:{ben.me['id']}", str(chat), f"{chat}:{ben.me['id']}"]


# --- bots: principals ------------------------------------------------------------------------------
def test_bots() -> None:
    ann, ben = person("Ann"), person("Ben")
    g = group(ann, ben, title="Ops")
    other = group(ben, ann, title="Ben's group")
    say(ann, g, "deploy please")
    bot = ann.post("/api/bots", json={"name": "Deploy bot"}).json()
    assert bot["key"].startswith("ak_")
    key = {"Authorization": f"Bearer {bot['key']}"}
    c = TestClient(app)
    assert c.get("/api/bot/chats", headers=key).json() == []  # in no chat yet
    assert ann.post(f"/api/chats/{g}/bots", json={"bot_id": bot["id"]}).status_code == 201
    assert ben.post(f"/api/chats/{other}/bots", json={"bot_id": bot["id"]}).status_code == 403  # not Ben's bot
    assert [x["id"] for x in c.get("/api/bot/chats", headers=key).json()] == [g]
    assert [m["body"] for m in c.get(f"/api/bot/chats/{g}/messages", headers=key).json()] == ["deploy please"]
    assert c.post(f"/api/bot/chats/{g}/messages", headers=key, json={"body": "deployed v42"}).status_code == 201
    assert c.post(f"/api/bot/chats/{other}/messages", headers=key, json={"body": "hi"}).status_code == 404
    last = ben.get(f"/api/chats/{g}/messages").json()[-1]
    assert (last["body"], last["bot_name"], last["sender_id"]) == ("deployed v42", "Deploy bot", None)
    after = c.get(f"/api/bot/chats/{g}/messages", headers=key, params={"after": last["seq"] - 1}).json()
    assert [m["body"] for m in after] == ["deployed v42"]  # only what came after that number
    # a member doesn't take the bot out; an admin does, and it no longer sees the group
    r = ben.delete(f"/api/chats/{g}/bots/{bot['id']}")
    assert r.status_code == 403 and r.json()["detail"] == "you can't remove this bot", r.text
    assert ann.delete(f"/api/chats/{g}/bots/{bot['id']}").status_code == 204
    assert c.get("/api/bot/chats", headers=key).json() == []
    assert c.post(f"/api/bot/chats/{g}/messages", headers=key, json={"body": "still here?"}).status_code == 404
    assert c.get("/api/bot/chats", headers={"Authorization": "Bearer ak_nope"}).status_code == 401
    # a switched-off bot's key signs in as nobody
    admin("UPDATE ms.bots SET active = false WHERE id = %s", (bot["id"],))
    assert c.get("/api/bot/chats", headers=key).status_code == 401


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


# --- live updates ------------------------------------------------------------------------------------
def test_live_updates_only_reach_readers() -> None:
    ann, ben, cat = person("Ann"), person("Ben"), person("Cat")
    chat = direct(ann, ben)
    got: dict[str, list[Answer]] = {}

    def listen(name: str, client: TestClient, n: int) -> None:
        with client.websocket_connect("/api/events") as ws:
            ready[name].set()
            got[name] = [json.loads(ws.receive_text()) for _ in range(n)]

    ready = {"ben": threading.Event(), "cat": threading.Event()}
    t = threading.Thread(target=listen, args=("ben", ben, 1), daemon=True)
    u = threading.Thread(target=listen, args=("cat", cat, 1), daemon=True)
    t.start(), u.start()
    ready["ben"].wait(5), ready["cat"].wait(5)
    say(ann, chat, "ping")
    t.join(10)
    assert got.get("ben") == [{"chat": chat}]
    # Cat heard nothing of it; her next event is about a chat she is in
    other = direct(cat, ann)
    u.join(10)
    assert got.get("cat") == [{"chat": other}]


def test_someone_removed_hears_of_it() -> None:
    """Live updates reach only readers, and the person a membership change is about: removed, Ben may no longer read
    the group, but his web app hears of it and closes it."""
    ann, ben = person("Ann"), person("Ben")
    g = group(ann, ben)
    got: list[Answer] = []
    ready = threading.Event()

    def listen() -> None:
        with ben.websocket_connect("/api/events") as ws:
            ready.set()
            got.append(json.loads(ws.receive_text()))

    t = threading.Thread(target=listen, daemon=True)
    t.start()
    ready.wait(5)
    assert ann.delete(f"/api/chats/{g}/members/{ben.me['id']}").status_code == 204
    t.join(10)
    assert got == [{"chat": g}]
    assert bodies(ben, g) == 404

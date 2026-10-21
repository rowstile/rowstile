"""The API against real Postgres with rowstile and db/policy.authz applied: run test.sh.

Every check goes through HTTP as a signed-in person (or a bot with its key), so what it proves is what
row-level security decides: the backend has no permission checks of its own.
"""

import json
import os
import random
import threading
from collections.abc import Iterator
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
    admin("UPDATE ms.members SET joined_at = joined_at - interval '1 day' WHERE chat_id = %s", (g,))
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
    assert c.get("/api/bot/chats", headers={"Authorization": "Bearer ak_nope"}).status_code == 401
    # a switched-off bot's key signs in as nobody
    admin("UPDATE ms.bots SET active = false WHERE id = %s", (bot["id"],))
    assert c.get("/api/bot/chats", headers=key).status_code == 401


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

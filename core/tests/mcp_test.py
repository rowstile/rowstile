#!/usr/bin/env python3
"""mcp_test: the MCP server (`rowstile mcp`) over its protocol, as a coding agent's client would use it: the
handshake and the tools, then each tool in a project folder (rowstile.toml, a policy, tests) on a scratch
database: check, prove, push, test, why, review, lint.

    PGHOST=... PGUSER=... python3 tests/mcp_test.py [--db authz_mcp]     (--no-db: only what needs none)
"""

import contextlib
import json
import os
import queue
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Callable, Iterator
from typing import Any, NamedTuple
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "cli"))
import mcp  # noqa: E402
import pgwire  # noqa: E402

fails = 0
# an answer from the server: its shape is what the checks check
Answer = Any
WAIT = 120  # seconds an answer may take (a tool call runs the command once; push and test touch a database)


def check(label: str, ok: object, detail: object = "") -> None:
    global fails
    if ok:
        print(f"ok    {label}")
    else:
        fails += 1
        print(f"FAIL  {label}{': ' + str(detail)[:800] if detail else ''}")


STARTED: list[subprocess.Popen[bytes]] = []  # every server the suite started, to wait for at its end


class Client:
    def __init__(self, cwd: str, *args: str, log: bool = False) -> None:
        self.p = subprocess.Popen(
            [sys.executable, os.path.join(ROOT, "cli", "rowstile_cli.py"), *args, "mcp"],
            cwd=cwd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE if log else None,
        )
        STARTED.append(self.p)
        assert self.p.stdin is not None and self.p.stdout is not None
        self.stdin, self.stdout = self.p.stdin, self.p.stdout
        self.n = 0
        # the server's lines as they come, so that a server that doesn't answer fails the suite instead of hanging it
        self.lines: queue.Queue[bytes] = queue.Queue()
        self.heard: list[bytes] = []  # every line the server wrote, in order
        self.pumping = threading.Thread(target=self.pump, daemon=True)
        self.pumping.start()

    def pump(self) -> None:
        for line in self.stdout:
            self.heard.append(line)
            self.lines.put(line)
        self.lines.put(b"")  # the server's output ended

    def send(self, obj: object) -> None:
        self.stdin.write((obj if isinstance(obj, str) else json.dumps(obj)).encode() + b"\n")
        self.stdin.flush()

    def read(self, wait: float = WAIT) -> Answer:
        try:
            return json.loads(self.lines.get(timeout=wait))
        except queue.Empty:
            raise AssertionError(f"no answer in {wait} s") from None

    def until(self, mid: str, wait: float = WAIT) -> list[Answer]:
        """The answers that come, up to the one to request mid (an empty list if it doesn't come in time)."""
        got: list[Answer] = []
        end = time.monotonic() + wait
        while time.monotonic() < end:
            try:
                got.append(json.loads(self.lines.get(timeout=max(0.01, end - time.monotonic()))))
            except queue.Empty:
                return []
            if isinstance(got[-1], dict) and got[-1].get("id") == mid:
                return got
        return []

    def children(self) -> list[int]:
        """The server's child processes, the commands its calls run (Linux: /proc)."""
        found: list[int] = []
        for task in os.listdir(f"/proc/{self.p.pid}/task"):
            with contextlib.suppress(OSError), open(f"/proc/{self.p.pid}/task/{task}/children", encoding="ascii") as fh:
                found += [int(pid) for pid in fh.read().split()]
        return found

    def command(self, wait: float = 20) -> int | None:
        """The process id of the command a call started, once it has started (None if none did in time)."""
        end = time.monotonic() + wait
        while time.monotonic() < end:
            if found := self.children():
                return found[0]
            time.sleep(0.05)
        return None

    def ended(self, pid: int, wait: float) -> bool:
        """Whether the server's child pid ended (and the server took note of it) within wait seconds."""
        end = time.monotonic() + wait
        while time.monotonic() < end:
            if pid not in self.children():
                return True
            time.sleep(0.05)
        return False

    def request(self, method: str, params: object = None) -> Answer:
        self.n += 1
        self.send(
            {"jsonrpc": "2.0", "id": self.n, "method": method, **({"params": params} if params is not None else {})}
        )
        msg = self.read()
        assert msg.get("id") == self.n, msg
        return msg

    def tool(self, name: str, **arguments: object) -> Answer:
        msg = self.request("tools/call", {"name": name, "arguments": arguments})
        return msg.get("result", msg.get("error"))

    def close(self) -> int:
        self.stdin.close()
        return self.p.wait(timeout=10)


def refused(r: Answer) -> str | None:
    """What a tool said in refusing a call's arguments, None for any other answer. A refusal is the tool's failed
    call, as one the command refuses (isError, exit code 2, the reason in its text), which a client shows the agent
    so that it corrects the call (MCP 2025-11-25: input validation errors are tool execution errors), not a
    protocol error, which a client may keep from it."""
    if not isinstance(r, dict) or r.get("isError") is not True or not r.get("content"):
        return None
    text = r["content"][0]["text"]
    return text if r.get("structuredContent") == {"ok": False, "exit_code": 2, "output": text} else None


def protocol(folder: str) -> None:
    print("-- the protocol")
    c = Client(folder)
    r = c.request(
        "initialize",
        {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "test", "version": "1"}},
    )["result"]
    check(
        "initialize: the version asked for, tools, and what the server is",
        r["protocolVersion"] == "2025-06-18"
        and "tools" in r["capabilities"]
        and r["serverInfo"]["name"] == "rowstile"
        and "push" in r["instructions"],
        r,
    )
    r = c.request("initialize", {"protocolVersion": "1999-01-01", "capabilities": {}})["result"]
    check("... a version it doesn't know: its newest", r["protocolVersion"] == "2025-11-25", r)
    c.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
    check("notifications get no answer (the next answer is the ping's)", c.request("ping")["result"] == {})
    tools = {t["name"]: t for t in c.request("tools/list")["result"]["tools"]}
    check("the tools", sorted(tools) == ["check", "lint", "prove", "push", "review", "test", "why"], sorted(tools))
    check(
        "... each with its input and output",
        all(t["inputSchema"]["type"] == "object" and t["outputSchema"]["required"] for t in tools.values()),
    )
    check(
        "... why needs who, the type, the id and the permission",
        tools["why"]["inputSchema"]["required"] == ["as", "type", "id", "perm"],
    )
    check(
        "... push is the only one that changes anything",
        [n for n, t in tools.items() if not t["annotations"]["readOnlyHint"]] == ["push"]
        and tools["push"]["annotations"]["destructiveHint"],
    )
    r = c.request("tools/call", {"name": "fly", "arguments": {}})
    check(
        "an unknown tool: a protocol error naming the tools",
        r.get("error") == {"code": -32602, "message": 'no tool "fly": check, prove, review, test, why, lint, push'},
        r,
    )
    r = c.request("tools/call", {"name": "check", "arguments": ["db/policy.authz"]})
    check(
        "arguments that aren't an object: a protocol error saying so, and the tool not run",
        r.get("error")
        == {"code": -32602, "message": 'check: arguments is an object (names and values), not ["db/policy.authz"]'},
        r,
    )
    r = c.request("tools/call", {"name": "check", "arguments": None})
    check(
        "... arguments that are null: none, as when none are given",
        r.get("result", {}).get("structuredContent", {}).get("ok") is True,
        r,
    )
    r = c.request("tools/call", {"name": "why", "arguments": {"as": "user:1"}})
    check(
        "missing arguments: the tool's failed call, naming them, which the agent sees",
        refused(r.get("result")) == "why: missing arguments type, id, perm",
        r,
    )
    r = c.request("tools/call", {"name": "why", "arguments": {"as": "user:1", "type": "folder", "id": "3"}})
    check("... one missing argument: named", refused(r.get("result")) == "why: missing argument perm", r)
    r = c.request("resources/list")
    check("a method it doesn't have: -32601", r["error"]["code"] == -32601, r)
    c.send("{not json")
    check(
        "a line that isn't JSON: a parse error, and the server carries on",
        c.read()["error"]["code"] == -32700 and c.request("ping")["result"] == {},
    )
    c.send("[" * 100000 + "]" * 100000)
    check(
        "... nor does one nested too deep to read end it",
        c.read()["error"]["code"] == -32700 and c.request("ping")["result"] == {},
    )
    c.send("")
    check("an empty line is no message: the next answer is the ping's", c.request("ping")["result"] == {})
    # JSON-RPC's batch, which protocol 2025-03-26 asks a server to take: an array of answers, none for a notification
    c.send(
        [
            {"jsonrpc": "2.0", "id": "b1", "method": "ping"},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": "b2", "method": "tools/list"},
        ]
    )
    r = c.read()
    check(
        "a batch: one answer for each request in it, in an array",
        isinstance(r, list)
        and [a["id"] for a in r] == ["b1", "b2"]
        and r[0]["result"] == {}
        and r[1]["result"]["tools"],
        r,
    )
    c.send([{"jsonrpc": "2.0", "method": "notifications/initialized"}])
    check("... of notifications only: no answer", c.request("ping")["result"] == {})
    c.send([1, {"jsonrpc": "2.0", "id": "b3", "method": "ping"}])
    r = c.read()
    check(
        "... what isn't a request in it: an error in its place",
        isinstance(r, list)
        and [(a["id"], a.get("error", {}).get("code")) for a in r] == [(None, -32600), ("b3", None)],
        r,
    )
    c.send([])
    r = c.read()
    check("... an empty one: an error, not an array", r["error"]["code"] == -32600 and r["id"] is None, r)
    c.send({"jsonrpc": "2.0", "id": None, "method": "ping"})
    r = c.read()
    check(
        "a request whose id is null (MCP gives every request one): an error, not silence",
        r["id"] is None and r["error"]["code"] == -32600 and "not null" in r["error"]["message"],
        r,
    )
    r = c.request("tools/call", ["check"])
    check(
        "params that aren't an object: an error saying so",
        r["error"]["code"] == -32602 and r["error"]["message"].startswith("tools/call: params is an object"),
        r,
    )
    r = c.tool("test", files="db/tests/docs.authz")
    check("test's files as one string, not a list: refused", refused(r) == "test: files: a list of file names", r)
    r = c.tool("why", **{"as": "user:1", "type": "folder", "id": None, "perm": "view"})
    check("an id that is null: refused, not run as the id 'None'", refused(r) == "why: id: a string, not null", r)
    r = c.tool("why", **{"as": "user:1", "type": "folder", "id": 3, "perm": True})
    check("... nor a permission that is true", refused(r) == "why: perm: a string, not true", r)
    # an argument longer than a process may be given (Linux takes 128 kB): the call fails, and the server carries on
    r = c.request("tools/call", {"name": "check", "arguments": {"policy": "p" * 300000}})
    check(
        "a call the server can't make: an error naming why, and the server carries on",
        r["error"]["code"] == -32603
        and r["error"]["message"].startswith("OSError: ")
        and c.request("ping")["result"] == {},
        r,
    )
    check("it stops when its input closes", c.close() == 0)
    # a call that runs longer than the server waits (600 s; here a moment): stopped, and a failed call
    request: Answer = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "check", "arguments": {}}}
    with mock.patch.object(mcp, "TIMEOUT", 0.001):
        r = mcp.Server().handle(request)
    result: Answer = r["result"] if r else {}
    check(
        "a call that takes too long: stopped, and said so",
        result.get("isError") is True
        and result["structuredContent"]["exit_code"] == 2
        and result["content"][0]["text"] == "rowstile check took more than 0.001 s and was stopped",
        r,
    )
    stopping()


def child(*code: str) -> subprocess.Popen[bytes]:
    """A command for the server's functions to stop: Python running the lines given, once it has said it runs them."""
    p = subprocess.Popen(
        [sys.executable, "-c", "\n".join([*code, "print('ready', flush=True)", "time.sleep(60)"])],
        stdout=subprocess.PIPE,
    )
    assert p.stdout is not None and p.stdout.readline() == b"ready\n"
    return p


def stopping() -> None:
    """How the server stops a command, asked of its functions in this process (each child here is this process's,
    waited for): what the protocol's checks seldom meet."""
    running = mcp.Running()
    running.cancel()
    try:
        running.start([sys.executable, "-c", "pass"], dict(os.environ))
        started: object = running.process
    except mcp.Cancelled:
        started = "cancelled"
    check("a call cancelled before its command started: the command never starts", started == "cancelled", started)
    done = subprocess.Popen([sys.executable, "-c", "pass"])
    done.wait()
    mcp.stop(done)
    check("a command that has ended: nothing sent to it", done.returncode == 0, done.returncode)
    p = child("import time")
    with mock.patch.object(mcp.os, "name", "nt"):
        mcp.stop(p)
    check(
        "on Windows, which has no Ctrl-C for one process: ended (terminate)",
        p.wait(10) == -signal.SIGTERM,
        p.returncode,
    )
    # the server stopped: a call whose command hasn't started yet, and one whose command doesn't heed Ctrl-C
    server = mcp.Server()
    waiting, deaf = mcp.Running(), mcp.Running()
    deaf.process = child("import signal, time", "signal.signal(signal.SIGINT, signal.SIG_IGN)")
    server.running = {'"a"': waiting, '"b"': deaf}
    began = time.monotonic()
    with mock.patch.object(mcp, "GRACE", 0.5):
        server.end()
    took = time.monotonic() - began
    check(
        "the server stopped: a command not started never starts, one that doesn't heed Ctrl-C killed after the wait",
        waiting.cancelled and deaf.process.returncode == -signal.SIGKILL and took < 5,
        [waiting.cancelled, deaf.process.returncode, f"{took:.1f} s"],
    )


def cancelling(folder: str) -> None:
    print("-- a call cancelled, and the messages that come while a call runs")
    # a call whose command runs until it is stopped, however fast the command is: a check of a policy file that is a
    # pipe nobody writes to (it waits to read it)
    pipe = os.path.join(folder, "db", "waits.authz")
    os.mkfifo(pipe)
    c = Client(folder, log=True)
    c.request("initialize", {"protocolVersion": "2025-11-25", "capabilities": {}})
    c.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
    waits = {"name": "check", "arguments": {"policy": "db/waits.authz"}}
    c.send({"jsonrpc": "2.0", "id": "long", "method": "tools/call", "params": waits})
    pid = c.command()
    c.send({"jsonrpc": "2.0", "id": "p1", "method": "ping"})
    got = c.until("p1", 5)
    check(
        "a ping while a call runs: answered at once, the call still running",
        pid is not None and got == [{"jsonrpc": "2.0", "id": "p1", "result": {}}] and pid in c.children(),
        [pid, got],
    )
    c.send({"jsonrpc": "2.0", "id": "l1", "method": "tools/list"})
    got = c.until("l1", 5)
    check("... and tools/list", [a.get("id") for a in got] == ["l1"] and got[0]["result"]["tools"], got)
    cancel = {"requestId": "long", "reason": "the agent moved on"}
    c.send({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": cancel})
    check(
        "notifications/cancelled: the call's command stopped (its process ended, the server waited for it)",
        pid is not None and c.ended(pid, 15),
        [pid, c.children()],
    )
    c.send({"jsonrpc": "2.0", "id": "p2", "method": "ping"})
    got = c.until("p2", 60)
    check(
        "... and no answer for it: the next answer is the ping's",
        got == [{"jsonrpc": "2.0", "id": "p2", "result": {}}],
        got,
    )
    # a cancellation for a request that has ended, or one the server never had: let be
    r = c.request("tools/call", {"name": "check", "arguments": {}})
    c.send({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": c.n}})
    c.send({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": "nothing"}})
    c.send({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": "long"})
    check(
        "a cancellation of a call answered already, of a request it never had, or with no request: no answer",
        r["result"]["structuredContent"]["ok"] and c.request("ping")["result"] == {},
        r,
    )
    # two calls at once: each answered, the quick one first
    c.send({"jsonrpc": "2.0", "id": "slow", "method": "tools/call", "params": waits})
    pid = c.command()
    c.send({"jsonrpc": "2.0", "id": "slow", "method": "tools/call", "params": waits})
    c.send({"jsonrpc": "2.0", "id": "quick", "method": "tools/call", "params": {"name": "check", "arguments": {}}})
    got = c.until("quick", 30)
    check(
        "a call while another runs: run beside it, and answered first; an id that is in use is refused",
        [(a.get("id"), a.get("error", {}).get("message")) for a in got]
        == [("slow", 'request "slow" is running already: each request has an id of its own'), ("quick", None)]
        and got[1]["result"]["structuredContent"]["ok"],
        got,
    )
    c.send({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": "slow"}})
    check("... and the first cancelled then", pid is not None and c.ended(pid, 15), pid)
    # the end of the input: the call running is answered, then the server ends
    c.send({"jsonrpc": "2.0", "id": "last", "method": "tools/call", "params": {"name": "check", "arguments": {}}})
    c.stdin.close()
    got = c.until("last", 30)
    check(
        "the end of the input with a call running: answered, then the server ends",
        len(got) == 1 and got[0]["result"]["structuredContent"]["ok"] and c.p.wait(timeout=30) == 0,
        got,
    )
    os.remove(pipe)
    # all the server wrote, now that it has ended (each call's thread ended before it): an answer to a cancelled call
    # would be among it, however late it came
    c.pumping.join(timeout=10)
    late = [a for a in map(json.loads, c.heard) if isinstance(a, dict) and a.get("id") in ("long", "slow")]
    check(
        "... and the calls cancelled never answered, however late",
        not c.pumping.is_alive() and [a.get("error", {}).get("code") for a in late] == [-32600],
        late,
    )
    said = c.p.stderr.read().decode() if c.p.stderr else ""
    check(
        "the server's log says what was cancelled, and why",
        'rowstile mcp: request "long" cancelled: the agent moved on\n' in said
        and 'rowstile mcp: request "slow" cancelled\n' in said,
        said,
    )


def without_db(folder: str) -> None:
    print("-- check and prove (no database)")
    c = Client(folder)
    r = c.tool("check")
    check(
        "check: the policy rowstile.toml names compiles",
        not r["isError"] and r["structuredContent"]["ok"] and r["content"][0]["text"].strip().endswith(": ok"),
        r,
    )
    policy = os.path.join(folder, "db", "policy.authz")
    with open(policy, encoding="utf-8") as fh:
        good = fh.read()
    with open(policy, "a", encoding="utf-8", newline="\n") as fh:
        fh.write("type robot = app.robots\n  owner : martian = owner_id\n")
    r = c.tool("check")
    s = r["structuredContent"]
    line = good.count("\n") + 2
    check(
        "a mistake: an answer (not a failed call), with the file, the line and the message",
        not r["isError"]
        and not s["ok"]
        and s["error"]["file"] == "db/policy.authz"
        and s["error"]["line"] == line
        and "martian" in s["error"]["message"],
        r,
    )
    check(
        "... its code, and its page: what it means and the same mistake fixed",
        s["error"].get("code") == "AZ201"
        and not s["error"]["message"].endswith("]")
        and s["error"]["help"].startswith("# AZ201: Unknown type")
        and "## Fixed" in r["content"][0]["text"],
        r,
    )
    with open(policy, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(good.replace("app role app_user", 'app role app_user\ninclude "roles.authz"', 1))
    with open(os.path.join(folder, "db", "roles.authz"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write("type robot = app.robots\n  owner : martian = owner_id\n")
    s = c.tool("check")["structuredContent"]
    check(
        "... in an included file: that file's path, and its line",
        s.get("error", {}).get("file") == "db/roles.authz" and s["error"]["line"] == 2,
        s,
    )
    with open(policy, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(good)
    r = c.tool("check", policy="db/nothing.authz")
    check("a policy file that isn't there: a failed call", r["isError"] and r["structuredContent"]["exit_code"] == 2, r)
    # what the command says of it reads like a mistake's line ("db: line 1: x.authz: No such file or directory"),
    # with no code: no mistake in a policy
    r = c.tool("check", policy="db: line 1: x.authz")
    check(
        "... nor one whose name reads like a mistake's line: no mistake given",
        r["isError"] and "error" not in r["structuredContent"],
        r,
    )
    r = c.tool("prove", worlds=40)
    s = r["structuredContent"]
    check(
        "prove: the docs example's counterexample (an owner outside the org may share)",
        not r["isError"]
        and not s["ok"]
        and "never folder: share and not org.member" in s["output"]
        and "the smallest found" in s["output"],
        r,
    )
    c.close()


def with_db(folder: str, db: str) -> None:
    print("-- push, test, why, lint (a scratch database)")
    subprocess.run(["dropdb", "--if-exists", db], capture_output=True)
    subprocess.run(["createdb", db], check=True)
    subprocess.run(
        ["psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-d", db, "-f", os.path.join(ROOT, "example", "app_schema.sql")],
        check=True,
        capture_output=True,
        env=dict(os.environ, PGOPTIONS="-c client_min_messages=error"),
    )
    c = Client(folder, "--db", f"dbname={db}", log=True)
    # the server's --db goes only to the commands that read a database: check and prove refuse it
    r = c.tool("check")
    check(
        "check on a server given --db: the policy compiles",
        r["structuredContent"]["ok"] and r["content"][0]["text"].strip().endswith(": ok"),
        r,
    )
    r = c.tool("prove", worlds=40)
    check("... and prove", "never folder: share and not org.member" in r["structuredContent"]["output"], r)
    r = c.tool("test")
    check(
        "test before a policy is applied: says so",
        not r["structuredContent"]["ok"] and "no policy is applied" in r["content"][0]["text"],
        r,
    )
    r = c.tool("push")
    check(
        "push: the policy applied (the whole policy, the first time)",
        not r["isError"] and r["structuredContent"]["ok"] and "applied" in r["content"][0]["text"],
        r,
    )
    r = c.tool("push")
    check("... again: unchanged", r["structuredContent"]["ok"] and "unchanged" in r["content"][0]["text"], r)
    r = c.tool("test")
    s = r["structuredContent"]
    check("test: the policy's tests and the named tests pass", s["ok"] and "policy tests passed" in s["output"], r)
    r = c.tool("test", coverage=True)
    check("... with coverage", r["structuredContent"]["ok"] and "branch" in r["structuredContent"]["output"], r)
    with open(os.path.join(folder, "db", "tests", "wrong.authz"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write(
            'test "a wrong expectation"\n'
            "  given ann  = {INSERT INTO app.users (id, name) VALUES (9101, 'Ann') RETURNING id}\n"
            "  given acme = {INSERT INTO app.orgs (id, name) VALUES (9101, 'Acme') RETURNING id}\n"
            "  given top  = {INSERT INTO app.folders (org_id, owner_id, name) VALUES ($acme, $ann, 'Top') RETURNING id}\n"
            "  user $ann cannot view folder $top\n"
        )
    r = c.tool("test", files=["db/tests/wrong.authz"])
    s = r["structuredContent"]
    check(
        "a failing test: an answer (not a failed call), naming the check",
        not r["isError"] and not s["ok"] and s["exit_code"] == 1 and "FAIL" in s["output"],
        r,
    )
    r = c.tool("why", **{"as": "user:3", "type": "folder", "id": "3", "perm": "edit"})
    s = r["structuredContent"]
    check(
        "why: no, why not, and the smallest change",
        s["ok"]
        and s["output"].startswith("no: user:3 does not hold edit on folder 3")
        and "share editor on folder 3 with user 3" in s["output"],
        r,
    )
    r = c.tool("why", **{"as": "user:2", "type": "folder", "id": "3", "perm": "fly"})
    check(
        "... a permission the type doesn't have: named, as authz.can names it",
        not r["structuredContent"]["ok"]
        and "no permission folder.fly in the policy\nHINT: rowstile help AZ707" in r["content"][0]["text"],
        r,
    )
    r = c.tool("lint")
    check("lint: the example leaves nothing open", r["structuredContent"]["ok"], r)
    review(folder, c)
    cancelled_push(folder, db, c)
    stopped_push(folder, db)
    # a database with a policy that nobody marked as a development database (applied, as production is)
    other = db + "_unmarked"
    subprocess.run(["dropdb", "--if-exists", other], capture_output=True)
    subprocess.run(["createdb", other], check=True)
    subprocess.run(
        [
            "psql",
            "-X",
            "-q",
            "-v",
            "ON_ERROR_STOP=1",
            "-d",
            other,
            "-f",
            os.path.join(ROOT, "example", "app_schema.sql"),
        ],
        check=True,
        capture_output=True,
        env=dict(os.environ, PGOPTIONS="-c client_min_messages=error"),
    )
    subprocess.run(
        [sys.executable, os.path.join(ROOT, "cli", "rowstile_cli.py"), "--db", f"dbname={other}", "apply"],
        cwd=folder,
        check=True,
        capture_output=True,
    )
    c2 = Client(folder, "--db", f"dbname={other}")
    with open(os.path.join(folder, "db", "policy.authz"), "a", encoding="utf-8", newline="\n") as fh:
        fh.write("\n-- a change\n")
    r = c2.tool("push")
    check(
        "push to a database nobody marked: refused",
        not r["structuredContent"]["ok"] and "AZ610" in r["content"][0]["text"],
        r,
    )
    for flag in ("--development", "--force", "--downgrade", "-d"):
        r = c2.tool("push", policy=flag)
        check(
            f"push with {flag} as the policy: not an option the agent may pass",
            refused(r) == f"push: policy: '{flag}' starts with '-': a name or a value, not an option",
            r,
        )
    r = c2.tool("push")
    check(
        "... and the database is still not marked",
        not r["structuredContent"]["ok"] and "AZ610" in r["content"][0]["text"],
        r,
    )
    r = c2.tool("review", base="--output=x")
    check(
        "review's base can't be an option either",
        refused(r) == "review: base: '--output=x' starts with '-': a name or a value, not an option",
        r,
    )
    r = c2.tool("why", **{"as": "user:3", "type": "folder", "id": "--development", "perm": "edit"})
    check("... nor why's id", refused(r) == "why: id: '--development' starts with '--': an id, not an option", r)
    c2.close()
    subprocess.run(["dropdb", "--if-exists", other], capture_output=True)
    subprocess.run(
        [
            "psql",
            "-X",
            "-q",
            "-d",
            db,
            "-c",
            "CREATE VIEW app.all_files AS SELECT * FROM app.files",
            "-c",
            "GRANT SELECT ON app.all_files TO app_user",
        ],
        check=True,
        capture_output=True,
    )
    r = c.tool("lint")
    s = r["structuredContent"]
    first = s["output"].split("\n")[2]
    check(
        "... a view that reads a governed table as its owner: an error, first",
        not r["isError"] and not s["ok"] and first.startswith("error") and "app.all_files" in first,
        r,
    )
    c.close()
    subprocess.run(["dropdb", "--if-exists", db], capture_output=True)


def review(folder: str, c: Client) -> None:
    """The review tool in a git repository, as an agent asks it before a pull request: what the policy change since
    a ref does, as the pull request's comment."""
    git = ["git", "-C", folder, "-c", "user.email=t@example.com", "-c", "user.name=t"]
    # no upkeep git starts in the background: a process left to this one (adopt) would read as a server's stray
    upkeep = (["config", "gc.auto", "0"], ["config", "maintenance.auto", "false"])
    for step in (["init", "-q", "-b", "main"], *upkeep, ["add", "-A"], ["commit", "-q", "-m", "base"]):
        subprocess.run([*git, *step], check=True, capture_output=True)
    policy = os.path.join(folder, "db", "policy.authz")
    with open(policy, encoding="utf-8") as fh:
        before = fh.read()
    with open(policy, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(before.replace("viewer or (parent.view and {inherit})", "viewer or parent.view", 1))
    try:
        r = c.tool("review", base="main")
    finally:
        with open(policy, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(before)
    s = r["structuredContent"]
    check(
        "review: what the change since main does, as the pull request's comment",
        not r["isError"]
        and s["ok"]
        and s["output"].startswith("<!-- rowstile review -->")
        and "| `folder.view` (changed) |" in s["output"]
        and "<details><summary>Access</summary>" in s["output"],
        r,
    )


class Waiting(NamedTuple):
    """A push the agent asked for, waiting for a lock on app.files that another session, the holder, holds."""

    holder: pgwire.Connection
    waiting: list[tuple[pgwire.Value, ...]]  # the sessions waiting for the lock (the push's one)
    versions: list[tuple[pgwire.Value, ...]]  # the policy in force before
    others: Callable[[], list[tuple[pgwire.Value, ...]]]  # the other sessions on the database, as they are now


@contextlib.contextmanager
def push_waiting(folder: str, db: str, c: Client) -> Iterator[Waiting]:
    """A change to the policy (delete takes share), and a push of it sent to the server c while the holder locks
    app.files: yielded once the push waits for the lock. The holder's session closed after, and the policy put back."""
    policy = os.path.join(folder, "db", "policy.authz")
    with open(policy, encoding="utf-8") as fh:
        before = fh.read()
    rule = "  delete                            : edit\n"
    with open(policy, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(before.replace(rule, rule.replace("edit", "share"), 1))
    holder = pgwire.connect(**pgwire.parse_dsn(f"dbname={db}"))
    try:
        versions = holder.query(IN_FORCE)
        holder.execute("BEGIN")
        holder.execute("LOCK TABLE app.files IN ACCESS EXCLUSIVE MODE")
        me = holder.query("SELECT pg_backend_pid()")[0][0]

        def others() -> list[tuple[pgwire.Value, ...]]:
            """The other sessions on the database, as they are now (a transaction otherwise sees them as at first)."""
            holder.query("SELECT pg_stat_clear_snapshot()")
            return holder.query(
                f"SELECT pid, wait_event_type FROM pg_stat_activity WHERE datname = '{db}' AND pid <> {me}"
            )

        c.send({"jsonrpc": "2.0", "id": "push", "method": "tools/call", "params": {"name": "push", "arguments": {}}})
        end, waiting = time.monotonic() + 30, []
        while time.monotonic() < end and not waiting:
            waiting = [r for r in others() if r[1] == "Lock"]
            time.sleep(0.05)
        yield Waiting(holder, waiting, versions, others)
    finally:
        holder.close()
        with open(policy, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(before)


def gone(others: Callable[[], list[tuple[pgwire.Value, ...]]]) -> list[tuple[pgwire.Value, ...]]:
    """The other sessions left on the database once they have had ten seconds to end."""
    end, left = time.monotonic() + 10, others()
    while time.monotonic() < end and left:
        time.sleep(0.05)
        left = others()
    return left


def cancelled_push(folder: str, db: str, c: Client) -> None:
    """A push the agent cancels while it waits for a lock on app.files (another session holds it): the command
    stopped as Ctrl-C stops it, its statement ended on the server at once (not left waiting for the lock), and
    nothing of it kept."""
    with push_waiting(folder, db, c) as p:
        pid = c.children()
        c.send({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": "push"}})
        left = gone(p.others)
        check(
            "push cancelled while it waits for a lock: its command stopped, and its session with it, at once",
            len(p.waiting) == 1 and len(pid) == 1 and c.ended(pid[0], 15) and left == [],
            [p.waiting, pid, left],
        )
        p.holder.execute("ROLLBACK")
        if pid:
            c.ended(pid[0], 40)  # a push that went on (the lock is free now) has ended, and committed, by then
        kept = p.holder.query(IN_FORCE)
        c.send({"jsonrpc": "2.0", "id": "after", "method": "ping"})
        got = c.until("after", 60)
        r = c.tool("push")
        check(
            "... no answer for it, and nothing of it kept: the next push applies the change",
            kept == p.versions
            and got == [{"jsonrpc": "2.0", "id": "after", "result": {}}]
            and r["structuredContent"]["ok"]
            and "unchanged" not in r["content"][0]["text"],
            [p.versions, kept, got, r],
        )
    check("... and back", c.tool("push")["structuredContent"]["ok"])


# the policy in force (a push records it, or puts it in the last row's place)
IN_FORCE = (
    "SELECT count(*), (SELECT policy FROM authz.policy_versions ORDER BY id DESC LIMIT 1) FROM authz.policy_versions"
)


def strays() -> list[int]:
    """The processes left to this process: a server's commands that its end left behind (adopt() makes this process
    their parent then), running or ended; not the servers it started (the suite starts nothing else that outlives
    its run)."""
    found: list[int] = []
    servers = {p.pid for p in STARTED}
    for task in os.listdir("/proc/self/task"):
        with contextlib.suppress(OSError), open(f"/proc/self/task/{task}/children", encoding="ascii") as fh:
            found += [pid for pid in map(int, fh.read().split()) if pid not in servers]  # one ended too (a zombie)
    return found


def stopped_push(folder: str, db: str) -> None:
    """The server stopped (SIGTERM, as an MCP client stops one) while a push waits for a lock another session
    holds: the push stopped as Ctrl-C stops it, its session ended on the server at once, nothing kept, and the
    server ended after it, leaving nothing running."""
    c = Client(folder, "--db", f"dbname={db}", log=True)
    with push_waiting(folder, db, c) as p:
        began = time.monotonic()
        c.p.send_signal(signal.SIGTERM)
        try:
            code: int | None = c.p.wait(timeout=20)
        except subprocess.TimeoutExpired:
            code = None
        took = time.monotonic() - began
        left = gone(p.others)
        stray = strays()
        check(
            "SIGTERM while a push waits for a lock: its session ended at once, the server after it, nothing left",
            len(p.waiting) == 1 and code == 128 + signal.SIGTERM and took < 5 and left == [] and stray == [],
            [p.waiting, code, f"{took:.1f} s", left, stray],
        )
        p.holder.execute("ROLLBACK")
        for pid in stray:  # a push left running goes on now the lock is free: this process is its parent
            os.waitpid(pid, 0)
        kept = p.holder.query(IN_FORCE)
    said = c.p.stderr.read().decode() if c.p.stderr else ""
    check(
        "... nothing of it kept, and the server's log says why it stopped",
        kept == p.versions and "rowstile mcp: stopped (signal 15): the commands running are stopped first" in said,
        [kept == p.versions, said],
    )


def project() -> str:
    """A project folder: rowstile.toml, the docs example's policy and its named tests."""
    folder = tempfile.mkdtemp(prefix="rowstile_mcp_")
    os.makedirs(os.path.join(folder, "db", "tests"))
    shutil.copy(os.path.join(ROOT, "example", "docs.authz"), os.path.join(folder, "db", "policy.authz"))
    shutil.copy(os.path.join(ROOT, "example", "docs.test.authz"), os.path.join(folder, "db", "tests", "docs.authz"))
    with open(os.path.join(folder, "rowstile.toml"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write('policy = "db/policy.authz"\ntests = ["db/tests/docs.authz"]\n')
    return folder


def adopt() -> None:
    """Linux: a command whose server ended before it (a server stopped with a call running: a failing check here)
    is this process's to wait for, not the container's first process's: where that is Postgres, a child it didn't
    start ending reads to it as a crashed server process, and it restarts every session (PR_SET_CHILD_SUBREAPER)."""
    if sys.platform == "linux":
        import ctypes

        ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0)


def wait_for_all() -> None:
    """The servers this suite started ended (their input closed: each answers what it runs, then ends) and every
    process left to this one waited for: nothing of the suite's goes on after it, and nothing is killed."""
    for p in STARTED:
        if p.poll() is None and p.stdin is not None:
            with contextlib.suppress(OSError):
                p.stdin.close()
    while True:
        try:
            os.waitpid(-1, 0)
        except ChildProcessError:
            return


def main() -> None:
    adopt()
    folder = project()
    try:
        protocol(folder)
        cancelling(folder)
        without_db(folder)
        if "--no-db" not in sys.argv:
            with_db(folder, sys.argv[sys.argv.index("--db") + 1] if "--db" in sys.argv else "authz_mcp")
    finally:
        shutil.rmtree(folder, ignore_errors=True)
        wait_for_all()
    print(f"mcp: {'all passed' if not fails else f'{fails} failed'}")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()

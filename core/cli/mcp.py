"""The rowstile MCP server: `rowstile mcp`, the Model Context Protocol over stdin and stdout, for coding agents.

Its tools are the command's own: check, prove, review, test, why, lint, and push to a development database. Each
call runs the command once, in its own process, in the folder the server was started in (so rowstile.toml, the
policy and the database are found as the command finds them), and returns what the command printed. Nothing is
kept between calls. A call runs beside the messages that come after it: a ping is answered meanwhile, and a call
the client cancels (notifications/cancelled) has its command stopped, as Ctrl-C stops it, and gets no answer. So
do the calls running when the server is stopped (SIGTERM): none runs on after it.

    {"mcpServers": {"rowstile": {"command": "rowstile", "args": ["mcp"]}}}
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import signal
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from typing import NamedTuple

from authzlib.connection import (
    Value as Json,  # what JSON holds: the same shape as a database value
)

HERE = os.path.dirname(os.path.abspath(__file__))
COMMAND = os.path.join(HERE, "rowstile_cli.py")
VERSIONS = ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"]  # newest first
TIMEOUT = 600  # seconds, for one call
GRACE = 10  # seconds a stopped command has to end on its own (a push rolls back) before it is killed
ERROR = re.compile(r"^(?P<file>.+?): (?:(?P<inc>\S+) )?line (?P<line>\d+): (?P<message>.*)$", re.S)

INSTRUCTIONS = """rowstile compiles an access policy (.authz) into row-level security for Postgres.
The policy file and the database come from rowstile.toml in this project.
The loop after editing the policy: `check` (the first mistake, with its line), then `push` (the development
database only), then `test` (the policy's tests; `coverage` lists branches no test makes true).
`why` answers whether someone holds a permission, why, and the smallest changes that would grant it.
`prove` checks the invariants in many small worlds; `review` says what a change since a git ref does.
`lint` lists the ways around row-level security the database leaves open.
Production takes migrations (`rowstile migrate`), never `push`."""

Message = dict[str, Json]

POLICY: Json = {"type": "string", "description": "the policy file (default: rowstile.toml's `policy`)"}
WHO: Json = {"type": "string", "description": "who asks: user:42, bot:7 (a principal type and id), or anyone"}
OUTPUT: Json = {
    "type": "object",
    "properties": {
        "ok": {"type": "boolean", "description": "true when the command found nothing wrong"},
        "exit_code": {"type": "integer"},
        "output": {"type": "string", "description": "what the command printed"},
        "error": {"type": "object", "description": "check: the mistake, when there is one"},
    },
    "required": ["ok", "exit_code", "output"],
}


class Tool(NamedTuple):
    description: str
    properties: dict[str, Json]
    required: list[str]
    notes: dict[str, bool]  # MCP's annotations: readOnlyHint, destructiveHint, idempotentHint
    command: Callable[[Message], list[str]]  # the arguments to the command, from the call's arguments


TOOLS: dict[str, Tool] = {
    "check": Tool(
        "Compile the policy without a database and report its first mistake, with the file, line and code.",
        {"policy": POLICY},
        [],
        {"readOnlyHint": True},
        lambda a: ["check", *opt_policy(a)],
    ),
    "prove": Tool(
        "Check every invariant of the policy in many small worlds (no database): the smallest counterexample, "
        "or that none was found.",
        {"policy": POLICY, "worlds": {"type": "integer", "description": "how many worlds to try (default 400)"}},
        [],
        {"readOnlyHint": True},
        lambda a: ["prove", *opt("--worlds", a.get("worlds")), *opt_policy(a)],
    ),
    "review": Tool(
        "What the policy change since a git ref does: meaning, access, risk, tests and deploy (the pull request "
        "comment, as markdown). Needs git.",
        {"base": {"type": "string", "description": "the ref to compare with (default: main)"}, "policy": POLICY},
        [],
        {"readOnlyHint": True},
        lambda a: ["review", "--markdown", *opt("--base", a.get("base")), *opt_policy(a)],
    ),
    "test": Tool(
        "Run the policy's tests, the test files rowstile.toml names (or these), and the invariants, on the "
        "database; nothing stays. With coverage, the branches of each permission no test makes true.",
        {
            "files": {
                "type": "array",
                "items": {"type": "string"},
                "description": "test files (default: rowstile.toml's `tests`)",
            },
            "coverage": {"type": "boolean"},
        },
        [],
        {"readOnlyHint": True},
        lambda a: ["test", *(["--coverage"] if a.get("coverage") else []), *strings(a.get("files"))],
    ),
    "why": Tool(
        "Whether someone holds a permission on an object, and why; if not, why not, and the smallest changes to "
        "the data that would grant it (each tried on the database and undone).",
        {
            "as": WHO,
            "type": {"type": "string", "description": "the policy's type, e.g. folder"},
            "id": {"type": "string"},
            "perm": {"type": "string", "description": "a permission of the type, e.g. view"},
        },
        ["as", "type", "id", "perm"],
        {"readOnlyHint": True},
        lambda a: [
            "why",
            "--as",
            plain("as", a["as"]),
            plain("type", a["type"]),
            ident(a["id"]),
            plain("perm", a["perm"]),
        ],
    ),
    "lint": Tool(
        "The ways around row-level security the database leaves open (authz.lint()): the app role owning a "
        "table, bypassing RLS, tables without rules, grants on masked columns, ...",
        {},
        [],
        {"readOnlyHint": True},
        lambda a: ["lint"],
    ),
    "push": Tool(
        "Bring the development database to the policy, with the migration production would get. Only a database "
        "marked as a development database (a person marks one with rowstile push --development; the first push "
        "to one with no policy marks it): production takes migrations (rowstile migrate).",
        {"policy": POLICY},
        [],
        {"readOnlyHint": False, "destructiveHint": True, "idempotentHint": True},
        lambda a: ["push", *opt_policy(a)],
    ),
}


def string(name: str, value: Json) -> str:
    """A tool's text argument: a string, or a number as written (an id). null, true, an object or a list is
    refused, not handed to the command as Python writes it ("None")."""
    if isinstance(value, bool) or not isinstance(value, (str, int, float)):
        raise ValueError(f"{name}: a string, not {json.dumps(value)[:40]}")
    return str(value)


def plain(name: str, value: Json) -> str:
    """A tool's argument as the command takes it: never one of the command's own options. An agent that sends
    "--development" as the policy would mark the database itself, which is a person's to do."""
    text = string(name, value)
    if text.startswith("-"):
        raise ValueError(f"{name}: {text!r} starts with '-': a name or a value, not an option")
    return text


def ident(value: Json) -> str:
    """An object's id: any text (a negative number too), but not one of the command's options."""
    text = string("id", value)
    if text.startswith("--"):
        raise ValueError(f"id: {text!r} starts with '--': an id, not an option")
    return text


def opt(flag: str, value: Json) -> list[str]:
    return [flag, plain(flag.lstrip("-"), value)] if value not in (None, "") else []


def opt_policy(a: Message) -> list[str]:
    return [plain("policy", a["policy"])] if a.get("policy") else []


def strings(items: Json) -> list[str]:
    if items is None:
        return []
    if not isinstance(items, list) or not all(isinstance(x, str) for x in items):
        raise ValueError("files: a list of file names")
    return [plain("files", x) for x in items]


def tool_list() -> list[Json]:
    return [
        {
            "name": name,
            "title": f"rowstile {name}",
            "description": desc,
            "inputSchema": {"type": "object", "properties": props, "required": required},
            "outputSchema": OUTPUT,
            "annotations": {"openWorldHint": False, **notes},
        }
        for name, (desc, props, required, notes, _) in TOOLS.items()
    ]


class Cancelled(Exception):
    """The client cancelled the call: its command is stopped, and it gets no answer."""


class Running:
    """A call in progress: the command's process, once started, and whether the client cancelled the call."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.process: subprocess.Popen[bytes] | None = None
        self.cancelled = False

    def start(self, argv: list[str], env: dict[str, str]) -> subprocess.Popen[bytes]:
        with self.lock:  # a call cancelled before its command started never starts it
            if self.cancelled:
                raise Cancelled
            self.process = subprocess.Popen(
                argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env
            )
            return self.process

    def cancel(self) -> None:
        with self.lock:
            self.cancelled = True
            p = self.process
        if p is not None:
            stop(p)


def stop(p: subprocess.Popen[bytes]) -> None:
    """Stops the command as Ctrl-C does: it takes back what it began (a push's transaction rolled back, the statement
    running stopped on the server) and ends; one still running GRACE seconds later is killed. Only this server's own
    child, by its process id, which the call waits for (so it is never left to run on its own)."""
    if p.poll() is not None:
        return
    if os.name == "nt":
        p.terminate()  # Windows has no Ctrl-C for one process: ended, its connection with it (the server rolls back)
    else:
        p.send_signal(signal.SIGINT)
    later = threading.Timer(GRACE, p.kill)  # nothing once the call has seen it end (Popen knows it ended)
    later.daemon = True
    later.start()


def run(dsn: str | None, args: list[str], running: Running | None = None) -> tuple[int, str]:
    """The command, once: (exit code, what it printed). Cancelled: stopped, and Cancelled raised."""
    argv = [sys.executable, COMMAND, *(["--db", dsn] if dsn else []), *args]
    env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUTF8="1")
    running = running or Running()
    p = running.start(argv, env)
    try:
        out, _ = p.communicate(timeout=TIMEOUT)
    except subprocess.TimeoutExpired:
        stop(p)
        p.communicate()
        if running.cancelled:
            raise Cancelled from None
        return 2, f"rowstile {args[0]} took more than {TIMEOUT} s and was stopped"
    if running.cancelled:
        raise Cancelled
    return p.returncode, out.decode("utf-8", "replace").replace("\r\n", "\n")


def call(dsn: str | None, name: Json, arguments: Json, running: Running | None = None) -> Message:
    if not isinstance(name, str) or name not in TOOLS:
        raise KeyError(name)
    args = TOOLS[name].command(arguments if isinstance(arguments, dict) else {})
    code, out = run(dsn, args, running)
    result: Message = {"ok": code == 0, "exit_code": code, "output": out}
    if name == "check" and code != 0:
        from authzlib import errors

        first, mistake = errors.split(out.strip().split("\n")[0])
        m = ERROR.match(first)
        # a mistake in the policy: its line, and its code (each has one), not a file whose name reads like a line
        if m and mistake is not None and mistake in errors.CODES:
            # an included file is named relative to the policy's folder
            path = os.path.join(os.path.dirname(m.group("file")), m.group("inc")) if m.group("inc") else m.group("file")
            try:
                path = os.path.relpath(path)  # relative to the project, as the agent names files
            except ValueError:
                pass  # another drive
            # with the code's page: what the mistake means, and the same mistake fixed
            result["error"] = {
                "file": path.replace(os.sep, "/"),
                "line": int(m.group("line")),
                "message": m.group("message"),
                "code": mistake,
                "help": errors.page(mistake),
            }
            out += f"\n{errors.page(mistake)}"
    # a finding (a mistake, a failing test, a counterexample) is an answer; exit code 2 is a call that couldn't
    # run (no policy file, no database, a wrong argument), which the agent has to fix first
    return {
        "content": [{"type": "text", "text": out or "(no output)"}],
        "structuredContent": result,
        "isError": code not in (0, 1),
    }


class Server:
    def __init__(self, dsn: str | None = None) -> None:
        self.dsn = dsn
        self.lock = threading.Lock()
        self.running: dict[str, Running] = {}  # the calls in progress, by their request's id (as JSON writes it)
        self.ending = False  # stopped: no call starts any more

    def end(self) -> None:
        """The server stopped (SIGTERM: how an MCP client ends one that hasn't ended once its input closed): each call
        running cancelled, as notifications/cancelled cancels one, and its command waited for, killed once GRACE
        seconds have passed, so that none runs on after the server."""
        with self.lock:
            self.ending = True
            running = list(self.running.values())
        for call in running:
            call.cancel()
        end = time.monotonic() + GRACE
        for call in running:
            if call.process is None:
                continue
            try:
                call.process.wait(timeout=max(0.0, end - time.monotonic()))
            except subprocess.TimeoutExpired:
                call.process.kill()
                call.process.wait()

    def cancel(self, params: Message) -> None:
        """notifications/cancelled: the call's command stopped, and no answer. One that has ended, or a request
        this server doesn't know, is let be (MCP: a cancellation may cross the answer on the way)."""
        with self.lock:
            running = self.running.get(json.dumps(params.get("requestId")))
        if running is not None:
            reason = params.get("reason")
            said = f": {reason}" if isinstance(reason, str) and reason else ""
            print(f"rowstile mcp: request {json.dumps(params.get('requestId'))} cancelled{said}", file=sys.stderr)
            running.cancel()

    def handle(self, msg: Message) -> Message | None:
        """The answer to one message (None for a notification)."""
        raw = msg.get("params")
        method, params, mid = msg.get("method"), raw if isinstance(raw, dict) else {}, msg.get("id")
        if mid is None:
            # a notification (notifications/initialized, notifications/cancelled, ...): no answer; a request whose id
            # is null (which MCP doesn't allow) is told so, or its client would wait for an answer
            null = "id" in msg and "method" in msg
            if method == "notifications/cancelled" and not null:
                self.cancel(params)
            return error(None, -32600, "a request's id is a string or a number, not null") if null else None
        if raw is not None and not isinstance(raw, dict):
            return error(mid, -32602, f"{method}: params is an object (names and values), not {json.dumps(raw)[:40]}")
        if method == "initialize":
            from authzlib import __version__

            asked = params.get("protocolVersion")
            return ok(
                mid,
                {
                    "protocolVersion": asked if asked in VERSIONS else VERSIONS[0],
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": "rowstile", "title": "rowstile", "version": __version__},
                    "instructions": INSTRUCTIONS,
                },
            )
        if method == "ping":
            return ok(mid, {})
        if method == "tools/list":
            return ok(mid, {"tools": tool_list()})
        if method == "tools/call":
            key, running = json.dumps(mid), Running()
            with self.lock:
                if self.ending:
                    return None
                if key in self.running:  # its cancellation would stop both
                    return error(mid, -32600, f"request {key} is running already: each request has an id of its own")
                self.running[key] = running
            try:
                return ok(mid, call(self.dsn, params.get("name"), params.get("arguments"), running))
            except Cancelled:
                return None
            except KeyError as e:
                if e.args and e.args[0] == params.get("name"):
                    return error(mid, -32602, f"no tool {params.get('name')!r}: {', '.join(TOOLS)}")
                return error(mid, -32602, f"{params.get('name')}: missing argument {e}")
            except ValueError as e:
                return error(mid, -32602, f"{params.get('name')}: {e}")
            finally:
                with self.lock:
                    del self.running[key]
        return error(mid, -32601, f"not supported: {method}")

    def reply(self, got: Json) -> Json:
        """The answer to what one line held: a message, or a batch (protocol 2025-03-26 has them): each message
        answered, the answers in one array, and nothing for notifications alone."""
        if isinstance(got, list) and got:
            answers: list[Json] = [a for a in map(self.answer, got) if a is not None]
            return answers or None
        return self.answer(got)

    def answer(self, got: Json) -> Message | None:
        """The answer to one message as read: an error for one that isn't an object, None for a notification."""
        if not isinstance(got, dict):
            return error(None, -32600, "not a request")
        msg: Message = {str(k): v for k, v in got.items()}
        try:
            return self.handle(msg)
        except Exception as e:  # answer and carry on: a dead server stops the agent's whole session
            return error(msg.get("id"), -32603, f"{type(e).__name__}: {e}") if msg.get("id") is not None else None


def ok(mid: Json, result: Json) -> Message:
    return {"jsonrpc": "2.0", "id": mid, "result": result}


def error(mid: Json, code: int, message: str) -> Message:
    return {"jsonrpc": "2.0", "id": mid, "error": {"code": code, "message": message}}


def calls(got: Json) -> bool:
    """Whether a line holds a tool call (alone or in a batch): it runs beside the lines after it."""
    items = got if isinstance(got, list) else [got]
    return any(isinstance(m, dict) and m.get("method") == "tools/call" for m in items)


def serve(dsn: str | None = None) -> None:
    """Newline-delimited JSON-RPC on stdin and stdout; the log goes to stderr. Each tool call runs in a thread of its
    own, so that the lines after it are read meanwhile (a ping, a cancellation, another call); the end of the input
    ends the server once the calls running have been answered."""
    server = Server(dsn)
    out = sys.stdout.buffer
    writing = threading.Lock()
    threads: list[threading.Thread] = []

    def write(answer: Json) -> None:
        if answer is not None:
            with writing:
                out.write(json.dumps(answer).encode() + b"\n")
                out.flush()

    def ended(signum: int, frame: object) -> None:
        print(f"rowstile mcp: stopped (signal {signum}): the commands running are stopped first", file=sys.stderr)
        server.end()
        writing.acquire(timeout=5)  # an answer another thread is writing is written whole (not one this thread is)
        with contextlib.suppress(OSError, ValueError, RuntimeError):
            out.flush()
        os._exit(128 + signum)

    signal.signal(signal.SIGTERM, ended)
    for raw in sys.stdin.buffer:
        if not raw.strip():
            continue
        try:
            got = json.loads(raw)
        except (ValueError, RecursionError):  # nested too deep to read is not JSON this server takes either
            write(error(None, -32700, "not JSON"))
            continue
        if calls(got):
            threads = [t for t in threads if t.is_alive()]
            thread = threading.Thread(target=lambda got=got: write(server.reply(got)), daemon=True)
            thread.start()
            threads.append(thread)
        else:
            write(server.reply(got))
    for thread in threads:
        thread.join()

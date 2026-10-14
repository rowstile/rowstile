"""A small PostgreSQL client (protocol 3, extended query protocol, text results), standard
library only. Enough for the rowstile command and tests: trust, password, MD5 and
SCRAM-SHA-256 authentication (bound to the TLS channel when the server offers it, as channel_binding
says, and only the methods require_auth allows); TCP (with TLS, as sslmode says, the server's certificate checked
against the root certificate libpq would use) or Unix sockets. A connection string's settings are libpq's: each is
honoured as libpq honours it, left alone where that changes nothing checked, or refused.

    conn = connect(host="/var/run/postgresql", user="app_user", password="...", database="app")
    conn.query("SELECT authz.can($1, $2, $3)", ["file", "11", "view"])   # -> [(True,)]
"""

from __future__ import annotations

import json
import os
import re
import struct
import sys
from collections.abc import Callable, Sequence
from typing import TYPE_CHECKING, NamedTuple, TypeAlias, TypedDict, TypeGuard

if TYPE_CHECKING:
    import socket
    import ssl

# what a column holds, decoded from its text form: NULL, a boolean, an integer, text, an array, or JSON
Value: TypeAlias = "None | bool | int | float | str | list[Value] | dict[str, Value]"
# the fields of an error or a notice: one letter each (M the message, C the code, D the detail, H the hint)
Fields: TypeAlias = "dict[str, str]"


class ConnectArgs(TypedDict):
    host: str
    port: int
    user: str
    password: str | None
    database: str
    options: str | None
    timeout: float
    sslmode: str  # disable | allow | prefer | require | verify-ca | verify-full
    # the root certificates the server's certificate is checked against: a file, or system (the system's); None:
    # root.crt in libpq's folder, if it is there (then require checks against it too, as verify-ca)
    sslrootcert: str | None
    sslcrl: str | None  # revoked certificates, checked with a root certificate file (None: libpq's root.crl)
    sslcrldir: str | None
    ssl_min_protocol_version: str | None  # TLSv1.2 (and below: the command never goes below it) or TLSv1.3
    ssl_max_protocol_version: str | None
    channel_binding: str  # disable | prefer | require
    require_auth: str | None  # the ways the server may ask for the password, as libpq reads them
    target_session_attrs: str  # any | read-write | read-only | primary | standby | prefer-standby
    settings: dict[str, str]  # sent with the start-up: what PGDATESTYLE, PGTZ and PGGEQO set, as libpq sends them


class PgError(Exception):
    def __init__(self, fields: Fields) -> None:
        self.fields = fields
        self.code = fields.get("C", "XX000")
        self.message = fields.get("M", "error")
        super().__init__(f"{self.code}: {self.message}")


class ProtocolError(Exception):
    pass


def _parse_array(text: str) -> list[str | None]:
    """Parse a one-dimensional Postgres array literal ({a,"b c",NULL}) into a list of str/None."""
    if not text.startswith("{") or text.startswith("{{"):  # an array of arrays starts {{: an element never does
        raise ProtocolError(f"not an array of one dimension: {text!r}")
    out: list[str | None] = []
    i = 1
    if text == "{}":
        return out
    while True:  # to the closing brace, which ends every literal the server writes
        if text[i] == '"':
            i += 1
            buf = []
            while text[i] != '"':
                if text[i] == "\\":
                    i += 1
                buf.append(text[i])
                i += 1
            i += 1
            out.append("".join(buf))
        else:
            j = i
            while text[j] not in ",}":
                j += 1
            word = text[i:j]
            out.append(None if word == "NULL" else word)
            i = j
        if text[i] == "}":
            break
        i += 1  # the comma
    return out


_INT = {20, 21, 23, 26}
_INT_ARRAYS = {1005, 1007, 1016}
_TEXT_ARRAYS = {1009, 1015, 1002, 199, 1014, 2951}


def _convert(oid: int, value: bytes | None) -> Value:
    if value is None:
        return None
    text = value.decode()
    if oid == 16:
        return text == "t"
    if oid in _INT:
        return int(text)
    if oid in (114, 3802):
        return json.loads(text)
    try:
        if oid in _TEXT_ARRAYS:
            return list(_parse_array(text))
        if oid in _INT_ARRAYS:
            return [None if x is None else int(x) for x in _parse_array(text)]
        if oid == 1000:
            return [None if x is None else x == "t" for x in _parse_array(text)]
    except (ValueError, IndexError, ProtocolError):
        return text  # two dimensions, or bounds ([0:1]={a,b}): as Postgres writes it
    return text


def _text(value: object) -> str:
    """A parameter as text, as psycopg sends it: a list as an array ({"a","b \\"c\\"",NULL}), true or false; a dict
    as JSON; anything else as str() writes it."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, dict):
        return json.dumps(value)
    if isinstance(value, list):
        items = (
            "NULL"
            if x is None
            else _text(x)
            if isinstance(x, list)
            else '"' + _text(x).replace("\\", "\\\\").replace('"', '\\"') + '"'
            for x in value
        )
        return "{" + ",".join(items) + "}"
    return str(value)


class Connection:
    def __init__(
        self,
        sock: socket.socket,
        user: str,
        password: str | None,
        database: str,
        options: str | None,
        channel_binding: str = "prefer",
        require_auth: str | None = None,
        settings: dict[str, str] | None = None,
    ) -> None:
        self.sock = sock
        self.buf = b""
        self.params: dict[str, str] = {}
        self.in_error = False
        self.busy = False  # a query was sent and its answer not fully read (the connection is unusable)
        self.tag = ""  # what the last statement of query_described did, in the server's words ("DELETE 0")
        self.on_notice: Callable[[Fields], None] | None = None  # called with each NOTICE / WARNING the server sends
        self.address: tuple[str, int] | None = None  # where connect() went, for cancel()
        self.backend: tuple[int, int] | None = None  # this session's process id and key, for cancel()
        self._startup(user, password, database, options, channel_binding, _auth_rules(require_auth), settings or {})

    # --- framing ----------------------------------------------------------
    def _send(self, kind: bytes, payload: bytes = b"") -> None:
        self.sock.sendall(kind + struct.pack("!i", len(payload) + 4) + payload)

    def _recv_exact(self, n: int) -> bytes:
        while len(self.buf) < n:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise ProtocolError("the server closed the connection")
            self.buf += chunk
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def _read(self) -> tuple[bytes, bytes]:
        head = self._recv_exact(5)
        kind, length = head[:1], struct.unpack("!i", head[1:])[0]
        return kind, self._recv_exact(length - 4)

    def _read_or(self, error: PgError | None) -> tuple[bytes, bytes]:
        """The next message; if the server closed the connection after an error (a FATAL one: it was ended, or
        is shutting down), that error, which says why."""
        try:
            return self._read()
        except (ProtocolError, OSError):
            if error is not None:
                raise error from None
            raise

    def cancel(self) -> None:
        """Asks the server to stop the statement this connection is running (a CancelRequest, on a connection of
        its own), then closes this one: its transaction is rolled back."""
        if self.address is not None and self.backend is not None:
            try:
                sock = _socket(*self.address, timeout=3)
                sock.sendall(struct.pack("!iiii", 16, 80877102, *self.backend))
                sock.close()
            except OSError:
                pass
        self.sock.close()

    @staticmethod
    def _cstr(s: str) -> bytes:
        return s.encode() + b"\0"

    @staticmethod
    def _fields(payload: bytes) -> Fields:
        fields: Fields = {}
        for part in payload.split(b"\0"):
            if part:
                fields[chr(part[0])] = part[1:].decode(errors="replace")
        return fields

    # --- start-up and authentication --------------------------------------
    def _startup(
        self,
        user: str,
        password: str | None,
        database: str,
        options: str | None,
        channel_binding: str = "prefer",
        rules: AuthRules | None = None,
        settings: dict[str, str] | None = None,
    ) -> None:
        body = struct.pack("!i", 196608)
        params = {
            **(settings or {}),
            "user": user,
            "database": database,
            "client_encoding": "UTF8",
            "application_name": "rowstile",
        }
        if options:
            params["options"] = options
        for k, v in params.items():
            body += self._cstr(k) + self._cstr(v)
        body += b"\0"
        self.sock.sendall(struct.pack("!i", len(body) + 4) + body)
        scram: _Scram | None = None
        bound = False  # signed in with SCRAM bound to this TLS channel, the server's proof checked
        done = False  # this client did its part: sent the password, or checked the server's SCRAM proof
        while True:
            kind, payload = self._read()
            if kind == b"R":
                code = struct.unpack("!i", payload[:4])[0]
                # each request is checked before anything is answered to it (libpq's check_expected_areq)
                _expected(code, rules, channel_binding, bound, done)
                if code == 0:
                    continue
                if code in (3, 5, 10) and password is None:
                    raise ProtocolError("the server asks for a password")
                if code == 3 and password is not None:
                    self._send(b"p", self._cstr(password))
                    done = True
                elif code == 5 and password is not None:
                    import hashlib

                    salt = payload[4:8]
                    inner = hashlib.md5(password.encode() + user.encode()).hexdigest()
                    outer = hashlib.md5(inner.encode() + salt).hexdigest()
                    self._send(b"p", self._cstr("md5" + outer))
                    done = True
                elif code == 10 and password is not None:
                    mechs = [m.decode() for m in payload[4:].split(b"\0") if m]
                    scram = _Scram(password, *self._binding(mechs, channel_binding, rules))
                    first = scram.client_first().encode()
                    self._send(b"p", self._cstr(scram.mechanism) + struct.pack("!i", len(first)) + first)
                elif code == 11 and scram is not None:
                    self._send(b"p", scram.client_final(payload[4:].decode()).encode())
                elif code == 12 and scram is not None:
                    scram.verify(payload[4:].decode())
                    bound = scram.binding is not None
                    done = True
                else:
                    raise ProtocolError(f"unsupported authentication method {code}")
            elif kind == b"E":
                raise PgError(self._fields(payload))
            elif kind == b"S":
                k, v = payload.split(b"\0")[:2]
                self.params[k.decode()] = v.decode()
            elif kind == b"K":
                pid, key = struct.unpack("!ii", payload[:8])
                self.backend = (pid, key)
            elif kind == b"Z":
                return
            # N (notice): ignored

    def _binding(self, mechs: list[str], channel_binding: str, rules: AuthRules | None) -> tuple[str, bytes | None]:
        """How SCRAM starts on this connection (its GS2 header), and what binds it to the TLS channel: the hash
        of the server's certificate (tls-server-end-point, RFC 5929), when the server offers SCRAM-SHA-256-PLUS
        and channel_binding isn't disable. A server in the middle has another certificate, and then the
        password exchange it passes on fails. Chosen as libpq's pg_SASL_init chooses, and refused as it refuses,
        before anything is sent."""
        tls = _is_tls(self.sock)
        if channel_binding == "require" and not tls:
            raise ProtocolError("channel binding required, but SSL not in use")
        if "SCRAM-SHA-256-PLUS" in mechs and not tls:
            # a server offers it only over TLS: offered here, it belongs to a TLS connection other than this one
            raise ProtocolError("server offered SCRAM-SHA-256-PLUS authentication over a non-SSL connection")
        plus = tls and channel_binding != "disable" and "SCRAM-SHA-256-PLUS" in mechs
        if not plus and "SCRAM-SHA-256" not in mechs:
            raise ProtocolError(f"unsupported SASL mechanisms {mechs}")
        if rules is not None and not rules.scram:
            name = "SCRAM-SHA-256-PLUS" if plus else "SCRAM-SHA-256"
            raise ProtocolError(
                f'authentication method requirement "{rules.text}" failed: server requested {name} authentication'
            )
        if channel_binding == "require" and not plus:
            raise ProtocolError(
                "channel binding is required, but server did not offer an authentication method that supports "
                "channel binding"
            )
        if plus:
            data = _end_point(self.sock)
            if data is None:
                raise ProtocolError("the server's certificate is signed in a way channel binding has no hash for")
            return "p=tls-server-end-point,,", data
        # y: this client could have bound the channel and the server didn't offer to (the server checks that it
        # really didn't); n: it couldn't, or was told not to
        return ("y,," if tls and channel_binding != "disable" else "n,,"), None

    # --- queries ------------------------------------------------------------
    def query(self, sql: str, args: Sequence[object] = ()) -> list[tuple[Value, ...]]:
        """Run one statement with $1..$n parameters (sent as text, see _text); returns a list of tuples."""
        rows, _ = self.query_described(sql, args)
        return rows

    def query_described(
        self, sql: str, args: Sequence[object] = (), text: bool = False
    ) -> tuple[list[tuple[Value, ...]], list[str]]:
        """(rows, column names); text: each value as Postgres writes it (as psql shows it), not read into Python's."""
        bind = b"\0\0" + struct.pack("!hh", 0, len(args))
        for a in args:
            if a is None:
                bind += struct.pack("!i", -1)
            else:
                v = _text(a).encode()
                if b"\0" in v:
                    raise ValueError("parameters cannot contain NUL characters")
                bind += struct.pack("!i", len(v)) + v
        bind += struct.pack("!h", 0)
        msg = (
            b"P"
            + struct.pack("!i", 4 + 1 + len(sql.encode()) + 1 + 2)
            + b"\0"
            + self._cstr(sql)
            + struct.pack("!h", 0)
            + b"B"
            + struct.pack("!i", len(bind) + 4)
            + bind
            + b"D"
            + struct.pack("!i", 6)
            + b"P\0"
            + b"E"
            + struct.pack("!i", 9)
            + b"\0"
            + struct.pack("!i", 0)
            + b"S"
            + struct.pack("!i", 4)
        )
        self.busy = True
        self.sock.sendall(msg)
        rows: list[tuple[Value, ...]] = []
        cols: list[tuple[str, int]] = []
        error: PgError | None = None
        self.tag = ""
        while True:
            kind, payload = self._read_or(error)
            if kind == b"C":
                self.tag = payload.rstrip(b"\0").decode()
            elif kind == b"T":
                n = struct.unpack("!h", payload[:2])[0]
                pos, cols = 2, []
                for _ in range(n):
                    end = payload.index(b"\0", pos)
                    name = payload[pos:end].decode()
                    oid = struct.unpack("!i", payload[end + 7 : end + 11])[0]
                    cols.append((name, oid))
                    pos = end + 19
            elif kind == b"D":
                n = struct.unpack("!h", payload[:2])[0]
                pos = 2
                row: list[Value] = []
                for i in range(n):
                    ln = struct.unpack("!i", payload[pos : pos + 4])[0]
                    pos += 4
                    val = None if ln < 0 else payload[pos : pos + ln]
                    pos += max(ln, 0)
                    row.append((None if val is None else val.decode()) if text else _convert(cols[i][1], val))
                rows.append(tuple(row))
            elif kind == b"E":
                error = PgError(self._fields(payload))
            elif kind == b"N":
                if self.on_notice:
                    self.on_notice(self._fields(payload))
            elif kind == b"Z":
                self.in_error = payload == b"E"
                self.busy = False
                if error:
                    raise error
                return rows, [c[0] for c in cols]
            # 1, 2, n, A, S: nothing to do

    def execute(self, sql: str) -> list[tuple[Value, ...]]:
        """Run a statement without parameters (BEGIN, COMMIT, ...)."""
        return self.query(sql)

    def script(self, sql: str) -> None:
        """Run one or many statements without parameters (the simple query protocol), such as a
        compiled policy. Results are dropped; the first error is raised once the server is done."""
        data = sql.encode()
        if b"\0" in data:
            raise ValueError("SQL cannot contain NUL characters")
        self.busy = True
        self._send(b"Q", data + b"\0")
        error: PgError | None = None
        while True:
            kind, payload = self._read_or(error)
            if kind == b"E":
                error = error or PgError(self._fields(payload))
            elif kind == b"N":
                if self.on_notice:
                    self.on_notice(self._fields(payload))
            elif kind == b"Z":
                self.in_error = payload == b"E"
                self.busy = False
                if error:
                    raise error
                return
            # T, D, C, I, S, ...: nothing to keep

    def cursor(self) -> Cursor:
        return Cursor(self)

    def close(self) -> None:
        try:
            self._send(b"X")
        except OSError:
            pass
        self.sock.close()


class Cursor:
    """Just enough DB-API for the generated Python client: %s placeholders, fetchone/fetchall, description."""

    def __init__(self, conn: Connection) -> None:
        self.conn = conn
        self.rows: list[tuple[Value, ...]] = []
        self.description: list[tuple[str, None, None, None, None, None, None]] | None = None

    def __enter__(self) -> Cursor:
        return self

    def __exit__(self, *exc: object) -> bool:
        return False

    def execute(self, sql: str, args: Sequence[object] = (), /) -> None:
        parts = sql.split("%s")
        if len(parts) - 1 != len(args):
            raise ValueError("the number of %s placeholders and arguments differ")
        text = parts[0] + "".join(f"${i + 1}" + p for i, p in enumerate(parts[1:]))
        self.rows, names = self.conn.query_described(text, list(args))
        self.description = [(n, None, None, None, None, None, None) for n in names]

    def fetchone(self) -> tuple[Value, ...] | None:
        return self.rows.pop(0) if self.rows else None

    def fetchall(self) -> list[tuple[Value, ...]]:
        rows, self.rows = self.rows, []
        return rows


def _saslprep(password: str) -> str:
    """The password as SCRAM prepares it (RFC 4013): what maps to nothing is dropped, other spaces become a space,
    compatibility characters their plain form. One with a prohibited character is used as it is, as Postgres does."""
    if password.isascii():
        return password
    import stringprep
    import unicodedata

    mapped = "".join(" " if stringprep.in_table_c12(c) else c for c in password if not stringprep.in_table_b1(c))
    out = unicodedata.normalize("NFKC", mapped)
    prohibited = (
        stringprep.in_table_a1,
        stringprep.in_table_c12,
        stringprep.in_table_c21_c22,
        stringprep.in_table_c3,
        stringprep.in_table_c4,
        stringprep.in_table_c5,
        stringprep.in_table_c6,
        stringprep.in_table_c7,
        stringprep.in_table_c8,
        stringprep.in_table_c9,
    )
    return password if any(f(c) for c in out for f in prohibited) else out


# the hash a certificate was signed with, by its signature algorithm (an OID's bytes); MD5 and SHA-1 count as
# SHA-256 for channel binding (RFC 5929)
def _oid(dotted: str) -> bytes:
    arcs = [int(a) for a in dotted.split(".")]
    out = bytes([arcs[0] * 40 + arcs[1]])
    for arc in arcs[2:]:
        part = bytes([arc & 0x7F])
        while arc > 0x7F:
            arc >>= 7
            part = bytes([arc & 0x7F | 0x80]) + part
        out += part
    return out


_SIGNED_WITH = {
    _oid(o): h
    for o, h in (
        ("1.2.840.113549.1.1.4", "sha256"),
        ("1.2.840.113549.1.1.5", "sha256"),
        ("1.2.840.113549.1.1.11", "sha256"),
        ("1.2.840.113549.1.1.12", "sha384"),
        ("1.2.840.113549.1.1.13", "sha512"),
        ("1.2.840.113549.1.1.14", "sha224"),
        ("1.2.840.10045.4.1", "sha256"),
        ("1.2.840.10045.4.3.1", "sha224"),
        ("1.2.840.10045.4.3.2", "sha256"),
        ("1.2.840.10045.4.3.3", "sha384"),
        ("1.2.840.10045.4.3.4", "sha512"),
    )
}
_RSA_PSS = _oid("1.2.840.113549.1.1.10")  # names its hash in its parameters (SHA-1 if it names none)
_PSS_HASHES = {
    _oid("2.16.840.1.101.3.4.2.1"): "sha256",
    _oid("2.16.840.1.101.3.4.2.2"): "sha384",
    _oid("2.16.840.1.101.3.4.2.3"): "sha512",
    _oid("2.16.840.1.101.3.4.2.4"): "sha224",
}


def _der(data: bytes, at: int) -> tuple[int, int, int]:
    """The DER element at `at`: its tag, where its content starts, and where it ends."""
    length, start = data[at + 1], at + 2
    if length & 0x80:
        n = length & 0x7F
        length, start = int.from_bytes(data[start : start + n], "big"), start + n
    return data[at], start, start + length


def _signature_hash(cert: bytes) -> str | None:
    """The hash a certificate (DER) was signed with, for channel binding; None if its signature has none (Ed25519)
    or isn't one this knows. A certificate is SEQUENCE { what is signed, the signature's algorithm, the signature }."""
    try:
        _, start, _ = _der(cert, 0)
        _, _, signed_end = _der(cert, start)
        _, algorithm, algorithm_end = _der(cert, signed_end)
        tag, oid_start, oid_end = _der(cert, algorithm)
    except IndexError:
        return None
    oid = cert[oid_start:oid_end]
    if tag != 6:
        return None
    if oid == _RSA_PSS:
        parameters = cert[oid_end:algorithm_end]
        return next((h for o, h in _PSS_HASHES.items() if bytes([6, len(o)]) + o in parameters), "sha256")
    return _SIGNED_WITH.get(oid)


def _is_tls(sock: socket.socket) -> TypeGuard[ssl.SSLSocket]:
    """Whether the socket is under TLS. ssl is imported only to put one under it (_tls): until then, none is."""
    tls = sys.modules.get("ssl")
    return tls is not None and isinstance(sock, tls.SSLSocket)


def _end_point(sock: socket.socket) -> bytes | None:
    """tls-server-end-point: the hash of the server's certificate, or None if there is nothing to hash it with."""
    import hashlib

    cert = sock.getpeercert(binary_form=True) if _is_tls(sock) else None
    name = _signature_hash(cert) if cert else None
    return hashlib.new(name, cert).digest() if cert and name else None


# what the server asks for, by the code of its authentication request: as libpq describes it in a refusal
ASKED = {
    3: "server requested a cleartext password",
    5: "server requested a hashed password",
    7: "server requested GSSAPI authentication",
    8: "server requested GSSAPI authentication",
    9: "server requested SSPI authentication",
    10: "server requested SASL authentication",
    11: "server requested SASL authentication",
    12: "server requested SASL authentication",
}
# require_auth's methods, by the requests each allows (SCRAM and OAuth are SASL's mechanisms: below)
METHODS = {"password": {3}, "md5": {5}, "gss": {7, 8}, "sspi": {8, 9}, "scram-sha-256": set(), "oauth": set()}


class AuthRules(NamedTuple):
    """require_auth, read: which authentication requests the server may make."""

    text: str  # as given, for a refusal
    codes: frozenset[int]  # the requests allowed
    scram: bool  # SCRAM-SHA-256 allowed (the SASL mechanism this client does)
    required: bool  # the server must ask for something: it may not sign the client in unasked (trust)


def _auth_rules(text: str | None) -> AuthRules | None:
    """require_auth as libpq reads it: the methods the server may ask for (password, md5, gss, sspi,
    scram-sha-256, oauth, and none for signing in unasked), or, each after a !, those it may not."""
    if not text:
        return None
    parts = text.split(",")
    negated = parts[0].startswith("!")
    codes: set[int] = set(ASKED) if negated else set()
    mechs: set[str] = {"scram-sha-256", "oauth"} if negated else set()
    required = not negated
    seen: set[str] = set()
    for part in parts:
        method = part.removeprefix("!")
        if part.startswith("!") != negated:
            raise ValueError(
                f'negative require_auth method "{part}" cannot be mixed with non-negative methods'
                if negated is False
                else f'require_auth method "{part}" cannot be mixed with negative methods'
            )
        if method not in METHODS and method != "none":
            raise ValueError(f'invalid require_auth value: "{method}"')
        if method in seen:
            raise ValueError(f'require_auth method "{part}" is specified more than once')
        seen.add(method)
        if method == "none":
            required = negated  # none: the server may sign in unasked; !none: it may not
        elif METHODS[method]:
            codes = codes - METHODS[method] if negated else codes | METHODS[method]
        else:
            mechs = mechs - {method} if negated else mechs | {method}
    codes = codes | {10, 11, 12} if mechs else codes - {10, 11, 12}
    return AuthRules(text, frozenset(codes), "scram-sha-256" in mechs, required)


def _expected(code: int, rules: AuthRules | None, channel_binding: str, bound: bool, done: bool) -> None:
    """Refuses an authentication request the settings don't allow, before anything is answered to it, as libpq's
    check_expected_areq: require_auth's methods, and channel_binding=require, which takes only SCRAM bound to the
    TLS channel. Code 0 is the server saying the client is signed in."""
    if rules is not None:
        if code == 0 and rules.required and not done:
            reason = "server did not complete authentication"
        elif code != 0 and code not in rules.codes:
            reason = ASKED.get(code, "server requested an unknown authentication type")
        else:
            reason = None
        if reason:
            raise ProtocolError(f'authentication method requirement "{rules.text}" failed: {reason}')
    if channel_binding == "require" and code not in (10, 11, 12):
        if code != 0:
            raise ProtocolError("channel binding required but not supported by server's authentication request")
        if not bound:
            raise ProtocolError("channel binding required, but server authenticated client without channel binding")


# SCRAM's hashing (hashlib, hmac, base64) is imported here, as it starts: a connection without a password doesn't
# load OpenSSL's hashes
class _Scram:
    def __init__(self, password: str, header: str = "n,,", binding: bytes | None = None) -> None:
        self.password = _saslprep(password).encode()
        self.header = header  # GS2: n,, (no channel binding), y,, (the server offered none), p=...,, (bound)
        self.binding = binding
        self.mechanism = "SCRAM-SHA-256-PLUS" if binding is not None else "SCRAM-SHA-256"
        import base64

        self.nonce = base64.b64encode(os.urandom(18)).decode()
        self.first_bare = ""
        self.auth_message = b""
        self.server_key = b""

    def client_first(self) -> str:
        self.first_bare = f"n=,r={self.nonce}"
        return self.header + self.first_bare

    def client_final(self, server_first: str) -> str:
        attrs = dict(kv.split("=", 1) for kv in server_first.split(","))
        if not attrs["r"].startswith(self.nonce):
            raise ProtocolError("SCRAM: the server's nonce does not extend ours")
        import base64
        import hashlib
        import hmac

        salted = hashlib.pbkdf2_hmac("sha256", self.password, base64.b64decode(attrs["s"]), int(attrs["i"]))
        client_key = hmac.new(salted, b"Client Key", hashlib.sha256).digest()
        stored = hashlib.sha256(client_key).digest()
        bind = base64.b64encode(self.header.encode() + (self.binding or b"")).decode()  # biws for n,,
        without_proof = f"c={bind},r={attrs['r']}"
        self.auth_message = f"{self.first_bare},{server_first},{without_proof}".encode()
        signature = hmac.new(stored, self.auth_message, hashlib.sha256).digest()
        proof = bytes(a ^ b for a, b in zip(client_key, signature, strict=True))
        self.server_key = hmac.new(salted, b"Server Key", hashlib.sha256).digest()
        return f"{without_proof},p={base64.b64encode(proof).decode()}"

    def verify(self, server_final: str) -> None:
        import base64
        import hashlib
        import hmac

        attrs = dict(kv.split("=", 1) for kv in server_final.split(","))
        want = hmac.new(self.server_key, self.auth_message, hashlib.sha256).digest()
        if not hmac.compare_digest(base64.b64decode(attrs.get("v", "")), want):
            raise ProtocolError("SCRAM: the server could not prove it knows the password")


SSLMODES = ("disable", "allow", "prefer", "require", "verify-ca", "verify-full")
CHANNEL_BINDINGS = ("disable", "prefer", "require")
TARGETS = ("any", "read-write", "read-only", "primary", "standby", "prefer-standby")
# TLS versions as libpq names them (in any case). This client never goes below TLSv1.2: a minimum below it is
# taken as TLSv1.2, which only refuses more servers; a maximum below it is refused
TLS_VERSIONS = {"tlsv1": 10, "tlsv1.1": 11, "tlsv1.2": 12, "tlsv1.3": 13}

# libpq's connection settings (libpq 18), each with the variable that gives it where the connection string doesn't
LIBPQ: dict[str, str | None] = {
    "host": "PGHOST",
    "hostaddr": "PGHOSTADDR",
    "port": "PGPORT",
    "dbname": "PGDATABASE",
    "user": "PGUSER",
    "password": "PGPASSWORD",
    "passfile": "PGPASSFILE",
    "require_auth": "PGREQUIREAUTH",
    "channel_binding": "PGCHANNELBINDING",
    "connect_timeout": "PGCONNECT_TIMEOUT",
    "client_encoding": "PGCLIENTENCODING",
    "options": "PGOPTIONS",
    "application_name": "PGAPPNAME",
    "fallback_application_name": None,
    "keepalives": None,
    "keepalives_idle": None,
    "keepalives_interval": None,
    "keepalives_count": None,
    "tcp_user_timeout": None,
    "replication": None,
    "gssencmode": "PGGSSENCMODE",
    "sslmode": "PGSSLMODE",
    "sslnegotiation": "PGSSLNEGOTIATION",
    "sslcompression": "PGSSLCOMPRESSION",
    "sslcert": "PGSSLCERT",
    "sslkey": "PGSSLKEY",
    "sslcertmode": "PGSSLCERTMODE",
    "sslpassword": None,
    "sslrootcert": "PGSSLROOTCERT",
    "sslcrl": "PGSSLCRL",
    "sslcrldir": "PGSSLCRLDIR",
    "sslsni": "PGSSLSNI",
    "requirepeer": "PGREQUIREPEER",
    "ssl_min_protocol_version": "PGSSLMINPROTOCOLVERSION",
    "ssl_max_protocol_version": "PGSSLMAXPROTOCOLVERSION",
    "min_protocol_version": "PGMINPROTOCOLVERSION",
    "max_protocol_version": "PGMAXPROTOCOLVERSION",
    "krbsrvname": "PGKRBSRVNAME",
    "gsslib": "PGGSSLIB",
    "gssdelegation": "PGGSSDELEGATION",
    "target_session_attrs": "PGTARGETSESSIONATTRS",
    "load_balance_hosts": "PGLOADBALANCEHOSTS",
    "service": "PGSERVICE",
    "scram_client_key": None,
    "scram_server_key": None,
    "oauth_issuer": None,
    "oauth_client_id": None,
    "oauth_client_secret": None,
    "oauth_scope": None,
    "sslkeylogfile": None,
}
# what this client does with each. Honoured: done as libpq does it
HONOURED = frozenset(
    {
        "host",
        "port",
        "dbname",
        "user",
        "password",
        "options",
        "connect_timeout",
        "sslmode",
        "sslrootcert",
        "sslcrl",
        "sslcrldir",
        "ssl_min_protocol_version",
        "ssl_max_protocol_version",
        "channel_binding",
        "require_auth",
        "target_session_attrs",
    }
)
# left alone: what they change is neither what is checked nor where the command connects
IGNORED = {
    "application_name": "the command names its sessions rowstile",
    "fallback_application_name": "the command names its sessions rowstile",
    "client_encoding": "the command reads and writes UTF-8 itself",
    "keepalives": "TCP's own timers",
    "keepalives_idle": "TCP's own timers",
    "keepalives_interval": "TCP's own timers",
    "keepalives_count": "TCP's own timers",
    "tcp_user_timeout": "TCP's own timers",
    "load_balance_hosts": "one host leaves nothing to balance",
    "sslcompression": "TLS compression is off in OpenSSL",
    "sslsni": "the name sent in the TLS handshake is a hint for routing, which nothing checks",
    "sslpassword": "a client key's passphrase, and the command uses no client key",
    "sslkeylogfile": "a log of the TLS keys, for debugging",
    "krbsrvname": "GSS sign-in, which the command doesn't do",
    "gsslib": "GSS sign-in, which the command doesn't do",
    "gssdelegation": "GSS sign-in, which the command doesn't do",
    "max_protocol_version": "the command speaks protocol 3.0, which no maximum excludes",
}
# taken with these values, which are what the command does anyway; any other is refused
ONLY = {
    "gssencmode": (("disable", "prefer"), "GSS encryption"),
    "sslcertmode": (("disable", "allow"), "a client certificate"),
    "sslnegotiation": (("postgres",), "TLS without asking the server first"),
    "min_protocol_version": (("3.0",), "a protocol version above 3.0"),
    "replication": (("0", "false", "off", "no"), "a replication connection"),
}
# never done: refused when given
REFUSED = {
    "service": "connection services",
    "hostaddr": "a host address apart from its name",
    "sslcert": "client certificates",
    "sslkey": "client certificates",
    "requirepeer": "requirepeer",
    "scram_client_key": "SCRAM keys in place of the password",
    "scram_server_key": "SCRAM keys in place of the password",
    "oauth_issuer": "OAuth",
    "oauth_client_id": "OAuth",
    "oauth_client_secret": "OAuth",
    "oauth_scope": "OAuth",
}
# and passfile, refused only when no password is given: libpq reads the file only then
# what libpq sends with its start-up from these variables, as the session's settings
STARTUP = {"PGDATESTYLE": "datestyle", "PGTZ": "timezone", "PGGEQO": "geqo"}
BLANKS = " \t\n\r\f\v"  # what separates the settings of a keyword string (C's isspace, as libpq reads it)
QUOTING = (
    "put a value with spaces in single quotes, and a quote or a backslash in a value after a backslash "
    "(password='it\\'s'), or use a postgresql:// URL"
)


def _keywords(text: str) -> list[tuple[str, str]]:
    """The settings of a keyword string, read as libpq reads one: key=value, spaces around = allowed; a value in
    single quotes may hold spaces; a backslash takes the character after it as it is (\\' and \\\\, in quotes or
    not), and any other character is itself (a " too)."""
    out: list[tuple[str, str]] = []
    i, n = 0, len(text)
    while i < n:
        if text[i] in BLANKS:
            i += 1
            continue
        start = i
        while i < n and text[i] != "=" and text[i] not in BLANKS:
            i += 1
        key = text[start:i]
        while i < n and text[i] in BLANKS:
            i += 1
        if i == n or text[i] != "=":
            raise ValueError(f'can\'t read the connection string: "{key}" has no "=" after it: {QUOTING}')
        i += 1
        while i < n and text[i] in BLANKS:
            i += 1
        quoted = i < n and text[i] == "'"
        i += quoted
        value: list[str] = []
        while i < n and (text[i] != "'" if quoted else text[i] not in BLANKS):
            if text[i] == "\\":
                i += 1  # a backslash at the very end takes nothing
            value.append(text[i : i + 1])
            i += 1
        if quoted and i >= n:
            raise ValueError(f"can't read the connection string: a quote isn't closed: {QUOTING}")
        i += quoted  # the closing quote
        out.append((key, "".join(value)))
    return out


def parse_dsn(text: str | None) -> ConnectArgs:
    """connect() arguments from "host=... port=... user=... password=... dbname=... sslmode=..." (read as libpq
    reads it) or a postgresql:// URL (its ?options too), with libpq's variables (PGHOST, PGSSLMODE, ...) for
    whatever is left out. Each of libpq's settings is honoured as libpq honours it, left alone where that changes
    nothing checked, or refused (ValueError, naming it); so are several hosts, and a setting libpq doesn't have, in
    a keyword string. A URL's other options (an ORM's own: ?schema=, ?pgbouncer=) are left to whoever they are
    for."""
    out: dict[str, str] = {}

    def setting(k: str, v: str, strict: bool) -> None:
        if k == "requiressl":  # libpq's old way to say sslmode
            k, v = "sslmode", "require" if v.startswith("1") else "prefer"
        if k in LIBPQ:
            out[k] = v
        elif strict:
            raise ValueError(f"unknown connection setting '{k}' (use host, port, user, password, dbname, sslmode)")

    def one(hosts: str) -> str:
        if "," in hosts:
            raise ValueError(
                f"the connection asks for several hosts ({hosts}), which the rowstile command doesn't do: name one"
            )
        return hosts

    if text and re.match(r"postgres(ql)?://", text):
        # a URL: postgresql://user:password@host:port/dbname?sslmode=require
        import urllib.parse

        u = urllib.parse.urlsplit(text)
        one(u.netloc.rpartition("@")[2])
        try:
            port = u.port
        except ValueError:
            raise ValueError(
                "the URL's port isn't a number: a #, ? or / in the password must be written %23, %3F, %2F"
            ) from None
        for k, v in (
            ("host", u.hostname),
            ("port", port),
            ("user", u.username),
            ("password", u.password),
            ("dbname", u.path.lstrip("/") or None),
        ):
            if v is not None:
                out[k] = urllib.parse.unquote(v) if isinstance(v, str) else str(v)
        for k, v in urllib.parse.parse_qsl(u.query, keep_blank_values=True):
            if k == "ssl":  # JDBC's way to ask for TLS, which libpq takes in a URL, in its place among the others
                if v != "true":
                    raise ValueError(
                        f'invalid URI query parameter: "ssl" ({v!r}): libpq reads only ssl=true (sslmode=require);'
                        " say sslmode= instead (disable, prefer, require, verify-full)"
                    )
                k, v = "sslmode", "require"
            setting(k, v, strict=False)
        text = ""
    for k, v in _keywords(text or ""):
        setting(k, v, strict=True)

    def given(k: str) -> str | None:
        """A setting as libpq takes it: from the string, else from its variable; empty is not given."""
        var = LIBPQ[k]
        return (out[k] if k in out else os.environ.get(var) if var else None) or None

    def refused(k: str, what: str, then: str = "") -> ValueError:
        how = f"{k}={out[k]}" if k in out else f"{LIBPQ[k]}={os.environ.get(LIBPQ[k] or '')}"
        return ValueError(f"the connection asks for {what} ({how}), which the rowstile command doesn't do{then}")

    for k, what in REFUSED.items():
        if given(k):
            raise refused(k, what)
    for k, (values, what) in ONLY.items():
        value = given(k)
        if value and value not in values:
            raise refused(k, what)
    password = given("password")
    if given("passfile") and not password:
        raise refused("passfile", "a password file", ": give the password in the connection string or PGPASSWORD")
    sslrootcert = given("sslrootcert")
    sslmode = given("sslmode")
    if sslmode is None and os.environ.get("PGREQUIRESSL", "").startswith("1"):
        sslmode = "require"  # libpq's old variable, where nothing else says
    if sslmode is None:
        sslmode = "verify-full" if sslrootcert == "system" else "prefer"  # as libpq: the system's roots, checked
    if sslmode not in SSLMODES:
        raise ValueError(f"sslmode={sslmode}: one of {', '.join(SSLMODES)}")
    if sslrootcert == "system" and sslmode != "verify-full":
        raise ValueError(f'weak sslmode "{sslmode}" may not be used with sslrootcert=system (use "verify-full")')
    channel_binding = given("channel_binding") or "prefer"
    if channel_binding not in CHANNEL_BINDINGS:
        raise ValueError(f"channel_binding={channel_binding}: one of {', '.join(CHANNEL_BINDINGS)}")
    require_auth = given("require_auth")
    _auth_rules(require_auth)  # read now, so that a mistake in it is said before connecting
    target = given("target_session_attrs") or "any"
    if target not in TARGETS:
        raise ValueError(f'invalid target_session_attrs value: "{target}"')
    tls = {k: given(k) for k in ("ssl_min_protocol_version", "ssl_max_protocol_version")}
    for k, version in tls.items():
        if version and version.lower() not in TLS_VERSIONS:
            raise ValueError(f'invalid "{k}" value: "{version}"')
    low, high = (TLS_VERSIONS[(v or "TLSv1.2").lower()] for v in tls.values())
    if tls["ssl_max_protocol_version"] and high < low:
        raise ValueError("invalid SSL protocol version range")
    if tls["ssl_max_protocol_version"] and high < 12:
        raise refused("ssl_max_protocol_version", "TLS older than TLSv1.2")
    host = one(given("host") or "/var/run/postgresql")
    port = given("port") or "5432"
    user = given("user") or "postgres"
    timeout = given("connect_timeout") or "10"
    if not port.isdigit() or not timeout.isdigit():
        raise ValueError(
            f"the port and connect_timeout are numbers, not {port!r}"
            if not port.isdigit()
            else f"connect_timeout is a number of seconds, not {timeout!r}"
        )
    return {
        "host": host,
        "port": int(port),
        "user": user,
        "password": password,
        "database": given("dbname") or user,
        "options": given("options"),
        "timeout": float(timeout) or 10,
        "sslmode": sslmode,
        "sslrootcert": sslrootcert,
        "sslcrl": given("sslcrl"),
        "sslcrldir": given("sslcrldir"),
        "ssl_min_protocol_version": tls["ssl_min_protocol_version"],
        "ssl_max_protocol_version": tls["ssl_max_protocol_version"],
        "channel_binding": channel_binding,
        "require_auth": require_auth,
        "target_session_attrs": target,
        "settings": {
            name: value
            for var, name in STARTUP.items()
            if (value := os.environ.get(var)) and value.lower() != "default"
        },
    }


def _socket(host: str, port: int, timeout: float) -> socket.socket:
    import socket

    if host.startswith("/"):
        if sys.platform == "win32":
            raise ProtocolError(f"host={host} is a Unix socket, which Windows doesn't have: use host=localhost")
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect(os.path.join(host, f".s.PGSQL.{port}"))
    else:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    return sock


def _libpq_file(name: str) -> str | None:
    """A file in libpq's own folder, where it looks for root.crt and root.crl: ~/.postgresql (HOME, else the
    user's own folder), or %APPDATA%\\postgresql on Windows. None: there is no folder to look in."""
    if sys.platform == "win32":
        appdata = os.environ.get("APPDATA")
        return os.path.join(appdata, "postgresql", name) if appdata else None
    home = os.environ.get("HOME")
    if not home:
        import pwd

        try:
            home = pwd.getpwuid(os.geteuid()).pw_dir
        except KeyError:
            return None
    return os.path.join(home, ".postgresql", name)


def _tls(
    sock: socket.socket,
    host: str,
    sslmode: str,
    sslrootcert: str | None,
    sslcrl: str | None = None,
    sslcrldir: str | None = None,
    minimum: str | None = None,
    maximum: str | None = None,
) -> socket.socket:
    """The socket under TLS, as sslmode says, as libpq does it: asked for (SSLRequest), and taken if the server has
    it; require and stronger refuse a server without it. The server's certificate is checked against the root
    certificate libpq would use: sslrootcert, else root.crt in libpq's folder (require then checks it too, as
    verify-ca), or the system's with sslrootcert=system. verify-ca and verify-full go on only with one, and
    verify-full checks the server's name too. With a root certificate file, a certificate sslcrl, sslcrldir (else
    root.crl in libpq's folder) says is revoked is refused."""
    sock.sendall(struct.pack("!ii", 8, 80877103))
    answer = sock.recv(1)
    if answer == b"N":
        if sslmode in ("require", "verify-ca", "verify-full"):
            raise ProtocolError(f"the server doesn't do TLS, and sslmode={sslmode} asks for it")
        return sock
    if answer != b"S":
        raise ProtocolError("the server didn't answer as Postgres does (is this the right host and port?)")
    import ssl

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE  # encrypted, the server not checked: require without a root certificate
    root = sslrootcert or _libpq_file("root.crt")
    if root == "system":
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_default_certs()
    elif root and os.path.exists(root):
        try:
            context.load_verify_locations(cafile=root)
        except (OSError, ssl.SSLError) as e:
            raise ProtocolError(f'could not read root certificate file "{root}": {e}') from None
        context.verify_mode = ssl.CERT_REQUIRED
        crl = sslcrl or (None if sslcrldir else _libpq_file("root.crl"))
        if crl or sslcrldir:
            try:
                context.load_verify_locations(cafile=crl, capath=sslcrldir)
                context.verify_flags |= ssl.VERIFY_CRL_CHECK_CHAIN  # every certificate of the chain, as libpq
            except (OSError, ssl.SSLError):
                pass  # none there: libpq goes on without one too
    elif sslmode in ("verify-ca", "verify-full"):
        raise ProtocolError(
            (f'root certificate file "{root}" does not exist' if root else "no home folder to find root.crt in")
            + ": give it with sslrootcert, use the system's trusted roots with sslrootcert=system, or set an sslmode "
            "that doesn't check the server's certificate"
        )
    context.check_hostname = sslmode == "verify-full"  # what sslrootcert=system comes with (parse_dsn)
    context.minimum_version = ssl.TLSVersion.TLSv1_3 if (minimum or "").lower() == "tlsv1.3" else ssl.TLSVersion.TLSv1_2
    if maximum:
        context.maximum_version = ssl.TLSVersion.TLSv1_2 if maximum.lower() == "tlsv1.2" else ssl.TLSVersion.TLSv1_3
    try:
        return context.wrap_socket(sock, server_hostname=host)
    except ssl.SSLError as e:
        raise ProtocolError(f"TLS with the server failed (sslmode={sslmode}): {e}") from None


def _target(conn: Connection, wanted: str) -> None:
    """target_session_attrs, checked as libpq checks a host once signed in: from what the server said as it started
    (default_transaction_read_only, in_hot_standby), else by asking it. prefer-standby, with one host, takes it."""
    said = None
    if wanted in ("read-write", "read-only"):
        reported = (conn.params.get("default_transaction_read_only"), conn.params.get("in_hot_standby"))
        asked = None in reported  # not said as it started: asked, as libpq asks
        read_only = conn.query("SHOW transaction_read_only")[0][0] == "on" if asked else "on" in reported
        if read_only == (wanted == "read-write"):
            said = "session is read-only" if read_only else "session is not read-only"
    elif wanted in ("primary", "standby"):
        reported_standby = conn.params.get("in_hot_standby")
        if reported_standby is None:
            standby = conn.query("SELECT pg_catalog.pg_is_in_recovery()")[0][0] is True
        else:
            standby = reported_standby == "on"
        if standby == (wanted == "primary"):
            said = "server is in hot standby mode" if standby else "server is not in hot standby mode"
    if said:
        conn.close()
        raise ProtocolError(said)


def connect(
    host: str = "localhost",
    port: int = 5432,
    user: str = "postgres",
    password: str | None = None,
    database: str | None = None,
    options: str | None = None,
    timeout: float = 10,
    sslmode: str = "prefer",
    sslrootcert: str | None = None,
    channel_binding: str = "prefer",
    sslcrl: str | None = None,
    sslcrldir: str | None = None,
    ssl_min_protocol_version: str | None = None,
    ssl_max_protocol_version: str | None = None,
    require_auth: str | None = None,
    target_session_attrs: str = "any",
    settings: dict[str, str] | None = None,
) -> Connection:
    sock = _socket(host, port, timeout)
    try:
        if not host.startswith("/") and sslmode != "disable":
            sock = _tls(
                sock, host, sslmode, sslrootcert, sslcrl, sslcrldir, ssl_min_protocol_version, ssl_max_protocol_version
            )
        # the timeout holds until it is signed in
        conn = Connection(sock, user, password, database or user, options, channel_binding, require_auth, settings)
        _target(conn, target_session_attrs)
    except BaseException:
        sock.close()
        raise
    sock.settimeout(None)
    conn.address = (host, port)
    return conn

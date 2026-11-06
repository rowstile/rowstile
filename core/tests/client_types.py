#!/usr/bin/env python3
"""client_types: the generated TypeScript client (rowstile client ts) under tsc --strict. It accepts correct
calls and refuses names the policy doesn't have. No database.

    python3 tests/client_types.py        # needs tsc: on PATH, or the repository's (npm ci at the root)

tools_test.py runs the same check where tsc is installed; CI's javascript job runs this file.
"""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
import compile_policy  # noqa: E402

USE = """import { authz, asUser, Queryable } from "./authz";
declare const db: Queryable;
async function main() {
  await asUser(db, 7, async (tx) => {
    const a = authz(tx);
    const ok: boolean = await a.can("file", 11, "edit");
    await a.share("folder", 3, "viewer", "user", 4, { expiresAt: new Date() });
    // @ts-expect-error: files have no permission 'fly'
    await a.can("file", 11, "fly");
    // @ts-expect-error: 'owner' is not a shared relation
    await a.share("folder", 3, "owner", "user", 4);
    // @ts-expect-error: no type 'robot'
    await a.list("robot", "view");
    return ok;
  });
}
main();
"""
WRONG = ("fly", "owner", "robot")  # the names USE gets wrong, one a line

# keys of several columns and the text Postgres writes for each (SELECT ROW(...)::text: tools_test.py asks it again),
# and a key of one column, which is its value. A field is quoted for ASCII's six spaces and no other space
KEYS: list[tuple[tuple[int | str | None, ...], str]] = [
    ((1, "plain"), "(1,plain)"),
    ((1, "a b"), '(1,"a b")'),
    *(((1, f"a{c}b"), f'(1,"a{c}b")') for c in "\t\n\v\f\r"),
    # a no-break space, an em space, NEL, a file separator and a zero-width no-break space
    *(((1, f"a{c}b"), f"(1,a{c}b)") for c in map(chr, (0xA0, 0x2003, 0x85, 0x1C, 0xFEFF))),
    ((1, ""), '(1,"")'),
    ((1, None), "(1,)"),
    ((1, 'q"t'), '(1,"q""t")'),
    ((1, "b\\s"), '(1,"b\\\\s")'),
    ((1, "(1)"), '(1,"(1)")'),
    (("x,y", 2), '("x,y",2)'),
    ((7,), "7"),
]


def tsc() -> list[str] | None:
    """How to run tsc here: the one on PATH, else the repository's own (node_modules, after npm ci)."""
    found = shutil.which("tsc")
    if found:
        return [found]
    local = os.path.join(os.path.dirname(ROOT), "node_modules", "typescript", "bin", "tsc")
    node = shutil.which("node")
    return [node, local] if node and os.path.exists(local) else None


def type_check(ts: str, use: str = USE) -> tuple[bool, str] | None:
    """Whether `use` type-checks against the client `ts`, and tsc's output; None when there is no tsc."""
    cmd = tsc()
    if cmd is None:
        return None
    with tempfile.TemporaryDirectory() as tmp:
        for name, text in (("authz.ts", ts), ("use.ts", use)):
            with open(os.path.join(tmp, name), "w", encoding="utf-8") as fh:
                fh.write(text)
        r = subprocess.run(
            [
                *cmd,
                "--noEmit",
                "--strict",
                "--target",
                "es2020",
                "--module",
                "esnext",
                "--moduleResolution",
                "bundler",
                os.path.join(tmp, "use.ts"),
            ],
            capture_output=True,
            text=True,
        )
    return r.returncode == 0, r.stdout + r.stderr


def key_texts(ts: str) -> list[tuple[str, str]] | None:
    """What the client `ts` sends and what it shows for each of KEYS (its `s` and `shown`), compiled by tsc and run
    in Node; None when there is no tsc."""
    cmd = tsc()
    node = shutil.which("node")
    if cmd is None or node is None:
        return None
    with tempfile.TemporaryDirectory() as tmp:
        source = os.path.join(tmp, "authz.ts")
        with open(source, "w", encoding="utf-8") as fh:
            fh.write(ts + "\nexport const keyTexts = (ids: Id[]): string[][] => ids.map((id) => [s(id), shown(id)]);\n")
        with open(os.path.join(tmp, "package.json"), "w", encoding="utf-8") as fh:
            fh.write('{"type": "module"}\n')
        built = subprocess.run(
            [*cmd, "--strict", "--target", "es2020", "--module", "esnext", "--moduleResolution", "bundler", source],
            capture_output=True,
            text=True,
        )
        if built.returncode != 0:
            raise SystemExit(f"client_types: the client doesn't build: {built.stdout}{built.stderr}")
        script = (
            "import(process.argv[1]).then((m) => console.log(JSON.stringify(m.keyTexts(JSON.parse(process.argv[2])))))"
        )
        ran = subprocess.run(
            [node, "-e", script, Path(tmp, "authz.js").as_uri(), json.dumps([list(k) for k, _ in KEYS])],
            capture_output=True,
            text=True,
            check=True,
        )
    return [(sent, shown) for sent, shown in json.loads(ran.stdout)]


def main() -> None:
    policy = os.path.join(ROOT, "example", "docs.authz")
    ts = compile_policy.load(policy).client("ts", "docs.authz")
    fails = 0

    def check(label: str, good: bool, detail: str) -> None:
        nonlocal fails
        if good:
            print(f"ok    {label}")
        else:
            fails += 1
            print(f"FAIL  {label}: {detail}")

    # an @ts-expect-error whose next line has no error is an error itself: each wrong name above is one
    got = type_check(ts)
    if got is None:
        raise SystemExit("client_types: tsc not found (install TypeScript, or npm ci at the repository's root)")
    check("tsc --strict accepts correct calls and refuses wrong names", got[0], got[1])
    # ... and each is refused for its wrong name, not for something else on its line
    bare = re.sub(r"(?m)^ *// @ts-expect-error.*\n", "", USE)
    want = {(n, name) for n, line in enumerate(bare.split("\n"), 1) for name in WRONG if f'"{name}"' in line}
    got = type_check(ts, bare)
    assert got is not None
    said = {
        (int(n), name)
        for n, name in re.findall(r"use\.ts\((\d+),\d+\): error TS\d+: Argument of type '\"(\w+)\"'", got[1])
    }
    check("... a wrong permission, a relation that isn't shared and a type the policy lacks", said == want, got[1])
    texts = key_texts(ts)
    assert texts is not None
    check(
        "a key in a message is as Postgres writes it: a field quoted for ASCII's six spaces, not a no-break space",
        [shown for _, shown in texts] == [text for _, text in KEYS],
        repr([(k, shown, text) for (k, text), (_, shown) in zip(KEYS, texts, strict=True) if shown != text]),
    )
    check(
        "a key sent of one value given as an array is that value, a NULL field nothing",
        [sent for (k, _), (sent, _) in zip(KEYS, texts, strict=True) if len(k) == 1 or None in k] == ['("1",)', "7"],
        repr(texts),
    )
    print("client_types: all passed" if not fails else f"client_types: {fails} failed")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()

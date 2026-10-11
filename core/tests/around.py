#!/usr/bin/env python3
"""around: random policies (tests/genpolicy.py), with what is around the policy drawn at random too.

    python3 tests/around.py --db authz_around --policies 10 --steps 6 --seed 1

difftest and genpolicy compare two evaluations of one policy on data they made, always the same way: plain
tables, the owner's session switched to the app role, a database nobody else was given anything in. Most of the
holes the bug hunt found were not in the policy's logic but around it. So each seed here takes genpolicy's
policy for that seed and draws a world for it:

  the catalog   each object table is plain, partitioned by its key (hash or range: a key that changes puts the
                row in another partition), or has a table that inherits from it, where half its rows are stored;
                the owner's default privileges give new tables, functions and schemas to the app role, to PUBLIC
                or to a role the policy doesn't name; conditions name the app's table and function without their
                schema, which the database's search path supplies; a schema on that path that others may create in
  the session   who connects: the owner switched to the app role (as the other suites do), a login role that is
                a member of the app role, or one that has to SET ROLE to it; the last two sign each user in with
                authz.act_as(). Each sets the user's request context (authz_ctx.*), which caveats read. Settings of the app's transaction that must change no answer: planner switches,
                read-only, how dates and identifiers are written, a search path that starts with a schema of
                decoys (a table, a function and an operator named as the policy's, a now() of its own)
  later         halfway, something changes behind the policy's back: a grant on rowstile's own objects,
                row-level security turned off, a table made under a governed one, CREATE on a schema of the path

and checks, after each random change to the data:

  - difftest's checks (lists, can, the rows each rule allows, explain, who, verify), the app role's answers
    asked in the world's session
  - real writes as the app role, each undone: an update that changes nothing, an update of a column with a rule,
    a delete, calls of authz.share() to three users, on every row and for every user, against what the reference
    evaluator says of the rules and of who may share, and what the relation's `shared if` says of the share; and
    the tables under a governed one, read and written directly
  - no share is left on a row that is gone or whose key changed
  - a role the policy doesn't name gets no row of a governed table, whatever it was granted there, and a
    member of the app role that didn't sign in gets an error (28000) or nothing, never a row
  - the privileges on authz, authz_gen and authz_int are the ones a database with no world around it has
  - what changed behind the policy's back: authz.lint() reports it, and `rowstile apply` puts it right (or
    refuses, AZ612, for the schema others may create in) and then answers `unchanged`

A failing seed is printed with its world and its policy; --only SEED runs it again. Then the world is made
plainer, one thing at a time, while it still fails.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import os
import random
import re
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))
import genpolicy  # noqa: E402
from authzlib import evaluate  # noqa: E402
from authzlib.parse import Rule  # noqa: E402
from authzlib.sqlutil import qt  # noqa: E402
from difftest import DB, Checker, Snapshot, idsql, lit  # noqa: E402
from genpolicy import SCHEMA, Refused, Slow, Spec  # noqa: E402

MEMBER = "authz_around_member"  # logs in, a member of app_user
SETROLE = "authz_around_setrole"  # logs in, a member that doesn't inherit: it has to SET ROLE app_user
OUTSIDER = "authz_around_outsider"  # logs in, nothing to do with the policy
SCRATCH = "around_scratch"  # the decoys' schema: never on the path the policy is applied with
OPEN = "around_open"  # a schema on that path, which someone else may create in
TOP = 1000000  # range partitions end here: ids never get that far, a partition made later starts here

LAYOUTS = ["plain", "plain", "hash", "range", "inherits", "inherits"]
DEFAULTS = [
    "ALTER DEFAULT PRIVILEGES GRANT ALL ON TABLES TO app_user",
    "ALTER DEFAULT PRIVILEGES GRANT SELECT ON TABLES TO PUBLIC",
    f"ALTER DEFAULT PRIVILEGES GRANT ALL ON TABLES TO {OUTSIDER}",
    f"ALTER DEFAULT PRIVILEGES GRANT EXECUTE ON FUNCTIONS TO {OUTSIDER}",
    "ALTER DEFAULT PRIVILEGES GRANT ALL ON SCHEMAS TO app_user",
    "ALTER DEFAULT PRIVILEGES GRANT USAGE ON SCHEMAS TO PUBLIC",
    "ALTER DEFAULT PRIVILEGES GRANT ALL ON SEQUENCES TO PUBLIC",
]
# settings of the app's transaction: none may change an answer
SETTINGS = [
    ("enable_hashjoin", "off"),
    ("enable_mergejoin", "off"),
    ("enable_nestloop", "off"),
    ("enable_seqscan", "off"),
    ("enable_indexscan", "off"),
    ("enable_bitmapscan", "off"),
    ("enable_hashagg", "off"),
    ("enable_material", "off"),
    ("enable_memoize", "off"),
    ("enable_partition_pruning", "off"),
    ("enable_partitionwise_join", "on"),
    ("from_collapse_limit", "1"),
    ("join_collapse_limit", "1"),
    ("plan_cache_mode", "force_generic_plan"),
    ("plan_cache_mode", "force_custom_plan"),
    ("work_mem", "64kB"),
    ("DateStyle", "German, DMY"),
    ("IntervalStyle", "sql_standard"),
    ("TimeZone", "Pacific/Kiritimati"),
    ("extra_float_digits", "0"),
    ("bytea_output", "escape"),
    ("quote_all_identifiers", "on"),
    ("transform_null_equals", "on"),
    ("standard_conforming_strings", "off"),
    ("default_transaction_isolation", "repeatable read"),
]
# grants made behind the policy's back, on what is rowstile's own
GRANTS = [
    "GRANT SELECT ON ALL TABLES IN SCHEMA authz_int TO app_user",
    f"GRANT USAGE ON SCHEMA authz_int TO {OUTSIDER}",
    "GRANT ALL ON authz.shares TO PUBLIC",
    f"GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA authz TO {OUTSIDER}",
    "GRANT UPDATE ON authz.settings TO app_user",
    "GRANT CREATE ON SCHEMA authz_gen TO app_user",
]
DRIFTS = ["grant", "rls off", "child", "creator"]


@dataclass
class World:
    """What is around one seed's policy."""

    seed: int
    layout: dict[str, str] = field(default_factory=dict)  # object type -> plain | hash | range | inherits
    defaults: list[str] = field(default_factory=list)  # the owner's default privileges, before applying
    unqualified: bool = False  # conditions name gp's table and function without the schema
    open_to: str = ""  # who may create in a schema of the path when the policy is first applied ('': nobody)
    session: str = "owner"  # owner | member | set role
    settings: list[tuple[str, str]] = field(default_factory=list)
    read_only: bool = False
    decoys: bool = False  # the app's transaction searches the decoys' schema first
    drift: list[str] = field(default_factory=list)  # what changes behind the policy's back, halfway

    def describe(self) -> str:
        parts = [f"{t} {how}" for t, how in self.layout.items() if how != "plain"]
        parts += self.defaults
        parts += ["conditions without the schema"] if self.unqualified else []
        parts += [f"{self.open_to} may create in a schema of the path"] if self.open_to else []
        parts += [f"session: {self.session}"]
        parts += [f"{k} = {v}" for k, v in self.settings]
        parts += ["read-only reads"] if self.read_only else []
        parts += ["decoys first on the search path"] if self.decoys else []
        parts += [f"later: {d}" for d in self.drift]
        return "; ".join(parts)


def draw(seed: int, spec: Spec) -> World:
    r = random.Random(f"around/{seed}")
    w = World(seed)
    w.layout = {o.name: r.choice(LAYOUTS) for o in spec.objs}
    w.defaults = r.sample(DEFAULTS, r.choice([0, 0, 1, 2, 3]))
    w.unqualified = r.random() < 0.4
    w.open_to = r.choice(["", "", "", "app_user", "PUBLIC", OUTSIDER])
    w.session = r.choice(["owner", "member", "member", "set role"])
    w.settings = r.sample(SETTINGS, r.choice([0, 1, 2, 4]))
    w.read_only = r.random() < 0.3
    w.decoys = r.random() < 0.5
    w.drift = r.sample(DRIFTS, r.choice([0, 1, 1, 2]))
    return w


def plainer(w: World) -> list[World]:
    """Each world with one thing taken away."""
    out: list[World] = []
    for t, how in w.layout.items():
        if how != "plain":
            out.append(dataclasses.replace(w, layout={**w.layout, t: "plain"}))
    for i in range(len(w.defaults)):
        out.append(dataclasses.replace(w, defaults=w.defaults[:i] + w.defaults[i + 1 :]))
    for i in range(len(w.settings)):
        out.append(dataclasses.replace(w, settings=w.settings[:i] + w.settings[i + 1 :]))
    for i in range(len(w.drift)):
        out.append(dataclasses.replace(w, drift=w.drift[:i] + w.drift[i + 1 :]))
    out += [dataclasses.replace(w, unqualified=False)] if w.unqualified else []
    out += [dataclasses.replace(w, open_to="")] if w.open_to else []
    out += [dataclasses.replace(w, session="owner")] if w.session != "owner" else []
    out += [dataclasses.replace(w, read_only=False)] if w.read_only else []
    out += [dataclasses.replace(w, decoys=False)] if w.decoys else []
    return out


def with_write_rules(spec: Spec, seed: int) -> Spec:
    """genpolicy's policy with more to write to: most tables get an update rule, a rule on a column and a delete
    rule (genpolicy gives a rule on a column to one table in ten), which the real writes below need."""
    r = random.Random(f"around/rules/{seed}")
    objs = []
    for o in spec.objs:
        rules = list(o.rules)
        heads = {h for h, _ in rules}
        perms = list(o.perms)
        if "update" not in heads and r.random() < 0.7:
            rules.append(("update", r.choice(perms)))
        if (
            not any(h.startswith("update b1") for h in heads)
            and any(h == "update" for h, _ in rules)
            and r.random() < 0.8
        ):
            rules.append(("update b1", r.choice(perms)))
        if "delete" not in heads and r.random() < 0.5:
            rules.append(("delete", r.choice(perms)))
        objs.append(dataclasses.replace(o, rules=rules))
    return dataclasses.replace(spec, objs=objs)


# ----------------------------------------------------------------------
# The database of a world
# ----------------------------------------------------------------------
def policy_text(spec: Spec, w: World) -> str:
    text = genpolicy.policy_text(spec)
    if w.unqualified:
        text = text.replace(f'{SCHEMA}."Flag"(', '"Flag"(').replace(f" from {SCHEMA}.t1 x", " from t1 x")
    return text


FOLLOWS = " ON DELETE CASCADE ON UPDATE CASCADE"


def follow(link: str, column: str, target: str) -> list[str]:
    """What a foreign key with ON DELETE CASCADE ON UPDATE CASCADE does, for a table with one that inherits from
    it: a foreign key to the table doesn't see the rows stored in the other, so triggers on both do its work."""
    fn = f"{link}_{column}_follow"
    return [
        f"CREATE FUNCTION {fn}() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $f$ BEGIN\n"
        f"  IF TG_OP = 'DELETE' THEN DELETE FROM {link} WHERE {column} = OLD.id; RETURN OLD; END IF;\n"
        f"  UPDATE {link} SET {column} = NEW.id WHERE {column} = OLD.id; RETURN NEW;\nEND $f$;",
        *[
            f"CREATE TRIGGER {link.split('.')[1]}_{column}_{op} AFTER {event} ON {tbl} FOR EACH ROW "
            f"EXECUTE FUNCTION {fn}();"
            for tbl in (target, f"{target}_old")
            for op, event in (("del", "DELETE"), ("upd", "UPDATE OF id"))
        ],
    ]


def schema_text(spec: Spec, w: World) -> str:
    out: list[str] = []
    for line in genpolicy.schema_text(spec).splitlines():
        m = re.match(rf"CREATE TABLE {SCHEMA}\.(t\d+_\w+) \((.*)\);$", line)
        if m:  # a link table: its foreign keys to a table with one that inherits become triggers
            link, follows = f"{SCHEMA}.{m.group(1)}", []
            for column, target in re.findall(rf"(\w+) bigint REFERENCES ({SCHEMA}\.t\d+){FOLLOWS}", line):
                if w.layout.get(target.split(".")[1]) == "inherits":
                    line = line.replace(f"{column} bigint REFERENCES {target}{FOLLOWS}", f"{column} bigint")
                    follows += follow(link, column, target)
            out += [line, *follows]
            continue
        m = re.match(rf"CREATE TABLE {SCHEMA}\.(t\d+) \((.*)\);$", line)
        how = w.layout.get(m.group(1), "plain") if m else "plain"
        if not m or how == "plain":
            out.append(line)
            continue
        tbl = f"{SCHEMA}.{m.group(1)}"
        if how == "hash":
            out.append(f"CREATE TABLE {tbl} ({m.group(2)}) PARTITION BY HASH (id);")
            out += [
                f"CREATE TABLE {tbl}_h{n} PARTITION OF {tbl} FOR VALUES WITH (MODULUS 2, REMAINDER {n});"
                for n in (0, 1)
            ]
        elif how == "range":
            out.append(f"CREATE TABLE {tbl} ({m.group(2)}) PARTITION BY RANGE (id);")
            out.append(f"CREATE TABLE {tbl}_low PARTITION OF {tbl} FOR VALUES FROM (MINVALUE) TO (5);")
            out.append(f"CREATE TABLE {tbl}_mid PARTITION OF {tbl} FOR VALUES FROM (5) TO ({TOP});")
        else:
            out.append(line)
            out.append(f"CREATE TABLE {tbl}_old () INHERITS ({tbl});")
    # the decoys: what a transaction that searches this schema first would find under the policy's own names
    out += [
        f"CREATE SCHEMA {SCRATCH};",
        f"CREATE TABLE {SCRATCH}.t1 (id bigint, b2 boolean);",
        f"INSERT INTO {SCRATCH}.t1 SELECT i, true FROM generate_series(1, 400) i;",
        f"CREATE TABLE {SCRATCH}.users (id bigint, active boolean);",
        f"INSERT INTO {SCRATCH}.users SELECT i, true FROM generate_series(1, 20) i;",
        f"CREATE FUNCTION {SCRATCH}.\"Flag\"(p bigint) RETURNS boolean LANGUAGE sql IMMUTABLE AS 'SELECT true';",
        f'CREATE OPERATOR {SCRATCH}.=!= (FUNCTION = {SCRATCH}."Flag", RIGHTARG = bigint);',
        f"CREATE FUNCTION {SCRATCH}.now() RETURNS timestamptz LANGUAGE sql IMMUTABLE AS "
        "'SELECT ''1970-01-01''::timestamptz';",
        f"GRANT USAGE ON SCHEMA {SCRATCH} TO PUBLIC;",
        f"GRANT SELECT ON ALL TABLES IN SCHEMA {SCRATCH} TO PUBLIC;",
        f"CREATE SCHEMA {OPEN};",
        # the role the policy doesn't name is given the app's tables, as the app role is
        f"GRANT USAGE ON SCHEMA {SCHEMA} TO {OUTSIDER};",
        f"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA {SCHEMA} TO {OUTSIDER};",
    ]
    return "\n".join(out) + "\n"


def path_sql(db: DB, w: World, open_too: bool) -> str:
    """The database's search path: the one the policy is applied with, and the checks' sessions start with."""
    path = ([SCHEMA] if w.unqualified else []) + ([OPEN] if open_too else []) + ["public"]
    return f'ALTER DATABASE "{db.name}" SET search_path = {", ".join(path)};'


def initial(gen: genpolicy.GenPolicyGen, w: World) -> str:
    """genpolicy's first rows; for a table with one that inherits from it, the rows with an even id are stored
    there (before the policy is applied: written there directly later, they would skip the table's triggers)."""
    out = []
    for line in gen.initial().splitlines():
        m = re.match(rf"INSERT INTO {SCHEMA}\.(t\d+) \(id, (.*)\) VALUES \((\d+), ", line)
        if m and w.layout.get(m.group(1)) == "inherits" and int(m.group(3)) % 2 == 0:
            line = line.replace(f"INSERT INTO {SCHEMA}.{m.group(1)} (", f"INSERT INTO {SCHEMA}.{m.group(1)}_old (", 1)
        out.append(line)
    return "\n".join(out)


def roles(db: DB) -> None:
    db.run(
        "DO $$ BEGIN\n"
        "  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'app_user') THEN CREATE ROLE app_user; END IF;\n"
        f"  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '{MEMBER}') THEN\n"
        f"    CREATE ROLE {MEMBER} LOGIN IN ROLE app_user; END IF;\n"
        f"  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '{SETROLE}') THEN\n"
        f"    CREATE ROLE {SETROLE} LOGIN NOINHERIT IN ROLE app_user; END IF;\n"
        f"  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '{OUTSIDER}') THEN CREATE ROLE {OUTSIDER} LOGIN; END IF;\n"
        "END $$;"
    )


def drop_roles() -> None:
    for role in (MEMBER, SETROLE, OUTSIDER):
        subprocess.run(["psql", "-X", "-q", "-d", "postgres", "-c", f"DROP ROLE IF EXISTS {role}"], capture_output=True)


def psql(db: DB, role: str | None, sql: str, stop: bool = True) -> tuple[int, str, str]:
    """As DB.run, logged in as a role (None: the owner the suite runs as)."""
    p = subprocess.run(
        ["psql", "-X", "-q", "-At", "-F", "\t", "-v", f"ON_ERROR_STOP={int(stop)}", "-d", db.name]
        + (["-U", role] if role else []),
        input="SET client_min_messages = warning;\n" + sql,
        capture_output=True,
        text=True,
    )
    return p.returncode, p.stdout, p.stderr


def command(db: DB, *args: str) -> tuple[int, str, str]:
    """The rowstile command on the database: its exit status, its last word on the policy (applied, unchanged;
    empty when it said none), and everything it printed."""
    p = subprocess.run(
        [sys.executable, "cli/rowstile_cli.py", "--db", f"dbname={db.name}", *args], capture_output=True, text=True
    )
    lines = p.stdout.strip().splitlines()
    word = lines[-1].rsplit(": ", 1)[-1] if lines else ""
    return p.returncode, word if word in ("applied", "unchanged", "pushed") else "", (p.stdout + p.stderr).strip()


# ----------------------------------------------------------------------
# The app's transaction, as the world has it
# ----------------------------------------------------------------------
def login(w: World) -> str | None:
    return {"owner": None, "member": MEMBER, "set role": SETROLE}[w.session]


def transaction(w: World, u: str, checker: Checker, body: list[str], reads: bool) -> str:
    """One transaction of the app's, signed in as u, with the world's settings, running body."""
    kind, pid = evaluate.principal_of(u, checker.types)
    level = next((v for k, v in w.settings if k == "default_transaction_isolation"), "read committed")
    lines = [f"BEGIN ISOLATION LEVEL {level.upper()};"]
    if w.session == "owner":
        # the owner's session says who is signed in by setting it, and is believed
        lines += [
            f"SET LOCAL authz.user_id = {lit(pid)};",
            f"SET LOCAL authz.principal_type = {lit('' if kind == 'user' else kind)};",
            f"SET LOCAL ROLE {checker.role};",
        ]
    else:
        if w.session == "set role":
            lines.append(f"SET LOCAL ROLE {checker.role};")
        who = f"{lit(kind)}, {lit(pid)}" if pid else "NULL, NULL"
        lines.append(f"DO $$ BEGIN PERFORM authz.act_as({who}); END $$;")
    lines += [f"SET LOCAL {k} = {lit(v)};" for k, v in w.settings if k != "default_transaction_isolation"]
    lines += [f"SET LOCAL authz_ctx.{k} = {lit(v)};" for k, v in checker.context(u).items()]  # caveats read it
    if w.decoys:
        lines.append(f"SET LOCAL search_path = {SCRATCH}, pg_catalog, {SCHEMA}, public;")
    if w.read_only and reads:
        lines.append("SET TRANSACTION READ ONLY;")
    return "\n".join([*lines, *body, "COMMIT;"])


def answers(db: DB, w: World, script: str) -> Snapshot:
    code, out, err = psql(db, login(w), script)
    if code != 0:
        raise RuntimeError(f"the app's transaction failed ({w.describe()}):\n{err}")
    return {tuple(json.loads(k)): json.loads(v) for k, v in (line.split("\t") for line in out.splitlines() if line)}


def emit(key: list[str], sql: str) -> str:
    return f"SELECT {lit(json.dumps(key))}, ({sql});"


class AroundChecker(Checker):
    """difftest's checker; what it asks as the app role is asked again in the world's session, and those are
    the answers compared with the reference evaluator."""

    world: World
    since: int = 2**62  # a transaction id from before the last change (none yet)
    excused: set[str]  # shares the changes wrote on rows they had removed (share_problems)
    spec: Spec  # the policy (its `shared if`s)

    def snapshot(self) -> Snapshot:
        snap = super().snapshot()  # (it makes difftest_app's functions too, which the questions below call)
        script = []
        for u in self.users:
            body = []
            # the same questions as difftest's snapshot asks as the app role
            for t in self.types.values():
                for p in t.perms:
                    body.append(
                        emit(
                            [u, "list", t.name, p],
                            f"SELECT coalesce(json_agg(x ORDER BY x), '[]') FROM authz.list({lit(t.name)}, {lit(p)}) x",
                        )
                    )
                    ids = ", ".join(lit(i) for i, _ in snap[(u, "can", t.name, p)])
                    body.append(
                        emit(
                            [u, "can", t.name, p],
                            f"SELECT coalesce(json_agg(json_build_array(i, authz.can({lit(t.name)}, i, {lit(p)}))), '[]') "
                            f"FROM unnest(ARRAY[{ids}]::text[]) i",
                        )
                    )
            for table in dict.fromkeys(r.table for r in self.rules if r.command == "select"):
                t = self.ref.type_of_table(table)
                body.append(emit([u, "rls", table], f"SELECT coalesce(json_agg({idsql(t)}), '[]') FROM {table}"))
            for key, fn in self.as_app_keys():
                body.append(emit([u, *key], f"SELECT {fn}()"))
            script.append(transaction(self.world, u, self, body, reads=True))
        snap.update(answers(self.db, self.world, "\n".join(script)))
        return snap


# ----------------------------------------------------------------------
# Real writes as the app role, each undone
# ----------------------------------------------------------------------
# runs a statement and undoes it: 'rows N', or the error's SQLSTATE and message
TRY = """CREATE OR REPLACE FUNCTION pg_temp.around_try(p text) RETURNS text LANGUAGE plpgsql AS $f$
DECLARE n bigint;
BEGIN
  EXECUTE p;
  GET DIAGNOSTICS n = ROW_COUNT;
  RAISE EXCEPTION USING ERRCODE = 'AZT98', MESSAGE = n::text;
EXCEPTION
  WHEN SQLSTATE 'AZT98' THEN RETURN 'rows ' || SQLERRM;
  WHEN OTHERS THEN RETURN SQLSTATE || ' ' || SQLERRM;
END $f$;"""


# what a refused WITH CHECK says (refusals.py): the update rule doesn't hold for the row as changed
CHECK_REFUSED = " may not update this row of "
# ... and what Postgres says itself when the user could not read the row as changed (the select rule)
UNREADABLE = "new row violates row-level security policy for table"
# what authz.share() says when the relation's `shared if` doesn't hold for the share
NOT_ALLOWED = "the policy does not allow this share"


def tried(key: list[str], statement: str, ids: list[str]) -> str:
    """statement (with %s for the row's id) tried on each row: [[id, outcome], ...]"""
    return emit(
        key,
        f"SELECT coalesce(json_agg(json_build_array(i, pg_temp.around_try(format({lit(statement)}, i)))), '[]') "
        f"FROM unnest(ARRAY[{', '.join(lit(i) for i in ids)}]::text[]) i",
    )


def under(db: DB, tables: list[str]) -> list[tuple[str, str]]:
    """(table, a partition of it or a table that inherits from it), at any depth."""
    return [
        (top, child)
        for top, child in db.rows(
            "WITH RECURSIVE d(top, oid) AS ("
            f"  SELECT i.inhparent, i.inhrelid FROM pg_inherits i WHERE i.inhparent = ANY (ARRAY[{', '.join(lit(t) for t in tables)}]::regclass[])"
            "  UNION SELECT d.top, i.inhrelid FROM pg_inherits i JOIN d ON i.inhparent = d.oid) "
            "SELECT top::regclass, oid::regclass FROM d ORDER BY 1, 2"
        )
    ]


def rule_set(checker: Checker, state: evaluate.State, table: str, command: str) -> set[str]:
    """The rows a rule allows (none where the table has no such rule: row-level security then allows nothing)."""
    try:
        return checker.expected_rule(state, table, command)
    except LookupError:
        return set()


def write_problems(checker: AroundChecker, direct: bool = True) -> list[str]:
    """Each user's writes, tried as the app role in the world's session and undone, against the rules. direct:
    and the tables under a governed one, read and written directly."""
    w, db = checker.world, checker.db
    snap = checker.snapshot_data_only()
    governed = list(dict.fromkeys(r.table for r in checker.rules))
    children = under(db, governed) if direct else []
    column_rules: list[Rule] = [r for r in checker.rules if r.columns and r.command == "update"]
    first = checker.users[0]
    # the relations shared with users: (type, relation, the permission that shares it, the permissions it gives)
    shared: list[tuple[str, str, str, list[str]]] = [
        (ot, rel, by, json.loads(needs))
        for ot, rel, by, needs in db.rows(
            "SELECT object_type, relation, shared_by, array_to_json(required) FROM authz_int.shared_relations "
            "WHERE subject = 'user' ORDER BY 1, 2"
        )
    ]
    # who a share is tried with: user 1, user 2 and a user whose row is not active (the last, if none is), whom
    # genpolicy's `shared if`s tell apart (SHARED_IFS)
    active = {i for (i,) in db.rows(f"SELECT {idsql(checker.types['user'])} FROM {SCHEMA}.users WHERE active")}
    asleep = sorted(set(map(str, range(1, genpolicy.USERS + 1))) - active, key=int)
    someone = list(dict.fromkeys(["1", "2", *(asleep[:1] or [str(genpolicy.USERS)])]))
    script = []
    for u in checker.users:
        body = [TRY]
        for table in governed:
            t = checker.ref.type_of_table(table)
            ids = snap[(first, "data", "ids", t.name)]
            body.append(tried([u, "update", table], f"UPDATE {table} SET b2 = b2 WHERE id = %s", ids))
            body.append(tried([u, "delete", table], f"DELETE FROM {table} WHERE id = %s", ids))
            for n, r in enumerate(column_rules):
                if r.table == table:
                    body.append(
                        tried([u, "column", str(n)], f"UPDATE {table} SET b1 = (b1 IS NOT TRUE) WHERE id = %s", ids)
                    )
        for ot, rel, _, _ in shared:
            ids = snap[(first, "data", "ids", ot)]
            for to in someone:
                call = f"SELECT authz.share({lit(ot)}, '%s', {lit(rel)}, 'user', {lit(to)})"
                body.append(tried([u, "share", ot, rel, to], call, ids))
        for n, (_, child) in enumerate(children):
            body.append(tried([u, "under", str(n)], f"SELECT 1 FROM {child}", ["0"]))
            body.append(tried([u, "under write", str(n)], f"DELETE FROM {child}", ["0"]))
        script.append(transaction(w, u, checker, body, reads=False))
    got = answers(db, w, "\n".join(script))
    problems: list[str] = []
    for u in checker.users:
        who = f"user {u or '(nobody)'}"
        data = evaluate.Data.of({tuple(k[2:]): v for k, v in snap.items() if k[0] == u and k[1] == "data"})
        state = checker.ref.evaluate(data, u, checker.links_of(u))  # (the links the session holds count)
        for table in governed:
            t = checker.ref.type_of_table(table)
            seen = rule_set(checker, state, table, "select")
            may = {"update": rule_set(checker, state, table, "update") & seen}
            may["delete"] = rule_set(checker, state, table, "delete") & seen
            # `update after`: what must hold on the row as changed (here, as it was), else a refusal
            after = any(r.table == table and r.command == "update check" and not r.columns for r in checker.rules)
            held_after = rule_set(checker, state, table, "update check") if after else may["update"]
            for cmd in ("update", "delete"):
                for i, outcome in got[(u, cmd, table)]:
                    if cmd == "update" and i in may[cmd] and i not in held_after:
                        ok, want = outcome.startswith("42501 ") and CHECK_REFUSED in outcome, "refused (update after)"
                    else:
                        want = f"rows {int(i in may[cmd])}"
                        ok = outcome == want
                    if not ok:
                        problems.append(f"{who}: {cmd} of {table} {i} as the app role: {outcome}, expected {want}")
            for n, r in enumerate(column_rules):
                if r.table != table:
                    continue
                holds = checker.ref.eval_expr(state, t, r.expr) & checker.ref.ids(t) & checker.ref.valid(t)
                for i, outcome in got[(u, "column", str(n))]:
                    refused = outcome.startswith(f"42501 changing {', '.join(r.columns)} of {table} ")
                    if i not in may["update"]:
                        ok = outcome == "rows 0"
                        want = "rows 0 (no update of the row at all)"
                    elif i not in holds:
                        ok, want = refused, f"refused by the rule on {', '.join(r.columns)} ({r.src})"
                    else:  # the rule holds; the update's check, on the row as changed, may still refuse
                        ok = outcome == "rows 1" or (
                            outcome.startswith("42501 ") and (CHECK_REFUSED in outcome or UNREADABLE in outcome)
                        )
                        want = "rows 1, or refused for the row as changed (the update rule, or the select rule)"
                    if not ok:
                        problems.append(
                            f"{who}: update of {', '.join(r.columns)} of {table} {i} as the app role: "
                            f"{outcome}, expected {want}"
                        )
        # authz.share: for whoever is signed in and holds, on the object, the permission that shares the relation
        # and every permission the relation gives (nobody gives more than they hold), where the relation's `shared
        # if` holds for the share
        kind, pid = evaluate.principal_of(u, checker.types)
        signed_in = bool(u) and pid in snap[(u, "data", "valid", kind)]
        for ot, rel, by, needs in shared:
            cond = next(x.shared_if for x in checker.spec.obj(ot).rels if x.name == rel and x.kind == "shared")
            for to in someone:
                for i, outcome in got[(u, "share", ot, rel, to)]:
                    may_share = signed_in and all(i in state[(ot, perm)] for perm in [by, *needs])
                    allowed = not cond or genpolicy.SHARED_IFS[cond](i, "user", to, active)
                    if not may_share:
                        ok, want = outcome.startswith("42501 you cannot "), "a refusal: you cannot ..."
                    elif not allowed:
                        ok, want = outcome.startswith(f"42501 {NOT_ALLOWED}"), f"a refusal: {cond} does not hold"
                    else:
                        ok, want = outcome == "rows 1", "the share"
                    if not ok:
                        problems.append(
                            f"{who}: authz.share('{ot}', {i}, '{rel}', 'user', {to}) as the app role: {outcome}, "
                            f"expected {want} (shared by {by}; gives {', '.join(needs)})"
                        )
        for n, (top, child) in enumerate(children):
            for key, what in ((("under", str(n)), "read"), (("under write", str(n)), "written")):
                outcome = got[(u, *key)][0][1]
                if outcome != "rows 0" and not outcome.startswith("42501 "):
                    problems.append(f"{who}: {child}, under {top}, {what} directly as the app role: {outcome}")
    return problems


def share_problems(checker: AroundChecker) -> list[str]:
    """Shares on (or to) rows that are gone, or whose key changed: rowstile forgets them, so there must be none.
    (A user that is no row may be named on purpose: genpolicy's GONE.) Except the ones the last change wrote
    itself: genpolicy inserts shares directly, and in one transaction may insert one for a row it has just
    deleted or given another key. A share written since checker.since (a transaction id from before the
    change) is that, and is excused for as long as it stays on no row."""
    found = []
    for t in checker.types.values():
        if t.name == "user":
            continue
        there = f"EXISTS (SELECT 1 FROM {qt(t.table)} r WHERE {idsql(t, 'r')} = "
        share = (
            "md5(ROW(g.object_type, g.object_id, g.relation, g.subject_type, g.subject_id, g.subject_relation)::text), "
            "g.xmin::text FROM authz.shares g"
        )
        found.append(
            f"SELECT {lit(t.name)}, 'on', g.object_id, {share} "
            f"WHERE g.object_type = {lit(t.name)} AND NOT {there}g.object_id)"
        )
        found.append(
            f"SELECT {lit(t.name)}, 'to', g.subject_id, {share} "
            f"WHERE g.subject_type = {lit(t.name)} AND g.subject_id <> '*' AND NOT {there}g.subject_id)"
        )
    rows = checker.db.rows("\nUNION ALL\n".join(found) + "\nORDER BY 1, 2, 3;") if found else []
    checker.excused &= {share for _, _, _, share, _ in rows}
    checker.excused |= {share for _, _, _, share, xmin in rows if int(xmin) >= checker.since}
    left = sorted({(name, side, i) for name, side, i, share, _ in rows if share not in checker.excused})
    return [f"shares {side} {name} {i}: no such row (it is gone, or its key changed)" for name, side, i in left]


# ----------------------------------------------------------------------
# Who is not the app, and who didn't sign in
# ----------------------------------------------------------------------
def stranger_problems(checker: Checker) -> list[str]:
    """A role the policy doesn't name, given the app's tables: no row of a governed table, read or written,
    through it or through what is under it, and none of rowstile's functions."""
    db = checker.db
    governed = list(dict.fromkeys(r.table for r in checker.rules))
    tables = governed + [child for _, child in under(db, governed)]
    body = ["BEGIN;", "SET LOCAL authz.user_id = '1';", TRY]
    for n, table in enumerate(tables):
        body.append(tried(["read", str(n)], f"SELECT 1 FROM {table}", ["0"]))
        body.append(tried(["update", str(n)], f"UPDATE {table} SET b2 = b2", ["0"]))
        body.append(tried(["delete", str(n)], f"DELETE FROM {table}", ["0"]))
    body.append(tried(["act_as"], "SELECT authz.act_as('user', '1')", ["0"]))
    body.append(tried(["list"], f"SELECT authz.list({lit(next(iter(checker.types)))}, 'p1')", ["0"]))
    code, out, err = psql(db, OUTSIDER, "\n".join([*body, "COMMIT;"]))
    if code != 0:
        raise RuntimeError(f"the stranger's transaction failed:\n{err}")
    problems = []
    for line in out.splitlines():
        if not line:
            continue
        key, val = line.split("\t")
        what, *n = json.loads(key)
        outcome = json.loads(val)[0][1]
        if what in ("act_as", "list"):
            if not outcome.startswith("42501 "):
                problems.append(f"a role the policy doesn't name calls authz.{what}: {outcome}")
        elif outcome != "rows 0" and not outcome.startswith("42501 "):
            problems.append(f"a role the policy doesn't name, {what} of {tables[int(n[0])]}: {outcome}")
    return problems


def unsigned_problems(checker: Checker) -> list[str]:
    """A member of the app role that doesn't sign in, sets the user itself, or brings a signature from another
    transaction: never a row. An error (28000) wherever Postgres comes to ask who is signed in; no row and no
    error where it doesn't have to (a rule that is false whoever asks, `nobody and {b1}`, is folded to false
    when the read is planned; so is one whose own conditions no row passes)."""
    db = checker.db
    problems = []
    for table in dict.fromkeys(r.table for r in checker.rules if r.command == "select"):
        read = f"SELECT pg_temp.around_try({lit(f'SELECT 1 FROM {table}')})"
        cases = {
            "nobody signed in": f"BEGIN;\n{read};\nCOMMIT;",
            "authz.user_id set directly": f"BEGIN;\nSET LOCAL authz.user_id = '1';\n{read};\nCOMMIT;",
            "a signature from the transaction before": (
                "BEGIN;\nDO $$ BEGIN PERFORM authz.act_as('user', '1'); END $$;\n"
                "SELECT current_setting('authz.session') AS sig \\gset\nCOMMIT;\n"
                "BEGIN;\nSET LOCAL authz.user_id = '2';\nSELECT set_config('authz.session', :'sig', true) \\gset x_\n"
                f"{read};\nCOMMIT;"
            ),
        }
        for role, first in ((MEMBER, ""), (SETROLE, f"SET ROLE {checker.role};\n")):
            for what, sql in cases.items():
                code, out, err = psql(db, role, first + TRY + "\n" + sql)
                last = out.strip().splitlines()[-1] if out.strip() else err.strip()
                if code != 0 or not (last.startswith("28000 ") or last == "rows 0"):
                    problems.append(f"{role}, {what}, reads {table}: {last}")
    return problems


# ----------------------------------------------------------------------
# Privileges, and what changes behind the policy's back
# ----------------------------------------------------------------------
PRIVILEGES = """SELECT x FROM (
  SELECT 'schema ' || n.nspname || ': ' || CASE a.grantee WHEN 0 THEN 'PUBLIC' ELSE a.grantee::regrole::text END
         || ' ' || a.privilege_type AS x
  FROM pg_namespace n, aclexplode(coalesce(n.nspacl, acldefault('n', n.nspowner))) a
  WHERE n.nspname IN ('authz', 'authz_gen', 'authz_int') AND a.grantee <> n.nspowner
  UNION ALL
  SELECT 'relation ' || c.oid::regclass || ': ' || CASE a.grantee WHEN 0 THEN 'PUBLIC' ELSE a.grantee::regrole::text END
         || ' ' || a.privilege_type
  FROM pg_class c, aclexplode(coalesce(c.relacl, acldefault(CASE c.relkind WHEN 'S' THEN 's'::"char" ELSE 'r' END, c.relowner))) a
  WHERE c.relnamespace IN ('authz'::regnamespace, 'authz_gen'::regnamespace, 'authz_int'::regnamespace)
    AND c.relkind IN ('r', 'v', 'S', 'p', 'm') AND a.grantee <> c.relowner
  UNION ALL
  SELECT 'column ' || c.oid::regclass || '.' || t.attname || ': ' || CASE a.grantee WHEN 0 THEN 'PUBLIC' ELSE a.grantee::regrole::text END
         || ' ' || a.privilege_type
  FROM pg_class c JOIN pg_attribute t ON t.attrelid = c.oid AND t.attacl IS NOT NULL, aclexplode(t.attacl) a
  WHERE c.relnamespace IN ('authz'::regnamespace, 'authz_gen'::regnamespace, 'authz_int'::regnamespace)
    AND a.grantee <> c.relowner
  UNION ALL
  SELECT 'function ' || p.oid::regprocedure || ': ' || CASE a.grantee WHEN 0 THEN 'PUBLIC' ELSE a.grantee::regrole::text END
         || ' ' || a.privilege_type
  FROM pg_proc p, aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a
  WHERE p.pronamespace IN ('authz'::regnamespace, 'authz_gen'::regnamespace, 'authz_int'::regnamespace)
    AND a.grantee <> p.proowner
) s ORDER BY 1"""


def privileges(db: DB) -> list[str]:
    """Every privilege anyone but the owner holds on rowstile's three schemas and what is in them."""
    return [row[0] for row in db.rows(PRIVILEGES)]


def privilege_problems(db: DB, plain: list[str], when: str) -> list[str]:
    have = privileges(db)
    extra, missing = sorted(set(have) - set(plain)), sorted(set(plain) - set(have))
    return [f"{when}, a privilege the policy doesn't give: {x}" for x in extra[:6]] + [
        f"{when}, a privilege the policy gives is missing: {x}" for x in missing[:6]
    ]


def lint_errors(db: DB) -> list[str]:
    return [
        f"{obj}: {problem}"
        for obj, problem in db.rows("SELECT object, problem FROM authz.lint() WHERE severity = 'error'")
    ]


def drift(checker: AroundChecker, rnd: random.Random, plain: list[str], policy_path: str) -> list[str]:
    """Something changes behind the policy's back: lint has to say so, and `rowstile apply` to put it right
    (or to refuse, where it can't: someone may create in a schema of the search path)."""
    w, db = checker.world, checker.db
    governed = list(dict.fromkeys(r.table for r in checker.rules))
    problems: list[str] = []
    for kind in w.drift:
        before = lint_errors(db)
        table = rnd.choice(governed)
        undo = ""
        reported = partition = True
        if kind == "grant":
            what = rnd.choice(GRANTS)
        elif kind == "rls off":
            what = f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY"
        elif kind == "child":
            how = w.layout.get(table.split(".")[1], "plain")
            if how == "hash":
                continue  # (a hash-partitioned table takes no more partitions)
            partition = how == "range"
            # a partition made later is often given nothing of its own: rows reach it through its table. Then
            # nothing is open, and lint has nothing to report (apply still turns row-level security on there)
            reported = not partition or rnd.random() < 0.5
            child = f"{table}_{'top' if partition else 'newer'}"
            if partition:
                what = f"CREATE TABLE {child} PARTITION OF {table} FOR VALUES FROM ({TOP}) TO ({TOP * 2})"
            else:
                what = f"CREATE TABLE {child} () INHERITS ({table})"
            if reported:
                what += f"; GRANT SELECT, INSERT, UPDATE, DELETE ON {child} TO app_user"
            if partition:  # ... and it takes a row: the one with the smallest key, which that changes
                what += f"; UPDATE {table} SET id = id + {TOP} WHERE id = (SELECT min(id) FROM {table})"
        else:  # creator: a schema the policy's functions search, and someone else may create in
            schema = SCHEMA if w.unqualified else "public"
            who = rnd.choice(["app_user", OUTSIDER, "PUBLIC"])
            what, undo = f"GRANT CREATE ON SCHEMA {schema} TO {who}", f"REVOKE CREATE ON SCHEMA {schema} FROM {who}"
        db.run(what + ";")
        if kind == "child" and partition:
            # Postgres gave the partition its table's row triggers, and its rows are read and written through
            # the table: the rules hold on them before the policy is applied again (read directly, it is open
            # until then where the app role was given it)
            held = checker.check() + write_problems(checker, direct=False) + share_problems(checker)
            problems += [f"after `{what}`, before the policy is applied again: {x}" for x in held[:8]]
        after = lint_errors(db)
        if reported and len(after) <= len(before):
            problems.append(f"after `{what}`, authz.lint() reports no new error")
        if kind == "creator":
            # nothing an apply can put right: applying again has to refuse, and lint to say so until it is undone
            code, word, out = command(db, "reapply")
            if code == 0 or "AZ612" not in out:
                problems.append(f"after `{what}`, rowstile reapply did not refuse (AZ612): {out[-300:]}")
            db.run(undo + ";")
        code, word, out = command(db, "apply", policy_path)
        if code != 0 or not word:
            problems.append(f"after `{what}`, rowstile apply failed: {out[-400:]}")
            continue
        if kind != "creator" and word != "applied":
            problems.append(f"after `{what}`, rowstile apply answers '{word}': it left it as it was")
        # (what the app role was given on the app's own table is the owner's to take back: the owner's default
        # privileges can give it TRUNCATE on a table made now, which lint goes on reporting, rightly)
        left = [e for e in lint_errors(db) if e not in before and "may TRUNCATE it" not in e]
        problems += [f"after `{what}` and rowstile apply, authz.lint() still reports: {e[:200]}" for e in left[:3]]
        problems += privilege_problems(db, plain, f"after `{what}` and rowstile apply")
        code, word, out = command(db, "apply", policy_path)
        if word != "unchanged":
            problems.append(f"after `{what}`, the second rowstile apply answers '{word}', not unchanged")
    open_tables = [
        child
        for _, child in under(db, governed)
        if db.rows(f"SELECT relrowsecurity FROM pg_class WHERE oid = {lit(child)}::regclass")[0][0] != "t"
    ]
    problems += [f"{child}, under a governed table, has row-level security off" for child in open_tables]
    return problems


# ----------------------------------------------------------------------
# One seed
# ----------------------------------------------------------------------
def run(spec: Spec, w: World, db: DB, control: DB, steps: int, workdir: str, seconds: float = 900) -> list[str]:
    """The problems found with this policy in this world (none: it passed). Refused and Slow as in genpolicy."""
    policy_path, schema_path = os.path.join(workdir, "around.authz"), os.path.join(workdir, "around_schema.sql")
    genpolicy.write_policy(policy_path, policy_text(spec, w), spec.include)
    with open(schema_path, "w", encoding="utf-8") as fh:
        fh.write(schema_text(spec, w))
    compiled = subprocess.run([sys.executable, "compile_policy.py", policy_path], capture_output=True, text=True)
    if compiled.returncode != 0:
        raise Refused(compiled.stderr.strip().splitlines()[-1] if compiled.stderr.strip() else "refused")
    if "view definitions to plan" in compiled.stdout:
        raise Slow("authz.lint() warns that a select rule is slow to plan")
    started = time.monotonic()
    rnd = random.Random(f"around/run/{w.seed}")
    gen = genpolicy.gen_class(spec, policy_path, schema_path)(random.Random(spec.seed))
    data = initial(gen, w)
    problems: list[str] = []
    # the world's database, and one with the same tables, rows and policy and nothing else around it
    for d, world in ((control, False), (db, True)):
        d.recreate()
        roles(d)
        d.run(schema_text(spec, w))
        d.run(path_sql(d, w, open_too=False))
        d.run(data)
        if world:
            d.run(";\n".join(w.defaults) + ";" if w.defaults else "SELECT 1;")
            if w.open_to:
                d.run(f"GRANT CREATE ON SCHEMA {OPEN} TO {w.open_to};\n" + path_sql(d, w, open_too=True))
                code, word, out = command(d, "apply", policy_path)
                if code == 0 or "AZ612" not in out:
                    problems.append(
                        f"{w.open_to} may create in a schema of the search path, and rowstile apply did not refuse (AZ612): {out[-300:]}"
                    )
                if d.rows("SELECT to_regnamespace('authz_gen') IS NOT NULL")[0][0] == "t":
                    problems.append("the refused apply left authz_gen behind")
                d.run(f"REVOKE CREATE ON SCHEMA {OPEN} FROM {w.open_to};")
        code, word, out = command(d, "apply", policy_path)
        if code != 0 or word != "applied":
            return [*problems, f"rowstile apply failed on the {'world' if world else 'plain'} database: {out[-600:]}"]
    db.run(gen.grants())
    plain = privileges(control)
    problems += privilege_problems(db, plain, "after the first apply")
    checker = AroundChecker(db, policy_path, gen)
    checker.world, checker.excused, checker.spec = w, set(), spec
    problems += stranger_problems(checker) + unsigned_problems(checker)
    if problems:
        return ["before any change:", *problems[:12]]
    for step in range(steps + 1):
        if time.monotonic() - started > seconds:
            raise Slow(f"over {seconds:.0f} s at step {step} of {steps}")
        problems = checker.check() + write_problems(checker) + share_problems(checker)
        if step == steps // 2 and not problems:
            problems = drift(checker, rnd, plain, policy_path)
            problems += [] if problems else checker.check() + stranger_problems(checker)
        if problems:
            return [f"step {step}:", *problems[:12]]
        if step == steps:
            break
        ids = {
            t.name: [x[0] for x in db.rows(f"SELECT {idsql(t)} FROM {qt(t.table)} ORDER BY 1")]
            for t in checker.types.values()
        }
        sql = gen.change(ids)
        checker.since = int(db.rows("SELECT txid_current()")[0][0])
        code, _, err = db.run(sql, check=False)
        if code != 0 and not any(e in err for e in gen.expected_errors):
            return [f"step {step + 1}: unexpected error", f"  {sql}", f"  {err.strip()}"]
    return []


# ----------------------------------------------------------------------
def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--db", default="authz_around")
    ap.add_argument("--policies", type=int, default=10)
    ap.add_argument("--steps", type=int, default=6)
    ap.add_argument("--seed", type=int, default=1, help="the first seed (each policy and its world: the next one)")
    ap.add_argument("--only", type=int, help="run this one seed, and print its world and its policy")
    ap.add_argument("--no-shrink", action="store_true")
    ap.add_argument("--seconds", type=float, default=900, help="a seed that takes longer is given up (and said)")
    args = ap.parse_args()
    os.chdir(os.path.dirname(HERE))
    db, control = DB(args.db), DB(args.db + "_plain")
    seeds = [args.only] if args.only is not None else range(args.seed, args.seed + args.policies)
    refused = failed = passed = 0
    slow: list[int] = []
    with tempfile.TemporaryDirectory() as workdir:

        def fails(s: Spec, w: World) -> bool:
            try:
                return bool(run(s, w, db, control, args.steps, workdir, args.seconds))
            except (Refused, Slow):
                return False

        for seed in seeds:
            # plain names: the worlds rebuild genpolicy's tables from its schema's text, as it writes them plainly
            spec = with_write_rules(genpolicy.make(seed, respell=False, keytype="bigint", composite=False), seed)
            w = draw(seed, spec)
            if args.only is not None:
                print(f"world: {w.describe()}\n\n{policy_text(spec, w)}")
            try:
                problems = run(spec, w, db, control, args.steps, workdir, args.seconds)
            except Slow as e:
                slow.append(seed)
                print(f"seed {seed}: not checked ({e})", flush=True)
                continue
            except Refused as e:
                refused += 1
                if args.only is not None:
                    print(f"refused: {e}")
                continue
            if not problems:
                passed += 1
                continue
            failed += 1
            print(f"seed {seed}: {w.describe()}")
            for p in problems:
                print("   ", p)
            if not args.no_shrink:
                changed = True
                while changed:
                    changed = False
                    for smaller in plainer(w):
                        if fails(spec, smaller):
                            w, changed = smaller, True
                            break
                spec = genpolicy.shrink(spec, lambda s, w=w: fails(s, w))
                print(f"  the plainest world and the smallest policy found that still fail (seed {seed}):")
                print(f"    world: {w.describe()}")
                print("    " + policy_text(spec, w).replace("\n", "\n    ").rstrip())
                for p in run(spec, w, db, control, args.steps, workdir):
                    print("   ", p)
            sys.stdout.flush()
    for d in (db, control):
        subprocess.run(["dropdb", "--if-exists", d.name], capture_output=True)
    drop_roles()
    print(
        f"around seeds {seeds[0]}..{seeds[-1]}: {passed} passed, {failed} failed, {refused} refused by the compiler"
        + (f", {len(slow)} too slow to check (seeds {', '.join(map(str, slow))})" if slow else "")
    )
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()

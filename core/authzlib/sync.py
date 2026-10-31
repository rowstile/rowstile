"""The sync index (a preview): who may read each row of a synced table, as keys, kept in authz_sync for sync engines.

`sync role sync_engine` names the engine's Postgres role, `sync app.files : view` a table and the permission its
readers hold (the table's select rule when no permission is named). Applying keeps two kinds of tables in the
persistent schema authz_sync, which the engines replicate as they do the app's tables:

- `<type>__readers(<key columns>, key)`: for each row, the keys that may read it;
- `keys(principal_type, principal_id, key)`: for each principal, the keys it holds.

A key is a principal (`user:42`), every signed-in principal of a type (`user:*`), `anyone`, or a group: the
holders of a relation or permission of a group's object (`team#member:10`). `groups(grp, key)` says which keys
make up each group key, and a principal holds the closure. Readers are worked out from the permission's expression
(Deriver): relations give their subjects' keys, inheritance reads the closure tables, `rel.perm` to another type's
object copies that object's readers in (or gives its group key), a condition on the row filters, `or` is a union,
and `and` or `not` between parts that depend on who asks expands them to principal keys (`expanded` keeps what
each such row was worked out from, to work it out again when someone gains or loses one of those keys).

Every trigger that may change access calls authz_int.changed(); with sync it also notes the objects in
authz_int.sync_dirty, and a deferred constraint trigger works their readers out again at commit, with what reads
them, in the same transaction, writing the difference.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import assert_never

from .compiler import Core, Name, once, only_on
from .parse import (
    KEYWORDS,
    And,
    Arrow,
    ArrowOn,
    Cond,
    Expr,
    Link,
    Loc,
    Not,
    Or,
    Ref,
    Relation,
    Source,
    Sync,
    Type,
    fail,
)
from .parse import leaves as expr_leaves
from .sqlutil import (
    AGE,
    TIME_WORDS,
    UNSTABLE,
    ident,
    lit,
    literal_text,
    on_row,
    one_argument,
    q,
    qt,
    reads_more,
    sql_code,
    strip_literals,
    union,
)
from .trees import BATCH

DEF = "SECURITY DEFINER SET search_path = pg_catalog, pg_temp"
# what evaluates the policy's own SQL resolves names as the policy does (output.search_path_sql)
DEF_CURRENT = "SECURITY DEFINER SET search_path FROM CURRENT"
KEYWORD_SQL = frozenset(KEYWORDS.values())
# what reads the clock or chance: the index can't follow it (AZ804); the rest of UNSTABLE reads who asks (AZ805)
CLOCK = frozenset(
    {
        "now",
        "clock_timestamp",
        "statement_timestamp",
        "transaction_timestamp",
        "timeofday",
        "random",
        "random_normal",
        "gen_random_uuid",
        "uuidv4",
        "uuidv7",
        "current_timestamp",
        "current_date",
        "current_time",
        "localtime",
        "localtimestamp",
    }
)
# the tables of authz_sync that aren't a type's readers
SYNC_TABLES = ("keys", "groups", "expanded", "definitions")
LOCK_KEYS = "sync#keys"  # the lock row of groups and keys (no type is named so: a type's name holds no #)


def sync_lock(t: str) -> str:
    """The lock row of a synced type's readers: never a tree's (a commit waits for no tree lock, so no cycle)."""
    return f"sync:{t}"


def unstable(sql: str) -> tuple[str, str] | None:
    """(code, what) when a condition reads what changes without a write: the clock or chance (AZ804), or who asks
    and the session (AZ805), as check_stable_condition reads them; None when it reads neither."""
    for code, text in sql_code(sql):
        if not code and text[0] in "'$" and (m := TIME_WORDS.fullmatch(literal_text(text))):
            return "AZ804", f"'{m.group(1)}', the current time"
    code = strip_literals(sql)
    m = UNSTABLE.search(code)
    if m:
        word = (m.group(1) or m.group(2)).lower()
        bare = re.sub(r"\s+", "", word)
        return ("AZ804" if bare in CLOCK else "AZ805"), bare + ("()" if m.group(1) else "")
    if any(one_argument(code, a.end()) for a in AGE.finditer(code)):
        return "AZ804", "age() with one argument, which counts from today"
    return None


@dataclass
class Edge:
    """The objects of dst whose readers read objects of src: sql selects their ids as text, from $ids (src's ids,
    as src's key type, or text for a composite key and for $text)."""

    src: str
    dst: str
    sql: str


@dataclass
class SyncState:
    """What sync_build worked out: the functions in the order they are made, and what the commit's work needs."""

    functions: list[str] = field(default_factory=list)
    made: dict[Name, str] = field(default_factory=dict)  # pair -> its function
    making: list[Name] = field(default_factory=list)  # pairs being made: one asked for again loops (AZ807)
    edges: list[Edge] = field(default_factory=list)
    groups: dict[Name, None] = field(default_factory=dict)  # keyed pairs a derivation gave the key of
    shared: dict[tuple[str, str], None] = field(default_factory=dict)  # (type, relation) shares read
    links: dict[tuple[str, str], None] = field(default_factory=dict)  # (type, relation) with link subjects read
    trees: dict[str, None] = field(default_factory=dict)  # closure tables read
    tops: dict[str, str] = field(default_factory=dict)  # synced type -> its readers' function
    expanding: set[str] = field(default_factory=set)  # synced types whose readers may be expanded
    n: int = 0  # a counter, for the names of a query's parts

    def next(self) -> int:
        self.n += 1
        return self.n


class SyncMixin(Core):
    sync_state: SyncState | None = None

    # --- what the policy says ---------------------------------------------------------------------------
    def sync_type(self, s: Sync) -> Type:
        found = [t for t in self.types.values() if t.table == s.table]
        if len(found) != 1:
            fail(
                s.loc,
                f"sync {s.table}: no type maps to {s.table}"
                if not found
                else f"sync {s.table}: two types map to {s.table} ({', '.join(t.name for t in found)}), so whose "
                f"readers it would hold isn't said",
                "AZ801",
                span=s.table_span,
            )
        return found[0]

    def sync_select(self, table: str) -> Expr | None:
        """The table's select rule (its expression), if it has one."""
        return next((r.expr for r in self.rules if r.table == table and r.command == "select" and not r.columns), None)

    def sync_expr(self, s: Sync) -> Expr:
        """What a sync line's readers hold: the permission named, or the table's select rule."""
        t = self.sync_type(s)
        if s.perm is None:
            sel = self.sync_select(s.table)
            if sel is None:
                fail(
                    s.loc,
                    f"sync {s.table}: the table has no select rule, so name the permission its readers hold: "
                    f"sync {s.table} : view",
                    "AZ801",
                    span=s.table_span,
                )
            return sel
        if s.perm not in self.public_perms(t):
            known = ", ".join(self.public_perms(t)) or "none"
            fail(
                s.loc,
                f"sync {s.table} : {s.perm}: {t.name} has no permission {s.perm} (it has: {known})",
                "AZ801",
                span=s.perm_span,
            )
        return Ref(s.perm)

    def sync_check(self) -> None:
        """The sync lines and the sync role, as written (AZ801, AZ802, AZ803)."""
        pol = self.pol
        if pol.syncs and pol.sync_role is None:
            first = next(iter(pol.syncs.values()))
            fail(
                first.loc,
                "sync lines need the sync engine's Postgres role, which reads the index: sync role sync_engine",
                "AZ802",
            )
        if pol.sync_role is not None and not pol.syncs:
            assert pol.sync_role_loc is not None
            fail(pol.sync_role_loc, "a sync role and nothing synced: add a line such as sync app.files : view", "AZ802")
        assert pol.sync_role is not None and pol.sync_role_loc is not None  # (AZ802 otherwise, above)
        if pol.sync_role == self.role or pol.sync_role.lower() == "public":
            fail(
                pol.sync_role_loc,
                f"the sync role reads every row (it holds BYPASSRLS), so it can't be "
                f"{'the app role' if pol.sync_role == self.role else 'PUBLIC'}: give the engine a role of its own",
                "AZ803",
            )
        for s in pol.syncs.values():
            t = self.sync_type(s)
            self.sync_expr(s)
            if any(c == "key" for c, _ in t.key):
                fail(
                    s.loc,
                    f"sync {s.table}: its readers table has a column `key`, so the type's key column can't be "
                    f"called key too",
                    "AZ801",
                    span=s.table_span,
                )

    # --- which keys are groups ------------------------------------------------------------------------
    def group_types(self) -> set[str]:
        """The types named as a subject with a relation (`team#member`): their relations and permissions may be
        group keys."""
        return {
            st
            for t in self.types.values()
            for r in t.relations.values()
            for st, sr in r.subjects()
            if sr and sr != "*" and st in self.types
        }

    @staticmethod
    def is_cond(e: Expr) -> bool:
        """A condition on the row (not one of the words that stand for who asks)."""
        match e:
            case Cond(sql):
                return sql not in KEYWORD_SQL
            case Not(Cond(sql)):
                return sql not in KEYWORD_SQL
        return False

    def expands(self, e: Expr) -> bool:
        """Whether an expression joins parts that depend on who asks with `and` or `not`: the index then works out
        its readers as principals (and_rows)."""
        match e:
            case Or(items):
                return any(self.expands(x) for x in items)
            case And(items):
                who = [x for x in once(items) if not self.is_cond(x)]
                if any(isinstance(x, Not) for x in who) or len(who) >= 2:
                    return True
                return any(self.expands(x) for x in who)
            case Not(_):
                return not self.is_cond(e)
        return False

    def pair_exprs(self, t: Type, name: str) -> list[tuple[Type, Expr]]:
        """The expressions a pair's readers are worked out from, each with its type: a permission's (its base items,
        and those of the permissions it inherits with, where it recurses); none for a relation."""
        if name in t.relations:
            return []
        key = self.recursive.get((t.name, name))
        if key is None:
            return [(t, t.perms[name].expr)]
        return [
            (self.T(tn), x)
            for tn, pn in self.scc_members[key]
            for x in self.base_items(self.T(tn), self.T(tn).perms[pn])
        ]

    def pair_refs(self, t: Type, name: str) -> Iterator[Name]:
        """The pairs a pair's readers read: the relations and permissions it names, through dots and groups."""
        if name in t.relations:
            for st, sr in t.relations[name].subjects():
                if sr and sr != "*" and st in self.types:
                    yield (st, sr)
            return
        for mt, e in self.pair_exprs(t, name):
            yield from self.expr_refs(mt, e)

    def expr_refs(self, t: Type, e: Expr) -> Iterator[Name]:
        for leaf, _ in expr_leaves(e):
            match leaf:
                case Ref(name):
                    yield (t.name, name)
                case Arrow(rel, perm) | ArrowOn(rel, perm, _):
                    on = only_on(leaf)
                    for st, sr in t.relations[rel].subjects():
                        if sr is None and st in self.types and (on is None or st in on):
                            yield (st, perm)

    def monotone(self, t: Type, name: str) -> bool:
        """Whether no part of what a pair's readers read joins who-dependent parts with `and` or `not`: its readers
        are then keys alone, and a group's may be a key."""
        seen: set[Name] = set()
        todo: list[Name] = [(t.name, name)]
        while todo:
            p = todo.pop()
            if p in seen:
                continue
            seen.add(p)
            pt = self.T(p[0])
            if any(self.expands(e) for _, e in self.pair_exprs(pt, p[1])):
                return False
            todo += self.pair_refs(pt, p[1])
        return True

    def keyed(self, st: str, name: str) -> bool:
        """Whether holding st.name on an object is a group key (team#member:10), rather than its readers copied in."""
        return st in self.group_types() and self.monotone(self.T(st), name)

    # --- what the index may evaluate ---------------------------------------------------------------------
    def sync_cond_ok(self, sql: str, loc: Loc, what: str) -> None:
        """A condition the index evaluates must give one answer for everyone until a write changes it: refused when
        it reads the clock or chance (AZ804), who asks or the session (AZ805), or more than its row (AZ806)."""
        bad = unstable(sql)
        if bad:
            code, on = bad
            if code == "AZ804":
                fail(
                    loc,
                    f"{{{sql}}} ({what}) reads {on}, which changes without a write, so the sync index can't follow "
                    f"it. Leave the clock out of what a synced permission reads: a share that ends is followed "
                    f"(authz.sync_tick())",
                    "AZ804",
                )
            fail(
                loc,
                f"{{{sql}}} ({what}) reads {on}: who asks, or the session. The sync index says who may read a row "
                f"for every principal at once, so it can't hold a condition on who asks. Say it with a relation "
                f"(owner : user = owner_id)",
                "AZ805",
            )
        if reads_more(sql):
            fail(
                loc,
                f"{{{sql}}} ({what}) reads more than its row (a subquery, or a function of the app's): no write to "
                f"what it reads tells the sync index, so it can't follow it. Say it with a relation, or with a "
                f"condition on the row's own columns",
                "AZ806",
            )

    # --- the build ------------------------------------------------------------------------------------
    def sync_build(self) -> SyncState:
        """The functions of the index, worked out from each synced table's expression (once)."""
        if self.sync_state is not None:
            return self.sync_state
        st = SyncState()
        self.sync_state = st
        d = Deriver(self, st)
        for s in self.pol.syncs.values():
            t = self.sync_type(s)
            st.tops[t.name] = d.top(t, self.sync_expr(s), s)
        # the groups the readers name, and those they name in turn
        done: set[Name] = set()
        while True:
            todo = [g for g in st.groups if g not in done]
            if not todo:
                break
            for g in todo:
                done.add(g)
                d.fn(self.T(g[0]), g[1], self.T(g[0]).loc)
        for s in self.pol.syncs.values():
            t = self.sync_type(s)
            e = self.sync_expr(s)
            if self.expands(e) or not all(self.monotone(self.T(p[0]), p[1]) for p in self.expr_refs(t, e)):
                st.expanding.add(t.name)
        for t in self.types.values():
            if t.principal and t.where:
                self.sync_cond_ok(t.where, t.loc, f"the where of {t.name}, which says who holds keys")
        return st

    # --- the types the commit's work reads -----------------------------------------------------------
    def sync_principals(self) -> list[Type]:
        return [t for t in self.types.values() if t.principal]

    def sync_group_types(self) -> list[str]:
        st = self.sync_build()
        return sorted({g[0] for g in st.groups})

    def sync_relevant(self) -> list[str]:
        """The types whose changes may change the index: synced, groups, principals, and what they read."""
        st = self.sync_build()
        out = set(st.tops) | set(self.sync_group_types()) | {t.name for t in self.sync_principals()}
        out |= {e.src for e in st.edges}
        return sorted(out)

    def sync_reach(self, start: str) -> set[str]:
        """The types whose readers read start's objects, directly or through others (start among them)."""
        st = self.sync_build()
        seen, todo = {start}, [start]
        while todo:
            x = todo.pop()
            for e in st.edges:
                if e.src == x and e.dst not in seen:
                    seen.add(e.dst)
                    todo.append(e.dst)
        return seen

    def sync_locks(self, start: str) -> list[str]:
        """The lock rows a change to start's objects takes, in one order: each synced type it reaches, and the keys'
        (with every synced type that expands, which a change of keys reaches) when it reaches groups, principals or
        an expanding type."""
        st = self.sync_build()
        reach = self.sync_reach(start)
        keys_types = set(self.sync_group_types()) | {t.name for t in self.sync_principals()} | st.expanding
        out = {sync_lock(t) for t in reach if t in st.tops}
        if reach & keys_types:
            out.add(LOCK_KEYS)
            for t in st.expanding:
                out |= {sync_lock(x) for x in self.sync_reach(t) if x in st.tops}
        return sorted(out)

    def sync_hash(self) -> str:
        """What the index is worked out by (line numbers aside): its functions, the keys' (a principal type's where),
        and the closure tables they read: a kept one by its definition's hash, one always rebuilt by its SQL."""
        st = self.sync_build()
        trees = dict(zip(self.tree_names, self.tree_sql, strict=True))
        text = "\n".join(
            [
                *st.functions,
                *(self.keys_fn_sql(t) for t in self.sync_principals()),
                *(f"{n} {self.tree_keep[n][0] if n in self.tree_keep else trees[n]}" for n in sorted(st.trees)),
            ]
        )
        return hashlib.sha256(re.sub(r"\bline \d+", "line", text).encode()).hexdigest()[:32]

    # --- the SQL applying makes --------------------------------------------------------------------------
    def readers_table(self, t: Type) -> str:
        return f"authz_sync.{q(t.name + '__readers')}"

    def sync_base_sql(self) -> str:
        """authz_sync and its tables, kept across applies (CREATE ... IF NOT EXISTS): a table this policy no longer
        keeps goes, and so does a readers table whose key columns changed."""
        st = self.sync_build()
        synced = [self.T(n) for n in st.tops]
        want = [
            ("keys", ["principal_type", "principal_id", "key"], ["text"] * 3),
            ("groups", ["grp", "key"], ["text"] * 2),
            ("expanded", ["object_type", "object_id", "key"], ["text"] * 3),
            ("definitions", ["name", "hash"], ["text"] * 2),
        ] + [
            (t.name + "__readers", [c for c, _ in t.key] + ["key"], [ty for _, ty in t.key] + ["text"]) for t in synced
        ]
        rows = ",\n             ".join(
            f"({lit(ident(n))}, ARRAY[{', '.join(lit(c) for c in cs)}]::name[], "
            f"ARRAY[{', '.join(lit(ty) for ty in tys)}]::regtype[])"
            for n, cs, tys in want
        )
        tables = []
        for t in synced:
            name = self.readers_table(t)
            pk = ", ".join(q(c) for c, _ in t.key)
            tables.append(
                f"CREATE TABLE IF NOT EXISTS {name} ("
                + ", ".join(f"{q(c)} {ty} NOT NULL" for c, ty in t.key)
                + f", key text NOT NULL, PRIMARY KEY ({pk}, key));\n"
                f"CREATE INDEX IF NOT EXISTS {q(t.name + '__readers_key')} ON {name} (key);\n"
                f"ALTER TABLE {name} REPLICA IDENTITY FULL;"
            )
        return f"""-- The sync index (a preview): who may read each row of the synced tables, as keys, and the keys each principal
-- holds. Kept across applies: the sync engines keep their shapes on these tables
CREATE SCHEMA IF NOT EXISTS authz_sync;
REVOKE ALL ON SCHEMA authz_sync FROM PUBLIC;
-- tables this policy doesn't keep, and a readers table whose key columns are not the type's any more, go
DO $sb$
DECLARE r record;
BEGIN
  FOR r IN SELECT c.oid::regclass AS tbl FROM pg_catalog.pg_class c
           LEFT JOIN (VALUES {rows}) w(name, cols, types) ON w.name = c.relname
           WHERE c.relnamespace = 'authz_sync'::regnamespace AND c.relkind IN ('r', 'p')
             AND (w.name IS NULL
                  OR (SELECT array_agg(a.attname ORDER BY a.attnum) FROM pg_catalog.pg_attribute a
                      WHERE a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped) IS DISTINCT FROM w.cols
                  OR (SELECT array_agg(a.atttypid::regtype ORDER BY a.attnum) FROM pg_catalog.pg_attribute a
                      WHERE a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped) IS DISTINCT FROM w.types) LOOP
    EXECUTE format('DROP TABLE %s', r.tbl);
  END LOOP;
  -- a table missing (dropped since, or just now): what the index holds is worked out again (sync_refresh)
  IF to_regclass('authz_sync.definitions') IS NOT NULL AND EXISTS (
       SELECT 1 FROM (VALUES {rows}) w(name, cols, types)
       WHERE to_regclass(pg_catalog.format('authz_sync.%I', w.name)) IS NULL) THEN
    DELETE FROM authz_sync.definitions;
  END IF;
END $sb$;
-- the keys each principal holds: its own (user:42), every one of its type's (user:*), anyone's, and its groups'
CREATE TABLE IF NOT EXISTS authz_sync.keys (principal_type text NOT NULL, principal_id text NOT NULL, key text NOT NULL,
  PRIMARY KEY (principal_type, principal_id, key));
CREATE INDEX IF NOT EXISTS keys_by_key ON authz_sync.keys (key);
ALTER TABLE authz_sync.keys REPLICA IDENTITY FULL;
-- the keys that make up each group key (team#member:10): a principal holding one holds the group's
CREATE TABLE IF NOT EXISTS authz_sync.groups (grp text NOT NULL, key text NOT NULL, PRIMARY KEY (grp, key));
CREATE INDEX IF NOT EXISTS groups_by_key ON authz_sync.groups (key);
ALTER TABLE authz_sync.groups REPLICA IDENTITY FULL;
-- the keys a row's readers were worked out from, where they are principals (an and / not between groups)
CREATE TABLE IF NOT EXISTS authz_sync.expanded (object_type text NOT NULL, object_id text NOT NULL, key text NOT NULL,
  PRIMARY KEY (object_type, object_id, key));
CREATE INDEX IF NOT EXISTS expanded_by_key ON authz_sync.expanded (key);
ALTER TABLE authz_sync.expanded REPLICA IDENTITY FULL;
-- what the rows were worked out by: an apply that changes it works them out again (by difference)
CREATE TABLE IF NOT EXISTS authz_sync.definitions (name text PRIMARY KEY, hash text NOT NULL);
ALTER TABLE authz_sync.definitions REPLICA IDENTITY FULL;
{chr(10).join(tables)}
REVOKE ALL ON ALL TABLES IN SCHEMA authz_sync FROM PUBLIC;"""

    def sync_capture_sql(self) -> str:
        """What a transaction changed, noted by authz_int.changed() (sync_dirty) and worked on at its commit, once:
        a row of sync_queued queues its deferred constraint trigger (deleted then, so a write after SET CONSTRAINTS
        ALL IMMEDIATE queues it again)."""
        relevant = "ARRAY[" + ", ".join(lit(n) for n in self.sync_relevant()) + "]::text[]"
        st = self.sync_build()
        locks = sorted({LOCK_KEYS} | {sync_lock(t) for t in st.tops})
        return f"""-- The sync index: the objects each transaction changed, worked on when it commits
CREATE UNLOGGED TABLE authz_int.sync_todo (txid bigint NOT NULL, type text NOT NULL, id text NOT NULL,
  round int NOT NULL DEFAULT 0, PRIMARY KEY (txid, type, id));
CREATE INDEX ON authz_int.sync_todo (txid, type, round);
CREATE UNLOGGED TABLE authz_int.sync_queued (txid bigint PRIMARY KEY);
INSERT INTO authz_int.locks VALUES {", ".join(f"({lit(x)}, 0)" for x in locks)} ON CONFLICT DO NOTHING;
CREATE FUNCTION authz_int.sync_dirty(p_type text, p_ids text[]) RETURNS void
LANGUAGE plpgsql {DEF} AS $f$
BEGIN
  IF coalesce(cardinality(p_ids), 0) = 0 OR p_type <> ALL ({relevant}) THEN RETURN; END IF;
  INSERT INTO authz_int.sync_todo (txid, type, id) SELECT txid_current(), p_type, x FROM unnest(p_ids) x
  WHERE x IS NOT NULL ON CONFLICT DO NOTHING;
  INSERT INTO authz_int.sync_queued VALUES (txid_current()) ON CONFLICT DO NOTHING;
END $f$;
CREATE FUNCTION authz_int.sync_commit() RETURNS trigger
LANGUAGE plpgsql {DEF} AS $f$
BEGIN
  DELETE FROM authz_int.sync_queued WHERE txid = txid_current();
  PERFORM authz_int.sync_process();
  RETURN NULL;
END $f$;
CREATE CONSTRAINT TRIGGER authz_sync_commit AFTER INSERT ON authz_int.sync_queued
  DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION authz_int.sync_commit();"""

    def todo_ids(self, t: Type, every: str, var: str = "v_tx") -> str:
        """text[]: the ids of t a transaction changed (or what it reached), or every one (every: a query of them)
        when it changed them all ('*', a TRUNCATE)."""
        return (
            f"CASE WHEN EXISTS (SELECT 1 FROM authz_int.sync_todo x WHERE x.txid = {var} AND x.type = {lit(t.name)} "
            f"AND x.id = '*') THEN ARRAY({every}) ELSE ARRAY(SELECT x.id FROM authz_int.sync_todo x "
            f"WHERE x.txid = {var} AND x.type = {lit(t.name)}) END"
        )

    @staticmethod
    def typed(t: Type, arr: str) -> str:
        """A text[] of t's ids as its key's type (text for a composite key), leaving out what isn't one."""
        if t.composite or t.pktype == "text":
            return arr
        return (
            f"ARRAY(SELECT v::{t.pktype} FROM unnest({arr}) v WHERE pg_catalog.pg_input_is_valid(v, {lit(t.pktype)}))"
        )

    def group_all_ids_sql(self, u: Type) -> str:
        """Every id of u a group key may name (text): its rows, and with no where, those its link tables and shares
        name (a link row is trusted as it is); and those the groups hold now."""
        st = self.sync_build()
        parts = [f"SELECT {self.key_text(u, 'x')} FROM {qt(u.table)} x"]
        if not u.where:
            for r in u.relations.values():
                for src in r.sources:
                    if src.kind == "table":
                        parts.append(f"SELECT {self.ref_text(u, 'x', src.obj_col)} FROM {qt(src.table)} x")
            parts.append(f"SELECT g.object_id FROM authz.shares g WHERE g.object_type = {lit(u.name)}")
        heads = ", ".join(lit(f"{g[0]}#{g[1]}:") for g in st.groups if g[0] == u.name)
        parts.append(
            f"SELECT substr(g.grp, strpos(g.grp, ':') + 1) FROM authz_sync.groups g "
            f"WHERE left(g.grp, strpos(g.grp, ':')) = ANY (ARRAY[{heads}]::text[])"
        )
        return " UNION ".join(parts)

    def readers_ids_sql(self, t: Type) -> str:
        """Every id of a synced type whose readers may be held: its rows, and those the index holds now."""
        return (
            f"SELECT {self.key_text(t, 'x')} FROM {qt(t.table)} x UNION SELECT {self.key_text(t, 'x')} "
            f"FROM {self.readers_table(t)} x UNION SELECT x.object_id FROM authz_sync.expanded x "
            f"WHERE x.object_type = {lit(t.name)}"
        )

    def principal_ids_sql(self, t: Type) -> str:
        return (
            f"SELECT {self.key_text(t, 'x')} FROM {qt(t.table)} x UNION SELECT k.principal_id FROM authz_sync.keys k "
            f"WHERE k.principal_type = {lit(t.name)}"
        )

    def keys_fn(self, t: Type) -> str:
        return f"authz_int.{q('sync_keys:' + t.name)}"

    def keys_fn_sql(self, t: Type) -> str:
        """The keys each principal of a type holds: its own, its type's, anyone's, and the closure of the groups
        over them. One that fails the type's where holds none: it is nobody."""
        pk = q(self.pk(t))
        where = f" AND coalesce(({on_row(t.where, 'x')}), false)" if t.where else ""
        return f"""-- the keys the principals of {t.name} hold
CREATE FUNCTION {self.keys_fn(t)}(p_ids text[]) RETURNS TABLE (o_id text, o_key text)
LANGUAGE sql STABLE {DEF_CURRENT} AS $f$
  WITH RECURSIVE k(id, key) AS (
    SELECT x.{pk}::text, v.key FROM {qt(t.table)} x
      CROSS JOIN LATERAL (VALUES ({lit(t.name + ":")} || x.{pk}::text), ({lit(t.name + ":*")}), ('anyone')) v(key)
    WHERE x.{pk} IN (SELECT unnest({self.typed(t, "p_ids")})){where}
    UNION
    SELECT k.id, g.grp FROM k JOIN authz_sync.groups g ON g.key = k.key)
  SELECT k.id, k.key FROM k
$f$;"""

    def group_rows_sql(self, g: Name, ids: str) -> str:
        """(grp, key) of a group key's members, for the ids (text[]) of its type."""
        st = self.sync_build()
        u = self.T(g[0])
        return (
            f"SELECT {lit(f'{g[0]}#{g[1]}:')} || f.o_id::text AS grp, f.o_key AS key "
            f"FROM {st.made[g]}({self.typed(u, ids)}) f WHERE NOT f.o_dep"
        )

    def readers_rows_sql(self, t: Type, ids: str) -> str:
        st = self.sync_build()
        return f"SELECT f.o_id, f.o_key, f.o_dep FROM {st.tops[t.name]}({self.typed(t, ids)}) f"

    def spread_sql(self) -> str:
        """authz_int.sync_spread(tx, round): what reads the objects a transaction reached in a round (Edge), added as
        the next round, until no round finds any; returns the last. Everything of a type reaches everything of
        what reads it."""
        st = self.sync_build()
        parts = []
        for e in st.edges:
            s = self.T(e.src)
            text = (
                f"ARRAY(SELECT x.id FROM authz_int.sync_todo x WHERE x.txid = p_tx AND x.type = {lit(e.src)} "
                f"AND x.round = r AND x.id <> '*')"
            )
            sql = e.sql.replace("$ids", self.typed(s, text)).replace("$text", text)
            parts.append(f"SELECT {lit(e.dst)}::text AS t, v.id::text AS i FROM ({sql}) v(id)")
            parts.append(
                f"SELECT {lit(e.dst)}::text, '*'::text WHERE EXISTS (SELECT 1 FROM authz_int.sync_todo x "
                f"WHERE x.txid = p_tx AND x.type = {lit(e.src)} AND x.round = r AND x.id = '*')"
            )
        insert = (
            "INSERT INTO authz_int.sync_todo (txid, type, id, round)\n    SELECT p_tx, d.t, d.i, r + 1 FROM (\n      "
            + "\n      UNION ALL ".join(parts)
            + ") d WHERE d.i IS NOT NULL\n    ON CONFLICT DO NOTHING;"
            if parts
            else "RETURN r;"
        )
        return f"""-- what reads the objects a transaction changed, and what reads those, to the end (no limit: each is worked out again)
CREATE FUNCTION authz_int.sync_spread(p_tx bigint, p_round int) RETURNS int
LANGUAGE plpgsql {DEF_CURRENT} AS $f$
DECLARE r int := p_round; n bigint;
BEGIN
  LOOP
    {insert}
    GET DIAGNOSTICS n = ROW_COUNT;
    EXIT WHEN n = 0;
    r := r + 1;
  END LOOP;
  RETURN r;
END $f$;"""

    def process_sql(self) -> str:
        """authz_int.sync_process(): at a transaction's commit, the index made current for what it changed."""
        st = self.sync_build()
        cases = "\n".join(
            f"             WHEN {lit(n)} THEN ARRAY[{', '.join(lit(x) for x in locks)}]::text[]"
            for n in self.sync_relevant()
            if (locks := self.sync_locks(n))
        )
        groups = []
        for u in self.sync_group_types():
            ut = self.T(u)
            pairs = [g for g in st.groups if g[0] == u]
            body = []
            for g in pairs:
                body.append(
                    f"""    WITH fresh AS MATERIALIZED ({self.group_rows_sql(g, "v_ids")}),
    gone AS (DELETE FROM authz_sync.groups g WHERE g.grp IN (SELECT {lit(f"{g[0]}#{g[1]}:")} || v FROM unnest(v_ids) v)
             AND NOT EXISTS (SELECT 1 FROM fresh f WHERE f.grp = g.grp AND f.key = g.key) RETURNING g.key),
    made AS (INSERT INTO authz_sync.groups SELECT f.grp, f.key FROM fresh f ON CONFLICT DO NOTHING RETURNING key)
    SELECT v_members || coalesce(array_agg(DISTINCT z.k), '{{}}') INTO v_members FROM (SELECT key FROM gone UNION SELECT key FROM made) z(k);"""
                )
            groups.append(
                f"  -- {u}'s groups\n  v_ids := {self.todo_ids(ut, self.group_all_ids_sql(ut))};\n"
                f"  IF cardinality(v_ids) > 0 THEN\n" + "\n".join(body) + "\n  END IF;"
            )
        keys = []
        for t in self.sync_principals():
            keys.append(
                f"""  -- the keys of the principals of {t.name} that changed, or hold a key of a group that did
  IF EXISTS (SELECT 1 FROM authz_int.sync_todo x WHERE x.txid = v_tx AND x.type = {lit(t.name)} AND x.id = '*') THEN
    v_ids := ARRAY({self.principal_ids_sql(t)});
  ELSE
    v_ids := ARRAY(SELECT x.id FROM authz_int.sync_todo x WHERE x.txid = v_tx AND x.type = {lit(t.name)}
                   UNION SELECT k.principal_id FROM authz_sync.keys k WHERE k.principal_type = {lit(t.name)} AND k.key IN (SELECT unnest(v_members)));
  END IF;
  IF cardinality(v_ids) > 0 THEN
    WITH fresh AS MATERIALIZED (SELECT * FROM {self.keys_fn(t)}(v_ids)),
    gone AS (DELETE FROM authz_sync.keys k WHERE k.principal_type = {lit(t.name)} AND k.principal_id IN (SELECT unnest(v_ids))
             AND NOT EXISTS (SELECT 1 FROM fresh f WHERE f.o_id = k.principal_id AND f.o_key = k.key) RETURNING k.key),
    made AS (INSERT INTO authz_sync.keys SELECT {lit(t.name)}, f.o_id, f.o_key FROM fresh f ON CONFLICT DO NOTHING RETURNING key)
    SELECT v_keys || coalesce(array_agg(DISTINCT z.k), '{{}}') INTO v_keys FROM (SELECT key FROM gone UNION SELECT key FROM made) z(k);
  END IF;"""
            )
        readers = []
        for n in st.tops:
            t = self.T(n)
            cols = "f.o_id" if not t.composite else ", ".join(f"(f.o_id::{t.keytype}).{q(c)}" for c, _ in t.key)
            readers.append(
                f"""  -- {n}'s readers
  v_ids := {self.todo_ids(t, self.readers_ids_sql(t))};
  -- (a batch of objects at a time, which a comparison holds in memory; what is there compared first, by the key's
  -- index: only the rows that change are visited)
  FOR v_from IN 1 .. coalesce(cardinality(v_ids), 0) BY {BATCH} LOOP
    v_part := v_ids[v_from : v_from + {BATCH - 1}];
    WITH fresh AS MATERIALIZED ({self.readers_rows_sql(t, "v_part")}),
    there AS MATERIALIZED (SELECT {self.key(t, "x")} AS id, x.key FROM {self.readers_table(t)} x
                           WHERE {self.key_in(t, "x", f"SELECT unnest({self.typed(t, 'v_part')}) AS id")}),
    stale AS (SELECT s.id, s.key FROM there s EXCEPT SELECT f.o_id, f.o_key FROM fresh f WHERE NOT f.o_dep),
    added AS (SELECT f.o_id, f.o_key FROM fresh f WHERE NOT f.o_dep EXCEPT SELECT s.id, s.key FROM there s),
    gone AS (DELETE FROM {self.readers_table(t)} x USING stale s WHERE {self.key_is(t, "x", "s.id")} AND x.key = s.key
             RETURNING 1),
    made AS (INSERT INTO {self.readers_table(t)} SELECT {cols.replace("f.o_id", "a.o_id")}, a.o_key FROM added a
             ORDER BY 1, 2 ON CONFLICT DO NOTHING RETURNING 1),
    gone_from AS (DELETE FROM authz_sync.expanded x WHERE x.object_type = {lit(n)} AND x.object_id IN (SELECT unnest(v_part))
             AND NOT EXISTS (SELECT 1 FROM fresh f WHERE f.o_dep AND f.o_id::text = x.object_id AND f.o_key = x.key) RETURNING 1),
    made_from AS (INSERT INTO authz_sync.expanded SELECT {lit(n)}, f.o_id::text, f.o_key FROM fresh f WHERE f.o_dep ON CONFLICT DO NOTHING RETURNING 1)
    SELECT count(*) INTO v_n FROM (SELECT 1 FROM gone UNION ALL SELECT 1 FROM made UNION ALL SELECT 1 FROM gone_from
                                   UNION ALL SELECT 1 FROM made_from) z;
  END LOOP;"""
            )
        return f"""-- At a transaction's commit, in it: the index made current for the objects it changed and what reads them (the
-- difference written, not every row again). The lock rows of what it reaches first, in one order: a writer with an
-- older snapshot (REPEATABLE READ, SERIALIZABLE) gets a serialization error rather than writing stale readers
CREATE FUNCTION authz_int.sync_process() RETURNS void
LANGUAGE plpgsql {DEF_CURRENT} AS $f$
DECLARE
  v_tx bigint := txid_current();
  v_round int;
  v_lock text; v_locks text[];
  v_ids text[]; v_part text[]; v_from int;
  v_members text[] := '{{}}';  -- the keys of the groups' rows that changed
  v_keys text[] := '{{}}';     -- the keys a principal gained or lost
  v_n bigint;
BEGIN
  IF NOT EXISTS (SELECT 1 FROM authz_int.sync_todo x WHERE x.txid = v_tx) THEN RETURN; END IF;
  SELECT array_agg(DISTINCT l ORDER BY l) INTO v_locks
  FROM (SELECT DISTINCT x.type FROM authz_int.sync_todo x WHERE x.txid = v_tx) d,
       LATERAL unnest(CASE d.type
{cases}
             ELSE '{{}}'::text[] END) l;
  FOREACH v_lock IN ARRAY coalesce(v_locks, '{{}}') LOOP
    UPDATE authz_int.locks SET n = n + 1 WHERE type = v_lock;
  END LOOP;
  v_round := authz_int.sync_spread(v_tx, 0);
{chr(10).join(groups)}
{chr(10).join(keys)}
  -- rows whose readers were worked out from a key someone gained or lost, and what reads them
  IF cardinality(v_keys) > 0 THEN
    INSERT INTO authz_int.sync_todo (txid, type, id, round)
    SELECT DISTINCT v_tx, x.object_type, x.object_id, v_round + 1 FROM authz_sync.expanded x WHERE x.key IN (SELECT unnest(v_keys))
    ON CONFLICT DO NOTHING;
    IF FOUND THEN
      v_round := authz_int.sync_spread(v_tx, v_round + 1);
    END IF;
  END IF;
{chr(10).join(readers)}
  DELETE FROM authz_int.sync_todo x WHERE x.txid = v_tx;
END $f$;"""

    def fresh_sql(self) -> list[tuple[str, str, str]]:
        """(what, stored, fresh): each table of the index as it is, and as a rebuild would make it."""
        st = self.sync_build()
        out: list[tuple[str, str, str]] = []
        fresh_groups = (
            " UNION ".join(self.group_rows_sql(g, f"ARRAY({self.group_all_ids_sql(self.T(g[0]))})") for g in st.groups)
            or "SELECT NULL::text, NULL::text WHERE false"
        )
        out.append(("groups", "SELECT grp, key FROM authz_sync.groups", fresh_groups))
        fresh_keys = " UNION ".join(
            f"SELECT {lit(t.name)}::text, f.o_id, f.o_key FROM {self.keys_fn(t)}(ARRAY({self.principal_ids_sql(t)})) f"
            for t in self.sync_principals()
        )
        out.append(("keys", "SELECT principal_type, principal_id, key FROM authz_sync.keys", fresh_keys))
        for n in st.tops:
            t = self.T(n)
            every = f"ARRAY({self.readers_ids_sql(t)})"
            out.append(
                (
                    f"{n}'s readers, and what they were worked out from",
                    f"SELECT {self.key_text(t, 'x')}, x.key, false FROM {self.readers_table(t)} x UNION ALL "
                    f"SELECT x.object_id, x.key, true FROM authz_sync.expanded x WHERE x.object_type = {lit(n)}",
                    f"SELECT f.o_id::text, f.o_key, f.o_dep FROM ({self.readers_rows_sql(t, every)}) f",
                )
            )
        return out

    def sync_functions_sql(self) -> str:
        """Every function of the index: the derivations, the keys, the commit's work, and the admin's."""
        st = self.sync_build()
        # (each worked out once: a rebuild of a big table takes a while; each IF's first line the same for every part)
        verify = "\n".join(
            f"  IF EXISTS (\n    WITH s AS MATERIALIZED ({stored}), f AS MATERIALIZED ({fresh})\n"
            f"    SELECT 1 FROM ((TABLE s EXCEPT TABLE f) UNION ALL (TABLE f EXCEPT TABLE s)) d) THEN\n"
            f"    RAISE NOTICE 'the sync index differs from a rebuild: %', {lit(what)};\n    RETURN false;\n  END IF;"
            for what, stored, fresh in self.fresh_sql()
        )
        stale = (
            "  DELETE FROM authz_sync.groups g WHERE left(g.grp, strpos(g.grp, ':')) <> ALL (ARRAY["
            + ", ".join(lit(f"{g[0]}#{g[1]}:") for g in st.groups)
            + "]::text[]);\n"
            "  DELETE FROM authz_sync.keys k WHERE k.principal_type <> ALL (ARRAY["
            + ", ".join(lit(t.name) for t in self.sync_principals())
            + "]::text[]);\n"
            "  DELETE FROM authz_sync.expanded x WHERE x.object_type <> ALL (ARRAY["
            + ", ".join(lit(n) for n in st.tops)
            + "]::text[]);"
        )
        every = sorted(set(self.sync_group_types()) | {t.name for t in self.sync_principals()} | set(st.tops))
        marks = "\n".join(f"    PERFORM authz_int.sync_dirty({lit(n)}, ARRAY['*']);" for n in every)
        return "\n".join(
            [
                "-- these functions call each other; their bodies are checked when first used\n"
                "SET LOCAL check_function_bodies = off;",
                *st.functions,
                *[self.keys_fn_sql(t) for t in self.sync_principals()],
                self.spread_sql(),
                self.process_sql(),
                f"""-- the index worked out again where what it is worked out by changed (p_hash), or all of it (p_force); by difference
CREATE FUNCTION authz_int.sync_refresh(p_hash text, p_force boolean DEFAULT false) RETURNS void
LANGUAGE plpgsql {DEF_CURRENT} AS $f$
BEGIN
  IF p_force OR NOT EXISTS (SELECT 1 FROM authz_sync.definitions d WHERE d.name = 'index' AND d.hash = p_hash) THEN
    -- what this policy no longer keeps
{stale.replace(chr(10), chr(10) + "  ")}
{marks}
    PERFORM authz_int.sync_process();
  END IF;
  IF p_hash IS NOT NULL THEN
    INSERT INTO authz_sync.definitions VALUES ('index', p_hash) ON CONFLICT (name) DO UPDATE SET hash = EXCLUDED.hash;
  END IF;
END $f$;""",
                f"""-- Shares that start or end later change who reads their objects with no write: SELECT authz.sync_tick() works out
-- again the readers of those whose start or end passed since it last ran, and says how many shares. Schedule it
-- (pg_cron, the app's jobs) as often as a share that ends should leave the engines' clients
CREATE FUNCTION authz.sync_tick() RETURNS bigint
LANGUAGE plpgsql {DEF} AS $f$
DECLARE
  v_from timestamptz := coalesce((SELECT s.value::timestamptz FROM authz.settings s WHERE s.key = 'sync_tick_to'), '-infinity');
  v_to timestamptz := now();
  n bigint;
BEGIN
  PERFORM authz_int.sync_dirty(g.object_type, array_agg(DISTINCT g.object_id)) FROM authz.shares g
  WHERE (g.expires_at > v_from AND g.expires_at <= v_to) OR (g.starts_at > v_from AND g.starts_at <= v_to)
  GROUP BY g.object_type;
  SELECT count(*) INTO n FROM authz.shares g
  WHERE (g.expires_at > v_from AND g.expires_at <= v_to) OR (g.starts_at > v_from AND g.starts_at <= v_to);
  -- (written in ISO 8601, which every session reads alike whatever its DateStyle)
  INSERT INTO authz.settings VALUES ('sync_tick_to', to_char(v_to AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'))
    ON CONFLICT (key) DO UPDATE SET value = to_char(greatest(authz.settings.value::timestamptz, v_to) AT TIME ZONE 'UTC',
                                                    'YYYY-MM-DD"T"HH24:MI:SS.US"Z"');
  RETURN n;
END $f$;""",
                f"""-- Admin check: the sync index matches a rebuild (false says which part differs, in a notice)
CREATE FUNCTION authz.sync_verify() RETURNS boolean
LANGUAGE plpgsql STABLE {DEF_CURRENT} AS $f$
BEGIN
{verify}
  RETURN true;
END $f$;""",
                "SET LOCAL check_function_bodies = on;",
            ]
        )

    def sync_refresh_sql(self) -> str:
        """After everything is made: the index worked out again where its definition changed (the hash is part of this
        step, so a migration runs it when it changes); a warning for shares that give nothing through sync."""
        st = self.sync_build()
        shared = [k for k in st.shared if k[1] != "role:*"]
        roles = sorted({k[0] for k in st.shared if k[1] == "role:*"})
        match = " OR ".join(
            [f"(g.object_type = {lit(t)} AND g.relation = {lit(r)})" for t, r in shared]
            + [f"(g.object_type = {lit(t)} AND g.relation LIKE 'role:%')" for t in roles]
        )
        warn = (
            f"""
DO $sw$
DECLARE n bigint; m bigint;
BEGIN
  SELECT count(*) FILTER (WHERE g.caveat IS NOT NULL), count(*) FILTER (WHERE g.subject_type = 'link') INTO n, m
  FROM authz.shares g WHERE {match};
  IF n > 0 THEN
    RAISE WARNING '% shares with a caveat give nothing through the sync index: a caveat is checked at each request, with what it says', n;
  END IF;
  IF m > 0 THEN
    RAISE WARNING '% share links give nothing through the sync index: a synced client is a principal, without links', m;
  END IF;
END $sw$;"""
            if match
            else ""
        )
        return f"SELECT authz_int.sync_refresh({lit(self.sync_hash())});{warn}"

    def sync_grants_sql(self) -> str:
        """The sync role reads the index (USAGE on authz_sync, SELECT on its tables) and nothing else of rowstile's.
        Refused: a role that isn't there, is the app role's member or member of it, or the owner's; one that may
        read a masked column (it holds BYPASSRLS: through the engine, every row's)."""
        role = self.pol.sync_role
        assert role is not None
        sync, app = lit(q(role)), lit(q(self.role))
        return f"""-- The sync role reads the index, and nothing else rowstile keeps
DO $sr$
DECLARE v_sync oid := to_regrole({sync}); v_app oid := to_regrole({app}); v_cols text;
BEGIN
  IF v_sync IS NULL THEN
    RAISE EXCEPTION 'the sync role {role} does not exist [AZ808]'
      USING HINT = 'make it for the engine: CREATE ROLE {role} LOGIN REPLICATION BYPASSRLS, then apply again';
  END IF;
  IF pg_catalog.pg_has_role(v_sync, CURRENT_USER, 'MEMBER') THEN
    RAISE EXCEPTION 'the sync role {role} is the role that applies the policy (%), or a member of it [AZ808]', CURRENT_USER
      USING HINT = 'the engine connects as a role of its own, which owns nothing of the database';
  END IF;
  IF v_app IS NOT NULL AND (pg_catalog.pg_has_role(v_sync, v_app, 'MEMBER') OR pg_catalog.pg_has_role(v_app, v_sync, 'MEMBER')) THEN
    RAISE EXCEPTION 'the sync role {role} and the app role {self.role} are one another''s members: the app would read every row [AZ808]'
      USING HINT = 'the engine connects as a role of its own, which the app role is not a member of, nor it of the app role';
  END IF;
  SELECT pg_catalog.string_agg(m.tbl || '.' || m.col, ', ' ORDER BY m.tbl, m.col) INTO v_cols FROM authz_int.masked_columns m
  WHERE pg_catalog.has_column_privilege(v_sync, m.tbl, m.col, 'SELECT');
  IF v_cols IS NOT NULL THEN
    RAISE EXCEPTION 'the sync role {role} may read masked columns: % [AZ809]', v_cols
      USING HINT = 'it reads every row, so a masked column would reach every client: revoke SELECT on the table, grant the other columns (GRANT SELECT (id, name) ON ...), then apply again';
  END IF;
END $sr$;
GRANT USAGE ON SCHEMA authz_sync TO {q(role)};
GRANT SELECT ON ALL TABLES IN SCHEMA authz_sync TO {q(role)};"""

    def sync_extra_grants_sql(self) -> str:
        """Privileges on authz_sync and its tables that the policy doesn't give (the sync role's USAGE and SELECT),
        as extra_grants_sql's rows."""
        if not self.pol.syncs:
            return ""
        role = self.pol.sync_role
        assert role is not None
        sync = f"to_regrole({lit(q(role))})"
        who = "LATERAL (SELECT CASE a.grantee WHEN 0 THEN 'PUBLIC' ELSE a.grantee::regrole::text END AS who) gw"
        return f"""
UNION ALL
SELECT n.nspname::text, gw.who, a.privilege_type,
       format('REVOKE %s ON SCHEMA %I FROM %s CASCADE', a.privilege_type, n.nspname, gw.who)
  FROM pg_namespace n, aclexplode(n.nspacl) a, {who}
  WHERE n.nspname = 'authz_sync' AND a.grantee <> n.nspowner
    AND NOT (a.grantee = {sync} AND a.privilege_type = 'USAGE')
UNION ALL
SELECT c.oid::regclass::text, gw.who, a.privilege_type,
       format('REVOKE %s ON TABLE %s FROM %s CASCADE', a.privilege_type, c.oid::regclass, gw.who)
  FROM pg_class c, aclexplode(c.relacl) a, {who}
  WHERE c.relnamespace = 'authz_sync'::regnamespace AND a.grantee <> c.relowner
    AND NOT (a.grantee = {sync} AND a.privilege_type = 'SELECT')
UNION ALL
SELECT format('%s (%I)', c.oid::regclass, att.attname), gw.who, a.privilege_type,
       format('REVOKE %s (%I) ON %s FROM %s CASCADE', a.privilege_type, att.attname, c.oid::regclass, gw.who)
  FROM pg_class c JOIN pg_attribute att ON att.attrelid = c.oid, aclexplode(att.attacl) a, {who}
  WHERE c.relnamespace = 'authz_sync'::regnamespace AND att.attacl IS NOT NULL"""

    def sync_lint_sql(self) -> str:
        """authz.lint()'s findings about the sync role: it must exist, not be the app role's member or member of it,
        bypass row-level security (or the engine's first snapshot is empty), read no masked column, not own a
        governed table, and no publication may publish a masked column."""
        if not self.pol.syncs:
            return ""
        role = self.pol.sync_role
        assert role is not None
        tables = "ARRAY[" + ", ".join(lit(qt(t)) for t in sorted({t.table for t in self.types.values()})) + "]::text[]"
        # (the role is named once, in the block's variables: its statements read the same whatever its name)
        return f"""  -- the sync role (a preview): the engine reads every row as it, by logical replication
  DECLARE
    v_sync_name text := {lit(role)};
    v_sync oid := to_regrole({lit(q(role))});
  BEGIN
  IF v_sync IS NULL THEN
    severity := 'error'; object := v_sync_name; problem := 'the sync role does not exist: the engine can''t read the index'; RETURN NEXT;
  ELSE
    IF pg_has_role(v_sync, v_role, 'MEMBER') OR pg_has_role(v_role, v_sync, 'MEMBER') THEN
      severity := 'error'; object := v_sync_name;
      problem := 'the sync role and the app role are one another''s members: the app would read every row through it'; RETURN NEXT;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles ro WHERE ro.oid = v_sync AND (ro.rolbypassrls OR ro.rolsuper)) THEN
      severity := 'error'; object := v_sync_name;
      problem := format('the sync role lacks BYPASSRLS: the rules apply to the app role, so it reads no row of a table with rules, and an engine''s first snapshot is empty while the changes it decodes hold every row. ALTER ROLE %I BYPASSRLS', v_sync_name); RETURN NEXT;
    END IF;
    FOR r IN SELECT m.tbl, m.col FROM authz_int.masked_columns m
             WHERE has_column_privilege(v_sync, m.tbl, m.col, 'SELECT') LOOP
      severity := 'error'; object := r.tbl || '.' || r.col;
      problem := format('is masked, and the sync role may read it: every client of the engine would. REVOKE SELECT (%I) ON %s FROM %I', r.col, r.tbl, v_sync_name); RETURN NEXT;
    END LOOP;
    FOR r IN SELECT c.oid::regclass AS tbl FROM pg_class c
             WHERE c.oid = ANY (SELECT to_regclass(x) FROM unnest({tables}) x) AND pg_has_role(v_sync, c.relowner, 'MEMBER') LOOP
      severity := 'error'; object := r.tbl::text;
      problem := 'is owned by the sync role (or a role it belongs to): an owner may turn row-level security off and change the rules. The engine connects as a role that owns nothing'; RETURN NEXT;
    END LOOP;
  END IF;
  END;
  FOR r IN SELECT p.pubname, m.tbl, m.col FROM authz_int.masked_columns m
           JOIN pg_class c ON c.oid = to_regclass(m.tbl) JOIN pg_namespace n ON n.oid = c.relnamespace
           JOIN pg_publication_tables p ON p.schemaname = n.nspname AND p.tablename = c.relname AND m.col = ANY (p.attnames) LOOP
    severity := 'error'; object := r.tbl || '.' || r.col;
    problem := format('is masked, and the publication %s publishes it: an engine that reads the publication reads it. Give the publication a column list without it', r.pubname); RETURN NEXT;
  END LOOP;
"""


class Deriver:
    """Writes the SQL of who holds what, as keys: one function per relation or permission the synced expressions
    reach (fn), returning (o_id, o_key, o_dep) for the ids it is given; o_dep marks a key an expanded row was
    worked out from, not one of its readers."""

    def __init__(self, c: SyncMixin, st: SyncState) -> None:
        self.c, self.st = c, st

    # --- names and empty answers ---
    def name(self, t: Type, name: str) -> str:
        return f"authz_int.{q(f'sync:{t.name}.{name}')}"

    @staticmethod
    def none(t: Type) -> str:
        return f"SELECT NULL::{t.pktype} AS id, NULL::text AS key, false AS d WHERE false"

    # --- functions ---
    def top(self, t: Type, e: Expr, s: Sync) -> str:
        """The readers of a synced type's rows: of the rows that exist and pass the type's where."""
        c = self.c
        fn = f"authz_int.{q(f'sync:{t.name}')}"
        where = ""
        if t.where:
            c.sync_cond_ok(t.where, t.loc, f"the where of {t.name}, which is synced")
            where = f" AND coalesce(({on_row(t.where, 'x')}), false)"
        rows = self.rows(t, e, "SELECT id FROM o", s.loc)
        self.st.functions.append(
            f"-- {s.table}: the keys that may read each row ({s.loc})\n"
            f"CREATE FUNCTION {fn}(p_ids {t.pktype}[]) RETURNS TABLE (o_id {t.pktype}, o_key text, o_dep boolean)\n"
            f"LANGUAGE sql STABLE {DEF_CURRENT} AS $f$\n"
            f"  WITH o AS (SELECT {c.key(t, 'x')} AS id FROM {qt(t.table)} x WHERE {c.key_in(t, 'x', 'SELECT unnest(p_ids) AS id')}{where})\n"
            f"  SELECT DISTINCT r.id, r.key, r.d FROM (\n  {rows}) r\n$f$;"
        )
        return fn

    def fn(self, t: Type, name: str, loc: Loc) -> str:
        """The function of t.name (a relation or a permission), made if it isn't yet."""
        c, st = self.c, self.st
        pair = (t.name, name)
        if pair in st.made:
            return st.made[pair]
        if pair in st.making:
            fail(
                loc,
                f"{t.name}.{name} is a group in itself, and who holds it joins parts that depend on who asks with "
                f"and / not: the sync index can't work it out as keys. Sync another permission, or say the group "
                f"without and / not",
                "AZ807",
            )
        st.making.append(pair)
        fn = self.name(t, name)
        where = ""
        if t.where:
            c.sync_cond_ok(t.where, t.loc, f"the where of {t.name}")
            where = f" WHERE {c.where_holds(t, 'x.id')}"
        entry = f"o AS (SELECT DISTINCT x.id FROM unnest(p_ids) x(id){where})"
        key = c.recursive.get(pair)
        if name in t.relations:
            r = t.relations[name]
            body = f"WITH {entry}\n  {self.rel_rows(t, r, 'SELECT id FROM o', r.loc)}"
            what = f"{t.name}.{name} ({r.loc})"
        elif key is None:
            # as its view: the permissions of its type it names written out in place, and a lookup another one
            # covers dropped (parent.edit beside parent.view), so each is worked out once
            perm = t.perms[name]
            items = c.prune(t, c.flat_items(t, perm, views=True))
            expr = items[0] if len(items) == 1 else Or(items)
            body = f"WITH {entry}\n  {self.rows(t, expr, 'SELECT id FROM o', perm.loc)}"
            what = f"{t.name}.{name} ({perm.loc}): {perm.src}"
        else:
            perm = t.perms[name]
            body = self.recursive_rows(t, perm.name, key, entry, perm.loc)
            what = f"{t.name}.{name} ({perm.loc}): {perm.src}, inherited"
        st.making.remove(pair)
        st.made[pair] = fn
        # (each key once for each object: what inherits, or reads what inherits, reads each one again for every
        # ancestor, and the next level would read those again for each of its own)
        st.functions.append(
            f"-- {what}: who holds it, as keys\n"
            f"CREATE FUNCTION {fn}(p_ids {t.pktype}[]) RETURNS TABLE (o_id {t.pktype}, o_key text, o_dep boolean)\n"
            f"LANGUAGE sql STABLE {DEF_CURRENT} AS $f$\n"
            f"  SELECT DISTINCT r.id, r.key, r.d FROM (\n  {body}) r\n$f$;"
        )
        return fn

    def recursive_rows(self, t: Type, name: str, key: tuple[Name, ...], entry: str, loc: Loc) -> str:
        """A permission that inherits: what its starting points give (base items), on each ancestor in its closure
        table."""
        c, st = self.c, self.st
        members = c.scc_members[key]
        edges = c.scc_edges(key)
        if len(members) == 1:
            tree = c.trees[(t.name, edges)]
            st.trees[tree] = None
            self.edge(
                t.name,
                t.name,
                f"SELECT c.descendant::text FROM authz_int.{q(tree)} c WHERE c.ancestor IN (SELECT unnest($ids))",
            )
            # where it starts, with what a permission of its type that inherits through links this walk follows gives
            # written out in place (start_items): that one's ancestors are among this one's, so one walk covers both,
            # where a call would walk its tree again from each ancestor of this one
            items = c.start_items(t, t.perms[name], edges)
            base = self.rows(t, Or(items) if len(items) > 1 else items[0], "SELECT DISTINCT a.a AS id FROM anc a", loc)
            return (
                f"WITH {entry},\n  anc AS MATERIALIZED (SELECT c.descendant AS id, c.ancestor AS a "
                f"FROM authz_int.{q(tree)} c WHERE c.descendant IN (SELECT id FROM o)),\n"
                f"  b AS MATERIALIZED ({base})\n  SELECT a.id, b.key, b.d FROM anc a JOIN b ON b.id = a.a"
            )
        tree = c.trees[key]
        st.trees[tree] = None
        names = sorted({tn for tn, _ in members})
        for a in names:
            for b in names:
                self.edge(
                    a,
                    b,
                    f"SELECT c.did FROM authz_int.{q(tree)} c WHERE c.atype = {lit(a)} AND c.aid IN (SELECT unnest($text)) "
                    f"AND c.dtype = {lit(b)}",
                )
        ctes = [
            entry,
            f"anc AS MATERIALIZED (SELECT c.did::{t.pktype} AS id, c.atype, c.aid FROM authz_int.{q(tree)} c "
            f"WHERE c.dtype = {lit(t.name)} AND c.did IN (SELECT id::text FROM o))",
        ]
        outs = []
        for i, (tn, pn) in enumerate(members):
            mt = c.T(tn)
            items = c.base_items(mt, mt.perms[pn])
            if not items:
                continue
            ids = f"SELECT DISTINCT a.aid::{mt.pktype} AS id FROM anc a WHERE a.atype = {lit(tn)}"
            ctes.append(f"b{i} AS MATERIALIZED ({self.rows(mt, Or(items) if len(items) > 1 else items[0], ids, loc)})")
            outs.append(f"SELECT a.id, b.key, b.d FROM anc a JOIN b{i} b ON a.atype = {lit(tn)} AND a.aid = b.id::text")
        return f"WITH {', '.join(ctes)}\n  " + (union(outs) if outs else self.none(t))

    # --- dependents ---
    def edge(self, src: str, dst: str, sql: str) -> None:
        """dst's readers read src's objects through sql (see Edge)."""
        e = Edge(src, dst, sql)
        if not any(x.src == src and x.dst == dst and x.sql == sql for x in self.st.edges):
            self.st.edges.append(e)

    def link_edge(self, t: Type, src: Link, st: str, sr: str | None) -> None:
        """t's readers read st's objects through a column or table source naming them."""
        c = self.c
        s = c.T(st)
        if s.composite:
            match = c.key_in(s, "x", "SELECT unnest($ids) AS id", c.source_columns(src))
            match += f" AND x.{q(src.type_col)} = {lit(st)}" if src.type_col else ""
        else:
            match = c.of_type(src, "x", st, f"{c.subject_id(src, 'x', st)} IN (SELECT unnest($ids))")
        if src.kind == "column":
            self.edge(st, t.name, f"SELECT {c.key_text(t, 'x')} FROM {qt(t.table)} x WHERE {match}")
        else:
            self.edge(st, t.name, f"SELECT {c.ref_text(t, 'x', src.obj_col)} FROM {qt(src.table)} x WHERE {match}")

    def share_edge(self, t: Type, st: str, sr: str | None, relation: str | None) -> None:
        """t's readers read st's objects through the shares to them (relation None: custom roles' assignments)."""
        rel = f"g.relation = {lit(relation)}" if relation else "g.relation LIKE 'role:%'"
        self.edge(
            st,
            t.name,
            f"SELECT g.object_id FROM authz.shares g WHERE g.subject_type = {lit(st)} AND g.subject_id IN (SELECT unnest($text)) "
            f"AND g.subject_relation = {lit(sr or '')} AND g.object_type = {lit(t.name)} AND {rel}",
        )

    # --- expressions ---
    def rows(self, t: Type, e: Expr, ids: str, loc: Loc) -> str:
        """SQL of (id, key, d): the keys that hold e on t's objects in ids (a query of `id`)."""
        c = self.c
        match e:
            case Or(items):
                return union([self.rows(t, x, ids, loc) for x in once(items)])
            case And(items):
                return self.and_rows(t, once(items), ids, loc)
            case Not(_):
                return self.and_rows(t, [Cond(KEYWORDS["anyone"]), e], ids, loc)
            case Cond(sql):
                if sql == KEYWORDS["nobody"]:
                    return self.none(t)
                key = {KEYWORDS["anyone"]: "anyone", KEYWORDS["signed_in"]: "user:*"}.get(sql)
                cond = ""
                if key is None:
                    c.sync_cond_ok(sql, loc, "a condition of what is synced")
                    cond, key = f" AND coalesce(({on_row(sql, 'r')}), false)", "anyone"
                return (
                    f"SELECT {c.key(t, 'r')} AS id, {lit(key)}::text AS key, false AS d FROM {qt(t.table)} r "
                    f"WHERE {c.key_in(t, 'r', ids)}{cond}"
                )
            case Ref(name):
                if name in t.relations:
                    return self.rel_rows(t, t.relations[name], ids, loc)
                return self.call(t, name, ids, loc)
            case Arrow(rel, perm) | ArrowOn(rel, perm, _):
                return self.arrow_rows(t, e, rel, perm, ids, loc)
            case _:
                assert_never(e)

    def call(self, t: Type, name: str, ids: str, loc: Loc) -> str:
        return (
            f"SELECT f.o_id AS id, f.o_key AS key, f.o_dep AS d FROM "
            f"{self.fn(t, name, loc)}(ARRAY(SELECT x.id FROM ({ids}) x)) f"
        )

    def held(self, st: str, name: str, links: str, u: str, loc: Loc) -> str:
        """The keys of whoever holds st.name on the objects in column u of the links l (id, u): its group key, or
        its holders' keys copied in."""
        if self.c.keyed(st, name):
            self.st.groups[(st, name)] = None
            return f"SELECT {links}.id, {lit(f'{st}#{name}:')} || ({links}.{u})::text AS key, false AS d FROM {links}"
        f = self.fn(self.c.T(st), name, loc)
        return (
            f"SELECT {links}.id, f.o_key AS key, f.o_dep AS d FROM {links} "
            f"JOIN {f}(ARRAY(SELECT DISTINCT y.{u} FROM {links} y)) f ON f.o_id = {links}.{u}"
        )

    def linked(self, t: Type, src: Source, st: str, sr: str | None, ids: str, relation: str) -> str:
        """(id, u) for t's objects in ids and the ids u of the st (#sr) a source links each to (a column, a table or
        shares: custom roles give keys only, share_rows, and aren't followed with a dot, AZ210)."""
        c = self.c
        s = c.T(st)
        if src.kind == "column":
            u = c.subject_id(src, "r", st)
            return (
                f"SELECT {c.key(t, 'r')} AS id, {u} AS u FROM {qt(t.table)} r WHERE {c.key_in(t, 'r', ids)} "
                f"AND {u} IS NOT NULL"
            )
        if src.kind == "table":
            if src.where:
                c.sync_cond_ok(src.where, src.loc, f"the where of {src.table}")
            u = c.subject_id(src, "s", st)
            where = f" AND coalesce(({on_row(src.where, 's')}), false)" if src.where else ""
            return (
                f"SELECT {c.ref(t, 's', src.obj_col)} AS id, {u} AS u FROM {qt(src.table)} s "
                f"WHERE {c.key_in(t, 's', ids, src.obj_col)} AND {u} IS NOT NULL{where}"
            )
        assert src.kind == "shared"
        self.st.shared[(t.name, relation)] = None
        return (
            f"SELECT g.object_id::{t.pktype} AS id, g.subject_id::{s.pktype} AS u FROM authz.shares g "
            f"WHERE g.object_type = {lit(t.name)} AND g.object_id IN (SELECT x.id::text FROM ({ids}) x) "
            f"AND g.relation = {lit(relation)} AND g.subject_type = {lit(st)} AND g.subject_relation = "
            f"{lit(sr or '')} AND {LIVE}"
        )

    def rel_rows(self, t: Type, r: Relation, ids: str, loc: Loc) -> str:
        """The keys that hold relation r on t's objects in ids: through each source, each of its subjects."""
        c = self.c
        parts: list[str] = []
        for src in r.sources:
            if src.kind == "shared" or src.kind == "roles":
                parts += self.share_rows(t, r, src, ids, loc)
                continue
            for st, sr in src.subjects:
                assert st in c.types and sr != "*"  # (anyone, link and type:* are only shared: AZ204)
                if sr is None and not c.is_principal(st):
                    continue  # links to objects: they give something only when followed with a dot
                links = self.linked(t, src, st, sr, ids, r.name)
                if sr is None:
                    cte = f"l{self.st.next()}"
                    parts.append(
                        wrap(
                            f"WITH {cte} AS ({links})\n  SELECT {cte}.id, {lit(st + ':')} || ({cte}.u)::text AS key, "
                            f"false AS d FROM {cte}"
                        )
                    )
                    continue
                if not c.keyed(st, sr):
                    self.link_edge(t, src, st, sr)
                cte = f"l{self.st.next()}"
                parts.append(wrap(f"WITH {cte} AS MATERIALIZED ({links})\n  {self.held(st, sr, cte, 'u', loc)}"))
        return union(parts) if parts else self.none(t)

    def share_rows(self, t: Type, r: Relation, src: Source, ids: str, loc: Loc) -> list[str]:
        """The keys shares give (src: shared, or custom roles' assignments): started, not ended, without a caveat
        (a caveat is checked at each request, with what the request says: through sync, it gives nothing). A share
        link gives nothing either: the index has no links."""
        c = self.c
        if src.kind == "roles":
            rel = c.role_rel_sql(t, src, f"g.object_id::{t.pktype}")
            self.st.shared[(t.name, "role:*")] = None
        else:
            rel = f"g.relation = {lit(r.name)}"
            self.st.shared[(t.name, r.name)] = None
        head = (
            f"FROM authz.shares g WHERE g.object_type = {lit(t.name)} AND g.object_id IN "
            f"(SELECT x.id::text FROM ({ids}) x) AND {rel} AND {LIVE}"
        )
        out: list[str] = []
        for st, sr in src.subjects:
            if st == "link":
                self.st.links[(t.name, r.name)] = None
                continue
            if st == "anyone":
                out.append(
                    f"SELECT g.object_id::{t.pktype} AS id, 'anyone'::text AS key, false AS d {head} "
                    f"AND g.subject_type = 'anyone'"
                )
            elif sr == "*":
                out.append(
                    f"SELECT g.object_id::{t.pktype} AS id, {lit(st + ':*')}::text AS key, false AS d {head} "
                    f"AND g.subject_type = {lit(st)} AND g.subject_relation = '' AND g.subject_id = '*'"
                )
            elif sr is None and c.is_principal(st):
                out.append(
                    f"SELECT g.object_id::{t.pktype} AS id, {lit(st + ':')} || g.subject_id AS key, false AS d "
                    f"{head} AND g.subject_type = {lit(st)} AND g.subject_relation = '' AND g.subject_id <> '*'"
                )
            elif sr is not None and st in c.types:
                s = c.T(st)
                links = (
                    f"SELECT g.object_id::{t.pktype} AS id, g.subject_id::{s.pktype} AS u {head} "
                    f"AND g.subject_type = {lit(st)} AND g.subject_relation = {lit(sr)}"
                )
                if not c.keyed(st, sr):
                    self.share_edge(t, st, sr, None if src.kind == "roles" else r.name)
                cte = f"l{self.st.next()}"
                out.append(wrap(f"WITH {cte} AS MATERIALIZED ({links})\n  {self.held(st, sr, cte, 'u', loc)}"))
        return out

    def arrow_rows(self, t: Type, e: Expr, rel: str, perm: str, ids: str, loc: Loc) -> str:
        """rel.perm: whoever holds perm on what rel links each object to."""
        c = self.c
        r, targets = c.targets(t, rel, loc)
        on = only_on(e)
        names = on if on is not None else [x.name for x in targets]
        parts: list[str] = []
        for st in dict.fromkeys(names):
            for src in r.sources:
                if (st, None) not in src.subjects:
                    continue
                links = self.linked(t, src, st, None, ids, r.name)
                if not c.keyed(st, perm):
                    if src.kind == "shared":
                        self.share_edge(t, st, None, r.name)
                    else:
                        assert src.kind == "column" or src.kind == "table"
                        self.link_edge(t, src, st, None)
                cte = f"l{self.st.next()}"
                parts.append(wrap(f"WITH {cte} AS MATERIALIZED ({links})\n  {self.held(st, perm, cte, 'u', loc)}"))
        return union(parts) if parts else self.none(t)

    def and_rows(self, t: Type, items: list[Expr], ids: str, loc: Loc) -> str:
        """An `and`: conditions on the row filter it; one part that depends on who asks gives its keys. Two or more,
        or a `not` of one: for each row where at most one positive part lacks `anyone` and nothing is denied, that
        part's keys (or `anyone`); elsewhere the principals holding a key of every positive part and of no negative
        one, as principal keys, and every key consulted as a dependency (o_dep)."""
        c = self.c
        conds: list[str] = []
        pos: list[Expr] = []
        neg: list[Expr] = []
        for x in items:
            match x:
                case Cond(sql) if sql not in KEYWORD_SQL:
                    c.sync_cond_ok(sql, loc, "a condition of what is synced")
                    conds.append(f"coalesce(({on_row(sql, 'r')}), false)")
                case Not(Cond(sql)) if sql not in KEYWORD_SQL:
                    c.sync_cond_ok(sql, loc, "a condition of what is synced")
                    conds.append(f"NOT coalesce(({on_row(sql, 'r')}), false)")
                case Not(inner):
                    neg.append(inner)
                case _:
                    pos.append(x)
        rows = f"SELECT {c.key(t, 'r')} AS id FROM {qt(t.table)} r WHERE {c.key_in(t, 'r', ids)}" + "".join(
            f" AND {x}" for x in conds
        )
        if not pos and not neg:
            return f"SELECT x.id, 'anyone'::text AS key, false AS d FROM ({rows}) x"
        if len(pos) == 1 and not neg:
            return self.rows(t, pos[0], rows, loc)
        if not pos:
            pos = [Cond(KEYWORDS["anyone"])]
        n = self.st.next()
        i = f"i{n}"
        ps = [f"p{n}_{k}" for k in range(len(pos))]
        ns = [f"n{n}_{k}" for k in range(len(neg))]
        ctes = [f"{i} AS MATERIALIZED ({rows})"]
        ctes += [
            f"{p} AS MATERIALIZED ({self.rows(t, x, f'SELECT id FROM {i}', loc)})" for p, x in zip(ps, pos, strict=True)
        ]
        ctes += [
            f"{m} AS MATERIALIZED ({self.rows(t, x, f'SELECT id FROM {i}', loc)})" for m, x in zip(ns, neg, strict=True)
        ]

        def has(part: str, on: str, anyone: bool = False) -> str:
            return f"EXISTS (SELECT 1 FROM {part} y WHERE y.id = {on} AND NOT y.d" + (
                " AND y.key = 'anyone')" if anyone else ")"
            )

        lacking = " + ".join(f"(CASE WHEN {has(p, f'{i}.id', True)} THEN 0 ELSE 1 END)" for p in ps)
        ctes.append(
            f"s{n} AS MATERIALIZED (SELECT {i}.id FROM {i} WHERE "
            + " AND ".join([f"NOT {has(m, f'{i}.id')}" for m in ns] + [f"{lacking} <= 1"])
            + ")"
        )
        ctes.append(
            f"e{n} AS MATERIALIZED (SELECT {i}.id FROM {i} WHERE {i}.id NOT IN (SELECT id FROM s{n}) AND "
            + " AND ".join(has(p, f"{i}.id") for p in ps)
            + ")"
        )
        outs = [
            f"SELECT x.id, x.key, false AS d FROM {p} x JOIN s{n} s ON s.id = x.id WHERE NOT x.d "
            f"AND NOT {has(p, 'x.id', True)}"
            for p in ps
        ]
        outs.append(
            f"SELECT s.id, 'anyone'::text AS key, false AS d FROM s{n} s WHERE "
            + " AND ".join(has(p, "s.id", True) for p in ps)
        )

        def expand(part: str) -> str:
            return (
                f"SELECT x.id, k.principal_type || ':' || k.principal_id AS key FROM {part} x "
                f"JOIN e{n} e ON e.id = x.id JOIN authz_sync.keys k ON k.key = x.key WHERE NOT x.d"
            )

        z = " INTERSECT ".join(f"({expand(p)})" for p in ps) + "".join(f" EXCEPT ({expand(m)})" for m in ns)
        outs.append(f"SELECT z.id, z.key, false AS d FROM ({z}) z")
        outs += [
            f"SELECT x.id, x.key, true AS d FROM {part} x WHERE x.d OR x.id IN (SELECT id FROM e{n})"
            for part in ps + ns
        ]
        return wrap(f"WITH {', '.join(ctes)}\n  " + union(outs))


def wrap(sql: str) -> str:
    """A query with a WITH of its own, as a part of another (a query's WITH can't be followed by another's)."""
    return f"SELECT w.id, w.key, w.d FROM ({sql}) w"


# a share counts from its start until its end, and through sync only without a caveat (one is checked at each request)
LIVE = (
    "(g.expires_at IS NULL OR g.expires_at > now()) AND (g.starts_at IS NULL OR g.starts_at <= now()) "
    "AND g.caveat IS NULL"
)

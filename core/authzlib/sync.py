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

Keyed by a type's inheritance (`sync app.files : view by folder`), the readers name an object's key for a
permission that inherits (`folder#view:7`), which no principal holds: `inherits(key, source)` says whose own keys it
takes (7 itself, and each folder above it that it inherits from, as the closure table has them) and `given(source,
key)` what each of those gives itself, before inheritance. The engines' filter joins through them (sync_filter_sql),
so a principal holds its groups' keys only, a move rewrites inherits (as its closure rows changed), and a share on
a folder one row of given.

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
LOCK_KEYS = "sync#keys"  # the lock row of groups and keys (no type is named so: a type's name holds no #)
LOCK_WORK = "sync#work"  # after commit: the lock row of the worker, one at a time
STRIPES = 4096  # the lock rows of the objects and keys a commit works out: each string's hash, modulo this
# the types whose inheritance a sync line's readers are keyed by (`by folder`), rather than copied in
By = frozenset[str]
NO_BY: By = frozenset()


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
    as src's key type, or text for a composite key and for $text). back the other way: the objects of src that
    dst's objects in $ids (dst's, typed so) read, as text: what a commit that works them out reads, and locks."""

    src: str
    dst: str
    sql: str
    back: str


@dataclass
class SyncState:
    """What sync_build worked out: the functions in the order they are made, and what the commit's work needs."""

    functions: list[str] = field(default_factory=list)
    made: dict[tuple[Name, By], str] = field(default_factory=dict)  # (pair, what it is keyed by) -> its function
    making: list[tuple[Name, By]] = field(default_factory=list)  # being made: one asked for again loops (AZ807)
    edges: list[Edge] = field(default_factory=list)
    groups: dict[Name, None] = field(default_factory=dict)  # keyed pairs a derivation gave the key of
    keyed: dict[Name, None] = field(default_factory=dict)  # pairs keyed by their inheritance (by folder)
    inherits: dict[Name, str] = field(default_factory=dict)  # such a pair -> its function: whose own keys each inherits
    given: dict[Name, str] = field(default_factory=dict)  # a pair whose own keys are a source -> its function
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
        """The sync lines and the sync role, as written (AZ801, AZ802, AZ803, AZ810)."""
        pol = self.pol
        if pol.sync_after_commit is not None and not pol.syncs:
            fail(
                pol.sync_after_commit,
                "sync after commit and nothing synced: add a line such as sync app.files : view",
                "AZ802",
            )
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
            if s.by is not None and s.by not in self.types:
                fail(
                    s.loc,
                    f"sync {s.table} ... by {s.by}: there is no type {s.by}. by names the type whose inheritance its "
                    f"readers are keyed by: by folder",
                    "AZ810",
                    span=s.by_span,
                )
            if any(c == "key" for c, _ in t.key):
                fail(
                    s.loc,
                    f"sync {s.table}: its readers table has a column `key`, so the type's key column can't be "
                    f"called key too",
                    "AZ801",
                    span=s.table_span,
                )
            if s.mirrored and s.by is not None:
                fail(
                    s.loc,
                    f"sync {s.table} ... by {s.by} mirrored: a mirror's readers are the keys each row is read by, and "
                    f"keyed by {s.by} they would be {s.by}'s keys, a PowerSync bucket for each: mirror the line without by",
                    "AZ811",
                    span=s.mirrored_span,
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
            st.tops[t.name] = Deriver(self, st, frozenset({s.by}) if s.by else NO_BY, s).top(t, self.sync_expr(s), s)
        # keyed by inheritance: whose own keys each object inherits, and what each gives itself
        for pair in list(st.keyed):
            d.inheritance(pair)
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

    def sync_inherit_types(self) -> list[str]:
        """The types keyed by their inheritance, or whose own keys such a type inherits (given, inherits)."""
        st = self.sync_build()
        return sorted({p[0] for p in st.given} | {p[0] for p in st.inherits})

    def sync_relevant(self) -> list[str]:
        """The types whose changes may change the index: synced, groups, principals, and what they read."""
        st = self.sync_build()
        out = set(st.tops) | set(self.sync_group_types()) | {t.name for t in self.sync_principals()}
        out |= set(self.sync_inherit_types()) | {e.src for e in st.edges}
        return sorted(out)

    def sync_hash(self) -> str:
        """What the index is worked out by (line numbers aside): its functions, the keys' (a principal type's where),
        and the closure tables they read: a kept one by its definition's hash, one always rebuilt by its SQL."""
        st = self.sync_build()
        trees = dict(zip(self.tree_names, self.tree_sql, strict=True))
        text = "\n".join(
            [
                "after commit" if self.pol.sync_after_commit is not None else "in the transaction",
                *st.functions,
                *(self.keys_fn_sql(t) for t in self.sync_principals()),
                *(f"{n} {self.tree_keep[n][0] if n in self.tree_keep else trees[n]}" for n in sorted(st.trees)),
            ]
        )
        return hashlib.sha256(re.sub(r"\bline \d+", "line", text).encode()).hexdigest()[:32]

    # --- the SQL applying makes --------------------------------------------------------------------------
    def readers_table(self, t: Type) -> str:
        return f"authz_sync.{q(t.name + '__readers')}"

    # --- PowerSync's mirrors (`mirrored`): the table's rows, but the masked columns, with each row's readers --------
    def mirrored(self) -> list[tuple[Sync, Type]]:
        return [(s, self.sync_type(s)) for s in self.pol.syncs.values() if s.mirrored]

    def mirror_table(self, t: Type) -> str:
        return f"authz_sync.{q(t.name + '__mirror')}"

    def masked_of(self, table: str) -> list[str]:
        return [c for r in self.rules if r.table == table and r.command == "mask" for c in r.columns]

    def mirror_readers_sql(self, t: Type, row: str) -> str:
        """A row's readers, as the mirror keeps them: a JSON array of its keys, in order (text, which json_each reads)."""
        on = " AND ".join(f"r.{q(c)} = {row}.{q(c)}" for c, _ in t.key)
        return (
            f"(SELECT coalesce(pg_catalog.json_agg(r.key ORDER BY r.key), '[]')::text FROM {self.readers_table(t)} r "
            f"WHERE {on})"
        )

    def mirror_rows_sql(self, t: Type, source: str, row: str) -> str:
        """The mirror's rows for the rows of source (as row): every column the mirror has, taken by name (so a masked
        column, which it hasn't, is left), and the readers."""
        mt = self.mirror_table(t)
        return (
            f"SELECT (pg_catalog.jsonb_populate_record(NULL::{mt}, pg_catalog.to_jsonb({row}) || "
            f"pg_catalog.jsonb_build_object('readers', {self.mirror_readers_sql(t, row)}))).* FROM {source} {row}"
        )

    def mirror_columns_sql(self, s: Sync, rel: str, mirror: bool = False) -> str:
        """The columns of rel, as `name type`, but the masked (and, of a mirror, its readers): the table's now are
        those its mirror should have."""
        masked = (
            "ARRAY["
            + ", ".join(lit(c) for c in [*self.masked_of(s.table), *(["readers"] if mirror else [])])
            + "]::name[]"
        )
        return (
            "(SELECT pg_catalog.array_agg(a.attname || ' ' || pg_catalog.format_type(a.atttypid, a.atttypmod) "
            f"ORDER BY a.attnum) FROM pg_catalog.pg_attribute a WHERE a.attrelid = {rel} AND a.attnum > 0 "
            f"AND NOT a.attisdropped AND a.attname <> ALL ({masked}))"
        )

    def mirror_base_sql(self, s: Sync, t: Type) -> str:
        """PowerSync's mirror of a table: made from the table's columns when it isn't there or they changed, and filled."""
        mt = self.mirror_table(t)
        tbl = qt(s.table)
        drops = "".join(f"\n    ALTER TABLE {mt} DROP COLUMN {q(c)};" for c in self.masked_of(s.table))
        pk = ", ".join(q(c) for c, _ in t.key)
        have = self.mirror_columns_sql(s, f"to_regclass({lit(mt)})", mirror=True)
        return f"""-- PowerSync's mirror of {s.table} (mirrored): every column of the table but those the policy masks, and readers, a
-- JSON array of the keys that may read the row, which a stream's buckets are keyed by. Kept across applies; made
-- again when the table's columns changed
-- @object table {mt}
DO $mi$
DECLARE c name;
BEGIN
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_attribute a WHERE a.attrelid = {lit(tbl)}::regclass AND a.attname = 'readers'
             AND a.attnum > 0 AND NOT a.attisdropped) THEN
    RAISE EXCEPTION '{s.table} has a column readers, which its mirror keeps each row''s keys in [AZ811]'
      USING HINT = 'rename the column, or sync the table without mirrored: rowstile help AZ811';
  END IF;
  IF to_regclass({lit(mt)}) IS NOT NULL AND {have} IS DISTINCT FROM {self.mirror_columns_sql(s, f"{lit(tbl)}::regclass")} THEN
    DROP TABLE {mt};
  END IF;
  IF to_regclass({lit(mt)}) IS NULL THEN
    CREATE TABLE {mt} (LIKE {tbl});{drops}
    -- (any column may be NULL but the key's: one dropped from the table since gives its rows NULL, not an error)
    FOR c IN SELECT a.attname FROM pg_catalog.pg_attribute a WHERE a.attrelid = {lit(mt)}::regclass AND a.attnum > 0
               AND NOT a.attisdropped AND a.attnotnull AND a.attname <> ALL (ARRAY[{", ".join(lit(c) for c, _ in t.key)}]::name[]) LOOP
      EXECUTE pg_catalog.format('ALTER TABLE %s ALTER COLUMN %I DROP NOT NULL', {lit(mt)}, c);
    END LOOP;
    ALTER TABLE {mt} ADD COLUMN readers text NOT NULL DEFAULT '[]', ADD PRIMARY KEY ({pk}), REPLICA IDENTITY FULL;
    INSERT INTO {mt} {self.mirror_rows_sql(t, tbl, "f")};
  END IF;
END $mi$;"""

    def mirror_functions_sql(self, s: Sync, t: Type) -> str:
        """What keeps a mirror: statement triggers on the table (as the rows are written: an update is its old rows'
        delete and its new rows' insert, which also follows a row an update puts in another partition) and on its
        readers table (as the index writes them)."""
        mt = self.mirror_table(t)
        tbl = qt(s.table)
        fn = f"authz_int.{q(t.name + '__mirror')}"
        fn_readers = f"authz_int.{q(t.name + '__mirror_readers')}"
        on_old = " AND ".join(f"m.{q(c)} = o.{q(c)}" for c, _ in t.key)
        cols = ", ".join(f"m.{q(c)}" for c, _ in t.key)
        xcols = ", ".join(f"x.{q(c)}" for c, _ in t.key)
        row = f"({cols})" if len(t.key) > 1 else cols

        def trig(what: str) -> str:
            return q(f"authz_{t.name}_mirror_{what}")

        def readers_trig(what: str) -> str:
            return q(f"{t.name}_mirror_readers_{what}")

        return f"""-- PowerSync's mirror of {s.table}, kept as its rows are written ...
CREATE FUNCTION {fn}() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $f$
BEGIN
  IF TG_OP = 'TRUNCATE' THEN
    DELETE FROM {mt};
    RETURN NULL;
  END IF;
  IF TG_OP IN ('UPDATE', 'DELETE') THEN
    DELETE FROM {mt} m USING old_rows o WHERE {on_old};
  END IF;
  IF TG_OP IN ('INSERT', 'UPDATE') THEN
    INSERT INTO {mt} {self.mirror_rows_sql(t, "new_rows", "n")};
  END IF;
  RETURN NULL;
END $f$;
CREATE TRIGGER {trig("ins")} AFTER INSERT ON {tbl}
  REFERENCING NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION {fn}();
CREATE TRIGGER {trig("upd")} AFTER UPDATE ON {tbl}
  REFERENCING OLD TABLE AS old_rows NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION {fn}();
CREATE TRIGGER {trig("del")} AFTER DELETE ON {tbl}
  REFERENCING OLD TABLE AS old_rows FOR EACH STATEMENT EXECUTE FUNCTION {fn}();
CREATE TRIGGER {trig("trunc")} AFTER TRUNCATE ON {tbl}
  FOR EACH STATEMENT EXECUTE FUNCTION {fn}();
-- ... and as the index writes the rows' readers
CREATE FUNCTION {fn_readers}() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $f$
BEGIN
  UPDATE {mt} m SET readers = {self.mirror_readers_sql(t, "m")}
  WHERE {row} IN (SELECT {xcols} FROM changed_rows x);
  RETURN NULL;
END $f$;
CREATE TRIGGER {readers_trig("ins")} AFTER INSERT ON {self.readers_table(t)}
  REFERENCING NEW TABLE AS changed_rows FOR EACH STATEMENT EXECUTE FUNCTION {fn_readers}();
CREATE TRIGGER {readers_trig("del")} AFTER DELETE ON {self.readers_table(t)}
  REFERENCING OLD TABLE AS changed_rows FOR EACH STATEMENT EXECUTE FUNCTION {fn_readers}();"""

    def sync_base_sql(self) -> str:
        """authz_sync and its tables, kept across applies (CREATE ... IF NOT EXISTS): a table this policy no longer
        keeps goes, and so does a readers table whose key columns changed."""
        st = self.sync_build()
        synced = [self.T(n) for n in st.tops]
        want = (
            [
                ("keys", ["principal_type", "principal_id", "key"], ["text"] * 3),
                ("groups", ["grp", "key"], ["text"] * 2),
                ("expanded", ["object_type", "object_id", "key"], ["text"] * 3),
                ("definitions", ["name", "hash"], ["text"] * 2),
            ]
            + (
                [("pending", ["id", "at", "type", "ids"], ["bigint", "timestamp with time zone", "text", "text[]"])]
                if self.pol.sync_after_commit is not None
                else []
            )
            + (
                [("inherits", ["key", "source"], ["text"] * 2), ("given", ["source", "key"], ["text"] * 2)]
                if st.keyed
                else []
            )
            + [
                (t.name + "__readers", [c for c, _ in t.key] + ["key"], [ty for _, ty in t.key] + ["text"])
                for t in synced
            ]
        )
        # (a mirror's columns are its table's: its own block below checks them)
        mirrors = [t.name + "__mirror" for _, t in self.mirrored()]
        rows = ",\n             ".join(
            [
                f"({lit(ident(n))}, ARRAY[{', '.join(lit(c) for c in cs)}]::name[], "
                f"ARRAY[{', '.join(lit(ty) for ty in tys)}]::regtype[])"
                for n, cs, tys in want
            ]
            + [f"({lit(ident(n))}, NULL::name[], NULL::regtype[])" for n in mirrors]
        )
        pending = (
            """
-- after commit: the objects each committed change reached, which authz.sync_work() works into the index
CREATE TABLE IF NOT EXISTS authz_sync.pending (id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  at timestamptz NOT NULL DEFAULT clock_timestamp(), type text NOT NULL, ids text[] NOT NULL);
ALTER TABLE authz_sync.pending REPLICA IDENTITY FULL;"""
            if self.pol.sync_after_commit is not None
            else ""
        )
        inherit = (
            """
-- keyed by inheritance (by folder): for each key of a permission that inherits (folder#view:7), the objects whose own
-- keys it takes (7 itself, and each one above it it inherits from: folder#view:3) ...
CREATE TABLE IF NOT EXISTS authz_sync.inherits (key text NOT NULL, source text NOT NULL, PRIMARY KEY (key, source));
CREATE INDEX IF NOT EXISTS inherits_by_source ON authz_sync.inherits (source);
ALTER TABLE authz_sync.inherits REPLICA IDENTITY FULL;
-- ... and the keys each of those gives itself, before what it inherits (folder#view:3: user:5, team#member:4)
CREATE TABLE IF NOT EXISTS authz_sync.given (source text NOT NULL, key text NOT NULL, PRIMARY KEY (source, key));
CREATE INDEX IF NOT EXISTS given_by_key ON authz_sync.given (key);
ALTER TABLE authz_sync.given REPLICA IDENTITY FULL;"""
            if st.keyed
            else ""
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
                  OR w.cols IS NOT NULL AND (
                    (SELECT array_agg(a.attname ORDER BY a.attnum) FROM pg_catalog.pg_attribute a
                     WHERE a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped) IS DISTINCT FROM w.cols
                    OR (SELECT array_agg(a.atttypid::regtype ORDER BY a.attnum) FROM pg_catalog.pg_attribute a
                        WHERE a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped) IS DISTINCT FROM w.types)) LOOP
    EXECUTE format('DROP TABLE %s', r.tbl);
  END LOOP;
  -- a table missing (dropped since, or just now): what the index holds is worked out again (sync_refresh)
  IF to_regclass('authz_sync.definitions') IS NOT NULL AND EXISTS (
       SELECT 1 FROM (VALUES {rows}) w(name, cols, types)
       WHERE w.cols IS NOT NULL AND to_regclass(pg_catalog.format('authz_sync.%I', w.name)) IS NULL) THEN
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
ALTER TABLE authz_sync.definitions REPLICA IDENTITY FULL;{pending}{inherit}
{chr(10).join(tables)}{"".join(chr(10) + self.mirror_base_sql(s, t) for s, t in self.mirrored())}
REVOKE ALL ON ALL TABLES IN SCHEMA authz_sync FROM PUBLIC;"""

    def sync_capture_sql(self) -> str:
        """What a transaction changed, noted by authz_int.changed() (sync_dirty). In the same transaction (the
        default), worked on at its commit, once: a row of sync_queued queues its deferred constraint trigger (deleted
        then, so a write after SET CONSTRAINTS ALL IMMEDIATE queues it again). After commit (`sync after commit`),
        noted in authz_sync.pending, which commits with the change and which authz.sync_work() works through."""
        relevant = "ARRAY[" + ", ".join(lit(n) for n in self.sync_relevant()) + "]::text[]"
        st = self.sync_build()
        after = self.pol.sync_after_commit is not None
        locks = [LOCK_KEYS] + ([LOCK_WORK] if after else [])
        head = f"""-- The sync index: the objects each transaction changed, worked on when it commits{" (after commit: by a worker)" if after else ""}
CREATE UNLOGGED TABLE authz_int.sync_todo (txid bigint NOT NULL, type text NOT NULL, id text NOT NULL,
  round int NOT NULL DEFAULT 0, PRIMARY KEY (txid, type, id));
CREATE INDEX ON authz_int.sync_todo (txid, type, round);
-- the groups' rows a commit wrote (made) or took away, which the keys follow
CREATE UNLOGGED TABLE authz_int.sync_moved (txid bigint NOT NULL, grp text NOT NULL, key text NOT NULL, made boolean NOT NULL);
CREATE INDEX ON authz_int.sync_moved (txid, made);
-- the keys a principal may lose, until what is left gives them again (sync_process)
CREATE UNLOGGED TABLE authz_int.sync_lost (txid bigint NOT NULL, ptype text NOT NULL, pid text NOT NULL, key text NOT NULL,
  PRIMARY KEY (txid, ptype, pid, key));
-- ... and those found given again, by the round they were found in
CREATE UNLOGGED TABLE authz_int.sync_found (txid bigint NOT NULL, ptype text NOT NULL, pid text NOT NULL, key text NOT NULL,
  round int NOT NULL);
CREATE INDEX ON authz_int.sync_found (txid, round);
INSERT INTO authz_int.locks VALUES {", ".join(f"({lit(x)}, 0)" for x in locks)} ON CONFLICT DO NOTHING;"""
        if after:
            return f"""{head}
CREATE FUNCTION authz_int.sync_dirty(p_type text, p_ids text[]) RETURNS void
LANGUAGE plpgsql {DEF} AS $f$
BEGIN
  IF coalesce(cardinality(p_ids), 0) = 0 OR p_type <> ALL ({relevant}) THEN RETURN; END IF;
  INSERT INTO authz_sync.pending (type, ids)
  SELECT p_type, ARRAY(SELECT DISTINCT x FROM unnest(p_ids) x WHERE x IS NOT NULL);
END $f$;"""
        stripes = (
            ""
            if st.expanding
            else f"""
-- the lock rows of what a commit works out, by the hash of each object and key: writers whose work meets queue on
-- them, the others go on (sync_process). Each is updated, to the same row: in REPEATABLE READ, a writer whose
-- snapshot is older than another's update of it gets a serialization error
CREATE TABLE authz_int.sync_stripes (stripe int PRIMARY KEY, n bigint NOT NULL);
INSERT INTO authz_int.sync_stripes SELECT s, 0 FROM generate_series(0, {STRIPES - 1}) s;"""
        )
        return f"""{head}{stripes}
CREATE UNLOGGED TABLE authz_int.sync_queued (txid bigint PRIMARY KEY);
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
            f"FROM {st.made[(g, NO_BY)]}({self.typed(u, ids)}) f WHERE NOT f.o_dep"
        )

    def readers_rows_sql(self, t: Type, ids: str) -> str:
        st = self.sync_build()
        return f"SELECT f.o_id, f.o_key, f.o_dep FROM {st.tops[t.name]}({self.typed(t, ids)}) f"

    def inherit_ids_sql(self, u: Type) -> str:
        """Every id of u whose given or inherits rows may be held (text): its rows, those its link tables and shares
        name (a share gives keys before its object has a row), and those the index holds now."""
        st = self.sync_build()
        parts = [f"SELECT {self.key_text(u, 'x')} FROM {qt(u.table)} x"]
        for r in u.relations.values():
            for src in r.sources:
                if src.kind == "table":
                    parts.append(f"SELECT {self.ref_text(u, 'x', src.obj_col)} FROM {qt(src.table)} x")
        parts.append(f"SELECT g.object_id FROM authz.shares g WHERE g.object_type = {lit(u.name)}")
        heads = ", ".join(lit(f"{p[0]}#{p[1]}:") for p in dict.fromkeys([*st.given, *st.inherits]) if p[0] == u.name)
        for table, col in (("given", "source"), ("inherits", "key")):
            parts.append(
                f"SELECT substr(x.{col}, strpos(x.{col}, ':') + 1) FROM authz_sync.{table} x "
                f"WHERE left(x.{col}, strpos(x.{col}, ':')) = ANY (ARRAY[{heads}]::text[])"
            )
        return " UNION ".join(dict.fromkeys(parts))

    def given_rows_sql(self, p: Name, ids: str) -> str:
        """(source, key) of what the objects of p's type in ids (text[]) give themselves of p."""
        st = self.sync_build()
        return (
            f"SELECT {lit(f'{p[0]}#{p[1]}:')} || f.o_id::text AS source, f.o_key AS key "
            f"FROM {st.given[p]}({self.typed(self.T(p[0]), ids)}) f"
        )

    def inherits_rows_sql(self, p: Name, ids: str) -> str:
        """(key, source) of whose own keys the objects of p's type in ids (text[]) inherit p from."""
        st = self.sync_build()
        return (
            f"SELECT {lit(f'{p[0]}#{p[1]}:')} || f.o_id::text AS key, f.o_source AS source "
            f"FROM {st.inherits[p]}({self.typed(self.T(p[0]), ids)}) f"
        )

    def inherit_sql(self) -> str:
        """sync_process's part for what is keyed by inheritance: for the objects a transaction reached, what each gives
        itself (given) and whose own keys each inherits (inherits), by difference. Neither reads the keys."""
        st = self.sync_build()
        out = []
        for n in self.sync_inherit_types():
            u = self.T(n)
            body = []
            for table, cols, pairs, rows in (
                ("given", ("source", "key"), st.given, self.given_rows_sql),
                ("inherits", ("key", "source"), st.inherits, self.inherits_rows_sql),
            ):
                a, b = cols
                for p in pairs:
                    if p[0] != n:
                        continue
                    body.append(
                        f"""    WITH fresh AS MATERIALIZED ({rows(p, "v_part")}),
    gone AS (DELETE FROM authz_sync.{table} x WHERE x.{a} IN (SELECT {lit(f"{p[0]}#{p[1]}:")} || v FROM unnest(v_part) v)
             AND NOT EXISTS (SELECT 1 FROM fresh f WHERE f.{a} = x.{a} AND f.{b} = x.{b}) RETURNING 1),
    made AS (INSERT INTO authz_sync.{table} SELECT f.{a}, f.{b} FROM fresh f ON CONFLICT DO NOTHING RETURNING 1)
    SELECT count(*) INTO v_n FROM (SELECT 1 FROM gone UNION ALL SELECT 1 FROM made) z;"""
                    )
            out.append(
                f"  -- {n}: what each gives itself, and whose own keys each inherits (keyed by inheritance)\n"
                f"  v_ids := {self.todo_ids(u, self.inherit_ids_sql(u))};\n"
                f"  FOR v_from IN 1 .. coalesce(cardinality(v_ids), 0) BY {BATCH} LOOP\n"
                f"    v_part := v_ids[v_from : v_from + {BATCH - 1}];\n" + "\n".join(body) + "\n  END LOOP;"
            )
        return "\n".join(out)

    def sync_filter_sql(self, t: Type, principal: Type, pid: str) -> str:
        """The engines' filter of a synced type's rows for a principal (pid: SQL of its id, as text): those whose readers
        hold a key it holds, or, keyed by inheritance, a key that inherits from an object that gives it one."""
        st = self.sync_build()
        cols = ", ".join(q(c) for c, _ in t.key)
        row = cols if len(t.key) == 1 else f"({cols})"
        held = (
            f"(SELECT {q('key')} FROM authz_sync.{q('keys')} WHERE {q('principal_type')} = {lit(principal.name)} "
            f"AND {q('principal_id')} = {pid})"
        )
        line = {self.sync_type(s).name: s for s in self.pol.syncs.values()}[t.name]
        inherited = (
            f" OR {q('key')} IN (SELECT {q('key')} FROM authz_sync.{q('inherits')} WHERE {q('source')} IN "
            f"(SELECT {q('source')} FROM authz_sync.{q('given')} WHERE {q('key')} IN {held}))"
            if line.by is not None and st.keyed
            else ""
        )
        return f"{row} IN (SELECT {cols} FROM {self.readers_table(t)} WHERE {q('key')} IN {held}{inherited})"

    def spread_sql(self) -> str:
        """authz_int.sync_spread(tx, round): what reads the objects a transaction reached in a round (Edge), added as
        the next round, until no round finds any; returns the last. Everything of a type reaches everything of
        what reads it. Run again from round 0, it adds what a change committed since makes them reach."""
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
    EXIT WHEN n = 0 AND NOT EXISTS (SELECT 1 FROM authz_int.sync_todo x WHERE x.txid = p_tx AND x.round > r);
    r := r + 1;
  END LOOP;
  RETURN r;
END $f$;"""

    def read_sql(self) -> str:
        """The objects a commit's work reads besides those it works out (each edge back from them): their folders
        above, what they link to, as type:id."""
        st = self.sync_build()
        parts = []
        for e in st.edges:
            d = self.T(e.dst)
            text = (
                f"ARRAY(SELECT x.id FROM authz_int.sync_todo x WHERE x.txid = v_tx AND x.type = {lit(e.dst)} "
                f"AND x.id <> '*')"
            )
            sql = e.back.replace("$ids", self.typed(d, text)).replace("$text", text)
            parts.append(f"SELECT {lit(e.src + ':')} || v.id FROM ({sql}) v(id)")
        return "\n                        UNION ".join(parts) if parts else "SELECT NULL::text WHERE false"

    def locks_sql(self) -> str:
        """The locks the commit's work takes before it reads anything, so that two writers whose work meets queue,
        and the others don't wait for each other."""
        st = self.sync_build()
        if self.pol.sync_after_commit is not None:
            return (
                "  -- (after commit: one worker at a time, under the lock its caller holds: authz.sync_work, sync_refresh)\n"
                "  v_round := authz_int.sync_spread(v_tx, 0);"
            )
        if st.expanding:
            # the readers of an `and` / `not` between parts that depend on who asks are principals, worked out from
            # the keys: every commit's work reads the keys, so one lock covers it
            return (
                "  -- one lock row for every commit's work: what an `and` or `not` between parts that depend on who asks\n"
                "  -- gives is worked out from the keys, which any change may move. In REPEATABLE READ or SERIALIZABLE, a\n"
                "  -- writer whose snapshot is older than another's index write gets a serialization error\n"
                f"  UPDATE authz_int.locks SET n = n + 1 WHERE type = {lit(LOCK_KEYS)};\n"
                "  v_keys_locked := true;\n"
                "  v_round := authz_int.sync_spread(v_tx, 0);"
            )
        return f"""  IF current_setting('transaction_isolation') IN ('repeatable read', 'serializable') THEN
    -- a snapshot older than another's index write: a serialization error, rather than readers worked out from
    -- what it can't see
    PERFORM 1 FROM authz_int.sync_stripes s ORDER BY s.stripe FOR UPDATE;
    UPDATE authz_int.sync_stripes SET n = n;
    v_round := authz_int.sync_spread(v_tx, 0);
  ELSE
    -- READ COMMITTED: the lock rows of what the work writes (what changed, and what reads it), and, shared, of what
    -- it reads (the folders above, what they link to), in one order. A writer whose work meets this one's waits for
    -- it, then sees what it committed; once they are held, what reads the changes is looked for again, and the lock
    -- rows of anything new are taken too, until there is none
    v_mode := array_fill(0, ARRAY[{STRIPES}]);
    LOOP
      v_round := authz_int.sync_spread(v_tx, 0);
      IF EXISTS (SELECT 1 FROM authz_int.sync_todo x WHERE x.txid = v_tx AND x.id = '*') THEN
        v_w := ARRAY(SELECT generate_series(0, {STRIPES - 1}));
        v_r := '{{}}';
      ELSE
        v_w := ARRAY(SELECT DISTINCT pg_catalog.hashtext(x.type || ':' || x.id) & {STRIPES - 1}
                     FROM authz_int.sync_todo x WHERE x.txid = v_tx);
        v_r := ARRAY(SELECT DISTINCT pg_catalog.hashtext(d.k) & {STRIPES - 1} FROM (
                        {self.read_sql()}) d(k) WHERE d.k IS NOT NULL);
      END IF;
      v_n := 0;
      FOR v_s, v_x IN SELECT z.s, bool_or(z.x) FROM (SELECT unnest(v_w) AS s, true AS x UNION ALL SELECT unnest(v_r), false) z
                      GROUP BY z.s ORDER BY z.s LOOP
        CONTINUE WHEN v_mode[v_s + 1] = 2 OR (NOT v_x AND v_mode[v_s + 1] = 1);
        IF v_x THEN
          UPDATE authz_int.sync_stripes SET n = n WHERE stripe = v_s;
          v_mode[v_s + 1] := 2;
        ELSE
          PERFORM 1 FROM authz_int.sync_stripes WHERE stripe = v_s FOR SHARE;
          v_mode[v_s + 1] := 1;
        END IF;
        v_n := v_n + 1;
      END LOOP;
      EXIT WHEN v_n = 0;
    END LOOP;
  END IF;"""

    def process_sql(self) -> str:
        """authz_int.sync_process(): the index made current for what a transaction changed (at its commit, or the
        worker's after it)."""
        st = self.sync_build()
        expanding = bool(st.expanding)
        groups = []
        for u in self.sync_group_types():
            ut = self.T(u)
            pairs = [g for g in st.groups if g[0] == u]
            body = []
            for g in pairs:
                body.append(
                    f"""      WITH fresh AS MATERIALIZED ({self.group_rows_sql(g, "v_part")}),
      gone AS (DELETE FROM authz_sync.groups g WHERE g.grp IN (SELECT {lit(f"{g[0]}#{g[1]}:")} || v FROM unnest(v_part) v)
               AND NOT EXISTS (SELECT 1 FROM fresh f WHERE f.grp = g.grp AND f.key = g.key) RETURNING g.grp, g.key),
      made AS (INSERT INTO authz_sync.groups SELECT f.grp, f.key FROM fresh f ON CONFLICT DO NOTHING RETURNING grp, key)
      INSERT INTO authz_int.sync_moved SELECT v_tx, z.grp, z.key, z.made
      FROM (SELECT grp, key, false AS made FROM gone UNION ALL SELECT grp, key, true FROM made) z
      WHERE NOT v_all;"""
                )
            groups.append(
                f"  -- {u}'s groups\n  v_ids := {self.todo_ids(ut, self.group_all_ids_sql(ut))};\n"
                f"  FOR v_from IN 1 .. coalesce(cardinality(v_ids), 0) BY {BATCH} LOOP\n"
                f"    v_part := v_ids[v_from : v_from + {BATCH - 1}];\n" + "\n".join(body) + "\n  END LOOP;"
            )
        principals = self.sync_principals()
        types = "ARRAY[" + ", ".join(lit(t.name) for t in principals) + "]::text[]"
        keys = []
        for t in principals:
            pk = q(self.pk(t))
            where = f" AND coalesce(({on_row(t.where, 'x')}), false)" if t.where else ""
            keys.append(
                f"""    -- the principals of {t.name}: every one worked out whole (applying), or those that changed: one who is
    -- nobody now (gone, or failing the type's where) holds no key, and one who is somebody now and held none gets theirs
    IF EXISTS (SELECT 1 FROM authz_int.sync_todo x WHERE x.txid = v_tx AND x.type = {lit(t.name)} AND x.id = '*') THEN
      v_whole := v_whole || {lit(t.name)}::text;
      v_ids := ARRAY({self.principal_ids_sql(t)});
      WITH fresh AS MATERIALIZED (SELECT * FROM {self.keys_fn(t)}(v_ids)),
      gone AS (DELETE FROM authz_sync.keys k WHERE k.principal_type = {lit(t.name)} AND k.principal_id IN (SELECT unnest(v_ids))
               AND NOT EXISTS (SELECT 1 FROM fresh f WHERE f.o_id = k.principal_id AND f.o_key = k.key) RETURNING k.key),
      made AS (INSERT INTO authz_sync.keys SELECT {lit(t.name)}, f.o_id, f.o_key FROM fresh f ON CONFLICT DO NOTHING RETURNING key)
      SELECT v_keys || coalesce(array_agg(DISTINCT z.k), '{{}}') INTO v_keys FROM (SELECT key FROM gone UNION SELECT key FROM made) z(k);
    ELSE
      v_ids := ARRAY(SELECT x.id FROM authz_int.sync_todo x WHERE x.txid = v_tx AND x.type = {lit(t.name)});
      IF cardinality(v_ids) > 0 THEN
        v_now := ARRAY(SELECT x.{pk}::text FROM {qt(t.table)} x WHERE x.{pk} IN (SELECT unnest({self.typed(t, "v_ids")})){where});
        WITH gone AS (DELETE FROM authz_sync.keys k WHERE k.principal_type = {lit(t.name)} AND k.principal_id = ANY (v_ids)
                      AND k.principal_id <> ALL (v_now) RETURNING k.key)
        SELECT v_keys || coalesce(array_agg(DISTINCT z.key), '{{}}') INTO v_keys FROM gone z;
        v_came := v_came || ARRAY(SELECT {lit(t.name)} || ':' || v FROM unnest(v_now) v WHERE NOT EXISTS (
          SELECT 1 FROM authz_sync.keys k WHERE k.principal_type = {lit(t.name)} AND k.principal_id = v));
      END IF;
    END IF;"""
            )
        came = "\n".join(
            f"""    WITH made AS (INSERT INTO authz_sync.keys SELECT {lit(t.name)}, f.o_id, f.o_key FROM {self.keys_fn(t)}(ARRAY(
                    SELECT substr(c, {len(t.name) + 2}) FROM unnest(v_came) c WHERE left(c, {len(t.name) + 1}) = {lit(t.name + ":")})) f
                  ON CONFLICT DO NOTHING RETURNING key)
    SELECT v_keys || coalesce(array_agg(DISTINCT z.key), '{{}}') INTO v_keys FROM made z;"""
            for t in principals
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
        expanded = (
            """
  -- rows whose readers were worked out from a key someone gained or lost, and what reads them
  IF cardinality(v_keys) > 0 THEN
    INSERT INTO authz_int.sync_todo (txid, type, id, round)
    SELECT DISTINCT v_tx, x.object_type, x.object_id, v_round + 1 FROM authz_sync.expanded x WHERE x.key IN (SELECT unnest(v_keys))
    ON CONFLICT DO NOTHING;
    IF FOUND THEN
      v_round := authz_int.sync_spread(v_tx, v_round + 1);
    END IF;
  END IF;"""
            if expanding
            else ""
        )
        return f"""-- The index made current for the objects a transaction changed and what reads them (the difference written, not
-- every row again): at its commit, in it, or after it, by the worker. The groups first, then the keys (a principal
-- holds the keys of every group whose members hold one of its own, through groups inside groups), then the readers
-- (JIT off: its statements read a few rows each, through indexes, which a plan made for many would compile for; no
-- merge joins: its sets of keys, which the planner can't count, are joined by hash, not sorted as text)
CREATE FUNCTION authz_int.sync_process() RETURNS void
LANGUAGE plpgsql {DEF_CURRENT} SET jit = off SET enable_mergejoin = off AS $f$
DECLARE
  v_tx bigint := txid_current();
  v_round int;
  v_mode int[]; v_w int[]; v_r int[]; v_s int; v_x boolean;
  v_ids text[]; v_part text[]; v_from int; v_now text[];
  v_keys text[] := '{{}}';     -- the keys a principal gained or lost
  v_came text[] := '{{}}';     -- the principals who are somebody now, and held no key (type:id)
  v_whole text[] := '{{}}';    -- the principal types worked out whole
  v_keys_locked boolean := false;
  v_all boolean;               -- every principal's keys worked out whole (applying): the groups' changes aren't followed
  v_n bigint;
  v_found int;
BEGIN
  IF NOT EXISTS (SELECT 1 FROM authz_int.sync_todo x WHERE x.txid = v_tx) THEN RETURN; END IF;
{self.locks_sql()}
  v_all := (SELECT count(DISTINCT x.type) FROM authz_int.sync_todo x WHERE x.txid = v_tx AND x.id = '*'
            AND x.type = ANY ({types})) = {len(principals)};
{chr(10).join(groups)}{chr(10) + self.inherit_sql() if st.keyed else ""}
  -- the keys, where the groups' rows or the principals changed: under one lock row, taken last (nothing after it waits
  -- for another lock)
  IF EXISTS (SELECT 1 FROM authz_int.sync_moved m WHERE m.txid = v_tx)
     OR EXISTS (SELECT 1 FROM authz_int.sync_todo x WHERE x.txid = v_tx AND x.type = ANY ({types})) THEN
    IF NOT v_keys_locked THEN
      UPDATE authz_int.locks SET n = n + 1 WHERE type = {lit(LOCK_KEYS)};
    END IF;
{chr(10).join(keys)}
    -- a group's row gone: the keys above it that its member's holders held may go, unless what is left gives them
    -- again (each found given is taken back from those that may go, as often as it finds more)
    IF EXISTS (SELECT 1 FROM authz_int.sync_moved m WHERE m.txid = v_tx AND NOT m.made) THEN
      WITH RECURSIVE up(src, c) AS (
        SELECT DISTINCT m.key, m.grp FROM authz_int.sync_moved m WHERE m.txid = v_tx AND NOT m.made
        UNION
        SELECT up.src, g.grp FROM up JOIN authz_sync.groups g ON g.key = up.c)
      -- (the holders of each key, a lookup by the keys' index: OFFSET 0 keeps the planner from reading every key for a
      -- few; then the sets joined whole)
      , by_src AS MATERIALIZED (
        SELECT DISTINCT up.c, k.principal_type AS pt, k.principal_id AS pid FROM up
        CROSS JOIN LATERAL (SELECT k.principal_type, k.principal_id FROM authz_sync.keys k WHERE k.key = up.src
                            AND k.principal_type <> ALL (v_whole) OFFSET 0) k),
      by_c AS MATERIALIZED (
        SELECT c.c, h.principal_type AS pt, h.principal_id AS pid FROM (SELECT DISTINCT up.c FROM up) c
        CROSS JOIN LATERAL (SELECT h.principal_type, h.principal_id FROM authz_sync.keys h WHERE h.key = c.c OFFSET 0) h)
      INSERT INTO authz_int.sync_lost (txid, ptype, pid, key)
      SELECT v_tx, s.pt, s.pid, s.c FROM by_src s JOIN by_c h ON h.c = s.c AND h.pt = s.pt AND h.pid = s.pid
      ON CONFLICT DO NOTHING;
      -- given again: by a member it holds that may not go (the holders of the members of the groups that may go, once
      -- each); then, round by round, by a member just found given
      WITH members AS MATERIALIZED (
        SELECT g.grp, g.key FROM (SELECT DISTINCT l.key FROM authz_int.sync_lost l WHERE l.txid = v_tx) c
        CROSS JOIN LATERAL (SELECT g.grp, g.key FROM authz_sync.groups g WHERE g.grp = c.key OFFSET 0) g),
      held AS MATERIALIZED (
        SELECT m.key, h.principal_type AS pt, h.principal_id AS pid FROM (SELECT DISTINCT key FROM members) m
        CROSS JOIN LATERAL (SELECT h.principal_type, h.principal_id FROM authz_sync.keys h WHERE h.key = m.key OFFSET 0) h),
      -- (the groups each holder holds a member of, that may not go; then the candidates they give again)
      supported AS MATERIALIZED (
        SELECT DISTINCT g.grp, h.pt, h.pid FROM members g JOIN held h ON h.key = g.key
        WHERE NOT EXISTS (SELECT 1 FROM authz_int.sync_lost o WHERE o.txid = v_tx AND o.ptype = h.pt AND o.pid = h.pid
                          AND o.key = h.key)),
      given AS (SELECT l.ptype, l.pid, l.key FROM authz_int.sync_lost l
                JOIN supported s ON s.grp = l.key AND s.pt = l.ptype AND s.pid = l.pid WHERE l.txid = v_tx),
      r AS (DELETE FROM authz_int.sync_lost l USING given z WHERE l.txid = v_tx AND l.ptype = z.ptype AND l.pid = z.pid
            AND l.key = z.key RETURNING l.ptype, l.pid, l.key)
      INSERT INTO authz_int.sync_found SELECT v_tx, r.ptype, r.pid, r.key, 1 FROM r;
      GET DIAGNOSTICS v_n = ROW_COUNT;
      v_found := 1;
      WHILE v_n > 0 LOOP
        WITH r AS (DELETE FROM authz_int.sync_lost l
                   USING (SELECT DISTINCT f.ptype, f.pid, g.grp FROM authz_int.sync_found f
                          JOIN authz_sync.groups g ON g.key = f.key WHERE f.txid = v_tx AND f.round = v_found) z
                   WHERE l.txid = v_tx AND l.ptype = z.ptype AND l.pid = z.pid AND l.key = z.grp
                   RETURNING l.ptype, l.pid, l.key)
        INSERT INTO authz_int.sync_found SELECT v_tx, r.ptype, r.pid, r.key, v_found + 1 FROM r;
        GET DIAGNOSTICS v_n = ROW_COUNT;
        v_found := v_found + 1;
      END LOOP;
      DELETE FROM authz_int.sync_found f WHERE f.txid = v_tx;
      WITH gone AS (DELETE FROM authz_sync.keys k USING authz_int.sync_lost l WHERE l.txid = v_tx
                    AND k.principal_type = l.ptype AND k.principal_id = l.pid AND k.key = l.key RETURNING k.key)
      SELECT v_keys || coalesce(array_agg(DISTINCT z.key), '{{}}') INTO v_keys FROM gone z;
      DELETE FROM authz_int.sync_lost l WHERE l.txid = v_tx;
    END IF;
    -- a group's row made: its member's holders hold the group, and the groups above it
    IF EXISTS (SELECT 1 FROM authz_int.sync_moved m WHERE m.txid = v_tx AND m.made) THEN
      WITH RECURSIVE up(src, c) AS (
        SELECT DISTINCT m.key, m.grp FROM authz_int.sync_moved m WHERE m.txid = v_tx AND m.made
        UNION
        SELECT up.src, g.grp FROM up JOIN authz_sync.groups g ON g.key = up.c),
      made AS (INSERT INTO authz_sync.keys SELECT DISTINCT k.principal_type, k.principal_id, up.c FROM up
               CROSS JOIN LATERAL (SELECT k.principal_type, k.principal_id FROM authz_sync.keys k WHERE k.key = up.src
                                   AND k.principal_type <> ALL (v_whole) OFFSET 0) k
               ON CONFLICT DO NOTHING RETURNING key)
      SELECT v_keys || coalesce(array_agg(DISTINCT z.key), '{{}}') INTO v_keys FROM made z;
    END IF;
    DELETE FROM authz_int.sync_moved m WHERE m.txid = v_tx;
    -- the principals who are somebody now: their keys, worked out whole
    IF cardinality(v_came) > 0 THEN
{came}
    END IF;
  END IF;{expanded}
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
        if st.keyed:
            ids_of = {n: f"ARRAY({self.inherit_ids_sql(self.T(n))})" for n in self.sync_inherit_types()}
            out.append(
                (
                    "what each object gives itself",
                    "SELECT source, key FROM authz_sync.given",
                    " UNION ".join(self.given_rows_sql(p, ids_of[p[0]]) for p in st.given),
                )
            )
            out.append(
                (
                    "whose own keys each object inherits",
                    "SELECT key, source FROM authz_sync.inherits",
                    " UNION ".join(self.inherits_rows_sql(p, ids_of[p[0]]) for p in st.inherits),
                )
            )
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

    def mirrors_match_sql(self) -> str:
        """authz_int.sync_mirrors_match(): each mirror has its table's columns (but the masked) and rows, with the
        readers the index holds (false says which differs, in a notice); sync_verify's last answer."""
        checks = "\n".join(
            f"""  IF {self.mirror_columns_sql(s, f"to_regclass({lit(self.mirror_table(t))})", mirror=True)}
       IS DISTINCT FROM {self.mirror_columns_sql(s, f"{lit(qt(s.table))}::regclass")} THEN
    RAISE NOTICE 'the sync index differs from a rebuild: %', {lit(f"{s.table}'s mirror: its columns are not its table's (rowstile reapply makes it again)")};
    RETURN false;
  END IF;
  IF EXISTS (
    WITH s AS MATERIALIZED (SELECT x::text FROM {self.mirror_table(t)} x),
         f AS MATERIALIZED (SELECT x::text FROM ({self.mirror_rows_sql(t, qt(s.table), "f")}) x)
    SELECT 1 FROM ((TABLE s EXCEPT TABLE f) UNION ALL (TABLE f EXCEPT TABLE s)) d) THEN
    RAISE NOTICE 'the sync index differs from a rebuild: %', {lit(f"{s.table}'s mirror")};
    RETURN false;
  END IF;"""
            for s, t in self.mirrored()
        )
        return f"""-- each mirror matches its table's rows, with the readers the index holds
CREATE FUNCTION authz_int.sync_mirrors_match() RETURNS boolean
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, pg_temp AS $f$
BEGIN
{checks}
  RETURN true;
END $f$;"""

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
        # forced (rowstile reapply --force): each mirror written again where it differs from its table's rows and readers
        mirrors = "".join(
            f"""
  IF p_force THEN
    DELETE FROM {self.mirror_table(t)} m WHERE NOT EXISTS (SELECT 1 FROM ({self.mirror_rows_sql(t, qt(s.table), "f")}) x
                                                           WHERE x::text = m::text);
    INSERT INTO {self.mirror_table(t)} SELECT x.* FROM ({self.mirror_rows_sql(t, qt(s.table), "f")}) x
      WHERE NOT EXISTS (SELECT 1 FROM {self.mirror_table(t)} m WHERE m::text = x::text);
  END IF;"""
            for s, t in self.mirrored()
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
        if st.keyed:
            for table, col, pairs in (("given", "source", st.given), ("inherits", "key", st.inherits)):
                heads = ", ".join(lit(f"{p[0]}#{p[1]}:") for p in pairs)
                stale += (
                    f"\n  DELETE FROM authz_sync.{table} x WHERE left(x.{col}, strpos(x.{col}, ':')) <> ALL "
                    f"(ARRAY[{heads}]::text[]);"
                )
        every = sorted(
            set(self.sync_group_types())
            | {t.name for t in self.sync_principals()}
            | set(st.tops)
            | set(self.sync_inherit_types())
        )
        marks = (
            "    INSERT INTO authz_int.sync_todo (txid, type, id) SELECT txid_current(), x, '*' FROM unnest(ARRAY["
            + ", ".join(lit(n) for n in every)
            + "]::text[]) x ON CONFLICT DO NOTHING;"
        )
        after = self.pol.sync_after_commit is not None
        # after commit: what waits is taken (the notes committed so far, as the worker's own to work on)
        take = (
            "  WITH taken AS (DELETE FROM authz_sync.pending p RETURNING p.type, p.ids)\n"
            "  INSERT INTO authz_int.sync_todo (txid, type, id) SELECT DISTINCT txid_current(), t.type, x\n"
            "  FROM taken t, unnest(t.ids) x WHERE x IS NOT NULL ON CONFLICT DO NOTHING;"
        )
        if after:
            refresh_lock = (
                f"  -- (after the worker working now, if one is: one at a time)\n"
                f"  PERFORM 1 FROM authz_int.locks l WHERE l.type = {lit(LOCK_WORK)} FOR UPDATE;\n"
                f"{take}\n"
            )
            work = f"""-- After commit (sync after commit): SELECT authz.sync_work() works the changes committed so far into the index, in
-- its own transaction, and says how many objects changed. Call it in a loop, or schedule it (pg_cron, the app's
-- jobs): the index is as late as its last run. One works at a time: while another does, it does nothing (0). A run
-- that fails or is stopped leaves the changes waiting for the next
CREATE FUNCTION authz.sync_work() RETURNS bigint
LANGUAGE plpgsql {DEF} AS $f$
DECLARE n bigint;
BEGIN
  PERFORM 1 FROM authz_int.locks l WHERE l.type = {lit(LOCK_WORK)} FOR UPDATE SKIP LOCKED;
  IF NOT FOUND THEN RETURN 0; END IF;
{take}
  GET DIAGNOSTICS n = ROW_COUNT;
  PERFORM authz_int.sync_process();
  RETURN n;
END $f$;
-- After commit: how long the oldest change the index doesn't hold yet has waited (NULL: it holds every one committed)
CREATE FUNCTION authz.sync_behind() RETURNS interval
LANGUAGE sql STABLE {DEF} AS $f$
  SELECT clock_timestamp() - min(p.at) FROM authz_sync.pending p
$f$;"""
            behind = """  IF EXISTS (SELECT 1 FROM authz_sync.pending) THEN
    RAISE NOTICE 'the sync index is behind: % changes wait for authz.sync_work()', (SELECT count(*) FROM authz_sync.pending);
    RETURN false;
  END IF;
"""
        else:
            refresh_lock = ""
            work = f"""-- In the same transaction (the default), nothing waits: authz.sync_work() has nothing to do (0), and
-- authz.sync_behind() says the index holds every change committed (NULL). They are for sync after commit
CREATE FUNCTION authz.sync_work() RETURNS bigint
LANGUAGE sql {DEF} AS $f$ SELECT 0::bigint $f$;
CREATE FUNCTION authz.sync_behind() RETURNS interval
LANGUAGE sql STABLE {DEF} AS $f$ SELECT NULL::interval $f$;"""
            behind = ""
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
{refresh_lock}  IF p_force OR NOT EXISTS (SELECT 1 FROM authz_sync.definitions d WHERE d.name = 'index' AND d.hash = p_hash) THEN
    -- what this policy no longer keeps
{stale.replace(chr(10), chr(10) + "  ")}
{marks}
  END IF;
  PERFORM authz_int.sync_process();{mirrors}
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
{behind}{verify}
  RETURN {"authz_int.sync_mirrors_match()" if self.mirrored() else "true"};
END $f$;""",
                work,
                *(self.mirror_functions_sql(s, t) for s, t in self.mirrored()),
                *([self.mirrors_match_sql()] if self.mirrored() else []),
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
  FOR r IN SELECT p.pubname, m.tbl, m.col, c.relreplident = 'f' AS whole FROM authz_int.masked_columns m
           JOIN pg_class c ON c.oid = to_regclass(m.tbl) JOIN pg_namespace n ON n.oid = c.relnamespace
           JOIN pg_publication_tables p ON p.schemaname = n.nspname AND p.tablename = c.relname AND m.col = ANY (p.attnames) LOOP
    severity := 'error'; object := r.tbl || '.' || r.col;
    -- (a column list that leaves out a column of the replica identity makes Postgres refuse the table's updates)
    problem := format('is masked, and the publication %s publishes it: an engine that reads the publication reads it. %s', r.pubname,
      CASE WHEN r.whole THEN 'The table''s replica identity is FULL (Electric asks for it), so a column list must hold every column: keep the column in a table of its own, which isn''t published'
           ELSE 'Give the publication a column list without it' END); RETURN NEXT;
  END LOOP;
"""


class Deriver:
    """Writes the SQL of who holds what, as keys: one function per relation or permission the synced expressions
    reach (fn), returning (o_id, o_key, o_dep) for the ids it is given; o_dep marks a key an expanded row was
    worked out from, not one of its readers."""

    def __init__(self, c: SyncMixin, st: SyncState, by: By = NO_BY, line: Sync | None = None) -> None:
        # by: the types whose inheritance is keyed (`by folder`): a permission of theirs that inherits gives its
        # key (folder#view:7), not the readers of each folder above copied in; line: the sync line saying so
        self.c, self.st, self.by, self.line = c, st, by, line
        self.keyed_by: set[Name] = set()  # the pairs keyed so, so far (or reached under an and / not: copied there)
        self.owner: Deriver | None = None  # under an and / not that expands: the line's deriver, whose by this copies

    def copied(self) -> Deriver:
        """The deriver of the parts of an `and` / `not` between parts that depend on who asks: their readers are
        expanded from the keys, which hold no key of inheritance, so what inherits is copied in there."""
        if not self.by:
            return self
        d = Deriver(self.c, self.st, NO_BY, self.line)
        d.owner = self
        return d

    # --- names and empty answers ---
    def name(self, t: Type, name: str) -> str:
        what = f"sync:{t.name}.{name}" + (f" by {', '.join(sorted(self.by))}" if self.by else "")
        return f"authz_int.{q(what)}"

    def keyed(self, st: str, name: str) -> bool:
        """Whether holding st.name on an object is a key (st#name:10): a group's (keyed), or, keyed by st's
        inheritance, a permission of st that inherits (whose holders inherits and given say: inheritance). Under an
        `and` / `not` that expands (owner set), such a permission is copied in, and only noted as reached."""
        if self.c.keyed(st, name):
            self.st.groups[(st, name)] = None
            return True
        line = self.owner or self
        if st not in line.by or (st, name) not in self.c.recursive:
            return False
        if not self.c.monotone(self.c.T(st), name):
            assert self.line is not None
            fail(
                self.line.loc,
                f"sync {self.line.table} ... by {st}: {st}.{name} inherits, and who holds it joins parts that depend "
                f"on who asks with and / not, so it can't be a key. Leave out by {st}: its readers are then copied in",
                "AZ810",
                span=self.line.by_span,
            )
        line.keyed_by.add((st, name))
        if self.owner is not None:
            return False
        self.st.keyed[(st, name)] = None
        return True

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
        if s.by is not None and not self.keyed_by:
            fail(
                s.loc,
                f"sync {s.table} ... by {s.by}: what its readers hold reaches no permission of {s.by} that inherits "
                f"(as parent.view does), so there is nothing to key them by. Leave out by {s.by}",
                "AZ810",
                span=s.by_span,
            )
        self.st.functions.append(
            f"-- {s.table}: the keys that may read each row ({s.loc})"
            + (f", keyed by {s.by}'s inheritance" if s.by else "")
            + "\n"
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
        if (pair, self.by) in st.made:
            return st.made[(pair, self.by)]
        if (pair, self.by) in st.making:
            fail(
                loc,
                f"{t.name}.{name} is a group in itself, and who holds it joins parts that depend on who asks with "
                f"and / not: the sync index can't work it out as keys. Sync another permission, or say the group "
                f"without and / not",
                "AZ807",
            )
        st.making.append((pair, self.by))
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
        st.making.remove((pair, self.by))
        st.made[(pair, self.by)] = fn
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
                f"SELECT c.ancestor::text FROM authz_int.{q(tree)} c WHERE c.descendant IN (SELECT unnest($ids))",
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
                    f"SELECT c.aid FROM authz_int.{q(tree)} c WHERE c.dtype = {lit(b)} AND c.did IN (SELECT unnest($text)) "
                    f"AND c.atype = {lit(a)}",
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

    def inheritance(self, pair: Name) -> None:
        """A permission keyed by its inheritance (folder#view:7): the function of whose own keys each object takes
        (inherits: each one above it in its closure table, itself among them, by the permission of the recursion
        that starts there), and of each such source, what it gives itself (given: its starting items, those of a
        permission one walk covers written out in place, as recursive_rows reads them; what names another such
        permission is copied in, so that the engines' filter needs no deeper join)."""
        c, st = self.c, self.st
        t = c.T(pair[0])
        perm = t.perms[pair[1]]
        key = c.recursive[pair]
        members = c.scc_members[key]
        edges = c.scc_edges(key)
        where = ""
        if t.where:
            c.sync_cond_ok(t.where, t.loc, f"the where of {t.name}")
            where = f" WHERE {c.where_holds(t, 'x.id')}"
        entry = f"WITH o AS (SELECT DISTINCT x.id FROM unnest(p_ids) x(id){where})"
        sources: list[tuple[Name, list[Expr]]]
        if len(members) == 1:
            tree = c.trees[(t.name, edges)]
            sources = [(pair, c.start_items(t, perm, edges))]
            body = (
                f"SELECT c.descendant AS id, {lit(f'{t.name}#{pair[1]}:')} || c.ancestor::text AS source "
                f"FROM authz_int.{q(tree)} c WHERE c.descendant IN (SELECT id FROM o)"
            )
        else:
            tree = c.trees[key]
            sources = [((tn, pn), c.base_items(c.T(tn), c.T(tn).perms[pn])) for tn, pn in members]
            sources = [(p, items) for p, items in sources if items]
            body = union(
                [
                    f"SELECT c.did::{t.pktype} AS id, {lit(f'{tn}#{pn}:')} || c.aid AS source FROM authz_int.{q(tree)} c "
                    f"WHERE c.dtype = {lit(t.name)} AND c.did IN (SELECT id::text FROM o) AND c.atype = {lit(tn)}"
                    for (tn, pn), _ in sources
                ]
            )
        st.trees[tree] = None
        fn = f"authz_int.{q(f'sync_inherits:{t.name}.{pair[1]}')}"
        st.inherits[pair] = fn
        st.functions.append(
            f"-- {t.name}.{pair[1]} ({perm.loc}): {perm.src}, keyed by its inheritance: whose own keys each object takes\n"
            f"CREATE FUNCTION {fn}(p_ids {t.pktype}[]) RETURNS TABLE (o_id {t.pktype}, o_source text)\n"
            f"LANGUAGE sql STABLE {DEF_CURRENT} AS $f$\n"
            f"  {entry}\n  SELECT DISTINCT r.id, r.source FROM ({body}) r\n$f$;"
        )
        for p, items in sources:
            if p in st.given:
                continue
            mt = c.T(p[0])
            mp = mt.perms[p[1]]
            rows = self.rows(mt, Or(items) if len(items) > 1 else items[0], "SELECT id FROM o", mp.loc)
            gfn = f"authz_int.{q(f'sync_given:{mt.name}.{p[1]}')}"
            st.given[p] = gfn
            st.functions.append(
                f"-- {mt.name}.{p[1]} ({mp.loc}): what each object gives itself, before what it inherits, as keys\n"
                f"CREATE FUNCTION {gfn}(p_ids {mt.pktype}[]) RETURNS TABLE (o_id {mt.pktype}, o_key text)\n"
                f"LANGUAGE sql STABLE {DEF_CURRENT} AS $f$\n"
                f"  SELECT DISTINCT r.id, r.key FROM (\n  WITH o AS (SELECT DISTINCT x.id FROM unnest(p_ids) x(id))\n"
                f"  {rows}) r WHERE NOT r.d\n$f$;"
            )

    # --- dependents ---
    def edge(self, src: str, dst: str, sql: str, back: str) -> None:
        """dst's readers read src's objects through sql, and back (see Edge)."""
        e = Edge(src, dst, sql, back)
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
        their = f"SELECT ({c.subject_id(src, 'x', st)})::text"
        if src.kind == "column":
            self.edge(
                st,
                t.name,
                f"SELECT {c.key_text(t, 'x')} FROM {qt(t.table)} x WHERE {match}",
                f"{their} FROM {qt(t.table)} x WHERE {c.key_in(t, 'x', 'SELECT unnest($ids) AS id')}",
            )
        else:
            self.edge(
                st,
                t.name,
                f"SELECT {c.ref_text(t, 'x', src.obj_col)} FROM {qt(src.table)} x WHERE {match}",
                f"{their} FROM {qt(src.table)} x WHERE {c.key_in(t, 'x', 'SELECT unnest($ids) AS id', src.obj_col)}",
            )

    def share_edge(self, t: Type, st: str, sr: str | None, relation: str | None) -> None:
        """t's readers read st's objects through the shares to them (relation None: custom roles' assignments)."""
        rel = f"g.relation = {lit(relation)}" if relation else "g.relation LIKE 'role:%'"
        self.edge(
            st,
            t.name,
            f"SELECT g.object_id FROM authz.shares g WHERE g.subject_type = {lit(st)} AND g.subject_id IN (SELECT unnest($text)) "
            f"AND g.subject_relation = {lit(sr or '')} AND g.object_type = {lit(t.name)} AND {rel}",
            f"SELECT g.subject_id FROM authz.shares g WHERE g.object_type = {lit(t.name)} AND g.object_id IN (SELECT unnest($text)) "
            f"AND {rel} AND g.subject_type = {lit(st)} AND g.subject_relation = {lit(sr or '')}",
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
                if t.name in self.by and self.keyed(t.name, name):
                    # keyed by its own inheritance: the object's key (folder#view:7), which inherits and given resolve
                    return (
                        f"SELECT {c.key(t, 'r')} AS id, {lit(f'{t.name}#{name}:')} || {c.key_text(t, 'r')} AS key, "
                        f"false AS d FROM {qt(t.table)} r WHERE {c.key_in(t, 'r', ids)}"
                    )
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
        if self.keyed(st, name):
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
                if not self.keyed(st, sr):
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
                if not self.keyed(st, sr):
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
                if not self.keyed(st, perm):
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
        # (expanded from the keys: what inherits is copied in here, keyed by it or not)
        d = self.copied()
        n = self.st.next()
        i = f"i{n}"
        ps = [f"p{n}_{k}" for k in range(len(pos))]
        ns = [f"n{n}_{k}" for k in range(len(neg))]
        ctes = [f"{i} AS MATERIALIZED ({rows})"]
        ctes += [
            f"{p} AS MATERIALIZED ({d.rows(t, x, f'SELECT id FROM {i}', loc)})" for p, x in zip(ps, pos, strict=True)
        ]
        ctes += [
            f"{m} AS MATERIALIZED ({d.rows(t, x, f'SELECT id FROM {i}', loc)})" for m, x in zip(ns, neg, strict=True)
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

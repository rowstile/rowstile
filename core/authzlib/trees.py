"""Inheritance: closure tables kept current by triggers.

One type (folder inherits from folder): a typed closure table (descendant,
ancestor). Several types in one recursion (folder -> project -> folder): a
closure over (type, id) nodes, with ids stored as text.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Callable

from .compiler import Core, Edge, Edges, NextTree, SccKey
from .parse import Cols, Loc, Relation, Source, Type, cols, fail
from .sqlutil import (
    check_stable_condition,
    dep_trigger,
    lit,
    on_row,
    q,
    qt,
    reads_tables,
    union,
)

DEFINER = "SECURITY DEFINER SET search_path FROM CURRENT"
# A whole tree is computed and checked this many rows at a time: the recursion that walks up keeps every row it
# has found in memory (a recursive UNION's hash table never goes to disk), so over all rows at once it would take
# memory in proportion to the tree, whatever work_mem says.
BATCH = 10000
# a name inside the tree's names: f('_refresh') is authz_int."<tree>_refresh"
Namer = Callable[[str], str]
# a condition to check where it is written: (table, SQL, loc)
Where = tuple[str, str, Loc]


class TreeMixin(Core):
    # --- shared pieces ----------------------------------------------------
    def lock_sql(self, types: list[str]) -> str:
        # Every change to a tree takes its types' lock rows. In READ COMMITTED this
        # queues writers; in REPEATABLE READ or SERIALIZABLE, a transaction whose
        # snapshot predates another writer's commit fails with a serialization
        # error instead of writing a closure from stale data.
        self.locked_types.update(types)
        return f"UPDATE authz_int.locks SET n = n + 1 WHERE type IN ({', '.join(lit(x) for x in sorted(types))});"

    def valid_sql(self, t: Type, alias: str) -> str:
        """The type's own `where`, for a row: rows that fail it pass nothing on."""
        return f" AND coalesce(({on_row(t.where, alias)}), false)" if t.where else ""

    def tree_checks(self, conds: list[Where], link_wheres: list[Where], views: list[str], first_line: Loc) -> str:
        """What decides inheritance must be IMMUTABLE. Postgres says whether an
        expression is IMMUTABLE when asked to index it (on an empty copy);
        conditions that read tables can't be indexed, so for those, check the
        functions they call."""
        probes = "\n".join(
            f"""  CREATE TEMP TABLE authz_probe (LIKE {qt(tb)});
  BEGIN
    CREATE INDEX ON authz_probe ((coalesce(({on_row(c, "authz_probe")}), false)));
  EXCEPTION WHEN others THEN
    RAISE EXCEPTION '%: a condition that limits inheritance must give the same answer for every user at any time (%) [AZ603]',
      {lit(loc)}, SQLERRM;
  END;
  DROP TABLE authz_probe;"""
            for tb, c, loc in conds + link_wheres
            if not reads_tables(c)
        )
        return f"""-- what decides inheritance must be IMMUTABLE
DO $imm$
DECLARE d record;
BEGIN
{probes}
  FOR d IN SELECT DISTINCT p.oid::regprocedure AS fn
           FROM pg_depend dep
           JOIN pg_rewrite w ON w.oid = dep.objid AND dep.classid = 'pg_rewrite'::regclass
           JOIN pg_proc p ON p.oid = dep.refobjid AND dep.refclassid = 'pg_proc'::regclass
           WHERE w.ev_class IN ({", ".join(f"{lit(v)}::regclass" for v in views)}) AND p.provolatile <> 'i' LOOP
    RAISE EXCEPTION '%: a condition used for inheritance calls %, which is not IMMUTABLE; read tables with a subquery instead, so changes to them are tracked [AZ603]',
      {lit(first_line)}, d.fn;
  END LOOP;
END $imm$;"""

    def deps_sql(self, name: str, conds_view: str, own_tables: list[str], first_line: Loc, on_deps: str) -> str:
        return f"""-- find the tables the conditions read and watch them
-- @locks SHARE ROW EXCLUSIVE: the tables the inheritance conditions read ({first_line})
DO $dep$
DECLARE d record;
BEGIN
  FOR d IN SELECT DISTINCT c.oid::regclass AS rel, c.relkind
           FROM pg_depend dep
           JOIN pg_rewrite w ON w.oid = dep.objid AND dep.classid = 'pg_rewrite'::regclass
           JOIN pg_class c ON c.oid = dep.refobjid AND dep.refclassid = 'pg_class'::regclass
           WHERE w.ev_class = {lit(conds_view)}::regclass
             AND c.oid NOT IN (w.ev_class, {", ".join(f"{lit(tb)}::regclass" for tb in own_tables)}) LOOP
    IF d.relkind NOT IN ('r', 'p') THEN
      RAISE EXCEPTION '%: a condition used for inheritance reads %, which is not a table; read its tables directly [AZ604]',
        {lit(first_line)}, d.rel;
    END IF;
    EXECUTE format('CREATE TRIGGER %I AFTER INSERT OR UPDATE OR DELETE OR TRUNCATE ON %s '
                   'FOR EACH STATEMENT EXECUTE FUNCTION {on_deps}()', {lit(dep_trigger(name))}, d.rel);
  END LOOP;
END $dep$;"""

    def collect_edges(self, edge_list: list[Edge]) -> tuple[list[Where], list[tuple[str, str, str]]]:
        """Per edge: its sources, plus link tables, shares, and conditions to check."""
        link_wheres: list[Where] = []
        share_keys: list[tuple[str, str, str]] = []
        for ct, rel, _cond, pt in edge_list:
            t = self.T(ct)
            r = t.relations[rel]
            for src in r.sources:
                if (pt, None) not in src.subjects:
                    continue
                if src.kind == "table" and src.where:
                    check_stable_condition(src.where, src.loc)
                    if reads_tables(src.where):
                        fail(
                            src.loc,
                            f"{t.name}.{rel} is used for inheritance, so its where {{...}} can only "
                            f"use the columns of {src.table}",
                            "AZ305",
                        )
                    assert src.table is not None
                    link_wheres.append((src.table, src.where, src.loc))
                if src.kind == "shared":
                    share_keys.append((ct, rel, pt))
        return link_wheres, share_keys

    def shares_guard_sql(
        self,
        name: str,
        f: Namer,
        trig: Namer,
        share_keys: list[tuple[str, str, str]],
        refresh_call: Callable[[str], str],
    ) -> str:
        """Shares that are inheritance links: refresh on change; they can't expire,
        start later or carry a caveat, since the closure is stored."""
        match = " OR ".join(
            f"(x.object_type = {lit(c)} AND x.relation = {lit(r)} AND x.subject_type = {lit(p)} "
            f"AND x.subject_relation = '')"
            for c, r, p in sorted(set(share_keys))
        )
        when = match.replace("x.", "NEW.")
        described = ", ".join(sorted({f"{c}.{r}" for c, r, _ in share_keys}))
        return f"""-- links people make with authz.share(); they can't expire, since the closure is stored
CREATE FUNCTION {f("_on_shares")}() RETURNS trigger
LANGUAGE plpgsql {DEFINER} AS $f$
DECLARE a_t text[]; a_i text[];
BEGIN
  -- one refresh for old and new links together: each refresh expects the rest to be current
  IF TG_OP = 'INSERT' THEN
    {refresh_call("SELECT x.object_type, x.object_id FROM new_rows x WHERE " + match)}
  ELSIF TG_OP = 'DELETE' THEN
    {refresh_call("SELECT x.object_type, x.object_id FROM old_rows x WHERE " + match)}
  ELSE
    {
            refresh_call(
                "SELECT x.object_type, x.object_id FROM new_rows x WHERE "
                + match
                + " UNION SELECT x.object_type, x.object_id FROM old_rows x WHERE "
                + match
            )
        }
  END IF;
  RETURN NULL;
END $f$;
DO $ex$
DECLARE n bigint;
BEGIN
  SELECT count(*) INTO n FROM authz.shares x
  WHERE (x.expires_at IS NOT NULL OR x.starts_at IS NOT NULL OR x.caveat IS NOT NULL) AND ({match});
  IF n > 0 THEN
    RAISE EXCEPTION '% existing shares of {
            described
        } have an expiry, a start time or a caveat, but links used for inheritance cannot; remove those (or the shares) first [AZ605]', n;
  END IF;
END $ex$;
CREATE FUNCTION {f("_no_expiry")}() RETURNS trigger
LANGUAGE plpgsql {DEFINER} AS $f$
BEGIN
  RAISE EXCEPTION '%.% links are used for inheritance, so they cannot expire, start later or have a caveat',
    NEW.object_type, NEW.relation USING ERRCODE = 'check_violation', HINT = 'rowstile help AZ605';
END $f$;
CREATE TRIGGER {trig("_shares_ins")} AFTER INSERT ON authz.shares
  REFERENCING NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION {f("_on_shares")}();
CREATE TRIGGER {trig("_shares_upd")} AFTER UPDATE ON authz.shares
  REFERENCING OLD TABLE AS old_rows NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION {f("_on_shares")}();
CREATE TRIGGER {trig("_shares_del")} AFTER DELETE ON authz.shares
  REFERENCING OLD TABLE AS old_rows FOR EACH STATEMENT EXECUTE FUNCTION {f("_on_shares")}();
CREATE TRIGGER {trig("_shares_trunc")} AFTER TRUNCATE ON authz.shares
  FOR EACH STATEMENT EXECUTE FUNCTION {f("_on_truncate")}();
CREATE TRIGGER {trig("_shares_expiry")} BEFORE INSERT OR UPDATE ON authz.shares FOR EACH ROW
  WHEN ((NEW.expires_at IS NOT NULL OR NEW.starts_at IS NOT NULL OR NEW.caveat IS NOT NULL) AND ({when}))
  EXECUTE FUNCTION {f("_no_expiry")}();"""

    # --- keeping unchanged trees across applies ------------------------------
    # applying recreates everything, but an inheritance table whose definition didn't change (and whose
    # tables weren't recreated) is still current: its triggers kept it so. Apply moves those aside before
    # dropping the schema (output.compile, keep_sql) and each one replaces its new, empty table here, so a
    # policy change that doesn't touch inheritance doesn't rebuild millions of rows under lock.
    def swap_in_kept(self, table: str) -> str:
        return f"""-- kept from the last apply if its definition is the same: its rows are current
DO $k$ BEGIN
  IF to_regclass({lit("authz_keep." + q(table))}) IS NOT NULL THEN
    DROP TABLE authz_int.{q(table)};
    ALTER TABLE authz_keep.{q(table)} SET SCHEMA authz_int;
    INSERT INTO pg_temp.authz_kept VALUES ({lit(table)}) ON CONFLICT DO NOTHING;
  END IF;
END $k$;"""

    def backfill_sql(self, name: str, f: Namer) -> str:
        return (
            f"-- backfill from the rows already there (unless the tree was kept)\n"
            f"DO $b$ BEGIN\n  IF NOT EXISTS (SELECT 1 FROM pg_temp.authz_kept WHERE name = {lit(name)}) THEN\n"
            f"    PERFORM {f('_rebuild')}();\n  END IF;\nEND $b$;"
        )

    def remember_tree(self, name: str, sql: list[str], tables: list[str], reads: bool) -> None:
        """What decides a tree's rows: its generated SQL (locations and error codes aside) and the tables it reads.
        Trees whose conditions read other tables are always rebuilt: those tables are found at apply time."""
        if reads:
            return
        text = re.sub(
            r" \[AZ\d{3}\]|, HINT = 'rowstile help AZ\d{3}'", "", re.sub(r"\bline \d+", "line", "\n\n".join(sql))
        )
        self.tree_keep[name] = (hashlib.sha256(text.encode()).hexdigest()[:32], sorted(set(tables)))

    def tree_name(self, types: list[str], edges: Edges) -> str:
        rels = sorted({rel for _, rel, _, _ in edges})
        stem = f"{'_'.join(sorted(types))}__{'_'.join(rels)}__tree"
        n = sum(1 for v in self.trees.values() if v.startswith(stem))
        return stem + (str(n + 1) if n else "")

    # --- one type ---------------------------------------------------------
    def ensure_tree(self, t: Type, edges: Edges) -> str:
        tree_key = (t.name, edges)
        if tree_key in self.trees:
            return self.trees[tree_key]
        name = self.tree_name([t.name], edges)
        self.trees[tree_key] = name
        edge_list = sorted(edges, key=lambda e: (e[1], e[2] or ""))
        tbl, pkt = qt(t.table), t.pktype
        key = lambda a: self.key(t, a)
        all_keys = key(tbl) if t.composite else q(self.pk(t))
        # every key, BATCH to an array
        batches = (
            f"SELECT array_agg(k.k) FROM (SELECT {all_keys} AS k, row_number() OVER () AS n FROM {tbl}) k "
            f"GROUP BY (k.n - 1) / {BATCH}"
        )
        lock = self.lock_sql([t.name])
        f: Namer = lambda suffix: f"authz_int.{q(name + suffix)}"
        trig: Namer = lambda suffix: q("authz_" + name + suffix)
        if t.where:
            check_stable_condition(t.where, t.loc, "decide who inherits (the type's where)")

        links: list[str] = []
        parents: list[str] = []
        allow: list[str] = []
        col_changes: list[str] = []
        cond_changes: list[str] = []
        conds: list[str] = []
        # the same sources, for lookups of one id (each_source): links with their number, parents
        link_args: list[tuple[Relation, Source, int]] = []
        parent_args: list[tuple[Relation, Source]] = []
        link_tables: dict[str, set[Cols]] = {}

        def link_sql(r: Relation, src: Source, i: int, match: tuple[str, str] | None = None) -> str:
            return self.pair_sql(
                t, r, src, t.name, "", "_child", "_parent", extra=f"{i} AS _link, ", tree=True, match=match
            )

        def parent_sql(r: Relation, src: Source, match: tuple[str, str] | None = None) -> str:
            return self.pair_sql(t, r, src, t.name, "", "_child", "_parent", match=match)

        link_wheres, share_keys = self.collect_edges(edge_list)
        for i, (_, rel, cond, _) in enumerate(edge_list):
            r = t.relations[rel]
            for src in r.sources:
                if (t.name, None) not in src.subjects:
                    continue
                link_args.append((r, src, i))
                links.append(link_sql(r, src, i))
                if src.kind == "column":
                    parent_args.append((r, src))
                    parents.append(parent_sql(r, src))
                    for c in cols(self.source_columns(src)) + ((src.type_col,) if src.type_col else ()):
                        col_changes.append(f"n.{q(c)} IS DISTINCT FROM o.{q(c)}")
                elif src.kind == "table":
                    assert src.table is not None and src.obj_col is not None
                    link_tables.setdefault(src.table, set()).add(src.obj_col)
            if cond:
                allow.append(f"(e._link = {i} AND coalesce(({on_row(cond, 'c')}), false))")
                conds.append(cond)
            else:
                allow.append(f"e._link = {i}")

        def each_source(sources: list[str], key: str, outer: str) -> str:
            """The rows of every source whose `key` is `outer`, as one lookup per source. Walks use this
            instead of joining the sources' UNION ALL view: through the view the planner can't use each
            source's index and scans every row at every step (measured with bench/). OFFSET 0 keeps each
            lookup a lookup: pulled up into the walk's join, a small table gets a full scan at every step.
            A composite key's lookup is written inside each source, column by column."""
            if t.composite:
                side = "obj" if key == "_child" else "subj"
                lookups = (
                    [link_sql(r, src, i, (side, outer)) for r, src, i in link_args]
                    if sources is links
                    else [parent_sql(r, src, (side, outer)) for r, src in parent_args]
                )
                return "\n      UNION ALL ".join(f"(SELECT x.* FROM ({s}) x OFFSET 0)" for s in lookups)
            return "\n      UNION ALL ".join(
                f"(SELECT x.* FROM ({s}) x WHERE x.{key} = {outer} OFFSET 0)" for s in sources
            )

        tracked = conds + ([t.where] if t.where else [])
        for c in tracked:
            cond_changes.append(
                f"(SELECT coalesce(({on_row(c, 'r')}), false) FROM (SELECT n.*) r) IS DISTINCT FROM "
                f"(SELECT coalesce(({on_row(c, 'r')}), false) FROM (SELECT o.*) r)"
            )
        changed = "\n         OR ".join(dict.fromkeys(col_changes + cond_changes)) or "false"
        described = ", ".join(f"{rel}" + (f" while {{{cond}}}" if cond else "") for _, rel, cond, _ in edge_list)
        reads = [c for c in tracked if reads_tables(c)]
        locs = [self.cond_lines.get((t.name, c), t.loc) for c in conds] + ([t.loc] if t.where else [])
        first_line = min(locs + [ln for _, _, ln in link_wheres]) if (locs or link_wheres) else t.loc

        # (its indexes are named as Postgres would name them, and shortened as every generated name: the one built
        # beside, stem + "__next", has its indexes renamed when it is swapped in, migrate.swap_sql)
        def table_sql(stem: str) -> str:
            return f"""CREATE TABLE authz_int.{q(stem)} (descendant {pkt} NOT NULL, ancestor {pkt} NOT NULL,
  CONSTRAINT {q(stem + "_pkey")} PRIMARY KEY (descendant, ancestor));
CREATE INDEX {q(stem + "_ancestor_idx")} ON authz_int.{q(stem)} (ancestor);"""

        def compute_sql(g: Namer) -> str:
            return f"""CREATE FUNCTION {g("_compute")}(p_ids {pkt}[]) RETURNS TABLE (o_descendant {pkt}, o_ancestor {pkt})
LANGUAGE sql STABLE {DEFINER} AS $f$
  WITH RECURSIVE up(_d, _a) AS (
    SELECT {key("x")}, {key("x")} FROM {tbl} x WHERE {self.key_any(t, "x", "p_ids")}
    UNION
    SELECT up._d, e._parent
    FROM up
    -- one index lookup per step: joined plainly, a small table gets a full scan at every step
    -- (OFFSET 0 keeps the planner from turning this into a hash join)
    CROSS JOIN LATERAL (SELECT c.* FROM {tbl} c WHERE {self.key_is(t, "c", "up._a")} OFFSET 0) c
    CROSS JOIN LATERAL (
      {each_source(links, "_child", "up._a")}) e
    WHERE ({" OR ".join(allow)})
      AND EXISTS (SELECT 1 FROM {tbl} p WHERE {self.key_is(t, "p", "e._parent")}{self.valid_sql(t, "p")}))
  SELECT _d, _a FROM up
$f$;"""

        sql = [
            f"""-- {t.name}: each row with every ancestor it inherits from, through {described}
{table_sql(name)}
INSERT INTO authz_int.locks VALUES ({lit(t.name)}, 0) ON CONFLICT DO NOTHING;
{self.swap_in_kept(name)}

-- every parent link, from every source
CREATE VIEW {f("_links")} AS
  {union(links)};

-- walk up from the given rows; a link is followed only if its condition holds on
-- the child, and the parent exists and passes its type's where
{compute_sql(f)}"""
        ]

        views = [f("_links")]
        if tracked:
            on_r = ", ".join(f"coalesce(({on_row(c, 'r')}), false)" for c in tracked)
            sql.append(f"""-- the conditions on each row (and the type's where)
CREATE VIEW {f("_conds")} AS
  SELECT {key("r")} AS id, ARRAY[{on_r}] AS v FROM {tbl} r;""")
            views.append(f("_conds"))
        sql.append(
            self.tree_checks(
                [(t.table, c, loc) for c, loc in zip(tracked, locs, strict=True)], link_wheres, views, first_line
            )
        )
        if reads:
            sql.append(f"""-- ...as last applied (they read other rows or tables, so changes there are re-checked)
CREATE TABLE {f("_cond_cache")} (id {pkt} PRIMARY KEY, v boolean[] NOT NULL);""")
        cache_refresh = (
            f"""
  DELETE FROM {f("_cond_cache")} WHERE id = ANY (affected);
  INSERT INTO {f("_cond_cache")} SELECT id, v FROM {f("_conds")} WHERE id = ANY (affected);"""
            if reads
            else ""
        )
        cache_rebuild = (
            f"""
  DELETE FROM {f("_cond_cache")};
  INSERT INTO {f("_cond_cache")} SELECT id, v FROM {f("_conds")};"""
            if reads
            else ""
        )
        cache_verify = (
            f"""
     AND NOT EXISTS ((SELECT id, v FROM {f("_conds")} EXCEPT SELECT id, v FROM {f("_cond_cache")})
                     UNION ALL
                     (SELECT id, v FROM {f("_cond_cache")} EXCEPT SELECT id, v FROM {f("_conds")}))"""
            if reads
            else ""
        )

        # A change that only alters the given rows' own links (a move, a link added or removed) can shift
        # stored rows instead of recomputing everything below: see _shift. Rows appearing, disappearing or
        # changing whether they pass the type's where alter links into them too, and conditions that read
        # other rows change links the trigger doesn't list, so those always recompute.
        shifts = not t.where and not reads
        recompute = f"""DELETE FROM {f("")} WHERE descendant = ANY (affected);
    INSERT INTO {f("")} (descendant, ancestor)
    SELECT o_descendant, o_ancestor FROM {f("_compute")}(affected);"""
        if shifts:
            sql.append(f"""-- after a change to the links of p_ids alone (nothing inserted, deleted or renumbered), everything
-- below them (p_below, which includes them) keeps its stored rows among itself, and only rows to the
-- ancestors of p_ids, before or after, can change: to those, each row below now reaches whatever the
-- stored rows of the links leaving the part below lead to. A move of a folder with thousands below it
-- then rewrites (below it) x (its old and new ancestors) rows instead of recomputing every one. That
-- holds only if no link of p_ids, before or after, leads back into the part below them (checked here;
-- false means nothing was done and the caller recomputes). Plans are made for each call's arrays:
-- one made for a few rows would be ruinous for a big move
CREATE FUNCTION {f("_shift")}(p_ids {pkt}[], p_below {pkt}[]) RETURNS boolean
LANGUAGE plpgsql {DEFINER} SET plan_cache_mode = force_custom_plan AS $f$
DECLARE touched {pkt}[];
BEGIN
  IF EXISTS (SELECT 1 FROM {f("")} t JOIN unnest(p_below) b(id) ON b.id = t.ancestor
             WHERE t.descendant = ANY (p_ids) AND t.ancestor <> t.descendant) THEN
    RETURN false;
  END IF;
  IF EXISTS (SELECT 1 FROM unnest(p_ids) b(_y) JOIN {tbl} c ON {self.key_is(t, "c", "b._y")}
             CROSS JOIN LATERAL (
               {each_source(links, "_child", "b._y")}) e
             WHERE ({" OR ".join(allow)}) AND e._parent = ANY (p_below)) THEN
    RETURN false;
  END IF;
  -- the ancestors of p_ids before (stored) and after (through their links now): no others change
  touched := ARRAY(
    SELECT t.ancestor FROM {f("")} t WHERE t.descendant = ANY (p_ids) AND t.ancestor <> t.descendant
    UNION
    SELECT u.ancestor FROM unnest(p_ids) b(_y) JOIN {tbl} c ON {self.key_is(t, "c", "b._y")}
    CROSS JOIN LATERAL (
      {each_source(links, "_child", "b._y")}) e
    JOIN {f("")} u ON u.descendant = e._parent
    WHERE ({" OR ".join(allow)}));
  WITH below AS MATERIALIZED (SELECT x AS _y FROM unnest(p_below) x),
  -- links from the part below to outside it, as they are now
  exits AS MATERIALIZED (
    SELECT e._child AS y, e._parent AS p
    FROM below JOIN {tbl} c ON {self.key_is(t, "c", "below._y")}
    CROSS JOIN LATERAL (
      {each_source(links, "_child", "below._y")}) e
    WHERE ({" OR ".join(allow)})),
  -- each row below: the touched ancestors it now reaches, through the exits it reaches
  fresh AS MATERIALIZED (
    SELECT DISTINCT d.descendant AS d, u.ancestor AS a
    FROM exits
    JOIN {f("")} u ON u.descendant = exits.p AND u.ancestor = ANY (touched)
    JOIN {f("")} d ON d.ancestor = exits.y
    WHERE NOT EXISTS (SELECT 1 FROM below b WHERE b._y = exits.p)),
  stale AS (
    DELETE FROM {f("")} t
    WHERE t.ancestor = ANY (touched) AND t.descendant IN (SELECT _y FROM below)
      AND NOT EXISTS (SELECT 1 FROM fresh o WHERE o.d = t.descendant AND o.a = t.ancestor))
  INSERT INTO {f("")} (descendant, ancestor) SELECT d, a FROM fresh ON CONFLICT DO NOTHING;
  RETURN true;
END $f$;""")
        body = (
            f"""IF NOT (p_shift AND {f("_shift")}(p_ids, affected)) THEN
    {recompute}
  END IF;"""
            if shifts
            else recompute.replace("\n    ", "\n  ")
        )
        sql.append(f"""-- recompute the given rows and everything linked below them; p_shift: only their own links changed
CREATE FUNCTION {f("_refresh")}(p_ids {pkt}[], p_shift boolean DEFAULT false) RETURNS void
LANGUAGE plpgsql {DEFINER} AS $f$
DECLARE affected {pkt}[];
BEGIN
  IF coalesce(cardinality(p_ids), 0) = 0 THEN RETURN; END IF;
  {lock}
  WITH RECURSIVE down(id) AS (
    SELECT x FROM unnest(p_ids) AS x WHERE x IS NOT NULL
    UNION
    SELECT e._child FROM down CROSS JOIN LATERAL (
      {each_source(links, "_parent", "down.id")}) e)
  SELECT array_agg(id) INTO affected FROM down;
  {body}{cache_refresh}
  PERFORM authz_int.changed({lit(t.name)}, affected::text[], 'inheritance');
END $f$;""")
        sql.append(f"""-- recompute everything (backfill, TRUNCATE), {BATCH} rows at a time
CREATE FUNCTION {f("_rebuild")}() RETURNS void
LANGUAGE plpgsql {DEFINER} AS $f$
DECLARE batch {pkt}[];
BEGIN
  {lock}
  DELETE FROM {f("")};
  FOR batch IN {batches} LOOP
    INSERT INTO {f("")} (descendant, ancestor)
    SELECT o_descendant, o_ancestor FROM {f("_compute")}(batch);
  END LOOP;{cache_rebuild}
END $f$;
CREATE FUNCTION {f("_on_truncate")}() RETURNS trigger
LANGUAGE plpgsql {DEFINER} AS $f$
BEGIN PERFORM {f("_rebuild")}(); RETURN NULL; END $f$;

-- what a rebuild would give against what is stored, {BATCH} rows at a time; then nothing stored for a row
-- that is gone
CREATE FUNCTION {f("_verify")}() RETURNS boolean
LANGUAGE plpgsql STABLE {DEFINER} AS $f$
DECLARE batch {pkt}[];
BEGIN
  FOR batch IN {batches} LOOP
    IF EXISTS (WITH fresh AS MATERIALIZED (SELECT o_descendant AS d, o_ancestor AS a FROM {f("_compute")}(batch)),
                    stored AS MATERIALIZED (SELECT descendant AS d, ancestor AS a FROM {f("")}
                                            WHERE descendant = ANY (batch))
               (SELECT d, a FROM fresh EXCEPT SELECT d, a FROM stored)
               UNION ALL
               (SELECT d, a FROM stored EXCEPT SELECT d, a FROM fresh)) THEN
      RETURN false;
    END IF;
  END LOOP;
  IF EXISTS (SELECT 1 FROM {f("")} s
             WHERE NOT EXISTS (SELECT 1 FROM {tbl} x WHERE {self.key_is(t, "x", "s.descendant")})) THEN
    RETURN false;
  END IF;
  RETURN true{cache_verify};
END $f$;""")

        if reads:
            sql.append(f"""-- re-evaluate the conditions after a change to what they read
CREATE FUNCTION {f("_recheck")}() RETURNS void
LANGUAGE plpgsql {DEFINER} AS $f$
BEGIN
  {lock}
  PERFORM {f("_refresh")}(ARRAY(
    SELECT coalesce(c.id, k.id) FROM {f("_conds")} c FULL JOIN {f("_cond_cache")} k ON k.id = c.id
    WHERE c.v IS DISTINCT FROM k.v));
END $f$;
CREATE FUNCTION {f("_on_deps")}() RETURNS trigger
LANGUAGE plpgsql {DEFINER} AS $f$
BEGIN PERFORM {f("_recheck")}(); RETURN NULL; END $f$;""")
            sql.append(self.deps_sql(name, f("_conds"), [tbl], first_line, f("_on_deps")))

        cycle_check = ""
        if parents:
            sql.append(f"""-- the tree's own columns may not loop (links through tables may: they add nothing)
CREATE VIEW {f("_parents")} AS
  {union(parents)};
CREATE FUNCTION {f("_check_loops")}(p_ids {pkt}[]) RETURNS void
LANGUAGE plpgsql {DEFINER} AS $f$
DECLARE bad text;
BEGIN
  WITH RECURSIVE up(start, id) AS (
    SELECT e._child, e._parent FROM {f("_parents")} e WHERE e._child = ANY (p_ids)
    UNION
    SELECT up.start, e._parent FROM up CROSS JOIN LATERAL (
      {each_source(parents, "_child", "up.id")}) e)
  SELECT start::text INTO bad FROM up WHERE id = start LIMIT 1;
  IF bad IS NOT NULL THEN
    RAISE EXCEPTION '{t.name} % cannot be moved inside itself', bad USING ERRCODE = 'check_violation', HINT = 'rowstile help AZ713';
  END IF;
END $f$;""")
            cycle_check = f"\n  IF TG_OP <> 'DELETE' THEN PERFORM {f('_check_loops')}(ids); END IF;"

        sql.append(f"""-- rows inserted, deleted, moved, or whose id or conditions change
CREATE FUNCTION {f("_on_rows")}() RETURNS trigger
LANGUAGE plpgsql {DEFINER} AS $f$
DECLARE ids {pkt}[]; shift boolean := false;
BEGIN
  IF TG_OP = 'INSERT' THEN
    ids := ARRAY(SELECT {key("n")} FROM new_rows n);
  ELSIF TG_OP = 'UPDATE' THEN
    -- rows whose id changed: the old id disappears and the new one appears
    ids := ARRAY(
      SELECT {key("o")} FROM old_rows o WHERE NOT EXISTS (SELECT 1 FROM new_rows n WHERE {key("n")} = {key("o")})
      UNION SELECT {key("n")} FROM new_rows n WHERE NOT EXISTS (SELECT 1 FROM old_rows o WHERE {key("o")} = {key("n")}));
    shift := {"cardinality(ids) = 0" if shifts else "false"};
    ids := ARRAY(
      SELECT {key("n")} FROM new_rows n JOIN old_rows o ON {key("o")} = {key("n")}
      WHERE {changed}
      UNION SELECT unnest(ids));
  ELSE
    ids := ARRAY(SELECT {key("o")} FROM old_rows o);
  END IF;
  IF cardinality(ids) > 0 THEN
    {lock}{cycle_check}
    PERFORM {f("_refresh")}(ids, shift);
  END IF;{f"{chr(10)}  PERFORM {f('_recheck')}();" if reads else ""}
  RETURN NULL;
END $f$;
CREATE TRIGGER {trig("_ins")} AFTER INSERT ON {tbl}
  REFERENCING NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION {f("_on_rows")}();
CREATE TRIGGER {trig("_upd")} AFTER UPDATE ON {tbl}
  REFERENCING OLD TABLE AS old_rows NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION {f("_on_rows")}();
CREATE TRIGGER {trig("_del")} AFTER DELETE ON {tbl}
  REFERENCING OLD TABLE AS old_rows FOR EACH STATEMENT EXECUTE FUNCTION {f("_on_rows")}();
CREATE TRIGGER {trig("_trunc")} AFTER TRUNCATE ON {tbl}
  FOR EACH STATEMENT EXECUTE FUNCTION {f("_on_truncate")}();""")

        shift_lit = "true" if shifts else "false"
        for i, (ltable, obj_cols) in enumerate(sorted(link_tables.items())):
            new_ids = " UNION ".join(
                f"SELECT {self.ref(t, 'n', c)} FROM new_rows n" for c in sorted(obj_cols, key=cols)
            )
            old_ids = " UNION ".join(
                f"SELECT {self.ref(t, 'o', c)} FROM old_rows o" for c in sorted(obj_cols, key=cols)
            )
            sfx = f"_on_links{i + 1}"
            sql.append(f"""-- links stored in {ltable}
CREATE FUNCTION {f(sfx)}() RETURNS trigger
LANGUAGE plpgsql {DEFINER} AS $f$
BEGIN
  -- one refresh for old and new links together: each refresh expects the rest to be current
  IF TG_OP = 'INSERT' THEN PERFORM {f("_refresh")}(ARRAY({new_ids}), {shift_lit});
  ELSIF TG_OP = 'DELETE' THEN PERFORM {f("_refresh")}(ARRAY({old_ids}), {shift_lit});
  ELSE PERFORM {f("_refresh")}(ARRAY({new_ids} UNION {old_ids}), {shift_lit});
  END IF;
  RETURN NULL;
END $f$;
CREATE TRIGGER {trig(sfx + "_ins")} AFTER INSERT ON {qt(ltable)}
  REFERENCING NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION {f(sfx)}();
CREATE TRIGGER {trig(sfx + "_upd")} AFTER UPDATE ON {qt(ltable)}
  REFERENCING OLD TABLE AS old_rows NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION {f(sfx)}();
CREATE TRIGGER {trig(sfx + "_del")} AFTER DELETE ON {qt(ltable)}
  REFERENCING OLD TABLE AS old_rows FOR EACH STATEMENT EXECUTE FUNCTION {f(sfx)}();
CREATE TRIGGER {trig(sfx + "_trunc")} AFTER TRUNCATE ON {qt(ltable)}
  FOR EACH STATEMENT EXECUTE FUNCTION {f("_on_truncate")}();""")

        if share_keys:
            refresh = lambda rows: (
                f"PERFORM {f('_refresh')}(ARRAY(SELECT y.object_id::{pkt} FROM ({rows}) y), {shift_lit});"
            )
            sql.append(self.shares_guard_sql(name, f, trig, share_keys, refresh))

        self.remember_tree(name, sql, [t.table, *link_tables] + (["authz.shares"] if share_keys else []), bool(reads))
        if not reads and not share_keys:
            self.tree_next[name] = self.next_tree(t, name, f, table_sql, compute_sql, sorted(link_tables), batches)
        sql.append(self.backfill_sql(name, f))
        self.tree_sql.append("\n\n".join(sql))
        self.tree_names.append(name)
        return name

    def next_tree(
        self,
        t: Type,
        name: str,
        f: Namer,
        table_sql: Callable[[str], str],
        compute_sql: Callable[[Namer], str],
        link_tables: list[str],
        batches: str,
    ) -> NextTree:
        """Building a tree beside the one in use, while the app runs (migrate.py): the first
        migration fills authz_int."<tree>__next" reading only the app's tables; the second swaps it in
        (it is kept, trees.swap_in_kept) and does again what changed since the first one's snapshot: rows
        of the type written since (their xmin), links changed since (the feed the relationship triggers
        write), and rows deleted since (no longer there)."""
        g: Namer = lambda suffix: f"authz_int.{q(name + '__next' + suffix)}"
        tbl, pkt = qt(t.table), t.pktype
        # a row's xmin as a full transaction id (xmin has no epoch: take the current one, or the one before)
        xid8 = (
            "((((pg_catalog.pg_current_xact_id()::text::bigint >> 32) - CASE WHEN x.xmin::text::bigint > "
            "(pg_catalog.pg_current_xact_id()::text::bigint & 4294967295) THEN 1 ELSE 0 END) << 32) "
            "| x.xmin::text::bigint)::text::xid8"
        )
        ids = (
            f"SELECT {self.key(t, 'x')} FROM {tbl} x WHERE NOT pg_catalog.pg_visible_in_snapshot({xid8}, v.snap)\n"
            f"      UNION SELECT y::{pkt} FROM authz.changes c, unnest(c.object_ids) y\n"
            f"      WHERE c.object_type = {lit(t.name)} AND c.txid >= pg_catalog.pg_snapshot_xmin(v.snap)::text::bigint\n"
            f"        AND NOT pg_catalog.pg_visible_in_snapshot(c.txid::text::xid8, v.snap) AND y <> '*'"
        )
        full = (
            f"coalesce((SELECT s.value::bigint FROM authz.settings s WHERE s.key = 'changes_trimmed_to'), 0) > v.feed\n"
            f"     OR EXISTS (SELECT 1 FROM authz.changes c WHERE c.object_type = {lit(t.name)} AND '*' = ANY (c.object_ids)\n"
            f"                AND NOT pg_catalog.pg_visible_in_snapshot(c.txid::text::xid8, v.snap))"
        )
        return {
            "types": [t.name],
            "tables": [t.table] + link_tables,
            "link_tables": link_tables,
            "next": g(""),
            "next_name": q(name + "__next"),
            "table": q(name),
            "indexes": [(q(name + "__next" + i), q(name + i)) for i in ("_pkey", "_ancestor_idx")],
            "objects": [("table", g("")), ("function", f"{g('_compute')}(p_ids {pkt}[])")],
            "build": f"""{table_sql(name + "__next")}
{compute_sql(g)}
DO $authz_build$
DECLARE batch {pkt}[];
BEGIN
  FOR batch IN {batches} LOOP
    INSERT INTO {g("")} (descendant, ancestor)
    SELECT o_descendant, o_ancestor FROM {g("_compute")}(batch);
  END LOOP;
END $authz_build$;""",
            "catch_up": f"""-- {name} was built beside the one in use, from a snapshot: what changed since is done again
DO $authz_catch_up$
DECLARE v authz_int.next_trees;
BEGIN
  SELECT * INTO v FROM authz_int.next_trees WHERE name = {lit(name)};
  IF v.name IS NULL OR NOT EXISTS (SELECT 1 FROM pg_temp.authz_kept WHERE name = {lit(name)}) THEN
    RAISE EXCEPTION 'rowstile: {name} was not built beside the one in use (the migration before this one does that) [AZ608]';
  END IF;
  IF {full} THEN
    PERFORM {f("_rebuild")}();          -- the feed doesn't say everything that changed since: all of it
  ELSE
    PERFORM {f("_refresh")}(ARRAY({ids}));
    -- rows deleted since
    DELETE FROM {f("")} d WHERE NOT EXISTS (SELECT 1 FROM {tbl} x WHERE {self.key_is(t, "x", "d.descendant")})
                             OR NOT EXISTS (SELECT 1 FROM {tbl} x WHERE {self.key_is(t, "x", "d.ancestor")});
  END IF;
  DELETE FROM authz_int.next_trees WHERE name = {lit(name)};
END $authz_catch_up$;""",
        }

    # --- several types in one recursion -------------------------------------
    def ensure_multi_tree(self, key: SccKey, edges: Edges) -> str:
        if key in self.trees:
            return self.trees[key]
        members = sorted({tn for tn, _ in self.scc_members[key]})
        name = self.tree_name(members, edges)
        self.trees[key] = name
        edge_list = sorted(edges, key=lambda e: (e[0], e[1], e[2] or "", e[3]))
        types = [self.T(m) for m in members]
        lock = self.lock_sql(members)
        f: Namer = lambda suffix: f"authz_int.{q(name + suffix)}"
        trig: Namer = lambda suffix: q("authz_" + name + suffix)
        for t in types:
            if t.where:
                check_stable_condition(t.where, t.loc, "decide who inherits (the type's where)")
        link_wheres, share_keys = self.collect_edges(edge_list)

        def typed(expr_text: tuple[str, str], t: Type) -> str:
            """The text id in expr_text as t's key; NULL unless it is a t node."""
            return f"(CASE WHEN {expr_text[0]} = {lit(t.name)} THEN {expr_text[1]} END)::{t.pktype}"

        up_steps: list[str] = []
        down_steps: list[str] = []
        loop_steps: list[str] = []
        conds_by_type: dict[str, list[str]] = {t.name: [] for t in types}
        col_changes: dict[str, list[str]] = {t.name: [] for t in types}
        link_tables: dict[str, set[tuple[Cols, str]]] = {}
        for ct, rel, cond, pt in edge_list:
            c, p = self.T(ct), self.T(pt)
            r = c.relations[rel]
            okc = f"coalesce(({on_row(cond, 'r')}), false)" if cond else "true"
            if cond:
                conds_by_type[ct].append(cond)
            parent_ok: Callable[[str], str] = lambda pid, p=p: (
                f"EXISTS (SELECT 1 FROM {qt(p.table)} pp WHERE {self.key_is(p, 'pp', pid)}{self.valid_sql(p, 'pp')})"
            )
            for src in r.sources:
                if (pt, None) not in src.subjects:
                    continue
                if src.kind == "column":
                    pid = self.subject_id(src, "r", pt)
                    for col in cols(self.source_columns(src)) + ((src.type_col,) if src.type_col else ()):
                        col_changes[ct].append(f"n.{q(col)} IS DISTINCT FROM o.{q(col)}")
                    base = (
                        f"FROM {qt(c.table)} r WHERE {self.key_is(c, 'r', typed(('up._at', 'up._a'), c))} "
                        f"AND {pid} IS NOT NULL"
                    )
                    up_steps.append(
                        f"SELECT {lit(pt)}::text AS pt, ({pid})::text AS p {base} AND {okc} AND {parent_ok(pid)}"
                    )
                    loop_steps.append(f"SELECT {lit(pt)}::text AS pt, ({pid})::text AS p {base}")
                    down_steps.append(
                        f"SELECT {lit(ct)}::text AS ct, {self.key_text(c, 'r')} AS c FROM {qt(c.table)} r "
                        f"WHERE {self.subject_is(src, 'r', pt, typed(('down._t', 'down._i'), p))}"
                    )
                elif src.kind == "table":
                    assert src.table is not None and src.obj_col is not None
                    link_tables.setdefault(src.table, set()).add((src.obj_col, ct))
                    pid = self.subject_id(src, "s", pt)
                    where = f" AND coalesce(({on_row(src.where, 's')}), false)" if src.where else ""
                    ok = (
                        f"(SELECT {okc} FROM {qt(c.table)} r WHERE {self.key_is(c, 'r', self.ref(c, 's', src.obj_col))})"
                        if cond
                        else "true"
                    )
                    up_steps.append(
                        f"SELECT {lit(pt)}::text AS pt, ({pid})::text AS p FROM {qt(src.table)} s "
                        f"WHERE {self.key_is(c, 's', typed(('up._at', 'up._a'), c), src.obj_col)} "
                        f"AND {pid} IS NOT NULL{where} AND {ok} AND {parent_ok(pid)}"
                    )
                    down_steps.append(
                        f"SELECT {lit(ct)}::text AS ct, {self.ref_text(c, 's', src.obj_col)} AS c "
                        f"FROM {qt(src.table)} s WHERE {self.subject_is(src, 's', pt, typed(('down._t', 'down._i'), p))}{where}"
                    )
                else:
                    ok = (
                        f"(SELECT {okc} FROM {qt(c.table)} r WHERE {self.key_is(c, 'r', 'g.object_id::' + c.pktype)})"
                        if cond
                        else "true"
                    )
                    gm = (
                        f"g.object_type = {lit(ct)} AND g.relation = {lit(rel)} AND g.subject_type = {lit(pt)} "
                        f"AND g.subject_relation = ''"
                    )
                    up_steps.append(
                        f"SELECT {lit(pt)}::text AS pt, g.subject_id AS p FROM authz.shares g "
                        f"WHERE up._at = {lit(ct)} AND g.object_id = up._a AND {gm} AND {ok} "
                        f"AND {parent_ok('g.subject_id::' + p.pktype)}"
                    )
                    down_steps.append(
                        f"SELECT {lit(ct)}::text AS ct, g.object_id AS c FROM authz.shares g "
                        f"WHERE down._t = {lit(pt)} AND g.subject_id = down._i AND {gm}"
                    )
        tracked = {t.name: conds_by_type[t.name] + ([t.where] if t.where else []) for t in types}
        reads = any(reads_tables(c) for cs in tracked.values() for c in cs)
        all_locs = [self.cond_lines.get((tn, c), self.T(tn).loc) for tn, cs in conds_by_type.items() for c in cs]
        first_line = min(
            all_locs + [t.loc for t in types if t.where] + [ln for _, _, ln in link_wheres] or [types[0].loc]
        )
        exists_case = " ".join(
            f"WHEN {lit(t.name)} THEN EXISTS (SELECT 1 FROM {qt(t.table)} x "
            f"WHERE {self.key_is(t, 'x', typed(('n.t', 'n.i'), t))})"
            for t in types
        )
        all_nodes = " UNION ALL ".join(
            f"SELECT {lit(t.name)}::text AS t, {self.key_text(t, 'x')} AS i FROM {qt(t.table)} x" for t in types
        )
        # every node, BATCH to a pair of arrays
        batches = (
            f"SELECT array_agg(k.t), array_agg(k.i) FROM (SELECT x.t, x.i, row_number() OVER () AS n "
            f"FROM ({all_nodes}) x) k GROUP BY (k.n - 1) / {BATCH}"
        )
        described = ", ".join(
            f"{ct}.{rel} -> {pt}" + (f" while {{{cond}}}" if cond else "") for ct, rel, cond, pt in edge_list
        )

        sql = [
            f"""-- {", ".join(members)}: each node with every ancestor it inherits from, through {described}
CREATE TABLE {f("")} (dtype text NOT NULL, did text NOT NULL, atype text NOT NULL, aid text NOT NULL,
  PRIMARY KEY (dtype, did, atype, aid));
CREATE INDEX ON {f("")} (atype, aid);
{chr(10).join(f"CREATE INDEX ON {f('')} ((did::{t.pktype})) WHERE dtype = {lit(t.name)};" for t in types if t.pktype != "text")}
INSERT INTO authz_int.locks SELECT x, 0 FROM unnest(ARRAY[{", ".join(lit(m) for m in members)}]) x ON CONFLICT DO NOTHING;
{self.swap_in_kept(name)}

-- walk up from the given nodes; a link is followed only if its condition holds on
-- the child, and the parent exists and passes its type's where
CREATE FUNCTION {f("_compute")}(p_types text[], p_ids text[])
RETURNS TABLE (o_dtype text, o_did text, o_atype text, o_aid text)
LANGUAGE sql STABLE {DEFINER} AS $f$
  WITH RECURSIVE up(_dt, _d, _at, _a) AS (
    SELECT n.t, n.i, n.t, n.i FROM unnest(p_types, p_ids) AS n(t, i)
    WHERE CASE n.t {exists_case} ELSE false END
    UNION
    SELECT up._dt, up._d, e.pt, e.p
    FROM up CROSS JOIN LATERAL (
      {chr(10) + "      UNION ALL ".join(up_steps)}) e)
  SELECT _dt, _d, _at, _a FROM up
$f$;"""
        ]

        views: list[str] = []
        cond_rows: list[str] = []
        for t in types:
            if tracked[t.name]:
                on_r = ", ".join(f"coalesce(({on_row(c, 'r')}), false)" for c in tracked[t.name])
                cond_rows.append(
                    f"SELECT {lit(t.name)}::text AS t, {self.key_text(t, 'r')} AS id, "
                    f"ARRAY[{on_r}] AS v FROM {qt(t.table)} r"
                )
        if cond_rows:
            sql.append(f"""-- the conditions on each node (and its type's where)
CREATE VIEW {f("_conds")} AS
  {chr(10) + "  UNION ALL ".join(cond_rows)};""")
            views.append(f("_conds"))
        if views or link_wheres:
            if not views:
                sql.append(
                    f"CREATE VIEW {f('_conds')} AS SELECT NULL::text AS t, NULL::text AS id, NULL::boolean[] AS v WHERE false;"
                )
                views.append(f("_conds"))
            conds_list = [
                (self.T(tn).table, c, self.cond_lines.get((tn, c), self.T(tn).loc))
                for tn, cs in tracked.items()
                for c in cs
            ]
            sql.append(self.tree_checks(conds_list, link_wheres, views, first_line))
        if reads:
            sql.append(f"CREATE TABLE {f('_cond_cache')} (t text, id text, v boolean[] NOT NULL, PRIMARY KEY (t, id));")
        cache_refresh = (
            f"""
  DELETE FROM {f("_cond_cache")} k WHERE (k.t, k.id) IN (SELECT * FROM unnest(a_t, a_i));
  INSERT INTO {f("_cond_cache")} SELECT c.t, c.id, c.v FROM {f("_conds")} c
  WHERE (c.t, c.id) IN (SELECT * FROM unnest(a_t, a_i));"""
            if reads
            else ""
        )
        cache_rebuild = (
            f"""
  DELETE FROM {f("_cond_cache")};
  INSERT INTO {f("_cond_cache")} SELECT t, id, v FROM {f("_conds")};"""
            if reads
            else ""
        )
        cache_verify = (
            f"""
     AND NOT EXISTS ((SELECT t, id, v FROM {f("_conds")} EXCEPT SELECT t, id, v FROM {f("_cond_cache")})
                     UNION ALL
                     (SELECT t, id, v FROM {f("_cond_cache")} EXCEPT SELECT t, id, v FROM {f("_conds")}))"""
            if reads
            else ""
        )

        sql.append(f"""-- recompute the given nodes and everything linked below them
CREATE FUNCTION {f("_refresh")}(p_types text[], p_ids text[]) RETURNS void
LANGUAGE plpgsql {DEFINER} AS $f$
DECLARE a_t text[]; a_i text[];
BEGIN
  IF coalesce(cardinality(p_ids), 0) = 0 THEN RETURN; END IF;
  {lock}
  WITH RECURSIVE down(_t, _i) AS (
    SELECT x.t, x.i FROM unnest(p_types, p_ids) AS x(t, i) WHERE x.i IS NOT NULL
    UNION
    SELECT e.ct, e.c FROM down CROSS JOIN LATERAL (
      {chr(10) + "      UNION ALL ".join(down_steps) if down_steps else "SELECT NULL::text AS ct, NULL::text AS c WHERE false"}) e)
  SELECT array_agg(_t), array_agg(_i) INTO a_t, a_i FROM down;
  DELETE FROM {f("")} WHERE (dtype, did) IN (SELECT * FROM unnest(a_t, a_i));
  INSERT INTO {f("")} SELECT * FROM {f("_compute")}(a_t, a_i);{cache_refresh}
  PERFORM authz_int.changed(x.t, array_agg(x.i), 'inheritance') FROM unnest(a_t, a_i) x(t, i) GROUP BY x.t;
END $f$;

-- recompute everything (backfill, TRUNCATE), {BATCH} nodes at a time
CREATE FUNCTION {f("_rebuild")}() RETURNS void
LANGUAGE plpgsql {DEFINER} AS $f$
DECLARE a_t text[]; a_i text[];
BEGIN
  {lock}
  DELETE FROM {f("")};
  FOR a_t, a_i IN {batches} LOOP
    INSERT INTO {f("")} SELECT * FROM {f("_compute")}(a_t, a_i);
  END LOOP;{cache_rebuild}
END $f$;
CREATE FUNCTION {f("_on_truncate")}() RETURNS trigger
LANGUAGE plpgsql {DEFINER} AS $f$
BEGIN PERFORM {f("_rebuild")}(); RETURN NULL; END $f$;

-- what a rebuild would give against what is stored, {BATCH} nodes at a time; then nothing stored for a node
-- that is gone
CREATE FUNCTION {f("_verify")}() RETURNS boolean
LANGUAGE plpgsql STABLE {DEFINER} AS $f$
DECLARE a_t text[]; a_i text[];
BEGIN
  FOR a_t, a_i IN {batches} LOOP
    IF EXISTS (WITH fresh AS MATERIALIZED (SELECT * FROM {f("_compute")}(a_t, a_i)),
                    stored AS MATERIALIZED (SELECT * FROM {f("")}
                                            WHERE (dtype, did) IN (SELECT * FROM unnest(a_t, a_i)))
               (SELECT * FROM fresh EXCEPT SELECT * FROM stored)
               UNION ALL
               (SELECT * FROM stored EXCEPT SELECT * FROM fresh)) THEN
      RETURN false;
    END IF;
  END LOOP;
  IF EXISTS (SELECT 1 FROM (SELECT DISTINCT dtype AS t, did AS i FROM {f("")}) n
             WHERE NOT CASE n.t {exists_case} ELSE false END) THEN
    RETURN false;
  END IF;
  RETURN true{cache_verify};
END $f$;""")

        if reads:
            sql.append(f"""CREATE FUNCTION {f("_recheck")}() RETURNS void
LANGUAGE plpgsql {DEFINER} AS $f$
DECLARE a_t text[]; a_i text[];
BEGIN
  {lock}
  SELECT array_agg(coalesce(c.t, k.t)), array_agg(coalesce(c.id, k.id)) INTO a_t, a_i
  FROM {f("_conds")} c FULL JOIN {f("_cond_cache")} k ON k.t = c.t AND k.id = c.id
  WHERE c.v IS DISTINCT FROM k.v;
  PERFORM {f("_refresh")}(a_t, a_i);
END $f$;
CREATE FUNCTION {f("_on_deps")}() RETURNS trigger
LANGUAGE plpgsql {DEFINER} AS $f$
BEGIN PERFORM {f("_recheck")}(); RETURN NULL; END $f$;""")
            sql.append(self.deps_sql(name, f("_conds"), [qt(t.table) for t in types], first_line, f("_on_deps")))

        if loop_steps:
            sql.append(f"""-- the types' own columns may not loop (links through tables may: they add nothing)
CREATE FUNCTION {f("_check_loops")}(p_types text[], p_ids text[]) RETURNS void
LANGUAGE plpgsql {DEFINER} AS $f$
DECLARE bad text;
BEGIN
  -- a loop means some node reaches itself through at least one link
  WITH RECURSIVE up(_st, _s, _at, _a, _n) AS (
    SELECT x.t, x.i, x.t, x.i, 0 FROM unnest(p_types, p_ids) AS x(t, i)
    UNION
    SELECT up._st, up._s, e.pt, e.p, 1 FROM up CROSS JOIN LATERAL (
      {chr(10) + "      UNION ALL ".join(loop_steps)}) e)
  SELECT _st || ' ' || _s INTO bad FROM up WHERE _n = 1 AND (_at, _a) = (_st, _s) LIMIT 1;
  IF bad IS NOT NULL THEN
    RAISE EXCEPTION '% cannot be moved inside itself', bad USING ERRCODE = 'check_violation', HINT = 'rowstile help AZ713';
  END IF;
END $f$;""")

        for t in types:
            kt: Callable[[str], str] = lambda a, t=t: self.key_text(t, a)
            key: Callable[[str], str] = lambda a, t=t: self.key(t, a)
            changes = col_changes[t.name] + [
                f"(SELECT coalesce(({on_row(c, 'r')}), false) FROM (SELECT n.*) r) IS DISTINCT FROM "
                f"(SELECT coalesce(({on_row(c, 'r')}), false) FROM (SELECT o.*) r)"
                for c in tracked[t.name]
            ]
            changed = "\n         OR ".join(dict.fromkeys(changes)) or "false"
            loops = (
                (
                    f"\n    IF TG_OP <> 'DELETE' THEN PERFORM {f('_check_loops')}"
                    f"(array_fill({lit(t.name)}::text, ARRAY[cardinality(ids)]), ids); END IF;"
                )
                if loop_steps
                else ""
            )
            sfx = f"_rows_{t.name}"
            sql.append(f"""-- {t.name} rows inserted, deleted, moved, or whose id or conditions change
CREATE FUNCTION {f(sfx)}() RETURNS trigger
LANGUAGE plpgsql {DEFINER} AS $f$
DECLARE ids text[];
BEGIN
  IF TG_OP = 'INSERT' THEN
    ids := ARRAY(SELECT {kt("n")} FROM new_rows n);
  ELSIF TG_OP = 'UPDATE' THEN
    ids := ARRAY(
      SELECT {kt("n")} FROM new_rows n JOIN old_rows o ON {key("o")} = {key("n")}
      WHERE {changed}
      UNION SELECT {kt("o")} FROM old_rows o WHERE NOT EXISTS (SELECT 1 FROM new_rows n WHERE {key("n")} = {key("o")})
      UNION SELECT {kt("n")} FROM new_rows n WHERE NOT EXISTS (SELECT 1 FROM old_rows o WHERE {key("o")} = {key("n")}));
  ELSE
    ids := ARRAY(SELECT {kt("o")} FROM old_rows o);
  END IF;
  IF cardinality(ids) > 0 THEN
    {lock}{loops}
    PERFORM {f("_refresh")}(array_fill({lit(t.name)}::text, ARRAY[cardinality(ids)]), ids);
  END IF;{f"{chr(10)}  PERFORM {f('_recheck')}();" if reads else ""}
  RETURN NULL;
END $f$;
CREATE TRIGGER {trig(sfx + "_ins")} AFTER INSERT ON {qt(t.table)}
  REFERENCING NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION {f(sfx)}();
CREATE TRIGGER {trig(sfx + "_upd")} AFTER UPDATE ON {qt(t.table)}
  REFERENCING OLD TABLE AS old_rows NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION {f(sfx)}();
CREATE TRIGGER {trig(sfx + "_del")} AFTER DELETE ON {qt(t.table)}
  REFERENCING OLD TABLE AS old_rows FOR EACH STATEMENT EXECUTE FUNCTION {f(sfx)}();
CREATE TRIGGER {trig(sfx + "_trunc")} AFTER TRUNCATE ON {qt(t.table)}
  FOR EACH STATEMENT EXECUTE FUNCTION {f("_on_truncate")}();""")

        for i, (ltable, pairs) in enumerate(sorted(link_tables.items())):
            sel: Callable[[str], str] = lambda rows, pairs=pairs: " UNION ".join(
                f"SELECT {lit(ct)}::text AS t, {self.ref_text(self.T(ct), 'x', c)} AS i FROM {rows} x"
                for c, ct in sorted(pairs, key=lambda p: (cols(p[0]), p[1]))
            )
            sfx = f"_on_links{i + 1}"
            sql.append(f"""-- links stored in {ltable}
CREATE FUNCTION {f(sfx)}() RETURNS trigger
LANGUAGE plpgsql {DEFINER} AS $f$
DECLARE a_t text[]; a_i text[];
BEGIN
  IF TG_OP IN ('INSERT', 'UPDATE') THEN
    SELECT array_agg(t), array_agg(i) INTO a_t, a_i FROM ({sel("new_rows")}) y;
    PERFORM {f("_refresh")}(a_t, a_i);
  END IF;
  IF TG_OP IN ('DELETE', 'UPDATE') THEN
    SELECT array_agg(t), array_agg(i) INTO a_t, a_i FROM ({sel("old_rows")}) y;
    PERFORM {f("_refresh")}(a_t, a_i);
  END IF;
  RETURN NULL;
END $f$;
CREATE TRIGGER {trig(sfx + "_ins")} AFTER INSERT ON {qt(ltable)}
  REFERENCING NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION {f(sfx)}();
CREATE TRIGGER {trig(sfx + "_upd")} AFTER UPDATE ON {qt(ltable)}
  REFERENCING OLD TABLE AS old_rows NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION {f(sfx)}();
CREATE TRIGGER {trig(sfx + "_del")} AFTER DELETE ON {qt(ltable)}
  REFERENCING OLD TABLE AS old_rows FOR EACH STATEMENT EXECUTE FUNCTION {f(sfx)}();
CREATE TRIGGER {trig(sfx + "_trunc")} AFTER TRUNCATE ON {qt(ltable)}
  FOR EACH STATEMENT EXECUTE FUNCTION {f("_on_truncate")}();""")

        if share_keys:
            refresh = lambda rows: (
                f"SELECT array_agg(y.object_type), array_agg(y.object_id) INTO a_t, a_i "
                f"FROM ({rows}) y;\n    PERFORM {f('_refresh')}(a_t, a_i);"
            )
            sql.append(self.shares_guard_sql(name, f, trig, share_keys, refresh))

        self.remember_tree(
            name, sql, [t.table for t in types] + list(link_tables) + (["authz.shares"] if share_keys else []), reads
        )
        sql.append(self.backfill_sql(name, f))
        self.tree_sql.append("\n\n".join(sql))
        self.tree_names.append(name)
        return name

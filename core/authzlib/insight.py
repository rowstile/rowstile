"""Answers about access: who holds a permission, and why (or why not)."""

from __future__ import annotations

import re

from .compiler import Core, only_on
from .parse import KEYWORDS, And, Arrow, ArrowOn, Cond, Expr, Not, Or, Ref, Relation, Source, Type
from .sqlutil import lit, q, qt, row_cond, union

DEFINER_FROM_CURRENT = "SECURITY DEFINER SET search_path FROM CURRENT"
# a condition the policy wrote as a word (signed_in, anyone, nobody), said as that word
WORD_OF = {sql: word for word, sql in KEYWORDS.items()}
USER_DEPENDENT = re.compile(
    r"\bauthz\s*\.\s*(uid|me|ctx)\b|\bcurrent_setting\b|\bcurrent_user\b|\bsession_user\b", re.IGNORECASE
)


def expr_text(node: Expr) -> str:
    """An item of what the policy wrote (never the compiler's own arrow_on: it is only ever a starting point)."""
    match node:
        case Ref(name):
            return name if not name.startswith("roles:") else "a custom role"
        case Arrow(rel, perm):
            return f"{rel}.{perm}"
        case Cond(sql):
            return WORD_OF.get(sql, "{" + sql + "}")
        case Not(item):
            return "not " + expr_text(item)
        case _:
            assert isinstance(node, (And, Or)), f"not an expression: {node!r}"
            return "(" + (" or " if isinstance(node, Or) else " and ").join(expr_text(x) for x in node.items) + ")"


class InsightMixin(Core):
    # ------------------------------------------------------------------
    # who: candidates (a superset, from the data), then each one checked
    # ------------------------------------------------------------------
    def who_fn(self, t: Type, name: str) -> str:
        return f"authz_int.{q(t.name + '__' + name + '__who')}"

    def who_base_fn(self, t: Type, name: str) -> str:
        return f"authz_int.{q(t.name + '__' + name + '__who_base')}"

    def all_users(self) -> str:
        u = self.T("user")
        return f"SELECT u.{q(self.pk(u))} FROM {qt(u.table)} u"

    def who_items(self, t: Type, node: Expr, obj: str) -> str | None:
        """SQL of the user ids that may hold node on object obj; None: anyone may (a condition decides)."""
        match node:
            case Ref(name):
                return f"SELECT x FROM {self.who_fn(t, name)}({obj}) x"
            case Arrow(rel, perm) | ArrowOn(rel, perm, _):
                r, targets = self.targets(t, rel, t.loc)
                on = only_on(node)
                names = on if on is not None else [x.name for x in targets]
                parts = []
                for st in names:
                    fn = self.who_fn(self.T(st), perm)
                    for src in r.sources:
                        if (st, None) not in src.subjects:
                            continue
                        for tsql in self.target_sql(t, r, src, st, obj):
                            parts.append(f"SELECT x FROM ({tsql}) tg, LATERAL {fn}(tg.id) x")
                return union(parts) if parts else f"SELECT NULL::{self.T('user').pktype} WHERE false"
            case Cond(_) | Not(_):
                return None
            case And(items):
                sets = [s for s in (self.who_items(t, x, obj) for x in items) if s is not None]
                if not sets:
                    return None
                return sets[0] if len(sets) == 1 else " INTERSECT ".join(f"({x})" for x in sets)
            case _:
                assert isinstance(node, Or), f"not an expression: {node!r}"
                found = [self.who_items(t, x, obj) for x in node.items]
                if any(s is None for s in found):
                    return None
                return union([s for s in found if s is not None])

    def target_sql(self, t: Type, r: Relation, src: Source, st: str, obj: str) -> list[str]:
        """Ids of the st objects that r links object obj to, through one source."""
        s = self.T(st)
        if src.kind == "column":
            sid = self.subject_id(src, "r", st)
            return [f"SELECT {sid} AS id FROM {qt(t.table)} r WHERE {self.key_is(t, 'r', obj)} AND {sid} IS NOT NULL"]
        if src.kind == "table":
            sid = self.subject_id(src, "s", st)
            where = f" AND coalesce(({row_cond(src.where, 's')}), false)" if src.where else ""
            return [
                f"SELECT {sid} AS id FROM {qt(self.source_table(src))} s WHERE {self.key_is(t, 's', obj, src.obj_col)} "
                f"AND {sid} IS NOT NULL{where}"
            ]
        assert src.kind == "shared", f"a {src.kind} source"  # (an arrow follows no custom roles' relation)
        return [
            f"SELECT g.subject_id::{s.pktype} AS id FROM authz.shares g WHERE g.object_type = {lit(t.name)} "
            f"AND g.object_id = ({obj})::text AND g.relation = {lit(r.name)} AND g.subject_type = {lit(st)} "
            f"AND g.subject_relation = ''"
        ]

    def rel_who_sql(self, t: Type, r: Relation, obj: str) -> str:
        """Users that may hold relation r on object obj (nested groups expanded)."""
        loops = [
            src for src in r.sources for st, sr in src.subjects if sr and sr != "*" and self.is_group_loop(t, r, st, sr)
        ]
        if not loops:
            return self.rel_who_direct(t, r, obj)
        # nested groups: every sub-group, to any depth, then their members
        pairs = union([self.pair_sql(t, r, src, t.name, r.name, "obj", "subj") for src in loops])
        return (
            f"WITH RECURSIVE gs(id) AS (SELECT {obj} UNION SELECT e.subj FROM ({pairs}) e JOIN gs ON e.obj = gs.id)\n"
            f"  SELECT x FROM gs, LATERAL ({self.rel_who_direct(t, r, 'gs.id')}) w(x)"
        )

    def rel_who_direct(self, t: Type, r: Relation, obj: str) -> str:
        u = self.T("user")
        parts: list[str] = []
        for src in r.sources:
            for st, sr in src.subjects:
                if sr and sr != "*" and self.is_group_loop(t, r, st, sr):
                    continue
                if src.kind == "column":
                    col = self.subject_id(src, "r", st)
                    if (st, sr) == ("user", None):
                        parts.append(
                            f"SELECT {col} FROM {qt(t.table)} r WHERE {self.key_is(t, 'r', obj)} AND {col} IS NOT NULL"
                        )
                    elif sr:
                        parts.append(
                            f"SELECT x FROM {qt(t.table)} r, LATERAL {self.who_fn(self.T(st), sr)}({col}) x "
                            f"WHERE {self.key_is(t, 'r', obj)}"
                        )
                elif src.kind == "table":
                    col = self.subject_id(src, "s", st)
                    where = f" AND coalesce(({row_cond(src.where, 's')}), false)" if src.where else ""
                    if (st, sr) == ("user", None):
                        parts.append(
                            f"SELECT {col} FROM {qt(self.source_table(src))} s WHERE {self.key_is(t, 's', obj, src.obj_col)}{where}"
                        )
                    elif sr:
                        parts.append(
                            f"SELECT x FROM {qt(self.source_table(src))} s, LATERAL {self.who_fn(self.T(st), sr)}({col}) x "
                            f"WHERE {self.key_is(t, 's', obj, src.obj_col)}{where}"
                        )
                else:
                    rel = self.role_rel_sql(t, src, obj) if src.kind == "roles" else f"g.relation = {lit(r.name)}"
                    gw = f"g.object_type = {lit(t.name)} AND g.object_id = ({obj})::text AND {rel}"
                    if (st, sr) == ("user", None):
                        parts.append(
                            f"SELECT g.subject_id::{u.pktype} FROM authz.shares g WHERE {gw} "
                            f"AND g.subject_type = 'user' AND g.subject_relation = '' AND g.subject_id <> '*'"
                        )
                    elif (st, sr) == ("user", "*") or st == "anyone":
                        stype = "user" if st == "user" else "anyone"
                        parts.append(
                            f"SELECT u.{q(self.pk(u))} FROM {qt(u.table)} u WHERE EXISTS (SELECT 1 FROM authz.shares g "
                            f"WHERE {gw} AND g.subject_type = {lit(stype)} AND g.subject_id = '*')"
                        )
                    elif sr == "*":
                        continue  # every signed-in service: no users (authz.who lists users)
                    elif sr:
                        parts.append(
                            f"SELECT x FROM authz.shares g, LATERAL {self.who_fn(self.T(st), sr)}"
                            f"(g.subject_id::{self.T(st).pktype}) x WHERE {gw} AND g.subject_type = {lit(st)} "
                            f"AND g.subject_relation = {lit(sr)}"
                        )
        return union(parts) if parts else f"SELECT NULL::{u.pktype} WHERE false"

    def who_sql(self) -> list[str]:
        """One function per relation and permission: users that may hold it on an
        object (a superset; authz.who checks each one)."""
        u = self.T("user")
        out: list[str] = []
        for t in self.types.values():
            for r in t.relations.values():
                if all(sr is None and st in self.types and not self.T(st).principal for st, sr in r.subjects()):
                    continue  # links to objects: nobody holds them
                out.append(
                    f"CREATE FUNCTION {self.who_fn(t, r.name)}(p_id {t.pktype}) RETURNS SETOF {u.pktype}\n"
                    f"LANGUAGE sql STABLE STRICT {DEFINER_FROM_CURRENT} ROWS 50 AS $f$\n"
                    f"  {self.rel_who_sql(t, r, 'p_id')}\n$f$;"
                )
        for t in self.types.values():
            for p in t.perms.values():
                key = self.recursive.get((t.name, p.name))
                if key is None:
                    sql = self.who_items(t, p.expr, "p_id")
                    body = self.all_users() if sql is None else sql
                    out.append(
                        f"CREATE FUNCTION {self.who_fn(t, p.name)}(p_id {t.pktype}) RETURNS SETOF {u.pktype}\n"
                        f"LANGUAGE sql STABLE STRICT {DEFINER_FROM_CURRENT} ROWS 50 AS $f$\n  {body}\n$f$;"
                    )
                    continue
                items = self.base_items(t, p)
                parts = [self.who_items(t, i, "p_id") for i in items]
                base = (
                    self.all_users()
                    if any(s is None for s in parts)
                    else union([s for s in parts if s is not None])
                    if parts
                    else f"SELECT NULL::{u.pktype} WHERE false"
                )  # a loop's member that only inherits
                out.append(
                    f"CREATE FUNCTION {self.who_base_fn(t, p.name)}(p_id {t.pktype}) RETURNS SETOF {u.pktype}\n"
                    f"LANGUAGE sql STABLE STRICT {DEFINER_FROM_CURRENT} ROWS 50 AS $f$\n  {base}\n$f$;"
                )
                members = self.scc_members[key]
                if len(members) == 1:
                    tree = self.trees[(t.name, self.scc_edges(key))]
                    body = (
                        f"SELECT x FROM authz_int.{q(tree)} c, LATERAL {self.who_base_fn(t, p.name)}(c.ancestor) x "
                        f"WHERE c.descendant = p_id"
                    )
                else:
                    tree = self.trees[key]
                    body = "\n  UNION ALL\n  ".join(
                        f"SELECT x FROM authz_int.{q(tree)} c, LATERAL {self.who_base_fn(self.T(mt), mp)}"
                        f"((CASE WHEN c.atype = {lit(mt)} THEN c.aid END)::{self.T(mt).pktype}) x "
                        f"WHERE c.dtype = {lit(t.name)} AND c.did = p_id::text"
                        for mt, mp in members
                    )
                out.append(
                    f"CREATE FUNCTION {self.who_fn(t, p.name)}(p_id {t.pktype}) RETURNS SETOF {u.pktype}\n"
                    f"LANGUAGE sql STABLE STRICT {DEFINER_FROM_CURRENT} ROWS 50 AS $f$\n  {body}\n$f$;"
                )
        return out

    # ------------------------------------------------------------------
    # why: the path that grants a permission (or what is missing)
    # ------------------------------------------------------------------
    def visible_sql(self) -> str:
        """authz_int.visible(type, id): the object is there and the signed-in user may select it (its table's
        select rule and scopes; a table without rules is readable). What explain shows, and where its walk stops:
        a row the user can't see reads as a missing one, whatever else they hold on it."""
        cases = []
        for t in self.types.values():
            alias = q(t.table.split(".")[1])
            rules = [r for r in self.rules if r.table == t.table]
            sel = next((r for r in rules if r.command == "select" and not r.columns), None)
            if rules and sel is None:
                cond = "false"  # row-level security on, and no select rule: nobody sees a row
            elif sel is not None:
                cond = (
                    f"(SELECT authz_int.scope_cmd({lit(t.table)}, 'select')) AND "
                    f"{self.rule_sql(t, alias, sel, point=True)}"
                )
            else:
                cond = f"coalesce(({row_cond(t.where, alias)}), false)" if t.where else "true"
            find = self.key_is(t, alias, "p_id" if t.composite else f"p_id::{t.pktype}")
            cases.append(
                f"    WHEN {lit(t.name)} THEN\n      RETURN EXISTS (SELECT 1 FROM {qt(t.table)} {alias} "
                f"WHERE {find}\n        AND {cond});"
            )
        return f"""-- May the signed-in user see this object (select it)? A hidden object reads as a missing one
CREATE FUNCTION authz_int.visible(p_type text, p_id text) RETURNS boolean
LANGUAGE plpgsql STABLE {DEFINER_FROM_CURRENT} AS $f$
BEGIN
  IF NOT coalesce(pg_catalog.pg_input_is_valid(p_id, (SELECT keytype FROM authz_int.types WHERE name = p_type)), false) THEN
    RETURN false;
  END IF;
  CASE p_type
{chr(10).join(cases)}
    ELSE RETURN false;
  END CASE;
END $f$;"""

    def why_fn(self, t: Type, name: str) -> str:
        return f"authz_int.{q(t.name + '__' + name + '__why')}"

    def holds_sql(self, t: Type, node: Expr, obj: str) -> str:
        return f"({obj}) IN ({self.set_sql(t, node, t.loc)})"

    def why_item_sql(self, t: Type, node: Expr, obj: str, nested: bool = False) -> str:
        """plpgsql statements explaining one item: 'yes'/'no' and, when it holds, how.
        At the top level only the first item that holds is explained in depth."""
        text = lit(expr_text(node).replace("__base", " (before the deny)"))  # split_denies' hidden permission
        pad = "pad || '  '" if nested else "pad"
        depth = "p_depth + 2" if nested else "p_depth + 1"
        go = "v_ok AND v_holds" if nested else "v_ok AND NOT v_done"
        mark = "" if nested else "v_done := true; "
        code = (
            f"    v_ok := {self.holds_sql(t, node, obj)};\n"
            f"    RETURN NEXT {pad} || CASE WHEN v_ok THEN 'yes  ' ELSE 'no   ' END || {text};\n"
        )
        match node:
            case Ref(name):
                return code + (
                    f"    IF {go} THEN {mark}RETURN QUERY SELECT * FROM {self.why_fn(t, name)}"
                    f"({obj}, {depth}, p_seen); END IF;\n"
                )
            case Arrow(rel, perm) | ArrowOn(rel, perm, _):
                return code + self.why_arrow_sql(t, node, rel, perm, obj, pad, go, mark, depth)
            case And(items) | Or(items) if not nested:
                return code + "".join(self.why_item_sql(t, x, obj, nested=True) for x in items)
        return code

    def why_arrow_sql(
        self, t: Type, node: Expr, rel: str, perm: str, obj: str, pad: str, go: str, mark: str, depth: str
    ) -> str:
        """why_item_sql for rel.perm: the objects rel links to, whether each has perm, and why."""
        r, targets = self.targets(t, rel, t.loc)
        on = only_on(node)
        names = on if on is not None else [x.name for x in targets]
        loops = []
        for st in names:
            s = self.T(st)
            view = self.view_ref(s, perm, s.loc)
            tag = lit(st + ":" + perm + ":")
            for src in r.sources:
                if (st, None) not in src.subjects:
                    continue
                for tsql in self.target_sql(t, r, src, st, obj):
                    loops.append(f"""    FOR v_t IN SELECT tg.id::text AS id, EXISTS (SELECT 1 FROM authz_int.{q(view)} v WHERE v.id = tg.id) AS ok
               FROM ({tsql}) tg ORDER BY 2 DESC, 1 LIMIT 5 LOOP
      -- the walk stops at an object the user can't see: nothing about it, or above it
      IF NOT authz_int.visible({lit(st)}, v_t.id) THEN
        RETURN NEXT {pad} || '       ' || {lit(rel + (" is an " if st[0] in "aeiou" else " is a ") + st + " you can" + chr(39) + "t see")};
        CONTINUE;
      END IF;
      RETURN NEXT {pad} || '  ' || CASE WHEN v_t.ok THEN 'yes  ' ELSE 'no   ' END || {lit(rel + " is " + st + " ")}
                  || v_t.id || CASE WHEN v_t.ok THEN {lit(", which has " + perm)} ELSE {lit(", without " + perm)} END;
      IF NOT ({tag} || v_t.id = ANY (p_seen)) AND ((v_t.ok AND {go}) OR (NOT v_ok AND NOT v_t.ok AND p_depth < 5)) THEN
        {mark}RETURN QUERY SELECT * FROM {self.why_fn(s, perm)}(v_t.id::{s.pktype}, {depth} + 1, p_seen || ({tag} || v_t.id));
      END IF;
    END LOOP;
""")
        return "".join(loops)

    def why_sql(self) -> list[str]:
        """One function per relation and permission explaining it for the current user."""
        out: list[str] = []
        for t in self.types.values():
            where = (
                (
                    f"  IF NOT EXISTS (SELECT 1 FROM {qt(t.table)} w WHERE {self.key_is(t, 'w', 'p_id')} "
                    f"AND coalesce(({row_cond(t.where, 'w')}), false)) THEN\n"
                    f"    RETURN NEXT pad || 'no   {t.name} ' || p_id || ' fails the type''s where {{' || "
                    f"{lit(t.where)} || '}}';\n    RETURN;\n  END IF;\n"
                )
                if t.where
                else ""
            )
            for r in t.relations.values():
                out.append(self.rel_why_sql(t, r, where))
            for p in t.perms.values():
                items = self.top_items(p)
                body = "".join(self.why_item_sql(t, i, "p_id") for i in items)
                out.append(f"""CREATE FUNCTION {self.why_fn(t, p.name)}(p_id {t.pktype}, p_depth int, p_seen text[])
RETURNS SETOF text LANGUAGE plpgsql STABLE {DEFINER_FROM_CURRENT} AS $f$
DECLARE pad text := repeat('  ', p_depth); v_ok boolean; v_done boolean := false; v_t record;
        v_holds boolean := p_id IN (SELECT id FROM authz_int.{q(t.name + "__" + p.name)});
BEGIN
  IF p_depth > 60 THEN RETURN NEXT pad || '...'; RETURN; END IF;
{where}  RETURN NEXT pad || {lit(t.name + "." + p.name + " = " + p.src.replace("  (or a custom role)", " or a custom role"))};
  BEGIN
{body}  END;
END $f$;""")
        return out

    def rel_why_sql(self, t: Type, r: Relation, where: str) -> str:
        """Which source gives the current user relation r on an object."""
        lines: list[str] = []
        for src in r.sources:
            for st, sr in src.subjects:
                if sr and sr != "*" and self.is_group_loop(t, r, st, sr):
                    pairs = self.pair_sql(t, r, src, t.name, r.name, "obj", "subj")
                    view = f"{t.name}__{r.name}"
                    lines.append(f"""  FOR v_t IN SELECT e.subj::text AS id FROM ({pairs}) e
             WHERE e.obj = p_id AND EXISTS (SELECT 1 FROM authz_int.{q(view)} v WHERE v.id = e.subj) LIMIT 1 LOOP
    IF NOT ({lit(t.name + ":" + r.name + ":")} || v_t.id = ANY (p_seen)) THEN
      RETURN NEXT pad || 'yes  through {t.name} ' || v_t.id || ', whose {r.name} count here too';
      RETURN QUERY SELECT * FROM {self.why_fn(t, r.name)}(v_t.id::{t.pktype}, p_depth + 1,
                                 p_seen || ({lit(t.name + ":" + r.name + ":")} || v_t.id));
      RETURN;
    END IF;
  END LOOP;""")
                    continue
                part = self.source_sql(t, r, src, (st, sr))
                if not part:
                    continue
                how = self.source_text(t, r, src, st, sr).rstrip()
                if sr and sr != "*" and st in self.types:
                    s = self.T(st)
                    gids = self.group_ids_sql(t, r, src, st, sr)
                    lines.append(f"""  IF p_id IN ({part}) THEN
    FOR v_t IN SELECT x.gid::text AS gid FROM ({gids}) x LIMIT 1 LOOP
      RETURN NEXT pad || 'yes  ' || {lit(how)} || ' {st} ' || v_t.gid || ', and you are {sr} there';
      RETURN QUERY SELECT * FROM {self.why_fn(s, sr)}(v_t.gid::{s.pktype}, p_depth + 1, p_seen);
    END LOOP;
    RETURN;
  END IF;""")
                else:
                    detail = self.share_detail_sql(t, r, src, st, sr) if src.kind in ("shared", "roles") else "''"
                    lines.append(f"""  IF p_id IN ({part}) THEN
    RETURN NEXT pad || 'yes  ' || {lit(how)} || {detail};
    RETURN;
  END IF;""")
        body = "\n".join(lines)
        return f"""CREATE FUNCTION {self.why_fn(t, r.name)}(p_id {t.pktype}, p_depth int, p_seen text[])
RETURNS SETOF text LANGUAGE plpgsql STABLE {DEFINER_FROM_CURRENT} AS $f$
DECLARE pad text := repeat('  ', p_depth); v_t record;
BEGIN
{where}{body}
  RETURN NEXT pad || 'no   you do not hold {t.name}.{r.name if not r.synthetic else "role"}';
END $f$;"""

    def group_ids_sql(self, t: Type, r: Relation, src: Source, st: str, sr: str) -> str:
        """The groups (st objects) through which the current user holds r on p_id."""
        view = self.view_ref(self.T(st), sr, self.T(st).loc)
        if src.kind == "column":
            col = self.subject_id(src, "r", st)
            return (
                f"SELECT {col} AS gid FROM {qt(t.table)} r WHERE {self.key_is(t, 'r', 'p_id')} "
                f"AND {col} IN (SELECT id FROM authz_int.{q(view)})"
            )
        if src.kind == "table":
            col = self.subject_id(src, "s", st)
            assert src.table is not None
            return (
                f"SELECT {col} AS gid FROM {qt(self.source_table(src))} s WHERE {self.key_is(t, 's', 'p_id', src.obj_col)} "
                f"AND {col} IN (SELECT id FROM authz_int.{q(view)})"
            )
        rel = self.role_rel_sql(t, src, "p_id") if src.kind == "roles" else f"g.relation = {lit(r.name)}"
        return (
            f"SELECT g.subject_id AS gid FROM authz.shares g WHERE g.object_type = {lit(t.name)} "
            f"AND g.object_id = p_id::text AND {rel} AND g.subject_type = {lit(st)} AND g.subject_relation = {lit(sr)} "
            f"AND g.subject_id IN (SELECT id::text FROM authz_int.{q(view)}) AND {self.live()}"
        )

    def source_text(self, t: Type, r: Relation, src: Source, st: str, sr: str | None) -> str:
        name = r.name if not r.synthetic else "a custom role"
        if src.kind == "column":
            column = self.source_columns(src)
            shown = column if isinstance(column, str) else "[" + ", ".join(column) + "]"
            col = f"({src.type_col}, {shown})" if src.type_col else shown
            return f"{name}: {col} is " + ("you" if (st, sr) == ("user", None) else "")
        if src.kind == "table":
            base = f"{name}: a row in {src.table}"
            return base + (" names you" if (st, sr) == ("user", None) else " names")
        if src.kind == "roles":
            return f"{name} given to " + ("you" if (st, sr) == ("user", None) else "")
        if sr == "*":
            return f"{name}: shared with every signed-in {st}"
        if st == "anyone":
            return f"{name}: shared with anyone"
        if st == "link":
            return f"{name}: shared by a link you presented"
        return f"{name}: shared with " + ("you" if (st, sr) == ("user", None) else "")

    def share_detail_sql(self, t: Type, r: Relation, src: Source, st: str, sr: str | None) -> str:
        """' (by X, until Y, caveat Z)' for the share that gives the signed-in principal the relation: theirs (or the
        link they presented, the one to every signed-in user, to anyone), never another's."""
        who = self.share_subject_sql(st, sr, src)
        # (a share that can give no one signed in the relation, to a row of a type that doesn't sign in, has no
        # source_sql for them: why_sql skips it before asking for its details)
        assert who is not None, f"no share to {st} gives the relation {r.name}"
        rel = self.role_rel_sql(t, src, "p_id") if src.kind == "roles" else f"g.relation = {lit(r.name)}"
        role = (
            " || coalesce(' (role ' || (SELECT ro.name FROM authz.roles ro WHERE 'role:' || ro.id = g.relation) || ')', '')"
            if src.kind == "roles"
            else ""
        )
        return (
            f"coalesce((SELECT concat(' (by ', coalesce(g.created_by, 'an admin'), coalesce(', until ' || g.expires_at, ''), "
            f"coalesce(', from ' || g.starts_at, ''), coalesce(', caveat ' || g.caveat, ''), ')'){role} "
            f"FROM authz.shares g WHERE g.object_type = {lit(t.name)} AND g.object_id = p_id::text AND {rel} "
            f"AND {who} AND {self.live()} "
            f"ORDER BY g.created_at LIMIT 1), '')"
        )

    # ------------------------------------------------------------------
    # the API
    # ------------------------------------------------------------------
    def insight_api_sql(self) -> str:
        # a column, a link table or a share may name an id the user table doesn't have: nobody, not a user to list
        u = self.T("user")
        is_user = f"EXISTS (SELECT 1 FROM {qt(u.table)} u WHERE u.{q(self.pk(u))} = x)"

        # a type without permissions is still a type: asked for one, it has no such permission (as authz.list says)
        no_perm = "      RAISE EXCEPTION 'no permission %.% in the policy', p_type, p_perm USING HINT = 'rowstile help AZ707';"

        def who_branch(t: Type) -> str:
            if not t.perms:
                return no_perm
            cases = "\n".join(
                f"        WHEN {lit(p)} THEN\n"
                f"          FOR v_c IN SELECT DISTINCT x::text FROM {self.who_fn(t, p)}(v_{t.pktype}) x WHERE {is_user} LOOP\n"
                f"            PERFORM set_config('authz.user_id', v_c, true);\n"
                f"            PERFORM authz_int.sign();\n"
                f"            IF authz.can(p_type, p_id, p_perm) THEN RETURN NEXT v_c; END IF;\n"
                f"          END LOOP;"
                for p in self.public_perms(t)
            )
            return f"      CASE p_perm\n{cases}\n        ELSE RAISE EXCEPTION 'no permission %.% in the policy', p_type, p_perm USING HINT = 'rowstile help AZ707';\n      END CASE;"

        def why_branch(t: Type) -> str:
            if not t.perms:
                return no_perm
            cases = "\n".join(
                f"        WHEN {lit(p)} THEN RETURN QUERY SELECT * FROM {self.why_fn(t, p)}(v_{t.pktype}, 1, '{{}}');"
                for p in self.public_perms(t)
            )
            return f"      CASE p_perm\n{cases}\n        ELSE RAISE EXCEPTION 'no permission %.% in the policy', p_type, p_perm USING HINT = 'rowstile help AZ707';\n      END CASE;"

        self._invalid = "NULL"
        who_body = self.dispatch_type(who_branch).replace("RETURN NULL;", "RETURN;")
        why_body = self.dispatch_type(why_branch).replace("RETURN NULL;", "RETURN;")
        return f"""{self.visible_sql()}

-- May the current user look at who has access to this object? (they can share it, or the caller is an
-- administrator: the policy's owner, a superuser or BYPASSRLS)
CREATE FUNCTION authz_int.may_inspect(p_type text, p_id text) RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $f$
BEGIN
  IF authz_int.caller_is_admin() THEN RETURN true; END IF;
  RETURN EXISTS (SELECT 1 FROM authz_int.perms WHERE type = p_type AND perm = 'share')
     AND authz.can(p_type, p_id, 'share');
END $f$;

-- Everyone who holds a permission on an object: SELECT * FROM authz.who('folder', 3, 'view')
-- Candidates come from the data (a superset); each is checked with authz.can, as that user.
CREATE FUNCTION authz.who(p_type text, p_id text, p_perm text) RETURNS SETOF text
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $f$
DECLARE v_me text := coalesce(current_setting('authz.user_id', true), ''); v_c text;
        v_pt text := coalesce(current_setting('authz.principal_type', true), '');
        v_scopes text := coalesce(current_setting('authz.scopes', true), '');{self.id_vars()}
BEGIN
  IF NOT authz_int.may_inspect(p_type, p_id) OR NOT authz_int.scope_perm(p_type, p_perm) THEN
    RAISE EXCEPTION 'you cannot see who has access to % %', p_type, p_id USING ERRCODE = 'insufficient_privilege', HINT = 'rowstile help AZ705';
  END IF;
  BEGIN
    PERFORM set_config('authz.scopes', '', true);   -- each candidate is checked with full rights
    PERFORM set_config('authz.principal_type', '', true);   -- candidates are users
  {who_body}
  EXCEPTION WHEN OTHERS THEN
    PERFORM set_config('authz.user_id', v_me, true);
    PERFORM set_config('authz.principal_type', v_pt, true);
    PERFORM set_config('authz.scopes', v_scopes, true);
    PERFORM authz_int.sign();
    RAISE;
  END;
  PERFORM set_config('authz.user_id', v_me, true);
  PERFORM set_config('authz.principal_type', v_pt, true);
  PERFORM set_config('authz.scopes', v_scopes, true);
  PERFORM authz_int.sign();
END $f$;

-- Why the current user (or, for people who may inspect the object, another user) holds a
-- permission, or what is missing: SELECT * FROM authz.explain('file', 11, 'edit')
CREATE FUNCTION authz.explain(p_type text, p_id text, p_perm text, p_user text DEFAULT NULL) RETURNS SETOF text
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $f$
DECLARE v_me text := coalesce(current_setting('authz.user_id', true), ''); v_ok boolean;{self.id_vars()}
        v_pt text := coalesce(current_setting('authz.principal_type', true), '');
BEGIN
  -- another user's access: only for people who may inspect the object (the signed-in user may explain their own;
  -- a service whose id is a user's may not)
  IF p_user IS NOT NULL AND authz_int.canon('user', p_user) IS DISTINCT FROM authz.uid()::text
     AND NOT authz_int.may_inspect(p_type, p_id) THEN
    RAISE EXCEPTION 'you cannot inspect access to % %', p_type, p_id USING ERRCODE = 'insufficient_privilege', HINT = 'rowstile help AZ705';
  END IF;
  -- people who can't see the object learn nothing about it, whatever else they hold on it (as for a missing one)
  IF p_user IS NULL AND NOT authz_int.may_inspect(p_type, p_id) AND NOT authz_int.visible(p_type, p_id) THEN
    RETURN NEXT 'no   you have no access to ' || p_type || ' ' || p_id;
    RETURN;
  END IF;
  BEGIN
    IF p_user IS NOT NULL THEN
      PERFORM set_config('authz.user_id', p_user, true);
      PERFORM set_config('authz.principal_type', '', true);
      PERFORM authz_int.sign();
    END IF;
    v_ok := authz.can(p_type, p_id, p_perm);
    RETURN NEXT CASE WHEN v_ok THEN 'yes  ' ELSE 'no   ' END || coalesce(coalesce(nullif(current_setting('authz.principal_type', true), ''), 'user') || ' ' || nullif(current_setting('authz.user_id', true), ''), 'nobody')
      || ' ' || CASE WHEN v_ok THEN 'holds ' ELSE 'does not hold ' END || p_perm || ' on ' || p_type || ' ' || p_id;
  {why_body}
  EXCEPTION WHEN OTHERS THEN
    PERFORM set_config('authz.user_id', v_me, true);
    PERFORM set_config('authz.principal_type', v_pt, true);
    PERFORM authz_int.sign();
    RAISE;
  END;
  PERFORM set_config('authz.user_id', v_me, true);
  PERFORM set_config('authz.principal_type', v_pt, true);
  PERFORM authz_int.sign();
END $f$;

-- The shares on an object (for a sharing dialog): SELECT * FROM authz.list_shares('folder', 3)
CREATE FUNCTION authz.list_shares(p_type text, p_id text)
RETURNS TABLE (relation text, role text, subject_type text, subject_id text, subject_relation text,
               expires_at timestamptz, starts_at timestamptz, caveat text, created_by text, created_at timestamptz)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $f$
BEGIN
  p_id := authz_int.canon(p_type, p_id);
  IF NOT authz_int.may_inspect(p_type, p_id) THEN
    RAISE EXCEPTION 'you cannot see the shares of % %', p_type, p_id USING ERRCODE = 'insufficient_privilege', HINT = 'rowstile help AZ705';
  END IF;
  RETURN QUERY SELECT g.relation, (SELECT r.name FROM authz.roles r WHERE 'role:' || r.id = g.relation),
    g.subject_type, CASE WHEN g.subject_type = 'link' THEN '(link)' ELSE g.subject_id END, g.subject_relation,
    g.expires_at, g.starts_at, g.caveat, g.created_by, g.created_at
  FROM authz.shares g WHERE g.object_type = p_type AND g.object_id = p_id ORDER BY g.created_at, g.relation;
END $f$;
""" + "\n".join(
            f"CREATE FUNCTION authz.{fn}(p_type text, p_id {pt}{extra}) RETURNS {ret} LANGUAGE sql STABLE AS\n"
            f"  $$ SELECT * FROM authz.{fn}(p_type, p_id::text{args}) $$;"
            for pt in sorted({t.pktype for t in self.types.values()} - {"text"})
            for fn, extra, args, ret in (
                ("who", ", p_perm text", ", p_perm", "SETOF text"),
                ("explain", ", p_perm text, p_user text DEFAULT NULL", ", p_perm, p_user", "SETOF text"),
                (
                    "list_shares",
                    "",
                    "",
                    "TABLE (relation text, role text, subject_type text, subject_id text, "
                    "subject_relation text, expires_at timestamptz, starts_at timestamptz, caveat text, "
                    "created_by text, created_at timestamptz)",
                ),
            )
        )

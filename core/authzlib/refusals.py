"""Refusals that say why. A rule's WITH CHECK becomes `(check) OR <refuse>(row)`: Postgres stops at the first
true, so the refuse function runs only when a write is refused. It raises insufficient_privilege naming the
rule, with the explanation in DETAIL. authz.explain_rule() gives the same explanation on request: for an
update or delete that changed no rows, or an insert before trying it.

Everything here runs as the app role, like the policies themselves, and checks the rows the way they do: what
reads other rows (a condition with a subquery, a link table, shares) is read by the same functions the policies
call, with the policy's rights, so the explanation says yes and no where the check did. Nothing is explained that
the user couldn't ask authz.explain about. The checks are compiled into BEGIN ATOMIC functions, whose names are
resolved when the policy is applied (as in the policies), so they reach what the policies reach without the app
role using authz_int.
"""

from __future__ import annotations

from .compiler import Core, only_on, rule_name
from .insight import expr_text
from .parse import And, Arrow, ArrowOn, Expr, Or, Ref, Rule, Type
from .sqlutil import lit, q, qt, reads_more, row_cond

EXPLAIN_LINES = 20  # lines of authz.explain per object, at most
TARGETS = 3  # objects explained per relation, at most


def parts(node: Expr) -> list[Expr]:
    """The items of an and/or; none for anything else."""
    match node:
        case And(items) | Or(items):
            return list(items)
    return []


class RefusalMixin(Core):
    def rule_fn(self, table: str, command: str, what: str) -> str:
        return f"authz_gen.{q(table + ':' + command.replace('update check', 'update_after') + ':' + what)}"

    def rule_nodes(self, rule: Rule) -> list[tuple[Expr, list[Expr]]]:
        """What to say yes or no about: the rule's items, and the items of those that are and/or."""
        return [(item, parts(item)) for item in parts(rule.expr) or [rule.expr]]

    def rule_items_sql(self, t: Type, table: str, alias: str, rule: Rule, name: str | None = None) -> str:
        """A BEGIN ATOMIC function returning, for a row: [the whole rule, scopes, the type's where, each node]."""
        cmd = "update" if rule.command == "update check" else rule.command
        where = "true"
        if t.where:
            where = (
                self.definer_cond(t, t.where, alias)
                if reads_more(t.where)
                else f"coalesce(({row_cond(t.where, alias)}), false)"
            )
        exprs = [
            self.rule_sql(t, alias, rule, point=True, invoker=True),
            f"(SELECT authz_int.scope_cmd({lit(table)}, {lit(cmd)}))",
            where,
        ]
        for item, kids in self.rule_nodes(rule):
            for node in [item, *kids]:
                exprs.append(self.row_sql(t, alias, node, rule.loc, point=True, invoker=True))
        body = ",\n    ".join(f"coalesce({e}, false)" for e in exprs)
        return (
            f"CREATE FUNCTION {self.rule_fn(table, name or rule.command, 'items')}(p_row {qt(table)}) RETURNS boolean[]\n"
            f"LANGUAGE sql STABLE\nBEGIN ATOMIC\n  SELECT ARRAY[\n    {body}]\n"
            f"  FROM (SELECT (p_row).*) AS {alias};\nEND;"
        )

    def row_targets_sql(self, t: Type, alias: str, node: Expr, rel: str) -> list[tuple[str, str]]:
        """(type, query of ids as text) for what a relation followed by `rel.perm` points at, from the row."""
        r, targets = self.targets(t, rel, t.loc)
        on = only_on(node)
        names = on if on is not None else [x.name for x in targets]
        out: list[tuple[str, str]] = []
        for src in r.sources:
            for st in names:
                if (st, None) not in src.subjects:
                    continue
                if src.kind == "column":
                    out.append(
                        (
                            st,
                            f"SELECT ({self.subject_id(src, alias, st)})::text AS id "
                            f"FROM (SELECT (p_row).*) AS {alias}",
                        )
                    )
                elif src.kind == "table":
                    where = f" AND coalesce(({row_cond(src.where, 's')}), false)" if src.where else ""
                    out.append(
                        (
                            st,
                            f"SELECT ({self.subject_id(src, 's', st)})::text AS id "
                            f"FROM (SELECT (p_row).*) AS {alias} JOIN {qt(self.source_table(src))} s "
                            f"ON {self.key_is(t, 's', self.key(t, alias), src.obj_col)}{where}",
                        )
                    )
        return out

    def rule_why_sql(self, t: Type, table: str, alias: str, rule: Rule, name: str | None = None) -> str:
        """Lines explaining the rule for a row: yes/no per item, and for a missing rel.perm, authz.explain on
        what the row points at; for a missing permission of the row itself, its explain (not on insert, nor for an
        `after` rule: the row isn't stored as it is checked, and authz.explain reads the row as stored). A plain
        update rule is checked on both rows: its function takes p_stored, false for the row after the change, which
        then has no such explain either."""
        cmd = "update" if rule.command == "update check" else rule.command
        both = self.checked_on_both(rule)
        head = f"{lit(rule_name(rule) + ' : ' + rule.src + '  (')} || {self.line_sql(f'rule {table} {rule_name(rule)}', rule.loc)} || ')'"
        code = [
            f"  RETURN NEXT CASE WHEN v[1] THEN 'yes  ' ELSE 'no   ' END || {head};",
            f"  IF NOT v[2] THEN RETURN NEXT {lit('  no   the sign-in' + chr(39) + 's scopes do not allow ' + cmd + ' on ' + table)}; END IF;",
        ]
        if t.where:
            code.append(
                f"  IF NOT v[3] THEN RETURN NEXT {lit('  no   the row fails the ' + t.name + ' type' + chr(39) + 's where {' + t.where + '}')}; END IF;"
            )
        i = 4

        def deeper(node: Expr, idx: int, pad: str) -> str:
            match node:
                case Arrow(rel, perm) | ArrowOn(rel, perm, _):
                    return arrow(node, rel, perm, idx, pad)
                case Ref(name) if cmd != "insert" and rule.command != "update check" and name in self.public_perms(t):
                    return (
                        f"  IF NOT v[{idx}]{' AND p_stored' if both else ''} THEN\n"
                        f"    RETURN QUERY SELECT {lit(pad)} || l FROM authz.explain("
                        f"{lit(t.name)}, ({self.key_text(t, alias)}), {lit(name)}) l "
                        f"LIMIT {EXPLAIN_LINES};\n  END IF;".replace(f"{alias}.", "(p_row).")
                    )
            return ""

        def arrow(node: Expr, rel: str, perm: str, idx: int, pad: str) -> str:
            loops = []
            for st, sql in self.row_targets_sql(t, alias, node, rel):
                loops.append(
                    f"    FOR v_t IN SELECT DISTINCT x.id FROM ({sql}) x WHERE x.id IS NOT NULL ORDER BY 1 LIMIT {TARGETS} LOOP\n"
                    f"      RETURN QUERY SELECT {lit(pad)} || l FROM authz.explain({lit(st)}, v_t.id, {lit(perm)}) l "
                    f"LIMIT {EXPLAIN_LINES};\n    END LOOP;"
                )
            return f"  IF NOT v[{idx}] THEN\n" + "\n".join(loops) + "\n  END IF;" if loops else ""

        for item, kids in self.rule_nodes(rule):
            code.append(
                f"  RETURN NEXT CASE WHEN v[{i}] THEN '  yes  ' ELSE '  no   ' END || "
                f"{lit(expr_text(item).replace('__base', ' (before the deny)'))};"
            )
            code.append(deeper(item, i, "    "))
            top = i
            i += 1
            if kids:
                code.append(f"  IF NOT v[{top}] THEN")
                for kid in kids:
                    code.append(
                        f"    RETURN NEXT CASE WHEN v[{i}] THEN '    yes  ' ELSE '    no   ' END || "
                        f"{lit(expr_text(kid).replace('__base', ' (before the deny)'))};"
                    )
                    code.append(deeper(kid, i, "      "))
                    i += 1
                code.append("  END IF;")
        body = "\n".join(c for c in code if c)
        stored = ", p_stored boolean" if both else ""
        return f"""CREATE FUNCTION {self.rule_fn(table, name or rule.command, "why")}(p_row {qt(table)}{stored}) RETURNS SETOF text
LANGUAGE plpgsql STABLE SET search_path FROM CURRENT AS $f$
#variable_conflict use_column
DECLARE v boolean[] := {self.rule_fn(table, name or rule.command, "items")}(p_row); v_t record;
BEGIN
{body}
END $f$;"""

    @staticmethod
    def checked_on_both(rule: Rule) -> bool:
        """A plain update rule (no columns): Postgres checks it on the row before the change and on the row after."""
        return rule.command == "update" and not rule.columns

    def refuse_sql(self, t: Type, table: str, rule: Rule) -> str:
        """The function a WITH CHECK calls when the write is refused: it raises, with the explanation."""
        schema, name = table.split(".")
        what = (
            ("insert this row into " if rule.command == "insert" else "update this row of ")
            + table
            + ("" if rule.command == "insert" else " to these values")
        )
        hint = (
            "the update rule must hold on the row after the change too (Postgres checks both) (rowstile help AZ709)"
            if rule.command == "update"
            else "rowstile help AZ709"
        )
        constraint = "authz_insert" if rule.command == "insert" else "authz_update"
        after = ", false" if self.checked_on_both(rule) else ""  # (a WITH CHECK reads the row after the change)
        return f"""CREATE FUNCTION {self.rule_fn(table, rule.command, "refuse")}(p_row {qt(table)}) RETURNS boolean
LANGUAGE plpgsql VOLATILE SET search_path FROM CURRENT AS $f$
DECLARE v_lines text; v_who text := CASE WHEN coalesce(current_setting('authz.user_id', true), '') = '' THEN 'someone not signed in'
  ELSE coalesce(nullif(current_setting('authz.principal_type', true), ''), 'user') || ' ' || current_setting('authz.user_id', true) END;
BEGIN
  BEGIN
    v_lines := (SELECT string_agg(l, E'\\n') FROM {self.rule_fn(table, rule.command, "why")}(p_row{after}) l);
  EXCEPTION WHEN OTHERS THEN
    v_lines := 'no explanation: ' || SQLERRM;
  END;
  RAISE EXCEPTION USING ERRCODE = 'insufficient_privilege', MESSAGE = 'permission denied: ' || v_who || ' may not ' || {lit(what)},
    DETAIL = v_lines, SCHEMA = {lit(schema)}, TABLE = {lit(name)}, CONSTRAINT = {lit(constraint)},
    HINT = {lit(hint)};
END $f$;"""

    def refusal_sql(self, t: Type, table: str, alias: str, rules: list[Rule]) -> tuple[list[str], dict[str, str]]:
        """For one table: items and why for each write rule, refuse for the WITH CHECK ones, and what
        authz.explain_rule calls. Returns (statements, {command: refuse call for the WITH CHECK})."""
        out: list[str] = []
        refuse: dict[str, str] = {}
        by_cmd = {
            r.command: r for r in rules if not r.columns and r.command in ("insert", "update", "update check", "delete")
        }
        for r in by_cmd.values():
            out += [self.rule_items_sql(t, table, alias, r), self.rule_why_sql(t, table, alias, r)]
            if r.command in ("insert", "update", "update check"):
                out.append(self.refuse_sql(t, table, r))
                refuse[r.command] = f"{self.rule_fn(table, r.command, 'refuse')}(ROW({alias}.*)::{qt(table)})"
        out.append(self.explain_table_sql(t, table, by_cmd))
        return out, refuse

    def explain_table_sql(self, t: Type, table: str, by_cmd: dict[str, Rule]) -> str:
        def why(cmd: str, row: str) -> str:
            return f"ARRAY(SELECT * FROM {self.rule_fn(table, cmd, 'why')}({row}))"

        def stored(cmd: str, row: str, is_stored: bool) -> str:
            """The arguments of cmd's why function for a row: whether it is the row as stored, for a plain update."""
            return f"{row}, {'true' if is_stored else 'false'}" if self.checked_on_both(by_cmd[cmd]) else row

        def none(cmd: str) -> str:
            return (
                f"ARRAY[{lit('no   there is no ' + cmd + ' rule for ' + table + ': nobody may ' + cmd + ' its rows')}]"
            )

        insert = (
            why("insert", f"jsonb_populate_record(NULL::{qt(table)}, coalesce(p_row, '{{}}'))")
            if "insert" in by_cmd
            else none("insert")
        )
        delete = why("delete", "r_old") if "delete" in by_cmd else none("delete")
        if "update" in by_cmd:
            # the row after the change answers to the `update after` rule where there is one, instead of the
            # update rule (the WITH CHECK is that rule's)
            after = "update check" if "update check" in by_cmd else "update"
            update = (
                f"{why('update', stored('update', 'r_old', True))} || CASE WHEN p_row IS NULL THEN '{{}}'::text[] ELSE "
                f"ARRAY['after the change:'] || "
                f"ARRAY(SELECT '  ' || l FROM {self.rule_fn(table, after, 'why')}({stored(after, 'r_new', False)}) l) END"
            )
        else:
            update = none("update")
        find = self.key_is(t, "x", "p_id" if t.composite else f"p_id::{t.pktype}")
        fetch = f"SELECT x.* INTO r_old FROM {qt(table)} x WHERE {find};"
        if any(r.table == table and r.command == "mask" for r in self.rules):
            # the app role can't read a masked column from the table: the row as the masked view gives it (the
            # same rows, a masked column NULL unless its rule holds), by column name
            fetch = (
                f"SELECT (jsonb_populate_record(NULL::{qt(table)}, to_jsonb(x))).* INTO r_old "
                f"FROM {qt(self.pol.views[table])} x WHERE {find};"
            )
        return f"""CREATE FUNCTION {self.rule_fn(table, "rules", "explain")}(p_command text, p_id text, p_row jsonb) RETURNS text[]
LANGUAGE plpgsql STABLE SET search_path FROM CURRENT AS $f$
DECLARE r_old {qt(table)}; r_new {qt(table)};
BEGIN
  IF p_command = 'insert' THEN
    RETURN {insert};
  END IF;
  IF p_id IS NULL THEN
    RAISE EXCEPTION 'which row? authz.explain_rule(%, %, id)', {lit(table)}, p_command USING ERRCODE = 'invalid_parameter_value', HINT = 'rowstile help AZ710';
  END IF;
  {fetch}
  IF NOT FOUND THEN
    RETURN NULL;          -- not there, or the signed-in user can't see it
  END IF;
  IF p_command = 'delete' THEN
    RETURN {delete};
  END IF;
  r_new := jsonb_populate_record(r_old, coalesce(p_row, '{{}}'));
  RETURN {update};
END $f$;"""

    def explain_rule_sql(self, tables: list[str]) -> str:
        cases = (
            "\n".join(
                f"    WHEN {lit(tb)} THEN RETURN {self.rule_fn(tb, 'rules', 'explain')}(p_command, p_id, p_row);"
                for tb in tables
            )
            or "    WHEN NULL THEN NULL;"
        )
        return f"""-- Why a write is or would be refused, as the signed-in user: an insert (p_row: the new row as JSON), or an
-- update or delete of the row whose id is p_id (for an update, p_row: the new values). NULL when that row isn't
-- there or the user can't see it (404, not 403). SELECT authz.explain_rule('app.files', 'update', '11')
CREATE FUNCTION authz.explain_rule(p_table text, p_command text, p_id text DEFAULT NULL, p_row jsonb DEFAULT NULL)
RETURNS text[] LANGUAGE plpgsql STABLE SET search_path = pg_catalog, pg_temp AS $f$
BEGIN
  IF p_command IS NULL OR p_command NOT IN ('insert', 'update', 'delete') THEN
    RAISE EXCEPTION 'explain_rule explains insert, update or delete, not %', p_command USING ERRCODE = 'invalid_parameter_value', HINT = 'rowstile help AZ710';
  END IF;
  CASE p_table
{cases}
    ELSE RAISE EXCEPTION 'the policy has no rules for table %', p_table USING HINT = 'rowstile help AZ707';
  END CASE;
END $f$;"""

    def who_among_sql(self) -> str:
        typed = sorted({t.pktype for t in self.types.values()} - {"text"})
        overloads = "\n".join(
            f"CREATE FUNCTION authz.who_among(p_type text, p_id {pt}, p_perm text, p_users text[], "
            f"p_principal_type text DEFAULT 'user') RETURNS SETOF text LANGUAGE sql VOLATILE AS\n"
            f"  $$ SELECT * FROM authz.who_among(p_type, p_id::text, p_perm, p_users, p_principal_type) $$;"
            for pt in typed
        )
        return f"""-- Which of these people (or principals of another type) hold a permission: who to tell about a change.
-- It signs each one in with authz.act_as(), as the caller: so only a backend trusted to sign anyone in can
-- use it, as it could ask authz.can for each one itself. Not in a session limited by scopes or view-as. SELECT * FROM authz.who_among('chat', '7', 'read', ARRAY['1', '2'])
CREATE FUNCTION authz.who_among(p_type text, p_id text, p_perm text, p_users text[], p_principal_type text DEFAULT 'user')
RETURNS SETOF text LANGUAGE plpgsql VOLATILE SET search_path = pg_catalog, pg_temp AS $f$
DECLARE v_me text := nullif(current_setting('authz.user_id', true), '');
        v_pt text := coalesce(nullif(current_setting('authz.principal_type', true), ''), 'user');
        v_u text;
BEGIN
  IF coalesce(current_setting('authz.scopes', true), '') <> '' OR coalesce(current_setting('authz.acting_user', true), '') <> '' THEN
    RAISE EXCEPTION 'authz.who_among() signs people in, which a session limited by scopes or view-as may not'
      USING ERRCODE = 'insufficient_privilege', HINT = 'rowstile help AZ704';
  END IF;
  BEGIN
    FOREACH v_u IN ARRAY coalesce(p_users, '{{}}') LOOP
      PERFORM authz.act_as(p_principal_type, v_u);
      IF authz.can(p_type, p_id, p_perm) THEN RETURN NEXT v_u; END IF;
    END LOOP;
  EXCEPTION WHEN OTHERS THEN
    PERFORM authz.act_as(v_pt, v_me);
    RAISE;
  END;
  PERFORM authz.act_as(v_pt, v_me);
END $f$;
{overloads}"""

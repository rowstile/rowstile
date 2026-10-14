"""Assembling the compiled policy: catalog, triggers, policies and the API."""

from __future__ import annotations

import re

from .base import BASE_SQL, GENERATED_FUNCTIONS
from .compiler import rule_name
from .governance import GovernanceMixin, trigger_if_partitioned
from .hardening import LintMixin, path_writers_sql
from .identity import SESSION_OK, IdentityMixin
from .insight import InsightMixin
from .parse import Expr, Loc, Not, Ref, Rule, Type, fail
from .refusals import RefusalMixin
from .sqlutil import (
    CHILD_TRIGGERS,
    CHILD_TRIGGERS_FN,
    DROP_OLD_POLICIES,
    LOST_RULES,
    STUB_COLUMNS,
    VIEW_MARKS,
    ident,
    lit,
    on_row,
    q,
    qt,
    row_cond,
)
from .trees import TreeMixin

DEFINER = "SECURITY DEFINER SET search_path = pg_catalog, pg_temp"
# for functions that run the policy's own SQL: the path applying vetted (search_path_sql), as views and policies resolve it
DEFINER_FROM_CURRENT = "SECURITY DEFINER SET search_path FROM CURRENT"
PT = "pg_catalog.current_setting('authz.principal_type', true)"  # the signed-in principal's type ('': a user)
# a link's id, from its share g: the start of its token's hash (enough to name it among an object's links)
LINK_ID = "left(g.subject_id, 16)"


def subject_key(st: str, sr: str | None) -> str:
    if sr == "*":
        return f"{st}:*"
    if st in ("anyone", "link"):
        return st
    return f"{st}#{sr}" if sr else st


def denied(item: Expr) -> str:
    """The permission a deny (`not <permission>`) takes away."""
    assert isinstance(item, Not) and isinstance(item.item, Ref), "split_denies refuses any other deny (AZ306)"
    return item.item.name


def read_now(rows: list[str]) -> str:
    """What follows a PL/pgSQL function that holds conditions of the policy no view or rule holds (a type's where
    in authz.uid(), a `shared ... if`): Postgres reads such a function's queries only when they first run, so each
    condition, `FROM <rows> WHERE <it>`, is read here, and one that doesn't run (a column that isn't there) is
    refused when applying (AZ613), not on the app's first query. In the part of the function, which a migration
    that changes it runs whole."""
    if not rows:
        return ""
    return (
        "\n-- what it reads, read now (Postgres reads a PL/pgSQL function's queries when they first run)\n"
        "DO $read$ BEGIN" + "".join(f"\n  PERFORM 1 FROM {x} LIMIT 0;" for x in rows) + "\nEND $read$;"
    )


def where_rows(table: str, where: str, alias: str) -> str:
    """The rows a type's where reads in a PL/pgSQL function (authz.uid(), a principal's __me), for read_now."""
    return f"{qt(table)} {alias} WHERE coalesce(({on_row(where, alias)}), false)"


def shared_if_rows(pktype: str, cond: str) -> str:
    """The row a `shared ... if` condition reads in authz_int.share_if (a share's), for read_now."""
    return (
        f"(SELECT NULL::{pktype} AS object_id, NULL::text AS subject_type, NULL::text AS "
        f"subject_id, NULL::text AS subject_relation) share "
        f"WHERE coalesce(({row_cond(cond, 'share')}), false)"
    )


# A share is made under a lock on its object's row and its subject's (FOR KEY SHARE), so a delete waits for it, and
# in READ COMMITTED the trigger that removes the shares on a deleted row sees it. A transaction whose snapshot is older
# than the share (REPEATABLE READ, SERIALIZABLE) doesn't, so each share also writes a new version of a mark row for
# the object and for the subject, and a delete, a new id or a TRUNCATE in such a transaction writes the same marks:
# where a share it can't see was made since its snapshot, that fails to serialize (40001), instead of committing and
# leaving the share on a row that is gone. The marks of a row go with it; there is one for each row shared on or to.
SHARE_MARKS = """-- a share on or to a row marks it (a new version of its mark, which a transaction that can't see the share
-- and then deletes the row, or changes its id, writes too: forget_marks)
CREATE FUNCTION authz_int.mark_shared(p_type text, p_id text) RETURNS void
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $f$
  INSERT INTO authz_int.share_marks AS m (type, id) VALUES (p_type, p_id)
  ON CONFLICT (type, id) DO UPDATE SET n = m.n + 1 $f$;
-- rows that are gone, or whose id changed: their marks go too. In a transaction whose snapshot may be older than a
-- share on one of them (not READ COMMITTED), the marks are written first: if a share was made since, that fails to
-- serialize (40001), rather than leave a share the deletes after can't see
CREATE FUNCTION authz_int.forget_marks(p_type text, p_ids text[]) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $f$
BEGIN
  IF pg_catalog.current_setting('transaction_isolation') <> 'read committed' THEN
    INSERT INTO authz_int.share_marks AS m (type, id) SELECT DISTINCT p_type, x FROM unnest(p_ids) x
    ON CONFLICT (type, id) DO UPDATE SET n = m.n + 1;
  END IF;
  DELETE FROM authz_int.share_marks WHERE type = p_type AND id = ANY (p_ids);
END $f$;
-- whether a row is there, locked (FOR KEY SHARE) until the transaction ends, as authz.share locks what it shares
CREATE FUNCTION authz_int.hold(p_type text, p_id text) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $f$
DECLARE v_tbl text; v_find text; v_found boolean;
BEGIN
  SELECT t.tbl, t.find INTO v_tbl, v_find FROM authz_int.types t WHERE t.name = p_type;
  -- (the key's type by a subquery, never a variable: pg_input_is_valid takes a variable's first value for every
  -- later call from the same line, so a uuid key checked after a bigint one would be invalid)
  IF v_tbl IS NULL OR NOT pg_catalog.pg_input_is_valid(p_id, (SELECT t.keytype FROM authz_int.types t WHERE t.name = p_type)) THEN
    RETURN false;
  END IF;
  EXECUTE format('SELECT EXISTS (SELECT 1 FROM %s x WHERE %s FOR KEY SHARE)', v_tbl, v_find) INTO v_found USING p_id;
  RETURN v_found;
END $f$;"""


class OutputMixin(RefusalMixin, InsightMixin, GovernanceMixin, IdentityMixin, LintMixin, TreeMixin):
    def late_conditions(self) -> list[tuple[str, str, Loc]]:
        """(rows, condition, line) for each condition only a PL/pgSQL function holds: a signing-in type's where,
        a `shared ... if`. Nothing in the catalog depends on what they read, so the app may drop a column they
        read after applying: read_now reads them when applying, and apply and push read them again when the
        policy in force is unchanged (database.unchanged)."""
        out: list[tuple[str, str, Loc]] = []
        for t in self.types.values():
            if t.principal and t.where:
                out.append((where_rows(t.table, t.where, "u" if t.name == "user" else "w"), t.where, t.loc))
            for r in t.relations.values():
                for src in r.sources:
                    if src.kind == "shared" and src.shared_if:
                        out.append((shared_if_rows(t.pktype, src.shared_if), src.shared_if, src.loc))
        return out

    # --- what sharing a relation needs ---------------------------------------
    def positive_refs(self, node: Expr, out: set[str]) -> set[str]:
        match node:
            case ("ref", name) | ("arrow", name, _) | ("arrow_on", name, _, _):
                out.add(name)
            case ("and", items) | ("or", items):
                for x in items:
                    self.positive_refs(x, out)
        return out

    def required_perms(self, t: Type, relname: str) -> list[str]:
        """Sharing a relation grants what it grants: the sharer must hold every
        permission the relation feeds into."""
        need = []
        denies = {denied(x) for (tn, _), negs in self.denies.items() if tn == t.name for x in negs}
        for p in t.perms.values():
            if p.hidden or p.name in denies:  # sharing into a deny takes away; it gives nothing to hold
                continue
            refs: set[str] = set()
            for item in self.flat_items(t, p):
                self.positive_refs(item, refs)
            if p.base is not None and p.base in refs:  # what the permission inherits, before its deny
                for item in self.flat_items(t, t.perms[p.base]):
                    self.positive_refs(item, refs)
            if relname in refs:
                need.append(p.name)
        return need

    # --- shares on rows that are gone -------------------------------------
    def forget_sql(self, t: Type) -> str:
        """Shares on (or to) a row are removed with the row, or when its id
        changes, so a row that later has that id starts with none."""
        tbl = qt(t.table)
        fn = f"authz_int.{q(t.name + '__forget')}"
        fn_row = f"authz_int.{q(t.name + '__forget_id')}"
        fn_trunc = f"authz_int.{q(t.name + '__forget_all')}"
        name = lit(t.name)
        gone = f"SELECT {self.key_text(t, 'o')} FROM old_rows o EXCEPT SELECT {self.key_text(t, 'n')} FROM new_rows n"
        moved = trigger_if_partitioned(
            t.table,
            f"CREATE TRIGGER {q('authz_' + t.name + '_forget_moved')} AFTER UPDATE ON {tbl} "
            f"REFERENCING OLD TABLE AS old_rows NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION {fn}()",
        )
        return f"""-- shares on {t.name} rows that are gone, or whose id changed, are removed (and their marks: forget_marks)
CREATE FUNCTION {fn}() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path FROM CURRENT AS $f$
BEGIN
  IF TG_OP = 'TRUNCATE' THEN
    DELETE FROM authz.shares WHERE object_type = {name};
    DELETE FROM authz.shares WHERE subject_type = {name} AND subject_id <> '*';      -- '*' (every one signed in) names no row
    DELETE FROM authz_int.share_marks WHERE type = {name};
  ELSIF TG_OP = 'UPDATE' THEN   -- on a partitioned table (the last trigger below): the ids the update left no row with
    PERFORM authz_int.forget_marks({name}, ARRAY({gone}));
    DELETE FROM authz.shares WHERE object_type = {name} AND object_id IN ({gone});
    DELETE FROM authz.shares WHERE subject_type = {name} AND subject_id IN ({gone});
  ELSE
    PERFORM authz_int.forget_marks({name}, ARRAY(SELECT {self.key_text(t, "o")} FROM old_rows o));
    DELETE FROM authz.shares WHERE object_type = {name} AND object_id IN (SELECT {self.key_text(t, "o")} FROM old_rows o);
    DELETE FROM authz.shares WHERE subject_type = {name} AND subject_id IN (SELECT {self.key_text(t, "o")} FROM old_rows o);
  END IF;
  RETURN NULL;
END $f$;
CREATE FUNCTION {fn_row}() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path FROM CURRENT AS $f$
BEGIN
  PERFORM authz_int.forget_marks({name}, ARRAY[{self.key_text(t, "OLD")}]);
  DELETE FROM authz.shares WHERE object_type = {name} AND object_id = {self.key_text(t, "OLD")};
  DELETE FROM authz.shares WHERE subject_type = {name} AND subject_id = {self.key_text(t, "OLD")};
  RETURN NULL;
END $f$;
-- before TRUNCATE empties the table: with a snapshot older than a share on one of its rows, fail to serialize
CREATE FUNCTION {fn_trunc}() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path FROM CURRENT AS $f$
BEGIN
  IF pg_catalog.current_setting('transaction_isolation') <> 'read committed' THEN
    PERFORM authz_int.forget_marks({name}, ARRAY(SELECT {self.key_text(t, "x")} FROM {tbl} x));
  END IF;
  RETURN NULL;
END $f$;
CREATE TRIGGER {q("authz_" + t.name + "_forget_del")} AFTER DELETE ON {tbl}
  REFERENCING OLD TABLE AS old_rows FOR EACH STATEMENT EXECUTE FUNCTION {fn}();
CREATE TRIGGER {q("authz_" + t.name + "_forget_id")} AFTER UPDATE ON {tbl} FOR EACH ROW
  WHEN ({self.key(t, "OLD")} IS DISTINCT FROM {self.key(t, "NEW")}) EXECUTE FUNCTION {fn_row}();
CREATE TRIGGER {q("authz_" + t.name + "_forget_trunc")} AFTER TRUNCATE ON {tbl}
  FOR EACH STATEMENT EXECUTE FUNCTION {fn}();
CREATE TRIGGER {q("authz_" + t.name + "_forget_trunc_first")} BEFORE TRUNCATE ON {tbl}
  FOR EACH STATEMENT EXECUTE FUNCTION {fn_trunc}();
-- On a partitioned table, an update that puts a row in another partition is a delete there and an insert here:
-- Postgres runs no AFTER UPDATE row trigger for it. The ids an update leaves no row with are forgotten too.
{moved}"""

    # --- rules on changed columns (RLS can't compare old and new rows) ----
    def column_rule_sql(self, t: Type, alias: str, rule: Rule, idx: int) -> str:
        new = rule.command == "update check"
        row = "NEW" if new else "OLD"
        cond = self.rule_sql(t, alias, rule, point=True, invoker=True)
        fn = f"authz_int.{q(f'{t.name}__update_{idx}')}"
        cols = ", ".join(rule.columns)
        when = "\n     OR ".join(f"OLD.{q(c)} IS DISTINCT FROM NEW.{q(c)}" for c in rule.columns)
        msg = f"changing {cols} of {rule.table} ".replace("%", "%%") + "%" + f" needs: {rule.src}".replace("%", "%%")
        # the explanation, as for refused inserts and updates (refusals.py)
        name = f"column_{idx}"
        why = self.rule_fn(rule.table, name, "why")
        holds = self.rule_fn(rule.table, name, "holds")
        schema, table = rule.table.split(".")
        tbl = f"{lit(qt(rule.table))}::pg_catalog.regclass"
        return f"""{self.rule_items_sql(t, rule.table, alias, rule, name)}

{self.rule_why_sql(t, rule.table, alias, rule, name)}

-- {rule.table} update {cols}{" after" if new else ""} ({rule.loc}): {rule.src}
-- Whether the rule holds for a row. BEGIN ATOMIC, as the refusals' functions are: the trigger below runs as the app
-- role, which can't name what is in authz_int in text read at run time (the signed-in service, authz_int."<type>__me")
CREATE FUNCTION {holds}(p_row {qt(rule.table)}) RETURNS boolean
LANGUAGE sql STABLE
BEGIN ATOMIC
  SELECT coalesce({cond}, false) FROM (SELECT (p_row).*) AS {alias};
END;
-- checked on the row {"after" if new else "before"} the change, for roles that row-level security applies to on the
-- table (not on TG_RELID: on a partition made since the policy was applied, where it is not on yet, this runs too)
CREATE FUNCTION {fn}() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $f$
DECLARE v_lines text; v_row {qt(rule.table)};
BEGIN
  IF pg_catalog.row_security_active({tbl}) THEN
    -- the row as the table's own: a partition's columns may be in another order, a table that inherits may have more
    IF TG_RELID = {tbl} THEN v_row := {row};
    ELSE v_row := pg_catalog.jsonb_populate_record(NULL::{qt(rule.table)}, pg_catalog.to_jsonb({row})); END IF;
    IF NOT {holds}(v_row) THEN
      BEGIN
        v_lines := (SELECT string_agg(l, E'\\n') FROM {why}(v_row) l);
      EXCEPTION WHEN OTHERS THEN
        v_lines := 'no explanation: ' || SQLERRM;
      END;
      RAISE EXCEPTION {lit(msg)}, {self.key(t, "OLD")} USING ERRCODE = 'insufficient_privilege', DETAIL = v_lines,
        SCHEMA = {lit(schema)}, TABLE = {lit(table)}, CONSTRAINT = 'authz_update', HINT = 'rowstile help AZ709';
    END IF;
  END IF;
  RETURN NEW;
END $f$;
CREATE TRIGGER {q("authz_update_" + str(idx))} BEFORE UPDATE ON {qt(rule.table)} FOR EACH ROW
  WHEN ({when})
  EXECUTE FUNCTION {fn}();"""

    # --- identity -----------------------------------------------------------
    def uid_sql(self) -> str:
        u = self.T("user")
        setting = "pg_catalog.current_setting('authz.user_id', true)"
        cast = (
            f"CASE WHEN {SESSION_OK} "
            f"AND coalesce(pg_catalog.current_setting('authz.principal_type', true), '') IN ('', 'user') "
            f"AND pg_catalog.pg_input_is_valid({setting}, {lit(u.pktype)}) THEN {setting}::{u.pktype} END"
        )
        # A user is a row of the user type: an id its table doesn't have (a deleted user still signed in), or
        # one that fails the type's where, is nobody.
        # PL/pgSQL: its plans are kept for the session, and it runs once per statement (an initplan)
        where = f" AND coalesce(({on_row(u.where, 'u')}), false)" if u.where else ""
        body = f"BEGIN RETURN (SELECT u.{q(self.pk(u))} FROM {qt(u.table)} u WHERE u.{q(self.pk(u))} = ({cast}){where}); END"
        attrs = "LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path FROM CURRENT"
        failing = ", or a user that fails the type''s where," if u.where else ""
        read = read_now([where_rows(u.table, u.where, "u")] if u.where else [])
        return f"""-- Who is asking: SELECT authz.act_as('user', '42') first in each transaction (a signed session).
-- An id the user table doesn't have{failing} counts as nobody.
DO $u$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_proc WHERE oid = to_regprocedure('authz.uid()')
             AND prorettype <> {lit(u.pktype)}::regtype) THEN
    RAISE EXCEPTION 'authz.uid() returns another type than this policy''s user ids ({u.pktype}); drop it first (DROP FUNCTION authz.uid() CASCADE drops what uses it) [AZ606]';
  END IF;
END $u$;
CREATE OR REPLACE FUNCTION authz.uid() RETURNS {u.pktype} {attrs} AS $uid$ {body} $uid$;{read}"""

    # --- the API app code calls ----------------------------------------------
    def can_sql(self, t: Type, perm: str) -> str:
        """t.perm on the row aliased o, with the type's where (like the views): what authz.can returns."""
        sql = self.row_sql(t, "o", Ref("ref", perm), t.perms[perm].loc, point=True)
        if t.where:
            sql = f"({sql}\n    AND coalesce(({row_cond(t.where, 'o')}), false))"
        return sql

    def list_cases_sql(self) -> str:
        """authz.list's branches: each row of the type tested with the permission's row check, as select
        rules do (lookups the planner hashes once for many rows, and what the object's own columns give
        first), rather than the permission's view, which builds every id through every path (46 s for an
        org admin over 5M files). With p_limit, pages in key order after p_after. Row checks may add views,
        so this runs before the views are written out."""
        cases = []
        for t in self.types.values():
            tbl = qt(t.table)
            order = ", ".join(f"o.{q(c)}" for c, _ in t.key)
            after = (
                f"({order}) > ({', '.join(f'(p_after::{t.keytype}).{q(c)}' for c, _ in t.key)})"
                if t.composite
                else f"o.{q(self.pk(t))} > p_after::{t.pktype}"
            )
            for p in self.public_perms(t):
                cond = self.row_sql(t, "o", Ref("ref", p), t.perms[p].loc)
                if t.where:
                    cond = f"({cond}\n    AND coalesce(({row_cond(t.where, 'o')}), false))"
                rows = f"SELECT {self.key_text(t, 'o')} FROM {tbl} o\n        WHERE "
                cases.append(
                    f"    WHEN {lit(t.name + '.' + p)} THEN\n"
                    f"      IF p_limit IS NULL AND p_after IS NULL THEN\n"
                    f"        RETURN QUERY {rows}{cond};\n"
                    f"      ELSIF p_after IS NULL THEN\n"
                    f"        RETURN QUERY {rows}{cond}\n        ORDER BY {order} LIMIT p_limit;\n"
                    f"      ELSE\n"
                    f"        RETURN QUERY {rows}{after} AND {cond}\n"
                    f"        ORDER BY {order} LIMIT p_limit;\n"
                    f"      END IF;"
                )
        return "\n".join(cases)

    def api_sql(self) -> str:
        perms_of = {t.name: self.public_perms(t) for t in self.types.values()}
        no_perm = (
            "RAISE EXCEPTION 'no permission %.% in the policy', p_type, p_perm USING HINT = 'rowstile help AZ707';"
        )

        def can_branch(t: Type) -> str:
            if not t.perms:  # a type without permissions is still a type: it has no such permission
                return f"      {no_perm}"
            # the permission on the object's own row, as a write rule checks it: that object's lookups (and
            # its ancestors, for recursive permissions), not every object the user holds it on. On any row with
            # the key, as the views say: a table that inherits from this one may hold a second (the primary
            # key doesn't cover its rows)
            cases = "\n".join(
                f"        WHEN {lit(p)} THEN RETURN EXISTS (SELECT 1 FROM {qt(t.table)} o "
                f"WHERE {self.key_is(t, 'o', 'v_' + t.pktype)} AND ({self.can_sql(t, p)}));"
                for p in perms_of[t.name]
            )
            return f"      CASE p_perm\n{cases}\n        ELSE {no_perm}\n      END CASE;"

        self._invalid = "false"
        can_body = self.dispatch_type(can_branch)
        list_cases = self._list_cases
        perms_cases = "\n".join(  # every type: one without permissions has an empty list of them
            f"    WHEN {lit(t.name)} THEN names := ARRAY[{', '.join(lit(p) for p in ps)}]::text[];"
            for t in self.types.values()
            for ps in [perms_of[t.name]]
        )
        id_types = sorted({t.pktype for t in self.types.values()} - {"text"})
        overloads = "\n".join(
            f"CREATE FUNCTION authz.can(p_type text, p_id {pt}, p_perm text) RETURNS boolean LANGUAGE sql STABLE AS\n"
            f"  $$ SELECT authz.can(p_type, p_id::text, p_perm) $$;\n"
            f"CREATE FUNCTION authz.perms(p_type text, p_id {pt}) RETURNS text[] LANGUAGE sql STABLE AS\n"
            f"  $$ SELECT authz.perms(p_type, p_id::text) $$;"
            for pt in id_types
        )
        return f"""-- Check a permission from app code: SELECT authz.can('file', 11, 'edit')
-- (only objects that exist; plans are cached per session)
CREATE FUNCTION authz.can(p_type text, p_id text, p_perm text) RETURNS boolean
LANGUAGE plpgsql STABLE {DEFINER_FROM_CURRENT} AS $f$
DECLARE v_allowed boolean;{self.id_vars()}
BEGIN
  IF current_setting('authz_debug.log_decisions', true) = 'on'
     AND current_setting('authz_debug.logging', true) IS DISTINCT FROM 'on' THEN
    -- decision log (SET authz_debug.log_decisions = on; lines go to the server log)
    PERFORM set_config('authz_debug.logging', 'on', true);
    v_allowed := authz.can(p_type, p_id, p_perm);
    PERFORM set_config('authz_debug.logging', 'off', true);
    RAISE LOG 'authz decision: user=% type=% id=% perm=% -> %',
      coalesce(to_json(nullif(current_setting('authz.user_id', true), ''))::text, 'none'), to_json(p_type)::text,
      to_json(p_id)::text, to_json(p_perm)::text, coalesce(v_allowed::text, 'error');
    RETURN v_allowed;
  END IF;
  IF NOT authz_int.scope_perm(p_type, p_perm) THEN RETURN false; END IF;
{can_body}
END $f$;

-- Everything the user holds a permission on: SELECT * FROM authz.list('folder', 'edit')
-- In pages, in key order: authz.list('file', 'view', NULL, 1000), then the last id seen as p_after
CREATE FUNCTION authz.list(p_type text, p_perm text, p_after text DEFAULT NULL, p_limit int DEFAULT NULL)
RETURNS SETOF text
LANGUAGE plpgsql STABLE {DEFINER_FROM_CURRENT} AS $f$
BEGIN
  -- a page cursor or size from a request: the caller's mistake, said plainly (the queries below would cast it)
  IF p_limit < 0 THEN
    RAISE EXCEPTION 'the page size must not be negative (got %)', p_limit
      USING ERRCODE = 'invalid_parameter_value', HINT = 'rowstile help AZ710';
  END IF;
  IF p_after IS NOT NULL AND NOT coalesce(pg_catalog.pg_input_is_valid(p_after,
                                            (SELECT keytype FROM authz_int.types WHERE name = p_type)), true) THEN
    RAISE EXCEPTION 'the page cursor % is not a % id', quote_literal(left(p_after, 40)), p_type
      USING ERRCODE = 'invalid_parameter_value', HINT = 'rowstile help AZ710';
  END IF;
  IF NOT authz_int.scope_perm(p_type, p_perm) THEN RETURN; END IF;
  CASE p_type || '.' || p_perm
{list_cases or "    WHEN NULL THEN NULL;"}
    ELSE
      {no_perm}
  END CASE;
END $f$;

-- Every permission the user holds on one object: SELECT authz.perms('file', 11)
CREATE FUNCTION authz.perms(p_type text, p_id text) RETURNS text[]
LANGUAGE plpgsql STABLE {DEFINER} AS $f$
DECLARE names text[];
BEGIN
  CASE p_type
{perms_cases or "    WHEN NULL THEN NULL;"}
    ELSE RAISE EXCEPTION 'no type % in the policy', p_type USING HINT = 'rowstile help AZ707';
  END CASE;
  RETURN ARRAY(SELECT n FROM unnest(names) n WHERE authz.can(p_type, p_id, n));
END $f$;

-- The permissions the user holds on many objects, in one call (a list's buttons): SELECT * FROM authz.perms_of('folder', ARRAY['1', '2'])
CREATE FUNCTION authz.perms_of(p_type text, p_ids text[]) RETURNS TABLE (id text, perms text[])
LANGUAGE plpgsql STABLE {DEFINER} AS $f$
BEGIN
  RETURN QUERY SELECT x, authz.perms(p_type, x) FROM unnest(p_ids) WITH ORDINALITY u(x, n) ORDER BY n;
END $f$;
{overloads}"""

    def share_sql(self) -> tuple[list[str], str, str]:
        """The catalog of what may be shared, with whom, by whom, and what the sharer must hold; the
        internal functions sharing uses; and authz.share, unshare and the rest of the sharing API."""
        rows: list[str] = []
        ifs: list[str] = []
        if_rows: list[str] = []  # each condition, on a share's row (read_now)
        for t in self.types.values():
            for r in t.relations.values():
                for src in r.sources:
                    if src.kind != "shared":
                        continue
                    req = self.required_perms(t, r.name)
                    for st, sr in src.subjects:
                        key = subject_key(st, sr)
                        rows.append(
                            f"({lit(t.name)}, {lit(r.name)}, {lit(key)}, {lit(src.shared_by or 'share')}, "
                            f"ARRAY[{', '.join(lit(p) for p in req)}]::text[], "
                            f"{lit(self.line_key(f'share {t.name}.{r.name} {key}', src.loc))})"
                        )
                        if src.shared_if:
                            ifs.append(
                                f"    WHEN {lit(t.name + '.' + r.name + '.' + key)} THEN\n"
                                f"      RETURN (SELECT coalesce(({row_cond(src.shared_if, 'share')}), false) FROM (SELECT "
                                f"p_object_id::{t.pktype} AS object_id, p_subject_type AS subject_type, "
                                f"p_subject_id AS subject_id, p_subject_relation AS subject_relation) share);"
                            )
                            if_rows.append(shared_if_rows(t.pktype, src.shared_if))
        roles = [(t.name, subject_key(st, sr)) for t in self.types.values() if t.roles for st, sr in t.roles[0]]
        grantable = [(t.name, p) for t in self.types.values() if t.roles for p in t.roles[1]]
        catalog = [
            "CREATE TABLE authz_int.shared_relations (object_type text, relation text, subject text, "
            "shared_by text, required text[], loc text, PRIMARY KEY (object_type, relation, subject));"
        ]
        if rows:
            catalog.append(
                "INSERT INTO authz_int.shared_relations VALUES\n  " + ",\n  ".join(dict.fromkeys(rows)) + ";"
            )
        catalog.append(
            "CREATE TABLE authz_int.role_subjects (object_type text, subject text, PRIMARY KEY (object_type, subject));"
        )
        if roles:
            catalog.append(
                "INSERT INTO authz_int.role_subjects VALUES "
                + ", ".join(dict.fromkeys(f"({lit(a)}, {lit(b)})" for a, b in roles))
                + ";"
            )
        catalog.append(
            "CREATE TABLE authz_int.role_grantable (object_type text, permission text, "
            "PRIMARY KEY (object_type, permission));"
        )
        if grantable:
            catalog.append(
                "INSERT INTO authz_int.role_grantable VALUES "
                + ", ".join(f"({lit(a)}, {lit(b)})" for a, b in grantable)
                + ";"
            )
        catalog.append("CREATE TABLE authz_int.caveats (name text PRIMARY KEY);")
        if self.pol.caveats:
            catalog.append(
                "INSERT INTO authz_int.caveats VALUES " + ", ".join(f"({lit(c)})" for c in self.pol.caveats) + ";"
            )
        share_if = f"""-- 'shared if {{...}}' conditions (they run as the policy's owner, like permissions)
CREATE FUNCTION authz_int.share_if(p_key text, p_object_id text, p_subject_type text, p_subject_id text,
  p_subject_relation text) RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path FROM CURRENT AS $f$
BEGIN
  CASE p_key
{chr(10).join(ifs) if ifs else "    WHEN NULL THEN NULL;"}
    ELSE RETURN true;
  END CASE;
END $f$;{read_now(list(dict.fromkeys(if_rows)))}"""
        owned = [t for t in self.types.values() if t.roles and t.roles_from]
        role_owned = "\n".join(
            f"    WHEN {lit(t.name)} THEN RETURN p_owner_type = {lit(self.role_owner_type(t))} AND p_owner_id IN "
            f"({self.role_owners_sql(t, 'p_id' if t.composite else f'p_id::{t.pktype}')});"
            for t in owned
        )
        role_owner_types = "\n".join(
            f"    WHEN {lit(t.name)} THEN RETURN {lit(self.role_owner_type(t))};" for t in owned
        )
        role_relations = (
            f"""-- `roles : ... from rel`: a role counts on an object only if what rel links the object to owns it
CREATE FUNCTION authz_int.role_owned(p_type text, p_id text, p_owner_type text, p_owner_id text) RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path FROM CURRENT AS $f$
BEGIN
  CASE p_type
{role_owned or "    WHEN NULL THEN NULL;"}
    ELSE RETURN true;
  END CASE;
END $f$;
-- the type that owns the custom roles of an object type, when the policy says (from rel)
CREATE FUNCTION authz_int.role_owner_type(p_object_type text) RETURNS text
LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $f$
BEGIN
  CASE p_object_type
{role_owner_types or "    WHEN NULL THEN NULL;"}
    ELSE RETURN NULL;
  END CASE;
END $f$;
"""
            + """-- relations ('role:<id>') of the custom roles that include a permission
CREATE FUNCTION authz_int.role_relations(p_type text, p_perm text) RETURNS text[]
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $f$
  SELECT coalesce(array_agg('role:' || r.id), '{}') FROM authz.roles r
  JOIN authz.role_permissions p ON p.role_id = r.id
  WHERE r.object_type = p_type AND p.permission = p_perm $f$;
-- deleting a role removes its assignments
CREATE FUNCTION authz_int.role_gone() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $f$
BEGIN
  DELETE FROM authz.shares WHERE relation IN (SELECT 'role:' || o.id FROM old_rows o);
  RETURN NULL;
END $f$;
CREATE TRIGGER authz_role_gone AFTER DELETE ON authz.roles
  REFERENCING OLD TABLE AS old_rows FOR EACH STATEMENT EXECUTE FUNCTION authz_int.role_gone();"""
        )

        link_columns = "id text, relation text, created_by text, created_at timestamptz, expires_at timestamptz"
        link_overloads = "\n".join(
            f"CREATE FUNCTION authz.list_links(p_type text, p_id {pt}) RETURNS TABLE ({link_columns}) LANGUAGE sql STABLE AS\n"
            f"  $$ SELECT * FROM authz.list_links(p_type, p_id::text) $$;\n"
            f"CREATE FUNCTION authz.revoke_link(p_type text, p_id {pt}, p_link text) RETURNS void LANGUAGE sql AS\n"
            f"  $$ SELECT authz.revoke_link(p_type, p_id::text, p_link) $$;"
            for pt in sorted({t.pktype for t in self.types.values()} - {"text"})
        )
        api = f"""-- Share: needs the relation's 'shared by' permission on the object, and every permission
-- the relation grants (you can't grant more than you hold); the subject must exist
CREATE FUNCTION authz.share(p_type text, p_id text, p_relation text,
  p_subject_type text, p_subject_id text, p_subject_relation text DEFAULT '',
  p_expires_at timestamptz DEFAULT NULL, p_starts_at timestamptz DEFAULT NULL,
  p_caveat text DEFAULT NULL, p_caveat_args jsonb DEFAULT NULL) RETURNS void
LANGUAGE plpgsql {DEFINER} AS $f$
DECLARE v_tbl text; v_find text; v_found boolean; v_key text; v_rel authz_int.shared_relations; v_need text;
        v_role authz.roles;
BEGIN
  PERFORM authz_int.check_writable();
  p_id := authz_int.canon(p_type, p_id);
  p_subject_id := authz_int.canon(p_subject_type, p_subject_id);
  IF NOT EXISTS (SELECT 1 FROM authz.principal()) THEN
    RAISE EXCEPTION 'you cannot share % %', p_type, p_id USING ERRCODE = 'insufficient_privilege', HINT = 'rowstile help AZ705';
  END IF;
  -- lock the object (FOR KEY SHARE): a concurrent delete waits for us, or we for it
  SELECT t.tbl, t.find INTO v_tbl, v_find FROM authz_int.types t WHERE t.name = p_type;
  IF v_tbl IS NULL THEN RAISE EXCEPTION 'no type % in the policy', p_type USING HINT = 'rowstile help AZ707'; END IF;
  IF NOT pg_catalog.pg_input_is_valid(p_id, (SELECT keytype FROM authz_int.types WHERE name = p_type)) THEN
    RAISE EXCEPTION 'you cannot share % %', p_type, p_id USING ERRCODE = 'insufficient_privilege', HINT = 'rowstile help AZ705';
  END IF;
  EXECUTE format('SELECT EXISTS (SELECT 1 FROM %s x WHERE %s FOR KEY SHARE)', v_tbl, v_find) INTO v_found USING p_id;
  -- a caller who may share nothing on the object gets the answer a missing object gets (this same RAISE),
  -- before the subject and the relation are looked at: sharing never tells a hidden object from a missing one
  v_found := v_found AND EXISTS (
    SELECT 1 FROM (SELECT s.shared_by AS perm FROM authz_int.shared_relations s WHERE s.object_type = p_type
                   UNION SELECT 'share') x
    -- (CASE: authz.can raises for a permission the type doesn't have, and AND doesn't say which runs first)
    WHERE CASE WHEN EXISTS (SELECT 1 FROM authz_int.perms WHERE type = p_type AND perm = x.perm)
               THEN authz.can(p_type, p_id, x.perm) ELSE false END);
  IF NOT v_found THEN
    RAISE EXCEPTION 'you cannot share % %', p_type, p_id USING ERRCODE = 'insufficient_privilege', HINT = 'rowstile help AZ705';
  END IF;
  v_key := CASE WHEN p_subject_type IN ('anyone', 'link') THEN p_subject_type
                WHEN p_subject_id = '*' AND p_subject_relation = '' THEN p_subject_type || ':*'
                WHEN p_subject_relation <> '' THEN p_subject_type || '#' || p_subject_relation
                ELSE p_subject_type END;
  -- the subject must exist (and is locked, like the object)
  IF v_key NOT LIKE '%:*' AND v_key NOT IN ('anyone', 'link') THEN
    SELECT t.tbl, t.find INTO v_tbl, v_find FROM authz_int.types t WHERE t.name = p_subject_type;
    v_found := v_tbl IS NOT NULL AND pg_catalog.pg_input_is_valid(p_subject_id,
                 (SELECT keytype FROM authz_int.types WHERE name = p_subject_type));
    IF v_found THEN
      EXECUTE format('SELECT EXISTS (SELECT 1 FROM %s x WHERE %s FOR KEY SHARE)', v_tbl, v_find)
        INTO v_found USING p_subject_id;
    END IF;
    IF NOT v_found THEN
      RAISE EXCEPTION 'there is no % %', p_subject_type, p_subject_id USING HINT = 'rowstile help AZ708';
    END IF;
  END IF;
  IF p_relation LIKE 'role:%' THEN
    -- a custom role: its type must match, the subject must be allowed, and you must hold all it grants
    SELECT * INTO v_role FROM authz.roles WHERE 'role:' || id = p_relation;
    IF v_role.id IS NULL OR v_role.object_type <> p_type THEN
      RAISE EXCEPTION 'no role % for %', p_relation, p_type USING HINT = 'rowstile help AZ706';
    END IF;
    IF NOT authz_int.role_owned(p_type, p_id, v_role.owner_type, v_role.owner_id) THEN
      RAISE EXCEPTION 'role % belongs to % %, which doesn''t own % %', v_role.name, v_role.owner_type, v_role.owner_id,
        p_type, p_id USING HINT = 'rowstile help AZ706';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM authz_int.role_subjects WHERE object_type = p_type AND subject = v_key) THEN
      RAISE EXCEPTION 'custom roles on % cannot be given to %', p_type, v_key USING HINT = 'rowstile help AZ706';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM authz_int.perms WHERE type = p_type AND perm = 'share')
       OR NOT authz.can(p_type, p_id, 'share') THEN
      RAISE EXCEPTION 'you cannot share % %', p_type, p_id USING ERRCODE = 'insufficient_privilege', HINT = 'rowstile help AZ705';
    END IF;
    SELECT string_agg(permission, ', ') INTO v_need FROM authz.role_permissions
    WHERE role_id = v_role.id AND NOT authz.can(p_type, p_id, permission);
    IF v_need IS NOT NULL THEN
      RAISE EXCEPTION 'you cannot give role % on % %: you do not hold %', v_role.name, p_type, p_id, v_need
        USING ERRCODE = 'insufficient_privilege', HINT = 'rowstile help AZ705';
    END IF;
  ELSE
    SELECT * INTO v_rel FROM authz_int.shared_relations s
    WHERE s.object_type = p_type AND s.relation = p_relation AND s.subject = v_key;
    IF v_rel.relation IS NULL THEN
      RAISE EXCEPTION 'the policy does not allow sharing %.% with %', p_type, p_relation, v_key USING HINT = 'rowstile help AZ706';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM authz_int.perms WHERE type = p_type AND perm = v_rel.shared_by)
       OR NOT authz.can(p_type, p_id, v_rel.shared_by) THEN
      RAISE EXCEPTION 'you cannot share % % (needs %)', p_type, p_id, v_rel.shared_by USING ERRCODE = 'insufficient_privilege', HINT = 'rowstile help AZ705';
    END IF;
    SELECT string_agg(n, ', ') INTO v_need FROM unnest(v_rel.required) n WHERE NOT authz.can(p_type, p_id, n);
    IF v_need IS NOT NULL THEN
      RAISE EXCEPTION 'you cannot grant %.% on % %: you do not hold %', p_type, p_relation, p_type, p_id, v_need
        USING ERRCODE = 'insufficient_privilege', HINT = 'rowstile help AZ705';
    END IF;
    IF NOT authz_int.share_if(p_type || '.' || p_relation || '.' || v_key, p_id, p_subject_type,
                              p_subject_id, p_subject_relation) THEN
      RAISE EXCEPTION 'the policy does not allow this share (%)', {self.line_sql(None, None, "v_rel.loc")} USING ERRCODE = 'insufficient_privilege', HINT = 'rowstile help AZ705';
    END IF;
  END IF;
  IF p_caveat IS NOT NULL AND NOT EXISTS (SELECT 1 FROM authz_int.caveats WHERE name = p_caveat) THEN
    RAISE EXCEPTION 'no caveat % in the policy', p_caveat USING HINT = 'rowstile help AZ707';
  END IF;
  PERFORM authz_int.mark_shared(p_type, p_id);
  IF v_key NOT LIKE '%:*' AND v_key NOT IN ('anyone', 'link') THEN
    PERFORM authz_int.mark_shared(p_subject_type, p_subject_id);
  END IF;
  INSERT INTO authz.shares (object_type, object_id, relation, subject_type, subject_id, subject_relation,
                            expires_at, created_by, starts_at, caveat, caveat_args)
  VALUES (p_type, p_id, p_relation, p_subject_type, p_subject_id, p_subject_relation,
          p_expires_at, authz_int.actor(), p_starts_at, p_caveat, p_caveat_args)
  ON CONFLICT ON CONSTRAINT shares_pkey
  DO UPDATE SET expires_at = EXCLUDED.expires_at, created_by = EXCLUDED.created_by,
                starts_at = EXCLUDED.starts_at, caveat = EXCLUDED.caveat, caveat_args = EXCLUDED.caveat_args;
END $f$;
CREATE FUNCTION authz.share(p_type text, p_id bigint, p_relation text, p_subject_type text, p_subject_id bigint,
  p_subject_relation text DEFAULT '', p_expires_at timestamptz DEFAULT NULL, p_starts_at timestamptz DEFAULT NULL,
  p_caveat text DEFAULT NULL, p_caveat_args jsonb DEFAULT NULL) RETURNS void LANGUAGE sql AS
  $$ SELECT authz.share(p_type, p_id::text, p_relation, p_subject_type, p_subject_id::text, p_subject_relation,
                        p_expires_at, p_starts_at, p_caveat, p_caveat_args) $$;
CREATE FUNCTION authz.share(p_type text, p_id bigint, p_relation text, p_subject_type text, p_subject_id text,
  p_subject_relation text DEFAULT '', p_expires_at timestamptz DEFAULT NULL, p_starts_at timestamptz DEFAULT NULL,
  p_caveat text DEFAULT NULL, p_caveat_args jsonb DEFAULT NULL) RETURNS void LANGUAGE sql AS
  $$ SELECT authz.share(p_type, p_id::text, p_relation, p_subject_type, p_subject_id, p_subject_relation,
                        p_expires_at, p_starts_at, p_caveat, p_caveat_args) $$;

-- Unshare: needs what sharing needs (the relation's 'shared by' permission)
CREATE FUNCTION authz.unshare(p_type text, p_id text, p_relation text,
  p_subject_type text, p_subject_id text, p_subject_relation text DEFAULT '') RETURNS void
LANGUAGE plpgsql {DEFINER} AS $f$
DECLARE v_by text;
BEGIN
  PERFORM authz_int.check_writable();
  p_id := authz_int.canon(p_type, p_id);
  p_subject_id := authz_int.canon(p_subject_type, p_subject_id);
  v_by := coalesce(authz_int.manage_perm(p_type, p_relation,
                                         authz_int.subject_key(p_subject_type, p_subject_id, p_subject_relation)),
                   authz_int.manage_perm(p_type, p_relation));
  -- what it needs comes from the policy alone: the same words for a hidden object and a missing one
  IF NOT EXISTS (SELECT 1 FROM authz.principal()) OR v_by IS NULL
     OR NOT EXISTS (SELECT 1 FROM authz_int.perms WHERE type = p_type AND perm = v_by)
     OR NOT authz.can(p_type, p_id, v_by) THEN
    IF v_by IS NULL THEN
      RAISE EXCEPTION 'you cannot unshare % on % %', p_relation, p_type, p_id USING ERRCODE = 'insufficient_privilege', HINT = 'rowstile help AZ705';
    END IF;
    RAISE EXCEPTION 'you cannot unshare % on % % (needs %)', p_relation, p_type, p_id, v_by USING ERRCODE = 'insufficient_privilege', HINT = 'rowstile help AZ705';
  END IF;
  DELETE FROM authz.shares WHERE object_type = p_type AND object_id = p_id
    AND relation = p_relation AND subject_type = p_subject_type
    AND subject_id = p_subject_id AND subject_relation = p_subject_relation;
END $f$;
CREATE FUNCTION authz.unshare(p_type text, p_id bigint, p_relation text, p_subject_type text, p_subject_id bigint,
  p_subject_relation text DEFAULT '') RETURNS void LANGUAGE sql AS
  $$ SELECT authz.unshare(p_type, p_id::text, p_relation, p_subject_type, p_subject_id::text, p_subject_relation) $$;
CREATE FUNCTION authz.unshare(p_type text, p_id bigint, p_relation text, p_subject_type text, p_subject_id text,
  p_subject_relation text DEFAULT '') RETURNS void LANGUAGE sql AS
  $$ SELECT authz.unshare(p_type, p_id::text, p_relation, p_subject_type, p_subject_id, p_subject_relation) $$;

-- A link anyone holding the token can use: returns the token once (only its hash is stored).
-- Requests present it with SET LOCAL authz_ctx.links = '<token>'.
CREATE FUNCTION authz.create_link(p_type text, p_id text, p_relation text, p_expires_at timestamptz DEFAULT NULL)
RETURNS text LANGUAGE plpgsql {DEFINER} AS $f$
DECLARE v_token text := replace(gen_random_uuid()::text || gen_random_uuid()::text, '-', '');
BEGIN
  PERFORM authz.share(p_type, p_id, p_relation, 'link', encode(sha256(convert_to(v_token, 'UTF8')), 'hex'),
                      '', p_expires_at);
  RETURN v_token;
END $f$;
CREATE FUNCTION authz.create_link(p_type text, p_id bigint, p_relation text, p_expires_at timestamptz DEFAULT NULL)
RETURNS text LANGUAGE sql AS $$ SELECT authz.create_link(p_type, p_id::text, p_relation, p_expires_at) $$;

-- The relations whose links on an object the caller may see: every one it has links of if they may inspect it
-- (they can share it, or are an administrator), else those they may share with a link. NULL: none
CREATE FUNCTION authz_int.link_relations(p_type text, p_id text) RETURNS text[]
LANGUAGE plpgsql STABLE {DEFINER} AS $f$
BEGIN
  IF authz_int.may_inspect(p_type, p_id) THEN
    RETURN coalesce((SELECT array_agg(DISTINCT g.relation) FROM authz.shares g
                     WHERE g.object_type = p_type AND g.object_id = p_id AND g.subject_type = 'link'), '{{}}');
  END IF;
  RETURN (SELECT array_agg(s.relation) FROM authz_int.shared_relations s
          WHERE s.object_type = p_type AND s.subject = 'link'
            AND authz_int.may_manage(p_type, p_id, s.relation, 'link'));
END $f$;
-- The links on an object: SELECT * FROM authz.list_links('folder', 3). For those who can share it, or may make
-- such links. A link's id names it for authz.revoke_link: it is not the token, and opens nothing.
CREATE FUNCTION authz.list_links(p_type text, p_id text)
RETURNS TABLE (id text, relation text, created_by text, created_at timestamptz, expires_at timestamptz)
LANGUAGE plpgsql STABLE {DEFINER} AS $f$
DECLARE v_relations text[];
BEGIN
  p_id := authz_int.canon(p_type, p_id);
  v_relations := authz_int.link_relations(p_type, p_id);
  IF v_relations IS NULL THEN
    RAISE EXCEPTION 'you cannot see the links of % %', p_type, p_id USING ERRCODE = 'insufficient_privilege', HINT = 'rowstile help AZ705';
  END IF;
  RETURN QUERY SELECT {LINK_ID}, g.relation, g.created_by, g.created_at, g.expires_at
  FROM authz.shares g WHERE g.object_type = p_type AND g.object_id = p_id AND g.subject_type = 'link'
    AND g.relation = ANY (v_relations) ORDER BY g.created_at, g.subject_id;
END $f$;
-- Turn a link off, by its id in authz.list_links: needs what unsharing it needs
CREATE FUNCTION authz.revoke_link(p_type text, p_id text, p_link text) RETURNS void
LANGUAGE plpgsql {DEFINER} AS $f$
DECLARE v_relations text[]; v record; v_found boolean := false;
BEGIN
  PERFORM authz_int.check_writable();
  p_id := authz_int.canon(p_type, p_id);
  v_relations := authz_int.link_relations(p_type, p_id);
  IF v_relations IS NULL THEN
    RAISE EXCEPTION 'you cannot turn off the links of % %', p_type, p_id USING ERRCODE = 'insufficient_privilege', HINT = 'rowstile help AZ705';
  END IF;
  FOR v IN SELECT g.relation, g.subject_id FROM authz.shares g
           WHERE g.object_type = p_type AND g.object_id = p_id AND g.subject_type = 'link'
             AND g.relation = ANY (v_relations) AND {LINK_ID} = p_link LOOP
    IF NOT authz_int.may_manage(p_type, p_id, v.relation, 'link') THEN
      RAISE EXCEPTION 'you cannot turn off link % of % % (you could not unshare it)', p_link, p_type, p_id
        USING ERRCODE = 'insufficient_privilege', HINT = 'rowstile help AZ705';
    END IF;
    DELETE FROM authz.shares g WHERE g.object_type = p_type AND g.object_id = p_id AND g.relation = v.relation
      AND g.subject_type = 'link' AND g.subject_id = v.subject_id;
    v_found := true;
  END LOOP;
  IF NOT v_found THEN
    RAISE EXCEPTION 'no link % on % %', p_link, p_type, p_id USING HINT = 'rowstile help AZ708';
  END IF;
END $f$;
{link_overloads}

-- Custom roles: defined per owner (e.g. an org) by people with 'manage_roles' there
CREATE FUNCTION authz.create_role(p_owner_type text, p_owner_id text, p_object_type text, p_name text,
  p_permissions text[]) RETURNS bigint LANGUAGE plpgsql {DEFINER} AS $f$
DECLARE v_id bigint; v_bad text;
BEGIN
  PERFORM authz_int.check_writable();
  IF NOT EXISTS (SELECT 1 FROM authz_int.perms WHERE type = p_owner_type AND perm = 'manage_roles') THEN
    RAISE EXCEPTION '% has no manage_roles permission in the policy', p_owner_type USING HINT = 'rowstile help AZ707';
  END IF;
  -- a type without `roles` (or one the policy doesn't have): a role there would be one nobody can be given
  IF NOT EXISTS (SELECT 1 FROM authz_int.role_subjects WHERE object_type = p_object_type) THEN
    RAISE EXCEPTION 'no custom roles on % in the policy', p_object_type USING HINT = 'rowstile help AZ707';
  END IF;
  IF authz.uid() IS NULL OR NOT authz.can(p_owner_type, p_owner_id, 'manage_roles') THEN
    RAISE EXCEPTION 'you cannot manage roles of % %', p_owner_type, p_owner_id USING ERRCODE = 'insufficient_privilege', HINT = 'rowstile help AZ705';
  END IF;
  IF p_owner_type IS DISTINCT FROM coalesce(authz_int.role_owner_type(p_object_type), p_owner_type) THEN
    RAISE EXCEPTION 'custom roles on % belong to a % (the policy says where they come from), not to a %',
      p_object_type, authz_int.role_owner_type(p_object_type), p_owner_type USING HINT = 'rowstile help AZ706';
  END IF;
  SELECT string_agg(p, ', ') INTO v_bad FROM unnest(p_permissions) p
  WHERE NOT EXISTS (SELECT 1 FROM authz_int.role_grantable g WHERE g.object_type = p_object_type AND g.permission = p);
  IF v_bad IS NOT NULL THEN
    RAISE EXCEPTION 'custom roles on % cannot grant %', p_object_type, v_bad USING HINT = 'rowstile help AZ706';
  END IF;
  INSERT INTO authz.roles (owner_type, owner_id, object_type, name, created_by)
  VALUES (p_owner_type, authz_int.canon(p_owner_type, p_owner_id), p_object_type, p_name, authz.uid()::text)
  RETURNING id INTO v_id;
  INSERT INTO authz.role_permissions SELECT v_id, p FROM unnest(p_permissions) p ON CONFLICT DO NOTHING;
  RETURN v_id;
END $f$;
CREATE FUNCTION authz.create_role(p_owner_type text, p_owner_id bigint, p_object_type text, p_name text,
  p_permissions text[]) RETURNS bigint LANGUAGE sql AS
  $$ SELECT authz.create_role(p_owner_type, p_owner_id::text, p_object_type, p_name, p_permissions) $$;
CREATE FUNCTION authz.set_role_permissions(p_role bigint, p_permissions text[]) RETURNS void
LANGUAGE plpgsql {DEFINER} AS $f$
DECLARE v authz.roles; v_bad text;
BEGIN
  PERFORM authz_int.check_writable();
  SELECT * INTO v FROM authz.roles WHERE id = p_role;
  IF v.id IS NULL OR authz.uid() IS NULL OR NOT authz.can(v.owner_type, v.owner_id, 'manage_roles') THEN
    RAISE EXCEPTION 'you cannot manage role %', p_role USING ERRCODE = 'insufficient_privilege', HINT = 'rowstile help AZ705';
  END IF;
  SELECT string_agg(p, ', ') INTO v_bad FROM unnest(p_permissions) p
  WHERE NOT EXISTS (SELECT 1 FROM authz_int.role_grantable g WHERE g.object_type = v.object_type AND g.permission = p);
  IF v_bad IS NOT NULL THEN RAISE EXCEPTION 'custom roles on % cannot grant %', v.object_type, v_bad USING HINT = 'rowstile help AZ706'; END IF;
  DELETE FROM authz.role_permissions WHERE role_id = p_role;
  INSERT INTO authz.role_permissions SELECT p_role, p FROM unnest(p_permissions) p ON CONFLICT DO NOTHING;
END $f$;
CREATE FUNCTION authz.delete_role(p_role bigint) RETURNS void LANGUAGE plpgsql {DEFINER} AS $f$
DECLARE v authz.roles;
BEGIN
  PERFORM authz_int.check_writable();
  SELECT * INTO v FROM authz.roles WHERE id = p_role;
  IF v.id IS NULL OR authz.uid() IS NULL OR NOT authz.can(v.owner_type, v.owner_id, 'manage_roles') THEN
    RAISE EXCEPTION 'you cannot manage role %', p_role USING ERRCODE = 'insufficient_privilege', HINT = 'rowstile help AZ705';
  END IF;
  DELETE FROM authz.roles WHERE id = p_role;
END $f$;
CREATE FUNCTION authz.roles_of(p_owner_type text, p_owner_id text)
RETURNS TABLE (id bigint, object_type text, name text, permissions text[])
LANGUAGE plpgsql STABLE {DEFINER} AS $f$
BEGIN
  IF authz.uid() IS NULL OR NOT (
       (EXISTS (SELECT 1 FROM authz_int.perms WHERE type = p_owner_type AND perm = 'manage_roles')
        AND authz.can(p_owner_type, p_owner_id, 'manage_roles'))
    OR (EXISTS (SELECT 1 FROM authz_int.perms WHERE type = p_owner_type AND perm = 'view')
        AND authz.can(p_owner_type, p_owner_id, 'view'))) THEN
    RAISE EXCEPTION 'you cannot see roles of % %', p_owner_type, p_owner_id USING ERRCODE = 'insufficient_privilege', HINT = 'rowstile help AZ705';
  END IF;
  RETURN QUERY SELECT r.id, r.object_type, r.name,
    ARRAY(SELECT p.permission FROM authz.role_permissions p WHERE p.role_id = r.id ORDER BY 1)
    FROM authz.roles r WHERE r.owner_type = p_owner_type AND r.owner_id = p_owner_id ORDER BY r.id;
END $f$;
CREATE FUNCTION authz.roles_of(p_owner_type text, p_owner_id bigint)
RETURNS TABLE (id bigint, object_type text, name text, permissions text[]) LANGUAGE sql STABLE AS
  $$ SELECT * FROM authz.roles_of(p_owner_type, p_owner_id::text) $$;"""
        return catalog, share_if + "\n\n" + role_relations + "\n\n" + SHARE_MARKS, api

    # --- output ---------------------------------------------------------
    def search_path_sql(self) -> str:
        """The functions made below that evaluate the policy's own SQL keep the search path in effect now (SET
        search_path FROM CURRENT) and run as the owner: only the schemas that exist ("$user" is resolved, so a schema
        by that name made later isn't on it), temporary schema last; refused if a role that isn't trusted anyway
        may create in one of them."""
        writers = path_writers_sql("pg_catalog.current_schemas(false)", "CURRENT_USER")
        return f"""-- Functions below resolve names with the search_path in effect now: the schemas that exist, temporary schema last
DO $sp$
DECLARE v_path text; v_bad text; f record;
BEGIN
  SELECT pg_catalog.string_agg(pg_catalog.format('%I (%s)', pw.schema, pw.who), ', ') INTO v_bad FROM ({writers}) pw;
  IF v_bad IS NOT NULL THEN
    RAISE EXCEPTION 'the search path has schemas that roles other than the owner may create objects in: % [AZ612]', v_bad
      USING HINT = 'rowstile''s functions that run as the owner resolve names on this path, so a function made there could run as the owner: revoke CREATE on those schemas, or apply with a search path without them';
  END IF;
  SELECT pg_catalog.string_agg(pg_catalog.quote_ident(s.name), ', ' ORDER BY s.i) INTO v_path
  FROM pg_catalog.unnest(pg_catalog.current_schemas(false)) WITH ORDINALITY s(name, i)
  WHERE s.name::text !~ '^pg_temp_';
  PERFORM pg_catalog.set_config('search_path', pg_catalog.concat_ws(', ', v_path, 'pg_temp'), true);
  -- functions made before (a migration keeps those it doesn't change) take the same path
  FOR f IN SELECT p.oid::regprocedure AS fn FROM pg_catalog.pg_proc p
           WHERE p.pronamespace IN (SELECT n.oid FROM pg_catalog.pg_namespace n WHERE n.nspname IN ('authz', 'authz_gen', 'authz_int'))
             AND EXISTS (SELECT 1 FROM pg_catalog.unnest(p.proconfig) c
                         WHERE c ^@ 'search_path=' AND c <> 'search_path=pg_catalog, pg_temp'
                           AND c <> 'search_path=' || pg_catalog.current_setting('search_path')) LOOP
    EXECUTE pg_catalog.format('ALTER FUNCTION %s SET search_path FROM CURRENT', f.fn);
  END LOOP;
END $sp$;"""

    def revoke_sql(self) -> str:
        """Nobody but the owner keeps a privilege on authz, authz_gen, authz_int or what is in them, except what
        the policy grants below (a previous version of the policy may have named another role; the owner's default
        privileges give new objects to others)."""
        return f"""-- Privileges the policy doesn't give on rowstile's schemas and what is in them are taken back
DO $r$
DECLARE g record; v_taken int := 0;
BEGIN
  FOR g IN {self.extra_grants_sql()} LOOP
    EXECUTE g.stmt;
    v_taken := v_taken + 1;
  END LOOP;
  IF v_taken > 0 THEN
    RAISE WARNING 'took back % privileges on rowstile''s schemas that the policy doesn''t give (default privileges of the owner, or grants made since the last apply)', v_taken;
  END IF;
END $r$;"""

    def masked_view_sql(self) -> list[str]:
        """Views that show the rows 'select' allows, with masked columns NULL where their rule does not hold.
        The app role loses direct SELECT on masked columns of the table."""
        out = []
        # each table's select rule: one (compile refuses two, AZ109), and a table with a view has it (AZ402)
        selects = {r.table: r for r in self.rules if r.command == "select" and not r.columns}
        for table, view in self.pol.views.items():
            t = self.governing(table)
            alias = q(table.split(".")[1])
            sel = selects[table]
            where = f"(SELECT authz_int.scope_cmd({lit(table)}, 'select')) AND {self.rule_sql(t, alias, sel)}"
            masks = [
                (c, self.rule_sql(t, alias, r), r)
                for r in self.rules
                if r.table == table and r.command == "mask"
                for c in r.columns
            ]
            cases = "\n".join(
                f"      WHEN {lit(c)} THEN format('CASE WHEN %s THEN %I.%I END AS %I', {lit(cond)}, "
                f"{lit(table.split('.')[1])}, a.attname, a.attname)"
                for c, cond, r in masks
            )
            col_expr = (
                f"CASE a.attname\n{cases}\n      ELSE format('%I.%I', {lit(table.split('.')[1])}, a.attname) END"
                if masks
                else f"format('%I.%I', {lit(table.split('.')[1])}, a.attname)"
            )
            notes = "".join(
                f"-- mask {', '.join(r.columns)} ({r.loc}): {r.src}\n" for r in {id(r): r for _, _, r in masks}.values()
            )
            out.append(f"""-- {view}: the rows of {table} the user may select ({sel.loc}: {sel.src})
{notes}-- @object view {qt(view)}
DO $mv$
DECLARE cols text; uses text;
BEGIN
  SELECT string_agg({col_expr}, ', ' ORDER BY a.attnum) INTO cols
  FROM pg_attribute a WHERE a.attrelid = {lit(qt(table))}::regclass AND a.attnum > 0 AND NOT a.attisdropped;
  -- in place when it is there: what the app built on it (a view over it) goes on working
  BEGIN
    EXECUTE format('CREATE OR REPLACE VIEW {qt(view)} WITH (security_barrier) AS SELECT %s FROM {qt(table)} {alias} WHERE %s',
                   cols, {lit(where)});
  EXCEPTION WHEN invalid_table_definition THEN
    -- its columns are not the ones it had (the table's changed): made anew, unless something is built on it
    BEGIN
      DROP VIEW {qt(view)};
    EXCEPTION WHEN dependent_objects_still_exist THEN
      GET STACKED DIAGNOSTICS uses = PG_EXCEPTION_DETAIL;
      RAISE EXCEPTION 'the masked view {view} can''t be replaced in place: the columns of {table} changed, and something is built on the view [AZ617]'
        USING DETAIL = uses, HINT = 'drop what is built on it, apply (or run the migration) again, then make it again';
    END;
    EXECUTE format('CREATE VIEW {qt(view)} WITH (security_barrier) AS SELECT %s FROM {qt(table)} {alias} WHERE %s',
                   cols, {lit(where)});
  END;
END $mv$;
COMMENT ON VIEW {qt(view)} IS 'rowstile masked view';
REVOKE ALL ON {qt(view)} FROM PUBLIC;
GRANT SELECT ON {qt(view)} TO {self.role};""")
        masked: dict[str, list[str]] = {}
        for r in self.rules:
            if r.command == "mask":
                masked.setdefault(r.table, []).extend(r.columns)
        current = ", ".join(lit(qt(tb) + "|" + self.role) for tb in masked)
        per_table = "\n".join(
            f"""  -- {tb}: {", ".join(cols)} only through {self.pol.views[tb]}
  IF has_table_privilege({lit(self.role)}, {lit(qt(tb))}, 'SELECT')
     OR EXISTS (SELECT 1 FROM authz.masked_tables WHERE tbl = {lit(qt(tb))} AND role = {lit(self.role)}) THEN
    REVOKE SELECT ON {qt(tb)} FROM {self.role};
    SELECT string_agg(format('%I', attname), ', ') INTO cols FROM pg_attribute
    WHERE attrelid = {lit(qt(tb))}::regclass AND attnum > 0 AND NOT attisdropped
      AND attname <> ALL (ARRAY[{", ".join(lit(c) for c in cols)}]);
    IF cols IS NOT NULL THEN EXECUTE format('GRANT SELECT (%s) ON {qt(tb)} TO {self.role}', cols); END IF;
    INSERT INTO authz.masked_tables VALUES ({lit(qt(tb))}, {lit(self.role)}) ON CONFLICT DO NOTHING;
  END IF;
  REVOKE SELECT ({", ".join(q(c) for c in cols)}) ON {qt(tb)} FROM {self.role};
  IF {" OR ".join(f"has_column_privilege({lit(self.role)}, {lit(qt(tb))}, {lit(c)}, 'SELECT')" for c in cols)} THEN
    RAISE EXCEPTION '{self.role} could still read masked columns of {tb} directly [AZ611]'
      USING HINT = 'SELECT on the table or these columns is granted to PUBLIC or to a role {self.role} belongs to; revoke it, then apply again';
  END IF;"""
            for tb, cols in masked.items()
        )
        out.append(f"""-- Column privileges: masked columns are read through the masked view only
DO $mc$
DECLARE r record; cols text;
BEGIN
  -- tables that are no longer masked get back the table-wide SELECT they had
  FOR r IN SELECT * FROM authz.masked_tables WHERE (tbl || '|' || role) <> ALL (ARRAY[{current}]::text[]) LOOP
    IF to_regclass(r.tbl) IS NOT NULL AND EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r.role) THEN
      EXECUTE format('GRANT SELECT ON %s TO %I', r.tbl, r.role);
    END IF;
    DELETE FROM authz.masked_tables WHERE tbl = r.tbl AND role = r.role;
  END LOOP;
{per_table}
END $mc$;""")
        rows = ", ".join(
            f"({lit(qt(tb))}, {lit(c)}, {lit(qt(self.pol.views[tb]))})" for tb, cols in masked.items() for c in cols
        )
        out.append(
            "CREATE TABLE authz_int.masked_columns (tbl text, col text, view text, PRIMARY KEY (tbl, col));"
            + (f"\nINSERT INTO authz_int.masked_columns VALUES {rows};" if rows else "")
        )
        return out

    def kept_views_sql(self) -> str:
        """The whole script's last look at masked views (see RESET_MASKED_VIEWS)."""
        # the whole script only: a masked view the reset emptied in place (something is built on it) that this
        # policy doesn't define is still empty
        ours = ", ".join(f"to_regclass({lit(qt(v))})::oid" for v in self.pol.views.values())
        return f"""DO $kv$
DECLARE v_old text;
BEGIN
  SELECT string_agg(c.oid::regclass || ' (' || (
           SELECT string_agg(DISTINCT pg_catalog.pg_describe_object(d.classid, d.objid, 0), ', ')
           FROM pg_depend d WHERE d.refclassid = 'pg_class'::regclass AND d.refobjid = c.oid AND d.deptype = 'n'
             AND NOT (d.classid = 'pg_rewrite'::regclass AND d.objid IN (SELECT oid FROM pg_rewrite WHERE ev_class = c.oid))) || ')', '; ')
  INTO v_old FROM pg_class c JOIN pg_description d ON d.objoid = c.oid AND d.classoid = 'pg_class'::regclass
  WHERE c.relkind = 'v' AND d.description IN {VIEW_MARKS} AND c.oid <> ALL (ARRAY[{ours}]::oid[]);
  IF v_old IS NOT NULL THEN
    RAISE EXCEPTION 'this policy no longer makes a masked view that something in the database is built on: % [AZ617]', v_old
      USING HINT = 'Drop or change what is built on it, then apply again.';
  END IF;
END $kv$;"""

    def compile(self, source_name: str, transaction: bool = True) -> str:
        """The SQL that applies the policy, base tables included. With transaction (for psql), it is one
        transaction; without, it runs inside the caller's (the rowstile command's)."""
        for t in self.types.values():
            for p in t.perms.values():
                self.ensure_view(t, p)
        policies: list[str] = []
        column_rules: list[str] = []
        by_table: dict[str, list[Rule]] = {}
        for rule in self.rules:
            if any(r.command == rule.command and r.columns == rule.columns for r in by_table.get(rule.table, [])):
                fail(rule.loc, f"{rule.table} has two '{rule_name(rule)}' rules", "AZ109")
            by_table.setdefault(rule.table, []).append(rule)
        for table, rules in by_table.items():
            t = self.governing(table)
            alias = q(table.split(".")[1])
            cmds = {r.command: r for r in rules if not r.columns}
            policies.append(
                f"ALTER TABLE {qt(table)} ENABLE ROW LEVEL SECURITY;\n"
                + DESCENDANTS_RLS.replace("{table}", lit(qt(table)))
            )
            # refused writes raise with the rule and why (refusals.py); an allowed write never calls these
            explaining, refuse = self.refusal_sql(t, table, alias, rules)
            policies += explaining
            for r in rules:
                if r.command == "mask":
                    continue
                if r.command == "update check" or r.columns:
                    if "update" not in cmds:
                        fail(r.loc, f"'{rule_name(r)}' refines updates, so {table} needs an 'update' rule too", "AZ403")
                    if r.columns:
                        column_rules.append(self.column_rule_sql(t, alias, r, len(column_rules) + 1))
                    continue
                # writes check one row at a time; select may read many, so it keeps the list-friendly views
                sql = (
                    f"((SELECT authz_int.scope_cmd({lit(table)}, {lit(r.command)})) AND "
                    f"{self.rule_sql(t, alias, r, point=r.command != 'select', invoker=True)})"
                )
                head = f"-- {table} {r.command} ({r.loc}): {r.src}\n"
                name = q("authz_" + r.command)
                if r.command == "insert":
                    policies.append(
                        f"{head}CREATE POLICY {name} ON {qt(table)} FOR INSERT TO {self.role}\n"
                        f"  WITH CHECK ({sql}\n    OR {refuse['insert']});"
                    )
                elif r.command == "update" and "update check" in cmds:
                    c = cmds["update check"]
                    # the scope's word on updates, as in USING: a scope without them refuses the row after too
                    check = (
                        f"((SELECT authz_int.scope_cmd({lit(table)}, 'update')) AND "
                        f"{self.rule_sql(t, alias, c, point=True, invoker=True)})"
                    )
                    head += f"-- {table} update after ({c.loc}): {c.src}\n"
                    policies.append(
                        f"{head}CREATE POLICY {name} ON {qt(table)} FOR UPDATE TO {self.role}\n"
                        f"  USING ({sql})\n  WITH CHECK ({check}\n    OR {refuse['update check']});"
                    )
                elif r.command == "update":
                    # the new row is checked as Postgres would anyway (with USING), then refused with the reason
                    policies.append(
                        f"{head}CREATE POLICY {name} ON {qt(table)} FOR UPDATE TO {self.role}\n"
                        f"  USING ({sql})\n  WITH CHECK ({sql}\n    OR {refuse['update']});"
                    )
                else:
                    policies.append(
                        f"{head}CREATE POLICY {name} ON {qt(table)} FOR {r.command.upper()} TO {self.role}\n"
                        f"  USING ({sql});"
                    )
                policies.append(f"COMMENT ON POLICY {name} ON {qt(table)} IS 'rowstile';")

        shared_types = {
            t.name
            for t in self.types.values()
            for r in t.relations.values()
            for src in r.sources
            if src.kind in ("shared", "roles")
        }
        shared_types |= {
            st
            for t in self.types.values()
            for r in t.relations.values()
            for src in r.sources
            if src.kind in ("shared", "roles")
            for st, _ in src.subjects
            if st in self.types
        }
        forget_types = [n for n in self.types if n in shared_types]
        verify = " AND ".join([f"authz_int.{q(n + '_verify')}()" for n in self.trees.values()] or ["true"])
        checks = "\n".join(
            f"  IF to_regclass({lit(qt(tbl))}) IS NULL THEN missing := missing || E'\\n  {loc}: table {tbl} not found [AZ601]';\n"
            f"  ELSIF NOT EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid = to_regclass({lit(qt(tbl))})\n"
            f"                    AND attname = {lit(col)} AND attnum > 0 AND NOT attisdropped) THEN\n"
            f"    missing := missing || E'\\n  {loc}: column {col} not found in {tbl} [AZ601]';\n  END IF;"
            for tbl, col, loc in dict.fromkeys((a, b, str(c)) for a, b, c in self.columns)
        )
        # the column's own type, as a type line writes it (varchar for character varying): what to write
        pk_checks = "\n".join(
            f"  SELECT atttypid, replace(format_type(atttypid, NULL), 'character varying', 'varchar') INTO v_oid, v_type\n"
            f"  FROM pg_attribute WHERE attrelid = to_regclass({lit(qt(tbl))}) AND attname = {lit(pk)} AND attnum > 0 AND NOT attisdropped;\n"
            f"  IF FOUND AND v_oid <> to_regtype({lit(pkt)}) THEN\n"
            f"    missing := missing || E'\\n  {loc}: {tbl}.{pk} is ' || v_type || E', not {pkt}: write its type after the key, ({pk} ' || v_type || ') [AZ602]';\n"
            f"  END IF;"
            for tbl, pk, pkt, loc in self.pk_checks
        )
        rule_tables = ", ".join(f"{lit(qt(tb))}::regclass" for tb in by_table)
        fk_warning = (
            f"""-- Foreign keys that delete governed rows skip row-level security
DO $fk$
DECLARE c record;
BEGIN
  FOR c IN SELECT con.conname, con.conrelid::regclass AS child, con.confrelid::regclass AS parent
           FROM pg_constraint con
           WHERE con.contype = 'f' AND con.confdeltype = 'c' AND con.conrelid IN ({rule_tables}) LOOP
    RAISE WARNING 'foreign key % on % is ON DELETE CASCADE: deleting a row of % also deletes rows of %, and cascades skip row-level security, so a user could remove rows they cannot see. Use ON DELETE RESTRICT unless that is intended.',
      c.conname, c.child, c.parent, c.child;
  END LOOP;
END $fk$;"""
            if by_table
            else ""
        )

        typed = [t for t in self.types.values() if t.pktype != "text"]
        index_names = [ident(f"shares_obj_{t.name}_{t.pktype}") for t in typed]
        grant_indexes = [
            f"""-- per-type indexes on share ids, for lookups by object
DO $gi$
DECLARE i record;
BEGIN
  FOR i IN SELECT c.relname FROM pg_index x JOIN pg_class c ON c.oid = x.indexrelid
           WHERE x.indrelid = 'authz.shares'::regclass AND (c.relname LIKE 'shares\\_obj\\_%' OR c.relname LIKE 'grants\\_obj\\_%')
             AND c.relname <> ALL (ARRAY[{", ".join(lit(n) for n in index_names)}]::text[]) LOOP
    EXECUTE format('DROP INDEX authz.%I', i.relname);
  END LOOP;
END $gi$;"""
        ] + [
            f"CREATE INDEX IF NOT EXISTS {q(n)} ON authz.shares ((object_id::{t.pktype}), relation) "
            f"WHERE object_type = {lit(t.name)};"
            for t, n in zip(typed, index_names, strict=True)
        ]
        canonical = CANONICAL_SHARES if any(t.pktype != "text" or t.composite for t in self.types.values()) else ""
        # (a subject id '*' names no row: it is every signed-in principal of the type, user:*)
        sweep = (
            canonical
            + "-- Shares on rows that no longer exist (deleted while no trigger watched them) are dropped\n"
            + "\n".join(
                f"DELETE FROM authz.shares g WHERE g.{side}_type = {lit(t.name)} "
                + ("AND g.subject_id <> '*' " if side == "subject" else "")
                + "AND NOT EXISTS "
                f"(SELECT 1 FROM {qt(t.table)} x WHERE {self.key_text(t, 'x')} = g.{side}_id);"
                for t in self.types.values()
                for side in ("object", "subject")
            )
            + "\n-- ...and so are the API keys of principals that no longer exist\n"
            + "\n".join(
                f"DELETE FROM authz.api_keys k WHERE k.principal_type = {lit(t.name)} AND NOT EXISTS "
                f"(SELECT 1 FROM {qt(t.table)} x WHERE {self.key_text(t, 'x')} = k.user_id);"
                for t in self.types.values()
                if t.principal
            )
        )
        catalog_share, share_internal, share_api = self.share_sql()
        # these may add views, so they run before the views are written out
        insight = [
            "-- these functions call each other; their bodies are checked when first used\n"
            "SET LOCAL check_function_bodies = off;",
            *self.who_sql(),
            *self.why_sql(),
            self.insight_api_sql(),
            self.invariant_sql(),
            "SET LOCAL check_function_bodies = on;",
        ]
        masked_views = self.masked_view_sql()
        self._list_cases = self.list_cases_sql()
        perms = [(t, p) for t in self.types.values() for p in self.public_perms(t)]
        catalog = [
            "-- per type: its table, key, how to find a row x by an id ($1, text), and a row's id (columns unqualified)\n"
            "CREATE TABLE authz_int.types (name text PRIMARY KEY, tbl text NOT NULL, pk text NOT NULL, pktype text NOT NULL,\n"
            "  keytype text NOT NULL, find text NOT NULL, id_of text NOT NULL, principal boolean NOT NULL);",
            "INSERT INTO authz_int.types VALUES\n  "
            + ",\n  ".join(
                f"({lit(t.name)}, {lit(qt(t.table))}, {lit(', '.join(c for c, _ in t.key))}, {lit(t.pktype)}, "
                f"{lit(t.keytype)}, {lit(self.key_is(t, 'x', '$1' if t.composite else '$1::' + t.keytype))}, {lit(self.bare_key_text(t))}, {str(t.principal).lower()})"
                for t in self.types.values()
            )
            + ";",
            "CREATE TABLE authz_int.perms (type text, perm text, PRIMARY KEY (type, perm));",
            (
                "INSERT INTO authz_int.perms VALUES\n  "
                + ",\n  ".join(f"({lit(t.name)}, {lit(p)})" for t, p in perms)
                + ";"
            )
            if perms
            else "",
            "CREATE TABLE authz_int.locks (type text PRIMARY KEY, n bigint NOT NULL);",
            "-- a row for each row a share was made on or to (authz_int.mark_shared), until that row is gone\n"
            "CREATE TABLE authz_int.share_marks (type text, id text, n bigint NOT NULL DEFAULT 0, PRIMARY KEY (type, id));",
            "-- each inheritance table's definition and the tables it reads, to keep it on the next apply if they are the same\n"
            "CREATE TABLE authz_int.trees (name text PRIMARY KEY, hash text NOT NULL, oids oid[] NOT NULL);",
            (
                "INSERT INTO authz_int.trees VALUES\n  "
                + ",\n  ".join(
                    f"({lit(n)}, {lit(h)}, {self.oids_sql(tables)})" for n, (h, tables) in self.tree_keep.items()
                )
                + ";"
            )
            if self.tree_keep
            else "",
            *catalog_share,
        ]
        drop_generated = f"""-- Functions this policy generates are recreated (whatever their old signatures). One that something of
-- the app's uses (a view that calls authz.can) stays, to be replaced in place
DO $g$
DECLARE f record; kept text := '';
BEGIN
  FOR f IN SELECT p.oid, p.ctid, p.oid::regprocedure AS name FROM pg_proc p WHERE p.pronamespace = to_regnamespace('authz')
           AND p.proname = ANY (ARRAY[{", ".join(lit(n) for n in GENERATED_FUNCTIONS)}]) LOOP
    BEGIN
      EXECUTE format('DROP FUNCTION %s', f.name);
    EXCEPTION WHEN dependent_objects_still_exist THEN
      kept := kept || f.oid || ' ' || f.ctid || ';';
    END;
  END LOOP;
  PERFORM set_config('authz_ctx.kept_functions', kept, true);
END $g$;"""
        # a kept function this policy didn't replace is the old one still: its row in pg_proc is where it was
        kept_functions = """DO $k$
DECLARE v_old text;
BEGIN
  SELECT string_agg(p.oid::regprocedure || ' (' || (
           SELECT string_agg(DISTINCT pg_catalog.pg_describe_object(d.classid, d.objid, 0), ', ')
           FROM pg_depend d WHERE d.refclassid = 'pg_proc'::regclass AND d.refobjid = p.oid AND d.deptype = 'n') || ')', '; ')
  INTO v_old FROM pg_proc p
  WHERE p.oid || ' ' || p.ctid = ANY (string_to_array(current_setting('authz_ctx.kept_functions', true), ';'));
  PERFORM set_config('authz_ctx.kept_functions', '', true);
  IF v_old IS NOT NULL THEN
    RAISE EXCEPTION 'this policy no longer makes a function that something in the database uses: % [AZ614]', v_old
      USING HINT = 'Drop or change what uses it, then apply again.';
  END IF;
END $k$;"""
        executes = self.api_signatures()

        shares_warning = """DO $w$
DECLARE n bigint;
BEGIN
  SELECT count(*) INTO n FROM authz.shares g WHERE g.relation NOT LIKE 'role:%' AND NOT EXISTS (
    SELECT 1 FROM authz_int.shared_relations s WHERE s.object_type = g.object_type AND s.relation = g.relation
      AND s.subject = CASE WHEN g.subject_type IN ('anyone', 'link') THEN g.subject_type
                           WHEN g.subject_id = '*' AND g.subject_relation = '' THEN g.subject_type || ':*'
                           WHEN g.subject_relation <> '' THEN g.subject_type || '#' || g.subject_relation
                           ELSE g.subject_type END);
  IF n > 0 THEN
    RAISE WARNING '% shares are for relations this policy does not declare as shared; they are kept, but grant nothing', n;
  END IF;
END $w$;"""
        # right after the shared relations are written (so a migration that changes them warns too)
        at = max(
            i
            for i, c in enumerate(catalog)
            if c.startswith(("CREATE TABLE authz_int.shared_relations", "INSERT INTO authz_int.shared_relations"))
        )
        catalog.insert(at + 1, shares_warning)
        uid_check, uid_fn = self.uid_sql().split("CREATE OR REPLACE FUNCTION authz.uid()")
        # What the migrations (migrate.py) do with each part: 'full', only in the whole script (it recreates
        # everything); 'always', in every migration; 'changed', when its SQL changed; 'created', also when
        # anything was made; 'objects', what changed of its functions, views, tables, triggers and policies;
        # 'tree', an inheritance tree, rebuilt when its definition changed.
        parts = [
            ("full", "header", f"-- Generated by rowstile from {source_name}. Edit the policy file, not this file."),
            ("full", "begin", "BEGIN;" if transaction else ""),
            (
                "full",
                "lock_timeout",
                "-- Applying locks the app's tables. Wait for them 10 s at most (unless lock_timeout is set) instead\n"
                "-- of queueing every query behind this transaction on a busy database; retry when it is quieter\n"
                "SELECT pg_catalog.set_config('lock_timeout', '10s', true) "
                "WHERE pg_catalog.current_setting('lock_timeout') IN ('0', '0ms');",
            ),
            ("always", "search_path", self.search_path_sql()),
            # applying twice in one transaction: the first apply's table is still there
            ("full", "reset", "DROP TABLE IF EXISTS pg_temp.authz_old_tables;"),
            ("full", "reset", DROP_OLD_POLICIES),
            ("full", "reset", RESET_MASKED_VIEWS),
            ("full", "reset", self.keep_sql()),
            ("full", "reset", "DROP SCHEMA IF EXISTS authz_gen, authz_int CASCADE;"),
            ("full", "reset", drop_generated),
            ("changed", "base", BASE_SQL),
            (
                "changed",
                "tables",
                f"DO $chk$\nDECLARE missing text := ''; v_oid oid; v_type text;\nBEGIN\n{checks}\n{pk_checks}\n"
                f"  IF missing <> '' THEN RAISE EXCEPTION 'the policy does not match this database:%', missing; END IF;\nEND $chk$;",
            ),
            ("full", "uid_type", uid_check),
            ("objects", "uid", "CREATE OR REPLACE FUNCTION authz.uid()" + uid_fn),
            ("objects", "schemas", "CREATE SCHEMA authz_gen;\nCREATE SCHEMA authz_int;"),
            ("objects", "session", self.session_sql()),
            ("objects", "keys", self.keys_sql()),
            ("objects", "principals", self.principals_sql()),
            *[("objects", "catalog", c) for c in catalog if c],
            ("changed", "share_indexes", "\n".join(grant_indexes)),
            ("objects", "scopes", self.scope_sql()),
            ("objects", "feed", self.feed_sql()),
            (
                "changed",
                "sweep",
                "DO $r$ BEGIN PERFORM set_config('authz_ctx.reason', 'applying the policy: the row was deleted', true); END $r$;\n\n"
                + sweep
                + "\n\nDO $r$ BEGIN PERFORM set_config('authz_ctx.reason', '', true); END $r$;",
            ),
            ("objects", "share_internal", share_internal),
            *[("tree", name, sql) for name, sql in zip(self.tree_names, self.tree_sql, strict=True)],
            (
                "full",
                "keep",
                "-- trees kept but no longer used (none, normally) go with the holding schema\n"
                "DROP SCHEMA authz_keep CASCADE;",
            ),
            *[("objects", "forget", self.forget_sql(self.T(n))) for n in forget_types],
            *[("objects", "audit", x) for x in self.relationship_audit_sql()],
            *[("objects", "views", x) for x in self.view_sql],
            *[("objects", "rules", x) for x in policies + column_rules],
            ("changed", "cascades", fk_warning),
            *[("objects", "masks", x) for x in masked_views[:-2]],
            ("changed", "mask_privileges", masked_views[-2]),
            ("objects", "masks", masked_views[-1]),
            ("objects", "api", self.api_sql()),
            ("objects", "share_api", share_api),
            ("objects", "explain_rule", self.explain_rule_sql(list(by_table))),
            ("objects", "who_among", self.who_among_sql()),
            *[("objects", "insight", x) for x in insight],
            ("objects", "identity", self.identity_api_sql()),
            *[("objects", "keys_gone", self.key_forget_sql(t)) for t in self.types.values() if t.principal],
            ("objects", "workflow", self.workflow_sql()),
            ("objects", "child_triggers", CHILD_TRIGGERS_FN),
            ("objects", "lint", self.lint_sql()),
            ("objects", "connection_check", self.connection_check_sql()),
            (
                "objects",
                "verify",
                "-- Admin check: every inheritance table matches a from-scratch rebuild\n"
                "CREATE FUNCTION authz.verify() RETURNS boolean LANGUAGE sql STABLE AS\n"
                f"  $$ SELECT {verify} $$;",
            ),
            # last: the generators above say which lines their messages name
            ("objects", "lines", self.lines_sql()),
            ("full", "kept_functions", kept_functions),
            ("full", "kept_views", self.kept_views_sql()),
            ("full", "lost_rules", LOST_RULES),
            # after every trigger is made
            ("always", "children", CHILD_TRIGGERS),
            ("always", "revoke", self.revoke_sql()),
            ("always", "revoke", "REVOKE ALL ON ALL FUNCTIONS IN SCHEMA authz FROM PUBLIC;"),
            ("always", "grant_usage", f"GRANT USAGE ON SCHEMA authz, authz_gen TO {self.role};"),
            ("created", "grant_views", f"GRANT SELECT ON ALL TABLES IN SCHEMA authz_gen TO {self.role};"),
            ("always", "revoke", "REVOKE ALL ON ALL FUNCTIONS IN SCHEMA authz_gen FROM PUBLIC;"),
            ("created", "grant_functions", f"GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA authz_gen TO {self.role};"),
            ("created", "grant_api", "GRANT EXECUTE ON FUNCTION\n  " + ",\n  ".join(executes) + f"\n  TO {self.role};"),
            ("always", "analyze", self.analyze_sql()),
            ("full", "commit", "COMMIT;" if transaction else ""),
        ]
        self.parts = [(mode, name, sql.strip()) for mode, name, sql in parts if sql and sql.strip()]
        # the whole script replaces the functions the reset kept (migrations replace the ones that changed)
        return (
            re.sub(
                r"^CREATE FUNCTION authz\.",
                "CREATE OR REPLACE FUNCTION authz.",
                "\n\n".join(sql for _, _, sql in self.parts),
                flags=re.M,
            )
            + "\n"
        )

    def analyze_sql(self) -> str:
        """ANALYZE the tables the policy reads, and rowstile's own, that were never analyzed."""
        tables = ", ".join(f"{lit(qt(tb))}" for tb in dict.fromkeys(tb for tb, _, _ in self.columns))
        return f"""-- Tables never analyzed (made just now, or too small for autovacuum to have reached them) are planned
-- as ten pages of rows: a table of 6 rows as thousands. Through the rules' lookups that becomes an estimate of
-- hundreds of thousands, and Postgres compiles (JIT) and plans for reads of a few rows. ANALYZE reads a
-- sample (30,000 rows at most) and blocks neither reads nor writes.
DO $an$
DECLARE r record;
BEGIN
  FOR r IN SELECT c.oid::regclass AS tbl FROM pg_class c
           WHERE c.relkind = 'r' AND c.relpersistence <> 't' AND c.reltuples < 0
             AND pg_has_role(c.relowner, 'USAGE')
             AND (c.relnamespace IN (SELECT oid FROM pg_namespace WHERE nspname IN ('authz', 'authz_int'))
                  OR c.oid = ANY (SELECT to_regclass(x) FROM unnest(ARRAY[{tables or "NULL"}]::text[]) x)) LOOP
    EXECUTE format('ANALYZE %s', r.tbl);
  END LOOP;
END $an$;"""

    @staticmethod
    def oids_sql(tables: list[str]) -> str:
        return (
            "ARRAY["
            + ", ".join(
                f"to_regclass({lit(qt(tb) if '.' in tb and not tb.startswith('authz.') else tb)})::oid" for tb in tables
            )
            + "]::oid[]"
        )

    def keep_sql(self) -> str:
        """Inheritance tables of the last apply whose definition and tables are the same now: moved aside
        before the schema is dropped, then back in place of their new, empty tables (trees.swap_in_kept)."""
        rows = ", ".join(f"({lit(n)}, {lit(h)}, {self.oids_sql(tables)})" for n, (h, tables) in self.tree_keep.items())
        return f"""-- Inheritance tables that don't change keep their rows: moved aside now, back after the schema is recreated
DROP TABLE IF EXISTS pg_temp.authz_kept;
CREATE TEMP TABLE authz_kept (name text PRIMARY KEY) ON COMMIT DROP;
DROP SCHEMA IF EXISTS authz_keep CASCADE;
CREATE SCHEMA authz_keep;
DO $keep$
DECLARE r record;
BEGIN
  IF to_regclass('authz_int.trees') IS NULL THEN RETURN; END IF;          -- the first apply
  FOR r IN SELECT t.name FROM authz_int.trees t
           JOIN (VALUES {rows or "(NULL::text, NULL::text, NULL::oid[])"}) n(name, hash, oids)
             ON n.name = t.name AND n.hash = t.hash AND n.oids = t.oids
           WHERE to_regclass(format('authz_int.%I', t.name)) IS NOT NULL LOOP
    EXECUTE format('ALTER TABLE authz_int.%I SET SCHEMA authz_keep', r.name);
    IF to_regclass(format('authz_int.%I', r.name || '_cond_cache')) IS NOT NULL THEN
      EXECUTE format('ALTER TABLE authz_int.%I SET SCHEMA authz_keep', r.name || '_cond_cache');
    END IF;
  END LOOP;
END $keep$;"""

    def principals_sql(self) -> str:
        """Who is signed in: authz.user_id says the id, authz.principal_type the type (empty: a user).
        authz.uid() is the user; each other principal type gets authz_int."<type>__me"(); authz.principal()
        is whoever it is, and authz_int.actor() how the audit trail names them ('7', 'service:3')."""
        setting = "pg_catalog.current_setting('authz.user_id', true)"
        out, cases = [], ["    WHEN 'user' THEN principal_id := authz.uid()::text;"]
        for t in self.types.values():
            if not t.principal or t.name == "user":
                continue
            cast = (
                f"CASE WHEN {SESSION_OK} AND {PT} = {lit(t.name)} "
                f"AND pg_catalog.pg_input_is_valid({setting}, {lit(t.pktype)}) THEN {setting}::{t.pktype} END"
            )
            where = f" AND coalesce(({on_row(t.where, 'w')}), false)" if t.where else ""
            body = f"BEGIN RETURN (SELECT w.{q(self.pk(t))} FROM {qt(t.table)} w WHERE w.{q(self.pk(t))} = ({cast}){where}); END"
            attrs = "LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path FROM CURRENT"
            out.append(
                f"-- the signed-in {t.name}, if a {t.name} is signed in (an id its table doesn't have"
                + (", or one failing the type's where," if t.where else "")
                + " counts as nobody)\n"
                f"CREATE FUNCTION authz_int.{q(t.name + '__me')}() RETURNS {t.pktype} {attrs} AS $me$ {body} $me$;"
                + read_now([where_rows(t.table, t.where, "w")] if t.where else [])
            )
            cases.append(f"    WHEN {lit(t.name)} THEN principal_id := authz_int.{q(t.name + '__me')}()::text;")
        whens = "\n".join(cases)
        out.append(f"""-- Who is signed in, whatever their type: SELECT * FROM authz.principal()
CREATE FUNCTION authz.principal() RETURNS TABLE (principal_type text, principal_id text)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path FROM CURRENT AS $f$
BEGIN
  principal_type := coalesce(nullif({PT}, ''), 'user');
  CASE principal_type
{whens}
    ELSE RETURN;
  END CASE;
  IF principal_id IS NOT NULL THEN RETURN NEXT; END IF;
END $f$;
-- how the audit trail and created_by name who acted: a user's id, or type:id for other principals
CREATE FUNCTION authz_int.actor() RETURNS text
LANGUAGE plpgsql STABLE {DEFINER} AS $f$
BEGIN
  RETURN CASE WHEN NOT {SESSION_OK} THEN NULL
              WHEN coalesce({PT}, '') IN ('', 'user') THEN nullif(current_setting('authz.user_id', true), '')
              ELSE {PT} || ':' || nullif(current_setting('authz.user_id', true), '') END;
END $f$;""")
        return "\n".join(out)

    def keys_sql(self) -> str:
        """A row type per composite key (to parse ids), and ids made canonical: a composite key's id is
        the text Postgres prints for the row, compared as text, so '(1, 42)' must become '(1,42)'."""
        composite = [t for t in self.types.values() if t.composite]
        types = [f"CREATE TYPE {t.keytype} AS ({', '.join(f'{q(c)} {ty}' for c, ty in t.key)});" for t in composite]
        cases = "\n".join(
            f"    WHEN {lit(t.name)} THEN\n"
            f"      IF pg_catalog.pg_input_is_valid(p_id, {lit(t.keytype)}) THEN RETURN p_id::{t.keytype}::text; END IF;"
            for t in self.types.values()
            if t.pktype != "text" or t.composite
        )
        canon = (
            f"""-- an id as it is stored and compared: '(1, 42)' -> '(1,42)', '007' -> '7' (invalid ids as they are)
CREATE FUNCTION authz_int.canon(p_type text, p_id text) RETURNS text
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, pg_temp AS $f$
BEGIN
  CASE p_type
{cases}
    ELSE NULL;
  END CASE;
  RETURN p_id;
END $f$;"""
            if cases
            else """CREATE FUNCTION authz_int.canon(p_type text, p_id text) RETURNS text
LANGUAGE sql IMMUTABLE AS $f$ SELECT p_id $f$;"""
        )
        # views cast stored ids to the key's type ('007' is 7), while the triggers that remove a row's shares and
        # apply's sweep compare text: every stored id must be canonical, whoever wrote it
        trigger = (
            """-- shares written directly get canonical ids too
CREATE FUNCTION authz_int.shares_canon() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $f$
BEGIN
  NEW.object_id := authz_int.canon(NEW.object_type, NEW.object_id);
  NEW.subject_id := authz_int.canon(NEW.subject_type, NEW.subject_id);
  RETURN NEW;
END $f$;
CREATE TRIGGER authz_shares_canon BEFORE INSERT OR UPDATE OF object_type, object_id, subject_type, subject_id
  ON authz.shares FOR EACH ROW EXECUTE FUNCTION authz_int.shares_canon();"""
            if cases
            else ""
        )
        return "\n".join(types + [canon, trigger])


CANONICAL_SHARES = """-- Shares stored with ids that aren't canonical ('007', an uppercase uuid: written directly before every
-- write went through authz_int.canon) are made canonical, since the sweep below and the triggers compare
-- text; one that then repeats a share already stored goes, the first made staying
CREATE TEMP TABLE authz_uncanonical ON COMMIT DROP AS
  SELECT g.ctid AS row, authz_int.canon(g.object_type, g.object_id) AS object_id,
         authz_int.canon(g.subject_type, g.subject_id) AS subject_id
  FROM authz.shares g
  WHERE g.object_id IS DISTINCT FROM authz_int.canon(g.object_type, g.object_id)
     OR g.subject_id IS DISTINCT FROM authz_int.canon(g.subject_type, g.subject_id);
DELETE FROM authz.shares g USING authz_uncanonical u
WHERE g.ctid = u.row AND EXISTS (
  SELECT 1 FROM authz.shares c WHERE c.object_type = g.object_type AND c.object_id = u.object_id AND c.relation = g.relation
    AND c.subject_type = g.subject_type AND c.subject_id = u.subject_id AND c.subject_relation = g.subject_relation);
DELETE FROM authz.shares g USING (
  SELECT u.row, row_number() OVER (PARTITION BY s.object_type, u.object_id, s.relation, s.subject_type, u.subject_id,
                                   s.subject_relation ORDER BY s.created_at, u.row) AS n
  FROM authz_uncanonical u JOIN authz.shares s ON s.ctid = u.row) d
WHERE g.ctid = d.row AND d.n > 1;
UPDATE authz.shares g SET object_id = u.object_id, subject_id = u.subject_id FROM authz_uncanonical u WHERE g.ctid = u.row;
DROP TABLE authz_uncanonical;

"""

DESCENDANTS_RLS = """-- its partitions and the tables that inherit from it: row-level security on, with no policies of their own,
-- so they are read and written through it only (read directly, they would skip its rules and triggers)
DO $rls$
DECLARE c regclass;
BEGIN
  FOR c IN WITH RECURSIVE d(oid) AS (
             SELECT i.inhrelid FROM pg_catalog.pg_inherits i WHERE i.inhparent = {table}::regclass
             UNION SELECT i.inhrelid FROM pg_catalog.pg_inherits i JOIN d ON i.inhparent = d.oid)
           SELECT d.oid::regclass FROM d JOIN pg_catalog.pg_class k ON k.oid = d.oid WHERE NOT k.relrowsecurity LOOP
    EXECUTE format('ALTER TABLE %s ENABLE ROW LEVEL SECURITY', c);
  END LOOP;
END $rls$;"""

# What apply does with them: gone, to be made again; one that something of the app's is built on (a view over it)
# can't be dropped, so it is emptied in place, and CREATE OR REPLACE VIEW defines it again further down
RESET_MASKED_VIEWS = (
    f"""-- The masked views the previous version made are made again; one that something is built on stays, emptied
DO $mv$
DECLARE v record; cols text;
BEGIN
  FOR v IN SELECT c.oid, c.oid::regclass AS name FROM pg_class c JOIN pg_description d ON d.objoid = c.oid
           AND d.classoid = 'pg_class'::regclass WHERE c.relkind = 'v' AND d.description IN {VIEW_MARKS} LOOP
    BEGIN
      EXECUTE format('DROP VIEW %s', v.name);
    EXCEPTION WHEN dependent_objects_still_exist THEN
      SELECT """
    + STUB_COLUMNS.replace("VIEW", "v.oid")
    + """ INTO cols;
      EXECUTE format('CREATE OR REPLACE VIEW %s AS SELECT %s WHERE false', v.name, cols);
    END;
  END LOOP;
END $mv$;"""
)

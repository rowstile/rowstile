"""authz.lint(): the ways around row-level security this database leaves open."""

from __future__ import annotations

from .compiler import MANY_EXPANSIONS, Core
from .parse import KEYWORDS, Cond, Loc, Ref, cols
from .sqlutil import CHILD_TRIGGER_MARK, POLICY_MARKS, VIEW_MARKS, lit, q, qt

DEF = "SECURITY DEFINER SET search_path = pg_catalog, pg_temp"


def path_writers_sql(schemas: str, owner: str) -> str:
    """(schema, who) for each schema of `schemas` (a name[] expression) that a role other than the trusted ones may
    create objects in: superusers, `owner` (the policy's owner) and the database's owner are trusted, with the
    roles that can become them. The functions that evaluate the policy's own SQL run as the owner with that search
    path, and a function there with an exact type match takes the place of a built-in one (CVE-2018-1058)."""
    return f"""SELECT n.nspname::text AS schema, w.who
FROM pg_catalog.unnest({schemas}) s(name) JOIN pg_catalog.pg_namespace n ON n.nspname = s.name,
LATERAL (SELECT CASE WHEN EXISTS (SELECT 1 FROM pg_catalog.aclexplode(n.nspacl) a
                                  WHERE a.grantee = 0 AND a.privilege_type = 'CREATE') THEN 'PUBLIC'
                ELSE (SELECT pg_catalog.string_agg(ro.rolname::text, ', ' ORDER BY ro.rolname) FROM pg_catalog.pg_roles ro
                      WHERE pg_catalog.has_schema_privilege(ro.oid, n.oid, 'CREATE') AND NOT ro.rolsuper
                        AND ro.rolname <> 'pg_database_owner' AND NOT pg_catalog.pg_has_role(ro.oid, {owner}, 'MEMBER')
                        AND NOT pg_catalog.pg_has_role(ro.oid, (SELECT d.datdba FROM pg_catalog.pg_database d
                                                               WHERE d.datname = pg_catalog.current_database()), 'MEMBER'))
                END AS who) w
-- a temporary schema is the session's own, and never searched for functions or operators
WHERE w.who IS NOT NULL AND n.nspname !~ '^pg_(toast_)?temp_'"""


class LintMixin(Core):
    def extra_grants_sql(self) -> str:
        """(object, who, privilege, stmt) for each privilege on authz, authz_gen, authz_int and what is in them
        that the policy doesn't give, with the REVOKE that takes it back. The policy gives the app role USAGE on
        authz and authz_gen, SELECT on policy_lines and on the authz_int views its rules read (app_views: it reads
        them through its rules alone, having no USAGE on authz_int), EXECUTE on the rules' own functions in authz_gen
        (app_functions) and on the API; authz_int's functions keep PUBLIC's EXECUTE (the rules and the views call them
        as the app role; nobody else may use the schema).
        Anything else comes from the owner's default privileges or a grant made since."""
        app = f"{lit(self.role)}::regrole"
        api = "ARRAY[" + ", ".join(lit(f) for f in self.api_signatures()) + "]::regprocedure[]"
        who = "LATERAL (SELECT CASE a.grantee WHEN 0 THEN 'PUBLIC' ELSE a.grantee::regrole::text END AS who) gw"
        ours = "(SELECT oid FROM pg_namespace WHERE nspname IN ('authz', 'authz_gen', 'authz_int'))"
        # the views by their quoted names, as the GRANT names them
        readable = (
            "ARRAY["
            + ", ".join(lit(n) for n in ['authz_gen."policy_lines"', *(f"authz_int.{q(v)}" for v in self.app_views)])
            + "]::text[]"
        )
        callable = "ARRAY[" + ", ".join(lit(f) for f in self.app_functions) + "]::text[]"
        return f"""SELECT n.nspname::text AS object, gw.who, a.privilege_type AS privilege,
       format('REVOKE %s ON SCHEMA %I FROM %s CASCADE', a.privilege_type, n.nspname, gw.who) AS stmt
  FROM pg_namespace n, aclexplode(n.nspacl) a, {who}
  WHERE n.nspname IN ('authz', 'authz_gen', 'authz_int') AND a.grantee <> n.nspowner
    AND NOT (a.grantee = {app} AND n.nspname <> 'authz_int' AND a.privilege_type = 'USAGE')
UNION ALL
SELECT c.oid::regclass::text, gw.who, a.privilege_type,
       format('REVOKE %s ON %s %s FROM %s CASCADE', a.privilege_type, CASE c.relkind WHEN 'S' THEN 'SEQUENCE' ELSE 'TABLE' END,
              c.oid::regclass, gw.who)
  FROM pg_class c, aclexplode(c.relacl) a, {who}
  WHERE c.relnamespace IN {ours} AND a.grantee <> c.relowner
    AND NOT (a.grantee = {app} AND a.privilege_type = 'SELECT'
             AND c.relnamespace::regnamespace::text || '."' || replace(c.relname, '"', '""') || '"' = ANY ({readable}))
UNION ALL
SELECT format('%s (%I)', c.oid::regclass, att.attname), gw.who, a.privilege_type,
       format('REVOKE %s (%I) ON %s FROM %s CASCADE', a.privilege_type, att.attname, c.oid::regclass, gw.who)
  FROM pg_class c JOIN pg_attribute att ON att.attrelid = c.oid, aclexplode(att.attacl) a, {who}
  WHERE c.relnamespace IN {ours} AND att.attacl IS NOT NULL
UNION ALL
SELECT p.oid::regprocedure::text, gw.who, a.privilege_type,
       format('REVOKE %s ON ROUTINE %s FROM %s CASCADE', a.privilege_type, p.oid::regprocedure, gw.who)
  FROM pg_proc p, aclexplode(p.proacl) a, {who}
  WHERE p.pronamespace IN {ours} AND a.grantee <> p.proowner
    AND NOT (p.pronamespace = 'authz_int'::regnamespace AND a.grantee IN (0, {app}))
    AND NOT (p.pronamespace = 'authz_gen'::regnamespace AND a.grantee = {app}
             AND '"' || replace(p.proname, '"', '""') || '"' = ANY ({callable}))
    AND NOT (p.pronamespace = 'authz'::regnamespace AND a.grantee = {app} AND p.oid = ANY ({api}))"""

    def api_signatures(self) -> list[str]:
        """The authz.* functions the app role may execute (the policy grants them): everything else there is
        for administrators."""
        typed = [t for t in self.types.values() if t.pktype != "text"]
        executes = [
            "authz.uid()",
            "authz.principal()",
            "authz.ctx(text)",
            "authz.link_hashes()",
            "authz.act_as(text, text)",
            "authz.connection_check()",
        ] + [
            f"{fn}"
            for fn in (
                "authz.can(text, text, text)",
                "authz.list(text, text, text, integer)",
                "authz.perms(text, text)",
                "authz.perms_of(text, text[])",
                "authz.share(text, text, text, text, text, text, timestamptz, timestamptz, text, jsonb)",
                "authz.share(text, bigint, text, text, bigint, text, timestamptz, timestamptz, text, jsonb)",
                "authz.share(text, bigint, text, text, text, text, timestamptz, timestamptz, text, jsonb)",
                "authz.unshare(text, text, text, text, text, text)",
                "authz.unshare(text, bigint, text, text, bigint, text)",
                "authz.unshare(text, bigint, text, text, text, text)",
                "authz.create_link(text, text, text, timestamptz)",
                "authz.create_link(text, bigint, text, timestamptz)",
                "authz.list_links(text, text)",
                "authz.revoke_link(text, text, text)",
                "authz.create_role(text, text, text, text, text[])",
                "authz.create_role(text, bigint, text, text, text[])",
                "authz.set_role_permissions(bigint, text[])",
                "authz.delete_role(bigint)",
                "authz.roles_of(text, text)",
                "authz.roles_of(text, bigint)",
                "authz.who(text, text, text)",
                "authz.explain(text, text, text, text)",
                "authz.list_shares(text, text)",
                "authz.explain_rule(text, text, text, jsonb)",
                "authz.who_among(text, text, text, text[], text)",
            )
        ]
        executes += [
            "authz.create_api_key(text, text, timestamptz, text, text)",
            "authz.list_api_keys(text, text)",
            "authz.revoke_api_key(bigint)",
            "authz.login_key(text)",
            "authz.login_jwt(text)",
            "authz.view_as(text, text)",
            "authz.request_access(text, text, text, text, interval)",
            "authz.request_access(text, bigint, text, text, interval)",
            "authz.pending_requests()",
            "authz.decide_request(bigint, boolean, text)",
            "authz.cancel_request(bigint)",
            "authz.break_glass(text, text, text, text, interval)",
            "authz.break_glass(text, bigint, text, text, interval)",
            "authz.start_review(text, text, timestamptz)",
            "authz.start_review(text, bigint, timestamptz)",
            "authz.review_items(bigint)",
            "authz.review_decide(bigint, integer, boolean)",
            "authz.close_review(bigint, boolean)",
        ]
        executes += [
            f"authz.{fn}(text, {pt}{args})"
            for pt in sorted({t.pktype for t in typed})
            for fn, args in (
                ("who", ", text"),
                ("explain", ", text, text"),
                ("list_shares", ""),
                ("list_links", ""),
                ("revoke_link", ", text"),
            )
        ]
        executes += [f"authz.can(text, {pt}, text)" for pt in sorted({t.pktype for t in typed})]
        executes += [f"authz.who_among(text, {pt}, text, text[], text)" for pt in sorted({t.pktype for t in typed})]
        executes += [f"authz.perms(text, {pt})" for pt in sorted({t.pktype for t in typed})]
        return executes

    def lint_sql(self) -> str:
        role = self.role
        governed = sorted({r.table for r in self.rules})
        typed_tables = sorted({t.table for t in self.types.values()})
        link_tables: set[str] = set()  # tables that hold relationships (who is in what)
        link_readers: dict[str, list[str]] = {}  # ... and the relations read from each
        # (table, column, what it grants, loc, the permission lint suggests asking for) for column sources
        link_cols: list[tuple[str, str, str, Loc, str]] = []
        # (table, columns, relation, loc): a column placing a row under another of its type
        move_cols: list[tuple[str, tuple[str, ...], str, Loc]] = []
        # (table, columns, why, the columns that serve the lookup alone too) that lookups go through: a (type, id)
        # pair is looked up by both, and an index on what pair_alone names serves it too, as rowstile indexes counts it
        index_cols: list[tuple[str, str, str, str]] = []
        for t in self.types.values():
            for r in t.relations.values():
                for src in r.sources:
                    lead = (src.type_col,) if (src.kind == "column" or src.kind == "table") and src.type_col else ()
                    if src.kind == "table":  # (never a custom roles' relation: its source is the roles)
                        table = src.table
                        link_tables.add(table)
                        link_readers.setdefault(table, []).append(f"{t.name}.{r.name}")
                        index_cols.append(
                            (
                                table,
                                ", ".join(cols(src.obj_col)),
                                f"{t.name}.{r.name}: find the members of an object",
                                "",
                            )
                        )
                        ids = cols(self.source_columns(src))
                        index_cols.append(
                            (
                                table,
                                ", ".join(lead + ids),
                                f"{t.name}.{r.name}: find what a subject is in",
                                ", ".join(self.pair_alone(src)),
                            )
                        )
                    elif src.kind == "column":
                        column = cols(self.source_columns(src))
                        # the type's own `share` where it has one: a suggestion that doesn't compile helps no one
                        ask = "share" if "share" in self.public_perms(t) or "share" in t.relations else "nobody"
                        for c in column + ((src.type_col,) if src.type_col else ()):
                            link_cols.append((t.table, c, f"{t.name}.{r.name}", src.loc, ask))
                        # (one that reads the row's own key is "this row", `self : user = id`: not a move)
                        if any(st == t.name for st, _ in src.subjects) and column != tuple(c for c, _ in t.key):
                            move_cols.append((t.table, column, r.name, src.loc))
                        shown = ", ".join(lead + column)
                        index_cols.append(
                            (
                                t.table,
                                shown,
                                f"{t.name}.{r.name}: find objects by {shown}",
                                ", ".join(self.pair_alone(src)),
                            )
                        )
            # each check on one object (authz.can, a write rule) finds its row by the key, as rowstile indexes says
            index_cols.append(
                (
                    t.table,
                    ", ".join(k for k, _ in t.key),
                    f"{t.name}: find one by its key, for checks and write rules",
                    "",
                )
            )
        # columns that grant something, on tables whose updates only need the plain 'update' rule
        guarded = {(r.table, c) for r in self.rules if r.columns and r.command != "mask" for c in r.columns}
        has_update = {r.table for r in self.rules if r.command == "update" and not r.columns}
        # (`update : nobody` lets no one change any column: there is nothing to guard)
        nobody = Cond(KEYWORDS["nobody"])
        open_update = {r.table for r in self.rules if r.command == "update" and not r.columns and r.expr != nobody}
        unguarded = [
            (tb, c, what, loc, ask)
            for tb, c, what, loc, ask in link_cols
            if tb in open_update and (tb, c) not in guarded
        ]
        # ...and those that move a row within its tree with nothing checking where it goes (an 'after' rule)
        after = {(r.table, c) for r in self.rules if r.command == "update after" for c in r.columns}
        after_all = {r.table for r in self.rules if r.command == "update after" and not r.columns}
        # a composite link ([org_id, parent_id]) is checked when one of its columns has an 'after' rule
        unchecked_moves = [
            (tb, ", ".join(cs), rel, loc)
            for tb, cs, rel, loc in move_cols
            if tb in has_update and not any((tb, c) in after for c in cs) and tb not in after_all
        ]
        arr = lambda xs: "ARRAY[" + ", ".join(lit(x) for x in xs) + "]::text[]"
        link_only = sorted(link_tables - set(governed))
        # (table, the relations read from it, whether it is a type's table too: those have a line of their own)
        link_rows = ", ".join(
            f"({lit(qt(t))}, {lit(', '.join(dict.fromkeys(link_readers.get(t, []))) or 'its relations')}, "
            f"{'true' if t in typed_tables else 'false'})"
            for t in link_only
        )
        whys: dict[tuple[str, str, str], list[str]] = {}
        for tb, c, why, alone in index_cols:
            whys.setdefault((tb, c, alone), []).append(why)
        idx_rows = ", ".join(
            f"({lit(qt(tb))}, {lit(c)}, {lit('; '.join(dict.fromkeys(w)))}, {lit(alone) if alone else 'NULL'})"
            for (tb, c, alone), w in whys.items()
        )
        unguarded_rows = ", ".join(
            f"({lit(qt(tb))}, {lit(c)}, {lit(what)}, {lit(self.line_key(f'relation {what} {c}', loc))}, {lit(ask)})"
            for tb, c, what, loc, ask in unguarded
        )
        # relations named like a type that signs in read, alone in a rule, like the type ("delete : user" is
        # the row's own user, not any user). One named like another type is only ever followed
        # ("project.edit"), which reads as what it means: `project : project = project_id` is no one's mistake
        shadows = [
            (t.name, r.name, str(r.loc))
            for t in self.types.values()
            for r in t.relations.values()
            if self.is_principal(r.name) and not r.synthetic
        ]
        # a rule for a command the app role may not run on the table at all: it never applies, and the
        # statement fails with Postgres's own "permission denied for table", which reads like the policy's
        # refusal. (`nobody` asks for no privilege; a rule on a column, or `after`, is an update's.)
        asked = sorted(
            {
                (r.table, "update" if r.command == "update after" else r.command)
                for r in self.rules
                if r.command != "mask" and r.expr != nobody
            }
        )
        rule_rows = ", ".join(f"({lit(qt(tb))}, {lit(cmd)})" for tb, cmd in asked)
        # principal types nobody can make keys for (they sign in only through a backend or JWTs)
        keyless = "".join(
            f"  severity := 'info'; object := {lit(t.name)};\n"
            f"  problem := {lit('signs in, but has no manage_keys permission, so nobody can make API keys for it: add can manage_keys = ... (')}"
            f" || {self.line_sql(f'type {t.name}', t.loc)} || ')';\n"
            f"  RETURN NEXT;\n"
            for t in self.types.values()
            if t.principal and t.name != "user" and "manage_keys" not in t.perms
        )
        # tables whose select rule makes Postgres write out many view definitions to plan one read: a
        # permission named more than once on the way is written out again each time (Core.expansions)
        heavy = ""
        for rule in self.rules:
            if rule.command != "select" or rule.columns:
                continue
            t = self.governing(rule.table)
            n = self.expansions(self.rule_sql(t, q(rule.table.split(".")[1]), rule))
            if n > MANY_EXPANSIONS:
                said = (
                    f"its select rule (' || {self.line_sql(f'rule {rule.table} select', rule.loc)} || ') names "
                    f"permissions that name others more than once, and Postgres writes each one out again every "
                    f"time: {n} view definitions to plan before a row is read, which can take a tenth of a "
                    f"second and more for every query. Name each permission once on the way"
                )
                heavy += (
                    f"  severity := 'warning'; object := to_regclass({lit(qt(rule.table))})::text;\n"
                    f"  problem := '{said}';\n  RETURN NEXT;\n"
                )
        # ...and any permission that does, whether a rule reads it or not: authz.list checks it on each row as a
        # select rule does, authz.can and write rules on one row (each way named at most once on the way)
        for t in self.types.values():
            for p in self.public_perms(t):
                perm = t.perms[p]
                n = max(self.expansions(self.row_sql(t, "o", Ref(p), perm.loc, point=point)) for point in (False, True))
                if n > MANY_EXPANSIONS:
                    said = (
                        f"names permissions that name others more than once (' || "
                        f"{self.line_sql(f'permission {t.name}.{p}', perm.loc)} || '), and Postgres writes each one out "
                        f"again every time: {n} view definitions to plan each check of it (authz.list, authz.can, a "
                        f"rule that names it) before a row is read, which can take a tenth of a second and more, up "
                        f"to a second or two. Name each permission once on the way"
                    )
                    heavy += (
                        f"  severity := 'warning'; object := {lit(f'{t.name}.{p}')};\n"
                        f"  problem := '{said}';\n  RETURN NEXT;\n"
                    )
        shadow_rows = ", ".join(
            f"({lit(tn)}, {lit(rn)}, {lit(self.line_key(f'relation {tn}.{rn}', loc))})" for tn, rn, loc in shadows
        )
        move_rows = ", ".join(
            f"({lit(qt(tb))}, {lit(c)}, {lit(rel)}, {lit(self.line_key(f'relation {tb} {rel} {c}', loc))})"
            for tb, c, rel, loc in unchecked_moves
        )
        return f"""-- The search path the functions that evaluate the policy's own SQL run with (SET search_path FROM CURRENT)
CREATE FUNCTION authz_int.policy_path() RETURNS name[]
LANGUAGE sql STABLE SET search_path FROM CURRENT AS $f$ SELECT pg_catalog.current_schemas(false) $f$;

-- Leaks: SELECT * FROM authz.lint()  (administrators; run after schema changes)
CREATE FUNCTION authz.lint() RETURNS TABLE (severity text, object text, problem text)
LANGUAGE plpgsql STABLE {DEF} AS $f$
DECLARE r record; v_role oid := to_regrole({lit(role)});
BEGIN
  IF v_role IS NULL THEN
    severity := 'error'; object := {lit(role)}; problem := 'the app role does not exist'; RETURN NEXT; RETURN;
  END IF;
  -- the app role itself
  FOR r IN SELECT rolsuper, rolbypassrls FROM pg_roles WHERE oid = v_role AND (rolsuper OR rolbypassrls) LOOP
    severity := 'error'; object := {lit(role)};
    problem := 'is a superuser or has BYPASSRLS: row-level security does not apply to it at all'; RETURN NEXT;
  END LOOP;
  FOR r IN SELECT p.oid::regrole AS parent FROM pg_roles p
           WHERE p.oid <> v_role AND (p.rolsuper OR p.rolbypassrls) AND pg_has_role(v_role, p.oid, 'MEMBER') LOOP
    severity := 'error'; object := {lit(role)};
    problem := format('is a member of %s, which bypasses row-level security', r.parent); RETURN NEXT;
  END LOOP;
  -- rowstile's own objects: nobody but the owner uses them, except for what the policy grants
  FOR r IN {self.extra_grants_sql()} LOOP
    severity := 'error'; object := r.object;
    problem := format('%s holds %s on it, which the policy doesn''t give (a default privilege of the owner, or a grant made since the last apply): the next apply takes it back, or %s', r.who, r.privilege, r.stmt);
    RETURN NEXT;
  END LOOP;
  -- schemas on the search path of the functions that run as the owner, which others may create in
  FOR r IN {path_writers_sql("authz_int.policy_path()", "(SELECT nspowner FROM pg_namespace WHERE nspname = 'authz_int')")} LOOP
    severity := 'error'; object := r.schema;
    problem := format('is on the search path of rowstile''s functions that run as the owner, and %s may create in it: a function there can take the place of a built-in one and run as the owner. REVOKE CREATE ON SCHEMA %I FROM %s, or apply with a search path without it', r.who, r.schema, r.who);
    RETURN NEXT;
  END LOOP;
  -- the audit trail's guard, which fires in every replication role (ENABLE ALWAYS): ENABLE TRIGGER ALL, which a
  -- data-only pg_restore --disable-triggers ends with, puts it back for ordinary sessions only
  FOR r IN SELECT t.name, g.tgenabled::text AS mode
           FROM (VALUES ('authz_audit_append_only'), ('authz_audit_no_truncate')) t (name)
           LEFT JOIN pg_trigger g ON g.tgrelid = 'authz.audit'::regclass AND g.tgname = t.name
           WHERE g.tgenabled IS DISTINCT FROM 'A' LOOP
    severity := 'warning'; object := 'authz.audit';
    problem := format('the trigger %s %s. rowstile reapply puts it back, in every replication role', r.name,
      CASE r.mode
        WHEN 'O' THEN 'guards it in ordinary sessions only: one with session_replication_role = replica may change the trail (ENABLE TRIGGER ALL leaves it so, as at the end of a data-only pg_restore --disable-triggers)'
        WHEN 'R' THEN 'guards it with session_replication_role = replica only: an ordinary session may change the trail'
        WHEN 'D' THEN 'that guards it is off: the trail may be changed'
        ELSE 'that guards it is missing: the trail may be changed' END);
    RETURN NEXT;
  END LOOP;
  -- governed tables
  FOR r IN SELECT c.oid::regclass AS tbl, c.relrowsecurity, c.relforcerowsecurity, c.relowner,
                  c.oid = ANY (SELECT to_regclass(x) FROM unnest({arr([qt(t) for t in governed])}) x) AS governed
           FROM pg_class c WHERE c.oid = ANY (SELECT to_regclass(x) FROM unnest({arr([qt(t) for t in typed_tables])}) x) LOOP
    IF r.relowner = v_role OR pg_has_role(v_role, r.relowner, 'MEMBER') THEN
      IF NOT r.relforcerowsecurity THEN
        severity := 'error'; object := r.tbl::text;
        problem := format('is owned by %s (or a role it belongs to): owners skip row-level security unless you ALTER TABLE %s FORCE ROW LEVEL SECURITY', {lit(role)}, r.tbl);
        RETURN NEXT;
      END IF;
    END IF;
    IF NOT r.relrowsecurity AND r.governed THEN
      severity := 'error'; object := r.tbl::text;
      problem := format('row-level security is off, so the policy''s rules don''t apply to it: %s reads and writes every row it has privileges on. Apply the policy again (it turns it on), or ALTER TABLE %s ENABLE ROW LEVEL SECURITY', {lit(role)}, r.tbl);
      RETURN NEXT;
    ELSIF NOT r.relrowsecurity AND has_table_privilege(v_role, r.tbl, 'SELECT') THEN
      severity := 'info'; object := r.tbl::text;
      problem := format('%s may read every row (the policy has no rules for this table): fine for a directory, otherwise add rules', {lit(role)});
      RETURN NEXT;
    END IF;
    IF has_table_privilege(v_role, r.tbl, 'TRUNCATE') THEN
      severity := 'error'; object := r.tbl::text;
      problem := format('%s may TRUNCATE it, which skips row-level security: REVOKE TRUNCATE ON %s FROM %s', {lit(role)}, r.tbl, {lit(role)});
      RETURN NEXT;
    END IF;
  END LOOP;
  -- policies on governed tables that rowstile didn't make (left from before, or made by a migration) and that
  -- apply to the app role: Postgres joins permissive policies with OR, so one widens what the rules allow
  FOR r IN SELECT p.polname, p.polrelid::regclass AS tbl, p.polpermissive,
                  CASE p.polcmd WHEN 'r' THEN 'select' WHEN 'a' THEN 'insert' WHEN 'w' THEN 'update'
                                WHEN 'd' THEN 'delete' ELSE 'every command' END AS cmd
           FROM pg_policy p
           LEFT JOIN pg_description d ON d.objoid = p.oid AND d.classoid = 'pg_policy'::regclass
           WHERE p.polrelid = ANY (SELECT to_regclass(x) FROM unnest({arr([qt(t) for t in governed])}) x)
             AND coalesce(d.description, '') NOT IN {POLICY_MARKS}
             AND EXISTS (SELECT 1 FROM unnest(p.polroles) o
                         WHERE CASE WHEN o = 0 THEN true ELSE pg_has_role(v_role, o, 'MEMBER') END)
           ORDER BY p.polrelid::regclass::text, p.polname LOOP
    object := r.tbl::text;
    IF r.polpermissive THEN
      severity := 'error';
      problem := format('the policy %I (%s) on it is not rowstile''s: Postgres joins a table''s policies with OR, so it lets %s through whatever the rules say. DROP POLICY %I ON %s, and say what it allowed in the policy file', r.polname, r.cmd, {lit(role)}, r.polname, r.tbl);
    ELSE
      severity := 'info';
      problem := format('the restrictive policy %I (%s) on it is not rowstile''s: %s gets less than the rules give, and a write it refuses fails with Postgres''s own message, not a reason', r.polname, r.cmd, {lit(role)});
    END IF;
    RETURN NEXT;
  END LOOP;
  -- tables beside the policy's (in their schemas) that it doesn't name: nothing filters what the app role reads there
  FOR r IN SELECT c.oid::regclass AS tbl FROM pg_class c
           WHERE c.relkind IN ('r', 'p') AND NOT c.relispartition AND NOT c.relrowsecurity
             AND c.relnamespace IN (SELECT k.relnamespace FROM unnest({arr([qt(t) for t in typed_tables + sorted(link_tables)])}) x
                                    JOIN pg_class k ON k.oid = to_regclass(x))
             AND c.oid NOT IN (SELECT to_regclass(x)::oid FROM unnest({arr([qt(t) for t in typed_tables + sorted(link_tables)])}) x
                               WHERE to_regclass(x) IS NOT NULL)
             AND has_any_column_privilege(v_role, c.oid, 'SELECT')
           ORDER BY c.oid::regclass::text LOOP
    severity := 'info'; object := r.tbl::text;
    problem := format('%s may read every row, and the policy doesn''t name this table: fine for a lookup table, otherwise give it a type and rules', {lit(role)});
    RETURN NEXT;
  END LOOP;
  -- partitions and inheritance children: used directly, they skip the rules of the table above (apply turns
  -- row-level security on for the ones there are then; later ones are found here), and TRUNCATE skips its
  -- triggers. The tables above: those with rules, and those rowstile watches (a trigger of its own on them)
  FOR r IN WITH RECURSIVE x(tbl, governed) AS (
             SELECT to_regclass(t), true FROM unnest({arr([qt(t) for t in governed])}) t
             UNION SELECT DISTINCT g.tgrelid::regclass, false FROM pg_trigger g
             JOIN pg_proc f ON f.oid = g.tgfoid AND f.pronamespace = 'authz_int'::regnamespace
             WHERE NOT g.tgisinternal AND g.tgrelid NOT IN (SELECT to_regclass(t) FROM unnest({arr([qt(t) for t in governed])}) t
                                                           WHERE to_regclass(t) IS NOT NULL)
               AND NOT EXISTS (SELECT 1 FROM pg_description c WHERE c.objoid = g.oid AND c.classoid = 'pg_trigger'::regclass
                               AND c.description = '{CHILD_TRIGGER_MARK}')),
           d(oid, top, governed) AS (
             SELECT i.inhrelid, i.inhparent, x.governed FROM pg_inherits i JOIN x ON i.inhparent = x.tbl
             UNION SELECT i.inhrelid, d.top, d.governed FROM pg_inherits i JOIN d ON i.inhparent = d.oid)
           SELECT d.oid::regclass AS part, d.top::regclass AS tbl, d.governed, k.relrowsecurity
           FROM d JOIN pg_class k ON k.oid = d.oid LOOP
    IF has_table_privilege(v_role, r.part, 'TRUNCATE') THEN
      severity := 'error'; object := r.part::text;
      problem := format('is a partition of %s (or inherits from it), and %s may TRUNCATE it, which skips row-level security and %s''s triggers: REVOKE TRUNCATE ON %s FROM %s', r.tbl, {lit(role)}, r.tbl, r.part, {lit(role)});
      RETURN NEXT;
    END IF;
    -- (on a table without rules, statements on it run the triggers of the table above as their own: the next loop
    -- finds one made since that lacks them)
    IF r.governed AND NOT r.relrowsecurity AND (has_table_privilege(v_role, r.part, 'INSERT') OR has_table_privilege(v_role, r.part, 'UPDATE')
                                 OR has_table_privilege(v_role, r.part, 'DELETE') OR has_table_privilege(v_role, r.part, 'SELECT')) THEN
      severity := 'error'; object := r.part::text;
      problem := format('is a partition of %s (or inherits from it), and %s may use it directly, without %s''s rules or the triggers that keep inheritance and the audit current: apply the policy again (it turns row-level security on for it), or ALTER TABLE %s ENABLE ROW LEVEL SECURITY', r.tbl, {lit(role)}, r.tbl, r.part);
      RETURN NEXT;
    END IF;
  END LOOP;
  -- partitions and tables that inherit, made since the last apply: Postgres runs a table's row triggers for its
  -- own rows and its partitions' only, and its statement triggers for statements on it only; applying gives
  -- them to each table under it (whatever the app role may do there: the owner's statements count too, and
  -- rows written through the table above need no privilege of their own)
  FOR r IN SELECT c.child, k.relispartition AS part, (SELECT i.inhparent::regclass FROM pg_inherits i WHERE i.inhrelid = c.child LIMIT 1) AS above,
                  string_agg(c.name::text, ', ' ORDER BY c.name) AS names
           FROM authz_int.child_triggers() c JOIN pg_class k ON k.oid = c.child GROUP BY c.child, k.relispartition LOOP
    severity := 'error'; object := r.child::text;
    IF r.part THEN
      problem := format('is a partition of %s, and was made since the policy was last applied: Postgres runs a table''s statement triggers for statements on it only, so a statement on this partition doesn''t keep inheritance, shares and the audit current (missing here: %s). Apply the policy again (it makes them)', r.above, r.names);
    ELSE
      problem := format('inherits from %s, and was made since the policy was last applied: Postgres runs a table''s row triggers for its own rows only, and its statement triggers for statements on it only, so a rule on a column is not checked on the rows stored here, their shares stay when their key changes, and a statement on this table doesn''t keep inheritance, shares and the audit current (missing here: %s). Apply the policy again (it makes them)', r.above, r.names);
    END IF;
    RETURN NEXT;
  END LOOP;
  -- unique constraints on governed tables tell people that rows they cannot see exist
  FOR r IN SELECT i.indexrelid::regclass AS idx, i.indrelid::regclass AS tbl
           FROM pg_index i WHERE i.indisunique AND NOT i.indisprimary
             AND i.indrelid = ANY (SELECT to_regclass(x) FROM unnest({arr([qt(t) for t in governed])}) x)
             AND has_table_privilege(v_role, i.indrelid, 'INSERT') LOOP
    severity := 'info'; object := r.idx::text;
    problem := format('a unique index on %s: inserting a duplicate fails even when the existing row is hidden, which tells the user it exists', r.tbl);
    RETURN NEXT;
  END LOOP;
  -- primary keys the app role may choose (a column it may insert or update, not GENERATED ALWAYS): the same
  FOR r IN SELECT i.indexrelid::regclass AS idx, i.indrelid::regclass AS tbl
           FROM pg_index i WHERE i.indisprimary
             AND i.indrelid = ANY (SELECT to_regclass(x) FROM unnest({arr([qt(t) for t in governed])}) x)
             AND EXISTS (SELECT 1 FROM pg_attribute a
                         WHERE a.attrelid = i.indrelid AND a.attnum = ANY (i.indkey) AND a.attidentity <> 'a'
                           AND (has_column_privilege(v_role, i.indrelid, a.attnum, 'INSERT')
                                OR has_column_privilege(v_role, i.indrelid, a.attnum, 'UPDATE'))) LOOP
    severity := 'info'; object := r.idx::text;
    problem := format('the primary key of %s, which %s may choose: an insert with the id of a hidden row fails, which tells the user it exists. Let the database make the ids (GENERATED ALWAYS AS IDENTITY, or random uuids), or revoke INSERT and UPDATE on the key', r.tbl, {lit(role)});
    RETURN NEXT;
  END LOOP;
  -- masked columns must only be readable through their view
  FOR r IN SELECT m.tbl, m.col, m.view FROM authz_int.masked_columns m
           WHERE CASE WHEN EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid = to_regclass(m.tbl) AND a.attname = m.col
                                   AND a.attnum > 0 AND NOT a.attisdropped)
                      THEN has_column_privilege(v_role, m.tbl, m.col, 'SELECT') ELSE false END LOOP
    severity := 'error'; object := to_regclass(r.tbl)::text || '.' || r.col;
    problem := format('the policy masks it, but %s may read it from the table (a GRANT to the role, a role it belongs to, or PUBLIC): read it through %s and revoke that', {lit(role)}, r.view);
    RETURN NEXT;
  END LOOP;
  -- tables holding relationships (memberships, links) the app role may change directly
  FOR r IN SELECT to_regclass(v.tbl) AS tbl, v.readers, v.typed
           FROM (VALUES {link_rows or "(NULL::text, NULL::text, NULL::boolean)"}) v(tbl, readers, typed) LOOP
    CONTINUE WHEN r.tbl IS NULL;
    IF has_table_privilege(v_role, r.tbl, 'TRUNCATE') THEN
      severity := 'error'; object := r.tbl::text;
      problem := format('%s may TRUNCATE it, which empties memberships without row-level security: REVOKE TRUNCATE ON %s FROM %s', {lit(role)}, r.tbl, {lit(role)});
      RETURN NEXT;
    END IF;
    IF (has_table_privilege(v_role, r.tbl, 'INSERT') OR has_table_privilege(v_role, r.tbl, 'UPDATE')
        OR has_table_privilege(v_role, r.tbl, 'DELETE'))
       AND NOT (SELECT relrowsecurity FROM pg_class WHERE oid = r.tbl) THEN
      severity := 'error'; object := r.tbl::text;
      problem := format('%s may change it, and it decides who is in what: anyone could add themselves. Revoke the write privileges, or give it rules', {lit(role)});
      RETURN NEXT;
    END IF;
    -- ... or read in full: who is linked to what (a type's table without rules is named above)
    IF NOT r.typed AND NOT (SELECT relrowsecurity FROM pg_class WHERE oid = r.tbl)
       AND has_any_column_privilege(v_role, r.tbl, 'SELECT') THEN
      severity := 'info'; object := r.tbl::text;
      problem := format('%s may read every row, and the policy reads it for %s: who is linked to what is readable. Fine where that is no secret, otherwise give it a type and rules', {lit(role)}, r.readers);
      RETURN NEXT;
    END IF;
  END LOOP;
  -- columns that grant a relation, changed by anyone who may update the row
  FOR r IN SELECT * FROM (VALUES {unguarded_rows or "(NULL::text, NULL::text, NULL::text, NULL::text, NULL::text)"}) v(tbl, col, what, loc, ask)
           WHERE tbl IS NOT NULL LOOP
    IF EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid = to_regclass(r.tbl) AND a.attname = r.col
               AND a.attnum > 0 AND NOT a.attisdropped)
       AND has_column_privilege(v_role, r.tbl, r.col, 'UPDATE') THEN
      severity := 'warning'; object := to_regclass(r.tbl)::text || '.' || r.col;
      problem := format('grants %s (%s), and anyone who may update the row may change it: add a rule such as "update %s : %s"', r.what, {self.line_sql(None, None, "r.loc")}, r.col, r.ask);
      RETURN NEXT;
    END IF;
  END LOOP;
  -- rules for a command the app role has no privilege for (one column's is enough for a read, an insert or
  -- an update: the app may write some columns only)
  FOR r IN SELECT to_regclass(v.tbl) AS tbl, v.cmd FROM (VALUES {rule_rows or "(NULL::text, NULL::text)"}) v(tbl, cmd)
           WHERE v.tbl IS NOT NULL LOOP
    CONTINUE WHEN r.tbl IS NULL;
    IF r.cmd = 'delete' THEN
      CONTINUE WHEN has_table_privilege(v_role, r.tbl, 'DELETE');
    ELSE
      CONTINUE WHEN has_any_column_privilege(v_role, r.tbl, r.cmd);
    END IF;
    severity := 'warning'; object := r.tbl::text;
    problem := format('the policy has a rule for %s, but %s has no %s privilege on the table: the rule never applies, and the statement fails with Postgres''s own "permission denied for table". GRANT %s ON %s TO %s, or make the rule "%s : nobody"', r.cmd, {lit(role)}, upper(r.cmd), upper(r.cmd), r.tbl, {lit(role)}, r.cmd);
    RETURN NEXT;
  END LOOP;
  -- relations named like a type that signs in
  FOR r IN SELECT * FROM (VALUES {shadow_rows or "(NULL::text, NULL::text, NULL::text)"}) v(type, rel, loc)
           WHERE type IS NOT NULL LOOP
    severity := 'info'; object := r.type || '.' || r.rel;
    problem := format('is named like the type %s (%s), which signs in: alone in a rule it reads like any %s, and it is this row''s. A name that says what the relation is (author, owner) reads better', r.rel, {self.line_sql(None, None, "r.loc")}, r.rel);
    RETURN NEXT;
  END LOOP;
{keyless}{heavy}  -- columns that move a row under another, with nothing checking where it moves to
  FOR r IN SELECT * FROM (VALUES {move_rows or "(NULL::text, NULL::text, NULL::text, NULL::text)"}) v(tbl, col, rel, loc)
           WHERE tbl IS NOT NULL LOOP
    -- (a composite key's columns are 'org_id, parent_id': any of them it may update)
    IF EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid = to_regclass(r.tbl) AND a.attnum > 0 AND NOT a.attisdropped
               AND a.attname::text = ANY (string_to_array(r.col, ', ')) AND has_column_privilege(v_role, r.tbl, a.attnum, 'UPDATE')) THEN
      severity := 'warning'; object := to_regclass(r.tbl)::text || '.' || r.col;
      problem := format('moves a row under another (%s, %s), and nothing checks where it moves to, so anyone who may update a row may put it inside something they may not change: add a rule such as "update %s after : %s.edit"', r.rel, {self.line_sql(None, None, "r.loc")}, r.col, r.rel);
      RETURN NEXT;
    END IF;
  END LOOP;
  -- views over governed tables that run with their owner's rights
  FOR r IN SELECT DISTINCT v.oid::regclass AS view, d.refobjid::regclass AS tbl
           FROM pg_depend d JOIN pg_rewrite w ON w.oid = d.objid JOIN pg_class v ON v.oid = w.ev_class
           LEFT JOIN pg_description ds ON ds.objoid = v.oid AND ds.classoid = 'pg_class'::regclass
           WHERE d.classid = 'pg_rewrite'::regclass AND d.refclassid = 'pg_class'::regclass
             AND d.refobjid = ANY (SELECT to_regclass(x) FROM unnest({arr([qt(t) for t in typed_tables + sorted(link_tables)])}) x)
             AND v.oid <> d.refobjid AND v.relkind IN ('v', 'm')
             AND v.relnamespace NOT IN (to_regnamespace('authz_gen'), to_regnamespace('authz_int'))
             AND coalesce(ds.description, '') NOT IN {VIEW_MARKS}
             AND NOT coalesce(v.reloptions @> ARRAY['security_invoker=true'], false)
             AND NOT coalesce(v.reloptions @> ARRAY['security_invoker=on'], false)
             AND has_table_privilege(v_role, v.oid, 'SELECT') LOOP
    severity := 'error'; object := r.view::text;
    problem := format('%s may read this view of %s, and views run with their owner''s rights, so row-level security does not apply: ALTER VIEW %s SET (security_invoker = on)', {lit(role)}, r.tbl, r.view);
    RETURN NEXT;
  END LOOP;
  -- functions that read governed tables as their owner
  FOR r IN SELECT p.oid::regprocedure AS fn FROM pg_proc p
           WHERE p.prosecdef AND p.pronamespace NOT IN (to_regnamespace('authz'), to_regnamespace('authz_int'),
                                                       to_regnamespace('authz_gen'), 'pg_catalog'::regnamespace)
             AND has_function_privilege(v_role, p.oid, 'EXECUTE')
             AND p.prokind IN ('f', 'p')
             AND EXISTS (SELECT 1 FROM unnest({arr(typed_tables + sorted(link_tables))}) x
                         WHERE lower(replace(pg_get_functiondef(p.oid), '"', '')) ~
                               ('(from|join|update|into|table|only)\\s+(' || lower(split_part(x, '.', 1)) || '\\.)?'
                                || lower(split_part(x, '.', 2)) || '([^a-z0-9_$]|$)')) LOOP
    severity := 'warning'; object := r.fn::text;
    problem := 'SECURITY DEFINER, callable by the app role, and seems to use a governed table: it reads rows without row-level security unless its owner is subject to it';
    RETURN NEXT;
  END LOOP;
  -- lookups the permission views make
  FOR r IN SELECT * FROM (VALUES {idx_rows or "(NULL::text, NULL::text, NULL::text, NULL::text)"}) v(tbl, col, why, alone) WHERE tbl IS NOT NULL LOOP
    CONTINUE WHEN to_regclass(r.tbl) IS NULL;
    -- a plain view can't have an index: the tables under it answer the lookups
    CONTINUE WHEN (SELECT c.relkind FROM pg_class c WHERE c.oid = to_regclass(r.tbl)) = 'v';
    -- an index whose first columns are these (one, or a composite key's, in any order), or what serves a (type, id)
    -- pair alone (its ids where they are two columns, its type where its id is one): a finished one, with no
    -- condition (the lookups are joins, which a partial index doesn't serve), as rowstile indexes counts them
    IF NOT EXISTS (SELECT 1 FROM pg_index i, unnest(ARRAY[r.col, r.alone]) w(cs)
                   WHERE w.cs IS NOT NULL AND i.indrelid = to_regclass(r.tbl) AND i.indisvalid AND i.indpred IS NULL
                     AND (SELECT array_agg(a.attname::text ORDER BY a.attname)
                          FROM unnest((i.indkey::int2[])[0:cardinality(string_to_array(w.cs, ', ')) - 1]) k
                          JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = k)
                         = (SELECT array_agg(c ORDER BY c) FROM unnest(string_to_array(w.cs, ', ')) c)) THEN
      severity := 'performance'; object := to_regclass(r.tbl)::text || '.' || r.col;
      problem := format('no index starts with %s (%s): CREATE INDEX ON %s (%s)',
                        CASE WHEN r.col LIKE '%, %' THEN 'these columns' ELSE 'this column' END, r.why, to_regclass(r.tbl),
                        (SELECT string_agg(quote_ident(c), ', ') FROM unnest(string_to_array(r.col, ', ')) c));
      RETURN NEXT;
    END IF;
  END LOOP;
END $f$;"""

    def connection_check_sql(self) -> str:
        """authz.connection_check(): what is wrong with the connection that calls it, for apps and SDKs to check
        when they start: a role row-level security doesn't apply to, or one the policy doesn't govern.
        Unlike authz.lint(), the app role may call it, and it looks only at the calling role."""
        role = self.role
        governed = "ARRAY[" + ", ".join(lit(qt(t)) for t in sorted({r.table for r in self.rules})) + "]::text[]"
        return f"""-- What is wrong with this connection, for the app to check when it starts: SELECT * FROM authz.connection_check()
-- 'error': the rules don't apply to the role this connection runs as. No rows: all is well.
CREATE FUNCTION authz.connection_check() RETURNS TABLE (severity text, problem text)
LANGUAGE plpgsql STABLE {DEF} AS $f$
DECLARE v_me oid := to_regrole(authz_int.caller_role()); v_app oid := to_regrole({lit(role)}); r record;
BEGIN
  IF (SELECT rolsuper FROM pg_roles WHERE oid = v_me) THEN
    severity := 'error'; problem := format('%s is a superuser: row-level security does not apply to it', v_me::regrole);
    RETURN NEXT; RETURN;
  END IF;
  IF (SELECT rolbypassrls FROM pg_roles WHERE oid = v_me) THEN
    severity := 'error'; problem := format('%s has BYPASSRLS: row-level security does not apply to it', v_me::regrole);
    RETURN NEXT;
  END IF;
  -- a table's owner (or a role with its rights) skips row-level security, unless the table forces it
  FOR r IN SELECT c.oid::regclass AS tbl FROM pg_class c
           WHERE c.oid = ANY (SELECT to_regclass(x) FROM unnest({governed}) x)
             AND NOT c.relforcerowsecurity AND pg_has_role(v_me, c.relowner, 'USAGE') LOOP
    severity := 'error';
    problem := format('%s owns %s (or has its owner''s rights): owners skip row-level security', v_me::regrole, r.tbl);
    RETURN NEXT;
  END LOOP;
  -- a table with rules whose row-level security is off: the rules don't apply
  FOR r IN SELECT c.oid::regclass AS tbl FROM pg_class c
           WHERE c.oid = ANY (SELECT to_regclass(x) FROM unnest({governed}) x) AND NOT c.relrowsecurity LOOP
    severity := 'error';
    problem := format('row-level security is off on %s: the policy''s rules don''t apply to it', r.tbl);
    RETURN NEXT;
  END LOOP;
  -- a login that switched to the app role (SET ROLE) but is an administrator: RESET ROLE leaves row-level
  -- security, and its sessions are believed without a signature
  FOR r IN SELECT l.oid::regrole AS login FROM pg_roles l, pg_namespace n
           WHERE l.rolname = session_user AND n.nspname = 'authz_int' AND l.oid <> v_me
             AND (l.rolsuper OR l.rolbypassrls OR pg_has_role(l.oid, n.nspowner, 'MEMBER')) LOOP
    severity := 'error';
    problem := format('this connection logs in as %s, a superuser, BYPASSRLS or the policy''s owner, and switched to %s: RESET ROLE leaves row-level security, and who is signed in is believed without a signature. Log in as the app role', r.login, v_me::regrole);
    RETURN NEXT;
  END LOOP;
  IF v_app IS NULL OR NOT pg_has_role(v_me, v_app, 'USAGE') THEN
    severity := 'error';
    problem := format('%s is not the policy''s app role %s, nor a member of it: the rules apply to %s only',
                      v_me::regrole, {lit(role)}, {lit(role)});
    RETURN NEXT;
  END IF;
END $f$;"""

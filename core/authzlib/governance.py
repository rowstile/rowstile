"""Governance: the audit trail, the change feed, access requests and emergency
access, access reviews, invariants, and previewing a policy change."""

from __future__ import annotations

from .compiler import Core
from .parse import Relation, Source, Type
from .parse import cols as columns_of
from .sqlutil import IF_PARTITIONED, lit, on_row, q, qt
from .statements import made

DEF = "SECURITY DEFINER SET search_path = pg_catalog, pg_temp"
# triggers that evaluate the policy's own SQL (link-table where {...}) resolve names as the policy does
DEF_CURRENT = "SECURITY DEFINER SET search_path FROM CURRENT"


def trigger_if_table(table: str, trigger_sql: str, what: str) -> str:
    """Create a trigger only when the relation is a table (a view cannot have these triggers). The comment
    names the trigger for the migrations (statements.made)."""
    body = trigger_sql.replace("'", "''")
    m = made(trigger_sql)
    assert m is not None, "a CREATE TRIGGER makes a trigger"
    kind, key = m
    return (
        f"-- @object {kind} {key}\n"
        f"DO $tr$ BEGIN\n"
        f"  IF (SELECT relkind FROM pg_class WHERE oid = {lit(qt(table))}::regclass) IN ('r', 'p') THEN\n"
        f"    EXECUTE '{body}';\n"
        f"  ELSE\n"
        f"    RAISE NOTICE '{qt(table).replace(chr(39), chr(39) * 2)} is not a table: changes to it are not audited or fed ({what})';\n"
        f"  END IF;\nEND $tr$;"
    )


def trigger_if_partitioned(table: str, trigger_sql: str) -> str:
    """Create a trigger only where the table is partitioned (what it is for only happens there). The comments name
    the trigger for the migrations (statements.made) and say where it is (database.unchanged)."""
    m = made(trigger_sql)
    assert m is not None, "a CREATE TRIGGER makes a trigger"
    kind, key = m
    body = trigger_sql.replace("'", "''")
    return (
        f"-- @object {kind} {key}\n"
        f"-- {IF_PARTITIONED}\n"
        f"DO $tr$ BEGIN\n"
        f"  IF (SELECT relkind FROM pg_catalog.pg_class WHERE oid = {lit(qt(table))}::regclass) = 'p' THEN\n"
        f"    EXECUTE '{body}';\n"
        f"  END IF;\nEND $tr$;"
    )


class GovernanceMixin(Core):
    # ------------------------------------------------------------------
    # audit trail and change feed
    # ------------------------------------------------------------------
    def feed_sql(self) -> str:
        return f"""-- The change feed: objects whose access may have changed. Consumers poll authz.changes_since(pos).
-- NOTIFY on channel authz_changes only with INSERT INTO authz.settings VALUES ('notify_changes', 'on'):
-- Postgres commits notifying transactions one at a time, so it would queue every write.
CREATE FUNCTION authz_int.changed(p_type text, p_ids text[], p_cause text) RETURNS void
LANGUAGE plpgsql {DEF} AS $f$
DECLARE v_pos bigint;
BEGIN
  IF coalesce(cardinality(p_ids), 0) = 0 THEN RETURN; END IF;
  INSERT INTO authz.changes (object_type, object_ids, cause) VALUES (p_type, p_ids, p_cause) RETURNING pos INTO v_pos;
  IF (SELECT s.value FROM authz.settings s WHERE s.key = 'notify_changes') = 'on' THEN
    PERFORM pg_notify('authz_changes', v_pos::text);
  END IF;
END $f$;
-- Read the feed from a position: SELECT * FROM authz.changes_since(0)  (administrators, sync jobs).
-- A reader behind what authz.trim_changes() removed gets an error: it must read everything again.
CREATE FUNCTION authz.changes_since(p_pos bigint, p_limit int DEFAULT 1000) RETURNS SETOF authz.changes
LANGUAGE plpgsql STABLE {DEF} AS $f$
DECLARE v_to bigint := (SELECT s.value::bigint FROM authz.settings s WHERE s.key = 'changes_trimmed_to');
BEGIN
  IF p_pos < v_to THEN
    RAISE EXCEPTION 'the change feed up to position % was trimmed: read everything again, then follow from there', v_to
      USING ERRCODE = 'object_not_in_prerequisite_state', HINT = 'rowstile help AZ712';
  END IF;
  RETURN QUERY SELECT * FROM authz.changes WHERE pos > p_pos ORDER BY pos LIMIT p_limit;
END $f$;

-- Retention (both grow forever otherwise); schedule these, with pg_cron or the app's jobs.
-- The feed: entries older than p_keep, by default the setting changes_keep, else 7 days.
CREATE FUNCTION authz.trim_changes(p_keep interval DEFAULT NULL) RETURNS bigint
LANGUAGE plpgsql {DEF} AS $f$
DECLARE
  v_keep interval := coalesce(p_keep, (SELECT s.value::interval FROM authz.settings s WHERE s.key = 'changes_keep'),
                              interval '7 days');
  v_to bigint; n bigint;
BEGIN
  SELECT max(c.pos) INTO v_to FROM authz.changes c WHERE c.at < now() - v_keep;
  IF v_to IS NULL THEN RETURN 0; END IF;
  DELETE FROM authz.changes c WHERE c.pos <= v_to;
  GET DIAGNOSTICS n = ROW_COUNT;
  INSERT INTO authz.settings VALUES ('changes_trimmed_to', v_to::text)
    ON CONFLICT (key) DO UPDATE SET value = greatest(authz.settings.value::bigint, v_to)::text;
  RETURN n;
END $f$;
-- The audit trail: entries older than p_keep (no default: how long to keep it is a compliance
-- decision). The trim itself is recorded in the audit trail.
CREATE FUNCTION authz.trim_audit(p_keep interval) RETURNS bigint
LANGUAGE plpgsql {DEF} AS $f$
DECLARE v_before timestamptz; n bigint;
BEGIN
  IF p_keep IS NULL OR p_keep < interval '0' THEN
    RAISE EXCEPTION 'say how long to keep the audit trail, e.g. authz.trim_audit(interval ''2 years'')' USING ERRCODE = 'invalid_parameter_value', HINT = 'rowstile help AZ710';
  END IF;
  v_before := now() - p_keep;
  -- the one way past the trigger is DDL, as the owner, here: nothing a session can set lets a DELETE through
  -- (ALTER TABLE takes an exclusive lock on the trail until the transaction ends); it is on again as it was, in
  -- every replication role
  ALTER TABLE authz.audit DISABLE TRIGGER authz_audit_append_only;
  DELETE FROM authz.audit a WHERE a.at < v_before;
  GET DIAGNOSTICS n = ROW_COUNT;
  ALTER TABLE authz.audit ENABLE ALWAYS TRIGGER authz_audit_append_only;
  INSERT INTO authz.audit (db_role, user_id, action, detail)
  VALUES (authz_int.caller_role(), authz_int.actor(), 'trim_audit',
          jsonb_build_object('before', v_before, 'rows', n));
  RETURN n;
END $f$;

-- The audit trail only grows, except through authz.trim_audit(). Its triggers fire in every replication role
-- (ENABLE ALWAYS): session_replication_role = replica, which turns ordinary triggers off, leaves them on. A
-- subscription's worker applies its publisher's rows in that role, and the trims made there with them: a process
-- Postgres lists as one (pg_stat_subscription), which no session can make itself
CREATE FUNCTION authz_int.audit_is_append_only() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $f$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_stat_subscription s WHERE s.pid = pg_catalog.pg_backend_pid()) THEN
    IF TG_OP = 'UPDATE' THEN
      RETURN NEW;
    END IF;
    RETURN OLD;
  END IF;
  RAISE EXCEPTION 'the audit trail cannot be changed' USING ERRCODE = 'insufficient_privilege', HINT = 'rowstile help AZ711';
END $f$;
CREATE TRIGGER authz_audit_append_only BEFORE UPDATE OR DELETE ON authz.audit
  FOR EACH ROW EXECUTE FUNCTION authz_int.audit_is_append_only();
ALTER TABLE authz.audit ENABLE ALWAYS TRIGGER authz_audit_append_only;
CREATE TRIGGER authz_audit_no_truncate BEFORE TRUNCATE ON authz.audit
  FOR EACH STATEMENT EXECUTE FUNCTION authz_int.audit_is_append_only();
ALTER TABLE authz.audit ENABLE ALWAYS TRIGGER authz_audit_no_truncate;

-- shares and role assignments
CREATE FUNCTION authz_int.on_grant() RETURNS trigger
LANGUAGE plpgsql {DEF} AS $f$
DECLARE r authz.shares;
BEGIN
  r := CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
  PERFORM authz_int.audit(CASE TG_OP WHEN 'INSERT' THEN 'share' WHEN 'DELETE' THEN 'unshare' ELSE 'share_changed' END,
    r.object_type, r.object_id, r.relation, r.subject_type,
    CASE WHEN r.subject_type = 'link' THEN '(link)' ELSE r.subject_id END, r.subject_relation,
    jsonb_strip_nulls(jsonb_build_object('expires_at', r.expires_at, 'starts_at', r.starts_at, 'caveat', r.caveat,
                                         'created_by', r.created_by)));
  PERFORM authz_int.changed(r.object_type, ARRAY[r.object_id], 'share');
  IF TG_OP = 'UPDATE' AND OLD.object_id <> NEW.object_id THEN
    PERFORM authz_int.changed(OLD.object_type, ARRAY[OLD.object_id], 'share');
  END IF;
  RETURN NULL;
END $f$;
CREATE TRIGGER authz_grant_audit AFTER INSERT OR UPDATE OR DELETE ON authz.shares
  FOR EACH ROW EXECUTE FUNCTION authz_int.on_grant();
CREATE FUNCTION authz_int.on_role() RETURNS trigger
LANGUAGE plpgsql {DEF} AS $f$
BEGIN
  IF TG_TABLE_NAME = 'roles' THEN
    PERFORM authz_int.audit(lower(TG_OP) || '_role', CASE WHEN TG_OP = 'DELETE' THEN OLD.owner_type ELSE NEW.owner_type END,
      CASE WHEN TG_OP = 'DELETE' THEN OLD.owner_id ELSE NEW.owner_id END, NULL, NULL, NULL, NULL,
      to_jsonb(CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END));
  ELSE
    PERFORM authz_int.audit(CASE TG_OP WHEN 'DELETE' THEN 'role_permission_removed' ELSE 'role_permission_added' END,
      NULL, NULL, 'role:' || CASE WHEN TG_OP = 'DELETE' THEN OLD.role_id ELSE NEW.role_id END, NULL, NULL, NULL,
      jsonb_build_object('permission', CASE WHEN TG_OP = 'DELETE' THEN OLD.permission ELSE NEW.permission END));
  END IF;
  RETURN NULL;
END $f$;
CREATE TRIGGER authz_role_audit AFTER INSERT OR UPDATE OR DELETE ON authz.roles
  FOR EACH ROW EXECUTE FUNCTION authz_int.on_role();
CREATE TRIGGER authz_role_perm_audit AFTER INSERT OR DELETE ON authz.role_permissions
  FOR EACH ROW EXECUTE FUNCTION authz_int.on_role();"""

    def subject_text(self, src: Source, a: str) -> str:
        """A column/table source's subject id as text (for any of its subject types), as the audit names it."""
        col = self.source_columns(src)
        if not src.type_col:
            st = self.types.get(src.subjects[0][0])
            return self.ref_text(st, a, col) if st else f"{a}.{q(columns_of(col)[0])}::text"
        if not any(self.T(st).composite for st, _ in src.subjects if st in self.types):
            return f"{a}.{q(columns_of(col)[0])}::text"
        whens = " ".join(
            f"WHEN {lit(st)} THEN {self.ref_text(self.T(st), a, col)}" for st, _ in src.subjects if st in self.types
        )
        return f"(CASE {a}.{q(src.type_col)} {whens} END)"

    def relationship_audit_sql(self) -> list[str]:
        """Audit and feed rows for relationships kept in your own tables."""
        out: list[str] = []
        tables: dict[str, list[tuple[Type, Relation, Source]]] = {}  # link table -> [(type, relation, source)]
        cols: dict[str, list[tuple[Relation, Source]]] = {}  # object type -> [(relation, source)]
        for t in self.types.values():
            for r in t.relations.values():
                for src in r.sources:
                    if src.kind == "table":
                        tables.setdefault(self.source_table(src), []).append((t, r, src))
                    elif src.kind == "column":
                        cols.setdefault(t.name, []).append((r, src))
        for i, (table, uses) in enumerate(sorted(tables.items(), key=lambda x: x[0])):
            rows = []
            for t, r, src in uses:
                st = src.subjects[0][0] if not src.type_col else None
                styp = f"x.{q(src.type_col)}::text" if src.type_col else lit(st)
                srel = lit(src.subjects[0][1] or "") if not src.type_col else "''"
                where = f" AND coalesce(({on_row(src.where, 'x')}), false)" if src.where else ""
                for which, action in (("new_rows", "relate"), ("old_rows", "unrelate")):
                    rows.append(
                        (
                            which,
                            f"SELECT {lit(action)} AS action, {lit(t.name)} AS ot, "
                            f"{self.ref_text(t, 'x', self.source_obj_columns(src))} AS oid, "
                            f"{lit(r.name)} AS rel, {styp} AS st, {self.subject_text(src, 'x')} AS sid, {srel} AS sr "
                            f"FROM {which} x WHERE true{where}",
                        )
                    )
            new_q = " UNION ALL ".join(sql for w, sql in rows if w == "new_rows")
            old_q = " UNION ALL ".join(sql for w, sql in rows if w == "old_rows")
            ins = lambda src, other: (
                f"""    INSERT INTO authz.audit (db_role, user_id, acting_user, action, object_type, object_id, relation, subject_type,
                             subject_id, subject_relation, reason)
    SELECT authz_int.caller_role(), authz_int.actor(),
           nullif(current_setting('authz.acting_user', true), ''), c.action, c.ot, c.oid, c.rel, c.st, c.sid, c.sr,
           nullif(current_setting('authz_ctx.reason', true), '')
    FROM ({src}) c"""
                + (
                    f"""
    WHERE NOT EXISTS (SELECT 1 FROM ({other}) o WHERE (o.ot, o.oid, o.rel, o.st, o.sid) = (c.ot, c.oid, c.rel, c.st, c.sid))"""
                    if other
                    else ""
                )
                + f""";
    PERFORM authz_int.changed(c.ot, array_agg(DISTINCT c.oid), 'relationship') FROM ({src}) c GROUP BY c.ot;"""
            )
            bodies = {
                "ins": ins(new_q, None),
                "del": ins(old_q, None),
                "upd": ins(new_q, old_q) + "\n" + ins(old_q, new_q),
            }
            object_types = sorted({t.name for t, r, src in uses})
            bodies["trunc"] = "\n".join(
                f"    PERFORM authz_int.audit('truncate', {lit(ot)}, NULL, NULL, NULL, NULL, NULL, "
                f"jsonb_build_object('table', {lit(table)}));\n"
                f"    PERFORM authz_int.changed({lit(ot)}, ARRAY['*'], 'relationship');"
                for ot in object_types
            )
            head = f"-- relationships kept in {table}"
            parts = [head]
            for op, event, ref in (
                ("ins", "INSERT", "REFERENCING NEW TABLE AS new_rows "),
                ("upd", "UPDATE", "REFERENCING OLD TABLE AS old_rows NEW TABLE AS new_rows "),
                ("del", "DELETE", "REFERENCING OLD TABLE AS old_rows "),
                ("trunc", "TRUNCATE", ""),
            ):
                fn = f"authz_int.{q('rel_audit_' + str(i + 1) + '_' + op)}"
                parts.append(f"""CREATE FUNCTION {fn}() RETURNS trigger
LANGUAGE plpgsql {DEF_CURRENT} AS $f$
BEGIN
{bodies[op]}
  RETURN NULL;
END $f$;""")
                parts.append(
                    trigger_if_table(
                        table,
                        f"CREATE TRIGGER {q('authz_rel_audit_' + str(i + 1) + '_' + op)} AFTER {event} ON {qt(table)} "
                        f"{ref}FOR EACH STATEMENT EXECUTE FUNCTION {fn}()",
                        "audit",
                    )
                )
            out.append("\n".join(parts))
        for tname, uses in cols.items():
            t = self.T(tname)
            kt = lambda a, t=t: self.key_text(t, a)
            changes = []
            for r, src in uses:
                for c in columns_of(self.source_columns(src)) + ((src.type_col,) if src.type_col else ()):
                    changes.append((r.name, c))
            pairs = list(dict.fromkeys(changes))
            audits = "\n".join(
                f"  IF NEW.{q(col)} IS DISTINCT FROM OLD.{q(col)} THEN\n"
                f"    INSERT INTO authz.audit (db_role, user_id, acting_user, action, object_type, object_id, relation, "
                f"subject_id, detail, reason)\n"
                f"    VALUES (authz_int.caller_role(), authz_int.actor(), "
                f"nullif(current_setting('authz.acting_user', true), ''), 'relate', {lit(tname)}, {kt('NEW')}, {lit(rel)}, "
                f"NEW.{q(col)}::text, jsonb_build_object('column', {lit(col)}, 'was', OLD.{q(col)}), "
                f"nullif(current_setting('authz_ctx.reason', true), ''));\n"
                f"  END IF;"
                for rel, col in pairs
            )
            watched = list(dict.fromkeys(col for _, col in pairs))
            # On a partitioned table Postgres runs no AFTER UPDATE row trigger for a row an update puts in another
            # partition (a delete there, an insert here). Those rows are audited by the statement's trigger, by
            # their key: each change the row trigger hasn't written in this transaction. (A row whose key
            # changed in the same update is not found.)
            moved = "\n".join(
                f"      INSERT INTO authz.audit (db_role, user_id, acting_user, action, object_type, object_id, "
                f"relation, subject_id, detail, reason)\n"
                f"      SELECT authz_int.caller_role(), authz_int.actor(), "
                f"nullif(current_setting('authz.acting_user', true), ''), 'relate', {lit(tname)}, {kt('n')}, {lit(rel)}, "
                f"n.{q(col)}::text, jsonb_build_object('column', {lit(col)}, 'was', o.{q(col)}), "
                f"nullif(current_setting('authz_ctx.reason', true), '')\n"
                f"      FROM old_rows o JOIN new_rows n ON {kt('n')} = {kt('o')}\n"
                f"      WHERE n.{q(col)} IS DISTINCT FROM o.{q(col)} AND NOT EXISTS (\n"
                f"        SELECT 1 FROM authz.audit a WHERE a.txid = txid_current() AND a.action = 'relate' "
                f"AND a.object_type = {lit(tname)}\n"
                f"          AND a.object_id = {kt('n')} AND a.relation = {lit(rel)} AND a.detail->>'column' = {lit(col)}\n"
                f"          AND a.subject_id IS NOT DISTINCT FROM n.{q(col)}::text "
                f"AND a.detail->'was' IS NOT DISTINCT FROM to_jsonb(o.{q(col)}));"
                for rel, col in pairs
            )
            bodies = {
                "ins": f"    PERFORM authz_int.changed({lit(tname)}, ARRAY(SELECT {kt('n')} FROM new_rows n), 'insert');",
                "upd": f"    PERFORM authz_int.changed({lit(tname)}, ARRAY(SELECT {kt('n')} FROM new_rows n "
                f"UNION SELECT {kt('o')} FROM old_rows o), 'update');\n"
                f"    -- a partitioned table: the rows this update put in another partition, which the row trigger never sees\n"
                f"    IF (SELECT relkind FROM pg_class WHERE oid = TG_RELID) = 'p' THEN\n{moved}\n    END IF;",
                "del": f"    PERFORM authz_int.changed({lit(tname)}, ARRAY(SELECT {kt('o')} FROM old_rows o), 'delete');",
                "trunc": f"    PERFORM authz_int.audit('truncate', {lit(tname)}, NULL, NULL, NULL, NULL, NULL, "
                f"jsonb_build_object('table', {lit(t.table)}));\n"
                f"    PERFORM authz_int.changed({lit(tname)}, ARRAY['*'], 'truncate');",
            }
            parts = [
                f"-- relationships kept in columns of {t.table}: audited when they change; the feed hears of every row"
            ]
            for op, event, ref in (
                ("ins", "INSERT", "REFERENCING NEW TABLE AS new_rows "),
                ("upd", "UPDATE", "REFERENCING OLD TABLE AS old_rows NEW TABLE AS new_rows "),
                ("del", "DELETE", "REFERENCING OLD TABLE AS old_rows "),
                ("trunc", "TRUNCATE", ""),
            ):
                fn = f"authz_int.{q(tname + '__col_audit_' + op)}"
                parts.append(f"""CREATE FUNCTION {fn}() RETURNS trigger
LANGUAGE plpgsql {DEF} AS $f$
BEGIN
{bodies[op]}
  RETURN NULL;
END $f$;""")
                parts.append(
                    trigger_if_table(
                        t.table,
                        f"CREATE TRIGGER {q('authz_' + tname + '_col_audit_' + op)} AFTER {event} ON {qt(t.table)} "
                        f"{ref}FOR EACH STATEMENT EXECUTE FUNCTION {fn}()",
                        "audit",
                    )
                )
            fn = f"authz_int.{q(tname + '__col_audit_row')}"
            parts.append(f"""-- one audit row per changed relationship column (a row trigger, so it also works when the key changes)
CREATE FUNCTION {fn}() RETURNS trigger
LANGUAGE plpgsql {DEF} AS $f$
BEGIN
{audits}
  RETURN NULL;
END $f$;""")
            parts.append(
                trigger_if_table(
                    t.table,
                    f"CREATE TRIGGER {q('authz_' + tname + '_col_audit_row')} AFTER UPDATE "
                    f"ON {qt(t.table)} FOR EACH ROW WHEN ("
                    + " OR ".join(f"OLD.{q(c)} IS DISTINCT FROM NEW.{q(c)}" for c in watched)
                    + f") EXECUTE FUNCTION {fn}()",
                    "audit",
                )
            )
            out.append("\n".join(parts))
        return out

    # ------------------------------------------------------------------
    # requests, approvals, emergency access, reviews
    # ------------------------------------------------------------------
    def workflow_sql(self) -> str:
        return f"""-- Who may manage a relation on an object: the permission that shares it (with users, when asked)
CREATE FUNCTION authz_int.manage_perm(p_type text, p_relation text, p_subject text DEFAULT NULL) RETURNS text
LANGUAGE sql STABLE {DEF} AS $f$
  SELECT CASE
    WHEN p_relation LIKE 'role:%' THEN
      CASE WHEN EXISTS (SELECT 1 FROM authz.roles r WHERE 'role:' || r.id = p_relation AND r.object_type = p_type)
                AND EXISTS (SELECT 1 FROM authz_int.perms WHERE type = p_type AND perm = 'share') THEN 'share' END
    ELSE (SELECT min(s.shared_by) FROM authz_int.shared_relations s JOIN authz_int.perms pm
            ON pm.type = s.object_type AND pm.perm = s.shared_by
          WHERE s.object_type = p_type AND s.relation = p_relation AND (p_subject IS NULL OR s.subject = p_subject))
  END $f$;
CREATE FUNCTION authz_int.may_manage(p_type text, p_id text, p_relation text, p_subject text DEFAULT NULL)
RETURNS boolean LANGUAGE plpgsql STABLE {DEF} AS $f$
DECLARE v_perm text := authz_int.manage_perm(p_type, p_relation, p_subject);
BEGIN
  IF authz_int.caller_is_admin() THEN RETURN true; END IF;
  RETURN v_perm IS NOT NULL AND EXISTS (SELECT 1 FROM authz.principal()) AND coalesce(authz.can(p_type, p_id, v_perm), false);
END $f$;
-- The subject key of a share (as the policy writes it: user, team#member, user:*, anyone, link)
CREATE FUNCTION authz_int.subject_key(p_type text, p_id text, p_relation text) RETURNS text
LANGUAGE sql IMMUTABLE AS $f$
  SELECT CASE WHEN p_type IN ('anyone', 'link') THEN p_type
              WHEN p_id = '*' AND p_relation = '' THEN p_type || ':*'
              WHEN p_relation <> '' THEN p_type || '#' || p_relation
              ELSE p_type END $f$;

-- Ask for access: SELECT authz.request_access('folder', '3', 'viewer', 'for the audit', '7 days')
CREATE FUNCTION authz.request_access(p_type text, p_id text, p_relation text, p_reason text,
  p_duration interval DEFAULT NULL) RETURNS bigint
LANGUAGE plpgsql {DEF} AS $f$
DECLARE v_id bigint; v_tbl text;
BEGIN
  p_id := authz_int.canon(p_type, p_id);
  PERFORM authz_int.check_writable();
  IF authz.uid() IS NULL THEN RAISE EXCEPTION 'sign in first' USING ERRCODE = 'insufficient_privilege', HINT = 'rowstile help AZ714'; END IF;
  IF coalesce(btrim(p_reason), '') = '' THEN RAISE EXCEPTION 'say why you need it' USING ERRCODE = 'invalid_parameter_value', HINT = 'rowstile help AZ710'; END IF;
  IF p_duration IS NOT NULL AND p_duration <= interval '0' THEN RAISE EXCEPTION 'the duration must be positive' USING ERRCODE = 'invalid_parameter_value', HINT = 'rowstile help AZ710'; END IF;
  SELECT tbl INTO v_tbl FROM authz_int.types WHERE name = p_type;
  IF v_tbl IS NULL THEN RAISE EXCEPTION 'no type % in the policy', p_type USING HINT = 'rowstile help AZ707'; END IF;
  IF authz_int.manage_perm(p_type, p_relation, CASE WHEN p_relation LIKE 'role:%' THEN NULL ELSE 'user' END) IS NULL
     OR (p_relation LIKE 'role:%' AND NOT EXISTS (SELECT 1 FROM authz_int.role_subjects
                                                  WHERE object_type = p_type AND subject = 'user')) THEN
    RAISE EXCEPTION 'the policy does not allow sharing %.% with a user', p_type, p_relation USING HINT = 'rowstile help AZ706';
  END IF;
  -- no check that the object exists: that would tell people which hidden objects do. A request
  -- for a missing object simply never reaches anyone who could approve it.
  INSERT INTO authz.requests (object_type, object_id, relation, requester, reason, duration)
  VALUES (p_type, p_id, p_relation, authz.uid()::text, p_reason, p_duration) RETURNING id INTO v_id;
  PERFORM authz_int.audit('request_access', p_type, p_id, p_relation, 'user', authz.uid()::text, '',
                          jsonb_build_object('request', v_id, 'duration', p_duration));
  PERFORM pg_notify('authz_requests', v_id::text);
  RETURN v_id;
END $f$;
CREATE FUNCTION authz.request_access(p_type text, p_id bigint, p_relation text, p_reason text,
  p_duration interval DEFAULT NULL) RETURNS bigint LANGUAGE sql AS
  $$ SELECT authz.request_access(p_type, p_id::text, p_relation, p_reason, p_duration) $$;

-- Requests the current user may decide (they may share that relation on the object), and their own
CREATE FUNCTION authz.pending_requests()
RETURNS TABLE (id bigint, object_type text, object_id text, relation text, requester text, reason text,
               duration interval, created_at timestamptz, mine boolean)
LANGUAGE sql STABLE {DEF} AS $f$
  SELECT r.id, r.object_type, r.object_id, r.relation, r.requester, r.reason, r.duration, r.created_at,
         r.requester = authz.uid()::text
  FROM authz.requests r
  WHERE r.status = 'pending' AND authz.uid() IS NOT NULL
    AND (r.requester = authz.uid()::text
         OR (r.requester IS DISTINCT FROM authz.uid()::text
             AND authz_int.may_manage(r.object_type, r.object_id, r.relation,
                                      CASE WHEN r.relation LIKE 'role:%' THEN NULL ELSE 'user' END)))
  ORDER BY r.id $f$;

-- Approve (it becomes a share, made by you, that ends after the requested time) or deny
CREATE FUNCTION authz.decide_request(p_id bigint, p_approve boolean, p_note text DEFAULT NULL) RETURNS void
LANGUAGE plpgsql {DEF} AS $f$
DECLARE r authz.requests;
BEGIN
  PERFORM authz_int.check_writable();
  IF p_approve IS NULL THEN RAISE EXCEPTION 'approve (true) or deny (false)' USING ERRCODE = 'invalid_parameter_value', HINT = 'rowstile help AZ710'; END IF;
  SELECT * INTO r FROM authz.requests WHERE id = p_id AND status = 'pending' FOR UPDATE;
  IF r.id IS NULL THEN RAISE EXCEPTION 'no pending request %', p_id USING HINT = 'rowstile help AZ708'; END IF;
  IF authz.uid() IS NULL OR r.requester = authz.uid()::text THEN
    RAISE EXCEPTION 'you cannot decide your own request' USING ERRCODE = 'insufficient_privilege', HINT = 'rowstile help AZ705';
  END IF;
  IF NOT authz_int.may_manage(r.object_type, r.object_id, r.relation,
                              CASE WHEN r.relation LIKE 'role:%' THEN NULL ELSE 'user' END) THEN
    RAISE EXCEPTION 'you cannot decide request %', p_id USING ERRCODE = 'insufficient_privilege', HINT = 'rowstile help AZ705';
  END IF;
  IF p_approve THEN
    -- authz.share checks again that you may share it, and that you hold what it grants
    PERFORM authz.share(r.object_type, r.object_id, r.relation, 'user', r.requester, '',
                        CASE WHEN r.duration IS NULL THEN NULL ELSE now() + r.duration END);
  END IF;
  UPDATE authz.requests SET status = CASE WHEN p_approve THEN 'approved' ELSE 'denied' END,
    decided_by = authz.uid()::text, decided_at = now(), note = p_note WHERE id = p_id;
  PERFORM authz_int.audit(CASE WHEN p_approve THEN 'approve_request' ELSE 'deny_request' END, r.object_type,
    r.object_id, r.relation, 'user', r.requester, '', jsonb_build_object('request', p_id, 'note', p_note));
END $f$;
CREATE FUNCTION authz.cancel_request(p_id bigint) RETURNS void
LANGUAGE plpgsql {DEF} AS $f$
BEGIN
  PERFORM authz_int.check_writable();
  UPDATE authz.requests SET status = 'cancelled', decided_at = now()
  WHERE id = p_id AND status = 'pending' AND requester = authz.uid()::text;
  IF NOT FOUND THEN RAISE EXCEPTION 'no pending request % of yours', p_id USING HINT = 'rowstile help AZ708'; END IF;
END $f$;

-- Emergency access: people who hold 'break_glass' on an object give themselves a relation on it
-- for a short time (one day at most); it is audited and announced on channel authz_alerts
-- (the notification carries the audit row's id; the details stay in authz.audit)
CREATE FUNCTION authz.break_glass(p_type text, p_id text, p_relation text, p_reason text,
  p_duration interval DEFAULT interval '1 hour') RETURNS void
LANGUAGE plpgsql {DEF} AS $f$
DECLARE g authz.shares; v_until timestamptz; v_audit bigint; v_held boolean;
BEGIN
  p_id := authz_int.canon(p_type, p_id);
  PERFORM authz_int.check_writable();
  IF coalesce(btrim(p_reason), '') = '' THEN RAISE EXCEPTION 'say why (it is kept in the audit trail)' USING ERRCODE = 'invalid_parameter_value', HINT = 'rowstile help AZ710'; END IF;
  IF p_duration IS NULL OR p_duration <= interval '0' OR p_duration > interval '1 day' THEN
    RAISE EXCEPTION 'emergency access lasts more than nothing and one day at most' USING ERRCODE = 'invalid_parameter_value', HINT = 'rowstile help AZ710';
  END IF;
  -- the object and the user are locked (FOR KEY SHARE), as authz.share locks them: a delete waits for this, or this
  -- for it and then finds nothing to break into
  v_held := authz.uid() IS NOT NULL;
  IF v_held THEN v_held := authz_int.hold(p_type, p_id); END IF;
  IF v_held THEN v_held := authz_int.hold('user', authz.uid()::text); END IF;
  IF NOT v_held
     OR NOT EXISTS (SELECT 1 FROM authz_int.perms WHERE type = p_type AND perm = 'break_glass')
     OR NOT authz.can(p_type, p_id, 'break_glass') THEN
    RAISE EXCEPTION 'you cannot break the glass on % %', p_type, p_id USING ERRCODE = 'insufficient_privilege', HINT = 'rowstile help AZ705';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM authz_int.shared_relations WHERE object_type = p_type AND relation = p_relation
                 AND subject = 'user') THEN
    RAISE EXCEPTION 'the policy does not allow sharing %.% with a user', p_type, p_relation USING HINT = 'rowstile help AZ706';
  END IF;
  v_until := now() + p_duration;
  PERFORM set_config('authz_ctx.reason', p_reason, true);
  PERFORM authz_int.mark_shared(p_type, p_id);
  PERFORM authz_int.mark_shared('user', authz.uid()::text);
  SELECT * INTO g FROM authz.shares WHERE object_type = p_type AND object_id = p_id AND relation = p_relation
    AND subject_type = 'user' AND subject_id = authz.uid()::text AND subject_relation = '' FOR UPDATE;
  IF g.object_id IS NULL THEN
    INSERT INTO authz.shares (object_type, object_id, relation, subject_type, subject_id, subject_relation,
                              expires_at, created_by)
    VALUES (p_type, p_id, p_relation, 'user', authz.uid()::text, '', v_until, authz.uid()::text);
  ELSIF g.caveat IS NOT NULL OR (g.starts_at IS NOT NULL AND g.starts_at > now())
        OR (g.expires_at IS NOT NULL AND g.expires_at < v_until) THEN
    -- a share that would not let them in now becomes an unconditional one until then (the old one is in the audit)
    UPDATE authz.shares SET expires_at = CASE WHEN g.expires_at IS NULL THEN v_until ELSE greatest(g.expires_at, v_until) END,
      starts_at = NULL, caveat = NULL, caveat_args = NULL
    WHERE object_type = p_type AND object_id = p_id AND relation = p_relation
      AND subject_type = 'user' AND subject_id = authz.uid()::text AND subject_relation = '';
  END IF;
  PERFORM authz_int.audit('break_glass', p_type, p_id, p_relation, 'user', authz.uid()::text, '',
                          jsonb_build_object('until', v_until, 'previous_share', CASE WHEN g.object_id IS NULL THEN NULL
                                             ELSE to_jsonb(g) - 'subject_id' END));
  SELECT max(id) INTO v_audit FROM authz.audit WHERE action = 'break_glass' AND txid = txid_current();
  PERFORM pg_notify('authz_alerts', json_build_object('audit_id', v_audit, 'action', 'break_glass')::text);
END $f$;
CREATE FUNCTION authz.break_glass(p_type text, p_id bigint, p_relation text, p_reason text,
  p_duration interval DEFAULT interval '1 hour') RETURNS void LANGUAGE sql AS
  $$ SELECT authz.break_glass(p_type, p_id::text, p_relation, p_reason, p_duration) $$;

-- Access reviews: snapshot the shares on an object; reviewers keep or revoke each; closing applies it.
-- Starting one needs 'share' on the object (or being an administrator); revoking an item needs
-- what unsharing it needs.
CREATE FUNCTION authz.start_review(p_type text, p_id text, p_closes_at timestamptz DEFAULT now() + interval '14 days')
RETURNS bigint LANGUAGE plpgsql {DEF} AS $f$
DECLARE v_id bigint;
BEGIN
  p_id := authz_int.canon(p_type, p_id);
  PERFORM authz_int.check_writable();
  IF NOT authz_int.may_inspect(p_type, p_id) THEN
    RAISE EXCEPTION 'you cannot review % %', p_type, p_id USING ERRCODE = 'insufficient_privilege', HINT = 'rowstile help AZ705';
  END IF;
  INSERT INTO authz.reviews (object_type, object_id, created_by, closes_at)
  VALUES (p_type, p_id, authz.uid()::text, p_closes_at) RETURNING id INTO v_id;
  INSERT INTO authz.review_items (review_id, item, relation, subject_type, subject_id, subject_relation, expires_at)
  SELECT v_id, row_number() OVER (ORDER BY g.created_at, g.relation, g.subject_type, g.subject_id), g.relation,
         g.subject_type, g.subject_id, g.subject_relation, g.expires_at
  FROM authz.shares g WHERE g.object_type = p_type AND g.object_id = p_id;
  PERFORM authz_int.audit('start_review', p_type, p_id, NULL, NULL, NULL, NULL, jsonb_build_object('review', v_id));
  RETURN v_id;
END $f$;
CREATE FUNCTION authz.start_review(p_type text, p_id bigint, p_closes_at timestamptz DEFAULT now() + interval '14 days')
RETURNS bigint LANGUAGE sql AS
  $$ SELECT authz.start_review(p_type, p_id::text, p_closes_at) $$;
CREATE FUNCTION authz.review_items(p_review bigint)
RETURNS TABLE (item int, relation text, subject_type text, subject_id text, subject_relation text,
               expires_at timestamptz, keep boolean, decided_by text)
LANGUAGE plpgsql STABLE {DEF} AS $f$
DECLARE v authz.reviews;
BEGIN
  SELECT * INTO v FROM authz.reviews WHERE id = p_review;
  IF v.id IS NULL OR NOT authz_int.may_inspect(v.object_type, v.object_id) THEN
    RAISE EXCEPTION 'you cannot see review %', p_review USING ERRCODE = 'insufficient_privilege', HINT = 'rowstile help AZ705';
  END IF;
  RETURN QUERY SELECT i.item, i.relation, i.subject_type,
    CASE WHEN i.subject_type = 'link' THEN '(link)' ELSE i.subject_id END, i.subject_relation, i.expires_at, i.keep,
    i.decided_by FROM authz.review_items i WHERE i.review_id = p_review ORDER BY i.item;
END $f$;
CREATE FUNCTION authz.review_decide(p_review bigint, p_item int, p_keep boolean) RETURNS void
LANGUAGE plpgsql {DEF} AS $f$
DECLARE v authz.reviews; i authz.review_items;
BEGIN
  PERFORM authz_int.check_writable();
  SELECT * INTO v FROM authz.reviews WHERE id = p_review AND closed_at IS NULL;
  IF v.id IS NULL OR NOT authz_int.may_inspect(v.object_type, v.object_id) THEN
    RAISE EXCEPTION 'you cannot decide in review %', p_review USING ERRCODE = 'insufficient_privilege', HINT = 'rowstile help AZ705';
  END IF;
  SELECT * INTO i FROM authz.review_items WHERE review_id = p_review AND item = p_item;
  IF i.item IS NULL THEN RAISE EXCEPTION 'no item % in review %', p_item, p_review USING HINT = 'rowstile help AZ708'; END IF;
  IF NOT authz_int.may_manage(v.object_type, v.object_id, i.relation,
                              authz_int.subject_key(i.subject_type, i.subject_id, i.subject_relation)) THEN
    RAISE EXCEPTION 'you cannot decide on % in review % (you could not unshare it)', i.relation, p_review
      USING ERRCODE = 'insufficient_privilege', HINT = 'rowstile help AZ705';
  END IF;
  UPDATE authz.review_items SET keep = p_keep, decided_by = authz.uid()::text, decided_at = now()
  WHERE review_id = p_review AND item = p_item;
END $f$;
-- Close: revoke what reviewers marked (and, if asked, whatever nobody decided and you could unshare)
CREATE FUNCTION authz.close_review(p_review bigint, p_revoke_undecided boolean DEFAULT false) RETURNS int
LANGUAGE plpgsql {DEF} AS $f$
DECLARE v authz.reviews; n int;
BEGIN
  PERFORM authz_int.check_writable();
  SELECT * INTO v FROM authz.reviews WHERE id = p_review AND closed_at IS NULL FOR UPDATE;
  IF v.id IS NULL OR NOT authz_int.may_inspect(v.object_type, v.object_id) THEN
    RAISE EXCEPTION 'you cannot close review %', p_review USING ERRCODE = 'insufficient_privilege', HINT = 'rowstile help AZ705';
  END IF;
  PERFORM set_config('authz_ctx.reason', 'access review ' || p_review, true);
  -- items marked 'revoke' were decided by someone allowed to unshare them; undecided ones need you to be
  DELETE FROM authz.shares g USING authz.review_items i
  WHERE i.review_id = p_review
    AND (i.keep = false OR (p_revoke_undecided AND i.keep IS NULL
         AND authz_int.may_manage(v.object_type, v.object_id, i.relation,
                                  authz_int.subject_key(i.subject_type, i.subject_id, i.subject_relation))))
    AND g.object_type = v.object_type AND g.object_id = v.object_id AND g.relation = i.relation
    AND g.subject_type = i.subject_type AND g.subject_id = i.subject_id AND g.subject_relation = i.subject_relation;
  GET DIAGNOSTICS n = ROW_COUNT;
  UPDATE authz.reviews SET closed_at = now() WHERE id = p_review;
  PERFORM authz_int.audit('close_review', v.object_type, v.object_id, NULL, NULL, NULL, NULL,
                          jsonb_build_object('review', p_review, 'revoked', n));
  RETURN n;
END $f$;"""

    # ------------------------------------------------------------------
    # invariants
    # ------------------------------------------------------------------
    def invariant_sql(self) -> str:
        # everyone who can sign in: each principal type's rows (users first), named as the audit trail names them
        people = " UNION ALL ".join(
            f"SELECT {lit('' if t.name == 'user' else t.name)}, x.{q(self.pk(t))}::text FROM {qt(t.table)} x"
            for t in sorted(self.types.values(), key=lambda t: t.name != "user")
            if t.name == "user" or t.principal
        )
        checks: list[str] = []
        for i, inv in enumerate(self.pol.invariants):
            t = self.T(inv.type)
            # its own view: no name a policy writes has `__` in it (AZ107), so no permission's or relation's is this
            view = f"{t.name}__never__{i + 1}"
            self.add_view(
                view,
                self.set_sql(t, inv.expr, inv.loc),
                f"-- invariant ({inv.loc}): never {t.name}: {inv.src}\n",
                t,
                public=False,
            )
            self.view_state[view] = "done"
            checks.append(f"""      v_ids := ARRAY(SELECT id::text FROM authz_int.{q(view)} ORDER BY 1 LIMIT 5);
      IF cardinality(v_ids) > 0 THEN
        invariant := {lit(f"never {t.name}: {inv.src} (")} || {self.line_sql(f"invariant never {t.name}: {inv.src}", inv.loc)} || ')'; user_id := nullif(CASE WHEN v_p = '' THEN v_u ELSE v_p || ':' || v_u END, ''); object_ids := v_ids;
        RETURN NEXT;
      END IF;""")
        body = "\n".join(checks) if checks else "      NULL;"
        return f"""-- Invariants: checked as everyone who can sign in (each user, each other principal as 'service:3') and as
-- nobody; returns the violations
CREATE FUNCTION authz.check_invariants() RETURNS TABLE (invariant text, user_id text, object_ids text[])
LANGUAGE plpgsql {DEF} AS $f$
DECLARE v_me text := coalesce(current_setting('authz.user_id', true), ''); v_pt text := coalesce(current_setting('authz.principal_type', true), '');
        v_scopes text := coalesce(current_setting('authz.scopes', true), ''); v_p text; v_u text; v_ids text[];
BEGIN
  BEGIN
    PERFORM set_config('authz.scopes', '', true);
    FOR v_p, v_u IN SELECT '', '' UNION ALL {people} LOOP
      PERFORM set_config('authz.principal_type', v_p, true);
      PERFORM set_config('authz.user_id', v_u, true);
      PERFORM authz_int.sign();
{body}
    END LOOP;
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
END $f$;"""

    # ------------------------------------------------------------------
    # previewing a policy change
    # ------------------------------------------------------------------
    def diff_parts(self, source_name: str, users: list[str] | None = None) -> dict[str, str]:
        """The pieces of a policy preview, run in order in a transaction that is then undone:
        setup (temp tables), before (snapshot), body (the new policy), after (snapshot).
        Afterwards DIFF_ROWS lists the changes."""
        # here the policy runs inside our transaction, and is rolled back
        body = self.compile(source_name, transaction=False)
        # everyone who can sign in, and nobody: each user, then each other principal named as the audit trail
        # names it ('service:7'); --users names them the same way
        only = ("CONTINUE WHEN v_u <> ALL (ARRAY[" + ", ".join(lit(u) for u in users) + "]::text[]);") if users else ""
        snapshot = lambda into: (
            f"""DO $snap$
DECLARE who record; v_id text; v_u text; p record; pol record; m record;
BEGIN
  IF to_regclass('authz_int.types') IS NULL THEN RETURN; END IF;
  IF to_regclass('authz_int.masked_columns') IS NOT NULL THEN
    INSERT INTO pg_temp.authz_diff_cols SELECT tbl, col FROM authz_int.masked_columns;
  END IF;
  FOR who IN SELECT CASE WHEN t.name = 'user' THEN '' ELSE t.name END AS ptype, t.tbl, t.pk FROM authz_int.types t
             WHERE t.name = 'user' OR t.principal ORDER BY t.name <> 'user', t.name LOOP
  FOR v_id IN EXECUTE format('SELECT %I::text FROM %s', who.pk, who.tbl) || CASE WHEN who.ptype = '' THEN ' UNION ALL SELECT ''''' ELSE '' END LOOP
    v_u := CASE WHEN who.ptype = '' THEN v_id ELSE who.ptype || ':' || v_id END;
    {only}
    PERFORM set_config('authz.principal_type', who.ptype, true);
    PERFORM set_config('authz.user_id', v_id, true);
    FOR p IN SELECT type, perm FROM authz_int.perms LOOP
      INSERT INTO pg_temp.{into} SELECT v_u, p.type, 'permission ' || p.perm, x FROM authz.list(p.type, p.perm) x;
    END LOOP;
    -- (each type's select policy by its table's oid, never by a name read back as a table: the planner may try that
    -- on every table there is, and for one of pg_toast's it is refused to an owner who is no superuser)
    FOR pol IN SELECT format('%I.%I', n.nspname, c.relname) AS tbl, pg_get_expr(pp.polqual, pp.polrelid) AS qual, t.id_of
               FROM authz_int.types t JOIN pg_policy pp ON pp.polrelid = to_regclass(t.tbl) AND pp.polname = 'authz_select'
               JOIN pg_class c ON c.oid = pp.polrelid JOIN pg_namespace n ON n.oid = c.relnamespace
               WHERE pp.polqual IS NOT NULL LOOP
      EXECUTE format('INSERT INTO pg_temp.{into} SELECT $1, $2, ''rows readable'', x::text FROM '
                     '(SELECT %s AS x FROM %s WHERE %s) s', pol.id_of, pol.tbl, pol.qual)
        USING v_u, pol.tbl;
    END LOOP;
    -- masked columns: through the view while masked, else wherever the row is readable
    FOR m IN SELECT c.tbl, c.col, t.id_of, mc.view, pg_get_expr(pp.polqual, pp.polrelid) AS qual
             FROM (SELECT DISTINCT tbl, col FROM pg_temp.authz_diff_cols) c
             JOIN authz_int.types t ON to_regclass(t.tbl) = to_regclass(c.tbl)
             LEFT JOIN authz_int.masked_columns mc ON mc.tbl = c.tbl AND mc.col = c.col
             LEFT JOIN pg_policy pp ON pp.polname = 'authz_select' AND pp.polrelid = to_regclass(c.tbl) LOOP
      IF m.view IS NOT NULL AND to_regclass(m.view) IS NOT NULL THEN
        EXECUTE format('INSERT INTO pg_temp.{into} SELECT $1, $2, $3, %s FROM %s WHERE %I IS NOT NULL',
                       m.id_of, m.view, m.col) USING v_u, to_regclass(m.tbl)::text, 'column ' || m.col || ' readable';
      ELSIF m.qual IS NOT NULL AND EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid = to_regclass(m.tbl)
                                            AND a.attname = m.col AND a.attnum > 0 AND NOT a.attisdropped) THEN
        CONTINUE WHEN NOT has_column_privilege({lit(self.role)}, m.tbl, m.col, 'SELECT');
        EXECUTE format('INSERT INTO pg_temp.{into} SELECT $1, $2, $3, %s FROM %s WHERE (%s) AND %I IS NOT NULL',
                       m.id_of, m.tbl, m.qual, m.col) USING v_u, to_regclass(m.tbl)::text, 'column ' || m.col || ' readable';
      END IF;
    END LOOP;
  END LOOP;
  END LOOP;
  PERFORM set_config('authz.principal_type', '', true);
  PERFORM set_config('authz.user_id', '', true);
END $snap$;"""
        )
        setup = f"""SET LOCAL client_min_messages = warning;
CREATE TEMP TABLE authz_diff_before (user_id text, type text, what text, id text) ON COMMIT DROP;
CREATE TEMP TABLE authz_diff_after (user_id text, type text, what text, id text) ON COMMIT DROP;
CREATE TEMP TABLE authz_diff_cols (tbl text, col text) ON COMMIT DROP;{"".join(chr(10) + f"INSERT INTO authz_diff_cols VALUES ({lit(qt(r.table))}, {lit(c)});" for r in self.rules if r.command == "mask" for c in r.columns)}"""
        return {
            "setup": setup,
            "before": snapshot("authz_diff_before"),
            "body": body,
            "after": snapshot("authz_diff_after"),
        }

    def compile_diff(self, source_name: str, users: list[str] | None = None, limit: int = 200) -> str:
        p = self.diff_parts(source_name, users)
        return f"""-- Preview of {source_name}: who gains and who loses access if it is applied.
-- Nothing is changed: everything runs in one transaction that is rolled back.
\\set ON_ERROR_STOP on
BEGIN;
{p["setup"]}
{p["before"]}

{p["body"]}

{p["after"]}
\\echo '== Summary: how many (user, object) pairs change =='
SELECT change, type, what, count(*) AS pairs, count(DISTINCT user_id) AS users
FROM ({DIFF_ROWS}) d
GROUP BY 1, 2, 3 ORDER BY 2, 3, 1;
\\echo '== Details (first {limit}) =='
SELECT change, coalesce(nullif(user_id, ''), '(nobody signed in)') AS user_id, type, what, id
FROM ({DIFF_ROWS}) d
ORDER BY type, what, id, user_id, change LIMIT {limit};
ROLLBACK;
"""


# Every (user, type, what, id) the new policy adds or removes, once both snapshots are taken
DIFF_ROWS = """(SELECT 'gains' AS change, * FROM (SELECT * FROM authz_diff_after EXCEPT SELECT * FROM authz_diff_before) a)
      UNION ALL
      (SELECT 'loses', * FROM (SELECT * FROM authz_diff_before EXCEPT SELECT * FROM authz_diff_after) b)"""

"""Identities other than a logged-in person: scopes, API keys, JWT login,
read-only impersonation, and syncing group members from an identity provider."""

from .compiler import Core
from .governance import trigger_if_partitioned
from .parse import Type, cols
from .sqlutil import lit, q, qt

DEF = "SECURITY DEFINER SET search_path = pg_catalog, pg_temp"

# HMAC-SHA256 of who is signed in, this backend and this transaction, with k a row of
# authz_int.session_key: only functions that run as the policy's owner can read it
SESSION_SIG = (
    "pg_catalog.encode(pg_catalog.sha256(k.opad || pg_catalog.sha256(k.ipad || pg_catalog.convert_to("
    "pg_catalog.concat_ws(pg_catalog.chr(31), "
    "coalesce(pg_catalog.current_setting('authz.user_id', true), ''), "
    "coalesce(pg_catalog.current_setting('authz.principal_type', true), ''), "
    "coalesce(pg_catalog.current_setting('authz.scopes', true), ''), "
    "coalesce(pg_catalog.current_setting('authz.acting_user', true), ''), "
    "pg_catalog.pg_backend_pid()::text, "
    "(EXTRACT(epoch FROM pg_catalog.transaction_timestamp()) * 1000000)::bigint::text), 'UTF8'))), 'hex')"
)
# Are the settings to be believed? true, or an error saying why not. Called by the functions that read them
# (uid, the principals' __me, actor, scopes), which all run as the owner.
SESSION_OK = "authz_int.session_ok()"


# A principal's API keys go with its row (key_forget_sql). A key is made under a lock on the principal's row (FOR
# KEY SHARE), so a delete waits for it, and in READ COMMITTED the trigger that deletes the row's keys then sees it. A
# transaction whose snapshot is older than the key (REPEATABLE READ, SERIALIZABLE) doesn't, so making a key also
# writes a new version of a mark row for its principal, and a delete, a new id or a TRUNCATE in such a transaction
# writes the same mark first: where a key it can't see was made since its snapshot, that fails to serialize (40001)
# instead of committing and leaving the key to whoever later has that id. One mark per principal with keys made,
# removed with the row.
KEY_MARKS = """-- a mark for each principal a key was made for (authz_int.mark_key), until its row is gone (keys_gone)
CREATE TABLE authz_int.key_marks (type text, id text, n bigint NOT NULL DEFAULT 0, PRIMARY KEY (type, id));
CREATE FUNCTION authz_int.mark_key(p_type text, p_id text) RETURNS void
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $f$
  INSERT INTO authz_int.key_marks AS m (type, id) VALUES (p_type, p_id)
  ON CONFLICT (type, id) DO UPDATE SET n = m.n + 1 $f$;
-- whether a principal's row is there, locked (FOR KEY SHARE) until the transaction ends
CREATE FUNCTION authz_int.lock_principal(p_type text, p_id text) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $f$
DECLARE v_tbl text; v_find text; v_found boolean;
BEGIN
  SELECT t.tbl, t.find INTO v_tbl, v_find FROM authz_int.types t WHERE t.name = p_type AND t.principal;
  -- (the key's type by a subquery, as authz_int.hold reads it: a variable would keep its first value)
  IF v_tbl IS NULL OR p_id IS NULL
     OR NOT pg_catalog.pg_input_is_valid(p_id, (SELECT t.keytype FROM authz_int.types t WHERE t.name = p_type)) THEN
    RETURN false;
  END IF;
  EXECUTE pg_catalog.format('SELECT EXISTS (SELECT 1 FROM %s x WHERE %s FOR KEY SHARE)', v_tbl, v_find) INTO v_found
    USING p_id;
  RETURN v_found;
END $f$;
-- the keys of principals that are gone, or whose id changed (p_ids; NULL: every one of the type, TRUNCATE) are
-- deleted, each in the audit trail. In a transaction whose snapshot may be older than a key made for one of them
-- (not READ COMMITTED), their marks are written first: if a key was made since, that fails to serialize (40001)
CREATE FUNCTION authz_int.keys_gone(p_type text, p_ids text[]) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $f$
DECLARE k record;
BEGIN
  IF p_ids IS NOT NULL AND pg_catalog.current_setting('transaction_isolation') <> 'read committed' THEN
    INSERT INTO authz_int.key_marks AS m (type, id) SELECT DISTINCT p_type, x FROM unnest(p_ids) x
    ON CONFLICT (type, id) DO UPDATE SET n = m.n + 1;
  END IF;
  DELETE FROM authz_int.key_marks WHERE type = p_type AND (p_ids IS NULL OR id = ANY (p_ids));
  FOR k IN DELETE FROM authz.api_keys WHERE principal_type = p_type AND (p_ids IS NULL OR user_id = ANY (p_ids))
           RETURNING id, user_id, name LOOP
    PERFORM authz_int.audit('delete_api_key', p_type, k.user_id, NULL, NULL, NULL, NULL,
                            jsonb_build_object('key', k.id, 'name', k.name, 'why', 'its principal is gone'));
  END LOOP;
END $f$;"""


class IdentityMixin(Core):
    def key_forget_sql(self, t: Type) -> str:
        """A principal's API keys go with its row: deleted with the row, when its id changes (as its shares are) or
        when its table is emptied, so a row that later has that id signs in with none of them."""
        tbl = qt(t.table)
        fn = f"authz_int.{q(t.name + '__keys_gone')}"
        fn_row = f"authz_int.{q(t.name + '__keys_gone_id')}"
        fn_first = f"authz_int.{q(t.name + '__keys_gone_all')}"
        name = lit(t.name)
        gone = f"SELECT {self.key_text(t, 'o')} FROM old_rows o EXCEPT SELECT {self.key_text(t, 'n')} FROM new_rows n"
        moved = trigger_if_partitioned(
            t.table,
            f"CREATE TRIGGER {q('authz_' + t.name + '_keys_gone_moved')} AFTER UPDATE ON {tbl} "
            f"REFERENCING OLD TABLE AS old_rows NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION {fn}()",
        )
        return f"""-- the API keys of {t.name} rows that are gone, or whose id changed, are deleted (authz_int.keys_gone)
CREATE FUNCTION {fn}() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path FROM CURRENT AS $f$
BEGIN
  IF TG_OP = 'TRUNCATE' THEN
    PERFORM authz_int.keys_gone({name}, NULL);
  ELSIF TG_OP = 'UPDATE' THEN   -- on a partitioned table (the last trigger below): the ids the update left no row with
    PERFORM authz_int.keys_gone({name}, ARRAY({gone}));
  ELSE
    PERFORM authz_int.keys_gone({name}, ARRAY(SELECT {self.key_text(t, "o")} FROM old_rows o));
  END IF;
  RETURN NULL;
END $f$;
CREATE FUNCTION {fn_row}() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path FROM CURRENT AS $f$
BEGIN
  PERFORM authz_int.keys_gone({name}, ARRAY[{self.key_text(t, "OLD")}]);
  RETURN NULL;
END $f$;
-- before TRUNCATE empties the table: with a snapshot older than a key made for one of its rows, fail to serialize
CREATE FUNCTION {fn_first}() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path FROM CURRENT AS $f$
BEGIN
  IF pg_catalog.current_setting('transaction_isolation') <> 'read committed' THEN
    PERFORM authz_int.keys_gone({name}, ARRAY(SELECT {self.key_text(t, "x")} FROM {tbl} x));
  END IF;
  RETURN NULL;
END $f$;
CREATE TRIGGER {q("authz_" + t.name + "_keys_gone_del")} AFTER DELETE ON {tbl}
  REFERENCING OLD TABLE AS old_rows FOR EACH STATEMENT EXECUTE FUNCTION {fn}();
CREATE TRIGGER {q("authz_" + t.name + "_keys_gone_id")} AFTER UPDATE ON {tbl} FOR EACH ROW
  WHEN ({self.key(t, "OLD")} IS DISTINCT FROM {self.key(t, "NEW")}) EXECUTE FUNCTION {fn_row}();
CREATE TRIGGER {q("authz_" + t.name + "_keys_gone_trunc")} AFTER TRUNCATE ON {tbl}
  FOR EACH STATEMENT EXECUTE FUNCTION {fn}();
CREATE TRIGGER {q("authz_" + t.name + "_keys_gone_trunc_first")} BEFORE TRUNCATE ON {tbl}
  FOR EACH STATEMENT EXECUTE FUNCTION {fn_first}();
-- On a partitioned table, an update that puts a row in another partition is a delete there and an insert here:
-- Postgres runs no AFTER UPDATE row trigger for it. The ids an update leaves no row with lose their keys too.
{moved}"""

    def session_sql(self) -> str:
        """Signed sessions: who is signed in (authz.user_id, principal_type, scopes, acting_user) is
        believed only with the signature authz.act_as() and the logins put in authz.session: an HMAC of those
        settings, this backend and this transaction, with a key the app role can't read. So the app role can't
        choose its own user, or widen its scopes, by setting them, on any Postgres. Sessions of the policy's
        owner and superusers are believed without one (psql, migrations, tests). Everyone else gets an error
        when nobody signed in (strict sign-in) or the settings changed after signing in."""
        return f"""-- Signed sessions: the key, made once and kept in authz.settings (the app role can't read either)
CREATE TABLE authz_int.session_key (ipad bytea NOT NULL, opad bytea NOT NULL);
INSERT INTO authz.settings (key, value)
  VALUES ('session_key', replace(gen_random_uuid()::text || gen_random_uuid()::text, '-', ''))
  ON CONFLICT (key) DO NOTHING;
DO $sk$
DECLARE k bytea; i bytea; o bytea;
BEGIN
  SELECT decode(value, 'hex') INTO k FROM authz.settings WHERE key = 'session_key';
  k := k || decode(repeat('00', 64 - length(k)), 'hex');
  i := k; o := k;
  FOR n IN 0..63 LOOP
    i := set_byte(i, n, get_byte(k, n) # 54);
    o := set_byte(o, n, get_byte(k, n) # 92);
  END LOOP;
  INSERT INTO authz_int.session_key VALUES (i, o);
END $sk$;
-- HMAC-SHA256 of who is signed in, this backend and this transaction
CREATE FUNCTION authz_int.session_sig() RETURNS text
LANGUAGE plpgsql STABLE {DEF} AS $f$
DECLARE k authz_int.session_key;
BEGIN
  SELECT * INTO k FROM authz_int.session_key;
  RETURN {SESSION_SIG};
END $f$;
-- signs the settings as they are now: for rowstile's own functions, after they switch who is signed in
CREATE FUNCTION authz_int.sign() RETURNS void
LANGUAGE plpgsql VOLATILE {DEF} AS $f$
BEGIN
  PERFORM set_config('authz.session', authz_int.session_sig(), true);
END $f$;
-- JIT off for the rest of the transaction, when it signs someone in (act_as, the logins, view_as). Postgres
-- compiles a plan whose estimated cost passes jit_above_cost, and the rules' lookups are costed per row though
-- each is hashed once: a read of a few thousand rows through row-level security is estimated at hundreds of
-- thousands, and JIT takes most of a second compiling a read that runs in a few ms. The app may turn it back
-- on after signing in (SET LOCAL jit = on); the transaction's end puts back the session's own setting.
CREATE FUNCTION authz_int.jit_off() RETURNS void
LANGUAGE sql VOLATILE AS $f$ SELECT pg_catalog.set_config('jit', 'off', true) $f$;
-- Are the settings to be believed? PL/pgSQL, so its plans are kept for the session, and not a definer: all its
-- callers run as the owner. (OR runs left to right: the refusal is asked only when the signature doesn't match.)
CREATE FUNCTION authz_int.session_ok() RETURNS boolean
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, pg_temp AS $f$
DECLARE k authz_int.session_key;
BEGIN
  SELECT * INTO k FROM authz_int.session_key;
  RETURN coalesce(current_setting('authz.session', true) = {SESSION_SIG}, false) OR authz_int.session_refused();
END $f$;
-- When the signature doesn't match: true for the owner's and superusers' sessions, else an error saying why
CREATE FUNCTION authz_int.session_refused() RETURNS boolean
LANGUAGE plpgsql STABLE {DEF} AS $f$
DECLARE v_sig text := coalesce(current_setting('authz.session', true), '');
BEGIN
  -- the policy's owner and superusers say who is signed in by setting it (psql, migrations, tests)
  IF pg_has_role(session_user, (SELECT nspowner FROM pg_namespace WHERE nspname = 'authz_int'), 'MEMBER') THEN
    RETURN true;
  END IF;
  IF v_sig <> '' THEN
    RAISE EXCEPTION 'who is signed in was changed after signing in' USING ERRCODE = 'invalid_authorization_specification',
      HINT = 'say who is signed in with authz.act_as(), never by setting authz.user_id or the other authz settings '
             '(rowstile help AZ702)';
  ELSIF coalesce(current_setting('authz.user_id', true), '') <> '' THEN
    RAISE EXCEPTION 'authz.user_id was set directly, so it is not believed' USING ERRCODE = 'invalid_authorization_specification',
      HINT = 'sign in with SELECT authz.act_as(''user'', ''42''), authz.login_key() or authz.login_jwt() (rowstile help AZ702)';
  END IF;
  RAISE EXCEPTION 'nobody signed in in this transaction' USING ERRCODE = 'invalid_authorization_specification',
    HINT = 'start each transaction with SELECT authz.act_as(''user'', ''42''), or authz.act_as(NULL, NULL) for nobody '
           '(or authz.login_key() / authz.login_jwt()) (rowstile help AZ701)';
END $f$;"""

    def scope_rows(self) -> list[tuple[str, str, str | None, str]]:
        """(scope, kind, qualifier, name) for each scope item, the built-in read scope included."""
        rows: list[tuple[str, str, str | None, str]] = []
        for sc in self.pol.scopes.values():
            for kind, qual, word in sc.items:
                rows.append((sc.name, kind, qual, word))
        if "read" not in self.pol.scopes:
            # built in: what 'view as' uses; reads everything the user can, changes nothing
            rows += [("read", "cmd", None, "select"), ("read", "perm", None, "*")]
        return rows

    def scope_sql(self) -> str:
        rows = self.scope_rows()
        values = ",\n  ".join(f"({lit(a)}, {lit(b)}, {lit(c) if c else 'NULL'}, {lit(d)})" for a, b, c, d in rows)
        return f"""-- Scopes: what a token may do (policy 'scope' lines; 'read' is built in unless redefined)
CREATE TABLE authz_int.scope_items (scope text, kind text, qual text, word text);
INSERT INTO authz_int.scope_items VALUES
  {values};

-- the scopes this transaction is limited to (NULL: not limited); believed only if signed, like the user
CREATE FUNCTION authz_int.scopes_active() RETURNS text[]
LANGUAGE sql STABLE {DEF} AS $f$
  SELECT CASE WHEN NOT {SESSION_OK} THEN ARRAY[]::text[]
              WHEN coalesce(current_setting('authz.scopes', true), '') = '' THEN NULL
              ELSE ARRAY(SELECT btrim(x) FROM unnest(string_to_array(current_setting('authz.scopes', true), ',')) x
                         WHERE btrim(x) <> '') END $f$;
-- may this transaction run a command on a table?
CREATE FUNCTION authz_int.scope_cmd(p_table text, p_cmd text) RETURNS boolean
LANGUAGE sql STABLE {DEF} AS $f$
  SELECT s IS NULL OR EXISTS (SELECT 1 FROM authz_int.scope_items i WHERE i.scope = ANY (s) AND i.kind = 'cmd'
                              AND i.word = p_cmd AND (i.qual IS NULL OR i.qual = p_table))
  FROM (SELECT authz_int.scopes_active() AS s) x $f$;
-- may this transaction ask about (or use) a permission?
CREATE FUNCTION authz_int.scope_perm(p_type text, p_perm text) RETURNS boolean
LANGUAGE sql STABLE {DEF} AS $f$
  SELECT s IS NULL OR EXISTS (SELECT 1 FROM authz_int.scope_items i WHERE i.scope = ANY (s) AND i.kind = 'perm'
                              AND (i.word = p_perm OR i.word = '*') AND (i.qual IS NULL OR i.qual = p_type))
  FROM (SELECT authz_int.scopes_active() AS s) x $f$;
-- may this transaction change anything? (not while viewing as someone, not with read-only scopes)
CREATE FUNCTION authz_int.writable() RETURNS boolean
LANGUAGE sql STABLE {DEF} AS $f$
  SELECT coalesce(current_setting('authz.acting_user', true), '') = ''
     AND (s IS NULL OR EXISTS (SELECT 1 FROM authz_int.scope_items i WHERE i.scope = ANY (s) AND i.kind = 'cmd'
                               AND i.word <> 'select'))
  FROM (SELECT authz_int.scopes_active() AS s) x $f$;
CREATE FUNCTION authz_int.check_writable() RETURNS void
LANGUAGE plpgsql STABLE {DEF} AS $f$
BEGIN
  IF NOT authz_int.writable() THEN
    RAISE EXCEPTION 'this session is read-only (viewing as someone else, or a read-only token)'
      USING ERRCODE = 'insufficient_privilege', HINT = 'rowstile help AZ704';
  END IF;
END $f$;
-- the role that called (inside SECURITY DEFINER functions current_user is the owner)
CREATE FUNCTION authz_int.caller_role() RETURNS text
LANGUAGE sql STABLE AS $f$
  SELECT CASE WHEN current_setting('role') = 'none' THEN session_user::text ELSE current_setting('role') END $f$;
-- The caller is an administrator, not the app: a superuser, BYPASSRLS, or the policy's owner (or a member of it)
CREATE FUNCTION authz_int.caller_is_admin() RETURNS boolean
LANGUAGE sql STABLE {DEF} AS $f$
  SELECT coalesce((SELECT r.rolsuper OR r.rolbypassrls OR pg_has_role(r.oid, n.nspowner, 'MEMBER')
                   FROM pg_roles r, pg_namespace n
                   WHERE r.rolname = authz_int.caller_role() AND n.nspname = 'authz_int'), false) $f$;
-- one row in the audit trail
CREATE FUNCTION authz_int.audit(p_action text, p_object_type text, p_object_id text, p_relation text,
  p_subject_type text, p_subject_id text, p_subject_relation text, p_detail jsonb) RETURNS void
LANGUAGE sql {DEF} AS $f$
  INSERT INTO authz.audit (db_role, user_id, acting_user, action, object_type, object_id, relation,
                           subject_type, subject_id, subject_relation, detail, reason)
  VALUES (authz_int.caller_role(), authz_int.actor(),
          nullif(current_setting('authz.acting_user', true), ''), p_action, p_object_type, p_object_id, p_relation,
          p_subject_type, p_subject_id, p_subject_relation, p_detail,
          nullif(current_setting('authz_ctx.reason', true), '')) $f$;"""

    def identity_api_sql(self) -> str:
        u = self.T("user")
        imp = "impersonate" in u.perms
        sync_cases: list[str] = []
        for t in self.types.values():
            for r in t.relations.values():
                srcs = [
                    s
                    for s in r.sources
                    if s.kind == "table" and ("user", None) in s.subjects and not s.where and not s.type_col
                ]
                if len(srcs) != 1:
                    continue
                src = srcs[0]
                # a user's key is one column, so the subject is one column
                obj = self.source_obj_columns(src)
                tbl, sc = qt(self.source_table(src)), q(cols(self.source_columns(src))[0])
                ocs = ", ".join(q(c) for c in cols(obj))
                vals = (
                    ", ".join(f"(p_id::{t.keytype}).{q(c)}" for c, _ in t.key) if t.composite else f"p_id::{t.pktype}"
                )
                this = self.key_is(t, "s", "p_id", obj) if t.composite else f"s.{q(cols(obj)[0])} = p_id::{t.pktype}"
                sync_cases.append(f"""    WHEN {lit(t.name + "." + r.name)} THEN
      WITH want AS (SELECT DISTINCT x::{u.pktype} AS m FROM unnest(p_members) x),
      del AS (DELETE FROM {tbl} s WHERE {this} AND s.{sc} NOT IN (SELECT m FROM want) RETURNING 1),
      ins AS (INSERT INTO {tbl} ({ocs}, {sc}) SELECT {vals}, w.m FROM want w
              WHERE NOT EXISTS (SELECT 1 FROM {tbl} s WHERE {this} AND s.{sc} = w.m) RETURNING 1)
      SELECT (SELECT count(*) FROM ins)::int, (SELECT count(*) FROM del)::int INTO added, removed;""")
        sync = "\n".join(sync_cases) if sync_cases else "    WHEN NULL THEN NULL;"
        return f"""{KEY_MARKS}

-- API keys: a signed-in user's own, or a principal's (a service's) made by someone holding
-- manage_keys on it; only a hash is kept
CREATE FUNCTION authz.create_api_key(p_name text, p_scopes text DEFAULT '', p_expires_at timestamptz DEFAULT NULL,
  p_principal_type text DEFAULT NULL, p_principal_id text DEFAULT NULL)
RETURNS text LANGUAGE plpgsql {DEF} AS $f$
DECLARE v_token text := 'ak_' || replace(gen_random_uuid()::text || gen_random_uuid()::text, '-', '');
        v_scopes text[] := ARRAY(SELECT DISTINCT btrim(x) FROM unnest(string_to_array(coalesce(p_scopes, ''), ',')) x
                                 WHERE btrim(x) <> '' ORDER BY 1);
        v_cur text[] := authz_int.scopes_active(); v_bad text;
        v_type text := coalesce(p_principal_type, 'user'); v_id text;
BEGIN
  PERFORM authz_int.check_writable();
  -- the principal's row is locked (FOR KEY SHARE) before it is checked: a delete of it waits for this key, or this
  -- for the delete, which leaves no principal to make it for (a delete with an older snapshot: keys_gone)
  IF p_principal_id IS NULL THEN
    v_id := authz.uid()::text;
    IF v_type <> 'user' OR v_id IS NULL OR NOT authz_int.lock_principal('user', v_id) THEN
      RAISE EXCEPTION 'sign in to create an API key' USING ERRCODE = 'insufficient_privilege', HINT = 'rowstile help AZ714';
    END IF;
  ELSE
    v_id := authz_int.canon(v_type, p_principal_id);
    PERFORM authz_int.lock_principal(v_type, v_id);
    PERFORM authz_int.check_manage_keys(v_type, v_id);
  END IF;
  SELECT string_agg(x, ', ') INTO v_bad FROM unnest(v_scopes) x
  WHERE NOT EXISTS (SELECT 1 FROM authz_int.scope_items WHERE scope = x);
  IF v_bad IS NOT NULL THEN RAISE EXCEPTION 'no scope % in the policy', v_bad USING HINT = 'rowstile help AZ707'; END IF;
  IF v_cur IS NOT NULL AND (cardinality(v_scopes) = 0 OR NOT v_scopes <@ v_cur) THEN
    RAISE EXCEPTION 'a key cannot have more scopes than the session creating it' USING ERRCODE = 'insufficient_privilege', HINT = 'rowstile help AZ704';
  END IF;
  INSERT INTO authz.api_keys (user_id, principal_type, name, prefix, hash, scopes, expires_at)
  VALUES (v_id, v_type, p_name, left(v_token, 10), encode(sha256(convert_to(v_token, 'UTF8')), 'hex'),
          array_to_string(v_scopes, ','), p_expires_at);
  PERFORM authz_int.mark_key(v_type, v_id);
  PERFORM authz_int.audit('create_api_key', v_type, v_id, NULL, NULL, NULL, NULL,
                          jsonb_build_object('name', p_name, 'scopes', v_scopes, 'expires_at', p_expires_at));
  RETURN v_token;
END $f$;

-- May the signed-in principal manage the keys of this one? Needs `can manage_keys` on its type.
CREATE FUNCTION authz_int.check_manage_keys(p_type text, p_id text) RETURNS void
LANGUAGE plpgsql STABLE {DEF} AS $f$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM authz_int.types WHERE name = p_type AND principal) THEN
    RAISE EXCEPTION 'no type % that signs in (type ... principal) in the policy', p_type USING HINT = 'rowstile help AZ707';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM authz_int.perms WHERE type = p_type AND perm = 'manage_keys') THEN
    RAISE EXCEPTION 'the policy gives % no manage_keys permission, so nobody manages its keys', p_type
      USING HINT = 'rowstile help AZ707';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM authz.principal()) OR NOT coalesce(authz.can(p_type, p_id, 'manage_keys'), false) THEN
    RAISE EXCEPTION 'you cannot manage the keys of % %', p_type, p_id USING ERRCODE = 'insufficient_privilege', HINT = 'rowstile help AZ705';
  END IF;
END $f$;

-- Your keys, or (with manage_keys on it) a principal's
CREATE FUNCTION authz.list_api_keys(p_principal_type text DEFAULT NULL, p_principal_id text DEFAULT NULL)
RETURNS TABLE (id bigint, name text, prefix text, scopes text, created_at timestamptz, expires_at timestamptz,
               last_used_at timestamptz, revoked_at timestamptz)
LANGUAGE plpgsql STABLE {DEF} AS $f$
DECLARE v_type text; v_id text;
BEGIN
  IF p_principal_id IS NULL THEN
    SELECT p.principal_type, p.principal_id INTO v_type, v_id FROM authz.principal() p;
  ELSE
    v_type := coalesce(p_principal_type, 'user');
    v_id := authz_int.canon(v_type, p_principal_id);
    PERFORM authz_int.check_manage_keys(v_type, v_id);
  END IF;
  RETURN QUERY SELECT k.id, k.name, k.prefix, k.scopes, k.created_at, k.expires_at, k.last_used_at, k.revoked_at
  FROM authz.api_keys k WHERE k.user_id = v_id AND k.principal_type = v_type ORDER BY k.id;
END $f$;

-- Revoke a key: your own, a user's you may inspect, or a principal's you manage the keys of
CREATE FUNCTION authz.revoke_api_key(p_id bigint) RETURNS void
LANGUAGE plpgsql {DEF} AS $f$
DECLARE k authz.api_keys;
BEGIN
  PERFORM authz_int.check_writable();
  SELECT * INTO k FROM authz.api_keys WHERE id = p_id AND revoked_at IS NULL;
  IF k.id IS NULL OR NOT (
       EXISTS (SELECT 1 FROM authz.principal() p WHERE p.principal_type = k.principal_type AND p.principal_id = k.user_id)
       OR (k.principal_type = 'user' AND authz_int.may_inspect('user', k.user_id))
       OR (EXISTS (SELECT 1 FROM authz_int.perms WHERE type = k.principal_type AND perm = 'manage_keys')
           AND EXISTS (SELECT 1 FROM authz.principal())
           AND coalesce(authz.can(k.principal_type, k.user_id, 'manage_keys'), false))) THEN
    RAISE EXCEPTION 'no API key % of yours', p_id USING HINT = 'rowstile help AZ708';
  END IF;
  UPDATE authz.api_keys SET revoked_at = now() WHERE id = p_id;
  PERFORM authz_int.audit('revoke_api_key', k.principal_type, k.user_id, NULL, NULL, NULL, NULL,
                          jsonb_build_object('key', p_id));
END $f$;

-- Say who is asking, for this transaction: SELECT authz.act_as('user', '42') (NULL, NULL: nobody), first in each
-- transaction. For the app's backend, which signs people in itself; the session is signed, so nothing but this
-- and the logins can change who is signed in. The app role (and its members) may call it.
CREATE FUNCTION authz.act_as(p_type text, p_id text) RETURNS void
LANGUAGE plpgsql {DEF} AS $f$
BEGIN
  IF p_id IS NOT NULL AND coalesce(p_type, 'user') <> 'user'
     AND NOT EXISTS (SELECT 1 FROM authz_int.types WHERE name = p_type AND principal) THEN
    RAISE EXCEPTION '% is not a type that signs in', p_type USING
      HINT = 'principal types are marked "principal" in the policy: type service = app.services principal (rowstile help AZ707)';
  END IF;
  -- stored as every other id is ('05' is 5), so the audit and created_by name the user as shares do
  PERFORM set_config('authz.user_id', coalesce(authz_int.canon(coalesce(p_type, 'user'), p_id), ''), true);
  PERFORM set_config('authz.principal_type', CASE WHEN p_id IS NULL OR coalesce(p_type, 'user') = 'user' THEN '' ELSE p_type END, true);
  PERFORM set_config('authz.scopes', '', true);
  PERFORM set_config('authz.acting_user', '', true);
  PERFORM authz_int.sign();
  PERFORM authz_int.jit_off();
END $f$;

-- Sign in with an API key for this transaction: SELECT authz.login_key('ak_...'). Returns who:
-- a user's id, or type:id for another principal
CREATE FUNCTION authz.login_key(p_token text) RETURNS text
LANGUAGE plpgsql {DEF} AS $f$
DECLARE k authz.api_keys;
BEGIN
  SELECT * INTO k FROM authz.api_keys WHERE hash = encode(sha256(convert_to(coalesce(p_token, ''), 'UTF8')), 'hex');
  IF k.id IS NULL OR k.revoked_at IS NOT NULL OR (k.expires_at IS NOT NULL AND k.expires_at <= now()) THEN
    RAISE EXCEPTION 'invalid API key' USING ERRCODE = 'invalid_authorization_specification', HINT = 'rowstile help AZ703';
  END IF;
  PERFORM set_config('authz.user_id', k.user_id, true);
  PERFORM set_config('authz.principal_type', CASE WHEN k.principal_type = 'user' THEN '' ELSE k.principal_type END, true);
  PERFORM set_config('authz.scopes', k.scopes, true);
  PERFORM set_config('authz.acting_user', '', true);
  PERFORM authz_int.sign();
  IF NOT EXISTS (SELECT 1 FROM authz.principal()) THEN
    PERFORM set_config('authz.user_id', '', true);
    PERFORM set_config('authz.principal_type', '', true);
    RAISE EXCEPTION 'invalid API key' USING ERRCODE = 'invalid_authorization_specification', HINT = 'rowstile help AZ703';
  END IF;
  -- when it was last used, to the minute: never waiting on another request with the key (the row they
  -- lock), and not at all in a read-only transaction (a replica, a GET)
  IF pg_catalog.current_setting('transaction_read_only') = 'off' THEN
    UPDATE authz.api_keys SET last_used_at = now()
    WHERE id = (SELECT x.id FROM authz.api_keys x
                WHERE x.id = k.id AND (x.last_used_at IS NULL OR x.last_used_at < now() - interval '1 minute')
                FOR UPDATE SKIP LOCKED);
  END IF;
  PERFORM authz_int.jit_off();
  RETURN authz_int.actor();
END $f$;

-- HMAC-SHA256 in SQL, for JWT signatures (HS256)
CREATE FUNCTION authz_int.hmac_sha256(p_key bytea, p_msg bytea) RETURNS bytea
LANGUAGE plpgsql IMMUTABLE STRICT AS $f$
DECLARE k bytea := p_key; ipad bytea; opad bytea;
BEGIN
  IF length(k) > 64 THEN k := sha256(k); END IF;
  k := k || decode(repeat('00', 64 - length(k)), 'hex');
  ipad := k; opad := k;
  FOR i IN 0..63 LOOP
    ipad := set_byte(ipad, i, get_byte(k, i) # 54);
    opad := set_byte(opad, i, get_byte(k, i) # 92);
  END LOOP;
  RETURN sha256(opad || sha256(ipad || p_msg));
END $f$;
CREATE FUNCTION authz_int.b64url(p text) RETURNS bytea
LANGUAGE sql IMMUTABLE STRICT AS $f$
  SELECT decode(rpad(translate(p, '-_', '+/'), ((length(p) + 3) / 4) * 4, '='), 'base64') $f$;

-- Sign in with a JWT (HS256) for this transaction: SELECT authz.login_jwt('eyJ...')
-- Settings (authz.settings): jwt_secret (required), jwt_issuer, jwt_audience, jwt_user_claim (default sub),
-- jwt_type_claim (a claim naming the principal's type, for services; absent or 'user': a user).
-- Tokens must carry exp.
-- A 'scope' claim (space separated) limits the transaction to those policy scopes.
CREATE FUNCTION authz.login_jwt(p_token text) RETURNS text
LANGUAGE plpgsql {DEF} AS $f$
DECLARE parts text[] := string_to_array(coalesce(p_token, ''), '.'); v_head jsonb; v_claims jsonb; v_secret text;
        v_user text; v_type text; v_scopes text[]; v_now numeric := extract(epoch FROM now()); v_want text;
BEGIN
  SELECT value INTO v_secret FROM authz.settings WHERE key = 'jwt_secret';
  IF v_secret IS NULL THEN RAISE EXCEPTION 'JWT login is not configured (authz.settings jwt_secret)' USING ERRCODE = 'invalid_authorization_specification', HINT = 'rowstile help AZ703'; END IF;
  BEGIN
    IF cardinality(parts) <> 3 THEN RAISE EXCEPTION 'bad'; END IF;
    v_head := convert_from(authz_int.b64url(parts[1]), 'UTF8')::jsonb;
    v_claims := convert_from(authz_int.b64url(parts[2]), 'UTF8')::jsonb;
    IF v_head->>'alg' IS DISTINCT FROM 'HS256'
       OR authz_int.b64url(parts[3]) <> authz_int.hmac_sha256(convert_to(v_secret, 'UTF8'),
                                                              convert_to(parts[1] || '.' || parts[2], 'UTF8')) THEN
      RAISE EXCEPTION 'bad';
    END IF;
  EXCEPTION WHEN OTHERS THEN
    RAISE EXCEPTION 'invalid token' USING ERRCODE = 'invalid_authorization_specification', HINT = 'rowstile help AZ703';
  END;
  -- an expiry is required; both are numbers of seconds
  IF jsonb_typeof(v_claims->'exp') IS DISTINCT FROM 'number' OR (v_claims->>'exp')::numeric <= v_now
     OR (v_claims ? 'nbf' AND (jsonb_typeof(v_claims->'nbf') <> 'number' OR (v_claims->>'nbf')::numeric > v_now)) THEN
    RAISE EXCEPTION 'token expired or not yet valid' USING ERRCODE = 'invalid_authorization_specification', HINT = 'rowstile help AZ703';
  END IF;
  SELECT value INTO v_want FROM authz.settings WHERE key = 'jwt_issuer';
  IF v_want IS NOT NULL AND v_claims->>'iss' IS DISTINCT FROM v_want THEN
    RAISE EXCEPTION 'token from another issuer' USING ERRCODE = 'invalid_authorization_specification', HINT = 'rowstile help AZ703';
  END IF;
  SELECT value INTO v_want FROM authz.settings WHERE key = 'jwt_audience';
  -- (coalesce: without the claim both sides are NULL, and a token that names no audience is not for this one)
  IF v_want IS NOT NULL AND NOT coalesce(v_claims->>'aud' = v_want
       OR (jsonb_typeof(v_claims->'aud') = 'array' AND v_claims->'aud' ? v_want), false) THEN
    RAISE EXCEPTION 'token for another audience' USING ERRCODE = 'invalid_authorization_specification', HINT = 'rowstile help AZ703';
  END IF;
  v_user := v_claims->>coalesce((SELECT value FROM authz.settings WHERE key = 'jwt_user_claim'), 'sub');
  v_type := v_claims->>(SELECT value FROM authz.settings WHERE key = 'jwt_type_claim');
  IF coalesce(v_type, 'user') <> 'user' AND NOT EXISTS (SELECT 1 FROM authz_int.types WHERE name = v_type AND principal) THEN
    RAISE EXCEPTION 'the token names a type that does not sign in' USING ERRCODE = 'invalid_authorization_specification', HINT = 'rowstile help AZ703';
  END IF;
  PERFORM set_config('authz.user_id', coalesce(authz_int.canon(coalesce(v_type, 'user'), v_user), ''), true);
  PERFORM set_config('authz.principal_type', CASE WHEN coalesce(v_type, 'user') = 'user' THEN '' ELSE v_type END, true);
  PERFORM set_config('authz.acting_user', '', true);
  IF v_claims ? 'scope' THEN
    v_scopes := ARRAY(SELECT x FROM unnest(string_to_array(v_claims->>'scope', ' ')) x
                      WHERE EXISTS (SELECT 1 FROM authz_int.scope_items WHERE scope = x));
    PERFORM set_config('authz.scopes', CASE WHEN cardinality(v_scopes) = 0 THEN '(none)'
                                            ELSE array_to_string(v_scopes, ',') END, true);
  ELSE
    PERFORM set_config('authz.scopes', '', true);
  END IF;
  PERFORM authz_int.sign();
  IF NOT EXISTS (SELECT 1 FROM authz.principal()) THEN
    PERFORM set_config('authz.user_id', '', true);
    PERFORM set_config('authz.principal_type', '', true);
    RAISE EXCEPTION 'the token names no active user' USING ERRCODE = 'invalid_authorization_specification', HINT = 'rowstile help AZ703';
  END IF;
  PERFORM authz_int.jit_off();
  RETURN authz_int.actor();
END $f$;

-- Support staff see what a user sees, read-only, for this transaction, with a reason on record:
-- SELECT authz.view_as('42', 'ticket 1234'){"" if imp else "  (the user type has no impersonate permission: administrators only)"}
CREATE FUNCTION authz.view_as(p_user text, p_reason text) RETURNS void
LANGUAGE plpgsql {DEF} AS $f$
DECLARE v_me text := nullif(current_setting('authz.user_id', true), '');
        v_pt text := coalesce(current_setting('authz.principal_type', true), ''); v_actor text := authz_int.actor();
BEGIN
  IF coalesce(current_setting('authz.acting_user', true), '') <> '' THEN
    RAISE EXCEPTION 'already viewing as someone' USING ERRCODE = 'insufficient_privilege', HINT = 'rowstile help AZ704';
  END IF;
  IF coalesce(btrim(p_reason), '') = '' THEN
    RAISE EXCEPTION 'say why (the reason is kept in the audit trail)' USING ERRCODE = 'invalid_parameter_value', HINT = 'rowstile help AZ710';
  END IF;
  IF NOT (authz_int.caller_is_admin()
          {"OR (EXISTS (SELECT 1 FROM authz.principal()) AND authz.can(" + lit("user") + ", p_user, " + lit("impersonate") + "))" if imp else ""}) THEN
    RAISE EXCEPTION 'you cannot view as user %', p_user USING ERRCODE = 'insufficient_privilege', HINT = 'rowstile help AZ705';
  END IF;
  PERFORM set_config('authz.user_id', coalesce(authz_int.canon('user', p_user), ''), true);
  PERFORM set_config('authz.principal_type', '', true);
  PERFORM authz_int.sign();
  IF authz.uid() IS NULL THEN
    PERFORM set_config('authz.user_id', coalesce(v_me, ''), true);
    PERFORM set_config('authz.principal_type', v_pt, true);
    PERFORM authz_int.sign();
    RAISE EXCEPTION 'there is no active user %', p_user USING HINT = 'rowstile help AZ708';
  END IF;
  PERFORM set_config('authz.acting_user', coalesce(v_actor, authz_int.caller_role()), true);
  PERFORM set_config('authz.scopes', 'read', true);
  PERFORM authz_int.sign();
  PERFORM set_config('authz_ctx.reason', p_reason, true);
  PERFORM authz_int.jit_off();
  PERFORM authz_int.audit('view_as', 'user', authz_int.canon('user', p_user), NULL, NULL, NULL, NULL, NULL);
END $f$;

-- Replace a group's members with the list your identity provider sends (administrators, sync jobs):
-- SELECT * FROM authz.sync_members('team', '10', 'member', ARRAY['1', '2'])
CREATE FUNCTION authz.sync_members(p_type text, p_id text, p_relation text, p_members text[],
  OUT added int, OUT removed int)
LANGUAGE plpgsql {DEF} AS $f$
BEGIN
  CASE p_type || '.' || p_relation
{sync}
    ELSE RAISE EXCEPTION '%.% has no single table of members to sync (it needs one source: table(group -> user), without where)',
      p_type, p_relation USING HINT = 'rowstile help AZ707';
  END CASE;
  PERFORM authz_int.audit('sync_members', p_type, p_id, p_relation, 'user', NULL, NULL,
                          jsonb_build_object('added', added, 'removed', removed, 'members', p_members));
END $f$;"""

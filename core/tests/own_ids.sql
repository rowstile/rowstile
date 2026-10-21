-- own_ids.sql: every authz_gen view and function the app role may use, as each user, against "own ids": nothing it
-- reads or calls tells apart two objects that authz.can (every permission of the policy) and the rules (whether the
-- row shows) can't. Two ids with the same answers (the profile; an id no row has is one more) must be both in a view
-- or both out, and a function must answer the same for both (a row function: for the row of one with the other's
-- id, the row as stored, its flags flipped, and the user as its owner). Conditions that read other tables
-- (<type>__check_<hash>) are left out: they answer for any row (a known limit), and are listed.
-- psql -v users='1 2 3' -f tests/own_ids.sql   (as the tables' owner, on a policy whose keys are bigint; prints one
-- line per breach, then a summary) (tests/adversarial.sh)
\set ON_ERROR_STOP on
SET client_min_messages = warning;
\pset footer off
\pset tuples_only on
CREATE TEMP TABLE sw_types AS
  SELECT t.name AS type, t.tbl, t.pk, EXISTS (SELECT 1 FROM pg_policy p WHERE p.polrelid = t.tbl::regclass) AS governed
  FROM authz_int.types t;
CREATE TEMP TABLE sw_rows (type text, id text, r jsonb);
DO $o$
DECLARE t record;
BEGIN
  FOR t IN SELECT * FROM sw_types LOOP
    EXECUTE format('INSERT INTO sw_rows SELECT %L, x.%I::text, to_jsonb(x) FROM %s x', t.type, t.pk, t.tbl);
    -- an id no row has
    EXECUTE format('INSERT INTO sw_rows SELECT %L, (max(x.%I) + 1000)::text, NULL FROM %s x', t.type, t.pk, t.tbl);
  END LOOP;
END $o$;
CREATE TEMP TABLE sw_out (who text, what text);
CREATE TEMP TABLE sw_prof (type text, id text, prof text);
SELECT set_config('sw.users', :'users', false) \g /dev/null
-- one call, its answer as text, or the error it raised
CREATE FUNCTION pg_temp.sw_call(p_sql text, p_arg text) RETURNS text LANGUAGE plpgsql AS $c$
DECLARE r text;
BEGIN
  EXECUTE p_sql INTO r USING p_arg;
  RETURN coalesce(r, 'NULL');
EXCEPTION WHEN OTHERS THEN
  RETURN 'error: ' || SQLSTATE || ' ' || SQLERRM;
END $c$;
-- an answer with the object's own id left out (what explain and the refusals say of it name it)
CREATE FUNCTION pg_temp.sw_mask(p_text text, p_type text, p_id text) RETURNS text LANGUAGE sql AS
  $m$ SELECT regexp_replace(p_text, '(on|to) ' || p_type || ' ' || p_id || '\M', '\1 it', 'g') $m$;
GRANT SELECT ON sw_types, sw_rows TO app_user;
GRANT INSERT, SELECT, DELETE ON sw_out, sw_prof TO app_user;
SET ROLE app_user;
DO $s$
DECLARE
  u text; t record; v record; f record; x record; y record; got text; ref text; vrow jsonb;
  variants jsonb[]; call text;
BEGIN
  FOREACH u IN ARRAY string_to_array(current_setting('sw.users'), ' ') LOOP
    PERFORM set_config('authz.user_id', u, false);
    DELETE FROM sw_prof;
    FOR t IN SELECT * FROM sw_types WHERE governed LOOP
      -- what the API says of it: each permission held, and how (authz.explain, its own id left out)
      EXECUTE format('INSERT INTO sw_prof SELECT %L, s.id, array_to_string(ARRAY(SELECT p || '': '' || (SELECT string_agg(regexp_replace(l, ''(on|to) %s '' || s.id || ''\M'', ''\1 it''), '' / '')
                        FROM authz.explain(%L, s.id, p) l) FROM unnest(authz.perms(%L, s.id)) p ORDER BY p), '' | '')
                        || CASE WHEN EXISTS (SELECT 1 FROM %s z WHERE z.%I::text = s.id) THEN '' shown'' ELSE '''' END
                      FROM sw_rows s WHERE s.type = %L', t.type, t.type, t.type, t.type, t.tbl, t.pk, t.type);
    END LOOP;
    -- the views: both ids of a profile in, or both out
    FOR v IN SELECT c.relname, split_part(c.relname, '__', 1) AS type FROM pg_class c
             WHERE c.relnamespace = 'authz_gen'::regnamespace AND c.relkind = 'v'
               AND has_table_privilege(c.oid, 'SELECT') ORDER BY 1 LOOP
      CONTINUE WHEN NOT coalesce((SELECT governed FROM sw_types WHERE type = v.type), false);
      EXECUTE format('SELECT string_agg(DISTINCT a.id || '' and '' || b.id || '' ('' || a.prof || '')'', ''; '')
                      FROM sw_prof a JOIN sw_prof b ON a.type = b.type AND a.prof = b.prof AND a.id < b.id
                      WHERE a.type = %L
                        AND EXISTS (SELECT 1 FROM authz_gen.%I w WHERE w.id::text = a.id)
                            <> EXISTS (SELECT 1 FROM authz_gen.%I w WHERE w.id::text = b.id)', v.type, v.relname, v.relname)
        INTO got;
      IF got IS NOT NULL THEN
        INSERT INTO sw_out VALUES (u, format('view %s tells apart %s', v.relname, left(got, 300)));
      END IF;
      INSERT INTO sw_out VALUES (u, 'checked view ' || v.relname);
    END LOOP;
    -- the functions: the same answer for both ids of a profile
    FOR f IN SELECT p.oid, p.proname, p.oid::regprocedure::text AS sig, ARRAY(SELECT unnest(p.proargtypes::regtype[])) AS args, p.proretset
             FROM pg_proc p WHERE p.pronamespace = 'authz_gen'::regnamespace
               AND has_function_privilege(p.oid, 'EXECUTE') ORDER BY 2 LOOP
      CONTINUE WHEN f.proname LIKE '%:refuse';   -- (it raises what its :why says)
      IF f.proname ~ '__check_[0-9a-f]+$' THEN
        INSERT INTO sw_out VALUES (u, 'skipped ' || f.proname);
        CONTINUE;
      END IF;
      FOR t IN SELECT * FROM sw_types WHERE governed LOOP
        IF array_length(f.args, 1) = 1 AND f.proname LIKE t.type || '\_\_%' AND f.args[1]::text = (
             SELECT format_type(a.atttypid, NULL) FROM pg_attribute a WHERE a.attrelid = t.tbl::regclass AND a.attname = t.pk) THEN
          call := format('SELECT %s($1::%s)::text', f.oid::regproc, f.args[1]);
          FOR x IN SELECT a.id AS a, b.id AS b FROM sw_prof a JOIN sw_prof b ON a.type = b.type AND a.prof = b.prof AND a.id < b.id
                   WHERE a.type = t.type AND EXISTS (SELECT 1 FROM sw_rows r WHERE r.type = a.type AND r.id = a.id AND r.r IS NOT NULL)
                     AND EXISTS (SELECT 1 FROM sw_rows r WHERE r.type = b.type AND r.id = b.id AND r.r IS NOT NULL) LOOP
            got := pg_temp.sw_call(call, x.a); ref := pg_temp.sw_call(call, x.b);
            IF got <> ref THEN
              INSERT INTO sw_out VALUES (u, format('%s says %s for %s, %s for %s', f.sig, got, x.a, ref, x.b));
            END IF;
          END LOOP;
        ELSIF f.args[1]::oid = (SELECT c.reltype FROM pg_class c WHERE c.oid = t.tbl::regclass) THEN
          call := CASE WHEN array_length(f.args, 1) = 2   -- (row, stored)
                         THEN format('SELECT string_agg(l, '' / '') FROM %s(jsonb_populate_record(NULL::%s, $1::jsonb), true) l', f.oid::regproc, t.tbl)
                       WHEN f.proretset
                         THEN format('SELECT string_agg(l, '' / '') FROM %s(jsonb_populate_record(NULL::%s, $1::jsonb)) l', f.oid::regproc, t.tbl)
                       ELSE format('SELECT %s(jsonb_populate_record(NULL::%s, $1::jsonb))::text', f.oid::regproc, t.tbl) END;
          FOR x IN SELECT s.id, s.r, pa.prof FROM sw_rows s JOIN sw_prof pa ON pa.type = s.type AND pa.id = s.id
                   WHERE s.type = t.type AND s.r IS NOT NULL LOOP
            vrow := x.r;
            variants := ARRAY[vrow,
              (SELECT jsonb_object_agg(k, CASE WHEN jsonb_typeof(val) = 'boolean' THEN to_jsonb(NOT val::text::boolean) ELSE val END)
               FROM jsonb_each(vrow) e(k, val)),
              CASE WHEN vrow ? 'owner_id' THEN vrow || jsonb_build_object('owner_id', u::bigint) ELSE vrow END];
            -- (stored rows only: whether a row with an id exists is told by inserting one, a known limit, and the
            -- write rules' functions answer for a new row)
            FOR y IN SELECT b.id FROM sw_prof b JOIN sw_rows r ON r.type = b.type AND r.id = b.id AND r.r IS NOT NULL
                     WHERE b.type = t.type AND b.prof = x.prof AND b.id <> x.id LOOP
              FOR i IN 1 .. array_length(variants, 1) LOOP
                got := pg_temp.sw_mask(pg_temp.sw_mask(pg_temp.sw_call(call, variants[i]::text), t.type, x.id), t.type, y.id);
                ref := pg_temp.sw_mask(pg_temp.sw_mask(pg_temp.sw_call(call, (variants[i] || jsonb_build_object(t.pk, y.id::bigint))::text), t.type, y.id), t.type, x.id);
                IF got <> ref THEN
                  INSERT INTO sw_out VALUES (u, format('%s on row %s (variant %s) says %s; with id %s: %s',
                                                       f.proname, x.id, i, left(got, 200), y.id, left(ref, 200)));
                END IF;
              END LOOP;
            END LOOP;
          END LOOP;
        END IF;
      END LOOP;
      INSERT INTO sw_out VALUES (u, 'checked function ' || f.proname);
    END LOOP;
  END LOOP;
END $s$;
RESET ROLE;
SELECT 'BREACH user ' || who || ': ' || what FROM sw_out WHERE what NOT LIKE 'checked %' AND what NOT LIKE 'skipped %' ORDER BY 1;
SELECT 'checked ' || count(*) FILTER (WHERE what LIKE 'checked view%') / greatest(count(DISTINCT who), 1) || ' views, '
       || count(*) FILTER (WHERE what LIKE 'checked function%') / greatest(count(DISTINCT who), 1) || ' functions; '
       || count(*) FILTER (WHERE what NOT LIKE 'checked %' AND what NOT LIKE 'skipped %') || ' breaches; skipped: '
       || coalesce(string_agg(DISTINCT substr(what, 9), ' ') FILTER (WHERE what LIKE 'skipped %'), 'none')
FROM sw_out;
SELECT 'readable: ' || string_agg(c.relname, ' ' ORDER BY c.relname) FROM pg_class c
  WHERE c.relnamespace = 'authz_gen'::regnamespace AND c.relkind IN ('r', 'v') AND has_table_privilege('app_user', c.oid, 'SELECT');
SELECT 'callable: ' || string_agg(p.proname, ' ' ORDER BY p.proname) FROM pg_proc p
  WHERE p.pronamespace = 'authz_gen'::regnamespace AND has_function_privilege('app_user', p.oid, 'EXECUTE')
    AND p.proname !~ '^[a-z0-9_]+\.[a-z0-9_]+:';

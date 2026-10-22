-- catalog.sql: what rowstile made in authz, authz_gen and authz_int, against the rules (tests/adversarial.sh).
--   psql -At -v role=<app role> -v api='<the GRANT EXECUTE list, one signature per |>' \
--     -v views='<the relations GRANT SELECT names: policy_lines, the views the rules read; one per |>' -f tests/catalog.sql
-- Prints one line per object that breaks a rule, nothing when all hold.
WITH o AS (SELECT nspowner AS owner FROM pg_namespace WHERE nspname = 'authz_int'),
fns AS (SELECT p.oid, p.oid::regprocedure::text AS name, n.nspname AS nsp, p.proowner, p.prosecdef, p.proconfig,
               p.proleakproof, p.proacl, p.proparallel
        FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname IN ('authz', 'authz_gen', 'authz_int')),
rels AS (SELECT c.oid, c.oid::regclass::text AS name, n.nspname AS nsp, c.relowner, c.relacl
         FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname IN ('authz', 'authz_gen', 'authz_int') AND c.relkind IN ('r', 'v', 'm', 'S', 'p', 'f')),
api AS (SELECT x::regprocedure AS oid FROM unnest(string_to_array(:'api', '|')) x),
-- what the app role may read: policy_lines, and the views its rules look up (in authz_int: only its rules can name them)
views AS (SELECT x::regclass AS oid FROM unnest(string_to_array(:'views', '|')) x),
-- the path applying gave the functions that run the policy's own SQL (SET search_path FROM CURRENT): the schemas on
-- the owner's path, then pg_temp, as this session (the owner's, as applying's) has it
path AS (SELECT 'search_path=' || concat_ws(', ', (SELECT string_agg(quote_ident(s.name), ', ' ORDER BY s.i)
                                                    FROM unnest(current_schemas(false)) WITH ORDINALITY s(name, i)
                                                    WHERE s.name !~ '^pg_temp_'), 'pg_temp') AS c)
SELECT problem || ': ' || name FROM (
  SELECT 'a definer function without its own search_path' AS problem, name FROM fns
    WHERE prosecdef AND NOT EXISTS (SELECT 1 FROM unnest(proconfig) c WHERE c LIKE 'search_path=%')
  -- "$user" in a captured search path is a schema anyone allowed to create schemas could make later
  UNION ALL SELECT 'its search_path names "$user"', name FROM fns
    WHERE EXISTS (SELECT 1 FROM unnest(proconfig) c WHERE c LIKE 'search_path=%$user%')
  -- and it is pg_catalog's alone, or the policy's path: any other may hold a schema others create functions in
  UNION ALL SELECT 'its search_path is ' || substr(c, 13) || ', not pg_catalog''s nor the policy''s', name FROM fns, unnest(proconfig) c
    WHERE prosecdef AND c LIKE 'search_path=%' AND c <> 'search_path=pg_catalog, pg_temp' AND c <> (SELECT c FROM path)
  UNION ALL SELECT 'owned by ' || proowner::regrole, name FROM fns WHERE proowner <> (SELECT owner FROM o)
  UNION ALL SELECT 'leakproof', name FROM fns WHERE proleakproof
  -- a session's signature is bound to its backend, which a parallel worker isn't: reads through the rules run in
  -- one process (docs/reference/limits.md)
  UNION ALL SELECT CASE proparallel WHEN 's' THEN 'parallel safe' ELSE 'parallel restricted' END, name FROM fns
    WHERE proparallel <> 'u'
  -- authz_int's functions keep PUBLIC's EXECUTE (the authz_gen views call them as the app role); no USAGE on the schema
  UNION ALL SELECT 'PUBLIC may execute', name FROM fns
    WHERE nsp <> 'authz_int' AND (proacl IS NULL OR EXISTS (SELECT 1 FROM aclexplode(proacl) a WHERE a.grantee = 0))
  UNION ALL SELECT 'executable by ' || a.grantee::regrole, name FROM fns, aclexplode(proacl) a
    WHERE a.grantee NOT IN (0, proowner, :'role'::regrole)
  UNION ALL SELECT 'the app role may execute it, but it is not in the API', name FROM fns
    WHERE nsp = 'authz' AND has_function_privilege(:'role', oid, 'EXECUTE') AND oid NOT IN (SELECT oid FROM api)
  -- in authz_gen: the rules' own functions (refusals, explanations), named <table>:<what>; what the rules look up
  -- is in authz_int, which the app role can't name
  UNION ALL SELECT 'the app role may execute it, but it is not a rule''s', name FROM fns
    WHERE nsp = 'authz_gen' AND has_function_privilege(:'role', oid, 'EXECUTE') AND name !~ '^authz_gen\."[^"]*:'
  UNION ALL SELECT 'in the API, but the app role may not execute it', a.oid::text FROM api a
    WHERE NOT has_function_privilege(:'role', a.oid, 'EXECUTE')
  UNION ALL SELECT 'owned by ' || relowner::regrole, name FROM rels WHERE relowner <> (SELECT owner FROM o)
  UNION ALL SELECT a.privilege_type || ' to ' || CASE a.grantee WHEN 0 THEN 'PUBLIC' ELSE a.grantee::regrole::text END, name
    FROM rels, aclexplode(relacl) a
    WHERE a.grantee <> relowner AND NOT (a.grantee = :'role'::regrole AND a.privilege_type = 'SELECT'
                                         AND oid IN (SELECT oid FROM views))
  UNION ALL SELECT 'its rules read it, but the app role may not', v.oid::regclass::text FROM views v
    WHERE NOT has_table_privilege(:'role', v.oid, 'SELECT')
  UNION ALL SELECT 'column ' || att.attname || ': ' || a.privilege_type || ' to ' || a.grantee::regrole, r.name
    FROM rels r JOIN pg_attribute att ON att.attrelid = r.oid, aclexplode(att.attacl) a
  UNION ALL SELECT a.privilege_type || ' to ' || CASE a.grantee WHEN 0 THEN 'PUBLIC' ELSE a.grantee::regrole::text END, n.nspname
    FROM pg_namespace n, aclexplode(n.nspacl) a
    WHERE n.nspname IN ('authz', 'authz_gen', 'authz_int') AND a.grantee <> n.nspowner
      AND NOT (n.nspname IN ('authz', 'authz_gen') AND a.grantee = :'role'::regrole AND a.privilege_type = 'USAGE')
) p ORDER BY 1;

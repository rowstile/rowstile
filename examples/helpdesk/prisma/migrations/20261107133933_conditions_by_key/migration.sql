-- The conditions the policy calls on a share being made look the person up by their key, so an index answers,
-- not a scan of every user: a person's id that isn't a uuid is no one (false), as before.
CREATE OR REPLACE FUNCTION "hd"."same_workspace"(ticket uuid, person text) RETURNS boolean LANGUAGE sql STABLE AS $$
  SELECT EXISTS (SELECT 1 FROM hd.tickets t JOIN hd.users u ON u.workspace_id = t.workspace_id
                 WHERE t.id = ticket
                   AND u.id = CASE WHEN person ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
                                   THEN person::uuid END)
$$;
CREATE OR REPLACE FUNCTION "hd"."is_staff"(person text) RETURNS boolean LANGUAGE sql STABLE AS $$
  SELECT EXISTS (SELECT 1 FROM hd.users u
                 WHERE u.id = CASE WHEN person ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
                                   THEN person::uuid END
                   AND u.kind = 'staff')
$$;

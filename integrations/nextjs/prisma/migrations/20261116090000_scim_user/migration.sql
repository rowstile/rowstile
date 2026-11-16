-- What an identity provider's users become: the function the SCIM settings name (authz.set_scim, user_function).
-- p_id NULL: a user to make; p_resource NULL: one to delete; else one to change. It answers the user's key.
-- rowstile calls it as the tables' owner, whose own it is: the app role has no right to write app.users

-- the keys of the users it makes
CREATE SEQUENCE "app"."provisioned_user_ids" AS integer START 1000;

CREATE FUNCTION "app"."scim_user"(p_id text, p_resource jsonb) RETURNS text LANGUAGE plpgsql AS $f$
DECLARE v_id text;
BEGIN
  IF p_resource IS NULL THEN
    DELETE FROM "app"."users" WHERE id = p_id::integer;
    RETURN p_id;
  ELSIF p_id IS NULL THEN
    INSERT INTO "app"."users" (id, name) VALUES (nextval('app.provisioned_user_ids'), p_resource->>'userName')
      RETURNING id::text INTO v_id;
  ELSE
    UPDATE "app"."users" SET name = p_resource->>'userName' WHERE id = p_id::integer RETURNING id::text INTO v_id;
  END IF;
  RETURN v_id;
END $f$;

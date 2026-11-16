-- What an identity provider's users become (SCIM): what the app keeps of one, and the function the endpoint's
-- settings name (authz.set_scim, user_function).

-- an email, whether the provider says the user is active, and the user as the provider wrote it
ALTER TABLE "app"."users" ADD COLUMN "email" TEXT,
  ADD COLUMN "active" BOOLEAN NOT NULL DEFAULT true,
  ADD COLUMN "scim" JSONB;

-- the keys of the users it makes
CREATE SEQUENCE "app"."provisioned_user_ids" AS integer START 1000;

-- p_id NULL: a user to make; p_resource NULL: one to delete; else one to change. It answers the user's key.
-- rowstile calls it as the tables' owner, whose own it is: the app role has no right to write app.users
CREATE FUNCTION "app"."scim_user"(p_id text, p_resource jsonb) RETURNS text LANGUAGE plpgsql AS $f$
DECLARE v_id text;
BEGIN
  IF p_resource IS NULL THEN
    DELETE FROM "app"."users" WHERE id = p_id::integer;
    RETURN p_id;
  ELSIF p_id IS NULL THEN
    INSERT INTO "app"."users" (id, name, email, active, scim)
    VALUES (nextval('app.provisioned_user_ids'), p_resource->>'userName', p_resource#>>'{emails,0,value}',
            coalesce((p_resource->>'active')::boolean, true), p_resource)
    RETURNING id::text INTO v_id;
  ELSE
    -- a user changed: what the provider says nothing of stays as the app had it
    UPDATE "app"."users" SET name = p_resource->>'userName', scim = p_resource,
      email = coalesce(p_resource#>>'{emails,0,value}', email),
      active = coalesce((p_resource->>'active')::boolean, active)
    WHERE id = p_id::integer RETURNING id::text INTO v_id;
  END IF;
  RETURN v_id;
END $f$;

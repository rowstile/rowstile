-- 0001: the file manager's tables. Run by db/migrate.py as the database owner, in one transaction.
CREATE SCHEMA fm;

CREATE TABLE fm.users (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email       text NOT NULL UNIQUE CHECK (email = lower(email)),
  name        text NOT NULL,
  is_support  boolean NOT NULL DEFAULT false,
  created_at  timestamptz NOT NULL DEFAULT now(),
  quota_bytes bigint NOT NULL DEFAULT 5368709120);   -- 5 GiB
-- kept apart from users, whom everyone signed in may look up (to share with them)
CREATE TABLE fm.credentials (
  user_id       uuid PRIMARY KEY REFERENCES fm.users ON DELETE CASCADE,
  password_hash text NOT NULL);
CREATE TABLE fm.sessions (
  token_hash text PRIMARY KEY,
  user_id    uuid NOT NULL REFERENCES fm.users ON DELETE CASCADE,
  expires_at timestamptz NOT NULL);
CREATE INDEX ON fm.sessions (user_id);

-- groups: whoever creates one owns it; owners and admins manage its members and sub-groups
CREATE TABLE fm.groups (
  id        uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name      text NOT NULL,
  parent_id uuid REFERENCES fm.groups,
  owner_id  uuid REFERENCES fm.users);
-- deleting a group doesn't delete its members by itself. The app removes them first, through the rules
-- (main.py, delete_group), and a foreign key's action would skip them: rowstile warns of one on a governed table.
CREATE TABLE fm.group_members (
  group_id uuid NOT NULL REFERENCES fm.groups ON DELETE RESTRICT,
  user_id  uuid NOT NULL REFERENCES fm.users ON DELETE CASCADE,
  id       bigserial UNIQUE,
  is_admin boolean NOT NULL DEFAULT false,
  PRIMARY KEY (group_id, user_id));
CREATE INDEX ON fm.group_members (user_id);
CREATE INDEX ON fm.groups (parent_id);
CREATE INDEX ON fm.groups (owner_id);   -- the index authz.lint() asks for (group.owner: the groups a person owns)

CREATE TABLE fm.folders (
  id         bigserial PRIMARY KEY,
  parent_id  bigint REFERENCES fm.folders ON UPDATE CASCADE,   -- empty a folder before deleting it
  owner_id   uuid NOT NULL REFERENCES fm.users,
  name       text NOT NULL CHECK (name <> '' AND strpos(name, '/') = 0),
  inherit    boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (parent_id, name));
CREATE INDEX ON fm.folders (parent_id);
CREATE INDEX ON fm.folders (owner_id);

CREATE TABLE fm.files (
  id           bigserial PRIMARY KEY,
  folder_id    bigint NOT NULL REFERENCES fm.folders ON UPDATE CASCADE,
  owner_id     uuid NOT NULL REFERENCES fm.users,
  name         text NOT NULL CHECK (name <> '' AND strpos(name, '/') = 0),
  size         bigint NOT NULL DEFAULT 0,
  content_type text NOT NULL DEFAULT 'application/octet-stream',
  object_key   uuid NOT NULL UNIQUE DEFAULT gen_random_uuid(),   -- the object in the bucket
  created_at   timestamptz NOT NULL DEFAULT now(),
  updated_at   timestamptz NOT NULL DEFAULT now(),
  -- a file uploaded straight from the browser to RustFS exists as a row first, ready once the bytes are there
  ready        boolean NOT NULL DEFAULT true,
  UNIQUE (folder_id, name));
CREATE INDEX ON fm.files (owner_id);

-- Every stored object is a version of a file; the file row points at its current one. Old versions
-- stay until the file is deleted, and can be made current again.
CREATE TABLE fm.file_versions (
  id           bigserial PRIMARY KEY,
  file_id      bigint NOT NULL REFERENCES fm.files ON UPDATE CASCADE,   -- delete a file's versions first
  object_key   uuid NOT NULL UNIQUE DEFAULT gen_random_uuid(),
  size         bigint NOT NULL DEFAULT 0,
  content_type text NOT NULL DEFAULT 'application/octet-stream',
  ready        boolean NOT NULL DEFAULT false,
  created_by   uuid NOT NULL REFERENCES fm.users,
  created_at   timestamptz NOT NULL DEFAULT now());
CREATE INDEX ON fm.file_versions (file_id);
CREATE INDEX ON fm.file_versions (created_by);

-- search: names containing what was typed
CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE INDEX files_name_trgm ON fm.files USING gin (name gin_trgm_ops);
CREATE INDEX folders_name_trgm ON fm.folders USING gin (name gin_trgm_ops);

-- the app's role: row-level security applies to it (db/policy.authz); it signs people in itself
GRANT USAGE ON SCHEMA fm TO fm_app;
GRANT SELECT ON fm.users TO fm_app;
GRANT SELECT ON fm.credentials TO fm_app;
GRANT SELECT, INSERT, DELETE ON fm.sessions TO fm_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON fm.groups, fm.group_members TO fm_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON fm.folders, fm.files, fm.file_versions TO fm_app;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA fm TO fm_app;

-- creating an account: the app role may read accounts but not write them, except through this
CREATE FUNCTION fm.sign_up(p_email text, p_name text, p_password_hash text)
RETURNS TABLE (id uuid, email text, name text, is_support boolean)
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  WITH u AS (INSERT INTO fm.users (email, name) VALUES (lower(p_email), p_name) RETURNING *),
       c AS (INSERT INTO fm.credentials (user_id, password_hash) SELECT u.id, p_password_hash FROM u)
  SELECT u.id, u.email, u.name, u.is_support FROM u $$;
REVOKE ALL ON FUNCTION fm.sign_up(text, text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION fm.sign_up(text, text, text) TO fm_app;

-- Quotas: what a person has uploaded (every version counts) may not exceed their quota.

-- bytes stored for a user, whatever they may see now (so it runs as the owner)
CREATE FUNCTION fm.usage(p_user uuid) RETURNS bigint
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT coalesce(sum(v.size), 0)::bigint FROM fm.file_versions v WHERE v.created_by = p_user $$;
-- the app role asks only about the user signed in
-- (plpgsql: authz.uid() comes with the policy, whose migration, 0002, runs after this one)
CREATE FUNCTION fm.my_usage() RETURNS TABLE (used bigint, quota bigint)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  RETURN QUERY SELECT fm.usage(u.id), u.quota_bytes FROM fm.users u WHERE u.id = authz.uid();
END $$;
REVOKE ALL ON FUNCTION fm.usage(uuid), fm.my_usage() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION fm.my_usage() TO fm_app;

-- The quota holds for uploads that commit at the same time: the check takes the person's row first, so the
-- second upload waits for the first to end, then counts it. (FOR NO KEY UPDATE: rows that refer to the person,
-- a new folder say, don't wait for it.)
CREATE FUNCTION fm.check_quota() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE v_used bigint; v_quota bigint;
BEGIN
  SELECT u.quota_bytes INTO v_quota FROM fm.users u WHERE u.id = NEW.created_by FOR NO KEY UPDATE;
  v_used := fm.usage(NEW.created_by) - CASE WHEN TG_OP = 'UPDATE' THEN OLD.size ELSE 0 END + NEW.size;
  IF v_used > v_quota THEN
    RAISE EXCEPTION 'storage quota exceeded: % of % bytes', v_used, v_quota USING ERRCODE = 'program_limit_exceeded';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER fm_quota BEFORE INSERT OR UPDATE OF size ON fm.file_versions
  FOR EACH ROW EXECUTE FUNCTION fm.check_quota();

-- a new file points at a new object, never at one that already belongs to a file (checked by the policy)
CREATE FUNCTION fm.key_is_new(p_key uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT NOT EXISTS (SELECT 1 FROM fm.file_versions v WHERE v.object_key = p_key) $$;
REVOKE ALL ON FUNCTION fm.key_is_new(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION fm.key_is_new(uuid) TO fm_app;

-- 0004: file versions and storage quotas.

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
-- the files already there: their content is their first version
INSERT INTO fm.file_versions (file_id, object_key, size, content_type, ready, created_by, created_at)
SELECT id, object_key, size, content_type, ready, owner_id, created_at FROM fm.files;
GRANT SELECT, INSERT, UPDATE, DELETE ON fm.file_versions TO fm_app;
GRANT USAGE ON SEQUENCE fm.file_versions_id_seq TO fm_app;

-- Quotas: what a person has uploaded (every version counts) may not exceed their quota.
ALTER TABLE fm.users ADD COLUMN quota_bytes bigint NOT NULL DEFAULT 5368709120;   -- 5 GiB

-- bytes stored for a user, whatever they may see now (so it runs as the owner)
CREATE FUNCTION fm.usage(p_user uuid) RETURNS bigint
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT coalesce(sum(v.size), 0)::bigint FROM fm.file_versions v WHERE v.created_by = p_user $$;
-- the app role asks only about the user signed in
-- (plpgsql: authz.uid() comes with the policy, whose first migration, 0005, runs after this one)
CREATE FUNCTION fm.my_usage() RETURNS TABLE (used bigint, quota bigint)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  RETURN QUERY SELECT fm.usage(u.id), u.quota_bytes FROM fm.users u WHERE u.id = authz.uid();
END $$;
REVOKE ALL ON FUNCTION fm.usage(uuid), fm.my_usage() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION fm.my_usage() TO fm_app;

CREATE FUNCTION fm.check_quota() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE v_used bigint; v_quota bigint;
BEGIN
  SELECT u.quota_bytes INTO v_quota FROM fm.users u WHERE u.id = NEW.created_by;
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

-- 0071: the storage quota holds for uploads that commit at the same time. Each one counted what the person had
-- stored without the other's new version, so both could pass. Now the check takes the person's row first: the
-- second upload waits for the first to end, then counts it. (FOR NO KEY UPDATE: rows that refer to the person,
-- a new folder say, don't wait for it.)
CREATE OR REPLACE FUNCTION fm.check_quota() RETURNS trigger
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

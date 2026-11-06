-- The role that owns the app's tables and applies the policy: db/migrate.py, the maintenance jobs, rowstile dev and
-- rowstile test run as it, never as the superuser (rowstile needs none). CREATEROLE lets migrate.py make the app
-- role, fm_app. The Postgres image runs this once, as its superuser, when it makes the database
-- (docker-compose.yml mounts it into /docker-entrypoint-initdb.d); elsewhere, run it the same way.
CREATE ROLE fm_owner LOGIN CREATEROLE PASSWORD 'fm_owner';
DO $$ BEGIN EXECUTE format('ALTER DATABASE %I OWNER TO fm_owner', current_database()); END $$;

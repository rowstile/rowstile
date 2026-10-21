-- The role that owns the app's tables and applies the policy: db/migrate.py, rowstile dev and rowstile test run as
-- it, never as the superuser (rowstile needs none). CREATEROLE lets migrate.py make the app role, ms_app. The Postgres
-- image runs this once, as its superuser, when it makes the database (docker-compose.yml mounts it into
-- /docker-entrypoint-initdb.d); elsewhere, run it the same way.
CREATE ROLE ms_owner LOGIN CREATEROLE PASSWORD 'ms_owner';
DO $$ BEGIN EXECUTE format('ALTER DATABASE %I OWNER TO ms_owner', current_database()); END $$;

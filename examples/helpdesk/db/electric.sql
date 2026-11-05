-- Electric's role: made once by whoever runs the database, as a superuser (or the managed service's admin). It
-- reads the synced tables by logical replication, where row-level security doesn't run, so it holds REPLICATION
-- and BYPASSRLS; it owns no table. test.sh and docker-compose.yml run this before the migrations.
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'hd_electric') THEN
    CREATE ROLE hd_electric LOGIN REPLICATION BYPASSRLS PASSWORD 'hd_electric';
  END IF;
END $$;

-- Blocking (docs/cookbook/blocking.md): direct messages, and people who blocked someone.
CREATE SCHEMA app;
CREATE TABLE app.users (id bigint PRIMARY KEY, name text NOT NULL);
CREATE TABLE app.blocks (blocker_id bigint NOT NULL REFERENCES app.users, blocked_id bigint NOT NULL REFERENCES app.users,
                         PRIMARY KEY (blocker_id, blocked_id));
CREATE INDEX ON app.blocks (blocked_id);
CREATE TABLE app.direct_messages (id bigserial PRIMARY KEY, from_id bigint NOT NULL REFERENCES app.users,
                                  to_id bigint NOT NULL REFERENCES app.users, body text);
CREATE INDEX ON app.direct_messages (from_id);
CREATE INDEX ON app.direct_messages (to_id);

-- the role the app connects as: no superuser, and row-level security applies to it
DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'app_user') THEN
    CREATE ROLE app_user NOSUPERUSER NOBYPASSRLS;
  END IF;
END $$;
GRANT USAGE ON SCHEMA app TO app_user;
GRANT SELECT ON app.users, app.direct_messages TO app_user;   -- not app.blocks: nobody reads the table
GRANT INSERT ON app.direct_messages TO app_user;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA app TO app_user;

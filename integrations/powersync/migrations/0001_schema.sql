-- The app's tables, the role the app connects as, and what PowerSync's role may read. PowerSync's role itself
-- (conf_ps: LOGIN REPLICATION BYPASSRLS) is made by whoever runs the database, as a superuser or the
-- service's admin: a role that may make roles may give neither REPLICATION nor BYPASSRLS without holding them.
CREATE SCHEMA app;

CREATE TABLE app.users (
  id   integer PRIMARY KEY,
  name text NOT NULL
);

CREATE TABLE app.teams (
  id        integer PRIMARY KEY,
  parent_id integer REFERENCES app.teams,
  name      text NOT NULL
);
CREATE INDEX ON app.teams (parent_id);

CREATE TABLE app.team_members (
  team_id integer NOT NULL REFERENCES app.teams ON DELETE CASCADE,
  user_id integer NOT NULL REFERENCES app.users ON DELETE CASCADE,
  PRIMARY KEY (team_id, user_id)
);
CREATE INDEX ON app.team_members (user_id);

CREATE TABLE app.folders (
  id        integer PRIMARY KEY,
  parent_id integer REFERENCES app.folders,
  owner_id  integer NOT NULL REFERENCES app.users,
  name      text NOT NULL
);
CREATE INDEX ON app.folders (parent_id);
CREATE INDEX ON app.folders (owner_id);

CREATE TABLE app.folder_teams (
  folder_id integer NOT NULL REFERENCES app.folders ON DELETE CASCADE,
  team_id   integer NOT NULL REFERENCES app.teams ON DELETE CASCADE,
  PRIMARY KEY (folder_id, team_id)
);
CREATE INDEX ON app.folder_teams (team_id);

CREATE TABLE app.files (
  id           integer PRIMARY KEY,
  folder_id    integer NOT NULL REFERENCES app.folders,
  owner_id     integer NOT NULL REFERENCES app.users,
  name         text NOT NULL,
  confidential boolean NOT NULL DEFAULT false
);
CREATE INDEX ON app.files (folder_id);
CREATE INDEX ON app.files (owner_id);

CREATE TABLE app.notes (
  id        integer PRIMARY KEY,
  file_id   integer NOT NULL REFERENCES app.files,
  author_id integer NOT NULL REFERENCES app.users,
  body      text NOT NULL
);
CREATE INDEX ON app.notes (file_id);
CREATE INDEX ON app.notes (author_id);

-- PowerSync reads the mirrors, not these tables: they keep their default replica identity, and PowerSync's
-- role reads none of them (a mirror holds what PowerSync syncs, but the masked columns)

-- the role the app connects as: not the owner, so row-level security applies to it
DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'conf_app') THEN
    CREATE ROLE conf_app LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD 'app';
  END IF;
END $$;
GRANT USAGE ON SCHEMA app TO conf_app;
GRANT SELECT ON ALL TABLES IN SCHEMA app TO conf_app;
GRANT INSERT, UPDATE ON app.files TO conf_app;
GRANT UPDATE ON app.folders TO conf_app;

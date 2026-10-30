-- The app's tables, and the role it connects as (written by hand: Flyway runs it as the tables' owner). A role
-- belongs to the whole server: it is made only where it is missing.
CREATE SCHEMA app;

CREATE TABLE app.users (
  id   bigint PRIMARY KEY,
  name text NOT NULL
);

CREATE TABLE app.services (
  id   bigint PRIMARY KEY,
  name text NOT NULL
);

CREATE TABLE app.projects (
  id       bigint PRIMARY KEY,
  owner_id bigint NOT NULL REFERENCES app.users,
  name     text NOT NULL,
  public   boolean NOT NULL DEFAULT false
);

CREATE TABLE app.members (
  project_id bigint REFERENCES app.projects,
  user_id    bigint REFERENCES app.users,
  PRIMARY KEY (project_id, user_id)
);
CREATE INDEX ON app.members (user_id);

CREATE TABLE app.project_services (
  project_id bigint REFERENCES app.projects,
  service_id bigint REFERENCES app.services,
  PRIMARY KEY (project_id, service_id)
);
CREATE INDEX ON app.project_services (service_id);

CREATE TABLE app.notes (
  id         bigserial PRIMARY KEY,
  project_id bigint NOT NULL REFERENCES app.projects,
  author_id  bigint NOT NULL REFERENCES app.users,
  body       text NOT NULL
);
CREATE INDEX ON app.notes (project_id);
CREATE INDEX ON app.notes (author_id);

CREATE TABLE app.inbox (
  id           bigserial PRIMARY KEY,
  sender_id    bigint NOT NULL REFERENCES app.users,
  recipient_id bigint NOT NULL REFERENCES app.users,
  body         text NOT NULL
);
CREATE INDEX ON app.inbox (sender_id);
CREATE INDEX ON app.inbox (recipient_id);

CREATE TABLE app.folders (
  id        bigint PRIMARY KEY,
  parent_id bigint REFERENCES app.folders,
  owner_id  bigint NOT NULL REFERENCES app.users,
  name      text NOT NULL
);
CREATE INDEX ON app.folders (parent_id);
CREATE INDEX ON app.folders (owner_id);

DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'conf_app') THEN
    CREATE ROLE conf_app LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD 'app';
  END IF;
END $$;
GRANT USAGE ON SCHEMA app TO conf_app;
GRANT SELECT ON ALL TABLES IN SCHEMA app TO conf_app;
GRANT INSERT, UPDATE, DELETE ON app.notes, app.inbox TO conf_app;
GRANT UPDATE ON app.folders TO conf_app;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA app TO conf_app;

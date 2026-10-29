# frozen_string_literal: true

# The app's tables: projects with members, notes in them (with a lock_version: Rails' optimistic locking), a
# service that reads projects, an inbox people can write to but only the recipient reads, and folders inside
# folders. And the role the app connects as.
class Schema < ActiveRecord::Migration[8.0]
  def up
    execute <<~SQL
      CREATE SCHEMA app;
      CREATE TABLE app.users (id bigint PRIMARY KEY, name text NOT NULL);
      CREATE TABLE app.services (id bigint PRIMARY KEY, name text NOT NULL);
      CREATE TABLE app.projects (
        id bigint PRIMARY KEY, owner_id bigint NOT NULL REFERENCES app.users, name text NOT NULL,
        public boolean NOT NULL DEFAULT false);
      CREATE TABLE app.members (
        project_id bigint REFERENCES app.projects, user_id bigint REFERENCES app.users,
        PRIMARY KEY (project_id, user_id));
      CREATE INDEX ON app.members (user_id);
      CREATE TABLE app.project_services (
        project_id bigint REFERENCES app.projects, service_id bigint REFERENCES app.services,
        PRIMARY KEY (project_id, service_id));
      CREATE INDEX ON app.project_services (service_id);
      CREATE TABLE app.notes (
        id bigserial PRIMARY KEY, project_id bigint NOT NULL REFERENCES app.projects,
        author_id bigint NOT NULL REFERENCES app.users, body text NOT NULL,
        lock_version integer NOT NULL DEFAULT 0);
      CREATE INDEX ON app.notes (project_id);
      CREATE INDEX ON app.notes (author_id);
      CREATE TABLE app.inbox (
        id bigserial PRIMARY KEY, sender_id bigint NOT NULL REFERENCES app.users,
        recipient_id bigint NOT NULL REFERENCES app.users, body text NOT NULL);
      CREATE INDEX ON app.inbox (sender_id);
      CREATE INDEX ON app.inbox (recipient_id);
      CREATE TABLE app.folders (
        id bigint PRIMARY KEY, parent_id bigint REFERENCES app.folders,
        owner_id bigint NOT NULL REFERENCES app.users, name text NOT NULL);
      CREATE INDEX ON app.folders (parent_id);
      CREATE INDEX ON app.folders (owner_id);
    SQL
    password = connection.quote(ENV.fetch("CONF_APP_PASSWORD", "app"))
    execute <<~SQL
      DO $$ BEGIN
        IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'conf_app') THEN
          CREATE ROLE conf_app LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD #{password};
        END IF;
      END $$;
      GRANT USAGE ON SCHEMA app TO conf_app;
      GRANT SELECT ON ALL TABLES IN SCHEMA app TO conf_app;
      GRANT INSERT, UPDATE, DELETE ON app.notes, app.inbox TO conf_app;
      GRANT UPDATE ON app.folders TO conf_app;
      GRANT USAGE ON ALL SEQUENCES IN SCHEMA app TO conf_app;
    SQL
  end

  def down
    execute "DROP SCHEMA app CASCADE"
  end
end

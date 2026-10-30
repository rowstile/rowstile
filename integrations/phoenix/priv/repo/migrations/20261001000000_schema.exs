defmodule Conformance.Repo.Migrations.Schema do
  # The app's tables: projects with members, notes in them (with a lock_version: Ecto's optimistic lock), a service
  # that reads projects, an inbox people can write to but only the recipient reads, and folders inside folders. And
  # the role the app connects as.
  @moduledoc false
  use Ecto.Migration

  def up do
    execute "CREATE SCHEMA app"
    execute "CREATE TABLE app.users (id bigint PRIMARY KEY, name text NOT NULL)"
    execute "CREATE TABLE app.services (id bigint PRIMARY KEY, name text NOT NULL)"

    execute """
    CREATE TABLE app.projects (
      id bigint PRIMARY KEY, owner_id bigint NOT NULL REFERENCES app.users, name text NOT NULL,
      public boolean NOT NULL DEFAULT false)
    """

    execute """
    CREATE TABLE app.members (
      project_id bigint REFERENCES app.projects, user_id bigint REFERENCES app.users,
      PRIMARY KEY (project_id, user_id))
    """

    execute "CREATE INDEX ON app.members (user_id)"

    execute """
    CREATE TABLE app.project_services (
      project_id bigint REFERENCES app.projects, service_id bigint REFERENCES app.services,
      PRIMARY KEY (project_id, service_id))
    """

    execute "CREATE INDEX ON app.project_services (service_id)"

    execute """
    CREATE TABLE app.notes (
      id bigserial PRIMARY KEY, project_id bigint NOT NULL REFERENCES app.projects,
      author_id bigint NOT NULL REFERENCES app.users, body text NOT NULL,
      lock_version integer NOT NULL DEFAULT 0)
    """

    execute "CREATE INDEX ON app.notes (project_id)"
    execute "CREATE INDEX ON app.notes (author_id)"

    execute """
    CREATE TABLE app.inbox (
      id bigserial PRIMARY KEY, sender_id bigint NOT NULL REFERENCES app.users,
      recipient_id bigint NOT NULL REFERENCES app.users, body text NOT NULL)
    """

    execute "CREATE INDEX ON app.inbox (sender_id)"
    execute "CREATE INDEX ON app.inbox (recipient_id)"

    execute """
    CREATE TABLE app.folders (
      id bigint PRIMARY KEY, parent_id bigint REFERENCES app.folders,
      owner_id bigint NOT NULL REFERENCES app.users, name text NOT NULL)
    """

    execute "CREATE INDEX ON app.folders (parent_id)"
    execute "CREATE INDEX ON app.folders (owner_id)"

    # the app's role (its password from CONF_APP_PASSWORD), made once per server
    password = String.replace(System.get_env("CONF_APP_PASSWORD", "app"), "'", "''")

    execute """
    DO $$ BEGIN
      IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'conf_app') THEN
        CREATE ROLE conf_app LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD '#{password}';
      END IF;
    END $$
    """

    execute "GRANT USAGE ON SCHEMA app TO conf_app"
    execute "GRANT SELECT ON ALL TABLES IN SCHEMA app TO conf_app"
    execute "GRANT INSERT, UPDATE, DELETE ON app.notes, app.inbox TO conf_app"
    execute "GRANT UPDATE ON app.folders TO conf_app"
    execute "GRANT USAGE ON ALL SEQUENCES IN SCHEMA app TO conf_app"
  end

  def down do
    execute "DROP SCHEMA app CASCADE"
  end
end

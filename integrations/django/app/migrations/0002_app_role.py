"""The role the app connects as: row-level security applies to it, and it may read and write what the app does."""

import os

from django.db import migrations

PASSWORD = os.environ.get("CONF_APP_PASSWORD", "app").replace("'", "''")


class Migration(migrations.Migration):
    dependencies = [("app", "0001_initial")]

    operations = [
        migrations.RunSQL(
            [
                f"""DO $$ BEGIN
                  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'conf_app') THEN
                    CREATE ROLE conf_app LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD '{PASSWORD}';
                  END IF; END $$""",
                "GRANT SELECT ON users, services, projects, members, project_services, notes, inbox, folders "
                "TO conf_app",
                "GRANT INSERT, UPDATE, DELETE ON notes, inbox TO conf_app",
                "GRANT UPDATE ON folders TO conf_app",
                "GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO conf_app",
            ],
            reverse_sql=migrations.RunSQL.noop,
        ),
    ]

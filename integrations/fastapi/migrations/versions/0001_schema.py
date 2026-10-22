"""the app's tables, and the role it connects as

Revision ID: 0001
Revises:
"""

import os

from alembic import op
from app.models import Base

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("CREATE SCHEMA app")
    Base.metadata.create_all(bind=op.get_bind())
    password = os.environ.get("CONF_APP_PASSWORD", "app").replace("'", "''")
    op.execute(f"""DO $$ BEGIN
      IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'conf_app') THEN
        CREATE ROLE conf_app LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD '{password}';
      END IF; END $$""")
    op.execute("GRANT USAGE ON SCHEMA app TO conf_app")
    op.execute("GRANT SELECT ON ALL TABLES IN SCHEMA app TO conf_app")
    op.execute("GRANT INSERT, UPDATE, DELETE ON app.notes, app.inbox TO conf_app")
    op.execute("GRANT UPDATE ON app.folders TO conf_app")
    op.execute("GRANT USAGE ON ALL SEQUENCES IN SCHEMA app TO conf_app")


def downgrade() -> None:
    op.execute("DROP SCHEMA app CASCADE")

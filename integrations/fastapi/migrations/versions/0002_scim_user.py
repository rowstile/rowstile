"""what an identity provider's users become: the function the SCIM settings name (authz.set_scim, user_function)

Revision ID: 0002
Revises: d852a08c9303
"""

from alembic import op

revision = "0002"
down_revision = "d852a08c9303"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # p_id NULL: a user to make; p_resource NULL: one to delete; else one to change. It answers the user's key.
    # rowstile calls it as the tables' owner, whose own it is: the app role has no right to write app.users
    op.execute("""CREATE FUNCTION app.scim_user(p_id text, p_resource jsonb) RETURNS text LANGUAGE plpgsql AS $f$
    DECLARE v_id text;
    BEGIN
      IF p_resource IS NULL THEN
        DELETE FROM app.users WHERE id = p_id::bigint;
        RETURN p_id;
      ELSIF p_id IS NULL THEN
        INSERT INTO app.users (name) VALUES (p_resource->>'userName') RETURNING id::text INTO v_id;
      ELSE
        UPDATE app.users SET name = p_resource->>'userName' WHERE id = p_id::bigint RETURNING id::text INTO v_id;
      END IF;
      RETURN v_id;
    END $f$""")


def downgrade() -> None:
    op.execute("DROP FUNCTION app.scim_user(text, jsonb)")

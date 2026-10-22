-- The tables the policy on README.md and site/index.md reads (the pages show only the policy and the SQL), with rows
-- that make the SQL's comments true: user 42 owns folder 8 and folder 12 inside it, and edits folder 10, not folder 7
-- (tests/docs_test.sh).
CREATE SCHEMA app;
CREATE TABLE app.users (id bigint PRIMARY KEY, name text);
CREATE TABLE app.folders (id bigint PRIMARY KEY, name text, owner_id bigint NOT NULL REFERENCES app.users,
                          parent_id bigint REFERENCES app.folders);
CREATE TABLE app.folder_editors (folder_id bigint REFERENCES app.folders, user_id bigint REFERENCES app.users,
                                 PRIMARY KEY (folder_id, user_id));
CREATE INDEX ON app.folders (owner_id);
CREATE INDEX ON app.folders (parent_id);
CREATE INDEX ON app.folder_editors (user_id);
DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'app_user') THEN
    CREATE ROLE app_user NOLOGIN;
  END IF;
END
$$;
GRANT USAGE ON SCHEMA app TO app_user;
GRANT SELECT ON ALL TABLES IN SCHEMA app TO app_user;
GRANT UPDATE ON app.folders TO app_user;

INSERT INTO app.users VALUES (1, 'ada'), (42, 'bo');
INSERT INTO app.folders VALUES (7, 'Notes', 1, NULL), (8, 'Home', 42, NULL), (9, 'Photos', 1, 8),
                               (10, 'Drafts', 1, 7), (11, 'Old', 1, 10), (12, 'Trips', 42, 8);
INSERT INTO app.folder_editors VALUES (10, 42);

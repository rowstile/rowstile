-- children_schema.sql: tables with tables under them (tests/children.authz, tests/children.sh).
-- Notes are partitioned by their key, tasks by a column that is not their key (a row changes partition
-- and keeps its key), and the older docs are stored in a table that inherits from docs.
CREATE SCHEMA ch;
CREATE TABLE ch.users (id bigint PRIMARY KEY, name text NOT NULL);

CREATE TABLE ch.notes (
  id        bigint PRIMARY KEY,
  owner_id  bigint REFERENCES ch.users,
  parent_id bigint,
  title     text
) PARTITION BY RANGE (id);
CREATE TABLE ch.notes_low PARTITION OF ch.notes FOR VALUES FROM (0) TO (100);
CREATE TABLE ch.notes_high PARTITION OF ch.notes FOR VALUES FROM (100) TO (1000);

CREATE TABLE ch.tasks (
  id       bigint NOT NULL,
  state    text   NOT NULL DEFAULT 'open',
  owner_id bigint REFERENCES ch.users,
  PRIMARY KEY (id, state)
) PARTITION BY LIST (state);
CREATE TABLE ch.tasks_open PARTITION OF ch.tasks FOR VALUES IN ('open');
CREATE TABLE ch.tasks_done PARTITION OF ch.tasks FOR VALUES IN ('done');

CREATE TABLE ch.docs (
  id       bigint PRIMARY KEY,
  owner_id bigint REFERENCES ch.users,
  title    text
);
CREATE TABLE ch.docs_old () INHERITS (ch.docs);

-- principals (they sign in with API keys): bots partitioned by their key, people some of whom are stored in a
-- table that inherits
CREATE TABLE ch.bots (id bigint PRIMARY KEY, name text) PARTITION BY RANGE (id);
CREATE TABLE ch.bots_low PARTITION OF ch.bots FOR VALUES FROM (0) TO (100);
CREATE TABLE ch.bots_high PARTITION OF ch.bots FOR VALUES FROM (100) TO (1000);
CREATE TABLE ch.people (id bigint PRIMARY KEY, name text);
CREATE TABLE ch.people_old () INHERITS (ch.people);

DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'app_user') THEN CREATE ROLE app_user; END IF;
END $$;
GRANT USAGE ON SCHEMA ch TO app_user;
GRANT SELECT, INSERT, UPDATE, DELETE ON ch.users, ch.notes, ch.tasks, ch.docs TO app_user;

INSERT INTO ch.users VALUES (1, 'alice'), (2, 'bob'), (3, 'carol');
INSERT INTO ch.notes VALUES (1, 1, NULL, 'top'), (2, 1, 1, 'under top'), (3, 1, NULL, 'alone'), (4, 1, NULL, 'another'),
  (101, 1, NULL, 'high');
INSERT INTO ch.tasks VALUES (1, 'open', 1), (2, 'open', 1), (3, 'done', 1);
INSERT INTO ch.docs VALUES (1, 1, 'new'), (2, 1, 'newer');
INSERT INTO ch.docs_old VALUES (11, 1, 'old'), (12, 1, 'older'), (13, 1, 'oldest');
INSERT INTO ch.bots VALUES (1, 'a'), (2, 'b'), (3, 'c');
INSERT INTO ch.people VALUES (12, 'new');
INSERT INTO ch.people_old VALUES (11, 'old');

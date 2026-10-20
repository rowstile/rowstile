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

-- trees whose tables have no rules (posts have them, and read the trees), with the tables rowstile watches for
-- them: the tree's own, its link table, and the table a condition on it reads. Topics' are partitioned,
-- shelves' are stored in part in tables that inherit
CREATE TABLE ch.topics (id bigint PRIMARY KEY, owner_id bigint, parent_id bigint) PARTITION BY RANGE (id);
CREATE TABLE ch.topics_low PARTITION OF ch.topics FOR VALUES FROM (0) TO (100);
CREATE TABLE ch.topics_high PARTITION OF ch.topics FOR VALUES FROM (100) TO (1000);
CREATE TABLE ch.topic_links (topic_id bigint, parent_id bigint, kind text NOT NULL DEFAULT 'see') PARTITION BY LIST (kind);
CREATE TABLE ch.topic_links_see PARTITION OF ch.topic_links FOR VALUES IN ('see');
CREATE TABLE ch.frozen (topic_id bigint, kind text NOT NULL DEFAULT 'hold') PARTITION BY LIST (kind);
CREATE TABLE ch.frozen_hold PARTITION OF ch.frozen FOR VALUES IN ('hold');
CREATE TABLE ch.shelves (id bigint PRIMARY KEY, owner_id bigint, parent_id bigint);
CREATE TABLE ch.shelves_old () INHERITS (ch.shelves);
CREATE TABLE ch.shelf_links (shelf_id bigint, parent_id bigint);
CREATE TABLE ch.shelf_links_old () INHERITS (ch.shelf_links);
CREATE TABLE ch.holds (shelf_id bigint);
CREATE TABLE ch.holds_old () INHERITS (ch.holds);
CREATE TABLE ch.posts (id bigint PRIMARY KEY, topic_id bigint, shelf_id bigint);

DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'app_user') THEN CREATE ROLE app_user; END IF;
END $$;
GRANT USAGE ON SCHEMA ch TO app_user;
GRANT SELECT, INSERT, UPDATE, DELETE ON ch.users, ch.notes, ch.tasks, ch.docs TO app_user;
-- (the trees' tables and those under them as an app is given them all: GRANT ... ON ALL TABLES IN SCHEMA)
GRANT SELECT, INSERT, UPDATE, DELETE ON ch.posts, ch.topics, ch.topics_low, ch.topics_high, ch.topic_links,
  ch.topic_links_see, ch.frozen, ch.frozen_hold, ch.shelves, ch.shelves_old, ch.shelf_links, ch.shelf_links_old,
  ch.holds, ch.holds_old TO app_user;

INSERT INTO ch.users VALUES (1, 'alice'), (2, 'bob'), (3, 'carol');
INSERT INTO ch.notes VALUES (1, 1, NULL, 'top'), (2, 1, 1, 'under top'), (3, 1, NULL, 'alone'), (4, 1, NULL, 'another'),
  (101, 1, NULL, 'high');
INSERT INTO ch.tasks VALUES (1, 'open', 1), (2, 'open', 1), (3, 'done', 1);
INSERT INTO ch.docs VALUES (1, 1, 'new'), (2, 1, 'newer');
INSERT INTO ch.docs_old VALUES (11, 1, 'old'), (12, 1, 'older'), (13, 1, 'oldest');
INSERT INTO ch.bots VALUES (1, 'a'), (2, 'b'), (3, 'c');
INSERT INTO ch.people VALUES (12, 'new');
INSERT INTO ch.people_old VALUES (11, 'old');
-- user 1 owns topic 1 and shelf 1, above user 2's 2 and 3; 150 and 50 stand alone, as do user 3's 151 and 51;
-- a post in each
INSERT INTO ch.topics VALUES (1, 1, NULL), (2, 2, 1), (3, 2, 1), (150, 2, NULL), (151, 3, NULL), (152, 2, NULL);
INSERT INTO ch.shelves VALUES (1, 1, NULL), (2, 2, 1), (3, 2, 1);
INSERT INTO ch.shelves_old VALUES (50, 2, NULL), (51, 3, NULL), (52, 2, NULL);
INSERT INTO ch.posts VALUES (1, 150, NULL), (2, 151, NULL), (3, NULL, 50), (4, NULL, 51), (5, 3, NULL), (6, NULL, 3),
  (7, 2, NULL), (8, NULL, 2);

-- The messenger's tables. Who may read or change what is not here: it is in db/policy.authz, which
-- rowstile turns into row-level security on these tables. What is here is plain data integrity.
CREATE SCHEMA ms;

-- people: sign up with a phone number and a name
CREATE TABLE ms.users (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  phone      text NOT NULL UNIQUE,
  name       text NOT NULL,
  about      text NOT NULL DEFAULT 'Hey there! I am using Messenger.',
  created_at timestamptz NOT NULL DEFAULT now());

-- accounts, not governed by the policy: the backend checks passwords and sessions itself
CREATE TABLE ms.credentials (
  user_id       uuid PRIMARY KEY REFERENCES ms.users ON DELETE CASCADE,
  password_hash text NOT NULL);
CREATE TABLE ms.sessions (
  token_hash text PRIMARY KEY,
  user_id    uuid NOT NULL REFERENCES ms.users ON DELETE CASCADE,
  expires_at timestamptz NOT NULL);
CREATE INDEX ON ms.sessions (user_id);

-- a chat: two people (direct) or a group
CREATE TABLE ms.chats (
  id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  kind        text NOT NULL CHECK (kind IN ('direct', 'group')),
  title       text,
  about       text NOT NULL DEFAULT '',
  admins_only boolean NOT NULL DEFAULT false,      -- announcements: only admins post
  created_by  uuid REFERENCES ms.users ON DELETE SET NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  last_seq    bigint NOT NULL DEFAULT 0,           -- the last message's number
  CHECK (kind = 'direct' OR title IS NOT NULL));
CREATE INDEX ON ms.chats (created_by);

-- who is in a chat, with which role, since when, and how far they have read
CREATE TABLE ms.members (
  chat_id       bigint NOT NULL REFERENCES ms.chats ON DELETE CASCADE,
  user_id       uuid NOT NULL REFERENCES ms.users ON DELETE CASCADE,
  role          text NOT NULL DEFAULT 'member' CHECK (role IN ('owner', 'admin', 'member')),
  joined_at     timestamptz NOT NULL DEFAULT now(),
  last_read_seq bigint NOT NULL DEFAULT 0,
  joined_seq    bigint NOT NULL DEFAULT 0,          -- the chat's last message number when they joined
  PRIMARY KEY (chat_id, user_id));
CREATE INDEX ON ms.members (user_id);
-- one owner a chat, however many rows a statement adds and however many transactions add them (a rule checks
-- each row against the table as the statement found it: one INSERT of several rows could make two)
CREATE UNIQUE INDEX members_one_owner ON ms.members (chat_id) WHERE role = 'owner';

-- joined_seq is set by the database, whatever the insert says: members read the messages after it, by number,
-- not by the clock (a clock that steps back refuses nothing). SECURITY DEFINER: it reads the chat's counter,
-- like ms.number_message below
CREATE FUNCTION ms.stamp_joined_seq() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $f$
BEGIN
  NEW.joined_seq := coalesce((SELECT c.last_seq FROM ms.chats c WHERE c.id = NEW.chat_id), 0);
  RETURN NEW;
END $f$;
CREATE TRIGGER stamp_joined_seq BEFORE INSERT ON ms.members FOR EACH ROW EXECUTE FUNCTION ms.stamp_joined_seq();

-- the number the signed-in person joined at (NULL: not a member)
-- (plpgsql: authz.uid() comes with the policy, applied after the migrations)
CREATE FUNCTION ms.joined_seq(p_chat bigint) RETURNS bigint
LANGUAGE plpgsql STABLE AS $$
BEGIN
  RETURN (SELECT m.joined_seq FROM ms.members m WHERE m.chat_id = p_chat AND m.user_id = authz.uid());
END $$;

-- a direct chat is its first two people: the two of each, in order, written by the database when the second
-- joins. One chat for two people (pair UNIQUE): once one of them left, its pair is NULL, and they may start
-- another. The row stays: nobody comes into that chat again (the policy reads it too). Not the app role's to read
-- or write: it could otherwise take a pair's place
CREATE TABLE ms.direct_pairs (
  chat_id bigint PRIMARY KEY REFERENCES ms.chats ON DELETE CASCADE,
  pair    uuid[] UNIQUE CHECK (array_length(pair, 1) = 2));

-- a third is refused here, after the statement, which sees all of its rows (the policy counts too, but row by
-- row). Two transactions adding one each both see two, and both write the pair: chat_id refuses the second.
-- (SECURITY DEFINER: it writes whoever adds the member)
CREATE FUNCTION ms.pair_direct() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $f$
DECLARE v_pair uuid[];
BEGIN
  IF (SELECT c.kind FROM ms.chats c WHERE c.id = NEW.chat_id) = 'direct' THEN
    -- the chat had its two: only they were added (two members added by one statement both see their pair here)
    IF EXISTS (SELECT 1 FROM ms.direct_pairs p WHERE p.chat_id = NEW.chat_id
               AND (p.pair IS NULL OR NOT NEW.user_id = ANY (p.pair))) THEN
      RAISE EXCEPTION 'a direct chat is the two people who started it' USING ERRCODE = 'check_violation';
    END IF;
    SELECT array_agg(m.user_id ORDER BY m.user_id) INTO v_pair FROM ms.members m WHERE m.chat_id = NEW.chat_id;
    IF array_length(v_pair, 1) > 2 THEN
      RAISE EXCEPTION 'a direct chat is two people' USING ERRCODE = 'check_violation';
    END IF;
    IF array_length(v_pair, 1) = 2 AND NOT EXISTS (SELECT 1 FROM ms.direct_pairs p WHERE p.chat_id = NEW.chat_id) THEN
      -- a second chat for the same two is refused here (23505): the API then answers with the first
      INSERT INTO ms.direct_pairs (chat_id, pair) VALUES (NEW.chat_id, v_pair);
    END IF;
  END IF;
  RETURN NULL;
END $f$;
CREATE TRIGGER pair_direct AFTER INSERT ON ms.members FOR EACH ROW EXECUTE FUNCTION ms.pair_direct();

-- a chat one of the two left is no longer the pair's: they may start another
CREATE FUNCTION ms.unpair_direct() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $f$
BEGIN
  UPDATE ms.direct_pairs p SET pair = NULL WHERE p.chat_id = OLD.chat_id AND p.pair IS NOT NULL;
  RETURN NULL;
END $f$;
CREATE TRIGGER unpair_direct AFTER DELETE ON ms.members FOR EACH ROW EXECUTE FUNCTION ms.unpair_direct();

-- messages are numbered per chat: (chat_id, seq) is the key
CREATE TABLE ms.messages (
  chat_id    bigint NOT NULL REFERENCES ms.chats ON DELETE CASCADE,
  seq        bigint NOT NULL,
  sender_id  uuid REFERENCES ms.users ON DELETE SET NULL,
  bot_id     bigint,                               -- or a bot (below)
  body       text NOT NULL CHECK (length(body) <= 4000),
  created_at timestamptz NOT NULL DEFAULT now(),
  edited_at  timestamptz,
  deleted    boolean NOT NULL DEFAULT false,       -- deleted for everyone: the row stays, the text goes
  PRIMARY KEY (chat_id, seq),
  CHECK ((sender_id IS NULL) <> (bot_id IS NULL) OR deleted));
CREATE INDEX ON ms.messages (sender_id);

-- the next number in the chat. SECURITY DEFINER: it bumps ms.chats.last_seq, which the sender may
-- not update themselves (the policy says who may post; this only counts)
CREATE FUNCTION ms.number_message() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $f$
BEGIN
  UPDATE ms.chats SET last_seq = last_seq + 1 WHERE id = NEW.chat_id RETURNING last_seq INTO NEW.seq;
  IF NEW.seq IS NULL THEN RAISE EXCEPTION 'no chat %', NEW.chat_id USING ERRCODE = 'foreign_key_violation'; END IF;
  RETURN NEW;
END $f$;
CREATE TRIGGER number_message BEFORE INSERT ON ms.messages FOR EACH ROW EXECUTE FUNCTION ms.number_message();

-- blocks: a person you blocked can't write to you, nor you to them, in your direct chat
CREATE TABLE ms.blocks (
  blocker_id uuid NOT NULL REFERENCES ms.users ON DELETE CASCADE,
  blocked_id uuid NOT NULL REFERENCES ms.users ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (blocker_id, blocked_id),
  CHECK (blocker_id <> blocked_id));
CREATE INDEX ON ms.blocks (blocked_id);

-- the members of direct chats between two people where either blocked the other
CREATE VIEW ms.direct_blocks AS
  SELECT m.chat_id, m.user_id
  FROM ms.members m
  JOIN ms.chats c ON c.id = m.chat_id AND c.kind = 'direct'
  JOIN ms.members o ON o.chat_id = m.chat_id AND o.user_id <> m.user_id
  WHERE EXISTS (SELECT 1 FROM ms.blocks b
                WHERE (b.blocker_id, b.blocked_id) IN ((o.user_id, m.user_id), (m.user_id, o.user_id)));

-- bots: services that sign in with their own API keys and post in the chats they were added to
CREATE TABLE ms.bots (
  id         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  name       text NOT NULL,
  owner_id   uuid NOT NULL REFERENCES ms.users ON DELETE CASCADE,
  active     boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now());
CREATE INDEX ON ms.bots (owner_id);
ALTER TABLE ms.messages ADD FOREIGN KEY (bot_id) REFERENCES ms.bots ON DELETE SET NULL;
CREATE INDEX ON ms.messages (bot_id);
CREATE TABLE ms.chat_bots (
  chat_id  bigint NOT NULL REFERENCES ms.chats ON DELETE CASCADE,
  bot_id   bigint NOT NULL REFERENCES ms.bots ON DELETE CASCADE,
  added_by uuid REFERENCES ms.users ON DELETE SET NULL,
  PRIMARY KEY (chat_id, bot_id));
CREATE INDEX ON ms.chat_bots (bot_id);

-- signing up: an account is a profile and a password, made together
CREATE FUNCTION ms.sign_up(p_phone text, p_name text, p_password_hash text) RETURNS SETOF ms.users
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $f$
DECLARE v_id uuid;
BEGIN
  INSERT INTO ms.users (phone, name) VALUES (p_phone, p_name) RETURNING id INTO v_id;
  INSERT INTO ms.credentials VALUES (v_id, p_password_hash);
  RETURN QUERY SELECT * FROM ms.users WHERE id = v_id;
END $f$;

-- signing in, before anyone is signed in (so before the policy lets the backend read ms.users):
-- the account behind a session, or behind a phone number with its password hash
CREATE FUNCTION ms.session_user(p_token_hash text) RETURNS uuid
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT s.user_id FROM ms.sessions s WHERE s.token_hash = p_token_hash AND s.expires_at > now() $$;
CREATE FUNCTION ms.credentials_for(p_phone text) RETURNS TABLE (user_id uuid, password_hash text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT c.user_id, c.password_hash FROM ms.users u JOIN ms.credentials c ON c.user_id = u.id WHERE u.phone = p_phone $$;

-- live updates: the backend listens, and tells each connected person "chat N changed" if they may read
-- it. A membership change names the person too ("N:user"), so someone removed hears of it.
CREATE FUNCTION ms.announce() RETURNS trigger
LANGUAGE plpgsql AS $f$
BEGIN
  IF TG_TABLE_NAME = 'members' THEN
    PERFORM pg_notify('ms_events', coalesce(NEW.chat_id, OLD.chat_id) || ':' || coalesce(NEW.user_id, OLD.user_id));
  ELSE
    PERFORM pg_notify('ms_events', NEW.chat_id::text);
  END IF;
  RETURN NULL;
END $f$;
CREATE TRIGGER announce AFTER INSERT OR UPDATE ON ms.messages FOR EACH ROW EXECUTE FUNCTION ms.announce();
CREATE TRIGGER announce AFTER INSERT OR UPDATE OR DELETE ON ms.members FOR EACH ROW EXECUTE FUNCTION ms.announce();
CREATE FUNCTION ms.announce_chat() RETURNS trigger
LANGUAGE plpgsql AS $f$
BEGIN
  PERFORM pg_notify('ms_events', NEW.id::text);
  RETURN NULL;
END $f$;
CREATE TRIGGER announce AFTER UPDATE OF title, about, admins_only ON ms.chats FOR EACH ROW EXECUTE FUNCTION ms.announce_chat();

-- the app role reads and writes every table; row-level security (the policy) decides which rows
GRANT USAGE ON SCHEMA ms TO ms_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA ms TO ms_app;
-- ...but not the view the policy reads blocks through: views run with their owner's rights (authz.lint says so);
-- nor the pairs the database keeps; nor password hashes: signing in goes through ms.credentials_for() and
-- ms.sign_up()
REVOKE ALL ON ms.direct_blocks, ms.direct_pairs, ms.credentials FROM ms_app;
REVOKE ALL ON FUNCTION ms.number_message(), ms.announce(), ms.announce_chat(), ms.stamp_joined_seq(),
  ms.pair_direct(), ms.unpair_direct() FROM PUBLIC;
REVOKE ALL ON FUNCTION ms.sign_up(text, text, text), ms.session_user(text), ms.credentials_for(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ms.sign_up(text, text, text), ms.session_user(text), ms.credentials_for(text),
  ms.joined_seq(bigint) TO ms_app;

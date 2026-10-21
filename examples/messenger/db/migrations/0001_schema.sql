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
  PRIMARY KEY (chat_id, user_id));
CREATE INDEX ON ms.members (user_id);

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

-- when a person joined a chat: they read only what was said since (NULL: not a member)
-- (plpgsql: authz.uid() comes with the policy, applied after the migrations)
CREATE FUNCTION ms.joined_at(p_chat bigint) RETURNS timestamptz
LANGUAGE plpgsql STABLE AS $$
BEGIN
  RETURN (SELECT m.joined_at FROM ms.members m WHERE m.chat_id = p_chat AND m.user_id = authz.uid());
END $$;

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
-- ...but not the view the policy reads blocks through: views run with their owner's rights (authz.lint says so)
REVOKE ALL ON ms.direct_blocks FROM ms_app;
REVOKE ALL ON FUNCTION ms.number_message(), ms.announce(), ms.announce_chat() FROM PUBLIC;
REVOKE ALL ON FUNCTION ms.sign_up(text, text, text), ms.session_user(text), ms.credentials_for(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ms.sign_up(text, text, text), ms.session_user(text), ms.credentials_for(text),
  ms.joined_at(bigint) TO ms_app;

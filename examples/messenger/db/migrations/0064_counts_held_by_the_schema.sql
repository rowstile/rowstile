-- 0053: what the policy counts, held for every statement. A rule checks each row against the tables as the
-- statement found them: one INSERT of several rows put three people in a direct chat, or two owners in a group
-- being set up, though each row alone passes its rule.

-- one owner a chat, however many rows a statement adds and however many transactions add them
CREATE UNIQUE INDEX members_one_owner ON ms.members (chat_id) WHERE role = 'owner';

-- a direct chat is two people: a third is refused here, after the statement, which sees all of its rows. Two
-- transactions adding one each both see two, and both write the pair: chat_id UNIQUE refuses the second
CREATE OR REPLACE FUNCTION ms.pair_direct() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $f$
DECLARE v_pair uuid[];
BEGIN
  IF (SELECT c.kind FROM ms.chats c WHERE c.id = NEW.chat_id) = 'direct' THEN
    SELECT array_agg(m.user_id ORDER BY m.user_id) INTO v_pair FROM ms.members m WHERE m.chat_id = NEW.chat_id;
    IF array_length(v_pair, 1) > 2 THEN
      RAISE EXCEPTION 'a direct chat is two people' USING ERRCODE = 'check_violation';
    END IF;
    -- once for the chat: two members added by one statement both see the two of them here
    IF array_length(v_pair, 1) = 2 AND NOT EXISTS (SELECT 1 FROM ms.direct_pairs p WHERE p.chat_id = NEW.chat_id) THEN
      -- a second chat for the same two is refused here (23505): the API then answers with the first
      INSERT INTO ms.direct_pairs (pair, chat_id) VALUES (v_pair, NEW.chat_id);
    END IF;
  END IF;
  RETURN NULL;
END $f$;

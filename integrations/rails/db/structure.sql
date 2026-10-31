SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET transaction_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: app; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA app;


SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: folders; Type: TABLE; Schema: app; Owner: -
--

CREATE TABLE app.folders (
    id bigint NOT NULL,
    parent_id bigint,
    owner_id bigint NOT NULL,
    name text NOT NULL
);


--
-- Name: inbox; Type: TABLE; Schema: app; Owner: -
--

CREATE TABLE app.inbox (
    id bigint NOT NULL,
    sender_id bigint NOT NULL,
    recipient_id bigint NOT NULL,
    body text NOT NULL
);


--
-- Name: notes; Type: TABLE; Schema: app; Owner: -
--

CREATE TABLE app.notes (
    id bigint NOT NULL,
    project_id bigint NOT NULL,
    author_id bigint NOT NULL,
    body text NOT NULL,
    lock_version integer DEFAULT 0 NOT NULL
);


--
-- Name: projects; Type: TABLE; Schema: app; Owner: -
--

CREATE TABLE app.projects (
    id bigint NOT NULL,
    owner_id bigint NOT NULL,
    name text NOT NULL,
    public boolean DEFAULT false NOT NULL
);


--
-- Name: members; Type: TABLE; Schema: app; Owner: -
--

CREATE TABLE app.members (
    project_id bigint NOT NULL,
    user_id bigint NOT NULL
);


--
-- Name: inbox_id_seq; Type: SEQUENCE; Schema: app; Owner: -
--

CREATE SEQUENCE app.inbox_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: inbox_id_seq; Type: SEQUENCE OWNED BY; Schema: app; Owner: -
--

ALTER SEQUENCE app.inbox_id_seq OWNED BY app.inbox.id;


--
-- Name: notes_id_seq; Type: SEQUENCE; Schema: app; Owner: -
--

CREATE SEQUENCE app.notes_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: notes_id_seq; Type: SEQUENCE OWNED BY; Schema: app; Owner: -
--

ALTER SEQUENCE app.notes_id_seq OWNED BY app.notes.id;


--
-- Name: project_services; Type: TABLE; Schema: app; Owner: -
--

CREATE TABLE app.project_services (
    project_id bigint NOT NULL,
    service_id bigint NOT NULL
);


--
-- Name: services; Type: TABLE; Schema: app; Owner: -
--

CREATE TABLE app.services (
    id bigint NOT NULL,
    name text NOT NULL
);


--
-- Name: users; Type: TABLE; Schema: app; Owner: -
--

CREATE TABLE app.users (
    id bigint NOT NULL,
    name text NOT NULL
);


--
-- Name: inbox id; Type: DEFAULT; Schema: app; Owner: -
--

ALTER TABLE ONLY app.inbox ALTER COLUMN id SET DEFAULT nextval('app.inbox_id_seq'::regclass);


--
-- Name: notes id; Type: DEFAULT; Schema: app; Owner: -
--

ALTER TABLE ONLY app.notes ALTER COLUMN id SET DEFAULT nextval('app.notes_id_seq'::regclass);


--
-- Name: folders folders_pkey; Type: CONSTRAINT; Schema: app; Owner: -
--

ALTER TABLE ONLY app.folders
    ADD CONSTRAINT folders_pkey PRIMARY KEY (id);


--
-- Name: inbox inbox_pkey; Type: CONSTRAINT; Schema: app; Owner: -
--

ALTER TABLE ONLY app.inbox
    ADD CONSTRAINT inbox_pkey PRIMARY KEY (id);


--
-- Name: members members_pkey; Type: CONSTRAINT; Schema: app; Owner: -
--

ALTER TABLE ONLY app.members
    ADD CONSTRAINT members_pkey PRIMARY KEY (project_id, user_id);


--
-- Name: notes notes_pkey; Type: CONSTRAINT; Schema: app; Owner: -
--

ALTER TABLE ONLY app.notes
    ADD CONSTRAINT notes_pkey PRIMARY KEY (id);


--
-- Name: project_services project_services_pkey; Type: CONSTRAINT; Schema: app; Owner: -
--

ALTER TABLE ONLY app.project_services
    ADD CONSTRAINT project_services_pkey PRIMARY KEY (project_id, service_id);


--
-- Name: projects projects_pkey; Type: CONSTRAINT; Schema: app; Owner: -
--

ALTER TABLE ONLY app.projects
    ADD CONSTRAINT projects_pkey PRIMARY KEY (id);


--
-- Name: services services_pkey; Type: CONSTRAINT; Schema: app; Owner: -
--

ALTER TABLE ONLY app.services
    ADD CONSTRAINT services_pkey PRIMARY KEY (id);


--
-- Name: users users_pkey; Type: CONSTRAINT; Schema: app; Owner: -
--

ALTER TABLE ONLY app.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);


--
-- Name: folders_owner_id_idx; Type: INDEX; Schema: app; Owner: -
--

CREATE INDEX folders_owner_id_idx ON app.folders USING btree (owner_id);


--
-- Name: folders_parent_id_idx; Type: INDEX; Schema: app; Owner: -
--

CREATE INDEX folders_parent_id_idx ON app.folders USING btree (parent_id);


--
-- Name: inbox_recipient_id_idx; Type: INDEX; Schema: app; Owner: -
--

CREATE INDEX inbox_recipient_id_idx ON app.inbox USING btree (recipient_id);


--
-- Name: inbox_sender_id_idx; Type: INDEX; Schema: app; Owner: -
--

CREATE INDEX inbox_sender_id_idx ON app.inbox USING btree (sender_id);


--
-- Name: members_user_id_idx; Type: INDEX; Schema: app; Owner: -
--

CREATE INDEX members_user_id_idx ON app.members USING btree (user_id);


--
-- Name: notes_author_id_idx; Type: INDEX; Schema: app; Owner: -
--

CREATE INDEX notes_author_id_idx ON app.notes USING btree (author_id);


--
-- Name: notes_project_id_idx; Type: INDEX; Schema: app; Owner: -
--

CREATE INDEX notes_project_id_idx ON app.notes USING btree (project_id);


--
-- Name: project_services_service_id_idx; Type: INDEX; Schema: app; Owner: -
--

CREATE INDEX project_services_service_id_idx ON app.project_services USING btree (service_id);


--
-- Name: folders authz_folder__parent__tree_del; Type: TRIGGER; Schema: app; Owner: -
--

CREATE TRIGGER authz_folder__parent__tree_del AFTER DELETE ON app.folders REFERENCING OLD TABLE AS old_rows FOR EACH STATEMENT EXECUTE FUNCTION authz_int.folder__parent__tree_on_rows();


--
-- Name: folders authz_folder__parent__tree_ins; Type: TRIGGER; Schema: app; Owner: -
--

CREATE TRIGGER authz_folder__parent__tree_ins AFTER INSERT ON app.folders REFERENCING NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION authz_int.folder__parent__tree_on_rows();


--
-- Name: folders authz_folder__parent__tree_trunc; Type: TRIGGER; Schema: app; Owner: -
--

CREATE TRIGGER authz_folder__parent__tree_trunc AFTER TRUNCATE ON app.folders FOR EACH STATEMENT EXECUTE FUNCTION authz_int.folder__parent__tree_on_truncate();


--
-- Name: folders authz_folder__parent__tree_upd; Type: TRIGGER; Schema: app; Owner: -
--

CREATE TRIGGER authz_folder__parent__tree_upd AFTER UPDATE ON app.folders REFERENCING OLD TABLE AS old_rows NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION authz_int.folder__parent__tree_on_rows();


--
-- Name: folders authz_folder_col_audit_del; Type: TRIGGER; Schema: app; Owner: -
--

CREATE TRIGGER authz_folder_col_audit_del AFTER DELETE ON app.folders REFERENCING OLD TABLE AS old_rows FOR EACH STATEMENT EXECUTE FUNCTION authz_int.folder__col_audit_del();


--
-- Name: folders authz_folder_col_audit_ins; Type: TRIGGER; Schema: app; Owner: -
--

CREATE TRIGGER authz_folder_col_audit_ins AFTER INSERT ON app.folders REFERENCING NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION authz_int.folder__col_audit_ins();


--
-- Name: folders authz_folder_col_audit_row; Type: TRIGGER; Schema: app; Owner: -
--

CREATE TRIGGER authz_folder_col_audit_row AFTER UPDATE ON app.folders FOR EACH ROW WHEN (((old.parent_id IS DISTINCT FROM new.parent_id) OR (old.owner_id IS DISTINCT FROM new.owner_id))) EXECUTE FUNCTION authz_int.folder__col_audit_row();


--
-- Name: folders authz_folder_col_audit_trunc; Type: TRIGGER; Schema: app; Owner: -
--

CREATE TRIGGER authz_folder_col_audit_trunc AFTER TRUNCATE ON app.folders FOR EACH STATEMENT EXECUTE FUNCTION authz_int.folder__col_audit_trunc();


--
-- Name: folders authz_folder_col_audit_upd; Type: TRIGGER; Schema: app; Owner: -
--

CREATE TRIGGER authz_folder_col_audit_upd AFTER UPDATE ON app.folders REFERENCING OLD TABLE AS old_rows NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION authz_int.folder__col_audit_upd();


--
-- Name: inbox authz_message_col_audit_del; Type: TRIGGER; Schema: app; Owner: -
--

CREATE TRIGGER authz_message_col_audit_del AFTER DELETE ON app.inbox REFERENCING OLD TABLE AS old_rows FOR EACH STATEMENT EXECUTE FUNCTION authz_int.message__col_audit_del();


--
-- Name: inbox authz_message_col_audit_ins; Type: TRIGGER; Schema: app; Owner: -
--

CREATE TRIGGER authz_message_col_audit_ins AFTER INSERT ON app.inbox REFERENCING NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION authz_int.message__col_audit_ins();


--
-- Name: inbox authz_message_col_audit_row; Type: TRIGGER; Schema: app; Owner: -
--

CREATE TRIGGER authz_message_col_audit_row AFTER UPDATE ON app.inbox FOR EACH ROW WHEN ((old.recipient_id IS DISTINCT FROM new.recipient_id)) EXECUTE FUNCTION authz_int.message__col_audit_row();


--
-- Name: inbox authz_message_col_audit_trunc; Type: TRIGGER; Schema: app; Owner: -
--

CREATE TRIGGER authz_message_col_audit_trunc AFTER TRUNCATE ON app.inbox FOR EACH STATEMENT EXECUTE FUNCTION authz_int.message__col_audit_trunc();


--
-- Name: inbox authz_message_col_audit_upd; Type: TRIGGER; Schema: app; Owner: -
--

CREATE TRIGGER authz_message_col_audit_upd AFTER UPDATE ON app.inbox REFERENCING OLD TABLE AS old_rows NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION authz_int.message__col_audit_upd();


--
-- Name: notes authz_note_col_audit_del; Type: TRIGGER; Schema: app; Owner: -
--

CREATE TRIGGER authz_note_col_audit_del AFTER DELETE ON app.notes REFERENCING OLD TABLE AS old_rows FOR EACH STATEMENT EXECUTE FUNCTION authz_int.note__col_audit_del();


--
-- Name: notes authz_note_col_audit_ins; Type: TRIGGER; Schema: app; Owner: -
--

CREATE TRIGGER authz_note_col_audit_ins AFTER INSERT ON app.notes REFERENCING NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION authz_int.note__col_audit_ins();


--
-- Name: notes authz_note_col_audit_row; Type: TRIGGER; Schema: app; Owner: -
--

CREATE TRIGGER authz_note_col_audit_row AFTER UPDATE ON app.notes FOR EACH ROW WHEN (((old.project_id IS DISTINCT FROM new.project_id) OR (old.author_id IS DISTINCT FROM new.author_id))) EXECUTE FUNCTION authz_int.note__col_audit_row();


--
-- Name: notes authz_note_col_audit_trunc; Type: TRIGGER; Schema: app; Owner: -
--

CREATE TRIGGER authz_note_col_audit_trunc AFTER TRUNCATE ON app.notes FOR EACH STATEMENT EXECUTE FUNCTION authz_int.note__col_audit_trunc();


--
-- Name: notes authz_note_col_audit_upd; Type: TRIGGER; Schema: app; Owner: -
--

CREATE TRIGGER authz_note_col_audit_upd AFTER UPDATE ON app.notes REFERENCING OLD TABLE AS old_rows NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION authz_int.note__col_audit_upd();


--
-- Name: projects authz_project_col_audit_del; Type: TRIGGER; Schema: app; Owner: -
--

CREATE TRIGGER authz_project_col_audit_del AFTER DELETE ON app.projects REFERENCING OLD TABLE AS old_rows FOR EACH STATEMENT EXECUTE FUNCTION authz_int.project__col_audit_del();


--
-- Name: projects authz_project_col_audit_ins; Type: TRIGGER; Schema: app; Owner: -
--

CREATE TRIGGER authz_project_col_audit_ins AFTER INSERT ON app.projects REFERENCING NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION authz_int.project__col_audit_ins();


--
-- Name: projects authz_project_col_audit_row; Type: TRIGGER; Schema: app; Owner: -
--

CREATE TRIGGER authz_project_col_audit_row AFTER UPDATE ON app.projects FOR EACH ROW WHEN ((old.owner_id IS DISTINCT FROM new.owner_id)) EXECUTE FUNCTION authz_int.project__col_audit_row();


--
-- Name: projects authz_project_col_audit_trunc; Type: TRIGGER; Schema: app; Owner: -
--

CREATE TRIGGER authz_project_col_audit_trunc AFTER TRUNCATE ON app.projects FOR EACH STATEMENT EXECUTE FUNCTION authz_int.project__col_audit_trunc();


--
-- Name: projects authz_project_col_audit_upd; Type: TRIGGER; Schema: app; Owner: -
--

CREATE TRIGGER authz_project_col_audit_upd AFTER UPDATE ON app.projects REFERENCING OLD TABLE AS old_rows NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION authz_int.project__col_audit_upd();


--
-- Name: members authz_rel_audit_1_del; Type: TRIGGER; Schema: app; Owner: -
--

CREATE TRIGGER authz_rel_audit_1_del AFTER DELETE ON app.members REFERENCING OLD TABLE AS old_rows FOR EACH STATEMENT EXECUTE FUNCTION authz_int.rel_audit_1_del();


--
-- Name: members authz_rel_audit_1_ins; Type: TRIGGER; Schema: app; Owner: -
--

CREATE TRIGGER authz_rel_audit_1_ins AFTER INSERT ON app.members REFERENCING NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION authz_int.rel_audit_1_ins();


--
-- Name: members authz_rel_audit_1_trunc; Type: TRIGGER; Schema: app; Owner: -
--

CREATE TRIGGER authz_rel_audit_1_trunc AFTER TRUNCATE ON app.members FOR EACH STATEMENT EXECUTE FUNCTION authz_int.rel_audit_1_trunc();


--
-- Name: members authz_rel_audit_1_upd; Type: TRIGGER; Schema: app; Owner: -
--

CREATE TRIGGER authz_rel_audit_1_upd AFTER UPDATE ON app.members REFERENCING OLD TABLE AS old_rows NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION authz_int.rel_audit_1_upd();


--
-- Name: project_services authz_rel_audit_2_del; Type: TRIGGER; Schema: app; Owner: -
--

CREATE TRIGGER authz_rel_audit_2_del AFTER DELETE ON app.project_services REFERENCING OLD TABLE AS old_rows FOR EACH STATEMENT EXECUTE FUNCTION authz_int.rel_audit_2_del();


--
-- Name: project_services authz_rel_audit_2_ins; Type: TRIGGER; Schema: app; Owner: -
--

CREATE TRIGGER authz_rel_audit_2_ins AFTER INSERT ON app.project_services REFERENCING NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION authz_int.rel_audit_2_ins();


--
-- Name: project_services authz_rel_audit_2_trunc; Type: TRIGGER; Schema: app; Owner: -
--

CREATE TRIGGER authz_rel_audit_2_trunc AFTER TRUNCATE ON app.project_services FOR EACH STATEMENT EXECUTE FUNCTION authz_int.rel_audit_2_trunc();


--
-- Name: project_services authz_rel_audit_2_upd; Type: TRIGGER; Schema: app; Owner: -
--

CREATE TRIGGER authz_rel_audit_2_upd AFTER UPDATE ON app.project_services REFERENCING OLD TABLE AS old_rows NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION authz_int.rel_audit_2_upd();


--
-- Name: services authz_service_col_audit_del; Type: TRIGGER; Schema: app; Owner: -
--

CREATE TRIGGER authz_service_col_audit_del AFTER DELETE ON app.services REFERENCING OLD TABLE AS old_rows FOR EACH STATEMENT EXECUTE FUNCTION authz_int.service__col_audit_del();


--
-- Name: services authz_service_col_audit_ins; Type: TRIGGER; Schema: app; Owner: -
--

CREATE TRIGGER authz_service_col_audit_ins AFTER INSERT ON app.services REFERENCING NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION authz_int.service__col_audit_ins();


--
-- Name: services authz_service_col_audit_trunc; Type: TRIGGER; Schema: app; Owner: -
--

CREATE TRIGGER authz_service_col_audit_trunc AFTER TRUNCATE ON app.services FOR EACH STATEMENT EXECUTE FUNCTION authz_int.service__col_audit_trunc();


--
-- Name: services authz_service_col_audit_upd; Type: TRIGGER; Schema: app; Owner: -
--

CREATE TRIGGER authz_service_col_audit_upd AFTER UPDATE ON app.services REFERENCING OLD TABLE AS old_rows NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION authz_int.service__col_audit_upd();


--
-- Name: services authz_service_keys_gone_del; Type: TRIGGER; Schema: app; Owner: -
--

CREATE TRIGGER authz_service_keys_gone_del AFTER DELETE ON app.services REFERENCING OLD TABLE AS old_rows FOR EACH STATEMENT EXECUTE FUNCTION authz_int.service__keys_gone();


--
-- Name: services authz_service_keys_gone_id; Type: TRIGGER; Schema: app; Owner: -
--

CREATE TRIGGER authz_service_keys_gone_id AFTER UPDATE ON app.services FOR EACH ROW WHEN ((old.id IS DISTINCT FROM new.id)) EXECUTE FUNCTION authz_int.service__keys_gone_id();


--
-- Name: services authz_service_keys_gone_trunc; Type: TRIGGER; Schema: app; Owner: -
--

CREATE TRIGGER authz_service_keys_gone_trunc AFTER TRUNCATE ON app.services FOR EACH STATEMENT EXECUTE FUNCTION authz_int.service__keys_gone();


--
-- Name: services authz_service_keys_gone_trunc_first; Type: TRIGGER; Schema: app; Owner: -
--

CREATE TRIGGER authz_service_keys_gone_trunc_first BEFORE TRUNCATE ON app.services FOR EACH STATEMENT EXECUTE FUNCTION authz_int.service__keys_gone_all();


--
-- Name: users authz_user_col_audit_del; Type: TRIGGER; Schema: app; Owner: -
--

CREATE TRIGGER authz_user_col_audit_del AFTER DELETE ON app.users REFERENCING OLD TABLE AS old_rows FOR EACH STATEMENT EXECUTE FUNCTION authz_int.user__col_audit_del();


--
-- Name: users authz_user_col_audit_ins; Type: TRIGGER; Schema: app; Owner: -
--

CREATE TRIGGER authz_user_col_audit_ins AFTER INSERT ON app.users REFERENCING NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION authz_int.user__col_audit_ins();


--
-- Name: users authz_user_col_audit_trunc; Type: TRIGGER; Schema: app; Owner: -
--

CREATE TRIGGER authz_user_col_audit_trunc AFTER TRUNCATE ON app.users FOR EACH STATEMENT EXECUTE FUNCTION authz_int.user__col_audit_trunc();


--
-- Name: users authz_user_col_audit_upd; Type: TRIGGER; Schema: app; Owner: -
--

CREATE TRIGGER authz_user_col_audit_upd AFTER UPDATE ON app.users REFERENCING OLD TABLE AS old_rows NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION authz_int.user__col_audit_upd();


--
-- Name: users authz_user_keys_gone_del; Type: TRIGGER; Schema: app; Owner: -
--

CREATE TRIGGER authz_user_keys_gone_del AFTER DELETE ON app.users REFERENCING OLD TABLE AS old_rows FOR EACH STATEMENT EXECUTE FUNCTION authz_int.user__keys_gone();


--
-- Name: users authz_user_keys_gone_id; Type: TRIGGER; Schema: app; Owner: -
--

CREATE TRIGGER authz_user_keys_gone_id AFTER UPDATE ON app.users FOR EACH ROW WHEN ((old.id IS DISTINCT FROM new.id)) EXECUTE FUNCTION authz_int.user__keys_gone_id();


--
-- Name: users authz_user_keys_gone_trunc; Type: TRIGGER; Schema: app; Owner: -
--

CREATE TRIGGER authz_user_keys_gone_trunc AFTER TRUNCATE ON app.users FOR EACH STATEMENT EXECUTE FUNCTION authz_int.user__keys_gone();


--
-- Name: users authz_user_keys_gone_trunc_first; Type: TRIGGER; Schema: app; Owner: -
--

CREATE TRIGGER authz_user_keys_gone_trunc_first BEFORE TRUNCATE ON app.users FOR EACH STATEMENT EXECUTE FUNCTION authz_int.user__keys_gone_all();


--
-- Name: folders folders_owner_id_fkey; Type: FK CONSTRAINT; Schema: app; Owner: -
--

ALTER TABLE ONLY app.folders
    ADD CONSTRAINT folders_owner_id_fkey FOREIGN KEY (owner_id) REFERENCES app.users(id);


--
-- Name: folders folders_parent_id_fkey; Type: FK CONSTRAINT; Schema: app; Owner: -
--

ALTER TABLE ONLY app.folders
    ADD CONSTRAINT folders_parent_id_fkey FOREIGN KEY (parent_id) REFERENCES app.folders(id);


--
-- Name: inbox inbox_recipient_id_fkey; Type: FK CONSTRAINT; Schema: app; Owner: -
--

ALTER TABLE ONLY app.inbox
    ADD CONSTRAINT inbox_recipient_id_fkey FOREIGN KEY (recipient_id) REFERENCES app.users(id);


--
-- Name: inbox inbox_sender_id_fkey; Type: FK CONSTRAINT; Schema: app; Owner: -
--

ALTER TABLE ONLY app.inbox
    ADD CONSTRAINT inbox_sender_id_fkey FOREIGN KEY (sender_id) REFERENCES app.users(id);


--
-- Name: members members_project_id_fkey; Type: FK CONSTRAINT; Schema: app; Owner: -
--

ALTER TABLE ONLY app.members
    ADD CONSTRAINT members_project_id_fkey FOREIGN KEY (project_id) REFERENCES app.projects(id);


--
-- Name: members members_user_id_fkey; Type: FK CONSTRAINT; Schema: app; Owner: -
--

ALTER TABLE ONLY app.members
    ADD CONSTRAINT members_user_id_fkey FOREIGN KEY (user_id) REFERENCES app.users(id);


--
-- Name: notes notes_author_id_fkey; Type: FK CONSTRAINT; Schema: app; Owner: -
--

ALTER TABLE ONLY app.notes
    ADD CONSTRAINT notes_author_id_fkey FOREIGN KEY (author_id) REFERENCES app.users(id);


--
-- Name: notes notes_project_id_fkey; Type: FK CONSTRAINT; Schema: app; Owner: -
--

ALTER TABLE ONLY app.notes
    ADD CONSTRAINT notes_project_id_fkey FOREIGN KEY (project_id) REFERENCES app.projects(id);


--
-- Name: project_services project_services_project_id_fkey; Type: FK CONSTRAINT; Schema: app; Owner: -
--

ALTER TABLE ONLY app.project_services
    ADD CONSTRAINT project_services_project_id_fkey FOREIGN KEY (project_id) REFERENCES app.projects(id);


--
-- Name: project_services project_services_service_id_fkey; Type: FK CONSTRAINT; Schema: app; Owner: -
--

ALTER TABLE ONLY app.project_services
    ADD CONSTRAINT project_services_service_id_fkey FOREIGN KEY (service_id) REFERENCES app.services(id);


--
-- Name: projects projects_owner_id_fkey; Type: FK CONSTRAINT; Schema: app; Owner: -
--

ALTER TABLE ONLY app.projects
    ADD CONSTRAINT projects_owner_id_fkey FOREIGN KEY (owner_id) REFERENCES app.users(id);


--
-- Name: notes authz_delete; Type: POLICY; Schema: app; Owner: -
--

CREATE POLICY authz_delete ON app.notes FOR DELETE TO conf_app USING ((( SELECT authz_int.scope_cmd('app.notes'::text, 'delete'::text) AS scope_cmd) AND (COALESCE((author_id = ( SELECT authz.uid() AS uid)), false) OR (EXISTS ( SELECT 1
   FROM authz_int.project__owner v
  WHERE (v.id = notes.project_id))))));


--
-- Name: POLICY authz_delete ON notes; Type: COMMENT; Schema: app; Owner: -
--

COMMENT ON POLICY authz_delete ON app.notes IS 'rowstile';


--
-- Name: inbox authz_insert; Type: POLICY; Schema: app; Owner: -
--

CREATE POLICY authz_insert ON app.inbox FOR INSERT TO conf_app WITH CHECK (((( SELECT authz_int.scope_cmd('app.inbox'::text, 'insert'::text) AS scope_cmd) AND (COALESCE((( SELECT authz.uid() AS uid) IS NOT NULL), false) AND COALESCE((sender_id = ( SELECT authz.uid() AS uid)), false))) OR authz_gen."app.inbox:insert:refuse"(inbox.*)));


--
-- Name: POLICY authz_insert ON inbox; Type: COMMENT; Schema: app; Owner: -
--

COMMENT ON POLICY authz_insert ON app.inbox IS 'rowstile';


--
-- Name: notes authz_insert; Type: POLICY; Schema: app; Owner: -
--

CREATE POLICY authz_insert ON app.notes FOR INSERT TO conf_app WITH CHECK (((( SELECT authz_int.scope_cmd('app.notes'::text, 'insert'::text) AS scope_cmd) AND (COALESCE((author_id = ( SELECT authz.uid() AS uid)), false) AND (EXISTS ( SELECT 1
   FROM authz_int.project__edit v
  WHERE (v.id = notes.project_id))))) OR authz_gen."app.notes:insert:refuse"(notes.*)));


--
-- Name: POLICY authz_insert ON notes; Type: COMMENT; Schema: app; Owner: -
--

COMMENT ON POLICY authz_insert ON app.notes IS 'rowstile';


--
-- Name: folders authz_select; Type: POLICY; Schema: app; Owner: -
--

CREATE POLICY authz_select ON app.folders FOR SELECT TO conf_app USING ((( SELECT authz_int.scope_cmd('app.folders'::text, 'select'::text) AS scope_cmd) AND (COALESCE((owner_id = ( SELECT authz.uid() AS uid)), false) OR ((EXISTS ( SELECT 1
   FROM authz_int.folder__edit__direct v
  WHERE (v.id = folders.parent_id))) OR (EXISTS ( SELECT 1
   FROM authz_int.folder__edit v
  WHERE (v.id = folders.parent_id)))))));


--
-- Name: POLICY authz_select ON folders; Type: COMMENT; Schema: app; Owner: -
--

COMMENT ON POLICY authz_select ON app.folders IS 'rowstile';


--
-- Name: inbox authz_select; Type: POLICY; Schema: app; Owner: -
--

CREATE POLICY authz_select ON app.inbox FOR SELECT TO conf_app USING ((( SELECT authz_int.scope_cmd('app.inbox'::text, 'select'::text) AS scope_cmd) AND COALESCE((recipient_id = ( SELECT authz.uid() AS uid)), false)));


--
-- Name: POLICY authz_select ON inbox; Type: COMMENT; Schema: app; Owner: -
--

COMMENT ON POLICY authz_select ON app.inbox IS 'rowstile';


--
-- Name: notes authz_select; Type: POLICY; Schema: app; Owner: -
--

CREATE POLICY authz_select ON app.notes FOR SELECT TO conf_app USING ((( SELECT authz_int.scope_cmd('app.notes'::text, 'select'::text) AS scope_cmd) AND (EXISTS ( SELECT 1
   FROM authz_int.project__view v
  WHERE (v.id = notes.project_id)))));


--
-- Name: POLICY authz_select ON notes; Type: COMMENT; Schema: app; Owner: -
--

COMMENT ON POLICY authz_select ON app.notes IS 'rowstile';


--
-- Name: projects authz_select; Type: POLICY; Schema: app; Owner: -
--

CREATE POLICY authz_select ON app.projects FOR SELECT TO conf_app USING ((( SELECT authz_int.scope_cmd('app.projects'::text, 'select'::text) AS scope_cmd) AND (COALESCE((owner_id = ( SELECT authz.uid() AS uid)), false) OR COALESCE(public, false) OR (EXISTS ( SELECT 1
   FROM authz_int.project__member v
  WHERE (v.id = projects.id))) OR (EXISTS ( SELECT 1
   FROM authz_int.project__service v
  WHERE (v.id = projects.id))))));


--
-- Name: POLICY authz_select ON projects; Type: COMMENT; Schema: app; Owner: -
--

COMMENT ON POLICY authz_select ON app.projects IS 'rowstile';


--
-- Name: folders authz_update; Type: POLICY; Schema: app; Owner: -
--

CREATE POLICY authz_update ON app.folders FOR UPDATE TO conf_app USING ((( SELECT authz_int.scope_cmd('app.folders'::text, 'update'::text) AS scope_cmd) AND (COALESCE((owner_id = ( SELECT authz.uid() AS uid)), false) OR authz_int.folder__edit__has(parent_id)))) WITH CHECK (((( SELECT authz_int.scope_cmd('app.folders'::text, 'update'::text) AS scope_cmd) AND (COALESCE((owner_id = ( SELECT authz.uid() AS uid)), false) OR authz_int.folder__edit__has(parent_id))) OR authz_gen."app.folders:update:refuse"(folders.*)));


--
-- Name: POLICY authz_update ON folders; Type: COMMENT; Schema: app; Owner: -
--

COMMENT ON POLICY authz_update ON app.folders IS 'rowstile';


--
-- Name: notes authz_update; Type: POLICY; Schema: app; Owner: -
--

CREATE POLICY authz_update ON app.notes FOR UPDATE TO conf_app USING ((( SELECT authz_int.scope_cmd('app.notes'::text, 'update'::text) AS scope_cmd) AND (COALESCE((author_id = ( SELECT authz.uid() AS uid)), false) OR (EXISTS ( SELECT 1
   FROM authz_int.project__owner v
  WHERE (v.id = notes.project_id)))))) WITH CHECK (((( SELECT authz_int.scope_cmd('app.notes'::text, 'update'::text) AS scope_cmd) AND (COALESCE((author_id = ( SELECT authz.uid() AS uid)), false) OR (EXISTS ( SELECT 1
   FROM authz_int.project__owner v
  WHERE (v.id = notes.project_id))))) OR authz_gen."app.notes:update:refuse"(notes.*)));


--
-- Name: POLICY authz_update ON notes; Type: COMMENT; Schema: app; Owner: -
--

COMMENT ON POLICY authz_update ON app.notes IS 'rowstile';


--
-- Name: folders; Type: ROW SECURITY; Schema: app; Owner: -
--

ALTER TABLE app.folders ENABLE ROW LEVEL SECURITY;

--
-- Name: inbox; Type: ROW SECURITY; Schema: app; Owner: -
--

ALTER TABLE app.inbox ENABLE ROW LEVEL SECURITY;

--
-- Name: notes; Type: ROW SECURITY; Schema: app; Owner: -
--

ALTER TABLE app.notes ENABLE ROW LEVEL SECURITY;

--
-- Name: projects; Type: ROW SECURITY; Schema: app; Owner: -
--

ALTER TABLE app.projects ENABLE ROW LEVEL SECURITY;

--
-- PostgreSQL database dump complete
--

SET search_path TO "$user", public;

INSERT INTO "schema_migrations" (version) VALUES
('20261031122124'),
('20261030032030'),
('20261029214107'),
('20261001000000');


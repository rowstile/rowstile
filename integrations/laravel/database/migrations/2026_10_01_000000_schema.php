<?php

// The app's tables: projects with members, notes in them, a service that reads projects, an inbox people can write
// to but only the recipient reads, and folders inside folders; the queue's table (public.jobs), which the app's
// workers read. And the role the app connects as.

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;

return new class extends Migration
{
    public function up(): void
    {
        DB::unprepared(<<<'SQL'
            CREATE SCHEMA app;
            CREATE TABLE app.users (id bigint PRIMARY KEY, name text NOT NULL);
            CREATE TABLE app.services (id bigint PRIMARY KEY, name text NOT NULL);
            CREATE TABLE app.projects (
              id bigint PRIMARY KEY, owner_id bigint NOT NULL REFERENCES app.users, name text NOT NULL,
              public boolean NOT NULL DEFAULT false);
            CREATE TABLE app.members (
              project_id bigint REFERENCES app.projects, user_id bigint REFERENCES app.users,
              PRIMARY KEY (project_id, user_id));
            CREATE INDEX ON app.members (user_id);
            CREATE TABLE app.project_services (
              project_id bigint REFERENCES app.projects, service_id bigint REFERENCES app.services,
              PRIMARY KEY (project_id, service_id));
            CREATE INDEX ON app.project_services (service_id);
            CREATE TABLE app.notes (
              id bigserial PRIMARY KEY, project_id bigint NOT NULL REFERENCES app.projects,
              author_id bigint NOT NULL REFERENCES app.users, body text NOT NULL);
            CREATE INDEX ON app.notes (project_id);
            CREATE INDEX ON app.notes (author_id);
            CREATE TABLE app.inbox (
              id bigserial PRIMARY KEY, sender_id bigint NOT NULL REFERENCES app.users,
              recipient_id bigint NOT NULL REFERENCES app.users, body text NOT NULL);
            CREATE INDEX ON app.inbox (sender_id);
            CREATE INDEX ON app.inbox (recipient_id);
            CREATE TABLE app.folders (
              id bigint PRIMARY KEY, parent_id bigint REFERENCES app.folders,
              owner_id bigint NOT NULL REFERENCES app.users, name text NOT NULL);
            CREATE INDEX ON app.folders (parent_id);
            CREATE INDEX ON app.folders (owner_id);
            CREATE TABLE public.jobs (
              id bigserial PRIMARY KEY, queue text NOT NULL, payload text NOT NULL, attempts smallint NOT NULL,
              reserved_at integer, available_at integer NOT NULL, created_at integer NOT NULL);
            CREATE INDEX ON public.jobs (queue);
            SQL);
        DB::unprepared(<<<'SQL'
            DO $$ BEGIN
              IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'conf_app') THEN
                CREATE ROLE conf_app LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD 'app';
              END IF;
            END $$;
            GRANT USAGE ON SCHEMA app TO conf_app;
            GRANT SELECT ON ALL TABLES IN SCHEMA app TO conf_app;
            GRANT INSERT, UPDATE, DELETE ON app.notes, app.inbox TO conf_app;
            GRANT UPDATE ON app.folders TO conf_app;
            GRANT USAGE ON ALL SEQUENCES IN SCHEMA app TO conf_app;
            GRANT SELECT, INSERT, UPDATE, DELETE ON public.jobs TO conf_app;
            GRANT USAGE ON SEQUENCE public.jobs_id_seq TO conf_app;
            SQL);
    }

    public function down(): void
    {
        DB::unprepared('DROP SCHEMA app CASCADE; DROP TABLE public.jobs');
    }
};

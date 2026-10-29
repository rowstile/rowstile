-- the role the app connects as: not the owner, so row-level security applies to it
DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'conf_app') THEN
    CREATE ROLE conf_app LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD 'app';
  END IF;
END $$;
--> statement-breakpoint
GRANT USAGE ON SCHEMA "app" TO conf_app;
--> statement-breakpoint
GRANT SELECT ON ALL TABLES IN SCHEMA "app" TO conf_app;
--> statement-breakpoint
GRANT INSERT, UPDATE, DELETE ON "app"."notes", "app"."inbox" TO conf_app;
--> statement-breakpoint
GRANT UPDATE ON "app"."folders" TO conf_app;
--> statement-breakpoint
GRANT USAGE ON ALL SEQUENCES IN SCHEMA "app" TO conf_app;

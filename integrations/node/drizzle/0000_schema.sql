CREATE SCHEMA "app";
--> statement-breakpoint
CREATE TABLE "app"."folders" (
	"id" integer PRIMARY KEY NOT NULL,
	"parent_id" integer,
	"owner_id" integer NOT NULL,
	"name" text NOT NULL
);
--> statement-breakpoint
CREATE TABLE "app"."inbox" (
	"id" serial PRIMARY KEY NOT NULL,
	"sender_id" integer NOT NULL,
	"recipient_id" integer NOT NULL,
	"body" text NOT NULL
);
--> statement-breakpoint
CREATE TABLE "app"."members" (
	"project_id" integer NOT NULL,
	"user_id" integer NOT NULL,
	CONSTRAINT "members_project_id_user_id_pk" PRIMARY KEY("project_id","user_id")
);
--> statement-breakpoint
CREATE TABLE "app"."notes" (
	"id" serial PRIMARY KEY NOT NULL,
	"project_id" integer NOT NULL,
	"author_id" integer NOT NULL,
	"body" text NOT NULL
);
--> statement-breakpoint
CREATE TABLE "app"."project_services" (
	"project_id" integer NOT NULL,
	"service_id" integer NOT NULL,
	CONSTRAINT "project_services_project_id_service_id_pk" PRIMARY KEY("project_id","service_id")
);
--> statement-breakpoint
CREATE TABLE "app"."projects" (
	"id" integer PRIMARY KEY NOT NULL,
	"owner_id" integer NOT NULL,
	"name" text NOT NULL,
	"public" boolean DEFAULT false NOT NULL
);
--> statement-breakpoint
CREATE TABLE "app"."services" (
	"id" integer PRIMARY KEY NOT NULL,
	"name" text NOT NULL
);
--> statement-breakpoint
CREATE TABLE "app"."users" (
	"id" integer PRIMARY KEY NOT NULL,
	"name" text NOT NULL
);
--> statement-breakpoint
CREATE INDEX "folders_parent_id_idx" ON "app"."folders" USING btree ("parent_id");--> statement-breakpoint
CREATE INDEX "folders_owner_id_idx" ON "app"."folders" USING btree ("owner_id");--> statement-breakpoint
CREATE INDEX "inbox_sender_id_idx" ON "app"."inbox" USING btree ("sender_id");--> statement-breakpoint
CREATE INDEX "inbox_recipient_id_idx" ON "app"."inbox" USING btree ("recipient_id");--> statement-breakpoint
CREATE INDEX "members_user_id_idx" ON "app"."members" USING btree ("user_id");--> statement-breakpoint
CREATE INDEX "notes_project_id_idx" ON "app"."notes" USING btree ("project_id");--> statement-breakpoint
CREATE INDEX "notes_author_id_idx" ON "app"."notes" USING btree ("author_id");--> statement-breakpoint
CREATE INDEX "project_services_service_id_idx" ON "app"."project_services" USING btree ("service_id");--> statement-breakpoint
CREATE INDEX "projects_owner_id_idx" ON "app"."projects" USING btree ("owner_id");
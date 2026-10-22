-- CreateSchema
CREATE SCHEMA IF NOT EXISTS "app";

-- CreateTable
CREATE TABLE "app"."users" (
    "id" INTEGER NOT NULL,
    "name" TEXT NOT NULL,

    CONSTRAINT "users_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "app"."services" (
    "id" INTEGER NOT NULL,
    "name" TEXT NOT NULL,

    CONSTRAINT "services_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "app"."projects" (
    "id" INTEGER NOT NULL,
    "owner_id" INTEGER NOT NULL,
    "name" TEXT NOT NULL,
    "public" BOOLEAN NOT NULL DEFAULT false,

    CONSTRAINT "projects_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "app"."members" (
    "project_id" INTEGER NOT NULL,
    "user_id" INTEGER NOT NULL,

    CONSTRAINT "members_pkey" PRIMARY KEY ("project_id","user_id")
);

-- CreateTable
CREATE TABLE "app"."project_services" (
    "project_id" INTEGER NOT NULL,
    "service_id" INTEGER NOT NULL,

    CONSTRAINT "project_services_pkey" PRIMARY KEY ("project_id","service_id")
);

-- CreateTable
CREATE TABLE "app"."notes" (
    "id" SERIAL NOT NULL,
    "project_id" INTEGER NOT NULL,
    "author_id" INTEGER NOT NULL,
    "body" TEXT NOT NULL,

    CONSTRAINT "notes_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "app"."inbox" (
    "id" SERIAL NOT NULL,
    "sender_id" INTEGER NOT NULL,
    "recipient_id" INTEGER NOT NULL,
    "body" TEXT NOT NULL,

    CONSTRAINT "inbox_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "projects_owner_id_idx" ON "app"."projects"("owner_id");

-- CreateIndex
CREATE INDEX "members_user_id_idx" ON "app"."members"("user_id");

-- CreateIndex
CREATE INDEX "project_services_service_id_idx" ON "app"."project_services"("service_id");

-- CreateIndex
CREATE INDEX "notes_project_id_idx" ON "app"."notes"("project_id");

-- CreateIndex
CREATE INDEX "notes_author_id_idx" ON "app"."notes"("author_id");

-- CreateIndex
CREATE INDEX "inbox_sender_id_idx" ON "app"."inbox"("sender_id");

-- CreateIndex
CREATE INDEX "inbox_recipient_id_idx" ON "app"."inbox"("recipient_id");


-- the role the app connects as: not the owner, so row-level security applies to it
DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'conf_app') THEN
    CREATE ROLE conf_app LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD 'app';
  END IF;
END $$;
GRANT USAGE ON SCHEMA "app" TO conf_app;
GRANT SELECT ON ALL TABLES IN SCHEMA "app" TO conf_app;
GRANT INSERT, UPDATE, DELETE ON "app"."notes", "app"."inbox" TO conf_app;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA "app" TO conf_app;

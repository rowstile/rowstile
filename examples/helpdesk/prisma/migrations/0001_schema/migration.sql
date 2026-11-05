-- CreateSchema
CREATE SCHEMA IF NOT EXISTS "hd";

-- CreateTable
CREATE TABLE "hd"."workspaces" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "name" TEXT NOT NULL,
    "open_queue" BOOLEAN NOT NULL DEFAULT false,

    CONSTRAINT "workspaces_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "hd"."customer_orgs" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "workspace_id" UUID NOT NULL,
    "name" TEXT NOT NULL,
    "shared_tickets" BOOLEAN NOT NULL DEFAULT false,

    CONSTRAINT "customer_orgs_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "hd"."users" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "workspace_id" UUID,
    "kind" TEXT NOT NULL,
    "role" TEXT,
    "customer_org_id" UUID,
    "name" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "notes" TEXT,
    "active" BOOLEAN NOT NULL DEFAULT true,

    CONSTRAINT "users_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "hd"."logins" (
    "email" TEXT NOT NULL,
    "user_id" UUID NOT NULL,

    CONSTRAINT "logins_pkey" PRIMARY KEY ("email")
);

-- CreateTable
CREATE TABLE "hd"."teams" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "workspace_id" UUID NOT NULL,
    "parent_id" UUID,
    "name" TEXT NOT NULL,

    CONSTRAINT "teams_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "hd"."team_members" (
    "workspace_id" UUID NOT NULL,
    "team_id" UUID NOT NULL,
    "user_id" UUID NOT NULL,

    CONSTRAINT "team_members_pkey" PRIMARY KEY ("team_id","user_id")
);

-- CreateTable
CREATE TABLE "hd"."team_leads" (
    "workspace_id" UUID NOT NULL,
    "team_id" UUID NOT NULL,
    "user_id" UUID NOT NULL,

    CONSTRAINT "team_leads_pkey" PRIMARY KEY ("team_id","user_id")
);

-- CreateTable
CREATE TABLE "hd"."support_access" (
    "workspace_id" UUID NOT NULL,
    "staff_id" UUID NOT NULL,
    "until" TIMESTAMPTZ(6) NOT NULL,

    CONSTRAINT "support_access_pkey" PRIMARY KEY ("workspace_id","staff_id")
);

-- CreateTable
CREATE TABLE "hd"."integrations" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "workspace_id" UUID NOT NULL,
    "name" TEXT NOT NULL,
    "active" BOOLEAN NOT NULL DEFAULT true,

    CONSTRAINT "integrations_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "hd"."tickets" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "workspace_id" UUID NOT NULL,
    "subject" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'open',
    "requester_id" UUID NOT NULL,
    "team_id" UUID,
    "assignee_id" UUID,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "tickets_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "hd"."comments" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "ticket_id" UUID NOT NULL,
    "author_id" UUID,
    "integration_id" UUID,
    "internal" BOOLEAN NOT NULL DEFAULT false,
    "body" TEXT NOT NULL,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "comments_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "customer_orgs_workspace_id_id_key" ON "hd"."customer_orgs"("workspace_id", "id");

-- CreateIndex
CREATE INDEX "users_customer_org_id_idx" ON "hd"."users"("customer_org_id");

-- CreateIndex
CREATE UNIQUE INDEX "users_workspace_id_id_key" ON "hd"."users"("workspace_id", "id");

-- CreateIndex
CREATE UNIQUE INDEX "users_workspace_id_email_key" ON "hd"."users"("workspace_id", "email");

-- CreateIndex
CREATE UNIQUE INDEX "logins_user_id_key" ON "hd"."logins"("user_id");

-- CreateIndex
CREATE INDEX "teams_parent_id_idx" ON "hd"."teams"("parent_id");

-- CreateIndex
CREATE UNIQUE INDEX "teams_workspace_id_id_key" ON "hd"."teams"("workspace_id", "id");

-- CreateIndex
CREATE INDEX "team_members_user_id_idx" ON "hd"."team_members"("user_id");

-- CreateIndex
CREATE INDEX "team_leads_user_id_idx" ON "hd"."team_leads"("user_id");

-- CreateIndex
CREATE INDEX "support_access_staff_id_idx" ON "hd"."support_access"("staff_id");

-- CreateIndex
CREATE UNIQUE INDEX "integrations_workspace_id_id_key" ON "hd"."integrations"("workspace_id", "id");

-- CreateIndex
CREATE INDEX "tickets_workspace_id_status_idx" ON "hd"."tickets"("workspace_id", "status");

-- CreateIndex
CREATE INDEX "tickets_requester_id_idx" ON "hd"."tickets"("requester_id");

-- CreateIndex
CREATE INDEX "tickets_team_id_idx" ON "hd"."tickets"("team_id");

-- CreateIndex
CREATE INDEX "tickets_assignee_id_idx" ON "hd"."tickets"("assignee_id");

-- CreateIndex
CREATE INDEX "comments_ticket_id_idx" ON "hd"."comments"("ticket_id");

-- CreateIndex
CREATE INDEX "comments_author_id_idx" ON "hd"."comments"("author_id");

-- CreateIndex
CREATE INDEX "comments_integration_id_idx" ON "hd"."comments"("integration_id");

-- AddForeignKey
ALTER TABLE "hd"."customer_orgs" ADD CONSTRAINT "customer_orgs_workspace_id_fkey" FOREIGN KEY ("workspace_id") REFERENCES "hd"."workspaces"("id") ON DELETE RESTRICT ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "hd"."users" ADD CONSTRAINT "users_workspace_id_fkey" FOREIGN KEY ("workspace_id") REFERENCES "hd"."workspaces"("id") ON DELETE RESTRICT ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "hd"."users" ADD CONSTRAINT "users_workspace_id_customer_org_id_fkey" FOREIGN KEY ("workspace_id", "customer_org_id") REFERENCES "hd"."customer_orgs"("workspace_id", "id") ON DELETE RESTRICT ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "hd"."logins" ADD CONSTRAINT "logins_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "hd"."users"("id") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "hd"."teams" ADD CONSTRAINT "teams_workspace_id_fkey" FOREIGN KEY ("workspace_id") REFERENCES "hd"."workspaces"("id") ON DELETE RESTRICT ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "hd"."teams" ADD CONSTRAINT "teams_workspace_id_parent_id_fkey" FOREIGN KEY ("workspace_id", "parent_id") REFERENCES "hd"."teams"("workspace_id", "id") ON DELETE RESTRICT ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "hd"."team_members" ADD CONSTRAINT "team_members_workspace_id_team_id_fkey" FOREIGN KEY ("workspace_id", "team_id") REFERENCES "hd"."teams"("workspace_id", "id") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "hd"."team_members" ADD CONSTRAINT "team_members_workspace_id_user_id_fkey" FOREIGN KEY ("workspace_id", "user_id") REFERENCES "hd"."users"("workspace_id", "id") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "hd"."team_leads" ADD CONSTRAINT "team_leads_workspace_id_team_id_fkey" FOREIGN KEY ("workspace_id", "team_id") REFERENCES "hd"."teams"("workspace_id", "id") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "hd"."team_leads" ADD CONSTRAINT "team_leads_workspace_id_user_id_fkey" FOREIGN KEY ("workspace_id", "user_id") REFERENCES "hd"."users"("workspace_id", "id") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "hd"."support_access" ADD CONSTRAINT "support_access_workspace_id_fkey" FOREIGN KEY ("workspace_id") REFERENCES "hd"."workspaces"("id") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "hd"."support_access" ADD CONSTRAINT "support_access_staff_id_fkey" FOREIGN KEY ("staff_id") REFERENCES "hd"."users"("id") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "hd"."integrations" ADD CONSTRAINT "integrations_workspace_id_fkey" FOREIGN KEY ("workspace_id") REFERENCES "hd"."workspaces"("id") ON DELETE RESTRICT ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "hd"."tickets" ADD CONSTRAINT "tickets_workspace_id_fkey" FOREIGN KEY ("workspace_id") REFERENCES "hd"."workspaces"("id") ON DELETE RESTRICT ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "hd"."tickets" ADD CONSTRAINT "tickets_workspace_id_requester_id_fkey" FOREIGN KEY ("workspace_id", "requester_id") REFERENCES "hd"."users"("workspace_id", "id") ON DELETE RESTRICT ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "hd"."tickets" ADD CONSTRAINT "tickets_workspace_id_team_id_fkey" FOREIGN KEY ("workspace_id", "team_id") REFERENCES "hd"."teams"("workspace_id", "id") ON DELETE RESTRICT ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "hd"."tickets" ADD CONSTRAINT "tickets_workspace_id_assignee_id_fkey" FOREIGN KEY ("workspace_id", "assignee_id") REFERENCES "hd"."users"("workspace_id", "id") ON DELETE RESTRICT ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "hd"."comments" ADD CONSTRAINT "comments_ticket_id_fkey" FOREIGN KEY ("ticket_id") REFERENCES "hd"."tickets"("id") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "hd"."comments" ADD CONSTRAINT "comments_author_id_fkey" FOREIGN KEY ("author_id") REFERENCES "hd"."users"("id") ON DELETE RESTRICT ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "hd"."comments" ADD CONSTRAINT "comments_integration_id_fkey" FOREIGN KEY ("integration_id") REFERENCES "hd"."integrations"("id") ON DELETE RESTRICT ON UPDATE RESTRICT;

-- What Prisma's schema can't say, written by hand.
-- A user is an agent (admin or not) or a customer of one workspace, or the vendor's staff (of none).
ALTER TABLE "hd"."users" ADD CONSTRAINT "users_kind" CHECK (kind IN ('agent', 'customer', 'staff')),
  ADD CONSTRAINT "users_staff_of_no_workspace" CHECK ((kind = 'staff') = (workspace_id IS NULL)),
  ADD CONSTRAINT "users_role" CHECK ((kind = 'agent') = (role IS NOT NULL) AND (role IS NULL OR role IN ('admin', 'agent'))),
  ADD CONSTRAINT "users_org_for_customers" CHECK (kind = 'customer' OR customer_org_id IS NULL);
ALTER TABLE "hd"."tickets" ADD CONSTRAINT "tickets_status" CHECK (status IN ('open', 'pending', 'solved', 'closed'));
ALTER TABLE "hd"."comments" ADD CONSTRAINT "comments_one_author" CHECK ((author_id IS NULL) <> (integration_id IS NULL));

-- the conditions the policy calls on a share being made (shared if): the person is of the ticket's workspace; the
-- person is the vendor's staff
CREATE FUNCTION "hd"."same_workspace"(ticket uuid, person text) RETURNS boolean LANGUAGE sql STABLE AS $$
  SELECT EXISTS (SELECT 1 FROM hd.tickets t JOIN hd.users u ON u.workspace_id = t.workspace_id
                 WHERE t.id = ticket AND u.id::text = person)
$$;
CREATE FUNCTION "hd"."is_staff"(person text) RETURNS boolean LANGUAGE sql STABLE AS $$
  SELECT EXISTS (SELECT 1 FROM hd.users u WHERE u.id::text = person AND u.kind = 'staff')
$$;

-- The app connects as hd_app, which row-level security applies to (the password is test.sh's and Compose's; a
-- real deployment sets its own). Electric's role, hd_electric, is made by whoever runs the database, as a
-- superuser: it needs REPLICATION and BYPASSRLS (db/electric.sql).
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'hd_app') THEN
    CREATE ROLE hd_app LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD 'hd_app';
  END IF;
END $$;
GRANT USAGE ON SCHEMA "hd" TO hd_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA "hd" TO hd_app;
-- the logins: read to sign someone in, written by no one but the owner (a sign-up flow would be the app's own)
REVOKE INSERT, UPDATE, DELETE ON "hd"."logins" FROM hd_app;

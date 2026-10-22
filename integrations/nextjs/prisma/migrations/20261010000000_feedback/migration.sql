-- Feedback on a project (a model with no @@map, in the app schema: its table is its name), which the app role
-- may read and write; the policy says who may (its migration comes after this one)
-- CreateTable
CREATE TABLE "app"."feedback" (
    "id" SERIAL NOT NULL,
    "project_id" INTEGER NOT NULL,
    "author_id" INTEGER NOT NULL,
    "body" TEXT NOT NULL,

    CONSTRAINT "feedback_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "feedback_project_id_idx" ON "app"."feedback"("project_id");

-- CreateIndex
CREATE INDEX "feedback_author_id_idx" ON "app"."feedback"("author_id");


GRANT SELECT, INSERT ON "app"."feedback" TO conf_app;
GRANT USAGE ON SEQUENCE "app"."feedback_id_seq" TO conf_app;

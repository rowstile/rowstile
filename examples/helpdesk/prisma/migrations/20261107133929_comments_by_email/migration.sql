-- A comment is a person's, an integration's (a mail from no one the workspace knows), or both: a person's mail,
-- which the email intake writes, names its sender as its author.
ALTER TABLE "hd"."comments" DROP CONSTRAINT "comments_one_author",
  ADD CONSTRAINT "comments_author" CHECK (author_id IS NOT NULL OR integration_id IS NOT NULL);

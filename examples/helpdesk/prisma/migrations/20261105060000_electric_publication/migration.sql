-- Electric's publication, in manual mode: its role (hd_electric, db/electric.sql) owns no table, so it can't add one
-- to a publication or set its replica identity. It holds the synced tables and the sync index's tables their
-- shapes' filters read: the readers of each synced table, and the keys each principal holds.
ALTER TABLE "hd"."tickets" REPLICA IDENTITY FULL;
ALTER TABLE "hd"."comments" REPLICA IDENTITY FULL;
GRANT USAGE ON SCHEMA "hd" TO hd_electric;
GRANT SELECT ON "hd"."tickets", "hd"."comments" TO hd_electric;
CREATE PUBLICATION electric_publication_default FOR TABLE "hd"."tickets", "hd"."comments", authz_sync.keys,
  authz_sync.ticket__readers, authz_sync.comment__readers;

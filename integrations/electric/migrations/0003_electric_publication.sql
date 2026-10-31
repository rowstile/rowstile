-- Electric's publication, in manual mode: Electric's role owns no table, so it can't add one to a publication or
-- set its replica identity. It holds the synced tables and the sync index's tables their shapes' filters read
-- (the readers of each synced table, and the keys each principal holds). The notes aren't in it: Electric asks
-- for every column of the old row (REPLICA IDENTITY FULL), so a publication of the notes would carry the body the
-- policy masks, and authz.lint() would say so.
CREATE PUBLICATION electric_publication_default FOR TABLE app.files, app.folders, authz_sync.keys,
  authz_sync.file__readers, authz_sync.folder__readers;

-- PowerSync's publication (it must be named powersync): the mirrors of the synced tables (each row, but the columns
-- the policy masks, with its readers) and the keys each principal holds, which the streams read. The service's role
-- reads them (the policy grants it the index) and nothing of the app's tables.
CREATE PUBLICATION powersync FOR TABLE authz_sync.file__mirror, authz_sync.folder__mirror, authz_sync.note__mirror,
  authz_sync.keys;

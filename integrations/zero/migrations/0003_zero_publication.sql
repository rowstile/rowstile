-- Zero's publication (zero-cache reads it as ZERO_APP_PUBLICATIONS): the synced tables, of the notes every column
-- but the body the policy masks, and the sync index's tables their filters read (the readers of each synced table,
-- and the keys each principal holds). zero-cache makes its own schemas beside them (zero, zero_0, ...): its role may
-- create in the database, and owns no table of the app's.
CREATE PUBLICATION zero_data FOR TABLE app.files, app.folders, app.notes (id, file_id, author_id), authz_sync.keys,
  authz_sync.file__readers, authz_sync.folder__readers, authz_sync.note__readers;
DO $$ BEGIN EXECUTE format('GRANT CREATE ON DATABASE %I TO conf_zero', current_database()); END $$;

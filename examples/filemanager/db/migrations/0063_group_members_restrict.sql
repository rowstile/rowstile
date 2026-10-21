-- 0063: deleting a group no longer deletes its members by itself. The app removes them first, through the rules
-- (main.py, delete_group), and a foreign key's action would skip them: rowstile warns of one on a governed table.
ALTER TABLE fm.group_members DROP CONSTRAINT group_members_group_id_fkey,
  ADD CONSTRAINT group_members_group_id_fkey FOREIGN KEY (group_id) REFERENCES fm.groups ON DELETE RESTRICT;

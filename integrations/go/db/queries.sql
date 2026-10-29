-- The app's queries, which sqlc turns into Go (internal/db). None checks a permission: they run in a transaction
-- rowstile.Tx signed in, and the database filters what they read and refuses what they may not write.

-- name: NoteIDs :many
SELECT id FROM app.notes ORDER BY id;

-- name: ProjectIDs :many
SELECT id FROM app.projects ORDER BY id;

-- name: EditableProjectIDs :many
-- the projects the user may edit: a join on the ids authz.list gives, in the query
SELECT p.id FROM app.projects p JOIN authz.list('project', 'edit') x ON x = p.id::text ORDER BY p.id;

-- name: CountProjects :one
SELECT count(*) FROM app.projects;

-- name: AddNote :one
INSERT INTO app.notes (project_id, author_id, body) VALUES ($1, $2, $3) RETURNING id;

-- name: EditNote :execrows
UPDATE app.notes SET body = $2 WHERE id = $1;

-- name: DeleteNote :execrows
DELETE FROM app.notes WHERE id = $1;

-- name: SendMessage :one
INSERT INTO app.inbox (sender_id, recipient_id, body) VALUES ($1, $2, $3) RETURNING id;

-- name: SendQuietly :exec
INSERT INTO app.inbox (sender_id, recipient_id, body) VALUES ($1, $2, $3);

-- name: MoveFolder :execrows
UPDATE app.folders SET parent_id = $2 WHERE id = $1;

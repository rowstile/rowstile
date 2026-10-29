package rowstile

import (
	"context"

	"github.com/jackc/pgx/v5"
)

// Permission is a permission of a type the policy declares, as `rowstile client go` writes them:
// authz.NoteEdit, of the type authz.NotePermission, whose ObjectType is "note". A plain string is none, so a
// misspelled name doesn't build.
type Permission interface {
	~string
	ObjectType() string
}

// Rows is what runs a query and gives its rows: a pgx.Tx, a *pgxpool.Pool, a *pgx.Conn, or sqlc's DBTX.
type Rows interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// Can says whether whoever q's transaction signed in as holds perm on the object with this id:
// Can(ctx, tx, authz.NoteEdit, 7).
func Can[P Permission](ctx context.Context, q Querier, perm P, id any) (bool, error) {
	var ok bool
	err := q.QueryRow(ctx, "SELECT authz.can($1, $2::text, $3)", perm.ObjectType(), keyText(id), string(perm)).Scan(&ok)
	return ok, translate(err)
}

// PermsOf is the permissions held on each of these objects, by id as the database writes it, in one call (a
// list's buttons): PermsOf[authz.ProjectPermission](ctx, tx, ids).
func PermsOf[P Permission, ID any](ctx context.Context, q Rows, ids []ID) (map[string][]P, error) {
	var kind P
	texts := make([]string, len(ids))
	for i, id := range ids {
		texts[i] = keyText(id)
	}
	rows, _ := q.Query(ctx, "SELECT id, perms FROM authz.perms_of($1, $2::text[])", kind.ObjectType(), texts)
	out := map[string][]P{}
	var id string
	var perms []string
	_, err := pgx.ForEachRow(rows, []any{&id, &perms}, func() error {
		out[id] = make([]P, len(perms))
		for i, p := range perms {
			out[id][i] = P(p)
		}
		return nil
	})
	if err != nil {
		return nil, translate(err)
	}
	return out, nil
}

// Page is a page of List: the ids after After (nil: from the first), Limit of them.
type Page struct {
	After any
	Limit int
}

// List is the ids of the objects of perm's type on which whoever q's transaction signed in as holds perm, in key
// order; with a page, that page alone (the database says when its size or its cursor is wrong: *CallError, 400).
// To filter a query to them instead, join authz.list(type, perm) in it.
func List[P Permission](ctx context.Context, q Rows, perm P, page *Page) ([]string, error) {
	args := []any{perm.ObjectType(), string(perm), nil, nil}
	if page != nil {
		args[3] = page.Limit
		if page.After != nil {
			args[2] = keyText(page.After)
		}
	}
	rows, _ := q.Query(ctx, "SELECT x FROM authz.list($1, $2, $3, $4) x", args...)
	ids, err := pgx.CollectRows(rows, pgx.RowTo[string])
	return ids, translate(err)
}

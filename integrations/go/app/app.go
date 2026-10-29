// Package app is the conformance app: no permission checks anywhere. rowstile signs each request's transactions
// in, the database filters reads and refuses writes, and the SDK turns refusals into 403 and hidden rows into 404.
package app

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	rowstile "github.com/rowstile/rowstile/sdk/go"

	"github.com/rowstile/rowstile/integrations/go/internal/authz"
	"github.com/rowstile/rowstile/integrations/go/internal/db"
)

// signedIn is the user the request acts for (the middleware set it from sessionUser), as the tables' key.
func signedIn(ctx context.Context) int64 {
	who, _ := rowstile.Current(ctx)
	id, _ := strconv.ParseInt(who.ID, 10, 64)
	return id
}

// reply writes v as JSON with this status.
func reply(w http.ResponseWriter, status int, v any) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	return json.NewEncoder(w).Encode(v)
}

// ids is a list for JSON: [] when there is none.
func ids(list []int64) []int64 {
	if list == nil {
		return []int64{}
	}
	return list
}

// New is the app's routes, on a pool of the app role's connections.
func New(pool *pgxpool.Pool) http.Handler {
	mux := http.NewServeMux()
	route := func(pattern string, fn func(w http.ResponseWriter, r *http.Request) error) {
		mux.Handle(pattern, rowstile.Handler(fn))
	}

	route("GET /notes", func(w http.ResponseWriter, r *http.Request) error {
		var notes []int64
		err := rowstile.Tx(r.Context(), pool, func(ctx context.Context, tx pgx.Tx) (err error) {
			notes, err = db.New(tx).NoteIDs(ctx)
			return err
		})
		if err != nil {
			return err
		}
		return reply(w, http.StatusOK, ids(notes))
	})

	route("GET /projects", func(w http.ResponseWriter, r *http.Request) error {
		var projects []int64
		err := rowstile.Tx(r.Context(), pool, func(ctx context.Context, tx pgx.Tx) (err error) {
			projects, err = db.New(tx).ProjectIDs(ctx)
			return err
		})
		if err != nil {
			return err
		}
		return reply(w, http.StatusOK, ids(projects))
	})

	route("GET /projects/editable", func(w http.ResponseWriter, r *http.Request) error {
		var projects []int64
		err := rowstile.Tx(r.Context(), pool, func(ctx context.Context, tx pgx.Tx) (err error) {
			projects, err = db.New(tx).EditableProjectIDs(ctx) // a join on authz.list('project', 'edit')
			return err
		})
		if err != nil {
			return err
		}
		return reply(w, http.StatusOK, ids(projects))
	})

	route("GET /projects/buttons", func(w http.ResponseWriter, r *http.Request) error {
		var buttons map[string][]authz.ProjectPermission
		err := rowstile.Tx(r.Context(), pool, func(ctx context.Context, tx pgx.Tx) error {
			projects, err := db.New(tx).ProjectIDs(ctx)
			if err == nil {
				buttons, err = rowstile.PermsOf[authz.ProjectPermission](ctx, tx, projects)
			}
			return err
		})
		if err != nil {
			return err
		}
		return reply(w, http.StatusOK, buttons)
	})

	route("GET /projects/page", func(w http.ResponseWriter, r *http.Request) error {
		// the projects the user may see, a page at a time: the database says when the size or the cursor is wrong
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		page := &rowstile.Page{Limit: limit}
		if r.URL.Query().Has("after") {
			page.After = r.URL.Query().Get("after")
		}
		var listed []string
		err := rowstile.Tx(r.Context(), pool, func(ctx context.Context, tx pgx.Tx) (err error) {
			listed, err = rowstile.List(ctx, tx, authz.ProjectView, page)
			return err
		})
		if err != nil {
			return err
		}
		return reply(w, http.StatusOK, listed)
	})

	route("DELETE /keys/{id}", func(w http.ResponseWriter, r *http.Request) error {
		// one of the user's API keys: someone else's, or one that isn't there, is 404
		err := rowstile.Tx(r.Context(), pool, func(ctx context.Context, tx pgx.Tx) error {
			_, err := tx.Exec(ctx, "SELECT 1 FROM authz.revoke_api_key($1::bigint)", r.PathValue("id"))
			return err
		})
		if err != nil {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	})

	route("POST /keys", func(w http.ResponseWriter, r *http.Request) error {
		// an API key, for the user or a principal whose keys they manage; a request that brings a key (x-api-key)
		// signs in with it first, in the same transaction: the database says who may make which
		var k struct {
			Name          string  `json:"name"`
			PrincipalType *string `json:"principal_type"`
			PrincipalID   *string `json:"principal_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&k); err != nil {
			return err
		}
		var key string
		err := rowstile.Tx(r.Context(), pool, func(ctx context.Context, tx pgx.Tx) error {
			if apiKey := r.Header.Get("x-api-key"); apiKey != "" {
				if _, err := tx.Exec(ctx, "SELECT authz.login_key($1)", apiKey); err != nil {
					return err
				}
			}
			made := "SELECT authz.create_api_key($1, '', NULL, $2::text, $3::text)"
			return tx.QueryRow(ctx, made, k.Name, k.PrincipalType, k.PrincipalID).Scan(&key)
		})
		if err != nil {
			return err
		}
		return reply(w, http.StatusCreated, map[string]string{"key": key})
	})

	route("GET /projects/{id}/shares", func(w http.ResponseWriter, r *http.Request) error {
		var subjects []string
		err := rowstile.Tx(r.Context(), pool, func(ctx context.Context, tx pgx.Tx) error {
			rows, _ := tx.Query(ctx, "SELECT subject_id FROM authz.list_shares('project', $1::text)", r.PathValue("id"))
			var err error
			subjects, err = pgx.CollectRows(rows, pgx.RowTo[string])
			return err
		})
		if err != nil {
			return err
		}
		return reply(w, http.StatusOK, subjects)
	})

	route("POST /projects/{id}/requests", func(w http.ResponseWriter, r *http.Request) error {
		// access asked for: the policy shares no relation of a project, so this is the app's mistake (a 500), once
		// the database knows who asks
		var a struct{ Relation, Reason string }
		if err := json.NewDecoder(r.Body).Decode(&a); err != nil {
			return err
		}
		var id int64
		err := rowstile.Tx(r.Context(), pool, func(ctx context.Context, tx pgx.Tx) error {
			asked := "SELECT authz.request_access('project', $1::text, $2, $3)"
			return tx.QueryRow(ctx, asked, r.PathValue("id"), a.Relation, a.Reason).Scan(&id)
		})
		if err != nil {
			return err
		}
		return reply(w, http.StatusCreated, map[string]int64{"id": id})
	})

	route("GET /notes/as/{user}", func(w http.ResponseWriter, r *http.Request) error {
		// who is signed in, changed by hand: the database doesn't believe it (the app's bug, a 500)
		return rowstile.Tx(r.Context(), pool, func(ctx context.Context, tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, "SELECT set_config('authz.user_id', $1, true)", r.PathValue("user")); err != nil {
				return err
			}
			_, err := db.New(tx).NoteIDs(ctx)
			return err
		})
	})

	route("PATCH /folders/{id}", func(w http.ResponseWriter, r *http.Request) error {
		// inside one of its own subfolders: 409, the database's words
		id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
		var m struct {
			ParentID pgtype.Int8 `json:"parent_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&m); err != nil {
			return err
		}
		err := rowstile.Tx(r.Context(), pool, func(ctx context.Context, tx pgx.Tx) error {
			moved, err := db.New(tx).MoveFolder(ctx, db.MoveFolderParams{ID: id, ParentID: m.ParentID})
			if err != nil {
				return err
			}
			return rowstile.Expect(ctx, tx, moved, "app.folders", "update", id)
		})
		if err != nil {
			return err
		}
		return reply(w, http.StatusOK, map[string]int64{"id": id})
	})

	route("POST /notes", func(w http.ResponseWriter, r *http.Request) error {
		var n struct {
			ProjectID int64  `json:"project_id"`
			Body      string `json:"body"`
		}
		if err := json.NewDecoder(r.Body).Decode(&n); err != nil {
			return err
		}
		var id int64
		err := rowstile.Tx(r.Context(), pool, func(ctx context.Context, tx pgx.Tx) (err error) {
			id, err = db.New(tx).AddNote(ctx, db.AddNoteParams{ProjectID: n.ProjectID, AuthorID: signedIn(ctx), Body: n.Body})
			return err // a refused insert: 403, with the rule and the reason
		})
		if err != nil {
			return err
		}
		return reply(w, http.StatusCreated, map[string]int64{"id": id})
	})

	route("PATCH /notes/{id}", func(w http.ResponseWriter, r *http.Request) error {
		id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
		var b struct {
			Body string `json:"body"`
		}
		if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
			return err
		}
		err := rowstile.Tx(r.Context(), pool, func(ctx context.Context, tx pgx.Tx) error {
			changed, err := db.New(tx).EditNote(ctx, db.EditNoteParams{ID: id, Body: b.Body})
			if err != nil {
				return err
			}
			// 0 rows: Expect asks the database why, and answers 404 (hidden) or 403 (with the reason)
			return rowstile.Expect(ctx, tx, changed, "app.notes", "update", id)
		})
		if err != nil {
			return err
		}
		return reply(w, http.StatusOK, map[string]int64{"id": id})
	})

	route("DELETE /notes/{id}", func(w http.ResponseWriter, r *http.Request) error {
		id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
		err := rowstile.Tx(r.Context(), pool, func(ctx context.Context, tx pgx.Tx) error {
			deleted, err := db.New(tx).DeleteNote(ctx, id)
			if err != nil {
				return err
			}
			return rowstile.Expect(ctx, tx, deleted, "app.notes", "delete", id)
		})
		if err != nil {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	})

	type message struct {
		RecipientID int64  `json:"recipient_id"`
		Body        string `json:"body"`
	}

	route("POST /inbox", func(w http.ResponseWriter, r *http.Request) error {
		var m message
		if err := json.NewDecoder(r.Body).Decode(&m); err != nil {
			return err
		}
		var id int64
		err := rowstile.Tx(r.Context(), pool, func(ctx context.Context, tx pgx.Tx) (err error) {
			sent := db.SendMessageParams{SenderID: signedIn(ctx), RecipientID: m.RecipientID, Body: m.Body}
			id, err = db.New(tx).SendMessage(ctx, sent) // reads the id back (RETURNING): only the recipient may read it
			return err
		})
		if err != nil {
			return err
		}
		return reply(w, http.StatusCreated, map[string]int64{"id": id})
	})

	route("POST /inbox/quietly", func(w http.ResponseWriter, r *http.Request) error {
		// without reading the row back
		var m message
		if err := json.NewDecoder(r.Body).Decode(&m); err != nil {
			return err
		}
		err := rowstile.Tx(r.Context(), pool, func(ctx context.Context, tx pgx.Tx) error {
			sent := db.SendQuietlyParams{SenderID: signedIn(ctx), RecipientID: m.RecipientID, Body: m.Body}
			return db.New(tx).SendQuietly(ctx, sent)
		})
		if err != nil {
			return err
		}
		return reply(w, http.StatusAccepted, map[string]any{})
	})

	return rowstile.Middleware(sessionUser)(mux)
}

// Digest is a background job: it signs in as service 1, whatever started it, and counts the projects it may read.
func Digest(ctx context.Context, pool *pgxpool.Pool) (int64, error) {
	var count int64
	err := rowstile.TxAs(ctx, pool, rowstile.As("service", "1"), func(ctx context.Context, tx pgx.Tx) (err error) {
		count, err = db.New(tx).CountProjects(ctx)
		return err
	})
	return count, err
}

package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rowstile/rowstile/sdk/go/rowstiletest"
)

// This package's own copy of the migrated test database (check 12: go test runs each package in a process of its
// own, side by side, so each package is a worker), the app role's pool on it, and the app.
var (
	copied  rowstiletest.Database
	pool    *pgxpool.Pool
	handler http.Handler
)

// the same few rows for every test: ann (1) owns project 1 (cy is a member, service 1 reads it) and the public
// project 3; bo (2) owns project 2. Ann's folder 1 has folder 2 inside it.
const data = `
TRUNCATE app.folders, app.inbox, app.notes, app.members, app.project_services, app.projects, app.services,
  app.users CASCADE;
INSERT INTO app.users VALUES (1, 'ann'), (2, 'bo'), (3, 'cy');
INSERT INTO app.services VALUES (1, 'digest');
INSERT INTO app.projects VALUES (1, 1, 'Plans', false), (2, 2, 'Bo''s', false), (3, 1, 'Open', true);
INSERT INTO app.members VALUES (1, 3);
INSERT INTO app.project_services VALUES (1, 1);
INSERT INTO app.notes (id, project_id, author_id, body) VALUES
  (1, 1, 1, 'plan'), (2, 2, 2, 'mine'), (3, 3, 1, 'hello'), (4, 1, 3, 'idea');
SELECT setval(pg_get_serial_sequence('app.notes', 'id'), 100);
INSERT INTO app.folders VALUES (1, NULL, 1, 'top'), (2, 1, 1, 'inside');`

func TestMain(m *testing.M) {
	ctx := context.Background()
	tests := os.Getenv("ROWSTILE_TESTS_URL")
	if tests == "" {
		fmt.Println("ROWSTILE_TESTS_URL is not set (test.sh sets it): the checks need a database")
		os.Exit(1)
	}
	var err error
	if copied, err = rowstiletest.PerPackage(ctx, tests, os.Getenv("ROWSTILE_APP_URL"), true); err == nil {
		err = asOwner(ctx, data)
	}
	if err == nil {
		pool, err = pgxpool.New(ctx, copied.AppURL)
	}
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	handler = New(pool)
	code := m.Run()
	pool.Close()
	os.Exit(code)
}

// asOwner runs SQL on this package's database as the tables' owner.
func asOwner(ctx context.Context, sql string) error {
	conn, err := pgx.Connect(ctx, copied.URL)
	if err != nil {
		return err
	}
	defer conn.Close(ctx)
	_, err = conn.Exec(ctx, sql)
	return err
}

// check prints the check's line once the test ends, as the other suites print theirs: ok, or FAIL.
func check(t *testing.T, what string) {
	t.Cleanup(func() {
		if t.Failed() {
			fmt.Println("FAIL  " + what)
		} else {
			fmt.Println("ok    " + what)
		}
	})
}

// answer is a response: its status, its content type and its body.
type answer struct {
	status int
	kind   string
	body   []byte
}

// Answer is a response's JSON, as the checks compare it.
type Answer = any

func (a answer) json(t *testing.T) Answer {
	t.Helper()
	var v Answer
	if err := json.Unmarshal(a.body, &v); err != nil {
		t.Fatalf("not JSON (%d): %s", a.status, a.body)
	}
	return v
}

// call sends a request to the app, as user (a user's id; "" is nobody), with headers and a JSON body (nil: none).
func call(h http.Handler, method, path, user string, body any, headers ...string) answer {
	var b bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&b).Encode(body)
	}
	r := httptest.NewRequest(method, path, &b)
	if user != "" {
		r.Header.Set("x-user", user)
	}
	for i := 0; i+1 < len(headers); i += 2 {
		r.Header.Set(headers[i], headers[i+1])
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return answer{w.Code, w.Header().Get("Content-Type"), w.Body.Bytes()}
}

// logged is what the app logs while fn runs (rowstile.Handler logs the errors it answers 500), each record's error.
func logged(fn func()) []error {
	keep := &records{}
	before := slog.Default()
	slog.SetDefault(slog.New(keep))
	defer slog.SetDefault(before)
	fn()
	return keep.errors
}

type records struct{ errors []error }

func (r *records) Enabled(context.Context, slog.Level) bool { return true }
func (r *records) WithAttrs([]slog.Attr) slog.Handler       { return r }
func (r *records) WithGroup(string) slog.Handler            { return r }
func (r *records) Handle(_ context.Context, rec slog.Record) error {
	rec.Attrs(func(a slog.Attr) bool {
		if err, ok := a.Value.Any().(error); ok && a.Key == "error" {
			r.errors = append(r.errors, err)
		}
		return true
	})
	return nil
}

// numbers is a JSON list of ids, as the checks compare them.
func numbers(ids ...float64) Answer {
	out := make([]any, len(ids))
	for i, id := range ids {
		out[i] = id
	}
	return out
}

func equal(a, b Answer) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return slices.Equal(x, y)
}

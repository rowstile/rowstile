// Package rowstiletest is the rowstile SDK's help for an app's tests (a preview: it may change in any release):
// a copy of the migrated test database for each test package, and assertions on refusals.
//
//	func TestMain(m *testing.M) {
//		db, err := rowstiletest.PerPackage(context.Background(), os.Getenv("TESTS_URL"), os.Getenv("APP_URL"), true)
//		if err != nil {
//			log.Fatal(err)
//		}
//		... // db.URL, the owner's, and db.AppURL, the app role's
//		os.Exit(m.Run())
//	}
//
// go test runs the tests of each package in a process of its own, packages side by side (-p): each package is a
// worker, and gets its own database, named after the one it copies and the package. Tests of one package share
// it, t.Parallel() ones too.
package rowstiletest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	rowstile "github.com/rowstile/rowstile/sdk/go"
)

// Database is a test package's own database: its URL (the owner's), and the app role's if one was given.
type Database struct {
	URL    string
	AppURL string
}

// Worker is this test binary's name for its database: its package's last name and a short hash of its import
// path (two packages named app in different folders get two), as go test built it; "go" elsewhere.
func Worker() string {
	path := "go"
	if info, ok := debug.ReadBuildInfo(); ok && info.Path != "" {
		path = strings.TrimSuffix(info.Path, ".test")
	}
	sum := sha256.Sum256([]byte(path))
	last := regexp.MustCompile(`[^a-z0-9]+`).ReplaceAllString(strings.ToLower(filepath.Base(path)), "_")
	return last + "_" + hex.EncodeToString(sum[:])[:8]
}

func withDatabase(u *url.URL, name string) string {
	c := *u
	c.Path, c.RawPath = "/"+name, ""
	return c.String()
}

// PerPackage copies the migrated test database testsURL names (with the policy) for this test package, and gives
// its URL, the same user's, and appURL's for it (if given). The copy is made by a role that may create databases
// (the owner), while nothing else is connected to the original. A copy an earlier run left is made again, unless
// fresh is false.
func PerPackage(ctx context.Context, testsURL, appURL string, fresh bool) (Database, error) {
	u, err := url.Parse(testsURL)
	template := strings.TrimPrefix(u.Path, "/")
	if err != nil || template == "" {
		return Database{}, fmt.Errorf("rowstiletest: %q is not a URL that names a database to copy", testsURL)
	}
	name := template + "_" + Worker()
	ident := pgx.Identifier{name}.Sanitize()
	// CREATE DATABASE ... TEMPLATE needs no one connected to the original, this connection included
	conn, err := pgx.Connect(ctx, withDatabase(u, "postgres"))
	if err != nil {
		return Database{}, err
	}
	defer conn.Close(context.WithoutCancel(ctx))
	var exists bool
	err = conn.QueryRow(ctx, "SELECT EXISTS (SELECT FROM pg_database WHERE datname = $1)", name).Scan(&exists)
	if err == nil && exists && fresh {
		_, err = conn.Exec(ctx, "DROP DATABASE "+ident+" WITH (FORCE)")
	}
	if err == nil && (fresh || !exists) {
		_, err = conn.Exec(ctx, "CREATE DATABASE "+ident+" TEMPLATE "+pgx.Identifier{template}.Sanitize())
	}
	if pg := (*pgconn.PgError)(nil); errors.As(err, &pg) && pg.Code == "55006" {
		// something is connected to the original (Postgres has waited five seconds for it to leave)
		err = fmt.Errorf("rowstiletest: %s can't be copied while anything is connected to it: close what holds it "+
			"(the app, a migration tool, a console). Where the service keeps a connection of its own for minutes "+
			"after yours (Neon does), a copy per package can't be made: use one test database, where each test "+
			"rolls back, or a branch for each run: %w", template, err)
	}
	if err != nil {
		return Database{}, err
	}
	db := Database{URL: withDatabase(u, name)}
	if app, err := url.Parse(appURL); appURL != "" && err == nil {
		db.AppURL = withDatabase(app, name)
	}
	return db, nil
}

// Refused is err as the refusal it must be (t fails at once otherwise): by command's rule, unless command is "".
func Refused(t testing.TB, err error, command string) *rowstile.Refused {
	t.Helper()
	var r *rowstile.Refused
	if !errors.As(err, &r) {
		t.Fatalf("expected a refusal, got %v", err)
	} else if command != "" && !strings.HasPrefix(r.Command, command) {
		t.Fatalf("expected the %s rule to refuse it, but: %s: %s", command, r.Command, r.Message)
	}
	return r
}

// NotFound is err as the *rowstile.NotFound it must be (t fails at once otherwise).
func NotFound(t testing.TB, err error) *rowstile.NotFound {
	t.Helper()
	var nf *rowstile.NotFound
	if !errors.As(err, &nf) {
		t.Fatalf("expected NotFound, got %v", err)
	}
	return nf
}

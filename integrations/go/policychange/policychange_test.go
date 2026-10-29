// Package policychange is check 14, in a package of its own: it gets its own copy of the migrated test database
// (go test runs it beside the app's package, each with its database: check 12), changes the policy, and migrates
// that copy.
package policychange

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/rowstile/rowstile/sdk/go/rowstiletest"
)

var copied rowstiletest.Database

func TestMain(m *testing.M) {
	var err error
	copied, err = rowstiletest.PerPackage(context.Background(), os.Getenv("ROWSTILE_TESTS_URL"), os.Getenv("ROWSTILE_APP_URL"), true)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	os.Exit(m.Run())
}

func check(t *testing.T, what string) {
	t.Cleanup(func() {
		if t.Failed() {
			fmt.Println("FAIL  " + what)
		} else {
			fmt.Println("ok    " + what)
		}
	})
}

// owner runs sql on this package's database as the tables' owner, and gives the first column of its first row
func owner(t *testing.T, sql string) string {
	t.Helper()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, copied.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	var got any
	if err := conn.QueryRow(ctx, sql).Scan(&got); err != nil && err != pgx.ErrNoRows {
		t.Fatal(err)
	}
	return fmt.Sprint(got)
}

// run runs a command in dir, with these variables added; t fails with what it said if it fails
func run(t *testing.T, dir string, env []string, name string, args ...string) string {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir, cmd.Env = dir, append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	}
	return string(out)
}

func TestCheck12EachPackageHasItsOwnCopy(t *testing.T) {
	check(t, "12: ... each package its own copy, kept with what the tests wrote, or copied again as migrated")
	ctx := context.Background()
	tests := os.Getenv("ROWSTILE_TESTS_URL")
	if !strings.Contains(copied.URL, "_policychange_") {
		t.Errorf("%s", copied.URL)
	}
	owner(t, "INSERT INTO app.users VALUES (1, 'ann'), (2, 'bo') RETURNING id")
	if kept, err := rowstiletest.PerPackage(ctx, tests, "", false); err != nil || kept.URL != copied.URL || kept.AppURL != "" {
		t.Errorf("%v %v", kept, err)
	}
	if n := owner(t, "SELECT count(*) FROM app.users"); n != "2" {
		t.Errorf("kept, with what the tests wrote: %s users", n)
	}
	if again, err := rowstiletest.PerPackage(ctx, tests, "", true); err != nil || again.URL != copied.URL {
		t.Errorf("%v %v", again, err)
	}
	if n := owner(t, "SELECT count(*) FROM app.users"); n != "0" {
		t.Errorf("copied again, as migrated: %s users", n)
	}
	// while anything is connected to the original, Postgres can't copy it, and says so: this package's copy as
	// the original, as the app's package may be copying the test database meanwhile
	conn, err := pgx.Connect(ctx, copied.URL)
	if err != nil {
		t.Fatal(err)
	}
	_, err = rowstiletest.PerPackage(ctx, copied.URL, "", true)
	conn.Close(ctx)
	if err == nil || !strings.Contains(err.Error(), "can't be copied while anything is connected to it") {
		t.Errorf("%v", err)
	}
}

// what the app's code does with the names the policy now makes: it names reply, and the database answers it
const replies = `package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	rowstile "github.com/rowstile/rowstile/sdk/go"

	"github.com/rowstile/rowstile/integrations/go/internal/authz"
)

func main() {
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	for _, user := range []string{"2", "1"} { // bo, to whom it is sent, may reply; ann, who sent it, may not even read it
		err := rowstile.TxAs(ctx, pool, rowstile.User(user), func(ctx context.Context, tx pgx.Tx) error {
			reply, err := rowstile.Can(ctx, tx, authz.MessageReply, os.Args[2])
			read, also := rowstile.Can(ctx, tx, authz.MessageRead, os.Args[2])
			fmt.Println(reply, read)
			return errors.Join(err, also)
		})
		if err != nil {
			log.Fatal(err)
		}
	}
}
`

func TestCheck14APolicyChangeShipsAsTheNextMigration(t *testing.T) {
	check(t, "14: after a policy change and a new migration, the app works with the new generated names")
	here, _ := filepath.Abs("..")
	sdk, _ := filepath.Abs("../../../sdk/go")
	work := filepath.Join(t.TempDir(), "app")
	if err := os.CopyFS(work, os.DirFS(here)); err != nil {
		t.Fatal(err)
	}
	policy := filepath.Join(work, "db", "policy.authz")
	text, err := os.ReadFile(policy)
	if err != nil {
		t.Fatal(err)
	}
	changed := strings.Replace(string(text), "  can read = recipient\n", "  can read = recipient\n  can reply = recipient\n", 1)
	if err := os.WriteFile(policy, []byte(changed), 0o644); err != nil {
		t.Fatal(err)
	}
	owner(t, "INSERT INTO app.users VALUES (1, 'ann'), (2, 'bo') RETURNING id")
	message := owner(t, "INSERT INTO app.inbox (sender_id, recipient_id, body) VALUES (1, 2, 'hi') RETURNING id")
	// the migrations there: the new one comes after the last of them
	there, err := filepath.Glob(filepath.Join(work, "migrations", "*.sql"))
	if err != nil || len(there) == 0 {
		t.Fatal("no migrations", err)
	}
	last := filepath.Base(there[len(there)-1])
	next := fmt.Sprintf("%05d_authz_", len(there)+1)
	cli := os.Getenv("ROWSTILE_CLI")
	run(t, work, nil, "python3", cli, "migrate")
	// goose migrates the database: the new migration alone is left to run
	said := run(t, work, nil, os.Getenv("GOOSE"), "-dir", "migrations", "postgres", copied.URL, "up")
	if !strings.Contains(said, next) || strings.Contains(said, last) {
		t.Errorf("goose: %s", said)
	}
	run(t, work, nil, "python3", cli, "client")
	if err := os.MkdirAll(filepath.Join(work, "cmd", "replies"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(work, "cmd", "replies", "main.go"), []byte(replies), 0o644); err != nil {
		t.Fatal(err)
	}
	run(t, work, nil, "go", "mod", "edit", "-replace", "github.com/rowstile/rowstile/sdk/go="+sdk)
	got := run(t, work, nil, "go", "run", "./cmd/replies", copied.AppURL, message)
	if got != "true true\nfalse false\n" {
		t.Errorf("%q", got)
	}
	// the copy's files: the migration and the names rowstile wrote, the lock
	var wrote []string
	_ = fs.WalkDir(os.DirFS(work), ".", func(path string, d fs.DirEntry, err error) error {
		if strings.Contains(path, next) {
			wrote = append(wrote, path)
		}
		return err
	})
	names, _ := os.ReadFile(filepath.Join(work, "internal", "authz", "authz.go"))
	if len(wrote) != 1 || !strings.Contains(string(names), `const MessageReply MessagePermission = "reply"`) {
		t.Errorf("%v", wrote)
	}
	if _, err := rowstiletest.PerPackage(context.Background(), os.Getenv("ROWSTILE_TESTS_URL"), "", true); err != nil {
		t.Fatal(err) // as migrated, for what comes after
	}
}

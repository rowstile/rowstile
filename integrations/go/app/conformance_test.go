// The conformance suite (integrations/README.md): the same checks for every stack. This is net/http, pgx and sqlc,
// with goose's migrations. test.sh does check 11 (a fresh database: migrate, the policy's tests, then goose's
// status shows nothing left to run) and the server's half of check 13 before these run; check 14 is the
// policychange package's.
package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	rowstile "github.com/rowstile/rowstile/sdk/go"

	"github.com/rowstile/rowstile/integrations/go/internal/authz"
)

// the notes each may see, and the projects
var expected = map[string]Answer{"1": numbers(1, 3, 4), "2": numbers(2, 3), "3": numbers(1, 3, 4), "": numbers(3)}

func TestCheck1And2ListsShowWhatEachMaySee(t *testing.T) {
	check(t, "2: signed out on purpose, only what anyone may see") // (said last: the cleanups run last first)
	check(t, "1: signed in, a list shows only the user's rows")
	for user, notes := range expected {
		if got := call(handler, "GET", "/notes", user, nil).json(t); !equal(got, notes) {
			t.Errorf("user %q: %v, not %v", user, got, notes)
		}
	}
	if got := call(handler, "GET", "/projects", "", nil).json(t); !equal(got, numbers(3)) {
		t.Errorf("nobody's projects: %v", got)
	}
}

func TestCheck3NotSignedInIsAnErrorThatSaysHow(t *testing.T) {
	check(t, "3: not signed in: the not-signed-in error (AZ701), naming act_as")
	ctx := context.Background()
	err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, "SELECT count(*) FROM app.notes")
		return err
	})
	var pg *pgconn.PgError
	if !errors.As(err, &pg) || pg.Code != "28000" || !strings.Contains(pg.Hint, "act_as") {
		t.Fatalf("not the not-signed-in error: %v", err)
	}
	if rowstile.ErrorCode(err) != "AZ701" { // rowstile help AZ701
		t.Errorf("code %q", rowstile.ErrorCode(err))
	}
	// the SDK's calls outside a signed-in transaction: NotSignedIn, which says how, and a 500
	_, err = rowstile.Can(ctx, pool, authz.NoteView, 1)
	var not *rowstile.NotSignedIn
	if !errors.As(err, &not) || !strings.Contains(err.Error(), "must begin with authz.act_as()") || !errors.As(err, &pg) {
		t.Errorf("not NotSignedIn: %v", err)
	}
	if _, ok := rowstile.ProblemOf(err); ok {
		t.Errorf("the not-signed-in error is the app's bug, a 500")
	}
}

func TestCheck4APooledConnectionCarriesNoOneOver(t *testing.T) {
	check(t, "4: with a pool of one connection, a request as Ann, then one as Bob: Bob never sees Ann's rows")
	ctx := context.Background()
	cfg, err := pgxpool.ParseConfig(copied.AppURL)
	if err != nil {
		t.Fatal(err)
	}
	cfg.MaxConns = 1
	one, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer one.Close()
	h := New(one)
	for _, user := range []string{"1", "2", ""} {
		if got := call(h, "GET", "/notes", user, nil).json(t); !equal(got, expected[user]) {
			t.Errorf("user %q: %v", user, got)
		}
	}
	// a transaction that commits (a folder moved where it is): a rollback undoes even a session's settings
	if a := call(h, "PATCH", "/folders/2", "1", map[string]any{"parent_id": 1}); a.status != 200 {
		t.Errorf("moved: %d %s", a.status, a.body)
	}
	// each request signed in again, so the answers alone can't tell: the pool's one connection, as the last request
	// left it, outside a transaction anyone signed in to, holds no one
	conn, err := one.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()
	var who *string
	if err := conn.QueryRow(ctx, "SELECT current_setting('authz.user_id', true)").Scan(&who); err != nil {
		t.Fatal(err)
	}
	if who != nil && *who != "" {
		t.Errorf("the connection still holds %q", *who)
	}
	_, err = conn.Exec(ctx, "SELECT count(*) FROM app.notes")
	if rowstile.ErrorCode(err) != "AZ701" {
		t.Errorf("not the not-signed-in error: %v", err)
	}
}

func TestCheck5ConcurrentRequestsNeverMixUsers(t *testing.T) {
	check(t, "5: concurrent requests never mix users")
	users := slicesRepeat([]string{"1", "2", "3", ""}, 10)
	got := make([]Answer, len(users))
	var wg sync.WaitGroup
	for i, user := range users {
		wg.Go(func() { got[i] = string(call(handler, "GET", "/notes", user, nil).body) })
	}
	wg.Wait()
	for i, user := range users {
		if !equal(answer{body: []byte(got[i].(string))}.json(t), expected[user]) {
			t.Errorf("request %d, user %q: %v", i, user, got[i])
		}
	}
}

func slicesRepeat(s []string, n int) []string {
	var out []string
	for range n {
		out = append(out, s...)
	}
	return out
}

func TestCheck6ARefusedInsertSaysWhichRule(t *testing.T) {
	check(t, "6: a refused insert: 403 with the problem body naming the rule")
	a := call(handler, "POST", "/notes", "2", map[string]any{"project_id": 3, "body": "hi"})
	body, _ := a.json(t).(map[string]any)
	if a.status != 403 || a.kind != "application/problem+json" {
		t.Fatalf("%d %s %s", a.status, a.kind, a.body)
	}
	if body["table"] != "app.notes" || body["command"] != "insert" || body["code"] != "AZ709" {
		t.Errorf("%v", body)
	}
	if !strings.Contains(body["detail"].(string), "user 2 may not insert this row into app.notes") {
		t.Errorf("%v", body["detail"])
	}
	if !strings.Contains(fmt.Sprint(body["why"]), "project.edit") {
		t.Errorf("%v", body["why"])
	}
}

func TestCheck7HiddenIs404AndNotAllowedIs403(t *testing.T) {
	check(t, "7: an update of a hidden row: 404; of a visible row the user may not edit: 403, with the reason")
	hidden := call(handler, "PATCH", "/notes/1", "2", map[string]any{"body": "x"})
	refused := call(handler, "PATCH", "/notes/1", "3", map[string]any{"body": "x"})
	mine := call(handler, "PATCH", "/notes/4", "3", map[string]any{"body": "better idea"})
	gone := call(handler, "DELETE", "/notes/2", "1", nil)
	no := call(handler, "DELETE", "/notes/1", "3", nil)
	notFound := map[string]any{"type": "https://rowstile.dev/problems/not-found", "title": "Not Found", "status": 404,
		"detail": "app.notes 1 not found"}
	if hidden.status != 404 || !equal(hidden.json(t), notFound) {
		t.Errorf("hidden: %d %s", hidden.status, hidden.body)
	}
	r, _ := refused.json(t).(map[string]any)
	if refused.status != 403 || r["command"] != "update" || !strings.Contains(fmt.Sprint(r["why"]), "edit") {
		t.Errorf("refused: %d %s", refused.status, refused.body)
	}
	// worded as the database words a refused insert: who, the command, the row, the table
	if r["detail"] != "permission denied: user 3 may not update row 1 of app.notes" {
		t.Errorf("refused: %v", r["detail"])
	}
	if mine.status != 200 || gone.status != 404 {
		t.Errorf("mine: %d %s; gone: %d %s", mine.status, mine.body, gone.status, gone.body)
	}
	d, _ := no.json(t).(map[string]any)
	if no.status != 403 || d["command"] != "delete" || d["detail"] != "permission denied: user 3 may not delete row 1 of app.notes" {
		t.Errorf("no: %d %s", no.status, no.body)
	}
}

func TestCheck8InsertThenReadBack(t *testing.T) {
	check(t, "8: insert, then read back, works when the select rule allows it, and is explained when not")
	ok := call(handler, "POST", "/notes", "1", map[string]any{"project_id": 1, "body": "new"})
	unreadable := call(handler, "POST", "/inbox", "1", map[string]any{"recipient_id": 2, "body": "hi bo"})
	quiet := call(handler, "POST", "/inbox/quietly", "1", map[string]any{"recipient_id": 2, "body": "hi bo"})
	if id, _ := ok.json(t).(map[string]any)["id"].(float64); ok.status != 201 || id <= 100 {
		t.Errorf("ok: %d %s", ok.status, ok.body)
	}
	u, _ := unreadable.json(t).(map[string]any)
	if unreadable.status != 403 || u["command"] != "select" || !strings.Contains(u["detail"].(string), "may not see the row as written") {
		t.Errorf("unreadable: %d %s", unreadable.status, unreadable.body)
	}
	if quiet.status != 202 {
		t.Errorf("quiet: %d %s", quiet.status, quiet.body)
	}
}

// the module's root: the folder with go.mod (go test runs in the package's)
func root(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

// command runs rowstile (ROWSTILE_CLI: test.sh's rowstile_cli.py) in dir
func command(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cli := os.Getenv("ROWSTILE_CLI")
	if cli == "" {
		t.Fatal("ROWSTILE_CLI is not set (test.sh sets it)")
	}
	cmd := exec.Command("python3", append([]string{cli}, args...)...)
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("rowstile %v: %v", args, err)
	}
	return string(out)
}

// builds says whether a main package of this source builds inside the module (go build, its file laid over a
// folder that isn't there), and what the compiler said
func builds(t *testing.T, source string) (bool, string) {
	t.Helper()
	dir := t.TempDir()
	file := filepath.Join(dir, "main.go")
	if err := os.WriteFile(file, []byte(source), 0o644); err != nil {
		t.Fatal(err)
	}
	at := filepath.Join(root(t), "check9", filepath.Base(dir), "main.go")
	overlay := filepath.Join(dir, "overlay.json")
	if err := os.WriteFile(overlay, fmt.Appendf(nil, `{"Replace": {%q: %q}}`, at, file), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("go", "build", "-overlay="+overlay, "-o", os.DevNull, "./"+filepath.ToSlash(filepath.Join("check9", filepath.Base(dir))))
	cmd.Dir = root(t)
	out, err := cmd.CombinedOutput()
	return err == nil, string(out)
}

func TestCheck9GeneratedNamesTypeCheck(t *testing.T) {
	check(t, "9: the generated names type-check, and a wrong permission name doesn't: in the generated names, "+
		"and in the SDK's own calls")
	// the committed names are the ones the policy makes (rowstile client go POLICY prints them, and writes nothing)
	made := command(t, root(t), "client", "go", "db/policy.authz")
	committed, err := os.ReadFile(filepath.Join(root(t), "internal", "authz", "authz.go"))
	if err != nil || made != string(committed) {
		t.Fatalf("internal/authz/authz.go is out of date: run rowstile client (%v)", err)
	}
	use := `package main

import (
	"context"

	"github.com/jackc/pgx/v5"
	rowstile "github.com/rowstile/rowstile/sdk/go"

	"github.com/rowstile/rowstile/integrations/go/internal/authz"
)

func use(ctx context.Context, tx pgx.Tx) error {
	%s
	return err
}

func main() { _ = use }
`
	for _, c := range []struct {
		code, wrong string
	}{
		{"_, err := rowstile.Can(ctx, tx, authz.NoteEdit, 1)", ""},
		{"_, err := rowstile.PermsOf[authz.ProjectPermission](ctx, tx, []int64{1, 3})", ""},
		{"_, err := rowstile.List(ctx, tx, authz.ProjectView, nil)", ""},
		{"_, err := rowstile.Can(ctx, tx, authz.NoteEdt, 1)", "undefined: authz.NoteEdt"},
		{"_, err := rowstile.Can(ctx, tx, authz.NteEdit, 1)", "undefined: authz.NteEdit"},
		// a plain string is no permission of the policy's, whatever it says
		{`_, err := rowstile.Can(ctx, tx, "edit", 1)`, "string does not satisfy rowstile.Permission"},
		{`_, err := rowstile.PermsOf[string](ctx, tx, []int64{1})`, "does not satisfy rowstile.Permission"},
		{`_, err := rowstile.List(ctx, tx, authz.NotePermission("edt"), nil); _ = authz.TypeNote`, ""},
	} {
		ok, said := builds(t, fmt.Sprintf(use, c.code))
		if ok != (c.wrong == "") || !strings.Contains(said, c.wrong) {
			t.Errorf("%s: built %v, said %s", c.code, ok, said)
		}
	}
}

func TestCheck10AJobActsAsItsService(t *testing.T) {
	check(t, "10: a background job signs in as a service principal")
	// whatever started it: nobody, who sees one project; service 1 sees two (the one it is added to, the public one)
	count, err := Digest(rowstile.ActingAs(context.Background(), rowstile.Nobody), pool)
	if err != nil || count != 2 {
		t.Errorf("%d %v", count, err)
	}
}

func TestCheck12ATestDatabasePerPackageHasThePolicy(t *testing.T) {
	check(t, "12: the test database has the policy: a copy of the migrated one for each test package")
	ctx := context.Background()
	tests := os.Getenv("ROWSTILE_TESTS_URL")
	template := tests[strings.LastIndex(tests, "/")+1:] // the migrated test database (test.sh's conf_tests)
	if !regexp.MustCompile(`/` + template + `_app_[0-9a-f]{8}$`).MatchString(copied.URL) {
		t.Errorf("%s", copied.URL)
	}
	if !strings.HasPrefix(copied.AppURL, "postgres://conf_app:") || !strings.HasSuffix(copied.AppURL, copied.URL[strings.LastIndex(copied.URL, "/"):]) {
		t.Errorf("%s", copied.AppURL)
	}
	if err := rowstile.Check(ctx, pool); err != nil { // the app's role, under row-level security
		t.Error(err)
	}
	var projects []string
	err := rowstile.TxAs(ctx, pool, rowstile.User("1"), func(ctx context.Context, tx pgx.Tx) (err error) {
		projects, err = rowstile.List(ctx, tx, authz.ProjectView, nil)
		return err
	})
	if err != nil || strings.Join(projects, ",") != "1,3" {
		t.Errorf("%v %v", projects, err)
	}
	// (test.sh checks the original is left as it was migrated, once no package copies it: a connection to it
	// would stop another package's copy)
}

func TestCheck13RefusesAConnectionThatSkipsRLS(t *testing.T) {
	check(t, "13: the app refuses to start on a connection that skips row-level security")
	ctx := context.Background()
	owner, err := pgxpool.New(ctx, copied.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	err = rowstile.Check(ctx, owner)
	var problem *rowstile.ConnectionProblem
	if !errors.As(err, &problem) || !strings.Contains(err.Error(), "an owner skips row-level security") {
		t.Errorf("%v", err)
	}
	if err := rowstile.Check(ctx, pool); err != nil {
		t.Error(err)
	}
}

func problem(kind, title string, status int, detail, code string) Answer {
	return map[string]any{"type": "https://rowstile.dev/problems/" + kind, "title": title, "status": status,
		"detail": detail, "code": code}
}

// an API key of ann's, made as the owner (in one transaction: it commits at the end); scopes "read" for one that
// may only read
func annsKey(t *testing.T, scopes string) (key string, id int64) {
	t.Helper()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, copied.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	err = pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SELECT authz.act_as('user', '1')"); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, "SELECT authz.create_api_key('ci', $1)", scopes).Scan(&key); err != nil {
			return err
		}
		return tx.QueryRow(ctx, "SELECT max(id) FROM authz.api_keys WHERE user_id = '1'").Scan(&id)
	})
	if err != nil {
		t.Fatal(err)
	}
	return key, id
}

func TestCheck16NotThereIs404AndAWrongArgument400(t *testing.T) {
	check(t, "16: what a call names isn't there (AZ708): 404; a missing or wrong argument (AZ710): 400")
	_, key := annsKey(t, "")
	page := call(handler, "GET", "/projects/page?limit=1", "1", nil)
	negative := call(handler, "GET", "/projects/page?limit=-1", "1", nil)
	cursor := call(handler, "GET", "/projects/page?limit=1&after=x", "1", nil)
	others := call(handler, "DELETE", fmt.Sprintf("/keys/%d", key), "2", nil) // bo's key it isn't
	revoked := call(handler, "DELETE", fmt.Sprintf("/keys/%d", key), "1", nil)
	again := call(handler, "DELETE", fmt.Sprintf("/keys/%d", key), "1", nil) // revoked: there is none now
	if page.status != 200 || !equal(page.json(t), []any{"1"}) {
		t.Errorf("page: %d %s", page.status, page.body)
	}
	for a, detail := range map[*answer]string{
		&negative: "the page size must not be negative (got -1)",
		&cursor:   "the page cursor 'x' is not a project id",
	} {
		if a.status != 400 || a.kind != "application/problem+json" ||
			!equal(a.json(t), problem("bad-argument", "Bad Request", 400, detail, "AZ710")) {
			t.Errorf("%d %s %s", a.status, a.kind, a.body)
		}
	}
	if revoked.status != 204 {
		t.Errorf("revoked: %d %s", revoked.status, revoked.body)
	}
	// no refusal: for this user the key isn't there (bo's own keys don't hold it; ann's no longer do)
	for _, a := range []answer{others, again} {
		want := problem("not-found", "Not Found", 404, fmt.Sprintf("no API key %d of yours", key), "AZ708")
		if a.status != 404 || a.kind != "application/problem+json" || !equal(a.json(t), want) {
			t.Errorf("%d %s %s", a.status, a.kind, a.body)
		}
	}
}

func TestCheck16EachCodeAnswersAsItsPageSays(t *testing.T) {
	check(t, "16: a login refused or a call that needs someone signed in 401, a move inside itself 409, "+
		"a refusal by the database's own code 403, the app's mistakes a 500")
	readOnly, _ := annsKey(t, "read")
	nobody := call(handler, "POST", "/keys", "", map[string]any{"name": "k"})
	asks := call(handler, "POST", "/projects/1/requests", "", map[string]any{"relation": "member", "reason": "the review"})
	badKey := call(handler, "POST", "/keys", "1", map[string]any{"name": "k"}, "x-api-key", "ak_nope")
	scoped := call(handler, "POST", "/keys", "1", map[string]any{"name": "k"}, "x-api-key", readOnly)
	made := call(handler, "POST", "/keys", "1", map[string]any{"name": "k"})
	notShared := call(handler, "GET", "/projects/1/shares", "2", nil)
	inside := call(handler, "PATCH", "/folders/1", "1", map[string]any{"parent_id": 2})
	stays := call(handler, "PATCH", "/folders/2", "1", map[string]any{"parent_id": 1})
	service := call(handler, "POST", "/keys", "", map[string]any{"name": "mine"}, "x-service", "1") // a key for itself
	var failed []answer
	errs := logged(func() {
		failed = []answer{
			call(handler, "POST", "/projects/1/requests", "2", map[string]any{"relation": "member", "reason": "the review"}),
			call(handler, "POST", "/keys", "1", map[string]any{"name": "k", "principal_type": "service", "principal_id": "1"}),
			call(handler, "GET", "/notes/as/2", "1", nil),
		}
	})
	if made.status != 201 || !strings.HasPrefix(fmt.Sprint(made.json(t).(map[string]any)["key"]), "ak_") {
		t.Errorf("made: %d %s", made.status, made.body)
	}
	if stays.status != 200 {
		t.Errorf("stays: %d %s", stays.status, stays.body)
	}
	for _, c := range []struct {
		got  answer
		want Answer
	}{
		{nobody, problem("not-signed-in", "Unauthorized", 401, "sign in to create an API key", "AZ714")},
		{asks, problem("not-signed-in", "Unauthorized", 401, "sign in first", "AZ714")},
		{badKey, problem("not-signed-in", "Unauthorized", 401, "invalid API key", "AZ703")},
		{inside, problem("conflict", "Conflict", 409, "folder 1 cannot be moved inside itself", "AZ713")},
	} {
		if c.got.kind != "application/problem+json" || !equal(c.got.json(t), c.want) ||
			c.got.status != int(c.want.(map[string]any)["status"].(int)) {
			t.Errorf("%d %s, not %v", c.got.status, c.got.body, c.want)
		}
	}
	// refusals, by the database's own code: 403, naming no rule
	for a, want := range map[*answer][2]string{
		&scoped:    {"this session is read-only", "AZ704"},
		&notShared: {"you cannot see the shares of project 1", "AZ705"},
	} {
		got, _ := a.json(t).(map[string]any)
		if a.status != 403 || got["type"] != "https://rowstile.dev/problems/refused" || got["code"] != want[1] ||
			!strings.HasPrefix(got["detail"].(string), want[0]) || got["table"] != nil || got["command"] != nil {
			t.Errorf("%d %s", a.status, a.body)
		}
	}
	// a call that is for users, made by a service (rowstile help AZ715): a refusal too, 403
	if !equal(service.json(t), map[string]any{"type": "https://rowstile.dev/problems/refused", "title": "Forbidden",
		"status": 403, "detail": "authz.create_api_key for oneself is for users, not services (service 1 is signed in)",
		"table": nil, "command": nil, "why": []any{}, "code": "AZ715"}) || service.status != 403 {
		t.Errorf("service: %d %s", service.status, service.body)
	}
	// the app's mistakes: a 500, and the database's own error, logged with its words
	words := []string{
		"the policy does not allow sharing project.member with a user",
		"the policy gives service no manage_keys permission, so nobody manages its keys",
		"who is signed in was changed after signing in",
	}
	codes := [][2]string{{"AZ706", "P0001"}, {"AZ707", "P0001"}, {"AZ702", "28000"}}
	if len(errs) != 3 {
		t.Fatalf("logged: %v", errs)
	}
	for i, err := range errs {
		var pg *pgconn.PgError
		if failed[i].status != 500 || !errors.As(err, &pg) || [2]string{rowstile.ErrorCode(err), pg.Code} != codes[i] ||
			!strings.Contains(err.Error(), words[i]) {
			t.Errorf("%d %s: %v", failed[i].status, failed[i].body, err)
		}
	}
}

func TestQueriesByPermission(t *testing.T) {
	check(t, "queries by permission: a join on authz.list, and one call for a list's buttons")
	if got := call(handler, "GET", "/projects/editable", "3", nil).json(t); !equal(got, numbers(1)) {
		t.Errorf("editable: %v", got)
	}
	want := map[string]any{"1": []any{"edit", "view"}, "3": []any{"view"}}
	if got := call(handler, "GET", "/projects/buttons", "3", nil).json(t); !equal(got, want) {
		t.Errorf("buttons: %v", got)
	}
}

package app

// The SDK's other paths: what the checks don't meet, run against the same database, so that every statement of
// the SDK runs (test.sh fails otherwise).

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	rowstile "github.com/rowstile/rowstile/sdk/go"
	"github.com/rowstile/rowstile/sdk/go/rowstiletest"

	"github.com/rowstile/rowstile/integrations/go/internal/authz"
)

// whom is who the transaction is signed in as, in the words the database's refusals use
func whom(ctx context.Context, tx pgx.Tx) string {
	var who string
	_ = tx.QueryRow(ctx, "SELECT coalesce((SELECT principal_type || ' ' || principal_id FROM authz.principal()), "+
		"'nobody')").Scan(&who)
	return who
}

// signedInAlready is the error for who's work inside a transaction signed in as signed
func signedInAlready(signed, who string) string {
	return "this transaction is signed in as " + signed + " already, and a sign-in lasts the database transaction: " +
		who + "'s work can't run inside it. Run it after, or in a transaction of its own (another connection)"
}

func TestATransactionIsOnePrincipals(t *testing.T) {
	check(t, "a transaction inside a transaction is a savepoint when it is the same principal's; anyone else's is "+
		"refused before anything is sent, and the transaction goes on as its principal's")
	ctx := rowstile.ActingAs(context.Background(), rowstile.User("2"))
	var said, ran []string
	var refused []error
	var notes []int64
	err := rowstile.Tx(ctx, pool, func(ctx context.Context, tx pgx.Tx) error {
		said = append(said, whom(ctx, tx))
		// bo's work inside bo's: a savepoint, as bo; one that fails rolls back its own part alone
		err := rowstile.TxAs(ctx, tx, rowstile.User("2"), func(ctx context.Context, inner pgx.Tx) error {
			who, _ := rowstile.Current(ctx)
			said = append(said, whom(ctx, inner), who.ID)
			return rowstile.Tx(ctx, inner, func(ctx context.Context, deeper pgx.Tx) error {
				said = append(said, whom(ctx, deeper))
				return nil
			})
		})
		said = append(said, fmt.Sprint(err))
		failed := rowstile.Tx(ctx, tx, func(ctx context.Context, inner pgx.Tx) error {
			_, _ = inner.Exec(ctx, "UPDATE app.notes SET body = 'gone' WHERE id = 2")
			return errors.New("no")
		})
		said = append(said, failed.Error())
		// anyone else's: refused, and their work never runs; on the transaction's connection too
		for _, other := range []struct {
			db  rowstile.Beginner
			who rowstile.Principal
		}{{tx, rowstile.As("service", "1")}, {tx, rowstile.Nobody}, {tx.Conn(), rowstile.User("1")}} {
			refused = append(refused, rowstile.TxAs(ctx, other.db, other.who, func(context.Context, pgx.Tx) error {
				ran = append(ran, other.who.ID)
				return nil
			}))
		}
		// the transaction's connection, as bo: pgx begins no savepoint on a *pgx.Conn
		refused = append(refused, rowstile.Tx(ctx, tx.Conn(), func(context.Context, pgx.Tx) error {
			ran = append(ran, "conn")
			return nil
		}))
		// still bo's: it reads and writes as bo, and commits
		said = append(said, whom(ctx, tx))
		rows, _ := tx.Query(ctx, "SELECT id FROM app.notes WHERE body <> 'gone' ORDER BY id")
		notes, err = pgx.CollectRows(rows, pgx.RowTo[int64])
		if err == nil {
			var changed pgconn.CommandTag
			changed, err = tx.Exec(ctx, "UPDATE app.notes SET body = body WHERE id IN (1, 2)")
			said = append(said, changed.String())
		}
		return err
	})
	if err != nil || strings.Join(said, ", ") != "user 2, user 2, 2, user 2, <nil>, no, user 2, UPDATE 1" ||
		!slices.Equal(notes, []int64{2, 3}) || len(ran) != 0 {
		t.Errorf("%v %v %v %v", said, notes, ran, err)
	}
	for i, want := range []string{
		signedInAlready("user 2", "service 1"),
		signedInAlready("user 2", "nobody"),
		signedInAlready("user 2", "user 1"),
		"this connection is in a transaction already, and pgx begins no savepoint on a *pgx.Conn: run this on the " +
			"transaction's pgx.Tx, or after it",
	} {
		if e := refused[i]; e == nil || e.Error() != want || rowstile.ErrorCode(e) != "" {
			t.Errorf("%d: %v", i, e)
		}
	}
	// nobody's transaction refuses a user's work too
	err = rowstile.TxAs(ctx, pool, rowstile.Nobody, func(ctx context.Context, tx pgx.Tx) error {
		return rowstile.TxAs(ctx, tx, rowstile.User("2"), func(context.Context, pgx.Tx) error { return nil })
	})
	if err == nil || err.Error() != signedInAlready("nobody", "user 2") {
		t.Errorf("%v", err)
	}
	// a transaction Tx didn't begin: who it is signed in as can't be known, so the work is refused, and the
	// transaction is as it was
	err = pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		err := rowstile.Tx(ctx, tx, func(context.Context, pgx.Tx) error {
			ran = append(ran, "foreign")
			return nil
		})
		var signedIn string
		_ = tx.QueryRow(ctx, "SELECT coalesce(current_setting('authz.user_id', true), '')").Scan(&signedIn)
		said = append(said, "signed in: "+signedIn)
		return err
	})
	if err == nil || err.Error() != foreign || len(ran) != 0 || said[len(said)-1] != "signed in: " {
		t.Errorf("%v %v %v", said, ran, err)
	}
	// after it ends, the connection begins anew: a *pgx.Conn, as cy
	c, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Release()
	for _, who := range []string{"3", "1"} {
		err = rowstile.TxAs(ctx, c.Conn(), rowstile.User(who), func(ctx context.Context, tx pgx.Tx) error {
			said = append(said, whom(ctx, tx))
			return nil
		})
		if err != nil {
			t.Error(err)
		}
	}
	if strings.Join(said[len(said)-2:], ", ") != "user 3, user 1" {
		t.Errorf("%v", said)
	}
	if _, set := rowstile.Current(context.Background()); set {
		t.Error("nothing set who a bare context acts for")
	}
}

// foreign is the error for work in a transaction Tx didn't begin; noSavepoint for work on a connection in one
const (
	foreign = "this connection is in a transaction rowstile.Tx didn't begin: who it is signed in as can't be " +
		"known, and a sign-in lasts the database transaction. Begin it with rowstile.Tx, or run this after it"
	noSavepoint = "this connection is in a transaction already, and pgx begins no savepoint on a *pgx.Conn: run " +
		"this on the transaction's pgx.Tx, or after it"
)

func TestWithOptions(t *testing.T) {
	check(t, "a transaction Tx begins with pgx's options (an isolation level, read only) signs in as any other; "+
		"one begun by pool.BeginTx itself, or by a pool's connection, is refused: who it is signed in as can't be known")
	ctx := rowstile.ActingAs(context.Background(), rowstile.User("2"))
	var said []string
	options := pgx.TxOptions{IsoLevel: pgx.Serializable, AccessMode: pgx.ReadOnly}
	err := rowstile.Tx(ctx, rowstile.WithOptions(pool, options), func(ctx context.Context, tx pgx.Tx) error {
		var level, readOnly string
		err := tx.QueryRow(ctx, "SELECT current_setting('transaction_isolation'), "+
			"current_setting('transaction_read_only')").Scan(&level, &readOnly)
		said = append(said, whom(ctx, tx), level, readOnly)
		// on the transaction's own connection, with options too: pgx would begin no savepoint there
		inner := rowstile.Tx(ctx, rowstile.WithOptions(tx.Conn(), pgx.TxOptions{}), func(context.Context, pgx.Tx) error {
			said = append(said, "ran")
			return nil
		})
		said = append(said, fmt.Sprint(inner))
		return err
	})
	if err != nil || strings.Join(said, ", ") != "user 2, serializable, on, "+noSavepoint {
		t.Errorf("%v %v", said, err)
	}
	// begun with the pool's own BeginTx, on a connection of the pool: Tx refuses it, on the pgx.Tx and on the
	// connection (a savepoint on neither would be signed in), and nothing is sent; the transaction is as it was
	c, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Release()
	tx, err := c.BeginTx(ctx, options)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	for db, want := range map[rowstile.Beginner]string{tx: foreign, c: noSavepoint,
		rowstile.WithOptions(c, options): noSavepoint} {
		err := rowstile.Tx(ctx, db, func(context.Context, pgx.Tx) error {
			said = append(said, "ran")
			return nil
		})
		if err == nil || err.Error() != want {
			t.Errorf("%T: %v", db, err)
		}
	}
	var signedIn string
	err = tx.QueryRow(ctx, "SELECT coalesce(current_setting('authz.user_id', true), '')").Scan(&signedIn)
	if err != nil || signedIn != "" || said[len(said)-1] == "ran" {
		t.Errorf("%v %q %v", said, signedIn, err)
	}
}

func TestATransactionThatCantBegin(t *testing.T) {
	check(t, "a pool that is closed: the error as it is")
	closed, err := pgxpool.New(context.Background(), copied.AppURL)
	if err != nil {
		t.Fatal(err)
	}
	closed.Close()
	err = rowstile.Tx(context.Background(), closed, func(context.Context, pgx.Tx) error { return nil })
	if err == nil || rowstile.ErrorCode(err) != "" {
		t.Errorf("%v", err)
	}
}

func TestExpect(t *testing.T) {
	check(t, "Expect: a change is no error; matched nothing for another reason: NotFound; asked outside a "+
		"signed-in transaction: the database's error")
	ctx := context.Background()
	err := rowstile.TxAs(ctx, pool, rowstile.User("3"), func(ctx context.Context, tx pgx.Tx) error {
		changed, err := tx.Exec(ctx, "UPDATE app.notes SET body = body WHERE id = 4")
		if err == nil {
			err = rowstile.Expect(ctx, tx, changed.RowsAffected(), "app.notes", "update", 4)
		}
		return err
	})
	if err != nil {
		t.Error(err)
	}
	// cy may edit note 4: an UPDATE whose WHERE says more than the key matched nothing, and that is no refusal
	err = rowstile.TxAs(ctx, pool, rowstile.User("3"), func(ctx context.Context, tx pgx.Tx) error {
		changed, _ := tx.Exec(ctx, "UPDATE app.notes SET body = 'x' WHERE id = 4 AND body = 'something else'")
		return rowstile.Expect(ctx, tx, changed.RowsAffected(), "app.notes", "update", 4)
	})
	if rowstiletest.NotFound(t, err).Error() != "app.notes 4 not found" {
		t.Error(err)
	}
	// a table named without its schema is found on the search_path, and the refusal names it as an insert's does
	err = rowstile.TxAs(ctx, pool, rowstile.User("3"), func(ctx context.Context, tx pgx.Tx) error {
		_, _ = tx.Exec(ctx, "SET LOCAL search_path = app")
		changed, _ := tx.Exec(ctx, "UPDATE notes SET body = 'x' WHERE id = 1")
		return rowstile.Expect(ctx, tx, changed.RowsAffected(), "notes", "update", 1)
	})
	if r := rowstiletest.Refused(t, err, "update"); r.Table != "app.notes" || r.Code != "AZ709" ||
		r.Message != "permission denied: user 3 may not update row 1 of app.notes" {
		t.Errorf("%+v", r)
	}
	if err = rowstile.Expect(ctx, pool, 0, "app.notes", "update", 1); rowstile.ErrorCode(err) == "" {
		t.Errorf("asked outside a signed-in transaction: %v", err)
	}
}

func TestPostgresOwnRefusalsNameTheRule(t *testing.T) {
	check(t, "Postgres's own refusals (an update out of sight, an upsert, MERGE) name the rule")
	ctx := context.Background()
	refused := func(sql string) *rowstile.Refused { // as cy (3): author of note 4 in project 1, a member there
		return rowstiletest.Refused(t, rowstile.TxAs(ctx, pool, rowstile.User("3"), func(ctx context.Context, tx pgx.Tx) error {
			_, err := tx.Exec(ctx, sql)
			return err
		}), "")
	}
	hidden := refused("UPDATE app.notes SET project_id = 2 WHERE id = 4") // into bo's project
	upsert := refused("INSERT INTO app.notes (id, project_id, author_id, body) VALUES (1, 1, 3, 'x') " +
		"ON CONFLICT (id) DO UPDATE SET body = 'x'") // note 1 is ann's
	merge := refused("MERGE INTO app.notes n USING (VALUES (1)) s(id) ON n.id = s.id WHEN MATCHED THEN UPDATE SET body = 'x'")
	for _, c := range []struct {
		got                       *rowstile.Refused
		command, message, problem string
	}{
		{hidden, "select", `new row violates row-level security policy for table "notes": this user may not see the row ` +
			"as written (the select rule). An insert that reads it back (RETURNING), an upsert, and an update with a " +
			"WHERE need to see it.", `"command":"select"`},
		{upsert, "update", `new row violates row-level security policy (USING expression) for table "notes": the row ` +
			"is there already, and the update rule (or the select rule) doesn't let this user change it (ON CONFLICT " +
			"DO UPDATE)", `"command":"update"`},
		{merge, "", `target row violates row-level security policy (USING expression) for table "notes": MERGE ` +
			"matched a row the update or delete rule doesn't let this user change", `"command":null`},
	} {
		p, _ := rowstile.ProblemOf(c.got)
		body, _ := p.MarshalJSON()
		if c.got.Table != "notes" || c.got.Command != c.command || c.got.Message != c.message || len(c.got.Why) != 0 ||
			!strings.Contains(string(body), c.problem) || !strings.Contains(string(body), `"why":[]`) {
			t.Errorf("%+v %s", c.got, body)
		}
	}
}

func TestErrorsThatArentRowstiles(t *testing.T) {
	check(t, "an error that isn't rowstile's: no code, no problem, a 500; a 42501 that isn't a policy's too")
	ctx := context.Background()
	// a table the app role was never granted: the app's mistake, not a refusal
	err := rowstile.TxAs(ctx, pool, rowstile.User("1"), func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, "SELECT * FROM public.goose_db_version")
		return err
	})
	var pg *pgconn.PgError
	if _, ok := rowstile.ProblemOf(err); ok || !errors.As(err, &pg) || pg.Code != "42501" || rowstile.ErrorCode(err) != "" {
		t.Errorf("%v", err)
	}
	if rowstile.ErrorCode(errors.New("rowstile help AZ709")) != "" {
		t.Error("only a database error has a code")
	}
	// the code is read from the message too, where the HINT has none
	if code := rowstile.ErrorCode(&pgconn.PgError{Message: "a check said no (rowstile help AZ612)"}); code != "AZ612" {
		t.Error(code)
	}
	// a body the handler can't read: its error, a 500
	errs := logged(func() {
		if a := call(handler, "POST", "/notes", "1", "not an object"); a.status != 500 {
			t.Errorf("%d %s", a.status, a.body)
		}
	})
	if len(errs) != 1 || !strings.Contains(errs[0].Error(), "json") {
		t.Errorf("%v", errs)
	}
	// a translated error, given back by a transaction around: as it is, the database's error inside it
	for e, said := range map[error]string{
		&rowstile.Refused{Message: "no", Err: &pgconn.PgError{Code: "42501"}}:                               "no",
		&rowstile.CallError{Code: "AZ710", Status: 400, Message: "no", Err: &pgconn.PgError{Code: "22023"}}: "no",
		&rowstile.NotSignedIn{Err: &pgconn.PgError{Severity: "ERROR", Code: "28000", Message: "x"}}: "a query ran in a transaction " +
			"nobody signed in to: every transaction must begin with authz.act_as() (rowstile.Tx does it; is this " +
			"query outside it?): ERROR: x (SQLSTATE 28000)",
	} {
		got := rowstile.Tx(ctx, pool, func(context.Context, pgx.Tx) error { return e })
		if got != e || !errors.As(got, &pg) || got.Error() != said {
			t.Errorf("%v", got)
		}
	}
	for _, c := range []struct {
		err  error
		said string
	}{
		{&rowstile.NotFound{}, "not found"},
		{&rowstile.NotFound{Table: "app.notes"}, "app.notes not found"},
		{&rowstile.NotFound{ID: "7"}, "row 7 not found"},
		{&rowstile.ConnectionProblem{Problems: []string{"a", "b"}}, "the app's database connection can't be used with rowstile: a; b"},
	} {
		if c.err.Error() != c.said {
			t.Errorf("%q, not %q", c.err.Error(), c.said)
		}
	}
}

func TestQueriesOutsideASignedInTransaction(t *testing.T) {
	check(t, "PermsOf and List outside a signed-in transaction: the not-signed-in error")
	ctx := context.Background()
	_, err := rowstile.PermsOf[authz.ProjectPermission](ctx, pool, []string{"1"})
	var not *rowstile.NotSignedIn
	if !errors.As(err, &not) {
		t.Errorf("%v", err)
	}
	if _, err := rowstile.List(ctx, pool, authz.ProjectView, &rowstile.Page{Limit: 1}); !errors.As(err, &not) {
		t.Errorf("%v", err)
	}
}

// row is the database's answer to Expect's question, made up: nothing there for this user
type row struct{ table string }

func (r row) Scan(dest ...any) error {
	*dest[0].(*[]string), *dest[1].(*string), *dest[2].(*string) = nil, "user 2", r.table
	return nil
}

type asked struct{ key string }

func (a *asked) QueryRow(_ context.Context, _ string, args ...any) pgx.Row {
	a.key = args[2].(string)
	return row{args[0].(string)}
}

func TestAKeyIsSpelledAsTheDatabaseWritesIt(t *testing.T) {
	check(t, "a key in a message: 7, (1,2), a field quoted only where Postgres would, and asked about so")
	for _, c := range []struct {
		key  any
		said string
	}{
		{7, "7"}, {[]any{7}, "7"}, {[]any{1, 2}, "(1,2)"}, {[]any{"a b", "x,y"}, `("a b","x,y")`},
		{[]any{"", `q"t`}, `("","q""t")`}, {[]any{`b\s`, "(1)"}, `("b\\s","(1)")`}, {[]any{1, nil}, "(1,)"},
	} {
		q := &asked{}
		err := rowstile.Expect(context.Background(), q, 0, "app.members", "delete", c.key)
		if err.Error() != "app.members "+c.said+" not found" || q.key != c.said {
			t.Errorf("%v: %v, asked about %s", c.key, err, q.key)
		}
	}
}

// fake is a test that fails without stopping, so that the helpers' failures can be seen
type fake struct {
	testing.TB
	said []string
}

func (f *fake) Helper()                        {}
func (f *fake) Fatalf(format string, a ...any) { f.said = append(f.said, format) }

func TestTheTestHelpersSayWhatWasExpected(t *testing.T) {
	check(t, "the test helpers: a refusal by the rule expected, NotFound, and what each says otherwise")
	f := &fake{TB: t}
	refused := &rowstile.Refused{Command: "update", Message: "no"}
	if rowstiletest.Refused(f, refused, "update") != refused || rowstiletest.Refused(f, refused, "") != refused {
		t.Error("the refusal itself")
	}
	rowstiletest.Refused(f, refused, "delete")
	rowstiletest.Refused(f, errors.New("other"), "")
	rowstiletest.NotFound(f, refused)
	want := "expected the %s rule to refuse it, but: %s: %s|expected a refusal, got %v|expected NotFound, got %v"
	if strings.Join(f.said, "|") != want {
		t.Errorf("%v", f.said)
	}
}

func TestTheMiddlewareAnswersABadToken(t *testing.T) {
	check(t, "who the request is may be refused by the app (a bad token): 401, not a 500")
	a := call(handler, "GET", "/notes", "", nil, "Authorization", "Bearer bad")
	if a.status != http.StatusUnauthorized || !equal(a.json(t), map[string]any{
		"type": "https://rowstile.dev/problems/not-signed-in", "title": "Unauthorized", "status": 401, "detail": "bad token",
	}) {
		t.Errorf("%d %s", a.status, a.body)
	}
	// one that is rowstile's own is answered as such
	h := rowstile.Middleware(func(*http.Request) (rowstile.Principal, error) { return rowstile.Nobody, &rowstile.NotFound{} })(nil)
	if a := call(h, "GET", "/", "", nil); a.status != 404 {
		t.Errorf("%d %s", a.status, a.body)
	}
}

func TestPerPackageSaysWhyItCantCopy(t *testing.T) {
	check(t, "a database per package: a URL that names none, and a server that isn't there, say so")
	ctx := context.Background()
	if _, err := rowstiletest.PerPackage(ctx, "postgres://conf_owner:owner@localhost", "", true); err == nil ||
		!strings.Contains(err.Error(), "names a database to copy") {
		t.Errorf("%v", err)
	}
	if _, err := rowstiletest.PerPackage(ctx, "postgres://conf_owner:owner@localhost:1/conf_tests?connect_timeout=2", "", true); err == nil {
		t.Error("no server there")
	}
	if !regexp.MustCompile(`^app_[0-9a-f]{8}$`).MatchString(rowstiletest.Worker()) {
		t.Error(rowstiletest.Worker())
	}
}

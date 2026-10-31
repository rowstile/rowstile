# Go: pgx, sqlc, net/http and goose

<!-- tested: every line of code below is in integrations/go (tests/unit_test.py checks it) -->

**Preview.** The Go SDK may change in any release: it is not part of what 1.0 keeps stable.

A Go app on [pgx](https://github.com/jackc/pgx) v5 (`pgxpool`), with sqlc's queries and goose's migrations. The
handlers check nothing: each request's transactions sign in as its user, the database filters what they read and
refuses what they may not write, and the SDK answers a refusal with 403 and a hidden row with 404.

Everything here comes from [`integrations/go`](../../integrations/go), the conformance suite: a small `net/http` app and the checks every
supported stack passes ([`integrations/go/test.sh`](../../integrations/go/test.sh)).

## Install

```sh
go get github.com/rowstile/rowstile/sdk/go    # a preview: the repository's tag sdk/go/vX.Y.Z
pip install --pre rowstile                    # the command (or npm install rowstile@next, or its image)
rowstile init                                 # once your migrations made the tables: a first policy from them, a test file, rowstile.toml
```

The SDK needs pgx v5 and nothing else, and Go 1.25 or newer (its `go.mod`; the suite runs on Go 1.26). Its
package is `rowstile` (`import rowstile "github.com/rowstile/rowstile/sdk/go"`), and its test helpers are
`rowstiletest`.

`init` finds goose's migrations, and writes `rowstile.toml` for them; the line that says where the policy's names
go (`[clients]`) is yours to add. The conformance app's, with its own name for the variable that holds the
owner's connection:

```toml
policy   = "db/policy.authz"
tests    = ["db/tests/*.authz"]
database = "env:ROWSTILE_OWNER_DSN"
[clients]
go = "internal/authz/authz.go"
[migrations]
tool = "goose"
dir  = "migrations"
```

Two roles connect. The owner of the tables runs the migrations, and the app connects as the role the policy
names (`app role conf_app`), which row-level security applies to.

## Sign in every transaction

`rowstile.Middleware(user)` makes each request act for whoever `user(r)` says it is (`rowstile.User("42")`,
`rowstile.As("service", "3")`, or `rowstile.Nobody`, who sees only what `anyone` may). `user` reads the session
or the token from the request; an error from it is answered 401. Here it is `sessionUser`, the app's own: yours
reads your session cookie or token. The conformance app has no sign-in, so its stands in for one, and this page
doesn't show it.

```go
	return rowstile.Middleware(sessionUser)(mux)
```

`rowstile.Tx(ctx, pool, fn)` runs `fn` in a transaction signed in as whoever `ctx` acts for, and commits it if
`fn` returns nil. The sign-in lasts the transaction alone, so pools and PgBouncer in transaction mode are safe.
sqlc's code runs on the transaction it gives (`db.New(tx)`: sqlc's `DBTX` is what a `pgx.Tx` is). A list shows
only the user's rows:

```go
	route("GET /notes", func(w http.ResponseWriter, r *http.Request) error {
		var notes []int64
		err := rowstile.Tx(r.Context(), pool, func(ctx context.Context, tx pgx.Tx) (err error) {
			notes, err = db.New(tx).NoteIDs(ctx)
			return err
		})
```

`rowstile.Handler` turns a handler that returns its error into an `http.Handler`: rowstile's errors are answered
as `application/problem+json`, any other is logged (`slog`) and answered 500:

```go
	route := func(pattern string, fn func(w http.ResponseWriter, r *http.Request) error) {
		mux.Handle(pattern, rowstile.Handler(fn))
	}
```

A background job acts for a principal of its own, whatever started it (`type service = app.services principal`
in the policy): `rowstile.TxAs` signs in as who it is given.

```go
	err := rowstile.TxAs(ctx, pool, rowstile.As("service", "1"), func(ctx context.Context, tx pgx.Tx) (err error) {
		count, err = db.New(tx).CountProjects(ctx)
```

A transaction is one principal's: a sign-in lasts the database transaction. On the `pgx.Tx` of a transaction `Tx`
signed in, `Tx` for the same principal is a savepoint of it. For anyone else (or for nobody, in someone's), it gives
an error before anything is sent, and the transaction goes on as it was: run that work after it, or in a transaction
of its own (on the pool, another connection). So does `Tx` on a transaction it didn't begin, whose sign-in it can't
know.

## Refusals

A refused INSERT is the database's error, which `Tx` gives back as `*rowstile.Refused`, with the table, the
command, the rule's reasons (`Why`) and the code (`AZ709`): `Handler` answers 403 with them. An UPDATE or DELETE
the rules refuse changes no row; `rowstile.Expect` asks the database why, in the same transaction, and gives
`*rowstile.NotFound` (the user can't see the row: 404) or `*rowstile.Refused` (403, with the reason):

```go
			changed, err := db.New(tx).EditNote(ctx, db.EditNoteParams{ID: id, Body: b.Body})
			if err != nil {
				return err
			}
			// 0 rows: Expect asks the database why, and answers 404 (hidden) or 403 (with the reason)
			return rowstile.Expect(ctx, tx, changed, "app.notes", "update", id)
```

sqlc's `:execrows` gives the count `Expect` takes; with `tx.Exec`, it is the command tag's `RowsAffected()`.

An insert that reads the new row back (`RETURNING`) also needs the select rule: if the user may insert but not
read the row, the 403 names the select rule.

A call the database turns down that is no refusal is `*rowstile.CallError`, with the status its code's page gives
and the database's words: something it names that isn't there (AZ708) 404, a missing or wrong argument (AZ710)
400, a call that needs someone signed in (AZ714) or a login refused (AZ703) 401, a folder moved into one of its own
subfolders (AZ713) 409. Each is read with `errors.As`:

```go
	var not *rowstile.NotSignedIn
```

`rowstile.ErrorCode(err)` is rowstile's code of any database error (`rowstile help AZ702` says what it means).
`rowstile.ProblemOf(err)` and `rowstile.WriteProblem(w, err)` give the problem body for another router.

At start-up, `rowstile.Check` refuses a connection that skips row-level security (a superuser, BYPASSRLS, the
tables' owner):

```go
	// a superuser, BYPASSRLS or the tables' owner: the database would filter nothing
	if err := rowstile.Check(ctx, pool); err != nil {
		log.Fatal(err)
	}
```

## The policy's names

`rowstile client go` writes the policy's names as Go: each type's permissions are a type of their own
(`authz.NotePermission`, with `authz.NoteEdit` and `authz.NoteView`). `rowstile.Can`, `PermsOf` and `List` take
only those, so a misspelled name doesn't build, and neither does a plain string:

```go
				buttons, err = rowstile.PermsOf[authz.ProjectPermission](ctx, tx, projects)
			listed, err = rowstile.List(ctx, tx, authz.ProjectView, page)
```

To filter a query to the objects the user holds a permission on, join `authz.list` in it, as this sqlc query
does:

```sql
SELECT p.id FROM app.projects p JOIN authz.list('project', 'edit') x ON x = p.id::text ORDER BY p.id;
```

## Migrations

The policy ships as goose migrations: `rowstile migrate` writes the next one (only what changed since
`db/policy.lock`), and goose applies it with the others. goose has no diff of its own; `rowstile migrate --check`
in CI fails if a policy change has no migration.

```sh
rowstile migrate                                      # after changing the policy
goose -dir migrations postgres "$DATABASE_URL" up
rowstile migrate --check                              # in CI: exit 1 if a policy change has no migration
```

sqlc reads the tables from the app's own migration, not from rowstile's (`schema: migrations/00001_schema.sql`
in `sqlc.yaml`).

## Tests

`go test` runs the tests of each package in a process of its own, packages side by side: each package is a
worker. `rowstiletest.PerPackage` copies the migrated test database once for the package that calls it, in its
`TestMain`, so tests that write don't meet another package's. A package's tests share its copy, `t.Parallel()`
ones too.

```go
	if copied, err = rowstiletest.PerPackage(ctx, tests, os.Getenv("ROWSTILE_APP_URL"), true); err == nil {
```

It returns the copy's URL, the owner's, and the app role's for it. The copy needs nobody connected to the
original. `rowstiletest.Refused(t, err, "update")` and `rowstiletest.NotFound(t, err)` fail the test unless
`err` is one.

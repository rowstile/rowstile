# rowstile for Go

**Preview.** This package may change in any release; it is not part of what 1.0 keeps stable.

rowstile for Go apps on [pgx](https://github.com/jackc/pgx) v5: every transaction signs in as whoever the request
acts for, the database filters what it reads and refuses what it may not write, and the package turns a refusal
into `*rowstile.Refused` (a 403 with the reason) and a hidden row into `*rowstile.NotFound` (a 404). It holds no
rowstile logic: it calls the `authz.*` functions the policy made, and reads their answers.

```sh
go get github.com/rowstile/rowstile/sdk/go
```

```go
import rowstile "github.com/rowstile/rowstile/sdk/go"

ctx = rowstile.ActingAs(ctx, rowstile.User("42"))     // rowstile.Middleware does it for each request
err := rowstile.Tx(ctx, pool, func(ctx context.Context, tx pgx.Tx) error {
	changed, err := tx.Exec(ctx, "UPDATE app.notes SET body = $1 WHERE id = $2", body, id)
	if err != nil {
		return err // a refused write: *rowstile.Refused
	}
	return rowstile.Expect(ctx, tx, changed.RowsAffected(), "app.notes", "update", id)
})
```

- `Tx`, `TxAs`: a transaction signed in (`authz.act_as`), on a `*pgxpool.Pool`, a `*pgx.Conn` or a `pgx.Tx`. The
  sign-in lasts the transaction alone, so pools and PgBouncer in transaction mode are safe. sqlc's code runs in
  it: `db.New(tx)`. A transaction is one principal's: inside one, `Tx` for the same principal is a savepoint, and
  for anyone else an error, before anything is sent.
- `Expect`: an UPDATE or DELETE that changed no row, asked about: `*NotFound` or `*Refused`, with the reason.
- `Refused`, `NotFound`, `CallError` (the codes a call can meet, each with its status), `NotSignedIn`, read with
  `errors.As`; `ErrorCode(err)` is rowstile's code (`rowstile help AZ709`).
- `Middleware`, `Handler`, `WriteProblem`, `ProblemOf`: `net/http`, with `application/problem+json` answers.
- `Check`: at start-up, refuse a connection that skips row-level security.
- `Can`, `PermsOf`, `List`: take only the policy's names, which `rowstile client go` writes.
- `rowstiletest`: a copy of the migrated test database for each test package, and `Refused` and `NotFound`
  assertions.

The guide: [Go](https://rowstile.dev/stacks/go). The version is the repository's tag `sdk/go/vX.Y.Z`.

// Package rowstile is rowstile for Go apps on pgx (a preview: it may change in any release).
//
// Every transaction signs in as whoever the request (or the job) acts for, with authz.act_as(); the database's
// refusals become *Refused (a 403 with the reason), rows the user can't see *NotFound (a 404), and the other
// codes the runtime answers with *CallError (each with its page's status). The package holds no rowstile logic:
// it calls the authz.* functions the policy made, and translates their answers.
//
//	ctx = rowstile.ActingAs(ctx, rowstile.User("42"))      // or rowstile.As("service", "3"), or rowstile.Nobody
//	err := rowstile.Tx(ctx, pool, func(ctx context.Context, tx pgx.Tx) error {
//		_, err := tx.Exec(ctx, "UPDATE app.notes SET body = $1 WHERE id = $2", body, id)
//		return err
//	})
//
// In a web app, Middleware sets who each request acts for, and Handler answers rowstile's errors as
// application/problem+json. Check refuses a connection that skips row-level security, at start-up. The policy's
// names come from `rowstile client go`, and Can, PermsOf and List take only those.
package rowstile

import (
	"context"
	"sync"

	"github.com/jackc/pgx/v5"
)

// Principal is who a transaction acts for: a user (Type "user"), another principal type the policy declares (a
// service, a bot), or nobody (Type "": only what `anyone` may see).
type Principal struct {
	Type string
	ID   string
}

// Nobody is no one signed in: only what `anyone` may see.
var Nobody = Principal{}

// User is the user whose id this is, whatever it holds ("service:3" too: ids come from outside).
func User(id string) Principal { return Principal{Type: "user", ID: id} }

// As is a principal of another type the policy declares: As("service", "3").
func As(principalType, id string) Principal { return Principal{Type: principalType, ID: id} }

// IsNobody says whether p is no one signed in.
func (p Principal) IsNobody() bool { return p.Type == "" }

type actingKey struct{}

// ActingAs is ctx acting for who: every transaction Tx begins with it signs in as them.
func ActingAs(ctx context.Context, who Principal) context.Context {
	return context.WithValue(ctx, actingKey{}, who)
}

// Current is who ctx acts for, and whether anything set it (ActingAs, Middleware, Tx).
func Current(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(actingKey{}).(Principal)
	return p, ok
}

// Beginner is what Tx begins a transaction on: a *pgxpool.Pool, a *pgx.Conn, or a pgx.Tx (a savepoint in it).
type Beginner interface {
	Begin(ctx context.Context) (pgx.Tx, error)
}

// signed holds who each transaction Tx began signed in as, while it is open: a savepoint inside it signs in as
// them again when it ends.
var signed sync.Map

func signIn(ctx context.Context, tx pgx.Tx, who Principal) error {
	if who.IsNobody() {
		_, err := tx.Exec(ctx, "SELECT authz.act_as(NULL, NULL)")
		return err
	}
	_, err := tx.Exec(ctx, "SELECT authz.act_as($1, $2)", who.Type, who.ID)
	return err
}

// Tx runs fn in a transaction signed in as whoever ctx acts for (nobody if nothing set it), and commits it if fn
// returns nil. fn's ctx acts for them too. The sign-in lasts the transaction alone, so pools and poolers in
// transaction mode are safe. A database error (fn's, or the commit's) comes back as rowstile's when it is one:
// *Refused, *NotSignedIn, *CallError; NotFound comes from Expect.
func Tx(ctx context.Context, db Beginner, fn func(ctx context.Context, tx pgx.Tx) error) error {
	who, _ := Current(ctx)
	return TxAs(ctx, db, who, fn)
}

// TxAs is Tx signed in as who, whoever ctx acts for. On a pgx.Tx it is a savepoint: when it ends, the
// transaction signs in again as whoever it was signed in as before (nobody, if Tx didn't begin it).
func TxAs(ctx context.Context, db Beginner, who Principal, fn func(ctx context.Context, tx pgx.Tx) error) error {
	tx, err := db.Begin(ctx)
	if err != nil {
		return translate(err)
	}
	defer tx.Rollback(context.WithoutCancel(ctx)) // after a commit, a no-op that says so
	signed.Store(tx, who)
	defer signed.Delete(tx)
	if err = signIn(ctx, tx, who); err == nil {
		err = fn(ActingAs(ctx, who), tx)
	}
	if outer, inside := db.(pgx.Tx); inside && err == nil {
		before, _ := signed.Load(outer)
		back, _ := before.(Principal) // (nobody, if Tx didn't begin the transaction around)
		err = signIn(ctx, tx, back)
	}
	if err == nil {
		err = tx.Commit(ctx)
	}
	return translate(err)
}

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
	"errors"
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

// signed holds who each connection's open transaction is signed in as, by the *pgx.Conn under it, from the
// moment TxAs signs it in until it ends: a sign-in lasts the database transaction, so its savepoints are theirs.
var signed sync.Map

// conn is the connection db begins on when it is one (a pgx.Tx's, a *pgx.Conn), and nil when db is a pool, which
// begins on a connection of its own.
func conn(db Beginner) *pgx.Conn {
	switch d := db.(type) {
	case pgx.Tx:
		return d.Conn()
	case *pgx.Conn:
		return d
	}
	return nil
}

// name is how the database's refusals name who: "user 42", "service 3", or "nobody".
func name(who Principal) string {
	if who.IsNobody() {
		return "nobody"
	}
	return who.Type + " " + who.ID
}

// entered says whether db's connection is in a transaction (inside), and gives an error, before anything is sent,
// when work for who can't run in it. A sign-in lasts the database transaction, so a second one would make the rest
// of it, after the work, the second principal's: work for whoever the transaction is signed in as runs in a
// savepoint of it, anyone else's is refused. So is a transaction TxAs didn't begin (who it is signed in as can't be
// known), and a *pgx.Conn in a transaction (pgx would begin no savepoint on it).
func entered(db Beginner, who Principal) (inside bool, err error) {
	c := conn(db)
	if c == nil || c.PgConn().TxStatus() == 'I' {
		return false, nil
	}
	before, known := signed.Load(c)
	if outer, _ := before.(Principal); known && outer != who {
		return true, errors.New("this transaction is signed in as " + name(outer) + " already, and a sign-in lasts " +
			"the database transaction: " + name(who) + "'s work can't run inside it. Run it after, or in a " +
			"transaction of its own (another connection)")
	}
	if _, onTx := db.(pgx.Tx); !onTx {
		return true, errors.New("this connection is in a transaction already, and pgx begins no savepoint on a " +
			"*pgx.Conn: run this on the transaction's pgx.Tx, or after it")
	}
	if !known {
		return true, errors.New("this connection is in a transaction rowstile.Tx didn't begin: who it is signed in " +
			"as can't be known, and a sign-in lasts the database transaction. Begin it with rowstile.Tx, or run this " +
			"after it")
	}
	return true, nil
}

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

// TxAs is Tx signed in as who, whoever ctx acts for. A transaction is one principal's, since a sign-in lasts the
// database transaction. So inside one TxAs signed in already (db is its pgx.Tx, or its connection), fn runs in a
// savepoint when who is the principal it is signed in as (its failure rolls back its own part alone); for anyone
// else TxAs gives an error before anything is sent, and the transaction goes on as it was. Run that work after,
// or in a transaction of its own (on the pool: another connection). A transaction TxAs didn't begin gets that
// error too: who it is signed in as can't be known.
func TxAs(ctx context.Context, db Beginner, who Principal, fn func(ctx context.Context, tx pgx.Tx) error) error {
	inside, err := entered(db, who)
	if err != nil {
		return err
	}
	tx, err := db.Begin(ctx)
	if err != nil {
		return translate(err)
	}
	defer tx.Rollback(context.WithoutCancel(ctx)) // after a commit, a no-op that says so
	if !inside {
		signed.Store(tx.Conn(), who)
		defer signed.Delete(tx.Conn())
		err = signIn(ctx, tx, who)
	}
	if err == nil {
		err = fn(ActingAs(ctx, who), tx)
	}
	if err == nil {
		err = tx.Commit(ctx)
	}
	return translate(err)
}

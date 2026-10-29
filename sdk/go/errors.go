package rowstile

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Refused is the database refusing a write, and saying why: the rule (Table and Command), and the reasons, a line
// each. Code is rowstile's (`rowstile help AZ709`): AZ709 for a rule's refusal, the database's own for another
// (AZ704: a read-only session, AZ705: the shares of an object one can't see, AZ715: a call for users made by a
// service), which names no rule.
type Refused struct {
	Message string
	Table   string // schema.table, "" when the refusal names none
	Command string // insert, update, delete or select; "" when it names none
	Why     []string
	Code    string
	Err     error // the database's error, if there was one
}

func (e *Refused) Error() string { return e.Message }
func (e *Refused) Unwrap() error { return e.Err }

// NotFound is a row that isn't there, or that whoever the transaction acts for can't see.
type NotFound struct {
	Table string
	ID    string // the row's key as Postgres writes it: 7, or (1,2) for a key of several columns
}

func (e *NotFound) Error() string {
	named := e.Table // app.notes 7 not found, row 7 not found, app.notes not found, or not found
	if e.ID != "" {
		named = cmp.Or(e.Table, "row") + " " + e.ID
	}
	return strings.TrimPrefix(named+" not found", " ")
}

// NotSignedIn is a query that needs to know who is asking, in a transaction nobody signed in to (AZ701): the
// app's bug, not the user's doing. Every transaction must begin with authz.act_as(), as Tx does.
type NotSignedIn struct {
	Err error
}

func (e *NotSignedIn) Error() string {
	return "a query ran in a transaction nobody signed in to: every transaction must begin with authz.act_as() " +
		"(rowstile.Tx does it; is this query outside it?): " + e.Err.Error()
}
func (e *NotSignedIn) Unwrap() error { return e.Err }

// CallError is a call the database turned down that is no refusal, with the status its code's page gives
// (`rowstile help AZ708`): a login refused or a call that needs someone signed in 401 (AZ703, AZ714), something it
// names that isn't there 404 (AZ708), an argument missing or wrong 400 (AZ710), a move inside itself 409 (AZ713).
// Message is the database's words.
type CallError struct {
	Code    string
	Status  int
	Message string
	Err     error
}

func (e *CallError) Error() string { return e.Message }
func (e *CallError) Unwrap() error { return e.Err }

// ConnectionProblem is authz.connection_check() finding that the app's connection skips row-level security (or
// worse): a superuser, a role with BYPASSRLS, the tables' owner.
type ConnectionProblem struct {
	Problems []string
}

func (e *ConnectionProblem) Error() string {
	return "the app's database connection can't be used with rowstile: " + strings.Join(e.Problems, "; ")
}

var codeIn = regexp.MustCompile(`rowstile help (AZ\d{3})`)

// ErrorCode is rowstile's code for a database error in err (AZ709; `rowstile help AZ709` says what it means), from
// its HINT, where the runtime puts it, or its message; "" for an error rowstile didn't raise.
func ErrorCode(err error) string {
	var pg *pgconn.PgError
	if !errors.As(err, &pg) {
		return ""
	}
	for _, text := range []string{pg.Hint, pg.Message} {
		if m := codeIn.FindStringSubmatch(text); m != nil {
			return m[1]
		}
	}
	return ""
}

// the codes of a call the database turned down that is no refusal, and the status their pages give
var callStatus = map[string]int{"AZ703": 401, "AZ708": 404, "AZ710": 400, "AZ713": 409, "AZ714": 401}

// Postgres's own words, not rowstile's: a check of a row no rule's own refusal covers. Postgres names the table
// without its schema
var rlsGeneric = regexp.MustCompile(
	`^(new|target) row violates row-level security policy (\(USING expression\) )?for table "([^"]+)"`)

const unseen = "this user may not see the row as written (the select rule). An insert that reads it back " +
	"(RETURNING), an upsert, and an update with a WHERE need to see it."

// refusal is a *Refused for a database error that is a refusal (SQLSTATE 42501, raised by rowstile's policies with
// the rule and why, or Postgres's own words for a check no rule's refusal covers), else nil. Another 42501 (a
// table the app role was never granted) is the app's mistake: nil.
func refusal(err error, pg *pgconn.PgError) *Refused {
	if pg.Code != "42501" {
		return nil
	}
	code := ErrorCode(pg)
	if g := rlsGeneric.FindStringSubmatch(pg.Message); g != nil {
		table := g[3] // Postgres sets no field for it
		switch {
		case g[1] == "target": // MERGE matched a row the update or the delete rule hides; Postgres doesn't say which
			return &Refused{Message: pg.Message + ": MERGE matched a row the update or delete rule doesn't let this " +
				"user change", Table: table, Code: "AZ709", Err: err}
		case g[2] != "": // an upsert whose existing row this user may not update, or not see
			return &Refused{Message: pg.Message + ": the row is there already, and the update rule (or the select " +
				"rule) doesn't let this user change it (ON CONFLICT DO UPDATE)", Table: table, Command: "update",
				Code: "AZ709", Err: err}
		}
		// the select rule, on the row as written: an insert that reads it back, an upsert, or an update after which
		// the row would be out of this user's sight
		return &Refused{Message: pg.Message + ": " + unseen, Table: table, Command: "select", Code: "AZ709", Err: err}
	}
	if _, call := callStatus[code]; code == "" || call { // sign in first (AZ714) is a 42501 too, but no refusal
		return nil
	}
	r := &Refused{Message: pg.Message, Table: pg.TableName, Code: code, Why: []string{}, Err: err}
	if pg.SchemaName != "" && pg.TableName != "" {
		r.Table = pg.SchemaName + "." + pg.TableName
	}
	if command, ours := strings.CutPrefix(pg.ConstraintName, "authz_"); ours {
		r.Command = command
	}
	if pg.Detail != "" {
		r.Why = strings.Split(pg.Detail, "\n")
	}
	return r
}

// translate is err as rowstile's error when it is one: a refusal *Refused, the not-signed-in error (AZ701)
// *NotSignedIn, a call turned down *CallError; anything else as it is.
func translate(err error) error {
	var pg *pgconn.PgError
	var r *Refused
	var n *NotSignedIn
	var c *CallError
	if !errors.As(err, &pg) || errors.As(err, &r) || errors.As(err, &n) || errors.As(err, &c) {
		return err
	}
	if r = refusal(err, pg); r != nil {
		return r
	}
	code := ErrorCode(pg)
	if status, call := callStatus[code]; call {
		return &CallError{Code: code, Status: status, Message: pg.Message, Err: err}
	}
	// a login refused (AZ703) and settings changed by hand (AZ702) share the SQLSTATE, and are no such thing
	if pg.Code == "28000" && (code == "" || code == "AZ701") {
		return &NotSignedIn{Err: err}
	}
	return err
}

// Querier is what runs one statement and gives its row: a pgx.Tx, a *pgxpool.Pool, a *pgx.Conn, or sqlc's DBTX.
type Querier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// the table as the policy names it (a table named without its schema is looked up on the search_path),
// authz.explain_rule's answer, and who is signed in, in the words the database's own refusals use
const explainRule = "SELECT authz.explain_rule(t.tbl, $2, $3, NULL), " +
	"coalesce((SELECT p.principal_type || ' ' || p.principal_id FROM authz.principal() p), " +
	"'someone not signed in'), t.tbl FROM (SELECT coalesce((SELECT n.nspname || '.' || c.relname " +
	"FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace " +
	"WHERE position('.' in $1::text) = 0 AND c.oid = pg_catalog.to_regclass(pg_catalog.quote_ident($1::text))), " +
	"$1::text) AS tbl) t"

// Expect is nil when an UPDATE or DELETE changed rows (affected: its pgconn.CommandTag's RowsAffected(), or what
// sqlc's :execrows returns). When it changed none, row-level security left the row out: Expect asks the database
// why, in the same transaction, and gives *NotFound (the user can't see the row, or the statement matched nothing
// for another reason, such as a WHERE with more than the key) or *Refused, worded as the database words a
// refused insert: "permission denied: user 2 may not update row 7 of app.notes". key: the row's key, or a []any of
// its columns for a key of several.
func Expect(ctx context.Context, q Querier, affected int64, table, command string, key any) error {
	if affected > 0 {
		return nil
	}
	var why []string
	var who, named string
	if err := q.QueryRow(ctx, explainRule, table, command, keyText(key)).Scan(&why, &who, &named); err != nil {
		return translate(err)
	}
	if why == nil || strings.HasPrefix(strings.TrimLeft(why[0], " "), "yes") {
		return &NotFound{Table: named, ID: keyText(key)}
	}
	return &Refused{Message: fmt.Sprintf("permission denied: %s may not %s row %s of %s", who, command,
		keyText(key), named), Table: named, Command: command, Why: why, Code: "AZ709"}
}

// keyText is a row's key as Postgres writes it: 7, or (1,2) for a key of several columns, a field quoted only where
// Postgres would (empty, or holding a comma, a quote, a backslash, a parenthesis or a space). What a message
// shows, and what authz.explain_rule reads back.
func keyText(key any) string {
	fields, many := key.([]any)
	if !many {
		return fmt.Sprint(key)
	}
	if len(fields) == 1 {
		return fmt.Sprint(fields[0])
	}
	shown := make([]string, len(fields))
	for i, f := range fields {
		if text := fmt.Sprint(f); f != nil && (text == "" || strings.ContainsAny(text, "\",\\() \t\n\r\v\f")) {
			shown[i] = `"` + strings.ReplaceAll(strings.ReplaceAll(text, `\`, `\\`), `"`, `""`) + `"`
		} else if f != nil {
			shown[i] = text
		}
	}
	return "(" + strings.Join(shown, ",") + ")"
}

// Check is nil on a connection row-level security applies to, and *ConnectionProblem on one that skips it (a
// superuser, BYPASSRLS, the tables' owner): call it at start-up, and refuse to start on an error. As nobody: there
// is no request yet to ask who is signed in.
func Check(ctx context.Context, db Beginner) error {
	var problems []string
	err := TxAs(ctx, db, Nobody, func(ctx context.Context, tx pgx.Tx) error {
		rows, _ := tx.Query(ctx, "SELECT problem FROM authz.connection_check() WHERE severity = 'error'")
		var err error
		problems, err = pgx.CollectRows(rows, pgx.RowTo[string])
		return err
	})
	if err == nil && len(problems) > 0 {
		err = &ConnectionProblem{Problems: problems}
	}
	return err
}

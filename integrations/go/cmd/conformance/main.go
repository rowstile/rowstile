// The conformance app's server: ROWSTILE_APP_URL is the app role's connection, ADDR where it listens. It refuses
// to start on a connection that skips row-level security (check 13).
package main

import (
	"context"
	"log"
	"net/http"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"
	rowstile "github.com/rowstile/rowstile/sdk/go"

	"github.com/rowstile/rowstile/integrations/go/app"
)

func main() {
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, os.Getenv("ROWSTILE_APP_URL"))
	if err != nil {
		log.Fatal(err)
	}
	// a superuser, BYPASSRLS or the tables' owner: the database would filter nothing
	if err := rowstile.Check(ctx, pool); err != nil {
		log.Fatal(err)
	}
	log.Fatal(http.ListenAndServe(os.Getenv("ADDR"), app.New(pool)))
}

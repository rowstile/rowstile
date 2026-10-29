module github.com/rowstile/rowstile/integrations/go

go 1.25.0

require (
	github.com/jackc/pgx/v5 v5.11.0
	github.com/rowstile/rowstile/sdk/go v0.0.0
)

require (
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	golang.org/x/sync v0.17.0 // indirect
	golang.org/x/text v0.29.0 // indirect
)

// the SDK of this checkout (test.sh also builds the app from the module as a release would publish it)
replace github.com/rowstile/rowstile/sdk/go => ../../sdk/go

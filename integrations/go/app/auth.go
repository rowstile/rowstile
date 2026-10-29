package app

import (
	"errors"
	"net/http"

	rowstile "github.com/rowstile/rowstile/sdk/go"
)

// sessionUser is who a request is. A real app reads its session or token here: a cookie, a bearer token, an API
// key. The conformance app has no sign-in: its checks name the user in a header, which a real app must never
// believe. So docs/stacks/go.md shows app.go passing sessionUser to the middleware, and never this file.
func sessionUser(r *http.Request) (rowstile.Principal, error) {
	if r.Header.Get("Authorization") == "Bearer bad" { // a token the app refuses: the middleware answers 401
		return rowstile.Nobody, errors.New("bad token")
	}
	if service := r.Header.Get("x-service"); service != "" { // a service's own API calls
		return rowstile.As("service", service), nil
	}
	if user := r.Header.Get("x-user"); user != "" {
		return rowstile.User(user), nil
	}
	return rowstile.Nobody, nil
}

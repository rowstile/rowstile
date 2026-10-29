package rowstile

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
)

// Problem is an RFC 9457 problem body, what WriteProblem answers with: a refusal's (403, with Table, Command,
// Why and Code), a hidden row's (404), or a call the database turned down (with Code).
type Problem struct {
	Type    string   `json:"type"` // https://rowstile.dev/problems/refused, /not-found, /not-signed-in, ...
	Title   string   `json:"title"`
	Status  int      `json:"status"`
	Detail  string   `json:"detail"` // the database's words
	Table   *string  `json:"table,omitempty"`
	Command *string  `json:"command,omitempty"`
	Why     []string `json:"why,omitempty"`
	Code    string   `json:"code,omitempty"`
}

// MarshalJSON writes a refusal's table and command as null when it names none, and its why as [], as the other
// SDKs do.
func (p Problem) MarshalJSON() ([]byte, error) {
	type plain Problem
	if p.Type != problemType+"refused" {
		return json.Marshal(plain(p))
	}
	return json.Marshal(struct {
		plain
		Table   *string  `json:"table"`
		Command *string  `json:"command"`
		Why     []string `json:"why"`
	}{plain(p), p.Table, p.Command, append([]string{}, p.Why...)})
}

const problemType = "https://rowstile.dev/problems/"

// the problem type and title of each status a call turned down answers with
var callProblem = map[int][2]string{
	400: {"bad-argument", "Bad Request"},
	401: {"not-signed-in", "Unauthorized"},
	404: {"not-found", "Not Found"},
	409: {"conflict", "Conflict"},
}

func named(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// ProblemOf is the problem body for err, and whether it is rowstile's to answer: a refusal 403, a hidden row 404,
// and a call the database turned down as its code's page says (AZ703, AZ714: 401; AZ708: 404; AZ710: 400; AZ713:
// 409), with the database's words. Anything else (the not-signed-in error, a share the policy doesn't declare, a
// name not in the policy, who is signed in changed by hand) is the app's mistake: false, for a 500.
func ProblemOf(err error) (Problem, bool) {
	var r *Refused
	var nf *NotFound
	var c *CallError
	switch err = translate(err); {
	case errors.As(err, &r):
		return Problem{Type: problemType + "refused", Title: "Forbidden", Status: 403, Detail: r.Message,
			Table: named(r.Table), Command: named(r.Command), Why: r.Why, Code: r.Code}, true
	case errors.As(err, &nf):
		return Problem{Type: problemType + "not-found", Title: "Not Found", Status: 404, Detail: nf.Error()}, true
	case errors.As(err, &c):
		kind := callProblem[c.Status]
		return Problem{Type: problemType + kind[0], Title: kind[1], Status: c.Status, Detail: c.Message,
			Code: c.Code}, true
	}
	return Problem{}, false
}

// WriteProblem answers err as application/problem+json when it is rowstile's to answer (ProblemOf), and says
// whether it did; for anything else it writes nothing.
func WriteProblem(w http.ResponseWriter, err error) bool {
	p, ok := ProblemOf(err)
	if ok {
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(p.Status)
		_ = json.NewEncoder(w).Encode(p) // (the client gone: nothing left to tell)
	}
	return ok
}

// Handler is an http.Handler from a handler that returns its error: rowstile's are answered as WriteProblem
// answers them, and any other is logged (slog, with the request's method and path) and answered 500.
func Handler(fn func(w http.ResponseWriter, r *http.Request) error) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := fn(w, r); err != nil && !WriteProblem(w, err) {
			slog.ErrorContext(r.Context(), "rowstile: the request failed", "method", r.Method, "path", r.URL.Path,
				"error", err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		}
	})
}

// Middleware makes each request act for whoever user says it is (Nobody: only what `anyone` may see), so every
// transaction Tx begins with the request's context signs in as them. user reads the session or the token from
// the request itself; an error from it (a bad token) is answered as rowstile's error when it is one, else 401.
func Middleware(user func(r *http.Request) (Principal, error)) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			who, err := user(r)
			if err != nil && !WriteProblem(w, err) {
				WriteProblem(w, &CallError{Code: "", Status: http.StatusUnauthorized, Message: err.Error(), Err: err})
			}
			if err == nil {
				next.ServeHTTP(w, r.WithContext(ActingAs(r.Context(), who)))
			}
		})
	}
}

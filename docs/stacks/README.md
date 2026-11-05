# rowstile in your stack

The policy and the database work the same everywhere. What changes from one stack to another is how the app
signs in each transaction, reads a refusal, and ships the policy with its migrations.

| stack | page | SDK |
|---|---|---|
| FastAPI, SQLAlchemy (async), Alembic | [fastapi.md](fastapi.md) | `pip install --pre rowstile` |
| Next.js, Prisma, React; preview: Neon's serverless driver, the edge runtime, BullMQ | [nextjs.md](nextjs.md) | `@rowstile/prisma`, `/next`, `/react` |
| Node: pg, postgres.js, Drizzle (Express, Hono, workers); preview: Neon's serverless driver, BullMQ | [node.md](node.md) | `@rowstile/pg`, `/postgres`, `/drizzle` |
| Python: SQLAlchemy (sync), SQLModel, psycopg, asyncpg; Celery and RQ workers (preview) | [python.md](python.md) | `pip install --pre rowstile` |
| Go: pgx, sqlc, net/http, goose (preview) | [go.md](go.md) | `go get github.com/rowstile/rowstile/sdk/go` |
| Django (a preview) | [django.md](django.md) | `pip install --pre "rowstile[django]"` |
| ASP.NET Core, EF Core, Npgsql (a preview) | [aspnetcore.md](aspnetcore.md) | `Rowstile.EntityFrameworkCore`, `Rowstile.AspNetCore`, from the repository |
| Rails, Active Record, Active Job (preview) | [rails.md](rails.md) | the `rowstile` gem, from the repository |
| Spring Boot, JPA, JdbcClient, Flyway (preview) | [spring.md](spring.md) | `dev.rowstile:rowstile-spring-boot-starter`, from the repository |
| Kotlin: Ktor, Exposed, coroutines, Flyway (preview) | [ktor.md](ktor.md) | `dev.rowstile:rowstile-kotlin`, from the repository |
| Rust: Axum, sqlx, tokio-postgres (preview) | [axum.md](axum.md) | the `rowstile` crate, from the repository |
| Phoenix, Ecto, Postgrex, Oban (preview) | [phoenix.md](phoenix.md) | `:rowstile` in `mix.exs`, from the repository |
| Laravel, Eloquent, queued jobs; PHP on PDO (preview) | [laravel.md](laravel.md) | `rowstile/rowstile`, from the repository |
| Electric, the sync engine, behind a Node app (preview) | [electric.md](electric.md) | `@rowstile/client` |
| Zero, the sync engine, with a Node app's endpoints (preview) | [zero.md](zero.md) | `@rowstile/client` |
| PowerSync, the sync engine, on the policy's mirrors (preview) | [powersync.md](powersync.md) | `@rowstile/client` |
| Anything else | [sql.md](sql.md) | none: a few SQL statements |

Every line of code these pages show is in a tested app ([`integrations/fastapi`](../../integrations/fastapi), [`integrations/nextjs`](../../integrations/nextjs),
[`integrations/node`](../../integrations/node), [`integrations/go`](../../integrations/go), [`integrations/django`](../../integrations/django), [`integrations/aspnetcore`](../../integrations/aspnetcore), [`integrations/rails`](../../integrations/rails), [`integrations/spring`](../../integrations/spring), [`integrations/ktor`](../../integrations/ktor), [`integrations/axum`](../../integrations/axum), [`integrations/phoenix`](../../integrations/phoenix), [`integrations/laravel`](../../integrations/laravel), [`integrations/electric`](../../integrations/electric), [`integrations/zero`](../../integrations/zero), [`integrations/powersync`](../../integrations/powersync), the conformance suites), in [`docs/getting-started.md`](../getting-started.md), which runs as written, or, for the SQL the SDKs send, in
the SDKs' own code. [`core/tests/unit_test.py`](../../core/tests/unit_test.py) checks each line, and that the install lines have each rowstile
package the code imports. A block is lines of one file, in their order, though it may leave lines out; a comment
naming a file (`# app/worker.py`) starts the lines of that file. So read the text around a block too.

## Problem details

Every SDK answers a refused write, a row that is hidden or isn't there, and each code a call meets as its page
says, with an RFC 9457 problem body that is the same in every language. Its `type` is a page of this site:
[Refused](../../site/problems/refused.md) (403), [Not found](../../site/problems/not-found.md) (404),
[Not signed in](../../site/problems/not-signed-in.md) (401), [Bad argument](../../site/problems/bad-argument.md)
(400) and [Conflict](../../site/problems/conflict.md) (409). Anything else is the app's mistake: no body, a 500.

| SDK | answers for you | the body of an error, for a handler of your own |
|---|---|---|
| Python | `rowstile.fastapi`, Django's `rowstile.django.Middleware` | `Refused.problem()`, `NotFound.problem()` |
| TypeScript | `route()` and `action()` in `@rowstile/next`, the routes `authzRoutes()` makes | `problemOf(e)`, `problemResponse(e)` |
| Go | `rowstile.Handler`, `rowstile.Middleware` | `ProblemOf(err)`, `WriteProblem(w, err)` |
| .NET | `UseRowstile()` of `Rowstile.AspNetCore` | `Errors.ProblemOf(e)` |
| Ruby | `Rowstile::Middleware`, which the Railtie adds | `Rowstile.problem_of(e)` |
| Java | the Spring Boot starter | `Errors.problem(e)` |
| Kotlin | the Ktor plugin `Rowstile` | `e.problem()`, `call.respondProblem(problem)` |
| Rust | `Error`, an Axum response (the `axum` feature) | `error.problem()` |
| Elixir | `Rowstile.Plug.Fallback` | `Rowstile.problem(e)`, `Rowstile.Plug.send_problem(conn, e)` |
| PHP | Laravel's service provider | `Rowstile::problemOf($e)` |

Start with [getting started](../getting-started.md) for the policy itself. Or from an app that already
runs, as a template repository: the [FastAPI starter](https://github.com/rowstile/starter-fastapi) and the
[Next.js and Prisma starter](https://github.com/rowstile/starter-nextjs-prisma).

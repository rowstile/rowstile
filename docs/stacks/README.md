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
| ASP.NET Core, EF Core, Npgsql (a preview) | [aspnetcore.md](aspnetcore.md) | `Rowstile.EntityFrameworkCore`, `Rowstile.AspNetCore` |
| Rails, Active Record, Active Job (preview) | [rails.md](rails.md) | `bundle add rowstile` |
| Spring Boot, JPA, JdbcClient, Flyway (preview) | [spring.md](spring.md) | `dev.rowstile:rowstile-spring-boot-starter` |
| Kotlin: Ktor, Exposed, coroutines, Flyway (preview) | [ktor.md](ktor.md) | `dev.rowstile:rowstile-kotlin` |
| Rust: Axum, sqlx, tokio-postgres (preview) | [axum.md](axum.md) | `cargo add rowstile` (from the repository) |
| Phoenix, Ecto, Postgrex, Oban (preview) | [phoenix.md](phoenix.md) | `:rowstile` in `mix.exs` |
| Laravel, Eloquent, queued jobs; PHP on PDO (preview) | [laravel.md](laravel.md) | `composer require rowstile/rowstile` |
| Anything else | [sql.md](sql.md) | none: a few SQL statements |

Every line of code these pages show is in a tested app ([`integrations/fastapi`](../../integrations/fastapi), [`integrations/nextjs`](../../integrations/nextjs),
[`integrations/go`](../../integrations/go), [`integrations/django`](../../integrations/django), [`integrations/aspnetcore`](../../integrations/aspnetcore), [`integrations/rails`](../../integrations/rails), [`integrations/spring`](../../integrations/spring), [`integrations/ktor`](../../integrations/ktor), [`integrations/axum`](../../integrations/axum), [`integrations/phoenix`](../../integrations/phoenix), [`integrations/laravel`](../../integrations/laravel), the conformance suites), in [`docs/getting-started.md`](../getting-started.md), which runs as written, or, for the SQL the SDKs send, in
the SDKs' own code. [`core/tests/unit_test.py`](../../core/tests/unit_test.py) checks each line, and that the install lines have each rowstile
package the code imports. It checks lines one by one: a block may be a few lines of a longer file, so read
the text around it too.

Start with [getting started](../getting-started.md) for the policy itself. Or from an app that already
runs, as a template repository: the [FastAPI starter](https://github.com/rowstile/starter-fastapi) and the
[Next.js and Prisma starter](https://github.com/rowstile/starter-nextjs-prisma).

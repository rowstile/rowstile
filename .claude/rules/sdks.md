---
paths:
  - "sdk/**"
  - "integrations/**"
  - "package.json"
  - "package-lock.json"
---

# The SDKs and their conformance suites

What each SDK holds, and the suites that check each one against a real app.

- `sdk/python/` — the `rowstile` Python package: the Python SDK (`rowstile`: FastAPI, SQLAlchemy, psycopg, asyncpg,
  Alembic, pytest) and the command, which `hatch_build.py` puts inside it (`rowstile/_command`).
  It holds no rowstile logic: it signs transactions in and translates the `authz.*` answers
- `sdk/typescript/` — the TypeScript SDK (`@rowstile/client`, `/pg`, `/postgres`, `/prisma`, `/drizzle`, `/next`,
  `/react`, `/vitest`, `/jest`), one package per folder, built with `npx tsc -b sdk/typescript`. The repository
  root's `package.json` is the npm workspace for these packages, the TypeScript conformance apps
  (`integrations/nextjs`, `integrations/node`, `integrations/electric`, `integrations/zero`,
  `integrations/powersync`) and `examples/helpdesk` (one React, one pg); `npm ci` at the root. Like the Python SDK
  it holds no rowstile logic
- The SDKs in preview, each in its language's own layout and with no rowstile logic either: `sdk/go/` (pgx,
  `rowstiletest`), `sdk/dotnet/` (`Rowstile`, `Rowstile.EntityFrameworkCore`, `Rowstile.AspNetCore`), `sdk/ruby/`
  (the gem, for Rails; Steep's signatures in `sig/`), `sdk/java/` (Maven: `rowstile` on JDBC, `rowstile-kotlin`,
  `rowstile-spring-boot-starter`), `sdk/rust/` (the crate, on sqlx or tokio-postgres), `sdk/elixir/` (Ecto,
  Postgrex) and `sdk/php/` (PDO, with Laravel); each README says what it holds
- `integrations/<stack>/` — each SDK's conformance suite, and each sync engine's: a small app and the checks listed
  in `integrations/README.md`, which names every suite; each one's `test.sh` runs it in Docker;
  `pooler.sh` puts PgBouncer in front of a suite's Postgres (`POOLER=pgbouncer test.sh`), its image pinned in
  `images/Dockerfile`

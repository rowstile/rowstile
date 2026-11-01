# Conformance suites

One list of checks, run by a small app per stack (`integrations/<stack>/`, each with its own `test.sh`: `fastapi`,
`nextjs`, and `aspnetcore`, the .NET SDK's, a preview, which runs every check but 15), in CI
on PostgreSQL 16 for each push, and on 17 and 18 every night (`PG_MAJOR=17` or `18` runs a suite on another
version). Every night they also run on 16 with the app connecting through PgBouncer in transaction mode
(`POOLER=pgbouncer`, `pooler.sh`; the owner and the change feed stay direct). The tests are numbered after
this list.

1. Signed in, a list shows only the user's rows.
2. Signed out on purpose, only what `anyone` may see.
3. Not signed in: the not-signed-in error (AZ701), naming `act_as`.
4. With a pool of one connection, a request as Ann, then one as Bob: Bob never sees Ann's rows.
5. Concurrent requests never mix users.
6. A refused insert: 403 with the problem body naming the rule.
7. An update of a hidden row: 404. Of a visible row the user may not edit: 403, with the reason.
8. Insert, then read back, works when the select rule allows it, and is explained when not.
9. The generated names type-check, and a wrong permission name doesn't: in the generated client, and in the
   SDK's own calls.
10. A background job signs in as a service principal.
11. A fresh database: migrate, and the policy tests pass. Then the tool's own diff shows no change.
12. The framework's test database has the policy: a copy of the migrated one for each test worker (Vitest's,
    pytest-xdist's; for Go, each test package, which `go test` runs in a process of its own).
13. The app refuses to start on a connection that skips row-level security.
14. After a policy change and a new migration, the app works with the new generated names.
15. Next.js only: a signed-in page is never served from a cache to another user, and a signed-in read inside
    `unstable_cache` or `"use cache"` fails instead of being cached.
16. A call the database turns down that is no refusal answers as its code's page says, with the database's
    words: what it names isn't there (AZ708) 404, a missing or wrong argument (AZ710) 400, a call that needs
    someone signed in (AZ714) or a login refused (AZ703) 401, a move inside itself (AZ713) 409. A refusal by the
    database's own code (AZ704, AZ705, AZ715) is 403. The app's mistakes stay errors, a 500: a share the policy
    doesn't declare (AZ706), a name not in the policy (AZ707), who is signed in changed by hand (AZ702). In
    every integration that answers HTTP, each code through each (Next.js: `route()` and `action()`), and through
    `authzRoutes()` the codes its calls can meet (AZ705, AZ706, AZ707, AZ708, AZ710, AZ714).

`fastapi/` runs the background jobs' checks (10, and 4, 6 and 7 for a job) in Celery's worker and RQ's, on a Redis of
its own (`tests/test_jobs.py`, preview): a job started by a request acts for its service, or for the user who
asked, given to it as an argument, and the next job on the worker's one connection never acts for the one before.

The Next.js suite (`integrations/nextjs`) also runs checks 1, 2, 4 to 7 and 9 through Neon's serverless driver, on
the Node.js runtime and on the edge (`edge/`, an app of its own), behind Neon's `wsproxy`, and check 10 through a
BullMQ queue on Redis: a preview.

The suites: `fastapi` (the Python SDK: FastAPI, SQLAlchemy, Alembic), `nextjs` (the TypeScript SDK: Next.js,
Prisma, pg, postgres.js, Drizzle, React, Vitest), `node` (a preview: a plain Express server on pg, Drizzle and
postgres.js, Drizzle Kit's migrations, its tests on Jest; `authzRoutes()` is `@rowstile/next`'s) and `go` (the Go
SDK, a preview: `net/http`, pgx, sqlc, goose) and `django` (the Python SDK's Django module, a preview: Django's
ORM on psycopg 3, Django's migrations, pytest-django) and `rails` (the Ruby SDK, a preview: Rails 8, Active
Record, Puma, Minitest) and `spring` (the Java SDK, a preview: Spring Boot, Spring Security, JPA and
JdbcClient over HikariCP, Flyway, JUnit), `ktor` (the Java SDK's Kotlin module, a preview: Ktor, Exposed over
HikariCP, Flyway, JUnit; the Java SDK's names, used from Kotlin)
`axum` (the Rust SDK, a preview: Axum on sqlx, sqlx's migrations,
tokio-postgres, cargo test), `phoenix` (the Elixir SDK, a preview: Phoenix on Bandit, Ecto on Postgrex, Ecto's
migrations, Oban, ExUnit) and `laravel` (the PHP SDK, a preview: Laravel 13, Eloquent on pdo_pgsql, the queue's
database worker, PHPUnit with paratest, PHPStan). Check 15 is Next.js's alone.

`electric` (a preview) is the sync engine's suite, on the sync index: Electric behind a small Express app, whose
shape routes are `@rowstile/client`'s `electricShape` on the shapes `rowstile client electric` writes, nginx as a
cache in front of it, and the checks on Vitest with Electric's own client. Every user's shapes of the files and the
folders stay open, live, and after each step each holds exactly the ids `authz.list` gives that user:

- E1. The first snapshot.
- E2. A share made: the row arrives live. Revoked: it leaves.
- E3. A folder moved out of reach: the files below it leave. Moved back: they return.
- E4. A team left: the rows reached only through it leave, and one also reached another way (a share) stays.
- E5. A sub-team moved under another team: its members' rows follow.
- E6. A share that ends: the row leaves at the next `authz.sync_tick()`, and not before.
- E7. `confidential` set: the file leaves those who read it only through its folder.
- E8. Every user at once, in rounds: each gets their own rows. A client's own `where`, user id (`params`), `table`
  or secret is refused (400), a subset only narrows, and a POST's body that is more than a subset is refused.
- E9. Not signed in: 401 with the problem body, and nothing is asked of Electric.
- E10. Answers vary on who asks, and nginx never gives one user's answer to another.
- E11. Writes through the app arrive in the shapes; a refused one is 403, a hidden row 404.
- E12. Lint finds Electric's role without BYPASSRLS, a member of the app role, or reading a masked column;
  `rowstile apply`, `reapply` and a changed policy leave the shapes as they are (the same handles, no
  `must-refetch`), and `authz.sync_verify()` is true.
- E13. A masked column is never in a shape, even when the client asks for it (in `columns` or a subset's filter).
- E14. A user deleted: their keys go, and their shape empties.
- E15. A session limited by scopes (an API key's), or viewing as someone, is refused (403).
- E16. Keyed by folder: a folder moved out of reach and back writes no file's readers, and the shapes follow.
- E17. After commit: with the worker stopped, a share waits; started again, it arrives.

And the stack's checks that apply: 1 (E1), 4 (a pool of one), 5 (E8), 11 (a fresh database migrates with the
app's SQL migrations, the policy's tests pass, the lock file is current) and 13 (the app refuses to start on the
owner's connection); 16 as the routes meet it (AZ703, AZ709, a hidden row).

The suite runs whole in each of the index's modes, which `SYNC_MODE` names: `copied` (the default), `keyed` (`by
folder` on the files' and the folders' sync lines) and `after` (`sync after commit`). In another mode than the
default, `test.sh` writes that mode's policy from `db/policy.authz` and the migration `rowstile migrate` writes to
it from the lock file, and runs it after the app's migrations, as an app changing its sync lines would. After
commit, a worker beside the app runs `authz.sync_work()` in a loop, and a check that needs the index to hold every
change so far waits for its next run. E16 runs keyed by folder only, E17 after commit only, and a first check says
the index in force is in the mode named. Each pull request runs the three modes, a job each; every night they run
on 17 and 18, and on 16 with the app through PgBouncer (Electric's own connection stays direct).

A new stack gets its own folder here, with every check that applies to it.

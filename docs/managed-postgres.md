# Managed Postgres

rowstile needs no extension and no superuser, so it runs on a managed Postgres as it does on your own. This
page is what we found running it on Neon and Supabase: the command, both SDKs' conformance suites (the
[FastAPI](stacks/fastapi.md) and [Next.js](stacks/nextjs.md) apps), direct and through each service's pooler.
We haven't run it on the other services (RDS, Cloud SQL, Azure); the first part applies to them too.

## On any service

The role a service gives you owns your tables but isn't a superuser. That is enough, with two things done once,
as that owner:

```sql
-- the role your app connects as: made with SQL, so that it is no administrator
CREATE ROLE app_user LOGIN PASSWORD 'a long random password' NOSUPERUSER NOBYPASSRLS;

-- the owner may then look at the data as the app does (rowstile test, sql --as, plans, bench, Studio)
GRANT app_user TO CURRENT_USER;
```

- **Make the app role with SQL.** Roles made in a service's console are often administrators: Neon's are
  members of `neon_superuser`, which has BYPASSRLS, and row-level security does not apply to them. As the app's
  connection, `SELECT * FROM authz.connection_check()` says when the role skips the rules.
- **The owner gives itself the app role.** Since PostgreSQL 16 a role that makes another one only administers
  it. Without the `GRANT`, the commands that switch to the app role stop and say so (`rowstile help AZ618`).
  The app is not affected: it logs in as the app role.
- **The command, migrations and the change feed** connect to the database directly, or through a pooler in
  *session* mode. The app may go through a pooler in *transaction* mode ([Behind a pooler](operations.md#behind-a-pooler)
  says what each driver needs there).
- **Every round trip counts** when the app is far from the database: a signed-in read is three (sign in, the
  query, commit). `rowstile plans` gives the server's time; `rowstile bench` times each statement from where it
  runs, and its first line says what a statement that does nothing takes from there.

## Neon

Tried on PostgreSQL 18, a free project, from 120 ms away. Everything works with the setup above: apply,
migrations (Alembic, Prisma Migrate), the policy's tests, signed sessions, direct and through the pooler. The
FastAPI suite passed 23 of 23 checks direct, and 22 through the pooler (the one left sets `options`). The
Next.js suite passed 32 of 37: the others were Prisma's wait, the test database's copy, and two that waited
for answers as if the database were on the same machine (below).

**Connecting.** The dashboard gives two strings, both with `sslmode=require&channel_binding=require`. Use them
as they are:

| | host | for |
|---|---|---|
| direct | `ep-....neon.tech` | the command, migrations, the change feed (`ROWSTILE_FEED_URL`) |
| pooled | `ep-...-pooler....neon.tech` | the app (PgBouncer in transaction mode) |

The owner is the role the project was made with (`neondb_owner`, or the one you named).

**What to know:**

- **Passwords of roles made with SQL must be strong.** A short one is refused: "insecure password, try
  including more special characters".
- **The pooler refuses `options`.** A connection that sets `options=-c search_path=app` is refused
  ("unsupported startup parameter in options"). Set it on the role: `ALTER ROLE app_user SET search_path = app`.
- **A database can't be copied for about five minutes after anything connected to it.** `CREATE DATABASE ...
  TEMPLATE` says "source database is being accessed by other users", though nobody shows in
  `pg_stat_activity`. So a copy of the test database per test worker (`databasePerWorker`, `database_per_worker`) doesn't work: use one
  test database, where each test rolls back, or a Neon branch per run.
- **Prisma waits 2 seconds for a transaction.** The Prisma SDK runs each `findUnique` in a transaction of its
  own. With many at once and the database far away (20 at once, on a pool of 5, failed on both services), give
  the client a longer wait:
  `new PrismaClient({ adapter, transactionOptions: { maxWait: 10_000 } })`, or a bigger pool.
- **A suspended compute wakes on the first connection.** After seven idle minutes the first connection took
  1.4 s direct and 1.8 s pooled, against 0.75 s awake.

## Supabase

Tried on PostgreSQL 17, a free project, from 55 ms away. Everything works with the setup above and one more
setting, the owner's search path. The FastAPI suite passed 23 of 23 checks through the session pooler. The
Next.js suite passed 34 of 37 through either pooler: the three left were Prisma's wait (as on Neon) and the
test database's copy (below).

**Connecting.** The direct host (`db.<project>.supabase.co`) has only an IPv6 address on the free plan; from a
network without IPv6 it can't be reached. Supabase's pooler (Supavisor) serves both modes on one host, and the
user name carries the project's id:

| | port | user | for |
|---|---|---|---|
| session pooler | 5432 | `postgres.<project>` | the command, migrations, the change feed |
| transaction pooler | 6543 | `app_user.<project>` | the app |
| direct (IPv6) | 5432 | `postgres` | the same as the session pooler, where IPv6 works |

More databases work too: `CREATE DATABASE`, then its name in the URL; Supavisor routes by it.

**The owner's search path.** The owner, `postgres`, has `extensions` on its search path, and Supabase's
`dashboard_user` may create objects there. rowstile's functions that run as the owner look names up on that path,
so the first `rowstile apply` stops:

```
the search path has schemas that roles other than the owner may create objects in: extensions (dashboard_user) [AZ612]
```

Apply with a path without `extensions`, on the connection that applies (the command and your migrations), not
for the role everywhere:

```
postgresql://postgres.<project>:<password>@aws-0-<region>.pooler.supabase.com:5432/postgres?sslmode=require&options=-c%20search_path%3Dpublic
```

Supavisor passes `options` on, in both modes. A tool that can't put `options` in its URL can take the setting for
the database instead, `ALTER ROLE postgres IN DATABASE postgres SET search_path = public`; Supabase's SQL editor
then needs `extensions.` before the functions of extensions (`extensions.uuid_generate_v4()`). A condition in
your policy that calls such a function writes `extensions.` too.

**What to know:**

- **Node: `sslmode=require` means `verify-full` to node-postgres**, and Supabase's certificate is signed by
  Supabase's own authority: every connection fails with "self-signed certificate in certificate chain". Write
  `?uselibpqcompat=true&sslmode=require` (encrypted, the certificate not checked, as libpq means it), or give
  node-postgres Supabase's authority (`sslrootcert`: the certificate the project's database settings offer to
  download) and keep `verify-full`. Prisma's client goes through node-postgres too (`@prisma/adapter-pg`);
  Prisma Migrate and the command take `sslmode=require` as libpq does. The command, as libpq, then checks the
  certificate against a root certificate when there is one: the authority `sslrootcert` names, or `root.crt` in
  libpq's folder (`~/.postgresql`).
- **The transaction pooler and prepared statements**: asyncpg and psycopg need the settings in
  [Behind a pooler](operations.md#behind-a-pooler). Through port 6543, 200 signed-in transactions from 20 at a
  time all saw their own rows with them; without them 154 of 200 failed ("prepared statement ... does not
  exist").
- **Statements of `postgres` stop after two minutes** (`statement_timeout`). Applying a policy backfills its
  inheritance tables in one statement each: 40 seconds at 250k folders, three minutes at a million. For one that long,
  add `-c statement_timeout=0` to the migration connection's `options`.
- **Supabase's Data API sees nothing in a governed table.** Its roles, `anon` and `authenticated`, are not the app
  role, and a table with row-level security and no rules for them shows them no rows, even where they have
  `SELECT`. Tables the policy doesn't govern are open to whoever is granted them, as always. rowstile does not
  take Supabase Auth's JWTs from the Data API: your backend signs in as the app role.
- **Settings outlive a client.** A session-level `SET` one client left on a server connection reached another
  client's transaction through the transaction pooler. rowstile refused it ("authz.user_id was set directly,
  so it is not believed"); your own session settings get no such check
  ([nothing may outlive a transaction](operations.md#behind-a-pooler)).
- **A password set again takes a few minutes to reach Supavisor.** `ALTER ROLE ... PASSWORD`, even with the
  same password, gives the stored secret a new salt, and logins through Supavisor fail with "password
  authentication failed" until it reads the role again. An app that keeps retrying then sets off Supavisor's
  circuit breaker: "too many authentication failures, new connections are temporarily blocked", for every role
  from that machine, for a few minutes. Set the app role's password once, in the migration that makes it.
- **A test database can't be copied** (`databasePerWorker`, `database_per_worker`): Supavisor keeps its own connections to the
  database for a while after yours, and `CREATE DATABASE ... TEMPLATE` is refused, as on Neon. Use one test
  database, where each test rolls back.
- **60 connections** on the free plan, for the app, the command and the dashboard together.

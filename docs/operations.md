# Running rowstile

Upgrading, backups, retention and what to watch. Applying is the `rowstile` command, run as the owner of
the tables; everything else here is plain SQL.

## Configuration

- **Sign in with `authz.act_as()`**, first in each transaction (the clients and SDKs do). The session is
  signed, so the app role can't change who is signed in by setting `authz.user_id`; only the app role (and
  its members) may call `act_as`, and services sign in with `authz.login_key()` or `authz.login_jwt()`.
  `SELECT * FROM authz.connection_check()` at start-up says what is wrong with the app's connection.
- **Memory**: the inheritance tables are read on every check. Give Postgres enough shared buffers for
  the database's hot part; on the benchmark, 250k folders needed more than 1 GB and a million (a 6 GB
  database, 3.4 GB of it inheritance tables) more than 4 GB (`core/bench/`).
- **Check your setup**: `SELECT * FROM authz.lint()` lists ways around the rules it can see.

## Behind a pooler

rowstile signs in each transaction, so a pooler in transaction mode works: PgBouncer and Supavisor (Supabase's)
pass both SDKs' conformance suites and the example apps. Session mode works as plain connections do.
Statement mode can't: signing in and the queries after it are one transaction, and it refuses transactions.

- **The change feed needs its own connection to Postgres.** `LISTEN` lasts as long as the session, and a pooler
  in transaction mode gives the session to other clients between transactions: the feed connects and hears
  nothing, with no error. Give `changes()` (and any `LISTEN` of your own) the database's direct URL, or a
  pooler in session mode (Supabase's session pooler, Neon's host without `-pooler`).
- **Prepared statements.** A pooler that keeps them per client (PgBouncer 1.21 or newer with
  `max_prepared_statements` above 0) needs nothing. One that doesn't (older PgBouncer,
  `max_prepared_statements = 0`, Supavisor in transaction mode) needs the Python drivers to make none:
  - asyncpg, with SQLAlchemy: `?prepared_statement_cache_size=0` on the URL and
    `connect_args={"statement_cache_size": 0}`;
  - psycopg: `prepare_threshold=None` (`ConnectionPool(url, kwargs={"prepare_threshold": None})`, or in
    SQLAlchemy's `connect_args`);
  - postgres.js: `{ prepare: false }`. node-postgres and Prisma need nothing.

  Without it, requests fail with "prepared statement ... does not exist" or "already exists". They fail; nobody
  is signed in as someone else. With no prepared statements, each query is planned anew, the policy's checks
  with it: [what that costs](reference/limits.md#limits).
- **Nothing may outlive a transaction.** The next transaction on that server connection may be another
  client's. A session-level `SET`, a temporary table, a statement prepared by name, or a `WITH HOLD` cursor in
  your own code reaches it: a cursor declared while signed in as one user is read by the next client, signed
  in or not. This holds for any pool. rowstile's own sign-in lasts one transaction.
- **Migrations and the command** run through a pooler too, each in one transaction. The pooler logs in as
  the role it is given: the owner for migrations, the app role for the app (`authz.connection_check()` judges
  the role the app's connection logs in as).
- **PgCat** (1.2) doesn't serve asyncpg or postgres.js: it doesn't handle a message they send when they
  prepare, and their first query never returns. It also drops a connection's `options`. node-postgres and
  Prisma work through it.

## On managed Postgres

The role a managed service gives you owns your tables but isn't a superuser, which is all rowstile needs. Make
the app role with SQL and give it to the owner once (`GRANT app_user TO CURRENT_USER`). [Managed
Postgres](managed-postgres.md) has the setup, and what we found on Neon and Supabase: their connection strings,
poolers, passwords, test databases and, on Supabase, the owner's search path.

## Deploying a policy change

A policy change is a migration: `rowstile migrate` writes it for the tool in `rowstile.toml`
(`[migrations]`), from the lock file (`db/policy.lock`, committed next to the policy), and the deploy runs
it with the app's other migrations, as the owner of the tables. There is no separate step. In CI,
`rowstile migrate --check` fails a change to the policy that has no migration.

- A migration holds only what changed. Most take milliseconds and lock the app's tables only where a
  rule or a trigger on them changes (the migration's first comments say what changed; `rowstile review`
  will say which tables it locks). Each waits at most 10 seconds for a table (`lock_timeout`, unless the
  migration tool set one), then fails, rather than queueing every query behind it; run it again when the
  database is quieter.
- A change to how something inherits comes as two migrations when it can: the first builds the new
  inheritance table beside the one in use while the app runs (it reads the app's tables, and takes as
  long as the backfill takes: seconds for tens of thousands of folders, 40 seconds at 250k, three minutes
  at a million); the
  second swaps it in, in a short transaction. Deploy them one after the other, or together: the second
  catches up with whatever the app changed in between. Other inheritance changes rebuild the table in one
  migration, with the app's tables locked while it runs.
- A migration checks that the database is where the one before it left it, so migrations applied out of
  order, or on a database changed by hand since (`rowstile push` or `apply`), stop with a message.
- Preview first with `rowstile diff`: who gains and loses what.

`rowstile apply db/policy.authz` still applies the whole policy in one transaction (keeping inheritance
tables that didn't change); use it for databases that don't take migrations. `rowstile push`
is for development databases.

## Upgrading rowstile

1. Install the new version of the `rowstile` command.
2. `rowstile migrate` writes what the new version makes differently, as the next migration; deploy it. If
   it makes the same, there is nothing to write, and `rowstile migrate --check` passes as before.
   (Databases that don't take migrations: `rowstile reapply`.)

This holds from 0.1.0-beta.1 on: the beta started afresh. A database an alpha (0.1.0-alpha.9 or earlier) made
is not upgraded: apply the policy from scratch, on a new database, or on the same one after
`rowstile remove --yes` (shares and history stay), then `rowstile apply`. Then upgrade from release to release
as above.

The tests (`core/tests/upgrade.sh`) install the release before this one (from the beta on) and make databases
with it, then upgrade them: with the next migration, with `rowstile reapply`, with `rowstile apply`, and with `rowstile push`
for a development database. Each then holds what this version makes on a new database, and the shares, API keys
and requests made before still work.

## Backups

`pg_dump` includes everything: the shares, the audit trail, the change feed, the policy history
(`authz.policy_versions`), and the objects the policy generated, as ordinary objects. Restore with
`pg_restore` (or `psql`); nothing needs to be installed first. Then check:

```sql
SELECT authz.verify();     -- the inheritance tables match a rebuild
```

and, if a newer rowstile is in use now, its next migration (`rowstile migrate`).

If `authz.verify()` says false, rows were written with the triggers off (a restore with `--disable-triggers`, a
bulk load under `session_replication_role = replica`, `ALTER TABLE ... DISABLE TRIGGER`): the inheritance
tables no longer match the app's tables, and people keep or miss access they shouldn't. `rowstile reapply
--force` (or `rowstile apply db/policy.authz --force`) computes every inheritance table again, under its
lock; a plain `apply` keeps the tables it finds unchanged, stale or not.

A data-only restore with `--disable-triggers` ends with `ENABLE TRIGGER ALL`, which leaves the audit trail's
guard on in ordinary sessions only: a session with `session_replication_role = replica` could change the trail.
`authz.lint()` says so, and `rowstile reapply` puts the guard back in every replication role.

## Retention

The audit trail and the change feed grow forever unless trimmed. Schedule (pg_cron, or your app's
jobs):

```sql
SELECT authz.trim_changes();                    -- keeps 7 days, or the setting changes_keep
SELECT authz.trim_audit(interval '2 years');    -- how long is your compliance decision; recorded
```

A change feed reader that falls behind the trimmed part gets an error from `authz.changes_since()` and
must read everything again, then follow from where the feed was when it started ([Governance](reference/governance.md)).

## What to watch

| | how |
|---|---|
| the inheritance tables are exact | `SELECT authz.verify()` (reads everything, a batch of rows at a time: about two and a half minutes for a million folders; run it off-peak); false: `rowstile reapply --force` |
| the policy's invariants hold | `SELECT * FROM authz.check_invariants()` |
| a tree write waits | `pg_locks` on `authz_int.locks`; a big move holds it for half a second to a second per 20k folders below (`core/bench/`) |
| slow checks | `pg_stat_statements` on your app's queries; `EXPLAIN` shows the policy's subplans |
| who did what | `authz.audit`; break-glass use is also announced on channel `authz_alerts` |

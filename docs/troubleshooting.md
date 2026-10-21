# Troubleshooting

What people run into, by what they see. Most of these were first hit while building the file manager and the
messenger. A mistake in a policy ends with its code (`[AZ203]`): its page in `docs/errors/`, or
`rowstile help AZ203`, says what it means and shows it fixed.

## On Windows: "DLL load failed ... The filename or extension is too long", or "this project's path is too long"

The npm package brings its own Python, inside `node_modules`, about 65 characters below your project. Windows
loads files whose path is up to 259 characters long, so in a deep folder that Python can't start. The command
then runs on a Python 3.11 or later from your `PATH` if there is one, and says so plainly if there is none.
The ways out: a shorter path for the project,
long paths turned on in Windows (`LongPathsEnabled`), or a Python of your own (`pip install --pre rowstile`
gives the same command).

## "can't connect to ..."

The command says where it tried and what the system said: `can't connect to db.example.com port 5433: connection
refused`, or for a server on this machine `can't connect to the socket /var/run/postgresql/.s.PGSQL.5432: no such
file or directory`. Check that a server runs there, and that the place is the one you meant. The database is
`--db`, else `database` in `rowstile.toml`, else `DATABASE_URL`, else the `PG*` variables; `DATABASE_URL` and the
variables may come from `.env.local` or `.env` beside `rowstile.toml`, and the message says when a file named the
database. With none of them, the command tries what `psql` tries: your system's user, on the server's socket in
`/var/run/postgresql` or `/tmp`, or `localhost` on Windows; the message then says nothing named a database, and
how to name one.

## A `{condition}` with a subquery matches rows it shouldn't (or none)

A bare column in a condition is the row's, unless a table the condition reads has one by that name: in
`{exists (select 1 from app.memberships m where m.project_id = id)}`, `id` is the membership's own id when
memberships have one, as most tables do. Applying warns about it: `the condition {...} names id, a column of
app.projects's rows, but reads it from another table the condition names`. Name the row's columns `this.`:

```
can view = owner or {exists (select 1 from app.memberships m where m.project_id = this.id)}
```

Conditions read with the policy's rights wherever they are checked (a rule, a permission, `authz.can`), as
relations do: a subquery sees every row of the tables it reads, not only those the signed-in user may.

## An UPDATE or DELETE changed 0 rows, with no error

That is how row-level security works: rows you may not change are left out, silently. Ask why in the same
transaction:

```sql
SELECT authz.explain_rule('app.files', 'update', '11', '{"name": "x"}');   -- NULL: you can't see it (404)
```

The generated clients do both steps: `az.expect(row_or_count, "app.files", "update", 11)` returns the result,
or raises `NotFound` (the row isn't there, or you can't see it) or `Refused` (with `.why`).

## "permission denied: user 7 may not update this row of T to these values"

The plain `update` rule must hold on the row before *and* after the change: Postgres checks both. If the rule
needs something the change itself removes (a message may be deleted only while it isn't deleted yet), the
update is refused after the change. The error's HINT says so. Keep the plain rule to what holds either side,
and check the new values with an `after` rule:

```
rules app.messages
  update                 : edit or remove
  update deleted after   : {deleted}          -- no undelete
```

## "function authz.uid() does not exist" in a migration

`authz.uid()` and the other generated functions come with the policy, and on a new database the policy is
applied after the migrations. A function whose body is `LANGUAGE sql` is checked when it is created. Write it
in `plpgsql`, whose body is checked when it runs:

```sql
CREATE FUNCTION app.my_usage() RETURNS bigint LANGUAGE plpgsql STABLE AS $$
BEGIN
  RETURN (SELECT sum(size) FROM app.files WHERE owner_id = authz.uid());
END $$;
```

Test your migrations on an empty database now and then (the apps here do: their `test.sh` starts from one).

## "nobody signed in in this transaction"

The app role asked something that depends on who is signing in, in a transaction where nobody said. Start
every transaction with `SELECT authz.act_as('user', '42')` (the generated clients' `sign_in` does it), or
`authz.act_as(NULL, NULL)` for someone not signed in. A sign-in lasts one transaction: with autocommit, each
statement is one, so sign in inside an explicit transaction.

## "authz.user_id was set directly, so it is not believed" / "who is signed in was changed after signing in"

Only `authz.act_as()` and the logins can say who is signed in: they sign the session. Setting
`authz.user_id`, `authz.principal_type`, `authz.scopes` or `authz.acting_user` yourself, or reusing a signature
from another transaction, is refused. Superusers and the policy's owner may set them directly (psql, tests).

## "permission denied for function act_as" / "permission denied for schema authz"

Only the policy's app role (`app role` in the policy) and its members may sign people in with `authz.act_as()`.
Connect as that role, or `GRANT app_user TO app_backend`. Services signing in with API keys or JWTs use
`authz.login_key()` and `authz.login_jwt()` the same way.

## "permission denied for table T"

That is Postgres's own message, not a rule's refusal (which says which rule, and why, and carries a code).
The role the app connects as has no privilege for that command on the table: row-level security comes after
the table's privileges, so the policy's rule for it is never reached. `GRANT UPDATE ON app.projects TO
app_user` (or `INSERT`, `DELETE`, `SELECT`), in the migration that makes the table. `authz.lint()` warns of
each rule the app role has no privilege for.

## "new row violates row-level security policy for table T"

That is Postgres's own message, not rowstile's (whose refusals say which rule, and why). It comes from:

- `INSERT ... RETURNING` or `UPDATE ... RETURNING` of a row the user may not *read* afterwards: returning it
  needs the `select` rule too. So does an `UPDATE` with a `WHERE` on the table's columns, which reads the row:
  an update after which its author could no longer see the row is refused this way.
- A policy on the table that rowstile didn't make. `authz.lint()` lists them: a restrictive one as a note, a
  permissive one as an error, since Postgres joins it to the rules with OR and it lets through what they don't.

## Your app's role sees everything

Row-level security doesn't apply to superusers, roles with `BYPASSRLS`, or a table's owner, who may also turn
it off (`FORCE ROW LEVEL SECURITY` doesn't stop that). The app role must be a role of its own: not the tables'
owner, nor the role that applies the policy, nor a member of either. Applying refuses an app role that is the
role applying the policy, or a member of it (AZ624). `authz.lint()` checks the rest, and applying shows its
findings.

## A list or a page is slow

- A query run outside the transaction that signed in has JIT as the server sets it: with JIT on, Postgres may
  spend most of a second compiling a read through the rules ([Speed and limits](reference/limits.md)).
- Add the indexes `authz.lint()` asks for: every column a check looks up (link tables' columns, foreign keys).
- Page through long lists: `authz.list('file', 'view', '<last id>', 1000)`.

## Applying says "lock timeout"

Applying locks the governed tables, and waits 10 s at most (unless you set `lock_timeout`) rather than queue
every query behind it. Apply when it is quieter. A policy whose inheritance didn't change applies in a fraction
of a second: its tables are kept.

## "rowstile: this database already holds what this migration brings" (AZ607)

A development database that `rowstile dev` or `push` brought to the newest policy holds what the migration
would make, so the migration stops. So does one that ran here before. Don't run it there: tell your
migration tool it is applied (Prisma: `prisma migrate resolve --applied <its folder>`, which also clears
the failed migration Prisma kept; Alembic: `alembic stamp head`), or make the database again from the
migrations, or keep using `push` there and leave the migrations to the other databases.

## "rowstile: this migration changes the policy the migration before it left (...), but the database has ..."

A rowstile migration starts where the one before it left the database, and says so when it doesn't:
it was applied out of order, the ones before it weren't applied, or the database was changed since with
`rowstile push` or `rowstile apply` (development databases). Apply the migrations in order.

## `rowstile push` or `dev`: isn't marked as a development database (AZ610)

Push changes a policy straight away, so it only changes a database marked as a development database. The
first push to a database that never had a policy marks it; one your migrations set up has a policy and no
mark, and `rowstile remove` doesn't change that: after it, push is still refused. If it is a development
database, mark it once: `rowstile push --development`. If it is production, it takes migrations
(`rowstile migrate`).

## "cannot drop column ... because other objects depend on it" in a schema migration

Something rowstile made reads that column, because the policy uses it: the DETAIL names it (a view, a
function, a trigger or a row-level security policy). A column the policy doesn't use drops as usual. Do
it in two steps: change the policy so it doesn't use the column and write its migration (`rowstile
migrate`), then drop the column in a later migration. Don't add `CASCADE`: it drops what rowstile made
with the column, the table's row-level security policies among them.

## A named test fails with "given x = {...} returned 0 rows"

A `given` that names a value must return exactly one row: end the statement with `RETURNING id` (or the key's
columns, for a key of several). Tests run on top of the data already in the database, then roll back: use
values nothing else uses, or let the database make the ids (`RETURNING id`).

## A new build of rowstile, and the database still has the old functions

`rowstile reapply` after installing a new version. A build from this repository's `main` (a version ending in
`-dev`) records a hash of its compiler, so `rowstile apply` applies again after the compiler changed; if it
still says `unchanged`, use `rowstile apply --force`.

## `authz.verify()` says false

Rows were written while the triggers were off (a restore with `--disable-triggers`, a bulk load under
`session_replication_role = replica`, `ALTER TABLE ... DISABLE TRIGGER`), so the inheritance tables don't match
the app's tables any more. `rowstile reapply --force` computes them again (it locks tree writes while it
runs). A plain `apply` or `reapply` keeps the tables whose definition didn't change, so it doesn't.

## `authz.lint()` says a SECURITY DEFINER function uses a governed table

Such functions run with their owner's rights, so they read past row-level security. Sometimes that is the
point (checking a password before anyone is signed in). Make sure each one reads only what it must, and
takes nothing from its caller it shouldn't trust.

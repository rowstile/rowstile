# Deploying a policy: migrations

The compiler runs in the `rowstile` command, never in the database. <!-- checked: tests/apply.sh "which needs nothing installed but plpgsql"; tests/cli.sh "check, graph and client of a file need no database" -->
A policy change is a
migration, written for the tool in `rowstile.toml`, reviewed and deployed with the app's
other migrations. The database needs nothing installed first: `plpgsql`, which every Postgres has, is
enough. <!-- checked: tests/apply.sh "rowstile apply, on a database with no extension"; tests/apply.sh "which needs nothing installed but plpgsql" -->
`core/Dockerfile` builds a Postgres for development and tests: the stock image, with the command in it.

    rowstile migrate                          # the next migration, and db/policy.lock (no database needed)
    rowstile migrate --check                  # in CI: exit 1 if the policy has a change no migration has
    rowstile push                             # a development database, with the same migration
    rowstile diff                             # who gains and loses what; changes nothing
    rowstile test                             # the tests and invariants

| tool | what `rowstile migrate` writes |
|---|---|
| `alembic` | a revision after the current head, `<rev>_authz_<name>.py`, with its SQL beside it (`.sql`) <!-- checked: tests/migrations.sh "alembic: revisions chained by down_revision, each with its SQL beside it" --> |
| `prisma` | `prisma/migrations/<time>_authz_<name>/migration.sql` <!-- checked: tests/migrations.sh "prisma: a folder with migration.sql for each" --> |
| `drizzle` | `drizzle/<n>_authz_<name>.sql` with statement breakpoints, its journal entry and snapshot <!-- checked: tests/migrations.sh "drizzle: numbered files, statement breakpoints, the journal, a snapshot each" --> |
| `sql` | `<n>_authz_<name>.sql` after numbered files (`0005_...`), else `<time>_authz_<name>.sql` <!-- checked: tests/migrations.sh "sql: two timestamped files"; tests/unit_test.py "test_file_names" --> |
| `goose`, `dbmate` | the same SQL, with each tool's markers <!-- checked: tests/migrations.sh "+goose Up, one statement block"; tests/migrations.sh "migrate:up and down" --> |
| `flyway` | `V<time>__authz_<name>.sql`, and its script config file beside it (`.sql.conf`, `placeholderReplacement=false`: the SQL holds `${`, which Flyway would take for a placeholder) <!-- checked: tests/migrations.sh "flyway: each script's config file turns placeholders off" --> |

- **The lock file** (`db/policy.lock`, next to the policy; commit it) lists the policy's lines, then
  each function, view, trigger, policy and table the migrations made so far, with a hash of its SQL. <!-- checked: tests/migrations.sh "the lock file starts with the policy's lines" -->
  So the next migration holds only what changed: a new permission is a new view and a few `CREATE OR
  REPLACE` of the functions that list permissions; unchanged inheritance tables are never touched. <!-- checked: tests/migrations.sh "and holds only what changed"; tests/unit_test.py "test_a_new_permission_is_a_small_migration" -->
  A view
  that changes is replaced in place (emptied first, then defined again), so what the app built on a masked
  view stays. <!-- checked: tests/migrate_test.py "a mask that changes, under a view of the app's"; tests/migrate_test.py "a permission the masked view reads changes, under a view of the app's" -->
  The same policy always gives the same bytes. <!-- checked: tests/unit_test.py "test_the_same_policy_gives_the_same_bytes" -->
  Lines that only moved need no migration. <!-- checked: tests/unit_test.py "test_lines_that_only_move_need_no_migration"; tests/migrate_test.py "lines that only move" -->
- **Each migration checks where it starts**: the lock's hash is recorded in `authz.policy_versions`, and
  a migration applied out of order, twice, or to a database changed since with `push` or `apply` stops
  with a message naming both. <!-- checked: tests/migrations.sh "the same migration again is refused: the database holds it already"; tests/migrations.sh "and so is one without the migrations before it"; tests/migrations.sh "but not to the pushed one, which holds it already" -->
- **Each migration is one transaction**, your tool's. Plain SQL files run with
  `psql -1 -v ON_ERROR_STOP=1 -f <file>`. Run a statement at a time (`psql -f` alone), a migration refuses
  before it changes anything (`AZ615`). <!-- checked: tests/migrations.sh "a migration run a statement at a time is refused (AZ615), and changes nothing" -->
- **Each migration starts with what changed**, as comments (`-- + type file: can comment = folder.view`). <!-- checked: tests/migrations.sh "starting with what changed, as comments" -->
  `migrate` also marks the lock and its migrations `linguist-generated` in `.gitattributes`, so reviews
  show them collapsed. <!-- checked: tests/docs_test.sh "rowstile migrate writes the first migration, the lock file and .gitattributes"; tests/unit_test.py "test_only_what_is_below_is_marked_generated" -->
- **Inheritance that changes is built beside, then swapped in**: two migrations. <!-- checked: tests/migrations.sh "migrate writes two: build beside, then swap in" -->
  The first fills the new
  inheritance table while the app runs (it only reads the app's tables); the second, a short
  transaction, swaps it in and does again what the app changed in between (rows written since the first
  one's snapshot, and the links the change feed records). <!-- checked: tests/migrations.sh "while the first one runs, the app still writes to the tables the tree follows"; tests/migrations.sh "the second swaps it in, with what the app wrote meanwhile" -->
  A tree of several types, one whose conditions
  read other tables, one that takes links from shares, or one whose link tables the policy in force
  doesn't watch yet is rebuilt in one migration, under lock. `--one-phase` asks for one migration.
- **The first migration** is the whole policy, which also applies over a database that already has
  one (applied with `rowstile apply`). <!-- checked: tests/unit_test.py "test_the_first_is_the_whole_policy"; tests/migrations.sh "which says it is the whole policy" -->
- **Upgrading rowstile** is the next migration when the new version makes something differently:
  `rowstile migrate --check` says so, and `rowstile migrate` writes it. <!-- checked: tests/unit_test.py "test_a_changed_step_every_migration_runs_is_a_migration"; tests/upgrade.sh "exit 1, the new version makes something differently"; tests/upgrade.sh "migrate writes the migration from the old lock file to this version"; tests/migrate_test.py "a release grants the app role another function, and nothing else"; tests/unit_test.py "test_a_changed_grant_alone_is_a_migration" -->
  When it changes only an inheritance tree's functions (a message, say), the migration replaces them in place
  and the tree keeps its rows. <!-- checked: tests/migrate_test.py "a release changes a message of an inheritance tree's function"; tests/unit_test.py "test_a_tree_function_changed_alone_is_replaced_in_place" -->
  A new version that makes the same
  needs no migration. <!-- checked: tests/migrations.sh "exit 0 after an upgrade that makes the same"; tests/unit_test.py "test_a_new_version_alone_needs_no_migration" -->
  The other way round is refused: a command older than the version that last wrote the
  lock file or the database stops (`AZ616`), unless told `--downgrade`. <!-- checked: tests/migrations.sh "a lock a newer version wrote is refused"; tests/apply.sh "a policy a newer version applied is refused, naming both versions" -->
- **Development**: `rowstile push` (and `rowstile dev`, on every save) runs the migration from the policy
  in force to this one, directly; `rowstile apply` applies the whole policy again. Neither is for
  production, which takes migrations. Push only changes a development database: the first push to a
  database that never had a policy marks it as one; mark one your migrations set up with
  `rowstile push --development`, once. <!-- checked: tests/reference.sh "the first push to a database that never had a policy marks it as a development one"; tests/migrations.sh "a database the migrations set up isn't pushed to until someone marks it as a development database" -->
  A database with a policy and no mark is refused (`AZ610`), and stays
  refused after `rowstile remove`: taking the policy out doesn't make a database a development one. <!-- checked: tests/migrations.sh "after rowstile remove, a database the migrations set up is still one push refuses"; tests/devx.sh "dev won't push to a database with a policy that isn't marked as a development database" -->

The version (semantic versioning; 1.0 will freeze the public surface) is the compiler's, in
`core/authzlib/__init__.py`; every package carries the same one (`packaging/version.py` sets them). <!-- checked: tests/unit_test.py "test_one_version" -->

- **Who may apply**: whoever may change the tables' policies and triggers, which is their owner (or a
  superuser). <!-- checked: tests/apply.sh "a role that doesn't own the tables can't apply: Postgres refuses"; tests/apply.sh "the owner applies the policy, with no superuser" -->
  The `{...}` conditions are SQL that runs with the rights of whoever applies the policy,
  so applying is as powerful as being that role.
- **Every applied policy is kept** in `authz.policy_versions`, with the rowstile version that applied
  it and the lock's hash (not readable by the app role). <!-- checked: tests/apply.sh "every apply is kept in authz.policy_versions"; tests/apply.sh "the history records which version applied it"; tests/migrations.sh "and records the policy and the lock's hash"; tests/apply.sh "the app role can't read or change the stored policies" -->
- **Backups**: everything is an ordinary table, view, function or policy, so `pg_dump` keeps it all:
  shares, audit trail, change feed, policy history, and what the policy made. <!-- checked: tests/apply.sh "pg_restore runs without errors"; tests/apply.sh "shares, audit trail, policy history and change feed are all restored"; tests/apply.sh "the restored database can apply its policy again" -->
- **Removing**: `rowstile remove --yes` drops everything the policy made and gives back the
  table-wide SELECT that masks replaced; shares and history stay, and row-level security stays on
  (with a warning), so nothing becomes readable by accident. <!-- checked: tests/apply.sh "its schemas are gone"; tests/apply.sh "remove gives back the table-wide SELECT the mask replaced"; tests/apply.sh "shares are kept"; tests/apply.sh "remove warns that row-level security stays on" -->
- **Nothing needs a superuser**: later grants on masked columns are reported by `authz.lint()`, not
  refused. <!-- checked: tests/apply.sh "the owner applies the policy, with no superuser"; tests/masks.sh "and applying again takes it back"; tests/apply.sh "and later grants aren't refused any more" -->

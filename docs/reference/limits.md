# Speed and limits

## Speed

`core/bench/benchmark_results.txt` (`benchmark.sql`): 200,000 files, 10,000 folders, 2,000 users, nested
teams, 500 linked folders; JIT off. These figures, and those below, were measured on 2026-10-03 by a build from
before the rename (`rowfence 0.1.0-dev`), on the laptop the project was developed on then; no build since has
run these benchmarks on a machine of its own.

| median | ms |
|---|---|
| open one file, prepared statement | 1.1 |
| open a folder (20 files), prepared statement | 1.2 |
| `authz.can('file', id, 'edit')` | 0.3 |
| list every visible file (11k to 53k of 200k) | 32 |
| apply the policy, backfilling 10,000 folders | 940 |
| move a folder holding 3,441 subfolders (inside the tree) | 290 |

The scale benchmark (`core/bench/scale.sh --large`: a million files, 50,000 folders, writes arriving while 400
reads a second are served) moves the folder with the most below it, about 19,000 folders, into another root in
0.56 to 0.62 s; reads through the rules have a p95 of 3.2 ms beside the writes (`core/bench/README.md`).

At twenty times that (`scale.sh --full`: 20 million files, a million folders, 40,000 users; 22 and 15 million
rows of inheritance in a 6 GB database; the same build and laptop, 8 GB of shared buffers) the same workload has reads at
a p95 of 4.3 to 4.6 ms and tree writes at 28 to 38 ms. The folder with the most below it, 54,000, moves in 2 to
3.7 s. Applying takes three minutes there (the backfill), and `authz.verify()` two and a half.

**JIT is off in signed-in transactions** ([Signed sessions](identity.md)): with JIT on, Postgres spends about
a third of a second compiling each large read through RLS (the list above takes 290 ms instead of 32), since the
rules' lookups are estimated once per row. Applying analyzes the tables the policy reads that were never
analyzed: a table never analyzed is planned as ten pages of rows (6 rows as thousands), and a read of it as one
JIT compiles. <!-- checked: tests/apply.sh "and leaves none of the tables the policy reads, nor of its own, never analyzed" -->
The audit trail and change feed add about 15 µs per changed row (10,000 owner changes: 292 ms instead of 137 ms).
The feed also looks up what reads the objects a write changed, a thousand objects of a type at most: on the docs
app a member leaving a team or a share on a folder takes about half a millisecond more (0.8 ms instead of 0.3), a
folder moved or made to stop inheriting 1.5 to 2 ms more; with 300 folders and 2,000 files below the folder, 4.5 ms
more, where the files pass a thousand and the feed says `{*}` for them. An update of a column no rule reads (a
folder's or a user's name) announces nothing and looks nothing up: about 0.1 ms (measured 2026-10-29).

## Limits

- **One database.** Everything lives next to the data, so it scales with that
  Postgres. Across shards, run the same policy in each shard and keep an object's
  whole tree (and its groups) on one shard; cross-shard inheritance isn't supported.
- **Nested groups are expanded per query**, walking up from the user's own groups: with 20,000
  teams in chains ten deep, opening a folder given to the top of one takes 1.7 ms (1.5 ms with chains
  one deep) and `authz.can` 0.2 ms (`benchmark.sql`). A stored closure would only pay off for much
  deeper or wider nesting, and couldn't honour expiring shares. <!-- unchecked: why rowstile is built this way, not what it does -->
- **A read costs what its reader holds.** A rule looks the object's ancestors up among the folders where the
  reader's permission starts (the ones they own, are shared, or reach through a team), and that set is worked
  out for each query: about a millisecond per thousand. With a million folders and everything in memory,
  opening a folder took 4.5 to 5 ms on the server for a member who held 4,000 folders directly, against the
  1.2 ms above for one who holds a hundred. Access through one membership of something big costs nothing of
  the kind: an org's admin, who reaches every folder, reads faster than any member in the benchmark.
- **Reads through the rules run on one CPU.** rowstile's functions aren't marked parallel safe: a session's
  signature is bound to its backend, which a parallel worker isn't. So Postgres never splits a read through
  the rules between workers: counting 200,000 files took 28 ms through them, 5.5 ms as the owner with two
  workers. <!-- checked: tests/adversarial.sh "none parallel safe" -->
  Marking them would not be enough. A rule's lookups sit under an `or`, where Postgres plans each one to run row
  by row for a few rows and hashed for many, and a lookup that may run row by row holds the whole query to one
  CPU, on 16, 17 and 18 alike. Written as `IN`, which is only ever hashed, counting 400,000 files on 17 took
  2 workers and 87 to 197 ms instead of 149 to 324, but opening one file took 8 to 73 ms instead of 1.5 to 4.4,
  so the rules keep the lookups that serve opening a file. <!-- unchecked: how Postgres plans, and times measured by hand on 2026-10-19 -->
- **An app's own search runs after the rules, unless Postgres knows it reveals nothing.** Postgres checks a
  table's rules before any condition of the query that isn't marked leakproof, so that such a condition sees no
  row the rules hide. `LIKE`, `ILIKE` and `lower()` aren't: their index goes unused, and worse, Postgres estimates
  few rows from the search and so checks the rules row by row, over every row. On the docs app with 400,000
  files, `lower(name) LIKE 'file\_1234%'` took 0.07 ms as the owner, through its index, and 2.1 s as an
  administrator, 8.5 s as a user who sees a quarter of the files; `lower(name) = ...` and a trigram `ILIKE`
  did the same. Equality and ranges on a column itself are leakproof and keep their index: `name >= 'file_1234'
  AND name < 'file_1235'` took 2.6 and 6.4 ms. At 20 million files the gap grows: `lower(name) LIKE` took 184 s
  as an administrator and over ten minutes for users who see a few hundred thousand files, the range 13 to 38 ms.
  So search on a column with `=` or a range (a generated column holding `lower(name)`, say), or narrow the search first by such a condition (a folder, an owner). <!-- unchecked: how Postgres orders a query's conditions, and times measured by hand on 2026-10-19 and 2026-10-23 -->
- **A big policy needs room in Postgres's lock table.** Applying it whole (or a first migration) takes a lock
  on each object it makes, in one transaction, and the table holds `max_locks_per_transaction` for each
  connection: 6,400 by default. GitLab's thousand tables, drafted by `rowstile init`, make about 45,000; applying
  stopped after two and a half minutes with "out of shared memory", and took 163 s with
  `max_locks_per_transaction = 1024`. `rowstile apply` warns before it starts and names the value to set (a
  restart; on managed Postgres, a parameter).
- **Identity providers**: `authz.sync_members` takes the member list; there is no SCIM
  endpoint. JWTs are HS256 only (no RS256/JWKS in plpgsql); for asymmetric tokens,
  verify in your backend and sign in from there ([Identity](identity.md)), or use an API key. <!-- checked: tests/identity.sh "alg none" -->
- **Writes cost more**: each closure table is maintained on every tree write,
  and tree writes to one type are serialized. Inheritance conditions that read
  other tables are re-evaluated for every row of the type when those tables change
  (and when a statement writes rows of the type's own table, if a condition reads it).
  A move rewrites one row per folder below it and per ancestor it gains or loses;
  while it runs, other tree writes to that type wait. If a link leads from inside the
  moved part back to the folder's old or new ancestors, everything below is recomputed
  instead, which is several times slower.
- **Privileges**: what the policy reads (relations, and `{conditions}` in permissions and rules) it reads with
  the privileges of whoever applied it, wherever it is checked. A condition on the row's own columns is
  written into the rules as it is; one that may read other rows (a subquery, a function other than a built-in
  that reads nothing, however its name is written, or an operator Postgres doesn't have for its own types) is
  called as a function per row the rules check, which costs more on large reads than the same test written as
  a relation.
- **A write rule sees the tables as the statement found them.** Postgres checks each row an `INSERT` or
  `UPDATE` writes as it writes it, and a rule's condition, relation or permission reads the tables as they were
  before the statement: the statement's other rows aren't there for it, those of a `WITH` query in the same
  statement included, and neither are rows another transaction hasn't committed yet. So a rule that holds while
  rows are missing (`not exists (...)`, `count(*) < 2`, a permission that holds while a chat has nobody in it)
  is checked for each row on its own. With `insert : {(select count(*) from app.seats s where s.room_id =
  this.room_id) < 2}`, a third seat added alone is refused, but one `INSERT` of three rows into an empty room
  writes all three. <!-- checked: tests/apply.sh "refuses the third seat added alone"; tests/apply.sh "but not three seats in one statement"; tests/apply.sh "nor the rows a WITH query of the same statement writes" -->
  Two transactions at once, each adding one seat to a room that has one, do the same, unless both are
  SERIALIZABLE: then one of them fails, to retry. A limit on how many rows there may be (two people in a direct
  chat, one owner of a group) belongs in the schema, which holds it for every statement and every transaction:
  a unique index (`CREATE UNIQUE INDEX ON app.members (chat_id) WHERE role = 'owner'`), or a trigger that
  counts after the statement and a unique key that two transactions at once can't both write, as the
  [messenger example](../../examples/messenger/README.md) does. <!-- unchecked: advice on the app's own schema, which rowstile doesn't make -->
- **Partitions go through their table**: apply turns row-level security on, with no rules
  of their own, for the partitions of a governed table and the tables that inherit from it,
  so the app role reads and writes them only through the table (whose rules and triggers
  are on it). <!-- checked: tests/children.sh "and the partition is closed: the app role reads it through its table"; tests/adversarial.sh "reading it directly, once applied again"; tests/adversarial.sh "adding to it directly" -->
  Postgres runs a table's statement triggers only for statements on that table, and it copies the
  table's row triggers to its partitions, not to a table that inherits from it (`CREATE TABLE ...
  INHERITS`). <!-- checked: tests/children.sh "the app role moves a $kind under another through $where of its table"; tests/children.sh "the table that inherits has its table's row and statement triggers" -->
  So apply gives the partitions and the inheriting tables of each table it keeps triggers on (one
  with rules, a tree's table, a link table, a table a condition reads) the triggers of the table
  above: a statement on one of them, the owner's too, keeps inheritance, shares and the audit
  current, and a rule on a column is checked on the rows stored there. <!-- checked: tests/children.sh "the partitions have their table's statement triggers (Postgres gave them the row triggers)"; tests/children.sh "... user 1 sees the posts in the ones moved under theirs and linked in"; tests/children.sh "the tables' owner moving them out again, through the partition and the table that inherits" -->
  A partition made after apply has its table's rules and row triggers from the start, for what is
  read and written through the table; read directly, it is open until the next apply if the app
  role was given it, and a statement on it runs none of the table's statement triggers until then.
  A table that inherits, made after apply, has neither until the next apply. `authz.lint()` reports
  both, and `rowstile apply` then applies (it does not answer `unchanged`). Truncating a partition
  skips the triggers (emptying one partition is not emptying the table), and `authz.lint()` reports
  an app role that may do it. <!-- checked: tests/children.sh "lint says the app role may empty a partition of the table a condition reads, which skips its triggers" -->
  Dropping or detaching a partition skips them too, which leaves its rows' shares until the next
  apply.
- **A key handed over inside one update of a partitioned table**: a row's shares are forgotten when
  its key changes, so a row that has the key later starts with none. Where the update also puts the
  row in another partition, rowstile forgets the shares of every key the update left without a row;
  if the same update gives that key to another row (two rows swapping keys, which takes a deferrable
  key), the shares stay with the key. And the audit has no line for a relation column changed by
  an update that changes the row's key and its partition at once.
- **A key two rows hold, through a table that inherits**: a table's primary key doesn't cover the rows of a
  table that inherits from it (`CREATE TABLE ... INHERITS`), so a row there may have the key of a row of the
  table. rowstile sees one object with that key, and a permission holds on it where it holds on either row:
  `authz.can`, `perms`, `explain`, `who` and `authz.list` answer so, as the rules do. <!-- checked: tests/children.sh "a key two rows hold: authz.can answers for either"; tests/children.sh "... and so do perms, explain and who"; tests/children.sh "... as list does" -->
  Where two such rows aren't meant to be one object, keep their keys apart (one sequence for both tables).
- **A foreign key's action skips the rules**: Postgres runs `ON DELETE CASCADE`, `ON DELETE SET NULL`
  or `SET DEFAULT`, and `ON UPDATE SET NULL` or `SET DEFAULT` without row-level security, so deleting a
  row (or changing its key) can delete or change rows of a governed table that the user may not. Apply
  warns of each such foreign key on a table with rules: use `RESTRICT`, or say that it is meant with
  `cascade from` under the table's rules ([the language](language.md)). <!-- checked: tests/apply.sh "deletes a governed table's rows by cascade"; tests/apply.sh "(ON DELETE SET NULL)"; tests/apply.sh "(ON UPDATE SET DEFAULT)" -->
  `ON UPDATE CASCADE` is no warning: the row still names the same row, by its new key.
- **Link rows are trusted as they are**: a row in a link table (`team_members`,
  `folder_teams`) grants what it says even when the object it names was deleted. Give link
  tables foreign keys to their objects with `ON DELETE CASCADE` (and `ON UPDATE CASCADE` for
  keys that change), as you would anyway; on a link table with rules of its own, apply warns of the
  cascade (above) until a `cascade from` line says it is meant. Shares are removed with their objects by rowstile. <!-- checked: tests/scenario.sql "so it goes with its row"; tests/principals.sh "deleting a user deletes the shares to them" -->
  (A type with a `where` looks its rows up, so a leftover row naming one of its objects counts
  for nothing; don't rely on it.)
- **A permission named many times over is slow to plan.** Each permission is a view, and Postgres
  writes a view out in full every time a query names it, again for each view it names. A rule that reaches
  another type's permission (`folder.view`), which names others more than once, which do the same, multiplies:
  the policies in this repository make Postgres write out at most a dozen views for a read, and at around a
  hundred, planning alone takes a tenth of a second and more for every query, before a row is read, up to a
  second or two. `authz.lint()` warns about each permission that makes it write out more than fifty, whether
  a rule names it or only `authz.list` and `authz.can` check it. <!-- checked: tests/governance.sh "lint finds a permission no rule reads that is slow to plan" -->
  Tiers that include each other and inherit from the row above don't multiply: with `can edit = owner or
  editor or parent.edit` and `can view = edit or viewer or parent.view`, `view` looks up `parent.view` alone,
  which includes `parent.edit`, so each type in a chain adds the same few views. A query that joins tables
  pays for each of them.
  Planning is paid by every query that isn't a prepared statement. One that is gets planned in full its first
  five runs on a connection, and then Postgres usually keeps the plan: a read that took 13 ms to plan took
  0.1 ms from its sixth run. <!-- unchecked: how Postgres plans prepared statements, and a time measured by hand -->
  The plan Postgres settles on then (a generic one) serves every user as well as the first: the rules read who is
  signed in when the query runs, not when it is planned, so a plan is made alike for a user who sees a few rows
  and one who sees them all. A generic plan changes what the app's own parameters change: on the docs app
  with 400,000 files, and on the scale benchmark's 20 million, a count, a page of a folder and one file took the
  same time either way, within a run's noise, for an administrator and for users who see a few hundred thousand
  files. <!-- unchecked: how Postgres plans prepared statements, and times measured by hand on 2026-10-19 and 2026-10-23 -->
  A parameter that hides how many rows match costs more, though. Postgres then guesses many, and may check the
  rules against the reader's whole set at once rather than row by row. At 20 million files, a search by range
  (`name >= $1 AND name < $1 || '~'`) found one file in 13 ms for an administrator with a plan made for its
  value, and in 0.93 s with the generic plan; for users who see 100,000 to 400,000 files, 20 to 28 ms against
  98 to 128 ms. The owner's query took 2 ms either way. For such a query, `SET LOCAL plan_cache_mode =
  force_custom_plan` in its transaction keeps a plan made for each value. <!-- unchecked: how Postgres plans prepared statements, and times measured by hand on 2026-10-23 -->
  Whether queries are prepared is the driver's doing, not the policy's. asyncpg and
  postgres.js prepare every query, and psycopg one it has run five times. node-postgres prepares only a query
  given a `name`, and Prisma's `pg` adapter only with its `statementNameGenerator` option: without them, each
  query is planned anew. <!-- unchecked: how other projects' drivers behave, which no check here holds them to -->
  So is every query behind a pooler that keeps no prepared statements, where the drivers
  are told to make none ([Behind a pooler](../operations.md#behind-a-pooler)). <!-- unchecked: how poolers and drivers behave, which no check here holds them to -->
  `authz.lint()` warns when a table's select rule passes 50 (applying shows it). <!-- checked: tests/unit_test.py "test_many_expansions_are_a_lint_warning" -->
  Name each permission once on
  the way: `can edit = owner or editor`, `can view = edit or viewer`, not `view` written out again inside
  three others. The same name twice in one `and` or `or` counts once. <!-- checked: tests/unit_test.py "test_an_operand_named_twice_is_written_once" -->
- **Composite keys cost more to check** than single-column ones: ids are built as text per row
  (20,000 folders keyed `(org_id, id)`: a list of 7,000 takes about 0.4 s). The benchmark
  gate is measured on single keys. Rows are looked up by each column of such a key, so an index on the columns
  serves the lookup (`rowstile indexes` names it). <!-- checked: tests/confidence_test.py "looked up through" -->
- **A `(type, id)` pair whose id is one column** is found by its type: its id is read through a `CASE` on the
  type, which no index serves. An index on `(type, id)` (what `rowstile indexes` asks for) finds the rows of that
  type, and each of them is read. Where most rows name one type, that is most of the table. <!-- checked: tests/confidence_test.py "the rows of that type found through" -->
- **prove and the review read text as ICU's root collations do.** Two texts a column may hold as one value (the
  same but for case, accents, spaces or punctuation, numbers written two ways, the same words in another order)
  are left to the database there. <!-- checked: tests/conditions_test.py "and not alike" -->
  A collation made for a language, or built from rules, may hold more texts as one value: Lithuanian holds
  `'ylp'` and `'ilp'` alike. For a column under such a collation, the database is the check:
  `authz.check_invariants()` on its data, and the review's access part on a review database. <!-- unchecked: a limit of the made-up worlds, said so that no more is expected of them -->

## What a 0.x release promises

rowstile 0.1.0 is in beta: complete enough to use before it is released, and it may still change where using
it shows a need. Until 1.0, a minor release (0.1 to 0.2) may change the policy language, the `authz.*`
functions, the SDKs, the error codes and the file formats (`rowstile.toml`, the lock file). What it does keep:

- **Each release from 0.1.0-beta.1 on upgrades from the one before it**: a database applied by 0.1 is
  migrated by 0.2, and the suites test it. <!-- checked: tests/upgrade.sh "the migration applies on the database"; tests/upgrade.sh "applied is applied again, not taken as up to date"; tests/upgrade.sh "it holds what applying this version on a new database leaves"; tests/upgrade.sh "the shares made before still grant" -->
  Skipping releases is tested each night too, from every release on PyPI from the beta on, but it is not
  promised.
- **The beta starts afresh**: a database an alpha (0.1.0-alpha.9 or earlier) made is not upgraded. Apply the
  policy from scratch: on a new database, or on the same one after `rowstile remove --yes`, then `rowstile
  apply` (shares and history stay through remove). <!-- checked: tests/apply.sh "a removed policy can be applied again"; tests/apply.sh "shares are kept" -->
  The upgrade tests start from the beta too. <!-- checked: tests/unit_test.py "test_the_alphas_are_never_the_release_before" -->
- **The changelog says what changed**, and its **Upgrading** says what to do: a policy line to rewrite, a call
  to rename, a migration to make.
- **A patch (0.1.1) only fixes.** <!-- unchecked: how releases are made (RELEASING.md), which no test can hold --> Nothing to do when upgrading.
- **Security fixes go into the newest version only**: the next pre-release while no final release exists, a
  patch after that ([SECURITY.md](../../SECURITY.md)). <!-- unchecked: how fixes are released (SECURITY.md), which no test can hold -->

What 1.0 promises is decided before 1.0, and this section is replaced by it.
